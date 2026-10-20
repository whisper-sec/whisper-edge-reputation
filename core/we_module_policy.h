/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_module_policy.h - the configuration-time policy glue the three server modules share.
 *
 * The existing directives (whisper_edge_snapshot, whisper_edge_mode, whisper_edge_threshold) are
 * SUGAR for the policy language: `whisper_edge_threshold high` is the program `deny if listed >= high`,
 * and `mode` and `allow_inferred` are the context's own configuration, never part of the program. This
 * header lets a module, at configuration time and nowhere else:
 *
 *   - compile each context's sugar through we_policy_sugar(), so the program a context will run is the
 *     one the policy compiler produces for the equivalent text, byte for byte;
 *   - INTERN the programs: a program depends on the threshold alone, so every context with the same
 *     threshold shares one block, and a context with no threshold line of its own runs its parent's
 *     block under its OWN mode (a context's policy lines replace its parent's, never append to them);
 *   - build the configuration's floor block (empty: the sugar has no floor rules) and place its
 *     hold-harmless view, so the table exists whatever the operator wrote;
 *   - keep every block and the view in page-aligned anonymous mappings, each made read-only as soon as
 *     it is built, so before any worker is forked, and say where they are, so a module gate can show
 *     the pages stay shared after fork;
 *   - print one line per context saying what it runs, and one per configuration with the hot bytes.
 *
 * The request path does not read any of it yet: the modules keep deciding with we_should_deny() until
 * the evaluator replaces it, so nothing here can change a verdict.
 *
 * Compiled only when the policy compiler is in the build (we_policy.h and we_eval.h on the include
 * path); a module built without it has none of this and says so.
 */
#ifndef WE_MODULE_POLICY_H
#define WE_MODULE_POLICY_H

#if defined(__has_include)
#if __has_include("we_policy.h") && __has_include("we_eval.h")
#define WE_HAVE_POLICY 1
#endif
#endif

#ifdef WE_HAVE_POLICY
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "we_policy.h"
#include "we_eval.h"         /* we_ctx_conf_t, the context's own configuration (POLICY.md section 3.1) */

#define WE_MP_REGIONS 16

/* mode as the modules store it (0 off, 1 log, 2 deny) to the evaluator's we_ctx_conf_t domain */
#define WE_MP_MODE(m) ((uint8_t)((m) == 2 ? WE_MODE_DENY : (m) == 0 ? WE_MODE_OFF : WE_MODE_LOG))

typedef struct { void *p; size_t len; const char *what; } we_mp_region_t;

typedef struct {
    we_program_t   *sugar[5];          /* one block per threshold, WE_SEV_NONE .. WE_SEV_CRITICAL */
    uint32_t        id[5];             /* its number in this configuration, 1-based */
    uint32_t        next_id;
    we_program_t   *floor;             /* the configuration's floor block, empty for the sugar */
    we_hh_view_t   *hh;                /* its hold-harmless view, on a page of its own */
    we_mp_region_t  region[WE_MP_REGIONS];
    uint32_t        nregion;
    uint32_t        sealed;            /* regions [0, sealed) are read-only */
} we_mp_t;

/*
 * A region of whole anonymous pages, recorded so it can be sealed, listed and released. Blocks are
 * POSITION-INDEPENDENT (every reference inside one is an offset from its start), so the module keeps
 * its own copy of each in a region like this, apart from whatever heap the compiler worked in.
 */
static inline void *we_mp_map(we_mp_t *s, size_t size, const char *what)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE), len = (size + page - 1u) & ~(page - 1u);
    void *p;

    if (s->nregion == WE_MP_REGIONS || len == 0u) {
        return NULL;
    }
    p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    s->region[s->nregion].p = p;
    s->region[s->nregion].len = len;
    s->region[s->nregion].what = what;
    s->nregion++;
    return p;
}

/* a block copied into a region of its own and verified there; NULL when no region is left or the copy
 * does not verify (the view is placed, and the request path will read, only a verified block) */
static inline we_program_t *we_mp_copy(we_mp_t *s, const we_program_t *p, const char *what)
{
    size_t len = we_program_size(p);
    we_program_t *c = we_mp_map(s, len, what);
    we_policy_error_t e;

    if (c == NULL) {
        return NULL;
    }
    memcpy(c, p, len);
    memset(&e, 0, sizeof e);
    return we_program_verify(c, len, &e) == 0 ? c : NULL;
}

/* every region built since the last seal, read-only; -1 when one cannot be */
static inline int we_mp_seal(we_mp_t *s)
{
    for (; s->sealed < s->nregion; s->sealed++) {
        if (mprotect(s->region[s->sealed].p, s->region[s->sealed].len, PROT_READ) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * The configuration's floor block and its hold-harmless view, once; 0 on success. The sugar writes no
 * floor rule, so the floor is the empty one, which every configuration has: it carries the
 * hold-harmless table.
 */
static inline int we_mp_floor(we_mp_t *s, char *err, size_t n)
{
    we_policy_source_t src;
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    const we_program_t *f;

    if (s->floor != NULL) {
        return 0;
    }
    memset(&src, 0, sizeof src);
    memset(&e, 0, sizeof e);
    if (we_policy_build(&src, &env, NULL, &b, &e, NULL) != WE_POLICY_OK || b == NULL
            || (f = we_policy_floor(b)) == NULL) {
        snprintf(err, n, "the empty floor block does not compile: %.72s", e.what);
        if (b != NULL) { we_policy_build_free(b); }
        return -1;
    }
    s->floor = we_mp_copy(s, f, "floor");
    we_policy_build_free(b);
    if (s->floor == NULL) {
        snprintf(err, n, "the floor block cannot be mapped");
        return -1;
    }
    s->hh = we_mp_map(s, sizeof *s->hh, "hold-harmless-view");
    if (s->hh == NULL || we_program_place(s->floor, s->hh) != 0) {
        snprintf(err, n, "the hold-harmless view cannot be placed");
        return -1;
    }
    if (we_mp_seal(s) != 0) {
        snprintf(err, n, "the floor block cannot be made read-only");
        return -1;
    }
    return 0;
}

/* the block a threshold compiles to, compiled and sealed once per configuration; NULL with a reason */
static inline we_program_t *we_mp_sugar(we_mp_t *s, unsigned threshold, uint32_t *id, char *err, size_t n)
{
    we_program_t *tmp = NULL;

    if (threshold > 4u) {
        snprintf(err, n, "threshold %u is outside off..critical", threshold);
        return NULL;
    }
    if (s->sugar[threshold] == NULL) {
        if (we_policy_sugar((uint8_t)threshold, NULL, &tmp) != 0 || tmp == NULL) {
            snprintf(err, n, "the policy compiler refused the sugar for threshold %u", threshold);
            return NULL;
        }
        s->sugar[threshold] = we_mp_copy(s, tmp, "program");
        we_program_free(NULL, tmp);
        if (s->sugar[threshold] == NULL || we_mp_seal(s) != 0) {
            snprintf(err, n, "the program for threshold %u cannot be mapped read-only", threshold);
            return NULL;
        }
        s->id[threshold] = ++s->next_id;
    }
    *id = s->id[threshold];
    return s->sugar[threshold];
}

/*
 * One context, at configuration time: the block its threshold compiles to, and the line that says so.
 * `own` is set when this context wrote its own threshold line; without it the context runs the block
 * its parent runs (the same threshold, so the same interned block) under its own mode.
 */
static inline we_program_t *we_mp_context(we_mp_t *s, const char *context, unsigned threshold, int own,
                                          unsigned mode, int allow_inferred, char *line, size_t n)
{
    static const char *const modes[3] = { "off", "log", "deny" };
    char text[256], err[128];
    uint32_t id = 0;
    we_program_t *p = we_mp_sugar(s, threshold, &id, err, sizeof err);

    if (p == NULL) {
        snprintf(line, n, "whisper edge: policy: %s: %s", context, err);
        return NULL;
    }
    if (we_program_print(p, text, sizeof text) < 0) {
        snprintf(text, sizeof text, "(the canonical text does not fit this line)");
    }
    text[strcspn(text, "\n")] = '\0';
    if (own) {
        snprintf(line, n, "whisper edge: policy: %s: its threshold line is the program \"%s\" (program #%u), "
                 "run under mode %s%s", context, text[0] != '\0' ? text : "(no rule: threshold off)", id,
                 modes[mode < 3u ? mode : 1u], allow_inferred ? " with inferred listings" : "");
    } else {
        snprintf(line, n, "whisper edge: policy: %s: no policy lines of its own; it runs its parent's program #%u "
                 "\"%s\" under its own mode %s%s", context, id, text[0] != '\0' ? text : "(no rule: threshold off)",
                 modes[mode < 3u ? mode : 1u], allow_inferred ? " with inferred listings" : "");
    }
    return p;
}

/*
 * Once per configuration, after every context: the floor block and its view if they are not yet built,
 * every region sealed, and the summary line with the configuration-wide hot bytes and where each region
 * lies. 0 on success; on failure `line` says why.
 */
static inline int we_mp_finish(we_mp_t *s, char *line, size_t n)
{
    char err[128];
    size_t hot = 0, off;
    uint32_t i;

    if (we_mp_floor(s, err, sizeof err) != 0) {
        snprintf(line, n, "whisper edge: policy: %s", err);
        return -1;
    }
    if (we_mp_seal(s) != 0) {
        snprintf(line, n, "whisper edge: policy: a program region cannot be made read-only");
        return -1;
    }
    for (i = 0; i < 5u; i++) {
        if (s->sugar[i] != NULL) { hot += s->sugar[i]->hot_len; }
    }
    hot += s->floor->hot_len;
    off = (size_t)snprintf(line, n, "whisper edge: policy: %u distinct programs and the floor, %zu hot bytes in all "
                           "(configuration-wide, after interning); read-only regions:", s->next_id, hot);
    for (i = 0; i < s->nregion && off < n; i++) {
        off += (size_t)snprintf(line + off, n - off, " %s %lx-%lx", s->region[i].what,
                                (unsigned long)(uintptr_t)s->region[i].p,
                                (unsigned long)((uintptr_t)s->region[i].p + s->region[i].len));
    }
    return 0;
}

/* every region unmapped, at configuration teardown */
static inline void we_mp_release(we_mp_t *s)
{
    uint32_t i;

    for (i = 0; i < s->nregion; i++) {
        munmap(s->region[i].p, s->region[i].len);
    }
    memset(s, 0, sizeof *s);
}

static inline we_ctx_conf_t we_mp_conf(unsigned mode, int allow_inferred)
{
    we_ctx_conf_t c;

    memset(&c, 0, sizeof c);
    c.mode = WE_MP_MODE(mode);
    c.allow_inferred = allow_inferred ? 1u : 0u;
    return c;
}
#endif /* WE_HAVE_POLICY */
#endif /* WE_MODULE_POLICY_H */
