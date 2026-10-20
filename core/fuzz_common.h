/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * What the two policy fuzz harnesses share: the allocator they hand the compiler, the corpus's record
 * framing, a whole-file reader, and the one place they meet the compiler's types.
 *
 * THE ADAPTER. POLICY.md fixes the function names and signatures (section 3.1); this header is where the
 * harnesses meet the compiler's types (we_policy.h, we_eval.h), so a disagreement is a compile error
 * here and nowhere else:
 *   we_policy_source_t    { d, n, context, floor }: the whole configuration, and which program of it
 *   we_policy_directive_t { kind, context, arg, len }
 *   we_policy_env_t       { present, schema_ok, legacy, canonical }: FZ_ENV() fills all four; canonical
 *                         is set only for R1's re-parse of the printed text (POLICY.md D32)
 *   we_policy_error_t     { layer, phrase, kind (WE_DIR_*, named by we_policy_kind_name()), directive,
 *                         rule, line, col, context[], token[] (ALREADY rendered as section 1.5 says),
 *                         token_len (the raw lexeme's bytes), what[], fix[] }: arrays, never NULL
 *   we_program_t          the block's own 64-byte header: rules_off, rule_count, instrs_off, instr_count,
 *                         bindings_off, sets_off, set_count, hh_off, setdata_off, hot_len, text_off,
 *                         text_len, total_len; the hold-harmless and set-data lengths follow from the
 *                         offsets (FZ_HH_LEN, FZ_SETDATA_LEN)
 *   we_program_size(p)    the block's total length
 *   we_program_print(p, buf, n)  one canonical rule per LF-terminated line and nothing else; the named
 *                         sets' declarations are we_program_print_sets()'s
 *   we_alloc_t            { alloc(ud, n, align), free(ud, p), ud }
 *   we_request_t { floor, server, hold_harmless_eligible, acme_exempt, walk }, we_ctx_conf_t { mode,
 *   allow_inferred }, we_eval_ctx_t { view[8].m, slot[2] }, we_verdict_t { step, action, program,
 *   reason, ..., rule, ... }, we_hh_view_t (64-byte aligned by its type, so a stack one is placed)
 */
#ifndef WE_FUZZ_COMMON_H
#define WE_FUZZ_COMMON_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "whisper_edge.h"
#include "we_policy.h"
#include "we_eval.h"

/* the environment, every field named; canonical only for R1 (POLICY.md D32) */
#define FZ_ENV(present, schema_ok, canonical) \
    ((we_policy_env_t){ (uint8_t)(present), (uint8_t)(schema_ok), 0u, (uint8_t)(canonical) })
/* the two lengths the header does not store: each table ends where the next one starts */
#define FZ_HH_LEN(h)      ((h).setdata_off >= (h).hh_off ? (h).setdata_off - (h).hh_off : 0u)
#define FZ_SETDATA_LEN(h) ((h).hot_len >= (h).setdata_off ? (h).hot_len - (h).setdata_off : 0u)

#define FZ_MAX_DIRS 4096u

static void *fz_alloc(void *ud, size_t n, size_t align)
{
    (void)ud;
    void *p = NULL;
    if (align < sizeof(void *)) {
        align = sizeof(void *);
    }
    return posix_memalign(&p, align, n == 0 ? 1 : n) == 0 ? p : NULL;
}

static void fz_free(void *ud, void *p)
{
    (void)ud;
    free(p);
}

static const we_alloc_t FZ_ALLOC = { fz_alloc, fz_free, NULL };

typedef struct {
    we_policy_directive_t d[FZ_MAX_DIRS];
    char ctx[FZ_MAX_DIRS][1024];          /* a context as deep as a nested-location configuration writes it */
    size_t n;
} fz_config_t;

static int fz_kind(const uint8_t *s, size_t n)
{
    static const struct { const char *name; int kind; } K[] = {
        { "policy", WE_DIR_POLICY }, { "set", WE_DIR_SET }, { "floor", WE_DIR_FLOOR },
        { "threshold", WE_DIR_THRESHOLD }, { "mode", WE_DIR_MODE },
    };
    for (size_t i = 0; i < sizeof K / sizeof K[0]; i++) {
        if (strlen(K[i].name) == n && memcmp(K[i].name, s, n) == 0) {
            return K[i].kind;
        }
    }
    return -1;
}

/* Split <kind> SP <context> SP <argument> 0x1E [0x0A] records. Returns 0, or -1 for framing the harness
 * does not accept (that input is skipped whole: the framing is the harness's, not the language's). */
static int fz_split(const uint8_t *p, size_t n, fz_config_t *c)
{
    c->n = 0;
    size_t i = 0;
    while (i < n) {
        if (p[i] == 0x0A && i > 0 && p[i - 1] == 0x1E) {
            i++;
            continue;
        }
        const uint8_t *end = memchr(p + i, 0x1E, n - i);
        size_t rec = end != NULL ? (size_t)(end - (p + i)) : n - i;
        const uint8_t *r = p + i;
        const uint8_t *sp1 = memchr(r, ' ', rec);
        if (sp1 == NULL || c->n == FZ_MAX_DIRS) {
            return -1;
        }
        size_t rest = rec - (size_t)(sp1 + 1 - r);
        const uint8_t *sp2 = memchr(sp1 + 1, ' ', rest);
        size_t clen = sp2 != NULL ? (size_t)(sp2 - sp1 - 1) : rest;
        int kind = fz_kind(r, (size_t)(sp1 - r));
        if (kind < 0 || clen == 0 || clen >= sizeof c->ctx[0]) {
            return -1;
        }
        memcpy(c->ctx[c->n], sp1 + 1, clen);
        c->ctx[c->n][clen] = '\0';
        c->d[c->n].kind = (uint8_t)kind;
        c->d[c->n].context = c->ctx[c->n];
        c->d[c->n].arg = sp2 != NULL ? sp2 + 1 : r + rec;
        c->d[c->n].len = sp2 != NULL ? rec - (size_t)(sp2 + 1 - r) : 0;
        c->n++;
        i += rec + (end != NULL ? 1u : 0u);
    }
    return 0;
}

static uint8_t *fz_read(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    size_t cap = (size_t)1 << 16, len = 0, r;
    uint8_t *b = malloc(cap);
    while (b != NULL && (r = fread(b + len, 1, cap - len, f)) > 0) {
        len += r;
        if (len == cap) {
            uint8_t *nb = realloc(b, cap * 2);
            if (nb == NULL) {
                free(b);
                b = NULL;
                break;
            }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    *n = len;
    return b;
}

/* ------------------------------------------------------------------------------------------------
 * THE PLANES. The harnesses evaluate against a real view of EVERY plane, so the memo fill runs and
 * every instruction's `off` is dereferenced against a real record. In the directory they are given they
 * expect `<plane>.bin` and `<plane>.txt` (the deciding addresses) for all eight planes:
 *   routing, tor          the Java builder's committed format-2 fixtures, testdata/format2/<plane>.bin,
 *                         with <plane>-expected.txt as <plane>.txt
 *   reputation            synthetic: format 1 with the schema tail, radix-16 both families
 *   rpki-unreachable, anonymizer, threat, registry, tenant
 *                         synthetic: format 2, every record field in its domain
 * The synthetic five and reputation are written by make-test-snapshot.py, the independent writer
 * check-py already holds the reader to; `make fuzz` and `check-policy` build the directory before either
 * harness runs. Each loaded buffer is moved onto pages of its own and made PROT_READ, so a store into a
 * plane faults (section 5.5).
 * ------------------------------------------------------------------------------------------------ */

static const char *const FZ_PLANES[8] = { "reputation", "tor", "rpki-unreachable", "routing", "anonymizer",
                                          "threat", "registry", "tenant" };

#define FZ_MAX_ADDRS 512u

typedef struct {
    we_map_t m[8];
    int loaded[8];
    uint8_t addr[FZ_MAX_ADDRS][16];
    int fam[FZ_MAX_ADDRS];
    size_t naddr;
} fz_planes_t;

/* Move a loaded plane's buffer onto pages of its own, rebase every pointer of the map that pointed into
 * it (the map's own fields, whisper_edge.h; a pointer outside the old buffer, such as the country table,
 * is left alone), free the old buffer and write-protect the new one. The map is never passed to
 * we_map_close afterwards. */
static int fz_protect_map(we_map_t *m)
{
    const uint8_t *old = (const uint8_t *)m->base;
    size_t len = m->len;
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t span = len == 0 ? pg : (len + pg - 1) / pg * pg;
    uint8_t *nb = mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (nb == MAP_FAILED) {
        return -1;
    }
    memcpy(nb, old, len);
#define FZ_REBASE(ptr)                                                                          \
    do {                                                                                        \
        const uint8_t *q_ = (const uint8_t *)(ptr);                                             \
        if (q_ >= old && q_ < old + len) {                                                      \
            (ptr) = (void *)(nb + (q_ - old));                                                  \
        }                                                                                       \
    } while (0)
    we_fam_t *fams[3] = { &m->f4, &m->f6, &m->f6w };
    for (int i = 0; i < 3; i++) {
        FZ_REBASE(fams[i]->start);
        FZ_REBASE(fams[i]->end);
        FZ_REBASE(fams[i]->records);
        FZ_REBASE(fams[i]->sev);
        FZ_REBASE(fams[i]->idx);
        FZ_REBASE(fams[i]->stree);
    }
    FZ_REBASE(m->h);
    FZ_REBASE(m->v4_index);
    FZ_REBASE(m->v4_start);
    FZ_REBASE(m->v4_end);
    FZ_REBASE(m->v4_sev);
    FZ_REBASE(m->v6_index);
    FZ_REBASE(m->v6_start);
    FZ_REBASE(m->v6_end);
    FZ_REBASE(m->v6_sev);
    FZ_REBASE(m->v4_meta);
    FZ_REBASE(m->v6_meta);
    FZ_REBASE(m->blob);
#undef FZ_REBASE
    free((void *)(uintptr_t)old);
    m->base = nb;
    return mprotect(nb, span, PROT_READ);
}

/* The deciding addresses a plane's expect file lists, `<family> <address> ...` per line: every seventh,
 * at most FZ_ADDRS_PER_PLANE from one plane, so all eight planes contribute addresses inside their own
 * ranges (and the misses beside them). */
#define FZ_ADDRS_PER_PLANE 64u

static void fz_read_addrs(const char *path, fz_planes_t *pl)
{
    FILE *f = fopen(path, "r");
    char line[512], a[128];
    int fam;
    unsigned k = 0;
    size_t cap = pl->naddr + FZ_ADDRS_PER_PLANE;
    while (f != NULL && fgets(line, sizeof line, f) != NULL && pl->naddr < FZ_MAX_ADDRS && pl->naddr < cap) {
        if (sscanf(line, "%d %127s", &fam, a) != 2 || (fam != 4 && fam != 6) || (k++ % 7u) != 0u) {
            continue;
        }
        uint8_t raw[16] = { 0 };
        if (inet_pton(fam == 4 ? AF_INET : AF_INET6, a, raw) == 1) {
            memcpy(pl->addr[pl->naddr], raw, 16);
            pl->fam[pl->naddr] = fam;
            pl->naddr++;
        }
    }
    if (f != NULL) {
        fclose(f);
    }
}

/* Load all eight planes from `dir`, each write-protected. Returns how many loaded; the harnesses
 * require all eight and say which one is missing. */
static int fz_load_planes(const char *dir, fz_planes_t *pl)
{
    char path[2048];
    int n = 0;
    memset(pl, 0, sizeof *pl);
    for (int i = 0; i < 8; i++) {
        we_load_detail_t det;
        snprintf(path, sizeof path, "%s/%s.bin", dir, FZ_PLANES[i]);
        int rc = we_plane_open(path, &pl->m[i], &det);
        if (rc == WE_OK && fz_protect_map(&pl->m[i]) == 0) {
            pl->loaded[i] = 1;
            n++;
        } else {
            fprintf(stderr, "plane %s did not load from %s: %s\n", FZ_PLANES[i], path,
                    rc == WE_OK ? "mprotect failed" : we_strerror(rc));
        }
        snprintf(path, sizeof path, "%s/%s.txt", dir, FZ_PLANES[i]);
        fz_read_addrs(path, pl);
    }
    return n;
}

/* The views for one evaluation: every plane present, or (null_mask bit set) that plane NULL. */
static void fz_views(we_eval_ctx_t *ec, const fz_planes_t *pl, uint8_t null_mask)
{
    for (int i = 0; i < 8; i++) {
        ec->view[i].m = (pl->loaded[i] && !(null_mask & (1u << i))) ? &pl->m[i] : NULL;
    }
}

/* Did the planes decide anything? One request evaluated with the real views and again with every view
 * NULL: a replay in which these never differ has not read a record, whatever else it asserted. The
 * verdict fields compared are the ones section 3.4 names: step, action, rule. */
static int fz_verdicts_differ(const we_verdict_t *a, const we_verdict_t *b)
{
    return a->step != b->step || a->action != b->action || a->rule != b->rule;
}

#endif /* WE_FUZZ_COMMON_H */
