/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * test_module - we_module.h and we_module.c, held to POLICY.md's rendering section and to the core.
 *
 *   test_module <tmpdir> [<planes dir>]
 *
 * The planes are the eight fixture planes `make fuzz-planes` writes (format 1 reputation with its schema,
 * format 2 for the rest, every index kind), read from <tmpdir>/fuzz/planes unless a directory is named.
 * Every check prints nothing when it holds and one line when it fails; the last line is the count the
 * README's published case total sums: `N checks, F failures`.
 *
 * What is held, by section:
 *   layout     the scratch is 1,024 bytes and 64-byte aligned, the record 576 with every offset where the
 *              rendering section puts it
 *   decide     we_mod_decide() against we_decide() on the same views: the verdict equal byte for byte, the
 *              views of exactly the masked planes taken and every other one NULL whatever the scratch held,
 *              and the shard equal to an independent recount from the verdict (the deciding rule, both
 *              bitmaps, the pre-stage line, the walk's line; nothing for the default allow)
 *   walk       every row of the walk table, the caps, the trust search against a linear scan
 *   entry      the grammar of one entry at each boundary and one past it
 *   format     RFC 5952 and the dotted quad
 *   acme       the exemption and each way out of it
 *   render     we_attr_render_fast() byte-equal to we_attr_render() over every attribute, state and block
 *              class, and its table equal to we_attr_info()
 *   record     the memo write's one rule, and every renderer the variables read
 *   digest     we_digest16() equal to `sha256sum | cut -c1-16`
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1         /* syscall(2) and the seccomp row's prctl; a superset of POSIX 2008 */
#endif

/* the severity scan's operation count (row R11): one step per bitmap bit tested */
static unsigned g_sev_steps;
#define WE_MOD_SEVERITY_STEP() (g_sev_steps++)

#include "we_module.h"
#include "we_procid.h"
#include "we_sha256.h"
#include "we_writer.h"
#include "walk_classes.h"

#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <valgrind/memcheck.h>

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned g_checks, g_failures;

/*
 * N2's trap: malloc, calloc, realloc and free interposed, aborting while g_alloc_trap is set. Not in a
 * sanitizer build (the sanitizer owns the allocator) and not in the memcheck build (memcheck replaces it).
 */
#ifndef WE_TEST_ALLOC_TRAP
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || defined(WE_TEST_NO_ALLOC_TRAP)
#define WE_TEST_ALLOC_TRAP 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define WE_TEST_ALLOC_TRAP 0
#endif
#endif
#endif
#ifndef WE_TEST_ALLOC_TRAP
#define WE_TEST_ALLOC_TRAP 1
#endif
static int g_alloc_trap;
#if WE_TEST_ALLOC_TRAP
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void  __libc_free(void *);
void *malloc(size_t n)
{
    if (__atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    return __libc_malloc(n);
}
void *calloc(size_t n, size_t m)
{
    if (__atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    return __libc_calloc(n, m);
}
void *realloc(void *p, size_t n)
{
    if (__atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    return __libc_realloc(p, n);
}
void free(void *p)
{
    if (p != NULL && __atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    __libc_free(p);
}
extern void *__libc_memalign(size_t, size_t);
int posix_memalign(void **out, size_t align, size_t n)
{
    if (__atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    *out = __libc_memalign(align, n);
    return *out != NULL ? 0 : 12;            /* ENOMEM */
}
void *aligned_alloc(size_t align, size_t n)
{
    if (__atomic_load_n(&g_alloc_trap, __ATOMIC_RELAXED)) {
        abort();
    }
    return __libc_memalign(align, n);
}
#endif
#ifdef WE_TRACE
/* the trace build's hooks, which this file only needs to link: the scratch compiles under WE_TRACE */
void we_trace_read(const void *p, size_t len)
{
    (void)p;
    (void)len;
}
void we_trace_eval(const void *p, size_t len)
{
    (void)p;
    (void)len;
}
void we_trace_k3(uint64_t t, uint64_t f)
{
    (void)t;
    (void)f;
}
void we_trace_op(uint32_t op, uint64_t t, uint64_t f)
{
    (void)op;
    (void)t;
    (void)f;
}

/* the cachegrind gate's C5+ hook on every counter write (we_module.h's WE_TRACE_COUNT): this suite counts
 * nothing there, so the trace build links; the traced driver records the line */
void we_trace_count(const void *p)
{
    (void)p;
}
#endif

static void check(int ok, const char *fmt, ...)
{
    va_list ap;

    g_checks++;
    if (ok) {
        return;
    }
    g_failures++;
    printf("FAIL ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}
/* the condition first, in a statement of its own: a function's arguments are evaluated in an unspecified
 * order (gcc on x86_64 reads them right to left), so a message reading what the condition's call wrote
 * would otherwise print the value from before the call */
#define CHECK(c, ...) do { int check_ok_ = (c) ? 1 : 0; check(check_ok_, __VA_ARGS__); } while (0)

/* ---------------------------------------------------------------------------------------------- */
/* addresses */

static we_addr_t A(const char *text)
{
    we_addr_t a;
    uint8_t b[16];

    memset(&a, 0, sizeof a);
    memset(b, 0, sizeof b);
    if (inet_pton(AF_INET, text, b) == 1) {
        we_addr_canon(b, 4, &a);
    } else if (inet_pton(AF_INET6, text, b) == 1) {
        we_addr_canon(b, 6, &a);
    } else {
        fprintf(stderr, "test_module: a test address does not parse: %s\n", text);
        exit(2);
    }
    return a;
}

static int addr_eq(const we_addr_t *x, const we_addr_t *y)
{
    return memcmp(x, y, sizeof *x) == 0;
}

/* ---------------------------------------------------------------------------------------------- */
/* layout */

static void t_layout(void)
{
    we_mod_scratch_t s;

#ifndef WE_TRACE
    CHECK(sizeof(we_mod_scratch_t) == 1024u, "layout: the scratch is %zu bytes, not 1,024", sizeof(we_mod_scratch_t));
#endif
    CHECK(_Alignof(we_mod_scratch_t) == 64u, "layout: the scratch's alignment is %zu", _Alignof(we_mod_scratch_t));
    CHECK(((uintptr_t)&s & 63u) == 0u, "layout: a stack scratch is not 64-byte aligned");
    CHECK((uintptr_t)&s.e.view[0] == (uintptr_t)&s && sizeof s.e.view == 64u, "layout: the views are not the first line");
    CHECK(sizeof(we_mod_record_t) == 576u, "layout: the record is %zu bytes, not 576", sizeof(we_mod_record_t));
    CHECK(offsetof(we_mod_record_t, slot) == 128u && offsetof(we_mod_record_t, ctx) == 448u
          && offsetof(we_mod_record_t, digest4) == 512u, "layout: the record's lines moved");
    {
        char raw[WE_MOD_RECORD_ALLOC + 64];
        uint32_t k;
        int ok = 1;

        for (k = 0u; k < 64u; k++) {
            we_mod_record_t *r = we_mod_record_at(raw + k);

            ok &= ((uintptr_t)r & 63u) == 0u && (char *)r >= raw + k
                && (char *)r + sizeof *r <= raw + k + WE_MOD_RECORD_ALLOC;
        }
        CHECK(ok, "layout: the hand-aligned record leaves its 576 + 63 byte allocation");
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the decision */

static const char *const plane_file[8] = {
    "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

typedef struct {
    we_policy_build_t *b;
    we_mod_cfg_t       cfg;
    we_mod_ctx_t       ctx;
    we_handle_t        h[8];
    const we_map_t    *standin[8];
    uint32_t           null_reason[8];
} fixture_t;

static we_policy_directive_t D(uint8_t kind, const char *context, const char *arg)
{
    we_policy_directive_t d;

    d.kind = kind;
    d.context = context;
    d.arg = (const uint8_t *)arg;
    d.len = strlen(arg);
    return d;
}

/* one configuration: the floor's lines and one context's, every plane bound unless `unbound` names it */
static int fixture_make(fixture_t *f, const char *planes, const we_policy_directive_t *d, size_t n,
                        uint8_t unbound, uint64_t now_ms)
{
    we_policy_source_t src;
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    uint32_t p;

    memset(f, 0, sizeof *f);
    memset(&src, 0, sizeof src);
    memset(&e, 0, sizeof e);
    src.d = d;
    src.n = n;
    if (we_policy_build(&src, &env, NULL, &f->b, &e, NULL) != WE_POLICY_OK) {
        printf("FAIL decide: the fixture configuration is refused: %s %s\n", e.what, e.fix);
        g_failures++;
        return -1;
    }
    f->cfg.floor = we_policy_floor(f->b);
    f->cfg.floor_conf = we_policy_conf(f->b, "http");
    f->cfg.floor_status = 403u;
    f->cfg.hh = NULL;
    {
        static we_hh_view_t hh;      /* 64-byte aligned by its type */

        if (we_program_place(f->cfg.floor, &hh) != 0) {
            printf("FAIL decide: the floor's hold-harmless view cannot be placed\n");
            g_failures++;
            return -1;
        }
        f->cfg.hh = &hh;
    }
    for (p = 0u; p < 8u; p++) {
        char path[1024];

        if ((unbound >> p) & 1u) {
            f->cfg.static_reason[p] = WE_MOD_NOMAP_ABSENT;
            continue;
        }
        snprintf(path, sizeof path, "%s/%s.bin", planes, plane_file[p]);
        if (we_handle_publish_plane(&f->h[p], path, now_ms, NULL) != WE_OK) {
            printf("FAIL decide: the fixture plane %s does not publish\n", path);
            g_failures++;
            return -1;
        }
        f->cfg.handle[p] = &f->h[p];
        f->cfg.bound_mask = (uint8_t)(f->cfg.bound_mask | (1u << p));
    }
    f->cfg.null_reason = f->null_reason;
    f->ctx.prog = we_policy_program(f->b, "http/s1");
    f->ctx.conf = we_policy_conf(f->b, "http/s1");
    f->ctx.deny_status = 403u;
    f->ctx.ctr_off = WE_MOD_CTR_FLOOR + f->cfg.floor->rule_count;
    f->ctx.rule_count = f->ctx.prog != NULL ? f->ctx.prog->rule_count : 0u;
    f->ctx.gen_mask = 0x0fu;
    return 0;
}

static void fixture_free(fixture_t *f)
{
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        we_map_t *m = (we_map_t *)(uintptr_t)f->h[p].current;
        uint32_t k;

        if (m != NULL) {
            we_map_close(m);
            free(m);
        }
        for (k = 0u; k < WE_RETIRE_SLOTS; k++) {
            if (f->h[p].retired[k].map != NULL) {
                we_map_close(f->h[p].retired[k].map);
                free(f->h[p].retired[k].map);
            }
        }
    }
    we_policy_build_free(f->b);
}

/* The expected shard, recounted from the verdict by a different route: walk the bits one by one. */
static void recount(const fixture_t *f, const we_verdict_t *v, const we_mod_req_t *q, uint64_t *want, size_t n)
{
    uint32_t r;

    memset(want, 0, n * sizeof *want);
    if (q->note == WE_MOD_NOTE_UNPARSED) {
        want[WE_MOD_CTR_FLOOR_HEADER_UNPARSED]++;
    } else if (q->note == WE_MOD_NOTE_CAPPED) {
        want[WE_MOD_CTR_FLOOR_HEADER_CAPPED]++;
    } else if (q->r.walk == WE_WALK_FLOOR_HEADER_MISSING) {
        want[WE_MOD_CTR_FLOOR_HEADER_MISSING]++;
    }
    if (v->rule != 0u) {
        want[(v->program == WE_VPROG_FLOOR ? WE_MOD_CTR_FLOOR : f->ctx.ctr_off) + v->rule - 1u]++;
    } else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_HOLD_HARMLESS) {
        want[WE_MOD_CTR_HOLD_HARMLESS]++;
    } else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_ACME) {
        want[WE_MOD_CTR_ACME]++;
    } else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_NO_ADDRESS) {
        want[WE_MOD_CTR_NO_ADDRESS]++;
    } else if (v->step == WE_STEP_TENANT) {
        want[WE_MOD_CTR_TENANT]++;
    } else if (v->step == WE_STEP_STALE_TENANT) {
        want[WE_MOD_CTR_STALE_TENANT]++;
    }
    for (r = 0u; r < 256u; r++) {
        if ((v->log_fired[0][r / 8u] >> (r % 8u)) & 1u) {
            want[WE_MOD_CTR_FLOOR + r]++;
        }
        if ((v->log_fired[1][r / 8u] >> (r % 8u)) & 1u) {
            want[f->ctx.ctr_off + r]++;
        }
    }
}

#define SHARD_N 1024u

/*
 * One request through we_mod_decide() and, independently, through we_decide() on views taken by hand.
 * Returns the module's verdict in *out.
 */
static void decide_one(const char *name, fixture_t *f, const we_mod_req_t *q, uint64_t now_ms, we_verdict_t *out,
                       uint64_t *shard)
{
    static we_mod_scratch_t s, ref;
    uint64_t want[SHARD_N];
    uint32_t mask, p;
    int views_ok = 1;

    memset(&s, 0xa5, sizeof s);          /* whatever a previous request left: every read field must be written */
    memset(&ref, 0, sizeof ref);
    memset(shard, 0, SHARD_N * sizeof *shard);
    we_mod_decide(&f->cfg, &f->ctx, &s, shard, q, now_ms);
    mask = ((uint32_t)f->cfg.floor->plane_mask | (f->ctx.prog != NULL ? f->ctx.prog->plane_mask : 0u) | 0x80u)
         & f->cfg.bound_mask;
    for (p = 0u; p < 8u; p++) {
        const we_map_t *want_view = ((mask >> p) & 1u) ? we_current(f->cfg.handle[p]) : NULL;

        views_ok &= s.e.view[p].m == want_view;
        ref.e.view[p].m = want_view;
    }
    CHECK(views_ok, "decide %s: the views are not exactly the masked planes' (mask %02x)", name, mask);
    we_decide(f->cfg.floor, &f->cfg.floor_conf, f->ctx.prog, &f->ctx.conf, f->cfg.hh, &q->r, &ref.e, now_ms, &ref.v);
    CHECK(memcmp(&s.v, &ref.v, 80) == 0, "decide %s: the verdict differs from we_decide()'s", name);
    recount(f, &ref.v, q, want, SHARD_N);
    CHECK(memcmp(shard, want, sizeof want) == 0, "decide %s: the shard differs from the recount", name);
    *out = s.v;
}

static we_mod_req_t REQ(const char *floor, const char *server, uint8_t walk, uint8_t note, uint8_t elig, uint8_t acme)
{
    we_mod_req_t q;

    memset(&q, 0, sizeof q);
    if (floor != NULL) {
        q.r.floor = A(floor);
    }
    q.r.server = A(server != NULL ? server : floor != NULL ? floor : "192.0.2.200");
    q.r.walk = walk;
    q.r.hold_harmless_eligible = elig;
    q.r.acme_exempt = acme;
    q.note = note;
    return q;
}

static void t_decide(const char *planes)
{
    fixture_t f;
    we_verdict_t v;
    uint64_t shard[SHARD_N], now = 1700000000000ull;
    we_mod_req_t q;
    we_policy_directive_t d[] = {
        D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
        D(WE_DIR_FLOOR, "http", "log if listed >= low"),
        D(WE_DIR_MODE, "http", "deny"),
        D(WE_DIR_POLICY, "http/s1", "log if listed >= low"),
        D(WE_DIR_POLICY, "http/s1", "log if country == AF"),
        D(WE_DIR_POLICY, "http/s1", "deny if listed >= medium"),
        D(WE_DIR_POLICY, "http/s1", "allow if anycast"),
        D(WE_DIR_MODE, "http/s1", "deny"),
    };

    if (fixture_make(&f, planes, d, sizeof d / sizeof d[0], 0u, now) != 0) {
        return;
    }
    /* the floor's deny: a tor exit */
    q = REQ("198.51.100.1", NULL, WE_WALK_OK, 0, 0, 0);
    decide_one("floor deny", &f, &q, now, &v, shard);
    CHECK(v.step == WE_STEP_FLOOR && v.action == WE_ACT_DENY && v.rule == 1u && shard[WE_MOD_CTR_FLOOR] == 1u,
          "decide floor deny: step %u action %u rule %u count %" PRIu64, v.step, v.action, v.rule, shard[WE_MOD_CTR_FLOOR]);
    /* a context deny with log bits from both programs: medium on reputation */
    q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
    decide_one("context deny", &f, &q, now, &v, shard);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY && v.rule == 3u
          && shard[WE_MOD_CTR_FLOOR + 1u] == 1u && shard[f.ctx.ctr_off] == 1u && shard[f.ctx.ctr_off + 2u] == 1u,
          "decide context deny: step %u rule %u", v.step, v.rule);
    /* the default allow: an address no plane lists counts nothing */
    q = REQ("0.217.186.65", NULL, WE_WALK_OK, 0, 0, 0);
    decide_one("default allow", &f, &q, now, &v, shard);
    {
        uint64_t sum = 0u;
        uint32_t k;

        for (k = 0u; k < SHARD_N; k++) {
            sum += shard[k];
        }
        CHECK(v.step == WE_STEP_CONTEXT && v.rule == 0u && sum == 0u, "decide default allow: %" PRIu64 " counts", sum);
    }
    /*
     * the pre-stage: hold-harmless, ACME, no address, each on its own line. The fixture planes sit in
     * special-use ranges the hold-harmless table exempts, so every other request here is ineligible.
     */
    q = REQ("198.41.0.4", NULL, WE_WALK_OK, 0, 1, 0);
    decide_one("hold-harmless", &f, &q, now, &v, shard);
    CHECK(v.reason == WE_WHY_HOLD_HARMLESS && shard[WE_MOD_CTR_HOLD_HARMLESS] == 1u, "decide hold-harmless");
    q = REQ("198.41.0.4", NULL, WE_WALK_OK, 0, 0, 0);
    decide_one("hold-harmless ineligible", &f, &q, now, &v, shard);
    CHECK(v.reason != WE_WHY_HOLD_HARMLESS && shard[WE_MOD_CTR_HOLD_HARMLESS] == 0u, "decide hold-harmless ineligible");
    q = REQ("198.51.100.1", NULL, WE_WALK_OK, 0, 0, 1);
    decide_one("acme", &f, &q, now, &v, shard);
    CHECK(v.reason == WE_WHY_ACME && shard[WE_MOD_CTR_ACME] == 1u && shard[WE_MOD_CTR_FLOOR] == 0u, "decide acme");
    q = REQ(NULL, "192.0.2.200", WE_WALK_NO_ADDRESS, 0, 0, 0);
    decide_one("no address", &f, &q, now, &v, shard);
    CHECK(v.reason == WE_WHY_NO_ADDRESS && shard[WE_MOD_CTR_NO_ADDRESS] == 1u, "decide no address");
    /* the tenant's allow, fresh, then stale within the grace */
    q = REQ("0.217.186.66", NULL, WE_WALK_OK, 0, 0, 0);
    decide_one("tenant", &f, &q, now, &v, shard);
    CHECK(v.step == WE_STEP_TENANT && shard[WE_MOD_CTR_TENANT] == 1u, "decide tenant: step %u", v.step);
    ((we_map_t *)(uintptr_t)f.h[7].current)->valid_until_ms = now - 1000u;
    decide_one("stale tenant", &f, &q, now, &v, shard);
    CHECK(v.step == WE_STEP_STALE_TENANT && shard[WE_MOD_CTR_STALE_TENANT] == 1u, "decide stale tenant: step %u", v.step);
    ((we_map_t *)(uintptr_t)f.h[7].current)->valid_until_ms = 0u;
    /* the walk's one line: missing, unparsed, capped, each alone, beside the decision's own */
    q = REQ("0.217.186.65", NULL, WE_WALK_FLOOR_HEADER_MISSING, 0, 0, 0);
    decide_one("header missing", &f, &q, now, &v, shard);
    CHECK(shard[WE_MOD_CTR_FLOOR_HEADER_MISSING] == 1u && shard[WE_MOD_CTR_FLOOR_HEADER_UNPARSED] == 0u, "decide header missing");
    q = REQ("0.217.186.65", NULL, WE_WALK_FLOOR_HEADER_MISSING, WE_MOD_NOTE_UNPARSED, 0, 0);
    decide_one("header unparsed", &f, &q, now, &v, shard);
    CHECK(shard[WE_MOD_CTR_FLOOR_HEADER_UNPARSED] == 1u && shard[WE_MOD_CTR_FLOOR_HEADER_MISSING] == 0u,
          "decide header unparsed: exactly one pre-stage line, not also missing");
    q = REQ("1.179.116.132", NULL, WE_WALK_OK, WE_MOD_NOTE_CAPPED, 0, 0);
    decide_one("header capped", &f, &q, now, &v, shard);
    CHECK(shard[WE_MOD_CTR_FLOOR_HEADER_CAPPED] == 1u, "decide header capped");
    /* the server's own address differs from the floor's: two slots */
    q = REQ("0.217.186.65", "1.179.116.132", WE_WALK_OK, 0, 0, 0);
    decide_one("two addresses", &f, &q, now, &v, shard);
    CHECK(v.rule == 3u && v.step == WE_STEP_CONTEXT, "decide two addresses: the context judged the server's address");
    fixture_free(&f);

    /* allow-by-unknown counts under its rule; an unbound plane's view is never taken */
    {
        we_policy_directive_t d2[] = {
            D(WE_DIR_POLICY, "http/s1", "allow if tor_exit"),
            D(WE_DIR_POLICY, "http/s1", "deny if listed >= low"),
            D(WE_DIR_MODE, "http/s1", "deny"),
        };

        if (fixture_make(&f, planes, d2, sizeof d2 / sizeof d2[0], 1u << 1, now) == 0) {
            q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
            decide_one("allow-by-unknown", &f, &q, now, &v, shard);
            CHECK(v.reason == WE_WHY_ALLOW_BY_UNKNOWN && v.rule == 1u && shard[f.ctx.ctr_off] == 1u,
                  "decide allow-by-unknown: reason %u rule %u", v.reason, v.rule);
            fixture_free(&f);
        }
    }
    /* mode log: the deny is a log bit (a would-deny), never a decision; mode off still runs the floor */
    {
        we_policy_directive_t d3[] = {
            D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
            D(WE_DIR_MODE, "http", "deny"),
            D(WE_DIR_POLICY, "http/s1", "deny if listed >= low"),
            D(WE_DIR_MODE, "http/s1", "log"),
        };

        if (fixture_make(&f, planes, d3, sizeof d3 / sizeof d3[0], 0u, now) == 0) {
            q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
            decide_one("would-deny", &f, &q, now, &v, shard);
            CHECK(v.enforce == 0u && v.rule == 0u && ((v.log_fired[1][0] & 1u) != 0u) && shard[f.ctx.ctr_off] == 1u,
                  "decide would-deny: enforce %u rule %u", v.enforce, v.rule);
            fixture_free(&f);
        }
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the trust table and the walk */

typedef struct {
    we_mod_iv4_t v4[16];
    we_mod_iv6_t v6[16];
    we_mod_trust_t t;
} trust_t;

static void trust_v4(trust_t *t, const char *lo, const char *hi)
{
    we_addr_t a = A(lo), b = A(hi);

    t->v4[t->t.n4].lo = (uint32_t)a.b[0] << 24 | (uint32_t)a.b[1] << 16 | (uint32_t)a.b[2] << 8 | a.b[3];
    t->v4[t->t.n4].hi = (uint32_t)b.b[0] << 24 | (uint32_t)b.b[1] << 16 | (uint32_t)b.b[2] << 8 | b.b[3];
    t->t.n4++;
    t->t.v4 = t->v4;
    t->t.v6 = t->v6;
}

static void trust_v6(trust_t *t, const char *lo, const char *hi)
{
    we_addr_t a = A(lo), b = A(hi);
    uint32_t k;
    uint64_t w[4] = { 0u, 0u, 0u, 0u };

    for (k = 0u; k < 8u; k++) {
        w[0] = w[0] << 8 | a.b[k];
        w[1] = w[1] << 8 | a.b[8u + k];
        w[2] = w[2] << 8 | b.b[k];
        w[3] = w[3] << 8 | b.b[8u + k];
    }
    t->v6[t->t.n6].lo_hi = w[0];
    t->v6[t->t.n6].lo_lo = w[1];
    t->v6[t->t.n6].hi_hi = w[2];
    t->v6[t->t.n6].hi_lo = w[3];
    t->t.n6++;
    t->t.v4 = t->v4;
    t->t.v6 = t->v6;
}

typedef struct {
    const char *name;
    const char *peer;           /* NULL: a unix-socket peer */
    int         header_set;
    uint32_t    hops;
    const char *lines[20];      /* oldest first; NULL ends; "<none>" for no line at all */
    int         older;
    const char *want_floor;     /* NULL: no address */
    uint8_t     walk, eligible, note;
} walk_case_t;

static void walk_run(const trust_t *t, const walk_case_t *c)
{
    we_mod_line_t lines[20];
    uint32_t n = 0u;
    we_mod_walk_t w;
    we_addr_t peer, want;

    while (n < 20u && c->lines[n] != NULL) {
        lines[n].p = (const uint8_t *)c->lines[n];
        lines[n].len = strlen(c->lines[n]);
        n++;
    }
    if (c->peer != NULL) {
        peer = A(c->peer);
    }
    we_mod_walk(&t->t, c->hops, c->header_set, c->peer != NULL ? &peer : NULL, lines, n, c->older, &w);
    if (c->want_floor != NULL) {
        want = A(c->want_floor);
    } else {
        memset(&want, 0, sizeof want);
        if (c->walk != WE_WALK_NO_ADDRESS) {
            want.family = 6u;    /* a trusted unix peer is judged as `::` */
        }
    }
    CHECK(addr_eq(&w.floor, &want) && w.walk == c->walk && w.eligible == c->eligible && w.note == c->note,
          "walk %s: judged %u.%u.%u.%u... walk %u eligible %u note %u, want walk %u eligible %u note %u", c->name,
          w.floor.b[0], w.floor.b[1], w.floor.b[2], w.floor.b[3], w.walk, w.eligible, w.note, c->walk, c->eligible,
          c->note);
    CHECK(w.entries <= WE_MOD_WALK_ENTRIES && w.bytes <= WE_MOD_WALK_BYTES && w.searches <= 1u + WE_MOD_WALK_ENTRIES,
          "walk %s: the bound: %u entries, %u bytes, %u searches", c->name, w.entries, w.bytes, w.searches);
    if (w.line >= 0) {
        we_addr_t back;

        CHECK((uint32_t)w.line < n && w.off + w.len <= lines[w.line].len
              && we_mod_entry_parse(lines[w.line].p + w.off, w.len, &back) == 0 && addr_eq(&back, &w.floor),
              "walk %s: the span does not hold the judged address", c->name);
    }
}

static void t_walk(void)
{
    trust_t t;
    static const char *const f17 =
        "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9, "
        "10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15, 10.0.0.16, 10.0.0.17";
    static const char *const f16 =
        "10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9, "
        "10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15, 10.0.0.16, 10.0.0.17";
    char big[2100];
    const walk_case_t cases[] = {
        { "untrusted peer", "192.0.2.9", 1, 0, { "203.0.113.5", NULL }, 0, "192.0.2.9", WE_WALK_OK, 1, 0 },
        { "no header configured", "10.0.0.1", 0, 0, { "203.0.113.5", NULL }, 0, "10.0.0.1", WE_WALK_OK, 1, 0 },
        { "header absent", "10.0.0.1", 1, 0, { NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 1, 0 },
        { "empty value", "10.0.0.1", 1, 0, { "", NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "commas only", "10.0.0.1", 1, 0, { " , ,", NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "rightmost bad", "10.0.0.1", 1, 0, { "203.0.113.5, junk", NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "untrusted, no hop", "10.0.0.1", 1, 0, { "203.0.113.5", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "past a skipped hop", "10.0.0.1", 1, 0, { "203.0.113.5, 10.0.0.7", NULL }, 0, "203.0.113.5", WE_WALK_OK, 0, 0 },
        { "C, junk, T1", "10.0.0.1", 1, 0, { "203.0.113.5, junk, 10.0.0.7", NULL }, 0, "10.0.0.7", WE_WALK_OK, 0, WE_MOD_NOTE_UNPARSED },
        { "all trusted, exhausted", "10.0.0.1", 1, 0, { "10.0.0.8, 10.0.0.7", NULL }, 0, "10.0.0.7", WE_WALK_OK, 0, 0 },
        { "17 trusted, skip mode", "10.0.0.1", 1, 0, { f17, NULL }, 0, "10.0.0.17", WE_WALK_OK, 0, WE_MOD_NOTE_CAPPED },
        { "16 trusted, exhausted", "10.0.0.1", 1, 0, { f16, NULL }, 0, "10.0.0.17", WE_WALK_OK, 0, 0 },
        { "hops 1", "10.0.0.1", 1, 1, { "203.0.113.5, 198.51.100.7", NULL }, 0, "198.51.100.7", WE_WALK_OK, 1, 0 },
        { "hops 2", "10.0.0.1", 1, 2, { "203.0.113.5, 198.51.100.7", NULL }, 0, "203.0.113.5", WE_WALK_OK, 0, 0 },
        { "hops 2, one entry", "10.0.0.1", 1, 2, { "198.51.100.7", NULL }, 0, "198.51.100.7", WE_WALK_OK, 0, WE_MOD_NOTE_UNPARSED },
        { "hops 3, the cap", "10.0.0.1", 1, 3, { "198.51.100.7", "198.51.100.8", NULL }, 1, "198.51.100.7", WE_WALK_OK, 0, WE_MOD_NOTE_CAPPED },
        { "two lines, newest last", "10.0.0.1", 1, 0, { "203.0.113.66", "203.0.113.5", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "an empty last line", "10.0.0.1", 1, 0, { "203.0.113.5, 10.0.0.7", "", NULL }, 0, "203.0.113.5", WE_WALK_OK, 0, 0 },
        { "oldest kept line, older dropped", "10.0.0.1", 1, 0, { "10.0.0.9", NULL }, 1, "10.0.0.9", WE_WALK_OK, 0, WE_MOD_NOTE_CAPPED },
        { "a port", "10.0.0.1", 1, 0, { "203.0.113.5:443", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "bracketed v6 port", "10.0.0.1", 1, 0, { "[2001:db8::7]:8080", NULL }, 0, "2001:db8::7", WE_WALK_OK, 1, 0 },
        { "v6 unbracketed with a port reads as one address", "10.0.0.1", 1, 0, { "2001:db8::1:443", NULL }, 0, "2001:db8::1:443", WE_WALK_OK, 1, 0 },
        { "a mapped peer against a v4 trust entry", "::ffff:10.0.0.1", 1, 0, { "203.0.113.5", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "a mapped entry judged as v4", "10.0.0.1", 1, 0, { "::ffff:203.0.113.5", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "a zone id", "10.0.0.1", 1, 0, { "fe80::1%eth0", NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "unix, trusted, absent", NULL, 1, 0, { NULL }, 0, NULL, WE_WALK_FLOOR_HEADER_MISSING, 0, 0 },
        { "unix, trusted, present", NULL, 1, 0, { "203.0.113.5", NULL }, 0, "203.0.113.5", WE_WALK_OK, 1, 0 },
        { "unix, trusted, bad", NULL, 1, 0, { "junk", NULL }, 0, NULL, WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "unix, no header", NULL, 0, 0, { NULL }, 0, NULL, WE_WALK_NO_ADDRESS, 0, 0 },
        { "a 2,000-byte entry", "10.0.0.1", 1, 0, { big, NULL }, 0, "10.0.0.1", WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED },
        { "a 2,000-byte entry left of a trusted one", "10.0.0.1", 1, 0, { big, "10.0.0.7", NULL }, 0, "10.0.0.7", WE_WALK_OK, 0, WE_MOD_NOTE_UNPARSED },
    };
    size_t i;

    memset(&t, 0, sizeof t);
    trust_v4(&t, "10.0.0.0", "10.255.255.255");
    trust_v6(&t, "2001:db8:ffff::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff");
    t.t.unix_ok = 1u;
    memset(big, '1', sizeof big - 1u);
    big[sizeof big - 1u] = '\0';
    for (i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        walk_run(&t, &cases[i]);
    }
    /* the byte budget: one line of OWS before the proxy's entry */
    {
        static char pad[1200];
        walk_case_t c = { "1,024 bytes of OWS before the entry", "10.0.0.1", 1, 0, { pad, NULL }, 0, "10.0.0.1",
                          WE_WALK_FLOOR_HEADER_MISSING, 0, WE_MOD_NOTE_UNPARSED };

        memset(pad, ' ', sizeof pad - 1u);
        memcpy(pad, "203.0.113.5", 11);
        walk_run(&t, &c);
    }
    /* the trust search against a linear scan, over nested, adjacent and duplicate-merged intervals */
    {
        trust_t m;
        uint32_t a, bad = 0u;

        memset(&m, 0, sizeof m);
        trust_v4(&m, "10.0.0.0", "10.0.255.255");
        trust_v4(&m, "10.1.0.0", "10.1.255.255");
        trust_v4(&m, "10.3.0.0", "10.3.0.0");
        trust_v4(&m, "192.0.2.0", "192.0.2.255");
        for (a = 0x09ffff00u; a < 0x0a040100u; a += 0x37u) {
            we_addr_t x;
            uint32_t k;
            int lin = 0;

            memset(&x, 0, sizeof x);
            x.family = 4u;
            x.b[0] = (uint8_t)(a >> 24);
            x.b[1] = (uint8_t)(a >> 16);
            x.b[2] = (uint8_t)(a >> 8);
            x.b[3] = (uint8_t)a;
            for (k = 0u; k < m.t.n4; k++) {
                lin |= a >= m.v4[k].lo && a <= m.v4[k].hi;
            }
            bad += (uint32_t)(we_mod_trusted(&m.t, &x, NULL) != lin);
        }
        CHECK(bad == 0u, "walk: the binary search disagrees with a linear scan %u times", bad);
    }
}


/* the configured list into the walk's table: merged, canonicalised, against a linear scan of the list */
static void t_trust_build(void)
{
    static const struct { const char *list[6]; const char *addr; int want; } c[] = {
        { { "10.0.0.0/8", "10.1.0.0/16" }, "10.2.0.1", 1 },
        { { "10.0.0.0/8", "10.1.0.0/16" }, "10.1.2.3", 1 },
        { { "10.0.0.0/9", "10.128.0.0/9" }, "10.200.0.1", 1 },
        { { "10.0.0.0/9", "10.128.0.0/9" }, "11.0.0.0", 0 },
        { { "192.0.2.0/24", "192.0.2.0/24" }, "192.0.2.7", 1 },
        { { "0.0.0.0/0" }, "203.0.113.9", 1 },
        { { "0.0.0.0/0" }, "2001:db8::1", 0 },
        { { "::/0" }, "2001:db8::1", 1 },
        { { "::ffff:10.0.0.0/104" }, "::ffff:10.0.0.1", 1 },
        { { "::ffff:10.0.0.0/104" }, "10.0.0.1", 1 },
        { { "2001:db8::/48", "2001:db8:0:1::/64" }, "2001:db8:0:2::5", 1 },
        { { "2001:db8::/33", "2001:db8:8000::/33" }, "2001:db8:ffff::1", 1 },
        { { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127" }, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1 },
        { { "192.0.2.5" }, "192.0.2.5", 1 },
        { { "192.0.2.5" }, "192.0.2.6", 0 },
    };
    size_t i;

    for (i = 0u; i < sizeof c / sizeof c[0]; i++) {
        we_mod_trust_t t;
        we_mod_trust_report_t rep;
        size_t n = 0u;
        char err[256];
        we_addr_t a = A(c[i].addr);

        while (n < 6u && c[i].list[n] != NULL) {
            n++;
        }
        if (we_mod_trust_build(c[i].list, n, &t, &rep, err, sizeof err) != 0) {
            CHECK(0, "trust build %s: refused: %s", c[i].list[0], err);
            continue;
        }
        CHECK(we_mod_trusted(&t, &a, NULL) == c[i].want, "trust build %s ...: %s %s", c[i].list[0], c[i].addr,
              c[i].want ? "not trusted" : "trusted");
        we_mod_trust_free(&t);
    }
    {
        /* no list at all: the table is built from nothing and trusts nothing, and the build touches no array
         * (it once sorted a NULL one, which qsort's contract forbids: fuzz_walk's "no-trust-list" seed) */
        we_mod_trust_t t;
        we_mod_trust_report_t rep;
        char err[256];
        we_addr_t a = A("10.0.0.1");

        CHECK(we_mod_trust_build(NULL, 0u, &t, &rep, err, sizeof err) == 0 && t.n4 == 0u && t.n6 == 0u && t.unix_ok == 0u
              && rep.configured4 == 0u && rep.configured6 == 0u && we_mod_trusted(&t, &a, NULL) == 0,
              "trust build: an empty list does not build to a table that trusts nothing");
        we_mod_trust_free(&t);
    }
    {
        const char *l[] = { "10.0.0.0/9", "10.128.0.0/9", "10.0.0.0/8", "unix:" };
        we_mod_trust_t t;
        we_mod_trust_report_t rep;
        char err[256];

        CHECK(we_mod_trust_build(l, 4u, &t, &rep, err, sizeof err) == 0 && t.n4 == 1u && t.unix_ok == 1u,
              "trust build: adjacent and nested prefixes are not one interval (%u)", t.n4);
        we_mod_trust_free(&t);
    }
    {
        const char *l[] = { "::/0", "10.0.0.0/8", "0.0.0.0/8" };
        we_mod_trust_t t;
        we_mod_trust_report_t rep;
        char err[256];

        CHECK(we_mod_trust_build(l, 3u, &t, &rep, err, sizeof err) == 0 && rep.covers_mapped == 1u && rep.broad == 3u,
              "trust build: the warnings: %u covering ::ffff:0:0/96, %u broad", rep.covers_mapped, rep.broad);
        we_mod_trust_free(&t);
    }
    {
        static const char *const bad[] = { "10.0.0.0/33", "10.0.0.0/x", "example.com", "::/129", "10.0.0.0/", "fe80::1%eth0" };
        size_t k;

        for (k = 0u; k < sizeof bad / sizeof bad[0]; k++) {
            we_mod_trust_t t;
            char err[256];

            CHECK(we_mod_trust_build(&bad[k], 1u, &t, NULL, err, sizeof err) != 0 && strstr(err, bad[k]) != NULL,
                  "trust build: \"%s\" is accepted, or refused without naming it", bad[k]);
        }
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the grammar of one entry */

static void t_entry(void)
{
    static const struct { const char *s; const char *want; } ok[] = {
        { "1.2.3.4", "1.2.3.4" }, { "255.255.255.255", "255.255.255.255" }, { "0.0.0.0", "0.0.0.0" },
        { "1.2.3.4:0", "1.2.3.4" }, { "1.2.3.4:65535", "1.2.3.4" }, { "1.2.3.4:00080", "1.2.3.4" },
        { "::1", "::1" }, { "::", "::" }, { "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0" },
        { "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304" }, { "::1.2.3.4", "::102:304" },
        { "0000:0000:0000:0000:0000:ffff:255.255.255.255", "255.255.255.255" },
        { "[2001:db8::1]", "2001:db8::1" }, { "[2001:db8::1]:443", "2001:db8::1" }, { "2001:DB8::A", "2001:db8::a" },
        { "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8" }, { "::ffff:192.0.2.1", "192.0.2.1" },
        { "[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535", "255.255.255.255" },
    };
    static const char *const bad[] = {
        "", "1.2.3", "1.2.3.4.5", "1.2.3.04", "01.2.3.4", "256.1.1.1", "1.2.3.4:", "1.2.3.4:65536", "1.2.3.4:123456",
        "[1.2.3.4]", "[1.2.3.4]:80", "1::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:1.2.3.4", ":::1", "::1.2.3.04", "12345::1",
        "1:2:3:4:5:6:7", "1::2::3", "fe80::1%eth0", "[fe80::1%25eth0]:80", "unknown", "for=1.2.3.4", "_hidden",
        "1:", ":1", "[::1", "[::1]x", "[::1]:", "[::1]:65536", "1.2.3.4 ", " 1.2.3.4", "1.2.3.4:8 0",
        "[0000:0000:0000:0000:0000:ffff:255.255.255.255]:655350",
    };
    size_t i;

    for (i = 0u; i < sizeof ok / sizeof ok[0]; i++) {
        we_addr_t a, w = A(ok[i].want);
        int rc = we_mod_entry_parse((const uint8_t *)ok[i].s, strlen(ok[i].s), &a);

        CHECK(rc == 0 && addr_eq(&a, &w), "entry \"%s\": not accepted as %s", ok[i].s, ok[i].want);
    }
    for (i = 0u; i < sizeof bad / sizeof bad[0]; i++) {
        we_addr_t a;

        CHECK(we_mod_entry_parse((const uint8_t *)bad[i], strlen(bad[i]), &a) != 0, "entry \"%s\": accepted", bad[i]);
    }
    CHECK(strlen("[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535") == WE_MOD_ENTRY_MAX,
          "entry: the longest entry is not the 53-byte bound");
    /* every IPv6address alternative at its group-count boundary and one past it */
    {
        static const char *const in[] = {
            "1:2:3:4:5:6:7:8", "::2:3:4:5:6:7:8", "1::3:4:5:6:7:8", "1:2::4:5:6:7:8", "1:2:3::5:6:7:8",
            "1:2:3:4::6:7:8", "1:2:3:4:5::7:8", "1:2:3:4:5:6::8", "1:2:3:4:5:6:7::",
        };
        static const char *const out[] = {
            "1:2:3:4:5:6:7:8:9", "::1:2:3:4:5:6:7:8", "1::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8::",
        };

        for (i = 0u; i < sizeof in / sizeof in[0]; i++) {
            we_addr_t a;

            CHECK(we_mod_entry_parse((const uint8_t *)in[i], strlen(in[i]), &a) == 0, "entry \"%s\": refused", in[i]);
        }
        for (i = 0u; i < sizeof out / sizeof out[0]; i++) {
            we_addr_t a;

            CHECK(we_mod_entry_parse((const uint8_t *)out[i], strlen(out[i]), &a) != 0, "entry \"%s\": accepted", out[i]);
        }
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the formatter */

static void t_format(void)
{
    static const struct { const char *in, *want; } c[] = {
        { "::102:304", "::102:304" }, { "2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1" },
        { "2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1" }, { "::ffff:192.0.2.1", "192.0.2.1" },
        { "::ffff:0:c000:201", "::ffff:0:c000:201" }, { "64:ff9b::c000:201", "64:ff9b::c000:201" },
        { "::", "::" }, { "::1", "::1" }, { "1::", "1::" }, { "2001:DB8::A:0:0:0:0", "2001:db8:0:a::" },
        { "0:0:1:0:0:0:1:0", "0:0:1::1:0" }, { "1:0:0:2:0:0:3:4", "1::2:0:0:3:4" },
        { "192.0.2.1", "192.0.2.1" }, { "0.0.0.0", "0.0.0.0" }, { "255.255.255.255", "255.255.255.255" },
        { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
        { "fe80::1:0:0:0", "fe80::1:0:0:0" },
    };
    size_t i;

    for (i = 0u; i < sizeof c / sizeof c[0]; i++) {
        we_addr_t a = A(c[i].in);
        char out[WE_ADDR_TEXT_MAX];
        size_t n = we_addr_format(&a, out);

        CHECK(strcmp(out, c[i].want) == 0 && n == strlen(out), "format %s: \"%s\", want \"%s\"", c[i].in, out, c[i].want);
    }
    /* every printed form reads back as the same address */
    {
        uint32_t k, bad = 0u;

        for (k = 0u; k < 4096u; k++) {
            we_addr_t a, b;
            char out[WE_ADDR_TEXT_MAX];
            uint32_t g;

            memset(&a, 0, sizeof a);
            a.family = 6u;
            for (g = 0u; g < 8u; g++) {
                /* each group zero or not by the bits of k, so every run shape is covered */
                uint32_t v = ((k >> g) & 1u) != 0u ? 0x1u + g * 0x1111u : 0u;

                a.b[2u * g] = (uint8_t)(v >> 8);
                a.b[2u * g + 1u] = (uint8_t)v;
            }
            if (a.b[0] == 0 && a.b[1] == 0 && a.b[2] == 0 && a.b[3] == 0 && a.b[4] == 0 && a.b[5] == 0 && a.b[6] == 0
                    && a.b[7] == 0 && a.b[8] == 0 && a.b[9] == 0 && a.b[10] == 0xff && a.b[11] == 0xff) {
                continue;
            }
            we_addr_format(&a, out);
            bad += (uint32_t)(we_mod_parse6((const uint8_t *)out, strlen(out), b.b) != 0 || memcmp(a.b, b.b, 16) != 0);
        }
        CHECK(bad == 0u, "format: %u printed forms do not read back", bad);
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* ACME */

static int acme(const char *m, const char *target, const char *norm)
{
    return we_mod_acme((const uint8_t *)m, strlen(m), (const uint8_t *)target, strlen(target), (const uint8_t *)norm,
                       strlen(norm));
}

static void t_acme(void)
{
    const char *tok = "/.well-known/acme-challenge/Ab_9-x";

    CHECK(acme("GET", tok, tok) == 1, "acme: the exact form is not exempt");
    CHECK(acme("HEAD", tok, tok) == 1, "acme: HEAD is not exempt");
    CHECK(acme("GET", "http://example.com/.well-known/acme-challenge/Ab_9-x", tok) == 1, "acme: the absolute form is not exempt");
    CHECK(acme("GET", "HTTPS://example.com:8443/.well-known/acme-challenge/Ab_9-x", tok) == 1, "acme: an absolute form with a port");
    CHECK(acme("POST", tok, tok) == 0, "acme: POST is exempt");
    CHECK(acme("get", tok, tok) == 0, "acme: a lower-case method is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/Ab_9-x?x=1", tok) == 0, "acme: a query is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/Ab_9-x?", tok) == 0, "acme: a bare ? is exempt");
    CHECK(acme("GET", "/.well-known/%2e/acme-challenge/Ab_9-x", tok) == 0, "acme: a %%2e dot segment is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/%41b_9-x", tok) == 0, "acme: a percent-encoded token is exempt");
    CHECK(acme("GET", "//.well-known/acme-challenge/Ab_9-x", "//.well-known/acme-challenge/Ab_9-x") == 0
          && acme("GET", "//.well-known/acme-challenge/Ab_9-x", tok) == 0, "acme: a leading // is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/a/b", "/.well-known/acme-challenge/a/b") == 0, "acme: two segments are exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/", "/.well-known/acme-challenge/") == 0, "acme: no token is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/a.b", "/.well-known/acme-challenge/a.b") == 0, "acme: a dot in the token is exempt");
    CHECK(acme("GET", "/.well-known/acme-challenge/missing", "/index.php") == 0, "acme: a rewritten request is exempt");
    CHECK(acme("GET", "example.com/.well-known/acme-challenge/Ab_9-x", tok) == 0, "acme: a scheme-less authority is exempt");
}

/* ---------------------------------------------------------------------------------------------- */
/* the request path's renderer against the core's */

/*
 * The rendered words' lengths are tables beside the words (we_mod_enum_len, we_mod_level_len,
 * we_mod_plane_word_len), so a rendering never measures a word at run time; each length must be its
 * word's, over every value each table holds. WE_MOD_TEST_LEN_OFF, one length off by one, fails by name.
 */
static void t_word_lengths(void)
{
    static const uint32_t dom[4] = { WE_MOD_DOM_RPKI, WE_MOD_DOM_REASON, WE_MOD_DOM_REP, WE_MOD_DOM_RIR };
    uint32_t d, v, bad = 0u;

    for (d = 0u; d < 4u; d++) {
        for (v = 0u; v < 8u; v++) {
            const char *w = we_mod_enum_word(dom[d], v);

            if (we_mod_enum_len(dom[d], v) != strlen(w)) {
                printf("FAIL word lengths: enum %u value %u is \"%s\" (%zu bytes), its table says %zu\n", dom[d], v, w,
                       strlen(w), we_mod_enum_len(dom[d], v));
                bad++;
            }
        }
    }
    for (v = 0u; v < 16u; v++) {
        if (we_mod_level_len(v) != strlen(we_mod_level_word(v))) {
            printf("FAIL word lengths: level %u is \"%s\" (%zu bytes), its table says %zu\n", v, we_mod_level_word(v),
                   strlen(we_mod_level_word(v)), we_mod_level_len(v));
            bad++;
        }
    }
    for (v = 0u; v < 8u; v++) {
        if (we_mod_plane_word_len(v) != strlen(we_mod_plane_word(v))) {
            printf("FAIL word lengths: plane %u is \"%s\", its table says %zu\n", v, we_mod_plane_word(v), we_mod_plane_word_len(v));
            bad++;
        }
    }
    CHECK(bad == 0u, "word lengths: %u length(s) are not their word's", bad);
}

static void t_render(void)
{
    uint32_t i, st, k, mism = 0u, cases = 0u;
    static const uint8_t bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x0f, 0x10, 0x3f, 0x40, 0x7f, 0x80,
                                     0x81, 0x84, 0x85, 0xc4, 0xff };

    CHECK(we_attr_count() == WE_MOD_ATTRS, "render: the core has %u attributes, the table %u", we_attr_count(), WE_MOD_ATTRS);
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        we_attr_info_t info;
        const we_mod_attr_t *t = we_mod_attr(i);

        we_attr_info(i, &info);
        CHECK(strcmp(info.name, t->name) == 0 && info.plane_id == t->plane + 1u && info.cls == t->cls
              && info.off == t->off && info.mask == t->mask, "render: attribute %u (%s) differs from we_attr_info()", i, t->name);
    }
    CHECK(we_mod_attr(WE_MOD_ATTRS) == NULL, "render: an index past the table is accepted");
    for (i = 0u; i < WE_MOD_ATTRS; i++) {
        const we_mod_attr_t *t = we_mod_attr(i);

        for (st = 0u; st <= WE_ST_REVOKED; st++) {
            for (k = 0u; k < sizeof bytes / sizeof bytes[0]; k++) {
                uint32_t lap;

                for (lap = 0u; lap < 2u; lap++) {
                    uint8_t b[16];
                    char want[64], asn[WE_MOD_ASN_BUF];
                    const char *s = NULL;
                    size_t n = 0u;

                    memset(b, bytes[k], sizeof b);
                    b[14] = (uint8_t)lap;
                    b[15] = 0u;
                    if (t->cls == WE_ATTR_COUNTRY) {
                        /* a code the table knows, one it does not, 0, and past 999 */
                        uint16_t c = (uint16_t)(k % 4u == 0u ? 528u : k % 4u == 1u ? 0u : k % 4u == 2u ? 999u : 1000u + k);

                        memcpy(b + t->off, &c, 2);
                    }
                    if (t->cls == WE_ATTR_ASN && k % 3u == 0u) {
                        uint32_t a = 0xffffffffu;

                        memcpy(b + t->off, &a, 4);
                    }
                    cases++;
                    we_attr_render(i, b, st, want, sizeof want);
                    if (we_attr_render_fast(i, b, st, asn, &s, &n) != 0 || n != strlen(want) || memcmp(s, want, n) != 0) {
                        if (mism++ < 8u) {
                            printf("FAIL render %s state %u byte %02x: \"%.*s\", the core writes \"%s\"\n", t->name, st,
                                   bytes[k], (int)n, s != NULL ? s : "", want);
                        }
                    }
                }
            }
        }
    }
    CHECK(mism == 0u, "render: %u of %u classes differ from we_attr_render()", mism, cases);
    /* the two classes POLICY.md section 3.9 changed, by their words as well as by equality */
    {
        uint8_t b[16];
        const char *s = NULL;
        size_t n = 0u;
        char asn[WE_MOD_ASN_BUF];
        uint16_t c;

        memset(b, 0, sizeof b);
        c = 999u;   /* in range, not assigned */
        memcpy(b + 4, &c, 2);
        CHECK(we_attr_render_fast(21u, b, WE_ST_FRESH_HIT, asn, &s, &n) == 0 && n == 12u && memcmp(s, "undetermined", 12) == 0, "render: an unknown country code is \"%.*s\"", (int)n, s != NULL ? s : "");
        c = 65535u;
        memcpy(b + 4, &c, 2);
        CHECK(we_attr_render_fast(22u, b, WE_ST_FRESH_HIT, asn, &s, &n) == 0 && n == 12u && memcmp(s, "undetermined", 12) == 0, "render: a raw 65535 is \"%.*s\"", (int)n, s != NULL ? s : "");
        c = 528u;
        memcpy(b + 4, &c, 2);
        CHECK(we_attr_render_fast(21u, b, WE_ST_FRESH_HIT, asn, &s, &n) == 0 && n == 2u && memcmp(s, "NL", 2) == 0, "render: 528 is \"%.*s\"", (int)n, s != NULL ? s : "");
        memset(b, 0, sizeof b);
        b[0] = WE_MF_TENANT_ALLOW;
        b[14] = 1u;                        /* past the 48-hour grace */
        CHECK(we_attr_render_fast(14u, b, WE_ST_STALE_HIT, asn, &s, &n) == 0 && n == 11u && memcmp(s, "lapsed:true", 11) == 0, "render: a tenant past its grace is \"%.*s\"", (int)n, s != NULL ? s : "");
        b[14] = 0u;
        CHECK(we_attr_render_fast(14u, b, WE_ST_STALE_HIT, asn, &s, &n) == 0 && n == 10u && memcmp(s, "stale:true", 10) == 0, "render: a tenant within its grace is \"%.*s\"", (int)n, s != NULL ? s : "");
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the record */

static void t_record(void)
{
    static we_mod_record_t rec;
    we_mod_cfg_t c;
    we_mod_ctx_t x;
    we_mod_ctx_cold_t xc;
    we_mod_cfg_cold_t cc;
    static const char *const fid[1] = { "floor:1" }, *const ftx[1] = { "deny if tor_exit" };
    static const char *const cid[2] = { "ctx:1", "ctx:2" }, *const ctx_text[2] = { "log if tor_exit", "deny if listed >= high" };
    static we_map_t standin, live, live2;
    static uint8_t sev[4] = { 0x00, 0x44, 0x83, 0x05 };
    /* each bound plane's word as bind leaves it (loading) or as its writer stored it since; never 0 */
    uint32_t nr[8] = { WE_MOD_NOMAP_LOADING, WE_MOD_NOMAP_LOADING, 0, WE_MOD_NOMAP_REFUSED, WE_MOD_NOMAP_LOADING, 0, 0,
                       WE_MOD_NOMAP_LOADING };
    we_handle_t h[8];
    we_memo_entry_t e;
    char buf[WE_MOD_LOGGED_MAX];
    /* set, though every renderer arm writes both: gcc 13 at -O2 on x86_64 cannot see through the inlined
     * renderer and reports them used uninitialised in the CHECK below, which -Werror makes fatal */
    const char *s = NULL;
    size_t n = 0u;

    memset(&c, 0, sizeof c);
    memset(&x, 0, sizeof x);
    memset(h, 0, sizeof h);
    memset(&cc, 0, sizeof cc);
    memset(&xc, 0, sizeof xc);
    cc.program_none = "floor:- ctx:-";
    cc.rule_id = fid;
    cc.rule_text = ftx;
    cc.rule_count = 1u;
    xc.program_ctx = "floor:ba7816bf8f01cfea ctx:ba7816bf8f01cfea";
    xc.program_floor = "floor:ba7816bf8f01cfea ctx:-";
    xc.rule_id = cid;
    xc.rule_text = ctx_text;
    xc.rule_count = 2u;
    c.cold = &cc;
    x.cold = &xc;
    x.gen_mask = 0x9bu;              /* reputation, tor, routing, anonymizer, tenant */
    c.null_reason = nr;
    c.static_reason[2] = WE_MOD_NOMAP_UNREADABLE;
    c.handle[0] = &h[0];
    c.handle[1] = &h[1];
    c.handle[3] = &h[3];
    c.handle[4] = &h[4];
    c.handle[7] = &h[7];
    memset(&standin, 0, sizeof standin);
    memset(&live, 0, sizeof live);
    live.digest[0] = 0xba;
    live.digest[1] = 0xd7;
    live.digest[2] = 0x6c;
    live.digest[3] = 0x5e;
    live.f4.sev = sev;
    live.f4.n = 4u;
    live2 = live;
    live2.digest[0] = 0x0a;
    c.standin[1] = &standin;
    c.standin[7] = &standin;
    we_mod_record_init(&rec, &x);
    CHECK(strcmp(we_mod_render_action(&rec), "-") == 0 && strcmp(we_mod_render_rule(&rec, &c, 1), "-") == 0,
          "record: before a decision the decision variables are not `-`");
    {
        we_addr_t srv = A("192.0.2.1");

        we_mod_record_key(&rec, &srv);
    }
    /* reputation fresh hit, the drop flag from the raw byte, the level from the clamped one */
    memset(&e, 0, sizeof e);
    e.block[0] = 0x84;               /* critical (clamped), inferred */
    e.generation = 497716u;
    e.range = 1u;
    e.family = 4u;
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_FRESH_HIT, &live, 0);
    CHECK(rec.raw_rep == 0x44 && strcmp(we_mod_render_verdict(&rec, WE_MOD_SPELL_NGINX), "critical,drop,inferred") == 0
          && strcmp(we_mod_render_verdict(&rec, WE_MOD_SPELL_SPAMHAUS), "critical,spamhaus-drop,inferred") == 0,
          "record: the verdict of a DROP range: %s", we_mod_render_verdict(&rec, WE_MOD_SPELL_NGINX));
    e.range = 3u;                    /* raw 0x05: a reserved nibble, read critical, no drop */
    e.block[0] = 0x04;
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_FRESH_HIT, &live, 0);
    CHECK(strcmp(we_mod_render_verdict(&rec, WE_MOD_SPELL_NGINX), "critical") == 0, "record: 0x05 is not `critical`");
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_FRESH_NR, &live, 0);
    CHECK(strcmp(we_mod_render_verdict(&rec, 0u), "none") == 0 && rec.raw_rep == 0u, "record: an unlisted address is not `none`");
    e.generation = 497716u;
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_UNKNOWN, &live, 0);
    CHECK(strcmp(we_mod_render_verdict(&rec, 0u), "unknown,stale") == 0, "record: a stale plane is not `unknown,stale`");
    e.generation = 0u;
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_UNKNOWN, NULL, 0);
    CHECK(strcmp(we_mod_render_verdict(&rec, 0u), "unknown") == 0 && we_mod_nomap_get(&rec, 0u) == WE_MOD_NOMAP_LOADING,
          "record: a plane with no map is not `unknown` with its reason");
    /* the stand-in: the disarmed bit, never the stand-in's bytes */
    e.block[0] = 0x01;
    e.generation = 1u;
    we_mod_memo_put(&rec, &c, 7u, &e, WE_ST_STALE_HIT, &standin, 0);
    CHECK((rec.disarmed_mask & 0x80u) != 0u && rec.slot.state[7] == WE_ST_UNKNOWN && rec.slot.e[7].generation == 0u,
          "record: an entry from the stand-in is not recorded disarmed");
    CHECK(we_mod_render_attr(&rec, 14u, &s, &n) == 0 && n == 7u && memcmp(s, "unknown", 7) == 0,
          "record: a disarmed tenant renders \"%.*s\"", (int)n, s != NULL ? s : "");
    /* a later write from a real map clears the bit: the one rule recomputes every mark */
    we_mod_memo_put(&rec, &c, 7u, &e, WE_ST_FRESH_HIT, &live2, 1);
    CHECK((rec.disarmed_mask & 0x80u) == 0u && (rec.lazy_mask & 0x80u) != 0u && rec.digest4[7][0] == 0x0a,
          "record: a real map's write did not recompute the marks");
    /* the generations token over the token set */
    memset(&e, 0, sizeof e);
    e.generation = 497716u;
    e.family = 4u;
    we_mod_memo_put(&rec, &c, 0u, &e, WE_ST_FRESH_NR, &live, 0);
    we_mod_memo_put(&rec, &c, 1u, &e, WE_ST_UNKNOWN, &standin, 1);
    e.generation = 0u;
    we_mod_memo_put(&rec, &c, 3u, &e, WE_ST_UNKNOWN, NULL, 0);    /* refused, by the plane's word */
    we_mod_memo_put(&rec, &c, 4u, &e, WE_ST_UNKNOWN, NULL, 1);    /* loading, lazily */
    e.generation = 41u;
    e.lapsed = 1u;
    we_mod_memo_put(&rec, &c, 7u, &e, WE_ST_STALE_NR, &live2, 1);
    {
        char g[WE_MOD_GEN_MAX];

        we_mod_render_generations(&rec, g);
        CHECK(strcmp(g, "reputation:497716.bad76c5e tor:-d* routing:-r anonymizer:-l* tenant:41.0ad76c5e^*") == 0,
              "record: the generations token is \"%s\"", g);
        CHECK(we_mod_render_attr(&rec, 15u, &s, &n) == 0 && n == 12u && memcmp(s, "lapsed:false", 12) == 0,
              "record: a tenant past its grace renders \"%.*s\", not lapsed:false", (int)n, s != NULL ? s : "");
        e.lapsed = 0u;
        e.generation = 0u;
        we_mod_memo_put(&rec, &c, 7u, &e, WE_ST_REVOKED, &live2, 0);
        rec.gen_mask = 0x80u;
        we_mod_render_generations(&rec, g);
        CHECK(strcmp(g, "tenant:0") == 0, "record: a revoked tenant is \"%s\"", g);
        rec.gen_mask = 0x04u;        /* rpki-unreachable: no handle, unreadable at configuration time */
        e.generation = 0u;
        we_mod_memo_put(&rec, &c, 2u, &e, WE_ST_UNKNOWN, NULL, 1);
        we_mod_render_generations(&rec, g);
        CHECK(strcmp(g, "rpki-unreachable:-u*") == 0, "record: an unreadable plane is \"%s\"", g);
    }
    /* the decision variables */
    rec.decided = 1u;
    rec.step = WE_STEP_CONTEXT;
    rec.program = WE_VPROG_CONTEXT;
    rec.rule = 2u;
    rec.severity = 2u;
    x.prog = (const we_program_t *)&live;   /* any non-NULL block: the context's program ran */
    x.conf.mode = WE_MODE_DENY;
    rec.log_fired[0][0] = 0x05;
    rec.log_fired[1][0] = 0x02;
    rec.log_fired[1][31] = 0x80;
    CHECK(strcmp(we_mod_render_action(&rec), "deny") == 0, "record: action");
    CHECK(strcmp(we_mod_render_rule(&rec, &c, 0), "ctx:2") == 0 && strcmp(we_mod_render_rule(&rec, &c, 1), "deny if listed >= high") == 0,
          "record: the rule id and text");
    CHECK(strcmp(we_mod_render_program(&rec, &c), "floor:ba7816bf8f01cfea ctx:ba7816bf8f01cfea") == 0, "record: program");
    we_mod_render_logged(&rec, buf);
    CHECK(strcmp(buf, "floor:1,3 ctx:2,256") == 0, "record: logged is \"%s\"", buf);
    x.conf.mode = WE_MODE_OFF;
    CHECK(strcmp(we_mod_render_program(&rec, &c), "floor:ba7816bf8f01cfea ctx:-") == 0, "record: a mode-off context names its block");
    rec.program = WE_VPROG_FLOOR;
    rec.rule = 1u;
    rec.step = WE_STEP_FLOOR;
    CHECK(strcmp(we_mod_render_rule(&rec, &c, 0), "floor:1") == 0 && strcmp(we_mod_render_program(&rec, &c), "floor:ba7816bf8f01cfea ctx:-") == 0,
          "record: a floor decision");
    memset(rec.log_fired, 0, sizeof rec.log_fired);
    we_mod_render_logged(&rec, buf);
    CHECK(strcmp(buf, "-") == 0, "record: nothing logged is \"%s\"", buf);
    rec.severity = 1u;
    CHECK(strcmp(we_mod_render_action(&rec), "would-deny") == 0, "record: would-deny");
    rec.step = WE_STEP_EXEMPT;
    rec.reason = WE_WHY_HOLD_HARMLESS;
    rec.marks = WE_MARK_TENANT_REVOKED;
    CHECK(strcmp(we_mod_render_reason(&rec, WE_WALK_FLOOR_HEADER_MISSING, WE_MOD_NOTE_UNPARSED),
                 "hold-harmless,floor-header-unparsed,tenant-revoked") == 0, "record: reason");
    rec.step = WE_STEP_CONTEXT;
    rec.reason = WE_WHY_RULE;
    rec.marks = 0u;
    CHECK(strcmp(we_mod_render_reason(&rec, WE_WALK_OK, WE_MOD_NOTE_NONE), "-") == 0
          && strcmp(we_mod_render_reason(&rec, WE_WALK_FLOOR_HEADER_MISSING, WE_MOD_NOTE_NONE), "floor-header-missing") == 0,
          "record: reason for a rule");
    {
        char f[WE_ADDR_TEXT_MAX];

        rec.floor = A("2001:db8:0:0:1:0:0:1");
        we_mod_render_floor(&rec, f);
        CHECK(strcmp(f, "2001:db8::1:0:0:1") == 0, "record: the floor address is \"%s\"", f);
        memset(&rec.floor, 0, sizeof rec.floor);
        we_mod_render_floor(&rec, f);
        CHECK(strcmp(f, "-") == 0, "record: no floor address is \"%s\"", f);
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the record write and the lazy fill, through the real decision */

static void t_record_write(const char *planes)
{
    fixture_t f;
    static we_mod_scratch_t s, local;
    static we_mod_record_t rec;
    uint64_t shard[SHARD_N], now = 1700000000000ull;
    we_mod_req_t q;
    we_policy_directive_t d[] = {
        D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
        D(WE_DIR_POLICY, "http/s1", "deny if listed >= medium"),
        D(WE_DIR_MODE, "http/s1", "log"),
    };
    char g[WE_MOD_GEN_MAX];
    const char *str;
    size_t n;

    if (fixture_make(&f, planes, d, sizeof d / sizeof d[0], 0u, now) != 0) {
        return;
    }
    f.ctx.gen_mask = 0x0bu;          /* reputation, tor, routing */
    /* a context decision: the record takes the slot the decision keyed */
    q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
    we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
    we_mod_record_init(&rec, &f.ctx);
    CHECK(we_mod_record_write(&rec, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server) == 1, "record write: refused");
    CHECK(rec.decided && strcmp(we_mod_render_action(&rec), "would-deny") == 0 && rec.slot.state[0] == WE_ST_FRESH_HIT
          && rec.lazy_mask == 0u, "record write: the decision's entry: action %s", we_mod_render_action(&rec));
    we_mod_fill(&rec, &f.cfg, &local, f.ctx.gen_mask, now);
    we_mod_render_generations(&rec, g);
    CHECK(rec.slot.state[3] != WE_ST_NONE && (rec.lazy_mask & 0x08u) != 0u && (rec.lazy_mask & 0x01u) == 0u
          && strstr(g, "routing:") != NULL && strstr(g, "routing:-") == NULL && strstr(g, "*") != NULL, "record write: the lazy fill: \"%s\"", g);
    CHECK(we_mod_render_attr(&rec, 16u, &str, &n) == 0 && n == 6u && memcmp(str, "medium", 6) == 0,
          "record write: listed is \"%.*s\"", (int)n, str);
    /* a pre-stage decision keys the record's slot itself, every state NONE, then the fill: an ACME request
     * behind a hold-harmless floor, which step 1 ends whatever the server's address (a hold-harmless floor
     * before a DISTINCT server address no longer ends the request: step 4 judges the server's) */
    q = REQ("198.41.0.4", "1.179.116.132", WE_WALK_OK, 0, 1, 1);
    we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
    we_mod_record_init(&rec, &f.ctx);
    we_mod_record_write(&rec, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server);
    CHECK(rec.slot.key_valid && rec.slot.state[0] == WE_ST_NONE && strcmp(we_mod_render_reason(&rec, 0, 0), "acme") == 0,
          "record write: a pre-stage decision (reason %s)", we_mod_render_reason(&rec, 0, 0));
    we_mod_fill(&rec, &f.cfg, &local, 0x01u, now);
    CHECK(strcmp(we_mod_render_verdict(&rec, 0u), "medium") == 0, "record write: the lazily filled verdict is %s",
          we_mod_render_verdict(&rec, 0u));
    /* the chain keeps the most severe evaluation: a later allow does not replace a would-deny */
    {
        we_mod_record_t keep = rec;

        q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        we_mod_record_init(&rec, &f.ctx);
        we_mod_record_write(&rec, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server);
        q = REQ("0.217.186.65", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        CHECK(we_mod_record_write(&rec, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server) == 0
              && strcmp(we_mod_render_action(&rec), "would-deny") == 0, "record write: the chain fold lost the would-deny");
        (void)keep;
    }
    fixture_free(&f);
    /*
     * Two interleaved requests on one worker (row V6): a decision that reads tor alone, so reputation is
     * filled lazily. A is decided and its record written, B is decided on the same scratch, then A's record is
     * filled through that scratch, as the servers reuse it. A's verdict must be A's (the value A's record gets
     * filled alone), not B's. WE_MOD_TEST_WORKER_SCRATCH_FILL, the fill keyed by the scratch's last decision,
     * renders B's and fails by name.
     */
    {
        we_policy_directive_t d1[] = { D(WE_DIR_FLOOR, "http", "deny if tor_exit") };
        static we_mod_record_t ra, rb;
        char va[32], vb[32], vi[32];

        if (fixture_make(&f, planes, d1, 1u, 0u, now) != 0) {
            return;
        }
        q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        we_mod_record_init(&ra, &f.ctx);
        we_mod_record_write(&ra, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server);
        we_mod_fill(&ra, &f.cfg, &s, 0x01u, now);
        snprintf(va, sizeof va, "%s", we_mod_render_verdict(&ra, 0u));
        q = REQ("0.217.186.65", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        we_mod_record_init(&rb, &f.ctx);
        we_mod_record_write(&rb, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server);
        we_mod_fill(&rb, &f.cfg, &s, 0x01u, now);
        snprintf(vb, sizeof vb, "%s", we_mod_render_verdict(&rb, 0u));
        CHECK(strcmp(va, vb) != 0, "interleave: the fixture gives A and B the same verdict (%s), so the row cannot tell them apart", va);
        q = REQ("1.179.116.132", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        we_mod_record_init(&ra, &f.ctx);
        we_mod_record_write(&ra, &f.cfg, &f.ctx, &s, &q.r.floor, &q.r.server);
        q = REQ("0.217.186.65", NULL, WE_WALK_OK, 0, 0, 0);
        we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
        we_mod_fill(&ra, &f.cfg, &s, 0x01u, now);
        snprintf(vi, sizeof vi, "%s", we_mod_render_verdict(&ra, 0u));
        CHECK(strcmp(vi, va) == 0, "interleave: A's record filled after B's decision renders %s, not A's %s (B's is %s)", vi, va, vb);
    }
    fixture_free(&f);
}


/* ---------------------------------------------------------------------------------------------- */
/* the arena and the configuration build */

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static void t_config(void)
{
    we_policy_directive_t d[] = {
        D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
        D(WE_DIR_POLICY, "http/s1", "log if listed >= low"),
        D(WE_DIR_POLICY, "http/s1", "deny if listed >= high"),
        D(WE_DIR_POLICY, "http/s2", "log if listed >= low"),
        D(WE_DIR_POLICY, "http/s2", "deny if listed >= high"),
        D(WE_DIR_THRESHOLD, "http/s3", "medium"),
    };
    we_mod_ctx_spec_t spec[] = {
        { "http", "http", 0, 0, 0 }, { "http/s1", "server \"a\"\n", 451, 1, 1 }, { "http/s1/l1", "location /x", 0, 0, 0 },
        { "http/s2", "server b", 0, 0, 0 }, { "http/s3", "server c", 0, 0, 0 },
    };
    we_policy_source_t src = { d, sizeof d / sizeof d[0], NULL, 0 };
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    we_mod_arena_t *a = we_mod_arena_new();
    we_mod_cfg_t cfg;
    we_mod_ctx_t *x = NULL;
    uint32_t stride = 0u;
    char msg[512], d16[17];
    uint8_t dg[32];

    memset(&e, 0, sizeof e);
    if (we_policy_build(&src, &env, NULL, &b, &e, NULL) != WE_POLICY_OK) {
        CHECK(0, "config: the configuration is refused: %s", e.what);
        return;
    }
    /* the ABI first: a module built against another header is refused before a byte of cfg is written */
    {
        static we_mod_cfg_t probe;
        static unsigned char was[sizeof(we_mod_cfg_t)];
        int arc;

        memset(&probe, 0xA5, sizeof probe);
        memcpy(was, &probe, sizeof was);
        arc = we_mod_config_build(WE_MODULE_ABI_VERSION + 1u, a, b, &src, spec, 5u, 403u, &probe, &x, &stride, msg,
                                  sizeof msg);
        CHECK(arc == WE_MOD_ERR_ABI && memcmp(was, &probe, sizeof was) == 0 && x == NULL && stride == 0u
              && strstr(msg, "ABI") != NULL,
              "config: another ABI was not refused before anything was written (rc %d: %s)", arc, msg);
    }
    CHECK(we_mod_config_build(WE_MODULE_ABI_VERSION, a, b, &src, spec, 5u, 403u, &cfg, &x, &stride, msg, sizeof msg) == 0, "config: %s", msg);
    if (x == NULL) {
        return;
    }
    CHECK(x[1].prog != NULL && x[1].prog == x[3].prog, "config: two contexts with one text do not share one block");
    CHECK(x[2].prog == x[1].prog, "config: an inheriting context does not run its parent's block");
    CHECK(x[1].ctr_off == WE_MOD_CTR_FLOOR + 1u && x[2].ctr_off == x[1].ctr_off && x[3].ctr_off == x[1].ctr_off + 2u
          && x[4].ctr_off == x[3].ctr_off + 2u, "config: counter offsets %u %u %u %u", x[1].ctr_off, x[2].ctr_off,
          x[3].ctr_off, x[4].ctr_off);
    CHECK(stride == 16u, "config: the stride is %u, not 16 (8 + 1 + 2 + 2 + 1, rounded)", stride);
    CHECK(we_mod_arena_blocks(a) == 3u, "config: %u blocks placed, not 3 (the floor, the shared pair, the sugar)",
          we_mod_arena_blocks(a));
    CHECK(x[1].deny_status == 451u && x[3].deny_status == 403u && cfg.floor_status == 403u, "config: deny statuses");
    we_sha256(x[1].prog, we_program_size(x[1].prog), dg);
    we_digest16(dg, d16);
    {
        char want[64];

        we_sha256(cfg.floor, we_program_size(cfg.floor), dg);
        snprintf(want, sizeof want, "floor:");
        we_digest16(dg, want + 6);
        snprintf(want + 22, sizeof want - 22, " ctx:%s", d16);
        CHECK(strcmp(x[1].cold->program_ctx, want) == 0, "config: program is \"%s\", want \"%s\"", x[1].cold->program_ctx, want);
    }
    CHECK(strcmp(x[1].cold->rule_id[1], "ctx:2") == 0 && strcmp(x[1].cold->rule_text[1], "deny if listed >= high") == 0
          && strcmp(cfg.cold->rule_text[0], "deny if tor_exit") == 0, "config: the rule strings");
    CHECK(x[1].cold->own == 1u && x[2].cold->own == 0u, "config: ownership of lines");
    {
        char esc[64];

        we_mod_escape(x[1].cold->name, esc, sizeof esc);
        CHECK(strcmp(esc, "\"server \\\"a\\\"\\x0a\"") == 0, "config: the escaped name is %s", esc);
    }
    CHECK(we_mod_arena_seal(a) == 0, "config: the arena does not seal");
    {
        pid_t pid = fork();

        if (pid == 0) {
            *(volatile uint8_t *)(uintptr_t)x[1].prog = 0u;   /* a store into a sealed block */
            _exit(0);
        }
        if (pid > 0) {
            int st = 0;

            waitpid(pid, &st, 0);
            CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "config: a store into a sealed block did not fault");
        }
    }
    we_policy_build_free(b);
    we_mod_arena_free(a);
}

/*
 * A spec that omits the context carrying a program's lines is refused: the stride never counted those
 * rules, so an inheriting context's counters would index past the shard. Under the control
 * (WE_MOD_TEST_SPEC_UNCHECKED, the refusal skipped) the configuration builds and a decide in the
 * inheriting context writes past a shard of exactly `stride` words, which a sanitizer build stops.
 */
static void t_config_spec(void)
{
    we_policy_directive_t d[] = {
        D(WE_DIR_POLICY, "http/s1", "log if tor_exit is unknown"),
        D(WE_DIR_POLICY, "http/s1", "log if rpki is unknown"),
        D(WE_DIR_POLICY, "http/s2/l1", "log if tor_exit is unknown"),
    };
    we_mod_ctx_spec_t spec[] = { { "http", "http", 0, 0, 0 }, { "http/s1/l1", "location /x", 0, 0, 0 } };
    we_mod_ctx_spec_t gap[] = {
        { "http", "http", 0, 0, 0 }, { "http/s2", "server b", 0, 0, 0 }, { "http/s2/l1/x", "location /x", 0, 0, 0 },
    };
    we_policy_source_t src = { d, sizeof d / sizeof d[0], NULL, 0 };
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    we_mod_arena_t *a = we_mod_arena_new();
    we_mod_cfg_t cfg;
    we_mod_ctx_t *x = NULL;
    uint32_t stride = 0u;
    char msg[512];
    int rc;

    memset(&e, 0, sizeof e);
    if (we_policy_build(&src, &env, NULL, &b, &e, NULL) != WE_POLICY_OK) {
        CHECK(0, "config spec: the configuration is refused by the compiler: %s", e.what);
        return;
    }
    rc = we_mod_config_build(WE_MODULE_ABI_VERSION, a, b, &src, spec, 2u, 403u, &cfg, &x, &stride, msg, sizeof msg);
    CHECK(rc == WE_MOD_ERR_SPEC && strstr(msg, "http/s1/l1") != NULL && strstr(msg, "runs the lines of http/s1,") != NULL,
          "config spec: a spec omitting http/s1, whose lines http/s1/l1 runs, is not refused (rc %d): %s", rc, msg);
    if (rc == 0 && x != NULL) {
        /* the control: a decide in the inheriting context, on a shard of exactly the configured length */
        uint64_t *shard = calloc(stride, sizeof *shard);
        static we_mod_scratch_t s;
        we_mod_req_t q = REQ("198.51.100.1", NULL, WE_WALK_OK, 0, 0, 0);

        if (shard != NULL) {
            we_mod_decide(&cfg, &x[1], &s, shard, &q, 1700000000000ull);
            CHECK(x[1].ctr_off + x[1].rule_count <= stride, "config spec: counters at %u..%u in a %u-slot shard",
                  x[1].ctr_off, x[1].ctr_off + x[1].rule_count - 1u, stride);
            free(shard);
        }
    }
    we_mod_arena_free(a);
    a = we_mod_arena_new();
    x = NULL;
    rc = we_mod_config_build(WE_MODULE_ABI_VERSION, a, b, &src, gap, 3u, 403u, &cfg, &x, &stride, msg, sizeof msg);
    CHECK(rc == WE_MOD_ERR_SPEC && strstr(msg, "runs the lines of http/s2/l1,") != NULL,
          "config spec: a spec listing an outer context but not the nearer one carrying the lines is not refused (rc %d): %s",
          rc, msg);
    we_policy_build_free(b);
    we_mod_arena_free(a);
}

/* over WE_MOD_STRIDE_MAX counted rule slots, the configuration is refused naming its largest contexts */
static void t_config_cap(void)
{
    static we_policy_directive_t d[257u * 256u];
    static char ctx[257][16];
    static we_mod_ctx_spec_t spec[257];
    we_policy_source_t src;
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    we_mod_arena_t *a = we_mod_arena_new();
    we_mod_cfg_t cfg;
    we_mod_ctx_t *x = NULL;
    uint32_t stride = 0u, i, r;
    size_t n = 0u;
    char msg[512];

    for (i = 0u; i < 257u; i++) {
        snprintf(ctx[i], sizeof ctx[i], "http/s%u", i);
        spec[i].path = ctx[i];
        spec[i].name = ctx[i];
        for (r = 0u; r < 256u; r++) {
            d[n++] = D(WE_DIR_POLICY, ctx[i], "log if tor_exit");
        }
    }
    src.d = d;
    src.n = n;
    src.context = NULL;
    src.floor = 0;
    memset(&e, 0, sizeof e);
    if (we_policy_build(&src, &env, NULL, &b, &e, NULL) != WE_POLICY_OK) {
        CHECK(0, "config cap: the configuration is refused by the compiler: %s", e.what);
        return;
    }
    msg[0] = '\0';                               /* written only on a refusal */
    CHECK(we_mod_config_build(WE_MODULE_ABI_VERSION, a, b, &src, spec, 257u, 403u, &cfg, &x, &stride, msg, sizeof msg)
              == WE_MOD_ERR_CAP
          && strstr(msg, "65800 counted rule slots") != NULL && strstr(msg, "http/s0 (256)") != NULL,
          "config cap: 65,800 slots were not refused naming the contexts: %s", msg);
    /* one context fewer is under the cap and accepted */
    we_mod_arena_free(a);
    a = we_mod_arena_new();
    CHECK(we_mod_config_build(WE_MODULE_ABI_VERSION, a, b, &src, spec, 255u, 403u, &cfg, &x, &stride, msg, sizeof msg) == 0,
          "config cap: 255 contexts (65,288 slots) were refused: %s", msg);
    we_policy_build_free(b);
    we_mod_arena_free(a);
}


/* ---------------------------------------------------------------------------------------------- */
/* binding: the lexical walk, the resolved chain, the trust checks, the peek */

#include <fcntl.h>
#include <sys/stat.h>

/* a base directory the trust rule accepts, for the binding fixtures; "" when none can be proven */
static const char *g_tmpdir;                    /* the run's tmpdir, argv[1] */
static char g_base_used[256];                   /* the base the lifecycle rows wrote under, for the leftover row */

/*
 * The base a lifecycle row builds its planes under, and removes when it is done: the run's own tmpdir when
 * its whole chain passes the trust rule a plane directory must pass, else the first of the runtime
 * directory and HOME that does (a checkout made under umask 002 leaves its tmpdir group-writable, and
 * the binding rightly refuses that). Either way the row removes what it made, and main checks nothing is
 * left behind.
 */
static void trusted_base(char *out, size_t n)
{
    const char *c[4];
    char run[64], why[256], tmp[PATH_MAX];
    size_t i;

    snprintf(run, sizeof run, "/run/user/%u", (unsigned)getuid());
    c[0] = g_tmpdir != NULL && realpath(g_tmpdir, tmp) != NULL ? tmp : NULL;
    c[1] = getenv("XDG_RUNTIME_DIR");
    c[2] = run;
    c[3] = getenv("HOME");
    for (i = 0u; i < 4u; i++) {
        int fd = -1;

        /* the planes' own rule, the lexical walk with no sticky exception: a candidate that passes only the
         * configuration-file rule (root's sticky /tmp above it) is no place for a plane */
        if (c[i] != NULL && c[i][0] == '/' && we_mod_dir_open(c[i], (unsigned)geteuid(), &fd, why, sizeof why) == 0) {
            close(fd);
            snprintf(out, n, "%s/we-test-module.%ld", c[i], (long)getpid());
            snprintf(g_base_used, sizeof g_base_used, "%s", out);
            return;
        }
    }
    out[0] = '\0';
}

static int rm_one(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void)st;
    (void)ftw;
    if (flag == FTW_DP) {
        chmod(path, 0700);
        return rmdir(path) == 0 ? 0 : -1;
    }
    return unlink(path) == 0 ? 0 : -1;
}

/* a row's tree removed, depth first, never following a link */
static void rm_tree(const char *path)
{
    struct stat st;

    if (lstat(path, &st) == 0) {
        nftw(path, rm_one, 16, FTW_DEPTH | FTW_PHYS);
    }
}

static void copy_file(const char *from, const char *to, mode_t mode)
{
    static char buf[1u << 16];
    int in = open(from, O_RDONLY), o = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t r;

    while (in >= 0 && o >= 0 && (r = read(in, buf, sizeof buf)) > 0) {
        if (write(o, buf, (size_t)r) != r) {
            break;
        }
    }
    if (in >= 0) {
        close(in);
    }
    if (o >= 0) {
        close(o);
    }
    chmod(to, mode);
}

static void t_binding(const char *planes)
{
    char base[256], d1[300], d2[300], lnk[400], f[400], src[1100], why[512];
    int fd = -1, pfd = -1;
    struct stat st;
    we_mod_peek_t pk;
    uid_t uid = geteuid();

    trusted_base(base, sizeof base);
    CHECK(base[0] != '\0', "binding: no trusted base directory (XDG_RUNTIME_DIR, /run/user/<uid>, HOME) to build "
          "the fixtures under; the binding rows did not run");
    if (base[0] == '\0') {
        return;
    }
    snprintf(d1, sizeof d1, "%s/data", base);
    snprintf(d2, sizeof d2, "%s/open", base);
    mkdir(base, 0755);
    mkdir(d1, 0755);
    mkdir(d2, 0777);
    chmod(d2, 0777);
    chmod(base, 0755);
    CHECK(we_mod_dir_open(d1, uid, &fd, why, sizeof why) == 0, "binding: a trusted directory is refused: %s", why);
    if (fd >= 0) {
        close(fd);
    }
    CHECK(we_mod_dir_open(d2, uid, &fd, why, sizeof why) != 0 && strstr(why, "writable by others") != NULL,
          "binding: a world-writable directory is accepted");
    CHECK(we_mod_dir_open("relative/dir", uid, &fd, why, sizeof why) != 0, "binding: a relative path is accepted");
    CHECK(we_mod_dir_open("/tmp", uid, &fd, why, sizeof why) != 0, "binding: /tmp, sticky and world-writable, is accepted");
    /* a link this user owns, in a trusted directory: followed; the same link inside the open directory: not */
    snprintf(lnk, sizeof lnk, "%s/link", base);
    unlink(lnk);
    CHECK(symlink(d1, lnk) == 0 && we_mod_dir_open(lnk, uid, &fd, why, sizeof why) == 0,
          "binding: a trusted owner's link in a trusted directory is refused: %s", why);
    if (fd >= 0) {
        close(fd);
    }
    snprintf(lnk, sizeof lnk, "%s/link", d2);
    unlink(lnk);
    CHECK(symlink(d1, lnk) == 0 && we_mod_dir_open(lnk, uid, &fd, why, sizeof why) != 0,
          "binding: a link inside a world-writable directory is followed");
    CHECK(we_mod_chain_check(d1, uid, why, sizeof why) == 0 && we_mod_chain_check(d2, uid, why, sizeof why) != 0,
          "binding: the resolved chain check");
    /* the trust rule for CONFIGURATION files: a root-owned sticky ancestor is allowed (sshd's rule for /tmp above a
     * key file), because a configuration file is found by an explicit path the operator wrote. A plane's
     * directory keeps the strict walk (we_mod_dir_open), and the exception is root's alone. */
    {
        struct stat ts;
        char sdir[64];

        snprintf(sdir, sizeof sdir, "/tmp/we-test-module-sticky.XXXXXX");
        if (stat("/tmp", &ts) == 0 && S_ISDIR(ts.st_mode) && ts.st_uid == 0u && (ts.st_mode & S_ISVTX) != 0u
                && (ts.st_mode & S_IWOTH) != 0u && mkdtemp(sdir) != NULL) {
            CHECK(we_mod_chain_check(sdir, uid, why, sizeof why) == 0,
                  "binding: a configuration file's chain through root's sticky /tmp is refused: %s", why);
            fd = -1;
            CHECK(we_mod_dir_open(sdir, uid, &fd, why, sizeof why) != 0 && strstr(why, "writable by others") != NULL,
                  "binding: a plane directory under /tmp is accepted (the sticky exception reached the planes): %s", why);
            if (fd >= 0) {
                close(fd);
            }
            rmdir(sdir);
        } else {
            printf("  note  binding: /tmp is not root's sticky world-writable directory here; the sticky rows did not run\n");
        }
        /* this user's own sticky world-writable directory: no exception, the owner is not root */
        CHECK(chmod(d2, 01777) == 0 && we_mod_chain_check(d2, uid, why, sizeof why) != 0,
              "binding: a sticky directory owned by this user, not root, passed the configuration chain check");
        chmod(d2, 0777);
    }
    /* the plane: 0444 and owned by this user, bound as reputation; then each refusal in turn */
    snprintf(src, sizeof src, "%s/reputation.bin", planes);
    snprintf(f, sizeof f, "%s/reputation.bin", d1);
    unlink(f);
    copy_file(src, f, 0444);
    if (we_mod_dir_open(d1, uid, &fd, why, sizeof why) == 0) {
        CHECK(we_plane_peek(fd, "reputation.bin", WE_PLANE_REPUTATION, &pk, why, sizeof why) == 0 && pk.schema == 1u
              && pk.plane_id == WE_PLANE_REPUTATION, "binding: the peek of a reputation plane: %s", why);
        CHECK(we_plane_peek(fd, "reputation.bin", WE_PLANE_TOR, &pk, why, sizeof why) != 0 && strstr(why, "plane 1") != NULL,
              "binding: a reputation plane bound as tor is accepted");
        CHECK(we_mod_plane_trust(fd, "reputation.bin", uid, 0, &pfd, &st, why, sizeof why) == 0,
              "binding: a 0444 plane owned by the reader is refused: %s", why);
        if (pfd >= 0) {
            CHECK((fcntl(pfd, F_GETFD) & FD_CLOEXEC) != 0, "binding: the plane's descriptor is not close-on-exec");
            close(pfd);
        }
        chmod(f, 0644);
        CHECK(we_mod_plane_trust(fd, "reputation.bin", uid, 0, &pfd, &st, why, sizeof why) != 0 && strstr(why, "0644") != NULL
              && strstr(why, "chmod 0444") != NULL, "binding: a 0644 plane is accepted for mapping");
        CHECK(we_mod_plane_trust(fd, "reputation.bin", uid, 1, &pfd, &st, why, sizeof why) == 0,
              "binding: the legacy file at 0644 is refused: %s", why);
        if (pfd >= 0) {
            close(pfd);
        }
        chmod(f, 0444);
        CHECK(we_mod_plane_trust(fd, "reputation.bin", uid + 1u, 0, &pfd, &st, why, sizeof why) != 0
              && strstr(why, "chown root") != NULL, "binding: a plane owned by another uid is accepted");
        unlink(lnk);
        snprintf(lnk, sizeof lnk, "%s/tor.bin", d1);
        unlink(lnk);
        CHECK(symlink(f, lnk) == 0 && we_mod_plane_trust(fd, "tor.bin", uid, 0, &pfd, &st, why, sizeof why) != 0
              && strstr(why, "symbolic link") != NULL, "binding: a plane reached through a link is accepted");
        CHECK(we_plane_peek(fd, "absent.bin", WE_PLANE_TOR, &pk, why, sizeof why) != 0 && pk.absent == 1u,
              "binding: an absent plane is not reported absent");
        close(fd);
        unlink(lnk);
    }
    unlink(f);
    snprintf(lnk, sizeof lnk, "%s/link", base);
    unlink(lnk);
    snprintf(lnk, sizeof lnk, "%s/link", d2);
    unlink(lnk);
    rmdir(d1);
    rmdir(d2);
    rmdir(base);
}


/* ---------------------------------------------------------------------------------------------- */
/* the writers: the temp-file discipline, the three formats */

static void t_writers(const char *tmpdir)
{
    we_mod_procid_t id;
    char dir[512], why[256], buf[8192], path[600], back[64];
    we_mod_text_t t;
    int dfd, fd;
    struct stat st;
    ssize_t n;

    CHECK(we_mod_procid(&id) == 0 && strlen(id.id16) == 16u && id.pid == (uint64_t)getpid(),
          "writers: the process identity");
    snprintf(dir, sizeof dir, "%s/writers-XXXXXX", tmpdir);
    if (mkdtemp(dir) == NULL) {
        CHECK(0, "writers: no temporary directory");
        return;
    }
    dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    /* a whole file, renamed into place, and no temp left behind */
    CHECK(we_mod_write_file(dfd, &id, "status", "a.status", "hello\n", 6u, why, sizeof why) == 0,
          "writers: a file is not written: %s", why);
    snprintf(path, sizeof path, "%s/a.status", dir);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? read(fd, back, sizeof back) : -1;
    if (fd >= 0) {
        close(fd);
    }
    CHECK(n == 6 && memcmp(back, "hello\n", 6) == 0, "writers: the bytes read back differ");
    /* a symlink planted at the temp name: the create refuses, and the link's target is untouched */
    {
        char tmp[700], target[600];

        snprintf(target, sizeof target, "%s/victim", dir);
        fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            if (write(fd, "keep", 4) != 4) {
                CHECK(0, "writers: the victim file cannot be written");
            }
            close(fd);
        }
        snprintf(tmp, sizeof tmp, "%s/.%llu-%llu-rules.tmp", dir, (unsigned long long)id.pid,
                 (unsigned long long)id.starttime);
        if (symlink(target, tmp) != 0) {
            CHECK(0, "writers: the planted link cannot be made");
        }
        /* the write refuses, nothing at the planted name is followed or removed */
        CHECK(we_mod_write_file(dfd, &id, "rules", "b.rules.cnt", "x\n", 2u, why, sizeof why) != 0,
              "writers: a write went ahead with a link planted at its temp name");
        fd = open(target, O_RDONLY);
        n = fd >= 0 ? read(fd, back, sizeof back) : -1;
        if (fd >= 0) {
            close(fd);
        }
        CHECK(n == 4 && memcmp(back, "keep", 4) == 0, "writers: the planted link's target was written through");
        CHECK(lstat(tmp, &st) == 0 && S_ISLNK(st.st_mode), "writers: the planted link was removed or replaced");
        unlink(tmp);
    }
    /* the version 2 rule file: the writer's key, then only the non-zero counts and pre-stage lines */
    {
        static uint64_t sum[64];
        we_mod_ctrmap_entry_t e[2] = { { 8u, 2u, "ba7816bf8f01cfea" }, { 10u, 3u, "0123456789abcdef" } };
        we_mod_ctrmap_t map = { e, 2u };
        char pidline[40];

        /* the writer's pid on its own line, as the core's counter record carries it */
        snprintf(pidline, sizeof pidline, "\nwritten 2000\npid %llu\n", (unsigned long long)id.pid);
        memset(sum, 0, sizeof sum);
        sum[1] = 4u;                       /* acme */
        sum[9] = 7u;                       /* the floor's rule 2 */
        sum[12] = 1u;                      /* the context's rule 3 */
        t.buf = buf;
        t.len = 0u;
        t.cap = sizeof buf;
        t.over = 0;
        we_mod_render_rules(&t, &id, &map, sum, 1000u, 3u, 1500u, 2000u, "ba7816bf8f01cfea");
        CHECK(!t.over && strncmp(buf, "whisper-edge-rule-counters 2\npidns ", 35) == 0
              && strstr(buf, "\nr ba7816bf8f01cfea 2 7\n") != NULL && strstr(buf, "\nr 0123456789abcdef 3 1\n") != NULL
              && strstr(buf, "\npre acme 4\n") != NULL && strstr(buf, pidline) != NULL && strstr(buf, " 1 0\n") == NULL
              && strstr(buf, "\ntick 3\n") != NULL,
              "writers: the rule file is not in its shape:\n%s", buf);
    }
    /* the status file's process line and a plane line, and an escaped reason */
    {
        static we_mod_status_t s;

        memset(&s, 0, sizeof s);
        s.server = "nginx/1.24.0";
        s.tick = 9u;
        snprintf(s.config16, sizeof s.config16, "ba7816bf8f01cfea");
        s.no_thread = 1u;
        s.plane[0].bound = 1u;
        snprintf(s.plane[0].state, sizeof s.plane[0].state, "refused");
        snprintf(s.plane[0].reason, sizeof s.plane[0].reason, "a \"bad\"\nfile");
        s.plane[0].generation = 497716u;
        s.plane[0].remaining_ms = -5;
        s.ntransitions = 1u;
        snprintf(s.transition[0], sizeof s.transition[0], "plane tor stale out=tor tenant=fresh: rule 5 allow captures");
        t.len = 0u;
        t.over = 0;
        we_mod_render_status(&t, &id, &s);
        CHECK(!t.over && strstr(buf, " tick 9 config ba7816bf8f01cfea no-thread shards ") != NULL
              && strstr(buf, "plane reputation refused \"a \\\"bad\\\"\\x0afile\" generation 497716 digest - ") != NULL
              && strstr(buf, " remaining -5 ") != NULL && strstr(buf, "transition 0 \"plane tor stale out=tor") != NULL,
              "writers: the status file is not in its shape:\n%s", buf);
        CHECK(strchr(buf, '\n') != NULL && memchr(buf, '\x0a', t.len) != NULL, "writers: no line in the status file");
        {
            size_t lines = 0u, i;

            for (i = 0u; i < t.len; i++) {
                lines += buf[i] == '\n';
            }
            CHECK(lines == 4u, "writers: the status file has %zu lines, not 4 (header, process, plane, transition; "
                  "the fault line unmeasured): an embedded newline was not escaped, or an unmeasured line printed", lines);
        }
        /* only measured fields print: none of the five here was measured, so none appears (the control prints them) */
        CHECK(strstr(buf, " slot-age ") == NULL && strstr(buf, " ticks ") == NULL && strstr(buf, " immutable ") == NULL
              && strstr(buf, " nonresident ") == NULL && strstr(buf, "majflt-delta") == NULL,
              "writers: the status file prints a field nobody measured:\n%s", buf);
        s.plane[0].measured = WE_MOD_MEASURED_IMMUTABLE | WE_MOD_MEASURED_NONRESIDENT | WE_MOD_MEASURED_SLOT_AGE
                              | WE_MOD_MEASURED_TICKS;
        s.plane[0].immutable = 1u;
        s.plane[0].nonresident = 3u;
        s.plane[0].ticks = 12u;
        s.measured = WE_MOD_MEASURED_MAJFLT;
        s.majflt_delta = 2u;
        t.len = 0u;
        t.over = 0;
        we_mod_render_status(&t, &id, &s);
        CHECK(!t.over && strstr(buf, " ticks 12 ") != NULL && strstr(buf, " immutable yes") != NULL
              && strstr(buf, " nonresident 3 ") != NULL && strstr(buf, " slot-age ") != NULL
              && strstr(buf, "\nmajflt-delta 2\n") != NULL,
              "writers: a measured field does not print:\n%s", buf);
    }
    unlink(path);
    {
        char p2[600];

        snprintf(p2, sizeof p2, "%s/b.rules.cnt", dir);
        unlink(p2);
        snprintf(p2, sizeof p2, "%s/victim", dir);
        unlink(p2);
    }
    close(dfd);
    rmdir(dir);
    (void)st;
}


/* ---------------------------------------------------------------------------------------------- */
/* publication, the retire list, the lists, the thread */

static unsigned released;
static void count_release(we_map_t *m, void *ud)
{
    (void)m;
    (void)ud;
    released++;
}

static void t_publication(void)
{
    we_handle_t h;
    we_map_t *standin = we_mod_standin_new(WE_PLANE_TOR), *a, *b;
    const we_map_t *displaced = NULL;
    we_mod_retire_t r;
    size_t bytes = (sizeof(we_map_t) + 63u) & ~(size_t)63u;

    memset(&h, 0, sizeof h);
    a = (we_map_t *)aligned_alloc(64, bytes);
    b = (we_map_t *)aligned_alloc(64, bytes);
    memset(a, 0, bytes);
    memset(b, 0, bytes);
    a->generation = 10u;
    b->generation = 11u;
    CHECK(standin != NULL && standin->generation == 1u && standin->valid_until_ms == 1u && standin->f4.n == 0u
          && we_eval_peek(standin, 1700000000000ull, 1u) == WE_ST_UNKNOWN,
          "publication: the stand-in does not read stale");
    CHECK(we_handle_publish_mapped(&h, NULL, a, &displaced) == WE_OK && we_current(&h) == a && displaced == NULL
          && h.high_water == 10u, "publication: the first publish");
    CHECK(we_handle_publish_mapped(&h, a, a, &displaced) == WE_ERR_ROLLBACK, "publication: an equal generation is published");
    CHECK(we_handle_publish_mapped(&h, NULL, b, &displaced) == WE_MOD_ERR_RACE && we_current(&h) == a,
          "publication: a stale expectation replaced the current map");
    CHECK(we_handle_set_view(&h, a, standin) == WE_OK && we_current(&h) == standin, "publication: the disarm");
    CHECK(we_handle_set_view(&h, standin, a) == WE_OK && we_current(&h) == a, "publication: the re-arm");
    CHECK(we_handle_set_view(&h, standin, a) == WE_MOD_ERR_RACE, "publication: a re-arm from a view no longer current");
    CHECK(we_handle_publish_mapped(&h, a, b, &displaced) == WE_OK && displaced == a && h.high_water == 11u
          && h.retired[0].map == NULL, "publication: the displaced map was not handed back, or reached the core's ring");
    a->generation = 9u;
    CHECK(we_handle_publish_mapped(&h, b, a, &displaced) == WE_ERR_ROLLBACK, "publication: a rollback below the mark");
    /* the retire list: four slots, the monotonic grace, the fifth deferred */
    memset(&r, 0, sizeof r);
    released = 0u;
    CHECK(we_mod_retire_push(&r, a, count_release, NULL, 1000u) == 0 && we_mod_retire_push(&r, a, count_release, NULL, 1000u) == 0
          && we_mod_retire_push(&r, a, count_release, NULL, 2000u) == 0 && we_mod_retire_push(&r, a, count_release, NULL, 2000u) == 0
          && we_mod_retire_push(&r, a, count_release, NULL, 2000u) == -1, "publication: the retire list holds other than four");
    CHECK(we_mod_retire_sweep(&r, 30999u, 30000u) == 0u && we_mod_retire_sweep(&r, 31000u, 30000u) == 2u && released == 2u
          && we_mod_retire_sweep(&r, 32000u, 30000u) == 2u && released == 4u, "publication: the grace was not honoured");
    free(a);
    free(b);
    free(standin);
}

typedef struct { we_mod_item_t it; int v; } item_t;

static void t_lists(void)
{
    we_mod_item_t *slot = NULL, *l;
    item_t x[5];
    int i, order = 1;

    for (i = 0; i < 5; i++) {
        x[i].it.next = NULL;
        x[i].v = i;
        we_mod_list_post(&slot, &x[i].it);
    }
    l = we_mod_list_take(&slot);
    for (i = 0; l != NULL; i++, l = l->next) {
        order &= ((item_t *)(void *)l)->v == i;
    }
    CHECK(order && i == 5 && slot == NULL, "lists: posted items are not taken whole, oldest first");
}

static int tick_calls, final_calls, wedge;
static void sleep_us(unsigned us)
{
    struct timespec ts = { (time_t)(us / 1000000u), (long)(us % 1000000u) * 1000L };

    nanosleep(&ts, NULL);
}
static int tick_tid;
static void on_tick(void *ud, uint64_t tick, const int *stop)
{
    (void)ud;
    (void)tick;
    __atomic_store_n(&tick_tid, (int)syscall(SYS_gettid), __ATOMIC_RELAXED);
    __atomic_add_fetch(&tick_calls, 1, __ATOMIC_RELAXED);
    while (__atomic_load_n(&wedge, __ATOMIC_RELAXED) && !__atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
        sleep_us(1000);
    }
    while (__atomic_load_n(&wedge, __ATOMIC_RELAXED) == 2) {
        sleep_us(1000);                      /* wedged past its stop flag: a job stuck in the kernel */
    }
}
static void on_final(void *ud, uint64_t tick, const int *stop)
{
    (void)ud;
    (void)tick;
    (void)stop;
    __atomic_add_fetch(&final_calls, 1, __ATOMIC_RELAXED);
}

static void t_thread(void)
{
    we_mod_thread_t *t = NULL;
    char why[256];
    int i, rc;
    uint64_t t0;

    rc = we_mod_thread_start(&t, 20u, 0u, on_tick, on_final, NULL, why, sizeof why);
    CHECK(rc == 0, "thread: not started: %s", why);
    if (rc != 0) {
        return;
    }
    for (i = 0; i < 200 && we_mod_thread_ticks(t) < 3u; i++) {
        sleep_us(10000);
    }
    CHECK(we_mod_thread_ticks(t) >= 3u && __atomic_load_n(&tick_calls, __ATOMIC_RELAXED) >= 3,
          "thread: the ticks did not run");
    {
        /* the thread's signal mask, read from the kernel: every asynchronous signal blocked, so a server's
         * SIGTERM, SIGHUP or SIGCHLD reaches the server's own threads, and the synchronous faults left open */
        char sp[96], line[256];
        unsigned long long blk = 0ull;
        int got = 0;
        FILE *f;

        snprintf(sp, sizeof sp, "/proc/self/task/%d/status", __atomic_load_n(&tick_tid, __ATOMIC_RELAXED));
        f = fopen(sp, "r");
        while (f != NULL && fgets(line, sizeof line, f) != NULL) {
            if (strncmp(line, "SigBlk:", 7) == 0) {
                got = sscanf(line + 7, "%llx", &blk) == 1;
            }
        }
        if (f != NULL) {
            fclose(f);
        }
#define MASK_BIT(sig) (1ull << ((sig) - 1))
        CHECK(got && (blk & MASK_BIT(SIGTERM)) && (blk & MASK_BIT(SIGHUP)) && (blk & MASK_BIT(SIGCHLD))
              && (blk & MASK_BIT(SIGUSR1)) && (blk & MASK_BIT(SIGPIPE)) && !(blk & MASK_BIT(SIGSEGV))
              && !(blk & MASK_BIT(SIGBUS)) && !(blk & MASK_BIT(SIGFPE)) && !(blk & MASK_BIT(SIGILL)),
              "thread: the module thread does not hold the full asynchronous mask (SigBlk %016llx from %s)", blk, sp);
#undef MASK_BIT
    }
    CHECK(we_mod_thread_stop(t, 2000u) == 0 && __atomic_load_n(&final_calls, __ATOMIC_RELAXED) == 1,
          "thread: the stop did not return by done after the final write");
    /* a thread wedged past its stop flag: the stop returns by its deadline, abandoning it */
    __atomic_store_n(&wedge, 2, __ATOMIC_RELAXED);
    rc = we_mod_thread_start(&t, 20u, 0u, on_tick, on_final, NULL, why, sizeof why);
    if (rc == 0) {
        t0 = we_mod_monotonic_ms();
        CHECK(we_mod_thread_stop(t, 300u) == 1 && we_mod_monotonic_ms() - t0 >= 300u,
              "thread: a wedged thread's stop did not return by the deadline");
        __atomic_store_n(&wedge, 0, __ATOMIC_RELAXED);   /* let the abandoned thread finish and exit */
        sleep_us(50000);
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* the digest rendering */

static void t_digest(void)
{
    uint8_t dg[32];
    char out[17];

    we_sha256("abc", 3, dg);
    we_digest16(dg, out);
    CHECK(strcmp(out, "ba7816bf8f01cfea") == 0, "digest: \"abc\" renders %s, not sha256sum's ba7816bf8f01cfea", out);
}


/* ---------------------------------------------------------------------------------------------- */
/* --module-cases: the C half of the twin differential (policy_ref.py --module-cases prints the same) */

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0u;

    if (strcmp(h, "-") == 0) {
        return 0u;
    }
    while (h[0] != '\0' && h[1] != '\0' && n < cap) {
        unsigned v;

        if (sscanf(h, "%2x", &v) != 1) {
            break;
        }
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static void print_addr(const we_addr_t *a)
{
    char t[WE_ADDR_TEXT_MAX];

    if (a == NULL || (a->family != 4u && a->family != 6u)) {
        printf("-");
        return;
    }
    we_addr_format(a, t);
    printf("%s", t);
}

static int module_cases(const char *path)
{
    FILE *f = fopen(path, "r");
    static char line[1u << 16];
    unsigned n = 0u;

    if (f == NULL) {
        fprintf(stderr, "test_module: cannot read %s\n", path);
        return 2;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char *w[16], *save = NULL, *t;
        int nw = 0;

        line[strcspn(line, "\n")] = '\0';
        for (t = strtok_r(line, " ", &save); t != NULL && nw < 16; t = strtok_r(NULL, " ", &save)) {
            w[nw++] = t;
        }
        if (nw == 0) {
            continue;
        }
        n++;
        if (strcmp(w[0], "entry") == 0 && nw == 2) {
            static uint8_t b[1u << 15];
            size_t len = unhex(w[1], b, sizeof b);
            we_addr_t a;

            printf("entry %s ", w[1]);
            if (we_mod_entry_parse(b, len, &a) == 0) {
                print_addr(&a);
            } else {
                printf("refused");
            }
            printf("\n");
        } else if (strcmp(w[0], "format") == 0 && nw == 3) {
            we_addr_t a;

            memset(&a, 0, sizeof a);
            unhex(w[2], a.b, 16);
            a.family = (uint8_t)atoi(w[1]);
            printf("format %s %s ", w[1], w[2]);
            print_addr(&a);
            printf("\n");
        } else if (strcmp(w[0], "render") == 0 && nw == 4) {
            uint8_t b[16];
            uint32_t i;
            const char *s = NULL;
            size_t len = 0u;
            char asn[WE_MOD_ASN_BUF];

            memset(b, 0, sizeof b);
            unhex(w[3], b, 16);
            for (i = 0u; i < WE_MOD_ATTRS && strcmp(we_mod_attr(i)->name, w[1]) != 0; i++) {
            }
            if (i == WE_MOD_ATTRS || we_attr_render_fast(i, b, (uint32_t)atoi(w[2]), asn, &s, &len) != 0) {
                printf("render %s %s %s ?no-attribute\n", w[1], w[2], w[3]);
            } else {
                printf("render %s %s %s %.*s\n", w[1], w[2], w[3], (int)len, s);
            }
        } else if (strcmp(w[0], "acme") == 0 && nw == 4) {
            static uint8_t tg[4096], nm[4096];
            size_t tl = unhex(w[2], tg, sizeof tg), nl = unhex(w[3], nm, sizeof nm);

            printf("acme %s %s %s %d\n", w[1], w[2], w[3],
                   we_mod_acme((const uint8_t *)w[1], strlen(w[1]), tg, tl, nm, nl));
        } else if (strcmp(w[0], "walk") == 0) {
            const char *peer = "", *trust = "", *ls = "-";
            uint32_t hops = 0u;
            int header = 0, older = 0, k;
            const char *items[16];
            char tbuf[1024], *ts = NULL, *it;
            size_t ni = 0u;
            we_mod_trust_t tt;
            char err[256];
            static uint8_t lb[64][4096];
            we_mod_line_t lines[64];
            uint32_t nl = 0u;
            we_mod_walk_t r;
            we_addr_t pa;

            for (k = 2; k < nw; k++) {
                if (strncmp(w[k], "peer=", 5) == 0) { peer = w[k] + 5; }
                else if (strncmp(w[k], "header=", 7) == 0) { header = atoi(w[k] + 7); }
                else if (strncmp(w[k], "hops=", 5) == 0) { hops = (uint32_t)atoi(w[k] + 5); }
                else if (strncmp(w[k], "older=", 6) == 0) { older = atoi(w[k] + 6); }
                else if (strncmp(w[k], "trust=", 6) == 0) { trust = w[k] + 6; }
                else if (strncmp(w[k], "lines=", 6) == 0) { ls = w[k] + 6; }
            }
            snprintf(tbuf, sizeof tbuf, "%s", trust);
            for (it = strtok_r(tbuf, ",", &ts); it != NULL && ni < 16u; it = strtok_r(NULL, ",", &ts)) {
                items[ni++] = it;
            }
            if (we_mod_trust_build(items, ni, &tt, NULL, err, sizeof err) != 0) {
                printf("walk %s trust-refused\n", w[1]);
                continue;
            }
            if (strcmp(ls, "-") != 0) {
                char lbuf[1u << 15], *s2 = NULL, *h;

                snprintf(lbuf, sizeof lbuf, "%s", ls);
                for (h = strtok_r(lbuf, "/", &s2); h != NULL && nl < 64u; h = strtok_r(NULL, "/", &s2)) {
                    lines[nl].len = unhex(h, lb[nl], sizeof lb[nl]);
                    lines[nl].p = lb[nl];
                    nl++;
                }
            }
            if (strcmp(peer, "unix") != 0
                    && we_mod_entry_parse((const uint8_t *)peer, strlen(peer), &pa) != 0) {
                printf("walk %s peer-refused\n", w[1]);
                we_mod_trust_free(&tt);
                continue;
            }
            we_mod_walk(&tt, hops, header, strcmp(peer, "unix") == 0 ? NULL : &pa, lines, nl, older, &r);
            printf("walk %s floor=", w[1]);
            print_addr(r.walk == WE_WALK_NO_ADDRESS ? NULL : &r.floor);
            printf(" walk=%u eligible=%u note=%u\n", r.walk, r.eligible, r.note);
            we_mod_trust_free(&tt);
        } else {
            printf("unknown-case %s\n", w[0]);
        }
    }
    fclose(f);
    fprintf(stderr, "test_module: %u module cases\n", n);
    return 0;
}

/* ---------------------------------------------------------------------------------------------- */
/* the rows on the walk's line cap, the severity scan, the ABI, the ownership flag, a reused
 * scratch, the network file systems, the planes' lifecycle, and V2, N2 and E1 over the walk corpus's input
 * classes (walk_classes.h: each class's walk through the parse loop, the decision, the record, the lazy fill
 * and every request-path renderer, and five ACME shapes; proven for those classes, not for every input) */

/* the line cap: 17 lines walk exactly as the newest 16 with older set, whatever the oldest line holds */
static void t_walk_cap(void)
{
    const char *items[] = { "10.0.0.0/8" };
    we_mod_trust_t t;
    we_mod_line_t lines[40];
    we_mod_walk_t a, b, c;
    we_addr_t peer = A("10.0.0.1");
    char err[256];
    uint32_t i, hops;
    int same = 1;

    if (we_mod_trust_build(items, 1u, &t, NULL, err, sizeof err) != 0) {
        CHECK(0, "walk cap: the trust table is refused: %s", err);
        return;
    }
    lines[0].p = (const uint8_t *)"203.0.113.9";
    lines[0].len = 11u;
    for (i = 1u; i < 40u; i++) {
        lines[i].p = (const uint8_t *)"";
        lines[i].len = 0u;
    }
    for (hops = 0u; hops <= 2u; hops++) {
        we_mod_walk(&t, hops, 1, &peer, lines, 17u, 0, &a);
        we_mod_walk(&t, hops, 1, &peer, lines + 1, 16u, 1, &b);
        we_mod_walk(&t, hops, 1, &peer, lines, 40u, 0, &c);
        same &= addr_eq(&a.floor, &b.floor) && a.walk == b.walk && a.eligible == b.eligible && a.note == b.note
             && addr_eq(&c.floor, &b.floor) && c.walk == b.walk && c.note == b.note;
    }
    CHECK(same && a.walk == WE_WALK_FLOOR_HEADER_MISSING && a.note == WE_MOD_NOTE_UNPARSED,
          "walk cap: 17 lines do not walk as the newest 16 with older set (walk %u note %u; the oldest line's "
          "203.0.113.9 must not be reached)", a.walk, a.note);
    we_mod_trust_free(&t);
}

/*
 * Which field lines are walked (row T5): a trusted proxy appends its line after the client's own, so the
 * entry judged is the proxy's, after one forged line and after sixteen. WE_MOD_TEST_FIRST_LINE (the first line
 * alone) and WE_MOD_TEST_FIRST_16_LINES (the oldest sixteen) each judge a forged entry, and fail by name.
 */
static void t_walk_lines(void)
{
    const char *items[] = { "10.0.0.0/8" };
    we_mod_trust_t t;
    we_mod_line_t lines[17];
    we_mod_walk_t w;
    we_addr_t peer = A("10.0.0.1"), want = A("198.51.100.7");
    char err[256];
    uint32_t i;

    if (we_mod_trust_build(items, 1u, &t, NULL, err, sizeof err) != 0) {
        CHECK(0, "walk lines: the trust table is refused: %s", err);
        return;
    }
    for (i = 0u; i < 17u; i++) {
        lines[i].p = (const uint8_t *)"203.0.113.66";   /* the client's own, forged */
        lines[i].len = 12u;
    }
    lines[1].p = (const uint8_t *)"198.51.100.7";       /* the proxy's, appended after the client's */
    lines[1].len = 12u;
    we_mod_walk(&t, 1u, 1, &peer, lines, 2u, 0, &w);
    CHECK(w.walk == WE_WALK_OK && addr_eq(&w.floor, &want),
          "walk lines: after one forged field line the proxy's line was not the one judged (walk %u)", w.walk);
    lines[1].p = (const uint8_t *)"203.0.113.66";
    lines[16].p = (const uint8_t *)"198.51.100.7";      /* sixteen forged lines, then the proxy's */
    we_mod_walk(&t, 1u, 1, &peer, lines, 17u, 0, &w);
    CHECK(w.walk == WE_WALK_OK && addr_eq(&w.floor, &want),
          "walk lines: after sixteen forged field lines the proxy's line was not the one judged (walk %u)", w.walk);
    we_mod_trust_free(&t);
}

/* the severity scan visits only set bits: none for the all-clear allow */
static void t_severity(void)
{
    we_mod_cfg_t c;
    we_mod_ctx_t x;
    we_verdict_t v;

    memset(&c, 0, sizeof c);
    memset(&x, 0, sizeof x);
    memset(&v, 0, sizeof v);
    g_sev_steps = 0u;
    CHECK(we_mod_severity(&c, &x, &v) == 0u && g_sev_steps == 0u,
          "severity: the all-clear allow tested %u bits, not 0", g_sev_steps);
    v.log_fired[0][0] = 0x05u;               /* floor rules 1 and 3 */
    v.log_fired[1][31] = 0x80u;              /* the context's rule 256 */
    g_sev_steps = 0u;
    CHECK(we_mod_severity(&c, &x, &v) == 0u && g_sev_steps == 3u,
          "severity: three log bits tested %u bits, not 3", g_sev_steps);
}

/* the network file systems by their statfs magic */
static void t_netfs(void)
{
    CHECK(we_mod_netfs_name(0x6969) != NULL && strcmp(we_mod_netfs_name(0x6969), "NFS") == 0
          && we_mod_netfs_name(0x65735546) != NULL && we_mod_netfs_name((long)0xFF534D42u) != NULL,
          "binding: NFS (0x6969), FUSE and CIFS are not recognised as network file systems");
    CHECK(we_mod_netfs_name(0xEF53) == NULL && we_mod_netfs_name(0x01021994) == NULL,
          "binding: ext4 or tmpfs is taken for a network file system");
}

/* the core refuses a publish on a handle a module owns, before it loads anything */
static void t_ownership(const char *planes)
{
    we_handle_t h;
    char path[1100];
    we_map_t *rv = we_map_new_revoked();

    memset(&h, 0, sizeof h);
    h.module_owned = 1u;
    snprintf(path, sizeof path, "%s/reputation.bin", planes);
    CHECK(we_handle_publish_plane(&h, path, 1700000000000ull, NULL) == WE_ERR_OWNERSHIP && we_current(&h) == NULL
          && h.loads_failed == 0u, "ownership: a core publish reached a module-owned handle");
    CHECK(we_handle_publish(&h, path, 1700000000000ull) == WE_ERR_OWNERSHIP && we_current(&h) == NULL,
          "ownership: the legacy publish reached a module-owned handle");
    CHECK(rv != NULL && we_handle_publish_map(&h, rv, 1700000000000ull) == WE_ERR_OWNERSHIP && we_current(&h) == NULL,
          "ownership: the revocation publish reached a module-owned handle");
    CHECK(strcmp(we_strerror(WE_ERR_OWNERSHIP), "unknown error") != 0
          && strcmp(we_mod_strerror(WE_MOD_ERR_ABI), "unknown error") != 0, "ownership: a code without its text");
    free(rv);
}

/*
 * A scratch reused across two requests serves no previous memo: the second decision, for the same
 * address after a publish, reads the new generation. Its control is the trace build without the memo
 * reset (WE_TEST_NO_MEMO_RESET), which serves the first request's entry.
 */
static void t_scratch_reuse(const char *planes)
{
    fixture_t f;
    static we_mod_scratch_t s;
    uint64_t shard[SHARD_N], now = 1700000000000ull;
    we_mod_req_t q = REQ("198.51.100.1", NULL, WE_WALK_OK, 0, 0, 0);
    we_policy_directive_t d[] = { D(WE_DIR_POLICY, "http/s1", "log if tor_exit") };
    we_map_t *st;

    if (fixture_make(&f, planes, d, sizeof d / sizeof d[0], 0u, now) != 0) {
        return;
    }
    memset(&s, 0, sizeof s);
    we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
    CHECK(s.v.log_fired[1][0] == 0x01u, "scratch reuse: the tor exit's log rule did not fire on the first request");
    /* the plane's view replaced (as a disarm would) and the same scratch reused for the same address */
    st = we_mod_standin_new(WE_PLANE_TOR);
    {
        we_map_t *orig = (we_map_t *)(uintptr_t)we_current(&f.h[1]);

        if (st != NULL && we_handle_set_view(&f.h[1], orig, st) == WE_OK) {
            we_mod_decide(&f.cfg, &f.ctx, &s, shard, &q, now);
            CHECK(s.v.log_fired[1][0] == 0x00u, "scratch reuse: a reused scratch served the previous request's tor "
                  "entry after the view changed (the stale memo)");
            we_handle_set_view(&f.h[1], st, orig);   /* the fixture's own map back, which it frees */
        }
    }
    fixture_free(&f);
    free(st);
}

/* ---- the planes ---- */

static char g_log[16][160];                    /* the logger's lines since the last pl_log_reset(), in arrival order */
static unsigned g_nlog;

static void pl_log_reset(void)
{
    g_nlog = 0u;
}

static void pl_logger(void *ud, const char *line)
{
    (void)ud;
    if (g_nlog < 16u) {
        snprintf(g_log[g_nlog], sizeof g_log[g_nlog], "%s", line);
    }
    g_nlog++;
    if (getenv("WE_TEST_MODULE_VERBOSE") != NULL) {
        printf("  log: %s\n", line);
    }
}

/* a reputation plane of one range at `generation`, written 0444 by rename into dir/reputation.bin */
static int pl_write_rep(const char *dir, const char *name, uint64_t generation, uint64_t valid_until_ms, uint32_t first)
{
    static __uint128_t s4[1], e4[1];
    ww_plane_t p;
    char tmp[1100], fin[1100];

    memset(&p, 0, sizeof p);
    s4[0] = first;
    e4[0] = first + 255u;
    p.format = 1u;
    p.schema = 1;
    p.plane = WE_PLANE_REPUTATION;
    p.generation = generation;
    p.valid_until_ms = valid_until_ms;
    p.v4.n = 1u;
    p.v4.start = s4;
    p.v4.end = e4;
    snprintf(tmp, sizeof tmp, "%s/.%s.new", dir, name);
    snprintf(fin, sizeof fin, "%s/%s", dir, name);
    if (ww_write(tmp, &p) != 0 || chmod(tmp, 0444) != 0 || rename(tmp, fin) != 0) {
        return -1;
    }
    return 0;
}

/* one tick of the thread followed by the loop's apply, as nginx would run them */
static void pl_cycle(we_mod_planes_t *pl, uint64_t tick)
{
    we_mod_planes_tick(pl, tick, NULL);
    we_mod_planes_apply(pl, pl_logger, NULL);
    we_mod_planes_tick(pl, tick, NULL);      /* the acknowledgements folded in, as the next tick would */
}

/* does any line captured since the last pl_log_reset() say this? */
static int pl_log_has(const char *needle)
{
    unsigned i;

    for (i = 0u; i < g_nlog && i < 16u; i++) {
        if (strstr(g_log[i], needle) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* a reputation plane of PL_BIG ranges, bigger than a 1 MiB chunk, written 0444 by rename: a budgeted
 * verification of it spans more than one chunk, and its buffer is the size a fork must not inherit */
#define PL_BIG 120000u
static __uint128_t pl_s4[PL_BIG], pl_e4[PL_BIG];

static int pl_write_rep_big(const char *dir, const char *name, uint64_t generation, uint64_t valid_until_ms)
{
    ww_plane_t p;
    char tmp[1100], fin[1100];
    uint32_t i;

    for (i = 0u; i < PL_BIG; i++) {
        pl_s4[i] = (__uint128_t)0xC0000200u + (__uint128_t)i * 0x100u;
        pl_e4[i] = pl_s4[i] + 0xFFu;
    }
    memset(&p, 0, sizeof p);
    p.format = 1u;
    p.schema = 1;
    p.plane = WE_PLANE_REPUTATION;
    p.generation = generation;
    p.valid_until_ms = valid_until_ms;
    p.v4.n = PL_BIG;
    p.v4.start = pl_s4;
    p.v4.end = pl_e4;
    snprintf(tmp, sizeof tmp, "%s/.%s.new", dir, name);
    snprintf(fin, sizeof fin, "%s/%s", dir, name);
    if (ww_write(tmp, &p) != 0 || chmod(tmp, 0444) != 0 || rename(tmp, fin) != 0) {
        return -1;
    }
    return 0;
}

/* this process's own >= 1 MiB writable anonymous mappings, counted from /proc/self/maps; the count is
 * poisoned when its own maps cannot be read, so a row that proved nothing fails instead of passing */
static uint32_t pl_anon_count(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uint32_t n = 0u;

    if (f == NULL) {
        return 0xFFFFFFFFu;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        unsigned long lo, hi;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) == 3 && perms[0] == 'r' && perms[1] == 'w'
                && (size_t)(hi - lo) >= (1u << 20) && strchr(line, '/') == NULL && strchr(line, '[') == NULL) {
            n++;
        }
    }
    fclose(f);
    return n;
}

/* one forked child's count, handed back over a pipe: the child looks at its own maps and leaves at once */
static uint32_t pl_fork_count(void)
{
    int pfd[2];
    pid_t pid;
    uint32_t v = 0xFFFFFFFFu;

    if (pipe(pfd) != 0) {
        return 0xFFFFFFFFu;
    }
    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return 0xFFFFFFFFu;
    }
    if (pid == 0) {
        uint32_t mine = pl_anon_count();

        close(pfd[0]);
        if (write(pfd[1], &mine, sizeof mine) == (ssize_t)sizeof mine) {
            close(pfd[1]);
            _exit(0);
        }
        _exit(1);
    }
    close(pfd[1]);
    if (read(pfd[0], &v, sizeof v) != (ssize_t)sizeof v) {
        v = 0xFFFFFFFFu;
    }
    close(pfd[0]);
    waitpid(pid, NULL, 0);
    return v;
}

static void t_planes(void)
{
    char base[256], dir[300], why[512], path[400];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    we_mod_status_t st;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;
    const we_map_t *cur;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "planes: no trusted base directory to build the planes under; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/planes", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0, "planes: the first generation is not written");

    /* the ABI: a module compiled against another header is refused at binding */
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION + 1u;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == WE_MOD_ERR_ABI && pl == NULL && strstr(why, "ABI") != NULL,
          "planes: a module built against ABI %u was bound (rc %d): %s", WE_MODULE_ABI_VERSION + 1u, rc, why);
    /* a relative snapshot path and a data directory the trust walk refuses: each plane they name refused at
     * configuration (`-r`, the reason with the fix), never the binding: that is the conflict's alone */
    {
        we_mod_bind_args_t bad = args;
        char open_dir[320];
        we_mod_planes_t *bp = NULL;
        we_mod_cfg_t bc;
        const char *r;

        bad.abi = WE_MODULE_ABI_VERSION;
        bad.data_dir = NULL;
        bad.legacy_file = "snapshot.bin";
        memset(&bc, 0, sizeof bc);
        rc = we_mod_bind(&bc, &bad, &bp, why, sizeof why);
        r = we_mod_plane_config_refusal(bp, 0u);
        CHECK(rc == 0 && bp != NULL && bc.handle[0] == NULL && bc.static_reason[0] == WE_MOD_NOMAP_REFUSED
              && r != NULL && strstr(r, "absolute path") != NULL && strstr(r, "name it from /") != NULL,
              "planes: a relative snapshot path did not refuse its plane alone, with the fix (rc %d, reason %s): %s",
              rc, r != NULL ? r : "(none)", why);
        we_mod_planes_release(bp);
        bp = NULL;
        snprintf(open_dir, sizeof open_dir, "%s/open", base);
        mkdir(open_dir, 0777);
        chmod(open_dir, 0777);
        bad.legacy_file = NULL;
        bad.data_dir = open_dir;
        memset(&bc, 0, sizeof bc);
        rc = we_mod_bind(&bc, &bad, &bp, why, sizeof why);
        r = we_mod_plane_config_refusal(bp, 0u);
        CHECK(rc == 0 && bp != NULL && bc.handle[0] == NULL && bc.static_reason[0] == WE_MOD_NOMAP_REFUSED
              && r != NULL && strstr(r, open_dir) != NULL && we_mod_plane_config_refusal(bp, 1u) == NULL,
              "planes: a world-writable data directory did not refuse the plane it holds alone (rc %d, reason %s): %s",
              rc, r != NULL ? r : "(none)", why);
        we_mod_planes_release(bp);
        CHECK(strcmp(we_mod_strerror(WE_MOD_ERR_CONFIG), "the configuration names the reputation plane's file twice") == 0,
              "planes: WE_MOD_ERR_CONFIG's text is not the conflict's, its one remaining cause");
        rmdir(open_dir);
        CHECK(strcmp(we_mod_strerror(WE_MOD_ERR_CAP), "the configuration counts more rule slots than one may hold") == 0
              && strcmp(we_mod_strerror(WE_MOD_ERR_THREAD), "the module's thread could not be started") == 0
              && strcmp(we_mod_strerror(WE_ERR_MMAP), "cannot allocate for snapshot") == 0,
              "planes: a module code has no text of its own");
    }

    /* the supervisor's binding: verified by pread, mapped, published on a module-owned handle */
    args.abi = WE_MODULE_ABI_VERSION;
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL, "planes: the binding is refused (rc %d): %s", rc, why);
    if (pl == NULL) {
        return;
    }
    cur = we_current(cfg.handle[0]);
    CHECK(cfg.bound_mask == 0x01u && cur != NULL && cur->generation == 100u && cfg.handle[0]->module_owned == 1u
          && cfg.standin[0] != NULL && cfg.handle[1] == NULL && cfg.static_reason[1] == WE_MOD_NOMAP_ABSENT,
          "planes: the binding did not arm reputation alone on a module-owned handle (mask %02x, generation %llu)",
          cfg.bound_mask, cur != NULL ? (unsigned long long)cur->generation : 0ull);
    CHECK(cur != NULL && we_eval_peek(cur, now, 0xC0000201u) != WE_ST_UNKNOWN,
          "planes: the armed mapping does not answer its own range");
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(we_handle_publish_plane(cfg.handle[0], path, now, NULL) == WE_ERR_OWNERSHIP,
          "planes: a core publish reached the module's handle");

    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0 && we_current(cfg.handle[0]) == cur,
          "planes: the worker-start check changed an unchanged plane: %s", why);

    /* (f) a newer generation at a new inode: verified, published, the old mapping retired */
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, far, 0xC0000300u) == 0, "planes: the second generation is not written");
    pl_cycle(pl, 1u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 200u && cfg.handle[0]->high_water == 200u,
          "planes: a newer generation was not armed (current %llu)", cur != NULL ? (unsigned long long)cur->generation : 0ull);

    /* (g) an older generation at a new inode: refused by its header, remembered, the armed one serves */
    CHECK(pl_write_rep(dir, "reputation.bin", 150u, far, 0xC0000400u) == 0, "planes: the old generation is not written");
    pl_cycle(pl, 2u);
    CHECK(we_current(cfg.handle[0]) == cur, "planes: a rollback replaced the armed map");
    we_mod_planes_status(pl, &st, now);
    CHECK(strcmp(st.plane[0].state, "armed") == 0 && st.plane[0].generation == 200u,
          "planes: after a refused rollback the status reads %s %llu", st.plane[0].state,
          (unsigned long long)st.plane[0].generation);

    /* a corrupt candidate (one byte past the header flipped): refused by its digest, the armed one serves */
    CHECK(pl_write_rep(dir, "reputation.bin", 300u, far, 0xC0000500u) == 0, "planes: the third generation is not written");
    {
        int fd;
        uint8_t b;

        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "planes: the corruption is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    pl_cycle(pl, 3u);
    CHECK(we_current(cfg.handle[0]) == cur, "planes: a corrupt candidate replaced the armed map");
    pl_cycle(pl, 4u);
    CHECK(we_current(cfg.handle[0]) == cur, "planes: a remembered failure was retried and changed the armed map");

    /* (b) the armed inode's ctime alone, through a chmod that admits a writer: disarmed at once */
    CHECK(pl_write_rep(dir, "reputation.bin", 400u, far, 0xC0000600u) == 0, "planes: the fourth generation is not written");
    pl_cycle(pl, 5u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 400u, "planes: generation 400 was not armed");
    {
        /* a ctime moves on the kernel's coarse clock: a chmod within its tick of the rename leaves it equal */
        struct timespec pause = { 0, 30000000 };

        nanosleep(&pause, NULL);
    }
    chmod(path, 0644);
    pl_cycle(pl, 6u);
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0],
          "planes: an armed file whose mode admits a writer was not disarmed to its stand-in");
    /* the fix applied in place: the trust checks pass, the re-digest matches, re-armed */
    {
        struct timespec pause = { 0, 30000000 };

        nanosleep(&pause, NULL);
    }
    chmod(path, 0444);
    pl_cycle(pl, 7u);
    pl_cycle(pl, 8u);
    CHECK(we_current(cfg.handle[0]) == cur, "planes: the fixed file was not re-armed by its digest");

    /* (c) a touch -m: disarmed at once, re-armed when the bytes still carry the arm-time digest */
    {
        struct timespec ts[2];

        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec = 1000000000;
        ts[1].tv_nsec = 0;
        utimensat(AT_FDCWD, path, ts, 0);
    }
    pl_cycle(pl, 9u);
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "planes: an armed file whose mtime moved was not disarmed");
    pl_cycle(pl, 10u);
    pl_cycle(pl, 11u);
    CHECK(we_current(cfg.handle[0]) == cur, "planes: a touch -m with the bytes unchanged was not re-armed");

    /* (c) an in-place rewrite of the bytes: disarmed, and the disarm final */
    {
        int fd;
        uint8_t b;

        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "planes: the rewrite is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    pl_cycle(pl, 12u);
    pl_cycle(pl, 13u);
    pl_cycle(pl, 14u);
    we_mod_planes_status(pl, &st, now);
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0] && strcmp(st.plane[0].state, "disarmed") == 0
          && strstr(st.plane[0].reason, "final") != NULL,
          "planes: bytes rewritten in place were not disarmed for good (state %s, reason %s)", st.plane[0].state,
          st.plane[0].reason);
    /* the next generation re-arms */
    CHECK(pl_write_rep(dir, "reputation.bin", 500u, far, 0xC0000700u) == 0, "planes: the fifth generation is not written");
    pl_cycle(pl, 15u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 500u, "planes: the next generation did not re-arm after a final disarm");

    /* (b) a rewrite in place with its size and mtime restored, so only the ctime moved: the trust checks pass
     * (mode 0444 again, the same owner) and the re-digest finds the bytes changed, so the disarm is final and
     * the forged bytes never serve */
    {
        struct stat sb;
        struct timespec ts[2], pause = { 0, 30000000 };
        int fd;
        uint8_t b;

        CHECK(stat(path, &sb) == 0, "planes: the armed file cannot be stat'ed");
        nanosleep(&pause, NULL);
        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "planes: the ctime-only rewrite is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1] = sb.st_mtim;
        CHECK(utimensat(AT_FDCWD, path, ts, 0) == 0, "planes: the armed file's mtime is not restorable");
    }
    pl_cycle(pl, 16u);
    pl_cycle(pl, 17u);
    pl_cycle(pl, 18u);
    we_mod_planes_status(pl, &st, now);
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0] && strcmp(st.plane[0].state, "disarmed") == 0,
          "planes: bytes rewritten in place with the mtime restored still serve (state %s): the ctime alone was not "
          "re-digested", st.plane[0].state);
    CHECK(pl_write_rep(dir, "reputation.bin", 600u, far, 0xC0000800u) == 0, "planes: the sixth generation is not written");
    pl_cycle(pl, 19u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 600u, "planes: generation 600 did not re-arm after the ctime arm");

    /* stale: past its valid-until the armed map serves, read stale by the status, never digested again */
    we_mod_planes_status(pl, &st, far + 1u);
    CHECK(strcmp(st.plane[0].state, "stale") == 0 && st.plane[0].remaining_ms < 0,
          "planes: past valid-until the status reads %s", st.plane[0].state);
    we_mod_planes_release(pl);
    rm_tree(base);
}

/* the tenant plane: its deletion revokes the allow list through the compare-and-swap */
/*
 * A plane present but unreadable by the configuration reader: the bind's open fails with
 * EACCES, and the plane is told apart from the two states it could be mistaken for. Not absent: the file is
 * there, and the token says `-u`, not `-a`. Not refused: nothing was verified, so it is not bound, its rules
 * are inert, and no handle reads it as `-r`. The comparison arm is the same plane present and readable but
 * refused on verification (mode 0644, a writer besides its owner): bound, `-r`. The open is refused by mode
 * 0000, which root's DAC override ignores, so as root the rows cannot be built and say so instead.
 */
static void t_planes_unreadable(void)
{
    char base[256], dir[300], path[400], why[512], g[WE_MOD_GEN_MAX];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_record_t rec;
    we_memo_entry_t e;
    uint64_t far = 4102444800000ull;
    int rc;

    if (geteuid() == 0u) {
        printf("  note  unreadable: euid 0 reads a mode-0000 plane, so the unreadable rows did not run\n");
        return;
    }
    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "unreadable: no trusted base directory to build the plane under; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/unreadable", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0 && chmod(path, 0000) == 0,
          "unreadable: the plane is not written at mode 0000");

    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL, "unreadable: the binding is refused (rc %d): %s", rc, why);
    CHECK((cfg.bound_mask & 0x01u) == 0u && cfg.handle[0] == NULL && cfg.static_reason[0] == WE_MOD_NOMAP_UNREADABLE,
          "unreadable: a plane the configuration reader cannot open is bound %u, handle %s, static reason %u, not unbound "
          "and unreadable (%u)", cfg.bound_mask & 0x01u, cfg.handle[0] != NULL ? "set" : "none",
          (unsigned)cfg.static_reason[0], (unsigned)WE_MOD_NOMAP_UNREADABLE);
    memset(&rec, 0, sizeof rec);
    memset(&e, 0, sizeof e);
    rec.gen_mask = 0x01u;
    we_mod_memo_put(&rec, &cfg, 0u, &e, WE_ST_UNKNOWN, cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL, 0);
    we_mod_render_generations(&rec, g);
    CHECK(strcmp(g, "reputation:-u") == 0, "unreadable: the token of a plane present and unreadable is \"%s\", not "
          "\"reputation:-u\"", g);
    if (pl != NULL) {
        we_mod_planes_release(pl);
        pl = NULL;
    }

    /* the comparison: present, readable, refused on verification (0644: a writer besides its owner) */
    CHECK(chmod(path, 0644) == 0, "unreadable: the plane's mode is not 0644");
    memset(&cfg, 0, sizeof cfg);
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL && (cfg.bound_mask & 0x01u) != 0u
          && we_current(cfg.handle[0]) == NULL && cfg.static_reason[0] == WE_MOD_NOMAP_NONE,
          "unreadable: the comparison plane (readable, refused on verification) is not bound with no map (rc %d): %s", rc, why);
    memset(&rec, 0, sizeof rec);
    rec.gen_mask = 0x01u;
    we_mod_memo_put(&rec, &cfg, 0u, &e, WE_ST_UNKNOWN, cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL, 0);
    we_mod_render_generations(&rec, g);
    CHECK(strcmp(g, "reputation:-r") == 0, "unreadable: the token of a plane refused on verification is \"%s\", not "
          "\"reputation:-r\"", g);
    if (pl != NULL) {
        we_mod_planes_release(pl);
    }
    unlink(path);
    rmdir(dir);
}

/* the plane's status word and its token letter, read the way the status file and a request read them */
static void nm_read(we_mod_planes_t *pl, const we_mod_cfg_t *cfg, char state[16], char g[WE_MOD_GEN_MAX])
{
    we_mod_status_t st;
    we_mod_record_t rec;
    we_memo_entry_t e;

    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, 1700000000000ull);
    snprintf(state, 16, "%s", st.plane[0].state);
    memset(&rec, 0, sizeof rec);
    memset(&e, 0, sizeof e);
    rec.gen_mask = 0x01u;
    we_mod_memo_put(&rec, cfg, 0u, &e, WE_ST_UNKNOWN, cfg->handle[0] != NULL ? we_current(cfg->handle[0]) : NULL, 0);
    we_mod_render_generations(&rec, g);
}

/* a reputation plane written by rename at 0444 with its last byte flipped: the header peeks clean, the digest fails */
static int nm_write_corrupt(const char *dir, uint64_t generation)
{
    char tmp[400], fin[400];
    int fd;
    off_t end;
    unsigned char b;

    if (pl_write_rep(dir, ".corrupt.bin", generation, 4102444800000ull, 0xC0000400u) != 0) {
        return -1;
    }
    snprintf(tmp, sizeof tmp, "%s/.corrupt.bin", dir);
    snprintf(fin, sizeof fin, "%s/reputation.bin", dir);
    if (chmod(tmp, 0644) != 0 || (fd = open(tmp, O_RDWR)) < 0) {
        return -1;
    }
    end = lseek(fd, -1, SEEK_END);
    if (end < 0 || pread(fd, &b, 1, end) != 1) {
        close(fd);
        return -1;
    }
    b ^= 0x01u;
    if (pwrite(fd, &b, 1, end) != 1 || close(fd) != 0 || chmod(tmp, 0444) != 0 || rename(tmp, fin) != 0) {
        return -1;
    }
    return 0;
}

/*
 * The no-map reason the plane's single writer stores, against the status the same plane reports (the
 * letters -l and -r: "stored before every publication that leaves or keeps the view NULL"). A plane
 * refused at configuration load reads refused and -r; a new generation whose verification is in flight
 * reads loading and -l, in the status and in the token alike; a verification that fails goes back to
 * refused and -r; one that passes arms. The supervisor's budgeted verification holds it in flight: a
 * zero budget starts the verification and reads nothing.
 */
static void t_planes_noreason(void)
{
    char base[256], dir[300], path[400], why[512], g[WE_MOD_GEN_MAX], state[16];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    uint32_t armed = 0u;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "no-map reason: no trusted base directory to build the plane under; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/noreason", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0 && chmod(path, 0644) == 0,
          "no-map reason: the refused plane is not written");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "no-map reason: the binding is refused (rc %d): %s", rc, why);
    if (pl == NULL || cfg.handle[0] == NULL) {
        return;
    }
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "refused") == 0 && strcmp(g, "reputation:-r") == 0,
          "no-map reason: a plane refused at configuration load reads \"%s\" and \"%s\", not refused and -r", state, g);

    /* a good generation, its verification started and held in flight */
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, 4102444800000ull, 0xC0000300u) == 0,
          "no-map reason: the good generation is not written");
    (void)we_mod_planes_monitor(pl, 0u, &armed);
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "loading") == 0 && strcmp(g, "reputation:-l") == 0,
          "no-map reason: a plane refused at load whose next generation is being verified reads \"%s\" and \"%s\", "
          "not loading and -l", state, g);
    (void)we_mod_planes_monitor(pl, 60000u, &armed);
    nm_read(pl, &cfg, state, g);
    CHECK(armed == 0x01u && strcmp(state, "armed") == 0 && strncmp(g, "reputation:-", 12) != 0
          && cfg.handle[0] != NULL && we_current(cfg.handle[0]) != NULL && we_current(cfg.handle[0])->generation == 200u,
          "no-map reason: the verified generation did not arm (mask %02x): \"%s\", \"%s\"", armed, state, g);
    we_mod_planes_release(pl);
    pl = NULL;

    /* refused at load, then a corrupt generation: loading and -l while in flight, refused and -r when it fails */
    CHECK(chmod(path, 0644) == 0, "no-map reason: the plane's mode is not 0644");
    memset(&cfg, 0, sizeof cfg);
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "no-map reason: the second binding is refused (rc %d): %s", rc, why);
    if (pl == NULL || cfg.handle[0] == NULL) {
        return;
    }
    CHECK(nm_write_corrupt(dir, 300u) == 0, "no-map reason: the corrupt generation is not written");
    (void)we_mod_planes_monitor(pl, 0u, &armed);
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "loading") == 0 && strcmp(g, "reputation:-l") == 0,
          "no-map reason: a corrupt generation in flight reads \"%s\" and \"%s\", not loading and -l", state, g);
    (void)we_mod_planes_monitor(pl, 60000u, &armed);
    nm_read(pl, &cfg, state, g);
    CHECK(armed == 0u && strcmp(state, "refused") == 0 && strcmp(g, "reputation:-r") == 0,
          "no-map reason: a corrupt generation that failed its digest reads \"%s\" and \"%s\", not refused and -r", state, g);
    we_mod_planes_release(pl);
    unlink(path);
    rmdir(dir);
}

/*
 * A snapshot path the refresh has not filled yet: bound (the legacy file is watched by name), no file at
 * all, so the plane is absent, never refused. Refused is for a file that failed its checks; a fresh install
 * before its first refresh has nothing that failed.
 */
/*
 * The per-plane binding (ABI 5): `whisper_edge_data <plane> <absolute file>` binds the plane to
 * that file over the directory, by the line itself whatever reads the plane, its directory trust-walked as the
 * data directory is; the snapshot beside a directory is the reputation plane's file, never dropped and never
 * legacy; both naming the reputation plane is refused, and so are a relative path and an untrusted directory.
 */
static void t_plane_file(void)
{
    char base[256], dd[300], fd[300], od[300], file[400], snap[400], ofile[400], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    const we_map_t *cur;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "plane file: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dd, sizeof dd, "%s/pf-dir", base);
    snprintf(fd, sizeof fd, "%s/pf-files", base);
    snprintf(od, sizeof od, "%s/pf-open", base);
    mkdir(dd, 0755); chmod(dd, 0755);
    mkdir(fd, 0755); chmod(fd, 0755);
    mkdir(od, 0777); chmod(od, 0777);
    snprintf(file, sizeof file, "%s/edge-reputation.bin", fd);
    snprintf(snap, sizeof snap, "%s/snapshot.bin", fd);
    snprintf(ofile, sizeof ofile, "%s/reputation.bin", od);
    CHECK(pl_write_rep(dd, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0
          && pl_write_rep(fd, "edge-reputation.bin", 200u, 4102444800000ull, 0xC0000300u) == 0
          && pl_write_rep(fd, "snapshot.bin", 300u, 4102444800000ull, 0xC0000400u) == 0
          && pl_write_rep(od, "reputation.bin", 400u, 4102444800000ull, 0xC0000500u) == 0,
          "plane file: the fixtures are not written");
    args.abi = WE_MODULE_ABI_VERSION;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;

    /* a per-plane file over the directory, bound with nothing reading the plane */
    memset(&cfg, 0, sizeof cfg);
    args.data_dir = dd;
    args.read_mask = 0x00u;
    args.plane_file[0] = file;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    cur = rc == 0 && cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL;
    CHECK(cur != NULL && cur->generation == 200u, "plane file: a per-plane file over the directory bound generation %llu, "
          "not the file's 200 (rc %d): %s", cur != NULL ? (unsigned long long)cur->generation : 0ull, rc, why);
    CHECK(pl != NULL && we_mod_plane_path(pl, 0u) != NULL && strcmp(we_mod_plane_path(pl, 0u), file) == 0,
          "plane file: the plane's path line is \"%s\", not the per-plane file", pl != NULL && we_mod_plane_path(pl, 0u) != NULL ? we_mod_plane_path(pl, 0u) : "(none)");
    if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }
    args.plane_file[0] = NULL;

    /* the snapshot beside the directory: the reputation plane's file, never dropped */
    memset(&cfg, 0, sizeof cfg);
    args.read_mask = 0x01u;
    args.legacy_file = snap;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    cur = rc == 0 && cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL;
    CHECK(cur != NULL && cur->generation == 300u, "plane file: a snapshot beside a directory bound generation %llu, not "
          "the snapshot's 300 (rc %d): %s", cur != NULL ? (unsigned long long)cur->generation : 0ull, rc, why);
    if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }

    /* and not legacy: a snapshot that is not there is absent, not the directory's file and not armed on appearance */
    memset(&cfg, 0, sizeof cfg);
    snprintf(snap, sizeof snap, "%s/no-such-snapshot.bin", fd);
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && cfg.handle[0] == NULL && cfg.static_reason[0] == WE_MOD_NOMAP_ABSENT,
          "plane file: a snapshot file that is not there, beside a directory, bound something (rc %d, handle %s)", rc,
          cfg.handle[0] != NULL ? "set" : "none");
    if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }

    /* a directory holding snapshot.bin and no reputation.bin binds no reputation plane (the bind refuses that fallback) */
    {
        char sd[300], sf[400];

        snprintf(sd, sizeof sd, "%s/pf-snaponly", base);
        mkdir(sd, 0755); chmod(sd, 0755);
        snprintf(sf, sizeof sf, "%s/snapshot.bin", sd);
        CHECK(pl_write_rep(sd, "snapshot.bin", 500u, 4102444800000ull, 0xC0000600u) == 0, "plane file: no snapshot-only fixture");
        memset(&cfg, 0, sizeof cfg);
        args.data_dir = sd;
        args.legacy_file = NULL;
        rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
        CHECK(rc == 0 && cfg.handle[0] == NULL, "plane file: a directory holding only snapshot.bin bound the reputation plane "
              "from it (rc %d, generation %llu): the fallback the bind refuses", rc,
              cfg.handle[0] != NULL && we_current(cfg.handle[0]) != NULL ? (unsigned long long)we_current(cfg.handle[0])->generation : 0ull);
        if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }
        args.data_dir = dd;
        args.legacy_file = snap;
        unlink(sf);
        rmdir(sd);
    }

    /* both naming the reputation plane: refused */
    memset(&cfg, 0, sizeof cfg);
    args.plane_file[0] = file;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == WE_MOD_ERR_CONFIG && pl == NULL && strstr(why, "both name the reputation plane") != NULL,
          "plane file: the snapshot and a reputation line together were not refused (rc %d): %s", rc, why);
    args.legacy_file = NULL;

    /* a per-plane file in a directory others can write: that plane refused by its own trust walk, named */
    memset(&cfg, 0, sizeof cfg);
    args.plane_file[0] = ofile;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] == NULL && we_mod_plane_config_refusal(pl, 0u) != NULL
          && strstr(we_mod_plane_config_refusal(pl, 0u), ofile) != NULL,
          "plane file: a per-plane file in a world-writable directory did not refuse its plane by name (rc %d): %s", rc, why);
    if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }

    /* a relative per-plane path: that plane refused */
    memset(&cfg, 0, sizeof cfg);
    args.plane_file[0] = "edge-reputation.bin";
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.static_reason[0] == WE_MOD_NOMAP_REFUSED && we_mod_plane_config_refusal(pl, 0u) != NULL
          && strstr(we_mod_plane_config_refusal(pl, 0u), "absolute path") != NULL,
          "plane file: a relative per-plane path did not refuse its plane (rc %d): %s", rc, why);
    if (pl != NULL) { we_mod_planes_release(pl); pl = NULL; }
    args.plane_file[0] = NULL;

    unlink(file);
    snprintf(snap, sizeof snap, "%s/snapshot.bin", fd);
    unlink(snap);
    unlink(ofile);
    snprintf(file, sizeof file, "%s/reputation.bin", dd);
    unlink(file);
    rmdir(dd);
    rmdir(fd);
    rmdir(od);
}

/*
 * The plane paths a configuration names, composed before any bind (we_mod_bind_plane_path) and by the bind
 * itself (we_mod_plane_path), over every form: the directory with and without trailing slashes, the snapshot
 * alone, the snapshot beside the directory, a per-plane file beside the directory and per-plane files alone.
 * For every plane the two are the same string, and none carries "//". Then the counters directory each form
 * writes into when no counters directive names one.
 */
static void t_bind_paths(void)
{
    char base[256], dd[300], dslash[310], fd[300], gd[300], f0[400], f1[400], g1[400], snap[400], why[512], a[PATH_MAX], cd[PATH_MAX];
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT, base_args;
    we_mod_cfg_t cfg;
    we_mod_planes_t *pl = NULL;
    uint32_t form, p, bad = 0u, seen = 0u;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "bind paths: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dd, sizeof dd, "%s/bp-dir", base);
    snprintf(dslash, sizeof dslash, "%s///", dd);
    snprintf(fd, sizeof fd, "%s/bp-files", base);
    snprintf(gd, sizeof gd, "%s/bp-other", base);
    mkdir(dd, 0755); chmod(dd, 0755);
    mkdir(fd, 0755); chmod(fd, 0755);
    mkdir(gd, 0755); chmod(gd, 0755);
    snprintf(f0, sizeof f0, "%s/rep.bin", fd);
    snprintf(f1, sizeof f1, "%s/tor.bin", fd);
    snprintf(g1, sizeof g1, "%s/tor.bin", gd);
    snprintf(snap, sizeof snap, "%s/snapshot.bin", fd);
    CHECK(pl_write_rep(dd, "reputation.bin", 10u, 4102444800000ull, 0xC0000200u) == 0
          && pl_write_rep(fd, "rep.bin", 11u, 4102444800000ull, 0xC0000300u) == 0
          && pl_write_rep(fd, "snapshot.bin", 12u, 4102444800000ull, 0xC0000400u) == 0,
          "bind paths: the fixtures are not written");
    args.abi = WE_MODULE_ABI_VERSION;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    base_args = args;
    for (form = 0u; form < 7u; form++) {
        args = base_args;
        switch (form) {
        case 0: args.data_dir = dd; break;
        case 1: args.data_dir = dslash; break;                       /* trailing slashes */
        case 2: args.legacy_file = snap; break;                      /* the snapshot alone */
        case 3: args.data_dir = dd; args.legacy_file = snap; break;  /* the snapshot beside the directory */
        case 4: args.data_dir = dd; args.plane_file[0] = f0; break;  /* a per-plane file beside the directory */
        case 5: args.plane_file[0] = f0; args.plane_file[1] = f1; break;   /* per-plane files alone */
        default: args.data_dir = dslash; args.plane_file[1] = f1; break;
        }
        memset(&cfg, 0, sizeof cfg);
        rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
        if (rc != 0 || pl == NULL) {
            printf("FAIL bind paths: form %u is refused (rc %d): %s\n", form, rc, why);
            bad++;
            continue;
        }
        for (p = 0u; p < 8u; p++) {
            const char *b = we_mod_plane_path(pl, p);
            int r = we_mod_bind_plane_path(&args, p, a, sizeof a);

            if ((r == 1) != (b != NULL) || (b != NULL && strcmp(a, b) != 0) || (b != NULL && strstr(b, "//") != NULL)) {
                printf("FAIL bind paths: form %u plane %u: configuration time \"%s\", bound \"%s\"\n", form, p,
                       r == 1 ? a : "(none)", b != NULL ? b : "(none)");
                bad++;
            }
            seen += b != NULL;
        }
        we_mod_planes_release(pl);
        pl = NULL;
    }
    CHECK(bad == 0u && seen > 0u, "bind paths: %u plane path(s) differ between the configuration test and the bind, or "
          "carry \"//\" (of %u)", bad, seen);
    /* the counters directory with no counters directive */
    args = base_args;
    args.data_dir = dslash;
    snprintf(a, sizeof a, "%s/counters", dd);
    CHECK(we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) == 1 && strcmp(cd, a) == 0,
          "bind paths: the counters directory of a data directory with trailing slashes is \"%s\", not \"%s\"", cd, a);
    args = base_args;
    args.legacy_file = snap;
    snprintf(a, sizeof a, "%s/counters", fd);
    CHECK(we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) == 1 && strcmp(cd, a) == 0,
          "bind paths: the counters directory beside the snapshot is \"%s\", not \"%s\"", cd, a);
    args = base_args;
    args.plane_file[0] = f0; args.plane_file[1] = f1;
    CHECK(we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) == 1 && strcmp(cd, a) == 0,
          "bind paths: per-plane files in one directory give the counters directory \"%s\", not \"%s\"", cd, a);
    args.plane_file[1] = g1;
    why[0] = '\0';                               /* written only on a refusal; a returned directory is in cd */
    cd[0] = '\0';
    rc = we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why);
    CHECK(rc == -1 && strstr(why, "whisper_edge_summary") != NULL,
          "bind paths: per-plane files in two directories were not refused naming the counters directive (rc %d): %s", rc,
          rc == -1 ? why : rc == 1 ? cd : "(nothing)");
    args = base_args;
    CHECK(we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) == 0, "bind paths: no data named still gave a counters directory");
    /* a snapshot at the filesystem root, or a data directory of /: never /counters; refused with the directive */
    {
        static const char *const root_snap = "/snapshot.bin";

        args = base_args;
        args.legacy_file = root_snap;
        why[0] = '\0';
        cd[0] = '\0';
        rc = we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why);
        CHECK(rc == -1 && cd[0] == '\0' && strstr(why, root_snap) != NULL && strstr(why, "whisper_edge_summary") != NULL,
              "bind paths: a snapshot at the filesystem root gave the counters directory %s (rc %d), not a refusal "
              "naming the file and the directive", rc == 1 ? cd : "(none)", rc);
        args = base_args;
        args.data_dir = "/";
        why[0] = '\0';
        cd[0] = '\0';
        rc = we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why);
        CHECK(rc == -1 && cd[0] == '\0' && strstr(why, "whisper_edge_summary") != NULL,
              "bind paths: a data directory of / gave the counters directory %s (rc %d), not a refusal",
              rc == 1 ? cd : "(none)", rc);
    }
    /* the same two refusals hold for every spelling of /, and the one-directory rule reads directories, not
     * spellings: "/.", "//", "//snapshot.bin" and "/./snapshot.bin" are refused, and per-plane files named
     * "<dir>/tor.bin" and "<dir>//./rep.bin" are one directory */
    {
        static const char *const roots[] = { "/.", "//", "/./." };
        static const char *const rsnaps[] = { "//snapshot.bin", "/./snapshot.bin" };
        char sp1[400], sp2[400];
        uint32_t k, wrong = 0u;

        for (k = 0u; k < sizeof roots / sizeof roots[0]; k++) {
            args = base_args;
            args.data_dir = roots[k];
            cd[0] = '\0';
            if (we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) != -1) {
                printf("  bind paths: the data directory \"%s\" gave counters at %s\n", roots[k], cd);
                wrong++;
            }
        }
        for (k = 0u; k < sizeof rsnaps / sizeof rsnaps[0]; k++) {
            args = base_args;
            args.legacy_file = rsnaps[k];
            cd[0] = '\0';
            if (we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why) != -1) {
                printf("  bind paths: the snapshot \"%s\" gave counters at %s\n", rsnaps[k], cd);
                wrong++;
            }
        }
        CHECK(wrong == 0u, "bind paths: %u spelling(s) of / got past the root refusal", wrong);
        args = base_args;
        snprintf(sp1, sizeof sp1, "%s/tor.bin", fd);
        snprintf(sp2, sizeof sp2, "%s//./rep.bin", fd);
        args.plane_file[0] = sp2; args.plane_file[1] = sp1;
        why[0] = '\0';
        rc = we_mod_bind_counters_dir(&args, cd, sizeof cd, why, sizeof why);
        CHECK(rc == 1, "bind paths: two spellings of one directory were refused as two directories (rc %d): %s", rc,
              rc == -1 ? why : "");
    }
    unlink(f0); unlink(snap);
    snprintf(a, sizeof a, "%s/reputation.bin", dd);
    unlink(a);
    rmdir(dd); rmdir(fd); rmdir(gd);
}

/*
 * A refused binding leaves the caller's configuration exactly as it was. The LiteSpeed adoption measured
 * the defect: the reputation plane verified and armed, then a per-plane file refused for an untrusted
 * directory, and the bind released its planes while the configuration still pointed at them, so every
 * worker died of signal 11 on its first request. A plane refused at configuration no longer refuses the
 * binding, so the refusal here is the one that still does, the snapshot and a reputation line both
 * naming the reputation plane's file: by then the bind has written the null reasons and the first plane's
 * handle. On a fresh configuration the refused bind leaves it byte for byte as it was (nothing bound);
 * after an earlier good binding, the same refusal leaves that binding intact and serving.
 * WE_MOD_TEST_BIND_LEAVES_POINTERS, the restore removed, fails both by name.
 */
static void t_bind_refused(void)
{
    char base[256], dd[300], od[300], ofile[400], why[512];
    we_mod_cfg_t cfg, before;
    we_mod_bind_args_t good = WE_MOD_BIND_ARGS_INIT, bad;
    we_mod_planes_t *pl = NULL, *pl2 = NULL;
    const we_map_t *cur;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "bind refused: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dd, sizeof dd, "%s/br-dir", base);
    snprintf(od, sizeof od, "%s/br-open", base);
    mkdir(dd, 0755); chmod(dd, 0755);
    mkdir(od, 0777); chmod(od, 0777);
    snprintf(ofile, sizeof ofile, "%s/tor.bin", od);
    CHECK(pl_write_rep(dd, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0, "bind refused: no fixture");
    good.abi = WE_MODULE_ABI_VERSION;
    good.data_dir = dd;
    good.read_mask = 0x03u;
    good.uid = (unsigned)geteuid();
    good.now_ms = 1700000000000ull;
    good.high_water_file = "/nonexistent/high-water";
    good.log = pl_logger;
    bad = good;
    bad.legacy_file = ofile;                     /* the snapshot and a reputation line: the conflict */
    bad.plane_file[0] = ofile;

    /* a fresh configuration: refused, and left as it was */
    memset(&cfg, 0, sizeof cfg);
    before = cfg;
    rc = we_mod_bind(&cfg, &bad, &pl, why, sizeof why);
    CHECK(rc == WE_MOD_ERR_CONFIG && pl == NULL, "bind refused: the conflict was not refused (rc %d): %s", rc, why);
    CHECK(memcmp(&cfg, &before, sizeof cfg) == 0 && cfg.handle[0] == NULL && cfg.null_reason == NULL,
          "bind refused: a refused binding left the configuration changed (reputation's handle %s, null reasons %s): "
          "it points at the planes the refusal released", cfg.handle[0] != NULL ? "set" : "none",
          cfg.null_reason != NULL ? "set" : "none");

    /* an earlier good binding: the same refusal leaves it intact and serving */
    memset(&cfg, 0, sizeof cfg);
    rc = we_mod_bind(&cfg, &good, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "bind refused: the good binding is refused (rc %d): %s", rc, why);
    if (pl != NULL && cfg.handle[0] != NULL) {
        before = cfg;
        rc = we_mod_bind(&cfg, &bad, &pl2, why, sizeof why);
        CHECK(rc == WE_MOD_ERR_CONFIG && pl2 == NULL && memcmp(&cfg, &before, sizeof cfg) == 0,
              "bind refused: a refused binding over a good one did not leave the good one intact (rc %d)", rc);
        if (memcmp(&cfg, &before, sizeof cfg) == 0) {
            cur = we_current(cfg.handle[0]);   /* read only when intact: the good binding's planes are live */
            CHECK(cur != NULL && cur->generation == 100u, "bind refused: the intact binding no longer serves generation 100");
        }
        we_mod_planes_release(pl);
    }
    snprintf(ofile, sizeof ofile, "%s/reputation.bin", dd);
    unlink(ofile);
    rmdir(dd);
    rmdir(od);
}

/*
 * One plane refused at configuration, the others bound and serving. The data directory is trusted and
 * holds reputation.bin; the tor plane's own line names a file in a world-writable directory. The bind
 * succeeds; reputation serves generation 100; tor has no handle, reads `-r`, and its reason names the
 * file and the fix, on the status file's plane line, on the configuration file's plane line and in the
 * one log sentence. WE_MOD_TEST_PLANE_REFUSAL_WHOLE (the binding refused for the one plane) and
 * WE_MOD_TEST_REFUSED_UNSAID (the refusal on neither line) fail by name.
 */
static void t_plane_refused(void)
{
    char base[256], dd[300], od[300], ofile[400], why[512];
    static char buf[16384];
    static we_mod_status_t st;
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_text_t t;
    we_mod_procid_t id;
    const we_map_t *cur;
    const char *path[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    const char *refused[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    const char *r;
    uint32_t p;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "plane refused: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dd, sizeof dd, "%s/pr-dir", base);
    snprintf(od, sizeof od, "%s/pr-open", base);
    mkdir(dd, 0755); chmod(dd, 0755);
    mkdir(od, 0777); chmod(od, 0777);
    snprintf(ofile, sizeof ofile, "%s/tor.bin", od);
    CHECK(pl_write_rep(dd, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0, "plane refused: no fixture");
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dd;
    args.plane_file[1] = ofile;
    args.read_mask = 0x03u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    pl_log_reset();
    memset(&cfg, 0, sizeof cfg);
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL, "plane refused: one refused plane refused the whole binding (rc %d): %s", rc, why);
    if (rc != 0 || pl == NULL) {
        goto out;
    }
    cur = cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL;
    CHECK(cur != NULL && cur->generation == 100u, "plane refused: the good plane beside the refused one does not serve "
          "generation 100");
    r = we_mod_plane_config_refusal(pl, 1u);
    CHECK(cfg.handle[1] == NULL && cfg.static_reason[1] == WE_MOD_NOMAP_REFUSED && (cfg.bound_mask & 0x02u) == 0u
          && r != NULL && strstr(r, ofile) != NULL && strstr(r, "chmod") != NULL,
          "plane refused: the refused plane is bound, or does not read -r, or its reason does not name the file and the "
          "fix (%s)", r != NULL ? r : "(none)");
    CHECK(we_mod_plane_config_refusal(pl, 0u) == NULL, "plane refused: the good plane carries a configuration refusal");
    /* the status file's plane line */
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, args.now_ms);
    memset(&id, 0, sizeof id);
    st.server = "test";
    t.buf = buf; t.cap = sizeof buf; t.len = 0u; t.over = 0;
    we_mod_render_status(&t, &id, &st);
    CHECK(!t.over && strstr(buf, "plane tor refused \"") != NULL && strstr(buf, "chmod") != NULL
          && strstr(buf, "plane reputation armed") != NULL,
          "plane refused: the status file does not name the refused plane with its fix beside the armed one:\n%s", buf);
    /* the configuration file's plane line */
    for (p = 0u; p < 8u; p++) {
        path[p] = we_mod_plane_path(pl, p);
        refused[p] = we_mod_plane_config_refusal(pl, p);
    }
    t.len = 0u; t.over = 0;
    we_mod_render_conf(&t, &cfg, NULL, 0u, path, NULL, refused);
    CHECK(!t.over && strstr(buf, "plane tor path \"") != NULL && strstr(buf, "\" refused \"whisper_edge_data ") != NULL
          && strstr(buf, "chmod") != NULL,
          "plane refused: the configuration file's plane line does not carry the refusal with its fix:\n%s", buf);
    /* the one log sentence */
    CHECK(pl_log_has("plane tor is refused at configuration and reads unknown"),
          "plane refused: the bind's logger was not handed the refused plane's sentence");
    we_mod_planes_release(pl);
out:
    snprintf(ofile, sizeof ofile, "%s/reputation.bin", dd);
    unlink(ofile);
    rmdir(dd);
    rmdir(od);
}

/*
 * The check-only bind and the bind agree on every case of the bind's table: the forms of the paths row, a
 * data directory and a per-plane directory others can write, relative paths, the snapshot alone and beside
 * the directory, the conflict, and files refused on their mode, on their header and on their bytes, absent
 * and unreadable. Per case the two return the same code; per plane the same path, the same token (verified
 * by the check is armed by the bind), the same configuration refusal and the same reason. Nothing the check
 * runs maps or arms: the case after it binds the same files afresh. WE_MOD_TEST_CHECK_NO_VERIFY (the check
 * stopping at the paths) fails by name.
 */
static void t_bind_check(void)
{
    char base[256], dd[300], fd[300], od[300], f0[400], f1[400], snap[400], omode[400], ohdr[400], obyte[400],
         oun[400], why[512], why2[512];
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT, base_args;
    static we_mod_plane_check_t chk[8];
    static we_mod_status_t st;
    we_mod_cfg_t cfg;
    we_mod_planes_t *pl = NULL;
    uint32_t c, p, bad = 0u, cases = 0u, verified = 0u, refusedn = 0u;
    int rc, rc2;
    FILE *f;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "bind check: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dd, sizeof dd, "%s/bc-dir", base);
    snprintf(fd, sizeof fd, "%s/bc-files", base);
    snprintf(od, sizeof od, "%s/bc-open", base);
    mkdir(dd, 0755); chmod(dd, 0755);
    mkdir(fd, 0755); chmod(fd, 0755);
    mkdir(od, 0777); chmod(od, 0777);
    snprintf(f0, sizeof f0, "%s/rep.bin", fd);
    snprintf(f1, sizeof f1, "%s/tor.bin", od);
    snprintf(snap, sizeof snap, "%s/snapshot.bin", fd);
    snprintf(omode, sizeof omode, "%s/mode.bin", fd);
    snprintf(ohdr, sizeof ohdr, "%s/header.bin", fd);
    snprintf(obyte, sizeof obyte, "%s/bytes.bin", fd);
    snprintf(oun, sizeof oun, "%s/unreadable.bin", fd);
    CHECK(pl_write_rep(dd, "reputation.bin", 10u, 4102444800000ull, 0xC0000200u) == 0
          && pl_write_rep(fd, "rep.bin", 11u, 4102444800000ull, 0xC0000300u) == 0
          && pl_write_rep(fd, "snapshot.bin", 12u, 4102444800000ull, 0xC0000400u) == 0
          && pl_write_rep(fd, "mode.bin", 13u, 4102444800000ull, 0xC0000500u) == 0
          && pl_write_rep(fd, "bytes.bin", 14u, 4102444800000ull, 0xC0000600u) == 0
          && pl_write_rep(fd, "unreadable.bin", 15u, 4102444800000ull, 0xC0000700u) == 0,
          "bind check: the fixtures are not written");
    chmod(omode, 0644);                          /* refused on its mode */
    f = fopen(ohdr, "w");                        /* refused on its header */
    if (f != NULL) {
        static char junk[512];

        memset(junk, 'x', sizeof junk);
        fwrite(junk, 1, sizeof junk, f);
        fclose(f);
    }
    chmod(ohdr, 0444);
    {
        /* refused on its bytes: the last byte flipped, so the header passes and the digest does not */
        struct stat sb;
        int fdw;

        chmod(obyte, 0644);
        fdw = open(obyte, O_RDWR);
        if (fdw >= 0 && fstat(fdw, &sb) == 0 && sb.st_size > 0) {
            unsigned char b;

            if (pread(fdw, &b, 1, sb.st_size - 1) == 1) {
                b ^= 0x5au;
                if (pwrite(fdw, &b, 1, sb.st_size - 1) != 1) {
                    printf("FAIL bind check: the byte fixture is not written\n");
                }
            }
        }
        if (fdw >= 0) {
            close(fdw);
        }
        chmod(obyte, 0444);
    }
    chmod(oun, 0000);                            /* unreadable (unless the rows run as root) */
    args.abi = WE_MODULE_ABI_VERSION;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    base_args = args;
    for (c = 0u; c < 17u; c++) {
        args = base_args;
        switch (c) {
        case 0:  args.data_dir = dd; break;
        case 1:  args.data_dir = dd; args.read_mask = 0x03u; break;          /* tor absent */
        case 2:  args.legacy_file = snap; break;
        case 3:  args.data_dir = dd; args.legacy_file = snap; break;
        case 4:  args.data_dir = dd; args.plane_file[0] = f0; break;
        case 5:  args.plane_file[0] = f0; args.plane_file[1] = f1; args.read_mask = 0x03u; break;   /* tor's dir open */
        case 6:  args.data_dir = od; break;                                  /* the data directory others can write */
        case 7:  args.data_dir = od; args.plane_file[0] = f0; args.read_mask = 0x03u; break;
        case 8:  args.legacy_file = "snapshot.bin"; break;                   /* relative */
        case 9:  args.data_dir = dd; args.plane_file[1] = "tor.bin"; args.read_mask = 0x03u; break;
        case 10: args.data_dir = dd; args.legacy_file = snap; args.plane_file[0] = f0; break;   /* the conflict */
        case 11: args.plane_file[0] = omode; break;
        case 12: args.plane_file[0] = ohdr; break;
        case 13: args.plane_file[0] = obyte; break;
        case 14: args.plane_file[0] = oun; break;
        case 15: args.legacy_file = omode; break;                            /* the snapshot: 0644 is its mode */
        default: args.data_dir = dd; args.plane_file[0] = "/nonexistent-dir/rep.bin"; break;
        }
        cases++;
        rc = we_mod_bind_check(&args, chk, why, sizeof why);
        memset(&cfg, 0, sizeof cfg);
        pl_log_reset();
        rc2 = we_mod_bind(&cfg, &args, &pl, why2, sizeof why2);
        if (rc != rc2 || (rc != 0 && strcmp(why, why2) != 0)) {
            printf("FAIL bind check: case %u: the check returns %d (%s), the bind %d (%s)\n", c, rc, rc != 0 ? why : "",
                   rc2, rc2 != 0 ? why2 : "");
            bad++;
        }
        if (rc2 == 0 && pl != NULL) {
            memset(&st, 0, sizeof st);
            we_mod_planes_status(pl, &st, args.now_ms);
            for (p = 0u; p < 8u && rc == 0; p++) {
                uint32_t code;
                const char *bp = we_mod_plane_path(pl, p), *cr = we_mod_plane_config_refusal(pl, p);
                const char *breason = "";

                if (cfg.handle[p] == NULL) {
                    code = cfg.static_reason[p];
                    if (cr != NULL) {
                        breason = cr;
                    }
                } else if (we_current(cfg.handle[p]) != NULL) {
                    code = WE_MOD_NOMAP_NONE;
                } else {
                    code = cfg.null_reason[p] & 7u;
                    breason = st.plane[p].reason;
                }
                if (code == WE_MOD_NOMAP_UNREADABLE) {
                    breason = chk[p].reason;     /* the errno text: the server's to print, compared by token */
                }
                if (chk[p].code != code || strcmp(chk[p].path, bp != NULL ? bp : "") != 0
                        || (chk[p].config_refused != 0) != (cr != NULL)
                        || (code == WE_MOD_NOMAP_REFUSED && strcmp(chk[p].reason, breason) != 0)) {
                    printf("FAIL bind check: case %u plane %u: the check says %s (%u) \"%s\" at \"%s\", the bind %u \"%s\" "
                           "at \"%s\"\n", c, p, chk[p].state, chk[p].code, chk[p].reason, chk[p].path, code, breason,
                           bp != NULL ? bp : "");
                    bad++;
                }
                verified += chk[p].code == WE_MOD_NOMAP_NONE && code == WE_MOD_NOMAP_NONE;
                refusedn += chk[p].code == WE_MOD_NOMAP_REFUSED && code == WE_MOD_NOMAP_REFUSED;
            }
            we_mod_planes_release(pl);
            pl = NULL;
        }
    }
    CHECK(bad == 0u && cases == 17u && verified >= 6u && refusedn >= 8u,
          "bind check: the check-only bind and the bind disagree on %u result(s) over %u cases (%u verified and %u "
          "refused by both)", bad, cases, verified, refusedn);
    chmod(oun, 0644);
    unlink(f0); unlink(snap); unlink(omode); unlink(ohdr); unlink(obyte); unlink(oun);
    snprintf(f0, sizeof f0, "%s/reputation.bin", dd);
    unlink(f0);
    rmdir(dd); rmdir(fd); rmdir(od);
}

/*
 * A context's policy lines REPLACE its parent's: a parent of four rules and a child of one, and
 * the child runs one. WE_MOD_TEST_APPEND, the child's lines appended to the parent's, runs five and fails
 * by name.
 */
static void t_policy_replace(void)
{
    we_policy_directive_t d[5];
    we_policy_source_t src;
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_policy_build_t *b = NULL;
    const we_program_t *parent, *child;

    d[0] = D(WE_DIR_POLICY, "http/s1", "deny if tor_exit");
    d[1] = D(WE_DIR_POLICY, "http/s1", "log if listed >= low");
    d[2] = D(WE_DIR_POLICY, "http/s1", "log if listed >= medium");
    d[3] = D(WE_DIR_POLICY, "http/s1", "log if listed >= high");
    d[4] = D(WE_DIR_POLICY, "http/s1/l1", "allow if tor_exit");
    memset(&src, 0, sizeof src);
    memset(&e, 0, sizeof e);
    src.d = d;
    src.n = 5u;
    if (we_policy_build(&src, &env, NULL, &b, &e, NULL) != WE_POLICY_OK) {
        CHECK(0, "replace: the configuration is refused: %s %s", e.what, e.fix);
        return;
    }
    parent = we_policy_program(b, "http/s1");
    child = we_policy_program(b, "http/s1/l1");
    CHECK(parent != NULL && parent->rule_count == 4u && child != NULL && child->rule_count == 1u,
          "replace: a child's one line ran %u rule(s) under a parent of %u, not one: its lines append, not replace",
          child != NULL ? child->rule_count : 0u, parent != NULL ? parent->rule_count : 0u);
    we_policy_build_free(b);
}

static void t_planes_snapshot_unfilled(void)
{
    char base[256], dir[300], file[400], why[512], state[16], g[WE_MOD_GEN_MAX];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "unfilled snapshot: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/unfilled", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(file, sizeof file, "%s/snapshot.bin", dir);
    unlink(file);
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.legacy_file = file;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "unfilled snapshot: the binding is refused (rc %d): %s", rc, why);
    if (pl == NULL || cfg.handle[0] == NULL) {
        return;
    }
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "absent") == 0, "unfilled snapshot: a snapshot path with no file yet reads \"%s\", not absent", state);
    CHECK(strcmp(g, "reputation:-a") == 0, "unfilled snapshot: the token of a bound path with no file is \"%s\", not "
          "\"reputation:-a\" as its status says", g);
    we_mod_planes_release(pl);
    pl = NULL;

    /* a bound plane refused at load whose file is then deleted: absent, in the status and the token */
    {
        char path[400];
        uint32_t armed = 0u;

        snprintf(path, sizeof path, "%s/reputation.bin", dir);
        CHECK(pl_write_rep(dir, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0 && chmod(path, 0644) == 0,
              "unfilled snapshot: the refused plane is not written");
        memset(&cfg, 0, sizeof cfg);
        args.legacy_file = NULL;
        args.data_dir = dir;
        rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
        CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "deleted plane: the binding is refused (rc %d): %s", rc, why);
        if (pl != NULL && cfg.handle[0] != NULL) {
            unlink(path);
            (void)we_mod_planes_monitor(pl, 0u, &armed);
            nm_read(pl, &cfg, state, g);
            CHECK(strcmp(state, "absent") == 0 && strcmp(g, "reputation:-a") == 0,
                  "deleted plane: a refused plane whose file was deleted reads \"%s\" and \"%s\", not absent and -a", state, g);
        }
        if (pl != NULL) {
            we_mod_planes_release(pl);
        }
        unlink(path);
    }
    rmdir(dir);
}

#ifdef WE_MOD_TEST_PAUSE_TICK
#include <pthread.h>

static we_mod_planes_t *g_pt_pl;
static int g_pt_done;

static int g_pt_monitor;               /* pt_held runs the supervisor's monitor, not the thread's tick */

static void *pt_tick(void *arg)
{
    if (g_pt_monitor) {
        uint32_t armed = 0u;

        (void)we_mod_planes_monitor(g_pt_pl, 1000u, &armed);
    } else {
        we_mod_planes_tick(g_pt_pl, (uint64_t)(uintptr_t)arg, NULL);
    }
    __atomic_store_n(&g_pt_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

/* the module thread's tick run on a thread of its own, held at `where`: 1 when the marker appeared and the
 * tick had not returned 100 ms later, 0 when it was not held */
static int pt_held(const char *pdir, const char *where, pthread_t *t, uint64_t tick)
{
    char hold[400], held[400];
    int i, fd, seen = 0;
    struct timespec ms = { 0, 1000000 }, hundred = { 0, 100000000 };

    snprintf(hold, sizeof hold, "%s/%s", pdir, where);
    snprintf(held, sizeof held, "%s/held.%s.%ld", pdir, where, (long)getpid());
    fd = open(hold, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd >= 0) {
        close(fd);
    }
    __atomic_store_n(&g_pt_done, 0, __ATOMIC_RELEASE);
    pthread_create(t, NULL, pt_tick, (void *)(uintptr_t)tick);
    for (i = 0; i < 5000 && !seen; i++) {
        seen = access(held, F_OK) == 0;
        if (!seen) {
            nanosleep(&ms, NULL);
        }
    }
    nanosleep(&hundred, NULL);
    return seen && !__atomic_load_n(&g_pt_done, __ATOMIC_ACQUIRE);
}

/*
 * WE_MOD_TEST_PAUSE_TICK's own rows: the hook holds, at both of its points, until the hold is removed. At
 * `loading` the plane refused at configuration load has its next generation admitted; the loop, applying
 * while the tick is held, stores the word, and the status and the token both read loading and -l; the
 * release lets the verification finish and the plane arm. At `tick` the whole tick is held.
 */
static void t_pause_tick(void)
{
    char base[256], dir[300], pdir[300], path[400], hold[400], why[512], g[WE_MOD_GEN_MAX], state[16];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    pthread_t t;
    int rc, held;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "pause: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/pause", base);
    snprintf(pdir, sizeof pdir, "%s/pause-hold", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    mkdir(pdir, 0755);
    setenv("WE_MOD_PAUSE_DIR", pdir, 1);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0 && chmod(path, 0644) == 0,
          "pause: the refused plane is not written");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.handle[0] != NULL, "pause: the binding is refused (rc %d): %s", rc, why);
    if (pl == NULL || cfg.handle[0] == NULL) {
        return;
    }
    /* the supervisor's monitor held at `monitor`, before any worker starts: a server's M3 holds the parent's
     * own check this way, so the parent cannot disarm a truncated plane before it forks a replacement */
    g_pt_pl = pl;
    g_pt_monitor = 1;
    held = pt_held(pdir, "monitor", &t, 0u);
    CHECK(held, "pause: the supervisor's monitor was not held at monitor");
    snprintf(hold, sizeof hold, "%s/monitor", pdir);
    unlink(hold);
    pthread_join(t, NULL);
    g_pt_monitor = 0;
    if (held) {
        printf("ok   pause: the supervisor's monitor held until its hold was removed\n");
    }
    memset(&w, 0, sizeof w);
    w.now_ms = 1700000000000ull;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "pause: the worker start failed: %s", why);
    g_pt_pl = pl;

    CHECK(pl_write_rep(dir, "reputation.bin", 200u, 4102444800000ull, 0xC0000300u) == 0,
          "pause: the good generation is not written");
    held = pt_held(pdir, "loading", &t, 1u);
    CHECK(held, "pause: the tick was not held at loading");
    we_mod_planes_apply(pl, pl_logger, NULL);    /* the loop, while the tick is held */
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "loading") == 0 && strcmp(g, "reputation:-l") == 0,
          "pause: a plane held at loading reads \"%s\" and \"%s\", not loading and -l", state, g);
    snprintf(hold, sizeof hold, "%s/loading", pdir);
    unlink(hold);
    pthread_join(t, NULL);
    we_mod_planes_apply(pl, pl_logger, NULL);
    we_mod_planes_tick(pl, 2u, NULL);
    nm_read(pl, &cfg, state, g);
    CHECK(strcmp(state, "armed") == 0 && we_current(cfg.handle[0]) != NULL && we_current(cfg.handle[0])->generation == 200u,
          "pause: the released verification did not arm: \"%s\", \"%s\"", state, g);
    if (held) {
        printf("ok   pause: a tick held at loading, the plane read loading and -l, released and armed\n");
    }

    held = pt_held(pdir, "tick", &t, 3u);
    CHECK(held, "pause: the tick was not held at tick");
    snprintf(hold, sizeof hold, "%s/tick", pdir);
    unlink(hold);
    pthread_join(t, NULL);
    if (held) {
        printf("ok   pause: a whole tick held until its hold was removed\n");
    }
    unsetenv("WE_MOD_PAUSE_DIR");
    we_mod_planes_release(pl);
    unlink(path);
    rmdir(dir);
    rmdir(pdir);
}
#endif

/*
 * A worker started after the plane it inherited was truncated in place (the truncate row, M3): the
 * worker start fstats the inherited inode, finds the size changed, and disarms before the first accept,
 * so no request of the new worker reads the truncated tail. The two controls the servers' M3 arms switch:
 * WE_MOD_TEST_NO_START_STAT looks at nothing at the start (the truncate is not noticed), and
 * WE_MOD_TEST_SERVE_INHERITED notices it and serves the inherited mapping until its re-digest (not
 * disarmed); each fails its own check below.
 */
static void t_start_truncate(void)
{
    char base[256], dir[300], path[400], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    const we_map_t *cur;
    struct stat st;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "start truncate: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/starttrunc", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0, "start truncate: no plane written");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    cur = pl != NULL && cfg.handle[0] != NULL ? we_current(cfg.handle[0]) : NULL;
    CHECK(rc == 0 && cur != NULL && cur != cfg.standin[0], "start truncate: the supervisor did not arm the plane (rc %d): %s", rc, why);
    if (cur == NULL) {
        if (pl != NULL) {
            we_mod_planes_release(pl);
        }
        return;
    }
    /* the in-place truncate of the inherited generation, between the supervisor's bind and the worker's start */
    CHECK(stat(path, &st) == 0 && chmod(path, 0644) == 0 && truncate(path, st.st_size / 2) == 0 && chmod(path, 0444) == 0,
          "start truncate: the plane is not truncated in place");
    pl_log_reset();
    memset(&w, 0, sizeof w);
    w.now_ms = 1700000000000ull;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "start truncate: the worker start failed: %s", why);
    CHECK(pl_log_has("rewritten in place"), "start truncate: the worker start did not notice the inherited plane truncated in place");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0],
          "start truncate: the worker start left the truncated inherited mapping serving, not disarmed before the first accept");
    we_mod_planes_release(pl);
    unlink(path);
    rmdir(dir);
}

/*
 * The tenant revocation mark, read at the bind. Its grammar is the keyed oracle's exactly,
 * [1-9][0-9]{0,18} and a newline, and its owner root or the trusted uid. A mark at or above tenant.bin's
 * generation keeps the plane unarmed; one below arms it; a malformed or untrusted mark is no transition
 * (nothing armed, the plane refused with the fix). WE_MOD_TEST_HW_LOOSE (strtoull's reader) arms
 * through " 6", "+6", "06" and "-1"'s wrap, and WE_MOD_TEST_HW_ROOT_ONLY refuses a mark the trusted uid
 * owns; each fails by name.
 */
static uint64_t hw_bind(const char *dir, const char *hw, char *state, size_t sn, char *reason, size_t rn)
{
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    static we_mod_status_t st;
    const we_map_t *cur;
    uint64_t g = 0u;
    char why[512];

    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = hw;
    snprintf(state, sn, "unbound");
    reason[0] = '\0';
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        snprintf(state, sn, "bind-refused");
        return 0u;
    }
    cur = cfg.handle[7] != NULL ? we_current(cfg.handle[7]) : NULL;
    if (cur != NULL && cur != cfg.standin[7]) {
        g = cur->generation;
    }
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, args.now_ms);
    snprintf(state, sn, "%s", st.plane[7].state);
    snprintf(reason, rn, "%s", st.plane[7].reason);
    we_mod_planes_release(pl);
    return g;
}

static void t_high_water(void)
{
    char base[256], dir[300], path[400], hw[400], state[16], reason[256];
    static __uint128_t s4[1], e4[1];
    static uint8_t rec[64];
    static const char *const bad[] = { " 6\n", "+6\n", "06\n", "0\n", "-1\n", "6", "6\n\n", "12345678901234567890\n", "" };
    ww_plane_t p;
    uint32_t i, armed_bad = 0u, unrefused = 0u;
    uint64_t g;
    FILE *f;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "high-water: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/hw-planes", base);
    mkdir(dir, 0755); chmod(dir, 0755);
    snprintf(hw, sizeof hw, "%s/hw-mark", base);
    memset(&p, 0, sizeof p);
    s4[0] = 0xC0000200u;
    e4[0] = 0xC00002FFu;
    p.format = 2u;
    p.schema = 1;
    p.plane = WE_PLANE_TENANT;
    p.generation = 7u;
    p.valid_until_ms = 4102444800000ull;
    p.v4.n = 1u;
    p.v4.start = s4;
    p.v4.end = e4;
    p.v4.rec = rec;
    snprintf(path, sizeof path, "%s/tenant.bin", dir);
    CHECK(ww_write(path, &p) == 0 && chmod(path, 0444) == 0, "high-water: the tenant plane is not written");
    CHECK(pl_write_rep(dir, "reputation.bin", 3u, 4102444800000ull, 0xC0000200u) == 0, "high-water: no reputation plane");

#define HW_WRITE(text, mode) do { unlink(hw); f = fopen(hw, "w"); if (f != NULL) { fputs((text), f); fclose(f); } chmod(hw, (mode)); } while (0)
    /* no mark: arms */
    unlink(hw);
    g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
    CHECK(g == 7u, "high-water: with no mark generation 7 did not arm (%llu, %s)", (unsigned long long)g, state);
    /* a mark below: arms; a mark at or above: nothing armed */
    HW_WRITE("6\n", 0444);
    g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
    CHECK(g == 7u, "high-water: a mark owned by the trusted uid at 6 did not let generation 7 arm (%llu, %s: %s)",
          (unsigned long long)g, state, reason);
    HW_WRITE("7\n", 0444);
    g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
    CHECK(g == 0u, "high-water: a mark at 7 let generation 7 arm, a restored pre-revocation plane");
    HW_WRITE("9223372036854775807\n", 0444);
    g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
    CHECK(g == 0u, "high-water: a nineteen-digit mark let generation 7 arm");
    /* malformed: nothing armed, the plane refused naming the file and the fix */
    for (i = 0u; i < sizeof bad / sizeof bad[0]; i++) {
        HW_WRITE(bad[i], 0444);
        g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
        if (g != 0u) {
            printf("  high-water: the malformed mark \"%s\" armed generation %llu\n", bad[i], (unsigned long long)g);
            armed_bad++;
        }
        if (strcmp(state, "refused") != 0 || strstr(reason, hw) == NULL || strstr(reason, "[1-9][0-9]{0,18}") == NULL) {
            unrefused++;
        }
    }
    CHECK(armed_bad == 0u && unrefused == 0u, "high-water: %u malformed mark(s) armed the tenant plane, %u not refused "
          "with the grammar named (the keyed oracle reads each as no transition)", armed_bad, unrefused);
    /* group-writable: refused with the chown/chmod fix */
    HW_WRITE("6\n", 0464);
    g = hw_bind(dir, hw, state, sizeof state, reason, sizeof reason);
    CHECK(g == 0u && strcmp(state, "refused") == 0 && strstr(reason, "chmod 0444") != NULL,
          "high-water: a group-writable mark was read (%llu, %s: %s)", (unsigned long long)g, state, reason);
#undef HW_WRITE
    chmod(hw, 0644);
    unlink(hw);
    unlink(path);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    unlink(path);
    rmdir(dir);
}

/*
 * The legacy snapshot's owner WARNING. The snapshot named as the one data directive keeps its 0644 mode, so
 * an owner other than root or the workers' uid is said at the bind, in the one sentence every server
 * prints, naming the owner and the chown fix; an owner the rule accepts says nothing. As a non-root runner
 * the workers' uid is set one past the file's owner, so the owner is the stranger; as root the file is
 * chowned to uid 4242. WE_MOD_TEST_LEGACY_OWNER_SILENT, the warning removed, fails by name.
 */
static void t_legacy_owner(void)
{
    char base[256], dir[300], path[400], warn[512], why[512], want[64];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    struct stat st;
    unsigned owner;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "legacy owner: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/legacy-owner", base);
    mkdir(dir, 0755); chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "snapshot.bin", 5u, 4102444800000ull, 0xC0000200u) == 0, "legacy owner: no snapshot");
    snprintf(path, sizeof path, "%s/snapshot.bin", dir);
    chmod(path, 0644);
    if (geteuid() == 0u) {
        CHECK(chown(path, 4242, (gid_t)-1) == 0, "legacy owner: the snapshot cannot be given to uid 4242");
        args.uid = 0u;
    } else {
        args.uid = (unsigned)geteuid() + 1u;
    }
    owner = stat(path, &st) == 0 ? (unsigned)st.st_uid : 0u;
    args.abi = WE_MODULE_ABI_VERSION;
    args.legacy_file = path;
    args.read_mask = 0x01u;
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    snprintf(want, sizeof want, "owned by uid %u,", owner);
    CHECK(we_mod_legacy_warning(&args, warn, sizeof warn) == 1 && strstr(warn, want) != NULL
          && strstr(warn, "chown root") != NULL && strstr(warn, path) != NULL,
          "legacy owner: a snapshot owned by uid %u, neither root nor the workers' uid %u, gave no warning naming the "
          "owner and the chown fix (\"%s\")", owner, args.uid, warn);
    pl_log_reset();
    memset(&cfg, 0, sizeof cfg);
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL && pl_log_has("WARNING: the snapshot"),
          "legacy owner: the bind did not hand its logger the warning (%s)", why);
    if (pl != NULL) {
        /* a warning, never a refusal: as root the directories pass for the workers' uid and the snapshot serves
         * (as a non-root runner the workers' uid owns no directory above it, so the trust walk refuses it) */
        CHECK(geteuid() != 0u || (cfg.handle[0] != NULL && we_current(cfg.handle[0]) != NULL),
              "legacy owner: the warned snapshot did not still serve");
        we_mod_planes_release(pl);
        pl = NULL;
    }
    /* the owner the rule accepts: no warning */
    args.uid = owner;
    CHECK(we_mod_legacy_warning(&args, warn, sizeof warn) == 0 && warn[0] == '\0',
          "legacy owner: a snapshot owned by the workers' uid was warned about (\"%s\")", warn);
    unlink(path);
    rmdir(dir);
}

/*
 * A whole-buffer digest marks progress per MiB, and the bind installs the module's mark. The bounded stop
 * abandons only a thread whose progress count stands still for a window; a one-shot verification digests
 * the whole plane after its last read, so without a mark during the digest a 126 MB plane read as a stuck
 * thread and lost the process's final write. The count is exact: 8 MiB in one update, 8 marks.
 * WE_MOD_TEST_DIGEST_SILENT (the bind installs nothing) fails by name.
 */
static uint32_t dg_marks;
static void dg_mark(void)
{
    dg_marks++;
}

static void t_digest_progress(void)
{
    char base[256], dir[300], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    void (*was)(void);
    uint8_t dg[32], *buf;
    size_t n = 8u << 20;

    trusted_base(base, sizeof base);
    snprintf(dir, sizeof dir, "%s/dg-planes", base);
    mkdir(base, 0755); chmod(base, 0755);
    mkdir(dir, 0755); chmod(dir, 0755);
    we_sha256_progress = NULL;
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    why[0] = '\0';                               /* written only on a refusal */
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && we_sha256_progress != NULL,
          "digest progress: the bind left the digest without a progress mark (%s)", why[0] != '\0' ? why : "bound");
    we_mod_planes_release(pl);
    was = we_sha256_progress;
    buf = calloc(1, n);
    if (buf != NULL) {
        dg_marks = 0u;
        we_sha256_progress = dg_mark;
        we_sha256(buf, n, dg);
        CHECK(dg_marks == 8u, "digest progress: 8 MiB in one update marked progress %u times, not 8", dg_marks);
        free(buf);
    }
    we_sha256_progress = was;
    rmdir(dir);
}

/*
 * The lists' single-producer rule, enforced in the debug build: posts from one thread, and again from a
 * forked child's own thread, pass; a second posting thread in one process aborts naming the slot. Run in a
 * child, so the abort is the row's to read.
 */
#include <pthread.h>
#ifdef WE_MOD_DEBUG
static we_mod_item_t *spsc_slot;
static we_mod_item_t spsc_items[4];
static void *spsc_second(void *u)
{
    (void)u;
    we_mod_list_post(&spsc_slot, &spsc_items[2]);
    return NULL;
}
#endif

static void t_spsc_rule(void)
{
#ifndef WE_MOD_DEBUG
    /* a release build of the harness (the controls' builds): this row needs the debug build's single-producer check */
    printf("  spsc: covered by the debug build (test_module's own), which has the single-producer check\n");
#else
    pid_t kid;
    int ws = 0;

    fflush(stdout);
    kid = fork();
    if (kid == 0) {
        pthread_t th;
        pid_t grand;
        int gws = 0;

        memset(spsc_items, 0, sizeof spsc_items);
        we_mod_list_post(&spsc_slot, &spsc_items[0]);
        we_mod_list_post(&spsc_slot, &spsc_items[1]);          /* the same thread: fine */
        grand = fork();
        if (grand == 0) {
            we_mod_list_post(&spsc_slot, &spsc_items[3]);      /* a forked child's own thread: fine */
            _exit(0);
        }
        if (grand < 0 || waitpid(grand, &gws, 0) != grand || !WIFEXITED(gws) || WEXITSTATUS(gws) != 0) {
            _exit(7);
        }
        if (freopen("/dev/null", "w", stderr) == NULL) {
            _exit(8);
        }
        if (pthread_create(&th, NULL, spsc_second, NULL) == 0) {
            pthread_join(th, NULL);
        }
        _exit(0);                                              /* reached only if the second producer passed */
    }
    CHECK(kid > 0 && waitpid(kid, &ws, 0) == kid && WIFSIGNALED(ws) && WTERMSIG(ws) == SIGABRT,
          "spsc: a second posting thread on one slot was not refused (child %s %d; 7 is a forked child's post refused)",
          WIFSIGNALED(ws) ? "signal" : "exit", WIFSIGNALED(ws) ? WTERMSIG(ws) : WIFEXITED(ws) ? WEXITSTATUS(ws) : -1);
#endif
}

/*
 * A remembered failure is confirmed by the header, not by fstatat's identity alone. A new file that reuses a
 * freed inode inside one timestamp tick, at the same size, carries the identity of a refused one (measured on
 * an x86_64 ext4 host, where a fresh generation was skipped as remembered). The debug seam plants exactly
 * that: the good generation at the name, remembered as a failure under its own identity and another file's
 * header digest. The next tick must look at the header, see another file, and arm it.
 * WE_MOD_TEST_FAIL_IDENT_ONLY, the identity alone deciding, leaves it unarmed and fails by name.
 */
static void t_fail_identity(void)
{
#ifndef WE_MOD_DEBUG
    /* a release build of the harness (the controls' builds): this row needs the debug build's seam we_mod_debug_remember_other */
    printf("  fail identity: covered by the debug build (test_module's own), which has the seam we_mod_debug_remember_other\n");
#else
    char base[256], dir[300], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_worker_args_t w;
    const we_map_t *cur;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;

    trusted_base(base, sizeof base);
    snprintf(dir, sizeof dir, "%s/fail-ident", base);
    mkdir(base, 0755); chmod(base, 0755);
    mkdir(dir, 0755); chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0, "fail identity: no first generation");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        CHECK(0, "fail identity: the binding is refused: %s", why);
        return;
    }
    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "fail identity: the worker start is refused: %s", why);
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, far, 0xC0000300u) == 0, "fail identity: no second generation");
    CHECK(we_mod_debug_remember_other(pl, 0u) == 0, "fail identity: the collision could not be planted");
    pl_cycle(pl, 1u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 200u,
          "fail identity: a new generation carrying a remembered failure's identity was skipped (armed %llu, not 200)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    we_mod_planes_release(pl);
    pl = NULL;

    /* the same collision on the parent's budgeted monitor, the other lookup (the monitor row's "fifth
     * generation did not arm" varied with it on a test host): no worker start, the monitor arms it */
    memset(&cfg, 0, sizeof cfg);
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        CHECK(0, "fail identity: the second binding is refused: %s", why);
        rm_tree(base);
        return;
    }
    CHECK(pl_write_rep(dir, "reputation.bin", 300u, far, 0xC0000400u) == 0, "fail identity: no third generation");
    CHECK(we_mod_debug_remember_other(pl, 0u) == 0, "fail identity: the monitor's collision could not be planted");
    {
        uint32_t armed = 0u;

        CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u
              && (cur = we_current(cfg.handle[0])) != NULL && cur->generation == 300u,
              "fail identity: the monitor skipped a new generation carrying a remembered failure's identity");
    }
    we_mod_planes_release(pl);
    rm_tree(base);
#endif
}

/*
 * The debug build's digest counts on the status file's process line, `digests N start-digests M`, per
 * process: zeroed at the worker start, so a forked worker counts its own. A worker start over an armed plane
 * whose mtime moved digests it once on the start path; a new generation at the name is one more digest, not
 * on the start path. WE_MOD_TEST_DIGEST_UNCOUNTED fails by name.
 */
#ifdef WE_MOD_DEBUG
static void dc_counts(we_mod_planes_t *pl, uint64_t now, unsigned long long *all, unsigned long long *start)
{
    static we_mod_status_t st;
    static char buf[16384];
    we_mod_text_t t;
    we_mod_procid_t id;
    const char *d;

    memset(&st, 0, sizeof st);
    memset(&id, 0, sizeof id);
    we_mod_planes_status(pl, &st, now);
    st.server = "test";
    t.buf = buf; t.cap = sizeof buf; t.len = 0u; t.over = 0;
    we_mod_render_status(&t, &id, &st);
    *all = *start = ~0ull;
    d = strstr(buf, " digests ");
    if (d == NULL || sscanf(d, " digests %llu start-digests %llu", all, start) != 2) {
        *all = *start = ~0ull;
    }
}
#endif

static void t_digest_counts(void)
{
#ifndef WE_MOD_DEBUG
    /* a release build of the harness (the controls' builds): this row needs the debug build's per-process digest counters */
    printf("  digest counts: covered by the debug build (test_module's own), which has the per-process digest counters\n");
#else
    char base[256], dir[300], path[400], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_worker_args_t w;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;
    unsigned long long all, start;
    struct timespec ts[2];
    struct stat a0, a1;
    const we_map_t *cur;
    int afd, moved;

    trusted_base(base, sizeof base);
    snprintf(dir, sizeof dir, "%s/digest-counts", base);
    mkdir(base, 0755); chmod(base, 0755);
    mkdir(dir, 0755); chmod(dir, 0755);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0, "digest counts: no plane");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        CHECK(0, "digest counts: the binding is refused: %s", why);
        return;
    }
    /* the armed file's mtime moved after the bind: the worker start digests it, on the start path */
    ts[0].tv_sec = 0; ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = 1000000000; ts[1].tv_nsec = 0;
    CHECK(utimensat(AT_FDCWD, path, ts, 0) == 0, "digest counts: the mtime is not settable");
    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "digest counts: the worker start is refused: %s", why);
    dc_counts(pl, now, &all, &start);
    CHECK(all == 1u && start == 1u, "digest counts: the worker start's digest of a touched plane reads digests %llu "
          "start-digests %llu, not 1 and 1", all, start);
    /*
     * The rename that publishes the new generation unlinks the armed inode, and an unlink moves its
     * ctime. Whether the tick SEES that move is the kernel's to say, not the test's: a fine-grained
     * ctime (the multigrain timestamps ext4, xfs, btrfs and tmpfs carry since Linux 6.13) shows it at
     * once, because the worker start's own fstat queried the ctime; a coarse one shows it only when a
     * clock tick fell between that fstat and the rename. A seen move is row (b), the armed inode's
     * confirming re-digest, which stays by design (an nlink change and a chmod move ctime alike, and
     * nothing in the identity tells them apart), and it runs before the name is looked at, in the same
     * tick. So the row reads the very field the module compares, the armed inode's ctime, through a
     * descriptor of its own on that inode, and expects exactly the digests that ctime implies: 2 when
     * it stood still, 3 when it moved. Expecting 2 alone passed on a coarse clock and failed on every
     * kernel with fine-grained ctimes.
     */
    afd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(afd >= 0 && fstat(afd, &a0) == 0, "digest counts: the armed inode cannot be held");
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, far, 0xC0000300u) == 0, "digest counts: no second generation");
    CHECK(afd >= 0 && fstat(afd, &a1) == 0 && a1.st_nlink == 0, "digest counts: the rename left the armed inode linked");
    moved = afd >= 0 && (a1.st_ctim.tv_sec != a0.st_ctim.tv_sec || a1.st_ctim.tv_nsec != a0.st_ctim.tv_nsec);
    if (afd >= 0) {
        close(afd);
    }
    pl_cycle(pl, 1u);
    dc_counts(pl, now, &all, &start);
    CHECK(all == (moved ? 3u : 2u) && start == 1u, "digest counts: a new generation on a tick reads digests %llu "
          "start-digests %llu, not %u and 1 (the armed inode's ctime %s)", all, start, moved ? 3u : 2u,
          moved ? "moved: its re-digest, then the candidate's" : "stood still: the candidate's alone");
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 200u, "digest counts: generation 200 did not arm (generation %llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    printf("  digest counts: the armed inode's ctime %s at the rename here, so the tick ran %llu digests\n",
           moved ? "moved" : "stood still", all);
    we_mod_planes_release(pl);
    rm_tree(base);
#endif
}

static void t_planes_tenant(void)
{
    char base[256], dir[300], why[512], path[400];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_worker_args_t w;
    static __uint128_t s4[1], e4[1];
    static uint8_t rec[64];
    ww_plane_t p;
    const we_map_t *cur;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        return;
    }
    snprintf(dir, sizeof dir, "%s/tenant", base);
    mkdir(base, 0755);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    memset(&p, 0, sizeof p);
    s4[0] = 0xC0000200u;
    e4[0] = 0xC00002FFu;
    p.format = 2u;
    p.schema = 1;
    p.plane = WE_PLANE_TENANT;
    p.generation = 7u;
    p.valid_until_ms = 4102444800000ull;
    p.v4.n = 1u;
    p.v4.start = s4;
    p.v4.end = e4;
    p.v4.rec = rec;
    snprintf(path, sizeof path, "%s/tenant.bin", dir);
    CHECK(ww_write(path, &p) == 0 && chmod(path, 0444) == 0, "tenant: the plane is not written");
    CHECK(pl_write_rep(dir, "reputation.bin", 3u, 4102444800000ull, 0xC0000200u) == 0, "tenant: the reputation plane is not written");
    memset(&cfg, 0, sizeof cfg);
    args.data_dir = dir;
    args.read_mask = 0x01u;                      /* the reputation bit only: no rule names the tenant plane */
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL, "tenant: the binding is refused: %s", why);
    if (pl == NULL) {
        return;
    }
    /* a present tenant.bin is bound whatever the rules read: no caller bit, and still the listed allow list
     * (the control binds by the mask and leaves the floor's stand-in here) */
    cur = we_current(cfg.handle[7]);
    CHECK(cur != NULL && cur->generation == 7u, "tenant: a listed tenant.bin with no caller bit was not bound");
    unlink(path);

    /* THE ORDER: a tick before the worker start does nothing and is counted; the start after a tick is refused */
    we_mod_planes_tick(pl, 1u, NULL);
    we_mod_planes_apply(pl, pl_logger, NULL);
    {
        static we_mod_status_t st;

        we_mod_planes_status(pl, &st, args.now_ms);
        CHECK(we_current(cfg.handle[7]) == cur && st.ticks_before_start == 1u,
              "order: a tick before the worker start acted (or went uncounted: %llu)",
              (unsigned long long)st.ticks_before_start);
    }
    memset(&w, 0, sizeof w);
    w.now_ms = args.now_ms;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "order: the worker start is refused: %s", why);
    pl_cycle(pl, 2u);
    cur = we_current(cfg.handle[7]);
    CHECK(cur != NULL && cur->revoked == 1u && cur->generation == 0u,
          "tenant: a deleted tenant.bin did not install the revoked map");
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == WE_MOD_ERR_ARG && strstr(why, "already ticks") != NULL,
          "order: a worker start after the thread ticked was not refused: %s", why);
    /*
     * THE LOG IN TICK ORDER: the tenant re-armed, then in ONE tick the reputation plane (plane 1) and the
     * tenant plane (plane 8) both deleted. The first logs a line and posts nothing (the armed generation
     * serves); the second logs and posts its revocation. The logger must read them in that order: the
     * control hands the revocation the newest line instead, and the reputation line arrives second.
     */
    p.generation = 8u;
    CHECK(ww_write(path, &p) == 0 && chmod(path, 0444) == 0, "log order: the tenant plane is not rewritten");
    pl_cycle(pl, 3u);
    {
        char rp[420];

        snprintf(rp, sizeof rp, "%s/reputation.bin", dir);
        CHECK(we_current(cfg.handle[7]) != NULL && we_current(cfg.handle[7])->generation == 8u
              && we_current(cfg.handle[0]) != NULL && we_current(cfg.handle[0])->generation == 3u,
              "log order: the two planes are not armed before the tick");
        unlink(rp);
        unlink(path);
    }
    pl_log_reset();
    pl_cycle(pl, 4u);
    CHECK(g_nlog >= 2u && strstr(g_log[0], "reputation.bin") != NULL && strstr(g_log[1], "tenant.bin") != NULL,
          "log order: one tick's lines reached the logger out of tick order (%u lines: \"%s\" then \"%s\")", g_nlog,
          g_nlog > 0u ? g_log[0] : "", g_nlog > 1u ? g_log[1] : "");
    {
        uint32_t armed = 7u;

        /* the built monitor refuses a serving process: this binding's worker started and its thread ticked */
        CHECK(we_mod_planes_monitor(pl, 5u, &armed) == WE_MOD_ERR_ARG && armed == 0u,
              "monitor: a binding whose worker started and thread ticked was not refused");
        CHECK(we_mod_planes_monitor(pl, 5u, NULL) == WE_MOD_ERR_ARG, "monitor: a NULL armed mask was not refused");
        we_mod_planes_monitor_release(pl);
    }
    we_mod_planes_tick(NULL, 3u, NULL);          /* a NULL binding: ignored, never dereferenced */
    CHECK(we_mod_worker_start(NULL, &w, why, sizeof why) == WE_MOD_ERR_ARG, "order: a NULL binding's start was not refused");
    we_mod_planes_release(pl);
    rm_tree(base);
}

/*
 * The binding holds the data directory's descriptor: every later look at a plane goes through
 * it, so repointing the configured path's link at another directory changes nothing read. The tenant plane
 * stays armed when the link is repointed at a directory with no tenant.bin. WE_MOD_TEST_REOPEN_BY_PATH,
 * the name reopened by its path string, reads the new directory and revokes the live allow list.
 */
static void t_planes_repointed(void)
{
    char base[256], d1[300], d2[300], lnk[300], why[512], path[400];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_worker_args_t w;
    static __uint128_t s4[1], e4[1];
    static uint8_t rec[64];
    ww_plane_t p;
    const we_map_t *cur;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "repointed: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755); chmod(base, 0755);
    snprintf(d1, sizeof d1, "%s/rp-a", base);
    snprintf(d2, sizeof d2, "%s/rp-b", base);
    snprintf(lnk, sizeof lnk, "%s/rp-data", base);
    mkdir(d1, 0755); chmod(d1, 0755);
    mkdir(d2, 0755); chmod(d2, 0755);
    unlink(lnk);
    memset(&p, 0, sizeof p);
    s4[0] = 0xC0000200u;
    e4[0] = 0xC00002FFu;
    p.format = 2u;
    p.schema = 1;
    p.plane = WE_PLANE_TENANT;
    p.generation = 7u;
    p.valid_until_ms = 4102444800000ull;
    p.v4.n = 1u;
    p.v4.start = s4;
    p.v4.end = e4;
    p.v4.rec = rec;
    snprintf(path, sizeof path, "%s/tenant.bin", d1);
    CHECK(ww_write(path, &p) == 0 && chmod(path, 0444) == 0 && symlink(d1, lnk) == 0, "repointed: the fixture is not made");
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = lnk;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL && cfg.handle[7] != NULL,
          "repointed: the binding through the link is refused: %s", why);
    if (pl == NULL || cfg.handle[7] == NULL) {
        return;
    }
    memset(&w, 0, sizeof w);
    w.now_ms = 1700000000000ull;
    w.interval_ms = 60000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "repointed: the worker start failed: %s", why);
    /* the link repointed at a directory with no tenant.bin, then a tick */
    unlink(lnk);
    CHECK(symlink(d2, lnk) == 0, "repointed: the link is not repointed");
    pl_cycle(pl, 2u);
    cur = we_current(cfg.handle[7]);
    CHECK(cur != NULL && cur->revoked == 0u && cur->generation == 7u,
          "repointed: repointing the data directory's link at another directory revoked the live allow list "
          "(generation %llu, revoked %u)", cur != NULL ? (unsigned long long)cur->generation : 0ull, cur != NULL ? cur->revoked : 0u);
    we_mod_planes_release(pl);
    unlink(lnk);
    unlink(path);
    rmdir(d1);
    rmdir(d2);
}

/*
 * THE SUPERVISOR'S BUDGETED VERIFICATION: the two calls the header declared ahead of their body,
 * built. Every row is deterministic: a zero budget is checked before every chunk, so it takes the
 * buffer and reads nothing, and the next call resumes; a big budget finishes and arms; the fork row
 * counts the process's own large anonymous mappings, which a child forked while the buffer is held
 * must carry exactly as many of as one forked while it is not, because that buffer is the one
 * mapping MADV_DONTFORK exists to keep from a child. The armed inode's rows (b) and (c) run here too:
 * the parent's monitor watches its own armed inode, disarms a trust-broken one at once, re-digests a
 * drifted one budgeted, refreshes its own I on a confirm (so the next call finds nothing new) and
 * ends a rewrite in place with the final disarm.
 */
static void t_planes_monitor(void)
{
    char base[256], dir[300], path[400], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_mod_status_t st;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;
    uint64_t calls, last, total, done, before_done, before_total;
    uint32_t armed, before_forks, held_forks, big_bytes;
    const we_map_t *cur;
    struct stat fs, fs0;
    int rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "monitor: no trusted base directory to build the plane under; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    snprintf(dir, sizeof dir, "%s/monitor", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(path, sizeof path, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0, "monitor: the first generation is not written");
    CHECK(stat(path, &fs0) == 0, "monitor: the armed generation is not at its name");
    memset(&cfg, 0, sizeof cfg);
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.log = pl_logger;
    args.high_water_file = "/nonexistent/high-water";
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && cfg.bound_mask == 0x01u && we_current(cfg.handle[0]) != NULL
          && we_current(cfg.handle[0])->generation == 100u,
          "monitor: the binding is refused or unarmed (rc %d): %s", rc, why);
    if (pl == NULL) {
        rm_tree(base);
        return;
    }
    /* the misuse rows: a NULL mask and a NULL binding are refused, and neither counts as a call */
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 5u, NULL) == WE_MOD_ERR_ARG, "monitor: a NULL armed mask was not refused");
    CHECK(we_mod_planes_monitor(NULL, 5u, &armed) == WE_MOD_ERR_ARG && armed == 0u, "monitor: a NULL binding was not refused");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(calls == 0u && done == 0u && total == 0u, "monitor: a refused call did work (calls %llu, done %llu)",
          (unsigned long long)calls, (unsigned long long)done);
    /* nothing due: the name still resolves to the armed inode, and the call holds no buffer */
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: a call with nothing due armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: a call with nothing due holds a buffer (%llu bytes)",
          (unsigned long long)st.verify_held);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(calls == 1u && last == 0u && done == 0u, "monitor: the first call's counters are wrong (calls %llu, last %llu)",
          (unsigned long long)calls, (unsigned long long)last);
    /* a new generation, budget zero: the buffer is taken and held, nothing is read, nothing is armed.
     * Which file the held buffer belongs to is the vantage's to say: when the rename's unlink-mark on
     * the armed inode is already visible here (a fine-grained ctime shows it at once, a coarse one
     * only when a tick boundary fell between the binding and this write), the call starts the armed
     * inode's confirming re-digest, row (b), in the candidate's place. Both files are one-range
     * planes of this writer, so both buffers are fs0.st_size bytes; the row takes either, and says
     * what it actually proves: the started verification's whole buffer, held unread. */
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, far, 0xC0000300u) == 0, "monitor: the second generation is not written");
    CHECK(stat(path, &fs) == 0, "monitor: the candidate is not at its name");
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: a zero budget armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)fs0.st_size || st.verify_held == (uint64_t)fs.st_size,
          "monitor: a zero budget did not hold the started verification's whole buffer "
          "(%llu of %llu)", (unsigned long long)st.verify_held, (unsigned long long)fs0.st_size);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(calls == 2u && last == 0u && total == 0u && done == 0u,
          "monitor: a zero budget read bytes (last %llu) or finished (done %llu)", (unsigned long long)last,
          (unsigned long long)done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the resumed zero-budget call armed something");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(calls == 3u && last == 0u && total == 0u && done == 0u, "monitor: the second zero budget read bytes (last %llu)",
          (unsigned long long)last);
    /* a child forked now, mid-verification: its worker start forgets what it inherited. The buffer was
     * DONTFORK, so only the descriptor and the held figure came across; the child closes the one (a replaced
     * plane's inode held open for its whole life otherwise) and drops the other to 0. Counted in the child,
     * by the descriptors on the two plane inodes before and after the start. WE_MOD_TEST_FORK_KEEPS_MONITOR
     * fails by name. */
    {
        pid_t kid;
        int ws = 0;

        fflush(stdout);
        kid = fork();
        if (kid == 0) {
            we_mod_worker_args_t cw;
            we_mod_status_t cs;
            char cwhy[256];
            int before = 0, after = 0, fdn;
            struct stat fst;

            for (fdn = 3; fdn < 1024; fdn++) {
                if (fstat(fdn, &fst) == 0 && (fst.st_ino == fs.st_ino || fst.st_ino == fs0.st_ino)) {
                    before++;
                }
            }
            memset(&cw, 0, sizeof cw);
            cw.now_ms = now;
            cw.interval_ms = 60000u;
            if (we_mod_worker_start(pl, &cw, cwhy, sizeof cwhy) != 0) {
                _exit(3);
            }
            for (fdn = 3; fdn < 1024; fdn++) {
                if (fstat(fdn, &fst) == 0 && (fst.st_ino == fs.st_ino || fst.st_ino == fs0.st_ino)) {
                    after++;
                }
            }
            we_mod_planes_status(pl, &cs, now);
            _exit(cs.verify_held != 0u ? 4 : after != before - 1 ? 5 : 0);
        }
        CHECK(kid > 0 && waitpid(kid, &ws, 0) == kid && WIFEXITED(ws) && WEXITSTATUS(ws) == 0,
              "monitor: a child forked mid-verification kept the parent's verification after its worker start "
              "(child exit %d: 4 the held figure, 5 the descriptor)", WIFEXITED(ws) ? WEXITSTATUS(ws) : -1);
    }
    /* a big budget finishes the carried verification and arms the plane */
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u,
          "monitor: the resumed verification did not arm plane 0 (mask 0x%x)", armed);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 200u, "monitor: the resumed verification armed the wrong generation (%llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the armed plane still holds its verification buffer (%llu bytes)",
          (unsigned long long)st.verify_held);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    /* The finishing call's accounting is whole verifications, every byte of each read inside this one
     * call (the zero-budget rows above already hold the earlier calls to no bytes). One completion is
     * the minimum. A second is legitimate, and which of the two shapes this vantage shows is the
     * kernel's to decide: where the rename's unlink-mark on the armed inode is already visible at
     * the second call (a fine-grained ctime shows it at once, a coarse one only when a tick boundary
     * fell between the binding and the rename), that call started the armed inode's confirming
     * re-digest in the candidate's place, and this call first confirms it and then, with budget
     * left, verifies and publishes the candidate in the same call: the armed file's bytes and the
     * candidate's bytes, two completions, the plane armed either way. Anything else here, a partial
     * read, a completion with no bytes, a third pass, is wrong. */
    CHECK(calls == 4u && last == total
          && ((done == 1u && total == (uint64_t)fs.st_size)
              || (done == 2u && total == (uint64_t)fs0.st_size + (uint64_t)fs.st_size)),
          "monitor: the finishing call's counters are wrong (calls %llu, done %llu, total %llu, last %llu)",
          (unsigned long long)calls, (unsigned long long)done, (unsigned long long)total, (unsigned long long)last);
    /* (b) the armed inode's ctime alone, a chmod that admits a writer: disarmed at once, the fix said */
    {
        struct timespec pause = { 0, 30000000 };

        nanosleep(&pause, NULL);               /* a ctime moves on the kernel's coarse clock */
    }
    CHECK(chmod(path, 0644) == 0, "monitor: the armed plane is not chmod-able");
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the trust-broken inode armed something");
    CHECK(pl_log_has("disarmed") && pl_log_has("chmod 0444"),
          "monitor: the trust-broken inode's disarm was not said with its fix");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "monitor: the trust-broken inode kept the plane armed");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: a trust-broken inode started a re-digest (%llu bytes)",
          (unsigned long long)st.verify_held);
    /* the fix applied in place: the re-digest is budgeted, confirms, re-arms, and refreshes the identity */
    {
        struct timespec pause = { 0, 30000000 };

        nanosleep(&pause, NULL);
    }
    CHECK(chmod(path, 0444) == 0, "monitor: the fixed plane is not chmod-able");
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the fixed inode armed before its re-digest");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)fs.st_size, "monitor: the fixed inode's re-digest is not budgeted (%llu bytes held)",
          (unsigned long long)st.verify_held);
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u, "monitor: the confirming re-digest did not re-arm");
    CHECK(we_current(cfg.handle[0]) == cur, "monitor: the confirming re-digest did not restore the armed map");
    CHECK(pl_log_has("re-armed"), "monitor: the confirming re-digest's re-arm was not said");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the confirmed re-digest left its buffer held (%llu bytes)",
          (unsigned long long)st.verify_held);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the confirmed inode armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the confirmed identity was not refreshed, so the next call re-digested it");
    /* (c) a moved mtime with the bytes unchanged: disarmed at once, re-armed by the confirming digest */
    {
        struct timespec ts[2];

        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec = 1000000000;
        ts[1].tv_nsec = 0;
        CHECK(utimensat(AT_FDCWD, path, ts, 0) == 0, "monitor: the armed plane's mtime is not settable");
    }
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the moved mtime armed something");
    CHECK(pl_log_has("disarmed") && pl_log_has("rewritten in place"),
          "monitor: the moved mtime's disarm was not said as row (c)");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "monitor: the moved mtime kept the plane armed");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)fs.st_size, "monitor: the moved mtime's re-digest is not budgeted (%llu bytes held)",
          (unsigned long long)st.verify_held);
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u, "monitor: the moved mtime's digest did not re-arm");
    CHECK(we_current(cfg.handle[0]) == cur && pl_log_has("re-armed"), "monitor: the moved mtime was not re-armed by its digest");
    armed = 7u;
    we_mod_planes_monitor(pl, 0u, &armed);
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the re-armed plane was re-digested again, so the identity was not refreshed");
    /* (c) a real rewrite of the bytes: the re-digest ends in the final disarm, and the rewritten file
     * is refused by its generation, remembered, never re-verified */
    {
        struct timespec pause = { 0, 30000000 };
        int fd;
        uint8_t b;

        nanosleep(&pause, NULL);
        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "monitor: the rewrite is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the rewritten file armed something");
    CHECK(pl_log_has("disarmed") && pl_log_has("rewritten in place"), "monitor: the rewrite's disarm was not said");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u, "monitor: the rewrite's re-digest armed something");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "monitor: the rewritten bytes kept the plane armed");
    we_mod_planes_status(pl, &st, now);
    CHECK(strcmp(st.plane[0].state, "disarmed") == 0 && strstr(st.plane[0].reason, "final") != NULL,
          "monitor: the rewrite did not end in the final disarm (state %s, reason %s)", st.plane[0].state,
          st.plane[0].reason);
    CHECK(pl_log_has("final: generation 200 is committed"), "monitor: the final disarm's text was not said");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the rewrite's re-digest did not run to its conclusion (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    CHECK(pl_log_has("not above"), "monitor: the rewritten same-generation file was not refused by its header "
          "in the call that finished the re-digest");
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u,
          "monitor: the remembered same-generation file armed something");
    CHECK(g_nlog == 0u && we_current(cfg.handle[0]) == cfg.standin[0],
          "monitor: the remembered same-generation file was looked at again (%u lines)", g_nlog);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the refused rewrite was digested again (done %llu)",
          (unsigned long long)done);
    /* the pconf cleanup: a verification in progress and its buffer are dropped, and the next call
     * verifies from scratch */
    CHECK(pl_write_rep(dir, "reputation.bin", 300u, far, 0xC0000400u) == 0, "monitor: the third generation is not written");
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the third generation's zero budget armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held > 0u, "monitor: the third generation's verification holds no buffer");
    we_mod_planes_monitor_release(pl);
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the released verification still holds its buffer (%llu bytes)",
          (unsigned long long)st.verify_held);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u,
          "monitor: the dropped verification was not restarted and armed");
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 300u, "monitor: the restarted verification armed the wrong generation (%llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the dropped verification was counted as finished (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    /* the release row's plane is disarmed for the fork row: rewriting its bytes ends in a second final
     * disarm, so no armed inode is left when the big write renames over the name (a rename over the
     * name unlinks the armed inode, and the ctime bump that follows would start a confirming re-digest
     * that steals the big candidate's start); disarmed, the fork row's zero budget can only be the
     * big candidate's own verification */
    {
        struct timespec pause = { 0, 30000000 };
        int fd;
        uint8_t b;

        nanosleep(&pause, NULL);
        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "monitor: the second rewrite is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the second rewrite armed something");
    CHECK(pl_log_has("disarmed") && pl_log_has("rewritten in place"),
          "monitor: the second rewrite's disarm was not said");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)fs.st_size, "monitor: the second rewrite's re-digest is not budgeted (%llu held)",
          (unsigned long long)st.verify_held);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u,
          "monitor: the second rewrite's re-digest armed something");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "monitor: the second rewrite kept the plane armed");
    we_mod_planes_status(pl, &st, now);
    CHECK(strcmp(st.plane[0].state, "disarmed") == 0 && strstr(st.plane[0].reason, "final") != NULL,
          "monitor: the second rewrite did not end in the final disarm (state %s, reason %s)", st.plane[0].state,
          st.plane[0].reason);
    CHECK(pl_log_has("final: generation 300 is committed"), "monitor: the second final disarm's text was not said");
    CHECK(pl_log_has("not above"), "monitor: the second rewrite's same-generation file was not refused by its header");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the second rewrite's re-digest did not run to its conclusion (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    /* THE DONTFORK ROW: a child forked while the buffer is held carries exactly as many large
     * anonymous mappings as one forked while it is not */
    before_forks = pl_fork_count();
    CHECK(before_forks != 0xFFFFFFFFu, "monitor: the fork probe cannot read its own maps");
    CHECK(pl_write_rep_big(dir, "reputation.bin", 400u, far) == 0, "monitor: the big generation is not written");
    CHECK(stat(path, &fs) == 0, "monitor: the big candidate is not at its name");
    big_bytes = (uint32_t)fs.st_size;
    CHECK(big_bytes > (1u << 20), "monitor: the big generation is not over a chunk (%u bytes)", big_bytes);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the big candidate's zero budget armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)big_bytes, "monitor: the big candidate's zero budget did not take its whole "
          "buffer (%llu of %u)", (unsigned long long)st.verify_held, big_bytes);
    held_forks = pl_fork_count();
    CHECK(held_forks == before_forks, "monitor: a child forked with the buffer held carries %u large anonymous "
          "mappings where one forked without it carries %u", held_forks, before_forks);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    we_mod_planes_monitor_counts(pl, &calls, &last, &before_total, &done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u, "monitor: the big generation did not arm");
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 400u, "monitor: the big generation armed the wrong plane (%llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(last == (uint64_t)big_bytes && total == before_total + (uint64_t)big_bytes,
          "monitor: the big generation's read counters are wrong (last %llu, total %llu of %llu)",
          (unsigned long long)last, (unsigned long long)total, (unsigned long long)before_total);
    CHECK(pl_fork_count() == before_forks, "monitor: the armed big plane's buffer was not released");
    /* the big plane is disarmed for the truncate row: rewriting its bytes ends in a third final disarm,
     * so the shrink's candidate starts alone (an armed inode would confirm under its rename and steal
     * the start, and the shrink would never be read) */
    {
        struct timespec pause = { 0, 30000000 };
        int fd;
        uint8_t b;

        nanosleep(&pause, NULL);
        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "monitor: the big rewrite is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the big rewrite armed something");
    CHECK(pl_log_has("disarmed") && pl_log_has("rewritten in place"), "monitor: the big rewrite's disarm was not said");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)big_bytes, "monitor: the big rewrite's re-digest is not budgeted (%llu of %u)",
          (unsigned long long)st.verify_held, big_bytes);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u, "monitor: the big rewrite's re-digest armed something");
    CHECK(we_current(cfg.handle[0]) == cfg.standin[0], "monitor: the big rewrite kept the plane armed");
    we_mod_planes_status(pl, &st, now);
    CHECK(strcmp(st.plane[0].state, "disarmed") == 0 && strstr(st.plane[0].reason, "final") != NULL,
          "monitor: the big rewrite did not end in the final disarm (state %s, reason %s)", st.plane[0].state,
          st.plane[0].reason);
    CHECK(pl_log_has("final: generation 400 is committed"), "monitor: the third final disarm's text was not said");
    CHECK(pl_log_has("not above"), "monitor: the big rewrite's same-generation file was not refused by its header");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the big rewrite's re-digest did not run to its conclusion (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    /* the truncate row: a file that shrank under a carried verification is refused, remembered, and
     * never re-verified; the standin serves, and the emptied file the shrink leaves is refused by its
     * header in the same call's window, remembered too */
    CHECK(pl_write_rep(dir, "reputation.bin", 500u, far, 0xC0000500u) == 0, "monitor: the fourth generation is not written");
    CHECK(stat(path, &fs) == 0, "monitor: the fourth generation is not at its name");
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 0u, &armed) == 0 && armed == 0u, "monitor: the fourth generation's zero budget armed something");
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == (uint64_t)fs.st_size, "monitor: the fourth generation's verification holds the wrong buffer "
          "(%llu of %llu)", (unsigned long long)st.verify_held, (unsigned long long)fs.st_size);
    CHECK(chmod(path, 0644) == 0 && truncate(path, 0) == 0, "monitor: the candidate is not truncatable");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u, "monitor: the shrunken candidate armed something");
    CHECK(pl_log_has("shrank") && we_current(cfg.handle[0]) == cfg.standin[0],
          "monitor: the shrunken candidate was not refused as a shrink");
    CHECK(pl_log_has("not a plane file"), "monitor: the emptied file the shrink left was not refused by its header");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the shrunken candidate's read did not run to its refusal (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    we_mod_planes_status(pl, &st, now);
    CHECK(st.verify_held == 0u, "monitor: the refused shrink left its buffer held (%llu bytes)",
          (unsigned long long)st.verify_held);
    /* both refusals are remembered with no retry: the next call looks at neither file again */
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u,
          "monitor: a remembered shrink and its emptied file armed something");
    CHECK(g_nlog == 0u && we_current(cfg.handle[0]) == cfg.standin[0],
          "monitor: the remembered shrink and the remembered emptied file were looked at again (%u lines)", g_nlog);
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done, "monitor: the remembered shrink was digested again (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    /* a corrupt candidate: refused by its digest, remembered, the armed generation serves */
    CHECK(pl_write_rep(dir, "reputation.bin", 700u, far, 0xC0000600u) == 0, "monitor: the corrupt generation is not written");
    {
        int fd;
        uint8_t b;

        chmod(path, 0644);
        fd = open(path, O_RDWR);
        if (fd >= 0 && pread(fd, &b, 1, 200) == 1) {
            b ^= 0x40u;
            if (pwrite(fd, &b, 1, 200) != 1) {
                CHECK(0, "monitor: the corruption is not written");
            }
        }
        if (fd >= 0) {
            close(fd);
        }
        chmod(path, 0444);
    }
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &before_done);
    pl_log_reset();
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u, "monitor: the corrupt candidate armed something");
    CHECK(pl_log_has("digest mismatch") && we_current(cfg.handle[0]) == cfg.standin[0],
          "monitor: the corrupt candidate was not refused by its digest");
    we_mod_planes_monitor_counts(pl, &calls, &last, &total, &done);
    CHECK(done == before_done + 1u, "monitor: the corrupt candidate's read did not run to its refusal (done %llu of %llu)",
          (unsigned long long)done, (unsigned long long)before_done);
    /* the next generation re-arms, and a call with nothing due arms nothing */
    CHECK(pl_write_rep(dir, "reputation.bin", 800u, far, 0xC0000700u) == 0, "monitor: the fifth generation is not written");
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 1 && armed == 0x01u, "monitor: the fifth generation did not arm");
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 800u, "monitor: the fifth generation armed the wrong plane (%llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    armed = 7u;
    CHECK(we_mod_planes_monitor(pl, 60000u, &armed) == 0 && armed == 0u, "monitor: a call with nothing due armed something");
    we_mod_planes_release(pl);
    rm_tree(base);
}

/* ---- V2, N2 and E1: the decision and the cold half make no system call, no allocation, no uninitialised read ---- */

/*
 * THE INPUT CLASSES the three rows run: the walk corpus's own (walk_classes.h, the table fuzz_walk writes
 * as its seeds), each one's walk through the parse loop feeding the decision, the record, a lazy fill of
 * every plane on a record the decision never touched, every request-path renderer over both records and
 * the judged span parsed and formatted again; then five ACME shapes. Everything a class needs that
 * allocates (its trust table, its peer, its lines) is built here, before any trap.
 */
#define WC_LINES 4u
static we_mod_trust_t g_wc_trust[WE_WALK_CLASSES];
static we_addr_t      g_wc_peer[WE_WALK_CLASSES];
static we_mod_line_t  g_wc_line[WE_WALK_CLASSES][WC_LINES];
static uint32_t       g_wc_nline[WE_WALK_CLASSES];
static uint32_t       g_wc_judged, g_wc_lazy;      /* classes whose walk judged a header entry; lazy fills that held */
static uint32_t       g_wc_aliased, g_wc_exempt, g_wc_acme;   /* aliased runs; exempt decisions; ACME matches */
static uint32_t       g_wc_acme_exempt;                        /* ACME matches the decision took as exempt */

static int wc_build(char *err, size_t errn)
{
    uint32_t i, k;

    for (i = 0u; i < WE_WALK_CLASSES; i++) {
        const we_walk_class_t *c = &we_walk_classes[i];
        const char *items[4];
        const char *p = c->body;
        uint32_t n = 0u;

        for (k = 0u; we_wc_lists[c->list][k] != NULL; k++) {
            items[n++] = we_wc_lists[c->list][k];
        }
        if (c->flags & 8u) {
            items[n++] = "unix:";
        }
        if (we_mod_trust_build(items, n, &g_wc_trust[i], NULL, err, errn) != 0) {
            return -1;
        }
        g_wc_peer[i] = A(c->peer);
        g_wc_nline[i] = 0u;
        while (g_wc_nline[i] < WC_LINES) {
            const char *e = strchr(p, '\n');
            size_t len = e != NULL ? (size_t)(e - p) : strlen(p);

            if (len == 0u && e == NULL && g_wc_nline[i] > 0u) {
                break;
            }
            g_wc_line[i][g_wc_nline[i]].p = (const uint8_t *)p;
            g_wc_line[i][g_wc_nline[i]].len = len;
            g_wc_nline[i]++;
            if (e == NULL) {
                break;
            }
            p = e + 1;
        }
        if (c->body[0] == '\0') {
            g_wc_nline[i] = 0u;              /* the header absent: no line at all */
        }
    }
    return 0;
}

/* every byte a renderer wrote, folded into the sink, so memcheck sees any it left undefined */
static uint32_t wc_fold(uint32_t sink, const char *p, size_t len)
{
    size_t i;

    for (i = 0u; p != NULL && i < len; i++) {
        sink = sink * 31u + (uint8_t)p[i];
    }
    return sink;
}

static uint32_t wc_render(uint32_t sink, we_mod_record_t *rec, const we_mod_cfg_t *cfg, const we_mod_walk_t *wk)
{
    char buf[WE_MOD_LOGGED_MAX], gen[WE_MOD_GEN_MAX], addr[WE_ADDR_TEXT_MAX];
    const char *sp, *t;
    size_t len;
    uint32_t i;

    for (i = 0u; i < 2u; i++) {
        t = we_mod_render_verdict(rec, i);
        sink = wc_fold(sink, t, t != NULL ? strlen(t) : 0u);
    }
    t = we_mod_render_action(rec);
    sink = wc_fold(sink, t, strlen(t));
    t = we_mod_render_reason(rec, wk->walk, wk->note);
    sink = wc_fold(sink, t, t != NULL ? strlen(t) : 0u);
    t = we_mod_render_program(rec, cfg);
    sink = wc_fold(sink, t, t != NULL ? strlen(t) : 0u);
    for (i = 0u; i < 2u; i++) {
        t = we_mod_render_rule(rec, cfg, (int)i);
        sink = wc_fold(sink, t, t != NULL ? strlen(t) : 0u);
    }
    sink = wc_fold(sink, buf, we_mod_render_logged(rec, buf));
    sink = wc_fold(sink, gen, we_mod_render_generations(rec, gen));
    sink = wc_fold(sink, addr, we_mod_render_floor(rec, addr));
    for (i = 0u; i < we_attr_count(); i++) {
        sp = NULL;
        len = 0u;
        if (we_mod_render_attr(rec, i, &sp, &len) == 0) {
            sink = wc_fold(sink, sp, len);
        }
    }
    return sink;
}

/* one request through the decision, the record write, every renderer and a lazy fill on a fresh record;
 * the scratch is marked undefined before the decision (row E1: a decision reads nothing a previous
 * request left), a no-op outside memcheck */
static uint32_t wc_one(fixture_t *f, we_mod_scratch_t *s, uint64_t *shard, we_mod_record_t *rec, we_mod_record_t *lazy,
                       const we_mod_req_t *q, const we_mod_walk_t *wk, uint32_t sink)
{
    we_mod_scratch_t local;                      /* the lazy-fill handler's stack-local path, uninitialised */

    VALGRIND_MAKE_MEM_UNDEFINED(s, sizeof *s);
    we_mod_decide(&f->cfg, &f->ctx, s, shard, q, 1700000000000ull);
    g_wc_exempt += s->v.step == WE_STEP_EXEMPT;
    we_mod_record_init(rec, &f->ctx);
    we_mod_record_write(rec, &f->cfg, &f->ctx, s, &q->r.floor, &q->r.server);
    sink = wc_render(sink, rec, &f->cfg, wk);
    we_mod_record_init(lazy, &f->ctx);
    we_mod_record_key(lazy, &q->r.floor);
    we_mod_fill(lazy, &f->cfg, &local, 0xFFu, 1700000000000ull);
    g_wc_lazy += lazy->lazy_mask != 0u;
    /* every byte of the local's verdict a reader uses (the 80 the record copies, and in the trace build the
     * lookup counts) is used here, so memcheck sees one the fill left as the stack held it */
    sink = wc_fold(sink, (const char *)&local.v, 80u);
#ifdef WE_TRACE
    sink = wc_fold(sink, (const char *)&local.v.lookups[0][0], sizeof local.v.lookups);
#endif
    return wc_render(sink, lazy, &f->cfg, wk);
}

static uint32_t cold_and_hot(fixture_t *f, we_mod_scratch_t *s, uint64_t *shard, we_mod_record_t *rec)
{
    static uint8_t raw2[WE_MOD_RECORD_ALLOC];
    /* method, target as sent, the server's normalised path: two that the matcher accepts (origin- and
     * absolute-form, so its normalised-path loop and final compare run) and four it refuses */
    static const char *const acme[6][3] = {
        { "GET", "/.well-known/acme-challenge/abc", "/.well-known/acme-challenge/abc" },
        { "HEAD", "http://a.test/.well-known/acme-challenge/Tok_en-1", "/.well-known/acme-challenge/Tok_en-1" },
        { "GET", "/.well-known/acme-challenge/%2e%2e/x", "/x" },
        { "GET", "//.well-known/acme-challenge/abc", "/.well-known/acme-challenge/abc" },
        { "GET", "/.well-known/acme-challenge/abc?", "/.well-known/acme-challenge/abc" },
        { "POST", "/.well-known/acme-challenge/abc", "/.well-known/acme-challenge/abc" },
    };
    we_mod_record_t *lazy = we_mod_record_at(raw2);
    we_addr_t server = A("192.0.2.200"), back;
    we_mod_walk_t wk0;
    char addr[WE_ADDR_TEXT_MAX];
    uint32_t i, sink = 0u;

    memset(&wk0, 0, sizeof wk0);
    for (i = 0u; i < WE_WALK_CLASSES; i++) {
        const we_walk_class_t *c = &we_walk_classes[i];
        we_mod_req_t q;
        we_mod_walk_t wk;
        uint32_t alias;

        we_mod_walk(&g_wc_trust[i], c->hops, (c->flags >> 1) & 1, (c->flags & 1u) ? NULL : &g_wc_peer[i],
                    g_wc_line[i], g_wc_nline[i], (c->flags >> 2) & 1, &wk);
        if (i == 0u) {
            wk0 = wk;
        }
        /* each class twice: the server's slot apart from the floor's, then ALIASED to it */
        for (alias = 0u; alias < 2u; alias++) {
            we_mod_req_build(&q, &wk, alias ? &wk.floor : &server, 0);
            g_wc_aliased += alias && memcmp(&q.r.floor, &q.r.server, sizeof q.r.floor) == 0;
            sink = wc_one(f, s, shard, rec, lazy, &q, &wk, sink);
        }
        g_wc_judged += wk.line >= 0;
        if (wk.line >= 0 && we_mod_entry_parse(g_wc_line[i][wk.line].p + wk.off, wk.len, &back) == 0) {
            sink = wc_fold(sink, addr, we_addr_format(&back, addr));
        }
    }
    /* ACME: the matcher over each shape, and its answer carried into the decision as the server sets it */
    for (i = 0u; i < 6u; i++) {
        we_mod_req_t q;
        int ex = we_mod_acme((const uint8_t *)acme[i][0], strlen(acme[i][0]), (const uint8_t *)acme[i][1],
                             strlen(acme[i][1]), (const uint8_t *)acme[i][2], strlen(acme[i][2]));

        uint32_t before = g_wc_exempt;

        g_wc_acme += ex != 0;
        we_mod_req_build(&q, &wk0, &server, ex);
        sink = wc_one(f, s, shard, rec, lazy, &q, &wk0, sink * 31u + (uint32_t)ex);
        g_wc_acme_exempt += ex != 0 && g_wc_exempt == before + 1u;
    }
    return sink;
}

static int run_isolated(const char *name, fixture_t *f, int mode)
{
    static we_mod_scratch_t s;
    static uint64_t shard[SHARD_N];
    static uint8_t raw[WE_MOD_RECORD_ALLOC];
    we_mod_record_t *rec = we_mod_record_at(raw);
    pid_t pid;
    int stw = 0;

    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        if (mode == 1) {
            /* V2: any system call but exit kills the process */
            struct sock_filter prog[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_exit_group, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            };
            struct sock_fprog fp = { (unsigned short)(sizeof prog / sizeof prog[0]), prog };

            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp) != 0) {
                _exit(3);
            }
            (void)cold_and_hot(f, &s, shard, rec);
            (void)cold_and_hot(f, &s, shard, rec);
        } else {
            /* N2: an allocation through any interposed call aborts, and one libc makes inside itself (which no
             * interposer sees) moves the arena's in-use bytes */
            struct mallinfo2 before = mallinfo2(), after;

            __atomic_store_n(&g_alloc_trap, 1, __ATOMIC_RELAXED);
            (void)cold_and_hot(f, &s, shard, rec);
            __atomic_store_n(&g_alloc_trap, 0, __ATOMIC_RELAXED);
            after = mallinfo2();
            if (after.uordblks != before.uordblks || after.hblkhd != before.hblkhd) {
                syscall(SYS_exit_group, 4);
            }
        }
        syscall(SYS_exit_group, 0);
    }
    if (pid < 0) {
        CHECK(0, "%s: fork failed", name);
        return -1;
    }
    waitpid(pid, &stw, 0);
    CHECK(WIFEXITED(stw) && WEXITSTATUS(stw) == 0,
          "%s: the decision and the cold half did not run clean (%s %d)", name,
          WIFSIGNALED(stw) ? "killed by signal" : "exit", WIFSIGNALED(stw) ? WTERMSIG(stw) : WEXITSTATUS(stw));
    return 0;
}

/* the mappings of one plane file this process holds: /proc/self/map_files, one link per mapped range */
static unsigned map_files_of(const char *file)
{
    DIR *d = opendir("/proc/self/map_files");
    struct dirent *e;
    unsigned n = 0u;
    char lp[300], tgt[1100];
    size_t fl = strlen(file);

    if (d == NULL) {
        return ~0u;
    }
    while ((e = readdir(d)) != NULL) {
        ssize_t k;

        if (e->d_name[0] == '.') {
            continue;
        }
        snprintf(lp, sizeof lp, "/proc/self/map_files/%s", e->d_name);
        k = readlink(lp, tgt, sizeof tgt - 1u);
        if (k > 0) {
            tgt[k] = '\0';
            n += strncmp(tgt, file, fl) == 0 && (tgt[fl] == '\0' || tgt[fl] == ' ');
        }
    }
    closedir(d);
    return n;
}

/* VmLck from /proc/self/status, in bytes; ~0 when unread */
static uint64_t vm_locked(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long kb = ~0ull;

    if (f == NULL) {
        return ~0ull;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        if (sscanf(line, "VmLck: %llu kB", &kb) == 1) {
            break;
        }
    }
    fclose(f);
    return kb == ~0ull ? ~0ull : (uint64_t)kb * 1024u;
}

/*
 * The retire list's bound (row M9): ten generations land inside one grace at a 1 s interval. Four displaced
 * maps fill the four slots; every later generation is DEFERRED (nothing posted, the armed map serves, the
 * deferral counted) until a slot frees, so the plane holds at most six mappings of its file (the armed,
 * four retired, one candidate) and locks at most twice the armed mapping (a retired map is unlocked at
 * retirement). The control lets a publish go ahead without a free slot: the displaced map is lost, and
 * the mappings grow past six.
 */
static void t_retire_bound(void)
{
    char base[256], dir[300], why[512], file[400];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    static we_mod_status_t st;
    uint64_t far = 4102444800000ull, now = 1700000000000ull, g, page = (uint64_t)sysconf(_SC_PAGESIZE), lck, armed, carry;
    unsigned maps, maxmaps = 0u;
    const we_map_t *cur;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "retire bound: no trusted base directory; the row did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/retire", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    snprintf(file, sizeof file, "%s/reputation.bin", dir);
    CHECK(pl_write_rep(dir, "reputation.bin", 1u, far, 0xC0000200u) == 0, "retire bound: the first generation is not written");
    memset(&cfg, 0, sizeof cfg);
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL, "retire bound: the binding is refused: %s", why);
    if (pl == NULL) {
        rm_tree(base);
        return;
    }
    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 1000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "retire bound: the worker start is refused: %s", why);
    we_mod_planes_status(pl, &st, now);
    carry = st.verify_peak;               /* the peak this process carried in, before this row's own cycles */
    for (g = 2u; g <= 11u; g++) {
        CHECK(pl_write_rep(dir, "reputation.bin", g, far, 0xC0000200u + (uint32_t)g * 256u) == 0,
              "retire bound: generation %llu is not written", (unsigned long long)g);
        pl_cycle(pl, g);
        maps = map_files_of(file);
        maxmaps = maps > maxmaps ? maps : maxmaps;
    }
    we_mod_planes_status(pl, &st, now);
    cur = we_current(cfg.handle[0]);
    armed = (st.plane[0].bytes + page - 1u) / page * page;
    lck = vm_locked();
    CHECK(maxmaps <= 6u, "retire bound: the plane held %u mappings of its file (at most 6: the armed, four retired, "
          "one candidate); a displaced map was lost", maxmaps);
    /* the arm is not vacuous: the armed map IS locked (an mlock this host refused would leave VmLck near 0) */
    CHECK(st.plane[0].locked == 1u && lck != ~0ull && armed > 0u && lck >= armed,
          "retire bound: the armed mapping is not locked (locked %u, %llu bytes locked against %llu), so the VmLck "
          "arm would pass on nothing", (unsigned)st.plane[0].locked, (unsigned long long)lck, (unsigned long long)armed);
    CHECK(lck != ~0ull && armed > 0u && lck <= 2u * armed,
          "retire bound: the locked bytes, %llu against an armed mapping of %llu, are over twice it", (unsigned long long)lck,
          (unsigned long long)armed);
    CHECK(cur != NULL && cur->generation == 5u && st.plane[0].deferred > 0u && st.retire_lost == 0u,
          "retire bound: generation %llu serves, %llu deferred, %llu lost (the fifth serves, the rest deferred, none lost)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull, (unsigned long long)st.plane[0].deferred,
          (unsigned long long)st.retire_lost);
    /* slot-age: the host's clock minus the armed header's built_at_ms (the test writer stamps 1,000,000),
     * signed, so a step of this host's clock across the publisher's reads negative, then positive */
    we_mod_planes_status(pl, &st, 999500u);
    CHECK((st.plane[0].measured & WE_MOD_MEASURED_SLOT_AGE) != 0u && st.plane[0].slot_age_ms == -500,
          "slot-age: a clock 500 ms behind the publisher's reads %lld (measured %u), not -500",
          (long long)st.plane[0].slot_age_ms, (unsigned)(st.plane[0].measured & WE_MOD_MEASURED_SLOT_AGE));
    we_mod_planes_status(pl, &st, 1000700u);
    CHECK((st.plane[0].measured & WE_MOD_MEASURED_SLOT_AGE) != 0u && st.plane[0].slot_age_ms == 700,
          "slot-age: a clock 700 ms ahead of the publisher's reads %lld, not 700", (long long)st.plane[0].slot_age_ms);
    we_mod_planes_status(pl, &st, now);
    /* the verification buffer: one at a time, a plane's size, released between verifications */
    {
        struct stat fst;
        uint64_t peak = st.verify_peak;
        char big[420];
        int fd;

        CHECK(stat(file, &fst) == 0 && st.verify_held == 0u && peak > 0u && peak <= carry + 2u * (uint64_t)fst.st_size,
              "verification buffer: %llu bytes held between verifications and a peak of %llu against a carry of %llu "
              "plus a plane of %lld (one buffer at a time, never the planes' sum)",
              (unsigned long long)st.verify_held, (unsigned long long)peak, (unsigned long long)carry,
              (long long)fst.st_size);
        /* a plane one byte past the loader's bound (2 GiB) is refused before a byte of buffer is taken */
        snprintf(big, sizeof big, "%s/.big", dir);
        fd = open(big, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        CHECK(fd >= 0 && ftruncate(fd, (off_t)0x80000000ll) == 0, "verification buffer: the sparse plane is not made");
        if (fd >= 0) {
            close(fd);
        }
        CHECK(chmod(big, 0444) == 0 && rename(big, file) == 0, "verification buffer: the sparse plane is not installed");
        pl_cycle(pl, 12u);
        we_mod_planes_status(pl, &st, now);
        CHECK(st.verify_peak == peak && st.verify_held == 0u && we_current(cfg.handle[0]) == cur,
              "verification buffer: a plane one byte past the bound moved the peak to %llu (was %llu) or displaced the armed map",
              (unsigned long long)st.verify_peak, (unsigned long long)peak);
    }
    we_mod_planes_release(pl);
    rm_tree(base);
}

/* the bind arguments' lifetime: legacy_file is copied, so the caller's string may be overwritten after the call */
/* ---- the transition lines (POLICY.md §2.5): the ring entry is the record and the logger's line is the entry ---- */
#define TR_MAX 24u
static char     g_tr[TR_MAX][WE_MOD_RING_ENTRY + 2048u];   /* every `plane ... out=` line the loop's logger got */
static unsigned g_ntr;

static void tr_logger(void *ud, const char *line)
{
    (void)ud;
    if (strncmp(line, "plane ", 6) == 0 && strstr(line, " out=") != NULL) {
        if (g_ntr < TR_MAX) {
            snprintf(g_tr[g_ntr], sizeof g_tr[g_ntr], "%s", line);
        }
        g_ntr++;
    }
}

static uint64_t tr_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void tr_cycle(we_mod_planes_t *pl, uint64_t tick)
{
    we_mod_planes_tick(pl, tick, NULL);
    we_mod_planes_apply(pl, tr_logger, NULL);
    we_mod_planes_tick(pl, tick, NULL);
}

/* a configuration built from directives and specs, its planes bound over dir, the worker started on tr_logger */
static int tr_bind(const char *dir, const we_policy_directive_t *d, size_t nd, const we_mod_ctx_spec_t *spec, size_t ns,
                   we_mod_arena_t **arena, we_policy_build_t **build, we_mod_cfg_t *cfg, we_mod_planes_t **pl,
                   const char *tag)
{
    we_policy_source_t src = { d, nd, NULL, 0 };
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    we_mod_ctx_t *x = NULL;
    uint32_t stride = 0u;
    char msg[512], why[512];
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;

    *build = NULL;
    *pl = NULL;
    *arena = we_mod_arena_new();
    memset(&e, 0, sizeof e);
    if (we_policy_build(&src, &env, NULL, build, &e, NULL) != WE_POLICY_OK) {
        CHECK(0, "transitions (%s): the policy is refused: %s", tag, e.what);
        return -1;
    }
    memset(cfg, 0, sizeof *cfg);
    if (we_mod_config_build(WE_MODULE_ABI_VERSION, *arena, *build, &src, spec, ns, 403u, cfg, &x, &stride, msg,
                            sizeof msg) != 0) {
        CHECK(0, "transitions (%s): the configuration is refused: %s", tag, msg);
        return -1;
    }
    args.data_dir = dir;
    args.read_mask = 0x03u;
    args.uid = (unsigned)geteuid();
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    if (we_mod_bind(cfg, &args, pl, why, sizeof why) != 0 || *pl == NULL) {
        CHECK(0, "transitions (%s): the binding is refused: %s", tag, why);
        return -1;
    }
    memset(&w, 0, sizeof w);
    w.interval_ms = 1000u;
    w.log = tr_logger;
    if (we_mod_worker_start(*pl, &w, why, sizeof why) != 0) {
        CHECK(0, "transitions (%s): the worker start is refused: %s", tag, why);
        return -1;
    }
    return 0;
}

static void tr_release(we_mod_planes_t *pl, we_mod_arena_t *a, we_policy_build_t *b)
{
    if (pl != NULL) {
        we_mod_planes_release(pl);
    }
    we_mod_arena_free(a);
    we_policy_build_free(b);
}

/*
 * The planes' transitions, as the modules reach them: we_mod_planes_apply() on the loop, the planes' single writer. On every
 * apply the bound planes' states are read; the first apply takes the baseline; a change writes one entry
 * per distinct program with a plane-dependent rule, the head `plane <P> <kind> out=<planes or ->
 * tenant=<state>` and then we_program_dependents_line()'s text, the first 511 bytes, into the status ring
 * and to the logger, byte for byte the same, an entry identical to one already written for the same
 * change written once; one summary entry when more than 16 programs are affected.
 */
static void t_transitions(void)
{
    static const char *const want_stale = "plane reputation stale out=reputation tenant=null: rule 1 disarmed";
    static const char *const want_back = "plane reputation armed out=- tenant=null: none";
    char base[256], dir[300];
    we_mod_cfg_t cfg;
    we_mod_planes_t *pl = NULL;
    we_mod_arena_t *a = NULL;
    we_policy_build_t *b = NULL;
    we_mod_status_t st;
    uint64_t far = 4102444800000ull, t0, t1;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);

    /* 1. three distinct programs: the floor and a server read the listed plane, a server reads the tor plane */
    snprintf(dir, sizeof dir, "%s/transitions", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, far, 0xC0000200u) == 0, "transitions: the first generation is not written");
    {
        we_policy_directive_t d[] = {
            D(WE_DIR_FLOOR, "http", "deny if listed >= high"),
            D(WE_DIR_POLICY, "http/s1", "log if listed >= low"),
            D(WE_DIR_POLICY, "http/s2", "deny if tor_exit"),
        };
        we_mod_ctx_spec_t spec[] = {
            { "http", "http", 0, 0, 0 }, { "http/s1", "server a", 0, 0, 0 }, { "http/s2", "server b", 0, 0, 0 },
        };

        if (tr_bind(dir, d, 3u, spec, 3u, &a, &b, &cfg, &pl, "three programs") != 0) {
            tr_release(pl, a, b);
            return;
        }
    }
    /* the baseline: the first apply reads the state and writes nothing */
    g_ntr = 0u;
    tr_cycle(pl, 1u);
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, tr_now_ms());
    CHECK(g_ntr == 0u && st.ntransitions == 0u, "transitions: the baseline wrote %u line(s), ring %u", g_ntr, st.ntransitions);
    /* a newer generation, still fresh: the state is what it was, nothing is written */
    t0 = tr_now_ms();
    CHECK(pl_write_rep(dir, "reputation.bin", 200u, t0 + 400u, 0xC0000200u) == 0, "transitions: the second generation is not written");
    tr_cycle(pl, 2u);
    CHECK(g_ntr == 0u, "transitions: a fresh re-arm wrote %u transition line(s): \"%s\"", g_ntr, g_ntr > 0u ? g_tr[0] : "");
    /* its valid-until passes: stale, out=reputation; the two programs reading it say their rule is disarmed,
     * the one reading tor says none is affected; the ring holds the same three entries */
    usleep(600000u);
    t0 = tr_now_ms();
    tr_cycle(pl, 3u);
    t1 = tr_now_ms();
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, t1);
    /* the program reading tor alone is untouched by the listed plane's change: no line (Q6: one line per
     * distinct program that has a dependent rule); the floor's and the first server's lines are the same
     * bytes (the line names no program), so they are ONE line: a second copy says nothing and reads as the
     * transition emitted twice */
    CHECK(g_ntr == 1u && strcmp(g_tr[0], want_stale) == 0,
          "transitions: the stale plane wrote %u line(s), not one: \"%s\" / \"%s\" / \"%s\"",
          g_ntr, g_ntr > 0u ? g_tr[0] : "", g_ntr > 1u ? g_tr[1] : "", g_ntr > 2u ? g_tr[2] : "");
    CHECK(st.ntransitions == 1u && strcmp(st.transition[0], want_stale) == 0
          && st.transition_ms[0] >= t0 && st.transition_ms[0] <= t1,
          "transitions: the status ring (%u entries, \"%s\", at %llu in [%llu, %llu]) is not the logger's lines", st.ntransitions,
          st.ntransitions > 0u ? st.transition[0] : "", (unsigned long long)st.transition_ms[0], (unsigned long long)t0,
          (unsigned long long)t1);
    /* the plane comes back: out=-, and the two programs the outage touched say none is affected now */
    g_ntr = 0u;
    CHECK(pl_write_rep(dir, "reputation.bin", 300u, far, 0xC0000200u) == 0, "transitions: the third generation is not written");
    tr_cycle(pl, 4u);
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, tr_now_ms());
    CHECK(g_ntr == 1u && strcmp(g_tr[0], want_back) == 0 && st.ntransitions == 2u && strcmp(st.transition[1], want_back) == 0,
          "transitions: the re-armed plane wrote %u line(s) (\"%s\"), ring %u (\"%s\")", g_ntr, g_ntr > 0u ? g_tr[0] : "",
          st.ntransitions, st.ntransitions > 1u ? st.transition[1] : "");
    tr_release(pl, a, b);
    pl = NULL;
    a = NULL;
    b = NULL;

    /* 1b. the inherited start: a worker gets its armed planes from the supervisor's binding with no apply of
     * its own, so its FIRST apply may already be the change. The baseline is the planes' state at the worker
     * start: a plane armed then and stale at the first apply is a transition, logged and in the ring. */
    snprintf(dir, sizeof dir, "%s/transitions-start", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    t0 = tr_now_ms();
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, t0 + 400u, 0xC0000200u) == 0, "transitions start: the plane is not written");
    {
        we_policy_directive_t d[] = { D(WE_DIR_FLOOR, "http", "deny if listed >= high") };
        we_mod_ctx_spec_t spec[] = { { "http", "http", 0, 0, 0 } };

        if (tr_bind(dir, d, 1u, spec, 1u, &a, &b, &cfg, &pl, "the inherited start") != 0) {
            tr_release(pl, a, b);
            return;
        }
        g_ntr = 0u;
        usleep(600000u);                         /* stale before the worker's first apply */
        tr_cycle(pl, 1u);
        memset(&st, 0, sizeof st);
        we_mod_planes_status(pl, &st, tr_now_ms());
        CHECK(g_ntr == 1u && strcmp(g_tr[0], want_stale) == 0 && st.ntransitions == 1u && strcmp(st.transition[0], want_stale) == 0,
              "transitions start: a plane armed at the worker start and stale at its first apply wrote %u line(s) (\"%s\"), "
              "ring %u: the change was taken as the baseline", g_ntr, g_ntr > 0u ? g_tr[0] : "", st.ntransitions);
        tr_release(pl, a, b);
        pl = NULL;
        a = NULL;
        b = NULL;
    }

    /* 2. the cut: a server program of 200 rules alternating allow and log on the listed plane (the floor
     * refuses allow); its uncut line runs past 511 bytes, the ring keeps the first 511 and a NUL, and the
     * logger gets that entry, never the uncut text; the floor's short line comes first */
    snprintf(dir, sizeof dir, "%s/transitions-cut", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    t0 = tr_now_ms();
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, t0 + 400u, 0xC0000200u) == 0, "transitions cut: the plane is not written");
    {
        static we_policy_directive_t d[201];
        static char big[4096];
        static const char head[] = "plane reputation stale out=reputation tenant=null";
        we_mod_ctx_spec_t spec[] = { { "http", "http", 0, 0, 0 }, { "http/s1", "server a", 0, 0, 0 } };
        size_t i;
        int rc;

        d[0] = D(WE_DIR_FLOOR, "http", "deny if listed >= high");
        for (i = 0u; i < 200u; i++) {
            d[i + 1u] = D(WE_DIR_POLICY, "http/s1", (i & 1u) == 0u ? "allow if listed >= low" : "log if listed >= low");
        }
        if (tr_bind(dir, d, 201u, spec, 2u, &a, &b, &cfg, &pl, "the cut") != 0) {
            tr_release(pl, a, b);
            return;
        }
        CHECK(we_mod_arena_blocks(a) == 2u && we_mod_arena_block(a, 0) == cfg.floor && we_mod_arena_block(a, 1) != NULL
              && we_mod_arena_block(a, 2) == NULL, "transitions cut: the arena does not hold the floor and the server's program");
        rc = we_program_dependents_line(we_mod_arena_block(a, 1), 0x01u, WE_TENANT_NULL, head, big, sizeof big);
        CHECK(rc > (int)WE_MOD_RING_ENTRY && strncmp(big, "plane reputation stale out=reputation tenant=null: rules 1,3,5,", 63) == 0
              && strstr(big, " allow captures; rules 2,4,6,") != NULL && strstr(big, ",200 disarmed") != NULL,
              "transitions cut: the uncut line is %d bytes: \"%.80s\"", rc, big);
        g_ntr = 0u;
        tr_cycle(pl, 1u);
        usleep(600000u);
        tr_cycle(pl, 2u);
        memset(&st, 0, sizeof st);
        we_mod_planes_status(pl, &st, tr_now_ms());
        CHECK(g_ntr == 2u && strcmp(g_tr[0], want_stale) == 0 && strlen(g_tr[1]) == WE_MOD_RING_ENTRY - 1u
              && memcmp(g_tr[1], big, WE_MOD_RING_ENTRY - 1u) == 0,
              "transitions cut: %u line(s); the server's is %zu bytes, not the first %u of the uncut line: \"%.80s\"", g_ntr,
              g_ntr > 1u ? strlen(g_tr[1]) : 0u, WE_MOD_RING_ENTRY - 1u, g_ntr > 1u ? g_tr[1] : "");
        CHECK(st.ntransitions == 2u && strlen(st.transition[1]) == WE_MOD_RING_ENTRY - 1u
              && memcmp(st.transition[1], big, WE_MOD_RING_ENTRY - 1u) == 0,
              "transitions cut: the ring's entry is %zu bytes: \"%.80s\"", st.ntransitions > 1u ? strlen(st.transition[1]) : 0u,
              st.ntransitions > 1u ? st.transition[1] : "");
        CHECK(g_ntr == 2u && st.ntransitions == 2u && strcmp(g_tr[0], st.transition[0]) == 0 && strcmp(g_tr[1], st.transition[1]) == 0,
              "transitions: the logger's line is not the ring's entry (%zu and %zu bytes)", g_ntr > 1u ? strlen(g_tr[1]) : 0u,
              st.ntransitions > 1u ? strlen(st.transition[1]) : 0u);
        tr_release(pl, a, b);
        pl = NULL;
        a = NULL;
        b = NULL;
    }

    /* 3. more than WE_MOD_TRANSITIONS programs affected: one summary entry, counted as one of the 16 */
    snprintf(dir, sizeof dir, "%s/transitions-many", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    t0 = tr_now_ms();
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, t0 + 400u, 0xC0000200u) == 0, "transitions many: the plane is not written");
    {
        static const char *const cc[17] = { "NL", "DE", "FR", "BE", "LU", "AT", "CH", "IT", "ES", "PT", "IE", "DK", "SE", "NO",
                                            "FI", "PL", "CZ" };
        static char ctx[17][16], rule[17][64];
        static we_policy_directive_t d[18];
        static we_mod_ctx_spec_t spec[18];
        size_t i;

        d[0] = D(WE_DIR_FLOOR, "http", "deny if listed >= high");
        spec[0].path = "http";
        spec[0].name = "http";
        for (i = 0u; i < 17u; i++) {
            snprintf(ctx[i], sizeof ctx[i], "http/c%02zu", i + 1u);
            snprintf(rule[i], sizeof rule[i], "deny if listed >= high and country in { %s }", cc[i]);
            d[i + 1u] = D(WE_DIR_POLICY, ctx[i], rule[i]);
            spec[i + 1u].path = ctx[i];
            spec[i + 1u].name = ctx[i];
        }
        if (tr_bind(dir, d, 18u, spec, 18u, &a, &b, &cfg, &pl, "eighteen programs") != 0) {
            tr_release(pl, a, b);
            return;
        }
        CHECK(we_mod_arena_blocks(a) == 18u, "transitions many: %u distinct programs, not 18", we_mod_arena_blocks(a));
        g_ntr = 0u;
        tr_cycle(pl, 1u);
        usleep(600000u);
        tr_cycle(pl, 2u);
        memset(&st, 0, sizeof st);
        we_mod_planes_status(pl, &st, tr_now_ms());
        CHECK(g_ntr == 1u && strcmp(g_tr[0], "plane reputation stale out=reputation tenant=null: 18 programs affected; "
                                             "whisper-edge-summary --status lists them") == 0
              && st.ntransitions == 1u && strcmp(st.transition[0], g_tr[0]) == 0,
              "transitions many: %u line(s) (\"%s\"), ring %u", g_ntr, g_ntr > 0u ? g_tr[0] : "", st.ntransitions);
        tr_release(pl, a, b);
    }
    rm_tree(base);
}

static void t_legacy_lifetime(void)
{
    char base[256], dir[300], why[512];
    static char legacy[400];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    const we_map_t *cur;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "legacy lifetime: no trusted base directory; the row did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/legacy", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "snapshot.bin", 1u, far, 0xC0000200u) == 0, "legacy lifetime: the snapshot is not written");
    snprintf(legacy, sizeof legacy, "%s/snapshot.bin", dir);
    memset(&cfg, 0, sizeof cfg);
    args.legacy_file = legacy;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL, "legacy lifetime: the binding is refused: %s",
          why);
    memset(legacy, 'X', sizeof legacy - 1u);     /* the caller's string gone: nothing the binding holds points at it */
    if (pl == NULL) {
        rm_tree(base);
        return;
    }
    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 1000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "legacy lifetime: the worker start is refused: %s", why);
    CHECK(pl_write_rep(dir, "snapshot.bin", 2u, far, 0xC0000300u) == 0, "legacy lifetime: the next snapshot is not written");
    pl_cycle(pl, 1u);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 2u,
          "legacy lifetime: with the caller's legacy_file overwritten the next snapshot did not arm (generation %llu)",
          cur != NULL ? (unsigned long long)cur->generation : 0ull);
    we_mod_planes_release(pl);
    rm_tree(base);
}

/*
 * The legacy snapshot (whisper_edge_snapshot) is served from a PRIVATE copy, never a mapping of the
 * file, so an in-place truncating rewrite of the file under a live reader (root's cp, curl -o, rsync
 * --inplace: every command an operator reaches for) cannot kill a worker with SIGBUS; the watch then
 * sees the drift and disarms. The read runs in a child, so a mapping that dies reports its signal by
 * name instead of taking the suite with it.
 */
static int t_legacy_truncate_read(const we_handle_t *h, uint32_t addr)
{
    const we_map_t *cur;
    pid_t pid;
    int st = 0;

    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        cur = we_current((we_handle_t *)h);
        _exit(cur == NULL ? 3 : we_find4(cur, addr) == WE_NO_RANGE ? 2 : 0);
    }
    if (pid < 0) {
        return -1;
    }
    waitpid(pid, &st, 0);
    return WIFSIGNALED(st) ? -WTERMSIG(st) : WEXITSTATUS(st);
}

static void t_legacy_truncate(void)
{
    char base[256], dir[300], legacy[400], why[512];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_worker_args_t w;
    we_mod_planes_t *pl = NULL;
    const we_map_t *cur;
    uint64_t far = 4102444800000ull, now = 1700000000000ull;
    int fd, rc;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "legacy truncate: no trusted base directory; the row did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/legacy-trunc", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "snapshot.bin", 1u, far, 0xC0000200u) == 0, "legacy truncate: the snapshot is not written");
    snprintf(legacy, sizeof legacy, "%s/snapshot.bin", dir);
    memset(&cfg, 0, sizeof cfg);
    args.legacy_file = legacy;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = now;
    args.high_water_file = "/nonexistent/high-water";
    CHECK(we_mod_bind(&cfg, &args, &pl, why, sizeof why) == 0 && pl != NULL, "legacy truncate: the binding is refused: %s", why);
    if (pl == NULL) {
        rm_tree(base);
        return;
    }
    memset(&w, 0, sizeof w);
    w.now_ms = now;
    w.interval_ms = 1000u;
    w.log = pl_logger;
    CHECK(we_mod_worker_start(pl, &w, why, sizeof why) == 0, "legacy truncate: the worker start is refused: %s", why);
    cur = we_current(cfg.handle[0]);
    CHECK(cur != NULL && cur->generation == 1u && we_find4(cur, 0xC0000201u) != WE_NO_RANGE,
          "legacy truncate: the snapshot did not arm before the rewrite");
    /* the rewrite in place: the inode the module holds, truncated to nothing, as root's cp or curl -o would
     * (root rewrites a 0444 inode; this suite runs unprivileged, so it loosens the mode first, to the 0644 the
     * legacy trust check admits, and the truncation itself is what the module must survive) */
    CHECK(chmod(legacy, 0644) == 0, "legacy truncate: the mode cannot be loosened for the rewrite (%s)", strerror(errno));
    fd = open(legacy, O_WRONLY | O_CLOEXEC);
    CHECK(fd >= 0 && ftruncate(fd, 0) == 0, "legacy truncate: the file cannot be truncated in place (%s)", strerror(errno));
    if (fd >= 0) {
        close(fd);
    }
    rc = t_legacy_truncate_read(cfg.handle[0], 0xC0000201u);
    CHECK(rc >= 0, "legacy truncate: the reader died of signal %d after the in-place truncation: the legacy file is "
          "served from a mapping of the file, not the private copy the legacy file is promised", -rc);
    CHECK(rc == 0, "legacy truncate: the reader still answers from the copy after the truncation (exit %d)", rc);
    /* the watch sees the drift on the next tick and disarms, as the transition table says */
    pl_log_reset();
    pl_cycle(pl, 1u);
    CHECK(pl_log_has("rewritten in place"), "legacy truncate: the next tick did not report the in-place rewrite");
    we_mod_planes_release(pl);
    rm_tree(base);
}

#ifdef WE_MOD_DEBUG
/*
 * The debug build's tail count (the truncate row, M3): a request whose judged address is in
 * WE_MOD_DEBUG_TAIL's range is counted before any plane is read, into a page the supervisor's bind mapped
 * shared, so a worker that counts a request and then dies on a truncated mapping (signal 7) leaves the
 * count behind for the lineage. Out of the range nothing is counted. The live status file prints it.
 * Run last: once armed, the counter stays armed for the process.
 */
static void t_debug_tail(void)
{
    char base[256], dir[300], file[400], why[512], buf[4096];
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    we_request_t r;
    uint64_t c0;
    int rc, fd, st = 0;
    pid_t kid;
    volatile const uint8_t *map;

    trusted_base(base, sizeof base);
    if (base[0] == '\0') {
        CHECK(0, "debug tail: no trusted base directory; the rows did not run");
        return;
    }
    mkdir(base, 0755);
    chmod(base, 0755);
    snprintf(dir, sizeof dir, "%s/tail", base);
    mkdir(dir, 0755);
    chmod(dir, 0755);
    CHECK(pl_write_rep(dir, "reputation.bin", 100u, 4102444800000ull, 0xC0000200u) == 0, "debug tail: no plane written");
    setenv("WE_MOD_DEBUG_TAIL", "198.51.100.0-198.51.100.255", 1);
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = dir;
    args.read_mask = 0x01u;
    args.uid = (unsigned)geteuid();
    args.now_ms = 1700000000000ull;
    args.high_water_file = "/nonexistent/high-water";
    args.log = pl_logger;
    rc = we_mod_bind(&cfg, &args, &pl, why, sizeof why);
    CHECK(rc == 0 && pl != NULL && we_mod_debug_tail_on(), "debug tail: the binding did not arm the count (rc %d): %s", rc, why);
    c0 = we_mod_debug_tail_count();
    memset(&r, 0, sizeof r);
    r.floor.family = 4u;
    r.floor.b[0] = 203u; r.floor.b[1] = 0u; r.floor.b[2] = 113u; r.floor.b[3] = 1u;
    we_mod_debug_tail_note(&r);
    CHECK(we_mod_debug_tail_count() == c0, "debug tail: an address outside the range was counted");
    r.floor.b[0] = 198u; r.floor.b[1] = 51u; r.floor.b[2] = 100u; r.floor.b[3] = 7u;
    we_mod_debug_tail_note(&r);
    CHECK(we_mod_debug_tail_count() == c0 + 1u, "debug tail: an address inside the range was not counted");

    /* a child counts its request, then touches a mapping truncated under it and dies of signal 7 */
    snprintf(file, sizeof file, "%s/truncated.bin", dir);
    memset(buf, 0x5a, sizeof buf);
    fd = open(file, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    map = NULL;
    if (fd >= 0 && write(fd, buf, sizeof buf) == (ssize_t)sizeof buf && write(fd, buf, sizeof buf) == (ssize_t)sizeof buf) {
        void *m = mmap(NULL, 8192u, PROT_READ, MAP_SHARED, fd, 0);

        map = m != MAP_FAILED ? (volatile const uint8_t *)m : NULL;
    }
    CHECK(map != NULL && ftruncate(fd, 0) == 0, "debug tail: the truncated mapping is not made");
    if (map != NULL) {
        kid = fork();
        if (kid == 0) {
            uint8_t x;

            we_mod_debug_tail_note(&r);
            x = map[4096];               /* the truncated tail: signal 7 */
            _exit(x == 0x5a ? 0 : 1);
        }
        waitpid(kid, &st, 0);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGBUS && we_mod_debug_tail_count() == c0 + 2u,
              "debug tail: a worker that counted its request and died of signal %d left %llu counted, not %llu",
              WIFSIGNALED(st) ? WTERMSIG(st) : 0, (unsigned long long)(we_mod_debug_tail_count() - c0),
              (unsigned long long)2u);
        munmap((void *)(uintptr_t)map, 8192u);
    }
    if (fd >= 0) {
        close(fd);
    }
    unlink(file);
    {
        static char out[8192];
        we_mod_text_t t = { out, 0u, sizeof out, 0 };
        we_mod_procid_t id;
        static we_mod_status_t s;
        char want[64];

        memset(&id, 0, sizeof id);
        memset(&s, 0, sizeof s);
        s.server = "nginx/1.24.0";
        we_mod_render_status(&t, &id, &s);
        snprintf(want, sizeof want, "\ndebug tail-requests %llu\n", (unsigned long long)we_mod_debug_tail_count());
        CHECK(!t.over && t.len < sizeof out && (out[t.len] = '\0', strstr(out, want) != NULL),
              "debug tail: the status file does not carry the count (want \"%s\")", want + 1);
    }
    unsetenv("WE_MOD_DEBUG_TAIL");
    if (pl != NULL) {
        we_mod_planes_release(pl);
    }
    unlink(file);
    snprintf(file, sizeof file, "%s/reputation.bin", dir);
    unlink(file);
    rmdir(dir);
    rmdir(base);                     /* the last row: the base it recreated goes too */
}
#endif

#if !defined(WE_MOD_CONTROL_BUILD) || defined(WE_MOD_TEST_FLAT_DEADLINE)
#include <pthread.h>

/*
 * The bounded stop (we_mod_thread_stop_bounded), the Apache module's five arms on the core's thread, at once:
 * a final write slower than one window but progressing (four 800 ms steps, each a mark) is waited for; one
 * held 3.5 s in one piece is waited for (it is the thread's own write, not a plane job); one held 8 s is
 * abandoned at the 6 s cap, naming the final write; and a plane job stuck after the stop with no progress
 * is abandoned at its 2 s window, naming the plane job. The fifth arm is the control build
 * WE_MOD_TEST_FLAT_DEADLINE, the stop before this rule, which loses the slow write.
 */
typedef struct {
    int              mode;               /* 1 slow and progressing, 2 held 3.5 s, 3 held 8 s, 4 a stuck plane job */
    we_mod_thread_t *t;
    int              rc;
    uint32_t         stage;
    uint64_t         ms;
} bs_arm_t;

static void bs_tick(void *ud, uint64_t tick, const int *stop)
{
    bs_arm_t *a = (bs_arm_t *)ud;

    (void)tick;
    if (a->mode == 4) {
        we_mod_thread_stage(WE_MOD_STAGE_PLANES);
        while (!__atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
            usleep(10000);
        }
        usleep(3000000);                 /* stuck, as a pread on a file system that stopped answering is */
    }
}

static void bs_final(void *ud, uint64_t tick, const int *stop)
{
    bs_arm_t *a = (bs_arm_t *)ud;
    int k;

    (void)tick;
    (void)stop;
    if (a->mode == 1) {
        for (k = 0; k < 4; k++) {
            usleep(800000);
            we_mod_thread_stage(WE_MOD_STAGE_FINAL);   /* a step done: progress */
        }
    } else if (a->mode == 2) {
        usleep(3500000);
    } else if (a->mode == 3) {
        usleep(8000000);
    }
}

static void *bs_stopper(void *arg)
{
    bs_arm_t *a = (bs_arm_t *)arg;
    uint64_t t0 = we_mod_monotonic_ms();

    a->rc = we_mod_thread_stop_bounded(a->t, &a->stage);
    a->ms = we_mod_monotonic_ms() - t0;
    return NULL;
}

static void t_bounded_stop(void)
{
    bs_arm_t arm[4];
    pthread_t st[4];
    char why[256];
    int i, started = 1;

    memset(arm, 0, sizeof arm);
    for (i = 0; i < 4; i++) {
        arm[i].mode = i + 1;
        if (we_mod_thread_start(&arm[i].t, 60000u, 60000u, bs_tick, bs_final, &arm[i], why, sizeof why) != 0) {
            started = 0;
        }
    }
    CHECK(started, "bounded stop: a thread did not start: %s", why);
    if (!started) {
        return;
    }
    usleep(200000);                      /* the first tick has run: the stuck arm sits in its plane job */
    for (i = 0; i < 4; i++) {
        pthread_create(&st[i], NULL, bs_stopper, &arm[i]);
    }
    for (i = 0; i < 4; i++) {
        pthread_join(st[i], NULL);
    }
    CHECK(arm[0].rc == 0, "bounded stop: a slow progressing final write was abandoned after %llu ms,%s",
          (unsigned long long)arm[0].ms, we_mod_stage_text(arm[0].stage));
    CHECK(arm[1].rc == 0 && arm[1].ms >= 3400u, "bounded stop: a final write held 3.5 s was not waited for (rc %d, %llu ms)",
          arm[1].rc, (unsigned long long)arm[1].ms);
    CHECK(arm[2].rc == 1 && arm[2].stage == WE_MOD_STAGE_FINAL && arm[2].ms >= WE_MOD_STOP_CAP_MS && arm[2].ms < 7900u,
          "bounded stop: a final write held 8 s was not abandoned at the 6 s cap naming it (rc %d, %llu ms,%s)",
          arm[2].rc, (unsigned long long)arm[2].ms, we_mod_stage_text(arm[2].stage));
    CHECK(arm[3].rc == 1 && arm[3].stage == WE_MOD_STAGE_PLANES && arm[3].ms >= WE_MOD_STOP_WINDOW_MS && arm[3].ms < 4000u,
          "bounded stop: a stuck plane job was not abandoned at its 2 s window naming it (rc %d, %llu ms,%s)",
          arm[3].rc, (unsigned long long)arm[3].ms, we_mod_stage_text(arm[3].stage));
    CHECK(strcmp(we_mod_stage_text(WE_MOD_STAGE_PLANES), " (the thread was in: a plane job)") == 0
          && strcmp(we_mod_stage_text(99u), " (the thread was in: a tick's own work)") == 0,
          "bounded stop: the stage words are not the abandonment line's");
}
#endif

static void t_isolation(const char *planes)
{
    fixture_t f;
    char err[256];
    we_policy_directive_t d[] = {
        D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
        D(WE_DIR_FLOOR, "http", "log if listed >= low"),
        D(WE_DIR_POLICY, "http/s1", "log if country == AF"),
        D(WE_DIR_POLICY, "http/s1", "deny if listed >= medium"),
    };

    err[0] = '\0';
    if (wc_build(err, sizeof err) != 0 ||
            fixture_make(&f, planes, d, sizeof d / sizeof d[0], 0u, 1700000000000ull) != 0) {
        CHECK(0, "isolation: the fixture is refused: %s", err);
        return;
    }
    {
        static we_mod_scratch_t s;
        static uint64_t shard[SHARD_N];
        static uint8_t raw[WE_MOD_RECORD_ALLOC];

        /* the classes reach what the rows claim: the parse loop judges header entries, the lazy fill holds */
        g_wc_judged = g_wc_lazy = g_wc_aliased = g_wc_exempt = g_wc_acme = g_wc_acme_exempt = 0u;
        (void)cold_and_hot(&f, &s, shard, we_mod_record_at(raw));
        CHECK(g_wc_judged >= 12u && g_wc_lazy == 2u * WE_WALK_CLASSES + 6u && g_wc_aliased >= WE_WALK_CLASSES - 2u
              && g_wc_acme == 2u && g_wc_acme_exempt == 2u,
              "isolation: over the %u classes the walk judged %u, the lazy fill held %u of %u, %u ran aliased, the ACME "
              "matcher accepted %u of 6 and the decision took %u of them as exempt (want at least 12, all, at least %u, "
              "2, 2)", (unsigned)WE_WALK_CLASSES, g_wc_judged, g_wc_lazy, 2u * WE_WALK_CLASSES + 6u, g_wc_aliased,
              g_wc_acme, g_wc_acme_exempt, (unsigned)WE_WALK_CLASSES - 2u);
    }
    run_isolated("V2 (seccomp: any system call kills)", &f, 1);
#if WE_TEST_ALLOC_TRAP
    run_isolated("N2 (malloc, calloc, realloc and free abort)", &f, 2);
#endif
    fixture_free(&f);
}

/* E1: the decision and the record under memcheck, the scratch and the record marked undefined first */
static int memcheck_mode(const char *planes)
{
    fixture_t f;
    char err[256];
    static we_mod_scratch_t s;
    static uint64_t shard[SHARD_N];
    static uint8_t raw[WE_MOD_RECORD_ALLOC];
    we_mod_record_t *rec = we_mod_record_at(raw);
    we_policy_directive_t d[] = {
        D(WE_DIR_FLOOR, "http", "deny if tor_exit"),
        D(WE_DIR_FLOOR, "http", "log if listed >= low"),
        D(WE_DIR_POLICY, "http/s1", "log if country == AF"),
        D(WE_DIR_POLICY, "http/s1", "deny if listed >= medium"),
    };
    uint32_t i, sum = 0u;

    if (wc_build(err, sizeof err) != 0 ||
            fixture_make(&f, planes, d, sizeof d / sizeof d[0], 0u, 1700000000000ull) != 0) {
        printf("memcheck: the fixture is refused\n");
        return 2;
    }
    VALGRIND_MAKE_MEM_UNDEFINED(&s, sizeof s);
    VALGRIND_MAKE_MEM_UNDEFINED(rec, sizeof *rec);
    sum = cold_and_hot(&f, &s, shard, rec);
    /* every byte the verdict carries is used, so memcheck sees any that the decision left undefined; every
     * rendered byte is in the sum already */
    for (i = 0u; i < 80u; i++) {
        sum += ((const uint8_t *)&s.v)[i];
    }
    printf("memcheck: the decision, the record, the lazy fill and every renderer ran over the walk corpus's %u "
           "input classes (%u)\n", (unsigned)WE_WALK_CLASSES, sum != 0u ? 1u : 0u);
    fixture_free(&f);
    return 0;
}

#ifdef WE_MOD_TEST_INTERLEAVE
/*
 * N2's interleave arm: the counter's relaxed load and store with a barrier between them. Two writers on ONE
 * shard, the second's increment landing inside the first's window k times, lose exactly k counts: the
 * reason every thread counts into a shard of its own and the summing happens on the tick.
 */
#include <pthread.h>
#include <semaphore.h>
static sem_t g_il_go, g_il_done;
static __thread int g_il_first;
static int g_il_left;
static uint64_t g_il_shard[1];

void we_mod_test_interleave(void)
{
    if (g_il_first && g_il_left > 0) {
        g_il_left--;
        sem_post(&g_il_go);                  /* the second writer increments inside this window */
        sem_wait(&g_il_done);
    }
}

static void *il_second(void *arg)
{
    uint32_t i, k = *(const uint32_t *)arg;

    for (i = 0u; i < k; i++) {
        sem_wait(&g_il_go);
        we_mod_count(g_il_shard, 0u);
        sem_post(&g_il_done);
    }
    return NULL;
}

static int interleave_mode(void)
{
    pthread_t t;
    uint32_t i, n = 100u, k = 4u;

    sem_init(&g_il_go, 0, 0);
    sem_init(&g_il_done, 0, 0);
    g_il_left = (int)k;
    pthread_create(&t, NULL, il_second, &k);
    g_il_first = 1;
    for (i = 0u; i < n; i++) {
        we_mod_count(g_il_shard, 0u);
    }
    pthread_join(t, NULL);
    printf("interleave: %u + %u increments on one shard counted %llu: %llu lost, exactly the %u interleaved\n", n, k,
           (unsigned long long)g_il_shard[0], (unsigned long long)(n + k - g_il_shard[0]), k);
    return g_il_shard[0] == n ? 0 : 1;
}
#endif

#ifdef WE_MOD_TEST_EUID0
/*
 * The root refusal's typed return (the seam build reads its euid as 0): a counters directory that is not
 * root-owned and closed is refused with WE_ERR_PERMISSIONS, nothing is written, and the reason says why;
 * any other failure is WE_ERR_OPEN, so a caller can say the permission sentence once and stay quiet.
 */
static int root_refusal_mode(const char *tmpdir)
{
    char dir[1100], why[256];
    we_mod_procid_t id;
    int dfd, rc;
    DIR *d;
    struct dirent *e;
    unsigned left = 0u;

    snprintf(dir, sizeof dir, "%s/root-refusal.%ld", tmpdir, (long)getpid());
    if (mkdir(dir, 0775) != 0 || chmod(dir, 0775) != 0 || (dfd = open(dir, O_RDONLY | O_DIRECTORY)) < 0) {
        printf("FAIL root refusal: the fixture directory cannot be made\n1 checks, 1 failures\n");
        return 1;
    }
    memset(&id, 0, sizeof id);
    id.pid = (uint64_t)getpid();
    id.starttime = 1u;
    rc = we_mod_write_file(dfd, &id, "status", "a.status", "x\n", 2u, why, sizeof why);
    d = opendir(dir);
    while (d != NULL && (e = readdir(d)) != NULL) {
        left += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
    }
    if (d != NULL) {
        closedir(d);
    }
    close(dfd);
    rm_tree(dir);
    if (rc != WE_ERR_PERMISSIONS || left != 0u || strstr(why, "runs as root") == NULL) {
        printf("FAIL root refusal: rc %d (want WE_ERR_PERMISSIONS %d), %u files written, reason \"%s\"\n"
               "1 checks, 1 failures\n", rc, WE_ERR_PERMISSIONS, left, why);
        return 1;
    }
    printf("ok   root refusal: WE_ERR_PERMISSIONS, nothing written: %s\n1 checks, 0 failures\n", why);
    return 0;
}
#endif

int main(int argc, char **argv)
{
    char planes[1024];

    if (argc < 2) {
        fprintf(stderr, "usage: test_module <tmpdir> [<planes dir>] | test_module --module-cases <file>\n");
        return 2;
    }
    if (strcmp(argv[1], "--module-cases") == 0) {
        return argc > 2 ? module_cases(argv[2]) : 2;
    }
#ifdef WE_MOD_TEST_EUID0
    if (strcmp(argv[1], "--root-refusal") == 0) {
        return argc > 2 ? root_refusal_mode(argv[2]) : 2;
    }
#endif
    if (strcmp(argv[1], "--memcheck") == 0) {
        return argc > 2 ? memcheck_mode(argv[2]) : 2;
    }
#ifdef WE_MOD_TEST_INTERLEAVE
    if (strcmp(argv[1], "--interleave") == 0) {
        return interleave_mode();
    }
#endif
    g_tmpdir = argv[1];
    if (argc > 2) {
        snprintf(planes, sizeof planes, "%s", argv[2]);
    } else {
        snprintf(planes, sizeof planes, "%s/fuzz/planes", argv[1]);
    }
    {
        char probe[1100];
        struct stat pst;

        snprintf(probe, sizeof probe, "%s/reputation.bin", planes);
        if (stat(probe, &pst) != 0) {
            /* refused, never skipped: the rows that need the planes cannot pass without them */
            printf("FAIL fixture: %s holds no fixture planes; run `make fuzz-planes` (make check does) and run "
                   "test_module again\n", planes);
            printf("1 checks, 1 failures\n");
            return 1;
        }
    }
    t_layout();
    t_decide(planes);
    t_walk();
    t_trust_build();
    t_entry();
    t_format();
    t_acme();
    t_word_lengths();
    t_render();
    t_record();
    t_record_write(planes);
    t_config();
    t_config_spec();
    t_config_cap();
    t_binding(planes);
    t_writers(argv[1]);
    t_publication();
    t_lists();
    t_thread();
    t_digest();
    t_walk_cap();
    t_walk_lines();
    t_severity();
    t_netfs();
    t_ownership(planes);
    t_scratch_reuse(planes);
    t_planes();
    t_planes_unreadable();
    t_planes_noreason();
    t_plane_file();
    t_bind_refused();
    t_plane_refused();
    t_bind_check();
    t_bind_paths();
    t_policy_replace();
    t_planes_snapshot_unfilled();
    t_start_truncate();
#ifdef WE_MOD_TEST_PAUSE_TICK
    t_pause_tick();
#endif
    t_planes_tenant();
    t_high_water();
    t_legacy_owner();
    t_digest_progress();
    t_spsc_rule();
    t_fail_identity();
    t_digest_counts();
    t_planes_repointed();
    t_planes_monitor();
    t_transitions();
    t_retire_bound();
    t_legacy_lifetime();
    t_legacy_truncate();
    t_isolation(planes);
#if !defined(WE_MOD_CONTROL_BUILD) || defined(WE_MOD_TEST_FLAT_DEADLINE)
    t_bounded_stop();
#endif
#ifdef WE_MOD_DEBUG
    t_debug_tail();
#endif
    {
        struct stat lst;

        /* every lifecycle row removed what it made */
        CHECK(g_base_used[0] == '\0' || lstat(g_base_used, &lst) != 0,
              "lifecycle: %s was left behind by a row", g_base_used);
    }
    printf("%u checks, %u failures\n", g_checks, g_failures);
    return g_failures == 0u ? 0 : 1;
}
