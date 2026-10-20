/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * cg_driver.c - the lookups and the policy evaluator cachegrind-gate.sh measures.
 *
 * Two builds of one file, each optionally with the policy evaluator (-DWE_HAVE_EVAL, which the gate
 * defines exactly when we_eval.h is in the tree):
 *
 *   plain       cg_driver <dir> cg <slot> <u|d|q|e> <count>
 *               Runs <count> lookups (or requests) of one slot between CACHEGRIND_START_INSTRUMENTATION
 *               and CACHEGRIND_STOP_INSTRUMENTATION, so valgrind --tool=cachegrind --instr-at-start=no
 *               counts them and nothing of the setup.
 *               cg_driver <dir> slots
 *               Prints the evaluator slot table: name, requests, and the count vectors the cost model
 *               needs. Plain data, so it works without the evaluator too.
 *               cg_driver <dir> verdicts <slot> <n>
 *               The first n verdicts of an evaluator slot, for the verify-before-measure comparison.
 *
 *   -DWE_TRACE  cg_driver <dir> residency <config> <l2 bytes> <l2 ways> <llc bytes> <llc ways> <line> <count>
 *               whisper_edge.h's WE_TRACE_READ hook (and the evaluator's WE_TRACE_EVAL) feeds every read
 *               to an LRU set-associative model, and the run reports index misses after one sequential
 *               sweep of the indexes (see residency() below); cachegrind-gate.sh judges them.
 *
 * The slots:
 *   plane-v4-radix18   the shipped format-2 lookup (we_find4) on IPv4 at radix-18          (stream u, d)
 *   plane-v6-rank64s   the shipped format-2 lookup (we_find6_64) on IPv6 at 64-bit keys    (stream u, d)
 *   shipped-v4         the format-1 we_lookup4 (radix-16, start/end/sev columns) on IPv4   (stream u, d)
 *   shipped-v6         the shipped we_lookup6 on IPv6, its 64-bit bounds widened to 128    (stream u, d)
 *   lookup-<plane>@q4, lookup-<plane>@q6
 *                      the bare find on each of the default policy's planes, over the default slot's
 *                      own named streams                                                   (stream q)
 *   lookup-hh@16, lookup-hh@4
 *                      the hold-harmless table at stride 16 (IPv4) and 4 (IPv6), at its costliest
 *                      class                                                               (stream q)
 *   lookup-<plane>@basis, lookup-hh@basis
 *                      the bare find on each plane of the evaluator's world, at its two addresses (q)
 *   evaluator-*        the policy evaluator's rows; EMPTY (exit 3) in a build without it, never a
 *                      number                                                              (stream e)
 * The two plane slots are the chosen kinds for the routing plane (FORMAT.md §4), on the format-2 lookup in
 * whisper_edge.h; the shipped-v4/v6 slots are the same functions reading a format-1 view.
 *
 * <dir> holds v4.start, v4.rec16, v6.start and v6.rec24 as bench/build7.py writes them; the streams
 * are bench/lay7.c's: xorshift64, seed 0x9e3779b97f4a7c15, uniform over IPv4 and 2000::/3, and dense
 * (a random range, then a random address in it). Every array is 4096-byte aligned (xalloc), and so is
 * every static the measured loops read (the map descriptors, WE_CG_PAGE), so a 32 KiB 8-way D1, whose set
 * index lies inside the page offset, sees the same sets on every run whatever the rest of the link
 * places beside them (the launch probe's geometry; the rows' own D1 is fully associative, because the
 * module renderers' strings, compiled in here and linked last, still move with the core's sizes). That is CHECKED, not assumed: `align` mode (and every measuring mode, first)
 * refuses with NOT PROVEN when one of them sits off a page boundary, and the gate builds a planted
 * misalignment (WE_CG_PLANT_MISALIGN) that must be refused. Before anything is measured each slot's
 * answers are checked against a plain binary search; a lookup that is wrong is not timed.
 */
#define _GNU_SOURCE
/*
 * This driver, and nothing else, may carry the memo mutant in a build without WE_TRACE: C2 measures
 * WE_TEST_NO_MEMO_HIT on evaluator-default, and we_eval.h refuses every WE_TEST_* mutant outside
 * test_policy's traced build unless WE_CG_DRIVER is defined. Defined here, in the source, so no other
 * translation unit can claim the exception by a -D; cachegrind-gate.sh shows one cannot.
 */
#define WE_CG_DRIVER 1
/* every file-scope static starts a page of its own: its D1 sets cannot move with the link */
#define WE_CG_PAGE __attribute__((aligned(4096)))
/*
 * The layout the D1 rows were measured on: 3 since the gate links this unit LAST, after the core and the
 * evaluator, so neither this driver's statics nor their alignment can move a table of the code it measures
 * (layout 2 linked it first: aligning two of its strings, read by no measured loop, shifted the core's
 * read-only tables and moved every evaluator row's D1 from 1.2 to 7.1 misses a request). A baseline written
 * on an older layout is another measurement; the gate reads it NOT PROVEN until it is rewritten. 4 since the
 * rows' D1 is fully associative: linked last, this unit's own strings and tables, the module
 * renderers' among them, still moved with every size change in the core, and an 8-way D1 read that move as
 * the code's; a fully associative one counts the footprint alone.
 */
#define WE_CG_LAYOUT 4

/* C2's build: the memo mutant in this unit ONLY, where we_eval.h inlines the evaluator the driver
 * measures; the gate passes -DWE_CG_NOMEMO, so we_policy.c, built in the same command, never sees it */
#ifdef WE_CG_NOMEMO
#define WE_TEST_NO_MEMO_HIT 1
#endif
/* the data-refs row's source-level control: one more load in every rule, where the evaluator offers it */
#ifdef WE_CG_EXTRALOAD
#define WE_TEST_EXTRA_LOAD 1
#endif
/*
 * The module rows' controls, each mapped from a -DWE_CG_* the gate passes to this unit alone: the
 * all-views read (C1+, judged on data reads), the locked counter increment (C7), the local context
 * rebuilt per lazily filled plane (C2+, judged on data writes), the linear country scan (the country
 * class) and every attribute rendered on the default export path. we_module.h admits WE_TEST_MOD_ALL_VIEWS
 * only where WE_CG_DRIVER is defined, and the others only in a declared control build.
 */
#ifdef WE_CG_ALLVIEWS
#define WE_TEST_MOD_ALL_VIEWS 1
#endif
#ifdef WE_CG_MODWORK
#define WE_TEST_MOD_PRESTAGE_WORK 1
#endif
#if defined(WE_CG_LOCKCOUNT) || defined(WE_CG_LAZY_PER_PLANE) || defined(WE_CG_COUNTRY_SCAN) || defined(WE_CG_EAGER_EXPORT)
#define WE_MOD_CONTROL_BUILD 1
#endif
#ifdef WE_CG_LOCKCOUNT
#define WE_MOD_TEST_LOCKED_COUNT 1
#endif
#ifdef WE_CG_LAZY_PER_PLANE
#define WE_MOD_TEST_LAZY_PER_PLANE 1
#endif
#ifdef WE_CG_COUNTRY_SCAN
#define WE_MOD_TEST_COUNTRY_SCAN 1
#endif
#ifdef WE_CG_EAGER_EXPORT
#define WE_MOD_TEST_EAGER_EXPORT 1
#endif
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <unistd.h>

#include "whisper_edge.h"
#include "we_writer.h"

#ifndef WE_TRACE
#include <valgrind/cachegrind.h>
#endif

#define SEED 0x9e3779b97f4a7c15ull

static uint64_t rs WE_CG_PAGE = SEED;
static uint64_t rnd(void)
{
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return rs;
}

static void *xalloc(size_t bytes)
{
    void *p = aligned_alloc(4096, (bytes + 4095u) & ~(size_t)4095u);
    if (p == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    memset(p, 0, (bytes + 4095u) & ~(size_t)4095u);
    return p;
}

/*
 * A plane file this driver writes into the data directory, written beside its name and renamed over it,
 * so a run that opens it sees the old file or the new one, never one half written. The gate's layout and
 * conflict rows run drivers at once (WE_CG_JOBS), two gates on one host share the directory, and every
 * driver writes the same bytes from the pinned seed: before this, one run's truncating write met another's
 * open, which read "snapshot length disagrees with its header" (measured, aarch64, under 6 jobs).
 */
static int cg_write_plane(const char *path, const ww_plane_t *p)
{
    char tmp[1300];

    snprintf(tmp, sizeof tmp, "%s.%ld.tmp", path, (long)getpid());
    if (ww_write(tmp, p) != 0) { (void)remove(tmp); return -1; }
    if (rename(tmp, path) != 0) { (void)remove(tmp); return -1; }
    return 0;
}

static void *slurp(const char *dir, const char *name, size_t *len)
{
    char path[1024];
    FILE *f;
    void *b;
    long l;

    snprintf(path, sizeof path, "%s/%s", dir, name);
    f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        exit(2);
    }
    if (fseek(f, 0, SEEK_END) != 0 || (l = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        perror(path);
        exit(2);
    }
    *len = (size_t)l;
    b = xalloc(*len);
    if (fread(b, 1, *len, f) != *len) {
        perror(path);
        exit(2);
    }
    fclose(f);
    return b;
}

/* ---- the data ---------------------------------------------------------------------------------- */
static uint32_t n4 WE_CG_PAGE, n6 WE_CG_PAGE;
static uint32_t *st4 WE_CG_PAGE;           /* v4 starts */
static uint8_t  *rec4 WE_CG_PAGE;          /* v4 records, 16 bytes, end at offset 0 */
static uint64_t *st6 WE_CG_PAGE;           /* v6 starts, 64-bit keys */
static uint8_t  *rec6 WE_CG_PAGE;          /* v6 records, 24 bytes, end at offset 0 */

static uint32_t end4(uint32_t i) { uint32_t e; memcpy(&e, rec4 + (size_t)i * 16u, 4); return e; }
static uint64_t end6(uint32_t i) { uint64_t e; memcpy(&e, rec6 + (size_t)i * 24u, 8); return e; }

static void load(const char *dir)
{
    size_t l, r;
    st4 = slurp(dir, "v4.start", &l);
    rec4 = slurp(dir, "v4.rec16", &r);
    n4 = (uint32_t)(l / 4u);
    if (r != (size_t)n4 * 16u) { fprintf(stderr, "v4.rec16 does not match v4.start\n"); exit(2); }
    st6 = slurp(dir, "v6.start", &l);
    rec6 = slurp(dir, "v6.rec24", &r);
    n6 = (uint32_t)(l / 8u);
    if (r != (size_t)n6 * 24u) { fprintf(stderr, "v6.rec24 does not match v6.start\n"); exit(2); }
}

#ifndef WE_TRACE
/* reference: i + 1 for the covering range, 0 for none */
static uint32_t ref4(uint32_t a)
{
    uint32_t lo = 0, hi = n4;
    while (lo < hi) { uint32_t m = lo + ((hi - lo) >> 1); if (st4[m] <= a) { lo = m + 1u; } else { hi = m; } }
    return lo != 0u && a <= end4(lo - 1u) ? lo : 0u;
}

static uint32_t ref6(uint64_t a)
{
    uint32_t lo = 0, hi = n6;
    while (lo < hi) { uint32_t m = lo + ((hi - lo) >> 1); if (st6[m] <= a) { lo = m + 1u; } else { hi = m; } }
    return lo != 0u && a <= end6(lo - 1u) ? lo : 0u;
}
#endif

/* ---- the structures ---------------------------------------------------------------------------- */
/*
 * The mappings are built in memory as the loader would describe them (we_fam_t, FORMAT.md section 4),
 * because the inputs are the real routing table and no writer in this tree turns it into a plane file.
 * The verify() pass below is what makes that safe: a view built wrongly gives wrong answers there and
 * is never measured.
 */
static we_map_t mp WE_CG_PAGE;    /* format 2: f4 radix-18 over 16-byte records, f6w rank-64s over 24 */
static we_map_t ship WE_CG_PAGE;  /* format 1: f4 and f6 radix-16 over start[], end[] and sev[] */
static size_t p4_index_bytes WE_CG_PAGE, p6_index_bytes WE_CG_PAGE;

static uint32_t *radix_index32(const uint32_t *st, uint32_t n, unsigned k)
{
    uint32_t *ix = xalloc((((size_t)1 << k) + 1u) * 4u);
    uint32_t cur = 0;
    uint64_t b;
    for (b = 0; b <= ((uint64_t)1 << k); b++) {
        while (cur < n && ((uint64_t)st[cur] >> (32u - k)) < b) { cur++; }
        ix[b] = cur;
    }
    return ix;
}

static void build_plane4(void)
{
    const unsigned k = 18;
    we_fam_t *f = &mp.f4;
    f->first = st4[0];
    f->start = (const uint8_t *)st4;
    f->end = rec4;
    f->records = rec4;
    f->idx = radix_index32(st4, n4, k);
    f->n = n4;
    f->stride = 16;
    f->kind = WE_KIND_RADIX;
    f->shift = (uint8_t)(32u - k);
    f->key_bits = 32;
    f->file_kind = WE_KIND_RADIX;
    f->file_param = (uint8_t)k;
    p4_index_bytes = (((size_t)1 << k) + 1u) * 4u;
}

/*
 * Rank-64s for 64-bit keys (FORMAT.md section 4.2): the separators start[j*64], j in [1, m), as a
 * complete 9-ary tree of 64-byte nodes in level order, 8 keys per node, maximum-key padding. Key i of
 * the node at position P of level l is separator (P * 9 + i + 1) * 9^(d - 1 - l), which is what makes
 * the per-level counts read as base-9 digits of the window index. d is the smallest with 9^d >= m.
 */
static void build_plane6(void)
{
    const uint32_t s = 64, B = 8, F = 9;
    uint32_t m = (n6 + s - 1u) / s, d = 0, l, P, i;
    uint64_t pw = 1, nodes = 0, off[16], levelw[16];
    uint64_t *tree;
    we_fam_t *f = &mp.f6w;

    while (pw < m) { pw *= F; d++; }
    pw = 1;
    for (l = 0; l < d; l++) { off[l] = nodes; levelw[l] = pw; nodes += pw; pw *= F; }
    tree = xalloc((size_t)nodes * 64u);
    for (l = 0; l < d; l++) {
        uint64_t below = 1;
        uint32_t q;
        for (q = l + 1u; q < d; q++) { below *= F; }
        for (P = 0; P < levelw[l]; P++) {
            for (i = 0; i < B; i++) {
                uint64_t w = ((uint64_t)P * F + i + 1u) * below;
                tree[(off[l] + P) * B + i] = w < m ? st6[w * s] : UINT64_MAX;
            }
        }
    }
    f->first = st6[0];
    f->start = (const uint8_t *)st6;
    f->end = rec6;
    f->records = rec6;
    f->stree = (const uint8_t *)tree;
    f->n = n6;
    f->m = m;
    f->stride = 24;
    f->nodes = (uint32_t)nodes;
    f->span = s;
    f->kind = WE_KIND_RANK;
    f->depth = (uint8_t)d;
    f->sshift = 6;
    f->key_bits = 64;
    f->file_kind = WE_KIND_RANK;
    f->file_param = 6;
    p6_index_bytes = (size_t)nodes * 64u;
}

/* The format-1 view: radix-16 index, start[], end[] and sev[] columns; IPv6 widened to 128 bits. */
static void build_shipped(void)
{
    uint32_t i, *end = xalloc((size_t)n4 * 4u);
    uint8_t *sev4 = xalloc(n4), *sev6 = xalloc(n6);
    __uint128_t *s6 = xalloc((size_t)n6 * 16u), *e6 = xalloc((size_t)n6 * 16u);
    uint32_t *ix6 = xalloc(65537u * 4u), cur = 0;
    uint64_t b;

    for (i = 0; i < n4; i++) { end[i] = end4(i); sev4[i] = WE_SEV_LOW; }
    ship.f4.first = st4[0];
    ship.f4.start = (const uint8_t *)st4;
    ship.f4.end = (const uint8_t *)end;
    ship.f4.sev = sev4;
    ship.f4.idx = radix_index32(st4, n4, 16);
    ship.f4.n = n4;
    ship.f4.stride = 4;
    ship.f4.kind = WE_KIND_RADIX;
    ship.f4.shift = 16;
    ship.f4.key_bits = 32;
    ship.f4.file_kind = WE_KIND_RADIX;
    ship.f4.file_param = 16;

    for (i = 0; i < n6; i++) {
        s6[i] = (__uint128_t)st6[i] << 64;
        e6[i] = ((__uint128_t)end6(i) << 64) | (__uint128_t)UINT64_MAX;
        sev6[i] = WE_SEV_LOW;
    }
    for (b = 0; b <= 65536u; b++) {
        while (cur < n6 && (st6[cur] >> 48) < b) { cur++; }
        ix6[b] = cur;
    }
    ship.f6.first = s6[0];
    ship.f6.start = (const uint8_t *)s6;
    ship.f6.end = (const uint8_t *)e6;
    ship.f6.sev = sev6;
    ship.f6.idx = ix6;
    ship.f6.n = n6;
    ship.f6.stride = 16;
    ship.f6.kind = WE_KIND_RADIX;
    ship.f6.shift = 63u - 16u;
    ship.f6.key_bits = 128;
    ship.f6.file_kind = WE_KIND_RADIX;
    ship.f6.file_param = 16;
    ship.format = 1;
    ship.v4_index = ship.f4.idx;
    ship.v4_start = st4;
    ship.v4_end = end;
    ship.v4_sev = sev4;
    ship.v4_count = n4;
    ship.v6_index = ix6;
    ship.v6_start = s6;
    ship.v6_end = e6;
    ship.v6_sev = sev6;
    ship.v6_count = n6;
    mp.format = 2;
}

/* ---- the streams ------------------------------------------------------------------------------- */
static uint32_t *u4 WE_CG_PAGE, *d4 WE_CG_PAGE;
static uint64_t *u6 WE_CG_PAGE, *d6 WE_CG_PAGE;
static uint8_t (*u6b)[16] WE_CG_PAGE, (*d6b)[16] WE_CG_PAGE;   /* the same IPv6 keys as network-order addresses */

static void to_bytes(uint64_t k, uint8_t out[16])
{
    int i;
    for (i = 0; i < 8; i++) { out[i] = (uint8_t)(k >> (56 - 8 * i)); out[8 + i] = 0; }
}

static void streams(uint32_t count)
{
    const uint64_t lo6 = 0x2000ull << 48, hi6 = (0x4000ull << 48) - 1u;
    uint32_t k;
    u4 = xalloc((size_t)count * 4u); d4 = xalloc((size_t)count * 4u);
    u6 = xalloc((size_t)count * 8u); d6 = xalloc((size_t)count * 8u);
    u6b = xalloc((size_t)count * 16u); d6b = xalloc((size_t)count * 16u);
    for (k = 0; k < count; k++) {
        uint32_t i;
        uint64_t w;
        u4[k] = (uint32_t)rnd();
        i = (uint32_t)(rnd() % n4);
        w = (uint64_t)(end4(i) - st4[i]) + 1u;
        d4[k] = st4[i] + (uint32_t)(rnd() % w);
        u6[k] = lo6 + rnd() % (hi6 - lo6 + 1u);
        i = (uint32_t)(rnd() % n6);
        w = end6(i) - st6[i] + 1u;
        d6[k] = st6[i] + (w != 0u ? rnd() % w : rnd());
        to_bytes(u6[k], u6b[k]);
        to_bytes(d6[k], d6b[k]);
    }
}

/* ---- the wrappers: what is measured ----------------------------------------------------------- */
/*
 * Each starts a 64-byte line of its own. The compiler pads a loop inside a function to its alignment
 * with nops that execute on every iteration, and how many it needs follows the function's start
 * address, which the layout of the whole object decides: when the module rows were added, gcc 13.3 put
 * one more nop into cg_plane4's hold-harmless path and lookup-hh@16 read 111.00 against its committed
 * 110.00, with the lookup's own code unchanged. Pinned, the padding is the wrapper's own, whatever else
 * this file grows.
 */
#define CG_WRAPPER __attribute__((noinline, aligned(64)))
CG_WRAPPER uint32_t cg_plane4(const we_map_t *m, uint32_t a) { return we_find4(m, a); }
CG_WRAPPER uint32_t cg_plane6(const we_map_t *m, const uint8_t *a) { return we_find6_64(m, a); }
CG_WRAPPER uint8_t cg_ship4(const we_map_t *m, uint32_t a) { return we_lookup4(m, a); }
CG_WRAPPER uint8_t cg_ship6(const we_map_t *m, const uint8_t *a) { return we_lookup6(m, a); }
CG_WRAPPER uint32_t cg_find6(const we_map_t *m, const uint8_t *a) { return we_find6(m, a); }

/* ---- the default policy's planes, live-shaped ---------------------------------------------------- */
/*
 * The planes decision 3's default policy reads, at the counts the builder's manifests carry (POLICY.md
 * section 6): reputation, the keyless plane's shape on the last build, 971 IPv4 and 27 IPv6 ranges;
 * tor, 2,696 single IPv4 addresses (no IPv6: the source states none); rpki-unreachable, 665 prefixes,
 * 484 IPv4 and 181 IPv6. The ranges are synthesized from a pinned xorshift (seed below), written by the
 * test suite's writer and loaded by the REAL loader, so the layout is a plane file's, byte for byte.
 *
 * Index kinds. Reputation is format 1 and therefore radix-16 in both families. tor and
 * rpki-unreachable have no recorded build profile yet (only reputation and routing do), so their kind is
 * the one the builder's selection rule gives for these counts: the smallest radix k in {12, 16, 18}
 * whose widest window costs 7 probes or fewer, else rank (reproduced here in integers).
 * Printed on every run, so the day a profile is recorded this is a one-line comparison.
 *
 * The loaded buffer is 64-byte aligned; it is copied to a 4096-byte aligned one and the map's pointers
 * moved with it, so a 32 KiB 8-way D1 sees the same sets on every run, as every other array here.
 *
 * The HOLD-HARMLESS table is built in memory from ../hold-harmless.txt (WE_HOLD_HARMLESS overrides
 * the path): the entries merged per family into sorted, non-overlapping ranges, laid out as FORMAT.md
 * 4.2's rank structure with the window stride equal to one node's key count, 16 at 32-bit keys and 4
 * at 128-bit keys, which the find functions honour and only the file loader refuses.
 */
#define DP_SEED 0xd1b54a32d192ed03ull
#define DP_MAX  4096u

typedef struct { uint32_t n; __uint128_t s[DP_MAX], e[DP_MAX]; } dp_set_t;

static uint64_t ds WE_CG_PAGE = DP_SEED;
static uint64_t drnd(void)
{
    ds ^= ds << 13;
    ds ^= ds >> 7;
    ds ^= ds << 17;
    return ds;
}

static dp_set_t rep4 WE_CG_PAGE, rep6 WE_CG_PAGE, tor4 WE_CG_PAGE, rpki4 WE_CG_PAGE, rpki6 WE_CG_PAGE, hh4 WE_CG_PAGE, hh6 WE_CG_PAGE;
static we_map_t dp_rep WE_CG_PAGE, dp_tor WE_CG_PAGE, dp_rpki WE_CG_PAGE, dp_hh WE_CG_PAGE;
static uint32_t *pq4 WE_CG_PAGE;        /* the pre-stage stream: hold-harmless inside, then critical-listed, alternating */
static const uint8_t *dp_rep_sev4 WE_CG_PAGE;      /* the reputation plane's IPv4 severities, as written */
static uint32_t *q4 WE_CG_PAGE, *hq4 WE_CG_PAGE;
static uint8_t (*q6)[16] WE_CG_PAGE, (*hq6)[16] WE_CG_PAGE;

/* n prefixes of length lo..hi inside [base, limit), sorted and disjoint, each aligned to its size */
static void dp_gen4(dp_set_t *d, uint32_t n, unsigned lo, unsigned hi)
{
    const uint64_t base = 0x01000000ull, limit = 0xe0000000ull;
    uint64_t cur = base, gap = (limit - base) / n;
    uint32_t i;

    for (i = 0; i < n; i++) {
        unsigned len = lo + (unsigned)(drnd() % (hi - lo + 1u));
        uint64_t size = 1ull << (32u - len), s = cur + drnd() % (gap / 2u + 1u);
        s = (s + size - 1u) & ~(size - 1u);
        if (s + size > limit) { fprintf(stderr, "dp_gen4: space exhausted\n"); exit(2); }
        d->s[i] = s;
        d->e[i] = s + size - 1u;
        cur = s + size;
    }
    d->n = n;
}

/* n prefixes of length lo..hi (at most 64) in 2000::/3, as 128-bit keys */
static void dp_gen6(dp_set_t *d, uint32_t n, unsigned lo, unsigned hi)
{
    const uint64_t base = 0x2000ull << 48, limit = 0x4000ull << 48;
    uint64_t cur = base, gap = (limit - base) / n;
    uint32_t i;

    for (i = 0; i < n; i++) {
        unsigned len = lo + (unsigned)(drnd() % (hi - lo + 1u));
        uint64_t size = 1ull << (64u - len), s = cur + drnd() % (gap / 2u + 1u);
        s = (s + size - 1u) & ~(size - 1u);
        if (s + size > limit || s + size < s) { fprintf(stderr, "dp_gen6: space exhausted\n"); exit(2); }
        d->s[i] = (__uint128_t)s << 64;
        d->e[i] = ((__uint128_t)(s + size - 1u) << 64) | (__uint128_t)UINT64_MAX;
        cur = s + size;
    }
    d->n = n;
}

/* the plane layout's selection rule (FORMAT.md §4), in integers: kind and parameter for one family */
static void dp_choose(const dp_set_t *d, int bits, uint32_t *kind, uint32_t *param)
{
    static const unsigned K[3] = { 12u, 16u, 18u };
    unsigned ki;

    if (d->n == 0u) { *kind = WE_KIND_NONE; *param = 0u; return; }
    for (ki = 0; ki < 3u; ki++) {
        uint32_t *cnt = calloc((size_t)1 << K[ki], 4), worst = 0, i, probes = 0;
        if (cnt == NULL) { fprintf(stderr, "out of memory\n"); exit(2); }
        for (i = 0; i < d->n; i++) {
            uint64_t top = bits == 32 ? (uint64_t)d->s[i] << 32 : (uint64_t)(d->s[i] >> 64);
            uint32_t b = (uint32_t)(top >> (64u - K[ki]));
            if (++cnt[b] > worst) { worst = cnt[b]; }
        }
        free(cnt);
        while ((worst >> probes) != 0u) { probes++; }     /* 32 - clz(worst), and 0 at worst 0 */
        if (probes <= 7u) { *kind = WE_KIND_RADIX; *param = K[ki]; return; }
    }
    *kind = WE_KIND_RANK;
    *param = bits == 128 ? 5u : 6u;
}

static const char *kind_name(uint32_t kind, uint32_t param, char *buf, size_t n)
{
    if (kind == WE_KIND_RADIX) { snprintf(buf, n, "radix-%u", param); }
    else if (kind == WE_KIND_RANK) { snprintf(buf, n, "rank-%us", 1u << param); }
    else { snprintf(buf, n, "none"); }
    return buf;
}

/* copy a loaded map's buffer to a 4096-byte aligned one and move every pointer into it */
static void dp_rebase(we_map_t *m)
{
    const uint8_t *ob = m->base;
    uint8_t *nb = xalloc(m->len);
    size_t len = m->len;

    memcpy(nb, ob, len);
#define RB(p) do { if ((const uint8_t *)(p) >= ob && (const uint8_t *)(p) < ob + len) \
                       { (p) = (void *)(nb + ((const uint8_t *)(p) - ob)); } } while (0)
    RB(m->f4.start); RB(m->f4.end); RB(m->f4.records); RB(m->f4.sev); RB(m->f4.idx); RB(m->f4.stree);
    RB(m->f6.start); RB(m->f6.end); RB(m->f6.records); RB(m->f6.sev); RB(m->f6.idx); RB(m->f6.stree);
    RB(m->f6w.start); RB(m->f6w.end); RB(m->f6w.records); RB(m->f6w.sev); RB(m->f6w.idx); RB(m->f6w.stree);
    RB(m->h); RB(m->v4_index); RB(m->v4_start); RB(m->v4_end); RB(m->v4_sev); RB(m->v6_index);
    RB(m->v6_start); RB(m->v6_end); RB(m->v6_sev); RB(m->v4_meta); RB(m->v6_meta); RB(m->blob);
#undef RB
    free((void *)ob);
    m->base = nb;
}

/* write one plane with the test writer, load it with the real loader, rebase it */
static void dp_plane(const char *dir, const char *name, uint32_t format, uint32_t plane, const dp_set_t *v4,
                     const dp_set_t *v6, we_map_t *out)
{
    ww_plane_t p;
    char path[1200], k4[24], k6[24];
    uint8_t *r4 = NULL, *r6 = NULL;
    uint32_t i;
    we_load_detail_t det;
    int rc;

    memset(&p, 0, sizeof p);
    p.format = format;
    p.schema = 1;
    p.plane = plane;
    p.generation = 1u;
    p.v4.n = v4->n; p.v4.start = v4->s; p.v4.end = v4->e;
    p.v6.n = v6->n; p.v6.start = v6->s; p.v6.end = v6->e;
    if (format == WE_FORMAT_1) {
        uint8_t *s4 = xalloc(v4->n + 1u), *s6 = xalloc(v6->n + 1u);
        for (i = 0; i < v4->n; i++) { s4[i] = (uint8_t)(1u + drnd() % 4u); }
        for (i = 0; i < v6->n; i++) { s6[i] = (uint8_t)(1u + drnd() % 4u); }
        p.v4.sev = s4; p.v6.sev = s6;
        dp_rep_sev4 = s4;
        p.v4.kind = p.v6.kind = WE_KIND_RADIX;
        p.v4.param = p.v6.param = 16u;
    } else {
        uint32_t flag = plane == WE_PLANE_TOR ? WE_MF_TOR_EXIT : WE_MF_RPKI_UNREACHABLE;
        uint32_t st4 = ww_record_stride(&p, 4), st6 = ww_record_stride(&p, 6);
        r4 = xalloc((size_t)(v4->n + 1u) * st4);
        r6 = xalloc((size_t)(v6->n + 1u) * st6);
        for (i = 0; i < v4->n; i++) {
            we_member4_t r;
            memset(&r, 0, sizeof r);
            r.flags = flag;
            r.reason = plane == WE_PLANE_RPKI_UNREACHABLE ? (uint8_t)(1u + drnd() % 2u) : 0u;
            memcpy(r4 + (size_t)i * st4, &r, sizeof r);
        }
        for (i = 0; i < v6->n; i++) {
            we_member6_t r;
            memset(&r, 0, sizeof r);
            r.flags = flag;
            r.reason = plane == WE_PLANE_RPKI_UNREACHABLE ? (uint8_t)(1u + drnd() % 2u) : 0u;
            memcpy(r6 + (size_t)i * st6, &r, sizeof r);
        }
        p.v4.rec = r4; p.v6.rec = r6;
        dp_choose(v4, 32, &p.v4.kind, &p.v4.param);
        dp_choose(v6, 128, &p.v6.kind, &p.v6.param);
    }
    snprintf(path, sizeof path, "%s/default-planes", dir);
    (void)mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/default-planes/%s.bin", dir, name);
    if (cg_write_plane(path, &p) != 0) { fprintf(stderr, "cannot write %s\n", path); exit(2); }
    memset(&det, 0, sizeof det);
    rc = we_plane_open(path, out, &det);
    if (rc != WE_OK) { fprintf(stderr, "%s does not load: %s\n", path, we_strerror(rc)); exit(2); }
    dp_rebase(out);
    fprintf(stderr, "plane %-16s format %u, IPv4 %u ranges (%s), IPv6 %u ranges (%s), %zu bytes\n", name,
            format, v4->n, kind_name(p.v4.kind, p.v4.param, k4, sizeof k4), v6->n,
            kind_name(p.v6.kind, p.v6.param, k6, sizeof k6), out->len);
}

/* ---- the hold-harmless table ---- */
static int dp_cmp(const void *a, const void *b)
{
    const __uint128_t *x = a, *y = b;
    return *x < *y ? -1 : *x > *y;
}

static void hh_add(dp_set_t *d, __uint128_t s, __uint128_t e)
{
    if (d->n >= DP_MAX) { fprintf(stderr, "hold-harmless: too many entries\n"); exit(2); }
    d->s[d->n] = s;
    d->e[d->n] = e;
    d->n++;
}

/* sort by start (ends travel with them) and merge OVERLAPPING entries; adjacent ones stay apart */
static void hh_merge(dp_set_t *d)
{
    __uint128_t (*pair)[2] = xalloc((size_t)d->n * 32u);
    uint32_t i, o = 0;

    for (i = 0; i < d->n; i++) { pair[i][0] = d->s[i]; pair[i][1] = d->e[i]; }
    qsort(pair, d->n, 32u, dp_cmp);
    for (i = 0; i < d->n; i++) {
        if (o > 0u && pair[i][0] <= d->e[o - 1u]) {
            if (pair[i][1] > d->e[o - 1u]) { d->e[o - 1u] = pair[i][1]; }
            continue;
        }
        d->s[o] = pair[i][0];
        d->e[o] = pair[i][1];
        o++;
    }
    d->n = o;
}

static void hh_parse(void)
{
    const char *path = getenv("WE_HOLD_HARMLESS");
    char line[512];
    FILE *f;

    if (path == NULL) { path = "../hold-harmless.txt"; }
    f = fopen(path, "r");
    if (f == NULL) { perror(path); exit(2); }
    while (fgets(line, sizeof line, f) != NULL) {
        char tok[128], *slash;
        unsigned len;
        uint8_t a[16];
        if (sscanf(line, "%127s", tok) != 1 || tok[0] == '#') { continue; }
        slash = strchr(tok, '/');
        if (slash != NULL) { *slash = '\0'; }
        if (inet_pton(AF_INET, tok, a) == 1) {
            uint32_t v = ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
            len = slash != NULL ? (unsigned)atoi(slash + 1) : 32u;
            if (len > 32u) { fprintf(stderr, "hold-harmless: bad length in %s\n", line); exit(2); }
            {
                uint32_t mask = len == 0u ? 0u : ~(uint32_t)0 << (32u - len);
                hh_add(&hh4, v & mask, (v & mask) | ~mask);
            }
        } else if (inet_pton(AF_INET6, tok, a) == 1) {
            __uint128_t v = 0, mask;
            int i;
            for (i = 0; i < 16; i++) { v = (v << 8) | a[i]; }
            len = slash != NULL ? (unsigned)atoi(slash + 1) : 128u;
            if (len > 128u) { fprintf(stderr, "hold-harmless: bad length in %s\n", line); exit(2); }
            mask = len == 0u ? 0 : ~(__uint128_t)0 << (128u - len);
            hh_add(&hh6, v & mask, (v & mask) | ~mask);
        } else {
            fprintf(stderr, "hold-harmless: not an address or prefix: %s\n", tok);
            exit(2);
        }
    }
    fclose(f);
    hh_merge(&hh4);
    hh_merge(&hh6);
}

/* FORMAT.md 4.2's complete (B+1)-ary separator tree, at window stride s, keys of kb bytes */
static void hh_family(we_fam_t *f, const dp_set_t *d, uint32_t kb, uint32_t s)
{
    uint32_t B = 64u / kb, F = B + 1u, m = (d->n + s - 1u) / s, dep = 0, l, P, i, sh = 0;
    uint64_t pw = 1, nodes = 0, off[16], levelw[16];
    uint8_t *st = xalloc((size_t)d->n * kb), *en = xalloc((size_t)d->n * kb), *tree;

    while ((1u << sh) < s) { sh++; }
    for (i = 0; i < d->n; i++) {
        if (kb == 4u) {
            uint32_t a = (uint32_t)d->s[i], b = (uint32_t)d->e[i];
            memcpy(st + (size_t)i * 4u, &a, 4); memcpy(en + (size_t)i * 4u, &b, 4);
        } else {
            memcpy(st + (size_t)i * 16u, &d->s[i], 16); memcpy(en + (size_t)i * 16u, &d->e[i], 16);
        }
    }
    while (pw < m) { pw *= F; dep++; }
    pw = 1;
    for (l = 0; l < dep; l++) { off[l] = nodes; levelw[l] = pw; nodes += pw; pw *= F; }
    tree = xalloc((size_t)(nodes + 1u) * 64u);
    for (l = 0; l < dep; l++) {
        uint64_t below = 1;
        uint32_t q;
        for (q = l + 1u; q < dep; q++) { below *= F; }
        for (P = 0; P < levelw[l]; P++) {
            for (i = 0; i < B; i++) {
                uint64_t w = ((uint64_t)P * F + i + 1u) * below;
                uint8_t *slot = tree + ((off[l] + P) * 64u) + (size_t)i * kb;
                if (kb == 4u) {
                    uint32_t v = w < m ? (uint32_t)d->s[w * s] : UINT32_MAX;
                    memcpy(slot, &v, 4);
                } else {
                    __uint128_t v = w < m ? d->s[w * s] : ~(__uint128_t)0;
                    memcpy(slot, &v, 16);
                }
            }
        }
    }
    f->first = d->n ? d->s[0] : 0;
    f->start = st;
    f->end = en;
    f->stree = tree;
    f->n = d->n;
    f->m = m;
    f->stride = kb;
    f->nodes = (uint32_t)nodes;
    f->span = s;
    f->kind = WE_KIND_RANK;
    f->depth = (uint8_t)dep;
    f->sshift = (uint8_t)sh;
    f->key_bits = (uint8_t)(kb * 8u);
    f->file_kind = WE_KIND_RANK;
    f->file_param = (uint8_t)sh;
}

static void addr6(__uint128_t v, uint8_t out[16])
{
    int i;
    for (i = 15; i >= 0; i--) { out[i] = (uint8_t)v; v >>= 8; }
}

/* the index of the range holding a, or -1: the reference every default-plane slot is checked against */
static int64_t dp_ref(const dp_set_t *d, __uint128_t a)
{
    uint32_t lo = 0, hi = d->n;
    while (lo < hi) { uint32_t mid = lo + ((hi - lo) >> 1); if (d->s[mid] <= a) { lo = mid + 1u; } else { hi = mid; } }
    return (lo != 0u && a <= d->e[lo - 1u]) ? (int64_t)(lo - 1u) : -1;
}

static __uint128_t dp_inside(const dp_set_t *d)
{
    uint32_t i = (uint32_t)(drnd() % d->n);
    __uint128_t w = d->e[i] - d->s[i] + 1u, r = ((__uint128_t)drnd() << 64) | drnd();
    return d->s[i] + (w != 0 ? r % w : r);
}

static void hh_build(void)
{
    static int built;

    if (built) { return; }
    built = 1;
    hh_parse();
    hh_family(&dp_hh.f4, &hh4, 4u, 16u);
    hh_family(&dp_hh.f6, &hh6, 16u, 4u);
    fprintf(stderr, "hold-harmless: IPv4 %u merged ranges, %u windows of 16, depth %u; IPv6 %u merged ranges, "
            "%u windows of 4, depth %u\n", hh4.n, dp_hh.f4.m, dp_hh.f4.depth, hh6.n, dp_hh.f6.m, dp_hh.f6.depth);
}

/*
 * ---- the evaluator's synthetic world -------------------------------------------------------------
 *
 * All eight planes, each holding the two /24s that contain the two request addresses EA (11.0.0.1) and
 * EB (22.0.0.1), with records chosen so every atom the evaluator slots use has a
 * known, definite value there. The BASIS world hands the evaluator every plane but anonymizer, whose
 * view stays NULL, so its atoms read UNKNOWN and `proxy is unknown` is the TRUE `is unknown` the basis
 * needs; the FULL world hands it all eight.
 *
 *   reputation        sev medium              (listed >= low TRUE, listed >= critical FALSE)
 *   tor               no flag                 (tor_exit FALSE)
 *   rpki-unreachable  flagged                 (rpki_unreachable TRUE: evaluator-worst-lines needs a seventh
 *                                             TRUE operand without spending a `not`; the FALSE or-chains
 *                                             that read the plane, the basis floor and the membership
 *                                             rows, write it `not rpki_unreachable`)
 *   anonymizer        proxy                   (proxy TRUE, vpn FALSE)
 *   threat            c2, bruteforce, spam    (TRUE; phishing, scanner, state_actor FALSE)
 *   tenant            no flag                 (tenant_allow and tenant_deny FALSE, so step 2 never ends a request)
 *   routing           AS500, NL, valid, RIPE, reputable
 *   registry          the same record
 *
 * Requests alternate EA and EB, so every request re-keys the memo and performs the same fills whatever the
 * evaluator's memo policy is between requests: a per-request cost the solve can rely on.
 *
 * NOT documentation addresses. The obvious choice, 192.0.2.1 and 198.51.100.1, is in the hold-harmless
 * table (RFC 5737 space), so the pre-stage exempts every request and no program instruction runs: every
 * basis row would measure the exemption and the solve would price nothing. Both addresses are asserted
 * to miss the table when the world is checked, so a table that grows to cover them stops the gate.
 */
#define EA 0x0b000001u     /* 11.0.0.1 */
#define EB 0x16000001u     /* 22.0.0.1 */

static we_map_t ew[WE_PLANE_MAX + 1u] WE_CG_PAGE;
static const char *const ew_names[WE_PLANE_MAX + 1u] WE_CG_PAGE = {
    NULL, "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

static void ew_build(const char *dir)
{
    static int built;
    static dp_set_t two;
    uint32_t p;

    if (built) { return; }
    built = 1;
    two.n = 2;
    two.s[0] = EA & 0xffffff00u; two.e[0] = EA | 0xffu;
    two.s[1] = EB & 0xffffff00u; two.e[1] = EB | 0xffu;
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        ww_plane_t w;
        uint8_t rec[2][32];
        char path[1200];
        uint8_t sev[2] = { WE_SEV_MEDIUM, WE_SEV_MEDIUM };
        int i, rc;

        memset(&w, 0, sizeof w);
        memset(rec, 0, sizeof rec);
        w.schema = 1;
        w.plane = p;
        w.generation = 1u;
        w.v4.n = 2; w.v4.start = two.s; w.v4.end = two.e;
        w.v4.kind = WE_KIND_RADIX;
        w.v4.param = p == WE_PLANE_REPUTATION ? 16u : 12u;
        w.v6.n = 0u;              /* IPv4 only: the requests are IPv4 */
        if (p == WE_PLANE_REPUTATION) {
            w.format = WE_FORMAT_1;
            w.v4.sev = sev;
        } else {
            w.format = WE_FORMAT_2;
            for (i = 0; i < 2; i++) {
                if (p == WE_PLANE_ROUTING || p == WE_PLANE_REGISTRY) {
                    we_route4_t r;
                    memset(&r, 0, sizeof r);
                    r.asn = 500u;
                    r.country = 528u;
                    r.rov = WE_ROV_VALID;
                    r.rir = WE_RIR_RIPE;
                    r.asn_rep = WE_REP_REPUTABLE;
                    memcpy(rec[i], &r, sizeof r);
                } else {
                    we_member4_t r;
                    memset(&r, 0, sizeof r);
                    r.flags = p == WE_PLANE_THREAT ? (WE_MF_C2 | WE_MF_BRUTEFORCE | WE_MF_SPAM)
                            : p == WE_PLANE_ANONYMIZER ? WE_MF_PROXY
                            : p == WE_PLANE_RPKI_UNREACHABLE ? WE_MF_RPKI_UNREACHABLE : 0u;
                    memcpy(rec[i], &r, sizeof r);
                }
            }
            /* every IPv4 record of both schemas is 16 bytes, and the writer reads n * 16 contiguous bytes */
            memmove(rec[0] + 16, rec[1], 16);
            w.v4.rec = &rec[0][0];
            /* country_version stays 0: the loader stores it and judges nothing by it, and NL (528) is
             * read through the reader's own table, which is what the atoms see */
        }
        snprintf(path, sizeof path, "%s/evaluator-world", dir);
        (void)mkdir(path, 0755);
        snprintf(path, sizeof path, "%s/evaluator-world/%s.bin", dir, ew_names[p]);
        if (cg_write_plane(path, &w) != 0) { fprintf(stderr, "cannot write %s\n", path); exit(2); }
        rc = we_plane_open(path, &ew[p], NULL);
        if (rc != WE_OK) { fprintf(stderr, "%s does not load: %s\n", path, we_strerror(rc)); exit(2); }
        dp_rebase(&ew[p]);
    }
}

/*
 * THE LIVE ROUTING PLANE: the pinned CAIDA RouteViews IPv4 table this driver already loads for its
 * lookup rows (1,169,047 ranges, the origin AS of each with its derived attributes, bench/build7.py),
 * written by the test suite's writer as a routing plane file and opened by the REAL loader, so the
 * evaluator reads a live-shaped plane exactly as it reads one in production. Built the first time a
 * live slot needs it: writing 1.2 million ranges is not something every lookup row should pay for.
 */
static const char *lv_dir WE_CG_PAGE;
#if !defined(WE_TRACE) || defined(WE_HAVE_EVAL)
static we_map_t lv_route WE_CG_PAGE;

static void lv_build(void)
{
    static int built;
    ww_plane_t w;
    char path[1200];
    __uint128_t *st, *en;
    uint32_t i;
    int rc;

    if (built) { return; }
    built = 1;
    st = xalloc((size_t)n4 * sizeof *st);
    en = xalloc((size_t)n4 * sizeof *en);
    for (i = 0; i < n4; i++) { st[i] = st4[i]; en[i] = end4(i); }
    memset(&w, 0, sizeof w);
    w.format = WE_FORMAT_2;
    w.schema = 1;
    w.plane = WE_PLANE_ROUTING;
    w.generation = 1u;
    w.v4.n = n4; w.v4.start = st; w.v4.end = en;
    w.v4.kind = WE_KIND_RADIX; w.v4.param = 18u;
    w.v4.rec = rec4;                    /* {end, asn, cc, rov, rir, flags, asn_rep}: the record layout itself */
    snprintf(path, sizeof path, "%s/live-routing", lv_dir);
    (void)mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/live-routing/routing.bin", lv_dir);
    if (cg_write_plane(path, &w) != 0) { fprintf(stderr, "cannot write %s\n", path); exit(2); }
    rc = we_plane_open(path, &lv_route, NULL);
    if (rc != WE_OK) { fprintf(stderr, "%s does not load: %s\n", path, we_strerror(rc)); exit(2); }
    dp_rebase(&lv_route);
    free(st);
    free(en);
}

/* the live slot's k-th request: the middle of a range, and every fourth one just past a range's end */
static uint32_t lv_addr(uint32_t k)
{
    uint32_t i = (uint32_t)(((uint64_t)k * 2654435761u) % n4);
    return (k & 3u) == 3u ? end4(i) + 1u : st4[i] + ((end4(i) - st4[i]) >> 1);
}
#endif

static void dp_build(const char *dir, uint32_t count)
{
    static const dp_set_t none;
    uint32_t k;

    dp_gen4(&rep4, 971u, 16u, 32u);
    dp_gen6(&rep6, 27u, 32u, 64u);
    dp_gen4(&tor4, 2696u, 32u, 32u);
    dp_gen4(&rpki4, 484u, 16u, 24u);
    dp_gen6(&rpki6, 181u, 29u, 48u);
    dp_plane(dir, "reputation", WE_FORMAT_1, WE_PLANE_REPUTATION, &rep4, &rep6, &dp_rep);
    dp_plane(dir, "tor", WE_FORMAT_2, WE_PLANE_TOR, &tor4, &none, &dp_tor);
    dp_plane(dir, "rpki-unreachable", WE_FORMAT_2, WE_PLANE_RPKI_UNREACHABLE, &rpki4, &rpki6, &dp_rpki);
    hh_build();
    ew_build(dir);

    /*
     * THE NAMED STREAMS. q4: request k is, by k mod 4, inside a reputation range, inside a tor entry,
     * inside an rpki-unreachable prefix, or inside none of the three, so each class is exactly a quarter.
     * q6: inside reputation, inside rpki-unreachable, then two quarters inside none (tor has no IPv6).
     * hq4/hq6: the hold-harmless table's costliest class, an address inside a range of a FULL window
     * (the last, partial window and everything below start[0] cost less).
     */
    q4 = xalloc((size_t)count * 4u);
    q6 = xalloc((size_t)count * 16u);
    hq4 = xalloc((size_t)count * 4u);
    hq6 = xalloc((size_t)count * 16u);
    for (k = 0; k < count; k++) {
        __uint128_t a;
        switch (k & 3u) {
        case 0:  a = dp_inside(&rep4); break;
        case 1:  a = dp_inside(&tor4); break;
        case 2:  a = dp_inside(&rpki4); break;
        default:
            do { a = (uint32_t)drnd(); } while (dp_ref(&rep4, a) >= 0 || dp_ref(&tor4, a) >= 0 || dp_ref(&rpki4, a) >= 0);
        }
        q4[k] = (uint32_t)a;
        switch (k & 3u) {
        case 0:  a = dp_inside(&rep6); break;
        case 1:  a = dp_inside(&rpki6); break;
        default:
            do { a = ((__uint128_t)((0x2000ull << 48) + drnd() % (0x2000ull << 48)) << 64) | drnd(); }
            while (dp_ref(&rep6, a) >= 0 || dp_ref(&rpki6, a) >= 0);
        }
        addr6(a, q6[k]);
        {
            uint32_t full4 = (dp_hh.f4.m - (hh4.n % 16u != 0u)) * 16u, full6 = (dp_hh.f6.m - (hh6.n % 4u != 0u)) * 4u;
            uint32_t i4 = (uint32_t)(drnd() % full4), i6 = (uint32_t)(drnd() % full6);
            __uint128_t w4 = hh4.e[i4] - hh4.s[i4] + 1u, w6 = hh6.e[i6] - hh6.s[i6] + 1u;
            hq4[k] = (uint32_t)(hh4.s[i4] + drnd() % w4);
            addr6(hh6.s[i6] + (w6 != 0 ? (((__uint128_t)drnd() << 64) | drnd()) % w6 : 0), hq6[k]);
        }
    }
    /*
     * THE PRE-STAGE STREAM (module-export-prestage and its twins): even requests an address inside the
     * hold-harmless table, exempt at the pre-stage, so the decision fills no plane and the export fills
     * every plane of its set lazily; odd requests a critical-listed address outside the table, denied by
     * the default policy's first rule, so the decision fills the reputation entry and the export fills
     * the rest. Built after the named streams, so their random draws are what they were.
     */
    pq4 = xalloc((size_t)count * 4u);
    for (k = 0; k < count; k++) {
        uint32_t tries;
        if ((k & 1u) == 0u) { pq4[k] = hq4[k]; continue; }
        for (tries = 0; ; tries++) {
            __uint128_t a = dp_inside(&rep4);
            int64_t i = dp_ref(&rep4, a);
            if (i >= 0 && (dp_rep_sev4[i] & 0x0fu) >= WE_SEV_CRITICAL && dp_ref(&hh4, a) < 0) { pq4[k] = (uint32_t)a; break; }
            if (tries == 1000000u) { fprintf(stderr, "the reputation plane offers no critical-listed address outside the hold-harmless table\n"); exit(2); }
        }
    }
    /*
     * The verify step's own negative control, which cachegrind-gate.sh runs every time: with
     * WE_CG_PLANT_WRONG set, the hold-harmless table's arm-time first key is moved past every address, so
     * every lookup answers "no range" and the verify pass MUST refuse the slot before it is measured.
     */
    if (getenv("WE_CG_PLANT_WRONG") != NULL) {
        dp_hh.f4.first = UINT32_MAX;
    }
}

#ifndef WE_TRACE
/* every default-plane slot's answers against the reference over the ranges it was built from */
static void dp_verify(uint32_t count)
{
    uint32_t k, ea, eb, lim = count < 200000u ? count : 200000u;
    for (k = 0; k < lim; k++) {
        __uint128_t a6 = 0;
        int i;
        for (i = 0; i < 16; i++) { a6 = (a6 << 8) | q6[k][i]; }
#define DV(slot, got, want) do { uint32_t r_ = (got); int64_t g_ = r_ == WE_NO_RANGE ? -1 : (int64_t)r_; \
        if (g_ != (want)) { fprintf(stderr, "%s disagrees with the reference at stream index %u\n", slot, k); exit(1); } } while (0)
        DV("lookup-reputation@q4", cg_plane4(&dp_rep, q4[k]), dp_ref(&rep4, q4[k]));
        DV("lookup-reputation@q6", cg_find6(&dp_rep, q6[k]), dp_ref(&rep6, a6));
        DV("lookup-tor@q4", cg_plane4(&dp_tor, q4[k]), dp_ref(&tor4, q4[k]));
        DV("lookup-rpki-unreachable@q4", cg_plane4(&dp_rpki, q4[k]), dp_ref(&rpki4, q4[k]));
        DV("lookup-rpki-unreachable@q6", cg_find6(&dp_rpki, q6[k]), dp_ref(&rpki6, a6));
        DV("lookup-hh@16", cg_plane4(&dp_hh, hq4[k]), dp_ref(&hh4, hq4[k]));
        for (a6 = 0, i = 0; i < 16; i++) { a6 = (a6 << 8) | hq6[k][i]; }
        DV("lookup-hh@4", cg_find6(&dp_hh, hq6[k]), dp_ref(&hh6, a6));
#undef DV
    }
    /* the evaluator world: EA is in each plane's first range and EB in its second */
    for (k = 1; k <= WE_PLANE_MAX; k++) {

        if (cg_plane4(&ew[k], EA) != 0u || cg_plane4(&ew[k], EB) != 1u) {
            fprintf(stderr, "lookup-%s@basis disagrees with the world it was built from\n", ew_names[k]);
            exit(1);
        }
    }
    if ((int64_t)(cg_plane4(&dp_hh, EA) == WE_NO_RANGE ? -1 : (int64_t)cg_plane4(&dp_hh, EA)) != dp_ref(&hh4, EA)
            || (int64_t)(cg_plane4(&dp_hh, EB) == WE_NO_RANGE ? -1 : (int64_t)cg_plane4(&dp_hh, EB)) != dp_ref(&hh4, EB)) {
        fprintf(stderr, "lookup-hh@basis disagrees with the reference\n");
        exit(1);
    }
    /* its negative control, run by cachegrind-gate.sh every time: the documentation pair must be refused */
    ea = getenv("WE_CG_PLANT_DOC_ADDR") != NULL ? 0xc0000201u : EA;      /* 192.0.2.1 */
    eb = getenv("WE_CG_PLANT_DOC_ADDR") != NULL ? 0xc6336401u : EB;      /* 198.51.100.1 */
    if (dp_ref(&hh4, ea) != -1 || dp_ref(&hh4, eb) != -1) {
        fprintf(stderr, "the evaluator world's request addresses are in the hold-harmless table, so every "
                "evaluator row would measure the exemption and run no program; move EA and EB\n");
        exit(1);
    }
}
#endif

#ifndef WE_TRACE
/* the plane id of a `lookup-<plane>@basis` slot, or 0 */
static uint32_t basis_plane(const char *slot)
{
    uint32_t p;
    size_t n;

    if (strncmp(slot, "lookup-", 7) != 0) { return 0u; }
    n = strlen(slot);
    if (n < 13u || strcmp(slot + n - 6u, "@basis") != 0) { return 0u; }
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        if (strlen(ew_names[p]) == n - 13u && strncmp(slot + 7, ew_names[p], n - 13u) == 0) {
            return p;
        }
    }
    return 0u;
}
#endif

#ifndef WE_TRACE
/* we_find* answers the range index or WE_NO_RANGE; the reference answers index + 1 or 0 */
static uint32_t one(uint32_t r) { return r == WE_NO_RANGE ? 0u : r + 1u; }

static void verify(uint32_t count)
{
    uint32_t k, lim = count < 200000u ? count : 200000u;
    for (k = 0; k < lim; k++) {
        if (one(cg_plane4(&mp, u4[k])) != ref4(u4[k]) || one(cg_plane4(&mp, d4[k])) != ref4(d4[k])) {
            fprintf(stderr, "plane-v4-radix18 disagrees with the reference at stream index %u\n", k);
            exit(1);
        }
        if (one(cg_plane6(&mp, u6b[k])) != ref6(u6[k]) || one(cg_plane6(&mp, d6b[k])) != ref6(d6[k])) {
            fprintf(stderr, "plane-v6-rank64s disagrees with the reference at stream index %u\n", k);
            exit(1);
        }
        if ((cg_ship4(&ship, u4[k]) != 0) != (ref4(u4[k]) != 0) || (cg_ship4(&ship, d4[k]) != 0) != (ref4(d4[k]) != 0)) {
            fprintf(stderr, "shipped-v4 disagrees with the reference at stream index %u\n", k);
            exit(1);
        }
        if ((cg_ship6(&ship, u6b[k]) != 0) != (ref6(u6[k]) != 0) || (cg_ship6(&ship, d6b[k]) != 0) != (ref6(d6[k]) != 0)) {
            fprintf(stderr, "shipped-v6 disagrees with the reference at stream index %u\n", k);
            exit(1);
        }
    }
}
#endif

static volatile uint64_t sink WE_CG_PAGE;

/* ==== THE POLICY EVALUATOR'S SLOTS ================================================================== */
/*
 * The slot TABLE is plain data and is built whether or not the evaluator is in the tree, so `slots`
 * names every evaluator row even when cachegrind-gate.sh can only report it DARK. Measuring one needs
 * the evaluator: that half is compiled under WE_HAVE_EVAL, which the gate defines exactly when
 * we_eval.h is in the tree, and without it every evaluator slot answers EMPTY (exit 3), never a number.
 *
 * Each slot carries what the cost model needs beside its measurement:
 *   vector   per request, the executed count vector in cost-model.py's factored basis (basis rows),
 *            or the finds the row performs as find:<lookup slot>=<count> (plane and pre-stage rows)
 *   sound    the composed bound's terms per request, term=count, for the soundness inequality
 *   program  the context program's own count vector, for the worst case's maximality check
 *
 * THE BASIS ROWS run in the BASIS world with a constant floor program that reads every plane the rows
 * read (an or-chain of seven FALSE atoms, so no jump is taken and every plane is filled on every
 * request), so the fills are the same in every row and land in `fixed`; requests alternate EA and EB,
 * so each one re-keys the memo whatever the evaluator keeps between requests. Every context rule is a
 * `log` rule, so every rule is visited, and each chain is arranged so no jump is taken except in the
 * one row that exists to take one.
 */
#if !defined(WE_TRACE) || defined(WE_HAVE_EVAL)
#include "eval_programs.h"

typedef enum { W_BASIS, W_FULL, W_DEFAULT, W_LIVE } ev_world_t;
/* A_HH_KEY2: the floor 127.0.0.1, hold-harmless (a same-box proxy), the server EA and EB alternating */
typedef enum { A_EQUAL, A_DISTINCT, A_STREAM, A_LIVE, A_PRESTAGE, A_HH_KEY2 } ev_addr_t;
/*
 * What runs the slot's requests: the evaluator through the harness (ev_one), the same with the views set
 * once before the loop (the harness's own view stores measured by their absence), or the MODULE's
 * request path (we_mod_decide) alone, with the export pass of the default set, of every attribute, or of
 * the default set after a decision that filled nothing, or with nginx's pre-decision variable path
 * reading three planes, or one.
 */
typedef enum { K_EVAL, K_EVAL_SV, K_MOD, K_MOD_EXPORT, K_MOD_EXPORT_ALL, K_MOD_PRESTAGE, K_MOD_VAR3, K_MOD_VAR1 } ev_kind_t;

typedef struct {
    char       *slot;
    uint32_t    requests;
    ev_world_t  world;
    ev_addr_t   addrs;
    char       *floor;     /* LF-separated records `<kind> <argument>`, kind floor or set; NULL: the empty floor */
    char       *ctx;       /* LF-separated `policy <argument>` records; NULL: no context program */
    char       *vector, *sound, *program;
    uint8_t     views;     /* the armed planes, bit plane_id - 1; the world's set unless the slot says otherwise */
    ev_kind_t   kind;
    char       *twin;      /* a module slot's evaluator twin: its programs, views and stream, whose cases are its own */
} ev_slot_t;

#define EV_MAX 512u                   /* 286 slots since every bitmap word got its own count rows */
static ev_slot_t ev[EV_MAX] WE_CG_PAGE;
static uint32_t nev WE_CG_PAGE;

static char *ev_dup(sb_t *b) { char *s = b->p != NULL ? b->p : strdup("-"); b->p = NULL; b->n = b->cap = 0; return s; }

static const char ev_preamble[] WE_CG_PAGE = FL "log if phishing or listed >= critical or rpki == invalid or tor_exit "
                                  "or not rpki_unreachable or tenant_deny or registry_rir == arin" RS;
/* decision 3's four rules: the default policy's context program */
#define DEFAULT4 PO "deny if listed >= critical" RS PO "deny if listed >= high" RS PO "log if rpki_unreachable" RS PO "log if tor_exit" RS
/* the view rows' atoms, one plane each, the deciding `c2` first */
static const struct { const char *atom; uint32_t plane; } md_vatoms[8] WE_CG_PAGE = {
    { "c2", WE_PLANE_THREAT }, { "listed >= low", WE_PLANE_REPUTATION }, { "tor_exit", WE_PLANE_TOR },
    { "rpki_unreachable", WE_PLANE_RPKI_UNREACHABLE }, { "rpki == valid", WE_PLANE_ROUTING },
    { "registry_rir == ripe", WE_PLANE_REGISTRY }, { "proxy", WE_PLANE_ANONYMIZER }, { "tenant_deny", WE_PLANE_TENANT },
};

/* the world's armed planes: everything but the anonymizer, everything, the default policy's three, the routing plane */
static uint8_t ev_world_views(ev_world_t w)
{
    return w == W_BASIS ? (uint8_t)~(1u << (WE_PLANE_ANONYMIZER - 1u)) : w == W_FULL ? 0xffu
         : w == W_DEFAULT ? (uint8_t)((1u << (WE_PLANE_REPUTATION - 1u)) | (1u << (WE_PLANE_TOR - 1u)) | (1u << (WE_PLANE_RPKI_UNREACHABLE - 1u)))
         : (uint8_t)(1u << (WE_PLANE_ROUTING - 1u));
}

static ev_slot_t *ev_add(const char *slot, uint32_t requests, ev_world_t w, ev_addr_t a, sb_t *floor, sb_t *ctx,
                         sb_t *vector, sb_t *sound, sb_t *program)
{
    ev_slot_t *e;

    /* the table is static; a slot past its end once overwrote the evaluator world beside it, silently */
    if (nev == EV_MAX) {
        fprintf(stderr, "ev_add: %s is slot %u, past the table's %u; raise EV_MAX\n", slot, nev + 1u, EV_MAX);
        exit(2);
    }
    e = &ev[nev++];
    e->slot = strdup(slot);
    e->requests = requests;
    e->world = w;
    e->addrs = a;
    e->floor = floor != NULL && floor->p != NULL ? ev_dup(floor) : NULL;
    e->ctx = ctx != NULL && ctx->p != NULL ? ev_dup(ctx) : NULL;
    e->vector = vector != NULL ? ev_dup(vector) : strdup("-");
    e->sound = sound != NULL ? ev_dup(sound) : strdup("-");
    e->program = program != NULL ? ev_dup(program) : strdup("-");
    e->views = ev_world_views(w);
    e->kind = K_EVAL;
    e->twin = NULL;
    return e;
}

/* a module slot: the twin's programs, world, views and stream, run through the module's request path */
static ev_slot_t *ev_add_module(const char *slot, const char *twin, ev_kind_t kind, sb_t *vector, sb_t *sound)
{
    const ev_slot_t *t = NULL;
    ev_slot_t *e;
    uint32_t i;
    sb_t fl = { 0 }, cx = { 0 };

    for (i = 0; i < nev; i++) { if (!strcmp(ev[i].slot, twin)) { t = &ev[i]; } }
    if (t == NULL) { fprintf(stderr, "%s: its twin %s is not in the table before it\n", slot, twin); exit(2); }
    if (t->floor != NULL) { sb_add(&fl, "%s", t->floor); }
    if (t->ctx != NULL) { sb_add(&cx, "%s", t->ctx); }
    e = ev_add(slot, t->requests, t->world, t->addrs, t->floor != NULL ? &fl : NULL, t->ctx != NULL ? &cx : NULL, vector, sound, NULL);
    e->views = t->views;
    e->kind = kind;
    e->twin = strdup(twin);
    return e;
}

/*
 * The floor pass's terms. An operation's cost was measured to depend on which pass runs it (under gcc 13
 * the floor pass ran a 256-rule INSET_ASN program about one instruction per atom dearer than the context
 * pass ran the same program), so every basis term has a floor-pass twin, `<term>@floor`, solved from
 * floor-pass rows, and every floor-pass count is priced by it. The measured constants (c_*, the finds)
 * keep their names: each is already a remainder of the pass it was measured in.
 */
static void ev_atfloor(sb_t *b, const char *vec)
{
    char buf[1024], *save = NULL, *t;
    snprintf(buf, sizeof buf, "%s", vec);
    for (t = strtok_r(buf, " ", &save); t != NULL; t = strtok_r(NULL, " ", &save)) {
        const char *eq = strchr(t, '=');
        if (eq == NULL || !strncmp(t, "c_", 2) || !strncmp(t, "find:", 5) || !strncmp(t, "lookup-", 7)
                || !strncmp(t, "held", 4)) {
            sb_add(b, " %s", t);
        } else {
            sb_add(b, " %.*s@floor%s", (int)(eq - t), t, eq);
        }
    }
}

/* the context records `policy http/server:s <rule>` as floor records `floor http <rule>` */
static void ev_tofloor(sb_t *b, const char *recs)
{
    const char *p = recs;
    size_t n = strlen(PO);
    while (*p != '\0') {
        if (!strncmp(p, PO, n)) { sb_add(b, "%s", FL); p += n; } else { sb_add(b, "%c", *p); p++; }
    }
}

static void ev_basis(const char *name, int held, const char *prog, const char *vec, int mirror)
{
    sb_t fl = { 0 }, cx = { 0 }, ve = { 0 };
    char fname[128];

    sb_add(&fl, "%s", ev_preamble); ev_sets(&fl);
    sb_add(&cx, "%s", prog);
    sb_add(&ve, "%s%s", vec, held ? " held=1" : "");
    ev_add(name, 20000u, W_BASIS, A_EQUAL, &fl, &cx, &ve, NULL, NULL);
    if (!mirror) { return; }
    /* the same rule as a second FLOOR rule, after the preamble that fills its planes; no context program */
    sb_add(&fl, "%s", ev_preamble); ev_sets(&fl);
    ev_tofloor(&fl, prog);
    ev_atfloor(&ve, vec);
    if (held) { sb_add(&ve, " held=1"); }
    snprintf(fname, sizeof fname, "%s@floor", name);
    ev_add(fname, 20000u, W_BASIS, A_EQUAL, &fl, NULL, &ve, NULL, NULL);
}

/* the held-out rows mirrored into the floor pass too, so the floor basis is held to exactness as well */
static int ev_mirror_held(const char *name)
{
    return !strcmp(name, "evaluator-basis-rules-4") || !strcmp(name, "evaluator-basis-BOOL-TTF")
        || !strcmp(name, "evaluator-basis-INSET_ASN-TTF") || !strcmp(name, "evaluator-basis-INSET_ASN-or2")
        || !strcmp(name, "evaluator-basis-ISUNK-TTF") || !strcmp(name, "evaluator-basis-SEV-deny");
}

static void ev_build_slots(void)
{
    sb_t fl = { 0 }, cx = { 0 }, ve = { 0 }, so = { 0 }, pr = { 0 };
    char name[96];
    uint32_t i;
    ev_shape_t ws;
    const char *planes8[8] = { "reputation", "threat", "routing", "registry", "tor", "rpki-unreachable",
                               "anonymizer", "tenant" };

    if (nev != 0u) { return; }
    /*
     * THE BASIS (cost-model.py, BASIS). Every row runs on ONE address (A_EQUAL): the floor's preamble
     * reads every plane but the anonymizer, so its fills cover the context's reads and no context atom
     * triggers a fill. On two distinct addresses the context's first read of a plane fills it, so each
     * kind's first atom carried a find that `is unknown`, which fills nothing, did not: the basis then
     * solved per row order, and its held-out rows missed by up to 180 instructions. The constants are per
     * kind AND per outcome (an atom TRUE, an atom FALSE), with the ending of a rule split by how it ends
     * (`end` FALSE, `fire_log`, `fire_deny`), and the rows are ordered so the first 25 determine them;
     * every later row is HELD OUT and must be predicted EXACTLY, which cost-model.py asserts.
     */
#define BASIS(name, held, prog, vec) ev_basis(name, held, prog, vec, !(held) || ev_mirror_held(name))
    BASIS("evaluator-basis-BOOL-F", 0, PO "log if phishing" RS, "fixed=1 BOOL.F=1 end=1");
    BASIS("evaluator-basis-rules-2", 0, PO "log if phishing" RS PO "log if scanner" RS, "fixed=1 BOOL.F=2 end=2");
    BASIS("evaluator-basis-BOOL-TF", 0, PO "log if c2 and phishing" RS, "fixed=1 BOOL.T=1 BOOL.F=1 end=1");
    BASIS("evaluator-basis-BOOL-T", 0, PO "log if c2" RS, "fixed=1 BOOL.T=1 fire_log=1");
    BASIS("evaluator-basis-BOOL-notT", 0, PO "log if not c2" RS, "fixed=1 BOOL.T=1 NOT=1 end=1");
    BASIS("evaluator-basis-not-2", 0, PO "log if not not phishing" RS, "fixed=1 BOOL.F=1 NOT=2 end=1");
    BASIS("evaluator-basis-BOOL-or2", 0, PO "log if phishing or scanner" RS, "fixed=1 BOOL.F=2 or_link=1 end=1");
    BASIS("evaluator-basis-BOOL-jump", 0, PO "log if phishing and c2" RS, "fixed=1 BOOL.F=1 jump=1 end=1");
    BASIS("evaluator-basis-BOOL-deny", 0, PO "deny if c2" RS, "fixed=1 BOOL.T=1 fire_deny=1");
    for (i = 1; i < EV_NATOMS; i++) {
        const ev_atom_t *t = &ev_atoms[i];
        char p1[256], v1[128];
        snprintf(name, sizeof name, "evaluator-basis-%s-F", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s" RS, t->f);
        snprintf(v1, sizeof v1, "fixed=1 %s.F=1 end=1", t->kind);
        BASIS(name, 0, p1, v1);
        snprintf(name, sizeof name, "evaluator-basis-%s-TF", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s and %s" RS, t->t, t->f);
        snprintf(v1, sizeof v1, "fixed=1 %s.T=1 %s.F=1 end=1", t->kind, t->kind);
        BASIS(name, 0, p1, v1);
    }
    /* held out: each must be predicted exactly from the 25 above */
    BASIS("evaluator-basis-rules-4", 1, PO "log if phishing" RS PO "log if scanner" RS PO "log if state_actor" RS
          PO "log if phishing" RS, "fixed=1 BOOL.F=4 end=4");
    for (i = 0; i < EV_NATOMS; i++) {
        const ev_atom_t *t = &ev_atoms[i];
        char p1[384], v1[128];
        snprintf(name, sizeof name, "evaluator-basis-%s-TTF", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s and %s and %s" RS, t->t, t->t, t->f);
        snprintf(v1, sizeof v1, "fixed=1 %s.T=2 %s.F=1 end=1", t->kind, t->kind);
        BASIS(name, 1, p1, v1);
        if (i == 0u) { continue; }       /* BOOL's other four rows are solved rows above */
        snprintf(name, sizeof name, "evaluator-basis-%s-T", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s" RS, t->t);
        snprintf(v1, sizeof v1, "fixed=1 %s.T=1 fire_log=1", t->kind);
        BASIS(name, 1, p1, v1);
        snprintf(name, sizeof name, "evaluator-basis-%s-notT", t->kind);
        snprintf(p1, sizeof p1, PO "log if not %s" RS, t->t);
        snprintf(v1, sizeof v1, "fixed=1 %s.T=1 NOT=1 end=1", t->kind);
        BASIS(name, 1, p1, v1);
        snprintf(name, sizeof name, "evaluator-basis-%s-or2", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s or %s" RS, t->f, t->f);
        snprintf(v1, sizeof v1, "fixed=1 %s.F=2 or_link=1 end=1", t->kind);
        BASIS(name, 1, p1, v1);
        snprintf(name, sizeof name, "evaluator-basis-%s-jump", t->kind);
        snprintf(p1, sizeof p1, PO "log if %s and %s" RS, t->f, t->t);
        snprintf(v1, sizeof v1, "fixed=1 %s.F=1 jump=1 end=1", t->kind);
        BASIS(name, 1, p1, v1);
    }
    BASIS("evaluator-basis-SEV-deny", 1, PO "deny if listed >= low" RS, "fixed=1 SEV.T=1 fire_deny=1");
#undef BASIS

    /*
     * THE PRE-STAGE, THE PROGRAM RUNS AND THE FILLS, each a remainder of exact terms. Every row names in
     * its vector every term already measured, and the cost model derives the one the row is named for as
     * what is left, in this order:
     *   c_prestage    the empty floor, no context program; less its two finds (the hold-harmless lookup
     *                 and the tenant's), so each find is priced once, by its L
     *   c_run_ctx     a context program run (entry, the server slot aliased to the floor's on equal keys),
     *                 from a context whose one atom is `is unknown`: it fills NOTHING, so nothing but the
     *                 run is left over
     *   c_key2        the server slot keyed apart on distinct keys (the same row, two addresses)
     *   c_run_floor   a non-empty floor's run beyond the empty one c_prestage holds
     *   c_fill@<p>    one entry of plane p filled, less its find: a context whose one atom reads p, on one
     *                 address (the tenant's, which the pre-stage fills on the floor's address, on two)
     * c_fill:<schema>, the term the composed bound names, is the MAXIMUM over its planes, so the bound
     * stays an upper bound whichever plane a slot fills. (It was a slope across rows that filled different
     * planes: a mean, fractional, and under clang 31 instructions short of a 1.25M-instruction request.)
     */
#define PRE "c_prestage=1 find:lookup-hh@basis=1 find:lookup-tenant@basis=1"
    sb_add(&ve, "find:lookup-hh@basis=1 find:lookup-tenant@basis=1");
    ev_add("evaluator-prestage", 100000u, W_BASIS, A_DISTINCT, NULL, NULL, &ve, NULL, NULL);
    sb_add(&cx, PO "log if tor_exit is unknown" RS);
    sb_add(&ve, PRE " ISUNK.F=1 end=1");
    ev_add("evaluator-run-ctx", 100000u, W_BASIS, A_EQUAL, NULL, &cx, &ve, NULL, NULL);
    sb_add(&cx, PO "log if tor_exit is unknown" RS);
    sb_add(&ve, PRE " ISUNK.F=1 end=1 c_run_ctx=1");
    ev_add("evaluator-run-key2", 100000u, W_BASIS, A_DISTINCT, NULL, &cx, &ve, NULL, NULL);
    /*
     * Behind a same-box proxy: a hold-harmless floor before a distinct server address. The floor's steps
     * are exempt (no tenant find, no floor run) and step 4 runs on the server's slot with no lookup of its
     * own (POLICY.md section 3.2), so the row is below the bound c_prestage + c_run_ctx + c_key2 prices
     * and carries no vector: it is held to its band, where a second hold-harmless search would show.
     */
    sb_add(&cx, PO "log if tor_exit is unknown" RS);
    ev_add("evaluator-hh-key2", 100000u, W_BASIS, A_HH_KEY2, NULL, &cx, NULL, NULL, NULL);
    sb_add(&fl, FL "log if tor_exit is unknown" RS);
    sb_add(&ve, PRE " ISUNK.F@floor=1 end@floor=1");
    ev_add("evaluator-run-floor", 100000u, W_BASIS, A_EQUAL, &fl, NULL, &ve, NULL, NULL);
    {
        /*
         * One atom per plane and outcome, with the terms it runs besides the fill. A fill's cost was
         * measured to depend on where it happens (under clang 18, by up to 11 instructions), so each is
         * measured everywhere a slot can fill: as the rule's FIRST atom and as a LATER one (after an
         * `is unknown` that fills nothing), and in each of the three places a program runs: the floor
         * pass (`@floor`), the context pass after an empty floor (the default slot's case) and the
         * context pass after a floor that ran (`@ctx2`, the worst slots' case). The outcome is varied
         * too, every outcome the world's record can give, and c_fill:<schema> is the costliest of all.
         * And a fill that FOLLOWS another fill in its rule (`-afterfill`) costs 10 instructions more
         * again under clang 18 (measured through the eight-plane rule: +10 at every fill after the
         * first), so on the two worst-slot passes each plane is also filled after a fill of another
         * plane, priced by that lead's own first-position row. tor holds no TRUE record (a TRUE one is not
         * needed by any slot) and the tenant's TRUE would end the request at the tenant step. Anonymizer
         * runs in the FULL world, where its view is armed (in the BASIS world it is NULL).
         */
        static const struct { const char *plane, *tag, *atom, *terms; ev_world_t w; } F[] = {
            { "reputation",       "F", "listed >= critical",   "SEV.F=1 end=1",       W_BASIS },
            { "reputation",       "T", "listed >= low",        "SEV.T=1 fire_log=1",  W_BASIS },
            { "tor",              "F", "tor_exit",             "BOOL.F=1 end=1",      W_BASIS },
            { "rpki-unreachable", "T", "rpki_unreachable",     "BOOL.T=1 fire_log=1", W_BASIS },
            { "routing",          "F", "rpki == invalid",      "EQ8.F=1 end=1",       W_BASIS },
            { "routing",          "T", "rpki == valid",        "EQ8.T=1 fire_log=1",  W_BASIS },
            { "anonymizer",       "F", "vpn",                  "BOOL.F=1 end=1",      W_FULL  },
            { "anonymizer",       "T", "proxy",                "BOOL.T=1 fire_log=1", W_FULL  },
            { "threat",           "F", "phishing",             "BOOL.F=1 end=1",      W_BASIS },
            { "threat",           "T", "c2",                   "BOOL.T=1 fire_log=1", W_BASIS },
            { "registry",         "F", "registry_rir == arin", "EQ8.F=1 end=1",       W_BASIS },
            { "registry",         "T", "registry_rir == ripe", "EQ8.T=1 fire_log=1",  W_BASIS },
        };
        for (i = 0; i < sizeof F / sizeof F[0]; i++) {
            /* the opening atom that fills nothing: TRUE in each world, so the chain goes on to the fill */
            const char *lead = F[i].w == W_FULL ? "tor_exit is not unknown and " : "proxy is unknown and ";
            const char *leadv = F[i].w == W_FULL ? "ISUNK.F=1 NOT=1" : "ISUNK.T=1";
            uint32_t pos, where;

            for (pos = 0; pos < 2u; pos++) {
                for (where = 0; where < 3u; where++) {
                    /* where: 0 the context after an empty floor, 1 after a floor that ran, 2 the floor */
                    snprintf(name, sizeof name, "evaluator-fill-%s@%s%s%s", F[i].plane, F[i].tag,
                             pos ? "-later" : "", where == 1u ? "@ctx2" : where == 2u ? "@floor" : "");
                    if (where == 2u) {
                        sb_add(&fl, FL "log if %s%s" RS, pos ? lead : "", F[i].atom);
                        sb_add(&ve, PRE " c_run_floor=1");
                        if (pos) { ev_atfloor(&ve, leadv); }
                        ev_atfloor(&ve, F[i].terms);
                        sb_add(&ve, " find:lookup-%s@basis=1", F[i].plane);
                        ev_add(name, 20000u, F[i].w, A_EQUAL, &fl, NULL, &ve, NULL, NULL);
                        continue;
                    }
                    if (where == 1u) { sb_add(&fl, FL "log if tor_exit is unknown" RS); }
                    sb_add(&cx, PO "log if %s%s" RS, pos ? lead : "", F[i].atom);
                    sb_add(&ve, PRE " c_run_ctx=1 %s%s %s find:lookup-%s@basis=1",
                           where == 1u ? "c_run_floor=1 ISUNK.F@floor=1 end@floor=1 " : "", pos ? leadv : "", F[i].terms,
                           F[i].plane);
                    ev_add(name, 20000u, F[i].w, A_EQUAL, where == 1u ? &fl : NULL, &cx, &ve, NULL, NULL);
                }
            }
        }
        /* the tenant entry: the server's, on a second address (the floor's is the pre-stage's) */
        /* after a fill of another plane, once every first-position row the leads are priced by is measured */
        for (i = 0; i < sizeof F / sizeof F[0]; i++) {
            uint32_t where;
            for (where = 1; where < 3u; where++) {
                /* after a fill of another plane: c2 (threat), or listed >= low for the threat plane itself */
                int th = !strcmp(F[i].plane, "threat");
                const char *ld = th ? "listed >= low and " : "c2 and ";
                char lv[160];
                snprintf(lv, sizeof lv, "%s=1 c_fill@%s@T%s=1 find:lookup-%s@basis=1", th ? "SEV.T" : "BOOL.T",
                         th ? "reputation" : "threat", where == 1u ? "@ctx2" : "@floor", th ? "reputation" : "threat");
                snprintf(name, sizeof name, "evaluator-fill-%s@%s-afterfill%s", F[i].plane, F[i].tag,
                         where == 1u ? "@ctx2" : "@floor");
                if (where == 2u) {
                    sb_add(&fl, FL "log if %s%s" RS, ld, F[i].atom);
                    sb_add(&ve, PRE " c_run_floor=1");
                    ev_atfloor(&ve, lv);
                    ev_atfloor(&ve, F[i].terms);
                    sb_add(&ve, " find:lookup-%s@basis=1", F[i].plane);
                    ev_add(name, 20000u, F[i].w, A_EQUAL, &fl, NULL, &ve, NULL, NULL);
                } else {
                    sb_add(&fl, FL "log if tor_exit is unknown" RS);
                    sb_add(&cx, PO "log if %s%s" RS, ld, F[i].atom);
                    sb_add(&ve, PRE " c_run_floor=1 ISUNK.F@floor=1 end@floor=1 c_run_ctx=1 %s %s find:lookup-%s@basis=1", lv,
                           F[i].terms, F[i].plane);
                    ev_add(name, 20000u, F[i].w, A_EQUAL, &fl, &cx, &ve, NULL, NULL);
                }
            }
        }
        {
            /* the tenant entry, only ever filled by a context on the server's address (the floor's is the
             * pre-stage's): first and later, after an empty floor and after a floor that ran */
            uint32_t pos, where;
            for (pos = 0; pos < 2u; pos++) {
                for (where = 0; where < 2u; where++) {
                    snprintf(name, sizeof name, "evaluator-fill-tenant@F%s%s", pos ? "-later" : "", where ? "@ctx2" : "");
                    if (where) { sb_add(&fl, FL "log if tor_exit is unknown" RS); }
                    sb_add(&cx, PO "log if %stenant_deny" RS, pos ? "proxy is unknown and " : "");
                    sb_add(&ve, PRE " c_run_ctx=1 c_key2=1 %s%sBOOL.F=1 end=1 find:lookup-tenant@basis=1",
                           where ? "c_run_floor=1 ISUNK.F@floor=1 end@floor=1 " : "", pos ? "ISUNK.T=1 " : "");
                    ev_add(name, 20000u, W_BASIS, A_DISTINCT, where ? &fl : NULL, &cx, &ve, NULL, NULL);
                }
            }
        }
    }
#undef PRE

    /*
     * evaluator-default: decision 3's four rules under mode deny, over the default planes and the named q4
     * stream (one address per request, so one memo slot). Its soundness terms are per-request means over
     * the stream it runs, computed from the planes it was written with, by outcome: a request inside the
     * hold-harmless table is exempt at the pre-stage and runs no rule (it pays c_prestage and the table's
     * lookup only); otherwise rule 1 denies a critical listing and rule 2 a high one, each `deny` that
     * fires ending the request, and a request that reaches rules 3 and 4 fills tor and rpki-unreachable,
     * whose `log` fires for every member (every record of those two planes carries its flag).
     */
    {
        uint32_t k, n = 200000u, ex = 0, r1 = 0, r2 = 0, r4 = 0, rp = 0, tr = 0, wd = 0;
        for (k = 0; k < n; k++) {
            int64_t i4;
            uint8_t sev;
            int bit = 0;
            if (dp_ref(&hh4, q4[k]) >= 0) { ex++; continue; }
            i4 = dp_ref(&rep4, q4[k]);
            sev = i4 >= 0 ? (uint8_t)(dp_rep_sev4[i4] & 0x0fu) : 0u;
            if (sev >= WE_SEV_CRITICAL) { r1++; }
            else if (sev >= WE_SEV_HIGH) { r2++; }
            else {
                r4++;
                if (dp_ref(&rpki4, q4[k]) >= 0) { rp++; bit = 1; }
                if (dp_ref(&tor4, q4[k]) >= 0) { tr++; bit = 1; }
            }
            wd += bit;                       /* the context bitmap's one word non-empty: a word's overhead */
        }
        sb_add(&cx, PO "deny if listed >= critical" RS PO "deny if listed >= high" RS
                    PO "log if rpki_unreachable" RS PO "log if tor_exit" RS);
        sb_add(&so, "c_prestage=1 lookup-hh@16=1 c_run_ctx=%u/%u SEV.T=%u/%u SEV.F=%u/%u BOOL.T=%u/%u BOOL.F=%u/%u fire_deny=%u/%u "
                    "fire_log=%u/%u end=%u/%u c_fill:format1=%u/%u lookup-reputation@q4=%u/%u "
                    "c_fill:membership=%u/%u lookup-tor@q4=%u/%u lookup-rpki-unreachable@q4=%u/%u",
               n - ex, n, r1 + r2, n, r2 + 2u * r4, n, rp + tr, n, 2u * r4 - rp - tr, n, r1 + r2, n,
               rp + tr, n, r2 + 2u * r4 + 2u * r4 - rp - tr, n, n - ex, n, n - ex, n,
               2u * r4, n, r4, n, r4, n);
        ev_add("evaluator-default", n, W_DEFAULT, A_STREAM, NULL, &cx, NULL, &so, NULL);

        /*
         * THE MODULE ROWS OF THE DEFAULT STREAM, and the twins they are read against. ev_one fills the
         * eight views before each request and nulls them after; evaluator-default-sv sets them once
         * before the loop, so evaluator-default less it is the harness's own view work, c_harness_view,
         * which no module pays. A module row less its twin, plus c_harness_view, is the module's work
         * alone: c_mod_fixed, c_view per bound plane the two programs or the tenant reference, and the
         * decision's counts, one direct count on every request a rule or the pre-stage decided
         * (c_cnt_rule and c_cnt_exempt, two code paths), c_count per log bit that fired, in the fractions
         * the loop above measured. module-default-tenant binds the synthetic tenant plane as well (one
         * more view; its twin's pre-stage finds the tenant entry) and is held out: predicted exactly.
         */
        {
            ev_slot_t *e;
            char mv[256];

            for (k = 0; k < n; k++) {
                if ((q4[k] & 0xffffff00u) == (EA & 0xffffff00u) || (q4[k] & 0xffffff00u) == (EB & 0xffffff00u)) {
                    fprintf(stderr, "the default stream's request %u is inside the synthetic tenant plane's ranges, so the "
                                    "tenant rows' counts would not be the default stream's\n", k);
                    exit(2);
                }
            }
            sb_add(&cx, DEFAULT4);
            e = ev_add("evaluator-default-sv", n, W_DEFAULT, A_STREAM, NULL, &cx, NULL, NULL, NULL);
            e->kind = K_EVAL_SV;
            sb_add(&cx, DEFAULT4);
            e = ev_add("evaluator-default-tenant", n, W_DEFAULT, A_STREAM, NULL, &cx, NULL, NULL, NULL);
            e->views = (uint8_t)(ev_world_views(W_DEFAULT) | (1u << (WE_PLANE_TENANT - 1u)));
            snprintf(mv, sizeof mv, "c_cnt_rule=%u/%u c_cnt_exempt=%u/%u c_count@ctx0=%u/%u c_word@ctx0=%u/%u", r1 + r2, n, ex, n, rp + tr, n, wd, n);
            sb_add(&ve, "twin:evaluator-default=1 c_harness_view=-1 c_mod_fixed=1 c_view=3 %s", mv);
            ev_add_module("module-default", "evaluator-default", K_MOD, &ve, NULL);
            /* RELATIVE to module-default (the same stream through the same inlined code, one bound plane more and
             * whatever the evaluator twins' difference carries), this row solves the tenant view's own cost: the
             * tenant's mask bit is a constant the compiler may fold (clang 18 on x86_64 reads it 2 instructions
             * cheaper than a program's view), so c_view@tenant stands apart from c_view and module-views@8, the
             * one view row that reads the tenant, holds the pair exactly */
            sb_add(&ve, "twin:evaluator-default-tenant=1 slot:evaluator-default=-1 slot:module-default=1 c_view@tenant=1");
            ev_add_module("module-default-tenant", "evaluator-default-tenant", K_MOD, &ve, NULL);
            /* the export pass of the default set after the decision, priced over the decision alone */
            sb_add(&ve, "slot:module-default=1 c_export=1");
            ev_add_module("module-export", "evaluator-default", K_MOD_EXPORT, &ve, NULL);
            /* nginx's pre-decision variable path: three planes read in the rewrite phase, and one */
            sb_add(&ve, "slot:module-default=1 c_prerewrite=1");
            ev_add_module("module-var-prerewrite", "evaluator-default", K_MOD_VAR3, &ve, NULL);
            sb_add(&ve, "slot:module-default=1 c_prerewrite@1=1");
            ev_add_module("module-var-prerewrite@1", "evaluator-default", K_MOD_VAR1, &ve, NULL);
        }
    }

    /*
     * evaluator-memo: the slot C2 runs on. Thirty-two single-atom `log` rules, every one reading the threat
     * plane on one address, all FALSE, after an empty floor: the evaluator fills the threat entry ONCE and
     * the other 31 atoms read the memo, so a memo that never hits (WE_TEST_NO_MEMO_HIT) refills on every
     * atom and costs the slot about a fill per rule more. POLICY.md puts row C2 on evaluator-default, whose
     * four rules read three planes once each, so there the mutant adds a single refill and stays inside
     * the band: that row is kept, as a recorded non-detection, and this one is the control.
     */
    {
        static const char *const memo_atoms[3] = { "phishing", "scanner", "state_actor" };
        for (i = 0; i < 32u; i++) { sb_add(&cx, PO "log if %s" RS, memo_atoms[i % 3u]); }
        ev_add("evaluator-memo", 20000u, W_BASIS, A_EQUAL, NULL, &cx, NULL, NULL, NULL);
    }

    /*
     * evaluator-dr-64 and evaluator-dr-128: the evaluator's straight-line family, gate/straight-64.policy
     * and gate/straight-128.policy (N rules of `log if c2`, one plane, one address, two operations a rule,
     * no jump), read verbatim after an empty floor. The gate takes data references PER RULE as the exact
     * difference between the two and holds it with no tolerance: a +-10% instruction band cannot see one
     * more load in each rule (about 4% of a one-atom rule's instructions), an exact count can. A build
     * with the evaluator refuses a missing file by name; a dark build never runs the slot.
     */
    {
        uint32_t nr;
        for (nr = 64; nr <= 128u; nr += 64u) {
            char path[64], buf[4096];
            size_t got;
            FILE *pf;
            snprintf(path, sizeof path, "gate/straight-%u.policy", nr);
            pf = fopen(path, "rb");
            if (pf != NULL) {
                while ((got = fread(buf, 1, sizeof buf - 1u, pf)) > 0) { buf[got] = '\0'; sb_add(&cx, "%s", buf); }
                fclose(pf);
            } else {
#ifdef WE_HAVE_EVAL
                fprintf(stderr, "evaluator-dr-%u: the straight-line family %s is missing\n", nr, path);
                exit(2);
#endif
            }
            snprintf(name, sizeof name, "evaluator-dr-%u", nr);
            ev_add(name, 20000u, W_BASIS, A_EQUAL, NULL, &cx, NULL, NULL, NULL);
        }
    }
#ifdef WE_CG_EXTRALOAD
    /* the planted control's driver: the mutant reaches only this unit (we_eval.h allows it here) */
#endif

    /*
     * evaluator-live: a context program of single-atom routing rules over the LIVE routing plane (the
     * RouteViews table as a plane file), one address per request, three in four inside a range and one
     * just past one. No rule takes a jump, so C5 holds it line for line; its verdicts are the reference
     * interpreter's (check-live's differential leg) and its cost is banded like every slot.
     */
    ev_sets(&fl);
    sb_add(&cx, PO "deny if rpki == invalid" RS PO "log if asn in @t" RS PO "log if country in { NL DE US }" RS
                PO "log if anycast" RS);
    ev_add("evaluator-live", 20000u, W_LIVE, A_LIVE, &fl, &cx, NULL, NULL, NULL);

    /*
     * evaluator-worst: the shape gate/evaluator-worst.tsv records, in the floor and in the context
     * program, on two distinct addresses in the BASIS world. cost-model.py holds the shape to the maximum
     * over every feasible count vector for this toolchain's constants and names the shape to rebuild to.
     * The counts each program executes come from the builder itself, by outcome.
     */
    ws = ev_worst_shape("gate/evaluator-worst.tsv");
    {
        const char *kind = ws.atom->kind;
        sb_t snd = { 0 };
        ev_counts_t cf = { 0 }, cc = { 0 };

        ev_sets(&fl);
        ev_worst_program(&fl, "floor http", ws, 0, &cf);
        ev_worst_program(&cx, "policy http/server:s", ws, 0, &cc);
        sb_add(&pr, "%s.T=%u %s.F=%u NOT=%u end=%u or_link=%u %s.T@floor=%u %s.F@floor=%u NOT@floor=%u end@floor=%u "
                    "or_link@floor=%u", kind, cc.t, kind, cc.f, cc.nots, cc.rules, cc.or_links,
               kind, cf.t, kind, cf.f, cf.nots, cf.rules, cf.or_links);
        sb_add(&snd, "%s.T=%u %s.F=%u NOT=%u end=%u or_link=%u %s.T@floor=%u %s.F@floor=%u NOT@floor=%u end@floor=%u "
                     "or_link@floor=%u c_prestage=1 lookup-hh@basis=1 lookup-tenant@basis=1 c_run_floor=1 c_run_ctx=1 c_key2=1",
               kind, cc.t, kind, cc.f, cc.nots, cc.rules, cc.or_links, kind, cf.t, kind, cf.f, cf.nots, cf.rules, cf.or_links);
        if (strcmp(ws.atom->schema, "-") != 0) {
            sb_add(&snd, " c_fill:%s=2 lookup-%s@basis=2", ws.atom->schema, ws.atom->plane);
        }
        /* the BASIS world: the shape reads its kind's plane and the tenant entry, and `is unknown` needs
         * the one NULL view */
        ev_add("evaluator-worst", 2000u, W_BASIS, A_DISTINCT, &fl, &cx, NULL, &snd, &pr);

        /*
         * evaluator-worst-lines: rule 1 of each program reads eight distinct planes (all armed: the FULL
         * world), so two distinct addresses make 16 fills; the other rules keep the shape. Rule 1 runs,
         * per program, BOOL TRUE three times (c2, rpki_unreachable, proxy) and FALSE twice (tenant_deny
         * under its `not`, tor_exit last), SEV and two EQ8 TRUE, and one NOT. In the FULL world no
         * `is unknown` is TRUE, so this slot refuses to build an ISUNK shape.
         */
        if (!strcmp(kind, "ISUNK")) {
            fprintf(stderr, "evaluator-worst-lines cannot be built for an ISUNK shape: no plane is UNKNOWN in the FULL world\n");
            exit(2);
        }
        memset(&cf, 0, sizeof cf);
        memset(&cc, 0, sizeof cc);
        ev_sets(&fl);
        ev_worst_program(&fl, "floor http", ws, 1, &cf);
        ev_worst_program(&cx, "policy http/server:s", ws, 1, &cc);
        {
            int same = !strcmp(kind, "BOOL") || !strcmp(kind, "SEV") || !strcmp(kind, "EQ8");
            if (same) {
                fprintf(stderr, "evaluator-worst-lines: a %s shape shares rule 1's kinds; give its counts their own sum\n", kind);
                exit(2);
            }
            sb_add(&snd, "%s.T=%u %s.F=%u BOOL.T=3 BOOL.F=2 SEV.T=1 EQ8.T=2 NOT=%u end=%u or_link=%u "
                         "%s.T@floor=%u %s.F@floor=%u BOOL.T@floor=3 BOOL.F@floor=2 SEV.T@floor=1 EQ8.T@floor=2 "
                         "NOT@floor=%u end@floor=%u or_link@floor=%u "
                         "c_prestage=1 lookup-hh@basis=1 c_run_floor=1 c_run_ctx=1 c_key2=1",
                   kind, cc.t, kind, cc.f, cc.nots + 1u, cc.rules + 1u, cc.or_links,
                   kind, cf.t, kind, cf.f, cf.nots + 1u, cf.rules + 1u, cf.or_links);
            for (i = 0; i < 8u; i++) {
                const char *sch = !strcmp(planes8[i], "reputation") ? "format1"
                                : (!strcmp(planes8[i], "routing") || !strcmp(planes8[i], "registry")) ? "routing" : "membership";
                if (!strcmp(planes8[i], "tenant")) {
                    /* the floor address's tenant fill is the pre-stage's (in c_prestage); its find is not */
                    sb_add(&snd, " c_fill:membership=1 lookup-tenant@basis=2");
                } else {
                    sb_add(&snd, " c_fill:%s=2 lookup-%s@basis=2", sch, planes8[i]);
                }
            }
            ev_add("evaluator-worst-lines", 2000u, W_FULL, A_DISTINCT, &fl, &cx, NULL, &snd, NULL);
        }
    }

    /*
     * THE PRE-STAGE STREAM: the default policy over pq4, hold-harmless inside and critical-listed
     * alternating, so every second decision is exempt and fills nothing and the other is the first
     * rule's deny, which fills the reputation entry. The export of the default set then fills what the
     * decision did not, three planes and then two, 5/2 lazy fills a request, priced by c_lazy over the
     * decision alone and the export's own renders (c_export, from the default stream).
     */
    sb_add(&cx, DEFAULT4);
    ev_add("evaluator-default-prestage", 20000u, W_DEFAULT, A_PRESTAGE, NULL, &cx, NULL, NULL, NULL);
    ev_add_module("module-default-prestage", "evaluator-default-prestage", K_MOD, NULL, NULL);
    sb_add(&ve, "slot:module-default-prestage=1 c_export=1 c_lazy=5/2");
    ev_add_module("module-export-prestage", "evaluator-default-prestage", K_MOD_PRESTAGE, &ve, NULL);

    /*
     * THE DEFAULT POLICY IN THE SYNTHETIC WORLD, every plane armed: on EA and EB the first two rules are
     * FALSE (a medium listing), the third fires (the rpki-unreachable record) and the fourth is FALSE, so
     * the default allow decides: one log bit, no direct count, four views. module-export-all renders all
     * 25 attributes after it, the two countries among them, filling the four planes the decision left.
     */
    sb_add(&cx, DEFAULT4);
    ev_add("evaluator-default-full", 20000u, W_FULL, A_EQUAL, NULL, &cx, NULL, NULL, NULL);
    ev_add_module("module-default-full", "evaluator-default-full", K_MOD, NULL, NULL);
    sb_add(&ve, "slot:module-default-full=1 c_export_all=1");
    ev_add_module("module-export-all", "evaluator-default-full", K_MOD_EXPORT_ALL, &ve, NULL);

    /*
     * THE VIEW ROWS, k = 1 to 8: one program whose first rule, `deny if c2`, ends every request, and k - 1
     * `log` rules after it, each on another plane, that never run. The k planes enter the context's
     * mask and exactly those k are bound, so the module takes k acquire loads and looks nothing up beyond
     * the first rule's threat entry; the twins arm the same k. 1, 2, 4 and 8 solve c_view and c_mod_fixed
     * beside c_cnt_rule; 3, 5, 6 and 7 are held out and predicted exactly.
     */
    /* THE ALLOW ROW: one context rule that ends FALSE, so the default allow decides, nothing is counted and
     * no bitmap word is non-empty: c_mod_fixed with one view and nothing else */
    sb_add(&cx, PO "log if phishing" RS);
    ev_add("evaluator-allow", 20000u, W_FULL, A_EQUAL, NULL, &cx, NULL, NULL, NULL)->views = (uint8_t)(1u << (WE_PLANE_THREAT - 1u));
    sb_add(&ve, "twin:evaluator-allow=1 c_harness_view=-1 c_mod_fixed=1 c_view=1");
    ev_add_module("module-allow", "evaluator-allow", K_MOD, &ve, NULL);
    for (i = 1; i <= 8u; i++) {
        uint32_t j;
        uint8_t views = 0;
        char tw[48];

        for (j = 0; j < i; j++) {
            sb_add(&cx, PO "%s if %s" RS, j == 0u ? "deny" : "log", md_vatoms[j].atom);
            views |= (uint8_t)(1u << (md_vatoms[j].plane - 1u));
        }
        snprintf(tw, sizeof tw, "evaluator-views@%u", i);
        ev_add(tw, 20000u, W_FULL, A_EQUAL, NULL, &cx, NULL, NULL, NULL)->views = views;
        if (i == 1u) {
            /* the harness's own view work, c_harness_view, measured where it is exact: the same one-rule
             * program and one path with the views set once before the loop. (The default stream's own
             * static-views twin gives a fractional figure, 48.047 on gcc 13: the evaluator is inlined into
             * each harness function and compiled differently in each, so across that stream's many request
             * shapes the two differ by more than the view stores; the model prints that pair as a note.) */
            ev_slot_t *e;

            sb_add(&cx, PO "deny if c2" RS);
            e = ev_add("evaluator-views@1-sv", 20000u, W_FULL, A_EQUAL, NULL, &cx, NULL, NULL, NULL);
            e->views = views;
            e->kind = K_EVAL_SV;
        }
        snprintf(name, sizeof name, "module-views@%u", i);
        if (i == 8u) {
            sb_add(&ve, "twin:%s=1 c_harness_view=-1 c_mod_fixed=1 c_view=7 c_view@tenant=1 c_cnt_rule=1 held=1", tw);
        } else {
            sb_add(&ve, "twin:%s=1 c_harness_view=-1 c_mod_fixed=1 c_view=%u c_cnt_rule=1%s", tw, i,
                   i == 3u || (i >= 5u && i <= 7u) ? " held=1" : "");
        }
        ev_add_module(name, tw, K_MOD, &ve, NULL);
    }

    /*
     * THE COUNT ROWS: k `log if c2` rules, every one firing, then the default allow, which counts
     * nothing: k bits in the context bitmap and no direct count, so 1 and 64 solve c_count beside
     * c_mod_fixed. THE WORST ROW: 256 floor rules and 255 context rules of the same, then the context's
     * deny: 511 bits across both bitmaps and one direct count, held to the composed bound with the
     * module's own terms, and predicted exactly.
     */
    /*
     * THE COUNT ROWS, every bitmap word on its own. The scan over the two bitmaps' eight words is unrolled
     * by the compilers, and each word's copy has a cost of its own (on x86_64 gcc 13.3 the floor's words 1
     * to 3 cost 15 instructions over the first word's figure: an x86_64 baseline write run, module-worst
     * 6331 against 6316 predicted from word 0 alone), so each word w of each pass has c_word@<pass><w>,
     * what the word costs non-empty over empty, and c_count@<pass><w> per bit set in it. A word is reached
     * only through rules that FIRE: a rule that ends FALSE costs the module's inlined evaluator one
     * instruction less than the harness's copy on gcc 13.3 aarch64, so leading FALSE rules put evaluator
     * code into the twin difference (a first shape solved floor1 to -63, floor2 to -127, floor3 to -191),
     * where leading firing rules are priced by the words they set. So the rows are cumulative: 64(w + 1)
     * rules fill words 0 to w, 64w + 1 rules fill words 0 to w - 1 and set one bit of word w, and the two
     * solve word w; 96 and 224 (a half word after one and after three full words) are held out, as is the
     * worst row. The floor rows' context ends FALSE and the context rows' floor is empty, as everywhere.
     */
    {
        static const struct { const char *pass; const char *dir; } P[2] = { { "floor", FL }, { "ctx", PO } };
        static const uint32_t N[] = { 1, 64, 65, 96, 128, 129, 192, 193, 224, 256 };
        uint32_t pi, ni;

        for (pi = 0; pi < 2u; pi++) {
            for (ni = 0; ni < sizeof N / sizeof N[0]; ni++) {
                uint32_t n = N[ni], j, w, full = n / 64u, rest = n % 64u;
                char tw[48], terms[512];
                size_t o = 0;
                sb_t *prog = pi == 0u ? &fl : &cx;

                for (j = 0; j < n; j++) { sb_add(prog, "%slog if c2" RS, P[pi].dir); }
                if (pi == 0u) { sb_add(&cx, PO "log if phishing" RS); }
                snprintf(tw, sizeof tw, "evaluator-count@%u-%s", n, P[pi].pass);
                ev_add(tw, 20000u, W_FULL, A_EQUAL, pi == 0u ? &fl : NULL, &cx, NULL, NULL, NULL)->views = (uint8_t)(1u << (WE_PLANE_THREAT - 1u));
                for (w = 0; w < full; w++) {
                    o += (size_t)snprintf(terms + o, sizeof terms - o, " c_word@%s%u=1 c_count@%s%u=64", P[pi].pass, w, P[pi].pass, w);
                }
                if (rest != 0u) {
                    o += (size_t)snprintf(terms + o, sizeof terms - o, " c_word@%s%u=1 c_count@%s%u=%u", P[pi].pass, full, P[pi].pass, full, rest);
                }
                snprintf(name, sizeof name, "module-count@%u-%s", n, P[pi].pass);
                sb_add(&ve, "twin:%s=1 c_harness_view=-1 c_mod_fixed=1 c_view=1%s%s", tw, terms, n == 96u || n == 224u ? " held=1" : "");
                ev_add_module(name, tw, K_MOD, &ve, NULL);
            }
        }
    }
    for (i = 0; i < 256u; i++) { sb_add(&fl, FL "log if c2" RS); }
    for (i = 0; i < 255u; i++) { sb_add(&cx, PO "log if c2" RS); }
    sb_add(&cx, PO "deny if c2" RS);
    ev_add("evaluator-modworst", 2000u, W_FULL, A_EQUAL, &fl, &cx, NULL, NULL, NULL)->views = (uint8_t)(1u << (WE_PLANE_THREAT - 1u));
#define WORST_WORDS "c_word@floor0=1 c_count@floor0=64 c_word@floor1=1 c_count@floor1=64 c_word@floor2=1 c_count@floor2=64 " \
                    "c_word@floor3=1 c_count@floor3=64 c_word@ctx0=1 c_count@ctx0=64 c_word@ctx1=1 c_count@ctx1=64 " \
                    "c_word@ctx2=1 c_count@ctx2=64 c_word@ctx3=1 c_count@ctx3=63"
    sb_add(&ve, "twin:evaluator-modworst=1 c_harness_view=-1 c_mod_fixed=1 c_view=1 " WORST_WORDS " c_cnt_rule=1 held=1");
    sb_add(&so, "BOOL.T@floor=256 fire_log@floor=256 c_run_floor=1 BOOL.T=256 fire_log=255 fire_deny=1 c_run_ctx=1 "
                "c_prestage=1 lookup-hh@basis=1 c_fill:membership=1 lookup-threat@basis=1 "
                "c_mod_fixed=1 c_view=1 " WORST_WORDS " c_cnt_rule=1");
#undef WORST_WORDS
    ev_add_module("module-worst", "evaluator-modworst", K_MOD, &ve, &so);
    free(ve.p); free(so.p); free(pr.p);
}

#ifndef WE_TRACE
static void ev_print_slots(void)
{
    uint32_t i;
    ev_build_slots();
    printf("# slot\trequests\tvector\tsound\tprogram\n");
    for (i = 0; i < nev; i++) {
        printf("%s\t%u\t%s\t%s\t%s\n", ev[i].slot, ev[i].requests, ev[i].vector, ev[i].sound, ev[i].program);
    }
}

/*
 * THE REFERENCE VERDICTS' INPUT. `cases <slot> <n>` writes the slot's first n requests as a case file
 * for the reference interpreter (policy_ref.py --cases, whose format its own header states): the
 * slot's directives, then per request the two addresses, every plane's state and each address's
 * record on every plane the slot's world arms, exactly as ew_build and dp_build wrote them. `make
 * verdicts` runs the interpreter over it and keeps its verdict lines as gate/expected/<slot>.verdicts,
 * which cachegrind-gate.sh holds the C evaluator's verdicts to before it measures a slot. Needs no
 * evaluator: the world is this driver's, and the reading of it is the interpreter's.
 */
static const char *const ev_plane_names[WE_PLANE_MAX + 1u] WE_CG_PAGE = {
    NULL, "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

static void ev_case_dirs(const char *recs)
{
    const char *p = recs;
    while (p != NULL && *p != '\0') {
        const char *e = strstr(p, RS);
        size_t n = e != NULL ? (size_t)(e - p) : strlen(p);
        if (n > 0u) { printf("dir %.*s\n", (int)n, p); }
        p = e != NULL ? e + strlen(RS) : NULL;
    }
}

static void ev_case_addr(const char *who, uint32_t a)
{
    struct in_addr in;
    char buf[INET_ADDRSTRLEN];
    in.s_addr = htonl(a);
    printf("addr %s %s\n", who, inet_ntop(AF_INET, &in, buf, sizeof buf));
}

/* one address's record on every armed plane of the slot's world */
static void ev_case_recs(const ev_slot_t *s, const char *who, uint32_t a)
{
    if (s->world == W_LIVE) { lv_build(); }
    uint32_t p;
    if (s->world == W_LIVE) {
        uint32_t i = we_find4(&lv_route, a);
        if (i == WE_NO_RANGE) { printf("rec %s routing none\n", who); return; }
        {
            const uint8_t *r = rec4 + (size_t)i * 16u;
            uint32_t asn;
            uint16_t cc;
            memcpy(&asn, r + 4, 4);
            memcpy(&cc, r + 8, 2);
            printf("rec %s routing asn=%u country=%u rov=%u rir=%u flags=%u asn_rep=%u\n", who, asn, (unsigned)cc,
                   (unsigned)r[10], (unsigned)r[11], (unsigned)r[12], (unsigned)r[13]);
        }
        return;
    }
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        if (((s->views >> (p - 1u)) & 1u) == 0u) { continue; }               /* its view is NULL */
        if (s->world == W_DEFAULT && (p == WE_PLANE_REPUTATION || p == WE_PLANE_TOR || p == WE_PLANE_RPKI_UNREACHABLE)) {
            int64_t i;
            if (p == WE_PLANE_REPUTATION) {
                i = dp_ref(&rep4, a);
                if (i < 0) { printf("rec %s reputation none\n", who); }
                else { printf("rec %s reputation sev=%u\n", who, (unsigned)dp_rep_sev4[i]); }
            } else {
                i = dp_ref(p == WE_PLANE_TOR ? &tor4 : &rpki4, a);
                if (i < 0) { printf("rec %s %s none\n", who, ev_plane_names[p]); }
                else {
                    printf("rec %s %s flags=%u source=0 reason=0\n", who, ev_plane_names[p],
                           (unsigned)(p == WE_PLANE_TOR ? WE_MF_TOR_EXIT : WE_MF_RPKI_UNREACHABLE));
                }
            }
            continue;
        }
        if (p == WE_PLANE_REPUTATION) {
            printf("rec %s reputation sev=%u\n", who, (unsigned)WE_SEV_MEDIUM);
        } else if (p == WE_PLANE_ROUTING || p == WE_PLANE_REGISTRY) {
            printf("rec %s %s asn=500 country=528 rov=%u rir=%u flags=0 asn_rep=%u\n", who, ev_plane_names[p],
                   (unsigned)WE_ROV_VALID, (unsigned)WE_RIR_RIPE, (unsigned)WE_REP_REPUTABLE);
        } else {
            uint32_t fl = p == WE_PLANE_THREAT ? (WE_MF_C2 | WE_MF_BRUTEFORCE | WE_MF_SPAM)
                        : p == WE_PLANE_ANONYMIZER ? WE_MF_PROXY
                        : p == WE_PLANE_RPKI_UNREACHABLE ? WE_MF_RPKI_UNREACHABLE : 0u;
            printf("rec %s %s flags=%u source=0 reason=0\n", who, ev_plane_names[p], (unsigned)fl);
        }
    }
}

static int ev_cases(const char *slot, uint32_t n)
{
    uint32_t i, k, p;
    const ev_slot_t *s = NULL;
    const char *name = slot;

    ev_build_slots();
    for (i = 0; i < nev; i++) { if (!strcmp(ev[i].slot, slot)) { s = &ev[i]; } }
    if (s == NULL) { fprintf(stderr, "unknown evaluator slot %s\n", slot); return 2; }
    /* a module slot decides exactly as its twin does, so its cases are the twin's under its own name */
    if (s->twin != NULL) {
        const ev_slot_t *t = NULL;
        for (i = 0; i < nev; i++) { if (!strcmp(ev[i].slot, s->twin)) { t = &ev[i]; } }
        if (t == NULL) { fprintf(stderr, "%s: its twin %s is not in the table\n", slot, s->twin); return 2; }
        s = t;
    }
    printf("program %s c\n", name);
    ev_case_dirs(s->floor);
    ev_case_dirs(s->ctx);
    printf("run http/server:s\n");
    for (k = 0; k < n; k++) {
        uint32_t f, v;
        switch (s->addrs) {
        case A_EQUAL:    f = v = (k & 1u) ? EB : EA; break;
        case A_DISTINCT: f = (k & 1u) ? EB : EA; v = (k & 1u) ? EA : EB; break;
        case A_LIVE:     f = v = lv_addr(k); break;
        case A_PRESTAGE: f = v = pq4[k]; break;
        case A_HH_KEY2:  f = 0x7f000001u; v = (k & 1u) ? EB : EA; break;
        default:         f = v = q4[k]; break;
        }
        printf("case %s.%u\n", name, k);
        /* both contexts under mode deny (3), inferences off, as ad_conf configures them */
        printf("conf floor 3 0\nconf ctx 3 0\n");
        for (p = 1; p < WE_PLANE_MAX; p++) {
            /* a NULL view reads UNKNOWN, which the interpreter's case file spells as a stale plane */
            if (((s->views >> (p - 1u)) & 1u) == 0u) { printf("plane %s stale\n", ev_plane_names[p]); }
        }
        /* the tenant plane: NULL where the slot leaves it unarmed, else armed with no expiry (fresh at 0) */
        printf("tenant %s 0 0\n", ((s->views >> (WE_PLANE_TENANT - 1u)) & 1u) ? "fresh" : "null");
        ev_case_addr("floor", f);
        ev_case_addr("server", v);
        printf("flags 1 0\n");
        ev_case_recs(s, "floor", f);
        ev_case_recs(s, "server", v);
        printf("end\n");
    }
    return 0;
}
#endif
#endif /* the slot table */

#ifdef WE_HAVE_EVAL
#include "we_eval.h"
#include "we_policy.h"
#ifdef WE_TRACE
/* C6: every we_current() the module's request path takes is counted. The core's read is resolved here,
 * before its name is redirected, so we_module.h's inline functions call the counting one and nothing
 * else does; the production driver has no such wrapper. */
static uint64_t cg_views_read WE_CG_PAGE;
static void md_trace_handle(const void *p);    /* C5+: the handle's line, when a bound run is recording */
static inline const we_map_t *cg_current(we_handle_t *h) { cg_views_read++; md_trace_handle(&h->current); return we_current(h); }
#define we_current cg_current
#endif
/*
 * THE ONE COPY OF THE DECISION. Every evaluator row (ev_one, ev_one_sv) and every module row (through
 * we_mod_decide, which calls WE_MOD_DECIDE_COPY) runs this one noinline function, so the instructions of
 * the decision are the same instructions in both, and a module row less its evaluator twin is the module's
 * own work: its views, its parks, its counts and its renders. It is that by construction, where it was by
 * the luck of two inlinings compiling alike (they did not: one instruction apart on a path, which the
 * module basis read as the module's cost). What each row measures:
 *   - an evaluator row: the decision, plus the call into this copy and the harness's view stores; the
 *     derived constants (c_prestage and the rest) carry the call, a constant per request;
 *   - a module row: the module's request path around the same copy, the real we_mod_decide;
 *   - the module row less its twin: the module's own work, independently of how the decision compiles.
 * What no row measures any more is the module's INLINED copy of the decision: hotpath-gate.sh's hpmod
 * holds that shape (no call, no store outside the caller's context, no local), and the evaluator rows hold
 * the decision's cost. The controls: WE_CG_PLANT_SEARCH runs the decision's hold-harmless search twice
 * inside this copy, which every row sees and c_prestage must refuse; WE_CG_MODWORK adds work to the module's
 * own path outside it, which the module rows must see and their twins must not.
 */
static __attribute__((noinline)) void cg_decide(const we_program_t *floor, const we_ctx_conf_t *floor_conf,
                                                const we_program_t *ctx_program, const we_ctx_conf_t *ctx_conf,
                                                const we_hh_view_t *hh, const we_request_t *req, we_eval_ctx_t *ctx,
                                                uint64_t now_ms, we_verdict_t *out)
{
#ifdef WE_CG_PLANT_SEARCH
    if (hh != NULL) {
        uint32_t a, i;

        __builtin_memcpy(&a, req->floor.b, 4);
        i = we_find4(&hh->map, __builtin_bswap32(a));
        __asm__ __volatile__("" : : "r"(i));
    }
#endif
    we_decide(floor, floor_conf, ctx_program, ctx_conf, hh, req, ctx, now_ms, out);
}
#define WE_MOD_DECIDE_COPY cg_decide
#include "we_module.h"
#ifdef WE_TRACE
#undef we_current
#endif

/*
 * THE ADAPTER: where this driver meets the evaluator's types (we_policy.h, we_eval.h), kept in these
 * functions and in eval_programs.h's ad_build, so a disagreement is a compile error there and nowhere
 * else.
 */
static void ad_conf(we_ctx_conf_t *c, int deny)
{
    memset(c, 0, sizeof *c);
    c->mode = (uint8_t)(deny ? WE_MODE_DENY : WE_MODE_LOG);
    c->allow_inferred = 0u;
}

static void ad_request(we_request_t *r, uint32_t floor_v4, uint32_t server_v4)
{
    uint8_t a[16];

    memset(r, 0, sizeof *r);
    memset(a, 0, sizeof a);
    a[0] = (uint8_t)(floor_v4 >> 24); a[1] = (uint8_t)(floor_v4 >> 16); a[2] = (uint8_t)(floor_v4 >> 8); a[3] = (uint8_t)floor_v4;
    we_addr_canon(a, 4, &r->floor);
    a[0] = (uint8_t)(server_v4 >> 24); a[1] = (uint8_t)(server_v4 >> 16); a[2] = (uint8_t)(server_v4 >> 8); a[3] = (uint8_t)server_v4;
    we_addr_canon(a, 4, &r->server);
    r->hold_harmless_eligible = 1u;
}

static void ad_view(we_eval_ctx_t *c, uint32_t plane_id, const we_map_t *m)
{
    c->view[plane_id - 1u].m = m;
}

#ifdef WE_TRACE
/* a block's hot length (what the request path may read) and its total length (the cold text after it) */
static void ad_block(const we_program_t *p, size_t *hot, size_t *total)
{
    *hot = p->hot_len;
    *total = p->total_len;
}

/* the evaluator's per-instruction trace hooks: nothing the residency model counts */
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
#endif

#ifndef WE_TRACE
/* the reference interpreter's verdict line, field for field (policy_ref.py states its format) */
static void ad_rules(char *buf, size_t n, const uint8_t bits[32])
{
    size_t off = 0;
    uint32_t r;
    buf[0] = '\0';
    for (r = 0; r < 256u && off < n; r++) {
        if (bits[r >> 3] & (1u << (r & 7u))) {
            off += (size_t)snprintf(buf + off, n - off, "%s%u", off != 0u ? "," : "", r + 1u);
        }
    }
    if (off == 0u) { snprintf(buf, n, "-"); }
}

static void ad_verdict(const we_verdict_t *v, char *buf, size_t n)
{
    static const char *const steps[] = { "?", "1", "2", "3", "3.5", "4" };
    char reason[64], lf[1100], lc[1100];
    size_t off = 0;

    reason[0] = '\0';
    switch (v->reason) {
    case WE_WHY_ALLOW_BY_UNKNOWN:
        off = (size_t)snprintf(reason, sizeof reason, "allow-by-unknown:%s",
                               v->unknown_plane >= 1u && v->unknown_plane <= WE_PLANE_MAX ? ev_plane_names[v->unknown_plane] : "-");
        break;
    case WE_WHY_HOLD_HARMLESS: off = (size_t)snprintf(reason, sizeof reason, "allow-by-hold-harmless"); break;
    case WE_WHY_ACME:          off = (size_t)snprintf(reason, sizeof reason, "allow-by-acme"); break;
    case WE_WHY_TENANT:        off = (size_t)snprintf(reason, sizeof reason, "allow-by-tenant"); break;
    case WE_WHY_NO_ADDRESS:    off = (size_t)snprintf(reason, sizeof reason, "no-address"); break;
    default: break;
    }
    if (v->marks & WE_MARK_TENANT_REVOKED) {
        off += (size_t)snprintf(reason + off, sizeof reason - off, "%stenant-revoked", off != 0u ? "," : "");
    }
    if (off == 0u) { snprintf(reason, sizeof reason, "-"); }
    ad_rules(lf, sizeof lf, v->log_fired[0]);
    ad_rules(lc, sizeof lc, v->log_fired[1]);
    snprintf(buf, n, "verdict step=%s action=%s program=%s rule=%u reason=%s log_floor=%s log_ctx=%s",
             v->step <= 5u ? steps[v->step] : "?", v->action == WE_ACT_DENY ? "deny" : "allow",
             v->program == WE_VPROG_FLOOR ? "floor" : v->program == WE_VPROG_CONTEXT ? "ctx" : "-",
             (unsigned)v->rule, reason, lf, lc);
}
#endif

/* one slot, compiled and placed, its views and requests ready */
typedef struct {
    const we_program_t *floor, *ctx;
    we_hh_view_t *hh;
    we_ctx_conf_t fconf, cconf;
    we_request_t *req;
    we_eval_ctx_t *ectx;
    const we_map_t *views[WE_PLANE_MAX + 1u];
    uint32_t n;
} ev_run_t;

static void ev_prepare(const ev_slot_t *s, uint32_t count, ev_run_t *r)
{
    uint32_t k, p;

    memset(r, 0, sizeof *r);
    {
        sb_t all = { 0 };
        we_policy_build_t *b;

        sb_add(&all, "%s%s", s->floor != NULL ? s->floor : "", s->ctx != NULL ? s->ctx : "");
        b = ad_build(all.p);
        r->floor = we_policy_floor(b);
        r->ctx = s->ctx != NULL ? we_policy_program(b, "http/server:s") : NULL;
        free(all.p);                    /* the build holds what it needs; its blocks live for the run */
    }
    r->hh = xalloc(sizeof *r->hh);      /* 64-byte aligned, as we_program_place requires: a page */
    if (r->floor == NULL || we_program_place(r->floor, r->hh) != 0) {
        fprintf(stderr, "%s: the floor block will not place\n", s->slot);
        exit(2);
    }
    ad_conf(&r->fconf, 1);
    ad_conf(&r->cconf, 1);
    /* the slot's armed planes, each from the world's source: the default policy's planes from the default
     * world's maps, the routing plane of the live world from the RouteViews table, the rest from the
     * synthetic world (a default-world slot that arms the tenant plane reads the synthetic one) */
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        r->views[p] = NULL;
        if (((s->views >> (p - 1u)) & 1u) == 0u) { continue; }
        if (s->world == W_DEFAULT && (p == WE_PLANE_REPUTATION || p == WE_PLANE_TOR || p == WE_PLANE_RPKI_UNREACHABLE)) {
            r->views[p] = p == WE_PLANE_REPUTATION ? &dp_rep : p == WE_PLANE_TOR ? &dp_tor : &dp_rpki;
        } else if (s->world == W_LIVE && p == WE_PLANE_ROUTING) {
            lv_build();
            r->views[p] = &lv_route;
        } else {
            r->views[p] = &ew[p];
        }
    }
    r->n = count;
    r->req = xalloc((size_t)count * sizeof *r->req);
    r->ectx = xalloc(sizeof *r->ectx);
    for (k = 0; k < count; k++) {
        uint32_t f, v;
        switch (s->addrs) {
        case A_EQUAL:    f = v = (k & 1u) ? EB : EA; break;
        case A_DISTINCT: f = (k & 1u) ? EB : EA; v = (k & 1u) ? EA : EB; break;
        case A_LIVE:     f = v = lv_addr(k); break;
        case A_PRESTAGE: f = v = pq4[k]; break;
        case A_HH_KEY2:  f = 0x7f000001u; v = (k & 1u) ? EB : EA; break;
        default:         f = v = q4[k]; break;
        }
        ad_request(&r->req[k], f, v);
    }
}

/* the views are filled immediately before each we_decide and nulled after, as a module does */
__attribute__((noinline)) static void ev_one(ev_run_t *r, uint32_t k, we_verdict_t *out)
{
    uint32_t p;
    for (p = 1; p <= WE_PLANE_MAX; p++) { ad_view(r->ectx, p, r->views[p]); }
    cg_decide(r->floor, &r->fconf, r->ctx, &r->cconf, r->hh, &r->req[k], r->ectx, 0u, out);
    for (p = 1; p <= WE_PLANE_MAX; p++) { ad_view(r->ectx, p, NULL); }
}

#ifndef WE_TRACE
/* the same decision with the views already set: what this lacks against ev_one is the harness's own view work */
__attribute__((noinline)) static void ev_one_sv(ev_run_t *r, uint32_t k, we_verdict_t *out)
{
    cg_decide(r->floor, &r->fconf, r->ctx, &r->cconf, r->hh, &r->req[k], r->ectx, 0u, out);
}
#endif

static const ev_slot_t *ev_find(const char *slot)
{
    uint32_t i;
    ev_build_slots();
    for (i = 0; i < nev; i++) { if (!strcmp(ev[i].slot, slot)) { return &ev[i]; } }
    fprintf(stderr, "unknown evaluator slot %s\n", slot);
    exit(2);
}

/* ==== THE MODULES' SLOTS ============================================================================ */
/*
 * Each module row has an evaluator TWIN: the same programs, world, views and request stream measured
 * through ev_one (the harness fills the views, we_decide runs). The module row runs the same requests
 * through we_mod_decide, which fills its own views and counts, so the row less its twin, plus the
 * harness's own view stores (c_harness_view: evaluator-default less its static-views twin), is the
 * module's work and nothing of the evaluator's. The configuration is built by hand from the twin's run,
 * as test_module's fixture builds its own: the module's cold half (we_module.c) is not linked, so the
 * link layout of every evaluator row is what it was, and the maps are published into the handles with
 * the one release store we_handle_set_view ends in. Every plane has a handle, NULL on the unbound ones,
 * so a mutant that reads every view pays an acquire load per plane and never a NULL-handle branch. The
 * rule ids and texts the renderers return are stand-ins of the production shape; a renderer returns a
 * pointer, and its cost does not read the text.
 */
typedef struct {
    ev_run_t          r;          /* the twin's run: programs, hold-harmless view, maps, requests */
    we_mod_cfg_t      cfg;
    we_mod_ctx_t      ctx;
    we_mod_cfg_cold_t ccold;
    we_mod_ctx_cold_t xcold;
    we_handle_t       h[8];
    uint32_t          null_reason[8];
    we_mod_scratch_t *s;          /* the decision's scratch, the export pass's local context too, as the servers reuse it */
    we_mod_scratch_t *local;      /* the variable handler's own local context */
    uint64_t         *shard;
    uint32_t          stride;
    we_mod_record_t  *rec;
    we_mod_req_t     *q;
    uint32_t          attrs;      /* the attributes the export or the variable path renders */
    uint32_t          varmask;    /* the planes the variable path fills before the decision */
} md_run_t;
static md_run_t md WE_CG_PAGE;
#ifndef WE_TRACE
static char md_logged[WE_MOD_LOGGED_MAX] WE_CG_PAGE;   /* the export's rendered strings, where a server has its pool */
static char md_gen[WE_MOD_GEN_MAX] WE_CG_PAGE;
static char md_floor[WE_ADDR_TEXT_MAX] WE_CG_PAGE;
#endif
#ifdef WE_TRACE
static int md_plant_ninth WE_CG_PAGE;   /* C6's control: one read more than the mask has bits */
static int md_plant_stride WE_CG_PAGE;  /* C5+'s controls: a shard base and stride off the line ... */
static int md_plant_scratch WE_CG_PAGE; /* ... a scratch that is not 64-byte aligned ... */
static int md_plant_split WE_CG_PAGE;   /* ... and the context's counters placed past a gap, off the layout rule */
#endif

static void md_strings(const we_program_t *p, const char *tag, const char *const **rid, const char *const **rtext)
{
    uint32_t i, n = p != NULL ? p->rule_count : 0u;
    const char **a = calloc(n != 0u ? n : 1u, sizeof *a), **b = calloc(n != 0u ? n : 1u, sizeof *b);

    if (a == NULL || b == NULL) { fprintf(stderr, "out of memory\n"); exit(2); }
    for (i = 0; i < n; i++) {
        char buf[64];
        snprintf(buf, sizeof buf, "%s:%u", tag, i + 1u);
        a[i] = strdup(buf);
        snprintf(buf, sizeof buf, "rule %u of the %s", i + 1u, tag);
        b[i] = strdup(buf);
    }
    *rid = (const char *const *)a;
    *rtext = (const char *const *)b;
}

/* the attributes of the planes in `planes`, as a module's default export set is derived */
static uint32_t md_attrs_of(uint32_t planes)
{
    uint32_t i, out = 0;
    for (i = 0; i < WE_MOD_ATTRS; i++) { if ((planes >> we_mod_attr(i)->plane) & 1u) { out |= 1u << i; } }
    return out;
}

static void md_prepare(const ev_slot_t *s, uint32_t count)
{
    const ev_slot_t *t = s->twin != NULL ? ev_find(s->twin) : s;
    uint32_t p, k, mask;

    memset(&md, 0, sizeof md);
    ev_prepare(t, count, &md.r);
    md.cfg.floor = md.r.floor;
    md.cfg.floor_conf = md.r.fconf;
    md.cfg.floor_status = 403u;
    md.cfg.hh = md.r.hh;
    for (p = 0; p < 8u; p++) {
        md.cfg.handle[p] = &md.h[p];
        __atomic_store_n(&md.h[p].current, (we_map_t *)(uintptr_t)md.r.views[p + 1u], __ATOMIC_RELEASE);
        if (md.r.views[p + 1u] != NULL) { md.cfg.bound_mask = (uint8_t)(md.cfg.bound_mask | (1u << p)); }
        else { md.cfg.static_reason[p] = WE_MOD_NOMAP_ABSENT; }
    }
    md.cfg.null_reason = md.null_reason;
    md.ccold.program_none = "floor:- ctx:-";
    md_strings(md.cfg.floor, "floor", &md.ccold.rule_id, &md.ccold.rule_text);
    md.ccold.rule_count = md.cfg.floor->rule_count;
    for (p = 0; p < 8u; p++) { md.ccold.plane_name[p] = we_mod_plane_word(p); }
    md.cfg.cold = &md.ccold;
    md.ctx.prog = md.r.ctx;
    md.ctx.conf = md.r.cconf;
    md.ctx.deny_status = 403u;
    md.ctx.ctr_off = WE_MOD_CTR_FLOOR + md.cfg.floor->rule_count;
    md.ctx.rule_count = (uint16_t)(md.r.ctx != NULL ? md.r.ctx->rule_count : 0u);
    mask = ((uint32_t)md.cfg.floor->plane_mask | (md.r.ctx != NULL ? (uint32_t)md.r.ctx->plane_mask : 0u) | 0x80u) & md.cfg.bound_mask;
    /* the default export set is the planes the two programs or the tenant reference; export-all every bound plane */
    md.ctx.export_mask = s->kind == K_MOD_EXPORT_ALL ? md.cfg.bound_mask : (uint8_t)mask;
    md.ctx.gen_mask = md.ctx.export_mask;
    md.xcold.program_ctx = "floor:0000000000000000 ctx:0000000000000000";
    md.xcold.program_floor = "floor:0000000000000000 ctx:-";
    md_strings(md.r.ctx, "ctx", &md.xcold.rule_id, &md.xcold.rule_text);
    md.xcold.rule_count = md.ctx.rule_count;
    md.ctx.cold = &md.xcold;
#ifdef WE_TRACE
    if (md_plant_split) { md.ctx.ctr_off += 8u; }      /* the control: a gap between the floor's counters and the context's */
#endif
    md.stride = (md.ctx.ctr_off + md.ctx.rule_count + 7u) & ~7u;
#ifdef WE_TRACE
    if (md_plant_stride) {
        /* the control: a stride one counter over the line, the base eight bytes into its line */
        md.stride += 1u;
        md.shard = (uint64_t *)((uint8_t *)xalloc((size_t)md.stride * sizeof *md.shard + 64u) + 8u);
    } else
#endif
    md.shard = xalloc((size_t)md.stride * sizeof *md.shard);
#ifdef WE_TRACE
    if (md_plant_scratch) { md.s = (we_mod_scratch_t *)(void *)((uint8_t *)xalloc(sizeof *md.s + 64u) + 32u); } else
#endif
    md.s = xalloc(sizeof *md.s);
    md.local = xalloc(sizeof *md.local);
    md.rec = xalloc(sizeof *md.rec);
    md.q = xalloc((size_t)count * sizeof *md.q);
    for (k = 0; k < count; k++) { memset(&md.q[k], 0, sizeof md.q[k]); md.q[k].r = md.r.req[k]; }
    switch (s->kind) {
    case K_MOD_EXPORT_ALL: md.attrs = (1u << WE_MOD_ATTRS) - 1u; break;
    case K_MOD_VAR1:       md.varmask = 1u << (WE_PLANE_REPUTATION - 1u); md.attrs = md_attrs_of(md.varmask) & ~1u; break;  /* `listed` */
    case K_MOD_VAR3:       md.varmask = md.cfg.bound_mask; md.attrs = 1u << 16 | 1u << 2 | 1u << 1; break;   /* listed, tor_exit, rpki_unreachable */
    default:               md.attrs = md_attrs_of(md.ctx.export_mask); break;
    }
}

#ifndef WE_TRACE
/* one request's counts as the verdict says they should be, accumulated */
static void md_recount(const we_verdict_t *v, const we_mod_req_t *q, uint64_t *want)
{
    uint32_t r;

    if (q->note == WE_MOD_NOTE_UNPARSED) { want[WE_MOD_CTR_FLOOR_HEADER_UNPARSED]++; }
    else if (q->note == WE_MOD_NOTE_CAPPED) { want[WE_MOD_CTR_FLOOR_HEADER_CAPPED]++; }
    else if (q->r.walk == WE_WALK_FLOOR_HEADER_MISSING) { want[WE_MOD_CTR_FLOOR_HEADER_MISSING]++; }
    if (v->rule != 0u) { want[(v->program == WE_VPROG_FLOOR ? WE_MOD_CTR_FLOOR : md.ctx.ctr_off) + v->rule - 1u]++; }
    else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_HOLD_HARMLESS) { want[WE_MOD_CTR_HOLD_HARMLESS]++; }
    else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_ACME) { want[WE_MOD_CTR_ACME]++; }
    else if (v->step == WE_STEP_EXEMPT && v->reason == WE_WHY_NO_ADDRESS) { want[WE_MOD_CTR_NO_ADDRESS]++; }
    else if (v->step == WE_STEP_TENANT) { want[WE_MOD_CTR_TENANT]++; }
    else if (v->step == WE_STEP_STALE_TENANT) { want[WE_MOD_CTR_STALE_TENANT]++; }
    for (r = 0; r < 256u; r++) {
        if ((v->log_fired[0][r / 8u] >> (r % 8u)) & 1u) { want[WE_MOD_CTR_FLOOR + r]++; }
        if ((v->log_fired[1][r / 8u] >> (r % 8u)) & 1u) { want[md.ctx.ctr_off + r]++; }
    }
}

#endif /* !WE_TRACE */

#ifdef WE_CG_PLANT_CONFLICT
/*
 * The 8-way conflict row's control (cachegrind-gate.sh): every module request makes 12 volatile loads from
 * one page-aligned buffer, WE_CG_PLANT_CONFLICT bytes apart. At 4,096 they are twelve lines in one 8-way
 * set, which evict each other every request; at 0 they read a line the request already reads, and no
 * buffer is made. Their sum is stored on this frame's stack, a line the request has just written, so the
 * twin adds loads and no line. Two earlier forms were wrong, each measured: summed into sink, which is
 * page-aligned, the twin wrote one more line into set 0 every request (gcc module-worst 9.205 against
 * 5.252); cast to void, clang loaded into the zero register and valgrind dropped the dead loads, so the
 * 4,096 build added 0.08 misses on every clang row. Now the twin reads each row's production figure (to
 * 0.007), and the 4,096 build adds 13.08 (gcc module-export-all) to 19.69 (gcc module-default) misses a
 * request at the production link, aarch64.
 */
static void md_touch_conflict(void)
{
    static const volatile uint8_t *buf;  /* read through volatile: the twelve loads are made, whatever the stride */
    const volatile uint8_t *b;
    volatile uint64_t keep;              /* on this frame's stack, which the request has just written */
    uint64_t a = 0;
    uint32_t i;

    if (WE_CG_PLANT_CONFLICT != 0 && buf == NULL) {
        void *m = aligned_alloc(4096, 12u * (size_t)(WE_CG_PLANT_CONFLICT + 4096));

        if (m == NULL) { fprintf(stderr, "out of memory\n"); exit(2); }
        memset(m, 1, 12u * (size_t)(WE_CG_PLANT_CONFLICT + 4096));
        buf = (const volatile uint8_t *)m;
    }
    /* at a stride of 0 the twelve loads read a line every request already reads (the configuration's
     * first, which we_mod_decide reads), so the twin adds loads and no line */
    b = WE_CG_PLANT_CONFLICT == 0 ? (const volatile uint8_t *)(const void *)&md.cfg : buf;
    for (i = 0; i < 12u; i++) {
        a += b[(size_t)i * WE_CG_PLANT_CONFLICT];
    }
    keep = a;
    (void)keep;
}
#define MD_TOUCH_CONFLICT() md_touch_conflict()
#else
#define MD_TOUCH_CONFLICT() ((void)0)
#endif

/* the module's whole request path: the views, the decision, the counts */
__attribute__((noinline)) static void md_one(uint32_t k)
{
    MD_TOUCH_CONFLICT();
    we_mod_decide(&md.cfg, &md.ctx, md.s, md.shard, &md.q[k], 0u);
#ifdef WE_TRACE
    if (md_plant_ninth) { sink += (uintptr_t)cg_current(&md.h[0]); }
#endif
}

#ifndef WE_TRACE
/* a rendered value kept live by its first byte, as a server keeps the pointer it stores */
static inline uint64_t md_keep(const char *s) { return (uint64_t)(uint8_t)s[0]; }

/*
 * The export pass after the decision, as the Apache and LiteSpeed modules run it (5.2): the record
 * written from the decision's scratch, every plane of the export set the decision did not fill filled
 * lazily through that same scratch, then the nine decision values and the set's attributes rendered.
 * The server stores each pointer in its table or environment; the exact-length pass and the table
 * calls are the server rows' (R1, the Apache gate), not this slot's.
 */
__attribute__((noinline)) static uint64_t md_one_export(uint32_t k)
{
    uint64_t acc = 0;
    uint32_t i;
    const char *v;
    size_t vl;

    MD_TOUCH_CONFLICT();
    we_mod_decide(&md.cfg, &md.ctx, md.s, md.shard, &md.q[k], 0u);
    we_mod_record_init(md.rec, &md.ctx);
    we_mod_record_write(md.rec, &md.cfg, &md.ctx, md.s, &md.q[k].r.floor, &md.q[k].r.server);
    we_mod_fill(md.rec, &md.cfg, md.s, (uint32_t)md.ctx.export_mask | (uint32_t)md.ctx.gen_mask | 1u, 0u);
    acc += md_keep(we_mod_render_action(md.rec));
    acc += md_keep(we_mod_render_rule(md.rec, &md.cfg, 1));
    acc += md_keep(we_mod_render_rule(md.rec, &md.cfg, 0));
    acc += md_keep(we_mod_render_reason(md.rec, md.q[k].r.walk, md.q[k].note));
    acc += md_keep(we_mod_render_program(md.rec, &md.cfg));
    acc += we_mod_render_logged(md.rec, md_logged);
    acc += we_mod_render_floor(md.rec, md_floor);
    acc += we_mod_render_generations(md.rec, md_gen);
    acc += md_keep(we_mod_render_verdict(md.rec, WE_MOD_SPELL_SPAMHAUS));
    for (i = 0; i < WE_MOD_ATTRS; i++) {
#ifndef WE_MOD_TEST_EAGER_EXPORT
        if (((md.attrs >> i) & 1u) == 0u) { continue; }
#endif
        if (we_mod_render_attr(md.rec, i, &v, &vl) == 0) { acc += vl + (uint8_t)v[0]; }
    }
    return acc;
}

/*
 * nginx's pre-decision variable path (5.2, 11.3): a variable read in the rewrite phase allocates the
 * record, keys its slot to the server address and fills the planes it reads through the handler's one
 * local context, renders each variable, and the decision then runs and merges its own entry over the
 * record. WE_CG_VAR_PER_READ is the control: the local context rebuilt for every read.
 */
__attribute__((noinline)) static uint64_t md_one_var(uint32_t k)
{
    uint64_t acc = 0;
    uint32_t i;
    const char *v;
    size_t vl;

    MD_TOUCH_CONFLICT();
    we_mod_record_init(md.rec, &md.ctx);
    we_mod_record_key(md.rec, &md.q[k].r.server);
#ifdef WE_CG_VAR_PER_READ
    for (i = 0; i < 8u; i++) {
        if ((md.varmask >> i) & 1u) { we_mod_fill(md.rec, &md.cfg, md.local, 1u << i, 0u); }
    }
#else
    we_mod_fill(md.rec, &md.cfg, md.local, md.varmask, 0u);
#endif
    for (i = 0; i < WE_MOD_ATTRS; i++) {
        if (((md.attrs >> i) & 1u) == 0u) { continue; }
        if (we_mod_render_attr(md.rec, i, &v, &vl) == 0) { acc += vl + (uint8_t)v[0]; }
    }
    we_mod_decide(&md.cfg, &md.ctx, md.s, md.shard, &md.q[k], 0u);
    we_mod_record_write(md.rec, &md.cfg, &md.ctx, md.s, &md.q[k].r.floor, &md.q[k].r.server);
    return acc;
}
#endif /* !WE_TRACE */

#ifndef WE_TRACE
static int cg_eval(const char *slot, uint32_t count)
{
    const ev_slot_t *s = ev_find(slot);
    ev_run_t r;
    we_verdict_t v;
    uint64_t acc = 0;
    uint32_t k;

    ev_prepare(s, count, &r);
    CACHEGRIND_START_INSTRUMENTATION;
    for (k = 0; k < count; k++) { ev_one(&r, k, &v); acc += v.action; }
    CACHEGRIND_STOP_INSTRUMENTATION;
    sink = acc;
    return 0;
}

/*
 * The module rows and the static-views twins, reached from cg_entry and never through cg(): cg() holds
 * every lookup row's loop inlined in one function, and a condition added to it moved gcc 13.3's register
 * allocation of the hold-harmless lookup by one instruction a lookup (lookup-hh@16 read 111.00 against its
 * committed 110.00), so cg() and cg_eval keep the text their rows were measured through.
 */
static int cg_module(const ev_slot_t *s, uint32_t count)
{
    ev_run_t r;
    we_verdict_t v;
    uint64_t acc = 0;
    uint32_t k, p;

    if (s->kind == K_EVAL_SV) {
        ev_prepare(s, count, &r);
        /* the views set once, outside the measured region: what ev_one does per request is the harness's */
        for (p = 1; p <= WE_PLANE_MAX; p++) { ad_view(r.ectx, p, r.views[p]); }
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { ev_one_sv(&r, k, &v); acc += v.action; }
        CACHEGRIND_STOP_INSTRUMENTATION;
        sink = acc;
        return 0;
    }
    md_prepare(s, count);
    CACHEGRIND_START_INSTRUMENTATION;
    switch (s->kind) {
    case K_MOD:
        for (k = 0; k < count; k++) { md_one(k); acc += md.s->v.action; }
        break;
    case K_MOD_EXPORT:
    case K_MOD_EXPORT_ALL:
    case K_MOD_PRESTAGE:
        for (k = 0; k < count; k++) { acc += md_one_export(k); }
        break;
    default:
        for (k = 0; k < count; k++) { acc += md_one_var(k); }
        break;
    }
    CACHEGRIND_STOP_INSTRUMENTATION;
    sink = acc;
    return 0;
}

/* the first n verdicts, one line each, for comparison with the reference interpreter's committed output */
static int ev_verdicts(const char *slot, uint32_t n)
{
    const ev_slot_t *s = ev_find(slot);
    ev_run_t r;
    we_verdict_t v;
    char line[2400];
    uint32_t k;

    if (s->kind >= K_MOD) {
        /* the module's decisions, and its counters held to the verdicts' recount: a module that
         * miscounts is not measured, whatever its verdicts say */
        uint64_t *want;

        md_prepare(s, n);
        want = calloc(md.stride, sizeof *want);
        if (want == NULL) { fprintf(stderr, "out of memory\n"); return 2; }
        for (k = 0; k < n; k++) {
            md_one(k);
            ad_verdict(&md.s->v, line, sizeof line);
            printf("%s\n", line);
            md_recount(&md.s->v, &md.q[k], want);
        }
        if (memcmp(md.shard, want, (size_t)md.stride * sizeof *want) != 0) {
            fprintf(stderr, "%s: the module's counters differ from the verdicts' recount over %u requests\n", slot, n);
            free(want);
            return 1;
        }
        free(want);
        return 0;
    }
    ev_prepare(s, n, &r);
    for (k = 0; k < n; k++) {
        ev_one(&r, k, &v);
        ad_verdict(&v, line, sizeof line);
        printf("%s\n", line);
    }
    return 0;
}
#endif /* !WE_TRACE */
#endif /* WE_HAVE_EVAL */

#ifndef WE_TRACE
static int cg(const char *slot, int dense, uint32_t count)
{
    uint64_t acc = 0;
    uint32_t k;
    if (!strncmp(slot, "evaluator", 9)) {
#ifdef WE_HAVE_EVAL
        return cg_eval(slot, count);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; nothing is measured in this slot\n", slot);
        return 3;
#endif
    }
    if (!strcmp(slot, "plane-v4-radix18")) {
        const uint32_t *s = dense ? d4 : u4;
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&mp, s[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "plane-v6-rank64s")) {
        uint8_t (*s)[16] = dense ? d6b : u6b;
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane6(&mp, s[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "shipped-v4")) {
        const uint32_t *s = dense ? d4 : u4;
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_ship4(&ship, s[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "shipped-v6")) {
        uint8_t (*s)[16] = dense ? d6b : u6b;
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_ship6(&ship, s[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-reputation@q4")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&dp_rep, q4[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-reputation@q6")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_find6(&dp_rep, q6[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-tor@q4")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&dp_tor, q4[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-rpki-unreachable@q4")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&dp_rpki, q4[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-rpki-unreachable@q6")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_find6(&dp_rpki, q6[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-hh@16")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&dp_hh, hq4[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-hh@4")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_find6(&dp_hh, hq6[k]); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (!strcmp(slot, "lookup-hh@basis")) {
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(&dp_hh, (k & 1u) ? EB : EA); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else if (basis_plane(slot) != 0u) {
        const we_map_t *m = &ew[basis_plane(slot)];
        CACHEGRIND_START_INSTRUMENTATION;
        for (k = 0; k < count; k++) { acc += cg_plane4(m, (k & 1u) ? EB : EA); }
        CACHEGRIND_STOP_INSTRUMENTATION;
    } else {
        fprintf(stderr, "unknown slot %s\n", slot);
        return 2;
    }
    sink = acc;
    return 0;
}

/*
 * THE MEASURED REGION RUNS ON A STACK OF ITS OWN. The D1 model's set index is the page offset of an
 * address, and the arrays are 4096-byte aligned so the sets they touch are fixed; the stack was not.
 * cg_eval's ev_run_t (the floor's conf, the plane views), the verdict and the frames of ev_one and
 * we_decide live on the stack, and the process stack's page offset is set by the launch: the size of
 * the environment and of argv, which the kernel copies above main's frame. Where those lines land in a
 * set the program block and the hold-harmless table already fill, they evict each other on every
 * request: evaluator-basis-rules-4@floor read 13.961, 15.934, 16.906 or 17.906 D1 misses per request
 * on one binary as the environment alone grew, with the instructions and the data references identical
 * (cg_annotate named ev_one's views, the conf check, the program's opcode load and the hold-harmless
 * family's first bound as the lines that moved). So every cg run switches to a stack of its own,
 * an aligned_alloc(4096) block entered at its top, so its page offset is the same on every launch.
 * The heap objects the run touches stay put for a different reason: the heap's allocation history
 * before the switch is the same on every launch, so the allocator hands out the same offsets, and
 * the counts no longer depend on how the process was started. WE_CG_PLANT_UNALIGNED runs on the
 * launch stack instead: cachegrind-gate.sh's control, which must see the drift come back.
 *
 * The stack's lowest page is made inaccessible before the switch, outside the instrumentation marks,
 * so a measured path that outgrows the stack faults rather than writing over whatever the allocator
 * placed below it. Measured: the deepest any slot reaches is 15,392 bytes (gcc -O2) and 20,764 bytes
 * (clang -O0), both on evaluator-basis-INSET_ASN-TF, about 50 times under the 1 MiB.
 */
#define CG_STACK_BYTES (1u << 20)
static ucontext_t cg_caller WE_CG_PAGE, cg_callee WE_CG_PAGE;
static const char *cg_slot WE_CG_PAGE;
static int cg_dense WE_CG_PAGE, cg_rc WE_CG_PAGE;
static uint32_t cg_count WE_CG_PAGE;

static void cg_entry(void)
{
    if (!strncmp(cg_slot, "module-", 7) || !strncmp(cg_slot, "evaluator", 9)) {
#ifdef WE_HAVE_EVAL
        const ev_slot_t *s = ev_find(cg_slot);

        if (s->kind != K_EVAL) {
            cg_rc = cg_module(s, cg_count);
            return;
        }
#else
        if (!strncmp(cg_slot, "module-", 7)) {
            printf("%s: EMPTY, this driver was built without the policy evaluator; nothing is measured in this slot\n", cg_slot);
            cg_rc = 3;
            return;
        }
#endif
    }
    cg_rc = cg(cg_slot, cg_dense, cg_count);
}

static int cg_on_own_stack(const char *slot, int dense, uint32_t count)
{
    if (getenv("WE_CG_PLANT_UNALIGNED") != NULL) {
        return cg(slot, dense, count);
    }
    cg_slot = slot;
    cg_dense = dense;
    cg_count = count;
    if (getcontext(&cg_callee) != 0) {
        perror("getcontext");
        exit(2);
    }
    cg_callee.uc_stack.ss_sp = xalloc(CG_STACK_BYTES);
    cg_callee.uc_stack.ss_size = CG_STACK_BYTES;
    if (mprotect(cg_callee.uc_stack.ss_sp, 4096u, PROT_NONE) != 0) {       /* the guard page */
        perror("mprotect");
        exit(2);
    }
    cg_callee.uc_link = &cg_caller;
    makecontext(&cg_callee, cg_entry, 0);
    if (swapcontext(&cg_caller, &cg_callee) != 0) {
        perror("swapcontext");
        exit(2);
    }
    return cg_rc;
}
#else
/* ---- the residency model ---------------------------------------------------------------------- */
/*
 * An LRU set-associative cache at one named geometry. Every read of the mapping is fed to the ONE
 * level being modelled, which is how an inclusive hierarchy behaves for residency: a line still in L1
 * is also in L2. The question asked is the performance budget's: after one sequential sweep of the index region, how
 * often does a lookup miss on an index line? The level is L2 where the indexes the run references fit,
 * and the LLC otherwise (a radix-18 index is the whole L2 of a 1 MiB part, and each of its lines is
 * touched once per 16,384 lookups, so an L2 model evicts it by construction).
 */
/*
 * ADDRESSES. An L2 of 1 MiB 8-way indexes its sets on address bits 6 to 16, above the page offset, so
 * a model fed the process's virtual addresses counts differently every run (measured: 5,848 then 6,521
 * index misses on the same input). So every read is translated to its offset in the plane's FILE, laid
 * out as FORMAT.md section 5 lays it out (header, then index, start[], record column and S-tree, each
 * 64-byte aligned), and each plane is placed at a fixed base. The model is then deterministic. A
 * physically indexed cache sees the kernel's page placement instead, which this model does not pretend
 * to know; it answers the question for a contiguous mapping.
 */
typedef struct { uint64_t *tag, *stamp; uint32_t sets, ways, line; uint64_t clock; } lru_t;
/* index: 0 other data, 1 a plane index, 2 a program block; plane: the plane id the region belongs to, or 0 */
typedef struct { const uint8_t *lo, *hi; uint64_t model; int index; uint32_t plane; } region_t;
static lru_t cache WE_CG_PAGE;
static region_t regions[64] WE_CG_PAGE;
static int nreg WE_CG_PAGE, counting WE_CG_PAGE;
#ifdef WE_HAVE_EVAL
static int rec_armed WE_CG_PAGE;           /* bound(): the reads go to its line set, not the cache model */
static int rec_discard WE_CG_PAGE;         /* fills(): the traced build counts finds, it models no cache */
#endif
static uint64_t idx_reads WE_CG_PAGE, idx_miss WE_CG_PAGE, other_reads WE_CG_PAGE, other_miss WE_CG_PAGE, prog_reads WE_CG_PAGE, prog_miss WE_CG_PAGE, plane_miss[WE_PLANE_MAX + 1u] WE_CG_PAGE;

static uint64_t al64(uint64_t x) { return (x + 63u) & ~(uint64_t)63u; }

/* add one array of a plane at the next 64-byte-aligned offset of that plane's file */
static void region(uint64_t *cursor, const void *p, size_t bytes, int index)
{
    *cursor = al64(*cursor);
    regions[nreg].lo = p;
    regions[nreg].hi = (const uint8_t *)p + bytes;
    regions[nreg].model = *cursor;
    regions[nreg].index = index;
    nreg++;
    *cursor += bytes;
}

static int lru_access(lru_t *c, uintptr_t addr)
{
    uint64_t t = addr / c->line;
    uint32_t set = (uint32_t)(t % c->sets), w, victim = 0;
    uint64_t *tg = c->tag + (size_t)set * c->ways, *sp = c->stamp + (size_t)set * c->ways;
    c->clock++;
    for (w = 0; w < c->ways; w++) {
        if (sp[w] != 0 && tg[w] == t) { sp[w] = c->clock; return 1; }
        if (sp[w] < sp[victim]) { victim = w; }
    }
    tg[victim] = t;
    sp[victim] = c->clock;
    return 0;
}

#ifdef WE_HAVE_EVAL
static void ls_range_hook(const void *p, size_t len);
#endif
void we_trace_read(const void *p, size_t len)
{
    const uint8_t *q = p;
    uint64_t a, e, line;
    int i;

#ifdef WE_HAVE_EVAL
    if (len != 0u) { ls_range_hook(p, len); }
    if (rec_armed || rec_discard) { return; }
#endif

    for (i = 0; i < nreg; i++) {
        if (q >= regions[i].lo && q < regions[i].hi) { break; }
    }
    if (i == nreg) {
        fprintf(stderr, "residency: a traced read outside every modelled region\n");
        exit(2);
    }
    a = regions[i].model + (uint64_t)(q - regions[i].lo);
    e = a + len - 1u;
    for (line = a / cache.line; line <= e / cache.line; line++) {
        int hit = lru_access(&cache, line * cache.line);
        if (!counting) { continue; }
        if (regions[i].index == 1) { idx_reads++; idx_miss += !hit; plane_miss[regions[i].plane] += !hit; }
        else if (regions[i].index == 2) { prog_reads++; prog_miss += !hit; }
        else { other_reads++; other_miss += !hit; }
    }
}

static int residency(const char *cfg, uint64_t l2, uint32_t l2w, uint64_t llc, uint32_t llcw, uint32_t line, uint32_t count)
{
    int use4 = !strcmp(cfg, "v4") || !strcmp(cfg, "both"), use6 = !strcmp(cfg, "v6") || !strcmp(cfg, "both");
    size_t ib = (use4 ? p4_index_bytes : 0u) + (use6 ? p6_index_bytes : 0u);
    uint64_t size = ib <= l2 ? l2 : llc;
    uint32_t ways = ib <= l2 ? l2w : llcw, k, i;
    const char *level = ib <= l2 ? "L2" : "LLC";
    uint64_t acc = 0;

    if (!use4 && !use6) { fprintf(stderr, "residency: config is v4, v6 or both\n"); return 2; }
    cache.line = line;
    cache.ways = ways;
    cache.sets = (uint32_t)(size / ((uint64_t)ways * line));
    if (cache.sets == 0u || (uint64_t)cache.sets * ways * line != size) { fprintf(stderr, "residency: bad geometry\n"); return 2; }
    cache.tag = calloc((size_t)cache.sets * ways, 8);
    cache.stamp = calloc((size_t)cache.sets * ways, 8);
    if (cache.tag == NULL || cache.stamp == NULL) { fprintf(stderr, "out of memory\n"); return 2; }
    {
        /* each plane's file at a fixed base; inside it, FORMAT.md section 5's order after the header */
        uint64_t cur = 0x100000000ull + 192u;
        region(&cur, mp.f4.idx, p4_index_bytes, 1);
        region(&cur, st4, (size_t)n4 * 4u, 0);
        region(&cur, rec4, (size_t)n4 * 16u, 0);
        cur = 0x200000000ull + 192u;
        region(&cur, st6, (size_t)n6 * 8u, 0);
        region(&cur, rec6, (size_t)n6 * 24u, 0);
        region(&cur, mp.f6w.stree, p6_index_bytes, 1);
    }
    /* warm-up: one sequential sweep of every REFERENCED index region, nothing else */
    for (i = 0; i < (uint32_t)nreg; i++) {
        uint64_t q;
        if (!regions[i].index || (regions[i].lo == (const uint8_t *)mp.f4.idx ? !use4 : !use6)) { continue; }
        for (q = regions[i].model & ~(uint64_t)(line - 1u); q < regions[i].model + (uint64_t)(regions[i].hi - regions[i].lo); q += line) {
            (void)lru_access(&cache, q);
        }
    }
    counting = 1;
    for (k = 0; k < count; k++) {
        if (use4) { acc += cg_plane4(&mp, d4[k]); }
        if (use6) { acc += cg_plane6(&mp, d6b[k]); }
    }
    sink = acc;
    printf("residency %-4s indexes %zu bytes, modelled against the %s (%llu bytes, %u-way, %u-byte lines): "
           "%u dense lookups per plane, index reads %llu misses %llu, other reads %llu misses %llu\n",
           cfg, ib, level, (unsigned long long)size, ways, line, count, (unsigned long long)idx_reads,
           (unsigned long long)idx_miss, (unsigned long long)other_reads, (unsigned long long)other_miss);
    /* the machine-readable line cachegrind-gate.sh compares with its baseline; the verdict is its own */
    printf("RESULT\t%s\t%s\t%llu\t%llu\n", cfg, level, (unsigned long long)idx_miss,
           (unsigned long long)count * (unsigned long long)(use4 + use6));
    return 0;
}

/*
 * The default planes' ALONE-rows, and the evaluator's rows BESIDE the program.
 *
 * A plane loaded from a real file (dp_plane, ew_build) is registered by its arrays, each translated to
 * its true offset in its file at a fixed base per plane, so the model is deterministic. The level is
 * L2 where the referenced plane indexes fit and the LLC otherwise; at the reference geometry every
 * default plane fits a 1 MiB L2, so their rows are L2 rows. Alone, one plane's index is swept once and
 * the q4 stream (the default slot's own stream) runs through that plane only.
 */
static size_t dp_regions(const we_map_t *m, uint64_t base, uint32_t plane)
{
    const we_fam_t *fs[3] = { &m->f4, &m->f6, &m->f6w };
    size_t ib = 0;
    int i;

    for (i = 0; i < 3; i++) {
        const we_fam_t *f = fs[i];
        uint32_t kb = f->key_bits / 8u;
        if (f->n == 0u) { continue; }
#define DPR(p, bytes, ix) do { if ((p) != NULL && (bytes) != 0u) { \
            regions[nreg].lo = (const uint8_t *)(p); regions[nreg].hi = (const uint8_t *)(p) + (bytes); \
            regions[nreg].model = base + (uint64_t)((const uint8_t *)(p) - (const uint8_t *)m->base); \
            regions[nreg].index = (ix); regions[nreg].plane = plane; nreg++; } } while (0)
        if (f->kind == WE_KIND_RADIX) {
            size_t b = (((size_t)1 << (f->key_bits == 32u ? 32u - f->shift : 63u - f->shift)) + 1u) * 4u;
            DPR(f->idx, b, 1);
            ib += b;
        } else {
            DPR(f->stree, (size_t)f->nodes * 64u, 1);
            ib += (size_t)f->nodes * 64u;
        }
        DPR(f->start, (size_t)f->n * kb, 0);
        if (f->records != NULL) {
            DPR(f->records, (size_t)f->n * f->stride, 0);
        } else {
            DPR(f->end, (size_t)f->n * kb, 0);
            DPR(f->sev, (size_t)f->n, 0);
        }
#undef DPR
    }
    return ib;
}

/* the model at the level the referenced indexes need, or the LLC when forced; returns the level */
static const char *model_init(size_t ib, int force_llc, uint64_t l2, uint32_t l2w, uint64_t llc, uint32_t llcw, uint32_t line)
{
    int at_l2 = !force_llc && ib <= l2;
    uint64_t size = at_l2 ? l2 : llc;
    uint32_t ways = at_l2 ? l2w : llcw;
    int i;

    cache.line = line;
    cache.ways = ways;
    cache.sets = (uint32_t)(size / ((uint64_t)ways * line));
    if (cache.sets == 0u || (uint64_t)cache.sets * ways * line != size) { fprintf(stderr, "residency: bad geometry\n"); exit(2); }
    cache.tag = calloc((size_t)cache.sets * ways, 8);
    cache.stamp = calloc((size_t)cache.sets * ways, 8);
    if (cache.tag == NULL || cache.stamp == NULL) { fprintf(stderr, "out of memory\n"); exit(2); }
    /* warm-up: one sequential sweep of every index region (and every program block), nothing else */
    for (i = 0; i < nreg; i++) {
        uint64_t q;
        if (regions[i].index == 0) { continue; }
        for (q = regions[i].model & ~(uint64_t)(line - 1u); q < regions[i].model + (uint64_t)(regions[i].hi - regions[i].lo); q += line) {
            (void)lru_access(&cache, q);
        }
    }
    printf("model: %s, %llu bytes, %u-way, %u-byte lines; referenced plane indexes %zu bytes\n",
           at_l2 ? "L2" : "LLC", (unsigned long long)size, ways, line, ib);
    return at_l2 ? "L2" : "LLC";
}

static int residency_dp(const char *cfg, uint64_t l2, uint32_t l2w, uint64_t llc, uint32_t llcw, uint32_t line, uint32_t count)
{
    uint32_t plane = !strcmp(cfg, "reputation") ? WE_PLANE_REPUTATION : !strcmp(cfg, "tor") ? WE_PLANE_TOR
                   : !strcmp(cfg, "rpki-unreachable") ? WE_PLANE_RPKI_UNREACHABLE : 0u;
    const we_map_t *m = plane == WE_PLANE_REPUTATION ? &dp_rep : plane == WE_PLANE_TOR ? &dp_tor : &dp_rpki;
    const char *level;
    uint64_t acc = 0;
    uint32_t k;

    if (plane == 0u) { fprintf(stderr, "residency: unknown plane %s\n", cfg); return 2; }
    level = model_init(dp_regions(m, 0x100000000ull, plane), 0, l2, l2w, llc, llcw, line);
    counting = 1;
    for (k = 0; k < count; k++) { acc += cg_plane4(m, q4[k]); }
    sink = acc;
    printf("residency %-16s alone, against the %s: %u q4 lookups, index reads %llu misses %llu, other reads %llu misses %llu\n",
           cfg, level, count, (unsigned long long)idx_reads, (unsigned long long)idx_miss,
           (unsigned long long)other_reads, (unsigned long long)other_miss);
    printf("RESULT\t%s\t%s\t%llu\t%llu\n", cfg, level, (unsigned long long)idx_miss, (unsigned long long)count);
    return 0;
}

#ifdef WE_HAVE_EVAL
/* the evaluator's own loads, through WE_TRACE_EVAL, go to the same model as the planes' */
void we_trace_eval(const void *p, size_t len)
{
    we_trace_read(p, len);
}

/* any object the evaluator may read on the request path, by its own address: a struct, an array */
static void obj_region(const void *p, size_t bytes, uint64_t base)
{
    if (p == NULL || bytes == 0u) { return; }
    regions[nreg].lo = p;
    regions[nreg].hi = (const uint8_t *)p + bytes;
    regions[nreg].model = base;
    regions[nreg].index = 0;
    regions[nreg].plane = 0;
    nreg++;
}

/*
 * evaluator-default and evaluator-worst BESIDE the program: the slot's planes registered as in the alone
 * rows, each program block's HOT region (header, rules, instructions, bindings, set data, the
 * hold-harmless arrays) as a program region, and every other object the request path reads (the map
 * descriptors, the hold-harmless view, the evaluation context, the requests, the verdict) as other
 * data. A read outside all of them is the model's existing refusal (exit 2), never a silent miss.
 * Printed: index misses per plane, so the gate can hold each beside its alone-row, and program misses,
 * which `@llc` (the LLC run) requires to be zero.
 */
static int residency_ev(const char *cfg, uint64_t l2, uint32_t l2w, uint64_t llc, uint32_t llcw, uint32_t line, uint32_t count)
{
    char slot[96];
    const char *at = strchr(cfg, '@');
    int force_llc = at != NULL && !strcmp(at, "@llc");
    const ev_slot_t *s;
    ev_run_t r;
    we_verdict_t v;
    size_t ib = 0, hot, total;
    uint64_t base = 0x100000000ull;
    uint32_t p, k;
    const char *level;

    snprintf(slot, sizeof slot, "%.*s", at != NULL ? (int)(at - cfg) : (int)strlen(cfg), cfg);
    s = ev_find(slot);
    ev_prepare(s, count, &r);
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        if (r.views[p] != NULL) {
            ib += dp_regions(r.views[p], base * (p + 1u), p);
            obj_region(r.views[p], sizeof *r.views[p], base * 0x40u + p * 0x1000u);
        }
    }
    ad_block(r.floor, &hot, &total);
    regions[nreg].lo = (const uint8_t *)r.floor; regions[nreg].hi = (const uint8_t *)r.floor + hot;
    regions[nreg].model = base * 0x20u; regions[nreg].index = 2; regions[nreg].plane = 0; nreg++;
    obj_region((const uint8_t *)r.floor + hot, total - hot, base * 0x20u + hot);
    if (r.ctx != NULL) {
        ad_block(r.ctx, &hot, &total);
        regions[nreg].lo = (const uint8_t *)r.ctx; regions[nreg].hi = (const uint8_t *)r.ctx + hot;
        regions[nreg].model = base * 0x28u; regions[nreg].index = 2; regions[nreg].plane = 0; nreg++;
        obj_region((const uint8_t *)r.ctx + hot, total - hot, base * 0x28u + hot);
    }
    obj_region(r.hh, sizeof *r.hh, base * 0x41u);
    obj_region(r.ectx, sizeof *r.ectx, base * 0x42u);
    obj_region(r.req, (size_t)count * sizeof *r.req, base * 0x43u);
    obj_region(&v, sizeof v, base * 0x44u);
    level = model_init(ib, force_llc, l2, l2w, llc, llcw, line);
    counting = 1;
    for (k = 0; k < count; k++) { ev_one(&r, k, &v); }
    printf("residency %s beside the program, against the %s: %u requests; plane index misses %llu, program reads %llu "
           "misses %llu, other reads %llu misses %llu\n", cfg, level, count, (unsigned long long)idx_miss,
           (unsigned long long)prog_reads, (unsigned long long)prog_miss, (unsigned long long)other_reads,
           (unsigned long long)other_miss);
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        if (r.views[p] != NULL) { printf("PLANE\t%s\t%llu\n", ew_names[p], (unsigned long long)plane_miss[p]); }
    }
    printf("RESULT\t%s\t%s\t%llu\t%llu\t%llu\n", cfg, level, (unsigned long long)idx_miss, (unsigned long long)count,
           (unsigned long long)prog_miss);
    return 0;
}

/*
 * C3 AND C5, the whole bound per request (POLICY.md section 3.7 and rows C3 and C5).
 *
 * `bound <slot> <n>` runs the slot's first n requests twice over. Once through we_decide, with every
 * traced load (the planes' WE_TRACE_READ, the evaluator's WE_TRACE_EVAL) recorded as a set of distinct
 * 64-byte lines: what the request READ. Once through a MODEL that never calls the evaluator: each find
 * the request performs replayed ALONE (the hold-harmless lookup on the floor's address, and every fill
 * of every plane on each address the programs read it on, in the order section 2.7 fixes), plus the
 * lines the evaluator's own loads must touch, computed from the block's layout: each visited rule's
 * 16-byte entry, each executed instruction's 8 bytes, each fill's binding template, each filled or
 * peeked plane's valid_until_ms and generation, and each set probe (INSET_COUNTRY's one byte, INSET_ASN's
 * node per level on the section 4.1 S+ path for the address's value). The two sets must be EQUAL on
 * every request: a load the model does not name, or a modelled line never read, fails by name.
 *
 * Held only on slots that take no jump (the model's executed instructions are every instruction of
 * every visited rule); C3 asserts that on the two worst slots (jumps_taken == 0, and instructions
 * executed == the two blocks' instruction counts) and counts their fills (evaluator-worst-lines: 16).
 * Not held here, and said so: the context WRITES of section 3.7 (W(ctx): the views, the memo entries,
 * the verdict), which no read hook sees; and the comparison with a PRINTED line bound, because the
 * compiler prints none yet.
 */
typedef struct { uint64_t *k; uint32_t cap, n; } lineset_t;
static lineset_t *rec_set WE_CG_PAGE;

static void ls_add(lineset_t *s, uint64_t line)
{
    uint32_t h;
    if (s->k == NULL) { s->cap = 1u << 16; s->k = calloc(s->cap, sizeof *s->k); if (s->k == NULL) { exit(2); } }
    h = (uint32_t)((line * 0x9e3779b97f4a7c15ull) >> 48) & (s->cap - 1u);
    while (s->k[h] != 0u && s->k[h] != line + 1u) { h = (h + 1u) & (s->cap - 1u); }
    if (s->k[h] == 0u) { s->k[h] = line + 1u; s->n++; }
}

static int ls_has(const lineset_t *s, uint64_t line)
{
    uint32_t h = (uint32_t)((line * 0x9e3779b97f4a7c15ull) >> 48) & (s->cap - 1u);
    while (s->k[h] != 0u) { if (s->k[h] == line + 1u) { return 1; } h = (h + 1u) & (s->cap - 1u); }
    return 0;
}

static void ls_clear(lineset_t *s) { if (s->k != NULL) { memset(s->k, 0, s->cap * sizeof *s->k); } s->n = 0; }

static void ls_range(lineset_t *s, const void *p, size_t len)
{
    uint64_t a = (uint64_t)(uintptr_t)p, l;
    for (l = a >> 6; l <= (a + len - 1u) >> 6; l++) { ls_add(s, l); }
}

/*
 * The value a routing atom reads for an address: the record's (the AS, or the country normalised as the
 * fill normalises it) when the address is in a range, the binding's template when it is not. Read from
 * the plane and the block, which is the outcome class the line model is per; never from the evaluator.
 */
static uint32_t bw_value(const we_map_t *m, const we_binding_t *bind, uint32_t op, uint32_t key)
{
    uint32_t i = m != NULL ? we_find4(m, key) : WE_NO_RANGE, asn;
    uint16_t cc;

    if (i == WE_NO_RANGE) {
        memcpy(&asn, bind->tmpl, 4);
        memcpy(&cc, bind->tmpl + 4, 2);
    } else {
        const uint8_t *r = m->f4.records + (size_t)i * m->f4.stride;
        memcpy(&asn, r + 4, 4);
        memcpy(&cc, r + 8, 2);
        cc = we_country(m, cc);
    }
    return (op & WE_OP_INSET_COUNTRY) ? cc : asn;
}

typedef struct { const ev_run_t *r; lineset_t *m; uint8_t filled[2][8]; uint32_t key[2]; int alias; } bm_t;

static void bm_fill(bm_t *b, uint32_t slot, uint32_t ix)
{
    const we_binding_t *bind = b->r->hh->bindings;
    const we_map_t *m = b->r->views[ix + 1u];
    if (b->alias) { slot = 0; }
    if (b->filled[slot][ix]) { return; }
    b->filled[slot][ix] = 1;
    /* C5's negative control: the model forgets the binding template, and the comparison must fail */
    if (getenv("WE_CG_PLANT_C5") == NULL) { ls_range(b->m, bind[ix].tmpl, 16); }
    if (m == NULL) { return; }
    ls_range(b->m, &m->valid_until_ms, 8);
    ls_range(b->m, &m->generation, 8);
    {
        /* replayed alone: its own hooks name its lines; then the record read the fill makes after it, which
         * the find does not (format 1 keeps the severity in its own array, a line of its own) */
        uint32_t i = we_find4(m, b->key[slot]);
        if (i != WE_NO_RANGE) {
            if (m->f4.sev != NULL) { ls_range(b->m, m->f4.sev + i, 1); }
            else { ls_range(b->m, m->f4.records + (size_t)i * m->f4.stride, m->f4.stride); }
        }
    }
}

static void bm_program(bm_t *b, const we_program_t *p, uint32_t slot, uint32_t nvis)
{
    const uint8_t *base = (const uint8_t *)p;
    const we_rule_t *rules = (const we_rule_t *)(const void *)(base + p->rules_off);
    const we_instr_t *ins = (const we_instr_t *)(const void *)(base + p->instrs_off);
    uint32_t r, pc;

    for (r = 0; r < nvis; r++) {
        ls_range(b->m, rules + r, 16);
        if (rules[r].flags & WE_RF_INERT) { continue; }
        for (pc = rules[r].instr_start; pc < (uint32_t)rules[r].instr_start + rules[r].instr_count; pc++) {
            const we_instr_t *I = ins + pc;
            uint32_t pl = I->plane & 7u;
            ls_range(b->m, I, 8);
            if (!(I->op & WE_OP_ATOM)) { continue; }
            if (I->op & WE_OP_ISUNK) {
                uint32_t s = b->alias ? 0u : slot;
                const we_map_t *m = b->r->views[pl + 1u];
                if (!b->filled[s][pl] && m != NULL) {      /* the peek: the state without a lookup */
                    ls_range(b->m, &m->valid_until_ms, 8);
                    ls_range(b->m, &m->generation, 8);
                }
                continue;
            }
            bm_fill(b, slot, pl);
            if (I->op & WE_OP_INSET_COUNTRY) {
                uint32_t c = bw_value(b->r->views[pl + 1u], b->r->hh->bindings + pl, I->op, b->key[b->alias ? 0 : slot]);
                ls_range(b->m, base + I->imm + (c >> 3), 1);
            }
            if (I->op & WE_OP_INSET_ASN) {
                /* the section 4.1 S+ path for this value: one node per level */
                const uint8_t *pay = base + WE_ASN_IMM_OFF(I->imm);
                uint32_t n = WE_ASN_IMM_N(I->imm), lv = WE_ASN_IMM_LEVELS(I->imm);
                uint32_t a = bw_value(b->r->views[pl + 1u], b->r->hh->bindings + pl, I->op, b->key[b->alias ? 0 : slot]);
                uint32_t ap = a - (a == 0xffffffffu ? 1u : 0u);
                uint32_t m0 = (n + 15u) >> 4, m1 = (m0 + 16u) / 17u, node = 0, loff = 0, size = 1, l, c;
                for (l = lv; l > 0u; l--) {
                    const we_node32_t *nd = (const we_node32_t *)(const void *)(pay + loff + (size_t)node * 64u);
                    ls_range(b->m, nd, 64);
                    c = 0;
                    c += (nd->k[c + 7u] <= ap) ? 8u : 0u;
                    c += (nd->k[c + 3u] <= ap) ? 4u : 0u;
                    c += (nd->k[c + 1u] <= ap) ? 2u : 0u;
                    c += (nd->k[c] <= ap) ? 1u : 0u;
                    c += (nd->k[c] <= ap) ? 1u : 0u;
                    loff += size * 64u;
                    size = (l == 2u) ? m0 : m1;
                    node = node * 17u + c;
                }
            }
        }
    }
}

/* what a line belongs to, for a failure message: which plane's map or buffer, which block and where */
static void bm_name(const ev_run_t *r, uint64_t line, char *buf, size_t n)
{
    uintptr_t a = (uintptr_t)(line << 6);
    uint32_t p;
    const we_program_t *blk[2] = { r->floor, r->ctx };
    for (p = 1; p <= WE_PLANE_MAX; p++) {
        const we_map_t *m = r->views[p];
        if (m == NULL) { continue; }
        if (a + 64u > (uintptr_t)m && a < (uintptr_t)(m + 1)) {
            snprintf(buf, n, "the %s map descriptor, bytes %ld..%ld", ew_names[p], (long)a - (long)(uintptr_t)m,
                     (long)a - (long)(uintptr_t)m + 63);
            return;
        }
        if (a + 64u > (uintptr_t)m->base && a < (uintptr_t)m->base + m->len) {
            snprintf(buf, n, "the %s plane buffer, offset %lu", ew_names[p], (unsigned long)(a - (uintptr_t)m->base));
            return;
        }
    }
    if (a + 64u > (uintptr_t)r->hh && a < (uintptr_t)(r->hh + 1)) {
        snprintf(buf, n, "the hold-harmless view, bytes %ld..", (long)a - (long)(uintptr_t)r->hh);
        return;
    }
    for (p = 0; p < 2u; p++) {
        if (blk[p] != NULL && a + 64u > (uintptr_t)blk[p] && a < (uintptr_t)blk[p] + blk[p]->total_len) {
            uint32_t o = (uint32_t)(a - (uintptr_t)blk[p]);
            snprintf(buf, n, "the %s block, offset %u (rules %u, instrs %u, bindings %u, sets %u, hh %u, setdata %u, text %u)",
                     p ? "context" : "floor", o, blk[p]->rules_off, blk[p]->instrs_off, blk[p]->bindings_off,
                     blk[p]->sets_off, blk[p]->hh_off, blk[p]->setdata_off, blk[p]->text_off);
            return;
        }
    }
    snprintf(buf, n, "no object this driver knows");
}

/*
 * C2's exact half: `fills <slot> <n>` prints the finds the slot's first n requests perform and the number
 * a memo that never hits adds by the model. On evaluator-default that is one reputation refill for every
 * request that reaches rule 2 (not exempt, not denied at rule 1); on evaluator-memo, 31 per request (32
 * rules on one plane, one fill). The gate runs it on the traced driver with and without the mutant and
 * holds the difference to the model's count exactly; instructions per refill vary with the address on
 * the dense stream, finds do not.
 */
static int fills(const char *slot, uint32_t count)
{
    const ev_slot_t *s = ev_find(slot);
    ev_run_t r;
    we_verdict_t v;
    uint64_t total = 0, extra = 0;
    uint32_t k, p;

    rec_discard = 1;
    ev_prepare(s, count, &r);
    for (k = 0; k < count; k++) {
        ev_one(&r, k, &v);
        for (p = 0; p < 8u; p++) { total += v.lookups[0][p] + v.lookups[1][p]; }
        if (!strcmp(slot, "evaluator-memo")) {
            extra += 31u;
        } else if (!strcmp(slot, "evaluator-default")) {
            uint32_t a = q4[k];
            int64_t i4;
            if (dp_ref(&hh4, a) >= 0) { continue; }
            i4 = dp_ref(&rep4, a);
            if ((i4 >= 0 ? (uint8_t)(dp_rep_sev4[i4] & 0x0fu) : 0u) < WE_SEV_CRITICAL) { extra++; }
        }
    }
    printf("FILLS\t%s\t%u\t%llu\t%llu\n", slot, count, (unsigned long long)total, (unsigned long long)extra);
    return 0;
}

static int bound(const char *slot, uint32_t count)
{
    const ev_slot_t *s = ev_find(slot);
    ev_run_t r;
    we_verdict_t v;
    lineset_t traced = { 0 }, model = { 0 };
    uint32_t k, lo = UINT32_MAX, hi = 0, bad = 0, i;
    int worst = !strcmp(slot, "evaluator-worst"), lines = !strcmp(slot, "evaluator-worst-lines");

    ev_prepare(s, count, &r);
    for (k = 0; k < count; k++) {
        bm_t b;
        uint32_t f, sv, fvis, cvis;

        ls_clear(&traced);
        rec_set = &traced;
        ev_one(&r, k, &v);
        rec_set = NULL;

        /* C3, on the two worst slots */
        if (worst || lines) {
            /* C3's negative control: one instruction more than the blocks hold must be refused */
            uint32_t want = r.floor->instr_count + r.ctx->instr_count + (getenv("WE_CG_PLANT_C3") != NULL), fills = 0, p;
            for (p = 0; p < 8u; p++) { fills += v.lookups[0][p] + v.lookups[1][p]; }
            if (v.jumps_taken != 0u || v.ops_executed != want || (lines && fills != 16u) || (worst && fills != 3u)) {
                printf("C3 FAIL %s request %u: %u instructions executed against %u in the two blocks, %u jumps taken, "
                       "%u fills (%u expected)\n", slot, k, v.ops_executed, want, v.jumps_taken, fills, lines ? 16u : 3u);
                return 1;
            }
        }

        /* the model: never the evaluator */
        memset(&b, 0, sizeof b);
        b.r = &r;
        b.m = &model;
        f = ntohl(*(const uint32_t *)(const void *)r.req[k].floor.b);
        sv = ntohl(*(const uint32_t *)(const void *)r.req[k].server.b);
        b.key[0] = f;
        b.key[1] = sv;
        b.alias = f == sv;
        ls_clear(&model);
        rec_set = &model;
        if (r.req[k].hold_harmless_eligible && we_find4(&r.hh->map, f) != WE_NO_RANGE) {
            rec_set = NULL;
        } else {
            bm_fill(&b, 0, 7u);                         /* the pre-stage's tenant entry, on the floor's address */
            fvis = v.program == WE_VPROG_FLOOR ? v.rule : r.floor->rule_count;
            bm_program(&b, r.floor, 0, fvis);
            if (v.program != WE_VPROG_FLOOR && r.ctx != NULL) {
                cvis = v.program == WE_VPROG_CONTEXT ? v.rule : r.ctx->rule_count;
                bm_program(&b, r.ctx, 1, cvis);
            }
            rec_set = NULL;
        }

        /* equal, line for line */
        if (traced.n != model.n) { bad++; }
        else {
            for (i = 0; i < traced.cap; i++) {
                if (traced.k[i] != 0u && !ls_has(&model, traced.k[i] - 1u)) { bad++; break; }
            }
        }
        if (bad) {
            uint32_t shown = 0;
            printf("C5 FAIL %s request %u: %u distinct lines read, the model names %u\n", slot, k, traced.n, model.n);
            for (i = 0; i < traced.cap && shown < 6; i++) {
                if (traced.k[i] != 0u && !ls_has(&model, traced.k[i] - 1u)) {
                    char nm[200];
                    bm_name(&r, traced.k[i] - 1u, nm, sizeof nm);
                    printf("  read, not modelled: %s\n", nm); shown++;
                }
            }
            for (i = 0; i < model.cap && shown < 12; i++) {
                if (model.k[i] != 0u && !ls_has(&traced, model.k[i] - 1u)) {
                    char nm[200];
                    bm_name(&r, model.k[i] - 1u, nm, sizeof nm);
                    printf("  modelled, not read: %s\n", nm); shown++;
                }
            }
            return 1;
        }
        if (traced.n < lo) { lo = traced.n; }
        if (traced.n > hi) { hi = traced.n; }
    }
    printf("ok   C5 %s: on all %u requests the distinct 64-byte lines read equal the model's, line for line "
           "(%u to %u per request)%s\n", slot, count, lo, hi,
           worst || lines ? "; C3: no jump taken, every instruction of both blocks executed, the fills counted" : "");
    printf("BOUND\t%s\t%u\t%u\t%u\n", slot, count, lo, hi);
    return 0;
}

static void ls_range_hook(const void *p, size_t len)
{
    rec_armed = rec_set != NULL;
    if (rec_set != NULL) { ls_range(rec_set, p, len); }
}

/* C6: the acquire loads of the module's decision, counted at we_current(), against popcount((floor | context | tenant) & bound) */
static int md_views(const char *slot, uint32_t n)
{
    const ev_slot_t *s = ev_find(slot);
    uint32_t k, want, mask;

    if (s->kind < K_MOD) { fprintf(stderr, "%s is not a module slot\n", slot); return 2; }
    rec_discard = 1;                   /* the traced build counts reads of the views, it models no cache */
    md_prepare(s, n);
    mask = ((uint32_t)md.cfg.floor->plane_mask | (md.r.ctx != NULL ? (uint32_t)md.r.ctx->plane_mask : 0u) | 0x80u) & md.cfg.bound_mask;
    want = (uint32_t)__builtin_popcount(mask);
    for (k = 0; k < n; k++) {
        cg_views_read = 0;
        md_one(k);
        if (cg_views_read != want) {
            printf("C6 FAIL %s request %u: %llu we_current() reads, the mask has %u bits\n", slot, k,
                   (unsigned long long)cg_views_read, want);
            return 1;
        }
    }
    printf("ok   C6 %s: on all %u requests we_current() was read exactly %u times, popcount((floor | context | tenant) & bound = 0x%02x)\n",
           slot, n, want, mask);
    return 0;
}

/*
 * C5+, THE MODULE HALF, under the module's layout rule: the lines the module's own path touches beyond the evaluator's
 * reads, per request, equal to a model that never calls the module. Two sets are traced: the handle lines
 * we_current() reads (cg_current, the counting wrapper above, records the handle's `current` field) and the
 * shard lines we_mod_count() writes (we_module.h's WE_TRACE_COUNT hook). The model: for the handles, the line
 * of each referenced bound plane's handle (popcount((floor | context | tenant) & bound) handles, C6's count,
 * here by address); for the counters, the lines the LAYOUT RULE gives the counted indices, computed
 * arithmetically from the shard's base, never from the pointer the module took: the pre-stage's eight named
 * counters at 0..7, the floor's rules from WE_MOD_CTR_FLOOR, the context's rules right after the floor's
 * (we_mod_config_build's order), each index's line being base_line + index / 8. The indices a request counts
 * are what we_mod_decide counts: the walk's note or header-missing mark, the deciding rule (allow-by-unknown
 * included) or the pre-stage step's counter, and every log bit of both bitmaps. Before any request: the
 * shard base and the stride are whole lines (the layout rule: "shard bases and the scratch 64-byte aligned and
 * strides a multiple of 64"), the scratch and the lazy-fill local are 64-byte aligned, and the eight view stores
 * are one line. Three planted layouts, each read from the environment, must each fail by name:
 * WE_CG_PLANT_STRIDE (a base eight bytes into its line and a stride one counter over), WE_CG_PLANT_SCRATCH
 * (the scratch 32 bytes into its line, so the view stores span two lines), WE_CG_PLANT_SPLIT (the context's
 * counters eight slots past the floor's, off the layout rule: the traced lines move, the model's do not).
 */
static lineset_t *hdl_set WE_CG_PAGE;
static lineset_t *cnt_set WE_CG_PAGE;
static void md_trace_handle(const void *p) { if (hdl_set != NULL) { ls_range(hdl_set, p, sizeof(we_map_t *)); } }
void we_trace_count(const void *p) { if (cnt_set != NULL) { ls_range(cnt_set, p, sizeof(uint64_t)); } }

/* the indices one request counts, as we_mod_decide counts them, each added as the layout rule's line */
static void md_model_counts(const we_verdict_t *v, const we_mod_req_t *q, uint32_t ctx_base, uint64_t base_line, lineset_t *out)
{
    uint32_t r;

    if ((q->note | (uint32_t)(q->r.walk == WE_WALK_FLOOR_HEADER_MISSING)) != 0u) {
        ls_add(out, base_line + ((WE_MOD_CTR_FLOOR_HEADER_MISSING + (q->note & 3u)) >> 3));
    }
    if (v->rule != 0u) {
        ls_add(out, base_line + (((v->program == WE_VPROG_FLOOR ? WE_MOD_CTR_FLOOR : ctx_base) + v->rule - 1u) >> 3));
    } else if (v->step == WE_STEP_EXEMPT) {
        ls_add(out, base_line + (((uint32_t)v->reason - 2u + (uint32_t)(v->reason == WE_WHY_NO_ADDRESS)) >> 3));
    } else if (v->step == WE_STEP_TENANT || v->step == WE_STEP_STALE_TENANT) {
        ls_add(out, base_line + (((uint32_t)v->step - (uint32_t)(v->step == WE_STEP_STALE_TENANT)) >> 3));
    }
    for (r = 0; r < 256u; r++) {
        if ((v->log_fired[0][r / 8u] >> (r % 8u)) & 1u) { ls_add(out, base_line + ((WE_MOD_CTR_FLOOR + r) >> 3)); }
        if ((v->log_fired[1][r / 8u] >> (r % 8u)) & 1u) { ls_add(out, base_line + ((ctx_base + r) >> 3)); }
    }
}

static int ls_equal(const lineset_t *a, const lineset_t *b)
{
    uint32_t i;

    if (a->n != b->n) { return 0; }
    for (i = 0; i < a->cap; i++) {
        if (a->k[i] != 0u && !ls_has(b, a->k[i] - 1u)) { return 0; }
    }
    return 1;
}

static void ls_print_diff(const char *what, const lineset_t *got, const lineset_t *want)
{
    uint32_t i, shown = 0;

    for (i = 0; i < got->cap && shown < 4u; i++) {
        if (got->k[i] != 0u && !ls_has(want, got->k[i] - 1u)) { printf("  %s line 0x%llx touched, not modelled\n", what, (unsigned long long)(got->k[i] - 1u)); shown++; }
    }
    for (i = 0; want->k != NULL && i < want->cap && shown < 8u; i++) {
        if (want->k[i] != 0u && !ls_has(got, want->k[i] - 1u)) { printf("  %s line 0x%llx modelled, not touched\n", what, (unsigned long long)(want->k[i] - 1u)); shown++; }
    }
}

static int md_bound(const char *slot, uint32_t n)
{
    const ev_slot_t *s = ev_find(slot);
    lineset_t th = { 0 }, tc = { 0 }, mh = { 0 }, mc = { 0 }, vs = { 0 };
    uint32_t k, p, mask, ctx_base, lo_c = UINT32_MAX, hi_c = 0, nh = 0;
    uint64_t base_line;

    if (s->kind < K_MOD) { fprintf(stderr, "%s is not a module slot\n", slot); return 2; }
    rec_discard = 1;                   /* the traced build records the module's own lines; it models no cache */
    md_prepare(s, n);
    if (((uintptr_t)md.shard & 63u) != 0u) {
        printf("C5+ FAIL %s: the shard base is not 64-byte aligned (%u bytes into its line)\n", slot, (unsigned)((uintptr_t)md.shard & 63u));
        return 1;
    }
    if (((size_t)md.stride * sizeof *md.shard) % 64u != 0u) {
        printf("C5+ FAIL %s: the shard stride, %u counters (%zu bytes), is not a multiple of 64 bytes\n", slot, md.stride, (size_t)md.stride * sizeof *md.shard);
        return 1;
    }
    if (((uintptr_t)md.s & 63u) != 0u || ((uintptr_t)md.local & 63u) != 0u) {
        printf("C5+ FAIL %s: the scratch (%u bytes into its line) or the lazy-fill local (%u) is not 64-byte aligned\n", slot,
               (unsigned)((uintptr_t)md.s & 63u), (unsigned)((uintptr_t)md.local & 63u));
        return 1;
    }
    ls_range(&vs, &md.s->e.view[0], sizeof md.s->e.view);
    if (vs.n != 1u) {
        printf("C5+ FAIL %s: the eight view stores span %u lines, not one\n", slot, vs.n);
        return 1;
    }
    mask = ((uint32_t)md.cfg.floor->plane_mask | (md.r.ctx != NULL ? (uint32_t)md.r.ctx->plane_mask : 0u) | 0x80u) & md.cfg.bound_mask;
    ctx_base = WE_MOD_CTR_FLOOR + md.cfg.floor->rule_count;       /* the layout rule, never md.ctx.ctr_off */
    base_line = (uint64_t)(uintptr_t)md.shard >> 6;
    for (p = 0; p < 8u; p++) {
        if ((mask >> p) & 1u) { ls_range(&mh, &md.h[p].current, sizeof(we_map_t *)); }
    }
    nh = mh.n;
    for (k = 0; k < n; k++) {
        ls_clear(&th);
        ls_clear(&tc);
        hdl_set = &th;
        cnt_set = &tc;
        md_one(k);
        hdl_set = NULL;
        cnt_set = NULL;
        ls_clear(&mc);
        md_model_counts(&md.s->v, &md.q[k], ctx_base, base_line, &mc);
        if (!ls_equal(&th, &mh)) {
            printf("C5+ FAIL %s request %u: %u handle lines read, the model names %u\n", slot, k, th.n, mh.n);
            ls_print_diff("handle", &th, &mh);
            return 1;
        }
        if (!ls_equal(&tc, &mc)) {
            printf("C5+ FAIL %s request %u: %u counter lines written, the model names %u\n", slot, k, tc.n, mc.n);
            ls_print_diff("counter", &tc, &mc);
            return 1;
        }
        if (tc.n < lo_c) { lo_c = tc.n; }
        if (tc.n > hi_c) { hi_c = tc.n; }
    }
    printf("ok   C5+ %s: on all %u requests the handle lines read (%u, one per referenced bound plane) and the counter lines "
           "written (%u to %u) equal the model's, line for line; the shard base and stride (%u counters) whole lines, the "
           "scratch and the lazy-fill local 64-byte aligned, the eight view stores one line\n", slot, n, nh, lo_c, hi_c, md.stride);
    printf("MBOUND\t%s\t%u\t%u\t%u\t%u\n", slot, n, nh, lo_c, hi_c);
    return 0;
}

#endif
#endif

#ifdef WE_HAVE_EVAL
/*
 * C5+'s layout figures, as this compiler lays the types out (the layout rule above): the scratch 1,024 bytes
 * on a 64-byte boundary with the views first, the record nine lines with its provenance fields where the
 * header's ABI asserts put them. Printed from the production build (the trace build's scratch is larger by
 * design, so that build prints its figures and judges the alignments only), compared with the header's
 * figures, so the gate's log carries them beside the measurements.
 */
static int md_layout(void)
{
    int bad = 0;

    printf("layout: sizeof(we_mod_scratch_t) %zu, alignof %zu, views at %zu; sizeof(we_mod_record_t) %zu, alignof %zu, "
           "digest4 at %zu, disarmed_mask at %zu, gen_mask at %zu; sizeof(we_handle_t) %zu, current at %zu\n",
           sizeof(we_mod_scratch_t), _Alignof(we_mod_scratch_t), offsetof(we_mod_scratch_t, e),
           sizeof(we_mod_record_t), _Alignof(we_mod_record_t), offsetof(we_mod_record_t, digest4),
           offsetof(we_mod_record_t, disarmed_mask), offsetof(we_mod_record_t, gen_mask),
           sizeof(we_handle_t), offsetof(we_handle_t, current));
#ifndef WE_TRACE
    bad |= sizeof(we_mod_scratch_t) != 1024u;
#endif
    bad |= _Alignof(we_mod_scratch_t) != 64u || offsetof(we_mod_scratch_t, e) != 0u;
    bad |= sizeof(we_mod_record_t) != 576u || _Alignof(we_mod_record_t) != 64u || offsetof(we_mod_record_t, digest4) != 512u
        || offsetof(we_mod_record_t, disarmed_mask) != 465u || offsetof(we_mod_record_t, gen_mask) != 547u;
    bad |= offsetof(we_handle_t, current) != 0u;
    if (bad) {
        printf("C5+ FAIL layout: a figure above is not the header's (scratch 1024/64/0, record 576/64/512/465/547, handle current at 0)\n");
        return 1;
    }
    printf("ok   C5+ layout: the scratch is 1,024 bytes on a 64-byte boundary with the views first, the record 576 bytes with "
           "its provenance fields where section 5.2 puts them\n");
    return 0;
}
#endif

/* the default slot's soundness terms are means over its first 200,000 requests, so q4 is never shorter */
#define DP_MIN 200000u

/*
 * Every file-scope static, from the scan of this source (gate/cg-statics.py writes gate/cg_statics.h; the gate
 * refuses a committed list that differs from the scan), on its page boundary: NOT PROVEN, never measured,
 * otherwise. WE_CG_PLANT_MISALIGN is the check's own control: one entry one line into its page.
 */
static int cg_alignment(int verbose)
{
#define CG_STATIC(n) { #n, (const void *)&(n) },
    static const struct { const char *name; const void *p; } obj[] = {
#include "cg_statics.h"
#ifdef WE_CG_PLANT_MISALIGN
        { "ew (the control: the evaluator's map descriptors one line into their page)", (const char *)ew + 64 },
#endif
    };
#undef CG_STATIC
    size_t i;
    int bad = 0;

    for (i = 0; i < sizeof obj / sizeof obj[0]; i++) {
        uintptr_t off = (uintptr_t)obj[i].p & 4095u;

        if (off != 0u) {
            printf("NOT PROVEN: the driver's %s sits at page offset %u, so its D1 sets follow the link layout and no D1 "
                   "count of this build is the code's\n", obj[i].name, (unsigned)off);
            bad = 1;
        }
    }
    if (verbose && !bad) {
        printf("ok   every file-scope static of the driver starts a page (%zu objects, from the scan); layout %d\n",
               sizeof obj / sizeof obj[0], WE_CG_LAYOUT);
    }
    return bad;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <dir> cg <slot> <u|d|q|e> <count> | slots | verdicts <slot> <n> | cases <slot> <n>\n"
                        "       %s <dir> residency <config> <l2> <l2 ways> <llc> <llc ways> <line> <count>   (-DWE_TRACE)\n"
                        "       %s <dir> bound <slot> <n>   (-DWE_TRACE: C3 and C5)\n"
                        "       %s <dir> views <slot> <n>   (-DWE_TRACE: C6)\n"
                        "       %s <dir> mbound <slot> <n>  (-DWE_TRACE: C5+, the module half)\n"
                        "       %s <dir> mlayout            (C5+: the scratch's and the record's layout figures)\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    if (!strcmp(argv[2], "align")) {
        return cg_alignment(1) ? 3 : 0;
    }
    if (!strcmp(argv[2], "mlayout")) {
#ifdef WE_HAVE_EVAL
        return md_layout();
#else
        printf("mlayout: EMPTY, this driver was built without the policy evaluator; no module type is laid out\n");
        return 3;
#endif
    }
    if (cg_alignment(0)) {
        return 3;                             /* nothing is measured on a layout that moves the D1 sets */
    }
    load(argv[1]);
    lv_dir = argv[1];
    build_plane4();
    build_plane6();
    build_shipped();
#ifndef WE_TRACE
    if (!strcmp(argv[2], "cg") && argc == 6) {
        uint32_t count = (uint32_t)strtoul(argv[5], NULL, 10);
#ifndef WE_HAVE_EVAL
        if (argv[4][0] == 'e') {
            return cg(argv[3], 0, count);       /* EMPTY, before anything is built */
        }
#endif
        if (argv[4][0] == 'q' || argv[4][0] == 'e') {
            /* the default policy's planes, the evaluator's world and the named streams; not the routing table */
            dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
            if (argv[4][0] == 'q') {
                dp_verify(count);
            }
        } else {
            streams(count);
            verify(count);
        }
        return cg_on_own_stack(argv[3], argv[4][0] == 'd', count);
    }
    if (!strcmp(argv[2], "slots") && argc == 3) {
        dp_build(argv[1], DP_MIN);
        ev_print_slots();
        return 0;
    }
    if (!strcmp(argv[2], "cases") && argc == 5) {
        uint32_t n = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], n > DP_MIN ? n : DP_MIN);
        return ev_cases(argv[3], n);
    }
    if (!strcmp(argv[2], "verdicts") && argc == 5) {
#ifdef WE_HAVE_EVAL
        uint32_t n = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], n > DP_MIN ? n : DP_MIN);
        return ev_verdicts(argv[3], n);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; no verdict exists\n", argv[3]);
        return 3;
#endif
    }
#else
    if (!strcmp(argv[2], "residency") && argc == 10) {
        uint32_t count = (uint32_t)strtoul(argv[9], NULL, 10);
        uint64_t l2 = strtoull(argv[4], NULL, 10), llc = strtoull(argv[6], NULL, 10);
        uint32_t l2w = (uint32_t)strtoul(argv[5], NULL, 10), llcw = (uint32_t)strtoul(argv[7], NULL, 10);
        uint32_t line = (uint32_t)strtoul(argv[8], NULL, 10);

        if (!strcmp(argv[3], "v4") || !strcmp(argv[3], "v6") || !strcmp(argv[3], "both")) {
            streams(count);
            return residency(argv[3], l2, l2w, llc, llcw, line, count);
        }
        if (!strncmp(argv[3], "evaluator-", 10)) {
#ifdef WE_HAVE_EVAL
            dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
            return residency_ev(argv[3], l2, l2w, llc, llcw, line, count);
#else
            printf("%s: EMPTY, this driver was built without the policy evaluator; nothing is modelled\n", argv[3]);
            return 3;
#endif
        }
        dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
        return residency_dp(argv[3], l2, l2w, llc, llcw, line, count);
    }
    if (!strcmp(argv[2], "views") && argc == 5) {
#ifdef WE_HAVE_EVAL
        uint32_t count = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
        md_plant_ninth = getenv("WE_CG_PLANT_NINTH") != NULL;
        return md_views(argv[3], count);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; no view is read\n", argv[3]);
        return 3;
#endif
    }
    if (!strcmp(argv[2], "mbound") && argc == 5) {
#ifdef WE_HAVE_EVAL
        uint32_t count = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
        md_plant_stride = getenv("WE_CG_PLANT_STRIDE") != NULL;
        md_plant_scratch = getenv("WE_CG_PLANT_SCRATCH") != NULL;
        md_plant_split = getenv("WE_CG_PLANT_SPLIT") != NULL;
        return md_bound(argv[3], count);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; no line is modelled\n", argv[3]);
        return 3;
#endif
    }
    if (!strcmp(argv[2], "fills") && argc == 5) {
#ifdef WE_HAVE_EVAL
        uint32_t count = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
        return fills(argv[3], count);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; nothing is counted\n", argv[3]);
        return 3;
#endif
    }
    if (!strcmp(argv[2], "bound") && argc == 5) {
#ifdef WE_HAVE_EVAL
        uint32_t count = (uint32_t)strtoul(argv[4], NULL, 10);
        dp_build(argv[1], count > DP_MIN ? count : DP_MIN);
        return bound(argv[3], count);
#else
        printf("%s: EMPTY, this driver was built without the policy evaluator; no bound is held\n", argv[3]);
        return 3;
#endif
    }
#endif
    fprintf(stderr, "bad arguments\n");
    return 2;
}
