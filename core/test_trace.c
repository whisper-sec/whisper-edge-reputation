/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * test_trace.c - the deterministic bound tests, FORMAT.md §7.
 *
 * Built with -DWE_TRACE, so every load the SHIPPED lookup makes from the mapping goes through
 * we_trace_read() below. For every address that decides an outcome, the traced reads must EQUAL, per
 * lookup, what a data-free model of the structure says that outcome class costs: probes, S-tree depth,
 * index reads, distinct 64- and 128-byte lines, distinct 4 KiB pages, and cold lines (lines outside the
 * index and the S-tree). The model never reads the mapping's keys; it works from the reference range
 * list the fixture was written from and the structure's integers (n, k, s, B, m, d), and the region
 * base addresses only to name the lines.
 *
 * Why per lookup and not per maximum: a mutant that searches one extra window entry finds every range
 * correctly and, on most fixtures, leaves the maximum unchanged. Equality per lookup cannot miss it.
 * The same source built with -DWE_TEST_WINDOW_SLACK=1u is that mutant, and it must FAIL here: the
 * Makefile runs it and requires a non-zero mismatch count.
 *
 * Why the enumeration is exact: every comparison either search makes is against a key from start[],
 * so it is a function of u(a) = #{i : start[i] <= a} alone (and, for radix, of the bucket); the answer
 * depends only on (u, hit). For radix the list is every bucket base and, per range, start - 1, start,
 * end, end + 1; for rank it is 0, the maximum key and the same four per range. That hits every
 * non-empty outcome class, so the maximum over the list is the maximum over the address space. On
 * 64-bit keys every address is also looked up with the low 64 bits of the client address at 0 and at
 * all ones, so the 128-to-64 truncation is exercised.
 *
 * Usage:
 *     test_trace <tmpdir>                synthetic fixtures (uniform and adversarial), every kind/width
 *     test_trace <tmpdir> --live <dir>   the live-shaped RouteViews fixtures (make check-live)
 *     test_trace <tmpdir> --file <bin>   one named plane: its maxima and working set (interop-gate.sh)
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef WE_TRACE
#error "test_trace.c is the trace build: compile it with -DWE_TRACE"
#endif

#include "whisper_edge.h"
#include "we_writer.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WE_TEST_WINDOW_SLACK
#define MUTANT 1
#else
#define MUTANT 0
#endif

static long long checks = 0;
static long long failures = 0;
static int printed = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        if (printed++ < 40) { printf("  FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
    } \
} while (0)

/* ---- the recorder ---- */

#define TR_CAP 256
static struct { uintptr_t a; size_t len; } tr[TR_CAP];
static int ntr;

void we_trace_read(const void *p, size_t len)
{
    if (ntr < TR_CAP) {
        tr[ntr].a = (uintptr_t)p;
        tr[ntr].len = len;
    }
    ntr++;
}

/* ---- a fixture: the reference ranges and the loaded family ---- */

typedef struct {
    const char        *name;
    int                family;      /* 4 or 6 */
    uint32_t           kb;          /* key bytes */
    uint32_t           n;
    const __uint128_t *start;       /* reference: what the file was written from */
    const __uint128_t *end;
    uint32_t           kind;        /* the file's kind */
    uint32_t           k;           /* radix k */
    uint32_t           s, fan, m, depth;
    uint32_t          *prefix;      /* radix: #starts with bucket < b, b in [0, 2^k] */
    const we_fam_t    *f;           /* the loaded family: region bases only */
    const we_map_t    *map;
    uintptr_t          base;        /* the mapping's byte 0: lines and pages count from FILE OFFSETS */
    int                f1;          /* format 1: end[] and sev[], not records */
    __uint128_t        kmax;
} fx_t;

typedef struct {
    uint32_t probes, depth, idx_reads, lines64, lines128, pages, cold64, cold128, stray;
    uint32_t table_reads;           /* reads of the radix arm's table, mapped or the one-bucket one */
    uint32_t result;
} met_t;

/* A read interval and whether it is cold (outside the index and the S-tree). */
typedef struct { uintptr_t lo, hi; int cold; } iv_t;

static uint32_t distinct(const iv_t *v, int n, int shift, int cold_only)
{
    uintptr_t u[TR_CAP * 2];
    uint32_t k = 0;
    int i;

    for (i = 0; i < n; i++) {
        uintptr_t x;

        if (cold_only && !v[i].cold) {
            continue;
        }
        for (x = v[i].lo >> shift; x <= (v[i].hi >> shift); x++) {
            uint32_t j;
            int seen = 0;

            for (j = 0; j < k; j++) {
                if (u[j] == x) {
                    seen = 1;
                    break;
                }
            }
            if (!seen && k < (uint32_t)(sizeof u / sizeof u[0])) {
                u[k++] = x;
            }
        }
    }
    return k;
}

static void finish(met_t *mt, const iv_t *v, int n)
{
    mt->lines64 = distinct(v, n, 6, 0);
    mt->lines128 = distinct(v, n, 7, 0);
    mt->pages = distinct(v, n, 12, 0);
    mt->cold64 = distinct(v, n, 6, 1);
    mt->cold128 = distinct(v, n, 7, 1);
}

static int within(uintptr_t a, const void *base, size_t len)
{
    return base != NULL && a >= (uintptr_t)base && a < (uintptr_t)base + len;
}

/*
 * Classify what the shipped lookup actually read. Every interval is the bytes the recorder saw, at
 * their FILE OFFSET (address minus the mapping's byte 0): mmap puts offset 0 on a page, so that is how
 * the manifest counts lines and pages (FORMAT.md 7). Nothing is widened here. A miss's end read is the
 * end field's bytes only, and the whole record on a hit is a read the harness makes through the shipped
 * we_record_of(), so a record straddling a line is MEASURED, never assumed.
 */
static met_t traced(const fx_t *x, uint32_t result)
{
    const we_fam_t *f = x->f;
    size_t idx_len = f->file_kind == WE_KIND_RADIX ? (((size_t)1 << x->k) + 1u) * 4u : 0u;
    size_t st_len = (size_t)f->nodes * 64u;
    iv_t v[TR_CAP];
    int nv = 0, i;
    met_t mt;

    memset(&mt, 0, sizeof mt);
    mt.result = result;
    for (i = 0; i < ntr && i < TR_CAP; i++) {
        uintptr_t a = tr[i].a;
        uintptr_t off = a - x->base;

        if (within(a, f->idx, idx_len) && f->file_kind == WE_KIND_RADIX) {
            mt.idx_reads++;
            mt.table_reads++;
            v[nv].lo = off; v[nv].hi = off + tr[i].len - 1u; v[nv++].cold = 0;
        } else if (within(a, f->stree, st_len)) {
            mt.depth++;
            v[nv].lo = off; v[nv].hi = off + tr[i].len - 1u; v[nv++].cold = 0;
        } else if (within(a, f->start, (size_t)x->n * x->kb)) {
            mt.probes++;
            v[nv].lo = off; v[nv].hi = off + tr[i].len - 1u; v[nv++].cold = 1;
        } else if (within(a, f->end, (size_t)x->n * f->stride)
                   || (f->sev != NULL && within(a, f->sev, x->n))) {
            v[nv].lo = off; v[nv].hi = off + tr[i].len - 1u; v[nv++].cold = 1;
        } else if (within(a, f->idx, 8u) && f->file_kind != WE_KIND_RADIX) {
            mt.table_reads++;        /* kind none: the one-bucket table, outside the mapping, no line */
        } else {
            mt.stray++;
        }
    }
    if (ntr > TR_CAP) {
        mt.stray += (uint32_t)(ntr - TR_CAP);
    }
    finish(&mt, v, nv);
    return mt;
}

/* #{i : start[i] <= a}, on the reference list. */
static uint32_t upper(const fx_t *x, __uint128_t a)
{
    uint32_t lo = 0, hi = x->n;

    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if (x->start[mid] <= a) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static uint32_t bucket(const fx_t *x, __uint128_t a)
{
    return (uint32_t)(a >> (x->kb * 8u - x->k));
}

/* The data-free model: what the structure says this address costs. */
static met_t model(const fx_t *x, __uint128_t a)
{
    const we_fam_t *f = x->f;
    uint32_t u = upper(x, a);
    uint32_t lo, hi;
    iv_t v[TR_CAP];
    int nv = 0;
    met_t mt;

    memset(&mt, 0, sizeof mt);
    mt.result = (u > 0u && a <= x->end[u - 1u]) ? u - 1u : WE_NO_RANGE;
    if (u == 0u) {
        /* below start[0]: answered from the arm-time copy, no load at all, either kind (FORMAT.md 4.2) */
        return mt;                       /* every count stays 0: no read at all */
    }
    if (x->kind == WE_KIND_RADIX) {
        uint32_t b = bucket(x, a);
        uintptr_t p = (uintptr_t)(f->idx + b) - x->base;

        v[nv].lo = p; v[nv].hi = p + 3u; v[nv++].cold = 0;
        v[nv].lo = p + 4u; v[nv].hi = p + 7u; v[nv++].cold = 0;
        mt.idx_reads = 2u;
        mt.table_reads = 2u;
        lo = x->prefix[b];
        hi = x->prefix[b + 1u];
    } else if (x->kind == WE_KIND_RANK) {
        /* separators <= a; the maximum key also matches every padding slot */
        uint64_t full = 1u;
        uint64_t r, node = 0u, place;
        uint32_t l, j;

        for (l = 0; l < x->depth; l++) {
            full *= x->fan;
        }
        r = (a == x->kmax) ? full - 1u : (u == 0u ? 0u : (uint64_t)((u - 1u) / x->s));
        place = full / x->fan;
        for (l = 0; l < x->depth; l++) {
            uint64_t c = (r / place) % x->fan;
            uintptr_t p = (uintptr_t)f->stree - x->base + (uintptr_t)node * 64u;

            v[nv].lo = p; v[nv].hi = p + 63u; v[nv++].cold = 0;
            mt.depth++;
            node = node * x->fan + c + 1u;
            place /= x->fan;
        }
        j = (uint32_t)(r < (uint64_t)x->m - 1u ? r : (uint64_t)x->m - 1u);
        lo = j * x->s + 1u;
        hi = j * x->s + x->s < x->n ? j * x->s + x->s : x->n;
    } else {
        lo = 0u;                         /* kind none: the whole array, no mapped index */
        hi = x->n;
        mt.table_reads = 2u;             /* the radix arm's one-bucket table, outside the mapping */
    }
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        uintptr_t p = (uintptr_t)f->start - x->base + (uintptr_t)mid * x->kb;

        v[nv].lo = p; v[nv].hi = p + x->kb - 1u; v[nv++].cold = 1;
        mt.probes++;
        if (mid < u) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    /*
     * The record, by the rule FORMAT.md 7 pins: a miss reads the end field's bytes only; a hit reads
     * the whole record (format 2), or the end and the sev byte (format 1). From the layout's offsets.
     */
    if (lo > 0u) {
        uintptr_t p = (uintptr_t)f->end - x->base + (uintptr_t)(lo - 1u) * f->stride;
        int hit = mt.result != WE_NO_RANGE;
        size_t len = (hit && !x->f1) ? f->stride : x->kb;

        v[nv].lo = p; v[nv].hi = p + len - 1u; v[nv++].cold = 1;
        if (hit && x->f1) {
            uintptr_t q = (uintptr_t)f->sev - x->base + (uintptr_t)(lo - 1u);

            v[nv].lo = q; v[nv].hi = q; v[nv++].cold = 1;
        }
    }
    finish(&mt, v, nv);
    return mt;
}

static void to_addr16(__uint128_t a, int kb, int low_ones, uint8_t out[16])
{
    int i;

    if (kb == 8) {
        uint64_t top = (uint64_t)a;
        for (i = 0; i < 8; i++) {
            out[i] = (uint8_t)(top >> (56 - 8 * i));
        }
        memset(out + 8, low_ones ? 0xff : 0x00, 8);
        return;
    }
    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t)(a >> (120 - 8 * i));
    }
}

/*
 * Run what a caller runs, with the recorder on, and return the range found.
 *
 * Format 1: the shipped verdict, we_lookup4/6, whose hit path reads sev[] through its own hook. Format
 * 2: the shipped find, and on a hit the read of the whole record a caller makes for its attributes, at
 * the address the shipped we_record_of() returns. The find itself reads only the end field, so the
 * miss case is exactly the end field's bytes, as the trace records them.
 */
static uint32_t run_find(const fx_t *x, __uint128_t a, int low_ones)
{
    uint8_t a16[16];
    uint32_t r;

    if (x->family != 4) {
        to_addr16(a, (int)x->kb, low_ones, a16);
    }
    if (x->f1) {
        r = x->family == 4 ? we_find4(x->map, (uint32_t)a) : we_find6(x->map, a16);
        ntr = 0;                         /* the trace is the verdict's own, below */
        if (x->family == 4) {
            (void)we_lookup4(x->map, (uint32_t)a);
        } else {
            (void)we_lookup6(x->map, a16);
        }
        return r;
    }
    ntr = 0;
    if (x->family == 4) {
        r = we_find4(x->map, (uint32_t)a);
    } else {
        r = x->kb == 8u ? we_find6_64(x->map, a16) : we_find6(x->map, a16);
    }
    if (r != WE_NO_RANGE) {
        const uint8_t *rec = we_record_of(x->f, r);

        we_trace_read(rec, x->f->stride);
    }
    return r;
}

typedef struct {
    long long lookups, mismatches, wrong;
    long long table_reads, mapped_table_reads, tree_reads;
    uint32_t max_probes, max_depth, max_cold64, max_cold128, max_lines64, max_lines128, max_pages;
} sum_t;

static int same(const met_t *p, const met_t *q)
{
    return p->result == q->result && p->probes == q->probes && p->depth == q->depth
        && p->idx_reads == q->idx_reads && p->table_reads == q->table_reads && p->lines64 == q->lines64
        && p->lines128 == q->lines128
        && p->pages == q->pages && p->cold64 == q->cold64 && p->cold128 == q->cold128 && p->stray == 0u;
}

static void one(const fx_t *x, __uint128_t a, sum_t *s)
{
    int pass, passes = x->kb == 8u ? 2 : 1;
    met_t want = model(x, a);

    for (pass = 0; pass < passes; pass++) {
        uint32_t r = run_find(x, a, pass);
        met_t got = traced(x, r);
        int eq = same(&got, &want);

        s->lookups++;
        if (!eq) {
            s->mismatches++;
        }
#if !MUTANT
        CHECK(eq, "%s a=0x%016" PRIx64 "%016" PRIx64 " low%s: traced r=%u probes %u depth %u idx %u l64 %u l128 %u"
              " pg %u cold %u/%u stray %u; model r=%u probes %u depth %u idx %u l64 %u l128 %u pg %u cold %u/%u",
              x->name, (uint64_t)(a >> 64), (uint64_t)a, pass ? "=ones" : "=0",
              got.result, got.probes, got.depth, got.idx_reads, got.lines64, got.lines128, got.pages,
              got.cold64, got.cold128, got.stray, want.result, want.probes, want.depth, want.idx_reads,
              want.lines64, want.lines128, want.pages, want.cold64, want.cold128);
#endif
        /* The region reads that prove which arm ran, summed per fixture and asserted in run_fixture. */
        s->table_reads += got.table_reads;
        s->tree_reads += got.depth;
        s->mapped_table_reads += got.idx_reads;
        if (got.result != want.result) {
            s->wrong++;
        }
        if (got.probes > s->max_probes) s->max_probes = got.probes;
        if (got.depth > s->max_depth) s->max_depth = got.depth;
        if (got.cold64 > s->max_cold64) s->max_cold64 = got.cold64;
        if (got.cold128 > s->max_cold128) s->max_cold128 = got.cold128;
        if (got.lines64 > s->max_lines64) s->max_lines64 = got.lines64;
        if (got.lines128 > s->max_lines128) s->max_lines128 = got.lines128;
        if (got.pages > s->max_pages) s->max_pages = got.pages;
    }
}

/* Every address that decides an outcome. */
static sum_t enumerate(const fx_t *x)
{
    sum_t s;
    uint32_t i;

    memset(&s, 0, sizeof s);
    if (x->kind == WE_KIND_RADIX) {
        uint64_t b, buckets = (uint64_t)1 << x->k;

        for (b = 0; b < buckets; b++) {
            one(x, (__uint128_t)b << (x->kb * 8u - x->k), &s);
        }
    } else {
        one(x, 0, &s);
        one(x, x->kmax, &s);
    }
    for (i = 0; i < x->n; i++) {
        if (x->start[i] > 0) {
            one(x, x->start[i] - 1u, &s);
        }
        one(x, x->start[i], &s);
        one(x, x->end[i], &s);
        if (x->end[i] < x->kmax) {
            one(x, x->end[i] + 1u, &s);
        }
    }
    return s;
}

/* ---- fixtures ---- */

static const char *TMP = "/tmp";

static __uint128_t kmax_of(uint32_t kb)
{
    return kb == 4u ? (__uint128_t)0xffffffffu : kb == 8u ? (__uint128_t)0xffffffffffffffffull : ~(__uint128_t)0;
}

/* The kind tallies across every fixture this run: lookups, model disagreements and wrong answers. */
static long long kind_lookups[3], kind_mismatches[3], kind_wrong[3];

/*
 * A fixture from a loaded family: the reference ranges, and the structure's integers taken from the
 * arm-time descriptor (the kind as the FILE states it, so `none` stays none here).
 */
static void fx_setup(fx_t *x, const we_map_t *m, int family, const char *name, uint32_t n,
                     const __uint128_t *start, const __uint128_t *end)
{
    memset(x, 0, sizeof *x);
    x->name = name;
    x->family = family;
    x->map = m;
    x->base = (uintptr_t)m->base;
    x->f1 = m->format == WE_FORMAT_1;
    x->f = family == 4 ? &m->f4 : we_family6(m);
    x->kb = x->f->key_bits / 8u;
    x->n = n;
    x->start = start;
    x->end = end;
    x->kind = x->f->file_kind;
    x->kmax = kmax_of(x->kb);
    if (x->kind == WE_KIND_RADIX) {
        uint32_t b, cur = 0;

        x->k = x->f->file_param;
        x->prefix = (uint32_t *)malloc((((size_t)1 << x->k) + 1u) * sizeof(uint32_t));
        for (b = 0; b <= (1u << x->k); b++) {
            while (cur < n && (b == (1u << x->k) || bucket(x, start[cur]) < b)) {
                cur++;
            }
            x->prefix[b] = cur;
        }
    }
    if (x->kind == WE_KIND_RANK) {
        x->s = 1u << x->f->file_param;
        x->fan = 64u / x->kb + 1u;
        x->m = (n + x->s - 1u) / x->s;
        x->depth = ww_depth(x->m, x->fan);
    }
}

/* What must hold of a fixture's run: the bounds the file states, and which arm ran. */
static void fx_assert(const fx_t *x, const we_map_t *m, const sum_t *s)
{
    int family = x->family;
    const char *name = x->name;

    kind_lookups[x->kind] += s->lookups;
    kind_mismatches[x->kind] += s->mismatches;
    kind_wrong[x->kind] += s->wrong;
#if !MUTANT
    CHECK(s->wrong == 0, "%s: %lld lookups found the wrong range", name, s->wrong);
    /*
     * BOTH ARMS, PROVEN FROM THE TRACE: a radix family's lookups read its radix table and never the
     * S-tree; kind none reads the radix arm's one-bucket table and nothing else; a rank family's read
     * the S-tree (when it has one: a single window has none) and never a radix table.
     */
    if (x->kind == WE_KIND_RADIX) {
        CHECK(s->mapped_table_reads > 0 && s->tree_reads == 0,
              "%s: radix arm: %lld radix-table reads (want > 0), %lld S-tree reads (want 0)",
              name, s->mapped_table_reads, s->tree_reads);
    } else if (x->kind == WE_KIND_NONE) {
        CHECK(s->table_reads > 0 && s->mapped_table_reads == 0 && s->tree_reads == 0,
              "%s: unindexed, the radix arm over its one-bucket table: %lld table reads, %lld mapped, %lld tree",
              name, s->table_reads, s->mapped_table_reads, s->tree_reads);
    } else {
        CHECK(s->table_reads == 0 && (x->f->nodes > 0u ? s->tree_reads > 0 : s->tree_reads == 0),
              "%s: rank arm: %lld radix-table reads (want 0), %lld S-tree reads (want %s)",
              name, s->table_reads, s->tree_reads, x->f->nodes > 0u ? "> 0" : "0, one window");
    }
    if (x->kind == WE_KIND_RADIX || x->kind == WE_KIND_NONE) {
        /* the maximum equals the bound computed from the file (the corrected ceil(log2(w + 1))) */
        uint32_t occ = family == 4 ? we_worst_bucket_occupancy4(m) : we_worst_bucket_occupancy6(m);

        CHECK(s->max_probes == we_max_probes(occ),
              "%s: max probes %u, the file's bound says %u (widest window %u)",
              name, s->max_probes, we_max_probes(occ), occ);
    } else {
        uint32_t occ = family == 4 ? we_worst_bucket_occupancy4(m) : we_worst_bucket_occupancy6(m);
        uint32_t dep = family == 4 ? we_rank_depth4(m) : we_rank_depth6(m);
        uint32_t said = family == 4 ? m->h->schema.v4_depth : m->h->schema.v6_depth;

        CHECK(s->max_probes == we_max_probes(occ), "%s: max window probes %u, the bound says %u",
              name, s->max_probes, we_max_probes(occ));
        CHECK(s->max_probes <= x->f->file_param, "%s: window probes %u above log2(stride) %u", name,
              s->max_probes, x->f->file_param);
        CHECK(s->max_depth == dep && dep == said && said == x->depth,
              "%s: max depth %u, descriptor %u, header %u, formula %u", name, s->max_depth, dep, said, x->depth);
    }
#else
    (void)m;
    (void)family;
    (void)name;
#endif
}

/*
 * Write, load and enumerate one family. format/plane decide the key width: v4 is always 32-bit; v6 is
 * 64-bit on routing and 128-bit on tor and in format 1.
 */
static void run_fixture(const char *name, uint32_t format, uint32_t plane, int family, uint32_t kind,
                        uint32_t param, uint32_t n, const __uint128_t *start, const __uint128_t *end,
                        int print, sum_t *out)
{
    ww_plane_t p;
    ww_family_t *wf;
    char path[512];
    we_map_t m;
    we_load_detail_t d;
    fx_t x;
    sum_t s;
    int rc;

    memset(&p, 0, sizeof p);
    p.format = format;
    p.schema = 1;
    p.plane = plane;
    p.generation = 1u;
    p.country_version = 5704u;
    wf = family == 4 ? &p.v4 : &p.v6;
    wf->n = n;
    wf->start = start;
    wf->end = end;
    wf->kind = kind;
    wf->param = param;
    snprintf(path, sizeof path, "%s/trace-fixture.snap", TMP);
    rc = ww_write(path, &p);
    CHECK(rc == 0, "%s: write", name);
    rc = we_plane_open(path, &m, &d);
    CHECK(rc == WE_OK, "%s: load: %s (%s, record %" PRId64 ")", name, we_strerror(rc),
          d.what ? d.what : "-", d.record);
    if (rc != WE_OK) {
        return;
    }
    fx_setup(&x, &m, family, name, n, start, end);
    s = enumerate(&x);
    *out = s;
    fx_assert(&x, &m, &s);
    if (print) {
        printf("  %-34s n=%-8u %9lld lookups  probes %2u  depth %u  cold64 %u  cold128 %u  lines64 %u"
               "  lines128 %u  pages %u%s\n",
               name, n, s.lookups, s.max_probes, s.max_depth, s.max_cold64, s.max_cold128, s.max_lines64,
               s.max_lines128, s.max_pages,
               MUTANT ? "" : "");
#if MUTANT
        printf("  %-34s MUTANT: %lld of %lld lookups disagree with the model\n", name, s.mismatches, s.lookups);
#endif
    }
    free(x.prefix);
    we_map_close(&m);
}

/* Uniform: n ranges evenly spaced over the key space, each half a step wide (gaps between). */
static void gen_uniform(uint32_t n, uint32_t kb, __uint128_t *start, __uint128_t *end)
{
    __uint128_t step = kmax_of(kb) / n;
    uint32_t i;

    for (i = 0; i < n; i++) {
        start[i] = (__uint128_t)i * step + 1u;
        end[i] = start[i] + step / 2u;
    }
}

/*
 * Adversarial: start[0] = 0, end[n-1] = the maximum key, every range adjacent to the next, half packed
 * at the bottom of the space and half at the top with one wide range between. That is skew in the
 * address bits (two crowded buckets) and in index space, and every address is in some range.
 */
static void gen_adversarial(uint32_t n, uint32_t kb, __uint128_t *start, __uint128_t *end)
{
    __uint128_t top = kmax_of(kb);
    uint32_t lo = n / 2u, i;

    for (i = 0; i < n; i++) {
        if (i < lo) {
            start[i] = i;
        } else {
            start[i] = top - (__uint128_t)(n - 1u - i);
            if (i == lo) {
                start[i] = lo;            /* the wide one, from the bottom pack to the top pack */
            }
        }
    }
    for (i = 0; i + 1u < n; i++) {
        end[i] = start[i + 1u] - 1u;
    }
    end[n - 1u] = top;
}

static uint32_t rank_param(uint32_t kb)
{
    return kb == 16u ? 5u : 6u;
}

static void synthetic(void)
{
    static const struct { const char *tag; int family; uint32_t plane; uint32_t kb; } W[3] = {
        { "v4/32",  4, WE_PLANE_ROUTING, 4u },
        { "v6/64",  6, WE_PLANE_ROUTING, 8u },
        { "v6/128", 6, WE_PLANE_TOR, 16u },
    };
    static const uint32_t radix_k[3] = { 12u, 16u, 18u };
    int w;

    printf("\n== the deterministic bound: per-lookup equality against the data-free model ==\n");
    for (w = 0; w < 3; w++) {
        uint32_t kb = W[w].kb;
        uint32_t s = 1u << rank_param(kb);
        uint32_t fan = 64u / kb + 1u;
        /* the depth flips at s * fan^d: one per width that stays under ~500k ranges */
        uint32_t flip = kb == 4u ? 64u * 17u * 17u * 17u : kb == 8u ? 64u * 9u * 9u * 9u * 9u
                                                                    : 32u * 5u * 5u * 5u * 5u * 5u;
        uint32_t ns[20];
        int nn = 0, i, kind;
        __uint128_t *st, *en;

        ns[nn++] = 1u; ns[nn++] = 2u; ns[nn++] = s - 1u; ns[nn++] = s; ns[nn++] = s + 1u;
        ns[nn++] = 2u * s - 1u; ns[nn++] = 2u * s + 1u; ns[nn++] = 4095u; ns[nn++] = 4096u;
        ns[nn++] = 4097u; ns[nn++] = 64u * 4096u + 1u;
        ns[nn++] = 64u * 6561u - 1u; ns[nn++] = 64u * 6561u; ns[nn++] = 64u * 6561u + 1u;
        if (flip != 64u * 6561u) {
            ns[nn++] = flip - 1u; ns[nn++] = flip; ns[nn++] = flip + 1u;
        }
        (void)fan;
        st = (__uint128_t *)malloc(sizeof(__uint128_t) * 520000u);
        en = (__uint128_t *)malloc(sizeof(__uint128_t) * 520000u);

        for (kind = 0; kind < 2; kind++) {
            uint32_t k = kind == 0 ? WE_KIND_RADIX : WE_KIND_RANK;
            char name[96];
            sum_t s1;

            /* uniform: n a multiple of the stride, and n = k*s + r */
            for (i = 0; i < 2; i++) {
                uint32_t n = i == 0 ? 100u * s : 100u * s + 37u;
                uint32_t param = k == WE_KIND_RADIX ? radix_k[(w + i) % 3] : rank_param(kb);

                gen_uniform(n, kb, st, en);
                snprintf(name, sizeof name, "%s %s-%u uniform", W[w].tag,
                         k == WE_KIND_RADIX ? "radix" : "rank", k == WE_KIND_RADIX ? param : 1u << param);
                run_fixture(name, WE_FORMAT_2, W[w].plane, W[w].family, k, param, n, st, en, 1, &s1);
            }
            /* adversarial */
            for (i = 0; i < nn; i++) {
                uint32_t n = ns[i];
                uint32_t param = k == WE_KIND_RADIX ? radix_k[i % 3] : rank_param(kb);

                gen_adversarial(n, kb, st, en);
                snprintf(name, sizeof name, "%s %s-%u adversarial", W[w].tag,
                         k == WE_KIND_RADIX ? "radix" : "rank", k == WE_KIND_RADIX ? param : 1u << param);
                run_fixture(name, WE_FORMAT_2, W[w].plane, W[w].family, k, param, n, st, en, 1, &s1);
            }
        }
        free(st);
        free(en);
    }

    /* Format 1, both families, radix-16 and unindexed: the shipped layout through the same find. */
    {
        __uint128_t *st = (__uint128_t *)malloc(sizeof(__uint128_t) * 8000u);
        __uint128_t *en = (__uint128_t *)malloc(sizeof(__uint128_t) * 8000u);
        sum_t s1;

        gen_uniform(6437u, 4u, st, en);
        run_fixture("v4/32 format-1 radix-16 uniform", WE_FORMAT_1, WE_PLANE_REPUTATION, 4, WE_KIND_RADIX,
                    16u, 6437u, st, en, 1, &s1);
        run_fixture("v4/32 format-1 unindexed uniform", WE_FORMAT_1, WE_PLANE_REPUTATION, 4, WE_KIND_NONE,
                    0u, 6437u, st, en, 1, &s1);
        gen_adversarial(4097u, 16u, st, en);
        run_fixture("v6/128 format-1 radix-16 adversarial", WE_FORMAT_1, WE_PLANE_REPUTATION, 6, WE_KIND_RADIX,
                    16u, 4097u, st, en, 1, &s1);
        run_fixture("v6/128 format-1 unindexed adversarial", WE_FORMAT_1, WE_PLANE_REPUTATION, 6, WE_KIND_NONE,
                    0u, 4097u, st, en, 1, &s1);
        free(st);
        free(en);
    }
}

/* ---- the live-shaped fixtures: the flattened RouteViews tables (fixtures/README.md) ---- */

static void *slurp(const char *dir, const char *name, size_t *len)
{
    char path[1024];
    FILE *f;
    long l;
    void *b;

    snprintf(path, sizeof path, "%s/%s", dir, name);
    f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (l = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    b = malloc((size_t)l + 1u);
    if (b == NULL || fread(b, 1, (size_t)l, f) != (size_t)l) {
        free(b);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)l;
    return b;
}

static void live(const char *dir)
{
    size_t l4s, l4r, l6s, l6r;
    uint8_t *s4 = (uint8_t *)slurp(dir, "v4.start", &l4s);
    uint8_t *r4 = (uint8_t *)slurp(dir, "v4.rec16", &l4r);
    uint8_t *s6 = (uint8_t *)slurp(dir, "v6.start", &l6s);
    uint8_t *r6 = (uint8_t *)slurp(dir, "v6.rec24", &l6r);
    uint32_t n4, n6, i;
    __uint128_t *st, *en;
    sum_t s;

    printf("\n== live-shaped: the flattened RouteViews tables in %s ==\n", dir);
    CHECK(s4 && r4 && s6 && r6, "the four fixture files are in %s (make fixtures)", dir);
    if (!(s4 && r4 && s6 && r6)) {
        return;
    }
    n4 = (uint32_t)(l4s / 4u);
    n6 = (uint32_t)(l6s / 8u);
    CHECK(l4r == (size_t)n4 * 16u && l6r == (size_t)n6 * 24u, "record files match the start files");
    printf("  %u IPv4 ranges (32-bit keys), %u IPv6 ranges (64-bit keys)\n", n4, n6);
    CHECK(n4 == 1169047u && n6 == 298246u, "the pinned counts: %u and %u", n4, n6);

    st = (__uint128_t *)malloc(sizeof(__uint128_t) * n4);
    en = (__uint128_t *)malloc(sizeof(__uint128_t) * n4);
    for (i = 0; i < n4; i++) {
        uint32_t a, b;
        memcpy(&a, s4 + (size_t)i * 4u, 4);
        memcpy(&b, r4 + (size_t)i * 16u, 4);
        st[i] = a;
        en[i] = b;
    }
    run_fixture("live IPv4 radix-18", WE_FORMAT_2, WE_PLANE_ROUTING, 4, WE_KIND_RADIX, 18u, n4, st, en, 1, &s);
#if !MUTANT
    printf("  LIVE IPv4 radix-18: max probes %u, max cold lines %u (64 B), all lines %u, pages %u\n",
           s.max_probes, s.max_cold64, s.max_lines64, s.max_pages);
#endif
    run_fixture("live IPv4 radix-16", WE_FORMAT_2, WE_PLANE_ROUTING, 4, WE_KIND_RADIX, 16u, n4, st, en, 1, &s);
    run_fixture("live IPv4 rank-64", WE_FORMAT_2, WE_PLANE_ROUTING, 4, WE_KIND_RANK, 6u, n4, st, en, 1, &s);
    free(st);
    free(en);

    st = (__uint128_t *)malloc(sizeof(__uint128_t) * n6);
    en = (__uint128_t *)malloc(sizeof(__uint128_t) * n6);
    for (i = 0; i < n6; i++) {
        uint64_t a, b;
        memcpy(&a, s6 + (size_t)i * 8u, 8);
        memcpy(&b, r6 + (size_t)i * 24u, 8);
        st[i] = a;
        en[i] = b;
    }
    run_fixture("live IPv6 rank-64", WE_FORMAT_2, WE_PLANE_ROUTING, 6, WE_KIND_RANK, 6u, n6, st, en, 1, &s);
#if !MUTANT
    printf("  LIVE IPv6 rank-64: max window probes %u, depth %u, max cold lines %u (64 B), all lines %u, pages %u\n",
           s.max_probes, s.max_depth, s.max_cold64, s.max_lines64, s.max_pages);
#endif
    run_fixture("live IPv6 radix-18", WE_FORMAT_2, WE_PLANE_ROUTING, 6, WE_KIND_RADIX, 18u, n6, st, en, 1, &s);
    free(st);
    free(en);
    free(s4);
    free(r4);
    free(s6);
    free(r6);
}

/*
 * A plane someone else wrote (the interop gate's Java fixtures): load it with the real reader, take the
 * reference ranges from the file itself, enumerate every family exactly as the synthetic fixtures are,
 * and print the maxima and the working set the manifest must state, one `maxima` line per family and a
 * `workingSetBytes` line, for the gate to compare with the manifest.
 */
static void named_file(const char *path)
{
    we_map_t m;
    we_load_detail_t d;
    uint64_t ws = 0;
    int k, rc = we_plane_open(path, &m, &d);

    CHECK(rc == WE_OK, "%s: the reader refused it: %s (%s)", path, we_strerror(rc), d.what ? d.what : "-");
    if (rc != WE_OK) {
        return;
    }
    for (k = 0; k < 2; k++) {
        int family = k == 0 ? 4 : 6;
        const we_fam_t *f = family == 4 ? &m.f4 : we_family6(&m);
        uint32_t kb = f->key_bits / 8u, i;
        __uint128_t *st, *en;
        fx_t x;
        sum_t s;
        uint64_t index_bytes = f->file_kind == WE_KIND_RADIX ? (((uint64_t)1 << f->file_param) + 1u) * 4u
                             : f->file_kind == WE_KIND_RANK ? (uint64_t)f->nodes * 64u : 0u;

        if (f->n == 0u) {
            printf("maxima v%d none\n", family);
            continue;
        }
        /* the working set: index, start[], and what a lookup reads per range (record, or end[] + sev[]) */
        ws += index_bytes + (uint64_t)f->n * kb
            + (m.format == WE_FORMAT_1 ? (uint64_t)f->n * kb + f->n : (uint64_t)f->n * f->stride);
        st = (__uint128_t *)malloc(sizeof(__uint128_t) * f->n);
        en = (__uint128_t *)malloc(sizeof(__uint128_t) * f->n);
        if (st == NULL || en == NULL) {
            CHECK(0, "allocation");
            free(st);
            free(en);
            break;
        }
        for (i = 0; i < f->n; i++) {
            st[i] = 0;
            en[i] = 0;
            memcpy(&st[i], f->start + (size_t)i * kb, kb);
            memcpy(&en[i], f->end + (size_t)i * f->stride, kb);
        }
        fx_setup(&x, &m, family, family == 4 ? "file v4" : "file v6", f->n, st, en);
        s = enumerate(&x);
        fx_assert(&x, &m, &s);
        printf("maxima v%d kind=%u maxProbes=%u depth=%u maxColdLines=%u maxLines64=%u maxLines128=%u"
               " maxPages4k=%u lookups=%lld\n", family, x.kind, s.max_probes, s.max_depth, s.max_cold64,
               s.max_lines64, s.max_lines128, s.max_pages, s.lookups);
        free(x.prefix);
        free(st);
        free(en);
    }
    printf("workingSetBytes=%" PRIu64 "\n", ws);
    we_map_close(&m);
}

int main(int argc, char **argv)
{
    const char *live_dir = NULL;
    const char *file = NULL;
    int i;

    TMP = argc > 1 ? argv[1] : "/tmp";
    for (i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--live") == 0) {
            live_dir = argv[i + 1];
        }
        if (strcmp(argv[i], "--file") == 0) {
            file = argv[i + 1];
        }
    }
    printf("whisper edge core, the trace build%s\n", MUTANT ? ": THE MUTANT (one extra window entry)" : "");
    if (file != NULL) {
        named_file(file);
        printf("\n%lld checks, %lld failures\n", checks, failures);
        return failures == 0 ? 0 : 1;
    }
    if (live_dir != NULL) {
        live(live_dir);
    } else {
        synthetic();
    }
#if MUTANT
    /*
     * PER INDEX KIND, not in aggregate: radix and rank must each be caught. The mutant finds every range
     * correctly on every kind (it searches more, never less), so a wrong answer is a different defect.
     * On kind none the window is already the whole array and there is no further entry to search: the
     * saturating mutant is the production lookup there, and it must disagree nowhere.
     */
    {
        static const char *const kn[3] = { "none", "radix", "rank" };
        int k;

        printf("\n");
        for (k = 0; k < 3; k++) {
            printf("mutant, %-5s: %lld of %lld lookups disagree with the model, %lld wrong answers\n", kn[k],
                   kind_mismatches[k], kind_lookups[k], kind_wrong[k]);
            CHECK(kind_wrong[k] == 0, "the mutant found a wrong range on kind %s", kn[k]);
        }
        CHECK(kind_lookups[WE_KIND_RADIX] > 0 && kind_mismatches[WE_KIND_RADIX] > 0,
              "the one-extra-entry mutant passed per-lookup equality on RADIX: the test cannot see it");
        CHECK(kind_lookups[WE_KIND_RANK] > 0 && kind_mismatches[WE_KIND_RANK] > 0,
              "the one-extra-entry mutant passed per-lookup equality on RANK: the test cannot see it");
        CHECK(kind_mismatches[WE_KIND_NONE] == 0,
              "kind none has no further entry, so the mutant must equal production there");
        CHECK(live_dir != NULL || kind_lookups[WE_KIND_NONE] > 0, "the synthetic run covers kind none");
    }
    printf("%lld mutant checks, %lld failures\n", checks, failures);
#else
    printf("\n%lld checks, %lld failures\n", checks, failures);
#endif
    return failures == 0 ? 0 : 1;
}
