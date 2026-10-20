/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * whisper_edge.c - load, validate, publish, retire. None of this runs in a request.
 *
 * The loader's job is to make the hot path's job trivial. we_lookup4() has no error handling because
 * every property it relies on is established HERE, once, over the whole file:
 *
 *   - the ranges are sorted and disjoint, so "the greatest start <= addr" is the only candidate
 *   - start[i] <= end[i], so the containment test cannot be inverted
 *   - the bucket index is monotone, idx[0] == 0 and idx[65536] == count, so every search window is
 *     in bounds and `lo - 1` cannot underflow past the array
 *   - every offset and length lies inside the file and is aligned for its type
 *
 * That is the deal: pay O(n) once at load, so the per-request cost is a binary search with no checks
 * in it. The alternative - bounds-checking in the lookup - would move the cost to the one place we
 * measure in nanoseconds, and would still only turn a corrupt file into a slower corrupt file.
 *
 * A validation failure is not a reason to serve a half-trusted snapshot. We refuse the file, leave the
 * previous mapping published, and count it. A node with no snapshot at all allows everything.
 */
/*
 * We are compiled into a host whose build flags are not ours to choose - nginx, Apache, whatever a
 * distro packager passes. Declare the feature level we need rather than inherit one: under a bare
 * -std=c11 the POSIX names below (O_CLOEXEC, fstat, read) are not visible, and the symptom is a
 * build failure in somebody else's tree, which is exactly the friction that stops a module being
 * deployed. Be liberal in what we accept, including build environments.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "whisper_edge.h"
#include "we_sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Format 1's radix-16 table: 65,536 buckets plus the sentinel that makes idx[b+1] safe for every b.
 * Both families of a format-1 file key on the top 16 bits (v4's first two octets, v6's leading /16),
 * and a format-1 file may carry no other index: the shipped loader validates exactly this many
 * entries, so a radix-12 reputation.bin would be refused by every deployed module.
 */
#define WE_V4_INDEX_ENTRIES 65537u

/*
 * The one-bucket table the loader points a family of kind NONE at, so the lookup keeps two arms: the
 * window is [0, min(UINT32_MAX, n)) = the whole array. Static and const, never in a mapping, so the
 * trace build sees no mapped index read for an unindexed family.
 */
static const uint32_t we_whole_window[2] = { 0u, 0xffffffffu };

#include "we_country_table.h"

/* plane_id -> the installed file's stem, FORMAT.md §2. */
static const char *const we_plane_names[WE_PLANE_MAX + 1u] = {
    NULL, "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

static int in_file(uint32_t off, uint64_t bytes, uint32_t file_len)
{
    /* Offset-plus-length arithmetic in 64-bit, so a hostile 32-bit length cannot wrap past the end. */
    return off != 0u && (uint64_t)off + bytes <= (uint64_t)file_len;
}

static int aligned(uint32_t off, uint32_t width)
{
    return (off % width) == 0u;
}

/* Record a refusal for the one log line, and return its code. */
static int refuse(we_load_detail_t *d, int rc, int family, int64_t record, const char *what)
{
    if (d != NULL) {
        d->rc = rc;
        d->family = family;
        d->record = record;
        d->what = what;
    }
    return rc;
}

/* ---- keys, read on the cold path through memcpy so no alignment is assumed while validating ---- */

static __uint128_t key_at(const uint8_t *p, uint32_t kb, uint32_t i)
{
    const uint8_t *q = p + (size_t)i * kb;

    if (kb == 4u) {
        uint32_t v;
        memcpy(&v, q, 4);
        return (__uint128_t)v;
    }
    if (kb == 8u) {
        uint64_t v;
        memcpy(&v, q, 8);
        return (__uint128_t)v;
    }
    {
        __uint128_t v;
        memcpy(&v, q, 16);
        return v;
    }
}

static __uint128_t key_max(uint32_t kb)
{
    return kb == 4u ? (__uint128_t)0xffffffffu
         : kb == 8u ? (__uint128_t)0xffffffffffffffffull
         : ~(__uint128_t)0;
}

/* The top k bits of a key, k in 1..18: its radix bucket. Shifts on the top word, never by 128. */
static uint32_t bucket_of(__uint128_t key, uint32_t kb, uint32_t k)
{
    if (kb == 4u) {
        return (uint32_t)((uint32_t)key >> (32u - k));
    }
    if (kb == 8u) {
        return (uint32_t)((uint64_t)key >> (64u - k));
    }
    return (uint32_t)((uint64_t)(key >> 64) >> (64u - k));
}

/* (B+1)^e in 64 bits; the callers keep it under (B+1) * 2^27. */
static uint64_t pow_u64(uint64_t base, uint32_t e)
{
    uint64_t p = 1u;

    while (e-- > 0u) {
        p *= base;
    }
    return p;
}

/*
 * The S-tree depth, FORMAT.md §4.2: the smallest integer d with (B+1)^d >= m, in integers. Never a
 * floating-point log, which rounds the exact powers the wrong way on some libms: m = 9^4 must give 4.
 */
static uint32_t rank_depth(uint32_t m, uint32_t fanout)
{
    uint64_t p = 1u;
    uint32_t d = 0u;

    while (p < (uint64_t)m) {
        p *= fanout;
        d++;
    }
    return d;
}

/* ---- one family, as the loader sees it while it validates ---- */
typedef struct {
    int      family;       /* 4 or 6 */
    uint32_t n;
    uint32_t kb;           /* key bytes: 4, 8 or 16 */
    uint32_t kind;         /* as the file states it */
    uint32_t param;
    int      flagged;      /* WE_H_Vx_INDEXED */
    uint32_t rstride;      /* format 2: the record stride */
    uint32_t idx_off, start_off, end_off, sev_off, meta_off, rec_off, sample_off;
    uint32_t sample_count, depth_said;
    uint32_t s, B, m, depth, nodes;
} lfam_t;

static void lfam_init(lfam_t *f, const we_header_t *h, int family)
{
    memset(f, 0, sizeof *f);
    f->family = family;
    if (family == 4) {
        f->n = h->v4_count;
        f->flagged = (h->flags & WE_H_V4_INDEXED) != 0u;
        f->idx_off = h->v4_index_off;
        f->start_off = h->v4_start_off;
        f->end_off = h->v4_end_off;
        f->sev_off = h->v4_sev_off;
        f->meta_off = h->v4_meta_off;
        f->rec_off = h->schema.v4_record_off;
        f->sample_off = h->schema.v4_sample_off;
        f->sample_count = h->schema.v4_sample_count;
        f->depth_said = h->schema.v4_depth;
    } else {
        f->n = h->v6_count;
        f->flagged = (h->flags & WE_H_V6_INDEXED) != 0u;
        f->idx_off = h->v6_index_off;
        f->start_off = h->v6_start_off;
        f->end_off = h->v6_end_off;
        f->sev_off = h->v6_sev_off;
        f->meta_off = h->v6_meta_off;
        f->rec_off = h->schema.v6_record_off;
        f->sample_off = h->schema.v6_sample_off;
        f->sample_count = h->schema.v6_sample_count;
        f->depth_said = h->schema.v6_depth;
    }
}

/*
 * The index kind and parameter of one family (part of the FORMAT stage). The kind byte is the one the
 * lookup branches on, so anything but none, radix and rank is refused here and the lookup's `else` arm
 * is unreachable; a plane so refused is UNKNOWN, the real fail-open state.
 */
static int check_kind(lfam_t *f, uint32_t format, we_load_detail_t *d)
{
    if (f->kind > WE_KIND_RANK) {
        return refuse(d, WE_ERR_FORMAT, f->family, -1, "an index kind other than none, radix or rank");
    }
    if (f->flagged != (f->kind == WE_KIND_RADIX)) {
        return refuse(d, WE_ERR_FORMAT, f->family, -1, "the INDEXED flag disagrees with the index kind");
    }
    if (format == WE_FORMAT_1) {
        if (f->kind == WE_KIND_RANK) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "format 1 carries the radix-16 index or none");
        }
        if (f->param != (f->kind == WE_KIND_RADIX ? 16u : 0u)) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "format 1's radix index is radix-16");
        }
    } else {
        if (f->kind == WE_KIND_NONE && f->param != 0u) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "kind none carries no parameter");
        }
        if (f->kind == WE_KIND_RADIX && f->param != 12u && f->param != 16u && f->param != 18u) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "radix k is not 12, 16 or 18");
        }
        if (f->kind == WE_KIND_RANK && f->param != (f->kb == 16u ? 5u : 6u)) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1,
                          "rank stride is not 64 (32- and 64-bit keys) or 32 (128-bit keys)");
        }
    }
    if (f->kind == WE_KIND_RANK) {
        f->s = 1u << f->param;
        f->B = 64u / f->kb;
        f->m = (uint32_t)(((uint64_t)f->n + f->s - 1u) / f->s);
        f->depth = rank_depth(f->m, f->B + 1u);
        f->nodes = (uint32_t)((pow_u64(f->B + 1u, f->depth) - 1u) / f->B);
        if (f->sample_count != f->m) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "sample_count is not ceil(n / stride)");
        }
        if (f->depth_said != f->depth) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1,
                          "the S-tree depth is not the smallest d with (B+1)^d >= m");
        }
        /* One window has no separators and no tree, and FORMAT.md §5 pins its offset at 0. */
        if (f->nodes == 0u && f->sample_off != 0u) {
            return refuse(d, WE_ERR_FORMAT, f->family, -1, "a one-window rank family's sample_off is not 0");
        }
    } else if (f->sample_off != 0u || f->sample_count != 0u || f->depth_said != 0u) {
        return refuse(d, WE_ERR_FORMAT, f->family, -1, "a radix or unindexed family carries rank fields");
    }
    return WE_OK;
}

/*
 * The schema tail, FORMAT.md §2, and the format/plane/schema agreement. Everything here is the FORMAT
 * stage of §6: it reads only the 192-byte header, so it runs before the length is even compared.
 */
static int check_schema(const we_header_t *h, uint32_t format, lfam_t *f4, lfam_t *f6,
                        uint32_t *plane, we_load_detail_t *d)
{
    const we_schema_t *t = &h->schema;
    uint32_t want_schema;
    uint32_t i;
    int rc;

    if ((h->flags & WE_H_SCHEMA) == 0u) {
        const uint8_t *raw = (const uint8_t *)t;

        if (format != WE_FORMAT_1) {
            return refuse(d, WE_ERR_FORMAT, 0, -1, "a format-2 file must carry the schema tail");
        }
        for (i = 0; i < sizeof *t; i++) {
            if (raw[i] != 0u) {
                return refuse(d, WE_ERR_FORMAT, 0, -1,
                              "the tail of a pre-schema format-1 file is reserved and must be zero");
            }
        }
        /* A pre-schema file is the reputation plane, format 1, as it always was. */
        *plane = WE_PLANE_REPUTATION;
        f4->kb = 4u;
        f6->kb = 16u;
        f4->kind = f4->flagged ? WE_KIND_RADIX : WE_KIND_NONE;
        f4->param = f4->flagged ? 16u : 0u;
        f6->kind = f6->flagged ? WE_KIND_RADIX : WE_KIND_NONE;
        f6->param = f6->flagged ? 16u : 0u;
        return WE_OK;
    }

    for (i = 0; i < sizeof t->reserved; i++) {
        if (t->reserved[i] != 0u) {
            return refuse(d, WE_ERR_FORMAT, 0, -1, "a reserved byte of the schema tail is not zero");
        }
    }
    if (t->plane_id == 0u || t->plane_id > WE_PLANE_MAX) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "an unknown plane_id");
    }
    *plane = t->plane_id;
    want_schema = t->plane_id == WE_PLANE_REPUTATION ? WE_SCHEMA_FORMAT1
                : (t->plane_id == WE_PLANE_ROUTING || t->plane_id == WE_PLANE_REGISTRY) ? WE_SCHEMA_ROUTING
                : WE_SCHEMA_MEMBERSHIP;
    if (t->schema_id != want_schema) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "the schema_id is not the plane's schema");
    }
    if ((format == WE_FORMAT_1) != (t->schema_id == WE_SCHEMA_FORMAT1)) {
        return refuse(d, WE_ERR_FORMAT, 0, -1,
                      "format 1 is the reputation plane's layout and every other plane is format 2");
    }
    if (t->v4_key_bits != 32u) {
        return refuse(d, WE_ERR_FORMAT, 4, -1, "IPv4 keys are 32 bits");
    }
    if (t->v6_key_bits != (t->schema_id == WE_SCHEMA_ROUTING ? 64u : 128u)) {
        return refuse(d, WE_ERR_FORMAT, 6, -1,
                      "IPv6 keys are 64 bits on routing and registry and 128 bits everywhere else");
    }
    f4->kb = 4u;
    f6->kb = t->v6_key_bits / 8u;
    if (t->schema_id == WE_SCHEMA_FORMAT1) {
        if (t->v4_record_stride != 0u || t->v6_record_stride != 0u || t->v4_record_off != 0u
                || t->v6_record_off != 0u || t->country_table_version != 0u) {
            return refuse(d, WE_ERR_FORMAT, 0, -1, "a format-1 tail carries record fields");
        }
    } else {
        f4->rstride = 16u;
        f6->rstride = t->schema_id == WE_SCHEMA_ROUTING ? 24u : 32u;
        if (t->v4_record_stride != f4->rstride || t->v6_record_stride != f6->rstride) {
            return refuse(d, WE_ERR_FORMAT, 0, -1, "a record stride is not the schema's");
        }
        if (t->schema_id != WE_SCHEMA_ROUTING && t->country_table_version != 0u) {
            return refuse(d, WE_ERR_FORMAT, 0, -1, "a membership plane carries a country table version");
        }
    }
    f4->kind = t->v4_index_kind;
    f4->param = t->v4_index_param;
    f6->kind = t->v6_index_kind;
    f6->param = t->v6_index_param;
    rc = check_kind(f4, format, d);
    if (rc == WE_OK) {
        rc = check_kind(f6, format, d);
    }
    return rc;
}

/*
 * plane_id against the installed name. Only `<known-plane>.bin`, the names whisper_edge_data installs
 * planes under, makes a claim; any other name (the published keyless `snapshot.bin`, the interop
 * fixtures, a temp the refresh verifies before it renames) is checked only for a plane_id in the known
 * range, which check_schema has already done. The shipped snapshot.bin must stay loadable.
 */
static int plane_name_ok(const char *path, uint32_t plane)
{
    const char *b = strrchr(path, '/');
    size_t len;
    uint32_t p;

    b = (b != NULL) ? b + 1 : path;
    len = strlen(b);
    if (len < 5u || strcmp(b + len - 4u, ".bin") != 0) {
        return 1;
    }
    len -= 4u;
    for (p = 1u; p <= WE_PLANE_MAX; p++) {
        if (strlen(we_plane_names[p]) == len && strncmp(b, we_plane_names[p], len) == 0) {
            return p == plane;
        }
    }
    return 1;
}

/* ---- the OFFSETS stage: every region inside the file, aligned, and distinct ---- */

typedef struct { uint32_t off; uint64_t len; } region_t;

#define WE_MAX_REGIONS 16

static int fam_regions(const lfam_t *f, uint32_t format, uint32_t file_len, region_t *r, int *nr,
                       we_load_detail_t *d)
{
    uint64_t n = f->n;

    if (format == WE_FORMAT_2) {
        /* Format 2 has no end[] or sev[], and only a radix family has a table. Checked at any n. */
        if (f->end_off != 0u || f->sev_off != 0u) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "format 2 has no end[] or sev[]; their offsets must be 0");
        }
        if (f->kind != WE_KIND_RADIX && f->idx_off != 0u) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "only a radix family has an index offset");
        }
    }
    if (n == 0u) {
        return WE_OK;                /* an empty family is never searched; its regions are not read */
    }
    if (!in_file(f->start_off, n * f->kb, file_len)
            || !aligned(f->start_off, format == WE_FORMAT_2 ? 64u : f->kb)) {
        return refuse(d, WE_ERR_OFFSETS, f->family, -1, "start[] outside the file or misaligned");
    }
    r[(*nr)].off = f->start_off;
    r[(*nr)++].len = n * f->kb;
    if (format == WE_FORMAT_1) {
        if (!in_file(f->end_off, n * f->kb, file_len) || !aligned(f->end_off, f->kb)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "end[] outside the file or misaligned");
        }
        if (!in_file(f->sev_off, n, file_len)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "sev[] outside the file");
        }
        r[(*nr)].off = f->end_off;
        r[(*nr)++].len = n * f->kb;
        r[(*nr)].off = f->sev_off;
        r[(*nr)++].len = n;
    } else {
        if (!in_file(f->rec_off, n * f->rstride, file_len) || !aligned(f->rec_off, 64u)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "the record column outside the file or not 64-byte aligned");
        }
        r[(*nr)].off = f->rec_off;
        r[(*nr)++].len = n * f->rstride;
    }
    if (f->kind == WE_KIND_RADIX) {
        uint64_t bytes = ((1ull << f->param) + 1u) * 4u;

        /* Format 2 pins the table at 64 bytes (FORMAT.md §5); format 1's shipped files are 4-aligned. */
        if (!in_file(f->idx_off, bytes, file_len)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "the radix index outside the file");
        }
        if (!aligned(f->idx_off, format == WE_FORMAT_2 ? 64u : 4u)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1,
                          format == WE_FORMAT_2 ? "the radix index is not 64-byte aligned"
                                                : "the radix index is not 4-byte aligned");
        }
        r[(*nr)].off = f->idx_off;
        r[(*nr)++].len = bytes;
    }
    if (f->kind == WE_KIND_RANK) {
        uint64_t bytes = (uint64_t)f->nodes * 64u;

        if (bytes != 0u) {           /* one window: no tree, and check_kind has required offset 0 */
            if (!in_file(f->sample_off, bytes, file_len) || !aligned(f->sample_off, 64u)) {
                return refuse(d, WE_ERR_OFFSETS, f->family, -1, "the S-tree outside the file or not 64-byte aligned");
            }
            r[(*nr)].off = f->sample_off;
            r[(*nr)++].len = bytes;
        }
    }
    /*
     * The meta array is validated HERE and the pointer cached, because it once was not, and that was a
     * wild read at an attacker-chosen offset: a crafted v4_meta_off of 0x40000000 loaded WE_OK and
     * faulted on the first evidence lookup, and a fuzzer found it unaided in 5% of accepted hostile
     * files. The digest does not help: it is unkeyed, so anyone who can write the file recomputes it.
     */
    if (f->meta_off != 0u) {
        if (!in_file(f->meta_off, n * 4u, file_len) || !aligned(f->meta_off, 4u)) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "meta[] outside the file or misaligned");
        }
        r[(*nr)].off = f->meta_off;
        r[(*nr)++].len = n * 4u;
    }
    return WE_OK;
}

/*
 * The radix table must agree with the ranges it indexes, or the hot path's search window is a lie.
 *
 * idx[b] is the number of ranges whose start has top-k bits below b, so three things must hold: it is
 * monotone non-decreasing, it starts at 0 and ends at n, and - the part the lookup actually leans on -
 * the entries before idx[b] all lie in a bucket below b and the entry at idx[b] does not.
 *
 * THE SENTINEL IS NOT A BUCKET. Entry 2^k exists so that idx[b + 1] is in bounds for the last bucket;
 * it has no address range of its own. Treating it as one is how the first version of this code broke:
 * for v6 the boundary address was (b << 112), and at b = 65536 that is 2^128, which wraps a __uint128_t
 * to ZERO, so every indexed v6 snapshot was refused. The comparison is now on the bucket of each key,
 * computed by shifting the key down, so no boundary address is ever formed.
 */
static int check_radix(const uint8_t *base, const lfam_t *f, we_load_detail_t *d)
{
    const uint32_t *idx = (const uint32_t *)(const void *)(base + f->idx_off);
    const uint8_t *st = base + f->start_off;
    uint32_t buckets = 1u << f->param;
    uint32_t b;

    if (idx[0] != 0u || idx[buckets] != f->n) {
        return refuse(d, WE_ERR_OFFSETS, f->family, -1, "the radix index does not run from 0 to n");
    }
    for (b = 1u; b <= buckets; b++) {
        if (idx[b] < idx[b - 1u] || idx[b] > f->n) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "the radix index is not monotone within [0, n]");
        }
    }
    for (b = 1u; b < buckets; b++) {                         /* real buckets only; see above */
        if (idx[b] > 0u && bucket_of(key_at(st, f->kb, idx[b] - 1u), f->kb, f->param) >= b) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "a radix bucket starts after a range it should hold");
        }
        if (idx[b] < f->n && bucket_of(key_at(st, f->kb, idx[b]), f->kb, f->param) < b) {
            return refuse(d, WE_ERR_OFFSETS, f->family, -1, "a radix bucket starts before a range it should not hold");
        }
    }
    return WE_OK;
}

/*
 * The S-tree must hold exactly the separators, FORMAT.md §4.2: a complete (B+1)-ary tree of depth d,
 * nodes in level order, keys in order. Slot q of node t at level l is in-order position
 *     p = (t (B+1) + q + 1) (B+1)^(d-1-l) - 1,
 * and holds start[(p+1) s] for p < m - 1 and the maximum key otherwise. A sample that disagrees with
 * start[] would silently send lookups to the wrong window, which on a membership plane disarms a
 * listing without a word, so it is refused rather than tolerated.
 */
static int check_stree(const uint8_t *base, const lfam_t *f, we_load_detail_t *d)
{
    const uint8_t *tree = base + f->sample_off;
    const uint8_t *st = base + f->start_off;
    uint64_t fan = (uint64_t)f->B + 1u;
    uint64_t width = 1u;          /* nodes at this level, (B+1)^l */
    uint64_t first = 0u;          /* level-order index of the level's first node */
    __uint128_t kmax = key_max(f->kb);
    uint32_t l;

    for (l = 0u; l < f->depth; l++) {
        uint64_t below = pow_u64(fan, f->depth - 1u - l);
        uint64_t t;

        for (t = 0u; t < width; t++) {
            const uint8_t *node = tree + (size_t)(first + t) * 64u;
            uint32_t q;

            for (q = 0u; q < f->B; q++) {
                uint64_t p = (t * fan + q + 1u) * below - 1u;
                __uint128_t want = p < (uint64_t)f->m - 1u
                                 ? key_at(st, f->kb, (uint32_t)((p + 1u) * f->s)) : kmax;

                if (key_at(node, f->kb, q) != want) {
                    return refuse(d, WE_ERR_OFFSETS, f->family, -1,
                                  "an S-tree sample is not start[j * stride] (or the maximum key as padding)");
                }
            }
        }
        first += width;
        width *= fan;
    }
    return WE_OK;
}

/* ---- the UNSORTED and OVERLAP stages ---- */

/*
 * Format 1, exactly as shipped: an inverted range is UNSORTED and a start at or below the previous end
 * is OVERLAP, which also catches out-of-order starts. Kept as it was because the suite pins those codes
 * and a format-1 file must be judged the same by the old reader and the new.
 */
static int check_ranges_f1(const uint8_t *base, const lfam_t *f, we_load_detail_t *d)
{
    const uint8_t *st = base + f->start_off;
    const uint8_t *en = base + f->end_off;
    uint32_t i;

    for (i = 0u; i < f->n; i++) {
        __uint128_t s = key_at(st, f->kb, i);

        if (s > key_at(en, f->kb, i)) {
            return refuse(d, WE_ERR_UNSORTED, f->family, i, "a range ends before it starts");
        }
        if (i > 0u && s <= key_at(en, f->kb, i - 1u)) {
            return refuse(d, WE_ERR_OVERLAP, f->family, i, "a range starts at or before the previous end");
        }
    }
    return WE_OK;
}

/* Format 2: starts strictly increasing (after the /64 truncation, which is what 64-bit keys are). */
static int check_sorted_f2(const uint8_t *base, const lfam_t *f, we_load_detail_t *d)
{
    const uint8_t *st = base + f->start_off;
    uint32_t i;

    for (i = 1u; i < f->n; i++) {
        if (key_at(st, f->kb, i) <= key_at(st, f->kb, i - 1u)) {
            return refuse(d, WE_ERR_UNSORTED, f->family, i, "starts are not strictly increasing");
        }
    }
    return WE_OK;
}

/* Format 2: an end at or past the next start. The end is the record's first field. */
static int check_overlap_f2(const uint8_t *base, const lfam_t *f, we_load_detail_t *d)
{
    const uint8_t *st = base + f->start_off;
    const uint8_t *rec = base + f->rec_off;
    uint32_t i;

    for (i = 0u; i + 1u < f->n; i++) {
        if (key_at(rec + (size_t)i * f->rstride, f->kb, 0u) >= key_at(st, f->kb, i + 1u)) {
            return refuse(d, WE_ERR_OVERLAP, f->family, i, "a range ends at or past the next start");
        }
    }
    return WE_OK;
}

/* ---- the record-domain scan, FORMAT.md §3, after the digest ---- */

static uint32_t member_mask(uint32_t plane)
{
    switch (plane) {
    case WE_PLANE_TOR:              return WE_MF_TOR_EXIT;
    case WE_PLANE_RPKI_UNREACHABLE: return WE_MF_RPKI_UNREACHABLE;
    case WE_PLANE_ANONYMIZER:       return WE_MF_PROXY | WE_MF_VPN;
    case WE_PLANE_THREAT:           return WE_MF_C2 | WE_MF_BRUTEFORCE | WE_MF_SPAM | WE_MF_PHISHING
                                           | WE_MF_SCANNER | WE_MF_STATE_ACTOR;
    case WE_PLANE_TENANT:           return WE_MF_TENANT_ALLOW | WE_MF_TENANT_DENY;
    default:                        return 0u;
    }
}

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int known_country(uint32_t code)
{
    return code <= WE_COUNTRY_MAX && ((we_country_known_table[code >> 3] >> (code & 7u)) & 1u) != 0u;
}

static int check_records(const uint8_t *base, const lfam_t *f, uint32_t plane, uint32_t schema, uint32_t feed_count,
                         uint32_t *unknown, we_load_detail_t *d)
{
    const uint8_t *st = base + f->start_off;
    const uint8_t *rec = base + f->rec_off;
    uint32_t mask = member_mask(plane);
    uint32_t i;

    for (i = 0u; i < f->n; i++) {
        const uint8_t *r = rec + (size_t)i * f->rstride;
        uint32_t country = 0u;

        if (key_at(r, f->kb, 0u) < key_at(st, f->kb, i)) {
            return refuse(d, WE_ERR_FORMAT, f->family, i, "the record's end is below its start");
        }
        if (schema == WE_SCHEMA_ROUTING) {
            uint32_t rov, rir, flags, rep;
            int reserved_ok;

            if (f->kb == 4u) {
                we_route4_t v;
                memcpy(&v, r, sizeof v);
                country = v.country; rov = v.rov; rir = v.rir; flags = v.flags; rep = v.asn_rep;
                reserved_ok = v.reserved == 0u && (flags & ~(uint32_t)(WE_RF_ANYCAST | WE_RF_MOAS)) == 0u;
            } else {
                we_route6_t v;
                memcpy(&v, r, sizeof v);
                country = v.country; rov = v.rov; rir = v.rir; flags = v.flags; rep = v.asn_rep;
                reserved_ok = all_zero(v.reserved, sizeof v.reserved)
                           && (flags & ~(uint32_t)(WE_RF_ANYCAST | WE_RF_MOAS | WE_RF_NARROWED)) == 0u;
            }
            if (country > WE_COUNTRY_MAX) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "country above 999");
            }
            if (rov > WE_ROV_NOT_FOUND) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "rov outside 0..3 (4, unrouted, never appears in a record)");
            }
            if (rir > WE_RIR_RIPE) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "rir outside 0..5");
            }
            if (rep > WE_REP_HIGHLY_SUSPICIOUS) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "asn_rep outside 0..4");
            }
            if (!reserved_ok) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "a reserved byte or flag bit is set");
            }
            if (country != 0u && !known_country(country)) {
                (*unknown)++;          /* read as undetermined through we_country(); logged once */
            }
        } else {
            uint32_t flags, reason;
            int reserved_ok;

            uint32_t source;

            if (f->kb == 4u) {
                we_member4_t v;
                memcpy(&v, r, sizeof v);
                flags = v.flags; reason = v.reason; source = v.source;
                reserved_ok = all_zero(v.reserved, sizeof v.reserved);
            } else {
                we_member6_t v;
                memcpy(&v, r, sizeof v);
                flags = v.flags; reason = v.reason; source = v.source;
                reserved_ok = all_zero(v.reserved, sizeof v.reserved);
            }
            if ((flags & ~mask) != 0u) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "an attribute bit this plane does not define");
            }
            if (source >= feed_count) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "source is past the blob's feed-name table");
            }
            if (reason > (plane == WE_PLANE_RPKI_UNREACHABLE ? WE_REASON_LENGTH : 0u)) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "reason outside its domain");
            }
            if (!reserved_ok) {
                return refuse(d, WE_ERR_FORMAT, f->family, i, "a reserved byte is set");
            }
        }
    }
    return WE_OK;
}

/*
 * The format-2 blob begins with a FEED-NAME TABLE: a u16 count, then that many NUL-terminated UTF-8
 * names, entry 0 the empty name meaning "none". A membership record's `source` indexes it (refused past
 * the count, in the record scan) and meta[] offsets point into the blob after it. An absent blob is a
 * table of one entry, so `source` must then be 0. Reputation (format 1) keeps its blob unchanged.
 * Part of the OFFSETS stage: a malformed table is a region that does not hold what it claims.
 */
static int check_feeds(const uint8_t *base, const we_header_t *h, const lfam_t *const fams[2],
                       uint32_t *count, uint32_t *table_end, we_load_detail_t *d)
{
    const uint8_t *blob = base + h->blob_off;
    uint32_t len = h->blob_len;
    int k;

    *count = 1u;
    *table_end = 0u;
    if (len > 0u) {
        uint16_t n;
        uint32_t pos = 2u, e;

        if (len < 3u) {
            return refuse(d, WE_ERR_OFFSETS, 0, -1, "the blob is too short for its feed-name table");
        }
        memcpy(&n, blob, 2);
        if (n == 0u || blob[2] != 0u) {
            return refuse(d, WE_ERR_OFFSETS, 0, -1, "feed-name entry 0 must exist and be the empty name");
        }
        for (e = 0u; e < n; e++) {
            while (pos < len && blob[pos] != 0u) {
                pos++;
            }
            if (pos >= len) {
                return refuse(d, WE_ERR_OFFSETS, 0, -1, "a feed name runs past the end of the blob");
            }
            pos++;
        }
        *count = n;
        *table_end = pos;
    }
    for (k = 0; k < 2; k++) {
        const lfam_t *f = fams[k];
        uint32_t i;

        if (f->n == 0u || f->meta_off == 0u) {
            continue;
        }
        for (i = 0u; i < f->n; i++) {
            uint32_t off;

            memcpy(&off, base + f->meta_off + (size_t)i * 4u, 4);
            if (off != 0u && (off < *table_end || off >= len)) {
                return refuse(d, WE_ERR_OFFSETS, f->family, i,
                              "a meta[] offset is not inside the blob after the feed-name table");
            }
        }
    }
    return WE_OK;
}

/* ---- the descriptor, from a validated family ---- */

static void fill_family(we_fam_t *out, const lfam_t *f, const uint8_t *base, uint32_t format)
{
    uint32_t k;

    memset(out, 0, sizeof *out);
    out->key_bits = (uint8_t)(f->kb * 8u);
    out->file_kind = (uint8_t)f->kind;
    out->file_param = (uint8_t)f->param;
    if (f->n == 0u) {
        out->kind = WE_KIND_RADIX;
        out->idx = we_whole_window;
        return;                      /* n = 0 short-circuits every lookup before any of this is read */
    }
    out->n = f->n;
    out->start = base + f->start_off;
    out->first = key_at(out->start, f->kb, 0u);
    if (format == WE_FORMAT_1) {
        out->end = base + f->end_off;
        out->stride = f->kb;
        out->sev = base + f->sev_off;
    } else {
        out->end = base + f->rec_off;
        out->records = out->end;
        out->stride = f->rstride;
    }
    if (f->kind == WE_KIND_RANK) {
        out->kind = WE_KIND_RANK;
        out->stree = f->nodes > 0u ? base + f->sample_off : NULL;
        out->nodes = f->nodes;
        out->depth = (uint8_t)f->depth;
        out->m = f->m;
        out->span = f->s;
        out->sshift = (uint8_t)f->param;
        return;
    }
    /* Radix, and NONE as radix over a one-bucket table that is not in the mapping. */
    out->kind = WE_KIND_RADIX;
    k = (f->kind == WE_KIND_RADIX) ? f->param : 0u;
    out->idx = (f->kind == WE_KIND_RADIX) ? (const uint32_t *)(const void *)(base + f->idx_off)
                                          : we_whole_window;
    out->shift = (uint8_t)(f->kb == 4u ? 32u - k : 63u - k);
}

/*
 * Validate a buffer that holds the whole file, in FORMAT.md §6 order, and fill *m. The buffer is the
 * caller's; nothing here allocates.
 *
 * Integrity is checked AFTER structure, which is §6's order: every structural check is bounded by the
 * file length it has already confirmed, so it is safe on bytes the digest has not yet vouched for, and
 * the expensive pass over every byte runs only on a file whose shape is right.
 */
static int we_validate(const uint8_t *base, size_t size, const char *path, int allow_format2,
                       we_map_t *m, we_load_detail_t *d, const uint8_t *supplied)
{
    const we_header_t *h = (const we_header_t *)(const void *)base;
    lfam_t f4, f6;
    uint32_t format, plane = 0u;
    region_t regions[WE_MAX_REGIONS];
    int nr = 0, rc;
    uint8_t want[32], got[32];
    we_header_t bare;
    uint32_t unknown = 0u;
    uint32_t feed_count = 1u, feed_end = 0u;

    /* MAGIC */
    if (h->magic != WE_MAGIC) {
        return refuse(d, WE_ERR_MAGIC, 0, -1, "not a whisper edge snapshot");
    }

    /* FORMAT: the version, the tail's domain, the plane against its name. Header bytes only. */
    format = h->format;
    if (format != WE_FORMAT_1 && format != WE_FORMAT_2) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "format is not 1 or 2");
    }
    if (format == WE_FORMAT_2 && !allow_format2) {
        return refuse(d, WE_ERR_FORMAT, 0, -1,
                      "a format-2 plane, refused by the format-1 entry point as a pre-format-2 reader refuses it");
    }
    /*
     * Generation 0 is the REVOKED map's and means "nothing armed" (we_handle_publish_map), so a
     * format-2 file may not claim it: the two meanings would collide, and a reader that tests
     * generation == 0 for revocation would read a real plane as revoked. Format 1 is the shipped
     * layout and keeps loading here as every deployed reader loads it; we_handle_publish_plane()
     * refuses generation 0 for it at publish instead.
     */
    if (format == WE_FORMAT_2 && h->generation == 0u) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "generation 0 is reserved for the revoked map");
    }
    lfam_init(&f4, h, 4);
    lfam_init(&f6, h, 6);
    rc = check_schema(h, format, &f4, &f6, &plane, d);
    if (rc != WE_OK) {
        return rc;
    }
    if (path != NULL && !plane_name_ok(path, plane)) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "the plane_id does not match the file's name");
    }

    /*
     * TRUNCATED. The length the builder wrote and the length on disk disagree: a truncated or appended
     * file. This is the common real-world corruption and it is caught before any region is read.
     */
    if (h->file_len != (uint32_t)size) {
        return refuse(d, WE_ERR_TRUNCATED, 0, -1, "file_len is not the file's size");
    }

    /* OFFSETS: every region inside the file and aligned, then distinct, then the indexes' contents. */
    regions[nr].off = 0u;
    regions[nr++].len = sizeof(we_header_t);
    rc = fam_regions(&f4, format, h->file_len, regions, &nr, d);
    if (rc == WE_OK) {
        rc = fam_regions(&f6, format, h->file_len, regions, &nr, d);
    }
    if (rc != WE_OK) {
        return rc;
    }
    /*
     * The blob is REFUSED rather than quietly disabled, and its terminator is required.
     *
     * The first version used in_file()'s result as a CONDITION rather than a check: an out-of-file
     * blob_off simply left m.blob NULL and the file loaded WE_OK. Every other region refuses the file;
     * this one degraded, which is the fail-fast-into-fail-silent conversion this project forbids.
     *
     * The terminator check closes a worse hole. we_evidence4() bounds its offset against blob_len, which
     * keeps the POINTER inside the blob but says nothing about a NUL following it, and the caller then
     * does what every shim does: strlen, strcmp, printf("%s"). Reproduced before the fix: strlen read
     * 3,845 bytes out of a 3,839-byte remainder and, with an unmapped page after it, SIGSEGV. Requiring
     * the last byte to be NUL makes every in-blob offset terminate by construction.
     */
    if (h->blob_len > 0u) {
        if (!in_file(h->blob_off, h->blob_len, h->file_len)
                || base[(size_t)h->blob_off + h->blob_len - 1u] != 0u) {
            return refuse(d, WE_ERR_OFFSETS, 0, -1, "the blob is outside the file or not NUL-terminated");
        }
        regions[nr].off = h->blob_off;
        regions[nr++].len = h->blob_len;
    }
    /*
     * The regions must not OVERLAP each other or the header. A crafted header with end[] aliased onto
     * start[], or sev[] pointing at byte 40 (the `tier` field), loaded cleanly once and the hot path
     * returned a verdict read out of the header. Not memory-unsafe, but it left the unkeyed digest as
     * the only thing between a crafted header and an arbitrary verdict. No honest builder emits one.
     */
    {
        int a, b;

        for (a = 0; a < nr; a++) {
            for (b = a + 1; b < nr; b++) {
                uint64_t oa = regions[a].off;
                uint64_t ob = regions[b].off;

                if (oa < ob + regions[b].len && ob < oa + regions[a].len) {
                    return refuse(d, WE_ERR_OFFSETS, 0, -1, "two regions overlap");
                }
            }
        }
    }
    {
        lfam_t *fams[2];
        int k;

        fams[0] = &f4;
        fams[1] = &f6;
        if (format == WE_FORMAT_2) {
            const lfam_t *const cf[2] = { &f4, &f6 };

            rc = check_feeds(base, h, cf, &feed_count, &feed_end, d);
            if (rc != WE_OK) {
                return rc;
            }
        }
        for (k = 0; k < 2; k++) {
            if (fams[k]->n == 0u) {
                continue;
            }
            if (fams[k]->kind == WE_KIND_RADIX) {
                rc = check_radix(base, fams[k], d);
            } else if (fams[k]->kind == WE_KIND_RANK) {
                rc = check_stree(base, fams[k], d);
            }
            if (rc != WE_OK) {
                return rc;
            }
        }
    }

    /* UNSORTED, then OVERLAP. Format 1 keeps its shipped single pass (see check_ranges_f1). */
    if (format == WE_FORMAT_1) {
        rc = check_ranges_f1(base, &f4, d);
        if (rc == WE_OK) {
            rc = check_ranges_f1(base, &f6, d);
        }
    } else {
        rc = check_sorted_f2(base, &f4, d);
        if (rc == WE_OK) {
            rc = check_sorted_f2(base, &f6, d);
        }
        if (rc == WE_OK) {
            rc = check_overlap_f2(base, &f4, d);
        }
        if (rc == WE_OK) {
            rc = check_overlap_f2(base, &f6, d);
        }
    }
    if (rc != WE_OK) {
        return rc;
    }

    /*
     * DIGEST. Covers (header with the digest zeroed || body), streamed, so a large plane needs no
     * transient copy. The digest field is excluded by patching a 192-byte COPY of the header rather
     * than by hashing around a hole, so the builder and the loader cannot disagree about the hole.
     * A budgeted verifier (the monitor, over its DONTFORK buffer) may hand in the bytes it has
     * already computed by this same recipe; the check against the header's own field is never
     * skipped, only the recomputation is, so no caller can pass a buffer it did not digest.
     */
    memcpy(want, h->digest, 32);
    if (supplied != NULL) {
        memcpy(got, supplied, 32);
    } else {
        memcpy(&bare, h, sizeof bare);
        memset(bare.digest, 0, 32);
        {
            we_sha256_ctx ctx;

            we_sha256_init(&ctx);
            we_sha256_update(&ctx, &bare, sizeof bare);
            we_sha256_update(&ctx, base + sizeof bare, size - sizeof bare);
            we_sha256_final(&ctx, got);
#ifdef WE_TEST_EXTRA_VERIFY_PASS
            /* the control: the same digest computed a second time, the work doubled and the answer not */
            we_sha256_init(&ctx);
            we_sha256_update(&ctx, &bare, sizeof bare);
            we_sha256_update(&ctx, base + sizeof bare, size - sizeof bare);
            we_sha256_final(&ctx, got);
#endif
        }
    }
    if (memcmp(want, got, 32) != 0) {
        return refuse(d, WE_ERR_DIGEST, 0, -1, "digest mismatch");
    }

    /* The record domains, naming the record. */
    if (format == WE_FORMAT_2) {
        rc = check_records(base, &f4, plane, h->schema.schema_id, feed_count, &unknown, d);
        if (rc == WE_OK) {
            rc = check_records(base, &f6, plane, h->schema.schema_id, feed_count, &unknown, d);
        }
        if (rc != WE_OK) {
            return rc;
        }
    }

    /* Accepted. The descriptor, with the arm-time copies. */
    memset(m, 0, sizeof *m);
    m->h = h;
    m->base = base;
    m->len = size;
    m->format = format;
    m->plane_id = (uint8_t)plane;
    m->schema_id = (h->flags & WE_H_SCHEMA) != 0u ? h->schema.schema_id : WE_SCHEMA_FORMAT1;
    m->generation = h->generation;
    m->valid_until_ms = h->valid_until_ms;
    memcpy(m->digest, h->digest, 32);
    m->country_table_version = (h->flags & WE_H_SCHEMA) != 0u ? h->schema.country_table_version : 0u;
    m->country_known = we_country_known_table;
    m->country_unknown = unknown;
    m->feed_count = format == WE_FORMAT_2 ? feed_count : 0u;
    m->feed_table_end = format == WE_FORMAT_2 ? feed_end : 0u;
    m->v4_count = h->v4_count;
    m->v6_count = h->v6_count;
    fill_family(&m->f4, &f4, base, format);
    if (f6.kb == 8u) {
        fill_family(&m->f6w, &f6, base, format);
        fill_family(&m->f6, &(lfam_t){ .family = 6, .kb = 16u }, base, format);
    } else {
        fill_family(&m->f6, &f6, base, format);
        fill_family(&m->f6w, &(lfam_t){ .family = 6, .kb = 8u }, base, format);
    }
    /* The format-1 view the shims, counters and tools read. */
    if (f4.n > 0u) {
        m->v4_start = (const uint32_t *)(const void *)(base + f4.start_off);
        if (format == WE_FORMAT_1) {
            m->v4_end = (const uint32_t *)(const void *)(base + f4.end_off);
            m->v4_sev = base + f4.sev_off;
        }
        if (f4.kind == WE_KIND_RADIX) {
            m->v4_index = (const uint32_t *)(const void *)(base + f4.idx_off);
        }
        if (f4.meta_off != 0u) {
            m->v4_meta = (const uint32_t *)(const void *)(base + f4.meta_off);
        }
    }
    if (f6.n > 0u) {
        if (f6.kb == 16u) {
            m->v6_start = (const __uint128_t *)(const void *)(base + f6.start_off);
        }
        if (format == WE_FORMAT_1) {
            m->v6_end = (const __uint128_t *)(const void *)(base + f6.end_off);
            m->v6_sev = base + f6.sev_off;
        }
        if (f6.kind == WE_KIND_RADIX) {
            m->v6_index = (const uint32_t *)(const void *)(base + f6.idx_off);
        }
        if (f6.meta_off != 0u) {
            m->v6_meta = (const uint32_t *)(const void *)(base + f6.meta_off);
        }
    }
    if (h->blob_len > 0u) {
        m->blob = (const char *)base + h->blob_off;
    }
    return WE_OK;
}

/*
 * Open a file that must be regular, without ever blocking on one that is not. open() on a FIFO waits for
 * a writer, so the type is checked before the open (stat), the open is non-blocking, and the type is
 * checked again on the descriptor (fstat), because the path can be replaced in between; only then is
 * O_NONBLOCK cleared. -1 with *why set on any refusal ("cannot open" when the path is absent or
 * unreadable), else the descriptor.
 */
int we_open_regular(const char *path, const char **why)
{
    int fd, fl;
    struct stat st;

    if (stat(path, &st) != 0) {
        *why = "cannot open";
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        *why = "not a regular file";
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        *why = "cannot open";
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        *why = "changed to a non-regular file after its check";
        return -1;
    }
    fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) != 0) {
        close(fd);
        *why = "cannot open";
        return -1;
    }
    return fd;
}

static int we_load(const char *path, we_map_t *out, int allow_format2, we_load_detail_t *d)
{
    int fd, rc;
    const char *d_what = "cannot open";
    struct stat st;
    void *base = NULL;
    we_map_t m;

    if (d != NULL) {
        d->rc = WE_OK;
        d->family = 0;
        d->record = -1;
        d->what = NULL;
    }
    if (path == NULL || out == NULL) {
        return refuse(d, WE_ERR_OPEN, 0, -1, "no path");
    }
    fd = we_open_regular(path, &d_what);
    if (fd < 0) {
        return refuse(d, WE_ERR_OPEN, 0, -1, d_what);
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        return refuse(d, WE_ERR_OPEN, 0, -1, "cannot open");
    }
    if ((uint64_t)st.st_size < sizeof(we_header_t) || (uint64_t)st.st_size > 0x7fffffffull) {
        close(fd);
        return refuse(d, WE_ERR_TOO_SMALL, 0, -1, "smaller than the 192-byte header");
    }

    /*
     * REFUSE A GROUP- OR WORLD-WRITABLE SNAPSHOT.
     *
     * The digest is unkeyed and self-referential - it covers the header with its own digest field
     * zeroed - so whoever can write this file controls whom the site blocks, with no detection
     * anywhere. That is a censorship and denial-of-service primitive, and on the shared-hosting
     * population this is aimed at, "another tenant can write that path" is not hypothetical.
     *
     * Checked here because the fstat is already in hand, and refused rather than warned because a
     * warning in somebody else's error log is not a control. The failure is also the FAIL-OPEN
     * direction: refusing the file means enforcing nothing, which is the safe outcome, and it tells
     * the operator exactly what to fix.
     *
     * Only the WRITE bits matter. A world-READABLE snapshot is fine and expected: the feed is public.
     */
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        return refuse(d, WE_ERR_PERMISSIONS, 0, -1, "group- or world-writable");
    }

    /*
     * READ IT, do not map it. This was an mmap and the change is the most important one in this file.
     *
     * A read-only MAP_PRIVATE page of a regular file is never copied-on-write, so it stays shared with
     * the page cache - and TRUNCATING the backing file invalidates that page even when it is already
     * resident. The next touch raises SIGBUS, inside a request, in somebody else's nginx worker.
     * Reproduced: a 4,000-range snapshot loads, answers, the file is rewritten to one byte, and the
     * next lookup is killed by signal 7.
     *
     * Replacing the file by rename is safe, because the unlinked inode lives as long as anything holds
     * it. But nothing enforced rename-only, and every command an operator will actually reach for
     * truncates in place: curl -o, wget -O, cp (which opens O_WRONLY|O_TRUNC), install, rsync
     * --inplace, a shell redirect. The first install guide that says `curl -o snapshot.bin` would have
     * shipped a remote worker-kill to every installation, and the loader's careful validation never
     * runs because the file was already mapped.
     *
     * What mmap bought was cross-process page sharing: N workers, one physical copy. Measured, that is
     * worth about 20 MB on a 16-worker box. It was paying for that with an entire crash class, and
     * with a hard requirement on how a stranger refreshes a file. An owned buffer costs N copies -
     * 8.8 MB across 16 workers at the Tier 1 size that is actually enforced - and cannot be pulled out
     * from under a reader by any means at all. That is the trade, and it is not close.
     *
     * (the publication rule returns to mmap for the large planes, with a writer discipline that makes
     * the in-place rewrite impossible rather than unlikely, and that is future work. Until it
     * lands, this owned buffer is what makes the hot path unconditionally safe.)
     *
     * 64-byte aligned, because format 2's start[], record column and S-tree are 64-byte aligned IN THE
     * FILE and the published line counts are measured against that alignment in memory; it also covers
     * the 16 bytes the native __uint128_t bounds need.
     */
    {
        size_t want = (size_t)st.st_size;
        size_t rounded = (want + 63u) & ~(size_t)63u;
        uint8_t *buf = (uint8_t *)aligned_alloc(64, rounded);
        size_t got = 0;

        if (buf == NULL) {
            close(fd);
            return refuse(d, WE_ERR_MMAP, 0, -1, "cannot allocate");
        }
        while (got < want) {
            ssize_t n = read(fd, buf + got, want - got);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                free(buf);
                close(fd);
                return refuse(d, WE_ERR_OPEN, 0, -1, "read failed");
            }
            if (n == 0) {
                /* The file shrank between fstat and here. Refuse rather than validate a short buffer. */
                free(buf);
                close(fd);
                return refuse(d, WE_ERR_TRUNCATED, 0, -1, "the file shrank while it was read");
            }
            got += (size_t)n;
        }
        close(fd);
        base = buf;
    }

    rc = we_validate((const uint8_t *)base, (size_t)st.st_size, path, allow_format2, &m, d, NULL);
    if (rc != WE_OK) {
        free(base);
        return rc;
    }
    *out = m;
    return WE_OK;
}

int we_map_from_buffer(const uint8_t *base, size_t size, const char *name, we_map_t *out, we_load_detail_t *d)
{
    if (d != NULL) {
        d->rc = WE_OK;
        d->family = 0;
        d->record = -1;
        d->what = NULL;
    }
    if (base == NULL || out == NULL || name == NULL) {
        return refuse(d, WE_ERR_OPEN, 0, -1, "no buffer");
    }
    if (((uintptr_t)base & 63u) != 0u) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "the buffer is not 64-byte aligned");
    }
    if (size < sizeof(we_header_t) || size > 0x7fffffffu) {
        return refuse(d, WE_ERR_TOO_SMALL, 0, -1, "smaller than the 192-byte header");
    }
    return we_validate(base, size, name, 1, out, d, NULL);
}

int we_map_from_buffer_digest(const uint8_t *base, size_t size, const char *name, we_map_t *out,
                              we_load_detail_t *d, const uint8_t digest[32])
{
    int rc;

    if (d != NULL) {
        d->rc = WE_OK;
        d->family = 0;
        d->record = -1;
        d->what = NULL;
    }
    if (digest == NULL) {
        return refuse(d, WE_ERR_OPEN, 0, -1, "no computed digest");
    }
    if (base == NULL || out == NULL || name == NULL) {
        return refuse(d, WE_ERR_OPEN, 0, -1, "no buffer");
    }
    if (((uintptr_t)base & 63u) != 0u) {
        return refuse(d, WE_ERR_FORMAT, 0, -1, "the buffer is not 64-byte aligned");
    }
    if (size < sizeof(we_header_t) || size > 0x7fffffffu) {
        return refuse(d, WE_ERR_TOO_SMALL, 0, -1, "smaller than the 192-byte header");
    }
    rc = we_validate(base, size, name, 1, out, d, digest);
    return rc;
}

void we_map_rebase(we_map_t *m, const void *new_base)
{
    /* compared as integers: a pointer to a static table and one into the buffer are different objects,
     * and a relational comparison of pointers into different objects is undefined in C */
    const uintptr_t ob = (uintptr_t)m->base;
    const uint8_t *nb = (const uint8_t *)new_base;
    size_t len = m->len;

#define WE_REBASE(f) do {                                                                       \
        const uintptr_t p_ = (uintptr_t)(const void *)(f);                                      \
        if (p_ != 0u && ob != 0u && p_ >= ob && p_ - ob < len) {                                \
            (f) = (__typeof__(f))(const void *)(nb + (p_ - ob));                                \
        }                                                                                       \
    } while (0)
#define WE_REBASE_FAM(fm) do {                                                                  \
        WE_REBASE((fm).start); WE_REBASE((fm).end); WE_REBASE((fm).records); WE_REBASE((fm).sev); \
        WE_REBASE((fm).idx); WE_REBASE((fm).stree);                                             \
    } while (0)
    WE_REBASE_FAM(m->f4);
    WE_REBASE_FAM(m->f6);
    WE_REBASE_FAM(m->f6w);
    WE_REBASE(m->country_known);
    WE_REBASE(m->h);
    WE_REBASE(m->v4_index);
    WE_REBASE(m->v4_start);
    WE_REBASE(m->v4_end);
    WE_REBASE(m->v4_sev);
    WE_REBASE(m->v6_index);
    WE_REBASE(m->v6_start);
    WE_REBASE(m->v6_end);
    WE_REBASE(m->v6_sev);
    WE_REBASE(m->v4_meta);
    WE_REBASE(m->v6_meta);
#ifndef WE_TEST_REBASE_DROP
    WE_REBASE(m->blob);                          /* the control leaves this one field in the old buffer */
#endif
#undef WE_REBASE_FAM
#undef WE_REBASE
    m->base = new_base;
}

int we_map_open(const char *path, we_map_t *out)
{
    return we_load(path, out, 0, NULL);
}

int we_plane_open(const char *path, we_map_t *out, we_load_detail_t *detail)
{
    return we_load(path, out, 1, detail);
}

void we_map_close(we_map_t *m)
{
    if (m == NULL || m->base == NULL) {
        return;
    }
    free((void *)m->base);
    memset(m, 0, sizeof *m);
}

const char *we_strerror(int rc)
{
    switch (rc) {
    case WE_OK:             return "ok";
    case WE_ERR_OPEN:       return "cannot open snapshot";
    case WE_ERR_TOO_SMALL:  return "snapshot smaller than its header";
    case WE_ERR_MAGIC:      return "not a whisper edge snapshot";
    case WE_ERR_FORMAT:     return "unsupported snapshot format, or a schema field outside its domain";
    case WE_ERR_TRUNCATED:  return "snapshot length disagrees with its header (truncated or appended)";
    case WE_ERR_OFFSETS:    return "snapshot offsets or bucket index inconsistent";
    case WE_ERR_UNSORTED:   return "snapshot ranges not sorted or inverted";
    case WE_ERR_OVERLAP:    return "snapshot ranges overlap";
    case WE_ERR_DIGEST:     return "snapshot digest mismatch";
    case WE_ERR_PERMISSIONS:
        return "snapshot is group- or world-writable; anyone who can write it controls what is blocked";
    case WE_ERR_MMAP:       return "cannot allocate for snapshot";
    case WE_ERR_ROLLBACK:   return "snapshot generation is not newer than the one in use";
    case WE_ERR_OWNERSHIP:  return "the handle's maps are a module's; a core publish may not replace them";
    default:                return "unknown error";
    }
}

/*
 * Which range contains addr, or -1. THE HOT PATH'S OWN SEARCH, called out of line: this is the cold
 * answer, and there is exactly one implementation of "which range is this", so the evidence lookup,
 * the per-range counters and the verdict cannot disagree about it. (These used to be a second,
 * unindexed binary search over start[] and end[], which was correct for format 1 and would have read
 * a 64-bit key array through a 128-bit pointer the first time a routing plane was loaded.)
 */
int we_range4(const we_map_t *m, uint32_t addr)
{
    uint32_t i = we_find4(m, addr);

    return i == WE_NO_RANGE ? -1 : (int) i;
}

int we_range6(const we_map_t *m, const uint8_t addr[16])
{
    uint32_t i;

    if (m == NULL || addr == NULL) {
        return -1;
    }
    i = (m->f6w.n > 0u) ? we_find6_64(m, addr) : we_find6(m, addr);
    return i == WE_NO_RANGE ? -1 : (int) i;
}

const char *we_feed_name(const we_map_t *m, uint32_t source)
{
    uint32_t pos = 2u, e;

    if (m == NULL || m->format != WE_FORMAT_2 || source >= m->feed_count) {
        return NULL;
    }
    if (m->blob == NULL) {
        return "";                       /* no blob: the one implied entry, "none" */
    }
    /* The loader proved the table: count names, each NUL-terminated inside the blob. */
    for (e = 0u; e < source; e++) {
        pos += (uint32_t)strlen(m->blob + pos) + 1u;
    }
    return m->blob + pos;
}

const char *we_evidence4(const we_map_t *m, uint32_t addr)
{
    uint32_t i;
    int found;

    if (m == NULL || m->blob == NULL || m->v4_meta == NULL) {
        return NULL;
    }
    found = we_range4(m, addr);
    if (found < 0) {
        return NULL;
    }
    i = (uint32_t) found;
    {
        /* m->v4_meta was bounds- and alignment-checked at load, and the blob's last byte is a NUL, so
         * any offset inside it terminates. Both are the loader's job and neither is re-checked here. */
        uint32_t off = m->v4_meta[i];

        if (off == 0u || off >= m->h->blob_len) {
            return NULL;
        }
        return m->blob + off;
    }
}

/*
 * The v6 sibling. Deliberately the same shape as we_evidence4 rather than a shared generic helper:
 * the key is a __uint128_t loaded big-endian instead of a uint32_t, and the two arrays it searches
 * are different types, so a shared version would be a macro or a void* walk. At 25 lines the
 * duplication is cheaper to read and to audit than either.
 */
const char *we_evidence6(const we_map_t *m, const uint8_t addr[16])
{
    uint32_t i;
    int found;

    if (m == NULL || m->blob == NULL || m->v6_meta == NULL) {
        return NULL;
    }
    found = we_range6(m, addr);
    if (found < 0) {
        return NULL;
    }
    i = (uint32_t) found;
    {
        uint32_t off = m->v6_meta[i];

        if (off == 0u || off >= m->h->blob_len) {
            return NULL;
        }
        return m->blob + off;
    }
}

/*
 * The widest window the search walks, over every bucket. One pass, cold path, no timing.
 *
 * For a radix family the window for bucket b is [idx[b], idx[b+1]): the still-open entry at
 * idx[b] - 1 is where the step back lands and is read as the record, never probed as a key, so it is
 * NOT counted (counting it is the off-by-one the header describes). For a rank family the window starts
 * after the entry already known to be <= a, so the widest is min(stride, n) - 1. For kind none the
 * window is the whole array.
 */
static uint32_t worst_window(const we_fam_t *f)
{
    uint32_t b, buckets, worst = 0u;

    if (f->n == 0u) {
        return 0u;
    }
    if (f->kind == WE_KIND_RANK) {
        return (f->span < f->n ? f->span : f->n) - 1u;
    }
    if (f->file_kind != WE_KIND_RADIX) {
        return f->n;                     /* unindexed: a full binary search is the bound */
    }
    buckets = 1u << f->file_param;
    for (b = 0u; b < buckets; b++) {
        uint32_t span = f->idx[b + 1u] - f->idx[b];

        if (span > worst) {
            worst = span;
        }
    }
    return worst;
}

uint32_t we_worst_bucket_occupancy4(const we_map_t *m)
{
    return m == NULL ? 0u : worst_window(&m->f4);
}

const we_fam_t *we_family6(const we_map_t *m)
{
    if (m == NULL) {
        return NULL;
    }
    return m->f6w.n > 0u ? &m->f6w : &m->f6;
}

uint32_t we_worst_bucket_occupancy6(const we_map_t *m)
{
    return m == NULL ? 0u : worst_window(we_family6(m));
}

uint32_t we_rank_depth4(const we_map_t *m)
{
    return (m == NULL || m->f4.n == 0u || m->f4.kind != WE_KIND_RANK) ? 0u : m->f4.depth;
}

uint32_t we_rank_depth6(const we_map_t *m)
{
    const we_fam_t *f = we_family6(m);

    return (f == NULL || f->n == 0u || f->kind != WE_KIND_RANK) ? 0u : f->depth;
}

/* ---- Publication ---- */

/*
 * Every we_map_t the core publishes is aligned_alloc(64, ...): the policy evaluator's descriptor line
 * counts (3, 3 and 2 lines per fill, by family) assume f4, f6, f6w and valid_until_ms sit at fixed
 * offsets from a 64-byte boundary, and malloc promises 16. Declaring the type alignas(64) instead
 * would be undefined behaviour under every malloc that already allocates one.
 */
static we_map_t *map_alloc(void)
{
    size_t bytes = (sizeof(we_map_t) + 63u) & ~(size_t)63u;
    we_map_t *m = (we_map_t *)aligned_alloc(64, bytes);

    if (m != NULL && ((uintptr_t)m & 63u) != 0u) {
        free(m);                   /* an allocator that broke its contract: refuse rather than mislay */
        return NULL;
    }
    return m;
}

/*
 * Swap `fresh` in and retire the map it replaces, by we_handle_publish's claim protocol (every step is
 * explained there). The caller has decided `fresh` may be published; it moves h->generation and the high
 * water only AFTER this returns WE_OK, so a refused publish moves neither (a revocation moves neither).
 */
static int publish_and_retire(we_handle_t *h, we_map_t *fresh, uint64_t now_ms)
{
    we_map_t *old;
    int i;

    /* first: a module-owned handle's maps never reach this ring (the ownership flag, see the header) */
    if (__atomic_load_n(&h->module_owned, __ATOMIC_ACQUIRE) != 0u) {
        return WE_ERR_OWNERSHIP;
    }
    old = __atomic_exchange_n(&h->current, fresh, __ATOMIC_ACQ_REL);
    WE_COUNT(h->loads_ok);
    if (old == NULL) {
        return WE_OK;
    }
    for (i = 0; i < WE_RETIRE_SLOTS; i++) {
        we_map_t *expect = NULL;

        if (__atomic_compare_exchange_n(&h->retired[i].map, &expect, WE_SLOT_RESERVED, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            __atomic_store_n(&h->retired[i].retired_at_ms, now_ms, __ATOMIC_RELAXED);
            __atomic_store_n(&h->retired[i].map, old, __ATOMIC_RELEASE);
            return WE_OK;
        }
    }
    WE_COUNT(h->leaked);           /* deliberate: never free under a live reader */
    return WE_OK;
}

int we_handle_publish_plane(we_handle_t *h, const char *path, uint64_t now_ms, we_load_detail_t *detail)
{
    we_map_t tmp;
    we_map_t *fresh;
    const we_map_t *cur;
    uint64_t mark;
    int rc;

    if (h == NULL) {
        return refuse(detail, WE_ERR_OPEN, 0, -1, "no handle");
    }
    if (__atomic_load_n(&h->module_owned, __ATOMIC_ACQUIRE) != 0u) {
        return refuse(detail, WE_ERR_OWNERSHIP, 0, -1, "the handle is a module's; only its own calls publish");
    }
    rc = we_plane_open(path, &tmp, detail);
    if (rc != WE_OK) {
        WE_COUNT(h->loads_failed);
        return rc;
    }
    if (tmp.generation == 0u) {
        /* format 2 never gets here (the loader refuses it); a format-1 file claiming "nothing armed" */
        we_map_close(&tmp);
        WE_COUNT(h->loads_failed);
        return refuse(detail, WE_ERR_FORMAT, 0, -1, "generation 0 is reserved for the revoked map");
    }
    /*
     * The rollback check against the CURRENT map's generation, never h->generation (a revocation does
     * not write it), and against the high-water mark, which a revocation does not lower: a backup that
     * puts the pre-revocation file back must not re-arm the revoked allow list.
     */
    cur = __atomic_load_n(&h->current, __ATOMIC_ACQUIRE);
    mark = __atomic_load_n(&h->high_water, __ATOMIC_RELAXED);
    if ((cur != NULL && tmp.generation <= cur->generation) || tmp.generation <= mark) {
        we_map_close(&tmp);
        WE_COUNT(h->rejected_rollbacks);
        return refuse(detail, WE_ERR_ROLLBACK, 0, -1,
                      "the generation is not above the current map's and the high-water mark");
    }
    fresh = map_alloc();
    if (fresh == NULL) {
        we_map_close(&tmp);
        WE_COUNT(h->loads_failed);
        return refuse(detail, WE_ERR_MMAP, 0, -1, "cannot allocate the descriptor");
    }
    *fresh = tmp;
    rc = publish_and_retire(h, fresh, now_ms);
    if (rc != WE_OK) {
        we_map_close(fresh);
        free(fresh);
        return refuse(detail, rc, 0, -1, "the handle is a module's; only its own calls publish");
    }
    __atomic_store_n(&h->high_water, fresh->generation, __ATOMIC_RELAXED);
    __atomic_store_n(&h->generation, fresh->generation, __ATOMIC_RELEASE);
    return WE_OK;
}

we_map_t *we_map_new_revoked(void)
{
    we_map_t *m = map_alloc();

    if (m == NULL) {
        return NULL;
    }
    memset(m, 0, sizeof *m);
    /* Every family n = 0, which answers "no range" before any load; idx still names a valid two-entry
     * table, as fill_family gives an empty family. */
    m->f4.kind = WE_KIND_RADIX;
    m->f4.idx = we_whole_window;
    m->f4.key_bits = 32u;
    m->f6.kind = WE_KIND_RADIX;
    m->f6.idx = we_whole_window;
    m->f6.key_bits = 128u;
    m->f6w.kind = WE_KIND_RADIX;
    m->f6w.idx = we_whole_window;
    m->f6w.key_bits = 64u;
    m->format = WE_FORMAT_2;
    m->plane_id = (uint8_t)WE_PLANE_TENANT;
    m->schema_id = (uint8_t)WE_SCHEMA_MEMBERSHIP;
    m->country_known = we_country_known_table;
    m->revoked = 1u;
    return m;
}

int we_handle_publish_map(we_handle_t *h, we_map_t *map, uint64_t now_ms)
{
    if (h == NULL || map == NULL) {
        return WE_ERR_OPEN;
    }
    if (((uintptr_t)map & 63u) != 0u || !map->revoked || map->generation != 0u || map->base != NULL
            || map->h != NULL || map->f4.n != 0u || map->f6.n != 0u || map->f6w.n != 0u) {
        return WE_ERR_FORMAT;
    }
    /* h->generation is NOT written and high_water is NOT lowered: see the header. */
    return publish_and_retire(h, map, now_ms);
}

int we_handle_publish(we_handle_t *h, const char *path, uint64_t now_ms)
{
    we_map_t *fresh;
    we_map_t tmp;
    we_map_t *old;
    int rc, i;

    if (h == NULL) {
        return WE_ERR_OPEN;
    }
    if (__atomic_load_n(&h->module_owned, __ATOMIC_ACQUIRE) != 0u) {
        return WE_ERR_OWNERSHIP;
    }
    rc = we_map_open(path, &tmp);
    if (rc != WE_OK) {
        WE_COUNT(h->loads_failed);
        return rc;                 /* previous mapping stays published; nothing changes */
    }
    /*
     * REFUSE A ROLLBACK. The generation is the format's own swap detector and nothing compared it.
     *
     * Serving an older snapshot is a silent policy downgrade, and because valid_until_ms travels in
     * the file, an old snapshot still inside its window enforces normally. Combined with an unkeyed
     * digest, anyone who can place a file - or a caching proxy, or an operator's rsync of a stale
     * mirror - could roll the fleet back to a previous policy with nothing noticing. That also undoes
     * the transparency story: an operator can prove WHICH snapshot they ran but would never be told it
     * went backwards.
     *
     * Refused rather than accepted-with-a-warning, because a rollback is never what anybody meant, and
     * refusing keeps the better data serving. An EQUAL generation is also refused: it is the same
     * snapshot, so reloading it is pure cost.
     */
    {
        const we_map_t *cur = __atomic_load_n(&h->current, __ATOMIC_ACQUIRE);

        if (cur != NULL && tmp.generation <= cur->generation) {
            we_map_close(&tmp);
            WE_COUNT(h->rejected_rollbacks);
            return WE_ERR_ROLLBACK;
        }
    }

    fresh = map_alloc();
    if (fresh == NULL) {
        we_map_close(&tmp);
        WE_COUNT(h->loads_failed);
        return WE_ERR_MMAP;
    }
    *fresh = tmp;

    /* Publish the generation BEFORE the mapping, so a metrics reader can never observe generation N
     * against mapping N+1. The reverse order was observable. */
    __atomic_store_n(&h->generation, fresh->generation, __ATOMIC_RELEASE);
    old = __atomic_exchange_n(&h->current, fresh, __ATOMIC_ACQ_REL);
    WE_COUNT(h->loads_ok);

    if (old != NULL) {
        for (i = 0; i < WE_RETIRE_SLOTS; i++) {
            we_map_t *expect = NULL;

            /*
             * CAS, NOT LOAD-THEN-STORE. The load-then-store this replaces let two concurrent
             * publishers both observe slot i empty and both store into it; the loser's mapping was
             * overwritten, so it was never unmapped and never counted in `leaked`. The design's leak
             * is deliberate, BOUNDED and counted; that one was unbounded and invisible.
             *
             * nginx cannot reach it (one worker, one thread, one refresher) which is why it shipped,
             * but this header promises the same core works "in a thread", and Apache worker/event and
             * LiteSpeed take that promise literally.
             *
             * The timestamp is still written BEFORE the map becomes visible, and the CAS IS that
             * release store, so the ordering the comment below describes is unchanged.
             */
            /*
             * RESERVE, write the timestamp, then PUBLISH. Three steps, and each one is load-bearing.
             *
             * Writing the timestamp before the claim - which is what this did - writes it into a slot
             * this publisher may not get. When the claim then fails because the slot is OCCUPIED, the
             * occupant's retirement time has already been overwritten with a later one, so its grace
             * window moves and it is not reclaimed when it should be. Under contention the documented
             * grace becomes unbounded and resident snapshots accumulate, which is a slow leak with no
             * counter behind it.
             *
             * ThreadSanitizer found it, and it took wiring the five gates into CI to find it at all:
             * TSan aborts before instrumenting on the aarch64 box this was written on, so it had
             * never run over this file. The race was unreachable from nginx (one worker, one thread)
             * and reachable from the Apache threaded MPMs and LiteSpeed, which is the population this
             * core promises to be safe in.
             *
             * The RESERVED sentinel keeps the ordering the previous fix established, with one writer
             * instead of two: a retirer that sees a real pointer is guaranteed by the release/acquire
             * pair to see the matching timestamp, and a slot mid-publish is simply skipped. The
             * timestamp is written ONLY by the thread that reserved the slot, so nothing else can
             * touch it, and the next reserver overwrites it before the slot is visible again - which
             * is why nothing has to clear it, and why no retirer may.
             */
            if (__atomic_compare_exchange_n(&h->retired[i].map, &expect, WE_SLOT_RESERVED, 0,
                                            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                __atomic_store_n(&h->retired[i].retired_at_ms, now_ms, __ATOMIC_RELAXED);
                __atomic_store_n(&h->retired[i].map, old, __ATOMIC_RELEASE);
                old = NULL;
                break;
            }
        }
        if (old != NULL) {
            WE_COUNT(h->leaked);           /* deliberate: see the header. Never free under a live reader. */
        }
    }
    return WE_OK;
}

void we_handle_retire(we_handle_t *h, uint64_t now_ms)
{
    uint64_t grace;
    int i;

    if (h == NULL) {
        return;
    }
    grace = (h->grace_ms != 0ull) ? h->grace_ms : WE_DEFAULT_GRACE_MS;
    for (i = 0; i < WE_RETIRE_SLOTS; i++) {
        we_map_t *m = __atomic_load_n(&h->retired[i].map, __ATOMIC_ACQUIRE);
        uint64_t at;

        if (m == NULL || m == WE_SLOT_RESERVED) {
            /* Empty, or reserved by a publisher that has not finished writing it. A reserved slot is
             * complete within a few instructions; leave it for the next sweep. The sentinel is never
             * dereferenced and never freed. */
            continue;
        }
        at = __atomic_load_n(&h->retired[i].retired_at_ms, __ATOMIC_RELAXED);
        if (at == 0ull) {
            /* A caller that passed now_ms == 0. A zero timestamp must never be read as "retired at
             * the epoch", which is what made the old code compute `now_ms >= 0 + grace` as TRUE on
             * any box up longer than the grace period and free a mapping a reader could still be
             * holding. (Before the RESERVED sentinel this also covered a slot mid-publish; that case
             * is now caught above, by a value a reader cannot mistake for a mapping.) */
            continue;
        }
        if (now_ms >= at + grace) {
            /*
             * CAS, so exactly ONE caller reclaims the slot and therefore exactly one frees.
             *
             * The load-then-store this replaces let two concurrent retirers both read the same
             * non-NULL m, both pass the grace test, and both run we_map_close(m); free(m). That is a
             * double free inside somebody else's web server, which is the single worst thing this
             * file could do. A thread that loses the CAS simply did not own the mapping and must not
             * touch it.
             */
            if (__atomic_compare_exchange_n(&h->retired[i].map, &m, (we_map_t *)NULL, 0,
                                            __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
                /*
                 * The timestamp is deliberately NOT cleared here, and that is a fix rather than an
                 * omission. Clearing it from a retirer is a second writer to a field whose whole
                 * safety rests on having one: after this CAS the slot is free, a publisher may claim
                 * and stamp it immediately, and a store landing after that would zero the NEW
                 * occupant's timestamp - leaving a slot that looks forever mid-publish, never
                 * reclaimed and never counted. The next reserver writes a fresh value before the
                 * slot is visible, so a stale one can never be read.
                 */
                we_map_close(m);
                free(m);
            }
        }
    }
}
