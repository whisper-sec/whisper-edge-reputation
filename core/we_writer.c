/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_writer.c - the test suite's snapshot writer. See we_writer.h; FORMAT.md is the layout.
 *
 * The S-tree is filled here by an IN-ORDER WALK of the implicit tree (visit child 0, slot 0, child 1,
 * slot 1, ... child B), which is a different algorithm from the loader's closed-form position check,
 * so a mistake in either shows up as a refused file rather than as two copies of one error.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "we_writer.h"
#include "we_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static size_t up(size_t v, size_t a)
{
    return (v + a - 1u) & ~(a - 1u);
}

static uint32_t schema_of(const ww_plane_t *p)
{
    if (p->format == WE_FORMAT_1) {
        return WE_SCHEMA_FORMAT1;
    }
    return (p->plane == WE_PLANE_ROUTING || p->plane == WE_PLANE_REGISTRY) ? WE_SCHEMA_ROUTING
                                                                           : WE_SCHEMA_MEMBERSHIP;
}

uint32_t ww_key_bytes(const ww_plane_t *p, int family)
{
    if (family == 4) {
        return 4u;
    }
    return schema_of(p) == WE_SCHEMA_ROUTING ? 8u : 16u;
}

uint32_t ww_record_stride(const ww_plane_t *p, int family)
{
    uint32_t schema = schema_of(p);

    if (schema == WE_SCHEMA_FORMAT1) {
        return 0u;
    }
    if (family == 4) {
        return 16u;
    }
    return schema == WE_SCHEMA_ROUTING ? 24u : 32u;
}

uint32_t ww_depth(uint32_t m, uint32_t fanout)
{
    uint64_t p = 1u;
    uint32_t d = 0u;

    while (p < (uint64_t)m) {
        p *= fanout;
        d++;
    }
    return d;
}

static void put_key(uint8_t *at, __uint128_t v, uint32_t kb)
{
    if (kb == 4u) {
        uint32_t x = (uint32_t)v;
        memcpy(at, &x, 4);
    } else if (kb == 8u) {
        uint64_t x = (uint64_t)v;
        memcpy(at, &x, 8);
    } else {
        memcpy(at, &v, 16);
    }
}

static uint32_t top_bits(__uint128_t key, uint32_t kb, uint32_t k)
{
    return (uint32_t)(key >> (kb * 8u - k));
}

/* ---- the S-tree, by an in-order walk ---- */
typedef struct {
    uint8_t           *tree;
    const __uint128_t *start;
    uint32_t           kb, fan, depth, s, m;
    uint32_t           next;     /* the next separator to place: j = next + 1 */
    __uint128_t        kmax;
} ww_tree_t;

static void walk(ww_tree_t *t, uint64_t node, uint32_t level)
{
    uint32_t q;

    if (level == t->depth) {
        return;
    }
    for (q = 0u; q < t->fan - 1u; q++) {
        __uint128_t v;

        walk(t, node * t->fan + q + 1u, level + 1u);
        if (t->next + 1u < t->m) {
            v = t->start[(size_t)(t->next + 1u) * t->s];
            t->next++;
        } else {
            v = t->kmax;
        }
        put_key(t->tree + (size_t)node * 64u + (size_t)q * t->kb, v, t->kb);
    }
    walk(t, node * t->fan + t->fan, level + 1u);
}

typedef struct {
    uint32_t idx_off, start_off, end_off, sev_off, meta_off, rec_off, sample_off;
    uint32_t sample_count, depth, nodes, kb, stride;
} ww_lay_t;

static size_t lay_family_f2(const ww_family_t *f, uint32_t kb, uint32_t stride, size_t off, ww_lay_t *l)
{
    memset(l, 0, sizeof *l);
    l->kb = kb;
    l->stride = stride;
    if (f->n == 0u) {
        return off;
    }
    if (f->kind == WE_KIND_RADIX) {
        off = up(off, 64u);         /* FORMAT.md §5: the radix table is 64-byte aligned */
        l->idx_off = (uint32_t)off;
        off += (((size_t)1 << f->param) + 1u) * 4u;
    }
    off = up(off, 64u);
    l->start_off = (uint32_t)off;
    off += (size_t)f->n * kb;
    off = up(off, 64u);
    l->rec_off = (uint32_t)off;
    off += (size_t)f->n * stride;
    if (f->kind == WE_KIND_RANK) {
        uint32_t s = 1u << f->param;
        uint32_t fan = 64u / kb + 1u;
        uint64_t p = 1u;
        uint32_t i;

        l->sample_count = (uint32_t)(((uint64_t)f->n + s - 1u) / s);
        l->depth = ww_depth(l->sample_count, fan);
        for (i = 0u; i < l->depth; i++) {
            p *= fan;
        }
        l->nodes = (uint32_t)((p - 1u) / (fan - 1u));
        if (l->nodes > 0u) {
            off = up(off, 64u);
            l->sample_off = (uint32_t)off;
            off += (size_t)l->nodes * 64u;
        }
    }
    if (f->meta != NULL) {
        off = up(off, 4u);
        l->meta_off = (uint32_t)off;
        off += (size_t)f->n * 4u;
    }
    return off;
}

static size_t lay_family_f1(const ww_family_t *f, uint32_t kb, size_t off, ww_lay_t *l)
{
    memset(l, 0, sizeof *l);
    l->kb = kb;
    if (f->n == 0u) {
        return off;
    }
    off = up(off, kb);
    l->start_off = (uint32_t)off;
    off += (size_t)f->n * kb;
    off = up(off, kb);
    l->end_off = (uint32_t)off;
    off += (size_t)f->n * kb;
    if (f->kind == WE_KIND_RADIX) {
        off = up(off, 4u);
        l->idx_off = (uint32_t)off;
        off += 65537u * 4u;
    }
    if (f->meta != NULL) {
        off = up(off, 4u);
        l->meta_off = (uint32_t)off;
        off += (size_t)f->n * 4u;
    }
    l->sev_off = (uint32_t)off;
    off += f->n;
    return off;
}

static void fill_family(uint8_t *buf, const ww_family_t *f, const ww_lay_t *l, uint32_t format)
{
    uint32_t i;

    if (f->n == 0u) {
        return;
    }
    for (i = 0u; i < f->n; i++) {
        put_key(buf + l->start_off + (size_t)i * l->kb, f->start[i], l->kb);
    }
    if (format == WE_FORMAT_1) {
        for (i = 0u; i < f->n; i++) {
            put_key(buf + l->end_off + (size_t)i * l->kb, f->end[i], l->kb);
            buf[l->sev_off + i] = f->sev != NULL ? f->sev[i] : (uint8_t)WE_SEV_HIGH;
        }
    } else {
        if (f->rec != NULL) {
            memcpy(buf + l->rec_off, f->rec, (size_t)f->n * l->stride);
        }
        for (i = 0u; i < f->n; i++) {
            put_key(buf + l->rec_off + (size_t)i * l->stride, f->end[i], l->kb);
        }
    }
    if (f->meta != NULL) {
        memcpy(buf + l->meta_off, f->meta, (size_t)f->n * 4u);
    }
    if (f->kind == WE_KIND_RADIX) {
        uint32_t k = format == WE_FORMAT_1 ? 16u : f->param;
        uint32_t buckets = 1u << k;
        uint32_t *idx = (uint32_t *)(void *)(buf + l->idx_off);
        uint32_t b, cur = 0u;

        /* idx[b] = how many starts have top-k bits below b; idx[2^k] = n, the sentinel. */
        for (b = 0u; b < buckets; b++) {
            while (cur < f->n && top_bits(f->start[cur], l->kb, k) < b) {
                cur++;
            }
            idx[b] = cur;
        }
        idx[buckets] = f->n;
    }
    if (f->kind == WE_KIND_RANK && l->nodes > 0u) {
        ww_tree_t t;

        t.tree = buf + l->sample_off;
        t.start = f->start;
        t.kb = l->kb;
        t.fan = 64u / l->kb + 1u;
        t.depth = l->depth;
        t.s = 1u << f->param;
        t.m = l->sample_count;
        t.next = 0u;
        t.kmax = l->kb == 4u ? (__uint128_t)0xffffffffu
               : l->kb == 8u ? (__uint128_t)0xffffffffffffffffull : ~(__uint128_t)0;
        walk(&t, 0u, 0u);
    }
}

void ww_sign(uint8_t *buf, size_t len)
{
    we_header_t bare;
    we_sha256_ctx ctx;
    uint8_t dig[32];

    memcpy(&bare, buf, sizeof bare);
    memset(bare.digest, 0, 32);
    we_sha256_init(&ctx);
    we_sha256_update(&ctx, &bare, sizeof bare);
    we_sha256_update(&ctx, buf + sizeof bare, len - sizeof bare);
    we_sha256_final(&ctx, dig);
    memcpy(buf + 104, dig, 32);
}

uint8_t *ww_build(const ww_plane_t *p, size_t *len)
{
    ww_lay_t l4, l6;
    uint32_t kb6 = ww_key_bytes(p, 6);
    size_t off = sizeof(we_header_t);
    size_t blob_off = 0u;
    uint8_t *buf;
    we_header_t h;
    char table[4096];
    const char *blob = p->blob;
    uint32_t blob_len = p->blob_len;

    /* Format 2's blob is the feed-name table: u16 count, then the NUL-terminated names. */
    if (p->format == WE_FORMAT_2 && blob == NULL) {
        uint16_t n = (uint16_t)(p->nfeeds == 0u ? 1u : p->nfeeds);
        size_t pos = 2u;
        uint32_t i;

        memcpy(table, &n, 2);
        for (i = 0; i < n; i++) {
            const char *name = p->nfeeds == 0u ? "" : p->feeds[i];
            size_t l = strlen(name) + 1u;

            if (pos + l > sizeof table) {
                return NULL;
            }
            memcpy(table + pos, name, l);
            pos += l;
        }
        blob = table;
        blob_len = (uint32_t)pos;
    }

    if (p->format == WE_FORMAT_2) {
        off = up(off, 64u);
        off = lay_family_f2(&p->v4, 4u, ww_record_stride(p, 4), off, &l4);
        off = lay_family_f2(&p->v6, kb6, ww_record_stride(p, 6), off, &l6);
    } else {
        off = lay_family_f1(&p->v6, 16u, off, &l6);
        off = lay_family_f1(&p->v4, 4u, off, &l4);
    }
    if (blob_len > 0u) {
        blob_off = off;
        off += blob_len;
    }
    buf = (uint8_t *)calloc(1, off);
    if (buf == NULL) {
        return NULL;
    }

    memset(&h, 0, sizeof h);
    h.magic = WE_MAGIC;
    h.format = p->format;
    h.generation = p->generation;
    h.built_at_ms = 1000000ull;
    h.valid_until_ms = p->valid_until_ms;
    h.tier = 1u;
    h.v4_count = p->v4.n;
    h.v6_count = p->v6.n;
    h.v4_index_off = l4.idx_off;
    h.v4_start_off = l4.start_off;
    h.v4_end_off = l4.end_off;
    h.v4_sev_off = l4.sev_off;
    h.v4_meta_off = l4.meta_off;
    h.v6_index_off = l6.idx_off;
    h.v6_start_off = l6.start_off;
    h.v6_end_off = l6.end_off;
    h.v6_sev_off = l6.sev_off;
    h.v6_meta_off = l6.meta_off;
    h.blob_off = (uint32_t)blob_off;
    h.blob_len = blob_len;
    h.file_len = (uint32_t)off;
    if (p->v4.kind == WE_KIND_RADIX) {
        h.flags |= WE_H_V4_INDEXED;
    }
    if (p->v6.kind == WE_KIND_RADIX) {
        h.flags |= WE_H_V6_INDEXED;
    }
    if (p->schema || p->format == WE_FORMAT_2) {
        we_schema_t *t = &h.schema;

        h.flags |= WE_H_SCHEMA;
        t->plane_id = (uint8_t)(p->format == WE_FORMAT_1 ? WE_PLANE_REPUTATION : p->plane);
        t->schema_id = (uint8_t)schema_of(p);
        t->v4_key_bits = 32u;
        t->v6_key_bits = (uint8_t)(kb6 * 8u);
        t->v4_index_kind = (uint8_t)p->v4.kind;
        t->v4_index_param = (uint8_t)(p->v4.kind == WE_KIND_NONE ? 0u : p->v4.param);
        t->v6_index_kind = (uint8_t)p->v6.kind;
        t->v6_index_param = (uint8_t)(p->v6.kind == WE_KIND_NONE ? 0u : p->v6.param);
        if (p->format == WE_FORMAT_2) {
            t->v4_record_stride = (uint16_t)ww_record_stride(p, 4);
            t->v6_record_stride = (uint16_t)ww_record_stride(p, 6);
            t->v4_record_off = l4.rec_off;
            t->v6_record_off = l6.rec_off;
            t->v4_sample_off = l4.sample_off;
            t->v6_sample_off = l6.sample_off;
            t->v4_sample_count = l4.sample_count;
            t->v6_sample_count = l6.sample_count;
            t->v4_depth = (uint8_t)l4.depth;
            t->v6_depth = (uint8_t)l6.depth;
            t->country_table_version = schema_of(p) == WE_SCHEMA_ROUTING ? p->country_version : 0u;
            /* An empty family's rank fields: m = ceil(0 / s) = 0 and depth 0, which lay_family_f2 left. */
        }
    }
    memcpy(buf, &h, sizeof h);
    fill_family(buf, &p->v4, &l4, p->format);
    fill_family(buf, &p->v6, &l6, p->format);
    if (blob_len > 0u) {
        memcpy(buf + blob_off, blob, blob_len);
    }
    ww_sign(buf, off);
    *len = off;
    return buf;
}

int ww_save(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL) {
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    return chmod(path, 0644) == 0 ? 0 : -1;
}

int ww_write(const char *path, const ww_plane_t *p)
{
    size_t len = 0u;
    uint8_t *buf = ww_build(p, &len);
    int rc;

    if (buf == NULL) {
        return -1;
    }
    rc = ww_save(path, buf, len);
    free(buf);
    return rc;
}
