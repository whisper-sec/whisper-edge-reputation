/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_writer.h - the test suite's snapshot writer: both formats, both index kinds, every plane.
 *
 * TEST SUPPORT, never linked into a module. It lays the file out from FORMAT.md by itself and shares
 * nothing with the loader but the struct definitions and SHA-256, so a reader and this writer agreeing
 * is an assertion about the format rather than one function agreeing with itself. (Agreement across
 * LANGUAGES is the interop gate's job: make-test-snapshot.py is the second, independent writer.)
 *
 * The caller hands it sorted, disjoint ranges as zero-extended 128-bit keys; the key width comes from
 * the plane (32 for IPv4, 64 for routing and registry IPv6, 128 otherwise and in format 1).
 */
#ifndef WE_WRITER_H
#define WE_WRITER_H

#include "whisper_edge.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t           n;
    const __uint128_t *start;     /* n keys, zero-extended */
    const __uint128_t *end;       /* n inclusive ends */
    uint32_t           kind;      /* WE_KIND_NONE, _RADIX or _RANK */
    uint32_t           param;     /* radix k, or log2 of the rank stride; 0 for none */
    const uint8_t     *sev;       /* format 1: n severity bytes (NULL: WE_SEV_HIGH for every range) */
    const uint8_t     *rec;       /* format 2: n * stride record bytes (NULL: zeros); `end` is stamped in */
    const uint32_t    *meta;      /* optional: n blob offsets */
} ww_family_t;

typedef struct {
    uint32_t    format;           /* 1 or 2 */
    int         schema;           /* set WE_H_SCHEMA; format 2 always does */
    uint32_t    plane;            /* WE_PLANE_*; ignored for a pre-schema format-1 file */
    uint16_t    country_version;  /* routing planes only */
    uint64_t    generation;
    uint64_t    valid_until_ms;
    ww_family_t v4;
    ww_family_t v6;
    /*
     * Format 2: the blob is the feed-name table built from `feeds` (entry 0 must be ""), or the
     * one-entry table {""} when nfeeds is 0. A caller that sets `blob` gets those bytes verbatim
     * instead, which is how a test writes a malformed table.
     */
    const char *const *feeds;
    uint32_t    nfeeds;
    const char *blob;
    uint32_t    blob_len;
} ww_plane_t;

/* The key bytes and record stride a plane's family uses. */
uint32_t ww_key_bytes(const ww_plane_t *p, int family);
uint32_t ww_record_stride(const ww_plane_t *p, int family);

/* The smallest d with (B+1)^d >= m, in integers (FORMAT.md §4.2). */
uint32_t ww_depth(uint32_t m, uint32_t fanout);

/* Lay the plane out and sign it. Returns a malloc'd buffer, or NULL; *len receives its length. */
uint8_t *ww_build(const ww_plane_t *p, size_t *len);

/* Recompute the digest over a buffer a test has sabotaged, so only the structure check can refuse it. */
void ww_sign(uint8_t *buf, size_t len);

/* Write a buffer at mode 0644 (the loader refuses a group- or world-writable file). 0 on success. */
int ww_save(const char *path, const uint8_t *buf, size_t len);

/* ww_build + ww_save. 0 on success. */
int ww_write(const char *path, const ww_plane_t *p);

#endif /* WE_WRITER_H */
