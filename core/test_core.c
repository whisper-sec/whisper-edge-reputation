/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * test_core.c - the acceptance criteria for the edge core, as runnable code.
 *
 * They are two kinds of claim: numbers (a bounded worst-case probe count, zero allocation on the
 * verdict, a small resident set, a fast cold start) and a chaos list (delete the snapshot, truncate
 * it, corrupt it, break DNS, fill the disk, kill the refresher; traffic must keep flowing in every
 * case). Both are checked here, in one binary, so the claim and the measurement cannot drift apart.
 *
 * The numbers are deliberately NOT restated here as targets. A target written in a comment is a
 * number that stops being measured; the assertions below carry the real ones, and
 * core/hotpath-gate.sh carries the allocation and syscall claims against the compiled code.
 *
 * HOW CORRECTNESS IS CHECKED, and why it is not two copies of one assumption. The property that
 * matters is "the compiled snapshot answers exactly what longest-prefix-match over the input prefixes
 * would answer". So the test keeps a naive LPM ORACLE - walk every prefix, take the most specific
 * match - and derives the range set FROM that oracle by sweeping the elementary intervals between
 * boundary points. The resolver cannot share a bug with the oracle, because it has no logic of its
 * own; it only asks the oracle. Then we assert the loaded binary search agrees with the oracle on
 * every boundary, every boundary plus and minus one, and a few hundred thousand random addresses.
 * A disagreement means the lookup, the index, or the file layout is wrong, which is exactly the set
 * of things under test.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "whisper_edge.h"
#include <sys/stat.h>

/* every stat() the identity's inline functions make in this file, counted while armed, so a row can
 * show that naming the namespace makes no stat of /proc/self/ns/pid at all on the normal path */
static int ts_stat_armed, ts_ns_stats;

__attribute__((unused)) static int ts_counted_stat(const char *path, struct stat *st)
{
    if (ts_stat_armed && strcmp(path, "/proc/self/ns/pid") == 0) {
        ts_ns_stats++;
    }
    return stat(path, st);
}
#define stat(path, st) ts_counted_stat(path, st)
#include "we_procid.h"
#undef stat
#include "we_sha256.h"
#include "we_writer.h"
#ifndef WE_COUNT_DIGEST
#error "test_core asserts the digest work by its block count: build it with -DWE_COUNT_DIGEST, as the Makefile's test_core rule does"
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

#define SECTION(name) printf("\n== %s ==\n", name)

/* ---- deterministic PRNG, so a failure is reproducible ---- */
static uint64_t rng_s = 0x9e3779b97f4a7c15ull;
static uint32_t rnd32(void)
{
    rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17;
    return (uint32_t)(rng_s >> 32);
}

/* ---- the oracle: naive longest-prefix-match ---- */
typedef struct { uint32_t addr; uint8_t len; uint8_t sev; } pfx_t;

static uint8_t oracle(const pfx_t *p, int n, uint32_t a)
{
    int best = -1, i;
    uint8_t bestlen = 0;

    for (i = 0; i < n; i++) {
        uint32_t mask = (p[i].len == 0) ? 0u : (0xffffffffu << (32 - p[i].len));
        if ((a & mask) == (p[i].addr & mask)) {
            if (best < 0 || p[i].len > bestlen) { best = i; bestlen = p[i].len; }
        }
    }
    return (best < 0) ? WE_SEV_NONE : p[best].sev;
}

/* ---- derive disjoint ranges by asking the oracle at every elementary interval ---- */
typedef struct { uint32_t start, end; uint8_t sev; } rng_t;

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x < y) ? -1 : (x > y);
}

static int resolve(const pfx_t *p, int n, rng_t *out, int cap)
{
    uint32_t *pts = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(2 * n + 2));
    int np = 0, i, nr = 0;

    pts[np++] = 0u;
    for (i = 0; i < n; i++) {
        uint32_t mask = (p[i].len == 0) ? 0u : (0xffffffffu << (32 - p[i].len));
        uint32_t lo = p[i].addr & mask;
        uint32_t hi = lo | ~mask;
        pts[np++] = lo;
        if (hi != 0xffffffffu) { pts[np++] = hi + 1u; }
    }
    qsort(pts, (size_t)np, sizeof(uint32_t), cmp_u32);

    for (i = 0; i < np; i++) {
        uint32_t lo, hi;
        uint8_t sev;

        if (i > 0 && pts[i] == pts[i - 1]) { continue; }
        lo = pts[i];
        hi = 0xffffffffu;
        { int j; for (j = i + 1; j < np; j++) { if (pts[j] > lo) { hi = pts[j] - 1u; break; } } }
        sev = oracle(p, n, lo);
        if (sev == WE_SEV_NONE) { continue; }
        /* merge with the previous range when adjacent and equal, so the file stays minimal */
        if (nr > 0 && out[nr - 1].sev == sev && out[nr - 1].end + 1u == lo) {
            out[nr - 1].end = hi;
        } else {
            if (nr >= cap) { free(pts); return -1; }
            out[nr].start = lo; out[nr].end = hi; out[nr].sev = sev; nr++;
        }
    }
    free(pts);
    return nr;
}

/* ---- snapshot writer: the file format, written independently of the reader ---- */
typedef struct { uint8_t a[16]; } v6a_t;
typedef struct { v6a_t start, end; uint8_t sev; } rng6_t;

static size_t align_up(size_t v, size_t a) { return (v + a - 1u) & ~(a - 1u); }

static int write_snapshot(const char *path, const rng_t *r4, uint32_t n4,
                          const rng6_t *r6, uint32_t n6, int with_index,
                          uint64_t generation, uint64_t valid_until_ms,
                          const char *blob, uint32_t blob_len, const uint32_t *meta4)
{
    we_header_t h;
    size_t off;
    uint8_t *buf;
    size_t total;
    uint32_t i;
    FILE *f;
    uint8_t dig[32];
    we_sha256_ctx ctx;
    we_header_t bare;

    memset(&h, 0, sizeof h);
    h.magic = WE_MAGIC;
    h.format = WE_FORMAT;
    h.generation = generation;
    h.built_at_ms = 1000000ull;
    h.valid_until_ms = valid_until_ms;
    h.tier = 1;
    h.v4_count = n4;
    h.v6_count = n6;
    if (with_index && n4 > 0) { h.flags |= WE_H_V4_INDEXED; }

    off = sizeof(we_header_t);
    if (n6 > 0) {
        off = align_up(off, 16); h.v6_start_off = (uint32_t)off; off += (size_t)n6 * 16u;
        off = align_up(off, 16); h.v6_end_off   = (uint32_t)off; off += (size_t)n6 * 16u;
        if (with_index) {
            h.flags |= WE_H_V6_INDEXED;
            off = align_up(off, 4); h.v6_index_off = (uint32_t)off; off += 65537u * 4u;
        }
    }
    if (n4 > 0) {
        if (with_index) { off = align_up(off, 4); h.v4_index_off = (uint32_t)off; off += 65537u * 4u; }
        off = align_up(off, 4); h.v4_start_off = (uint32_t)off; off += (size_t)n4 * 4u;
        off = align_up(off, 4); h.v4_end_off   = (uint32_t)off; off += (size_t)n4 * 4u;
        if (meta4) { off = align_up(off, 4); h.v4_meta_off = (uint32_t)off; off += (size_t)n4 * 4u; }
        h.v4_sev_off = (uint32_t)off; off += n4;
    }
    if (n6 > 0) { h.v6_sev_off = (uint32_t)off; off += n6; }
    if (blob_len > 0) { h.blob_off = (uint32_t)off; h.blob_len = blob_len; off += blob_len; }
    total = off;
    h.file_len = (uint32_t)total;

    buf = (uint8_t *)calloc(1, total);
    if (!buf) { return -1; }

    for (i = 0; i < n4; i++) {
        memcpy(buf + h.v4_start_off + i * 4u, &r4[i].start, 4);
        memcpy(buf + h.v4_end_off   + i * 4u, &r4[i].end,   4);
        buf[h.v4_sev_off + i] = r4[i].sev;
        if (meta4) { memcpy(buf + h.v4_meta_off + i * 4u, &meta4[i], 4); }
    }
    for (i = 0; i < n6; i++) {
        __uint128_t s = 0, e = 0;
        int k;
        /* The fixture carries v6 bounds as big-endian octets for readability, so convert, then store
         * the NATIVE value - which is the little-endian the format specifies and the reader loads
         * directly. This memcpy of a native __uint128_t is only portable because whisper_edge.h
         * refuses to build on a big-endian target; see the note there. */
        for (k = 0; k < 16; k++) { s = (s << 8) | r6[i].start.a[k]; e = (e << 8) | r6[i].end.a[k]; }
        memcpy(buf + h.v6_start_off + i * 16u, &s, 16);
        memcpy(buf + h.v6_end_off   + i * 16u, &e, 16);
        buf[h.v6_sev_off + i] = r6[i].sev;
    }
    if (with_index && n4 > 0) {
        /* idx[b] = number of ranges whose start is below (b << 16) */
        uint32_t *idx = (uint32_t *)(buf + h.v4_index_off);
        uint32_t b, cur = 0;
        for (b = 0; b < 65536u; b++) {
            uint64_t bucket = (uint64_t)b << 16;
            while (cur < n4 && (uint64_t)r4[cur].start < bucket) { cur++; }
            idx[b] = cur;
        }
        idx[65536] = n4;   /* the sentinel: not a bucket, just the end of the array */
    }
    if (with_index && n6 > 0) {
        /* idx[b] = number of v6 ranges whose start is below (b << 112) */
        uint32_t *idx = (uint32_t *)(buf + h.v6_index_off);
        uint32_t b, cur = 0;
        for (b = 0; b < 65536u; b++) {
            __uint128_t bucket = (__uint128_t)b << 112;
            while (cur < n6) {
                __uint128_t sv = 0;
                int k;
                for (k = 0; k < 16; k++) { sv = (sv << 8) | r6[cur].start.a[k]; }
                if (sv < bucket) { cur++; } else { break; }
            }
            idx[b] = cur;
        }
        idx[65536] = n6;   /* the sentinel: see the v4 writer above */
    }
    if (blob_len > 0) { memcpy(buf + h.blob_off, blob, blob_len); }

    memcpy(&bare, &h, sizeof bare);
    memset(bare.digest, 0, 32);
    we_sha256_init(&ctx);
    we_sha256_update(&ctx, &bare, sizeof bare);
    we_sha256_update(&ctx, buf + sizeof bare, total - sizeof bare);
    we_sha256_final(&ctx, dig);
    memcpy(h.digest, dig, 32);
    memcpy(buf, &h, sizeof h);

    f = fopen(path, "wb");
    if (!f) { free(buf); return -1; }
    if (fwrite(buf, 1, total, f) != total) { fclose(f); free(buf); return -1; }
    fclose(f);
    free(buf);
    /* 0644, because the loader refuses a group- or world-WRITABLE snapshot and a real publisher must
     * therefore produce one that is not. A fixture written at the ambient umask would have been
     * group-writable here, which is exactly the thing the loader is now right to refuse. */
    if (chmod(path, 0644) != 0) { return -1; }
    return 0;
}

static const char *TMPDIR_ = NULL;

/*
 * Rotating buffers, NOT one. The first version of this helper returned a single static buffer, which
 * made corrupt(tmppath("good.snap"), tmppath("c.snap"), ...) pass the SAME pointer twice: both
 * arguments were evaluated before the call, so the second snprintf overwrote the first and the
 * function read the file it was about to write. It segfaulted on the missing file, which is the lucky
 * outcome; had c.snap existed the test would have quietly corrupted the wrong file and still passed.
 * Four slots is enough for any one call here, and the rotation is what makes two tmppath() results
 * usable in a single expression.
 */
#define TMPPATH_SLOTS 4
static char pathbuf[TMPPATH_SLOTS][512];
static int pathslot = 0;
static const char *tmppath(const char *name)
{
    char *b = pathbuf[pathslot];
    pathslot = (pathslot + 1) % TMPPATH_SLOTS;
    snprintf(b, 512, "%s/%s", TMPDIR_, name);
    return b;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/*
 * ---- write_crafted(): sign a buffer the CALLER laid out byte by byte ----
 *
 * This is the primitive the suite was missing, and its absence is why the offset validator went
 * unexercised and why the meta array had no bounds check at all.
 *
 * write_snapshot() computes every offset itself, so NO test written through it can express a header
 * whose offsets are hostile - and hostile offsets are the entire reason in_file() and aligned() exist.
 * The 7,088 single-bit flips and the index tamperings all mutate a file that writer produced: they
 * prove the digest and the index validator thoroughly, and they cannot reach the offset validator.
 *
 * So this hands we_map_open() a file no honest builder would ever emit, with a VALID digest, so only
 * the structure check can refuse it. Every case below is a single-field sabotage of one legal
 * baseline, which keeps a failure pointing at exactly one rule.
 */
#define CRAFT_CAP 8192

static void write_crafted(const char *path, uint8_t *buf, size_t total)
{
    we_header_t bare;
    we_sha256_ctx ctx;
    uint8_t dig[32];
    FILE *f;

    memcpy(&bare, buf, sizeof bare);
    memset(bare.digest, 0, 32);
    we_sha256_init(&ctx);
    we_sha256_update(&ctx, &bare, sizeof bare);
    we_sha256_update(&ctx, buf + sizeof bare, total - sizeof bare);
    we_sha256_final(&ctx, dig);
    memcpy(buf + 104, dig, 32);
    f = fopen(path, "wb");
    if (f == NULL) {
        CHECK(0, "cannot open %s for writing", path);
        return;
    }
    if (fwrite(buf, 1, total, f) != total) {
        CHECK(0, "short write to %s", path);
    }
    fclose(f);
    if (chmod(path, 0644) != 0) {
        CHECK(0, "cannot chmod %s", path);
    }
}

/* A minimal LEGAL unindexed one-range v4 snapshot with a meta array and a blob: 10.0.0.0/24 at HIGH
 * with evidence "SBL1". Each test then sabotages exactly one field of it. */
static size_t craft_base(uint8_t *buf)
{
    we_header_t *h = (we_header_t *)buf;

    memset(buf, 0, CRAFT_CAP);
    h->magic = WE_MAGIC;
    h->format = WE_FORMAT;
    h->generation = 1;
    h->v4_count = 1;
    h->v4_start_off = 192;
    h->v4_end_off = 196;
    h->v4_meta_off = 200;
    h->v4_sev_off = 204;
    h->blob_off = 208;
    h->blob_len = 8;
    h->file_len = 216;
    { uint32_t v = 0x0a000000u; memcpy(buf + 192, &v, 4); }
    { uint32_t v = 0x0a0000ffu; memcpy(buf + 196, &v, 4); }
    { uint32_t v = 1u; memcpy(buf + 200, &v, 4); }     /* meta[0] -> blob offset 1 */
    buf[204] = WE_SEV_HIGH;
    memcpy(buf + 208, "\0SBL1\0\0", 8);
    return 216;
}

/*
 * Call something in a CHILD, so a fault is a reported failure rather than a dead test run.
 *
 * Returns the child's exit status, or the negated signal number if it died. Both of the memory-safety
 * findings this exercises killed the process, so a test that called them directly would take the whole
 * suite down and report nothing.
 */
static int in_child(const char *path, int (*body)(const char *))
{
    pid_t pid;
    int st = 0;

    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        _exit(body(path));
    }
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) {
        return -WTERMSIG(st);
    }
    return WEXITSTATUS(st);
}

/* strlen the evidence, which is what every shim does with it. */
static int child_evidence(const char *path)
{
    we_map_t m;
    const char *e;

    if (we_map_open(path, &m) != WE_OK) {
        return 70;
    }
    e = we_evidence4(&m, 0x0a000005u);
    if (e == NULL) {
        we_map_close(&m);
        return 71;
    }
    if (strlen(e) > 4096) {
        we_map_close(&m);
        return 72;
    }
    we_map_close(&m);
    return 0;
}

/* Load, answer, have the file rewritten IN PLACE underneath, then answer again. */
static int child_truncate_under_live_snapshot(const char *path)
{
    we_map_t m;
    volatile uint8_t sink;
    int fd;

    if (we_map_open(path, &m) != WE_OK) {
        return 70;
    }
    sink = we_lookup4(&m, 0x0a000005u);
    if ((sink & WE_SEV_MASK) != WE_SEV_HIGH) {
        we_map_close(&m);
        return 71;
    }
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
    }
    sink = we_lookup4(&m, 0x0a000005u);        /* must still answer, must not fault */
    if ((sink & WE_SEV_MASK) != WE_SEV_HIGH) {
        we_map_close(&m);
        return 72;
    }
    we_map_close(&m);
    (void) sink;
    return 0;
}

static void test_a_writable_snapshot_is_refused(void)
{
    uint8_t buf[CRAFT_CAP];
    size_t total;
    we_map_t m;
    int rc;

    SECTION("a group- or world-writable snapshot is refused, not merely warned about");

    /*
     * The digest is unkeyed and self-referential, so whoever can write the file controls whom the site
     * blocks, with nothing anywhere to detect it. On shared hosting that is another tenant.
     */
    total = craft_base(buf);
    write_crafted(tmppath("c-perm.snap"), buf, total);

    CHECK(chmod(tmppath("c-perm.snap"), 0644) == 0, "chmod 0644");
    rc = we_map_open(tmppath("c-perm.snap"), &m);
    CHECK(rc == WE_OK, "0644 is fine: the feed is public, only WRITE bits matter (%s)", we_strerror(rc));
    if (rc == WE_OK) {
        we_map_close(&m);
    }

    CHECK(chmod(tmppath("c-perm.snap"), 0664) == 0, "chmod 0664");
    CHECK(we_map_open(tmppath("c-perm.snap"), &m) == WE_ERR_PERMISSIONS, "group-writable refused");

    CHECK(chmod(tmppath("c-perm.snap"), 0666) == 0, "chmod 0666");
    CHECK(we_map_open(tmppath("c-perm.snap"), &m) == WE_ERR_PERMISSIONS, "world-writable refused");

    CHECK(chmod(tmppath("c-perm.snap"), 0600) == 0, "chmod 0600");
    rc = we_map_open(tmppath("c-perm.snap"), &m);
    CHECK(rc == WE_OK, "0600 is fine (%s)", we_strerror(rc));
    if (rc == WE_OK) {
        /* And refusing is the FAIL-OPEN direction: no mapping means every address is allowed. */
        we_map_close(&m);
    }
    {
        we_map_t none;
        memset(&none, 0, sizeof none);
        CHECK(we_lookup4(&none, 0x0a000005u) == WE_SEV_NONE,
              "a refused snapshot leaves nothing published, so everything is allowed");
    }
}

static void test_hostile_offsets(void)
{
    uint8_t buf[CRAFT_CAP];
    we_header_t *h = (we_header_t *)buf;
    we_map_t m;
    size_t total;
    int rc;

    SECTION("hostile offsets: a header no honest builder emits, with a VALID digest");

    total = craft_base(buf);
    write_crafted(tmppath("c-base.snap"), buf, total);
    rc = we_map_open(tmppath("c-base.snap"), &m);
    CHECK(rc == WE_OK, "the crafted BASELINE must load, or every case below proves nothing: %s",
          we_strerror(rc));
    if (rc == WE_OK) {
        CHECK(we_lookup4(&m, 0x0a000005u) == WE_SEV_HIGH, "and answer");
        {
            const char *e = we_evidence4(&m, 0x0a000005u);
            CHECK(e != NULL && strcmp(e, "SBL1") == 0, "and carry its evidence: %s", e ? e : "(null)");
        }
        we_map_close(&m);
    }

    /* The meta array: an attacker-chosen offset that used to be dereferenced unchecked. */
    total = craft_base(buf); h->v4_meta_off = 0x40000000u;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS,
          "a 1 GiB v4_meta_off must be refused at LOAD, not dereferenced later");
    CHECK(in_child(tmppath("c.snap"), child_evidence) == 70,
          "and the file must not even open, let alone fault");

    total = craft_base(buf); h->v4_meta_off = (uint32_t)(total - 3u);
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS,
          "a meta array running one byte past the file must be refused");

    total = craft_base(buf); h->v4_meta_off = 193u;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS,
          "an unaligned v4_meta_off must be refused: meta[i] is a native uint32 load");

    total = craft_base(buf); h->v4_meta_off = 0u;
    write_crafted(tmppath("c.snap"), buf, total);
    rc = we_map_open(tmppath("c.snap"), &m);
    CHECK(rc == WE_OK, "meta_off 0 means absent, which is legal: %s", we_strerror(rc));
    if (rc == WE_OK) {
        CHECK(we_evidence4(&m, 0x0a000005u) == NULL, "and yields no evidence rather than faulting");
        we_map_close(&m);
    }

    /* The blob: refused, not quietly disabled. */
    total = craft_base(buf); h->blob_off = 0xfffffff0u; h->blob_len = 64u;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS,
          "blob_len > 0 with an out-of-file blob_off must be REFUSED, not ignored");

    /* Overlapping regions: the digest must not be the only thing between a crafted header and a
     * verdict read out of the header itself. */
    total = craft_base(buf); h->v4_end_off = h->v4_start_off;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS, "aliased start/end arrays refused");

    total = craft_base(buf); h->v4_sev_off = 40u;    /* the `tier` field */
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS,
          "a severity array inside the HEADER refused");

    total = craft_base(buf); h->v4_start_off = 100u;  /* inside the header */
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS, "a range array inside the header refused");

    /* Count overflow: v4_count * 4 and v6_count * 16 must not wrap. */
    total = craft_base(buf); h->v4_count = 0x40000000u;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS, "a count whose *4 wraps 32 bits refused");
    total = craft_base(buf); h->v4_count = 0xffffffffu;
    write_crafted(tmppath("c.snap"), buf, total);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_OFFSETS, "an all-ones count refused");

    /* A header-only file must load and allow everything, never fault. */
    memset(buf, 0, CRAFT_CAP);
    h->magic = WE_MAGIC; h->format = WE_FORMAT; h->generation = 1; h->file_len = sizeof(we_header_t);
    write_crafted(tmppath("c.snap"), buf, sizeof(we_header_t));
    rc = we_map_open(tmppath("c.snap"), &m);
    CHECK(rc == WE_OK, "a header-only snapshot is legal and empty: %s", we_strerror(rc));
    if (rc == WE_OK) {
        uint8_t a6[16];
        memset(a6, 0x42, 16);
        CHECK(we_lookup4(&m, 0x08080808u) == WE_SEV_NONE, "and allows every v4 address");
        CHECK(we_lookup6(&m, a6) == WE_SEV_NONE, "and every v6 address");
        CHECK(we_evidence4(&m, 0x08080808u) == NULL, "and has no evidence");
        we_map_close(&m);
    }
}

static void test_blob_must_terminate_inside_the_file(void)
{
    uint8_t buf[CRAFT_CAP];
    we_header_t *h = (we_header_t *)buf;
    we_map_t m;
    size_t total;
    size_t blob;

    SECTION("the evidence blob must be a C string that ends inside the buffer");

    /*
     * The subtler of the two memory findings, and the one that needed no invalid offset at all.
     *
     * we_evidence4 bounds its offset against blob_len, which keeps the POINTER inside the blob and
     * says nothing about a NUL following it - and the caller then does strlen, strcmp, printf("%s").
     * A blob of all non-zero bytes passes every structural check and hands back a string that runs off
     * the end. Reproduced before the fix: strlen read 3,845 bytes out of a 3,839-byte remainder, and
     * with a guaranteed unmapped page after the buffer, SIGSEGV.
     *
     * The fix is one byte: the loader requires the blob's LAST byte to be NUL, which makes every
     * in-blob offset terminate by construction.
     */
    total = craft_base(buf);
    blob = 512;
    h->blob_off = (uint32_t)blob;
    h->blob_len = 1024u;
    h->file_len = (uint32_t)(blob + 1024u);
    memset(buf + blob, 'A', 1024);                      /* no NUL anywhere */
    { uint32_t v = 1u; memcpy(buf + 200, &v, 4); }
    write_crafted(tmppath("c-noterm.snap"), buf, blob + 1024u);
    CHECK(we_map_open(tmppath("c-noterm.snap"), &m) == WE_ERR_OFFSETS,
          "a blob with no terminator must be refused at load");
    CHECK(in_child(tmppath("c-noterm.snap"), child_evidence) == 70,
          "so no caller can ever strlen off the end of it");

    /* And the legal shape still works: the last byte is NUL. */
    total = craft_base(buf);
    blob = 512;
    h->blob_off = (uint32_t)blob;
    h->blob_len = 16u;
    h->file_len = (uint32_t)(blob + 16u);
    memset(buf + blob, 0, 16);
    memcpy(buf + blob + 1, "SBL9", 4);
    { uint32_t v = 1u; memcpy(buf + 200, &v, 4); }
    write_crafted(tmppath("c-term.snap"), buf, blob + 16u);
    {
        int rc = we_map_open(tmppath("c-term.snap"), &m);
        CHECK(rc == WE_OK, "a terminated blob loads: %s", we_strerror(rc));
        if (rc == WE_OK) {
            const char *e = we_evidence4(&m, 0x0a000005u);
            CHECK(e != NULL && strcmp(e, "SBL9") == 0, "evidence: %s", e ? e : "(null)");
            we_map_close(&m);
        }
    }
    (void) total;
}

static void test_in_place_rewrite_under_a_live_snapshot(void)
{
    uint8_t buf[CRAFT_CAP];
    size_t total;
    int rc;

    SECTION("the snapshot file rewritten IN PLACE under a live reader");

    /*
     * The chaos criterion this file holds itself to: truncate the file, and traffic must keep flowing in
     * every case. Every other
     * truncation test in this file truncates BEFORE the open, so none of them covered the case that
     * actually happens.
     *
     * When this was an mmap, a read-only MAP_PRIVATE page stayed shared with the page cache and
     * truncating the file invalidated it even when resident: the next lookup died of SIGBUS, inside a
     * request, in somebody else's worker. Reproduced with signal 7. Every command an operator reaches
     * for to refresh a file truncates in place.
     *
     * The loader now reads into an owned buffer, so this is structurally impossible rather than
     * merely unlikely - and that is what this test pins. If anyone ever switches it back to mmap to
     * reclaim the page sharing, this fails.
     */
    total = craft_base(buf);
    write_crafted(tmppath("c-live.snap"), buf, total);
    rc = in_child(tmppath("c-live.snap"), child_truncate_under_live_snapshot);
    CHECK(rc >= 0, "the reader must not die of a signal; got signal %d", -rc);
    CHECK(rc == 0, "and must still answer correctly after the file was truncated (exit %d)", rc);
}

/* =================== the tests =================== */

static void test_sha256(void)
{
    uint8_t o[32];
    char got[65];
    int i;
    struct { const char *in; const char *want; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };

    SECTION("sha256 (FIPS 180-4 vectors)");
    for (i = 0; i < 3; i++) {
        int j;
        we_sha256(v[i].in, strlen(v[i].in), o);
        for (j = 0; j < 32; j++) { sprintf(got + j * 2, "%02x", o[j]); }
        CHECK(strcmp(got, v[i].want) == 0, "vector %d: got %s want %s", i, got, v[i].want);
    }
    /* streaming in arbitrary chunks must equal one-shot: the loader relies on this */
    {
        uint8_t big[5000], a[32], b[32];
        we_sha256_ctx c;
        size_t pos = 0;
        for (pos = 0; pos < sizeof big; pos++) { big[pos] = (uint8_t)(pos * 31u); }
        we_sha256(big, sizeof big, a);
        we_sha256_init(&c);
        pos = 0;
        while (pos < sizeof big) {
            size_t take = 1u + (rnd32() % 200u);
            if (pos + take > sizeof big) { take = sizeof big - pos; }
            we_sha256_update(&c, big + pos, take);
            pos += take;
        }
        we_sha256_final(&c, b);
        CHECK(memcmp(a, b, 32) == 0, "streamed digest differs from one-shot");
    }
    printf("  header is %zu bytes\n", sizeof(we_header_t));
    CHECK(sizeof(we_header_t) == 192, "header size %zu", sizeof(we_header_t));
}

/* The core correctness test, run for both index modes. */
static void test_lookup_against_oracle(int with_index, int trials)
{
    int t;

    SECTION(with_index ? "lookup vs oracle, WITH bucket index" : "lookup vs oracle, no index");
    for (t = 0; t < trials; t++) {
        pfx_t p[40];
        rng_t r[512];
        int n = 1 + (int)(rnd32() % 40u), nr, i;
        we_map_t m;
        int rc;

        for (i = 0; i < n; i++) {
            p[i].len = (uint8_t)(rnd32() % 33u);
            p[i].addr = rnd32();
            p[i].sev = (uint8_t)(1u + (rnd32() % 4u));
            if (rnd32() % 4u == 0u) { p[i].sev |= WE_F_INFERRED; }
        }
        nr = resolve(p, n, r, 512);
        if (nr < 0) { continue; }
        if (nr == 0) { continue; }

        CHECK(write_snapshot(tmppath("t.snap"), r, (uint32_t)nr, NULL, 0, with_index,
                             (uint64_t)t + 1u, 0, NULL, 0, NULL) == 0, "write failed");
        rc = we_map_open(tmppath("t.snap"), &m);
        CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
        if (rc != WE_OK) { continue; }

        /* every boundary, and one either side of it: where an off-by-one lives */
        for (i = 0; i < nr; i++) {
            uint32_t pts[4];
            int k;
            pts[0] = r[i].start; pts[1] = r[i].end;
            pts[2] = (r[i].start > 0u) ? r[i].start - 1u : 0u;
            pts[3] = (r[i].end < 0xffffffffu) ? r[i].end + 1u : 0xffffffffu;
            for (k = 0; k < 4; k++) {
                uint8_t want = oracle(p, n, pts[k]);
                uint8_t got = we_lookup4(&m, pts[k]);
                CHECK(got == want, "trial %d addr %u.%u.%u.%u: got 0x%02x want 0x%02x",
                      t, pts[k] >> 24, (pts[k] >> 16) & 255, (pts[k] >> 8) & 255, pts[k] & 255, got, want);
            }
        }
        for (i = 0; i < 4000; i++) {
            uint32_t a = rnd32();
            uint8_t want = oracle(p, n, a), got = we_lookup4(&m, a);
            CHECK(got == want, "trial %d random %u: got 0x%02x want 0x%02x", t, a, got, want);
        }
        we_map_close(&m);
    }
}

/* The spanning case the index arithmetic is built around, stated explicitly rather than left to
 * random chance: a /8 covers 256 buckets, so 255 of them contain no range start at all. */
static void test_spanning_prefix(void)
{
    pfx_t p[2];
    rng_t r[16];
    int nr, i, mode;

    SECTION("a /8 spanning 256 index buckets, with a /24 punched out of it");
    p[0].addr = 0x0a000000u; p[0].len = 8;  p[0].sev = WE_SEV_LOW;
    p[1].addr = 0x0a7f3f00u; p[1].len = 24; p[1].sev = WE_SEV_CRITICAL;
    nr = resolve(p, 2, r, 16);
    printf("  10.0.0.0/8 + 10.127.63.0/24 resolve to %d disjoint ranges\n", nr);
    CHECK(nr == 3, "expected 3 ranges, got %d", nr);

    for (mode = 0; mode < 2; mode++) {
        we_map_t m;
        int rc;
        CHECK(write_snapshot(tmppath("span.snap"), r, (uint32_t)nr, NULL, 0, mode, 1, 0, NULL, 0, NULL) == 0, "write");
        rc = we_map_open(tmppath("span.snap"), &m);
        CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
        if (rc != WE_OK) { continue; }
        /* probe one address in every one of the 256 buckets the /8 spans */
        for (i = 0; i < 256; i++) {
            uint32_t a = 0x0a000000u | ((uint32_t)i << 16) | 0x1234u;
            uint8_t want = oracle(p, 2, a), got = we_lookup4(&m, a);
            CHECK(got == want, "index=%d bucket 10.%d.x: got 0x%02x want 0x%02x", mode, i, got, want);
        }
        CHECK(we_lookup4(&m, 0x0a7f3f05u) == WE_SEV_CRITICAL, "index=%d the punched /24 must be CRITICAL", mode);
        CHECK(we_lookup4(&m, 0x0a7f3e05u) == WE_SEV_LOW, "index=%d just below the /24 must be LOW", mode);
        CHECK(we_lookup4(&m, 0x0a7f4005u) == WE_SEV_LOW, "index=%d just above the /24 must be LOW", mode);
        CHECK(we_lookup4(&m, 0x09ffffffu) == WE_SEV_NONE, "index=%d just below the /8 must be NONE", mode);
        CHECK(we_lookup4(&m, 0x0b000000u) == WE_SEV_NONE, "index=%d just above the /8 must be NONE", mode);
        we_map_close(&m);
    }
}

static void test_edges(void)
{
    rng_t r[3];
    we_map_t m;
    int rc;

    SECTION("address-space edges: 0.0.0.0 and 255.255.255.255");
    r[0].start = 0u;          r[0].end = 0u;          r[0].sev = WE_SEV_HIGH;
    r[1].start = 0x80000000u; r[1].end = 0x80000000u; r[1].sev = WE_SEV_MEDIUM;
    r[2].start = 0xffffffffu; r[2].end = 0xffffffffu; r[2].sev = WE_SEV_CRITICAL;
    CHECK(write_snapshot(tmppath("edge.snap"), r, 3, NULL, 0, 1, 1, 0, NULL, 0, NULL) == 0, "write");
    rc = we_map_open(tmppath("edge.snap"), &m);
    CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
    if (rc == WE_OK) {
        CHECK(we_lookup4(&m, 0u) == WE_SEV_HIGH, "0.0.0.0");
        CHECK(we_lookup4(&m, 1u) == WE_SEV_NONE, "0.0.0.1");
        CHECK(we_lookup4(&m, 0xffffffffu) == WE_SEV_CRITICAL, "255.255.255.255");
        CHECK(we_lookup4(&m, 0xfffffffeu) == WE_SEV_NONE, "255.255.255.254");
        CHECK(we_lookup4(&m, 0x7fffffffu) == WE_SEV_NONE, "below the middle entry");
        CHECK(we_lookup4(&m, 0x80000001u) == WE_SEV_NONE, "above the middle entry");
        we_map_close(&m);
    }
}

static void test_v6(void)
{
    rng6_t r[2];
    we_map_t m;
    int rc;
    uint8_t a[16];

    SECTION("IPv6 ranges");
    memset(&r, 0, sizeof r);
    /*
     * BOTH RANGES ARE DOCUMENTATION SPACE, and that is not a detail. This file ships in a public
     * repository, so a real prefix compiled into an assertion here is a permanent, unexpiring public
     * claim that somebody's network is criminal - the standard testdata/README.md and rpz-gate.sh both
     * state, and which the binary fixtures were corrected to meet.
     *
     * These two lines used to be 2a04:2a01::/32, which is OUR OWN live agent egress prefix carrying
     * customer traffic, asserted at WE_SEV_HIGH, and 2620::, which is allocated ARIN space, asserted
     * at WE_SEV_CRITICAL. Neither belonged here.
     *
     * 2001:db8::/32 is RFC 3849 and 3fff::/20 is RFC 9637, so there are now two reserved documentation
     * blocks to draw a disjoint pair from, which is what this test needs.
     *
     * Already in sorted order, which the format requires, so there is no swap: 2001:db8 < 3fff.
     */
    /* 2001:db8::/32 - RFC 3849 documentation space */
    r[0].start.a[0] = 0x20; r[0].start.a[1] = 0x01; r[0].start.a[2] = 0x0d; r[0].start.a[3] = 0xb8;
    memcpy(&r[0].end, &r[0].start, sizeof r[0].start);
    { int i; for (i = 4; i < 16; i++) { r[0].end.a[i] = 0xff; } }
    r[0].sev = WE_SEV_HIGH;
    /* 3fff:: single address - RFC 9637 documentation space, strictly above the range above */
    r[1].start.a[0] = 0x3f; r[1].start.a[1] = 0xff;
    memcpy(&r[1].end, &r[1].start, sizeof r[1].start);
    r[1].sev = WE_SEV_CRITICAL;

    CHECK(write_snapshot(tmppath("v6.snap"), NULL, 0, r, 2, 0, 1, 0, NULL, 0, NULL) == 0, "write");
    rc = we_map_open(tmppath("v6.snap"), &m);
    CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
    if (rc == WE_OK) {
        memset(a, 0, 16); a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[15] = 0x99;
        CHECK(we_lookup6(&m, a) == WE_SEV_HIGH, "inside 2001:db8::/32");
        a[3] = 0xb9;
        CHECK(we_lookup6(&m, a) == WE_SEV_NONE, "2001:db9:: is outside");
        memset(a, 0, 16); a[0] = 0x3f; a[1] = 0xff;
        CHECK(we_lookup6(&m, a) == WE_SEV_CRITICAL, "the exact 3fff:: address");
        a[15] = 1;
        CHECK(we_lookup6(&m, a) == WE_SEV_NONE, "3fff::1 is outside the single-address range");
        memset(a, 0xff, 16);
        CHECK(we_lookup6(&m, a) == WE_SEV_NONE, "all-ones v6");
        memset(a, 0, 16);
        CHECK(we_lookup6(&m, a) == WE_SEV_NONE, ":: is below everything");
        we_map_close(&m);
    }
}

static void test_fail_open(void)
{
    we_map_t empty;
    uint8_t a[16];

    SECTION("fail open: the invariant that must hold with no data at all");
    memset(&empty, 0, sizeof empty);
    memset(a, 0x42, 16);
    CHECK(we_lookup4(NULL, 0x08080808u) == WE_SEV_NONE, "NULL map allows");
    CHECK(we_lookup6(NULL, a) == WE_SEV_NONE, "NULL map allows v6");
    CHECK(we_lookup4(&empty, 0x08080808u) == WE_SEV_NONE, "zero-count map allows");
    CHECK(we_lookup6(&empty, a) == WE_SEV_NONE, "zero-count map allows v6");
    CHECK(we_current(NULL) == NULL, "NULL handle has no mapping");
    CHECK(we_lookup4(we_current(NULL), 0x08080808u) == WE_SEV_NONE, "NULL handle allows");
    CHECK(we_is_stale(NULL, 0) == 1, "a NULL mapping counts as stale");
}

static void test_policy(void)
{
    SECTION("deny policy: threshold and the inference rule");
    CHECK(we_should_deny(WE_SEV_NONE, WE_SEV_HIGH, 1) == 0, "no verdict never denies");
    CHECK(we_should_deny(WE_SEV_CRITICAL, 0, 1) == 0, "threshold 0 denies nothing");
    CHECK(we_should_deny(WE_SEV_HIGH, WE_SEV_HIGH, 0) == 1, "HIGH meets a HIGH threshold");
    CHECK(we_should_deny(WE_SEV_CRITICAL, WE_SEV_HIGH, 0) == 1, "CRITICAL exceeds a HIGH threshold");
    CHECK(we_should_deny(WE_SEV_MEDIUM, WE_SEV_HIGH, 0) == 0, "MEDIUM is below a HIGH threshold");
    CHECK(we_should_deny(WE_SEV_CRITICAL | WE_F_INFERRED, WE_SEV_LOW, 0) == 0,
          "an INFERRED verdict must not deny without an explicit opt-in");
    CHECK(we_should_deny(WE_SEV_CRITICAL | WE_F_INFERRED, WE_SEV_LOW, 1) == 1,
          "an INFERRED verdict denies once opted in");
    CHECK(we_should_deny(WE_SEV_HIGH | WE_F_DROP, WE_SEV_HIGH, 0) == 1,
          "the DROP flag does not interfere with the severity comparison");
}

static void test_staleness(void)
{
    rng_t r[1];
    we_map_t m;
    int rc;

    SECTION("staleness: the bound travels in the file");
    r[0].start = 0x08080808u; r[0].end = 0x08080808u; r[0].sev = WE_SEV_CRITICAL;
    CHECK(write_snapshot(tmppath("stale.snap"), r, 1, NULL, 0, 0, 1, 5000ull, NULL, 0, NULL) == 0, "write");
    rc = we_map_open(tmppath("stale.snap"), &m);
    CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
    if (rc == WE_OK) {
        CHECK(we_is_stale(&m, 4999ull) == 0, "before the bound");
        CHECK(we_is_stale(&m, 5000ull) == 0, "exactly at the bound is still valid");
        CHECK(we_is_stale(&m, 5001ull) == 1, "past the bound is stale");
        we_map_close(&m);
    }
    CHECK(write_snapshot(tmppath("nostale.snap"), r, 1, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
    rc = we_map_open(tmppath("nostale.snap"), &m);
    if (rc == WE_OK) {
        CHECK(we_is_stale(&m, 0xffffffffffffffffull) == 0, "valid_until 0 means no bound");
        we_map_close(&m);
    }
}

/* ---- chaos: every way a snapshot can be wrong must be REFUSED, and refusal must not deny ---- */
static void corrupt(const char *src, const char *dst, size_t at, uint8_t xorval, long truncate_to)
{
    FILE *in = fopen(src, "rb"), *out;
    uint8_t *b;
    size_t n;
    struct stat st;

    stat(src, &st);
    b = (uint8_t *)malloc((size_t)st.st_size);
    n = fread(b, 1, (size_t)st.st_size, in);
    fclose(in);
    if (at < n) { b[at] ^= xorval; }
    if (truncate_to >= 0 && (size_t)truncate_to < n) { n = (size_t)truncate_to; }
    out = fopen(dst, "wb");
    fwrite(b, 1, n, out);
    fclose(out);
    free(b);
    if (chmod(dst, 0644) != 0) { CHECK(0, "cannot chmod %s", dst); }
}

static void test_chaos(void)
{
    rng_t r[64];
    pfx_t p[8];
    int nr, i;
    we_map_t m;
    int rc;
    we_handle_t h;
    const we_map_t *live;

    SECTION("chaos: corrupt, truncate, lie, overlap, invert. Every one must be refused");

    for (i = 0; i < 8; i++) {
        p[i].addr = rnd32(); p[i].len = (uint8_t)(8u + (rnd32() % 20u)); p[i].sev = WE_SEV_HIGH;
    }
    nr = resolve(p, 8, r, 64);
    CHECK(nr > 0, "fixture resolved to %d ranges", nr);
    CHECK(write_snapshot(tmppath("good.snap"), r, (uint32_t)nr, NULL, 0, 1, 7, 0, NULL, 0, NULL) == 0, "write");

    rc = we_map_open(tmppath("good.snap"), &m);
    CHECK(rc == WE_OK, "the baseline must load: %s", we_strerror(rc));
    if (rc == WE_OK) { we_map_close(&m); }

    /* a missing file */
    CHECK(we_map_open(tmppath("does-not-exist.snap"), &m) == WE_ERR_OPEN, "missing file refused");
    /* a directory, not a regular file */
    CHECK(we_map_open(TMPDIR_, &m) == WE_ERR_OPEN, "a directory refused");
    /*
     * A FIFO named like a snapshot: open() on it waits for a writer, so a loader that opens before it
     * checks the type hangs the reload. The alarm turns a hang into a killed test, never a silent pass.
     */
    {
        we_load_detail_t det;
        const char *why = NULL;
        int fd, fl;

        unlink(tmppath("fifo.snap"));
        unlink(tmppath("null.snap"));
        CHECK(mkfifo(tmppath("fifo.snap"), 0644) == 0, "mkfifo");
        CHECK(symlink("/dev/null", tmppath("null.snap")) == 0, "symlink to /dev/null");
        alarm(10);
        CHECK(we_map_open(tmppath("fifo.snap"), &m) == WE_ERR_OPEN, "a FIFO refused, without blocking");
        CHECK(we_plane_open(tmppath("fifo.snap"), &m, &det) == WE_ERR_OPEN && det.what != NULL
              && strcmp(det.what, "not a regular file") == 0, "a FIFO plane: refused as \"not a regular file\" (%s)",
              det.what != NULL ? det.what : "-");
        CHECK(we_plane_open(tmppath("null.snap"), &m, &det) == WE_ERR_OPEN && det.what != NULL
              && strcmp(det.what, "not a regular file") == 0, "a symlink to a device: refused as not regular");
        CHECK(we_open_regular(tmppath("fifo.snap"), &why) == -1 && why != NULL
              && strcmp(why, "not a regular file") == 0, "we_open_regular refuses the FIFO by name");
        why = NULL;
        CHECK(we_open_regular(tmppath("does-not-exist.snap"), &why) == -1 && why != NULL
              && strcmp(why, "cannot open") == 0, "an absent path reads \"cannot open\"");
        alarm(0);
        /* the control: a regular file opens, and its descriptor is blocking again */
        fd = we_open_regular(tmppath("good.snap"), &why);
        fl = fd >= 0 ? fcntl(fd, F_GETFL) : -1;
        CHECK(fd >= 0 && fl >= 0 && (fl & O_NONBLOCK) == 0, "a regular file opens, O_NONBLOCK cleared");
        if (fd >= 0) {
            close(fd);
        }
        unlink(tmppath("fifo.snap"));
        unlink(tmppath("null.snap"));
    }
    /* empty */
    { FILE *f = fopen(tmppath("empty.snap"), "wb"); fclose(f);
      if (chmod(tmppath("empty.snap"), 0644) != 0) { CHECK(0, "chmod"); } }
    CHECK(we_map_open(tmppath("empty.snap"), &m) == WE_ERR_TOO_SMALL, "empty file refused");
    /* magic */
    corrupt(tmppath("good.snap"), tmppath("c.snap"), 0, 0xff, -1);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_MAGIC, "bad magic refused");
    /* format version */
    corrupt(tmppath("good.snap"), tmppath("c.snap"), 8, 0x02, -1);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_FORMAT, "unknown format refused");
    /* truncation: the single most likely real-world corruption */
    {
        struct stat st;
        stat(tmppath("good.snap"), &st);
        corrupt(tmppath("good.snap"), tmppath("c.snap"), 0, 0, (long)st.st_size - 1);
        CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_TRUNCATED, "truncated by one byte refused");
        corrupt(tmppath("good.snap"), tmppath("c.snap"), 0, 0, (long)sizeof(we_header_t));
        CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_TRUNCATED, "header-only file refused");
        corrupt(tmppath("good.snap"), tmppath("c.snap"), 0, 0, 7);
        CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_TOO_SMALL, "7-byte file refused");
    }
    /* a flipped bit anywhere in the body must be caught by the digest */
    {
        struct stat st;
        size_t at;
        int caught = 0, tried = 0;
        stat(tmppath("good.snap"), &st);
        for (at = sizeof(we_header_t); at < (size_t)st.st_size; at += 37u) {
            corrupt(tmppath("good.snap"), tmppath("c.snap"), at, 0x01, -1);
            tried++;
            if (we_map_open(tmppath("c.snap"), &m) != WE_OK) { caught++; } else { we_map_close(&m); }
        }
        CHECK(caught == tried, "%d of %d single-bit body flips caught", caught, tried);
        printf("  %d single-bit flips across the body, all refused\n", tried);
    }
    /* a flipped bit in the digest itself */
    CHECK(we_map_open(tmppath("c.snap"), &m) != WE_OK, "sanity");
    corrupt(tmppath("good.snap"), tmppath("c.snap"), 104, 0x01, -1);
    CHECK(we_map_open(tmppath("c.snap"), &m) == WE_ERR_DIGEST, "a flipped digest byte refused");

    /* structurally invalid snapshots, each written with a VALID digest so only the structure check
     * can catch them. This is the part a digest cannot do for us. */
    {
        rng_t bad[3];
        /* inverted: start > end */
        bad[0].start = 100u; bad[0].end = 50u; bad[0].sev = WE_SEV_HIGH;
        CHECK(write_snapshot(tmppath("inv.snap"), bad, 1, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
        CHECK(we_map_open(tmppath("inv.snap"), &m) == WE_ERR_UNSORTED, "an inverted range refused");
        /* overlapping */
        bad[0].start = 100u; bad[0].end = 200u; bad[0].sev = WE_SEV_HIGH;
        bad[1].start = 150u; bad[1].end = 300u; bad[1].sev = WE_SEV_LOW;
        CHECK(write_snapshot(tmppath("ov.snap"), bad, 2, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
        CHECK(we_map_open(tmppath("ov.snap"), &m) == WE_ERR_OVERLAP, "overlapping ranges refused");
        /* out of order */
        bad[0].start = 300u; bad[0].end = 400u; bad[0].sev = WE_SEV_HIGH;
        bad[1].start = 100u; bad[1].end = 200u; bad[1].sev = WE_SEV_LOW;
        CHECK(write_snapshot(tmppath("uo.snap"), bad, 2, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
        CHECK(we_map_open(tmppath("uo.snap"), &m) == WE_ERR_OVERLAP, "out-of-order ranges refused");
        /* touching but not overlapping is LEGAL and must load */
        bad[0].start = 100u; bad[0].end = 200u; bad[0].sev = WE_SEV_HIGH;
        bad[1].start = 201u; bad[1].end = 300u; bad[1].sev = WE_SEV_LOW;
        CHECK(write_snapshot(tmppath("touch.snap"), bad, 2, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
        rc = we_map_open(tmppath("touch.snap"), &m);
        CHECK(rc == WE_OK, "adjacent ranges must load: %s", we_strerror(rc));
        if (rc == WE_OK) {
            CHECK(we_lookup4(&m, 200u) == WE_SEV_HIGH, "last address of the first range");
            CHECK(we_lookup4(&m, 201u) == WE_SEV_LOW, "first address of the second");
            we_map_close(&m);
        }
    }
    /* a corrupted bucket index with an otherwise valid file: the index must be checked against the
     * ranges, not trusted, or the hot path searches the wrong window and answers wrongly. */
    {
        struct stat st;
        we_header_t hh;
        FILE *f = fopen(tmppath("good.snap"), "rb");
        uint8_t *b;
        uint32_t *idx;
        uint8_t dig[32];
        we_sha256_ctx ctx;
        we_header_t bare;
        int refused = 0, n = 0;
        size_t k;

        stat(tmppath("good.snap"), &st);
        b = (uint8_t *)malloc((size_t)st.st_size);
        if (fread(b, 1, (size_t)st.st_size, f) != (size_t)st.st_size) { CHECK(0, "read"); }
        fclose(f);
        memcpy(&hh, b, sizeof hh);
        idx = (uint32_t *)(b + hh.v4_index_off);
        for (k = 0; k < 6; k++) {
            uint32_t slot = (uint32_t)(k * 9973u) % 65537u;
            uint32_t saved = idx[slot];
            FILE *o;
            idx[slot] = (uint32_t)(saved + 7u);          /* break monotonicity or the boundary */
            memcpy(&bare, b, sizeof bare);
            memset(bare.digest, 0, 32);
            we_sha256_init(&ctx);
            we_sha256_update(&ctx, &bare, sizeof bare);
            we_sha256_update(&ctx, b + sizeof bare, (size_t)st.st_size - sizeof bare);
            we_sha256_final(&ctx, dig);
            memcpy(b + 104, dig, 32);                    /* re-sign, so only the structure check can catch it */
            o = fopen(tmppath("badidx.snap"), "wb");
            fwrite(b, 1, (size_t)st.st_size, o);
            fclose(o);
            if (chmod(tmppath("badidx.snap"), 0644) != 0) { CHECK(0, "chmod"); }
            n++;
            if (we_map_open(tmppath("badidx.snap"), &m) != WE_OK) { refused++; } else { we_map_close(&m); }
            idx[slot] = saved;
        }
        CHECK(refused == n, "%d of %d tampered-and-resigned indexes refused", refused, n);
        printf("  %d re-signed index tamperings, all refused by the structure check\n", n);
        free(b);
    }

    /* the same tampering against the v6 index, since it has its own validator */
    {
        rng6_t r6[4];
        we_header_t hh;
        struct stat st;
        FILE *f;
        uint8_t *b;
        int refused = 0, ntry = 0;
        size_t k;

        memset(r6, 0, sizeof r6);
        for (k = 0; k < 4; k++) {
            r6[k].start.a[0] = 0x20; r6[k].start.a[1] = (uint8_t)(0x01u + k * 3u);
            memcpy(&r6[k].end, &r6[k].start, sizeof r6[k].start);
            r6[k].end.a[15] = 0xff;
            r6[k].sev = WE_SEV_HIGH;
        }
        CHECK(write_snapshot(tmppath("g6.snap"), NULL, 0, r6, 4, 1, 1, 0, NULL, 0, NULL) == 0, "write v6");
        rc = we_map_open(tmppath("g6.snap"), &m);
        CHECK(rc == WE_OK, "the indexed v6 baseline must load: %s", we_strerror(rc));
        if (rc == WE_OK) {
            uint8_t a[16];
            memset(a, 0, 16); a[0] = 0x20; a[1] = 0x04; a[15] = 0x07;
            CHECK(we_lookup6(&m, a) == WE_SEV_HIGH, "indexed v6 answers inside a range");
            memset(a, 0, 16); a[0] = 0x20; a[1] = 0x02;
            CHECK(we_lookup6(&m, a) == WE_SEV_NONE, "indexed v6 allows outside every range");
            we_map_close(&m);
        }
        stat(tmppath("g6.snap"), &st);
        f = fopen(tmppath("g6.snap"), "rb");
        b = (uint8_t *)malloc((size_t)st.st_size);
        if (fread(b, 1, (size_t)st.st_size, f) != (size_t)st.st_size) { CHECK(0, "read v6"); }
        fclose(f);
        memcpy(&hh, b, sizeof hh);
        CHECK(hh.v6_index_off != 0u, "the v6 index was emitted");
        for (k = 0; k < 5; k++) {
            uint32_t *idx = (uint32_t *)(b + hh.v6_index_off);
            uint32_t slot = (uint32_t)(0x2001u + k * 1013u) % 65537u;
            uint32_t saved = idx[slot];
            we_sha256_ctx ctx;
            we_header_t bare;
            uint8_t dig[32];
            FILE *o;

            idx[slot] = saved + 3u;
            memcpy(&bare, b, sizeof bare);
            memset(bare.digest, 0, 32);
            we_sha256_init(&ctx);
            we_sha256_update(&ctx, &bare, sizeof bare);
            we_sha256_update(&ctx, b + sizeof bare, (size_t)st.st_size - sizeof bare);
            we_sha256_final(&ctx, dig);
            memcpy(b + 104, dig, 32);
            o = fopen(tmppath("bad6.snap"), "wb");
            fwrite(b, 1, (size_t)st.st_size, o);
            fclose(o);
            if (chmod(tmppath("bad6.snap"), 0644) != 0) { CHECK(0, "chmod"); }
            ntry++;
            if (we_map_open(tmppath("bad6.snap"), &m) != WE_OK) { refused++; } else { we_map_close(&m); }
            idx[slot] = saved;
        }
        CHECK(refused == ntry, "%d of %d tampered v6 indexes refused", refused, ntry);
        printf("  %d re-signed v6 index tamperings, all refused\n", ntry);
        free(b);
    }

    /*
     * A tamper the SHAPE check cannot see, so the boundary check is proved load-bearing.
     *
     * Adding to one index slot usually breaks monotonicity or the sentinel, and check_index_shape()
     * catches that on its own - which means those cases prove nothing about the boundary rule. Here we
     * set idx[b] = idx[b+1] at a bucket where a range starts. Still monotone, still 0 at the front and
     * still count at the end, so the shape check is satisfied; but the lookup's window for bucket b now
     * EXCLUDES a range that starts in it, which is precisely a wrong answer on live traffic. Only the
     * "entries before idx[b] start below the bucket, the entry at idx[b] does not" check can refuse it.
     */
    {
        struct stat st;
        we_header_t hh;
        FILE *f;
        uint8_t *b;
        int refused = 0, ntry = 0;
        uint32_t bb;

        stat(tmppath("good.snap"), &st);
        f = fopen(tmppath("good.snap"), "rb");
        b = (uint8_t *)malloc((size_t)st.st_size);
        if (fread(b, 1, (size_t)st.st_size, f) != (size_t)st.st_size) { CHECK(0, "read"); }
        fclose(f);
        memcpy(&hh, b, sizeof hh);
        for (bb = 1; bb < 65536u && ntry < 6; bb++) {
            uint32_t *idx = (uint32_t *)(b + hh.v4_index_off);
            uint32_t saved;
            we_sha256_ctx ctx;
            we_header_t bare;
            uint8_t dig[32];
            FILE *o;
            int shape_ok;

            if (idx[bb] == idx[bb + 1]) { continue; }   /* no range starts in this bucket */
            saved = idx[bb];
            idx[bb] = idx[bb + 1];
            /* confirm the shape rules still hold, so this really is invisible to that check */
            shape_ok = (idx[0] == 0u) && (idx[65536] == hh.v4_count) &&
                       (idx[bb] >= idx[bb - 1]) && (idx[bb + 1] >= idx[bb]);
            CHECK(shape_ok, "the tamper at bucket %u must stay shape-valid", bb);

            memcpy(&bare, b, sizeof bare);
            memset(bare.digest, 0, 32);
            we_sha256_init(&ctx);
            we_sha256_update(&ctx, &bare, sizeof bare);
            we_sha256_update(&ctx, b + sizeof bare, (size_t)st.st_size - sizeof bare);
            we_sha256_final(&ctx, dig);
            memcpy(b + 104, dig, 32);
            o = fopen(tmppath("shifted.snap"), "wb");
            fwrite(b, 1, (size_t)st.st_size, o);
            fclose(o);
            if (chmod(tmppath("shifted.snap"), 0644) != 0) { CHECK(0, "chmod"); }
            ntry++;
            if (we_map_open(tmppath("shifted.snap"), &m) != WE_OK) {
                refused++;
            } else {
                we_map_close(&m);
            }
            idx[bb] = saved;
        }
        CHECK(ntry > 0, "found a bucket to shift");
        CHECK(refused == ntry, "%d of %d SHAPE-VALID index shifts refused by the boundary check",
              refused, ntry);
        printf("  %d shape-valid index shifts (invisible to the monotonicity check), all refused\n", ntry);
        free(b);
    }

    /* The property that matters most: a failed reload leaves the PREVIOUS snapshot serving. */
    memset(&h, 0, sizeof h);
    CHECK(we_handle_publish(&h, tmppath("good.snap"), 1000ull) == WE_OK, "publish the good snapshot");
    live = we_current(&h);
    CHECK(live != NULL, "a mapping is published");
    CHECK(h.generation == 7ull, "generation is %" PRIu64, h.generation);
    {
        uint8_t before = we_lookup4(live, r[0].start);
        CHECK(before != WE_SEV_NONE, "the fixture answers before the failed reload");
        CHECK(we_handle_publish(&h, tmppath("c.snap"), 2000ull) != WE_OK, "a corrupt reload must fail");
        CHECK(we_current(&h) == live, "the published mapping must not change on a failed reload");
        CHECK(we_lookup4(we_current(&h), r[0].start) == before, "answers must be unchanged");
        CHECK(we_handle_publish(&h, tmppath("does-not-exist.snap"), 3000ull) != WE_OK, "a missing reload fails");
        CHECK(we_current(&h) == live, "still unchanged after a missing file");
        CHECK(h.loads_ok == 1 && h.loads_failed == 2, "counters: ok=%" PRIu64 " failed=%" PRIu64,
              h.loads_ok, h.loads_failed);
    }
    we_handle_retire(&h, 1000000ull);
    { we_map_t *cur = (we_map_t *)we_current(&h); we_map_close(cur); free(cur); }
}

static void test_swap_and_retire(void)
{
    rng_t r[1];
    we_handle_t h;
    const we_map_t *first;
    int i;

    SECTION("swap under a reader, and the retire grace period");
    memset(&h, 0, sizeof h);
    h.grace_ms = 1000ull;
    r[0].start = 0x01020304u; r[0].end = 0x01020304u; r[0].sev = WE_SEV_HIGH;
    CHECK(write_snapshot(tmppath("g1.snap"), r, 1, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write g1");
    CHECK(we_handle_publish(&h, tmppath("g1.snap"), 0ull) == WE_OK, "publish g1");
    first = we_current(&h);

    r[0].sev = WE_SEV_CRITICAL;
    CHECK(write_snapshot(tmppath("g2.snap"), r, 1, NULL, 0, 0, 2, 0, NULL, 0, NULL) == 0, "write g2");
    CHECK(we_handle_publish(&h, tmppath("g2.snap"), 100ull) == WE_OK, "publish g2");
    CHECK(we_current(&h) != first, "the swap published a new mapping");
    CHECK(we_lookup4(we_current(&h), 0x01020304u) == WE_SEV_CRITICAL, "the new verdict is live");
    CHECK(h.generation == 2ull, "generation advanced to %" PRIu64, h.generation);

    /* a reader that grabbed the old pointer before the swap must still get a valid answer */
    CHECK(we_lookup4(first, 0x01020304u) == WE_SEV_HIGH, "the retired mapping is still readable");
    we_handle_retire(&h, 500ull);
    CHECK(we_lookup4(first, 0x01020304u) == WE_SEV_HIGH, "still readable inside the grace period");
    CHECK(h.retired[0].map == first, "still held in a retire slot");
    we_handle_retire(&h, 1100ull);
    CHECK(h.retired[0].map == NULL, "unmapped once the grace period elapsed");
    CHECK(h.leaked == 0, "nothing leaked");

    /*
     * A rollback, or a republish of the same generation, must be REFUSED.
     *
     * Serving an older snapshot is a silent policy downgrade, and since the validity bound travels in
     * the file an old snapshot still inside its window enforces normally.
     */
    CHECK(we_handle_publish(&h, tmppath("g1.snap"), 200ull) == WE_ERR_ROLLBACK,
          "republishing generation 1 over generation 2 must be refused");
    CHECK(we_current(&h) != NULL && we_lookup4(we_current(&h), 0x01020304u) == WE_SEV_CRITICAL,
          "and the newer snapshot must still be the one serving");
    CHECK(h.rejected_rollbacks == 1, "the refusal is counted: %" PRIu64, h.rejected_rollbacks);
    CHECK(we_handle_publish(&h, tmppath("g2.snap"), 200ull) == WE_ERR_ROLLBACK,
          "republishing the SAME generation is also refused; it is the same snapshot");
    CHECK(h.rejected_rollbacks == 2, "counted again: %" PRIu64, h.rejected_rollbacks);

    /*
     * Exhausting the slots must LEAK, never free early. Each reload needs a DISTINCT, INCREASING
     * generation now that a rollback is refused, which is itself the more realistic fixture: a real
     * rebuild always advances the generation.
     */
    for (i = 0; i < WE_RETIRE_SLOTS + 3; i++) {
        char name[64];
        snprintf(name, sizeof name, "gen%d.snap", i);
        r[0].sev = WE_SEV_HIGH;
        CHECK(write_snapshot(tmppath(name), r, 1, NULL, 0, 0, (uint64_t)(100 + i), 0, NULL, 0, NULL) == 0,
              "write %s", name);
        CHECK(we_handle_publish(&h, tmppath(name), 2000ull) == WE_OK, "rapid reload %d", i);
    }
    CHECK(h.leaked == 3, "%d reloads past the slot count leaked %" PRIu64 " mappings (expected 3)",
          WE_RETIRE_SLOTS + 3, h.leaked);
    printf("  %d reloads inside one grace window: %" PRIu64 " deliberately leaked rather than freed under a reader\n",
           WE_RETIRE_SLOTS + 3, h.leaked);
    we_handle_retire(&h, 100000ull);
    { we_map_t *cur = (we_map_t *)we_current(&h); we_map_close(cur); free(cur); }
}

static void test_evidence(void)
{
    rng_t r[2];
    uint32_t meta[2];
    const char blob[] = "\0SBL698389\0SBL123456";
    we_map_t m;
    int rc;

    SECTION("evidence lookup (cold path, for the log line only)");
    r[0].start = 0x0202004bu; r[0].end = 0x0202004bu; r[0].sev = WE_SEV_CRITICAL | WE_F_DROP;
    r[1].start = 0x0a000000u; r[1].end = 0x0a0000ffu; r[1].sev = WE_SEV_HIGH;
    meta[0] = 1u;    /* offset into blob */
    meta[1] = 11u;
    CHECK(write_snapshot(tmppath("ev.snap"), r, 2, NULL, 0, 0, 1, 0, blob, (uint32_t)sizeof blob, meta) == 0, "write");
    rc = we_map_open(tmppath("ev.snap"), &m);
    CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
    if (rc == WE_OK) {
        const char *e = we_evidence4(&m, 0x0202004bu);
        CHECK(e != NULL && strcmp(e, "SBL698389") == 0, "evidence for the first range: %s", e ? e : "(null)");
        e = we_evidence4(&m, 0x0a000005u);
        CHECK(e != NULL && strcmp(e, "SBL123456") == 0, "evidence for the second: %s", e ? e : "(null)");
        CHECK(we_evidence4(&m, 0x7f000001u) == NULL, "no evidence for an address with no verdict");
        we_map_close(&m);
    }
}

/*
 * The per-range counters and the file the summary tool reads.
 *
 * Everything the summary prints comes from here, so what this asserts is what that artifact can
 * claim: that a hit lands on the RANGE the address is in, that an address in no range is counted
 * nowhere, that a counter set from a previous snapshot does not get attributed to this one's
 * networks, and that the file carries the prefix and the evidence rather than an index.
 *
 * The one that matters most is the stale-generation case. Ranges are renumbered by every build, so a
 * counter set that outlived its snapshot indexes a different network than the one the hits came
 * from - and the summary would name an innocent prefix as the worst offender in a report somebody
 * pastes into a chat. Undercounting is the only acceptable failure here.
 */
static void test_counters(void)
{
    rng_t r[2];
    uint32_t meta[2];
    const char blob[] = "\0ransomware c2, confirmed 2026-10-02\0scanner, first seen 2026-09-30";
    we_map_t m;
    we_counters_t *c;
    int rc;

    SECTION("per-range denial counters, and the summary file they produce");
    r[0].start = 0x0202004bu; r[0].end = 0x0202004bu; r[0].sev = WE_SEV_CRITICAL | WE_F_DROP;
    r[1].start = 0x0a000000u; r[1].end = 0x0a0000ffu; r[1].sev = WE_SEV_HIGH;
    meta[0] = 1u;
    meta[1] = 37u;
    CHECK(write_snapshot(tmppath("cnt.snap"), r, 2, NULL, 0, 0, 7, 0, blob,
                         (uint32_t)sizeof blob, meta) == 0, "write");
    rc = we_map_open(tmppath("cnt.snap"), &m);
    CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
    if (rc != WE_OK) {
        return;
    }

    /* The range search the counters and the evidence lookup now share. */
    CHECK(we_range4(&m, 0x0202004bu) == 0, "the single address is range 0");
    CHECK(we_range4(&m, 0x0a000005u) == 1, "an address inside the /24 is range 1");
    CHECK(we_range4(&m, 0x7f000001u) == -1, "an address in no range is -1, not 0");
    CHECK(we_range4(NULL, 0x0a000005u) == -1, "a NULL mapping is -1 rather than a crash");

    c = we_counters_new(&m, 1760000000000ull);
    CHECK(c != NULL, "counters allocated");
    if (c == NULL) {
        we_map_close(&m);
        return;
    }
    CHECK(c->denied == 0, "a fresh set has counted nothing");

    we_counters_count4(c, &m, 0x0a000005u);
    we_counters_count4(c, &m, 0x0a0000ffu);
    we_counters_count4(c, &m, 0x0202004bu);
    we_counters_count4(c, &m, 0x7f000001u);          /* in no range: counted nowhere */
    we_counters_count4(NULL, &m, 0x0a000005u);       /* a NULL set is a no-op, never a crash */

    CHECK(c->denied == 3, "three hits landed, the one in no range did not (denied=%llu)",
          (unsigned long long) c->denied);
    CHECK(c->v4_hits[1] == 2, "both /24 addresses counted against the /24 (%llu)",
          (unsigned long long) c->v4_hits[1]);
    CHECK(c->v4_hits[0] == 1, "and the single address against its own range (%llu)",
          (unsigned long long) c->v4_hits[0]);

    /* The file: prefix form, severity, count, evidence - and zero-hit ranges left out. */
    {
        char dir[512];
        char path[640];
        FILE *f;
        char line[1024];
        int saw_magic = 0, saw_24 = 0, saw_single = 0, saw_pid = 0, lines = 0;
        char pid_line[64];

        snprintf(pid_line, sizeof pid_line, "pid %ld\n", (long) getpid());

        snprintf(dir, sizeof dir, "%s", TMPDIR_);
        CHECK(we_counters_write(c, &m, dir, 1760000600000ull) == WE_OK, "counters written");
        {
            we_procid_t id;

            /* the file is named by the process, pid and identity, so a reused pid never overwrites it */
            CHECK(we_proc_id(&id) == 0, "the process identity is readable");
            snprintf(path, sizeof path, "%s/%llu-%s.cnt", dir, (unsigned long long)id.pid, id.id16);
        }
        f = fopen(path, "r");
        CHECK(f != NULL, "the file is named for the process that wrote it: %s", path);
        if (f != NULL) {
            while (fgets(line, sizeof line, f) != NULL) {
                lines++;
                if (strncmp(line, "whisper-edge-counters 1", 23) == 0) { saw_magic = 1; }
                if (strncmp(line, "pid ", 4) == 0) {
                    saw_pid = 1;
                    CHECK(strcmp(line, pid_line) == 0, "the record names the process that wrote it: %s", line);
                }
                if (strstr(line, "10.0.0.0/24") != NULL) {
                    saw_24 = 1;
                    /* The WHOLE line, not a substring of it: a `strstr(line, " 2 ")` would be
                     * satisfied by the severity, by the count, or by a digit in the evidence, and
                     * would have passed on the off-by-one blob offset this test caught. */
                    CHECK(strcmp(line, "4 10.0.0.0/24 3 2 scanner, first seen 2026-09-30\n") == 0,
                          "family, prefix, severity, count, evidence, exactly: %s", line);
                }
                if (strstr(line, "2.2.0.75/32") != NULL) { saw_single = 1; }
            }
            fclose(f);
        }
        CHECK(saw_magic, "the file says what it is on its first line");
        CHECK(saw_24, "the /24 is written as a prefix, not as an index");
        CHECK(saw_single, "a single address is written as a /32");
        CHECK(saw_pid, "the record carries a pid line, so it says whose it is outside its file");
        CHECK(lines == 9, "seven header lines (the writer's pid, pidns and start time among them) and two ranges, with no zero-hit rows (%d)", lines);
    }

    /*
     * A counter set whose snapshot has been replaced. The generation moved, so every count is
     * dropped rather than attributed to whichever network now holds that index.
     */
    {
        we_map_t m2;
        rng_t r2[1];

        r2[0].start = 0xc0000200u; r2[0].end = 0xc00002ffu; r2[0].sev = WE_SEV_HIGH;
        CHECK(write_snapshot(tmppath("cnt2.snap"), r2, 1, NULL, 0, 0, 8, 0, NULL, 0, NULL) == 0,
              "write a second generation");
        if (we_map_open(tmppath("cnt2.snap"), &m2) == WE_OK) {
            uint64_t before = c->denied;

            we_counters_count4(c, &m2, 0xc0000205u);
            CHECK(c->denied == before,
                  "a stale counter set counts NOTHING against a new snapshot rather than the wrong"
                  " network (%llu -> %llu)",
                  (unsigned long long) before, (unsigned long long) c->denied);
            CHECK(we_counters_write(c, &m2, TMPDIR_, 1760000600000ull) == WE_OK,
                  "and writing it out is a no-op rather than a wrong file");
            we_map_close(&m2);
        }
    }

    we_counters_free(c);
    we_counters_free(NULL);                          /* freeing nothing is not a crash either */
    we_map_close(&m);
}

/*
 * A FAILED retire-slot claim must not touch the slot it failed to get.
 *
 * Single-threaded and deterministic, which is the point: the defect it pins was found by
 * ThreadSanitizer on a CI runner, and TSan does not run on every machine this is developed on. A
 * concurrency bug that can only be demonstrated by a sanitiser is one that regresses on every box
 * without one.
 *
 * The bug: the publisher wrote `retired_at_ms` BEFORE the compare-exchange that claims the slot. On
 * a slot that is already occupied the claim fails, but the write has already happened - so the
 * OCCUPANT's retirement time has been replaced with a later one and it is no longer reclaimed when
 * its grace elapses. Under a steady stream of reloads the documented grace becomes unbounded and
 * resident snapshots accumulate, with no counter to show it.
 *
 * Reproduced here by filling every slot and then publishing once more, which is exactly the shape
 * that makes the claim fail.
 */
static void test_a_failed_slot_claim_leaves_the_occupant_alone(void)
{
    rng_t r[1];
    we_handle_t h;
    const we_map_t *occupant;
    int i;

    SECTION("a failed retire-slot claim must not move the occupant's grace window");
    memset(&h, 0, sizeof h);
    h.grace_ms = 1000ull;
    r[0].start = 0x0a0b0c0du; r[0].end = 0x0a0b0c0du; r[0].sev = WE_SEV_HIGH;

    /* Generation 1 at t=0, then one reload at t=0 so generation 1 lands in slot 0 stamped 0. */
    CHECK(write_snapshot(tmppath("fsc1.snap"), r, 1, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write 1");
    CHECK(we_handle_publish(&h, tmppath("fsc1.snap"), 10ull) == WE_OK, "publish generation 1");
    occupant = we_current(&h);

    for (i = 2; i <= WE_RETIRE_SLOTS + 1; i++) {
        char name[64];
        snprintf(name, sizeof name, "fsc%d.snap", i);
        CHECK(write_snapshot(tmppath(name), r, 1, NULL, 0, 0, (uint64_t) i, 0, NULL, 0, NULL) == 0,
              "write %d", i);
        /* All at t=10, so every retired mapping's grace expires at the same moment. */
        CHECK(we_handle_publish(&h, tmppath(name), 10ull) == WE_OK, "publish generation %d", i);
    }
    CHECK(h.retired[0].map == occupant, "generation 1 is the occupant of slot 0");
    CHECK(h.retired[0].retired_at_ms == 10ull,
          "and it is stamped with the time it was retired (%" PRIu64 ")", h.retired[0].retired_at_ms);

    /*
     * Now one more publish. Every slot is full, so EVERY claim fails and the mapping is deliberately
     * leaked - which is the documented behaviour. What must not happen is any slot's timestamp
     * moving: before the fix, all four were overwritten with 5000.
     */
    CHECK(write_snapshot(tmppath("fsc-extra.snap"), r, 1, NULL, 0, 0, 99, 0, NULL, 0, NULL) == 0,
          "write the one that cannot fit");
    CHECK(we_handle_publish(&h, tmppath("fsc-extra.snap"), 5000ull) == WE_OK, "publish it anyway");
    CHECK(h.leaked == 1, "it was leaked rather than freed under a reader (%" PRIu64 ")", h.leaked);
    for (i = 0; i < WE_RETIRE_SLOTS; i++) {
        CHECK(h.retired[i].retired_at_ms == 10ull,
              "slot %d still carries ITS OWN retirement time, not the failed claim's (%" PRIu64 ")",
              i, h.retired[i].retired_at_ms);
    }

    /* And the consequence that makes it matter: the grace still elapses when it should. */
    we_handle_retire(&h, 500ull);
    CHECK(h.retired[0].map == occupant, "inside the grace, still held");
    we_handle_retire(&h, 1100ull);
    CHECK(h.retired[0].map == NULL,
          "and reclaimed at 10+1000 as documented - which is what the clobber delayed indefinitely");

    we_handle_retire(&h, 100000ull);
    { we_map_t *cur = (we_map_t *) we_current(&h); we_map_close(cur); free(cur); }
}

/*
 * The probe bound, asserted structurally rather than sampled.
 *
 * This is the test that makes the latency claim defensible. It sweeps all 65,536 buckets and asserts a
 * ceiling on the worst window, which bounds the probe count for EVERY address in the space - no
 * timing, no hardware dependence, no distribution assumption. Then it asserts the property the index
 * exists for: the bound does not grow with the range count.
 */
static void test_probe_bound_is_a_property_of_the_file(void)
{
    SECTION("the worst-case probe count, computed over every bucket rather than sampled");

    CHECK(we_max_probes(0) == 0, "an empty window needs no probe");
    CHECK(we_max_probes(1) == 1, "a window of 1 needs 1 probe");
    CHECK(we_max_probes(2) == 2, "2 -> 2");
    CHECK(we_max_probes(3) == 2, "3 -> 2");
    CHECK(we_max_probes(4) == 3, "4 -> 3");
    CHECK(we_max_probes(255) == 8, "255 -> 8");
    CHECK(we_max_probes(256) == 9, "256 -> 9");

    {
        /* Two snapshots two orders of magnitude apart. The INDEXED probe bound must not grow with the
         * range count; that is the O(1) claim, proved rather than sampled. */
        const uint32_t sizes[2] = { 1000u, 100000u };
        uint32_t bound[2] = { 0u, 0u };
        int k;

        for (k = 0; k < 2; k++) {
            uint32_t n = sizes[k];
            rng_t *r = (rng_t *)malloc(sizeof(rng_t) * n);
            uint32_t cur = 1000u;
            uint32_t i;
            uint32_t step = (uint32_t)(0xf0000000u / n);
            we_map_t m;
            int rc;

            for (i = 0; i < n; i++) {
                r[i].start = cur;
                r[i].end = cur + 255u;
                r[i].sev = WE_SEV_HIGH;
                cur += 256u + (rnd32() % (step > 256u ? step - 256u : 1u));
            }
            CHECK(write_snapshot(tmppath("probe.snap"), r, n, NULL, 0, 1, (uint64_t)(k + 1), 0,
                                 NULL, 0, NULL) == 0, "write %u ranges", n);
            rc = we_map_open(tmppath("probe.snap"), &m);
            CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
            if (rc == WE_OK) {
                uint32_t worst = we_worst_bucket_occupancy4(&m);
                bound[k] = we_max_probes(worst);
                printf("  %6u ranges: worst bucket window %u entries, so at most %u probes for ANY"
                       " address in the IPv4 space\n", n, worst, bound[k]);
                /*
                 * And verify the computed bound is REAL by walking every bucket's window directly. The
                 * window is idx[b+1] - idx[b]: the still-open entry at idx[b] - 1 is where the step back
                 * lands, read as the record and never probed, so counting it (as this line did, with a
                 * `+ 1u`) published ceil(log2(w + 2)), one probe too many whenever w + 1 is a power of
                 * two. Corrected here together with the C helper and the Java writer (FORMAT.md
                 * §4.2); the deterministic test below checks the bound against the real search instead of
                 * recomputing the formula.
                 */
                {
                    uint32_t b;
                    uint32_t seen = 0;
                    for (b = 0; b < 65536u; b++) {
                        uint32_t span = m.v4_index[b + 1] - m.v4_index[b];
                        if (span > seen) { seen = span; }
                    }
                    CHECK(seen == worst, "the swept worst (%u) must equal the reported worst (%u)",
                          seen, worst);
                }
                we_map_close(&m);
            }
            free(r);
        }
        CHECK(bound[0] > 0 && bound[1] > 0, "both bounds computed");
        CHECK(bound[1] <= bound[0] + 2,
              "a 100x range count must not meaningfully grow the probe bound: %u vs %u",
              bound[0], bound[1]);
        CHECK(bound[1] <= 12, "the bound at 100,000 ranges is %u probes", bound[1]);
    }

    {
        /* The UNINDEXED fallback does grow, which is exactly why the builder always emits an index.
         * Stated as a test rather than left as an assumption. */
        rng_t r[2000];
        uint32_t i;
        we_map_t m;
        int rc;

        for (i = 0; i < 2000; i++) {
            r[i].start = 1000u + i * 1000u;
            r[i].end = r[i].start + 255u;
            r[i].sev = WE_SEV_HIGH;
        }
        CHECK(write_snapshot(tmppath("noidx.snap"), r, 2000, NULL, 0, 0, 9, 0, NULL, 0, NULL) == 0, "write");
        rc = we_map_open(tmppath("noidx.snap"), &m);
        CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
        if (rc == WE_OK) {
            uint32_t worst = we_worst_bucket_occupancy4(&m);
            CHECK(worst == 2000u, "unindexed, the whole array is the window: %u", worst);
            CHECK(we_max_probes(worst) == 11, "so 11 probes, against 1 or 2 indexed");
            printf("  unindexed 2,000 ranges: %u probes, which is why the index is unconditional\n",
                   we_max_probes(worst));
            we_map_close(&m);
        }
    }
}

/* =================== format 2 and the schema tail (FORMAT.md) =================== */

/*
 * A plane the refusal tests sabotage one field at a time. Ranges are evenly spaced with gaps, the
 * records carry real-looking attributes in every field's domain, and both families have enough ranges
 * that a rank S-tree has real nodes (IPv4: m = 5, one level; IPv6: m = 11, two levels).
 */
#define F2_N4 300u
#define F2_N6 700u

typedef struct {
    __uint128_t s4[F2_N4], e4[F2_N4], s6[F2_N6], e6[F2_N6];
    uint8_t     r4[F2_N4 * 16u];
    uint8_t     r6[F2_N6 * 32u];
    ww_plane_t  p;
} f2_t;

static void f2_ranges(__uint128_t *s, __uint128_t *e, uint32_t n, uint32_t kb)
{
    __uint128_t top = kb == 4u ? (__uint128_t)0xffffffffu
                    : kb == 8u ? (__uint128_t)0xffffffffffffffffull : ~(__uint128_t)0;
    __uint128_t step = top / (n + 1u);
    uint32_t i;

    for (i = 0; i < n; i++) {
        s[i] = (__uint128_t)(i + 1u) * step;
        e[i] = s[i] + step / 3u;
    }
}

static void f2_records(f2_t *x, uint32_t plane)
{
    uint32_t i;

    memset(x->r4, 0, sizeof x->r4);
    memset(x->r6, 0, sizeof x->r6);
    for (i = 0; i < F2_N4; i++) {
        if (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) {
            we_route4_t r;
            memset(&r, 0, sizeof r);
            r.asn = 64496u + i;                      /* RFC 5398 documentation ASNs and up */
            r.country = (uint16_t)(i % 2u ? 528u : 840u);
            r.rov = (uint8_t)(1u + i % 3u);
            r.rir = (uint8_t)(i % 6u);
            r.flags = (uint8_t)(i % 4u);
            r.asn_rep = (uint8_t)(i % 5u);
            memcpy(x->r4 + i * 16u, &r, sizeof r);
        } else {
            we_member4_t r;
            memset(&r, 0, sizeof r);
            r.flags = 1u;
            r.source = (uint8_t)(i % 7u);
            memcpy(x->r4 + i * 16u, &r, sizeof r);
        }
    }
    for (i = 0; i < F2_N6; i++) {
        if (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) {
            we_route6_t r;
            memset(&r, 0, sizeof r);
            r.asn = 4200000000u + i;                 /* RFC 6996 private-use 32-bit ASNs */
            r.country = 276u;
            r.rov = 3u;
            r.rir = 5u;
            r.flags = (uint8_t)(i % 8u);             /* anycast, moas and narrowed are all IPv6-legal */
            r.asn_rep = 2u;
            memcpy(x->r6 + i * 24u, &r, sizeof r);
        } else {
            we_member6_t r;
            memset(&r, 0, sizeof r);
            r.flags = 1u;
            memcpy(x->r6 + i * 32u, &r, sizeof r);
        }
    }
}

static void f2_init(f2_t *x, uint32_t plane, uint32_t k4, uint32_t p4, uint32_t k6, uint32_t p6)
{
    memset(&x->p, 0, sizeof x->p);
    x->p.format = WE_FORMAT_2;
    x->p.schema = 1;
    x->p.plane = plane;
    x->p.generation = 42u;
    x->p.valid_until_ms = 0u;
    x->p.country_version = (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) ? 5704u : 0u;
    f2_ranges(x->s4, x->e4, F2_N4, 4u);
    f2_ranges(x->s6, x->e6, F2_N6, ww_key_bytes(&x->p, 6));
    f2_records(x, plane);
    x->p.v4.n = F2_N4;
    x->p.v4.start = x->s4;
    x->p.v4.end = x->e4;
    x->p.v4.kind = k4;
    x->p.v4.param = p4;
    x->p.v4.rec = x->r4;
    x->p.v6.n = F2_N6;
    x->p.v6.start = x->s6;
    x->p.v6.end = x->e6;
    x->p.v6.kind = k6;
    x->p.v6.param = p6;
    x->p.v6.rec = x->r6;
    {
        /* the membership records' `source` runs 0..6, so the table has seven entries */
        static const char *const feeds[7] = { "", "feed-a", "feed-b", "feed-c", "feed-d", "feed-e", "feed-f" };

        x->p.feeds = feeds;
        x->p.nfeeds = 7u;
    }
}

static void addr16_of(__uint128_t a, uint32_t kb, int low_ones, uint8_t out[16])
{
    int i;

    if (kb == 8u) {
        for (i = 0; i < 8; i++) {
            out[i] = (uint8_t)((uint64_t)a >> (56 - 8 * i));
        }
        memset(out + 8, low_ones ? 0xff : 0x00, 8);
        return;
    }
    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t)(a >> (120 - 8 * i));
    }
}

/* The reference answer: the index of the range holding a, or WE_NO_RANGE. Linear, so it shares nothing. */
static uint32_t ref_find(const __uint128_t *s, const __uint128_t *e, uint32_t n, __uint128_t a)
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        if (a >= s[i] && a <= e[i]) {
            return i;
        }
    }
    return WE_NO_RANGE;
}

static void test_format2_planes(void)
{
    static const struct { const char *file; uint32_t plane, k4, p4, k6, p6; } C[] = {
        { "routing.bin",          WE_PLANE_ROUTING,  WE_KIND_RADIX, 18u, WE_KIND_RANK,  6u },
        { "registry.bin",         WE_PLANE_REGISTRY, WE_KIND_RANK,  6u,  WE_KIND_RADIX, 16u },
        { "tor.bin",              WE_PLANE_TOR,      WE_KIND_RADIX, 12u, WE_KIND_RANK,  5u },
        { "anonymizer.bin",       WE_PLANE_ANONYMIZER, WE_KIND_NONE, 0u, WE_KIND_RADIX, 18u },
        { "threat.bin",           WE_PLANE_THREAT,   WE_KIND_RANK,  6u,  WE_KIND_NONE,  0u },
        { "rpki-unreachable.bin", WE_PLANE_RPKI_UNREACHABLE, WE_KIND_RADIX, 16u, WE_KIND_RADIX, 12u },
        { "tenant.bin",           WE_PLANE_TENANT,   WE_KIND_RANK,  6u,  WE_KIND_RANK,  5u },
    };
    static f2_t x;
    size_t c;

    SECTION("format 2: every plane, both index kinds and none, answered through we_plane_open");
    for (c = 0; c < sizeof C / sizeof C[0]; c++) {
        we_map_t m;
        we_load_detail_t d;
        int rc;
        uint32_t i, kb6, hits = 0;
        char rel[64];

        f2_init(&x, C[c].plane, C[c].k4, C[c].p4, C[c].k6, C[c].p6);
        kb6 = ww_key_bytes(&x.p, 6);
        snprintf(rel, sizeof rel, "%s", C[c].file);
        CHECK(ww_write(tmppath(rel), &x.p) == 0, "%s: write", C[c].file);

        /* The legacy entry refuses it exactly as a reader built before format 2 does. */
        CHECK(we_map_open(tmppath(rel), &m) == WE_ERR_FORMAT,
              "%s: we_map_open (the format-1 entry point) must refuse format 2 with WE_ERR_FORMAT", C[c].file);

        rc = we_plane_open(tmppath(rel), &m, &d);
        CHECK(rc == WE_OK, "%s: we_plane_open: %s (%s)", C[c].file, we_strerror(rc), d.what ? d.what : "-");
        if (rc != WE_OK) {
            continue;
        }
        CHECK(m.format == WE_FORMAT_2 && m.plane_id == C[c].plane, "%s: format %u plane %u", C[c].file,
              m.format, m.plane_id);
        CHECK(m.generation == 42u && m.v4_sev == NULL && m.v6_sev == NULL && m.v4_end == NULL,
              "%s: arm-time generation copied; no sev[] or end[] in format 2", C[c].file);
        CHECK(we_counters_new(&m, 1u) == NULL, "%s: no per-range counters on a format-2 plane", C[c].file);

        for (i = 0; i < F2_N4; i++) {
            __uint128_t pts[5];
            int k;

            pts[0] = x.s4[i] - 1u; pts[1] = x.s4[i]; pts[2] = x.e4[i]; pts[3] = x.e4[i] + 1u;
            pts[4] = x.s4[i] + (x.e4[i] - x.s4[i]) / 2u;
            for (k = 0; k < 5; k++) {
                uint32_t want = ref_find(x.s4, x.e4, F2_N4, pts[k]);
                uint32_t got = we_find4(&m, (uint32_t)pts[k]);

                CHECK(got == want, "%s v4 addr %u: got %u want %u", C[c].file, (uint32_t)pts[k], got, want);
                CHECK(we_lookup4(&m, (uint32_t)pts[k]) == WE_SEV_NONE,
                      "%s: a format-2 plane carries no severity, so the format-1 verdict is allow", C[c].file);
                CHECK(we_range4(&m, (uint32_t)pts[k]) == (want == WE_NO_RANGE ? -1 : (int)want),
                      "%s: we_range4 is the hot path's answer", C[c].file);
                if (got != WE_NO_RANGE && got == want) {
                    const uint8_t *r = we_record_of(&m.f4, got);

                    hits++;
                    CHECK(r != NULL && memcmp(r + 4, x.r4 + (size_t)got * 16u + 4u, 12) == 0,
                          "%s: the record's attributes are the written ones", C[c].file);
                }
            }
        }
        for (i = 0; i < F2_N6; i++) {
            __uint128_t pts[4];
            int k, low;

            pts[0] = x.s6[i] - 1u; pts[1] = x.s6[i]; pts[2] = x.e6[i]; pts[3] = x.e6[i] + 1u;
            for (k = 0; k < 4; k++) {
                uint32_t want = ref_find(x.s6, x.e6, F2_N6, pts[k]);

                for (low = 0; low < (kb6 == 8u ? 2 : 1); low++) {
                    uint8_t a16[16];
                    uint32_t got, other;

                    addr16_of(pts[k], kb6, low, a16);
                    got = kb6 == 8u ? we_find6_64(&m, a16) : we_find6(&m, a16);
                    other = kb6 == 8u ? we_find6(&m, a16) : we_find6_64(&m, a16);
                    CHECK(got == want, "%s v6 range %u point %d low=%s: got %u want %u", C[c].file, i, k,
                          low ? "ones" : "0", got, want);
                    CHECK(other == WE_NO_RANGE,
                          "%s: the other key width's lookup answers no range through its n = 0", C[c].file);
                    CHECK(we_range6(&m, a16) == (want == WE_NO_RANGE ? -1 : (int)want),
                          "%s: we_range6 is the hot path's answer", C[c].file);
                    if (got != WE_NO_RANGE && got == want) {
                        const we_fam_t *f6 = we_family6(&m);
                        const uint8_t *r = we_record_of(f6, got);
                        uint32_t st = kb6 == 8u ? 24u : 32u;

                        CHECK(r != NULL && memcmp(r + kb6, x.r6 + (size_t)got * st + kb6, st - kb6) == 0,
                              "%s: the IPv6 record's attributes are the written ones", C[c].file);
                    }
                }
            }
        }
        CHECK(hits > 0, "%s: some addresses hit", C[c].file);
        CHECK(we_record_of(&m.f4, WE_NO_RANGE) == NULL && we_record_of(&m.f4, F2_N4) == NULL,
              "%s: no record for no range, or past n", C[c].file);
        we_map_close(&m);
    }
}

static void test_format1_with_schema(void)
{
    rng_t r[64];
    pfx_t p[8];
    int nr, i, mode;

    SECTION("format 1 with WE_H_SCHEMA: the shipped layout plus a populated tail");
    for (i = 0; i < 8; i++) {
        p[i].addr = rnd32(); p[i].len = (uint8_t)(8u + (rnd32() % 20u)); p[i].sev = WE_SEV_HIGH;
    }
    nr = resolve(p, 8, r, 64);
    CHECK(nr > 0, "fixture resolved");
    for (mode = 0; mode < 2; mode++) {
        static __uint128_t s[64], e[64];
        uint8_t sev[64];
        ww_plane_t pl;
        we_map_t m, plain;
        int rc, k;
        uint32_t a;

        for (i = 0; i < nr; i++) {
            s[i] = r[i].start; e[i] = r[i].end; sev[i] = r[i].sev;
        }
        memset(&pl, 0, sizeof pl);
        pl.format = WE_FORMAT_1;
        pl.schema = 1;
        pl.generation = 9u;
        pl.v4.n = (uint32_t)nr;
        pl.v4.start = s;
        pl.v4.end = e;
        pl.v4.sev = sev;
        pl.v4.kind = mode ? WE_KIND_RADIX : WE_KIND_NONE;
        pl.v4.param = mode ? 16u : 0u;
        CHECK(ww_write(tmppath("reputation.bin"), &pl) == 0, "write");
        rc = we_map_open(tmppath("reputation.bin"), &m);
        CHECK(rc == WE_OK, "index=%d: a format-1 file with the schema tail loads through we_map_open: %s",
              mode, we_strerror(rc));
        pl.schema = 0;
        CHECK(ww_write(tmppath("plain.snap"), &pl) == 0, "write");
        CHECK(we_map_open(tmppath("plain.snap"), &plain) == WE_OK, "and the same file without it");
        if (rc == WE_OK) {
            CHECK(m.plane_id == WE_PLANE_REPUTATION && m.h->schema.schema_id == WE_SCHEMA_FORMAT1
                  && m.h->schema.v6_key_bits == 128u, "the tail says reputation, schema 0, 128-bit IPv6");
            for (k = 0; k < 20000; k++) {
                a = rnd32();
                CHECK(we_lookup4(&m, a) == we_lookup4(&plain, a), "answers agree with the plain file");
            }
            for (i = 0; i < nr; i++) {
                CHECK(we_lookup4(&m, r[i].start) == r[i].sev && we_lookup4(&m, r[i].end) == r[i].sev,
                      "range %d answers its severity", i);
            }
            we_map_close(&m);
        }
        we_map_close(&plain);
        /* the legacy name of the reputation plane is honoured, and a plane name that is not is refused */
        pl.schema = 1;
        CHECK(ww_write(tmppath("snapshot.bin"), &pl) == 0, "write");
        rc = we_map_open(tmppath("snapshot.bin"), &m);
        CHECK(rc == WE_OK, "snapshot.bin is the reputation plane's legacy name: %s", we_strerror(rc));
        if (rc == WE_OK) {
            we_map_close(&m);
        }
        CHECK(ww_write(tmppath("routing.bin"), &pl) == 0, "write");
        CHECK(we_map_open(tmppath("routing.bin"), &m) == WE_ERR_FORMAT,
              "a reputation plane installed as routing.bin is refused: plane_id must match the name");
        pl.schema = 0;
        CHECK(ww_write(tmppath("tor.bin"), &pl) == 0, "write");
        CHECK(we_map_open(tmppath("tor.bin"), &m) == WE_ERR_FORMAT,
              "a pre-schema file is the reputation plane, so tor.bin is the wrong name for it");
    }
}

/* Build the routing base, let `patch` sabotage it, re-sign (or not), save, load. */
static int f2_load(f2_t *x, const char *name, void (*patch)(uint8_t *, size_t, const f2_t *), int resign,
                   we_load_detail_t *d)
{
    size_t len = 0;
    uint8_t *buf = ww_build(&x->p, &len);
    we_map_t m;
    int rc;

    if (buf == NULL) {
        return 1000;
    }
    if (patch != NULL) {
        patch(buf, len, x);
    }
    if (resign) {
        ww_sign(buf, len);
    }
    if (ww_save(tmppath(name), buf, len) != 0) {
        free(buf);
        return 1001;
    }
    free(buf);
    rc = we_plane_open(tmppath(name), &m, d);
    if (rc == WE_OK) {
        we_map_close(&m);
    }
    return rc;
}

#define HDR(b) ((we_header_t *)(void *)(b))
static void p_format3(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->format = 3u; }
static void p_noschema(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->flags &= ~WE_H_SCHEMA; }
static void p_kind3(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v6_index_kind = 3u; }
static void p_radix14(uint8_t *b, size_t l, const f2_t *x)
{
    (void)l; (void)x;
    HDR(b)->schema.v4_index_kind = WE_KIND_RADIX;
    HDR(b)->schema.v4_index_param = 14u;
    HDR(b)->flags |= WE_H_V4_INDEXED;
}
static void p_rank5(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v6_index_param = 5u; }
static void p_reserved(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.reserved[15] = 1u; }
static void p_plane9(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.plane_id = 9u; }
static void p_schema2(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.schema_id = 2u; }
static void p_keybits(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v6_key_bits = 128u; }
static void p_stride(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v4_record_stride = 24u; }
static void p_mcount(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v6_sample_count += 1u; }
static void p_depth(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v6_depth = 3u; }
static void p_flag(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->flags |= WE_H_V4_INDEXED; }
static void p_len(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->file_len -= 1u; }
static void p_recoff(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v4_record_off += 16u; }
static void p_startoff(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->v6_start_off += 8u; }
static void p_endoff(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->v4_end_off = 192u; }
static void p_rankidx(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->v6_index_off = 192u; }
static void p_treeout(uint8_t *b, size_t l, const f2_t *x) { (void)x; HDR(b)->schema.v6_sample_off = (uint32_t)(l & ~(size_t)63u); }
static void p_sample(uint8_t *b, size_t l, const f2_t *x)
{
    /* the IPv6 S-tree's first slot: a separator, now one more than start[j*s] */
    uint64_t v;
    (void)l; (void)x;
    memcpy(&v, b + HDR(b)->schema.v6_sample_off, 8);
    v += 1u;
    memcpy(b + HDR(b)->schema.v6_sample_off, &v, 8);
}
static void p_padding(uint8_t *b, size_t l, const f2_t *x)
{
    /* the IPv4 tree has one node holding m - 1 = 4 separators; slot 15 is padding */
    uint32_t v = 7u;
    (void)l; (void)x;
    memcpy(b + HDR(b)->schema.v4_sample_off + 15u * 4u, &v, 4);
}
static void p_unsorted(uint8_t *b, size_t l, const f2_t *x)
{
    /* start[11] := start[10]: not strictly increasing */
    uint32_t v;
    (void)l; (void)x;
    memcpy(&v, b + HDR(b)->v4_start_off + 10u * 4u, 4);
    memcpy(b + HDR(b)->v4_start_off + 11u * 4u, &v, 4);
}
static void p_overlap(uint8_t *b, size_t l, const f2_t *x)
{
    /* record 20's end := start[21] */
    uint64_t v;
    (void)l; (void)x;
    memcpy(&v, b + HDR(b)->v6_start_off + 21u * 8u, 8);
    memcpy(b + HDR(b)->schema.v6_record_off + 20u * 24u, &v, 8);
}
/* a bit of record 0's ASN: any value is in the domain, so only the digest can see it */
static void p_body(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v4_record_off + 4u] ^= 0x01u; }
static void p_rov4(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v4_record_off + 5u * 16u + 10u] = 4u; }
static void p_country(uint8_t *b, size_t l, const f2_t *x)
{
    uint16_t v = 1000u;
    (void)l; (void)x;
    memcpy(b + HDR(b)->schema.v6_record_off + 77u * 24u + 12u, &v, 2);
}
static void p_rir(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v4_record_off + 9u * 16u + 11u] = 6u; }
static void p_rep(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v6_record_off + 3u * 24u + 17u] = 5u; }
static void p_narrow4(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v4_record_off + 0u * 16u + 12u] = WE_RF_NARROWED; }
static void p_rsv(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v6_record_off + 699u * 24u + 23u] = 1u; }
static void p_endlow(uint8_t *b, size_t l, const f2_t *x)
{
    /* record 2's end := start[2] - 1 */
    uint32_t v;
    (void)l; (void)x;
    memcpy(&v, b + HDR(b)->v4_start_off + 2u * 4u, 4);
    v -= 1u;
    memcpy(b + HDR(b)->schema.v4_record_off + 2u * 16u, &v, 4);
}
static void p_unknown_cc(uint8_t *b, size_t l, const f2_t *x)
{
    uint16_t v = 999u;                      /* in range, assigned to nothing */
    (void)l; (void)x;
    memcpy(b + HDR(b)->schema.v4_record_off + 1u * 16u + 8u, &v, 2);
}
/* two defects at once: the earlier stage in FORMAT.md §6 must be the one reported */
static void p_fmt_trunc(uint8_t *b, size_t l, const f2_t *x) { p_kind3(b, l, x); p_len(b, l, x); }
static void p_trunc_off(uint8_t *b, size_t l, const f2_t *x) { p_len(b, l, x); p_recoff(b, l, x); }
static void p_off_uns(uint8_t *b, size_t l, const f2_t *x) { p_recoff(b, l, x); p_unsorted(b, l, x); }
static void p_uns_ovl(uint8_t *b, size_t l, const f2_t *x) { p_overlap(b, l, x); p_unsorted(b, l, x); }
static void p_ovl_dig(uint8_t *b, size_t l, const f2_t *x) { p_overlap(b, l, x); }
static void p_dig_rec(uint8_t *b, size_t l, const f2_t *x) { p_rov4(b, l, x); }

static void test_format2_refusals(void)
{
    static f2_t x;
    static const struct {
        void (*patch)(uint8_t *, size_t, const f2_t *);
        int resign;
        int want;
        int family;
        int64_t record;
        const char *what;
    } T[] = {
        { p_format3,  1, WE_ERR_FORMAT,    0, -1, "format 3" },
        { p_noschema, 1, WE_ERR_FORMAT,    0, -1, "format 2 without the schema tail" },
        { p_kind3,    1, WE_ERR_FORMAT,    6, -1, "an unknown index kind (3): the lookup's else arm stays unreachable" },
        { p_radix14,  1, WE_ERR_FORMAT,    4, -1, "radix k = 14" },
        { p_rank5,    1, WE_ERR_FORMAT,    6, -1, "rank stride 32 on 64-bit keys" },
        { p_reserved, 1, WE_ERR_FORMAT,    0, -1, "a non-zero reserved tail byte" },
        { p_plane9,   1, WE_ERR_FORMAT,    0, -1, "plane_id 9" },
        { p_schema2,  1, WE_ERR_FORMAT,    0, -1, "the routing plane declaring the membership schema" },
        { p_keybits,  1, WE_ERR_FORMAT,    6, -1, "128-bit keys on the routing plane" },
        { p_stride,   1, WE_ERR_FORMAT,    0, -1, "a record stride that is not the schema's" },
        { p_mcount,   1, WE_ERR_FORMAT,    6, -1, "a sample_count that is not ceil(n / s)" },
        { p_depth,    1, WE_ERR_FORMAT,    6, -1, "a depth that is not the integer formula's" },
        { p_flag,     1, WE_ERR_FORMAT,    4, -1, "the INDEXED flag disagreeing with the kind" },
        { p_len,      1, WE_ERR_TRUNCATED, 0, -1, "file_len one short" },
        { p_recoff,   1, WE_ERR_OFFSETS,   4, -1, "a record column 16 bytes off alignment (an unaligned array)" },
        { p_startoff, 1, WE_ERR_OFFSETS,   6, -1, "a start[] 8 bytes off alignment" },
        { p_endoff,   1, WE_ERR_OFFSETS,   4, -1, "an end[] offset in format 2" },
        { p_rankidx,  1, WE_ERR_OFFSETS,   6, -1, "a radix index offset on a rank family" },
        { p_treeout,  1, WE_ERR_OFFSETS,   6, -1, "an S-tree running past the file" },
        { p_sample,   1, WE_ERR_OFFSETS,   6, -1, "a sample that is not start[j * s] (a bad sample)" },
        { p_padding,  1, WE_ERR_OFFSETS,   4, -1, "a padding slot that is not the maximum key" },
        { p_unsorted, 1, WE_ERR_UNSORTED,  4, 11, "starts not strictly increasing" },
        { p_overlap,  1, WE_ERR_OVERLAP,   6, 20, "an end at the next start" },
        { p_body,     0, WE_ERR_DIGEST,    0, -1, "one flipped body bit, not re-signed" },
        { p_rov4,     1, WE_ERR_FORMAT,    4, 5,  "rov = 4 (unrouted) in a record" },
        { p_country,  1, WE_ERR_FORMAT,    6, 77, "country 1000" },
        { p_rir,      1, WE_ERR_FORMAT,    4, 9,  "rir 6" },
        { p_rep,      1, WE_ERR_FORMAT,    6, 3,  "asn_rep 5" },
        { p_narrow4,  1, WE_ERR_FORMAT,    4, 0,  "narrowed on an IPv4 record" },
        { p_rsv,      1, WE_ERR_FORMAT,    6, 699, "a reserved record byte" },
        { p_endlow,   1, WE_ERR_FORMAT,    4, 2,  "a record's end below its start" },
        /* the order of FORMAT.md §6, two defects at a time */
        { p_fmt_trunc, 1, WE_ERR_FORMAT,   6, -1, "FORMAT before TRUNCATED" },
        { p_trunc_off, 1, WE_ERR_TRUNCATED, 0, -1, "TRUNCATED before OFFSETS" },
        { p_off_uns,  1, WE_ERR_OFFSETS,   4, -1, "OFFSETS before UNSORTED" },
        { p_uns_ovl,  1, WE_ERR_UNSORTED,  4, 11, "UNSORTED before OVERLAP" },
        { p_ovl_dig,  0, WE_ERR_OVERLAP,   6, 20, "OVERLAP before DIGEST" },
        { p_dig_rec,  0, WE_ERR_DIGEST,    0, -1, "DIGEST before the record domains" },
    };
    size_t t;
    we_load_detail_t d;
    int rc;

    SECTION("format 2: every refusal in FORMAT.md §6, in order, each with its named error");
    f2_init(&x, WE_PLANE_ROUTING, WE_KIND_RANK, 6u, WE_KIND_RANK, 6u);
    rc = f2_load(&x, "routing.bin", NULL, 0, &d);
    CHECK(rc == WE_OK, "the baseline must load or every refusal below proves nothing: %s (%s)",
          we_strerror(rc), d.what ? d.what : "-");
    for (t = 0; t < sizeof T / sizeof T[0]; t++) {
        rc = f2_load(&x, "routing.bin", T[t].patch, T[t].resign, &d);
        CHECK(rc == T[t].want, "%s: got %s, want %s (%s)", T[t].what, we_strerror(rc), we_strerror(T[t].want),
              d.what ? d.what : "-");
        CHECK(d.rc == rc, "%s: the detail carries the code", T[t].what);
        CHECK(T[t].family == 0 || d.family == T[t].family, "%s: family %d, want %d", T[t].what, d.family,
              T[t].family);
        CHECK(T[t].record < 0 || d.record == T[t].record, "%s: names record %" PRId64 ", want %" PRId64,
              T[t].what, d.record, T[t].record);
    }

    /* The name rule: a routing plane is not tor.bin. Any other name carries no claim. */
    CHECK(f2_load(&x, "tor.bin", NULL, 0, &d) == WE_ERR_FORMAT, "a routing plane installed as tor.bin");
    CHECK(f2_load(&x, "plane-under-test.snap", NULL, 0, &d) == WE_OK, "a fixture name carries no claim");
    CHECK(f2_load(&x, ".routing.bin.Xy12", NULL, 0, &d) == WE_OK, "a refresh dot-temp carries no claim");
    CHECK(f2_load(&x, "snapshot.bin", NULL, 0, &d) == WE_OK,
          "snapshot.bin is not a <plane>.bin name, so it carries no claim either");

    /* An in-range code this reader does not know is read as undetermined, not refused. */
    {
        size_t len = 0;
        uint8_t *buf = ww_build(&x.p, &len);
        we_map_t m;

        p_unknown_cc(buf, len, &x);
        ww_sign(buf, len);
        CHECK(ww_save(tmppath("routing.bin"), buf, len) == 0, "save");
        free(buf);
        rc = we_plane_open(tmppath("routing.bin"), &m, &d);
        CHECK(rc == WE_OK, "a code in range but unknown loads: %s", we_strerror(rc));
        if (rc == WE_OK) {
            const uint8_t *r = we_record_of(&m.f4, 1u);
            uint16_t raw = 0;

            CHECK(m.country_unknown == 1u, "and is counted for the log-once (%u)", m.country_unknown);
            CHECK(m.country_table_version == 5704u, "the file's table version is kept");
            if (r != NULL) {
                memcpy(&raw, r + 8, 2);
            }
            CHECK(raw == 999u && we_country(&m, raw) == WE_COUNTRY_UNDETERMINED, "999 reads as undetermined");
            CHECK(we_country(&m, 528u) == 528u && we_country(&m, 903u) == 903u && we_country(&m, 1u) == 0u,
                  "528 (NL) and 903 (XK) are known, 1 is not");
            we_map_close(&m);
        }
    }

    /* A format-1 file whose tail is reserved (no WE_H_SCHEMA) must keep it zero. */
    {
        rng_t r1[1];
        we_map_t m;
        uint8_t *buf;
        FILE *f;
        struct stat st;

        r1[0].start = 0x0a000000u; r1[0].end = 0x0a0000ffu; r1[0].sev = WE_SEV_HIGH;
        CHECK(write_snapshot(tmppath("t1.snap"), r1, 1, NULL, 0, 0, 1, 0, NULL, 0, NULL) == 0, "write");
        stat(tmppath("t1.snap"), &st);
        buf = (uint8_t *)malloc((size_t)st.st_size);
        f = fopen(tmppath("t1.snap"), "rb");
        if (f != NULL && buf != NULL && fread(buf, 1, (size_t)st.st_size, f) == (size_t)st.st_size) {
            buf[150] = 1u;
            ww_sign(buf, (size_t)st.st_size);
            CHECK(ww_save(tmppath("t1.snap"), buf, (size_t)st.st_size) == 0, "save");
            CHECK(we_map_open(tmppath("t1.snap"), &m) == WE_ERR_FORMAT,
                  "a non-zero byte in a pre-schema file's reserved tail is refused");
        }
        if (f != NULL) {
            fclose(f);
        }
        free(buf);
    }
}

static void p_src7(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->schema.v4_record_off + 4u * 16u + 8u] = 7u; }
static void p_feed0(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; b[HDR(b)->blob_off + 2u] = 'x'; }
static void p_feedn(uint8_t *b, size_t l, const f2_t *x)
{
    uint16_t n = 200u;            /* more names than the blob holds */
    (void)l; (void)x;
    memcpy(b + HDR(b)->blob_off, &n, 2);
}

static void p_radix_off4(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->v4_index_off += 4u; }
static void p_m1_sample(uint8_t *b, size_t l, const f2_t *x) { (void)l; (void)x; HDR(b)->schema.v4_sample_off = 64u; }

/* FORMAT.md §5: the radix table is 64-byte aligned, and a one-window rank family has sample_off 0. */
static void test_format2_layout_pins(void)
{
    static f2_t x;
    we_load_detail_t d;
    int rc;

    SECTION("format 2: the radix table 64-byte aligned, and a one-window rank family's sample_off 0");
    f2_init(&x, WE_PLANE_ROUTING, WE_KIND_RADIX, 18u, WE_KIND_RANK, 6u);
    CHECK(f2_load(&x, "routing.bin", NULL, 0, &d) == WE_OK, "baseline: %s", d.what ? d.what : "-");
    {
        size_t len = 0;
        uint8_t *buf = ww_build(&x.p, &len);

        CHECK(buf != NULL && HDR(buf)->v4_index_off % 64u == 0u, "the writer aligns the table to 64 (%u)",
              buf ? HDR(buf)->v4_index_off : 0u);
        free(buf);
    }
    rc = f2_load(&x, "routing.bin", p_radix_off4, 1, &d);
    CHECK(rc == WE_ERR_OFFSETS && d.family == 4 && d.what != NULL && strstr(d.what, "64-byte") != NULL,
          "a radix table 4 bytes off 64 is refused for its alignment (%s: %s)", we_strerror(rc),
          d.what ? d.what : "-");

    /* one window: n <= 64 on IPv4 */
    f2_init(&x, WE_PLANE_ROUTING, WE_KIND_RANK, 6u, WE_KIND_RANK, 6u);
    x.p.v4.n = 40u;
    rc = f2_load(&x, "routing.bin", NULL, 0, &d);
    CHECK(rc == WE_OK, "a one-window rank family loads: %s", d.what ? d.what : "-");
    {
        size_t len = 0;
        uint8_t *buf = ww_build(&x.p, &len);

        CHECK(buf != NULL && HDR(buf)->schema.v4_sample_off == 0u && HDR(buf)->schema.v4_sample_count == 1u
              && HDR(buf)->schema.v4_depth == 0u, "and is written sample_off 0, sample_count 1, depth 0");
        free(buf);
    }
    rc = f2_load(&x, "routing.bin", p_m1_sample, 1, &d);
    CHECK(rc == WE_ERR_FORMAT && d.family == 4, "a non-zero sample_off at m = 1 is refused (%s: %s)",
          we_strerror(rc), d.what ? d.what : "-");
}

/* FORMAT.md: the format-2 blob begins with the feed-name table that membership `source` indexes. */
static void test_format2_feed_table(void)
{
    static f2_t x;
    we_load_detail_t d;
    we_map_t m;
    int rc;

    SECTION("format 2: the blob's feed-name table, and the source byte that indexes it");
    f2_init(&x, WE_PLANE_TOR, WE_KIND_RADIX, 12u, WE_KIND_RANK, 5u);
    CHECK(f2_load(&x, "tor.bin", NULL, 0, &d) == WE_OK, "baseline: %s", d.what ? d.what : "-");
    rc = we_plane_open(tmppath("tor.bin"), &m, &d);
    CHECK(rc == WE_OK, "open");
    if (rc == WE_OK) {
        const char *f3 = we_feed_name(&m, 3u);
        const char *f0 = we_feed_name(&m, 0u);

        CHECK(m.feed_count == 7u, "seven feeds (%u)", m.feed_count);
        CHECK(f3 != NULL && strcmp(f3, "feed-c") == 0, "source 3 is feed-c (%s)", f3 ? f3 : "(null)");
        CHECK(f0 != NULL && f0[0] == '\0', "source 0 is the empty name, none");
        CHECK(we_feed_name(&m, 7u) == NULL, "no name past the table");
        we_map_close(&m);
    }
    rc = f2_load(&x, "tor.bin", p_src7, 1, &d);
    CHECK(rc == WE_ERR_FORMAT && d.family == 4 && d.record == 4,
          "source 7 against a 7-entry table is refused naming record 4 (%s, %d, %" PRId64 ")",
          we_strerror(rc), d.family, d.record);
    CHECK(f2_load(&x, "tor.bin", p_feed0, 1, &d) == WE_ERR_OFFSETS, "entry 0 must be the empty name");
    CHECK(f2_load(&x, "tor.bin", p_feedn, 1, &d) == WE_ERR_OFFSETS, "a count past the names the blob holds");

    /* An absent blob is a table of one: source 0 loads, any other source is refused. */
    x.p.blob = "";
    x.p.blob_len = 0u;
    rc = f2_load(&x, "tor.bin", NULL, 0, &d);
    CHECK(rc == WE_ERR_FORMAT && d.record == 1, "no blob: record 1's source 1 is refused (%s, %" PRId64 ")",
          we_strerror(rc), d.record);
    memset(x.r4, 0, sizeof x.r4);
    memset(x.r6, 0, sizeof x.r6);
    {
        uint32_t i;
        for (i = 0; i < F2_N4; i++) { x.r4[i * 16u + 4u] = 1u; }
        for (i = 0; i < F2_N6; i++) { x.r6[i * 32u + 16u] = 1u; }
    }
    CHECK(f2_load(&x, "tor.bin", NULL, 0, &d) == WE_OK, "no blob and every source 0 loads: %s",
          d.what ? d.what : "-");

    /* format-2 meta[] points into the blob after the table, or is 0 */
    {
        static uint32_t meta[F2_N4];
        uint32_t i;

        f2_init(&x, WE_PLANE_TOR, WE_KIND_RADIX, 12u, WE_KIND_RANK, 5u);
        for (i = 0; i < F2_N4; i++) { meta[i] = 0u; }
        meta[9] = 3u;                      /* inside the table */
        x.p.v4.meta = meta;
        rc = f2_load(&x, "tor.bin", NULL, 0, &d);
        CHECK(rc == WE_ERR_OFFSETS && d.record == 9, "a meta[] offset inside the table is refused (%s)",
              we_strerror(rc));
        x.p.v4.meta = NULL;
    }
}

/*
 * The arm-time copies and the branchless clamp: rewrite the bytes UNDER a loaded descriptor (what a
 * same-length in-place rewrite does to a mapping) and the lookup must stay inside the buffer. The index
 * entries and the S-tree keys are what the lookup reads; set them to the worst values there are.
 */
static int child_rewritten_under_the_descriptor(const char *path)
{
    we_map_t m;
    we_load_detail_t d;
    uint32_t i, k;
    int bad = 0;

    if (we_plane_open(path, &m, &d) != WE_OK) {
        return 70;
    }
    for (k = 0; k < 4; k++) {
        uint8_t *base = (uint8_t *)(uintptr_t)m.base;
        uint32_t fill = k == 0 ? 0xffffffffu : k == 1 ? 0u : k == 2 ? 0x7fffffffu : 0x80000000u;

        /* every byte of the radix table, the S-tree and start[] */
        if (m.f4.file_kind == WE_KIND_RADIX) {
            for (i = 0; i <= (1u << m.f4.file_param); i++) {
                memcpy(base + ((const uint8_t *)m.f4.idx - (const uint8_t *)m.base) + (size_t)i * 4u, &fill, 4);
            }
        }
        if (m.f6w.stree != NULL) {
            memset(base + (m.f6w.stree - (const uint8_t *)m.base), (int)(fill & 0xffu), (size_t)m.f6w.nodes * 64u);
        }
        for (i = 0; i < 200000; i++) {
            uint32_t a = rnd32();
            uint8_t a16[16];
            uint32_t r4 = we_find4(&m, a);
            uint32_t r6;

            memset(a16, 0, 16);
            memcpy(a16, &a, 4);
            a16[5] = (uint8_t)i;
            r6 = we_find6_64(&m, a16);
            if ((r4 != WE_NO_RANGE && r4 >= m.f4.n) || (r6 != WE_NO_RANGE && r6 >= m.f6w.n)) {
                bad++;
            }
        }
    }
    we_map_close(&m);
    return bad == 0 ? 0 : 71;
}

static void test_clamp_under_a_rewritten_mapping(void)
{
    static f2_t x;
    we_load_detail_t d;
    int rc;

    SECTION("the arm-time copies and the clamp: bytes rewritten under a loaded descriptor stay in bounds");
    f2_init(&x, WE_PLANE_ROUTING, WE_KIND_RADIX, 18u, WE_KIND_RANK, 6u);
    CHECK(f2_load(&x, "routing.bin", NULL, 0, &d) == WE_OK, "baseline");
    rc = in_child(tmppath("routing.bin"), child_rewritten_under_the_descriptor);
    CHECK(rc >= 0, "the reader must not die of a signal; got signal %d", -rc);
    CHECK(rc == 0, "and every answer stays a valid index or no range (exit %d)", rc);

    /* n = 0 short-circuits: an empty IPv6 half answers no range before any index-derived load. */
    {
        we_map_t m;
        uint8_t a16[16];

        x.p.v6.n = 0u;
        CHECK(f2_load(&x, "routing.bin", NULL, 0, &d) == WE_OK, "an empty IPv6 family loads: %s",
              d.what ? d.what : "-");
        if (we_plane_open(tmppath("routing.bin"), &m, &d) == WE_OK) {
            memset(a16, 0xff, 16);
            CHECK(m.f6w.n == 0u && we_find6_64(&m, a16) == WE_NO_RANGE && we_find6(&m, a16) == WE_NO_RANGE,
                  "n = 0 answers no range");
            CHECK(m.f6w.idx != NULL, "and the descriptor is still safe to read");
            we_map_close(&m);
        }
        x.p.v6.n = F2_N6;
    }
}

/* ---- the performance criteria this core holds itself to ---- */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y);
}

static void test_performance(void)
{
    const uint32_t N = 120000u;   /* Tier 3 scale: the WORST case we would ever ship */
    rng_t *r = (rng_t *)malloc(sizeof(rng_t) * N);
    uint32_t i;
    uint32_t cur = 1000u;
    int mode;

    SECTION("performance: p99 lookup, cold start, resident size");

    for (i = 0; i < N; i++) {
        r[i].start = cur;
        r[i].end = cur + 255u;
        r[i].sev = WE_SEV_HIGH;
        cur += 256u + (rnd32() % 30000u);
        if (cur > 0xfff00000u) { break; }
    }
    { uint32_t n = i; printf("  fixture: %u ranges (%.1f KB of range data)\n", n, (double)n * 9.0 / 1024.0);

    for (mode = 0; mode < 2; mode++) {
        we_map_t m;
        int rc;
        uint64_t t0, t1;
        struct stat st;

        CHECK(write_snapshot(tmppath("perf.snap"), r, n, NULL, 0, mode, 1, 0, NULL, 0, NULL) == 0, "write");
        stat(tmppath("perf.snap"), &st);

        /*
         * LOAD TIME, not "cold start". The comment here used to say it dropped the page cache
         * influence and the code did nothing of the kind - it just timed we_map_open on a file that
         * had been written moments earlier, so every figure ever quoted as a cold start was a
         * warm-cache number, mislabelled. Measuring a genuinely cold start needs either root
         * (drop_caches) or posix_fadvise(DONTNEED) and a separate fd; until one of those is here, this
         * is load-and-verify time on a warm page cache and is labelled as such.
         */
        /*
         * The claim is the work, not the time: load+verify digests the file in ONE pass, so it runs
         * exactly the compression blocks one SHA-256 of `size` bytes needs, ceil((size + 9) / 64), and
         * the rest of the verification is the structure walk, linear in the ranges and gated by the
         * trace build's per-read model. A wall-clock budget asserted here failed on a loaded box with
         * nothing wrong (75 ms against 50, the same row 8 to 29 ms re-run), so the time is printed and
         * never asserted. WE_TEST_EXTRA_VERIFY_PASS, a second digest pass, is this row's control.
         */
        we_sha256_blocks = 0u;
        t0 = now_ns();
        rc = we_map_open(tmppath("perf.snap"), &m);
        t1 = now_ns();
        CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
        if (rc != WE_OK) { continue; }
        printf("  %-12s file %6.1f KB   load+verify (warm cache) %6.2f ms, %llu digest blocks (printed, not asserted)\n",
               mode ? "WITH index" : "no index", (double)st.st_size / 1024.0,
               (double)(t1 - t0) / 1e6, (unsigned long long)we_sha256_blocks);
        CHECK(we_sha256_blocks == ((uint64_t)st.st_size + 9u + 63u) / 64u,
              "load+verify: %llu digest blocks for a %lld-byte file, not the one pass's %llu",
              (unsigned long long)we_sha256_blocks, (long long)st.st_size,
              (unsigned long long)(((uint64_t)st.st_size + 9u + 63u) / 64u));

        /* throughput and tail latency. Batched, because a clock_gettime per lookup costs more than
         * the lookup does; the batch size is stated so the number cannot be read as more precise
         * than it is. */
        {
            const int BATCH = 32;
            const int ROUNDS = 40000;
            uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * (size_t)ROUNDS);
            volatile uint8_t sink = 0;
            int k, j;
            uint64_t sum = 0;

            /* warm the cache the way real traffic would */
            for (k = 0; k < 200000; k++) { sink = (uint8_t)(sink + we_lookup4(&m, rnd32())); }

            for (k = 0; k < ROUNDS; k++) {
                uint32_t a[32];
                for (j = 0; j < BATCH; j++) { a[j] = rnd32(); }
                t0 = now_ns();
                for (j = 0; j < BATCH; j++) { sink = (uint8_t)(sink + we_lookup4(&m, a[j])); }
                t1 = now_ns();
                samples[k] = (t1 - t0) / (uint64_t)BATCH;
                sum += samples[k];
            }
            qsort(samples, (size_t)ROUNDS, sizeof(uint64_t), cmp_u64);
            /*
             * These are per-lookup figures derived from BATCH means, and that is a real limitation
             * rather than a footnote: a p99 of batch means is structurally blind to a tail. Injecting
             * a stall into 2% of lookups put the true p99 at 576 ns and this harness reported 57 and
             * passed. The number below is therefore a sound MEAN and an unsound p99, and the
             * assertion that follows is kept only as a mean gate. The claim that actually holds is
             * the structural probe bound asserted above.
             */
            printf("  %-12s mean %3" PRIu64 " ns   p50 %3" PRIu64 "   p90 %3" PRIu64
                   "   p99 %3" PRIu64 "   p99.9 %4" PRIu64 " ns  (per-lookup figures derived from"
                   " batches of %d: a sound mean, NOT a sound p99)\n",
                   mode ? "WITH index" : "no index",
                   sum / (uint64_t)ROUNDS, samples[ROUNDS / 2], samples[(ROUNDS * 9) / 10],
                   samples[(ROUNDS * 99) / 100], samples[(ROUNDS * 999) / 1000], BATCH);
            /*
             * Printed, never asserted: a wall-clock mean reds a loaded box with nothing wrong. The
             * lookup's cost is gated deterministically elsewhere: the probe bound above, the trace
             * build's model of every memory read (whose extra-window mutant, test_mutant, must fail),
             * and the cachegrind gate's per-lookup instruction and data-reference rows on both
             * architectures.
             */
            free(samples);
            (void)sink;
        }
        /* resident cost: the mapping is read-only and file-backed, so N workers share one copy */
        CHECK((uint64_t)st.st_size < 16ull * 1024ull * 1024ull,
              "snapshot %.1f MB exceeds the 16 MB budget", (double)st.st_size / 1048576.0);
        we_map_close(&m);
    }
    }
    free(r);
}

/* ---- v6 correctness against an independent oracle, both index modes ---- */
typedef struct { __uint128_t addr; uint8_t len; uint8_t sev; } pfx6_t;

static __uint128_t mask6(uint8_t len)
{
    if (len == 0) { return (__uint128_t)0; }
    if (len >= 128) { return ~(__uint128_t)0; }
    return (~(__uint128_t)0) << (128 - len);
}

static uint8_t oracle6(const pfx6_t *p, int n, __uint128_t a)
{
    int best = -1, i;
    uint8_t bestlen = 0;

    for (i = 0; i < n; i++) {
        __uint128_t mk = mask6(p[i].len);
        if ((a & mk) == (p[i].addr & mk)) {
            if (best < 0 || p[i].len > bestlen) { best = i; bestlen = p[i].len; }
        }
    }
    return (best < 0) ? WE_SEV_NONE : p[best].sev;
}

static int cmp_u128(const void *a, const void *b)
{
    __uint128_t x = *(const __uint128_t *)a, y = *(const __uint128_t *)b;
    return (x < y) ? -1 : (x > y);
}

static void put6(v6a_t *out, __uint128_t v)
{
    int k;
    for (k = 15; k >= 0; k--) { out->a[k] = (uint8_t)(v & 0xffu); v >>= 8; }
}

static __uint128_t rnd128_global(void)
{
    /* Weighted towards 2000::/3, where global unicast and therefore every real verdict lives. */
    __uint128_t v = 0;
    int k;
    for (k = 0; k < 4; k++) { v = (v << 32) | rnd32(); }
    if ((rnd32() & 3u) != 0u) {
        v = (v & ~(((__uint128_t)0xe000u) << 112)) | (((__uint128_t)0x2000u) << 112);
    }
    return v;
}

static void test_v6_against_oracle(int with_index, int trials)
{
    int t;

    SECTION(with_index ? "v6 lookup vs oracle, WITH bucket index" : "v6 lookup vs oracle, no index");
    for (t = 0; t < trials; t++) {
        pfx6_t p[24];
        rng6_t r[512];
        __uint128_t pts[64];
        int n = 1 + (int)(rnd32() % 24u), np = 0, nr = 0, i;
        we_map_t m;
        int rc;

        for (i = 0; i < n; i++) {
            p[i].len = (uint8_t)(rnd32() % 129u);
            p[i].addr = rnd128_global();
            p[i].sev = (uint8_t)(1u + (rnd32() % 4u));
        }
        /* elementary intervals, same construction as v4 */
        pts[np++] = 0;
        for (i = 0; i < n; i++) {
            __uint128_t mk = mask6(p[i].len);
            __uint128_t lo = p[i].addr & mk;
            __uint128_t hi = lo | ~mk;
            pts[np++] = lo;
            if (hi != ~(__uint128_t)0) { pts[np++] = hi + 1; }
        }
        qsort(pts, (size_t)np, sizeof(__uint128_t), cmp_u128);
        for (i = 0; i < np; i++) {
            __uint128_t lo, hi;
            uint8_t sev;
            int j;

            if (i > 0 && pts[i] == pts[i - 1]) { continue; }
            lo = pts[i];
            hi = ~(__uint128_t)0;
            for (j = i + 1; j < np; j++) { if (pts[j] > lo) { hi = pts[j] - 1; break; } }
            sev = oracle6(p, n, lo);
            if (sev == WE_SEV_NONE) { continue; }
            if (nr > 0 && r[nr - 1].sev == sev) {
                __uint128_t prev_end = 0;
                int k;
                for (k = 0; k < 16; k++) { prev_end = (prev_end << 8) | r[nr - 1].end.a[k]; }
                if (prev_end + 1 == lo) { put6(&r[nr - 1].end, hi); continue; }
            }
            put6(&r[nr].start, lo);
            put6(&r[nr].end, hi);
            r[nr].sev = sev;
            nr++;
        }
        if (nr == 0) { continue; }

        CHECK(write_snapshot(tmppath("t6.snap"), NULL, 0, r, (uint32_t)nr, with_index,
                             (uint64_t)t + 1u, 0, NULL, 0, NULL) == 0, "write failed");
        rc = we_map_open(tmppath("t6.snap"), &m);
        CHECK(rc == WE_OK, "open: %s", we_strerror(rc));
        if (rc != WE_OK) { continue; }

        for (i = 0; i < nr; i++) {
            __uint128_t sv = 0, ev = 0;
            v6a_t probe;
            int k, q;
            for (k = 0; k < 16; k++) { sv = (sv << 8) | r[i].start.a[k]; ev = (ev << 8) | r[i].end.a[k]; }
            for (q = 0; q < 4; q++) {
                __uint128_t a = (q == 0) ? sv : (q == 1) ? ev
                              : (q == 2) ? (sv > 0 ? sv - 1 : 0)
                              : (ev != ~(__uint128_t)0 ? ev + 1 : ev);
                uint8_t want, got;
                put6(&probe, a);
                want = oracle6(p, n, a);
                got = we_lookup6(&m, probe.a);
                CHECK(got == want, "trial %d boundary q=%d: got 0x%02x want 0x%02x", t, q, got, want);
            }
        }
        for (i = 0; i < 2000; i++) {
            __uint128_t a = rnd128_global();
            v6a_t probe;
            uint8_t want, got;
            put6(&probe, a);
            want = oracle6(p, n, a);
            got = we_lookup6(&m, probe.a);
            CHECK(got == want, "trial %d random: got 0x%02x want 0x%02x", t, got, want);
        }
        we_map_close(&m);
    }
}

/*
 * we_map_rebase() moves EVERY pointer field into the new buffer: each field the scan of we_map_t finds
 * (we_map_fields.h, generated by gen-map-fields.py and held to whisper_edge.h by make check) is pointed at
 * its own place in the old buffer, the map is rebased, and each must name the same place in the new one;
 * a pointer outside the old buffer (a static table) stays where it was, and base moves last.
 */
static void test_rebase_moves_every_pointer(void)
{
    static uint8_t oldb[4096] __attribute__((aligned(64))), newb[4096] __attribute__((aligned(64)));
    static const uint8_t outside[8] = { 0 };
    static we_map_t m;
    uint32_t k = 0u, n = 0u;

    memset(&m, 0, sizeof m);
    m.base = oldb;
    m.len = sizeof oldb;
#define WE_MAP_FIELD(f) m.f = (__typeof__(m.f))(const void *)(oldb + 8u * ++k);
#include "we_map_fields.h"
#undef WE_MAP_FIELD
    we_map_rebase(&m, newb);
    k = 0u;
#define WE_MAP_FIELD(f) \
    k++; \
    n++; \
    CHECK((const uint8_t *)(const void *)m.f == newb + 8u * k, "rebase: " #f " still points into the old buffer");
#include "we_map_fields.h"
#undef WE_MAP_FIELD
    CHECK(m.base == (const void *)newb && n >= 31u, "rebase: base did not move, or the scan listed %u fields", n);
    m.country_known = outside;
    we_map_rebase(&m, oldb);
    CHECK(m.country_known == outside, "rebase: a pointer outside the buffer was moved");
}

/* the writer's pid namespace: the stat, and the link's text when the stat is refused; a malformed text
 * gives nothing, never a garbage inode */
static void test_pidns_from_the_link(void)
{
    static const struct { const char *t; uint64_t want; } ok[] = {
        { "pid:[4026531836]", 4026531836ull }, { "pid:[1]", 1ull },
        { "pid:[18446744073709551615]", 18446744073709551615ull },
    };
    static const char *const bad[] = {
        "", "pid:[]", "pid:[0]", "pid:[00]", "pid:[12a]", "pid:[1", "pid:1]", "net:[4026531836]", " pid:[1]",
        "pid:[1] ", "pid:[-1]", "pid:[+1]", "pid:[18446744073709551616]", "pid:[184467440737095516150]",
        "pid:[99999999999999999999]", "pid:[4026531836]\n",
    };
    struct stat st;
    size_t i;

    printf("== the writer's pid namespace: the stat, and the link's text when the stat is refused ==\n");
    for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        uint64_t ino = 7u;

        CHECK(we_proc_ns_link_ino(ok[i].t, strlen(ok[i].t), &ino) == 0 && ino == ok[i].want,
              "pidns link: \"%s\" did not read as %llu (got %llu)", ok[i].t, (unsigned long long)ok[i].want,
              (unsigned long long)ino);
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        uint64_t ino = 7u;

        CHECK(we_proc_ns_link_ino(bad[i], strlen(bad[i]), &ino) == -1 && ino == 7u,
              "pidns link: the malformed \"%s\" read as an inode (%llu)", bad[i], (unsigned long long)ino);
    }
    /* the whole path: what a writer names is the namespace's inode, through the link, or (with the link
     * refused, WE_TEST_PIDNS_READLINK_DENIED) through the stat; with both refused, nothing */
    if (stat("/proc/self/ns/pid", &st) == 0) {
        we_procid_t id;
        uint64_t got;
#if defined(WE_TEST_PIDNS_READLINK_DENIED) && defined(WE_TEST_PIDNS_STAT_DENIED)
        const uint64_t want = 0u;
#else
        const uint64_t want = (uint64_t)st.st_ino;
#endif

        ts_ns_stats = 0;
        ts_stat_armed = 1;
        got = we_proc_pidns();
        ts_stat_armed = 0;
        CHECK(got == want, "pidns: the writer names %llu, and the namespace's inode is %llu (want %llu)",
              (unsigned long long)got, (unsigned long long)st.st_ino, (unsigned long long)want);
        CHECK(we_proc_id(&id) == 0 && id.pidns == want,
              "pidns: the process identity carries %llu, not %llu", (unsigned long long)id.pidns,
              (unsigned long long)want);
#if !defined(WE_TEST_PIDNS_READLINK_DENIED) && !defined(WE_TEST_PIDNS_NO_READLINK)
        /* the normal path reads the link and never stats the namespace: no getattr, so no AVC record on a
         * confined host */
        CHECK(ts_ns_stats == 0, "pidns: naming the namespace made %d stat() call(s) on /proc/self/ns/pid; "
              "the link alone should answer", ts_ns_stats);
#endif
    } else {
        CHECK(0, "pidns: this test cannot stat /proc/self/ns/pid to know the inode; the rows did not run");
    }
#if defined(WE_TEST_PIDNS_READLINK_DENIED) && defined(WE_TEST_PIDNS_STAT_DENIED)
    printf("  (the link and the stat refused: the writer names no namespace)\n");
#elif defined(WE_TEST_PIDNS_READLINK_DENIED)
    printf("  (the link refused: the inode above came from the stat)\n");
#endif
}

int main(int argc, char **argv)
{
    TMPDIR_ = (argc > 1) ? argv[1] : "/tmp";
    printf("whisper edge core, acceptance tests \n");

    test_sha256();
    test_fail_open();
    test_policy();
    test_edges();
    test_spanning_prefix();
    test_v6();
    test_staleness();
    test_evidence();
    test_counters();
    test_lookup_against_oracle(0, 60);
    test_lookup_against_oracle(1, 60);
    test_v6_against_oracle(0, 40);
    test_v6_against_oracle(1, 40);
    test_chaos();
    test_hostile_offsets();
    test_a_writable_snapshot_is_refused();
    test_blob_must_terminate_inside_the_file();
    test_in_place_rewrite_under_a_live_snapshot();
    test_swap_and_retire();
    test_a_failed_slot_claim_leaves_the_occupant_alone();
    test_probe_bound_is_a_property_of_the_file();
    test_format1_with_schema();
    test_format2_planes();
    test_format2_refusals();
    test_format2_feed_table();
    test_format2_layout_pins();
    test_rebase_moves_every_pointer();
    test_clamp_under_a_rewritten_mapping();
    test_performance();
    test_pidns_from_the_link();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
