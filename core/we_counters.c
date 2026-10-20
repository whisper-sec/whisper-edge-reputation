/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * we_counters.c - the per-range denial counters behind the weekly summary.
 *
 * The contract, the reasoning and the reason none of this is in the lookup are in whisper_edge.h
 * above we_counters_new. What is here is the mechanism.
 *
 * NOTHING IN THIS FILE MAY COST AN ANSWER. Every function is a no-op on a NULL counter set, on an
 * allocation that failed, on a generation that has moved on, and on an address in no range. The
 * module keeps serving with no counters exactly as it served before they existed; a summary is a
 * nice-to-have and a verdict is the product.
 *
 * RELAXED ATOMIC INCREMENTS, the same WE_COUNT the handle's own counters use. nginx and
 * OpenLiteSpeed are one request at a time per worker process, but the Apache worker and event MPMs
 * put many threads in one process against one counter set - so a plain `++` would be a data race.
 *
 * The reason that matters is not the lost update. A lost update costs an undercount of a reporting
 * figure, which nobody bills on. It is the WRITER: we_counters_write reads every counter while other
 * threads are incrementing them, and a 64-bit read torn across a 32-bit load pair - armv7 and
 * OpenWrt are exactly the population this is aimed at - yields a number that is not any value the
 * counter ever held. An absurd figure in a report somebody pastes into a chat is worse than a
 * missing one, and it is unexplainable afterwards.
 *
 * Relaxed is the right ordering: these are counters, nothing is published through them, and the
 * cost is one locked add on the DENY path, which is rare by construction and already pays for a log
 * line. There is no atomic anywhere near the lookup - core/hotpath-gate.sh fails the build on one.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "whisper_edge.h"
#include "we_procid.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

we_counters_t *we_counters_new(const we_map_t *m, uint64_t now_ms)
{
    we_counters_t *c;

    /*
     * Format 1 only. The counters are the reputation plane's weekly summary and they print sev[] and
     * end[]; a format-2 plane has neither, and by design the routing plane does not
     * instantiate counters at all (8 bytes per range is 11.7 MB per worker for a number nobody reads).
     * NULL is "no counting", which every caller already handles.
     */
    if (m == NULL || (m->h != NULL && m->h->format != WE_FORMAT_1)) {
        return NULL;
    }
    c = (we_counters_t *) calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->started_ms = now_ms;
    c->generation = m->h == NULL ? 0u : m->h->generation;
    c->v4_count = m->v4_count;
    c->v6_count = m->v6_count;
    if (c->v4_count > 0) {
        c->v4_hits = (uint64_t *) calloc(c->v4_count, sizeof(uint64_t));
        if (c->v4_hits == NULL) {
            we_counters_free(c);
            return NULL;
        }
    }
    if (c->v6_count > 0) {
        c->v6_hits = (uint64_t *) calloc(c->v6_count, sizeof(uint64_t));
        if (c->v6_hits == NULL) {
            we_counters_free(c);
            return NULL;
        }
    }
    return c;
}

void we_counters_free(we_counters_t *c)
{
    if (c == NULL) {
        return;
    }
    free(c->v4_hits);
    free(c->v6_hits);
    free(c);
}

/*
 * The one guard both counters share: are these indices still the shape this mapping has?
 *
 * A snapshot reload renumbers the ranges, so a counter set built against the previous generation
 * indexes nothing meaningful. The module is expected to rebuild the set on reload; this is here so
 * that a module which forgets UNDERCOUNTS rather than attributing a hit to whichever network happens
 * to hold that index now. A wrong number in a summary an operator pastes into a chat is worse than a
 * missing one.
 */
static int matches(const we_counters_t *c, const we_map_t *m)
{
    return c != NULL && m != NULL && m->h != NULL && c->generation == m->h->generation
            && c->v4_count == m->v4_count && c->v6_count == m->v6_count;
}

void we_counters_count4(we_counters_t *c, const we_map_t *m, uint32_t addr)
{
    int i;

    if (!matches(c, m) || c->v4_hits == NULL) {
        return;
    }
    i = we_range4(m, addr);
    if (i < 0) {
        return;
    }
    WE_COUNT(c->v4_hits[i]);
    WE_COUNT(c->denied);
}

void we_counters_count6(we_counters_t *c, const we_map_t *m, const uint8_t addr[16])
{
    int i;

    if (!matches(c, m) || c->v6_hits == NULL) {
        return;
    }
    i = we_range6(m, addr);
    if (i < 0) {
        return;
    }
    WE_COUNT(c->v6_hits[i]);
    WE_COUNT(c->denied);
}

/*
 * THE FILE FORMAT, which is deliberately text.
 *
 * A binary format would be smaller and would need a reader before anybody could see whether the
 * thing works. This is a blocklist for small hosts; the operator who installs it debugs with `cat`.
 * So the file is lines an operator can read, the tool parses the same lines, and the format is its
 * own documentation:
 *
 *   whisper-edge-counters 1
 *   pidns 4026531836 starttime 81234567
 *   started 1760000000000
 *   written 1760000600000
 *   pid 4242
 *   generation 497653
 *   denied 1234
 *   4 203.0.113.0/24 3 912 ransomware c2, confirmed 2026-10-02
 *   6 2001:db8::/32 2 322 scanner, first seen 2026-09-30
 *
 * `pid` names the process that wrote the record, the number the file name starts with, so a record
 * that has been copied out of its file (pasted, or concatenated with the others) still says whose it
 * is; `pidns` and `starttime` tell that process from a later one that reused its number.
 * A reader that predates it skips it as an unknown line, which is how every reader of this format
 * treats a key it does not know.
 *
 * A range line is: family, prefix (or first-last when the range is not a CIDR block), severity, hit
 * count, then the evidence string to the end of the line. Zero-hit ranges are omitted, which is what
 * keeps the file proportional to what was actually seen rather than to the size of the feed.
 */
#define WE_COUNTERS_MAGIC "whisper-edge-counters 1"

/* 203.0.113.0 -> dotted quad, into buf. */
static void v4_text(uint32_t a, char *buf, size_t n)
{
    snprintf(buf, n, "%u.%u.%u.%u",
             (unsigned)((a >> 24) & 0xffu), (unsigned)((a >> 16) & 0xffu),
             (unsigned)((a >> 8) & 0xffu), (unsigned)(a & 0xffu));
}

/*
 * A range back to the prefix it came from, when it IS one, and to first-last when it is not.
 *
 * The build resolves nesting by splitting, so a /8 with a /24 carved out of it becomes three ranges
 * and the outer two are not CIDR blocks at all. Printing those as a prefix would be a lie about what
 * is listed, and the operator pasting the summary into a chat is the last person who should be the
 * one to discover that. So: a range whose length is a power of two and whose start is aligned to it
 * prints as a prefix, and everything else prints as what it is.
 */
static void v4_range_text(uint32_t start, uint32_t end, char *buf, size_t n)
{
    uint64_t span = (uint64_t) end - (uint64_t) start + 1ull;
    char a[16], b[16];

    v4_text(start, a, sizeof(a));
    if ((span & (span - 1ull)) == 0ull && ((uint64_t) start % span) == 0ull) {
        int bits = 32;
        uint64_t s = span;

        while (s > 1ull) {
            s >>= 1;
            bits--;
        }
        snprintf(buf, n, "%s/%d", a, bits);
        return;
    }
    v4_text(end, b, sizeof(b));
    snprintf(buf, n, "%s-%s", a, b);
}

/* The 16 bytes of a __uint128_t address, most significant first. */
static void v6_bytes(__uint128_t a, uint8_t out[16])
{
    int i;

    for (i = 15; i >= 0; i--) {
        out[i] = (uint8_t)(a & 0xffu);
        a >>= 8;
    }
}

/* Full-form IPv6, eight groups. Not the RFC 5952 short form: unambiguous beats pretty in a report. */
static void v6_text(__uint128_t a, char *buf, size_t n)
{
    uint8_t b[16];
    int i;
    size_t off = 0;

    v6_bytes(a, b);
    for (i = 0; i < 16; i += 2) {
        int wrote = snprintf(buf + off, off < n ? n - off : 0u, "%s%02x%02x",
                             i == 0 ? "" : ":", b[i], b[i + 1]);
        if (wrote < 0) {
            break;
        }
        off += (size_t) wrote;
        if (off >= n) {
            break;
        }
    }
}

static void v6_range_text(__uint128_t start, __uint128_t end, char *buf, size_t n)
{
    __uint128_t span = end - start + 1;
    char a[48], b[48];

    v6_text(start, a, sizeof(a));
    if ((span & (span - 1)) == 0 && (start % span) == 0) {
        int bits = 128;
        __uint128_t s = span;

        while (s > 1) {
            s >>= 1;
            bits--;
        }
        snprintf(buf, n, "%s/%d", a, bits);
        return;
    }
    v6_text(end, b, sizeof(b));
    snprintf(buf, n, "%s-%s", a, b);
}

/* The evidence line for a range, with newlines stripped: one record is one line, by construction. */
static void evidence_line(const char *ev, char *buf, size_t n)
{
    size_t i = 0;

    if (ev == NULL) {
        buf[0] = '\0';
        return;
    }
    while (ev[i] != '\0' && i + 1 < n) {
        char ch = ev[i];

        buf[i] = (ch == '\n' || ch == '\r') ? ' ' : ch;
        i++;
    }
    buf[i] = '\0';
}

int we_counters_write(const we_counters_t *c, const we_map_t *m, const char *dir, uint64_t now_ms)
{
    char tmp[96], final[64];
    FILE *f;
    uint32_t i;
    int dfd, fd;
    we_procid_t id;
    struct stat st;

    if (c == NULL || m == NULL || dir == NULL) {
        return WE_ERR_OPEN;
    }
    if (!matches(c, m)) {
        /* The counters belong to a snapshot that is no longer published. Writing them out against
         * THIS mapping's prefixes would attribute every hit to whatever network now holds that
         * index, so there is nothing honest to write and this is not an error worth logging. */
        return WE_OK;
    }
    /*
     * NEVER THROUGH A PLANTED NAME. The directory is writable by every server user, so the file is named
     * by the process (`<pid>-<16 hex>.cnt`, we_procid.h), its temp is created O_EXCL | O_NOFOLLOW relative
     * to the directory's descriptor and renamed into place, and a writer running as root writes only into
     * a directory root owns and nobody else may write. The second line names the writer, so the summary
     * can tell a gone writer's file from a live one's.
     */
    if (we_proc_id(&id) != 0) {
        return WE_ERR_OPEN;
    }
    dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        return WE_ERR_OPEN;
    }
    if (geteuid() == 0u && (fstat(dfd, &st) != 0 || st.st_uid != 0u || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u)) {
        close(dfd);
        return WE_ERR_PERMISSIONS;
    }
    snprintf(final, sizeof final, "%llu-%s.cnt", (unsigned long long)id.pid, id.id16);
    fd = we_proc_tmp_open(dfd, &id, "cnt", tmp);
    f = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (f == NULL) {
        if (fd >= 0) {
            close(fd);
            unlinkat(dfd, tmp, 0);
        }
        close(dfd);
        return WE_ERR_OPEN;
    }
    fprintf(f, "%s\n", WE_COUNTERS_MAGIC);
    fprintf(f, "pidns %llu starttime %llu\n", (unsigned long long)id.pidns, (unsigned long long)id.starttime);
    fprintf(f, "started %" PRIu64 "\n", c->started_ms);
    fprintf(f, "written %" PRIu64 "\n", now_ms);
    fprintf(f, "pid %llu\n", (unsigned long long)id.pid);
    fprintf(f, "generation %" PRIu64 "\n", c->generation);
    fprintf(f, "denied %" PRIu64 "\n", __atomic_load_n(&c->denied, __ATOMIC_RELAXED));
    for (i = 0; i < c->v4_count; i++) {
        char range[48], ev[512];

        uint64_t hits;

        if (c->v4_hits == NULL) {
            continue;
        }
        hits = __atomic_load_n(&c->v4_hits[i], __ATOMIC_RELAXED);
        if (hits == 0u) {
            continue;
        }
        v4_range_text(m->v4_start[i], m->v4_end[i], range, sizeof(range));
        evidence_line(we_evidence4(m, m->v4_start[i]), ev, sizeof(ev));
        fprintf(f, "4 %s %u %" PRIu64 " %s\n", range, (unsigned) m->v4_sev[i], hits, ev);
    }
    for (i = 0; i < c->v6_count; i++) {
        char range[128], ev[512];
        uint8_t first[16];

        uint64_t hits;

        if (c->v6_hits == NULL) {
            continue;
        }
        hits = __atomic_load_n(&c->v6_hits[i], __ATOMIC_RELAXED);
        if (hits == 0u) {
            continue;
        }
        v6_range_text(m->v6_start[i], m->v6_end[i], range, sizeof(range));
        v6_bytes(m->v6_start[i], first);
        evidence_line(we_evidence6(m, first), ev, sizeof(ev));
        fprintf(f, "6 %s %u %" PRIu64 " %s\n", range, (unsigned) m->v6_sev[i], hits, ev);
    }
    /*
     * FLUSH, THEN CHECK, THEN RENAME. A failed write that is renamed into place replaces a good
     * file with a truncated one, and the summary tool would then read a short count as the truth.
     * ferror after fclose is too late, so the order is explicit.
     */
    if (fflush(f) != 0 || ferror(f) != 0) {
        fclose(f);
        unlinkat(dfd, tmp, 0);
        close(dfd);
        return WE_ERR_OPEN;
    }
    if (fclose(f) != 0 || renameat(dfd, tmp, dfd, final) != 0) {
        unlinkat(dfd, tmp, 0);
        close(dfd);
        return WE_ERR_OPEN;
    }
    close(dfd);
    return WE_OK;
}
