/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * fuzz_walk - the trusted-header walk (we_module.h) under libFuzzer, ASan and UBSan.
 *
 * One input is a peer, a trust list, a hop count, two flags and up to 32 field lines. Each line is
 * copied into its OWN malloc(len) with no terminator before the walk sees it, so a read one byte past a
 * line reaches the end of an allocation and ASan reports it. Then, on every input:
 *
 *   span      a judged entry's (line, offset, length) lies inside that line, and its bytes, parsed again
 *             by the grammar, are the judged address; when no entry was judged the floor is the peer
 *             (or `::` for a trusted unix peer), and nothing else
 *   trust     the peer's classification, and every entry's, through the merged table equals a LINEAR scan
 *             of the prefixes as configured
 *   bound     at most 16 entries, 1,024 bytes and 17 binary searches
 *   table     the outcome is one of the walk table's rows: a note never comes with eligibility, NO_ADDRESS
 *             only for an untrusted or unconfigured unix peer, FLOOR_HEADER_MISSING only with the peer
 *
 * Without libFuzzer it is a replay harness: `fuzz_walk_replay --replay <dir>` runs every file in the
 * directory, and `--seeds <dir>` writes the seed corpus (the walk table's rows) there first.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "we_module.h"
#include "walk_classes.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FW_LINES 32u
#define FW_PREFIXES 12u

typedef struct {
    uint8_t b[16];
    uint8_t fam, len;
} fw_prefix_t;

static void fw_fail(const char *what)
{
    fprintf(stderr, "fuzz_walk: %s\n", what);
    abort();
}

/* a prefix as configured, matched by a linear scan: the reference the merged table must equal */
static int fw_linear(const fw_prefix_t *p, uint32_t n, const we_addr_t *a)
{
    uint32_t i, k;

    for (i = 0u; i < n; i++) {
        uint32_t bits = p[i].fam == 4u ? 32u : 128u, len = p[i].len, ok = 1u;

        if (p[i].fam != a->family) {
            continue;
        }
        for (k = 0u; k < len && k < bits; k++) {
            if (((p[i].b[k / 8u] ^ a->b[k / 8u]) >> (7u - k % 8u)) & 1u) {
                ok = 0u;
                break;
            }
        }
        if (ok) {
            return 1;
        }
    }
    return 0;
}

/*
 * The input: [flags][hops][peer family][16 peer bytes][prefix count] then per prefix [family][16][len],
 * then the lines, separated by 0x0A. flags: bit 0 a unix peer, bit 1 the header configured, bit 2 older
 * lines dropped, bit 3 unix: is trusted.
 */
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    fw_prefix_t pre[FW_PREFIXES];
    const char *items[FW_PREFIXES + 1u];
    char text[FW_PREFIXES + 1u][64];
    we_mod_line_t lines[FW_LINES];
    uint8_t *own[FW_LINES];
    uint32_t np = 0u, nl = 0u, i, hops;
    we_addr_t peer;
    int unix_peer, header, older;
    we_mod_trust_t t;
    we_mod_walk_t w;
    char err[256];
    size_t at;

    if (n < 20u) {
        return 0;
    }
    unix_peer = d[0] & 1;
    header = (d[0] >> 1) & 1;
    older = (d[0] >> 2) & 1;
    hops = d[1] % (WE_MOD_HOPS_MAX + 1u);
    we_addr_canon(d + 3, (d[2] & 1u) ? 6 : 4, &peer);
    at = 20u;
    np = n > at ? d[at] % (FW_PREFIXES + 1u) : 0u;
    at++;
    for (i = 0u; i < np && at + 18u <= n; i++, at += 18u) {
        we_addr_t a;

        we_addr_canon(d + at + 1u, (d[at] & 1u) ? 6 : 4, &a);
        memcpy(pre[i].b, a.b, 16);
        pre[i].fam = a.family;
        pre[i].len = (uint8_t)(d[at + 17u] % (a.family == 4u ? 33u : 129u));
        if (a.family == 4u) {
            snprintf(text[i], sizeof text[i], "%u.%u.%u.%u/%u", a.b[0], a.b[1], a.b[2], a.b[3], pre[i].len);
        } else {
            char f[WE_ADDR_TEXT_MAX];

            we_addr_format(&a, f);
            snprintf(text[i], sizeof text[i], "%s/%u", f, pre[i].len);
        }
        items[i] = text[i];
    }
    np = i;
    if (d[0] & 8u) {
        items[np] = "unix:";
    }
    if (we_mod_trust_build(items, np + ((d[0] & 8u) ? 1u : 0u), &t, NULL, err, sizeof err) != 0) {
        fw_fail("the trust list built from formatted prefixes was refused");
    }
    while (at < n && nl < FW_LINES) {
        const uint8_t *e = memchr(d + at, 0x0A, n - at);
        size_t len = e != NULL ? (size_t)(e - (d + at)) : n - at;

        own[nl] = (uint8_t *)malloc(len > 0u ? len : 1u);   /* exactly the line: no terminator */
        if (own[nl] == NULL) {
            break;
        }
        memcpy(own[nl], d + at, len);
        lines[nl].p = own[nl];
        lines[nl].len = len;
        nl++;
        at += len + 1u;
    }
    we_mod_walk(&t, hops, header, unix_peer ? NULL : &peer, lines, nl, older, &w);

    /* bound */
    if (w.entries > WE_MOD_WALK_ENTRIES || w.bytes > WE_MOD_WALK_BYTES || w.searches > WE_MOD_WALK_ENTRIES + 1u) {
        fw_fail("the walk's bound was exceeded");
    }
    /* trust: the peer through the merged table against the linear scan */
    if (!unix_peer && (we_mod_trusted(&t, &peer, NULL) != 0) != fw_linear(pre, np, &peer)) {
        fw_fail("the merged table and the linear scan disagree on the peer");
    }
    /* span */
    if (w.line >= 0) {
        we_addr_t back;

        if ((uint32_t)w.line >= nl || (size_t)w.off + w.len > lines[w.line].len) {
            fw_fail("the judged span lies outside its line");
        }
        if (we_mod_entry_parse(lines[w.line].p + w.off, w.len, &back) != 0 || memcmp(&back, &w.floor, sizeof back) != 0) {
            fw_fail("the judged span does not parse to the judged address");
        }
        if (!unix_peer && hops == 0u && w.note == WE_MOD_NOTE_NONE && w.eligible == 1u
                && (we_mod_trusted(&t, &w.floor, NULL) != 0) != fw_linear(pre, np, &w.floor)) {
            fw_fail("the merged table and the linear scan disagree on the judged entry");
        }
        if (w.walk != WE_WALK_OK) {
            fw_fail("an entry was judged with a walk mark other than OK");
        }
    } else if (w.walk == WE_WALK_NO_ADDRESS) {
        if (!unix_peer || (header && (d[0] & 8u))) {
            fw_fail("no address for a peer the table says has one");
        }
    } else {
        we_addr_t zero;

        memset(&zero, 0, sizeof zero);
        zero.family = 6u;
        if (memcmp(&w.floor, unix_peer ? &zero : &peer, sizeof w.floor) != 0) {
            fw_fail("no entry was judged, and the floor is not the peer");
        }
    }
    /*
     * The peer judged on a header with lines: then nothing in the header parsed where the walk began.
     * An independent reading of the newest element, within the byte budget and within the line cap
     * (POLICY.md 3.9: the walk reads the newest WE_MOD_WALK_LINES lines and counts older ones as lines
     * not kept, so an entry below the cap is not one the walk could have reached): when it parses, the
     * walk had an entry and judging the peer drops it. The reading once walked every line, and the
     * fuzzer found the disagreement with an entry in the oldest of 32 lines; the seed
     * entry-below-line-cap keeps that input's shape.
     */
    if (w.walk == WE_WALK_FLOOR_HEADER_MISSING && w.note == WE_MOD_NOTE_UNPARSED) {
        size_t total = 0u;
        int32_t li, lo = nl > WE_MOD_WALK_LINES ? (int32_t)(nl - WE_MOD_WALK_LINES) : 0;

        for (i = 0u; i < nl; i++) {
            total += lines[i].len + 1u;
        }
        for (li = (int32_t)nl - 1; total <= WE_MOD_WALK_BYTES && li >= lo; li--) {
            const uint8_t *q = lines[li].p;
            size_t end = lines[li].len, s0;
            int found = 0;

            while (!found) {
                size_t s1, e1;

                for (s0 = end; s0 > 0u && q[s0 - 1u] != ','; s0--) {
                }
                for (s1 = s0; s1 < end && (q[s1] == ' ' || q[s1] == '\t'); s1++) {
                }
                for (e1 = end; e1 > s1 && (q[e1 - 1u] == ' ' || q[e1 - 1u] == '\t'); e1--) {
                }
                if (e1 > s1) {
                    we_addr_t a;

                    if (we_mod_entry_parse(q + s1, e1 - s1, &a) == 0) {
                        fw_fail("the peer was judged unparsed, but the newest entry parses");
                    }
                    found = 1;
                    break;
                }
                if (s0 == 0u) {
                    break;
                }
                end = s0 - 1u;
            }
            if (found) {
                break;
            }
        }
    }
    /* table */
    if (w.note != WE_MOD_NOTE_NONE && w.eligible != 0u) {
        fw_fail("a noted request kept its hold-harmless eligibility");
    }
    if (w.walk == WE_WALK_FLOOR_HEADER_MISSING && w.line >= 0) {
        fw_fail("FLOOR_HEADER_MISSING with an entry judged");
    }
    for (i = 0u; i < nl; i++) {
        free(own[i]);
    }
    we_mod_trust_free(&t);
    return 0;
}

#ifndef FZ_LIBFUZZER
/* the walk table's rows, as inputs: the seeds of the corpus */
static void fw_seed(const char *dir, const char *name, uint8_t flags, uint8_t hops, const char *peer,
                    const char *const *pfx, const char *body)
{
    uint8_t buf[4096];
    size_t o = 0u;
    char path[1024], addr[64];
    FILE *f;
    unsigned len;
    uint32_t i, np = 0u;

    memset(buf, 0, sizeof buf);
    buf[o++] = flags;
    buf[o++] = hops;
    buf[2] = strchr(peer, ':') != NULL ? 1u : 0u;      /* the peer's family: bit 0 set for IPv6 */
    if (inet_pton(buf[2] ? AF_INET6 : AF_INET, peer, buf + 3) != 1) {
        fprintf(stderr, "fuzz_walk: the seed %s's peer %s does not parse\n", name, peer);
        exit(2);
    }
    o = 20u;
    while (pfx[np] != NULL) {
        np++;
    }
    buf[o++] = (uint8_t)np;
    for (i = 0u; i < np; i++) {
        if (sscanf(pfx[i], "%63[^/]/%u", addr, &len) != 2) {
            fprintf(stderr, "fuzz_walk: the seed %s's prefix %s does not parse\n", name, pfx[i]);
            exit(2);
        }
        buf[o] = strchr(addr, ':') != NULL ? 1u : 0u;
        if (inet_pton(buf[o] ? AF_INET6 : AF_INET, addr, buf + o + 1u) != 1) {
            fprintf(stderr, "fuzz_walk: the seed %s's prefix %s does not parse\n", name, pfx[i]);
            exit(2);
        }
        buf[o + 17u] = (uint8_t)len;
        o += 18u;
    }
    memcpy(buf + o, body, strlen(body));
    o += strlen(body);
    snprintf(path, sizeof path, "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (f == NULL || fwrite(buf, 1, o, f) != o) {
        fprintf(stderr, "fuzz_walk: cannot write the seed %s\n", path);
        exit(2);
    }
    fclose(f);
}

/* the seeds in name order, so the first input a control trips is the same on every file system */
static int fw_replay(const char *dir)
{
    struct dirent **ents = NULL;
    int ne = scandir(dir, &ents, NULL, alphasort), i;
    unsigned n = 0u;

    if (ne < 0) {
        fprintf(stderr, "fuzz_walk: cannot read %s\n", dir);
        return 2;
    }
    for (i = 0; i < ne; i++) {
        struct dirent *e = ents[i];
        char path[1024];
        static uint8_t buf[1u << 16];
        FILE *f;
        size_t len;

        if (e->d_name[0] == '.') {
            free(e);
            continue;
        }
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        free(e);
        f = fopen(path, "rb");
        if (f == NULL) {
            continue;
        }
        len = fread(buf, 1, sizeof buf, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, len);
        n++;
    }
    free(ents);
    printf("%u checks, 0 failures\n", n);
    return n > 0u ? 0 : 1;
}

int main(int argc, char **argv)
{
    uint32_t i;

    if (argc == 3 && strcmp(argv[1], "--seeds") == 0) {
        for (i = 0u; i < WE_WALK_CLASSES; i++) {
            const we_walk_class_t *c = &we_walk_classes[i];

            fw_seed(argv[2], c->name, c->flags, c->hops, c->peer, we_wc_lists[c->list], c->body);
        }
        printf("fuzz_walk: %u seeds written to %s\n", (unsigned)WE_WALK_CLASSES, argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--replay") == 0) {
        return fw_replay(argv[2]);
    }
    fprintf(stderr, "usage: fuzz_walk_replay --seeds <dir> | --replay <dir>\n");
    return 2;
}
#endif /* FZ_LIBFUZZER */
