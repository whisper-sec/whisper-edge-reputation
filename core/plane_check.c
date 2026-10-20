/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * plane_check.c - hold the C reader to a plane the INDEPENDENT writer produced.
 *
 * make-test-snapshot.py --plane ... --expect FILE writes a plane (either format, any index kind) and,
 * for every range, the addresses that decide an outcome with the answer the reader must give: the
 * range index and the record's bytes, or `-`. This loads the plane through we_plane_open() and checks
 * every line through the hot path's own find, so a disagreement about any byte of the layout (a record
 * offset, the S-tree's slot order, the radix bucket of a 128-bit key, the 64-bit truncation) is a
 * failed line rather than an assumption two implementations happen to share.
 *
 * Usage: plane_check <plane.bin> <expect.txt>
 *        plane_check --fields <plane.bin> <expected.txt>
 *        plane_check --dump <plane.bin>
 *        plane_check --dump-full <plane.bin>
 *        plane_check --rpz-oracle <plane.bin> <zone file>
 *
 * The --fields form reads the Java builder's interop expectations: `family address 0` for no range,
 * `family address 1 <fields>` for a hit, the fields being the record's attributes in FORMAT.md order
 * (routing: asn country rov rir flags asn_rep; membership: flags source reason; format 1: the raw
 * `sev` byte, severity nibble and flag bits together).
 *
 * The writer's lines may carry a `fields=name=value,...` token after the record (make-test-snapshot.py
 * writes it from the record it packed). It must equal the record as the shared renderer
 * (we_record_fields.h, which whisper-edge-lookup prints through too) reads it from the loaded bytes, so
 * the field names are held to the bytes as well as the bytes to the writer.
 *
 * A line this cannot parse is a DISAGREEMENT, never skipped: an expectation file the checker silently
 * reads less of proves less than its summary says, and the count it prints would not show it. The
 * summary's line count is every line read, so a caller can hold it to the number of lines it wrote.
 *
 * The --dump form loads a plane through the same we_plane_open() (so every structural, domain and digest
 * refusal applies) and prints each range as `family first last flags`, inclusive, one per line, the flags
 * being the record's attribute bits (FORMAT.md 3: the membership record's flags, the routing record's
 * flags byte; 0 in format 1), followed by a
 * summary line on stderr. It is how a tool that needs a plane's address set reads one without a second
 * parser of the format: a reader that refuses the file prints nothing on stdout and exits 1. A 64-bit key
 * is printed as the full address range it stands for (the /64's first and last address).
 *
 * The --dump output is an interface: a deployed tool reads every stdout line as exactly four fields, so it
 * never changes. --dump-full is the superset for a person or a gate that needs the rest: the header's
 * `generation`, `valid_until_ms`, `built_at_ms` and `tier` as `<name> <value>` lines; one `feed <k> <name>`
 * line per entry of a format-2 feed-name table, the name written with every byte outside 0x21 to 0x7E, the
 * backslash and the double quote as \xHH (so a space, a newline or a non-ASCII byte cannot split or forge a
 * line, a name stays one token, a literal backslash cannot imitate an escape, and a name of two quote bytes
 * cannot imitate the empty one), and the empty name as ""; then the
 * ranges as --dump prints them with a fifth field, the membership record's `source`, or `-` for a record
 * that has none (format 1, routing). Same loader, same refusals, same exit codes.
 *
 * The --rpz-oracle form holds a policy zone to the plane it was written from: plane_check --rpz-oracle
 * <plane.bin> <zone file>. Both are step functions over the address line (an address is enforced or it
 * is not), so they agree everywhere exactly when they agree at every breakpoint of either and one
 * address either side. The probes are the first and last address of every plane range and of every
 * rpz-ip trigger, each with its neighbour outside; each probe is answered by the reader's own find on
 * the plane and by a per-family binary trie of the zone's rpz-ip triggers, longest prefix winning as RPZ
 * matches (`CNAME .` and `CNAME *.` enforce, `CNAME rpz-passthru.` exempts). The plane enforces a range
 * whose format-1 severity is above NONE and not inferred, and every range of a format-2 plane (a
 * membership plane such as rpki-unreachable has no severity). rpz-nsip triggers are counted and not
 * compared: the plane has no nameserver addresses. A trigger owner that does not parse, or names bits
 * below its prefix, is a disagreement, never skipped. The first disagreement printed is the lowest
 * address of its family; the exit is 0 only when every probe agrees and at least one was checked.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "whisper_edge.h"
#include "we_record_fields.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int hexbyte(const char *p)
{
    unsigned v;

    return sscanf(p, "%2x", &v) == 1 ? (int)v : -1;
}

/* One address through the hot path's own find, for the family the line names; 0 if it does not parse. */
static int find_line(const we_map_t *m, char fam, const char *addr, uint32_t *got)
{
    if (fam == '4') {
        struct in_addr a4;

        if (inet_pton(AF_INET, addr, &a4) != 1) {
            return 0;
        }
        *got = we_find4(m, ntohl(a4.s_addr));
        return 1;
    }
    if (fam == '6') {
        struct in6_addr a6;

        if (inet_pton(AF_INET6, addr, &a6) != 1) {
            return 0;
        }
        *got = m->f6w.n > 0u ? we_find6_64(m, (const uint8_t *)&a6) : we_find6(m, (const uint8_t *)&a6);
        return 1;
    }
    return 0;
}

static int fields_mode(const char *bin, const char *exp)
{
    we_map_t m;
    we_load_detail_t d;
    FILE *f;
    char line[512];
    int rc, lineno = 0, bad = 0, checked = 0, hits = 0;

    rc = we_plane_open(bin, &m, &d);
    if (rc != WE_OK) {
        fprintf(stderr, "PLANE CHECK FAIL: the reader refused %s: %s (%s, family %d, record %" PRId64 ")\n",
                bin, we_strerror(rc), d.what ? d.what : "-", d.family, d.record);
        return 1;
    }
    f = fopen(exp, "r");
    if (f == NULL) {
        fprintf(stderr, "PLANE CHECK FAIL: cannot read %s\n", exp);
        we_map_close(&m);
        return 1;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char fam, addr[80];
        int hit, n, used = 0, k, nf;
        unsigned long want[8], got_v[WE_RECORD_MAX_FIELDS];
        const char *names[WE_RECORD_MAX_FIELDS];
        uint32_t got;
        const char *p;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        if (sscanf(line, " %c %79s %d%n", &fam, addr, &hit, &used) < 3 || (hit != 0 && hit != 1)
            || !find_line(&m, fam, addr, &got)) {
            printf("  DISAGREE line %d: unparseable: %.60s\n", lineno, line);
            bad++;
            continue;
        }
        checked++;
        p = line + used;
        for (n = 0; n < 8 && sscanf(p, " %lu%n", &want[n], &k) == 1; n++) {
            p += k;
        }
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            p++;
        }
        if (*p != '\0' || (!hit && n != 0)) {
            printf("  DISAGREE line %d %s: unparseable field text: %.40s\n", lineno, addr, p);
            bad++;
            continue;
        }
        if ((got != WE_NO_RANGE) != (hit != 0)) {
            printf("  DISAGREE line %d %s: reader says %s, the builder says %s\n", lineno, addr,
                   got != WE_NO_RANGE ? "a range" : "no range", hit ? "a range" : "no range");
            bad++;
            continue;
        }
        if (!hit) {
            continue;
        }
        hits++;
        nf = we_record_values(&m, fam == '4' ? 4 : 6, got, names, got_v);
        if (n != nf) {
            printf("  DISAGREE line %d %s: %d fields expected, the schema has %d\n", lineno, addr, n, nf);
            bad++;
            continue;
        }
        for (k = 0; k < nf; k++) {
            if (want[k] != got_v[k]) {
                printf("  DISAGREE line %d %s: field %s is %lu, the builder wrote %lu\n", lineno, addr,
                       names[k], got_v[k], want[k]);
                bad++;
                break;
            }
        }
    }
    fclose(f);
    printf("plane check (builder fields) %s: format %u plane %u, %u IPv4 + %u IPv6 ranges, kinds %u/%u"
           " (k %u/%u), feeds %u: %d lines, %d hits, %d disagreements\n",
           bin, m.format, m.plane_id, m.v4_count, m.v6_count, m.f4.file_kind, we_family6(&m)->file_kind,
           m.f4.file_param, we_family6(&m)->file_param, m.feed_count, lineno, hits, bad);
    we_map_close(&m);
    return (bad == 0 && checked > 0 && hits > 0) ? 0 : 1;
}

/* The writer's `fields=` token against the record the reader returns, through the shared renderer. */
static int fields_token_ok(const we_map_t *m, char fam, uint32_t got, const char *tok, int lineno,
                           const char *addr)
{
    char have[256];

    if (we_record_render(m, fam == '4' ? 4 : 6, got, have, sizeof have) < 0) {
        printf("  DISAGREE line %d %s: the reader has no record to render for range %u\n", lineno, addr, got);
        return 0;
    }
    if (strcmp(have, tok) != 0) {
        printf("  DISAGREE line %d %s: the reader's fields are %s, the writer wrote %s\n", lineno, addr, have,
               tok);
        return 0;
    }
    return 1;
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Write a 128-bit key (hi, lo) in network order and print it. */
static void print6(uint64_t hi, uint64_t lo)
{
    uint8_t b[16];
    char s[INET6_ADDRSTRLEN];
    int i;

    for (i = 0; i < 8; i++) {
        b[i] = (uint8_t)(hi >> (56 - 8 * i));
        b[8 + i] = (uint8_t)(lo >> (56 - 8 * i));
    }
    inet_ntop(AF_INET6, b, s, sizeof s);
    fputs(s, stdout);
}

/* The record's attribute bits, for --dump: what a reader of the address set needs to tell a member apart. */
static unsigned long record_flags(const we_map_t *m, const we_fam_t *f, uint32_t i)
{
    const char *names[WE_RECORD_MAX_FIELDS];
    unsigned long v[WE_RECORD_MAX_FIELDS] = {0};
    int nf;

    if (m->format != 2u || f->records == NULL) {
        return 0;
    }
    nf = we_record_values(m, f == &m->f4 ? 4 : 6, i, names, v);
    if (m->schema_id == WE_SCHEMA_ROUTING) {
        return nf > 4 ? v[4] : 0;
    }
    return nf > 0 ? v[0] : 0;
}

/* The record's source, for --dump-full; -1 for a record that has none (format 1, routing). Read through
 * we_record_fields.h as record_flags is: a format-2 listing record's fields are flags, source, reason, in
 * FORMAT.md's order, so the source is the second value. */
static long record_source(const we_map_t *m, const we_fam_t *f, uint32_t i)
{
    const char *names[WE_RECORD_MAX_FIELDS];
    unsigned long v[WE_RECORD_MAX_FIELDS] = {0};
    int nf;

    if (m->format != 2u || f->records == NULL || m->schema_id == WE_SCHEMA_ROUTING) {
        return -1;
    }
    nf = we_record_values(m, f == &m->f4 ? 4 : 6, i, names, v);
    return nf > 1 ? (long)v[1] : -1;
}

/* A feed name as one token: bytes outside 0x21..0x7E, the backslash and the quote as \xHH, the empty one as "". */
static void print_name(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;

    if (*p == '\0') {
        fputs("\"\"", stdout);
        return;
    }
    for (; *p != '\0'; p++) {
        if (*p < 0x21u || *p > 0x7Eu || *p == '\\' || *p == '"') {
            printf("\\x%02X", *p);
        } else {
            fputc(*p, stdout);
        }
    }
}

static void print_source(long src)
{
    if (src < 0) {
        fputs(" -", stdout);
    } else {
        printf(" %ld", src);
    }
}

static int dump_mode(const char *bin, int full)
{
    we_map_t m;
    we_load_detail_t d;
    const we_fam_t *f6;
    uint32_t i;
    int rc;

    rc = we_plane_open(bin, &m, &d);
    if (rc != WE_OK) {
        fprintf(stderr, "PLANE CHECK FAIL: the reader refused %s: %s (%s, family %d, record %" PRId64 ")\n",
                bin, we_strerror(rc), d.what ? d.what : "-", d.family, d.record);
        return 1;
    }
    if (full) {
        uint32_t k;

        printf("generation %" PRIu64 "\n", m.h->generation);
        printf("valid_until_ms %" PRIu64 "\n", m.h->valid_until_ms);
        printf("built_at_ms %" PRIu64 "\n", m.h->built_at_ms);
        printf("tier %" PRIu32 "\n", m.h->tier);
        for (k = 0; k < m.feed_count; k++) {
            const char *name = we_feed_name(&m, k);

            printf("feed %" PRIu32 " ", k);
            print_name(name != NULL ? name : "");
            fputc('\n', stdout);
        }
    }
    for (i = 0; i < m.f4.n; i++) {
        struct in_addr a;
        char s[INET_ADDRSTRLEN], e[INET_ADDRSTRLEN];

        a.s_addr = htonl(le32(m.f4.start + 4u * i));
        inet_ntop(AF_INET, &a, s, sizeof s);
        a.s_addr = htonl(le32(m.f4.end + (size_t)m.f4.stride * i));
        inet_ntop(AF_INET, &a, e, sizeof e);
        printf("4 %s %s %lu", s, e, record_flags(&m, &m.f4, i));
        if (full) {
            print_source(record_source(&m, &m.f4, i));
        }
        fputc('\n', stdout);
    }
    f6 = we_family6(&m);
    for (i = 0; i < f6->n; i++) {
        uint64_t shi, slo, ehi, elo;

        if (f6->key_bits == 64u) {
            shi = le64(f6->start + 8u * i);
            slo = 0u;
            ehi = le64(f6->end + (size_t)f6->stride * i);
            elo = ~(uint64_t)0;
        } else {
            slo = le64(f6->start + 16u * i);
            shi = le64(f6->start + 16u * i + 8u);
            elo = le64(f6->end + (size_t)f6->stride * i);
            ehi = le64(f6->end + (size_t)f6->stride * i + 8u);
        }
        fputs("6 ", stdout);
        print6(shi, slo);
        fputc(' ', stdout);
        print6(ehi, elo);
        printf(" %lu", record_flags(&m, f6, i));
        if (full) {
            print_source(record_source(&m, f6, i));
        }
        fputc('\n', stdout);
    }
    fprintf(stderr, "plane dump %s: format %u plane %u generation %" PRIu64 ", %u IPv4 + %u IPv6 ranges\n",
            bin, m.format, m.plane_id, m.generation, m.f4.n, f6->n);
    we_map_close(&m);
    return 0;
}

/* ---- --rpz-oracle ---------------------------------------------------------------------------------- */

typedef struct {
    int32_t child[2];
    int8_t  action; /* -1 no trigger here, 0 passthru, 1 enforce */
} rz_node_t;

typedef struct {
    rz_node_t *n;
    size_t     len, cap;
} rz_trie_t;

typedef struct {
    uint8_t a[16];
} rz_key_t;

typedef struct {
    rz_key_t *k;
    size_t    len, cap;
} rz_keys_t;

static int32_t rz_new(rz_trie_t *t)
{
    if (t->len == t->cap) {
        size_t cap = t->cap ? t->cap * 2u : 1024u;
        rz_node_t *n = realloc(t->n, cap * sizeof *n);

        if (n == NULL) {
            return -1;
        }
        t->n = n;
        t->cap = cap;
    }
    t->n[t->len].child[0] = t->n[t->len].child[1] = -1;
    t->n[t->len].action = -1;
    return (int32_t)t->len++;
}

static int rz_bit(const uint8_t *a, unsigned i)
{
    return (a[i / 8u] >> (7u - i % 8u)) & 1;
}

/* Insert a prefix; 0 on success, -1 out of memory, 1 a second trigger at one owner. */
static int rz_insert(rz_trie_t *t, const uint8_t *a, unsigned plen, int action)
{
    int32_t cur = 0;
    unsigned i;

    for (i = 0; i < plen; i++) {
        int b = rz_bit(a, i);

        if (t->n[cur].child[b] < 0) {
            int32_t nx = rz_new(t);

            if (nx < 0) {
                return -1;
            }
            t->n[cur].child[b] = nx;
        }
        cur = t->n[cur].child[b];
    }
    if (t->n[cur].action >= 0) {
        return 1;
    }
    t->n[cur].action = (int8_t)action;
    return 0;
}

/* The longest matching trigger's action; 0 (no policy) when none covers the address. */
static int rz_lookup(const rz_trie_t *t, const uint8_t *a, unsigned bits)
{
    int32_t cur = 0;
    int act = t->n[0].action > 0;
    unsigned i;

    for (i = 0; i < bits; i++) {
        cur = t->n[cur].child[rz_bit(a, i)];
        if (cur < 0) {
            break;
        }
        if (t->n[cur].action >= 0) {
            act = t->n[cur].action;
        }
    }
    return act;
}

static int rz_push(rz_keys_t *v, const uint8_t *a)
{
    if (v->len == v->cap) {
        size_t cap = v->cap ? v->cap * 2u : 1024u;
        rz_key_t *k = realloc(v->k, cap * sizeof *k);

        if (k == NULL) {
            return -1;
        }
        v->k = k;
        v->cap = cap;
    }
    memcpy(v->k[v->len++].a, a, 16);
    return 0;
}

/* a +/- 1 over `bytes` big-endian bytes; 0 when it wrapped (no neighbour on that side). */
static int rz_step(uint8_t *a, size_t bytes, int up)
{
    size_t i = bytes;

    while (i-- > 0) {
        if (up) {
            if (++a[i] != 0u) {
                return 1;
            }
        } else if (a[i]-- != 0u) {
            return 1;
        }
    }
    return 0;
}

/* The range [first, last] and both outside neighbours, as probes. */
static int rz_probe_range(rz_keys_t *v, const uint8_t *first, const uint8_t *last, size_t bytes)
{
    uint8_t x[16];

    if (rz_push(v, first) < 0 || rz_push(v, last) < 0) {
        return -1;
    }
    memcpy(x, first, 16);
    if (rz_step(x, bytes, 0) && rz_push(v, x) < 0) {
        return -1;
    }
    memcpy(x, last, 16);
    if (rz_step(x, bytes, 1) && rz_push(v, x) < 0) {
        return -1;
    }
    return 0;
}

static int rz_cmp(const void *x, const void *y)
{
    return memcmp(x, y, 16);
}

/* Parse the labels of an rpz-ip owner ahead of ".rpz-ip.": 4 = IPv4, 6 = IPv6, 0 = refused. */
static int rz_owner(const char *labels, uint8_t addr[16], unsigned *plen)
{
    char buf[256], *lab[40], *save = NULL, *t;
    int n = 0, i, zz = -1;
    unsigned long v;
    char *end;

    if (strlen(labels) >= sizeof buf) {
        return 0;
    }
    strcpy(buf, labels);
    for (t = strtok_r(buf, ".", &save); t != NULL; t = strtok_r(NULL, ".", &save)) {
        if (n == 40) {
            return 0;
        }
        lab[n++] = t;
    }
    if (n < 2) {
        return 0;
    }
    memset(addr, 0, 16);
    if (!isdigit((unsigned char)lab[0][0])) {
        return 0;
    }
    v = strtoul(lab[0], &end, 10);
    if (*end != '\0' || v == 0u || v > 128u) {
        return 0;
    }
    *plen = (unsigned)v;
    if (n == 5 && strcmp(lab[1], "zz") != 0 && strchr(labels, ':') == NULL) {
        int dec = 1;

        for (i = 1; i < 5; i++) {
            const char *c;

            for (c = lab[i]; *c != '\0'; c++) {
                dec &= isdigit((unsigned char)*c) != 0;
            }
        }
        if (dec && *plen <= 32u) {
            for (i = 0; i < 4; i++) {
                v = strtoul(lab[4 - i], &end, 10);
                if (*end != '\0' || v > 255u || lab[4 - i][0] == '\0') {
                    return 0;
                }
                addr[i] = (uint8_t)v;
            }
            return 4;
        }
    }
    /* IPv6: words least significant first, one `zz` standing for the longest run of zero words */
    {
        int words = n - 1, w = 0;
        uint16_t word[8] = {0};

        for (i = 1; i < n; i++) {
            if (strcmp(lab[i], "zz") == 0) {
                if (zz >= 0) {
                    return 0;
                }
                zz = i;
            }
        }
        if ((zz < 0 && words != 8) || (zz >= 0 && words > 8)) {
            return 0;
        }
        /* lab[n-1] is the most significant word */
        for (i = n - 1; i >= 1; i--) {
            if (i == zz) {
                w += 8 - (words - 1);
                continue;
            }
            if (strlen(lab[i]) == 0u || strlen(lab[i]) > 4u || w >= 8) {
                return 0;
            }
            v = strtoul(lab[i], &end, 16);
            if (*end != '\0') {
                return 0;
            }
            word[w++] = (uint16_t)v;
        }
        if (w != 8) {
            return 0;
        }
        for (i = 0; i < 8; i++) {
            addr[2 * i] = (uint8_t)(word[i] >> 8);
            addr[2 * i + 1] = (uint8_t)word[i];
        }
        return 6;
    }
}

/* Whether the plane enforces this address: the reader's own find, then the severity rule. */
static int rz_plane(const we_map_t *m, int fam, const uint8_t *a)
{
    uint32_t i;
    const uint8_t *sev;

    if (fam == 4) {
        i = we_find4(m, ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3]);
        sev = m->v4_sev;
    } else {
        i = m->f6w.n > 0u ? we_find6_64(m, a) : we_find6(m, a);
        sev = m->v6_sev;
    }
    if (i == WE_NO_RANGE) {
        return 0;
    }
    if (m->format != 1u || sev == NULL) {
        return 1;
    }
    return (sev[i] & WE_SEV_MASK) != WE_SEV_NONE && (sev[i] & WE_F_INFERRED) == 0u;
}

static void rz_print(int fam, const uint8_t *a)
{
    char s[INET6_ADDRSTRLEN];

    inet_ntop(fam == 4 ? AF_INET : AF_INET6, a, s, sizeof s);
    fputs(s, stdout);
}

static int rpz_oracle_mode(const char *bin, const char *zone)
{
    we_map_t m;
    we_load_detail_t d;
    const we_fam_t *f6;
    rz_trie_t trie[2] = {{0}, {0}};
    rz_keys_t probes[2] = {{0}, {0}};
    FILE *f;
    char line[1024];
    uint32_t i;
    int rc, fam, lineno = 0, bad = 0, ip = 0, nsip = 0, oom = 0;
    size_t checked = 0;

    rc = we_plane_open(bin, &m, &d);
    if (rc != WE_OK) {
        fprintf(stderr, "PLANE CHECK FAIL: the reader refused %s: %s (%s, family %d, record %" PRId64 ")\n",
                bin, we_strerror(rc), d.what ? d.what : "-", d.family, d.record);
        return 1;
    }
    f = fopen(zone, "r");
    if (f == NULL) {
        fprintf(stderr, "PLANE CHECK FAIL: cannot read %s\n", zone);
        we_map_close(&m);
        return 1;
    }
    if (rz_new(&trie[0]) < 0 || rz_new(&trie[1]) < 0) {
        oom = 1;
    }
    while (!oom && fgets(line, sizeof line, f) != NULL) {
        char owner[512], tok[5][256], *at;
        uint8_t a[16], last[16];
        unsigned plen = 0, k;
        int nt, kind, act, r;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        nt = sscanf(line, "%511s %255s %255s %255s %255s", owner, tok[0], tok[1], tok[2], tok[3]);
        if (nt < 1 || owner[0] == ';' || owner[0] == '$') {
            continue;
        }
        if (strstr(owner, ".rpz-nsip.") != NULL) {
            nsip++;
            continue;
        }
        at = strstr(owner, ".rpz-ip.");
        if (at == NULL) {
            continue;
        }
        ip++;
        *at = '\0';
        /* the target is the last token, after the CNAME type */
        if (nt < 3 || strcasecmp(tok[nt - 3], "CNAME") != 0) {
            printf("  DISAGREE line %d: an rpz-ip owner with no CNAME action: %.80s\n", lineno, line);
            bad++;
            continue;
        }
        if (strcmp(tok[nt - 2], ".") == 0 || strcmp(tok[nt - 2], "*.") == 0) {
            act = 1;
        } else if (strcasecmp(tok[nt - 2], "rpz-passthru.") == 0) {
            act = 0;
        } else {
            printf("  DISAGREE line %d: an rpz-ip action this oracle does not model: %.80s\n", lineno, line);
            bad++;
            continue;
        }
        kind = rz_owner(owner, a, &plen);
        if (kind == 0 || (kind == 4 && plen > 32u)) {
            printf("  DISAGREE line %d: an rpz-ip owner that does not parse: %.80s\n", lineno, owner);
            bad++;
            continue;
        }
        fam = kind == 4 ? 0 : 1;
        memcpy(last, a, 16);
        for (k = plen; k < (kind == 4 ? 32u : 128u); k++) {
            if (rz_bit(a, k)) {
                break;
            }
            last[k / 8u] |= (uint8_t)(1u << (7u - k % 8u));
        }
        if (k < (kind == 4 ? 32u : 128u)) {
            printf("  DISAGREE line %d: an rpz-ip owner with bits below its /%u: %.80s\n", lineno, plen, owner);
            bad++;
            continue;
        }
        r = rz_insert(&trie[fam], a, plen, act);
        if (r == 1) {
            printf("  DISAGREE line %d: a second rpz-ip trigger at one owner: %.80s\n", lineno, owner);
            bad++;
            continue;
        }
        if (r < 0 || rz_probe_range(&probes[fam], a, last, kind == 4 ? 4u : 16u) < 0) {
            oom = 1;
        }
    }
    fclose(f);
    for (i = 0; !oom && i < m.f4.n; i++) {
        uint8_t s[16] = {0}, e[16] = {0};
        uint32_t v = le32(m.f4.start + 4u * i), w = le32(m.f4.end + (size_t)m.f4.stride * i);
        int b;

        for (b = 0; b < 4; b++) {
            s[b] = (uint8_t)(v >> (24 - 8 * b));
            e[b] = (uint8_t)(w >> (24 - 8 * b));
        }
        oom = rz_probe_range(&probes[0], s, e, 4u) < 0;
    }
    f6 = we_family6(&m);
    for (i = 0; !oom && i < f6->n; i++) {
        uint64_t shi, slo, ehi, elo;
        uint8_t s[16], e[16];
        int b;

        if (f6->key_bits == 64u) {
            shi = le64(f6->start + 8u * i);
            slo = 0u;
            ehi = le64(f6->end + (size_t)f6->stride * i);
            elo = ~(uint64_t)0;
        } else {
            slo = le64(f6->start + 16u * i);
            shi = le64(f6->start + 16u * i + 8u);
            elo = le64(f6->end + (size_t)f6->stride * i);
            ehi = le64(f6->end + (size_t)f6->stride * i + 8u);
        }
        for (b = 0; b < 8; b++) {
            s[b] = (uint8_t)(shi >> (56 - 8 * b));
            s[8 + b] = (uint8_t)(slo >> (56 - 8 * b));
            e[b] = (uint8_t)(ehi >> (56 - 8 * b));
            e[8 + b] = (uint8_t)(elo >> (56 - 8 * b));
        }
        oom = rz_probe_range(&probes[1], s, e, 16u) < 0;
    }
    if (oom) {
        fprintf(stderr, "PLANE CHECK FAIL: out of memory building the oracle\n");
        bad++;
    }
    for (fam = 0; !oom && fam < 2; fam++) {
        size_t j;
        int famfam = fam == 0 ? 4 : 6, shown = 0;

        if (probes[fam].len == 0u) {
            continue;
        }
        qsort(probes[fam].k, probes[fam].len, sizeof(rz_key_t), rz_cmp);
        for (j = 0; j < probes[fam].len; j++) {
            const uint8_t *a = probes[fam].k[j].a;
            int pl, zn;

            if (j > 0 && memcmp(a, probes[fam].k[j - 1].a, 16) == 0) {
                continue;
            }
            checked++;
            pl = rz_plane(&m, famfam, a);
            zn = rz_lookup(&trie[fam], a, famfam == 4 ? 32u : 128u);
            if (pl != zn) {
                if (!shown) {
                    printf("  DISAGREE %d ", famfam);
                    rz_print(famfam, a);
                    printf(": the plane %s it, the zone %s\n", pl ? "enforces" : "does not enforce",
                           zn ? "does" : "does not");
                    shown = 1;
                }
                bad++;
            }
        }
    }
    printf("rpz oracle %s against %s: format %u plane %u, %u IPv4 + %u IPv6 ranges, %d rpz-ip triggers"
           " (%d rpz-nsip, not compared), %zu probes, %d disagreements\n",
           bin, zone, m.format, m.plane_id, m.f4.n, f6->n, ip, nsip, checked, bad);
    free(trie[0].n);
    free(trie[1].n);
    free(probes[0].k);
    free(probes[1].k);
    we_map_close(&m);
    if (checked == 0u) {
        printf("RPZ ORACLE FAIL: nothing was checked\n");
        return 1;
    }
    if (bad != 0) {
        printf("RPZ ORACLE FAIL: the zone and the plane disagree\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    we_map_t m;
    we_load_detail_t d;
    FILE *f;
    char line[512];
    int rc, lineno = 0, bad = 0, checked = 0, hits = 0, fieldtoks = 0;

    if (argc == 4 && strcmp(argv[1], "--fields") == 0) {
        return fields_mode(argv[2], argv[3]);
    }
    if (argc == 3 && strcmp(argv[1], "--dump") == 0) {
        return dump_mode(argv[2], 0);
    }
    if (argc == 3 && strcmp(argv[1], "--dump-full") == 0) {
        return dump_mode(argv[2], 1);
    }
    if (argc == 4 && strcmp(argv[1], "--rpz-oracle") == 0) {
        return rpz_oracle_mode(argv[2], argv[3]);
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s [--fields] <plane.bin> <expect.txt> | --dump <plane.bin>"
                " | --dump-full <plane.bin> | --rpz-oracle <plane.bin> <zone>\n", argv[0]);
        return 2;
    }
    rc = we_plane_open(argv[1], &m, &d);
    if (rc != WE_OK) {
        fprintf(stderr, "PLANE CHECK FAIL: the reader refused %s: %s (%s, family %d, record %" PRId64 ")\n",
                argv[1], we_strerror(rc), d.what ? d.what : "-", d.family, d.record);
        return 1;
    }
    f = fopen(argv[2], "r");
    if (f == NULL) {
        fprintf(stderr, "PLANE CHECK FAIL: cannot read %s\n", argv[2]);
        we_map_close(&m);
        return 1;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char fam, addr[80], want[16], extra[160], ftok[256], tail[8];
        uint32_t got;
        const we_fam_t *fm;
        int fields;

        lineno++;
        line[strcspn(line, "\r\n")] = '\0';
        extra[0] = '\0';
        ftok[0] = '\0';
        fields = sscanf(line, " %c %79s %15s %159s %255s %7s", &fam, addr, want, extra, ftok, tail);
        if (fields < 3 || fields > 5
            || (fields == 3 && strcmp(want, "-") != 0)
            || (fields >= 4 && strncmp(extra, "rec=", 4) != 0 && strncmp(extra, "sev=", 4) != 0)
            || (fields == 5 && strncmp(ftok, "fields=", 7) != 0)
            || !find_line(&m, fam, addr, &got)) {
            printf("  DISAGREE line %d: unparseable: %.60s\n", lineno, line);
            bad++;
            continue;
        }
        fm = fam == '4' ? &m.f4 : we_family6(&m);
        checked++;
        if (strcmp(want, "-") == 0) {
            if (got != WE_NO_RANGE) {
                printf("  DISAGREE line %d %s: reader finds range %u, the writer says none\n", lineno, addr, got);
                bad++;
            }
            continue;
        }
        if (got != (uint32_t)strtoul(want, NULL, 10)) {
            printf("  DISAGREE line %d %s: reader finds %d, the writer says %s\n", lineno, addr,
                   got == WE_NO_RANGE ? -1 : (int)got, want);
            bad++;
            continue;
        }
        hits++;
        if (strncmp(extra, "rec=", 4) == 0) {
            const uint8_t *r = we_record_of(fm, got);
            size_t len = strlen(extra + 4) / 2u, i;

            if (r == NULL || len != fm->stride) {
                printf("  DISAGREE line %d %s: no record, or stride %u against %zu bytes\n", lineno, addr,
                       fm->stride, len);
                bad++;
                continue;
            }
            for (i = 0; i < len; i++) {
                if (hexbyte(extra + 4 + 2 * i) != r[i]) {
                    printf("  DISAGREE line %d %s: record byte %zu is 0x%02x, the writer wrote %.2s\n",
                           lineno, addr, i, r[i], extra + 4 + 2 * i);
                    bad++;
                    break;
                }
            }
            if (i < len) {
                continue;
            }
        } else if (strncmp(extra, "sev=", 4) == 0) {
            const uint8_t *sev = fam == '4' ? m.v4_sev : m.v6_sev;
            unsigned want_sev = (unsigned)strtoul(extra + 4, NULL, 10);

            if (sev == NULL || sev[got] != want_sev) {
                printf("  DISAGREE line %d %s: severity %u, the writer wrote %u\n", lineno, addr,
                       sev ? sev[got] : 0u, want_sev);
                bad++;
                continue;
            }
        }
        if (ftok[0] != '\0') {
            fieldtoks++;
            if (!fields_token_ok(&m, fam, got, ftok + 7, lineno, addr)) {
                bad++;
            }
        }
    }
    fclose(f);
    printf("plane check %s: format %u plane %u, %u IPv4 + %u IPv6 ranges, kinds %u/%u (k %u/%u):"
           " %d lines, %d hits, %d fields tokens, %d disagreements\n",
           argv[1], m.format, m.plane_id, m.v4_count, m.v6_count, m.f4.file_kind,
           we_family6(&m)->file_kind, m.f4.file_param, we_family6(&m)->file_param, lineno, hits, fieldtoks,
           bad);
    we_map_close(&m);
    if (checked == 0 || hits == 0) {
        printf("PLANE CHECK FAIL: nothing was checked\n");
        return 1;
    }
    return bad == 0 ? 0 : 1;
}
