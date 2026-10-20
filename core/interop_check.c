/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * interop_check.c - the reader answering lookups out of a snapshot the builder produced.
 *
 * The format is a contract between two programs in two languages, and each side believes things about
 * offsets, alignment, byte order, the 192-byte header, where the digest hole is, and what index entry
 * 65536 means. A test written on one side alone proves only that that side agrees with itself.
 *
 * So the fixture in testdata/ carries a snapshot the real builder produced plus expected.txt, whose
 * lines are
 *
 *     4 <ipv4-address> <expected-verdict-byte>
 *     6 <ipv6-address> <expected-verdict-byte>
 *
 * computed by the builder. This program loads the snapshot with the real reader and fails on the
 * first disagreement.
 *
 *     interop_check --tenant <tenant.bin> <expected-tenant-id>
 *
 * is the tenant plane's writer-conformance check. The loader checks a feed-name table's STRUCTURE only,
 * for every plane, and no module decision reads its content; the content rules for plane_id 8 are the
 * writer's (FORMAT.md section 3.3): count 3, entry 0 empty, entry 1 "tenant:" and exactly 16 lower-case
 * hex digits equal to the expected id, entry 2 "rev:" and [1-9][0-9]{0,18} at most 2^63 - 1, source 1 on
 * every record, every record's flags non-zero and inside tenant_allow | tenant_deny, and the header's tier
 * 1. A plane that breaks one still loads; this refuses it, naming the rule, so the builder's fixtures are
 * held to the rule the refresh enforces before install.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "whisper_edge.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tenant_fail(we_map_t *m, const char *bin, const char *why)
{
    fprintf(stderr, "INTEROP FAIL: %s breaks the tenant plane's writer rule: %s\n", bin, why);
    we_map_close(m);
    return 1;
}

/* [1-9][0-9]{0,18}, at most 2^63 - 1, compared as text so no integer type can round or wrap it. */
static int rev_ok(const char *v)
{
    static const char max[] = "9223372036854775807";
    size_t n = strlen(v), i;

    if (n < 1 || n > 19 || v[0] < '1' || v[0] > '9') {
        return 0;
    }
    for (i = 1; i < n; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return 0;
        }
    }
    return n < 19 || strcmp(v, max) <= 0;
}

static int tenant_mode(const char *bin, const char *expect_id)
{
    we_map_t m;
    we_load_detail_t d;
    const char *e0, *e1, *e2;
    const we_fam_t *fams[2];
    char want[32];
    size_t i;
    uint32_t r, records = 0;
    int rc, f;

    rc = we_plane_open(bin, &m, &d);
    if (rc != WE_OK) {
        fprintf(stderr, "INTEROP FAIL: the reader refused %s: %s (%s, family %d, record %" PRId64 ")\n",
                bin, we_strerror(rc), d.what ? d.what : "-", d.family, d.record);
        return 1;
    }
    if (m.plane_id != 8u) {
        return tenant_fail(&m, bin, "plane_id is not 8");
    }
    if (m.h->tier != 1u) {
        return tenant_fail(&m, bin, "the header's tier is not 1, keyed");
    }
    if (m.feed_count != 3u) {
        return tenant_fail(&m, bin, "the feed-name table's count is not 3");
    }
    e0 = we_feed_name(&m, 0);
    e1 = we_feed_name(&m, 1);
    e2 = we_feed_name(&m, 2);
    if (e0 == NULL || e0[0] != '\0') {
        return tenant_fail(&m, bin, "entry 0 is not empty");
    }
    if (strlen(expect_id) != 16) {
        return tenant_fail(&m, bin, "the expected tenant id is not 16 characters");
    }
    for (i = 0; i < 16; i++) {
        char c = expect_id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return tenant_fail(&m, bin, "the expected tenant id is not lower-case hex");
        }
    }
    snprintf(want, sizeof want, "tenant:%s", expect_id);
    if (e1 == NULL || strcmp(e1, want) != 0) {
        return tenant_fail(&m, bin, "entry 1 is not tenant: and the expected id, byte for byte");
    }
    if (e2 == NULL || strncmp(e2, "rev:", 4) != 0 || !rev_ok(e2 + 4)) {
        return tenant_fail(&m, bin, "entry 2 is not rev: and a canonical decimal from 1 to 2^63 - 1");
    }
    fams[0] = &m.f4;
    fams[1] = we_family6(&m);
    for (f = 0; f < 2; f++) {
        for (r = 0; r < fams[f]->n; r++) {
            const uint8_t *rec = we_record_of(fams[f], r);
            uint32_t flags;
            uint8_t source;

            if (fams[f]->key_bits == 32u) {
                we_member4_t x;
                memcpy(&x, rec, sizeof x);
                flags = x.flags;
                source = x.source;
            } else {
                we_member6_t x;
                memcpy(&x, rec, sizeof x);
                flags = x.flags;
                source = x.source;
            }
            if (source != 1u) {
                return tenant_fail(&m, bin, "a record's source is not 1");
            }
            if (flags == 0u || (flags & ~3u) != 0u) {
                return tenant_fail(&m, bin, "a record's flags are zero or outside tenant_allow | tenant_deny");
            }
            records++;
        }
    }
    printf("tenant plane %s: generation %" PRIu64 ", %s, %s, %u record(s) at source 1, follows the writer rule\n",
           bin, m.h->generation, e1, e2, records);
    we_map_close(&m);
    return 0;
}

int main(int argc, char **argv)
{
    we_map_t m;
    FILE *f;
    FILE *f_count;
    char line[256];
    int rc, lineno = 0, bad = 0, checked = 0, ev_checked = 0;

    if (argc == 4 && strcmp(argv[1], "--tenant") == 0) {
        return tenant_mode(argv[2], argv[3]);
    }
    if (argc < 3) {
        fprintf(stderr, "usage: %s <snapshot> <expected.txt> | --tenant <tenant.bin> <expected-tenant-id>\n",
                argv[0]);
        return 2;
    }
    rc = we_map_open(argv[1], &m);
    if (rc != WE_OK) {
        fprintf(stderr, "INTEROP FAIL: the reader refused the builder-written snapshot: %s\n",
                we_strerror(rc));
        return 1;
    }
    printf("loaded a builder-written snapshot: format %u, generation %" PRIu64 ", tier %u, %u v4 + %u v6 ranges,"
           " v4 index %s, v6 index %s\n",
           m.h->format, m.h->generation, m.h->tier, m.v4_count, m.v6_count,
           m.v4_index ? "present" : "absent", m.v6_index ? "present" : "absent");

    f_count = fopen(argv[2], "r");
    f = fopen(argv[2], "r");
    if (f == NULL || f_count == NULL) {
        fprintf(stderr, "INTEROP FAIL: cannot read %s\n", argv[2]);
        we_map_close(&m);
        return 1;
    }
    while (fgets(line, sizeof line, f) != NULL) {
        char fam;
        char addr[80];
        char want_ev[128];
        unsigned want;
        unsigned got;
        const char *got_ev = NULL;
        int fields;

        lineno++;
        /*
         * The fourth field is the EVIDENCE the reader must return, or "-" for none. It is optional so
         * that an older fixture still parses, but when it is present it is checked, because the
         * verdict column alone cannot catch a missing evidence lookup: the verdicts were right the
         * whole time the IPv6 evidence path did not exist.
         */
        want_ev[0] = '\0';
        fields = sscanf(line, " %c %79s %u %127s", &fam, addr, &want, want_ev);
        if (fields < 3) {
            continue;
        }
        if (fam == '4') {
            struct in_addr a4;
            if (inet_pton(AF_INET, addr, &a4) != 1) {
                fprintf(stderr, "line %d: unparseable v4 address %s\n", lineno, addr);
                bad++;
                continue;
            }
            got = we_lookup4(&m, ntohl(a4.s_addr));
            got_ev = we_evidence4(&m, ntohl(a4.s_addr));
        } else if (fam == '6') {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, addr, &a6) != 1) {
                fprintf(stderr, "line %d: unparseable v6 address %s\n", lineno, addr);
                bad++;
                continue;
            }
            got = we_lookup6(&m, (const uint8_t *)&a6);
            got_ev = we_evidence6(&m, (const uint8_t *)&a6);
        } else {
            continue;
        }
        checked++;
        if (got != want) {
            printf("  DISAGREE %s: reader says 0x%02x, the fixture expects 0x%02x\n", addr, got, want);
            bad++;
        }
        if (fields == 4) {
            const char *shown = (got_ev != NULL) ? got_ev : "-";

            checked++;
            if (strcmp(shown, want_ev) != 0) {
                printf("  DISAGREE evidence for %s: reader says %s, the fixture expects %s\n",
                       addr, shown, want_ev);
                bad++;
            }
            ev_checked++;
        }
    }
    fclose(f);

    /*
     * A FLOOR ON THE EVIDENCE COLUMN. The per-line check above is skipped when a line has only three
     * fields, so a fixture regenerated by an older writer would silently check no evidence at all and
     * still report CLEAR. That is the shape of pass this gate must not have: the IPv6 evidence lookup
     * did not exist for a while and nothing went red, because nothing was looking.
     *
     * The numbers are the two families' probe counts in the checked-in fixture. They are asserted as
     * a floor rather than an equality so that adding probes does not break the gate, and naming both
     * families separately is the point: a v4-only fixture would otherwise satisfy a single total.
     */
    {
        int v4_ev = 0, v6_ev = 0;

        rewind(f_count);
        while (fgets(line, sizeof line, f_count) != NULL) {
            char fam;
            char a[80], e[128];
            unsigned w;

            if (sscanf(line, " %c %79s %u %127s", &fam, a, &w, e) == 4) {
                if (fam == '4') { v4_ev++; } else if (fam == '6') { v6_ev++; }
            }
        }
        fclose(f_count);
        if (v4_ev < 20 || v6_ev < 15) {
            fprintf(stderr, "INTEROP FAIL: the fixture carries an evidence column on only %d v4 and"
                    " %d v6 lines; the gate would be reporting CLEAR without checking the evidence"
                    " lookup for either family\n", v4_ev, v6_ev);
            we_map_close(&m);
            return 1;
        }
        if (v4_ev + v6_ev != ev_checked) {
            fprintf(stderr, "INTEROP FAIL: %d evidence lines were compared, and the fixture holds %d IPv4 and %d IPv6;"
                    " a line was skipped or counted twice\n", ev_checked, v4_ev, v6_ev);
            we_map_close(&m);
            return 1;
        }
        printf("evidence column checked on %d IPv4 and %d IPv6 probes\n", v4_ev, v6_ev);
    }

    we_map_close(&m);
    printf("%d lookups checked across both families, %d disagreements\n", checked, bad);
    if (checked == 0) {
        fprintf(stderr, "INTEROP FAIL: nothing was checked; the fixture is empty or unparsed\n");
        return 1;
    }
    if (bad != 0) {
        fprintf(stderr, "INTEROP GATE: FAILED\n");
        return 1;
    }
    printf("INTEROP GATE: the format-1 fixture agrees (the gate goes on; its last line is the verdict)\n");
    return 0;
}
