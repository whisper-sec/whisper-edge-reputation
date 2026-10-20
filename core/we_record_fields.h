/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_record_fields.h - a range's RAW record, field by field, from the bytes the reader returns.
 *
 * One renderer, shared by plane_check (which holds the reader to both independent writers) and
 * whisper-edge-lookup (whose `record` key and `--fields` lines print the same thing), so the two can
 * never disagree about which byte is which field. The values are the record as written, before any
 * clamp: what a policy rule reads is the evaluator's business, and the tool prints that separately.
 *
 * The field names and their order are FORMAT.md's: routing `asn country rov rir flags asn_rep`,
 * membership `flags source reason`, format 1 the `sev` byte (severity nibble and flag bits together).
 * Cold path only; nothing here is on a request.
 */
#ifndef WE_RECORD_FIELDS_H
#define WE_RECORD_FIELDS_H

#include "whisper_edge.h"

#include <stdio.h>
#include <string.h>

#define WE_RECORD_MAX_FIELDS 6

/*
 * The raw fields of range `i` of the family `family` (4 or 6) declares. Returns the field count and
 * fills `names` and `vals`; returns 0 for a range index the family does not hold.
 */
static inline int we_record_values(const we_map_t *m, int family, uint32_t i, const char **names,
                                   unsigned long *vals)
{
    const we_fam_t *f = family == 4 ? &m->f4 : we_family6(m);
    const uint8_t *r;

    if (i >= f->n) {
        return 0;
    }
    if (m->format == WE_FORMAT_1) {
        names[0] = "sev";
        vals[0] = f->sev[i];
        return 1;
    }
    r = we_record_of(f, i);
    if (r == NULL) {
        return 0;
    }
    if (m->schema_id == WE_SCHEMA_ROUTING) {
        unsigned long asn, country, rov, rir, flags, rep;

        if (f->key_bits == 32u) {
            we_route4_t x;
            memcpy(&x, r, sizeof x);
            asn = x.asn; country = x.country; rov = x.rov; rir = x.rir; flags = x.flags; rep = x.asn_rep;
        } else {
            we_route6_t x;
            memcpy(&x, r, sizeof x);
            asn = x.asn; country = x.country; rov = x.rov; rir = x.rir; flags = x.flags; rep = x.asn_rep;
        }
#ifdef WE_LOOKUP_TEST_FIELD_SWAP
        { unsigned long t = rov; rov = rir; rir = t; }   /* the mutant: two fields read from each other's byte */
#endif
        names[0] = "asn";     vals[0] = asn;
        names[1] = "country"; vals[1] = country;
        names[2] = "rov";     vals[2] = rov;
        names[3] = "rir";     vals[3] = rir;
        names[4] = "flags";   vals[4] = flags;
        names[5] = "asn_rep"; vals[5] = rep;
        return 6;
    }
    if (f->key_bits == 32u) {
        we_member4_t x;
        memcpy(&x, r, sizeof x);
        vals[0] = x.flags; vals[1] = x.source; vals[2] = x.reason;
    } else {
        we_member6_t x;
        memcpy(&x, r, sizeof x);
        vals[0] = x.flags; vals[1] = x.source; vals[2] = x.reason;
    }
    names[0] = "flags";
    names[1] = "source";
    names[2] = "reason";
    return 3;
}

/*
 * The `name=value,...` form, which make-test-snapshot.py's `fields=` token and the tool's `record`
 * key both carry. Returns the length written, or -1 when it does not fit or the range is not held.
 */
static inline int we_record_render(const we_map_t *m, int family, uint32_t i, char *buf, size_t n)
{
    const char *names[WE_RECORD_MAX_FIELDS];
    unsigned long vals[WE_RECORD_MAX_FIELDS];
    int k, nf = we_record_values(m, family, i, names, vals);
    size_t at = 0;

    if (nf <= 0 || n == 0u) {
        return -1;
    }
    buf[0] = '\0';
    for (k = 0; k < nf; k++) {
        int w = snprintf(buf + at, n - at, "%s%s=%lu", k ? "," : "", names[k], vals[k]);

        if (w < 0 || (size_t)w >= n - at) {
            return -1;
        }
        at += (size_t)w;
    }
    return (int)at;
}

#endif /* WE_RECORD_FIELDS_H */
