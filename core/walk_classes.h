/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * walk_classes.h - the walk corpus's input classes, one table read by two harnesses: fuzz_walk writes
 * them as its seed corpus (`--seeds`), and test_module runs V2, N2 and E1 over them, each class's walk
 * feeding the decision, the record, the lazy fill and every request-path renderer. One table, so the
 * classes the no-syscall, no-allocation and no-uninitialised-read rows claim are the corpus's own.
 *
 * A class: its name (the seed's file name), the fuzz input's flags byte (bit 0 a unix peer, bit 1 the
 * header configured, bit 2 older lines dropped, bit 3 unix: is trusted), the hop count, the peer (IPv4 or
 * IPv6 text, ignored for a unix peer), the trust list (an index into we_wc_lists; IPv4 and IPv6 prefixes)
 * and the field lines, separated by a newline.
 */
#ifndef WE_WALK_CLASSES_H
#define WE_WALK_CLASSES_H

#include <stdint.h>

typedef struct {
    const char *name;
    uint8_t     flags, hops;
    const char *peer;
    uint8_t     list;
    const char *body;
} we_walk_class_t;

enum { WE_WC_TEN, WE_WC_NESTED, WE_WC_HALVES, WE_WC_NONE, WE_WC_ALL, WE_WC_V6, WE_WC_MIXED, WE_WC_LISTS };

static const char *const we_wc_lists[WE_WC_LISTS][3] = {
    { "10.0.0.0/8", NULL, NULL },
    { "10.0.0.0/8", "10.1.0.0/16", NULL },
    { "10.0.0.0/9", "10.128.0.0/9", NULL },
    { NULL, NULL, NULL },
    { "0.0.0.0/0", NULL, NULL },
    { "2001:db8::/32", NULL, NULL },
    { "10.0.0.0/8", "2001:db8:100::/40", NULL },
};

static const we_walk_class_t we_walk_classes[] = {
    { "untrusted-peer", 2u, 0u, "192.0.2.9", WE_WC_TEN, "203.0.113.5" },
    { "absent", 2u, 0u, "10.0.0.1", WE_WC_TEN, "" },
    { "commas", 2u, 0u, "10.0.0.1", WE_WC_TEN, " , ," },
    { "c-junk-t1", 2u, 0u, "10.0.0.1", WE_WC_TEN, "203.0.113.5, junk, 10.0.0.7" },
    { "skipped-hop", 2u, 0u, "10.0.0.1", WE_WC_TEN, "203.0.113.5, 10.0.0.7" },
    { "seventeen", 2u, 0u, "10.0.0.1", WE_WC_TEN,
      "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9, "
      "10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15, 10.0.0.16, 10.0.0.17" },
    { "hops2", 2u, 2u, "10.0.0.1", WE_WC_TEN, "203.0.113.5, 198.51.100.7" },
    { "hops3-older", 6u, 3u, "10.0.0.1", WE_WC_TEN, "198.51.100.7\n198.51.100.8" },
    { "nested", 2u, 0u, "10.2.0.1", WE_WC_NESTED, "203.0.113.5" },
    { "halves", 2u, 0u, "10.200.0.1", WE_WC_HALVES, "203.0.113.5" },
    { "all", 2u, 0u, "203.0.113.9", WE_WC_ALL, "[2001:db8::7]:80, 198.51.100.7:443" },
    /* no trust list at all (no prefix, no unix:): the table is built from nothing, so every peer is untrusted
     * and the header is never walked; the empty table once reached qsort with a NULL array (UBSan) */
    { "no-trust-list", 2u, 0u, "10.0.0.1", WE_WC_NONE, "203.0.113.5" },
    { "unix-absent", 11u, 0u, "0.0.0.0", WE_WC_NONE, "" },
    { "unix-present", 11u, 0u, "0.0.0.0", WE_WC_NONE, "203.0.113.5" },
    /* the only entry in the oldest of 18 lines, below the newest-16 cap (POLICY.md 3.9): the walk reads
     * sixteen empty lines and judges the peer unparsed; the harness's own reading honours the same cap */
    { "entry-below-line-cap", 2u, 0u, "10.0.0.1", WE_WC_TEN, "203.0.113.5\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" },
    { "limit-53", 2u, 0u, "10.0.0.1", WE_WC_TEN, "[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535" },
    { "limit-54", 2u, 0u, "10.0.0.1", WE_WC_TEN, "[0000:0000:0000:0000:0000:ffff:255.255.255.255]:655350" },
    { "zone", 2u, 0u, "10.0.0.1", WE_WC_TEN, "fe80::1%eth0, [fe80::1%25eth0]:80" },
    /* an IPv6 peer through an IPv6 trust list: the binary search over the IPv6 half, which every IPv4 class
     * leaves at n6 == 0 */
    { "v6-trusted", 2u, 0u, "2001:db8::1", WE_WC_V6, "2001:db9::5, 2001:db8::7" },
    { "v6-untrusted", 2u, 0u, "2001:db9::1", WE_WC_V6, "203.0.113.5" },
    { "v6-mixed", 2u, 0u, "2001:db8:100::1", WE_WC_MIXED, "[2001:db9::9]:443, 10.1.2.3, 2001:db8:1ff::4" },
    { "v6-mapped", 2u, 0u, "2001:db8::2", WE_WC_V6, "::ffff:198.51.100.7, [2001:db8::3]" },
};

#define WE_WALK_CLASSES ((uint32_t)(sizeof we_walk_classes / sizeof we_walk_classes[0]))

#endif /* WE_WALK_CLASSES_H */
