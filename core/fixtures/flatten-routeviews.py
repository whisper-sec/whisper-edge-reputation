#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
flatten-routeviews.py - the live-shaped fixtures of the deterministic bound test (make check-live).

The edge plane layout was measured on the real RouteViews tables (FORMAT.md). This
is that build, kept so the live-shaped maxima the test prints can be reproduced by anyone: it reads
the two CAIDA RouteViews prefix-to-AS files, resolves nesting most-specific-wins into disjoint ranges
(the same flattening the edge builder does), and writes the routing plane's arrays:

    v4.start   u32 start[] (1,169,047 ranges)       v4.rec16  16-byte IPv4 routing records
    v6.start   u64 start[] (298,246 ranges, /64)    v6.rec24  24-byte IPv6 routing records

Only the ORIGIN ASN and the MOAS bit come from the data. country, rov, rir and asn_rep are
synthetic, derived per origin ASN by a keyed hash, so they are correlated the way real attributes
are and are never a claim about a real network. Ranges narrower than a /64 collapse onto their /64
with the `narrowed` flag (FORMAT.md 3.1).

The output is deterministic, and fixtures/SHA256SUMS pins the inputs and the outputs. The inputs are
not committed: CAIDA's terms are for use, not redistribution, so make-fixtures.sh fetches them.

Usage: flatten-routeviews.py <rib-dir> <out-dir>
"""
import array
import collections
import gzip
import hashlib
import ipaddress
import struct
import sys

RV4 = "routeviews-rv2-20261009-1200.pfx2as.gz"
RV6 = "routeviews-rv6-20261009-1200.pfx2as.gz"


def h(x, salt):
    return int.from_bytes(hashlib.blake2b(f"{salt}:{x}".encode(), digest_size=4).digest(), "little")


CC = ([840] * 25 + [156] * 8 + [76] * 7 + [356] * 5 + [643] * 3 + [276] * 3 + [826] * 3 + [392] * 3
      + [250] * 2 + [410] * 2 + list(range(4, 900, 7)))
stats = collections.Counter()


def attrs(origin):
    toks = origin.replace(",", "_").split("_")
    moas = "_" in origin
    asn = int(toks[0].strip("{}"))
    cc = CC[h(asn, "cc") % len(CC)]
    rov = 1 if (h(asn, "roa") % 1000) < 730 else 3          # 1 valid, 3 not-found
    if rov == 1 and (h(asn, "inv") % 1000) < 6:
        rov = 2                                             # 2 invalid
    rir = 1 + (h(asn, "rir") % 5)
    rep = 1 + (h(asn, "rep") % 4)
    return (asn, cc, rov, rir, (2 if moas else 0), rep, len(toks))


def load(path, bits):
    out = []
    for line in gzip.open(path, "rt"):
        p, length, o = line.split()
        length = int(length)
        s = int(ipaddress.ip_address(p))
        e = s + (1 << (bits - length)) - 1
        a = attrs(o)
        stats[f"v{4 if bits == 32 else 6} prefixes"] += 1
        out.append((s, e, a[:6]))
    return out


def flatten(pfx):
    pfx.sort(key=lambda t: (t[0], -t[1]))
    out = []
    stack = []
    cur = None

    def emit(a, b, at):
        if a <= b:
            out.append((a, b, at))

    for s, e, at in pfx:
        while stack and stack[-1][0] < s:
            te, ta = stack.pop()
            emit(cur, te, ta)
            cur = max(cur, te + 1)
        if stack:
            emit(cur, s - 1, stack[-1][1])
        cur = s
        stack.append((e, at))
    while stack:
        te, ta = stack.pop()
        emit(cur, te, ta)
        cur = max(cur, te + 1)
    return out


def main():
    rib, out = sys.argv[1], sys.argv[2]
    v4 = flatten(load(f"{rib}/{RV4}", 32))
    v6 = flatten(load(f"{rib}/{RV6}", 128))
    stats["v4 flattened ranges"] = len(v4)
    stats["v6 flattened ranges (128-bit)"] = len(v6)

    # IPv6 to 64-bit keys, narrowing what is finer than a /64 onto its /64
    mask = (1 << 64) - 1
    split = {}
    inner = []
    for s, e, a in v6:
        s64, e64 = s >> 64, e >> 64
        sal = (s & mask) == 0
        eal = ((e + 1) & mask) == 0
        w = e - s + 1
        for q, al in ((s64, sal), (e64, eal)):
            if not al and (q not in split or w < split[q][0]):
                split[q] = (w, a)
        lo = s64 if sal else s64 + 1
        hi = e64 if eal else e64 - 1
        if lo <= hi:
            inner.append((lo, hi, a, 0))
    narrowed = [(q, q, a, 4) for q, (w, a) in split.items()]
    r6 = sorted(inner + narrowed)
    for i in range(1, len(r6)):
        assert r6[i][0] > r6[i - 1][1], ("overlap", i)
    stats["v6 /64s that are narrowed"] = len(split)
    stats["v6 64-bit ranges"] = len(r6)

    def rec4(e, a):
        return struct.pack("<IIHBBBBH", e, a[0], a[1], a[2], a[3], a[4], a[5], 0)

    def rec6(e, a, f):
        return struct.pack("<QIHBBBB6x", e, a[0], a[1], a[2], a[3], a[4] | f, a[5])

    with open(f"{out}/v4.start", "wb") as f:
        array.array("I", [s for s, _, _ in v4]).tofile(f)
    with open(f"{out}/v4.rec16", "wb") as f:
        f.write(b"".join(rec4(e, a) for _, e, a in v4))
    with open(f"{out}/v6.start", "wb") as f:
        array.array("Q", [s for s, _, _, _ in r6]).tofile(f)
    with open(f"{out}/v6.rec24", "wb") as f:
        f.write(b"".join(rec6(e, a, fl) for _, e, a, fl in r6))
    for k, v in stats.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
