# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# build7.py - flatten the real RouteViews prefix-to-AS tables into the routing plane's two columns.
#
# Usage: python3 build7.py <dir with rib/> [<output dir>]
#
# Reads rib/routeviews-rv2-*.pfx2as.gz and rib/routeviews-rv6-*.pfx2as.gz (CAIDA's daily snapshots,
# pinned by digest in run-x86.sh) and writes the layout of the routing record (FORMAT.md section 3.1):
#   v4.start   u32 start[]
#   v4.rec16   16-byte records {u32 end, u32 asn, u16 cc, u8 rov, u8 rir, u8 flags, u8 asn_rep, u16 0}
#   v6.start   u64 start[], IPv6 at 64-bit keys
#   v6.rec24   24-byte records {u64 end, u32 asn, u16 cc, u8 rov, u8 rir, u8 flags, u8 asn_rep, u8[6] 0}
#   v6.rec32   the same records padded to 32 bytes, for the stride comparison
# Prefixes are flattened into disjoint ranges, the most specific prefix winning. An IPv6 range narrower
# than a /64 collapses onto its /64 with flags bit 2 (narrowed). The origin ASN and MOAS flag are
# real; country, ROV, RIR and ASN reputation are SYNTHETIC, derived per ASN from a fixed hash, because
# what this measures is the layout (counts of probes, lines and pages), which depends on the range
# boundaries and the record width and on nothing an attribute holds. The output is deterministic:
# run-x86.sh asserts the row counts and the sha256 of every file it reads.
import gzip, ipaddress, struct, sys, hashlib, array, collections, os
S = sys.argv[1]; O = sys.argv[2] if len(sys.argv) > 2 else S
def h(x, salt): return int.from_bytes(hashlib.blake2b(f"{salt}:{x}".encode(), digest_size=4).digest(), 'little')
CC = ([840]*25 + [156]*8 + [76]*7 + [356]*5 + [643]*3 + [276]*3 + [826]*3 + [392]*3 + [250]*2 + [410]*2 + list(range(4, 900, 7)))
stats = collections.Counter()
def attrs(origin):
    toks = origin.replace(',', '_').split('_')
    moas = '_' in origin; asset = ',' in origin or '{' in origin
    asn = int(toks[0].strip('{}'))
    cc = CC[h(asn, 'cc') % len(CC)]
    rov = 1 if (h(asn, 'roa') % 1000) < 730 else 3          # 1 valid, 3 not-found, as FORMAT.md numbers them
    if rov == 1 and (h(asn, 'inv') % 1000) < 6: rov = 2      # 2 invalid
    rir = 1 + (h(asn, 'rir') % 5)
    rep = 1 + (h(asn, 'rep') % 4)
    return (asn, cc, rov, rir, (2 if moas else 0), rep, len(toks))
def load(path, bits):
    out = []
    for line in gzip.open(path, 'rt'):
        p, l, o = line.split(); l = int(l)
        s = int(ipaddress.ip_address(p)); e = s + (1 << (bits - l)) - 1
        a = attrs(o)
        stats[f"v{4 if bits==32 else 6} prefixes"] += 1
        if a[4]: stats[f"v{4 if bits==32 else 6} MOAS prefixes"] += 1
        if a[6] > 2: stats[f"v{4 if bits==32 else 6} prefixes with >2 origins"] += 1
        out.append((s, e, a[:6]))
    return out
def flatten(pfx):
    pfx.sort(key=lambda t: (t[0], -t[1])); out = []; stack = []; cur = None
    def emit(a, b, at):
        if a <= b: out.append((a, b, at))
    for s, e, at in pfx:
        while stack and stack[-1][0] < s:
            te, ta = stack.pop(); emit(cur, te, ta); cur = max(cur, te + 1)
        if stack: emit(cur, s - 1, stack[-1][1])
        cur = s; stack.append((e, at))
    while stack:
        te, ta = stack.pop(); emit(cur, te, ta); cur = max(cur, te + 1)
    return out
v4 = flatten(load(f"{S}/rib/routeviews-rv2-20261009-1200.pfx2as.gz", 32))
v6 = flatten(load(f"{S}/rib/routeviews-rv6-20261009-1200.pfx2as.gz", 128))
stats["v4 flattened ranges"] = len(v4); stats["v6 flattened ranges (128-bit)"] = len(v6)
stats["v4 MOAS ranges"] = sum(1 for r in v4 if r[2][4] & 2); stats["v6 MOAS ranges"] = sum(1 for r in v6 if r[2][4] & 2)
# --- v6 to 64-bit keys with narrowing
M = (1 << 64) - 1
split = {}       # /64 -> (width, attr) of the narrowest range touching it
inner = []
for s, e, a in v6:
    s64, e64 = s >> 64, e >> 64
    sal = (s & M) == 0; eal = ((e + 1) & M) == 0
    w = e - s + 1
    for q, aligned in ((s64, sal), (e64, eal)):
        if not aligned:
            if q not in split or w < split[q][0]: split[q] = (w, a)
    lo = s64 if sal else s64 + 1; hi = e64 if eal else e64 - 1
    if lo <= hi: inner.append((lo, hi, a, 0))
# a /64 that is split must not also appear inside an aligned interior (it cannot: interiors exclude the unaligned ends)
conflict = 0
for q, (w, a) in split.items():
    # was the /64 shared by ranges with different ASNs?
    pass
narrowed = [(q, q, a, 4) for q, (w, a) in split.items()]
r6 = sorted(inner + narrowed)
for i in range(1, len(r6)):
    assert r6[i][0] > r6[i-1][1], ("overlap", i)
# how many split /64s held ranges with differing ASN
cnt = collections.defaultdict(set)
for s, e, a in v6:
    for q in {s >> 64, e >> 64}:
        if q in split: cnt[q].add(a[0])
stats["v6 /64s that are narrowed"] = len(split)
stats["v6 narrowed /64s whose ranges disagree on origin ASN"] = sum(1 for q in cnt if len(cnt[q]) > 1)
stats["v6 ranges narrower than /64"] = sum(1 for s, e, a in v6 if e - s + 1 < (1 << 64))
stats["v6 64-bit ranges"] = len(r6)
def rec4(e, a): return struct.pack('<IIHBBBBH', e, a[0], a[1], a[2], a[3], a[4], a[5], 0)
def rec6(e, a, f): return struct.pack('<QIHBBBB6x', e, a[0], a[1], a[2], a[3], a[4] | f, a[5])
# Each table is written beside its name and renamed over it, so a reader (another gate's driver, which
# reads these while this runs on a shared host) sees the old file or the new one, never one half
# written; the bytes are the same either way, since the output is deterministic.
def put(name, data):
    tmp = f"{O}/{name}.{os.getpid()}.tmp"
    with open(tmp, 'wb') as f:
        f.write(data)
    os.replace(tmp, f"{O}/{name}")
put("v4.start", array.array('I', [s for s, _, _ in v4]).tobytes())
put("v4.rec16", b''.join(rec4(e, a) for _, e, a in v4))
put("v6.start", array.array('Q', [s for s, _, _, _ in r6]).tobytes())
put("v6.rec24", b''.join(rec6(e, a, f) for _, e, a, f in r6))
put("v6.rec32", b''.join(rec6(e, a, f) + b'\0'*8 for _, e, a, f in r6))
# Top-12-bit concentration of v6 routed ranges (proxy for the small v6 planes at radix-12)
c12 = collections.Counter(s >> 52 for s, _, _, _ in r6)
stats["v6 radix-12 nonempty buckets"] = len(c12); stats["v6 radix-12 worst bucket (routing)"] = max(c12.values())
top = c12.most_common(3); stats["v6 radix-12 top buckets"] = str([(hex(b << 4), c) for b, c in top])
v4b = 4 * len(v4) + 16 * len(v4); v6b = 8 * len(r6) + 24 * len(r6)
stats["v4 bytes start+rec16 (MB)"] = round(v4b / 1e6, 2); stats["v6 bytes start+rec24 (MB)"] = round(v6b / 1e6, 2)
for k, v in stats.items(): print(f"{k}: {v}")
