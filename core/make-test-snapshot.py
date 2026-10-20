#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
make-test-snapshot.py - the independent writer: every plane, both formats, both index kinds.

ONE generator, shared by every gate. There used to be a copy of this inline in nginx-gate.sh, and a
second one was about to be inlined into apache-gate.sh; two copies of a binary format written by
hand is a format that drifts, and the gates would have disagreed about what "valid" means while both
reported CLEAR.

It writes the bytes from FORMAT.md by hand rather than calling the builder, deliberately:
a gate that cannot run without a JDK is a gate a module developer skips, and writing the bytes
independently of the reader is what makes format agreement a real assertion rather than a tautology.
The interop gate holds the C reader to two independent writers: the real builder, whose output is
checked in under testdata/ and frozen there, and this script, which writes format 1 with and without
the schema tail and format 2 for every plane with radix-12/16/18, rank and unindexed families.

Usage, the form every web-server gate uses (format 1, one IPv4 range, unchanged byte for byte):
    make-test-snapshot.py <path> [generation] [valid_until_ms] [severity] [start] [end]
    make-test-snapshot.py --evidence

Usage, any plane:
    make-test-snapshot.py --plane <name> --out <path> [--format 1|2] [--schema]
        [--v4-index none|radix-12|radix-16|radix-18|rank] [--v6-index ...]
        [--synthetic <n4> <n6> | --records <path>] [--generation N] [--valid-until MS] [--expect <path>]

--records names the ranges and their records instead of drawing synthetic ones: one range per line,
`<4|6> <start> <end> [field=value ...]`, start and end the range's keys as integers (decimal or 0x hex;
an IPv6 key is the address, or its top 64 bits on the routing and registry planes), in key order and
disjoint; the fields are the plane's record fields (format 1: sev), unnamed ones zero. The cross-server
differential writes its planes so, from the one record set it also hands the reference interpreter.

Usage, the domain sweep (every in-domain value of every record field, and each field's refused edges):
    make-test-snapshot.py --sweep <dir> [--generation N] [--valid-until MS]

--expect writes, for every range, the addresses that decide an outcome (start - 1, start, end,
end + 1; on 64-bit keys each with the low 64 bits at 0 and at all ones) and the answer the reader must
give: the range index and the record bytes (format 1: the severity byte), or `-`. A hit line ends in a
`fields=` token written from the record this writer packed, never read back from the bytes:
`fields=asn=..,country=..,rov=..,rir=..,flags=..,asn_rep=..` on the routing schema,
`fields=flags=..,source=..,reason=..` on the membership schema, `fields=sev=..` on format 1.
plane_check.c reads it. Synthetic ranges are spread over the whole key space by a fixed rule, with
every record field inside its domain.

Defaults of the legacy form cover 127.0.0.0/8 at HIGH with no validity bound, so the loopback client
of a gate is the address being judged and no header trickery is needed. valid_until_ms of 0 means "no
bound", which is what the format says; pass a small number to make a deliberately stale snapshot.
"""
import bisect
import hashlib
import ipaddress
import os
import struct
import sys

HDR = 192
MAGIC = 0x31504E5347444557        # "WEDGSNP1"
H_V4_INDEXED, H_V6_INDEXED, H_SCHEMA = 0x1, 0x2, 0x4
KIND = {"none": 0, "radix": 1, "rank": 2}
PLANES = {"reputation": 1, "tor": 2, "rpki-unreachable": 3, "routing": 4, "anonymizer": 5,
          "threat": 6, "registry": 7, "tenant": 8}
MEMBER_FLAGS = {"tor": 0x01, "rpki-unreachable": 0x01, "anonymizer": 0x03, "threat": 0x3f,
                "tenant": 0x03}
COUNTRY_TABLE_VERSION = 202312 % 65536
FEEDS = ("", "feed-a", "feed-b", "feed-c", "feed-d", "feed-e", "feed-f")

# The evidence string the fixture carries. Shaped like a real listing (an SBL id plus an abuse
# contact, with a space in it) because that is what the real builder writes, and a fixture that looks
# nothing like production hides formatting bugs. Printed by `--evidence` so no gate holds a copy.
EVIDENCE = "SBL-EXAMPLE-EVIDENCE-12345 abuse@example.net"


def write(path, generation=1, valid_until_ms=0, severity=3, start=0x7F000000, end=0x7FFFFFFF):
    # The substring EXAMPLE-EVIDENCE is load-bearing: nginx-gate.sh and apache-gate.sh assert that a
    # deny log line carries the evidence, and they grep for it. It is shaped like a real listing (an
    # SBL id plus an abuse contact) because that is what the real builder puts here, and a fixture
    # that looks nothing like production is a fixture that hides a formatting bug.
    blob = b"\0" + EVIDENCE.encode() + b"\0"
    off = HDR
    v4_start, off = off, off + 4
    v4_end, off = off, off + 4
    v4_meta, off = off, off + 4
    v4_sev, off = off, off + 1
    blob_off, off = off, off + len(blob)
    total = off

    h = bytearray(total)
    struct.pack_into('<Q', h, 0, MAGIC)
    struct.pack_into('<I', h, 8, 1)                 # format
    struct.pack_into('<I', h, 12, 0)                # flags: no bucket index at this size
    struct.pack_into('<Q', h, 16, generation)
    struct.pack_into('<Q', h, 24, 1)                # built_at_ms
    struct.pack_into('<Q', h, 32, valid_until_ms)
    struct.pack_into('<I', h, 40, 1)                # tier
    struct.pack_into('<I', h, 44, 1)                # v4_count
    struct.pack_into('<I', h, 56, v4_start)
    struct.pack_into('<I', h, 60, v4_end)
    struct.pack_into('<I', h, 64, v4_sev)
    struct.pack_into('<I', h, 68, v4_meta)
    struct.pack_into('<I', h, 92, blob_off)
    struct.pack_into('<I', h, 96, len(blob))
    struct.pack_into('<I', h, 100, total)
    struct.pack_into('<I', h, v4_meta, 1)           # meta[0] -> blob offset 1
    h[blob_off:blob_off + len(blob)] = blob
    struct.pack_into('<I', h, v4_start, start)
    struct.pack_into('<I', h, v4_end, end)
    h[v4_sev] = severity
    save(path, sign(h))


def sign(h):
    bare = bytearray(h[:HDR])
    bare[104:136] = b'\0' * 32
    h[104:136] = hashlib.sha256(bytes(bare) + bytes(h[HDR:])).digest()
    return h


def save(path, h):
    with open(path, 'wb') as f:
        f.write(bytes(h))
    # 0644 EXPLICITLY. The loader refuses a group- or world-writable snapshot, and the ambient umask
    # on a good number of distributions is 002, so a fixture written without this is one the module is
    # right to reject. The symptom is a gate reporting "the default mode is silent" rather than "your
    # fixture is group-writable", which is how a correct security check reads as a broken product.
    os.chmod(path, 0o644)


# ---- any plane ----

def up(v, a):
    return (v + a - 1) // a * a


def key_bytes(plane, fmt, family):
    if family == 4:
        return 4
    if fmt == 1:
        return 16
    return 8 if plane in ("routing", "registry") else 16


def record_stride(plane, fmt, family):
    if fmt == 1:
        return 0
    if family == 4:
        return 16
    return 24 if plane in ("routing", "registry") else 32


def depth_of(m, fan):
    """The smallest d with fan**d >= m, in integers (FORMAT.md 4.2)."""
    d, p = 0, 1
    while p < m:
        p *= fan
        d += 1
    return d


def synthetic_ranges(n, kb):
    """n ranges spread evenly over the key space, each a third of a step wide, gaps between."""
    top = (1 << (8 * kb)) - 1
    step = top // (n + 1)
    return [((i + 1) * step, (i + 1) * step + step // 3) for i in range(n)]


ROUTING_FIELDS = ("asn", "country", "rov", "rir", "flags", "asn_rep")
MEMBER_FIELDS = ("flags", "source", "reason")


def synthetic_fields(plane, family, i):
    """The record's attribute fields, as a dict, by the fixed synthetic rule; every value in its domain."""
    if plane in ("routing", "registry"):
        return {"asn": 64496 + i if family == 4 else 4200000000 + i,
                "country": (528, 840, 276, 999, 0)[i % 5],      # 999: in range, assigned to nothing
                "rov": 1 + i % 3, "rir": i % 6,
                "flags": i % (4 if family == 4 else 8),         # narrowed (bit 2) is IPv6 only
                "asn_rep": i % 5}
    return {"flags": (i % MEMBER_FLAGS[plane]) + 1, "source": i % 7,
            "reason": (i % 3) if plane == "rpki-unreachable" else 0}


def pack_record(plane, fmt, family, end, rec):
    """The record bytes from a field dict: the end in the key width, the attributes, zero padding."""
    kb = key_bytes(plane, fmt, family)
    endb = end.to_bytes(kb, 'little')
    if plane in ("routing", "registry"):
        body = struct.pack('<IHBBBB', *(rec[k] for k in ROUTING_FIELDS))
    else:
        body = struct.pack('<IBB', *(rec[k] for k in MEMBER_FIELDS))
    return endb + body + bytes(record_stride(plane, fmt, family) - kb - len(body))


def fields_token(plane, fmt, rec):
    """The `fields=` token an --expect hit line carries, written from the dict this writer packed (the
    record) or the severity byte it wrote (format 1), never read back from the bytes."""
    if fmt == 1:
        return "fields=sev=%d" % rec
    names = ROUTING_FIELDS if plane in ("routing", "registry") else MEMBER_FIELDS
    return "fields=" + ",".join("%s=%d" % (k, rec[k]) for k in names)


def synthetic_record(plane, fmt, family, i, end):
    return pack_record(plane, fmt, family, end, synthetic_fields(plane, family, i))


def build_stree(starts, s, kb):
    """The complete (B+1)-ary tree of the m - 1 separators, nodes in level order, keys in order."""
    n = len(starts)
    m = (n + s - 1) // s
    b = 64 // kb
    fan = b + 1
    d = depth_of(m, fan)
    nodes = (fan ** d - 1) // b
    kmax = (1 << (8 * kb)) - 1
    out = bytearray(nodes * 64)
    first = 0
    for level in range(d):
        width = fan ** level
        below = fan ** (d - 1 - level)
        for t in range(width):
            for q in range(b):
                p = (t * fan + q + 1) * below - 1
                v = starts[(p + 1) * s] if p < m - 1 else kmax
                at = (first + t) * 64 + q * kb
                out[at:at + kb] = v.to_bytes(kb, 'little')
        first += width
    return bytes(out), m, d


def write_plane(path, plane, fmt, schema, kinds, ranges, generation=1, valid_until_ms=0, expect=None,
                records=None):
    """kinds: {4: ('radix', k) | ('rank', None) | ('none', None), 6: ...}; ranges: {4: [(s, e)], 6: ...},
    a range (s, e) taking the synthetic record of its index, or (s, e, record) its own (--records; unnamed
    fields are zero, format 1's record is {'sev': byte}); records: None, else {4: [...], 6: [...]} with one
    field dict per range (format 2) or one severity byte per range (format 1), which the sweep passes."""
    schema = schema or fmt == 2
    lay = {}
    off = up(HDR, 64) if fmt == 2 else HDR
    for fam in (4, 6):
        kb = key_bytes(plane, fmt, fam)
        kind, k = kinds[fam]
        rs = ranges[fam]
        n = len(rs)
        L = {"kb": kb, "n": n, "kind": KIND[kind], "param": 0}
        if kind == "radix":
            L["param"] = 16 if fmt == 1 else k
        if kind == "rank":
            L["param"] = 5 if kb == 16 else 6
        lay[fam] = L
        if n == 0:
            continue
        starts = [r[0] for r in rs]
        if fmt == 2:
            if kind == "radix":
                off = up(off, 64)          # FORMAT.md 5: the radix table is 64-byte aligned
                L["idx"] = off
                off += ((1 << L["param"]) + 1) * 4
            off = up(off, 64)
            L["start"] = off
            off += n * kb
            off = up(off, 64)
            L["rec"] = off
            off += n * record_stride(plane, fmt, fam)
            if kind == "rank":
                tree, m, d = build_stree(starts, 1 << L["param"], kb)
                L["tree"], L["m"], L["depth"] = tree, m, d
                if tree:
                    off = up(off, 64)
                    L["sample"] = off
                    off += len(tree)
        else:
            off = up(off, kb)
            L["start"] = off
            off += n * kb
            off = up(off, kb)
            L["end"] = off
            off += n * kb
            if kind == "radix":
                off = up(off, 4)
                L["idx"] = off
                off += 65537 * 4
            L["sev"] = off
            off += n
    # Format 2's blob is the feed-name table: u16 count, then NUL-terminated names, entry 0 "" (none).
    # The synthetic membership `source` runs 0..6, so seven entries.
    blob = b""
    if fmt == 2:
        blob = struct.pack('<H', len(FEEDS)) + b"".join(n.encode() + b"\0" for n in FEEDS)
    blob_off = off if blob else 0
    off += len(blob)
    total = off
    h = bytearray(total)
    h[blob_off:blob_off + len(blob)] = blob
    flags = (H_V4_INDEXED if lay[4]["kind"] == 1 else 0) | (H_V6_INDEXED if lay[6]["kind"] == 1 else 0)
    flags |= H_SCHEMA if schema else 0
    struct.pack_into('<QIIQQQI', h, 0, MAGIC, fmt, flags, generation, 1, valid_until_ms, 1)
    struct.pack_into('<II', h, 44, lay[4]["n"], lay[6]["n"])
    for fam, base in ((4, 52), (6, 72)):
        L = lay[fam]
        struct.pack_into('<IIIII', h, base, L.get("idx", 0), L.get("start", 0), L.get("end", 0),
                         L.get("sev", 0), 0)
    struct.pack_into('<III', h, 92, blob_off, len(blob), total)
    if schema:
        schema_id = 0 if fmt == 1 else (1 if plane in ("routing", "registry") else 2)
        struct.pack_into('<BBBBBBBB', h, 136, PLANES[plane], schema_id, 32, lay[6]["kb"] * 8,
                         lay[4]["kind"], lay[4]["param"], lay[6]["kind"], lay[6]["param"])
        struct.pack_into('<HH', h, 144, record_stride(plane, fmt, 4), record_stride(plane, fmt, 6))
        struct.pack_into('<IIIIII', h, 148, lay[4].get("rec", 0), lay[6].get("rec", 0),
                         lay[4].get("sample", 0), lay[6].get("sample", 0),
                         lay[4].get("m", 0), lay[6].get("m", 0))
        struct.pack_into('<HBB', h, 172, COUNTRY_TABLE_VERSION if schema_id == 1 else 0,
                         lay[4].get("depth", 0), lay[6].get("depth", 0))

    lines = []
    packed_by_fam = {4: [], 6: []}
    for fam in (4, 6):
        L = lay[fam]
        rs = ranges[fam]
        kb = L["kb"]
        if not rs:
            continue
        starts = [rr[0] for rr in rs]
        packed = []
        for i, rr in enumerate(rs):
            s, e = rr[0], rr[1]
            own = rr[2] if len(rr) > 2 else None
            h[L["start"] + i * kb:L["start"] + (i + 1) * kb] = s.to_bytes(kb, 'little')
            if fmt == 2:
                st = record_stride(plane, fmt, fam)
                if records is not None:
                    rec = records[fam][i]
                elif own is not None:
                    names = ROUTING_FIELDS if plane in ("routing", "registry") else MEMBER_FIELDS
                    rec = {k: own.get(k, 0) for k in names}
                else:
                    rec = synthetic_fields(plane, fam, i)
                h[L["rec"] + i * st:L["rec"] + (i + 1) * st] = pack_record(plane, fmt, fam, e, rec)
            else:
                h[L["end"] + i * kb:L["end"] + (i + 1) * kb] = e.to_bytes(kb, 'little')
                if records is not None:
                    rec = records[fam][i]
                elif own is not None:
                    rec = own['sev']
                else:
                    rec = 1 + i % 4
                h[L["sev"] + i] = rec
            packed.append(rec)
        packed_by_fam[fam] = packed
        if L["kind"] == 1:
            k = L["param"]
            cur = 0
            for b in range(1 << k):
                while cur < len(starts) and starts[cur] >> (8 * kb - k) < b:
                    cur += 1
                struct.pack_into('<I', h, L["idx"] + 4 * b, cur)
            struct.pack_into('<I', h, L["idx"] + 4 * (1 << k), len(starts))
        if L.get("tree"):
            h[L["sample"]:L["sample"] + len(L["tree"])] = L["tree"]
        if expect is not None:
            top = (1 << (8 * kb)) - 1
            for r in rs:
                s, e = r[0], r[1]
                for a in (s - 1, s, e, e + 1):
                    if a < 0 or a > top:
                        continue
                    u = bisect.bisect_right(starts, a)
                    hit = u > 0 and a <= rs[u - 1][1]
                    if fmt == 2:
                        st = record_stride(plane, fmt, fam)
                        want = "%d rec=%s %s" % (u - 1, h[L["rec"] + (u - 1) * st:L["rec"] + u * st].hex(),
                                                 fields_token(plane, fmt, packed[u - 1])) if hit else "-"
                    else:
                        want = "%d sev=%d %s" % (u - 1, h[L["sev"] + u - 1], fields_token(plane, fmt, packed[u - 1])) \
                            if hit else "-"
                    if fam == 4:
                        lines.append("4 %s %s" % (ipaddress.IPv4Address(a), want))
                    elif kb == 8:
                        for low in (0, (1 << 64) - 1):
                            lines.append("6 %s %s" % (ipaddress.IPv6Address((a << 64) | low), want))
                    else:
                        lines.append("6 %s %s" % (ipaddress.IPv6Address(a), want))
    save(path, sign(h))
    if expect is not None:
        with open(expect, 'w') as f:
            f.write("\n".join(lines) + "\n")
        # Every range with the fields this writer packed into it, so a case generator can find the record
        # any address hits from the writer's own data, never by reading the plane back:
        # `<family> <key-bytes> <start> <end> fields=...`, keys as integers (a 64-bit IPv6 key is the
        # address's top 64 bits).
        with open(os.path.splitext(expect)[0] + ".ranges", 'w') as f:
            for fam in (4, 6):
                kb = lay[fam]["kb"]
                for i, rr in enumerate(ranges[fam]):
                    f.write("%d %d %d %d %s\n" % (fam, kb, rr[0], rr[1],
                                                  fields_token(plane, fmt, packed_by_fam[fam][i])))


def parse_kind(text):
    if text in ("none", "rank"):
        return (text, None)
    if text.startswith("radix-") and text[6:] in ("12", "16", "18"):
        return ("radix", int(text[6:]))
    raise SystemExit("unknown index kind %r: none, radix-12, radix-16, radix-18 or rank" % text)


def read_records(path, plane, fmt):
    """The --records file: {4: [(s, e, rec)], 6: [...]}, checked for order, disjointness and key width."""
    out = {4: [], 6: []}
    fields = ("asn", "country", "rov", "rir", "flags", "asn_rep") if plane in ("routing", "registry") \
        else ("sev",) if fmt == 1 else ("flags", "source", "reason")
    with open(path) as f:
        for n, line in enumerate(f, 1):
            w = line.split()
            if not w or w[0].startswith('#'):
                continue
            if len(w) < 3 or w[0] not in ("4", "6"):
                raise SystemExit("%s:%d: a records line is `<4|6> <start> <end> [field=value ...]`" % (path, n))
            fam = int(w[0])
            s, e = int(w[1], 0), int(w[2], 0)
            top = (1 << (8 * key_bytes(plane, fmt, fam))) - 1
            if not 0 <= s <= e <= top:
                raise SystemExit("%s:%d: the range %d..%d is not inside the %d-byte key space in order" %
                                 (path, n, s, e, key_bytes(plane, fmt, fam)))
            if out[fam] and s <= out[fam][-1][1]:
                raise SystemExit("%s:%d: the range %d..%d is not after the previous one (%d..%d)" %
                                 (path, n, s, e, out[fam][-1][0], out[fam][-1][1]))
            rec = {}
            for kv in w[3:]:
                k, _, v = kv.partition('=')
                if k not in fields:
                    raise SystemExit("%s:%d: %r is not a field of the %s plane (%s)" % (path, n, k, plane, ' '.join(fields)))
                rec[k] = int(v, 0)
            out[fam].append((s, e, rec))
    return out


VALUED = ("--plane", "--out", "--format", "--v4-index", "--v6-index", "--records", "--generation",
          "--valid-until", "--expect")


def usage_error(msg):
    """A refusal that names what was wrong and the usage, exit 2, nothing written."""
    print("make-test-snapshot.py: %s\n\n%s" % (msg, __doc__.strip().split("\n\n", 1)[1].split("--records")[0].strip()),
          file=sys.stderr)
    sys.exit(2)


def out_path(path):
    """An output path that starts with a dash is an option mistyped, never a file to create."""
    if path.startswith("-"):
        usage_error("%r is an option, not an output path (an output path never starts with a dash)" % path)
    return path


def main_plane(argv):
    opts = {"--format": "2", "--v4-index": "radix-16", "--v6-index": "rank", "--generation": "1",
            "--valid-until": "0"}
    flags = set()
    synth = (300, 700)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--schema":
            flags.add(a)
            i += 1
        elif a == "--synthetic":
            if i + 2 >= len(argv):
                usage_error("--synthetic takes two counts")
            flags.add(a)
            synth = (int(argv[i + 1]), int(argv[i + 2]))
            i += 3
        elif a in VALUED:
            if i + 1 >= len(argv):
                usage_error("%s takes a value" % a)
            opts[a] = argv[i + 1]
            i += 2
        else:
            usage_error("unknown option %r" % a)
    if "--out" not in opts:
        usage_error("--plane needs --out <path>")
    out_path(opts["--out"])
    plane = opts["--plane"]
    if plane not in PLANES:
        raise SystemExit("unknown plane %r" % plane)
    fmt = int(opts["--format"])
    records = None
    if "--records" in opts:
        if "--synthetic" in flags:
            raise SystemExit("--records and --synthetic name two sources of ranges; give one")
        records = read_records(opts["--records"], plane, fmt)
    if (fmt == 1) != (plane == "reputation"):
        raise SystemExit("format 1 is the reputation plane's layout and every other plane is format 2")
    kinds = {4: parse_kind(opts["--v4-index"]), 6: parse_kind(opts["--v6-index"])}
    if fmt == 1 and any(k[0] == "rank" or (k[0] == "radix" and k[1] != 16) for k in kinds.values()):
        raise SystemExit("format 1 carries the radix-16 index or none")
    if records is not None:
        ranges = records
    else:
        ranges = {4: synthetic_ranges(synth[0], 4), 6: synthetic_ranges(synth[1], key_bytes(plane, fmt, 6))}
    write_plane(opts["--out"], plane, fmt, "--schema" in flags, kinds, ranges,
                int(opts["--generation"], 0), int(opts["--valid-until"], 0), opts.get("--expect"))


# ---- the domain sweep: every in-domain value of every record field, and each field's refused edges ----
#
# The loader refuses a WHOLE plane on the first record outside its domain (FORMAT.md section 3); a
# reader that renders those fields must therefore be shown every value it can be handed and every
# value that makes the loader refuse. One directory holds every in-domain value, each in its own range
# with the plane's other fields at 0, so all eight planes arm fresh; one directory per refused value
# holds a one-range plane that must be refused. The counts are derived here and restated, from the
# same domain table, by lookup-states.py, which asserts them.

SWEEP_ASN = (0, 1, 23456, 64495, 64496, 65535, 65536, 4199999999, 4294967294, 4294967295)
DEFINED_BITS = {"tor": (0x01,), "rpki-unreachable": (0x01,), "anonymizer": (0x01, 0x02),
                "threat": (0x01, 0x02, 0x04, 0x08, 0x10, 0x20), "tenant": (0x01, 0x02)}
LOWEST_UNDEFINED_BIT = {"tor": 0x02, "rpki-unreachable": 0x02, "anonymizer": 0x04, "threat": 0x40,
                        "tenant": 0x04}
SWEEP_KINDS = {1: {4: ("radix", 16), 6: ("radix", 16)}, 2: {4: ("radix", 16), 6: ("rank", None)}}


def sweep_routing_values(family):
    """(field, value) per range, other fields 0: rov 0..3, rir 0..5, asn_rep 0..4, country 0..999, ten
    AS numbers, flags 0..3 on IPv4 and 0..7 on IPv6 (narrowed is IPv6 only)."""
    out = [("rov", v) for v in range(4)] + [("rir", v) for v in range(6)]
    out += [("asn_rep", v) for v in range(5)] + [("country", v) for v in range(1000)]
    out += [("asn", v) for v in SWEEP_ASN] + [("flags", v) for v in range(4 if family == 4 else 8)]
    return out


def sweep_member_values(plane):
    out = [("flags", b) for b in DEFINED_BITS[plane]]
    if plane == "threat":
        out += [("source", v) for v in range(1, len(FEEDS))]
    if plane == "rpki-unreachable":
        out += [("reason", v) for v in (1, 2)]
    return out


def sweep_record(plane, field, value):
    names = ROUTING_FIELDS if plane in ("routing", "registry") else MEMBER_FIELDS
    rec = {k: 0 for k in names}
    rec[field] = value
    return rec


def sweep_refusals():
    """(plane, family, field, value): the first out-of-domain value and the field's maximum."""
    out = []
    for plane in ("routing", "registry"):
        for fam in (4, 6):
            for field, first, top in (("rov", 4, 255), ("rir", 6, 255), ("asn_rep", 5, 255),
                                      ("country", 1000, 65535)):
                if fam == 4:
                    out += [(plane, fam, field, first), (plane, fam, field, top)]
            out += [(plane, fam, "flags", 4 if fam == 4 else 8), (plane, fam, "flags", 255)]
    for plane in ("tor", "rpki-unreachable", "anonymizer", "threat", "tenant"):
        out += [(plane, 4, "flags", LOWEST_UNDEFINED_BIT[plane]), (plane, 4, "flags", 0xFFFFFFFF)]
    out += [("threat", 4, "source", len(FEEDS)), ("threat", 4, "source", 255)]
    out += [("rpki-unreachable", 4, "reason", 3), ("rpki-unreachable", 4, "reason", 255)]
    out += [("threat", 4, "reason", 1), ("threat", 4, "reason", 255)]
    return out


def main_sweep(argv):
    opts = {"--generation": "1", "--valid-until": "0"}
    out = argv[0]
    i = 1
    while i < len(argv):
        opts[argv[i]] = argv[i + 1]
        i += 2
    gen, vu = int(opts["--generation"], 0), int(opts["--valid-until"], 0)
    ind = os.path.join(out, "in-domain")
    os.makedirs(ind, exist_ok=True)
    index = []
    totals = {4: 0, 6: 0}
    for plane in PLANES:
        fmt = 1 if plane == "reputation" else 2
        records, ranges = {}, {}
        for fam in (4, 6):
            if plane == "reputation":
                records[fam] = list(range(256))
            elif plane in ("routing", "registry"):
                records[fam] = [sweep_record(plane, f, v) for f, v in sweep_routing_values(fam)]
            else:
                records[fam] = [sweep_record(plane, f, v) for f, v in sweep_member_values(plane)]
            ranges[fam] = synthetic_ranges(len(records[fam]), key_bytes(plane, fmt, fam))
            totals[fam] += len(records[fam])
        write_plane(os.path.join(ind, plane + ".bin"), plane, fmt, True, SWEEP_KINDS[fmt], ranges, gen, vu,
                    os.path.join(ind, plane + ".expect"), records)
        index.append("fresh in-domain %s %d %d" % (plane, len(records[4]), len(records[6])))
    refused = sweep_refusals()
    for plane, fam, field, value in refused:
        name = "refused-%s-v%d-%s-%d" % (plane, fam, field, value)
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        fmt = 2
        kb = key_bytes(plane, fmt, fam)
        ranges = {4: [], 6: []}
        records = {4: [], 6: []}
        ranges[fam] = synthetic_ranges(1, kb)
        records[fam] = [sweep_record(plane, field, value)]
        write_plane(os.path.join(d, plane + ".bin"), plane, fmt, True, SWEEP_KINDS[fmt], ranges, gen, vu, None,
                    records)
        s = ranges[fam][0][0]
        addr = ipaddress.IPv4Address(s) if fam == 4 else \
            ipaddress.IPv6Address(s << 64 if kb == 8 else s)
        index.append("refused %s %s %d %s %d %s" % (name, plane, fam, field, value, addr))
    index.append("totals in-domain-v4 %d in-domain-v6 %d refused %d" % (totals[4], totals[6], len(refused)))
    with open(os.path.join(out, "sweep.txt"), "w") as f:
        f.write("\n".join(index) + "\n")
    print("sweep %s: %d IPv4 and %d IPv6 in-domain ranges over 8 planes, %d refused planes"
          % (out, totals[4], totals[6], len(refused)))


if __name__ == '__main__':
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(__doc__.strip())
        sys.exit(0)
    if len(sys.argv) >= 3 and sys.argv[1] == '--sweep':
        main_sweep(sys.argv[2:])
        sys.exit(0)
    # `--evidence` prints the evidence string this generator writes, so a gate asserting that a deny
    # log line carries it can ASK rather than hold a second copy of the literal. Two copies is how
    # this broke once: the string was improved here and nginx-gate.sh went on grepping for the old
    # one, reporting "the feed cannot explain itself" about a feed that explained itself fine.
    if len(sys.argv) == 2 and sys.argv[1] == '--evidence':
        print(EVIDENCE)
        sys.exit(0)
    if len(sys.argv) >= 2 and sys.argv[1] == '--plane':
        main_plane(sys.argv[1:])
        sys.exit(0)
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    args = sys.argv[2:]
    write(out_path(sys.argv[1]), *[int(a, 0) for a in args])
