#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
make-tenant-plane.py - a tenant plane for the install gate, written by the independent writer.

It drives core/make-test-snapshot.py's write_plane (the writer the interop gate holds the C reader
to) with a tenant's own ranges and the feed-name table FORMAT.md's fourth amendment fixes for the
tenant plane: entry 0 empty, entry 1 tenant:<16 hex>, entry 2 rev:<decimal>, every record's source 1.
The --names and --source options exist to write the planes the refresh must refuse.

Usage:
    make-tenant-plane.py OUT --gen G --tenant HEX16 --rev R [--valid-until MS]
        [--allow CIDR]... [--deny CIDR]... [--names 'a,b,c'] [--source N]
"""
import importlib.util
import ipaddress
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "mts", os.path.join(HERE, "..", "..", "core", "make-test-snapshot.py"))
mts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mts)


def main(argv):
    out = argv[0]
    opts = {"--gen": "1", "--valid-until": "0", "--source": "1"}
    lists = {"--allow": [], "--deny": []}
    i = 1
    while i < len(argv):
        if argv[i] in lists:
            lists[argv[i]].append(argv[i + 1])
        else:
            opts[argv[i]] = argv[i + 1]
        i += 2
    names = opts.get("--names")
    if names is None:
        names = ",".join(("", "tenant:" + opts["--tenant"], "rev:" + opts["--rev"]))
    mts.FEEDS = tuple(names.split(","))
    # one range per entry, bit 0 tenant_allow and bit 1 tenant_deny; no merging, the gate's lists
    # never overlap
    ranges = {4: [], 6: []}
    for flag, key in ((1, "--allow"), (2, "--deny")):
        for cidr in lists[key]:
            n = ipaddress.ip_network(cidr, strict=False)
            ranges[n.version].append((int(n.network_address), int(n.broadcast_address), flag))
    if not ranges[4] and not ranges[6]:
        ranges[4].append((int(ipaddress.ip_address("192.0.2.1")),) * 2 + (2,))
    flags = {}
    for fam in (4, 6):
        ranges[fam].sort()
        for j, (_, _, f) in enumerate(ranges[fam]):
            flags[(fam, j)] = f
    source = int(opts["--source"])

    # Each record's fields through write_plane's records= argument, packed by make-test-snapshot.py's own
    # pack_record (flags, source, reason), so the writer and its readers share one layout. (Before the rebase
    # onto the merged streams this replaced mts.synthetic_record, which write_plane no longer calls: every
    # fixture then carried the synthetic source 0 and the refresh refused it.)
    records = {fam: [{"flags": flags[(fam, j)], "source": source, "reason": 0} for j in range(len(ranges[fam]))]
               for fam in (4, 6)}
    kinds = {fam: (("rank", None) if ranges[fam] else ("none", None)) for fam in (4, 6)}
    mts.write_plane(out, "tenant", 2, True, kinds, {fam: [(s, e) for s, e, _ in ranges[fam]] for fam in (4, 6)},
                    int(opts["--gen"]), int(opts["--valid-until"]), records=records)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1:])
