#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
"""check-record.py - read back the record bench_core wrote, and hold it to its shape.

The record is what a page reads verbatim, so it is checked the way a reader would use it: it parses as
JSON; it carries its key (record, version, commit, compiler, flags, machine, and the data it measured);
the layout table has every size and every layout, each with its bound columns; the policy table says
whether it ran, and when it ran every rule carries its counts, with instructions no fewer than
operations (every operation is at least one instruction) and the END each rule adds.

    check-record.py RECORD [COMMIT]     check one record; with COMMIT, the record must carry exactly
                                        that commit (make bench passes the tree's, so a record written
                                        by a binary from another commit is refused)
    check-record.py --selftest RECORD   the negative controls: the record must pass, and a copy with
                                        its commit removed, one with a layout row dropped, one from
                                        another commit and one with a rule's instructions below its
                                        operations must each be refused

A commit of "unknown" is accepted and said out loud: a vendored copy has no git, and its record is
still the numbers its build printed.
"""

import copy
import json
import sys

LAYOUTS = {"f1 unindexed", "f1 radix-16", "f2 radix-12", "f2 radix-16", "f2 radix-18", "f2 rank-64"}
SIZES = {500, 4000, 32000, 120000, 1500000}
LAYOUT_KEYS = {"ranges", "layout", "fileBytes", "widestWindow", "maxProbes", "depth", "meanNsInformation"}
RULE_KEYS = {"program", "rule", "operations", "instructions", "planeMask", "text"}


def check(rec, commit=None):
    """The list of what is wrong with a record; empty when nothing is."""
    bad = []
    if commit is not None and rec.get("commit") != commit:
        bad.append("the record's commit is %r and the tree's is %r: it was written by another build" % (
            rec.get("commit"), commit))
    if rec.get("record") != "whisper-edge-bench" or rec.get("version") != 1:
        bad.append("not a version-1 whisper-edge-bench record")
    for k in ("commit", "compiler", "flags", "machine"):
        if not isinstance(rec.get(k), str) or not rec.get(k):
            bad.append("the key field %s is missing or empty" % k)
    data = rec.get("data")
    if not isinstance(data, dict) or "seed" not in data or "planeGeneration" not in data:
        bad.append("the data the record measured is not named (seed, planeGeneration)")
    rows = rec.get("layout")
    if not isinstance(rows, list):
        bad.append("no layout table")
        rows = []
    seen = set()
    for r in rows:
        if not isinstance(r, dict) or set(r) != LAYOUT_KEYS:
            bad.append("a layout row has the wrong fields: %r" % (r,))
            continue
        seen.add((r["ranges"], r["layout"]))
    want = {(s, l) for s in SIZES for l in LAYOUTS}
    if seen != want:
        bad.append("the layout table is missing %d of its %d rows" % (len(want - seen), len(want)))
    pol = rec.get("policy")
    if not isinstance(pol, dict) or pol.get("status") not in ("dark", "live"):
        bad.append("the policy table does not say whether it ran")
    elif pol["status"] == "dark":
        if not pol.get("why"):
            bad.append("the policy table is dark and does not say why")
    else:
        rules = pol.get("rules")
        if not isinstance(rules, list) or not rules:
            bad.append("the policy table ran and holds no rule")
            rules = []
        for r in rules:
            if not isinstance(r, dict) or set(r) != RULE_KEYS:
                bad.append("a policy rule has the wrong fields: %r" % (r,))
                continue
            if r["instructions"] < r["operations"] + 1:
                bad.append("%s rule %s: %s instructions for %s operations and an END" % (
                    r["program"], r["rule"], r["instructions"], r["operations"]))
    return bad


def main(argv):
    if len(argv) == 3 and argv[1] == "--selftest":
        with open(argv[2]) as fh:
            rec = json.load(fh)
        failures = []
        if check(rec):
            failures.append("the real record was refused: %s" % "; ".join(check(rec)))
        no_commit = copy.deepcopy(rec)
        del no_commit["commit"]
        short = copy.deepcopy(rec)
        short["layout"] = short["layout"][1:]
        mutants = [("its commit removed", no_commit), ("a layout row dropped", short)]
        other = copy.deepcopy(rec)
        other["commit"] = "0" * 40
        if not check(other, rec.get("commit")):
            failures.append("a record from another commit was ACCEPTED")
        if rec.get("policy", {}).get("status") == "live":
            low = copy.deepcopy(rec)
            low["policy"]["rules"][0]["instructions"] = low["policy"]["rules"][0]["operations"]
            mutants.append(("a rule's instructions below its operations and END", low))
        for what, m in mutants:
            if not check(m):
                failures.append("a record with %s was ACCEPTED" % what)
        if failures:
            for f in failures:
                print("RECORD SELFTEST FAIL: " + f)
            return 1
        print("ok   check-record.py refuses a record with %s, and one from another commit"
              % ", with ".join(w for w, _ in mutants))
        return 0
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    try:
        with open(argv[1]) as fh:
            rec = json.load(fh)
    except (OSError, ValueError) as e:
        print("RECORD FAIL: %s does not read back as JSON: %s" % (argv[1], e))
        return 1
    bad = check(rec, argv[2] if len(argv) == 3 else None)
    if bad:
        for b in bad:
            print("RECORD FAIL: " + b)
        return 1
    note = " (commit unknown: no git here)" if rec["commit"] == "unknown" else ""
    print("ok   the bench record reads back: commit %s%s, %s, %d layout rows, policy table %s" % (
        rec["commit"], note, rec["compiler"], len(rec["layout"]),
        rec["policy"]["status"] + ("" if rec["policy"]["status"] == "live" else " (" + rec["policy"]["why"] + ")")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
