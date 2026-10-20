#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
lookup-check.py - the second reading of whisper-edge-lookup's output and of the manifests it reads.

Standard library only. Written from the output grammar and the manifest rules, never from the C.

    lookup-check.py doc <json-file> <lines-file>
        The two output forms of one run: (a) the JSON is canonical (re-serialised with ',' and ':' it is
        byte-identical); (b) the lines rendered from the parsed JSON equal the line output byte for byte;
        (c) every field has its type, by name; (d) every field whose presence condition holds is present
        and none whose condition fails; plus the JSON names, the positional counts, the comma-list member
        patterns and a refused address's shape.
    lookup-check.py docs <list-file>
        `doc` over many runs in one process: each line of the list names a JSON file and a lines file.
    lookup-check.py lines <lines-file>
        The line form alone: every line tokenizes with its kind's positional count.
    lookup-check.py manifest <file>...
        The reference manifest reader: one dump per file, the format fuzz_manifest prints, so the two
        readers can be compared byte for byte.
    lookup-check.py seeds <out-dir>
        The manifest reader's seed corpus, every cap at its bound and one past it among them.
    lookup-check.py derive <writer-dir> <tor-plane> <out-dir>
        The derived manifests: the writer's own manifests (testdata/lookup/writer/, written by the real
        publisher) verbatim or with one edit each; <tor-plane> is the plane the tor-as-routing edit names
        (testdata/lookup/derived/README.md names each).
    lookup-check.py transcripts <edge-dir> <tool> <work-dir> [--plant]
        Every whisper-edge-lookup transcript in REFERENCE.md that reads the checked-in fixtures, run again
        with <tool> in <work-dir> (each fixture copied there at mode 0644, and `data` seeded from
        core/testdata/format2/tor.bin at 0444, as the README says) and compared with the transcript byte
        for byte, stdout only. A transcript that reads anything else is named with why it cannot run.
        --plant changes one expected line first, the control: the run must then fail.
    lookup-check.py normalise <file>
        The one normalisation for comparing whole outputs: the values of `dir` and `snapshot` only.

Exit 0 when every check passes; each failing check prints one `FAIL` line. The last line is always
`N checks, F failures`.
"""
import hashlib
import json
import os
import re
import sys

CHECKS = [0, 0]


def check(cond, what):
    CHECKS[0] += 1
    if not cond:
        CHECKS[1] += 1
        print("FAIL " + what)
    return cond


def finish():
    print("%d checks, %d failures" % (CHECKS[0], CHECKS[1]))
    sys.exit(0 if CHECKS[1] == 0 else 1)


# ---- the output grammar: kind -> positionals, keys (name, type) in order -----------------------------------

GRAMMAR = {
    "lookup": ([], [("format", "n"), ("now", "t"), ("model", "s"), ("model-from", "s"), ("prestage", "s"),
                    ("dir", "s"), ("snapshot", "s"), ("dir-writable", "b"), ("view", "s")]),
    "manifest": ([], [("state", "s"), ("why", "s"), ("file", "s"), ("generation", "d"), ("builder", "s"),
                      ("tier", "s"), ("built", "t"), ("age", "a"), ("verified", "s")]),
    "plane": ([("name", "s")],
              [("id", "n"), ("state", "s"), ("file", "s"), ("format", "n"), ("generation", "d"), ("unit", "s"),
               ("built", "t"), ("valid-until", "t"), ("admission-tier", "n"), ("ranges-v4", "n"),
               ("ranges-v6", "n"), ("key-bits-v6", "n"), ("manifest", "s"), ("why", "l"),
               ("entry-generation", "d"), ("bound-to", "s"), ("tier", "s"), ("sources", "d"),
               ("coverage-v4", "d"), ("coverage-v6", "d"), ("coverage-v6-slash32s", "d"), ("feed", "l"),
               ("until", "t"), ("refused", "s"), ("refused-detail", "s"), ("disagree", "l")]),
    "source": ([("plane", "s"), ("index", "n")],
               [("name", "s"), ("kind", "s"), ("count", "d"), ("observed-at", "t"), ("recall", "s"),
                ("precision", "s")]),
    "withheld": ([("plane", "s")],
                 [("reasons", "r"), ("reason", "s"), ("detail", "s"), ("since", "t"), ("built-generation", "d"),
                  ("built-generation-unit", "s"), ("last-published-valid-until", "t"), ("from", "s")]),
    "policy": ([], [("source", "s"), ("installed", "s"), ("applied", "s"), ("threshold", "s"), ("defaults", "s"),
                    ("context", "s"), ("mode", "s"), ("allow-inferred", "b"), ("rules", "n"),
                    ("floor-rules", "n"), ("digest", "s")]),
    "rule": ([("program", "s"), ("n", "n")], [("text", "s")]),
    "note": ([("text", "s")], []),
    "address": ([("input", "s")], [("family", "n"), ("canonical", "s"), ("error", "s")]),
    "attr": ([("name", "s"), ("value", "u")],
             [("plane", "s"), ("range", "s"), ("key-bits", "n"), ("record", "s"), ("drop", "b"),
              ("evidence", "s"), ("why", "l"), ("feed", "l"), ("bounded", "s"), ("identity", "l")]),
    "hold-harmless": ([("member", "b")], [("eligible", "b"), ("applies", "b"), ("range", "s")]),
    "cite": ([("entry", "s")], [("method", "s"), ("note", "s")]),
    "decision": ([("action", "s")],
                 [("enforce", "b"), ("would-deny", "b"), ("step", "s"), ("rule", "n"), ("text", "s"),
                  ("reason", "s"), ("log", "s"), ("identity", "l"), ("would-deny-rule", "s"),
                  ("would-deny-text", "s")]),
}
ORACLE_KINDS = ("verdict", "cost", "report", "dependents")
ATTRS = ("listed inferred tor_exit rpki_unreachable rpki_reason rpki asn asn_rep country registry_country rir "
         "registry_rir proxy vpn c2 bruteforce spam phishing scanner state_actor anycast moas narrowed "
         "tenant_allow tenant_deny").split()
ATTR_PLANE = dict(zip(ATTRS, ["reputation"] * 2 + ["tor"] + ["rpki-unreachable"] * 2 + ["routing"] * 4
                      + ["registry", "routing", "registry"] + ["anonymizer"] * 2 + ["threat"] * 6
                      + ["routing"] * 3 + ["tenant"] * 2))
STEPS = {"hold-harmless", "acme", "tenant", "floor", "tenant-grace", "context", "default", "sugar"}
MEMBER_RE = re.compile(r"^[a-z0-9-]+(:[A-Za-z0-9_:-]+)?$")
REASON_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
DEC_RE = re.compile(r"^(0|[1-9][0-9]*)$")
WD_RULE_RE = re.compile(r"^(floor|ctx):[1-9][0-9]*$")
AGE_RE = re.compile(r"^-?(0|[1-9][0-9]*)$")
INSTANT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z$")


def camel(name):
    parts = name.split("-")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def needs_quote(tok):
    return tok == "" or " " in tok or "\\" in tok or "=" in tok


def token(v):
    return '"%s"' % v if needs_quote(v) else v


def tokenize(line):
    """Split a line into tokens; a quoted token keeps its content (rendered, so it holds no `"`)."""
    out, i, n = [], 0, len(line)
    while i < n:
        if line[i] == " ":
            i += 1
            continue
        if line[i] == '"':
            j = line.index('"', i + 1)
            out.append(("q", line[i + 1:j]))
            i = j + 1
            continue
        if "=" in line[i:line.find(" ", i) if line.find(" ", i) >= 0 else n]:
            j = line.find(" ", i)
            j = n if j < 0 else j
            k = line.index("=", i)
            key = line[i:k]
            if k + 1 < n and line[k + 1] == '"':
                e = line.index('"', k + 2)
                out.append(("k", key, line[k + 2:e]))
                i = e + 1
            else:
                out.append(("k", key, line[k + 1:j]))
                i = j
            continue
        j = line.find(" ", i)
        j = n if j < 0 else j
        out.append(("p", line[i:j]))
        i = j
    return out


# ---- types ------------------------------------------------------------------------------------------------

def type_ok(t, v, ms=None):
    """A field's JSON value against its type; None means absent and is judged by presence instead."""
    if v is None:
        return True
    if t == "n":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "b":
        return isinstance(v, bool)
    if not isinstance(v, str):
        return False
    if t == "d":
        return v in ("not-stated", "none") or bool(DEC_RE.match(v))
    if t == "a":
        return v == "not-stated" or bool(AGE_RE.match(v))
    if t == "t":
        return v in ("not-stated", "none") or bool(INSTANT_RE.match(v))
    if t == "l":
        return all(MEMBER_RE.match(m) and not m.isdigit() for m in v.split(","))
    if t == "r":
        return v == "not-stated" or all(REASON_RE.match(m) for m in v.split(","))
    return True


def line_of(kind, obj):
    """A line from a JSON object, by the grammar."""
    pos, keys = GRAMMAR[kind]
    out = [kind]
    for name, t in pos:
        v = obj.get(camel(name))
        if t == "u":
            out.append("UNKNOWN" if v is None else token(v))
        elif t == "b":
            out.append("yes" if v else "no")
        elif t == "n":
            out.append(str(v))
        else:
            out.append(token(v))
    for name, t in keys:
        jn = camel(name)
        v = obj.get(jn)
        if t == "t":
            ms = obj.get(jn + "Ms")
            if v is None and ms is not None:
                v = "ms:" + ms
        if v is None:
            continue
        if t == "b":
            v = "yes" if v else "no"
        elif t == "n":
            v = str(v)
        out.append("%s=%s" % (name, token(v)))
    return " ".join(out)


def expected_names(kind):
    pos, keys = GRAMMAR[kind]
    names = [camel(n) for n, _ in pos]
    for n, t in keys:
        names.append(camel(n))
        if t == "t":
            names.append(camel(n) + "Ms")
    return names


def check_object(kind, obj, where, extra=()):
    """Names in order, every name present, every type right."""
    want = expected_names(kind) + list(extra)
    check(list(obj.keys()) == want, "%s: %s keys %s, the grammar says %s" % (where, kind, list(obj.keys()), want))
    pos, keys = GRAMMAR[kind]
    for name, t in pos + keys:
        jn = camel(name)
        v = obj.get(jn)
        check(type_ok(t, v), "%s: %s.%s has the wrong type: %r" % (where, kind, name, v))
        if t == "t":
            ms = obj.get(jn + "Ms")
            check(ms is None or type_ok("d", ms), "%s: %s.%sMs is not a decimal string: %r" % (where, kind, jn, ms))
            check((v is None) == (ms is None) or (v is None and ms is not None),
                  "%s: %s.%s and its Ms sibling disagree" % (where, kind, name))


# ---- presence conditions, where the object itself shows whether they hold ------------------------------

def presence(kind, o, where, ctx):
    def must(cond, name):
        # a t field past 9999 is JSON null beside its Ms sibling: present all the same
        v = o.get(camel(name))
        if v is None:
            v = o.get(name)
        if v is None:
            v = o.get(camel(name) + "Ms")
        check((v is not None) == bool(cond), "%s: %s.%s present=%s, its condition says %s" %
              (where, kind, name, v is not None, bool(cond)))
    if kind == "lookup":
        must(o["model"] == "data", "dir")
        must(o["model"] == "legacy", "snapshot")
    elif kind == "manifest":
        read = o["state"] == "read"
        must(not read, "why")
        for k in ("generation", "builder", "tier", "built", "age", "verified"):
            must(read, k)
    elif kind == "plane":
        st = o["state"]
        armed = st in ("fresh", "stale")
        bound = o["manifest"] == "bound"
        must(st != "absent", "file")
        for k in ("format", "generation", "unit", "built", "valid-until", "ranges-v4", "ranges-v6"):
            must(armed, k)
        must(armed and o.get("format") == 1, "admission-tier")
        must(not (st == "fresh" and bound), "why")
        must(bound, "bound-to")
        for k in ("tier", "sources", "coverage-v4", "coverage-v6", "coverage-v6-slash32s"):
            must(bound, k)
        must(st == "refused", "refused")
        must(st == "refused", "refused-detail")
        feed = o.get("feed")
        must(st == "fresh" and feed is not None and feed.startswith("withheld:"), "until")
        if not bound:
            must(False, "disagree")
        if not armed:
            must(False, "key-bits-v6")
        # feed: present when a manifest withholds the plane, or one of its own tier was read; absent when no
        # manifest was read at all
        if ctx.get("withheld_named", {}).get(o["name"]) or ctx.get("own_tier_read", {}).get(o["name"]):
            must(True, "feed")
        if not ctx.get("any_read"):
            must(False, "feed")
        why = o.get("why") or ""
        must("other-bytes" in why.split(",") and not bound, "entry-generation")
    elif kind == "address":
        must(o.get("family") is None, "error")
        must(o.get("error") is None, "canonical")
    elif kind == "attr":
        must(o.get("value") is None, "why")
        if o.get("value") is None:
            for k in ("range", "record", "evidence", "drop"):
                must(False, k)
        must(o["name"] in ("tenant_allow", "tenant_deny") and ctx.get("tenant_armed"), "identity")
        if o["name"] != "tenant_allow":
            must(False, "bounded")
        if o.get("value") is None:
            must(False, "key-bits")
            must(False, "feed")
        if o["name"] != "listed" or o.get("range") is None:
            must(False, "drop")
    elif kind == "hold-harmless":
        must(o["member"], "range")
    elif kind == "rule":
        must(True, "text")
    elif kind == "decision":
        must(o["action"] == "deny", "enforce")
        must(o["action"] == "log", "would-deny")
        must(o.get("rule") not in (None, 0), "text")
        must(o["action"] == "log", "would-deny-rule")
        must(o["action"] == "log", "would-deny-text")
        wr = o.get("wouldDenyRule")
        check(wr is None or WD_RULE_RE.match(wr) is not None,
              "%s: decision.would-deny-rule %r is not <floor|ctx>:<rule>" % (where, wr))
        if wr is not None and o.get("log") is not None:
            check(wr in o["log"].split(","), "%s: decision.would-deny-rule %r is not one of log=%s"
                  % (where, wr, o["log"]))
        must(ctx.get("tenant_armed") and o.get("step") != "sugar", "identity")
        check(o.get("step") in STEPS, "%s: decision.step %r is not one of %s" % (where, o.get("step"), sorted(STEPS)))
        r = o.get("reason")
        check(r is None or r in ("no-map", "stale") or r.startswith("allow-by-unknown:"),
              "%s: decision.reason %r is not allow-by-unknown:<plane>, no-map or stale" % (where, r))


# ---- doc: the two forms of one run -------------------------------------------------------------------------

def doc(json_path, lines_path):
    raw = open(json_path, "rb").read()
    check(raw.endswith(b"\n") and raw.count(b"\n") == 1, "the JSON document is one LF-terminated line")
    check(all(b < 0x80 for b in raw), "the JSON document is ASCII")
    d = json.loads(raw)
    check(json.dumps(d, separators=(",", ":")).encode() + b"\n" == raw,
          "(a) the JSON re-serialised with ',' and ':' equals the tool's bytes")
    lines = open(lines_path, encoding="ascii").read().split("\n")
    check(lines[-1] == "", "the line output ends in LF")
    lines = lines[:-1]
    top = ["format", "now", "nowMs", "model", "modelFrom", "prestage", "dir", "snapshot", "dirWritable", "view",
           "manifests", "planes", "withheld", "policy", "notes", "addresses"]
    check(list(d.keys()) == top, "the document's top-level names are the grammar's, in order: %s" % list(d.keys()))
    want = []
    lk = {k: d[k] for k in top[:10]}
    check_object("lookup", lk, "lookup")
    presence("lookup", {"model": d["model"], "dir": d["dir"], "snapshot": d["snapshot"]}, "lookup", {})
    want.append(line_of("lookup", lk))
    for i, m in enumerate(d["manifests"]):
        check_object("manifest", m, "manifests[%d]" % i)
        presence("manifest", m, "manifests[%d]" % i, {})
        want.append(line_of("manifest", m))
    check(len(d["planes"]) == 8, "eight plane objects")
    tenant_armed = False
    keyless_planes = ("reputation", "tor", "rpki-unreachable")
    read = {m["file"] for m in d["manifests"] if m["state"] == "read"}
    pctx = {"any_read": bool(read),
            "withheld_named": {w["plane"]: True for w in d["withheld"]},
            "own_tier_read": {p["name"]: ("manifest.json" if p["name"] in keyless_planes else "k/manifest.json") in read
                              for p in d["planes"]}}
    for i, p in enumerate(d["planes"]):
        po = {k: v for k, v in p.items() if k != "sourceList"}
        check_object("plane", dict(po, sourceList=None), "planes[%d]" % i, extra=("sourceList",))
        presence("plane", dict(po, **{"valid-until": po.get("validUntil"), "ranges-v4": po.get("rangesV4"),
                                      "ranges-v6": po.get("rangesV6"), "admission-tier": po.get("admissionTier"),
                                      "bound-to": po.get("boundTo"), "coverage-v4": po.get("coverageV4"),
                                      "coverage-v6": po.get("coverageV6"),
                                      "coverage-v6-slash32s": po.get("coverageV6Slash32s"),
                                      "refused-detail": po.get("refusedDetail"),
                                      "entry-generation": po.get("entryGeneration"),
                                      "key-bits-v6": po.get("keyBitsV6")}),
                 "planes[%d]" % i, pctx)
        if p["name"] == "tenant" and p["state"] != "absent" and not (
                p["state"] == "refused" and "inert-at-config" in (p.get("why") or "")):
            tenant_armed = True
        want.append(line_of("plane", po))
    for p in d["planes"]:
        for j, s in enumerate(p["sourceList"]):
            check_object("source", s, "%s.sourceList[%d]" % (p["name"], j))
            want.append(line_of("source", s))
    for i, w in enumerate(d["withheld"]):
        check_object("withheld", w, "withheld[%d]" % i)
        want.append(line_of("withheld", w))
    if check(isinstance(d["policy"], dict), "the policy object is present"):
        pol = {k: v for k, v in d["policy"].items() if k not in ("ruleList", "reports")}
        check_object("policy", dict(pol, ruleList=None, reports=None), "policy", extra=("ruleList", "reports"))
        check(pol.get("installed") in ("yes", "no", "unknown"), "policy.installed is yes, no or unknown (%r)"
              % pol.get("installed"))
        check((pol.get("applied") is not None) == (pol.get("installed") == "yes"), "policy.applied present exactly "
              "when installed=yes")
        check((pol.get("threshold") is not None) == (pol.get("source") == "sugar"), "policy.threshold present "
              "exactly for the sugar")
        check(pol.get("applied") in (None, "not-verified"), "policy.applied is not-verified: the tool never knows "
              "whether a server loads the policy (%r)" % pol.get("applied"))
        check(isinstance(pol.get("context"), str) and pol["context"] != ""
              and all(0x21 <= ord(ch) <= 0x7E for ch in pol["context"]),
              "policy.context is printable ASCII without spaces: %r" % pol.get("context"))
        want.append(line_of("policy", pol))
        for r in d["policy"]["ruleList"]:
            check_object("rule", r, "policy.ruleList")
            presence("rule", r, "policy.ruleList", {})
            want.append(line_of("rule", r))
        for r in d["policy"]["reports"]:
            check(all(0x20 <= ord(ch) <= 0x7E for ch in r), "a report line holds only 0x20..0x7E")
            want.append("report " + r)
    for n in d["notes"]:
        want.append(line_of("note", {"text": n}))
    for i, a in enumerate(d["addresses"]):
        where = "addresses[%d]" % i
        names = ["input", "family", "canonical", "error", "attributes", "holdHarmless", "verdict", "cost",
                 "dependents", "decision", "notes"]
        check(list(a.keys()) == names, "%s: the address object's names are %s" % (where, list(a.keys())))
        ao = {k: a.get(k) for k in ("input", "family", "canonical", "error")}
        check_object("address", ao, where)
        presence("address", ao, where, {})
        want.append(line_of("address", ao))
        if a.get("error") is not None:
            check(a["attributes"] == [] and a["holdHarmless"] is None and a["verdict"] is None and a["cost"] is None
                  and a["dependents"] == [] and a["decision"] is None and isinstance(a["notes"], list),
                  "%s: a refused address has every member, empty or null" % where)
            continue
        names_seen = []
        for at in a["attributes"]:
            check_object("attr", at, where + ".attributes")
            presence("attr", at, where + ".attributes", {"tenant_armed": tenant_armed})
            names_seen.append(at["name"])
            want.append(line_of("attr", at))
        check(names_seen == ATTRS, "%s: the 25 attributes in vocabulary order" % where)
        state = {p["name"]: p["state"] for p in d["planes"]}
        for at in a["attributes"]:
            check(at["plane"] == ATTR_PLANE[at["name"]], "%s: %s is read from %s, not %s" % (where, at["name"],
                  ATTR_PLANE[at["name"]], at["plane"]))
            check(at["value"] is None or isinstance(at["value"], str), "%s: %s's value is a string or null"
                  % (where, at["name"]))
            check((at["value"] is not None) == (state[at["plane"]] == "fresh"),
                  "%s: %s has a value exactly when its plane is fresh" % (where, at["name"]))
        hh = a["holdHarmless"]
        if not check(isinstance(hh, dict), "%s: an accepted address has a holdHarmless object" % where):
            continue
        hho = {k: v for k, v in hh.items() if k != "cites"}
        check_object("hold-harmless", dict(hho, cites=None), where + ".holdHarmless", extra=("cites",))
        presence("hold-harmless", hho, where, {})
        want.append(line_of("hold-harmless", hho))
        for c in hh["cites"]:
            check_object("cite", c, where + ".cites")
            want.append(line_of("cite", c))
        for k in ("verdict", "cost"):
            if check(isinstance(a[k], str), "%s: %s is present" % (where, k)):
                check(all(0x20 <= ord(ch) <= 0x7E for ch in a[k]), "%s: the %s line holds only 0x20..0x7E" % (where, k))
                want.append(k + " " + a[k])
        for dep in a["dependents"]:
            check(dep.startswith("floor ") or dep.startswith("ctx "), "%s: a dependents element begins floor or ctx"
                  % where)
            want.append("dependents " + dep)
        if check(isinstance(a["decision"], dict), "%s: an accepted address has a decision" % where):
            check_object("decision", a["decision"], where + ".decision")
            presence("decision", a["decision"], where + ".decision", {"tenant_armed": tenant_armed})
            want.append(line_of("decision", a["decision"]))
        for n in a["notes"]:
            want.append(line_of("note", {"text": n}))
    check(want == lines, "(b) the lines rendered from the JSON equal the line output")
    if want != lines:
        for k, (x, y) in enumerate(zip(want, lines)):
            if x != y:
                print("  first difference at line %d:\n    from JSON: %s\n    the tool:  %s" % (k + 1, x, y))
                break
        if len(want) != len(lines):
            print("  %d lines from JSON, %d from the tool" % (len(want), len(lines)))
    lines_check(lines)


FIELDS_RE = re.compile(r"^fields [a-z-]+ [46] [0-9a-f:.]+ (0|1( [0-9]+)+)$")
EXPECT_RE = re.compile(r"^expect [a-z-]+ [46] [0-9a-f:.]+ (-|[0-9]+ (rec=[0-9a-f]+|sev=[0-9]+) fields=[a-z_]+=[0-9]+(,[a-z_]+=[0-9]+)*)$")


def lines_check(lines):
    for k, line in enumerate(lines):
        kind = line.split(" ", 1)[0]
        if kind in ("fields", "expect"):
            check((FIELDS_RE if kind == "fields" else EXPECT_RE).match(line) is not None,
                  "line %d: a %s line outside its grammar: %s" % (k + 1, kind, line))
            continue
        if kind in ORACLE_KINDS:
            check(all(0x20 <= ord(c) <= 0x7e for c in line), "line %d: an oracle line holds only 0x20..0x7E" % (k + 1))
            continue
        if not check(kind in GRAMMAR, "line %d: unknown kind %r" % (k + 1, kind)):
            continue
        try:
            toks = tokenize(line)[1:]
        except ValueError:
            check(False, "line %d does not tokenize: %s" % (k + 1, line))
            continue
        pos = [t for t in toks if t[0] in ("p", "q")]
        keys = [t for t in toks if t[0] == "k"]
        check(len(pos) == len(GRAMMAR[kind][0]), "line %d: %s has %d positionals, the grammar says %d: %s" %
              (k + 1, kind, len(pos), len(GRAMMAR[kind][0]), line))
        order = [n for n, _ in GRAMMAR[kind][1]]
        idx = [order.index(t[1]) if t[1] in order else -1 for t in keys]
        check(-1 not in idx and idx == sorted(idx), "line %d: %s keys out of order or unknown: %s" % (k + 1, kind, line))
        for t in keys:
            typ = dict(GRAMMAR[kind][1]).get(t[1])
            if typ == "l":
                check(type_ok("l", t[2]), "line %d: %s=%s holds a member outside the pattern" % (k + 1, t[1], t[2]))


# ---- the reference manifest reader -------------------------------------------------------------------------

READ_NAMES = ("generation builtAt builder tier planes legacy withheld name sha256 bytes headerGeneration validUntil "
              "coverage v4Addresses v6Addresses v6Slash32s sources kind count observedAt recall precision reason "
              "reasons detail since builtGeneration lastPublishedValidUntil").split()
MAX_MS = 253402300799999
TWO_128 = 1 << 128
CAPS = {"depth": 32, "members": 1024, "elements": 4096, "key": 256, "size": 1 << 20}


class Refused(Exception):
    pass


class Tok(str):
    """A number kept as its token text."""


def render(b):
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogatepass")
    return "".join(chr(c) if 0x20 <= c <= 0x7E and c not in (0x22, 0x5C) else "\\x%02X" % c for c in b)


def prewalk(text, caps):
    """Depth, width and raw control bytes inside strings, over the text, before any parse."""
    depth, stack, i, n, in_str = 0, [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            elif ord(c) < 0x20:
                raise Refused("control-byte")
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
            if depth > caps["depth"]:
                raise Refused("too-deep")
            stack.append([c, 0])
        elif c in "]}":
            if stack:
                stack.pop()
            depth -= 1
        elif c == "," and stack:
            # n commas separate n + 1 members or elements
            stack[-1][1] += 1
            if stack[-1][1] + 1 > (caps["members"] if stack[-1][0] == "{" else caps["elements"]):
                raise Refused("too-wide")
        i += 1


def bad_string(s):
    if "\x00" in s:
        return "nul"
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in s):
        return "lone-surrogate"
    return None


def ref_parse(data, caps=CAPS, walk_keys=True):
    if len(data) > caps["size"]:
        raise Refused("too-large")
    if data.startswith(b"\xef\xbb\xbf") or data.startswith(b"\xfe\xff") or data.startswith(b"\xff\xfe"):
        raise Refused("bom")
    if b"\x00" in data:
        raise Refused("nul-byte")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("bad-utf8")
    prewalk(text, caps)

    def pairs(ps):
        seen = set()
        for k, _ in ps:
            if walk_keys:
                b = bad_string(k)
                if b:
                    raise Refused(b)
            if len(k.encode("utf-8")) > caps["key"]:
                raise Refused("too-long")
            if k in READ_NAMES:
                if k in seen:
                    raise Refused("duplicate-key:" + k)
                seen.add(k)
        return dict(ps)

    def const(x):
        raise Refused("syntax")

    dec = json.JSONDecoder(object_pairs_hook=pairs, parse_int=Tok, parse_float=Tok, parse_constant=const)
    i = 0
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    try:
        v, end = dec.raw_decode(text, i)
    except Refused:
        raise
    except (ValueError, RecursionError):
        raise Refused("syntax")
    if isinstance(v, Tok) and end < len(text) and text[end] in ".eE":
        raise Refused("syntax")                 # `1.` and `1e`: the number's own grammar fails, not what follows
    while end < len(text) and text[end] in " \t\r\n":
        end += 1
    if end != len(text):
        raise Refused("trailing-bytes")

    def walk(x):
        if isinstance(x, str) and not isinstance(x, Tok):
            b = bad_string(x)
            if b:
                raise Refused(b)
        elif isinstance(x, list):
            for e in x:
                walk(e)
        elif isinstance(x, dict):
            for e in x.values():
                walk(e)
    walk(v)
    return v


class Reader:
    """The field rules on a parsed manifest; notes in the order the fields are read."""

    def __init__(self, file):
        self.file = file
        self.notes = []

    def note(self, path, rule):
        self.notes.append((path, rule))

    @staticmethod
    def reserved(s):
        return s in ("not-stated", "none") or s.startswith("ms:")

    def string(self, v, path):
        if v is None:
            return None
        if not isinstance(v, str) or isinstance(v, Tok):
            self.note(path, "not-a-string")
            return None
        if self.reserved(v):
            self.note(path, "reserved-token")
            return None
        return v

    @staticmethod
    def int_tok(v):
        if not isinstance(v, Tok) or not re.fullmatch(r"0|[1-9][0-9]*", v):
            return None
        x = int(v)
        return x if x <= (1 << 63) - 1 else None

    def integer(self, v, path):
        if v is None:
            return None
        if not isinstance(v, Tok):
            self.note(path, "not-an-integer")
            return None
        if "." in v or "e" in v or "E" in v or v == "-0":
            self.note(path, "not-an-integer")
            return None
        x = self.int_tok(v)
        if x is None:
            self.note(path, "out-of-range")
            return None
        return str(x)

    def count(self, v, path):
        if v is None:
            return None
        x = self.int_tok(v) if isinstance(v, Tok) else None
        if x is not None:
            return str(x)
        if isinstance(v, str) and not isinstance(v, Tok) and re.fullmatch(r"0|[1-9][0-9]{0,38}", v) \
                and int(v) <= TWO_128:
            return v
        self.note(path, "not-a-count")
        return None

    def time(self, v, path):
        """('absent'|'null'|'refused'|'ms', value)"""
        if path is None:
            return ("absent", None)
        if v is _ABSENT:
            return ("absent", None)
        if v is None:
            return ("null", None)
        if isinstance(v, Tok):
            x = self.int_tok(v)
            if x is None:
                self.note(path, "not-an-instant" if v.startswith("-") or any(c in v for c in ".eE")
                          else "out-of-range")
                return ("refused", None)
            if x < 10 ** 12:
                self.note(path, "not-an-instant")
                return ("refused", None)
            if x > MAX_MS:
                self.note(path, "out-of-range")
                return ("refused", None)
            return ("ms", x)
        if not isinstance(v, str):
            self.note(path, "bad-time")
            return ("refused", None)
        ms = rfc3339(v)
        if ms is None:
            self.note(path, "reserved-token" if self.reserved(v) else "bad-time")
            return ("refused", None)
        if ms < 0:
            self.note(path, "before-1970")
            return ("refused", None)
        return ("ms", ms)


_ABSENT = object()


def get(o, k):
    return o.get(k, _ABSENT) if isinstance(o, dict) else _ABSENT


def val(o, k):
    v = get(o, k)
    return None if v is _ABSENT else v


def days_from_civil(y, m, d):
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def rfc3339(s):
    m = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?"
                     r"([Zz]|[+-][0-9]{2}:[0-9]{2})", s)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(m.group(k)) for k in range(1, 7))
    frac = int((m.group(7)[1:] + "000")[:3]) if m.group(7) else 0
    off = m.group(8)
    oh = om = 0
    sign = 0
    if off not in ("Z", "z"):
        sign = 1 if off[0] == "+" else -1
        oh, om = int(off[1:3]), int(off[4:6])
    if not (1 <= mo <= 12) or d < 1 or h > 23 or mi > 59 or se > 60 or oh > 23 or om > 59:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if d > dim:
        return None
    local = days_from_civil(y, mo, d) * 86400000 + h * 3600000 + mi * 60000 + se * 1000 + frac
    return local - sign * (oh * 60 + om) * 60000


def sha_ok(v):
    return isinstance(v, str) and not isinstance(v, Tok) and re.fullmatch(r"[0-9a-f]{64}", v) is not None


def tstr(t):
    return {"absent": "absent", "null": "null", "refused": "refused"}.get(t[0]) or "ms:%d" % t[1]


def s_(v):
    return "-" if v is None else render(v)


def dump(data, file="manifest.json", caps=CAPS, walk_keys=True):
    """The reader's verdict on one manifest's bytes, in the dump format fuzz_manifest prints."""
    out = []
    try:
        root = ref_parse(data, caps, walk_keys)
    except Refused as e:
        return ["result refuse:%s" % e.args[0]]
    if not isinstance(root, dict):
        return ["result refuse:not-an-object"]
    r = Reader(file)
    out.append("result accept")
    gen = r.integer(val(root, "generation"), "generation")
    built = r.time(get(root, "builtAt"), "builtAt")
    builder = r.string(val(root, "builder"), "builder")
    tier = r.string(val(root, "tier"), "tier")
    out.append("top generation=%s builtAt=%s builder=%s tier=%s" % (s_(gen), tstr(built), s_(builder), s_(tier)))
    planes = val(root, "planes")
    if isinstance(planes, list):
        k = 0
        for i, e in enumerate(planes):
            if not isinstance(e, dict):
                r.note("planes[%d]" % i, "not-an-object")
                continue
            name = r.string(val(e, "name"), "planes[%d].name" % i)
            sh = val(e, "sha256")
            if not sha_ok(sh):
                r.note("planes[%d].sha256" % i, "bad-sha256")
                sh = None
            by = r.integer(val(e, "bytes"), "planes[%d].bytes" % i)
            g = r.integer(val(e, "generation"), "planes[%d].generation" % i)
            hg = r.integer(val(e, "headerGeneration"), "planes[%d].headerGeneration" % i)
            ba = r.time(get(e, "builtAt"), "planes[%d].builtAt" % i)
            vu = r.time(get(e, "validUntil"), "planes[%d].validUntil" % i)
            cov = val(e, "coverage")
            cv = "null"
            if isinstance(cov, dict):
                c4 = r.count(val(cov, "v4Addresses"), "planes[%d].coverage.v4Addresses" % i)
                c6 = r.count(val(cov, "v6Addresses"), "planes[%d].coverage.v6Addresses" % i)
                c3 = r.count(val(cov, "v6Slash32s"), "planes[%d].coverage.v6Slash32s" % i)
                cv = "%s/%s/%s" % (s_(c4), s_(c6), s_(c3))
            elif cov is not None:
                r.note("planes[%d].coverage" % i, "not-an-object")
            srcs = val(e, "sources")
            sl = []
            if isinstance(srcs, list):
                for j, s in enumerate(srcs):
                    if not isinstance(s, dict):
                        r.note("planes[%d].sources[%d]" % (i, j), "not-an-object")
                        sl.append("source %d %d name=- kind=- count=- observedAt=absent recall=- precision=-" % (k, j))
                        continue
                    p = "planes[%d].sources[%d]." % (i, j)
                    sn = r.string(val(s, "name"), p + "name")
                    sk = r.string(val(s, "kind"), p + "kind")
                    sc = r.count(val(s, "count"), p + "count")
                    so = r.time(get(s, "observedAt"), p + "observedAt")
                    rc, pr = val(s, "recall"), val(s, "precision")
                    if rc is not None and not isinstance(rc, Tok):
                        r.note(p + "recall", "not-a-number")
                    if pr is not None and not isinstance(pr, Tok):
                        r.note(p + "precision", "not-a-number")
                    sl.append("source %d %d name=%s kind=%s count=%s observedAt=%s recall=%s precision=%s" % (
                        k, j, s_(sn), s_(sk), s_(sc), tstr(so), rc if isinstance(rc, Tok) else "-",
                        pr if isinstance(pr, Tok) else "-"))
            elif srcs is not None:
                r.note("planes[%d].sources" % i, "not-an-array")
            out.append("plane %d name=%s sha256=%s bytes=%s generation=%s headerGeneration=%s builtAt=%s "
                       "validUntil=%s coverage=%s sources=%d" % (k, s_(name), sh or "-", s_(by), s_(g), s_(hg),
                                                                 tstr(ba), tstr(vu), cv, len(sl)))
            out.extend(sl)
            k += 1
    elif planes is not None:
        r.note("planes", "not-an-array")
    legacy = val(root, "legacy")
    if isinstance(legacy, list):
        k = 0
        for i, e in enumerate(legacy):
            if not isinstance(e, dict):
                r.note("legacy[%d]" % i, "not-an-object")
                continue
            name = r.string(val(e, "name"), "legacy[%d].name" % i)
            sh = val(e, "sha256")
            if not sha_ok(sh):
                r.note("legacy[%d].sha256" % i, "bad-sha256")
                sh = None
            by = r.integer(val(e, "bytes"), "legacy[%d].bytes" % i)
            hg = r.integer(val(e, "headerGeneration"), "legacy[%d].headerGeneration" % i)
            out.append("legacy %d name=%s sha256=%s bytes=%s headerGeneration=%s" % (k, s_(name), sh or "-", s_(by),
                                                                                  s_(hg)))
            k += 1
    elif legacy is not None:
        r.note("legacy", "not-an-array")
    wh = val(root, "withheld")
    if isinstance(wh, list):
        k = 0
        names_seen = []
        for i, e in enumerate(wh):
            if not isinstance(e, dict):
                r.note("withheld[%d]" % i, "not-an-object")
                continue
            p = "withheld[%d]." % i
            name = r.string(val(e, "name"), p + "name")
            reason, reason_bad = None, False
            r1 = val(e, "reason")
            if isinstance(r1, str) and not isinstance(r1, Tok):
                if REASON_RE.fullmatch(r1):
                    reason = r1
                else:
                    r.note(p + "reason", "bad-token")
                    reason_bad = True
            elif r1 is not None:
                r.note(p + "reason", "not-a-string")
            rs = val(e, "reasons")
            state, lst = "ok", []
            if reason_bad:
                state = "refused"
            elif rs is None:
                if reason is not None:
                    lst = [reason]
                else:
                    state = "not-stated"
            elif not isinstance(rs, list):
                r.note(p + "reasons", "not-an-array")
                state = "refused"
            else:
                if any(not isinstance(x, str) or isinstance(x, Tok) for x in rs):
                    r.note(p + "reasons", "not-a-string")
                    state = "refused"
                else:
                    uniq = []
                    for x in rs:
                        if x not in uniq:
                            uniq.append(x)
                    lst = ([reason] if reason is not None and reason not in rs else []) + uniq
                    if len(lst) > 8:
                        r.note(p + "reasons", "too-many")
                        state, lst = "refused", []
                    elif any(not REASON_RE.fullmatch(x) for x in lst):
                        r.note(p + "reasons", "bad-token")
                        state, lst = "refused", []
            detail = r.string(val(e, "detail"), p + "detail")
            since = r.time(get(e, "since"), p + "since")
            lp = r.time(get(e, "lastPublishedValidUntil"), p + "lastPublishedValidUntil")
            bg = r.integer(val(e, "builtGeneration"), p + "builtGeneration")
            reasons = {"ok": ",".join(lst) if lst else "-", "not-stated": "not-stated", "refused": "refused"}[state]
            out.append("withheld %d name=%s reasons=%s reason=%s detail=%s since=%s builtGeneration=%s "
                       "lastPublishedValidUntil=%s" % (k, s_(name), reasons, s_(reason), s_(detail), tstr(since),
                                                       s_(bg), tstr(lp)))
            if name is not None and name in names_seen:
                r.note(p + "name", "duplicate-entry-ignored")
            names_seen.append(name)
            k += 1
    elif wh is not None:
        r.note("withheld", "not-an-array")
    for path, rule in r.notes:
        out.append("fieldnote %s %s" % (path, rule))
    return out


# ---- the seed corpus (J4) ----------------------------------------------------------------------------------

SHA_A = "a" * 64
SHA_B = "b" * 64


def base_manifest(planes=None, legacy=None, withheld=None, **top):
    m = {"format": 2, "generation": 1791878400, "builtAt": "2026-10-13T08:00:04Z", "builder": "primary",
         "tier": "keyless", "tenant": None,
         "planes": planes if planes is not None else [
             {"name": "reputation", "format": 1, "sha256": SHA_A, "bytes": 1000, "generation": 1791878400,
              "headerGeneration": 497744, "builtAt": "2026-10-13T08:00:00Z", "validUntil": "2026-10-14T08:00:00Z",
              "coverage": {"v4Addresses": "1792", "v6Addresses": "4722366482869645213696", "v6Slash32s": "1"},
              "sources": []}],
         "legacy": legacy if legacy is not None else [
             {"name": "snapshot.bin", "sha256": SHA_A, "bytes": 1000, "headerGeneration": 497744}],
         "withheld": withheld if withheld is not None else [
             {"name": "tor", "reason": "LOW_RECALL", "reasons": ["LOW_RECALL"], "detail": "LOW_RECALL: recall 0.318",
              "since": "2026-10-12T00:00:00Z", "builtGeneration": 1791792000, "lastPublishedValidUntil": None}]}
    m.update(top)
    return m


def enc(m):
    return json.dumps(m, separators=(",", ":")).encode()


def seeds():
    """name -> bytes; every class of the manifest reader's rules, each cap at its bound and one past it."""
    s = {}
    s["ok-base"] = enc(base_manifest())
    s["ok-pretty"] = json.dumps(base_manifest(), indent=2).encode()
    # caps
    # the top-level object counts 1, so 31 arrays inside it are depth 32
    s["cap-depth-32"] = b'{"x":' + b"[" * 31 + b"]" * 31 + b"}"
    s["cap-depth-33"] = b'{"x":' + b"[" * 32 + b"]" * 32 + b"}"
    s["cap-depth-1e6"] = b'{"x":' + b"[" * 10 ** 6 + b"]" * 10 ** 6 + b"}"
    s["cap-depth-1e6-under-size"] = b'{"x":' + b"[" * 500000 + b"]" * 500000 + b"}"
    s["cap-members-1024"] = enc({"m%d" % i: i for i in range(1024)})
    s["cap-members-1025"] = enc({"m%d" % i: i for i in range(1025)})
    s["cap-elements-4096"] = enc({"x": list(range(4096))})
    s["cap-elements-4097"] = enc({"x": list(range(4097))})
    s["cap-key-256"] = enc({"k" * 256: 1})
    s["cap-key-257"] = enc({"k" * 257: 1})
    pad = lambda n: b'{"x":"' + b"y" * (n - 8) + b'"}'
    s["cap-size-1MiB"] = pad(1 << 20)
    s["cap-size-1MiB+1"] = pad((1 << 20) + 1)
    # strings
    s["nul-in-element"] = b'{"a":["x\\u0000y"]}'
    s["surrogate-in-element"] = b'{"a":["\\ud800"]}'
    s["nul-in-key"] = b'{"a\\u0000":1}'
    s["surrogate-in-key"] = b'{"\\ud800":1}'
    s["surrogate-pair-ok"] = b'{"a":"\\ud83d\\ude00"}'
    s["dup-sha256"] = b'{"planes":[{"name":"reputation","sha256":"' + SHA_A.encode() + b'","sha256":"' + \
        SHA_B.encode() + b'","bytes":1}]}'
    s["dup-unread-object"] = b'{"unread":{"sha256":"a","sha256":"b"}}'
    s["dup-escaped-name"] = b'{"planes":[{"sha256":"' + SHA_A.encode() + b'","sha\\u0032\\u0035\\u0036":"' + \
        SHA_B.encode() + b'"}]}'
    s["dup-unread-name"] = b'{"zzz":1,"zzz":2}'
    s["bom"] = b"\xef\xbb\xbf" + enc(base_manifest())
    s["trailing"] = enc(base_manifest()) + b" x"
    s["utf16"] = enc({"a": 1}).decode().encode("utf-16-le")
    s["raw-tab"] = b'{"a":"x\ty"}'
    s["overlong"] = b'{"a":"\xc0\xaf"}'
    s["cesu"] = b'{"a":"\xed\xa0\xbd\xed\xb8\x80"}'
    s["nan"] = b'{"generation":NaN}'
    s["infinity"] = b'{"generation":Infinity}'
    s["leading-zero"] = b'{"generation":007}'
    s["plus-one"] = b'{"generation":+1}'
    # fields
    s["gen-float"] = enc(base_manifest()).replace(b'"generation":1791878400,"builtAt"', b'"generation":1.7e9,"builtAt"')
    s["gen-2-64"] = enc(base_manifest()).replace(b'"generation":1791878400,"builtAt"',
                                                   b'"generation":18446744073709551616,"builtAt"')
    s["gen-neg-zero"] = enc(base_manifest()).replace(b'"generation":1791878400,"builtAt"', b'"generation":-0,"builtAt"')
    s["bad-sha256"] = enc(base_manifest(planes=[{"name": "reputation", "sha256": "A" * 64, "bytes": 1}]))
    for tok in ("not-stated", "none", "ms:5"):
        s["reserved-" + tok.replace(":", "")] = enc(base_manifest(builder=tok))
    s["at-small-int"] = enc(base_manifest(builtAt=1791878))
    s["at-numeric"] = enc(base_manifest(builtAt=1791878404000))
    s["observed-zero"] = enc(base_manifest(planes=[{"name": "tor", "sha256": SHA_A, "bytes": 1, "sources": [
        {"name": "tor-onionoo", "kind": "relays", "count": 383, "observedAt": 0}]}]))
    s["reasons-nonstring"] = enc(base_manifest(withheld=[{"name": "tor", "reason": "LOW_RECALL",
                                                         "reasons": ["LOW_RECALL", 5]}]))
    s["reasons-no-reason"] = enc(base_manifest(withheld=[{"name": "tor", "reasons": ["LOW_RECALL", "SOURCE_STALE"]}]))
    s["reasons-two"] = enc(base_manifest(withheld=[{"name": "tor", "reason": "LOW_RECALL",
                                                   "reasons": ["LOW_RECALL", "SOURCE_STALE"]}]))
    s["reason-comma"] = enc(base_manifest(withheld=[{"name": "tor", "reason": "A,B"}]))
    s["reasons-nine"] = enc(base_manifest(withheld=[{"name": "tor", "reasons": ["R%d" % i for i in range(9)]}]))
    s["reasons-eight"] = enc(base_manifest(withheld=[{"name": "tor", "reasons": ["R%d" % i for i in range(8)]}]))
    for name, v in (("space", "12 34"), ("neg", "-3"), ("exp", "1e5"), ("lead0", "007"), ("lspace", " 1"),
                    ("empty", ""), ("2-128", str(1 << 128)), ("2-128-plus1", str((1 << 128) + 1)), ("40digits", "1" * 40)):
        s["count-" + name] = enc(base_manifest(planes=[{"name": "reputation", "sha256": SHA_A, "bytes": 1,
                                                        "coverage": {"v4Addresses": v}}]))
    s["mday-2026-02-30"] = enc(base_manifest(builtAt="2026-02-30T00:00:00Z"))
    for name, v in (("leap-2024-02-29", "2024-02-29T00:00:00Z"), ("2026-02-29", "2026-02-29T00:00:00Z"),
                    ("2026-04-31", "2026-04-31T00:00:00Z"), ("h24", "2026-10-13T24:00:00Z"),
                    ("m60", "2026-10-13T23:60:00Z"), ("off24", "2026-10-13T00:00:00+24:00"),
                    ("sec60", "2026-10-13T23:59:60Z"), ("frac0009", "2026-10-13T08:00:00.0009Z"),
                    ("lower", "2026-10-13t08:00:00z"), ("y10000", "+10000-01-01T00:00:00Z"),
                    ("pre1970-half", "1969-12-31T23:59:59.5Z"), ("pre1970-off", "1969-12-31T23:59:59-00:01"),
                    ("1970-plus1", "1970-01-01T00:00:00+00:01"), ("9999-minus1", "9999-12-31T23:59:59-00:01"),
                    ("9999-60", "9999-12-31T23:59:60Z")):
        s["time-" + name] = enc(base_manifest(builtAt=v))
    s["coverage-null"] = enc(base_manifest(planes=[{"name": "tor", "sha256": SHA_A, "bytes": 1, "coverage": None}]))
    s["coverage-six"] = enc(base_manifest(planes=[{"name": "routing", "sha256": SHA_A, "bytes": 1, "coverage": {
        "announced": 1, "invalid": 2, "valid": 3, "notFound": 4, "v4Prefixes": 5, "v6Prefixes": 6}}]))
    s["not-an-object"] = b"[1,2,3]"
    # Several defects at once: both readers refuse, and which defect each names first is its own, so the gate
    # compares these by verdict only. Each pair is a later defect the one reader meets first.
    s["multi-syntax-then-wide"] = b'{"a":1,,' + enc({"m%d" % i: i for i in range(1100)})[1:]
    s["multi-syntax-then-deep"] = b'{"a":1,,"b":' + b"[" * 40 + b"]" * 40 + b"}"
    s["multi-syntax-then-control"] = b'{"a":1,,"b":"x\ty"}'
    s["multi-dup-then-surrogate"] = b'{"name":1,"name":2,"x":{"\\ud800":1}}'
    s["multi-surrogate-then-dup"] = b'{"x":{"\\ud800":1},"name":1,"name":2}'
    s["number-cut-dot"] = b"1."
    s["number-cut-exp"] = b"1e"
    s["reasons-repeated"] = enc(base_manifest(withheld=[{"name": "tor", "reason": "LOW_RECALL",
                                                        "reasons": ["LOW_RECALL", "LOW_RECALL", "SOURCE_STALE"]}]))
    s["withheld-twice"] = enc(base_manifest(withheld=[{"name": "tor", "reason": "LOW_RECALL"},
                                                      {"name": "tor", "reason": "SOURCE_STALE"}]))
    s["time-exp-integer"] = enc(base_manifest()).replace(b'"builtAt":"2026-10-13T08:00:04Z"', b'"builtAt":1e12')
    s["empty"] = b""
    return s


# ---- derived manifests: one-edit mutations of a base naming real planes ------------------------------------

def plane_facts(d, name):
    p = os.path.join(d, name + ".bin")
    data = open(p, "rb").read()
    gen = int.from_bytes(data[16:24], "little")
    return hashlib.sha256(data).hexdigest(), len(data), gen


def derive(writer, tor_plane, out):
    """The derived manifests: each the writer's own manifest (testdata/lookup/writer/, written by the real
    publisher and composer) with one edit, or the writer's bytes verbatim. derived/README.md names each."""
    import copy
    os.makedirs(out, exist_ok=True)
    keyless = json.load(open(os.path.join(writer, "keyless", "manifest.json")))
    jobs = json.load(open(os.path.join(writer, "jobs", "manifest.json")))
    tsha = hashlib.sha256(open(tor_plane, "rb").read()).hexdigest()
    tn = os.path.getsize(tor_plane)
    files = {}

    def put(name, m):
        files[name] = enc(m) + b"\n"

    def edit(base, fn):
        m = copy.deepcopy(base)
        fn(m)
        return m

    def rep(m):
        return [p for p in m["planes"] if p["name"] == "reputation"][0]

    def drop_legacy_snapshot(m):
        m["legacy"] = [l for l in m["legacy"] if l["name"] != "snapshot.bin"]

    def withheld(m, name):
        return [w for w in m["withheld"] if w["name"] == name][0]

    def wentry(name, reasons, lpvu):
        w = copy.deepcopy(withheld(keyless, "tor"))
        w.update({"name": name, "reason": reasons[0], "reasons": reasons, "detail": "the edit: " + ",".join(reasons),
                  "lastPublishedValidUntil": lpvu})
        return w

    files["base.json"] = open(os.path.join(writer, "keyless", "manifest.json"), "rb").read()
    files["disarm.json"] = open(os.path.join(writer, "disarm", "manifest.json"), "rb").read()
    files["jobs.json"] = open(os.path.join(writer, "jobs", "manifest.json"), "rb").read()

    def not_named(m):
        m["planes"] = [p for p in m["planes"] if p["name"] != "reputation"]
        drop_legacy_snapshot(m)
    put("not-named.json", edit(keyless, not_named))

    def other_bytes(m):
        rep(m).update({"sha256": SHA_B, "headerGeneration": rep(m)["headerGeneration"] + 1})
        drop_legacy_snapshot(m)
    put("other-bytes.json", edit(keyless, other_bytes))

    def duplicate(m):
        r = rep(m)
        first = dict(copy.deepcopy(r), sha256=SHA_B)
        m["planes"] = [first] + m["planes"]
        drop_legacy_snapshot(m)
    put("duplicate-entry.json", edit(keyless, duplicate))
    put("planes-and-withheld.json", edit(keyless, lambda m: m["withheld"].append(
        wentry("reputation", ["SOURCE_STALE"], None))))
    put("legacy-only.json", edit(keyless, lambda m: m.update(planes=[p for p in m["planes"] if p["name"] != "reputation"])))
    put("valid-until-differs.json", edit(keyless, lambda m: rep(m).update(validUntil="2026-10-13T00:00:00Z")))
    put("withheld-one-reason.json", edit(keyless, lambda m: withheld(m, "tor").update(reasons=["LOW_RECALL"])))
    # a withheld entry whose reasons cannot be read: every one invalid, an empty list, or none at all
    put("withheld-reasons-invalid.json", edit(keyless, lambda m: withheld(m, "tor").update(
        reason="x" * 10240, reasons=["x" * 10240])))
    put("withheld-reasons-empty.json", edit(keyless, lambda m: withheld(m, "tor").update(reason=None, reasons=[])))
    put("withheld-reasons-null.json", edit(keyless, lambda m: withheld(m, "tor").update(reason=None, reasons=None)))

    def withheld_rep(reasons):
        def f(m):
            not_named(m)
            m["withheld"].append(wentry("reputation", reasons, "2026-10-14T08:00:00Z"))
        return f
    put("withheld-reputation.json", edit(keyless, withheld_rep(["SOURCE_STALE"])))
    put("withheld-reputation-two.json", edit(keyless, withheld_rep(["LOW_RECALL", "SOURCE_STALE"])))
    put("tor-as-routing.json", edit(keyless, lambda m: m["planes"].append(
        dict(copy.deepcopy(rep(m)), name="routing", format=2, sha256=tsha, bytes=tn))))

    def numeric(m):
        src = [p for p in m["planes"] if p["name"] == "routing"][0]["sources"][1]
        src["observedAt"] = rfc3339(src["observedAt"])
    put("numeric-times.json", edit(jobs, numeric))
    put("observed-at-zero.json", edit(jobs, lambda m: [p for p in m["planes"] if p["name"] == "tor"][0]["sources"][0]
                                      .update(observedAt=0)))

    def future(m):
        ms = rfc3339(m["builtAt"]) + 365 * 86400000
        m["builtAt"] = "%sZ" % __import__("datetime").datetime.fromtimestamp(ms / 1000, __import__("datetime").timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%S")
    put("future.json", edit(keyless, future))

    def keyed(m):
        m["tier"] = "keyed"
        drop_legacy_snapshot(m)
        m["withheld"] = [w for w in m["withheld"] if w["name"] == "routing"]
    put("keyed.json", edit(keyless, keyed))
    put("tor-withheld-only.json", edit(keyless, lambda m: m.update(withheld=[withheld(m, "tor")])))

    def floored(m):
        r = rep(m)
        r["builtAt"] = r["builtAt"][:-1] + ".0009Z" if "." not in r["builtAt"] else r["builtAt"]
    put("built-at-floored.json", edit(keyless, floored))
    put("coverage-large.json", edit(keyless, lambda m: rep(m)["coverage"].update(v6Addresses="4722366482869645213696")))
    for name, data in sorted(files.items()):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    print("derived %d manifests into %s" % (len(files), out))


# ---- the README's own lookup transcripts --------------------------------------------------------------

def transcripts(edge, tool, work, plant=False):
    """Re-run the README's whisper-edge-lookup transcripts that read the checked-in fixtures."""
    import shutil
    import subprocess
    text = open(os.path.join(edge, "REFERENCE.md"), encoding="utf-8").read().split("\n")
    blocks, i = [], 0
    while i < len(text):
        m = re.match(r"^( *)```\s*$", text[i])
        if m:
            ind, start, body = m.group(1), i + 1, []
            i += 1
            while i < len(text) and text[i].strip() != "```":
                body.append(text[i][len(ind):] if text[i].startswith(ind) else text[i])
                i += 1
            blocks.append((start, body))
        i += 1
    ran = failed = 0
    planted = False
    for start, body in blocks:
        if not any(re.match(r"^\$ (chmod .*; )?whisper-edge-lookup ", ln) for ln in body):
            continue
        steps, cur = [], None
        k = 0
        while k < len(body):
            ln = body[k]
            if ln.startswith("$ "):
                cmd = ln[2:]
                while cmd.endswith("\\") and k + 1 < len(body):
                    k += 1
                    cmd = cmd[:-1] + body[k].strip()
                cur = [cmd, []]
                steps.append(cur)
            elif cur is not None:
                cur[1].append(ln)
            k += 1
        where = "REFERENCE.md:%d" % start

        def on_planes(c):
            return any(w == "planes" or w.startswith("planes/") for w in c.split())
        for c, _ in steps:
            if on_planes(c):
                print("skip %s, $ %s: it reads the planes the differential's producer wrote, on the capturing"
                      " host, whose owner and uid lines are that host's" % (where, c))
        steps = [st for st in steps if not on_planes(st[0])]
        if not steps:
            continue
        words = " ".join(c for c, _ in steps).split()
        d = os.path.join(work, "t%d" % start)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, mode=0o755)
        os.chmod(d, 0o755)
        for w in words:
            w = w.strip("'\"")
            if w.startswith("core/testdata/"):
                dst = os.path.join(d, w)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                for root, _, _ in os.walk(d):
                    os.chmod(root, 0o755)
                shutil.copyfile(os.path.join(edge, w), dst)
                os.chmod(dst, 0o644)
        if "data" in words or "data/tor.bin" in words:
            os.makedirs(os.path.join(d, "data"), mode=0o755, exist_ok=True)
            os.chmod(os.path.join(d, "data"), 0o755)
            shutil.copyfile(os.path.join(edge, "core/testdata/format2/tor.bin"), os.path.join(d, "data", "tor.bin"))
            os.chmod(os.path.join(d, "data", "tor.bin"), 0o444)
        env = dict(os.environ)
        env["PATH"] = os.path.dirname(os.path.abspath(tool)) + os.pathsep + env.get("PATH", "")
        bad = None
        for cmd, exp in steps:
            if plant and not planted and exp:
                exp = exp[:-1] + [exp[-1] + " (planted)"]
                planted = True
            r = subprocess.run(["bash", "-c", cmd], cwd=d, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=120)
            got = r.stdout.decode("utf-8", "replace").rstrip("\n").split("\n") if r.stdout else []
            if got != exp:
                n = next((j for j in range(max(len(got), len(exp)))
                          if j >= len(got) or j >= len(exp) or got[j] != exp[j]), 0)
                bad = "%s, $ %s: line %d reads %r, the transcript %r" % (
                    where, cmd, n + 1, got[n] if n < len(got) else None, exp[n] if n < len(exp) else None)
                break
        ran += 1
        if bad:
            failed += 1
            print("FAIL " + bad)
        else:
            print("ok   %s: %d command(s) reproduce the transcript byte for byte" % (where, len(steps)))
    print("%d transcripts run, %d failed" % (ran, failed))
    return 1 if failed or ran == 0 else 0


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "doc":
        doc(sys.argv[2], sys.argv[3])
        finish()
    elif cmd == "docs":
        for line in open(sys.argv[2]):
            if line.strip():
                j, l = line.split()
                before = CHECKS[1]
                doc(j, l)
                if CHECKS[1] > before:
                    print("  in %s" % l)
        finish()
    elif cmd == "lines":
        lines_check(open(sys.argv[2], encoding="ascii").read().split("\n")[:-1])
        finish()
    elif cmd == "manifest":
        flags = [a for a in sys.argv[2:] if a.startswith("--")]
        caps = dict(CAPS)
        for f in flags:
            if f.startswith("--no-cap="):
                caps[f.split("=", 1)[1]] = 1 << 62
        walk_keys = "--values-only" not in flags
        for path in [a for a in sys.argv[2:] if not a.startswith("--")]:
            print("seed %s" % os.path.basename(path))
            for line in dump(open(path, "rb").read(), caps=caps, walk_keys=walk_keys):
                print(line)
    elif cmd == "seeds":
        out = sys.argv[2]
        os.makedirs(out, exist_ok=True)
        s = seeds()
        for name, data in sorted(s.items()):
            with open(os.path.join(out, name + ".json"), "wb") as f:
                f.write(data)
        print("%d seeds into %s" % (len(s), out))
    elif cmd == "derive":
        derive(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "transcripts":
        sys.exit(transcripts(sys.argv[2], sys.argv[3], sys.argv[4], plant="--plant" in sys.argv[5:]))
    elif cmd == "normalise":
        for line in open(sys.argv[2], encoding="ascii"):
            line = re.sub(r'(^| )(dir|snapshot)=("[^"]*"|[^ ]*)', lambda m: m.group(1) + m.group(2) + "=<" + m.group(2)
                          + ">", line.rstrip("\n"))
            line = re.sub(r'"(dir|snapshot)":"[^"]*"', lambda m: '"%s":"<%s>"' % (m.group(1), m.group(1)), line)
            print(line)
    else:
        print(__doc__.strip())
        sys.exit(2)


if __name__ == "__main__":
    main()
