#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
lookup-states.py - the counts the lookup gate asserts, derived from the format's domains and the
mutant table, never typed in by hand.

    lookup-states.py l2          the domain sweep: "<invocations> <cases> <in-domain v4> <in-domain v6>
                                 <refused>", from the record domains of FORMAT.md section 3
    lookup-states.py mutants     the mutant table: one "<name> <rows> <unit> [<macro>]" line per mutant;
                                 <unit> is the translation unit the mutant recompiles
    lookup-states.py patch <name> <unit> <out>
                                 a shared unit's copy with the mutant's one edit planted
    lookup-states.py pending     the rows and mutants this build does not run, each with what it needs
    lookup-states.py hhagree <we_hold_harmless.h> <we_hold_harmless_cite.h>
                                 the evaluator's merged hold-harmless ranges and the tool's cite header's
                                 merged ranges are the same set
    lookup-states.py files       the files this work adds that ship, for the hygiene check
    lookup-states.py ocounts <planes>
                                 the differential's counts: "<plain invocations> <plain cases> <flag
                                 invocations> <flag cases>", from the 22 programs and the planes they read
    lookup-states.py oderived    the same counts from the per-program parameters, with a covering greedy
                                 written apart from the generator's
    lookup-states.py opinned     the counts as measured at implementation and pinned
    lookup-states.py build <planes> <stale-planes> <out>
                                 the differential's directories and its plan (out/plan.tsv)
    lookup-states.py judge <plan> <tool-out-dir> <cache-dir> [--first]
                                 the tool's lines against both evaluators' over the gate's own
                                 restatement of every request; --first stops at the first difference

The sweep's numbers restate the loader's domains independently of make-test-snapshot.py, which writes
the planes: the gate holds the writer's sweep.txt to these, so a writer that drops or doubles a value,
or writes one outside its domain into the in-domain directory, fails a count.
"""
import bisect
import ipaddress
import itertools
import os
import re
import stat
import subprocess
import sys

# The record domains the loader enforces (FORMAT.md section 3), field -> (in-domain values, refused edges).
ROUTING = {
    "rov": (range(0, 4), (4, 255)),
    "rir": (range(0, 6), (6, 255)),
    "asn_rep": (range(0, 5), (5, 255)),
    "country": (range(0, 1000), (1000, 65535)),
}
ROUTING_FLAGS = {4: (range(0, 4), (4, 255)), 6: (range(0, 8), (8, 255))}
ASN_BOUNDARIES = 10          # 0, 1, 23456, 64495, 64496, 65535, 65536, 4199999999, 4294967294, 4294967295
MEMBER_BITS = {"tor": 1, "rpki-unreachable": 1, "anonymizer": 2, "threat": 6, "tenant": 2}
FEEDS = 7                    # the writer's feed table: entry 0 "none" and six names
THREAT_SOURCES = FEEDS - 1   # source 1..6 in domain on threat; 7 and 255 refused
REASONS = 2                  # rpki-unreachable reason 1..2 in domain; 3 and 255 refused, 1 and 255 on threat
SEV = 256                    # format-1 sev has no refused value


def l2():
    per_plane = {fam: sum(len(v[0]) for v in ROUTING.values()) + ASN_BOUNDARIES + len(ROUTING_FLAGS[fam][0])
                 for fam in (4, 6)}
    member = sum(MEMBER_BITS.values()) + THREAT_SOURCES + REASONS
    v4 = SEV + 2 * per_plane[4] + member
    v6 = SEV + 2 * per_plane[6] + member
    refused = 2 * (2 * len(ROUTING) + 2 * len(ROUTING_FLAGS)) + 2 * len(MEMBER_BITS) + 2 + 4
    return 1 + refused, v4 + v6 + refused, v4, v6, refused


# name, rows it must fail, the unit it recompiles, and the macro when it is not WE_LOOKUP_TEST_<name>.
# A mutant in another unit than the tool's is planted there: plane_check.c by its own macro, and the two
# units the tool shares with the module (whisper_edge.c, we_policy.c) by a one-edit copy `patch` writes,
# so the shipped sources carry no mutant of this work's. RAW_NOT_CLAMPED is the evaluator's own
# WE_TEST_NO_CLAMP, which leaves the fill's clamps out of the tool's translation unit, where the fill is
# inlined.
MUTANTS = """
STALE_NO_ZERO W1 we_lookup_cli.c
STALE_AS_VALUE W1,W5 we_lookup_cli.c
WITHHELD_VALUE W2 we_lookup_cli.c
WITHHOLD_MASKED_BY_TIER W2 we_lookup_cli.c
FIRST_REASON_ONLY W2 we_lookup_cli.c
NULL_REFUSED W2,M4 we_lookup_cli.c
FEED_ONE_MEMBER W8,J1 we_lookup_cli.c
RAW_NOT_CLAMPED L2 we_lookup_cli.c WE_TEST_NO_CLAMP
ASN_SENTINEL_DECIMAL L2 we_policy.c
REGISTRY_FROM_ROUTING L2 we_policy.c
DETAIL_FROM_OTHER L2 we_lookup_cli.c
FIELD_SWAP L1 we_lookup_cli.c
FIELD_SWAP_PLANE_CHECK L1 plane_check.c WE_LOOKUP_TEST_FIELD_SWAP
DROP_FROM_BLOCK L1 we_lookup_cli.c
NO_EVIDENCE_CALL L4 we_lookup_cli.c
NO_DIGEST_BIND M1 we_lookup_cli.c
UNBOUND_ONE_REASON M1 we_lookup_cli.c
LAST_ENTRY_BINDS M1 we_lookup_cli.c
GEN_UNIT M2 we_lookup_cli.c
LEGACY_FIRST M2 we_lookup_cli.c
PRE_1970_ACCEPTED M3 we_lookup_cli.c
MDAY_UNCHECKED M3,J4 we_lookup_cli.c
YEAR_NOT_INSTANT M3,J3 we_lookup_cli.c
OBSERVED_AT_AS_T M4 we_lookup_cli.c
COVERAGE_SHAPE_REFUSED M4 we_lookup_cli.c
COUNT_STRING_PASSTHROUGH J3,J4 we_lookup_cli.c
SMALL_INT_AS_INSTANT M4 we_lookup_cli.c
LAST_RENAMED_TIER M7 we_lookup_cli.c
NO_BOUND_TO M7 we_lookup_cli.c
NO_UNCHECKED_QUALIFIER M8 we_lookup_cli.c
REVOCATION_QUALIFIER_DROPPED M8 we_lookup_cli.c
IDENTITY_TENANT_STEP_ONLY M8 we_lookup_cli.c
MANIFEST_NO_MODE W6 we_lookup_cli.c
REFUSED_AS_NOT_NAMED W6 we_lookup_cli.c
PROBE_OWN_RULES T1,T2 we_lookup_cli.c
ADDR_OWN_RULES T2,T3 we_lookup_cli.c
DIR_PATH_OPEN W6 we_lookup_cli.c
LOAD_AROUND_MODE W3 we_lookup_cli.c
REFUSED_ALWAYS_STALE W3 we_lookup_cli.c
PERMISSION_AS_INERT W3 we_lookup_cli.c
FIFO_UNFIXED_CORE W9 whisper_edge.c
MISSING_FILE_AS_ADDRESS A1 we_lookup_cli.c
STEP_NUMERIC J1 we_lookup_cli.c
WITHHELD_NO_MEMBER W2 we_lookup_cli.c
SNAPSHOT_AS_REPUTATION W4,O1 we_lookup_cli.c
AMBIGUOUS_AS_DATA W4 we_lookup_cli.c
PRESTAGE_IN_LEGACY W4 we_lookup_cli.c
LEGACY_LOADER_IS_PLANE W4 we_lookup_cli.c
LEGACY_STALE_ENFORCED W4 we_lookup_cli.c
GEN0_AS_REVOKED W4 we_lookup_cli.c
BOUNDED_AS_UNIFORM W5 we_lookup_cli.c
GRACE_ROUNDED_UP W5 we_lookup_cli.c
GRACE_AS_MEMBER J1,W5 we_lookup_cli.c
NOW_PER_ADDRESS W7 we_lookup_cli.c
NOW_GETTIMEOFDAY W7 we_lookup_cli.c
DISARM_NO_NOTE W10 we_lookup_cli.c
DISARM_PATH_UNQUOTED W10 we_lookup_cli.c
AGE_TRUNCATED W11 we_lookup_cli.c
AGE_CAP_2_62 W11 we_lookup_cli.c
ARM_NO_SCHEMA_CHECK W12 we_lookup_cli.c
BIND_BY_DIGEST_ONLY W12 we_lookup_cli.c
NO_SECOND_PROBE W13 we_lookup_cli.c
CLASSIFY_AFTER_PROBE W13 we_lookup_cli.c
PROBE_FROM_LOAD W13 we_lookup_cli.c
NOW_CLOCK O1 we_lookup_cli.c
DISPLAY_FILL_COUNTED O1 we_lookup_cli.c
DEPENDENTS_CTX_ONLY O1 we_lookup_cli.c
DOWNGRADE_NO_RULE O1,X2 we_lookup_cli.c
WOULD_DENY_UNQUALIFIED O1,X2 we_lookup_cli.c
ORACLE_LINE_QUOTED J1,O1 we_lookup_cli.c
FLOOR_AS_ACME O1,O4 we_lookup_cli.c
CONTEXT_HTTP O3 we_lookup_cli.c
NO_PRESTAGE_ELIGIBLE H1,O4 we_lookup_cli.c
FLAG_DROP O4 we_lookup_cli.c
ACME_AS_HOLD_HARMLESS O4 we_lookup_cli.c
K3_HOOK_NOOP V1 we_lookup_cli.c
REFUSAL_GENERIC P1 we_lookup_cli.c
CONF_KEEPS_COMMENTS P2 we_lookup_cli.c
THRESHOLD_OFF_AS_HIGH P4 we_lookup_cli.c
DEFAULT_WITHOUT_POLICY X2 we_lookup_cli.c
ENFORCED_WITHOUT_POLICY X2 we_lookup_cli.c
TIER_BY_KEY_PRESENCE K1 we_lookup_cli.c
EXIT_ON_LOG X1 we_lookup_cli.c
OLD_FORM_EXIT_FLIPPED X1 we_lookup_cli.c
NO_OUTPUT_CHECK X1 we_lookup_cli.c
EXIT_MID_DOCUMENT X1 we_lookup_cli.c
CONTEXT_BYTES_PASSED P6,J1,O1 we_lookup_cli.c
POLICY_NOFOLLOW P5 we_lookup_cli.c
REHASH_DIRECT S1 we_lookup_cli.c
MANIFEST_PER_ADDRESS S1 we_lookup_cli.c
RELOAD_SECOND_PUBLISH S1 we_lookup_cli.c
HASH_WITHOUT_MANIFEST S1 we_lookup_cli.c
INTERN_UNCOUNTED S1 we_policy.c
JSON_DROP_KEY J1 we_lookup_cli.c
REFUSED_ADDRESS_KEYS_OMITTED J1 we_lookup_cli.c
UNQUOTED_POSITIONAL J1,A1 we_lookup_cli.c
JSON_SNAKE_CASE J1 we_lookup_cli.c
WHY_FREE_TEXT J1 we_lookup_cli.c
RULE_NO_TEXT J1 we_lookup_cli.c
LONG_DIR_ACCEPTED J2 we_lookup_cli.c
TYPE_BY_MAGNITUDE J3 we_lookup_cli.c
VALUE_TYPE_BY_STATE J3 we_lookup_cli.c
INSTANT_SHORT_FRACTION J3 we_lookup_cli.c
NOW_SECONDS_NO_NOTE J3 we_lookup_cli.c
BAD_REASON_TOKEN J4 we_lookup_cli.c
RAW_SPAN_KEYS J4 we_lookup_cli.c
RESERVED_TOKEN_PASSED J4 we_lookup_cli.c
JR_DUP_READ_NAME J4 we_lookup_cli.c
JR_LONE_SURROGATE J4 we_lookup_cli.c
JR_NUL_ESCAPE J4 we_lookup_cli.c
JR_BOM J4 we_lookup_cli.c
JR_TRAILING J4 we_lookup_cli.c
JR_GEN_FLOAT J4 we_lookup_cli.c
JR_GEN_2_64 J4 we_lookup_cli.c
JR_NEG_ZERO J4 we_lookup_cli.c
JR_LEADING_ZERO J4 we_lookup_cli.c
JR_NAN J4 we_lookup_cli.c
JR_INFINITY J4 we_lookup_cli.c
JR_UTF16 J4 we_lookup_cli.c
JR_RAW_TAB J4 we_lookup_cli.c
JR_OVERLONG J4 we_lookup_cli.c
JR_CESU J4 we_lookup_cli.c
JR_NINE_REASONS J4 we_lookup_cli.c
NAT64_AS_V4 A1 we_lookup_cli.c
NAT64_LOCAL_NO_NOTE A1 we_lookup_cli.c
PREFIX_LEN_QUOTES_RAW A1 we_lookup_cli.c
ZONE_PREFIX_TRUNCATED A1 we_lookup_cli.c
BRACKET_PREFIX_REFUSED A1 we_lookup_cli.c
SNAPSHOT_OPEN_NO_ERRNO W9 we_lookup_cli.c
CLASSIFY_IGNORES_ERRNO W9 we_lookup_cli.c
DIR_OPEN_NO_NOTE W9 we_lookup_cli.c
INSTALLED_IGNORES_ERRNO W9 we_lookup_cli.c
INSTALLED_UNKNOWN_EXITS W9 we_lookup_cli.c
INSTALLED_NOTE_UID_ALWAYS W9 we_lookup_cli.c
MODEL_LOOK_IGNORES_ERRNO W9 we_lookup_cli.c
LOOP_AS_PERMISSION W9 we_lookup_cli.c
DIR_NOTE_ON_ANY_ERRNO W9 we_lookup_cli.c
ZONE_SWALLOWS_PREFIX A1 we_lookup_cli.c
PORT_GENERIC A1 we_lookup_cli.c
PORT_STRIPS_DIGITS A1 we_lookup_cli.c
TRAILING_DOT_GENERIC A1 we_lookup_cli.c
SLASH_MARKS_FILE A1 we_lookup_cli.c
STDERR_RAW A1 we_lookup_cli.c
INET_NTOP A2 we_lookup_cli.c
"""

# The one edit each shared-unit mutant plants, applied to a copy: (unit, the text, its replacement). The
# text must occur exactly once, so a change to the unit stops the mutant loudly instead of planting nothing.
PATCHES = {
    "ASN_SENTINEL_DECIMAL": ("we_policy.c",
                             'return a == 0xffffffffu ? snprintf(buf, n, "undetermined") : snprintf(buf, n, "%" PRIu32, a);',
                             'return snprintf(buf, n, "%" PRIu32, a);'),
    "REGISTRY_FROM_ROUTING": ("we_policy.c",
                              '{ "registry_country", AC_COUNTRY, 0,        6, 4, 0,     1, 0 },\n'
                              '    { "rir",              AC_ENUM,    D_RIR,    3, 7, 0,     1, 6 },\n'
                              '    { "registry_rir",     AC_ENUM,    D_RIR,    6, 7, 0,     1, 6 },',
                              '{ "registry_country", AC_COUNTRY, 0,        3, 4, 0,     1, 0 },\n'
                              '    { "rir",              AC_ENUM,    D_RIR,    3, 7, 0,     1, 6 },\n'
                              '    { "registry_rir",     AC_ENUM,    D_RIR,    3, 7, 0,     1, 6 },'),
    "INTERN_UNCOUNTED": ("we_policy.c",
                         '    we_sha256(p, p->total_len, dp);\n    i = ((uint32_t)dp[0]',
                         '    {\n        uint64_t keep_ = we_lookup_hashed_bytes;\n\n'
                         '        we_sha256(p, p->total_len, dp);\n        we_lookup_hashed_bytes = keep_;\n    }\n'
                         '    i = ((uint32_t)dp[0]'),
    "FIFO_UNFIXED_CORE": ("whisper_edge.c",
                          '    if (!S_ISREG(st.st_mode)) {\n        *why = "not a regular file";\n        return -1;\n    }\n'
                          '    fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);',
                          '    fd = open(path, O_RDONLY | O_CLOEXEC);'),
}


def patch(name, src, out):
    unit, old, new = PATCHES[name]
    text = open(src).read()
    if text.count(old) != 1:
        print("patch %s: the text to replace occurs %d times in %s; the mutant plants nothing" % (
            name, text.count(old), unit), file=sys.stderr)
        sys.exit(1)
    with open(out, "w") as f:
        f.write(text.replace(old, new))


# What this gate does not run. The README's lookup transcripts on the checked-in fixtures are re-run by the transcripts row; SECURITY.md
# quotes a command, not a transcript.
PENDING_ROWS = """
the README's two --probe-dir planes transcripts: they read the planes the differential's producer wrote on the capturing host, whose owner and uid lines are that host's
"""
PENDING_MUTANTS = """
"""

# the files this work adds that ship, which the hygiene check reads
FILES = """
core/we_lookup_cli.c core/we_record_fields.h core/we_plane_tier.h core/we_hold_harmless_cite.h
core/we_default_policy.h core/we_lookup_guard.h core/gen-lookup-headers.py core/lookup-check.py
core/lookup-states.py core/lookup-gate.sh core/lookup_shim.c core/fuzz_manifest.c
core/testdata/lookup/README.md core/testdata/lookup/derived/README.md core/testdata/lookup/deny-all.conf
core/testdata/lookup/writer/keyless/manifest.json core/testdata/lookup/writer/disarm/manifest.json
core/testdata/lookup/writer/jobs/manifest.json core/testdata/lookup/floor-and-ctx.policy
core/testdata/lookup/floor-log-ctx-decides.policy core/testdata/lookup/disarmed-old-form.txt
""".split()


# ======================================================================================================
# The differential: the case set, the gate's own restatement of the request, and the judge
# ======================================================================================================

# The generator's own controls, each a planted edit that must fail a count (LOOKUP_STATES_MUTANT):
#   DROP_STATE    one state of the first program left out
#   DOUBLE_ADDRS  one program's address set given twice
#   DROP_ABSENT   the covering array without its `absent` level
#   SEV1_ONLY     the reputation address chosen at severity 1, so no floor or high rule can decide on it
#   PROBE_OPEN    the restatement's probe opens a plane path with a plain blocking open()
#   HH_SETS_ONLY  hhagree compares the two sides as sets alone, so two empty sides or a doubled row agree
#   HH_NO_SET_SIZE  hhagree without its duplicate-row conditions: a doubled row whose count was bumped agrees
GEN_MUTANT = os.environ.get("LOOKUP_STATES_MUTANT", "")

PLANE_NAMES = ("reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant")
NT_LEVELS = ("fresh", "stale", "absent", "refused")
T_LEVELS_640 = ("fresh", "grace", "lapsed", "null")
T_LEVELS = T_LEVELS_640 + ("absent",)
V = 1791878400000                    # the stale fixtures' valid_until_ms (lookup-gate.sh's PV)
H48 = 48 * 3600 * 1000
HH_ADDR = "192.0.2.1"                # a hold-harmless address (TEST-NET-1)


def _ref():
    """The reference interpreter, for its readers and its compiler only: the directives of a policy file
    and the planes a compiled program reads. It judges nothing here."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import policy_ref
    return policy_ref


def read_directives(path):
    """(records, form) of a policy source the way the tool reads it: the record form when the text holds
    0x1E 0x0A, else the installer's policy.conf form."""
    R = _ref()
    data = open(path, "rb").read()
    if b"\x1e\n" in data:
        return R.read_records(data)
    return R.conf_records(data)


def run_context(records):
    """The context whose program step 4 runs: the first context a policy or threshold line names."""
    for kind, ctx, _ in records:
        if kind in ("policy", "threshold"):
            return ctx
    return "http"


def planes_read(records, run):
    """The plane ids the floor and the run context's program read, from the compiled programs."""
    R = _ref()
    cfg = R.compile_config(records)
    out = set()
    for p in (cfg.floor, cfg.effective(run)):
        for r in (p.rules if p is not None else ()):
            for a in r.atoms:
                out.add(R.BOOLS[a.attr][0] if a.attr in R.BOOLS else R.VALUED[a.attr][0])
    return out


def programs(core):
    """The 22 programs of the differential: the accept corpus, the default policy, deny-all."""
    acc = os.path.join(core, "testdata/policy/accept")
    out = [os.path.join(acc, f) for f in sorted(os.listdir(acc)) if f.endswith(".policy")]
    return out + [os.path.join(core, "testdata/policy/default.conf"), os.path.join(core, "testdata/lookup/deny-all.conf")]


def covering(k, tenant):
    """The strength-2 covering array over {fresh, stale, absent, refused} per non-tenant plane read and
    {the four tenant states, absent} for the tenant plane: seeded with the all-absent row and each
    single-absent row (the others fresh), completed greedily, the first maximum in the level order
    fresh, stale, absent, refused (tenant: fresh, grace, lapsed, null, absent) winning a tie. A single
    factor is covered level by level."""
    nt = tuple(l for l in NT_LEVELS if not (GEN_MUTANT == "DROP_ABSENT" and l == "absent"))
    levels = [nt] * k + ([T_LEVELS] if tenant else [])
    n = len(levels)
    rows = []
    for r in [tuple("absent" for _ in range(n))] + [tuple("absent" if j == i else "fresh" for j in range(n))
                                                    for i in range(n)]:
        if r not in rows:
            rows.append(r)

    def covers(r):
        if n == 1:
            return {(0, r[0])}
        return {(i, r[i], j, r[j]) for i in range(n) for j in range(i + 1, n)}
    need = set()
    if n == 1:
        need = {(0, a) for a in levels[0]}
    for i in range(n):
        for j in range(i + 1, n):
            need |= {(i, a, j, b) for a in levels[i] for b in levels[j]}
    for r in rows:
        need -= covers(r)
    cands = [tuple(levels[i][c[i]] for i in range(n))
             for c in itertools.product(*[range(len(lv)) for lv in levels])]
    while need:
        best, bc = None, -1
        for r in cands:
            g = len(covers(r) & need)
            if g > bc:
                best, bc = r, g
        rows.append(best)
        need -= covers(best)
    return rows


def expect_addrs(pdir, name):
    """One address inside a range and one in none, per family, from the writer's --expect file; a missing
    one stops the run rather than shrinking the case set. On the reputation plane the address inside is a
    critical one (the writer's severities run 1 + i % 4), so every listing rule the corpus writes matches
    it. (Step 3 is reached through floor-and-ctx.policy's fixed cases: no corpus floor runs in mode deny.)"""
    got = {}
    want_sev = "sev=1" if GEN_MUTANT == "SEV1_ONLY" else "sev=4"
    for line in open(os.path.join(pdir, name + ".expect")):
        f = line.split()
        fam, addr, ans = f[:3]
        if name == "reputation" and ans != "-" and want_sev not in f:
            continue
        key = (fam, ans != "-")
        got.setdefault(key, addr)
    keys = (("4", True), ("4", False), ("6", True), ("6", False))
    missing = [k for k in keys if k not in got]
    if missing:
        raise SystemExit("lookup-states.py: %s.expect has no %s address" % (name, missing))
    return [got[k] for k in keys]


def state_dirs(core, pdir):
    """Every invocation of O1 (plain flags) and O4 (--acme and --skipped-hop on the all-fresh states):
    (program, context, states {plane: level}, flags, addresses)."""
    inv = []
    for prog in programs(core):
        recs = read_directives(prog)
        run = run_context(recs)
        rd = planes_read(recs, run)
        nt = sorted(p for p in rd if p != 8)
        t = 8 in rd
        addrs = []
        for p in nt:
            addrs += expect_addrs(pdir, PLANE_NAMES[p - 1])
        if t:
            ta = expect_addrs(pdir, "tenant")
            addrs += ta[:2]
        addrs.append(HH_ADDR)
        vectors = []
        for bits in itertools.product(("fresh", "stale"), repeat=len(nt)):
            for ts in (T_LEVELS_640 if t else (None,)):
                vectors.append(tuple(bits) + ((ts,) if t else ()))
        vectors += covering(len(nt), t)
        if GEN_MUTANT == "DROP_STATE" and prog == programs(core)[0]:
            vectors = vectors[1:]
        if GEN_MUTANT == "DOUBLE_ADDRS" and prog == programs(core)[0]:
            addrs = addrs + addrs
        for vec in vectors:
            st = {PLANE_NAMES[p - 1]: vec[i] for i, p in enumerate(nt)}
            if t:
                st["tenant"] = vec[-1]
            inv.append((prog, run, st, "plain", addrs))
        allfresh = {PLANE_NAMES[p - 1]: "fresh" for p in nt}
        if t:
            allfresh["tenant"] = "fresh"
        for flag in ("acme", "skipped-hop"):
            inv.append((prog, run, dict(allfresh), flag, addrs))
    return inv


def o_counts(core, pdir):
    inv = state_dirs(core, pdir)
    plain = [i for i in inv if i[3] == "plain"]
    flags = [i for i in inv if i[3] != "plain"]
    return (len(plain), sum(len(i[4]) for i in plain), len(flags), sum(len(i[4]) for i in flags))


# The differential's counts, measured at implementation and pinned: 22 programs, 956 plain states
# (640 fresh-and-stale products and 316 covering rows) with 20,258 cases, and two flag runs per program
# with 488 cases. o_counts() must give these, and so must o_counts_derived(), which works from the
# per-program parameters (the same plane-set reader the generator uses) with a covering greedy written
# apart; the pinned figures are the independent anchor.
O_PINNED = (956, 20258, 44, 488)


def o_counts_derived(core):
    """The same four counts from the parameter table alone: per program, k non-tenant planes read and t the
    tenant plane read; 2^k x (4 if t) fresh-and-stale states, the covering rows by a second greedy written
    apart from covering(), and 4k + 2t + 1 addresses per state (two per family per plane, two for the
    tenant, one hold-harmless address); two flag runs per program at the all-fresh state."""
    params = []
    for prog in programs(core):
        recs = read_directives(prog)
        rd = planes_read(recs, run_context(recs))
        params.append((len([p for p in rd if p != 8]), 1 if 8 in rd else 0))

    def rows_needed(k, t):
        sizes = [4] * k + ([5] if t else [])
        # `absent` is level 2 of a plane's four (fresh, stale, absent, refused) and level 4, the last, of
        # the tenant's five (fresh, grace, lapsed, null, absent); level 0 is `fresh` for both
        absent = [2] * k + ([4] if t else [])
        n = len(sizes)
        if n == 1:
            return sizes[0]
        chosen = [tuple(absent)]
        for i in range(n):
            row = tuple(absent[i] if j == i else 0 for j in range(n))
            if row not in chosen:
                chosen.append(row)
        open_pairs = set((i, j, x, y) for i in range(n) for j in range(i + 1, n)
                         for x in range(sizes[i]) for y in range(sizes[j]))

        def pairs(row):
            return set((i, j, row[i], row[j]) for i in range(n) for j in range(i + 1, n))
        for row in chosen:
            open_pairs -= pairs(row)
        count = len(chosen)
        while open_pairs:
            best_row, best_gain = None, 0
            row = [0] * n
            while True:
                gain = len(pairs(row) & open_pairs)
                if gain > best_gain:
                    best_row, best_gain = tuple(row), gain
                d = n - 1
                while d >= 0 and row[d] == sizes[d] - 1:
                    row[d] = 0
                    d -= 1
                if d < 0:
                    break
                row[d] += 1
            open_pairs -= pairs(best_row)
            count += 1
        return count
    plain_states = plain_cases = flag_runs = flag_cases = 0
    for k, t in params:
        per = 4 * k + 2 * t + 1
        states = 2 ** k * (4 if t else 1) + rows_needed(k, t)
        plain_states += states
        plain_cases += states * per
        flag_runs += 2
        flag_cases += 2 * per
    return plain_states, plain_cases, flag_runs, flag_cases


def build_cases(core, pdir, pvdir, out):
    """Write the O1 and O4 directories and the plan.tsv the gate runs and the judge reads. A plane the program
    does not read is installed fresh; snapshot.bin sits in every directory, where only the legacy synonym
    may read it. Each plan line: id, dir, policy, context, now, flags, states, ranges dir, addresses."""
    os.makedirs(out, exist_ok=True)
    # every installed plane is a hard link into one pool, so 1,000 directories cost a few megabytes: the
    # fresh and bounded planes themselves, and one cut-short copy of each plane for the refused states
    pool = os.path.join(out, "pool")
    os.makedirs(pool, exist_ok=True)
    for name in PLANE_NAMES:
        cut = os.path.join(pool, name + ".cut")
        if not os.path.exists(cut):
            with open(cut, "wb") as f:
                f.write(open(os.path.join(pdir, name + ".bin"), "rb").read()[:-10])
            os.chmod(cut, 0o444)   # refused for its bytes, never its mode: the module maps 0444 alone
    plan = []
    for n, (prog, run, st, flag, addrs) in enumerate(state_dirs(core, pdir)):
        d = os.path.join(out, "s%04d" % n)
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o755)
        lapsed = st.get("tenant") == "lapsed"
        now = V + H48 + 1 if lapsed else V + 1
        states = {}
        for name in PLANE_NAMES:
            lv = st.get(name, "fresh")
            if lv == "absent":
                continue
            if lv in ("refused", "null"):
                src = os.path.join(pool, name + ".cut")
            else:
                src = os.path.join(pvdir if lv in ("stale", "grace", "lapsed") else pdir, name + ".bin")
            os.link(src, os.path.join(d, name + ".bin"))
            states[name] = {"grace": "stale", "lapsed": "stale", "null": "refused"}.get(lv, lv)
        os.link(os.path.join(pdir, "reputation.bin"), os.path.join(d, "snapshot.bin"))
        plan.append("\t".join(["s%04d" % n, d, prog, run, str(now), flag,
                               ",".join("%s=%s" % kv for kv in sorted(states.items())), pdir, " ".join(addrs)]))
    with open(os.path.join(out, "plan.tsv"), "w") as f:
        f.write("\n".join(plan) + "\n")
    # the same lines interleaved program by program, the order the mutant phase walks: a defect one
    # program reaches is met within the first round rather than at that program's place in the list
    rank, seen = [], {}
    for line in plan:
        prog = line.split("\t")[2]
        rank.append((seen.get(prog, 0), sorted(set(l.split("\t")[2] for l in plan)).index(prog), line))
        seen[prog] = seen.get(prog, 0) + 1
    with open(os.path.join(out, "plan-rr.tsv"), "w") as f:
        f.write("\n".join(r[2] for r in sorted(rank, key=lambda r: (r[0], r[1]))) + "\n")
    print("%d invocations, %d cases" % (len(plan), sum(len(p.split("\t")[8].split()) for p in plan)))


# ---- the gate's own restatement of the request, never the tool's ----

def probe_present(path):
    """The module's probe rule: stat(); a non-regular target is present; a regular one when an
    open(O_RDONLY|O_NONBLOCK) succeeds. Never a blocking open."""
    if GEN_MUTANT == "PROBE_OPEN":
        try:
            os.close(os.open(path, os.O_RDONLY))
            return True
        except OSError:
            return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return True
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False
    os.close(fd)
    return True


def load_ranges(rdir, cache={}):
    if rdir not in cache:
        tab = {}
        for name in PLANE_NAMES:
            path = os.path.join(rdir, name + ".ranges")
            if not os.path.exists(path):
                continue
            fams = {4: ([], []), 6: ([], [])}
            for line in open(path):
                fam, kb, s, e, tok = line.split()
                fams[int(fam)][0].append((int(s), int(e), int(kb)))
                fams[int(fam)][1].append(tok[len("fields="):].replace(",", " "))
            tab[name] = fams
        cache[rdir] = tab
    return cache[rdir]


def rec_line(rdir, name, addr):
    """The record the writer packed into the range the address falls in, or none."""
    tab = load_ranges(rdir).get(name)
    ip = ipaddress.ip_address(addr)
    fam = ip.version
    if tab is None or not tab[fam][0]:
        return "rec floor %s none" % name
    kb = tab[fam][0][0][2]
    key = int(ip) >> 64 if (fam == 6 and kb == 8) else int(ip)
    starts = [s for s, _, _ in tab[fam][0]]
    i = bisect.bisect_right(starts, key) - 1
    if i >= 0 and key <= tab[fam][0][i][1]:
        return "rec floor %s %s" % (name, tab[fam][1][i])
    return "rec floor %s none" % name


def conf_of(cfg, ctx):
    """we_policy_conf: each scalar from the nearest context that sets it."""
    R = _ref()
    mode = ai = 0
    for c in R.ancestors(ctx):
        if c in cfg.modes:
            mode = cfg.modes[c]
            break
    for c in R.ancestors(ctx):
        if c in cfg.inferred:
            ai = cfg.inferred[c]
            break
    return mode, ai


def restate(line):
    """The case block of one plan.tsv line, from that line and the directory alone."""
    R = _ref()
    pid, d, prog, run, now, flag, states, rdir, addrs = line.rstrip("\n").split("\t")
    now = int(now)
    st = dict(kv.split("=") for kv in states.split(",") if kv)
    # a state may carry the plane's valid_until_ms after an @; the tenant line states it (FORMAT.md: 0 is
    # no bound), and a stale plane of this gate's fixtures was written with V
    vus = {k: int(v.split("@")[1]) for k, v in st.items() if "@" in v}
    st = {k: v.split("@")[0] for k, v in st.items()}
    legacy = prog.startswith("legacy:")
    if prog.startswith("sugar:") or legacy:
        # the threshold sugar; under the legacy synonym (--snapshot, `dir` the file) nothing is inert
        thr, mode = prog.split(":")[1:3]
        recs = [("threshold", "http", thr.encode())]
        conf = (3 if mode == "deny" else 2, 0)
        confs = (conf, conf)
    else:
        recs = read_directives(prog)
        cfg = R.compile_config(recs)
        confs = (conf_of(cfg, "http"), conf_of(cfg, run))
    problems = []
    present = {}
    for name in PLANE_NAMES:
        if legacy:
            present[name] = name == "reputation"
            continue
        present[name] = probe_present(os.path.join(d, name + ".bin"))
        if present[name] != (name in st):
            problems.append("%s: the probe finds it %s, plan.tsv says %s" % (
                name, "present" if present[name] else "absent", st.get(name, "absent")))
    out = ["program lookup cases"]
    for kind, ctx, arg in recs:
        out.append("dir %s %s %s" % (kind, ctx, R.escape(arg)))
    out.append("run %s" % run)
    absent = [n for n in PLANE_NAMES if not present[n]]
    if absent:
        out.append("absent " + " ".join(absent))
    if legacy:
        out.append("legacy")
    tvu = vus.get("tenant", V if st.get("tenant") == "stale" else 0)
    tword = {"fresh": "fresh", "stale": "stale"}.get(st.get("tenant"), "null")
    prestage = not (legacy and prog.split(":")[3] == "absent")
    hh, acme = (0 if flag == "skipped-hop" or not prestage else 1), (1 if flag == "acme" and prestage else 0)
    for i, a in enumerate(addrs.split()):
        out.append("case %d" % (i + 1))
        out.append("conf floor %d %d" % confs[0])
        out.append("conf ctx %d %d" % confs[1])
        for name in PLANE_NAMES[:7]:
            if present[name]:
                out.append("plane %s %s" % (name, "fresh" if st.get(name) == "fresh" else "stale"))
        out.append("tenant %s %d %d" % (tword, now, tvu if tword in ("fresh", "stale") else 0))
        out.append("addr floor %s" % ipaddress.ip_address(a).compressed)
        out.append("flags %d %d" % (hh, acme))
        for name in PLANE_NAMES:
            if present[name]:
                out.append(rec_line(rdir, name, a) if st.get(name) in ("fresh", "stale")
                           else "rec floor %s none" % name)
        out.append("end")
    return out, problems


# ---- the judge: the tool's lines against both evaluators' ----

ORACLE_KINDS = ("verdict", "cost", "dependents")
STEP_OF = {("1", "allow-by-hold-harmless"): "hold-harmless", ("1", "allow-by-acme"): "acme"}


def step_fn(vline):
    """The decision's step as a function of the verdict's (step, program, reason)."""
    kv = dict(t.split("=", 1) for t in vline.split()[1:])
    step, prog, why = kv["step"], kv["program"], kv["reason"].split(",")[0]
    if step == "1":
        return STEP_OF.get((step, why))
    return {("2", "-"): "tenant", ("3", "floor"): "floor", ("3.5", "-"): "tenant-grace", ("4", "ctx"): "context",
            ("4", "-"): "default"}.get((step, prog))


def render_token(v):
    """A value as the line form writes it: quoted when empty or holding a space, `"`, `\\` or `=`, with bytes
    outside 0x20..0x7E, `"` and `\\` written \\xHH inside."""
    if v != "" and not any(c in v for c in ' "\\='):
        return v
    return '"%s"' % "".join(c if 0x20 <= ord(c) <= 0x7E and c not in '"\\' else "\\x%02X" % ord(c) for c in v)


def expected_decision(vline, texts, sugar, rep_state, tenant_present):
    """The decision line the evaluator's verdict and the program's rule texts give, in the one format both
    models print: `rule` and `text` are always the deciding rule; `log` lists every rule that recorded;
    a `log` decision names the first deny that mode log downgraded (floor before context) in
    `would-deny-rule=<floor|ctx>:<rule>` and `would-deny-text`."""
    kv = dict(t.split("=", 1) for t in vline.split()[1:])
    if sugar and rep_state in ("stale", "refused"):
        return "decision allow step=sugar rule=0 reason=%s" % ("stale" if rep_state == "stale" else "no-map")
    fired = [(prog, int(n)) for prog, key in (("floor", "log_floor"), ("ctx", "log_ctx"))
             for n in kv[key].split(",") if n != "-"]
    down = [(prog, n) for prog, n in fired if texts.get(prog, {}).get(n, "").startswith("deny ")]
    prog_word = {"floor": "floor", "ctx": "ctx"}.get(kv["program"])
    out = ["decision"]
    rule, rprog = int(kv["rule"]), prog_word
    if kv["action"] == "deny":
        out += ["deny", "enforce=yes"]
    elif down:
        out += ["log", "would-deny=yes"]
    else:
        out += ["allow"]
    out.append("step=%s" % ("sugar" if sugar else step_fn(vline)))
    out.append("rule=%d" % rule)
    if rule != 0:
        out.append("text=%s" % render_token(texts.get(rprog, {}).get(rule, "?")))
    why = kv["reason"].split(",")[0]
    if why.startswith("allow-by-unknown:"):
        out.append("reason=%s" % why)
    if fired:
        out.append("log=%s" % ",".join("%s:%d" % f for f in fired))
    if tenant_present and not sugar:
        out.append("identity=unchecked,revocation-not-checked")
    if kv["action"] != "deny" and down:
        out.append("would-deny-rule=%s:%d" % down[0])
        out.append("would-deny-text=%s" % render_token(texts.get(down[0][0], {}).get(down[0][1], "?")))
    return " ".join(out)


def tool_addresses(path):
    """Per address: verdict, cost, attr lines (name value [bounded=]), dependents, the decision line."""
    out = []
    cur = None
    reports = []
    for line in open(path, encoding="ascii"):
        line = line.rstrip("\n")
        kind = line.split(" ", 1)[0]
        if kind == "report":
            reports.append(line)
        elif kind == "address":
            cur = {"attrs": [], "dependents": [], "verdict": None, "cost": None, "step": None, "decision": None}
            out.append(cur)
        elif cur is None:
            continue
        elif kind == "attr":
            w = line.split()
            b = [t for t in w[3:] if t.startswith("bounded=")]
            cur["attrs"].append(" ".join(["attr", w[1], w[2]] + b))
        elif kind in ("verdict", "cost"):
            cur[kind] = line
        elif kind == "dependents":
            cur["dependents"].append(line)
        elif kind == "decision":
            cur["step"] = [t[5:] for t in line.split() if t.startswith("step=")][0]
            cur["decision"] = line
    return out, reports


def oracle_cases(path):
    """program id -> (report lines, {case id: {verdict, cost, attrs, dependents, invariant}}, the rules'
    texts {floor|ctx: {n: text}})."""
    progs = {}
    cur = None
    case = None
    for line in open(path, encoding="latin-1"):
        line = line.rstrip("\n")
        kind = line.split(" ", 1)[0]
        if kind == "program":
            cur = progs.setdefault(line.split()[1], ([], {}, {}))
            case = None
        elif kind == "report" and case is None:
            cur[0].append(line)
        elif kind == "text" and case is None:
            w = line.split(" ", 3)
            if len(w) == 4 and w[2].isdigit():
                cur[2].setdefault(w[1], {})[int(w[2])] = w[3]
        elif kind == "case":
            case = {"attrs": [], "dependents": []}
            cur[1][line.split()[1]] = case
        elif case is None:
            continue
        elif kind in ("verdict", "cost", "invariant"):
            case[kind] = line
        elif kind == "attr":
            case["attrs"].append(line)
        elif kind == "dependents":
            case["dependents"].append(line)
    return progs


def judge(plan_path, tooldir, cache, first):
    """Compare every invocation of a plan; `cache` holds both evaluators' outputs over the restated case
    file and is written when absent (the normal phase) and reused (the mutant phase). Prints FAIL lines and
    one summary line; with `first`, stops at the first invocation that differs."""
    checks = [0, 0]

    def check(cond, what):
        checks[0] += 1
        if not cond:
            checks[1] += 1
            print("FAIL " + what)
        return cond
    lines = [l for l in open(plan_path) if l.strip()]
    ref_file = os.path.join(cache, "ref.case")
    if not os.path.exists(os.path.join(cache, "c.out")):
        os.makedirs(cache, exist_ok=True)
        with open(ref_file, "w") as f:
            for line in lines:
                block, problems = restate(line)
                pid = line.split("\t")[0]
                for p in problems:
                    print("FAIL %s: the gate's restatement: %s" % (pid, p))
                for b in block:
                    if b.startswith("program "):
                        b = "program %s cases" % pid
                    elif b.startswith("case "):
                        b = "case %s.%s" % (pid, b.split()[1])
                    f.write(b + "\n")
        here = os.path.dirname(os.path.abspath(__file__))
        r1 = subprocess.run([sys.executable, os.path.join(here, "policy_ref.py"), "--cases", ref_file, "--attrs",
                             "--out", os.path.join(cache, "py.out")], stdout=subprocess.DEVNULL,
                            stderr=open(os.path.join(cache, "py.err"), "w"))
        with open(os.path.join(cache, "c.out"), "w") as cf:
            r2 = subprocess.run([os.environ.get("TEST_POLICY", os.path.join(here, "test_policy")), "--cases", ref_file,
                                 "--attrs"], stdout=cf, stderr=open(os.path.join(cache, "c.err"), "w"))
        with open(os.path.join(cache, "rc"), "w") as rf:
            rf.write("%d %d\n" % (r1.returncode, r2.returncode))
    # Both evaluators must finish clean: exit 0, and nothing on standard error but their summary lines.
    rcs = open(os.path.join(cache, "rc")).read().split()
    check(rcs == ["0", "0"], "both evaluators exit 0 (policy_ref.py %s, test_policy %s)" % tuple(rcs))
    for name, allowed in (("py.err", (r"^oracle: ", r"^0 checks, 0 failures$", r"^[0-9]+ checks, 0 failures$")),
                          ("c.err", (r"^test_policy --cases: ", r"^[0-9]+ checks, 0 failures$"))):
        stray = [l for l in open(os.path.join(cache, name)).read().splitlines()
                 if not any(re.match(a, l) for a in allowed)]
        check(not stray, "%s holds only the summary lines: %r" % (name, stray[:2]))
    py = oracle_cases(os.path.join(cache, "py.out"))
    cc = oracle_cases(os.path.join(cache, "c.out"))
    n_inv = n_case = floor_arm = acme_arm = 0
    for line in lines:
        f = line.rstrip("\n").split("\t")
        pid, addrs = f[0], f[8].split()
        n_inv += 1
        bad0 = checks[1]
        block, _ = restate(line)
        try:
            mine = open(os.path.join(tooldir, pid + ".case"), encoding="ascii").read().split("\n")[:-1]
        except (OSError, UnicodeDecodeError):
            mine = []
        check(mine == block, "%s: the tool's --case block differs from the gate's restatement%s" % (
            pid, next((": line %d, tool %r, gate %r" % (k + 1, x, y) for k, (x, y) in enumerate(zip(mine, block))
                       if x != y), " (%d lines against %d)" % (len(mine), len(block)))))
        try:
            got, reports = tool_addresses(os.path.join(tooldir, pid + ".out"))
        except (OSError, UnicodeDecodeError):
            got, reports = [], []
        if not check(len(got) == len(addrs), "%s: %d addresses printed, %d given" % (pid, len(got), len(addrs))):
            continue
        pr, cr = py.get(pid), cc.get(pid)
        if not check(pr is not None and cr is not None, "%s: both evaluators judged the program" % pid):
            continue
        check(reports == pr[0] == cr[0], "%s: the report lines equal both evaluators' (tool %r, py %r, c %r)"
              % (pid, reports[:2], pr[0][:2], cr[0][:2]))
        for i, a in enumerate(got):
            cid = "%s.%d" % (pid, i + 1)
            n_case += 1
            p, c = pr[1].get(cid), cr[1].get(cid)
            if not check(p is not None and c is not None, "%s: both evaluators judged the case" % cid):
                continue
            for k in ("verdict", "cost"):
                check(a[k] == p.get(k) == c.get(k), "%s: %s: tool %r, py %r, c %r" % (cid, k, a[k], p.get(k),
                                                                                     c.get(k)))
            check(a["attrs"] == p["attrs"] == c["attrs"], "%s: attr lines differ: %s" % (cid, next(
                ("tool %r, py %r, c %r" % t for t in zip(a["attrs"], p["attrs"], c["attrs"]) if len(set(t)) > 1),
                "%d, %d, %d lines" % (len(a["attrs"]), len(p["attrs"]), len(c["attrs"])))))
            check(a["dependents"] == p["dependents"] == c["dependents"], "%s: dependents: tool %r, py %r, c %r"
                  % (cid, a["dependents"], p["dependents"], c["dependents"]))
            check(c.get("invariant", "").endswith(" failed=0"), "%s: the C invariant: %r" % (cid, c.get("invariant")))
            if p.get("verdict"):
                # a module without the pre-stage decides on the legacy request path, step `sugar`
                sugar = f[2].startswith("legacy:") and f[2].endswith(":absent")
                want = "sugar" if sugar else step_fn(p["verdict"])
                check(a["step"] == want, "%s: decision step=%s, the verdict's function gives %s" % (cid, a["step"], want))
                states = dict(kv.split("=") for kv in f[6].split(",") if kv)
                dline = expected_decision(p["verdict"], pr[2], sugar, states.get("reputation", "absent").split("@")[0],
                                          "tenant" in states)
                check(a["decision"] == dline, "%s: the decision line: tool %r, from the verdict %r" % (cid, a["decision"],
                                                                                                    dline))
                kv = dict(x.split("=", 1) for x in p["verdict"].split()[1:])
                floor_arm += kv.get("step") == "3" and kv.get("program") == "floor"
                acme_arm += kv.get("reason", "").split(",")[0] == "allow-by-acme"
        if first and checks[1] > bad0:
            break
    print("judged %d invocations, %d cases; step=3 program=floor %d, allow-by-acme %d" % (n_inv, n_case,
                                                                                        floor_arm, acme_arm))
    print("%d checks, %d failures" % tuple(checks))
    return 0 if checks[1] == 0 else 1


def hh_agree(eval_h, cite_h):
    """The evaluator's merged ranges (we_hold_harmless.h, host-order words) and the cite header's merged
    ranges (network-order bytes) as one set each, compared; both come from hold-harmless.txt through two
    generators, so this is the check that they merged it alike."""
    ev = []
    text = open(eval_h).read()
    for a, b in re.findall(r"\{ 0x([0-9a-f]{8})u, 0x([0-9a-f]{8})u \}", text):
        ev.append((4, int(a, 16), int(b, 16)))
    for w in re.findall(r"\{ 0x([0-9a-f]{16})ull, 0x([0-9a-f]{16})ull, 0x([0-9a-f]{16})ull, 0x([0-9a-f]{16})ull \}",
                        text):
        ev.append((6, int(w[0] + w[1], 16), int(w[2] + w[3], 16)))
    ct = []
    cite_text = open(cite_h).read()
    if "we_hh_ranges[" not in cite_text:
        print("hold-harmless: %s has no we_hh_ranges table" % cite_h)
        return 1
    body = cite_text.split("we_hh_ranges[", 1)[1]
    for fam, a, b in re.findall(r"\{ ([46]), \{([^}]*)\},\s*\{([^}]*)\} \}", body):
        width = 4 if fam == "4" else 16
        def num(x):
            return int.from_bytes(bytes(int(v, 16) for v in x.split(",")[:width]), "big")
        ct.append((int(fam), num(a), num(b)))
    counts = re.findall(r"#define WE_HH_V[46]_COUNT ([0-9]+)u", text)
    want = sum(int(c) for c in counts)
    # read every row, and each row once: two counts in the header, no empty side, no duplicate row
    ok = (len(counts) == 2 and want > 0 and len(ev) == want == len(set(ev)) and len(ct) == len(set(ct))
          and set(ev) == set(ct))
    if GEN_MUTANT == "HH_NO_SET_SIZE":
        ok = (len(counts) == 2 and want > 0 and len(ev) == want and set(ev) == set(ct))   # no duplicate test
    if GEN_MUTANT == "HH_SETS_ONLY":
        ok = len(set(ev)) == want and set(ev) == set(ct)       # the earlier form: sets alone
    print("hold-harmless: evaluator %d ranges (header says %d), cite %d, %s" % (
        len(ev), want, len(ct), "the same set" if ok else "DIFFERENT, or a side read short"))
    return 0 if ok else 1


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else ""
    if what == "l2":
        print("%d %d %d %d %d" % l2())
    elif what == "mutants":
        for line in MUTANTS.strip().splitlines():
            print(line)
    elif what == "pending":
        for line in PENDING_ROWS.strip().splitlines():
            print("DARK " + line)
        for line in PENDING_MUTANTS.strip().splitlines():
            if line.strip():
                print("DARK mutant " + line)
    elif what == "files":
        print("\n".join(FILES))
    elif what == "hhagree":
        sys.exit(hh_agree(sys.argv[2], sys.argv[3]))
    elif what == "patch":
        patch(sys.argv[2], sys.argv[3], sys.argv[4])
    elif what == "ocounts":
        print("%d %d %d %d" % o_counts(os.path.dirname(os.path.abspath(__file__)), sys.argv[2]))
    elif what == "oaddrs":
        a = expect_addrs(sys.argv[2], "reputation")
        print("%s %s" % (a[0], a[2]))
    elif what == "oderived":
        print("%d %d %d %d" % o_counts_derived(os.path.dirname(os.path.abspath(__file__))))
    elif what == "opinned":
        print("%d %d %d %d" % O_PINNED)
    elif what == "build":
        build_cases(os.path.dirname(os.path.abspath(__file__)), sys.argv[2], sys.argv[3], sys.argv[4])
    elif what == "judge":
        sys.exit(judge(sys.argv[2], sys.argv[3], sys.argv[4], "--first" in sys.argv[5:]))
    else:
        print(__doc__.strip())
        sys.exit(2)


if __name__ == "__main__":
    main()
