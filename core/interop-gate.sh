#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# interop-gate.sh - prove the independent writers and the C reader agree about the snapshot format,
# and, for format 2, that the builder's published lookup bounds are the ones the lookup measures.
#
#   interop-gate.sh [OUT]                  the checked-in fixtures (or WHISPER_EDGE_FIXTURE=<dir>)
#   interop-gate.sh --builder DIR [OUT]    the planes a builder actually produced, read from its edge
#                                          directory: the staged planes, the withheld builds and the
#                                          planes a committed manifest names
#
# If the fixture is missing this FAILS and says so; it does not skip. A format gate that quietly skips
# when its input is absent is how two halves of a wire format drift apart while every build stays
# green. The builder mode holds itself to the same rule: a part of the directory that does not exist
# yet is reported DARK by name, and a run that checked no plane at all fails.
set -euo pipefail

cd "$(dirname "$0")"
BUILDER=""
if [ "${1:-}" = "--builder" ]; then
    BUILDER="${2:?--builder needs a builder edge directory}"
    shift 2
    [ -d "$BUILDER" ] || { echo "INTEROP GATE: FAILED - no directory at $BUILDER"; exit 1; }
    BUILDER="$(cd "$BUILDER" && pwd)"
fi
FIX="${WHISPER_EDGE_FIXTURE:-./testdata}"
CC="${CC:-cc}"
OUT="${1:-./.testtmp/interop}"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------------------------------
# COPY A PLANE TO 0644 BEFORE LOADING IT, and the reason is worth the four lines.
#
# The loader REFUSES a group- or world-writable snapshot, correctly: the digest is unkeyed, so whoever
# can write the file controls what a site blocks. Git creates a checked-out file at `0666 & ~umask`,
# and umask 002 is the default on Debian and Ubuntu wherever a user's primary group is their own - so
# a clone there gets mode 664 and this gate fails, with a message that reads as a security problem
# rather than as a umask artifact. Measured: 644 gives CLEAR, 664 gives "snapshot is group- or
# world-writable" and exit 1.
#
# That is the FIRST command the README tells a sceptic to run, so the gate has to work in their clone.
# The loader's check is right and stays; the fixture gets a private copy at the mode a published
# snapshot actually has.
stage() {
    cp "$1" "$2"
    chmod 0644 "$2"
}

build_plane_tools() {
    "$CC" -std=c11 -O2 -Wall -Wextra -Werror -I. -o "$OUT/plane_check" \
        plane_check.c whisper_edge.c we_sha256.c we_counters.c
    "$CC" -std=c11 -O2 -Wall -Wextra -Werror -DWE_TRACE -I. -o "$OUT/test_trace" \
        test_trace.c we_writer.c whisper_edge.c we_sha256.c we_counters.c
}

# ---------------------------------------------------------------------------------------------------
# ONE FORMAT-2 PLANE, against the manifest object the builder wrote for it. Four assertions:
#
#   1. the file is the one the manifest describes: its sha256 equals the manifest's "sha256", and the
#      plane it names is the plane the file is installed as;
#   2. the reader loads it (every structural, domain and digest refusal applies) and finds exactly the
#      range counts the manifest states;
#   3. the reader answers every expected line, where there are expectations: plane_check --fields,
#      0 disagreements (the fixtures carry them; a real build is checked by 2 and 4, and by probes);
#   4. the lookup's measured maxima EQUAL the manifest's: the trace build enumerates every outcome
#      class of this very file (test_trace --file) and every per-family figure (maxProbes, depth,
#      maxColdLines, maxLines64, maxLines128, maxPages4k) and workingSetBytes must match exactly. The
#      manifest is the builder's cost model; the trace is the shipped lookup's reads. Equal, or the two
#      halves have drifted.
#
# check_plane <plane.bin> <manifest-object.json> <expected.txt or ""> <label>
check_plane() {
    local bin="$1" man="$2" exp="$3" label="$4" plane dir got_sha
    plane=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name",""))' "$man")
    if [ -z "$plane" ]; then
        echo "INTEROP GATE: FAILED - $label: the manifest object names no plane"
        return 1
    fi
    # staged under its own plane name, so the loader's name rule applies to it as on the edge
    dir="$OUT/format2/$label"
    mkdir -p "$dir"
    stage "$bin" "$dir/$plane.bin"

    got_sha=$(sha256sum "$bin" | cut -d' ' -f1)
    if ! python3 - "$man" "$got_sha" "$plane" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
if m.get("sha256") != sys.argv[2]:
    sys.exit("manifest sha256 %s, the file is %s" % (m.get("sha256"), sys.argv[2]))
if m.get("name") != sys.argv[3]:
    sys.exit("manifest names plane %r, the file is %s.bin" % (m.get("name"), sys.argv[3]))
PY
    then
        echo "INTEROP GATE: FAILED - $label: the manifest does not describe this file"
        return 1
    fi

    if ! "$OUT/plane_check" --dump "$dir/$plane.bin" > "$dir/$plane.dump" 2> "$dir/$plane.dump.err"; then
        cat "$dir/$plane.dump.err"
        echo "INTEROP GATE: FAILED - $label: the reader refused the file"
        return 1
    fi
    if ! python3 - "$man" "$dir/$plane.dump" "$label" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
want = m.get("records") or {}
v4 = v6 = 0
for line in open(sys.argv[2]):
    if line.startswith("4 "):
        v4 += 1
    elif line.startswith("6 "):
        v6 += 1
if (want.get("v4Ranges"), want.get("v6Ranges")) != (v4, v6):
    sys.exit("  the manifest states %s IPv4 + %s IPv6 ranges, the reader found %d + %d"
             % (want.get("v4Ranges"), want.get("v6Ranges"), v4, v6))
print("  %s: the reader loads it, %d IPv4 + %d IPv6 ranges as the manifest states" % (sys.argv[3], v4, v6))
PY
    then
        echo "INTEROP GATE: FAILED - $label: the range counts are not the manifest's"
        return 1
    fi

    if [ -n "$exp" ]; then
        if ! "$OUT/plane_check" --fields "$dir/$plane.bin" "$exp"; then
            echo "INTEROP GATE: FAILED - $label: the reader disagrees with the builder's expected answers"
            return 1
        fi
    fi

    if ! "$OUT/test_trace" "$OUT" --file "$dir/$plane.bin" > "$dir/$plane.trace"; then
        cat "$dir/$plane.trace"
        echo "INTEROP GATE: FAILED - $label: the trace build refused or failed on the file"
        return 1
    fi
    if ! python3 - "$man" "$dir/$plane.trace" "$label" <<'PY'
import json, re, sys
m = json.load(open(sys.argv[1]))
look = m.get("lookup")
if not isinstance(look, dict):
    sys.exit("  DISAGREE the manifest object carries no lookup block, so it publishes no bounds to check")
traced, ws = {}, None
for line in open(sys.argv[2]):
    mm = re.match(r"maxima v([46]) (.*)", line)
    if mm:
        fam = "v" + mm.group(1)
        traced[fam] = None if mm.group(2).strip() == "none" else \
            {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", mm.group(2))}
    mm = re.match(r"workingSetBytes=(\d+)", line)
    if mm:
        ws = int(mm.group(1))
bad = []
for fam in ("v4", "v6"):
    want, got = look.get(fam), traced.get(fam)
    if want is None:
        # the builder publishes no bounds for an empty or unindexed family
        if got is not None and got["kind"] != 0:
            bad.append("%s: the manifest has no lookup block, the file's family is indexed" % fam)
        continue
    if got is None:
        bad.append("%s: the manifest has a lookup block, the file's family is empty" % fam)
        continue
    for key in ("maxProbes", "depth", "maxColdLines", "maxLines64", "maxLines128", "maxPages4k"):
        w = want.get(key, 0)
        if w != got[key]:
            bad.append("%s %s: manifest %s, traced %s" % (fam, key, w, got[key]))
    print("  %s %s: maxProbes %d depth %d maxColdLines %d maxLines64 %d maxLines128 %d maxPages4k %d,"
          " manifest and trace equal over %d lookups" % (sys.argv[3], fam, got["maxProbes"], got["depth"],
          got["maxColdLines"], got["maxLines64"], got["maxLines128"], got["maxPages4k"], got["lookups"])
          if not [b for b in bad if b.startswith(fam)] else "")
if look.get("workingSetBytes") != ws:
    bad.append("workingSetBytes: manifest %s, traced %s" % (look.get("workingSetBytes"), ws))
if bad:
    sys.exit("\n".join("  DISAGREE " + b for b in bad))
print("  %s workingSetBytes %d: manifest and file equal" % (sys.argv[3], ws))
PY
    then
        echo "INTEROP GATE: FAILED - $label: the manifest's lookup bounds are not the lookup's measured ones"
        return 1
    fi
    CHECKED_PLANES="$CHECKED_PLANES $plane"
}
CHECKED_PLANES=""

# ---------------------------------------------------------------------------------------------------
# A FIXTURE MAKES NO CLAIM ABOUT A REAL NETWORK.
#
# Every line an expectations file marks as a HIT says "this address is listed", and these files are
# published. So every hit must be documentation space (RFC 5737, RFC 3849) or one of the end points of
# the address space the boundary cases need (the /32 or /128 at each end, and the /64 at each IPv6 end
# where a plane has 64-bit keys), and every origin AS a routing record names must be a documentation
# AS (RFC 5398), AS0 or the undetermined sentinel. A MISS asserts nothing about anybody and may sit
# anywhere, which is what lets a fixture probe the address one below a documentation range.
#
# The rule is checked rather than written down only, and the check carries its own control: a copy
# with one real address marked as a hit must be refused, or the check is decoration.
claims_in_documentation_space() {
    python3 - "$@" <<'PY'
import ipaddress, sys
DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                         "2001:db8::/32", "0.0.0.0/32", "255.255.255.255/32",
                                         "::/64", "ffff:ffff:ffff:ffff::/64")]
DOC_AS = set(range(64496, 64512)) | set(range(65536, 65552)) | {0, 4294967295}
bad = []
for path in sys.argv[1:]:
    routing = path.endswith("routing-expected.txt")
    for n, line in enumerate(open(path), 1):
        t = line.split()
        if len(t) < 3 or t[0] not in ("4", "6"):
            continue
        # format 1 (expected.txt): "family address severity label", 0 is no verdict;
        # format 2 (<plane>-expected.txt): "family address hit fields...", 1 is a hit
        if t[2] in ("0", "-"):
            continue
        a = ipaddress.ip_address(t[1])
        if not any(a.version == d.version and a in d for d in DOC):
            bad.append("%s:%d: %s is a hit outside documentation space" % (path, n, a))
        if routing and len(t) > 3 and int(t[3]) not in DOC_AS:
            bad.append("%s:%d: origin AS%s is not a documentation AS" % (path, n, t[3]))
if bad:
    print("\n".join("  CLAIM " + b for b in bad[:10]))
    if len(bad) > 10:
        print("  ... and %d more" % (len(bad) - 10))
    sys.exit(1)
PY
}

# ===================================================================================================
# THE BUILDER MODE: the planes a builder produced, on the disk it produced them on.
#
# The fixtures prove the format on files frozen in this tree. This proves it on the files a builder
# actually wrote, which is the claim a published bound makes: three places a plane can be found in a
# builder's edge directory, each with the manifest object the builder wrote beside it.
#
#   .stage/ready/<plane>-<walkid>/   a job's staged output, stage.json's "entry" and its "file"
#   withheld/<plane>/<walkid>/       a build the publisher holds back, laid out as the stage it came from
#   manifest.json + planes/<sha>     a committed format-2 plane, named by the plain sha256 of its bytes
#
# A place that does not exist yet is DARK, by name, with what lights it; it is never a pass. Once
# withheld/ exists the three planes the publisher withholds are REQUIRED (tor, routing,
# rpki-unreachable, or WHISPER_EDGE_REQUIRE), and a run that checked no plane at all fails.
#
# Probes: WHISPER_EDGE_PROBES=<file>, lines "<plane> <family> <address> <hit> <fields...>", the second
# half being a plane_check --fields line. Each plane checked runs its probes; a probe naming a plane
# that was never checked fails, because a probe that never ran proves nothing.
# ===================================================================================================
if [ -n "$BUILDER" ]; then
    echo "INTEROP GATE: builder mode over $BUILDER (the checked-in fixtures are the default mode's)"
    build_plane_tools
    DARK=0
    n=0

    probe_plane() { # <plane> <bin> <label>
        [ -n "${WHISPER_EDGE_PROBES:-}" ] || return 0
        local lines="$OUT/format2/$3/probes.txt"
        awk -v p="$1" '$1 == p { $1 = ""; sub(/^ /, ""); print }' "$WHISPER_EDGE_PROBES" > "$lines"
        [ -s "$lines" ] || return 0
        if ! "$OUT/plane_check" --fields "$OUT/format2/$3/$1.bin" "$lines"; then
            echo "INTEROP GATE: FAILED - $3: a probe from $WHISPER_EDGE_PROBES disagrees"
            return 1
        fi
        echo "  $3: $(grep -c . "$lines") probe(s) from $(basename "$WHISPER_EDGE_PROBES") agree"
    }

    # A stage directory: stage.json carries the manifest's plane object as "entry" and the file name.
    check_stage_dir() { # <dir> <label>
        local d="$1" label="$2" file
        if [ ! -f "$d/stage.json" ]; then
            echo "INTEROP GATE: FAILED - $label: $d holds no stage.json, so nothing describes the plane in it"
            return 1
        fi
        python3 - "$d/stage.json" "$OUT/format2/$label.entry.json" <<'PY' || return 1
import json, sys
s = json.load(open(sys.argv[1]))
if s.get("stageVersion") != 2:
    sys.exit("  %s: stageVersion %r is not the version this gate reads (2)" % (sys.argv[1], s.get("stageVersion")))
if not isinstance(s.get("entry"), dict) or not s.get("file"):
    sys.exit("  %s: no entry object or no file name" % sys.argv[1])
json.dump(s["entry"], open(sys.argv[2], "w"))
PY
        file=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' "$d/stage.json")
        mkdir -p "$OUT/format2"
        check_plane "$d/$file" "$OUT/format2/$label.entry.json" "" "$label" || return 1
        probe_plane "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' \
            "$OUT/format2/$label.entry.json")" "$d/$file" "$label" || return 1
        n=$((n + 1))
    }

    mkdir -p "$OUT/format2"
    shopt -s nullglob
    if [ -d "$BUILDER/.stage/ready" ]; then
        for d in "$BUILDER"/.stage/ready/*/; do
            check_stage_dir "${d%/}" "ready-$(basename "$d")" || exit 1
        done
    else
        echo "  DARK  .stage/ready/: no staged plane on this directory (lit by a plane job's first stage)"
        DARK=$((DARK + 1))
    fi
    if [ -d "$BUILDER/withheld" ]; then
        for d in "$BUILDER"/withheld/*/*/; do
            p=$(basename "$(dirname "$d")")
            check_stage_dir "${d%/}" "withheld-$p-$(basename "$d")" || exit 1
        done
        REQUIRE="${WHISPER_EDGE_REQUIRE:-tor routing rpki-unreachable}"
    else
        echo "  DARK  withheld/: the publisher has written no withheld build here (lit by its first commit;"
        echo "        then tor, routing and rpki-unreachable are required)"
        DARK=$((DARK + 1))
        REQUIRE="${WHISPER_EDGE_REQUIRE:-}"
    fi
    if [ -f "$BUILDER/manifest.json" ]; then
        python3 - "$BUILDER/manifest.json" "$OUT/format2" <<'PY' > "$OUT/format2/committed.list" || exit 1
import json, os, sys
m = json.load(open(sys.argv[1]))
planes = m.get("planes")
if not isinstance(planes, list):
    sys.exit("INTEROP GATE: FAILED - manifest.json carries no planes[] array")
for e in planes:
    if e.get("format") != 2:
        continue  # the format-1 reputation entry: its file is checked by the default mode's shape
    path = os.path.join(sys.argv[2], "committed-%s.entry.json" % e["name"])
    json.dump(e, open(path, "w"))
    print(e["name"], e["sha256"], path)
PY
        while read -r p sha entry; do
            if [ ! -f "$BUILDER/planes/$sha.bin" ]; then
                echo "INTEROP GATE: FAILED - committed-$p: manifest.json names planes/$sha.bin and it is not there"
                exit 1
            fi
            check_plane "$BUILDER/planes/$sha.bin" "$entry" "" "committed-$p" || exit 1
            probe_plane "$p" "$BUILDER/planes/$sha.bin" "committed-$p" || exit 1
            n=$((n + 1))
        done < "$OUT/format2/committed.list"
    else
        echo "  DARK  manifest.json: no committed manifest here (lit by the publisher's first commit)"
        DARK=$((DARK + 1))
    fi
    shopt -u nullglob

    for p in $REQUIRE; do
        case " $CHECKED_PLANES " in
            *" $p "*) ;;
            *) echo "INTEROP GATE: FAILED - the $p plane is required and none was found to check"; exit 1 ;;
        esac
    done
    if [ -n "${WHISPER_EDGE_PROBES:-}" ]; then
        while read -r p; do
            case " $CHECKED_PLANES " in
                *" $p "*) ;;
                *) echo "INTEROP GATE: FAILED - $WHISPER_EDGE_PROBES probes the $p plane and no $p plane was checked"
                   exit 1 ;;
            esac
        done < <(awk '!/^#/ && NF { print $1 }' "$WHISPER_EDGE_PROBES" | sort -u)
    fi
    if [ "$n" -eq 0 ]; then
        echo "INTEROP GATE: FAILED - no plane was found in $BUILDER, so nothing was checked"
        exit 1
    fi
    echo "INTEROP GATE: CLEAR - $n builder plane(s) (${CHECKED_PLANES# }): sha256, the reader, the range counts"
    echo "  and every manifest maximum equal to the traced one; $DARK place(s) DARK, named above"
    exit 0
fi

if [ ! -f "$FIX/interop.snap" ] || [ ! -f "$FIX/expected.txt" ]; then
    echo "INTEROP GATE: FAILED - no fixture at $FIX"
    echo "  Expected interop.snap and expected.txt. Set WHISPER_EDGE_FIXTURE to point elsewhere."
    exit 1
fi

"$CC" -std=c11 -O2 -Wall -Wextra -Werror -I. -o "$OUT/interop_check" \
    interop_check.c whisper_edge.c we_sha256.c

stage "$FIX/interop.snap" "$OUT/interop.snap"

"$OUT/interop_check" "$OUT/interop.snap" "$FIX/expected.txt"

# ---------------------------------------------------------------------------------------------------
# THE DISARMED SNAPSHOT: a valid snapshot with no entries, the shape the break-glass publishes.
#
# It carries a REAL validity bound rather than the zero that means "no bound", because zero skips the
# staleness check entirely and production always writes one - so a zero fixture would have left the
# one field that governs whether a reader enforces at all untested. The bound is far enough out that
# a checked-in fixture cannot start failing on the calendar, and the gate asserts the reader reports
# it as within its window, which is what proves the check ran rather than was skipped.
#
# This is its own check because the break-glass is the one publication that must always work, and its
# whole value is that an installed reader ADOPTS it: withdrawing the files would leave every install
# enforcing its last snapshot for the full 24-hour validity, so the kill switch publishes an EMPTY
# policy under a newer generation instead. If the reader refused an entry-less file for any structural
# reason - and it is 192 bytes, header only, with no index and no range arrays - the switch would fail
# silently at the worst possible moment.
#
# Asserted here rather than in the C suite because the C suite's fixtures are written by C. This one
# is written by the real builder, which is the half that could disagree.
if [ -f "$FIX/disarmed.snap" ]; then
    # whisper-edge-lookup, not interop_check: interop_check also asserts the fixture's EVIDENCE
    # expectations, and an empty snapshot carries none, so it would fail for the wrong reason.
    make -s whisper-edge-lookup >/dev/null
    DIS="$OUT/disarmed.txt"
    stage "$FIX/disarmed.snap" "$OUT/disarmed.snap"
    ./whisper-edge-lookup "$OUT/disarmed.snap" \
        1.1.1.1 8.8.8.8 192.0.2.1 198.51.100.200 0.0.0.0 255.255.255.255 \
        2001:db8::1 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff > "$DIS"
    # The tool's line form: the plane fresh (within its validity window) with no range in either family,
    # and nine decisions, every one an allow, none a deny or a would-deny. The old free-text form ("allow
    # no verdict") must be gone, so this check cannot pass against a stale build of the tool: its control
    # is the same check over the old tool's own capture of these nine probes, which it must refuse.
    disarmed_ok() {
        grep -qE '^plane reputation id=1 state=fresh .* ranges-v4=0 ranges-v6=0 ' "$1" \
            && [ "$(grep -c '^decision allow ' "$1")" = 9 ] \
            && ! grep -qE '^decision (deny|log) ' "$1" \
            && ! grep -q 'allow  no verdict' "$1"
    }
    if [ ! -s testdata/lookup/disarmed-old-form.txt ]; then
        echo "INTEROP GATE: FAILED - testdata/lookup/disarmed-old-form.txt, the old tool's capture, is missing or empty"
        exit 1
    fi
    if disarmed_ok testdata/lookup/disarmed-old-form.txt; then
        echo "INTEROP GATE: FAILED - the disarmed check passes the old tool's output, so it proves nothing"
        exit 1
    fi
    if disarmed_ok "$DIS"; then
        echo "INTEROP GATE: the disarmed (empty) snapshot loads and allows all 9 probes"
    else
        echo "INTEROP GATE: FAILED - the reader did not accept the disarmed snapshot, or denied something"
        cat "$DIS"
        exit 1
    fi
else
    echo "INTEROP GATE: FAILED - no disarmed.snap fixture at $FIX"
    echo "  The break-glass publishes an entry-less snapshot and this is the only check that a reader"
    echo "  accepts one. The fixture is checked in; if it is missing, this tree is incomplete rather"
    echo "  than misconfigured. Point the gate elsewhere with WHISPER_EDGE_FIXTURE=<dir>."
    exit 1
fi

# ---------------------------------------------------------------------------------------------------
# FORMAT 2: the Java builder's planes, read by the real reader and costed by the real lookup.
#
# testdata/format2/ holds, per plane, <plane>.bin as the builder wrote it, <plane>-expected.txt (every
# deciding address and the record the reader must return) and <plane>.manifest.json (the builder's
# manifest object for that plane), each held to the four assertions of check_plane above.
#
# Absent fixtures FAIL here, like the format-1 ones: routing, tor, the tenant planes and the feed-name escape
# fixture must all be present.
F2="$FIX/format2"
for plane in routing tor tenant tenant-w1 tenant-w64 tenant-w65 names; do
    for f in "$plane.bin" "$plane-expected.txt" "$plane.manifest.json"; do
        if [ ! -f "$F2/$f" ]; then
            echo "INTEROP GATE: FAILED - no format-2 fixture $F2/$f"
            echo "  The builder writes <plane>.bin, <plane>-expected.txt and <plane>.manifest.json for routing,"
            echo "  tor, the tenant planes and names; the interop gate holds the reader and the lookup's costs to them."
            exit 1
        fi
    done
done
for f in tenant-empty.bin tenant-empty.manifest.json tenant-full.txt names-full.txt; do
    if [ ! -f "$F2/$f" ]; then
        echo "INTEROP GATE: FAILED - no format-2 fixture $F2/$f"
        exit 1
    fi
done

build_plane_tools

# A plane whose manifest states no ranges at all has nothing to hit, so it carries no expectations file; every
# other plane must have one.
ranges_in() {
    python3 -c 'import json,sys; r=json.load(open(sys.argv[1])).get("records") or {}; print((r.get("v4Ranges") or 0)+(r.get("v6Ranges") or 0))' "$1"
}

f2_planes=0
F2_LABELS=""
for bin in "$F2"/*.bin; do
    plane=$(basename "$bin" .bin)
    man="$F2/$plane.manifest.json"
    exp="$F2/$plane-expected.txt"
    if [ ! -f "$man" ]; then
        echo "INTEROP GATE: FAILED - $bin has no $plane.manifest.json beside it"
        exit 1
    fi
    if [ ! -f "$exp" ]; then
        if [ "$(ranges_in "$man")" != 0 ]; then
            echo "INTEROP GATE: FAILED - $bin has ranges and no $plane-expected.txt beside it"
            exit 1
        fi
        exp=""
    fi
    check_plane "$bin" "$man" "$exp" "$plane" || exit 1
    f2_planes=$((f2_planes + 1))
    F2_LABELS="$F2_LABELS $plane"
done
echo "INTEROP GATE: $f2_planes format-2 plane(s): sha256, the reader, the range counts, every expected answer,"
echo "  and every manifest maximum equal to the traced one"

# ---------------------------------------------------------------------------------------------------
# THE DUMP IS AN INTERFACE. A deployed tool reads every line plane_check --dump prints as exactly four
# fields (family, first, last, flags), so a fifth field on that output would break it in production. Every
# fixture's --dump is held to four fields per line; --dump-full is the superset that carries the rest.
for label in $F2_LABELS; do
    for dump in "$OUT/format2/$label/"*.dump; do
        if ! awk 'NF != 4 { bad = 1 } END { exit bad }' "$dump"; then
            echo "INTEROP GATE: FAILED - plane_check --dump printed a line that is not four fields for $label"
            exit 1
        fi
    done
done
echo "INTEROP GATE: plane_check --dump prints four fields per line on every fixture, the interface it keeps"

# --dump-full, byte for byte: the header's generation, valid_until_ms, built_at_ms and tier, one escaped token
# per feed name, and each range with its source, against the text the builder's test computed from its inputs
# (tenant-full.txt) and the feed-name escape fixture (names-full.txt: a space and a newline inside a name, a
# literal backslash before x41, a plain A, two double quotes). A raw-byte dump would split the first name
# across two lines and print the second and third the same way, and an escape that passed the quote through
# would print the fourth as the empty name's "" token; each is a difference here.
for full in "$F2"/*-full.txt; do
    label=$(basename "$full" -full.txt)
    plane=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$F2/$label.manifest.json")
    if ! "$OUT/plane_check" --dump-full "$OUT/format2/$label/$plane.bin" 2>/dev/null | cmp -s - "$full"; then
        echo "INTEROP GATE: FAILED - plane_check --dump-full on $label is not $full:"
        "$OUT/plane_check" --dump-full "$OUT/format2/$label/$plane.bin" 2>/dev/null | diff - "$full" | sed -n '1,20p' || true # shown only; exit 1 follows
        exit 1
    fi
    echo "  $label: plane_check --dump-full equals $(basename "$full") byte for byte"
done

# ---------------------------------------------------------------------------------------------------
# THE TENANT PLANE'S TABLE IS A WRITER RULE (FORMAT.md section 3.3). The loader checks the feed-name table's
# structure only and no module decision reads its content, so the content rules are the writer's and the
# refresh's: count 3, entry 0 empty, entry 1 "tenant:" and the 16 lower-case hex digits of the tenant id,
# entry 2 "rev:" and a canonical decimal at most 2^63 - 1, source 1 on every record. Every builder fixture is
# held to it, against the id this gate derives on its own from the fixtures' documented owner, never read
# from the plane. The controls are planes the loader accepts and the rule refuses, re-digested so only the
# rule can refuse them: a leading zero in the rev, upper-case hex in the id, a record at source 2. Each must
# load (proving the loader does not enforce content, so no module decision may read it) and be refused.
TENANT_ID=$(python3 -c 'import hashlib; print(hashlib.sha256(b"whisper-edge-tenant-v1\x00user_edge_fixture").hexdigest()[:16])')
tenant_planes=0
for bin in "$F2"/tenant*.bin; do
    label=$(basename "$bin" .bin)
    if ! "$OUT/interop_check" --tenant "$OUT/format2/$label/tenant.bin" "$TENANT_ID"; then
        echo "INTEROP GATE: FAILED - $label breaks the tenant plane's writer rule"
        exit 1
    fi
    tenant_planes=$((tenant_planes + 1))
done
mkdir -p "$OUT/format2/tenant-controls"
for control in rev-leading-zero upper-case-id source-2; do
    cdir="$OUT/format2/tenant-controls/$control"
    mkdir -p "$cdir"
    python3 - "$F2/tenant.bin" "$cdir/tenant.bin" "$control" <<'PY'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
kind = sys.argv[3]
blob_off, blob_len = struct.unpack_from("<II", b, 92)
blob = bytes(b[blob_off:blob_off + blob_len])
if kind == "rev-leading-zero":
    i = blob.index(b"rev:") + 4
    b[blob_off + i] = ord("0")                   # same length, so no offset moves
elif kind == "upper-case-id":
    i = blob.index(b"tenant:") + 7
    b[blob_off + i:blob_off + i + 16] = blob[i:i + 16].upper()
    if blob[i:i + 16] == blob[i:i + 16].upper():
        sys.exit("the fixture id has no letter to upper-case; pick a fixture owner whose id has one")
else:
    rec = struct.unpack_from("<I", b, 136 + 12)[0]  # v4_record_off: the first IPv4 record
    b[rec + 4 + 4] = 2                            # end u32, flags u32, then source
hdr = bytes(b[:104]) + bytes(32) + bytes(b[136:192])
digest = hashlib.sha256(hdr + bytes(b[192:])).digest()
b[104:136] = digest
open(sys.argv[2], "wb").write(bytes(b))
PY
    chmod 0644 "$cdir/tenant.bin"
    if ! "$OUT/plane_check" --dump "$cdir/tenant.bin" > /dev/null 2>&1; then
        echo "INTEROP GATE: FAILED - the loader refused the $control control, so it does not prove the loader"
        echo "  leaves the table's content to the writer rule"
        exit 1
    fi
    if "$OUT/interop_check" --tenant "$cdir/tenant.bin" "$TENANT_ID" > /dev/null 2>&1; then
        echo "INTEROP GATE: FAILED - the writer-rule check accepted the $control control; it cannot say no"
        exit 1
    fi
done
echo "INTEROP GATE: $tenant_planes tenant plane(s) follow the writer rule for tenant $TENANT_ID; the loader accepts"
echo "  and the rule refuses each of its three controls (a leading-zero rev, an upper-case id, a source-2 record)"

# A single rank window. tenant-w64 holds 64 IPv4 and 32 IPv6 ranges, one window at each stride, which the
# format writes with depth 0, sample_count 1 and sample_off 0 (no separators); tenant-w65 holds one more of
# each and loads with its separators (both checked above). The control: the same single-window plane with an
# IPv4 sample_off that is not 0, re-digested so only the layout rule can refuse it, which the loader must.
cdir="$OUT/format2/tenant-controls/single-window-sample-off"
mkdir -p "$cdir"
python3 - "$F2/tenant-w64.bin" "$cdir/tenant.bin" <<'PY'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
if struct.unpack_from("<I", b, 156)[0] != 0 or struct.unpack_from("<I", b, 164)[0] != 1:
    sys.exit("tenant-w64's IPv4 family is not a single window with sample_off 0; the control cannot be made")
struct.pack_into("<I", b, 156, 192)
hdr = bytes(b[:104]) + bytes(32) + bytes(b[136:192])
b[104:136] = hashlib.sha256(hdr + bytes(b[192:])).digest()
open(sys.argv[2], "wb").write(bytes(b))
PY
chmod 0644 "$cdir/tenant.bin"
if "$OUT/plane_check" --dump "$cdir/tenant.bin" > /dev/null 2>&1; then
    echo "INTEROP GATE: FAILED - the loader accepted a single-window rank family with a non-zero sample_off"
    exit 1
fi
echo "INTEROP GATE: a single-window rank family with a non-zero sample_off is refused by the loader (the control)"

# The claims: every hit in every expectations file is documentation space, and the control first.
CTRL="$OUT/claims-control-expected.txt"
{ cat "$F2/tor-expected.txt"; echo "4 8.8.8.8 1 1 1 0"; } > "$CTRL"
if claims_in_documentation_space "$CTRL" >/dev/null; then
    echo "INTEROP GATE: FAILED - the documentation-space check accepted a real address marked as a hit;"
    echo "  it cannot say no, so its pass below would mean nothing"
    exit 1
fi
if ! claims_in_documentation_space "$FIX/expected.txt" "$F2"/*-expected.txt; then
    echo "INTEROP GATE: FAILED - a published fixture lists an address or an AS outside documentation space"
    exit 1
fi
echo "INTEROP GATE: every hit in every expectations file is documentation space (and the check refuses a"
echo "  real address, its control)"

echo "INTEROP GATE: CLEAR - format 1, the disarmed snapshot, and every format-2 plane"
