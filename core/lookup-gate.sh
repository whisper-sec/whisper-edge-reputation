#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# lookup-gate.sh - the gate for whisper-edge-lookup, run by `make check-lookup` (part of `make check`).
#
# Every row of the lookup tool's test matrix that this tree can run is here, each with the negative
# control that shows it can fail: a mutant build of the tool (or of the manifest reader, or of
# plane_check) planted with one defect, which must fail the row it names, or a planted input. A mutant
# that no row catches fails the gate. The mutant table and the sweep's counts come from lookup-states.py,
# never from this file.
#
# The differential (O1, O3, O4, L2 and the W rows that name it) holds the tool's verdict, cost, report,
# dependents and attribute lines to both evaluators', policy_ref.py --attrs and test_policy --attrs, over
# the gate's own restatement of every request (lookup-states.py), with the records make-test-snapshot.py
# packed, never the tool's.
#
# Usage: lookup-gate.sh <work-dir>
# Prints one summary line: N checks, F failures, I invocations, C cases, M mutant compiles.
# python3 absent is a failure, never a skip.
set -uo pipefail
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }
umask 022

cd "$(dirname "$0")" || exit 1
CORE=$PWD
OUT=${1:-$CORE/.testtmp/lookup}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
# The tool reports each plane by the module's own bind verdict, and the bind walks every directory above a
# plane (owned by root or this uid, writable by neither group nor world, no sticky exception). A run under
# a tree that fails the walk would read every plane refused, so the run moves to the first of HOME, the
# runtime directory and /run/user/<uid> that passes, judged by the shipped tool on a 0444 plane, and says
# so. None passing leaves it where it was, and the rows fail by name.
OUT_GIVEN=$OUT RELOCATED=
ot_trusted() {
    local t=$1/.trust-probe
    rm -rf "$t" && mkdir -p "$t" && chmod 755 "$1" "$t" \
        && cp "$CORE/testdata/format2/tor.bin" "$t/tor.bin" && chmod 444 "$t/tor.bin" \
        && timeout 60 "$CORE/whisper-edge-lookup" --probe-dir "$t" 2>/dev/null | grep_any '^  plane tor  *state=present '
    local rc=$?
    rm -rf "$t"
    return $rc
}
if [ -x "$CORE/whisper-edge-lookup" ] && ! ot_trusted "$OUT"; then
    for c in "${HOME:-}" "${XDG_RUNTIME_DIR:-}" "/run/user/$(id -u)"; do
        [ -n "$c" ] && [ -d "$c" ] && [ -w "$c" ] || continue
        if mkdir -p "$c/we-lookup-gate.$$" 2>/dev/null && ot_trusted "$c/we-lookup-gate.$$"; then
            OUT=$c/we-lookup-gate.$$ RELOCATED=1
            echo "work directory: $OUT (the given $OUT_GIVEN fails the planes' trust walk)"
            break
        fi
        rm -rf "$c/we-lookup-gate.$$"
    done
fi
CC=${CC:-cc}
read -ra CFL <<< "${CFLAGS:--std=c11 -O2 -Wall -Wextra -Werror}"
TOOLFLAGS=(-DWE_TRACE -DWE_LOOKUP_TOOL)
SANFLAGS=()
san_probe=$(mktemp -d)
printf 'int main(void){return 0;}' > "$san_probe/p.c"
NO_SAN_DARK=
if "$CC" -fsanitize=address,undefined -o "$san_probe/p" "$san_probe/p.c" 2>/dev/null; then
    SANFLAGS=("-fsanitize=address,undefined" -fno-sanitize-recover=all)
else
    NO_SAN_DARK="W11 W12 J4 ran without ASan and UBSan: this compiler cannot build them"
fi
rm -rf "$san_probe"

if ! command -v python3 >/dev/null 2>&1; then
    echo "CHECK FAIL: lookup-gate needs python3; a missing interpreter is a failure, not a skip"
    exit 1
fi

N=0 F=0 I=0 C=0 M=0
MODE=normal
RF=0

ok()  { if [ "$MODE" = normal ]; then N=$((N + 1)); fi; }
bad() { if [ "$MODE" = normal ]; then N=$((N + 1)); F=$((F + 1)); echo "FAIL $*"; else RF=$((RF + 1)); fi; }
# a <description> <command...>: one check
a() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok; else bad "$d"; fi; }
has()   { grep -qF -- "$2" "$1"; }
not()   { ! "$@"; }
hasre() { grep -qE -- "$2" "$1"; }
lacks() { ! grep -qF -- "$2" "$1"; }
eq()    { [ "$1" = "$2" ]; }
count() { grep -cF -- "$2" "$1"; }

# L <name> <args...>: one run of the tool under test ($T) in $W; status in RC. In the normal phase every
# run that printed a document is run again with --json and the two forms checked against each other (J1).
# A run with no --now of its own is given one fixed instant, so its two forms are one evaluation.
# 2026-10-11T00:30Z, inside the writer reputation plane's validity (it is valid until 2026-10-12T00:00Z)
NOWFIX=1791678600000
L() {
    local name=$1; shift
    case " $* " in *" --now "*|*" --now="*) ;; *) set -- --now "$NOWFIX" "$@" ;; esac
    [ "$MODE" = normal ] && I=$((I + 1))
    timeout 60 "$T" "$@" > "$W/$name.out" 2> "$W/$name.err"
    RC=$?
    if [ "$MODE" = normal ]; then
        local n
        n=$(sed -n 's/^whisper-edge-lookup: \([0-9]*\) address.*/\1/p' "$W/$name.err" | tail -1)
        C=$((C + ${n:-0}))
    fi
    case " $* " in
        *" --fields "*)
            python3 lookup-check.py lines "$W/$name.out" > "$W/$name.doc" 2>&1
            a "J1 $name: a --fields line outside its grammar: $(grep -m1 FAIL "$W/$name.doc")" \
                grep -q '^[0-9]* checks, 0 failures$' "$W/$name.doc"
            return ;;
    esac
    if [ "${JPAIR:-1}" = 1 ] && [ -s "$W/$name.out" ]; then
        [ "$MODE" = normal ] && I=$((I + 1))
        timeout 60 "$T" --json "$@" > "$W/$name.json" 2>/dev/null
        local drc=0
        python3 lookup-check.py doc "$W/$name.json" "$W/$name.out" > "$W/$name.doc" 2>&1 || drc=$?
        a "J1 $name: the two forms disagree: $(grep -m1 FAIL "$W/$name.doc")" test "$drc" -eq 0
    fi
}

mkd() { mkdir -p "$1"; chmod 755 "$1"; }
# sev4 [<generator mutant>]: every reputation address the differential uses is a critical listing; the
# generator must name exactly two, so an empty or failed answer is a failure, not a pass
sev4() {
    local xs x
    xs=$(LOOKUP_STATES_MUTANT=${1:-} python3 lookup-states.py oaddrs "$P") || return 1
    read -ra x <<< "$xs"
    [ "${#x[@]}" = 2 ] || return 1
    for x in "${x[@]}"; do
        awk -v a="$x" '$2 == a && $4 == "sev=4" { f = 1 } END { exit !f }' "$P/reputation.expect" || return 1
    done
}
# in_block <file> <address input> <line>: the line sits in that address's block, before the next address
in_block() {
    awk -v a="address $2 " -v w="$3" 'index($0, "address ") == 1 { inb = index($0, a) == 1 } inb && $0 == w { f = 1 }
        END { exit !f }' "$1"
}
# four decimals, as ocounts prints them
counts4() { [[ $1 =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; }
# refused_with <plane> <out> <reason>: the plane line is refused and its detail begins with the reason, as text
refused_with() {
    local line
    line=$(grep "^plane $1 id=[0-9] state=refused " "$2")
    [ -n "$3" ] && [[ $line == *"refused-detail=\"$3: "* ]]
}
# the count file the shim wrote (the first, if a broken run made several), and how many there are
cntfile() { local f; for f in "$W"/cnt.*; do [ -e "$f" ] && { echo "$f"; return; }; done; echo "$W/no-count-file"; }
cntn() { local f n=0; for f in "$W"/cnt.*; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
# each row starts from an empty directory in every phase: its fixtures are 0444, as the module maps them, so
# a pass that copied onto the last pass's files would fail on the copy, not on what the row checks
row() { W=$OUT/$MODE/$1; rm -rf "$W"; mkd "$W"; }

# ---- fixtures, made once ---------------------------------------------------------------------------------
FX=$OUT/fx
rm -rf "$OUT/normal" "$OUT/mutant" "$FX"
mkd "$FX"
# no configuration of the host's reaches a run: no /etc/whisper-edge/policy.conf, no server drop-in
mkd "$FX/etc-empty"
export WHISPER_EDGE_ETC=$FX/etc-empty
P=$FX/planes
PV=$FX/planes-vu
mkd "$P"; mkd "$PV"
V=1791878400000
w() {
    python3 make-test-snapshot.py --plane "$1" --out "$P/$1.bin" --format "$2" --v4-index "$3" --v6-index "$4" \
        "${@:5}" --expect "$P/$1.expect" > /dev/null
    python3 make-test-snapshot.py --plane "$1" --out "$PV/$1.bin" --format "$2" --v4-index "$3" --v6-index "$4" \
        "${@:5}" --valid-until "$V" > /dev/null
}
w reputation 1 radix-16 radix-16 --schema
w tor 2 radix-12 rank
w rpki-unreachable 2 radix-16 none
w routing 2 radix-18 rank
w anonymizer 2 rank radix-18
w threat 2 none radix-16
w registry 2 radix-16 rank
w tenant 2 rank rank
# the manifests: the writer's own (testdata/lookup/writer/, written by the real publisher and composer), and
# one-edit derivations of them
WR=$CORE/testdata/lookup/writer
python3 lookup-check.py derive "$WR" "$P/tor.bin" "$FX/derived" > /dev/null
python3 make-test-snapshot.py --sweep "$FX/sweep" > /dev/null
chmod -R go-w "$FX"
# every plane the fixtures hold is 0444, the only mode the module maps: the tool reports a plane by the
# module's own bind verdict, so a 0644 fixture would read refused (rows that plant a mode say so)
find "$FX" -name '*.bin' -type f -exec chmod 444 {} +
B=$FX/builder
mkd "$B"
cp testdata/format2/routing.bin testdata/format2/tor.bin "$B/"
chmod 444 "$B"/*.bin
cp testdata/interop.snap "$FX/interop.snap"; chmod 644 "$FX/interop.snap"
cp testdata/disarmed.snap "$FX/disarmed.snap"; chmod 644 "$FX/disarmed.snap"
# the first address each plane lists, IPv4, outside 0.0.0.0/8 (which the hold-harmless set holds, so step
# 1 would decide every request on it); the tenant's carries the allow flag, so a GRACE plane decides
hit() { awk '$3 != "-" && $1 == "4" && $2 !~ /^0\./ { print $2; exit }' "$P/$1.expect"; }
REP4=$(hit reputation)
TOR4=$(hit tor)
TEN4=$(awk '$3 != "-" && $1 == "4" && $2 !~ /^0\./ && $5 ~ /^fields=flags=[13],/ { print $2; exit }' "$P/tenant.expect")
# an address no tenant range holds, outside the hold-harmless set
TMISS=$(awk '$3 == "-" && $1 == "4" && $2 !~ /^0\./ { print $2; exit }' "$P/tenant.expect")
# a data directory: mkdata <dir> <manifest|-> <plane>...
mkdata() {
    local d=$1 m=$2; shift 2
    rm -rf "$d"; mkd "$d"
    # reputation is always the writer's own plane, which every derived manifest names by its digest
    for p in "$@"; do
        if [ "$p" = reputation ]; then cp "$WR/keyless/reputation.bin" "$d/"; else cp "$P/$p.bin" "$d/"; fi
        chmod 444 "$d/$p.bin"
    done
    if [ "$m" != - ]; then cp "$FX/derived/$m" "$d/manifest.json"; chmod 644 "$d/manifest.json"; fi
}
# the shim and its probe
"$CC" "${CFL[@]}" -shared -fPIC -o "$FX/lookup_shim.so" lookup_shim.c -ldl
"$CC" "${CFL[@]}" -DLOOKUP_SHIM_PROBE -o "$FX/shim_probe" lookup_shim.c
# the tool under the sanitizers, the manifest reader's replay, plane_check
TOOL=$CORE/whisper-edge-lookup
"$CC" "${CFL[@]}" "${SANFLAGS[@]}" "${TOOLFLAGS[@]}" -o "$FX/lookup_san" we_lookup_cli.c whisper_edge.c we_sha256.c \
    we_counters.c we_policy.c we_module.c
# the module's own bind of a data directory, for --probe-dir's agreement row (T2)
"$CC" "${CFL[@]}" -o "$FX/plane_bind_probe" plane_bind_probe.c we_module.c whisper_edge.c we_sha256.c we_counters.c we_policy.c
# the C evaluator's side of the differential
"$CC" "${CFL[@]}" -DWE_TRACE -o "$FX/test_policy" test_policy.c we_writer.c whisper_edge.c we_sha256.c we_counters.c we_policy.c
# the tool's other units, compiled once with the shipped rule's flags: every build of the tool
# the gate makes, a mutant's or a planted one's, links these
MO=$OUT/mutant/obj; mkd "$MO"
TOOLOBJ=$MO/units; mkd "$TOOLOBJ"
for src in whisper_edge we_sha256 we_counters we_policy we_module; do
    "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -c -o "$TOOLOBJ/$src.o" $src.c
done
# the differential's directories: 1,000 invocations over the 22 programs (lookup-states.py build)
python3 lookup-states.py build "$P" "$PV" "$FX/o1" > /dev/null
"$CC" -std=c11 -O1 -g -fno-omit-frame-pointer -Wall -Wextra -Werror "${SANFLAGS[@]}" -o "$FX/fuzz_manifest" \
    fuzz_manifest.c whisper_edge.c we_sha256.c we_counters.c
"$CC" "${CFL[@]}" -o "$FX/plane_check" plane_check.c whisper_edge.c we_sha256.c we_counters.c
PC=$FX/plane_check
FM=$FX/fuzz_manifest
python3 lookup-check.py seeds "$FX/seeds" > /dev/null

# ======================================================================================================
# L1, L3: the attributes' raw records against both writers and the reader
# ======================================================================================================
rowL1() {
    row L1
    local p
    for p in reputation tor rpki-unreachable routing anonymizer threat registry tenant; do
        mapfile -t addrs < <(awk '{print $2}' "$P/$p.expect")
        JPAIR=0 L "fields-$p" --fields --dir "$P" "${addrs[@]}"
        grep "^expect $p " "$W/fields-$p.out" | cut -d' ' -f3- > "$W/$p.expect"
        a "L1 $p: the tool's --expect lines byte-equal the writer's" cmp -s "$W/$p.expect" "$P/$p.expect"
        grep "^fields $p " "$W/fields-$p.out" | cut -d' ' -f3- > "$W/$p.fields"
        "$PC" --fields "$P/$p.bin" "$W/$p.fields" > "$W/$p.pc" 2>&1
        a "L1 $p: plane_check --fields over the tool's lines, 0 disagreements" test $? -eq 0
        a "L1 $p: plane_check's line count equals the tool's" \
            hasre "$W/$p.pc" " $(wc -l < "$P/$p.expect") lines, .* 0 disagreements$"
    done
    # the format-1 severity sweep: every sev byte 0..255, with its raw value
    mapfile -t addrs < <(awk '{print $2}' "$FX/sweep/in-domain/reputation.expect")
    JPAIR=0 L fields-sev --fields --dir "$FX/sweep/in-domain" "${addrs[@]}"
    grep "^expect reputation " "$W/fields-sev.out" | cut -d' ' -f3- > "$W/sev.expect"
    a "L1 sev sweep: the tool's --expect lines equal the writer's" cmp -s "$W/sev.expect" "$FX/sweep/in-domain/reputation.expect"
    # every listed hit's record and drop on the attr line, against the writer's severity byte
    JPAIR=0 L attr-sev --dir "$FX/sweep/in-domain" --now 1 "${addrs[@]}"
    a "L1 sev sweep: every listed hit's record and drop equal the writer's byte" python3 - "$W/attr-sev.out" \
        "$FX/sweep/in-domain/reputation.expect" <<'PY'
import sys
sev = {}
for line in open(sys.argv[2]):
    f = line.split()
    if f[2] != "-":
        sev[f[1]] = int(f[3].split("=")[1])
cur, bad, n = None, 0, 0
for line in open(sys.argv[1]):
    if line.startswith("address "):
        cur = line.split()[1]
    elif line.startswith("attr listed ") and cur in sev:
        kv = dict(t.split("=", 1) for t in line.split()[3:] if "=" in t)
        n += 1
        bad += kv.get("record") != '"sev=%d"' % sev[cur] or (kv.get("drop") == "yes") != bool(sev[cur] & 0x40)
sys.exit(0 if n == len(sev) and bad == 0 else 1)
PY
}

rowL3() {
    row L3
    local p
    for p in routing tor; do
        mapfile -t addrs < <(awk '{print $2}' "testdata/format2/$p-expected.txt")
        JPAIR=0 L "fields-$p" --fields --dir "$B" "${addrs[@]}"
        grep "^fields $p " "$W/fields-$p.out" | cut -d' ' -f3- > "$W/$p.fields"
        "$PC" --fields "$B/$p.bin" "$W/$p.fields" > "$W/$p.pc" 2>&1
        a "L3 $p: plane_check --fields over the tool's lines" test $? -eq 0
        a "L3 $p: the tool's fields lines equal the Java builder's, address spelling aside" python3 - \
            "$W/$p.fields" "testdata/format2/$p-expected.txt" <<'PY'
import ipaddress, sys
def norm(path):
    out = []
    for line in open(path):
        f = line.split()
        f[1] = str(ipaddress.ip_address(f[1]))
        out.append(" ".join(f))
    return out
sys.exit(0 if norm(sys.argv[1]) == norm(sys.argv[2]) else 1)
PY
    done
}

# ======================================================================================================
# L2: the domain sweep, its states and its counts
# ======================================================================================================
rowL2() {
    row L2
    local li=0 lc=0 name plane addr
    python3 - "$FX/sweep/in-domain" > "$W/in.addrs" <<'PY'
import sys
d = sys.argv[1]
for p in ("reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"):
    seen = set()
    for line in open("%s/%s.expect" % (d, p)):
        fam, addr, ans = line.split()[:3]
        if ans != "-" and (fam, ans) not in seen:
            seen.add((fam, ans))
            print(addr)
PY
    mapfile -t addrs < "$W/in.addrs"
    local all="anonymizer=fresh,registry=fresh,reputation=fresh,routing=fresh,rpki-unreachable=fresh,tenant=fresh,threat=fresh,tor=fresh"
    plan "$W/in.tsv" "$(pline in-domain "$FX/sweep/in-domain" sugar:high:log http "$NOWFIX" plain "$all" "$FX/sweep/in-domain" "${addrs[*]}")"
    runplan "$W/in.tsv" "$W/t"
    judgeplan "L2 in-domain" "$W/in.tsv" "$W/t" "$W/cache"
    cp "$W/t/in-domain.out" "$W/in-domain.out"
    li=$((li + 1)); lc=$((lc + ${#addrs[@]}))
    a "L2: every in-domain plane state=fresh" eq "$(grep -c '^plane .* state=fresh' "$W/in-domain.out")" 8
    # registry_country and registry_rir read the registry plane: with routing gone they keep their values
    mkd "$W/noroute"; cp "$FX/sweep/in-domain/"*.bin "$W/noroute/"; rm -f "$W/noroute/routing.bin"
    mapfile -t raddrs < <(awk '$3 != "-" && $5 ~ /country=[1-9]/ { print $2 }' "$FX/sweep/in-domain/registry.expect" | head -20)
    plan "$W/nr.tsv" "$(pline noroute "$W/noroute" sugar:high:log http "$NOWFIX" plain \
        "anonymizer=fresh,registry=fresh,reputation=fresh,rpki-unreachable=fresh,tenant=fresh,threat=fresh,tor=fresh" "$FX/sweep/in-domain" "${raddrs[*]}")"
    runplan "$W/nr.tsv" "$W/tnr"
    judgeplan "L2 registry without routing" "$W/nr.tsv" "$W/tnr" "$W/cache-nr"
    a "L2: registry_country definite with routing absent" grep -qE '^attr registry_country [A-Z]{2} plane=registry ' "$W/tnr/noroute.out"
    while read -r kind name plane _ _ _ addr; do
        [ "$kind" = refused ] || continue
        JPAIR=0 L "r-$name" --dir "$FX/sweep/$name" "$addr"
        li=$((li + 1)); lc=$((lc + 1))
        "$PC" "$FX/sweep/$name/$plane.bin" /dev/null > /dev/null 2> "$W/r-$name.pc"
        # the loader's own words, anchored on its fixed suffix (a reason may hold commas and parentheses)
        local what
        what=$(sed -n 's/.* a schema field outside its domain (\(.*\), family [46], record [0-9]*)$/\1/p' "$W/r-$name.pc")
        a "L2 $name: plane_check names the loader's reason" test -n "$what"
        a "L2 $name: state=refused with the loader's reason" refused_with "$plane" "$W/r-$name.out" "$what"
    done < "$FX/sweep/sweep.txt"
    read -r want_i want_c _ < <(python3 lookup-states.py l2)
    a "L2: $li invocations, lookup-states.py derives $want_i" eq "$li" "$want_i"
    a "L2: $lc cases, lookup-states.py derives $want_c" eq "$lc" "$want_c"
    a "L2: the writer's sweep.txt totals equal lookup-states.py's" has "$FX/sweep/sweep.txt" \
        "totals in-domain-v4 $(python3 lookup-states.py l2 | cut -d' ' -f3) in-domain-v6 $(python3 lookup-states.py l2 | cut -d' ' -f4) refused 40"
}

# ======================================================================================================
# W rows: UNKNOWN, the planes' states, the manifests and the directory
# ======================================================================================================
rowW1() {
    row W1
    L at-vu --dir "$PV" --now $V "$REP4" "$TOR4"
    a "W1: every plane fresh at valid_until" eq "$(grep -c '^plane .* state=fresh' "$W/at-vu.out")" 8
    L past-vu --dir "$PV" --now $((V + 1)) "$REP4"
    a "W1: every plane stale at valid_until + 1" eq "$(grep -c '^plane .* state=stale' "$W/past-vu.out")" 8
    a "W1: a stale plane's attribute UNKNOWN why=stale" has "$W/past-vu.out" "attr listed UNKNOWN plane=reputation why=stale"
    a "W1: a stale tenant plane in its grace" has "$W/past-vu.out" "attr tenant_allow UNKNOWN plane=tenant why=grace:47"
    L vu0 --dir "$P" --now 9999-12-31T23:59:59.999Z "$REP4"
    a "W1: valid_until 0 is fresh at the last instant: state=fresh valid-until=none" \
        eq "$(grep -c '^plane .* state=fresh .*valid-until=none' "$W/vu0.out")" 8
    a "W1: at valid_until the values are definite" grep -qE '^attr listed (low|medium|high|critical) plane=reputation range=' "$W/at-vu.out"
    a "W1: at valid_until 0 the values are definite" grep -qE '^attr listed (low|medium|high|critical) plane=reputation range=' "$W/vu0.out"
    local all="anonymizer=fresh,registry=fresh,reputation=fresh,routing=fresh,rpki-unreachable=fresh,tenant=fresh,threat=fresh,tor=fresh"
    plan "$W/p.tsv" \
        "$(pline at "$PV" "$CORE/testdata/policy/accept/03-every-boolean.policy" http/server:a "$V" plain "${all/tenant=fresh/tenant=fresh@$V}" "$P" "$REP4 $TOR4 $TEN4")" \
        "$(pline past "$PV" "$CORE/testdata/policy/accept/03-every-boolean.policy" http/server:a $((V + 1)) plain "${all//fresh/stale}" "$P" "$REP4 $TOR4 $TEN4")" \
        "$(pline zero "$P" "$CORE/testdata/policy/accept/03-every-boolean.policy" http/server:a 253402300799999 plain "$all" "$P" "$REP4 $TOR4 $TEN4")"
    runplan "$W/p.tsv" "$W/t"
    judgeplan W1 "$W/p.tsv" "$W/t" "$W/cache"
}

rowW2() {
    row W2
    mkdata "$W/a" base.json reputation
    L a --dir "$W/a" "$REP4"
    a "W2: absent and withheld, every reason the writer gave" has "$W/a.out" \
        "plane tor id=2 state=absent manifest=unbound why=absent,withheld:LOW_RECALL,withheld:IPV6_NOT_STATED"
    a "W2: absent, withheld and keyed" has "$W/a.out" \
        "why=absent,withheld:BGP_CLOCK_UNKNOWN,withheld:UNPINNED,withheld:VRP_CAP_UNSET,keyed"
    a "W2: the attribute carries the withhold reasons" has "$W/a.out" \
        "attr tor_exit UNKNOWN plane=tor why=absent,withheld:LOW_RECALL,withheld:IPV6_NOT_STATED"
    a "W2: two reasons on the withheld line" has "$W/a.out" "withheld tor reasons=LOW_RECALL,IPV6_NOT_STATED reason=LOW_RECALL"
    a "W2: the writer's nulls print not-stated" has "$W/a.out" "last-published-valid-until=not-stated from=keyless"
    a "W2: no UNKNOWN carries a range, record, evidence or drop" lacks "$W/a.out" "UNKNOWN plane=tor range="
    mkdata "$W/b" tor-withheld-only.json reputation
    L b --dir "$W/b" "$REP4"
    a "W2: absent and not named by its own tier's manifest" has "$W/b.out" "plane rpki-unreachable id=3 state=absent manifest=unbound why=absent,not-published"
    mkdata "$W/c" - reputation
    L c --dir "$W/c" "$REP4"
    a "W2: absent with no manifest, nothing after it" hasre "$W/c.out" "^plane tor id=2 state=absent manifest=unbound why=absent$"
    mkdata "$W/d" withheld-one-reason.json reputation
    L d --dir "$W/d" "$REP4"
    a "W2: one reason, one member" hasre "$W/d.out" "^plane tor id=2 state=absent manifest=unbound why=absent,withheld:LOW_RECALL feed=withheld:LOW_RECALL$"
    local wr
    for wr in invalid empty null; do
        mkdata "$W/r-$wr" "withheld-reasons-$wr.json" reputation
        L "r-$wr" --dir "$W/r-$wr" "$REP4"
        a "W2: reasons $wr: the plane is still withheld" has "$W/r-$wr.out" \
            "plane tor id=2 state=absent manifest=unbound why=absent,withheld:not-stated feed=withheld:not-stated"
    done
    mkdata "$W/e" base.json tor
    L e --dir "$W/e" "$REP4"
    a "W2: a manifest entry is never used for an absent plane" \
        hasre "$W/e.out" "^plane reputation id=1 state=absent manifest=unbound why=absent feed=published$"
}

rowW3() {
    row W3
    local d=$W/d
    mkdata "$d" - tor rpki-unreachable anonymizer
    cp "$P/reputation.bin" "$d/"; chmod 664 "$d/reputation.bin"
    head -c -10 "$P/tenant.bin" > "$d/tenant.bin"; chmod 444 "$d/tenant.bin"
    rm -f "$d/anonymizer.bin"
    python3 -c "import sys; b=bytearray(open(sys.argv[1],'rb').read()); b[104]^=1; open(sys.argv[2],'wb').write(b)" \
        "$P/anonymizer.bin" "$d/anonymizer.bin"
    chmod 444 "$d/anonymizer.bin"
    ln -s "$d/no-such-file.bin" "$d/threat.bin"
    ln -s "$d/registry.bin" "$d/registry.bin"
    mkd "$W/elsewhere"; cp "$P/rpki-unreachable.bin" "$W/elsewhere/r.bin"; rm -f "$d/rpki-unreachable.bin"
    ln -s "$W/elsewhere/r.bin" "$d/rpki-unreachable.bin"
    cp "$P/routing.bin" "$d/routing.bin"
    L a --dir "$d" "$REP4"
    a "W3: a 0664 plane refused=mode, present" has "$W/a.out" "plane reputation id=1 state=refused file=reputation.bin manifest=unbound why=refused:mode"
    a "W3: its attributes UNKNOWN" has "$W/a.out" "attr listed UNKNOWN plane=reputation why=refused:mode"
    a "W3: exit 0" eq "$RC" 0
    a "W3: a truncated plane refused" has "$W/a.out" "plane tenant id=8 state=refused file=tenant.bin manifest=unbound why=refused:truncated"
    a "W3: a bad digest refused" has "$W/a.out" "plane anonymizer id=5 state=refused file=anonymizer.bin manifest=unbound why=refused:digest"
    a "W3: a dangling symlink inert at config" has "$W/a.out" "plane threat id=6 state=refused file=threat.bin manifest=unbound why=refused:open,inert-at-config"
    a "W3: a self-loop symlink inert at config" has "$W/a.out" "plane registry id=7 state=refused file=registry.bin manifest=unbound why=refused:open,inert-at-config"
    # the module opens a plane without following a link, so a link to a fresh plane is refused, as it is there
    a "W3: a symlink to a fresh plane is refused, as the module refuses a link" has "$W/a.out" \
        "plane rpki-unreachable id=3 state=refused file=rpki-unreachable.bin manifest=unbound why=refused:trust"
    plan "$W/p.tsv" "$(pline w3 "$d" "$CORE/testdata/policy/accept/03-every-boolean.policy" http/server:a "$NOWFIX" plain \
        "anonymizer=refused,reputation=refused,routing=fresh,rpki-unreachable=refused,tenant=refused,tor=fresh" "$P" "$REP4 $TOR4")"
    runplan "$W/p.tsv" "$W/t"
    judgeplan "W3: refused present planes stale, the symlinks absent" "$W/p.tsv" "$W/t" "$W/cache"
    # a uid that cannot read the plane: every open of it fails with EACCES (the probe, the load, the module's
    # check with its own probe, header peek and trust open, the second probe: 1 to 6), then the load alone
    # succeeding (all but 2)
    local at
    for at in 1,2,3,4,5,6 1,3,4,5,6; do
        rm -f "$W/cnt".*
        [ "$MODE" = normal ] && I=$((I + 1))
        timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$d/routing.bin" LOOKUP_SHIM_FAIL_PATH="$d/routing.bin" \
            LOOKUP_SHIM_FAIL_AT=$at LOOKUP_SHIM_FAIL_ERRNO=EACCES LOOKUP_SHIM_OUT="$W/cnt" "$T" --dir "$d" "$REP4" > "$W/perm-$at.out" 2>/dev/null
        a "W3 EACCES at $at: refused=permission, uid-dependent" has "$W/perm-$at.out" \
            "plane routing id=4 state=refused file=routing.bin manifest=unbound why=refused:permission,uid-dependent"
        a "W3 EACCES at $at: the note" has "$W/perm-$at.out" "routing: whether the module arms these rules depends on the user it loads as; re-run as that user"
    done
}

rowW4() {
    row W4
    local etc=$W/etc; mkd "$etc"
    mkd "$W/snaponly"; cp "$P/reputation.bin" "$W/snaponly/snapshot.bin"
    L data-snap --dir "$W/snaponly" "$REP4"
    a "W4: snapshot.bin is never reputation in the data model" has "$W/data-snap.out" "plane reputation id=1 state=absent"
    a "W4: and the note says why" has "$W/data-snap.out" "snapshot.bin is read only through whisper_edge_snapshot; see --snapshot"
    L legacy --snapshot "$FX/interop.snap" --now 2026-10-13T09:00:00Z 192.0.2.0
    a "W4: legacy, no pre-stage: a high listing under mode log" has "$W/legacy.out" \
        "decision log would-deny=yes step=sugar rule=0 log=ctx:1 would-deny-rule=ctx:1 "
    a "W4: legacy, no pre-stage: hold-harmless does not apply" has "$W/legacy.out" "hold-harmless yes eligible=yes applies=no"
    # the decision is the module's three steps: a direct restatement over the sev sweep
    mapfile -t sv < <(awk '$3 != "-" {print $2}' "$FX/sweep/in-domain/reputation.expect" | awk '!s[$0]++')
    cp "$FX/sweep/in-domain/reputation.bin" "$W/sev.snap"
    JPAIR=0 L sev --snapshot "$W/sev.snap" --mode deny "${sv[@]}"
    a "W4: the sugar decision equals a restatement of the request path over every sev byte" python3 - \
        "$W/sev.out" "$FX/sweep/in-domain/reputation.expect" <<'PY'
import sys
sev = {}
for line in open(sys.argv[2]):
    f = line.split()
    if f[2] != "-":
        sev[f[1]] = int(f[3].split("=")[1])
cur, bad, n = None, 0, 0
for line in open(sys.argv[1]):
    if line.startswith("address "):
        cur = line.split()[1]
    elif line.startswith("decision ") and cur in sev:
        v = sev[cur]
        nib = v & 0x0F
        deny = nib != 0 and not (v & 0x80) and nib >= 3
        got = line.split()[1] == "deny"
        n += 1
        bad += deny != got
sys.exit(0 if n > 0 and bad == 0 else 1)
PY
    mkd "$W/amb"; cp "$P/reputation.bin" "$W/amb/snapshot.bin"
    [ "$MODE" = normal ] && I=$((I + 1))
    WHISPER_EDGE_DIR="$W/amb" WHISPER_EDGE_ETC="$etc" timeout 60 "$T" "$REP4" > "$W/so.out" 2>/dev/null
    a "W4: neither option, snapshot.bin alone: model-from=snapshot-only" has "$W/so.out" "model=legacy model-from=snapshot-only prestage=absent"
    a "W4: WHISPER_EDGE_DIR chose the directory, and a note says so" has "$W/so.out" \
        "note \"WHISPER_EDGE_DIR is set: the directory read is $W/amb, not /var/lib/whisper-edge\""
    [ "$MODE" = normal ] && I=$((I + 1))
    WHISPER_EDGE_DIR="$W/amb" timeout 60 "$T" --dir "$W/amb" "$REP4" > "$W/dir-over.out" 2>/dev/null
    a "W4: --dir chose it instead: no WHISPER_EDGE_DIR note" lacks "$W/dir-over.out" "WHISPER_EDGE_DIR is set"
    # WHISPER_EDGE_ETC unset: the default /etc/whisper-edge/policy.conf is only stat()ed under --policy
    # default (installed= reports it; it is never read), so nothing here depends on that host file
    [ "$MODE" = normal ] && I=$((I + 2))
    env -u WHISPER_EDGE_ETC timeout 60 "$T" --dir "$W/amb" --policy default "$REP4" > "$W/etc-unset.out" 2>/dev/null
    a "W4: WHISPER_EDGE_ETC unset: the run prints its policy line" grep -q '^policy source=builtin-default ' "$W/etc-unset.out"
    a "W4: and no note names the variable" lacks "$W/etc-unset.out" "WHISPER_EDGE_ETC is set"
    WHISPER_EDGE_ETC="$W/amb" timeout 60 "$T" --dir "$W/amb" --policy default "$REP4" > "$W/etc-set.out" 2>/dev/null
    a "W4 control: the same command with the variable set names it" has "$W/etc-set.out" \
        "note \"WHISPER_EDGE_ETC is set: the installed policy is looked for at $W/amb/policy.conf"
    cp "$P/tor.bin" "$W/amb/"
    [ "$MODE" = normal ] && I=$((I + 1))
    WHISPER_EDGE_DIR="$W/amb" WHISPER_EDGE_ETC="$etc" timeout 60 "$T" "$REP4" > "$W/amb.out" 2>/dev/null
    a "W4: snapshot.bin and a plane: model-from=ambiguous, the legacy model" has "$W/amb.out" "model=legacy model-from=ambiguous"
    python3 make-test-snapshot.py "$W/lo.snap" 5 0 3 > /dev/null
    L lo --snapshot "$W/lo.snap" --mode deny 127.0.0.1
    a "W4: 127.0.0.1 under --mode deny: hold-harmless does not apply without the pre-stage" has "$W/lo.out" "applies=no"
    a "W4: 127.0.0.1 denied, as nginx-gate.sh asserts" has "$W/lo.out" "decision deny enforce=yes step=sugar rule=1"
    a "W4: exit 1" eq "$RC" 1
    L f2-absent --snapshot "$P/tor.bin" "$TOR4"
    a "W4: a format-2 file under --snapshot, no pre-stage: refused=format" has "$W/f2-absent.out" "state=refused file=tor.bin manifest=unbound why=refused:format"
    python3 make-test-snapshot.py "$W/g0.snap" 0 0 4 > /dev/null
    L g0 --snapshot "$W/g0.snap" --mode deny 127.0.0.1
    a "W4: generation 0, no pre-stage: armed" has "$W/g0.out" "plane reputation id=1 state=fresh file=g0.snap format=1 generation=0"
    a "W4: generation 0: the note" has "$W/g0.out" "format-1 generation 0: a module with the policy evaluator refuses this file"
    a "W4: generation 0: the legacy path decides from it" has "$W/g0.out" "decision deny enforce=yes step=sugar"
    a "W4: generation 0: the attribute is the legacy path's severity" grep -q '^attr listed critical plane=reputation range=' "$W/g0.out"
    a "W4: generation 0: the verdict's action equals the decision" grep -q '^verdict step=4 action=deny program=ctx rule=1 ' "$W/g0.out"
    L g0p --snapshot "$W/g0.snap" --prestage present 127.0.0.1
    a "W4: generation 0 with the pre-stage: refused" has "$W/g0p.out" "state=refused file=g0.snap manifest=unbound why=refused:generation"
    python3 make-test-snapshot.py "$W/v.snap" 5 $V 3 > /dev/null
    L at --snapshot "$W/v.snap" --mode deny --now $V 127.0.0.1
    a "W4: at valid_until: deny, exit 1" eq "$(grep -c '^decision deny enforce=yes' "$W/at.out") $RC" "1 1"
    L past --snapshot "$W/v.snap" --mode deny --now $((V + 1)) 127.0.0.1
    a "W4: at valid_until + 1: allow, stale, exit 0" eq "$(grep -c '^decision allow step=sugar rule=0 reason=stale' "$W/past.out") $RC" "1 0"
    # the legacy synonym through both evaluators, with and without the pre-stage, fresh and stale
    plan "$W/p.tsv" \
        "$(pline absent "$P/reputation.bin" legacy:high:deny:absent http "$V" plain reputation=fresh "$P" "$(crit) $REP4 192.0.2.1")" \
        "$(pline present "$P/reputation.bin" legacy:high:deny:present http "$V" plain reputation=fresh "$P" "$(crit) $REP4 192.0.2.1")" \
        "$(pline stale "$PV/reputation.bin" legacy:critical:log:present http $((V + 1)) plain reputation=stale "$P" "$(crit) 192.0.2.1")"
    runplan "$W/p.tsv" "$W/t"
    judgeplan "W4: the legacy synonym" "$W/p.tsv" "$W/t" "$W/cache"
    a "W4: a legacy case block names the synonym" grep -qx legacy "$W/t/absent.case"
    a "W4: without the pre-stage the verdict's action is the decision's" \
        eq "$(grep -c '^verdict step=4 action=deny program=ctx rule=1 ' "$W/t/absent.out")" "$(grep -c '^decision deny ' "$W/t/absent.out")"
}

rowW5() {
    row W5
    local h=3600000
    mkdata "$W/d" - reputation
    cp "$PV/tenant.bin" "$W/d/"
    L g1 --dir "$W/d" --now $((V + 1)) "$TEN4"
    a "W5: 1 ms past valid_until: grace:47" has "$W/g1.out" "attr tenant_allow UNKNOWN plane=tenant why=grace:47"
    a "W5: tenant_deny never carries a value when stale" has "$W/g1.out" "attr tenant_deny UNKNOWN plane=tenant why=grace:47"
    L g2 --dir "$W/d" --now $((V + 47 * h + 1)) "$TEN4"
    a "W5: 47 h + 1 ms: grace:0" has "$W/g2.out" "attr tenant_allow UNKNOWN plane=tenant why=grace:0"
    L g3 --dir "$W/d" --now $((V + 48 * h)) "$TEN4"
    a "W5: exactly 48 h: still grace:0" has "$W/g3.out" "attr tenant_allow UNKNOWN plane=tenant why=grace:0"
    L g4 --dir "$W/d" --now $((V + 48 * h + 1)) "$TEN4"
    a "W5: 48 h + 1 ms: lapsed" has "$W/g4.out" "attr tenant_allow UNKNOWN plane=tenant why=lapsed"
    a "W5: GRACE: tenant_allow carries the stale record's bounded value" \
        grep -q '^attr tenant_allow UNKNOWN plane=tenant why=grace:47 bounded=\(true\|false\) ' "$W/g1.out"
    a "W5: LAPSED: bounded=false" grep -q '^attr tenant_allow UNKNOWN plane=tenant why=lapsed bounded=false ' "$W/g4.out"
    a "W5: tenant_deny never carries bounded" not grep -q '^attr tenant_deny .*bounded=' "$W/g1.out"
    mkdata "$W/f" - tenant; cp "$P/reputation.bin" "$W/f/"
    mkdata "$W/n" -; cp "$P/reputation.bin" "$W/n/"; head -c -10 "$P/tenant.bin" > "$W/n/tenant.bin"
    mkdata "$W/g" -; cp "$P/reputation.bin" "$PV/tenant.bin" "$W/g/"
    chmod 444 "$W/f/"*.bin "$W/n/"*.bin "$W/g/"*.bin
    local pol prog ten
    ten="$TEN4 $(awk '$3 == "-" && $1 == "4" { print $2; exit }' "$P/tenant.expect")"
    for pol in "allow if tenant_allow" "deny if not tenant_allow" "deny if tenant_deny"; do
        prog=$W/p-${pol// /-}.policy
        printf 'mode http deny\x1e\npolicy http %s\x1e\npolicy http deny if listed >= none\x1e\n' "$pol" > "$prog"
        plan "$W/p.tsv" \
            "$(pline fresh "$W/f" "$prog" http "$V" plain reputation=fresh,tenant=fresh "$P" "$ten")" \
            "$(pline grace1 "$W/g" "$prog" http $((V + 1)) plain reputation=fresh,tenant=stale "$P" "$ten")" \
            "$(pline grace47 "$W/g" "$prog" http $((V + 47 * h + 1)) plain reputation=fresh,tenant=stale "$P" "$ten")" \
            "$(pline grace48 "$W/g" "$prog" http $((V + 48 * h)) plain reputation=fresh,tenant=stale "$P" "$ten")" \
            "$(pline lapsed "$W/g" "$prog" http $((V + 48 * h + 1)) plain reputation=fresh,tenant=stale "$P" "$ten")" \
            "$(pline null "$W/n" "$prog" http "$V" plain reputation=fresh,tenant=refused "$P" "$ten")"
        runplan "$W/p.tsv" "$W/t-${pol// /-}"
        judgeplan "W5 $pol" "$W/p.tsv" "$W/t-${pol// /-}" "$W/cache-${pol// /-}"
    done
}

rowW6() {
    row W6
    local d
    d=$W/m664; mkdata "$d" base.json reputation; chmod 664 "$d/manifest.json"
    L m664 --dir "$d" "$REP4"
    a "W6: a 0664 manifest refused" has "$W/m664.out" "manifest state=refused why=group-or-world-writable file=manifest.json"
    a "W6: its planes manifest=refused" has "$W/m664.out" "plane reputation id=1 state=fresh file=reputation.bin format=1"
    a "W6: its planes manifest=refused, why=refused" hasre "$W/m664.out" "^plane reputation .* manifest=refused why=refused"
    d=$W/fifo; mkdata "$d" - reputation; mkfifo "$d/manifest.json"
    L fifo --dir "$d" "$REP4"
    a "W6: a FIFO manifest refused, never waited on" has "$W/fifo.out" "manifest state=refused why=not-regular file=manifest.json"
    d=$W/sym; mkdata "$d" - reputation; ln -s "$FX/derived/base.json" "$d/manifest.json"
    L sym --dir "$d" "$REP4"
    a "W6: a symlinked manifest refused" has "$W/sym.out" "manifest state=refused why=symlink file=manifest.json"
    d=$W/gw; mkdata "$d" base.json reputation; chmod 775 "$d"
    L gw --dir "$d" "$REP4"
    a "W6: a group-writable directory" has "$W/gw.out" "manifest state=refused why=directory-writable file=manifest.json"
    d=$W/k; mkdata "$d" base.json reputation; mkd "$W/kreal"; cp "$FX/derived/keyed.json" "$W/kreal/manifest.json"
    ln -s "$W/kreal" "$d/k"
    L k --dir "$d" "$REP4"
    a "W6: k a symlink to a valid directory: refused" has "$W/k.out" "manifest state=refused why=symlink file=k/manifest.json"
    # another user's manifest, without making one: the shim's owner part reports the file as another uid's
    d=$W/foreign; mkdata "$d" base.json reputation
    [ "$MODE" = normal ] && I=$((I + 2)) && C=$((C + 2))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_FOREIGN="$d/manifest.json" "$T" --dir "$d" --now "$NOWFIX" \
        "$REP4" > "$W/foreign.out" 2>/dev/null
    a "W6: a manifest another user owns" has "$W/foreign.out" "manifest state=refused why=foreign-owner file=manifest.json"
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" "$T" --dir "$d" --now "$NOWFIX" "$REP4" > "$W/foreign-control.out" 2>/dev/null
    a "W6 control: the same shim without LOOKUP_SHIM_FOREIGN reads the manifest" \
        has "$W/foreign-control.out" "manifest state=read file=manifest.json"
    # one manifest read, the other refused: a plane the refused one would bind reads why=refused, never
    # not-named (the read manifest's silence says nothing about the refused one)
    d=$W/half; rm -rf "$d"; mkd "$d"; mkd "$d/k"
    cp "$WR/jobs/routing.bin" "$WR/jobs/tor.bin" "$d/"; chmod 444 "$d/"*.bin
    cp "$WR/keyless/manifest.json" "$d/manifest.json"; chmod 644 "$d/manifest.json"
    cp "$WR/jobs/manifest.json" "$d/k/manifest.json"; chmod 664 "$d/k/manifest.json"
    L half --dir "$d" --now 2026-10-11T03:00:00Z 192.0.2.1
    a "W6: the keyed manifest refused" has "$W/half.out" "manifest state=refused why=group-or-world-writable file=k/manifest.json"
    a "W6: the keyless manifest read" has "$W/half.out" "manifest state=read file=manifest.json"
    a "W6: a plane only the refused manifest names: why=refused" \
        hasre "$W/half.out" "^plane routing id=4 state=fresh .* manifest=refused why=refused "
    a "W6: not the not-named note" lacks "$W/half.out" "routing: the manifest in the directory does not list this plane"
    a "W6: the note says what the tool knows: a manifest was refused, and it may bind the plane" has "$W/half.out" \
        'note "routing: a manifest in the directory was refused, and it may be the one that binds this plane; see its manifest line"'
}

rowW7() {
    row W7
    python3 make-test-snapshot.py "$W/v.snap" 5 $(( $(date +%s) * 1000 + 86400000 )) 3 > /dev/null
    local adv=$(( $(date +%s) * 1000 + 2 * 86400000 ))
    rm -f "$W/cnt".*
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 2))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_CLOCK=1 LOOKUP_SHIM_ADVANCE_MS=$adv LOOKUP_SHIM_OUT="$W/cnt" \
        "$T" --snapshot "$W/v.snap" 127.0.0.1 127.0.0.2 > "$W/clock.out" 2>/dev/null
    a "W7: one count file" eq "$(cntn)" 1
    a "W7: exactly one wall-clock read for two addresses" has "$(cntfile)" "clock 1"
    a "W7: both decisions on the start sample" eq "$(grep -c '^decision log would-deny=yes' "$W/clock.out")" 2
    a "W7: the plane line on the start sample" has "$W/clock.out" "plane reputation id=1 state=fresh"
    rm -f "$W/cnt".*
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 2))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_CLOCK=1 LOOKUP_SHIM_OUT="$W/cnt" \
        "$T" --snapshot "$W/v.snap" --now $V 127.0.0.1 127.0.0.2 > /dev/null 2>&1
    a "W7: with --now, no wall-clock read" has "$(cntfile)" "clock 0"
}

rowW8() {
    row W8
    mkdata "$W/one" withheld-reputation.json reputation
    L one --dir "$W/one" "$REP4"
    a "W8: a fresh plane the feed withholds: feed and until" has "$W/one.out" "feed=withheld:SOURCE_STALE until=2026-10-14T08:00:00Z"
    mkdata "$W/two" withheld-reputation-two.json reputation
    L two --dir "$W/two" "$REP4"
    a "W8: two reasons, two members in why's order" has "$W/two.out" "feed=withheld:LOW_RECALL,withheld:SOURCE_STALE until=2026-10-14T08:00:00Z"
}

rowW9() {
    row W9
    local g=60
    if [ "$MODE" = mutant ]; then g=3; fi      # a control whose catch is a hang is caught at 3 s
    local d=$W/d p
    rm -rf "$d"; mkd "$d"
    for p in reputation tor rpki-unreachable routing anonymizer threat registry tenant; do mkfifo "$d/$p.bin"; done
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout "$g" "$T" --dir "$d" --now "$NOWFIX" 192.0.2.1 > "$W/fifo.out" 2>/dev/null
    RC=$?
    a "W9: a FIFO at every plane name: the run finishes (exit $RC)" eq "$RC" 0
    a "W9: every FIFO refused, present, not a regular file" \
        eq "$(grep -c 'state=refused file=[a-z-]*.bin manifest=unbound why=refused:not-regular refused=not-regular refused-detail="not a regular file"' "$W/fifo.out")" 8
    a "W9: its attributes UNKNOWN" has "$W/fifo.out" "attr listed UNKNOWN plane=reputation why=refused:not-regular"
    plan "$W/p.tsv" "$(pline fifo "$d" "$CORE/testdata/policy/accept/03-every-boolean.policy" http/server:a "$NOWFIX" plain \
        "anonymizer=refused,registry=refused,reputation=refused,routing=refused,rpki-unreachable=refused,tenant=refused,threat=refused,tor=refused" "$P" "192.0.2.1 1.1.1.1")"
    runplan "$W/p.tsv" "$W/t"
    judgeplan "W9: every FIFO present, its rules armed" "$W/p.tsv" "$W/t" "$W/cache"
    if [ "$MODE" = normal ]; then
        # the control: a restatement whose probe opens the plane path with a plain blocking open(). Both runs
        # get the same ceiling, one only a hang reaches: a 3 s budget read a loaded box's slow but finishing
        # unplanted run as a hang (exit 124 under a 15-minute load average of 28 on 8 CPUs), and a ceiling
        # tighter for the planted run than for the unplanted one could not tell its hang from slowness
        local jrc=0 prc=0 ceil=60
        TEST_POLICY=$FX/test_policy timeout $ceil python3 lookup-states.py judge \
            "$W/p.tsv" "$W/t" "$W/cache-open0" > "$W/open-positive.txt" 2>&1 || prc=$?
        a "W9: the same judge command, unplanted, finishes and agrees under the same ${ceil} s (exit $prc)" eq "$prc" 0
        LOOKUP_STATES_MUTANT=PROBE_OPEN TEST_POLICY=$FX/test_policy timeout $ceil python3 lookup-states.py judge \
            "$W/p.tsv" "$W/t" "$W/cache-open" > "$W/open-only.txt" 2>&1 || jrc=$?
        a "W9 control: a restatement probing with open() alone blocks on the FIFO, killed at ${ceil} s (exit $jrc)" eq "$jrc" 124
    fi
    rm -rf "$W/n"; mkd "$W/n"; ln -s /dev/null "$W/n/tor.bin"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout "$g" "$T" --dir "$W/n" --now "$NOWFIX" 192.0.2.1 > "$W/null.out" 2>/dev/null
    a "W9: a symlink to /dev/null at a plane name: refused, not a regular file" has "$W/null.out" \
        "plane tor id=2 state=refused file=tor.bin manifest=unbound why=refused:not-regular"
    rm -f "$W/s.snap"; mkfifo "$W/s.snap"
    [ "$MODE" = normal ] && I=$((I + 2)) && C=$((C + 2))
    timeout "$g" "$T" --snapshot "$W/s.snap" --prestage present --now "$NOWFIX" 192.0.2.1 > "$W/sp.out" 2>/dev/null
    a "W9: a FIFO as --snapshot with the pre-stage: refused, not a regular file" has "$W/sp.out" \
        'refused=not-regular refused-detail="not a regular file"'
    timeout "$g" "$T" --snapshot "$W/s.snap" --now "$NOWFIX" 192.0.2.1 > "$W/sa.out" 2>/dev/null
    a "W9: a FIFO as --snapshot without it: refused=open with the core's text" has "$W/sa.out" \
        'refused=open refused-detail="cannot open snapshot"'
    L nosnap --snapshot "$W/no-such.snap" --now "$NOWFIX" 192.0.2.1
    a "W9: a --snapshot that is not there: the core's text and the reason" has "$W/nosnap.out" \
        'refused=open refused-detail="cannot open snapshot: No such file or directory"'
    a "W9: a FIFO keeps the core's text alone" hasre "$W/sa.out" 'refused-detail="cannot open snapshot"( |$)'
    # a --snapshot this uid cannot open, at any uid (root reads a mode-000 file): the shim's open part fails
    # the core's open and the reason's own non-blocking open with EACCES, on a readable regular file
    cp "$FX/interop.snap" "$W/eacces.snap"; chmod 644 "$W/eacces.snap"
    rm -f "$W/cnt".*
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$W/eacces.snap" LOOKUP_SHIM_FAIL_PATH="$W/eacces.snap" \
        LOOKUP_SHIM_FAIL_AT=1,2 LOOKUP_SHIM_FAIL_ERRNO=EACCES LOOKUP_SHIM_OUT="$W/cnt" "$T" --snapshot "$W/eacces.snap" \
        --now "$NOWFIX" 192.0.2.1 > "$W/eacces.out" 2>/dev/null
    a "W9: a --snapshot this uid cannot open: the core's text and the reason" has "$W/eacces.out" \
        'refused=open refused-detail="cannot open snapshot: Permission denied"'
    a "W9: the shim ran in one process" eq "$(cntn)" 1
    a "W9: and saw the path opened twice, the core's open and the reason's" has "$(cntfile)" "open 2 $W/eacces.snap"
    rm -f "$W/eacces.snap"
    # a directory as --snapshot: the reason named from its mode, nothing opened
    mkd "$W/snapdir"
    L snapdir --snapshot "$W/snapdir" --now "$NOWFIX" 192.0.2.1
    a "W9: a directory as --snapshot: the core's text and the reason" has "$W/snapdir.out" \
        'refused=open refused-detail="cannot open snapshot: Is a directory"'
    # a data directory this uid cannot search or open, at any uid, root included: the shim's deny part
    # refuses every look inside it and the open of the directory itself, as a mode-000 directory does
    mkd "$W/deny"; cp "$P/reputation.bin" "$W/deny/"; chmod 444 "$W/deny/reputation.bin"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_DENY_DIR="$W/deny" "$T" --dir "$W/deny" --now "$NOWFIX" \
        "$REP4" > "$W/deny.out" 2>/dev/null
    a "W9: a plane in a directory this uid cannot search: refused, permission, uid-dependent, never absent" has "$W/deny.out" \
        'plane reputation id=1 state=refused file=reputation.bin manifest=unbound why=refused:permission,uid-dependent refused=permission refused-detail="cannot open: Permission denied"'
    a "W9: with the note that the answer depends on the uid" has "$W/deny.out" \
        "note \"reputation: whether the module arms these rules depends on the user it loads as; re-run as that user\""
    a "W9: and the directory's own note" has "$W/deny.out" \
        "note \"the directory $W/deny cannot be opened by this uid (Permission denied): its manifests are not read"
    a "W9 control: the same directory without the deny part: the plane fresh" \
        hasre <(timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" "$T" --dir "$W/deny" --now "$NOWFIX" "$REP4" 2>/dev/null) \
        '^plane reputation id=1 state=fresh '
    # the installed policy in a directory this uid cannot search: no answer, never installed=no
    mkd "$W/etcdeny"; cp "$CORE/testdata/policy/default.conf" "$W/etcdeny/policy.conf"; chmod 644 "$W/etcdeny/policy.conf"
    [ "$MODE" = normal ] && I=$((I + 1))
    timeout 60 env WHISPER_EDGE_ETC="$W/etcdeny" LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_DENY_DIR="$W/etcdeny" \
        "$T" --dir "$W/deny" --now "$NOWFIX" "$REP4" > "$W/etcdeny.out" 2> "$W/etcdeny.err"
    RC=$?
    a "W9: an installed policy this uid cannot look at: exit 2 (exit $RC)" eq "$RC" 2
    a "W9: naming the path and the reason" has "$W/etcdeny.err" \
        "whisper-edge-lookup: cannot look at the installed policy $W/etcdeny/policy.conf: Permission denied"
    a "W9: and no output" test ! -s "$W/etcdeny.out"
    a "W9 control: the same directory without the deny part: installed=yes" \
        hasre <(timeout 60 env WHISPER_EDGE_ETC="$W/etcdeny" LD_PRELOAD="$FX/lookup_shim.so" "$T" --dir "$W/deny" \
            --now "$NOWFIX" "$REP4" 2>/dev/null) '^policy source=policy-conf installed=yes '
    # where the installed file decides nothing (an explicit policy), the run answers: installed=unknown
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 env WHISPER_EDGE_ETC="$W/etcdeny" LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_DENY_DIR="$W/etcdeny" \
        "$T" --dir "$W/deny" --policy default --now "$NOWFIX" "$REP4" > "$W/etcdef.out" 2> "$W/etcdef.err"
    RC=$?
    a "W9: --policy default beside an installed policy this uid cannot look at: the run answers (exit $RC)" \
        test "$RC" -le 1
    a "W9: installed=unknown" grep -q '^policy source=builtin-default installed=unknown ' "$W/etcdef.out"
    a "W9: with the note naming the path and the reason" has "$W/etcdef.out" \
        "note \"the installed policy $W/etcdeny/policy.conf cannot be looked at by this uid (Permission denied): installed is unknown"
    a "W9: and a decision" grep -q '^decision ' "$W/etcdef.out"
    # the same where no uid can look (a symlink loop): the note says so without blaming the uid
    rm -f "$W/etcloop" "$W/etcloop2"; ln -s etcloop2 "$W/etcloop"; ln -s etcloop "$W/etcloop2"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 env WHISPER_EDGE_ETC="$W/etcloop" "$T" --dir "$W/deny" --policy default --now "$NOWFIX" "$REP4" \
        > "$W/etcloop.out" 2>/dev/null
    a "W9: an installed policy behind a symlink loop: installed=unknown" \
        grep -q '^policy source=builtin-default installed=unknown ' "$W/etcloop.out"
    a "W9: its note names the loop and not the uid" has "$W/etcloop.out" \
        "note \"the installed policy $W/etcloop/policy.conf cannot be looked at (Too many levels of symbolic links): installed is unknown"
    # where the directory's contents pick the model, a look that cannot answer stops the run
    mkd "$W/amb"; cp "$FX/interop.snap" "$W/amb/snapshot.bin"; chmod 444 "$W/amb/snapshot.bin"
    [ "$MODE" = normal ] && I=$((I + 1))
    timeout 60 env WHISPER_EDGE_ETC="$W/no-etc" WHISPER_EDGE_DIR="$W/amb" LD_PRELOAD="$FX/lookup_shim.so" \
        LOOKUP_SHIM_DENY_DIR="$W/amb" "$T" --now "$NOWFIX" 192.0.2.1 > "$W/ambdeny.out" 2> "$W/ambdeny.err"
    RC=$?
    a "W9: the default directory this uid cannot search: exit 2 (exit $RC)" eq "$RC" 2
    a "W9: naming the path the model rests on" has "$W/ambdeny.err" \
        "whisper-edge-lookup: cannot look at $W/amb/snapshot.bin: Permission denied"
    a "W9: and no model chosen past it" test ! -s "$W/ambdeny.out"
    # a symlink loop fails for every uid alike: inert, with its reason, never uid-dependent
    rm -rf "$W/loop"; mkd "$W/loop"; ln -s b "$W/loop/a"; ln -s a "$W/loop/b"
    L loop --dir "$W/loop/a" --now "$NOWFIX" "$REP4"
    a "W9: a plane under a symlink loop: refused, open, inert at config, with the loop's reason" has "$W/loop.out" \
        'plane reputation id=1 state=refused file=reputation.bin manifest=unbound why=refused:open,inert-at-config refused=open refused-detail="Too many levels of symbolic links"'
    a "W9: never uid-dependent" lacks "$W/loop.out" "uid-dependent"
    a "W9: the directory's note, without the uid" has "$W/loop.out" \
        "note \"the directory $W/loop/a cannot be opened (Too many levels of symbolic links): its manifests are not read"
    # a --dir inside a directory this uid cannot search: the open's note alone, never 'does not exist'
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_DENY_DIR="$W/deny" "$T" --dir "$W/deny/sub" --now "$NOWFIX" \
        "$REP4" > "$W/denysub.out" 2>/dev/null
    a "W9: a --dir under an unsearchable parent: the open's note" has "$W/denysub.out" \
        "note \"the directory $W/deny/sub cannot be opened by this uid (Permission denied)"
    a "W9: and not the contradicting one" lacks "$W/denysub.out" "the --dir directory does not exist or is not a directory"
}

rowW10() {
    row W10
    local d="$W/dis arm\"d"
    mkdata "$d" disarm.json reputation tor
    L dis --dir "$d" "$REP4"
    a "W10: builder=disarm" has "$W/dis.out" "builder=disarm"
    a "W10: the note with the path as one quoted token and the chattr sentence" has "$W/dis.out" \
        "reputation: the feed is disarmed, and this plane is still fresh on disk until 2026-10-12T00:00:00Z at \\x22$W/dis arm\\x22d/reputation.bin\\x22; remove it (the refresh sets the immutable flag, so chattr -i it first) and reload the server"
}

rowW11() {
    row W11
    mkdata "$W/d" base.json reputation
    L ahead --dir "$W/d" --now 2026-10-10T23:59:59.500Z "$REP4"
    a "W11: built 500 ms after now: age=-1" has "$W/ahead.out" " age=-1 "
    L behind --dir "$W/d" --now 2026-10-11T00:00:01.500Z "$REP4"
    a "W11: built 1,500 ms before now: age=1" has "$W/behind.out" " age=1 "
    mkdata "$W/f" future.json reputation
    L future --dir "$W/f" --now 2026-10-11T00:00:00Z "$REP4"
    a "W11: built a year after now: a negative age" has "$W/future.out" " age=-31536000 "
    if [ "$MODE" = normal ]; then
        I=$((I + 1)); C=$((C + 1))
        "$FX/lookup_san" --dir "$W/f" --now 2026-10-11T00:00:00Z "$REP4" > /dev/null 2> "$W/san.err"
        a "W11: no sanitizer report on a negative age" test $? -eq 0
    fi
}

rowW12() {
    row W12
    local S=${SAN:-$T}
    [ "$MODE" = normal ] && I=$((I + 2)) && C=$((C + 2))
    timeout 60 "$S" --snapshot "$P/tor.bin" --prestage present "$TOR4" > "$W/tor.out" 2>/dev/null
    a "W12: a tor plane as --snapshot: refused=binding" has "$W/tor.out" 'refused=binding refused-detail="carries plane 2, not reputation'"'"'s 1"'
    timeout 60 "$S" --snapshot "$P/routing.bin" --prestage present "$TOR4" > "$W/routing.out" 2>/dev/null
    a "W12: a routing plane as --snapshot: refused=binding" has "$W/routing.out" 'refused-detail="carries plane 4, not reputation'"'"'s 1"'
    local d=$W/d; rm -rf "$d"; mkd "$d"
    cp "$P/reputation.bin" "$d/tor.bin"; cp "$P/routing.bin" "$d/anonymizer.bin"; cp "$P/tor.bin" "$d/reputation.bin"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 "$S" --dir "$d" "$REP4" > "$W/names.out" 2>/dev/null
    a "W12: a format-1 file at tor.bin refused" hasre "$W/names.out" "^plane tor id=2 state=refused .*refused=format"
    a "W12: a tor plane at reputation.bin refused" hasre "$W/names.out" "^plane reputation id=1 state=refused .*refused=format"
    a "W12: a routing plane at anonymizer.bin refused" hasre "$W/names.out" "^plane anonymizer id=5 state=refused .*refused=format"
    mkdata "$W/b" tor-as-routing.json reputation tor
    L bind --dir "$W/b" "$REP4"
    a "W12: a manifest naming the tor bytes as routing does not bind tor" hasre "$W/bind.out" "^plane tor id=2 state=fresh .* manifest=unbound"
}

rowW13() {
    row W13
    mkdata "$W/d" - reputation
    local at
    for at in 2 1; do
        rm -f "$W/cnt".*
        [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
        timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$W/d/reputation.bin" LOOKUP_SHIM_FAIL_PATH="$W/d/reputation.bin" \
            LOOKUP_SHIM_FAIL_AT=$at LOOKUP_SHIM_FAIL_ERRNO=ENOENT LOOKUP_SHIM_OUT="$W/cnt" "$T" --dir "$W/d" "$REP4" \
            > "$W/at$at.out" 2> "$W/at$at.err"
        RC=$?
        a "W13 open $at failed: the path opened 6 times (probe, load, the module's check: its probe, header and trust open; probe)" has "$(cntfile)" "open 6 $W/d/reputation.bin"
        if [ $at = 2 ]; then
            a "W13 (a) the load failed: refused, present" has "$W/at2.out" "plane reputation id=1 state=refused file=reputation.bin manifest=unbound why=refused:open"
            mkd "$W/t"; cp "$W/at2.out" "$W/t/w13.out"
            rm -f "$W/cnt".*
            timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$W/d/reputation.bin" LOOKUP_SHIM_FAIL_PATH="$W/d/reputation.bin" \
                LOOKUP_SHIM_FAIL_AT=2 LOOKUP_SHIM_FAIL_ERRNO=ENOENT LOOKUP_SHIM_OUT="$W/cnt" "$T" --case --dir "$W/d" --now "$NOWFIX" \
                --policy "$CORE/testdata/policy/default.conf" "$REP4" > "$W/t/w13.case" 2>/dev/null
            rm -f "$W/cnt".*
            timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$W/d/reputation.bin" LOOKUP_SHIM_FAIL_PATH="$W/d/reputation.bin" \
                LOOKUP_SHIM_FAIL_AT=2 LOOKUP_SHIM_FAIL_ERRNO=ENOENT LOOKUP_SHIM_OUT="$W/cnt" "$T" --dir "$W/d" --now "$NOWFIX" \
                --policy "$CORE/testdata/policy/default.conf" "$REP4" > "$W/t/w13.out" 2>/dev/null
            plan "$W/p.tsv" "$(pline w13 "$W/d" "$CORE/testdata/policy/default.conf" http "$NOWFIX" plain reputation=refused "$P" "$REP4")"
            judgeplan "W13 (a): the plane present, its rules armed" "$W/p.tsv" "$W/t" "$W/cache"
        else
            a "W13 (b) the first probe failed: exit 2" eq "$RC" 2
            a "W13 (b) with the message" has "$W/at1.err" "the directory changed during this run (a plane appeared or disappeared); re-run"
        fi
    done
    # a plane that appears between the tool's looks at an absent path, each look beginning with a stat():
    # the probe, the load, the classification, the second probe. Appearing as the classification's stat
    # returns, the second probe sees it and the run says the directory changed; appearing after the second
    # probe, it is outside the run and reads absent. Classified after the second probe instead, the first
    # would be blamed on a permission and the second on a dangling link.
    cp "$P/tor.bin" "$W/staged-tor.bin"; chmod 444 "$W/staged-tor.bin"
    for at in 3 4; do
        rm -f "$W/cnt".* "$W/d/tor.bin"
        [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
        timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_APPEAR_PATH="$W/d/tor.bin" LOOKUP_SHIM_APPEAR_AFTER=$at \
            LOOKUP_SHIM_APPEAR_FROM="$W/staged-tor.bin" LOOKUP_SHIM_OUT="$W/cnt" "$T" --dir "$W/d" --now "$NOWFIX" "$REP4" \
            > "$W/ap$at.out" 2> "$W/ap$at.err"
        RC=$?
        a "W13 appear $at: four looks at the path, each a stat()" has "$(cntfile)" "stat 4 $W/d/tor.bin"
        a "W13 appear $at: never a permission or a dangling link" lacks "$W/ap$at.out" "plane tor id=2 state=refused"
        if [ $at = 3 ]; then
            a "W13 (c) appearing before the second probe: exit 2" eq "$RC" 2
            a "W13 (c) with the message" has "$W/ap3.err" "the directory changed during this run (a plane appeared or disappeared); re-run"
        else
            a "W13 (d) appearing after the second probe: absent" has "$W/ap4.out" "plane tor id=2 state=absent manifest=unbound why=absent"
            a "W13 (d) exit 0" eq "$RC" 0
        fi
    done
    rm -f "$W/d/tor.bin"
}

# ======================================================================================================
# M rows: binding and the manifest's fields
# ======================================================================================================
rowM1() {
    row M1
    local m
    for m in base none not-named other-bytes duplicate-entry planes-and-withheld; do
        if [ $m = none ]; then mkdata "$W/$m" - reputation; else mkdata "$W/$m" $m.json reputation; fi
        L $m --dir "$W/$m" "$REP4"
    done
    a "M1: bound to the entry naming its digest" hasre "$W/base.out" "^plane reputation id=1 state=fresh .* manifest=bound bound-to=manifest.json"
    a "M1: no manifest" hasre "$W/none.out" "^plane reputation .* manifest=unbound why=no-manifest$"
    a "M1: no manifest, its note" has "$W/none.out" "reputation: no manifest in the directory, so nothing states this plane's provenance"
    a "M1: not named" hasre "$W/not-named.out" "^plane reputation .* manifest=unbound why=not-named "
    a "M1: not named, its note" has "$W/not-named.out" "reputation: the manifest in the directory does not list this plane"
    a "M1: other bytes, with the entry's generation" hasre "$W/other-bytes.out" "^plane reputation .* generation=497688 .* manifest=unbound why=other-bytes entry-generation=497689 "
    a "M1: other bytes, its note" has "$W/other-bytes.out" "reputation: the manifest names other bytes for this plane"
    a "M1: two entries of one name: the first read" hasre "$W/duplicate-entry.out" "^plane reputation .* manifest=unbound why=other-bytes "
    a "M1: two entries of one name: the note" has "$W/duplicate-entry.out" "only its first planes[] entry is read"
    a "M1: in planes[] and withheld[]: bound, published" hasre "$W/planes-and-withheld.out" "^plane reputation .* manifest=bound .*feed=published"
    a "M1: in planes[] and withheld[]: the note" has "$W/planes-and-withheld.out" "also lists it as withheld; it is bound through planes[]"
}

rowM2() {
    row M2
    mkdata "$W/legacy" legacy-only.json reputation
    L legacy --dir "$W/legacy" "$REP4"
    a "M2: format 1 bound through legacy[], slot-index" hasre "$W/legacy.out" "^plane reputation .* unit=slot-index .* manifest=bound bound-to=manifest.json tier=not-stated"
    mkd "$W/jobs"; cp "$WR/jobs/routing.bin" "$WR/jobs/tor.bin" "$W/jobs/"; chmod 444 "$W/jobs/"*.bin
    cp "$FX/derived/jobs.json" "$W/jobs/manifest.json"
    L jobs --dir "$W/jobs" --now 2026-10-11T03:00:00Z 198.51.100.1
    a "M2: format 2 bound through planes[], epoch-seconds" hasre "$W/jobs.out" "^plane tor id=2 state=fresh .* unit=epoch-seconds .* manifest=bound"
    a "M2: the routing plane bound through planes[]" hasre "$W/jobs.out" "^plane routing id=4 state=fresh .* manifest=bound bound-to=manifest.json"
    mkd "$W/snap"; cp "$WR/keyless/reputation.bin" "$W/snap/snapshot.bin"; cp "$FX/derived/base.json" "$W/snap/manifest.json"
    chmod 644 "$W/snap/"*
    L snap --snapshot "$W/snap/snapshot.bin" "$REP4"
    a "M2: --snapshot binds through the manifest beside the file" hasre "$W/snap.out" "^plane reputation .* manifest=bound bound-to=manifest.json"
    a "M2: both planes[] and legacy[]: sources and coverage from planes[]" hasre "$W/snap.out" "sources=0 coverage-v4=76800 "
}

rowM3() {
    row M3
    mkdata "$W/vu" valid-until-differs.json reputation
    L vu --dir "$W/vu" "$REP4"
    a "M3: validUntil differing from the header: disagree=valid-until" hasre "$W/vu.out" "^plane reputation .* disagree=valid-until$"
    mkdata "$W/fl" built-at-floored.json reputation
    L fl --dir "$W/fl" "$REP4"
    a "M3: the floored manifest binds the plane" hasre "$W/fl.out" "^plane reputation .* manifest=bound "
    a "M3: .0019Z floors to the header's millisecond" lacks "$W/fl.out" "disagree=built"
    local t
    for t in 2026-02-30T00:00:00Z 2026-04-31T00:00:00Z 2026-02-29T00:00:00Z 2026-10-13T24:00:00Z 2026-10-13T23:60:00Z \
             2026-10-13T00:00:00+24:00 1970-01-01T00:00:00+00:01 9999-12-31T23:59:59-00:01 9999-12-31T23:59:60Z \
             +10000-01-01T00:00:00Z 1969-12-31T23:59:59.5Z 253402300800000; do
        JPAIR=0 L now-bad --now "$t" --snapshot "$FX/interop.snap" 1.1.1.1
        a "M3: --now $t exits 2" eq "$RC" 2
    done
    JPAIR=0 L now-leap --now 2024-02-29T00:00:00Z --snapshot "$FX/interop.snap" 1.1.1.1
    a "M3: --now 2024-02-29 is accepted" eq "$RC" 0
    JPAIR=0 L now-pre --now 1969-12-31T23:59:59-00:01 --snapshot "$FX/interop.snap" 1.1.1.1
    a "M3: --now 1969-12-31T23:59:59-00:01 is 1970-01-01T00:00:59Z" has "$W/now-pre.out" "now=1970-01-01T00:00:59Z"
}

rowM4() {
    row M4
    mkd "$W/b"; cp "$WR/jobs/routing.bin" "$WR/jobs/tor.bin" "$W/b/"; chmod 444 "$W/b/"*.bin
    cp "$FX/derived/jobs.json" "$W/b/manifest.json"
    L b --dir "$W/b" --now 2026-10-11T03:00:00Z 192.0.2.1
    a "M4: routing's two sources" eq "$(grep -c '^source routing ' "$W/b.out")" 2
    a "M4: routing's six-counter coverage: coverage-v4 not-stated" hasre "$W/b.out" "^plane routing .* coverage-v4=not-stated "
    a "M4: tor's null coverage" hasre "$W/b.out" "^plane tor .* coverage-v4=not-stated coverage-v6=not-stated coverage-v6-slash32s=not-stated"
    a "M4: tor's source, its null recall and precision" has "$W/b.out" \
        "source tor 1 name=tor-onionoo kind=relay-exit-edges count=20 observed-at=2026-10-11T02:32:36.291Z recall=not-stated precision=not-stated"
    a "M4: a null observedAt is not-stated" has "$W/b.out" "source routing 1 name=announced-prefix kind=bgp-routes count=3 observed-at=not-stated"
    a "M4: an ISO observedAt" has "$W/b.out" "source routing 2 name=rpki-roa kind=vrps-covering-announced-routes count=3 observed-at=2026-10-11T03:32:36Z"
    cp "$FX/derived/numeric-times.json" "$W/b/manifest.json"
    L num --dir "$W/b" --now 2026-10-11T03:00:00Z 192.0.2.1
    a "M4: the same observedAt as integer milliseconds reads as the same instant" has "$W/num.out" \
        "source routing 2 name=rpki-roa kind=vrps-covering-announced-routes count=3 observed-at=2026-10-11T03:32:36Z"
    cp "$FX/derived/observed-at-zero.json" "$W/b/manifest.json"
    L z --dir "$W/b" --now 2026-10-11T03:00:00Z 192.0.2.1
    a "M4: observedAt 0 is not-stated" has "$W/z.out" "source tor 1 name=tor-onionoo kind=relay-exit-edges count=20 observed-at=not-stated"
    a "M4: observedAt 0, the note" has "$W/z.out" "manifest.json planes[1].sources[0].observedAt: not-an-instant"
    mkdata "$W/rep" base.json reputation
    L rep --dir "$W/rep" "$REP4"
    a "M4: reputation's empty sources and string coverage" hasre "$W/rep.out" "sources=0 coverage-v4=76800 coverage-v6=0 coverage-v6-slash32s=0"
    a "M4: the writer's nulls leave the manifest read" has "$W/rep.out" "manifest state=read"
}

rowM7() {
    row M7
    mkdata "$W/d" base.json reputation
    mkd "$W/d/k"; cp "$FX/derived/keyed.json" "$W/d/k/manifest.json"
    L d --dir "$W/d" "$REP4"
    a "M7: two manifests read" eq "$(grep -c '^manifest state=read' "$W/d.out")" 2
    a "M7: the plane binds through its own tier's manifest" hasre "$W/d.out" "^plane reputation .* manifest=bound bound-to=manifest.json tier=keyless"
    a "M7: a keyed manifest read: both tiers' reasons, its own first, and no keyed member" hasre "$W/d.out" \
        "^plane routing id=4 state=absent manifest=unbound why=absent(,withheld:(BGP_CLOCK_UNKNOWN|UNPINNED|VRP_CAP_UNSET)){6} feed="
    mkdata "$W/l" legacy-only.json reputation
    L l --dir "$W/l" "$REP4"
    a "M7: bound-to on a legacy[] binding" has "$W/l.out" "manifest=bound bound-to=manifest.json"
}

rowM8() {
    row M8
    mkdata "$W/st" - reputation; cp "$PV/tenant.bin" "$W/st/"
    L st --dir "$W/st" --now $((V + 1)) "$TEN4"
    a "M8: a stale tenant plane: identity on tenant_allow" has "$W/st.out" "attr tenant_allow UNKNOWN plane=tenant why=grace:47 bounded=true identity=unchecked,revocation-not-checked"
    a "M8: and on tenant_deny" has "$W/st.out" "attr tenant_deny UNKNOWN plane=tenant why=grace:47 identity=unchecked,revocation-not-checked"
    mkdata "$W/rf" - reputation; head -c -10 "$P/tenant.bin" > "$W/rf/tenant.bin"
    L rf --dir "$W/rf" "$TEN4"
    a "M8: a refused tenant plane: identity" has "$W/rf.out" "attr tenant_allow UNKNOWN plane=tenant why=refused:truncated bounded=unknown identity=unchecked,revocation-not-checked"
    mkdata "$W/ab" - reputation
    L ab --dir "$W/ab" "$TEN4"
    a "M8: the tenant plane absent, the address judged" grep -q '^decision ' "$W/ab.out"
    a "M8: no identity with the tenant plane absent" lacks "$W/ab.out" "identity="
    mkdata "$W/fr" - reputation; cp "$P/tenant.bin" "$W/fr/"
    L s4 --dir "$W/fr" --policy "$CORE/testdata/lookup/deny-all.conf" "$TMISS" "$TEN4"
    a "M8: a step-4 decision by a rule reading no tenant attribute carries identity" \
        grep -q '^decision deny enforce=yes step=context rule=1 .*identity=unchecked,revocation-not-checked$' "$W/s4.out"
    a "M8: a step-2 decision carries identity" grep -q '^decision allow step=tenant rule=0 identity=unchecked,revocation-not-checked$' "$W/s4.out"
    L s35 --dir "$W/st" --now $((V + 1)) --policy "$CORE/testdata/lookup/deny-all.conf" "$TEN4" "$TMISS"
    a "M8: a step 3.5 decision carries identity" grep -q '^decision allow step=tenant-grace rule=0 identity=unchecked,revocation-not-checked$' "$W/s35.out"
    a "M8: every decision with the tenant plane present carries identity" \
        eq "$(grep '^decision ' "$W/s4.out" "$W/s35.out" | grep -vc 'identity=unchecked,revocation-not-checked$')" 0
}

# ======================================================================================================
# P, H, A, X, S, J rows
# ======================================================================================================
rowP5() {
    row P5
    mkdata "$W/d" - reputation
    head -c $((1024 * 1024 + 1)) /dev/zero | tr '\0' '#' > "$W/big.conf"
    JPAIR=0 L big --dir "$W/d" --policy "$W/big.conf" "$REP4"
    a "P5: a policy over 1 MiB: exit 2 naming the bound" eq "$RC $(grep -c '1 MiB' "$W/big.err")" "2 1"
    rm -f "$W/fifo.conf"; mkfifo "$W/fifo.conf"
    JPAIR=0 L fifo --dir "$W/d" --policy "$W/fifo.conf" "$REP4"
    a "P5: a FIFO policy: exit 2, not-regular" eq "$RC $(grep -c 'not-regular' "$W/fifo.err")" "2 1"
    ln -sf "$CORE/testdata/policy/default.conf" "$W/link.conf"
    JPAIR=0 L link --dir "$W/d" --policy "$W/link.conf" "$REP4"
    a "P5: a symlinked policy is read" eq "$RC" 0
}

rowP6() {
    row P6
    local c
    for c in $'http\x1b' $'http\n' $'http\xc3\xa9'; do
        JPAIR=0 L ctx --context "$c" --snapshot "$FX/interop.snap" 1.1.1.1
        a "P6: a context holding a byte outside 0x21..0x7E: exit 2" eq "$RC" 2
        a "P6: nothing on standard output" test ! -s "$W/ctx.out"
        a "P6: the message names the byte" hasre "$W/ctx.err" "holds byte 0x(1B|0A|C3); a context is printable ASCII without spaces"
    done
}

rowH2() {
    row H2
    python3 - > "$W/addrs" <<'PY'
import ipaddress
for line in open("../hold-harmless.txt", encoding="utf-8"):
    body = line.split("#", 1)[0].split()
    if body:
        print(ipaddress.ip_network(body[0]).network_address)
PY
    mapfile -t addrs < "$W/addrs"
    JPAIR=0 L all --json --snapshot "$FX/disarmed.snap" "${addrs[@]}"
    a "H2: every entry cited by an address inside it, and every cite contains its address" python3 - "$W/all.out" ../hold-harmless.txt <<'PY'
import ipaddress, json, sys
doc = json.load(open(sys.argv[1]))
entries = [l.split("#", 1)[0].split()[0] for l in open(sys.argv[2], encoding="utf-8") if l.split("#", 1)[0].split()]
cited, bad = set(), 0
for a in doc["addresses"]:
    ip = ipaddress.ip_address(a["canonical"])
    hh = a["holdHarmless"]
    if not hh["member"]:
        bad += 1
    lo, hi = (ipaddress.ip_address(x) for x in hh["range"].split("-", 1))
    bad += not (lo <= ip <= hi)
    for c in hh["cites"]:
        cited.add(c["entry"])
        bad += ip not in ipaddress.ip_network(c["entry"])
# ::ffff:0:0/96 is unreachable from an address: the module unmaps IPv4-mapped to IPv4 before step 1
mapped = ipaddress.ip_network("::ffff:0:0/96")
reachable = {e for e in entries if not (":" in e and ipaddress.ip_network(e).subnet_of(mapped))}
sys.exit(0 if bad == 0 and cited == reachable else 1)
PY
    # the tool's cite header and the evaluator's header merge the one list through two generators
    a "H2: the cite header's merged ranges are the evaluator's" python3 lookup-states.py hhagree we_hold_harmless.h we_hold_harmless_cite.h
    awk 'f && !d && sub(/0x00,0xff,0xff,0xff/, "0x00,0xff,0xff,0xfe") { d = 1 } /we_hh_ranges\[/ { f = 1 } { print }' \
        we_hold_harmless_cite.h > "$W/cite-edited.h"
    a "H2 control: the edit landed" not cmp -s we_hold_harmless_cite.h "$W/cite-edited.h"
    a "H2 control: one range's end moved fails the agreement" not python3 lookup-states.py hhagree we_hold_harmless.h "$W/cite-edited.h"
    grep -v '^    { [46], {0x' we_hold_harmless_cite.h > "$W/cite-short.h"
    a "H2 control: a cite header whose ranges were not read fails, never passes on two empty sides" \
        not python3 lookup-states.py hhagree we_hold_harmless.h "$W/cite-short.h"
    # two inputs a comparison of sets alone accepts: neither header holding a range table, and the
    # evaluator's header with one range row twice; each must be refused, and each control shows the
    # sets-alone comparison (HH_SETS_ONLY) accepting it, so the refusal is the new conditions' work
    grep -vE '^    \{ 0x|^#define WE_HH_V[46]_COUNT ' we_hold_harmless.h > "$W/eval-none.h"
    awk '{ print } /we_hh_ranges\[/ { print "};"; exit }' we_hold_harmless_cite.h > "$W/cite-none.h"
    awk '{ print } !d && /^    \{ 0x[0-9a-f]{8}u, 0x[0-9a-f]{8}u \}/ { print; d = 1 }' we_hold_harmless.h > "$W/eval-dup.h"
    a "H2 control: the doubled row landed" eq "$(( $(wc -l < "$W/eval-dup.h") - $(wc -l < we_hold_harmless.h) ))" 1
    local hc hn he hcite
    for hc in "none:$W/eval-none.h:$W/cite-none.h" "dup:$W/eval-dup.h:we_hold_harmless_cite.h"; do
        IFS=: read -r hn he hcite <<< "$hc"
        a "H2 control ($hn): the sets-alone comparison accepts it" \
            env LOOKUP_STATES_MUTANT=HH_SETS_ONLY python3 lookup-states.py hhagree "$he" "$hcite"
        a "H2 ($hn): the agreement check refuses it" not python3 lookup-states.py hhagree "$he" "$hcite"
    done
    # a doubled row the counts cannot see: the evaluator's with its header count bumped to match, and the
    # cite header's (which states no count); only the duplicate-row conditions refuse these, and the check
    # without them (HH_NO_SET_SIZE) accepts both
    awk '/^#define WE_HH_V4_COUNT / { n = $3; sub(/u$/, "", n); $3 = (n + 1) "u" } { print }' "$W/eval-dup.h" > "$W/eval-dupc.h"
    a "H2 control: the bumped count landed" grep -q "^#define WE_HH_V4_COUNT $(( $(sed -n 's/^#define WE_HH_V4_COUNT \([0-9]*\)u/\1/p' we_hold_harmless.h) + 1 ))u" "$W/eval-dupc.h"
    awk 'f && !d && /^    \{ [46], \{0x/ { a = $0; getline; print a; print; print a; print; d = 1; next }
         { print } /we_hh_ranges\[/ { f = 1 }' we_hold_harmless_cite.h > "$W/cite-dup.h"
    a "H2 control: the doubled cite row landed" eq "$(( $(wc -l < "$W/cite-dup.h") - $(wc -l < we_hold_harmless_cite.h) ))" 2
    for hc in "dup-counted:$W/eval-dupc.h:we_hold_harmless_cite.h" "cite-dup:we_hold_harmless.h:$W/cite-dup.h"; do
        IFS=: read -r hn he hcite <<< "$hc"
        a "H2 control ($hn): the check without its duplicate-row conditions accepts it" \
            env LOOKUP_STATES_MUTANT=HH_NO_SET_SIZE python3 lookup-states.py hhagree "$he" "$hcite"
        a "H2 ($hn): the agreement check refuses it" not python3 lookup-states.py hhagree "$he" "$hcite"
    done
}

rowA1() {
    row A1
    mkd "$W/plant/192.0.2.1"; : > "$W/plant/192.0.2.1/32"
    JPAIR=1 L forms --snapshot "$FX/interop.snap" 010.1.1.1 127.1 0x7f.0.0.1 ::1.2.3.4 64:ff9b::1.2.3.4 \
        'fe80::1%eth0' '2001:db8::1%abcdefghijabcdefghijabcdefghijabcdefghij' 1.2.3.4/32 1.2.3.0/24 'a=b' '"' \
        '[2001:db8::1]:443' 192.0.2.1:443 example.com. 2001:db8::443 1:2:3:4:5:6:7:443 ::ffff:192.0.2.1 $'1.2.3.4\x1b[2J'
    local o=$W/forms.out
    a "A1: a leading zero refused naming the part" has "$o" 'address 010.1.1.1 error="the part 010 has a leading zero'
    a "A1: a short form refused naming the four parts" has "$o" 'address 127.1 error="a short or numeric IPv4 form; give all four parts, 127.0.0.1"'
    a "A1: a hex form refused naming the four parts" has "$o" 'give all four parts, 127.0.0.1"'
    a "A1: ::1.2.3.4 stays family 6" has "$o" "address ::1.2.3.4 family=6 canonical=::102:304"
    a "A1: NAT64 stays family 6" has "$o" "address 64:ff9b::1.2.3.4 family=6 canonical=64:ff9b::102:304"
    a "A1: NAT64 with the note" has "$o" 'note "the embedded IPv4 address is not looked up"'
    a "A1: a zone stripped with a note" has "$o" 'note "the zone %eth0 is not part of the address and was stripped"'
    a "A1: a 40-byte zone stripped" has "$o" "family=6 canonical=2001:db8::1"
    a "A1: /32 is the address" has "$o" "address 1.2.3.4/32 family=4 canonical=1.2.3.4"
    a "A1: a prefix refused with its first address" has "$o" 'address 1.2.3.0/24 error="a prefix is many addresses; give one, for example its first, 1.2.3.0"'
    a "A1: odd input quoted as one positional" has "$o" 'address "a=b" error='
    a "A1: a quote rendered inside a quoted positional" has "$o" 'address "\x22" error='
    a "A1: a bracketed port refused with the address" has "$o" 'error="a port is not part of the address; give 2001:db8::1"'
    a "A1: a dotted-quad port refused with the address" has "$o" 'error="a port is not part of the address; give 192.0.2.1"'
    a "A1: a trailing-dot host name gets the host name refusal" has "$o" 'address example.com. error="example.com. is a hostname; resolve it first and give its addresses"'
    a "A1: 2001:db8::443 is an address" has "$o" "address 2001:db8::443 family=6"
    a "A1: 1:2:3:4:5:6:7:443 is an address" has "$o" "address 1:2:3:4:5:6:7:443 family=6"
    a "A1: IPv4-mapped is IPv4" has "$o" "address ::ffff:192.0.2.1 family=4 canonical=192.0.2.1"
    JPAIR=1 L zp --snapshot "$FX/interop.snap" '2001:db8::%x/32' 'fe80::1%eth0/64' 'fe80::1%eth0/128' '1.2.3.4%e/32' \
        010.1.1.1/32 '[a"b c]:80' '1.2.3.4 junk' 64:ff9b:1::1.2.3.4
    o=$W/zp.out
    a "A1: a zone then a /32 on IPv6 is a prefix" has "$o" 'address 2001:db8::%x/32 error="a prefix is many addresses; give one, for example its first, 2001:db8::"'
    a "A1: a zone then /64 is a prefix" has "$o" 'address fe80::1%eth0/64 error="a prefix is many addresses; give one, for example its first, fe80::"'
    a "A1: a zone then /128 is the address" has "$o" "address fe80::1%eth0/128 family=6 canonical=fe80::1"
    a "A1: a zone on IPv4 before a prefix length refused" has "$o" 'error="a zone applies only to an IPv6 address; give 1.2.3.4"'
    a "A1: a leading zero before a prefix length named" has "$o" 'address 010.1.1.1/32 error="the part 010 has a leading zero'
    a "A1: a bracketed non-address with a port is no address" has "$o" 'address "[a\x22b c]:80" error="not an IPv4 or IPv6 address"'
    a "A1: inner junk after four parts is no address" has "$o" 'address "1.2.3.4 junk" error="not an IPv4 or IPv6 address"'
    a "A1: RFC 8215's local-use NAT64 prefix is an address" has "$o" "address 64:ff9b:1::1.2.3.4 family=6"
    a "A1: and carries the note, in its own block" in_block "$o" 64:ff9b:1::1.2.3.4 \
        'note "the embedded IPv4 address is not looked up"'
    JPAIR=1 L lens --snapshot "$FX/interop.snap" 'fe80::1%x/00000000000000000000000000000128' \
        2001:db8::/000000000000000000000000000000000000128 '[2001:db8::1]/128' '[2001:db8::]/64'
    o=$W/lens.out
    a "A1: a long prefix length after a zone reads as it does without one" has "$o" \
        "address fe80::1%x/00000000000000000000000000000128 family=6 canonical=fe80::1"
    a "A1: and without a zone" has "$o" "address 2001:db8::/000000000000000000000000000000000000128 family=6 canonical=2001:db8::"
    a "A1: a bracketed address with a prefix length is the address" has "$o" "address [2001:db8::1]/128 family=6 canonical=2001:db8::1"
    JPAIR=1 L plen --snapshot "$FX/interop.snap" 1.2.3.4/0000000033 ::1/0000000000129 1.2.3.4/123456789012
    a "A1: a zero-padded over-width length quotes the length read" has "$W/plen.out" \
        'address 1.2.3.4/0000000033 error="a prefix length of 33 is longer than an IPv4 address'"'"'s 32 bits"'
    a "A1: on IPv6 too" has "$W/plen.out" \
        'address ::1/0000000000129 error="a prefix length of 129 is longer than an IPv6 address'"'"'s 128 bits"'
    a "A1: a 12-digit length says how many digits, never a cut number" has "$W/plen.out" \
        'address 1.2.3.4/123456789012 error="a prefix length of 12 digits is longer than an IPv4 address'"'"'s 32 bits"'
    a "A1: a bracketed prefix is a prefix, with its fix" has "$o" \
        'address [2001:db8::]/64 error="a prefix is many addresses; give one, for example its first, 2001:db8::"'
    JPAIR=1 L minors --snapshot "$FX/interop.snap" 1.2.3.4/032 ::1/0128 1.2.3.4/33 1.2.3.4. 1.2.3.4%eth0 'fe80::1%'
    o=$W/minors.out
    a "A1: /032 is /32" has "$o" "address 1.2.3.4/032 family=4 canonical=1.2.3.4"
    a "A1: /0128 is /128" has "$o" "address ::1/0128 family=6 canonical=::1"
    a "A1: a prefix length past the family's width named" has "$o" 'error="a prefix length of 33 is longer than an IPv4 address'"'"'s 32 bits"'
    a "A1: a trailing dot after an IPv4 address gets its fix" has "$o" 'error="a trailing dot after an IPv4 address; give 1.2.3.4"'
    a "A1: a zone on an IPv4 address refused" has "$o" 'error="a zone applies only to an IPv6 address; give 1.2.3.4"'
    a "A1: an empty zone refused" has "$o" 'error="an empty zone; give the address without the %"'
    JPAIR=0 L missing "$W/no-such-dir/snap.bin" 1.1.1.1
    a "A1: a mistyped snapshot path exits 2 naming it, before any output" eq "$RC $(wc -c < "$W/missing.out")" "2 0"
    a "A1: the message names the path" has "$W/missing.err" "no-such-dir/snap.bin names no regular file"
    JPAIR=0 L jf --json --fields --snapshot "$FX/interop.snap" 1.1.1.1
    a "A1: --json with --fields refused, nothing printed" eq "$RC $(wc -c < "$W/jf.out")" "2 0"
    a "A1: an ESC in an address rendered" has "$W/forms.out" 'address "1.2.3.4\x1B[2J" error='
    JPAIR=0 L esc --mode $'x\x1b[2J' 1.1.1.1
    a "A1: nothing outside 0x20..0x7E on standard error" python3 -c \
        "import sys; d=open(sys.argv[1],'rb').read(); sys.exit(0 if all(0x20<=b<0x7f or b==10 for b in d) and d else 1)" "$W/esc.err"
    mkd "$W/empty"
    ( cd "$W/plant" && WHISPER_EDGE_DIR="$W/empty" WHISPER_EDGE_ETC="$W/empty" timeout 60 "$T" 192.0.2.1/32 1.1.1.1 \
        > "$W/plant.out" 2>/dev/null )
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 2))
    a "A1: a planted file named like an address is an address" has "$W/plant.out" "address 192.0.2.1/32 family=4 canonical=192.0.2.1"
}

rowA2() {
    row A2
    JPAIR=0 L v --snapshot "$FX/interop.snap" 2001:0db8:0000:0000:0001:0000:0000:0001 2001:db8:0:1:1:1:1:1 2001:DB8::1 \
        2001:db8:0:0:1:0:0:1 2001:db8::1:0:0:1 ::1.2.3.4 0:0:0:0:0:0:0:1
    local o=$W/v.out
    a "A2: the longest run, the leftmost on a tie" has "$o" "address 2001:0db8:0000:0000:0001:0000:0000:0001 family=6 canonical=2001:db8::1:0:0:1"
    a "A2: one zero group is not shortened" has "$o" "canonical=2001:db8:0:1:1:1:1:1"
    a "A2: lower case" has "$o" "address 2001:DB8::1 family=6 canonical=2001:db8::1"
    a "A2: no mixed notation outside ::ffff:0:0/96" has "$o" "address ::1.2.3.4 family=6 canonical=::102:304"
    a "A2: ::1" has "$o" "canonical=::1"
}

rowX1() {
    row X1
    python3 make-test-snapshot.py "$W/v.snap" 5 0 3 > /dev/null
    L allow --snapshot "$W/v.snap" 1.1.1.1
    a "X1: allow: exit 0" eq "$RC" 0
    L deny --snapshot "$W/v.snap" --mode deny 127.0.0.1
    a "X1: an enforced deny: exit 1" eq "$RC" 1
    L log --snapshot "$W/v.snap" 127.0.0.1
    a "X1: a mode-log deny outside the old form: exit 0" eq "$RC" 0
    JPAIR=0 L typo --snapshot "$W/v.snap" --mode deny 127.0.0.1 127.0.0.01x
    a "X1: a typo and a deny: exit 2" eq "$RC" 2
    L old "$W/v.snap" 127.0.0.1
    a "X1: the old form on a fresh high listing: log would-deny, exit 1" eq "$(grep -c '^decision log would-deny=yes' "$W/old.out") $RC" "1 1"
    python3 make-test-snapshot.py "$W/s.snap" 5 1 3 > /dev/null
    L stale "$W/s.snap" 127.0.0.1
    a "X1: the old form on a stale snapshot: exit 0" eq "$RC" 0
    local j
    for j in "" --json; do
        [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
        timeout 60 "$T" $j --snapshot "$W/v.snap" 1.1.1.1 > /dev/full 2> "$W/full.err"
        RC=$?
        a "X1: standard output to /dev/full${j:+ with $j}: exit 2" eq "$RC" 2
        a "X1: /dev/full: the message" has "$W/full.err" "cannot write output"
    done
    L ul --dir "$P" --policy "$CORE/testdata/policy/accept/11-is-unknown-in-log-rules.policy" --context http/server:a 1.1.1.2
    a "X1: a fired log rule: exit 0" eq "$RC" 0
    L none --dir "$P" --policy none 1.1.1.2
    a "X1: --policy none: exit 0" eq "$RC" 0
    "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -DWE_LOOKUP_TEST_K3_PLANT ${MUTMACRO:+"-D$MUTMACRO"} \
        -o "$W/k3" we_lookup_cli.c "$TOOLOBJ"/*.o 2> "$W/cc.err"
    M=$((M + 1))
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 "$W/k3" --json --dir "$P" --now "$V" 1.1.1.1 1.1.1.2 > "$W/k3.json" 2> "$W/k3.err"
    RC=$?
    a "X1: the K3 build with --json: exit 2" eq "$RC" 2
    a "X1: the K3 build's document is closed and parses" python3 -c "import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if len(d['addresses']) == 1 else 1)" "$W/k3.json"
}

rowS1() {
    row S1
    mkdata "$W/m" base.json reputation tor
    mkdata "$W/n" - reputation tor
    mapfile -t many < <(python3 -c "print('\n'.join('10.%d.%d.%d' % (i >> 16, (i >> 8) & 255, i & 255) for i in range(1000)))")
    local mode k
    for mode in m n; do
        for k in 1 1000; do
            rm -f "$W/cnt".*
            [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + k))
            timeout 60 env LD_PRELOAD="$FX/lookup_shim.so" \
                LOOKUP_SHIM_PATHS="$W/$mode/reputation.bin:$W/$mode/tor.bin:$W/$mode/manifest.json" LOOKUP_SHIM_OUT="$W/cnt" \
                "$T" --dir "$W/$mode" --now $V "${many[@]:0:$k}" > /dev/null 2> "$W/$mode-$k.err"
            a "S1 $mode $k: each present plane opened 6 times (probe, load, the module's check: its probe, header and trust open; probe)" eq "$(grep -c '^open 6 .*\.bin$' "$(cntfile)")" 2
            if [ $mode = m ]; then
                a "S1 $mode $k: the manifest opened once" has "$(cntfile)" "open 1 $W/m/manifest.json"
            fi
            sed -n 's/.*hashed-bytes=\([0-9]*\)$/\1/p' "$W/$mode-$k.err" > "$W/$mode-$k.hb"
        done
        a "S1 $mode: both runs print a decimal hashed-bytes" bash -c "grep -qx '[0-9][0-9]*' '$W/$mode-1.hb' && grep -qx '[0-9][0-9]*' '$W/$mode-1000.hb'"
        a "S1 $mode: hashed-bytes equal at 1 and at 1,000 addresses" cmp -s "$W/$mode-1.hb" "$W/$mode-1000.hb"
    done
    local want
    want=$(( $(stat -c %s "$W/m/reputation.bin") + $(stat -c %s "$W/m/tor.bin") ))
    a "S1: with a manifest minus without equals the armed planes' bytes ($want)" \
        eq "$(( $(cat "$W/m-1.hb") - $(cat "$W/n-1.hb") ))" "$want"
    # the legacy model: one load, whatever the address count
    rm -f "$W/cnt".*
    [ "$MODE" = normal ] && I=$((I + 2)) && C=$((C + 1001))
    timeout 60 "$T" --snapshot "$FX/interop.snap" --now $V 1.1.1.1 > /dev/null 2> "$W/l1.err"
    timeout 60 "$T" --snapshot "$FX/interop.snap" --now $V "${many[@]}" > /dev/null 2> "$W/l1000.err"
    a "S1 legacy: both runs print a decimal hashed-bytes" bash -c "grep -q 'hashed-bytes=[0-9][0-9]*\$' '$W/l1.err' && grep -q 'hashed-bytes=[0-9][0-9]*\$' '$W/l1000.err'"
    a "S1 legacy: hashed-bytes equal at 1 and at 1,000 addresses" eq "$(sed -n 's/.*hashed-bytes=//p' "$W/l1.err")" "$(sed -n 's/.*hashed-bytes=//p' "$W/l1000.err")"
    # (c) the compiler's interning is counted. Two policies of equal directive bytes, so the tool's own
    # policy digest hashes the same number of bytes for both: one adds a distinct, larger block, the other
    # a block that interns to the http block already built. Only the interning digest, over each block it
    # is given, tells the two apart.
    local base='policy http deny if listed >= high'
    local dis='policy http/server:a deny if tor_exit or c2 or spam or proxy'
    local same='policy http/server:bbbbbbbbbbbbbbbbbb deny if listed >= high'
    a "S1: the two policies' added directives are equal in bytes (${#dis} and ${#same})" eq "${#dis}" "${#same}"
    printf '%s\x1e\n%s\x1e\n' "$base" "$dis" > "$W/distinct.policy"
    printf '%s\x1e\n%s\x1e\n' "$base" "$same" > "$W/interned.policy"
    JPAIR=0 L distinct --dir "$W/n" --now "$V" --policy "$W/distinct.policy" 1.1.1.1
    JPAIR=0 L interned --dir "$W/n" --now "$V" --policy "$W/interned.policy" 1.1.1.1
    local hd hi
    hd=$(sed -n 's/.*hashed-bytes=\([0-9][0-9]*\)$/\1/p' "$W/distinct.err")
    hi=$(sed -n 's/.*hashed-bytes=\([0-9][0-9]*\)$/\1/p' "$W/interned.err")
    a "S1: both runs print a hashed-bytes count" test -n "$hd" -a -n "$hi"
    a "S1: a distinct block raises hashed-bytes over an interned one at equal directive bytes ($hd against $hi)" \
        test "${hd:-0}" -gt "${hi:-0}"
}

rowJ1() {
    row J1
    mkdata "$W/d" withheld-reputation-two.json reputation
    cp "$PV/tenant.bin" "$W/d/"
    head -c -10 "$P/anonymizer.bin" > "$W/d/anonymizer.bin"
    L j1 --dir "$W/d" --now $((V + 1)) "$REP4" "a=b" "$TEN4"
    L j1-legacy --snapshot "$FX/interop.snap" --now $V 192.0.2.0 not-an-address
    L j1-ctx --dir "$P" --policy default --context $'http\x1b' "$REP4"
    a "J1: a context holding a byte outside 0x21..0x7E: exit 2, nothing printed" eq "$RC $(wc -c < "$W/j1-ctx.out")" "2 0"
    # the --case and --fields modes print no address line: a refused address's reason goes to stderr
    JPAIR=0 L case-host --case --dir "$P" --policy default example.com
    a "J1: --case on a host name: exit 2" eq "$RC" 2
    a "J1: --case on a host name: the fix on stderr" has "$W/case-host.err" "example.com: example.com is a hostname; resolve it first"
    JPAIR=0 L fields-prefix --fields --dir "$P" 1.2.3.0/24
    a "J1: --fields on a prefix: exit 2" eq "$RC" 2
    a "J1: --fields on a prefix: the fix on stderr" has "$W/fields-prefix.err" "a prefix is many addresses; give one, for example its first, 1.2.3.0"
    a "J1: --case says it judged nothing" has "$W/case-host.err" "not judged (--case)"
}

rowJ2() {
    row J2
    local base=$W/x
    rm -rf "$W/x"*
    local d1002 d1003
    # a path of exactly n bytes, in components a file system takes (at most 200 bytes each)
    long_path() { python3 -c "
import sys
out, n = sys.argv[1], int(sys.argv[2])
while n - len(out) > 202:
    out += '/' + 'a' * 200
print(out + '/' + 'a' * (n - len(out) - 1))" "$1" "$2"; }
    d1002=$(long_path "$base" 1002)
    d1003=$(long_path "$base" 1003)
    a "J2: the paths are 1,002 and 1,003 bytes" eq "${#d1002} ${#d1003}" "1002 1003"
    mkd "$d1002"
    JPAIR=0 L d1002 --dir "$d1002" 1.1.1.1
    a "J2: a 1,002-byte --dir is accepted" eq "$RC" 0
    JPAIR=0 L d1003 --dir "$d1003" 1.1.1.1
    a "J2: a 1,003-byte --dir exits 2 naming the bound" eq "$RC $(grep -c '1,002 bytes' "$W/d1003.err")" "2 1"
    local odd="$W/odd dir \"q\" "$'\x1b'
    mkdata "$odd" base.json reputation
    L odd --dir "$odd" "$REP4"
    a "J2: an odd directory renders identically in both forms" test -s "$W/odd.json"
}

rowJ3() {
    row J3
    local g
    for g in 9007199254740991 9007199254740992 18446744073709551615; do
        mkd "$W/g$g"
        python3 make-test-snapshot.py --plane reputation --out "$W/g$g/reputation.bin" --format 1 --v4-index none \
            --v6-index none --schema --generation $g --valid-until $g > /dev/null
        chmod 444 "$W/g$g/reputation.bin"
        L g$g --dir "$W/g$g" --now 0 1.1.1.1
        a "J3: generation $g is a decimal string in JSON" has "$W/g$g.json" "\"generation\":\"$g\""
    done
    a "J3: valid_until 2^64 - 1 prints ms:" has "$W/g18446744073709551615.out" "valid-until=ms:18446744073709551615"
    JPAIR=1 L max --now 253402300799999 --snapshot "$FX/interop.snap" 1.1.1.1
    a "J3: --now at the last millisecond of 9999" has "$W/max.out" "now=9999-12-31T23:59:59.999Z"
    local t
    for t in 2026-10-13T08:00:00.000Z 2026-10-13T08:00:00.100Z 2026-10-13T08:00:00.123Z; do
        L ms --now "$t" --snapshot "$FX/interop.snap" 1.1.1.1
        a "J3: --now $t" has "$W/ms.out" "now=${t/.000Z/Z}"
    done
    for t in 253402300800000 1970-01-01T00:00:00+00:01 9999-12-31T23:59:59-00:01 9999-12-31T23:59:60Z; do
        JPAIR=0 L now-bad --now "$t" --snapshot "$FX/interop.snap" 1.1.1.1
        a "J3: --now $t is out of range: exit 2" eq "$RC" 2
    done
    mkd "$W/badcov"; cp "$WR/keyless/reputation.bin" "$W/badcov/"; chmod 444 "$W/badcov/reputation.bin"
    sed 's/"v4Addresses":"76800"/"v4Addresses":"1e5"/' "$FX/derived/base.json" > "$W/badcov/manifest.json"
    L badcov --dir "$W/badcov" "$REP4"
    a "J3: a count string outside its grammar prints not-stated" has "$W/badcov.out" "coverage-v4=not-stated"
    L secs --now 1791792000 --snapshot "$FX/interop.snap" 1.1.1.1
    a "J3: an integer --now below 10^12: the epoch-seconds note" has "$W/secs.out" "if that was epoch seconds, give 1791792000000"
    mkdata "$W/cov" coverage-large.json reputation
    L cov --dir "$W/cov" "$REP4"
    a "J3: a coverage above 2^53 stays a decimal string" has "$W/cov.json" '"coverageV6":"4722366482869645213696"'
    a "J3: a negative age is the signed form" python3 - "$W/cov.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if isinstance(d["manifests"][0]["age"], str) else 1)
PY
    L asn --dir "$P" --now 1 "$(awk '$3 != "-" && $1 == "4" { print $2; exit }' "$P/routing.expect")" 1.0.0.1
    a "J3: a definite asn is a string, an unknown one null" python3 - "$W/asn.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
vals = [at["value"] for a in d["addresses"] for at in a["attributes"] if at["name"] == "asn"]
sys.exit(0 if vals and all(isinstance(v, str) for v in vals) and "64496" in vals else 1)
PY
}

rowJ4() {
    row J4
    local F4=${FMB:-$FM}
    local jrc=0
    timeout 60 "$F4" "$FX/seeds/"*.json > "$W/c.raw" 2> "$W/c.err" || jrc=$?
    a "J4: the C reader replays every seed under the sanitizers inside 60 s (exit $jrc)" test "$jrc" -eq 0
    timeout 60 python3 lookup-check.py manifest "$FX/seeds/"*.json > "$W/py.raw"
    # a seed with several defects is refused by both, and which defect each names first is its own
    verdict_only() { awk '/^seed / { multi = ($2 ~ /^multi-/) } multi && /^result refuse:/ { print "result refuse"; next } { print }' "$1"; }
    verdict_only "$W/c.raw" > "$W/c.txt"
    verdict_only "$W/py.raw" > "$W/py.txt"
    a "J4: every seed's verdict and every extracted field equal the reference reader's" cmp -s "$W/c.txt" "$W/py.txt"
    a "J4: every multi-defect seed refused by the C reader" \
        eq "$(grep -c '^seed multi-' "$W/c.txt")" "$(grep -A1 '^seed multi-' "$W/c.txt" | grep -c '^result refuse$')"
    if [ "$MODE" = normal ]; then
        local s v
        for s in cap-depth-32:accept cap-depth-33:refuse:too-deep cap-members-1024:accept cap-members-1025:refuse:too-wide \
                 cap-elements-4096:accept cap-elements-4097:refuse:too-wide cap-key-256:accept cap-key-257:refuse:too-long \
                 cap-size-1MiB:accept cap-size-1MiB+1:refuse:too-large cap-depth-1e6:refuse:too-large \
                 cap-depth-1e6-under-size:refuse:too-deep dup-sha256:refuse:duplicate-key:sha256 \
                 dup-unread-object:refuse:duplicate-key:sha256 dup-escaped-name:refuse:duplicate-key:sha256 \
                 dup-unread-name:accept nul-in-element:refuse:nul surrogate-in-element:refuse:lone-surrogate \
                 nul-in-key:refuse:nul surrogate-in-key:refuse:lone-surrogate bom:refuse:bom utf16:refuse:nul-byte \
                 trailing:refuse:trailing-bytes raw-tab:refuse:control-byte overlong:refuse:bad-utf8 cesu:refuse:bad-utf8 \
                 nan:refuse:syntax infinity:refuse:syntax leading-zero:refuse:syntax plus-one:refuse:syntax \
                 number-cut-dot:refuse:syntax number-cut-exp:refuse:syntax; do
            v=${s#*:}
            a "J4: seed ${s%%:*} is ${v/:/ }" python3 - "$W/c.txt" "${s%%:*}" "$v" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
i = lines.index("seed %s.json" % sys.argv[2])
want = "result accept" if sys.argv[3] == "accept" else "result refuse:" + sys.argv[3].split(":", 1)[1]
sys.exit(0 if lines[i + 1] == want else 1)
PY
        done
        for s in count-space count-neg count-exp count-lead0 count-lspace count-empty count-2-128-plus1 count-40digits; do
            a "J4: $s is not-a-count" has "$W/c.txt" "fieldnote planes[0].coverage.v4Addresses not-a-count"
        done
        a "J4: 2^128 is a count" python3 -c "import sys; t=open(sys.argv[1]).read().split('seed count-2-128.json')[1].split('seed ')[0]; sys.exit(0 if 'not-a-count' not in t and '340282366920938463463374607431768211456' in t else 1)" "$W/c.txt"
        a "J4: reserved tokens refused" eq "$(grep -c '^fieldnote builder reserved-token' "$W/c.txt")" 3
        a "J4: a small integer under an At key is not-an-instant" has "$W/c.txt" "fieldnote builtAt not-an-instant"
        a "J4: a reason A,B is a bad token" has "$W/c.txt" "fieldnote withheld[0].reason bad-token"
        a "J4: a repeated reason read once" has "$W/c.txt" "withheld 0 name=tor reasons=LOW_RECALL,SOURCE_STALE reason=LOW_RECALL"
        a "J4: a second withheld entry for one plane named" has "$W/c.txt" "fieldnote withheld[1].name duplicate-entry-ignored"
        a "J4: an exponent under a time key is not an instant" python3 -c "import sys; t=open(sys.argv[1]).read().split('seed time-exp-integer.json')[1].split('seed ')[0]; sys.exit(0 if 'fieldnote builtAt not-an-instant' in t else 1)" "$W/c.txt"
        a "J4: an impossible date refused" python3 -c "import sys; t=open(sys.argv[1]).read().split('seed mday-2026-02-30.json')[1].split('seed ')[0]; sys.exit(0 if 'builtAt=refused' in t else 1)" "$W/c.txt"
        # the reference reader's own controls: each cap removed, and a walk over values only
        local cap
        for cap in depth members elements key size; do
            python3 lookup-check.py manifest --no-cap=$cap "$FX/seeds/"*.json > "$W/nocap.txt"
            a "J4 control: a reference reader without the $cap cap disagrees" not cmp -s "$W/nocap.txt" "$W/c.txt"
        done
        python3 lookup-check.py manifest --values-only "$FX/seeds/"*.json > "$W/vo.txt"
        a "J4 control: a reference reader walking values only fails the key seeds" not cmp -s "$W/vo.txt" "$W/c.txt"
    fi
}

rowX3() {
    row X3
    local files
    mapfile -t files < <(python3 lookup-states.py files)
    a "X3: the hygiene list names files" test "${#files[@]}" -gt 0
    local f missing=
    for f in "${files[@]}"; do [ -f "../$f" ] || missing="$missing $f"; done
    a "X3: every file the hygiene list names exists:${missing:- all}" test -z "$missing"
    ( cd .. && grep -nE '#[0-9]{3,}|\bWB[0-9]+\b|\bround [0-9]|\bR[0-9]+ row' "${files[@]}" ) > "$W/hits" 2>/dev/null
    a "X3: no tracker number, planning or review reference in the files this work adds: $(head -1 "$W/hits")" test ! -s "$W/hits"
    "$T" --help > "$W/help" 2>/dev/null
    a "X3: --help is clean" bash -c "! grep -qE '#[0-9]{3,}|\\bWB[0-9]+\\b' '$W/help'"
}

# ======================================================================================================
# The differential (part 2): the tool's lines against both evaluators', over the gate's own restatement
# of every request (lookup-states.py restate, never the tool's --case), with the records the writer packed
# ======================================================================================================

# plan <file> <line>...: write a plan, one tab-separated line per invocation:
#   id, dir (the snapshot file under legacy:), policy (a path, sugar:<threshold>:<mode>, or
#   legacy:<threshold>:<mode>:<prestage> for --snapshot), context, now, flags (plain, acme, skipped-hop),
#   the states the gate installed (<plane>=fresh|stale|refused, comma-separated), the ranges directory,
#   and the addresses
plan() { local f=$1; shift; printf '%s\n' "$@" > "$f"; }
pline() { local IFS=$'\t'; echo "$*"; }

# runplan <plan> <out-dir> [first-batch]: each line's normal run and --case run with the tool under test
runplan() {
    local planf=$1 out=$2 id d prog ctx now flag addrs
    mkdir -p "$out"
    while IFS=$'\t' read -r id d prog ctx now flag _ _ addrs; do
        local args=(--dir "$d" --now "$now" --context "$ctx") al lthr lmode lpre
        case $prog in
            sugar:*) ;;
            legacy:*)
                IFS=: read -r _ lthr lmode lpre <<< "$prog"
                args=(--snapshot "$d" --now "$now" --context "$ctx" --threshold "$lthr" --mode "$lmode" --prestage "$lpre") ;;
            *) args+=(--policy "$prog") ;;
        esac
        case $flag in acme) args+=(--acme) ;; skipped-hop) args+=(--skipped-hop) ;; esac
        read -ra al <<< "$addrs"
        if [ "$MODE" = normal ]; then I=$((I + 2)); C=$((C + ${#al[@]})); fi
        timeout 60 "$T" "${args[@]}" "${al[@]}" > "$out/$id.out" 2> "$out/$id.err"
        timeout 60 "$T" --case "${args[@]}" "${al[@]}" > "$out/$id.case" 2>/dev/null
        if [ "${JPAIR_PLAN:-0}" = 1 ] && [ "$MODE" = normal ]; then
            I=$((I + 1))
            timeout 60 "$T" --json "${args[@]}" "${al[@]}" > "$out/$id.json" 2>/dev/null
            printf '%s %s\n' "$out/$id.json" "$out/$id.out" >> "$out/docs.list"
        fi
    done < "$planf"
}

# judgeplan <row> <plan> <out-dir> <cache-dir> [--first]
judgeplan() {
    TEST_POLICY=$FX/test_policy python3 lookup-states.py judge "$2" "$3" "$4" ${5:+"$5"} > "$3/judge.txt" 2>&1
    a "$1: the tool's lines equal both evaluators': $(grep -m1 '^FAIL' "$3/judge.txt" | cut -c1-300)" \
        grep -q ' 0 failures$' "$3/judge.txt"
}

# the one critical-listed reputation address, IPv4, and a hit on any plane
crit() { awk '$3 != "-" && $1 == "4" && $5 == "fields=sev=4" { print $2; exit }' "$P/reputation.expect"; }

rowO1() {
    row O1
    local cache=$OUT/normal/O1/cache
    # the fixed cases first: the NOW_CLOCK state, and a program whose floor and context both read an out
    # plane, fresh (a floor deny: step 3's arm) and stale (both dependents lines)
    a "O1: the NOW_CLOCK plane's valid_until_ms (1) is below the clock" test "$(date +%s%3N)" -gt 1
    mkd "$W/nc"; python3 make-test-snapshot.py --plane reputation --out "$W/nc/reputation.bin" --format 1 \
        --v4-index radix-16 --v6-index radix-16 --schema --valid-until 1 > /dev/null; chmod 444 "$W/nc/reputation.bin"
    mkd "$W/fcf"; cp "$P/reputation.bin" "$W/fcf/"; mkd "$W/fcs"; cp "$PV/reputation.bin" "$W/fcs/"
    chmod 444 "$W/fcf/reputation.bin" "$W/fcs/reputation.bin"
    local FC=$CORE/testdata/lookup/floor-and-ctx.policy FL=$CORE/testdata/lookup/floor-log-ctx-decides.policy
    plan "$W/fixed.tsv" \
        "$(pline nowclock "$W/nc" "$CORE/testdata/policy/default.conf" http 0 plain reputation=fresh "$P" "$(crit) 192.0.2.1")" \
        "$(pline floorfresh "$W/fcf" "$FC" http "$V" plain reputation=fresh "$P" "$(crit) 1.1.1.1")" \
        "$(pline floorstale "$W/fcs" "$FC" http $((V + 1)) plain reputation=stale "$P" "$(crit)")" \
        "$(pline floorlog "$W/fcf" "$FL" http "$V" plain reputation=fresh "$P" "$(crit)")"
    runplan "$W/fixed.tsv" "$W/fixed"
    judgeplan "O1 fixed cases" "$W/fixed.tsv" "$W/fixed" "$W/fixed-cache" --first
    if [ "$MODE" = normal ]; then
        a "O1: the floor and the context both print a dependents line on the stale plane" \
            eq "$(grep -c '^dependents ' "$W/fixed/floorstale.out")" 2
        a "O1: step 3's arm: a floor verdict" grep -q '^verdict step=3 action=deny program=floor rule=1 ' "$W/fixed/floorfresh.out"
    fi
    a "O1: a floor deny downgraded by mode log, context rule 2 deciding: rule and text are the decider's" \
        grep -qx 'decision log would-deny=yes step=context rule=2 text="allow if listed >= low" log=floor:1,ctx:1 would-deny-rule=floor:1 would-deny-text="deny if listed >= high"' \
        "$W/fixed/floorlog.out"
    # a context the oracle kinds cannot carry never reaches a case block
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 "$T" --case --dir "$W/fcf" --policy "$FC" --context $'http\x1b' --now "$V" "$(crit)" > "$W/ctxcase.out" 2> "$W/ctxcase.err"
    RC=$?
    a "O1: a context outside 0x21..0x7E never reaches a case block" test ! -s "$W/ctxcase.out"
    a "O1: it is refused, exit 2 (exit $RC)" eq "$RC" 2
    a "O1: naming the byte" has "$W/ctxcase.err" "holds byte 0x1B"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 "$T" --case --dir "$W/fcf" --policy "$FC" --context http --now "$V" "$(crit)" > "$W/ctxcase-ok.out" 2>/dev/null
    a "O1: the same run with context http prints a case block" grep -q '^case ' "$W/ctxcase-ok.out"
    # the 956 states of the 22 programs, plain flags
    grep -P '\tplain\t' "$FX/o1/plan.tsv" > "$W/plain.tsv"
    grep -P '\tplain\t' "$FX/o1/plan-rr.tsv" > "$W/plain-rr.tsv"
    if [ "$MODE" = normal ]; then
        rm -f "$W/t/docs.list"
        JPAIR_PLAN=1 runplan "$W/plain.tsv" "$W/t"
        judgeplan O1 "$W/plain.tsv" "$W/t" "$cache"
        python3 lookup-check.py docs "$W/t/docs.list" > "$W/docs.txt" 2>&1
        a "J1 over O1: the two forms of every run agree: $(grep -m1 '^FAIL' "$W/docs.txt")" \
            grep -q ' 0 failures$' "$W/docs.txt"
        # the counts held three ways: the generator, a second derivation from the parameter table alone,
        # and the figures pinned at implementation; each planted generator defect must move them
        local gen der pin m mc wi wc
        gen=$(python3 lookup-states.py ocounts "$P"); der=$(python3 lookup-states.py oderived)
        pin=$(python3 lookup-states.py opinned)
        read -r wi wc _ _ <<< "$gen"
        a "O1: $wi invocations and $wc cases, the generator's" \
            grep -q "^judged $wi invocations, $wc cases;" "$W/t/judge.txt"
        a "O1: the derivation's totals with O4's are 1,000 invocations" eq "$(awk '{ print $1 + $3 }' <<< "$gen")" 1000
        a "O1: the generator's counts ($gen) are four decimals" counts4 "$gen"
        a "O1: equal to the derivation's ($der)" eq "$gen" "$der"
        a "O1: and the pinned counts ($pin)" eq "$gen" "$pin"
        for m in DROP_STATE DOUBLE_ADDRS DROP_ABSENT; do
            mc=$(LOOKUP_STATES_MUTANT=$m python3 lookup-states.py ocounts "$P")
            a "O1 control: a generator with $m answers ($mc)" counts4 "$mc"
            a "O1 control: and fails the counts" not eq "$mc" "$pin"
        done
        a "O1: the reputation addresses are critical listings, so every listing rule matches them" sev4
        a "O1 control: a generator choosing severity-1 addresses fails that" not sev4 SEV1_ONLY
        a "O1: step 3's arm reached in the fixed cases, counted by the oracle's verdicts" \
            grep -q 'step=3 program=floor [1-9]' "$W/fixed/judge.txt"
    else
        # each mutant walks the states program by program, in batches, and stops at its first difference
        rm -rf "$W/rr"; mkd "$W/rr"
        split -l 25 -d -a 3 "$W/plain-rr.tsv" "$W/rr/b"
        local b
        for b in "$W"/rr/b*; do
            [ "$RF" -gt 0 ] && break
            runplan "$b" "$W/t"
            TEST_POLICY=$FX/test_policy python3 lookup-states.py judge "$b" "$W/t" "$cache" --first > "$b.judge" 2>&1 \
                || bad "O1: a batch differs"
        done
    fi
}

rowO4() {
    row O4
    local cache=$OUT/normal/O4/cache
    grep -vP '\tplain\t' "$FX/o1/plan.tsv" > "$W/flags.tsv"
    # the floor program under both flags: past a skipped hop a member is judged by the floor (step 3),
    # and ACME exempts a critical listing the floor would deny
    mkd "$W/fc"; cp "$P/reputation.bin" "$W/fc/"; chmod 444 "$W/fc/reputation.bin"
    local FC=$CORE/testdata/lookup/floor-and-ctx.policy
    plan "$W/fixed.tsv" \
        "$(pline hop "$W/fc" "$FC" http "$V" skipped-hop reputation=fresh "$P" "$(crit) 192.0.2.1")" \
        "$(pline acme "$W/fc" "$FC" http "$V" acme reputation=fresh "$P" "$(crit) 192.0.2.1")"
    runplan "$W/fixed.tsv" "$W/fixed"
    judgeplan "O4 fixed cases" "$W/fixed.tsv" "$W/fixed" "$W/fixed-cache" --first
    if [ "$MODE" = normal ]; then
        a "O4: past a skipped hop the floor decides" grep -q '^decision deny enforce=yes step=floor rule=1 ' "$W/fixed/hop.out"
        a "O4: ACME under a deny" grep -q '^decision allow step=acme rule=0' "$W/fixed/acme.out"
    fi
    if [ "$MODE" = normal ]; then
        rm -f "$W/t/docs.list"
        JPAIR_PLAN=1 runplan "$W/flags.tsv" "$W/t"
        judgeplan O4 "$W/flags.tsv" "$W/t" "$cache"
        python3 lookup-check.py docs "$W/t/docs.list" > "$W/docs.txt" 2>&1
        a "J1 over O4: the two forms agree: $(grep -m1 '^FAIL' "$W/docs.txt")" grep -q ' 0 failures$' "$W/docs.txt"
        read -r _ _ wi wc < <(python3 lookup-states.py ocounts "$P")
        a "O4: $wi invocations and $wc cases, the generator's" grep -q "^judged $wi invocations, $wc cases;" "$W/t/judge.txt"
        a "O4: the ACME arm reached, counted by the oracle's verdicts" grep -q 'allow-by-acme [1-9]' "$W/t/judge.txt"
        local id hh=0
        while read -r id; do
            hh=$((hh + $(grep -c 'reason=allow-by-hold-harmless' "$W/t/$id.out")))
        done < <(grep -P '\tskipped-hop\t' "$W/flags.tsv" | cut -f1)
        a "O4: step 1 only with eligibility: no hold-harmless verdict under --skipped-hop" eq "$hh" 0
    else
        runplan "$W/flags.tsv" "$W/t"
        TEST_POLICY=$FX/test_policy python3 lookup-states.py judge "$W/flags.tsv" "$W/t" "$cache" --first > "$W/judge.txt" 2>&1 \
            || bad "O4: the flag sets differ"
    fi
}

rowO3() {
    row O3
    local A18=$CORE/testdata/policy/accept/18-contexts-floor-inheritance.policy addr
    addr=$(awk '$3 != "-" && $1 == "4" { print $2; exit }' "$P/routing.expect")
    mkdata "$W/d" - tor rpki-unreachable routing anonymizer threat registry tenant
    cp "$P/reputation.bin" "$W/d/"; chmod 444 "$W/d/reputation.bin"
    local st="anonymizer=fresh,registry=fresh,reputation=fresh,routing=fresh,rpki-unreachable=fresh,tenant=fresh,threat=fresh,tor=fresh"
    plan "$W/p.tsv" \
        "$(pline a "$W/d" "$A18" http/server:a "$V" plain "$st" "$P" "$addr")" \
        "$(pline api "$W/d" "$A18" http/server:a/location:api "$V" plain "$st" "$P" "$addr")" \
        "$(pline c "$W/d" "$A18" http/server:c "$V" plain "$st" "$P" "$addr")"
    runplan "$W/p.tsv" "$W/t"
    judgeplan O3 "$W/p.tsv" "$W/t" "$W/cache"
    a "O3: the run context is the argument" grep -q '^policy .* context=http/server:a/location:api ' "$W/t/api.out"
}

rowV1() {
    row V1
    local k3=$W/k3
    "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -DWE_LOOKUP_TEST_K3_PLANT ${MUTMACRO:+"-D$MUTMACRO"} \
        -o "$k3" we_lookup_cli.c "$TOOLOBJ"/*.o 2> "$W/cc.err"
    M=$((M + 1))
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    timeout 60 "$k3" --dir "$P" --now "$V" 1.1.1.1 > "$W/k3.out" 2> "$W/k3.err"
    RC=$?
    a "V1: a planted K3 state (1,1) exits 2" eq "$RC" 2
    a "V1: with the K3 message" has "$W/k3.err" "internal: K3 state (1,1) reached 1 times"
}

rowP1() {
    row P1
    local f n=0
    for f in testdata/policy/refuse/*.policy; do
        local e=${f%.policy}.expect rule line col msg
        rule=$(sed -n 's/^rule\t//p' "$e"); line=$(sed -n 's/^line\t//p' "$e"); col=$(sed -n 's/^col\t//p' "$e")
        msg=$(sed -n 's/^message\t//p' "$e")
        JPAIR=0 L r --dir "$P" --policy "$CORE/$f" 1.1.1.1
        n=$((n + 1))
        a "P1 $(basename "$f"): exit 2" eq "$RC" 2
        a "P1 $(basename "$f"): the compiler's located refusal" has "$W/r.err" "rule $rule, line $line, column $col: "
        a "P1 $(basename "$f"): its phrase" has "$W/r.err" "$msg"
        a "P1 $(basename "$f"): nothing on standard output" test ! -s "$W/r.out"
    done
    a "P1: the 50 corpus refusals" eq "$n" 50
}

rowP2() {
    row P2
    local addrs
    addrs=("$(crit)" "$TOR4" 1.1.1.1)
    JPAIR=0 L conf --dir "$P" --now "$V" --policy "$CORE/testdata/policy/default.conf" "${addrs[@]}"
    JPAIR=0 L acc --dir "$P" --now "$V" --policy "$CORE/testdata/policy/accept/01-default-policy.policy" --context http/server:a "${addrs[@]}"
    a "P2: the default policy.conf and accept/01 compile to the same rules" \
        eq "$(grep '^rule ' "$W/conf.out")" "$(grep '^rule ' "$W/acc.out")"
    a "P2: and judge alike" eq "$(grep '^verdict \|^cost ' "$W/conf.out")" "$(grep '^verdict \|^cost ' "$W/acc.out")"
    a "P2: the rules are the default's four" eq "$(grep -c '^rule ctx ' "$W/conf.out")" 4
}

rowP4() {
    row P4
    mkd "$W/d"; cp "$P/reputation.bin" "$W/d/"; chmod 444 "$W/d/reputation.bin"
    local th mo addrs
    mapfile -t addrs < <(awk '$3 != "-" && $1 == "4" { print $2 }' "$P/reputation.expect" | head -8)
    for th in off low medium high critical; do
        for mo in log deny; do
            if [ $th = off ]; then printf 'mode http %s\x1e\n' "$mo" > "$W/t.policy"
            else printf 'mode http %s\x1e\npolicy http deny if listed >= %s\x1e\n' "$mo" "$th" > "$W/t.policy"; fi
            JPAIR=0 L sugar --snapshot "$W/d/reputation.bin" --prestage present --threshold $th --mode $mo "${addrs[@]}" 192.0.2.1
            JPAIR=0 L rule --dir "$W/d" --policy "$W/t.policy" "${addrs[@]}" 192.0.2.1
            a "P4 $th $mo: the sugar's verdicts equal the written rule's" \
                eq "$(grep '^verdict \|^cost ' "$W/sugar.out")" "$(grep '^verdict \|^cost ' "$W/rule.out")"
        done
    done
    # the old form has no pre-stage, so the written rule is judged without hold-harmless eligibility too
    JPAIR=0 L old "$W/d/reputation.bin" --threshold critical "${addrs[@]}"
    printf 'mode http log\x1e\npolicy http deny if listed >= critical\x1e\n' > "$W/t.policy"
    JPAIR=0 L rule --dir "$W/d" --skipped-hop --policy "$W/t.policy" "${addrs[@]}"
    a "P4: the old form's verdicts equal the written rule's" \
        eq "$(grep '^verdict ' "$W/old.out")" "$(grep '^verdict ' "$W/rule.out")"
}

rowH1() {
    row H1
    mkdata "$W/d" - reputation
    local DA=$CORE/testdata/lookup/deny-all.conf past
    JPAIR=0 L a --dir "$W/d" --policy "$DA" 193.0.14.129
    past=$(sed -n 's/^hold-harmless yes .* range=[^-]*-\([^ ]*\)$/\1/p' "$W/a.out")
    past=$(python3 -c "import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]) + 1)" "$past")
    L h --dir "$W/d" --policy "$DA" 193.0.14.129 2001:7fd::1 1.1.1.1 ::ffff:1.1.1.1 "$past"
    a "H1: step 1 on the four members" eq "$(grep -c '^decision allow step=hold-harmless rule=0' "$W/h.out")" 4
    a "H1: one past the merged range is judged by the rule" grep -q '^decision deny enforce=yes step=context rule=1' "$W/h.out"
    a "H1: exit 1 for the denied one" eq "$RC" 1
}

rowX2() {
    row X2
    mkd "$W/d"; cp "$P/reputation.bin" "$W/d/"; chmod 444 "$W/d/reputation.bin"
    local c
    c=$(crit)
    L sugar --dir "$W/d" "$c"
    a "X2: no policy.conf: the sugar at the module's defaults" has "$W/sugar.out" \
        "policy source=sugar installed=no threshold=high defaults=module context=http mode=log"
    a "X2: a high listing logs, would deny: the default allow decides, the downgraded rule named in its own keys" \
        grep -qx 'decision log would-deny=yes step=default rule=0 log=ctx:1 would-deny-rule=ctx:1 would-deny-text="deny if listed >= high"' "$W/sugar.out"
    L legacy --snapshot "$W/d/reputation.bin" "$c"
    a "X2: the legacy model's line has the same shape, step sugar" \
        grep -qx 'decision log would-deny=yes step=sugar rule=0 log=ctx:1 would-deny-rule=ctx:1 would-deny-text="deny if listed >= high"' "$W/legacy.out"
    a "X2: exit 0" eq "$RC" 0
    L def --dir "$W/d" --policy default "$c"
    a "X2: --policy default: the shipped default" grep -q '^policy source=builtin-default installed=no ' "$W/def.out"
    a "X2: --policy default: an enforced deny" grep -q '^decision deny enforce=yes step=context rule=1' "$W/def.out"
    a "X2: --policy default: exit 1" eq "$RC" 1
    a "X2: --policy default: the note" has "$W/def.out" \
        "the decision below is the shipped default's, chosen with --policy default, not your server's configuration"
    mkd "$W/etc"; cp "$CORE/testdata/policy/default.conf" "$W/etc/policy.conf"; chmod 644 "$W/etc/policy.conf"
    [ "$MODE" = normal ] && I=$((I + 1)) && C=$((C + 1))
    WHISPER_EDGE_ETC="$W/etc" timeout 60 "$T" --dir "$W/d" --now "$V" "$c" > "$W/inst.out" 2>/dev/null
    a "X2: an installed policy.conf: installed=yes applied=not-verified, whatever the server does" \
        grep -q '^policy source=policy-conf installed=yes applied=not-verified ' "$W/inst.out"
    a "X2: the override is named with the path it chose" has "$W/inst.out" \
        "WHISPER_EDGE_ETC is set: the installed policy is looked for at $W/etc/policy.conf"
    a "X2: the installed policy's path is stated" has "$W/inst.out" "the policy evaluated is the installed $W/etc/policy.conf"
    a "X2: and it decides: the installed default denies" grep -q '^decision deny enforce=yes step=context rule=1' "$W/inst.out"
}

rowK1() {
    row K1
    mkdata "$W/kl" base.json reputation
    mkdata "$W/kd" base.json reputation; mkd "$W/kd/k"; cp "$FX/derived/keyed.json" "$W/kd/k/manifest.json"
    chmod 644 "$W/kd/k/manifest.json"
    L kl --dir "$W/kl" "$REP4"
    L kd --dir "$W/kd" "$REP4"
    keyless() { grep -E '^attr (listed|inferred|tor_exit|rpki_unreachable|rpki_reason) ' "$1"
                grep -E '^plane (reputation|tor|rpki-unreachable) ' "$1" | grep -oE ' (tier|sources|coverage-v4|coverage-v6|coverage-v6-slash32s|manifest)=[^ ]*'; }
    a "K1: the keyless planes read the same with a keyed manifest beside them" eq "$(keyless "$W/kl.out")" "$(keyless "$W/kd.out")"
    a "K1: the keyed manifest was read" eq "$(grep -c '^manifest state=read' "$W/kd.out")" 2
}

rowL4() {
    row L4
    mapfile -t ev < <(awk '$3 != "0" { print $2 }' testdata/expected.txt)
    JPAIR=0 L ev --snapshot "$FX/interop.snap" --now 1 "${ev[@]}"
    a "L4: every listed address's evidence and drop equal the builder's" python3 - "$W/ev.out" testdata/expected.txt <<'PY'
import ipaddress, sys
want = {}
for line in open(sys.argv[2]):
    f = line.split()
    if f[2] != "0":
        want[str(ipaddress.ip_address(f[1]))] = (int(f[2]), "" if f[3] == "-" else f[3])
cur, bad, n = None, 0, 0
for line in open(sys.argv[1]):
    if line.startswith("address "):
        cur = line.split("canonical=")[1].split()[0]
    elif line.startswith("attr listed ") and cur in want:
        sev, ev = want[cur]
        kv = dict(t.split("=", 1) for t in line.split()[3:] if "=" in t)
        got_ev = kv.get("evidence", "").strip('"')
        n += 1
        bad += got_ev != ev or (kv.get("drop") == "yes") != bool(sev & 0x40)
sys.exit(0 if n == len(want) and bad == 0 and any(":" in a for a in want) else 1)
PY
}

# ---- --probe-dir: the module's own bind verdict, never a rule of the tool's ----
# the rows run under the work directory, which the planes' trust walk accepts (see OUT above); when it does
# not, the rows fail by name, never skip
TB=
ot_trusted "$OUT" && TB=$OUT/trust && mkd "$TB"
# probe <name> <dir> [args...]: one --probe-dir run of the tool under test, into $W/<name>.out
probe() {
    local name=$1 d=$2; shift 2
    [ "$MODE" = normal ] && I=$((I + 1))
    timeout 60 "$T" --probe-dir "$d" "$@" > "$W/$name.out" 2> "$W/$name.err"
    RC=$?
}
# the plane line's state and why, as `<state>|<why>`: the why runs to its line's last quote before the
# owner fields or the inert note, since a walk's reason quotes the directory it names
pstate() {
    local st why
    st=$(sed -n "s/^  plane $2  *state=\([a-z]*\) .*/\1/p" "$1")
    why=$(sed -n "s/^  plane $2  *state=[a-z]* probe=[^ ]* why=\"\(.*\)\"\( owner=[0-9]* mode=[0-7]* size=[0-9]*\)\{0,1\}\( (rules on it are inert)\)\{0,1\}$/\1/p" "$1")
    printf '%s|%s\n' "$st" "$why"
}

rowT1() {
    row T1
    if [ -z "$TB" ]; then bad "T1: no directory the planes' trust walk accepts (runtime dir, /run/user/<uid>, HOME); the row did not run"; return; fi
    local d=$TB/t1
    rm -rf "$d"; mkd "$d"
    cp "$P/tor.bin" "$d/tor.bin"; chmod 444 "$d/tor.bin"
    probe ok "$d"
    a "T1 control: a 0444 tor.bin is present (exit $RC)" eq "$(pstate "$W/ok.out" tor)" "present|"
    chmod 644 "$d/tor.bin"
    probe m644 "$d"
    a "T1: a 0644 tor.bin is refused with the module's reason: $(grep -m1 ' plane tor ' "$W/m644.out")" \
        eq "$(pstate "$W/m644.out" tor)" "refused|mode 0644: a mapped plane must be exactly 0444, so no writer but root can change its bytes under the mapping; chmod 0444 the file"
    a "T1: exit 0, the probe answered" eq "$RC" 0
    # a directory named from where the operator stands reads as the same directory named from /
    [ "$MODE" = normal ] && I=$((I + 1))
    (cd "$TB" && timeout 60 "$T" --probe-dir t1) > "$W/rel.out" 2> "$W/rel.err"
    a "T1: the relative name t1 is judged as $d: $(grep -m1 ' plane tor ' "$W/rel.out")" \
        eq "$(pstate "$W/rel.out" tor)" "$(pstate "$W/m644.out" tor)"
    rm -rf "$d"
}

rowT2() {
    row T2
    if [ -z "$TB" ]; then bad "T2: no directory the planes' trust walk accepts (runtime dir, /run/user/<uid>, HOME); the row did not run"; return; fi
    local d=$TB/t2 u n=0 p want got
    u=$(id -u)
    rm -rf "$d"; mkd "$d"; mkd "$d/a"; mkd "$d/b"; mkd "$d/c"
    # a: one case per plane, each the bind's own rule: 0444 (binds), 0644, 0664, a link to a good file, a
    # FIFO, a short file, a dangling link, absent
    cp "$P/reputation.bin" "$d/a/reputation.bin"; chmod 444 "$d/a/reputation.bin"
    cp "$P/tor.bin" "$d/a/tor.bin"; chmod 644 "$d/a/tor.bin"
    cp "$P/rpki-unreachable.bin" "$d/a/rpki-unreachable.bin"; chmod 664 "$d/a/rpki-unreachable.bin"
    cp "$P/routing.bin" "$d/routing-real.bin"; chmod 444 "$d/routing-real.bin"; ln -s "$d/routing-real.bin" "$d/a/routing.bin"
    mkfifo "$d/a/anonymizer.bin"
    head -c 100 "$P/threat.bin" > "$d/a/threat.bin"; chmod 444 "$d/a/threat.bin"
    ln -s "$d/nowhere" "$d/a/registry.bin"
    # b: a 0444 plane another uid owns (neither root nor the workers'), chowned as root or through sudo
    cp "$P/tenant.bin" "$d/b/tenant.bin"; chmod 444 "$d/b/tenant.bin"
    local owner_ok=0
    if [ "$u" = 0 ]; then chown 4242 "$d/b/tenant.bin" && owner_ok=1
    elif sudo -n true 2>/dev/null; then sudo -n chown 4242 "$d/b/tenant.bin" && owner_ok=1; fi
    a "T2: a plane another uid owns could be planted (root or passwordless sudo); without it the owner case proves nothing" eq "$owner_ok" 1
    # c: a good 0444 plane in a group-writable directory
    cp "$P/tor.bin" "$d/c/tor.bin"; chmod 444 "$d/c/tor.bin"; chmod 775 "$d/c"
    for sub in a b c; do
        probe "p$sub" "$d/$sub" --uid "$u"
        timeout 60 "$FX/plane_bind_probe" "$d/$sub" "$u" > "$W/b$sub.out" 2> "$W/b$sub.err"
        a "T2 $sub: the module's bind ran" grep -q '^plane tenant ' "$W/b$sub.out"
        JPAIR=0 L "d$sub" --dir "$d/$sub" --uid "$u" 192.0.2.1
        for p in reputation tor rpki-unreachable routing anonymizer threat registry tenant; do
            got=$(pstate "$W/p$sub.out" "$p")
            want=$(sed -n "s/^plane $p //p" "$W/b$sub.out")
            case "$want" in
                armed) want="present|" ;;
                absent*) want="absent|" ;;
                *) want="${want%% *}|${want#* }" ;;
            esac
            n=$((n + 1))
            a "T2 $sub/$p: --probe-dir says '$got' and the module's bind '$want'" eq "$got" "$want"
            # the address mode: read (fresh or stale) exactly when the module arms it, refused when it
            # refuses, absent when it is absent
            got=$(sed -n "s/^plane $p id=[0-9] state=\([a-z]*\) .*/\1/p" "$W/d$sub.out")
            case "$got" in fresh|stale) got=present ;; esac
            a "T2 $sub/$p: the address mode says '$got' and the module's bind '${want%%|*}'" eq "$got" "${want%%|*}"
        done
    done
    a "T2: the cases cover each rule: a binds one plane, b refuses its owner, c its directory" bash -c \
        "grep -q '^plane reputation armed' '$W/ba.out' && grep -q '^plane tenant refused owned by uid 4242' '$W/bb.out' && grep -q '^plane tor refused .*directory' '$W/bc.out'"
    a "T2: 24 plane verdicts compared, each by --probe-dir and by the address mode" eq "$n" 24
    [ "$owner_ok" = 1 ] && { [ "$u" = 0 ] && rm -f "$d/b/tenant.bin" || sudo -n rm -f "$d/b/tenant.bin"; }
    chmod 755 "$d/c"; rm -rf "$d"
}

rowT3() {
    row T3
    if [ -z "$TB" ]; then bad "T3: no directory the planes' trust walk accepts; the row did not run"; return; fi
    local d=$TB/t3
    rm -rf "$d"; mkd "$d"
    cp "$P/tor.bin" "$d/tor.bin"; chmod 444 "$d/tor.bin"
    printf 'mode http deny\x1e\npolicy http deny if tor_exit\x1e\n' > "$W/t.policy"
    JPAIR=0 L ok --dir "$d" --policy "$W/t.policy" "$TOR4"
    a "T3 control: a 0444 tor.bin is read: $(grep -m1 '^plane tor ' "$W/ok.out")" grep -q '^plane tor id=2 state=fresh ' "$W/ok.out"
    a "T3 control: and its listing denies $TOR4" grep -q '^decision deny enforce=yes step=context rule=1' "$W/ok.out"
    chmod 644 "$d/tor.bin"
    JPAIR=0 L m644 --dir "$d" --policy "$W/t.policy" "$TOR4"
    a "T3: a 0644 tor.bin is refused with the module's reason: $(grep -m1 '^plane tor ' "$W/m644.out")" has "$W/m644.out" \
        'plane tor id=2 state=refused file=tor.bin manifest=unbound why=refused:trust refused=trust refused-detail="mode 0644: a mapped plane must be exactly 0444, so no writer but root can change its bytes under the mapping; chmod 0444 the file"'
    a "T3: tor_exit is not read from it" grep -q '^attr tor_exit UNKNOWN plane=tor why=refused:trust' "$W/m644.out"
    a "T3: and the request is judged as the server judges it, without the plane: $(grep -m1 '^decision ' "$W/m644.out")" \
        not grep -q '^decision deny' "$W/m644.out"
    rm -rf "$d"
}

# ======================================================================================================
# the normal phase
# ======================================================================================================
T=$TOOL
SAN=$FX/lookup_san
ROWS="L1 L2 L3 L4 W1 W2 W3 W4 W5 W6 W7 W8 W9 W10 W11 W12 W13 M1 M2 M3 M4 M7 M8 O1 O3 O4 V1 P1 P2 P4 P5 P6 H1 H2 A1 A2 X1 X2 S1 K1 J1 J2 J3 J4 X3 T1 T2 T3"
# A developer may run some rows alone (LOOKUP_GATE_ROWS="W2 M1"), with only the mutants of those rows; the
# summary then says it is partial and the gate fails, so a partial run can never stand in for the gate.
PARTIAL=${LOOKUP_GATE_ROWS:-}
if [ -n "$PARTIAL" ]; then ROWS=$PARTIAL; fi
for r in $ROWS; do
    "row$r"
done

# ---- controls that are inputs, not builds ----
W=$OUT/normal/controls; mkd "$W"
for f in "$FX/derived"/*; do basename "$f"; done > "$W/derived.have"
sed -n "s/^| \`\([a-z0-9-]*\.json\)\`.*/\1/p" testdata/lookup/derived/README.md | sort > "$W/derived.want"
a "the derived manifests written are exactly derived/README.md's list" cmp -s "$W/derived.have" "$W/derived.want"
# The README's own lookup transcripts. Every one that reads the checked-in fixtures runs again with the
# shipped tool, in a directory the bind's walk accepts, and must reproduce its transcript byte for byte; its
# control plants one changed line, which must fail. The two that read the differential producer's planes
# are named by lookup-check.py and stay DARK below, with why.
TR=$OUT/normal/transcripts; mkd "$TR"
python3 lookup-check.py transcripts "$CORE/.." "$TOOL" "$TR" > "$TR/run.out" 2>&1 && trc=0 || trc=$?
a "the README's lookup transcripts on the checked-in fixtures reproduce byte for byte: $(grep -m1 '^FAIL' "$TR/run.out")" eq "$trc" 0
python3 lookup-check.py transcripts "$CORE/.." "$TOOL" "$TR" --plant > "$TR/plant.out" 2>&1 && trc=0 || trc=$?
a "the transcripts' control: a transcript with one planted line fails the comparison" eq "$trc" 1
printf '4 %s 1 2\n' 127.0.0.1 > "$W/sev.fields"
python3 make-test-snapshot.py "$W/f1.snap" 5 0 3 > /dev/null
a "control L1: a wrong sev line fails plane_check --fields" bash -c "! '$PC' --fields '$W/f1.snap' '$W/sev.fields'"
printf '4 127.0.0.1 1 3\ngarbage\n' > "$W/garb.fields"
a "control L1: a garbage line fails plane_check --fields" bash -c "! '$PC' --fields '$W/f1.snap' '$W/garb.fields'"
sed -E 's/rov=([0-9]+),rir=([0-9]+)/rov=\2,rir=\1/' "$P/routing.expect" > "$W/swapped.expect"
a "control L1: a writer swapping rov and rir in its dict only fails plane_check" bash -c "! '$PC' '$P/routing.bin' '$W/swapped.expect'"
mkd "$W/ood"; cp "$FX/sweep/in-domain/"*.bin "$W/ood/"; rm -f "$W/ood/routing.bin"   # a 0444 copy: replaced, not written over
cp "$FX/sweep/refused-routing-v4-rov-4/routing.bin" "$W/ood/"
I=$((I + 1)); C=$((C + 1))
"$TOOL" --dir "$W/ood" 1.1.1.1 > "$W/ood.out" 2>/dev/null
a "control L2: one out-of-domain value in the in-domain directory: seven fresh" \
    eq "$(grep -c '^plane .* state=fresh' "$W/ood.out")" 7
a "control L2: and the routing plane refused" grep -q '^plane routing id=4 state=refused ' "$W/ood.out"
cp ../hold-harmless.txt "$W/hh.txt"; sed -i '0,/^198.41.0.4/{/^198.41.0.4/d}' "$W/hh.txt"
python3 gen-lookup-headers.py cite "$W/hh.txt" > "$W/cite.h"
a "control H2: a list with one entry dropped regenerates a different header" bash -c "! cmp -s '$W/cite.h' we_hold_harmless_cite.h"
cp testdata/lookup/README.md "$W/plant.md"; printf 'planted in %s 3, see %s%s\n' round W B8 >> "$W/plant.md"
a "control X3: the row's own grep over its list and a planted file finds the plant" \
    bash -c "cd .. && mapfile -t fl < <(python3 core/lookup-states.py files) && grep -nE '#[0-9]{3,}|\\bWB[0-9]+\\b|\\bround [0-9]|\\bR[0-9]+ row' \"\${fl[@]}\" '$W/plant.md' | grep -q plant.md"
# the shim's composition
rm -f "$W/cnt".*
env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_CLOCK=1 LOOKUP_SHIM_OUT="$W/cnt" "$FX/shim_probe" clock
a "W7 composition: a one-read probe reads 1" has "$(cntfile)" "clock 1"
echo '{}' > "$W/probe.json"
for how in open openat openat-cwd; do
    if [ $how = open ]; then args=("$W/probe.json"); else args=("$W" probe.json); fi
    rm -f "$W/cnt".*
    env LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_PATHS="$W/probe.json" LOOKUP_SHIM_OUT="$W/cnt" "$FX/shim_probe" "$how" "${args[@]}"
    a "W7/S1 composition: '$how' counts 1 for the full path" has "$(cntfile)" "open 1 $W/probe.json"
done
rm -f "$W/cnt".*
LD_PRELOAD="$FX/lookup_shim.so" LOOKUP_SHIM_CLOCK=1 LOOKUP_SHIM_OUT="$W/cnt" timeout 60 "$FX/shim_probe" clock
a "W7 control: the shim given to the guard too makes two count files" eq "$(cntn)" 2
rm -f "$W/cnt".*
env LD_PRELOAD="$W/no-such-shim.so" LOOKUP_SHIM_OUT="$W/cnt" "$FX/shim_probe" clock 2>/dev/null
a "W7 control: a missing preload makes no count file" eq "$(cntn)" 0

# ======================================================================================================
# the mutant phase: every mutant built with WE_LOOKUP_MUTANT_BUILD must fail each row it names
# ======================================================================================================
# the no-mutant control: the mutant phase's build of the unmutated tool prints the shipped
# build's hashed-bytes on S1's fixture, at 1 and at 1,000 addresses, with a manifest and without
"$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -o "$MO/none" we_lookup_cli.c "$TOOLOBJ"/*.o
M=$((M + 1))
mapfile -t many < <(python3 -c "print('\n'.join('10.%d.%d.%d' % (i >> 16, (i >> 8) & 255, i & 255) for i in range(1000)))")
for mode in m n; do
    for k in 1 1000; do
        "$TOOL" --dir "$OUT/normal/S1/$mode" --now $V "${many[@]:0:$k}" 2>&1 >/dev/null | sed -n 's/.*hashed-bytes=//p' > "$MO/shipped.hb"
        "$MO/none" --dir "$OUT/normal/S1/$mode" --now $V "${many[@]:0:$k}" 2>&1 >/dev/null | sed -n 's/.*hashed-bytes=//p' > "$MO/none.hb"
        a "the mutant phase's unmutated build prints the shipped build's hashed-bytes ($mode, $k)" \
            bash -c "[ -s '$MO/shipped.hb' ] && cmp -s '$MO/shipped.hb' '$MO/none.hb'"
    done
done

MODE=mutant
caught=0 missed=0 nmut=0
while read -r name rows unit macro; do
    [ -n "$name" ] || continue
    if [ -n "$PARTIAL" ]; then
        keep=0
        for r in ${rows//,/ }; do case " $PARTIAL " in *" $r "*) keep=1 ;; esac; done
        [ $keep = 1 ] || continue
        rows=$(for r in ${rows//,/ }; do case " $PARTIAL " in *" $r "*) printf '%s,' "$r" ;; esac; done)
        rows=${rows%,}
    fi
    nmut=$((nmut + 1))
    mb=$MO/m_$name
    macro=${macro:-WE_LOOKUP_TEST_$name}
    MUTMACRO=$macro
    T=$TOOL SAN=$TOOL FMB=$FM
    PC_SAVE=$PC
    built=1
    if [ "$unit" = plane_check.c ]; then
        "$CC" "${CFL[@]}" "-D$macro" -o "$mb.pc" plane_check.c whisper_edge.c we_sha256.c we_counters.c 2>/dev/null || built=0
        M=$((M + 1)); PC=$mb.pc
    elif [ "$unit" = we_policy.c ] || [ "$unit" = whisper_edge.c ]; then
        # a shared unit: its one-edit copy compiled in place of the unit's object, the tool unchanged
        MUTMACRO=
        rm -rf "$mb.units"; mkd "$mb.units"; cp "$TOOLOBJ"/*.o "$mb.units/"
        if python3 lookup-states.py patch "$name" "$unit" "$mb.${unit}" 2> "$mb.cc.err" \
            && "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -I"$CORE" -c -o "$mb.units/${unit%.c}.o" "$mb.${unit}" 2>> "$mb.cc.err" \
            && "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD -o "$mb" we_lookup_cli.c "$mb.units"/*.o 2>> "$mb.cc.err"; then
            T=$mb SAN=$mb
        else
            built=0
        fi
        M=$((M + 2))
    else
        if "$CC" "${CFL[@]}" "${TOOLFLAGS[@]}" -DWE_LOOKUP_MUTANT_BUILD "-D$macro" -o "$mb" we_lookup_cli.c "$TOOLOBJ"/*.o \
            2> "$mb.cc.err"; then
            T=$mb SAN=$mb
        else
            built=0
        fi
        M=$((M + 1))
        case ",$rows," in *,J4,*)
            "$CC" -std=c11 -O1 -Wall -Wextra -Werror "-D$macro" -o "$mb.fm" fuzz_manifest.c whisper_edge.c we_sha256.c we_counters.c 2>/dev/null && FMB=$mb.fm || built=0
            M=$((M + 1)) ;;
        esac
    fi
    for r in ${rows//,/ }; do
        if [ $built = 0 ]; then
            if [ "$name" = AGE_CAP_2_62 ] && grep -q 'age operands stay below 2^48' "$mb.cc.err"; then
                caught=$((caught + 1)); N=$((N + 1)); continue
            fi
            echo "FAIL mutant $name did not compile, so row $r proved nothing"; N=$((N + 1)); F=$((F + 1)); missed=$((missed + 1)); continue
        fi
        RF=0
        "row$r"
        N=$((N + 1))
        if [ $RF -gt 0 ]; then caught=$((caught + 1)); else
            echo "FAIL mutant $name was not caught by row $r"; F=$((F + 1)); missed=$((missed + 1))
        fi
    done
    PC=$PC_SAVE
    MUTMACRO=
done < <(python3 lookup-states.py mutants)
MODE=normal
want=$(python3 lookup-states.py mutants | wc -l)
if [ -n "$PARTIAL" ]; then
    echo "PARTIAL RUN of rows $PARTIAL: not the gate"
    F=$((F + 1))
else
    a "every mutant of the table ran: $nmut of $want" eq "$nmut" "$want"
fi
echo "  mutant phase: $nmut mutants, $caught row failures caught, $missed missed"

# the bulk of a run's disk, gone once its verdict is in: the differential's directories and outputs and
# every build of the mutant phase (the verdict and the failing rows' own outputs stay)
rm -rf "$FX/o1" "$MO" "$OUT"/*/O1/t "$OUT"/*/O4/t "$OUT"/*/O1/rr
python3 lookup-states.py pending
# a run moved out of the tree it was given leaves nothing behind when it passes; a failing one stays, named
if [ -n "$RELOCATED" ]; then
    if [ "$F" -eq 0 ]; then rm -rf "$OUT"; else echo "the failing run's outputs: $OUT"; fi
fi
[ -n "$NO_SAN_DARK" ] && echo "DARK $NO_SAN_DARK"
echo "$N checks, $F failures, $I invocations, $C cases, $M mutant compiles"
[ "$F" -eq 0 ]
