#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# xserver-cases.sh - the cross-server differential's case producer: the input half of a run directory and
# the reference columns (xserver-gate.sh at the tree's root, whose header is the contract).
#
#   ./xserver-cases.sh --xserver-columns DIR [--export default|all]   write the run directory's input half
#                                                                     (cases.in, conf/, planes/, next/,
#                                                                     schedule.in, www/) and cases.col,
#                                                                     python.col, oracle.col and
#                                                                     oracle-<server>.counters into DIR
#   ./xserver-cases.sh --selftest                                     the producer over a scratch run
#                                                                     directory, and its controls
#
# The work is xserver_cases.py's (the programs, the records, the planes, the requests, the schedule, the
# twin's rendering, the interpreter's verdicts); this script builds the one C reading it takes, the shipped
# whisper-edge-lookup tool's `--programs` mode, which compiles the same directive lines through
# we_policy_build() in the environment `--probe-dir` probes from the run's planes, for the program digests the
# servers count under, and declares the column contract below, which `run` looks for.
#
# Exit 0 when every file was written; 1 when the producer refused (a planted or real disagreement between
# the compiler's canonical text and the interpreter's, a case file that does not reproduce its verdicts,
# a plane the writer refused), with the reason on stderr.
# shellcheck disable=SC2034  # the contract's declaration: xserver-gate.sh greps for this line, nothing reads the variable
XSERVER_COLUMNS_VERSION=1
set -uo pipefail
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDGE="$(cd "$HERE/.." && pwd)"

build_tool() {
    if ! make -s -C "$HERE" whisper-edge-lookup >"$1" 2>&1; then
        echo "xserver-cases: whisper-edge-lookup does not build: $(tail -1 "$1")" >&2
        return 1
    fi
}

produce() { # DIR EXPORT [HOPS]: XSERVER_CASES_NOW pins the produce clock (the grace step's valid-until), so two
            # runs from one seed under one clock are byte-identical
    local dir=$1 export=$2 hops=${3:-0} log
    log=$(mktemp "${TMPDIR:-/tmp}/xserver-cases-build.XXXXXX")
    if ! build_tool "$log"; then
        rm -f -- "$log"
        return 1
    fi
    rm -f -- "$log"
    mkdir -p -- "$dir"
    PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/xserver_cases.py" --out "$dir" --export "$export" --hops "$hops" \
        ${XSERVER_CASES_NOW:+--now "$XSERVER_CASES_NOW"} --tool "$HERE/whisper-edge-lookup"
}

selftest() {
    local base rc=0 checks=0 fails=0 d1 d2 out now_ms pdir c
    base=$(mktemp -d "${TMPDIR:-/tmp}/xserver-cases-selftest.XXXXXX")
    now_ms=$(date +%s%3N)
    export XSERVER_CASES_NOW=$now_ms              # one clock for the selftest: the determinism check needs it
    ok()  { checks=$((checks + 1)); echo "ok   $*"; }
    bad() { checks=$((checks + 1)); fails=$((fails + 1)); echo "FAIL $*"; }

    # 1. the producer writes a run directory the comparator's input grammar accepts, for both export sets
    for export in default all; do
        d1="$base/$export"
        if out=$(produce "$d1" "$export" 2>&1); then
            ok "produce --export $export: $(tail -1 <<<"$out")"
        else
            bad "produce --export $export exited non-zero: $(tail -3 <<<"$out" | tr '\n' ' ')"
            continue
        fi
        if out=$(bash "$EDGE/xserver-gate.sh" --check-inputs "$d1" 2>&1); then
            ok "check-inputs ($export): $(tail -1 <<<"$out")"
        else
            bad "check-inputs ($export) refused the input half: $(grep -m3 'MALFORMED\|NOT PROVEN' <<<"$out" | tr '\n' ' ')"
        fi
        # 2. the comparator over the producer's columns alone: nothing disagrees, the server columns are
        #    named absent (exit 2), never a pass
        out=$(bash "$EDGE/xserver-gate.sh" --compare "$d1" 2>&1); rc=$?
        if [ "$rc" = 2 ] && grep -q ' 0 disagreements' <<<"$out" && grep -q 'nginx.col is absent' <<<"$out"; then
            ok "compare ($export) over the reference columns alone: NOT PROVEN by the absent server columns, 0 disagreements"
        else
            bad "compare ($export) over the reference columns alone: exit $rc: $(tail -2 <<<"$out" | tr '\n' ' ')"
        fi
        # 3. a server column derived from the twin's column and the oracle's totals passes the comparator
        #    whole: the reference columns are consistent with the rules the comparator applies
        d2="$base/$export-derived"
        cp -r "$d1" "$d2"
        python3 - "$d2" <<'PY'
import os, sys
d = sys.argv[1]
cases = {}
for line in open(os.path.join(d, 'cases.col')):
    f = line.rstrip('\n').split('\t')
    cases[f[0]] = dict(x.split('=', 1) for x in f[1:])
py = {}
for line in open(os.path.join(d, 'python.col')):
    f = line.rstrip('\n').split('\t')
    py[f[0]] = f[1:]
cols = {s: [] for s in ('nginx', 'apache', 'litespeed')}
for c, kv in cases.items():
    for s in kv['servers'].split(','):
        status = '403' if any(x == 'var_action=deny' for x in py[c]) else '200'
        nostore = '1' if status != '200' else '0'
        cols[s].append('\t'.join([c, 'status=' + status, 'nostore=' + nostore, 'class=' + kv['class_' + s]] + py[c]))
for s, lines in cols.items():
    if lines:
        open(os.path.join(d, s + '.col'), 'w').write(''.join(l + '\n' for l in lines))
        open(os.path.join(d, s + '.counters'), 'w').write(open(os.path.join(d, 'oracle-%s.counters' % s)).read())
PY
        out=$(bash "$EDGE/xserver-gate.sh" --compare "$d2" 2>&1); rc=$?
        if [ "$rc" = 0 ]; then
            ok "compare ($export) with server columns derived from the twin: $(tail -1 <<<"$out")"
        else
            bad "compare ($export) with derived server columns: exit $rc: $(grep -m3 'DISAGREE\|NOT PROVEN' <<<"$out" | tr '\n' ' ')"
        fi
        # 4. one changed server value is a disagreement, and one dropped case is NOT PROVEN by name
        sed -i '1s/var_action=\([a-z-]*\)/var_action=mutant/' "$d2/apache.col"
        out=$(bash "$EDGE/xserver-gate.sh" --compare "$d2" 2>&1); rc=$?
        if [ "$rc" = 1 ] && grep -q 'var_action on apache is mutant' <<<"$out"; then
            ok "control ($export): a changed server value is reported as a disagreement"
        else
            bad "control ($export): a changed server value was not reported (exit $rc)"
        fi
    done

    # 5. the C reader over every plane the producer wrote, at the addresses that decide each range (the
    #    writer's --expect beside each records file): the records are where the twin believes they are
    if [ -d "$base/default" ]; then
        if make -s -C "$HERE" plane_check >/dev/null 2>&1; then
            n=0; failed=""
            for e in "$base"/default/records/*.expect; do
                p=$(basename "$e" .expect)
                case "$p" in
                    reputation|tor|rpki-unreachable|routing|anonymizer|threat|registry|tenant) bin="$base/default/planes/$p.bin" ;;
                    *) bin="$base/default/next/$p.bin" ;;
                esac
                if "$HERE/plane_check" "$bin" "$e" >/dev/null 2>&1; then n=$((n + 1)); else failed="$failed $p"; fi
            done
            if [ -z "$failed" ]; then
                ok "plane_check: the C reader finds every record of all $n planes where the writer's expectation puts it"
            else
                bad "plane_check refused:$failed"
            fi
        else
            bad "plane_check does not build"
        fi
    fi
    # 5b. the shipped tool's --probe-dir over the run's planes: eight present planes, each digest the file's own
    #     header digest16 (offset 104, the first eight bytes), the environment every plane present and schema-ok;
    #     and over a directory holding snapshot.bin alone, reputation absent with the legacy-file note (never
    #     bound as a plane). Each state is the module's bind verdict, and the bind refuses a data directory
    #     under a sticky world-writable /tmp, so the planes are probed from a copy in a directory the planes'
    #     trust walk accepts: the runtime directory, /run/user/<uid> or HOME. None found is a failure.
    pdir=
    for c in "${XDG_RUNTIME_DIR:-}" "/run/user/$(id -u)" "${HOME:-}"; do
        [ -n "$c" ] && [ -d "$c" ] && [ -w "$c" ] || continue
        pdir=$c/xserver-cases-probe.$$
        rm -rf "$pdir" && mkdir -p "$pdir/planes" && chmod 755 "$pdir" "$pdir/planes" \
            && cp -p "$base/default/planes"/*.bin "$pdir/planes/" 2>/dev/null \
            && "$HERE/whisper-edge-lookup" --probe-dir "$pdir/planes" 2>/dev/null | grep_any '^  plane reputation  *state=present ' && break
        rm -rf "$pdir"; pdir=
    done
    if [ -z "$pdir" ] && [ -d "$base/default" ]; then
        bad "whisper-edge-lookup --probe-dir: no directory the planes' trust walk accepts (runtime dir, /run/user/<uid>, HOME) to probe the run's planes from"
    elif [ -d "$base/default" ]; then
        "$HERE/whisper-edge-lookup" --probe-dir "$pdir/planes" >"$base/lookup-dir.out" 2>&1; rc=$?
        out=$(cat "$base/lookup-dir.out")
        if [ "$rc" = 0 ] && python3 - "$pdir/planes" "$base/lookup-dir.out" <<'PYCHK'
import os, sys
d = sys.argv[1]
want = {}
for name in ('reputation', 'tor', 'rpki-unreachable', 'routing', 'anonymizer', 'threat', 'registry', 'tenant'):
    with open(os.path.join(d, name + '.bin'), 'rb') as f:
        want[name] = f.read(192)[104:112].hex()
seen = {}
env_ok = False
for line in open(sys.argv[2]):
    w = line.split()
    if len(w) > 2 and w[0] == 'plane':
        kv = dict(x.split('=', 1) for x in w[2:] if '=' in x)
        seen[w[1]] = (kv.get('state'), kv.get('probe'), kv.get('digest'))
    if len(w) > 1 and w[0] == 'environment':
        env_ok = 'present=0xff' in line and 'schema-ok=0xff' in line
ok = env_ok and len(seen) == 8 and all(seen[n] == ('present', 'present,schema-ok', want[n]) for n in want)
sys.exit(0 if ok else 1)
PYCHK
        then
            ok "whisper-edge-lookup --probe-dir: eight present planes, every digest the file's own header digest16, environment 0xff/0xff"
        else
            bad "whisper-edge-lookup --probe-dir over the run's planes (exit $rc): $(head -3 <<<"$out" | tr '\n' ' ' | cut -c1-200)"
        fi
        d2="$pdir/snaponly"
        mkdir -p "$d2" && chmod 755 "$d2" && cp -p "$base/default/planes/reputation.bin" "$d2/snapshot.bin"
        out=$("$HERE/whisper-edge-lookup" --probe-dir "$d2" 2>&1); rc=$?
        if [ "$rc" = 0 ] && grep -q 'plane reputation *state=absent' <<<"$out" && grep -q 'snapshot.bin is here and reputation.bin is not' <<<"$out"; then
            ok "whisper-edge-lookup --probe-dir over a snapshot-only directory: reputation absent, the note names the fix"
        else
            bad "whisper-edge-lookup --probe-dir over a snapshot-only directory (exit $rc): $(grep -m2 'reputation\|note' <<<"$out" | tr '\n' ' ' | cut -c1-200)"
        fi
    fi
    [ -n "$pdir" ] && rm -rf "$pdir"
    # 6. determinism: two runs from the same seed write the same bytes (the planes included)
    if [ -d "$base/default" ]; then
        d2="$base/default-again"
        if produce "$d2" default >/dev/null 2>&1 && diff -r "$base/default" "$d2" >/dev/null; then
            ok "determinism: a second run writes a byte-identical run directory ($(find "$d2" -type f | wc -l) files)"
        else
            bad "determinism: a second run differs: $(diff -rq "$base/default" "$d2" 2>&1 | head -3 | tr '\n' ' ')"
        fi
    fi
    # 7. the control: a planted disagreement between the compiler's text and the interpreter's refuses the run
    d2="$base/planted"
    if out=$(XSERVER_CASES_PLANT=text produce "$d2" default 2>&1); then
        bad "control: the planted text disagreement was not refused"
    elif grep -q 'planted: the canonical texts were declared unequal' <<<"$out"; then
        ok "control: a planted text disagreement refuses the run by name"
    else
        bad "control: the planted run failed for another reason: $(tail -1 <<<"$out")"
    fi
    # 8. the input grammar's own controls still refuse: a request without its peer
    if [ -d "$base/default" ]; then
        d2="$base/nopeer"
        cp -r "$base/default" "$d2"
        sed -i '1s/\tpeer=[^\t]*//' "$d2/cases.in"
        out=$(bash "$EDGE/xserver-gate.sh" --check-inputs "$d2" 2>&1); rc=$?
        if [ "$rc" = 2 ] && grep -q 'has no peer' <<<"$out"; then
            ok "control: the input half with one peer removed is refused by name"
        else
            bad "control: a removed peer was not refused (exit $rc)"
        fi
    fi
    # 9. the hops run: a third configuration, `trusted_hops 2` at the http level on all three servers, and the
    # hop host's shapes that flip between the runs (POLICY.md 3.9: fewer than N entries judge the leftmost,
    # with the unparsed note; the Nth from the right otherwise)
    d2="$base/hops"
    if out=$(produce "$d2" default 2 2>&1) && bash "$EDGE/xserver-gate.sh" --check-inputs "$d2" >/dev/null 2>&1 \
       && grep -q '^whisper_edge_trusted_hops 2;$' "$d2/conf/nginx.conf" && grep -q '^WhisperEdgeTrustedHops 2$' "$d2/conf/apache.conf" \
       && grep -q '^    whisper_edge_trusted_hops 2$' "$d2/conf/litespeed.conf"; then
        local one0 one2
        one0=$(grep -m1 "^hop.one.b0	" "$base/default/python.col" | grep -o 'var_reason=[^	]*')
        one2=$(grep -m1 "^hop.one.b0	" "$d2/python.col" | grep -o 'var_reason=[^	]*')
        if [ "$one0" = 'var_reason=-' ] && [ "$one2" = 'var_reason=floor-header-unparsed' ]; then
            ok "hops run: --hops 2 renders trusted_hops 2 on every server and passes check-inputs; hop.one reads $one0 at hops 0 and $one2 at hops 2"
        else
            bad "hops run: hop.one reads $one0 at hops 0 and $one2 at hops 2 (want - and floor-header-unparsed)"
        fi
    else
        bad "hops run: produce --hops 2 or its input half failed: $(tail -2 <<<"$out" | tr '\n' ' ')"
    fi
    # 10. the HEAD family: judged like GET, no body to classify, so the expected class is `-` on every server
    if [ -d "$base/default" ]; then
        local nhead ndash
        nhead=$(grep -c "	method=HEAD	" "$base/default/cases.in")
        ndash=$(grep '^head\.' "$base/default/cases.col" | grep -c 'class_nginx=-	class_apache=-	class_litespeed=-')
        if [ "$nhead" -ge 10 ] && [ "$nhead" = "$(grep -c '^head\.' "$base/default/cases.col")" ] && [ "$ndash" = "$nhead" ] \
           && grep -q "^head.crit.b0	action=deny" "$base/default/oracle.col" && grep -q "^head.crit-acme-exact.b0	action=allow" "$base/default/oracle.col"; then
            ok "HEAD family: $nhead HEAD cases, every one with class - on all three servers; crit denied, the exact ACME form exempt"
        else
            bad "HEAD family: $nhead HEAD lines in cases.in, $ndash with class - everywhere"
        fi
        # 11. the unix-socket peer: nginx and LiteSpeed alone, the header's client judged, `::` with none
        local nunix
        nunix=$(grep -c "	peer=unix:	" "$base/default/cases.in")
        if [ "$nunix" -ge 8 ] && ! grep -qv "	servers=nginx,litespeed	" <<<"$(grep "	peer=unix:	" "$base/default/cases.in")" \
           && grep -q '^    listen unix:@SOCK@;$' "$base/default/conf/nginx.conf" && grep -q 'address UDS://@SOCK@' "$base/default/conf/litespeed.conf" \
           && grep -q "^unx.hdr-high.b0	action=deny" "$base/default/oracle.col" \
           && grep -q 'var_floor_addr=::	' <<<"$(grep -m1 "^unx.absent.b0	" "$base/default/python.col")" \
           && grep -q 'var_reason=floor-header-missing' <<<"$(grep -m1 "^unx.absent.b0	" "$base/default/python.col")"; then
            ok "unix-socket peer: $nunix cases on nginx and LiteSpeed alone, the listeners rendered, the header's client judged (hdr-high denied) and :: with the header missing"
        else
            bad "unix-socket peer: $nunix peer=unix: lines; listeners or verdicts off: $(grep -m1 '^unx.absent.b0	' "$base/default/python.col" | cut -c1-160)"
        fi
        # 12. the grace tenant: generation 2, valid-until an hour before the pinned clock, installed before the
        # revocation; the twin reads the tenant attributes as stale:<v> and the token carries ~
        local vu
        vu=$(python3 -I -c "import struct,sys; print(struct.unpack_from('<Q', open(sys.argv[1],'rb').read(40), 32)[0])" "$base/default/next/tenant-grace.bin")
        if grep -q "	plane=tenant.bin	op=install	from=next/tenant-grace.bin$" "$base/default/schedule.in" && [ "$vu" = "$((now_ms - 3600000))" ] \
           && grep -q 'var_tenant_allow=stale:' <<<"$(grep -m1 '^off.crit.b6	' "$base/default/python.col")" \
           && grep -qE 'tenant:2\.[0-9a-f]{8}~' <<<"$(grep -m1 '^off.crit.b6	' "$base/default/python.col")"; then
            ok "grace tenant: step 6 installs generation 2 with valid-until $vu (the pinned clock less one hour); the twin renders stale:<v> and tenant:2.<d8>~"
        else
            bad "grace tenant: valid-until $vu (want $((now_ms - 3600000))), or the twin's rendering: $(grep -m1 '^off.crit.b6	' "$base/default/python.col" | grep -o 'var_tenant_allow=[^	]*\|tenant:2[^ 	]*' | tr '\n' ' ')"
        fi
    fi
    # 13. the gate's age control: a run directory whose grace step is older than the gate's bound is refused by name
    d2="$base/old-grace"
    if XSERVER_CASES_NOW=$((now_ms - 40 * 3600 * 1000)) produce "$d2" default >/dev/null 2>&1; then
        out=$(bash "$EDGE/xserver-gate.sh" --check-inputs "$d2" 2>&1); rc=$?
        if [ "$rc" = 1 ] && grep -q 'the servers would read it lapsed' <<<"$out"; then
            ok "control: a run directory produced 40 h ago is refused by name: $(grep -m1 'lapsed' <<<"$out" | cut -c1-120)"
        else
            bad "control: a 40 h old grace step was not refused (exit $rc): $(head -2 <<<"$out" | tr '\n' ' ')"
        fi
    else
        bad "control: the old-grace produce failed"
    fi
    rm -rf -- "$base"
    echo "xserver-cases selftest: $checks checks, $fails failures"
    [ "$fails" = 0 ]
}

case "${1:-}" in
    --xserver-columns)
        dir=${2:?--xserver-columns needs the run directory}
        export=default
        hops=0
        shift 2
        while [ $# -gt 0 ]; do
            case "$1" in
                --export) export=${2:?--export needs default or all}; shift 2 ;;
                --hops) hops=${2:?--hops needs a count}; shift 2 ;;
                *) echo "usage: $0 --xserver-columns DIR [--export default|all] [--hops N] | --selftest" >&2; exit 2 ;;
            esac
        done
        produce "$dir" "$export" "$hops"
        ;;
    --selftest) selftest ;;
    *) echo "usage: $0 --xserver-columns DIR [--export default|all] [--hops N] | --selftest" >&2; exit 2 ;;
esac
