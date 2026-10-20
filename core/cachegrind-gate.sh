#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# cachegrind-gate.sh - the machine-independent cost of a lookup and of a policy decision, and whether
# their indexes stay resident.
#
# hotpath-gate.sh proves what the hot path may not CONTAIN. This proves what it COSTS, in two layers
# that do not move with the machine the gate runs on:
#
# 1. CACHEGRIND. valgrind --tool=cachegrind simulates a pinned cache over a fixed address stream and
#    counts, per lookup or per request, the instructions executed and the D1 misses (reads and writes).
#    The rows' D1 is 32 KiB of 64-byte lines, fully associative, so it counts the code's footprint and no
#    conflict that depends on where the link put an object (below, at CG_FLAGS); the launch probe keeps
#    the hardware's 8-way sets, every array is 4096-byte aligned, and the same lookup touches the same
#    sets on every run. Both are gated within +-10% of the baseline committed for this architecture and compiler
#    (gate/cachegrind-baseline.tsv), over every slot of gate/cg_driver.c, each answer checked against a
#    reference before that slot's row is measured (the layout rows that run first, the link-order arm,
#    the D1 layout row and the 8-way conflict row, compare two builds of the same code with each other and
#    judge no answer; every slot they measure is checked against its reference before its own row):
#      - the routing kinds FORMAT.md §4 ships (IPv4 radix-18, IPv6 rank-64s) and the shipped format-1
#        lookups, on the dense stream (the uniform stream is printed, never gated);
#      - the LOOKUP-ONLY rows the policy evaluator's composed bound prices its finds with: each of the
#        default policy's planes at the counts the builder's manifests carry, over the default slot's
#        own named stream; the hold-harmless table at strides 16 and 4; every plane of the evaluator's
#        synthetic world. These are live today: they measure the finds in whisper_edge.h.
#      - the POLICY EVALUATOR's rows (POLICY.md section 6): the basis rows, the per-schema fill rows,
#        the pre-stage, the default policy, the worst case and the lines-and-lookups worst case. They
#        run when we_eval.h is in the tree. Until then each is reported DARK by name, after the driver
#        has been made to answer EMPTY for it (exit 3), so nothing is ever measured in its place. Once
#        they run, gate/cost-model.py solves the cost basis from them exactly (a rank check fails the
#        gate if the rows do not determine it), holds every derived constant within +-10% of its
#        committed value (gate/cost-constants.tsv), runs the soundness inequality of the composed bound
#        on every slot with a 0.8 tightness floor, and holds the worst-case fixture to the maximum over
#        every feasible program; the memo-hit mutant must then land OUTSIDE the band, or the band
#        proves nothing.
#    The LL figures are printed and never gated: LL indexes above the page offset, so its misses move
#    with where the kernel puts the pages.
#
# 2. RESIDENCY. The per-request sum of cold lines that a module reports at config test is an upper
#    bound only while the indexes it references stay in cache. cg_driver, built with -DWE_TRACE, feeds
#    every read to an LRU set-associative model at a NAMED geometry (gate/geometry.tsv), sweeps the index
#    regions once, runs the stream, and counts index-region misses: in the L2 model where the referenced
#    indexes fit in L2, in the LLC model otherwise, and the level is stated on every row. Rows: the two
#    routing planes alone and together; each default-policy plane ALONE; and, with the evaluator, the
#    default and worst slots BESIDE THE PROGRAM, whose plane-index misses must stay within +-10% of the
#    alone-rows and whose program blocks must take ZERO misses in a separate LLC run. Zero is otherwise
#    asserted only for the radix routing index against the LLC. A mean LL miss rate cannot answer this
#    question (a non-resident index still shows 4 or 5 misses per lookup, under any ceiling), which is
#    why the model is in the harness.
#
# The routing inputs are bench/run-x86.sh's: the pinned CAIDA tables, flattened and asserted by row
# count and sha256 (run-x86.sh --prepare). The default planes and the evaluator's world are written by
# the test suite's writer from a pinned seed and loaded by the real loader.
#
# Usage: cachegrind-gate.sh [workdir] [--write-baseline]
#   --write-baseline replaces this architecture's rows in gate/cachegrind-baseline.tsv (and, with the
#   evaluator, gate/cost-constants.tsv) with this run's; the other architecture's rows are kept. A
#   missing row is a failure that prints the measured values.
# Environment: WE_BENCH_DATA (where the flattened tables live; default $TMPDIR/whisper-edge-bench),
#              WE_RESIDENCY_GEOMETRY (a row of gate/geometry.tsv; default production when filled in,
#              else reference), WE_CG_COUNT (lookups per lookup-row run, default 1000000),
#              WE_CG_JOBS (the layout and conflict rows' valgrind runs made at once, default nproc).
set -euo pipefail

cd "$(dirname "$0")"
HERE=$(pwd)
WORK=""
WRITE=0
for a in "$@"; do
    case "$a" in
        --write-baseline) WRITE=1 ;;
        -*) echo "usage: cachegrind-gate.sh [workdir] [--write-baseline]" >&2; exit 2 ;;
        *) WORK=$a ;;
    esac
done
[ -n "$WORK" ] || WORK=$(mktemp -d)
if [ "$WRITE" = 1 ] && [ "${WE_CG_D1_HW:-0}" = 1 ]; then
    echo "usage: WE_CG_D1_HW=1 is the layout row's control and measures no row the baseline holds; --write-baseline refuses it" >&2
    exit 2
fi
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
DATA="${WE_BENCH_DATA:-${TMPDIR:-/tmp}/whisper-edge-bench}"
COUNT="${WE_CG_COUNT:-1000000}"
BASELINE="$HERE/gate/cachegrind-baseline.tsv"
CONFLICT_BASE="$HERE/gate/conflict-baseline.tsv"   # the 8-way conflict row's figures (best placement, production link), per architecture and compiler
CONSTANTS="$HERE/gate/cost-constants.tsv"
GEOMETRY="$HERE/gate/geometry.tsv"
TOL_PCT=10
# the routing and shipped slots, on the dense (gated) and uniform (printed) streams
SLOTS=(plane-v4-radix18 plane-v6-rank64s shipped-v4 shipped-v6)
# the lookup-only rows, each on its own named stream
QSLOTS=(lookup-reputation@q4 lookup-reputation@q6 lookup-tor@q4 lookup-rpki-unreachable@q4
        lookup-rpki-unreachable@q6 lookup-hh@16 lookup-hh@4
        lookup-reputation@basis lookup-tor@basis lookup-rpki-unreachable@basis lookup-routing@basis
        lookup-anonymizer@basis lookup-threat@basis lookup-registry@basis lookup-tenant@basis lookup-hh@basis)
fail=0
dark=0          # evaluator rows not measured because we_eval.h is absent
vdark=0         # evaluator rows not measured because their reference verdicts are absent
ev_rows=0       # every evaluator row this run met, live or dark, so the DARK count can be held to it

ARCH=$(uname -m)
case "$ARCH" in arm64) ARCH=aarch64 ;; amd64) ARCH=x86_64 ;; esac

if ! command -v valgrind >/dev/null 2>&1; then
    echo "CACHEGRIND GATE: FAILED: valgrind is not installed, so nothing was measured"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "CACHEGRIND GATE: FAILED: python3 is not installed, so the cost model cannot run"
    exit 1
fi
echo "cachegrind gate, $ARCH, $(valgrind --version), $COUNT lookups per lookup row"

# ---- the cost model's own negative controls, before it judges anything ------------------------------
if ! python3 gate/cost-model.py selftest; then
    echo "GATE FAIL: gate/cost-model.py failed its own controls, so nothing it computes can be trusted"
    fail=1
fi

# ---- the policy evaluator: live or dark ---------------------------------------------------------------
EVAL_DARK=""
EVAL_SRC=()
EVAL_DEF=()
if [ -f we_eval.h ]; then
    EVAL_DEF=(-DWE_HAVE_EVAL)
    if [ -f we_policy.c ]; then
        EVAL_SRC+=(we_policy.c)
    else
        echo "GATE FAIL: we_eval.h is in the tree but we_policy.c is not, so the evaluator cannot be built"
        fail=1
    fi
else
    EVAL_DARK="we_eval.h is not in this tree"
    echo "  DARK: the policy evaluator's rows are not measured: $EVAL_DARK; they run, with no edit here, once it is"
fi

# ---- the data, pinned and asserted -----------------------------------------------------------------
"$HERE/bench/run-x86.sh" "$DATA" --prepare | sed 's/^/  /'

# ---- layer 1: cachegrind -----------------------------------------------------------------------------
# THE D1 THE ROWS GATE is fully associative: 32 KiB of 64-byte lines in one set of 512 ways, so a row
# counts the code's footprint (each line it first touches, and each it touched again after the capacity
# pushed it out) and no conflict misses. A conflict miss is where two data objects land against each other
# in an 8-way set, which follows the link: the module renderers' strings and tables are compiled into the
# driver, linked after the core, so an unrelated static anywhere in the core moved them, and the rows read
# that move as the code's (measured: one 1,000-byte plant moved module-export's 8-way D1 from 26.135
# to 23.456 misses a request on gcc aarch64 with every instruction the same; fully associative, 5.989 and
# 5.998). The hardware's own geometry, 8-way, stays where a set-associative cache is the point: the launch
# probe and its control below prove the harness's placement is stable, which only a conflict can show.
# WE_CG_D1_HW=1 measures the rows on the 8-way geometry instead: the layout row's control.
CG_FLAGS=(--tool=cachegrind --cache-sim=yes --instr-at-start=no
          "--I1=32768,8,64" "--D1=32768,512,64" "--LL=8388608,16,64")
HW_FLAGS=(--tool=cachegrind --cache-sim=yes --instr-at-start=no
          "--I1=32768,8,64" "--D1=32768,8,64" "--LL=8388608,16,64")
[ "${WE_CG_D1_HW:-0}" = 1 ] && CG_FLAGS=("${HW_FLAGS[@]}")
CORE_SRC=(whisper_edge.c we_writer.c we_sha256.c we_counters.c)
RES_SLACK=2     # misses a plane beside the program may differ from its alone-row by, whatever the percentage (see the band below)
# THE LAUNCH. A D1 count is exact only if every address the measured region touches has the same page
# offset on every run. The arrays are 4096-byte aligned and the driver runs the measured loop on a stack
# carved from that arena (cg_on_own_stack in gate/cg_driver.c), so neither the environment nor argv can
# move a count; the launch probe below proves it on every run. Every valgrind client is also started
# under env -i with this fixed environment, so the launch is the same wherever the gate runs.
VALGRIND=$(command -v valgrind)
CG_ENV=(PATH=/usr/bin:/bin LC_ALL=C)
[ -n "${WE_HOLD_HARMLESS:-}" ] && CG_ENV+=("WE_HOLD_HARMLESS=$WE_HOLD_HARMLESS")

# measure BIN SLOT STREAM COUNT -> "instr d1 ll irtotal" per lookup or request, from the summary line
measure() {
    local bin=$1 slot=$2 stream=$3 n=$4 out ev sm
    out="$WORK/cg.$1.${2//@/_}.$3${OUT_TAG:-}.out"
    env -i "${CG_ENV[@]}" "$VALGRIND" "${CG_FLAGS[@]}" --cachegrind-out-file="$out" "$WORK/$bin" "$DATA" cg "$slot" "$stream" "$n" </dev/null \
        >"$out.stdout" 2>"$out.log" || { echo "ERROR"; return 0; }
    ev=$(sed -n 's/^events: //p' "$out")
    sm=$(sed -n 's/^summary: //p' "$out")
    awk -v ev="$ev" -v sm="$sm" -v n="$n" 'BEGIN {
        k = split(ev, e, " "); split(sm, s, " ");
        for (i = 1; i <= k; i++) v[e[i]] = s[i];
        printf "%.2f %.3f %.3f %d\n", v["Ir"] / n, (v["D1mr"] + v["D1mw"]) / n, (v["DLmr"] + v["DLmw"]) / n, v["Ir"] }'
}

# measure_hw BIN SLOT STREAM COUNT -> as measure, on the hardware's 8-way D1 (the layout row's control)
measure_hw() {
    local -a keep=("${CG_FLAGS[@]}")
    local OUT_TAG=.hw   # its own output file, so a run of each geometry on one binary and slot can run at once
    CG_FLAGS=("${HW_FLAGS[@]}")
    measure "$@"
    CG_FLAGS=("${keep[@]}")
}

# cg_cached fa|hw BIN SLOT -> CG_LINE, measure's (fa, the rows' geometry) or measure_hw's (hw) line for 20,000
# requests of SLOT on BIN, measured once a run: the D1 layout row and the 8-way conflict row read the same
# runs, and the cache (cleared when the run starts) is what keeps the second from measuring them again
cg_cached() {
    local f="$WORK/cache.$1.$2.${3//@/_}"
    if [ ! -s "$f" ]; then
        if [ "$1" = hw ]; then measure_hw "$2" "$3" e 20000 > "$f.tmp"; else measure "$2" "$3" e 20000 > "$f.tmp"; fi
        mv "$f.tmp" "$f"
    fi
    CG_LINE=$(cat "$f")
}
# cg_prefetch KIND:BIN:SLOT... -> each into cg_cached's cache, CG_JOBS at a time (a count is simulated, so
# it is the same however many run beside it)
cg_prefetch() {
    local r n=0
    for r in "$@"; do
        local k=${r%%:*} rest=${r#*:}
        ( cg_cached "$k" "${rest%%:*}" "${rest#*:}" ) &
        n=$((n + 1))
        if [ "$n" -ge "$CG_JOBS" ]; then wait -n || true; n=$((n - 1)); fi
    done
    wait || true
}
CG_JOBS=${WE_CG_JOBS:-$(nproc 2>/dev/null || echo 2)}
rm -f "$WORK"/cache.fa.* "$WORK"/cache.hw.*
# THE 8-WAY CONFLICT ROW's module rows (below), every module request path the driver has: the decision
# alone, with a tenant, the export pass, its pre-staged and all-planes forms, the pre-decision variables
# (all and one), and the worst case. The D1 layout row measures the same rows, and cachegrind-target.sh
# requires each one's committed figures.
CF_SLOTS=(module-default module-default-tenant module-export module-export-prestage module-export-all
          module-var-prerewrite module-var-prerewrite@1 module-worst)
# the conflict row's bound, FLAT: the committed figure plus exactly three misses a request, and the cure
# that mirrors it, three under
CF_MARGIN=3
cf_bound() { awk -v b="$1" -v k="$CF_MARGIN" 'BEGIN { printf "%.3f", b + k }'; }
cf_over() { awk -v m="$1" -v b="$2" -v k="$CF_MARGIN" 'BEGIN { exit !(m > b + k) }'; }    # outside the bound
cf_cured() { awk -v m="$1" -v b="$2" -v k="$CF_MARGIN" 'BEGIN { exit !(m < b - k) }'; }   # a cured conflict

# measure_ir BIN SLOT N -> the Ir total of N requests with the cache simulator off (instructions only)
measure_ir() {
    local out="$WORK/ir.$1.${2//@/_}.$3.out"
    env -i "${CG_ENV[@]}" "$VALGRIND" --tool=cachegrind --cache-sim=no --instr-at-start=no --cachegrind-out-file="$out" \
        "$WORK/$1" "$DATA" cg "$2" e "$3" </dev/null >"$out.stdout" 2>"$out.log" || { echo ERROR; return 0; }
    awk '/^events: / { split($0, e, " ") } /^summary: / { split($0, v, " "); for (i = 2; i in e; i++) if (e[i] == "Ir") print v[i] }' "$out"
}

# measure_refs BIN SLOT N -> the run's Ir, Dr and Dw totals for N requests (the data-refs row sums the two;
# the module controls judge reads and writes apart)
measure_refs() {
    local out="$WORK/refs.$1.${2//@/_}.$3.out"
    env -i "${CG_ENV[@]}" "$VALGRIND" --tool=cachegrind --cache-sim=yes --instr-at-start=no --cachegrind-out-file="$out" \
        "$WORK/$1" "$DATA" cg "$2" e "$3" </dev/null >"$out.stdout" 2>"$out.log" || { echo ERROR; return 0; }
    awk '/^events: / { k = split($0, e, " ") } /^summary: / { split($0, v, " ") }
         END { for (i = 2; i <= k; i++) x[e[i]] = v[i]; print x["Ir"], x["Dr"], x["Dw"] }' "$out"
}

# launch_probe BIN [VAR=VALUE] -> the distinct "instructions D1" figures of one evaluator row measured
# under 34 launches that differ ONLY in what the kernel copies above main's frame: the environment padded
# by 0 to 3968 bytes in steps of 128 (one page of stack offsets), the gate's own environment inherited, and
# the data directory reached through a symlink under a 97-character directory name. Prints one line per
# distinct figure.
PROBE_SLOT=evaluator-basis-rules-4@floor
PROBE_REQ=2000
launch_probe() {
    local bin=$1 plant=${2:-} n pad out i=0 tag=plain
    local -a extra=()
    [ -n "$plant" ] && { extra=("$plant"); tag=planted; }
    mkdir -p "$WORK/probe-a-data-path-one-hundred-bytes-longer-than-the-gate-gives-its-driver-xxxxxxxxxxxxxxxxxxxxxxx"
    ln -sfn "$DATA" "$WORK/probe-a-data-path-one-hundred-bytes-longer-than-the-gate-gives-its-driver-xxxxxxxxxxxxxxxxxxxxxxx/d"
    {
        for n in $(seq 0 128 3968) inherit longpath; do
            out="$WORK/probe.$tag.$bin.$i.out"; i=$((i + 1))
            case "$n" in
                inherit)  env "${extra[@]}" "$VALGRIND" "${HW_FLAGS[@]}" --cachegrind-out-file="$out" "$WORK/$bin" "$DATA" cg "$PROBE_SLOT" e "$PROBE_REQ" ;;
                longpath) env -i "${CG_ENV[@]}" "${extra[@]}" "$VALGRIND" "${HW_FLAGS[@]}" --cachegrind-out-file="$out" "$WORK/$bin" \
                              "$WORK/probe-a-data-path-one-hundred-bytes-longer-than-the-gate-gives-its-driver-xxxxxxxxxxxxxxxxxxxxxxx/d" cg "$PROBE_SLOT" e "$PROBE_REQ" ;;
                *)        pad=$(printf '%*s' "$n" '' | tr ' ' x)
                          env -i "${CG_ENV[@]}" "${extra[@]}" "WE_CG_PROBE_PAD=$pad" "$VALGRIND" "${HW_FLAGS[@]}" --cachegrind-out-file="$out" \
                              "$WORK/$bin" "$DATA" cg "$PROBE_SLOT" e "$PROBE_REQ" ;;
            esac </dev/null >/dev/null 2>"$out.log" || { echo "ERROR $n"; continue; }
            awk '/^events: / { k = split($0, e, " ") } /^summary: / { split($0, v, " ") }
                 END { for (j = 2; j <= k; j++) x[e[j]] = v[j]; print x["Ir"], x["D1mr"] + x["D1mw"] }' "$out"
        done
    } | sort -u
}

# per_rule BIN -> "ir/rule refs/rule" as exact fractions: each slot's per-request figure is the difference
# between N and N/2 requests (no per-run constant survives), and the per-rule figure the difference between
# the 128-rule and the 64-rule slot over the 64 rules between them
per_rule() {
    local s n h a b c
    local -a v=()
    for s in evaluator-dr-64 evaluator-dr-128; do
        n=${REQ[$s]}; h=$((n / 2))
        read -r a b c <<<"$(measure_refs "$1" "$s" "$n")"
        v+=("$a" "$((b + c))")
        read -r a b c <<<"$(measure_refs "$1" "$s" "$h")"
        v+=("$a" "$((b + c))" "$((n - h))")
    done
    python3 -c '
import sys
from fractions import Fraction as F
x = [int(t) for t in sys.argv[1:]]
i64 = F(x[0] - x[2], x[4]); r64 = F(x[1] - x[3], x[4])
i128 = F(x[5] - x[7], x[9]); r128 = F(x[6] - x[8], x[9])
print((i128 - i64) / 64, (r128 - r64) / 64)' "${v[@]}"
}

# ---- the module rows' controls (C1+, C2+, C7, C6) -------------------------------------------------------
# Each is a build of this driver with one planted defect, judged against the production run's own figures:
# the model's constants (its `const` lines) and the rows it measured. Arithmetic is exact (fractions).
mconst() { awk -F'\t' -v n="$2" '$1 == "const" && $2 == n { print $3; exit }' "$WORK/model.$1.out"; }
per_req() { awk -F'\t' -v s="$2" '$1 == s { print $2; exit }' "$MEAS"; }
fx() { python3 -c 'import sys
from fractions import Fraction as F
print(eval(sys.argv[1]))' "$1"; }
# ir_diff BIN SLOT -> instructions per request by the difference method (n and n/2 requests), or ERROR
ir_diff() {
    local n=${REQ[$2]} h a b
    h=$((n / 2))
    a=$(measure_ir "$1" "$2" "$n"); b=$(measure_ir "$1" "$2" "$h")
    if [ "$a" = ERROR ] || [ "$b" = ERROR ] || [ -z "$a" ] || [ -z "$b" ]; then echo ERROR; return; fi
    echo "$((a - b))/$h"
}
# refs_diff BIN SLOT -> "Ir Dr Dw" per request by the difference method, or ERROR
refs_diff() {
    local n=${REQ[$2]} h a1 a2 a3 b1 b2 b3
    h=$((n / 2))
    read -r a1 a2 a3 <<<"$(measure_refs "$1" "$2" "$n")"
    read -r b1 b2 b3 <<<"$(measure_refs "$1" "$2" "$h")"
    if [ "$a1" = ERROR ] || [ "$b1" = ERROR ] || [ -z "$a1" ] || [ -z "$b1" ]; then echo ERROR; return; fi
    echo "$((a1 - b1))/$h $((a2 - b2))/$h $((a3 - b3))/$h"
}
# build_ctl CC TAG FLAGS... -> $WORK/cg_CC_TAG, or the GATE FAIL line and 1
build_ctl() {
    local cc=$1 tag=$2
    shift 2
    if ! "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" "$@" -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_${cc}_$tag" \
           "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c 2>"$WORK/ctl.$tag.$cc.err"; then
        echo "GATE FAIL: the module control $tag does not build ($cc): $(head -1 "$WORK/ctl.$tag.$cc.err" | cut -c1-120)"
        fail=1
        return 1
    fi
}
# outside BAND-CENTRE VALUE -> True when VALUE lies outside +-TOL_PCT% of the centre
outside() { fx "abs(F('$2') - F('$1')) > F($TOL_PCT, 100) * abs(F('$1'))"; }
mod_controls() {
    local cc=$1 c_view c_count c_export c_prerewrite md_per slot k bound pi pr pw mi mr mw a b d di dr dw row st
    c_view=$(mconst "$cc" c_view); c_count=$(mconst "$cc" c_count@ctx0)
    c_export=$(mconst "$cc" c_export); c_prerewrite=$(mconst "$cc" c_prerewrite)
    md_per=$(per_req "$cc" module-default)
    if [ -z "$c_view" ] || [ -z "$c_count" ] || [ -z "$c_export" ] || [ -z "$c_prerewrite" ] || [ -z "$md_per" ]; then
        echo "GATE FAIL: the module constants were not derived ($cc), so no module control can be judged"
        fail=1
        return
    fi
    # the control-blind precheck: a view that costs nothing cannot be seen missing
    if [ "$(fx "F('$c_view') > 0")" != True ]; then
        echo "GATE FAIL: control blind ($cc): c_view is $c_view, not above 0, so WE_TEST_MOD_ALL_VIEWS cannot be seen"
        fail=1
        return
    fi
    # C1+: every view read. On each held-out row the mutant must cost more instructions than the production
    # row (whose prediction is exact, so the production model refuses the mutant's row by name) and at least
    # 8 - k data reads more a request, k the row's referenced count (4 for module-default-tenant)
    if build_ctl "$cc" allviews -DWE_CG_ALLVIEWS; then
        for k in module-views@3:3 module-views@5:5 module-views@6:6 module-views@7:7 module-default-tenant:4; do
            slot=${k%%:*}
            bound=$((8 - ${k#*:}))
            read -r pi pr pw <<<"$(refs_diff "cg_$cc" "$slot")"
            read -r mi mr mw <<<"$(refs_diff "cg_${cc}_allviews" "$slot")"
            if [ "$pi" = ERROR ] || [ "$mi" = ERROR ]; then
                echo "GATE FAIL: C1+ could not measure $slot ($cc)"
                fail=1
                continue
            fi
            di=$(fx "F('$mi') - F('$pi')"); dr=$(fx "F('$mr') - F('$pr')")
            if [ "$(fx "F('$di') > 0 and F('$dr') >= $bound")" = True ]; then
                echo "ok   C1+: WE_TEST_MOD_ALL_VIEWS on $slot ($cc): +$di instructions a request, which the exact production prediction refuses by name, and +$dr data reads, at least 8 - k = $bound"
            else
                echo "GATE FAIL: C1+: WE_TEST_MOD_ALL_VIEWS on $slot ($cc): +$di instructions and +$dr data reads a request; the reads must rise by at least $bound and the instructions must rise"
                fail=1
            fi
        done
    fi
    # C7: a locked increment moves c_count@ctx0 outside its band (module-count@64-ctx less @1-ctx0, over 63 increments)
    if build_ctl "$cc" lockcount -DWE_CG_LOCKCOUNT; then
        a=$(ir_diff "cg_${cc}_lockcount" module-count@1-ctx); b=$(ir_diff "cg_${cc}_lockcount" module-count@64-ctx)
        if [ "$a" = ERROR ] || [ "$b" = ERROR ]; then
            echo "GATE FAIL: C7 could not measure the count rows under WE_MOD_TEST_LOCKED_COUNT ($cc)"
            fail=1
        else
            d=$(fx "(F('$b') - F('$a')) / 63")
            if [ "$(outside "$c_count" "$d")" = True ]; then
                echo "ok   C7: the locked increment costs $d an increment against c_count@ctx0 $c_count ($cc), outside the +-$TOL_PCT% band"
            else
                echo "GATE FAIL: C7: the locked increment costs $d an increment against c_count@ctx0 $c_count ($cc), INSIDE the +-$TOL_PCT% band"
                fail=1
            fi
        fi
    fi
    # C2+: every attribute rendered on the default export path moves c_export outside its band
    if build_ctl "$cc" eager -DWE_CG_EAGER_EXPORT; then
        a=$(ir_diff "cg_${cc}_eager" module-export)
        if [ "$a" = ERROR ]; then
            echo "GATE FAIL: C2+ could not measure module-export under WE_MOD_TEST_EAGER_EXPORT ($cc)"
            fail=1
        else
            d=$(fx "F('$a') - F('$md_per')")
            if [ "$(outside "$c_export" "$d")" = True ]; then
                echo "ok   C2+: WE_MOD_TEST_EAGER_EXPORT makes the export pass cost $d against c_export $c_export ($cc), outside the +-$TOL_PCT% band"
            else
                echo "GATE FAIL: C2+: WE_MOD_TEST_EAGER_EXPORT makes the export pass cost $d against c_export $c_export ($cc), INSIDE the +-$TOL_PCT% band"
                fail=1
            fi
        fi
    fi
    # C2+: the lazy fill's control, judged on data writes. The local context rebuilt per plane after the
    # first adds the 80-byte verdict clear (we_verdict_clear: ten 8-byte stores) and the 320-byte slot copy
    # per extra fill, 400 bytes; module-export-prestage fills 5/2 planes a request, so 3/2 extra: 600 bytes
    # a request. Cachegrind counts one write per store INSTRUCTION, and how many bytes one store moves is the
    # code generation's, not the design's: NEON and SSE stores move 16, glibc's AVX memmove 32, gcc's inline
    # rep movsq 8 (measured on these 600 bytes: 41 and 39 writes a request on aarch64 gcc and clang, 14.6 and
    # 15.4 bytes a store; 69.5 and 29.5 on x86_64 gcc and clang, 8.6 and 20.3). The literal "at least 20 a
    # fill" this read until the x86_64 write run of 2026-10-14 was aarch64's store width, and clang on
    # x86_64 refused it at 29.5 with every byte written. The bound is therefore the bytes over the widest
    # store any current ISA issues, 64 (AVX-512): at least 600 / 64 writes a request, architecture-neutral
    # by construction; the implied bytes a store are printed, never judged.
    if build_ctl "$cc" lazyplane -DWE_CG_LAZY_PER_PLANE; then
        read -r pi pr pw <<<"$(refs_diff "cg_$cc" module-export-prestage)"
        read -r mi mr mw <<<"$(refs_diff "cg_${cc}_lazyplane" module-export-prestage)"
        if [ "$pi" = ERROR ] || [ "$mi" = ERROR ]; then
            echo "GATE FAIL: the lazy control could not be measured on module-export-prestage ($cc)"
            fail=1
        else
            dw=$(fx "F('$mw') - F('$pw')"); di=$(fx "F('$mi') - F('$pi')")
            if [ "$(fx "F('$dw') > 0")" != True ]; then
                echo "GATE FAIL: lazy control blind ($cc): the per-plane local context adds $dw data writes a request, not above 0"
                fail=1
            elif [ "$(fx "F('$dw') >= F(600, 64)")" = True ]; then
                bps=$(fx "round(600 / F('$dw'), 1)")
                echo "ok   C2+: the per-plane local context adds $dw data writes a request on module-export-prestage ($cc), at least 600 bytes / 64 = 75/8 (3/2 rebuilds of 400 bytes, every store 64 bytes wide); $bps bytes a store implied, instructions +$di, both printed, not judged"
            else
                echo "GATE FAIL: C2+: the per-plane local context adds $dw data writes a request on module-export-prestage ($cc), under 600 bytes / 64 = 75/8"
                fail=1
            fi
        fi
    fi
    # the country class: a linear country scan moves module-export-all outside its own band
    if build_ctl "$cc" cscan -DWE_CG_COUNTRY_SCAN; then
        read -r di dr _ _ <<<"$(measure "cg_${cc}_cscan" module-export-all e "${REQ[module-export-all]}")"
        row=${GOT["$cc|module-export-all"]%% *}
        if [ "$di" = ERROR ] || [ -z "$row" ]; then
            echo "GATE FAIL: the country class could not be judged ($cc)"
            fail=1
        elif awk -v x="$di" -v b="$row" -v t="$TOL_PCT" 'BEGIN { exit !(x >= b * (1 - t / 100) && x <= b * (1 + t / 100)) }'; then
            echo "GATE FAIL: the country class: a linear country scan costs $di against $row on module-export-all ($cc), INSIDE the +-$TOL_PCT% band"
            fail=1
        else
            echo "ok   the country class: a linear country scan costs $di against $row on module-export-all ($cc), outside the +-$TOL_PCT% band"
        fi
    fi
    # the variable path's control: the local context rebuilt per read moves c_prerewrite outside its band
    if build_ctl "$cc" varread -DWE_CG_VAR_PER_READ; then
        a=$(ir_diff "cg_${cc}_varread" module-var-prerewrite)
        if [ "$a" = ERROR ]; then
            echo "GATE FAIL: the variable path's control could not be measured ($cc)"
            fail=1
        else
            d=$(fx "F('$a') - F('$md_per')")
            if [ "$(outside "$c_prerewrite" "$d")" = True ]; then
                echo "ok   the variable path: the local context rebuilt per read costs $d against c_prerewrite $c_prerewrite ($cc), outside the +-$TOL_PCT% band"
            else
                echo "GATE FAIL: the variable path: the local context rebuilt per read costs $d against c_prerewrite $c_prerewrite ($cc), INSIDE the +-$TOL_PCT% band"
                fail=1
            fi
        fi
    fi
    # THE ONE COPY's controls. The module rows and their evaluator twins run one compiled copy of the
    # decision (cg_decide in gate/cg_driver.c), so module-less-twin is the module's own work by
    # construction; these show that a cost regression on either side of that copy is still refused.
    # CS: the decision's hold-harmless search run twice inside the copy. Every row sees it, and c_prestage,
    # evaluator-prestage less its finds, leaves its band: the evaluator half still prices the decision.
    if build_ctl "$cc" plantsearch -DWE_CG_PLANT_SEARCH; then
        local c_pre
        c_pre=$(mconst "$cc" c_prestage)
        a=$(ir_diff "cg_${cc}_plantsearch" evaluator-prestage); b=$(ir_diff "cg_$cc" evaluator-prestage)
        if [ -z "$c_pre" ] || [ "$a" = ERROR ] || [ "$b" = ERROR ]; then
            echo "GATE FAIL: CS could not be judged ($cc): c_prestage ${c_pre:-not derived}, evaluator-prestage $b, planted $a"
            fail=1
        else
            d=$(fx "F('$a') - F('$b')")
            if [ "$(outside "$c_pre" "$(fx "F('$c_pre') + F('$d')")")" = True ]; then
                echo "ok   CS: the hold-harmless search run twice inside the decision's one copy costs +$d a request on evaluator-prestage, which moves c_prestage $c_pre outside the +-$TOL_PCT% band ($cc)"
            else
                echo "GATE FAIL: CS: the hold-harmless search run twice inside the decision's one copy costs +$d a request, which leaves c_prestage $c_pre INSIDE the +-$TOL_PCT% band ($cc)"
                fail=1
            fi
        fi
    fi
    # CM: 128 instructions of the module's own work before the decision, outside the copy
    # (WE_TEST_MOD_PRESTAGE_WORK). The module row must rise, its twin must not move by one instruction, and
    # c_mod_fixed must leave its band, the wider of the tolerance and the spread over the committed toolchains.
    if build_ctl "$cc" modwork -DWE_CG_MODWORK; then
        local m m0 t t0 c_fix spread
        c_fix=$(mconst "$cc" c_mod_fixed)
        spread=$(awk -F'\t' '$3 == "c_mod_fixed" { v = $4 + 0; if (n == 0 || v < lo) lo = v; if (n == 0 || v > hi) hi = v; n++ } END { print (n > 1 ? hi - lo : 0) }' "$CONSTANTS")
        m=$(ir_diff "cg_${cc}_modwork" module-allow); m0=$(ir_diff "cg_$cc" module-allow)
        t=$(ir_diff "cg_${cc}_modwork" evaluator-allow); t0=$(ir_diff "cg_$cc" evaluator-allow)
        if [ -z "$c_fix" ] || [ "$m" = ERROR ] || [ "$m0" = ERROR ] || [ "$t" = ERROR ] || [ "$t0" = ERROR ]; then
            echo "GATE FAIL: CM could not be judged ($cc): c_mod_fixed ${c_fix:-not derived}, module-allow $m0 / $m, evaluator-allow $t0 / $t"
            fail=1
        else
            dm=$(fx "F('$m') - F('$m0')"); dt=$(fx "F('$t') - F('$t0')")
            if [ "$(fx "F('$dt') == 0 and abs(F('$dm')) > max(F($TOL_PCT, 100) * abs(F('$c_fix')), F('$spread'))")" = True ]; then
                echo "ok   CM: the module's own planted work costs +$dm a request on module-allow and 0 on its twin evaluator-allow, which moves c_mod_fixed $c_fix outside its band (+-max($TOL_PCT%, $spread)) ($cc)"
            else
                echo "GATE FAIL: CM: the module's own planted work costs +$dm a request on module-allow and +$dt on its twin; the twin must not move and c_mod_fixed $c_fix must leave its band (+-max($TOL_PCT%, $spread)) ($cc)"
                fail=1
            fi
        fi
    fi
    # CX: this run's own module rows with module-worst one instruction a request dearer, through the model:
    # the basis must refuse the row by name, so EXACT is shown to see a +1 drift on the real module build
    {
        local mx="$WORK/meas.$cc.plus1.tsv"
        awk -F'\t' -v OFS='\t' '$1 == "module-worst" { split($2, q, "/"); $2 = (q[1] + q[2]) "/" q[2] } { print }' "$MEAS" > "$mx"
        if python3 gate/cost-model.py gate "$mx" "$CONSTANTS" "$ARCH" "$cc" "$TOL_PCT" > "$WORK/model.$cc.plus1.out" 2>&1 \
                || ! grep -q 'EXACT: .*module-worst' "$WORK/model.$cc.plus1.out"; then
            echo "GATE FAIL: CX: module-worst one instruction a request dearer on this run's own rows is not refused by name by the module basis ($cc)"
            fail=1
        else
            echo "ok   CX: module-worst one instruction a request dearer on this run's own rows is refused by name by the module basis ($cc)"
        fi
    }
    # and the all-views mutant stays this driver's: the hot-path module wrapper with it defined must not build
    st=0
    "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_TEST_MOD_ALL_VIEWS -I"$HERE" -c -o "$WORK/guard-views.$cc.o" hp_mod.c 2>"$WORK/guard-views.$cc.err" || st=$?
    if [ "$st" = 0 ]; then
        echo "GATE FAIL: hp_mod.c compiled with WE_TEST_MOD_ALL_VIEWS ($cc): the control is no longer the driver's alone"
        fail=1
    elif grep -q "cachegrind driver's control alone" "$WORK/guard-views.$cc.err"; then
        echo "ok   WE_TEST_MOD_ALL_VIEWS is refused outside the driver: hp_mod.c stops at we_module.h's guard ($cc)"
    else
        echo "GATE FAIL: hp_mod.c with WE_TEST_MOD_ALL_VIEWS failed, but not at the guard ($cc): $(head -1 "$WORK/guard-views.$cc.err" | cut -c1-120)"
        fail=1
    fi
}

# check_band SLOT CC INSTR D1 -> prints ok, or fails naming the slot; the baseline row is the arch's
check_band() {
    local slot=$1 cc=$2 di=$3 dd=$4 row bi bd verdict
    row=$(awk -F'\t' -v a="$ARCH" -v c="$cc" -v s="$slot" '$1 == a && $2 == c && $3 == s { print $5 "\t" $6 }' "$BASELINE" 2>/dev/null || true)
    if [ -z "$row" ] && [ "$STALE" = 1 ]; then
        echo "NOT PROVEN: $slot ($cc) measured instructions $di, D1 misses $dd; no $ARCH baseline on this layout"
        return
    fi
    if [ -z "$row" ]; then
        echo "GATE FAIL: no baseline for $ARCH $cc $slot (measured: instructions $di, D1 misses $dd);"
        echo "        run cachegrind-gate.sh --write-baseline on $ARCH and commit gate/cachegrind-baseline.tsv"
        fail=1
        return
    fi
    IFS=$'\t' read -r bi bd <<<"$row"
    if [ "$STALE" = 1 ]; then
        # a baseline measured on another driver layout is not this measurement: printed, never judged
        echo "NOT PROVEN: $slot ($cc) measured instructions $di, D1 misses $dd; the $ARCH baseline (instructions $bi, D1 misses $bd) is layout ${BASE_LAYOUT:-1}'s"
        return
    fi
    verdict=$(awk -v x="$di" -v b="$bi" -v y="$dd" -v c="$bd" -v t="$TOL_PCT" 'BEGIN {
        bad = "";
        if (x < b * (1 - t / 100) || x > b * (1 + t / 100)) bad = bad sprintf(" instructions %s against %s", x, b);
        if (y < c * (1 - t / 100) || y > c * (1 + t / 100)) bad = bad sprintf(" D1 misses %s against %s", y, c);
        print bad }')
    if [ -n "$verdict" ]; then
        echo "GATE FAIL: $slot ($cc) is outside +-$TOL_PCT% of its baseline:$verdict"
        fail=1
    else
        echo "ok   $slot ($cc) within +-$TOL_PCT% of baseline (instructions $bi, D1 misses $bd)"
    fi
}

COMPILERS=()
command -v gcc >/dev/null 2>&1 && COMPILERS+=(gcc)
command -v clang >/dev/null 2>&1 && COMPILERS+=(clang)
for want in gcc clang; do
    case " ${COMPILERS[*]:-} " in
        *" $want "*) ;;
        *) echo "GATE FAIL: $want is not installed; the band is per compiler and $want's is unchecked"; fail=1 ;;
    esac
done

# THE TOOLCHAIN THE BASELINE WAS MEASURED WITH. Counts are exact per compiler and valgrind, so a row
# measured with one compiler release says nothing about another: a run whose compiler or valgrind is not
# the one the baseline's header names for this architecture fails by name, and --write-baseline is how a
# new toolchain is adopted (it rewrites the header with the rows).
if [ "$WRITE" != 1 ]; then
    for cc in "${COMPILERS[@]}"; do
        want="# $ARCH $cc: $("$cc" --version | sed -n 1p), $(valgrind --version)"
        have=$(grep -F "# $ARCH $cc: " "$BASELINE" 2>/dev/null | sed -n 1p || true)
        if [ -z "$have" ]; then
            echo "GATE FAIL: gate/cachegrind-baseline.tsv names no toolchain for $ARCH $cc; it is measured with ${want#*: }"
            fail=1
        elif [ "${have#"$want"}" = "$have" ]; then
            echo "GATE FAIL: the baseline for $ARCH $cc was measured with ${have#*: }; this run has ${want#*: }"
            fail=1
        else
            # its control: the same header against a compiler one release away must not match
            planted="${want/ 1/ 9}"
            [ "$planted" = "$want" ] && planted="${want}-planted"
            if [ "${have#"$planted"}" != "$have" ]; then
                echo "GATE FAIL: the toolchain check accepted a planted compiler string for $ARCH $cc"
                fail=1
            else
                echo "ok   the baseline's toolchain is this run's for $ARCH $cc, and a different one is refused"
            fi
        fi
    done
fi

# THE LAYOUT the baseline was measured on: the driver prints its own (WE_CG_LAYOUT) in `align` mode, the
# baseline's header records the one each architecture's rows were written on, and rows from another layout
# are printed NOT PROVEN, never judged, until --write-baseline rewrites them on that architecture
STALE=0
LINK_BLIND=0
LINK_BLIND_WHY=""   # the row that was blind, named in the verdict
CF_DARK=0           # a module row with no conflict baseline on this layout: measured and printed, not judged
BASE_LAYOUT=$(sed -n "s/^# layout $ARCH: \([0-9]*\)\$/\1/p" "$BASELINE" 2>/dev/null | sed -n 1p)
DRV_LAYOUT=$(sed -n 's/^#define WE_CG_LAYOUT \([0-9]*\)$/\1/p' gate/cg_driver.c | sed -n 1p)
if [ "$WRITE" != 1 ] && [ "${BASE_LAYOUT:-1}" != "$DRV_LAYOUT" ]; then
    STALE=1
    echo "NOT PROVEN: the $ARCH baseline rows were measured on driver layout ${BASE_LAYOUT:-1}, this driver is layout $DRV_LAYOUT; every $ARCH row is printed, none judged, until cachegrind-gate.sh --write-baseline runs on $ARCH"
fi

# THE STATICS the layout check holds: gate/cg_statics.h is the scan of the driver's file-scope statics
# (gate/cg-statics.py), never a hand list; a committed list that differs from the scan is refused, and so is
# the list with one static planted out of it (the control), so a static added to the driver is checked
if ! python3 gate/cg-statics.py gate/cg_driver.c > "$WORK/cg_statics.scan" 2>"$WORK/cg_statics.err"; then
    echo "GATE FAIL: the driver's statics cannot be scanned: $(head -1 "$WORK/cg_statics.err")"
    fail=1
elif ! cmp -s "$WORK/cg_statics.scan" gate/cg_statics.h; then
    echo "GATE FAIL: gate/cg_statics.h is not the scan of gate/cg_driver.c's statics; regenerate it:"
    diff gate/cg_statics.h "$WORK/cg_statics.scan" | sed 's/^/  /' | sed -n '1,10p'
    fail=1
else
    sed '/CG_STATIC(lv_route)/d' gate/cg_statics.h > "$WORK/cg_statics.omit"
    if cmp -s "$WORK/cg_statics.scan" "$WORK/cg_statics.omit"; then
        echo "GATE FAIL: a list with lv_route planted out of it compares equal to the scan"
        fail=1
    else
        echo "ok   gate/cg_statics.h is the scan of the driver's $(grep -c '^CG_STATIC' gate/cg_statics.h) file-scope statics, and a list missing lv_route is not"
    fi
fi

declare -A GOT=()
DRNEW=()        # data-refs rows this run writes, with --write-baseline
CFNEW=()        # the conflict row's minima this run writes, with --write-baseline
declare -A REQ=()
declare -A RES=()
for cc in "${COMPILERS[@]}"; do
    "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_$cc" \
        "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c
    ver=$("$cc" --version | sed -n 1p)
    echo
    echo "---- $cc ($ver) ----"
    # THE LAYOUT, checked before anything is measured: every static the measured loops read starts a page,
    # or no D1 count of this build is the code's (it would be the link's); and a planted misalignment is
    # refused, so the check is shown to see one
    if ! "$WORK/cg_$cc" "$DATA" align > "$WORK/align.$cc.out" 2>&1; then
        sed 's/^/  /' "$WORK/align.$cc.out"
        echo "GATE FAIL: NOT PROVEN on $cc: the driver's layout moves the D1 sets (above); nothing of $cc is measured"
        fail=1
        continue
    fi
    sed 's/^/  /' "$WORK/align.$cc.out"
    # C5+'s layout figures from this compiler's production build (the layout rule: shard bases and the scratch
    # 64-byte aligned, strides a multiple of 64): the scratch 1,024 bytes on a
    # 64-byte boundary with the views first, the record 576 bytes with its provenance fields in place
    if [ -n "${EVAL_DEF[*]}" ]; then
        st=0
        "$WORK/cg_$cc" "$DATA" mlayout >"$WORK/mlayout.$cc.out" 2>&1 || st=$?
        if [ "$st" = 0 ] && grep -q '^ok   C5+ layout' "$WORK/mlayout.$cc.out"; then
            grep '^layout:\|^ok   C5+ layout' "$WORK/mlayout.$cc.out" | sed 's/^layout:/  layout ('"$cc"'):/'
        else
            echo "GATE FAIL: C5+ layout on $cc (exit $st): $(grep -m1 'C5+ FAIL\|^layout' "$WORK/mlayout.$cc.out" | cut -c1-140)"
            fail=1
        fi
    fi
    if "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" -DWE_CG_PLANT_MISALIGN -I"$HERE" -I"$HERE/gate" \
           -o "$WORK/cg_${cc}_misalign" "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c 2>"$WORK/misalign.$cc.err"; then
        if "$WORK/cg_${cc}_misalign" "$DATA" align > "$WORK/misalign.$cc.out" 2>&1 \
           || ! grep -q 'NOT PROVEN: the driver.s ew (the control' "$WORK/misalign.$cc.out"; then
            echo "GATE FAIL: the layout check passed a planted misalignment (WE_CG_PLANT_MISALIGN) on $cc"
            fail=1
        else
            echo "ok   the layout check refuses a planted misalignment ($cc): $(head -1 "$WORK/misalign.$cc.out" | cut -c1-90)"
        fi
    else
        echo "GATE FAIL: the planted-misalignment control does not build on $cc: $(head -1 "$WORK/misalign.$cc.err")"
        fail=1
    fi
    # THE LINK ORDER, checked before anything is measured. The core's read-only and data tables sit where
    # the link puts them, and a D1 row moves with their page offsets (measured on aarch64: about six misses a
    # request between two placements), so the driver is linked LAST and nothing of its own can move them.
    # The control holds that by the placement itself, the same on every architecture, with 1,000 read-only
    # bytes in an object of their own (gate/cg_plant.c): linked after the driver they leave the page offset
    # of every data object the core and the evaluator define unchanged, and linked before the core they move
    # at least one (the arm that shows the comparison can see a move; a plant inside the driver could not,
    # because the driver's page-aligned statics re-align whatever follows them). Then, with the plant after
    # the driver, a row's instructions and D1 are measured equal with and without it.
    if [ -z "$EVAL_DARK" ]; then
        lo_slot=evaluator-basis-BOOL-F
        lo_ok=1
        for lo_name in rodata rodata_first; do
            lo_src=("${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c gate/cg_plant.c)
            [ "$lo_name" = rodata_first ] && lo_src=(gate/cg_plant.c "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c)
            if ! "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" -I"$HERE" -I"$HERE/gate" \
                   -o "$WORK/cg_${cc}_$lo_name" "${lo_src[@]}" 2>"$WORK/linkorder.$cc.err"; then
                echo "GATE FAIL: the link-order control ($lo_name) does not build on $cc: $(head -1 "$WORK/linkorder.$cc.err")"
                fail=1
                lo_ok=0
            fi
        done
        # the core's and the evaluator's data objects, by name, from their own objects
        : > "$WORK/core-objects.$cc"
        for f in "${CORE_SRC[@]}" "${EVAL_SRC[@]}"; do
            "$cc" -std=gnu11 -O2 "${EVAL_DEF[@]}" -I"$HERE" -c "$f" -o "$WORK/lo.$cc.o" 2>/dev/null \
                && nm --defined-only -P "$WORK/lo.$cc.o" | awk '$2 ~ /^[rRdDbBV]$/ {print $1}' >> "$WORK/core-objects.$cc"
        done
        lo_offsets() { # binary -> "<name> <page offset>" for every core data object, sorted
            # the page offset is the address's last three hex digits, read by hand: strtonum is gawk's alone,
            # and mawk (Debian's and Ubuntu's default awk) has none
            nm --defined-only -P "$1" | awk -v list="$WORK/core-objects.$cc" '
                function pageoff(h,   i, v) { h = tolower(substr(h, length(h) > 3 ? length(h) - 2 : 1)); v = 0
                    for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1
                    return v }
                BEGIN { while ((getline n < list) > 0) want[n] = 1 }
                ($1 in want) && $2 ~ /^[rRdDbBV]$/ { printf "%s %d\n", $1, pageoff($3) }' | sort
        }
        if [ "$lo_ok" = 1 ] && [ -s "$WORK/core-objects.$cc" ]; then
            lo_offsets "$WORK/cg_$cc" > "$WORK/lo.last.$cc"
            lo_offsets "$WORK/cg_${cc}_rodata" > "$WORK/lo.last-plant.$cc"
            lo_offsets "$WORK/cg_${cc}_rodata_first" > "$WORK/lo.first-plant.$cc"
            lo_n=$(wc -l < "$WORK/lo.last.$cc")
            lo_moved_first=$(diff "$WORK/lo.last.$cc" "$WORK/lo.first-plant.$cc" | grep -c '^>' || true)
            if [ "$lo_n" -eq 0 ]; then
                echo "NOT PROVEN: the link-order control found none of the core's data objects in the $cc build"
                LINK_BLIND=1; LINK_BLIND_WHY="the link-order control ($cc)"
            elif ! cmp -s "$WORK/lo.last.$cc" "$WORK/lo.last-plant.$cc"; then
                echo "GATE FAIL: with the driver linked last its planted bytes moved a core object ($cc): $(diff "$WORK/lo.last.$cc" "$WORK/lo.last-plant.$cc" | grep -m1 '^>')"
                fail=1
            elif [ "$lo_moved_first" -eq 0 ]; then
                echo "NOT PROVEN: the link-order control is blind on $cc: linked before the core, the planted bytes moved none of its $lo_n data objects"
                LINK_BLIND=1; LINK_BLIND_WHY="the link-order control ($cc)"
            else
                read -r li ld _ _ <<<"$(measure_hw "cg_$cc" "$lo_slot" e 2000)"
                read -r pi pd _ _ <<<"$(measure_hw "cg_${cc}_rodata" "$lo_slot" e 2000)"
                if [ "$li" = ERROR ] || [ "$pi" = ERROR ] || [ "$li" != "$pi" ] || [ "$ld" != "$pd" ]; then
                    echo "GATE FAIL: with the driver linked last its own read-only bytes still move the code's counts ($cc): $lo_slot $li/$ld against $pi/$pd"
                    fail=1
                else
                    echo "ok   the driver links last ($cc): a 1,000-byte plant after it leaves all $lo_n core data objects at their page offsets and $lo_slot at $li instructions, $ld misses on the 8-way D1; before the core the same plant moves $lo_moved_first of them"
                fi
            fi
        fi
    fi
    # THE PLACEMENTS the two layout rows below measure: the production driver, and the same driver with the
    # gate's plant of 1,000, 2,000 or 3,500 bytes linked before the core; and the conflict row's control builds
    # at each placement. Built once, here, for both rows, and measured once: every run the two rows read is
    # made up front, CG_JOBS at a time, into a cache the rows then read, so the conflict row never re-measures
    # what the layout row has measured (a cachegrind count does not depend on what else the host runs).
    cf_ok=0
    if [ -z "$EVAL_DARK" ] && [ "${lo_ok:-0}" = 1 ]; then
        cf_build() { # cf_build NAME PLANT_BYTES [DEFINES...] -> cg_${cc}_NAME, the plant linked before the core unless 0
            local name=$1 pb=$2
            shift 2
            local -a src=("${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c) def=("$@")
            if [ "$pb" != 0 ]; then src=(gate/cg_plant.c "${src[@]}"); def+=("-DWE_CG_PLANT_BYTES=$pb"); fi
            "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" "${def[@]}" -I"$HERE" -I"$HERE/gate" \
                -o "$WORK/cg_${cc}_$name" "${src[@]}" 2>"$WORK/cf.$cc.$name.err"
        }
        cf_ok=1
        for cf_v in prod: c4096:-DWE_CG_PLANT_CONFLICT=4096 c0:-DWE_CG_PLANT_CONFLICT=0; do
            for pb in 0 1000 2000 3500; do
                if ! cf_build "${cf_v%%:*}_$pb" "$pb" ${cf_v#*:}; then
                    echo "GATE FAIL: the conflict row's ${cf_v%%:*} build at a $pb-byte plant does not build on $cc: $(head -1 "$WORK/cf.$cc.${cf_v%%:*}_$pb.err")"
                    fail=1; cf_ok=0
                fi
            done
        done
    fi
    if [ "$cf_ok" = 1 ]; then
        cf_runs=()
        for pb in 0 1000 2000 3500; do
            for d1_slot in "$lo_slot" "${CF_SLOTS[@]}"; do
                cf_runs+=("fa:cg_${cc}_prod_$pb:$d1_slot" "hw:cg_${cc}_prod_$pb:$d1_slot")
            done
            for d1_slot in "${CF_SLOTS[@]}"; do
                cf_runs+=("hw:cg_${cc}_c4096_$pb:$d1_slot" "hw:cg_${cc}_c0_$pb:$d1_slot")
            done
        done
        cg_prefetch "${cf_runs[@]}"
    fi
    # THE D1 ROWS FOLLOW THE CODE, NOT THE LINK: every module row and the link-order row measured on the
    # production build and at each of the three plant placements, which move the page offsets of the core's
    # data and of everything linked after it, the driver's strings among them. On the rows' D1 every
    # placement agrees within 1% (a line straddled or not is the only residue), and the instructions are
    # equal; on the 8-way geometry some placement must move some row by more than 1%, or the plants moved
    # nothing and the row is blind (one plant alone was, on x86_64 clang: run 38697985954)
    if [ "$cf_ok" = 1 ]; then
        d1_moved=0 d1_bad=0 d1_n=0
        for d1_slot in "$lo_slot" "${CF_SLOTS[@]}"; do
            cg_cached fa "cg_${cc}_prod_0" "$d1_slot"; read -r ai ad _ _ <<<"$CG_LINE"
            cg_cached hw "cg_${cc}_prod_0" "$d1_slot"; read -r hi ah _ _ <<<"$CG_LINE"
            if [ "$ai" = ERROR ] || [ "$hi" = ERROR ]; then
                echo "GATE FAIL: the layout row could not measure $d1_slot ($cc)"
                fail=1
                continue
            fi
            d1_n=$((d1_n + 1))
            d1_slot_moved=0
            for pb in 1000 2000 3500; do
                cg_cached fa "cg_${cc}_prod_$pb" "$d1_slot"; read -r bi bd _ _ <<<"$CG_LINE"
                cg_cached hw "cg_${cc}_prod_$pb" "$d1_slot"; read -r hi bh _ _ <<<"$CG_LINE"
                if [ "$bi" = ERROR ] || [ "$hi" = ERROR ]; then
                    echo "GATE FAIL: the layout row could not measure $d1_slot at a $pb-byte plant ($cc)"
                    fail=1
                    continue
                fi
                # a move is what the row's own test would call one: more than 1% of the row
                awk -v a="$ah" -v b="$bh" 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d > a / 100) }' && d1_slot_moved=1
                if [ "$ai" != "$bi" ] || awk -v a="$ad" -v b="$bd" 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d > a / 100) }'; then
                    echo "GATE FAIL: the D1 row follows the link ($cc): $d1_slot reads $ad misses a request, and $bd with an unrelated $pb-byte plant linked before the core (instructions $ai and $bi)"
                    d1_bad=1
                    fail=1
                fi
            done
            d1_moved=$((d1_moved + d1_slot_moved))
        done
        if [ "$d1_bad" = 0 ] && [ "$d1_moved" = 0 ]; then
            echo "NOT PROVEN: the layout row is blind on $cc: no plant moved any row's 8-way D1 by more than 1%, so nothing was shown to be held"
            LINK_BLIND=1; LINK_BLIND_WHY="the D1 layout row ($cc)"
        elif [ "$d1_bad" = 0 ]; then
            echo "ok   the D1 rows follow the code ($cc): $d1_n rows within 1% and at equal instructions under unrelated plants of 1,000, 2,000 and 3,500 bytes linked before the core, which move $d1_moved of them by more than 1% on the 8-way geometry"
        fi
    fi
    # THE 8-WAY CONFLICT ROW, gated. The rows' D1 above is fully associative, so it cannot see two hot
    # objects landing in one set: a conflict regression, which on a real 8-way cache evicts a line every
    # request. Planes are mapped page-aligned, so a stride of a page between hot lines is not hypothetical.
    # Each module row is measured on the hardware's 8-way D1 at four placements (the gate's plant of 0,
    # 1,000, 2,000 and 3,500 bytes linked before the core), and two figures are held to the committed ones:
    # - the MINIMUM over the four. The plants move objects by amounts that are not a page, so they leave
    #   every page-aligned object in its set: a conflict among page-aligned objects (the planes, the
    #   driver's arrays, set 0 where each of them starts) is the same at every placement and link jitter
    #   only lifts the others, so the minimum is that conflict's floor. It is NOT a floor for an object the
    #   link places: a hot static colliding at the production link can leave its set at some plant, and the
    #   minimum would read the cured placement. So, also:
    # - placement 0, the production link itself, with its own bound.
    # The bound is FLAT, the committed figure plus exactly three misses a request. A bound that grows with
    # the figure is weakest where the floor is already high: 2b+1 let twelve lines thrashing one set pass on
    # four of eight rows on gcc aarch64 (module-export at 39.093 against 53.030), and b + b/5 was fitted to
    # the tightest row of the day, let an 8.24-miss regression on module-export-all at the production link
    # read green, and goes blind once a figure nears 65. The figures repeat to 0.000 run to run (the runner
    # against this box, a write against a push, all 16 x86_64 rows), so three is far above the noise, and
    # the control's smallest step, 13.08 misses on gcc module-export-all at the production link, clears it
    # by 10.08 whatever the figure grows to. The cure mirrors the bound: a figure more than three under its
    # committed one fails as a conflict cured, so --write-baseline records the new floor and the same
    # conflict coming back is never read green, on a high-floor row as on a low one.
    # The control is two builds making 12 loads a request at a 4,096-byte stride (twelve lines in one set)
    # and at a stride of 0 (one line the request already reads), measured on EVERY row against this run's own
    # figures at both the minimum and placement 0: the first must cross the bound everywhere and the second
    # nowhere, so the row refuses the conflict and not the loads, on the high-floor rows as on the low.
    if [ "$cf_ok" = 1 ]; then
        cf_min() { # cf_min PREFIX SLOT -> CF_M, the minimum 8-way D1 misses a request over PREFIX's four placements, and CF_P, placement 0's; ERROR if one could not be measured
            local pb i d
            CF_M="" CF_P=""
            for pb in 0 1000 2000 3500; do
                cg_cached hw "cg_${cc}_${1}_$pb" "$2"; read -r i d _ _ <<<"$CG_LINE"
                if [ "$i" = ERROR ]; then CF_M=ERROR CF_P=ERROR; return 0; fi
                [ "$pb" = 0 ] && CF_P=$d
                CF_M=$(awk -v a="${CF_M:-$d}" -v b="$d" 'BEGIN { print (b < a ? b : a) }')
            done
        }
        cf_n=0 cf_judged=0 cf_bad=0 cf_ctl_bad=0
        # THE ROW SET, by identity: CF_SLOTS names each row once, and this architecture's committed rows for
        # this compiler are exactly those rows, each once. A row that leaves CF_SLOTS with its figures still
        # committed is named, not dropped from the gate without a word (a row CF_SLOTS has and the file does
        # not is NOT PROVEN below, by name)
        cf_dups=$(printf '%s\n' "${CF_SLOTS[@]}" | sort | uniq -d | tr '\n' ' ')
        if [ -n "$cf_dups" ]; then
            echo "GATE FAIL: CF_SLOTS names ${cf_dups% } more than once; each module row is one row of the conflict row"
            fail=1; cf_bad=1
        fi
        if [ "$WRITE" != 1 ] && [ "$STALE" != 1 ]; then
            cf_have=$(awk -F'\t' -v a="$ARCH" -v c="$cc" '$1 == a && $2 == c { print $3 }' "$CONFLICT_BASE" 2>/dev/null || true)
            cf_twice=$(printf '%s\n' "$cf_have" | sed '/^$/d' | sort | uniq -d | tr '\n' ' ')
            cf_orphans=$(comm -13 <(printf '%s\n' "${CF_SLOTS[@]}" | sort -u) <(printf '%s\n' "$cf_have" | sed '/^$/d' | sort -u) | tr '\n' ' ')
            if [ -n "$cf_twice" ]; then
                echo "GATE FAIL: gate/conflict-baseline.tsv holds ${cf_twice% } more than once for $ARCH $cc"
                fail=1; cf_bad=1
            fi
            if [ -n "$cf_orphans" ]; then
                echo "GATE FAIL: gate/conflict-baseline.tsv commits figures for ${cf_orphans% } on $ARCH $cc, which CF_SLOTS does not name: a row removed from the conflict row is removed from the file too, by --write-baseline on each architecture"
                fail=1; cf_bad=1
            fi
        fi
        for cf_slot in "${CF_SLOTS[@]}"; do
            cf_n=$((cf_n + 1))
            cf_min prod "$cf_slot"; m=$CF_M p=$CF_P
            cf_min c4096 "$cf_slot"; am=$CF_M ap=$CF_P
            cf_min c0 "$cf_slot"; zm=$CF_M zp=$CF_P
            if [ "$m" = ERROR ] || [ "$am" = ERROR ] || [ "$zm" = ERROR ]; then
                echo "GATE FAIL: the conflict row could not measure $cf_slot or its control ($cc)"; fail=1; cf_bad=1; continue
            fi
            printf '  %-28s 8-way D1: best %7s (bound %7s)  conflict %7s  twin %7s | production link %7s (bound %7s)  conflict %7s  twin %7s\n' \
                "$cf_slot" "$m" "$(cf_bound "$m")" "$am" "$zm" "$p" "$(cf_bound "$p")" "$ap" "$zp"
            # the control, against this row's own figures in this run
            if ! cf_over "$am" "$m" || ! cf_over "$ap" "$p"; then
                echo "GATE FAIL: the conflict row is blind on $cf_slot ($cc): 12 hot lines at a 4,096-byte stride read $am misses a request at the best placement and $ap at the production link, inside the bounds of $(cf_bound "$m") and $(cf_bound "$p")"
                fail=1; cf_ctl_bad=1
            elif cf_over "$zm" "$m" || cf_over "$zp" "$p"; then
                echo "GATE FAIL: the conflict row refuses the extra loads, not the conflict, on $cf_slot ($cc): the same 12 loads of one line read $zm and $zp, against bounds of $(cf_bound "$m") and $(cf_bound "$p")"
                fail=1; cf_ctl_bad=1
            fi
            if [ "$WRITE" = 1 ]; then
                CFNEW+=("$ARCH	$cc	$cf_slot	$m	$p")
                continue
            fi
            b=$(awk -F'\t' -v a="$ARCH" -v c="$cc" -v s="$cf_slot" '$1 == a && $2 == c && $3 == s { print $4 }' "$CONFLICT_BASE" 2>/dev/null || true)
            bp=$(awk -F'\t' -v a="$ARCH" -v c="$cc" -v s="$cf_slot" '$1 == a && $2 == c && $3 == s { print $5 }' "$CONFLICT_BASE" 2>/dev/null || true)
            if [ -z "$b" ] || [ -z "$bp" ] || [ "$STALE" = 1 ]; then
                echo "NOT PROVEN: $cf_slot ($cc) reads $m misses a request at its best 8-way placement and $p at the production link; no $ARCH conflict baseline for both on this layout"
                CF_DARK=1
                continue
            fi
            cf_judged=$((cf_judged + 1))
            if cf_over "$m" "$b"; then
                echo "GATE FAIL: $cf_slot ($cc) has a conflict on the 8-way D1: $m misses a request at its best of four placements, against a committed $b (bound $(cf_bound "$b"))"
                fail=1; cf_bad=1
            elif cf_over "$p" "$bp"; then
                echo "GATE FAIL: $cf_slot ($cc) has a conflict at the production link on the 8-way D1: $p misses a request at placement 0, against a committed $bp (bound $(cf_bound "$bp")); the other placements cure it, so it is an object the link places"
                fail=1; cf_bad=1
            elif cf_cured "$m" "$b" || cf_cured "$p" "$bp"; then
                echo "GATE FAIL: $cf_slot ($cc) has cured a conflict on the 8-way D1: $m misses a request at its best placement and $p at the production link, against a committed $b and $bp; more than $CF_MARGIN under is a new floor, and cachegrind-gate.sh --write-baseline on $ARCH records it, or a return of the same conflict reads green"
                fail=1; cf_bad=1
            fi
        done
        if [ "$cf_ctl_bad" = 0 ] && [ "$cf_bad" = 0 ]; then
            if [ "$cf_judged" = "$cf_n" ]; then
                echo "ok   the 8-way conflict row ($cc): all $cf_n module rows within their bounds at the best of four placements and at the production link, and no more than $CF_MARGIN under their committed figures; on every row the control's 12 lines in one set cross both bounds and its 12 loads of one line cross neither"
            elif [ "$WRITE" = 1 ]; then
                echo "ok   the 8-way conflict row's control ($cc): on all $cf_n module rows the 12 lines in one set cross both bounds and the 12 loads of one line cross neither; the $cf_n rows' figures are this run's to write, none judged"
            else
                echo "ok   the 8-way conflict row's control ($cc): on all $cf_n module rows the 12 lines in one set cross both bounds and the 12 loads of one line cross neither; $cf_judged of $cf_n rows judged against a committed figure, the rest NOT PROVEN above"
            fi
        fi
    fi
    # every slot's answers are checked against a reference search before anything is measured
    for slot in "${SLOTS[@]}"; do
        if ! "$WORK/cg_$cc" "$DATA" cg "$slot" d 200000 >/dev/null 2>"$WORK/verify.$cc.$slot.err"; then
            echo "GATE FAIL: $slot built by $cc gives wrong answers, so it is not measured:"
            sed 's/^/        /' "$WORK/verify.$cc.$slot.err"
            fail=1
            continue
        fi
        read -r di dd dl _ <<<"$(measure "cg_$cc" "$slot" d "$COUNT")"
        read -r ui ud _ _ <<<"$(measure "cg_$cc" "$slot" u "$COUNT")"
        if [ "$di" = ERROR ] || [ "$ui" = ERROR ]; then
            echo "GATE FAIL: valgrind could not run $slot ($cc); see $WORK"
            fail=1
            continue
        fi
        GOT["$cc|$slot"]="$di $dd"
        printf '  %-28s dense: instructions %8s  D1 misses %6s  (LL %s, not gated) | uniform, not gated: %s / %s\n' \
            "$slot" "$di" "$dd" "$dl" "$ui" "$ud"
        [ "$WRITE" = 1 ] || check_band "$slot" "$cc" "$di" "$dd"
    done

    # the verify step's own negative control: a planted wrong answer must be refused before measuring
    if WE_CG_PLANT_WRONG=1 "$WORK/cg_$cc" "$DATA" cg lookup-hh@16 q 1000 >/dev/null 2>"$WORK/planted.$cc.err"; then
        echo "GATE FAIL: the verify pass ACCEPTED a planted wrong answer ($cc), so no lookup row here is checked"
        fail=1
    else
        echo "ok   the verify pass refuses a planted wrong answer ($cc): $(tail -1 "$WORK/planted.$cc.err")"
    fi
    # and the evaluator world's: request addresses inside the hold-harmless table must stop the driver,
    # or every evaluator row could measure the exemption and run no program instruction
    if WE_CG_PLANT_DOC_ADDR=1 "$WORK/cg_$cc" "$DATA" cg lookup-hh@16 q 1000 >/dev/null 2>"$WORK/planted-doc.$cc.err"; then
        echo "GATE FAIL: the driver ACCEPTED evaluator request addresses inside the hold-harmless table ($cc)"
        fail=1
    elif grep -q 'hold-harmless table' "$WORK/planted-doc.$cc.err"; then
        echo "ok   the driver refuses evaluator request addresses inside the hold-harmless table ($cc)"
    else
        echo "GATE FAIL: the documentation-address control failed for another reason ($cc): $(tail -1 "$WORK/planted-doc.$cc.err")"
        fail=1
    fi
    MEAS="$WORK/meas.$cc.tsv"
    printf '# slot\tmeasured\tvector\tsound\tprogram\n' > "$MEAS"
    for slot in "${QSLOTS[@]}"; do
        if ! "$WORK/cg_$cc" "$DATA" cg "$slot" q 200000 >/dev/null 2>"$WORK/verify.$cc.${slot//@/_}.err"; then
            echo "GATE FAIL: $slot built by $cc gives wrong answers, so it is not measured:"
            sed 's/^/        /' "$WORK/verify.$cc.${slot//@/_}.err"
            fail=1
            continue
        fi
        read -r di dd dl ir <<<"$(measure "cg_$cc" "$slot" q "$COUNT")"
        if [ "$di" = ERROR ]; then
            echo "GATE FAIL: valgrind could not run $slot ($cc); see $WORK"
            fail=1
            continue
        fi
        GOT["$cc|$slot"]="$di $dd"
        REQ["$slot"]=$COUNT
        printf '%s\t%s/%s\t-\t-\t-\n' "$slot" "$ir" "$COUNT" >> "$MEAS"
        printf '  %-28s %s lookups: instructions %8s  D1 misses %6s  (LL %s, not gated)\n' "$slot" "$COUNT" "$di" "$dd" "$dl"
        [ "$WRITE" = 1 ] || check_band "$slot" "$cc" "$di" "$dd"
    done

    # the evaluator's rows: the driver's own table names them, dark or live
    if ! "$WORK/cg_$cc" "$DATA" slots > "$WORK/slots.$cc.tsv" 2>"$WORK/slots.$cc.err"; then
        echo "GATE FAIL: the driver could not print its evaluator slot table ($cc):"
        sed 's/^/        /' "$WORK/slots.$cc.err"
        fail=1
        continue
    fi
    while IFS=$'\t' read -r slot req vector sound program; do
        case "$slot" in ''|\#*) continue ;; esac
        REQ["$slot"]=$req
        ev_rows=$((ev_rows + 1))
        if [ -n "$EVAL_DARK" ]; then
            st=0
            "$WORK/cg_$cc" "$DATA" cg "$slot" e 1 </dev/null >"$WORK/dark.out" 2>&1 || st=$?
            if [ "$st" = 3 ]; then
                echo "  DARK $slot ($cc): $EVAL_DARK"
                dark=$((dark + 1))
            else
                echo "GATE FAIL: the dark slot $slot answered $st, not EMPTY; nothing may be measured in its place"
                fail=1
            fi
            continue
        fi
        # verify before measuring: the reference interpreter's verdicts, committed beside the gate
        expect="$HERE/gate/expected/$slot.verdicts"
        if [ ! -f "$expect" ]; then
            # With the interpreter in the tree a missing file is a FAILURE: the slot would go unmeasured
            # and the run still end CLEAR. Without it, the slot is dark by name and the CLEAR line counts it.
            if [ -f policy_ref.py ]; then
                echo "GATE FAIL: $slot has no reference verdicts in gate/expected/, though policy_ref.py is here (make verdicts)"
                fail=1
            else
                echo "  DARK $slot ($cc): no reference verdicts in gate/expected/, and policy_ref.py is not in this tree"
                vdark=$((vdark + 1))
            fi
            continue
        fi
        n=$(grep -c . "$expect")
        if ! "$WORK/cg_$cc" "$DATA" verdicts "$slot" "$n" </dev/null > "$WORK/verdicts.$cc.$slot" 2>"$WORK/verdicts.$cc.$slot.err" \
           || ! diff -q "$expect" "$WORK/verdicts.$cc.$slot" >/dev/null; then
            echo "GATE FAIL: $slot built by $cc does not give the reference interpreter's $n verdicts, so it is not measured"
            diff "$expect" "$WORK/verdicts.$cc.$slot" 2>&1 | sed -n 1,6p | sed 's/^/        /'
            fail=1
            continue
        fi
        read -r di dd dl ir <<<"$(measure "cg_$cc" "$slot" e "$req")"
        if [ "$di" = ERROR ]; then
            echo "GATE FAIL: valgrind could not run $slot ($cc); see $WORK"
            fail=1
            continue
        fi
        GOT["$cc|$slot"]="$di $dd"
        # The model's figure is the DIFFERENCE between req and req/2 requests, so whatever the run pays
        # once (the loop's set-up, the first request's cold path) is not spread over the requests: the
        # cost model holds held-out rows to their predictions exactly, and a per-run constant divided by
        # the request count would read as a fraction of an instruction on every one of them.
        half=$((req / 2))
        ih=$(measure_ir "cg_$cc" "$slot" "$half")
        if [ "$ih" = ERROR ] || [ -z "$ih" ]; then
            echo "GATE FAIL: valgrind could not run $slot at $half requests ($cc); see $WORK"
            fail=1
            continue
        fi
        printf '%s\t%s/%s\t%s\t%s\t%s\n' "$slot" "$((ir - ih))" "$((req - half))" "$vector" "$sound" "$program" >> "$MEAS"
        printf '  %-34s %s requests: instructions %10s  D1 misses %8s  (LL %s, not gated)\n' "$slot" "$req" "$di" "$dd" "$dl"
        [ "$WRITE" = 1 ] || check_band "$slot" "$cc" "$di" "$dd"
    done < "$WORK/slots.$cc.tsv"

    if [ -z "$EVAL_DARK" ]; then
        # THE LAUNCH PROBE. One evaluator row under 34 launches that differ only in environment size and
        # argv length must give ONE figure, or every D1 row here measures the launch. Its control is the
        # driver on the launch stack (WE_CG_PLANT_UNALIGNED), which must give more than one: a probe that
        # cannot see the drift it exists for proves nothing.
        lp=$(launch_probe "cg_$cc")
        lpn=$(printf '%s\n' "$lp" | grep -c .)
        if grep -q ERROR <<<"$lp"; then
            echo "GATE FAIL: the launch probe could not run $PROBE_SLOT ($cc): $(printf '%s\n' "$lp" | grep ERROR | tr '\n' ' ')"
            fail=1
        elif [ "$lpn" != 1 ]; then
            echo "GATE FAIL: $PROBE_SLOT ($cc) gives $lpn different counts under 34 launches that differ only in environment and argv size: $(printf '%s\n' "$lp" | tr '\n' ';')"
            fail=1
        else
            echo "ok   the counts do not depend on the launch: $PROBE_SLOT ($cc) gives one figure (Ir D1 $lp) under 34 launches"
        fi
        pp=$(launch_probe "cg_$cc" WE_CG_PLANT_UNALIGNED=1)
        ppn=$(printf '%s\n' "$pp" | grep -c .)
        if grep -q ERROR <<<"$pp"; then
            echo "GATE FAIL: the launch probe's control could not run ($cc): $(printf '%s\n' "$pp" | grep ERROR | tr '\n' ' ')"
            fail=1
        elif [ "$ppn" -lt 2 ]; then
            echo "GATE FAIL: the launch probe is blind ($cc): on the launch stack (WE_CG_PLANT_UNALIGNED) $PROBE_SLOT still gives one figure, $pp"
            fail=1
        else
            echo "ok   the launch probe sees the drift on the launch stack (WE_CG_PLANT_UNALIGNED, $cc): $ppn figures, D1 misses $(printf '%s\n' "$pp" | awk -v n="$PROBE_REQ" '{ printf "%s%.3f", (NR > 1 ? " " : ""), $2 / n }') per request"
        fi
        # the basis, every derived constant against its committed value, soundness, the worst fixture
        wflag=()
        [ "$WRITE" = 1 ] && wflag=(--write)
        if ! python3 gate/cost-model.py gate "$MEAS" "$CONSTANTS" "$ARCH" "$cc" "$TOL_PCT" "${wflag[@]}" | tee "$WORK/model.$cc.out" | sed 's/^/  /'; then
            fail=1
        fi
        grep -q '^GATE FAIL' "$WORK/model.$cc.out" && fail=1
        if awk -F'\t' '!/^#/ && $1 ~ /^module-/ { f = 1 } END { exit !f }' "$WORK/slots.$cc.tsv"; then
            mod_controls "$cc"
        fi
        # C2: the memo-hit mutant must fall OUTSIDE the band on evaluator-memo, where 32 rules read one
        # plane on one address and the mutant refills on every one of them, or the band is blind to the
        # memo. evaluator-default is measured too and RECORDED, not judged: its four rules read three
        # planes once each, so the mutant adds a single refill and sits inside the band by construction.
        if "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" -DWE_CG_NOMEMO -I"$HERE" -I"$HERE/gate" \
               -o "$WORK/cg_${cc}_nomemo" "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c 2>"$WORK/nomemo.$cc.err"; then
            for c2slot in evaluator-memo evaluator-default; do
                read -r mi _ _ _ <<<"$(measure "cg_${cc}_nomemo" "$c2slot" e "${REQ[$c2slot]}")"
                # against the committed row; when this run is writing the baseline, against what it just measured
                row=$(awk -F'\t' -v a="$ARCH" -v c="$cc" -v s="$c2slot" '$1 == a && $2 == c && $3 == s { print $5 }' "$BASELINE" 2>/dev/null || true)
                [ "$WRITE" = 1 ] && row=${GOT["$cc|$c2slot"]%% *}
                if [ -z "$row" ]; then
                    echo "GATE FAIL: C2 cannot be judged ($cc): $c2slot has no baseline"
                    fail=1
                    continue
                fi
                ratio=$(awk -v x="$mi" -v b="$row" 'BEGIN { printf "%.3f", x / b }')
                inside=0
                awk -v x="$mi" -v b="$row" -v t="$TOL_PCT" 'BEGIN { exit !(x >= b * (1 - t / 100) && x <= b * (1 + t / 100)) }' && inside=1
                if [ "$c2slot" = evaluator-default ]; then
                    echo "note C2 on evaluator-default, recorded and not judged: the memo-hit mutant costs $mi against $row (x$ratio), $([ $inside = 1 ] && echo inside || echo outside) the +-$TOL_PCT% band ($cc); one refill in four rules"
                elif [ "$inside" = 1 ]; then
                    echo "GATE FAIL: C2: the memo-hit mutant costs $mi against $row (x$ratio) on $c2slot, INSIDE the +-$TOL_PCT% band ($cc)"
                    fail=1
                else
                    echo "ok   C2: the memo-hit mutant costs $mi against $row (x$ratio) on $c2slot, outside the +-$TOL_PCT% band ($cc)"
                fi
            done
        else
            echo "GATE FAIL: C2 cannot run: the WE_TEST_NO_MEMO_HIT build failed ($cc):"
            sed 's/^/        /' "$WORK/nomemo.$cc.err" | sed -n 1,6p
            fail=1
        fi
        # THE DATA-REFS ROW: data references per rule on the straight-line family, held EXACTLY to the
        # committed figure for this architecture and compiler (gate/dataref-baseline.tsv). Its control is
        # the evaluator's one-extra-load mutant where we_eval.h offers it (WE_TEST_EXTRA_LOAD), which must
        # move the figure by exactly one; until it does, the control is the comparison itself, which must
        # refuse a figure one reference per rule higher, and the line says which control ran.
        read -r dri drr <<<"$(per_rule "cg_$cc")"
        drrow=$(awk -F'\t' -v a="$ARCH" -v c="$cc" '$1 == a && $2 == c { print $3 "\t" $4 }' "$HERE/gate/dataref-baseline.tsv" 2>/dev/null || true)
        if [ "$WRITE" = 1 ]; then
            DRNEW+=("$ARCH	$cc	$drr	$dri")
            echo "  data refs per rule ($cc): $drr (instructions $dri), written"
        elif [ -z "$drrow" ]; then
            echo "GATE FAIL: no data-refs baseline for $ARCH $cc (measured: $drr data references, $dri instructions per rule)"
            fail=1
        else
            IFS=$'\t' read -r brefs bir <<<"$drrow"
            if [ "$drr" = "$brefs" ]; then
                echo "ok   data refs per rule ($cc): $drr, exactly the committed figure (instructions $dri, committed $bir)"
            else
                echo "GATE FAIL: data refs per rule ($cc) are $drr against the committed $brefs: a load was added or removed in every rule"
                fail=1
            fi
            if grep -q 'WE_TEST_EXTRA_LOAD' we_eval.h; then
                if "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror "${EVAL_DEF[@]}" -DWE_CG_EXTRALOAD -I"$HERE" -I"$HERE/gate" \
                       -o "$WORK/cg_${cc}_extraload" "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c 2>"$WORK/extraload.$cc.err"; then
                    read -r _ xr <<<"$(per_rule "cg_${cc}_extraload")"
                    if python3 -c 'import sys; from fractions import Fraction as F; sys.exit(0 if F(sys.argv[1]) - F(sys.argv[2]) == 1 else 1)' "$xr" "$drr"; then
                        echo "ok   the data-refs row sees the planted extra load: $xr per rule against $drr ($cc)"
                    else
                        echo "GATE FAIL: the extra-load mutant moved data refs per rule from $drr to $xr, not by exactly one ($cc)"
                        fail=1
                    fi
                else
                    echo "GATE FAIL: the extra-load mutant does not build ($cc):"; sed -n 's/^/        /;1,4p' "$WORK/extraload.$cc.err"
                    fail=1
                fi
            else
                if python3 -c 'import sys; from fractions import Fraction as F; sys.exit(0 if F(sys.argv[1]) + 1 == F(sys.argv[2]) else 1)' "$brefs" "$drr"; then
                    echo "GATE FAIL: the data-refs comparison accepts a figure one reference per rule off ($cc)"
                    fail=1
                else
                    echo "ok   the data-refs comparison refuses a figure one reference per rule higher ($cc; the evaluator offers no extra-load mutant yet, so this is the control)"
                fi
            fi
        fi
        # and the exception stays the driver's: a production unit with the mutant defined must not build
        if "$cc" -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_TEST_NO_MEMO_HIT -I"$HERE" -c -o "$WORK/guard.$cc.o" \
               hp_eval.c 2>"$WORK/guard.$cc.err"; then
            echo "GATE FAIL: hp_eval.c, a production unit, compiled with WE_TEST_NO_MEMO_HIT ($cc): the mutant guard is gone"
            fail=1
        elif grep -q 'WE_TEST_\*' "$WORK/guard.$cc.err"; then
            echo "ok   the memo mutant is refused outside the driver: hp_eval.c with WE_TEST_NO_MEMO_HIT stops at we_eval.h's guard ($cc)"
        else
            echo "GATE FAIL: hp_eval.c with WE_TEST_NO_MEMO_HIT failed, but not at the mutant guard ($cc):"
            sed 's/^/        /' "$WORK/guard.$cc.err" | sed -n 1,6p
            fail=1
        fi
    fi
done

# THE VANTAGE, before anything is written: the counts are simulated and do not move with load, but a
# baseline is only written from a run whose every control held, and from a host the run measured: a
# fixed control target (the launch probe's row, 2,000 requests, cache simulation on) timed three times,
# its counts required identical and its wall time within 1.5x of its fastest; otherwise NOT PROVEN and
# nothing is written. The host's load, CPU count and the time are recorded in the header.
if [ "$WRITE" = 1 ] && { [ "$fail" != 0 ] || [ "$LINK_BLIND" = 1 ]; }; then
    echo "NOT PROVEN: --write-baseline refused: a control above failed, so no row of this run is written"
    echo "CACHEGRIND GATE: FAILED"
    exit 1
fi
if [ "$WRITE" = 1 ]; then
    vt=() vc=()
    for _ in 1 2 3; do
        t0=$(date +%s%N)
        vc+=("$(measure "cg_${COMPILERS[0]}" "$PROBE_SLOT" e "$PROBE_REQ")")
        vt+=($(( ($(date +%s%N) - t0) / 1000000 )))
    done
    vmin=$(printf '%s\n' "${vt[@]}" | sort -n | sed -n 1p)
    vmax=$(printf '%s\n' "${vt[@]}" | sort -n | tail -1)
    VANTAGE="load $(cut -d' ' -f1-3 /proc/loadavg) on $(nproc) CPUs at $(date -u +%Y-%m-%dT%H:%MZ); control $PROBE_SLOT timed ${vt[*]} ms"
    vc_text=$(printf '%s\n' "${vc[@]}")
    if [ "$(printf '%s' "$vc_text" | sort -u | grep -c .)" != 1 ] || grep -q ERROR <<<"$vc_text"; then
        echo "NOT PROVEN: --write-baseline refused: the control target's counts differ across three runs: ${vc[*]}"
        exit 2
    fi
    if [ "$vmax" -gt $(( vmin * 3 / 2 )) ]; then
        echo "NOT PROVEN: --write-baseline refused: the host is noisy ($VANTAGE, spread over 1.5x); nothing is written"
        exit 2
    fi
    echo "ok   the vantage: $VANTAGE, counts identical"
fi

if [ "$WRITE" = 1 ]; then
    {
        echo "# cachegrind-baseline.tsv - instructions and D1 misses per lookup (or per request, for an evaluator"
        echo "# row), D1 32 KiB of 64-byte lines, fully associative. cachegrind-gate.sh gates each within +-$TOL_PCT% for its"
        echo "# architecture and compiler. Rows are rewritten per architecture by --write-baseline."
        awk '/^# (aarch64|x86_64) /' "$BASELINE" 2>/dev/null | grep -v "^# $ARCH " || true
        for cc in "${COMPILERS[@]}"; do
            echo "# $ARCH $cc: $("$cc" --version | sed -n 1p), $(valgrind --version), $(ldd --version 2>&1 | sed -n '1s/^ldd //p')"
        done
        awk '/^# layout (aarch64|x86_64): /' "$BASELINE" 2>/dev/null | grep -v "^# layout $ARCH: " || true
        echo "# layout $ARCH: $DRV_LAYOUT"
        awk '/^# vantage (aarch64|x86_64): /' "$BASELINE" 2>/dev/null | grep -v "^# vantage $ARCH: " || true
        echo "# vantage $ARCH: $VANTAGE"
        echo "# the C library is recorded, not compared: no libc code runs between the instrumentation marks"
        echo "# Since the driver measures on its own aligned stack, a D1 row is a different quantity from one"
        echo "# measured on the launch stack: rows written with the launch probe in the gate are the reference,"
        echo "# and an architecture's rows written before it are the old measurement until --write-baseline"
        echo "# rewrites them on that architecture."
        echo "# requests per run: the routing and shipped slots $COUNT per stream; lookup rows $COUNT; each evaluator"
        echo "# row the count the driver's slot table gives it (cg_driver <dir> slots)"
        echo "# arch	compiler	slot	stream	instructions	d1_misses"
        grep -v '^#' "$BASELINE" 2>/dev/null | awk -F'\t' -v a="$ARCH" '$1 != a' || true
        for cc in "${COMPILERS[@]}"; do
            for slot in "${SLOTS[@]}" "${QSLOTS[@]}" $(awk -F'\t' '!/^#/ { print $1 }' "$WORK/slots.$cc.tsv" 2>/dev/null); do
                [ -n "${GOT["$cc|$slot"]:-}" ] || continue
                read -r di dd <<<"${GOT["$cc|$slot"]}"
                stream=dense
                case "$slot" in lookup-*) stream=q ;; evaluator-*|module-*) stream="e${REQ[$slot]}" ;; esac
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ARCH" "$cc" "$slot" "$stream" "$di" "$dd"
            done
        done
    } > "$WORK/baseline.new"
    mv "$WORK/baseline.new" "$BASELINE"
    echo "wrote $BASELINE for $ARCH"
    if [ -z "$EVAL_DARK" ]; then
        {
            echo "# cost-constants.tsv - every constant gate/cost-model.py derives from the evaluator rows, per"
            echo "# architecture and compiler; cachegrind-gate.sh holds each within +-$TOL_PCT%."
            echo "# arch	compiler	name	value"
            grep -v '^#' "$CONSTANTS" 2>/dev/null | awk -F'\t' -v a="$ARCH" '$1 != a' || true
            for cc in "${COMPILERS[@]}"; do
                sed -n 's/^baseline\t//p' "$WORK/model.$cc.out"
            done
        } > "$WORK/constants.new"
        mv "$WORK/constants.new" "$CONSTANTS"
        echo "wrote $CONSTANTS for $ARCH"
        {
            echo "# dataref-baseline.tsv - data references (Dr + Dw) and instructions per rule on the straight-line"
            echo "# family evaluator-dr-64/-128, exact fractions; cachegrind-gate.sh holds the references EXACTLY."
            echo "# arch	compiler	refs_per_rule	instructions_per_rule"
            grep -v '^#' "$HERE/gate/dataref-baseline.tsv" 2>/dev/null | awk -F'\t' -v a="$ARCH" '$1 != a' || true
            printf '%s\n' "${DRNEW[@]}"
        } > "$WORK/dataref.new"
        mv "$WORK/dataref.new" "$HERE/gate/dataref-baseline.tsv"
        echo "wrote gate/dataref-baseline.tsv for $ARCH"
        if [ "${#CFNEW[@]}" -gt 0 ]; then
            {
                echo "# conflict-baseline.tsv - each module row's 8-way D1 misses a request at its best of four placements"
                echo "# and at placement 0, the production link (cachegrind-gate.sh's conflict row); each is refused above"
                echo "# itself plus exactly three misses a request, and more than three below itself."
                echo "# arch	compiler	slot	best_8way_misses	prod_8way_misses"
                grep -v '^#' "$CONFLICT_BASE" 2>/dev/null | awk -F'\t' -v a="$ARCH" '$1 != a' || true
                printf '%s\n' "${CFNEW[@]}"
            } > "$WORK/conflict.new"
            mv "$WORK/conflict.new" "$CONFLICT_BASE"
            echo "wrote gate/conflict-baseline.tsv for $ARCH"
        fi
    fi
fi

# ---- layer 2: residency ------------------------------------------------------------------------------
# What is asserted (FORMAT.md §7's cost model): a committed per-geometry baseline of index-region
# misses per lookup, +-10%, in gate/residency-baseline.tsv, published as indexMissesPerLookup with the
# geometry named; and exactly ZERO only for the radix routing index modelled against the LLC and for the
# evaluator's program blocks in the LLC run. "Zero against L2 wherever the index fits" was the first
# criterion and it cannot pass for a rank plane on any realistic L2 (the S-tree's leaves are read about
# once per 729 lookups and cold traffic evicts them), and a criterion that cannot pass is not a gate.
RES_BASELINE="$HERE/gate/residency-baseline.tsv"
GEO="${WE_RESIDENCY_GEOMETRY:-}"
if [ -z "$GEO" ]; then
    prod=$(awk -F'\t' '$1 == "production" { print $2 }' "$GEOMETRY")
    if [ -n "$prod" ] && [ "$prod" != "-" ]; then GEO=production; else GEO=reference; fi
fi
IFS=$'\t' read -r gname l2 l2w llc llcw line gdesc <<<"$(awk -F'\t' -v g="$GEO" '$1 == g' "$GEOMETRY")"
echo
RES_CFGS=(v4 v6 both reputation tor rpki-unreachable)
EV_RES=(evaluator-default evaluator-default@llc evaluator-worst@llc)
if [ -z "${gname:-}" ] || [ "$l2" = "-" ]; then
    echo "GATE FAIL: geometry '$GEO' is not in gate/geometry.tsv or is not filled in"
    fail=1
else
    [ "$GEO" = reference ] && echo "residency: the production geometry is not filled in yet, so this runs at 'reference'"
    echo "residency at '$gname': $gdesc"
    gcc -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_TRACE "${EVAL_DEF[@]}" -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_trace" \
        "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c
    for cfg in "${RES_CFGS[@]}"; do
        out=$("$WORK/cg_trace" "$DATA" residency "$cfg" "$l2" "$l2w" "$llc" "$llcw" "$line" "$COUNT" 2>"$WORK/res.$cfg.err") || {
            echo "GATE FAIL: the residency model could not run for $cfg:"
            sed 's/^/        /' "$WORK/res.$cfg.err" | sed -n 1,4p
            fail=1
            continue
        }
        printf '%s\n' "$out" | grep -v '^RESULT' | sed 's/^/  /'
        IFS=$'\t' read -r _ _ level misses lookups <<<"$(printf '%s\n' "$out" | grep '^RESULT')"
        RES["$cfg"]="$level $misses $lookups"
        rate=$(awk -v m="$misses" -v n="$lookups" 'BEGIN { printf "%.6f", m / n }')
        # the shape the manifest carries
        printf '  {"planes":"%s","indexMissesPerLookup":%s,"geometry":{"name":"%s","l2Bytes":%s,"l2Ways":%s,"llcBytes":%s,"llcWays":%s,"lineBytes":%s,"level":"%s"}}\n' \
            "$cfg" "$rate" "$gname" "$l2" "$l2w" "$llc" "$llcw" "$line" "$level"
        if [ "$cfg" = v4 ] && [ "$level" = LLC ]; then
            if [ "$misses" != 0 ]; then
                echo "GATE FAIL: residency v4: the radix index takes $misses misses against the LLC at '$gname'; it must take none"
                fail=1
            else
                echo "ok   residency v4: the radix index takes no miss against the LLC at '$gname' (asserted zero)"
            fi
            continue
        fi
        [ "$WRITE" = 1 ] && continue
        row=$(awk -F'\t' -v g="$gname" -v a="$l2" -v b="$l2w" -v c="$llc" -v d="$llcw" -v e="$line" -v p="$cfg" \
            '$1 == g && $2 == a && $3 == b && $4 == c && $5 == d && $6 == e && $7 == p { print $8 "\t" $9 "\t" $10 }' \
            "$RES_BASELINE" 2>/dev/null || true)
        if [ -z "$row" ]; then
            echo "GATE FAIL: no residency baseline for $cfg at '$gname' (measured $misses index misses in $lookups lookups, $level);"
            echo "        run cachegrind-gate.sh --write-baseline and commit gate/residency-baseline.tsv"
            fail=1
            continue
        fi
        IFS=$'\t' read -r blevel bmiss blook <<<"$row"
        verdict=$(awk -v m="$misses" -v n="$lookups" -v bm="$bmiss" -v bn="$blook" -v t="$TOL_PCT" -v l="$level" -v bl="$blevel" 'BEGIN {
            r = m / n; b = bm / bn;
            if (l != bl) { printf "modelled against the %s, the baseline against the %s", l, bl; exit }
            if (bm == 0) { if (m != 0) printf "%d index misses against a baseline of none", m; exit }
            if (r < b * (1 - t / 100) || r > b * (1 + t / 100)) printf "%.6f index misses per lookup against %.6f", r, b }')
        if [ -n "$verdict" ]; then
            echo "GATE FAIL: residency $cfg at '$gname' is outside +-$TOL_PCT% of its baseline: $verdict"
            fail=1
        else
            echo "ok   residency $cfg at '$gname' ($level): $rate index misses per lookup, within +-$TOL_PCT% of the baseline ($bmiss in $blook)"
        fi
    done

    # the evaluator beside the program: dark until it exists; live, the program takes no LLC miss and each
    # default plane's index misses stay within the band of its alone-row
    for cfg in "${EV_RES[@]}"; do
        ev_rows=$((ev_rows + 1))
        st=0
        out=$("$WORK/cg_trace" "$DATA" residency "$cfg" "$l2" "$l2w" "$llc" "$llcw" "$line" "${REQ[${cfg%@*}]:-200000}" 2>"$WORK/res.$cfg.err") || st=$?
        if [ -n "$EVAL_DARK" ]; then
            if [ "$st" = 3 ]; then
                echo "  DARK residency $cfg: $EVAL_DARK"
                dark=$((dark + 1))
            else
                echo "GATE FAIL: the dark residency row $cfg answered $st, not EMPTY"
                fail=1
            fi
            continue
        fi
        if [ "$st" != 0 ]; then
            echo "GATE FAIL: the residency model could not run for $cfg:"
            sed 's/^/        /' "$WORK/res.$cfg.err" | sed -n 1,4p
            fail=1
            continue
        fi
        printf '%s\n' "$out" | grep -v '^RESULT' | grep -v '^PLANE' | sed 's/^/  /'
        IFS=$'\t' read -r _ _ level _ requests progmiss <<<"$(printf '%s\n' "$out" | grep '^RESULT')"
        case "$cfg" in
            *@llc)
                if [ "$progmiss" != 0 ]; then
                    echo "GATE FAIL: residency $cfg: the program blocks take $progmiss misses against the LLC; they must take none"
                    fail=1
                else
                    echo "ok   residency $cfg: the program blocks take no miss against the LLC at '$gname' (asserted zero)"
                fi
                ;;
            evaluator-default)
                # Each default plane beside the program against its alone-row, per lookup of that plane.
                # THE BAND: the alone-row's rate, +-TOL_PCT%, and never tighter than RES_SLACK misses either
                # way. The slack is measured, not chosen: against the evaluator the model put ONE
                # extra miss on reputation in 20,000 requests at L2 beside the program (a program line
                # evicting an index line once), where the alone-row has none in 1,000,000; a +-10% band
                # around zero is no band, and twice the largest excess seen is. Every plane the slot looks
                # up must be compared: a PLANE line with no lookup term, or a plane never printed, fails.
                sound=$(awk -F'\t' '$1 == "evaluator-default" { print $4 }' "$WORK/slots.${COMPILERS[0]}.tsv")
                want=$(printf '%s\n' "$sound" | tr ' ' '\n' | grep -c '^lookup-[a-z-]*@q4=' || true)
                compared=0
                while IFS=$'\t' read -r _ plane pmiss; do
                    frac=$(printf '%s\n' "$sound" | tr ' ' '\n' | sed -n "s/^lookup-$plane@q4=//p")
                    if [ -z "$frac" ]; then
                        echo "GATE FAIL: residency $cfg prints the plane $plane, which the slot's terms never look up"
                        fail=1
                        continue
                    fi
                    compared=$((compared + 1))
                    read -r _ amiss alook <<<"${RES[$plane]:-- - -}"
                    verdict=$(awk -v m="$pmiss" -v r="$requests" -v f="$frac" -v am="$amiss" -v al="$alook" -v t="$TOL_PCT" -v sl="$RES_SLACK" 'BEGIN {
                        split(f, q, "/"); n = r * (q[2] ? q[1] / q[2] : q[1]);
                        if (al == "-" || al == 0) { print "no alone-row to compare with"; exit }
                        want = n * am / al; d = want * t / 100; if (d < sl) d = sl;
                        if (m < want - d || m > want + d)
                            printf "%d misses in %d lookups beside the program; the alone-row gives %.2f, +-%.2f", m, n, want, d }')
                    if [ -n "$verdict" ]; then
                        echo "GATE FAIL: residency $plane beside the program: $verdict"
                        fail=1
                    else
                        echo "ok   residency $plane beside the program ($level): $pmiss misses, inside the alone-row's band (+-$TOL_PCT%, at least $RES_SLACK misses)"
                    fi
                done < <(printf '%s\n' "$out" | grep '^PLANE')
                if [ "$compared" != "$want" ]; then
                    echo "GATE FAIL: residency $cfg compared $compared planes with their alone-rows; the slot looks up $want"
                    fail=1
                fi
                ;;
        esac
    done

    # C3 and C5, the whole bound per request (cg_driver `bound`): every line each request reads equals the
    # model's, line for line, on the slots that take no jump; on the two worst slots no jump is taken,
    # every instruction of both blocks runs and the fills are counted. Each with its planted control.
    for slot in evaluator-default evaluator-live evaluator-worst evaluator-worst-lines; do
        ev_rows=$((ev_rows + 1))
        n=64
        case "$slot" in evaluator-default|evaluator-live) n=2000 ;; esac
        st=0
        out=$("$WORK/cg_trace" "$DATA" bound "$slot" "$n" 2>"$WORK/bound.$slot.err") || st=$?
        if [ -n "$EVAL_DARK" ]; then
            if [ "$st" = 3 ]; then
                echo "  DARK C3/C5 $slot: $EVAL_DARK"
                dark=$((dark + 1))
            else
                echo "GATE FAIL: the dark bound row $slot answered $st, not EMPTY"
                fail=1
            fi
            continue
        fi
        printf '%s\n' "$out" | grep -v '^BOUND' | sed 's/^/  /'
        if [ "$st" != 0 ]; then
            echo "GATE FAIL: C3/C5 $slot: the lines read are not the model's, or the worst slot is not what it claims"
            fail=1
        fi
    done
    # C2's exact half: with the memo mutant the finds rise by exactly the model's count (fills)
    if [ -z "$EVAL_DARK" ]; then
        if gcc -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_TRACE "${EVAL_DEF[@]}" -DWE_CG_NOMEMO -I"$HERE" -I"$HERE/gate" \
               -o "$WORK/cg_trace_nomemo" "${CORE_SRC[@]}" "${EVAL_SRC[@]}" gate/cg_driver.c 2>"$WORK/trace_nomemo.err"; then
            for slot in evaluator-memo evaluator-default; do
                n=2000
                # each driver's status is read, not lost in a pipe: a driver that dies prints no FILLS line,
                # and that is a failure by name, never an empty comparison
                base="" want="" mut=""
                for drv in cg_trace cg_trace_nomemo; do
                    st=0
                    fo=$("$WORK/$drv" "$DATA" fills "$slot" "$n" 2>"$WORK/fills.$drv.err") || st=$?
                    fl=$(printf '%s\n' "$fo" | sed -n 's/^FILLS\t//p')
                    if [ "$st" != 0 ] || [ -z "$fl" ]; then
                        echo "GATE FAIL: C2 exact on $slot: $drv fills exited $st with no count: $(head -c 160 "$WORK/fills.$drv.err")"
                        fail=1
                        continue
                    fi
                    if [ "$drv" = cg_trace ]; then
                        IFS=$'\t' read -r _ _ base want <<<"$fl"
                    else
                        IFS=$'\t' read -r _ _ mut _ <<<"$fl"
                    fi
                done
                if [ -z "$base" ] || [ -z "$mut" ]; then continue; fi
                if [ $((mut - base)) = "$want" ] && [ "$want" -gt 0 ]; then
                    echo "ok   C2 exact on $slot: the memo mutant adds $((mut - base)) finds in $n requests, the model's $want"
                else
                    echo "GATE FAIL: C2 exact on $slot: the memo mutant added $((mut - base)) finds in $n requests; the model says $want"
                    fail=1
                fi
            done
        else
            echo "GATE FAIL: the traced memo-mutant driver does not build:"; sed -n 's/^/        /;1,4p' "$WORK/trace_nomemo.err"
            fail=1
        fi
    fi
    if [ -z "$EVAL_DARK" ]; then
        # every plant on every slot it applies to: C5 on all four, C3 on the two worst
        for ctl in C5:evaluator-default C5:evaluator-live C5:evaluator-worst C5:evaluator-worst-lines \
                   C3:evaluator-worst C3:evaluator-worst-lines; do
            row=${ctl%%:*}
            slot=${ctl#*:}
            st=0
            env "WE_CG_PLANT_$row=1" "$WORK/cg_trace" "$DATA" bound "$slot" 4 >"$WORK/plant.$row" 2>&1 || st=$?
            if [ "$st" != 0 ] && grep -q "^$row FAIL" "$WORK/plant.$row"; then
                echo "ok   $row refuses its planted defect on $slot: $(grep "^$row FAIL" "$WORK/plant.$row" | head -1 | cut -c1-120)"
            else
                echo "GATE FAIL: $row accepted its planted defect on $slot (exit $st), so it holds nothing"
                fail=1
            fi
        done
        # C6: the module's acquire loads, counted at we_current() in the traced build, equal
        # popcount((floor | context | tenant) & bound) on every request; a planted ninth read is refused
        for slot in module-default module-default-tenant module-views@1 module-views@3 module-views@8 module-count@64-ctx module-worst; do
            st=0
            "$WORK/cg_trace" "$DATA" views "$slot" 200 >"$WORK/views.$slot" 2>&1 || st=$?
            if [ "$st" = 0 ] && grep -q '^ok   C6' "$WORK/views.$slot"; then
                grep '^ok   C6' "$WORK/views.$slot"
            else
                echo "GATE FAIL: C6 on $slot (exit $st): $(grep -m1 'C6 FAIL' "$WORK/views.$slot" | cut -c1-120)"
                fail=1
            fi
        done
        st=0
        WE_CG_PLANT_NINTH=1 "$WORK/cg_trace" "$DATA" views module-default 200 >"$WORK/views.plant" 2>&1 || st=$?
        if [ "$st" != 0 ] && grep -q '^C6 FAIL' "$WORK/views.plant"; then
            echo "ok   C6 refuses a planted ninth read: $(grep -m1 '^C6 FAIL' "$WORK/views.plant" | cut -c1-100)"
        else
            echo "GATE FAIL: C6 accepted a planted ninth read (exit $st), so it holds nothing"
            fail=1
        fi
        # C5+, the module half (under the layout rule above): on every request the handle lines we_current() reads and
        # the shard lines we_mod_count() writes equal the model's (one handle line per referenced bound plane;
        # the counter lines the layout rule gives the indices the decision counts), the shard base and
        # stride whole lines, the scratch and the lazy-fill local 64-byte aligned, the eight view stores one
        # line; three planted layouts each refused by name
        for slot in module-default module-default-tenant module-views@3 module-views@8 module-count@64-ctx module-worst module-allow; do
            st=0
            "$WORK/cg_trace" "$DATA" mbound "$slot" 200 >"$WORK/mbound.$slot" 2>&1 || st=$?
            if [ "$st" = 0 ] && grep -q '^ok   C5+' "$WORK/mbound.$slot"; then
                grep '^ok   C5+' "$WORK/mbound.$slot"
            else
                echo "GATE FAIL: C5+ (module half) on $slot (exit $st): $(grep -m1 'C5+ FAIL' "$WORK/mbound.$slot" | cut -c1-140)"
                fail=1
            fi
        done
        for plant in STRIDE:'not 64-byte aligned\|not a multiple of 64' SCRATCH:'span 2 lines\|not 64-byte aligned' SPLIT:'counter lines written'; do
            name=${plant%%:*}; want=${plant#*:}
            st=0
            env "WE_CG_PLANT_$name=1" "$WORK/cg_trace" "$DATA" mbound module-default 50 >"$WORK/mbound.plant.$name" 2>&1 || st=$?
            if [ "$st" != 0 ] && grep -q "^C5+ FAIL.*\($want\)" "$WORK/mbound.plant.$name"; then
                echo "ok   C5+ refuses the planted layout WE_CG_PLANT_$name: $(grep -m1 '^C5+ FAIL' "$WORK/mbound.plant.$name" | cut -c1-110)"
            else
                echo "GATE FAIL: C5+ accepted the planted layout WE_CG_PLANT_$name (exit $st), so the module half holds nothing"
                fail=1
            fi
        done
    fi

    if [ "$WRITE" = 1 ]; then
        {
            echo "# residency-baseline.tsv - index-region misses per lookup from cachegrind-gate.sh's LRU residency"
            echo "# model, per geometry (the numbers are part of the key, so editing a geometry cannot reuse an old"
            echo "# row). v4, v6, both: the routing planes on the dense stream; reputation, tor, rpki-unreachable:"
            echo "# each default-policy plane ALONE on the default slot's q4 stream, the level stated. Gated within"
            echo "# +-$TOL_PCT% of misses / lookups (a baseline of zero must stay zero); the radix routing plane against"
            echo "# the LLC is asserted zero whatever this file says. Rows are rewritten per geometry by --write-baseline."
            echo "# geometry	l2_bytes	l2_ways	llc_bytes	llc_ways	line	planes	level	index_misses	lookups"
            grep -v '^#' "$RES_BASELINE" 2>/dev/null | awk -F'\t' -v g="$gname" '$1 != g' || true
            for cfg in "${RES_CFGS[@]}"; do
                [ -n "${RES[$cfg]:-}" ] || continue
                read -r level misses lookups <<<"${RES[$cfg]}"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$gname" "$l2" "$l2w" "$llc" "$llcw" "$line" "$cfg" "$level" "$misses" "$lookups"
            done
        } > "$WORK/residency.new"
        mv "$WORK/residency.new" "$RES_BASELINE"
        echo "wrote $RES_BASELINE for '$gname'"
    fi
fi

echo
if [ "$fail" != 0 ]; then
    echo "CACHEGRIND GATE: FAILED"
    exit 1
fi
# The DARK count is held to the rows met: with the evaluator absent EVERY evaluator row must have been
# reported dark (a row that went missing from the table, or one that ran, is a failure), and with it
# present none may be dark for that reason.
if [ -n "$EVAL_DARK" ] && [ "$dark" != "$ev_rows" ]; then
    echo "GATE FAIL: $dark evaluator rows reported DARK, but $ev_rows evaluator rows were met"
    echo "CACHEGRIND GATE: FAILED"
    exit 1
fi
if [ -z "$EVAL_DARK" ] && [ "$dark" != 0 ]; then
    echo "GATE FAIL: $dark evaluator rows reported DARK for the evaluator's absence, though we_eval.h is here"
    echo "CACHEGRIND GATE: FAILED"
    exit 1
fi
if [ "$LINK_BLIND" = 1 ]; then
    echo "CACHEGRIND GATE: NOT PROVEN on $ARCH: ${LINK_BLIND_WHY:-a layout row} was blind (above), so no D1 row is shown to be the code's rather than the link's"
    exit 2
fi
if [ "$CF_DARK" = 1 ] && [ "$STALE" != 1 ]; then
    echo "CACHEGRIND GATE: NOT PROVEN on $ARCH: the 8-way conflict row has no committed minimum for a module row (above); cachegrind-gate.sh --write-baseline on $ARCH writes gate/conflict-baseline.tsv"
    exit 2
fi
if [ "$STALE" = 1 ]; then
    echo "CACHEGRIND GATE: NOT PROVEN on $ARCH: the baseline rows are driver layout ${BASE_LAYOUT:-1}'s and this driver is layout $DRV_LAYOUT; every row was measured and printed above, none judged; cachegrind-gate.sh --write-baseline on $ARCH re-measures them"
    exit 2
fi
dark_note=""
[ "$dark" != 0 ] && dark_note="; all $dark of $ev_rows evaluator rows DARK ($EVAL_DARK), each driver answer asserted EMPTY"
[ "$vdark" != 0 ] && dark_note="$dark_note; $vdark of $ev_rows evaluator rows DARK for want of reference verdicts (make verdicts)"
echo "CACHEGRIND GATE: CLEAR on $ARCH (${COMPILERS[*]}): every slot within +-$TOL_PCT% of its baseline; index misses per lookup within +-$TOL_PCT% of the baseline at '$GEO', the radix index resident in the LLC$dark_note"
