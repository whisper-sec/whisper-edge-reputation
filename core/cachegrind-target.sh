#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# cachegrind-target.sh - `make cachegrind`: the cost rows, run, and refused unless every slot they rest on
# has a baseline on every architecture.
#
# cachegrind-gate.sh measures this host's architecture and fails a slot with no baseline as one `GATE
# FAIL` line among many. A merge needs more than that: CLEAR here means every evaluator slot the driver
# lists and every module slot the cost rows name has a committed baseline for BOTH compilers on BOTH
# architectures, and this architecture's run is within its bands. A slot missing anywhere is named with
# the architecture it is missing on, the run on this host is reported as it is, and the verdict is never
# CLEAR while one is missing: an architecture this host cannot run is NOT PROVEN by name, never assumed.
#
# Usage: cachegrind-target.sh <workdir>
set -uo pipefail

cd "$(dirname "$0")" || exit 2
WORK=${1:-.testtmp/cachegrind}
mkdir -p "$WORK"
BASELINE=gate/cachegrind-baseline.tsv
ARCH=$(uname -m)
case "$ARCH" in arm64) ARCH=aarch64 ;; amd64) ARCH=x86_64 ;; esac

# The 8-way conflict row's module rows, read from the gate itself so the two lists cannot drift apart: the
# array's text from "CF_SLOTS=(" to its closing parenthesis, on one line or on several, split into words.
# The set is then held by identity, below, against the committed rows and the driver's slot table.
cf_text=$(awk '/^CF_SLOTS=\(/ { on = 1 } on { printf "%s ", $0; if (index($0, ")")) exit }' cachegrind-gate.sh)
cf_text=${cf_text#*\(}
cf_text=${cf_text%%\)*}
read -r -a CF_SLOTS <<<"${cf_text//\\/ }"
if [ "${#CF_SLOTS[@]}" = 0 ]; then
    echo "CACHEGRIND TARGET: NOT CLEAR: cachegrind-gate.sh has no CF_SLOTS=( ... ) array to read, so the conflict row's rows cannot be checked"
    exit 1
fi
# The module slots the cost rows name (C1+, C2+, C7): each needs a baseline per architecture and compiler.
MODULE_SLOTS=(module-default module-default-tenant module-default-full module-default-prestage
              module-var-prerewrite module-var-prerewrite@1
              module-export module-export-all module-export-prestage
              module-worst
              evaluator-default-sv evaluator-default-tenant evaluator-default-full evaluator-default-prestage
              evaluator-views@1-sv evaluator-modworst)
for k in 1 2 3 4 5 6 7 8; do
    MODULE_SLOTS+=("evaluator-views@$k" "module-views@$k")
done
for p in floor ctx; do
    for n in 1 64 65 96 128 129 192 193 224 256; do
        MODULE_SLOTS+=("evaluator-count@$n-$p" "module-count@$n-$p")
    done
done

# a slot table left by an earlier run in this directory is never read as this run's: the gate writes each
# compiler's anew, and one it could not write is absent, named below, rather than stale
rm -f "$WORK"/slots.gcc.tsv "$WORK"/slots.clang.tsv
./cachegrind-gate.sh "$WORK" > "$WORK/gate.log" 2>&1
gate_rc=$?
cat "$WORK/gate.log"
echo
echo "cachegrind target: the slots the cost rows rest on, per architecture and compiler"

missing=0
set_bad=0   # the conflict row's row set is not CF_SLOTS: a defect of the tree, named, never a gap
# the evaluator slots the driver lists on this host, and the module slots the rows name
slots=()
for cc in gcc clang; do
    # every compiler's slot table, so a slot one compiler's driver lists and the other's does not is still named
    if [ -f "$WORK/slots.$cc.tsv" ] && ! grep -q '[^[:space:]]' "$WORK/slots.$cc.tsv"; then
        # the driver ran and printed nothing: the gate's own GATE FAIL names why (the driver could not
        # write its planes, most often an unwritable WE_BENCH_DATA); the CF_SLOTS rows are not compared
        # with an empty table, which would read as a renamed slot
        echo "NOT CLEAR: the $cc driver's slot table is empty: $(grep -m1 . "$WORK/slots.$cc.err" 2>/dev/null || echo 'no error was printed')"
        missing=$((missing + 1))
    elif [ -f "$WORK/slots.$cc.tsv" ]; then
        while IFS=$'\t' read -r slot _; do
            case "$slot" in ''|\#*) continue ;; esac
            slots+=("$slot")
        done < "$WORK/slots.$cc.tsv"
    else
        echo "NOT CLEAR: the $cc driver's slot table was not written by this run ($WORK/slots.$cc.tsv), so its slots cannot be enumerated"
        missing=$((missing + 1))
    fi
done
# the union, each slot once: the rows' own names are in every driver's table too, and a name counted
# twice once read "160 slot rows have no baseline" for 88 (44 slots on two compilers)
mapfile -t slots < <(printf '%s\n' "${slots[@]}" "${MODULE_SLOTS[@]}" | sort -u)
# the gate's CF_SLOTS: each row once, and each a slot the driver has (a misspelt row would be measured as
# an error, and the committed one it was meant to be would be left unjudged)
for cf_slot in $(printf '%s\n' "${CF_SLOTS[@]}" | sort | uniq -d); do
    echo "NOT CLEAR: the gate's CF_SLOTS names $cf_slot more than once"
    set_bad=$((set_bad + 1))
done
for cf_slot in "${CF_SLOTS[@]}"; do
    for cc in gcc clang; do
        if [ -f "$WORK/slots.$cc.tsv" ] && grep -q '[^[:space:]]' "$WORK/slots.$cc.tsv" \
                && ! awk -F'\t' -v s="$cf_slot" '$1 == s { f = 1 } END { exit !f }' "$WORK/slots.$cc.tsv"; then
            echo "NOT CLEAR: the gate's CF_SLOTS names $cf_slot, which the $cc driver's slot table does not list"
            set_bad=$((set_bad + 1))
        fi
    done
done
# a row is only a baseline on the driver layout it was measured on: an architecture whose stamp is not this
# driver's WE_CG_LAYOUT has rows of another measurement, and is NOT PROVEN by name, never counted as covered
drv_layout=$(sed -n 's/^#define WE_CG_LAYOUT \([0-9]*\)$/\1/p' gate/cg_driver.c | sed -n 1p)
stale_layout=0
for arch in aarch64 x86_64; do
    stamp=$(sed -n "s/^# layout $arch: \([0-9]*\)\$/\1/p" "$BASELINE" | sed -n 1p)
    if [ "${stamp:-1}" != "$drv_layout" ]; then
        echo "NOT PROVEN: the $arch rows are driver layout ${stamp:-1}'s and this driver is layout $drv_layout; cachegrind-gate.sh --write-baseline on $arch rewrites them"
        stale_layout=$((stale_layout + 1))
    fi
    # and the 8-way conflict row's two figures (the best placement's and the production link's): the rows
    # committed for each compiler are EXACTLY the gate's CF_SLOTS, each once. A CF_SLOTS row with no
    # figures is a gap (NOT PROVEN, rewritten by --write-baseline on that architecture); a committed row
    # CF_SLOTS does not name, or a row committed twice, is a defect and is named
    for cc in gcc clang; do
        have=$(awk -F'\t' -v a="$arch" -v c="$cc" '$1 == a && $2 == c { print $3 }' gate/conflict-baseline.tsv 2>/dev/null)
        for cf_slot in $(printf '%s\n' "$have" | sed '/^$/d' | sort | uniq -d); do
            echo "NOT CLEAR: gate/conflict-baseline.tsv holds $cf_slot more than once on $arch ($cc)"
            set_bad=$((set_bad + 1))
        done
        for cf_slot in $(comm -13 <(printf '%s\n' "${CF_SLOTS[@]}" | sort -u) <(printf '%s\n' "$have" | sed '/^$/d' | sort -u)); do
            echo "NOT CLEAR: gate/conflict-baseline.tsv commits $cf_slot on $arch ($cc), which the gate's CF_SLOTS does not name: removed from the gate, or misspelled there"
            set_bad=$((set_bad + 1))
        done
        for cf_slot in "${CF_SLOTS[@]}"; do
            if ! awk -F'\t' -v a="$arch" -v c="$cc" -v s="$cf_slot" '$1 == a && $2 == c && $3 == s && $4 != "" && $5 != "" { f = 1 } END { exit !f }' \
                    gate/conflict-baseline.tsv 2>/dev/null; then
                echo "NOT PROVEN: $cf_slot has no 8-way conflict minimum and production-link figure on $arch ($cc) in gate/conflict-baseline.tsv"
                stale_layout=$((stale_layout + 1))
            fi
        done
    done
done
for arch in aarch64 x86_64; do
    for cc in gcc clang; do
        n=0
        for slot in "${slots[@]}"; do
            if ! awk -F'\t' -v a="$arch" -v c="$cc" -v s="$slot" '$1 == a && $2 == c && $3 == s { f = 1 } END { exit !f }' "$BASELINE"; then
                if [ "$arch" = "$ARCH" ]; then
                    echo "NOT CLEAR: slot $slot has no baseline on $arch ($cc)"
                else
                    echo "NOT PROVEN: slot $slot has no baseline on $arch ($cc), and this $ARCH host cannot measure it"
                fi
                n=$((n + 1))
            fi
        done
        echo "  $arch $cc: ${#slots[@]} slots, $n without a baseline"
        missing=$((missing + n))
    done
done
# a gate that did not reach its verdict line crashed, and reads FAILED: no gap or NOT PROVEN below may
# stand for a run that never judged anything
if ! grep -q '^CACHEGRIND GATE: ' "$WORK/gate.log"; then
    echo "CACHEGRIND TARGET: FAILED: cachegrind-gate.sh on $ARCH ended without a CACHEGRIND GATE: verdict (exit $gate_rc; its last line: $(tail -n 1 "$WORK/gate.log" | cut -c1-160))"
    exit 1
fi
# a gate that FAILED reads FAIL, whatever else is missing: a row out of band or a blind control is not
# hidden behind a baseline gap, which every layout bump opens on the architecture not yet rewritten
if grep -q '^CACHEGRIND GATE: FAILED' "$WORK/gate.log" || [ "$gate_rc" = 1 ]; then
    echo "CACHEGRIND TARGET: FAILED: cachegrind-gate.sh on $ARCH FAILED (exit $gate_rc; the GATE FAIL lines above)$([ "$stale_layout" != 0 ] && echo ", and $stale_layout baseline gap(s) above besides")"
    exit 1
fi
if [ "$set_bad" != 0 ]; then
    echo "CACHEGRIND TARGET: NOT CLEAR: the conflict row's rows are not the gate's CF_SLOTS, $set_bad named above$([ "$stale_layout" != 0 ] && echo ", and $stale_layout baseline gap(s) besides")"
    exit 1
fi
if [ "$stale_layout" != 0 ]; then
    echo "CACHEGRIND TARGET: NOT PROVEN: $stale_layout baseline gap(s) above: rows of another driver layout, or a module row without both of its conflict figures"
    exit 2
fi
if grep -q '^CACHEGRIND GATE: NOT PROVEN' "$WORK/gate.log"; then
    echo "CACHEGRIND TARGET: NOT PROVEN: $(grep -m1 '^CACHEGRIND GATE: NOT PROVEN' "$WORK/gate.log" | sed 's/^CACHEGRIND GATE: NOT PROVEN //')"
    exit 2
fi
if [ "$gate_rc" != 0 ] || ! grep -q '^CACHEGRIND GATE: CLEAR' "$WORK/gate.log"; then
    echo "CACHEGRIND TARGET: NOT CLEAR: cachegrind-gate.sh on $ARCH did not report CLEAR (exit $gate_rc)"
    exit 1
fi
if [ "$missing" != 0 ]; then
    echo "CACHEGRIND TARGET: NOT CLEAR: $missing slot rows have no baseline (named above)"
    exit 1
fi
echo "CACHEGRIND TARGET: CLEAR: the $ARCH run is within its bands and every slot has a baseline on both architectures"
