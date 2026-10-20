#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# policy-mutants.sh - the negative controls for test_policy, every run.
#
# Each mutant is a -D build of test_policy that plants one known defect in the compiler, the verifier,
# the evaluator or the classifier. It must FAIL, and it must fail on the row POLICY.md names for it:
# a mutant that fails some other row has shown nothing about the row that claims to catch it, and a
# mutant nothing catches is a row that has stopped seeing what it says it sees. A process that dies
# of a signal is never a catch: the two defects a fault exposes (a store into a write-protected plane,
# a search that reads past its payload into a guard page) are caught inside test_policy and reported
# on their rows, H3 and S2, like every other.
#
# Then the guard on the mutants themselves: a plain build of we_policy.c must refuse every one of them,
# and the cachegrind driver's build (WE_CG_DRIVER) must admit the memo mutant and refuse every other,
# so the exception is exactly as wide as it says; a module translation unit must refuse every one too;
# and the rows, the guard and the names the sources test must be one set.
#
# Prints one `N mutant checks, F failures` line for the README count, and exits non-zero if any
# mutant was not caught by its named row.
#
# Usage: policy-mutants.sh <workdir> <cc> <cflags...>
set -u

OUT=$1
shift
CC=$1
shift
CFLAGS=("$@")
SRC=(test_policy.c we_writer.c whisper_edge.c we_sha256.c we_counters.c we_policy.c)

# mutant : the row that must fail
MUTANTS=(
    "K3_WEAK:K2"
    "ALLOW_U_FALLTHROUGH:K4"
    "LOG_TERMINATES:F1"
    "POLARITY_NO_ALLOW:N4"
    "ISNOTUNK_POSITIVE:N4"
    "BOOL_NOT:K1"
    "SENTINEL_NE:P2"
    "SHORTCIRCUIT_U:K3"
    "NO_CLAMP:M4"
    "NO_MEMO_HIT:X1"
    "NO_SHORTCIRCUIT:X1"
    "NO_MEMO_RESET:M1"
    "CLASSIFY_ISUNK_U:D2"
    "NO_CAPTURES:D1"
    "CLASSIFY_SINGLE_EVAL:D2"
    "SENTINEL_PADDING:S2"
    "TENANT_ATOM_U:F4"
    "TENANT_BIT_IGNORED:F4"
    "SPLUS_NO_CLAMP:S2"
    "NO_EXHAUSTIVE:K7"
    "PLANTED_STORE:H3"
    "HH_FLOOR_ENDS_ALL:F6"
    "HH_SERVER_EXEMPT:F6"
    "HH_RAW_COMPARE:F6"
    "SERVER_UNSET_KEYED:F6"
)

mkdir -p "$OUT/mutants"
checks=0
failures=0
for row in "${MUTANTS[@]}"; do
    IFS=: read -r name want <<<"$row"
    bin="$OUT/mutants/test_policy_$name"
    log="$OUT/mutants/$name.out"
    checks=$((checks + 1))
    if ! "$CC" "${CFLAGS[@]}" -DWE_TRACE "-DWE_TEST_$name=1" -o "$bin" "${SRC[@]}" 2>"$log.build"; then
        echo "MUTANT FAIL: WE_TEST_$name does not build:"
        sed 's/^/    /' "$log.build" | sed -n 1,10p
        failures=$((failures + 1))
        continue
    fi
    "$bin" "$OUT/mutants/tmp-$name" >"$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "MUTANT FAIL: WE_TEST_$name was NOT caught: test_policy passed with the defect planted"
        failures=$((failures + 1))
        continue
    fi
    if [ "$rc" -gt 128 ]; then
        echo "MUTANT FAIL: WE_TEST_$name killed test_policy with signal $((rc - 128)) instead of failing row $want"
        failures=$((failures + 1))
        continue
    fi
    if grep -q "FAIL .*\[$want\]" "$log"; then
        n=$(grep -c "FAIL .*\[$want\]" "$log")
        echo "ok   mutant WE_TEST_$name caught by row $want ($n failing checks there)"
    else
        echo "MUTANT FAIL: WE_TEST_$name failed, but not on its named row $want:"
        grep FAIL "$log" | sed -n 1,5p | sed 's/^/    /'
        failures=$((failures + 1))
    fi
done

# the guard on the mutants: every one refused by a plain build of the compiler, and the cachegrind
# driver's exception (WE_CG_DRIVER) admits its two controls and no other. EXTRA_LOAD changes no
# verdict (one more load per rule), so no test_policy row can catch it: cachegrind-gate.sh's per-rule
# data-reference row is its catcher, and here it is held to the guard alone.
CG_ADMITS=" NO_MEMO_HIT EXTRA_LOAD "
for row in "${MUTANTS[@]}" "EXTRA_LOAD:cachegrind"; do
    IFS=: read -r name want <<<"$row"
    checks=$((checks + 1))
    if "$CC" "${CFLAGS[@]}" "-DWE_TEST_$name=1" -c -o "$OUT/mutants/guard.o" we_policy.c 2>/dev/null; then
        echo "MUTANT FAIL: a plain build of we_policy.c compiled with WE_TEST_$name defined; the guard is gone"
        failures=$((failures + 1))
    fi
    checks=$((checks + 1))
    if "$CC" "${CFLAGS[@]}" -DWE_CG_DRIVER "-DWE_TEST_$name=1" -c -o "$OUT/mutants/guard.o" we_policy.c 2>"$OUT/mutants/guard.err"; then
        if [[ "$CG_ADMITS" != *" $name "* ]]; then
            echo "MUTANT FAIL: the WE_CG_DRIVER exception admits WE_TEST_$name, wider than its two controls"
            failures=$((failures + 1))
        fi
    elif [[ "$CG_ADMITS" == *" $name "* ]]; then
        echo "MUTANT FAIL: the WE_CG_DRIVER build with WE_TEST_$name does not compile:"
        sed -n 1,5p "$OUT/mutants/guard.err" | sed 's/^/    /'
        failures=$((failures + 1))
    fi
done
echo "ok   every mutant is refused by a plain build; WE_CG_DRIVER admits WE_TEST_NO_MEMO_HIT and WE_TEST_EXTRA_LOAD alone"

# The same guard as every server module meets it: we_module.c includes we_module.h, which includes
# we_eval.h, which includes we_policy.h, so a module translation unit built without WE_TRACE refuses each
# mutant by that header's own #error, the one a stray -D on a shipped nginx, Apache or LiteSpeed build hits.
guard_msg="the WE_TEST_\* mutants exist only in test_policy's WE_TRACE build"
before=$failures
for row in "${MUTANTS[@]}" "EXTRA_LOAD:cachegrind"; do
    IFS=: read -r name want <<<"$row"
    checks=$((checks + 1))
    if "$CC" "${CFLAGS[@]}" "-DWE_TEST_$name=1" -c -o "$OUT/mutants/module-guard.o" we_module.c 2>"$OUT/mutants/module-guard.err"; then
        echo "MUTANT FAIL: a module translation unit (we_module.c) compiled with WE_TEST_$name defined and no WE_TRACE"
        failures=$((failures + 1))
    elif ! grep -q "$([ "$name" = EXTRA_LOAD ] && echo "WE_TEST_EXTRA_LOAD is the cachegrind driver's control alone" || echo "$guard_msg")" \
            "$OUT/mutants/module-guard.err"; then
        echo "MUTANT FAIL: a module translation unit with WE_TEST_$name failed, but not on we_policy.h's guard:"
        sed -n 1,5p "$OUT/mutants/module-guard.err" | sed 's/^/    /'
        failures=$((failures + 1))
    fi
done
[ "$failures" = "$before" ] && echo "ok   a module translation unit built without WE_TRACE refuses every mutant by we_policy.h's #error"

# The guard above holds only outside WE_TRACE, the harnesses' build, so a server module refuses WE_TRACE
# itself: each server's source, preprocessed with it (no server headers needed, the refusal is its first
# directive), must stop at that #error.
before=$failures
for src in ../nginx/ngx_http_whisper_edge_module.c ../apache/mod_whisper_edge.c ../litespeed/mod_whisper_edge.c; do
    checks=$((checks + 1))
    "$CC" -DWE_TRACE -DWE_TEST_HH_SERVER_EXEMPT=1 -E -o /dev/null "$src" 2>"$OUT/mutants/trace-guard.err"
    if ! grep -q "a server module is never built with WE_TRACE" "$OUT/mutants/trace-guard.err"; then
        echo "MUTANT FAIL: $src preprocessed with WE_TRACE and a mutant did not stop at its WE_TRACE refusal"
        sed -n 1,3p "$OUT/mutants/trace-guard.err" | sed 's/^/    /'
        failures=$((failures + 1))
    fi
done
[ "$failures" = "$before" ] && echo "ok   every server module refuses WE_TRACE, the one build in which the policy core admits a mutant"

# The list above is held to the sources, so a new mutant cannot be forgotten: every WE_TEST_* name the
# evaluator, the compiler and test_policy test is a row here (or the cachegrind driver's EXTRA_LOAD), and
# every row is a name they test, and the same names are we_policy.h's WE_TRACE guard (EXTRA_LOAD has a
# guard of its own beside it). WE_TEST_NO_EVAL_SITES is the evaluation-site check's control, refused by
# we_eval.h's own guard and held by gate/eval-sites.sh.
checks=$((checks + 1))
in_src=$(grep -ohE 'WE_TEST_[A-Z0-9_]+' we_eval.h we_policy.c test_policy.c | sed 's/^WE_TEST_//' \
         | grep -vx 'NO_EVAL_SITES' | sort -u)
in_rows=$( { for row in "${MUTANTS[@]}"; do echo "${row%%:*}"; done; echo EXTRA_LOAD; } | sort -u)
in_guard=$(sed -n '/^#if !defined(WE_TRACE) && ( \\$/,/^#error/p' we_policy.h | grep -oE 'WE_TEST_[A-Z0-9_]+' \
           | sed 's/^WE_TEST_//' | sort -u)
if [ "$in_src" != "$in_rows" ]; then
    echo "MUTANT FAIL: the sources' WE_TEST_* names and this script's rows differ (< sources only, > rows only):"
    diff <(echo "$in_src") <(echo "$in_rows") | grep '^[<>]' | sed 's/^/    /'
    failures=$((failures + 1))
elif [ "$(echo "$in_src" | grep -vx EXTRA_LOAD)" != "$in_guard" ]; then
    echo "MUTANT FAIL: the sources' WE_TEST_* names and we_policy.h's guard differ (< sources only, > guard only):"
    diff <(echo "$in_src" | grep -vx EXTRA_LOAD) <(echo "$in_guard") | grep '^[<>]' | sed 's/^/    /'
    failures=$((failures + 1))
else
    echo "ok   the $(echo "$in_src" | wc -l) WE_TEST_* names the sources test are exactly this script's rows and we_policy.h's guard"
fi
echo "$checks mutant checks, $failures failures"
[ "$failures" -eq 0 ]
