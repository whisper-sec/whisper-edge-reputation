#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# reference-verdicts.sh - the reference interpreter's verdicts for every evaluator slot of the cachegrind
# driver, written to gate/expected/<slot>.verdicts, which cachegrind-gate.sh holds the C evaluator to
# before it measures a slot (a slot whose verdicts are wrong is never priced).
#
# The driver writes each slot's world as the interpreter's case file (`cg_driver <dir> cases <slot> <n>`:
# the slot's directives, then per request the two addresses, every plane's state and each address's
# records); policy_ref.py reads it with its own compiler and evaluator and prints a verdict line per
# request; the lines are kept as they are. Nothing of the C evaluator is involved, so this runs before
# we_eval.h exists. A slot is given the first 16 of its requests, the two stream slots (default and live)
# their first 2,000 (their requests are not all alike).
#
# DARK by name while policy_ref.py is not in the tree. python3 absent is a failure, never a skip.
#
# Usage: reference-verdicts.sh [workdir]
set -euo pipefail

cd "$(dirname "$0")/.."
HERE=$PWD
WORK="${1:-${TMPDIR:-/tmp}/whisper-edge-verdicts}"
DATA="${WE_BENCH_DATA:-${TMPDIR:-/tmp}/whisper-edge-bench}"
OUT="$HERE/gate/expected"

if [ ! -f policy_ref.py ]; then
    echo "DARK the reference verdicts: policy_ref.py is not in this tree, so no slot has an independent verdict to be held to"
    exit 0
fi
command -v python3 >/dev/null 2>&1 || { echo "VERDICTS FAIL: python3 is not installed; a missing interpreter is a failure, not a skip"; exit 1; }

mkdir -p "$WORK" "$OUT"
"$HERE/bench/run-x86.sh" "$DATA" --prepare | sed 's/^/  /'
# every step fails by name: a set -e exit with no message once read as nothing at all
cc -std=gnu11 -O2 -Wall -Wextra -Werror -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_cases" \
    gate/cg_driver.c whisper_edge.c we_writer.c we_sha256.c we_counters.c \
    || { echo "VERDICTS FAIL: the driver does not build"; exit 1; }
"$WORK/cg_cases" "$DATA" slots > "$WORK/slots.tsv" 2>"$WORK/slots.err" \
    || { echo "VERDICTS FAIL: the driver could not print its slot table:"; sed 's/^/        /' "$WORK/slots.err"; exit 1; }

n=0
while IFS=$'\t' read -r slot req _; do
    case "$slot" in ''|\#*) continue ;; esac
    k=16
    case "$slot" in evaluator-default|evaluator-live) k=2000 ;; esac
    [ "$req" -lt "$k" ] && k=$req
    "$WORK/cg_cases" "$DATA" cases "$slot" "$k" > "$WORK/$slot.cases" 2>"$WORK/$slot.cases.err" \
        || { echo "VERDICTS FAIL: the driver could not write $slot's cases:"; tail -3 "$WORK/$slot.cases.err"; exit 1; }
    if ! PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --cases "$WORK/$slot.cases" --out "$WORK/$slot.out" \
            > "$WORK/$slot.log" 2>&1; then
        echo "VERDICTS FAIL: the reference interpreter refused $slot's cases:"
        sed 's/^/        /' "$WORK/$slot.log" | tail -5
        exit 1
    fi
    if grep -q '^refusal ' "$WORK/$slot.out"; then
        echo "VERDICTS FAIL: the reference interpreter refuses $slot's program, so the slot measures nothing real:"
        grep '^refusal ' "$WORK/$slot.out" | sed -n 1,3p | sed 's/^/        /'
        exit 1
    fi
    grep '^verdict ' "$WORK/$slot.out" > "$WORK/$slot.verdicts"
    got=$(grep -c . "$WORK/$slot.verdicts" || true)
    if [ "$got" != "$k" ]; then
        echo "VERDICTS FAIL: $slot: $k cases written, $got verdicts read back"
        exit 1
    fi
    mv "$WORK/$slot.verdicts" "$OUT/$slot.verdicts"
    n=$((n + 1))
done < "$WORK/slots.tsv"
echo "ok   the reference interpreter's verdicts for $n evaluator slots are in gate/expected/"
