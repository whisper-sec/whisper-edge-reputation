#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# rpz-gate-concurrency.sh - the control for overlapping runs: two RPZ gate runs started together must both finish
# CLEAR, and no named either run started may be left behind.
#
# Two `make proof` runs overlapping on one machine used to share the gate's fixed work directory: the
# second cleared the first's pid files, the first could then not stop its named (left reparented to
# pid 1), and the second died on the first's ports with a bare "Error 9". Each run now has a directory
# of its own and stops what it started by the pid it got.
#
#   ./rpz/rpz-gate-concurrency.sh        (from edge/, or `make rpz-concurrency`)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The named processes a gate run starts read a config from its run directory; anything else is not ours.
gate_named() { pgrep -af '^named .*(whisper-rpz-gate|\.testtmp/rpz)/run' || true; }
before=$(gate_named)

./rpz/rpz-gate.sh > "$W/a.log" 2>&1 & a=$!
./rpz/rpz-gate.sh > "$W/b.log" 2>&1 & b=$!
ra=0; wait "$a" || ra=$?
rb=0; wait "$b" || rb=$?
after=$(gate_named)

fail=0
for r in "a:$ra" "b:$rb"; do
    n=${r%%:*} rc=${r#*:}
    if [ "$rc" = 0 ] && grep -q '^RPZ GATE: CLEAR' "$W/$n.log"; then
        echo "  ok    run $n finished CLEAR beside the other"
    elif [ "$rc" = 77 ]; then
        echo "  ok    run $n held everything it ran beside the other (77: a part this host cannot run, named in its log)"
    else
        echo "  FAIL  run $n exited $rc beside the other:"; tail -n 15 "$W/$n.log" | sed 's/^/        /'; fail=1
    fi
done
if [ "$after" = "$before" ]; then
    echo "  ok    no named started by either run is left running"
else
    echo "  FAIL  a gate-owned named outlived its run:"; printf '%s\n' "$after" | sed 's/^/        /'; fail=1
fi
[ "$fail" = 0 ] && { echo "RPZ GATE CONCURRENCY: CLEAR"; exit 0; }
echo "RPZ GATE CONCURRENCY: FAILED"; exit 1
