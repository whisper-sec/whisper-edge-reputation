#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# live-legs.sh - check-live's two policy legs (POLICY.md section 6), over the LIVE routing plane: the
# pinned CAIDA RouteViews IPv4 table written as a routing plane file and opened by the real loader
# (gate/cg_driver.c, evaluator-live).
#
#   differential  the C compiler and evaluator against the reference interpreter on 2,000 live requests:
#                 the driver writes the slot as policy_ref.py's case file (each address's live record),
#                 and every verdict line must be the interpreter's
#   cost          the whole bound per request on the same 2,000 (rows C3 and C5): the 64-byte lines each
#                 request reads equal the line model's, line for line, in the traced build
#
# Each leg is DARK by name until what it compares is in the tree: the evaluator (we_eval.h, we_policy.c)
# for both, the reference interpreter (policy_ref.py) for the differential. python3 absent is a failure.
# The RouteViews inputs are the ones `make fixtures` fetched and pinned (fixtures/rib): no second fetch.
#
# Usage: live-legs.sh <workdir>
set -euo pipefail

cd "$(dirname "$0")/.."
HERE=$PWD
WORK="${1:?usage: live-legs.sh <workdir>}"
N=2000

if [ ! -f we_eval.h ] || [ ! -f we_policy.c ]; then
    echo "DARK the live differential and cost legs: the policy evaluator (we_eval.h, we_policy.c) is not in this tree; they run, with no edit here, once it is"
    exit 0
fi
command -v python3 >/dev/null 2>&1 || { echo "LIVE FAIL: python3 is not installed; a missing interpreter is a failure, not a skip"; exit 1; }

# the bench's flattened tables, from the inputs check-live already fetched and verified
mkdir -p "$WORK/data"
[ -e "$WORK/data/rib" ] || ln -s "$HERE/fixtures/rib" "$WORK/data/rib"
"$HERE/bench/run-x86.sh" "$WORK/data" --prepare | sed 's/^/  /'

SRC=(gate/cg_driver.c whisper_edge.c we_writer.c we_sha256.c we_counters.c we_policy.c)
cc -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_HAVE_EVAL -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_live" "${SRC[@]}"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -DWE_HAVE_EVAL -DWE_TRACE -I"$HERE" -I"$HERE/gate" -o "$WORK/cg_live_trace" "${SRC[@]}"
fail=0

if [ -f policy_ref.py ]; then
    "$WORK/cg_live" "$WORK/data" cases evaluator-live "$N" > "$WORK/live.cases" 2>"$WORK/live.cases.err"
    PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --cases "$WORK/live.cases" --out "$WORK/live.ref" > "$WORK/live.ref.log" 2>&1 \
        || { echo "LIVE FAIL: the reference interpreter refused the live cases:"; tail -5 "$WORK/live.ref.log"; exit 1; }
    grep '^verdict ' "$WORK/live.ref" > "$WORK/live.ref.verdicts"
    "$WORK/cg_live" "$WORK/data" verdicts evaluator-live "$N" > "$WORK/live.c.verdicts" 2>"$WORK/live.c.err"
    if [ "$(grep -c . "$WORK/live.ref.verdicts")" != "$N" ]; then
        echo "LIVE FAIL: the reference interpreter gave $(grep -c . "$WORK/live.ref.verdicts") verdicts for $N live requests"
        fail=1
    elif diff -q "$WORK/live.ref.verdicts" "$WORK/live.c.verdicts" >/dev/null; then
        denies=$(grep -c 'action=deny' "$WORK/live.c.verdicts" || true)
        echo "ok   live differential: the C evaluator's $N verdicts on the live routing plane are the reference interpreter's ($denies denies among them)"
        # its planted control: one live record's origin validation rewritten to invalid in the interpreter's
        # input only; rule 1 (deny if rpki == invalid) must then deny there and the comparison must see it
        python3 - "$WORK/live.cases" "$WORK/live.planted.cases" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
done = False
with open(src) as f, open(dst, "w") as o:
    for line in f:
        if not done and line.startswith("rec ") and " routing asn=" in line and " rov=2 " not in line:
            line = re.sub(r" rov=\d+ ", " rov=2 ", line)
            done = True
        o.write(line)
sys.exit(0 if done else 1)
PY
        PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --cases "$WORK/live.planted.cases" --out "$WORK/live.planted" > /dev/null 2>&1 || true
        if grep '^verdict ' "$WORK/live.planted" | diff -q - "$WORK/live.c.verdicts" >/dev/null; then
            echo "LIVE FAIL: the live differential did not see a planted record change; it compares nothing"
            fail=1
        else
            echo "ok   the live differential sees a planted record: one origin rewritten to invalid, one verdict apart"
        fi
    else
        echo "LIVE FAIL: the C evaluator and the reference interpreter disagree on the live routing plane:"
        diff "$WORK/live.ref.verdicts" "$WORK/live.c.verdicts" | sed -n 1,8p | sed 's/^/        /'
        fail=1
    fi
else
    echo "DARK the live differential: policy_ref.py is not in this tree, so the C evaluator has nothing independent to agree with"
fi

if out=$("$WORK/cg_live_trace" "$WORK/data" bound evaluator-live "$N" 2>"$WORK/live.bound.err"); then
    printf '%s\n' "$out" | grep -v '^BOUND' | sed 's/^/  /'
else
    printf '%s\n' "$out" | sed 's/^/  /'
    echo "LIVE FAIL: the live cost leg: the lines read on the live plane are not the model's"
    fail=1
fi
exit "$fail"
