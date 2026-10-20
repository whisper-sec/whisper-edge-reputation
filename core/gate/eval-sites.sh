#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# eval-sites.sh - the evaluation-site record (we_eval.h, WE_EVAL_SITE): built as the modules are built
# (-O2 -fPIC -shared -ffunction-sections), the evaluator's wrapper carries exactly one 4-byte record in
# .we_eval_sites, resolving into hpeval and into no other symbol; the record adds no RELATIVE relocation
# (the shared object's count equals the control build's); and hpeval's instruction count is the same with the record and without it (the control
# build, WE_TEST_NO_EVAL_SITES, admitted here alone). The control: the build without the record has no
# record, and this check refuses it as `no evaluation site found`, never passes it.
#
# Usage: eval-sites.sh [workdir]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WORK=${1:-.testtmp/eval-sites}
mkdir -p "$WORK"
fail=0
FLAGS=(-std=c11 -O2 -fPIC -shared -ffunction-sections -Wall -Wextra -Werror -I. -Igate)

# records SO -> one line per record: the site's address (hex), the symbol it falls in
records() {
    local so=$1
    python3 - "$so" <<'PY'
import re, subprocess, sys
so = sys.argv[1]
sec = subprocess.run(["readelf", "-SW", so], capture_output=True, text=True).stdout
m = re.search(r"\]\s+\.we_eval_sites\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", sec)
if not m:
    print("none")
    sys.exit(0)
addr, off, size = (int(x, 16) for x in m.groups())
dump = subprocess.run(["objdump", "-s", "-j", ".we_eval_sites", so], capture_output=True, text=True).stdout
data = bytearray()
for line in dump.splitlines():
    mm = re.match(r"^ ([0-9a-f]+) ((?:[0-9a-f]{2,8} ?)+)", line)
    if mm:
        for word in mm.group(2).split():
            data += bytes.fromhex(word)
syms = []
for line in subprocess.run(["nm", "-n", "-S", "--defined-only", so], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    if len(f) == 4 and f[2] in "tTwW":
        syms.append((int(f[0], 16), int(f[1], 16), f[3]))
for i in range(0, size - size % 4, 4):
    rel = int.from_bytes(data[i:i + 4], "little", signed=True)
    site = addr + i + rel
    name = next((n for a, sz, n in syms if a <= site < a + sz), "?")
    print("%x %s" % (site, name))
PY
}

for cc in gcc clang; do
    command -v "$cc" >/dev/null 2>&1 || { echo "  $cc: not installed, not measured"; continue; }
    for arm in record control; do
        extra=()
        [ "$arm" = control ] && extra=(-DWE_EVAL_SITES_CONTROL -DWE_TEST_NO_EVAL_SITES)
        if ! "$cc" "${FLAGS[@]}" "${extra[@]}" -o "$WORK/hp_eval.$cc.$arm.so" hp_eval.c 2>"$WORK/build.$cc.$arm.err"; then
            echo "EVAL-SITES FAIL: hp_eval.c does not build as a shared object ($cc, $arm): $(head -1 "$WORK/build.$cc.$arm.err" | cut -c1-120)"
            fail=1
            continue
        fi
    done
    [ -f "$WORK/hp_eval.$cc.record.so" ] && [ -f "$WORK/hp_eval.$cc.control.so" ] || continue
    recs=$(records "$WORK/hp_eval.$cc.record.so")
    [ "$recs" = none ] && recs=""
    n=$(printf '%s\n' "$recs" | grep -c . || true)
    inside=$(printf '%s\n' "$recs" | awk '$2 == "hpeval"' | grep -c . || true)
    # a shared object carries the C runtime's own RELATIVE entries (.init_array, .fini_array); the record must
    # add none, so the count is held equal to the control build's, and both are printed
    relative=$(readelf -rW "$WORK/hp_eval.$cc.record.so" | grep -c RELATIVE || true)
    crelative=$(readelf -rW "$WORK/hp_eval.$cc.control.so" | grep -c RELATIVE || true)
    with=$(objdump -d --no-show-raw-insn "$WORK/hp_eval.$cc.record.so" | awk '/<hpeval>:$/ { p=1; next } /^[0-9a-f]+ <.*>:/ { p=0 } p && /^ +[0-9a-f]+:/ { n++ } END { print n+0 }')
    without=$(objdump -d --no-show-raw-insn "$WORK/hp_eval.$cc.control.so" | awk '/<hpeval>:$/ { p=1; next } /^[0-9a-f]+ <.*>:/ { p=0 } p && /^ +[0-9a-f]+:/ { n++ } END { print n+0 }')
    if [ "$recs" = none ] || [ "$n" != 1 ] || [ "$inside" != 1 ]; then
        echo "EVAL-SITES FAIL ($cc): $n record(s), $inside inside hpeval; wanted exactly one, inside hpeval: $(printf '%s' "$recs" | tr '\n' ';')"
        fail=1
    elif [ "$relative" != "$crelative" ]; then
        echo "EVAL-SITES FAIL ($cc): $relative RELATIVE relocation(s) with the record against $crelative without it; the record must add none"
        fail=1
    elif [ "$with" != "$without" ] || [ "$with" = 0 ]; then
        echo "EVAL-SITES FAIL ($cc): hpeval is $with instructions with the record and $without without it"
        fail=1
    else
        echo "ok   eval-sites ($cc): one record in .we_eval_sites, inside hpeval (site $(printf '%s' "$recs" | cut -d' ' -f1)); $relative RELATIVE relocations, the runtime's own, $crelative without the record; hpeval $with instructions with the record and $without without it"
    fi
    # the control: the build without the record must be refused as no evaluation site found
    crecs=$(records "$WORK/hp_eval.$cc.control.so")
    if [ "$crecs" = none ] || [ -z "$crecs" ]; then
        echo "ok   eval-sites control ($cc): the build without the record is refused: no evaluation site found"
    else
        echo "EVAL-SITES FAIL ($cc): the control build carries a record: $(printf '%s' "$crecs" | tr '\n' ';')"
        fail=1
    fi
done
# the control define stays this check's: a production unit with it set must not build
if gcc -std=c11 -O2 -fPIC -Wall -Wextra -Werror -DWE_TEST_NO_EVAL_SITES -I. -c -o "$WORK/guard.o" hp_eval.c 2>"$WORK/guard.err"; then
    echo "EVAL-SITES FAIL: hp_eval.c compiled with WE_TEST_NO_EVAL_SITES alone: the guard is gone"
    fail=1
elif grep -q "evaluation-site check's control alone" "$WORK/guard.err"; then
    echo "ok   eval-sites: WE_TEST_NO_EVAL_SITES is refused outside this check (we_eval.h's guard)"
else
    echo "EVAL-SITES FAIL: hp_eval.c with WE_TEST_NO_EVAL_SITES failed, but not at the guard: $(head -1 "$WORK/guard.err" | cut -c1-120)"
    fail=1
fi
if [ "$fail" != 0 ]; then echo "EVAL SITES: FAILED"; exit 1; fi
echo "EVAL SITES: CLEAR"
