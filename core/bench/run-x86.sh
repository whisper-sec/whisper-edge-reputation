#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# run-x86.sh - reproduce the routing-plane layout measurements on any 64-bit host, and fail if the
# hardware-independent ones differ from the committed expectation.
#
# The index-kind table was measured on an aarch64 host. Its probe, line, page and percentile
# columns depend on the data and the layout and on nothing about the machine, so they must come out
# IDENTICAL on the production x86_64 box; that is the check that the x86 run measured the same thing.
# Everything that can move them is pinned here:
#
#   the inputs     CAIDA's RouteViews prefix-to-AS snapshots of 2026-10-09 12:00, by sha256
#   the flattening build7.py, with the row count and sha256 of every file it writes asserted, so a
#                  change to the flattening cannot move every count unnoticed
#   the streams    one xorshift64 generator, seed 0x9e3779b97f4a7c15, in lay7.c
#   the layout     every array 4096-byte aligned, so a read's line and page depend only on its index
#   the arithmetic the percentiles are computed in integers
#
# and the counts are compared with expected-counts.tsv beside this script. ANY difference in them is a
# non-zero exit. Nanoseconds and hardware counters are printed after the comparison, labelled with the
# machine, and never compared: they are information.
#
# Usage: run-x86.sh [workdir] [--write-expected | --prepare]
#   workdir defaults to $TMPDIR/whisper-edge-bench; the inputs are downloaded into workdir/rib once.
#   --write-expected rewrites expected-counts.tsv from this run (how the committed file was made).
#   --prepare stops after the inputs and the flattened tables are in workdir and asserted; it is how
#             cachegrind-gate.sh gets the same data.
# Needs: a C compiler, python3, curl, sha256sum. Optional: taskset, perf.
set -euo pipefail

D=$(cd "$(dirname "$0")" && pwd)
W="${TMPDIR:-/tmp}/whisper-edge-bench"
WRITE=0
PREPARE=0
for a in "$@"; do
    case "$a" in
        --write-expected) WRITE=1 ;;
        --prepare) PREPARE=1 ;;
        -*) echo "usage: run-x86.sh [workdir] [--write-expected | --prepare]" >&2; exit 2 ;;
        *) W=$a ;;
    esac
done
mkdir -p "$W/rib"
W=$(cd "$W" && pwd)
EXPECTED="$D/expected-counts.tsv"
CC="${CC:-cc}"
SEED=0x9e3779b97f4a7c15

# ---- the inputs, pinned ------------------------------------------------------------------------
BASE=https://publicdata.caida.org/datasets/routing
RV4=routeviews-rv2-20261009-1200.pfx2as.gz
RV6=routeviews-rv6-20261009-1200.pfx2as.gz
RV4_SHA=6d21f6a224160e10b7af081064eb289575b75fe4e3be9374193e94672e454cee
RV6_SHA=270dcc20b304df7c06dded6614ab9905374d5bdf9c098ef79fe7c88e092f7a82

fetch() { # dataset file
    if [ ! -s "$W/rib/$2" ]; then
        echo "fetching $2"
        curl -fsS --retry 3 -o "$W/rib/$2.part" "$BASE/$1/2026/10/$2"
        mv "$W/rib/$2.part" "$W/rib/$2"
    fi
}
fetch routeviews-prefix2as "$RV4"
fetch routeviews6-prefix2as "$RV6"

check_sha() { # file expected-sha what
    local got
    got=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$got" != "$2" ]; then
        echo "BENCH FAIL: $3 $1 has sha256 $got, pinned $2"
        exit 1
    fi
}
check_sha "$W/rib/$RV4" "$RV4_SHA" input
check_sha "$W/rib/$RV6" "$RV6_SHA" input
echo "ok   inputs: $RV4 and $RV6 match their pinned digests"

# ---- the flattening, asserted ------------------------------------------------------------------
python3 "$D/build7.py" "$W" "$W" > "$W/build7.log.$$.tmp" && mv "$W/build7.log.$$.tmp" "$W/build7.log"
# file : element bytes : rows : sha256
FLAT=(
    "v4.start:4:1169047:6224f960d6edb0fb2b108b44d22cf77b6a1166e39aad6d5704ca4da8d1be18d5"
    "v4.rec16:16:1169047:2a1667fdea860211c3cd597ed4a0b2e6925306206f14c0eee4f6262fe63b5511"
    "v6.start:8:298246:c1b1c1f1128d0bec6945d8b6f2f01c7bc9cb3e3de7abf1816478e11fb469b253"
    "v6.rec24:24:298246:453171a8003ccfc428c36f96e2155e6e7e0a5e7ba6aac57be6cfa3e3a2ea3496"
)
for row in "${FLAT[@]}"; do
    IFS=: read -r f esz rows sha <<<"$row"
    bytes=$(wc -c < "$W/$f")
    if [ $((bytes % esz)) != 0 ] || [ $((bytes / esz)) != "$rows" ]; then
        echo "BENCH FAIL: $f holds $bytes bytes, which is not $rows rows of $esz bytes"
        exit 1
    fi
    check_sha "$W/$f" "$sha" "flattened output"
    echo "ok   $f: $rows rows, sha256 as pinned"
done
if [ "$PREPARE" = 1 ]; then
    echo "RUN-X86: PREPARED $W"
    exit 0
fi

# ---- the counts, compared ----------------------------------------------------------------------
ARCH=$(uname -m)
MARCH=()
case "$ARCH" in
    x86_64) MARCH=(-march=x86-64-v3) ;;
    aarch64|arm64) MARCH=(-mcpu=native) ;;
esac
for f in 4 6; do
    "$CC" -std=gnu11 -O2 "${MARCH[@]}" -Wall -Wextra -Werror -DFAM=$f "$D/lay7.c" -o "$W/lay7-v$f"
done
{ "$W/lay7-v4" "$W" tsv; "$W/lay7-v6" "$W" tsv; } > "$W/counts.tsv"

HEADER="family	kind	ranges	hot_bytes	probes_max	cold64_max	cold128_max	lines64_max	pages4k_max	exact_uniform_cold64_p50	exact_uniform_cold64_p99	uniform_cold64_p50	uniform_cold64_p99	uniform_cold64_max	uniform_lines64_p99	dense_cold64_p50	dense_cold64_p99	dense_cold64_max	dense_lines64_p99"

if [ "$WRITE" = 1 ]; then
    {
        echo "# expected-counts.tsv - the hardware-independent columns of the routing-plane layout table,"
        echo "# written by run-x86.sh --write-expected on $ARCH. run-x86.sh fails on any difference in them."
        echo "# input   $RV4_SHA  $RV4"
        echo "# input   $RV6_SHA  $RV6"
        for row in "${FLAT[@]}"; do
            IFS=: read -r f esz rows sha <<<"$row"
            echo "# output  $sha  $f ($rows rows)"
        done
        echo "# streams xorshift64, seed $SEED; 1,000,000 sampled per stream; uniform over IPv4 and 2000::/3"
        echo "# columns: probes, cold lines (outside the index) and all lines at 64 bytes, pages at 4 KiB;"
        echo "# the exact_ columns are over every outcome class, address-weighted; the others are sampled."
        echo "$HEADER"
        cat "$W/counts.tsv"
    } > "$EXPECTED"
    echo "wrote $EXPECTED from this run on $ARCH"
fi

if [ ! -f "$EXPECTED" ]; then
    echo "BENCH FAIL: no $EXPECTED to compare with"
    exit 1
fi
if ! diff <(grep -v '^#' "$EXPECTED") <(echo "$HEADER"; cat "$W/counts.tsv") > "$W/counts.diff"; then
    echo "BENCH FAIL: the hardware-independent counts differ from expected-counts.tsv (< expected, > this run on $ARCH):"
    sed 's/^/        /' "$W/counts.diff"
    exit 1
fi
echo "ok   probes, cold lines, all lines, pages and p99 equal expected-counts.tsv on $ARCH: $(wc -l < "$W/counts.tsv") rows"
column -t -s "$(printf '\t')" <(echo "$HEADER"; cat "$W/counts.tsv") 2>/dev/null || { echo "$HEADER"; cat "$W/counts.tsv"; }

# ---- information: ns and hardware counters, never compared ------------------------------------
echo
echo "---- information only, never compared: this machine ----"
uname -srm
grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
lscpu 2>/dev/null | grep -E 'Model name|L1d|L2|L3' || true
if sudo -n cpupower frequency-set -g performance >/dev/null 2>&1; then
    echo "governor: performance"
else
    echo "governor: not pinned (needs passwordless sudo and cpupower); the ns figures carry that noise"
fi
# The CPU pin is for the ns figures only, and BEST-EFFORT: a CI runner with two vCPUs, or a cgroup
# that does not allow the CPU asked for, makes taskset fail with EINVAL, and that must never fail a
# script whose comparison already ran. So the pin is tried once and dropped, with one line saying so.
PIN=()
if command -v taskset >/dev/null 2>&1 && taskset -c "${CPU:-2}" true >/dev/null 2>&1; then
    PIN=(taskset -c "${CPU:-2}")
    echo "cpu: pinned to ${CPU:-2}"
else
    echo "cpu: not pinned (taskset is missing or CPU ${CPU:-2} is not in this process's allowed set); the ns figures carry that noise"
fi
for f in 4 6; do
    "${PIN[@]}" "$W/lay7-v$f" "$W" time
done
if ! command -v perf >/dev/null 2>&1; then
    echo "perf not installed: no hardware counters"
elif ! perf stat -e instructions true >/dev/null 2>&1; then
    echo "perf is installed but may not read counters here (kernel.perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)); no hardware counters"
else
    E=cycles,instructions,L1-dcache-load-misses,LLC-load-misses,dTLB-load-misses
    for f in 4 6; do
        for k in radix-16 radix-18 rank-64s; do
            # per lookup: a run of 4M lookups minus the same run with 0, which is setup only
            a=$("${PIN[@]}" perf stat -x, -e "$E" "$W/lay7-v$f" "$W" "cg-$k" d 4000000 2>&1 >/dev/null | cut -d, -f1 | tr '\n' ' ') || true
            b=$("${PIN[@]}" perf stat -x, -e "$E" "$W/lay7-v$f" "$W" "cg-$k" d 0 2>&1 >/dev/null | cut -d, -f1 | tr '\n' ' ') || true
            echo "$a|$b" | awk -v t="IPv$f $k dense" -F'|' '
                function per(x, y) { return (x ~ /^[0-9]+$/ && y ~ /^[0-9]+$/) ? sprintf("%.2f", (x - y) / 4e6) : "n/a" }
                { split($1, x, " "); split($2, y, " ");
                  printf "%s per lookup: cycles %s instructions %s L1d-miss %s LLC-miss %s dTLB-miss %s\n", t,
                         per(x[1], y[1]), per(x[2], y[2]), per(x[3], y[3]), per(x[4], y[4]), per(x[5], y[5]) }'
        done
    done
fi
echo "RUN-X86: COUNTS MATCH on $ARCH"
