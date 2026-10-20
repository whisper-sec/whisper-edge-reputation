#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# control-builds.sh - every control the guard list declares compiles, alone, with -Werror.
#
# A control build that no longer compiles is a gate that cannot run: the first to notice was a server walk,
# where two counters controls stopped compiling because each compiled out the only call of a helper. This
# builds the shipped core once per name declared in we_module.h's guard list, in the release and the debug
# configuration, each shipped source that mentions the name compiled with -Werror, and every test harness
# that includes the module header, the way the controls' own runs build it. A name with a body only
# in a server's module (whose gate builds it) compiles the core unchanged, which is still a build to pass.
#
#   ./control-builds.sh [CC [CFLAGS...]]     default: cc -std=c11 -O2 -Wall -Wextra -Werror
# Exit 0 with "N control builds, 0 failures", 1 naming every control and configuration that did not build.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CC=${1:-cc}; [ $# -gt 0 ] && shift
CFLAGS=("$@"); [ ${#CFLAGS[@]} -gt 0 ] || CFLAGS=(-std=c11 -O2 -Wall -Wextra -Werror)
SHIPPED=(we_module.c whisper_edge.c we_policy.c we_counters.c we_sha256.c)
# the harnesses a control build compiles: every test source that includes the module header, each built under
# every control (the controls' runs are release builds of these, so a row that calls a debug-only symbol
# unguarded breaks every one of them)
HARNESS=()
for f in "$HERE"/test_*.c; do
    grep -q '#include "we_module.h"' "$f" && HARNESS+=("$(basename "$f")")
done
OUT=$(mktemp -d "${TMPDIR:-/tmp}/control-builds.XXXXXX")
trap 'rm -rf "$OUT"' EXIT

# the guard list: the #if !defined(WE_MOD_CONTROL_BUILD) block, read as one logical line
names=$(awk '/^#if !defined\(WE_MOD_CONTROL_BUILD\) && \(/ { on = 1 } on { print } on && !/\\$/ { exit }' \
        "$HERE/we_module.h" | grep -oE '\bWE_MOD_TEST_[A-Z0-9_]+\b' | sort -u)
[ -n "$names" ] || { echo "control-builds: no names read from we_module.h's guard list"; exit 1; }
declare -A DEPS
deps() { # source -> the source and the tree's headers it includes, once per source
    if [ -z "${DEPS[$1]:-}" ]; then
        DEPS[$1]=$("$CC" -MM -I"$HERE" "$HERE/$1" 2>/dev/null | tr ' \\' '\n\n' | grep -E '\.(c|h)$' \
                   | while read -r d; do [ -f "$d" ] && printf '%s ' "$d"; [ -f "$HERE/$d" ] && printf '%s ' "$HERE/$d"; done)
    fi
    printf '%s' "${DEPS[$1]}"
}
for f in "${SHIPPED[@]}"; do deps "$f" > /dev/null; done
jobs=()
for n in $names; do
    for mode in release debug; do
        def=(-DWE_MOD_CONTROL_BUILD "-D$n"); [ "$mode" = debug ] && def+=(-DWE_MOD_DEBUG)
        for f in "${SHIPPED[@]}"; do
            # the source, or a header of this tree it includes (cc -MM: what the compiler actually reads)
            # shellcheck disable=SC2046
            grep -qw "$n" $(deps "$f") 2>/dev/null || continue
            jobs+=("$n $mode $f")
        done
        if [ "$mode" = release ]; then
            # the controls' runs build the harnesses in the release configuration; the debug one is make
            # check's own test_module build
            for f in "${HARNESS[@]}"; do
                jobs+=("$n $mode $f")
            done
        fi
    done
done
build() { # name mode file
    local def=(-DWE_MOD_CONTROL_BUILD "-D$1"); [ "$2" = debug ] && def+=(-DWE_MOD_DEBUG)
    if ! "$CC" "${CFLAGS[@]}" "${def[@]}" -I"$HERE" -c "$HERE/$3" -o "$OUT/$1.$2.${3%.c}.o" 2> "$OUT/$1.$2.${3%.c}.err"; then
        printf 'FAIL control builds: %s (%s) does not compile %s: %s\n' "$1" "$2" "$3" \
            "$(grep -m1 -E 'error|warning' "$OUT/$1.$2.${3%.c}.err" | cut -c1-200)"
    fi
}
export -f build; export CC OUT HERE; export CFLAGS_STR="${CFLAGS[*]}"
fails=$(printf '%s\n' "${jobs[@]}" | xargs -P "$(nproc 2>/dev/null || echo 4)" -L1 bash -c \
        'CFLAGS=($CFLAGS_STR); build "$0" "$1" "$2"' | sort)
[ -n "$fails" ] && printf '%s\n' "$fails"
nf=$(printf '%s' "$fails" | grep -c '^FAIL' || true)
echo "${#jobs[@]} control builds, $nf failures"
[ "$nf" = 0 ]
