#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# locals-claims.sh - the modules' decision's locals, said three times and held to one table, both ways.
#
# hotpath-gate.sh's expected-locals table is the measurement: every `hpmod` entry is a compiler leg that
# keeps a spill, held exactly. we_module.h's opening comment and POLICY.md section 3.7 say what holds. Each
# entry is keyed by (compiler, major, architecture, bytes), the architecture from the key's `@<arch>` or,
# failing that, its flag set (an x86 or znver set is x86_64; a key that names neither is refused: a claim
# that cannot say where it holds says nothing). Then, in BOTH directions:
#
#   table to text   each entry is in the header as `on <arch> <compiler> <major> ... keeps <bytes> bytes` and
#                   in POLICY.md's hpmod table as a row `| <compiler> <major>, <a set on arch> | <bytes> ...`
#   text to table   each such sentence of the header and each row of POLICY.md's hpmod table is an entry, and
#                   each `none on <arch>` the header says has no entry on that architecture
#
#   locals-claims.sh                      the tree's three files
#   locals-claims.sh --header FILE        another header (a control)
#   locals-claims.sh --gate FILE          another gate (a control: a table with an aarch64 entry)
set -uo pipefail

cd "$(dirname "$0")" || exit 2
HEADER=we_module.h
POLICY=../POLICY.md
GATE=hotpath-gate.sh
while [ $# -gt 0 ]; do
    case "$1" in
        --header) HEADER=${2:?--header needs a file}; shift 2 ;;
        --gate)   GATE=${2:?--gate needs a file}; shift 2 ;;
        *)        echo "usage: $0 [--header FILE] [--gate FILE]" >&2; exit 2 ;;
    esac
done

checks=0
fails=0
fail() { echo "FAIL locals claims: $*"; fails=$((fails + 1)); }

# the table's entries: "<cc> <major> <arch> <bytes>"
legs=()
while IFS= read -r k; do
    cc=$(sed -E 's/^\["(gcc|clang)-.*/\1/' <<<"$k")
    major=$(sed -E 's/^\["(gcc|clang)-([0-9]+).*/\2/' <<<"$k")
    bytes=${k##*=}
    set_=$(cut -d'|' -f2 <<<"$k")
    if [[ $k =~ @([a-z0-9_]+)\| ]]; then
        arch=${BASH_REMATCH[1]}
    elif [[ $set_ =~ x86|znver ]]; then
        arch=x86_64
    elif [[ $set_ =~ aarch64|arm|neoverse ]]; then
        arch=aarch64
    else
        checks=$((checks + 1))
        fail "the table's key $k names no architecture (no @<arch>, and its set $set_ is not one architecture's)"
        continue
    fi
    legs+=("$cc $major $arch $bytes")
done < <(sed -n '/^declare -A EXPECT_LOCALS=(/,/^)/p' "$GATE" \
    | grep -oE '\["(gcc|clang)-[0-9]+(@[a-z0-9_]+)?\|[^]]*\|hpmod"\]=[0-9]+')   # the locals table only, never the relocations
mapfile -t legs < <(printf '%s\n' "${legs[@]}" | sed '/^$/d' | sort -u)
if [ "${#legs[@]}" -eq 0 ] && [ "$fails" -eq 0 ]; then
    echo "locals claims: NOT PROVEN: no hpmod entry in $GATE's expected-locals table to hold the claims to"
    exit 2
fi

head_text=$(sed -n '1,40p' "$HEADER" | tr -d '*' | tr -s ' \n' ' ')
# the header's sentences: "<arch> <cc> <major> <bytes>", and its "none on <arch>"
mapfile -t said < <(grep -oE 'on (aarch64|x86_64) (gcc|clang) [0-9]+[^;.)]* keeps [0-9]+ bytes' <<<"$head_text" \
    | sed -E 's/^on ([a-z0-9_]+) (gcc|clang) ([0-9]+).* keeps ([0-9]+) bytes$/\2 \3 \1 \4/' | sort -u)
mapfile -t none < <(grep -oE 'none on (aarch64|x86_64)' <<<"$head_text" | sed 's/^none on //' | sort -u)
# POLICY.md's hpmod table: the rows under its `| compiler and set | `hpmod` |` header, to the blank line
mapfile -t rows < <(awk '/^\| compiler and set \| `hpmod` \|/ {t = 1; next} t && /^$/ {t = 0} t && /^\| (gcc|clang) [0-9]/' "$POLICY" \
    | sed -E 's/^\| (gcc|clang) ([0-9]+),([^|]*)\| ([0-9]+).*/\1 \2 \3|\4/' \
    | while IFS='|' read -r head bytes; do
        arch=none
        [[ $head =~ x86_64 ]] && arch=x86_64
        [[ $head =~ aarch64 ]] && arch=aarch64
        read -r cc major _ <<<"$head"
        echo "$cc $major $arch $bytes"
    done | sort -u)

said_text=$(printf '%s\n' "${said[@]}")          # newline-joined once: every lookup below reads a here-string
rows_text=$(printf '%s\n' "${rows[@]}")
legs_text=$(printf '%s\n' "${legs[@]}")
for leg in "${legs[@]}"; do
    read -r cc major arch bytes <<<"$leg"
    checks=$((checks + 2))
    grep -qx "$leg" <<<"$said_text" \
        || fail "$HEADER's opening comment does not say on $arch $cc $major keeps $bytes bytes, which the gate's table holds"
    grep -qx "$leg" <<<"$rows_text" \
        || fail "POLICY.md section 3.7 has no row for $cc $major on $arch keeping $bytes bytes in hpmod, which the gate's table holds"
done
for x in "${said[@]}"; do
    checks=$((checks + 1))
    grep -qx "$x" <<<"$legs_text" \
        || fail "$HEADER says $x (compiler, major, architecture, bytes), which the gate's table does not hold"
done
for x in "${rows[@]}"; do
    checks=$((checks + 1))
    grep -qx "$x" <<<"$legs_text" \
        || fail "POLICY.md's hpmod row $x (compiler, major, architecture, bytes) is not in the gate's table"
done
for a in "${none[@]}"; do
    checks=$((checks + 1))
    if grep -q " $a " <<<"$legs_text"; then
        fail "$HEADER says none on $a, and the gate's table holds $(printf '%s\n' "${legs[@]}" | grep " $a " | head -1 | tr '\n' ' ')"
    fi
done
if [ "$fails" -eq 0 ]; then
    echo "ok   locals claims: the header and POLICY.md say exactly what the gate's table holds for hpmod: $(printf '%s; ' "${legs[@]}")none on ${none[*]}"
fi
echo "$checks checks, $fails failures"
[ "$fails" -eq 0 ]
