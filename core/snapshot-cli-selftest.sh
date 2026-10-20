#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# snapshot-cli-selftest.sh - make-test-snapshot.py's command line: help is help, and a mistyped option
# is refused, never written as a file. `--help` used to be taken as the legacy form's output path and
# left a file named --help in the working directory.
#
# Usage: snapshot-cli-selftest.sh <workdir>
set -u
W=$1/snapshot-cli
rm -rf "$W"; mkdir -p "$W"
HERE=$(cd "$(dirname "$0")" && pwd)
checks=0; fails=0
row() { # row <name> <want exit> <want text> <args...>: run in $W, the exit and a stderr/stdout line checked, nothing left behind but what the row names
    local name=$1 want=$2 text=$3 out rc
    shift 3
    checks=$((checks + 1))
    out=$(cd "$W" && python3 -I "$HERE/make-test-snapshot.py" "$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" = "$want" ] && grep -qF -- "$text" <<<"$out"; then
        echo "ok   snapshot cli: $name (exit $rc)"
    else
        echo "FAIL snapshot cli: $name: exit $rc, want $want and \"$text\": $(head -1 <<<"$out")"
        fails=$((fails + 1))
    fi
}
empty() { # empty <name>: the work directory holds nothing the refused run wrote
    checks=$((checks + 1))
    local left
    left=$(find "$W" -mindepth 1 -printf '%f ')
    if [ -z "$left" ]; then echo "ok   snapshot cli: $1 wrote nothing"; else echo "FAIL snapshot cli: $1 left $left"; fails=$((fails + 1)); fi
}
row "--help prints the usage" 0 "Usage, the form every web-server gate uses" --help
empty "--help"
row "-h prints the usage" 0 "Usage, any plane" -h
empty "-h"
row "a dash-led legacy output path is refused" 2 "is an option, not an output path" -o
empty "a dash-led legacy path"
row "a dash-led --out is refused" 2 "is an option, not an output path" --plane tor --out -x
row "an unknown --plane option is refused" 2 "unknown option '--outt'" --plane tor --outt x.bin
row "a valued option with no value is refused" 2 "--out takes a value" --plane tor --out
empty "the refused --plane forms"
row "the legacy form still writes its file" 0 "" snap.bin 1
checks=$((checks + 1))
if [ -s "$W/snap.bin" ]; then echo "ok   snapshot cli: the legacy form wrote snap.bin"; else echo "FAIL snapshot cli: the legacy form wrote no file"; fails=$((fails + 1)); fi
rm -rf "$W"
echo "$checks checks, $fails failures"
[ "$fails" -eq 0 ]
