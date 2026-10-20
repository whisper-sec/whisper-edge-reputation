# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# shellcheck shell=bash
# policy-rows.sh - the module gates' policy rows, sourced by nginx/nginx-gate.sh, apache/apache-gate.sh
# and litespeed/litespeed-gate.sh. Each gate defines ROOT (the edge tree) and its own ok and bad.
#
# The three modules compile their directives to policy programs at configuration time when the policy
# compiler is in the build (core/we_module_policy.h). These rows prove what that may and may not do:
#
#   G2  every context the gate configures gets its configuration-time line exactly once per load, and
#       the line names a program. (Whether a rule is inert is not on this line and is not claimed here:
#       the sugar compiles with every plane present, so its program has no plane to be inert on.)
#   G3  two contexts with the same threshold under different modes run ONE program (the same number)
#       and get different verdicts; a context with no threshold line runs its PARENT's program, not the
#       server's, under its own mode. The gates give each level its own threshold, so the program
#       numbers can tell a parent from the server: two levels at one threshold would share a number
#       whichever one was inherited.
#   G4  the programs and the hold-harmless view sit in pages that two worker processes SHARE after the
#       fork: in each worker's /proc/<pid>/smaps every resident page of every region is shared and
#       none is private, so no worker took a copy-on-write copy; and the configuration-wide hot-bytes
#       total is printed. POLICY.md row G4 words this as Shared_Clean, but anonymous pages written before a
#       fork are reported as Shared_Dirty in both processes (measured: a page written, sealed with
#       mprotect and forked reads Shared_Dirty 16 kB, Shared_Clean 0), so the property asserted is the
#       one that matters: shared, with no private page. The parser is shown first to see a private
#       page where one exists (the worker's own stack), so it cannot pass by seeing nothing.
#
# Until the policy compiler is in the tree every row is reported DARK by name and nothing is claimed.

policy_lit() { [ -f "$ROOT/core/we_policy.h" ] && [ -f "$ROOT/core/we_eval.h" ]; }

# last_load <log text> -> the lines of the LAST configuration load: everything after the previous
# summary line up to and including the last one. Apache parses its configuration twice at startup and
# a server log accumulates across restarts, so "once per load" is counted inside one load.
last_load() {
    printf '%s\n' "$1" | awk '{ buf = buf $0 "\n" } /whisper edge: policy: .*read-only regions:/ { last = buf; buf = "" } END { printf "%s", last }'
}

policy_dark() { # policy_dark <server>
    echo "  DARK  G2, G3, G4 ($1): the policy compiler (core/we_policy.h, core/we_eval.h) is not in this tree; these rows run, with no edit here, once it is"
}

# TWO LINE GRAMMARS, one reader. The first module build printed `whisper edge: policy: <label>: ...`
# with the program numbered (`program #1`). A module that compiles its configuration whole prints
# the context's name as an escaped, quoted field (`"location \"/\""`, `"server \"a\""`, or
# `"server #1"` for an unnamed one) followed by its place in parentheses, and names the program by the
# first sixteen hex digits of its digest (`program 031d8b707e4f44ac`). The rows read either, so the
# three gates can move one at a time; what each row asserts is the same under both.

# ere_escape <text> -> the text with every extended-regex metacharacter escaped
ere_escape() { printf '%s' "$1" | sed 's/[][\.*^$|()+?{}]/\\&/g'; }

# d32_quote <text> -> the text as the status and log files write a free-text field: quoted, `\` and `"` escaped
d32_quote() { local t=$1; t=${t//\\/\\\\}; t=${t//\"/\\\"}; printf '"%s"' "$t"; }

# label_ere <label> -> an extended regex matching the label's line head in either grammar
label_ere() {
    local label=$1
    if [ "$label" = server ]; then
        printf '%s' 'whisper edge: policy: (server: |"server (#[0-9]+|\\".*\\")" \()'
    else
        printf 'whisper edge: policy: (%s: |%s \\()' "$(ere_escape "$label")" "$(ere_escape "$(d32_quote "$label")")"
    fi
}

# g2_lines <log text> <context label>...: each label's line appears exactly once and names a program.
# A grep that finds nothing is an answer here (a count of 0, which fails the row by name), not an
# error, hence the `|| true` on the pipelines under `set -o pipefail`.
g2_lines() {
    local text=$1 label n line ere
    shift
    for label in "$@"; do
        ere=$(label_ere "$label")
        n=$(printf '%s\n' "$text" | grep -cE "$ere" || true)
        line=$(printf '%s\n' "$text" | grep -E "$ere" | head -1 || true)
        if [ "$n" != 1 ]; then
            bad "G2: the configuration-time line for $label appears $n times in one load, not once"
        elif ! [[ $line =~ program\ (\#[0-9]+|[0-9a-f]{16}) ]]; then
            bad "G2: the line for $label names no program: $line"
        else
            ok "G2: $label has its configuration-time line once, naming its program"
        fi
    done
}

# g3_program <log text> <context label> -> the program that label runs: its number or its digest
g3_program() {
    printf '%s\n' "$1" | grep -E "$(label_ere "$2")" | head -1 \
        | sed -n 's/.*program \(#[0-9]*\|[0-9a-f]\{16\}\).*/\1/p' || true
}

# policy_line <log text> <context label> -> that label's first configuration-time line
policy_line() {
    printf '%s\n' "$1" | grep -E "$(label_ere "$2")" | head -1 || true
}

# g3_rows <log text> <server label> <same-a label> <same-b label> <parent label> <child label> <child mode>
# The program-number half of G3: the two same-threshold contexts share one program that is NOT the
# server's; the child with no threshold line runs its parent's program, which is neither the server's
# nor the same-threshold pair's, and its line says it runs it under its own mode.
g3_rows() {
    local load=$1 ps pa pb pp pc cl
    ps=$(g3_program "$load" "$2"); pa=$(g3_program "$load" "$3"); pb=$(g3_program "$load" "$4")
    pp=$(g3_program "$load" "$5"); pc=$(g3_program "$load" "$6")
    if [ -n "$pa" ] && [ "$pa" = "$pb" ] && [ "$pa" != "$ps" ]; then
        ok "G3: the same threshold under two modes is one program (#$pa), not the server's (#$ps)"
    else
        bad "G3: the same threshold under two modes compiled to #$pa and #$pb (the server's is #$ps); one program, not the server's, was expected"
    fi
    cl=$(policy_line "$load" "$6")
    if [ -n "$pp" ] && [ "$pp" = "$pc" ] && [ "$pp" != "$ps" ] && [ "$pp" != "$pa" ] \
            && { [[ $cl == *"no policy lines of its own"*"under its own mode $7"* ]] \
                 || [[ $cl == *"no lines of its own; runs program"*"under mode $7"* ]]; }; then
        ok "G3: a child with no threshold line runs its PARENT's program #$pp (the server's is #$ps) under its own mode $7"
    else
        bad "G3: the child runs #$pc; its parent's is #$pp, the server's #$ps, the pair's #$pa: $cl"
    fi
}

# smaps_field <smaps text of one mapping> <field> -> kB
smaps_field() { printf '%s\n' "$1" | sed -n "s/^$2: *\\([0-9]*\\) kB.*/\\1/p" | head -1; }

# smaps_vma <pid> <hex address> [sudo] -> the smaps lines of the mapping holding that address
smaps_vma() {
    ${3:-} awk -v want="$2" '
        function hexv(s,   i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
        /^[0-9a-f]+-[0-9a-f]+ / { split($1, r, "-"); a = hexv(want); inside = (a >= hexv(r[1]) && a < hexv(r[2])); next }
        inside { print }' "/proc/$1/smaps"
}

# g4_shared <summary line> <pid1> <pid2> [sudo]
g4_shared() {
    local summary=$1 p1=$2 p2=$3 su=${4:-} total regions pid what range lo vma rss shc shd prc prd stack
    total=$(printf '%s' "$summary" | sed -n 's/.* \([0-9]*\) hot bytes in all.*/\1/p')
    if [ -n "$total" ]; then
        ok "G4: the configuration-wide hot-bytes total is printed at configuration time: $total bytes"
    else
        bad "G4: no configuration-wide hot-bytes total in: $summary"
    fi
    # the parser's own control: a worker's stack is private and dirty, and it must say so
    stack=$(${su} awk '/\[stack\]/ { f = 1; next } /^[0-9a-f]+-[0-9a-f]+ / { f = 0 } f' "/proc/$p1/smaps")
    if [ "$(smaps_field "$stack" Private_Dirty)" -gt 0 ] 2>/dev/null; then
        ok "G4: the smaps reader sees a private page where one exists (the worker's stack)"
    else
        bad "G4: the smaps reader saw no private page even in the worker's stack, so it can see nothing"
        return
    fi
    # nginx appends " in <file>:<line>" to a configuration-time line; it is not a region
    regions=$(printf '%s' "$summary" | sed -n '/read-only regions:/{s/.*read-only regions: *//;s/ in [^ ]*:[0-9]*$//;p}')
    [ -n "$regions" ] || { bad "G4: the summary line lists no region: $summary"; return; }
    set -- $regions
    while [ $# -ge 2 ]; do
        what=$1 range=$2
        shift 2
        lo=${range%-*}
        for pid in $p1 $p2; do
            vma=$(smaps_vma "$pid" "$lo" "$su")
            rss=$(smaps_field "$vma" Rss); shc=$(smaps_field "$vma" Shared_Clean); shd=$(smaps_field "$vma" Shared_Dirty)
            prc=$(smaps_field "$vma" Private_Clean); prd=$(smaps_field "$vma" Private_Dirty)
            if [ -z "$rss" ]; then
                bad "G4: worker $pid has no mapping at the $what region $range"
            elif [ "$rss" -gt 0 ] && [ $((prc + prd)) = 0 ] && [ $((shc + shd)) -ge "$rss" ]; then
                ok "G4: worker $pid shares the $what region $range ($rss kB resident, all shared, none private)"
            else
                bad "G4: worker $pid holds a private copy of the $what region $range (Rss $rss, Shared $shc+$shd, Private $prc+$prd kB)"
            fi
        done
    done
}
