#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# apache-gate.sh - run the module inside a real Apache httpd and assert the properties that matter.
#
# The properties are about the policy language on the request path, the lifecycle around it, and the
# default. The most important assertion is still DRY RUN IS THE DEFAULT: with no mode directive at all, a
# request from a listed address must get a 200, and the verdict it would have acted on must be in the
# error log and the notes.
#
# WHAT THIS GATE RUNS, and the reason each part is here:
#
#   - EVERY MPM THE HOST HAS. prefork, worker and event each run the whole lifecycle suite. The threaded
#     MPMs are where a per-thread counter shard, a module thread beside request threads and a stop from a
#     signal handler can go wrong; a gate that only ran prefork would certify the one case that was never
#     at risk.
#   - THE LISTED CLIENT IS JUDGED PAST A HOP. The fixed exemptions exempt every special-purpose address,
#     loopback and the benchmarking space (RFC 2544, 198.18.0.0/15) included, when the floor address is
#     eligible for them. So the gate configures what a CDN deployment configures, WhisperEdgeTrustedHops 2
#     behind a trusted proxy (the loopback peer), and every client arrives as the second entry of an
#     X-Forwarded-For line whose rightmost entry is the balancer's own: judged by the floor and, through
#     mod_remoteip's identical reading, by the context's rules, with no exemption, because an address
#     reached past a hop never gets one. The fixture lists 198.18.0.0/24 (benchmarking space, made for test
#     setups and never routed) at HIGH; 198.18.0.5 is the listed client and 198.18.1.7 the unlisted twin. A
#     request with no header is the loopback peer, exempt, and that is a row of its own.
#   - THE CONFIGURATION TEST. `apache2 -t` compiles every rule, so a refusal fails it with the directive's
#     own file and line: the policy corpus's fifty refusals rendered as httpd.conf, the sections the module
#     refuses by name, the http-only directives, a second definition, the deny statuses, the argument forms.
#   - THE BUILT OBJECT. The decide wrapper is disassembled out of the module's own .so and held to the
#     hot-path gate's checks with the hot-path gate's own patterns and locals parser (extracted from
#     core/hotpath-gate.sh, so there is one copy); a planted call is the control. The keyless and keyed
#     builds are compared byte for byte.
#   - THE FILES. The thread's status, rule-counter and configuration files are read through the real
#     whisper-edge-summary, and the rule counts must move by exactly the requests sent.
#
# THE WORK DIRECTORY IS NOT IN THE REPOSITORY. The module refuses a plane whose directory chain is writable
# by group or world, by design (the writer discipline), and a checkout cloned under umask 002 is exactly
# that. The default is $HOME/.local/state/whisper-edge-gate/apache, created 0755; pass another path as
# $1 or WE_GATE_WORK. The chain is checked before anything starts and the gate says what to fix.
#
# ONE GROUP AT A TIME, for a re-run while a row is being lit: WE_GATE_ONLY="run_outage_rows run_outage_debug_rows run_m10_control_rows"
# runs only the named groups (the run_* names in the run list at the bottom; run_suite stands for the per-MPM
# suites and the floor suite). Such a run prints its gate line as partial, never compares the README's count
# and never says CLEAR, so a selection cannot be mistaken for the walk.
#
# No pipefail: a `producer | grep -q` ends the producer with SIGPIPE at the first match, and under pipefail
# that reads as a miss (the hot-path gate's own lesson, where it turned a relocation check into a silent
# pass). Every producer whose failure matters is checked for its exit code where it runs.
set -u

cd "$(dirname "$0")" || exit 1
# ROOT is the EDGE TREE's own root, one level up from this script, NOT two: two levels up is the parent of
# the clone in the published repository, and `$ROOT/...` then resolves outside the checkout.
ROOT=$(cd .. && pwd)
umask 022
# the work directory is per tree by default (the gate's own path, hashed), so two trees walking on one box never
# share logs, counters or pid files: a rehearsal clone and this tree walked the one default directory at once, and
# the second start read "httpd (pid N) already running" from the first's pid file while the first's copy arms saw
# the second's plane churn (measured: six rows red in one walk, none a defect)
W="${1:-${WE_GATE_WORK:-$HOME/.local/state/whisper-edge-gate/apache-$(printf '%s' "$PWD" | sha256sum | cut -c1-8)}}"
# the gate's fixed port range, its own and clear of the nginx (8098) and LiteSpeed (8120 and up) gates' ranges,
# so the three module gates can walk on one box; every port the rows bind is checked before any row runs, and a
# held one refuses the walk by cause (a 403 or a bind failure from a stranger's listener reads like a module
# defect: measured twice on one night, when 8099 was also another gate's port)
PORT=${PORT:-8160}
port_holder() { # port_holder <port>: who listens there, as far as this user can see
    local who
    who=$(ss -ltnp 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" { print $6 }' | head -1)
    case $who in
        users:*) printf '%s' "$who" | sed 's/users:((//; s/))$//' ;;
        *) printf 'a listener this user cannot name (another user'"'"'s process; ss -ltnp as root shows it)' ;;
    esac
}
for _p in "$PORT" $((PORT + 1)) $((PORT + 2)) $((PORT + 3)); do
    if ss -ltn 2>/dev/null | awk -v p=":$_p" '$4 ~ p"$" { found = 1 } END { exit !found }'; then
        echo "APACHE GATE: REFUSED - port $_p is held by $(port_holder "$_p"); the gate binds $PORT to $((PORT + 3)) and will not share a port with another listener"
        exit 1
    fi
done
_module_given=${MODULE:+yes}   # an object named by MODULE= is the caller's choice; the default is this tree's build
MODULE="${MODULE:-$PWD/.libs/mod_whisper_edge.so}"
export TMPDIR="${TMPDIR:-${XDG_RUNTIME_DIR:-/tmp}}"

HTTPD=$(command -v apache2 || command -v httpd || true)
[ -n "$HTTPD" ] || { echo "APACHE GATE: FAILED - no apache2/httpd on this host"; exit 1; }
if [ ! -f "$MODULE" ]; then
    echo "APACHE GATE: FAILED - no built module at $MODULE. Build it with:"
    echo "    cd $PWD && ./build.sh"
    exit 1
fi
# this tree's own build, when it is older than any source build.sh compiles into it, is refused by name: the gate
# would otherwise walk every row that loads $MODULE against an object built before the change under test (measured:
# two full walks of this tree ran their release rows on an object built before the module's stop fix and three
# rebases of the core, while the debug builds the gate compiles itself carried both)
_stale=""
for _s in mod_whisper_edge.c ../core/whisper_edge.c ../core/we_sha256.c ../core/we_counters.c ../core/we_policy.c \
          ../core/we_module.c ../core/*.h; do
    [ "$_s" -nt "$MODULE" ] && _stale="$_stale ${_s#../}"
done
if [ -n "$_stale" ] && [ -z "$_module_given" ]; then
    echo "APACHE GATE: REFUSED - $MODULE is older than the source it is built from:$_stale"
    echo "    rebuild it: cd $PWD && ./build.sh"
    exit 1
fi
MODDIR=$(cd "$(dirname "$MODULE")" && pwd)
MODULE="$MODDIR/$(basename "$MODULE")"
MODPATH=${APACHE_MODULES:-/usr/lib/apache2/modules}
[ -d "$MODPATH" ] || MODPATH="$("$HTTPD" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p')/modules"
APXS=""
for c in apxs apxs2; do command -v "$c" >/dev/null 2>&1 && { APXS="$c"; break; }; done

# The summary assertions read the REAL tool's output, so build it rather than skip the assertions when it is absent.
SUMMARY_BIN="$ROOT/core/whisper-edge-summary"
# summary_total <counters dir>: the headline's total, read by the headline's own grammar ("  N request(s)
# denied", the line the summary prints first under the window); nothing when the line is not there, so a
# changed headline fails the row that reads it by name, never a number taken from another line
summary_total() { "$SUMMARY_BIN" "$1" 2>/dev/null | sed -n -E 's/^  ([0-9]+) requests? denied$/\1/p'; }
if [ ! -x "$SUMMARY_BIN" ]; then
    make -C "$ROOT/core" whisper-edge-summary >/dev/null \
        || { echo "APACHE GATE: FAILED - cannot build whisper-edge-summary"; exit 1; }
fi

PASS=0; FAILED=0; DARK=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
bad()  { FAILED=$((FAILED+1)); echo "  FAIL  $1"; }
dark() { DARK=$((DARK+1)); echo "  DARK  $1"; }
na()   { echo "  n/a   $1"; }

# ---- the work directory and its chain --------------------------------------------------------------
mkdir -p "$W" || { echo "APACHE GATE: FAILED - cannot create $W"; exit 1; }
W=$(cd "$W" && pwd)
# a work directory another run still holds is refused by cause, like a held port: its pid files name the httpd
for _p in "$W"/httpd-*.pid; do
    [ -f "$_p" ] || continue
    _pid=$(cat "$_p" 2>/dev/null)
    if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
        echo "APACHE GATE: REFUSED - the work directory $W is held by a running httpd (pid $_pid, $(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null | cut -c1-120)); another gate run owns it, so pass WE_GATE_WORK=<a directory of this run's own>"
        exit 1
    fi
done
chain_ok() { # <path> -> every directory of the resolved path owned by root or us, writable by neither group nor world
    local p
    p=$(realpath "$1")
    while :; do
        local mode owner
        mode=$(stat -c '%a' "$p"); owner=$(stat -c '%u' "$p")
        if [ "$owner" != 0 ] && [ "$owner" != "$(id -u)" ]; then echo "$p is owned by uid $owner"; return 1; fi
        if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then echo "$p is mode $mode, writable by group or world"; return 1; fi
        [ "$p" = / ] && return 0
        p=$(dirname "$p")
    done
}
if ! why=$(chain_ok "$W"); then
    echo "APACHE GATE: FAILED - the work directory's chain is not one the module trusts: $why"
    echo "    the module refuses a plane under a directory writable by group or world (the writer discipline);"
    echo "    chmod g-w,o-w that directory, or pass a work directory under a clean chain (WE_GATE_WORK=...)"
    exit 1
fi

# THE GENERATION MUST ONLY EVER GO UP, across every suite in this run: the loader refuses a snapshot whose
# generation is not newer than the one in use (a rollback is a silent policy downgrade).
GEN=0
# the listed range: 198.18.0.0/24, benchmarking space (RFC 2544), at HIGH; the fixture's one IPv4 range
RANGE_START=3323068416; RANGE_END=3323068671
LISTED=198.18.0.5; UNLISTED=198.18.1.7; HOP=198.19.0.1
fresh_snapshot() { # fresh_snapshot [valid_until_ms] [severity]
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.bin" "$GEN" "${1:-0}" "${2:-3}" "$RANGE_START" "$RANGE_END"
}
EVIDENCE=$(python3 "$ROOT/core/make-test-snapshot.py" --evidence)

# the client: X-Forwarded-For "<client>, <hop>", judged at hop 2; hdr prints the header for curl
xff() { printf 'X-Forwarded-For: %s, %s' "$1" "$HOP"; }
code()   { curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$2")" "http://127.0.0.1:$PORT$1" 2>/dev/null; }
code_nohdr() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$PORT$1" 2>/dev/null; }
body()   { curl -s --max-time 8 -H "$(xff "$2")" "http://127.0.0.1:$PORT$1" 2>/dev/null; }
headers(){ curl -s -o /dev/null -D - --max-time 8 -H "$(xff "$2")" "http://127.0.0.1:$PORT$1" 2>/dev/null; }
await() { # await <test> <seconds> <what>
    local i=0
    while [ $i -lt $((${2} * 4)) ]; do eval "$1" && return 0; sleep 0.25; i=$((i+1)); done
    return 1
}
# the last access line, read only once the request before it has been logged: httpd writes the line in its
# log_transaction phase, after the response has gone, so a read straight after curl returned could take the
# line before (measured: the h2 raw-peer arm read the previous request's 10.20.30.40). Every curl the gate runs
# notes the log's line count first, and the read waits up to 3 s for the count to pass it
curl() {
    if [ -d "$W/logs" ]; then
        { [ -f "$W/logs/access.log" ] && wc -l < "$W/logs/access.log" || echo 0; } > "$W/logs/.la_before" 2>/dev/null
    fi
    command curl "$@"
}
last_access() {
    local b i=0
    b=$(cat "$W/logs/.la_before" 2>/dev/null)
    while [ "$i" -lt 60 ] && [ "$(wc -l < "$W/logs/access.log" 2>/dev/null || echo 0)" -le "${b:-0}" ]; do
        sleep 0.05; i=$((i + 1))
    done
    tail -1 "$W/logs/access.log" 2>/dev/null
}
# a control fails by value, never by a crash: after a control arm's server stops, no child of it exited on a signal
# (one the arm causes on purpose is named as allowed) and nothing in its logs is a sanitizer's report
ctl_exit_clean() { # ctl_exit_clean <label> [allowed signal pattern]
    local sigs san
    sigs=$(cat "$W/logs/error.log" 2>/dev/null | grep 'exit signal' | { if [ -n "${2:-}" ]; then grep -vE "$2"; else cat; fi; } | grep -c . || true)
    san=$(cat "$W/logs/error.log" "$W"/start-*.err 2>/dev/null | grep -cE 'ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:|ThreadSanitizer' || true)
    if [ "${sigs:-0}" = 0 ] && [ "${san:-0}" = 0 ]; then
        ok "$1 exited normally: no child on a signal${2:+ other than the one the arm causes}, no sanitizer report"
    else
        bad "$1: $sigs child exit(s) on a signal${2:+ other than the one the arm causes}, $san sanitizer line(s): $(grep -hE 'exit signal|Sanitizer|runtime error:' "$W/logs/error.log" "$W"/start-*.err 2>/dev/null | sed -n 1p | cut -c1-160)"
    fi
}
field() { # field <access line> <key> -> the value of key=... in the gate's access-log format (a value may hold spaces)
    printf '%s\n' "$1" | sed -n "s/.* $2=//p" | sed -E 's/ [a-z]+=.*$//'
}

# ---- the module set this httpd needs, resolved rather than assumed ------------------------------
BUILTIN=$("$HTTPD" -l 2>/dev/null)
need_mod() { # need_mod <module-name> <file.so>
    case "$BUILTIN" in
        *"$(echo "$2" | sed 's/\.so$/.c/')"*) echo "# $2 is compiled in" ; return ;;
    esac
    if [ -f "$MODPATH/$2" ]; then echo "LoadModule $1 $MODPATH/$2"; else echo "#missing $2"; fi
}

# the access-log format every suite reads: the request's decision as the module exported it
LOGFMT='LogFormat "%h %>s action=%{WHISPER_EDGE_ACTION}n rule=%{WHISPER_EDGE_RULE_ID}n verdict=%{WHISPER_EDGE_VERDICT}n floor=%{WHISPER_EDGE_FLOOR_ADDR}n gen=%{WHISPER_EDGE_GENERATIONS}n program=%{WHISPER_EDGE_PROGRAM}n reason=%{WHISPER_EDGE_REASON}n listed=%{WHISPER_EDGE_LISTED}n logged=%{WHISPER_EDGE_LOGGED}n" whisperfmt'

# the MPM's children, pinned: two processes that never come or go, so a child exiting between two reads of the
# counter files cannot write its final counts late, which no barrier over the live children could see
PINNED_CHILDREN=2
children_turned_over() { # children_turned_over "<old pids>": none of them is a child now, and exactly the pinned count are
    local now k
    now=$(pgrep -P "${HTTPD_PID:-0}" 2>/dev/null | sort | tr '\n' ' ')
    [ "$(printf '%s' "$now" | wc -w)" = "$PINNED_CHILDREN" ] || return 1
    for k in $1; do
        case " $now " in *" $k "*) return 1 ;; esac
    done
    return 0
}
mpm_sizing() {
    case "$1" in
        prefork) printf 'StartServers 2\nMinSpareServers 2\nMaxSpareServers 2\nMaxRequestWorkers 2\nMaxConnectionsPerChild 0\n' ;;
        *) printf 'ServerLimit 2\nStartServers 2\nThreadsPerChild 16\nMinSpareThreads 32\nMaxSpareThreads 32\nMaxRequestWorkers 32\nMaxConnectionsPerChild 0\n' ;;
    esac
}

# conf_head <mpm> <conf path> [extra module lines]: the common preamble of every configuration this gate writes
conf_head() {
    local MPM=$1
    cat <<CONF
ServerName 127.0.0.1
ServerRoot $W
PidFile $W/httpd-$MPM.pid
Listen 127.0.0.1:$PORT
DocumentRoot $W/html
ErrorLog $W/logs/error.log
LogLevel info
$(need_mod mpm_${MPM}_module mod_mpm_${MPM}.so)
$(mpm_sizing "$MPM")
$(need_mod authz_core_module mod_authz_core.so)
$(need_mod unixd_module mod_unixd.so)
$(need_mod mime_module mod_mime.so)
TypesConfig /etc/mime.types
$(need_mod dir_module mod_dir.so)
$(need_mod log_config_module mod_log_config.so)
$(need_mod remoteip_module mod_remoteip.so)
LoadModule whisper_edge_module $MODULE
$LOGFMT
CustomLog $W/logs/access.log whisperfmt
# the balancer's reading, for the context's address: mod_remoteip takes the same entry the module's walk takes
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 127.0.0.1
RemoteIPTrustedProxy $HOP
<Directory $W/html>
    Require all granted
</Directory>
CONF
}

# the one data directive set, shared by the lifecycle suites
conf_data() {
    cat <<CONF
WhisperEdgeSnapshot $W/snapshot.bin
WhisperEdgeRefresh 10
WhisperEdgeTrustedProxy 127.0.0.1
WhisperEdgeTrustedHeader X-Forwarded-For
WhisperEdgeTrustedHops 2
CONF
}

# the lifecycle suite's contexts: the default at the server (log), a deny location, an exempt one, the
# policy rows' contexts (one threshold as sugar beside the same rule written out, under two modes; a
# parent at medium whose child writes no line of its own), and the floor, which the http level runs under log
conf_contexts() {
    cat <<'CONF'
WhisperEdgePolicyFloor "deny if listed >= critical"
<Location /enforced>
    WhisperEdgeMode deny
</Location>
<Location /exempt>
    WhisperEdgeMode off
</Location>
<Location /g3a>
    WhisperEdgeThreshold low
    WhisperEdgeMode log
</Location>
<Location /g3b>
    whisper_edge_policy  deny   if listed   >=  low
    WhisperEdgeMode deny
</Location>
<Location /g3p>
    WhisperEdgePolicy "deny if listed >= medium"
    WhisperEdgeMode deny
</Location>
<Location /g3p/c>
    WhisperEdgeMode log
</Location>
<Location /legal>
    WhisperEdgeMode deny
    WhisperEdgeDenyStatus 451
</Location>
CONF
}

start_httpd() { # start_httpd <conf> <mpm> -> 0 when serving
    rm -rf "$W/logs"; mkdir -p "$W/logs"
    "$HTTPD" -f "$1" -k start 2>"$W/start-$2.err"
    await "[ \"\$(code_nohdr /)\" != 000 ]" 10 "httpd up" || return 1
    HTTPD_PID=$(cat "$W/httpd-$2.pid" 2>/dev/null)
    return 0
}
stop_httpd() { # stop_httpd <conf> <mpm>: the pid file's process, never a pattern over every process
    local pid
    pid=$(cat "$W/httpd-$2.pid" 2>/dev/null)
    timeout 20 "$HTTPD" -f "$1" -k stop >/dev/null 2>&1
    if ! await "[ ! -f \"$W/httpd-$2.pid\" ]" 15 "stopped"; then
        [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
        return 1
    fi
    return 0
}
cfg_lines() { # the configuration-time lines of the LAST load in the error log (httpd logs them once per start)
    grep 'whisper edge: policy: ' "$W/logs/error.log" | awk '{ buf = buf $0 "\n" } /read-only regions:/ { last = buf; buf = "" } END { printf "%s", last }'
}
ctx_digest() { # ctx_digest <config lines> <human name|floor> -> the program digest of that context's line
    printf '%s\n' "$1" | grep -E "whisper edge: policy: $2( \(|:)" | head -1 | sed -n 's/.*program \([0-9a-f]\{16\}\).*/\1/p'
}
rule_count() { # rule_count <digest> <rule> -> the summed count the real tool prints, 0 when absent
    local n
    n=$("$SUMMARY_BIN" --rules "$W/counters" 2>/dev/null | awk -v d="$1" -v r="$2" '$1 == "r" && $2 == d && $3 == r { print $4 }')
    echo "${n:-0}"
}
HTTPD_PID=""   # the running httpd's parent, set by start_httpd: the barrier covers every child it has
tick_of() { # the smallest tick over every live child's rule-counter file; empty while a child has no file yet
    local f pid t min="" kids k
    kids=$(pgrep -P "${HTTPD_PID:-0}" 2>/dev/null)
    [ -n "$kids" ] || { echo ""; return; }
    for k in $kids; do
        set -- "$W"/counters/"$k"-*.rules.cnt 2>/dev/null
        f=${1-}
        [ -f "$f" ] || { echo ""; return; }    # a child with no file yet: the barrier is not met
        t=$(sed -n 's/^tick \([0-9]*\)$/\1/p' "$f")
        [ -n "$t" ] || { echo ""; return; }
        [ -z "$min" ] || [ "$t" -lt "$min" ] && min=$t
    done
    echo "$min"
}
await_first_tick() { # until every live writer has a counter file with a tick (the start barrier; a bare wait)
    await "m=\$(tick_of); [ -n \"\$m\" ]" 40 "the first tick"
}
# the per-child barrier: every live child's file carries a tick above the one it shows at the call. A load
# that completed before the call is wholly inside each child's next tick; the min-based barrier above can
# return on a child whose tick landed mid-load (measured: a 128-request burst read as 0 counted once)
tick_each_above() { # tick_each_above "<pid:tick ...>": every named child's file now carries a tick above the one given
    local e k t f
    for e in $1; do
        k=${e%%:*}; t=${e#*:}
        set -- "$W"/counters/"$k"-*.rules.cnt
        f=${1-}
        [ -f "$f" ] || return 1
        [ "$(sed -n 's/^tick \([0-9]*\)$/\1/p' "$f")" -gt "$t" ] 2>/dev/null || return 1
    done
    return 0
}
await_next_tick() {
    local k t f spec=""
    for k in $(pgrep -P "${HTTPD_PID:-0}" 2>/dev/null); do
        set -- "$W"/counters/"$k"-*.rules.cnt
        f=${1-}
        t=$(sed -n 's/^tick \([0-9]*\)$/\1/p' "$f" 2>/dev/null)
        spec="$spec $k:${t:--1}"
    done
    [ -n "$spec" ] || return 1
    await "tick_each_above \"$spec\"" 40 "every child's next tick"
}
plane_pids() { # plane_pids <fixed text>: the number of distinct CHILDREN that logged a plane-transition line; the parent's
    # monitor logs the same lines (measured at a merge rehearsal: a two-child barrier released on the parent plus one
    # child, and the slow child ended disarmed at generation 0 in eleven lifecycle rows), so its pid is left out
    grep -F -- "$1" "$W/logs/error.log" 2>/dev/null | sed -n 's/.*\[pid \([0-9]*\).*/\1/p' | grep -vx -- "${HTTPD_PID:-0}" | sort -u | wc -l
}
await_plane() { # await_plane <fixed text> <n>: until n distinct children logged it (a child's tick straddling the
    # file event satisfies a one-tick barrier without observing it, so the awaited fact is the per-child line)
    local pat=$1 n=$2
    await "[ \"\$(plane_pids \"\$pat\")\" -ge \"\$n\" ]" 40 "every child's line"
}

# =====================================================================================================
# THE LIFECYCLE SUITE, once per MPM
# =====================================================================================================
run_suite() { # run_suite <mpm>
    local MPM="$1"
    local conf="$W/httpd-$MPM.conf"
    local line d_default d_g3a d_g3b d_g3p d_g3pc d_floor n0 n1

    rm -rf "$W/html" "$W/counters"
    mkdir -p "$W/html/enforced" "$W/html/exempt" "$W/html/g3a" "$W/html/g3b" "$W/html/g3p/c" "$W/html/legal"
    fresh_snapshot
    cp "$W/snapshot.bin" "$W/snapshot.good"
    for d in . enforced exempt g3a g3b g3p g3p/c legal; do echo "page" > "$W/html/$d/index.html"; done
    { conf_head "$MPM"; conf_data; conf_contexts; } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "$MPM: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "$MPM: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-400)"
        return
    fi
    echo "  [$MPM, pid $(cat "$W/httpd-$MPM.pid" 2>/dev/null)]"

    # ---- 1. THE PROMISE THE PRODUCT RESTS ON ---------------------------------------------------------
    [ "$(code / "$LISTED")" = 200 ] \
        && ok "$MPM: no mode directive + a listed client past the hop -> 200 (the default is log)" \
        || bad "$MPM: a listed client was blocked with no mode directive: $(code / "$LISTED")"
    line=$(last_access)
    [ "$(field "$line" action)" = would-deny ] && [ "$(field "$line" verdict)" = high ] \
        && ok "$MPM: and the notes say so: action=would-deny verdict=high in the access log" \
        || bad "$MPM: the notes do not carry the dry run: $line"
    await 'grep -q "WOULD DENY" "$W/logs/error.log"' 8 "would-deny" \
        && ok "$MPM: and the would-deny line is written, so log mode is not silent" \
        || bad "$MPM: no WOULD DENY line: the default mode says nothing, which is useless"
    grep -q "evidence $EVIDENCE" "$W/logs/error.log" \
        && ok "$MPM: and it carries the CITABLE EVIDENCE, not just a severity" \
        || bad "$MPM: the log line carries no evidence: $(grep 'WOULD DENY' "$W/logs/error.log" | tail -1)"
    grep -q "WOULD DENY $LISTED: rule - (-), program floor:[0-9a-f]\{16\} ctx:[0-9a-f]\{16\}, verdict high" "$W/logs/error.log" \
        && ok "$MPM: the line names the judged address, the rule and both program digests" \
        || bad "$MPM: the would-deny line is not in the documented shape: $(grep 'WOULD DENY' "$W/logs/error.log" | tail -1 | cut -c60-)"
    [ "$(field "$line" floor)" = "$LISTED" ] \
        && ok "$MPM: WHISPER_EDGE_FLOOR_ADDR is the entry judged at hop 2, $LISTED" \
        || bad "$MPM: the floor address is $(field "$line" floor), not $LISTED"
    case "$(field "$line" gen)" in
        reputation:$GEN.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\ tenant:-a)
            ok "$MPM: WHISPER_EDGE_GENERATIONS names the plane's generation and digest prefix, and the unbound tenant plane as -a" ;;
        *) bad "$MPM: the generations token is $(field "$line" gen)" ;;
    esac
    [ "$(field "$line" logged)" = "ctx:1" ] \
        && ok "$MPM: WHISPER_EDGE_LOGGED lists the default policy's rule ctx:1, fired as a downgraded deny beside the pre-stage's verdict" \
        || bad "$MPM: the logged note reads $(field "$line" logged), not the fired default rule ctx:1"

    # ---- 2. the unlisted twin and the exempt peer ----------------------------------------------------
    [ "$(code / "$UNLISTED")" = 200 ] && [ "$(field "$(last_access)" action)" = allow ] && [ "$(field "$(last_access)" verdict)" = none ] \
        && ok "$MPM: the unlisted twin is allowed, verdict none (never a bare -)" \
        || bad "$MPM: the unlisted twin: $(last_access)"
    [ "$(field "$(last_access)" logged)" = "-" ] \
        && ok "$MPM: and the twin's WHISPER_EDGE_LOGGED is the documented dash: no rule fired on the allow" \
        || bad "$MPM: the twin's logged note reads $(field "$(last_access)" logged), not the dash"
    [ "$(code_nohdr /)" = 200 ] && [ "$(field "$(last_access)" reason)" = "hold-harmless,floor-header-missing" ] \
        && ok "$MPM: a request with no header is the loopback peer: exempt by hold-harmless, and the missing header is marked" \
        || bad "$MPM: the loopback peer with no header: $(last_access)"
    [ "$(field "$(last_access)" floor)" = 127.0.0.1 ] \
        && ok "$MPM: and its floor address is the TCP peer" \
        || bad "$MPM: the peer's floor address reads $(field "$(last_access)" floor)"

    # ---- 3. deny where asked, and nowhere else -------------------------------------------------------
    [ "$(code /enforced/ "$LISTED")" = 403 ] \
        && ok "$MPM: a <Location> that says deny DOES block -> 403" \
        || bad "$MPM: WhisperEdgeMode deny did not block: $(code /enforced/ "$LISTED")"
    grep -qi '^Cache-Control: no-store' <<<"$(headers /enforced/ "$LISTED")" \
        && ok "$MPM: and the deny carries Cache-Control: no-store" \
        || bad "$MPM: the deny response carries no Cache-Control: no-store"
    grep -q '<title>403 Forbidden</title>' <<<"$(body /enforced/ "$LISTED")" \
        && ok "$MPM: a context-rule deny keeps the server's own error page (class built-in)" \
        || bad "$MPM: the context-rule deny body is not httpd's 403 page"
    [ "$(code /enforced/ "$UNLISTED")" = 200 ] \
        && ok "$MPM: and the unlisted twin passes the same location" \
        || bad "$MPM: the unlisted twin was denied in /enforced: $(code /enforced/ "$UNLISTED")"
    [ "$(code /exempt/ "$LISTED")" = 200 ] && [ "$(field "$(last_access)" program)" = "floor:$(ctx_digest "$(cfg_lines)" floor | cut -c1-16) ctx:-" ] \
        && ok "$MPM: a <Location> that says off is EXEMPT -> 200, and the floor still ran (program floor:<d16> ctx:-)" \
        || bad "$MPM: WhisperEdgeMode off: $(code /exempt/ "$LISTED") $(last_access)"
    [ "$(code /legal/ "$LISTED")" = 451 ] && grep -qi '^Cache-Control: no-store' <<<"$(headers /legal/ "$LISTED")" \
        && ok "$MPM: WhisperEdgeDenyStatus 451 is the status on the wire, with no-store" \
        || bad "$MPM: the configured deny status: $(code /legal/ "$LISTED")"

    # ---- 4. the configuration-time lines: digests, sugar, inheritance (G1+, G2+, G3+) -------------------
    local LOAD
    LOAD=$(cfg_lines)
    for label in 'server "127.0.0.1"' 'location "/enforced"' 'location "/exempt"' 'location "/g3a"' 'location "/g3b"' 'location "/g3p"' 'location "/g3p/c"' 'location "/legal"'; do
        n0=$(printf '%s\n' "$LOAD" | grep -cF "whisper edge: policy: $label (" || true)
        [ "$n0" = 1 ] \
            && ok "$MPM: G2+: $label has its configuration-time line once, with its file and line" \
            || bad "$MPM: G2+: the line for $label appears $n0 times in one load"
    done
    d_default=$(ctx_digest "$LOAD" 'server "127.0.0.1"'); d_g3a=$(ctx_digest "$LOAD" 'location "/g3a"'); d_g3b=$(ctx_digest "$LOAD" 'location "/g3b"')
    d_g3p=$(ctx_digest "$LOAD" 'location "/g3p"'); d_g3pc=$(ctx_digest "$LOAD" 'location "/g3p/c"')
    [ -n "$d_g3a" ] && [ "$d_g3a" = "$d_g3b" ] && [ "$d_g3a" != "$d_default" ] \
        && ok "$MPM: G1+: WhisperEdgeThreshold low and the rule written out compile to ONE digest ($d_g3a), not the server's ($d_default)" \
        || bad "$MPM: G1+: the sugar and the rule differ: $d_g3a vs $d_g3b (server $d_default)"
    [ -n "$d_g3p" ] && [ "$d_g3p" = "$d_g3pc" ] && [ "$d_g3p" != "$d_default" ] \
        && grep -q 'no lines of its own; runs program '"$d_g3p"' under mode log' <<<"$(printf '%s\n' "$LOAD" | grep -F 'location "/g3p/c" (')" \
        && ok "$MPM: G3+: a child with no lines runs its PARENT's program $d_g3p under its own mode log" \
        || bad "$MPM: G3+: the child: $(printf '%s\n' "$LOAD" | grep -F 'location "/g3p/c" (' | cut -c60-)"
    [ "$(code /g3a/ "$LISTED")" = 200 ] && [ "$(code /g3b/ "$LISTED")" = 403 ] \
        && ok "$MPM: G3+: the two sections' own modes give different verdicts (200 under log, 403 under deny)" \
        || bad "$MPM: G3+: the shared program's sections answered $(code /g3a/ "$LISTED") and $(code /g3b/ "$LISTED")"
    code /g3a/ "$LISTED" >/dev/null; line=$(last_access)
    [ "$(field "$line" logged)" = "ctx:1" ] \
        && ok "$MPM: WHISPER_EDGE_LOGGED names the fired rule ctx:1 on the log-mode would-deny, its one pool string" \
        || bad "$MPM: the log-mode would-deny's logged note reads $(field "$line" logged), not ctx:1"
    code /g3b/ "$LISTED" >/dev/null; line=$(last_access)
    [ "$(field "$line" logged)" = "-" ] \
        && ok "$MPM: and the enforced twin's 403 is no log entry: the logged note stays the dash (only log rules and downgraded denies are listed)" \
        || bad "$MPM: the enforced deny's logged note reads $(field "$line" logged), not the dash"
    [ "$(code /g3p/ "$LISTED")" = 403 ] && [ "$(code /g3p/c/ "$LISTED")" = 200 ] \
        && ok "$MPM: G3+: the parent denies (403) while the child only logs (200)" \
        || bad "$MPM: G3+: parent and child answered $(code /g3p/ "$LISTED") and $(code /g3p/c/ "$LISTED")"
    grep -q 'floor: 1 rule, program [0-9a-f]\{16\}, mode log and deny status 403 from the http level' <<<"$LOAD" \
        && ok "$MPM: floor conf: the floor line names its program, and the mode and deny status it takes from the http level" \
        || bad "$MPM: no floor line: $(printf '%s\n' "$LOAD" | grep -F 'floor' | head -1 | cut -c60-)"
    grep -q 'the floor will not deny: its mode is the http level.s (log); add "WhisperEdgeMode deny" at http level' <<<"$LOAD" \
        && ok "$MPM: floor mode: with mode deny only in contexts, the configuration test says the floor will not deny, with the fix" \
        || bad "$MPM: floor mode: the will-not-deny line is missing"
    d_floor=$(ctx_digest "$LOAD" floor)
    [ "$(field "$(last_access)" program)" = "floor:$d_floor ctx:$d_g3p" ] \
        && ok "$MPM: program note: WHISPER_EDGE_PROGRAM names both blocks, floor:$d_floor ctx:$d_g3p" \
        || bad "$MPM: the program note reads $(field "$(last_access)" program)"

    # ---- 5. the counters, through the real tool, by exactly the requests sent -------------------------
    await "ls \"$W\"/counters/*.status >/dev/null 2>&1" 25 "a status file" \
        && ok "$MPM: the thread wrote the status file before the first tick, under $W/counters" \
        || bad "$MPM: no status file in $W/counters after 25 s"
    "$SUMMARY_BIN" --status "$W/counters" >"$W/status.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && grep -q "plane reputation armed generation $GEN digest" "$W/status.out" \
        && ok "$MPM: whisper-edge-summary --status exits 0 with the reputation plane armed at generation $GEN" \
        || bad "$MPM: --status exit $rc: $(tr '\n' '|' < "$W/status.out" | cut -c1-300)"
    # the rule counts are attributed through the configuration file, which a worker renames into place
    # only after its rules file, inside the same tick: a barrier over the ticks alone can pass while that
    # first write is still in flight and read a directory with no mapping yet (the tool prints no rule
    # lines, so the count reads as 0), so the file is awaited first, and only then the tick. The barrier
    # is per child: every child's next tick after the call, so a denial a child served before the call
    # is in its file before the baseline is read. The min-tick barrier it replaces returned when the
    # lagging child advanced while the other's file predated its own share, and under worker a baseline
    # read that way missed two held denials and read a delta of eight for six (forced with SIGSTOP on
    # one child, measured; the per-child barrier read six under the same forcing)
    await "ls \"$W\"/counters/conf-*.status >/dev/null 2>&1" 25 "the configuration file" \
        && ok "$MPM: the configuration file conf-<16 hex>.status was written once by a worker" \
        || bad "$MPM: no conf-<16 hex>.status in $W/counters after 25 s"
    await_next_tick
    n0=$(rule_count "$d_g3p" 1)
    for i in 1 2 3 4 5 6; do code /g3p/ "$LISTED" >/dev/null; done
    await_next_tick
    n1=$(rule_count "$d_g3p" 1)
    [ "$n1" = "$((n0 + 6))" ] \
        && ok "$MPM: six denied requests move rule 1 of $d_g3p by exactly six ($n0 -> $n1), read through --rules across the tick barrier" \
        || bad "$MPM: the per-rule count moved $n0 -> $n1 for six denied requests"
    grep -q "^r $d_g3p 1 [0-9]* \"deny if listed >= medium\"" <<<"$("$SUMMARY_BIN" --rules "$W/counters")" \
        && ok "$MPM: and --rules joins the count to the rule's canonical text through the configuration file" \
        || bad "$MPM: --rules does not print the rule text: $("$SUMMARY_BIN" --rules "$W/counters" | head -3 | tr '\n' '|')"
    n0=$(rule_count "$d_g3p" 1)
    for i in 1 2; do code /g3p/ "$UNLISTED" >/dev/null; code_nohdr /g3p/ >/dev/null; done
    await_next_tick
    [ "$(rule_count "$d_g3p" 1)" = "$n0" ] \
        && ok "$MPM: the unlisted twin and the exempt peer move no rule counter (the default allow writes nothing)" \
        || bad "$MPM: the counter moved for requests that fired no rule: $n0 -> $(rule_count "$d_g3p" 1)"

    # ---- 5b. the per-range count in log mode, after every exact count above ----------------------------
    # the per-range count in log mode, the same traffic as the nginx and OpenLiteSpeed gates' row: five requests
    # from the listed client under the server's default mode (log), each answered, and the summary's headline
    # total risen by exactly five, because a would-deny is counted on every server (the core's contract counts
    # after the verdict, on the path that writes the log line)
    lc_total() { summary_total "$W/counters"; }
    # BEFORE only once two reads a tick apart agree: every process writes its own counts on its own tick, so a
    # read taken while an earlier count is still in flight would make "before + 5" the wrong target
    lc_before=$(lc_total); for _ in 1 2 3 4 5; do sleep 11; lc_now=$(lc_total); [ "$lc_now" = "$lc_before" ] && break; lc_before=$lc_now; done
    lc_codes=""
    for i in 1 2 3 4 5; do lc_codes="$lc_codes$(code "/index.html?lc=$i" "$LISTED")"; done
    lc_expired=no
    await '[ "$(lc_total)" = "$(( ${lc_before:-0} + 5 ))" ]' 60 "the five would-denies counted" || lc_expired=yes   # a ceiling for a hang
    lc_after=$(lc_total)
    [ "$lc_codes" = "200200200200200" ] && [ "$(( ${lc_after:-0} - ${lc_before:-0} ))" = 5 ] \
        && ok "$MPM: log-mode count: 5 would-denies from the listed client (each answered 200) raise the summary's total by 5 ($lc_before to $lc_after), the same traffic and number as on nginx and OpenLiteSpeed" \
        || bad "$MPM: log-mode count: 5 requests from the listed client answered $lc_codes, and the summary's total went from \"${lc_before:-none}\" to \"${lc_after:-none}\"$([ "$lc_expired" = yes ] && echo " (the wait reached its 60 s ceiling)")"

    # ---- 6. the pages are shared after fork (G4+) ------------------------------------------------------
    local kids
    kids=$(pgrep -P "$(cat "$W/httpd-$MPM.pid")" 2>/dev/null | sort | tr '\n' ' ')
    # shellcheck disable=SC2086
    set -- $kids
    if [ $# -ge 2 ]; then
        g4_shared "$(printf '%s\n' "$LOAD" | grep 'read-only regions:' | tail -1)" "$1" "$2"
    else
        bad "$MPM: G4+: two child processes are needed to show the pages are shared, and $# is running"
    fi

    # ---- 7. the lifecycle: graceful restart must turn children over and not hang --------------------
    timeout 20 "$HTTPD" -f "$conf" -k graceful
    if [ $? -ne 0 ]; then
        bad "$MPM: graceful restart did not return within 20s (a child that will not exit)"
    else
        ok "$MPM: graceful restart returned (the module thread's stop does not hold shutdown)"
    fi
    await "[ \"\$(code /enforced/ $LISTED)\" = 403 ]" 10 "serving again" \
        && ok "$MPM: and it still serves, and still enforces, after the graceful" \
        || bad "$MPM: not serving correctly after a graceful restart: $(code /enforced/ "$LISTED")"
    # the turnover: the pre-graceful children finish and exit on their own time (a worker child lingered 20 s
    # once), and the parent refills to the pinned count; the inode rows below count over a steady set
    await "children_turned_over \"$kids\"" 40 "the old children gone and $PINNED_CHILDREN new ones" \
        && ok "$MPM: the pre-graceful children ($kids) exited and the parent runs $PINNED_CHILDREN new ones" \
        || bad "$MPM: 40 s after the graceful the children are still turning over: before $kids, now $(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')"
    # the line names where the thread was (its stage), which says whether the stop's bound or the thread is at fault
    grep -q 'the module thread did not stop' "$W/logs/error.log" \
        && bad "$MPM: a child abandoned its module thread at the graceful: $(grep 'the module thread did not stop' "$W/logs/error.log" | sed -n 's/.*\(pid [0-9]*\):.*(the thread was in: \(.*\))$/\1 in \2/p' | tr '\n' ';' | cut -c1-200)" \
        || ok "$MPM: no child abandoned its module thread at the graceful (the stop finished inside its deadline)"

    # ---- 8. an in-place rewrite of the legacy snapshot: no child dies, and the core's inode rule runs in each ----
    # The module holds a private copy, so the truncate kills nobody. The thread's next tick finds the armed inode
    # changed (size or mtime) and disarms the plane at once, logged; the tick after re-digests the file and, the
    # bytes being the arm-time ones, re-arms it. Both are awaited per child (a child whose tick straddled the
    # rewrite satisfies a one-tick barrier without observing it), never read through a request, which the
    # kernel hands to whichever child accepts.
    local kids_before kids_after nkids good_gen dis_pat rearm_pat fin_pat arm_pat gone_pat old_pat
    good_gen=$GEN
    kids_before=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
    nkids=$(printf '%s' "$kids_before" | wc -w)
    dis_pat='plane snapshot.bin disarmed: the armed file was rewritten in place (its size or mtime changed)'
    rearm_pat='plane snapshot.bin re-armed: its bytes still carry the arm-time digest'
    : > "$W/snapshot.bin"                     # O_TRUNC, which is what curl -o and cp do
    sleep 0.3
    cat "$W/snapshot.good" > "$W/snapshot.bin"; chmod 0644 "$W/snapshot.bin"
    [ "$(code / "$LISTED")" = 200 ] \
        && ok "$MPM: traffic flows right after an in-place truncate-and-rewrite of the legacy snapshot" \
        || bad "$MPM: traffic stopped after an in-place rewrite: $(code / "$LISTED")"
    if await_plane "$dis_pat" "$nkids"; then
        ok "$MPM: at its next tick each of the $nkids children disarmed the plane: the armed file was rewritten in place"
    else
        bad "$MPM: only $(plane_pids "$dis_pat") of $nkids children logged the disarm after 40 s"
    fi
    if await_plane "$rearm_pat" "$nkids" && [ "$(code /enforced/ "$LISTED")" = 403 ]; then
        ok "$MPM: at the tick after, each child re-digested the file, found the arm-time bytes and re-armed: /enforced/ denies again"
    else
        bad "$MPM: $(plane_pids "$rearm_pat") of $nkids children re-armed; /enforced/ $(code /enforced/ "$LISTED")"
    fi
    kids_after=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
    [ "$kids_after" = "$kids_before" ] && ! grep -q 'exit signal' "$W/logs/error.log" \
        && ok "$MPM: the same $nkids children are alive through it; none exited on a signal" \
        || bad "$MPM: children changed over the rewrite (before: $kids_before after: $kids_after) or one exited on a signal"

    # ---- 8b. the same inode rewritten with OTHER bytes: the final disarm, fail-open until a newer generation ------
    fin_pat="plane snapshot.bin disarmed: final: generation $GEN is committed; a reload or generation $((GEN + 1)) re-arms"
    cat "$W/snapshot.good" > "$W/snapshot.bin"; printf 'x' >> "$W/snapshot.bin"; chmod 0644 "$W/snapshot.bin"
    # the thread folds the writer's answer into its state word at its NEXT tick's start, so the word settles
    # one tick after the transition's own line (measured: the child that had just logged `re-armed` still
    # wrote `disarmed` on that same tick's status file). --status is polled for the final disarm's word,
    # never read off the re-arm's one-tick lag.
    if await_plane "$fin_pat" "$nkids" \
        && await '"$SUMMARY_BIN" --status "$W/counters" >"$W/status.out" 2>&1; rc=$?; [ "$rc" = 1 ]' 15 "the disarmed status word" \
        && [ "$(code /enforced/ "$LISTED")$(code /enforced/ "$LISTED")$(code /enforced/ "$LISTED")$(code /enforced/ "$LISTED")" = 200200200200 ] \
        && [ "$(field "$(last_access)" verdict)" = "unknown,disarmed" ] \
        && [ "$(field "$(last_access)" gen)" = "reputation:-d tenant:-a" ]; then
        ok "$MPM: the same inode rewritten with other bytes: the re-digest fails and each child disarms for good (final: generation $GEN is committed); requests fail open as unknown,disarmed with reputation:-d, and --status exits 1"
    else
        bad "$MPM: after a rewrite with other bytes: $(plane_pids "$fin_pat") of $nkids children logged the final disarm, /enforced/ $(code /enforced/ "$LISTED"), verdict $(field "$(last_access)" verdict), gen $(field "$(last_access)" gen), --status rc $rc"
    fi
    fresh_snapshot
    arm_pat="plane snapshot.bin: generation $GEN verified, arming"
    if await_plane "$arm_pat" "$nkids" && [ "$(code /enforced/ "$LISTED")" = 403 ]; then
        ok "$MPM: generation $GEN at the bound name re-armed each child at its next tick, as the final line promised; /enforced/ denies again"
    else
        bad "$MPM: generation $GEN did not re-arm every child: $(plane_pids "$arm_pat") of $nkids, /enforced/ $(code /enforced/ "$LISTED")"
    fi

    # ---- 9. a deleted snapshot must leave traffic flowing, armed ------------------------------------
    gone_pat='plane snapshot.bin is gone from the data directory; the armed generation serves until its valid-until'
    rm -f "$W/snapshot.bin"
    [ "$(code / "$LISTED")" = 200 ] && [ "$(code /enforced/ "$LISTED")" = 403 ] \
        && ok "$MPM: snapshot deleted -> the armed generation keeps serving and enforcing" \
        || bad "$MPM: deleting the snapshot broke traffic: $(code / "$LISTED") $(code /enforced/ "$LISTED")"
    # as at 8b: the armed word settles a tick after the arming line, so --status is polled for the armed
    # generation once every child has logged the name gone, never read off the settle's lag
    if await_plane "$gone_pat" "$nkids" \
        && await '"$SUMMARY_BIN" --status "$W/counters" >"$W/status.out" 2>&1; rc=$?; [ "$rc" = 0 ] && grep -q "plane reputation armed generation $GEN digest" "$W/status.out"' 15 "the armed status word" \
        && [ "$(code /enforced/ "$LISTED")" = 403 ]; then
        ok "$MPM: at the next tick each child logged the name gone and kept generation $GEN armed; --status still exits 0"
    else
        bad "$MPM: after the deletion: $(plane_pids "$gone_pat") of $nkids children logged it, /enforced/ $(code /enforced/ "$LISTED"), --status rc $rc: $(grep -m1 'plane reputation' "$W/status.out" | cut -c1-120)"
    fi
    old_pat="plane snapshot.bin: generation $good_gen is not above $GEN; refused by its header, not digested"
    cp "$W/snapshot.good" "$W/snapshot.bin"; chmod 0644 "$W/snapshot.bin"
    if await_plane "$old_pat" "$nkids" && [ "$(code /enforced/ "$LISTED")" = 403 ]; then
        ok "$MPM: an older generation ($good_gen) put back at the name is refused by its header before any digest, and $GEN keeps enforcing"
    else
        bad "$MPM: the older generation put back: $(plane_pids "$old_pat") of $nkids children logged the refusal, /enforced/ $(code /enforced/ "$LISTED")"
    fi

    # ---- 10. a STALE snapshot must enforce NOTHING -------------------------------------------------------
    fresh_snapshot 1                      # valid_until_ms of 1 is 1970: deliberately stale
    timeout 20 "$HTTPD" -f "$conf" -k graceful >/dev/null 2>&1
    await "[ \"\$(code /enforced/ $LISTED)\" = 200 ]" 15 "stale snapshot ignored" \
        && ok "$MPM: a snapshot past its own validity window enforces nothing, even in deny mode" \
        || bad "$MPM: a STALE snapshot was still enforced: $(code /enforced/ "$LISTED")"
    [ "$(field "$(last_access)" verdict)" = "unknown,stale" ] \
        && ok "$MPM: and the verdict says unknown,stale, never a severity the module no longer acts on" \
        || bad "$MPM: the stale verdict reads $(field "$(last_access)" verdict)"
    await '"$SUMMARY_BIN" --status "$W/counters" >/dev/null 2>&1; [ $? = 1 ]' 25 "status exit 1" \
        && ok "$MPM: and whisper-edge-summary --status exits 1 on the stale plane" \
        || bad "$MPM: --status did not exit 1 on a stale plane"

    fresh_snapshot                        # leave a VALID file behind for whatever runs next
    stop_httpd "$conf" "$MPM" \
        && ok "$MPM: stop actually exits" \
        || bad "$MPM: httpd did not stop within 15s"
}

# the smaps reader of the shared policy rows: every program region shared, none private, in two workers
. "$ROOT/policy-rows.sh"

# =====================================================================================================
# THE FLOOR SUITE (event): a floor deny is the module's own text with no-store, under the http-level mode
# =====================================================================================================
run_floor_suite() {
    local MPM=event conf="$W/httpd-floor.conf" line d_floor n0 n1
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html/app"
    echo "page" > "$W/html/index.html"; echo "app" > "$W/html/app/index.html"
    fresh_snapshot 0 4                    # the listed range at CRITICAL
    { conf_head "$MPM"; conf_data; cat <<'CONF'
WhisperEdgeMode deny
WhisperEdgePolicyFloor "deny if listed >= critical"
ErrorDocument 403 /app/index.html
<Location /app>
    WhisperEdgeMode off
</Location>
CONF
    } > "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "floor: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    echo "  [floor suite, $MPM]"
    d_floor=$(ctx_digest "$(cfg_lines)" floor)
    [ "$(code / "$LISTED")" = 403 ] \
        && ok "floor: a floor-listed client is denied with the http-level status" \
        || bad "floor: the floor did not deny: $(code / "$LISTED")"
    line=$(last_access)
    [ "$(field "$line" rule)" = "floor:1" ] && [ "$(field "$line" program)" = "floor:$d_floor ctx:-" ] \
        && ok "floor: the notes name the floor's rule (floor:1) and the program as floor:<d16> ctx:-" \
        || bad "floor: the notes read $line"
    [ "$(body / "$LISTED")" = "Forbidden by the Whisper edge policy floor." ] \
        && ok "floor: the body is the module's own fixed text (class module), not the ErrorDocument below the floor" \
        || bad "floor: the floor deny served: $(body / "$LISTED" | head -c 120)"
    grep -qi '^Cache-Control: no-store' <<<"$(headers / "$LISTED")" \
        && ok "floor: and it carries Cache-Control: no-store" \
        || bad "floor: no no-store on the floor deny"
    [ "$(code /app/ "$LISTED")" = 403 ] \
        && ok "floor: a context whose mode is off cannot disarm the floor" \
        || bad "floor: mode off disarmed the floor: $(code /app/ "$LISTED")"
    [ "$(code / "$UNLISTED")" = 200 ] \
        && ok "floor: the unlisted twin passes the floor" \
        || bad "floor: the unlisted twin was denied by the floor"
    grep -q "denied $LISTED: rule floor:1 (deny if listed >= critical), program floor:$d_floor ctx:-, verdict critical" "$W/logs/error.log" \
        && ok "floor: the deny line names floor:1, its text and the floor's digest" \
        || bad "floor: the deny line: $(grep 'denied' "$W/logs/error.log" | tail -1 | cut -c60-)"
    await "[ -n \"\$(tick_of)\" ]" 25 "a counter file"
    await_next_tick
    n0=$(rule_count "$d_floor" 1)
    for i in 1 2 3; do code / "$LISTED" >/dev/null; done
    await_next_tick
    n1=$(rule_count "$d_floor" 1)
    [ "$n1" = "$((n0 + 3))" ] \
        && ok "floor: three floor denies move the floor's rule 1 by exactly three ($n0 -> $n1)" \
        || bad "floor: the floor counter moved $n0 -> $n1 for three denies"
    stop_httpd "$conf" "$MPM" || bad "floor: httpd did not stop"
    fresh_snapshot
}

# =====================================================================================================
# THE REQUEST PATH'S OWN ROWS: the header walk over HTTP/1.1 (T5), .htaccess (the access-only directives), Satisfy Any (T6),
# the cache warning's runtime arm (T8), the env/note split (V3a)
# =====================================================================================================

# a raw request over one keep-alive connection, so several requests' notes come from one child: the
# bytes are read from a file the row wrote; one line per response is printed: "<status> <body bytes>"
raw_session() { # raw_session <port> <request-bytes-file>...
    python3 - "$1" "${@:2}" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=20)
for path in sys.argv[2:]:
    with open(path, "rb") as f:
        data = f.read()
    s.sendall(data)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    clen = 0
    chunked = False
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
        if line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
            chunked = True
    # a keep-alive response of unknown length is chunked: it is drained to its last chunk, so its tail
    # cannot be read as the head of the next response on the connection (measured: a 1,000-entry index
    # read as 8,012 bytes, the rest left in the socket)
    while (chunked and not (rest.endswith(b"0\r\n\r\n") or b"\r\n0\r\n\r\n" in rest)) or (not chunked and len(rest) < clen):
        chunk = s.recv(65536)
        if not chunk:
            break
        rest += chunk
    status = head.split(b"\r\n")[0].split(b" ")[1:2]
    print((status[0] if status else b"?").decode(), len(rest))
s.close()
PY
}

# the walk's address grammar and its caps, over HTTP/1.1: the proxy's appended entry is the one judged
run_evidence6_rows() { # the evidence of an IPv6 listing, cited by the deny line as an IPv4 one is
    # testdata/interop.snap is the real builder's file: 2001:db8::1 is listed HIGH with the evidence EXAMPLE-6,
    # 192.0.2.0 critical with EXAMPLE-DROP-1 (testdata/expected.txt). Each walked past the trusted hop is
    # judged and denied, and its deny line carries the listing's evidence. The nginx and OpenLiteSpeed gates
    # assert the same IPv6 listing's evidence with the same literal, read from the same expected.txt, so the
    # three servers' lines carry it byte for byte. One deny line a second, so the two wait it out.
    local MPM=event conf="$W/httpd-ev6.conf" E6="$W/ev6" r6 r4 ev6 ev4 l6 l4
    echo "  [the evidence of an IPv6 listing]"
    ev6=$(awk '$1 == 6 && $2 == "2001:db8::1" { print $4 }' "$ROOT/core/testdata/expected.txt")
    ev4=$(awk '$1 == 4 && $2 == "192.0.2.0" { print $4 }' "$ROOT/core/testdata/expected.txt")
    rm -rf "$W/html" "$W/counters" "$E6"; mkdir -p "$W/html/enforced" "$E6"; chmod 0755 "$E6"
    echo page > "$W/html/index.html"; echo e > "$W/html/enforced/index.html"
    cp "$ROOT/core/testdata/interop.snap" "$E6/snapshot.bin"; chmod 0644 "$E6/snapshot.bin"
    { conf_head "$MPM"; cat <<CONF
WhisperEdgeSnapshot $E6/snapshot.bin
WhisperEdgeRefresh 10
WhisperEdgeTrustedProxy 127.0.0.1
WhisperEdgeTrustedHeader X-Forwarded-For
WhisperEdgeTrustedHops 2
<Location /enforced>
    WhisperEdgeMode deny
</Location>
CONF
    } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "evidence: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "evidence: httpd did not start: $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    sleep 1.1
    r6=$(code /enforced/ 2001:db8::1); sleep 1.1
    r4=$(code /enforced/ 192.0.2.0); sleep 0.5
    l6=$(grep -m1 -F 'whisper edge: denied 2001:db8::1: ' "$W/logs/error.log")
    l4=$(grep -m1 -F 'whisper edge: denied 192.0.2.0: ' "$W/logs/error.log")
    if [ -n "$ev6" ] && [ "$r6" = 403 ] && grep -qE ", evidence ${ev6}([^-A-Za-z0-9]|\$)" <<<"$l6"; then
        ok "evidence: an IPv6 listing's deny line cites its evidence ($ev6), the literal the nginx and OpenLiteSpeed gates assert for the same listing (403)"
    else
        bad "evidence: the IPv6 listing 2001:db8::1: status $r6, line \"$(printf '%s' "$l6" | cut -c1-200)\", want evidence ${ev6:-<none in expected.txt>}"
    fi
    if [ -n "$ev4" ] && [ "$r4" = 403 ] && grep -qE ", evidence ${ev4}([^-A-Za-z0-9]|\$)" <<<"$l4"; then
        ok "evidence: and an IPv4 listing of the same file cites its own ($ev4), so the row reads the file's evidence per family (403)"
    else
        bad "evidence: the IPv4 listing 192.0.2.0: status $r4, line \"$(printf '%s' "$l4" | cut -c1-200)\", want evidence ${ev4:-<none in expected.txt>}"
    fi
    stop_httpd "$conf" "$MPM" || bad "evidence: httpd did not stop"
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
}

run_realip_only_rows() { # behind a proxy only mod_remoteip trusts: step 4 judges the client, the proxy keeps its exemption
    # The installer's shape for a site behind a proxy on the same box: mod_remoteip trusts the loopback proxy
    # and reads X-Forwarded-For (conf_head), and the module has no trust list of its own, so the floor's
    # address is the TCP peer, 127.0.0.1, which is hold-harmless. That exemption covers the floor's steps;
    # step 4 judges the address mod_remoteip derived by the context's rules, with no exemption of its own, so
    # a hold-harmless client behind the proxy is allowed because it is listed nowhere. Every other row reaches
    # its listed client past a trusted hop with the module's own trust list, which is why none of them saw
    # this shape. The client must be outside hold-harmless (the fixture's benchmarking space is in it), so a
    # snapshot of its own lists 21.0.0.0/24 at HIGH; 21.0.0.5 is that client, 198.41.0.4 the hold-harmless one.
    # LogLevel error: the deny line and the log mode's WOULD DENY are written at error, httpd's own level for
    # a denial (AH01797), so they are seen wherever httpd's own denials are.
    local MPM=event conf="$W/httpd-realip.conf" RP="$W/realip-only" r line
    echo "  [behind a proxy only mod_remoteip trusts]"
    rm -rf "$W/html" "$W/counters" "$RP"; mkdir -p "$W/html/enforced" "$RP"; chmod 0755 "$RP"
    echo page > "$W/html/index.html"; echo e > "$W/html/enforced/index.html"
    python3 "$ROOT/core/make-test-snapshot.py" "$RP/snapshot.bin" 1 0 67 352321536 352321791; chmod 0644 "$RP/snapshot.bin"   # HIGH, drop (0x43)
    rp_conf() { # <module object>
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#"; cat <<CONF
LogLevel error
WhisperEdgeSnapshot $RP/snapshot.bin
WhisperEdgeRefresh 10
<Location /enforced>
    WhisperEdgeMode deny
</Location>
CONF
        } > "$conf"
    }
    rp_conf "$MODULE"
    if grep -q '^#missing' "$conf"; then
        bad "realip-only: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "realip-only: httpd did not start: $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H 'X-Forwarded-For: 21.0.0.5' "http://127.0.0.1:$PORT/enforced/")
    line=$(last_access)
    [ "$r" = 403 ] && [[ $line == "21.0.0.5 403 action=deny "* ]] && [[ $line == *" floor=127.0.0.1 "* ]] \
        && ok "realip-only: a listed client (21.0.0.5, HIGH) behind the loopback proxy is denied by the context (403), the floor still the proxy 127.0.0.1" \
        || bad "realip-only: the listed client behind the loopback proxy: status $r, line \"$line\""
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$PORT/enforced/")
    line=$(last_access)
    [ "$r" = 200 ] && [[ $line == "127.0.0.1 200 action=allow "* ]] && [[ $line == *" reason=hold-harmless "* ]] \
        && ok "realip-only: the proxy's own request (no X-Forwarded-For) is exempt as the loopback peer (200)" \
        || bad "realip-only: the proxy's own request: status $r, line \"$line\""
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H 'X-Forwarded-For: 198.41.0.4' "http://127.0.0.1:$PORT/enforced/")
    line=$(last_access)
    [ "$r" = 200 ] && [[ $line == "198.41.0.4 200 action=allow "* ]] && [[ $line == *" reason=- "* ]] \
        && ok "realip-only: a hold-harmless client (198.41.0.4) behind the proxy is judged at step 4 and allowed as unlisted, reason=- and not hold-harmless (200)" \
        || bad "realip-only: the hold-harmless client behind the proxy: status $r, line \"$line\""
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H 'X-Forwarded-For: 21.0.0.5' "http://127.0.0.1:$PORT/")
    line=$(last_access)
    grep -q ':error\] .*whisper edge: denied 21\.0\.0\.5: .*, verdict high,spamhaus-drop, evidence ' "$W/logs/error.log" \
        && ok "deny line: under LogLevel error the deny is written at error, httpd's own level for a denial (AH01797), with the canonical verdict \"verdict high,spamhaus-drop\" every server's line prints" \
        || bad "deny line: no :error deny line under LogLevel error: $(grep -m1 'whisper edge: denied' "$W/logs/error.log" | cut -c1-160)"
    [ "$r" = 200 ] && grep -q ':error\] .*whisper edge: WOULD DENY 21\.0\.0\.5: ' "$W/logs/error.log" \
        && ok "would-deny line: under LogLevel error the log mode's WOULD DENY is written at error too (status $r)" \
        || bad "would-deny line: status $r, no :error WOULD DENY line: $(grep -m1 'WOULD DENY' "$W/logs/error.log" | cut -c1-160)"
    stop_httpd "$conf" "$MPM" || bad "realip-only: httpd did not stop"
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    if build_variant denywarn -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_DENY_AT_WARN; then
        rp_conf "$CTL/denywarn.so"
        if start_httpd "$conf" "$MPM"; then
            curl -s -o /dev/null --max-time 8 -H 'X-Forwarded-For: 21.0.0.5' "http://127.0.0.1:$PORT/enforced/"
            curl -s -o /dev/null --max-time 8 -H 'X-Forwarded-For: 21.0.0.5' "http://127.0.0.1:$PORT/"; sleep 0.5
            ! grep -q 'whisper edge: \(denied\|WOULD DENY\) 21\.0\.0\.5' "$W/logs/error.log" \
                && ok "deny line control (both lines at warn): LogLevel error shows neither, so the rows above prove the level" \
                || bad "deny line control (both lines at warn): a line passed LogLevel error; the rows pass without the code they prove"
            stop_httpd "$conf" "$MPM" || bad "realip-only: the control httpd did not stop"
            await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        else
            bad "deny line control: the control httpd did not start"
        fi
    else
        bad "deny line control: the control module does not build: $(tail -2 "$CTL/denywarn.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
}

run_walk_rows() { # T5 over HTTP/1.1: the forged line is never the judged entry, every form parses
    local MPM=event conf="$W/httpd-walk.conf" P2=$((PORT + 1)) r line
    echo "  [the header walk over HTTP/1.1]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html/w"
    echo page > "$W/html/index.html"; echo w > "$W/html/w/index.html"
    fresh_snapshot 0 4                     # the listed range at critical, the floor program's bar
    # the floor enforces, so every deny below is the module's own walk deciding, never mod_remoteip's
    # reading of the same header (the context plane holds no rule in this configuration, ctx:-);
    # LimitRequestFields is raised so the 100-forged-lines arm is the walk's own cap that answers, not
    # httpd's field limit (the header-count row covers that limit at its default)
    { conf_head "$MPM"; conf_data; cat <<CONF
Listen [::]:$P2
LimitRequestFields 128
WhisperEdgeMode deny
WhisperEdgePolicyFloor "deny if listed >= critical"
CONF
    } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "walk: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "walk: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    local d_floor
    d_floor=$(ctx_digest "$(cfg_lines)" floor)
    echo "  [walk, $MPM, the floor enforcing; the v6 listener on [::]:$P2 for the mapped peer]"
    # two XFF lines: the client's forged line first, the trusted proxy's appended line second
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H 'X-Forwarded-For: 1.2.3.4' \
        -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/w/")
    line=$(last_access)
    [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
        && ok "walk: two X-Forwarded-For lines, the forged first: the proxy-appended entry is the first walked and judged ($LISTED, the floor's own rule), so the forged 1.2.3.4 never decides" \
        || bad "walk: the forged-first pair answered $r: $line"
    # the line cap: 16, 17, 40, 64 and 100 forged lines before the proxy's; the walk keeps the newest 16
    local n hdrs i out=all
    for n in 16 17 40 64 100; do
        hdrs=(-H 'Accept:' -H 'User-Agent:')
        for i in $(seq 1 "$n"); do hdrs+=(-H "X-Forwarded-For: 1.2.3.$i"); done
        r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${hdrs[@]}" \
            -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/w/")
        line=$(last_access)
        [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
            || out="$n:$r/$(field "$line" floor)/$(field "$line" rule)"
    done
    [ "$out" = all ] \
        && ok "walk: 16, 17, 40, 64 and 100 forged lines before the proxy's: the newest sixteen are kept and the walk starts at the proxy's line in every one, so the judged entry is $LISTED each time" \
        || bad "walk: a forged-line count answered wrong: $out"
    # the entry grammar: a port suffix, a bracketed IPv6 entry with a port, empty elements
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "X-Forwarded-For: $LISTED:443, $HOP" "http://127.0.0.1:$PORT/w/")
    line=$(last_access)
    [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
        && ok "walk: an entry with a port suffix ($LISTED:443) parses and the address still matches the plane, whatever mod_remoteip makes of the form" \
        || bad "walk: the port-suffix entry answered $r: $line"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "X-Forwarded-For: [2001:db8::5]:443, $HOP" "http://127.0.0.1:$PORT/w/")
    line=$(last_access)
    [ "$r" = 200 ] && [ "$(field "$line" floor)" = "2001:db8::5" ] && [ "$(field "$line" verdict)" = none ] \
        && ok "walk: a bracketed IPv6 entry with a port parses into its address (floor 2001:db8::5), unlisted so allowed" \
        || bad "walk: the bracketed entry answered $r: $line"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "X-Forwarded-For: , , $LISTED, $HOP" "http://127.0.0.1:$PORT/w/")
    line=$(last_access)
    [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
        && ok "walk: empty list elements are skipped without consuming a hop, so $LISTED is still judged at hop 2" \
        || bad "walk: the empty-element line answered $r: $line"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "X-Forwarded-For: $LISTED, $HOP, " "http://127.0.0.1:$PORT/w/")
    line=$(last_access)
    [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
        && ok "walk: a trailing empty element (the merged value's shape) is skipped and the walk still reaches $LISTED" \
        || bad "walk: the trailing-empty line answered $r: $line"
    # a ::ffff: peer against a v4 trust entry: the dual-stack listener hands the module ::ffff:127.0.0.1
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$P2/w/" -H "X-Forwarded-For: $LISTED, $HOP")
    line=$(last_access)
    [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ] && [ "$(field "$line" rule)" = "floor:1" ] \
        && ok "walk: a ::ffff:127.0.0.1 peer (the dual-stack listener) is canonicalised onto the v4 trust entry, so the header is read and $LISTED judged" \
        || bad "walk: the mapped peer answered $r: $line"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$P2/")
    line=$(last_access)
    [ "$r" = 200 ] && [ "$(field "$line" floor)" = "127.0.0.1" ] \
        && ok "walk: and with no header its floor address prints 127.0.0.1, the canonical form, never ::ffff:127.0.0.1" \
        || bad "walk: the mapped peer with no header: $r: $line"
    # the floor's own decision line: the plane matched the judged entry at critical, the bar the program sets
    grep -q "denied $LISTED: rule floor:1 (deny if listed >= critical), program floor:$d_floor ctx:-, verdict critical" "$W/logs/error.log" \
        && ok "walk: the deny line names $LISTED at verdict critical, so every form that reached the floor matched the plane, not just parsed" \
        || bad "walk: the floor's deny line: $(grep 'denied' "$W/logs/error.log" | tail -1 | cut -c60-)"
    stop_httpd "$conf" "$MPM" || bad "walk: httpd did not stop"
    # the core's two line controls, walked through this server: the first field line alone, and the oldest sixteen.
    # httpd merges repeated X-Forwarded-For lines into one field, comma-joined in arrival order, before any module
    # reads it, so the module is handed one line and both controls judge exactly what the release does. On Apache
    # the forged-line arms above are held by the entry walk over the merged field, not by the line choice; the
    # controls are run, and their agreement is printed as the measurement that they cannot fail here
    local v cfl hdrs17
    hdrs17=(-H 'Accept:' -H 'User-Agent:')
    for i in $(seq 1 17); do hdrs17+=(-H "X-Forwarded-For: 1.2.3.$i"); done
    for v in firstline first16; do
        case "$v" in
        firstline) build_variant "$v" -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_FIRST_LINE ;;
        *)         build_variant "$v" -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_FIRST_16_LINES ;;
        esac || { bad "walk: the $v control build failed: $(tail -2 "$CTL/$v.log" | tr '\n' ' ' | cut -c1-200)"; continue; }
        cfl="$W/httpd-walk-$v.conf"
        sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/$v.so#" "$conf" > "$cfl"
        start_httpd "$cfl" "$MPM" || { bad "walk: the $v control did not start"; continue; }
        if [ "$v" = firstline ]; then
            r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H 'X-Forwarded-For: 1.2.3.4' \
                -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/w/")
        else
            r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${hdrs17[@]}" \
                -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/w/")
        fi
        line=$(last_access)
        if [ "$r" = 403 ] && [ "$(field "$line" floor)" = "$LISTED" ]; then
            na "walk's control ($v): $( [ "$v" = firstline ] && echo 'WE_MOD_TEST_FIRST_LINE' || echo 'WE_MOD_TEST_FIRST_16_LINES') judges $LISTED (403) as the release does, because httpd merged the field lines into one before the module read them: the line controls cannot fail on Apache, and the entry walk over the merged field is what the arms above prove"
        else
            bad "walk's control ($v): the build judged $r with floor $(field "$line" floor), so httpd no longer merges the field lines and the line controls now apply: make them a proving row"
        fi
        stop_httpd "$cfl" "$MPM" || bad "walk: the $v control did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        ctl_exit_clean "walk's $v control"
    done
    fresh_snapshot
}

# the .htaccess arm: the directives are ACCESS_CONF only, so httpd itself refuses them in .htaccess
run_htaccess_rows() {
    local MPM=event conf="$W/httpd-ht.conf" doc="$W/html/tenant" r
    echo "  [.htaccess]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$doc"
    echo page > "$W/html/index.html"; echo t > "$doc/index.html"
    fresh_snapshot
    { conf_head "$MPM"; conf_data; cat <<CONF
<Directory $doc>
    AllowOverride All
    Require all granted
</Directory>
CONF
    } > "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "htaccess: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    printf 'WhisperEdgeMode deny\n' > "$doc/.htaccess"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$PORT/tenant/")
    [ "$r" = 500 ] && grep -qi 'WhisperEdgeMode not allowed here' "$W/logs/error.log" \
        && ok "htaccess: a WhisperEdge directive in .htaccess is refused by httpd itself (500, not allowed here), never silently dropped" \
        || bad "htaccess: the .htaccess with the directive answered $r: $(grep -i 'not allowed here' "$W/logs/error.log" | tail -1 | cut -c1-160)"
    rm "$doc/.htaccess"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$PORT/tenant/")
    [ "$r" = 200 ] \
        && ok "htaccess: the twin without the line serves 200, so the 500 was the directive's own refusal" \
        || bad "htaccess: the clean twin answered $r"
    { conf_head "$MPM"; conf_data; printf '<Directory %s>\n    AllowOverride All\n    Require all granted\n    WhisperEdgeMode deny\n</Directory>\n' "$doc"; } > "$conf"
    "$HTTPD" -t -f "$conf" >/dev/null 2>&1 && ok "htaccess: the same line one level up (the directory section) is accepted" \
        || bad "htaccess: the same line one level up was refused: $("$HTTPD" -t -f "$conf" 2>&1 | grep -i 'refused\|AH0' | head -1 | cut -c1-200)"
    stop_httpd "$conf" "$MPM" || bad "htaccess: httpd did not stop"
    fresh_snapshot
}

# T6: Satisfy Any votes a deny away; the fixups hook at REALLY_FIRST enforces it anyway
run_satisfy_rows() {
    local MPM=event conf="$W/httpd-sat.conf" doc="$W/html/vip" r
    echo "  [Satisfy Any]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$doc"
    echo page > "$W/html/index.html"; echo vip > "$doc/index.html"
    fresh_snapshot
    htpasswd -bc "$W/htpass" gate gatepw >/dev/null 2>&1
    { conf_head "$MPM"; conf_data; need_mod env_module mod_env.so; cat <<CONF
$(need_mod access_compat_module mod_access_compat.so)
$(need_mod authn_core_module mod_authn_core.so)
$(need_mod auth_basic_module mod_auth_basic.so)
$(need_mod authn_file_module mod_authn_file.so)
$(need_mod authz_user_module mod_authz_user.so)
<Location /vip>
    WhisperEdgeMode deny
    AuthType Basic
    AuthName vip
    AuthUserFile $W/htpass
    Satisfy Any
    Require all granted
</Location>
CONF
    } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "satisfy: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "satisfy: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/vip/")
    [ "$r" = 403 ] \
        && ok "satisfy: under Satisfy Any with Require all granted a listed client still gets the deny" \
        || bad "satisfy: Satisfy Any + all granted answered $r"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -u gate:gatepw -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/vip/")
    [ "$r" = 403 ] \
        && ok "satisfy: and with Require valid-user plus valid credentials the deny stands (a vote the authz hook won is enforced at fixups)" \
        || bad "satisfy: Satisfy Any + valid-user with credentials answered $r"
    stop_httpd "$conf" "$MPM" || bad "satisfy: httpd did not stop"
    # the same two Require forms in a tenant .htaccess under AllowOverride AuthConfig
    { conf_head "$MPM"; conf_data; cat <<CONF
$(need_mod access_compat_module mod_access_compat.so)
$(need_mod authn_core_module mod_authn_core.so)
$(need_mod auth_basic_module mod_auth_basic.so)
$(need_mod authn_file_module mod_authn_file.so)
$(need_mod authz_user_module mod_authz_user.so)
<Directory $doc>
    AllowOverride AuthConfig
    Require all granted
</Directory>
<Location /vip>
    WhisperEdgeMode deny
</Location>
CONF
    } > "$conf"
    cat > "$doc/.htaccess" <<'HT'
AuthType Basic
AuthName vip
AuthUserFile HTPASS
Satisfy Any
Require valid-user
HT
    sed -i "s#HTPASS#$W/htpass#" "$doc/.htaccess"
    if ! start_httpd "$conf" "$MPM"; then
        bad "satisfy: the .htaccess server did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -u gate:gatepw -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/vip/")
    [ "$r" = 403 ] \
        && ok "satisfy: the same Satisfy Any in a tenant .htaccess under AllowOverride AuthConfig, with credentials: the deny is enforced" \
        || bad "satisfy: the .htaccess Satisfy Any arm answered $r"
    stop_httpd "$conf" "$MPM" || bad "satisfy: the .htaccess server did not stop"
    fresh_snapshot
}

# T8's runtime arm: the quick handler bypasses every access hook, so with CacheQuickHandler off the
# judgment is back in front of the cache; with it on (the default) a cached page is handed over
run_cache_rows() {
    local MPM=event conf="$W/httpd-cache.conf" r age code
    echo "  [mod_cache]"
    rm -rf "$W/html" "$W/counters" "$W/cache"; mkdir -p "$W/html/cached" "$W/cache"
    echo page > "$W/html/cached/index.html"
    # the stored page must stay fresh across the restart below: with only Last-Modified to go on the
    # disk cache's heuristic freshness is (now - mtime) x 0.1, so a just-written file is stale within a
    # second; a two-hour-old mtime gives the entry twelve fresh minutes
    touch -d '2 hours ago' "$W/html/cached/index.html"
    fresh_snapshot
    { conf_head "$MPM"; conf_data; cat <<CONF
$(need_mod cache_module mod_cache.so)
$(need_mod cache_disk_module mod_cache_disk.so)
CacheEnable disk /cached
CacheRoot $W/cache
CacheQuickHandler off
<Location /cached>
    WhisperEdgeMode deny
</Location>
CONF
    } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "cache: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "cache: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/cached/")" = 200 ] \
        || { bad "cache: the unlisted twin did not prime the cache"; stop_httpd "$conf" "$MPM"; return; }
    [ "$(find "$W/cache" -type f | wc -l)" -gt 0 ] \
        || { bad "cache: the disk cache stored nothing under $W/cache, so the quick handler has nothing to serve"; stop_httpd "$conf" "$MPM"; return; }
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/cached/")
    [ "$r" = 403 ] \
        && ok "cache: with CacheQuickHandler off a cached URL requested by a listed client gets the deny" \
        || bad "cache: with CacheQuickHandler off the listed client got $r"
    stop_httpd "$conf" "$MPM" || bad "cache: httpd did not stop"
    # the default: the quick handler serves the cached page before every access hook, which is what the warning names
    { conf_head "$MPM"; conf_data; cat <<CONF
$(need_mod cache_module mod_cache.so)
$(need_mod cache_disk_module mod_cache_disk.so)
CacheEnable disk /cached
CacheRoot $W/cache
<Location /cached>
    WhisperEdgeMode deny
</Location>
CONF
    } > "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "cache: the quick-handler-on server did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    curl -s -o /dev/null --max-time 8 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/cached/"
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -D - -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/cached/" \
        | tr -d '\r' | sed -n 's/^Age: //p' | head -1)
    age=${r%% *}
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/cached/")
    [ "$code" = 200 ] && [ -n "$age" ] \
        && ok "cache: under CacheQuickHandler On (the default) the same listed client is handed the cached 200 (Age: $age) before any judgment, the bypass the warning names and the README states" \
        || bad "cache: the quick handler did not serve the cached page to the listed client ($code, Age: '$age'), so the bypass the README states is not what this httpd does"
    stop_httpd "$conf" "$MPM" || bad "cache: the quick-handler server did not stop"
    fresh_snapshot
}

# V3a: a tenant's SetEnv cannot rewrite the verdict note; the environment copy is the tenant's to set
run_envnote_rows() {
    local MPM=event conf="$W/httpd-env.conf" r line
    echo "  [the note and the environment]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
    echo page > "$W/html/index.html"
    fresh_snapshot
    { conf_head "$MPM"; conf_data; need_mod env_module mod_env.so; cat <<'CONF'
SetEnv WHISPER_EDGE_ACTION allow
LogFormat "%{WHISPER_EDGE_ACTION}n|%{WHISPER_EDGE_ACTION}e" envfmt
CONF
    } > "$conf"
    printf 'CustomLog %s/logs/env.log envfmt\n' "$W" >> "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "envnote: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$(xff "$LISTED")" "http://127.0.0.1:$PORT/")
    line=$(tail -1 "$W/logs/env.log" 2>/dev/null)
    [ "$r" = 200 ] && [ "$line" = "would-deny|allow" ] \
        && ok "envnote: SetEnv WHISPER_EDGE_ACTION allow leaves the note would-deny while the environment copy prints allow, so a tenant cannot rewrite what the log's verdict column reads" \
        || bad "envnote: the SetEnv arm answered $r with the pair '$line' (note|environment)"
    stop_httpd "$conf" "$MPM" || bad "envnote: httpd did not stop"
    if command -v php >/dev/null 2>&1 || command -v php-cgi >/dev/null 2>&1; then
        :   # a php on the host: the apache_note arm runs (not this host's shape; the arm lands with it)
    else
        printf '  NOT PROVEN  envnote: the PHP apache_note arm: no php binary on this host, so the handler-module rewrite of the note is not exercised; the SetEnv arm above covers the note path, and the README states the PHP arm unproven here\n'
    fi
    fresh_snapshot
}

# =====================================================================================================
# C5+: the request path's frame, measured on the built object, and the header pass, counted by the
# debug build's own counter over raw requests no client library shapes
# =====================================================================================================
# THE FRAME RULE: the scratch's frame and the deepest chain beneath it at most 10% of the target's PTHREAD_STACK_MIN
# (the smallest stack ThreadStackSize accepts), capped at 2,048 bytes; and a ratchet against the checked-in figure for
# the architecture, which the chain may not exceed by 64 bytes or more. A single fixed figure (1,500 was tried first) was
# about 9% of x86_64's 16,384, so the bound is per architecture rather than one number
frame_ratchet() { # the checked-in figure for an architecture, empty for one that has none
    case "$1" in
    x86_64)  echo 1592 ;;
    aarch64) echo 1488 ;;
    esac
}
frame_stack_min() { # the target's PTHREAD_STACK_MIN, from the compiler's own headers
    local CC t
    CC=$("$APXS" -q CC 2>/dev/null || echo cc)
    t=$(mktemp -d)
    printf '#include <limits.h>\n#include <pthread.h>\n#include <stdio.h>\nint main(void) { printf("%%ld\\n", (long) PTHREAD_STACK_MIN); return 0; }\n' > "$t/s.c"
    $CC -o "$t/s" "$t/s.c" 2>/dev/null && "$t/s"
    rm -rf "$t"
}
frame_rule() { # frame_rule <bytes> <label>: sets FRAME_VERDICT (ok|fail) and FRAME_WHY (bytes, fraction, bound, ratchet)
    local seg=${1:-0} arch min limit ratchet
    arch=$(uname -m)
    min=${FRAME_STACK_MIN:-$(frame_stack_min)}
    FRAME_STACK_MIN=$min
    ratchet=$(frame_ratchet "$arch")
    if [ -z "$min" ] || [ -z "$ratchet" ] || [ "$seg" -le 0 ]; then
        FRAME_VERDICT=fail; FRAME_RULE=fail; FRAME_RATCHET=fail
        FRAME_WHY="${seg} bytes, but no PTHREAD_STACK_MIN (${min:-unread}) or no checked-in figure for $arch (${ratchet:-none})"
        return
    fi
    limit=$((min / 10)); [ "$limit" -gt 2048 ] && limit=2048
    FRAME_WHY="$seg bytes, $(awk -v a="$seg" -v b="$min" 'BEGIN { printf "%.2f%%", 100 * a / b }') of $arch's PTHREAD_STACK_MIN $min; the bound $limit (10%, at most 2,048), the checked-in figure $ratchet (a ratchet at +64)"
    FRAME_RULE=ok; FRAME_RATCHET=ok
    [ "$seg" -le "$limit" ] || FRAME_RULE=fail
    [ "$seg" -lt $((ratchet + 64)) ] || FRAME_RATCHET=fail
    if [ "$FRAME_RULE" = ok ] && [ "$FRAME_RATCHET" = ok ]; then FRAME_VERDICT=ok; else FRAME_VERDICT=fail; fi
}
run_frame_rows() {
    local out
    echo "  [the frame and the header pass]"
    # the stack figure: every handler's static call chains, summed -fstack-usage, against the 1,500 bound.
    # -fno-lto because apxs's own -flto=auto moves codegen to the linker's temp dirs, where the .su
    # files are written and deleted before anything can read them; this is a measurement build, and
    # per-function stack usage is only attributable where each function is compiled once. The
    # module's own translation unit is compiled once more beside the variant build because libtool's
    # link step rm -f's .libs/<module>.* (its output-name pattern), which deletes the module's
    # compile-time .su while the core files' survive under their own names; the flags match the
    # variant's optimisation level so the figure is the shipped build's
    frame_analysis() { # frame_analysis <variant name> <extra -Wc flags...> -> the segment, per-handler and chain lines
        local name=$1 CC
        shift
        build_variant "$name" -Wc,-fno-lto -Wc,-fstack-usage "$@" || return 1
        CC=$("$APXS" -q CC 2>/dev/null || echo cc)
        # shellcheck disable=SC2046
        "$CC" -O2 -g -fPIC -fno-lto -fstack-usage -std=gnu11 -Wall -Wextra $(printf '%s\n' "$@" | sed -n 's/^-Wc,//p' | tr '\n' ' ') \
            -I"$("$APXS" -q INCLUDEDIR)" -I"$("$APXS" -q APR_INCLUDEDIR)" -I"$CTL/core" \
            -c "$CTL/apache/mod_whisper_edge.c" -o "$CTL/mod-whisper-su.o" >>"$CTL/$name.log" 2>&1 \
            || { echo "module-su-failed"; return 1; }
        python3 - "$CTL/$name.so" "$CTL" <<'PY'
import re, subprocess, sys, glob, os
so, ctl = sys.argv[1], sys.argv[2]
usage = {}
for f in glob.glob(ctl + "/apache/*.su") + glob.glob(ctl + "/apache/.libs/*.su") + glob.glob(ctl + "/*.su") \
         + glob.glob(ctl + "/core/*.su") + glob.glob(ctl + "/core/.libs/*.su"):
    with open(f) as fh:
        for line in fh:
            m = re.match(r"^[^:]*:[0-9]+:[0-9]+:([^\t]+)\t([0-9]+)", line)
            if m:
                # the .su names a compiler clone by its suffix without the number the symbol carries
                # (we_legacy_ranges.isra against we_legacy_ranges.isra.0), so both fold to the base name;
                # a callee named only by its clone was invisible to the chain (measured by the planted frame)
                base = re.sub(r"\.(lto_priv|constprop|isra|part)(\.[0-9]+)?$", "", m.group(1))
                usage[base] = max(int(m.group(2)), usage.get(base, 0))
syms = {}
for line in subprocess.run(["nm", so], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if len(p) == 3 and p[1] in ("t", "T"):
        base = re.sub(r"\.(lto_priv|constprop|isra|part)\.[0-9]+", "", p[2])
        base = re.sub(r"\.cold$", "", base)
        syms[p[2]] = base
edges = {}
dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", so], capture_output=True, text=True).stdout
cur = None
for line in dis.splitlines():
    m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
    if m:
        cur = m.group(1)
        continue
    if cur:
        # only bl and call stack a frame: a bare b or jmp is a tail call, which REPLACES the
        # caller's frame, so its callee never stacks on it (and an unsymbolised cold blob's
        # stray b must not read as an edge either)
        m = re.search(r"<([A-Za-z_][A-Za-z0-9_.@]*)>", line)
        if m and re.match(r"\s*[0-9a-f]+:\s+(bl|call)\s", line):
            t = m.group(1)
            if not t.endswith("@plt") and t != cur:
                edges.setdefault(syms.get(cur, cur), set()).add(syms.get(t, t))
def worst(name, seen):
    if name not in usage:
        return 0
    best = 0
    for t in edges.get(name, ()):
        if t in seen or t == name:
            continue
        best = max(best, worst(t, seen | {t}))
    return usage[name] + best
def through(name, seen, need):
    if name not in usage:
        return 0
    left = None if name == need else need
    best = 0
    for t in edges.get(name, ()):
        if t in seen or t == name:
            continue
        best = max(best, through(t, seen | {t}, left))
    if left is not None and best == 0:
        return 0
    return usage[name] + best
def path(name, seen):
    if name not in usage:
        return (0, None)
    best = (0, None)
    for t in edges.get(name, ()):
        if t in seen or t == name:
            continue
        r = path(t, seen | {t})
        if r[0] > best[0]:
            best = r
    return (usage[name] + best[0], (name, usage[name], best[1]))
own = usage.get("we_decide_frame", 0)
seg = worst("we_decide_frame", {"we_decide_frame"})
print("segment", seg, own, seg - own)
for h in ("we_access_checker", "we_fixups_first", "we_fixups_last", "we_post_read_request"):
    print(h, worst(h, {h}), through(h, {h}, "we_walk_head"))
tot, p = path("we_access_checker", {"we_access_checker"})
chain = []
while p is not None:
    chain.append("%s:%d" % (p[0], p[1]))
    p = p[2]
print("deepest", " ".join(chain))
PY
    }
    # the chain accounted frame by frame: the handler's full-chain figure is the sum of the frames on its deepest
    # chain, and the segment is the decision frame plus the one evaluation beneath it, so what stands between the
    # handler's figure and the segment is exactly the frames above the decision frame; prints the verdict words
    chain_check() { # chain_check "<chain line>" <fig> <seg> <own> -> "ok <below> <above>" or "FAIL <why>"
        python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
chain = [(e.rsplit(":", 1)[0], int(e.rsplit(":", 1)[1])) for e in sys.argv[1].split()]
fig, seg, own = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
names = [n for n, b in chain]
total = sum(b for n, b in chain)
if total != fig:
    print("FAIL the chain's frames sum to %d, the handler's figure is %d" % (total, fig)); raise SystemExit
if "we_decide_frame" not in names:
    print("FAIL we_decide_frame is not on the deepest chain: %s" % " ".join(names)); raise SystemExit
i = names.index("we_decide_frame")
if chain[i][1] != own:
    print("FAIL we_decide_frame holds %d on the chain, %d in the segment" % (chain[i][1], own)); raise SystemExit
below = chain[i + 1:]
# the export fill and what it calls (x86_64's gcc keeps we_mod_memo_put out of line beneath it, measured), never
# another callee of the decision frame
if not below or below[0][0] != "we_mod_fill":
    print("FAIL beneath we_decide_frame the chain runs %s, not the export fill alone" % (" ".join("%s:%d" % x for x in below) or "nothing")); raise SystemExit
if own + sum(b for n, b in below) != seg:
    print("FAIL the decision frame plus the fill's chain is %d, the segment %d" % (own + sum(b for n, b in below), seg)); raise SystemExit
above = chain[:i]
if sum(b for n, b in above) != fig - seg:
    print("FAIL the frames above we_decide_frame sum to %d, the figure less the segment is %d" % (sum(b for n, b in above), fig - seg)); raise SystemExit
print("ok %s %s" % ("+".join("%s:%d" % x for x in below), " + ".join("%s:%d" % x for x in above)))
PY
    }
    if [ -n "$APXS" ] && out=$(frame_analysis stackusage) && [ "$out" != module-su-failed ]; then
        local worstfig=0 seg=0 segown=0 h fig walk chainline chk
        seg=$(printf '%s\n' "$out" | awk '$1 == "segment" { print $2 }')
        segown=$(printf '%s\n' "$out" | awk '$1 == "segment" { print $3 }')
        chainline=$(printf '%s\n' "$out" | awk '$1 == "deepest" { $1 = ""; sub(/^ /, ""); print }')
        echo "  the scratch's own frame holds ${segown:-no} bytes; the deepest evaluation beneath it" \
             "$(printf '%s\n' "$out" | awk '$1 == "segment" { print $4 }') more; together ${seg:-no} bytes"
        echo "  the deepest chain runs: ${chainline:-not found}"
        local worstwalk=0
        for h in we_access_checker we_fixups_first we_fixups_last we_post_read_request; do
            fig=$(printf '%s\n' "$out" | awk -v h="$h" '$1 == h { print $2 }')
            walk=$(printf '%s\n' "$out" | awk -v h="$h" '$1 == h { print $3 }')
            echo "  $h: ${fig:-no figure} bytes over its static call chains; the walk's own path there ${walk:-0}"
            [ -n "$fig" ] && [ "$fig" -gt "$worstfig" ] && worstfig=$fig
            [ -n "$walk" ] && [ "$walk" -gt "$worstwalk" ] && worstwalk=$walk
        done
        # the frame figure as its own enumeration states it: the scratch (1,024 plus at most 63 of
        # alignment), the frame's own locals, and the deepest evaluation beneath it (the wrapper's
        # slot: the export pass's fill is the deepest here) together under 1,500. The full chain from
        # each handler is printed above it; the walk runs in a frame that has returned before the
        # decision frame owns the scratch, so its path never stacks on it, and that is gated too.
        frame_rule "$seg" release
        case $FRAME_VERDICT in
        ok)  ok "frame: the scratch's frame and the deepest chain beneath it hold $FRAME_WHY" ;;
        *)   bad "frame: the scratch's frame and the deepest chain beneath it (the bound $FRAME_RULE, the ratchet $FRAME_RATCHET) hold $FRAME_WHY" ;;
        esac
        [ "$worstwalk" -gt 0 ] && [ "$worstwalk" -lt 1500 ] \
            && ok "frame: the walk's own path from a handler holds at most $worstwalk bytes, so the header pass never stacks on the scratch's frame" \
            || bad "frame: the walk's path from a handler holds ${worstwalk:-0} bytes, at or over the 1,500-byte bound"
        grep -q 'WE_ALIGN64 we_eval_ctx_t e;' "$ROOT/core/we_module.h" \
            && grep -q 'sizeof(we_mod_scratch_t) == 1024u' "$ROOT/core/we_module.h" \
            && grep -q '_Alignof(we_mod_scratch_t) == 64u' "$ROOT/core/we_module.h" \
            && ok "frame: the scratch is declared 1,024 bytes and 64-byte aligned by static asserts, so every build of the core enforces both" \
            || bad "frame: the core's scratch declaration lost its size or alignment asserts"
        # the full chain from the access handler, frame by frame
        fig=$(printf '%s\n' "$out" | awk '$1 == "we_access_checker" { print $2 }')
        chk=$(chain_check "$chainline" "${fig:-0}" "${seg:-0}" "${segown:-0}")
        case $chk in
        ok*) ok "frame: the deepest chain from we_access_checker is accounted frame by frame: ${fig} = $(printf '%s' "$chainline" | sed 's/[a-z_]*://g; s/ / + /g'); beneath we_decide_frame only the export fill ($(printf '%s\n' "$chk" | awk '{print $2}')), and the $((fig - seg)) above it are $(printf '%s\n' "$chk" | cut -d' ' -f3-)" ;;
        *)   bad "frame: the chain's decomposition: ${chk#FAIL }" ;;
        esac
        # the control: a 512-byte frame planted in a callee beneath the decision frame is what the chain names
        if out=$(frame_analysis plantframe -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PLANT_FRAME) && [ "$out" != module-su-failed ]; then
            chainline=$(printf '%s\n' "$out" | awk '$1 == "deepest" { $1 = ""; sub(/^ /, ""); print }')
            fig=$(printf '%s\n' "$out" | awk '$1 == "we_access_checker" { print $2 }')
            seg=$(printf '%s\n' "$out" | awk '$1 == "segment" { print $2 }'); segown=$(printf '%s\n' "$out" | awk '$1 == "segment" { print $3 }')
            chk=$(chain_check "$chainline" "${fig:-0}" "${seg:-0}" "${segown:-0}")
            case $chk in
            FAIL*beneath*we_test_planted_callee*) ok "frame: the planted-frame control is seen: beneath we_decide_frame the deepest chain runs through the planted callee instead of the fill (${chk#FAIL beneath we_decide_frame the chain runs }), the handler's figure at ${fig}" ;;
            *) bad "frame: the planted 512-byte frame beneath the decision frame was not named by the chain check: $chk (chain: $chainline)" ;;
            esac
            :
        else
            bad "frame: the planted-frame control build failed: $(tail -2 "$CTL/plantframe.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
        fi
        # the two plants the rule needs: one frame past the bound (700 bytes), and one that puts the chain 64 or more
        # over the checked-in figure. A planted frame replaces the export fill as the deepest callee only when it is
        # deeper than the fill's chain (112 bytes on aarch64, 168 on x86_64, measured; a 64-byte plant read 1488,
        # unchanged), so the ratchet's plant is 240 bytes: about 1632 on aarch64, under its 2,048 bound, and about
        # 1680 on x86_64, which crosses its 1,638 bound as well, since x86_64 has only 46 bytes of room; each must
        # fail the part it plants
        local pv pbytes
        for pv in rule:700 ratchet:240; do
            pbytes=${pv#*:}
            if out=$(frame_analysis "plant${pv%%:*}" -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PLANT_FRAME \
                    -Wc,-DWE_MOD_TEST_PLANT_FRAME_BYTES="$pbytes") && [ "$out" != module-su-failed ]; then
                seg=$(printf '%s\n' "$out" | awk '$1 == "segment" { print $2 }')
                frame_rule "${seg:-0}" "plant-${pv%%:*}"
                case "${pv%%:*}" in
                rule)
                    [ "$FRAME_RULE" = fail ] \
                        && ok "frame's rule control: a planted $pbytes-byte frame under the decision frame fails the bound ($FRAME_WHY)" \
                        || bad "frame's rule control: a planted $pbytes-byte frame passed the bound ($FRAME_WHY), so the bound proves nothing" ;;
                *)
                    [ "$FRAME_RATCHET" = fail ] \
                        && ok "frame's ratchet control: a planted $pbytes-byte frame fails the ratchet, the bound reading $FRAME_RULE ($FRAME_WHY)" \
                        || bad "frame's ratchet control: a planted $pbytes-byte frame passed the ratchet ($FRAME_WHY), so the ratchet proves nothing" ;;
                esac
            else
                bad "frame: the $pbytes-byte plant build failed: $(tail -2 "$CTL/plant${pv%%:*}.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
            fi
        done
    else
        bad "frame: the -fstack-usage build failed: $(tail -2 "$CTL/stackusage.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
}

run_header_count_rows() { # C5's Apache arms: the one-pass byte counter over 99 lines, the 400 for 101 fields, the merge cap
    local MPM=event conf="$W/httpd-c5.conf" out r i maxv d0 d1 body exp fieldsline=""
    echo "  [the header pass, counted]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html/idx"
    echo page > "$W/html/index.html"
    for i in $(seq 1 1000); do : > "$W/html/idx/f$i"; done
    fresh_snapshot
    [ -n "$APXS" ] || { bad "hdrpass: no apxs to build the counter module"; return; }
    build_variant c5 -Wc,-DWE_MOD_TEST_COUNT_HDR_BYTES \
        || { bad "hdrpass: the counter build failed: $(tail -2 "$CTL/c5.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    c5_conf() { # c5_conf [extra directive]: one child, since the counter is a per-process cumulative that the
        # arms compare across connections, which the kernel hands to whichever child accepts
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/c5.so#" \
            | sed 's/^ServerLimit 2$/ServerLimit 1/; s/^StartServers 2$/StartServers 1/; s/^MinSpareThreads 32$/MinSpareThreads 8/; s/^MaxSpareThreads 32$/MaxSpareThreads 16/; s/^MaxRequestWorkers 32$/MaxRequestWorkers 16/'; conf_data; cat <<CONF
$(need_mod autoindex_module mod_autoindex.so)
<Directory $W/html/idx>
    Options +Indexes
</Directory>
LogFormat "%>s hbytes=%{WHISPER_EDGE_TEST_HEADER_BYTES}n" c5fmt
CustomLog $W/logs/c5.log c5fmt
${1:-}
CONF
        } > "$conf"
    }
    hb() { tail -1 "$W/logs/c5.log" | sed -n 's/.*hbytes=//p'; }   # the last request's cumulative note
    # ---- under the default limits: the longest value a field admits, the merge cap, the field count cap
    c5_conf
    if ! start_httpd "$conf" "$MPM"; then
        bad "hdrpass: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    maxv=0
    for v in 8171 8172 8173 8174; do
        { printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: '; printf '%*s' "$v" '' | tr ' ' 'x'; printf '\r\nConnection: close\r\n\r\n'; } > "$W/c5-req"
        r=$(raw_session "$PORT" "$W/c5-req" | awk '{print $1}')
        [ "$r" = 200 ] && maxv=$v
    done
    [ "$maxv" -gt 0 ] \
        && ok "hdrpass: the longest value a field admits after its name measures $maxv bytes (LimitRequestFieldSize 8190 minus the name and separator)" \
        || bad "hdrpass: no value length from 8171 to 8174 was admitted, so the field-size limit is not what this row assumes"
    # two such lines: httpd merges repeated fields and holds the MERGED value to LimitRequestFieldSize, so under
    # the default the trusted header the module reads is at most 8190 bytes however many lines carry it
    { printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n'; for i in 1 2; do printf 'X-Forwarded-For: '; printf '%*s' "$maxv" '' | tr ' ' 'x'; printf '\r\n'; done; printf 'Connection: close\r\n\r\n'; } > "$W/c5-two"
    d0=$(hb)
    r=$(raw_session "$PORT" "$W/c5-two" | awk '{print $1}')
    if [ "$r" = 400 ] && grep -q 'AH00560: Request header exceeds LimitRequestFieldSize after merging: X-Forwarded-For' "$W/logs/error.log"; then
        ok "hdrpass: two lines at $maxv bytes are refused 400 by httpd after merging (AH00560), so under the default LimitRequestFieldSize the merged trusted header the module reads is at most 8190 bytes"
    else
        bad "hdrpass: two maximal lines answered $r (AH00560 line: $(grep -c AH00560 "$W/logs/error.log"))"
    fi
    # Host plus 100 short lines: 101 fields, answered 400 by httpd's field count before the module reads anything
    { printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n'; for i in $(seq 1 100); do printf 'X-Forwarded-For: 198.51.100.%d\r\n' $((i % 250 + 1)); done; printf 'Connection: close\r\n\r\n'; } > "$W/c5-over"
    r=$(raw_session "$PORT" "$W/c5-over" | awk '{print $1}')
    grep -qi 'exceeds LimitRequestFields' "$W/logs/error.log" && fieldsline=yes
    [ "$r" = 400 ] && [ "$fieldsline" = yes ] \
        && ok "hdrpass: Host plus 100 lines is answered 400 (LimitRequestFields) before the module reads anything" \
        || bad "hdrpass: the 100-line request answered $r (LimitRequestFields line: ${fieldsline:-absent})"
    { printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'; } > "$W/c5-probe"
    raw_session "$PORT" "$W/c5-probe" >/dev/null
    d1=$(hb)
    [ -n "$d0" ] && [ "$d1" = "$d0" ] \
        && ok "hdrpass: and the counter reads $d1 after both refusals, unchanged, so a request httpd refuses counts nothing" \
        || bad "hdrpass: the counter moved across the refused requests: $d0 -> $d1"
    stop_httpd "$conf" "$MPM" || bad "hdrpass: httpd did not stop"
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    # ---- with the merge admitted: Host plus 99 lines at that length, one pass, every byte once
    c5_conf 'LimitRequestFieldSize 1000000'
    if ! start_httpd "$conf" "$MPM"; then
        bad "hdrpass: httpd did not start with the raised field size: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    # Host plus 99 lines is exactly the default LimitRequestFields of 100 fields; HTTP/1.1 keeps the connection
    # alive without a Connection line (one more field here was a 400 before the module ran, measured)
    { printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n'; } > "$W/c5-probe"
    { printf 'GET /idx/ HTTP/1.1\r\nHost: 127.0.0.1\r\n'; for i in $(seq 1 99); do printf 'X-Forwarded-For: '; printf '%*s' "$maxv" '' | tr ' ' 'x'; printf '\r\n'; done; printf '\r\n'; } > "$W/c5-big"
    out=$(raw_session "$PORT" "$W/c5-probe" "$W/c5-big" "$W/c5-probe")
    d0=$(tail -3 "$W/logs/c5.log" | head -1 | sed -n 's/.*hbytes=//p'); d1=$(tail -3 "$W/logs/c5.log" | tail -2 | head -1 | sed -n 's/.*hbytes=//p')
    r=$(printf '%s\n' "$out" | sed -n 2p | awk '{print $1}')
    body=$(printf '%s\n' "$out" | sed -n 2p | awk '{print $2}')
    exp=$((99 * maxv + 2 * 98))
    [ "$r" = 200 ] && [ "${body:-0}" -gt 20000 ] && [ -n "$d0" ] && [ $((d1 - d0)) = "$exp" ] \
        && ok "hdrpass: with the merge admitted (LimitRequestFieldSize 1000000), Host plus 99 lines at $maxv bytes over the 1,000-file index reads $((d1 - d0)) in the one-pass byte counter, exactly $exp: every line's bytes once, the merge's 98 gaps of two" \
        || bad "hdrpass: the 99-line request answered $r with body ${body:-0} and the counter moved ${d1:-?} - ${d0:-?}, wanted $exp"
    dark "hdrpass: the no-pool-allocation arm is the trace build's (R1's allocation counter), not this gate's"
    stop_httpd "$conf" "$MPM" || bad "hdrpass: httpd did not stop"
    fresh_snapshot
}

# =====================================================================================================
# the child's processes and descriptors: CGI children (S10), graceful restarts (R3), the signal mask
# (Q2), close-on-exec (Q4), mlock under a limit (M7)
# =====================================================================================================
run_cgi_rows() { # S10: a CGI child is a writer never; 1,000 of each interleaved across 5 ticks
    local MPM conf="$W/httpd-cgi.conf" bin="$W/html/bin" r i d_judged n0 n1 pids
    echo "  [CGI children]"
    for MPM in prefork event; do
        conf="$W/httpd-cgi-$MPM.conf"
        rm -rf "$W/html" "$W/counters"; mkdir -p "$bin"
        echo page > "$W/html/index.html"
        printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\necho "cgi $$"\n' > "$bin/x.cgi"; chmod 0755 "$bin/x.cgi"
        fresh_snapshot
        { conf_head "$MPM"; conf_data; cat <<CONF
$( [ "$MPM" = prefork ] && need_mod cgi_module mod_cgi.so || { need_mod cgid_module mod_cgid.so; echo "ScriptSock $W/cgisock"; } )
<Directory $bin>
    Options +ExecCGI
    AddHandler cgi-script .cgi
    Require all granted
</Directory>
<Location /judged>
    WhisperEdgeMode deny
</Location>
CONF
        } > "$conf"
        if grep -q '^#missing' "$conf"; then
            bad "cgi($MPM): this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
            continue
        fi
        if ! start_httpd "$conf" "$MPM"; then
            bad "cgi($MPM): httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            continue
        fi
        d_judged=$(ctx_digest "$(cfg_lines)" 'location "/judged"')
        : > "$W/cgipids"
        await "[ -n \"\$(tick_of)\" ]" 25 "a counter file"
        await_next_tick
        n0=$(rule_count "$d_judged" 1)
        for t in 1 2 3 4 5; do
            for i in $(seq 1 200); do
                curl -s --max-time 8 "http://127.0.0.1:$PORT/bin/x.cgi" | sed -n 's/^cgi //p' >> "$W/cgipids"
                code /judged/ "$LISTED" >/dev/null
            done
            await_next_tick
        done
        n1=$(rule_count "$d_judged" 1)
        pids=$(sort -u "$W/cgipids" | wc -l)
        local clash=""
        while read -r p; do
            [ -n "$p" ] && ls "$W/counters/$p"-*.cnt >/dev/null 2>&1 && clash="$clash $p"
        done < <(sort -u "$W/cgipids")
        [ "$pids" -ge 990 ] && [ -z "$clash" ] && [ "$n1" = "$((n0 + 1000))" ] \
            && ok "cgi($MPM): 1,000 CGI requests interleaved with judged ones across 5 ticks: $pids CGI children wrote no counter file, and the rule count moved by exactly 1,000 ($n0 -> $n1)" \
            || bad "cgi($MPM): $pids CGI children (clashing files:$clash) and the count moved $n0 -> $n1 for 1,000 judged"
        stop_httpd "$conf" "$MPM" || bad "cgi($MPM): httpd did not stop"
    done
    fresh_snapshot
}

run_graceful_rows() { # R3: the parent creates no pthread key across 50 graceful restarts
    local MPM=event conf="$W/httpd-r3.conf" master i n parentlines childlines
    echo "  [graceful restarts and the thread key]"
    [ -n "$APXS" ] || { bad "r3: no apxs to build the debug module"; return; }
    build_variant r3 -Wc,-DWE_MOD_TEST_COUNT_KEY_CREATE \
        || { bad "r3: the debug build failed: $(tail -2 "$CTL/r3.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
    echo page > "$W/html/index.html"
    fresh_snapshot
    { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/r3.so#"; conf_data; } > "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "r3: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    master=$(cat "$W/httpd-$MPM.pid")
    # each restart waits for a child of its own generation to log its key before the next is sent: -k graceful
    # returns once its signal is sent, and on a loaded host signals sent faster than the parent restarts
    # coalesce (measured: 50 sent back to back at load 40 made 47 key lines), which would make fewer than 50
    # restarts while the row claims 50
    await "grep -q 'thread key created' '$W/logs/error.log'" 20 "the first child's key line"
    for i in $(seq 1 50); do
        n=$(grep -c 'whisper edge: thread key created' "$W/logs/error.log")
        timeout 20 "$HTTPD" -f "$conf" -k graceful >/dev/null 2>&1 || { bad "r3: graceful restart $i did not return within 20s"; break; }
        await "[ \"\$(grep -c 'whisper edge: thread key created' '$W/logs/error.log')\" -gt $n ]" 30 "restart $i's children" \
            || { bad "r3: no child of graceful restart $i logged its key within 30 s"; break; }
    done
    await "[ \"\$(code_nohdr /)\" != 000 ]" 20 "serving after the restarts" \
        || bad "r3: not serving after 50 graceful restarts"
    n=$(grep -c 'whisper edge: thread key created' "$W/logs/error.log")
    parentlines=$(grep 'whisper edge: thread key created' "$W/logs/error.log" | grep -c "pid $master")
    childlines=$(grep 'whisper edge: thread key created' "$W/logs/error.log" | grep -vc "pid $master")
    local distinct
    distinct=$(grep 'whisper edge: thread key created' "$W/logs/error.log" | sed -n 's/.*\[pid \([0-9]*\).*/\1/p' | sort -u | grep -vc "^$master\$")
    [ "$parentlines" = 0 ] && [ "$childlines" = "$n" ] && [ "$n" -ge 50 ] && [ "$distinct" = "$childlines" ] \
        && ok "r3: across 50 graceful restarts the parent created no pthread key ($parentlines lines for pid $master) and each of the $childlines children created exactly one" \
        || bad "r3: $parentlines parent lines and $childlines child lines over $n, with $distinct distinct children"
    stop_httpd "$conf" "$MPM" || bad "r3: httpd did not stop"
    # the control: a build creating the key in the parent leaks one per configuration pass
    build_variant r3ctrl -Wc,-DWE_MOD_TEST_KEY_IN_PARENT \
        || { bad "r3: the parent-key control build failed: $(tail -2 "$CTL/r3ctrl.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    rm -rf "$W/counters"
    { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/r3ctrl.so#"; conf_data; } > "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "r3: the control server did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    master=$(cat "$W/httpd-$MPM.pid")
    for i in $(seq 1 5); do
        timeout 20 "$HTTPD" -f "$conf" -k graceful >/dev/null 2>&1 || true
    done
    parentlines=$(grep 'whisper edge: thread key created' "$W/logs/error.log" | grep -c "pid $master")
    [ "$parentlines" -ge 5 ] \
        && ok "r3's control: the parent-key build (WE_MOD_TEST_KEY_IN_PARENT) logs $parentlines parent lines over 5 restarts, one per pass, so the parent's zero above is the build's own doing" \
        || bad "r3's control: the parent-key build logged only $parentlines parent lines over 5 restarts, so the control is blind"
    stop_httpd "$conf" "$MPM" || bad "r3: the control server did not stop"
    fresh_snapshot
}

run_signal_rows() { # Q2: the module thread's signal mask, in a prefork child and an event child
    local MPM conf="$W/httpd-q2.conf" pid tid mask clash found tids t mb bits seen="" spec so nkids
    echo "  [the module thread's signal mask]"
    # the four fault signals' bits (SIGILL 4, SIGBUS 7, SIGFPE 8, SIGSEGV 11; zero-based 3, 6, 7, 10):
    # the thread's mask keeps them clear and everything else set that the kernel will block, so the
    # test is a predicate, not one literal value (SIGKILL and SIGSTOP are unblockable and read clear,
    # and this libc also leaves two real-time signals clear, both measured, neither a fault signal)
    local fault=$(( (1 << 3) | (1 << 6) | (1 << 7) | (1 << 10) ))
    # the control: the core's WE_MOD_TEST_THREAD_MASK, a module thread that inherits its caller's mask, on prefork
    if [ -n "$APXS" ] && build_variant threadmask -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_THREAD_MASK; then
        so=ok
    else
        so=""
        bad "q2: the inherited-mask control build failed: $(tail -2 "$CTL/threadmask.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    for spec in prefork:release event:release ${so:+prefork:control}; do
        MPM=${spec%%:*}
        conf="$W/httpd-q2-$MPM-${spec#*:}.conf"
        clash=0; seen=""; nkids=0
        rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
        echo page > "$W/html/index.html"
        fresh_snapshot
        if [ "${spec#*:}" = control ]; then
            { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/threadmask.so#"; conf_data; } > "$conf"
        else
            { conf_head "$MPM"; conf_data; } > "$conf"
        fi
        if ! start_httpd "$conf" "$MPM"; then
            bad "q2($MPM): httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            continue
        fi
        code / "$LISTED" >/dev/null
        for pid in $(pgrep -P "$(cat "$W/httpd-$MPM.pid")"); do
            nkids=$((nkids + 1))
            tids=$(ls "/proc/$pid/task" 2>/dev/null)
            found=0
            for tid in $tids; do
                mask=$(sed -n 's/^SigBlk:[[:space:]]*//p' "/proc/$pid/task/$tid/status" 2>/dev/null)
                [ -n "$mask" ] || continue
                mb=$((16#$mask))
                bits=0
                # bash reads the 64-bit word as signed, so the top-bit-set mask goes negative and a
                # shift loop over the whole word stops at once; count set bits in four 16-bit chunks
                for pos in 0 4 8 12; do
                    t=$((16#${mask:$pos:4}))
                    while [ "$t" -gt 0 ]; do
                        bits=$((bits + (t & 1)))
                        t=$((t >> 1))
                    done
                done
                if [ $((mb & fault)) -eq 0 ] && [ "$bits" -ge 56 ]; then
                    found=$((found + 1))
                    seen=$mask
                fi
            done
            [ "$found" = 1 ] || clash=$((clash + 1))
        done
        if [ "${spec#*:}" = control ]; then
            [ "$nkids" -ge 1 ] && [ "$clash" = "$nkids" ] \
                && ok "q2's control: the inherited-mask build (WE_MOD_TEST_THREAD_MASK) leaves all $nkids prefork children without a fully masked thread, so the rows above can fail" \
                || bad "q2's control: the inherited-mask build still shows a fully masked thread in $((nkids - clash)) of $nkids children, so the rows above prove nothing"
        else
            [ "$clash" = 0 ] \
                && ok "q2($MPM): every child holds exactly one thread with the full asynchronous mask (measured $seen: every signal set that the kernel blocks, SIGILL, SIGFPE, SIGSEGV and SIGBUS clear), the module thread" \
                || bad "q2($MPM): $clash child(ren) without exactly one masked thread"
        fi
        stop_httpd "$conf" "$MPM" || bad "q2($MPM): httpd did not stop"
        [ "${spec#*:}" = control ] && ctl_exit_clean "q2's control"
    done
    fresh_snapshot
}

# journal_reads <socket> <journalctl command>: 0 when a line sent to that syslog socket is read back by that journalctl
# within 5 s. A socket and a journalctl binary are not a journal: rsyslog creates /dev/log with no journald behind it,
# and journalctl then exits 0 and prints nothing (measured on a test host), which made q6 wait 45 s for lines that could
# never arrive and fail. So the probe is the round trip the arms depend on, as the uid that reads them
journal_reads() {
    local sock=$1 jc=$2 tag since out k
    [ -S "$sock" ] && command -v "${jc%% *}" >/dev/null 2>&1 && command -v logger >/dev/null 2>&1 || return 1
    tag="we-gate-journal-probe-$$-$RANDOM"
    since=$(date '+%F %T')
    logger -u "$sock" -p local1.notice -- "$tag" 2>/dev/null || return 1
    for k in 1 2 3 4 5 6 7 8 9 10; do
        out=$($jc --since "$since" --no-pager -q 2>/dev/null)
        grep -qF -- "$tag" <<<"$out" && return 0
        sleep 0.5
    done
    return 1
}
journal_rows() { # the detector itself, against a stand-in logger: a syslog socket with nothing behind it reads no journal
    local d="$W/jprobe" pid
    rm -rf "$d"; mkdir -p "$d"
    # the stand-in: a datagram socket that appends what it is sent to a file, as rsyslog writes /var/log/syslog
    python3 - "$d/log" "$d/received" <<'PY2' &
import os, socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
s.settimeout(0.5)
end = time.time() + 30
with open(sys.argv[2], "ab", buffering=0) as f:
    while time.time() < end and not os.path.exists(sys.argv[1] + ".stop"):
        try:
            f.write(s.recv(65536) + b"\n")
        except socket.timeout:
            pass
PY2
    pid=$!
    await "[ -S '$d/log' ]" 5 "the stand-in socket" || true
    printf '#!/bin/sh\nexit 0\n' > "$d/journalctl-empty"                         # journalctl with no journald: rc 0, nothing
    printf '#!/bin/sh\ncat %s/received\n' "$d" > "$d/journalctl-reads"          # a journal that reads the socket's lines
    chmod 0755 "$d/journalctl-empty" "$d/journalctl-reads"
    if journal_reads "$d/log" "$d/journalctl-empty"; then
        bad "q6's journal detection: a syslog socket with a journalctl that reads nothing (rsyslog without journald) was taken for a journal"
    elif journal_reads "$d/log" "$d/journalctl-reads"; then
        ok "q6's journal detection: a syslog socket whose journalctl reads nothing back (rsyslog without journald) is no journal, so q6 reads n/a there; the same socket with a journalctl that returns the probe line is one, so the detection can say yes"
    else
        bad "q6's journal detection: the probe line did not come back even through a journalctl that reads the socket's own file ($(wc -l < "$d/received" 2>/dev/null) line(s) received)"
    fi
    touch "$d/log.stop"; wait "$pid" 2>/dev/null
    rm -rf "$d"
}

run_q6_rows() { # Q6: the transition line's sinks, the ring's 512-byte cut, the head grammar
    local MPM=event D="$W/q6data" conf out rc i kids kid n f ent stalepat pg ctout bdigest jpat jts miss pat st bcode jc fc armed
    echo "  [the transition line's sinks, its cut and its head]"
    plane_fixture() { # plane_fixture <plane> <path> <generation> [valid_until_ms]: renamed in at 0444
        local fmt=2 idx="" synth="4 0"
        [ "$1" = reputation ] && { fmt=1; idx="--v4-index none --v6-index none"; }
        # the tenant plane takes 2 ranges, not 4: synthetic_ranges spreads n ranges at the same
        # positions for every plane, so at 4 the tenant's entry 0 would cover the same 51.51.51.51
        # the tor plane lists, and the walk would end at the tenant allow step (WE_STEP_TENANT)
        # before the context program ever ran; at 2 its ranges sit between the tor ones, so a
        # tor-exit client stays un-tenanted and the 256 rules judge it
        [ "$1" = tenant ] && synth="2 0"
        # shellcheck disable=SC2086
        python3 "$ROOT/core/make-test-snapshot.py" --plane "$1" --out "$2.q6new" --format "$fmt" $idx \
            --synthetic $synth --generation "$3" --valid-until "${4:-0}"
        chmod 0444 "$2.q6new"                # a mapped plane arms only at exactly 0444, measured
        mv "$2.q6new" "$2"
    }
    jpids() { # jpids <text> <since>: the distinct children whose line reached the system journal
        journalctl --since "$2" --no-pager -q 2>/dev/null | grep -F -- "$1" | sed -n 's/.*\[pid \([0-9]*\).*/\1/p' | sort -u | wc -l
    }

    # ---- the model of the formatter's own rule, computed before any run (fmt_ranges) ------------------
    # we_policy.c:3477-3499: neighbouring numbers join as "a-b", lone numbers print bare, commas between,
    # "-" when the list is empty. The bound program is the limit itself: 256 rules alternating allow and
    # log on tor_exit, so both class lists are 128 lone numbers and no compression is possible anywhere.
    if python3 - <<'PY' >"$W/q6-model.out" 2>&1
def fmt_ranges(ns):                       # we_policy.c:3477-3499, the same rule
    out, i = [], 0
    while i < len(ns):
        j = i
        while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1:
            j += 1
        out.append(str(ns[i]) if i == j else '%d-%d' % (ns[i], ns[j]))
        i = j + 1
    return ','.join(out) if out else '-'
assert fmt_ranges([3, 4, 5, 7]) == '3-5,7' and fmt_ranges([]) == '-'
head = 'plane tor stale out=tor tenant=fresh'    # the head grammar: the transitioning plane, the out set, the tenant state
def line(n):
    odds, evens = list(range(1, 2 * n + 1, 2)), list(range(2, 2 * n + 1, 2))
    return '%s: rules %s allow captures; rules %s disarmed' % (head, fmt_ranges(odds), fmt_ranges(evens))
odds_s = fmt_ranges(list(range(1, 257, 2)))
evens_s = fmt_ranges(list(range(2, 257, 2)))
parts = [(head, 'the head'), (':', 'the colon'), (' rules ', 'the first rules word'),
         (odds_s, 'the 128 odd rule numbers 1..255'), (' allow captures', 'the captures class'),
         ('; rules ', 'the second rules word'), (evens_s, 'the 128 even rule numbers 2..256'),
         (' disarmed', 'the disarmed class')]
full = ''.join(p[0] for p in parts)
for text, name in parts:
    shown = text if len(text) <= 44 else text[:41] + '...'
    print('%-34s %4d bytes  %s' % (name + ':', len(text), shown))
print('%-34s %4d bytes' % ('the uncut line:', len(full)))
print('the ring keeps the first 511 bytes (WE_MOD_RING_ENTRY 512), so the cut ends "...%s"' % full[495:511])
print('the same model gives %d bytes at 64 rules and %d at 140, so neither reaches the cut'
      % (len(line(32)), len(line(70))))
assert len(full) == 990 and len(line(32)) == 257 and len(line(70)) == 526
assert full[495:511] == '3,255 allow capt'   # 500 bytes through "...,255", then 11 bytes of " allow captures"
PY
    then
        sed 's/^/  note  q6 model: /' "$W/q6-model.out"
        ok "q6: the gate's own model of fmt_ranges computes the 256-rule transition line at 990 bytes uncut and the ring's 511-byte cut ends '255 allow capt', the derivation above"
    else
        bad "q6: the model's arithmetic failed: $(tr '\n' ' ' <"$W/q6-model.out" | cut -c1-300)"
    fi

    # ---- the bound program's own planes: three <plane>.bin files in one data directory -----------------
    rm -rf "$D" "$W/counters" "$W/html"
    # the logs directory too: the configuration tests below name the error log in it, and a group walked on
    # its own after a start that left none failed every configtest (AH02291, measured)
    mkdir -p "$D" "$W/html" "$W/logs"
    echo page > "$W/html/index.html"
    pg=$((GEN * 10 + 4000000))
    plane_fixture reputation "$D/reputation.bin" $((pg + 1))
    plane_fixture tor "$D/tor.bin" $((pg + 2))
    plane_fixture tenant "$D/tenant.bin" $((pg + 3))
    { echo "WhisperEdgeData $D"
      echo "WhisperEdgeRefresh 10"
      echo "WhisperEdgeTrustedProxy 127.0.0.1"
      echo "WhisperEdgeTrustedHeader X-Forwarded-For"
      echo "WhisperEdgeTrustedHops 2"
      echo "WhisperEdgeSummary $W/counters"
      echo '<Location /bound>'
      i=1
      while [ "$i" -le 256 ]; do
          if [ $((i % 2)) -eq 1 ]; then echo 'WhisperEdgePolicy allow if tor_exit'; else echo 'WhisperEdgePolicy log if tor_exit'; fi
          i=$((i + 1))
      done
      echo '</Location>'
    } > "$W/q6.body"

    # ---- the limit itself: 256 rules accepted over the three planes, the 257th refused with the fix ----
    { conf_head "$MPM"; cat "$W/q6.body"; } > "$W/q6.conf"
    chmod 0644 "$W/q6.conf"
    ctout=$("$HTTPD" -t -f "$W/q6.conf" 2>&1); rc=$?
    ctout=$(printf '%s\n' "$ctout" | sed 's/\\\(["\\]\)/\1/g')   # httpd's logger escapes a quote and a backslash
    bdigest=$(printf '%s\n' "$ctout" | grep -F 'location "/bound"' | sed -n 's/.*program \([0-9a-f]\{16\}\).*/\1/p' | head -1)
    if [ "$rc" = 0 ] && grep -qF 'location "/bound"' <<<"$ctout" \
        && [ "$(printf '%s\n' "$ctout" | grep -cF '256 rules')" -ge 1 ]; then
        ok "q6: the context program of 256 alternating rules configtests over the three-plane data directory, the limit itself (we_policy.h:70)"
    else
        bad "q6: the 256-rule program did not configtest: exit $rc: $(printf '%s\n' "$ctout" | grep -iE 'refused|AH00' | head -1 | cut -c1-250)"
    fi
    sed 's#^</Location>#WhisperEdgePolicy deny if tor_exit\n</Location>#' "$W/q6.conf" > "$W/q6over.conf"
    chmod 0644 "$W/q6over.conf"
    out=$("$HTTPD" -t -f "$W/q6over.conf" 2>&1); rc=$?
    out=$(printf '%s\n' "$out" | sed 's/\\\(["\\]\)/\1/g')
    if [ "$rc" != 0 ] && grep -qF 'over 256 rules in a context' <<<"$out"; then
        ok "q6: and the 257th rule is refused, the message naming the limit and its fix (sets)"
    else
        bad "q6: the 257th rule was not refused with the limit's message: exit $rc"
    fi

    # ---- the sink: with ErrorLog syslog:local1 the tick's lines are read back from the journal ---------
    # Apache's ErrorLog takes the system logger, not a gate-owned socket (nginx's error_log form), so the
    # arm reads the journal as the unprivileged uid the workers run as, which is also the uid that wrote.
    journal_rows
    Q6_JOURNAL=no
    journal_reads /dev/log journalctl && Q6_JOURNAL=yes
    if [ "$Q6_JOURNAL" = yes ]; then
        rm -rf "$W/counters"
        conf="$W/q6sys.conf"
        { conf_head "$MPM" | sed 's#^ErrorLog .*#ErrorLog syslog:local1#'; cat "$W/q6.body"; } > "$conf"
        chmod 0644 "$conf"
        jts=$(date '+%F %T')
        if ! start_httpd "$conf" "$MPM"; then
            bad "q6: the syslog conf did not start (its errors went to the journal): $(journalctl --since "$jts" --no-pager -q 2>/dev/null | grep -iE 'refused|error|AH0' | head -2 | tr '\n' ' ' | cut -c1-300)"
        else
            kids=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
            # shellcheck disable=SC2086
            set -- $kids
            n=$#
            jpat="plane tor.bin: generation $((pg + 4)) verified, arming"
            plane_fixture tor "$D/tor.bin" $((pg + 4)) 1    # valid_until 1 is 1970: armed at the next tick, stale at the one after
            if await "[ \"\$(jpids \"\$jpat\" \"\$jts\")\" -ge \"$n\" ]" 45 "every child's arming line at the journal"; then
                ok "q6: with ErrorLog syslog:local1, the arming line of each of the $n children reached the system journal, read back as the unprivileged uid"
            else
                bad "q6: the journal holds the arming line for $(jpids "$jpat" "$jts") of $n children after 45 s"
            fi
            jpat="plane tor.bin is stale: generation $((pg + 4))'s valid-until passed"
            if await "[ \"\$(jpids \"\$jpat\" \"\$jts\")\" -ge \"$n\" ]" 45 "every child's stale line at the journal"; then
                ok "q6: and the stale line of each child reached the journal with its text intact, through the same ring the error log reads"
            else
                bad "q6: the journal holds the stale line for $(jpids "$jpat" "$jts") of $n children after 45 s"
            fi
            await_next_tick
            miss=0
            for kid in $kids; do
                f=$(ls "$W/counters/$kid"-*.status 2>/dev/null | head -1)
                [ -n "$f" ] && grep -q 'log-dropped 0' "$f" || miss=$((miss + 1))
            done
            [ "$miss" = 0 ] \
                && ok "q6: every child's status file says log-dropped 0, so nothing the thread logged was lost to the ring" \
                || bad "q6: $miss child(ren) without log-dropped 0 in the status file"
            if [ "$(code_nohdr /)" = 200 ] && [ -n "$bdigest" ]; then
                bcode=$(code /bound 51.51.51.51)   # a tor-exit client: the fixture's first synthetic range ends at 0x44444444, so this
                # address is listed and the 256-rule program runs for it, its first rule firing at the access phase,
                # before the file lookup answers 404; the note's ctx: value fills only when the program ran
                # shellcheck disable=SC2046    # the split is the point: the access line's fields become the positional params
                set -- $(last_access)
                if [ "$bcode" = 404 ] && [ "$2" = 404 ]; then
                    case "$(field "$(last_access)" program)" in
                        *"ctx:$bdigest"*) ok "q6: the location still serves through the stale tor plane, and a tor-exit request into it is judged by the 256-rule program itself (program note ctx:$bdigest)" ;;
                        *) bad "q6: the /bound request's program note reads $(field "$(last_access)" program), not the bound location's digest" ;;
                    esac
                else
                    bad "q6: the /bound request did not complete as a logged 404: code $bcode, last line: $(last_access | cut -c1-120)"
                fi
            else
                bad "q6: the server did not serve through the stale plane: $(code_nohdr /)"
            fi
            stop_httpd "$conf" "$MPM" || bad "q6: the syslog httpd did not stop"
        fi
    else
        na "q6: the syslog arm needs a journal that reads back what the system logger socket is sent, and on this host a probe line sent to /dev/log did not come back through journalctl (no socket, no journalctl, or a syslog daemon with no journald behind it)"
    fi

    # ---- the plain file around a graceful: the line after the restart lands in the live file -----------
    rm -rf "$W/counters"
    conf="$W/q6file.conf"
    { conf_head "$MPM"; cat "$W/q6.body"; } > "$conf"
    chmod 0644 "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "q6: the plain-file conf did not start: $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    kids=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
    # shellcheck disable=SC2086
    set -- $kids
    n=$#
    plane_fixture tor "$D/tor.bin" $((pg + 20))          # fresh: this httpd binds and arms it
    stalepat="plane tor.bin is stale: generation $((pg + 21))'s valid-until passed"
    plane_fixture tor "$D/tor.bin" $((pg + 21)) 1        # transition 1: the stale swap, before the rotation
    await_plane "plane tor.bin: generation $((pg + 21)) verified, arming" "$n" \
        && await_plane "$stalepat" "$n" \
        && ok "q6: the first transition (the stale) is logged by each of the $n children into the plain file before the rotation" \
        || bad "q6: the stale transition reached $(plane_pids "$stalepat") of $n children in the plain file"
    [ "$(code_nohdr /)" = 200 ] || bad "q6: the plain-file httpd stopped serving at the stale transition: $(code_nohdr /)"
    mv "$W/logs/error.log" "$W/logs/error.log.1"
    timeout 30 "$HTTPD" -f "$conf" -k graceful
    await "children_turned_over \"$kids\"" 40 "the old children gone and $PINNED_CHILDREN new ones" \
        && ok "q6: the graceful after the rotation turned the children over (a living child never reopens its error log, so the old children finish on the rotated file)" \
        || bad "q6: the children did not turn over after the graceful"
    kids=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
    # shellcheck disable=SC2086
    set -- $kids
    n=$#
    plane_fixture tor "$D/tor.bin" $((pg + 22))          # transition 2: the re-arm, after the graceful
    pat="plane tor.bin: generation $((pg + 22)) verified, arming"
    if await_plane "$pat" "$n" && [ "$(code_nohdr /)" = 200 ]; then
        ok "q6: the second transition (the re-arm) after the graceful is logged by each of the $n new children into the live error.log, and the location still serves"
    else
        bad "q6: the re-arm after the graceful reached $(plane_pids "$pat") of $n children; serving $(code_nohdr /)"
    fi
    grep -qF "generation $((pg + 22)) verified" "$W/logs/error.log.1" \
        && bad "q6: the re-arm line landed in the ROTATED error.log.1, so the new children hold the old descriptor" \
        || ok "q6: and the rotated error.log.1 holds no line of the second transition: the new children write the live file"
    await_next_tick
    miss=0
    # the ring holds the core's transition line since the emitter was wired into we_mod_planes_apply (the
    # dependents line, "plane tor armed out=... tenant=...: ..."), not the verification message, so the child's
    # logged copy of THAT line is what the status file's last transition text must equal byte for byte
    for kid in $kids; do
        ent=$(grep -E "\[pid ${kid}[]:]" "$W/logs/error.log" | grep -F "whisper edge: plane tor armed out=" | tail -1 | sed -E 's/^.* whisper edge: //')
        f=$(ls "$W/counters/$kid"-*.status 2>/dev/null | head -1)
        st=$(sed -n 's/^transition [0-9]* "\(plane tor armed out=.*\)"$/\1/p' "$f" 2>/dev/null | tail -1)
        if [ -n "$ent" ] && [ "$ent" = "$st" ]; then
            continue
        fi
        miss=$((miss + 1))
    done
    [ "$miss" = 0 ] \
        && ok "q6: each new child's transition line in the file (the core's dependents line of the re-arm) and its status file's last transition text are byte-equal, the channel the ring's cut is compared through" \
        || bad "q6: $miss child(ren) whose re-arm message and status transition text disagree"
    miss=0
    for kid in $kids; do
        f=$(ls "$W/counters/$kid"-*.status 2>/dev/null | head -1)
        [ -n "$f" ] && grep -q 'log-dropped 0' "$f" || miss=$((miss + 1))
    done
    [ "$miss" = 0 ] \
        && ok "q6: and every new child's status file still says log-dropped 0 across the rotation and the graceful" \
        || bad "q6: $miss new child(ren) without log-dropped 0 in the status file"
    cp "$W/logs/error.log" "$W/q6-file-arm.log"
    stop_httpd "$conf" "$MPM" || bad "q6: the plain-file httpd did not stop"

    # ---- the control that can fail: the refresher's line dropped at the logger -------------------------
    if [ -z "$APXS" ]; then
        dark "q6: the drop control needs apxs on this host, so the arms above stand uncontrolled this run"
    elif [ "${Q6_JOURNAL:-no}" != yes ]; then
        na "q6: the drop control reads the journal, as the syslog arm does, and this host has no journal that reads the system logger socket back"
    elif build_variant droplog -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_DROP_LOG; then
        rm -rf "$W/counters"
        conf="$W/q6dropsys.conf"
        { conf_head "$MPM" | sed -e 's#^ErrorLog .*#ErrorLog syslog:local1#' \
            -e "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/droplog.so#"; cat "$W/q6.body"; } > "$conf"
        chmod 0644 "$conf"
        jts=$(date '+%F %T')    # before the start: the parent's bind lines land inside the window, and the liveness proof below reads them
        if start_httpd "$conf" "$MPM"; then
            plane_fixture tor "$D/tor.bin" $((pg + 30)) 1
            sleep 30                            # two refresh ticks past the swap, the window the real lines landed in
            journalctl --since "$jts" --no-pager -q 2>/dev/null >"$W/q6drop.journal" || true
            jc=$(grep -cF "plane tor.bin: generation $((pg + 22)) verified, arming" "$W/q6drop.journal")
            armed=0
            for kid in $(pgrep -P "$HTTPD_PID"); do
                f=$(ls "$W/counters/$kid"-*.status 2>/dev/null | head -1)
                [ -n "$f" ] && grep -qE "plane tor (armed|stale) generation $((pg + 30)) " "$f" && armed=$((armed + 1))
            done
            if [ "$(code_nohdr /)" = 200 ] && [ "$jc" = 1 ] && [ "$armed" = "$PINNED_CHILDREN" ] \
                && [ -z "$(grep -F "generation $((pg + 30))" "$W/q6drop.journal" | grep -vE "\[pid ${HTTPD_PID}[]:]")" ]; then
                ok "q6: the control build (WE_MOD_TEST_DROP_LOG) served the same traffic, its parent's bind line of the armed generation is at the journal exactly once (the sink alive, the children's copies fallen with it) and every child's status file holds the swapped generation on its tor line (the state word stale: armed, then its valid-until passed), yet neither the arming nor the stale line of that generation arrived: the syslog arm above fails when the line is dropped"
            else
                bad "q6: the drop control: serving $(code_nohdr /), bind lines $jc, children armed at the swap $armed, swapped-generation lines at the journal $(grep -F "generation $((pg + 30))" "$W/q6drop.journal" | grep -vcE "\[pid ${HTTPD_PID}[]:]")"
            fi
            rm -f "$W/q6drop.journal"
            stop_httpd "$conf" "$MPM" || bad "q6: the drop-control syslog httpd did not stop"
        else
            bad "q6: the drop-control syslog conf did not start: $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-200)"
        fi
        rm -rf "$W/counters"
        conf="$W/q6dropfile.conf"
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/droplog.so#"; cat "$W/q6.body"; } > "$conf"
        chmod 0644 "$conf"
        if start_httpd "$conf" "$MPM"; then
            plane_fixture tor "$D/tor.bin" $((pg + 40)) 1
            sleep 30
            fc=$(grep -cF "plane tor.bin: generation $((pg + 30)) verified, arming" "$W/logs/error.log")
            armed=0
            for kid in $(pgrep -P "$HTTPD_PID"); do
                f=$(ls "$W/counters/$kid"-*.status 2>/dev/null | head -1)
                [ -n "$f" ] && grep -qE "plane tor (armed|stale) generation $((pg + 40)) " "$f" && armed=$((armed + 1))
            done
            if [ "$(code_nohdr /)" = 200 ] && [ "$fc" = 1 ] && [ "$armed" = "$PINNED_CHILDREN" ] \
                && [ -z "$(grep -F "generation $((pg + 40))" "$W/logs/error.log" | grep -vE "\[pid ${HTTPD_PID}[]:]")" ]; then
                ok "q6: and the same control build logged its parent's bind line of the armed generation into the plain file exactly once (the sink alive, the children's copies fallen with it) and every child's status file holds the swapped generation on its tor line, while neither the arming nor the stale line of that generation is in the file: the file arm fails when the refresher's line is dropped, never vacuously"
            else
                bad "q6: the file drop control: serving $(code_nohdr /), bind lines $fc, children armed at the swap $armed, swapped-generation lines in the file $(grep -F "generation $((pg + 40))" "$W/logs/error.log" | grep -vcE "\[pid ${HTTPD_PID}[]:]")"
            fi
            stop_httpd "$conf" "$MPM" || bad "q6: the drop-control file httpd did not stop"
        else
            bad "q6: the drop-control file conf did not start: $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-200)"
        fi
    else
        bad "q6: the drop-control build failed: $(tail -2 "$CTL/droplog.log" 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
    fi

    # ---- the bound arm and the head arms, against the core's emitter ------------------------------------
    # Fresh planes at the start, no publish after it: tor goes stale 25 s in and reputation 10 s later, so the
    # FIRST transition after the workers start is the one measured. Each child logs the core's entry and pushes
    # it into its ring; the /bound program's entry is the 990-byte line the model above computed, cut to 511 in
    # the ring, and /two's reputation rule gives the second head. Read per child: its logged entries against
    # its own status file's ring, byte for byte.
    q6_bound_phase() { # q6_bound_phase <module> <label> <tenant valid-until ms, 0 for none> -> $W/q6b-<label>.out
        local so=$1 lbl=$2 tvu=$3 now kids n
        rm -rf "$W/counters"
        now=$(date +%s%3N)
        plane_fixture reputation "$D/reputation.bin" $((pg + 50)) $((now + 35000))
        plane_fixture tor "$D/tor.bin" $((pg + 51)) $((now + 25000))
        plane_fixture tenant "$D/tenant.bin" $((pg + 52)) "$tvu"
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $so#"; cat "$W/q6.body"
          echo '<Location /two>'; echo 'WhisperEdgePolicy "deny if listed >= high"'; echo 'WhisperEdgePolicy log if tor_exit'; echo '</Location>'
        } > "$W/q6b.conf"
        chmod 0644 "$W/q6b.conf"
        start_httpd "$W/q6b.conf" "$MPM" || { echo "start-failed $(tail -2 "$W/start-$MPM.err" | tr '\n' ' ' | cut -c1-200)" > "$W/q6b-$lbl.out"; return 1; }
        kids=$(pgrep -P "$HTTPD_PID" | sort | tr '\n' ' ')
        # shellcheck disable=SC2086
        set -- $kids
        n=$#
        await "[ \"\$(plane_pids 'whisper edge: plane reputation stale out=reputation,tor')\" -ge $n ]" 75 "every child's second transition"
        await_next_tick
        python3 - "$W/logs/error.log" "$W/counters" "$kids" <<'PY' > "$W/q6b-$lbl.out"
import glob, re, sys
log, cdir, kids = sys.argv[1], sys.argv[2], sys.argv[3].split()
def unesc(s):
    o = bytearray(); i = 0
    while i < len(s):
        c = s[i]
        if c == 0x5c and i + 1 < len(s):
            if s[i + 1] == ord("x"):
                o.append(int(s[i + 2:i + 4], 16)); i += 4; continue
            o.append(s[i + 1]); i += 2; continue
        o.append(c); i += 1
    return bytes(o)
lines = open(log, "rb").read().split(b"\n")
TOR = b"plane tor stale out=tor tenant="
REP = b"plane reputation stale out=reputation,tor tenant="
res = {"kids": len(kids)}
bad = []
for k in kids:
    ent = [l.split(b"whisper edge: ", 1)[1] for l in lines
           if re.search(rb"\[pid " + k.encode() + rb"[]:]", l) and re.search(rb"whisper edge: plane [a-z-]+ [a-z]+ out=", l)]
    fs = glob.glob("%s/%s-*.status" % (cdir, k))
    ring = []
    dropped = None
    if fs:
        for l in open(fs[0], "rb").read().split(b"\n"):
            m = re.match(rb'^transition [0-9]+ "(.*)"$', l)
            if m:
                ring.append(unesc(m.group(1)))
            m = re.search(rb"log-dropped ([0-9]+)", l)
            if m:
                dropped = int(m.group(1))
    b_log = [e for e in ent if e.startswith(TOR) and b"rules 1,3,5" in e]
    b_ring = [e for e in ring if e.startswith(TOR) and b"rules 1,3,5" in e]
    h_log = [e for e in ent if e.startswith(REP)]
    h_ring = [e for e in ring if e.startswith(REP)]
    rec = {
        "bound_log_len": len(b_log[0]) if b_log else 0,
        "bound_ring_len": len(b_ring[0]) if b_ring else 0,
        "bound_equal": int(bool(b_log) and bool(b_ring) and b_log[0] == b_ring[0]),
        "bound_head": (b_log[0].split(b":")[0] if b_log else b"").decode(),
        "bound_log_n": len(b_log), "bound_ring_n": len(b_ring),
        "head2": (h_log[0].split(b":")[0] if h_log else b"").decode(),
        "head2_equal": int(bool(h_log) and bool(h_ring) and h_log[0] == h_ring[0]),
        "head2_text": int(bool(h_log) and b":" in h_log[0]),
        "all_in_ring": int(bool(ent) and all(e in ring for e in ent)),
        "dropped": dropped if dropped is not None else -1,
    }
    for key, v in rec.items():
        print("%s %s %s" % (k, key, v))
PY
        stop_httpd "$W/q6b.conf" "$MPM" || echo "stop-failed" >> "$W/q6b-$lbl.out"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        return 0
    }
    q6v() { awk -v k="$2" '$2 == k { $1 = ""; $2 = ""; sub(/^  /, ""); print }' "$W/q6b-$1.out" | sort -u | paste -sd'|'; }   # the distinct values over the children, a value may hold spaces
    q6_bound_phase "$MODULE" main 0
    if grep -q '^start-failed' "$W/q6b-main.out"; then
        bad "q6: the bound phase did not start: $(cut -c1-200 "$W/q6b-main.out")"
    else
        [ "$(q6v main bound_log_len)" = 511 ] && [ "$(q6v main bound_ring_len)" = 511 ] && [ "$(q6v main bound_equal)" = 1 ] \
            && ok "q6: the first transition after the workers start (tor going stale, no publish before it) is logged by each child, and the 256-rule entry is exactly 511 bytes in the log and in the ring, byte for byte the same: the model's 990 cut at the ring's bound" \
            || bad "q6: the 256-rule entry: logged $(q6v main bound_log_len) bytes, ring $(q6v main bound_ring_len), equal $(q6v main bound_equal) (per child)"
        [ "$(q6v main bound_head)" = "plane tor stale out=tor tenant=fresh" ] \
            && ok "q6: its head is intact: plane tor stale out=tor tenant=fresh" \
            || bad "q6: the 256-rule entry's head reads '$(q6v main bound_head)'"
        [ "$(q6v main head2)" = "plane reputation stale out=reputation,tor tenant=fresh" ] && [ "$(q6v main head2_equal)" = 1 ] && [ "$(q6v main head2_text)" = 1 ] \
            && ok "q6: the second transition's head reads out=reputation,tor in plane order, with its dependents text, the entry equal to the status file's" \
            || bad "q6: the second head: '$(q6v main head2)', equal $(q6v main head2_equal), text $(q6v main head2_text)"
        [ "$(q6v main all_in_ring)" = 1 ] \
            && ok "q6: every transition entry each child logged is one of its status file's ring entries, byte for byte" \
            || bad "q6: a logged transition entry is absent from its child's ring (per child: $(q6v main all_in_ring))"
        [ "$(q6v main dropped)" = 0 ] && ok "q6: log-dropped 0 on every child's status file" || bad "q6: log-dropped reads $(q6v main dropped)"
        echo "    [q6: the 256-rule entry per child: logged $(q6v main bound_log_n) time(s), in the ring $(q6v main bound_ring_n) time(s) (printed, not gated: one transition, one entry, is the expectation)]"
    fi
    # a tenant plane past its valid-until and its 48 h grace: the head's tenant word is lapsed
    q6_bound_phase "$MODULE" lapsed $(( $(date +%s%3N) - 49 * 3600 * 1000 ))
    [ "$(q6v lapsed bound_head)" = "plane tor stale out=tor tenant=lapsed" ] \
        && ok "q6: with tenant.bin past its valid-until and its 48 h grace, the head reads tenant=lapsed" \
        || bad "q6: the lapsed head reads '$(q6v lapsed bound_head)' ($(head -c 200 "$W/q6b-lapsed.out" | tr '\n' ' '))"
    # the controls: the uncut text handed to the logger, and the head alone handed to it
    if build_variant uncutlog -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_UNCUT_LOG && q6_bound_phase "$CTL/uncutlog.so" uncut 0; then
        [ "$(q6v uncut bound_log_len)" = 990 ] && [ "$(q6v uncut bound_ring_len)" = 511 ] \
            && ok "q6: the uncut-log control (WE_MOD_TEST_UNCUT_LOG) logs the 256-rule entry at 990 bytes, the model's figure, against the ring's 511, so the 511 above is the cut" \
            || bad "q6: the uncut-log control logged $(q6v uncut bound_log_len) bytes against the ring's $(q6v uncut bound_ring_len)"
    else
        bad "q6: the uncut-log control did not build or run: $(tail -2 "$CTL/uncutlog.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    if build_variant headalone -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_HEAD_ALONE && q6_bound_phase "$CTL/headalone.so" headalone 0; then
        [ "$(q6v headalone all_in_ring)" = 0 ] && [ "$(q6v headalone head2_text)" = 0 ] \
            && ok "q6: the head-alone control (WE_MOD_TEST_HEAD_ALONE) logs lines absent from the ring (no dependents text), so the byte comparison above can fail" \
            || bad "q6: the head-alone control's lines matched the ring (in ring $(q6v headalone all_in_ring), text $(q6v headalone head2_text))"
    else
        bad "q6: the head-alone control did not build or run: $(tail -2 "$CTL/headalone.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    rm -f "$W"/q6b-*.out "$W/q6b.conf"
    rm -rf "$D"
}

# =====================================================================================================
# T11 and T5's h2 twin: HTTP/2 and h2c on the main listener, the PROXY-protocol listener, the
# hold-harmless match and the no-address counter of the debug build
# =====================================================================================================
run_h2_rows() {
    local MPM=event P2=$((PORT + 1)) P3=$((PORT + 2)) conf="$W/httpd-h2.conf" out
    local v11 vh2c vh2 r r2 r3 n z line1 line2 line3 body11 d_floor d_ctx f
    local ALIASED=no lo_addrs
    echo "  [HTTP/2 and h2c; the PROXY-protocol listener]"
    # the row needs mod_http2 and mod_ssl; a httpd without either leaves the whole group unwalked
    for f in "$(need_mod http2_module mod_http2.so)" "$(need_mod ssl_module mod_ssl.so)"; do
        case $f in
            \#missing*) dark "h2: this httpd ships no $(printf '%s' "$f" | sed 's/#missing //'), so the HTTP/2 arms stand unwalked this run"; return ;;
        esac
    done
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
    echo page > "$W/html/index.html"
    # the listed range must hold the walked client ($LISTED) and the raw-peer arm's temporary
    # loopback alias at 12.34.56.78 in one span, an address the hold-harmless table does not cover
    # (measured: the generated table's v4 entries jump from 10/8 to 17.253.14.0), while the
    # balancer's alias at 12.34.55.78 sits just below the span: the floor denies a listed RAW peer,
    # and on the PROXY listener the unlisted balancer passes the floor so the vhost rule alone
    # decides on the header's source
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.bin" "$GEN" 0 4 203569152 3323068671
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/h2key.pem" -out "$W/h2crt.pem" -days 2 \
        -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
    h2_conf() { # h2_conf <module> <proxy on|off> <debug 0|1> <out path>: the three-listener configuration
        {
            conf_head "$MPM"; conf_data
            need_mod http2_module mod_http2.so
            need_mod ssl_module mod_ssl.so
            echo 'Protocols h2 h2c'
            echo 'WhisperEdgeMode deny'
            echo 'WhisperEdgePolicyFloor "deny if listed >= critical"'
            if [ "$3" = 1 ]; then
                echo 'LogFormat "%h %>s unset=%{WHISPER_EDGE_TEST_UNSET_ADDR}n" unsetfmt'
                echo "CustomLog $W/logs/access-unset.log unsetfmt"
            fi
            echo "Listen 127.0.0.1:$P2"
            echo "Listen 127.0.0.1:$P3"
            echo "<VirtualHost 127.0.0.1:$P2>"
            echo '    SSLEngine on'
            echo "    SSLCertificateFile $W/h2crt.pem"
            echo "    SSLCertificateKeyFile $W/h2key.pem"
            echo '    Protocols h2 http/1.1'
            echo "    CustomLog $W/logs/access.log whisperfmt"
            [ "$3" = 1 ] && echo "    CustomLog $W/logs/access-unset.log unsetfmt"
            echo '</VirtualHost>'
            echo "<VirtualHost 127.0.0.1:$P3>"
            [ "$2" = on ] && echo '    RemoteIPProxyProtocol On'
            echo '    WhisperEdgeMode deny'
            echo '    WhisperEdgePolicy "deny if listed >= critical"'
            echo "    CustomLog $W/logs/access.log whisperfmt"
            [ "$3" = 1 ] && echo "    CustomLog $W/logs/access-unset.log unsetfmt"
            echo '</VirtualHost>'
        } | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#" > "$4"
    }
    h2c() { # h2c <path> [entry]: "<code> <version>" over h2c prior knowledge, the entry the proxy appended
        if [ -n "${2:-}" ]; then
            curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge \
                -H "X-Forwarded-For: $2, $HOP" "http://127.0.0.1:$PORT$1" 2>/dev/null
        else
            curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge \
                "http://127.0.0.1:$PORT$1" 2>/dev/null
        fi
    }
    h2s() { # h2s <path> [entry]: "<code> <version>" over TLS with ALPN h2
        if [ -n "${2:-}" ]; then
            curl -s -k -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 \
                -H "X-Forwarded-For: $2, $HOP" "https://127.0.0.1:$P2$1" 2>/dev/null
        else
            curl -s -k -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 \
                "https://127.0.0.1:$P2$1" 2>/dev/null
        fi
    }
    # the configuration test's PROXY line, exactly when the directive is present
    h2_conf "$MODULE" on 0 "$conf"
    out=$("$HTTPD" -t -f "$conf" 2>&1)
    if grep -qF "whisper edge: policy: the floor judges the PROXY-protocol load balancer on 127.0.0.1:$P3, not the client" <<<"$out" \
        && grep -qF "the PROXY header's source is not read; a balancer that does not append to X-Forwarded-For lets the client choose the judged address" <<<"$out"; then
        ok "h2: with RemoteIPProxyProtocol on the second listener the configuration test prints the PROXY line, naming that virtual host and the trusted-header advice"
    else
        bad "h2: the configuration test's PROXY line: $(printf '%s\n' "$out" | grep -F 'PROXY' | head -1 | cut -c1-250)"
    fi
    h2_conf "$MODULE" off 0 "$conf"
    out=$("$HTTPD" -t -f "$conf" 2>&1)
    if ! grep -qF 'PROXY-protocol load balancer' <<<"$out"; then
        ok "h2: without the directive no PROXY line is printed (the control)"
    else
        bad "h2: a PROXY line appeared without RemoteIPProxyProtocol: $(printf '%s\n' "$out" | grep -F 'PROXY' | head -1 | cut -c1-250)"
    fi
    h2_conf "$MODULE" on 0 "$conf"
    if ! start_httpd "$conf" "$MPM"; then
        bad "h2: httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        fresh_snapshot
        return
    fi
    d_floor=$(ctx_digest "$(cfg_lines)" floor)
    # the PROXY listener's own program, taken from its rendered context: the second virtual host is
    # the only "localhost" that prints 'inherits nothing' (the TLS one prints 'no lines of its own',
    # the main 'server "127.0.0.1"'), so the main server's sugar default cannot be picked by mistake
    d_ctx=$(cfg_lines | grep -F 'server "localhost"' | grep -F 'inherits nothing' | sed -n 's/.*program \([0-9a-f]\{16\}\).*/\1/p' | head -1)
    # the floor over h2 exactly as over HTTP/1.1: the same client, the same three notes
    v11=$(code / "$LISTED"); line1=$(last_access)
    vh2c=$(h2c / "$LISTED"); line2=$(last_access)
    vh2=$(h2s / "$LISTED"); line3=$(last_access)
    if [ "$v11" = 403 ] && [ "${vh2c% *}" = 403 ] && [ "${vh2c#* }" = 2 ] && [ "${vh2% *}" = 403 ] && [ "${vh2#* }" = 2 ] \
        && [ "$(field "$line1" rule)" = "floor:1" ] && [ "$(field "$line2" rule)" = "floor:1" ] && [ "$(field "$line3" rule)" = "floor:1" ] \
        && [ "$(field "$line1" floor)" = "$LISTED" ] && [ "$(field "$line2" floor)" = "$LISTED" ] && [ "$(field "$line3" floor)" = "$LISTED" ] \
        && [ "$(field "$line1" program)" = "floor:$d_floor ctx:-" ] && [ "$(field "$line2" program)" = "floor:$d_floor ctx:-" ] && [ "$(field "$line3" program)" = "floor:$d_floor ctx:-" ]; then
        ok "h2: the listed client behind the trusted proxy is denied by the floor over HTTP/1.1, h2c and TLS-h2 alike, 403 with rule floor:1, floor $LISTED and the same program note, the negotiated versions 1.1, ${vh2c#* } and ${vh2#* }"
    else
        bad "h2: the floor deny differs across protocols: 1.1 $v11 / $(field "$line1" rule) $(field "$line1" floor) $(field "$line1" program); h2c $vh2c / $(field "$line2" rule) $(field "$line2" floor) $(field "$line2" program); TLS $vh2 / $(field "$line3" rule) $(field "$line3" floor) $(field "$line3" program)"
    fi
    body11=$(curl -s --http2-prior-knowledge --max-time 8 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" 2>/dev/null)
    if [ "$body11" = "Forbidden by the Whisper edge policy floor." ] \
        && grep -qi '^Cache-Control: no-store' <<<"$(curl -s -o /dev/null -D - --http2-prior-knowledge --max-time 8 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" 2>/dev/null)"; then
        ok "h2: over h2c the deny carries the module's own fixed body and Cache-Control: no-store, the HTTP/1.1 floor deny byte for byte"
    else
        bad "h2: the h2c deny's body or no-store header differs from the HTTP/1.1 floor deny: $(printf '%s' "$body11" | cut -c1-80)"
    fi
    # no header: the floor address is the primary connection's peer on every protocol
    r=$(code_nohdr /); line1=$(last_access)
    vh2c=$(h2c /); line2=$(last_access)
    vh2=$(h2s /); line3=$(last_access)
    if [ "$r" = 200 ] && [ "${vh2c% *}" = 200 ] && [ "${vh2c#* }" = 2 ] && [ "${vh2% *}" = 200 ] && [ "${vh2#* }" = 2 ] \
        && [ "$(field "$line1" floor)" = 127.0.0.1 ] && [ "$(field "$line2" floor)" = 127.0.0.1 ] && [ "$(field "$line3" floor)" = 127.0.0.1 ] \
        && [ "$(field "$line1" reason)" = "hold-harmless,floor-header-missing" ] && [ "$(field "$line2" reason)" = "hold-harmless,floor-header-missing" ] \
        && [ "$(field "$line3" reason)" = "hold-harmless,floor-header-missing" ]; then
        ok "h2: with no header the floor address is the primary connection's peer (127.0.0.1) over HTTP/1.1, h2c and TLS-h2 alike, the reason hold-harmless,floor-header-missing on all three"
    else
        bad "h2: the no-header floor address or reason differs: 1.1 $r / $(field "$line1" floor) $(field "$line1" reason); h2c $vh2c / $(field "$line2" floor) $(field "$line2" reason); TLS $vh2 / $(field "$line3" floor) $(field "$line3" reason)"
    fi
    # a lone header entry under two trusted hops never reaches a judged entry: the walk parses one
    # entry where it needs two, marks the tail unparsed and hands the floor the parsed entry; the
    # covered address still passes the floor, with no exemption and the unparsed note on the reason
    r=$(curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 \
        -H 'X-Forwarded-For: 8.8.8.8' "http://127.0.0.1:$PORT/" 2>/dev/null); line1=$(last_access)
    r2=$(curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge \
        -H 'X-Forwarded-For: 8.8.8.8' "http://127.0.0.1:$PORT/" 2>/dev/null); line2=$(last_access)
    r3=$(curl -sk -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 \
        -H 'X-Forwarded-For: 8.8.8.8' "https://127.0.0.1:$P2/" 2>/dev/null); line3=$(last_access)
    if [ "${r% *}" = 200 ] && [ "${r2% *}" = 200 ] && [ "${r2#* }" = 2 ] && [ "${r3% *}" = 200 ] && [ "${r3#* }" = 2 ] \
        && [ "$(field "$line1" floor)" = 8.8.8.8 ] && [ "$(field "$line1" reason)" = "floor-header-unparsed" ] \
        && [ "$(field "$line2" floor)" = 8.8.8.8 ] && [ "$(field "$line2" reason)" = "floor-header-unparsed" ] \
        && [ "$(field "$line3" floor)" = 8.8.8.8 ] && [ "$(field "$line3" reason)" = "floor-header-unparsed" ]; then
        ok "h2: a lone X-Forwarded-For entry never reaches a judged entry under two trusted hops: over HTTP/1.1, h2c and TLS-h2 the covered 8.8.8.8 passes as the parsed tail's floor address, the reason floor-header-unparsed on all three, no exemption claimed"
    else
        bad "h2: the lone-entry shape: 1.1 $r / $(field "$line1" floor) $(field "$line1" reason); h2c $r2 / $(field "$line2" floor) $(field "$line2" reason); TLS $r3 / $(field "$line3" floor) $(field "$line3" reason)"
    fi
    # the CDN shape: the proxy appends its hop, so the covered entry sits past the skipped hop; it is
    # judged but ineligible, the exemption does not follow it there, and the covered floor address
    # passes with no reason at all, the same address the covered-peer arm below judges exempt. The
    # server's address stays the hop ($HOP: mod_remoteip takes no private client from a trusted proxy),
    # and step 4 judges it by the vhost's rules with no exemption of its own: listed nowhere, it gets the
    # default allow, reason "-", never hold-harmless although $HOP is benchmarking space
    r=$(code / 10.20.30.40); line1=$(last_access)
    r2=$(h2c / 10.20.30.40); line2=$(last_access)
    r3=$(h2s / 10.20.30.40); line3=$(last_access)
    if [ "$r" = 200 ] && [ "${r2% *}" = 200 ] && [ "${r2#* }" = 2 ] && [ "${r3% *}" = 200 ] && [ "${r3#* }" = 2 ] \
        && [ "$(field "$line1" floor)" = 10.20.30.40 ] && [ "$(field "$line1" reason)" = "-" ] \
        && [ "$(field "$line2" floor)" = 10.20.30.40 ] && [ "$(field "$line2" reason)" = "-" ] \
        && [ "$(field "$line3" floor)" = 10.20.30.40 ] && [ "$(field "$line3" reason)" = "-" ]; then
        ok "h2: the CDN shape judges the covered entry past the skipped hop: over HTTP/1.1, h2c and TLS-h2 the same 10.20.30.40 passes with an empty reason, the exemption lost with eligibility, so the hold-harmless match keys the judged entry, not the address; the server's hold-harmless hop is judged by the rules and allowed as unlisted, not exempt"
    else
        bad "h2: the CDN shape: 1.1 $r / $(field "$line1" floor) $(field "$line1" reason); h2c $r2 / $(field "$line2" floor) $(field "$line2" reason); TLS $r3 / $(field "$line3" floor) $(field "$line3" reason)"
    fi
    # T5's twin over h2: the forged line first, the proxy's appended line judged
    r=$(curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge \
        -H 'X-Forwarded-For: 1.2.3.4' -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" 2>/dev/null)
    line1=$(last_access)
    vh2=$(curl -sk -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 \
        -H 'X-Forwarded-For: 1.2.3.4' -H "X-Forwarded-For: $LISTED, $HOP" "https://127.0.0.1:$P2/" 2>/dev/null)
    line2=$(last_access)
    if [ "${r% *}" = 403 ] && [ "${r#* }" = 2 ] && [ "${vh2% *}" = 403 ] && [ "${vh2#* }" = 2 ] \
        && [ "$(field "$line1" floor)" = "$LISTED" ] && [ "$(field "$line1" rule)" = "floor:1" ] \
        && [ "$(field "$line2" floor)" = "$LISTED" ] && [ "$(field "$line2" rule)" = "floor:1" ]; then
        ok "h2: two X-Forwarded-For lines over h2c and TLS-h2, the forged 1.2.3.4 first: the proxy-appended entry is the one judged ($LISTED, the floor's own rule), exactly the HTTP/1.1 walk"
    else
        bad "h2: the forged-first pair answered h2c $r / $(field "$line1" floor) $(field "$line1" rule); TLS $vh2 / $(field "$line2" floor) $(field "$line2" rule)"
    fi
    # the directly judged covered peer, the listed RAW peer and the PROXY pair need source addresses
    # of their own, which on this host means temporary loopback aliases (root): two the hold-harmless
    # table does not cover (the listed raw peer, the unlisted balancer) and one it does (10.20.30.40,
    # inside the table's 10/8 entry)
    if sudo -n true 2>/dev/null; then
        sudo -n ip addr add 12.34.56.78/32 dev lo 2>/dev/null
        sudo -n ip addr add 12.34.55.78/32 dev lo 2>/dev/null
        sudo -n ip addr add 10.20.30.40/32 dev lo 2>/dev/null
        lo_addrs=$(ip -4 addr show dev lo 2>/dev/null)
        if grep -q '12.34.56.78/32' <<<"$lo_addrs" \
            && grep -q '12.34.55.78/32' <<<"$lo_addrs" \
            && grep -q '10.20.30.40/32' <<<"$lo_addrs"; then
            ALIASED=yes
        else
            sudo -n ip addr del 12.34.56.78/32 dev lo 2>/dev/null
            sudo -n ip addr del 12.34.55.78/32 dev lo 2>/dev/null
            sudo -n ip addr del 10.20.30.40/32 dev lo 2>/dev/null
        fi
    fi
    if [ "$ALIASED" = yes ]; then
        # the covered peer judged directly: the connection's own address is not a trusted proxy, so
        # the walk stops at the peer and never reads the forged line; judged eligible, the covered
        # address carries the exemption the CDN shape above lost to the skipped hop
        r=$(curl -s --interface 10.20.30.40 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 \
            -H 'X-Forwarded-For: 1.2.3.4' "http://127.0.0.1:$PORT/" 2>/dev/null); line1=$(last_access)
        r2=$(curl -s --interface 10.20.30.40 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge \
            -H 'X-Forwarded-For: 1.2.3.4' "http://127.0.0.1:$PORT/" 2>/dev/null); line2=$(last_access)
        r3=$(curl -sk --interface 10.20.30.40 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 \
            -H 'X-Forwarded-For: 1.2.3.4' "https://127.0.0.1:$P2/" 2>/dev/null); line3=$(last_access)
        if [ "${r% *}" = 200 ] && [ "${r2% *}" = 200 ] && [ "${r2#* }" = 2 ] && [ "${r3% *}" = 200 ] && [ "${r3#* }" = 2 ] \
            && [ "$(field "$line1" floor)" = 10.20.30.40 ] && [ "$(field "$line1" reason)" = "hold-harmless" ] \
            && [ "$(field "$line2" floor)" = 10.20.30.40 ] && [ "$(field "$line2" reason)" = "hold-harmless" ] \
            && [ "$(field "$line3" floor)" = 10.20.30.40 ] && [ "$(field "$line3" reason)" = "hold-harmless" ]; then
            ok "h2: the covered peer judged directly (the alias 10.20.30.40, its forged line never read) carries the exemption over HTTP/1.1, h2c and TLS-h2, reason hold-harmless each time: the same address the CDN shape judged ineligible, so the exemption follows the judged entry"
        else
            bad "h2: the covered-peer arm: 1.1 $r / $(field "$line1" floor) $(field "$line1" reason); h2c $r2 / $(field "$line2" floor) $(field "$line2" reason); TLS $r3 / $(field "$line3" floor) $(field "$line3" reason)"
        fi
        # the RAW peer, listed by the fixture's span, over 1.1, h2c and TLS-h2
        r=$(curl -s --interface 12.34.56.78 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 "http://127.0.0.1:$PORT/" 2>/dev/null)
        line1=$(last_access)
        r2=$(curl -s --interface 12.34.56.78 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2-prior-knowledge "http://127.0.0.1:$PORT/" 2>/dev/null)
        line2=$(last_access)
        r3=$(curl -sk --interface 12.34.56.78 -o /dev/null -w '%{http_code} %{http_version}' --max-time 8 --http2 "https://127.0.0.1:$P2/" 2>/dev/null)
        line3=$(last_access)
        if [ "${r% *}" = 403 ] && [ "${r2% *}" = 403 ] && [ "${r2#* }" = 2 ] && [ "${r3% *}" = 403 ] && [ "${r3#* }" = 2 ] \
            && [ "$(field "$line1" floor)" = 12.34.56.78 ] && [ "$(field "$line1" rule)" = "floor:1" ] \
            && [ "$(field "$line2" floor)" = 12.34.56.78 ] && [ "$(field "$line2" rule)" = "floor:1" ] \
            && [ "$(field "$line3" floor)" = 12.34.56.78 ] && [ "$(field "$line3" rule)" = "floor:1" ]; then
            ok "h2: a listed RAW peer (the temporary alias 12.34.56.78, one the hold-harmless table does not cover) is denied by the floor over HTTP/1.1, h2c and TLS-h2, its own address in the floor note each time"
        else
            bad "h2: the listed raw peer: 1.1 $r / $(field "$line1" floor) $(field "$line1" rule); h2c $r2 / $(field "$line2" floor) $(field "$line2" rule); TLS $r3 / $(field "$line3" floor) $(field "$line3" rule)"
        fi
        # the PROXY-protocol listener: the balancer (12.34.55.78, unlisted) is the floor's own
        # address and passes it; the vhost rule alone decides on the header's source
        proxy_probe() { # proxy_probe <port> <bind> <source>: the status a PROXY-v2 request answers
            python3 - "$1" "$2" "$3" <<'PY'
import socket, struct, sys
port, bind, source = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((bind, 0))
s.settimeout(8)
s.connect(("127.0.0.1", port))
s.sendall(b"\r\n\r\n\x00\r\nQUIT\n" + b"\x21\x11" + struct.pack(">H", 12)
          + socket.inet_aton(source) + socket.inet_aton("127.0.0.1")
          + struct.pack(">HH", 44444, port))
s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
first = buf.split(b"\r\n")[0].split(b" ")
print(first[1].decode() if len(first) > 1 else "?")
s.close()
PY
        }
        # the outcome logger writes at most one line per second per outcome per process, and floor
        # denies and context denies share its deny slot, so the raw-peer trio's floor denies can
        # swallow the context rule's own line; a gap past the shared slot's second clears it. $LISTED is
        # benchmarking space, which is hold-harmless: the vhost rule denies it all the same, because step
        # 4 judges the header's source with no hold-harmless exemption of its own
        sleep 1.2
        r=$(proxy_probe "$P3" 12.34.55.78 "$UNLISTED"); line1=$(last_access)
        r2=$(proxy_probe "$P3" 12.34.55.78 "$LISTED"); line2=$(last_access)
        if [ "$r" = 200 ] && [ "$(field "$line1" floor)" = 12.34.55.78 ] \
            && [ "$(field "$line1" program)" = "floor:$d_floor ctx:$d_ctx" ] \
            && [ "$r2" = 403 ] && [ "$(field "$line2" floor)" = 12.34.55.78 ] \
            && [ "$(field "$line2" rule)" = "ctx:1" ] && [ "$(field "$line2" program)" = "floor:$d_floor ctx:$d_ctx" ] \
            && grep -qF "denied $LISTED: rule ctx:1 " "$W/logs/error.log"; then
            ok "h2: on the PROXY listener the floor's address is the balancer (12.34.55.78, unlisted, in the floor note on both lines) while the vhost rule judges the header's source alone: $UNLISTED passes and $LISTED, hold-harmless space, is denied by rule ctx:1 with no exemption at step 4, the deny line naming $LISTED"
        else
            bad "h2: the PROXY pair: unlisted $r / $(field "$line1" floor) $(field "$line1" program); listed $r2 / $(field "$line2" floor) $(field "$line2" rule) $(field "$line2" program); vhost digest $d_ctx"
        fi
    else
        na "h2: the covered-peer arm, the listed-raw-peer arm and the PROXY pair need source addresses of their own (one covered by the hold-harmless table, two outside it), which on this host means temporary loopback aliases (root); without them all three stand unwalked this run, and the walked-client arms above cover the floor's address source over h2"
    fi
    stop_httpd "$conf" "$MPM" || bad "h2: httpd did not stop"
    # the graceful stop keeps answering while the event MPM drains its connections (measured ~11s
    # here before the port is released), and a start inside that window both fails to bind and has
    # its await answered by the dying listener: wait for the port to actually refuse first
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release" \
        || bad "h2: the main listener still answered 15s after the stop, so the debug leg below may be racing the drain"
    # the debug build's no-address counter: 0 under a correct read of the connection's peer
    if build_variant unset -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_COUNT_UNSET_ADDR \
        && [ -f "$CTL/unset.so" ]; then
        h2_conf "$CTL/unset.so" on 1 "$conf"
        if start_httpd "$conf" "$MPM"; then
            code_nohdr / >/dev/null; h2c / >/dev/null; h2s / >/dev/null
            if [ "$ALIASED" = yes ]; then
                proxy_probe "$P3" 12.34.55.78 "$UNLISTED" >/dev/null
                proxy_probe "$P3" 12.34.55.78 "$LISTED" >/dev/null
            fi
            # a missing log is itself the failure (the debug httpd wrote no line), and a wc on a
            # missing file reports through the shell's redirection, which no 2>/dev/null silences
            if [ -f "$W/logs/access-unset.log" ]; then
                n=$(wc -l < "$W/logs/access-unset.log" | tr -d '[:space:]')
                z=$(grep -c 'unset=0' "$W/logs/access-unset.log")
            else
                n=""; z=""
            fi
            if [ -n "$n" ] && [ "$n" -ge 4 ] && [ "$n" = "$z" ]; then
                ok "h2: the debug build's no-address counter reads 0 on every one of the $n request lines across HTTP/1.1, h2c, TLS-h2 and the PROXY listener, so every request was judged from a real address"
            else
                bad "h2: the no-address counter: $z of $n lines hold unset=0: $(grep -v 'unset=0' "$W/logs/access-unset.log" 2>/dev/null | head -2 | tr '\n' ' ' | cut -c1-200)"
            fi
            stop_httpd "$conf" "$MPM" || bad "h2: the debug httpd did not stop"
        else
            bad "h2: the debug httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        fi
    else
        bad "h2: the unset-address debug build failed: $(tail -2 "$CTL/unset.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    if [ "$ALIASED" = yes ]; then
        sudo -n ip addr del 12.34.56.78/32 dev lo 2>/dev/null
        sudo -n ip addr del 12.34.55.78/32 dev lo 2>/dev/null
        sudo -n ip addr del 10.20.30.40/32 dev lo 2>/dev/null
    fi
    fresh_snapshot
}

run_shard_rows() { # N2: one writer per shard, under load on the threaded MPMs and through h2 worker churn
    local conf="$W/httpd-n2.conf" out chk d_floor mpm sent n0 n1 i H2W=20 CEIL kids0 kids1 vname vdefs vflags
    local builds_ok=yes rseq ret_end fail
    echo "  [one writer per shard, under load]"
    if ! command -v h2load >/dev/null 2>&1; then
        dark "N2: this host ships no h2load, so the h2 arms and the MPM-slot control stand unwalked this run"
        return
    fi
    out=$(need_mod http2_module mod_http2.so)
    case $out in
        \#missing*) dark "N2: this httpd ships no mod_http2, so the h2 arms and the MPM-slot control stand unwalked this run"; return ;;
    esac
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
    echo page > "$W/html/index.html"
    # the listed range at CRITICAL for the whole group, so the floor ("deny if listed >= critical") is the
    # rule every load request fires and its rule 1 is the counting oracle; at the default HIGH the server
    # context's sugar rule takes the deny instead (measured: rule=ctx:1, the floor's counter at 0)
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.bin" "$GEN" 0 4 "$RANGE_START" "$RANGE_END"
    # the five builds the row needs: the export, and the four controls named beside it
    while read -r vname vdefs; do
        vflags=""
        for i in $vdefs; do vflags="$vflags -Wc,-D$i"; done
        # shellcheck disable=SC2086
        if ! build_variant "$vname" -Wc,-DWE_MOD_CONTROL_BUILD $vflags; then
            bad "N2: the $vname build failed: $(tail -2 "$CTL/$vname.log" 2>/dev/null | tr '\n' ' ' | cut -c1-250)"
            builds_ok=no
        fi
    done <<'EOF'
sharddbg WE_MOD_TEST_EXPORT_SHARDS
shardglobal WE_MOD_TEST_EXPORT_SHARDS WE_MOD_TEST_GLOBAL_SHARD
shardowner WE_MOD_TEST_EXPORT_SHARDS WE_MOD_TEST_SHARD_OWNER
shardslot WE_MOD_TEST_EXPORT_SHARDS WE_MOD_TEST_MPM_SLOT
shardnorelease WE_MOD_TEST_EXPORT_SHARDS WE_MOD_TEST_NO_RELEASE
EOF
    [ "$builds_ok" = yes ] || return
    n2_conf() { # n2_conf <mpm> <module> <out path>: the floor denies the listed client on every context, h2 ready
        {
            conf_head "$1"; conf_data
            need_mod http2_module mod_http2.so
            echo 'Protocols h2 h2c'
            echo "H2MaxWorkers $H2W"
            echo 'H2MaxWorkerIdleSeconds 1'
            echo 'WhisperEdgeMode deny'
            echo 'WhisperEdgePolicyFloor "deny if listed >= critical"'
        } | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $2#" > "$3"
    }
    # the arm's own deny lines: the access log is wiped per start, so within an arm every line of this
    # shape is one of the arm's own floor denies (the client field is the remoteip-rewritten listed address)
    n_denies() { grep -c 'action=deny rule=floor:1' "$W/logs/access.log" 2>/dev/null || true; }
    # every child's export, checked whole: the bases distinct, aligned and disjoint, the live count under
    # the ceiling, the retired count against the destructor's own, and the byte ledger against the live
    # shards' exact footprint; prints "ok <per-child summary>" or "FAIL <every reason>"
    shard_check() { # shard_check <ceiling>
        python3 - "$W/counters" "$HTTPD_PID" "$1" <<'PY'
import glob, os, re, subprocess, sys
d, pid, ceiling = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
if len(kids) < 2:
    print("FAIL fewer than two children are running")
    raise SystemExit
fails = []
parts = []
for kid in kids:
    fs = glob.glob(os.path.join(d, kid + "-*.shard"))
    if not fs:
        fails.append("child %s wrote no export" % kid)
        continue
    with open(fs[0]) as fh:
        text = fh.read()
    m = re.search(r"^pid \d+ tick \d+ live (\d+) retired (\d+) dtor (\d+) registrations (\d+) swaps (\d+) "
                  r"alloc (\d+) freed (\d+) hdr (\d+) ctr (\d+) truncated (\d+)$", text, re.M)
    if not m:
        fails.append("child %s: the export's head line is unreadable" % kid)
        continue
    live, retired, dtor, regs, swaps, alloc, freed, hdr, ctr, trunc = [int(x) for x in m.groups()]
    rows = re.findall(r"^shard ([0-9a-f]+) ranges (\d+)$", text, re.M)
    bases = [int(b, 16) for b, r in rows]
    rng = sum(int(r) for b, r in rows)
    if len(bases) != live:
        fails.append("child %s: %d shard lines for %d live" % (kid, len(bases), live))
    if trunc:
        fails.append("child %s: %d shards over the export's bound" % (kid, trunc))
    if len(set(bases)) != len(bases):
        fails.append("child %s: two shards share one base" % kid)
    for b in bases:
        if b % 64:
            fails.append("child %s: the base %#x is not 64-byte aligned" % (kid, b))
    bs = sorted(bases)
    for i in range(1, len(bs)):
        if bs[i] < bs[i - 1] + ctr:
            fails.append("child %s: the shards at %#x and %#x overlap" % (kid, bs[i - 1], bs[i]))
    if live > ceiling:
        fails.append("child %s: %d live shards, the ceiling is %d" % (kid, live, ceiling))
    if retired != dtor:
        fails.append("child %s: retired %d against %d destructor runs" % (kid, retired, dtor))
    if alloc - freed != live * (hdr + ctr) + rng:
        fails.append("child %s: the ledger holds %d, the live footprint is %d"
                     % (kid, alloc - freed, live * (hdr + ctr) + rng))
    rss = ""
    try:
        with open("/proc/%s/status" % kid) as fh:
            rss = " rss %s kB" % re.search(r"VmRSS:\s+(\d+)", fh.read()).group(1)
    except OSError:
        pass
    parts.append("pid %s live %d retired %d dtor %d registrations %d swaps %d%s" % (kid, live, retired, dtor, regs, swaps, rss))
if fails:
    print("FAIL " + "; ".join(fails))
else:
    print("ok " + "; ".join(parts))
PY
    }
    # the summed <field arithmetic> over every live child's export: the retired total (the churn's own
    # number) and the alloc-minus-freed ledger (the no-release control's number)
    shard_sum() { # shard_sum <sed program over the head line, with one capture as an arithmetic string>
        local kid f v sum=0
        for kid in $(pgrep -P "${HTTPD_PID:-0}" 2>/dev/null); do
            for f in "$W/counters/$kid"-*.shard; do
                [ -f "$f" ] || continue
                v=$(sed -n "$1" "$f")
                [ -n "$v" ] && sum=$((sum + v))
            done
        done
        echo "$sum"
    }
    # the positive arms, on both threaded MPMs: the 64-client HTTP/1.1 load, then ten h2 churn cycles whose
    # workers spawn under load and idle out inside each tick; each arm's counters start empty, so the rule
    # counter the oracle reads sums only this arm's own children
    CEIL=$((16 + H2W))
    for mpm in event worker; do
        rm -rf "$W/counters"
        n2_conf "$mpm" "$CTL/sharddbg.so" "$conf"
        if ! start_httpd "$conf" "$mpm"; then
            bad "N2 $mpm: httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$mpm.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            continue
        fi
        d_floor=$(ctx_digest "$(cfg_lines)" floor)
        kids0=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        await_first_tick || { bad "N2 $mpm: no counter tick ever appeared"; stop_httpd "$conf" "$mpm" >/dev/null 2>&1; continue; }
        # the HTTP/1.1 arm: 64 clients, every request denied by the floor, one writer per MPM thread
        n0=$(n_denies)
        ab -c 64 -n 1024 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        await_next_tick
        n1=$(n_denies)
        chk=$(shard_check "$CEIL")
        case $chk in
        ok*) if [ "$n1" = "$((n0 + 1024))" ] && [ "$(rule_count "$d_floor" 1)" = 1024 ]; then
                ok "N2 $mpm: 64 HTTP/1.1 clients, 1024 requests: every one denied by the floor and counted once (rule 1 of the floor at $(rule_count "$d_floor" 1), $(n_denies) deny lines), the export holds ($chk), no child died"
            else
                bad "N2 $mpm: the HTTP/1.1 arm's counts: the access log holds $((n1 - n0)) denies of 1024, the rule counter $(rule_count "$d_floor" 1)"
            fi ;;
        *)  bad "N2 $mpm: the HTTP/1.1 arm's export: $chk" ;;
        esac
        kids1=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        [ "$kids0" = "$kids1" ] || bad "N2 $mpm: a child died under the HTTP/1.1 load ($kids0 -> $kids1)"
        # the h2 arm: ten cycles, 64 streams over 8 connections each, the workers spawning under the load
        # and idleing out inside the tick the cycle's read waits for
        sent=0
        rseq=""
        fail=0
        n0=$n1
        for i in 1 2 3 4 5 6 7 8 9 10; do
            h2load -n 128 -c 8 -m 8 -p h2c -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
            sent=$((sent + 128))
            await_next_tick
            chk=$(shard_check "$CEIL")
            case $chk in
            ok*) ;;
            *)  bad "N2 $mpm: cycle $i's export: $chk"; fail=1 ;;
            esac
            if [ "$(rule_count "$d_floor" 1)" != "$((1024 + sent))" ]; then
                bad "N2 $mpm: cycle $i: rule 1 of the floor counts $(rule_count "$d_floor" 1) of $((1024 + sent)) sent"
                fail=1
            fi
            rseq="$rseq $(shard_sum 's/^pid [0-9]* tick [0-9]* live [0-9]* retired \([0-9]*\) dtor.*$/\1/p')"
        done
        n1=$(n_denies)
        kids1=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        ret_end=$(shard_sum 's/^pid [0-9]* tick [0-9]* live [0-9]* retired \([0-9]*\) dtor.*$/\1/p')
        if [ "$fail" = 0 ] && [ "$n1" = "$((n0 + sent))" ] && [ "$kids0" = "$kids1" ] && [ "$ret_end" -gt 0 ]; then
            ok "N2 $mpm: ten h2 churn cycles, $sent requests at 64 streams over 8 connections: every cycle's export held (bases distinct, aligned and disjoint, live under $CEIL, retired equal to the destructor runs, the ledger equal to the live footprint), the counts exact through $(rule_count "$d_floor" 1), the verdicts one shape ($((n1 - n0)) denies), the workers churned (retired per cycle:$rseq), no child died"
        else
            [ "$kids0" = "$kids1" ] || bad "N2 $mpm: a child died under the h2 load ($kids0 -> $kids1)"
            [ "$n1" = "$((n0 + sent))" ] || bad "N2 $mpm: the h2 arm's verdicts: $((n1 - n0)) deny lines for $sent requests"
            [ "$ret_end" -gt 0 ] || bad "N2 $mpm: no shard was ever retired across the ten cycles (retired per cycle:$rseq), so the h2 workers never churned and the arm proved nothing about worker turnover"
            bad "N2 $mpm: the h2 churn cycles ended with failures above"
        fi
        stop_httpd "$conf" "$mpm" || bad "N2 $mpm: httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release" \
            || bad "N2 $mpm: the stopped listener still answered 15s later, so the next arm may race the drain"
        done
    # the shared-shard control: every thread's load-and-store on one array, so the concurrent writers lose
    # counts the exact accounting then reads
    rm -rf "$W/counters"
    n2_conf event "$CTL/shardglobal.so" "$conf"
    if start_httpd "$conf" event; then
        d_floor=$(ctx_digest "$(cfg_lines)" floor)
        await_first_tick || bad "N2: the shared-shard control's first tick never appeared"
        # four times the positive arm's volume: the loss is a scheduling race (measured 19 to 653 lost of
        # 4,096 across runs), so the control reads it at a volume where a run with none would be remarkable,
        # and reports such a run as unproven rather than as a defect
        ab -c 64 -n 16384 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        await_next_tick
        n1=$(rule_count "$d_floor" 1)
        if [ "$n1" -lt 16384 ]; then
            ok "N2: the shared-shard control lost counts under the same load: rule 1 of the floor counted $n1 of 16384 ($((16384 - n1)) lost)"
        else
            na "N2: the shared-shard control counted every one of 16384 requests this run, so the lost-count arm is unproven here (the barrier-forced interleave in the core's own test is the deterministic one)"
        fi
        stop_httpd "$conf" event || bad "N2: the shared-shard control's httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "N2: the shared-shard control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-event.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the owner-tid control: the second thread to touch the first's shard is caught at the write itself
    rm -rf "$W/counters"
    n2_conf event "$CTL/shardowner.so" "$conf"
    if start_httpd "$conf" event; then
        code / "$LISTED" >/dev/null
        ab -c 64 -n 1024 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        if await 'grep -q "the shard ownership trap" "$W/logs/error.log"' 20 "the ownership trap"; then
            ok "N2: the owner-tid control trapped: the second thread to write the shared shard aborted at the write, the error log naming both threads"
        else
            bad "N2: the owner-tid control never trapped under the same load"
        fi
        stop_httpd "$conf" event || bad "N2: the owner control's httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "N2: the owner control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-event.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the MPM-slot control: the connection, not the thread, keys the shard, which under HTTP/1.1 is the
    # one thread the MPM pinned the connection to (clean), and under h2 is every worker that picks up a
    # stream (the trap)
    rm -rf "$W/counters"
    n2_conf event "$CTL/shardslot.so" "$conf"
    if start_httpd "$conf" event; then
        d_floor=$(ctx_digest "$(cfg_lines)" floor)
        await_first_tick || bad "N2: the slot control's first tick never appeared"
        ab -c 64 -n 1024 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        await_next_tick
        n1=$(rule_count "$d_floor" 1)
        if [ "$n1" = 1024 ] && ! grep -q "the shard ownership trap" "$W/logs/error.log"; then
            ok "N2: the MPM-slot control under HTTP/1.1 is clean: one thread per connection, 1024 of 1024 counted, no trap"
        else
            bad "N2: the MPM-slot control's HTTP/1.1 phase was not clean: counted $n1 of 1024, trap lines $(grep -c "the shard ownership trap" "$W/logs/error.log" 2>/dev/null || true)"
        fi
        h2load -n 1024 -c 8 -m 8 -p h2c -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        if await 'grep -q "the shard ownership trap" "$W/logs/error.log"' 20 "the ownership trap under h2"; then
            ok "N2: the MPM-slot control trapped under h2: a stream's worker wrote a shard another worker had registered, the wrong keying caught at the write"
        else
            bad "N2: the MPM-slot control never trapped under h2, so the wrong keying went undetected"
        fi
        stop_httpd "$conf" event || bad "N2: the slot control's httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "N2: the slot control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-event.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the no-release control: the destructor folds and unlinks but frees nothing, so the ledger's
    # difference grows with every worker the cycles retire
    rm -rf "$W/counters"
    n2_conf event "$CTL/shardnorelease.so" "$conf"
    if start_httpd "$conf" event; then
        local g1=0 g2=0 g3=0
        await_first_tick || bad "N2: the no-release control's first tick never appeared"
        for i in 1 2 3; do
            h2load -n 128 -c 8 -m 8 -p h2c -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
            await_next_tick
            case $i in
            1) g1=$(shard_sum 's/^pid [0-9]* tick [0-9]* live [0-9]* retired [0-9]* dtor [0-9]* registrations [0-9]* swaps [0-9]* alloc \([0-9]*\) freed \([0-9]*\) hdr.*$/\1 - \2/p') ;;
            2) g2=$(shard_sum 's/^pid [0-9]* tick [0-9]* live [0-9]* retired [0-9]* dtor [0-9]* registrations [0-9]* swaps [0-9]* alloc \([0-9]*\) freed \([0-9]*\) hdr.*$/\1 - \2/p') ;;
            3) g3=$(shard_sum 's/^pid [0-9]* tick [0-9]* live [0-9]* retired [0-9]* dtor [0-9]* registrations [0-9]* swaps [0-9]* alloc \([0-9]*\) freed \([0-9]*\) hdr.*$/\1 - \2/p') ;;
            esac
        done
        if [ "$g1" -gt 0 ] && [ "$g2" -gt "$g1" ] && [ "$g3" -gt "$g2" ]; then
            ok "N2: the no-release control shows the leak the ledger carries: the difference grew $g1 -> $g2 -> $g3 bytes across the cycles, away from the live footprint"
        else
            bad "N2: the no-release control's ledger did not grow: $g1 -> $g2 -> $g3"
        fi
        stop_httpd "$conf" event || bad "N2: the no-release control's httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "N2: the no-release control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-event.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    fresh_snapshot
}

run_asan_rows() { # N6: a legacy generation with twice the ranges, published under load, the module under AddressSanitizer
    local conf="$W/httpd-n6.conf" MPM=event ASANRT G0 kids0 kids1
    echo "  [a generation with twice the ranges, published under load, under AddressSanitizer]"
    ASANRT=$(gcc -print-file-name=libasan.so 2>/dev/null)
    if [ -z "$ASANRT" ] || [ ! -e "$ASANRT" ]; then
        dark "N6: this host's compiler ships no libasan, so the sanitizer arms stand unwalked this run"
        return
    fi
    rm -rf "$W/html" "$W/counters" "$W/asan"; mkdir -p "$W/html" "$W/asan"
    echo page > "$W/html/index.html"
    # the production shape instrumented, and the control: no generation check on the per-thread sub-block
    if ! build_variant asan -Wc,-fsanitize=address -Wc,-fno-omit-frame-pointer -Wl,-fsanitize=address; then
        bad "N6: the sanitizer build failed: $(tail -2 "$CTL/asan.log" 2>/dev/null | tr '\n' ' ' | cut -c1-250)"
        return
    fi
    if ! build_variant asanunchecked -Wc,-fsanitize=address -Wc,-fno-omit-frame-pointer -Wl,-fsanitize=address \
            -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_RANGES_UNCHECKED; then
        bad "N6: the unchecked-sub-block control build failed: $(tail -2 "$CTL/asanunchecked.log" 2>/dev/null | tr '\n' ' ' | cut -c1-250)"
        return
    fi
    n6_conf() { # n6_conf <module> <out path>: every listed address denied at the server, so every listed request counts its range
        {
            conf_head "$MPM"; conf_data
            echo 'WhisperEdgeMode deny'
            echo 'WhisperEdgePolicy "deny if listed >= low"'
        } | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#" > "$2"
    }
    # the sanitizer runtime is preloaded into httpd (the server itself is not instrumented, the module is),
    # its reports going to files; the stop runs the same binary with the module loaded, so it needs the runtime too
    asan_start() { # asan_start <conf> -> 0 when serving
        rm -rf "$W/logs" "$W/asan"; mkdir -p "$W/logs" "$W/asan"
        LD_PRELOAD=$ASANRT ASAN_OPTIONS="log_path=$W/asan/report,detect_leaks=0" "$HTTPD" -f "$1" -k start 2>"$W/start-$MPM.err"
        await "[ \"\$(code_nohdr /)\" != 000 ]" 20 "httpd up" || return 1
        HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
        return 0
    }
    asan_stop() { # asan_stop <conf>
        local pid
        pid=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
        LD_PRELOAD=$ASANRT ASAN_OPTIONS="log_path=$W/asan/report,detect_leaks=0" timeout 20 "$HTTPD" -f "$1" -k stop >/dev/null 2>&1
        if ! await "[ ! -f \"$W/httpd-$MPM.pid\" ]" 20 "stopped"; then
            [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
            return 1
        fi
        return 0
    }
    asan_reports() { # the sanitizer's error reports, from its files and from the logs it may also have reached
        { cat "$W"/asan/report.* 2>/dev/null; grep -h 'AddressSanitizer' "$W/logs/error.log" "$W/start-$MPM.err" 2>/dev/null; } \
            | grep -c 'ERROR: AddressSanitizer'
    }
    # the two generations: G with 4 synthetic ranges at the bound name, G + 1 with 8 beside it, ready to rename in;
    # the generator's expectation files name each range's start and end, and the walked address of a range is its start
    n6_pair() {
        G0=$((GEN + 1)); GEN=$((GEN + 2))
        python3 "$ROOT/core/make-test-snapshot.py" --plane reputation --out "$W/snapshot.bin" --format 1 --v4-index radix-16 \
            --v6-index none --synthetic 4 0 --generation "$G0" --expect "$W/n6-g.expect"
        python3 "$ROOT/core/make-test-snapshot.py" --plane reputation --out "$W/snapshot.n6next" --format 1 --v4-index radix-16 \
            --v6-index none --synthetic 8 0 --generation "$GEN" --expect "$W/n6-g1.expect"
        chmod 0644 "$W/snapshot.bin" "$W/snapshot.n6next"
    }
    n6_starts() { awk '$3 != "-" { print $2 }' "$1" | awk 'NR % 2 == 1'; }
    n6_load() { # the twelve range starts (G + 1's eight, G's four), one client each for 14 seconds, concurrently
        local a pids=""
        for a in $(n6_starts "$W/n6-g1.expect") $(n6_starts "$W/n6-g.expect"); do
            ab -t 14 -n 20000 -c 1 -H "X-Forwarded-For: $a, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1 &
            pids="$pids $!"
        done
        # shellcheck disable=SC2086
        wait $pids
    }
    # the oracle: every denied request the access log attributes to generation G + 1 (its gen note) is charged to
    # the G + 1 range holding its judged address; the live children's counter files must carry generation G + 1,
    # exactly those per-range totals, and nothing from G; prints "ok ..." or "MISMATCH ..."
    n6_check() { # n6_check <G + 1>
        python3 - "$W/counters" "$W/logs/access.log" "$W/n6-g1.expect" "$1" "$HTTPD_PID" <<'PY'
import glob, os, re, subprocess, sys
d, log, expect, gen, pid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
def ip(s):
    a, b, c, e = (int(x) for x in s.split("."))
    return a << 24 | b << 16 | c << 8 | e
def text(s, e):
    span = e - s + 1
    a = "%d.%d.%d.%d" % (s >> 24, s >> 16 & 255, s >> 8 & 255, s & 255)
    if span & (span - 1) == 0 and s % span == 0:
        return "%s/%d" % (a, 32 - span.bit_length() + 1)
    return "%s-%s" % (a, "%d.%d.%d.%d" % (e >> 24, e >> 16 & 255, e >> 8 & 255, e & 255))
pts = [l.split() for l in open(expect) if l.split()[2:3] != ["-"]]
ranges = []
for i in range(0, len(pts), 2):
    ranges.append((ip(pts[i][1]), ip(pts[i + 1][1])))
ranges.sort()
expected = {}
pat = re.compile(r"^(\d+\.\d+\.\d+\.\d+) 403 .* gen=reputation:" + re.escape(gen) + r"\.")
nlines = 0
with open(log) as fh:
    for line in fh:
        m = pat.match(line)
        if not m:
            continue
        v = ip(m.group(1))
        for s, e in ranges:
            if s <= v <= e:
                k = text(s, e)
                expected[k] = expected.get(k, 0) + 1
                nlines += 1
                break
kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
observed, fails, files = {}, [], 0
for kid in kids:
    for f in glob.glob(os.path.join(d, kid + "-*.cnt")):
        if f.endswith(".rules.cnt"):
            continue
        files += 1
        g = None
        denied = None
        hits = 0
        for line in open(f):
            w = line.split()
            if w[:1] == ["generation"]:
                g = w[1]
            elif w[:1] == ["denied"]:
                denied = int(w[1])
            elif w[:1] == ["4"]:
                observed[w[1]] = observed.get(w[1], 0) + int(w[3])
                hits += int(w[3])
            elif w[:1] == ["6"]:
                fails.append("%s: an IPv6 range line in an IPv4-only generation" % os.path.basename(f))
        if g != gen:
            fails.append("%s carries generation %s, not %s" % (os.path.basename(f), g, gen))
        if denied != hits:
            fails.append("%s: denied %s against %d range hits" % (os.path.basename(f), denied, hits))
if files < 2:
    fails.append("only %d live counter files" % files)
for k in sorted(set(expected) | set(observed)):
    if expected.get(k, 0) != observed.get(k, 0):
        fails.append("%s: the files hold %d, the log attributes %d" % (k, observed.get(k, 0), expected.get(k, 0)))
if fails:
    print("MISMATCH " + "; ".join(fails))
else:
    print("ok %d denied requests attributed to generation %s across %d ranges, every per-range total equal in %d files: %s"
          % (nlines, gen, len(expected), files, ", ".join("%s=%d" % (k, expected[k]) for k in sorted(expected))))
PY
    }
    n6_arm() { # n6_arm <module> <label> -> the measured facts in n6_rep, n6_chk, n6_kids (0 = unchanged), or 1 when httpd never served
        n6_pair
        n6_conf "$1" "$conf"
        if ! asan_start "$conf"; then
            bad "N6 $2: httpd did not start under the sanitizer: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            return 1
        fi
        kids0=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        await_first_tick || bad "N6 $2: no counter tick ever appeared"
        # the publish right after a tick: each child arms G + 1 at its next tick, inside the 14-second load
        mv "$W/snapshot.n6next" "$W/snapshot.bin"
        n6_load
        await_plane "plane snapshot.bin: generation $GEN verified, arming" "$PINNED_CHILDREN" \
            || bad "N6 $2: $(plane_pids "plane snapshot.bin: generation $GEN verified, arming") of $PINNED_CHILDREN children armed generation $GEN inside the load"
        await_next_tick
        n6_chk=$(n6_check "$GEN")
        n6_rep=$(asan_reports)
        kids1=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        n6_kids=0; [ "$kids0" = "$kids1" ] || n6_kids=1
        asan_stop "$conf" || bad "N6 $2: httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        return 0
    }
    local n6_chk n6_rep n6_kids
    rm -rf "$W/counters"
    if n6_arm "$CTL/asan.so" "sanitizer"; then
        case $n6_chk in
        ok*) if [ "$n6_rep" = 0 ] && [ "$n6_kids" = 0 ]; then
                ok "N6: generation $GEN (8 ranges) renamed in over generation $G0 (4 ranges) under a 12-client load: no sanitizer report, no child died, and the counter files carry the new generation only, $n6_chk"
            else
                bad "N6: $n6_rep sanitizer reports, children changed: $n6_kids ($(head -c 300 "$W"/asan/report.* 2>/dev/null | tr '\n' ' '))"
            fi ;;
        *)  bad "N6: the per-range totals against the log's attribution: $n6_chk" ;;
        esac
    fi
    # the control: the same publish on a build that never checks the sub-block against the map it writes under
    rm -rf "$W/counters"
    if n6_arm "$CTL/asanunchecked.so" "unchecked control"; then
        case $n6_chk in
        MISMATCH*) ok "N6: the unchecked-sub-block control is caught by the attribution: generation $G0's counts land under generation $GEN's prefixes and $GEN's own go missing ($(printf '%s' "$n6_chk" | cut -c10-300)); sanitizer reports: $n6_rep" ;;
        *) if [ "$n6_rep" -gt 0 ]; then
                ok "N6: the unchecked-sub-block control is caught by the sanitizer ($n6_rep reports) while the totals happened to agree"
            else
                bad "N6: the unchecked-sub-block control went undetected: no sanitizer report and the totals agree ($n6_chk)"
            fi ;;
        esac
    fi
    rm -f "$W/snapshot.n6next" "$W/n6-g.expect" "$W/n6-g1.expect"
    fresh_snapshot
}

m10_counts() { # m10_counts <parent pid> <boot-clock ms, 0 for all>: over the CHILD status files whose process started after
    # that instant, "<files> <files carrying the debug build's digest pair> <digests summed> <start-digests summed>"
    python3 - "$W/counters" "$1" "$2" <<'PY'
import glob, os, re, sys
ctr, parent, since = sys.argv[1], sys.argv[2], float(sys.argv[3])
tck = os.sysconf("SC_CLK_TCK")
files = paired = d = s = 0
for f in glob.glob(ctr + "/*.status"):
    if os.path.basename(f).split("-")[0] == parent:
        continue
    m = re.search(r"^process .* starttime (\d+) .*$", open(f, errors="replace").read(), re.M)
    if not m or int(m.group(1)) * 1000.0 / tck <= since:
        continue
    files += 1
    mm = re.search(r" digests (\d+) start-digests (\d+)$", m.group(0))
    if mm:
        paired += 1
        d += int(mm.group(1))
        s += int(mm.group(2))
print(files, paired, d, s)
PY
}
m10_pid_digests() { # m10_pid_digests <pid>: that process's own "digests start-digests" from its status file, "- -" without the pair
    sed -n 's/^process .* digests \([0-9]*\) start-digests \([0-9]*\)$/\1 \2/p' "$W"/counters/"$1"-*.status 2>/dev/null | tail -1 | grep . || echo "- -"
}
m10_boot_ms() { awk '{ printf "%d\n", $1 * 1000 }' /proc/uptime; }
m10_refused_after_fork() { # m10_refused_after_fork <parent pid> -> "<refusals by children forked after the parent's> <by children forked before> <the parent's refusal, boot-clock ms>"
    python3 - "$W/logs/error.log" "$W/counters" "$1" <<'PY'
import glob, os, re, sys, time
log, ctr, parent = sys.argv[1], sys.argv[2], sys.argv[3]
up = float(open("/proc/uptime").read().split()[0])
boot_epoch = time.time() - up                    # CLOCK_BOOTTIME's zero on the wall clock, to about 10 ms
stamp = re.compile(r"^\[\w{3} (\w{3} \d{2} \d{2}:\d{2}:\d{2}\.\d{6} \d{4})\] .*\[pid (\d+)[\]:]")
pat = "plane snapshot.bin refused:"
parent_ms, after, before = None, 0, 0
for line in open(log, errors="replace"):
    if pat not in line:
        continue
    m = stamp.match(line)
    if not m:
        continue
    pid = m.group(2)
    if pid == parent and parent_ms is None:
        t = time.mktime(time.strptime(m.group(1)[:15] + m.group(1)[22:], "%b %d %H:%M:%S %Y")) + float("0." + m.group(1)[16:22])
        parent_ms = (t - boot_epoch) * 1000.0
        continue
    if parent_ms is None or pid == parent:
        continue
    started = None                               # the fork, /proc field 22 as the status file records it
    for f in glob.glob("%s/%s-*.status" % (ctr, pid)):
        mm = re.search(r" starttime (\d+) ", open(f, errors="replace").read())
        if mm:
            started = int(mm.group(1)) * 1000.0 / os.sysconf("SC_CLK_TCK")
    # no status file for the pid: placed after, the conservative reading
    if started is None or started > parent_ms:
        after += 1
    else:
        before += 1
print(after, before, int(parent_ms) if parent_ms is not None else 0)
PY
}
run_outage_rows() { # M10's Apache arms: a feed outage, a digest-failing newer file, and copies at new inodes, over cycled children.
    # run_outage_rows [object tag]: the release object by default; run_outage_debug_rows passes the WE_MOD_DEBUG object,
    # whose status file carries the per-process digest counts (`digests N start-digests M`, zeroed at the worker
    # start), and only that run reads them: the three count rows and their controls are the debug run's
    local OBJ="${1:-$MODULE}" TAG="${2:-release}" MPM=prefork conf="$W/httpd-m10.conf" G lines pids r line n0 n1 i kids before after parent_line
    local L=M10 c c1 t0 t1 parent_ms k dk dk1=""
    [ "$TAG" = debug ] && L="M10 (debug build)"
    echo "  [a feed outage, a bad newer file, and copies at new inodes, over cycled children: the $TAG object]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"; echo page > "$W/html/index.html"
    m10_conf() { # m10_conf <cycle 0|1>: every listed address denied at the server; 1 cycles a child per connection,
        # with eight children so the parent's spawn rate (one a second at rest, doubling while children are
        # missing) turns 500 children over in tens of seconds rather than one a second (measured at the pinned two)
        { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } \
            | if [ "$1" = 1 ]; then
                sed 's/^StartServers 2$/ServerLimit 8\nStartServers 8/; s/^MinSpareServers 2$/MinSpareServers 8/; s/^MaxSpareServers 2$/MaxSpareServers 8/; s/^MaxRequestWorkers 2$/MaxRequestWorkers 8/; s/^MaxConnectionsPerChild 0$/MaxConnectionsPerChild 1/'
            else
                cat
            fi | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $OBJ#" > "$conf"
    }
    m10_snap() { # m10_snap <path> <generation> <valid_until_ms>: the legacy snapshot renamed in at a new inode
        python3 "$ROOT/core/make-test-snapshot.py" "$1.m10tmp" "$2" "$3" 3 "$RANGE_START" "$RANGE_END"
        chmod 0644 "$1.m10tmp"; mv "$1.m10tmp" "$1"
    }
    m10_cycle() { # m10_cycle <n>: n requests, eight at a time, one connection each, each ending a child
        ab -c 8 -n "$1" -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
    }
    m10_lines() { grep -cF -- "$1" "$W/logs/error.log" 2>/dev/null || true; }
    m10_child_lines() { grep -F -- "$1" "$W/logs/error.log" 2>/dev/null | grep -vcE "\[pid ${HTTPD_PID}[]:]" || true; }   # the parent's monitor logs the same lines
    m10_stale_procs() { # the processes that said the plane is stale, by their line or by their status file (a child cycled by
        # MaxConnectionsPerChild 1 exits before its thread's first tick and inherits said_stale from a parent that has said it,
        # so it logs nothing; "one stale line per process" therefore counts either)
        { grep -F -- "is stale: generation $1's valid-until passed" "$W/logs/error.log" 2>/dev/null | sed -n 's/.*\[pid \([0-9]*\).*/\1/p'
          grep -lE "^plane reputation stale generation $1( |$)" "$W"/counters/*.status 2>/dev/null | sed -n 's#.*/\([0-9]*\)-[0-9a-f]*\.status$#\1#p'; } | grep -vx -- "${HTTPD_PID:-0}" | sort -u | wc -l
    }
    # ---- 1. the outage: a plane past its valid-until, no newer file, 500 children cycled by MaxConnectionsPerChild 1
    GEN=$((GEN + 1)); G=$GEN
    m10_snap "$W/snapshot.bin" "$G" 1000
    m10_conf 1
    if start_httpd "$conf" "$MPM"; then
        r=$(code / "$LISTED"); line=$(last_access)
        if [ "$r" = 200 ] && [ "$(field "$line" verdict)" = "unknown,stale" ]; then
            ok "$L: a plane past its valid-until serves at once: the listed client passes as unknown,stale (fail open, generation $G stale)"
        else
            bad "$L: the stale plane answered $r with verdict $(field "$line" verdict)"
        fi
        m10_cycle 500
        await "[ \"\$(m10_stale_procs $G)\" -ge 500 ]" 60 "every cycled child's stale word"
        lines=$(m10_child_lines "plane snapshot.bin is stale: generation $G's valid-until passed"); pids=$(plane_pids "is stale: generation $G's valid-until passed"); procs=$(m10_stale_procs "$G")
        n1=$(grep -c ' 200 action=allow .* verdict=unknown,stale ' "$W/logs/access.log" 2>/dev/null || true)
        if [ "$procs" -ge 500 ] && [ "$lines" = "$pids" ] && [ "$n1" -ge 501 ] && ! grep -q 'exit signal' "$W/logs/error.log"; then
            ok "$L: through the outage 500 children were cycled: $procs child processes said the plane is stale, each once ($pids by a log line, $lines lines, the rest by their status file, having inherited the word from the parent), every one of $n1 requests passed as unknown,stale, no child exited on a signal"
        else
            bad "$L: the outage over cycled children: $procs processes said stale ($lines lines from $pids), $n1 fail-open requests, signals: $(grep -c 'exit signal' "$W/logs/error.log")"
        fi
        if [ "$TAG" = debug ]; then
            read -r c n0 n1 i <<<"$(m10_counts "$HTTPD_PID" 0)"
            if [ "$c" -ge 500 ] && [ "$n0" = "$c" ] && [ "$n1" = 0 ] && [ "$i" = 0 ]; then
                ok "$L: through the outage no process digested anything: $c child status files, every one carrying the digest pair, read digests 0 and start-digests 0"
            else
                bad "$L: the outage's digest counts: $c child status files, $n0 carrying the pair, digests $n1, start-digests $i (wanted 0 and 0 over at least 500)"
            fi
            # the control: the stale plane's mtime moved with its bytes the same, so a worker start finds the inherited
            # identity old and digests the armed inode on the start path; children forked after it read start-digests
            # above 0, so the 0 above is a reading of the counter on this path and not a counter that never moves.
            # The window closes when the parent's own check re-digests the inode and its later children inherit the
            # new identity (one move cycled 59 children and 4 of them digested at their start, measured), so the
            # mtime moves five times, each followed by its own cycles
            t0=$(m10_boot_ms)
            for i in 1 2 3 4 5; do
                python3 -c 'import os, sys; st = os.stat(sys.argv[1]); os.utime(sys.argv[1], ns=(st.st_atime_ns, st.st_mtime_ns + 1000000000))' "$W/snapshot.bin"
                m10_cycle 16
            done
            await_next_tick || true
            read -r c n0 n1 i <<<"$(m10_counts "$HTTPD_PID" "$t0")"
            if [ "$c" -ge 1 ] && [ "$n0" = "$c" ] && [ "$i" -ge 1 ]; then
                ok "$L's control: the plane's mtime moved and $c children forked after it read start-digests $i in all (digests $n1), so the outage row's 0 can fail"
            else
                bad "$L's control: after the mtime moved, $c children forked after it ($n0 with the pair) read start-digests $i and digests $n1; the outage row's 0 is not shown to be able to fail"
            fi
        fi
        stop_httpd "$conf" "$MPM" || bad "$L: httpd did not stop after the outage arm"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "$L: httpd did not start on the stale plane: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # ---- 2. a digest-failing newer file at the name, over 500 respawns and 10 ticks: the armed generation serves on
    GEN=$((GEN + 1)); G=$GEN
    m10_snap "$W/snapshot.bin" "$G" 0
    cp "$W/snapshot.bin" "$W/snapshot.m10good"
    m10_conf 1
    if start_httpd "$conf" "$MPM"; then
        await_first_tick || bad "$L: no first tick before the bad file"
        python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.m10tmp" "$((G + 1))" 0 3 "$RANGE_START" "$RANGE_END"
        python3 - "$W/snapshot.m10tmp" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0x5a                      # a body byte, so the header parses and the digest fails
open(p, "wb").write(b)
PY
        chmod 0644 "$W/snapshot.m10tmp"; mv "$W/snapshot.m10tmp" "$W/snapshot.bin"
        for i in 1 2 3 4 5 6 7 8 9 10; do m10_cycle 50; await_next_tick; done
        r=$(code / "$LISTED"); line=$(last_access)
        # every process that verified the file refused it once, the parent's monitor included (it verifies the
        # file itself, and the children it forks after that inherit the memory and verify nothing)
        lines=$(m10_lines "plane snapshot.bin refused:"); pids=$(grep -F "plane snapshot.bin refused:" "$W/logs/error.log" | sed -n 's/.*\[pid \([0-9]*\).*/\1/p' | sort -u | wc -l)
        if [ "$r" = 403 ] && [ "$(field "$line" gen)" = "reputation:$G.$(sed -n 's/.*plane reputation armed generation [0-9]* digest \([0-9a-f]\{8\}\).*/\1/p' <<<"$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null)" | head -1) tenant:-a" ] \
            && [ "$(m10_lines "generation $((G + 1)) verified, arming")" = 0 ] && [ "$lines" = "$pids" ] && [ "$pids" -ge 1 ]; then
            ok "$L: a digest-failing generation $((G + 1)) at the name over 500 respawns and 10 ticks: never armed, generation $G serves on (the listed client denied under it), and every process that verified the file refused it exactly once ($pids processes, $(grep -F 'plane snapshot.bin refused:' "$W/logs/error.log" | head -1 | sed 's/.*refused: //' | cut -c1-100))"
        else
            bad "$L: the bad newer file: listed $r under $(field "$line" gen), arming lines $(m10_lines "generation $((G + 1)) verified, arming"), refused $lines lines from $pids processes"
        fi
        # the inheritance: a child forked after the parent's monitor remembered the file verifies nothing. The
        # parent's own refusal line is the sign its monitor verifies; without it the arm waits on that body
        parent_line=$(grep -F 'plane snapshot.bin refused:' "$W/logs/error.log" | grep -E "\[pid ${HTTPD_PID}[]:]" | head -1)   # prefork prints "[pid N]", the threaded MPMs "[pid N:tid M]"
        if [ -n "$parent_line" ]; then
            # the row's claim is about FORK order: a child forked after the parent remembered the file verifies
            # nothing. Log order is not fork order: a child forked before the parent's refusal and still verifying
            # logs its own refusal after the parent's line. A walk at load 15 read 4 refusals after the parent's
            # line in log order and failed; its logs were not kept, so which order they were in is not known.
            # So each child that refused is placed by its fork, the starttime field of its status file
            # (/proc's field 22, clock ticks since boot), against the parent's line, its wall-clock stamp carried onto the same clock
            read -r after before_fork parent_ms <<<"$(m10_refused_after_fork "$HTTPD_PID")"
            if [ "$TAG" = debug ]; then
                read -r c n0 n1 i <<<"$(m10_counts "$HTTPD_PID" "$parent_ms")"
                if [ "$c" -ge 1 ] && [ "$n0" = "$c" ] && [ "$n1" = 0 ]; then
                    ok "$L: 0 digests after the first remembering process: the $c children forked after the parent's refusal read digests 0 and start-digests 0 on their status files"
                else
                    bad "$L: the children forked after the parent's refusal: $c status files, $n0 with the pair, digests $n1, start-digests $i (wanted at least one, all 0)"
                fi
            fi
            [ "$after" = 0 ] \
                && ok "$L: the failure memory is inherited: no child forked after the parent's refusal verified the file again (0 such refusals; $before_fork child refusal(s) logged after the parent's line came from children forked before it, by their own start time)" \
                || bad "$L: $after child(ren) forked after the parent's monitor had remembered the file refused it again, so the memory is not inherited ($before_fork more forked before it)"
        else
            bad "$L: the parent's monitor never refused the bad file, so no child was forked into the memory and the inheritance arm proves nothing ($pids refusals from $pids processes, none the parent's)"
        fi
        stop_httpd "$conf" "$MPM" || bad "$L: httpd did not stop after the bad-file arm"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "$L: httpd did not start for the bad-file arm: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    GEN=$((G + 1))                               # the refused generation's number is spent; the controls below go above it
    # ---- 3. an equal-generation copy with other bytes renamed in at a new inode on each of 10 ticks: refused by its
    # header, never digested, never armed, the plane serving on; then 4. a byte-identical copy of the armed bytes at a
    # new inode on each of 10 ticks: nothing logged, nothing re-armed
    cp "$W/snapshot.m10good" "$W/snapshot.bin"
    m10_conf 0
    if start_httpd "$conf" "$MPM"; then
        await_first_tick || bad "$L: no first tick before the copies"
        kids=$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')
        # the one arming line is the parent's, at the start; the children inherit the armed plane (measured)
        before=$(m10_child_lines 'verified, arming')
        dk=""; for k in $kids; do dk="$dk $(m10_pid_digests "$k" | cut -d' ' -f1)"; done   # each child's digests before the copies
        for i in 1 2 3 4 5 6 7 8 9 10; do
            m10_snap "$W/snapshot.bin" "$G" $((86400000 * i)); await_next_tick
            # after the first copy: the armed inode's re-digest is the one digest it causes (read below)
            [ "$i" = 1 ] && { dk1=""; for k in $kids; do dk1="$dk1 $(m10_pid_digests "$k" | cut -d' ' -f1)"; done; }
        done
        lines=$(m10_child_lines "plane snapshot.bin: generation $G is not above $G; refused by its header, not digested")
        if [ "$lines" = "$((10 * PINNED_CHILDREN))" ] && [ "$(m10_child_lines 'verified, arming')" = "$before" ] && [ "$(m10_child_lines 'disarmed')" = 0 ] \
            && [ "$(code / "$LISTED")" = 403 ] && "$SUMMARY_BIN" --status "$W/counters" >/dev/null 2>&1; then
            ok "$L: ten equal-generation copies with other bytes, each at a new inode: each of $PINNED_CHILDREN children refused each by its header, not digested ($lines child lines; the parent's monitor refused them too, $(( $(m10_lines "is not above $G") - lines )) lines of its own), nothing armed or disarmed, the plane armed and denying throughout"
        else
            bad "$L: the equal-generation copies: $lines header refusals by children (wanted $((10 * PINNED_CHILDREN)); the parent's own $(( $(m10_lines "is not above $G") - lines ))), arming lines $(m10_child_lines 'verified, arming') (were $before), disarmed $(m10_child_lines 'disarmed'), listed $(code / "$LISTED")"
        fi
        # a byte-identical copy of the armed bytes carries the armed generation, so its header is what refuses
        # it, before any digest, and it is remembered as a rollback (the header check runs ahead of the
        # equal-digest one, measured: the same line as above, once per child per inode)
        after=$(m10_child_lines 'whisper edge')
        for i in 1 2 3 4 5 6 7 8 9 10; do cp "$W/snapshot.m10good" "$W/snapshot.m10tmp"; mv "$W/snapshot.m10tmp" "$W/snapshot.bin"; await_next_tick; done
        lines=$(m10_child_lines "plane snapshot.bin: generation $G is not above $G; refused by its header, not digested")
        if [ "$lines" = "$((20 * PINNED_CHILDREN))" ] && [ "$(( $(m10_child_lines 'whisper edge') - after ))" = "$((10 * PINNED_CHILDREN))" ] \
            && [ "$(m10_child_lines 'verified, arming')" = "$before" ] && [ "$(m10_child_lines 'disarmed')" = 0 ] && [ "$(code / "$LISTED")" = 403 ] \
            && [ "$(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ')" = "$kids" ] && "$SUMMARY_BIN" --status "$W/counters" >/dev/null 2>&1; then
            ok "$L: ten byte-identical copies of the armed bytes, each at a new inode: each refused by its header before any digest and remembered (one line per child per inode, $((10 * PINNED_CHILDREN)) more, nothing else logged), nothing re-armed or disarmed, the same $PINNED_CHILDREN children serving and denying"
        else
            bad "$L: the equal-digest copies: $(( $(m10_child_lines 'whisper edge') - after )) new child lines ($lines header refusals by children in all), arming $(m10_child_lines 'verified, arming') (were $before), disarmed $(m10_child_lines 'disarmed'), listed $(code / "$LISTED"), children $(pgrep -P "$HTTPD_PID" 2>/dev/null | sort | tr '\n' ' ') vs $kids"
        fi
        if [ "$TAG" = debug ]; then
            # each child's digests across the twenty copies. The copies are refused by their headers and never digested.
            # The first rename over the name unlinks the ARMED inode, the unlink moves that inode's ctime, and a moved
            # ctime is re-digested (the defense M10's ctime control proves): one digest per child, of the armed bytes,
            # not of a copy (measured on the debug build: 1 at the first copy, 0 at each of the next nineteen). The
            # armed inode then stays unlinked and still, so the other nineteen copies cost nothing
            m10_delta_between() { # m10_delta_between <figures before> <figures after>, both in $kids order -> the increases
                local out="" a b
                set -- $1 "|" $2
                local -a A=() B=(); local side=A x
                for x in "$@"; do if [ "$x" = "|" ]; then side=B; elif [ $side = A ]; then A+=("$x"); else B+=("$x"); fi; done
                for x in "${!A[@]}"; do a=${A[$x]}; b=${B[$x]:--}
                    case "$a:$b" in -:*|*:-) out="$out -" ;; *) out="$out $((b - a))" ;; esac
                done
                printf '%s\n' "${out# }"
            }
            m10_delta() { # m10_delta <the per-child figures before, in $kids order> -> the per-child increases, "-" for a child without the pair
                local out="" k now
                set -- $1
                for k in $kids; do
                    now=$(m10_pid_digests "$k" | cut -d' ' -f1)
                    case "$1:$now" in -:*|*:-|:*) out="$out -" ;; *) out="$out $((now - $1))" ;; esac
                    shift
                done
                printf '%s\n' "${out# }"
            }
            t0=$(printf '0 %.0s' $kids); t0=${t0% }; t1=$(printf '1 %.0s' $kids); t1=${t1% }
            c=$(m10_delta "$dk1"); c1=$(m10_delta_between "$dk" "$dk1")
            if [ "$c1" = "$t1" ] && [ "$c" = "$t0" ]; then
                ok "$L: the copies are never digested: each of the $PINNED_CHILDREN children digested once at the first copy ($c1, the armed inode re-digested after the rename's unlink moved its ctime) and 0 times over the next nineteen ($c), every copy refused by its header"
            else
                bad "$L: the copies' per-child digests: '$c1' at the first copy (wanted '$t1', the armed inode's ctime re-digest) and '$c' over the next nineteen (wanted '$t0')"
            fi
            # control 1: a digest-failing newer generation at a new inode. The same children, forked before it, have no
            # memory of it, so each digests it exactly once, refuses it, and remembers: no second digest on later ticks.
            # The inheritance row's 0 is the memory a child is forked with, and this is the reading without it
            dk=""; for k in $kids; do dk="$dk $(m10_pid_digests "$k" | cut -d' ' -f1)"; done
            GEN=$((GEN + 1))
            python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.m10tmp" "$GEN" 0 3 "$RANGE_START" "$RANGE_END"
            python3 -c 'import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0x5a; open(p, "wb").write(b)' "$W/snapshot.m10tmp"
            chmod 0644 "$W/snapshot.m10tmp"; mv "$W/snapshot.m10tmp" "$W/snapshot.bin"
            await_next_tick; await_next_tick; await_next_tick
            c=$(m10_delta "$dk"); t0=$(printf '1 %.0s' $kids); t0=${t0% }
            if [ "$c" = "$t0" ] && [ "$(code / "$LISTED")" = 403 ]; then
                ok "$L's control: a digest-failing generation $GEN at the name: each child forked before it digested it exactly once over three ticks ($c), refused it and kept denying under generation $G, so the inheritance row's 0 can fail"
            else
                bad "$L's control: a digest-failing generation $GEN: the per-child digest increases over three ticks are '$c', wanted '$t0'"
            fi
            # control 2: a valid newer generation at a new inode passes its header, so each child digests it once and arms it;
            # the copies' 0 above is a header refusal, not a counter that never moves
            dk=""; for k in $kids; do dk="$dk $(m10_pid_digests "$k" | cut -d' ' -f1)"; done
            GEN=$((GEN + 1)); m10_snap "$W/snapshot.bin" "$GEN" 0
            await_next_tick; await_next_tick
            c=$(m10_delta "$dk")
            if [ "$c" = "$t0" ] && [ "$(m10_child_lines "generation $GEN verified, arming")" -ge 1 ]; then
                ok "$L's control: a valid generation $GEN at a new inode: each child digested it exactly once ($c) and armed it, so the copies' 0 can fail"
            else
                bad "$L's control: a valid generation $GEN: the per-child digest increases are '$c' (wanted '$t0'), arming lines $(m10_child_lines "generation $GEN verified, arming")"
            fi
        fi
        stop_httpd "$conf" "$MPM" || bad "$L: httpd did not stop after the copy arms"
    else
        bad "$L: httpd did not start for the copy arms: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the two plane controls (WE_MOD_TEST_CTIME_NO_DIGEST, WE_MOD_TEST_DROP_ARMED) are run_m10_control_rows
    rm -f "$W/snapshot.m10good" "$W/snapshot.m10tmp"
    fresh_snapshot
}

run_outage_debug_rows() { # the same M10 arms on the WE_MOD_DEBUG object, the only build whose status file carries the digest counts
    [ -n "$APXS" ] || { bad "M10 (debug build): no apxs to build the debug object"; return; }
    build_debug_module || { bad "M10 (debug build): the WE_MOD_DEBUG build failed: $(tail -2 "$CTL/debug.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    run_outage_rows "$CTL/debug.so" debug
}

run_m10_control_rows() { # M10's two plane controls on Apache: a ctime-only rewrite is re-digested, a failed candidate keeps the armed map
    local MPM=event conf="$W/httpd-m10c.conf" D="$W/m10cd" v st r g
    echo "  [M10's controls: the digest after a ctime-only rewrite, and the armed generation through a failed candidate]"
    [ -n "$APXS" ] || { bad "M10's controls: no apxs to build them"; return; }
    build_variant ctimenodigest -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_CTIME_NO_DIGEST \
        || { bad "M10's controls: the ctime build failed: $(tail -2 "$CTL/ctimenodigest.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant droparmed -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_DROP_ARMED \
        || { bad "M10's controls: the drop-armed build failed: $(tail -2 "$CTL/droparmed.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    m10c_start() { # m10c_start <object> <generation>: a data-directory reputation plane listing the gate's range, armed
        rm -rf "$D" "$W/counters" "$W/html"; mkdir -p "$D" "$W/html" "$W/logs"; chmod 0755 "$D"; echo page > "$W/html/index.html"
        python3 "$ROOT/core/make-test-snapshot.py" "$D/reputation.new" "$2" 0 3 "$RANGE_START" "$RANGE_END"
        chmod 0444 "$D/reputation.new"; mv "$D/reputation.new" "$D/reputation.bin"
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#"
          printf '%s\n' "WhisperEdgeData $D" "WhisperEdgeRefresh 10" "WhisperEdgeSummary $W/counters" 'WhisperEdgeMode deny' \
              'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader X-Forwarded-For' 'WhisperEdgeTrustedHops 2' \
              'WhisperEdgePolicy "deny if listed >= low"'
        } > "$conf"
        start_httpd "$conf" "$MPM" || return 1
        await "[ \"\$(code / $LISTED)\" = 403 ]" 20 "the plane armed and denying"
    }
    m10c_state() { "$SUMMARY_BIN" --status "$W/counters" 2>/dev/null | sed -n 's/^ *plane reputation \([a-z]*\)\( generation \([0-9]*\)\)\{0,1\}.*/\1 \3/p' | sort -u | tr '\n' ';'; }
    m10c_stop() {
        stop_httpd "$conf" "$MPM" || bad "M10's controls: httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    }
    # ---- (1) the bytes rewritten in place with the mode and mtime put back, so only the ctime moved: the trust
    # checks pass and the re-digest finds other bytes, so every child disarms for good and the forged bytes never
    # serve. The control (the trust checks alone, no re-digest) keeps serving them ----
    for v in "$MODULE:release" "$CTL/ctimenodigest.so:control"; do
        if ! m10c_start "${v%%:*}" 50; then bad "M10 ctime(${v##*:}): the armed configuration did not start or deny"; continue; fi
        python3 - "$D/reputation.bin" <<'PY'
import os, sys
p = sys.argv[1]
st = os.stat(p)
os.chmod(p, 0o644)
with open(p, "r+b") as f:                    # a byte of the body, rewritten in place, the size unchanged
    f.seek(st.st_size // 2)
    b = f.read(1)
    f.seek(st.st_size // 2)
    f.write(bytes([b[0] ^ 0x40]))
os.chmod(p, 0o444)
os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))   # the mtime put back: only the ctime moved
PY
        await_next_tick || true; await_next_tick || true; await_next_tick || true
        st=$(m10c_state); r=$(code / "$LISTED")
        case "${v##*:}" in
        release)
            case "$st" in disarmed*) g=yes ;; *) g=no ;; esac
            [ "$g" = yes ] && [ "$r" = 200 ] \
                && ok "M10: a ctime-only rewrite of the armed plane's bytes (mode and mtime put back) is re-digested and disarmed for good on every child ($st), and the listed client fails open (200), so the forged bytes never serve" \
                || bad "M10: a ctime-only rewrite: the plane reads '$st' and the listed client $r, wanted disarmed and 200" ;;
        *)
            case "$st" in armed*) g=yes ;; *) g=no ;; esac
            [ "$g" = yes ] \
                && ok "M10's control: the trust-checks-only build (WE_MOD_TEST_CTIME_NO_DIGEST) keeps the rewritten plane armed ($st, the listed client $r), so the row above can fail" \
                || bad "M10's control: WE_MOD_TEST_CTIME_NO_DIGEST read '$st', not armed, so the row above proves nothing" ;;
        esac
        m10c_stop
        [ "${v##*:}" = control ] && ctl_exit_clean "M10's ctime control"
    done
    # ---- (2) a digest-failing newer generation renamed in at the name: refused, and the armed generation keeps
    # serving. The control (a failed candidate drops the armed generation) disarms it ----
    for v in "$MODULE:release" "$CTL/droparmed.so:control"; do
        if ! m10c_start "${v%%:*}" 60; then bad "M10 drop(${v##*:}): the armed configuration did not start or deny"; continue; fi
        python3 "$ROOT/core/make-test-snapshot.py" "$D/reputation.bad" 61 0 3 "$RANGE_START" "$RANGE_END"
        python3 - "$D/reputation.bad" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b) // 2] ^= 0x5a                       # a body byte: the header parses, the digest fails
open(p, "wb").write(b)
PY
        chmod 0444 "$D/reputation.bad"; mv "$D/reputation.bad" "$D/reputation.bin"
        await "grep -q 'plane reputation.bin refused' '$W/logs/error.log'" 30 "the refusal" || true
        await_next_tick || true; await_next_tick || true
        st=$(m10c_state); r=$(code / "$LISTED")
        case "${v##*:}" in
        release)
            [ "$st" = "armed 60;" ] && [ "$r" = 403 ] \
                && ok "M10: a digest-failing generation 61 renamed in at the name is refused and generation 60 keeps serving on every child ($st), the listed client still denied (403)" \
                || bad "M10: the failed candidate: the plane reads '$st' and the listed client $r, wanted armed 60 and 403" ;;
        *)
            [ "$st" != "armed 60;" ] && [ "$r" != 403 ] \
                && ok "M10's control: the build dropping the armed generation on a failed candidate (WE_MOD_TEST_DROP_ARMED) reads '$st' and the listed client $r, so the row above can fail" \
                || bad "M10's control: WE_MOD_TEST_DROP_ARMED still served generation 60 ($st, $r), so the row above proves nothing" ;;
        esac
        m10c_stop
        [ "${v##*:}" = control ] && ctl_exit_clean "M10's drop-armed control"
    done
    rm -rf "$D" "$W/counters"
    fresh_snapshot
}

run_pidreuse_rows() { # S3: pid reuse forced inside the gate's own pid namespace; the files' identity carries the counts across it
    local S3D NSH out r sent forced reused total live gone n
    echo "  [pid reuse, forced in a pid namespace]"
    if ! sudo -n true 2>/dev/null || ! sudo -n unshare --pid --fork --mount-proc true 2>/dev/null; then
        na "S3: the pid-reuse arms need root for a pid namespace and /proc/sys/kernel/ns_last_pid, and this run has none, so they stand unwalked"
        return
    fi
    [ -n "$APXS" ] || { bad "S3: no apxs to build the control module"; return; }
    build_variant pidonly -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PID_ONLY_NAMES \
        || { bad "S3: the pid-only-names control build failed: $(tail -2 "$CTL/pidonly.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    rm -rf "$W/html"; mkdir -p "$W/html"; echo page > "$W/html/index.html"
    # the configuration is read as root inside the namespace, so every file defining an http-level directive and
    # every directory above it must be root's, and every directory above the plane must be neither writable by
    # others nor the sticky /tmp (the module refused that chain, measured): a root-owned directory under /run,
    # the counters inside it owned by the children's uid (the writer's root rule binds only a process that
    # itself runs as root)
    S3D=$(sudo -n mktemp -d /run/we-gate-s3.XXXXXX) || { bad "S3: cannot make the root-owned directory"; return; }
    sudo -n chmod 0755 "$S3D"; sudo -n mkdir -p "$S3D/logs" "$S3D/counters"; sudo -n chown "$(id -u):$(id -g)" "$S3D/counters"
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/s3snap.tmp" "$GEN" 0 3 "$RANGE_START" "$RANGE_END"
    sudo -n cp "$W/s3snap.tmp" "$S3D/snapshot.bin"; sudo -n chmod 0644 "$S3D/snapshot.bin"; rm -f "$W/s3snap.tmp"
    s3_conf() { # s3_conf <module> -> the root-owned configuration: prefork, two children cycled by MaxConnectionsPerChild 1
        { conf_head prefork | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#; s#^PidFile .*#PidFile $S3D/httpd.pid#; s#^ErrorLog .*#ErrorLog $S3D/logs/error.log#; s#^CustomLog .*#CustomLog $S3D/logs/access.log whisperfmt#; s#^MaxConnectionsPerChild 0\$#MaxConnectionsPerChild 1#"
          echo "User $(id -un)"; echo "Group $(id -gn)"
          conf_data | sed "s#^WhisperEdgeSnapshot .*#WhisperEdgeSnapshot $S3D/snapshot.bin#"
          echo "WhisperEdgeSummary $S3D/counters"
          echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'
        } > "$W/s3.conf"
        sudo -n cp "$W/s3.conf" "$S3D/httpd.conf"; sudo -n chmod 0644 "$S3D/httpd.conf"
    }
    # the namespace script: forks only to make a request; the wait for a child's exit, the ns_last_pid write and
    # the wait for the respawn are builtins over /proc, so the parent's fork is the next one in the namespace
    NSH="$W/s3-ns.sh"
    cat > "$NSH" <<'NS'
#!/bin/bash
set -u
S3D=$1 PORT=$2 N=$3 LISTED=$4 HOP=$5 HTTPD=$6 SUM=$7
cd "$S3D" || exit 1
rm -f counters/* logs/*
"$HTTPD" -f "$S3D/httpd.conf" -k start 2>"$S3D/start.err" || { echo "S3-START-FAILED $(tr '\n' ' ' < "$S3D/start.err" | cut -c1-300)"; exit 1; }
for ((i = 0; i < 100; i++)); do c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/" 2>/dev/null); [ "$c" = 200 ] && break; sleep 0.1; done
[ "$c" = 200 ] && [ -f "$S3D/httpd.pid" ] || { echo "S3-START-FAILED $(grep -v 'policy:' "$S3D/logs/error.log" 2>/dev/null | tail -2 | tr '\n' ' ' | cut -c1-300)"; exit 1; }
PARENT=$(cat "$S3D/httpd.pid")
mkfifo "$S3D/nap"; exec 9<>"$S3D/nap"
CH="" ZH=""
# the parent's children from /proc, the live ones and the zombies apart (a zombie is a child that has exited and
# waits for the parent's reap, which prefork does in the same maintenance pass as the respawn)
children() { local d p st rest; CH=""; ZH=""; for d in /proc/[0-9]*; do p=${d#/proc/}; st=""; rest=""; { read -r _ _ st rest < "$d/stat"; } 2>/dev/null || continue; set -- $rest; [ "${1:-}" = "$PARENT" ] || continue; if [ "$st" = Z ]; then ZH="$ZH $p"; else CH="$CH $p"; fi; done; }
nap() { read -t 0.02 -u 9 _ 2>/dev/null; }
sent=0 forced=0 reused=0 dead="" prev="" nb=0
for ((i = 0; i < N; i++)); do
    children; set -- $CH; nb=$#
    # the parent is held by SIGSTOP before the request, which the children serve on their own; the served child
    # exits into a zombie that stands until the parent runs again. The pid set as the next one is the PREVIOUS
    # cycle's dead child's (reaped since, so free): prefork forks the replacement before it reaps the child that
    # just exited (measured: the respawn took the zombie's pid plus one every time the zombie's own pid was set),
    # and a pid freed one cycle earlier is taken every time. Nothing here forks between the write and that fork.
    kill -STOP "$PARENT"
    curl -s -o /dev/null -H "X-Forwarded-For: $LISTED, $HOP" --max-time 8 "http://127.0.0.1:$PORT/" 2>/dev/null && sent=$((sent + 1))
    dead=""
    for ((t = 0; t < 400 && ${#dead} == 0; t++)); do children; set -- $ZH; dead=${1:-}; [ -n "$dead" ] || nap; done
    if [ -z "$dead" ]; then kill -CONT "$PARENT"; continue; fi
    if [ -n "$prev" ]; then echo $((prev - 1)) > /proc/sys/kernel/ns_last_pid; forced=$((forced + 1)); fi
    kill -CONT "$PARENT"
    for ((t = 0; t < 400; t++)); do children; set -- $CH; [ $# -ge "$nb" ] && [ -z "$ZH" ] && break; nap; done
    if [ -n "$prev" ]; then case " $CH " in *" $prev "*) reused=$((reused + 1)) ;; esac; fi
    prev=$dead
done
dg=$(grep 'whisper edge: policy: server "127.0.0.1"' "$S3D/logs/error.log" | tail -1 | sed -n 's/.*program \([0-9a-f]\{16\}\).*/\1/p')
total=$("$SUM" --rules "$S3D/counters" 2>/dev/null | awk -v d="$dg" '$1 == "r" && $2 == d && $3 == 1 { s += $4 } END { print s + 0 }')
status=$("$SUM" --status "$S3D/counters" 2>/dev/null | grep -E '^live ' | head -1)
echo "S3-RESULT sent=$sent forced=$forced reused=$reused total=$total files=$(ls counters | wc -l) $status"
timeout 20 "$HTTPD" -f "$S3D/httpd.conf" -k stop >/dev/null 2>&1
t=0; while [ "$t" -lt 100 ] && [ -f "$S3D/httpd.pid" ]; do sleep 0.2; t=$((t + 1)); done
[ -f "$S3D/httpd.pid" ] && kill -TERM "$PARENT" 2>/dev/null
exit 0
NS
    s3_run() { # s3_run <module> <cycles> -> the S3-RESULT line
        s3_conf "$1"
        sudo -n unshare --pid --fork --mount-proc bash "$NSH" "$S3D" "$PORT" "$2" "$LISTED" "$HOP" "$HTTPD" "$SUMMARY_BIN" 2>&1 | grep -E '^S3-' | tail -1
    }
    s3_field() { printf '%s\n' "$1" | sed -n "s/.*[ ]$2=\([0-9]*\).*/\1/p" | head -1; }
    out=$(s3_run "$MODULE" 500)
    r=$(printf '%s\n' "$out" | grep '^S3-RESULT' | tail -1)
    sent=$(s3_field "$r" sent); forced=$(s3_field "$r" forced); reused=$(s3_field "$r" reused); total=$(s3_field "$r" total)
    live=$(printf '%s\n' "$r" | sed -n 's/.*live \([0-9]*\),.*/\1/p'); gone=$(printf '%s\n' "$r" | sed -n 's/.*gone \([0-9]*\),.*/\1/p')
    if [ -z "$r" ]; then
        bad "S3: the namespace run printed no result: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
    elif [ "${reused:-0}" -lt 400 ]; then
        bad "S3: the forcing took only ${reused:-0} pid reuses in ${forced:-0} forced respawns of ${sent:-0} requests (fewer than the 400 the row needs), so the row is unproven this run"
    elif [ "$total" = "$sent" ] && [ "$sent" -ge 500 ]; then
        ok "S3: 500 prefork children cycled in a pid namespace with ns_last_pid set to each dead child's pid less one: $reused of $forced respawns took a dead child's pid, and the rule count summed over live and gone files ($live live, $gone gone) is exactly the $sent requests sent, the files' pid and start-time identity keeping every gone writer's counts apart"
    else
        bad "S3: $reused reuses forced, but the summed count is $total for $sent requests ($live live, $gone gone)"
    fi
    # the control: files named by the pid alone, so a reused pid writes over the gone child's counts
    out=$(s3_run "$CTL/pidonly.so" 100)
    r=$(printf '%s\n' "$out" | grep '^S3-RESULT' | tail -1)
    sent=$(s3_field "$r" sent); reused=$(s3_field "$r" reused); total=$(s3_field "$r" total)
    if [ -n "$r" ] && [ "${reused:-0}" -ge 50 ] && [ "${total:-0}" -lt "${sent:-1}" ]; then
        ok "S3: the pid-only-names control loses counts under the same forcing: $total of $sent requests survive $reused pid reuses, so the start-time half of the identity is load-bearing"
    else
        bad "S3: the pid-only-names control: result '$r'"
    fi
    sudo -n rm -rf "$S3D"; rm -f "$W/s3.conf" "$NSH"
    fresh_snapshot
}

run_baseline_rows() { # baseline: a counter baseline read behind the per-child barrier holds every denial served before it
    local MPM=worker conf="$W/httpd-bl.conf" v A B tB tA n0 n1 m r i kids timer
    echo "  [the counter baseline under a forced tick skew between two worker children]"
    # the forcing, per arm: child A held across one of B's ticks, so B is strictly one tick ahead (asserted while
    # both are held); right after B's tick, two denials served by B with A held; then B held 20 s (its flush with
    # them) while A goes on; the baseline is read
    # behind the arm's barrier, six denials follow, and the after-read waits for B's return and every child's
    # next tick. The min-tick barrier (the control, the barrier the gate used before) returns on A's tick with B's two
    # denials still unflushed, so its delta reads eight; the per-child barrier waits for B and reads six.
    # The min-tick snapshot is taken while BOTH children are held, before A goes on: a held child's missed tick
    # fires the moment it is continued (measured on a test host: A's file went 0 -> 1 within a second of SIGCONT), so
    # a snapshot taken after the continue raced A's catch-up tick, found the pair level, and waited for B's flush
    # (the control read 2 -> 8 on two x86_64 runs)
    for v in perchild mintick; do
        rm -rf "$W/html" "$W/counters" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
        fresh_snapshot
        { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } > "$conf"
        if ! start_httpd "$conf" "$MPM"; then
            bad "baseline($v): httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            continue
        fi
        HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
        await '[ "$(pgrep -P "$HTTPD_PID" | wc -l)" = 2 ]' 15 "two children"
        await_first_tick
        kids=$(pgrep -P "$HTTPD_PID" | sort -n | tr '\n' ' ')
        read -r A B _ <<<"$kids"
        r=$(bl_rule_ctx)
        kill -STOP "$A"
        tA=$(bl_tick "$A"); tB=$(bl_tick "$B"); i=$(( ${tA:-0} > ${tB:-0} ? ${tA:-0} : ${tB:-0} ))
        await "[ \"\$(bl_tick $B)\" -gt $i ] 2>/dev/null" 25 "B's tick past A's"
        for i in 1 2; do code / "$LISTED" >/dev/null; done
        kill -STOP "$B"
        tA=$(bl_tick "$A"); tB=$(bl_tick "$B"); m=$(tick_of)
        [ "${tA:-0}" -lt "${tB:-0}" ] && [ "${m:-x}" = "${tA:-0}" ] \
            || bad "baseline($v): the forcing did not hold A behind B (A's tick $tA, B's $tB, the smallest $m)"
        kill -CONT "$A"
        ( sleep 20; kill -CONT "$B" 2>/dev/null ) & timer=$!
        if [ "$v" = mintick ]; then
            await "t=\$(tick_of); [ -n \"\$t\" ] && [ \"\$t\" -gt ${m:-0} ]" 40 "the smallest tick"
        else
            await_next_tick
        fi
        n0=$(rule_count "$r" 1)
        for i in 1 2 3 4 5 6; do code / "$LISTED" >/dev/null; done
        wait "$timer"
        await_next_tick
        n1=$(rule_count "$r" 1)
        case "$v" in
        perchild)
            [ "$((n1 - n0))" = 6 ] \
                && ok "baseline: two worker children with forced tick skew (A one tick behind, B held with two unflushed denials): the baseline read behind the per-child barrier waits for B and holds them ($n0), and six denials move rule 1 by exactly six ($n0 -> $n1)" \
                || bad "baseline: behind the per-child barrier six denials moved rule 1 $n0 -> $n1 (A's tick at the read $tA)" ;;
        mintick)
            [ "$((n1 - n0))" -gt 6 ] \
                && ok "baseline's control: the min-tick barrier under the same forcing returns on A's tick with B's two denials unflushed, so the same six read as $((n1 - n0)) ($n0 -> $n1): the arm above can fail" \
                || bad "baseline's control: the min-tick barrier read $n0 -> $n1 under the forcing, so the forcing did not open the window and the per-child arm proves nothing" ;;
        esac
        stop_httpd "$conf" "$MPM" || bad "baseline($v): httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    done
    rm -rf "$W/counters" "$W/logs"; mkdir -p "$W/logs"
    fresh_snapshot
}
bl_tick() { sed -n 's/^tick \([0-9]*\)$/\1/p' "$W"/counters/"$1"-*.rules.cnt 2>/dev/null | head -1; }
bl_rule_ctx() { ctx_digest "$(cfg_lines)" 'server "127.0.0.1"'; }

run_slowstop_rows() { # Q1's slow-stop arms: a child whose module thread is slow to stop keeps the counts it served
    local MPM=prefork conf="$W/httpd-q1s.conf" v d_ctx total aband stagew t0 t1 i k served unaband nserved stillup
    echo "  [a module thread slow to stop: the counts of one request per child, MaxConnectionsPerChild 1]"
    [ -n "$APXS" ] || { bad "q1s: no apxs to build the debug modules"; return; }
    # five builds: the final write slowed past the 2 s window but running (four 800 ms steps); held 3.5 s in one
    # piece (a slow disk); held 8 s, past the 6 s cap; the first under the old flat deadline, the control; and a
    # plane job stuck 5 s when the stop comes, which is abandoned once a window passes with no progress
    build_variant slowstop -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_SLOW_STOP \
        || { bad "q1s: the slow-stop build failed: $(tail -2 "$CTL/slowstop.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant stallwrite -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_STALL_WRITE=3500 \
        || { bad "q1s: the stalled-write build failed: $(tail -2 "$CTL/stallwrite.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant stallcap -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_STALL_WRITE=8000 \
        || { bad "q1s: the past-the-cap build failed: $(tail -2 "$CTL/stallcap.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant slowflat -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_SLOW_STOP -Wc,-DWE_MOD_TEST_FLAT_DEADLINE \
        || { bad "q1s: the flat-deadline build failed: $(tail -2 "$CTL/slowflat.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant stallstop -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_STALL_STOP \
        || { bad "q1s: the stalled-plane-job build failed: $(tail -2 "$CTL/stallstop.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    for v in slowstop stallwrite stallcap slowflat stallstop; do
        rm -rf "$W/html" "$W/counters" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
        fresh_snapshot
        { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } \
            | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/$v.so#; s/^StartServers 2\$/StartServers 8/; s/^MinSpareServers 2\$/MinSpareServers 8/; s/^MaxSpareServers 2\$/MaxSpareServers 8/; s/^MaxRequestWorkers 2\$/MaxRequestWorkers 8/; s/^MaxConnectionsPerChild 0\$/MaxConnectionsPerChild 1/" > "$conf"
        if ! start_httpd "$conf" "$MPM"; then
            bad "q1s($v): httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
            continue
        fi
        HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
        await '[ "$(pgrep -P "$HTTPD_PID" | wc -l)" -ge 8 ]' 15 "eight children"
        d_ctx=$(ctx_digest "$(cfg_lines)" 'server "127.0.0.1"')
        t0=$(date +%s%N)
        for i in 1 2 3 4 5 6 7 8; do
            curl -s -o /dev/null --max-time 8 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" &
        done
        wait
        # the counts land when each serving child's final write does; 14 s is past every bound the stop keeps
        await "[ \"\$(rule_count $d_ctx 1)\" = 8 ]" 14 "the eight counts" || true
        t1=$(date +%s%N)
        sleep 1
        total=$(rule_count "$d_ctx" 1)
        aband=$(grep -c 'the module thread did not stop within' "$W/logs/error.log" 2>/dev/null || true)
        stagew=$(sed -n 's/.*the module thread did not stop within.*(the thread was in: \(.*\))$/\1/p' "$W/logs/error.log" | sort | uniq -c | sed 's/^ *//' | tr '\n' ';' | sed 's/;$//')
        # the children that served (each logs its one denial) and the children that abandoned their thread, by pid:
        # the abandonment arms ask that every child that served abandoned, which holds however the parallel requests
        # spread over the children (a walk read 6 abandonments for 8 requests, with the row counting 8)
        served=$(sed -n 's/.*\[pid \([0-9]*\)[]:].*whisper edge: denied .*/\1/p' "$W/logs/error.log" | sort -u)
        # every child that served has finished its stop before the lines are read: on a loaded host the last one's
        # 6 s cap can end after the counts' wait (a full walk read one serving child not yet abandoned)
        # shellcheck disable=SC2086
        await "[ -z \"\$(for k in $(tr '\n' ' ' <<<"$served"); do kill -0 \$k 2>/dev/null && echo \$k; done)\" ]" 20 "the serving children's exits" || true
        stillup=$(for k in $served; do kill -0 "$k" 2>/dev/null && echo "$k"; done | tr '\n' ' ')
        cp "$W/logs/error.log" "$W/q1s-$v-error.log" 2>/dev/null   # kept for reading when an arm fails
        aband=$(grep -c 'the module thread did not stop within' "$W/logs/error.log" 2>/dev/null || true)
        stagew=$(sed -n 's/.*the module thread did not stop within.*(the thread was in: \(.*\))$/\1/p' "$W/logs/error.log" | sort | uniq -c | sed 's/^ *//' | tr '\n' ';' | sed 's/;$//')
        unaband=$(comm -23 <(printf '%s\n' "$served") <(sed -n 's/.*\[whisper edge\] pid \([0-9]*\): the module thread did not stop within.*/\1/p' "$W/logs/error.log" | sort -u) | grep -c . || true)
        nserved=$(grep -c . <<<"$served" || true)
        case "$v" in
        slowstop)
            if [ "$total" = 8 ] && [ "$aband" = 0 ]; then
                ok "q1s: a final write slower than the 2 s window but running (four 800 ms steps) keeps its counts: rule 1 summed 8 for the 8 requests, one per MaxConnectionsPerChild-1 child, no abandonment line, the last count in $(( (t1 - t0) / 1000000 )) ms"
            else
                bad "q1s: the slow-stop build: rule 1 summed $total for 8 requests, $aband abandonment line(s) ($stagew): a child whose thread was slow to stop lost what it served"
            fi ;;
        stallwrite)
            if [ "$total" = 8 ] && [ "$aband" = 0 ]; then
                ok "q1s: a final write held 3.5 s in one piece, no progress (a slow disk under the counters directory), keeps its counts: rule 1 summed 8 for 8, no abandonment line, the last count in $(( (t1 - t0) / 1000000 )) ms"
            else
                bad "q1s: the stalled-write build: rule 1 summed $total for 8 requests, $aband abandonment line(s) ($stagew)"
            fi ;;
        stallcap)
            if [ "${nserved:-0}" -ge 1 ] && [ "$unaband" = 0 ] && [ "${total:-8}" -lt 8 ] && [ "$stagew" = "$aband its final write" ]; then
                ok "q1s: a final write held 8 s is abandoned at the 6 s cap, so the stop stays bounded: every one of the $nserved children that served abandoned ($aband abandonment lines, each naming its final write), and rule 1 summed $total of 8, the window at risk the line states"
            else
                bad "q1s: the past-the-cap build: rule 1 summed $total, $aband abandonment line(s) ($stagew), $unaband of $nserved serving children did not abandon (still running: ${stillup:-none}): the cap did not hold"
            fi ;;
        slowflat)
            if [ "${total:-0}" -lt 8 ] && [ "${aband:-0}" -ge 1 ]; then
                ok "q1s: the flat-deadline control (WE_MOD_TEST_FLAT_DEADLINE, the stop before this fix) loses them: rule 1 summed $total for 8 requests with $aband abandonment line(s), so the arms above can fail"
            else
                bad "q1s: the flat-deadline control kept its counts (rule 1 $total, $aband abandonment lines), so the slow-stop arms prove nothing"
            fi ;;
        stallstop)
            # a thread that wakes while its process is still exiting may yet write, so the sum is held only below 8
            if [ "${nserved:-0}" -ge 1 ] && [ "$unaband" = 0 ] && [ "${total:-8}" -lt 8 ] && [ "$stagew" = "$aband a plane job" ]; then
                ok "q1s: a plane job stuck 5 s when the stop comes is abandoned once a 2 s window passes with no progress, the bound the stop keeps for a stalled plane read: every one of the $nserved children that served abandoned ($aband abandonment lines, each naming a plane job), and rule 1 summed $total of 8"
            else
                bad "q1s: the stalled-plane-job build: rule 1 summed $total, $aband abandonment line(s) ($stagew), $unaband of $nserved serving children did not abandon (still running: ${stillup:-none}): a stuck plane job was not abandoned at its bound"
            fi ;;
        esac
        stop_httpd "$conf" "$MPM" || bad "q1s($v): httpd did not stop"
        ctl_exit_clean "q1s's $v build"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    done
    rm -rf "$W/counters" "$W/logs"; mkdir -p "$W/logs"
    fresh_snapshot
}

run_nofold_rows() { # S6: no fold: a server process never opens another's counter file, over 10,000 cycled children and 100 writers ended between temp and rename
    local MPM=prefork conf="$W/httpd-s6.conf" PRE kills=0 i t f pid pp sent n foreign gone_files gone_bytes sumline sfiles sbytes d_ctx total
    echo "  [no fold: 10,000 cycled children, 100 writers ended between temp and rename]"
    [ -n "$APXS" ] || { bad "S6: no apxs to build the debug modules"; return; }
    build_variant pause -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PAUSE_BEFORE_RENAME \
        || { bad "S6: the pause build failed: $(tail -2 "$CTL/pause.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant fold -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PAUSE_BEFORE_RENAME -Wc,-DWE_MOD_TEST_FOLD_IN_SERVER \
        || { bad "S6: the fold control build failed: $(tail -2 "$CTL/fold.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    # the foreign-open counter: an interposer preloaded into httpd, so every openat the server makes, the
    # core's included, passes through it; an open of a counter, status, shard or temp file carrying another
    # process's pid is written to stderr, which httpd's children hold on the error log
    PRE="$CTL/we_foreign_open.so"
    cat > "$CTL/we_foreign_open.c" <<'CSRC'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
static int (*real_openat)(int, const char *, int, ...);
int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    if (real_openat == NULL) real_openat = (int (*)(int, const char *, int, ...)) dlsym(RTLD_NEXT, "openat");
    {   /* the path is declared nonnull by the libc header, so it is read, not tested */
        const char *q = path; unsigned long long pid = 0;
        if (*q == '.') q++;
        if (*q >= '0' && *q <= '9') {
            while (*q >= '0' && *q <= '9') pid = pid * 10 + (unsigned long long) (*q++ - '0');
            if ((*q == '-' || *q == '.') && pid != (unsigned long long) getpid()
                    && (strstr(q, ".cnt") || strstr(q, ".status") || strstr(q, ".tmp") || strstr(q, ".shard"))) {
                char line[320]; int n = snprintf(line, sizeof line, "whisper edge: foreign open: %s by pid %lu\n", path, (unsigned long) getpid());
                if (n > 0) (void) !write(2, line, (size_t) n);
            }
        }
    }
    return real_openat(dirfd, path, flags, mode);
}
CSRC
    if ! gcc -shared -fPIC -O2 -Wall -Wextra -Werror -o "$PRE" "$CTL/we_foreign_open.c" -ldl 2>"$CTL/we_foreign_open.log"; then
        bad "S6: the foreign-open interposer failed to build: $(tail -2 "$CTL/we_foreign_open.log" | tr '\n' ' ' | cut -c1-200)"; return
    fi
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"; echo page > "$W/html/index.html"
    fresh_snapshot
    s6_conf() { # s6_conf <module>: prefork, 32 children, a child per connection (15.6 children a second, measured)
        { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } \
            | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#; s/^StartServers 2\$/ServerLimit 32\nStartServers 32/; s/^MinSpareServers 2\$/MinSpareServers 32/; s/^MaxSpareServers 2\$/MaxSpareServers 32/; s/^MaxRequestWorkers 2\$/MaxRequestWorkers 32/; s/^MaxConnectionsPerChild 0\$/MaxConnectionsPerChild 1/" > "$conf"
    }
    s6_start() { # s6_start: start_httpd with the interposer preloaded and the core's pause directory named
        rm -rf "$W/logs" "$W/pause"; mkdir -p "$W/logs" "$W/pause"
        WE_MOD_PAUSE_DIR=$W/pause LD_PRELOAD=$PRE "$HTTPD" -f "$conf" -k start 2>"$W/start-$MPM.err"
        await "[ \"\$(code_nohdr /)\" != 000 ]" 15 "httpd up" || return 1
        HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
    }
    s6_gone() { # s6_gone: the directory's own account of dead writers' status and rules files, count and bytes (the tool's rule)
        # a writer is live when its pid is a child of the parent AND that child started when the writer's status file
        # says it did: on a fast host a gone writer's pid is reused within the 10,000 cycles (measured on the first
        # x86_64 walk: four files of two gone writers counted live by pid alone), the reuse S3 is about
        python3 - "$W/counters" "$HTTPD_PID" <<'PY'
import os, re, subprocess, sys
d, parent = sys.argv[1], sys.argv[2]
def start_of(pid):
    try:
        st = open("/proc/%s/stat" % pid).read()
    except OSError:
        return None
    return st[st.rindex(")") + 2:].split()[19]
live = {}
for p in subprocess.run(["pgrep", "-P", parent], capture_output=True, text=True).stdout.split():
    t = start_of(p)
    if t is not None:
        live[p] = t
def writer_start(pid, id16):
    try:
        m = re.search(r" starttime (\d+) ", open(os.path.join(d, "%s-%s.status" % (pid, id16))).read())
    except OSError:
        return None
    return m.group(1) if m else None
n = b = 0
for f in os.listdir(d):
    m = re.match(r"^(\d+)-([0-9a-f]+)\.(status|rules\.cnt)$", f)
    if not m:
        continue
    pid, id16 = m.group(1), m.group(2)
    if pid in live and writer_start(pid, id16) == live[pid]:
        continue
    n += 1
    b += os.stat(os.path.join(d, f)).st_size
print(n, b)
PY
    }
    # two phases, so no count is ever lost to the pause itself: a writer held at its temp file and ended there
    # loses that write, and with a child per connection that write is the child's final flush of its one
    # request (measured: 2,453 counts short, one per orphaned temp). So the children are first cycled with the
    # flag off, every final flush landing; then a second httpd keeps its children, their counts are flushed
    # by a tick before the flag goes up, and the writers held at their NEXT tick's rename, which carries
    # nothing new, are the ones ended by SIGKILL, a hundred of them, each leaving its temp file behind
    s6_conf "$CTL/pause.so"
    if s6_start; then
        d_ctx=$(ctx_digest "$(cfg_lines)" 'server "127.0.0.1"')
        ab -c 32 -n 10000 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >"$W/s6-ab.out" 2>&1
        sent=$(sed -n 's/^Complete requests: *\([0-9]*\).*/\1/p' "$W/s6-ab.out")
        n=$(sed -n 's/^Failed requests: *\([0-9]*\).*/\1/p' "$W/s6-ab.out")
        await_next_tick
        total=$(rule_count "$d_ctx" 1)
        foreign=$(grep -c 'foreign open:' "$W/logs/error.log" 2>/dev/null || true)
        if [ "${sent:-0}" -ge 10000 ] && [ "${n:-1}" = 0 ] && [ "$total" = "$sent" ] && [ "$foreign" = 0 ]; then
            ok "S6: 10,000 prefork children cycled (32 at a time, one connection each): ab reports 0 failed requests, rule 1 of the server summed over live and gone files is exactly $total, and no server process opened another process's file (0 foreign opens through the preloaded interposer)"
        else
            bad "S6: the cycling phase: requests $sent (failed ${n:-?}), rule 1 summed $total, foreign opens $foreign"
            # the phase's own error log, kept before the kill phase's start empties the directory, and the
            # module's lines that name a lost count: a child that abandoned its thread at the stop deadline, or
            # one that ran with no thread and so wrote no counter file
            cp "$W/logs/error.log" "$W/s6-cycling-error.log" 2>/dev/null
            echo "    [S6 cycling shortfall: $(grep -c 'the module thread did not stop within' "$W/s6-cycling-error.log" 2>/dev/null || true) abandonment line(s), $(grep -c 'whisper edge: no module thread' "$W/s6-cycling-error.log" 2>/dev/null || true) no-thread line(s); the phase's log kept at $W/s6-cycling-error.log]"
        fi
        stop_httpd "$conf" "$MPM" || bad "S6: httpd did not stop after the cycling"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "S6: httpd did not start under the interposer: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the kill phase: the same directory (the cycled children's files stay as gone writers' files), children that
    # keep their connections, 200 requests flushed by a tick, then the flag and a hundred SIGKILLs at the rename
    { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } \
        | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/pause.so#; s/^StartServers 2\$/ServerLimit 32\nStartServers 32/; s/^MinSpareServers 2\$/MinSpareServers 32/; s/^MaxSpareServers 2\$/MaxSpareServers 32/; s/^MaxRequestWorkers 2\$/MaxRequestWorkers 32/" > "$conf"
    if s6_start; then
        d_ctx=$(ctx_digest "$(cfg_lines)" 'server "127.0.0.1"')
        await_first_tick
        ab -c 32 -n 200 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        await_next_tick
        # the core's pause (we_mod_test_pause): a writer at the rename point is held while <dir>/rename exists
        : > "$W/pause/rename"
        for ((i = 0; i < 100; i++)); do
            pid=""
            for ((t = 0; t < 400 && ${#pid} == 0; t++)); do
                for f in "$W"/counters/.*.tmp; do
                    [ -f "$f" ] || continue
                    pid=$(basename "$f" | sed -n 's/^\.\([0-9]*\)-.*/\1/p')
                    { read -r _ _ _ pp _ < "/proc/$pid/stat"; } 2>/dev/null || { pid=""; continue; }
                    [ "$pp" = "$HTTPD_PID" ] && break
                    pid=""
                done
                [ -n "$pid" ] || sleep 0.05
            done
            [ -n "$pid" ] || break
            kill -KILL "$pid" 2>/dev/null && kills=$((kills + 1))
            for ((t = 0; t < 100; t++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.02; done
        done
        rm -f "$W/pause/rename"
        await_next_tick
        total=$(rule_count "$d_ctx" 1)
        foreign=$(grep -c 'foreign open:' "$W/logs/error.log" 2>/dev/null || true)
        n=$(ls "$W"/counters/.*.tmp 2>/dev/null | wc -l)
        if [ "$kills" = 100 ] && [ "$total" = "$((10000 + 200))" ] && [ "$foreign" = 0 ] && [ "$n" -ge 100 ]; then
            ok "S6: 100 writers ended by SIGKILL between their temp file and its rename (held there by the pause hook), each leaving its temp ($n orphaned temp files), the counts flushed before the flag all present: rule 1 summed over live and gone files is exactly $total (10,000 cycled plus 200), 0 foreign opens"
        else
            bad "S6: the kill phase: kills $kills, rule 1 summed $total (wanted 10200), foreign opens $foreign, orphaned temps $n"
        fi
        # the gone writers' account, by the tool's own rule: a writer's status and rules files (its ranges file and
        # the dot-prefixed temps stand outside it), for every writer that is not live
        read -r gone_files gone_bytes <<<"$(s6_gone)"
        sumline=$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null | grep "gone writers' files" | head -1)
        sfiles=$(printf '%s\n' "$sumline" | sed -n "s/.*gone writers' files \([0-9]*\), \([0-9]*\) bytes.*/\1/p"); sbytes=$(printf '%s\n' "$sumline" | sed -n "s/.*gone writers' files \([0-9]*\), \([0-9]*\) bytes.*/\2/p")
        if [ -n "$sfiles" ] && [ "$sfiles" = "$gone_files" ] && [ "$sbytes" = "$gone_bytes" ]; then
            ok "S6: the summary's gone writers' account ($sfiles files, $sbytes bytes) equals the directory's own count of dead writers' status and rules files; beside them $(find "$W/counters" -maxdepth 1 -name '*.cnt' ! -name '*.rules.cnt' | wc -l) ranges files and $n orphaned temps, which the tool leaves out by design"
        else
            bad "S6: the summary says '$sumline' while the directory holds $gone_files dead writers' status and rules files of $gone_bytes bytes"
        fi
        stop_httpd "$conf" "$MPM" || bad "S6: httpd did not stop after the kill phase"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "S6: the kill phase's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the control: a server that folds the other processes' files itself is seen opening them
    rm -rf "$W/counters"
    s6_conf "$CTL/fold.so"
    if s6_start; then
        ab -c 32 -n 300 -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1
        await_next_tick; await_next_tick
        foreign=$(grep -c 'foreign open:' "$W/logs/error.log" 2>/dev/null || true)
        [ "$foreign" -gt 0 ] \
            && ok "S6: the fold-in-server control is seen by the same interposer: $foreign foreign opens over two ticks" \
            || bad "S6: the fold-in-server control opened nothing the interposer saw, so the counter is blind"
        stop_httpd "$conf" "$MPM" || bad "S6: the control's httpd did not stop"
    else
        bad "S6: the control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    rm -f "$W/s6-ab.out"
    fresh_snapshot
}

run_final_lock_rows() { # the final write takes the shard-list mutex by a bounded try, so a stop that lands while it is held stays short
    local MPM=prefork conf="$W/httpd-fl.conf" v held aband stagew
    echo "  [the final write against a held shard-list mutex, and a tick in flight at the stop]"
    [ -n "$APXS" ] || { bad "final lock: no apxs to build the controls"; return; }
    # every build holds the mutex in the stop (WE_MOD_TEST_HOLD_MU_AT_STOP), as prefork's SIGTERM handler would when it
    # lands inside a first request's registration. flblock takes the final write's lock blocking (the lock the try-lock
    # replaced). fltick also holds the stop until the module thread's next tick is waiting for that mutex
    # (WE_MOD_TEST_TICK_AT_STOP), the case a loaded walk hit by chance: the blocking tick lock then held the thread until
    # the 6 s cap abandoned it in "a tick's own work", and flblock read that instead of its own stage. A tick's lock now
    # gives the tick up on a stop; fltickblock keeps the blocking tick lock (WE_MOD_TEST_TICK_BLOCKING), the reproduction
    build_variant flhold -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_HOLD_MU_AT_STOP \
        || { bad "final lock: the held-mutex build failed: $(tail -2 "$CTL/flhold.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant flblock -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_HOLD_MU_AT_STOP -Wc,-DWE_MOD_TEST_FINAL_BLOCKING \
        || { bad "final lock: the blocking control build failed: $(tail -2 "$CTL/flblock.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant fltick -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_HOLD_MU_AT_STOP -Wc,-DWE_MOD_TEST_TICK_AT_STOP \
        || { bad "final lock: the tick-at-stop build failed: $(tail -2 "$CTL/fltick.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant fltickblock -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_HOLD_MU_AT_STOP -Wc,-DWE_MOD_TEST_TICK_AT_STOP \
        -Wc,-DWE_MOD_TEST_TICK_BLOCKING \
        || { bad "final lock: the blocking-tick control build failed: $(tail -2 "$CTL/fltickblock.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    for v in flhold flblock fltick fltickblock; do
        rm -rf "$W/html" "$W/counters" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
        fresh_snapshot
        { conf_head "$MPM"; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } \
            | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/$v.so#; s/^MaxConnectionsPerChild 0\$/MaxConnectionsPerChild 1/" > "$conf"
        start_httpd "$conf" "$MPM" || { bad "final lock($v): httpd did not start"; continue; }
        await_first_tick
        for _ in 1 2 3 4; do code / "$LISTED" >/dev/null; done     # each request ends its child, whose stop runs held
        # a tick-at-stop child waits up to one interval for its tick before stopping, then up to the 6 s cap
        await "[ \"\$(grep -cE 'the final write found the shard-list mutex held|the module thread did not stop within' '$W/logs/error.log')\" -ge 2 ]" 45 "two stops" || true
        held=$(grep -c 'the final write found the shard-list mutex held' "$W/logs/error.log" 2>/dev/null || true)
        aband=$(grep -c 'the module thread did not stop within' "$W/logs/error.log" 2>/dev/null || true)
        stagew=$(sed -n 's/.*the module thread did not stop within.*(the thread was in: \(.*\))$/\1/p' "$W/logs/error.log" | sort -u | tr '\n' ';')
        case "$v" in
        flhold)
            [ "${held:-0}" -ge 2 ] && [ "${aband:-0}" = 0 ] \
                && ok "final lock: with the shard-list mutex held through the stop, the final write gives up after its bounded try, writes the status file and says the counts are not written ($held line(s)); no stop is abandoned at the 6 s cap" \
                || bad "final lock: with the mutex held at the stop: $held held line(s), $aband abandonment line(s) ($stagew)" ;;
        flblock)
            [ "${aband:-0}" -ge 2 ] && [ "${held:-0}" = 0 ] && [ "$stagew" = "its final write;" ] \
                && ok "final lock's control: the blocking lock (WE_MOD_TEST_FINAL_BLOCKING) holds the final write until the stop abandons it at the cap ($aband abandonment line(s), each in its final write), so the row above can fail" \
                || bad "final lock's control: the blocking build read $aband abandonment line(s) ($stagew) and $held held line(s), so the row above proves nothing" ;;
        fltick)
            [ "${held:-0}" -ge 2 ] && [ "${aband:-0}" = 0 ] \
                && ok "final lock: a stop that lands with the mutex held AND the module thread's tick waiting for it: the tick gives up at the stop, the final write's bounded try writes the status file and the held line ($held line(s)); no stop is abandoned in a tick's own work" \
                || bad "final lock: a stop with a tick waiting on the held mutex: $held held line(s), $aband abandonment line(s) ($stagew)" ;;
        *)
            [ "${aband:-0}" -ge 2 ] && [ "${held:-0}" = 0 ] && [ "$stagew" = "a tick's own work;" ] \
                && ok "final lock's tick control: the blocking tick lock (WE_MOD_TEST_TICK_BLOCKING) under the same stop holds the tick until the cap abandons it ($aband abandonment line(s), each in a tick's own work), the stall the walk hit, so the row above can fail" \
                || bad "final lock's tick control: the blocking tick build read $aband abandonment line(s) ($stagew) and $held held line(s), so the row above proves nothing" ;;
        esac
        stop_httpd "$conf" "$MPM" || bad "final lock($v): httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        ctl_exit_clean "final lock's $v build"
    done
    fresh_snapshot
}

run_subblock_race_rows() { # the legacy copy's range sub-block is published to the module thread under the shard mutex
    local MPM=event conf="$W/httpd-sbr.conf" v hg pid n races sites
    echo "  [the range sub-block's publication, under helgrind]"
    if ! command -v valgrind >/dev/null 2>&1; then
        dark "subblock: this host has no valgrind, so the publication row stands unwalked"; return
    fi
    [ -n "$APXS" ] || { bad "subblock: no apxs to build the control"; return; }
    build_variant sbunlocked -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_SUBBLOCK_UNLOCKED \
        || { bad "subblock: the unlocked-publication control build failed: $(tail -2 "$CTL/sbunlocked.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    # a request thread swaps in a new sub-block on its first judged request after a publish, and the module thread
    # sums every live sub-block at its tick under the shard-list mutex. Helgrind reports any pair of accesses with no
    # happens-before between them; the row reads only the reports with an access in the swap, so httpd's and APR's
    # own lock-free paths, and the shards' relaxed atomic counters the tick sums by design, stay out of it
    for v in "$MODULE:release" "$CTL/sbunlocked.so:control"; do
        rm -rf "$W/html" "$W/counters" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
        fresh_snapshot
        { conf_head "$MPM" | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module ${v%%:*}#"
          conf_data | sed 's/^WhisperEdgeRefresh .*/WhisperEdgeRefresh 10/'
          echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; } > "$conf"
        hg="$W/hg-${v##*:}"; rm -f "$hg".*
        setsid valgrind --tool=helgrind --error-limit=no --num-callers=24 --log-file="$hg.%p" "$HTTPD" -X -f "$conf" \
            </dev/null >"$W/hg-${v##*:}.out" 2>&1 &
        pid=$!
        await "[ \"\$(code / $LISTED)\" = 403 ]" 120 "the server under helgrind denying" \
            || { bad "subblock(${v##*:}): the server under helgrind never answered 403"; kill -TERM "$pid" 2>/dev/null; continue; }
        for _ in 1 2 3 4 5 6 7 8; do code / "$LISTED" >/dev/null; done
        sleep 12                                   # a tick of the module thread sums the sub-blocks
        fresh_snapshot                             # a new generation: the next judged request swaps again
        sleep 12
        for _ in 1 2 3 4 5 6 7 8; do code / "$LISTED" >/dev/null; done
        sleep 12
        kill -TERM "$pid" 2>/dev/null
        await "! kill -0 $pid 2>/dev/null" 60 "helgrind's exit" || kill -KILL "$pid" 2>/dev/null
        n=$(cat "$hg".* 2>/dev/null | grep -c 'Possible data race')
        # a report runs from its "Possible data race" to helgrind's separator line; it counts when one of its two
        # accesses, not the block's allocation stack, is in the swap (the shards' relaxed atomic counters, which
        # the tick sums by design, sit in blocks the swap allocated and are not the defect)
        races=$(cat "$hg".* 2>/dev/null | awk '/^==[0-9]+== -{20,}/ || /Possible data race/ { if (r && hit) n++; r = 0; hit = 0; alloc = 0 }
            /Possible data race/ { r = 1 } r && /alloc.d/ { alloc = 1 }
            r && !alloc && /(at|by) 0x[0-9A-F]+: we_apache_subblock_swap/ { hit = 1 } END { if (r && hit) n++; print n + 0 }')
        sites=$(cat "$hg".* 2>/dev/null | grep -oE '(at|by) 0x[0-9A-F]+: we_[a-z_]+(\.[a-z0-9.]+)?' | awk '{ print $3 }' | grep -E 'we_apache_subblock_swap|we_tick_write' | sort -u | tr '\n' ' ')
        case "${v##*:}" in
        release)
            [ "${races:-0}" = 0 ] \
                && ok "subblock: under helgrind, a publish and two rounds of judged requests leave no race on the sub-block's swap ($n reports in all, none naming it)" \
                || bad "subblock: helgrind reports $races race(s) naming the swap ($sites), so the sub-block is published without ordering" ;;
        *)
            [ "${races:-0}" -ge 1 ] \
                && ok "subblock's control: the build publishing the sub-block outside the mutex (WE_MOD_TEST_SUBBLOCK_UNLOCKED) draws $races helgrind race report(s) naming $sites, so the row above can fail" \
                || bad "subblock's control: helgrind saw no race in the unlocked publication ($n reports in all), so the row above proves nothing" ;;
        esac
    done
    fresh_snapshot
}

run_mutex_rows() { # N7: no file I/O under the shard-list mutex, while new h2 workers register through slowed writer I/O
    local MPM=event conf="$W/httpd-n7.conf" PRE under waits slow found i
    echo "  [the shard-list mutex against the writer's slowed I/O]"
    [ -n "$APXS" ] || { bad "N7: no apxs to build the debug modules"; return; }
    if ! command -v h2load >/dev/null 2>&1; then
        dark "N7: this host ships no h2load, so the h2 worker churn the row needs stands unwalked this run"; return
    fi
    case $(need_mod http2_module mod_http2.so) in
        \#missing*) dark "N7: this httpd ships no mod_http2, so the row stands unwalked this run"; return ;;
    esac
    build_variant muflag -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_MU_FLAG \
        || { bad "N7: the mutex-flag build failed: $(tail -2 "$CTL/muflag.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant locked -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_MU_FLAG -Wc,-DWE_MOD_TEST_LOCKED_WRITE \
        || { bad "N7: the locked-write control build failed: $(tail -2 "$CTL/locked.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    # the interposer, preloaded into httpd: write, openat, renameat and fsync count a call made by the thread that
    # holds the shard-list mutex (the module's exported holder word names that thread), and a write to a counter
    # temp file is slowed by 200 ms so the writer's I/O spans the registrations the load drives
    PRE="$CTL/we_io_flag.so"
    cat > "$CTL/we_io_flag.c" <<'CSRC'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
static ssize_t (*real_write)(int, const void *, size_t);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_renameat)(int, const char *, int, const char *);
static int (*real_fsync)(int);
static volatile unsigned long *holder;
static int said_found;
static __thread int in_hook, temp_fd = -1;
static void say(const char *what)
{
    char line[160]; int n;
    if (!real_write) real_write = (ssize_t (*)(int, const void *, size_t)) dlsym(RTLD_NEXT, "write");
    n = snprintf(line, sizeof line, "whisper edge: %s\n", what);
    if (n > 0) (void) !real_write(2, line, (size_t) n);
}
static void check(const char *call)
{
    if (in_hook) return;
    in_hook = 1;
    /* looked up until found: the server's first wrapped calls precede the module's load, so a lookup made once
     * and kept would stay empty and every child would inherit it (measured: the flag found in 0 processes) */
    if (!holder) { holder = (volatile unsigned long *) dlsym(RTLD_DEFAULT, "we_mod_test_mu_holder");
        if (holder && !said_found) { said_found = 1; say("mutex flag found by the interposer"); } }
    if (holder && *holder != 0u && *holder == (unsigned long) syscall(SYS_gettid)) {
        char what[96]; snprintf(what, sizeof what, "io under the shard mutex: %s", call); say(what);
    }
    in_hook = 0;
}
ssize_t write(int fd, const void *buf, size_t len)
{
    if (!real_write) real_write = (ssize_t (*)(int, const void *, size_t)) dlsym(RTLD_NEXT, "write");
    check("write");
    if (fd == temp_fd && fd >= 0 && !in_hook) {
        struct timespec ts = { 0, 200000000L }; in_hook = 1; say("slow write injected"); nanosleep(&ts, NULL); in_hook = 0;
    }
    return real_write(fd, buf, len);
}
int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0; int fd;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t) va_arg(ap, int); va_end(ap); }
    if (!real_openat) real_openat = (int (*)(int, const char *, int, ...)) dlsym(RTLD_NEXT, "openat");
    check("openat");
    fd = real_openat(dirfd, path, flags, mode);
    if (fd >= 0 && path[0] == '.' && strstr(path, ".tmp")) temp_fd = fd;
    return fd;
}
int renameat(int od, const char *o, int nd, const char *n)
{
    if (!real_renameat) real_renameat = (int (*)(int, const char *, int, const char *)) dlsym(RTLD_NEXT, "renameat");
    check("renameat"); temp_fd = -1;
    return real_renameat(od, o, nd, n);
}
int fsync(int fd)
{
    if (!real_fsync) real_fsync = (int (*)(int)) dlsym(RTLD_NEXT, "fsync");
    check("fsync");
    return real_fsync(fd);
}
CSRC
    if ! gcc -shared -fPIC -O2 -Wall -Wextra -Werror -o "$PRE" "$CTL/we_io_flag.c" -ldl 2>"$CTL/we_io_flag.log"; then
        bad "N7: the I/O interposer failed to build: $(tail -2 "$CTL/we_io_flag.log" | tr '\n' ' ' | cut -c1-200)"; return
    fi
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"; echo page > "$W/html/index.html"
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/snapshot.bin" "$GEN" 0 4 "$RANGE_START" "$RANGE_END"
    n7_conf() { # n7_conf <module>: the N2 shape, h2 workers spawning above the thread count and idling out in a second
        {
            conf_head "$MPM"; conf_data
            need_mod http2_module mod_http2.so
            echo 'Protocols h2 h2c'; echo 'H2MaxWorkers 20'; echo 'H2MaxWorkerIdleSeconds 1'
            echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicyFloor "deny if listed >= critical"'
        } | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $1#" > "$conf"
    }
    n7_start() { rm -rf "$W/logs"; mkdir -p "$W/logs"; LD_PRELOAD=$PRE "$HTTPD" -f "$conf" -k start 2>"$W/start-$MPM.err"; await "[ \"\$(code_nohdr /)\" != 000 ]" 15 "httpd up" || return 1; HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null); }
    n7_load() { # two ticks of continuous h2 streams, so the workers' first requests fall across the writer's slowed I/O
        for i in 1 2; do h2load -D 11 -c 8 -m 8 -p h2c -H "X-Forwarded-For: $LISTED, $HOP" "http://127.0.0.1:$PORT/" >/dev/null 2>&1; done
    }
    n7_counts() { under=$(grep -c 'io under the shard mutex' "$W/logs/error.log" 2>/dev/null || true); waits=$(grep -c 'a registration waited' "$W/logs/error.log" 2>/dev/null || true); slow=$(grep -c 'slow write injected' "$W/logs/error.log" 2>/dev/null || true); found=$(cat "$W/logs/error.log" "$W/start-$MPM.err" 2>/dev/null | grep -c 'mutex flag found by the interposer' || true); }   # the parent finds the flag at load, before its stderr is the error log (measured: the line in the start file)
    n7_conf "$CTL/muflag.so"
    if n7_start; then
        await_first_tick; n7_load; await_next_tick
        n7_counts
        if [ "$found" -ge 1 ] && [ "$slow" -gt 0 ] && [ "$under" = 0 ]; then
            ok "N7: through $slow slowed writer writes (200 ms each) across two ticks of continuous h2 streams with workers idling out each second, no write, openat, renameat or fsync was made by the thread holding the shard-list mutex (0 of them under it; the flag seen by the interposer in $found processes); registrations that waited over 1 ms for the mutex: $waits (printed, not gated)"
        else
            bad "N7: flag found in $found processes, slowed writes $slow, I/O calls under the mutex $under, waits over 1 ms $waits"
        fi
        stop_httpd "$conf" "$MPM" || bad "N7: httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "N7: httpd did not start under the interposer: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    # the control: the writer holds the mutex across its file I/O
    rm -rf "$W/counters"
    n7_conf "$CTL/locked.so"
    if n7_start; then
        await_first_tick; n7_load; await_next_tick
        n7_counts
        if [ "$under" -gt 0 ]; then
            ok "N7: the locked-write control is seen: $under I/O calls under the shard-list mutex, and $waits registrations waited over 1 ms behind the writer's slowed I/O"
        else
            bad "N7: the locked-write control made no I/O the interposer saw under the mutex (flag found $found, slowed writes $slow)"
        fi
        stop_httpd "$conf" "$MPM" || bad "N7: the control's httpd did not stop"
    else
        bad "N7: the control's httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    fresh_snapshot
}

run_cloexec_rows() { # Q4: every descriptor the module holds is close-on-exec, and a CGI child holds none
    local MPM=prefork conf="$W/httpd-q4.conf" pidmaster res n miss
    echo "  [close-on-exec]"
    rm -rf "$W/html" "$W/counters" "$W/data"; mkdir -p "$W/html/bin" "$W/data"
    echo page > "$W/html/index.html"
    printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nls -l /proc/self/fd\n' > "$W/html/bin/x.cgi"; chmod 0755 "$W/html/bin/x.cgi"
    fresh_snapshot
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" "$W/data/reputation.bin" "$GEN" 0 3 "$RANGE_START" "$RANGE_END"
    chmod 0444 "$W/data/reputation.bin"     # a mapped plane arms only at exactly 0444 (measured); at 0644 the child refuses it and the row would walk an unarmed module
    { conf_head "$MPM"; need_mod cgi_module mod_cgi.so; cat <<CONF
WhisperEdgeData $W/data
WhisperEdgeRefresh 10
WhisperEdgeTrustedProxy 127.0.0.1
WhisperEdgeTrustedHeader X-Forwarded-For
WhisperEdgeTrustedHops 2
<Directory $W/html/bin>
    Options +ExecCGI
    AddHandler cgi-script .cgi
    Require all granted
</Directory>
CONF
    } > "$conf"
    if grep -q '^#missing' "$conf"; then
        bad "q4: this httpd is missing $(grep '^#missing' "$conf" | tr '\n' ' ')"
        return
    fi
    if ! start_httpd "$conf" "$MPM"; then
        bad "q4: httpd did not start: $(grep -v 'policy: \(server\|location\)' "$W/start-$MPM.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        return
    fi
    pidmaster=$(cat "$W/httpd-$MPM.pid")
    # the module's descriptors under the work directory, named by what they point at (the plane file, the
    # data directory, the counters): the debug build's own descriptor list is not in this tree's core,
    # so the row enumerates by target, which is the same set on a gate-owned work directory
    q4_check() { # q4_check <pid set...>: every $W-targeting descriptor carries O_CLOEXEC, as "n miss"
        local p f tgt fl n=0 miss=0
        for p in "$@"; do
            for f in /proc/$p/fd/*; do
                [ -e "$f" ] || continue
                tgt=$(readlink "$f" 2>/dev/null) || continue
                case "$tgt" in
                    "$W"/logs/*) continue ;;   # httpd's own error and access logs (fd 2 is the error log, which httpd holds inheritable by its own choice), not this module's
                    "$W"/*) ;;
                    "$W") ;;
                    *) continue ;;
                esac
                fl=$(sed -n 's/^flags:[[:space:]]*//p' "/proc/$p/fdinfo/${f##*/}" 2>/dev/null)
                n=$((n + 1))
                if [ -n "$fl" ] && [ $((8#$fl & 8#02000000)) -ne 0 ]; then :; else miss=$((miss + 1)); fi
            done
        done
        echo "$n $miss"
    }
    local res
    res=$(q4_check "$pidmaster" $(pgrep -P "$pidmaster"))
    local n miss
    n=$(printf '%s' "$res" | awk '{print $1}'); miss=$(printf '%s' "$res" | awk '{print $2}')
    [ "$n" -ge 3 ] && [ "$miss" = 0 ] \
        && ok "q4: after start every one of the $n descriptors the master and the workers hold under the work directory carries O_CLOEXEC" \
        || bad "q4: after start $miss of $n descriptors under the work directory lack O_CLOEXEC"
    timeout 20 "$HTTPD" -f "$conf" -k graceful >/dev/null 2>&1
    await "[ \"\$(code_nohdr /)\" != 000 ]" 15 "serving after the graceful" || bad "q4: not serving after the graceful"
    res=$(q4_check "$pidmaster" $(pgrep -P "$pidmaster"))
    n=$(printf '%s' "$res" | awk '{print $1}'); miss=$(printf '%s' "$res" | awk '{print $2}')
    [ "$n" -ge 3 ] && [ "$miss" = 0 ] \
        && ok "q4: and after a reload the same $n descriptors still carry it" \
        || bad "q4: after the reload $miss of $n descriptors lack O_CLOEXEC"
    # a prefork child running a CGI: the CGI inherits no plane, data or counters descriptor (httpd's own
    # inheritable error log is its choice, not this module's, so the logs directory is out of the row's scope)
    local out
    out=$(curl -s --max-time 8 "http://127.0.0.1:$PORT/bin/x.cgi")
    [ -n "$out" ] || bad "q4: the CGI child answered nothing (the script's output was not served)"
    if printf '%s\n' "$out" | grep "$W" | grep -v "$W/logs/" >"$W/q4-cgi-fds" 2>/dev/null; then
        bad "q4: the CGI child holds a work-directory descriptor: $(tr '\n' ' ' <"$W/q4-cgi-fds" | cut -c1-300)"
    else
        ok "q4: a CGI child's own descriptor list holds no plane, data or counters descriptor, so a tenant CGI inherits none of them"
    fi
    rm -f "$W/q4-cgi-fds"
    stop_httpd "$conf" "$MPM" || bad "q4: httpd did not stop"
    fresh_snapshot
}

run_mlock_rows() { # M7: mlock under a 1 MiB LimitMEMLOCK fails loudly and keeps serving; above twice the plane it holds
    local MPM=event conf="$W/httpd-m7.conf" big pid line r n_no n_yes
    echo "  [mlock under a limit]"
    rm -rf "$W/html" "$W/counters"; mkdir -p "$W/html"
    echo page > "$W/html/index.html"
    GEN=$((GEN + 1))
    python3 "$ROOT/core/make-test-snapshot.py" --plane reputation --out "$W/snapshot.bin" --format 1 \
        --v4-index none --v6-index none --synthetic 120000 0 --generation "$GEN" >/dev/null
    chmod 0644 "$W/snapshot.bin"
    big=$(stat -c '%s' "$W/snapshot.bin")
    if [ "$big" -le 1048576 ]; then
        bad "mlock: the fixture is $big bytes, not above the 1 MiB limit, so the arm cannot bite; raise the synthetic range count"
        return
    fi
    { conf_head "$MPM"; conf_data; } > "$conf"
    # the low limit: the parent binds under a 1 MiB RLIMIT_MEMLOCK, so the mlock fails per child
    prlimit --memlock=1048576 -- "$HTTPD" -f "$conf" -k start 2>"$W/start-m7.err"
    await "[ \"\$(code_nohdr /)\" != 000 ]" 15 "httpd up under the 1 MiB limit" \
        || { bad "mlock: httpd did not start under the 1 MiB limit: $(tail -2 "$W/start-m7.err" | tr '\n' ' ' | cut -c1-300)"; return; }
    HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
    await "grep -q 'mlock of [0-9]* bytes failed' '$W/logs/error.log'" 20 "the mlock failure line" \
        && ok "mlock: under a 1 MiB limit the bind logs the failure with the bytes wanted ($(grep -o 'mlock of [0-9]* bytes failed' "$W/logs/error.log" | tail -1)), serving goes on" \
        || bad "mlock: the mlock failure line never appeared under the 1 MiB limit: $(grep -i mlock "$W/logs/error.log" | tail -1 | cut -c1-200)"
    r=$(code_nohdr /)
    # the per-process status files carry the plane line with its locked word (the --status summary does not)
    n_no=$(grep -h 'plane reputation' "$W"/counters/*.status 2>/dev/null | grep -c 'locked no')
    n_yes=$(grep -h 'plane reputation' "$W"/counters/*.status 2>/dev/null | grep -c 'locked yes')
    [ "$r" = 200 ] && [ "$n_no" -ge 1 ] && [ "$n_yes" = 0 ] \
        && ok "mlock: serving continues ($r) and every child's status file says locked no, the pages may be evicted" \
        || bad "mlock: under the limit the request answered $r; the status files say locked no $n_no times and locked yes $n_yes times"
    timeout 20 "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1
    await "[ ! -f \"$W/httpd-$MPM.pid\" ]" 15 "stopped" || bad "mlock: httpd did not stop"
    # above twice the fixture's bytes: the lock holds
    rm -rf "$W/logs" "$W/counters"; mkdir -p "$W/logs"
    local lim=$((big * 2 + 65536))
    prlimit --memlock=$lim -- "$HTTPD" -f "$conf" -k start 2>"$W/start-m7.err"
    await "[ \"\$(code_nohdr /)\" != 000 ]" 15 "httpd up under the high limit" \
        || { bad "mlock: httpd did not start under the $lim-byte limit: $(tail -2 "$W/start-m7.err" | tr '\n' ' ' | cut -c1-300)"; return; }
    HTTPD_PID=$(cat "$W/httpd-$MPM.pid" 2>/dev/null)
    await 'n_no=$(grep -h "plane reputation" "$W"/counters/*.status 2>/dev/null | grep -c "locked no"); n_yes=$(grep -h "plane reputation" "$W"/counters/*.status 2>/dev/null | grep -c "locked yes"); [ "$n_yes" -ge 1 ] && [ "$n_no" = 0 ]' 20 "the locked word" \
        && ok "mlock: under a limit above twice the plane ($lim bytes over $big) every child's status file says locked yes" \
        || bad "mlock: the status files never said locked yes: $(grep -h 'plane reputation' "$W"/counters/*.status 2>/dev/null | grep -o 'locked [a-z]*' | head -1)"
    timeout 20 "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1
    await "[ ! -f \"$W/httpd-$MPM.pid\" ]" 15 "stopped" || bad "mlock: the high-limit httpd did not stop"
    fresh_snapshot
}

# =====================================================================================================
# THE CONFIGURATION TEST: what is refused, with what words
# =====================================================================================================
# ct_case <label> <expect: refused|ok> <grep pattern> <body...>: write a conf with the body under the common head
ct_case() {
    local label=$1 expect=$2 pat=$3 conf="$W/ct.conf" out
    shift 3
    { conf_head event; printf '%s\n' "$@"; } > "$conf"
    out=$("$HTTPD" -t -f "$conf" 2>&1); local rc=$?
    if [ "$expect" = refused ]; then
        if [ "$rc" != 0 ] && grep -q -- "$pat" <<<"$out"; then
            ok "configtest: $label is refused: $(printf '%s\n' "$out" | grep -- "$pat" | head -1 | sed 's/.*whisper edge: //; s/.*AH00526: //' | cut -c1-150)"
        else
            bad "configtest: $label: exit $rc, expected a refusal matching \"$pat\": $(printf '%s\n' "$out" | grep -v 'policy: \(server\|location\|snapshot\|data\|floor\|[0-9] distinct\|trusted\|the floor\|the configuration is read\)' | tail -2 | tr '\n' '|' | cut -c1-300)"
        fi
    else
        if [ "$rc" = 0 ] && ! grep -q 'refused' <<<"$out"; then
            ok "configtest: $label is accepted"
        else
            bad "configtest: $label: exit $rc: $(printf '%s\n' "$out" | grep -i 'refused\|error\|AH0' | head -2 | tr '\n' '|' | cut -c1-300)"
        fi
    fi
}

run_configtest_rows() {
    echo "  [configuration test]"
    local data; data=$(conf_data)

    # a refused rule fails the configuration test, with the directive's own file and line (the pin's hook
    # ran in post_config, which -t never reaches, and printed Syntax OK on the same configuration)
    ct_case "a rule with trailing input (the compiler's line, with the directive's own file and line)" refused \
        'whisper edge: policy refused: .*/ct.conf:[0-9]*: WhisperEdgePolicy (http): rule 1, line 1, column 18: near "garbage": .*trailing input' \
        "$data" 'WhisperEdgePolicy deny if tor_exit garbage'
    ct_case "the same rule with the offending word removed (the control)" ok '' "$data" 'WhisperEdgePolicy deny if tor_exit'
    # the sections the module refuses by name, and the same lines one level up
    ct_case "<Files> (a refused section)" refused 'WhisperEdgeMode is allowed in the main configuration, <VirtualHost>, <Directory>, <DirectoryMatch>, <Location> and <LocationMatch>; it selects a policy by path, and <Files would select it on other request properties' \
        "$data" "<Directory $W/html>" '<Files index.html>' 'WhisperEdgeMode deny' '</Files>' '</Directory>'
    ct_case "<If> (a refused section)" refused 'and <If would select it' "$data" '<If "true">' 'WhisperEdgePolicy deny if tor_exit' '</If>'
    ct_case "<Limit> (a refused section)" refused 'and <Limit would select it' "$data" "<Location /x>" '<Limit GET>' 'WhisperEdgeMode deny' '</Limit>' '</Location>'
    ct_case "<FilesMatch> (a refused section)" refused 'and <FilesMatch would select it' "$data" '<FilesMatch "\.php$">' 'WhisperEdgeThreshold low' '</FilesMatch>'
    ct_case "the same directives one level up (the sections' control)" ok '' "$data" "<Directory $W/html>" 'WhisperEdgeMode deny' '</Directory>' '<Location /x>' 'WhisperEdgePolicy deny if tor_exit' '</Location>' '<DirectoryMatch "^/var">' 'WhisperEdgeThreshold low' '</DirectoryMatch>' '<LocationMatch "^/api">' 'WhisperEdgeMode log' '</LocationMatch>'
    ct_case "<IfModule> around the directives is transparent (a conditional, not a section)" ok '' "$data" '<IfModule whisper_edge_module>' 'WhisperEdgeMode log' '</IfModule>'
    ct_case "<Proxy> (a refused section)" refused 'and <Proxy would select it' \
        "$data" "$(need_mod proxy_module mod_proxy.so)" '<Proxy *>' 'WhisperEdgeMode deny' '</Proxy>'
    ct_case "<ProxyMatch> (a refused section)" refused 'and <ProxyMatch would select it' \
        "$data" "$(need_mod proxy_module mod_proxy.so)" '<ProxyMatch "example\.com">' 'WhisperEdgeThreshold low' '</ProxyMatch>'
    # http-only directives in a virtual host, and a second definition at http level
    ct_case "WhisperEdgeData in a <VirtualHost> (http level only)" refused 'WhisperEdgeData is http level only, so that no virtual host can change the floor' \
        "$data" "<VirtualHost 127.0.0.1:$PORT>" 'ServerName a' "WhisperEdgeData $W" '</VirtualHost>'
    ct_case "WhisperEdgePolicyFloor in a <VirtualHost> (http level only)" refused 'WhisperEdgePolicyFloor is http level only' \
        "$data" "<VirtualHost 127.0.0.1:$PORT>" 'ServerName a' 'WhisperEdgePolicyFloor deny if tor_exit' '</VirtualHost>'
    ct_case "WhisperEdgeTrustedProxy in a <Location> (http level only; httpd itself refuses an RSRC_CONF directive in a section)" refused 'WhisperEdgeTrustedProxy not allowed in <Location> context\|WhisperEdgeTrustedProxy is http level only' \
        "$data" '<Location /x>' 'WhisperEdgeTrustedProxy 10.0.0.0/8' '</Location>'
    ct_case "a second WhisperEdgeMode at http level (http level only)" refused 'WhisperEdgeMode is defined twice at http level: .*/ct.conf:[0-9]* and .*/ct.conf:[0-9]*' \
        "$data" 'WhisperEdgeMode log' 'WhisperEdgeMode deny'
    ct_case "a second WhisperEdgeSnapshot at http level (http level only)" refused 'WhisperEdgeSnapshot is defined twice at http level' "$data" "WhisperEdgeSnapshot $W/snapshot.bin"
    ct_case "one definition at http level and one in a <Location> (the http-level control)" ok '' "$data" 'WhisperEdgeMode log' '<Location /x>' 'WhisperEdgeMode deny' '</Location>'
    ct_case "WhisperEdgeSnapshot beside WhisperEdgeData (the snapshot is the reputation plane's file)" ok '' "$data" "WhisperEdgeData $W"
    ct_case "WhisperEdgeSnapshot and WhisperEdgeData reputation <file> (both name the reputation plane's file)" refused \
        'policy refused: whisper_edge_snapshot .* and whisper_edge_data reputation .* both name the reputation plane.s file; keep one.*(WhisperEdgeSnapshot at .*/ct.conf:[0-9]*, WhisperEdgeData reputation at .*/ct.conf:[0-9]*)' \
        "$data" "WhisperEdgeData reputation $W/snapshot.bin"
    ct_case "a second WhisperEdgeData <directory> at http level" refused 'WhisperEdgeData <directory> is defined twice at http level: .*/ct.conf:[0-9]* and .*/ct.conf:[0-9]*' \
        "WhisperEdgeData $W" "WhisperEdgeData $W/html"
    # the trusted header's grammar (section 2.1, 4.1)
    ct_case "WhisperEdgeTrustedHeader Forwarded (4.1)" refused 'Forwarded uses the RFC 7239 syntax, which this module does not read; name X-Forwarded-For, or a single-address header such as X-Real-IP' \
        'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader Forwarded'
    ct_case "WhisperEdgeTrustedHeader FORWARDED, another case" refused 'Forwarded uses the RFC 7239 syntax' 'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader FORWARDED'
    ct_case "WhisperEdgeTrustedHeader \"X Forwarded\" (a space)" refused 'a header name is a token (RFC 9110 section 5.1); "X Forwarded" contains a space' 'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader "X Forwarded"'
    ct_case "WhisperEdgeTrustedHeader X_Real_IP is accepted on Apache (it keeps the line)" ok '' 'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader X_Real_IP'
    ct_case "WhisperEdgeTrustedProxy with a word that is not an address" refused 'WhisperEdgeTrustedProxy: "balancer" is not an address or a prefix' 'WhisperEdgeTrustedProxy balancer'
    ct_case "WhisperEdgeTrustedHops 17" refused 'WhisperEdgeTrustedHops takes a number of hops between 1 and 16' 'WhisperEdgeTrustedHops 17'
    # the deny statuses, each refused by its class, every message ending `use 403`
    local st why
    for st in 401 405 407 426 416 408 421 417 411 431 412 414 511 494 495 499 402 444 460 500 502 503 504 505; do
        case $st in
            401|405|407|426|416) why='requires an\? .* header, which this module does not send; use 403' ;;
            408|421|417|411|431) why='send the request again\|clients retry' ;;
            412|414) why='describes the request, not a decision; use 403' ;;
            511) why='captive portal; use 403' ;;
            494|495|499) why='never on the wire as written; use 403' ;;
            444) why="444 is nginx's close without a response, which httpd cannot send; use 403" ;;
            402) why='402 is reserved (RFC 9110 section 15.5.3); use 403' ;;
            460) why='does not register, which httpd sends as `NNN Status NNN` with its 500 body; use 403' ;;
            *) why='a 5xx says the server failed (RFC 9110 section 15.6); balancers and health checks in front .* can eject this origin under denied traffic; use 403' ;;
        esac
        ct_case "WhisperEdgeDenyStatus $st (a refused status)" refused "WhisperEdgeDenyStatus $st: .*$why" "WhisperEdgeDenyStatus $st"
    done
    for st in 400 403 404 406 409 410 413 415 422 428 429 451; do
        ct_case "WhisperEdgeDenyStatus $st (an accepted status)" ok '' "WhisperEdgeDenyStatus $st"
    done
    # the argument forms compile to one digest; a two-word set name changes it
    local out d1 d2 d3 d4
    { conf_head event; printf '%s\n' "$data" '<Location /a>' 'WhisperEdgePolicy deny if listed >= low' '</Location>' \
        '<Location /b>' 'WhisperEdgePolicy "deny if listed >= low"' '</Location>' \
        '<Location /c>' 'whisper_edge_policy    deny   if   listed>=low' '</Location>' \
        '<Location /d>' "WhisperEdgePolicy 'deny if listed >= low'" '</Location>' \
        '<Location /e>' 'WhisperEdgeThreshold low' '</Location>'; } > "$W/ct.conf"
    out=$("$HTTPD" -t -f "$W/ct.conf" 2>&1)
    d1=$(ctx_digest "$out" 'location "/a"'); d2=$(ctx_digest "$out" 'location "/b"'); d3=$(ctx_digest "$out" 'location "/c"'); d4=$(ctx_digest "$out" 'location "/d"')
    [ -n "$d1" ] && [ "$d1" = "$d2" ] && [ "$d1" = "$d3" ] && [ "$d1" = "$d4" ] && [ "$d1" = "$(ctx_digest "$out" 'location "/e"')" ] \
        && ok "argument forms: unquoted, double-quoted, single-quoted, extra spaces, the snake_case alias and the threshold sugar compile to one digest ($d1)" \
        || bad "argument forms: the forms differ: $d1 $d2 $d3 $d4 $(ctx_digest "$out" 'location "/e"')"
    { conf_head event; printf '%s\n' "$data" '<Location /a>' 'WhisperEdgePolicy deny if listed >= low' '</Location>' '<Location /b>' 'WhisperEdgePolicy deny if listed >= medium' '</Location>'; } > "$W/ct.conf"
    out=$("$HTTPD" -t -f "$W/ct.conf" 2>&1)
    [ -n "$(ctx_digest "$out" 'location "/a"')" ] && [ "$(ctx_digest "$out" 'location "/a"')" != "$(ctx_digest "$out" 'location "/b"')" ] \
        && ok "argument forms' control: a different level is a different digest" \
        || bad "argument forms' control: two different rules compiled to one digest"
    # the data line: a directory holding only snapshot.bin binds no reputation plane, and the line says what to add
    mkdir -p "$W/d9"; python3 "$ROOT/core/make-test-snapshot.py" "$W/d9/snapshot.bin" 1 0 >/dev/null; chmod 0644 "$W/d9/snapshot.bin"
    ct_case "a data directory holding only snapshot.bin (the snapshot synonym's fix)" ok '' "WhisperEdgeData $W/d9"
    { conf_head event; printf '%s\n' "WhisperEdgeData $W/d9"; } > "$W/ct.conf"
    out=$("$HTTPD" -t -f "$W/ct.conf" 2>&1)
    grep -q 'data "'"$W/d9"'": reputation absent;.*(snapshot.bin is here, generation 1, valid until .*: add "WhisperEdgeSnapshot '"$W"'/d9/snapshot.bin" to read it' <<<"$out" \
        && ok "data line: the data line names reputation absent and the snapshot.bin beside it with the directive to add" \
        || bad "data line: the data line: $(printf '%s\n' "$out" | grep 'policy: data' | cut -c60-300)"
    rm -rf "$W/d9"
    ct_case "WhisperEdgeData <plane> <file> beside a directory (the per-plane form, ABI 5)" ok '' "WhisperEdgeData $W" "WhisperEdgeData reputation $W/snapshot.bin"
    ct_case "WhisperEdgeData tor tor.bin (a relative path)" refused 'WhisperEdgeData tor needs an absolute path to the plane.s file' "WhisperEdgeData $W" 'WhisperEdgeData tor tor.bin'
    ct_case "WhisperEdgeData bogus <file> (not a plane)" refused 'WhisperEdgeData bogus /x/y.bin: "bogus" is not a plane; the planes are reputation, tor, ' "WhisperEdgeData $W" 'WhisperEdgeData bogus /x/y.bin'
    ct_case "a second WhisperEdgeData tor <file> at http level" refused 'WhisperEdgeData tor is defined twice at http level: .*/ct.conf:[0-9]* and .*/ct.conf:[0-9]*' \
        "WhisperEdgeData $W" "WhisperEdgeData tor $W/a.bin" "WhisperEdgeData tor $W/b.bin"
    ct_case "WhisperEdgeExport with a name that is not an attribute" refused 'WhisperEdgeExport: "bogus" is not an attribute; the attributes are inferred, listed, tor_exit' 'WhisperEdgeExport asn bogus'
    ct_case "WhisperEdgeExport asn country, and all" ok '' 'WhisperEdgeExport asn country' '<Location /x>' 'whisper_edge_export all' '</Location>'
    # T8: the quick-handler warning, exactly when mod_cache is loaded and the module has something to judge
    { conf_head event; printf '%s\n' "$data"; need_mod cache_module mod_cache.so; echo 'WhisperEdgePolicy deny if tor_exit'; } > "$W/ct.conf"
    out=$("$HTTPD" -t -f "$W/ct.conf" 2>&1)
    grep -q "mod_cache's quick handler serves cached responses before this module judges them; set CacheQuickHandler off" <<<"$out" \
        && ok "configtest: with mod_cache loaded and a rule, the test warns that the quick handler serves cached responses and names CacheQuickHandler off" \
        || bad "configtest: the mod_cache warning is missing with the module loaded: $(printf '%s\n' "$out" | grep -i cache | head -1 | cut -c1-200)"
    { conf_head event; printf '%s\n' "$data"; echo 'WhisperEdgePolicy deny if tor_exit'; } > "$W/ct.conf"
    out=$("$HTTPD" -t -f "$W/ct.conf" 2>&1)
    ! grep -q 'quick handler' <<<"$out" \
        && ok "configtest: without mod_cache loaded no warning is printed (the control)" \
        || bad "configtest: a quick-handler warning appeared without mod_cache loaded"
}

# =====================================================================================================
# the policy corpus's refusals and acceptances, rendered as httpd.conf
# =====================================================================================================
run_corpus_rows() {
    local corpus="$ROOT/core/testdata/policy" f base n_na=0
    echo "  [the policy corpus as httpd.conf]"
    [ -d "$corpus/refuse" ] || { bad "corpus: no corpus at $corpus"; return; }
    for f in "$corpus"/refuse/*.policy; do
        base=$(basename "$f" .policy)
        # render: the record file -> an httpd.conf, and the line and ordinal context of each directive
        if ! python3 - "$f" "$W/corpus.conf" "$PORT" "$MODULE" "$W" <<'PY' > "$W/corpus.map" 2>"$W/corpus.err"; then
import sys
src, out, port, module, w = sys.argv[1:6]
data = open(src, 'rb').read()
recs = [r for r in data.split(b'\x1e\n') if r]
names = {b'policy': 'WhisperEdgePolicy', b'set': 'WhisperEdgeSet', b'floor': 'WhisperEdgePolicyFloor',
         b'threshold': 'WhisperEdgeThreshold', b'mode': 'WhisperEdgeMode', b'allow_inferred': 'WhisperEdgeAllowInferred'}
vhosts = []            # corpus server names in order of first appearance -> s1, s2, ...
locs = {}              # (server, location) -> lN within the vhost
by_ctx = {}            # corpus context -> list of (kind, argbytes)
order = []
for r in recs:
    kind, ctx, arg = r.split(b' ', 2)
    ctx = ctx.decode()
    if ctx not in by_ctx:
        by_ctx[ctx] = []
        order.append(ctx)
    by_ctx[ctx].append((kind, arg))
    if ctx.startswith('http/server:'):
        srv = ctx.split('/')[1][len('server:'):]
        if srv not in vhosts:
            vhosts.append(srv)
        if '/location:' in ctx:
            key = (srv, ctx.split('/location:')[1])
            if key not in locs:
                locs[key] = sum(1 for k in locs if k[0] == srv) + 1
lines = []
head = open(w + '/corpus.head').read().rstrip('\n').split('\n')
lines.extend(head)
def emit(kind, arg, ctx_ord, counters, corpus_ctx):
    name = names[kind]
    counters[(kind, ctx_ord)] = counters.get((kind, ctx_ord), 0) + 1
    rule = counters[(kind, ctx_ord)]
    bad = any(b < 0x20 and b not in (0x09,) for b in arg) or b'\\\n' in arg
    text = arg.decode('latin-1')
    if kind in (b'threshold', b'mode', b'allow_inferred'):
        line = '%s "%s"' % (name, text)
    else:
        line = '%s %s' % (name, text if (text == text.strip() and not text.startswith('"') and not text.startswith("'")) else '"' + text + '"')
    lines.append(line)
    print('%d\t%s\t%s\t%d\t%s\t%s\t%s' % (len(lines), kind.decode(), ctx_ord, rule, 'na' if bad else 'ok', name, corpus_ctx))
counters = {}
for kind, arg in by_ctx.get('http', []):
    emit(kind, arg, 'http', counters, 'http')
for i, srv in enumerate(vhosts, 1):
    lines.append('<VirtualHost 127.0.0.1:%s>' % port)
    lines.append('ServerName %s' % srv)
    for kind, arg in by_ctx.get('http/server:%s' % srv, []):
        emit(kind, arg, 'http/s%d' % i, counters, 'http/server:%s' % srv)
    for (s, loc), n in sorted(locs.items(), key=lambda kv: kv[1]):
        if s != srv:
            continue
        lines.append('<Location /%s>' % loc)
        for kind, arg in by_ctx.get('http/server:%s/location:%s' % (s, loc), []):
            emit(kind, arg, 'http/s%d/l%d' % (i, n), counters, 'http/server:%s/location:%s' % (s, loc))
        lines.append('</Location>')
    lines.append('</VirtualHost>')
open(out, 'wb').write(('\n'.join(lines) + '\n').encode('latin-1'))
PY
            bad "corpus $base: the renderer failed: $(head -2 "$W/corpus.err" | tr '\n' ' ')"; continue
        fi
        local exp_layer exp_kind exp_ctx exp_rule exp_line exp_col exp_token exp_msg
        exp_layer=$(awk -F'\t' '$1=="layer"{print $2}' "$corpus/refuse/$base.expect")
        exp_kind=$(awk -F'\t' '$1=="kind"{print $2}' "$corpus/refuse/$base.expect")
        exp_ctx=$(awk -F'\t' '$1=="context"{print $2}' "$corpus/refuse/$base.expect")
        exp_rule=$(awk -F'\t' '$1=="rule"{print $2}' "$corpus/refuse/$base.expect")
        exp_line=$(awk -F'\t' '$1=="line"{print $2}' "$corpus/refuse/$base.expect")
        exp_col=$(awk -F'\t' '$1=="col"{print $2}' "$corpus/refuse/$base.expect")
        exp_token=$(awk -F'\t' '$1=="token"{print $2}' "$corpus/refuse/$base.expect")
        exp_msg=$(awk -F'\t' '$1=="message"{print $2}' "$corpus/refuse/$base.expect")
        # the ordinal of the corpus context: http, http/server:a -> http/s1, .../location:api -> http/s1/l1
        local ord want_line want_na want_name
        ord=$(awk -F'\t' -v k="$exp_kind" -v r="$exp_rule" -v c="$exp_ctx" '$2==k && $4==r && $7==c {print $3; exit}' "$W/corpus.map")
        want_line=$(awk -F'\t' -v k="$exp_kind" -v r="$exp_rule" -v c="$exp_ctx" '$2==k && $4==r && $7==c {print $1; exit}' "$W/corpus.map")
        want_na=$(awk -F'\t' -v k="$exp_kind" -v r="$exp_rule" -v c="$exp_ctx" '$2==k && $4==r && $7==c {print $5; exit}' "$W/corpus.map")
        want_name=$(awk -F'\t' -v k="$exp_kind" -v r="$exp_rule" -v c="$exp_ctx" '$2==k && $4==r && $7==c {print $6; exit}' "$W/corpus.map")
        local out rc
        # httpd's error logger writes a backslash as two; the module's token is compared as the module wrote it
        out=$("$HTTPD" -t -f "$W/corpus.conf" 2>&1); rc=$?
        out=$(printf '%s\n' "$out" | sed 's/\\\\/\\/g')
        local want="whisper edge: policy refused: $W/corpus.conf:$want_line: $want_name ($ord): rule $exp_rule, line $exp_line, column $exp_col: near \"$exp_token\": "
        if [ "$rc" != 0 ] && grep -qF -- "$want" <<<"$out" && grep -qF -- "$exp_msg" <<<"$(printf '%s\n' "$out" | grep -F -- "$want")"; then
            ok "corpus $base ($exp_layer, $exp_ctx as $ord): refused at $want_name line $want_line, rule $exp_rule, line $exp_line, column $exp_col, token \"$exp_token\", message \"$exp_msg\""
        elif [ "$want_na" = na ]; then
            n_na=$((n_na + 1))
            na "corpus $base: httpd's configuration reader does not carry this record's bytes (a control character inside a line); the compiler's own corpus replay holds it"
        else
            bad "corpus $base: exit $rc; wanted \"$want...$exp_msg\"; got: $(printf '%s\n' "$out" | grep -i 'refused\|AH00526\|Syntax' | head -2 | tr '\n' '|' | cut -c1-400)"
        fi
    done
    for f in "$corpus"/accept/*.policy; do
        base=$(basename "$f" .policy)
        python3 - "$f" "$W/corpus.conf" "$PORT" "$MODULE" "$W" <<'PY' > "$W/corpus.map" 2>"$W/corpus.err" || { bad "corpus-accept $base: the renderer failed"; continue; }
import sys
src, out, port, module, w = sys.argv[1:6]
data = open(src, 'rb').read()
recs = [r for r in data.split(b'\x1e\n') if r]
names = {b'policy': 'WhisperEdgePolicy', b'set': 'WhisperEdgeSet', b'floor': 'WhisperEdgePolicyFloor',
         b'threshold': 'WhisperEdgeThreshold', b'mode': 'WhisperEdgeMode', b'allow_inferred': 'WhisperEdgeAllowInferred'}
vhosts, locs, by_ctx = [], {}, {}
for r in recs:
    kind, ctx, arg = r.split(b' ', 2)
    ctx = ctx.decode()
    by_ctx.setdefault(ctx, []).append((kind, arg))
    if ctx.startswith('http/server:'):
        srv = ctx.split('/')[1][len('server:'):]
        if srv not in vhosts:
            vhosts.append(srv)
        if '/location:' in ctx:
            key = (srv, ctx.split('/location:')[1])
            if key not in locs:
                locs[key] = sum(1 for k in locs if k[0] == srv) + 1
lines = open(w + '/corpus.head').read().rstrip('\n').split('\n')
def emit(kind, arg):
    text = arg.decode('latin-1')
    if kind in (b'threshold', b'mode', b'allow_inferred'):
        lines.append('%s "%s"' % (names[kind], text))
    else:
        lines.append('%s %s' % (names[kind], text if text == text.strip() else '"' + text + '"'))
for kind, arg in by_ctx.get('http', []):
    emit(kind, arg)
for srv in vhosts:
    lines.append('<VirtualHost 127.0.0.1:%s>' % port)
    lines.append('ServerName %s' % srv)
    for kind, arg in by_ctx.get('http/server:%s' % srv, []):
        emit(kind, arg)
    for (s, loc), n in sorted(locs.items(), key=lambda kv: kv[1]):
        if s == srv:
            lines.append('<Location /%s>' % loc)
            for kind, arg in by_ctx.get('http/server:%s/location:%s' % (s, loc), []):
                emit(kind, arg)
            lines.append('</Location>')
    lines.append('</VirtualHost>')
open(out, 'wb').write(('\n'.join(lines) + '\n').encode('latin-1'))
PY
        local out rc
        out=$("$HTTPD" -t -f "$W/corpus.conf" 2>&1); rc=$?
        if [ "$rc" = 0 ] && ! grep -q 'refused' <<<"$out"; then
            ok "corpus-accept $base: accepted (Syntax OK)"
        else
            bad "corpus-accept $base: exit $rc: $(printf '%s\n' "$out" | grep -i 'refused\|AH00526' | head -1 | cut -c1-300)"
        fi
    done
    [ "$n_na" = 0 ] || echo "  note  corpus: $n_na record(s) not carried by httpd's reader, listed above as n/a, neither counted nor failed"
}

# build_variant <name> [extra apxs args...] -> $CTL/<name>.so from a copy of the tree, so the shipped object is never touched
CTL=""
ctl_tree() {
    CTL="$W/ctl"
    # the sources are copied EVERY time, not only when the directory is absent: the work directory persists
    # between runs, so a copy made once would quietly keep building yesterday's module against today's
    # assertions, and a control build compiled from the pre-seam source is a control that passes vacuously
    if [ ! -d "$CTL/apache" ]; then
        rm -rf "$CTL"
        mkdir -p "$CTL/core" "$CTL/apache"
    fi
    cp "$ROOT"/core/*.c "$ROOT"/core/*.h "$CTL/core/"
    cp "$ROOT/apache/mod_whisper_edge.c" "$CTL/apache/"
    # a control that plants a line into the module source hands the sed program here, after the copy: a
    # plant made before the copy was overwritten by it and the control it fed went blind (the planted
    # key-string object came out byte-identical to the keyless one, measured at a full walk)
    if [ -n "${WE_CTL_PATCH:-}" ]; then
        sed -i "$WE_CTL_PATCH" "$CTL/apache/mod_whisper_edge.c"
    fi
}
build_variant() {
    local name=$1; shift
    [ -n "$APXS" ] || return 1
    ctl_tree
    ( cd "$CTL/apache" && rm -rf .libs ./*.lo ./*.slo ./*.la ../core/.libs ../core/*.lo ../core/*.slo \
        && SOURCE_DATE_EPOCH=1700000000 nice -n 10 "$APXS" -c -I../core -Wc,-ffunction-sections -Wc,-Wall -Wc,-Wextra -Wc,-Werror -Wc,-std=gnu11 "$@" \
           mod_whisper_edge.c ../core/whisper_edge.c ../core/we_sha256.c ../core/we_counters.c ../core/we_policy.c ../core/we_module.c >"$CTL/$name.log" 2>&1 \
        && cp .libs/mod_whisper_edge.so "$CTL/$name.so" )
}

# =====================================================================================================
# StrictModes: the files that define http-level directives
# =====================================================================================================
run_strictmodes_rows() {
    local S="$W/strict" out rc d
    echo "  [StrictModes on the files defining http-level directives]"
    rm -rf "$S"; mkdir -p "$S/conf.d" "$S/tenant/edge"
    echo 'WhisperEdgeMode log' > "$S/conf.d/a.conf"
    echo 'WhisperEdgeAllowInferred on' > "$S/tenant/edge/b.conf"
    chmod o+w "$S/tenant"                         # a tenant-writable tree
    ln -s "$S/tenant/edge" "$S/link"              # the operator's symlinked include directory, resolving into it
    printf '<Macro WeMode>\nWhisperEdgeMode log\n</Macro>\n' > "$S/macros.conf"
    sm_case() { # sm_case <label> <expect: refused|ok> <grep pattern> <module> <conf lines...>
        local label=$1 expect=$2 pat=$3 module=$4 conf="$S/t.conf"
        shift 4
        { conf_head event | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $module#"; printf 'LoadModule macro_module %s/mod_macro.so\n' "$MODPATH"; printf '%s\n' "$@"; } > "$conf"
        out=$("$HTTPD" -t -f "$conf" 2>&1); rc=$?
        out=$(printf '%s\n' "$out" | sed 's/\\\(["\\]\)/\1/g')   # httpd's logger escapes a quote and a backslash; the module's line is compared as written
        if [ "$expect" = refused ]; then
            if [ "$rc" != 0 ] && grep -q -- "$pat" <<<"$out"; then
                ok "StrictModes: $label is refused: $(printf '%s\n' "$out" | grep -- "$pat" | head -1 | sed 's/.*StrictModes: //' | cut -c1-170)"
            else
                bad "StrictModes: $label: exit $rc, expected a refusal matching \"$pat\": $(printf '%s\n' "$out" | grep -i 'refused\|AH0' | head -1 | cut -c1-300)"
            fi
        else
            if [ "$rc" = 0 ] && ! grep -q 'refused' <<<"$out"; then
                ok "StrictModes: $label is accepted"
            else
                bad "StrictModes: $label: exit $rc: $(printf '%s\n' "$out" | grep -i 'refused\|AH0' | head -1 | cut -c1-300)"
            fi
        fi
    }
    sm_case "an http-level directive in an included conf.d file on a clean chain" ok '' "$MODULE" "Include $S/conf.d/*.conf"
    chmod g+w "$S/conf.d/a.conf"
    sm_case "the same file group-writable" refused "StrictModes: $S/conf.d/a.conf is owned by uid $(id -u), mode 0664; a file that defines an http-level directive must be owned by root or by uid $(id -u) (the configuration reader) and writable by neither group nor world: chown it to root and chmod go-w it" "$MODULE" "Include $S/conf.d/*.conf"
    chmod g-w "$S/conf.d/a.conf"
    sm_case "chmod g-w on the file (the control)" ok '' "$MODULE" "Include $S/conf.d/*.conf"
    chmod g+w "$S/conf.d"
    sm_case "a group-writable ancestor directory" refused "StrictModes: $S/conf.d, above the file, is owned by uid $(id -u), mode 0775; every directory above a file that defines an http-level directive must be owned by root or by uid $(id -u) (the configuration reader) and writable by neither group nor world (a root-owned sticky directory is allowed): chmod go-w that directory" "$MODULE" "Include $S/conf.d/*.conf"
    chmod g-w "$S/conf.d"
    sm_case "chmod g-w on the ancestor (the control)" ok '' "$MODULE" "Include $S/conf.d/*.conf"
    sm_case "an include through a symbolic link resolving into a tenant-writable tree" refused "StrictModes: $S/tenant, above the file, is owned by uid $(id -u), mode 0757" "$MODULE" "Include $S/link/b.conf"
    d=$(mktemp -d -p /tmp we-gate-strict.XXXXXX)
    echo 'WhisperEdgeMode log' > "$d/c.conf"; chmod 0644 "$d/c.conf"
    if [ "$(stat -c '%u' /tmp)" = 0 ] && [ $(( 8#$(stat -c '%a' /tmp) & 8#1000 )) -ne 0 ]; then
        sm_case "a configuration file under a root-owned sticky ancestor (/tmp, as sshd allows above a key)" ok '' "$MODULE" "Include $d/c.conf"
    else
        na "StrictModes: /tmp on this host is not a root-owned sticky directory, so the sticky arm has no fixture"
    fi
    rm -rf "$d"
    chmod g+w "$S/macros.conf"
    sm_case "a mod_macro-expanded http-level directive whose defining file is group-writable" refused "WhisperEdgeMode at macro 'wemode' (defined on line 1 of \"$S/macros.conf\") used on line [0-9]* of \"$S/t.conf\":1: StrictModes: $S/macros.conf is owned by uid $(id -u), mode 0664" "$MODULE" "Include $S/macros.conf" 'Use WeMode'
    chmod g-w "$S/macros.conf"
    sm_case "the same macro with its file fixed (the control)" ok '' "$MODULE" "Include $S/macros.conf" 'Use WeMode'
    # the control: a build that walks the configured path lexically never sees the link's target
    if build_variant lexical -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_LEXICAL; then
        sm_case "the symlinked include under the lexical-walk control build (WE_MOD_TEST_LEXICAL) is accepted, so the resolved chain is what refuses it" ok '' "$CTL/lexical.so" "Include $S/link/b.conf"
    else
        bad "StrictModes: the lexical-walk control build failed: $(tail -2 "$CTL/lexical.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    rm -rf "$S"
}

# =====================================================================================================
# H2: the decide wrapper out of the built .so, held to the hot-path gate's own checks; K1: keyless = keyed
# =====================================================================================================
bind_plane() { # bind_plane <path> <generation>: a format-1 reputation plane, renamed in at 0444
    python3 "$ROOT/core/make-test-snapshot.py" --plane reputation --out "$1.new" --format 1 --v4-index none \
        --v6-index none --synthetic 4 0 --generation "$2" --valid-until 0 >/dev/null
    chmod 0444 "$1.new"; mv "$1.new" "$1"
}
bind_arm() { # bind_arm <object> <label> <conf lines...>: start, read the reputation plane's generation and path line
    local so=$1 label=$2 conf="$W/httpd-bind.conf"
    shift 2
    BIND_GEN=""; BIND_PATH=""; BIND_START=ok
    rm -rf "$W/counters" "$W/html"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
    { conf_head event | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $so#"
      printf '%s\n' "$@" "WhisperEdgeRefresh 10" "WhisperEdgeSummary $W/counters" "WhisperEdgePolicy \"deny if listed >= low\""
    } > "$conf"
    if ! start_httpd "$conf" event; then
        BIND_START=$(grep -v 'whisper edge: policy:' "$W/start-event.err" | grep -i 'refused\|error' | tail -1 | cut -c1-400)
        [ -n "$BIND_START" ] || BIND_START=$(grep 'policy refused' "$W/logs/error.log" 2>/dev/null | tail -1 | cut -c1-400)
        [ -n "$BIND_START" ] || BIND_START="did not start"
        return 1
    fi
    await 'grep -q "^ *plane reputation " <<<"$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null)"' 25 "the reputation plane's status" || true
    BIND_GEN=$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null | sed -n 's/^ *plane reputation armed generation \([0-9]*\) .*/\1/p' | sed -n 1p)
    await 'ls "$W"/counters/conf-*.status >/dev/null 2>&1' 25 "the configuration file" || true
    BIND_PATH=$(sed -n 's/^plane reputation path "\(.*\)"$/\1/p' "$W"/counters/conf-*.status 2>/dev/null | sed -n 1p)
    stop_httpd "$conf" event || bad "binding($label): httpd did not stop"
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    return 0
}
run_binding_rows() { # ABI 5's binding: a plane's own file over the directory, and the snapshot beside a directory
    local D="$W/bd" P="$W/bp" S="$W/bs" U="$W/bu" v out
    echo "  [the per-plane binding: a plane's own file, and the snapshot beside a directory]"
    [ -n "$APXS" ] || { bad "binding: no apxs to build the control modules"; return; }
    build_variant pfignored -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PLANE_FILE_IGNORED \
        || { bad "binding: the plane-file-ignored build failed: $(tail -2 "$CTL/pfignored.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant snapdropped -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_SNAPSHOT_DROPPED \
        || { bad "binding: the snapshot-dropped build failed: $(tail -2 "$CTL/snapdropped.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    rm -rf "$D" "$P" "$S" "$U"; mkdir -p "$D" "$P" "$S" "$U"; chmod 0755 "$D" "$P" "$S"
    bind_plane "$D/reputation.bin" 100        # the directory's reputation plane
    bind_plane "$P/rep-200.bin" 200           # a plane's own file, any name
    bind_plane "$S/snap-300.bin" 300          # the snapshot beside the directory
    # ---- a plane's own file overrides the directory for its plane, and the path line names the file ----
    for v in "$MODULE:release" "$CTL/pfignored.so:pfignored"; do
        if bind_arm "${v%%:*}" "${v##*:}" "WhisperEdgeData $D" "WhisperEdgeData reputation $P/rep-200.bin"; then
            case "${v##*:}" in
            release)
                [ "$BIND_GEN" = 200 ] && [ "$BIND_PATH" = "$P/rep-200.bin" ] \
                    && ok "binding: WhisperEdgeData reputation <file> beside WhisperEdgeData <directory> serves the file's generation 200 over the directory's 100, and the configuration file's path line names the file (from the core's we_mod_plane_path)" \
                    || bad "binding: a plane's own file beside a directory: reputation armed generation ${BIND_GEN:-none}, path line ${BIND_PATH:-none}, wanted 200 and $P/rep-200.bin" ;;
            *)
                [ "$BIND_GEN" != 200 ] \
                    && ok "binding's control: the build reading the per-plane line as nothing (WE_MOD_TEST_PLANE_FILE_IGNORED) serves generation ${BIND_GEN:-none} with path line ${BIND_PATH:-none}, so the override row can fail" \
                    || bad "binding's control: WE_MOD_TEST_PLANE_FILE_IGNORED still served the plane's own file (generation 200), so the override row proves nothing"
                ctl_exit_clean "binding's plane-file-ignored control" ;;
            esac
        else
            bad "binding(${v##*:}): the per-plane configuration did not start: $BIND_START"
        fi
    done
    # ---- the snapshot beside a directory is the reputation plane's file, mapped, never dropped and never legacy ----
    for v in "$MODULE:release" "$CTL/snapdropped.so:snapdropped"; do
        if bind_arm "${v%%:*}" "${v##*:}" "WhisperEdgeData $D" "WhisperEdgeSnapshot $S/snap-300.bin"; then
            case "${v##*:}" in
            release)
                out=$({ conf_head event; printf '%s\n' "WhisperEdgeData $D" "WhisperEdgeSnapshot $S/snap-300.bin"; } > "$W/ct.conf"; "$HTTPD" -t -f "$W/ct.conf" 2>&1 | grep 'whisper edge: policy: data ')
                [ "$BIND_GEN" = 300 ] && [ "$BIND_PATH" = "$S/snap-300.bin" ] && grep -qF "reputation file \"$S/snap-300.bin\" (the snapshot) reputation generation 300" <<<"$out" && ! grep -q ', legacy' <<<"$out" \
                    && ok "binding: WhisperEdgeSnapshot beside WhisperEdgeData binds the snapshot as the reputation plane's file: generation 300 armed over the directory's 100, the path line names the snapshot, and the configuration test's data line names it as the snapshot with no legacy mark" \
                    || bad "binding: the snapshot beside a directory: reputation armed generation ${BIND_GEN:-none}, path line ${BIND_PATH:-none}, data line: $(cut -c1-240 <<<"$out")" ;;
            *)
                [ "$BIND_GEN" != 300 ] \
                    && ok "binding's control: the build with ABI 4's rule (WE_MOD_TEST_SNAPSHOT_DROPPED) drops the snapshot and serves the directory's generation ${BIND_GEN:-none}, so the snapshot row can fail" \
                    || bad "binding's control: WE_MOD_TEST_SNAPSHOT_DROPPED still served the snapshot (generation 300), so the snapshot row proves nothing"
                ctl_exit_clean "binding's snapshot-dropped control" ;;
            esac
        else
            bad "binding(${v##*:}): the snapshot-beside-directory configuration did not start: $BIND_START"
        fi
    done
    # ---- still refused: a plane's own file in a directory others can write. The bind refuses the binding whole; the
    # server starts and serves fail open (run_refused_bind_rows walks that), and the refusal names the file and its
    # directory at error level ----
    chmod 0777 "$U"; bind_plane "$U/rep-u.bin" 400
    if bind_arm "$MODULE" untrusted "WhisperEdgeData $D" "WhisperEdgeData reputation $U/rep-u.bin"; then
        grep -q "whisper edge: plane reputation is refused at configuration and reads unknown.*whisper_edge_data $U/rep-u.bin: directory" "$W/logs/error.log" && [ "${BIND_GEN:-none}" != 400 ] \
            && ok "binding: a plane's own file in a directory others can write (0777) is refused at configuration, never armed (reputation generation ${BIND_GEN:-none}), the core's sentence naming the file and its directory" \
            || bad "binding: the 0777 directory: reputation generation ${BIND_GEN:-none}, refusal line: $(grep 'refused' "$W/logs/error.log" | sed -n 1p | cut -c1-200)"
    else
        bad "binding: a binding refused for a 0777 directory stopped httpd from starting: $BIND_START"
    fi
    chmod 0755 "$U"
    rm -rf "$D" "$P" "$S" "$U" "$W/counters"
    fresh_snapshot
}
run_graceful_refusal_rows() { # a graceful into a refused configuration never takes the running parent down
    local conf="$W/httpd-gm.conf" inc="$W/gm-inc.conf" ctl c P rc alive now rok rfail loop
    echo "  [a graceful into a refused configuration, with requests running across it]"
    ctl=$(command -v apache2ctl || command -v apachectl || true)
    gm_good() {
        { conf_head event; conf_data; echo 'WhisperEdgeMode deny'; echo 'WhisperEdgePolicy "deny if listed >= low"'; echo "Include $inc"; } > "$conf"
        : > "$inc"; chmod 0644 "$inc"
    }
    gm_bad() { # gm_bad <case>: the included file turned into one refused configuration
        case "$1" in
        policy)    printf '%s\n' '<Location /x>' 'WhisperEdgePolicy "deny if tor_exit garbage"' '</Location>' > "$inc" ;;
        strict)    echo 'WhisperEdgeExport asn' > "$inc"; chmod 0666 "$inc" ;;
        directive) echo 'WhisperEdgeTrustedHops 17' > "$inc" ;;
        plane)     mkdir -p "$W/gmu"; chmod 0777 "$W/gmu"; echo "WhisperEdgeData tor $W/gmu/tor.bin" > "$inc" ;;
        esac
    }
    gm_across() { # gm_across: requests for 8 s in the background, "<answered> <failed>" into gm-req
        local end ok=0 bad=0
        end=$(( $(date +%s) + 8 ))
        while [ "$(date +%s)" -lt "$end" ]; do
            if [ "$(code_nohdr /)" = 000 ]; then bad=$((bad + 1)); else ok=$((ok + 1)); fi
            sleep 0.05
        done
        echo "$ok $bad" > "$W/gm-req"
    }
    # apachectl graceful runs the configuration test first and signals the parent only when it passes, so each of the
    # module's fatal refusals (a policy compile error, StrictModes on an included file, a directive's own refusal) is
    # met with the old configuration serving on. A raw SIGUSR1 to the parent (or apache2 -k graceful) skips the test,
    # and then httpd itself exits on ANY configuration error, its own unknown directive included (measured):
    # httpd's behaviour, not the module's, and not asserted here. A plane refused at configuration is the one refusal
    # the module serves fail open, so it survives even the raw signal
    for c in policy strict directive plane; do
        rm -rf "$W/counters" "$W/html" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
        gm_good; fresh_snapshot
        if [ "$c" != plane ] && [ -z "$ctl" ]; then
            dark "graceful($c): this host ships no apachectl, so the tested graceful stands unwalked"; continue
        fi
        start_httpd "$conf" event || { bad "graceful($c): the good configuration did not start"; continue; }
        P=$HTTPD_PID
        gm_across & loop=$!
        sleep 1
        gm_bad "$c"
        if [ "$c" = plane ]; then
            kill -USR1 "$P"; rc=$?
        else
            APACHE_ARGUMENTS="-f $conf" "$ctl" graceful >/dev/null 2>&1; rc=$?
        fi
        wait "$loop"
        read -r rok rfail < "$W/gm-req"
        alive=no; kill -0 "$P" 2>/dev/null && alive=yes
        now=$(code_nohdr /)
        if [ "$alive" = yes ] && [ "${rfail:-1}" = 0 ] && [ "${rok:-0}" -ge 20 ] && [ "$now" = 200 ]; then
            if [ "$c" = plane ]; then
                ok "graceful(plane): a raw SIGUSR1 into a configuration with a plane refused at configuration keeps the parent ($P) serving: $rok requests across it answered, none failed"
            else
                ok "graceful($c): apachectl graceful into the refused configuration ($(basename "$ctl") exit $rc, its test failing) keeps the parent ($P) and the old configuration serving: $rok requests across it answered, none failed"
            fi
        else
            bad "graceful($c): the parent alive $alive, $rok answered and $rfail failed across it, / after it $now, the command's exit $rc"
        fi
        gm_good
        "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1; kill -TERM "$P" 2>/dev/null
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
        [ -d "$W/gmu" ] && chmod 0755 "$W/gmu" && rm -rf "$W/gmu"
    done
    rm -f "$inc" "$W/gm-req"
    fresh_snapshot
}
run_refused_bind_rows() { # a plane refused at configuration: Apache never exits on it, the other planes serve, and it says why
    local D="$W/rd" U="$W/ru" conf="$W/httpd-refuse.conf" ans sig rc P alive r403 rtor out errl cline sline
    echo "  [a plane refused at configuration: at configtest, at a fresh start, and at a graceful into it]"
    rm -rf "$D" "$U"; mkdir -p "$D" "$U"; chmod 0755 "$D"
    # reputation from the directory, listing the gate's client range (the listed client is denied while it serves)
    python3 "$ROOT/core/make-test-snapshot.py" "$D/reputation.new" 100 0 3 "$RANGE_START" "$RANGE_END"
    chmod 0444 "$D/reputation.new"; mv "$D/reputation.new" "$D/reputation.bin"
    python3 "$ROOT/core/make-test-snapshot.py" --plane tor --out "$U/tor.new" --format 2 --synthetic 4 0 --generation 5 \
        --valid-until 0 >/dev/null
    chmod 0444 "$U/tor.new"; mv "$U/tor.new" "$U/tor-u.bin"; chmod 0777 "$U"
    # the case D found: reputation arms from the directory, and the tor plane's own file sits in a directory others
    # can write. The core refuses that plane at configuration: it reads unknown, every other plane serves
    refuse_conf() { # refuse_conf <with the refused line: 1|0>
        { conf_head event
          printf '%s\n' "WhisperEdgeData $D" "WhisperEdgeRefresh 10" "WhisperEdgeSummary $W/counters" 'WhisperEdgeMode deny' \
              'WhisperEdgeTrustedProxy 127.0.0.1' 'WhisperEdgeTrustedHeader X-Forwarded-For' 'WhisperEdgeTrustedHops 2' \
              'WhisperEdgePolicy "deny if listed >= low"' '<Location /tor>' 'WhisperEdgePolicy "deny if tor_exit"' '</Location>'
          [ "$1" = 1 ] && echo "WhisperEdgeData tor $U/tor-u.bin"
        } > "$conf"
    }
    refuse_fresh() {
        rm -rf "$W/counters" "$W/html" "$W/logs"; mkdir -p "$W/html/tor" "$W/logs"
        echo page > "$W/html/index.html"; echo page > "$W/html/tor/index.html"
    }
    refuse_answers() { # refuse_answers: how many of 20 requests (the listed client, at / and /tor/) were answered
        local n=0
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            [ "$(code / "$LISTED")" != 000 ] && n=$((n + 1))
            [ "$(code /tor/ "$LISTED")" != 000 ] && n=$((n + 1))
        done
        echo "$n"
    }
    refuse_signals() { cat "$W/logs/error.log" "$W/start-event.err" 2>/dev/null | grep -cE 'exit signal|Segmentation fault|Bus error' || true; }
    refuse_lines() { # the core's words: the error-level sentence, the configuration file's plane line, the status line
        errl=$(grep -c "\[:error\].*whisper edge: plane tor is refused at configuration and reads unknown.*$U/tor-u.bin" "$W/logs/error.log" 2>/dev/null || true)
        await 'ls "$W"/counters/conf-*.status >/dev/null 2>&1' 20 "the configuration file" || true
        cline=$(grep -h "^plane tor path \"$U/tor-u.bin\" refused \"" "$W"/counters/conf-*.status 2>/dev/null | sed -n 1p)
        await 'grep -q "^ *plane tor refused" <<<"$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null)"' 25 "the tor plane's status" || true
        sline=$("$SUMMARY_BIN" --status "$W/counters" 2>/dev/null | grep -m1 '^ *plane tor ' | sed 's/^ *//' | cut -c1-120)
    }
    # ---- the configuration test runs the core's check-only bind and names the refusal in the core's sentence ----
    refuse_fresh; refuse_conf 1
    out=$("$HTTPD" -t -f "$conf" 2>&1); rc=$?
    if [ "$rc" != 0 ] && grep -qF "plane tor is refused at configuration" <<<"$out" && grep -qF "$U/tor-u.bin" <<<"$out" && ! grep -q 'Syntax OK' <<<"$out"; then
        ok "refused bind: the configuration test (we_mod_bind_check) names the refused tor plane, its file and the fix in the core's sentence, and exits $rc, never Syntax OK"
    else
        bad "refused bind: the configuration test exits $rc for a plane the bind refuses: $(grep -E 'Syntax OK|refused' <<<"$out" | sed -n 1p | cut -c1-200)"
    fi
    # ---- a fresh start: the good plane serves, the refused one reads unknown with its reason, no signal ----
    refuse_fresh; refuse_conf 1
    "$HTTPD" -f "$conf" -k start 2>"$W/start-event.err"; rc=$?
    await "[ \"\$(code_nohdr /)\" != 000 ]" 10 "httpd up" || true
    HTTPD_PID=$(cat "$W/httpd-event.pid" 2>/dev/null)
    ans=$(refuse_answers); sig=$(refuse_signals); r403=$(code / "$LISTED"); rtor=$(code /tor/ "$LISTED"); refuse_lines
    if [ "$ans" = 20 ] && [ "$sig" = 0 ] && [ "$r403" = 403 ] && [ "$rtor" != 000 ] && [ "${errl:-0}" -ge 1 ] && [ -n "$cline" ] && [ -n "$sline" ]; then
        ok "refused bind: a fresh start with the tor plane refused at configuration serves: 20 of 20 answered, reputation still denying the listed client (403), /tor/ fail open ($rtor), no signal; the core's sentence at error level, the configuration file's \"plane tor path ... refused\" line, and the status line \"$sline\""
    else
        bad "refused bind: a fresh start with the tor plane refused: $ans of 20 answered, the listed client $r403 (reputation should deny), /tor/ $rtor, $sig signal death line(s), $errl error sentence(s), configuration line '${cline:0:80}', status '${sline}', start rc $rc"
    fi
    "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    # ---- a graceful from a good configuration into it: the parent stays, the good plane serves, tor reads unknown ----
    refuse_fresh; refuse_conf 0
    if start_httpd "$conf" event; then
        P=$HTTPD_PID
        await "[ \"\$(code / $LISTED)\" = 403 ]" 15 "the good binding denying" || true
        refuse_conf 1
        timeout 20 "$HTTPD" -f "$conf" -k graceful 2>"$W/start-event.err"; rc=$?
        await "grep -q 'SIGUSR1 received' '$W/logs/error.log'" 10 "the graceful" || true
        await "[ \"\$(grep -c 'plane tor is refused at configuration' '$W/logs/error.log')\" -ge 1 ]" 15 "the refusal" || true
        sleep 2
        ans=$(refuse_answers); sig=$(refuse_signals); r403=$(code / "$LISTED"); rtor=$(code /tor/ "$LISTED")
        alive=no; kill -0 "$P" 2>/dev/null && alive=yes
        refuse_lines
        if [ "$alive" = yes ] && [ "$ans" = 20 ] && [ "$sig" = 0 ] && [ "$r403" = 403 ] && [ "$rtor" != 000 ] && [ "${errl:-0}" -ge 1 ] && [ -n "$cline" ]; then
            ok "refused bind: a graceful into a configuration with the tor plane refused keeps the parent, reputation still denies the listed client (403), /tor/ answers fail open ($rtor), 20 of 20 answered, no child killed, and the core's sentence and configuration-file line name the refusal"
        else
            bad "refused bind: a graceful into the refused tor plane: the parent alive $alive, $ans of 20 answered, the listed client $r403 (reputation should deny), /tor/ $rtor, $sig signal death line(s), $errl error sentence(s), configuration line '${cline:0:80}', graceful rc $rc"
        fi
        "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1
        kill -TERM "$P" 2>/dev/null
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "refused bind: the good configuration did not start"
    fi
    # ---- the one binding refused whole, the snapshot and a reputation line naming two files for one plane, at a real
    # start that skipped the configuration test: Apache serves fail open, nothing bound, and says why at error level
    # (nginx refuses the start instead; the configuration test fails on it on every server) ----
    refuse_fresh
    { conf_head event
      printf '%s\n' "WhisperEdgeSnapshot $W/snapshot.bin" "WhisperEdgeData reputation $D/reputation.bin" "WhisperEdgeRefresh 10" \
          "WhisperEdgeSummary $W/counters" 'WhisperEdgeMode deny' 'WhisperEdgeTrustedProxy 127.0.0.1' \
          'WhisperEdgeTrustedHeader X-Forwarded-For' 'WhisperEdgeTrustedHops 2' 'WhisperEdgePolicy "deny if listed >= low"'
    } > "$conf"
    "$HTTPD" -f "$conf" -k start 2>"$W/start-event.err"; rc=$?
    await "[ \"\$(code_nohdr /)\" != 000 ]" 10 "httpd up" || true
    ans=$(refuse_answers); sig=$(refuse_signals); r403=$(code / "$LISTED")
    errl=$(grep -c '\[:error\].*policy refused: whisper_edge_snapshot .* and whisper_edge_data reputation .* both name the reputation plane' "$W/logs/error.log" 2>/dev/null || true)
    if [ "$ans" = 20 ] && [ "$sig" = 0 ] && [ "$r403" = 200 ] && [ "${errl:-0}" -ge 1 ]; then
        ok "refused bind: a real start with the snapshot and a reputation line both set (refused whole by the bind) serves fail open: 20 of 20 answered, the listed client 200 with nothing bound, no signal, and the refusal at error level naming both files"
    else
        bad "refused bind: the two-files start: $ans of 20 answered, the listed client $r403, $sig signal death line(s), $errl error-level refusal line(s), start rc $rc"
    fi
    "$HTTPD" -f "$conf" -k stop >/dev/null 2>&1
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    chmod 0755 "$U"; rm -rf "$D" "$U" "$W/counters"
    fresh_snapshot
}
m3_start_of() { # m3_start_of <pid>: field 22 of /proc/<pid>/stat, the start in clock ticks since boot
    local s
    s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    s=${s##*) }
    # shellcheck disable=SC2086
    set -- $s
    echo "${20}"
}
m3_note_children() { # every child of the parent not yet seen gets its start recorded, read when it appears
    local k
    for k in $(pgrep -P "$HTTPD_PID" 2>/dev/null); do
        [ -n "${M3_START[$k]:-}" ] && continue
        M3_START[$k]=$(m3_start_of "$k")
    done
}
m3_replacements() { local k; for k in $(pgrep -P "$HTTPD_PID" 2>/dev/null); do case " $M3_ORIG " in *" $k "*) ;; *) echo "$k" ;; esac; done; }
m3_zombies() { local k st; for k in $(pgrep -P "$HTTPD_PID" 2>/dev/null); do st=$(cat "/proc/$k/stat" 2>/dev/null); st=${st##*) }; [ "${st%% *}" = Z ] && echo "$k"; done; }
m3_dead_replacements() { local k; for k in $(m3_zombies); do case " $M3_ORIG " in *" $k "*) ;; *) echo "$k" ;; esac; done; }
m3_dead() { sed -n 's/.*child pid \([0-9]*\) exit signal Bus error (7).*/\1/p' "$W/logs/error.log" 2>/dev/null | sort -u; }
m3_tail_addr() { echo "198.18.$((125 + $1 % 131)).$(($1 % 256))"; }   # inside 198.18.125.0-198.18.255.255
m3_arm() { # m3_arm <object> <data|legacy> <label> [stop-on-post-truncate-death]: one truncate under held ticks
    local so=$1 kind=$2 label=$3 early=${4:-} conf="$W/httpd-m3.conf" file k i r t0 t1 d
 M3_ORIG=""; M3_NORIG=0; M3_DEATHS=0; M3_POSTDEAD=0; M3_ORIGDEAD=0; M3_SENT=0; M3_ANSWERED=0; M3_COUNTED=""
    M3_START=()
    sudo -n chattr -i "$W/m3data/reputation.bin" "$W/m3snap.bin" 2>/dev/null
    rm -rf "$W/m3data" "$W/m3pause" "$W/m3snap.bin" "$W/counters" "$W/html"
    mkdir -p "$W/m3data" "$W/m3pause" "$W/html" "$W/logs"; chmod 0755 "$W/m3data"; echo page > "$W/html/index.html"
    if [ "$kind" = data ]; then file="$W/m3data/reputation.bin"; else file="$W/m3snap.bin"; fi
    cp "$W/m3.bin" "$file.new"; chmod 0444 "$file.new"; mv "$file.new" "$file"
    sudo -n chattr +i "$file" || { bad "M3($label): chattr +i failed on $file"; return 1; }
    { conf_head prefork | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $so#; s/^StartServers 2\$/StartServers 4/; s/^MinSpareServers 2\$/MinSpareServers 4/; s/^MaxSpareServers 2\$/MaxSpareServers 4/; s/^MaxRequestWorkers 2\$/MaxRequestWorkers 4/"
      if [ "$kind" = data ]; then echo "WhisperEdgeData $W/m3data"; else echo "WhisperEdgeSnapshot $file"; fi
      echo "WhisperEdgeRefresh 10"
      echo "WhisperEdgeTrustedProxy 127.0.0.1"
      echo "WhisperEdgeTrustedHeader X-Forwarded-For"
      echo "WhisperEdgeTrustedHops 2"
      echo "WhisperEdgeSummary $W/counters"
      echo "WhisperEdgeMode deny"
      echo 'WhisperEdgePolicy "deny if listed >= high"'
    } > "$conf"
    if ! WE_MOD_DEBUG_TAIL=198.18.125.0-198.18.255.255 WE_MOD_PAUSE_DIR="$W/m3pause" start_httpd "$conf" prefork; then
        bad "M3($label): httpd did not start: $(grep -v 'whisper edge: policy:' "$W/start-prefork.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
        sudo -n chattr -i "$file" 2>/dev/null; return 1
    fi
    await '[ "$(pgrep -P "$HTTPD_PID" | wc -l)" -ge 4 ]' 15 "four children"
    await_first_tick
    # /index.html, one decision per request: / adds mod_dir's internal redirect and a second decision (measured:
    # 397 counted for 198 requests)
    r=$(code /index.html "$(m3_tail_addr 0)")
    [ "$r" = 200 ] || bad "M3($label): before the truncate a tail address answered $r, not 200"
    M3_ORIG=$(pgrep -P "$HTTPD_PID" | sort -n | tr '\n' ' ')
    for k in $M3_ORIG; do M3_START[$k]=$(m3_start_of "$k"); M3_NORIG=$((M3_NORIG + 1)); done
    # every original thread parked at the tick's pause before the truncate, so none can see it before a request does
    : > "$W/m3pause/tick"
    for k in $M3_ORIG; do
        await "[ -f '$W/m3pause/held.tick.$k' ]" 30 "child $k held" || { bad "M3($label): child $k's tick was not held within 30 s"; }
    done
    # the parent's monitor as a barrier: held at its top, then let through once, so its check runs on the intact file
    # and the next comes no sooner than its own interval; the truncate follows it (the parent's loop is one thread:
    # held, it neither checks nor forks)
    : > "$W/m3pause/monitor"
    await "[ -f '$W/m3pause/held.monitor.$HTTPD_PID' ]" 25 "the parent's monitor held" \
        || { bad "M3($label): the parent's monitor was not held within 25 s"; rm -f "$W/m3pause/tick" "$W/m3pause/monitor"; return 1; }
    rm -f "$W/m3pause/monitor"
    await "[ ! -f '$W/m3pause/held.monitor.$HTTPD_PID' ]" 10 "the parent's monitor released" || true
    sleep 0.2
    M3_TRUNC=$(awk -v hz="$(getconf CLK_TCK)" '{ printf "%d", $1 * hz }' /proc/uptime)
    M3_LOGLINE=$(wc -l < "$W/logs/error.log")
    sudo -n chattr -i "$file" && chmod u+w "$file" && truncate -s 139264 "$file" \
        || { bad "M3($label): the in-place truncate failed"; rm -f "$W/m3pause/tick"; return 1; }
    t0=$(date +%s%N)
    # every original reached at once, so the parent forks the replacements under test at once; as soon as one exists
    # the parent's monitor is held again, before its next check, so the replacements inherit the parent's view of
    # the plane as it stood at the truncate, and only a worker's own start can see the change
    for k in $M3_ORIG; do code /index.html "$(m3_tail_addr "$k")" >/dev/null & done
    wait
    if [ "$kind" = data ]; then                      # the private copy's arm has no death, so no replacement to wait for
        await "m3_note_children; [ -n \"\$(m3_replacements)\" ]" 15 "a replacement child" \
            || { bad "M3($label): no replacement child was forked within 15 s of the originals' requests"; rm -f "$W/m3pause/tick"; return 1; }
    fi
    : > "$W/m3pause/monitor"
    if [ "$kind" = data ] && awk -v from="$M3_LOGLINE" -v p="$HTTPD_PID" 'NR > from && (index($0, "[pid " p "]") || index($0, "[pid " p ":")) && index($0, "the armed file was rewritten in place") { f = 1 } END { exit !f }' "$W/logs/error.log"; then
        # the parent's check ran before the hold: this run proves nothing, and m3_try runs it again
        rm -f "$W/m3pause/tick" "$W/m3pause/monitor"
        return 2
    fi
    for ((i = 1; i <= 200; i++)); do
        r=$(code /index.html "$(m3_tail_addr "$i")")
        M3_SENT=$i
        [ "$r" != 000 ] && M3_ANSWERED=$((M3_ANSWERED + 1))
        m3_note_children
        # a replacement that died is a zombie until the held parent reaps it
        if [ -n "$early" ] && [ -n "$(m3_dead_replacements)" ]; then break; fi
    done
    t1=$(date +%s%N)
    M3_RATE=$(( M3_SENT * 1000000000 / (t1 - t0 + 1) ))
    rm -f "$W/m3pause/tick" "$W/m3pause/monitor"                      # the release
    await '[ -z "$(m3_zombies)" ]' 20 "the parent's reaping" || true
    await_next_tick || true
    M3_COUNTED=$(grep -h '^debug tail-requests ' "$W"/counters/*.status 2>/dev/null | awk '{ if ($3 > m) m = $3 } END { print m + 0 }')
    for d in $(m3_dead); do
        M3_DEATHS=$((M3_DEATHS + 1))
        case " $M3_ORIG " in
            *" $d "*) M3_ORIGDEAD=$((M3_ORIGDEAD + 1)) ;;
            *) M3_POSTDEAD=$((M3_POSTDEAD + 1)) ;;          # not an original: forked after the truncate
        esac
        # an original read later than the truncate would be a recording fault; printed with the row by its start
        if [ -n "${M3_START[$d]:-}" ] && [ "${M3_START[$d]}" -gt "$M3_TRUNC" ]; then
            echo "    [M3: pid $d started at tick ${M3_START[$d]}, after the truncate at $M3_TRUNC]"
        fi
    done
    return 0
}
m3_try() { # m3_try <args of m3_arm>: up to three runs while the parent's check wins the race to the hold (rc 2)
    local t rc
    for t in 1 2 3; do
        m3_arm "$@"; rc=$?
        [ "$rc" = 1 ] && m3_finish                   # a failed run leaves nothing running for the next
        [ "$rc" = 2 ] || return "$rc"
        echo "    [M3($3): run $t: the parent's monitor checked the truncated file before its hold; run again]"
        m3_finish
    done
    bad "M3($3): in three runs the parent's monitor checked the truncated file before the hold, so the arm never ran under its precondition"
    return 1
}
m3_finish() { # stop the arm's httpd and leave no immutable file behind
    rm -f "$W/m3pause/tick" "$W/m3pause/monitor"
    stop_httpd "$W/httpd-m3.conf" prefork || bad "M3: httpd did not stop"
    await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    sudo -n chattr -i "$W/m3data/reputation.bin" "$W/m3snap.bin" 2>/dev/null
}
run_truncate_rows() { # M3: an in-place truncate of the inherited generation kills only workers forked before it
    local i k alive n1000 t0 t1
    declare -gA M3_START=()
    echo "  [M3: the inherited generation truncated in place under held ticks]"
    sudo -n true 2>/dev/null || { bad "M3: needs root for chattr, and sudo -n is refused on this host"; return; }
    [ -n "$APXS" ] || { bad "M3: no apxs to build the debug module"; return; }
    # the debug object (WE_MOD_DEBUG: the core's tail count) with the tick pause; the two start-check controls on it
    build_variant m3 -Wc,-DWE_MOD_DEBUG -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PAUSE_TICK \
        || { bad "M3: the debug pause build failed: $(tail -2 "$CTL/m3.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant m3nostat -Wc,-DWE_MOD_DEBUG -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PAUSE_TICK -Wc,-DWE_MOD_TEST_NO_START_STAT \
        || { bad "M3: the no-start-stat control build failed: $(tail -2 "$CTL/m3nostat.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    build_variant m3inherit -Wc,-DWE_MOD_DEBUG -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_PAUSE_TICK -Wc,-DWE_MOD_TEST_SERVE_INHERITED \
        || { bad "M3: the serve-inherited control build failed: $(tail -2 "$CTL/m3inherit.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    # the plane: format 1 reputation, 16,384 ranges of four addresses over 198.18.0.0/16, no meta and no blob, so
    # sev[] is the file's last array (bytes 131264 to 147647). The cut, at the page boundary 139264, falls inside it:
    # a lookup whose range index is 8,000 or above reads sev[] past the new end, and those ranges are
    # 198.18.125.0 to 198.18.255.255, the range WE_MOD_DEBUG_TAIL names. Their severity is low and the rule asks
    # for high, so a request a worker survives is answered 200
    python3 -c '
import sys
base = (198 << 24) | (18 << 16)
with open(sys.argv[1], "w") as f:
    for i in range(16384):
        f.write("4 %d %d sev=1\n" % (base + 4 * i, base + 4 * i + 3))
' "$W/m3rec.txt"
    python3 "$ROOT/core/make-test-snapshot.py" --plane reputation --out "$W/m3.bin" --format 1 --v4-index none \
        --v6-index none --records "$W/m3rec.txt" --generation $((GEN * 10 + 7000000)) --valid-until 0
    if ! python3 - "$W/m3.bin" <<'PY'
import struct, sys
b = open(sys.argv[1], "rb").read()
sev, meta, blob, flen = struct.unpack_from("<I", b, 64)[0], struct.unpack_from("<I", b, 68)[0], struct.unpack_from("<I", b, 92)[0], struct.unpack_from("<I", b, 100)[0]
sys.exit(0 if (sev, meta, blob, flen, len(b)) == (131264, 0, 0, 147648, 147648) else 1)
PY
    then
        bad "M3: the plane's layout is not the one the cut was computed for (sev[] at 131264, no meta or blob, 147648 bytes)"; return
    fi

    # ---- the row: the data directory's mapped generation, inherited by the children ----
    if m3_try "$CTL/m3.so" data main; then
        alive=$(for k in $M3_ORIG; do kill -0 "$k" 2>/dev/null && echo "$k"; done | grep -c . || true)
        [ "$((M3_COUNTED - 1))" -ge 200 ] \
            && ok "M3: 200 tail-touching requests counted across the lineage after the truncate ($((M3_COUNTED - 1)), read from the debug build's shared count, $M3_RATE requests a second; $M3_ANSWERED of $M3_SENT answered)" \
            || bad "M3: only $((M3_COUNTED - 1)) of 200 tail-touching requests were counted after the truncate ($M3_SENT sent, $M3_RATE a second)"
        [ "$M3_DEATHS" -ge 1 ] \
            && ok "M3: $M3_DEATHS original worker(s) died by signal 7 on the truncated tail, which the held ticks make certain, not the timing" \
            || bad "M3: no worker died by signal 7 under held ticks, so the truncate was never read through the inherited mapping"
        [ "$M3_POSTDEAD" = 0 ] \
            && ok "M3: no process forked after the truncate died by signal 7 (each started later than it, by /proc field 22)" \
            || bad "M3: $M3_POSTDEAD process(es) forked after the truncate died by signal 7"
        [ "$M3_DEATHS" -le "$M3_NORIG" ] \
            && ok "M3: deaths ($M3_DEATHS) are at most the $M3_NORIG workers running at the truncate" \
            || bad "M3: $M3_DEATHS deaths for the $M3_NORIG workers running at the truncate"
        await "[ -z \"\$(for k in $M3_ORIG; do kill -0 \$k 2>/dev/null && echo \$k; done)\" ]" 20 "the original workers gone" || true
        alive=$(for k in $M3_ORIG; do kill -0 "$k" 2>/dev/null && echo "$k"; done | grep -c . || true)
        n1000=0; t0=$(date +%s%N)
        for ((i = 0; i < 1000; i++)); do [ "$(code /index.html "$(m3_tail_addr "$i")")" != 000 ] && n1000=$((n1000 + 1)); done
        t1=$(date +%s%N)
        [ "$n1000" = 1000 ] && [ "$(m3_dead | grep -c . || true)" = "$M3_DEATHS" ] \
            && ok "M3: then 1,000 consecutive tail requests are all answered, no further death ($(( (t1 - t0) / 1000000 )) ms; $alive original worker(s) still running, past their released tick)" \
            || bad "M3: after the release $n1000 of 1,000 tail requests were answered, $(( $(m3_dead | grep -c . || true) - M3_DEATHS )) more death(s)"
        m3_finish
    fi
    # ---- the legacy snapshot.bin: the module serves a private copy, so the same truncate kills nothing ----
    if m3_try "$CTL/m3.so" legacy legacy; then
        [ "$M3_DEATHS" = 0 ] && [ "$M3_ANSWERED" = "$M3_SENT" ] \
            && ok "M3: the same truncate on the legacy snapshot.bin (served from a private copy) kills no worker: $M3_ANSWERED of $M3_SENT tail requests answered ($((M3_COUNTED - 1)) counted)" \
            || bad "M3: the legacy snapshot.bin truncate: $M3_DEATHS death(s), $M3_ANSWERED of $M3_SENT answered"
        m3_finish
    fi
    # ---- the controls: a worker start that looks at nothing, and one that keeps serving the inherited mapping ----
    for i in m3nostat m3inherit; do
        if m3_try "$CTL/$i.so" data "$i" early; then
            # the parent's monitor was held before its next check, so every replacement inherited the plane as it stood at
            # the truncate: a worker start that looks at nothing, or keeps serving it, must die on the tail
            if [ "$M3_POSTDEAD" -ge 1 ]; then
                ok "M3's control: $( [ "$i" = m3nostat ] && echo 'a worker start that looks at nothing (WE_MOD_TEST_NO_START_STAT)' || echo 'a worker start that keeps serving the inherited mapping (WE_MOD_TEST_SERVE_INHERITED)') shows $M3_POSTDEAD process(es) forked after the truncate dying by signal 7, with the parent's monitor held, so the arm above can fail"
            else
                bad "M3's control ($i): with the parent's monitor held, no process forked after the truncate died ($M3_DEATHS deaths, $M3_SENT requests), so the arm above proves nothing"
            fi
            ctl_exit_clean "M3's $i control" 'Bus error \(7\)'
            m3_finish
        fi
    done
    rm -rf "$W/m3data" "$W/m3pause" "$W/m3snap.bin" "$W/counters"
    fresh_snapshot
}
build_debug_module() { # the WE_MOD_DEBUG build (the core's debug counters on) at $CTL/debug.so, for M3 and M10's digest counts
    build_variant debug -Wc,-DWE_MOD_DEBUG
}
run_debug_build_rows() { # the WE_MOD_DEBUG switch: a separate debug object for M3, never the release build
    local conf="$W/httpd-dbg.conf" out
    echo "  [the debug build switch]"
    [ -n "$APXS" ] || { bad "debug: no apxs to build the debug module"; return; }
    build_debug_module || { bad "debug: the WE_MOD_DEBUG build failed: $(tail -2 "$CTL/debug.log" | tr '\n' ' ' | cut -c1-200)"; return; }
    if grep -qF 'whisper edge: the WE_MOD_DEBUG build' "$CTL/debug.so" && ! grep -qF 'whisper edge: the WE_MOD_DEBUG build' "$MODULE" \
        && ! grep -q 'WE_MOD_DEBUG' "$ROOT/apache/build.sh"; then
        ok "debug: the WE_MOD_DEBUG build carries its marker and the release module (as build.sh compiled it, which never names the switch) does not"
    else
        bad "debug: the marker test: debug $(grep -cF 'whisper edge: the WE_MOD_DEBUG build' "$CTL/debug.so") release $(grep -cF 'whisper edge: the WE_MOD_DEBUG build' "$MODULE") build.sh $(grep -c 'WE_MOD_DEBUG' "$ROOT/apache/build.sh")"
    fi
    rm -rf "$W/html" "$W/counters" "$W/logs"; mkdir -p "$W/html" "$W/logs"; echo page > "$W/html/index.html"
    fresh_snapshot
    { conf_head prefork | sed "s#^LoadModule whisper_edge_module .*#LoadModule whisper_edge_module $CTL/debug.so#"; conf_data; } > "$conf"
    if start_httpd "$conf" prefork; then
        await "[ \"\$(grep -c 'runs the WE_MOD_DEBUG build' '$W/logs/error.log')\" -ge 2 ]" 15 "each child's debug line" || true
        out=$(grep -c 'runs the WE_MOD_DEBUG build' "$W/logs/error.log" 2>/dev/null || true)
        [ "${out:-0}" -ge 2 ] && [ "$(code / "$LISTED")" = 200 ] \
            && ok "debug: the debug build serves, and each of its children says at start that it runs the WE_MOD_DEBUG build ($out lines)" \
            || bad "debug: the debug build: $out start lines, / answered $(code / "$LISTED")"
        stop_httpd "$conf" prefork || bad "debug: httpd did not stop"
        await '[ "$(code_nohdr /)" = 000 ]' 15 "the stopped listener's port release"
    else
        bad "debug: the debug build did not start: $(grep -v 'whisper edge: policy:' "$W/start-prefork.err" | tail -2 | tr '\n' ' ' | cut -c1-300)"
    fi
    rm -rf "$W/counters" "$W/logs"; mkdir -p "$W/logs"
    fresh_snapshot
}
run_built_object_rows() {
    local HP="$ROOT/core/hotpath-gate.sh" arch cc_line cc_id
    echo "  [the built object]"
    arch=$(uname -m)
    # the hot-path gate's patterns and its locals parser, extracted so there is ONE copy of each
    eval "$(grep -E '^(A64|X86)_[A-Z_0-9]+=' "$HP")"
    eval "$(sed -n '/^locals_of() {/,/^}/p' "$HP")"
    local band bmin bmax stack_max
    band=$(grep -oE '"hpmod:hp_mod.c:\$STACK_MAX_EVAL:[0-9]+:[0-9]+' "$HP" | head -1)
    bmin=$(printf '%s' "$band" | cut -d: -f4); bmax=$(printf '%s' "$band" | cut -d: -f5)
    stack_max=$(sed -n 's/^STACK_MAX_EVAL=\([0-9]*\)$/\1/p' "$HP")
    cc_line=$(readelf -p .comment "$MODULE" 2>/dev/null | grep -oE 'GCC: \([^)]*\) [0-9]+|clang version [0-9]+' | head -1)
    case "$cc_line" in
        GCC*) cc_id="gcc-${cc_line##* }" ;;
        clang*) cc_id="clang-${cc_line##* }" ;;
        *) cc_id="unknown" ;;
    esac
    echo "  leg: $cc_id on $arch, the module as build.sh compiled it (the distribution's apxs flags); hpmod band $bmin..$bmax, stack bound $stack_max"

    # the wrapper, by symbol, from the linked object
    local sym=apache_whisper_edge_decide body insns n
    body=$(objdump -d --no-show-raw-insn "$MODULE" | sed -n "/<$sym>:\$/,/^\$/p" | sed '1d')
    if [ -z "$body" ]; then
        bad "H2: the decide wrapper $sym is not a symbol of the built module (stripped, inlined or renamed)"
        return
    fi
    ok "H2: the decide wrapper $sym is one symbol of the built module"
    grep -qE " [tT] $sym\.(constprop|isra|part|cold|lto_priv)" <<<"$(nm "$MODULE")" \
        && bad "H2: the wrapper has a clone: $(nm "$MODULE" | grep -E " $sym\." | tr '\n' ' ')" \
        || ok "H2: and it has no .constprop, .isra, .part, .cold or .lto_priv clone"
    insns=$(printf '%s\n' "$body" | grep -E '^[[:space:]]*[0-9a-f]+:' | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' | tr '\t' ' ')
    n=$(printf '%s\n' "$insns" | grep -c .)
    local fired
    if [ "$arch" = aarch64 ]; then
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_BRANCH" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no bl, blr, br, svc or trap in the wrapper (no call, no syscall)" || bad "H2: branch class in the wrapper: $fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_BARRIER" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no barrier in the wrapper" || bad "H2: barrier in the wrapper: $fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_STRING" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no string instruction in the wrapper" || bad "H2: string instruction in the wrapper: $fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$A64_RETREG" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: the wrapper returns through the link register" || bad "H2: ret through another register: $fired"
        local cls nacq
        cls=$(printf '%s\n' "$insns" | grep -E "$A64_CLASS" || true)
        nacq=$(printf '%s\n' "$cls" | grep -cE "$A64_ACQUIRE_ONE" || true)
        cls=$(printf '%s\n' "$cls" | grep -vE "$A64_ACQUIRE_ONE" | grep -v '^$' || true)
        [ "$nacq" -ge 1 ] && [ "$nacq" -le 8 ] \
            && ok "H2: acquire-views: $nacq acquire load(s) of a view pointer (the mask loop's shape; the per-request count is a trace row's)" \
            || bad "H2: expected one to eight acquire loads of the view pointers, found $nacq"
        [ -z "$cls" ] && ok "H2: nothing else in the atomic class (no locked add, no exclusive pair, no outline atomic)" || bad "H2: atomic class in the wrapper: $(printf '%s\n' "$cls" | head -3 | tr '\n' ';')"
    else
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_BRANCH" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no call, syscall, indirect jmp or trap in the wrapper" || bad "H2: branch class in the wrapper: $fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_LOCK|$X86_FENCE|$X86_XCHG" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no lock prefix, fence or xchg in the wrapper" || bad "H2: atomic class in the wrapper: $fired"
        fired=$(printf '%s\n' "$insns" | grep -E "$X86_STRING" | head -3 | tr '\n' ';' || true)
        [ -z "$fired" ] && ok "H2: no string instruction in the wrapper" || bad "H2: string instruction in the wrapper: $fired"
    fi
    # a branch that names ANOTHER symbol is a call however it is spelled
    fired=$(printf '%s\n' "$body" | grep -oE '<[A-Za-z_.][A-Za-z0-9_.@]*(\+0x[0-9a-f]+)?>' | grep -vE "<$sym(\+0x[0-9a-f]+)?>" | sort -u | tr '\n' ' ' || true)
    [ -z "$fired" ] && ok "H2: the wrapper names no other symbol (no tail call, no PLT, no constant pool through a symbol)" || bad "H2: the wrapper references $fired"
    # constant-pool references in the LINKED object: adrp/adr and literal loads (aarch64), rip-relative (x86_64)
    local pool
    if [ "$arch" = aarch64 ]; then
        pool=$(printf '%s\n' "$insns" | grep -cE '^(adrp|adr) |^ldr[a-z]* +[a-z][0-9]+, +[0-9a-f]+ <' || true)
    else
        pool=$(printf '%s\n' "$insns" | grep -cE '\(%rip\)' || true)
    fi
    local exp_pool=0
    case "$cc_id|$arch" in
        "clang-20|x86_64") exp_pool=14 ;;    # the hot-path gate's expected-relocations table for hpmod's shape on this leg
    esac
    [ "$pool" = "$exp_pool" ] && ok "H2: $pool constant-pool references in the linked wrapper, the expected-relocations table's figure for this leg" \
        || bad "H2: $pool constant-pool references in the wrapper, where the table holds $exp_pool for this leg"
    # locals, through the hot-path gate's own parser; the expectation is the gate's hpmod entry for this leg
    local nloc exp_loc=0
    nloc=$(printf '%s\n' "$insns" | locals_of "$arch")
    case "$cc_id|$arch" in
        "clang-18|x86_64") exp_loc=16 ;;
    esac
    [ "${nloc:-0}" = "$exp_loc" ] && ok "H2: $nloc bytes of locals in the wrapper, exactly the expected-locals table's figure for this leg" \
        || bad "H2: $nloc bytes of locals in the wrapper, where the table holds $exp_loc for $cc_id on $arch"
    [ "$n" -ge "$bmin" ] && [ "$n" -le "$bmax" ] \
        && ok "H2: $n instructions in the wrapper, inside hpmod's band $bmin..$bmax" \
        || bad "H2: $n instructions in the wrapper, outside $bmin..$bmax"
    local frame
    frame=$(printf '%s\n' "$insns" | grep -oE 'stp +x29, x30, \[sp, #-[0-9]+\]!|sub +sp, sp, #[0-9]+|sub +\$0x[0-9a-f]+,%rsp' | head -1)
    echo "  frame: $frame (locals $nloc, stack bound $stack_max)"
    # every evaluation site: the three handlers reach the wrapper through the module's own text and nothing else
    local h reach
    for h in we_access_checker we_fixups_first we_fixups_last; do
        reach=$(reaches "$h" "$sym")
        [ "$reach" = yes ] && ok "H2: $h (symbol $(sym_of "$h")) reaches $sym by direct calls through the module's own functions ($(reach_path "$h" "$sym"))" \
            || bad "H2: $h (symbol $(sym_of "$h")) does not reach the wrapper by direct calls: $(reach_path "$h" "$sym")"
    done
    # the evaluation-site records: the marker is the core's; dark by name until it is in this tree
    if grep -q 'we_eval_sites' "$ROOT/core/we_eval.h" 2>/dev/null; then
        local recs
        recs=$(objdump -s -j .we_eval_sites "$MODULE" 2>/dev/null | grep -cE '^ [0-9a-f]+' || true)
        [ "$recs" -ge 1 ] && ok "H2: .we_eval_sites holds records (resolved per symbol below)" || bad "H2: no evaluation site found"
    else
        dark "H2 eval-sites: the core's we_eval.h in this tree carries no .we_eval_sites marker; the record check runs, with no edit here, once it does"
    fi
    # the cold symbols the handler rows name, pinned and hidden
    for h in we_apache_shard_register we_apache_subblock_swap; do
        if grep -qE " t $h\$" <<<"$(nm "$MODULE")"; then
            if grep -qE " $h\$" <<<"$(nm -D "$MODULE")"; then bad "N5: $h is exported (default visibility): interposable, so not pinned"; else ok "N5: $h is a local symbol of its own (noinline, hidden)"; fi
        else
            bad "N5: $h is not a symbol of the built module (inlined into its caller: the control's own failure)"
        fi
    done
    # N5: the request path outside the wrapper takes no lock except inside the two cold symbols
    local f fs locking
    for f in we_access_checker we_fixups_first we_fixups_last we_evaluate we_decide_frame we_post_read_request; do
        fs=$(sym_of "$f")
        [ -n "$fs" ] || continue              # inlined into its caller: its body is judged there
        body=$(objdump -d --no-show-raw-insn "$MODULE" | sed -n "/<$fs>:\$/,/^\$/p" | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' | tr '\t' ' ')
        if [ "$arch" = aarch64 ]; then
            fired=$(printf '%s\n' "$body" | grep -E '^(ldadd|ldclr|ldeor|ldset|ldxr|stxr|ldaxr|stlxr|cas|swp)[a-z]* |^bl +[0-9a-f]+ <__aarch64_' | head -2 | tr '\n' ';' || true)
        else
            # an xchg is atomic only against memory (the core's hot-path rule); `xchg %ax,%ax` is the two-byte nop
            # gcc pads x86_64 code with (66 90), measured on the first x86_64 walk
            fired=$(printf '%s\n' "$body" | grep -E '^lock |^xchg[a-z]*[[:space:]].*\(' | head -2 | tr '\n' ';' || true)
        fi
        locking=$(printf '%s\n' "$body" | grep -oE '<(pthread_mutex_lock|pthread_mutex_unlock|aligned_alloc|malloc|calloc|realloc|posix_memalign|pthread_setspecific)@plt>' | sort -u | tr '\n' ' ' || true)
        [ -z "$fired" ] && [ -z "$locking" ] \
            && ok "N5: $fs has no locked instruction and calls no allocator or mutex (those sit in the two cold symbols)" \
            || bad "N5: $fs: ${fired:+atomic: $fired }${locking:+calls: $locking}"
    done
    for f in we_apache_shard_register we_apache_subblock_swap; do
        body=$(objdump -d --no-show-raw-insn "$MODULE" | sed -n "/<$f>:\$/,/^\$/p")
        locking=$(printf '%s\n' "$body" | grep -oE '<[a-z_]+@plt>' | sort -u | sed 's/<//;s/@plt>//' | tr '\n' ' ')
        local extra
        extra=$(printf '%s\n' "$locking" | tr ' ' '\n' | grep -vE '^(aligned_alloc|free|pthread_mutex_lock|pthread_mutex_unlock|pthread_setspecific|__stack_chk_fail)$' | grep -v '^$' | tr '\n' ' ' || true)
        [ -z "$extra" ] && ok "N5: $f calls only $(printf '%s' "$locking" | sed 's/ $//'), the cold row's allow-list" \
            || bad "N5: $f calls outside its row: $extra"
    done
    # Q1 create arm: the stop function's calls, and the calls of every function it reaches, are the Apache row of the
    # stop-path table. The module calls the core's bounded stop, which calls the core's stop in windows; the stage's
    # words are a constant the core returns. Each function's call targets are read from the linked object
    local q1f q1calls c q1extra="" q1all=""
    for q1f in we_child_stop:we_mod_thread_stop_bounded,we_mod_stage_text,write,__errno_location,__stack_chk_fail \
               we_mod_thread_stop_bounded:we_mod_thread_stop,__stack_chk_fail \
               we_mod_stage_text: \
               we_mod_thread_stop:write,poll,clock_gettime,__errno_location,__stack_chk_fail; do
        body=$(objdump -d --no-show-raw-insn "$MODULE" | sed -n "/<${q1f%%:*}>:\$/,/^\$/p")
        if [ -z "$body" ]; then
            q1extra="$q1extra ${q1f%%:*}(not found in the object)"
            continue
        fi
        # the targets of the branch instructions alone: a symbol on a data reference (x86_64's `lea text.0(%rip)`,
        # the stage words' table) is not a call, measured on the first x86_64 walk
        q1calls=$(sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' <<<"$body" | tr '\t' ' ' \
            | grep -E '^(call|callq|jmp|jmpq|bl|b|b\.[a-z]+|cbz|cbnz|tbz|tbnz) ' \
            | grep -oE '<[A-Za-z_][A-Za-z0-9_.]*(@plt)?>' | grep -vE "^<${q1f%%:*}([+>])" | sed 's/<//;s/>//;s/@plt//;s/+0x.*//' | sort -u | tr '\n' ' ')
        q1all="$q1all ${q1f%%:*}: ${q1calls:-none};"
        for c in $q1calls; do
            case ",${q1f#*:}," in *",$c,"*) ;; *) q1extra="$q1extra ${q1f%%:*}->$c" ;; esac
        done
    done
    [ -z "$q1extra" ] && ok "Q1: the child's stop path reaches only the stop-path table's Apache row (an atomic flag, write, poll, clock_gettime):$(sed 's/ $//' <<<"$q1all")" \
        || bad "Q1: the stop path reaches calls outside the Apache row of the stop-path table:$q1extra"

    # the evaluation is a frame of its own: the decision frame CALLS the decide wrapper, so the evaluator's locals sit
    # beside the export fill's chain, never stacked with it (the frame rule's accounting). An inlined wrapper would
    # move them into the scratch's frame; the control inlines it and must fail this
    eval_called() { # eval_called <object>: 0 when we_decide_frame branches to apache_whisper_edge_decide
        local fs body
        fs=$(nm "$1" | awk '($2 == "t" || $2 == "T") && ($3 == "we_decide_frame" || index($3, "we_decide_frame.") == 1) { print $3; exit }')
        [ -n "$fs" ] || return 1
        body=$(objdump -d --no-show-raw-insn "$1" | sed -n "/<$fs>:\$/,/^\$/p" | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' | tr '\t' ' ')
        grep -qE '^(call|callq|jmp|jmpq|bl|b) +[0-9a-f]+ <apache_whisper_edge_decide(\.[a-z0-9.]+)?>' <<<"$body"
    }
    eval_called "$MODULE" \
        && ok "frame: the decision frame calls the decide wrapper (apache_whisper_edge_decide), so the evaluation is a frame of its own beside the export fill's chain" \
        || bad "frame: the decision frame does not call the decide wrapper: the evaluation is inlined into the scratch's frame"
    if [ -n "$APXS" ] && build_variant decideinline -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_TEST_DECIDE_INLINED; then
        eval_called "$CTL/decideinline.so" \
            && bad "frame's control: the build inlining the decide wrapper (WE_MOD_TEST_DECIDE_INLINED) still shows the call, so the row above proves nothing" \
            || ok "frame's control: the build inlining the decide wrapper (WE_MOD_TEST_DECIDE_INLINED) shows no call to it from the decision frame, so the row above can fail"
    else
        bad "frame's control: the inlined-wrapper build failed: $(tail -2 "$CTL/decideinline.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi

    # the controls, built from a copy of the tree so the shipped object is never touched
    if [ -z "$APXS" ]; then
        bad "H2/K1 controls: no apxs on this host to build the control objects"
        return
    fi
    ctl_tree
    local T="$CTL"
    if build_variant plant -Wc,-DWE_MOD_CONTROL_BUILD -Wc,-DWE_MOD_PLANT_CALL; then
        body=$(objdump -d --no-show-raw-insn "$T/plant.so" | sed -n "/<$sym>:\$/,/^\$/p" | sed '1d')
        if [ "$arch" = aarch64 ]; then fired=$(printf '%s\n' "$body" | grep -E "$A64_BRANCH" | head -1); else fired=$(printf '%s\n' "$body" | grep -E "$X86_BRANCH" | head -1); fi
        [ -n "$fired" ] && ok "H2's control: a getpid() planted in the wrapper (WE_MOD_PLANT_CALL) is refused by the branch check: $(printf '%s' "$fired" | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//')" \
            || bad "H2's control: the planted call was not seen by the branch check (the check is blind)"
    else
        bad "H2's control: the planted-call build failed: $(tail -3 "$T/plant.log" | tr '\n' ' ' | cut -c1-200)"
    fi
    # K1: keyless and keyed builds are one byte string; the source names no key
    if build_variant keyless && WHISPER_EDGE_KEY=whisper_live_planted WE_KEY_FILE="$T/key" build_variant keyed; then
        : > "$T/key"
        for s in .text .rodata .data .data.rel.ro; do
            objcopy -O binary -j "$s" "$T/keyless.so" "$T/keyless$s.bin" 2>/dev/null
            objcopy -O binary -j "$s" "$T/keyed.so" "$T/keyed$s.bin" 2>/dev/null
            cmp -s "$T/keyless$s.bin" "$T/keyed$s.bin" && ok "K1: $s is byte-identical keyless and keyed" || bad "K1: $s differs between the keyless and the keyed build"
        done
        objcopy --remove-section .we_eval_sites "$T/keyless.so" "$T/keyless.stripped" 2>/dev/null; objcopy --remove-section .we_eval_sites "$T/keyed.so" "$T/keyed.stripped" 2>/dev/null
        cmp -s "$T/keyless.stripped" "$T/keyed.stripped" && ok "K1: the whole file is identical keyless and keyed (after the evaluation-site section is removed)" \
            || bad "K1: the keyless and keyed files differ: $(cmp "$T/keyless.stripped" "$T/keyed.stripped" 2>&1 | head -1)"
        if WE_CTL_PATCH='s/^module AP_MODULE_DECLARE_DATA whisper_edge_module;$/module AP_MODULE_DECLARE_DATA whisper_edge_module;\n__attribute__((used)) static const char we_planted_key[] = "whisper_live_planted_X-API-Key";/' build_variant planted; then
            objcopy --remove-section .we_eval_sites "$T/planted.so" "$T/planted.stripped" 2>/dev/null
            cmp -s "$T/keyless.stripped" "$T/planted.stripped" && bad "K1's control: a planted key string left the file identical (the comparison is blind)" \
                || ok "K1's control: a planted key string changes the file, so the comparison can fail"
        else
            bad "K1's control: the planted build failed"
        fi
    else
        bad "K1: a build failed: $(tail -2 "$T/keyless.log" "$T/keyed.log" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    local scan
    scan=$(grep -rnE 'X-API-Key|/edge/k/|whisper-edge/key|WHISPER_EDGE_KEY' "$ROOT/apache/mod_whisper_edge.c" "$ROOT"/core/*.c "$ROOT"/core/*.h 2>/dev/null | grep -v 'we_hold_harmless.h' | head -3 || true)
    [ -z "$scan" ] && ok "K1: the module and core sources name no key path, header or directory" || bad "K1: a key reference in the sources: $scan"
    grep -q 'whisper_live_planted_X-API-Key' "$T/apache/mod_whisper_edge.c" && ok "K1's scan control: the planted reference is found by the same grep" || bad "K1's scan control is blind"
    rm -rf "$T"
}
# sym_of <name> -> the symbol the built module holds for that function: the name itself, or its clone
# (gcc's .lto_priv.N, .constprop.N, .isra.N, .part.N, .cold suffixes map to the parent's row); empty when absent
sym_of() {
    nm "$MODULE" | awk -v n="$1" '($2 == "t" || $2 == "T") && ($3 == n || index($3, n ".") == 1) { print $3; exit }'
}
# base_of <symbol> -> the parent name, every clone suffix stripped
base_of() { printf '%s\n' "$1" | sed -E 's/\.(lto_priv|constprop|isra|part)\.[0-9]+//g; s/\.cold$//'; }
# the direct call targets of <symbol>, by name (clone suffixes stripped), one per line
calls_of() {
    objdump -d --no-show-raw-insn "$MODULE" | sed -n "/<$1>:\$/,/^\$/p" | tr '\t' ' ' \
        | grep -oE '(bl|call[a-z]*|jmp[a-z]*|b) +[0-9a-f]+ <[A-Za-z_][A-Za-z0-9_.@]*>' | grep -oE '<[^>]*>' | tr -d '<>' | sort -u
}
# reaches <from> <to>: does <from> reach <to> by direct calls through the module's own text? (depth-first over bl/call targets)
reaches() {
    local from to seen=" " f t
    from=$(sym_of "$1"); to=$2
    local q=("$from")
    while [ ${#q[@]} -gt 0 ]; do
        f=${q[0]}; q=("${q[@]:1}")
        [ -n "$f" ] || continue
        case "$seen" in *" $f "*) continue ;; esac
        seen="$seen$f "
        [ "$(base_of "$f")" = "$to" ] && { echo yes; return; }
        for t in $(calls_of "$f"); do
            [ "$t" = "$f" ] && continue
            case "$t" in *@plt) continue ;; esac
            q+=("$t")
        done
    done
    echo no
}
reach_path() { # the module functions <from> calls, one level, for the message
    calls_of "$(sym_of "$1")" | grep -v '@plt' | tr '\n' ' '
}

# gate_selected <group>: true for every group, or only for those WE_GATE_ONLY names
GATE_GROUPS="run_suite run_walk_rows run_realip_only_rows run_evidence6_rows run_htaccess_rows run_satisfy_rows run_cache_rows run_envnote_rows run_frame_rows run_header_count_rows run_cgi_rows run_graceful_rows run_signal_rows run_q6_rows run_h2_rows run_shard_rows run_asan_rows run_outage_rows run_outage_debug_rows run_m10_control_rows run_pidreuse_rows run_nofold_rows run_slowstop_rows run_baseline_rows run_subblock_race_rows run_final_lock_rows run_mutex_rows run_cloexec_rows run_mlock_rows run_configtest_rows run_strictmodes_rows run_corpus_rows run_binding_rows run_refused_bind_rows run_graceful_refusal_rows run_truncate_rows run_debug_build_rows run_built_object_rows"
gate_selected() { [ -z "${WE_GATE_ONLY:-}" ] && return 0; case " $WE_GATE_ONLY " in *" $1 "*) return 0 ;; esac; return 1; }
# =====================================================================================================
# the run
# =====================================================================================================
rm -rf "$W/logs" "$W/counters" "$W/html"
mkdir -p "$W/logs"
echo "=== apache gate: $("$HTTPD" -v | head -1 | sed 's/Server version: //') ==="
echo "work $W"
echo "module $MODULE"
fresh_snapshot
cp "$W/snapshot.bin" "$W/snapshot.good"
# the common head every rendered corpus configuration gets
{ conf_head event; conf_data; } > "$W/corpus.head"

for g in ${WE_GATE_ONLY:-}; do
    case " $GATE_GROUPS " in *" $g "*) ;; *) echo "APACHE GATE: REFUSED - WE_GATE_ONLY names $g, which is not a group (the groups: $GATE_GROUPS)"; exit 2 ;; esac
done
# every listed group is run: a group named here and never invoked below would read as a pass with its rows
# absent (run_evidence6_rows was, for one run on a test host)
for g in $GATE_GROUPS; do
    [ "$g" = run_suite ] && continue
    grep -qx "gate_selected $g && $g" "$ROOT/apache/apache-gate.sh" \
        || { echo "APACHE GATE: FAILED - the group $g is in GATE_GROUPS and nothing below runs it"; exit 1; }
done
# EVERY MPM this host ships, not just the safe one. The threaded ones are the whole point.
MPMS=""
for m in prefork worker event; do
    [ -f "$MODPATH/mod_mpm_$m.so" ] && MPMS="$MPMS $m"
done
[ -n "$MPMS" ] || { echo "APACHE GATE: FAILED - no MPM modules found under $MODPATH"; exit 1; }
echo "mpms:$MPMS"
THREADED=0
if gate_selected run_suite; then
for m in $MPMS; do
    run_suite "$m"
    [ "$m" != prefork ] && THREADED=1
done
if [ "$THREADED" -eq 0 ]; then
    bad "only prefork was exercised; the threaded MPMs are where a per-thread shard and a module thread beside request threads can go wrong"
fi
case "$MPMS" in *event*) run_floor_suite ;; *) bad "floor suite: the event MPM is not on this host" ;; esac
fi
gate_selected run_walk_rows && run_walk_rows
gate_selected run_realip_only_rows && run_realip_only_rows
gate_selected run_evidence6_rows && run_evidence6_rows
gate_selected run_htaccess_rows && run_htaccess_rows
gate_selected run_satisfy_rows && run_satisfy_rows
gate_selected run_cache_rows && run_cache_rows
gate_selected run_envnote_rows && run_envnote_rows
gate_selected run_frame_rows && run_frame_rows
gate_selected run_header_count_rows && run_header_count_rows
gate_selected run_cgi_rows && run_cgi_rows
gate_selected run_graceful_rows && run_graceful_rows
gate_selected run_signal_rows && run_signal_rows
gate_selected run_q6_rows && run_q6_rows
gate_selected run_h2_rows && run_h2_rows
gate_selected run_shard_rows && run_shard_rows
gate_selected run_asan_rows && run_asan_rows
gate_selected run_outage_rows && run_outage_rows
gate_selected run_outage_debug_rows && run_outage_debug_rows
gate_selected run_m10_control_rows && run_m10_control_rows
gate_selected run_pidreuse_rows && run_pidreuse_rows
gate_selected run_nofold_rows && run_nofold_rows
gate_selected run_slowstop_rows && run_slowstop_rows
gate_selected run_baseline_rows && run_baseline_rows
gate_selected run_subblock_race_rows && run_subblock_race_rows
gate_selected run_final_lock_rows && run_final_lock_rows
gate_selected run_mutex_rows && run_mutex_rows
gate_selected run_cloexec_rows && run_cloexec_rows
gate_selected run_mlock_rows && run_mlock_rows
gate_selected run_configtest_rows && run_configtest_rows
gate_selected run_strictmodes_rows && run_strictmodes_rows
gate_selected run_corpus_rows && run_corpus_rows
gate_selected run_binding_rows && run_binding_rows
gate_selected run_refused_bind_rows && run_refused_bind_rows
gate_selected run_graceful_refusal_rows && run_graceful_refusal_rows
gate_selected run_truncate_rows && run_truncate_rows
gate_selected run_debug_build_rows && run_debug_build_rows
gate_selected run_built_object_rows && run_built_object_rows

#
# THE PAGE MUST AGREE WITH THIS RUN. README.md prints this exact line as a transcript, and a number typed
# into prose goes stale on the edit that changes it and nothing notices. So the gate compares.
#
README="$ROOT/README.md"
if [ -z "${WE_GATE_ONLY:-}" ] && [ "$FAILED" = 0 ] && [ -f "$README" ] && grep -q '=== apache gate: ' "$README"; then
    want="=== apache gate: $PASS ok, 0 failed ==="
    if ! grep -qF "$want" "$README"; then
        printf '  FAIL  README.md says "%s" and this run is "%s"\n' \
            "$(grep -o '=== apache gate: [0-9]* ok, [0-9]* failed ===' "$README" | head -1)" "$want"
        FAILED=$((FAILED+1))
    else
        printf '  ok    README.md prints this run'"'"'s own count, so the page cannot go stale unnoticed\n'
    fi
fi

if [ -n "${WE_GATE_ONLY:-}" ]; then
    echo "=== apache gate (partial, only: $WE_GATE_ONLY): $PASS ok, $FAILED failed ==="
else
    echo "=== apache gate: $PASS ok, $FAILED failed ==="
fi
[ "$DARK" = 0 ] || echo "=== $DARK row(s) dark by name, waiting on the core (listed above) ==="
if [ "$FAILED" -ne 0 ]; then
    echo "--- error log tail ---"; tail -25 "$W/logs/error.log" 2>/dev/null | cut -c1-300 | sed 's/^/        /'
    echo "APACHE GATE: FAILED"; exit 1
fi
[ -n "${WE_GATE_ONLY:-}" ] && { echo "APACHE GATE: PARTIAL - only $WE_GATE_ONLY ran, 0 failed; not a walk"; exit 0; }
echo "APACHE GATE: CLEAR - $("$HTTPD" -v | head -1 | sed 's/Server version: //') held every property under$MPMS"
