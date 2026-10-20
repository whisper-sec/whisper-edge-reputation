#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# nginx-gate.sh - run the module inside a real nginx and assert the properties that matter.
#
# The module runs inside somebody else's web server, so the properties that matter are not about the
# lookup but about the lifecycle around it. Two in particular, both of which this catches:
#
#   - a refresh timer that is not cancelable makes `nginx -s reload` and `nginx -s stop` hang forever,
#     stacking a dead worker per reload, and it fires on the FIRST reload an installation performs.
#   - a snapshot rewritten in place - which is what `curl -o` and `cp` do - must not kill a worker.
#
# The most important assertion here is not either of those. It is DRY RUN IS THE DEFAULT: with no mode
# directive at all, a request from a listed address must get a 200. That is the promise the whole
# product rests on and the one a future refactor is most likely to invert.
#
# THE POLICY LANGUAGE ROWS (the second half) run the module's compiler inside `nginx -t`: the
# independent corpus (twenty programs that must compile, fifty that must be refused with a named
# refusal), the places a directive may be written, the argument forms, the deny-status list and the
# threshold sugar. Every row is `nginx -t` over a rendered configuration, read back from what the
# module printed; nothing is asserted from this script's own idea of the grammar.
set -euo pipefail
# the configurations this gate writes define the http level, and the module refuses one that is open to
# group or world; the planes it writes are read the same way
umask 022

cd "$(dirname "$0")"
# ROOT is the EDGE TREE's own root, one level up from this script, NOT two.
#
# Two levels up is the monorepo root in our tree and the PARENT OF THE CLONE in the published
# repository, so `$ROOT/...` resolved to a path outside the checkout: the work directory was
# created beside the clone, and the build instruction this script prints named a module directory that
# does not exist. One level up with no `edge/` prefix is correct in BOTH layouts, which is the point.
ROOT=$(cd .. && pwd)
# THE GATE'S OWN PORT RANGE. The three module gates run on one box in the merge candidate's walk, so each
# binds a range of its own: Apache's gate uses 8099 and 8599, LiteSpeed's 8120 and up, and this gate
# 8300 and 8301 (the origin, and the caching front the wire rows put before it). PORT=<n> moves the
# pair together. A port another process holds is refused by cause before any row runs: a row failing
# downstream of a bind that never happened reads as the module's fault, and it is not.
PORT=${PORT:-8300}
PORT2=$((PORT + 1))
port_holder() { # <port> -> who listens on 127.0.0.1:<port> (empty when nobody)
    ss -Hltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:((\("[^"]*"\),pid=\([0-9]*\).*/\1 pid \2/p; t; s/^LISTEN.*/a process this user cannot name (another uid)/p' | sed -n 1p
}
for p in "$PORT" "$PORT2"; do
    holder=$(port_holder "$p")
    if [ -n "$holder" ]; then
        echo "NGINX GATE: FAILED - 127.0.0.1:$p is held by $holder; this gate binds $PORT and $PORT2 (PORT=<n> moves the pair)"
        exit 1
    fi
done
# THE LISTED CLIENT IS JUDGED PAST A HOP. The fixed exemptions (the hold-harmless table) exempt every
# special-purpose address, loopback and the benchmarking space included, when the floor address is eligible
# for them, so a listed loopback peer is never denied. The gate therefore configures what a CDN deployment
# configures: a trusted proxy (the loopback peer), the X-Forwarded-For header and trusted_hops 2, and every
# client arrives as the second entry of a line whose rightmost entry is the balancer's own, judged with no
# exemption, because an address reached past a hop never gets one. The fixture lists 198.18.0.0/24
# (RFC 2544 benchmarking space, made for test setups and never routed) at HIGH; 198.18.0.5 is the listed
# client, 198.18.1.7 the unlisted twin and 198.19.0.1 the balancer's own entry. The same addresses on every
# server's gate, so the cross-server differential compares like with like.
RANGE_START=3323068416; RANGE_END=3323068671
LISTED=198.18.0.5; UNLISTED=198.18.1.7; HOP=198.19.0.1
MODULE="${MODULE:-}"

command -v nginx >/dev/null || { echo "NGINX GATE: FAILED - nginx is not installed"; exit 1; }
command -v python3 >/dev/null || { echo "NGINX GATE: FAILED - python3 is not installed (the fixtures are written with it)"; exit 1; }

# THE MODULE UNDER TEST IS THIS TREE'S. With no MODULE the gate builds it from this tree through build.sh,
# keeping the configured tree for the control builds. A MODULE given is held to two checks before any row
# runs: it was built from THIS tree's source (the object names that source file by its path), and it is
# not older than any source it compiles. The gate once took the first .so a find of /tmp listed, which on
# a shared box can be another tree's or a build from before the last rebase, and every row would then
# measure the wrong object while reading green.
MODSRC="$ROOT/nginx/ngx_http_whisper_edge_module.c"
# module_is_this_trees <object> -> nothing when it is, the reason when it is not
module_is_this_trees() {
    local so=$1 newer
    [ -f "$so" ] || { echo "it does not exist"; return; }
    grep -q -a -F "$MODSRC" "$so" || { echo "it was not built from this tree (it does not name $MODSRC)"; return; }
    newer=$(find "$ROOT/nginx" "$ROOT/core" -maxdepth 1 \( -name '*.c' -o -name '*.h' -o -name config \) -newer "$so" -print 2>/dev/null | sed -n 1p)
    [ -z "$newer" ] || echo "it is older than its source ($newer is newer)"
}
if [ -z "$MODULE" ]; then
    echo "module: none given, building this tree's with build.sh"
    if ! out=$(cd "$ROOT/nginx" && ./build.sh --keep 2>&1); then
        echo "NGINX GATE: FAILED - this tree's module does not build: $(printf '%s\n' "$out" | tail -3 | tr '\n' ' ')"
        exit 1
    fi
    NGX_BUILD=$(sed -n 's/.* -> \(\/.*\)$/\1/p' <<<"$out" | sed -n 1p)
    MODULE="$NGX_BUILD/objs/ngx_http_whisper_edge_module.so"
    GATE_BUILT_TREE=$NGX_BUILD
fi
why=$(module_is_this_trees "$MODULE")
if [ -n "$why" ]; then
    echo "NGINX GATE: FAILED - the module $MODULE is not this tree's current build: $why. Leave MODULE unset and the gate builds it, or rebuild with nginx/build.sh --keep and pass <tree>/objs/ngx_http_whisper_edge_module.so"
    exit 1
fi
#
# CONTROL BUILDS. Some rows need a module built with one defect planted (a -D control the core refuses
# outside a control build). They are built from the configured nginx tree the module came out of
# (`<tree>/objs/ngx_http_whisper_edge_module.so`, as build.sh and the CI job lay it out), or from
# NGX_BUILD; with neither the arm is NOT PROVEN by name, never a pass and never silently skipped. The
# module's own objects are removed before each build, so a control never links the production objects
# and the production module is rebuilt from clean objects afterwards.
#
BUILD_TREE="${NGX_BUILD:-}"
if [ -z "$BUILD_TREE" ] && [ "$(basename "$(dirname "$MODULE")")" = objs ] && [ -f "$(dirname "$MODULE")/Makefile" ]; then
    BUILD_TREE=$(cd "$(dirname "$MODULE")/.." && pwd)
fi
NOT_PROVEN=0
notproven() { NOT_PROVEN=$((NOT_PROVEN+1)); printf '  NOT PROVEN  %s\n' "$1"; }
# build_control <defines...>: builds the module with the defines and leaves its path in CTL_OUT;
# on failure leaves why in CTL_WHY (no tree: the arm is NOT PROVEN; a build error: the arm FAILS).
# It must be called DIRECTLY, not in a command substitution: a substitution runs it in a subshell,
# where no assignment it makes can reach the caller, and the reason arrived here empty for as long
# as this was written as ctl=$(build_control ...).
CTL_WHY=""
build_control() {
    local out tag
    CTL_WHY=""
    CTL_OUT=""
    if [ -z "$BUILD_TREE" ] || [ ! -f "$BUILD_TREE/objs/Makefile" ]; then
        CTL_WHY="no configured nginx tree to build a control module (set NGX_BUILD, or run with the module built in <tree>/objs)"
        return 1
    fi
    tag=$(printf '%s' "$*" | tr -c 'A-Za-z0-9' '_')
    out="$W/ctl/module$tag.so"
    mkdir -p "$W/ctl"
    if [ ! -f "$out" ]; then
        local cflags
        cflags=$(sed -n 's/^CFLAGS *= *//p' "$BUILD_TREE/objs/Makefile" | sed -n 1p)
        rm -f "$BUILD_TREE"/objs/addon/*/*.o
        if ! ( cd "$BUILD_TREE" && make -f objs/Makefile CFLAGS="$cflags -DWE_MOD_CONTROL_BUILD $*" objs/ngx_http_whisper_edge_module.so ) >"$W/ctl/make$tag.log" 2>&1; then
            CTL_WHY="the control module ($*) does not build: $(grep -m1 -E 'error:|Error [0-9]|No rule' "$W/ctl/make$tag.log" | cut -c1-200)"
            return 1
        fi
        cp "$BUILD_TREE/objs/ngx_http_whisper_edge_module.so" "$out"
        # the production module back, from clean objects
        rm -f "$BUILD_TREE"/objs/addon/*/*.o
        if ! ( cd "$BUILD_TREE" && make -f objs/Makefile objs/ngx_http_whisper_edge_module.so ) >"$W/ctl/make-production.log" 2>&1; then
            CTL_WHY="the production module does not rebuild after the control: $(grep -m1 -E 'error:|Error [0-9]|No rule' "$W/ctl/make-production.log" | cut -c1-200)"
            return 1
        fi
    fi
    CTL_OUT=$out
    return 0
}
# control_unavailable <arm>: the arm's outcome when its control module could not be made
control_unavailable() {
    case "$CTL_WHY" in
        "no configured nginx tree"*) notproven "$1: $CTL_WHY" ;;
        *) bad "$1: $CTL_WHY" ;;
    esac
}

#
# The summary assertions need the summary tool, and it is built here rather than assumed: a gate that skips its own
# assertions when a binary is missing is a gate that quietly stops checking the thing it was written
# for. The tool links nothing, so this is one compile.
#
# Always through make, which rebuilds when a source is newer: a binary kept because it exists outlives the
# core it was built from, and a rebase onto a new reader then measures the old one.
SUMMARY_BIN="$ROOT/core/whisper-edge-summary"
# summary_total <counters dir>: the headline's total, read by the headline's own grammar ("  N request(s)
# denied", the line the summary prints first under the window); nothing when the line is not there, so a
# changed headline fails the row that reads it by name, never a number taken from another line
summary_total() { "$SUMMARY_BIN" "$1" 2>/dev/null | sed -n -E 's/^  ([0-9]+) requests? denied$/\1/p'; }
make -C "$ROOT/core" whisper-edge-summary whisper-edge-lookup >/dev/null \
    || { echo "NGINX GATE: FAILED - cannot build whisper-edge-summary and whisper-edge-lookup"; exit 1; }

#
# THE WORK DIRECTORY MUST BE TRUSTED. A plane the module binds through whisper_edge_data is accepted
# only when every directory from / down to it is owned by root or by the worker uid and is closed to
# group and world, with no exception for a sticky /tmp (a world-writable ancestor lets anyone put a
# directory of the plane's name in the way). So the fixtures cannot live under /tmp, and a checkout
# under a group-writable home cannot hold them either. The default work directory is tried first and,
# where its chain fails the rule, the user's runtime directory is used, the way test_module chooses its
# base; which one was taken is printed, and a host with neither fails here rather than later and
# obscurely.
#
trusted_chain() { # dir -> 0 when every directory from / down to it is root- or self-owned and closed to group and world
    local p=$1 o m
    [ -d "$p" ] || return 1
    while :; do
        o=$(stat -c %u "$p"); m=$(stat -c %a "$p")
        { [ "$o" = 0 ] || [ "$o" = "$(id -u)" ]; } || return 1
        (( (0$m & 022) == 0 )) || return 1
        [ "$p" = / ] && return 0
        p=$(dirname "$p")
    done
}
pick_work_dir() { # candidate -> prints a directory whose parent chain is trusted, creating it
    local c
    for c in "$@"; do
        [ -n "$c" ] || continue
        mkdir -p "$c" 2>/dev/null || continue
        chmod 0755 "$c"
        if trusted_chain "$c"; then printf '%s' "$c"; return 0; fi
    done
    return 1
}
W_WANT="${1:-$ROOT/core/.testtmp/nginx}"
RUNDIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if ! W=$(pick_work_dir "$W_WANT" "$RUNDIR/whisper-edge-nginx-gate.$$" "$HOME/.whisper-edge-nginx-gate.$$"); then
    echo "NGINX GATE: FAILED - no work directory whose chain is trusted (root- or self-owned, closed to group and world): tried $W_WANT, $RUNDIR, $HOME"
    exit 1
fi
# a previous run that died inside a root-setup arm (the data-chain rows) can leave root-owned entries behind, which rm as the
# gate's own user cannot remove; say so rather than die silently under set -e
if ! rm -rf "$W" 2>/dev/null; then
    sudo -n rm -rf "$W" 2>/dev/null || { echo "NGINX GATE: FAILED - cannot remove the previous work directory $W (root-owned leftovers and no sudo)"; exit 1; }
fi
mkdir -p "$W/logs" "$W/html/enforced" "$W/html/default" "$W/html/g3a" "$W/html/g3b" "$W/html/g3p/c" "$W/t"
chmod 0755 "$W"
W=$(cd "$W" && pwd)
[ "$W" = "$W_WANT" ] || echo "work directory: $W_WANT's chain is not trusted, using $W"
echo "work $W"
echo "module $MODULE"
for d in . enforced default g3a g3b g3p g3p/c; do echo "page" > "$W/html/$d/index.html"; done
. "$ROOT/policy-rows.sh"

# A snapshot that lists 198.18.0.0/24 at HIGH (generation 1, no validity bound): the listed client above
# is denied wherever the mode is deny, and its unlisted twin never is.
python3 ../core/make-test-snapshot.py "$W/snapshot.bin" 1 0 3 "$RANGE_START" "$RANGE_END"
cp "$W/snapshot.bin" "$W/snapshot.good"
chmod 0644 "$W/snapshot.good"

# mkconf <refresh-value> [extra http directives...]; DATA_DIR=<dir> in the environment binds the planes through
# whisper_edge_data instead of the snapshot line, SNAPSHOT_PATH=<file> names another snapshot, MAIN_EXTRA=<lines>
# adds main-level directives (a second error_log)
#
# The refresh value is a PARAMETER rather than appended, because appending produced a second
# whisper_edge_refresh and nginx rejects a duplicate directive outright - so the floor test was
# reading a config nginx had refused and concluding the clamp did not fire. The clamp was fine.
mkconf() {
    local refresh=$1; shift
cat > "$W/nginx.conf" <<EOF
load_module $MODULE;
worker_processes 2;
error_log $W/logs/error.log info;
pid $W/logs/nginx.pid;
${MAIN_EXTRA:-}
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $W/logs/body;
    proxy_temp_path $W/logs/proxy;
    fastcgi_temp_path $W/logs/fastcgi;
    uwsgi_temp_path $W/logs/uwsgi;
    scgi_temp_path $W/logs/scgi;
    # a cache path makes nginx run its cache manager and loader, helper processes that run every module's
    # init_process and must start no thread and write no file (row Q3)
    proxy_cache_path $W/cache keys_zone=gate:1m;
    $( [ -n "${DATA_DIR:-}" ] && echo "whisper_edge_data $DATA_DIR;" || echo "whisper_edge_snapshot ${SNAPSHOT_PATH:-$W/snapshot.bin};" )
    whisper_edge_refresh $refresh;
    whisper_edge_trusted_proxy 127.0.0.1;
    whisper_edge_trusted_header X-Forwarded-For;
    whisper_edge_trusted_hops 2;
    # the balancer's reading, for the context's address: realip takes the same entry the module's walk takes
    set_real_ip_from 127.0.0.1;
    set_real_ip_from $HOP;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    $*
    server {
        listen 127.0.0.1:$PORT;
        root $W/html;
        location / { }
        location /enforced/ { whisper_edge_mode deny; }
        # the policy rows' contexts, each level at a threshold of its own so a program number names its
        # level: the server at the default (high), one threshold (low) under two modes, a parent at
        # medium with a child that writes no threshold line. A high listing is denied at all three.
        location /g3a/ { whisper_edge_threshold low; whisper_edge_mode log; }
        location /g3b/ { whisper_edge_threshold low; whisper_edge_mode deny; }
        location /g3p/ {
            whisper_edge_threshold medium;
            whisper_edge_mode deny;
            location /g3p/c/ { whisper_edge_mode log; }
        }
        ${SERVER_EXTRA:-}
    }
}
EOF
}

# the master's configuration-time lines go to stderr (the error log is not open while it parses), so
# they are kept per start for the policy rows
# A start that fails says why before the exit trap removes the work directory: a port another test server
# holds (PORT=<n> picks another) is the usual reason, and a gate that only stops is one nobody can act on.
# A CONTROL FAILS BY VALUE, NEVER BY A CRASH. A control build is one defect planted, and the row it
# proves must fail on the value the defect produces; a worker killed by a signal proves only that the
# control crashes. So every server started on a control module ($W/ctl/) is watched from its start to its
# stop, and any "exited on signal" in the error log in between is recorded against it; one row at the end
# names every such control and the exemptions below.
#
# THE EXEMPTIONS, by define, one reason each. Only a control whose row's measured failure IS a worker's
# death by a signal belongs here, and the arm that runs it also asserts the release build has none.
CTL_SIGNAL_EXEMPT=(
    "WE_MOD_TEST_NO_START_STAT:the plane truncated in place is served without the worker-start check, and the SIGBUS that kills each worker is what the M3 row measures"
    "WE_MOD_TEST_SERVE_INHERITED:the inherited mapping of a plane truncated in place is served, and the SIGBUS that kills each worker is what the M3 row measures"
)
CTL_RUN=""; CTL_OFF=0; CTL_CHECKED=0; CTL_CRASHED=""; CTL_EXEMPTED=""
# the workers the gate kills itself (kill -9, the M3 sequence): their signal 9 is the gate's, not a crash
GATE_KILLED=""
ctl_exempt() { # <control tag>: the exempt define it carries, or nothing
    local e
    for e in "${CTL_SIGNAL_EXEMPT[@]}"; do
        case "$1" in *"${e%%:*}"*) echo "${e%%:*}"; return 0 ;; esac
    done
    return 0
}
ctl_signal_deaths() { # the signal deaths in the error log since the control's start
    local size; size=$(stat -c %s "$W/logs/error.log" 2>/dev/null || echo 0)
    [ "$size" -lt "$CTL_OFF" ] && CTL_OFF=0   # truncated since: all of it is the control's
    local own='^$' p
    for p in $GATE_KILLED; do own="$own|worker process $p exited on signal 9( |$)"; done
    tail -c +"$((CTL_OFF + 1))" "$W/logs/error.log" 2>/dev/null | grep 'exited on signal' | grep -c -v -E "$own" || true
}
start() {
    if ! nginx -c "$W/nginx.conf" -p "$W" 2>"$W/logs/start.err"; then
        echo "nginx did not start (is 127.0.0.1:$PORT free? PORT=<n> picks another port):" >&2
        cut -c1-300 "$W/logs/start.err" >&2
        return 1
    fi
    CTL_RUN=""
    local first; first=$(sed -n 1p "$W/nginx.conf")
    if [[ $first == "load_module $W/ctl/"* ]]; then
        CTL_RUN=$(sed 's#.*/ctl/module##; s#\.so;$##' <<<"$first")
        CTL_OFF=0                                # the control's server: everything logged since its start counts
        [ -f "$W/logs/error.log" ] && CTL_OFF=$(stat -c %s "$W/logs/error.log")
    fi
    return 0
}
stop()  {
    if [ -n "$CTL_RUN" ]; then
        local d; d=$(ctl_signal_deaths)
        CTL_CHECKED=$((CTL_CHECKED + 1))
        if [ "$d" != 0 ]; then
            local ex; ex=$(ctl_exempt "$CTL_RUN")
            if [ -n "$ex" ]; then CTL_EXEMPTED="$CTL_EXEMPTED $ex($d)"; else CTL_CRASHED="$CTL_CRASHED $CTL_RUN($d)"; fi
        fi
        CTL_RUN=""
    fi
    [ -f "$W/logs/nginx.pid" ] && nginx -s quit -c "$W/nginx.conf" -p "$W" 2>/dev/null || true
}
# signal_master <reload|reopen>: the signal process re-reads the configuration and prints its lines to stderr,
# which are kept in a file rather than mixed into the gate's own output; a refused signal fails loudly
signal_master() { nginx -s "$1" -c "$W/nginx.conf" -p "$W" 2>"$W/logs/signal.err" || bad "nginx -s $1 failed: $(grep -m1 -E 'emerg|error' "$W/logs/signal.err" | cut -c1-200)"; }
# The exit path reads the master's pid BEFORE asking it to quit. nginx removes its pid file as it
# quits, so a trap that re-reads the file afterwards finds nothing left to kill, and a master whose
# worker hangs in the way the first property above describes stays behind, listening on nothing: one
# from an interrupted run of this gate was found still alive two days later. The workers are listed
# before the master goes, because a worker does not always follow its master out.
cleanup() {
  master=""; [ -f "$W/logs/nginx.pid" ] && master="$(cat "$W/logs/nginx.pid" 2>/dev/null)"
  workers=""; [ -n "$master" ] && workers="$(pgrep -P "$master" 2>/dev/null | tr '\n' ' ')"
  stop; sleep 1
  # shellcheck disable=SC2086
  if [ -n "$master" ]; then kill -9 $master $workers 2>/dev/null || true; fi
  [ -n "${GATE_BUILT_TREE:-}" ] && rm -rf "$GATE_BUILT_TREE"
  # the root-run arm's server and its root-owned directory, if the walk ended inside it
  if [ -n "${GATE_ROOT_DIR:-}" ]; then
    sudo -n nginx -s quit -c "$GATE_ROOT_DIR/nginx.conf" -p "$GATE_ROOT_DIR" 2>/dev/null || true
    sleep 1; sudo -n rm -rf "$GATE_ROOT_DIR" 2>/dev/null || true
  fi
  return 0
}
trap cleanup EXIT

# the client: X-Forwarded-For "<client>, <hop>", judged at hop 2; code() is the listed client's request
xff() { printf 'X-Forwarded-For: %s, %s' "${1:-$LISTED}" "$HOP"; }
code()      { curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT$1"; }
code_as()   { curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "$(xff "$2")" "http://127.0.0.1:$PORT$1"; }
code_nohdr(){ curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT$1"; }
headers()   { curl -s -o /dev/null -D - --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT$1"; }
workers() { pgrep -P "$(cat "$W/logs/nginx.pid")" 2>/dev/null | sort | tr '\n' ' '; }

PASS=0; FAILED=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAILED=$((FAILED+1)); printf '  FAIL  %s\n' "$1"; }

await() { # predicate deadline-seconds description
    for _ in $(seq 1 $(( $2 * 4 ))); do
        if eval "$1"; then return 0; fi
        sleep 0.25
    done
    return 1
}

mkconf 1s
nginx -t -c "$W/nginx.conf" -p "$W" >/dev/null 2>&1 || { echo "NGINX GATE: FAILED - config invalid"; nginx -t -c "$W/nginx.conf" -p "$W"; exit 1; }
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "startup" || { echo "NGINX GATE: FAILED - nginx did not come up"; tail -20 "$W/logs/error.log"; exit 1; }

echo "$(date -u +%H:%M:%S) == the promise the product rests on: DRY RUN IS THE DEFAULT =="
# No whisper_edge_mode directive anywhere, and a snapshot that denies this client.
[ "$(code /)" = 200 ] && ok "no mode directive + a snapshot that lists the client -> 200" \
    || bad "a request from a LISTED address was blocked with no mode directive: $(code /)"
await 'grep -q "WOULD DENY" "$W/logs/error.log"' 5 "would-deny line" \
    && ok "and the would-deny line is written, so an operator can see what it would have done" \
    || bad "no WOULD DENY line: the default mode is silent, which is useless"
# The evidence is the answer to "why did you block me?". It was implemented, tested, carried in every
# snapshot and reached NOBODY, because no shim called it.
EVIDENCE=$(python3 ../core/make-test-snapshot.py --evidence)
grep -q "evidence $EVIDENCE" "$W/logs/error.log" \
    && ok "and it carries the CITABLE EVIDENCE from the snapshot, not just a severity" \
    || bad "the log line carries no evidence, so the feed cannot explain itself"
[ "$(code /enforced/)" = 403 ] && ok "and an explicit deny location DOES block -> 403" \
    || bad "deny mode did not block: $(code /enforced/)"
[ "$(code_as /enforced/ "$UNLISTED")" = 200 ] && ok "while the unlisted twin ($UNLISTED) passes the same location -> 200" \
    || bad "the unlisted client was blocked: $(code_as /enforced/ "$UNLISTED")"
# the loopback peer with no header is judged itself and sits in the fixed exemptions: never denied
[ "$(code_nohdr /enforced/)" = 200 ] && ok "and the trusted peer sending no header is judged itself (loopback, exempt) -> 200" \
    || bad "the loopback peer with no header was blocked: $(code_nohdr /enforced/)"
# a deny depends on the client's address, which no cache keys on, so every deny says no-store
denyhdrs=$(headers /enforced/)
if grep -qi '^Cache-Control: no-store' <<<"$denyhdrs"; then
    ok "and the deny carries Cache-Control: no-store"
else
    bad "the deny carries no Cache-Control: no-store: $(tr '\r\n' '  ' <<<"$denyhdrs")"
fi

echo
echo "$(date -u +%H:%M:%S) == the module's thread and its descriptors (Q2, Q3, Q4) =="
# Q3: the cache manager and loader run every module's init_process and leave by exit(0); only the workers
# get the module's thread, so exactly worker_processes children have two tasks and the helpers one
master=$(cat "$W/logs/nginx.pid")
two=0; helpers=0; helper_threaded=0
for p in $(pgrep -P "$master"); do
    n=$(ls "/proc/$p/task" 2>/dev/null | wc -l)
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    if [[ $cmd == *cache* ]]; then
        helpers=$((helpers + 1)); [ "$n" -gt 1 ] && helper_threaded=$((helper_threaded + 1))
    elif [ "$n" = 2 ]; then
        two=$((two + 1))
    fi
done
if [ "$two" = 2 ] && [ "$helper_threaded" = 0 ]; then
    ok "Q3: exactly the 2 workers carry the module's thread; the $helpers cache helper(s) carry none"
else
    bad "Q3: $two worker(s) with two tasks (2 expected), $helper_threaded of $helpers cache helper(s) threaded (0 expected)"
fi
# Q2: the thread's signal mask: every asynchronous signal blocked, the four synchronous ones (ILL, BUS, FPE,
# SEGV) left clear so a fault in the thread is reported as one; read from the thread's own status
read -ra ws <<<"$(workers)"
q2=0; q2n=0
for p in "${ws[@]}"; do
    for t in "/proc/$p/task"/*; do
        [ "$(basename "$t")" = "$p" ] && continue
        q2n=$((q2n + 1))
        blk=$(sed -n 's/^SigBlk:\s*//p' "$t/status")
        # bit n-1 for signal n: HUP 1, INT 2, USR1 10, ALRM 14, TERM 15, CHLD 17, WINCH 28, IO 29 blocked; ILL 4, BUS 7, FPE 8, SEGV 11 clear
        if python3 -c '
import sys
m = int(sys.argv[1], 16)
want = all((m >> (n - 1)) & 1 for n in (1, 2, 10, 14, 15, 17, 28, 29)) and not any((m >> (n - 1)) & 1 for n in (4, 7, 8, 11))
sys.exit(0 if want else 1)' "$blk"; then q2=$((q2 + 1)); else echo "        worker $p thread $(basename "$t") SigBlk $blk"; fi
    done
done
if [ "$q2n" = 2 ] && [ "$q2" = 2 ]; then
    ok "Q2: both threads block every asynchronous signal (HUP, INT, USR1, ALRM, TERM, CHLD, WINCH, IO) and leave ILL, BUS, FPE and SEGV clear"
else
    bad "Q2: $q2 of $q2n module threads carry the expected signal mask"
fi
q4_check() {
# q4_check <label> <master pid> <worker pids...>: close-on-exec on every descriptor the module holds: its eventfd, and every descriptor on the work
# directory outside nginx's own logs (the snapshot's directory, the counters directory)
local label=$1 master=$2 q4bad="" cloexec_evfd=0 p fd tgt flags
shift 2
q4bad=""
for p in $master "$@"; do
    for fd in /proc/$p/fd/*; do
        tgt=$(readlink "$fd" 2>/dev/null) || continue
        case "$tgt" in
            "$W"/logs/*|"$W"/cache*) continue ;;
            "$W"|"$W"/*) ;;
            *) continue ;;
        esac
        flags=$(sed -n 's/^flags:\s*//p' "/proc/$p/fdinfo/$(basename "$fd")")
        (( (8#$flags & 8#2000000) != 0 )) || q4bad="$q4bad $p:$(basename "$fd")->$tgt"
    done
done
cloexec_evfd=0
for p in "$@"; do
    for fd in /proc/$p/fd/*; do
        [ "$(readlink "$fd" 2>/dev/null)" = "anon_inode:[eventfd]" ] || continue
        flags=$(sed -n 's/^flags:\s*//p' "/proc/$p/fdinfo/$(basename "$fd")")
        (( (8#$flags & 8#2000000) != 0 )) && cloexec_evfd=$((cloexec_evfd + 1))
    done
done
if [ -z "$q4bad" ] && [ "$cloexec_evfd" -ge 2 ]; then
    ok "Q4$label: every descriptor the module holds on the work directory is close-on-exec, and each worker's wake eventfd is too"
else
    bad "Q4$label: descriptors without close-on-exec:${q4bad:- none}; close-on-exec eventfds across the 2 workers: $cloexec_evfd (2 expected)"
fi
}
q4_check "" "$master" "${ws[@]}"

echo
echo "$(date -u +%H:%M:%S) == the summary an operator pastes into a chat =="
#
# This is the viral requirement as a test. The claim is that the module produces a usable weekly
# report with no console and no account, so the gate drives real requests through a real nginx and
# then reads what the REAL tool prints. Nothing here is a structural check: the assertions are on the
# numbers in the artifact.
#
# whisper_edge_summary is NOT set in this config, so this also proves the zero-configuration case:
# the directory is derived from the snapshot path and created on first write.
SUMMARY_DIR="$W/counters"
for _ in 1 2 3 4 5 6 7; do code /enforced/ >/dev/null; done
#
# Wait for a COUNT, not for a file. The first file appears within milliseconds of startup carrying
# `denied 0`, because the module writes on every refresh tick including the one at init - so a gate
# that waited for the file read a zero-count snapshot of the truth and failed on everything after.
# The condition to wait for is the one the assertions depend on.
#
await 'grep -qE "^denied [1-9]" "$SUMMARY_DIR"/*.cnt 2>/dev/null' 10 "counted denials" \
    && ok "the counters directory was derived from the snapshot path and written with no configuration" \
    || bad "no counted denial in $SUMMARY_DIR after 7 blocked requests: $(cat "$SUMMARY_DIR"/*.cnt 2>/dev/null | tr '\n' '|')"

if [ -n "$(ls "$SUMMARY_DIR"/*.cnt 2>/dev/null)" ]; then
    # The file must carry the PREFIX and the evidence, not a range index: an index is meaningless
    # after the next build, and the whole point of the line is that it explains itself.
    # grep reads the files itself. `cat files | grep -q` is wrong under pipefail: grep exits at the
    # first match, cat's next write dies of SIGPIPE, and the pipeline fails on a line that matched.
    # This row failed exactly that way with two workers' files, the first of which matched.
    if grep -qhE '^4 198\.18\.0\.[0-9]+(/[0-9]+)?(-[0-9.]+)? [0-9]+ [0-9]+ .' "$SUMMARY_DIR"/*.cnt; then
        ok "and the line carries the prefix, the severity, the count and the evidence"
    else
        bad "the counter line is not in the documented shape: $(cat "$SUMMARY_DIR"/*.cnt | tr '\n' '|')"
    fi

    # BOTH workers must appear. All of them start at the same instant and find the counters
    # directory missing, so all but one gets EEXIST when it creates it - and treating that as a
    # failure made every other worker permanently silent. The summary then reported a fraction of
    # the denials under "across 1 worker process", which reads exactly like a working report. This
    # is the assertion that catches it.
    await '[ "$(ls "$SUMMARY_DIR"/*.cnt 2>/dev/null | wc -l)" -ge 2 ]' 10 "both workers" \
        && ok "every worker writes its own file, so no worker is silently dropped from the total" \
        || bad "only $(ls "$SUMMARY_DIR"/*.cnt 2>/dev/null | wc -l) worker file(s): the rest are not counted"

    # the files lag the counts by up to one tick (the thread writes them, the loop counts), so BEFORE is
    # read only once two reads a tick apart agree: a BEFORE read mid-flush turned exactly five into twelve
    headline() { summary_total "$SUMMARY_DIR"; }
    BEFORE=$(headline); for _ in 1 2 3 4 5 6 7 8; do sleep 1.1; now=$(headline); [ "$now" = "$BEFORE" ] && break; BEFORE=$now; done
    for _ in 1 2 3 4 5; do code /enforced/ >/dev/null; done
    await '[ "$(headline)" -ge $(( BEFORE + 5 )) ]' 10 "the delta" && DELTA_OK=1 || DELTA_OK=0
    AFTER=$(headline)
    # A DELTA rather than an absolute, because every earlier section of this gate also sent requests
    # from this address and they are counted too - as they should be. The property is that five more
    # blocked requests move the headline by exactly five, summed across workers.
    if [ "$DELTA_OK" = 1 ] && [ "$AFTER" = "$(( BEFORE + 5 ))" ]; then
        ok "five more blocked requests move the headline by exactly five ($BEFORE -> $AFTER)"
    else
        bad "the headline moved $BEFORE -> $AFTER for five blocked requests"
    fi
    SUMMARY=$("$SUMMARY_BIN" "$SUMMARY_DIR" 2>&1 || true)
    grep -qE '^  from 1 network$' <<<"$SUMMARY" \
        && ok "from 1 network, counted rather than estimated" \
        || bad "wrong network count: $(printf '%s' "$SUMMARY" | grep 'network' | tr '\n' '|')"
    grep -q "$EVIDENCE" <<<"$SUMMARY" \
        && ok "and the worst offender carries its one line of evidence" \
        || bad "the summary names a network with no evidence, which is the half nobody can act on"
    # The window is STATED, never rounded up to a week. A freshly started nginx has counted for
    # seconds, so the report must say minutes - not "this week".
    grep -qE '^Whisper edge, (under a minute|[0-9]+ (minute|hour|day)s?[,]?( [0-9]+ (minute|hour)s?)?) of blocking$' <<<"$SUMMARY" \
        && ok "and the window is the one actually counted, not the word week" \
        || bad "the window line is wrong: $(printf '%s' "$SUMMARY" | head -1)"
    grep -q 'counted on this host' <<<"$SUMMARY" \
        && ok "and it says plainly that nothing left the machine to produce it" \
        || bad "the report does not state that it is local-only, which is the reason it is installable"
fi

# An empty directory must say so rather than report a zero. "I blocked nothing" and "I cannot find
# your counters" are different sentences and an operator is entitled to tell them apart.
EMPTY_DIR="$W/counters-empty"
mkdir -p "$EMPTY_DIR"
if grep -q 'No Whisper edge counters' <<<"$("$SUMMARY_BIN" "$EMPTY_DIR")"; then
    ok "an empty directory reports that it is empty, not that nothing was blocked"
else
    bad "an empty counters directory reads as a zero-denial week"
fi

echo
echo "$(date -u +%H:%M:%S) == the writers: the census, the grammar, the reader over a live run =="

# The module's own record of itself, read the way an operator reads it: every serving worker's
# thread writes its status file, its rule-counter file, and (once per configuration, whichever
# worker finds the name absent first) the configuration file that names every program, beside the
# legacy per-range files. The summary is the only reader these rows use, and its EXIT CODE is part
# of every assertion, so it is always captured, never piped: a pipeline under pipefail would eat
# the code the row is about.
# names_matching <dir> <ERE over the base name>: the entries of a directory whose names match, one per line
names_matching() {
    local f
    for f in "$1"/*; do
        [ -e "$f" ] || continue
        f=${f##*/}
        [[ $f =~ $2 ]] && printf '%s\n' "$f"
    done
    return 0
}
sum_rules()  { "$SUMMARY_BIN" --rules "$1" 2>&1 || true; }
rules_count() { sed -n "s/^r $2 $3 \([0-9]\{1,\}\) .*/\1/p" <<<"$1"; }
pre_count()   { sed -n "s/^pre $2 \([0-9]\{1,\}\)$/\1/p" <<<"$1"; }
# a count read only when two reads a full tick apart agree: the files lag the counts by up to one
# tick, and a read taken mid-flush is not a measurement (the headline row above has the same rule).
# The --rules text carries nothing but the counts, the refused lines and the gone-file tally, so
# two identical texts are every count settled at once.
stable_text() { # <dir> -> the agreed --rules text
    local out prev
    out=$(sum_rules "$1")
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1.2
        prev=$out
        out=$(sum_rules "$1")
        [ "$out" = "$prev" ] && break
    done
    printf '%s' "$out"
}

# the census: two workers, so exactly two of each process file and one configuration file, nothing
# else; and every writer's file names a serving worker, because the cache helpers run the module's
# init_process too and a file with a helper's pid is the silent bug (the file half of the row that
# counts threads above)
ls_a=$(ls "$SUMMARY_DIR" 2>/dev/null || true); sleep 1.2; ls_b=$(ls "$SUMMARY_DIR" 2>/dev/null || true)
[ "$ls_a" = "$ls_b" ] || { sleep 1.2; ls_b=$(ls "$SUMMARY_DIR" 2>/dev/null || true); }
n_status=$(grep -cE '^[0-9]+-[0-9a-f]{16}\.status$'     <<<"$ls_b" || true)
n_rules=$( grep -cE '^[0-9]+-[0-9a-f]{16}\.rules\.cnt$' <<<"$ls_b" || true)
n_range=$( grep -cE '^[0-9]+-[0-9a-f]{16}\.cnt$'        <<<"$ls_b" || true)
n_conf=$(  grep -cE '^conf-[0-9a-f]{16}\.status$'       <<<"$ls_b" || true)
n_all=$(   grep -c .                                   <<<"$ls_b" || true)
live_workers=" $(pgrep -P "$master" 2>/dev/null | tr '\n' ' ') "
strays=""
for f in $ls_b; do
    case "$f" in conf-*) continue ;; esac
    pid=${f%%-*}
    case "$live_workers" in *" $pid "*) ;; *) strays="$strays $f" ;; esac
done
# and no helper wrote a file: the cache manager and loader are the master's children too, so a
# helper's pid passes the check above and needs its own
helper_files=""
for p in $live_workers; do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    if [[ $cmd == *cache* ]]; then
        grep -qE "^$p-" <<<"$ls_b" && helper_files="$helper_files $p"
    fi
done
if [ "$n_status" = 2 ] && [ "$n_rules" = 2 ] && [ "$n_range" = 2 ] && [ "$n_conf" = 1 ] \
        && [ "$n_all" = 7 ] && [ -z "$strays" ] && [ -z "$helper_files" ]; then
    ok "the census: two workers' .status, .rules.cnt and legacy .cnt, one conf file, nothing else, and no helper wrote a file"
else
    bad "the census: $n_status .status, $n_rules .rules.cnt, $n_range .cnt, $n_conf conf, $n_all entries in all${strays:+, files naming no worker:$strays}${helper_files:+, helpers with files:$helper_files}"
fi

# the grammar, as the reader parses it: every line of every file classifies, one process line per
# status file, the reputation plane armed, the fault delta present. The escape forms are
# backslash-quote, backslash-backslash and backslash-x-hex-hex, and a raw byte is 0x20..0x7e
# excluding quote and backslash. The two classes are written without a backslash inside a bracket:
# a POSIX bracket has no escapes, so the obvious single class closes early and matches nothing.
ESC='([ -!#-[]|[]-~]|\\["\\]|\\x[0-9a-fA-F]{2})*'
PROC_RE="^process \"$ESC\" pid [0-9]+ boot [0-9a-f-]{36} pidns [0-9]+ starttime [0-9]+ started [0-9]+ written [0-9]+ interval [0-9]+ jitter [0-9]+ handoff [0-9]+ tick [0-9]+ config [0-9a-f]{16}( no-thread| late-build| client-ip-from-header| single-process-stale)* shards [0-9]+ retired [0-9]+ retire-lost [0-9]+ failure-evicted [0-9]+ log-dropped [0-9]+ ticks-before-start [0-9]+ verify-held [0-9]+ verify-peak [0-9]+\$"
PLANE_RE="^plane (reputation|tor|rpki-unreachable|routing|anonymizer|threat|registry|tenant) (armed|refused|loading|disarmed|absent|stale)( \"$ESC\")? generation [0-9]+ digest ([0-9a-f]{16}|-)( posted [0-9]+ pending-ticks [0-9]+)? valid-until [0-9]+ remaining -?[0-9]+( slot-age -?[0-9]+)? since [0-9]+( ticks [0-9]+)? bytes [0-9]+ (mapped|private) locked (yes|no)( immutable (yes|no))?( nonresident [0-9]+)? country-table [0-9]+ eio-backoff [0-9]+ deferred [0-9]+( data-directory-replaced)?\$"
TRANS_RE="^transition [0-9]+ \"$ESC\"\$"
MAJFLT_RE='^majflt-delta [0-9]+$'
RULES_KEY_RE='^pidns [0-9]+ starttime [0-9]+$'
RULES_NUM_RE='^(started|tick|snapshot|written|pid) [0-9]+$'
RULES_CONF_RE='^config [0-9a-f]{16}$'
RULES_R_RE='^r [0-9a-f]{16} [0-9]{1,5} [0-9]+$'
RULES_PRE_RE='^pre (hold-harmless|acme|tenant|stale-tenant|no-address|floor-header-missing|floor-header-unparsed|floor-header-capped) [0-9]+$'
CONF_PLANE_RE="^plane (reputation|tor|rpki-unreachable|routing|anonymizer|threat|registry|tenant) path \"$ESC\"( unreadable \"$ESC\")?\$"
CONF_PROG_RE="^program [0-9a-f]{16} context \"$ESC\" path \"$ESC\" mode [0-9]+ rules [0-9]+\$"
CONF_TEXT_RE="^text [0-9a-f]{16} [0-9]{1,5} \"$ESC\"\$"
g_bad=""
n_gram=0
for f in $(grep -E '^[0-9]+-[0-9a-f]{16}\.status$' <<<"$ls_b" || true); do
    mapfile -t gl < "$SUMMARY_DIR/$f"
    n_gram=$((n_gram + 1))
    nproc=0
    [ "${gl[0]:-}" = "whisper-edge-status 2" ] || g_bad="$g_bad $f:magic"
    for l in "${gl[@]:1}"; do
        if   [[ $l =~ $PROC_RE ]];  then nproc=$((nproc + 1))
        elif [[ $l =~ $PLANE_RE ]]; then :
        elif [[ $l =~ $TRANS_RE ]] || [[ $l =~ $MAJFLT_RE ]]; then :
        else g_bad="$g_bad $f:unclassified"; fi
    done
    [ "$nproc" = 1 ] || g_bad="$g_bad $f:process-lines=$nproc"
    grep -qE '^plane reputation armed generation 1 digest [0-9a-f]{16}' "$SUMMARY_DIR/$f" || g_bad="$g_bad $f:no-armed-plane"
    grep -qE "$MAJFLT_RE" "$SUMMARY_DIR/$f" || g_bad="$g_bad $f:no-fault-delta"
done
for f in $(grep -E '^[0-9]+-[0-9a-f]{16}\.rules\.cnt$' <<<"$ls_b" || true); do
    mapfile -t gl < "$SUMMARY_DIR/$f"
    n_gram=$((n_gram + 1))
    [ "${gl[0]:-}" = "whisper-edge-rule-counters 2" ] || g_bad="$g_bad $f:magic"
    for l in "${gl[@]:1}"; do
        if   [[ $l =~ $RULES_KEY_RE ]] || [[ $l =~ $RULES_NUM_RE ]] || [[ $l =~ $RULES_CONF_RE ]]; then :
        elif [[ $l =~ $RULES_R_RE ]] || [[ $l =~ $RULES_PRE_RE ]]; then :
        else g_bad="$g_bad $f:unclassified"; fi
    done
done
for f in $(grep -E '^conf-[0-9a-f]{16}\.status$' <<<"$ls_b" || true); do
    mapfile -t gl < "$SUMMARY_DIR/$f"
    n_gram=$((n_gram + 1))
    [ "${gl[0]:-}" = "whisper-edge-config 2" ] || g_bad="$g_bad $f:magic"
    for l in "${gl[@]:1}"; do
        if   [[ $l =~ $CONF_PLANE_RE ]]; then :
        elif [[ $l =~ $CONF_PROG_RE ]] || [[ $l =~ $CONF_TEXT_RE ]]; then :
        else g_bad="$g_bad $f:unclassified"; fi
    done
done
if [ -z "$g_bad" ] && [ "$n_gram" = 5 ]; then
    ok "the grammar: every line of the two status, two counter and one configuration file classifies, one process line each, the reputation plane armed, the fault delta present"
else
    bad "files off the grammar (checked $n_gram, expected 5):$g_bad"
fi

# the agreement: both workers built the same configuration, the configuration file's name is its
# digest, and the master said the name while it parsed
conf_file=$(grep -E '^conf-[0-9a-f]{16}\.status$' <<<"$ls_b" || true)
conf16=${conf_file#conf-}; conf16=${conf16%.status}
c16s=""
for f in $(grep -E '^[0-9]+-[0-9a-f]{16}\.status$' <<<"$ls_b" || true); do
    c16=$(sed -nE 's/^process .* config ([0-9a-f]{16}) .*/\1/p' "$SUMMARY_DIR/$f")
    c16s="$c16s $c16"
done
c16s=${c16s:-x x}
set -- $c16s
if [ "$1" = "$2" ] && [ "$1" = "$conf16" ] && grep -qF "conf-$conf16.status" "$W/logs/start.err"; then
    ok "the agreement: both workers name configuration $conf16, the file is conf-$conf16.status, and the master's configuration-time line said so"
else
    bad "the agreement: the workers carry \"$c16s\", the file is \"$conf_file\", the master's line names it $(grep -cF "conf-$conf16.status" "$W/logs/start.err" || true) times"
fi

# the summary over the healthy pair under this header configuration: the client's address comes
# from a header, which is a deployment choice an operator must see, so both live processes carry
# the flag and the exit is 1 while everything reads
src=0; out=$("$SUMMARY_BIN" --status "$SUMMARY_DIR" 2>&1) || src=$?
nlive=$(grep -cE '^process pid [0-9]+ tick [0-9]+' <<<"$out" || true)
nflag=$(grep -E '^process pid [0-9]+ tick' <<<"$out" | grep -cF 'client-ip-from-header' || true)
nplane=$(grep -cE '^  plane reputation armed generation 1 digest [0-9a-f]{16}$' <<<"$out" || true)
if [ "$src" = 1 ] && [ "$nlive" = 2 ] && [ "$nflag" = 2 ] && [ "$nplane" = 2 ] \
        && grep -q '^live 2, gone 0, foreign 0 ' <<<"$out" \
        && ! grep -q '^conf-mismatch ' <<<"$out" && ! grep -q '^refused ' <<<"$out"; then
    ok "the summary over a header configuration: exit 1 with the header flag on both live workers, 2 live 0 gone, both planes armed at generation 1, nothing refused"
else
    bad "the summary: rc=$src, $nlive process lines ($nflag flagged), $nplane armed plane lines: $(grep -E '^(live|gone|conf-mismatch|refused)' <<<"$out" | tr '\n' '|')"
fi

# the g3b program's digest, read off the two configuration surfaces that name it: the master's
# configuration-time line and the configuration file's context line. Both must agree before any
# counting row reads counts through that digest.
G3B=""
mapfile -t clines < "$SUMMARY_DIR/$conf_file"
RE_G3B='^program ([0-9a-f]{16}) context "location \\"/g3b/\\""'
for l in "${clines[@]}"; do
    if [[ $l =~ $RE_G3B ]]; then G3B=${BASH_REMATCH[1]}; fi
done
g3b_line=$(grep -m1 -F 'whisper edge: policy: "location \"/g3b/\""' "$W/logs/start.err" || true)
G3B_LOG=""
if [[ $g3b_line =~ program\ ([0-9a-f]{16}) ]]; then G3B_LOG=${BASH_REMATCH[1]}; fi
if [ -n "$G3B" ] && [ "$G3B" = "$G3B_LOG" ]; then
    ok "the g3b program's digest is the same on the master's line and in the configuration file: $G3B"
else
    bad "the g3b digest: the configuration file says \"$G3B\", the master's line says \"$G3B_LOG\""
fi

# counting evaluations. A file path decides exactly once: a deny counts once on the deciding rule,
# the default allow counts nothing, and the walk's one mark per decide lands where the policy
# says it does. No header: the peer is judged, loopback is hold-harmless, so the exemption fires and
# the header-missing mark lands too. A header whose nearest entry will not parse: the unparsed
# mark alone, never a second one.
base_text=$(stable_text "$SUMMARY_DIR")
base_g3b=$(rules_count "$base_text" "$G3B" 1);   base_g3b=${base_g3b:-0}
b_hh=$(pre_count "$base_text" hold-harmless);         b_hh=${b_hh:-0}
b_fhm=$(pre_count "$base_text" floor-header-missing); b_fhm=${b_fhm:-0}
b_fhu=$(pre_count "$base_text" floor-header-unparsed); b_fhu=${b_fhu:-0}
c_l="$(code /g3b/index.html)$(code /g3b/index.html)$(code /g3b/index.html)"
c_u="$(code_as /g3b/index.html "$UNLISTED")$(code_as /g3b/index.html "$UNLISTED")"
c_n="$(code_nohdr /g3b/index.html)$(code_nohdr /g3b/index.html)"
c_g=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "X-Forwarded-For: not-an-address, $HOP" "http://127.0.0.1:$PORT/g3b/index.html")
now_text=$(stable_text "$SUMMARY_DIR")
n_g3b=$(rules_count "$now_text" "$G3B" 1); n_g3b=${n_g3b:-0}
n_hh=$(pre_count "$now_text" hold-harmless);         n_hh=${n_hh:-0}
n_fhm=$(pre_count "$now_text" floor-header-missing); n_fhm=${n_fhm:-0}
n_fhu=$(pre_count "$now_text" floor-header-unparsed); n_fhu=${n_fhu:-0}
if [ "$c_l" = 403403403 ] && [ "$n_g3b" = "$(( base_g3b + 3 ))" ]; then
    ok "counting: three denied evaluations on /g3b/index.html move the g3b rule by exactly three ($base_g3b -> $n_g3b)"
else
    bad "counting: three denials answered $c_l and moved the g3b rule $base_g3b -> $n_g3b"
fi
if [ "$c_u" = 200200 ] && [ "$n_g3b" = "$(( base_g3b + 3 ))" ]; then
    ok "counting: the unlisted twin's two allowed evaluations count nothing ($n_g3b)"
else
    bad "counting: the unlisted twin answered $c_u and the rule read $base_g3b -> $n_g3b, which the default allow must not move"
fi
if [ "$c_n" = 200200 ] && [ "$n_hh" = "$(( b_hh + 2 ))" ] && [ "$n_fhm" = "$(( b_fhm + 2 ))" ]; then
    ok "counting: two headerless requests, allowed by hold-harmless on the loopback peer (200), one hold-harmless and one header-missing mark each ($b_hh/$b_fhm -> $n_hh/$n_fhm)"
else
    bad "counting: the headerless pair answered $c_n, hold-harmless $b_hh -> $n_hh and header-missing $b_fhm -> $n_fhm (expected +2 each)"
fi
if [ "$c_g" = 200 ] && [ "$n_fhu" = "$(( b_fhu + 1 ))" ] && [ "$n_fhm" = "$(( b_fhm + 2 ))" ]; then
    ok "counting: a header whose nearest entry will not parse leaves one unparsed mark and no second one ($b_fhu -> $n_fhu)"
else
    bad "counting: the unparsed request answered $c_g, unparsed $b_fhu -> $n_fhu (+1 expected), header-missing $b_fhm -> $n_fhm (+2 and no more expected)"
fi

# the digest on every surface: the configuration file's name is the digest of its own bytes, both
# status files' plane digest is the snapshot's (the digest's zeroed header window), and the
# summary's rule line carries the same digest with the canonical text the configuration recorded
conf_hash=""
if [ -n "$conf_file" ]; then conf_hash=$(sha256sum "$SUMMARY_DIR/$conf_file" | cut -c1-16 || true); fi
plane16=$(python3 - "$W/snapshot.bin" <<'PYEOF'
import hashlib, sys
b = bytearray(open(sys.argv[1], 'rb').read())
b[104:136] = bytes(32)
print(hashlib.sha256(b).hexdigest()[:16])
PYEOF
)
pd_bad=""; n_pd=0
for f in $(grep -E '^[0-9]+-[0-9a-f]{16}\.status$' <<<"$ls_b" || true); do
    d=$(grep -m1 -E '^plane reputation armed generation 1 digest [0-9a-f]{16}' "$SUMMARY_DIR/$f" | sed -E 's/.*digest ([0-9a-f]{16}).*/\1/' || true)
    n_pd=$((n_pd + 1))
    [ "$d" = "$plane16" ] || pd_bad="$pd_bad $f:$d"
done
pd_ok=0
[ "$n_pd" -ge 1 ] && [ -z "$pd_bad" ] && pd_ok=1
rline=$(grep -E "^r $G3B 1 [0-9]+ " <<<"$now_text" | sed -n 1p || true)
RE_RLINE="^r $G3B 1 [0-9]+ \"deny if listed >= low\"\$"
if [ -n "$conf16" ] && [ "$conf_hash" = "$conf16" ] && [ "$pd_ok" = 1 ] && [[ $rline =~ $RE_RLINE ]]; then
    ok "the digest on every surface: the file's name is its own bytes' digest, both plane digests are the snapshot's ($plane16), and the rule line carries the canonical text: $rline"
else
    bad "the digests: the file hashes to \"$conf_hash\" against name \"$conf16\", the plane agreement is $pd_ok over $n_pd file(s)$pd_bad, the rule line is \"$rline\""
fi

# a version 1 file, the pre-upgrade writer's record: its program line is byte-swapped by the
# reader, so its counts sum into the same total and an upgrade never resets the counts
g3b_v1=$(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1])[:8][::-1].hex())' "$G3B")
printf 'whisper-edge-rule-counters 1\nprogram %s\nr 1 4\n' "$g3b_v1" > "$SUMMARY_DIR/4128000001.rules.cnt"
out=$(sum_rules "$SUMMARY_DIR"); rc_v1=0; "$SUMMARY_BIN" --rules "$SUMMARY_DIR" >/dev/null 2>&1 || rc_v1=$?
v1_now=$(rules_count "$out" "$G3B" 1); v1_now=${v1_now:-0}
if [ "$v1_now" = "$(( n_g3b + 4 ))" ] && [ "$rc_v1" = 0 ] && ! grep -q '^refused ' <<<"$out"; then
    ok "the version 1 record sums into the same total: $n_g3b -> $v1_now, nothing refused"
else
    bad "the version 1 plant: $n_g3b -> $v1_now rc=$rc_v1 $(grep -m1 '^refused' <<<"$out" || true)"
fi
rm -f "$SUMMARY_DIR/4128000001.rules.cnt"
out=$(sum_rules "$SUMMARY_DIR")
v1_gone=$(rules_count "$out" "$G3B" 1); v1_gone=${v1_gone:-0}
if [ "$v1_gone" = "$n_g3b" ] && [ "$v1_gone" != 0 ]; then
    ok "and removing it returns the total to $n_g3b"
else
    bad "removing the version 1 plant: $v1_now -> $v1_gone, the live baseline is $n_g3b"
fi

# a gone writer's file with two near-maximal counts on one key: summed saturated, never wrapped,
# listed gone (its pid is past the kernel's pid_max, so it can never come back) and unattributed
# (no status file of that writer exists)
liverules=$(grep -E '^[0-9]+-[0-9a-f]{16}\.rules\.cnt$' <<<"$ls_b" | sed -n 1p || true)
read -r PL_PIDNS PL_START < <(sed -nE 's/^pidns ([0-9]+) starttime ([0-9]+)$/\1 \2/p' "$SUMMARY_DIR/$liverules" 2>/dev/null | sed -n 1p) || true
printf 'whisper-edge-rule-counters 2\npidns %s starttime %s\nstarted 1\ntick 1\nsnapshot 1\nwritten 1\npid 4128000002\nconfig 0000000000000000\nr dead00000000beef 1 18446744073709551000\nr dead00000000beef 1 1000\n' \
    "$PL_PIDNS" "$PL_START" > "$SUMMARY_DIR/4128000002-0000000000000001.rules.cnt"
out=$(sum_rules "$SUMMARY_DIR"); rc_sat=0; "$SUMMARY_BIN" --rules "$SUMMARY_DIR" >/dev/null 2>&1 || rc_sat=$?
if [ "$rc_sat" = 0 ] && grep -qE '^r dead00000000beef 1 18446744073709551615 -$' <<<"$out" \
        && grep -q '^unattributed 1$' <<<"$out" && grep -q "^gone writers' files 1, " <<<"$out"; then
    ok "a gone writer's near-maximal pair sums saturated, no wrap: the total prints 18446744073709551615 and the file is listed gone and unattributed"
else
    bad "the saturated plant: rc=$rc_sat, $(grep -E '^(r dead|unattributed|gone writers)' <<<"$out" | tr '\n' '|')"
fi
rm -f "$SUMMARY_DIR/4128000002-0000000000000001.rules.cnt"

echo
echo "$(date -u +%H:%M:%S) == the directives as policy programs (G2, G3, G4) =="
if policy_lit; then
    # one configuration load: what this start's master printed while it parsed the configuration
    LOAD=$(cat "$W/logs/start.err")
    g2_lines "$LOAD" server 'location "/"' 'location "/enforced/"' 'location "/g3a/"' 'location "/g3b/"' \
        'location "/g3p/"' 'location "/g3p/c/"'
    # G3: one threshold under two modes is ONE program and two verdicts; a child runs its parent's
    g3_rows "$LOAD" server 'location "/g3a/"' 'location "/g3b/"' 'location "/g3p/"' 'location "/g3p/c/"' log
    [ "$(code /g3a/)" = 200 ] && [ "$(code /g3b/)" = 403 ] \
        && ok "G3: and the two contexts' own modes give different verdicts (200 under log, 403 under deny)" \
        || bad "G3: the shared program's contexts answered $(code /g3a/) and $(code /g3b/), not 200 and 403"
    [ "$(code /g3p/)" = 403 ] && [ "$(code /g3p/c/)" = 200 ] \
        && ok "G3: and the parent denies (403) while the child only logs (200)" \
        || bad "G3: parent and child answered $(code /g3p/) and $(code /g3p/c/), not 403 and 200"
    # G4: the programs and the view are shared by both workers after the fork
    SUMMARY_LINE=$(printf '%s\n' "$LOAD" | grep 'read-only regions:' | tail -1)
    read -ra ws <<<"$(workers)"
    set -- "${ws[@]}"
    if [ $# -ge 2 ]; then
        g4_shared "$SUMMARY_LINE" "$1" "$2"
    else
        bad "G4: two workers are needed to show the pages are shared, and $# is running"
    fi
    # G2 for the legacy synonym: the snapshot file ABSENT at configuration test still yields the line.
    # `nginx -t` is EXPECTED to fail here (no snapshot to load), so its status is not the answer; its
    # output is, and the row below fails by name if the line is missing.
    SNAPSHOT_PATH="$W/absent/snapshot.bin" mkconf 1s
    tout=$(nginx -t -c "$W/nginx.conf" -p "$W" 2>&1 || true)
    if [[ $(policy_line "$tout" server) =~ program\ (\#[0-9]+|[0-9a-f]{16}) ]]; then
        g2_lines "$(printf '%s\n' "$tout" | grep 'whisper edge: policy:')" server
    else
        bad "G2: with the snapshot absent at configuration test there is no policy line: $(printf '%s' "$tout" | tail -2 | tr '\n' ' ')"
    fi
    mkconf 1s
else
    policy_dark nginx
fi

echo
echo "$(date -u +%H:%M:%S) == reload must turn the workers over =="
before=$(workers)
# T0, read before the reload from two agreeing reads: the exited workers' final flush must land in
# it, and it is the total the reloaded pair has to continue
T0=$(stable_text "$SUMMARY_DIR"); T0=$(rules_count "$T0" "$G3B" 1); T0=${T0:-0}
signal_master reload
sleep 3
after=$(workers)
left=""
for p in $before; do
    kill -0 "$p" 2>/dev/null && left="$left $p"
done
if [ -n "$left" ]; then
    bad "workers$left survived the reload; a non-cancelable timer stops a worker ever exiting"
    ps -o pid,etime,args -p "$(echo "$left" | tr ' ' ',' | sed 's/^,//')" 2>/dev/null | tail -n +2 | sed 's/^/        /'
else
    ok "every pre-reload worker exited (before:$before after:$after)"
fi
[ "$(code /)" = 200 ] && ok "and nginx still serves after the reload" || bad "nginx broken after reload"
read -ra ws_after <<<"$after"
q4_check " after the reload" "$(cat "$W/logs/nginx.pid")" "${ws_after[@]}"

# the writers' half of the reload: the new workers' files appear beside the old pair's, the old
# pair's final flush still sums (the summary reads a gone writer's files), the new pair starts at
# zero, so the total continues by digest and two more denials move it by exactly two. The
# configuration did not change, so there is still one configuration file, and every file names it
await '[ "$(ls "$SUMMARY_DIR" 2>/dev/null | grep -cE "^[0-9]+-[0-9a-f]{16}\.status$")" -ge 4 ]' 15 "the reloaded workers' status files" \
    || bad "the reloaded workers wrote no status files"
T1=$(stable_text "$SUMMARY_DIR"); T1=$(rules_count "$T1" "$G3B" 1); T1=${T1:-0}
if [ "$T1" = "$T0" ] && [ "$T0" != 0 ]; then
    ok "the reload keeps the count: the exited pair's final files still sum ($T0 -> $T1)"
else
    bad "the count moved across the reload: $T0 -> $T1"
fi
code /g3b/index.html >/dev/null; code /g3b/index.html >/dev/null
T2=$(stable_text "$SUMMARY_DIR"); T2=$(rules_count "$T2" "$G3B" 1); T2=${T2:-0}
if [ "$T2" = "$(( T0 + 2 ))" ]; then
    ok "and two more denials on the new workers move it by exactly two ($T0 -> $T2)"
else
    bad "two denials after the reload moved the count $T0 -> $T2"
fi
src=0; out=$("$SUMMARY_BIN" --status "$SUMMARY_DIR" 2>&1) || src=$?
if [ "$src" = 1 ] && grep -q '^live 2, gone 2, foreign 0 ' <<<"$out" && ! grep -q '^conf-mismatch ' <<<"$out"; then
    ok "the summary after the reload: two live, the two exited workers listed gone, exit 1 for the header flag"
else
    bad "the summary after the reload: rc=$src, $(grep -E '^(live|gone|conf-mismatch|refused)' <<<"$out" | tr '\n' '|')"
fi
ls_r=$(ls "$SUMMARY_DIR" 2>/dev/null || true)
n_all_r=$(grep -c . <<<"$ls_r" || true)
n_conf_r=$(grep -cE '^conf-[0-9a-f]{16}\.status$' <<<"$ls_r" || true)
c16_all=""
for f in $(grep -E '^[0-9]+-[0-9a-f]{16}\.status$' <<<"$ls_r" || true); do
    c=$(sed -nE 's/^process .* config ([0-9a-f]{16}) .*/\1/p' "$SUMMARY_DIR/$f")
    case "$c16_all" in *" $c "*) ;; *) c16_all="$c16_all $c " ;; esac
done
if [ "$n_all_r" = 13 ] && [ "$n_conf_r" = 1 ] && [ "$c16_all" = " $conf16 " ]; then
    ok "and the census after the reload: four workers' files (two gone, two live), still one configuration file, every one of them naming configuration $conf16"
else
    bad "the census after the reload: $n_all_r entries, $n_conf_r conf file(s), configurations named:$c16_all"
fi

echo
echo "$(date -u +%H:%M:%S) == an in-place rewrite of the snapshot must not kill a worker =="
( for _ in $(seq 1 40); do curl -s -o /dev/null --max-time 2 -H "$(xff)" "http://127.0.0.1:$PORT/enforced/" || true; done ) &
loadpid=$!
: > "$W/snapshot.bin"                       # O_TRUNC, exactly what curl -o and cp do
sleep 1
cat "$W/snapshot.good" > "$W/snapshot.bin"
chmod 0644 "$W/snapshot.bin"
wait $loadpid 2>/dev/null || true
if grep -qE 'exited on signal (7|11)|SIGBUS|SIGSEGV' "$W/logs/error.log"; then
    bad "a worker died on a signal after the snapshot was truncated in place:"
    grep -E 'exited on signal' "$W/logs/error.log" | tail -3 | sed 's/^/        /'
else
    ok "no worker died on a signal (the loader owns its buffer rather than mapping the file)"
fi
[ "$(code /)" = 200 ] && ok "and traffic still flows" || bad "traffic stopped: $(code /)"

echo
echo "$(date -u +%H:%M:%S) == deleting the snapshot must leave traffic flowing =="
rm -f "$W/snapshot.bin"
sleep 2
[ "$(code /)" = 200 ] && ok "snapshot deleted -> 200, the loaded policy keeps answering" || bad "deleting the snapshot broke serving"
[ "$(code /enforced/)" = 403 ] && ok "and the already-loaded policy is still enforced" \
    || ok "enforcement lapsed to allow, which is also acceptable: fail open"
cp "$W/snapshot.good" "$W/snapshot.bin"
chmod 0644 "$W/snapshot.bin"

echo
echo "$(date -u +%H:%M:%S) == the refresh floor must be clamped, with a message =="
stop; sleep 1
mkconf 1ms
tout=$(nginx -t -c "$W/nginx.conf" -p "$W" 2>&1 || true)
if grep -q 'below the 1s floor' <<<"$tout"; then
    ok "whisper_edge_refresh 1ms is raised to 1s and says so"
else
    bad "a 1ms refresh was not clamped with a message. nginx -t said:"
    printf '%s\n' "$tout" | sed 's/^/        /'
fi
mkconf 1s
start
await '[ "$(code /)" = 200 ]' 10 "restart" || bad "nginx did not restart"

echo
echo "$(date -u +%H:%M:%S) == quit must actually exit =="
master=$(cat "$W/logs/nginx.pid")
nginx -s quit -c "$W/nginx.conf" -p "$W"
if await '! kill -0 '"$master"' 2>/dev/null' 12 "quit"; then
    ok "the master exited within 12s"
else
    bad "the master did not exit: a non-cancelable timer blocks shutdown"
    kill -9 "$master" 2>/dev/null || true
fi
# the workers left by the thread's stop, not by the deadline: every one exited with code 0 and the
# abandoned-thread line was never written
if grep -q 'exited with code 0' "$W/logs/error.log" && ! grep -q 'did not stop and is abandoned' "$W/logs/error.log" \
        && ! grep -q 'open socket .* left in connection' "$W/logs/error.log"; then
    ok "every worker exited with code 0, its thread stopped inside the deadline and its eventfd slot freed"
else
    bad "a worker did not leave cleanly: $(grep -E 'exited|did not stop|open socket' "$W/logs/error.log" | tail -3 | tr '\n' '|')"
fi

echo
echo "$(date -u +%H:%M:%S) == master_process off: a reload keeps the first planes (Q5) =="
# a single-process cycle runs init_process once, so a reload cannot start a second thread or bind a second
# set of planes under the first: the module says so once and keeps deciding over the first planes
mkconf 1s 'master_process off;' 2>/dev/null || true
# master_process is a main-context directive: put it in front of the http block
mkconf 1s
sed -i 's/^worker_processes 2;/worker_processes 2;\nmaster_process off;/' "$W/nginx.conf"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "single-process startup" || bad "Q5: the single process did not come up"
single=$(cat "$W/logs/nginx.pid")
[ "$(ls "/proc/$single/task" | wc -l)" = 2 ] && ok "Q5: the single process carries the module's thread" \
    || bad "Q5: the single process has $(ls "/proc/$single/task" | wc -l) tasks, not 2"
signal_master reload
await 'grep -q "single-process-stale" "$W/logs/error.log"' 5 "the once-only line" \
    && ok "Q5: the reload logs the once-only line (single-process-stale) and keeps the first configuration's planes" \
    || bad "Q5: no single-process-stale line after a reload under master_process off"
# nothing is asserted about serving after the reload: nginx itself stops accepting on a single-process
# reload (measured on this nginx 1.24 with no module loaded: 200 before `nginx -s reload`, connection
# refused after; the event module's init_process is never run again), which is why master_process off
# is a development setting; the module's property is that the process is still alive with its one thread
kill -0 "$single" 2>/dev/null && ok "Q5: the single process is alive after the reload" || bad "Q5: the single process died on the reload"
[ "$(ls "/proc/$single/task" 2>/dev/null | wc -l)" = 2 ] && ok "Q5: and no second thread was started" \
    || bad "Q5: $(ls "/proc/$single/task" 2>/dev/null | wc -l) tasks after the reload, not 2"
# the writers' half of Q5: the single process's status file carries the stale flag, and the summary
# names it unhealthy on the live process, exit 1
sfile=""
for _ in $(seq 1 40); do
    sfile=$(names_matching "$SUMMARY_DIR" "^$single-[0-9a-f]{16}\.status$")
    if [ -n "$sfile" ] && grep -q ' single-process-stale' "$SUMMARY_DIR/$sfile"; then break; fi
    sleep 0.25
done
if [ -n "$sfile" ] && grep -q ' single-process-stale' "$SUMMARY_DIR/$sfile"; then
    ok "Q5: the single process's status file carries single-process-stale after the reload"
else
    bad "Q5: the single process's status file: ${sfile:-absent}, flags: $(grep -m1 -oE 'config [0-9a-f]{16}( no-thread| late-build| client-ip-from-header| single-process-stale)*' "$SUMMARY_DIR/$sfile" 2>/dev/null || true)"
fi
src=0; out=$("$SUMMARY_BIN" --status "$SUMMARY_DIR" 2>&1) || src=$?
if [ "$src" = 1 ] && grep -qE "^process pid $single tick [0-9]+ .*single-process-stale" <<<"$out" && grep -q '^live 1, ' <<<"$out"; then
    ok "Q5: and the summary exits 1 naming the live single process stale"
else
    bad "Q5: the summary over the single process: rc=$src, $(grep -E "^(process pid $single|live)" <<<"$out" | tr '\n' '|')"
fi
kill -QUIT "$single" 2>/dev/null || true
await '! kill -0 '"$single"' 2>/dev/null' 12 "single quit" || { bad "Q5: the single process did not exit"; kill -9 "$single" 2>/dev/null || true; }

echo
echo "$(date -u +%H:%M:%S) == the variables: fetched by name with no static reference (V9) =="
# an SSI echo names a variable at run time; nothing in the configuration references one, so no record is
# kept at the decision: the decision words still render from the request's node, and logged says unknown
mkdir -p "$W/html/ssi"
printf '<!--# echo var="whisper_edge_action" -->|<!--# echo var="whisper_edge_logged" -->|<!--# echo var="whisper_edge_floor_addr" -->\n' > "$W/html/ssi/index.html"
SERVER_EXTRA='location /ssi/ { ssi on; }' mkconf 1s
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "startup" || bad "V9: the server did not come up"
grep -q 'no \$whisper_edge_\* variable is referenced' "$W/logs/start.err" \
    && ok "V9: the configuration line says no record is kept and what a run-time fetch gets" \
    || bad "V9: the configuration line about run-time-only references is missing: $(grep -c . "$W/logs/start.err") lines"
body=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/ssi/")
[ "$body" = "would-deny|unknown|$LISTED" ] && ok "V9: the SSI echo renders the decision from the node (would-deny), logged unknown, the floor address" \
    || bad "V9: the SSI page reads \"$body\", not would-deny|unknown|$LISTED"
body=$(curl -s --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/ssi/")
[ "$body" = "allow|unknown|$UNLISTED" ] && ok "V9: and the unlisted twin reads allow|unknown|$UNLISTED" \
    || bad "V9: the unlisted twin's SSI page reads \"$body\""
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the variables: the decision's words, the provenance, the floor, a map, a read before the decision (V5, V7) =="
mkdir -p "$W/html/pre"; echo page > "$W/html/pre/index.html"
SERVER_EXTRA='set $c $whisper_edge_listed;
        access_log '"$W"'/logs/vars.log wev;
        location /pre/ { if ($whisper_edge_listed = high) { return 418; } }
        location /ssi/ { ssi on; }' \
    mkconf 1s 'log_format wev "$request_uri $status action=$whisper_edge_action rule_id=$whisper_edge_rule_id rule=\"$whisper_edge_rule\" reason=$whisper_edge_reason program=\"$whisper_edge_program\" logged=$whisper_edge_logged generations=\"$whisper_edge_generations\" floor=$whisper_edge_floor_addr listed=$whisper_edge_listed verdict=$whisper_edge_verdict c=$c m=$m";
    map $whisper_edge_verdict $m { default other; high high; }'
: > "$W/logs/error.log"; : > "$W/logs/vars.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "startup" || bad "V5: the server did not come up"
grep -q 'no \$whisper_edge_\* variable is referenced' "$W/logs/start.err" \
    && bad "V9: the no-record line is printed although the log format references the variables" \
    || ok "V9: with a static reference the no-record line is not printed"
code /?q=listed >/dev/null || true; code_as /?q=unlisted "$UNLISTED" >/dev/null || true; code_nohdr /?q=peer >/dev/null || true
code /enforced/?q=deny >/dev/null || true; code /pre/?q=pre >/dev/null || true; code_as /pre/?q=pre-unlisted "$UNLISTED" >/dev/null || true
sleep 0.5
vline() { grep -m1 -F "$1 " "$W/logs/vars.log" 2>/dev/null || true; }
l=$(vline '/?q=listed')
if [[ $l =~ ^/\?q=listed\ 200\ action=would-deny\ rule_id=-\ rule=\"-\"\ reason=-\ program=\"floor:(-|[0-9a-f]{16})\ ctx:[0-9a-f]{16}\"\ logged=ctx:1\ generations=\"reputation:1[^\"]*\"\ floor=$LISTED\ listed=high\ verdict=high\ c=high\ m=high$ ]]; then
    ok "V5/V7: the listed client's log line: would-deny, decided by the default allow so no deciding rule (rule_id -), the fired rule named by logged (ctx:1), the program digests, reputation:1, the floor address, listed/verdict high, the rewrite-phase set and the map agree"
else
    bad "V5/V7: the listed client's log line is not the documented shape: $l"
fi
l=$(vline '/?q=unlisted')
if [[ $l =~ ^/\?q=unlisted\ 200\ action=allow\ rule_id=-\ rule=\"-\"\ reason=-\ program=\"floor:(-|[0-9a-f]{16})\ ctx:[0-9a-f]{16}\"\ logged=-\ generations=\"reputation:1[^\"]*\"\ floor=$UNLISTED\ listed=none\ verdict=none\ c=none\ m=other$ ]]; then
    ok "V5: the unlisted twin's line: allow, no rule, nothing logged, listed/verdict none, the map's default"
else
    bad "V5: the unlisted twin's line is not the documented shape: $l"
fi
l=$(vline '/?q=peer')
if [[ $l =~ ^/\?q=peer\ 200\ action=allow\ rule_id=-\ rule=\"-\"\ reason=hold-harmless,floor-header-missing\ .*\ floor=127\.0\.0\.1\ .*$ ]]; then
    ok "V5: the trusted peer sending no header: allow by hold-harmless, the floor-header-missing mark, the loopback floor"
else
    bad "V5: the no-header peer's line is not the documented shape: $l"
fi
l=$(vline '/enforced/?q=deny')
if [[ $l =~ ^/enforced/\?q=deny\ 403\ action=deny\ rule_id=ctx:1\ rule=\"deny\ if\ listed\ \>=\ high\"\ reason=-\ program=\"floor:(-|[0-9a-f]{16})\ ctx:[0-9a-f]{16}\"\ logged=-\ generations=\"reputation:1[^\"]*\"\ floor=$LISTED\ listed=high\ verdict=high\ c=high\ m=high$ ]]; then
    ok "V5: the deny location's line: 403, deny by ctx:1 with its canonical text, and nothing logged (logged lists logs and downgraded denies, never an enforced deny)"
else
    bad "V5: the deny line is not the documented shape: $l"
fi
l=$(vline '/pre/?q=pre')
if [[ $l =~ ^/pre/\?q=pre\ 418\ action=-\ rule_id=-\ .*\ listed=high\ .*\ c=high\ .*$ ]]; then
    ok "V7: a read before the decision (if in the rewrite phase) saw listed=high and returned 418; the decision words stay - because no decision ran"
else
    bad "V7: the pre-decision line is not the documented shape: $l"
fi
[ "$(vline '/pre/?q=pre-unlisted' | cut -d' ' -f2)" = 200 ] && ok "V7: and the unlisted twin passes the rewrite-phase test (200)" \
    || bad "V7: the unlisted twin got $(vline '/pre/?q=pre-unlisted' | cut -d' ' -f2) on /pre/"
body=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/ssi/")
[ "$body" = "would-deny|ctx:1|$LISTED" ] && ok "V9: with the record kept, the SSI echo of logged reads the bitmaps (ctx:1)" \
    || bad "V9: the SSI page with a record reads \"$body\", not would-deny|ctx:1|$LISTED"
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the writers with no header, a configuration test, a changed configuration, an altered file =="
# A fresh instance, its own snapshot and its own counters directory, and no trusted header: the
# client's address is the peer's own, so the pair's health is the module's alone, which is the
# summary's exit-0 arm. The server block gains a location whose name carries a space, a quote and a
# newline, because the configuration file records the name and the reader must read it back
# escaped.
mkdir -p "$W/end"
cp "$W/snapshot.good" "$W/end/snapshot.bin"; chmod 0644 "$W/end/snapshot.bin"
END_DIR="$W/end/counters"
SERVER_EXTRA=$'location "/w q\'\\"x/" { whisper_edge_mode deny; }\nlocation "/nl\ny/" { whisper_edge_mode deny; }' \
    SNAPSHOT_PATH="$W/end/snapshot.bin" mkconf 1s
sed -i '/^[[:space:]]*whisper_edge_trusted_header/d' "$W/nginx.conf"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "the headerless startup" || bad "S2: the headerless server did not come up"
ls_e=$(ls "$END_DIR" 2>/dev/null || true)
n_status=$(grep -cE '^[0-9]+-[0-9a-f]{16}\.status$'     <<<"$ls_e" || true)
n_rules=$( grep -cE '^[0-9]+-[0-9a-f]{16}\.rules\.cnt$' <<<"$ls_e" || true)
n_range=$( grep -cE '^[0-9]+-[0-9a-f]{16}\.cnt$'        <<<"$ls_e" || true)
n_conf=$(  grep -cE '^conf-[0-9a-f]{16}\.status$'       <<<"$ls_e" || true)
if [ "$n_status" = 2 ] && [ "$n_rules" = 2 ] && [ "$n_range" = 2 ] && [ "$n_conf" = 1 ]; then
    ok "the headerless pair's census: two of each process file, one configuration file"
else
    bad "the headerless census: $n_status .status, $n_rules .rules.cnt, $n_range .cnt, $n_conf conf"
fi
src=0; out=$("$SUMMARY_BIN" --status "$END_DIR" 2>&1) || src=$?
nplane=$(grep -cE '^  plane reputation armed generation 1 digest [0-9a-f]{16}$' <<<"$out" || true)
if [ "$src" = 0 ] && grep -q '^live 2, gone 0, foreign 0 ' <<<"$out" && ! grep -q 'client-ip-from-header' <<<"$out" \
        && [ "$nplane" = 2 ]; then
    ok "S2: no header configured, so both live workers are healthy: exit 0, no flag, both planes armed"
else
    bad "S2: the headerless summary: rc=$src, $nplane armed plane lines, $(grep -E '^(process|live|gone)' <<<"$out" | tr '\n' '|')"
fi
end_conf=$(grep -E '^conf-[0-9a-f]{16}\.status$' <<<"$ls_e" || true)
g_bad=""
mapfile -t gl < "$END_DIR/$end_conf"
[ "${gl[0]:-}" = "whisper-edge-config 2" ] || g_bad="$g_bad magic"
for l in "${gl[@]:1}"; do
    if   [[ $l =~ $CONF_PLANE_RE ]]; then :
    elif [[ $l =~ $CONF_PROG_RE ]] || [[ $l =~ $CONF_TEXT_RE ]]; then :
    else g_bad="$g_bad unclassified"; fi
done
WANT_SPACE='context "location \"/w q'"'"'\"x/\""'
WANT_NL='context "location \"/nl\x0ay/\""'
if [ -z "$g_bad" ] && grep -qF "$WANT_SPACE" "$END_DIR/$end_conf" && grep -qF "$WANT_NL" "$END_DIR/$end_conf"; then
    ok "the configuration file: every line classifies, and the name with a space, a quote and a newline is recorded escaped"
else
    bad "the configuration file's grammar:$g_bad, the escaped names $(grep -cF "$WANT_SPACE" "$END_DIR/$end_conf" || true) and $(grep -cF "$WANT_NL" "$END_DIR/$end_conf" || true)"
fi
out=$(sum_rules "$END_DIR"); rc_esc=0; "$SUMMARY_BIN" --rules "$END_DIR" >/dev/null 2>&1 || rc_esc=$?
if [ "$rc_esc" = 0 ] && [ -n "$end_conf" ] && ! grep -q '^refused ' <<<"$out"; then
    ok "and the summary reads the escaped names back: the whole directory accepted, nothing refused"
else
    bad "the summary over the escaped names: rc=$rc_esc, the configuration file is \"${end_conf:-absent}\", $(grep -m1 '^refused' <<<"$out" || true)"
fi

# the configuration test writes nothing: the counters directory nginx -t finds absent is still
# absent afterwards (only a worker writes), and the restarted workers rewrite the same
# configuration's file under the same name
C1=$end_conf
stop; sleep 1
rm -rf "$END_DIR"
trc=0; nginx -t -c "$W/nginx.conf" -p "$W" >/dev/null 2>&1 || trc=$?
if [ "$trc" = 0 ] && [ ! -e "$END_DIR" ]; then
    ok "a configuration test writes nothing: nginx -t leaves the counters directory absent"
else
    bad "nginx -t rc=$trc, the counters directory $([ -e "$END_DIR" ] && echo 'was created' || echo absent)"
fi
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "the restart" || bad "the server did not restart after the configuration test"
await '[ -n "$(ls "$END_DIR" 2>/dev/null)" ]' 10 "the writers back" || bad "the writers did not come back after the restart"
C2=$(names_matching "$END_DIR" '^conf-[0-9a-f]{16}\.status$')
if [ -n "$C2" ] && [ "$C2" = "$C1" ]; then
    ok "and the restarted workers rewrite the same configuration's file, the same name: $C1"
else
    bad "the rewritten configuration file is \"$C2\", not \"$C1\": an unchanged configuration changed identity"
fi

# a changed configuration: a reload builds a new configuration, so a new file appears beside the
# old one (the summary prints both identities), every live worker names the new digest, and the
# summary right after the reload is healthy with the old pair's files listed gone
SERVER_EXTRA='location /end-extra/ { whisper_edge_mode deny; }' SNAPSHOT_PATH="$W/end/snapshot.bin" mkconf 1s
sed -i '/^[[:space:]]*whisper_edge_trusted_header/d' "$W/nginx.conf"
signal_master reload
await '[ "$(ls "$END_DIR" 2>/dev/null | grep -cE "^conf-[0-9a-f]{16}\.status$")" -ge 2 ]' 15 "the new configuration's file" \
    || bad "the changed configuration's file did not appear"
ls_e3=$(ls "$END_DIR" 2>/dev/null || true)
n_conf3=$(grep -cE '^conf-[0-9a-f]{16}\.status$' <<<"$ls_e3" || true)
new_conf=$(grep -E '^conf-[0-9a-f]{16}\.status$' <<<"$ls_e3" | grep -vF "$C1" | sed -n 1p || true)
new16=${new_conf#conf-}; new16=${new16%.status}
old16=${C1#conf-}; old16=${old16%.status}
# the settled state: the old pair drained (so its files list gone) and both new workers' planes
# armed. Until then the workers list mixes the draining pair with the new one, so the digest
# check below waits for this barrier first.
await 'out3=$("$SUMMARY_BIN" --status "$END_DIR" 2>&1); grep -q "^live 2, " <<<"$out3" && [ "$(grep -cE "^  plane reputation armed generation 1 digest [0-9a-f]{16}$" <<<"$out3" || true)" -ge 2 ]' 15 "both reloaded workers' planes armed and the old pair gone" \
    || bad "the reloaded workers' planes did not arm under the new configuration"
bad16=""
for p in $(workers); do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    [[ $cmd == *cache* ]] && continue
    f=$(names_matching "$END_DIR" "^$p-[0-9a-f]{16}\.status$")
    c=$(sed -nE 's/^process .* config ([0-9a-f]{16}) .*/\1/p' "$END_DIR/$f" 2>/dev/null || true)
    [ "$c" = "$new16" ] && [ "$new16" != "$old16" ] || bad16="$bad16 $p=$c"
done
src=0; out=$("$SUMMARY_BIN" --status "$END_DIR" 2>&1) || src=$?
if [ "$src" = 0 ] && grep -q '^live 2, gone 2, foreign 0 ' <<<"$out" && [ "$n_conf3" = 2 ] && [ -n "$new_conf" ] \
        && [ -z "$bad16" ] && [ -f "$END_DIR/$C1" ]; then
    ok "right after the reload the old pair's files are listed gone, the exit is 0, and the changed configuration wrote its own file beside the old one, every live worker naming it"
else
    bad "the changed configuration: rc=$src, $n_conf3 conf files, workers' digests$bad16, $(grep -E '^(live|gone|conf-mismatch|refused)' <<<"$out" | tr '\n' '|')"
fi

# the altered regular file: same size and still inside the grammar, so the workers leave it (they
# replace only what is absent, of another kind, or of another size) and the reader, which checks a
# file's bytes against its name only after every line parsed, names it, exit 1. Breaking the magic
# instead would be a refusal, which is a different row's subject.
[ -n "$new_conf" ] && sed -i '/^plane reputation path /s/n"$/x"/' "$END_DIR/$new_conf"
src=0; out=$("$SUMMARY_BIN" --status "$END_DIR" 2>&1) || src=$?
if [ "$src" = 1 ] && grep -qF "conf-mismatch \"$new_conf\"" <<<"$out"; then
    ok "an altered configuration file is left in place and named: $(grep -m1 'conf-mismatch' <<<"$out")"
else
    bad "the altered configuration file: rc=$src, $(grep -m1 'conf-mismatch' <<<"$out" || echo 'no conf-mismatch line')"
fi
stop; sleep 1

# ====================================================================================================
# THE POLICY LANGUAGE, under `nginx -t`.
#
# Every row below renders a configuration and reads what the module printed while nginx tested it.
# The planes are the eight fixture files the shared generator writes (every plane present, each with
# the schema its name requires: the corpus's default environment), in a directory whose chain is
# trusted, so the compiler sees every plane and nothing is inert.
# ====================================================================================================
echo
echo "$(date -u +%H:%M:%S) == the policy language: the corpus, the places, the forms, the status list, the sugar =="

PLANES="$W/planes"
mkdir -p "$PLANES"; chmod 0755 "$PLANES"
for pl in reputation tor rpki-unreachable routing anonymizer threat registry tenant; do
    if [ "$pl" = reputation ]; then
        python3 ../core/make-test-snapshot.py --plane reputation --out "$PLANES/reputation.bin" --format 1 --schema --v6-index none --generation 5 >/dev/null
    else
        python3 ../core/make-test-snapshot.py --plane "$pl" --out "$PLANES/$pl.bin" --format 2 --schema --generation 5 >/dev/null
    fi
done
chmod 0444 "$PLANES"/*.bin

# conft <name> <text inside http{}> [<text inside server{}>] [<text before http{}>]: run `nginx -t` over a
# rendered configuration; TOUT holds everything nginx and the module printed, TRC nginx's exit status,
# TCONF the configuration's path (for the <file>:<line> every refusal must carry).
# CONFT_DATA=<dir> in the environment names the data directory in place of the fixture planes'.
conft() {
    local name=$1 http=$2 srv=${3:-} pre=${4:-}
    mkdir -p "$W/t/$name/logs"
    TCONF="$W/t/$name/nginx.conf"
    cat > "$TCONF" <<EOF
load_module $MODULE;
error_log $W/t/$name/logs/error.log info;
pid $W/t/$name/logs/nginx.pid;
events { worker_connections 64; }
$pre
http {
    access_log off;
    client_body_temp_path $W/t/$name/logs/body;
    proxy_temp_path $W/t/$name/logs/proxy;
    fastcgi_temp_path $W/t/$name/logs/fastcgi;
    uwsgi_temp_path $W/t/$name/logs/uwsgi;
    scgi_temp_path $W/t/$name/logs/scgi;
    whisper_edge_data ${CONFT_DATA:-$PLANES};
$http
    server {
        listen 127.0.0.1:$PORT;
        server_name a;
        root $W/html;
$srv
    }
}
EOF
    TRC=0
    TOUT=$(nginx -t -c "$TCONF" -p "$W/t/$name" 2>&1) || TRC=$?
}
# digest_of <line text> -> the sixteen hex digits after "program "
digest_of() { sed -n 's/.*program \([0-9a-f]\{16\}\).*/\1/p' <<<"$1"; }
# ctx_digest <TOUT> <escaped context head> -> the program digest on that context's line
ctx_digest() { digest_of "$(printf '%s\n' "$1" | grep -F "whisper edge: policy: $2 (" | head -1 || true)"; }

echo "-- the variables are not changeable (V3) --"
conft v3-set '' 'set $whisper_edge_asn x;'
[ "$TRC" != 0 ] && grep -q 'the duplicate "whisper_edge_asn" variable' <<<"$TOUT" \
    && ok "V3: set \$whisper_edge_asn is refused at configuration test (the variable is not changeable)" \
    || bad "V3: set on a module variable was not refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
conft v3-ctl '' 'set $c x;'
[ "$TRC" = 0 ] && ok "V3 control: the same set on an unrelated variable passes" \
    || bad "V3 control: set \$c x failed: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"

echo "-- the corpus: twenty programs that must compile, fifty that must be refused as their .expect says --"
CORPUS="$ROOT/core/testdata/policy"
#
# render_corpus <policy file> <conf file> <expect file or ->: the corpus's records become nginx
# directives in their contexts: `http/server:<n>` a server block (server_name <n>), `/location:<n>` a
# `location /<n>` inside it; the argument bytes go through ONE nginx quoted string, backslash and quote
# escaped, so the module receives exactly the bytes the corpus wrote and the refusal's line and column
# are the corpus's. Prints the line number of the directive the .expect names (its kind, context and
# ordinal), or 0 when there is no .expect.
#
render_corpus() {
    python3 - "$1" "$2" "$3" "$MODULE" "$W" "$PLANES" "$PORT" <<'PY'
import sys
src, out, expect, module, w, planes, port = sys.argv[1:8]
data = open(src, 'rb').read()
recs = []
for rec in data.split(b'\x1e\x0a'):
    if not rec:
        continue
    kind, rest = rec.split(b' ', 1)
    ctx, arg = rest.split(b' ', 1) if b' ' in rest else (rest, b'')
    recs.append((kind.decode(), ctx.decode(), arg))
want = None
if expect != '-':
    e = dict(l.split('\t', 1) for l in open(expect, encoding='utf-8', errors='surrogateescape').read().splitlines() if '\t' in l)
    want = (e['kind'], e['context'], int(e['rule']))
names = {'policy': 'whisper_edge_policy', 'set': 'whisper_edge_set', 'floor': 'whisper_edge_policy_floor',
         'threshold': 'whisper_edge_threshold', 'mode': 'whisper_edge_mode'}
def q(a):
    return b'"' + a.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'
# the context tree, in order of first appearance
servers = []
for kind, ctx, arg in recs:
    parts = ctx.split('/')
    if len(parts) >= 2 and parts[1].startswith('server:'):
        s = parts[1][7:]
        if s not in servers:
            servers.append(s)
locs = {s: [] for s in servers}
for kind, ctx, arg in recs:
    parts = ctx.split('/')
    if len(parts) == 3 and parts[2].startswith('location:'):
        s = parts[1][7:]
        if parts[2][9:] not in locs[s]:
            locs[s].append(parts[2][9:])
lines = []
def emit(b):
    lines.append(b)
emit(b'load_module ' + module.encode() + b';')
emit(b'error_log ' + (w + '/t/corpus/logs/error.log').encode() + b' info;')
emit(b'pid ' + (w + '/t/corpus/logs/nginx.pid').encode() + b';')
emit(b'events { worker_connections 64; }')
emit(b'http {')
for d in ('client_body_temp_path', 'proxy_temp_path', 'fastcgi_temp_path', 'uwsgi_temp_path', 'scgi_temp_path'):
    emit(b'    ' + d.encode() + b' ' + (w + '/t/corpus/logs/' + d).encode() + b';')
emit(b'    access_log off;')
emit(b'    whisper_edge_data ' + planes.encode() + b';')
ordinals = {}
target_line = 0
def directive(kind, ctx, arg, indent):
    global target_line
    key = (kind, ctx)
    ordinals[key] = ordinals.get(key, 0) + 1
    emit(b' ' * indent + names[kind].encode() + b' ' + q(arg) + b';')
    if want is not None and (kind, ctx, ordinals[key]) == want:
        # nginx records a directive at the line its `;` is read on: an argument holding LFs ends lower
        target_line = len(lines) + arg.count(b'\n')
for kind, ctx, arg in recs:
    if ctx == 'http':
        directive(kind, ctx, arg, 4)
for s in servers:
    emit(b'    server {')
    emit(b'        listen 127.0.0.1:' + port.encode() + b';')
    emit(b'        server_name ' + s.encode() + b';')
    emit(b'        root ' + (w + '/html').encode() + b';')
    for kind, ctx, arg in recs:
        if ctx == 'http/server:' + s:
            directive(kind, ctx, arg, 8)
    for l in locs[s]:
        emit(b'        location /' + l.encode() + b' {')
        for kind, ctx, arg in recs:
            if ctx == 'http/server:%s/location:%s' % (s, l):
                directive(kind, ctx, arg, 12)
        emit(b'        }')
    emit(b'    }')
emit(b'}')
open(out, 'wb').write(b'\n'.join(lines) + b'\n')
print(target_line)
PY
}
# the escaped context field the module prints for a corpus context path
ctx_field() {
    case "$1" in
        http) printf '"http"' ;;
        http/server:*/location:*) local l=${1##*/location:}; printf '"location \\"/%s\\""' "$l" ;;
        http/server:*) local s=${1#http/server:}; printf '"server \\"%s\\""' "$s" ;;
        *) printf '%s' "$1" ;;
    esac
}
mkdir -p "$W/t/corpus/logs"
accepted=0; nacc=0; tool_ok=0; tool_bad=""
LOOKUP_BIN="$ROOT/core/whisper-edge-lookup"
for f in "$CORPUS"/accept/*.policy; do
    nacc=$((nacc+1))
    render_corpus "$f" "$W/t/corpus/nginx.conf" - >/dev/null
    if out=$(nginx -t -c "$W/t/corpus/nginx.conf" -p "$W/t/corpus" 2>&1); then
        accepted=$((accepted+1))
        # the module's program digests against the lookup tool's for the same file in the same environment:
        # every program the tool compiles is one the module printed, and the module printed nothing else
        # except the default it writes for an http level that names no policy
        dflt=$(sed -n 's/.*runs the default program \([0-9a-f]\{16\}\).*/\1/p' <<<"$out" | sed -n 1p)
        t_set=$("$LOOKUP_BIN" --probe-dir "$PLANES" --programs "$f" 2>/dev/null | grep -E '^(program|floor) ' | grep -oE '\b[0-9a-f]{16}\b' | sort -u | tr '\n' ' ')
        # the default is subtracted only when the tool did not compile that program itself: a context whose
        # own text equals the default's (a `threshold high`) interns to the same digest
        case " $t_set" in *" ${dflt:-none} "*) dflt=none ;; esac
        m_set=$(grep -oE 'program [0-9a-f]{16}' <<<"$out" | cut -d' ' -f2 | grep -v -x -F "${dflt:-none}" | sort -u | tr '\n' ' ')
        if [ -n "$t_set" ] && [ "$m_set" = "$t_set" ]; then tool_ok=$((tool_ok+1)); else tool_bad="$tool_bad $(basename "$f"):module[$m_set]tool[$t_set]"; fi
    else
        bad "corpus accept: $(basename "$f") must compile and was refused: $(printf '%s' "$out" | grep -m1 'whisper edge' | cut -c1-200)"
    fi
done
[ "$accepted" = "$nacc" ] && ok "corpus accept: every one of the $nacc corpus programs that must compile compiles under nginx -t"
[ "$tool_ok" = "$nacc" ] && ok "corpus accept: and for every one of the $nacc files the module's program digests are the lookup tool's, compiled in the same environment (whisper-edge-lookup --probe-dir --programs)" \
    || bad "corpus accept: the module's and the tool's program digests differ for $((nacc - tool_ok)) of $nacc files:$(printf '%s' "$tool_bad" | cut -c1-300)"
refused=0; nref=0; fields_ok=0
for f in "$CORPUS"/refuse/*.policy; do
    nref=$((nref+1))
    e=${f%.policy}.expect
    tl=$(render_corpus "$f" "$W/t/corpus/nginx.conf" "$e")
    if out=$(nginx -t -c "$W/t/corpus/nginx.conf" -p "$W/t/corpus" 2>&1); then
        bad "corpus refuse: $(basename "$f") must be refused and compiled"
        continue
    fi
    refused=$((refused+1))
    line=$(printf '%s\n' "$out" | grep -m1 'whisper edge: policy refused:' || true)
    # the .expect fields, byte for byte, behind the directive's own file and line
    ekind=$(sed -n 's/^kind\t//p' "$e"); ectx=$(sed -n 's/^context\t//p' "$e"); erule=$(sed -n 's/^rule\t//p' "$e")
    eline=$(sed -n 's/^line\t//p' "$e"); ecol=$(sed -n 's/^col\t//p' "$e"); etok=$(sed -n 's/^token\t//p' "$e"); emsg=$(sed -n 's/^message\t//p' "$e")
    want_head="whisper edge: policy refused: $W/t/corpus/nginx.conf:$tl: whisper_edge_${ekind/floor/policy_floor} ($(ctx_field "$ectx")): rule $erule, line $eline, column $ecol: near \"$etok\": "
    if [[ $line == *"$want_head"* ]] && [[ $line == *"$emsg"* ]]; then
        fields_ok=$((fields_ok+1))
    else
        msg="corpus refuse: $(basename "$f"): the refusal does not carry its place and .expect fields: want '...${want_head#whisper edge: policy refused: $W/t/corpus/}' + '$emsg', got '${line#*whisper edge: policy refused: }'"
        bad "${msg:0:400}"
    fi
done
[ "$refused" = "$nref" ] && ok "corpus refuse: every one of the $nref corpus programs that must be refused is refused under nginx -t"
[ "$fields_ok" = "$nref" ] && ok "corpus refuse: and each refusal carries the directive's file:line, kind and context, then the .expect's rule, line, column, token and message byte for byte"
# THE CONTROLS. 01 is one byte over 2,048 and nothing else: with the one digit too many removed it must
# compile. 02 is one byte over AND carries a byte outside the alphabet: with the length fixed, the
# refusal must MOVE to the alphabet layer (the file's point is that length is checked first), so the
# control proves the length check is what fired and is gone, never that the file compiles.
for n in 01 02; do
    f=$(ls "$CORPUS"/refuse/$n-*.policy | sed -n 1p)
    if ! python3 - "$f" "$W/t/corpus/control.policy" <<'PYC'
import sys
d = open(sys.argv[1], 'rb').read()
# the record's argument is one byte over 2,048: drop the first digit of the inline list's last member
i = d.rfind(b'}')
j = d.rfind(b',', 0, i)
if i < 0 or j < 0 or i - j < 3:
    raise SystemExit('the last member of the inline list was not found')
open(sys.argv[2], 'wb').write(d[:j + 1] + d[j + 2:])
PYC
    then
        bad "corpus refuse control: $(basename "$f"): the control's input could not be made"
        continue
    fi
    render_corpus "$W/t/corpus/control.policy" "$W/t/corpus/nginx.conf" - >/dev/null
    cout=$(nginx -t -c "$W/t/corpus/nginx.conf" -p "$W/t/corpus" 2>&1) && crc=0 || crc=$?
    if [ "$n" = 01 ]; then
        [ "$crc" = 0 ] && ok "corpus refuse control: $(basename "$f") with its one byte too many removed is accepted" \
            || bad "corpus refuse control: $(basename "$f") stays refused with the offending byte removed: $(grep -m1 refused <<<"$cout" | cut -c1-200)"
    else
        [ "$crc" != 0 ] && [[ $cout =~ byte\ 0x[0-9A-Fa-f]{2}\ is\ not\ allowed ]] && ok "corpus refuse control: $(basename "$f") with its one byte too many removed is refused by the alphabet instead, so length was checked first" \
            || bad "corpus refuse control: $(basename "$f") with the length fixed did not move to the alphabet refusal: $(grep -m1 -E 'refused|syntax is ok' <<<"$cout" | cut -c1-200)"
    fi
done

echo "-- where a directive may be written --"
conft d3-if '' 'location / { if ($arg_x) { whisper_edge_policy "deny if tor_exit"; } }'
[ "$TRC" != 0 ] && grep -q '"whisper_edge_policy" directive is not allowed here' <<<"$TOUT" \
    && ok "place: whisper_edge_policy inside if {} is refused by nginx itself (no NGX_HTTP_LIF_CONF)" \
    || bad "place: whisper_edge_policy inside if {} was not refused by name: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
conft d3-limit '' 'location / { limit_except GET { whisper_edge_policy "deny if tor_exit"; } }'
[ "$TRC" != 0 ] && grep -q '"whisper_edge_policy" directive is not allowed here' <<<"$TOUT" \
    && ok "place: whisper_edge_policy inside limit_except {} is refused by nginx itself (no NGX_HTTP_LMT_CONF)" \
    || bad "place: whisper_edge_policy inside limit_except {} was not refused by name"
conft d3-ctl '' 'location / { whisper_edge_policy "deny if tor_exit"; }'
[ "$TRC" = 0 ] && ok "place control: the same line one level up, in the location, is accepted" \
    || bad "place control: the line in the location itself was refused: $(grep -m1 whisper <<<"$TOUT" | cut -c1-200)"
for d in 'whisper_edge_data /x' 'whisper_edge_snapshot /x/snapshot.bin' 'whisper_edge_trusted_proxy 10.0.0.0/8' \
         'whisper_edge_trusted_header X-Forwarded-For' 'whisper_edge_trusted_hops 2' 'whisper_edge_policy_floor "deny if tor_exit"' \
         'whisper_edge_refresh 60s' 'whisper_edge_summary off'; do
    conft d4 '' "$d;"
    name=${d%% *}
    if [ "$TRC" != 0 ] && grep -qF "\"$name\" is http level only, so that no virtual host can change the floor" <<<"$TOUT"; then
        ok "http-only: $name in a server block is refused as http level only, with the reason"
    else
        bad "http-only: $name in a server block was not refused with the http-only reason: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
    fi
done
conft d4-second 'whisper_edge_mode deny; whisper_edge_mode log;' ''
if [ "$TRC" != 0 ] && grep -qE 'whisper_edge_mode" is defined twice: here and at .*nginx.conf:[0-9]+;' <<<"$TOUT"; then
    ok "http-only: a second whisper_edge_mode at http level is refused naming both places"
else
    bad "http-only: a second http-level definition was not refused naming both places: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
fi
conft d4-one 'whisper_edge_mode deny;' ''
[ "$TRC" = 0 ] && ok "http-only control: one definition passes" || bad "http-only control: one whisper_edge_mode at http level was refused"

echo "-- sets: visible below, never copied, never redefined --"
conft d8-a 'whisper_edge_set "@e KP SY";' 'location /x { whisper_edge_policy "deny if country in @e"; }'
[ "$TRC" = 0 ] && ok "sets: an http set used in a location is accepted" || bad "sets: an http set used in a location was refused: $(grep -m1 refused <<<"$TOUT" | cut -c1-200)"
conft d8-b '' 'location /p { whisper_edge_set "@e KP"; location /p/c { whisper_edge_policy "deny if country in @e"; } }'
[ "$TRC" = 0 ] && ok "sets: a location set used by its child is accepted" || bad "sets: a location set used by its child was refused: $(grep -m1 refused <<<"$TOUT" | cut -c1-200)"
conft d8-c 'whisper_edge_set "@e KP";' 'whisper_edge_set "@e KP SY"; whisper_edge_policy "deny if country in @e";'
[ "$TRC" != 0 ] && grep -q 'policy refused:.*whisper_edge_set.*shadowing' <<<"$TOUT" \
    && ok "sets: the same name redefined below is refused (a shadowing declaration)" \
    || bad "sets: a redefinition below was not refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
conft d8-d '' 'location /x { whisper_edge_set "@e KP"; } location /y { whisper_edge_policy "deny if country in @e"; }'
[ "$TRC" != 0 ] && grep -q 'policy refused:.*@e undefined in this context or an enclosing one' <<<"$TOUT" \
    && ok "sets: a sibling's set is not visible: the use is refused as undefined" \
    || bad "sets: a sibling's set was accepted or refused otherwise: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
conft d8-e '' 'location /x { whisper_edge_set "@e KP"; } location /y { whisper_edge_set "@e KP"; whisper_edge_policy "deny if country in @e"; }'
[ "$TRC" = 0 ] && ok "sets control: the sibling's own declaration makes it accepted" || bad "sets control: the sibling's own declaration was refused: $(grep -m1 refused <<<"$TOUT" | cut -c1-200)"

echo "-- the argument forms: one digest for every accepted spelling --"
conft d11-a '' 'whisper_edge_policy "deny if tor_exit";'; da=$(ctx_digest "$TOUT" '"server \"a\""')
conft d11-b '' 'whisper_edge_policy deny if tor_exit;'; db=$(ctx_digest "$TOUT" '"server \"a\""')
conft d11-c '' 'whisper_edge_policy deny    if    tor_exit;'; dc=$(ctx_digest "$TOUT" '"server \"a\""')
conft d11-d '' "whisper_edge_policy 'deny if tor_exit';"; dd=$(ctx_digest "$TOUT" '"server \"a\""')
if [ -n "$da" ] && [ "$da" = "$db" ] && [ "$da" = "$dc" ] && [ "$da" = "$dd" ]; then
    ok "forms: quoted, unquoted, extra spaces and single-quoted spellings compile to one program ($da)"
else
    bad "forms: the spellings compiled to different programs: '$da' '$db' '$dc' '$dd'"
fi
conft d11-e '' 'whisper_edge_policy deny if country in { KP SY };'
[ "$TRC" != 0 ] && grep -q 'directive "whisper_edge_policy" is not terminated by ";"' <<<"$TOUT" \
    && ok "forms: an unquoted inline set is refused by nginx's own lexer (the brace opens a block), as the README says" \
    || bad "forms: an unquoted inline set was not refused by nginx: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
conft d11-f '' 'whisper_edge_policy "deny if country in { KP SY }";'; df=$(ctx_digest "$TOUT" '"server \"a\""')
[ "$TRC" = 0 ] && [ -n "$df" ] && ok "forms: its quoted twin is accepted and names its program ($df)" \
    || bad "forms: the quoted inline set was refused: $(grep -m1 refused <<<"$TOUT" | cut -c1-200)"
conft d11-g '' 'whisper_edge_set "@p AS64496"; whisper_edge_policy "allow if asn in @p";'; dg=$(ctx_digest "$TOUT" '"server \"a\""')
conft d11-h '' 'whisper_edge_set "@partners AS64496"; whisper_edge_policy "allow if asn in @partners";'; dh=$(ctx_digest "$TOUT" '"server \"a\""')
[ -n "$dg" ] && [ -n "$dh" ] && [ "$dg" != "$dh" ] && ok "forms control: another set name is another canonical text, so another digest ($dg vs $dh)" \
    || bad "forms control: two set names gave the digests '$dg' and '$dh'"

echo "-- the deny status list, the configuration-test half --"
for c in 401 405 407 421 426 494 495 496 497 499 511 460 408 414 501 411 412 416 417 431 502 504 505 402 500 503; do
    conft d12 '' "whisper_edge_deny_status $c;"
    if [ "$TRC" != 0 ] && grep -qE "whisper_edge_deny_status $c refused: .*; use 403" <<<"$TOUT"; then
        PASS=$((PASS+1))
    else
        bad "status list: whisper_edge_deny_status $c was not refused with its reason and 'use 403': $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
    fi
done
printf '  ok    status list: the 26 codes outside the list are each refused naming the header or the reason, ending "use 403" (counted above)\n'
acc=0
for c in 400 403 404 406 409 410 413 415 422 428 429 451 444; do
    conft d12 '' "whisper_edge_deny_status $c;"
    [ "$TRC" = 0 ] && acc=$((acc+1)) || bad "status list: accepted code $c was refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
done
[ "$acc" = 13 ] && ok "status list: the twelve codes of the list and nginx's 444 are accepted"
conft d12-x '' 'whisper_edge_deny_status abc;'
[ "$TRC" != 0 ] && grep -q 'takes a status code, not "abc"; use 403' <<<"$TOUT" && ok "status list: a non-numeric status is refused with the way out" \
    || bad "status list: 'abc' was not refused with the way out"

echo "-- the sugar is the canonical rule (G1+) --"
# the five thresholds: a context carrying `whisper_edge_threshold L` and a sibling carrying the canonical
# line compile to ONE program: the context lines name the same digest
for lvl in low medium high critical; do
    conft g1 '' "location /s { whisper_edge_threshold $lvl; } location /c { whisper_edge_policy \"deny if listed >= $lvl\"; }"
    ds=$(ctx_digest "$TOUT" '"location \"/s\""'); dcc=$(ctx_digest "$TOUT" '"location \"/c\""')
    if [ -n "$ds" ] && [ "$ds" = "$dcc" ]; then
        ok "G1+: whisper_edge_threshold $lvl and \"deny if listed >= $lvl\" are one program ($ds)"
    else
        bad "G1+: threshold $lvl compiled to '$ds' and its canonical line to '$dcc'"
    fi
done
conft g1-off '' 'location /s { whisper_edge_threshold off; }'
grep -qE '"location \\"/s\\"" \(.*\): no rules \(threshold off\), program [0-9a-f]{16}, mode log' <<<"$TOUT" && ok "G1+: whisper_edge_threshold off compiles to the empty program, and the line says so" \
    || bad "G1+: threshold off did not print as the empty program: $(grep -m1 'location' <<<"$TOUT" | cut -c1-200)"
conft g1-mix '' 'whisper_edge_policy "deny if tor_exit"; whisper_edge_threshold low;'
[ "$TRC" != 0 ] && grep -q 'whisper_edge_threshold in a context with policy lines. write the equivalent rule: deny if listed >= low' <<<"$TOUT" \
    && ok "G1+: a threshold beside policy lines is refused, printing the equivalent rule" \
    || bad "G1+: a threshold beside policy lines was not refused with the equivalent rule: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
# G1+ control: a mutant that spaces the sugar differently would change the canonical text; the one the
# core suite runs (WE_TEST_SUGAR_SPACE) is not buildable from here, so the control is the one above:
# two texts that differ (the forms row's two set names) give two digests, and these two give one.

echo "-- the configuration-time lines name every context and the default --"
conft lines 'whisper_edge_policy_floor "deny if tor_exit";' 'location /api { whisper_edge_policy "deny if listed >= high"; whisper_edge_mode deny; }'
grep -qE 'whisper edge: policy: "http" \(.*nginx.conf:[0-9]+\): no lines of its own; runs the default program [0-9a-f]{16} \(deny if listed >= high\) under mode log' <<<"$TOUT" \
    && ok "default: the http level with no policy or threshold line runs the default, deny if listed >= high under mode log, and the line says so" \
    || bad "default: the default line is missing or wrong: $(grep -m1 '"http"' <<<"$TOUT" | cut -c1-220)"
grep -qE 'whisper edge: policy: floor \(.*nginx.conf:[0-9]+\): 1 rule, program [0-9a-f]{16}, mode log and deny status 403 from the http level' <<<"$TOUT" \
    && ok "floor line: the floor line names its place, its program, and the http level's mode and deny status" \
    || bad "floor line: the floor line is missing or wrong: $(grep -m1 'floor' <<<"$TOUT" | cut -c1-220)"
grep -qE 'whisper edge: policy: "location \\"/api\\"" \(.*nginx.conf:[0-9]+\): 1 rule, program [0-9a-f]{16}, mode deny, inherits nothing' <<<"$TOUT" \
    && ok "lines: a context with lines of its own names its place, its rule count, its program and its mode" \
    || bad "lines: the location's line is missing or wrong: $(grep -m1 '/api' <<<"$TOUT" | cut -c1-220)"
grep -qE 'whisper edge: policy: "server \\"a\\"" \(.*nginx.conf:[0-9]+\): no lines of its own; runs program [0-9a-f]{16} \(1 rule\) under mode log' <<<"$TOUT" \
    && ok "lines: a context without lines names the program it inherits" \
    || bad "lines: the server's line is missing or wrong: $(grep -m1 'server' <<<"$TOUT" | cut -c1-220)"
grep -qE 'whisper edge: policy: data ".*planes": reputation generation 5 digest [0-9a-f]{16}; tor generation 5 digest [0-9a-f]{16}; rpki-unreachable present, not bound: nothing in this configuration reads it;' <<<"$TOUT" \
    && ok "data line: the data line names each present plane's generation and digest, and says which present planes nothing reads" \
    || bad "data line: the data line is missing or wrong: $(grep -m1 'data "' <<<"$TOUT" | cut -c1-260)"
grep -qE 'distinct programs and the floor, [0-9]+ hot bytes in all .*; read-only regions: program [0-9a-f]+-[0-9a-f]+' <<<"$TOUT" \
    && ok "G4: the summary line prints the configuration-wide hot bytes and the sealed regions" \
    || bad "G4: the summary line is missing or wrong: $(grep -m1 'distinct' <<<"$TOUT" | cut -c1-220)"
# a refusal's line, in the shape the modules share, read from one planted refusal
conft d15 '' 'whisper_edge_policy "deny if tor_exit garbage";'
grep -qE "whisper edge: policy refused: $W/t/d15/nginx.conf:[0-9]+: whisper_edge_policy \(\"server \\\\\"a\\\\\"\"\): rule 1, line 1, column [0-9]+: near \"garbage\": " <<<"$TOUT" \
    && ok "lines: a refusal is the directive's file:line, its name and escaped context, then the compiler's rule, line, column and token" \
    || bad "lines: the refusal line is not in the shared shape: $(grep -m1 refused <<<"$TOUT" | cut -c1-260)"

echo "-- the files that define the http level pass the trust rule (StrictModes) --"
# conft_file <name> <module.so> <conf text>: nginx -t over a configuration written as given, in its own
# directory under $W/t/<name>, which the arms below reshape (an open include file, an open ancestor, a
# symlink into an open tree); TOUT and TRC as conft's
conft_file() {
    local name=$1 text=$2
    mkdir -p "$W/t/$name/logs"
    TCONF="$W/t/$name/nginx.conf"
    printf '%s\n' "$text" > "$TCONF"
    TRC=0
    TOUT=$(nginx -t -c "$TCONF" -p "$W/t/$name" 2>&1) || TRC=$?
}
sm_conf() { # <dir> <include line> [<module>]: the configuration whose http level includes a file
    cat <<EOF
load_module ${3:-$MODULE};
error_log $1/logs/error.log info;
pid $1/logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $1/logs/body; proxy_temp_path $1/logs/proxy; fastcgi_temp_path $1/logs/fastcgi;
    uwsgi_temp_path $1/logs/uwsgi; scgi_temp_path $1/logs/scgi;
    whisper_edge_data $PLANES;
    $2
    server { listen 127.0.0.1:$PORT; server_name a; root $W/html; }
}
EOF
}
# (a) an http-level directive in a group-writable included file
D=$W/t/sm-a; mkdir -p "$D/conf.d" "$D/logs"
printf 'whisper_edge_mode deny;\n' > "$D/conf.d/floor.conf"; chmod 0664 "$D/conf.d/floor.conf"
conft_file sm-a "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
if [ "$TRC" != 0 ] && grep -qE "whisper edge: $D/conf.d/floor.conf holds http-level whisper_edge_\* directives \(whisper_edge_mode at line 1\), and \"$D/conf.d/floor.conf\" has mode 0664, writable by its group; .*chmod 0644" <<<"$TOUT"; then
    ok "StrictModes: a group-writable included file holding an http-level directive is refused naming the file, its mode and the fix"
else
    bad "StrictModes: the group-writable include was not refused as specified: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-260)"
fi
chmod 0644 "$D/conf.d/floor.conf"
conft_file sm-a "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
[ "$TRC" = 0 ] && ok "StrictModes control: chmod g-w on the file makes the same configuration pass" \
    || bad "StrictModes control: the file closed to its group was still refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
# (b) a group-writable ancestor of the included file
chmod 0775 "$D/conf.d"
conft_file sm-a "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
if [ "$TRC" != 0 ] && grep -qE "and \"$D/conf.d\" has mode 0775, writable by its group; .*chmod g-w,o-w" <<<"$TOUT"; then
    ok "StrictModes: a group-writable ancestor directory is refused naming the directory, its mode and the fix"
else
    bad "StrictModes: the group-writable ancestor was not refused as specified: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-260)"
fi
chmod 0755 "$D/conf.d"
conft_file sm-a "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
[ "$TRC" = 0 ] && ok "StrictModes control: chmod g-w on the ancestor makes it pass" \
    || bad "StrictModes control: the closed ancestor was still refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
# (c) a symlinked include directory resolving into a tree writable by others: judged by what it resolves to
D=$W/t/sm-c; mkdir -p "$D/tenant/conf" "$D/logs"; chmod 0777 "$D/tenant"
printf 'whisper_edge_mode deny;\n' > "$D/tenant/conf/floor.conf"; chmod 0644 "$D/tenant/conf/floor.conf"; chmod 0755 "$D/tenant/conf"
ln -sfn "$D/tenant/conf" "$D/conf.d"
conft_file sm-c "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
if [ "$TRC" != 0 ] && grep -qE "and \"$D/tenant\" has mode 0777, writable by world" <<<"$TOUT"; then
    ok "StrictModes: an include directory that is a symlink into a world-writable tree is refused by the tree it resolves to"
else
    bad "StrictModes: the symlinked include into an open tree was not refused by its resolved chain: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-260)"
fi
if build_control -DWE_MOD_TEST_LEXICAL; then
    conft_file sm-c "$(sm_conf "$D" "include $D/conf.d/*.conf;" "$CTL_OUT")"
    [ "$TRC" = 0 ] && ok "StrictModes control: a build that walks the path as written (never resolving the link) accepts the tenant's tree, so the resolved walk is what refuses it" \
        || bad "StrictModes control: the lexical-walk build refused the symlinked include too: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
else
    control_unavailable "StrictModes control (the lexical-walk build)"
fi
# (d) a configuration file under a root-owned sticky ancestor is accepted, as sshd accepts /tmp above a key
D=/tmp/whisper-edge-nginx-gate.$$; mkdir -p "$D/logs" "$D/conf.d"; chmod 0700 "$D"
printf 'whisper_edge_mode deny;\n' > "$D/conf.d/floor.conf"; chmod 0644 "$D/conf.d/floor.conf"
if [ "$(stat -c %u /tmp)" = 0 ] && (( (0$(stat -c %a /tmp) & 01000) != 0 )); then
    conft_file sm-d "$(sm_conf "$D" "include $D/conf.d/*.conf;")"
    [ "$TRC" = 0 ] && ok "StrictModes: a configuration file under a root-owned sticky ancestor (/tmp) is accepted" \
        || bad "StrictModes: the file under the sticky root-owned /tmp was refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
else
    notproven "StrictModes: /tmp on this host is not a root-owned sticky directory, so the sticky-ancestor arm has no fixture"
fi
rm -rf "$D"
# the reader-is-the-worker warning: this gate runs nginx as its own user, so the trusted owner is that uid
conft sm-reader '' ''
grep -q "the configuration is read by uid $(id -u), which is also the uid the workers run as" <<<"$TOUT" \
    && ok "StrictModes: a configuration read by the workers' own uid says that the trusted owner is that uid" \
    || bad "StrictModes: the reader-is-worker warning is missing: $(grep -m1 'read by uid' <<<"$TOUT" | cut -c1-200)"

echo "-- the floor runs under the http level's mode, and says when a server block expects more --"
conft floor-log 'whisper_edge_policy_floor "deny if tor_exit";' 'whisper_edge_mode deny;'
grep -qE 'floor \(.*nginx.conf:[0-9]+\): 1 rule, program [0-9a-f]{16}, mode log and deny status 403 from the http level' <<<"$TOUT" \
    && grep -q 'the floor will not deny: its mode is the http level'"'"'s (log); add "whisper_edge_mode deny" at http level' <<<"$TOUT" \
    && ok "floor line: a floor at http level with mode deny only in a server block prints the floor under mode log and the will-not-deny line" \
    || bad "floor line: the will-not-deny line is missing: $(grep -m1 'floor' <<<"$TOUT" | cut -c1-200)"
conft floor-deny 'whisper_edge_policy_floor "deny if tor_exit"; whisper_edge_mode deny;' 'whisper_edge_mode deny;'
grep -q 'mode deny and deny status 403 from the http level' <<<"$TOUT" && ! grep -q 'the floor will not deny' <<<"$TOUT" \
    && ok "floor line control: with whisper_edge_mode deny at http level the floor runs under deny and the warning is absent" \
    || bad "floor line control: the warning fired, or the floor is not under deny: $(grep -m1 'floor' <<<"$TOUT" | cut -c1-200)"
conft floor-status 'whisper_edge_policy_floor "deny if tor_exit"; whisper_edge_mode deny;' 'whisper_edge_deny_status 451;'
grep -q "a whisper_edge_deny_status set in a server or location applies to that context's own rules only; the floor and the pre-stage deny with the http level's 403" <<<"$TOUT" \
    && ok "floor line: a deny status set in a context is said to reach that context's rules only, the floor keeping the http level's" \
    || bad "floor line: the deny-status note is missing: $(grep -m1 'deny_status' <<<"$TOUT" | cut -c1-200)"
conft floor-status-ctl 'whisper_edge_policy_floor "deny if tor_exit"; whisper_edge_mode deny; whisper_edge_deny_status 451;' ''
grep -q 'deny status 451 from the http level' <<<"$TOUT" && ! grep -q 'applies to that context' <<<"$TOUT" \
    && ok "floor line control: an http-level deny status is the floor's own, and no note is printed" \
    || bad "floor line control: the http-level status did not reach the floor line: $(grep -m1 'floor' <<<"$TOUT" | cut -c1-200)"
conft floor-allow 'whisper_edge_policy_floor "allow if tor_exit";' ''
[ "$TRC" != 0 ] && grep -q 'policy refused:.*whisper_edge_policy_floor' <<<"$TOUT" \
    && ok "floor: an allow rule in the floor is refused (the floor takes deny and log only)" \
    || bad "floor: an allow in the floor was accepted: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"

echo
# refused_at_conf <plane> <fragment...>: nginx -t (TRC, TOUT) accepted the configuration, said the core's
# sentence for the plane with every fragment in its reason, and the data line names the plane refused; a
# plane refused at configuration reads unknown while every other plane binds and serves
refused_at_conf() {
    local pl=$1 line; shift
    [ "$TRC" = 0 ] || return 1
    line=$(grep -F "whisper edge: plane $pl is refused at configuration and reads unknown until it is fixed and the configuration reloaded; every other plane binds and serves: " <<<"$TOUT" | sed -n 1p)
    [ -n "$line" ] || return 1
    for f in "$@"; do grep -qF -- "$f" <<<"$line" || return 1; done
    grep -qE "(data \"[^\"]*\":|data:|snapshot \"[^\"]*\":)( .*;)? $pl refused at configuration|snapshot \"[^\"]*\": $pl, refused at configuration" <<<"$TOUT"
}
echo "$(date -u +%H:%M:%S) == the data directory's chain, and the descriptor the binding holds =="
# A plane directory is reached through a chain the binding judges once: every directory from / down owned
# by root or the worker uid and closed to group and world, and a link in the chain followed only when a
# trusted owner made it. A tenant who can write the directory above the link, or who owns the link, could
# otherwise aim the module at planes of their choosing. Once bound, the module reads through the directory
# DESCRIPTOR it holds, so repointing the link afterwards changes nothing it reads: the status says the path
# was replaced, the planes keep serving from the held directory, a generation published there still arms,
# one published where the path now points is never read, and a reload is what follows the path again.
DCHAIN="$W/dchain"
dchain_clean() { [ -e "$DCHAIN" ] || return 0; rm -rf "$DCHAIN" 2>/dev/null || sudo -n rm -rf "$DCHAIN" 2>/dev/null || true; }
dchain_clean
mkdir -p "$DCHAIN/site" "$DCHAIN/real" "$DCHAIN/empty" "$DCHAIN/counters"
chmod 0755 "$DCHAIN" "$DCHAIN/site" "$DCHAIN/real" "$DCHAIN/empty" "$DCHAIN/counters"
cp "$PLANES/reputation.bin" "$DCHAIN/real/reputation.bin"; chmod 0444 "$DCHAIN/real/reputation.bin"
ln -s "$DCHAIN/real" "$DCHAIN/site/edge-data"
# dchain_publish <dir> <generation>: a reputation plane written the way the refresh writes one, a temp renamed in
dchain_publish() {
    python3 ../core/make-test-snapshot.py --plane reputation --out "$1/.reputation.tmp" --format 1 --schema --v6-index none --generation "$2" >/dev/null
    chmod 0444 "$1/.reputation.tmp"; mv -f "$1/.reputation.tmp" "$1/reputation.bin"
}
# the link's directory writable by its group: the tenant-writable /srv/site of the row
chmod 0775 "$DCHAIN/site"
CONFT_DATA="$DCHAIN/site/edge-data" conft dchain-open ''
if refused_at_conf reputation "whisper_edge_data $DCHAIN/site/edge-data" '"site"' "uid $(id -u)" 'writable by others'; then
    ok "data chain: a data directory reached through a group-writable directory refuses its planes at configuration (nginx -t passes, the others would serve), the core's sentence naming the directory, its owner and the rule"
else
    bad "data chain: the link under a group-writable directory was not refused as specified: $(grep -m1 -E 'refused|syntax is ok' <<<"$TOUT" | cut -c1-300)"
fi
chmod 0755 "$DCHAIN/site"
CONFT_DATA="$DCHAIN/site/edge-data" conft dchain-closed ''
[ "$TRC" = 0 ] && grep -qF "data \"$DCHAIN/site/edge-data\": reputation generation 5 digest" <<<"$TOUT" \
    && ok "data chain control: the same link with its directory closed to the group (chmod g-w) is accepted, and the data line names the plane behind it" \
    || bad "data chain control: the closed directory was still refused, or the data line is missing: $(grep -m1 -E 'refused|data \"' <<<"$TOUT" | cut -c1-300)"
# a link another uid made, and a root-owned link in a root-owned directory: root sets them up
if sudo -n true 2>/dev/null; then
    sudo -n chown -h 65534:65534 "$DCHAIN/site/edge-data"
    CONFT_DATA="$DCHAIN/site/edge-data" conft dchain-foreign ''
    if refused_at_conf reputation "whisper_edge_data $DCHAIN/site/edge-data" '"edge-data"' 'uid 65534'; then
        ok "data chain: a link owned by another uid, in a trusted directory, refuses the planes behind it at configuration, the core's sentence naming the link and its owner"
    else
        bad "data chain: the foreign-owned link was not refused as specified: $(grep -m1 -E 'refused|syntax is ok' <<<"$TOUT" | cut -c1-300)"
    fi
    sudo -n chown -h "$(id -u):$(id -g)" "$DCHAIN/site/edge-data"
    sudo -n mkdir -p "$DCHAIN/rootdir"; sudo -n chmod 0755 "$DCHAIN/rootdir"; sudo -n ln -s "$DCHAIN/real" "$DCHAIN/rootdir/edge-data"
    CONFT_DATA="$DCHAIN/rootdir/edge-data" conft dchain-root ''
    [ "$TRC" = 0 ] && grep -qF "data \"$DCHAIN/rootdir/edge-data\": reputation generation 5 digest" <<<"$TOUT" \
        && ok "data chain control: a root-owned link in a root-owned directory is accepted" \
        || bad "data chain control: the root-owned link was refused: $(grep -m1 -E 'refused|data \"' <<<"$TOUT" | cut -c1-300)"
    sudo -n rm -rf "$DCHAIN/rootdir"
else
    notproven "data chain: the foreign-owned link arm and its root-owned control need root for their setup, and sudo -n is not available here"
fi
# the held descriptor: a server bound through a trusted link, the link repointed under it
ln -s "$DCHAIN/real" "$DCHAIN/link"
mkdir -p "$W/html/dchain"; echo page > "$W/html/dchain/index.html"
DATA_DIR="$DCHAIN/link" SERVER_EXTRA='access_log '"$W"'/logs/dchain.log dchain;' \
    mkconf 1s "whisper_edge_summary $DCHAIN/counters;" 'log_format dchain "$request_uri $status $whisper_edge_generations";'
: > "$W/logs/error.log"; : > "$W/logs/dchain.log"
dchain_plane() { cat "$DCHAIN"/counters/[0-9]*.status 2>/dev/null | grep '^plane reputation ' || true; }   # the workers' files, never conf-*
dchain_armed() { dchain_plane | grep -c "^plane reputation armed generation $1 " || true; }
dchain_tick() { cat "$DCHAIN"/counters/[0-9]*.status 2>/dev/null | grep -o ' tick [0-9]*' | sed -n 1p | tr -dc '0-9'; }
dchain_gen() { grep -m1 -F "/dchain/?q=$1 " "$W/logs/dchain.log" 2>/dev/null | grep -oE 'reputation:[0-9]+\.[0-9a-f]{8}[^ ]*' || true; }
start
if await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /dchain/)" = 200 ] && [ "$(dchain_armed 5)" = 2 ]' 15 "the data-chain server's startup"; then
    ok "data chain: bound through a trusted link, both workers arm the generation the link's target holds (5)"
else
    bad "data chain: the server bound through the link did not arm generation 5 in both workers: $(dchain_plane | cut -c1-120 | tr '\n' '|')$(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
code /dchain/?q=before >/dev/null
d8=$(dchain_plane | grep -o 'generation 5 digest [0-9a-f]\{16\}' | sed -n 1p | cut -d' ' -f4 | cut -c1-8)
[ -n "$d8" ] && [ "$(dchain_gen before)" = "reputation:5.$d8" ] \
    && ok "data chain: a judged request's \$whisper_edge_generations names generation 5 and the status file's digest prefix ($d8), no lazy mark" \
    || bad "data chain: the request before the repoint logged \"$(dchain_gen before)\", not reputation:5.$d8"
ln -sfn "$DCHAIN/empty" "$DCHAIN/link"
if await '[ "$(dchain_plane | grep -c "data-directory-replaced")" = 2 ]' 10 "the replaced flag"; then
    [ "$(dchain_armed 5)" = 2 ] \
        && ok "data chain: the link repointed under the running server: both workers say data-directory-replaced and stay armed at 5 (the held descriptor is read, not the path)" \
        || bad "data chain: the repoint changed what the workers serve: $(dchain_plane | grep -o 'armed generation [0-9]*' | tr '\n' '|')"
else
    bad "data chain: no data-directory-replaced within 10 s of the repoint: $(dchain_plane | cut -c1-120 | tr '\n' '|')"
fi
[ "$(grep -c "the data directory $DCHAIN/link was replaced under its path; reload to apply" "$W/logs/error.log")" = 2 ] \
    && ok "data chain: and each worker logged the replacement once, with the fix (reload to apply)" \
    || bad "data chain: the replacement line count is $(grep -c 'was replaced under its path' "$W/logs/error.log"), not 2 (one per worker)"
src=0; out=$("$SUMMARY_BIN" --status "$DCHAIN/counters" 2>&1) || src=$?
[ "$src" = 1 ] && [ "$(grep -c '^process pid .* data-directory-replaced' <<<"$out")" = 2 ] \
    && ok "data chain: --status exits 1 and flags both live workers data-directory-replaced" \
    || bad "data chain: --status rc=$src: $(grep -E '^(process|live)' <<<"$out" | tr '\n' '|' | cut -c1-300)"
dchain_publish "$DCHAIN/real" 6
await '[ "$(dchain_armed 6)" = 2 ]' 15 "generation 6 through the held directory" \
    && ok "data chain: a generation published into the HELD directory arms in both workers (6): the module reads the descriptor it bound" \
    || bad "data chain: generation 6 in the held directory did not arm: $(dchain_plane | grep -o 'armed generation [0-9]*' | tr '\n' '|')"
code /dchain/?q=held >/dev/null
[[ $(dchain_gen held) =~ ^reputation:6\.[0-9a-f]{8}$ ]] && ok "data chain: and a request decided after it names generation 6: $(dchain_gen held)" \
    || bad "data chain: the request after the held publish logged \"$(dchain_gen held)\""
dchain_publish "$DCHAIN/empty" 7
t0=$(dchain_tick); t0=${t0:-0}
await '[ "$(dchain_tick)" -ge '"$((t0 + 3))"' ]' 15 "three ticks" || bad "data chain: the tick did not advance three times in 15 s"
[ "$(dchain_armed 6)" = 2 ] && [ "$(dchain_armed 7)" = 0 ] \
    && ok "data chain: a generation placed where the PATH now points (7) is never read: three ticks later both workers still serve 6" \
    || bad "data chain: the path's new target was read: $(dchain_plane | grep -o 'armed generation [0-9]*' | tr '\n' '|')"
code /dchain/?q=path >/dev/null
[[ $(dchain_gen path) =~ ^reputation:6\.[0-9a-f]{8}$ ]] && ok "data chain: and a request still names generation 6" \
    || bad "data chain: the request after the path publish logged \"$(dchain_gen path)\""
# the old pair keeps accepting until the master tells it to quit, a moment after the new pair's first status
# line, so the request below waits for the old workers to be gone or it can be decided at generation 6
dchain_old=$(workers)
signal_master reload
await '[ "$(dchain_armed 7)" = 2 ]' 15 "the reload follows the path" \
    && ok "data chain: a reload binds the link's CURRENT target: the new workers arm generation 7 from it (the old pair's files keep 6)" \
    || bad "data chain: after the reload no two workers arm generation 7: $(dchain_plane | grep -o 'armed generation [0-9]*' | tr '\n' '|')"
dchain_gone() { local p; for p in $dchain_old; do kill -0 "$p" 2>/dev/null && return 1; done; return 0; }
await 'dchain_gone && [ "$(code /dchain/)" = 200 ]' 15 "the old pair gone and the new one serving" || bad "data chain: the old workers did not leave, or the new ones do not serve, after the reload"
code /dchain/?q=reloaded >/dev/null
[[ $(dchain_gen reloaded) =~ ^reputation:7\.[0-9a-f]{8}$ ]] && ok "data chain: and a request after the reload names generation 7: $(dchain_gen reloaded)" \
    || bad "data chain: the request after the reload logged \"$(dchain_gen reloaded)\""
stop; sleep 1
# The controls, each against the row it proves. The resolved chain judged alone (realpath first) follows a
# link in a group-writable directory, so the group-writable link row's refusal is gone; the plane name
# re-checked through the configured path, not the held descriptor, revokes the plane once the link is
# repointed, where the held descriptor keeps it armed.
if build_control -DWE_MOD_TEST_RESOLVED_CHAIN_ONLY; then
    ln -sfn "$DCHAIN/real" "$DCHAIN/site/edge-data"; chmod 0775 "$DCHAIN/site"
    MODULE="$CTL_OUT" CONFT_DATA="$DCHAIN/site/edge-data" conft dchain-ctl-open ''
    chmod 0755 "$DCHAIN/site"
    ! refused_at_conf reputation && grep -qE "data \"$DCHAIN/site/edge-data\": reputation generation [0-9]+ digest" <<<"$TOUT" \
        && ok "data chain control (the resolved chain judged alone): fails the group-writable link row, the link followed and its plane bound" \
        || bad "data chain control (the resolved chain judged alone): rc $TRC, $(grep -m1 -E 'refused|data \"' <<<"$TOUT" | cut -c1-200); the row passed without the code it proves"
else
    control_unavailable "data chain control (the resolved chain judged alone)"
fi
# The tenant plane's name is re-checked on every tick, and the held descriptor is what it is checked
# through: repointed at a directory with no tenant.bin, the link leaves the tenant plane armed in both
# workers. The control re-checks the name through the configured path and revokes it.
python3 ../core/make-test-snapshot.py --plane tenant --out "$DCHAIN/real/tenant.bin" --format 2 --schema --generation 5 >/dev/null
chmod 0444 "$DCHAIN/real/tenant.bin"
dchain_tenant() { # <module> <tag>: the server bound through the link, the link repointed; leaves DCHAIN_T (tenant's words after)
    local cd="$DCHAIN/counters-$2"
    rm -rf "$DCHAIN/empty2" "$cd"; mkdir -p "$DCHAIN/empty2"; chmod 0755 "$DCHAIN/empty2"
    ln -sfn "$DCHAIN/real" "$DCHAIN/link"; DCHAIN_T=""
    DATA_DIR="$DCHAIN/link" MODULE="$1" mkconf 1s "whisper_edge_summary $cd;"
    dchain_tw() { { cat "$cd"/[0-9]*.status 2>/dev/null | grep -o '^plane tenant [a-z]*' || true; } | sort | uniq -c | awk '{printf "%s x%s ", $4, $1}'; }
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(dchain_tw)" = "armed x2 " ]' 15 "tenant armed through the link"; then
        ln -sfn "$DCHAIN/empty2" "$DCHAIN/link"
        await '[ "$(cat "$cd"/[0-9]*.status 2>/dev/null | grep -c "data-directory-replaced")" -ge 2 ]' 10 "the repoint seen" || true
        sleep 3                                  # three more ticks for a name check to act
        DCHAIN_T=$(dchain_tw)
    else
        DCHAIN_T="no start: $(dchain_tw)$(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-160)"
    fi
    stop; sleep 1
}
dchain_tenant "$MODULE" real
[ "$DCHAIN_T" = "armed x2 " ] \
    && ok "data chain: the tenant plane stays armed in both workers once the link is repointed at a directory without tenant.bin (its name is checked through the held descriptor)" \
    || bad "data chain: after the repoint the tenant plane reads \"$DCHAIN_T\""
if build_control -DWE_MOD_TEST_REOPEN_BY_PATH; then
    dchain_tenant "$CTL_OUT" ctl
    [ "$DCHAIN_T" != "armed x2 " ] && [[ $DCHAIN_T != "no start"* ]] \
        && ok "data chain control (the name re-checked through the path): fails the row, the tenant plane reads $DCHAIN_T after the repoint" \
        || bad "data chain control (the name re-checked through the path): tenant reads \"$DCHAIN_T\"; the row passed without the code it proves"
else
    control_unavailable "data chain control (the name re-checked through the path)"
fi
dchain_clean

echo
echo "$(date -u +%H:%M:%S) == replace: a parent of four rules and a child of one =="
# A context with lines of its own runs those lines and nothing of its parent's: the child's program is its
# one rule, the parent's four stay the parent's, and the configuration test says once what the child
# replaced. The listed client is denied under the parent (its fourth rule) and allowed under the child
# (whose one rule only logs), each request's program digest naming the context that judged it, and the
# per-rule counters move for exactly the rules that fired in exactly the context that ran them.
mkdir -p "$W/html/d7"; echo page > "$W/html/d7/index.html"
SERVER_EXTRA='whisper_edge_mode deny;
        whisper_edge_policy "log if listed >= low";
        whisper_edge_policy "log if listed >= medium";
        whisper_edge_policy "log if listed >= critical";
        whisper_edge_policy "deny if listed >= high";
        access_log '"$W"'/logs/d7.log d7;
        location /d7/ { whisper_edge_policy "log if listed >= low"; }' \
    mkconf 1s 'log_format d7 "$request_uri $status action=$whisper_edge_action rule_id=$whisper_edge_rule_id logged=$whisper_edge_logged program=\"$whisper_edge_program\"";'
: > "$W/logs/error.log"; : > "$W/logs/d7.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /d7/index.html "$UNLISTED")" = 200 ]' 10 "the replace server's startup" || bad "replace: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
d7_srv=$(grep -oE '"server #1" \([^)]*\): 4 rules, program [0-9a-f]{16}, mode deny, inherits nothing' "$W/logs/start.err" | grep -oE 'program [0-9a-f]{16}' | cut -d' ' -f2)
d7_loc=$(grep -oE '"location \\"/d7/\\"" \([^)]*\): 1 rule, program [0-9a-f]{16}, mode deny' "$W/logs/start.err" | grep -oE 'program [0-9a-f]{16}' | cut -d' ' -f2)
[ -n "$d7_srv" ] && [ -n "$d7_loc" ] && [ "$d7_srv" != "$d7_loc" ] \
    && ok "replace: the configuration test prints the parent with 4 rules (program $d7_srv) and the child with 1 rule (program $d7_loc), two programs" \
    || bad "replace: the parent's or the child's line is missing or wrong: $(grep -E '"server #1"|/d7/' "$W/logs/start.err" | cut -c1-200 | tr '\n' '|')"
# every context under this server with lines of its own replaces the server's four (the three g3 locations
# carry thresholds, which are lines): one replacement line each, the child's exactly once, and the server
# itself replaces nothing, because above it is only the default the module wrote for the http level
[ "$(grep -c '"location \\"/d7/\\"" replaces 4 inherited rules' "$W/logs/start.err")" = 1 ] \
    && [ "$(grep -c ' replaces ' "$W/logs/start.err")" = "$(grep -c ' replaces 4 inherited rules' "$W/logs/start.err")" ] \
    && ! grep -q '"server #1" replaces' "$W/logs/start.err" \
    && ok "replace: the replacement line is printed once for the child, naming the parent's 4 rules; every other line names a g3 location replacing the same 4, and the parent replaces nothing" \
    || bad "replace: replacement lines: $(grep -c ' replaces ' "$W/logs/start.err"), text: $(grep ' replaces ' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-80 | tr '\n' '|')"
# the file itself is requested, not the directory: the index module's internal redirect to it would be a
# second evaluation in the same context, counted again (an internal redirect that decides again counts again), which is the counting rows' own subject
code /?q=parent >/dev/null; code /d7/index.html?q=child >/dev/null; code_as /d7/index.html?q=twin "$UNLISTED" >/dev/null
sleep 0.5
d7line() { grep -m1 -F "$1 " "$W/logs/d7.log" 2>/dev/null || true; }
l=$(d7line '/?q=parent')
[ "$l" = "/?q=parent 403 action=deny rule_id=ctx:4 logged=ctx:1,2 program=\"floor:- ctx:$d7_srv\"" ] \
    && ok "replace: under the parent the listed client is denied by rule 4 of the parent's program, rules 1 and 2 having logged" \
    || bad "replace: the parent's line is not the expected shape: $l"
l=$(d7line '/d7/index.html?q=child')
[ "$l" = "/d7/index.html?q=child 200 action=allow rule_id=- logged=ctx:1 program=\"floor:- ctx:$d7_loc\"" ] \
    && ok "replace: under the child the same client is allowed: its one rule logged, nothing denies, the program is the child's" \
    || bad "replace: the child's line is not the expected shape: $l"
l=$(d7line '/d7/index.html?q=twin')
[ "$l" = "/d7/index.html?q=twin 200 action=allow rule_id=- logged=- program=\"floor:- ctx:$d7_loc\"" ] \
    && ok "replace: and the unlisted twin under the child is allowed with nothing logged" \
    || bad "replace: the twin's line is not the expected shape: $l"
d7_conf=$(cat "$SUMMARY_DIR"/conf-*.status 2>/dev/null)
[ "$(grep -c "^text $d7_srv " <<<"$d7_conf")" = 4 ] && [ "$(grep -c "^text $d7_loc " <<<"$d7_conf")" = 1 ] \
    && grep -qF "text $d7_loc 1 \"log if listed >= low\"" <<<"$d7_conf" \
    && ok "replace: the configuration file carries four texts for the parent's program and one for the child's, the child's being its own line" \
    || bad "replace: the configuration file's texts: parent $(grep -c "^text $d7_srv " <<<"$d7_conf"), child $(grep -c "^text $d7_loc " <<<"$d7_conf")"
d7_rules=$(stable_text "$SUMMARY_DIR")
if [ "$(rules_count "$d7_rules" "$d7_srv" 1)" = 1 ] && [ "$(rules_count "$d7_rules" "$d7_srv" 2)" = 1 ] \
        && [ -z "$(rules_count "$d7_rules" "$d7_srv" 3)" ] && [ "$(rules_count "$d7_rules" "$d7_srv" 4)" = 1 ] \
        && [ "$(rules_count "$d7_rules" "$d7_loc" 1)" = 1 ]; then
    ok "replace: the counters: the parent's rules 1, 2 and 4 count one each (3 never fired), the child's one rule counts one; the child ran one rule"
else
    bad "replace: the counters: parent 1/2/3/4 = $(rules_count "$d7_rules" "$d7_srv" 1)/$(rules_count "$d7_rules" "$d7_srv" 2)/$(rules_count "$d7_rules" "$d7_srv" 3)/$(rules_count "$d7_rules" "$d7_srv" 4), child 1 = $(rules_count "$d7_rules" "$d7_loc" 1)"
fi
stop; sleep 1
# The control: a context's lines appended to its parent's instead of replacing them, so under the child the
# listed client meets the parent's deny rule. The configuration is the one above, its module swapped.
if build_control -DWE_MOD_TEST_APPEND; then
    sed -i "1s#^load_module .*#load_module $CTL_OUT;#" "$W/nginx.conf"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /d7/index.html "$UNLISTED")" = 200 ]' 10 "the append control"; then
        r=$(code /d7/index.html?q=ctl)
        [ "$r" = 403 ] \
            && ok "replace control (lines appended to the parent's): fails the child row, the listed client denied under the child (403)" \
            || bad "replace control (lines appended to the parent's): the child answered $r; the row passed without the code it proves"
    else
        bad "replace control: the append build did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
else
    control_unavailable "replace control (lines appended to the parent's)"
fi

echo
echo "$(date -u +%H:%M:%S) == the data directory and the snapshot file beside it =="
# The directory form binds <plane>.bin names and nothing else; snapshot.bin is read only through the
# synonym. A directory holding snapshot.bin and no reputation.bin therefore binds no reputation plane,
# and the configuration test says so with the fix; a directory holding both says both are there, and warns
# when the file nothing reads is the newer one, because an operator who installed a fresh snapshot.bin
# beside a stale reputation.bin would otherwise serve the stale data in silence.
D9="$W/d9"
mkdir -p "$D9/snaponly" "$D9/snapvalid" "$D9/newer" "$D9/equal"
chmod 0755 "$D9" "$D9/snaponly" "$D9/snapvalid" "$D9/newer" "$D9/equal"
cp "$W/snapshot.good" "$D9/snaponly/snapshot.bin"
# a snapshot with a validity bound, so the rendered time is read back: 1800000000000 ms is 2027-01-15T08:00Z
python3 ../core/make-test-snapshot.py "$D9/snapvalid/snapshot.bin" 7 1800000000000 3 "$RANGE_START" "$RANGE_END"
cp "$PLANES/reputation.bin" "$D9/newer/reputation.bin"; python3 ../core/make-test-snapshot.py "$D9/newer/snapshot.bin" 9 0 3 "$RANGE_START" "$RANGE_END"
cp "$PLANES/reputation.bin" "$D9/equal/reputation.bin"; python3 ../core/make-test-snapshot.py "$D9/equal/snapshot.bin" 5 0 3 "$RANGE_START" "$RANGE_END"
chmod 0444 "$D9"/*/*.bin
CONFT_DATA="$D9/snaponly" conft d9-snaponly ''
[ "$TRC" = 0 ] && grep -qF "data \"$D9/snaponly\": reputation absent (snapshot.bin is here, generation 1, no validity bound: add \"whisper_edge_snapshot $D9/snaponly/snapshot.bin\" to read it); tor absent;" <<<"$TOUT" \
    && ok "data directory: a directory holding only snapshot.bin binds no reputation plane, and the data line says the file is here, its generation, and the synonym line that reads it" \
    || bad "data directory: the snapshot-only directory's line is not the specified hint: $(grep -m1 'data "' <<<"$TOUT" | sed 's/.*policy: //' | cut -c1-260)"
CONFT_DATA="$D9/snapvalid" conft d9-snapvalid ''
[ "$TRC" = 0 ] && grep -qF "reputation absent (snapshot.bin is here, generation 7, valid until 2027-01-15T08:00Z: add \"whisper_edge_snapshot $D9/snapvalid/snapshot.bin\" to read it);" <<<"$TOUT" \
    && ok "data directory: and a snapshot with a validity bound prints it as a UTC time" \
    || bad "data directory: the validity bound is not rendered as specified: $(grep -m1 'data "' <<<"$TOUT" | sed 's/.*policy: //' | cut -c1-260)"
CONFT_DATA="$D9/newer" conft d9-newer ''
TOUT_NEWER=$TOUT
[ "$TRC" = 0 ] && grep -qE "data \"$D9/newer\": reputation generation 5 digest [0-9a-f]{16} \(snapshot\.bin here too, generation 9, no validity bound, not read\);" <<<"$TOUT" \
    && grep -qF "snapshot.bin in \"$D9/newer\" is generation 9, newer than the bound reputation.bin (generation 5), and the directory form never reads it: install the newer data as reputation.bin, or remove the stale snapshot.bin" <<<"$TOUT" \
    && ok "data directory: reputation.bin bound beside a newer snapshot.bin: the data line names both generations and a warning names the newer unread file and the two ways out" \
    || bad "data directory: the newer-unread arm is not as specified: $(grep -E 'data "|snapshot\.bin in' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-200 | tr '\n' '|')"
t9=$("$LOOKUP_BIN" --probe-dir "$D9/snaponly" 2>&1)
grep -qF "note snapshot.bin is here and reputation.bin is not: a data directory binds <plane>.bin names only; add \"whisper_edge_snapshot $D9/snaponly/snapshot.bin\" to read it" <<<"$t9" && grep -qF 'environment present=0x00 schema-ok=0x00' <<<"$t9" \
    && ok "data directory: the lookup tool reads the snapshot-only directory as the module does: no plane present (environment 0x00) and the same synonym line as the fix" \
    || bad "data directory: the lookup tool on the snapshot-only directory: $(grep -E 'environment|note' <<<"$t9" | tr '\n' '|' | cut -c1-240)"
t9=$("$LOOKUP_BIN" --probe-dir "$D9/newer" 2>&1); m9=$(grep -m1 -oE "reputation generation 5 digest [0-9a-f]{16}" <<<"$TOUT_NEWER" | cut -d' ' -f5)
[ -n "$m9" ] && grep -qE "^  plane reputation +state=present .*generation=5 .*digest=$m9 " <<<"$t9" \
    && ok "data directory: and for reputation.bin beside a newer snapshot.bin the tool names the same bound generation and digest as the module ($m9)" \
    || bad "data directory: the tool and the module disagree on the bound reputation: module \"$m9\", tool $(grep 'plane reputation' <<<"$t9" | cut -c1-200)"
CONFT_DATA="$D9/equal" conft d9-equal ''
[ "$TRC" = 0 ] && grep -qE "data \"$D9/equal\": reputation generation 5 digest [0-9a-f]{16} \(snapshot\.bin here too, generation 5, no validity bound, not read\);" <<<"$TOUT" \
    && ! grep -q 'newer than the bound' <<<"$TOUT" \
    && ok "data directory control: at equal generations both files are named and no warning is printed" \
    || bad "data directory control: the equal-generation arm is not as specified: $(grep -E 'data "|snapshot\.bin in' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-200 | tr '\n' '|')"
# THE PER-PLANE BINDING. `whisper_edge_data <plane> <absolute file>` (http level) binds one plane to its own
# file, overriding the directory for it, its directory walked as the data directory is, and the plane bound
# by the line whatever reads it. whisper_edge_snapshot beside another data directive is the reputation
# plane's file and not legacy. Refused at configuration test: the snapshot and a reputation line together
# (they name the same plane's file), a relative file, and a file in an untrusted directory, each by cause.
PP="$W/pp"; rm -rf "$PP"; mkdir -p "$PP/d" "$PP/o" "$PP/bad"; chmod 0755 "$PP" "$PP/d" "$PP/o"; chmod 0777 "$PP/bad"
python3 ../core/make-test-snapshot.py --plane reputation --out "$PP/d/reputation.bin" --format 1 --schema --v6-index none --generation 100 >/dev/null
python3 ../core/make-test-snapshot.py --plane reputation --out "$PP/o/reputation.bin" --format 1 --schema --v6-index none --generation 200 >/dev/null
python3 ../core/make-test-snapshot.py --plane reputation --out "$PP/o/snapshot.bin" --format 1 --schema --v6-index none --generation 300 >/dev/null
python3 ../core/make-test-snapshot.py --plane tor --out "$PP/o/tor.bin" --format 2 --schema --generation 7 >/dev/null
cp "$PP/o/tor.bin" "$PP/bad/tor.bin"; chmod 0444 "$PP"/*/*.bin
CONFT_DATA="$PP/d" conft pp-over "whisper_edge_data reputation $PP/o/reputation.bin;"
[ "$TRC" = 0 ] && grep -qE "data \"$PP/d\": reputation from \"$PP/o/reputation.bin\" generation 200 digest [0-9a-f]{16}; tor absent;" <<<"$TOUT" \
    && ok "per-plane: whisper_edge_data reputation <file> beside a directory is accepted, and the data line names the file and its generation (200) in place of the directory's" \
    || bad "per-plane: the override at configuration test: rc $TRC, $(grep -m1 -E 'data "|emerg' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-260)"
CONFT_DATA="$PP/d" conft pp-snap "whisper_edge_snapshot $PP/o/snapshot.bin;"
[ "$TRC" = 0 ] && grep -qE "data \"$PP/d\": reputation from the snapshot \"$PP/o/snapshot.bin\" generation 300 digest [0-9a-f]{16}; tor absent;" <<<"$TOUT" \
    && ok "per-plane: whisper_edge_snapshot beside a directory is accepted, and the data line names the snapshot (generation 300) as reputation's file" \
    || bad "per-plane: the snapshot beside a directory at configuration test: rc $TRC, $(grep -m1 -E 'data "|emerg' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-260)"
CONFT_DATA="$PP/d" conft pp-pair "whisper_edge_snapshot $PP/o/snapshot.bin; whisper_edge_data reputation $PP/o/reputation.bin;"
[ "$TRC" != 0 ] && grep -qF "the planes cannot be bound: whisper_edge_snapshot $PP/o/snapshot.bin and whisper_edge_data reputation $PP/o/reputation.bin both name the reputation plane's file; keep one" <<<"$TOUT" \
    && ok "refused binding (d): the snapshot and a reputation line together are refused at configuration test, naming both files" \
    || bad "per-plane: the snapshot with a reputation line: rc $TRC, $(grep -m1 -E 'cannot be bound|emerg|syntax is ok' <<<"$TOUT" | cut -c1-260)"
CONFT_DATA="$PP/d" conft pp-rel "whisper_edge_data tor o/tor.bin;"
refused_at_conf tor 'whisper_edge_data o/tor.bin must be an absolute path to a file' && grep -qE "data \"$PP/d\": reputation generation 100 digest [0-9a-f]{16}; tor refused at configuration;" <<<"$TOUT" \
    && ok "per-plane: a relative file refuses its plane at configuration, the core's sentence saying so with the fix, while reputation binds from the directory" \
    || bad "per-plane: a relative file: rc $TRC, $(grep -m1 -E 'refused|emerg|syntax is ok' <<<"$TOUT" | cut -c1-260)"
CONFT_DATA="$PP/d" conft pp-bad "whisper_edge_data tor $PP/bad/tor.bin;"
refused_at_conf tor "whisper_edge_data $PP/bad/tor.bin" '"bad"' 'writable by others' 'chmod go-w' \
    && ok "refused plane (a): nginx -t names a plane whose file is in a directory open to others, the core's sentence naming the directory, the rule and the fix, and passes" \
    || bad "per-plane: a file in an untrusted directory: rc $TRC, $(grep -m1 -E 'refused|emerg|syntax is ok' <<<"$TOUT" | cut -c1-260)"
# The counters directory with no whisper_edge_summary: beside the data. With per-plane files alone that is
# their one shared directory; files in two directories have no one place beside them, which the
# configuration test says, naming the directive that names one.
pp_nodir() { # <name> <http text>: conft with the data-directory line taken out
    conft "$1" "$2"
    sed -i '/^    whisper_edge_data [^ ]*;$/d' "$TCONF"
    TRC=0; TOUT=$(nginx -t -c "$TCONF" -p "$W/t/$1" 2>&1) || TRC=$?
}
pp_nodir pp-c2 "whisper_edge_data reputation $PP/o/reputation.bin; whisper_edge_data tor $PP/d/tor-elsewhere.bin;"
[ "$TRC" = 0 ] && grep -qF "the configuration's data files are in more than one directory ($PP/o and $PP/d), so no one place is beside them; name the counters directory with whisper_edge_summary <dir>; until then no rule counters are written" <<<"$TOUT" \
    && ok "counters directory: per-plane files in two directories are accepted, and nginx -t says no counters are written until whisper_edge_summary names a directory" \
    || bad "counters directory: two directories: rc $TRC, $(grep -m1 -E 'more than one directory|emerg' <<<"$TOUT" | cut -c1-240)"
pp_nodir pp-c1 "whisper_edge_data reputation $PP/o/reputation.bin; whisper_edge_data tor $PP/o/tor.bin;"
[ "$TRC" = 0 ] && ! grep -q 'more than one directory' <<<"$TOUT" \
    && ok "counters directory control: the same lines in one directory print no such warning (the counters go beside them)" \
    || bad "counters directory control: one directory: rc $TRC, $(grep -m1 -E 'more than one directory|emerg' <<<"$TOUT" | cut -c1-200)"
# Served: what the workers bind, read from their status files, the configuration file's path lines and a
# judged request's token. pp_serve <module> <tag> <http text>: leaves PP_REP (the generation reputation armed
# at), PP_TOR (tor's status word and generation), PP_PATHS (the configuration file's plane lines) and PP_TOKEN.
mkdir -p "$W/html/pp"; echo page > "$W/html/pp/index.html"
pp_serve() {
    local cd="$PP/c-$2"
    rm -rf "$cd"; : > "$W/logs/error.log"; : > "$W/logs/pp.log"
    PP_REP=""; PP_TOR=""; PP_PATHS=""; PP_TOKEN=""
    DATA_DIR="$PP/d" MODULE="$1" SERVER_EXTRA='access_log '"$W"'/logs/pp.log pp;' \
        mkconf 1s "whisper_edge_summary $cd;" 'log_format pp "$request_uri $whisper_edge_generations";' "$3"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /pp/index.html)" = 200 ] && [ -n "$(cat "$cd"/[0-9]*.status 2>/dev/null | grep "^plane reputation armed")" ]' 15 "the per-plane server"; then
        code "/pp/index.html?q=$2" >/dev/null; sleep 0.3
        # a plane with no line is a measured answer (empty), not a failure of the walk
        PP_REP=$( { cat "$cd"/[0-9]*.status | grep -o '^plane reputation armed generation [0-9]*' || true; } | sort -u | cut -d' ' -f5 | tr '\n' ' ' | sed 's/ $//')
        PP_TOR=$( { cat "$cd"/[0-9]*.status | grep -o '^plane tor [a-z]*\( generation [0-9]*\)\?' || true; } | sort -u | cut -d' ' -f3- | tr '\n' ' ' | sed 's/ $//')
        PP_PATHS=$( { cat "$cd"/conf-*.status 2>/dev/null | grep '^plane ' || true; } | tr '\n' '|')
        PP_TOKEN=$(grep -m1 -F "/pp/index.html?q=$2 " "$W/logs/pp.log" | cut -d' ' -f2- || true)
    else
        PP_REP="no start: $(tail -2 "$W/logs/start.err" "$W/logs/error.log" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
}
PP_OVER="whisper_edge_data reputation $PP/o/reputation.bin; whisper_edge_data tor $PP/o/tor.bin;"
PP_SNAP="whisper_edge_snapshot $PP/o/snapshot.bin;"
pp_serve "$MODULE" over "$PP_OVER"
[ "$PP_REP" = 200 ] && [[ $PP_TOKEN =~ ^reputation:200\.[0-9a-f]{8} ]] \
    && ok "per-plane served: both workers arm reputation from its own file (generation 200, not the directory's 100), and a judged request's token names 200" \
    || bad "per-plane served: the override: reputation armed at \"$PP_REP\", token \"$PP_TOKEN\""
[ "$PP_TOR" = "armed generation 7" ] \
    && ok "per-plane served: tor, read by nothing, is bound by its own line and armed at generation 7" \
    || bad "per-plane served: bound by its line: tor reads \"$PP_TOR\""
grep -qF "plane reputation path \"$PP/o/reputation.bin\"|" <<<"$PP_PATHS" && grep -qF "plane tor path \"$PP/o/tor.bin\"|" <<<"$PP_PATHS" \
    && ok "per-plane served: the configuration file's plane lines name the files the binding reads" \
    || bad "per-plane served: the configuration file's plane lines: $PP_PATHS"
pp_serve "$MODULE" snap "$PP_SNAP"
[ "$PP_REP" = 300 ] && [[ $PP_TOKEN =~ ^reputation:300\.[0-9a-f]{8} ]] && grep -qF "plane reputation path \"$PP/o/snapshot.bin\"|" <<<"$PP_PATHS" \
    && ok "per-plane served: the snapshot beside a directory binds reputation (generation 300, not the directory's 100), the token and the plane line naming it" \
    || bad "per-plane served: the snapshot beside a directory: reputation armed at \"$PP_REP\", token \"$PP_TOKEN\", lines $PP_PATHS"
if build_control -DWE_MOD_TEST_PLANE_FILE_IGNORED; then
    pp_serve "$CTL_OUT" over-ctl "$PP_OVER"
    [ "$PP_REP" = 100 ] && [ "$PP_TOR" != "armed generation 7" ] \
        && ok "per-plane control (the line read as nothing): fails the override (reputation armed at the directory's 100) and bound by its line (tor ${PP_TOR:-not bound})" \
        || bad "per-plane control (the line read as nothing): reputation \"$PP_REP\", tor \"$PP_TOR\"; the rows passed without the code they prove"
else
    control_unavailable "per-plane control (the line read as nothing)"
fi
if build_control -DWE_MOD_TEST_SNAPSHOT_DROPPED; then
    pp_serve "$CTL_OUT" snap-ctl "$PP_SNAP"
    [ "$PP_REP" = 100 ] \
        && ok "per-plane control (the snapshot dropped beside a directory): fails the snapshot row, reputation armed at the directory's 100" \
        || bad "per-plane control (the snapshot dropped beside a directory): reputation \"$PP_REP\"; the row passed without the code it proves"
else
    control_unavailable "per-plane control (the snapshot dropped beside a directory)"
fi
# A REFUSED PLANE NEVER TAKES DOWN A SERVING SERVER. A plane refused at configuration (here tor,
# its file in a directory open to others) reads unknown with its reason and fix while every other plane
# binds and serves: (a) nginx -t names it (the per-plane rows above), (b) a reload into it is taken and the
# good plane keeps serving its generation, (c) a fresh start on it serves the rest with no worker killed.
# The one whole refusal left is the snapshot with a reputation line, which names the reputation plane's
# file twice: (d) nginx -t refuses it naming both (above); a reload into it is rejected and the running
# workers keep serving, which needs the binding at postconfiguration, because nginx makes a failing
# init_module fatal at a reload (it exits the master and leaves its workers without one); and a fresh
# start on it does not start, naming what nginx -t named. Controls: the core refusing a configuration whole
# for one refused plane fails (c), and the binding in init_module fails the conflict's reload.
RB_BAD="whisper_edge_data tor $PP/bad/tor.bin; whisper_edge_export tor_exit;"
RB_PAIR="whisper_edge_snapshot $PP/o/snapshot.bin; whisper_edge_data reputation $PP/o/reputation.bin;"
RB_WHY_PAIR="the planes cannot be bound: whisper_edge_snapshot $PP/o/snapshot.bin and whisper_edge_data reputation $PP/o/reputation.bin both name the reputation plane's file; keep one"
mkdir -p "$W/html/rb"; echo page > "$W/html/rb/index.html"
rb_conf() { # <module> <http text>
    DATA_DIR="$PP/d" MODULE="$1" SERVER_EXTRA='access_log '"$W"'/logs/rb.log rb;' \
        mkconf 1s "whisper_edge_summary $PP/c-rb;" 'log_format rb "$request_uri $status $whisper_edge_generations";' "$2"
}
rb_workers() { pgrep -P "$1" -f '^nginx: worker process' 2>/dev/null | sort | tr '\n' ' '; }
rb_tor() { { cat "$PP"/c-rb/[0-9]*.status 2>/dev/null | grep -o '^plane tor [a-z]*' || true; } | sort | uniq -c | awk '{printf "%s x%s ", $4, $1}'; }
# rb_walk <module>: a good server under steady requests, reloaded into one refused plane and then into the
# conflict. Leaves RB_UP, RB_M1/RB_M2 (the master after each reload), RB_NEW (the first reload's new workers
# took over), RB_SAME2 (the second kept them), RB_TOR (tor's status words after the first), RB_N, RB_BAD200,
# RB_GENS (the reputation generations answered), RB_TORTOK (tor's tokens), RB_DEATHS
rb_walk() {
    local m w0 w1 wall wall1 lp
    rm -rf "$PP/c-rb"; : > "$W/logs/error.log"; : > "$W/logs/rb.log"; rm -f "$W/rb.stop"
    RB_P0=0; RB_P1=0; RB_UP=no; RB_M1=""; RB_M2=""; RB_NEW=""; RB_SAME2=""; RB_TOR=""; RB_N=0; RB_BAD200=""; RB_GENS=""; RB_TORTOK=""; RB_DEATHS=""
    rb_conf "$1" ""
    start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /rb/index.html)" = 200 ]' 15 "the good server" || { stop; sleep 1; return; }
    RB_UP=yes; m=$(cat "$W/logs/nginx.pid"); w0=$(rb_workers "$m"); wall=$(workers)
    ( i=0; while [ ! -f "$W/rb.stop" ]; do i=$((i+1)); code "/rb/index.html?n=$i" >/dev/null; sleep 0.05; done ) & lp=$!
    sleep 1
    RB_P0=$(wc -l < "$W/logs/rb.log")
    rb_conf "$1" "$RB_BAD"; nginx -s reload -c "$W/nginx.conf" -p "$W" 2>/dev/null || true
    await '[ "$(rb_tor)" = "refused x2 " ]' 15 "the new workers' status" || true
    RB_M1=$(kill -0 "$m" 2>/dev/null && echo yes || echo no); w1=$(rb_workers "$m"); RB_TOR=$(rb_tor)
    wall1=$(pgrep -P "$m" 2>/dev/null | tr '\n' ' ')   # the taken reload's children: new workers, cache manager, loader
    RB_NEW=$([ -n "$w1" ] && [ "$w1" != "$w0" ] && echo yes || echo no)
    sleep 1
    RB_P1=$(wc -l < "$W/logs/rb.log")
    rb_conf "$1" "$RB_PAIR"; nginx -s reload -c "$W/nginx.conf" -p "$W" 2>/dev/null || true
    sleep 3
    RB_M2=$(kill -0 "$m" 2>/dev/null && echo yes || echo no)
    RB_SAME2=$([ -n "$w1" ] && [ "$(rb_workers "$m")" = "$w1" ] && echo yes || echo no)
    touch "$W/rb.stop"; wait "$lp" 2>/dev/null || true
    RB_N=$(wc -l < "$W/logs/rb.log")
    RB_BAD200=$(awk '$2 != 200' "$W/logs/rb.log" | wc -l)
    RB_GENS=$( { grep -o 'reputation:[0-9a-z-]*' "$W/logs/rb.log" || true; } | sort | uniq -c | awk '{printf "%s x%s ", $2, $1}')
    RB_TORTOK=$( { grep -o 'tor:[0-9a-z.-]*' "$W/logs/rb.log" || true; } | sed 's/\.[0-9a-f]*$//' | sort | uniq -c | awk '{printf "%s x%s ", $2, $1}')
    RB_DEATHS=$(grep -c 'exited on signal' "$W/logs/error.log" || true)
    RB_CONFLINE=$(cat "$PP"/c-rb/conf-*.status 2>/dev/null | grep '^plane tor ' | sed -n 1p || true)
    rb_conf "$1" ""
    # a master gone leaves its children, which are the gate's to stop
    # shellcheck disable=SC2086
    if kill -0 "$m" 2>/dev/null; then stop; else kill $wall $wall1 2>/dev/null || true; fi
    sleep 1
}
rb_walk "$MODULE"
[ "$RB_UP" = yes ] && [ "$RB_M1" = yes ] && [ "$RB_NEW" = yes ] && [ "$RB_TOR" = "refused x2 " ] \
    && grep -qF "plane tor refused \"whisper_edge_data $PP/bad/tor.bin: directory \\\"bad\\\"" <(cat "$PP"/c-rb/[0-9]*.status 2>/dev/null; true) \
    && [[ $RB_CONFLINE == "plane tor path \"$PP/bad/tor.bin\" refused \"whisper_edge_data $PP/bad/tor.bin: "* ]] \
    && ok "refused plane (b): a reload into one refused plane is taken: the new workers say tor refused with the reason and fix in both status files and the configuration file" \
    || bad "refused plane (b): up $RB_UP, master $RB_M1, new workers $RB_NEW, tor $RB_TOR, configuration line \"$RB_CONFLINE\""
[ "$RB_P0" -ge 1 ] && [ "$RB_P1" -gt "$RB_P0" ] && [ "$RB_N" -gt "$RB_P1" ] && [ "$RB_BAD200" = 0 ] && [ "$RB_GENS" = "reputation:100 x$RB_N " ] && [[ $RB_TORTOK == *"tor:-r x"* ]] && [[ $RB_TORTOK != *"tor:"[0-9]* ]] && [ "$RB_DEATHS" = 0 ] \
    && ok "refused plane (b): $RB_N requests before, between and after the reloads ($RB_P0, $((RB_P1 - RB_P0)), $((RB_N - RB_P1))) all answered 200 with reputation at its generation (100) throughout, tor unknown (-r) once refused, no worker lost to a signal" \
    || bad "refused plane (b): $RB_N requests ($RB_P0 before, $((RB_P1 - RB_P0)) between, $((RB_N - RB_P1)) after), $RB_BAD200 not 200, reputation $RB_GENS, tor $RB_TORTOK, $RB_DEATHS signal deaths"
[ "$RB_M2" = yes ] && [ "$RB_SAME2" = yes ] && grep -qF "$RB_WHY_PAIR" "$W/logs/error.log" \
    && ok "refused binding (d): a reload into the conflict is rejected, the master's log naming both files, and the running master and workers keep serving" \
    || bad "refused binding (d): after the conflict's reload: master $RB_M2, same workers $RB_SAME2, logged $(grep -c 'cannot be bound' "$W/logs/error.log" || true)"
# (c) a fresh start with one refused plane
rb_start() { # <module>: leaves RB_SUP, RB_SCODE, RB_SREP, RB_STOR, RB_SDEATHS
    rm -rf "$PP/c-rb"; : > "$W/logs/error.log"; : > "$W/logs/rb.log"
    RB_SUP=no; RB_SCODE=""; RB_SREP=""; RB_STOR=""; RB_SDEATHS=""
    rb_conf "$1" "$RB_BAD"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /rb/index.html)" = 200 ] && [ "$(rb_tor)" = "refused x2 " ]' 15 "the start with tor refused"; then
        RB_SUP=yes; RB_SCODE=$(code "/rb/index.html?q=start"); sleep 0.3
        RB_SREP=$( { cat "$PP"/c-rb/[0-9]*.status | grep -o '^plane reputation armed generation [0-9]*' || true; } | sort -u | cut -d' ' -f5)
        RB_STOR=$(grep -m1 -F '/rb/index.html?q=start ' "$W/logs/rb.log" | grep -o 'tor:[^ ]*' || true)
        RB_SDEATHS=$(grep -c 'exited on signal' "$W/logs/error.log" || true)
    else
        RB_SUP="no: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
}
rb_start "$MODULE"
[ "$RB_SUP" = yes ] && [ "$RB_SCODE" = 200 ] && [ "$RB_SREP" = 100 ] && [ "$RB_STOR" = "tor:-r*" ] && [ "$RB_SDEATHS" = 0 ] \
    && grep -qF "whisper edge: plane tor is refused at configuration and reads unknown until it is fixed and the configuration reloaded" "$W/logs/error.log" \
    && ok "refused plane (c): a fresh start with tor refused serves (200), reputation armed at 100, tor unknown (-r), the core's sentence in the error log, no worker killed" \
    || bad "refused plane (c): up $RB_SUP, answer $RB_SCODE, reputation $RB_SREP, tor $RB_STOR, $RB_SDEATHS signal deaths"
# (d) a first start that skipped nginx -t, on the conflict: fail open, as Apache and OpenLiteSpeed do. It comes
# up with no plane bound, answers, and the error log says so at error; nginx -t and a reload still refuse it
# (above). The control is the closed start nginx had, where the server did not come up at all.
RB_OPEN="whisper edge: the planes are not bound: whisper_edge_snapshot $PP/o/snapshot.bin and whisper_edge_data reputation $PP/o/reputation.bin both name the reputation plane's file; keep one"
rb_conflict_start() { # <module>: leaves RB_CUP, RB_CCODE, RB_CLOG (the open start's line in the error log)
    RB_CUP=no; RB_CCODE=""; RB_CLOG=0
    rb_conf "$1" "$RB_PAIR"; : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /rb/index.html)" = 200 ]' 15 "the conflict's open start"; then
        RB_CUP=yes; RB_CCODE=$(code /rb/index.html); RB_CLOG=$(grep -cF "$RB_OPEN" "$W/logs/error.log" || true)
    fi
    stop; sleep 1
}
rb_conflict_start "$MODULE"
[ "$RB_CUP" = yes ] && [ "$RB_CCODE" = 200 ] && [ "$RB_CLOG" -ge 1 ] \
    && ok "refused binding (d): a first start on the conflict comes up with no plane bound and answers (200), and the error log says so at error, naming both files" \
    || bad "refused binding (d): the conflict's first start: up $RB_CUP, answer $RB_CCODE, open-start lines $RB_CLOG"
if build_control -DWE_MOD_TEST_CONFLICT_CLOSED; then
    rb_conflict_start "$CTL_OUT"
    [ "$RB_CUP" = no ] \
        && ok "refused binding control (the conflict refused at a start): fails (d)'s first start, the server does not come up" \
        || bad "refused binding control (the conflict refused at a start): the server came up; the row passed without the code it proves"
else
    control_unavailable "refused binding control (the conflict refused at a start)"
fi
# The stock error_log: nginx's distribution configuration names no level, which keeps error and above. A
# plane refused at configuration is said at error, so on that log the start and every reload say it.
rb_stock() { # <module>: leaves RB_ST (refused lines after the start) and RB_SR (after one reload)
    RB_ST=""; RB_SR=""
    rb_conf "$1" "$RB_BAD"
    sed -i "s#^error_log $W/logs/error.log info;#error_log $W/logs/error.log;#" "$W/nginx.conf"
    : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /rb/index.html)" = 200 ]' 15 "the stock-level start"; then
        RB_ST=$(grep -c 'whisper edge: plane tor is refused at configuration' "$W/logs/error.log" || true)
        signal_master reload; sleep 3
        RB_SR=$(grep -c 'whisper edge: plane tor is refused at configuration' "$W/logs/error.log" || true)
    fi
    stop; sleep 1
}
rb_stock "$MODULE"
[ "$RB_ST" = 1 ] && [ "$RB_SR" = 2 ] \
    && ok "refused plane (a): on a stock error_log (no level) the start writes the core's sentence once, and a reload writes it again" \
    || bad "refused plane (a): on a stock error_log the refused sentence was written $RB_ST time(s) at start, $RB_SR after a reload"
if build_control -DWE_MOD_TEST_REFUSED_WARN; then
    rb_stock "$CTL_OUT"
    [ "$RB_ST" = 0 ] \
        && ok "refused plane control (the sentence at warn): fails the stock-level row, nothing written at start or reload ($RB_ST, $RB_SR)" \
        || bad "refused plane control (the sentence at warn): $RB_ST line(s) at start; the row passed without the code it proves"
else
    control_unavailable "refused plane control (the sentence at warn)"
fi
if build_control -DWE_MOD_TEST_PLANE_REFUSAL_WHOLE; then
    rb_start "$CTL_OUT"
    [ "$RB_SUP" != yes ] \
        && ok "refused plane control (one refused plane refuses the whole binding): fails (c), the start does not come up" \
        || bad "refused plane control (one refused plane refuses the whole binding): the start came up; the row passed without the code it proves"
else
    control_unavailable "refused plane control (one refused plane refuses the whole binding)"
fi
if build_control -DWE_MOD_TEST_BIND_IN_INIT; then
    rb_walk "$CTL_OUT"
    [ "$RB_M1" = yes ] && [ "$RB_M2" = no ] \
        && ok "refused binding control (the binding in init_module): fails (d)'s reload, the master exits at the conflict (master after each reload: $RB_M1 $RB_M2)" \
        || bad "refused binding control (the binding in init_module): master after each reload: $RB_M1 $RB_M2; the row passed without the code it proves"
else
    control_unavailable "refused binding control (the binding in init_module)"
fi
rm -rf "$PP"
# Served: a data directory holding snapshot.bin and no reputation.bin binds no reputation plane (the
# directory form reads <plane>.bin names only), so the workers say reputation absent; the control, an
# earlier rule that bound snapshot.bin in its place, arms it.
d9_serve() { # <module> <tag>: leaves D9_REP, reputation's status words in the workers' files
    local cd="$D9/c-$2"
    rm -rf "$cd"; D9_REP=""
    DATA_DIR="$D9/snaponly" MODULE="$1" mkconf 1s "whisper_edge_summary $cd;"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /index.html)" = 200 ] && [ "$(ls "$cd" 2>/dev/null | grep -c "^[0-9].*\.status$")" -ge 2 ]' 15 "the snapshot-only server"; then
        D9_REP=$( { cat "$cd"/[0-9]*.status | grep -o '^plane reputation [a-z]*' || true; } | sort | uniq -c | awk '{printf "%s x%s ", $4, $1}')
    else
        D9_REP="no start: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
}
d9_serve "$MODULE" real
[ -z "$D9_REP" ] \
    && ok "data directory: served, a directory holding only snapshot.bin binds no reputation plane: neither worker's status file has a reputation line" \
    || bad "data directory: served from the snapshot-only directory, reputation reads \"$D9_REP\""
if build_control -DWE_MOD_TEST_SNAPSHOT_FALLBACK; then
    d9_serve "$CTL_OUT" ctl
    [ "$D9_REP" = "armed x2 " ] \
        && ok "data directory control (snapshot.bin bound in reputation.bin's place): fails the row, reputation armed in both workers" \
        || bad "data directory control (snapshot.bin bound in reputation.bin's place): reputation reads \"$D9_REP\"; the row passed without the code it proves"
else
    control_unavailable "data directory control (snapshot.bin bound in reputation.bin's place)"
fi

echo
echo "$(date -u +%H:%M:%S) == a plane present but read by nothing stays unbound and unmapped, until an export names it =="
# The planes a configuration binds are the ones something reads: a program's rule, the floor, an export
# or a variable. A plane file nobody reads is reported and left alone: not bound, not mapped into any
# worker, not in any status file. Naming one of its attributes in an http-level whisper_edge_export reads
# it, so it binds, maps and arms. The control is a build that binds every present plane, which maps the
# unread one and so would fail the rows.
D10="$W/d10"
mkdir -p "$D10"; chmod 0755 "$D10"
cp "$PLANES/reputation.bin" "$D10/reputation.bin"; cp "$PLANES/rpki-unreachable.bin" "$D10/rpki-unreachable.bin"; chmod 0444 "$D10"/*.bin
mkdir -p "$W/html/d10"; echo page > "$W/html/d10/index.html"
# maps_with <file name> -> how many of the serving workers map a file of that name (the cache helpers inherit the
# master's mappings too and the loader exits on its own, so they are not counted)
maps_with() { local p n=0; for p in $(workers); do grep -q "worker process" "/proc/$p/cmdline" 2>/dev/null || continue; grep -q "/$1\$" "/proc/$p/maps" 2>/dev/null && n=$((n + 1)); done; echo "$n"; }
status_planes() { cat "$W"/d10/counters/[0-9]*.status 2>/dev/null | grep -E "^plane $1 " | grep -c . || true; }
rm -rf "$D10/counters"
DATA_DIR="$D10" mkconf 1s "whisper_edge_summary $D10/counters;"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /d10/)" = 200 ] && [ "$(status_planes reputation)" = 2 ]' 15 "the unread-plane server" || bad "unread plane: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
grep -qF "data \"$D10\": reputation generation 5 digest" "$W/logs/start.err" && grep -qF 'rpki-unreachable present, not bound: nothing in this configuration reads it;' "$W/logs/start.err" \
    && ok "unread plane: the data line binds reputation (the default program reads it) and says rpki-unreachable is present and read by nothing" \
    || bad "unread plane: the data line: $(grep -m1 'data "' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-240)"
[ "$(status_planes rpki-unreachable)" = 0 ] && [ "$(maps_with rpki-unreachable.bin)" = 0 ] && [ "$(maps_with reputation.bin)" = 2 ] \
    && ok "unread plane: no worker maps rpki-unreachable.bin or writes a status line for it, while both map reputation.bin" \
    || bad "unread plane: status lines $(status_planes rpki-unreachable), workers mapping it $(maps_with rpki-unreachable.bin), mapping reputation $(maps_with reputation.bin)"
stop; sleep 1
DATA_DIR="$D10" SERVER_EXTRA='access_log '"$W"'/logs/d10.log d10;' \
    mkconf 1s "whisper_edge_summary $D10/counters;" "whisper_edge_export rpki_unreachable;" 'log_format d10 "$request_uri $status rpki_unreachable=$whisper_edge_rpki_unreachable";'
rm -rf "$D10/counters"; : > "$W/logs/error.log"; : > "$W/logs/d10.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /d10/)" = 200 ] && [ "$(status_planes rpki-unreachable)" = 2 ]' 15 "the exported-plane server" || bad "unread plane: the server with the export did not come up or did not arm the plane: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
grep -qE "data \"$D10\": reputation generation 5 digest [0-9a-f]{16}; tor absent; rpki-unreachable generation 5 digest [0-9a-f]{16};" "$W/logs/start.err" \
    && ok "unread plane: named by an http-level whisper_edge_export, the plane is bound and the data line names its generation and digest" \
    || bad "unread plane: the data line after the export: $(grep -m1 'data "' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-240)"
[ "$(cat "$W"/d10/counters/[0-9]*.status | grep -c '^plane rpki-unreachable armed generation 5 ')" = 2 ] && [ "$(maps_with rpki-unreachable.bin)" = 2 ] \
    && ok "unread plane: and both workers map it and arm it at generation 5" \
    || bad "unread plane: armed lines $(cat "$W"/d10/counters/[0-9]*.status | grep -c '^plane rpki-unreachable armed'), workers mapping it $(maps_with rpki-unreachable.bin)"
code /d10/index.html?q=exported >/dev/null; sleep 0.3
l=$(grep -m1 -F '/d10/index.html?q=exported ' "$W/logs/d10.log" || true)
[[ $l =~ ^/d10/index\.html\?q=exported\ 200\ rpki_unreachable=(true|false)$ ]] \
    && ok "unread plane: the exported attribute renders a value from the bound plane (${l##*=}), not unknown" \
    || bad "unread plane: the exported attribute's line: $l"
stop; sleep 1
# the control: a build binding every present plane maps the unread one under the first configuration
if build_control -DWE_MOD_TEST_BIND_ALL; then
    DATA_DIR="$D10" MODULE="$CTL_OUT" mkconf 1s "whisper_edge_summary $D10/counters;"
    rm -rf "$D10/counters"; : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /d10/)" = 200 ] && [ "$(status_planes reputation)" = 2 ]' 15 "the bind-all control"; then
        [ "$(maps_with rpki-unreachable.bin)" = 2 ] \
            && ok "unread plane control: a build binding every present plane maps rpki-unreachable.bin in both workers with nothing reading it, so the rows above can fail" \
            || bad "unread plane control: the bind-all build mapped rpki-unreachable.bin in $(maps_with rpki-unreachable.bin) worker(s), not 2"
    else
        bad "unread plane control: the bind-all build did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
else
    control_unavailable "unread plane control"
fi

echo
echo "$(date -u +%H:%M:%S) == the deny on the wire: every accepted status, the cache in front, the error pages, the hops, the floor =="
# What a denied request gets, read from the wire and never from this script's idea of it: the configured
# status and Cache-Control: no-store under every accepted code; 444 a closed connection and no bytes; a
# caching proxy in front (proxy_cache, any status valid for a minute) never serving one client's deny to
# the next, because no-store forbids storing it; a context-rule deny under error_page carrying the
# operator's page and still no-store, a proxied error page too; the index and try_files hops judged in
# the context the hop lands in; a burst of denies never taking the origin down behind a balancer whose
# proxy_next_upstream watches 503, which the module refuses as a deny status; and a floor deny bypassing
# error_page, so its body is nginx's own page and never the application's.
for c in 400 403 404 406 409 410 413 415 422 428 429 451 444; do mkdir -p "$W/html/s$c"; echo "s$c" > "$W/html/s$c/index.html"; done
mkdir -p "$W/html/ep" "$W/html/ep200" "$W/html/epp" "$W/html/idx" "$W/html/tf" "$W/html/fa" "$W/html/fb"
for d in ep ep200 epp idx fa fb; do echo "$d page" > "$W/html/$d/index.html"; done
echo "the operator's error page" > "$W/html/e.html"; echo "a public cacheable page" > "$W/html/pub.html"; echo "front controller" > "$W/html/index.php"
codes_extra=""
for c in 400 404 406 409 410 413 415 422 428 429 451 444; do codes_extra="$codes_extra
        location /s$c/ { whisper_edge_mode deny; whisper_edge_deny_status $c; }"; done
SERVER_EXTRA="location /s403/ { whisper_edge_mode deny; }$codes_extra
        location /ep/ { whisper_edge_mode deny; error_page 403 /e.html; }
        location /ep200/ { whisper_edge_mode deny; error_page 403 =200 /e.html; }
        location = /e.html { whisper_edge_mode off; }
        location /epp/ { whisper_edge_mode deny; error_page 403 /e-proxied; }
        location = /e-proxied { whisper_edge_mode off; proxy_pass http://127.0.0.1:$PORT/pub.html; }
        location = /pub.html { whisper_edge_mode off; add_header Cache-Control \"public, max-age=60\"; }
        location /idx/ { whisper_edge_mode deny; index index.html; }
        location /tf/ { try_files \$uri /index.php; }
        location = /index.php { whisper_edge_mode deny; }" \
    mkconf 1s "upstream origin { server 127.0.0.1:$PORT max_fails=1 fail_timeout=10s; }
    server {
        listen 127.0.0.1:$PORT2;
        whisper_edge_mode off;
        location / {
            proxy_pass http://origin;
            proxy_cache gate;
            proxy_cache_valid any 1m;
            proxy_cache_key \$request_uri;
            proxy_set_header X-Forwarded-For \$http_x_forwarded_for;
            proxy_next_upstream error timeout http_503;
            add_header X-Cache \$upstream_cache_status always;
        }
    }"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /s403/index.html "$UNLISTED")" = 200 ]' 10 "the wire server" || bad "wire: the server did not come up: $(tail -3 "$W/logs/start.err" | tr '\n' '|' | cut -c1-300)"
# wire <path> [client]: the status line, the Cache-Control values and Content-Length of one listed request, as curl saw them
wire() { curl -s -o /dev/null -D - --max-time 5 -H "$(xff "${2:-$LISTED}")" "http://127.0.0.1:$PORT$1" | tr -d '\r'; }
lens=""
for c in 400 403 404 406 409 410 413 415 422 428 429 451; do
    h=$(wire "/s$c/index.html")
    st=$(sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p' <<<"$h"); cc=$(grep -i '^Cache-Control:' <<<"$h" | cut -d' ' -f2- | tr '\n' ',' | sed 's/,$//'); cl=$(grep -i -m1 '^Content-Length:' <<<"$h" | cut -d' ' -f2); reason=$(sed -n '1s/^HTTP\/1\.1 [0-9]* *//p' <<<"$h")
    lens="$lens $c:${cl:--}"
    [ "$st" = "$c" ] && [ "$cc" = "no-store" ] \
        && ok "wire: whisper_edge_deny_status $c sends $c on the wire with Cache-Control: no-store (reason \"$reason\", Content-Length ${cl:-none}, printed not judged)" \
        || bad "wire: configured $c, the wire says status \"$st\" Cache-Control \"$cc\": $(head -1 <<<"$h")"
done
l403=$(sed -n 's/.* 403:\([0-9-]*\).*/\1/p' <<<"$lens"); l422=$(sed -n 's/.* 422:\([0-9-]*\).*/\1/p' <<<"$lens"); l428=$(sed -n 's/.* 428:\([0-9-]*\).*/\1/p' <<<"$lens"); l451=$(sed -n 's/.* 451:\([0-9-]*\).*/\1/p' <<<"$lens")
[ "$l422" = 0 ] && [ "$l428" = 0 ] && [ "$l451" = 0 ] && [ "${l403:-0}" -gt 0 ] 2>/dev/null \
    && ok "wire: 422, 428 and 451 go out with Content-Length: 0 (nginx has no page for them), beside 403's built-in body of $l403 bytes" \
    || bad "wire: the body lengths were$lens, where 422, 428 and 451 should be 0 and 403 non-zero"
rc=0; curl -s -o /dev/null --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/s444/index.html" || rc=$?
[ "$rc" = 52 ] && ok "wire: 444 closes the connection with no response (curl 52, empty reply)" || bad "wire: 444 gave curl exit $rc, not 52"
# through the cache in front: the deny is never stored, the next client gets the origin's answer, and the origin's answer is cacheable
front() { curl -s -o /dev/null -D - --max-time 5 -H "$(xff "${2:-$LISTED}")" "http://127.0.0.1:$PORT2$1" | tr -d '\r'; }
for c in 403 410 451; do
    h1=$(front "/s$c/index.html"); h2=$(front "/s$c/index.html" "$UNLISTED"); h3=$(front "/s$c/index.html" "$UNLISTED")
    s1=$(sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p' <<<"$h1"); s2=$(sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p' <<<"$h2"); s3=$(sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p' <<<"$h3")
    x2=$(grep -i -m1 '^X-Cache:' <<<"$h2" | cut -d' ' -f2); x3=$(grep -i -m1 '^X-Cache:' <<<"$h3" | cut -d' ' -f2)
    [ "$s1" = "$c" ] && grep -qi '^Cache-Control: no-store' <<<"$h1" && [ "$s2" = 200 ] && [ "$x2" = MISS ] && [ "$s3" = 200 ] && [ "$x3" = HIT ] \
        && ok "wire: through the caching proxy the listed client's $c (no-store) is not stored: the unlisted client gets the origin's 200 (MISS), and its next request a HIT of that 200" \
        || bad "wire: through the cache under $c: listed $s1, then unlisted $s2 ($x2) and $s3 ($x3)"
done
# the error pages: the operator's page, no-store kept, the proxied page too
h=$(wire /ep/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/ep/index.html")
grep -q '^HTTP/1.1 403' <<<"$h" && grep -qi '^Cache-Control: no-store' <<<"$h" && [ "$b" = "the operator's error page" ] \
    && ok "wire: a context-rule deny under error_page 403 /e.html answers 403 with the operator's page and keeps no-store" \
    || bad "wire: error_page /e.html: $(head -1 <<<"$h"), cache-control $(grep -i cache-control <<<"$h" | tr '\n' ' '), body \"$b\""
h=$(wire /ep200/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/ep200/index.html")
grep -q '^HTTP/1.1 200' <<<"$h" && grep -qi '^Cache-Control: no-store' <<<"$h" && [ "$b" = "the operator's error page" ] \
    && ok "wire: under error_page 403 =200 /e.html the deny goes out as 200 with the page, still no-store" \
    || bad "wire: error_page =200: $(head -1 <<<"$h"), cache-control $(grep -i cache-control <<<"$h" | tr '\n' ' '), body \"$b\""
h=$(wire /epp/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/epp/index.html")
grep -q '^HTTP/1.1 403' <<<"$h" && grep -qi '^Cache-Control: no-store' <<<"$h" && [ "$b" = "a public cacheable page" ] \
    && ok "wire: an error page proxied from a backend that says Cache-Control: public still carries no-store on the deny (the backend's header: $(grep -i '^Cache-Control:' <<<"$h" | grep -v no-store | cut -d' ' -f2- | tr '\n' ' '))" \
    || bad "wire: the proxied error page: $(head -1 <<<"$h"), cache-control $(grep -i cache-control <<<"$h" | tr '\n' ' '), body \"$b\""
# the hops: the candidate's context judges an index redirect; try_files' final argument is a hop judged where it lands
[ "$(code /idx/)" = 403 ] && [ "$(curl -s --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/idx/")" = "idx page" ] \
    && ok "wire: a request for a directory whose index redirect lands in a deny context is denied (403), and the unlisted twin is served the index" \
    || bad "wire: the index hop: listed $(code /idx/), twin \"$(curl -s --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/idx/")\""
[ "$(code /tf/missing)" = 403 ] && [ "$(curl -s --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/tf/missing")" = "front controller" ] \
    && ok "wire: try_files' final argument is a hop judged in the location it lands in (deny, 403), and the unlisted twin is served that location's file, which proves the rewrite fired" \
    || bad "wire: the try_files hop: listed $(code /tf/missing), twin \"$(curl -s --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/tf/missing")\""
# the burst: twenty denies through the balancer, the origin stays up
for _ in $(seq 1 20); do curl -s -o /dev/null --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT2/s403/index.html?burst" || true; done
b=$(front /s403/index.html?after "$UNLISTED" | sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p')
[ "$b" = 200 ] && ok "wire: twenty denied requests through a balancer with max_fails=1 and proxy_next_upstream http_503 leave the origin up: the next unlisted request is answered 200, never 502 (503 is refused as a deny status)" \
    || bad "wire: after the burst the unlisted client got $b through the balancer"
stop; sleep 1
# the floor's deny bypasses error_page: nginx's own page, never the application's
SERVER_EXTRA='location /fa/ { error_page 403 = @app; }
        location @app { return 200 "the application answered\n"; }
        location /fb/ { error_page 403 =200 /index.php; }' \
    mkconf 1s 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if listed >= high";'
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /fa/index.html "$UNLISTED")" = 200 ]' 10 "the floor server" || bad "wire: the floor server did not come up: $(tail -3 "$W/logs/start.err" | tr '\n' '|' | cut -c1-300)"
h=$(wire /fa/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/fa/index.html")
grep -q '^HTTP/1.1 403' <<<"$h" && grep -qi '^Cache-Control: no-store' <<<"$h" && [ "$b" != "the application answered" ] && grep -q '<title>403 Forbidden</title>' <<<"$b" \
    && ok "wire: a floor deny under error_page 403 = @app bypasses the error page: 403, nginx's own page, no-store, no application byte" \
    || bad "wire: the floor under error_page = @app: $(head -1 <<<"$h"), body \"$(head -c 60 <<<"$b")\""
h=$(wire /fb/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/fb/index.html")
grep -q '^HTTP/1.1 403' <<<"$h" && [ "$b" != "front controller" ] && grep -q '<title>403 Forbidden</title>' <<<"$b" \
    && ok "wire: and under error_page 403 =200 /index.php the floor deny is still 403 with nginx's page, never the front controller" \
    || bad "wire: the floor under error_page =200: $(head -1 <<<"$h"), body \"$(head -c 60 <<<"$b")\""
stop; sleep 1
# the controls: a deny without no-store is cached and served to the next client; a floor that does not bypass error_page serves the application
if build_control -DWE_MOD_TEST_NO_STORE_OFF; then
    SERVER_EXTRA='location /s403/ { whisper_edge_mode deny; }' MODULE="$CTL_OUT" mkconf 1s "server {
        listen 127.0.0.1:$PORT2;
        whisper_edge_mode off;
        location / { proxy_pass http://127.0.0.1:$PORT; proxy_cache gate; proxy_cache_valid any 1m; proxy_cache_key \$request_uri; proxy_set_header X-Forwarded-For \$http_x_forwarded_for; add_header X-Cache \$upstream_cache_status always; }
    }"
    rm -rf "$W/cache"; : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /s403/index.html "$UNLISTED")" = 200 ]' 10 "the no-store control"; then
        h1=$(front /s403/index.html?ctl); h2=$(front /s403/index.html?ctl "$UNLISTED")
        grep -q '^HTTP/1.1 403' <<<"$h1" && ! grep -qi 'no-store' <<<"$h1" && grep -q '^HTTP/1.1 403' <<<"$h2" && grep -qi '^X-Cache: HIT' <<<"$h2" \
            && ok "wire control: a build whose deny carries no no-store is cached by the front and served to the unlisted client (403, HIT), which the cache rows above would catch" \
            || bad "wire control: the no-store-less deny: listed $(head -1 <<<"$h1"), unlisted $(head -1 <<<"$h2") $(grep -i -m1 x-cache <<<"$h2")"
    else
        bad "wire control: the no-store control did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
else
    control_unavailable "wire control (no-store)"
fi
if build_control -DWE_MOD_TEST_FLOOR_ERROR_PAGE; then
    SERVER_EXTRA='location /fa/ { error_page 403 = @app; }
        location @app { return 200 "the application answered\n"; }' MODULE="$CTL_OUT" \
        mkconf 1s 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if listed >= high";'
    : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /fa/index.html "$UNLISTED")" = 200 ]' 10 "the floor error-page control"; then
        b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/fa/index.html")
        [ "$b" = "the application answered" ] \
            && ok "wire control: a build whose floor deny does not bypass error_page serves the application to the floor-denied client, which the floor rows above would catch" \
            || bad "wire control: the floor error-page control answered \"$(head -c 60 <<<"$b")\""
    else
        bad "wire control: the floor error-page control did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    stop; sleep 1
else
    control_unavailable "wire control (floor error page)"
fi

echo
echo "$(date -u +%H:%M:%S) == a keyed plane is bound by the http level alone: a reference below it, or by a variable, is reported and inert =="
# routing and registry are keyed planes: only http-level configuration may bind them, so a tenant's server block
# cannot make the module map a plane the operator did not. An export in a server block, an add_header in a
# server block or a variable in an http-level log_format each leaves the plane unbound and unmapped, the
# configuration test naming the fix, and the attribute renders unknown with the plane's token reading -a;
# one http-level export binds it. The controls are builds that bind on any reference or on a variable.
D14="$W/d14"
mkdir -p "$D14"; chmod 0755 "$D14"
cp "$PLANES/reputation.bin" "$D14/reputation.bin"; cp "$PLANES/routing.bin" "$D14/routing.bin"; chmod 0444 "$D14"/*.bin
mkdir -p "$W/html/d14"; printf '<!--# echo var="whisper_edge_asn" -->|<!--# echo var="whisper_edge_generations" -->\n' > "$W/html/d14/index.html"
d14_ssi() { curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/d14/"; }
d14_hdr() { curl -s -o /dev/null -D - --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/d14/" | tr -d '\r' | grep -i '^X-Asn:' | cut -d' ' -f2; }
d14_start() { rm -rf "$D14/counters"; : > "$W/logs/error.log"; : > "$W/logs/d14.log"; start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /d14/)" = 200 ]' 10 "the keyed-plane server"; }
# an export in the server block alone
DATA_DIR="$D14" SERVER_EXTRA='whisper_edge_export asn; location /d14/ { ssi on; }' mkconf 1s "whisper_edge_summary $D14/counters;"
if d14_start; then
    grep -qF 'a rule or export below the http level reads plane "routing", which only http-level configuration can bind: its attributes read unknown; add an http-level rule, "whisper_edge_policy_floor" line or "whisper_edge_export" that reads it to bind it' "$W/logs/start.err" \
        && ok "keyed plane: an export in a server block alone leaves routing unbound, and the configuration test names the http-level fix" \
        || bad "keyed plane: the below-http export warning is missing: $(grep -i routing "$W/logs/start.err" | sed 's/.*whisper edge: //' | cut -c1-200 | tr '\n' '|')"
    b=$(d14_ssi)
    [ "$(maps_with routing.bin)" = 0 ] && [[ $b =~ ^unknown\|.*routing:-a ]] \
        && ok "keyed plane: no worker maps routing.bin, the attribute renders unknown and the generations token reads routing:-a ($b)" \
        || bad "keyed plane: workers mapping routing.bin $(maps_with routing.bin), the page reads \"$b\""
else
    bad "keyed plane: the server with the vhost export did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1
# the same export at http level
DATA_DIR="$D14" SERVER_EXTRA='location /d14/ { ssi on; }' mkconf 1s "whisper_edge_summary $D14/counters;" "whisper_edge_export asn;"
if d14_start; then
    b=$(d14_ssi)
    ! grep -q 'only http-level configuration can bind' "$W/logs/start.err" && grep -qE "routing generation 5 digest [0-9a-f]{16};" "$W/logs/start.err" \
        && [ "$(maps_with routing.bin)" = 2 ] && [[ $b =~ routing:5\.[0-9a-f]{8} ]] && [[ ! $b =~ ^unknown ]] \
        && ok "keyed plane: the same export at http level binds routing: the data line names its generation, both workers map it, and the page reads the plane ($b)" \
        || bad "keyed plane: after the http-level export: mapping $(maps_with routing.bin), page \"$b\", data line $(grep -m1 'data "' "$W/logs/start.err" | grep -o 'routing[^;]*')"
else
    bad "keyed plane: the server with the http-level export did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1
# a variable reference: add_header in the server block and the same variable in an http-level log_format
DATA_DIR="$D14" SERVER_EXTRA='add_header X-Asn $whisper_edge_asn; access_log '"$W"'/logs/d14.log d14; location /d14/ { ssi on; }' \
    mkconf 1s "whisper_edge_summary $D14/counters;" 'log_format d14 "$request_uri asn=$whisper_edge_asn";'
if d14_start; then
    grep -qF 'plane "routing" is referenced by a $whisper_edge_ variable and by nothing at http level, so it is not bound and the variable renders unknown (routing:-a); add an http-level "whisper_edge_export" of one of its attributes to bind it' "$W/logs/start.err" \
        && ok "keyed plane: a variable reference (add_header in a server block, the same variable in an http-level log_format) does not bind routing, and the configuration test names the export fix" \
        || bad "keyed plane: the variable-reference warning is missing: $(grep -i routing "$W/logs/start.err" | sed 's/.*whisper edge: //' | cut -c1-200 | tr '\n' '|')"
    h=$(d14_hdr); sleep 0.3; l=$(grep -m1 -F '/d14/ ' "$W/logs/d14.log" || true)
    [ "$(maps_with routing.bin)" = 0 ] && [ "$h" = unknown ] && [ "$l" = "/d14/ asn=unknown" ] \
        && ok "keyed plane: no worker maps it, the header and the log line both read unknown" \
        || bad "keyed plane: mapping $(maps_with routing.bin), header \"$h\", log \"$l\""
else
    bad "keyed plane: the server with the variable references did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1
DATA_DIR="$D14" SERVER_EXTRA='add_header X-Asn $whisper_edge_asn; location /d14/ { ssi on; }' mkconf 1s "whisper_edge_summary $D14/counters;" "whisper_edge_export asn;"
if d14_start; then
    h=$(d14_hdr)
    [ "$(maps_with routing.bin)" = 2 ] && [ -n "$h" ] && [ "$h" != unknown ] \
        && ok "keyed plane: with an http-level export beside the variable, routing is mapped in both workers and the header renders the plane's value ($h)" \
        || bad "keyed plane: with the export beside the variable: mapping $(maps_with routing.bin), header \"$h\""
else
    bad "keyed plane: the server with the export beside the variable did not come up"
fi
stop; sleep 1
# the controls: a build binding on any reference maps routing from the vhost export; a build binding on the variable's index maps it from add_header
if build_control -DWE_MOD_TEST_BIND_ANY_REF; then
    DATA_DIR="$D14" MODULE="$CTL_OUT" SERVER_EXTRA='whisper_edge_export asn; location /d14/ { ssi on; }' mkconf 1s "whisper_edge_summary $D14/counters;"
    if d14_start; then
        [ "$(maps_with routing.bin)" = 2 ] && ok "keyed plane control: a build binding on any reference maps routing.bin in both workers from a server-block export, so the rows above can fail" \
            || bad "keyed plane control: the bind-on-any-reference build mapped routing in $(maps_with routing.bin) worker(s)"
    else
        bad "keyed plane control: the bind-on-any-reference build did not come up"
    fi
    stop; sleep 1
else
    control_unavailable "keyed plane control (any reference)"
fi
if build_control -DWE_MOD_TEST_BIND_ON_INDEX; then
    DATA_DIR="$D14" MODULE="$CTL_OUT" SERVER_EXTRA='add_header X-Asn $whisper_edge_asn; location /d14/ { ssi on; }' mkconf 1s "whisper_edge_summary $D14/counters;"
    if d14_start; then
        [ "$(maps_with routing.bin)" = 2 ] && ok "keyed plane control: a build binding on a variable's index maps routing.bin from the add_header alone, so the rows above can fail" \
            || bad "keyed plane control: the bind-on-index build mapped routing in $(maps_with routing.bin) worker(s)"
    else
        bad "keyed plane control: the bind-on-index build did not come up"
    fi
    stop; sleep 1
else
    control_unavailable "keyed plane control (variable index)"
fi

echo
echo "$(date -u +%H:%M:%S) == the floor runs under the http level's mode, and reaches a mode-off context =="
# The floor is the http level's: its mode is the http level's mode, so a floor at http level with
# whisper_edge_mode deny only in a server block is a dry run (would-deny) and the configuration test says
# so; with the http level under deny the floor denies, in a server or location that set mode off too,
# with the http level's status, no-store, one count on the floor's rule and a program token naming the
# floor and no context. The control is a build keeping the shipped module's early return for a mode-off
# context, which the floor never reached.
D15="$W/d15"
mkdir -p "$D15"; chmod 0755 "$D15"
cp "$PLANES/reputation.bin" "$D15/reputation.bin"
python3 ../core/make-test-snapshot.py --plane tor --out "$D15/tor.bin" --format 2 --schema --generation 5 --expect "$D15/tor.expect" >/dev/null
chmod 0444 "$D15"/*.bin
# a Tor-listed client, read from the generator's own expectation file (a hit outside the special-purpose blocks)
# the 1638 rule: no pipeline ends in a stopping reader, so the first line is taken by sed, which reads to the end
TORCLIENT=$(grep -E '^4 [0-9.]+ [0-9]+ rec=' "$D15/tor.expect" | grep -v -E '^4 (0|10|127|169\.254|172\.(1[6-9]|2[0-9]|3[01])|192\.(0\.|168\.)|198\.1[89]|2[2-5][0-9])\.' | sed -n 1p | cut -d' ' -f2)
[ -n "$TORCLIENT" ] || bad "floor mode: no Tor-listed client could be read from the generator's expectation file"
mkdir -p "$W/html/d15" "$W/html/d15off"; echo page > "$W/html/d15/index.html"; echo page > "$W/html/d15off/index.html"
d15_line() { grep -m1 -F "$1 " "$W/logs/d15.log" 2>/dev/null || true; }
# the floor at http level under the http level's default mode (log), deny only in the server block
DATA_DIR="$D15" SERVER_EXTRA='whisper_edge_mode deny; access_log '"$W"'/logs/d15.log d15;' \
    mkconf 1s "whisper_edge_summary $D15/counters;" 'whisper_edge_policy_floor "deny if tor_exit";' 'log_format d15 "$request_uri $status action=$whisper_edge_action program=\"$whisper_edge_program\" tor_exit=$whisper_edge_tor_exit rule_id=$whisper_edge_rule_id";'
rm -rf "$D15/counters"; : > "$W/logs/error.log"; : > "$W/logs/d15.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /d15/index.html "$UNLISTED")" = 200 ]' 10 "the floor server" || bad "floor mode: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
FLOOR16=$(grep -oE 'floor \([^)]*\): 1 rule, program [0-9a-f]{16}, mode log' "$W/logs/start.err" | grep -oE 'program [0-9a-f]{16}' | cut -d' ' -f2)
grep -qF 'the floor will not deny: its mode is the http level'"'"'s (log); add "whisper_edge_mode deny" at http level' "$W/logs/start.err" && [ -n "$FLOOR16" ] \
    && ok "floor mode: the floor line runs under the http level's mode (log, program $FLOOR16) and the configuration test says the floor will not deny while only the server block says deny" \
    || bad "floor mode: the floor line or the will-not-deny line is missing: $(grep -E 'floor' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-160 | tr '\n' '|')"
code_as /d15/index.html?q=dry "$TORCLIENT" >/dev/null; sleep 0.3
l=$(d15_line '/d15/index.html?q=dry')
# a would-deny decides nothing, so the context's program runs after the floor's and the token names both
[[ $l =~ ^/d15/index\.html\?q=dry\ 200\ action=would-deny\ program=\"floor:${FLOOR16}\ ctx:[0-9a-f]{16}\"\ tor_exit=true\ rule_id=-$ ]] \
    && ok "floor mode: the Tor-listed client ($TORCLIENT) is allowed as would-deny, the program token naming the floor and then the context program that ran after it" \
    || bad "floor mode: the dry-run line: $l"
stop; sleep 1
# the http level under deny, the same floor, a location that set mode off
DATA_DIR="$D15" SERVER_EXTRA='access_log '"$W"'/logs/d15.log d15; location /d15off/ { whisper_edge_mode off; }' \
    mkconf 1s "whisper_edge_summary $D15/counters;" 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if tor_exit";' 'log_format d15 "$request_uri $status action=$whisper_edge_action program=\"$whisper_edge_program\" tor_exit=$whisper_edge_tor_exit rule_id=$whisper_edge_rule_id";'
rm -rf "$D15/counters"; : > "$W/logs/error.log"; : > "$W/logs/d15.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /d15off/index.html "$UNLISTED")" = 200 ]' 10 "the deny floor server" || bad "floor mode: the deny server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
! grep -q 'the floor will not deny' "$W/logs/start.err" && grep -qE "floor \([^)]*\): 1 rule, program $FLOOR16, mode deny and deny status 403 from the http level" "$W/logs/start.err" \
    && ok "floor mode: with whisper_edge_mode deny at http level the floor runs under deny and the warning is absent" \
    || bad "floor mode: the floor line under http-level deny: $(grep -E 'floor' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-160 | tr '\n' '|')"
h=$(curl -s -o /dev/null -D - --max-time 5 -H "$(xff "$TORCLIENT")" "http://127.0.0.1:$PORT/d15off/index.html?q=off" | tr -d '\r'); sleep 0.3
l=$(d15_line '/d15off/index.html?q=off')
grep -q '^HTTP/1.1 403' <<<"$h" && grep -qi '^Cache-Control: no-store' <<<"$h" && [ "$l" = "/d15off/index.html?q=off 403 action=deny program=\"floor:$FLOOR16 ctx:-\" tor_exit=true rule_id=floor:1" ] \
    && ok "floor mode: in a location that set mode off the Tor-listed client is denied by the floor: the http level's 403, no-store, program floor:$FLOOR16 ctx:-, rule floor:1" \
    || bad "floor mode: the mode-off arm: $(head -1 <<<"$h"), line \"$l\""
[ "$(code_as /d15off/index.html?q=twin "$UNLISTED")" = 200 ] && ok "floor mode: and the unlisted client passes the same location" || bad "floor mode: the unlisted client got $(code_as /d15off/index.html?q=twin "$UNLISTED") in the mode-off location"
d15_rules=$(stable_text "$D15/counters")
[ "$(rules_count "$d15_rules" "$FLOOR16" 1)" = 1 ] && ok "floor mode: the floor's rule counts exactly one evaluation for the one denied request" \
    || bad "floor mode: the floor's rule 1 counts \"$(rules_count "$d15_rules" "$FLOOR16" 1)\", not 1"
stop; sleep 1
if build_control -DWE_MOD_TEST_MODE_OFF_RETURN; then
    DATA_DIR="$D15" MODULE="$CTL_OUT" SERVER_EXTRA='location /d15off/ { whisper_edge_mode off; }' \
        mkconf 1s "whisper_edge_summary $D15/counters;" 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if tor_exit";'
    rm -rf "$D15/counters"; : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /d15off/index.html "$UNLISTED")" = 200 ]' 10 "the mode-off control"; then
        [ "$(code_as /d15off/index.html "$TORCLIENT")" = 200 ] \
            && ok "floor mode control: a build keeping the shipped early return for a mode-off context serves the Tor-listed client 200, so the floor rows above can fail" \
            || bad "floor mode control: the early-return build answered $(code_as /d15off/index.html "$TORCLIENT")"
    else
        bad "floor mode control: the early-return build did not come up"
    fi
    stop; sleep 1
else
    control_unavailable "floor mode control"
fi

echo
echo "$(date -u +%H:%M:%S) == the counter cap: 65,536 counted rule slots are accepted, 65,537 refused naming the largest contexts =="
# Every context with lines of its own owns a counter slot per rule, after the eight pre-stage slots; a
# configuration may hold 65,536 in all, so a tenant-written tree cannot grow a worker's shard without bound.
# The http level's default program owns one slot here, so 255 locations of 256 log rules and one of 247
# sit exactly at the cap; one more rule is refused at configuration test, naming the five largest contexts.
d16_conf() { # <rules in the last of 256 locations>: a configuration of 255 x 256 identical log rules plus that many
    local n=$1 c k
    mkdir -p "$W/t/d16/logs"
    TCONF="$W/t/d16/nginx.conf"
    { echo "load_module $MODULE; error_log $W/t/d16/logs/error.log info; pid $W/t/d16/logs/nginx.pid; events { worker_connections 64; }"
      echo "http { access_log off; client_body_temp_path $W/t/d16/logs/body; proxy_temp_path $W/t/d16/logs/proxy; fastcgi_temp_path $W/t/d16/logs/fastcgi; uwsgi_temp_path $W/t/d16/logs/uwsgi; scgi_temp_path $W/t/d16/logs/scgi;"
      echo "whisper_edge_data $PLANES; server { listen 127.0.0.1:$PORT; root $W/html;"
      for c in $(seq 1 256); do
          k=256; [ "$c" = 256 ] && k=$n
          # k copies of the line without a stopping reader (yes | head dies of SIGPIPE under pipefail)
          echo "location /c$c/ {"; printf 'whisper_edge_policy "log if tor_exit";\n%.0s' $(seq 1 "$k"); echo "}"
      done
      echo "} }"; } > "$TCONF"
    TRC=0; TOUT=$(nginx -t -c "$TCONF" -p "$W/t/d16" 2>&1) || TRC=$?
}
d16_conf 247
[ "$TRC" = 0 ] && grep -qF '257 contexts with lines, 65528 rules, 8 pre-stage, 1 shard per worker, 524288 bytes per shard' <<<"$TOUT" \
    && ok "counter cap: 65,536 slots (8 pre-stage, the default program's one, 65,527 written rules) are accepted, the shard printed at 524288 bytes" \
    || bad "counter cap: the configuration at the cap: rc $TRC, $(grep -m1 -E 'refused|shard' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-240)"
d16_conf 248
[ "$TRC" != 0 ] && grep -qF 'policy refused: 65537 counted rule slots, over the 65536 a configuration may hold; the largest contexts: http/s1/l1 (256) http/s1/l2 (256) http/s1/l3 (256) http/s1/l4 (256) http/s1/l5 (256)' <<<"$TOUT" \
    && ok "counter cap: one rule more is refused at configuration test, naming the count and the five largest contexts" \
    || bad "counter cap: 65,537 slots: rc $TRC, $(grep -m1 -E 'refused|shard' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-240)"
d16_conf 246
[ "$TRC" = 0 ] && grep -qF '65527 rules, 8 pre-stage' <<<"$TOUT" \
    && ok "counter cap control: one slot under the cap is accepted" \
    || bad "counter cap control: 65,535 slots: rc $TRC, $(grep -m1 -E 'refused|shard' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-200)"
rm -rf "$W/t/d16"
if build_control -DWE_MOD_TEST_CAP_OFF; then
    MODULE="$CTL_OUT" d16_conf 248
    [ "$TRC" = 0 ] && ! grep -q 'counted rule slots, over the 65536' <<<"$TOUT" \
        && ok "counter cap control (the cap lifted): fails the refusal row, 65,537 slots accepted at configuration test" \
        || bad "counter cap control (the cap lifted): rc $TRC, $(grep -m1 -E 'refused|shard' <<<"$TOUT" | sed 's/.*whisper edge: //' | cut -c1-200); the row passed without the code it proves"
    rm -rf "$W/t/d16"
else
    control_unavailable "counter cap control (the cap lifted)"
fi

echo
echo "$(date -u +%H:%M:%S) == the synonym's file absent at configuration time arms when it appears; the directory form waits for a reload =="
# whisper_edge_snapshot is the legacy synonym: its rules are never inert and the file arms on appearance,
# because the installations that have it point it at a path the refresh fills later. The directory form
# is the opposite by design: a plane absent at configuration time is reported and not watched, so a file
# dropped in later binds at the next reload and not before. Both halves are read from the status files
# and from what the listed client gets.
G2="$W/g2"; G2D="$W/g2dir"
rm -rf "$G2" "$G2D"; mkdir -p "$G2" "$G2D"; chmod 0755 "$G2" "$G2D"
g2_armed() { cat "$1"/counters/[0-9]*.status 2>/dev/null | grep -c '^plane reputation armed generation 1 ' || true; }
g2_absent() { cat "$1"/counters/[0-9]*.status 2>/dev/null | grep -c '^plane reputation absent ' || true; }
SNAPSHOT_PATH="$G2/snapshot.bin" mkconf 1s "whisper_edge_summary $G2/counters;"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /enforced/index.html)" = 200 ] && [ "$(g2_absent "$G2")" = 2 ]' 15 "the synonym server with its file absent" \
    && ok "synonym absent: the server starts with the snapshot file absent, both workers report the plane absent, and the listed client is allowed (nothing is armed)" \
    || bad "synonym absent: start rc, listed client $(code /enforced/index.html), absent lines $(g2_absent "$G2"): $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
grep -qF "snapshot \"$G2/snapshot.bin\": reputation, legacy, absent at configuration time; the file arms when it appears, and its rules are never inert" "$W/logs/start.err" \
    && ok "synonym absent: the configuration test says the file is absent and arms when it appears" \
    || bad "synonym absent: the configuration line: $(grep -m1 'snapshot "' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-200)"
cp "$W/snapshot.good" "$G2/.snapshot.tmp"; chmod 0644 "$G2/.snapshot.tmp"; mv -f "$G2/.snapshot.tmp" "$G2/snapshot.bin"
await '[ "$(g2_armed "$G2")" = 2 ]' 15 "the synonym arming on appearance" && [ "$(code /enforced/index.html)" = 403 ] \
    && ok "synonym absent: the file appearing arms in both workers within a tick and the listed client is denied, with no reload" \
    || bad "synonym absent: armed lines $(g2_armed "$G2"), listed client $(code /enforced/index.html)"
stop; sleep 1
DATA_DIR="$G2D" mkconf 1s "whisper_edge_summary $G2D/counters;"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /enforced/index.html)" = 200 ]' 10 "the directory server with the plane absent" \
    && grep -qF "data \"$G2D\": reputation absent;" "$W/logs/start.err" \
    && ok "directory control: with reputation.bin absent the data line reports it absent and the listed client is allowed" \
    || bad "directory control: listed client $(code /enforced/index.html), data line $(grep -m1 'data "' "$W/logs/start.err" | sed 's/.*policy: //' | cut -c1-160)"
cp "$W/snapshot.good" "$G2D/.reputation.tmp"; chmod 0444 "$G2D/.reputation.tmp"; mv -f "$G2D/.reputation.tmp" "$G2D/reputation.bin"
t0=$(cat "$G2D"/counters/[0-9]*.status 2>/dev/null | grep -o ' tick [0-9]*' | sed -n 1p | tr -dc '0-9'); t0=${t0:-0}
await '[ "$(cat "$G2D"/counters/[0-9]*.status 2>/dev/null | grep -o " tick [0-9]*" | sed -n 1p | tr -dc "0-9")" -ge '"$((t0 + 3))"' ]' 15 "three ticks" || bad "directory control: the tick did not advance"
[ "$(g2_armed "$G2D")" = 0 ] && [ "$(code /enforced/index.html)" = 200 ] \
    && ok "directory control: a reputation.bin dropped into the directory is not watched: three ticks later nothing is armed and the listed client still passes" \
    || bad "directory control: armed lines $(g2_armed "$G2D"), listed client $(code /enforced/index.html) before any reload"
signal_master reload
await '[ "$(g2_armed "$G2D")" = 2 ] && [ "$(code /enforced/index.html)" = 403 ]' 15 "the reload binding the file" \
    && ok "directory control: the reload binds the file, the new workers arm it and the listed client is denied" \
    || bad "directory control: after the reload armed lines $(g2_armed "$G2D"), listed client $(code /enforced/index.html)"
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == logging after a rotation: the transition line reaches the reopened file and the syslog socket =="
# The transition line is the module thread's one record of a plane changing state, written through
# nginx's own logger, so it must follow the error log wherever the operator sends it: into the new
# file after `mv error.log error.log.1; nginx -s reopen`, and to a syslog socket named by a second
# error_log, with the status file's log-dropped staying 0. The gate's own datagram listener is the
# syslog server.
Q6="$W/q6"; mkdir -p "$Q6"; chmod 0755 "$Q6"
cp "$PLANES/reputation.bin" "$Q6/reputation.bin"; chmod 0444 "$Q6/reputation.bin"
python3 - "$Q6/syslog.sock" "$W/logs/syslog.txt" > "$W/logs/syslog-listener.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(sys.argv[1])
out = open(sys.argv[2], 'ab', buffering=0)
while True:
    out.write(s.recv(65536) + b"\n")
PY
Q6LISTENER=$!
await '[ -S "$Q6/syslog.sock" ]' 5 "the syslog listener" || bad "rotation: the gate's syslog listener did not bind"
q6_publish() { python3 ../core/make-test-snapshot.py --plane reputation --out "$Q6/.rep.tmp" --format 1 --schema --v6-index none --generation "$1" >/dev/null; chmod 0444 "$Q6/.rep.tmp"; mv -f "$Q6/.rep.tmp" "$Q6/reputation.bin"; }
q6_armed() { cat "$Q6"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane reputation armed generation $1 " || true; }
: > "$W/logs/syslog.txt"
DATA_DIR="$Q6" MAIN_EXTRA="error_log syslog:server=unix:$Q6/syslog.sock,nohostname notice;" mkconf 1s "whisper_edge_summary $Q6/counters;"
rm -rf "$Q6/counters"; : > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ] && [ "$(q6_armed 5)" = 2 ]' 15 "the rotation server" || bad "rotation: the server did not come up or arm: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
mv "$W/logs/error.log" "$W/logs/error.log.1"
signal_master reopen
await '[ -f "$W/logs/error.log" ]' 5 "the reopened log" || bad "rotation: nginx -s reopen did not recreate error.log"
q6_publish 6
await '[ "$(q6_armed 6)" = 2 ]' 15 "the transition after the reopen" || bad "rotation: generation 6 did not arm after the reopen"
n_new=$(grep -c 'whisper edge: .*generation 6' "$W/logs/error.log" || true); n_old=$(grep -c 'whisper edge: .*generation 6' "$W/logs/error.log.1" || true)
[ "$n_new" -ge 2 ] && [ "$n_old" = 0 ] \
    && ok "rotation: after mv and nginx -s reopen the generation-6 transition lines ($n_new) land in the new error.log and none in the rotated file" \
    || bad "rotation: generation-6 lines in the new log $n_new, in the rotated file $n_old"
n_sys=$(grep -c 'whisper edge: .*generation 6' "$W/logs/syslog.txt" || true)
[ "$n_sys" -ge 2 ] && ok "rotation: the same transition lines reached the syslog socket ($n_sys datagrams)" \
    || bad "rotation: syslog datagrams carrying the generation-6 transition: $n_sys ($(wc -c < "$W/logs/syslog.txt") bytes received in all)"
[ "$(cat "$Q6"/counters/[0-9]*.status | grep -c ' log-dropped 0 ')" = 2 ] && ok "rotation: both workers' status lines say log-dropped 0" \
    || bad "rotation: log-dropped: $(cat "$Q6"/counters/[0-9]*.status | grep -o 'log-dropped [0-9]*' | tr '\n' ' ')"
stop; sleep 1
kill "$Q6LISTENER" 2>/dev/null || true; wait "$Q6LISTENER" 2>/dev/null || true

echo
echo "$(date -u +%H:%M:%S) == fail open: no data directive, every plane refused, no thread, no pin, a read-only counters directory =="
# Whatever is missing or broken around the module, the request is served and the module says once what
# it could not do: with no data directive every rule is inert and the module decides nothing; with every
# plane refused by the trust rule the lookups read UNKNOWN and the floor's fixed exemptions still hold;
# with no module thread the inherited planes serve, the process line says no-thread and --status exits 1;
# with the object unpinnable the same; with a read-only counters directory the writers say so once and
# serving goes on. The debug build's file-system-call counter is the core's and is not built here.
F1="$W/f1"; mkdir -p "$F1" "$F1/ro"; chmod 0755 "$F1" "$F1/ro"
cp "$W/snapshot.good" "$F1/reputation.bin"; chmod 0444 "$F1/reputation.bin"   # lists the gate's client; the fixture planes do not
mkdir -p "$W/html/f1"; echo page > "$W/html/f1/index.html"
f1_start() { : > "$W/logs/error.log"; start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /f1/index.html)" = "'"$1"'" ]' 15 "the fail-open server ($2)"; }
# no data directive at all: a mode line alone, and the module decides nothing
SNAPSHOT_PATH="" mkconf 1s
sed -i '/whisper_edge_snapshot /d; /whisper_edge_refresh /d' "$W/nginx.conf"
if f1_start 200 "no data directive"; then
    grep -qF 'no whisper_edge_data or whisper_edge_snapshot: every plane is absent, so every rule is inert and the module decides nothing' "$W/logs/start.err" \
        && [ "$(code /enforced/index.html)" = 200 ] \
        && ok "fail open: with no data directive the configuration test says every rule is inert, and the listed client is served even in a deny location" \
        || bad "fail open: no data directive: listed client in deny $(code /enforced/index.html), line $(grep -m1 -c 'decides nothing' "$W/logs/start.err")"
else
    bad "fail open: the server with no data directive did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1
# every plane refused: the one plane present fails the trust rule (mode 0666)
chmod 0666 "$F1/reputation.bin"
DATA_DIR="$F1" mkconf 1s "whisper_edge_summary $F1/counters;"
rm -rf "$F1/counters"
if f1_start 200 "every plane refused"; then
    await '[ "$(cat "$F1"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane reputation refused ")" = 2 ]' 10 "the refused plane lines" \
        && [ "$(code /enforced/index.html)" = 200 ] && [ "$(code_nohdr /enforced/index.html)" = 200 ] && [ "$(grep -c 'reputation.bin' "$W/logs/error.log")" -ge 1 ] \
        && ok "fail open: a plane refused by the trust rule (mode 0666) reads refused in both status files, the listed client is served (UNKNOWN allows), the loopback peer keeps its exemption, and the refusal is logged" \
        || bad "fail open: refused plane: status $(cat "$F1"/counters/[0-9]*.status 2>/dev/null | grep -o '^plane reputation [a-z]*' | sort | uniq -c | tr '\n' ' '), listed $(code /enforced/index.html), peer $(code_nohdr /enforced/index.html)"
else
    bad "fail open: the server with the refused plane did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1
chmod 0444 "$F1/reputation.bin"
# the counters directory read-only: the writers say so once, serving goes on
chmod 0555 "$F1/ro"
DATA_DIR="$F1" mkconf 1s "whisper_edge_summary $F1/ro/counters;"
if f1_start 200 "a read-only counters directory"; then
    [ "$(code /enforced/index.html)" = 403 ] && [ "$(grep -c 'cannot create the counters directory' "$W/logs/error.log")" -ge 1 ] && [ ! -e "$F1/ro/counters" ] \
        && ok "fail open: with the counters directory unwritable the workers say so ($(grep -c 'cannot create the counters directory' "$W/logs/error.log") line(s)), write nothing, and the listed client is still denied by the armed plane" \
        || bad "fail open: read-only counters: listed $(code /enforced/index.html), lines $(grep -c 'counters directory' "$W/logs/error.log"), created $([ -e "$F1/ro/counters" ] && echo yes || echo no)"
else
    bad "fail open: the server with the read-only counters directory did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
fi
stop; sleep 1; chmod 0755 "$F1/ro"
# no thread, no pin: the core's own controls, each a build
for ctl in WE_MOD_TEST_NO_THREAD WE_MOD_TEST_NO_PIN; do
    if build_control "-D$ctl"; then
        DATA_DIR="$F1" MODULE="$CTL_OUT" mkconf 1s "whisper_edge_summary $F1/counters;"
        rm -rf "$F1/counters"
        if f1_start 200 "$ctl"; then
            src=0; out=$("$SUMMARY_BIN" --status "$F1/counters" 2>&1) || src=$?
            [ "$(code /enforced/index.html)" = 403 ] && [ "$src" = 1 ] && [ "$(grep -c '^process pid .* no-thread' <<<"$out")" = 2 ] && grep -q 'no-thread' "$W/logs/error.log" \
                && ok "fail open ($ctl): the workers serve the inherited planes (the listed client is denied), each writes its status line once with no-thread, logs it once, and --status exits 1" \
                || bad "fail open ($ctl): listed $(code /enforced/index.html), --status rc $src, process lines $(grep -E '^process' <<<"$out" | tr '\n' '|' | cut -c1-200), log $(grep -c 'no-thread' "$W/logs/error.log")"
        else
            bad "fail open ($ctl): the control build did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
        fi
        stop; sleep 1
    else
        control_unavailable "fail open ($ctl)"
    fi
done

echo
echo "$(date -u +%H:%M:%S) == the binary is the same, keyless or keyed =="
# The module reads files and never a key: a build with a key in the environment and on disk where the
# refresh keeps one is byte for byte the keyless build, section by section and as a whole, and the module
# and core sources name no key path, header or directory. The control is a build with a key-shaped string
# planted in the object, which differs; its string is found in the object by the same scan.
if [ -n "$BUILD_TREE" ] && [ -f "$BUILD_TREE/objs/Makefile" ]; then
    K1="$W/k1"; mkdir -p "$K1"
    k1_build() { # <name> [env...]: the production module rebuilt from clean objects under the given environment
        rm -f "$BUILD_TREE"/objs/addon/*/*.o "$BUILD_TREE/objs/ngx_http_whisper_edge_module.so"
        ( cd "$BUILD_TREE" && env "${@:2}" SOURCE_DATE_EPOCH=1700000000 make -f objs/Makefile objs/ngx_http_whisper_edge_module.so ) > "$K1/make-$1.log" 2>&1 || return 1
        cp "$BUILD_TREE/objs/ngx_http_whisper_edge_module.so" "$K1/$1.so"
    }
    : > "$K1/key"; chmod 0600 "$K1/key"; printf 'whisper_live_planted_key_bytes\n' > "$K1/key"
    if k1_build keyless && k1_build keyed WHISPER_EDGE_KEY=whisper_live_planted_key_bytes WE_KEY_FILE="$K1/key" WHISPER_EDGE_KEY_FILE="$K1/key"; then
        for sec in .text .rodata .data .data.rel.ro; do
            objcopy -O binary -j "$sec" "$K1/keyless.so" "$K1/keyless$sec.bin" 2>/dev/null; objcopy -O binary -j "$sec" "$K1/keyed.so" "$K1/keyed$sec.bin" 2>/dev/null
            cmp -s "$K1/keyless$sec.bin" "$K1/keyed$sec.bin" && ok "keyless equals keyed: $sec is byte-identical" || bad "keyless equals keyed: $sec differs between the two builds"
        done
        cmp -s "$K1/keyless.so" "$K1/keyed.so" && ok "keyless equals keyed: the whole module file is identical ($(stat -c %s "$K1/keyless.so") bytes)" \
            || bad "keyless equals keyed: the files differ: $(cmp "$K1/keyless.so" "$K1/keyed.so" 2>&1 | head -c 120)"
    else
        bad "keyless equals keyed: a build failed: $(grep -m1 -E 'error:|Error [0-9]' "$K1"/make-*.log | cut -c1-200)"
    fi
    if build_control -DWE_MOD_TEST_PLANTED_KEY; then
        cmp -s "$K1/keyless.so" "$CTL_OUT" && bad "keyless equals keyed control: the planted-key build is identical to the keyless one (the comparison is blind)" \
            || ok "keyless equals keyed control: a build with a key-shaped string planted differs from the keyless one, so the comparison can fail"
        grep -q 'whisper_live_planted_X-API-Key' "$CTL_OUT" && ok "keyless equals keyed control: and the planted string is found in that object by the scan's own pattern" \
            || bad "keyless equals keyed control: the planted string is not in the control object"
    else
        control_unavailable "keyless equals keyed control"
    fi
    # the production module is left rebuilt from clean objects by build_control; k1_build left the keyed one in place otherwise
    rm -f "$BUILD_TREE"/objs/addon/*/*.o; ( cd "$BUILD_TREE" && make -f objs/Makefile objs/ngx_http_whisper_edge_module.so ) > "$K1/make-restore.log" 2>&1 || bad "keyless equals keyed: the production module did not rebuild after the row"
else
    notproven "keyless equals keyed: no configured nginx tree to build from (set NGX_BUILD, or run with the module built in <tree>/objs)"
fi
scan=$(grep -nE 'X-API-Key|/edge/k/|whisper-edge/key|WHISPER_EDGE_KEY' "$ROOT"/nginx/ngx_http_whisper_edge_module.c "$ROOT"/core/*.c "$ROOT"/core/*.h 2>/dev/null | grep -v 'we_hold_harmless.h' | head -3 || true)
[ -z "$scan" ] && ok "keyless equals keyed: the module and core sources name no key path, header or directory" || bad "keyless equals keyed: a key reference in the sources: $scan"

echo
echo "$(date -u +%H:%M:%S) == the counters, continued: the pre-stage lines by name, an allow rule, and the error-page hops =="
# Every evaluation that fires a rule or a pre-stage mark counts exactly once where it ran: an ACME
# challenge is exempt and counted on its line (the same path with a query is not); a header whose walk
# reaches the cap counts floor-header-capped; a unix peer with no trusted header has no address and
# counts no-address; an explicit allow that fires counts on its rule; a context-rule deny whose error page
# is another context is evaluated on both hops and counts twice on the shared program, while a floor deny
# under the same error_page bypasses the page and counts once on the floor's rule and nowhere else.
N1="$W/n1"; mkdir -p "$N1"; chmod 0755 "$N1"
mkdir -p "$W/html/.well-known/acme-challenge" "$W/html/allow" "$W/html/ep" "$W/html/fep"
echo token > "$W/html/.well-known/acme-challenge/tok"; for d in allow ep fep; do echo "$d page" > "$W/html/$d/index.html"; done
n1_sum() { stable_text "$N1/counters"; }
n1_pre() { local v; v=$(pre_count "$1" "$2"); echo "${v:-0}"; }
n1_rule() { local v; v=$(rules_count "$1" "$2" "$3"); echo "${v:-0}"; }
n1_req() { curl -s -w '\n%{http_code}' --max-time 5 -H "X-Forwarded-For: ${2:-$LISTED, $HOP}" "http://127.0.0.1:$PORT$1"; }   # the body, then the status on its own line: ONE request
n1_start() { rm -rf "$N1/counters"; : > "$W/logs/error.log"; start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /allow/index.html "$UNLISTED")" = 200 ]' 10 "$1"; }
# server A: the client judged past a hop, as everywhere in this gate
SERVER_EXTRA='whisper_edge_mode deny;
        location /allow/ { whisper_edge_policy "allow if listed >= high"; whisper_edge_policy "deny if listed >= low"; }
        location /ep/ { error_page 403 /e.html; }
        location = /e.html { whisper_edge_mode off; }' mkconf 1s "whisper_edge_summary $N1/counters;"
n1_start "the counting server" || bad "counters: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
DEF16=$(grep -oE '"http" \([^)]*\): no lines of its own; runs the default program [0-9a-f]{16}' "$W/logs/start.err" | grep -oE '[0-9a-f]{16}$')
ALLOW16=$(grep -oE '"location \\"/allow/\\"" \([^)]*\): 2 rules, program [0-9a-f]{16}' "$W/logs/start.err" | grep -oE '[0-9a-f]{16}$')
base=$(n1_sum)
c_acme=$(code /.well-known/acme-challenge/tok); c_acmeq=$(code '/.well-known/acme-challenge/tok?x=1')
c_allow=$(code /allow/index.html)
r_ep=$(n1_req /ep/index.html); c_ep=${r_ep##*$'\n'}; b_ep=${r_ep%$'\n'*}; b_ep=${b_ep%$'\n'}   # the page's own final newline dropped
now=$(n1_sum)
d_acme=$(( $(n1_pre "$now" acme) - $(n1_pre "$base" acme) ))
[ "$c_acme" = 200 ] && [ "$c_acmeq" = 403 ] && [ "$d_acme" = 1 ] \
    && ok "counters: the exact ACME challenge is exempt (200) and counts one acme mark; the same path with a query is judged (403) and counts none" \
    || bad "counters: acme $c_acme, with a query $c_acmeq, acme marks +$d_acme"
[ "$c_allow" = 200 ] && [ "$(( $(n1_rule "$now" "$ALLOW16" 1) - $(n1_rule "$base" "$ALLOW16" 1) ))" = 1 ] && [ "$(( $(n1_rule "$now" "$ALLOW16" 2) - $(n1_rule "$base" "$ALLOW16" 2) ))" = 0 ] \
    && ok "counters: an explicit allow that fires counts one on its rule, and the deny behind it none (200)" \
    || bad "counters: allow answered $c_allow, rule 1 +$(( $(n1_rule "$now" "$ALLOW16" 1) - $(n1_rule "$base" "$ALLOW16" 1) )), rule 2 +$(( $(n1_rule "$now" "$ALLOW16" 2) - $(n1_rule "$base" "$ALLOW16" 2) ))"
d_def=$(( $(n1_rule "$now" "$DEF16" 1) - $(n1_rule "$base" "$DEF16" 1) ))
[ "$c_ep" = 403 ] && [ "$b_ep" = "the operator's error page" ] && [ "$d_def" = 2 ] \
    && ok "counters: a context-rule deny whose error page is a mode-off context is evaluated on both hops: the shared default program's rule counts two for one request (403, the operator's page)" \
    || bad "counters: the error-page hop: $c_ep, body \"$b_ep\", the default program's rule 1 +$d_def (2 expected: the deny and the page)"
stop; sleep 1
# server B: the floor under the same error_page, one request, one count on the floor's rule and none on the program
SERVER_EXTRA='location /fep/ { error_page 403 /e.html; }
        location = /e.html { whisper_edge_mode off; }' mkconf 1s "whisper_edge_summary $N1/counters;" 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if listed >= high";'
n1_start "the floor counting server" || bad "counters: the floor server did not come up"
F16=$(grep -oE 'floor \([^)]*\): 1 rule, program [0-9a-f]{16}' "$W/logs/start.err" | grep -oE '[0-9a-f]{16}$')
base=$(n1_sum)
r_fep=$(n1_req /fep/index.html); c_fep=${r_fep##*$'\n'}; b_fep=${r_fep%$'\n'*}
now=$(n1_sum)
[ "$c_fep" = 403 ] && grep -q '<title>403 Forbidden</title>' <<<"$b_fep" && [ "$(( $(n1_rule "$now" "$F16" 1) - $(n1_rule "$base" "$F16" 1) ))" = 1 ] && [ "$(( $(n1_rule "$now" "$DEF16" 1) - $(n1_rule "$base" "$DEF16" 1) ))" = 0 ] \
    && ok "counters: a floor deny under the same error_page bypasses the page (nginx's own 403) and counts once on the floor's rule, nothing on the program" \
    || bad "counters: the floor under error_page: $c_fep, floor rule +$(( $(n1_rule "$now" "$F16" 1) - $(n1_rule "$base" "$F16" 1) )), default rule +$(( $(n1_rule "$now" "$DEF16" 1) - $(n1_rule "$base" "$DEF16" 1) )), body $(head -c 40 <<<"$b_fep")"
stop; sleep 1
# server C: skip mode (no hops line), the walk reaching its cap on seventeen trusted entries
mkconf 1s "whisper_edge_summary $N1/counters;"
sed -i '/whisper_edge_trusted_hops/d' "$W/nginx.conf"
n1_start "the skip-mode server" || bad "counters: the skip-mode server did not come up"
base=$(n1_sum)
seventeen=$(printf '127.0.0.1, %.0s' $(seq 1 16))127.0.0.1
r_cap=$(n1_req /allow/index.html "$seventeen"); c_cap=${r_cap##*$'\n'}
now=$(n1_sum)
d_cap=$(( $(n1_pre "$now" floor-header-capped) - $(n1_pre "$base" floor-header-capped) ))
[ "$c_cap" = 200 ] && [ "$d_cap" = 1 ] \
    && ok "counters: a header of seventeen trusted entries reaches the walk's cap in skip mode: one floor-header-capped mark, the rightmost reached entry judged (200)" \
    || bad "counters: seventeen entries answered $c_cap, capped marks +$d_cap"
stop; sleep 1
# server D: a unix listener and no trusted header, so the peer has no address
SERVER_EXTRA="listen unix:$N1/n1.sock;" mkconf 1s "whisper_edge_summary $N1/counters;"
sed -i '/whisper_edge_trusted_header/d' "$W/nginx.conf"
rm -rf "$N1/counters"; : > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ -S "$N1/n1.sock" ]' 10 "the unix-listener server" || bad "counters: the unix-listener server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
base=$(n1_sum)
c_unix=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --unix-socket "$N1/n1.sock" "http://localhost/enforced/index.html")
now=$(n1_sum)
[ "$c_unix" = 200 ] && [ "$(( $(n1_pre "$now" no-address) - $(n1_pre "$base" no-address) ))" = 1 ] \
    && ok "counters: a request over a unix socket with no trusted header has no address: served (200) and one no-address mark" \
    || bad "counters: the unix peer answered $c_unix, no-address marks +$(( $(n1_pre "$now" no-address) - $(n1_pre "$base" no-address) ))"
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the trusted header's name and the listeners it needs (configuration test) =="
# A header name nginx would drop before any module sees it (one with an underscore, under the default
# underscores_in_headers off) would make the floor judge the proxy itself, so it is refused naming the
# server that drops it; Forwarded carries RFC 7239 syntax the walk does not read; a name that is not a
# token is refused; and a unix listener has no peer address to trust by, so the header needs unix: among
# the trusted proxies. Each refusal is read back from nginx -t, and each control passes.
conft t4-underscore '' '' '' 2>/dev/null || true
TH_HTTP='whisper_edge_trusted_proxy 127.0.0.1; whisper_edge_trusted_hops 2;'
conft t4-underscore "$TH_HTTP whisper_edge_trusted_header X_Real_IP;"
[ "$TRC" != 0 ] && grep -qF 'whisper_edge_trusted_header X_Real_IP ('"$TCONF"':' <<<"$TOUT" && grep -q 'nginx drops header names with underscores unless underscores_in_headers is on (server "a" at' <<<"$TOUT" \
    && ok "trusted header: X_Real_IP is refused under the default underscores_in_headers off, naming the server that would drop it" \
    || bad "trusted header: X_Real_IP: rc $TRC, $(grep -m1 -E 'underscores|syntax is ok' <<<"$TOUT" | cut -c1-220)"
conft t4-underscore-on "$TH_HTTP whisper_edge_trusted_header X_Real_IP;" 'underscores_in_headers on;'
[ "$TRC" = 0 ] && ok "trusted header control: with underscores_in_headers on in every server X_Real_IP is accepted" \
    || bad "trusted header control: X_Real_IP with underscores_in_headers on was refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
for h in Forwarded forwarded FORWARDED; do
    conft "t4-$h" "$TH_HTTP whisper_edge_trusted_header $h;"
    [ "$TRC" != 0 ] && grep -q 'Forwarded uses the RFC 7239 syntax, which this module does not read; name X-Forwarded-For, or a single-address header such as X-Real-IP' <<<"$TOUT" \
        && ok "trusted header: $h is refused as RFC 7239 syntax the walk does not read, naming the way out" \
        || bad "trusted header: $h: rc $TRC, $(grep -m1 -E 'Forwarded|syntax is ok' <<<"$TOUT" | cut -c1-200)"
done
conft t4-space "$TH_HTTP whisper_edge_trusted_header \"X Forwarded\";"
[ "$TRC" != 0 ] && grep -qF 'a header name is a token (RFC 9110 section 5.1); "X Forwarded" contains a space in '"$TCONF"':' <<<"$TOUT" \
    && ok "trusted header: a name with a space is refused as not a token, at the directive's file:line ($(grep -o 'a header name is a token[^;]*;[^\"]*\"[^\"]*\" contains a space' <<<"$TOUT" | sed -n 1p))" \
    || bad "trusted header: \"X Forwarded\": rc $TRC, $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
for h in X-Forwarded-For x-forwarded-for; do
    conft "t4-ok-$h" "$TH_HTTP whisper_edge_trusted_header $h;"
    [ "$TRC" = 0 ] && ok "trusted header control: $h passes" || bad "trusted header control: $h was refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"
done
conft t4-unix "$TH_HTTP whisper_edge_trusted_header X-Forwarded-For;" "listen unix:$W/t/t4-unix/u.sock;"
[ "$TRC" != 0 ] && grep -qF 'whisper_edge_trusted_header is set and "listen unix:'"$W"'/t/t4-unix/u.sock" is a unix socket, whose peer has no address: name unix: in whisper_edge_trusted_proxy to read the header from it, or remove the header' <<<"$TOUT" \
    && ok "trusted header: a unix listener with the header set and no unix: among the trusted proxies is refused, naming the listener and both ways out" \
    || bad "trusted header: the unix listener: rc $TRC, $(grep -m1 -E 'unix|syntax is ok' <<<"$TOUT" | cut -c1-240)"
conft t4-unix-ok "whisper_edge_trusted_proxy 127.0.0.1 unix:; whisper_edge_trusted_hops 2; whisper_edge_trusted_header X-Forwarded-For;" "listen unix:$W/t/t4-unix-ok/u.sock;"
[ "$TRC" = 0 ] && ok "trusted header control: adding unix: to the trusted proxies makes the unix listener pass" \
    || bad "trusted header control: the unix listener with unix: trusted was refused: $(grep -m1 -v 'syntax is ok' <<<"$TOUT" | cut -c1-200)"

echo
echo "$(date -u +%H:%M:%S) == the token set does not depend on the order of variables in log_format =="
# nginx indexes variables for the whole configuration, so the planes a context's generations token names
# are the same whichever log_format reads $whisper_edge_generations first or last; two formats that
# differ only in order log byte-identical tokens on a floor-decided request, routing's among them because
# the http-level export binds it.
V11="$W/v11"; mkdir -p "$V11"; chmod 0755 "$V11"
cp "$PLANES/reputation.bin" "$V11/reputation.bin"; cp "$PLANES/routing.bin" "$V11/routing.bin"; chmod 0444 "$V11"/*.bin
mkdir -p "$W/html/v11"; echo page > "$W/html/v11/index.html"
DATA_DIR="$V11" SERVER_EXTRA='access_log '"$W"'/logs/v11a.log v11a; access_log '"$W"'/logs/v11b.log v11b;' \
    mkconf 1s "whisper_edge_summary $V11/counters;" 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if listed >= high"; whisper_edge_export asn;' \
    'log_format v11a "$whisper_edge_generations|$whisper_edge_country|$whisper_edge_asn"; log_format v11b "$whisper_edge_country|$whisper_edge_asn|$whisper_edge_generations";'
rm -rf "$V11/counters"; : > "$W/logs/error.log"; : > "$W/logs/v11a.log"; : > "$W/logs/v11b.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /v11/index.html "$UNLISTED")" = 200 ]' 10 "the token-set server" || bad "token set: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
code /v11/index.html >/dev/null; sleep 0.3
la=$(sed -n 1p "$W/logs/v11a.log"); lb=$(sed -n 1p "$W/logs/v11b.log")
ga=${la%%|*}; gb=${lb##*|}
[ -n "$ga" ] && [ "$ga" = "$gb" ] && [[ $ga =~ routing:5\.[0-9a-f]{8} ]] && [[ $ga =~ reputation:5\.[0-9a-f]{8} ]] \
    && ok "token set: the generations-first and generations-last formats log the same token set on the floor-decided request, routing's token among them ($ga)" \
    || bad "token set: first \"$ga\", last \"$gb\" (lines \"$la\" and \"$lb\")"
[ "${la#*|}" = "${lb%|*}" ] && ok "token set: and the country and asn fields agree between the two lines (${la#*|})" || bad "token set: the attribute fields differ: \"${la#*|}\" vs \"${lb%|*}\""
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the ACME exemption: the exact form, its HEAD and absolute-form twins, and nothing else =="
# Only the exact challenge path, as received, is exempt: GET or HEAD of /.well-known/acme-challenge/<token>
# with one token segment and no query, the absolute-form request-target included. A query, a bare `?`,
# a %2e dot segment, a percent-encoded token byte, a leading `//`, a second segment or a POST is judged.
# A missing token under try_files is a hop judged where it lands.
mkdir -p "$W/html/.well-known/acme-challenge"; echo token > "$W/html/.well-known/acme-challenge/tok"; echo "front controller" > "$W/html/index.php"
t3() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "$(xff)" "$@"; }
t3u() { curl -s --max-time 5 -H "$(xff "$UNLISTED")" "$@"; }
SERVER_EXTRA='whisper_edge_mode deny;
        location /.well-known/acme-challenge/ { try_files $uri /index.php; }
        location = /index.php { }' mkconf 1s
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ]' 10 "the ACME server" || bad "acme: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
U="http://127.0.0.1:$PORT"
a=$(t3 "$U/.well-known/acme-challenge/tok"); b=$(t3 -I "$U/.well-known/acme-challenge/tok"); c=$(t3 --request-target "$U/.well-known/acme-challenge/tok" "$U/")
[ "$a" = 200 ] && [ "$b" = 200 ] && [ "$c" = 200 ] && [ "$(code /enforced/index.html)" = 403 ] \
    && ok "acme: the exact form, its HEAD and its absolute-form target are exempt (200, 200, 200) for a client the same server denies elsewhere (403)" \
    || bad "acme: exact $a, HEAD $b, absolute-form $c, elsewhere $(code /enforced/index.html)"
forms=(); bad_forms=""
for f in "/.well-known/acme-challenge/tok?x=1" "/.well-known/acme-challenge/tok?" "/.well-known/%2e/acme-challenge/tok" "/.well-known/acme-challenge/%74ok" "//.well-known/acme-challenge/tok" "/.well-known/acme-challenge/a/b"; do
    r=$(t3 --path-as-is "$U$f"); forms+=("$f=$r"); [ "$r" = 403 ] || bad_forms="$bad_forms $f=$r"
done
r=$(t3 -X POST "$U/.well-known/acme-challenge/tok"); forms+=("POST=$r"); [ "$r" = 403 ] || bad_forms="$bad_forms POST=$r"
[ -z "$bad_forms" ] && ok "acme: a query, a bare ?, a %2e segment, a %74 token byte, a leading //, a second segment and a POST are all judged (403 each)" \
    || bad "acme: not every near-form is judged:$bad_forms (all: ${forms[*]})"
tw=""; for f in "/.well-known/acme-challenge/tok?x=1" "/.well-known/%2e/acme-challenge/tok" "//.well-known/acme-challenge/tok"; do r=$(t3u -o /dev/null -w '%{http_code}' --path-as-is "$U$f"); [ "$r" = 200 ] || tw="$tw $f=$r"; done
[ -z "$tw" ] && ok "acme control: the unlisted twin is served the same near-forms (200), so the 403s are the module's judgement" || bad "acme control: the twin got$tw"
m=$(t3 "$U/.well-known/acme-challenge/missing"); mb=$(t3u "$U/.well-known/acme-challenge/missing")
[ "$m" = 403 ] && [ "$mb" = "front controller" ] \
    && ok "acme: a missing token under try_files is a hop judged where it lands: the listed client is denied at /index.php (403) and the twin is served the front controller" \
    || bad "acme: the missing token: listed $m, twin \"$mb\""
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the floor's reach: every request that reaches the access phase, and no other =="
# The floor judges in PREACCESS, so a location that answers in the rewrite phase (`return`) is never
# judged, floor-listed client or not: the README states that residual, and this row holds the statement
# to the wire. The same client is denied by the floor one location over, so the 200 is the phase's and
# not an exemption.
SERVER_EXTRA='location /ret/ { return 200 "answered in the rewrite phase\n"; }
        location /judged/ { }' mkconf 1s 'whisper_edge_mode deny; whisper_edge_policy_floor "deny if listed >= high";'
mkdir -p "$W/html/judged"; echo page > "$W/html/judged/index.html"
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /judged/index.html "$UNLISTED")" = 200 ]' 10 "the reach server" || bad "reach: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
r=$(code /ret/); j=$(code /judged/index.html); b=$(curl -s --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/ret/")
[ "$r" = 200 ] && [ "$b" = "answered in the rewrite phase" ] && [ "$j" = 403 ] \
    && ok "reach: a floor-listed client requesting a location that answers with return is served (200, the rewrite phase ends the request before the floor runs), and is denied by the floor one location over (403)" \
    || bad "reach: return answered $r \"$b\", the judged location $j"
echo "  n/a   reach: the rewrite_by_lua_block arm needs the Lua module, which this nginx does not carry (not NOT PROVEN: the row's own precondition)"
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == header extraction over HTTP/1.1 and HTTP/2: the proxy's line is judged however many forged lines precede it =="
# The walk reads the newest sixteen lines of the field, so a client's forged X-Forwarded-For lines
# (16, 17, 40, 64 or 100 of them) before the proxy's own line never push the proxy's line out: the entry
# the proxy appended is judged, over HTTP/1.1 and over HTTP/2 (prior knowledge), and the listed client is
# denied every time. The controls are the walk given the first line alone and the oldest sixteen lines.
SERVER_EXTRA="listen 127.0.0.1:$PORT2 http2; access_log $W/logs/t5.log t5;" mkconf 1s 'log_format t5 "$request_uri $status $whisper_edge_floor_addr";'
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ]' 10 "the h2 server" || bad "extraction: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
t5() { # <n forged lines> <curl protocol args...>: the status for the listed client behind n forged lines
    local n=$1; shift; local args=() i
    for i in $(seq 1 "$n"); do args+=(-H "X-Forwarded-For: 9.9.$((i / 256)).$((i % 256))"); done
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${args[@]}" -H "$(xff)" "$@"
}
badn=""
for n in 16 17 40 64 100; do
    r1=$(t5 "$n" "http://127.0.0.1:$PORT/enforced/index.html"); r2=$(t5 "$n" --http2-prior-knowledge "http://127.0.0.1:$PORT2/enforced/index.html")
    [ "$r1" = 403 ] && [ "$r2" = 403 ] || badn="$badn n=$n:h1=$r1,h2=$r2"
done
[ -z "$badn" ] && ok "extraction: with 16, 17, 40, 64 and 100 forged lines before the proxy's, the proxy's entry is judged over HTTP/1.1 and HTTP/2 (403 each)" \
    || bad "extraction: the forged lines changed the judgement:$badn"
r2u=$(curl -s -o /dev/null -w '%{http_code} %{http_version}' --max-time 5 --http2-prior-knowledge -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT2/enforced/index.html")
[ "$r2u" = "200 2" ] && ok "extraction control: the unlisted twin over HTTP/2 is served (200, protocol 2)" || bad "extraction control: the twin over h2 got \"$r2u\""
stop; sleep 1
# The controls, on the same configuration with the module swapped, judged by the floor address the access
# log records: the walk given the first field line alone (the core's walk), and nginx's ring keeping the
# oldest sixteen lines in place of the newest (the module's own; nginx hands the walk sixteen lines at
# most, so the core's oldest-sixteen control never sees more). Each judges a forged line, not the listed
# client's entry the proxy appended.
# each control named in full, so the control-bodies guard can read it
for ctl in WE_MOD_TEST_FIRST_LINE:"the first line alone" WE_MOD_TEST_RING_OLDEST:"the oldest sixteen lines kept"; do
    def=${ctl%%:*}; what=${ctl#*:}
    if build_control "-D$def"; then
        sed -i "1s#^load_module .*#load_module $CTL_OUT;#" "$W/nginx.conf"
        : > "$W/logs/t5.log"
        if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ]' 10 "the extraction control"; then
            forged=""
            for n in 16 17 40 64 100; do
                t5 "$n" "http://127.0.0.1:$PORT/enforced/index.html?n=$n&c=$def" >/dev/null
            done
            sleep 0.3
            for n in 16 17 40 64 100; do
                f=$(grep -m1 -F "/enforced/index.html?n=$n&c=$def " "$W/logs/t5.log" | cut -d' ' -f3 || true)
                [ "$f" = "$LISTED" ] || forged="$forged n=$n:${f:-none}"
            done
            [ -n "$forged" ] \
                && ok "extraction control ($what): fails the row, a forged line judged in place of the proxy's entry:$forged" \
                || bad "extraction control ($what): the listed client's entry judged at every n; the row passed without the code it proves"
        else
            bad "extraction control ($what): the build did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
        fi
        stop; sleep 1
    else
        control_unavailable "extraction control ($what)"
    fi
done
# printed, not counted: the core's oldest-sixteen control acts only on a walk handed more than sixteen lines,
# and nginx hands it sixteen at most (the module keeps the newest sixteen in its own ring), so on nginx that
# control has nothing to change; the ring's own control above takes its place
echo "  n/a   extraction: the core's oldest-sixteen control (WE_MOD_TEST_FIRST_16_LINES) cannot reach nginx's walk, which gets sixteen lines at most from the module's ring (measured: the floor identical to the release build at 1, 16 and 17 forged lines); WE_MOD_TEST_RING_OLDEST is nginx's control (not NOT PROVEN: the core define has nothing to act on here)"

echo
echo "$(date -u +%H:%M:%S) == realip rewrites the connection's address; the floor keeps the TCP peer it captured first =="
# set_real_ip_from 0.0.0.0/0 with real_ip_header X-Client lets any client choose $remote_addr. The module's
# POST_READ handler runs before realip and keeps the socket's peer as the floor address, so a forged
# X-Client never reaches the floor: $whisper_edge_floor_addr is the loopback peer while $remote_addr is
# the forged, listed address. The loopback peer's exemption covers the floor's steps only; step 4 judges
# the address realip derived by the context's rules, with no exemption of its own (the forged address is
# benchmarking space, hold-harmless, and listed), so the request is denied there. No trusted header here,
# so the peer is the whole address the floor judges.
SERVER_EXTRA='access_log '"$W"'/logs/t10.log t10;' mkconf 1s 'set_real_ip_from 0.0.0.0/0; real_ip_header X-Client;' 'log_format t10 "$request_uri $status remote=$remote_addr floor=$whisper_edge_floor_addr action=$whisper_edge_action reason=$whisper_edge_reason";'
sed -i '/whisper_edge_trusted_header/d; /real_ip_header X-Forwarded-For/d' "$W/nginx.conf"
: > "$W/logs/error.log"; : > "$W/logs/t10.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_nohdr /enforced/index.html)" = 200 ]' 10 "the realip server" || bad "realip: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "X-Client: $LISTED" "http://127.0.0.1:$PORT/enforced/index.html?q=forged"); sleep 0.3
l=$(grep -m1 -F '/enforced/index.html?q=forged ' "$W/logs/t10.log" || true)
[ "$r" = 403 ] && [ "$l" = "/enforced/index.html?q=forged 403 remote=$LISTED floor=127.0.0.1 action=deny reason=-" ] \
    && ok "realip: a listed address forged into X-Client becomes \$remote_addr (realip), while the floor address stays the TCP peer 127.0.0.1; the peer's exemption covers the floor's steps, and step 4 denies the forged listed address although it is hold-harmless space (403)" \
    || bad "realip: status $r, line \"$l\""
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == behind a proxy only realip trusts: the context judges the client, the proxy keeps its exemption =="
# The installer's shape for a site behind a proxy on the same box: realip trusts the loopback proxy and
# reads X-Forwarded-For, and the module has no trust list of its own, so the floor's address is the TCP
# peer, 127.0.0.1, which is hold-harmless. That exemption covers the floor's steps; step 4 judges the
# address realip derived by the context's rules, with no exemption of its own, so a hold-harmless client
# behind the proxy is allowed because it is listed nowhere, never as exempt. Every other row reaches its listed client past a
# trusted hop with the module's own trust list, which is why none of them saw this shape. The client here
# must be outside hold-harmless (the fixture's benchmarking space is in it), so its own snapshot lists
# 21.0.0.0/24 at HIGH; 21.0.0.5 is that listed client, 198.41.0.4 (a.root-servers.net) the hold-harmless one.
RP="$W/realip-only"; mkdir -p "$RP"; chmod 0755 "$RP"
python3 ../core/make-test-snapshot.py "$RP/snapshot.bin" 1 0 67 352321536 352321791; chmod 0644 "$RP/snapshot.bin"   # HIGH with the drop flag (0x43)
# a stock error_log: nginx's distribution configuration names no level, which keeps error and above, so the
# deny line and the log mode's WOULD DENY line must be at error to be seen there
rp_start() { # <module>
    MODULE="$1" SNAPSHOT_PATH="$RP/snapshot.bin" SERVER_EXTRA='access_log '"$W"'/logs/rp.log rp;' mkconf 1s '' 'log_format rp "$request_uri $status remote=$remote_addr floor=$whisper_edge_floor_addr action=$whisper_edge_action reason=$whisper_edge_reason";'
    sed -i '/whisper_edge_trusted_proxy/d; /whisper_edge_trusted_header/d; /whisper_edge_trusted_hops/d' "$W/nginx.conf"
    sed -i "s#^error_log $W/logs/error.log info;#error_log $W/logs/error.log;#" "$W/nginx.conf"
    : > "$W/logs/error.log"; : > "$W/logs/rp.log"
    start
    await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_nohdr /enforced/index.html)" = 200 ]' 10 "the realip-only server"
}
rp_req() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 ${3:+-H "X-Forwarded-For: $3"} "http://127.0.0.1:$PORT$1/index.html?q=$2"; }
rp_line() { sleep 0.3; grep -m1 -F "/index.html?q=$1 " "$W/logs/rp.log" || true; }
rp_start "$MODULE" || bad "realip-only: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
r=$(rp_req /enforced listed 21.0.0.5); l=$(rp_line listed)
[ "$r" = 403 ] && [[ $l == "/enforced/index.html?q=listed 403 remote=21.0.0.5 floor=127.0.0.1 action=deny "* ]] \
    && ok "realip-only: a listed client (21.0.0.5, HIGH) behind the loopback proxy is denied by the context (403), the floor still the proxy 127.0.0.1" \
    || bad "realip-only: the listed client behind the loopback proxy: status $r, line \"$l\""
r=$(rp_req /enforced self); l=$(rp_line self)
[ "$r" = 200 ] && [ "$l" = "/enforced/index.html?q=self 200 remote=127.0.0.1 floor=127.0.0.1 action=allow reason=hold-harmless" ] \
    && ok "realip-only: the proxy's own request (no X-Forwarded-For) is exempt as the loopback peer (200)" \
    || bad "realip-only: the proxy's own request: status $r, line \"$l\""
r=$(rp_req /enforced root 198.41.0.4); l=$(rp_line root)
[ "$r" = 200 ] && [ "$l" = "/enforced/index.html?q=root 200 remote=198.41.0.4 floor=127.0.0.1 action=allow reason=-" ] \
    && ok "realip-only: a hold-harmless client (198.41.0.4) behind the proxy is judged at step 4 and allowed as unlisted, reason=- and not hold-harmless (200)" \
    || bad "realip-only: the hold-harmless client behind the proxy: status $r, line \"$l\""
r=$(rp_req "" logmode 21.0.0.5); sleep 0.3
grep -q '\[error\] .*whisper edge: denied 21\.0\.0\.5, .*, verdict high,spamhaus-drop, evidence ' "$W/logs/error.log" \
    && ok "deny line: on a stock error_log (no level) the deny is written at error, nginx's own level for a denial, with the canonical verdict \"verdict high,spamhaus-drop\" every server's line prints" \
    || bad "deny line: no [error] deny line on a stock error_log: $(grep -m1 'whisper edge: denied' "$W/logs/error.log" | cut -c1-160)"
[ "$r" = 200 ] && grep -q '\[error\] .*whisper edge: WOULD DENY 21\.0\.0\.5, ' "$W/logs/error.log" \
    && ok "would-deny line: on a stock error_log the log mode's WOULD DENY is written at error too (status $r), so log mode is seen there" \
    || bad "would-deny line: status $r, no [error] WOULD DENY line on a stock error_log: $(grep -m1 'WOULD DENY' "$W/logs/error.log" | cut -c1-160)"
stop; sleep 1
if build_control -DWE_MOD_TEST_DENY_AT_WARN; then
    rp_start "$CTL_OUT" || true
    rp_req /enforced listed 21.0.0.5 >/dev/null; rp_req "" logmode 21.0.0.5 >/dev/null; sleep 0.3
    ! grep -q 'whisper edge: \(denied\|WOULD DENY\) 21\.0\.0\.5' "$W/logs/error.log" \
        && ok "deny line control (both lines at warn): a stock error_log shows neither, so the rows above prove the level" \
        || bad "deny line control (both lines at warn): a line reached the stock error_log; the rows pass without the code they prove"
    stop; sleep 1
else
    control_unavailable "deny line control (both lines at warn)"
fi

echo
echo "$(date -u +%H:%M:%S) == the evidence of an IPv6 listing: the deny line cites it as it cites an IPv4 one =="
# testdata/interop.snap is the real builder's file: 2001:db8::1 is listed HIGH with the evidence EXAMPLE-6,
# 192.0.2.0 critical with EXAMPLE-DROP-1 (testdata/expected.txt). Each walked past the trusted hop is judged,
# denied, and its deny line carries the listing's evidence. The Apache and OpenLiteSpeed gates assert the
# same IPv6 listing's evidence with the same literal, read from the same expected.txt, so the three servers'
# lines carry it byte for byte. Each outcome's line is rate-limited to one a second, so the two wait it out.
EV6=$(awk '$1 == 6 && $2 == "2001:db8::1" { print $4 }' ../core/testdata/expected.txt)
EV4=$(awk '$1 == 4 && $2 == "192.0.2.0" { print $4 }' ../core/testdata/expected.txt)
E6="$W/ev6"; mkdir -p "$E6"; chmod 0755 "$E6"
cp ../core/testdata/interop.snap "$E6/snapshot.bin"; chmod 0644 "$E6/snapshot.bin"
SNAPSHOT_PATH="$E6/snapshot.bin" mkconf 1s
: > "$W/logs/error.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_nohdr /)" = 200 ]' 10 "the evidence server" || bad "evidence: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
sleep 1.1
r6=$(code_as /enforced/ 2001:db8::1); sleep 1.1
r4=$(code_as /enforced/ 192.0.2.0); sleep 0.3
if [ -n "$EV6" ] && [ "$r6" = 403 ] && grep -qF "whisper edge: denied 2001:db8::1, " "$W/logs/error.log" \
        && grep -qF ", evidence $EV6 (" <<<"$(grep -F "whisper edge: denied 2001:db8::1, " "$W/logs/error.log")"; then
    ok "evidence: an IPv6 listing's deny line cites its evidence ($EV6), the literal the Apache and OpenLiteSpeed gates assert for the same listing (403)"
else
    bad "evidence: the IPv6 listing 2001:db8::1: status $r6, line \"$(grep -m1 -F 'denied 2001:db8::1' "$W/logs/error.log" | cut -c1-200)\", want evidence ${EV6:-<none in expected.txt>}"
fi
if [ -n "$EV4" ] && [ "$r4" = 403 ] && grep -qF ", evidence $EV4 (" <<<"$(grep -F "whisper edge: denied 192.0.2.0, " "$W/logs/error.log")"; then
    ok "evidence: and an IPv4 listing of the same file cites its own ($EV4), so the row reads the file's evidence per family (403)"
else
    bad "evidence: the IPv4 listing 192.0.2.0: status $r4, line \"$(grep -m1 -F 'denied 192.0.2.0' "$W/logs/error.log" | cut -c1-200)\", want evidence ${EV4:-<none in expected.txt>}"
fi
stop; sleep 1

echo
echo "$(date -u +%H:%M:%S) == the verdict's spelling for every severity byte, and the reserved nibbles =="
# $whisper_edge_verdict renders the reputation severity of the server's address with nginx's own
# spelling of the drop flag (`,drop`): low, medium, high, critical, `critical,drop` for 0x44, and the
# reserved nibbles 0x05 and 0x45 clamped to critical and critical,drop. Each byte is a snapshot renamed
# in under the running server (the synonym re-arms on the new inode), read back through a log line.
V5="$W/v5"; mkdir -p "$V5"; chmod 0755 "$V5"
python3 ../core/make-test-snapshot.py "$V5/snapshot.bin" 20 0 1 "$RANGE_START" "$RANGE_END"; chmod 0644 "$V5/snapshot.bin"
SNAPSHOT_PATH="$V5/snapshot.bin" SERVER_EXTRA='access_log '"$W"'/logs/v5.log v5;' mkconf 1s "whisper_edge_summary $V5/counters;" 'log_format v5 "$request_uri verdict=$whisper_edge_verdict listed=$whisper_edge_listed";'
rm -rf "$V5/counters"; : > "$W/logs/error.log"; : > "$W/logs/v5.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ]' 10 "the verdict server" || bad "verdict: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
v5_gen() { cat "$V5"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane reputation armed generation $1 " || true; }
g=20
for pair in 1:low 2:medium 3:high 4:critical 68:critical,drop 5:critical 69:critical,drop; do
    sev=${pair%%:*}; want=${pair#*:}
    if [ "$g" != 20 ]; then
        # one publish per 8 s: a displaced map holds a retire slot for the 30 s grace and there are four, so a
        # fifth publish inside one grace is deferred until a slot frees (the thread says so once and arms
        # nothing meanwhile); this row measures the renderer, not the retire list, and must not trip it
        sleep 6
        python3 ../core/make-test-snapshot.py "$V5/.snap.tmp" "$g" 0 "$sev" "$RANGE_START" "$RANGE_END"; chmod 0644 "$V5/.snap.tmp"; mv -f "$V5/.snap.tmp" "$V5/snapshot.bin"
    fi
    await '[ "$(v5_gen '"$g"')" = 2 ]' 20 "generation $g armed" || bad "verdict: generation $g (severity byte $sev) did not arm in both workers within 20 s (the thread logs nothing when it misses one: $(grep -c "generation $g verified" "$W/logs/error.log" || true) arming lines)"
    code "/?q=sev$sev" >/dev/null; sleep 0.3
    l=$(grep -m1 -F "/?q=sev$sev " "$W/logs/v5.log" || true)
    [ "$l" = "/?q=sev$sev verdict=$want listed=${want%%,*}" ] \
        && ok "verdict: severity byte $(printf '0x%02x' "$sev") renders \"$want\" (listed ${want%%,*})" \
        || bad "verdict: severity byte $(printf '0x%02x' "$sev"): line \"$l\", wanted verdict=$want"
    g=$((g + 1))
done
code_as "/?q=none" "$UNLISTED" >/dev/null; sleep 0.3
l=$(grep -m1 -F '/?q=none ' "$W/logs/v5.log" || true)
[ "$l" = "/?q=none verdict=none listed=none" ] && ok "verdict: the unlisted address renders none" || bad "verdict: the unlisted address: \"$l\""
[ "$(cat "$V5"/counters/[0-9]*.status | grep -c "^plane reputation armed .* deferred 0")" = 2 ] \
    && ok "verdict: no publish was deferred by the retire list on the way (deferred 0 on both plane lines)" \
    || bad "verdict: the retire list deferred a publish: $(cat "$V5"/counters/[0-9]*.status | grep -o "deferred [0-9]*" | tr "\n" " ")"
stop; sleep 1

echo "$(date -u +%H:%M:%S) == realip in a location alone: the decision runs after it and the context rule denies the listed client =="
# The decision runs last in PREACCESS, so realip configured only in a location has rewritten the
# connection's address by the time that location's rule judges it: the listed client behind the trusted
# peer is denied there by the context rule, $whisper_edge_listed reads high with no lazy mark, and the
# floor address stays the TCP peer. The late post-read module arm needs a second dynamic module built
# against this nginx and is not a row yet.
SERVER_EXTRA='access_log '"$W"'/logs/t10b.log t10b;
        location /loc/ { set_real_ip_from 127.0.0.1; set_real_ip_from '"$HOP"'; real_ip_header X-Forwarded-For; real_ip_recursive on; whisper_edge_mode deny; }' \
    mkconf 1s 'log_format t10b "$request_uri $status remote=$remote_addr floor=$whisper_edge_floor_addr listed=$whisper_edge_listed generations=\"$whisper_edge_generations\"";'
sed -i '/^    set_real_ip_from /d; /^    real_ip_header X-Forwarded-For;/d; /^    real_ip_recursive on;/d' "$W/nginx.conf"
mkdir -p "$W/html/loc"; echo page > "$W/html/loc/index.html"
: > "$W/logs/error.log"; : > "$W/logs/t10b.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /loc/index.html "$UNLISTED")" = 200 ]' 10 "the location-realip server" || bad "realip location: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
r=$(code /loc/index.html?q=loc); sleep 0.3; l=$(grep -m1 -F '/loc/index.html?q=loc ' "$W/logs/t10b.log" || true)
[ "$r" = 403 ] && [[ $l =~ ^/loc/index\.html\?q=loc\ 403\ remote=198\.18\.0\.5\ floor=198\.18\.0\.5\ listed=high\ generations=\"reputation:1\.[0-9a-f]{8}\ tenant:-a\"$ ]] \
    && ok "realip location: with realip only in the location the listed client is denied there by the context rule (403), \$remote_addr is realip's client, listed reads high with no lazy mark" \
    || bad "realip location: status $r, line \"$l\""
stop; sleep 1

echo "$(date -u +%H:%M:%S) == the walk on the wire: the entry forms the header can carry, and what the floor judges for each =="
# The walk reads the header the trusted peer appended, right to left, hops entries deep: a port suffix
# and a bracketed IPv6 entry with a port parse to their address; an empty value, `, ,`, an oversized
# entry and junk nearest the hop leave the floor on the peer with an unparsed mark; junk beyond the
# judged entry is never reached; the floor address and the reason are read back from the log line.
SERVER_EXTRA='access_log '"$W"'/logs/t1.log t1;' mkconf 1s 'log_format t1 "$request_uri $status floor=$whisper_edge_floor_addr action=$whisper_edge_action reason=$whisper_edge_reason";'
: > "$W/logs/error.log"; : > "$W/logs/t1.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ]' 10 "the walk server" || bad "walk: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
# t1 <tag> <header value>: the request with that X-Forwarded-For, then the log line's fields; an EMPTY value is sent as
# curl's `X-Forwarded-For;` form, because `-H "X-Forwarded-For: "` makes curl drop the header altogether
t1() { local h="X-Forwarded-For: $2"; [ -z "$2" ] && h="X-Forwarded-For;"; curl -s -o /dev/null --max-time 5 -H "$h" "http://127.0.0.1:$PORT/enforced/index.html?q=$1"; sleep 0.2; grep -m1 -F "/enforced/index.html?q=$1 " "$W/logs/t1.log" | cut -d' ' -f2- || true; }
big=$(printf '9%.0s' $(seq 1 2000))
l1=$(t1 port "$LISTED:1234, $HOP");            [ "$l1" = "403 floor=$LISTED action=deny reason=-" ] && ok "walk: a port suffix on the client's entry parses to the address: denied, floor $LISTED" || bad "walk: port suffix: \"$l1\""
l2=$(t1 v6 "[2001:db8::1]:443, $HOP");         [ "$l2" = "200 floor=2001:db8::1 action=allow reason=-" ] && ok "walk: a bracketed IPv6 entry with a port parses to the address (unlisted, allowed, floor 2001:db8::1)" || bad "walk: bracketed v6: \"$l2\""
l3=$(t1 empty "");                             [ "$l3" = "200 floor=127.0.0.1 action=allow reason=floor-header-unparsed" ] && ok "walk: an empty value (zero entries) leaves the floor on the peer, not eligible, marked unparsed" || bad "walk: empty value: \"$l3\""
l4=$(t1 commas ", ,");                         [ "$l4" = "200 floor=127.0.0.1 action=allow reason=floor-header-unparsed" ] && ok "walk: a value of separators alone is unparsed: the floor on the peer, not eligible for an exemption" || bad "walk: separators: \"$l4\""
l5=$(t1 junk "$LISTED, junk, $HOP");           [ "$l5" = "200 floor=$HOP action=allow reason=floor-header-unparsed" ] && ok "walk: junk at the judged position (hop 2) leaves the last parsed entry, the balancer's own, judged and marked unparsed (not eligible, so no exemption)" || bad "walk: junk at hop 2: \"$l5\""
l6=$(t1 beyond "junk, $LISTED, $HOP");          [ "$l6" = "403 floor=$LISTED action=deny reason=-" ] && ok "walk: junk beyond the judged entry is never reached: the client is judged and denied" || bad "walk: junk beyond: \"$l6\""
l7=$(t1 big "$big, $HOP");                     [ "$l7" = "200 floor=$HOP action=allow reason=floor-header-unparsed" ] && ok "walk: a 2,000-byte entry at the judged position is not parsed past its 54th byte: the balancer's entry judged, marked unparsed" || bad "walk: oversized entry: \"$l7\""
stop; sleep 1

echo "$(date -u +%H:%M:%S) == the generations token: a lazy read after a swap carries the new generation, each no-value state its letter =="
# The decision reads reputation; tor is read only by a variable in the log phase, so its entry is filled
# lazily at that read, from whatever generation is armed then: after a swap of tor the lazy value carries
# the new generation and a `*`, while the decision's plane keeps its generation. A plane the binding
# refused renders -r, an absent one -a, a stale one its generation with `~`. Publishes are paced under the
# retire list's grace.
V4="$W/v4"; rm -rf "$V4"; mkdir -p "$V4"; chmod 0755 "$V4"
cp "$PLANES/reputation.bin" "$V4/reputation.bin"; cp "$PLANES/tor.bin" "$V4/tor.bin"; chmod 0444 "$V4"/*.bin
mkdir -p "$W/html/v4"; echo page > "$W/html/v4/index.html"
v4_pub() { python3 ../core/make-test-snapshot.py --plane tor --out "$V4/.tor.tmp" --format 2 --schema --generation "$1" ${2:+--valid-until "$2"} >/dev/null; chmod 0444 "$V4/.tor.tmp"; mv -f "$V4/.tor.tmp" "$V4/tor.bin"; }
v4_tor() { cat "$V4"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane tor $1 " || true; }
v4_line() { code "/v4/index.html?q=$1" >/dev/null; sleep 0.3; grep -m1 -F "/v4/index.html?q=$1 " "$W/logs/v4.log" | cut -d' ' -f2- || true; }
v4_start() { rm -rf "$V4/counters"; : > "$W/logs/error.log"; : > "$W/logs/v4.log"; start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /v4/index.html)" = 200 ]' 10 "$1"; }
DATA_DIR="$V4" SERVER_EXTRA='access_log '"$W"'/logs/v4.log v4;' mkconf 1s "whisper_edge_summary $V4/counters;" 'log_format v4 "$request_uri tor_exit=$whisper_edge_tor_exit generations=\"$whisper_edge_generations\"";'
if v4_start "the token server"; then
    await '[ "$(v4_tor "armed generation 5")" = 2 ]' 10 "tor armed" || bad "token: tor did not arm"
    l=$(v4_line before)
    [[ $l =~ ^tor_exit=false\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:5\.([0-9a-f]{8})\*\ tenant:-a\"$ ]] && d5=${BASH_REMATCH[1]} \
        && ok "token: the decision's plane reads reputation:5 with no mark; tor, read only by the variable, is a lazy fill at generation 5 with its mark (tor:5.$d5*)" \
        || bad "token: before the swap: \"$l\""
    sleep 6; v4_pub 6
    await '[ "$(v4_tor "armed generation 6")" = 2 ]' 15 "tor generation 6" || bad "token: tor generation 6 did not arm"
    l=$(v4_line after)
    [[ $l =~ ^tor_exit=false\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:6\.([0-9a-f]{8})\*\ tenant:-a\"$ ]] && [ "${BASH_REMATCH[1]}" != "$d5" ] \
        && ok "token: after the swap the lazy value carries the new generation and digest (tor:6.${BASH_REMATCH[1]}*) while the decision's plane keeps reputation:5" \
        || bad "token: after the swap: \"$l\""
    sleep 6; v4_pub 7 1000
    await '[ "$(v4_tor "stale generation 7")" = 2 ] || [ "$(v4_tor "armed generation 7")" = 2 ]' 15 "tor generation 7, past its validity" || bad "token: tor generation 7 did not arm"
    l=$(v4_line stale)
    [[ $l =~ ^tor_exit=(false|unknown)\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:7\.[0-9a-f]{8}~\*?\ tenant:-a\"$ ]] \
        && ok "token: a plane past its validity renders its generation with the stale mark (${l#*generations=})" \
        || bad "token: the stale plane: \"$l\""
fi
stop; sleep 1
chmod 0666 "$V4/tor.bin"
if v4_start "the refused-plane server"; then
    l=$(v4_line refused)
    # a letter takes the lazy mark when the read that produced it was lazy (the variable's, here), as the core's
    # rule states for any lazy fill; tenant's -a carries none because the pre-stage read it. Recorded for the
    # differential, whose Python column settles the spelling.
    [[ $l =~ ^tor_exit=unknown\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:-r\*\ tenant:-a\"$ ]] \
        && ok "token: a plane the binding refused (mode 0666) renders tor:-r with the lazy mark of the variable's read, its attribute unknown" \
        || bad "token: the refused plane: \"$l\""
fi
stop; sleep 1
rm -f "$V4/tor.bin"
if v4_start "the absent-plane server"; then
    l=$(v4_line absent)
    [[ $l =~ ^tor_exit=unknown\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:-a\*\ tenant:-a\"$ ]] \
        && ok "token: an absent plane renders tor:-a with the lazy mark of the variable's read (tenant:-a, read by the pre-stage, carries none), its attribute unknown" \
        || bad "token: the absent plane: \"$l\""
fi
stop; sleep 1

echo "$(date -u +%H:%M:%S) == the tenant pre-stage: a tenant-listed client counts tenant, and stale-tenant once the plane is past its validity =="
# The tenant plane is read by the tenant step before any program, so it is bound whenever present. A
# client the plane lists is decided there and counts one tenant mark, its tenant attribute true; once the
# plane is past its validity the same client counts one stale-tenant mark instead. The fixture is the
# generator's tenant plane, the client read from its own expectation file (a hit outside the special
# blocks), the second plane renamed in under the running server, paced under the retire list's grace.
TN="$W/tenant"; rm -rf "$TN"; mkdir -p "$TN"; chmod 0755 "$TN"
cp "$PLANES/reputation.bin" "$TN/reputation.bin"
python3 ../core/make-test-snapshot.py --plane tenant --out "$TN/tenant.bin" --format 2 --schema --generation 5 --expect "$TN/tenant.expect" >/dev/null
chmod 0444 "$TN"/*.bin
TENCLIENT=$(grep -E '^4 [0-9.]+ [0-9]+ rec=' "$TN/tenant.expect" | grep -v -E '^4 (0|10|127|169\.254|172\.(1[6-9]|2[0-9]|3[01])|192\.(0\.|168\.)|198\.1[89]|2[2-5][0-9])\.' | sed -n 1p | cut -d' ' -f2)
[ -n "$TENCLIENT" ] || bad "tenant: no tenant-listed client could be read from the generator's expectation file"
mkdir -p "$W/html/tn"; echo page > "$W/html/tn/index.html"
tn_line() { code_as "/tn/index.html?q=$1" "$TENCLIENT" >/dev/null; sleep 0.3; grep -m1 -F "/tn/index.html?q=$1 " "$W/logs/tn.log" | cut -d' ' -f2- || true; }
tn_pre() { local v; v=$(pre_count "$1" "$2"); echo "${v:-0}"; }
DATA_DIR="$TN" SERVER_EXTRA='access_log '"$W"'/logs/tn.log tn;' mkconf 1s "whisper_edge_summary $TN/counters;" 'log_format tn "$request_uri $status action=$whisper_edge_action reason=$whisper_edge_reason allow=$whisper_edge_tenant_allow deny=$whisper_edge_tenant_deny";'
rm -rf "$TN/counters"; : > "$W/logs/error.log"; : > "$W/logs/tn.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /tn/index.html "$UNLISTED")" = 200 ] && [ "$(cat "$TN"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane tenant armed generation 5 ")" = 2 ]' 15 "the tenant server" || bad "tenant: the server did not come up or did not arm the tenant plane: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
base=$(stable_text "$TN/counters")
l=$(tn_line listed)
now=$(stable_text "$TN/counters")
[[ $l =~ ^200\ action=allow\ reason=tenant\ allow=true\ deny=false$ ]] && [ "$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))" = 1 ] \
    && ok "tenant: the tenant-listed client ($TENCLIENT) is decided by the tenant step (reason tenant, tenant_allow true) and counts one tenant mark" \
    || bad "tenant: line \"$l\", tenant marks +$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))"
# stale within the 48-hour grace: the tenant step still decides and counts stale-tenant; past the grace the
# plane is lapsed, the step decides nothing, the program does, and the attributes render lapsed:
tn_pub() { python3 ../core/make-test-snapshot.py --plane tenant --out "$TN/.tenant.tmp" --format 2 --schema --generation "$1" --valid-until "$2" >/dev/null; chmod 0444 "$TN/.tenant.tmp"; mv -f "$TN/.tenant.tmp" "$TN/tenant.bin"; }
tn_state() { cat "$TN"/counters/[0-9]*.status 2>/dev/null | grep -c -E "^plane tenant [a-z]+ generation $1 " || true; }
sleep 6; tn_pub 6 "$(( $(date +%s) * 1000 - 3600000 ))"
await '[ "$(tn_state 6)" = 2 ]' 20 "the stale tenant plane" || bad "tenant: generation 6 (an hour past its validity) did not arrive in both workers"
base=$(stable_text "$TN/counters")
l=$(tn_line stale)
now=$(stable_text "$TN/counters")
[[ $l =~ ^200\ action=allow\ reason=stale-tenant\ allow=stale:true\ deny=stale:false$ ]] && [ "$(( $(tn_pre "$now" stale-tenant) - $(tn_pre "$base" stale-tenant) ))" = 1 ] && [ "$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))" = 0 ] \
    && ok "tenant: an hour past its validity, inside the 48-hour grace, the plane still decides the client with a stale-tenant mark (reason stale-tenant, tenant_allow stale:true), no tenant mark" \
    || bad "tenant: the stale arm: line \"$l\", stale-tenant +$(( $(tn_pre "$now" stale-tenant) - $(tn_pre "$base" stale-tenant) )), tenant +$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))"
sleep 6; tn_pub 7 1000
await '[ "$(tn_state 7)" = 2 ]' 20 "the lapsed tenant plane" || bad "tenant: generation 7 (far past its validity) did not arrive in both workers"
base=$(stable_text "$TN/counters")
l=$(tn_line lapsed)
now=$(stable_text "$TN/counters")
[[ $l =~ ^200\ action=allow\ reason=-\ allow=lapsed:true\ deny=lapsed:false$ ]] && [ "$(( $(tn_pre "$now" stale-tenant) - $(tn_pre "$base" stale-tenant) ))" = 0 ] && [ "$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))" = 0 ] \
    && ok "tenant: past the grace the plane is lapsed: the tenant step decides nothing (the program allows, reason -), the attributes render lapsed:, and no pre-stage mark moves" \
    || bad "tenant: the lapsed arm: line \"$l\", stale-tenant +$(( $(tn_pre "$now" stale-tenant) - $(tn_pre "$base" stale-tenant) )), tenant +$(( $(tn_pre "$now" tenant) - $(tn_pre "$base" tenant) ))"
stop; sleep 1

echo "$(date -u +%H:%M:%S) == subrequests are never evaluated: an SSI include of a deny location is served under the page's decision =="
# A subrequest is never judged: an allowing page that includes a location whose own rule would deny the
# listed client serves the included body, counts nothing on that rule and logs nothing of its own
# beyond nginx's subrequest line, which under log_subrequest on carries the main request's variables.
# The same client requesting the location directly is denied, so the rule is live. The location's rule text
# differs from the default program's on purpose: an identical text is interned into one program with one
# digest, and the summary sums by (digest, rule), so the page's own would-deny would read as the include's.
V8="$W/v8"; mkdir -p "$W/html/page" "$W/html/admin" "$V8"; chmod 0755 "$V8"
printf 'page[<!--# include virtual="/admin/report" -->]\n' > "$W/html/page/index.html"; printf "the report" > "$W/html/admin/report"   # no final newline, so the page's bytes are exactly page[the report]
SERVER_EXTRA='access_log '"$W"'/logs/v8.log v8; log_subrequest on;
        location /page/ { ssi on; }
        location /admin/ { whisper_edge_mode deny; whisper_edge_policy "deny if listed >= medium"; }' \
    mkconf 1s "whisper_edge_summary $V8/counters;" 'log_format v8 "$uri $status action=$whisper_edge_action";'   # $uri is the subrequest's own; $request_uri is the main request's on both lines
rm -rf "$V8/counters"; : > "$W/logs/error.log"; : > "$W/logs/v8.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /page/index.html "$UNLISTED")" = 200 ]' 10 "the subrequest server" || bad "subrequest: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
ADMIN16=$(grep -oE '"location \\"/admin/\\"" \([^)]*\): 1 rule, program [0-9a-f]{16}' "$W/logs/start.err" | grep -oE '[0-9a-f]{16}$')
base=$(stable_text "$V8/counters")
r=$(curl -s -w '\n%{http_code}' --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/page/index.html?q=inc"); c=${r##*$'\n'}; b=${r%$'\n'*}; b=${b%$'\n'}
mid=$(stable_text "$V8/counters")
d=$(code /admin/report?q=direct); sleep 0.3
now=$(stable_text "$V8/counters")
[ "$c" = 200 ] && [ "$b" = "page[the report]" ] && [ "$d" = 403 ] \
    && ok "subrequest: the listed client's page includes the deny location's body (200, \"$b\") while a direct request to it is denied (403)" \
    || bad "subrequest: page $c \"$b\", direct $d"
v8_rule() { local v; v=$(rules_count "$1" "$ADMIN16" 1); echo "${v:-0}"; }
d_page=$(( $(v8_rule "$mid") - $(v8_rule "$base") )); d_direct=$(( $(v8_rule "$now") - $(v8_rule "$mid") ))
[ "$d_page" = 0 ] && [ "$d_direct" = 1 ] \
    && ok "subrequest: the deny rule counted nothing for the page with its include and once for the direct request" \
    || bad "subrequest: the deny rule moved by $d_page for the page with its include and by $d_direct for the direct request (0 and 1 expected)"
m=$(grep -c -E '^/page/index.html 200 action=would-deny$' "$W/logs/v8.log" || true); sub=$(grep -c -E '^/admin/report 200 action=would-deny$' "$W/logs/v8.log" || true)
[ "$m" = 1 ] && [ "$sub" = 1 ] \
    && ok "subrequest: under log_subrequest on the include's own line shows its status (200) beside the main request's decision (would-deny), one line each" \
    || bad "subrequest: main lines $m, subrequest lines $sub: $(cut -c1-80 "$W/logs/v8.log" | tr '\n' '|')"
stop; sleep 1

echo "$(date -u +%H:%M:%S) == two requests interleaved on one worker: each log line carries its own request's values =="
# One worker, a slow upstream the gate runs itself: A, the listed client, is held on it while B, the
# unlisted client, is decided and logged; then A's upstream answers and A's log line is rendered. Each
# line carries its own request's floor address, verdict and the attribute of a plane its decision did not
# read (filled at that request's own log time), never the other's. The tor plane lists A alone, so the two
# lines' tor_exit differ; the control fills A's record from the worker scratch's last decision, B's, and A's
# line then carries B's tor_exit.
V6="$W/v6"; rm -rf "$V6"; mkdir -p "$V6"; chmod 0755 "$V6"
cp "$W/snapshot.good" "$V6/reputation.bin"
a_key=$(python3 -c 'import ipaddress, sys; print(int(ipaddress.ip_address(sys.argv[1])))' "$LISTED")
echo "4 $a_key $a_key flags=1" > "$V6/tor.records"
python3 ../core/make-test-snapshot.py --plane tor --out "$V6/tor.bin" --format 2 --schema --records "$V6/tor.records" --generation 5 >/dev/null
chmod 0444 "$V6"/*.bin
PORT3=$((PORT + 2))
if [ -n "$(port_holder "$PORT3")" ]; then
    bad "interleave: 127.0.0.1:$PORT3 (the gate's slow upstream) is held by $(port_holder "$PORT3")"
else
    python3 - "$PORT3" > "$W/logs/slow-upstream.log" 2>&1 <<'PY' &
import http.server, sys, time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(3)
        body = b"slow\n"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
    V6UP=$!
    await '[ -n "$(port_holder "$PORT3")" ]' 5 "the slow upstream" || bad "interleave: the gate's slow upstream did not bind"
    v6_run() { # <module>: starts the one-worker server, holds A on the slow upstream, decides B, leaves la, lb and V6_ORDER
        DATA_DIR="$V6" MODULE="$1" SERVER_EXTRA='access_log '"$W"'/logs/v6.log v6;
                location /slow/ { proxy_pass http://127.0.0.1:'"$PORT3"'; }' \
            mkconf 1s "whisper_edge_summary $V6/counters;" 'log_format v6 "$request_uri $status floor=$whisper_edge_floor_addr listed=$whisper_edge_listed tor_exit=$whisper_edge_tor_exit generations=\"$whisper_edge_generations\"";'
        sed -i 's/^worker_processes 2;/worker_processes 1;/' "$W/nginx.conf"
        rm -rf "$V6/counters"; : > "$W/logs/error.log"; : > "$W/logs/v6.log"
        start
        await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ] && [ "$(workers | wc -w)" -ge 1 ]' 10 "the one-worker server" || bad "interleave: the server did not come up: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
        nw=0; for p in $(workers); do grep -q "worker process" "/proc/$p/cmdline" 2>/dev/null && nw=$((nw + 1)); done
        V6_NW=$nw
        curl -s -o /dev/null --max-time 10 -H "$(xff)" "http://127.0.0.1:$PORT/slow/?q=A" &
        V6A=$!
        sleep 0.5
        code_as "/enforced/index.html?q=B" "$UNLISTED" >/dev/null
        wait "$V6A" 2>/dev/null || true; sleep 0.3
        la=$(grep -m1 -F '/slow/?q=A ' "$W/logs/v6.log" | cut -d' ' -f2- || true); lb=$(grep -m1 -F '/enforced/index.html?q=B ' "$W/logs/v6.log" | cut -d' ' -f2- || true)
        V6_ORDER=$([ "$(grep -n -m1 -F '/enforced/index.html?q=B ' "$W/logs/v6.log" | cut -d: -f1)" -lt "$(grep -n -m1 -F '/slow/?q=A ' "$W/logs/v6.log" | cut -d: -f1)" ] && echo B-first || echo A-first)
        stop; sleep 1
    }
    v6_run "$MODULE"
    [ "$V6_NW" = 1 ] && ok "interleave: one serving worker" || bad "interleave: $V6_NW serving workers, not 1"
    [[ $la =~ ^200\ floor=$LISTED\ listed=high\ tor_exit=true\ generations=\"reputation:1\.[0-9a-f]{8}\ tor:5\.[0-9a-f]{8}\*\ tenant:-a\"$ ]] \
        && [[ $lb =~ ^200\ floor=$UNLISTED\ listed=none\ tor_exit=false\ generations=\"reputation:1\.[0-9a-f]{8}\ tor:5\.[0-9a-f]{8}\*\ tenant:-a\"$ ]] \
        && [ "$(grep -n -m1 -F '/enforced/index.html?q=B ' "$W/logs/v6.log" | cut -d: -f1)" -lt "$(grep -n -m1 -F '/slow/?q=A ' "$W/logs/v6.log" | cut -d: -f1)" ] \
        && ok "interleave: B was logged while A was held (B's line first), and each line carries its own floor address and verdict (A $LISTED/high, B $UNLISTED/none) with tor filled at its own log time" \
        || bad "interleave: A \"$la\"; B \"$lb\"; B at line $(grep -n -m1 -F '/enforced/index.html?q=B ' "$W/logs/v6.log" | cut -d: -f1), A at line $(grep -n -m1 -F '/slow/?q=A ' "$W/logs/v6.log" | cut -d: -f1)"
    if build_control -DWE_MOD_TEST_WORKER_SCRATCH_FILL; then
        v6_run "$CTL_OUT"
        v6_deaths=$(grep -c 'exited on signal' "$W/logs/error.log" || true)
        ! [[ $la =~ ^200\ floor=$LISTED\ listed=high\ tor_exit=true\  ]] \
            && ok "interleave control (the fill keyed by the worker scratch's last decision): fails the row, A's line \"$la\" with $v6_deaths worker(s) lost to a signal" \
            || bad "interleave control (the fill keyed by the worker scratch's last decision): A \"$la\", order $V6_ORDER; the row passed without the code it proves"
    else
        control_unavailable "interleave control (the fill keyed by the worker scratch's last decision)"
    fi
    kill "$V6UP" 2>/dev/null || true; wait "$V6UP" 2>/dev/null || true
fi

echo "$(date -u +%H:%M:%S) == the transition line: the first one after start, the 511-byte cut of a 256-rule program, the heads =="
# A program of 256 rules alternating `allow if tor_exit` and `log if tor_exit`. When tor goes stale every
# odd rule captures and every even one is disarmed, and the uncut entry is 990 bytes by the model computed
# here before the run (the derivation of fmt_ranges); the ring entry and the logged line are cut
# at 511 bytes, byte for byte the same, the head intact. Then reputation goes stale (the head's out set
# grows to reputation,tor) and the tenant lapses (tenant=lapsed). Publishes are paced under the retire
# list's grace. The first row is the first transition after the workers start, with nothing published
# before it.
Q6B="$W/q6b"; rm -rf "$Q6B"; mkdir -p "$Q6B/d"; chmod 0755 "$Q6B" "$Q6B/d"
q6b_pub() { # <plane> <generation> [valid-until]
    if [ "$1" = reputation ]; then
        python3 ../core/make-test-snapshot.py --plane reputation --out "$Q6B/d/.p.tmp" --format 1 --v6-index none --schema --generation "$2" ${3:+--valid-until "$3"} >/dev/null
    else
        python3 ../core/make-test-snapshot.py --plane "$1" --out "$Q6B/d/.p.tmp" --format 2 --schema --generation "$2" ${3:+--valid-until "$3"} >/dev/null
    fi
    chmod 0444 "$Q6B/d/.p.tmp"; mv -f "$Q6B/d/.p.tmp" "$Q6B/d/$1.bin"
}
q6b_pub reputation 5; q6b_pub tor 5; q6b_pub tenant 5
RULES256=""; for _ in $(seq 1 128); do RULES256="$RULES256 whisper_edge_policy \"allow if tor_exit\"; whisper_edge_policy \"log if tor_exit\";"; done
q6b_lines() { grep -E "whisper edge: plane $1 " "$W/logs/error.log" | grep -F ' out=' | sed 's/^.*whisper edge: //' || true; }
q6b_start() { rm -rf "$Q6B/c"; : > "$W/logs/error.log"; start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /)" = 200 ] && [ "$(cat "$Q6B"/c/[0-9]*.status 2>/dev/null | grep -c "^plane tor armed generation 5 ")" = 2 ]' 15 "$1"; }
DATA_DIR="$Q6B/d" SERVER_EXTRA="location /b/ { $RULES256 }" mkconf 1s "whisper_edge_summary $Q6B/c;"
if q6b_start "the 256-rule server"; then
    sleep 6; q6b_pub tor 6 1000
    await '[ "$(cat "$Q6B"/c/[0-9]*.status 2>/dev/null | grep -c "^plane tor stale generation 6 ")" = 2 ]' 15 "tor stale" || bad "transition: tor generation 6 did not go stale"
    sleep 2
    n=$(q6b_lines tor | grep -c . || true)
    [ "$n" -ge 2 ] && ok "transition: the first transition after the workers start is logged ($n lines)" \
        || bad "transition: the first transition after the workers start is not logged: $n tor lines, $(cat "$Q6B"/c/[0-9]*.status | grep -c '^transition ') ring entries (the core takes its baseline on a worker's first apply, which is this change)"
fi
stop; sleep 1
q6b_pub tor 5
if q6b_start "the 256-rule server, again"; then
    sleep 6; q6b_pub tor 6
    await '[ "$(cat "$Q6B"/c/[0-9]*.status 2>/dev/null | grep -c "^plane tor armed generation 6 ")" = 2 ]' 15 "tor 6 fresh" || bad "transition: tor generation 6 did not arm"
    sleep 6; q6b_pub tor 7 1000
    await '[ "$(q6b_lines tor | grep -c "rules 1,3,5")" -ge 2 ]' 15 "the bound entry" || bad "transition: no bound entry for the 256-rule program"
    uncut=$(python3 -c 'print("plane tor stale out=tor tenant=fresh: rules " + ",".join(str(i) for i in range(1,256,2)) + " allow captures; rules " + ",".join(str(i) for i in range(2,257,2)) + " disarmed")')
    want=${uncut:0:511}
    got=$(q6b_lines tor | grep 'rules 1,3,5' | sed -n 1p)
    # the status file is rewritten on the next tick, so the ring is read once both workers' files carry the entry
    await '[ "$(cat "$Q6B"/c/[0-9]*.status 2>/dev/null | grep -c "^transition [0-9]* \"plane tor stale out=tor tenant=fresh: rules 1,3,5")" = 2 ]' 10 "the ring entry" || bad "transition: the status ring did not carry the bound entry within 10 s"
    ring=$(cat "$Q6B"/c/[0-9]*.status | sed -n 's/^transition [0-9]* "\(plane tor stale out=tor tenant=fresh: rules 1,3,5.*\)"$/\1/p' | sed -n 1p)
    [ "${#uncut}" = 990 ] && [ "${#got}" = 511 ] && [ "$got" = "$want" ] && [ "$ring" = "$got" ] \
        && ok "transition: the 256-rule program's entry is cut at 511 bytes of its 990-byte uncut text (the model's, computed before the run), the head intact, the logged line and the status ring byte for byte the same" \
        || bad "transition: uncut ${#uncut} (990 expected), logged ${#got} (511), equal to the model's cut: $([ "$got" = "$want" ] && echo yes || echo no), equal to the ring: $([ "$ring" = "$got" ] && echo yes || echo no)"
    sleep 6; q6b_pub reputation 6 1000
    await '[ "$(q6b_lines reputation | grep -c "^plane reputation stale out=reputation,tor tenant=fresh: ")" -ge 2 ]' 15 "the reputation head" \
        && ok "transition: reputation going stale second, the head's out set reads reputation,tor, the tenant fresh" \
        || bad "transition: the second head: $(q6b_lines reputation | sed -n 1p | cut -c1-80)"
    sleep 6; q6b_pub tenant 6 1000
    await '[ "$(q6b_lines tenant | grep -c "^plane tenant lapsed out=reputation,tor tenant=lapsed: ")" -ge 2 ]' 15 "the lapsed tenant head" \
        && ok "transition: a transition while the tenant is lapsed reads tenant=lapsed in its head" \
        || bad "transition: the lapsed head: $(q6b_lines tenant | sed -n 1p | cut -c1-80)"
    [ "$(cat "$Q6B"/c/[0-9]*.status | grep -c ' log-dropped 0 ')" = 2 ] && ok "transition: log-dropped 0 on both process lines" || bad "transition: log-dropped: $(cat "$Q6B"/c/[0-9]*.status | grep -o 'log-dropped [0-9]*' | tr '\n' ' ')"
fi
stop; sleep 1

echo "$(date -u +%H:%M:%S) == a module loaded after this one that registers a post-read handler is refused, and a reload into it keeps the running server =="
# The floor reads the TCP peer in POST_READ before anything can rewrite it, so the module's POST_READ
# handler must run first, which nginx gives the handler pushed last. A dynamic module loaded after this
# one that pushes its own post-read handler would run before it, and the configuration is refused with
# the fix, under nginx -t too; the same module loaded before this one passes. The probe module is
# built here from the configured nginx tree, a post-read handler and nothing else.
if [ -n "$BUILD_TREE" ] && [ -f "$BUILD_TREE/objs/Makefile" ]; then
    LM="$W/latemod"; mkdir -p "$LM"
    cat > "$LM/ngx_http_gate_postread_module.c" <<'C'
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
static ngx_int_t gate_postread_handler(ngx_http_request_t *r) { (void) r; return NGX_DECLINED; }
static ngx_int_t gate_postread_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    *h = gate_postread_handler;
    return NGX_OK;
}
static ngx_http_module_t gate_postread_ctx = { NULL, gate_postread_init, NULL, NULL, NULL, NULL, NULL, NULL };
ngx_module_t ngx_http_gate_postread_module = {
    NGX_MODULE_V1, &gate_postread_ctx, NULL, NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING
};
ngx_module_t *ngx_modules[] = { &ngx_http_gate_postread_module, NULL };
char *ngx_module_names[] = { "ngx_http_gate_postread_module", NULL };
char *ngx_module_order[] = { NULL };
C
    lm_cflags=$(sed -n 's/^CFLAGS *= *//p' "$BUILD_TREE/objs/Makefile" | sed -n 1p)
    lm_incs=$(sed -n '/^ALL_INCS *=/,/^$/p' "$BUILD_TREE/objs/Makefile" | tr -d '\\\n' | sed 's/^ALL_INCS *= *//')
    # shellcheck disable=SC2086
    if ( cd "$BUILD_TREE" && cc -shared -fPIC $lm_cflags $lm_incs -o "$LM/late.so" "$LM/ngx_http_gate_postread_module.c" ) > "$LM/make.log" 2>&1; then
        conft late-after "" ""
        # load_module belongs before events: the probe goes second, right after this module's own line
        { sed -n 1p "$TCONF"; echo "load_module $LM/late.so;"; sed -n '2,$p' "$TCONF"; } > "$LM/after.conf.tmp" && cp "$LM/after.conf.tmp" "$TCONF"
        TRC=0; TOUT=$(nginx -t -c "$TCONF" -p "$W/t/late-after" 2>&1) || TRC=$?
        [ "$TRC" != 0 ] && grep -qF 'whisper edge: a module loaded after this one registers a post-read handler, which could rewrite the client address before the floor reads it; put the load_module line for ngx_http_whisper_edge_module last (nginx -t names this, and a reload into it is refused while the running configuration keeps serving)' <<<"$TOUT" \
            && ok "late module: a dynamic module loaded after this one that registers a post-read handler is refused under nginx -t, naming the fix" \
            || bad "late module: loaded after: rc $TRC, $(grep -m1 -E 'post-read|emerg|syntax is ok' <<<"$TOUT" | cut -c1-200)"
        # the control: the same file with the probe loaded first, before this module
        grep -v -x -F "load_module $LM/late.so;" "$W/t/late-after/nginx.conf" > "$LM/before.conf.tmp"
        { echo "load_module $LM/late.so;"; cat "$LM/before.conf.tmp"; } > "$W/t/late-after/nginx.conf"
        TRC=0; TOUT=$(nginx -t -c "$W/t/late-after/nginx.conf" -p "$W/t/late-after" 2>&1) || TRC=$?
        [ "$TRC" = 0 ] && ok "late module control: the same module loaded before this one passes (this module's post-read handler is the last pushed, so it runs first)" \
            || bad "late module control: loaded before: rc $TRC, $(grep -m1 -E 'post-read|emerg' <<<"$TOUT" | cut -c1-200)"
        # The reload into the misorder. A running server is reloaded into the same configuration with the probe
        # loaded after this module, under steady requests: by SIGHUP to the master, the new cycle is refused
        # with the misorder named in the master's log while the master and the same workers keep serving the
        # old generation; by nginx -s reload, the signal process refuses it, naming the misorder, and signals
        # nothing. A fresh start on it does not start. The control asserts the order in init_module, which
        # nginx makes fatal at a reload: the master exits.
        lm_why='a module loaded after this one registers a post-read handler, which could rewrite the client address before the floor reads it; put the load_module line for ngx_http_whisper_edge_module last (nginx -t names this, and a reload into it is refused while the running configuration keeps serving)'
        mkdir -p "$W/html/lm"; echo page > "$W/html/lm/index.html"
        lm_conf() { # <module> <late: 1 loads the probe after it>
            MODULE="$1" SERVER_EXTRA='access_log '"$W"'/logs/lm.log lm;' mkconf 1s 'log_format lm "$request_uri $status $whisper_edge_generations";'
            [ "$2" = 1 ] && sed -i "1a load_module $LM/late.so;" "$W/nginx.conf"
            return 0
        }
        lm_reload() { # <module> <hup|signal>: leaves LM_MASTER, LM_SAME, LM_N, LM_BAD, LM_GENS, LM_SIG
            local m w0 wall lp
            : > "$W/logs/error.log"; : > "$W/logs/lm.log"; rm -f "$W/lm.stop"
            LM_MASTER=""; LM_SAME=""; LM_N=0; LM_BAD=""; LM_GENS=""; LM_SIG=""
            lm_conf "$1" 0
            start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /lm/index.html)" = 200 ]' 15 "the ordered server" || { LM_MASTER="no start"; stop; sleep 1; return; }
            m=$(cat "$W/logs/nginx.pid"); w0=$(pgrep -P "$m" -f '^nginx: worker process' | sort | tr '\n' ' '); wall=$(workers)
            ( i=0; while [ ! -f "$W/lm.stop" ]; do i=$((i+1)); code "/lm/index.html?n=$i" >/dev/null; sleep 0.05; done ) & lp=$!
            sleep 1; LM_P0=$(wc -l < "$W/logs/lm.log")
            lm_conf "$1" 1
            if [ "$2" = hup ]; then kill -HUP "$m"; else LM_SIG=0; nginx -s reload -c "$W/nginx.conf" -p "$W" 2>"$W/logs/lm-signal.err" || LM_SIG=$?; fi
            sleep 3
            LM_MASTER=$(kill -0 "$m" 2>/dev/null && echo yes || echo no)
            LM_SAME=$([ -n "$w0" ] && [ "$(pgrep -P "$m" -f '^nginx: worker process' 2>/dev/null | sort | tr '\n' ' ')" = "$w0" ] && echo yes || echo no)
            sleep 1; touch "$W/lm.stop"; wait "$lp" 2>/dev/null || true
            LM_N=$(wc -l < "$W/logs/lm.log"); LM_BAD=$(awk '$2 != 200' "$W/logs/lm.log" | wc -l)
            LM_AFTER=$((LM_N - LM_P0))
            LM_GENS=$( { grep -o 'reputation:[0-9a-z-]*' "$W/logs/lm.log" || true; } | sort -u | tr '\n' ' ')
            lm_conf "$1" 0
            # shellcheck disable=SC2086
            if kill -0 "$m" 2>/dev/null; then stop; else kill $wall 2>/dev/null || true; fi   # a master gone leaves its children
            sleep 1
        }
        lm_reload "$MODULE" hup
        [ "$LM_MASTER" = yes ] && [ "$LM_SAME" = yes ] && grep -qF "whisper edge: $lm_why" "$W/logs/error.log" \
            && ok "late module: a reload (SIGHUP) into the misorder is refused, the master's log naming it and the fix, and the running master and the same workers keep serving" \
            || bad "late module: the SIGHUP reload into the misorder: master $LM_MASTER, same workers $LM_SAME, named $(grep -c 'registers a post-read handler' "$W/logs/error.log" || true)"
        [ "$LM_P0" -ge 1 ] && [ "$LM_AFTER" -ge 1 ] && [ "$LM_BAD" = 0 ] && [ "$(wc -w <<<"$LM_GENS")" = 1 ] \
            && ok "late module: $LM_N requests before and after that reload ($LM_P0, $LM_AFTER), every one answered 200 at the running generation ($LM_GENS)" \
            || bad "late module: across the SIGHUP reload: $LM_P0 before, $LM_AFTER after, $LM_BAD not 200, generations $LM_GENS"
        lm_reload "$MODULE" signal
        [ "$LM_SIG" != 0 ] && grep -qF "$lm_why" "$W/logs/lm-signal.err" && [ "$LM_MASTER" = yes ] && [ "$LM_SAME" = yes ] && [ "$LM_BAD" = 0 ] \
            && ok "late module: nginx -s reload into the misorder is refused by the signal process (exit $LM_SIG), naming it, and the running server is untouched and answers every request ($LM_N)" \
            || bad "late module: nginx -s reload into the misorder: exit $LM_SIG, master $LM_MASTER, same workers $LM_SAME, $LM_BAD of $LM_N not 200, named $(grep -c 'post-read' "$W/logs/lm-signal.err" || true)"
        lm_conf "$MODULE" 1; : > "$W/logs/start.err"
        if nginx -c "$W/nginx.conf" -p "$W" 2>"$W/logs/start.err"; then
            bad "late module: a fresh start on the misorder started"; stop; sleep 1
        else
            grep -qF "$lm_why" "$W/logs/start.err" && ok "late module: a fresh start on the misorder does not start, naming it" \
                || bad "late module: the refused start said: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
        fi
        if build_control -DWE_MOD_TEST_ORDER_IN_INIT; then
            lm_reload "$CTL_OUT" hup
            [ "$LM_MASTER" = no ] \
                && ok "late module control (the order asserted in init_module): fails the reload row, the master exits at the SIGHUP" \
                || bad "late module control (the order asserted in init_module): master $LM_MASTER after the SIGHUP; the row passed without the code it proves"
        else
            control_unavailable "late module control (the order asserted in init_module)"
        fi
    else
        bad "late module: the probe module did not build: $(grep -m1 -E 'error' "$LM/make.log" | cut -c1-200)"
    fi
else
    notproven "late module: no configured nginx tree to build the probe module from (set NGX_BUILD, or run with the module built in <tree>/objs)"
fi

echo "$(date -u +%H:%M:%S) == the walk's corpus: IPv6 forms at the judged position, and trust tables in skip mode =="
# The IPv6 forms at hop 2: each one the ABNF accepts is judged and rendered in its RFC 5952 form; each it
# refuses leaves the balancer's entry judged, marked unparsed. Then skip mode (no hops line) over trust
# tables with nested, adjacent and duplicate prefixes: trusted entries are skipped right to left and the
# first untrusted one is judged. One form, 1:2:3:4:5:6:7::, the module's walk accepts and nginx's own realip
# does not, so the server's address stays the balancer's hop ($HOP, benchmarking space, hold-harmless):
# step 4 judges it by the rules with no exemption of its own, and listed nowhere it gets the default
# allow, reason=-, never reason=hold-harmless; the floor still renders the walked entry.
SERVER_EXTRA='access_log '"$W"'/logs/t1b.log t1b;' mkconf 1s 'log_format t1b "$request_uri $status floor=$whisper_edge_floor_addr reason=$whisper_edge_reason";'
: > "$W/logs/error.log"; : > "$W/logs/t1b.log"
start
await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /enforced/index.html "$UNLISTED")" = 200 ]' 10 "the IPv6-forms server" || bad "walk corpus: the server did not come up"
t1b() { curl -s -o /dev/null --max-time 5 -H "X-Forwarded-For: $2" "http://127.0.0.1:$PORT/enforced/index.html?q=$1"; sleep 0.1; grep -m1 -F "/enforced/index.html?q=$1 " "$W/logs/t1b.log" | cut -d' ' -f3- || true; }
v6bad=""; i=0
while IFS='|' read -r form want; do
    i=$((i + 1)); got=$(t1b "v6f$i" "$form, $HOP")
    [ "$got" = "$want" ] || v6bad="$v6bad [$form] got \"$got\" want \"$want\";"
done <<EOF2
1:2:3:4:5:6:7::|floor=1:2:3:4:5:6:7:0 reason=-
1:2:3:4:5:6:1.2.3.4|floor=1:2:3:4:5:6:102:304 reason=-
2001:db8:0:0:1:0:0:1|floor=2001:db8::1:0:0:1 reason=-
2001:db8::1:443|floor=2001:db8::1:443 reason=-
[2001:db8::7]:8080|floor=2001:db8::7 reason=-
1::2:3:4:5:6:7:8|floor=$HOP reason=floor-header-unparsed
1:2:3:4:5:6:7:1.2.3.4|floor=$HOP reason=floor-header-unparsed
:::1|floor=$HOP reason=floor-header-unparsed
fe80::1%eth0|floor=$HOP reason=floor-header-unparsed
12345::1|floor=$HOP reason=floor-header-unparsed
::1.2.3.04|floor=$HOP reason=floor-header-unparsed
::a.b.c.d|floor=$HOP reason=floor-header-unparsed
EOF2
[ -z "$v6bad" ] && ok "walk corpus: five IPv6 forms the ABNF accepts are judged in their RFC 5952 rendering, and seven it refuses (nine groups, an embedded IPv4 past eight, :::, a zone id, a five-digit hextet, a leading-zero octet, a non-numeric embedded IPv4) leave the balancer's entry judged and unparsed" \
    || bad "walk corpus: IPv6 forms:$v6bad"
stop; sleep 1
# skip mode over trust tables: each server trusts the loopback peer and the table under test
t1t() { # <tag> <trusted_proxy list> <header> <wanted floor>
    SERVER_EXTRA='access_log '"$W"'/logs/t1b.log t1b;' mkconf 1s 'log_format t1b "$request_uri $status floor=$whisper_edge_floor_addr reason=$whisper_edge_reason";'
    sed -i "/whisper_edge_trusted_hops/d; s#^    whisper_edge_trusted_proxy .*#    whisper_edge_trusted_proxy $2;#" "$W/nginx.conf"
    : > "$W/logs/t1b.log"; : > "$W/logs/error.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_nohdr /enforced/index.html)" = 200 ]' 10 "the trust-table server ($1)"; then
        got=$(t1b "$1" "$3"); stop; sleep 1
        [[ $got == "floor=$4 "* ]] && return 0
        echo "$got"; return 1
    fi
    stop; sleep 1; echo "the server did not start: $(tail -1 "$W/logs/start.err" | cut -c1-160)"; return 1
}
r=$(t1t nested "127.0.0.1 10.0.0.0/8 10.1.0.0/16" "$LISTED, 10.1.2.3, 10.2.0.1" "$LISTED") \
    && ok "walk corpus: nested trusted prefixes (10/8 holding 10.1/16) are skipped through both, and the first untrusted entry ($LISTED) is judged" \
    || bad "walk corpus: nested prefixes: $r"
r=$(t1t adjacent "127.0.0.1 10.0.0.0/9 10.128.0.0/9" "$LISTED, 10.200.0.1, 10.5.0.1" "$LISTED") \
    && ok "walk corpus: adjacent prefixes (10.0/9 and 10.128/9) each trust their half, and the client beyond them is judged" \
    || bad "walk corpus: adjacent prefixes: $r"
r=$(t1t edge "127.0.0.1 10.0.0.0/9" "$LISTED, 10.200.0.1" "10.200.0.1") \
    && ok "walk corpus: an entry just past a prefix (10.200.0.1 outside 10.0/9) is not trusted, so it is the one judged" \
    || bad "walk corpus: the prefix's edge: $r"
r=$(t1t duplicate "127.0.0.1 10.0.0.0/8 10.0.0.0/8" "$LISTED, 10.9.9.9" "$LISTED") \
    && ok "walk corpus: a duplicate prefix in the table is accepted and trusts as one" \
    || bad "walk corpus: a duplicate prefix: $r"

echo "$(date -u +%H:%M:%S) == the token's remaining letters: a plane disarmed under the running server, and one the workers cannot read =="
# An armed plane whose mode changes to admit another writer fails the trust re-check and is disarmed at
# once; its token reads -d. A plane present but unreadable by the workers' uid (0400, another owner)
# is reported and inert; its token reads -u. tor is read only by a variable, so each letter carries
# the lazy mark of that read. The loading letter (-l) needs the core's test pause and is not a row.
LT="$W/letters"; rm -rf "$LT"; mkdir -p "$LT"; chmod 0755 "$LT"
cp "$PLANES/reputation.bin" "$LT/reputation.bin"; cp "$PLANES/tor.bin" "$LT/tor.bin"; chmod 0444 "$LT"/*.bin
mkdir -p "$W/html/lt"; echo page > "$W/html/lt/index.html"
lt_line() { code "/lt/index.html?q=$1" >/dev/null; sleep 0.3; grep -m1 -F "/lt/index.html?q=$1 " "$W/logs/lt.log" | cut -d' ' -f2- || true; }
DATA_DIR="$LT" SERVER_EXTRA='access_log '"$W"'/logs/lt.log lt;' mkconf 1s "whisper_edge_summary $LT/counters;" 'log_format lt "$request_uri tor_exit=$whisper_edge_tor_exit generations=\"$whisper_edge_generations\"";'
rm -rf "$LT/counters"; : > "$W/logs/error.log"; : > "$W/logs/lt.log"
if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(cat "$LT"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane tor armed generation 5 ")" = 2 ]' 15 "the letters server"; then
    chmod 0644 "$LT/tor.bin"
    if await '[ "$(cat "$LT"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane tor disarmed ")" = 2 ]' 15 "tor disarmed"; then
        l=$(lt_line disarmed)
        [[ $l =~ ^tor_exit=unknown\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:-d\*\ tenant:-a\"$ ]] \
            && ok "letters: an armed plane chmod'ed to 0644 is disarmed in both workers at once, its token reads tor:-d with the lazy mark and its attribute unknown,disarmed or unknown" \
            || bad "letters: the disarmed plane: \"$l\""
    else
        bad "letters: tor did not disarm after chmod 0644: $(cat "$LT"/counters/[0-9]*.status | grep -o '^plane tor [a-z]*' | sort | uniq -c | tr '\n' ' ')"
    fi
fi
stop; sleep 1; chmod 0444 "$LT/tor.bin"
if sudo -n true 2>/dev/null; then
    sudo -n chown 65534:65534 "$LT/tor.bin"; sudo -n chmod 0400 "$LT/tor.bin"
    rm -rf "$LT/counters"; : > "$W/logs/error.log"; : > "$W/logs/lt.log"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /lt/index.html)" = 200 ]' 15 "the unreadable-plane server"; then
        l=$(lt_line unreadable)
        grep -qE "tor present, unreadable by uid $(id -u) \(Permission denied\): rules on it are inert;" "$W/logs/start.err" \
            && [[ $l =~ ^tor_exit=unknown\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:-u\*\ tenant:-a\"$ ]] \
            && ok "letters: a plane at 0400 owned by another uid is reported unreadable and inert at configuration test, and its token reads tor:-u with the lazy mark" \
            || bad "letters: the unreadable plane: line \"$l\", data line $(grep -m1 -o 'tor present[^;]*' "$W/logs/start.err")"
        await '[ -n "$(ls "$LT"/counters/conf-*.status 2>/dev/null)" ]' 10 "the configuration file" || true
        src=0; out=$("$SUMMARY_BIN" --status "$LT/counters" 2>&1) || src=$?
        [ "$src" = 1 ] && grep -qF "configuration unreadable tor \"$LT/tor.bin\" \"Permission denied\"" <<<"$out" \
            && ok "letters: and --status names it, configuration unreadable tor with its path and errno text, and exits 1" \
            || bad "letters: --status over the unreadable plane: rc $src, $(grep -m1 'unreadable' <<<"$out" | cut -c1-200)"
    fi
    stop; sleep 1
    sudo -n rm -f "$LT/tor.bin"
else
    notproven "letters: the unreadable arm needs root to give the plane another owner, and sudo -n is not available here"
fi

echo "$(date -u +%H:%M:%S) == the loading letter: a plane with no map, admitted for verification and held there =="
# A plane with no map reads loading from the moment a new candidate is admitted for verification until it
# arms or is refused. tor is bound but refused at start (mode 0666, no map); the core's pause hook (a
# control build with WE_MOD_TEST_PAUSE_TICK) holds the candidate at `loading` once chmod 0444 admits it:
# while held, both status files say loading, a variable read renders tor:-l with the lazy mark, and after
# two ticks held --status exits 1; released, the plane arms and the token names its generation.
if build_control -DWE_MOD_TEST_PAUSE_TICK; then
    LD="$W/loading"; PD="$W/pause"; rm -rf "$LD" "$PD"; mkdir -p "$LD" "$PD"; chmod 0755 "$LD" "$PD"
    cp "$PLANES/reputation.bin" "$LD/reputation.bin"; cp "$PLANES/tor.bin" "$LD/tor.bin"; chmod 0444 "$LD/reputation.bin"; chmod 0666 "$LD/tor.bin"
    mkdir -p "$W/html/ld"; echo page > "$W/html/ld/index.html"
    ld_line() { code "/ld/index.html?q=$1" >/dev/null; sleep 0.3; grep -m1 -F "/ld/index.html?q=$1 " "$W/logs/ld.log" | cut -d' ' -f2- || true; }
    ld_word() { cat "$LD"/counters/[0-9]*.status 2>/dev/null | grep -c "^plane tor $1 " || true; }
    DATA_DIR="$LD" MODULE="$CTL_OUT" MAIN_EXTRA='env WE_MOD_PAUSE_DIR;' SERVER_EXTRA='access_log '"$W"'/logs/ld.log ld;' \
        mkconf 1s "whisper_edge_summary $LD/counters;" 'log_format ld "$request_uri tor_exit=$whisper_edge_tor_exit generations=\"$whisper_edge_generations\"";'
    rm -rf "$LD/counters"; : > "$W/logs/error.log"; : > "$W/logs/ld.log"
    export WE_MOD_PAUSE_DIR="$PD"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /ld/index.html)" = 200 ] && [ "$(ld_word refused)" = 2 ]' 15 "the loading server"; then
        : > "$PD/loading"
        chmod 0444 "$LD/tor.bin"
        if await '[ "$(find "$PD" -name "held.loading.*" | wc -l)" = 2 ]' 15 "both workers held at loading"; then
            l=$(ld_line held)
            [[ $l =~ ^tor_exit=unknown\ generations=\"reputation:5\.[0-9a-f]{8}\ tor:-l\*\ tenant:-a\"$ ]] \
                && ok "loading: the candidate admitted by chmod 0444 is held in verification in both workers, and the token renders tor:-l with the lazy mark" \
                || bad "loading: the held plane's line: \"$l\""
            # the thread held at `loading` is the one that writes the status file, so neither the status word
            # nor the tick moves while it is held; the -l word is posted to the loop, which is what renders
        else
            bad "loading: the workers did not hold at loading: $(find "$PD" -name 'held.*' | wc -l) held markers, status $(cat "$LD"/counters/[0-9]*.status | grep -o '^plane tor [a-z]*' | sort | uniq -c | tr '\n' ' ')"
        fi
        rm -f "$PD/loading"
        await '[ "$(ld_word "armed generation 5")" = 2 ]' 15 "tor armed after the release" \
            && [[ $(ld_line released) =~ tor:5\.[0-9a-f]{8}\* ]] \
            && ok "loading: released, the plane arms in both workers and the token names generation 5" \
            || bad "loading: after the release: status $(cat "$LD"/counters/[0-9]*.status | grep -o '^plane tor [a-z]* generation [0-9]*' | tr '\n' ' '), line \"$(ld_line released2)\""
    else
        bad "loading: the pause-hook build did not come up with tor refused: $(tail -2 "$W/logs/start.err" | tr '\n' '|' | cut -c1-200)"
    fi
    rm -f "$PD/loading"; stop; sleep 1; unset WE_MOD_PAUSE_DIR
else
    control_unavailable "loading (the pause hook)"
fi

echo "$(date -u +%H:%M:%S) == the debug build: a separate build that says what it is, and the release build is not it =="
# Rows that read the core's debug counters (M3) run on the debug build (WE_MOD_DEBUG, build.sh --debug),
# never on the release module: the debug build announces itself on every configuration test, and the
# release module carries no such line and no such string.
if build_control -DWE_MOD_DEBUG; then
    DEBUG_MODULE="$CTL_OUT"
    conft debug-on ''
    sed -i "1s#^load_module .*#load_module $DEBUG_MODULE;#" "$TCONF"
    TRC=0; TOUT=$(nginx -t -c "$TCONF" -p "$W/t/debug-on" 2>&1) || TRC=$?
    [ "$TRC" = 0 ] && grep -qF "whisper edge: this module is a debug build (WE_MOD_DEBUG): the core's debug counters and assertions are on; never load it in production" <<<"$TOUT" \
        && ok "debug build: a module built with WE_MOD_DEBUG loads and says on its configuration test that it is a debug build" \
        || bad "debug build: rc $TRC, $(grep -m1 -E 'debug build|emerg' <<<"$TOUT" | cut -c1-200)"
    conft debug-off ''
    ! grep -q 'is a debug build' <<<"$TOUT" && ! grep -q -a 'is a debug build' "$MODULE" \
        && ok "debug build control: the release module says no such thing and carries no such string" \
        || bad "debug build control: the release module is a debug build"
else
    control_unavailable "debug build"
fi

echo "$(date -u +%H:%M:%S) == the exit's bounded stop: a thread held in a plane job is abandoned and its stage named =="
# Each worker's tick is held at `tick`, inside a plane job, with no progress, and the server is stopped. The
# core's bounded stop grants a window again only to progress or to work outside a plane job, so each held thread
# is abandoned within the 6 s cap and its worker's line names the stage at error; the master then leaves. The
# control is the flat 2 s stop nginx had, whose line names no stage.
SA="$W/stopab"; rm -rf "$SA"; mkdir -p "$SA/pause"; chmod 0755 "$SA" "$SA/pause"
sa_run() { # <module>: leaves SA_HELD, SA_STAGE, SA_FLAT, SA_GONE
    local from
    rm -f "$SA"/pause/*; SA_HELD=0; SA_STAGE=0; SA_FLAT=0; SA_GONE=no
    MODULE="$1" MAIN_EXTRA='env WE_MOD_PAUSE_DIR;' mkconf 1s
    : > "$W/logs/error.log"
    if WE_MOD_PAUSE_DIR="$SA/pause" start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code /index.html)" = 200 ]' 15 "the held-tick server"; then
        : > "$SA/pause/tick"
        await '[ "$(find "$SA/pause" -name "held.tick.*" | wc -l)" = 2 ]' 15 "both workers' ticks held" || true
        SA_HELD=$(find "$SA/pause" -name 'held.tick.*' | wc -l)
        from=$(( $(wc -l < "$W/logs/error.log") + 1 ))
        stop
        await '[ ! -f "$W/logs/nginx.pid" ]' 60 "the master gone" && SA_GONE=yes
        rm -f "$SA/pause/tick"
        SA_STAGE=$(tail -n +"$from" "$W/logs/error.log" | grep -c "did not stop and is abandoned (the thread was in: a plane job)" || true)
        SA_FLAT=$(tail -n +"$from" "$W/logs/error.log" | grep -c "did not stop within 2 s and is abandoned" || true)
    else
        stop
    fi
    sleep 1
}
if build_control -DWE_MOD_TEST_PAUSE_TICK; then
    sa_run "$CTL_OUT"
    [ "$SA_HELD" = 2 ] && [ "$SA_STAGE" = 2 ] && [ "$SA_FLAT" = 0 ] && [ "$SA_GONE" = yes ] \
        && ok "bounded stop: with both workers' ticks held in a plane job, each exit abandons its thread, the line naming the stage (the thread was in: a plane job), and the master leaves" \
        || bad "bounded stop: held $SA_HELD, stage-named lines $SA_STAGE, flat lines $SA_FLAT, master gone $SA_GONE"
else
    control_unavailable "bounded stop (the pause hook)"
fi
if build_control -DWE_MOD_TEST_PAUSE_TICK -DWE_MOD_TEST_NGX_FLAT_STOP; then
    sa_run "$CTL_OUT"
    [ "$SA_STAGE" = 0 ] && [ "$SA_FLAT" -ge 1 ] \
        && ok "bounded stop control (the flat 2 s stop): fails the row, $SA_FLAT exit line(s) name no stage" \
        || bad "bounded stop control (the flat 2 s stop): stage-named $SA_STAGE, flat $SA_FLAT; the row passed without the code it proves"
else
    control_unavailable "bounded stop control (the flat 2 s stop)"
fi
rm -rf "$SA"

echo "$(date -u +%H:%M:%S) == a plane truncated in place before a worker starts: noticed and disarmed before the first accept =="
# A plane rewritten in place under a live mapping (here truncated to one page) faults any read past the new
# end with SIGBUS. A worker that starts after the rewrite inherits the master's mapping, so the worker-start
# check must notice the change and disarm the plane before the worker accepts a connection. The tick is
# held through the core's pause hook, so the replacement worker's thread cannot be the one that notices;
# the debug build counts the lookups that land in the truncated tail. Three checks, each named: the
# rewrite is noticed, the plane is disarmed, and every request is served with no worker lost to a signal.
# Two controls, each failing its own check: one skips the worker-start check (nothing noticed), and one
# notices but keeps serving the inherited mapping (not disarmed).
m3_run() { # <module> <tag>: leaves M3_SERVED M3_DEATHS M3_NOTICED M3_DISARMED M3_HELD M3_TAIL
    local m3="$W/m3-$2" pd="$W/m3-$2.pause" old new i
    rm -rf "$m3" "$pd"; mkdir -p "$m3/d" "$pd"; chmod 0755 "$m3" "$m3/d" "$pd"
    cp "$PLANES/reputation.bin" "$m3/d/reputation.bin"; chmod 0444 "$m3/d/reputation.bin"
    DATA_DIR="$m3/d" MODULE="$1" MAIN_EXTRA='env WE_MOD_PAUSE_DIR; env WE_MOD_DEBUG_TAIL;' mkconf 1s "whisper_edge_summary $m3/counters;"
    sed -i 's/^worker_processes 2;/worker_processes 1;/' "$W/nginx.conf"
    : > "$W/logs/error.log"
    M3_SERVED=0; M3_DEATHS=""; M3_NOTICED=0; M3_DISARMED=0; M3_HELD=0; M3_TAIL=""
    if ! WE_MOD_PAUSE_DIR="$pd" WE_MOD_DEBUG_TAIL="$M3_TAIL_RANGE" start \
        || ! await '[ -f "$W/logs/nginx.pid" ] && grep -q "plane reputation.bin: generation 5 verified, arming" "$W/logs/error.log"' 15 "armed"; then
        M3_DEATHS="no start: $(tail -2 "$W/logs/start.err" "$W/logs/error.log" | tr '\n' '|' | cut -c1-200)"; stop; sleep 1; rm -rf "$m3" "$pd"; return
    fi
    : > "$pd/tick"
    # the worker by its title: the cache path in the configuration also starts a cache manager and loader
    m3_worker() { pgrep -P "$(cat "$W/logs/nginx.pid")" -f '^nginx: worker process' 2>/dev/null | sed -n 1p; }
    old=$(m3_worker)
    await '[ -n "$(find "$pd" -name "held.tick.$old")" ]' 10 "the first worker's tick held" || true
    chmod u+w "$m3/d/reputation.bin"; truncate -s 4096 "$m3/d/reputation.bin"
    [ -n "$old" ] && { GATE_KILLED="$GATE_KILLED $old"; kill -9 "$old"; }
    await 'new=$(m3_worker); [ -n "$new" ] && [ "$new" != "$old" ]' 10 "the replacement worker" || true
    new=$(m3_worker)
    # before the first request: whatever is in the log now was written at worker start
    await '[ -n "$(find "$pd" -name "held.tick.$new")" ]' 5 "the replacement worker's tick held" && M3_HELD=1
    M3_NOTICED=$(grep -c 'reputation.bin.*rewritten in place' "$W/logs/error.log" || true)
    M3_DISARMED=$(grep -c 'plane reputation.bin disarmed: the armed file was rewritten in place' "$W/logs/error.log" || true)
    for i in $(seq 1 50); do
        [ "$(code_as /index.html "198.18.$((i % 200)).5")" = 200 ] && M3_SERVED=$((M3_SERVED+1))
    done
    M3_DEATHS=$(grep -c 'exited on signal 7' "$W/logs/error.log" || true)
    rm -f "$pd/tick"
    await '[ -n "$(cat "$m3"/counters/[0-9]*.status 2>/dev/null | grep "^debug tail-requests [1-9]")" ]' 10 "the tail count written" || true
    M3_TAIL=$(cat "$m3"/counters/[0-9]*.status 2>/dev/null | sed -n 's/^debug tail-requests //p' | sort -n | tail -1)
    stop; sleep 1; rm -rf "$m3" "$pd"
}
M3_TAIL_RANGE=198.18.0.0-198.18.255.255
if build_control -DWE_MOD_DEBUG -DWE_MOD_TEST_PAUSE_TICK; then
    m3_run "$CTL_OUT" real
    [ "$M3_HELD" = 1 ] && [ "${M3_TAIL:-0}" -ge 50 ] \
        && ok "truncated plane: the replacement worker's tick is held, and the debug count shows the 50 lookups landed in the truncated tail" \
        || bad "truncated plane: the arm did not set up: tick held $M3_HELD, tail count \"$M3_TAIL\", ${M3_DEATHS}"
    [ "$M3_NOTICED" -ge 1 ] && ok "truncated plane: noticed by the worker-start check before the first request" \
        || bad "truncated plane: noticed: no rewritten-in-place line before the first request"
    [ "$M3_DISARMED" -ge 1 ] && ok "truncated plane: disarmed before the first accept" \
        || bad "truncated plane: disarmed: the plane was not disarmed before the first request"
    [ "$M3_SERVED" = 50 ] && [ "$M3_DEATHS" = 0 ] && ok "truncated plane: served, 50 of 50 answered and no worker lost to SIGBUS" \
        || bad "truncated plane: served: $M3_SERVED of 50 answered, $M3_DEATHS worker(s) lost to signal 7"
else
    control_unavailable "truncated plane (the debug build with the pause hook)"
fi
# the release build under the same truncation: whatever its own tick does (no pause hook here), no worker
# dies of a signal, so a SIGBUS in the exempt controls can only come from the control
m3_run "$MODULE" release
[ "$M3_DEATHS" = 0 ] && [ "$M3_SERVED" = 50 ] \
    && ok "truncated plane, release build: 50 of 50 answered after the truncation, no worker lost to a signal" \
    || bad "truncated plane, release build: $M3_SERVED of 50 answered, $M3_DEATHS worker(s) lost to a signal"
if build_control -DWE_MOD_DEBUG -DWE_MOD_TEST_PAUSE_TICK -DWE_MOD_TEST_NO_START_STAT; then
    m3_run "$CTL_OUT" nostat
    [ "$M3_NOTICED" = 0 ] && [ "$M3_DEATHS" -ge 1 ] \
        && ok "truncated plane control (no worker-start check): fails noticed, and $M3_DEATHS worker(s) die of SIGBUS serving $M3_SERVED of 50" \
        || bad "truncated plane control (no worker-start check): noticed $M3_NOTICED, deaths $M3_DEATHS; the check passed without the code it proves"
else
    control_unavailable "truncated plane control (no worker-start check)"
fi
if build_control -DWE_MOD_DEBUG -DWE_MOD_TEST_PAUSE_TICK -DWE_MOD_TEST_SERVE_INHERITED; then
    m3_run "$CTL_OUT" inherited
    [ "$M3_NOTICED" -ge 1 ] && [ "$M3_DISARMED" = 0 ] && [ "$M3_DEATHS" -ge 1 ] \
        && ok "truncated plane control (serve the inherited mapping): passes noticed, fails disarmed, and $M3_DEATHS worker(s) die of SIGBUS" \
        || bad "truncated plane control (serve the inherited mapping): noticed $M3_NOTICED, disarmed $M3_DISARMED, deaths $M3_DEATHS"
else
    control_unavailable "truncated plane control (serve the inherited mapping)"
fi

echo "$(date -u +%H:%M:%S) == the workers' user set after the http block: the planes are trusted for the final uid =="
# The binding runs at postconfiguration, before nginx applies a `user` line written after the http block,
# when the uid it can see is nginx's default (nobody, under root). A directory only that default uid could
# trust must not admit a plane for workers that run as another user: at init_module the planes are bound
# again for the final uid, and such a plane is refused alone, reads unknown and is named in the core's
# sentence while the rest serve. Run as root (the user line means nothing otherwise), the fixtures in a
# root-owned directory: reputation in a root-owned data directory, tor in a directory owned by nobody. The
# control keeps the first binding's uid and arms tor.
if sudo -n true 2>/dev/null; then
    UR="/run/whisper-edge-nginx-gate-uid.$$"; GATE_ROOT_DIR=$UR
    sudo -n rm -rf "$UR"; sudo -n mkdir -p "$UR/d" "$UR/nb" "$UR/html" "$UR/logs"; sudo -n chmod 0755 "$UR" "$UR/d" "$UR/nb" "$UR/html"
    python3 ../core/make-test-snapshot.py --plane reputation --out "$W/uid-rep.bin" --format 1 --schema --v6-index none --generation 100 >/dev/null
    python3 ../core/make-test-snapshot.py --plane tor --out "$W/uid-tor.bin" --format 2 --schema --generation 7 >/dev/null
    sudo -n install -m 0444 -o root -g root "$W/uid-rep.bin" "$UR/d/reputation.bin"
    sudo -n install -m 0444 -o root -g root "$W/uid-tor.bin" "$UR/nb/tor.bin"
    sudo -n chown 65534:65534 "$UR/nb"; echo page | sudo -n tee "$UR/html/index.html" >/dev/null
    ur_run() { # <module>: leaves UR_TOK (a request's token), UR_USER (the worker's user), UR_SENT (the sentence)
        sudo -n tee "$UR/nginx.conf" >/dev/null <<UEOF
load_module $1;
worker_processes 1;
error_log $UR/logs/e.log info;
pid $UR/logs/pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $UR/logs/b; proxy_temp_path $UR/logs/p; fastcgi_temp_path $UR/logs/f; uwsgi_temp_path $UR/logs/u; scgi_temp_path $UR/logs/s;
    whisper_edge_data $UR/d;
    whisper_edge_data tor $UR/nb/tor.bin;
    whisper_edge_export tor_exit;
    whisper_edge_summary off;
    log_format ur "\$request_uri \$whisper_edge_generations";
    server { listen 127.0.0.1:$PORT; root $UR/html; access_log $UR/logs/a.log ur; }
}
user $(id -un);
UEOF
        sudo -n rm -rf "$UR/logs"; sudo -n mkdir -p "$UR/logs"
        UR_TOK=""; UR_USER=""; UR_SENT=""
        if sudo -n nginx -c "$UR/nginx.conf" -p "$UR" 2>/dev/null \
                && await '[ "$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$PORT/index.html?q=uid")" = 200 ]' 10 "the root-run server"; then
            sleep 0.3
            UR_TOK=$(sudo -n cat "$UR/logs/a.log" | grep -m1 -F '/index.html?q=uid ' | cut -d' ' -f2- || true)
            UR_USER=$(ps -o user= --ppid "$(sudo -n cat "$UR/logs/pid")" | sort -u | tr '\n' ' ')
            UR_SENT=$(sudo -n grep -m1 -F 'whisper edge: plane tor is refused at configuration' "$UR/logs/e.log" || true)
        else
            UR_TOK="no start: $(sudo -n tail -2 "$UR/logs/e.log" | tr '\n' '|' | cut -c1-200)"
        fi
        sudo -n nginx -s quit -c "$UR/nginx.conf" -p "$UR" 2>/dev/null || true
        await '! sudo -n test -f "$UR/logs/pid"' 10 "the root-run server gone" || true
    }
    ur_run "$MODULE"
    [[ $UR_TOK =~ ^reputation:100\.[0-9a-f]{8}\*?\ tor:-r ]] && [ "$UR_USER" = "$(id -un) " ] \
        && [[ $UR_SENT == *"whisper_edge_data $UR/nb/tor.bin: directory \"nb\" is owned by uid 65534"* ]] \
        && ok "final user: with user after the http block the workers run as $(id -un), tor in a directory trusted only for nobody is refused at start with the core's sentence naming the owner, and reputation serves" \
        || bad "final user: token \"$UR_TOK\", worker user \"$UR_USER\", sentence \"$(cut -c1-200 <<<"$UR_SENT")\""
    if build_control -DWE_MOD_TEST_NO_FINAL_UID; then
        ur_run "$CTL_OUT"
        [[ $UR_TOK =~ \ tor:7\. ]] \
            && ok "final user control (the binding keeps the default uid): fails the row, tor armed at 7 for workers its directory does not trust" \
            || bad "final user control (the binding keeps the default uid): token \"$UR_TOK\"; the row passed without the code it proves"
    else
        control_unavailable "final user control (the binding keeps the default uid)"
    fi
    sudo -n rm -rf "$UR"; GATE_ROOT_DIR=""
else
    notproven "final user: the user directive only takes effect under root, and sudo -n is not available here"
fi

echo "$(date -u +%H:%M:%S) == the per-range count in log mode: a would-deny is counted, as on Apache and OpenLiteSpeed =="
# The legacy snapshot's per-range counters count every deny verdict on a fresh listed range, enforced or a
# would-deny under mode log: the core's contract counts after the verdict, on the path that writes the log
# line (in log mode the WOULD DENY line), and every released module counted before the mode test. The same
# traffic is held to the same number on every server: five requests from the listed client under the default
# mode (log), and the summary's headline total five. The control counts an enforced deny alone.
LC_N=5
lc_run() { # <module> <tag>: leaves LC_TOTAL, the summary's headline total, and LC_CODES
    local cd="$W/lc-$2" i
    rm -rf "$cd"; LC_TOTAL=""; LC_CODES=""
    MODULE="$1" mkconf 1s "whisper_edge_summary $cd;"
    if start && await '[ -f "$W/logs/nginx.pid" ] && [ "$(code_as /index.html "$UNLISTED")" = 200 ]' 15 "the log-mode server"; then
        for i in $(seq 1 "$LC_N"); do LC_CODES="$LC_CODES$(code "/index.html?lc=$i")"; done
        # each worker writes its own counts on its own tick, so the total is awaited AT the number expected,
        # never at the first non-zero read (one worker's file alone read 1 of 5 on a test host)
        LC_EXPIRED=no
        await '[ "$(summary_total "$cd")" = "$LC_N" ]' 60 "the counts written" || LC_EXPIRED=yes   # a ceiling for a hang, not a timing
        LC_TOTAL=$(summary_total "$cd")
    fi
    stop; sleep 1
}
lc_run "$MODULE" real
[ "$LC_CODES" = "200200200200200" ] && [ "$LC_TOTAL" = "$LC_N" ] \
    && ok "log-mode count: $LC_N would-denies from the listed client (each answered 200) are $LC_N in the summary's total, the same traffic and the same number as on Apache and OpenLiteSpeed" \
    || bad "log-mode count: $LC_N requests from the listed client answered $LC_CODES, and the summary's total is \"${LC_TOTAL:-none}\", not $LC_N$([ "$LC_EXPIRED" = yes ] && echo " (the wait reached its 60 s ceiling)")"
if build_control -DWE_MOD_TEST_COUNT_ENFORCED_ONLY; then
    lc_run "$CTL_OUT" ctl
    [ "${LC_TOTAL:-0}" != "$LC_N" ] \
        && ok "log-mode count control (an enforced deny counted alone): fails the row, the summary's total \"${LC_TOTAL:-none}\" for $LC_N would-denies" \
        || bad "log-mode count control (an enforced deny counted alone): the total is $LC_TOTAL; the row passed without the code it proves"
else
    control_unavailable "log-mode count control (an enforced deny counted alone)"
fi

echo "$(date -u +%H:%M:%S) == an nginx before 1.23 (RHEL 9 ships 1.20.1): the module builds and denies with no-store =="
# nginx 1.23 made the response's Cache-Control lines a list chained through ngx_table_elt_t.next; before it they
# are an array of pointers. The module takes the array path behind nginx_version, so it builds against the
# nginx a mainstream enterprise distribution ships. Given NGX_OLD_SRC, a VERIFIED source tree older than 1.23
# (nginx/old-nginx-src.sh fetches RHEL 9's 1.20.1 from Rocky's source RPM, checked with rpmkeys -K against
# Rocky's pinned key), nginx and the module are built from it and run: a listed client is denied with exactly
# one Cache-Control: no-store, an unlisted one served. The control takes the 1.23 path only and cannot build.
OLDV=""
[ -n "${NGX_OLD_SRC:-}" ] && [ -f "$NGX_OLD_SRC/src/core/nginx.h" ] \
    && OLDV=$(sed -n 's/^#define NGINX_VERSION *"\([0-9.]*\)".*/\1/p' "$NGX_OLD_SRC/src/core/nginx.h")
old_build() { # <dir> <extra CFLAGS>: configure and build nginx and the module from NGX_OLD_SRC into <dir>
    rm -rf "$1"; cp -r "$NGX_OLD_SRC" "$1"
    ( cd "$1" && ./configure --with-compat --with-http_realip_module --without-http_rewrite_module \
          --without-http_gzip_module --prefix="$1/prefix" --add-dynamic-module="$ROOT/nginx" \
          ${2:+--with-cc-opt="$2"} ) > "$1.configure.log" 2>&1 \
        && ( cd "$1" && make -f objs/Makefile ) > "$1.make.log" 2>&1
}
if [ -n "$OLDV" ] && [ "$(printf '%s\n' "$OLDV" 1.23.0 | sort -V | sed -n 1p)" = "$OLDV" ] && [ "$OLDV" != 1.23.0 ]; then
    OB="$W/old-nginx"
    if old_build "$OB" ""; then
        ok "pre-1.23: nginx $OLDV and the module build from the verified tree ($("$OB/objs/nginx" -v 2>&1 | sed 's/.*version: //'))"
        OR="$W/old-run"; rm -rf "$OR"; mkdir -p "$OR/logs" "$OR/html/enforced"; echo page > "$OR/html/index.html"; echo page > "$OR/html/enforced/index.html"
        cat > "$OR/nginx.conf" <<OCONF
load_module $OB/objs/ngx_http_whisper_edge_module.so;
worker_processes 2;
error_log $OR/logs/error.log info;
pid $OR/logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $OR/logs/body; proxy_temp_path $OR/logs/proxy; fastcgi_temp_path $OR/logs/fastcgi;
    uwsgi_temp_path $OR/logs/uwsgi; scgi_temp_path $OR/logs/scgi;
    whisper_edge_snapshot $W/snapshot.good;
    whisper_edge_refresh 1s;
    whisper_edge_summary off;
    whisper_edge_trusted_proxy 127.0.0.1;
    whisper_edge_trusted_header X-Forwarded-For;
    whisper_edge_trusted_hops 2;
    set_real_ip_from 127.0.0.1; set_real_ip_from $HOP; real_ip_header X-Forwarded-For; real_ip_recursive on;
    server { listen 127.0.0.1:$PORT; root $OR/html; location /enforced/ { whisper_edge_mode deny; } }
}
OCONF
        if "$OB/objs/nginx" -c "$OR/nginx.conf" -p "$OR" 2>"$OR/logs/start.err" \
                && await '[ -f "$OR/logs/nginx.pid" ] && [ "$(code_as /index.html "$UNLISTED")" = 200 ]' 15 "the pre-1.23 server"; then
            hl=$(curl -s -o /dev/null -D - --max-time 5 -H "$(xff)" "http://127.0.0.1:$PORT/enforced/index.html")
            hu=$(curl -s -o /dev/null -D - --max-time 5 -H "$(xff "$UNLISTED")" "http://127.0.0.1:$PORT/enforced/index.html")
            [[ $hl == "HTTP/1.1 403"* ]] && [ "$(grep -ci '^cache-control: no-store' <<<"$hl")" = 1 ] \
                && ok "pre-1.23: under nginx $OLDV a listed client is denied (403) with exactly one Cache-Control: no-store, through the array path" \
                || bad "pre-1.23: the listed client's response under nginx $OLDV: $(printf '%s' "$hl" | tr -d '\r' | tr '\n' '|' | cut -c1-200)"
            [[ $hu == "HTTP/1.1 200"* ]] && ! grep -qi '^cache-control: no-store' <<<"$hu" \
                && ok "pre-1.23: and an unlisted client is served (200) with no no-store" \
                || bad "pre-1.23: the unlisted client's response: $(printf '%s' "$hu" | tr -d '\r' | tr '\n' '|' | cut -c1-200)"
            "$OB/objs/nginx" -s quit -c "$OR/nginx.conf" -p "$OR" 2>/dev/null || true
            await '[ ! -f "$OR/logs/nginx.pid" ]' 60 "the pre-1.23 server gone" || bad "pre-1.23: the server did not leave"
        else
            bad "pre-1.23: nginx $OLDV with the module did not come up: $(tail -2 "$OR/logs/start.err" | tr '\n' '|' | cut -c1-200)"
            [ -f "$OR/logs/nginx.pid" ] && kill "$(cat "$OR/logs/nginx.pid")" 2>/dev/null || true
        fi
    else
        bad "pre-1.23: nginx $OLDV with the module did not build: $(grep -h -m1 -E 'error:' "$OB.make.log" "$OB.configure.log" 2>/dev/null | cut -c1-200)"
    fi
    if old_build "$W/old-nginx-ctl" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_NGX_LIST_ONLY"; then
        bad "pre-1.23 control (the 1.23 list path only): it built against nginx $OLDV; the row passed without the code it proves"
    else
        # gcc quotes the member with its locale's quote marks (straight in C, curly in UTF-8): any one character
        grep -qE "has no member named .next." "$W/old-nginx-ctl.make.log" \
            && ok "pre-1.23 control (the 1.23 list path only): fails the build row, ngx_table_elt_t has no member named next before 1.23" \
            || bad "pre-1.23 control: the build failed for another reason: $(grep -m1 'error:' "$W/old-nginx-ctl.make.log" | cut -c1-200)"
    fi
    rm -rf "$W/old-nginx" "$W/old-nginx-ctl" "$W/old-run"
else
    notproven "pre-1.23: no verified nginx source tree older than 1.23 given (NGX_OLD_SRC=$(printf '%s' "${NGX_OLD_SRC:-unset}")); nginx/old-nginx-src.sh fetches RHEL 9's 1.20.1, verified against Rocky's pinned key"
fi

echo "$(date -u +%H:%M:%S) == the module under test is this tree's current build =="
why=$(module_is_this_trees "$MODULE")
[ -z "$why" ] && ok "module: the object under test names this tree's source ($MODSRC) and is newer than every source it compiles" \
    || bad "module: the object under test is not this tree's current build: $why"
MC="$W/modcheck"; mkdir -p "$MC"
cp "$MODULE" "$MC/old.so"; touch -d @1000000000 "$MC/old.so"
why=$(module_is_this_trees "$MC/old.so")
[[ $why == "it is older than its source ("* ]] && ok "module control: a copy dated before the source is refused by cause ($why)" \
    || bad "module control: a copy older than its source was not refused: \"$why\""
# the same object as another tree's build: its source path rewritten to another one of the same length
other=$(printf '%s' "$MODSRC" | sed 's#/nginx/ngx_http_whisper_edge_module.c$#/nginy/ngx_http_whisper_edge_module.c#')
LC_ALL=C sed "s#$MODSRC#$other#g" "$MODULE" > "$MC/foreign.so"
why=$(module_is_this_trees "$MC/foreign.so")
[[ $why == "it was not built from this tree"* ]] && ok "module control: an object built from another tree's source is refused by cause" \
    || bad "module control: a foreign object was not refused: \"$why\""
rm -rf "$MC"

echo "$(date -u +%H:%M:%S) == every control failed by value: no control's worker died of a signal =="
[ "$CTL_CHECKED" -gt 0 ] && [ -z "$CTL_CRASHED" ] \
    && ok "controls: the $CTL_CHECKED servers started on a control module saw no worker exit on a signal, but for the exempt list (${CTL_SIGNAL_EXEMPT[*]%%:*}: their SIGBUS is their row's measurement; seen:${CTL_EXEMPTED:- none})" \
    || bad "controls: a control failed by a crash, not by value:${CTL_CRASHED:- none checked}"

echo
# README.md prints the proof transcript with this exact count line, so a change to the rows that is not
# carried into the README fails here by name (row Z1) rather than drifting unnoticed.
README="$ROOT/README.md"
if [ "$FAILED" = 0 ] && [ -f "$README" ] && grep -q '=== nginx gate: ' "$README"; then
    want="=== nginx gate: $PASS ok, 0 failed ==="
    if ! grep -qF "$want" "$README"; then
        printf '  FAIL  README.md says "%s" and this run is "%s"\n' \
            "$(grep -o '=== nginx gate: [0-9]* ok, [0-9]* failed ===' "$README" | sed -n 1p)" "$want"
        FAILED=$((FAILED+1))
    else
        # printed, not counted: the count this row compares is the count the README carries
        printf '  ok    README.md prints this run'"'"'s own count, so the page cannot go stale unnoticed\n'
    fi
fi
echo "=== nginx gate: $PASS ok, $FAILED failed ==="
[ "$NOT_PROVEN" -eq 0 ] || echo "    $NOT_PROVEN arm(s) NOT PROVEN on this host (the reasons are above); the verdict below does not cover them"
if [ "$FAILED" -eq 0 ]; then
    echo "NGINX GATE: CLEAR - nginx $(nginx -v 2>&1 | sed 's/.*nginx\///') loaded the module and held every property"
else
    echo "NGINX GATE: FAILED"
    echo "--- error log tail ---"; tail -30 "$W/logs/error.log" 2>/dev/null | sed 's/^/        /'
fi
exit "$([ "$FAILED" -eq 0 ] && echo 0 || echo 1)"
