#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# litespeed-gate.sh - run the module inside a real OpenLiteSpeed and assert the properties that matter.
#
# Same brief as the nginx and Apache gates, and the same most-important assertion: DRY RUN IS THE
# DEFAULT. With no mode directive at all, a request from a listed address must get a 200.
#
# WHAT IS DIFFERENT HERE, and why this gate is not optional:
#
#   - LiteSpeed is NOT Apache-module-compatible. It reads Apache DIRECTIVES, which makes it very easy
#     to assume it loads Apache .so modules too, and it does not. This gate is the thing that proves
#     we shipped a real LSIAPI module rather than a confident README.
#   - THE GRANULARITY IS SERVER AND VIRTUAL HOST, not location. That is a platform limit, traced to
#     the server's own source and documented in mod_whisper_edge.c, so the cases here are virtual
#     hosts rather than locations, one listener each.
#   - THE LISTED CLIENT ARRIVES THROUGH THE TRUSTED PROXY. The gate's own requests come from
#     127.0.0.1, and loopback, every private range and every documentation range are in the module's
#     hold-harmless table: the pre-stage exempts them before any rule runs, by design. So the server
#     level trusts 127.0.0.1 and names X-Forwarded-For, and a case's client is the header's last entry:
#     an address from the shared generator's synthetic planes (never a hand-picked public address),
#     chosen from the generator's own expectation files so that a reputation client is in no Tor range
#     and the Tor client in no reputation range. That is also what a CDN-fronted deployment looks like,
#     so the walk is exercised on every row rather than on a few.
#   - THE PLANES LIVE UNDER A ROOT-OWNED CHAIN. The module maps only a 0444 root-owned plane reached
#     through directories nobody but root may write, and /tmp is sticky and world-writable, so the
#     fixture directory is made under /var/lib (and removed on exit). The server's own work files stay
#     under /tmp, where its user can read them: a work directory under a 0700 path reads as 403 on
#     every file and as an unwritable counters directory, which this gate once mistook for a module
#     fault.
#   - OpenLiteSpeed runs as nobody, so the doc root has to be readable by it, directories 0755 and
#     FILES 0644. A blanket chmod -R 0755 leaves index.html world-executable, which the server
#     refuses to serve, and the resulting 403 is indistinguishable from the module blocking.
#
# IT MODIFIES THE INSTALLED CONFIG AND PUTS IT BACK. OpenLiteSpeed resolves everything against its
# own home, so there is no "run a second instance from a scratch directory" option the way there is
# with nginx and httpd. The installed conf/ and modules/ are archived first and restored byte for
# byte from a trap, including on failure, and a server systemd was running is stopped through
# systemd and started again on the way out.
#
# Rows marked DARK run, with no edit here, once what they wait for is in the tree; they are printed
# and never counted. A control row builds the module with one planted defect and must see the named
# assertion fail: a control that passes is a gate that has stopped seeing what it claims to see.
set -uo pipefail

cd "$(dirname "$0")" || exit 1
# ROOT is the EDGE TREE's own root, one level up from this script, NOT two: two levels up is the monorepo
# root in our tree and the PARENT OF THE CLONE in the published repository.
ROOT=$(cd .. && pwd)
LSWS=${LSWS:-/usr/local/lsws}
# the first of thirteen consecutive ports this gate binds (one listener per host); the default range is clear of the
# nginx gate (8098) and the Apache gate (8099 to 8101), which bind theirs on the same box
PORT=${PORT:-8120}
WORKERS=${WORKERS:-2}                 # httpdWorkers; the syscall-count row runs one
# the refusals that need nothing of this run come first, so they leave nothing behind: no work directory, no
# fixture directory
[ -x "$LSWS/bin/lswsctrl" ] || {
    echo "LITESPEED GATE: FAILED - no OpenLiteSpeed at $LSWS. Install it with:"
    echo "    see https://docs.openlitespeed.org/installation/repo/ for your distribution"
    exit 1
}
SDK=${LS_SDK:-}
if [ -z "$SDK" ]; then
    for c in "$ROOT/litespeed/sdk/include" "$LSWS/include"; do
        [ -f "$c/ls.h" ] && SDK="$c" && break
    done
fi
[ -n "$SDK" ] && [ -f "$SDK/ls.h" ] || {
    echo "LITESPEED GATE: FAILED - no LSIAPI header (ls.h). Fetch the PINNED SDK with:"
    echo "    make -C .. litespeed-sdk"
    echo "  or pass LS_SDK=<dir>/include."
    exit 1
}
W_MINE=0
[ -z "${W:-}" ] && W_MINE=1            # a work directory this run made is removed on every exit but a named FAILED
W=${W:-$(mktemp -d /tmp/whisper-edge-ols-gate.XXXXXX)}
# until the full exit handler below is armed, an exit removes the (still empty of anything root-owned) work directory
trap '[ "$W_MINE" = 1 ] && rm -rf -- "$W"' EXIT
chmod 0755 "$W"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"
# the fixture directory: root-owned, 0755, under a root-owned chain, the planes 0444 inside it
D=$($SUDO mktemp -d /var/lib/whisper-edge-ols-gate.XXXXXX) || { echo "LITESPEED GATE: FAILED - cannot make the fixture directory under /var/lib"; exit 1; }
$SUDO chmod 0755 "$D"

PASS=0; FAILED=0; DARK=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
bad()  { FAILED=$((FAILED+1)); echo "  FAIL  $1"; }
dark() { DARK=$((DARK+1)); echo "  DARK  $1"; }
# a control row: the planted defect must make the named assertion fail
ctl()  { # ctl <0 when the control was caught> <text>
    if [ "$1" = 0 ]; then ok "control: $2"; else bad "control NOT caught: $2"; fi
}
is()   { # is <got> <want> <ok text> <bad text>
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$4 (got \"$1\", wanted \"$2\")"; fi
}

code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@" 2>/dev/null; }
# `grep -q` at the end of a pipeline under pipefail reads a match as a failure when the producer is still
# writing (it gets SIGPIPE on grep's early exit); hit() counts instead, consumes everything, exits 0 on a match
hit()   { grep -c "$@" >/dev/null; }
wire()  { curl -s -i --max-time 8 "$@" 2>/dev/null | sed 's/\r//'; }
await() { local i=0; while [ $i -lt $((${2} * 4)) ]; do eval "$1" && return 0; sleep 0.25; i=$((i+1)); done; return 1; }
now_ms() { date +%s%3N; }
u()     { echo "http://127.0.0.1:$1$2"; }

CONF="$LSWS/conf/httpd_config.conf"
ELOG="$LSWS/logs/error.log"
BACKUP="$W/restore"
PIDFILE=/tmp/lshttpd/lshttpd.pid
MODULE_SRC="${LS_GATE_MODULE_SRC:-mod_whisper_edge.c}"
UNIT=""

server_procs() {
    local p t
    for p in $(pgrep -x 'litespeed|lshttpd|openlitespeed' 2>/dev/null || true); do
        t=$({ tr '\0' ' ' < "/proc/$p/cmdline"; } 2>/dev/null) || continue
        case "$t" in *"(lshttpd - "*|*"(lscgid)"*) echo "$p $t" ;; esac
    done
}
server_alive() { [ -n "$(server_procs)" ]; }
elog_lines() { $SUDO wc -l "$ELOG" 2>/dev/null | awk '{print $1}'; }
# the module's lines since line FROM of the error log, the server's own prefix removed
mod_log_since() { $SUDO tail -n +"$1" "$ELOG" 2>/dev/null | grep -F '[whisper_edge]' | sed 's/^.*\[whisper_edge\] //'; }
elog_has()   { $SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | hit -F -- "$1"; }
await_elog() { local i=0; while [ $i -lt 16 ]; do elog_has "$1" && return 0; sleep 0.25; i=$((i+1)); done; return 1; }

restore() {
    if [ -f "$BACKUP/lsws.tar" ]; then
        $SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1
        await '! server_alive' 20 || true
        $SUDO tar -C "$LSWS" -xpf "$BACKUP/lsws.tar"
        $SUDO find "$LSWS/conf" "$LSWS/modules" -print | LC_ALL=C sort > "$BACKUP/after.list"
        LC_ALL=C comm -13 "$BACKUP/before.list" "$BACKUP/after.list" | while IFS= read -r p; do
            $SUDO rm -rf -- "$p"
        done
        $SUDO sh -c 'rm -f -- "$1"/whisper-gate.*.log' sh "$LSWS/logs"
        $SUDO rm -f "$BACKUP/lsws.tar"
        echo "  (installed OpenLiteSpeed config and modules restored)"
    fi
    if [ -n "$UNIT" ]; then
        $SUDO systemctl start "$UNIT" >/dev/null 2>&1 \
            && echo "  (the $UNIT unit this run stopped is started again)" \
            || echo "  (could not start the $UNIT unit again: systemctl start $UNIT)"
        UNIT=""
    fi
    [ -d "$D" ] && $SUDO rm -rf -- "$D"
    # the root-snapshot row's file at /, and /counters only when this run made it
    [ -n "${ROOTSNAP:-}" ] && $SUDO rm -f -- "$ROOTSNAP"
    [ "${ROOT_COUNTERS_MADE:-0}" = 1 ] && $SUDO rmdir -- /counters 2>/dev/null
    true
}
W_KEEP=0
on_exit() {
    restore
    # the work directory holds the restore's own backup, so it goes only now, and only when this run made it
    # (the server wrote root-owned files under it, so its removal needs the same privilege). It is kept only when
    # finish() says so by name on a FAILED run; every other exit (CLEAR, an early refusal, a signal) removes it
    if [ "$W_KEEP" = 0 ] && [ "$W_MINE" = 1 ]; then
        $SUDO rm -rf -- "$W"
    fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

finish() {
    # THE PAGE MUST AGREE WITH THIS RUN: REFERENCE.md prints the count line as a transcript, and a number
    # typed into prose goes stale on the edit that changes it; the comparison is what makes a missed
    # update fail rather than go stale.
    if [ "$FAILED" = 0 ] && [ -f "$ROOT/REFERENCE.md" ] && grep -q '=== litespeed gate: ' "$ROOT/REFERENCE.md"; then
        want="=== litespeed gate: $PASS ok, 0 failed ==="
        if ! grep -qF "$want" "$ROOT/REFERENCE.md"; then
            printf '  FAIL  REFERENCE.md says "%s" and this run is "%s"\n' \
                "$(grep -o '=== litespeed gate: [0-9]* ok, [0-9]* failed ===' "$ROOT/REFERENCE.md" | head -1)" "$want"
            FAILED=$((FAILED+1))
        else
            printf '  ok    REFERENCE.md prints this run'"'"'s own count, so the page cannot go stale unnoticed\n'
        fi
    fi
    echo "=== litespeed gate: $PASS ok, $FAILED failed ==="
    [ "$DARK" -gt 0 ] && echo "    ($DARK rows dark, printed and not counted: each names what it waits for)"
    if [ "$FAILED" -ne 0 ]; then
        echo "--- error log tail ---"
        $SUDO tail -25 "$ELOG" 2>/dev/null | sed 's/^/        /'
        echo "LITESPEED GATE: FAILED"
        echo "    (the work directory $W is kept for inspection)"
        W_KEEP=1
        exit 1
    fi
    echo "LITESPEED GATE: CLEAR - $($LSWS/bin/lshttpd -v 2>/dev/null | head -1) held every property"
    # the work directory is removed by the exit handler, AFTER the restore that reads the backup kept under it
    exit 0
}

# ---- the fixtures ---------------------------------------------------------------------------------
mkdir -p "$W/html/a" "$W/html/early" "$W/html/.well-known/acme-challenge" "$BACKUP" "$W/unit"
echo "page" > "$W/html/index.html"
echo "pinned static file" > "$W/html/pin.html"
echo "custom-403-page" > "$W/html/e403.html"
echo "tok-body" > "$W/html/.well-known/acme-challenge/tok"
echo "afile" > "$W/html/a/x"
printf 'RewriteEngine On\nRewriteRule . /x [R=302]\n' > "$W/html/early/.htaccess"
find "$W" -type d -exec chmod 0755 {} +
find "$W" -type f -exec chmod 0644 {} +

GEN=../core/make-test-snapshot.py
# The planes, from the ONE generator every gate shares: a synthetic reputation plane (format 1, the
# radix index) and a synthetic Tor plane (format 2). The generator spreads n ranges over the key space
# by a fixed rule, so two planes made with the same n cover the same addresses; the Tor plane takes a
# different n, and the clients are chosen below from the two expectation files so that each reputation
# client is in no Tor range and the Tor client in no reputation range.
python3 "$GEN" --plane reputation --out "$W/rep.bin" --format 1 --v4-index radix-16 --v6-index none --synthetic 4 4 --expect "$W/rep.expect" >/dev/null \
    || { echo "LITESPEED GATE: FAILED - the generator did not write the reputation plane"; exit 1; }
python3 "$GEN" --plane tor --out "$W/tor.bin" --format 2 --synthetic 3 3 --expect "$W/tor.expect" >/dev/null \
    || { echo "LITESPEED GATE: FAILED - the generator did not write the tor plane"; exit 1; }
EVIDENCE=$(python3 "$GEN" --evidence)
CLIENTS=$(python3 - "$W/rep.expect" "$W/tor.expect" <<'PY'
import ipaddress, sys
def ranges(path, fam):
    rs = {}
    for line in open(path):
        w = line.split()
        if len(w) < 3 or w[0] != fam or w[2] == '-':
            continue
        a = int(ipaddress.ip_address(w[1]))
        lo, hi = rs.get(int(w[2]), (a, a))
        rs[int(w[2])] = (min(lo, a), max(hi, a))
    return rs
def sev(path, fam):
    out = {}
    for line in open(path):
        w = line.split()
        if len(w) >= 4 and w[0] == fam and w[2] != '-' and w[3].startswith('sev='):
            out[int(w[2])] = int(w[3][4:])
    return out
def inside(a, rs):
    return any(lo <= a <= hi for lo, hi in rs.values())
def usable(a, *others):
    ip = ipaddress.ip_address(a)
    return ip.is_global and not ip.is_multicast and not any(inside(a, o) for o in others)
def pick(rs, sv, want, *others):
    for idx, (lo, hi) in sorted(rs.items()):
        if sv.get(idx) != want:
            continue
        for a in (lo, hi):
            if usable(a, *others):
                return str(ipaddress.ip_address(a))
    return ''
def pick_out(path, fam, *others):
    for line in open(path):
        w = line.split()
        if len(w) >= 3 and w[0] == fam and w[2] == '-' and usable(int(ipaddress.ip_address(w[1])), *others):
            return w[1]
    return ''
def pick_any(rs, *others):
    for idx, (lo, hi) in sorted(rs.items()):
        for a in (lo, hi):
            if usable(a, *others):
                return str(ipaddress.ip_address(a))
    return ''
rep4, tor4, rep6 = ranges(sys.argv[1], '4'), ranges(sys.argv[2], '4'), ranges(sys.argv[1], '6')
s4, s6 = sev(sys.argv[1], '4'), sev(sys.argv[1], '6')
print('LLOW=%s' % pick(rep4, s4, 1, tor4))
print('LMED=%s' % pick(rep4, s4, 2, tor4))
print('LHIGH=%s' % pick(rep4, s4, 3, tor4))
print('LCRIT=%s' % pick(rep4, s4, 4, tor4))
print('UNL=%s' % pick_out(sys.argv[1], '4', rep4, tor4))
print('L6HIGH=%s' % pick(rep6, s6, 3))
print('TOR=%s' % pick_any(tor4, rep4))
PY
) || { echo "LITESPEED GATE: FAILED - the clients could not be chosen from the expectation files"; exit 1; }
eval "$CLIENTS"
[ -n "$LHIGH" ] && [ -n "$LLOW" ] && [ -n "$LMED" ] && [ -n "$LCRIT" ] && [ -n "$UNL" ] && [ -n "$L6HIGH" ] && [ -n "$TOR" ] \
    || { echo "LITESPEED GATE: FAILED - the expectation files do not name every client this gate needs: $CLIENTS"; exit 1; }
echo "clients: low $LLOW, medium $LMED, high $LHIGH, critical $LCRIT, unlisted $UNL, high (IPv6) $L6HIGH, tor exit $TOR"
# the legacy snapshot, the generator's single-range form (the snapshot rows' fixture; the installer's block
# names the per-plane directory, so Z2 reads reputation.bin from $D, placed below)
python3 "$GEN" "$W/snapshot.bin" 1 0 3 >/dev/null
$SUDO mkdir -p "$D/planes" "$D/counters"
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/planes/reputation.bin"
$SUDO install -o root -g root -m 0444 "$W/tor.bin" "$D/planes/tor.bin"
$SUDO install -o root -g root -m 0444 "$W/snapshot.bin" "$D/snapshot.bin"
# Z2's data directory is $D itself, as install.sh --dir "$D" names it: the plane the installer fetches there
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/reputation.bin"
$SUDO chown nobody:nogroup "$D/counters"
$SUDO chmod 0755 "$D/counters"

echo "=== litespeed gate: $($LSWS/bin/lshttpd -v 2>/dev/null | head -1) ==="
echo "work $W, planes $D"

# ---- build the module, and its controls -------------------------------------------------------------
# the LSIAPI header: SDK, found and refused above, before the work directory
[ "$MODULE_SRC" = mod_whisper_edge.c ] || echo "module $MODULE_SRC"
CORE_SRC="../core/whisper_edge.c ../core/we_sha256.c ../core/we_counters.c ../core/we_policy.c ../core/we_module.c"
CC_BIN=${CC:-gcc}
# every build through build.sh, the one way an operator builds, so the gate judges the object they get;
# the leg (compiler, version, flags) is build.sh's own print, not this file's claim
build_module() { # build_module <out> [extra cflags]; BUILD_DEBUG=1 builds through build.sh --debug
    local out=$1 extra=${2:-} log
    log=$(CC="$CC_BIN" LSWS="$LSWS" SOURCE_DATE_EPOCH=0 ./build.sh ${BUILD_DEBUG:+--debug} --out "$out" ${extra:+--cflags "$extra"} 2>&1) || {
        printf '%s\n' "$log" | tail -12 | sed 's/^/        /'
        return 1
    }
    BUILD_LEG=$(printf '%s\n' "$log" | grep -E '^== (cc|flags|sdk)')
}
build_debug() { BUILD_DEBUG=1 build_module "$@"; }   # the debug object (WE_MOD_DEBUG) with extra flags, as build.sh --debug makes it
if build_module "$W/mod_whisper_edge.so"; then
    ok "the module compiles clean (-Wall -Wextra -Werror) against the real LSIAPI header"
    printf '%s\n' "$BUILD_LEG" | sed 's/^== /    leg: /'
else
    echo "LITESPEED GATE: FAILED - the module did not compile"; exit 1
fi
# the debug build (WE_MOD_DEBUG, the core's debug counters and assertions on): a separate object, built here for the
# rows that read those counters (M3, row 27e), never the release build and never installed
DBG_SO="$W/mod_whisper_edge-debug.so"
if DLOG=$(CC="$CC_BIN" LSWS="$LSWS" SOURCE_DATE_EPOCH=0 ./build.sh --debug --out "$DBG_SO" 2>&1); then
    grep -q -- '-DWE_MOD_DEBUG' <<<"$DLOG" \
        && ok "debug: the WE_MOD_DEBUG build compiles clean, a separate object ($(wc -c < "$DBG_SO") bytes) whose flags carry -DWE_MOD_DEBUG" \
        || bad "debug: the debug build's flags lack -DWE_MOD_DEBUG: $(grep '^== flags' <<<"$DLOG" | cut -c1-160)"
    dl=$(strings "$DBG_SO" | grep -c 'debug build (WE_MOD_DEBUG)'); rl=$(strings "$W/mod_whisper_edge.so" | grep -c 'debug build (WE_MOD_DEBUG)')
    [ "$dl" -ge 1 ] && [ "$rl" = 0 ] && ! cmp -s "$DBG_SO" "$W/mod_whisper_edge.so" \
        && ok "debug: it carries the line that names a debug build at configuration load, and the release object does not" \
        || bad "debug: the debug line is in the debug object $dl time(s) and in the release object $rl time(s)"
else
    bad "debug: the WE_MOD_DEBUG build failed: $(tail -3 <<<"$DLOG" | tr '\n' '|')"
fi
m0=$($SUDO sha256sum "$LSWS/modules/mod_whisper_edge.so" 2>/dev/null | cut -c1-64)
if out=$(LSWS="$LSWS" ./build.sh --debug --install --out "$W/never.so" 2>&1); then
    bad "debug: build.sh --debug --install did not refuse: $(tail -1 <<<"$out")"
else
    [ "$($SUDO sha256sum "$LSWS/modules/mod_whisper_edge.so" 2>/dev/null | cut -c1-64)" = "$m0" ] && [ ! -e "$W/never.so" ] \
        && ok "debug: build.sh --debug --install is refused before compiling ($out), and the installed module is untouched" \
        || bad "debug: the refused install changed the installed module or built an object"
fi
build_module "$W/ctl-modeoff.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_MODE_OFF_RETURN" || bad "the mode-off control build failed"
build_module "$W/ctl-nostore.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_DROP_NOSTORE" || bad "the no-store control build failed"
build_module "$W/ctl-noflush.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_NO_EXIT_FLUSH" || bad "the exit-flush control build failed"
if build_module "$W/ctl-refused.so" "-DWE_LS_TEST_DROP_NOSTORE" >/dev/null 2>&1; then
    bad "a control define built outside a control build"
else
    ok "the control defines are refused outside a control build (WE_MOD_CONTROL_BUILD)"
fi

# ---- the module's own unit test, against a stub of the server's API ----------------------------------
# shellcheck disable=SC2086
if $CC_BIN -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$SDK" -I../core -DWE_MODULE_SRC="\"$MODULE_SRC\"" \
       -o "$W/test_mod" test_mod.c $CORE_SRC; then
    UNIT_OUT=$("$W/test_mod" "$W/rep.bin" "$W/unit" "$LHIGH" "$UNL" "$LCRIT" 2>&1); URC=$?
    if [ "$URC" = 0 ]; then
        ok "the module's unit test: $(printf '%s\n' "$UNIT_OUT" | grep -o '[0-9]* checks, 0 failed')"
    else
        bad "the module's unit test failed (exit $URC): $(printf '%s\n' "$UNIT_OUT" | grep -E 'FAIL|===' | tr '\n' '|' | cut -c1-300)"
    fi
else
    bad "the module's unit test did not compile"
fi
# two legacy publishes inside one write, made deterministic by the seam WE_MOD_TEST_LEGACY_HOLD and run under
# AddressSanitizer: the writer keeps the set it loaded alive across both publishes. The control
# WE_MOD_TEST_LEGACY_LOOP_FREES is the one-slot handoff the retired list replaced, which freed that set on the second
# publish: ASan must report the heap-use-after-free
legacy_hold_run() { # legacy_hold_run <out> <extra defines> -> LH_RC, LH_OUT
    # shellcheck disable=SC2086
    if $CC_BIN -std=gnu11 -O1 -g -fno-omit-frame-pointer -fsanitize=address -Wall -Wextra -Werror -I"$SDK" -I../core \
           -DWE_MODULE_SRC="\"$MODULE_SRC\"" -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_LEGACY_HOLD $2 -o "$1" test_mod.c $CORE_SRC; then
        rm -rf "$W/unit-lh"; mkdir -p "$W/unit-lh"
        LH_OUT=$(ASAN_OPTIONS=detect_leaks=0 "$1" "$W/rep.bin" "$W/unit-lh" "$LHIGH" "$UNL" "$LCRIT" 2>&1); LH_RC=$?
    else
        LH_RC=99; LH_OUT="did not compile"
    fi
}
legacy_hold_run "$W/test_mod_lh" ""
if [ "$LH_RC" = 0 ] && ! grep -q 'AddressSanitizer' <<<"$LH_OUT"; then
    ok "legacy hold: two publishes inside one write, under AddressSanitizer: the written set stays alive and the next tick frees both ($(grep -o '[0-9]* checks, 0 failed' <<<"$LH_OUT"))"
else
    bad "legacy hold: exit $LH_RC: $(grep -E 'FAIL|ERROR: AddressSanitizer|SUMMARY|===' <<<"$LH_OUT" | tr '\n' '|' | cut -c1-300)"
fi
legacy_hold_run "$W/test_mod_lhc" "-DWE_MOD_TEST_LEGACY_LOOP_FREES"
if grep -q 'ERROR: AddressSanitizer: heap-use-after-free' <<<"$LH_OUT"; then
    ctl 0 "WE_MOD_TEST_LEGACY_LOOP_FREES frees the handed-over set on the second publish and ASan reports the heap-use-after-free: $(grep -o 'SUMMARY: AddressSanitizer: heap-use-after-free [^ ]*' <<<"$LH_OUT" | head -1)"
else
    ctl 1 "WE_MOD_TEST_LEGACY_LOOP_FREES (exit $LH_RC, no heap-use-after-free reported)"
fi

# ---- H2: the built object, read by symbol ------------------------------------------------------------
#
# The decide wrapper is disassembled out of the built .so and held to the hot-path gate's checks (no
# branch-and-link, no supervisor call, nothing of the atomic class but the acquire loads of the view
# pointers, the instruction band of the hpmod row), the access handler's evaluation must reach that
# exact symbol directly, and every function the handler calls, transitively inside the module's own
# text, may call outside it only what the LiteSpeed rows of the handler-call table allow. The table is
# carried here until the shared file exists under core/gate.
ARCH=$(uname -m)
OBJ="$W/mod_whisper_edge.so"
WRAP=ls_whisper_edge_decide
if readelf -SW "$OBJ" | hit ' \.symtab '; then
    ok "H2: the build carries its symbol table (not a stripped build)"
else
    bad "H2: stripped build: no .symtab, so no symbol can be judged"
fi
dis() { objdump -d --no-show-raw-insn "--disassemble=$1" "$OBJ" 2>/dev/null | sed -n "/<$1>:\$/,/^\$/p" | sed '1d'; }
insns() { dis "$1" | grep -E '^[[:space:]]*[0-9a-f]+:' | sed -E 's/^[[:space:]]*[0-9a-f]+:[[:space:]]*//' | tr '\t' ' '; }
A64_BRANCH='\b(bl|blr|br|svc|hvc|smc|brk|hlt|eret)[a-z]*\b'
A64_CLASS='\b(ld|st)(add|clr|eor|set|smax|smin|umax|umin)[a-z]*\b|\b(ld|st)[a-z]*x[rp][bh]?\b|\b(stl|lda|ldla|stll|swp|cas|ldiap|stil)[a-z]*\b'
A64_ACQUIRE='^[[:space:]]*ld(a|ap)r[[:space:]]+x[0-9]+,[[:space:]]*\[x[0-9]+\]$'
A64_BARRIER='\b(dmb|dsb|isb)\b'
X86_BRANCH='\b(call[a-z]*|lcall[a-z]*|syscall|sysenter|int|int[0-9]|into|ud[0-9a-z]*)\b|\b(jmp[a-z]*|ljmp[a-z]*)[[:space:]]+\*|\bljmp[a-z]*\b|\bnotrack\b'
X86_LOCK='\block\b'
X86_FENCE='\b[lms]fence\b'
WI=$(insns "$WRAP")
if [ -z "$WI" ]; then
    bad "H2: the decide wrapper $WRAP is not in the object (or could not be disassembled)"
else
    N=$(printf '%s\n' "$WI" | grep -c .)
    if [ "$N" -ge 1944 ] && [ "$N" -le 4384 ]; then
        ok "H2: the decide wrapper $WRAP is $N instructions, inside the hpmod band 1944..4384"
    else
        bad "H2: the decide wrapper is $N instructions, outside the hpmod band 1944..4384"
    fi
    if [ "$ARCH" = aarch64 ]; then
        f=$(printf '%s\n' "$WI" | grep -E "$A64_BRANCH" | head -3 | tr '\n' ';')
        [ -z "$f" ] && ok "H2: no bl, blr, br or svc in the wrapper" || bad "H2: a branch in the wrapper: $f"
        f=$(printf '%s\n' "$WI" | grep -E "$A64_BARRIER" | head -3 | tr '\n' ';')
        [ -z "$f" ] && ok "H2: no barrier in the wrapper" || bad "H2: a barrier in the wrapper: $f"
        nacq=$(printf '%s\n' "$WI" | grep -cE "$A64_ACQUIRE")
        cls=$(printf '%s\n' "$WI" | grep -E "$A64_CLASS" | grep -vE "$A64_ACQUIRE" | head -3 | tr '\n' ';')
        if [ "$nacq" -ge 1 ] && [ "$nacq" -le 8 ] && [ -z "$cls" ]; then
            ok "H2: the atomic class in the wrapper is $nacq acquire load(s) of a view pointer and nothing else"
        else
            bad "H2: the wrapper's atomic class: $nacq acquire loads, other: ${cls:-none}"
        fi
    else
        f=$(printf '%s\n' "$WI" | grep -E "$X86_BRANCH" | head -3 | tr '\n' ';')
        [ -z "$f" ] && ok "H2: no call, syscall or indirect jump in the wrapper" || bad "H2: a call in the wrapper: $f"
        f=$(printf '%s\n' "$WI" | grep -E "$X86_LOCK|$X86_FENCE" | head -3 | tr '\n' ';')
        [ -z "$f" ] && ok "H2: no locked instruction or fence in the wrapper" || bad "H2: a lock or fence in the wrapper: $f"
    fi
    # a branch to another symbol is a call however it is spelled
    f=$(dis "$WRAP" | grep -oE '<[A-Za-z_.][A-Za-z0-9_.@]*(\+0x[0-9a-f]+)?>' | grep -vE "<$WRAP(\+0x[0-9a-f]+)?>" | sort -u | tr '\n' ' ')
    [ -z "$f" ] && ok "H2: the wrapper names no other symbol" || bad "H2: the wrapper reaches another symbol: $f"
fi
# the evaluation reaches the wrapper directly, never a clone of it
if nm "$OBJ" | hit -E " [tT] $WRAP\."; then
    bad "H2: a clone of the wrapper exists: $(nm "$OBJ" | grep -E " [tT] $WRAP\." | awk '{print $3}' | tr '\n' ' ')"
else
    ok "H2: no .constprop, .isra or .part clone of the wrapper exists"
fi
if dis ls_decide_frame | hit -E "(bl|call)[a-z]*[[:space:]]+[0-9a-f]+ <$WRAP>"; then
    ok "H2: the decision frame calls the wrapper directly by its own symbol"
else
    bad "H2: the decision frame does not call <$WRAP> directly"
fi
# every function the HTTP_AUTH handler reaches inside the module, and what each may call outside it
declare -A ALLOW_EXT=(
    [memcpy]=1 [memset]=1 [memchr]=1 [memcmp]=1 [strlen]=1 [strncasecmp]=1 [strchr]=1 [inet_pton]=1 [__stack_chk_fail]=1
    [ls_xpool_alloc]=1 [__snprintf_chk]=1 [snprintf]=1 [vsnprintf]=1 [__vsnprintf_chk]=1
)
FORBID='^(malloc|calloc|realloc|free|posix_memalign|aligned_alloc|syscall|getpid|clock_gettime|gettimeofday|write|read|open|openat|stat|fstat|mmap|munmap|pthread_.*|dlopen|dlclose|strtoul|strtol|strtoull)$'
LOCAL_SYMS=$(nm "$OBJ" | awk '$2 ~ /^[tT]$/ {print $3}')
is_local() { printf '%s\n' "$LOCAL_SYMS" | hit -x -- "$1"; }
declare -A SEEN=()
queue=(we_check)
indirect=0
h2bad=""
while [ ${#queue[@]} -gt 0 ]; do
    fn=${queue[0]}; queue=("${queue[@]:1}")
    [ -n "${SEEN[$fn]:-}" ] && continue
    SEEN[$fn]=1
    body=$(dis "$fn")
    [ -z "$body" ] && continue
    indirect=$((indirect + $(printf '%s\n' "$body" | grep -cE '\b(blr|call[a-z]*[[:space:]]+\*)' || true)))
    for t in $(printf '%s\n' "$body" | grep -oE '\b(bl|call[a-z]*|b|jmp[a-z]*)[[:space:]]+[0-9a-f]+ <[A-Za-z_.][A-Za-z0-9_.@]*>' | sed -E 's/.*<//; s/>$//' | sort -u); do
        base=${t%@plt}
        base=${base%.cold}
        base=$(printf '%s' "$base" | sed -E 's/\.(constprop|isra|part|lto_priv)\.[0-9]+$//')
        [ "$base" = "$fn" ] && continue
        if is_local "$t" || is_local "$base"; then
            queue+=("$t")
            continue
        fi
        if printf '%s' "$base" | hit -E "$FORBID"; then
            h2bad="$h2bad $fn->$base"
        elif [ -z "${ALLOW_EXT[$base]:-}" ]; then
            h2bad="$h2bad $fn->$base(unlisted)"
        fi
    done
done
if [ -z "$h2bad" ]; then
    ok "H2: every external call of the HTTP_AUTH handler and its ${#SEEN[@]} reachable module functions is on the LiteSpeed row ($indirect indirect sites: the server's API table)"
else
    bad "H2: a call outside the LiteSpeed row:$h2bad"
fi
# the wrapper's control: a call planted inside the decision (the core's WE_MOD_PLANT_CALL) must fail the branch
# row by the same pattern the row reads
if build_module "$W/ctl-plant.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_PLANT_CALL"; then
    o=$OBJ; OBJ=$W/ctl-plant.so
    if [ "$ARCH" = aarch64 ]; then f=$(insns "$WRAP" | grep -E "$A64_BRANCH" | head -1); else f=$(insns "$WRAP" | grep -E "$X86_BRANCH" | head -1); fi
    OBJ=$o
    if [ -n "$f" ]; then ctl 0 "a call planted in the decision is seen in the wrapper ($f)"; else ctl 1 "the planted call (no branch seen in the wrapper)"; fi
else
    bad "H2: the planted-call control build failed"
fi
# eval_records <so> -> one line per record of .we_eval_sites, "<site hex> <symbol holding the site>", or "none"
# when the object carries no such section: the core's own reader (gate/eval-sites.sh), so every gate resolves a
# record the same way. A record is the signed 32-bit distance from its own address to the inlined site.
eval_records() {
    python3 -I - "$1" <<'PY'
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
rec_lines()  { printf '%s\n' "$1" | grep -c . || true; }
rec_inside() { printf '%s\n' "$1" | awk -v w="$WRAP" '$2 == w' | grep -c . || true; }
if grep -q 'we_eval_sites' ../core/we_eval.h 2>/dev/null; then
    # exactly one record per module, inside the decide wrapper; zero records never pass
    recs=$(eval_records "$OBJ"); [ "$recs" = none ] && recs=""
    n=$(rec_lines "$recs"); inside=$(rec_inside "$recs")
    if [ "$n" = 0 ]; then
        bad "H2: no evaluation site found: the core carries the marker and the object has no record"
    elif [ "$n" = 1 ] && [ "$inside" = 1 ]; then
        ok "H2: exactly one evaluation-site record in .we_eval_sites, inside $WRAP (site $(printf '%s' "$recs" | cut -d' ' -f1))"
    else
        bad "H2: $n evaluation-site record(s), $inside inside $WRAP; wanted exactly one, inside the wrapper: $(printf '%s' "$recs" | tr '\n' ';')"
    fi
    # the controls: a decision frame that inlines the evaluator leaves a second record outside the wrapper; the
    # core's record compiled out (its own control define, admitted in a control build alone) leaves none
    if build_module "$W/ctl-inline.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_INLINE_HANDLER"; then
        crecs=$(eval_records "$W/ctl-inline.so"); [ "$crecs" = none ] && crecs=""
        cn=$(rec_lines "$crecs"); cin=$(rec_inside "$crecs")
        if [ "$cn" -gt 1 ] || [ "$cin" != 1 ]; then
            ctl 0 "a decision frame that inlines the evaluator leaves $cn records, $cin inside the wrapper: $(printf '%s' "$crecs" | tr '\n' ';')"
        else
            ctl 1 "the inlined evaluator (records: $(printf '%s' "$crecs" | tr '\n' ';'))"
        fi
    else
        bad "H2: the inline-handler control build failed"
    fi
    if build_module "$W/ctl-nosite.so" "-DWE_MOD_CONTROL_BUILD -DWE_EVAL_SITES_CONTROL -DWE_TEST_NO_EVAL_SITES"; then
        crecs=$(eval_records "$W/ctl-nosite.so")
        if [ "$crecs" = none ] || [ -z "$crecs" ]; then
            ctl 0 "the build with the record compiled out is refused: no evaluation site found"
        else
            ctl 1 "the build without the record carries one: $(printf '%s' "$crecs" | tr '\n' ';')"
        fi
    else
        bad "H2: the no-record control build failed"
    fi
else
    dark "H2 evaluation-site records: core/we_eval.h carries no .we_eval_sites marker on this tree; the row runs, with no edit here, once it does"
fi

# ---- K1: the binary has no key input -----------------------------------------------------------------
mkdir -p "$W/k"
echo "not-a-real-key" > "$W/k/key"
build_module "$W/k/a.so" >/dev/null 2>&1
WHISPER_EDGE_KEY=planted WHISPER_EDGE_KEY_FILE="$W/k/key" build_module "$W/k/b.so" >/dev/null 2>&1
if objcopy --remove-section .we_eval_sites "$W/k/a.so" "$W/k/a.stripped" 2>/dev/null && objcopy --remove-section .we_eval_sites "$W/k/b.so" "$W/k/b.stripped" 2>/dev/null \
        && cmp -s "$W/k/a.stripped" "$W/k/b.stripped"; then
    ok "K1: the module built with and without a key in the environment and on disk is one file"
else
    bad "K1: the keyed and keyless builds differ"
fi
if cmp -s "$W/k/a.so" "$W/mod_whisper_edge.so"; then
    ok "K1: two builds of one tree are one file (reproducible under SOURCE_DATE_EPOCH)"
else
    bad "K1: two builds of one tree differ"
fi
if cmp -s "$W/k/a.so" "$W/ctl-nostore.so"; then ctl 1 "K1: a build with one planted define differs from the tree's"; else ctl 0 "K1: a build with one planted define differs from the tree's"; fi
if grep -nE 'X-API-Key|/edge/k/|whisper-edge/key|WHISPER_EDGE_KEY' mod_whisper_edge.c >/dev/null; then
    bad "K1: the module source names a key path, header or variable"
else
    ok "K1: the module source names no key path, header, variable or keyed URL"
fi

# ---- THE SERVER MUST BE THIS GATE'S ALONE --------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    for unit in lshttpd lsws; do
        case "$(systemctl show -p ActiveState --value "$unit" 2>/dev/null)" in
            active|activating|reloading) UNIT=$unit; break ;;
        esac
    done
fi
if [ -n "$UNIT" ]; then
    $SUDO systemctl stop "$UNIT" >/dev/null 2>&1
    echo "  (the $UNIT unit was running; stopped for this run)"
fi
$SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1
if ! await '! server_alive' 30; then
    echo "LITESPEED GATE: FAILED - an OpenLiteSpeed server is still running and this gate needs it stopped:"
    server_procs | sed 's/^/    /'
    exit 1
fi
# and every port this gate binds must be free: OpenLiteSpeed binds with SO_REUSEPORT, so a port another server
# already holds does not fail the start, and a request to it may be answered by that server, a 200 with no
# module line that would read as a module defect (measured once: a sibling gate on 8099). Refused by cause.
HELD=""
for p in $(seq "$PORT" $((PORT + 12))); do
    h=$($SUDO ss -Hltnp "sport = :$p" 2>/dev/null | head -1)
    [ -n "$h" ] && HELD="$HELD
    $p: $(printf '%s' "$h" | grep -oE 'users:\(.*' | cut -c1-120)"
done
if [ -n "$HELD" ]; then
    echo "LITESPEED GATE: FAILED - a port this gate binds ($PORT to $((PORT + 12))) is held by another process; run with PORT=<free first port>:$HELD"
    exit 1
fi

# ---- stand up the sites --------------------------------------------------------------------------
$SUDO find "$LSWS/conf" "$LSWS/modules" -print | LC_ALL=C sort > "$BACKUP/before.list"
# the access logs are this gate's own files, removed by restore(); a run killed before its restore leaves them, and
# the next run would count that run's lines beside its own (N1 read 60 logged denies against 16 counted), so they go
# here too, before the first start
$SUDO sh -c 'rm -f -- "$1"/whisper-gate.*.log' sh "$LSWS/logs"
$SUDO tar -C "$LSWS" -cpf "$BACKUP/lsws.tar" conf modules || {
    echo "LITESPEED GATE: FAILED - could not archive $LSWS/conf and $LSWS/modules before changing them"; exit 1
}
VHOSTS="WhisperDefault WhisperDeny WhisperOff WhisperBad WhisperPolicy WhisperCtx WhisperAcme WhisperSugar WhisperErr"
for v in $VHOSTS; do $SUDO mkdir -p "$LSWS/conf/vhosts/$v"; done
# a fresh inode renamed into place: the server keeps the file it has mapped until it restarts, where a copy over the
# mapped file changes the running workers' code under them (measured: six SIGSEGVs after one such copy)
# every control arm's workers must exit normally: a control plants a defect a row must see, never a crash. Each ctl-*
# module opens a window when it is installed and the next install closes it, counting the server's lines for a worker
# killed by a signal in between, by timestamp (the Q6 phases move the error log aside and merge it back, which line
# numbers would not survive). M3's dbg-* modules are not windowed: their originals dying of signal 7 is the row.
CTL_OPEN=""; CTL_NAME=""; CTL_ARMS=0; CTL_SIG=""
ctl_window_close() {
    local now n
    [ -n "$CTL_OPEN" ] || return 0
    now=$(date '+%Y-%m-%d %H:%M:%S.%6N')
    n=$($SUDO cat "$ELOG" "$LSWS/logs/error-pre-q6.log" 2>/dev/null \
        | awk -v a="$CTL_OPEN" -v b="$now" '/\[AutoRestarter\] child process with pid=[0-9]+ received signal=/ { t = $1 " " $2; if (t >= a && t <= b) c++ } END { print c + 0 }')
    CTL_ARMS=$((CTL_ARMS + 1))
    [ "$n" = 0 ] || CTL_SIG="$CTL_SIG $CTL_NAME:$n"
    CTL_OPEN=""
}
install_module() {
    ctl_window_close
    case "${1##*/}" in ctl-*) CTL_OPEN=$(date '+%Y-%m-%d %H:%M:%S.%6N'); CTL_NAME=${1##*/} ;; esac
    $SUDO cp "$1" "$LSWS/modules/.mod_whisper_edge.so.new" && $SUDO mv -f "$LSWS/modules/.mod_whisper_edge.so.new" "$LSWS/modules/mod_whisper_edge.so"
}
install_module "$W/mod_whisper_edge.so"
PDEF=$PORT; PDENY=$((PORT+1)); POFF=$((PORT+2)); PBAD=$((PORT+3)); PPOL=$((PORT+4)); PCTX=$((PORT+5)); PACME=$((PORT+6)); PSUG=$((PORT+7)); PERR=$((PORT+8)); P6=$((PORT+9))

# the server-level configuration; <module block> and <extra top-level lines> vary per phase. The phases that
# exercise the trusted-proxy walk write useIpInProxyHeader 0 themselves: a value other than an explicit 0
# is not trusted, and neither is none.
write_main() { # write_main <module block> [top-level extra]
    local i=0 vh listeners="" hosts="" extra=${2:-}
    for vh in $VHOSTS; do
        hosts="$hosts
virtualHost $vh {
    vhRoot                   $W/
    allowSymbolLink          1
    enableScript             0
    restrained               0
    configFile               conf/vhosts/$vh/vhconf.conf
}"
        listeners="$listeners
listener L$i {
    address                  *:$((PORT + i))
    secure                   0
    map                      $vh *
}"
        i=$((i + 1))
    done
    $SUDO tee "$CONF" >/dev/null <<CONF
serverName               whisper-edge-gate
user                     nobody
group                    nogroup
priority                 0
autoRestart              0
httpdWorkers             $WORKERS
inMemBufSize             60M
swappingDir              /tmp/lshttpd/swap
mime                     conf/mime.properties
indexFiles               index.html
disableWebAdmin          1
$extra

errorlog logs/error.log {
    logLevel             ${ELEVEL:-INFO}
    rollingSize          ${ROLLING:-0}
    enableStderrLog      1
}

accessLog logs/whisper-gate.server.log {
    logFormat            "%h %>s"
}

tuning {
    maxConnections       100
    eventDispatcher      best
}

accessControl {
    allow                ALL, 127.0.0.1T, ::1T
}

security {
    fileAccessControl {
        followSymbolLink            1
        checkSymbolLink             0
        requiredPermissionMask      000
        restrictedPermissionMask    000
        restrictedDirPermissionMask 000
    }
    # the CGI daemon starts only when CGIRLimit is a child of this block: 1.9.3's security pass
    # reads it here and nowhere else, so a top-level CGIRLimit is never seen, the daemon forks
    # without a socket and every CGI request fails to connect (measured: no cgid.sock, a deaf
    # child polling a -1 fd, 503 on each request). The CGI phase below needs the daemon, so the
    # limit lives here from the start.
    CGIRLimit {
        maxCGIInstances            20
        minUID                     11
        minGID                     10
        priority                    0
        CPUSoftLimit                10
        CPUHardLimit                50
        memSoftLimit                2047M
        memHardLimit                2047M
        procSoftLimit               400
        procHardLimit               450
    }
}

$1
$hosts
$listeners
listener Lv6 {
    address                  [::1]:$P6
    secure                   0
    map                      WhisperDeny *
}
CONF
}
main_block() { # main_block [mode line] [trusted header]: the http level; no mode line unless asked, so the default is the default
    cat <<BLOCK
module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_data            $D/planes
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_policy_floor    deny if listed >= critical
    whisper_edge_policy_floor    log if tor_exit
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  ${2:-X-Forwarded-For}
    whisper_edge_policy          deny if listed >= high
    whisper_edge_policy          log if listed >= low
${1:+    whisper_edge_mode            $1}
}
BLOCK
}
# every environment value the module exports, in one access-log line per request
LOGFMT='%h %>s action=%{WHISPER_EDGE_ACTION}e rule=\"%{WHISPER_EDGE_RULE}e\" id=%{WHISPER_EDGE_RULE_ID}e reason=%{WHISPER_EDGE_REASON}e program=\"%{WHISPER_EDGE_PROGRAM}e\" logged=\"%{WHISPER_EDGE_LOGGED}e\" gen=\"%{WHISPER_EDGE_GENERATIONS}e\" floor=%{WHISPER_EDGE_FLOOR_ADDR}e verdict=%{WHISPER_EDGE_VERDICT}e listed=%{WHISPER_EDGE_LISTED}e tor=%{WHISPER_EDGE_TOR_EXIT}e inferred=%{WHISPER_EDGE_INFERRED}e asn=%{WHISPER_EDGE_ASN}e country=%{WHISPER_EDGE_COUNTRY}e'
write_vhost() { # write_vhost <name> <module-block-or-empty> [context extra] [vhost extra]
    $SUDO tee "$LSWS/conf/vhosts/$1/vhconf.conf" >/dev/null <<VH
docRoot                  \$VH_ROOT/html/
enableGzip               0

index {
    useServer            0
    indexFiles           index.html
}

accessLog \$SERVER_ROOT/logs/whisper-gate.$1.log {
    useServer            0
    logFormat            "$LOGFMT"
}

rewrite {
    enable               1
    autoLoadHtaccess     1
}
${4:-}
context / {
    location             \$DOC_ROOT/
    allowBrowse          1
    rewrite {
        enable           1
        inherit          1
        autoLoadHtaccess 1
    }
${3:-}
}
$2
VH
}
# WhisperDefault writes NO module block: OpenLiteSpeed hands a virtual host's block to the module only
# when it holds one of the module's parameters (measured), and a host that says nothing is the host that
# proves the default. It is judged as the server's context.
write_vhost WhisperDefault ""
write_vhost WhisperDeny "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      deny
    whisper_edge_threshold low
}"
write_vhost WhisperOff "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      off
}"
write_vhost WhisperBad "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      deny
    whisper_edge_policy    deny if tor_exit garbage
    whisper_edge_deny_status 401
    whisper_edge_data      /nowhere
}"
policy_vhost() { # policy_vhost <deny status>
    write_vhost WhisperPolicy "module mod_whisper_edge {
    ls_enabled               1
    whisper_edge_mode        deny
    whisper_edge_deny_status $1
    whisper_edge_set         @embargo KP SY
    whisper_edge_policy      deny if country in @embargo
    whisper_edge_policy      deny if listed >= medium
    whisper_edge_export      all
}"
}
policy_vhost 451
write_vhost WhisperCtx "" "    module mod_whisper_edge {
        ls_enabled         1
        whisper_edge_mode  deny
    }"
write_vhost WhisperAcme "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      deny
    whisper_edge_policy    deny if listed >= low
}"
write_vhost WhisperSugar "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      deny
    whisper_edge_threshold high
    whisper_edge_policy    deny if listed >= high
}"
write_vhost WhisperErr "module mod_whisper_edge {
    ls_enabled             1
    whisper_edge_mode      deny
    whisper_edge_policy    deny if listed >= low
}" "" "
errorPage 403 {
    url                  /e403.html
}"

start_server() { # start_server -> sets FROM to the first error-log line of this start
    local n0
    n0=$(alog_n WhisperDefault)
    FROM=$(( $(elog_lines) + 1 ))
    $SUDO ${START_WRAP:-} "$LSWS/bin/lswsctrl" start >/dev/null 2>&1
    if await "[ \"\$(code http://127.0.0.1:$PDEF/)\" != 000 ]" 25; then
        # the aliveness request above sends no header, so its own log line is a hold-harmless judgment,
        # and with two workers flushing their access logs on independent clocks that line can land
        # after the NEXT request's line; a phase reading the tail would capture the warmup instead of
        # its request (observed once). Await the warmup's line too, so every line has landed before any
        # phase request is issued: that is the invariant req()'s tail read relies on.
        await "[ \"\$(alog_n WhisperDefault)\" -gt $n0 ]" 5
        return 0
    fi
    return 1
}
restart_server() { # a stop and a start: a clean load, the error log read from this start
    $SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1
    await '! server_alive' 20 || true
    start_server
}
alog()   { $SUDO cat "$LSWS/logs/whisper-gate.$1.log" 2>/dev/null; }
alog_n() { alog "$1" | grep -c .; }
field()  { printf '%s\n' "$1" | grep -oE "(^| )$2=(\"[^\"]*\"|[^ ]*)" | head -1 | sed -E "s/^ ?$2=//; s/^\"//; s/\"\$//"; }
# req <vhost> <url> [curl args]: CODE, and LINE, the access-log line this request wrote (the server flushes
# its access log on its own clock, so the line is awaited rather than read at once)
req()  { local vh=$1 url=$2 n; shift 2; n=$(alog_n "$vh"); CODE=$(code "$@" "$url"); if await "[ \"\$(alog_n $vh)\" -gt $n ]" 5; then LINE=$(alog "$vh" | tail -1); else LINE=""; fi; }
reqw() { local vh=$1 url=$2 n; shift 2; n=$(alog_n "$vh"); WIRE=$(wire "$@" "$url"); CODE=$(printf '%s\n' "$WIRE" | head -1 | awk '{print $2}'); if await "[ \"\$(alog_n $vh)\" -gt $n ]" 5; then LINE=$(alog "$vh" | tail -1); else LINE=""; fi; }
want() { is "$CODE" "$1" "$2" "$3"; }
# the module's configuration-time lines of this start
LOAD=""
load_lines() { LOAD=$(mod_log_since "$FROM" | grep -F 'whisper edge: policy: ' | sed 's/^whisper edge: policy: //'); }
has_line()   { printf '%s\n' "$LOAD" | hit -F -- "$1"; }
line_of()    { printf '%s\n' "$LOAD" | grep -F -- "$1" | head -1; }
count_line() { printf '%s\n' "$LOAD" | grep -cF -- "$1"; }
d16_of()     { printf '%s\n' "$1" | grep -oE 'program [0-9a-f]{16}' | head -1 | awk '{print $2}'; }

write_main "$(main_block)" "useIpInProxyHeader       0"
if ! start_server; then
    bad "OpenLiteSpeed did not start or did not serve: $($SUDO tail -3 "$ELOG" 2>/dev/null | tr '\n' ' ')"
    finish
fi
sleep 0.5
load_lines

# ---- 1. THE PROMISE THE PRODUCT RESTS ON: dry run is the default -----------------------------------------
req WhisperDefault "$(u $PDEF /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "no mode directive anywhere + a listed HIGH client behind the trusted proxy -> 200" "a listed client was blocked with no mode directive"
is "$(field "$LINE" action)|$(field "$LINE" logged)|$(field "$LINE" floor)" "would-deny|ctx:1,2|$LHIGH" \
    "and the access log carries the decision: action=would-deny logged=ctx:1,2 (the downgraded deny and the log rule) floor=$LHIGH" "the access log does not carry the dry-run decision: $LINE"
is "$(field "$LINE" verdict)|$(field "$LINE" listed)|$(field "$LINE" tor)|$(field "$LINE" inferred)" "high|high|false|false" \
    "and the exported attributes: verdict=high listed=high tor=false inferred=false" "the exported attributes are wrong: $LINE"
case "$(field "$LINE" gen)" in reputation:1.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\ tor:1.[0-9a-f]*) ok "and the generations token names both planes with their generation and digest: $(field "$LINE" gen)" ;; *) bad "the generations token is $(field "$LINE" gen)" ;; esac
case "$(field "$LINE" program)" in floor:????????????????\ ctx:????????????????) ok "and the program names both blocks: $(field "$LINE" program)" ;; *) bad "the program renders $(field "$LINE" program)" ;; esac
is "$(field "$LINE" id)|$(field "$LINE" reason)" "-|-" "and a would-deny decides nothing: rule_id=- reason=- (the default allow decided, the fired rules are in logged)" "a would-deny rendered rule_id and reason: $LINE"
if await_elog "WOULD DENY $LHIGH by ctx:1,ctx:2"; then
    ok "and the would-deny line is written to the error log, naming the fired rules, so log mode is not silent"
else
    bad "no WOULD DENY line for $LHIGH: $($SUDO grep -F 'WOULD DENY' "$ELOG" | tail -1)"
fi
elog_has "WOULD DENY $LHIGH by ctx:1,ctx:2 \"the rules logged\" (program floor:" && elog_has "; evidence none carried; mode is log, request allowed;" \
    && ok "and it names the program and the evidence slot: this synthetic plane carries none, and the line says so rather than inventing one" || bad "the would-deny line's program or evidence slot is wrong: $($SUDO grep -F 'WOULD DENY' "$ELOG" | tail -1 | cut -c1-200)"

# ---- 2. the pre-stage: the gate's own loopback is hold-harmless, exempt before any rule ----------------
req WhisperDeny "$(u $PDENY /index.html)"
want 200 "the loopback peer itself (hold-harmless) is exempt on the deny host -> 200" "loopback was judged by a rule"
is "$(field "$LINE" action)|$(field "$LINE" reason)" "allow|hold-harmless,floor-header-missing" \
    "and reason=hold-harmless,floor-header-missing: a trusted peer that sent no header is judged itself, exempt by the hold-harmless step" "the loopback decision: $LINE"
case "$(field "$LINE" program)" in floor:*\ ctx:-) ok "and a pre-stage decision renders ctx:- (no context program ran)" ;; *) bad "a pre-stage decision renders $(field "$LINE" program)" ;; esac

# ---- 3. control: deny where asked, with the module's body and no-store on the wire ----------------------
reqw WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "a site with whisper_edge_mode deny and threshold low DOES block a LOW client -> 403" "the deny host did not deny"
printf '%s\n' "$WIRE" | hit -i '^cache-control: no-store' && ok "and the deny carries Cache-Control: no-store on the wire" || bad "no Cache-Control: no-store on the deny"
printf '%s\n' "$WIRE" | hit '^Forbidden by the Whisper edge policy floor.$' && ok "and the body is the module's own fixed text (class module)" || bad "the deny body is not the module's text"
printf '%s\n' "$WIRE" | hit -i '^content-length: 44$' && ok "and Content-Length is the text's 44 bytes" || bad "Content-Length is not 44: $(printf '%s\n' "$WIRE" | grep -i content-length)"
is "$(field "$LINE" action)|$(field "$LINE" id)|$(field "$LINE" rule)" "deny|ctx:1|deny if listed >= low" \
    "and the access log names the deciding rule: action=deny id=ctx:1 rule=\"deny if listed >= low\"" "the deny's log line: $LINE"
await_elog "denied $LLOW by ctx:1 \"deny if listed >= low\"" && ok "and the denied line names the rule and its text" || bad "no denied line for $LLOW"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $UNL"
want 200 "an unlisted client on the deny host -> 200" "an unlisted client was denied"
is "$(field "$LINE" verdict)|$(field "$LINE" listed)|$(field "$LINE" action)" "none|none|allow" \
    "and an unlisted address renders verdict=none listed=none (the definite absence, never unknown)" "the unlisted client's line: $LINE"

# ---- 4. mode off: the context program is skipped, the floor still judges, the verdict is still written ----
req WhisperOff "$(u $POFF /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "a site with whisper_edge_mode off serves a HIGH client -> 200" "mode off denied"
if [ "$(field "$LINE" action)" = allow ] && [ "$(field "$LINE" verdict)" = high ] && case "$(field "$LINE" program)" in floor:*\ ctx:-) true ;; *) false ;; esac; then
    ok "and under mode off the program reads ctx:- while the verdict is still exported (high): off skips the rules, not the record"
else
    bad "mode off rendered action $(field "$LINE" action) program $(field "$LINE" program) verdict $(field "$LINE" verdict)"
fi
req WhisperOff "$(u $POFF /index.html)" -H "X-Forwarded-For: $LCRIT"
want 200 "a CRITICAL client on the off site under the http level's default mode -> 200 (the floor's deny is a dry run)" "the floor denied under mode log"
is "$(field "$LINE" action)|$(field "$LINE" logged)" "would-deny|floor:1" "and the floor's downgraded deny is logged=floor:1 under the http level's mode, whatever the site says" "the floor under mode off: $LINE"
req WhisperDefault "$(u $PDEF /index.html)" -H "X-Forwarded-For: $TOR"
want 200 "a Tor exit that is in no reputation range, on the default site -> 200" "a tor exit was denied"
is "$(field "$LINE" tor)|$(field "$LINE" logged)|$(field "$LINE" listed)" "true|floor:2|none" "and the floor's log rule fired alone: tor=true logged=floor:2 listed=none" "the tor exit's line: $LINE"

# ---- 5. a refused policy refuses the site's rules as a whole; the rest stand --------------------------
has_line 'policy refused: "WhisperBad": policy #2: rule 1, line 1, column 18: near "garbage": trailing input after a complete rule. join conditions with and or or. The context'"'"'s policy is refused as a whole' \
    && ok "L1: the refused host's line names the host, the directive's ordinal (#2) and the refusal (rule 1, line 1, column 18, near \"garbage\")" \
    || bad "L1: no refusal line for WhisperBad: $(line_of WhisperBad)"
has_line '"WhisperBad": whisper_edge_deny_status #3: 401 requires a WWW-Authenticate header, which this module does not send; use 403' \
    && ok "deny_status 401 is refused with its class's reason" || bad "deny_status 401 was not refused: $(line_of deny_status)"
has_line 'vhost "WhisperBad": whisper_edge_data #4: whisper_edge_data is http level only, so that no virtual host can change the floor' \
    && ok "an http-only directive in a virtual host is refused, so no virtual host can change the floor" || bad "whisper_edge_data in a vhost was not refused"
has_line 'vhost "WhisperBad": refused (policy #2: rule 1, line 1, column 18: near "garbage": trailing input after a complete rule. join conditions with and or or); runs no context rule under mode deny' \
    && ok "L1: and the per-context line says what the host runs: no context rule, under its own mode" || bad "L1: the WhisperBad context line: $(line_of 'vhost "WhisperBad":')"
req WhisperBad "$(u $PBAD /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "L1: the refused host runs no context rule: a HIGH client -> 200 (the floor's critical rule does not fire)" "the refused host judged"
case "$(field "$LINE" program)" in floor:????????????????\ ctx:????????????????) ok "L1: and its program renders a context digest: the empty program, not the absence of one" ;; *) bad "L1: the refused host's program renders $(field "$LINE" program)" ;; esac
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "L1: and the good host beside it still denies" "the good host stopped denying"

# ---- 6. the policy host: a status of its own, a set, an inert rule on an absent plane, export all --------
reqw WhisperPolicy "$(u $PPOL /index.html)" -H "X-Forwarded-For: $LHIGH"
want 451 "whisper_edge_deny_status 451 is the status on the wire" "the policy host's status"
printf '%s\n' "$WIRE" | hit -i '^cache-control: no-store' && ok "and 451 carries no-store" || bad "no no-store on the 451"
RL=$(line_of 'references plane "routing"')
case "$RL" in report\ http/v[0-9]*:\ rule\ 1:\ rule\ 1\ references\ plane\ \"routing\",\ which\ is\ not\ installed\ here*) ok "the rule on the absent routing plane is reported inert at configuration time: ${RL%%;*}" ;; *) bad "the inert routing rule was not reported: $(printf '%s\n' "$LOAD" | grep -F 'report' | head -3 | tr '\n' '|')" ;; esac
is "$(field "$LINE" id)|$(field "$LINE" asn)|$(field "$LINE" country)" "ctx:2|unknown|unknown" \
    "under export all an attribute of an unbound plane renders unknown (asn, country) and the deciding rule is ctx:2" "the policy host's line: $LINE"
case "$(field "$LINE" gen)" in *routing:-a*) ok "and the generations token says why: routing:-a (absent or not bound)" ;; *) bad "the token lacks routing:-a: $(field "$LINE" gen)" ;; esac

# ---- 7. the context-level block never reaches the module -----------------------------------------------
req WhisperCtx "$(u $PCTX /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "a context-level module block is dropped by the server: the host runs the server's program under the default mode -> 200" "the context block was honoured"
if has_line 'WhisperCtx' || has_line 'context-level module block'; then bad "the module received a configuration for WhisperCtx, which has only a context-level block"; else ok "and the module printed no line for it: the block is visible in the server's log, not in the module's"; fi

# ---- 8. the sugar: a threshold line and the written rule are one program (G1) --------------------------
S_LINE=$(line_of 'vhost "WhisperDeny":')
case "$S_LINE" in *"(the threshold line's sugar program "*" equals the written rule deny if listed >= low), mode deny, inherits nothing")
    d1=$(printf '%s\n' "$S_LINE" | sed -E 's/.*program ([0-9a-f]{16}) \(the threshold line.s sugar program ([0-9a-f]{16}).*/\1 \2/')
    if [ "${d1% *}" = "${d1#* }" ]; then ok "G1: the threshold line's sugar program and the written rule compile to one digest (${d1% *})"; else bad "G1: the two digests differ: $d1"; fi ;;
    *) bad "G1: the WhisperDeny line does not print the two digests: $S_LINE" ;;
esac
SUG=$(line_of 'policy refused: "WhisperSugar"')
case "$SUG" in *"write the equivalent rule: deny if listed >= high"*) ok "G1: a threshold beside a policy line is refused with the equivalent rule named: $(printf '%s' "$SUG" | grep -oE 'threshold #[0-9]+: .{0,90}')" ;; *) bad "G1: threshold beside a policy line was not refused: $(line_of WhisperSugar)" ;; esac
req WhisperSugar "$(u $PSUG /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "G1: and the refused host runs no context rule (a HIGH client -> 200)" "the refused sugar host judged"

# ---- 9. the configuration-time lines, once per context, naming the programs (G2, G3) -------------------
for c in 'floor: 2 rules, program ' 'server: 2 rules, program ' 'vhost "WhisperDeny": 1 rules, program ' 'vhost "WhisperOff": no lines of its own; runs program ' 'vhost "WhisperPolicy": 2 rules, program ' 'vhost "WhisperAcme": 1 rules, program '; do
    n=$(count_line "$c")
    [ "$n" = 1 ] && ok "G2: the line \"${c%%,*}\" appears once in this load, naming its program" || bad "G2: the line \"$c\" appears $n times"
done
PS=$(d16_of "$(line_of 'server: 2 rules')")
PY=$(d16_of "$(line_of 'vhost "WhisperDeny": 1 rules')")
PO=$(d16_of "$(line_of 'vhost "WhisperOff"')")
if [ -n "$PS" ] && [ "$PO" = "$PS" ] && [ -n "$PY" ] && [ "$PY" != "$PS" ]; then
    ok "G3: the host with no lines of its own runs the server's program $PS under its own mode; WhisperDeny runs its own $PY"
else
    bad "G3: server $PS, WhisperOff $PO, WhisperDeny $PY"
fi
has_line 'vhost "WhisperDeny" replaces 2 inherited rules' && ok "G3: a host with its own lines REPLACES the inherited rules, and the line says so" || bad "the replacement line is missing"
has_line 'floor: 2 rules, program ' && has_line ', mode log and deny status 403 from the http level' && ok "the floor line prints its mode and status from the http level: $(line_of 'floor: 2 rules')" || bad "the floor line: $(line_of 'floor:')"
has_line 'the floor will not deny: its mode is the http level'"'"'s (log); add "whisper_edge_mode deny" at the server level' && ok "the silent dry run is named: the floor will not deny while the http level's mode is log" || bad "the floor's dry run was not named"
has_line 'distinct programs and the floor, ' && has_line ' hot bytes in all (configuration-wide, after interning)' && ok "G4: the configuration-wide hot-bytes total is printed: $(line_of 'hot bytes' | grep -oE '[0-9]+ distinct programs and the floor, [0-9]+ hot bytes')" || bad "no hot-bytes line"
has_line 'trusted proxies: 1 IPv4 and 0 IPv6 prefixes as written, merged to 1 and 0' && ok "T1: the trust table line: 1 IPv4 and 0 IPv6 prefixes, merged to 1 and 0" || bad "the trust table line: $(line_of 'trusted proxies')"

# ---- 10. the arena and the planes in the workers: read-only, shared, locked (G4, G5) -------------------
workers() {
    local main p out=""
    main=$($SUDO cat "$PIDFILE" 2>/dev/null || true)
    [ -n "$main" ] || return 0
    for p in $(pgrep -P "$main" 2>/dev/null || true); do
        case "$($SUDO tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)" in *lscgid*) ;; *) out="$out $p" ;; esac
    done
    echo $out
}
sm() { printf '%s\n' "$1" | sed -n "s/^$2: *\\([0-9]*\\) kB.*/\\1/p" | head -1; }
perms_at() { # perms_at <pid> <hex address without 0x> -> the permission column of the mapping holding it
    $SUDO awk -v want="$2" 'function hexv(s, i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
        { split($1, r, "-"); a = hexv(want); if (a >= hexv(r[1]) && a < hexv(r[2])) print $2 }' "/proc/$1/maps"
}
read -r -a WK <<< "$(workers)"
if [ ${#WK[@]} -ge 2 ]; then
    W1=${WK[0]}; W2=${WK[1]}
    BLOCKS=$(line_of 'blocks at' | sed -n 's/.*blocks at //p' | tr -d ',')
    nb=0
    for b in $BLOCKS; do
        addr=${b#0x}
        for pid in $W1 $W2; do
            perms=$(perms_at "$pid" "$addr")
            [ "$perms" = "r--p" ] && nb=$((nb + 1)) || bad "G5: the arena page at 0x$addr is ${perms:-unmapped} in worker $pid, not r--p"
        done
    done
    [ "$nb" -gt 0 ] && ok "G5: every arena block ($((nb / 2)) blocks: the floor, its hold-harmless view and the programs) is r--p in two workers after WORKER_INIT"
    for plane in reputation tor; do
        for pid in $W1 $W2; do
            vma=$($SUDO awk -v f="$D/planes/$plane.bin" 'index($0, f) { show=1; print; next } /^[0-9a-f]+-[0-9a-f]+ / { show=0 } show { print }' "/proc/$pid/smaps")
            rss=$(sm "$vma" Rss); shc=$(sm "$vma" Shared_Clean); prd=$(sm "$vma" Private_Dirty); an=$(sm "$vma" Anonymous); lk=$(sm "$vma" Locked)
            if [ -z "$rss" ]; then
                bad "G4+: worker $pid has no mapping of $plane.bin"
            elif [ "${an:-1}" = 0 ] && [ "${prd:-1}" = 0 ] && [ "${lk:-0}" -gt 0 ] && [ "${shc:-0}" = "$rss" ]; then
                ok "G4+: worker $pid maps $plane.bin from the page cache: Rss $rss kB, Shared_Clean $shc, Anonymous 0, Private_Dirty 0, Locked $lk kB"
            else
                bad "G4+: worker $pid's $plane.bin mapping: Rss $rss Shared_Clean $shc Anonymous $an Private_Dirty $prd Locked $lk"
            fi
        done
    done
    # Q2: the module's thread (the one at nice 10) blocks every asynchronous signal, SIGILL, FPE, SEGV and BUS clear
    tid=""
    for t in $($SUDO ls "/proc/$W1/task"); do
        [ "$($SUDO sed 's/^.*) //' "/proc/$W1/task/$t/stat" 2>/dev/null | awk '{print $17}')" = 10 ] && { tid=$t; break; }
    done
    if [ -n "$tid" ]; then
        blk=$($SUDO awk '/^SigBlk:/ {print $2}' "/proc/$W1/task/$tid/status")
        v=$((16#$blk))
        if [ $((v & (1 << 3))) = 0 ] && [ $((v & (1 << 7))) = 0 ] && [ $((v & (1 << 10))) = 0 ] && [ $((v & (1 << 6))) = 0 ] \
            && [ $((v & (1 << 14))) != 0 ] && [ $((v & (1 << 0))) != 0 ] && [ $((v & (1 << 9))) != 0 ] && [ $((v & (1 << 1))) != 0 ]; then
            ok "Q2: the module's thread (tid $tid, nice 10) blocks the asynchronous signals (SigBlk $blk) with SIGILL, SIGFPE, SIGSEGV and SIGBUS clear"
        else
            bad "Q2: the module thread's SigBlk is $blk"
        fi
    else
        bad "Q2: no thread at nice 10 in worker $W1: the module's thread is missing"
    fi
    # Q4: every descriptor the module holds on the planes and the counters directory is close-on-exec
    nfd=0; badfd=0
    for fd in $($SUDO ls "/proc/$W1/fd"); do
        case "$($SUDO readlink "/proc/$W1/fd/$fd" 2>/dev/null)" in "$D/planes/"*|"$D/counters"|"$D/planes")
            nfd=$((nfd + 1))
            fl=$($SUDO awk '/^flags:/ {print $2}' "/proc/$W1/fdinfo/$fd")
            [ $((8#$fl & 02000000)) != 0 ] || badfd=$((badfd + 1)) ;;
        esac
    done
    [ "$nfd" -gt 0 ] && [ "$badfd" = 0 ] && ok "Q4: all $nfd module descriptors on the planes and the counters directory in worker $W1 carry O_CLOEXEC" || bad "Q4: $badfd of $nfd module descriptors lack O_CLOEXEC"
else
    bad "G4/G5/Q2/Q4: two OpenLiteSpeed workers are needed (workers: ${WK[*]:-none})"
fi

# ---- 11. the trusted-header walk (T5, T1) ------------------------------------------------------------------
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $UNL" -H "X-Forwarded-For: $LLOW"
want 403 "T5: a forged line before the proxy's: the newest line is judged (two X-Forwarded-For lines, the listed one last) -> 403" "the forged first line was judged"
ARGS=(); for i in $(seq 1 40); do ARGS+=(-H "X-Forwarded-For: $UNL"); done
req WhisperDeny "$(u $PDENY /index.html)" "${ARGS[@]}" -H "X-Forwarded-For: $LLOW"
want 403 "T5: 40 forged lines before the proxy's line: the walk keeps the newest 16 and judges the proxy's entry -> 403" "40 forged lines moved the judged entry"
ARGS=(); for i in $(seq 1 100); do ARGS+=(-H "X-Forwarded-For: $UNL"); done
req WhisperDeny "$(u $PDENY /index.html)" "${ARGS[@]}" -H "X-Forwarded-For: $LLOW"
want 403 "T5: 100 forged lines -> 403, the same" "100 forged lines moved the judged entry"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: [::ffff:$LLOW]:443"
want 403 "T1: a bracketed IPv6 entry with a port, [::ffff:$LLOW]:443, is parsed and canonicalised to IPv4 -> 403" "the bracketed entry did not parse"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW:8080"
want 403 "T1: an IPv4 entry with a port, $LLOW:8080 -> 403" "the port suffix broke the parse"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: zzz, $LLOW"
want 403 "T1: the entries left of the judged one are never examined: zzz, $LLOW -> 403" "a left entry stopped the walk"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW, junk"
want 200 "T1: the rightmost element unparsable: the peer is judged with the unparsed note -> 200 (the peer is 127.0.0.1)" "an unparsable rightmost entry was not the peer"
is "$(field "$LINE" reason)|$(field "$LINE" floor)" "floor-header-unparsed|127.0.0.1" "T1: and the line reads reason=floor-header-unparsed floor=127.0.0.1 with no hold-harmless (eligibility cleared)" "the unparsed case's line: $LINE"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW, junk, 127.0.0.1"
want 200 "T1: a bad entry after a parsed trusted one: the last parsed (the proxy itself) is judged -> 200" "the bad entry was not handled"
is "$(field "$LINE" reason)|$(field "$LINE" floor)" "floor-header-unparsed|127.0.0.1" "T1: and the judged address is the last parsed entry, noted unparsed" "the bad-after-parsed case: $LINE"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For;"
want 200 "T1: an empty header value: the peer, unparsed -> 200" "an empty value broke the walk"
is "$(field "$LINE" reason)" "floor-header-unparsed" "T1: and reason=floor-header-unparsed" "the empty value's line: $LINE"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $L6HIGH"
want 403 "T1: a HIGH IPv6 client, $L6HIGH -> 403" "the IPv6 client was not denied"
is "$(field "$LINE" floor)" "$L6HIGH" "V10: and the floor address is written by the RFC 5952 formatter: $(field "$LINE" floor)" "the IPv6 floor address renders wrong"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 2001:db8:0:0:1:0:0:1"
want 200 "V10: an IPv6 documentation client, 2001:db8:0:0:1:0:0:1 (hold-harmless) -> 200" "the hold-harmless IPv6 client was denied"
is "$(field "$LINE" floor)|$(field "$LINE" reason)" "2001:db8::1:0:0:1|hold-harmless" "V10: and it renders 2001:db8::1:0:0:1 (the longest zero run compressed, the first on a tie)" "the formatter wrote: $LINE"
req WhisperDeny "http://[::1]:$P6/index.html" -g -H "X-Forwarded-For: $LLOW"
want 200 "T1: a request over ::1 (not a trusted proxy): the header is never read, the peer is hold-harmless -> 200" "the untrusted peer's header was read"
is "$(field "$LINE" floor)|$(field "$LINE" reason)" "::1|hold-harmless" "T1: and the untrusted peer is judged itself: floor=::1 reason=hold-harmless (no header-missing mark: the header was not consulted)" "the untrusted peer's line: $LINE"

# ---- 12. ACME (T3) -----------------------------------------------------------------------------------------
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/tok)" -H "X-Forwarded-For: $LLOW"
want 200 "T3: the exact ACME form from a listed client is exempt -> 200" "the ACME challenge was denied"
is "$(field "$LINE" reason)|$(field "$LINE" action)" "acme|allow" "T3: and reason=acme" "the ACME line: $LINE"
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/tok)" -I -H "X-Forwarded-For: $LLOW"
want 200 "T3: HEAD is exempt too" "HEAD was denied"
req WhisperAcme "$(u $PACME '/.well-known/acme-challenge/tok?')" -H "X-Forwarded-For: $LLOW"
want 403 "T3: an empty query (tok?) is a query: not exempt -> 403" "tok? was exempt"
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/%74ok)" -H "X-Forwarded-For: $LLOW"
want 403 "T3: a percent-encoded token character is not exempt -> 403" "%74ok was exempt"
req WhisperAcme "$(u $PACME /.well-known/%2e/acme-challenge/tok)" -H "X-Forwarded-For: $LLOW"
want 403 "T3: a %2e dot segment is not exempt -> 403" "%2e was exempt"
req WhisperAcme "$(u $PACME //.well-known/acme-challenge/tok)" -H "X-Forwarded-For: $LLOW"
want 403 "T3: a leading // is not exempt -> 403" "// was exempt"
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/tok)" -X POST -H "X-Forwarded-For: $LLOW"
want 403 "T3: a POST to the challenge path is not exempt -> 403" "POST was exempt"
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/tok/more)" -H "X-Forwarded-For: $LLOW"
want 403 "T3: two segments are not exempt -> 403" "two segments were exempt"
req WhisperAcme "$(u $PACME /.well-known/acme-challenge/missing)" -H "X-Forwarded-For: $LLOW"
want 404 "T3: a missing token in the exact form is exempt too (the exemption is the path's, not the file's): the server's 404, never the module's deny" "a missing token was judged"
is "$(field "$LINE" reason)" "acme" "T3: and its line reads reason=acme" "the missing token's line: $LINE"

# ---- 13. the error page: the module writes the deny itself, so no error-page hop runs (T7) -----------------
reqw WhisperErr "$(u $PERR /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "T7: a listed client on a host with errorPage 403 configured -> 403" "the errorPage host did not deny"
if printf '%s\n' "$WIRE" | hit '^Forbidden by the Whisper edge policy floor.$' && ! printf '%s\n' "$WIRE" | hit custom-403-page && printf '%s\n' "$WIRE" | hit -i '^cache-control: no-store'; then
    ok "T7: and the body is the module's own text with no-store, not the configured error page: the module ends the response itself, so the server runs no error-page hop (class module)"
else
    bad "T7: the errorPage host's deny: $(printf '%s\n' "$WIRE" | tail -2 | tr '\n' '|')"
fi

# ---- 14. the counters, the status and the configuration files (N1, N4, S1, S8) -----------------------------
SUMMARY_BIN="$ROOT/core/whisper-edge-summary"
# summary_total <counters dir>: the headline's total, read by the headline's own grammar ("  N request(s)
# denied", the line the summary prints first under the window); nothing when the line is not there, so a
# changed headline fails the row that reads it by name, never a number taken from another line
summary_total() { $SUDO "$SUMMARY_BIN" "$1" 2>/dev/null | sed -n -E 's/^  ([0-9]+) requests? denied$/\1/p'; }
# always through make, which rebuilds a binary older than its sources: an executable merely present can predate the
# reader this run's rows assert (a summary built before it read the configuration file's refused lines turned S2 red)
make -C "$ROOT/core" whisper-edge-summary >/dev/null || { echo "LITESPEED GATE: FAILED - cannot build whisper-edge-summary"; exit 1; }
REFRESH_S=10
# every live worker's rule-counter file carries a write taken after <ms>: a tick after the requests
all_ticked_after() { # all_ticked_after <ms>
    local p f w
    for p in $(workers); do
        f=$($SUDO find "$D/counters" -maxdepth 1 -name "$p-*.rules.cnt" 2>/dev/null | head -1)
        [ -n "$f" ] || return 1
        w=$($SUDO sed -n 's/^written \([0-9]*\)$/\1/p' "$f" | head -1)
        [ -n "$w" ] && [ "$w" -ge "$1" ] || return 1
    done
    return 0
}
await_tick() { local t; t=$(now_ms); await "all_ticked_after $t" $((2 * REFRESH_S + 8)); }
await_tick && ok "S1: every live worker wrote its status and rule-counter files after the requests (within two intervals)" \
    || bad "S1: a live worker wrote no rule-counter file in $((2 * REFRESH_S + 8)) s: $($SUDO ls "$D/counters" | tr '\n' ' ')"
DENY16=$PY
RULES=$($SUDO "$SUMMARY_BIN" --rules "$D/counters" 2>&1)
n_deny=$(printf '%s\n' "$RULES" | awk -v d="$DENY16" '$1=="r" && $2==d && $3==1 {print $4}')
DENIES=$( { alog WhisperDeny; alog WhisperAcme; alog WhisperErr; } | grep -c ' 403 action=deny .* id=ctx:1 ')
[ -n "$n_deny" ] && [ "$n_deny" = "$DENIES" ] && ok "N1: whisper-edge-summary --rules sums rule 1 of program $DENY16 to $n_deny, the number of ctx:1 denies the three hosts that run it (interned configuration-wide) logged" \
    || bad "N1: --rules reads rule 1 of $DENY16 as ${n_deny:-nothing}; the access logs hold $DENIES denies: $(printf '%s\n' "$RULES" | head -12 | tr '\n' '|')"
# one request is one pass on this path: a deny counts exactly once
r0=$n_deny
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
await_tick || true
r1=$($SUDO "$SUMMARY_BIN" --rules "$D/counters" 2>/dev/null | awk -v d="$DENY16" '$1=="r" && $2==d && $3==1 {print $4}')
is "$r1" "$((r0 + 1))" "N1: and one more denied request moves rule 1 by exactly one ($r0 to $r1): one pass, one count" "N1: one denied request moved rule 1 from $r0"
n_hh=$(printf '%s\n' "$RULES" | awk '$1=="pre" && $2=="hold-harmless" {print $3}')
n_unp=$(printf '%s\n' "$RULES" | awk '$1=="pre" && $2=="floor-header-unparsed" {print $3}')
n_acme=$(printf '%s\n' "$RULES" | awk '$1=="pre" && $2=="acme" {print $3}')
[ "${n_hh:-0}" -ge 3 ] && [ "${n_unp:-0}" = 3 ] && [ "${n_acme:-0}" = 3 ] \
    && ok "N1: and the pre-stage counters are summed by name: hold-harmless $n_hh, floor-header-unparsed 3, acme 3 (the three exempt ACME requests)" \
    || bad "N1: the pre-stage counts: hold-harmless ${n_hh:-0}, floor-header-unparsed ${n_unp:-0}, acme ${n_acme:-0}"
CONFF=$($SUDO ls "$D/counters" | grep -E '^conf-[0-9a-f]{16}\.status$' | head -1)
if [ -n "$CONFF" ]; then
    d16=$($SUDO sha256sum "$D/counters/$CONFF" | cut -c1-16)
    [ "conf-$d16.status" = "$CONFF" ] && ok "N4/S8: the configuration file is named by the first 16 hex digits of its own SHA-256 ($d16), in byte order" || bad "N4: $CONFF digests to $d16"
    $SUDO grep -q "^text $DENY16 1 \"deny if listed >= low\"$" "$D/counters/$CONFF" && ok "S8: and it carries the deny host's rule text under its digest" || bad "the configuration file lacks the rule text"
    $SUDO grep -qE '^refused "http/v[0-9]+" "policy #2: rule 1, line 1, column 18: near \\"garbage\\": trailing input after a complete rule. join conditions with and or or"$' "$D/counters/$CONFF" && ok "L1: and the refused host's line, refused \"http/vN\" \"policy #2: ...\"" || bad "the configuration file lacks the refused line: $($SUDO grep refused "$D/counters/$CONFF" | head -2 | tr '\n' '|')"
    $SUDO grep -qE '^refused "http/v[0-9]+" "threshold #2: .*whisper_edge_threshold in a context with policy lines. write the equivalent rule: deny if listed >= high"$' "$D/counters/$CONFF" && ok "G1: and the sugar host's refusal with the equivalent rule" || bad "the configuration file lacks the sugar refusal"
    $SUDO grep -q "^plane reputation path \"$D/planes/reputation.bin\"$" "$D/counters/$CONFF" && $SUDO grep -q "^plane tor path \"$D/planes/tor.bin\"$" "$D/counters/$CONFF" && ok "S8: and the bound planes' paths" || bad "the configuration file lacks the plane paths"
else
    bad "S8: no conf-<16 hex>.status file in the counters directory"
fi
STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
# the configuration holds a refused host (WhisperBad, by design), which the reader now reads from the configuration
# file's refused line: the exit is 1 for that reason alone while both workers report every plane armed
[ "$SRC" = 1 ] && [ "$(printf '%s\n' "$STAT" | grep -c 'plane reputation armed generation 1 digest ')" = 2 ] && [ "$(printf '%s\n' "$STAT" | grep -c 'plane tor armed generation 1 digest ')" = 2 ] \
    && ok "S2: whisper-edge-summary --status exits 1 on the refused host (WhisperBad) while both live workers report reputation and tor armed" || bad "S2: --status exit $SRC: $(printf '%s\n' "$STAT" | head -6 | tr '\n' '|')"
SF=$($SUDO ls "$D/counters" | grep -E "^$W1-[0-9a-f]{16}\.status$" | head -1)
if [ -n "$SF" ]; then
    $SUDO grep -q '^process "OpenLiteSpeed (LSIAPI [0-9.]*)" pid '"$W1"' boot [0-9a-f-]* pidns [0-9]* starttime [0-9]* ' "$D/counters/$SF" && ok "S1: worker $W1's status file names it by pid, boot id, pid namespace and start time: $SF" || bad "the status file's process line: $($SUDO head -2 "$D/counters/$SF" | tail -1 | cut -c1-120)"
    [ "$($SUDO grep -c ' mapped locked yes' "$D/counters/$SF")" = 2 ] && ok "S1: and reports both planes mapped and locked" || bad "the status file does not say mapped locked yes for both planes"
else
    bad "no status file for worker $W1"
fi

# ---- 15. a graceful restart loses no count (the exit flush) ----------------------------------------------
gone() { local p; for p in $OLD; do [ -d "/proc/$p" ] && return 1; done; return 0; }
rules_total() { $SUDO "$SUMMARY_BIN" --rules "$D/counters" 2>/dev/null | awk -v d="$DENY16" '$1=="r" && $2==d && $3==1 {print $4}'; }
graceful_flush_row() { # -> 0 when the counts survived the restart
    local before after sent=0 OLDMAIN
    await_tick || true
    before=$(rules_total); before=${before:-0}
    for _ in 1 2 3; do [ "$(code -H "X-Forwarded-For: $LLOW" "$(u $PDENY /index.html)")" = 403 ] && sent=$((sent + 1)); done
    OLD=$(workers); OLDMAIN=$($SUDO cat "$PIDFILE" 2>/dev/null || true)
    [ -n "$OLDMAIN" ] && $SUDO kill -USR1 "$OLDMAIN"
    await gone 120 || { echo "    (old workers still alive after 120 s)"; return 2; }
    await "[ -n \"\$(workers)\" ] && [ \"\$(code $(u $PDEF /))\" != 000 ]" 60 || true
    after=$(rules_total); after=${after:-0}
    echo "    ($before before, $sent refused since the last tick, $after after the old workers exited)"
    [ "$after" -ge $((before + sent)) ] && [ "$sent" -gt 0 ]
}
if graceful_flush_row; then ok "a graceful restart (SIGUSR1 to the main process) loses no count: the exit flush writes what the tick had not"; else bad "a graceful restart lost counts"; fi

# ---- 16. the plane lifecycle: a new generation, a trust change, a rollback, a deletion (M5, M11, S13) ----
status_field() { # status_field <plane> <field regex capture> -> the value every live worker reports, or MIXED
    local p f s set="" first=1
    for p in $(workers); do
        f=$($SUDO find "$D/counters" -maxdepth 1 -name "$p-*.status" 2>/dev/null | head -1)
        [ -n "$f" ] || { echo none; return; }
        s=$($SUDO grep -E "^plane $1 " "$f" | sed -nE "s/^plane $1 $2.*/\\1/p" | head -1)
        if [ $first = 1 ]; then set=$s; first=0; fi
        [ "$s" = "$set" ] || { echo MIXED; return; }
    done
    echo "${set:-none}"
}
status_state() { status_field "$1" '([a-z-]+)'; }
status_gen()   { status_field "$1" '.* generation ([0-9]+)'; }
python3 "$GEN" --plane reputation --out "$W/rep2.bin" --format 1 --v4-index radix-16 --v6-index none --synthetic 4 4 --generation 2 >/dev/null
$SUDO install -o root -g root -m 0444 "$W/rep2.bin" "$D/planes/.reputation.new" && $SUDO mv "$D/planes/.reputation.new" "$D/planes/reputation.bin"
FROM_LIFE=$(( $(elog_lines) + 1 ))
await "[ \"\$(status_gen reputation)\" = 2 ]" $((2 * REFRESH_S + 8)) && ok "M5: a new generation renamed into place is verified off the loop and armed in every worker within the interval (generation 2), no restart" \
    || bad "M5: generation 2 was not armed in $((2 * REFRESH_S + 8)) s (status says $(status_state reputation) $(status_gen reputation))"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "M5: and the new generation is served (a LOW client is still denied)" "the new generation does not serve"
case "$(field "$LINE" gen)" in reputation:2.*) ok "M5: and the record names it: $(field "$LINE" gen | awk '{print $1}')" ;; *) bad "the generations token after the arm: $(field "$LINE" gen)" ;; esac
$SUDO chmod 0644 "$D/planes/reputation.bin"
await "[ \"\$(status_state reputation)\" = disarmed ]" $((2 * REFRESH_S + 8)) && ok "M5: a ctime-only change that admits another writer (chmod 0644) disarms the plane within a tick, every worker reporting disarmed" \
    || bad "M5: after chmod 0644 the status reads $(status_state reputation)"
STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
[ "$SRC" = 1 ] && ok "S2: and --status exits 1 on a disarmed plane" || bad "S2: --status exits $SRC on a disarmed plane"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 200 "a LOW client is no longer denied while reputation is disarmed (fail open)" "a disarmed plane still denied"
if [ "$(field "$LINE" verdict)" = "unknown,disarmed" ] && case "$(field "$LINE" gen)" in reputation:-d*) true ;; *) false ;; esac; then
    ok "and the record says why: verdict=unknown,disarmed, generations reputation:-d"
else
    bad "the disarmed rendering: $LINE"
fi
$SUDO chmod 0444 "$D/planes/reputation.bin"
await "[ \"\$(status_state reputation)\" = armed ]" $((2 * REFRESH_S + 8)) && ok "M5: chmod 0444 back re-arms it (the bytes still carry the arm-time digest)" || bad "M5: after chmod 0444 the status reads $(status_state reputation)"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "M5: and it denies again" "the re-armed plane does not serve"
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/planes/.reputation.new" && $SUDO mv "$D/planes/.reputation.new" "$D/planes/reputation.bin"
await_tick || true
if [ "$(status_gen reputation)" = 2 ] && [ "$(status_state reputation)" = armed ] && $SUDO tail -n +"$FROM_LIFE" "$ELOG" | hit 'plane reputation.bin: generation 1 is not above 2; refused by its header, not digested'; then
    ok "M5/S13: an older generation renamed in is refused by its header, not digested, and the armed generation 2 keeps serving"
else
    bad "a rollback moved the armed generation to $(status_gen reputation) ($(status_state reputation)): $($SUDO tail -n +"$FROM_LIFE" "$ELOG" | grep -F 'plane reputation' | tail -2 | tr '\n' '|')"
fi
$SUDO rm -f "$D/planes/reputation.bin"
await_tick || true
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "M11: the bound name gone: the armed generation serves until its valid-until (a LOW client is still denied)" "deleting the plane dropped the loaded policy"
$SUDO tail -n +"$FROM_LIFE" "$ELOG" | hit 'plane reputation.bin is gone from the data directory; the armed generation serves until its valid-until' && ok "M11: and the line says so" || bad "M11: no gone line"
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/planes/reputation.bin"

# ---- 17. the second configuration: the http level's mode deny, useIpInProxyHeader 1 (L2), the floor's reach (T7)
write_main "$(main_block deny)" "useIpInProxyHeader       1"
restart_server || bad "the server did not restart with the second configuration"
sleep 0.5; load_lines
reqw WhisperOff "$(u $POFF /index.html)" -H "X-Forwarded-For: $LCRIT"
want 403 "with whisper_edge_mode deny at the http level a CRITICAL client in a mode-off site is denied by the floor -> 403" "the floor under a mode-off site"
printf '%s\n' "$WIRE" | hit '^Forbidden by the Whisper edge policy floor.$' && printf '%s\n' "$WIRE" | hit -i '^cache-control: no-store' && ok "with the module's text and no-store" || bad "the floor deny's body or header"
case "$(field "$LINE" program)" in floor:????????????????\ ctx:-) ok "and the program reads floor:<d16> ctx:- (the floor decided)" ;; *) bad "program $(field "$LINE" program)" ;; esac
is "$(field "$LINE" id)|$(field "$LINE" rule)" "floor:1|deny if listed >= critical" "rule_id=floor:1 rule=\"deny if listed >= critical\"" "the floor deny's line: $LINE"
await_elog "denied $LCRIT by floor:1 \"deny if listed >= critical\"" && ok "and the denied line names the floor rule" || bad "no denied line for the floor"
if has_line 'the floor will not deny'; then bad "the dry-run warning is printed although the http level says deny"; else ok "and the dry-run warning is absent under whisper_edge_mode deny"; fi
has_line 'floor: 2 rules, program ' && has_line ', mode deny and deny status 403 from the http level' && ok "the floor line now prints mode deny" || bad "the floor line: $(line_of 'floor:')"
elog_has 'the floor does not trust the client address the server reports: useIpInProxyHeader is 1, and the module trusts only an explicit 0; set it to 0 and name your proxies with whisper_edge_trusted_proxy' && ok "L2: useIpInProxyHeader 1 is named at ERROR: not an explicit 0, so not trusted" || bad "L2: no ERROR line for useIpInProxyHeader 1"
await_tick || true
STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
[ "$SRC" = 1 ] && [ "$(printf '%s\n' "$STAT" | grep -c 'client-ip-from-header')" -ge 2 ] && ok "L2: and both workers' status carries client-ip-from-header, so --status exits 1" || bad "L2: --status exit $SRC: $(printf '%s\n' "$STAT" | grep -m2 process | tr '\n' '|')"
# T7, the floor's reach: a .htaccess redirect answers before the access phase, with no floor count
FLOOR16=$(d16_of "$(line_of 'floor: 2 rules')")
floor_count() { $SUDO "$SUMMARY_BIN" --rules "$D/counters" 2>/dev/null | awk -v d="$FLOOR16" '$1=="r" && $2==d && $3==1 {s+=$4} END {print s+0}'; }
fc0=$(floor_count)
reqw WhisperDeny "$(u $PDENY /early/anything)" -H "X-Forwarded-For: $LCRIT"
want 302 "T7: a floor-listed CRITICAL client requesting a path under .htaccess RewriteRule . /x [R=302] gets the redirect: the early handler answers before the floor" "T7: the early redirect"
await_tick || true
fc1=$(floor_count)
is "$fc1" "$fc0" "T7: and the floor counted nothing for it (floor rule 1: $fc0 before, $fc1 after)" "T7: the floor counted the redirected request"
req WhisperDeny "$(u $PDENY /a/x)" -H "X-Forwarded-For: $LCRIT"
want 403 "T7: the same client on a path the rewrite does not touch is denied by the floor" "the floor did not reach the sibling path"

# ---- 17b. the directive ABSENT: not an explicit 0, so not trusted, and the module says so --------------------
write_main "$(main_block deny)"
restart_server || bad "the server did not restart without a useIpInProxyHeader line"
sleep 0.5; load_lines
elog_has 'the floor does not trust the client address the server reports: useIpInProxyHeader is not set, and the module trusts only an explicit 0; set it to 0 and name your proxies with whisper_edge_trusted_proxy' \
    && ok "L2: and the module names it at ERROR: no setting, so not trusted" || bad "L2: no ERROR line for the absent directive: $($SUDO tail -n +"$FROM" "$ELOG" | grep -F 'does not trust the client address' | head -1 | cut -c1-200)"
await_tick || true
STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
[ "$SRC" = 1 ] && [ "$(printf '%s\n' "$STAT" | grep -c 'client-ip-from-header')" -ge 2 ] && ok "L2: and the status carries client-ip-from-header for the absent directive too, so --status exits 1" || bad "L2: --status exit $SRC under the absent directive"

# ---- 17b'. useIpInProxyHeader 2: a value other than an explicit 0 is not trusted, so the module names it at
# ERROR and the status carries client-ip-from-header, as for 1
write_main "$(main_block deny)" "useIpInProxyHeader       2"
restart_server || bad "the server did not restart with useIpInProxyHeader 2"
sleep 0.5; load_lines
elog_has 'the floor does not trust the client address the server reports: useIpInProxyHeader is 2, and the module trusts only an explicit 0; set it to 0 and name your proxies with whisper_edge_trusted_proxy' \
    && ok "L2: useIpInProxyHeader 2 is named at ERROR too: not an explicit 0, so not trusted" || bad "L2: no ERROR line for useIpInProxyHeader 2: $($SUDO tail -n +"$FROM" "$ELOG" | grep -F 'does not trust the client address' | head -1 | cut -c1-200)"
await_tick || true
STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
[ "$SRC" = 1 ] && [ "$(printf '%s\n' "$STAT" | grep -c 'client-ip-from-header')" -ge 2 ] && ok "L2: and the status carries client-ip-from-header under 2, so --status exits 1" || bad "L2: --status exit $SRC under useIpInProxyHeader 2"

# ---- 17c. the legacy snapshot, with the evidence the generator writes, through the trusted proxy -------------
python3 "$GEN" "$W/snapshot-high.bin" 1 0 3 "$(python3 -c "import ipaddress,sys; print(int(ipaddress.ip_address(sys.argv[1])))" "$LHIGH")" "$(python3 -c "import ipaddress,sys; print(int(ipaddress.ip_address(sys.argv[1])))" "$LHIGH")" >/dev/null
$SUDO install -o root -g root -m 0444 "$W/snapshot-high.bin" "$D/snapshot-high.bin"
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_snapshot        $D/snapshot-high.bin
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_mode            deny
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       0"
restart_server || bad "the server did not restart with the legacy snapshot"
sleep 0.5; load_lines
has_line 'plane snapshot-high.bin: generation 1 verified, arming' && ok "the legacy whisper_edge_snapshot form binds the reputation plane (the synonym, never inert)" || bad "the legacy snapshot was not armed: $(printf '%s\n' "$LOAD" | grep -F plane | head -2 | tr '\n' '|')"
reqw WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LHIGH"
want 403 "a HIGH client in the legacy snapshot's one range, behind the trusted proxy -> 403" "the legacy snapshot did not deny"
await_elog "denied $LHIGH by ctx:1 \"deny if listed >= low\" (program floor:- ctx:" && elog_has "evidence $EVIDENCE" \
    && ok "and the denied line carries the CITABLE EVIDENCE the snapshot holds ($EVIDENCE), read from the view the decision used; the deciding rule is the deny host's own threshold line, not the server's" || bad "the denied line carries no evidence: $($SUDO tail -n +"$FROM" "$ELOG" | grep -F 'denied ' | tail -1 | cut -c1-220)"
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/planes/reputation.bin"

# ---- 17d. the per-range count in log mode: the same traffic as the nginx and Apache gates' row ----------------
# The legacy snapshot again, under mode log at the main level (WhisperDefault inherits it): five requests from the
# listed client, each answered, raise the summary's headline total by exactly five, because a would-deny is counted
# on every server (the core's contract counts after the verdict, on the path that writes the log line).
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_snapshot        $D/snapshot-high.bin
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_mode            log
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       0"
restart_server || bad "the server did not restart with the legacy snapshot under mode log"
lc_total() { summary_total "$D/counters"; }
# BEFORE only once two reads a tick apart agree: every process writes its own counts on its own tick, so a
# read taken while an earlier count is still in flight would make "before + 5" the wrong target
lc_before=$(lc_total); for _ in 1 2 3 4 5; do sleep 11; lc_now=$(lc_total); [ "$lc_now" = "$lc_before" ] && break; lc_before=$lc_now; done
lc_codes=""
for i in 1 2 3 4 5; do lc_codes="$lc_codes$(code -H "X-Forwarded-For: $LHIGH" "$(u $PDEF "/index.html?lc=$i")")"; done
lc_expired=no
await '[ "$(lc_total)" = "$(( ${lc_before:-0} + 5 ))" ]' 60 "the five would-denies counted" || lc_expired=yes   # a ceiling for a hang
lc_after=$(lc_total)
[ "$lc_codes" = "200200200200200" ] && [ "$(( ${lc_after:-0} - ${lc_before:-0} ))" = 5 ] \
    && ok "log-mode count: 5 would-denies from the listed client (each answered 200) raise the summary's total by 5 ($lc_before to $lc_after), the same traffic and number as on nginx and Apache" \
    || bad "log-mode count: 5 requests from the listed client answered $lc_codes, and the summary's total went from \"${lc_before:-none}\" to \"${lc_after:-none}\"$([ "$lc_expired" = yes ] && echo " (the wait reached its 60 s ceiling)")"

# ---- 17e. behind a proxy on the server's own trusted list (127.0.0.1T), no module trust list ---------------------
# The installer's shape for a site behind a proxy on the same box. The floor reads get_client_ip, and for
# this trusted peer the server reports the header's client, so the floor and step 4 judge one address: a listed
# client behind the proxy is denied, the proxy's own request is the hold-harmless loopback, and a
# hold-harmless client behind the proxy is exempt. The client must be outside hold-harmless, so the snapshot
# lists 21.0.0.0/24 at HIGH; 21.0.0.5 is that client, 198.41.0.4 (a.root-servers.net) the hold-harmless one.
python3 "$GEN" "$W/snapshot-rp.bin" 1 0 67 352321536 352321791   # HIGH with the drop flag (0x43)
$SUDO install -o root -g root -m 0444 "$W/snapshot-rp.bin" "$D/snapshot-rp.bin"
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_snapshot        $D/snapshot-rp.bin
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_mode            deny
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       2
accessControl {
    allow                    ALL, 127.0.0.1T
}"
restart_server || bad "the server did not restart with useIpInProxyHeader 2"
sleep 0.5; load_lines
reqw WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 21.0.0.5"
want 403 "realip-only: a listed client (21.0.0.5, HIGH) behind the loopback proxy the server trusts is denied -> 403" "the listed client behind the trusted proxy was allowed"
is "$(field "$LINE" floor)" "21.0.0.5" "and the floor judged the client the server derived (floor=21.0.0.5)" "the floor did not judge the proxied client"
await_elog "denied 21.0.0.5 by " && elog_has "; verdict high,spamhaus-drop; evidence " \
    && ok "and the deny line carries the canonical verdict \"verdict high,spamhaus-drop\", byte for byte the token the nginx and Apache lines print" \
    || bad "the deny line's verdict is not the canonical high,spamhaus-drop: $($SUDO tail -n +"$FROM" "$ELOG" | grep -m1 'denied 21.0.0.5' | cut -c1-200)"
req WhisperDeny "$(u $PDENY /index.html)"
want 200 "realip-only: the proxy's own request (no X-Forwarded-For) is the hold-harmless loopback -> 200" "the proxy's own request was denied"
is "$(field "$LINE" floor)|$(field "$LINE" reason)" "127.0.0.1|hold-harmless" "and it reads floor=127.0.0.1 reason=hold-harmless" "the proxy's own request's line"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 198.41.0.4"
want 200 "realip-only: a hold-harmless client (198.41.0.4) behind the proxy is exempt -> 200" "the hold-harmless client behind the proxy was denied"
is "$(field "$LINE" reason)" "hold-harmless" "and it reads reason=hold-harmless" "the hold-harmless client's line"
# The deny line and the log mode's WOULD DENY line are at error, as on nginx and Apache, so they are seen at
# every logLevel this server takes: ERROR, the strictest an operator sets, shows both (the stock
# httpd_config.conf says DEBUG, which shows everything). The control writes both at warn, and under ERROR
# neither may appear. WhisperDeny denies under its own mode; WhisperDefault takes the server's, log here.
# Each line is rate-limited to one a second per outcome, so a request waits out the previous second.
rp_levels() { # <module object> <seen|unseen>
    install_module "$1"
    ELEVEL=ERROR write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_snapshot        $D/snapshot-rp.bin
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_mode            log
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       2
accessControl {
    allow                    ALL, 127.0.0.1T
}"
    restart_server || { bad "the server did not restart at logLevel ERROR (${1##*/})"; return; }
    sleep 1.1
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 21.0.0.5"
    want 403 "logLevel ERROR (${1##*/}): the listed client behind the trusted proxy is denied -> 403" "the listed client was allowed at logLevel ERROR"
    req WhisperDefault "$(u $PDEF /index.html)" -H "X-Forwarded-For: 21.0.0.5"
    want 200 "logLevel ERROR (${1##*/}): log mode allows the listed client -> 200" "log mode denied the listed client"
    if [ "$2" = seen ]; then
        await_elog "denied 21.0.0.5 by " && elog_has "; verdict high,spamhaus-drop; evidence " \
            && ok "deny line: at logLevel ERROR the deny is written at error, with the canonical verdict high,spamhaus-drop" \
            || bad "deny line: no deny line at logLevel ERROR: $($SUDO tail -n +"$FROM" "$ELOG" | grep -m1 'whisper edge' | cut -c1-200)"
        await_elog "WOULD DENY 21.0.0.5 by " \
            && ok "would-deny line: at logLevel ERROR the log mode's WOULD DENY is written at error too, so log mode is seen there" \
            || bad "would-deny line: no WOULD DENY line at logLevel ERROR: $($SUDO tail -n +"$FROM" "$ELOG" | grep -m1 'WOULD DENY' | cut -c1-200)"
    else
        sleep 2
        if elog_has "denied 21.0.0.5 by " || elog_has "WOULD DENY 21.0.0.5 by "; then
            bad "deny-line control: WE_MOD_TEST_DENY_AT_WARN's lines at warn appeared at logLevel ERROR, so the rows above cannot tell error from warn"
        else
            ok "deny-line control: WE_MOD_TEST_DENY_AT_WARN writes both lines at warn, and at logLevel ERROR neither appears"
        fi
    fi
}
rp_levels "$W/mod_whisper_edge.so" seen
if build_module "$W/ctl-denywarn.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_DENY_AT_WARN"; then
    rp_levels "$W/ctl-denywarn.so" unseen
else
    bad "deny-line control: the WE_MOD_TEST_DENY_AT_WARN build failed"
fi
install_module "$W/mod_whisper_edge.so"
$SUDO rm -f "$D/snapshot-rp.bin"

# ---- 17f. the evidence of an IPv6 listing, cited by the deny line as an IPv4 one is ----------------------
# testdata/interop.snap is the real builder's file: 2001:db8::1 is listed HIGH with the evidence EXAMPLE-6,
# 192.0.2.0 critical with EXAMPLE-DROP-1 (testdata/expected.txt). Both are documentation space, which is
# hold-harmless, so each is sent past a skipped balancer hop (198.19.0.1, two trusted hops), where the walk
# judges it and its exemption does not follow it, as the nginx and Apache gates send theirs; each is then
# denied, and its deny line carries the listing's evidence. The nginx and Apache gates assert
# the same IPv6 listing's evidence with the same literal, read from the same expected.txt, so the three
# servers' lines carry it byte for byte. One deny line a second, so the two wait it out.
EV6=$(awk '$1 == 6 && $2 == "2001:db8::1" { print $4 }' "$ROOT/core/testdata/expected.txt")
EV4=$(awk '$1 == 4 && $2 == "192.0.2.0" { print $4 }' "$ROOT/core/testdata/expected.txt")
$SUDO install -o root -g root -m 0444 "$ROOT/core/testdata/interop.snap" "$D/snapshot-ev6.bin"
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_snapshot        $D/snapshot-ev6.bin
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
    whisper_edge_trusted_hops    2
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       0"
restart_server || bad "the server did not restart with the evidence snapshot"
sleep 1.1; load_lines
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 2001:db8::1, 198.19.0.1"
want 403 "evidence: the IPv6 listing 2001:db8::1 past the skipped hop is denied -> 403" "the IPv6 listing was allowed: $LINE"
if [ -n "$EV6" ] && await_elog "denied 2001:db8::1 by " && grep -qF "; evidence $EV6;" <<<"$($SUDO tail -n +"$FROM" "$ELOG" | grep -F "denied 2001:db8::1 by ")"; then
    ok "evidence: the IPv6 listing's deny line cites its evidence ($EV6), the literal the nginx and Apache gates assert for the same listing"
else
    bad "evidence: the IPv6 listing's deny line: $($SUDO tail -n +"$FROM" "$ELOG" | grep -m1 -F 'denied 2001:db8::1' | cut -c1-200), want evidence ${EV6:-<none in expected.txt>}"
fi
sleep 1.1
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: 192.0.2.0, 198.19.0.1"
want 403 "evidence: the IPv4 listing 192.0.2.0 of the same file is denied -> 403" "the IPv4 listing was allowed: $LINE"
if [ -n "$EV4" ] && await_elog "denied 192.0.2.0 by " && grep -qF "; evidence $EV4;" <<<"$($SUDO tail -n +"$FROM" "$ELOG" | grep -F "denied 192.0.2.0 by ")"; then
    ok "evidence: and the IPv4 listing cites its own ($EV4), so the row reads the file's evidence per family"
else
    bad "evidence: the IPv4 listing's deny line: $($SUDO tail -n +"$FROM" "$ELOG" | grep -m1 -F 'denied 192.0.2.0' | cut -c1-200), want evidence ${EV4:-<none in expected.txt>}"
fi
$SUDO rm -f "$D/snapshot-ev6.bin"

# ---- 18. every accepted deny status on the wire  ---------------------------------------------------
write_main "$(main_block deny)" "useIpInProxyHeader       0"
for c in 400 403 404 406 409 410 413 415 422 428 429 451; do
    policy_vhost "$c"
    restart_server || { bad "the server did not restart for status $c"; continue; }
    R=$(wire -H "X-Forwarded-For: $LHIGH" "$(u $PPOL /index.html)")
    st=$(printf '%s\n' "$R" | head -1); cl=$(printf '%s\n' "$R" | grep -i '^content-length:' | awk '{print $2}'); cc=$(printf '%s\n' "$R" | grep -i '^cache-control:' | sed 's/^[^:]*: //')
    case "$st" in "HTTP/1.1 $c "*) [ "$cl" = 44 ] && [ "$cc" = no-store ] && ok "deny_status $c on the wire: \"$st\", Content-Length 44, Cache-Control no-store" || bad "$c: $st, Content-Length ${cl:-none}, Cache-Control ${cc:-none}" ;;
        *) bad "deny_status $c gave \"$st\"" ;; esac
done
for c in 405 408 444 460 500 503 302 402; do
    policy_vhost "$c"
    restart_server || { bad "the server did not restart for status $c"; continue; }
    load_lines
    RL=$(line_of '"WhisperPolicy": whisper_edge_deny_status #2: ')
    if [ -n "$RL" ] && [ "$(code -H "X-Forwarded-For: $LHIGH" "$(u $PPOL /index.html)")" = 403 ]; then
        ok "deny_status $c is refused ($(printf '%s' "$RL" | sed -E 's/.*#2: //' | cut -c1-72)...) and the host denies with 403"
    else
        bad "deny_status $c: ${RL:-no refusal line}"
    fi
done

# ---- 19. the controls, each a build with one planted defect that must fail its row ---------------------------
policy_vhost 451
install_module "$W/ctl-modeoff.so"; restart_server || bad "the mode-off control did not start"
got=$(code -H "X-Forwarded-For: $LCRIT" "$(u $POFF /index.html)")
if [ "$got" = 200 ]; then ctl 0 "a mode-off early return serves a CRITICAL client (200) where the floor must deny"; else ctl 1 "the mode-off early return (got $got)"; fi
install_module "$W/ctl-nostore.so"; restart_server || bad "the no-store control did not start"
R=$(wire -H "X-Forwarded-For: $LLOW" "$(u $PDENY /index.html)")
if printf '%s\n' "$R" | hit -i '^cache-control: no-store'; then ctl 1 "a build without the header"; else ctl 0 "a build without Cache-Control: no-store fails the no-store assertion"; fi
install_module "$W/ctl-noflush.so"
write_main "$(main_block)" "useIpInProxyHeader       0"; restart_server || bad "the exit-flush control did not start"
if graceful_flush_row; then ctl 1 "the exit flush: a build whose exit does not stop the thread"; else ctl 0 "a build whose exit does not stop the thread loses the counts since the last tick on a graceful restart"; fi
install_module "$W/mod_whisper_edge.so"

# ---- 20. fail open: no data source at all --------------------------------------------------------------------
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_summary         $D/counters
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
    whisper_edge_policy          deny if listed >= high
}" "useIpInProxyHeader       0"
restart_server || bad "the server did not restart without a data source"
sleep 0.5; load_lines
has_line 'no whisper_edge_data and no whisper_edge_snapshot: every rule reads unknown and the module denies nothing until a data source is configured' \
    && ok "F1: no data source: the configuration line says every rule reads unknown and nothing is denied" || bad "F1: no line about the missing data source"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "F1: and a HIGH client on the deny host is served (fail open)" "a request was denied with no plane"
if [ "$(field "$LINE" verdict)" = unknown ] && case "$(field "$LINE" gen)" in reputation:-a*) true ;; *) false ;; esac; then
    ok "F1: verdict=unknown, generations reputation:-a"
else
    bad "F1: $LINE"
fi

# ---- 21. the block install.sh prints, loaded by this server (Z2) ---------------------------------------------
INSTALLER="${LS_GATE_INSTALLER:-$ROOT/install/install.sh}"
IOUT=$("$INSTALLER" --dry-run --dir "$D" --base https://whisper.online/edge 2>&1 || true)
PRINTED=$(printf '%s\n' "$IOUT" | sed -n '/^  # OpenLiteSpeed:/,/^  }/p' | grep -vE '^  #')
if [ -z "$PRINTED" ]; then
    bad "Z2: install.sh --dry-run printed no OpenLiteSpeed block on a host that has OpenLiteSpeed"
else
    write_main "$PRINTED"
    restart_server || true
    sleep 0.5; load_lines
    if elog_has '[Module: mod_whisper_edge v2.0] has been initialized successfully'; then
        ok "Z2: the block install.sh prints loads the module"
    else
        bad "Z2: the printed block does not load the module: $($SUDO tail -n +"$FROM" "$ELOG" | grep -E 'Failed to load module|whisper' | head -2 | tr '\n' '|')"
    fi
    # the printed block names the per-plane directory (whisper_edge_data $D, since the installer moved to per-plane refreshes; it named the
    # legacy snapshot before, which is what this row once awaited), and the reputation plane there is armed
    printf '%s\n' "$PRINTED" | hit -E "^[[:space:]]*whisper_edge_data[[:space:]]+$D\$" \
        && ok "Z2: the printed block names the data directory the installer was given (whisper_edge_data $D)" \
        || bad "Z2: the printed block names no whisper_edge_data $D: $(printf '%s\n' "$PRINTED" | grep -E 'whisper_edge_(data|snapshot)' | head -2 | tr '\n' '|')"
    await "\$SUDO tail -n +\"\$FROM\" \"\$ELOG\" | hit 'plane reputation.bin: generation [0-9]* verified, arming'" 10 \
        && ok "Z2: and the reputation plane in that directory is verified and armed under it" \
        || bad "Z2: the plane was not armed under the printed block: $(printf '%s\n' "$LOAD" | grep -F plane | head -2 | tr '\n' '|')"
    req WhisperDeny "$(u $PDENY /index.html)"
    want 200 "Z2: a request under the printed block -> 200 (no trusted proxy is named, so the loopback peer is judged itself and is hold-harmless)" "the printed block denied"
    is "$(field "$LINE" reason)|$(field "$LINE" action)" "hold-harmless|allow" "Z2: and the access log shows the module judged it: reason=hold-harmless action=allow" "Z2: no decision under the printed block: $LINE"
fi

# ---- 22. T4: the trusted header's names, and the unix listener ----------------------------------------------
# The refusals are parse-time lines, and the second-definition rule keeps two trusted_header lines out of
# one configuration, so each name gets its own load. The acceptance spellings are judged through the
# header each names. Measured: this server does not drop underscore field names, so X_Real_IP
# is accepted here (nginx's underscores_in_headers off is the server that refuses it).
for hdr in Forwarded forwarded FORWARDED 'X Forwarded'; do
    write_main "$(main_block "" "$hdr")" "useIpInProxyHeader       0"
    restart_server || { bad "T4: the server did not restart with whisper_edge_trusted_header $hdr"; continue; }
    sleep 0.5; load_lines
    case "$hdr" in
    'X Forwarded')
        is "$(count_line "a header name is a token (RFC 9110 section 5.1)")" "1" \
            "T4: whisper_edge_trusted_header 'X Forwarded' is refused: a header name is a token and the space is not" \
            "T4: 'X Forwarded' was not refused by the token rule" ;;
    *)
        is "$(count_line "Forwarded uses the RFC 7239 syntax")" "1" \
            "T4: trusted_header $hdr is refused: field names are case-insensitive, and every case of Forwarded names the RFC 7239 syntax this module does not read" \
            "T4: trusted_header $hdr was not refused" ;;
    esac
done
# a refused trust directive refuses the configuration, as nginx and Apache refuse it: the module runs no program,
# so a CRITICAL client the floor would deny is served, no decision is rendered, and one line says why (the last
# load above is 'X Forwarded')
TREFUSED="the configuration is refused and the module runs no program until it is fixed"
no_program() { # no_program <label> -> 0 when the module runs no program: the CRITICAL client served, no action rendered
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LCRIT"
    [ "$CODE" = 200 ] && case "$(field "$LINE" action)" in ""|-) true ;; *) false ;; esac
}
no_program; NP=$?
if [ "$NP" = 0 ] && has_line "$TREFUSED"; then
    ok "T4: a refused trusted_header refuses the configuration: one line says so, and the module runs no program (a CRITICAL client is served, no decision rendered)"
else
    bad "T4: a refused trusted_header: refusal line $(count_line "$TREFUSED"), the CRITICAL client $CODE, action $(field "$LINE" action)"
fi
# the accepted spellings: configured lowercase, sent capitalized, judged through the name the line spells
write_main "$(main_block "" x-forwarded-for)" "useIpInProxyHeader       0"
restart_server || bad "T4: the server did not restart with a lowercase trusted header"
sleep 0.5; load_lines
is "$(count_line "a header name is a token")$(count_line "RFC 7239")" "00" \
    "T4: trusted_header x-forwarded-for passes the same rules as X-Forwarded-For (field names are case-insensitive)" \
    "T4: the lowercase spelling was refused"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LHIGH"
want 403 "T4: and the walk reads the header the line names, configured lowercase and sent capitalized" "the lowercase spelling did not deny the listed client"
# the underscore name: kept by this server's header lookup (measured), refused by nginx's default
write_main "$(main_block "" X_Real_IP)" "useIpInProxyHeader       0"
restart_server || bad "T4: the server did not restart with X_Real_IP"
sleep 0.5; load_lines
is "$(count_line "a header name is a token")$(count_line "RFC 7239")" "00" \
    "T4: X_Real_IP passes: this server keeps underscore field names (measured), unlike nginx with underscores_in_headers off" \
    "T4: X_Real_IP was refused where the measurement shows the name is kept"
req WhisperDeny "$(u $PDENY /index.html)" -H "X_Real_IP: $LHIGH"
want 403 "T4: the judged address equals the client the header names: an X_Real_IP HIGH client is denied" "the X_Real_IP client was not judged"
is "$(field "$LINE" floor)" "$LHIGH" "T4: and the floor is the header's address, so the underscore name reached the lookup whole" "the X_Real_IP request's line: $LINE"
# the unix listener: its peer is a socket, not an address, so trusted_header beside it needs a unix: trust
# entry; the check reads the configured listener, and 1.9.3 binds the address (measured: the stop line
# at shutdown names the socket path with its fd), so the refusal guards a live listener
UDS_LISTENER="listener Uds {
    address                  uds://$W/uds.sock
    secure                   0
    map                      WhisperDefault *
}"
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_data            $D/planes
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_policy_floor    deny if listed >= critical
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
}" "useIpInProxyHeader       0
$UDS_LISTENER"
restart_server || bad "T4: the server did not restart with a unix listener"
sleep 0.5; load_lines
is "$(count_line "a listener is a unix socket")" "1" \
    "T4: a unix listener with trusted_header set and no unix: entry is a configuration error, and the line names both settings and the fix" \
    "T4: the unix-listener configuration error did not print"
no_program; NP=$?
if [ "$NP" = 0 ] && has_line "$TREFUSED"; then
    ok "T4: and the configuration is refused, as nginx and Apache refuse it: the module runs no program (a CRITICAL client is served, no decision rendered)"
else
    bad "T4: the unix-listener refusal: refusal line $(count_line "$TREFUSED"), the CRITICAL client $CODE, action $(field "$LINE" action)"
fi
# the control: adding unix: passes
write_main "module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_data            $D/planes
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_policy_floor    deny if listed >= critical
    whisper_edge_trusted_proxy   127.0.0.1 unix:
    whisper_edge_trusted_header  X-Forwarded-For
}" "useIpInProxyHeader       0
$UDS_LISTENER"
restart_server || bad "T4: the server did not restart with unix: beside the unix listener"
sleep 0.5; load_lines
is "$(count_line "a listener is a unix socket")" "0" \
    "T4: adding unix: passes the check: the unix peer is trusted, so the header line stands" \
    "T4: the unix: entry did not clear the configuration error"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LHIGH"
want 403 "T4: and the header is read again: the listed client through it is denied" "the unix: control did not judge the header client"

# the hops value is read whole, as Apache reads it: a number followed by anything is refused, never its prefix; and the
# proxy list splits on whitespace alone, as Apache's does, so a comma stays inside its entry and the table refuses it.
# Each refuses the configuration
write_main "$(main_block deny | sed 's|^    whisper_edge_trusted_header .*|    whisper_edge_trusted_hops    000000000000002garbage|')" "useIpInProxyHeader       0"
restart_server || bad "T4: the server did not restart with a garbage hops value"
sleep 0.5; load_lines
no_program; NP=$?
if [ "$NP" = 0 ] && has_line 'whisper_edge_trusted_hops #' && has_line "\"000000000000002garbage\" is refused; $TREFUSED"; then
    ok "T4: whisper_edge_trusted_hops 000000000000002garbage is refused whole, never read as 2, and the configuration with it (a CRITICAL client served)"
else
    bad "T4: the garbage hops value: $(line_of 'whisper_edge_trusted_hops' | cut -c1-140); the CRITICAL client $CODE"
fi
write_main "$(main_block deny | sed 's|^    whisper_edge_trusted_proxy .*|    whisper_edge_trusted_proxy   127.0.0.1,10.0.0.1|')" "useIpInProxyHeader       0"
restart_server || bad "T4: the server did not restart with a comma in the trusted proxy"
sleep 0.5; load_lines
no_program; NP=$?
if [ "$NP" = 0 ] && has_line "whisper_edge_trusted_proxy: " && has_line "$TREFUSED"; then
    ok "T4: whisper_edge_trusted_proxy 127.0.0.1,10.0.0.1 is one entry, as Apache reads it, which the table refuses, and the configuration with it: $(line_of 'whisper_edge_trusted_proxy: ' | cut -c1-110)"
else
    bad "T4: the comma in the trusted proxy: $(line_of 'whisper_edge_trusted_proxy' | cut -c1-140); the CRITICAL client $CODE"
fi

# ---- 23. T8: the cache module, measured: a hit still runs HTTP_AUTH, so a cached url is judged --------------
# Measured on this server (cache 1.66): only dynamic responses are stored ("cacheTofile to be
# cancelled for static file type"), and a hit still runs the HTTP_AUTH hook (two hits of ONE disk entry
# carried different floor exports when one of them sent X-Forwarded-For). So the CacheQuickHandler
# warning, which names Apache's mod_cache quick handler, has no LiteSpeed arm: this cache changes only
# the body's source, and the module judges every hit. The floor-listed client below is denied on the
# CACHED url, and the unlisted twin still gets the cached bytes after the deny.
$SUDO mkdir -p "$LSWS/conf/vhosts/WhisperCache" "$W/html/cgi"
$SUDO tee "$W/html/cgi/probe.cgi" >/dev/null <<'CGI'
#!/bin/sh
echo "Content-Type: text/html"
echo ""
echo "cgi-cache-body"
CGI
$SUDO chmod 0755 "$W/html/cgi/probe.cgi"
PCACHE=$((PORT+10))
write_vhost WhisperCache "" "" "context /cgi-bin/ {
    type                    cgi
    location                $W/html/cgi/
    order                   allow,deny
    addDefaultCharset       off
}"
write_main "$(main_block deny)" "useIpInProxyHeader       0
module cache {
    ls_enabled                   1
    enableCache                 1
    ignoreRespCacheCtrl         1
    expireInSeconds             3600
}
virtualHost WhisperCache {
    vhRoot                   $W/
    allowSymbolLink          1
    enableScript             1
    restrained               0
    configFile               conf/vhosts/WhisperCache/vhconf.conf
}
listener Lcache {
    address                  *:$PCACHE
    secure                   0
    map                      WhisperCache *
}"
restart_server || bad "T8: the server did not restart with the cache enabled"
sleep 0.5; load_lines
is "$(printf '%s\n' "$LOAD" | grep -ci cache)" "0" \
    "T8: no cache-naming configuration line is printed: this server's cache serves the body but the module still judges every hit, so the quick-handler warning has no LiteSpeed arm" \
    "T8: a cache warning line was printed: $(printf '%s\n' "$LOAD" | grep -i cache | head -1)"
req WhisperCache "$(u $PCACHE /cgi-bin/probe.cgi)" -H "X-Forwarded-For: $UNL"
want 200 "T8: the unlisted client primes the CGI url (a dynamic response, the only kind this cache stores)" "the prime request failed"
reqw WhisperCache "$(u $PCACHE /cgi-bin/probe.cgi)" -H "X-Forwarded-For: $UNL"
want 200 "T8: the second unlisted request answers 200" "the second request was not served"
printf '%s\n' "$WIRE" | hit -i '^x-litespeed-cache: hit' \
    && ok "T8: and the response says x-litespeed-cache: hit, so the url is cached" \
    || bad "T8: no x-litespeed-cache: hit header: $(printf '%s\n' "$WIRE" | head -1)"
is "$(field "$LINE" action)|$(field "$LINE" floor)" "allow|$UNL" \
    "T8: and the HIT carries the module's own decision (action=allow floor=$UNL): HTTP_AUTH runs on hits, the measurement's discriminator in-gate" \
    "T8: the hit's access-log line carries no module decision: $LINE"
req WhisperCache "$(u $PCACHE /cgi-bin/probe.cgi)" -H "X-Forwarded-For: $LCRIT"
want 403 "T8: a floor-listed client requesting the CACHED url gets the deny (the module judged the hit)" "the listed client was served the cached 200 on a hit"
is "$(field "$LINE" action)|$(field "$LINE" floor)|$(field "$LINE" rule)" "deny|$LCRIT|deny if listed >= critical" \
    "T8: the deny's line: action=deny floor=$LCRIT by the floor's own rule" "the listed client's line: $LINE"
req WhisperCache "$(u $PCACHE /cgi-bin/probe.cgi)" -H "X-Forwarded-For: $UNL"
want 200 "T8: and the unlisted twin still gets the cached bytes after the deny: the deny was the hit's own judgment, not a teardown" "the cache was lost after the deny"

# ---- 24. R1s: per-request syscalls on the handler's thread, counted under ptrace (root) -------------------
# A control build brackets the HTTP_AUTH hook with two marker syscalls (getpgid of a pid above PID_MAX_LIMIT,
# answered ESRCH; strace prints getpgid(2147483646) at entry and getpgid(2147483645) at exit), so a trace of
# the worker's loop thread attributes every call between them to the module by position: counted, never
# differenced, with no allow-list and no baseline run. One worker, strace -p on its loop thread alone (no -f,
# so the module's thread is never attached); the request pinned to one existing static file on a host with
# no index, rewrite or error page; a sequential client that sends Connection: close on an HTTP/1.1 request
# line, reads to EOF and waits for it before the next connect, so windows (the accept4 that returns a fd,
# through its markers, to close(<that fd>)) cannot overlap. H_server, the passes per request, is MEASURED
# on the warm-up and must equal t, the handler-call table's count for this server's one bracketed handler;
# the table is carried here (t = 1: HTTP_AUTH, its export inside its bracket) until the shared file exists.
R1S_W=${R1S_W:-1000}; R1S_N=${R1S_N:-10000}; R1S_T=1
r1s_client() { # r1s_client <port> <path> <count> <close|overlap> <X-Forwarded-For>
    python3 -I - "$@" <<'PY'
import socket, sys
port, path, count, mode, xff = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
def one(keep):
    c = socket.create_connection(("127.0.0.1", port), timeout=20)
    conn = "keep-alive" if keep else "close"
    c.sendall(("GET %s HTTP/1.1\r\nHost: pin\r\nX-Forwarded-For: %s\r\nConnection: %s\r\n\r\n" % (path, xff, conn)).encode())
    buf = b""
    if keep:
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d: break
            buf += d
        head, _, body = buf.partition(b"\r\n\r\n")
        need = 0
        for ln in head.split(b"\r\n"):
            if ln.lower().startswith(b"content-length:"): need = int(ln.split(b":")[1])
        while len(body) < need:
            d = c.recv(65536)
            if not d: break
            body += d
        return c
    while True:
        d = c.recv(65536)
        if not d: break
        buf += d
    c.close()
    return None
if mode == "close":
    for _ in range(count):
        one(False)
else:
    # the interleave control: connection k + 1 opened and served before connection k's FIN, ten overlapping pairs
    for _ in range(count):
        a = one(True); b = one(True)
        a.close(); b.close()
print("sent %d %s" % (count * (2 if mode != "close" else 1), mode))
PY
}
r1s_parse() { # r1s_parse <trace> <W> -> key=value lines; windows: accept4 returning a fd, to close(<fd>)
    python3 -I - "$@" <<'PY'
import re, sys
trace, W = sys.argv[1], int(sys.argv[2])
ENTRY, EXIT = "getpgid(2147483646)", "getpgid(2147483645)"
call = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|0x[0-9a-f]+|\?)(.*)$")
resumed = re.compile(r"^<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|0x[0-9a-f]+|\?)(.*)$")
windows = []          # [entries, exits, between, getpid_in] per closed window, in order
open_w = {}           # fd -> window being filled
cur = None            # the most recently opened window
interleave = 0
in_bracket = False
first_entry = last_exit = None
sigs_all = []         # (lineno, name)
lookalike = bare_ppid = 0
exited = False
unfinished = None
for ln, line in enumerate(open(trace, errors="replace"), 1):
    line = line.rstrip("\n")
    if line.startswith("--- SIG"):
        sigs_all.append((ln, line.split()[1])); continue
    if line.startswith("+++ exited"):
        exited = True; continue
    m = call.match(line); name = None
    if m:
        name, args, ret = m.group(1), m.group(2), m.group(3)
    else:
        m = resumed.match(line)
        if m and unfinished is not None:
            name, args, ret = unfinished[0], unfinished[1] + m.group(2), m.group(3)
            unfinished = None
        elif "<unfinished ...>" in line:
            mm = re.match(r"^(\w+)\((.*)<unfinished \.\.\.>$", line)
            if mm: unfinished = (mm.group(1), mm.group(2))
            continue
        else:
            continue
    text = "%s(%s)" % (name, args)
    if text == ENTRY or text == EXIT:
        lookalike += 1
    if name == "getppid":
        bare_ppid += 1
    if name == "accept4" and not ret.startswith("-") and ret != "?":
        fd = int(ret, 0)
        if open_w: interleave += 1
        cur = [0, 0, 0, 0]; open_w[fd] = cur
        continue
    if name == "close" and ret == "0":
        try: fd = int(args.split(",")[0])
        except ValueError: fd = -1
        if fd in open_w:
            windows.append(open_w.pop(fd))
            if not open_w: cur = None
        continue
    if text == ENTRY:
        if cur is not None: cur[0] += 1
        in_bracket = True
        if first_entry is None: first_entry = ln
        continue
    if text == EXIT:
        if cur is not None: cur[1] += 1
        in_bracket = False; last_exit = ln
        continue
    if in_bracket:
        if cur is not None:
            cur[2] += 1
            if name == "getpid": cur[3] += 1
warm = windows[:W]; run = windows[W:]
counts = sorted(set(w[0] for w in warm))
hs = str(counts[0]) if len(counts) == 1 and warm else "unstable:" + ",".join(str(c) for c in counts)
sigs_in = [n for (l, n) in sigs_all if first_entry is not None and last_exit is not None and first_entry < l < last_exit]
print("windows=%d" % len(windows))
print("warm=%d" % len(warm))
print("run=%d" % len(run))
print("interleave=%d" % interleave)
print("hserver=%s" % hs)
print("entries_run=%d" % sum(w[0] for w in run))
print("exits_run=%d" % sum(w[1] for w in run))
print("between_run=%d" % sum(w[2] for w in run))
print("between_all=%d" % sum(w[2] for w in windows))
print("getpid_in=%d" % sum(w[3] for w in windows))
print("pairs=%d" % sum(w[1] for w in windows))
print("lookalike=%d" % lookalike)
print("getppid_bare=%d" % bare_ppid)
print("signals=%s" % (",".join(sigs_in) if sigs_in else "none"))
print("exited=%d" % (1 if exited else 0))
print("open_left=%d" % len(open_w))
PY
}
r1s_read() { # r1s_read <trace> <W>: the parse into R_<key> variables
    local k v
    while IFS='=' read -r k v; do
        case "$k" in [a-z_]*) eval "R_$k=\$v" ;; esac
    done < <(r1s_parse "$1" "$2")
}
r1s_trace_start() { # r1s_trace_start <tid> <log> -> TRACE_PID (the strace), attached
    $SUDO rm -f "$2"
    $SUDO strace -p "$1" -e trace=all -o "$2" >"$W/r1s-strace.err" 2>&1 &
    TRACE_SUDO=$!
    await "[ \"\$(awk '/^TracerPid:/ {print \$2}' /proc/$1/status 2>/dev/null)\" != 0 ]" 10
}
r1s_trace_stop() { # detach: SIGINT to the strace process, then wait for it
    local sp
    sp=$(pgrep -f "^strace -p $WPID " | head -1)
    [ -n "$sp" ] && $SUDO kill -INT "$sp" 2>/dev/null
    await "! kill -0 $TRACE_SUDO 2>/dev/null" 15 || true
    wait "$TRACE_SUDO" 2>/dev/null || true
}
build_module "$W/ctl-markers.so" "-DWE_MOD_CONTROL_BUILD -DWE_TEST_MARKERS" || bad "R1s: the markers build failed"
build_module "$W/ctl-markers-plant.so" "-DWE_MOD_CONTROL_BUILD -DWE_TEST_MARKERS -DWE_MOD_PLANT_CALL" || bad "R1s: the markers-and-planted-call build failed"
if build_module "$W/ctl-markers-refused.so" "-DWE_TEST_MARKERS" >/dev/null 2>&1; then
    bad "R1s: WE_TEST_MARKERS built outside a control build"
else
    ok "R1s: WE_TEST_MARKERS is refused outside a control build (WE_MOD_CONTROL_BUILD)"
fi
if ! command -v strace >/dev/null 2>&1; then
    bad "R1s: strace is not installed; the row fails by cause, never reads a zero"
else
# the pinned host: an existing static file, no index block, no rewrite, no error page, the exports in its log
PPIN=$((PORT+11))
$SUDO mkdir -p "$LSWS/conf/vhosts/WhisperPin"
$SUDO tee "$LSWS/conf/vhosts/WhisperPin/vhconf.conf" >/dev/null <<VH
docRoot                  \$VH_ROOT/html/
enableGzip               0

accessLog \$SERVER_ROOT/logs/whisper-gate.WhisperPin.log {
    useServer            0
    logFormat            "$LOGFMT"
}

context / {
    location             \$DOC_ROOT/
    allowBrowse          1
}
VH
PIN_HOST="virtualHost WhisperPin {
    vhRoot                   $W/
    allowSymbolLink          1
    enableScript             0
    restrained               0
    configFile               conf/vhosts/WhisperPin/vhconf.conf
}
listener Lpin {
    address                  *:$PPIN
    secure                   0
    map                      WhisperPin *
}"
r1s_topology() { # install <module>, one worker, pinned host; sets WPID to the one worker's pid (its loop tid)
    install_module "$1"
    WORKERS=1 write_main "$(main_block)" "useIpInProxyHeader       0
$PIN_HOST"
    restart_server || { bad "R1s: the server did not start with one worker"; return 1; }
    await "[ \"\$(workers | wc -w)\" = 1 ]" 10
    WPID=$(workers | awk '{print $1}')
    [ -n "$WPID" ] && [ "$(workers | wc -w)" = 1 ] || { bad "R1s: topology: $(workers | wc -w) worker(s), wanted one"; return 1; }
    c=$(code "$(u $PPIN /pin.html)")
    [ "$c" = 200 ] || { bad "R1s: the pinned file does not serve 200 on the pinned host (got $c)"; return 1; }
    return 0
}
if r1s_topology "$W/ctl-markers.so"; then
    ok "R1s: topology: one worker (pid $WPID, $(ls /proc/$WPID/task | wc -l) threads: the loop and the module's); the loop tid $WPID alone is traced"
    r1s_trace_start "$WPID" "$W/r1s.trace" || bad "R1s: strace did not attach to $WPID within 10 s: $(cat "$W/r1s-strace.err")"
    t0=$(now_ms)
    r1s_client $PPIN /pin.html "$R1S_W" close "$UNL" >/dev/null
    r1s_client $PPIN /pin.html "$R1S_N" close "$UNL" >/dev/null
    t1=$(now_ms)
    WPID2=$(workers | awk '{print $1}')
    r1s_trace_stop
    echo "    parse: a window opens at accept4(...) = <fd> (a non-negative fd; EAGAIN is not a window) and closes at close(<fd>) = 0; entry getpgid(2147483646), exit getpgid(2147483645); every other call between an entry and its exit counts"
    echo "    expected: $R1S_N x t = $((R1S_N * R1S_T)) entry markers in the run, t = $R1S_T from the LiteSpeed row (HTTP_AUTH, the one bracketed handler; the context count 1 is printed, never the assertion); W = $R1S_W, N = $R1S_N, $((t1 - t0)) ms for W + N requests under ptrace"
    r1s_read "$W/r1s.trace" "$R1S_W"
    [ "$WPID2" = "$WPID" ] && [ "${R_exited:-1}" = 0 ] && [ "${R_windows:-0}" = $((R1S_W + R1S_N)) ] \
        && ok "R1s: topology held: the traced pid $WPID is unchanged, did not exit, and the trace holds exactly W + N = ${R_windows} windows" \
        || bad "R1s: topology: pid $WPID -> $WPID2, exited=${R_exited:-?}, windows=${R_windows:-?} (wanted $((R1S_W + R1S_N))), open_left=${R_open_left:-?}"
    echo "    windows interleave: ${R_interleave:-?}"
    case "${R_hserver:-?}" in
        unstable:*) bad "R1s: NOT PROVEN by cause: H_server ${R_hserver} across the $R1S_W warm-up windows" ;;
        "$R1S_T") ok "R1s: H_server measured $R_hserver on every one of the $R1S_W warm-up windows, equal to the table's t = $R1S_T" ;;
        *) if [ "${R_hserver:-0}" -lt "$R1S_T" ] 2>/dev/null; then bad "R1s: handler missing its bracket: measured ${R_hserver}, table $R1S_T"; else bad "R1s: table incomplete: measured ${R_hserver}, table $R1S_T"; fi ;;
    esac
    if [ "${R_interleave:-1}" = 0 ]; then
        is "${R_entries_run:-?}|${R_exits_run:-?}" "$((R1S_N * R1S_T))|$((R1S_N * R1S_T))" \
            "R1s: the run holds exactly N x t = $((R1S_N * R1S_T)) entry markers and as many exits, each inside its own window" \
            "R1s: the run's markers (entries|exits)"
        is "${R_between_run:-?}" "0" \
            "R1s: exactly 0 syscalls between any entry marker and its exit marker over the $R1S_N requests (and ${R_between_all:-?} over W + N)" \
            "R1s: syscalls inside the brackets"
    else
        bad "R1s: NOT PROVEN by cause: windows interleave: ${R_interleave} (a window overlapped the next accept4 or lacked its close)"
    fi
    if [ "${R_signals:-x}" = none ]; then
        ok "R1s: the quiet window holds no signal line between the first entry marker and the last exit marker"
    else
        bad "R1s: NOT PROVEN: a signal in the quiet window (${R_signals}); the row reruns once, never passes or fails on it"
    fi
    # the listed-client stream, printed, not gated: the rate-limited log writes between the markers
    r1s_trace_start "$WPID" "$W/r1s-listed.trace" >/dev/null 2>&1 || true
    r1s_client $PPIN /pin.html 200 close "$LHIGH" >/dev/null
    r1s_trace_stop
    r1s_read "$W/r1s-listed.trace" 0
    echo "    listed client under mode log, 200 requests, printed not gated: ${R_between_all:-?} syscalls inside the brackets over ${R_windows:-?} windows (the rate-limited would-deny log line)"
    # the zero-request trace: marker-valued calls (expected 0) and the server's own bare getppid, printed
    r1s_trace_start "$WPID" "$W/r1s-idle.trace" >/dev/null 2>&1 || true
    sleep 30
    r1s_trace_stop
    r1s_read "$W/r1s-idle.trace" 0
    echo "    30 s with no request on the traced tid: ${R_lookalike:-?} marker-valued call(s) (expected 0), ${R_getppid_bare:-?} bare getppid (the worker loop's once-a-second parent check; never a marker)"
    is "${R_lookalike:-?}" "0" "R1s: no marker-valued call outside a bracket in the idle trace" "R1s: marker look-alike in the idle trace"
    # the interleave control: keep-alive pairs, connection k + 1 served before k's FIN; the parse must print a
    # count of at least 1 and come out NOT PROVEN, never a pass
    r1s_trace_start "$WPID" "$W/r1s-overlap.trace" >/dev/null 2>&1 || true
    r1s_client $PPIN /pin.html 10 overlap "$UNL" >/dev/null
    r1s_trace_stop
    r1s_read "$W/r1s-overlap.trace" 0
    echo "    windows interleave: ${R_interleave:-?} (the planted overlap, ten keep-alive pairs)"
    if [ "${R_interleave:-0}" -ge 1 ]; then ctl 0 "ten overlapping keep-alive pairs read windows interleave: ${R_interleave}, NOT PROVEN by cause, never a pass"; else ctl 1 "control blind: interleave (0 overlaps read from ten overlapping pairs)"; fi
fi
# the planted-call control: getpid() inside the decision must be read exactly N x H_server times inside the brackets
if r1s_topology "$W/ctl-markers-plant.so"; then
    r1s_trace_start "$WPID" "$W/r1s-plant.trace" >/dev/null 2>&1 || true
    r1s_client $PPIN /pin.html 1000 close "$UNL" >/dev/null
    r1s_trace_stop
    r1s_read "$W/r1s-plant.trace" 0
    if [ "${R_getpid_in:-0}" = "$((1000 * R1S_T))" ]; then
        ctl 0 "a getpid() planted in the decision is read exactly 1000 x H_server = ${R_getpid_in} times inside the brackets (${R_between_all:-?} calls inside them in all)"
    else
        ctl 1 "control blind: ${R_getpid_in:-?} planted getpid inside the brackets, wanted $((1000 * R1S_T))"
    fi
fi
# the production module under the same trace: no marker-valued call (a look-alike fails by cause), and the parse
# reads zero pairs, which it refuses as no marker, never passes
if r1s_topology "$W/mod_whisper_edge.so"; then
    r1s_trace_start "$WPID" "$W/r1s-prod.trace" >/dev/null 2>&1 || true
    r1s_client $PPIN /pin.html 200 close "$UNL" >/dev/null
    r1s_trace_stop
    r1s_read "$W/r1s-prod.trace" 0
    is "${R_lookalike:-?}" "0" "R1s: the production module makes no marker-valued call over 200 traced requests (${R_windows:-?} windows)" "R1s: marker look-alike in the production build"
    if [ "${R_pairs:-1}" = 0 ]; then ctl 0 "a build without the markers reads zero pairs and is refused as no marker (never a pass)"; else ctl 1 "the production build read ${R_pairs} marker pairs"; fi
fi
fi


# ---- 25. the policy corpus, rendered as this server's configuration: every refusal, every accepted program -------
# Every refusal in core/testdata/policy/refuse is rendered into a virtual host (the corpus context http/server:a is
# one vhost; its http lines are the server level), loaded for real, and the module's refusal line must carry the
# vhost and the directive's ordinal and then, byte for byte, the .expect fields: rule, line, column, token and
# message. The 46 refusals with no server-level line share one configuration (one vhost each); the three with one
# load alone. The 20 accepted programs load the same way with no refusal and a per-context line counting their
# rules (the acceptance half; the location-level line LiteSpeed cannot express is reported, not rendered). The
# control: the length and alphabet refusals with the offending byte removed load with no refusal.
corpus_render() { # corpus_render <corpus .policy> <vhost base name> <out dir> <server-level lines already in the block> [strip]
    python3 -I - "$@" <<'PY'
import os, sys
src, base, out, base_n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
strip = len(sys.argv) > 5 and sys.argv[5] == "strip"
as_vhost = len(sys.argv) > 6 and sys.argv[6] == "vhost"      # the http context rendered as the vhost <base>v
KEY = {"policy": "whisper_edge_policy", "set": "whisper_edge_set", "floor": "whisper_edge_policy_floor",
       "threshold": "whisper_edge_threshold", "mode": "whisper_edge_mode", "allow_inferred": "whisper_edge_allow_inferred"}
exp = {}
ep = src[:-len(".policy")] + ".expect"
if os.path.exists(ep):
    for ln in open(ep, encoding="utf-8", errors="surrogateescape").read().split("\n"):
        if "\t" in ln:
            k, v = ln.split("\t", 1); exp[k] = v
blocks = {}          # context -> [(kind, text)]
order = []
na = []
has_nul = False
# a record is <kind> SP <context> SP <argument> 0x1E 0x0A; the argument may span lines
for raw in open(src, "rb").read().split(b"\x1e\n"):
    if not raw.strip(): continue
    parts = raw.split(b" ", 2)
    if b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        has_nul = True     # a NUL, CR or LF in the argument: no plain-conf parameter carries one (measured: cut or dropped)
    kind, ctx = parts[0].decode(), parts[1].decode()
    text = parts[2] if len(parts) > 2 else b""
    if "/location:" in ctx:
        na.append(ctx); continue
    if ctx not in blocks: blocks[ctx] = []; order.append(ctx)
    blocks[ctx].append((kind, text))
def vhost_of(ctx):
    if ctx == "http": return base + "v" if as_vhost else None
    name = ctx.split(":", 1)[1]
    return base if name == "a" else base + name
if strip and exp:
    # the control: the offending byte removed; for the length layer the directive's last byte
    ctx = exp["context"]; kind = exp["kind"]; n = int(exp["rule"]); seen = 0
    for i, (k, t) in enumerate(blocks.get(ctx, [])):
        if k != kind: continue
        seen += 1
        if seen != n: continue
        if exp["layer"] == "length":
            t = t[:-2] + t[-1:] if t.endswith(b"}") else t[:-1]      # one byte fewer, the closing brace kept
        else:
            # the offending character whole (its lead byte and every UTF-8 continuation byte after it) becomes
            # one space, so the words on either side of it do not glue
            lines = t.split(b"\n"); li = int(exp["line"]) - 1; ci = int(exp["col"]) - 1
            e = ci + 1
            while e < len(lines[li]) and 0x80 <= lines[li][e] <= 0xBF: e += 1
            lines[li] = lines[li][:ci] + b" " + lines[li][e:]
            t = b"\n".join(lines)
        blocks[ctx][i] = (k, t)
os.makedirs(out, exist_ok=True)
for ctx in order:
    vh = vhost_of(ctx)
    fn = "server.conf" if vh is None else "vhost-%s.conf" % vh
    with open(os.path.join(out, fn), "wb") as f:
        for k, t in blocks[ctx]:
            f.write(("    %-28s " % KEY[k]).encode() + t + b"\n")
    with open(os.path.join(out, "rules-%s" % (vh or "server")), "w") as f:
        f.write("%d\n" % sum(1 for k, _ in blocks[ctx] if k == "policy"))
with open(os.path.join(out, "vhosts"), "w") as f:
    f.write(" ".join(v for v in (vhost_of(c) for c in order) if v) + "\n")
with open(os.path.join(out, "na"), "w") as f:
    f.write("\n".join(na) + ("\n" if na else ""))
with open(os.path.join(out, "nul"), "w") as f:
    f.write("1\n" if has_nul else "")
if exp and not strip:
    ctx = exp["context"]; kind = exp["kind"]; n = int(exp["rule"]); ordinal = 0; seen = 0
    for i, (k, t) in enumerate(blocks.get(ctx, [])):
        if k == kind:
            seen += 1
            if seen == n: ordinal = i + 1; break
    if ctx == "http" and not as_vhost: ordinal += base_n
    where = "server" if ctx == "http" and not as_vhost else '"%s"' % vhost_of(ctx)
    key = "whisper_edge_policy_floor" if ctx == "http" and kind == "floor" and not as_vhost else kind
    # the located prefix, byte for byte, then the message: the fragment the corpus names, which the module's
    # fuller text (what, then the fix) contains, as the core's own test reads the same field
    frag = 'policy refused: %s: %s #%d: rule %s, line %s, column %s: near "%s": ' % (
        where, key, ordinal, exp["rule"], exp["line"], exp["col"], exp["token"])
    with open(os.path.join(out, "expect"), "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(frag + "\t" + exp["message"] + "\n")
PY
}
CORPUS="$ROOT/core/testdata/policy"
CB="$W/corpus"; mkdir -p "$CB"
# the server level these configurations share: no policy or set line, so a vhost's rule numbers are its own
corpus_main() { # corpus_main [extra server-level module lines file]
    local extra=""
    [ -n "${1:-}" ] && [ -f "$1" ] && extra=$(cat "$1")
    cat <<BLOCK
module mod_whisper_edge {
    ls_enabled                   1
    whisper_edge_data            $D/planes
    whisper_edge_summary         $D/counters
    whisper_edge_refresh         10
    whisper_edge_trusted_proxy   127.0.0.1
    whisper_edge_trusted_header  X-Forwarded-For
$extra
}
BLOCK
}
CORPUS_BASE_N=5           # the whisper_edge_ lines of corpus_main before a corpus file's own server-level lines
mod_server_line() { $SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | grep -a 'preParseModuleParam' | head -1 | sed 's/^.*\] //'; }
# this server's own cap on a module block (measured): three hosts whose blocks hold 299, 300 and 301 module
# parameters beside ls_enabled; the one past the cap must vanish whole, with the server's line and no module line
cap_block() { local n=$1; local i=1 f="$CB/cap$n.conf"; : > "$f"; while [ $i -le "$n" ]; do printf '    whisper_edge_set             @k%d KP\n' $i >> "$f"; i=$((i + 1)); done; printf '%s\n' "$f"; }
corpus_vhost() { # corpus_vhost <name> <module lines file>: a host with no listener, the block alone
    $SUDO mkdir -p "$LSWS/conf/vhosts/$1"
    $SUDO tee "$LSWS/conf/vhosts/$1/vhconf.conf" >/dev/null <<VH
docRoot                  \$VH_ROOT/html/
module mod_whisper_edge {
    ls_enabled             1
$(cat "$2")
}
VH
    printf 'virtualHost %s {\n    vhRoot                   %s/\n    allowSymbolLink          1\n    enableScript             0\n    restrained               0\n    configFile               conf/vhosts/%s/vhconf.conf\n}\n' "$1" "$W" "$1"
}
# configuration 1: every refusal with no server-level line, every accepted program with none, and the control twins
HOSTS=""; EXPECTS="$CB/expects"; : > "$EXPECTS"; ACCEPTS="$CB/accepts"; : > "$ACCEPTS"; TWINS="$CB/twins"; : > "$TWINS"
SOLO=""
for f in "$CORPUS"/refuse/*.policy; do
    b=$(basename "$f" .policy); nn=${b%%-*}
    if grep -qE '^(set|policy|floor|threshold|mode) http( |$)' "$f"; then SOLO="$SOLO $b"; continue; fi
    corpus_render "$f" "r$nn" "$CB/r$nn" "$CORPUS_BASE_N"
    for vh in $(cat "$CB/r$nn/vhosts"); do HOSTS="$HOSTS
$(corpus_vhost "$vh" "$CB/r$nn/vhost-$vh.conf")"; done
    printf '%s\t%s\n' "$b" "$(cat "$CB/r$nn/expect")" >> "$EXPECTS"
    # the control twin, where the layer names the byte: the length and alphabet layers
    case "$(sed -n 's/^layer\t//p' "${f%.policy}.expect")" in
        length|alphabet)
            [ -s "$CB/r$nn/nul" ] && continue
            # two records have no twin: 02 carries two defects by design (the length is checked before the
            # alphabet), and 06's character sits inside a country literal, so neither its removal nor a space
            # leaves a program
            case "$nn" in 02|06) echo "    n/a: $b: no byte-removed twin (two defects by design, or the character is part of a literal)"; continue ;; esac
            corpus_render "$f" "c$nn" "$CB/c$nn" "$CORPUS_BASE_N" strip
            for vh in $(cat "$CB/c$nn/vhosts"); do HOSTS="$HOSTS
$(corpus_vhost "$vh" "$CB/c$nn/vhost-$vh.conf")"; done
            printf '%s\tc%s\n' "$b" "$nn" >> "$TWINS" ;;
    esac
done
ASOLO=""
for f in "$CORPUS"/accept/*.policy; do
    b=$(basename "$f" .policy); nn=${b%%-*}
    if grep -qE '^(set|policy|floor|threshold|mode) http( |$)' "$f"; then ASOLO="$ASOLO $b"; continue; fi
    corpus_render "$f" "a$nn" "$CB/a$nn" "$CORPUS_BASE_N"
    for vh in $(cat "$CB/a$nn/vhosts"); do
        HOSTS="$HOSTS
$(corpus_vhost "$vh" "$CB/a$nn/vhost-$vh.conf")"
        printf '%s\t%s\t%s\n' "$b" "$vh" "$(cat "$CB/a$nn/rules-$vh")" >> "$ACCEPTS"
    done
    [ -s "$CB/a$nn/na" ] && echo "    n/a: $b: a location-level line ($(tr '\n' ' ' < "$CB/a$nn/na")) has no LiteSpeed form (per-vhost policy); not rendered"
done
for n in 299 300 301; do HOSTS="$HOSTS
$(corpus_vhost "cap$n" "$(cap_block $n)")"; done
install_module "$W/mod_whisper_edge.so"
write_main "$(corpus_main)" "useIpInProxyHeader       0
$HOSTS"
restart_server || bad "corpus: the server did not start with the corpus hosts"
sleep 1; load_lines
while IFS=$'\t' read -r b frag; do
    if [ -s "$CB/r${b%%-*}/nul" ]; then
        # the argument carries a NUL byte or spans lines: what reaches the module is this server's
        # configuration parser's business, so the outcome is measured and printed, never asserted either way
        echo "    n/a: $b: the argument carries a NUL byte or spans lines, which a parameter of this server's configuration cannot carry; the module received: $(printf '%s\n' "$LOAD" | grep -F "\"r${b%%-*}\"" | head -1 | cut -c1-160)"
        continue
    fi
    pre=${frag%%	*}; msg=${frag#*	}
    got=$(line_of "$pre")
    if [ -n "$got" ] && [ "${got#*"$pre"}" != "$got" ] && printf '%s' "${got#*"$pre"}" | hit -F -- "$msg"; then
        ok "corpus: $b: refused as the corpus expects: ${pre#policy refused: }... $msg"
    else
        bad "corpus: $b: wanted \"$pre\" then \"$msg\"; the module said: $(printf '%s\n' "$LOAD" | grep -F "\"r${b%%-*}\"" | head -1)"
    fi
done < "$EXPECTS"
nacc=0; nbad=""
while IFS=$'\t' read -r b vh rules; do
    if has_line "policy refused: \"$vh\":"; then nbad="$nbad $b($vh)"; continue; fi
    if [ "$(line_of "vhost \"$vh\": $rules rules")" != "" ] || { [ "$rules" = 0 ] && [ "$(line_of "vhost \"$vh\"")" != "" ]; }; then nacc=$((nacc + 1)); else nbad="$nbad $b($vh:no-line-for-$rules-rules)"; fi
done < "$ACCEPTS"
[ -z "$nbad" ] && ok "corpus accepted: the $nacc accepted corpus contexts without a server-level line load with no refusal, each with its per-context line counting its rules" || bad "corpus accepted: accepted corpus contexts refused or miscounted:$nbad"
# the cap (measured): 299 and 300 module parameters load; at 301 the server gives the block's parameters up with
# its own ERROR line and still hands the host to the module, which sees it with no lines of its own, so the host
# runs the server's program and the operator's only word is the server's line
for n in 299 300; do
    [ -n "$(line_of "vhost \"cap$n\"")" ] && ok "corpus: a module block of $n parameters loads: $(line_of "vhost \"cap$n\"" | cut -c1-70)" || bad "corpus: the block of $n parameters got no module line: $(mod_server_line)"
done
if [ -n "$(mod_server_line)" ] && line_of 'vhost "cap301"' | hit -F 'no lines of its own'; then
    ok "corpus: a module block of 301 parameters: this server gives its parameters up with its own line ($(mod_server_line | cut -c1-90)) and the module sees the host with no lines of its own"
else
    bad "corpus: the block of 301 parameters: module line \"$(line_of 'vhost "cap301"' | cut -c1-60)\", server line \"$(mod_server_line)\""
fi
ntw=0; tbad=""
while IFS=$'\t' read -r b vh; do
    if has_line "policy refused: \"$vh\":"; then tbad="$tbad $b($(line_of "policy refused: \"$vh\":" | cut -c1-100))"; else ntw=$((ntw + 1)); fi
done < "$TWINS"
[ -z "$tbad" ] && ctl 0 "the $ntw length and alphabet refusals with the offending byte removed load with no refusal" || ctl 1 "byte-removed twins still refused:$tbad"
# the refusals and accepted programs with a server-level line: one configuration each
for b in $SOLO; do
    nn=${b%%-*}; f="$CORPUS/refuse/$b.policy"
    corpus_render "$f" "r$nn" "$CB/r$nn" "$CORPUS_BASE_N"
    HOSTS=""; for vh in $(cat "$CB/r$nn/vhosts"); do HOSTS="$HOSTS
$(corpus_vhost "$vh" "$CB/r$nn/vhost-$vh.conf")"; done
    write_main "$(corpus_main "$CB/r$nn/server.conf")" "useIpInProxyHeader       0
$HOSTS"
    restart_server || { bad "corpus: $b: the server did not start"; continue; }
    sleep 0.5; load_lines
    frag=$(cat "$CB/r$nn/expect"); pre=${frag%%	*}; msg=${frag#*	}
    got=$(line_of "$pre")
    if [ -n "$got" ] && printf '%s' "${got#*"$pre"}" | hit -F -- "$msg"; then
        ok "corpus: $b (a server-level line, its own configuration): ${pre#policy refused: }... $msg"
    elif [ "$(wc -l < "$CB/r$nn/server.conf")" -gt 300 ]; then
        # a module block of more than 300 parameters is given up whole by this server (its own ERROR line,
        # below), so the record has no LiteSpeed form in one block; what happened is printed, not asserted
        echo "    n/a: $b: $(wc -l < "$CB/r$nn/server.conf") server-level lines in one module block; the server said: $(mod_server_line | cut -c1-120); the module's server line: $(line_of 'server:' | cut -c1-80)"
    else
        bad "corpus: $b: wanted \"$pre\" then \"$msg\"; the module said: $(printf '%s\n' "$LOAD" | grep -E "policy refused: (server|\"r$nn)" | head -1)"
    fi
done
for b in $ASOLO; do
    nn=${b%%-*}; f="$CORPUS/accept/$b.policy"
    corpus_render "$f" "a$nn" "$CB/a$nn" "$CORPUS_BASE_N"
    HOSTS=""; for vh in $(cat "$CB/a$nn/vhosts"); do HOSTS="$HOSTS
$(corpus_vhost "$vh" "$CB/a$nn/vhost-$vh.conf")"; done
    write_main "$(corpus_main "$CB/a$nn/server.conf")" "useIpInProxyHeader       0
$HOSTS"
    restart_server || { bad "corpus accepted: $b: the server did not start"; continue; }
    sleep 0.5; load_lines
    if grep -qE "policy refused: (server|\"a$nn)" <<<"$LOAD"; then
        bad "corpus accepted: $b: refused: $(printf '%s\n' "$LOAD" | grep -E "policy refused: (server|\"a$nn)" | head -1)"
    else
        ok "corpus accepted: $b (a server-level line, its own configuration): accepted; its hosts' lines: $(printf '%s\n' "$LOAD" | grep -cE "^vhost \"a$nn") host line(s), the server level $(line_of 'server:' | cut -c1-60)"
    fi
    [ -s "$CB/a$nn/na" ] && echo "    n/a: $b: a location-level line has no LiteSpeed form; not rendered"
done


# ---- 26. the counter cap: 65,536 counted rule slots across 256 hosts; the crossing host is refused -------------
# A module block holds at most 300 parameters on this server and a context at most 256 rules in the core, so the
# cap is reached only across at least 256 virtual hosts. Slots are 8 pre-stage, the floor's rules and every
# context's own rules, so with no server-level rule the standard hosts' R0 rules (read from the configuration-wide
# line) plus 255 hosts of 256 rules and a filler host of 248 - R0 rules make exactly 65,536: accepted, the stride
# and the per-worker ceiling printed. A 257th host with one rule crosses and is refused with the core's line naming
# the five largest contexts, every other context standing; one slot under the cap is accepted. Startup time is
# printed, not gated.
install_module "$W/mod_whisper_edge.so"
write_main "$(corpus_main)" "useIpInProxyHeader       0"
restart_server || bad "cap: the server did not start for the baseline"
sleep 0.5; load_lines
R0=$(line_of 'distinct programs' | sed -nE 's/.*counters [0-9]+ contexts, ([0-9]+) rules.*/\1/p')
C0=$(line_of 'distinct programs' | sed -nE 's/.*counters ([0-9]+) contexts, [0-9]+ rules.*/\1/p')
if [ -n "$R0" ] && [ "$R0" -le 240 ]; then
    ok "cap: the baseline counts $R0 rules in the standard hosts and $(line_of 'distinct programs' | sed -nE 's/.* ([0-9]+) bytes per shard.*/\1/p') bytes per shard (8 pre-stage slots, no floor)"
else
    bad "cap: no usable rule count from the configuration-wide line: $(line_of 'distinct programs' | cut -c1-140)"; R0=0
fi
FILL=$((248 - R0))
d16_hosts() { # d16_hosts <nhosts> <rules in host 256> <rules in host 257> -> the vhconf files under $W/d16, the virtualHost blocks on stdout
    local n=$1 r256=$2 r257=$3 h r rules
    rm -rf "$W/d16"; mkdir -p "$W/d16"
    for h in $(seq 1 "$n"); do
        rules=256; [ "$h" = 256 ] && rules=$r256; [ "$h" = 257 ] && rules=$r257
        mkdir -p "$W/d16/d16h$h"
        { printf 'docRoot                  $VH_ROOT/html/\nmodule mod_whisper_edge {\n    ls_enabled             1\n'
          r=1; while [ $r -le "$rules" ]; do printf '    whisper_edge_policy    deny if asn == %d\n' $((h * 1000 + r)); r=$((r + 1)); done
          printf '}\n'; } > "$W/d16/d16h$h/vhconf.conf"
        printf 'virtualHost d16h%d {\n    vhRoot                   %s/\n    allowSymbolLink          1\n    enableScript             0\n    restrained               0\n    configFile               conf/vhosts/d16h%d/vhconf.conf\n}\n' "$h" "$W" "$h"
    done
}
d16_install() { # the files copied as root (no ownership preserved), so each host's file passes the trust rule
    $SUDO find "$LSWS/conf/vhosts" -maxdepth 1 -name 'd16h*' -exec rm -rf {} +
    $SUDO cp -r "$W/d16/." "$LSWS/conf/vhosts/"
}
d16_run() { # d16_run <nhosts> <rules in host 256> <rules in host 257> <label> -> restarts with the fixture, sets LOAD and START_MS
    local t0 blocks
    blocks=$(d16_hosts "$1" "$2" "$3"); d16_install
    # the fixture hosts go AFTER the standard hosts in the main file, so the 257th is last in configuration order
    write_main "$(corpus_main)" "useIpInProxyHeader       0"
    printf '%s\n' "$blocks" | $SUDO tee -a "$CONF" >/dev/null
    t0=$(now_ms)
    restart_server || { bad "cap: the server did not start with $1 hosts ($4)"; return 1; }
    START_MS=$(( $(now_ms) - t0 ))
    sleep 1; load_lines
    echo "    $4: $1 hosts, $(( 255 * 256 + $2 + ($1 > 256 ? $3 : 0) )) fixture rules, the server up in $START_MS ms"
}
if d16_run 256 "$FILL" 0 "at the cap"; then
    is "$(line_of 'distinct programs' | sed -nE 's/.*counters ([0-9]+) contexts, ([0-9]+) rules.*/\1 \2/p')" "$((C0 + 256)) 65528" \
        "cap: exactly 65,536 slots (8 pre-stage + 65,528 rules) is accepted; the configuration-wide line counts every context and rule" \
        "cap: the configuration-wide line at the cap"
    is "$(line_of 'distinct programs' | sed -nE 's/.* ([0-9]+) bytes per shard.*/\1/p')" "524288" \
        "cap: and prints the stride's bytes, the per-worker ceiling on this server (one shard per worker): 524288" \
        "cap: the bytes per shard at the cap"
    [ -z "$(line_of 'cross the cap')" ] && ok "cap: no host is refused at the cap" || bad "cap: a host refused at the cap: $(line_of 'cross the cap' | cut -c1-120)"
fi
if d16_run 257 "$FILL" 1 "one over the cap"; then
    got=$(line_of 'policy refused: "d16h257"')
    if printf '%s' "$got" | hit -F 'cross the cap at this host: 65537 counted rule slots, over the 65536 a configuration may hold; the largest contexts:'; then
        ok "cap: the 257th host, with one rule, crosses and is refused with the core's line naming the five largest contexts: ${got#*the largest contexts: }"
    else
        bad "cap: the crossing host's refusal: ${got:-no line for d16h257}; $(line_of 'the configuration is refused' | cut -c1-100)"
    fi
    is "$(line_of 'distinct programs' | sed -nE 's/.*counters [0-9]+ contexts, ([0-9]+) rules.*/\1/p')" "65528" \
        "cap: and the build stands at 65,528 rules with the crossing host running the empty program" \
        "cap: the rule count after the crossing host was refused"
    [ -z "$(line_of 'policy refused: "d16h256"')" ] && ok "cap: the 256th host, at the cap, stands" || bad "cap: the 256th host was refused too"
    CF16=$(line_of 'distinct programs' | sed -nE 's/.*configuration ([0-9a-f]{16}).*/\1/p')
    if [ -n "$CF16" ] && $SUDO test -f "$D/counters/conf-$CF16.status"; then
        $SUDO grep -q '^refused "http/v[0-9]*" "the configuration.s counted rule slots cross the cap at this host' "$D/counters/conf-$CF16.status" \
            && ok "cap: this configuration's file (conf-$CF16.status, $($SUDO wc -c < "$D/counters/conf-$CF16.status") bytes) carries the crossing host's refused line, naming the cap" \
            || bad "cap: conf-$CF16.status carries no cap refusal: $($SUDO grep -c '^refused' "$D/counters/conf-$CF16.status") refused line(s), $($SUDO grep -c '^text' "$D/counters/conf-$CF16.status") text lines"
    else
        bad "cap: this configuration's file (digest ${CF16:-unread}) was not written: a configuration of 65,528 rules has no configuration file"
    fi
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
    want 403 "cap: and a standard host beside the fixture still denies (its program untouched by the refusal)" "the deny host stopped denying beside the cap"
fi
if d16_run 256 "$((FILL - 1))" 0 "one under the cap"; then
    is "$(line_of 'distinct programs' | sed -nE 's/.*counters [0-9]+ contexts, ([0-9]+) rules.*/\1/p')" "65527" \
        "cap: one slot under the cap is accepted (65,527 rules, 65,535 slots)" "cap: the rule count one under the cap"
    [ -z "$(line_of 'cross the cap')" ] && ok "cap: and no host is refused one under it" || bad "cap: a host refused one under the cap"
fi
$SUDO find "$LSWS/conf/vhosts" -maxdepth 1 -name 'd16h*' -exec rm -rf {} +

# ---- 27. StrictModes on the files this server reads for module keys; the data directory through a symlink ---------
# The main file, every file it includes and every host's configuration file must be owned by root or the server's
# admin account, writable by neither group nor world, under directories held to the same rule. The main file or an
# include failing it refuses the http level (the module runs no program and says which file, its owner and mode, and
# the fix); a host's file failing it refuses that host alone. The data directory: a tenant-owned symlink in a
# tenant-writable directory is refused at binding; a root-owned symlink in a root-owned directory binds, and
# repointing it afterwards changes nothing the module reads (the held directory descriptor).
MAINF="$LSWS/conf/httpd_config.conf"
strict_phase() { # strict_phase <label> <setup command> <undo command> <expect refused: 1|0>
    local lbl=$1 do=$2 undo=$3 want=$4 line code
    eval "$do"
    restart_server || { eval "$undo"; bad "strict: $lbl: the server did not start"; return; }
    sleep 0.5; load_lines
    line=$(line_of 'fails the trust rule')
    code=$(code -H "X-Forwarded-For: $LCRIT" "$(u $PDENY /index.html)")
    eval "$undo"
    if [ "$want" = 1 ]; then
        if printf '%s' "$line" | hit -E 'owned by uid [0-9]+, mode [0-7]{4}; .* Fix: chown root \(or uid [0-9]+\) and chmod go-w'; then
            ok "strict: $lbl: refused naming the file, its owner and mode, and the fix: $(printf '%s' "$line" | sed -E 's/^the file that defines http-level directives fails the trust rule: //' | cut -c1-150)"
        else
            bad "strict: $lbl: no refusal with owner, mode and fix: ${line:-no line}"
        fi
        is "$code" "200" "strict: $lbl: and the module runs no program from the untrusted file (a CRITICAL client is served 200 under mode deny)" "strict: $lbl: the floor from the untrusted file ran"
    else
        [ -z "$line" ] && is "$code" "403" "strict: $lbl: accepted, the floor denies the CRITICAL client" "strict: $lbl: not accepted" || bad "strict: $lbl: refused where it must be accepted: $line"
    fi
}
write_main "$(main_block deny)" "useIpInProxyHeader       0"
strict_phase "the main file group-writable" "\$SUDO chmod g+w '$MAINF'" "\$SUDO chmod g-w '$MAINF'" 1
strict_phase "the main file's mode restored" ":" ":" 0
$SUDO chmod g+w "$LSWS/conf"
restart_server || bad "strict: the server did not start with conf/ group-writable"
sleep 0.5; load_lines
CMODE=$($SUDO stat -c %a "$LSWS/conf"); line=$(line_of 'fails the trust rule'); code=$(code -H "X-Forwarded-For: $LCRIT" "$(u $PDENY /index.html)")
$SUDO chmod g-w "$LSWS/conf"
if [ "$CMODE" = 770 ]; then
    if printf '%s' "$line" | hit -F '"'"$LSWS/conf"'" is owned by uid'; then ok "strict: a group-writable ancestor (conf/ at $CMODE) is refused naming the directory: $(printf '%s' "$line" | cut -c60-180)"; else bad "strict: conf/ at $CMODE was not refused: ${line:-no line}; a CRITICAL client got $code"; fi
else
    # a row that is not walked says so by name: this arm's ok above is counted only where the mode survives the start.
    # OpenLiteSpeed 1.9.3 resets conf/ to 0750 at every start and at every graceful restart (measured: 0775 and
    # 0770 set before each read 0750 after it), so here the arm cannot run and the count is one lower
    echo "  n/a   strict: a group-writable ancestor (conf/): set group-writable before the start, it reads $CMODE after it, because this server resets the directory's mode at start and at a graceful restart, so the arm is not walked here and is not counted; the module saw $CMODE (a CRITICAL client got $code)"
fi
# an include whose directory is a root-owned symlink into a tenant-writable tree: the lexical path is trusted, the
# resolved chain is not (the core's chain check reads realpath)
mkdir -p "$W/tenant"; chmod 0777 "$W/tenant"; echo "# nothing" > "$W/tenant/extra.conf"
$SUDO ln -sfn "$W/tenant" "$D/inc"
write_main "$(main_block deny)" "useIpInProxyHeader       0
include                  $D/inc/extra.conf"
strict_phase "an include through a root-owned symlink into a tenant-writable tree" ":" ":" 1
$SUDO rm -f "$D/inc"
# a root-owned sticky ancestor (/tmp) above an include: the configuration-file rule allows it; the core's
# chain rule has no sticky exception today, so the outcome is measured and printed, never asserted
STK=$($SUDO mktemp -d /tmp/whisper-edge-ols-sticky.XXXXXX); $SUDO chmod 0755 "$STK"; echo "# nothing" | $SUDO tee "$STK/extra.conf" >/dev/null
write_main "$(main_block deny)" "useIpInProxyHeader       0
include                  $STK/extra.conf"
restart_server || bad "strict: the server did not start with the sticky include"
sleep 0.5; load_lines
echo "    measured: an include under a root-owned sticky ancestor (/tmp): $(line_of 'fails the trust rule' | cut -c1-140); a CRITICAL client gets $(code -H "X-Forwarded-For: $LCRIT" "$(u $PDENY /index.html)")"
$SUDO rm -rf "$STK"
# a host's own configuration file group-writable: that host alone is refused
write_main "$(main_block deny)" "useIpInProxyHeader       0"
$SUDO chmod g+w "$LSWS/conf/vhosts/WhisperPolicy/vhconf.conf"
restart_server || bad "strict: the server did not start with a group-writable host file"
sleep 0.5; load_lines
$SUDO chmod g-w "$LSWS/conf/vhosts/WhisperPolicy/vhconf.conf"
line=$(line_of 'policy refused: "WhisperPolicy": its configuration file fails the trust rule')
if printf '%s' "$line" | hit -E 'writable by group or world \(mode [0-7]{4}\); chown root \(or uid [0-9]+'; then
    ok "strict: a host's group-writable configuration file refuses that host alone, with mode and fix: $(printf '%s' "$line" | cut -c1-130)"
else
    bad "strict: the host's file: ${line:-no refusal line}"
fi
req WhisperPolicy "$(u $PPOL /index.html)" -H "X-Forwarded-For: $LHIGH"
want 200 "strict: the refused host runs no context rule (a HIGH client it would deny is served)" "the refused host judged"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "strict: and the host beside it still denies" "the good host stopped denying"
# the data directory through a symlink: refused through the tenant's, bound through root's, held after a repoint
mkdir -p "$W/site"; ln -sfn "$D/planes" "$W/site/edge-data"
write_main "$(main_block deny | sed "s|whisper_edge_data            $D/planes|whisper_edge_data            $W/site/edge-data|")" "useIpInProxyHeader       0"
restart_server || bad "strict: the server did not start with the tenant symlink"
sleep 0.5; load_lines
# per plane (the core's rule, POLICY.md): every plane the refused directory holds is refused at configuration, in the core's
# words, and reads unknown
REFSENT="whisper edge: plane reputation is refused at configuration and reads unknown until it is fixed and the configuration reloaded; every other plane binds and serves: "
line=$($SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | grep -aF -- "$REFSENT" | head -1 | sed 's/^.*\[whisper_edge\] //')
[ -n "$line" ] && ok "strict: whisper_edge_data through a tenant-owned symlink in a tenant-writable directory refuses the planes it holds at configuration: $(printf '%s' "$line" | cut -c1-170)" || bad "strict: the tenant symlink bound"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 200 "strict: and with no plane bound a LOW client is served (fail open, every rule unknown)" "a plane bound through the tenant's symlink"
$SUDO ln -sfn "$D/planes" "$D/link"
write_main "$(main_block deny | sed "s|whisper_edge_data            $D/planes|whisper_edge_data            $D/link|")" "useIpInProxyHeader       0"
restart_server || bad "strict: the server did not start with root's symlink"
sleep 0.5; load_lines
rl=$($SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | grep -aF -- "is refused at configuration and reads unknown" | head -1)
[ -z "$rl" ] && ok "strict: a root-owned symlink in a root-owned directory binds, no plane refused" || bad "strict: root's symlink refused: $(printf '%s' "$rl" | cut -c1-160)"
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "strict: and the planes bound through it serve (a LOW client is denied)" "no deny through root's symlink"
$SUDO mkdir -p "$D/empty"; $SUDO ln -sfn "$D/empty" "$D/link"
await_tick
req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
want 403 "strict: the symlink repointed at an empty directory after binding changes nothing the module reads (the held descriptor; a LOW client is still denied after a tick)" "the repoint changed what the module reads"
is "$(status_state reputation)" "armed" "strict: and the status keeps reputation armed after the repoint" "strict: reputation after the repoint"
$SUDO rm -f "$D/link"; $SUDO rm -rf "$D/empty"

# ---- 27b. a plane the configuration reader cannot open: -u in the token, `unreadable` in the configuration file ---
# The rule: a plane present but unreadable by the configuration reader is inert, its token reads
# <plane>:-u, and the configuration file's plane line carries `unreadable "<errno text>"`. On this server the reader
# is the main process, which binds before any fork, and it is root with every capability (measured on 1.9.3:
# "lshttpd - main" is euid 0, CapEff 000001ffffffffff; the workers are nobody and only inherit what it mapped).
# Mode 0000 alone therefore does not make a plane unreadable here, since DAC override reads it, and the first step
# says so. Root is refused a read by a mandatory access control, an AppArmor or SELinux denial on a mislabelled data
# file being the deployed case, so the second step starts the server under a Landlock domain that denies reading
# that one file and nothing else: the kernel's own EACCES, the errno a denying LSM returns. The domain is inherited
# by the server's whole tree, and the next full stop and start leaves it.
cat > "$W/deny-read.c" <<'CSRC'
/* deny-read <file> <command...>: run the command in a Landlock domain that may read every file but <file> */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int allow(int rs, const char *path)
{
    struct landlock_path_beneath_attr a = { .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE };
    int rc;

    a.parent_fd = open(path, O_PATH | O_CLOEXEC);
    if (a.parent_fd < 0) {
        return 0;                                   /* a dangling link names nothing to allow */
    }
    rc = (int) syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &a, 0);
    close(a.parent_fd);
    return rc;
}

int main(int argc, char **argv)
{
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE };
    char real[PATH_MAX], dir[PATH_MAX] = "/", next[PATH_MAX], path[PATH_MAX];
    char *c, *save = NULL;
    int rs;

    if (argc < 3 || realpath(argv[1], real) == NULL) {
        fprintf(stderr, "deny-read: usage: deny-read <existing file> <command...>\n");
        return 2;
    }
    rs = (int) syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) {
        int e = errno;

        perror("deny-read: landlock_create_ruleset");
        return e == ENOSYS || e == EOPNOTSUPP ? 3 : 2;   /* 3: this kernel has no Landlock */
    }
    /* every sibling along the file's path is allowed, recursively; the file and its ancestors are not */
    for (c = strtok_r(real, "/", &save); c != NULL; c = strtok_r(NULL, "/", &save)) {
        DIR *d = opendir(dir);
        struct dirent *e;

        if (d == NULL) {
            perror("deny-read: opendir");
            return 2;
        }
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 || strcmp(e->d_name, c) == 0) {
                continue;
            }
            snprintf(path, sizeof path, "%s%s%s", dir, strcmp(dir, "/") == 0 ? "" : "/", e->d_name);
            if (allow(rs, path) != 0) {
                fprintf(stderr, "deny-read: landlock_add_rule %s: %s\n", path, strerror(errno));
                return 2;
            }
        }
        closedir(d);
        snprintf(next, sizeof next, "%s%s%s", dir, strcmp(dir, "/") == 0 ? "" : "/", c);
        memcpy(dir, next, sizeof dir);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || syscall(SYS_landlock_restrict_self, rs, 0) != 0) {
        perror("deny-read: landlock_restrict_self");
        return 2;
    }
    close(rs);
    execvp(argv[2], argv + 2);
    perror("deny-read: exec");
    return 127;
}
CSRC
TORP="$D/planes/tor.bin"
conf_with_tor() { $SUDO sh -c 'grep -l "^plane tor path " "$1"/conf-*.status 2>/dev/null' sh "$D/counters" | head -1; }
tor_line() { local f; await "[ -n \"\$(conf_with_tor)\" ]" 10; f=$(conf_with_tor); [ -n "$f" ] && $SUDO grep '^plane tor path ' "$f" | head -1; }
# a start with no configuration file left from an earlier one: the old workers flush theirs as they exit, so
# the files go after the stop and before the start
fresh_start() { # fresh_start [wrapper]
    $SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1; await '! server_alive' 20 || true
    $SUDO sh -c 'rm -f "$1"/conf-*.status' sh "$D/counters"
    START_WRAP="${1:-}" start_server
}
if "$CC_BIN" -O2 -Wall -Wextra -Werror -o "$W/deny-read" "$W/deny-read.c" 2>"$W/deny-read.log"; then
    # step 1: mode 0000 alone, the server started as always
    $SUDO chmod 0000 "$TORP"
    write_main "$(main_block deny)" "useIpInProxyHeader       0"
    fresh_start || bad "unreadable: the server did not start with tor at mode 0000"
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
    g=$(field "$LINE" gen)
    line=$(tor_line)
    case "$g" in *tor:-u*) bad "unreadable: mode 0000 alone read as unreadable to a root configuration reader: $g" ;;
        *) [ "$line" = "plane tor path \"$TORP\"" ] \
            && ok "unreadable: mode 0000 alone does not stop this server's root configuration reader: it opens and binds tor, no unreadable field (token $g)" \
            || bad "unreadable: with mode 0000 under root the plane line is \"$line\", token $g" ;; esac
    # the domain needs Landlock in this kernel; without it the rows below cannot run, and the gate says so by cause
    $SUDO "$W/deny-read" "$TORP" true 2>/dev/null; LLRC=$?
    VHOSTS_ALL=$VHOSTS
    if [ "$LLRC" = 3 ]; then
        bad "unreadable: NOT PROVEN by cause: this kernel ($(uname -r)) has no Landlock (landlock_create_ruleset answers ENOSYS), so the server cannot be started inside a domain that refuses root one file; the -u token, its configuration line and field, the --status row and the NULL-field control did not run"
    else
        # the vantage: the domain refuses root that one file, and only that one
        out=$($SUDO "$W/deny-read" "$TORP" cat "$TORP" 2>&1 >/dev/null); r1=$?
        n=$($SUDO "$W/deny-read" "$TORP" cat "$D/planes/reputation.bin" 2>/dev/null | wc -c)
        [ "$r1" != 0 ] && case "$out" in *"Permission denied"*) true ;; *) false ;; esac && [ "$n" -gt 0 ] \
            && ok "unreadable: inside the Landlock domain root's read of tor.bin fails ($out) while reputation.bin beside it reads $n bytes" \
            || bad "unreadable: the domain did not isolate the one file: tor rc=$r1 \"$out\", reputation $n bytes"
        # step 2: the same plane, the server started inside the domain, with the default and deny hosts alone, so that
        # nothing else in the configuration (the refused hosts WhisperBad and WhisperSugar) makes --status exit 1
        VHOSTS_ALL=$VHOSTS; VHOSTS="WhisperDefault WhisperDeny"
        write_main "$(main_block deny)" "useIpInProxyHeader       0"
        unreadable_phase() { # unreadable_phase <module> -> LINE, g, line, USTAT, URC
            install_module "$1"
            fresh_start "$W/deny-read $TORP" || bad "unreadable: the server did not start inside the domain ($1)"
            sleep 0.5; load_lines
            req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"
            g=$(field "$LINE" gen)
            await_tick || true
            line=$(tor_line)
            USTAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); URC=$?
        }
        UWANT="configuration unreadable tor \"$TORP\" \"Permission denied\""
        unreadable_phase "$W/mod_whisper_edge.so"
        case "$g" in *tor:-u*) ok "unreadable: a mode-0000 plane the root configuration reader cannot open reads tor:-u in the token ($g)" ;;
            *) bad "unreadable: the token lacks tor:-u: $g" ;; esac
        has_line "tor present, unreadable by uid 0 (Permission denied): rules on it are inert" \
            && ok "unreadable: and the configuration line says so: $(line_of 'tor present, unreadable')" || bad "unreadable: no configuration line for the unreadable plane"
        want 403 "unreadable: and the plane beside it still serves: reputation denies the LOW client" "the unreadable tor plane stopped reputation"
        is "$line" "plane tor path \"$TORP\" unreadable \"Permission denied\"" \
            "unreadable: and the configuration file's plane line carries the reader's errno: $line" "unreadable: the configuration file's tor line"
        grep -qxF "$UWANT" <<<"$USTAT" && [ "$URC" = 1 ] \
            && ok "unreadable: whisper-edge-summary --status prints $UWANT and exits 1, the configuration's one unhealthy fact" \
            || bad "unreadable: --status exit $URC: $(printf '%s\n' "$USTAT" | grep -v '^  plane' | head -8 | tr '\n' '|')"
        if build_module "$W/ctl-nounread.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_NO_UNREADABLE_FIELD"; then
            unreadable_phase "$W/ctl-nounread.so"
            if [ "$line" = "plane tor path \"$TORP\" unreadable \"Permission denied\"" ]; then
                ctl 1 "a configuration file written with the unreadable field left NULL"
            else
                ctl 0 "a configuration file written with the unreadable field left NULL fails the row (its line: ${line:-none})"
            fi
            if grep -qxF "$UWANT" <<<"$USTAT" || [ "$URC" != 0 ]; then
                ctl 1 "--status with the unreadable field left NULL (exit $URC)"
            else
                ctl 0 "with the unreadable field left NULL --status prints no unreadable line and exits 0, so the --status row fails"
            fi
        else
            bad "unreadable: the NULL-field control build failed"
        fi
    fi
    if build_module "$W/ctl-nounread-refused.so" "-DWE_LS_TEST_NO_UNREADABLE_FIELD" >/dev/null 2>&1; then bad "unreadable: WE_LS_TEST_NO_UNREADABLE_FIELD built outside a control build"; else ok "unreadable: WE_LS_TEST_NO_UNREADABLE_FIELD is refused outside a control build"; fi
    VHOSTS=$VHOSTS_ALL
    install_module "$W/mod_whisper_edge.so"
    $SUDO chmod 0444 "$TORP"
    write_main "$(main_block deny)" "useIpInProxyHeader       0"
    restart_server || bad "unreadable: the server did not restart outside the domain"
else
    bad "unreadable: the Landlock helper did not compile: $(head -3 "$W/deny-read.log" | tr '\n' '|')"
    $SUDO chmod 0444 "$TORP"
fi

# ---- 27c. a plane with no map held at loading by the tick's pause (the core's WE_MOD_TEST_PAUSE_TICK) -----------
# tor at mode 0000 is refused at configuration load (a mapped plane must be exactly 0444), so it has no map and reads
# tor:-r. A newer generation published at 0444 is admitted on the next tick, which posts loading and wakes the loop,
# then holds at `loading` while $WE_MOD_PAUSE_DIR/loading exists. The loop applies the word meanwhile, so a
# request reads tor:-l; the release lets the verification finish and the plane arms at generation 2.
# Not run here, by cause: S2's held-loading arm reads the STATUS FILE across two held ticks, and on this server the
# file is written by the module thread after its tick, the thread the hold stops, so the file keeps its pre-hold word
# (printed below). M3 is row 27e.
PD="$W/pause"; mkdir -p "$PD"; chmod 1777 "$PD"
python3 "$GEN" --plane tor --out "$W/tor2.bin" --format 2 --synthetic 3 3 --generation 2 >/dev/null || bad "pause: the generation-2 tor plane was not written"
all_held() { local p n=0 pt=${1:-loading}; for p in $(workers); do [ -e "$PD/held.$pt.$p" ] || return 1; n=$((n + 1)); done; [ "$n" -ge 1 ]; }
publish_tor() { $SUDO install -o root -g root -m 0444 "$1" "$D/planes/.tor.new" && $SUDO mv -f "$D/planes/.tor.new" "$TORP"; }
pause_phase() { # pause_phase <module> -> g0 gL gA HELD SHELD
    $SUDO rm -f "$PD"/loading "$PD"/held.*
    install_module "$1"
    $SUDO chmod 0000 "$TORP"
    fresh_start "env WE_MOD_PAUSE_DIR=$PD" || bad "pause: the server did not start ($1)"
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"; g0=$(field "$LINE" gen)
    : > "$PD/loading"
    publish_tor "$W/tor2.bin"
    # every worker ticks on its own jittered clock: the request is sent once each live worker holds, so it cannot
    # land on one that has not reached the hold yet (the first walk's request did, and read tor:-r)
    HELD=no; await all_held $((2 * REFRESH_S + 8)) && HELD=yes
    sleep 1
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"; gL=$(field "$LINE" gen)
    SHELD=$(status_state tor)
    rm -f "$PD/loading"
    await "[ \"\$(status_state tor)\" = armed ]" $((2 * REFRESH_S + 8)) || true
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"; gA=$(field "$LINE" gen)
    publish_tor "$W/tor.bin"
}
if build_module "$W/ctl-pause.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK"; then
    pause_phase "$W/ctl-pause.so"
    case "$g0" in *tor:-r*) ok "pause: tor at mode 0000 is refused at load and has no map: $g0" ;; *) bad "pause: tor at mode 0000 reads $g0, not tor:-r" ;; esac
    [ "$HELD" = yes ] && case "$gL" in *tor:-l*) true ;; *) false ;; esac \
        && ok "pause: generation 2 admitted, the tick held at loading (a held marker from every live worker), and a request in the hold reads tor:-l: $gL" \
        || bad "pause: held=$HELD, the token in the hold reads $gL"
    case "$gA" in *tor:2.*) ok "pause: released, the verification finishes and tor arms at generation 2: $gA" ;; *) bad "pause: after the release the token reads $gA" ;; esac
    echo "    n/a: S2's held-loading status arm: the status file is the held thread's to write; during the hold it read tor ${SHELD:-nothing}"
    if build_module "$W/ctl-nohold.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK -DWE_MOD_TEST_PAUSE_NO_HOLD"; then
        pause_phase "$W/ctl-nohold.so"
        case "$gL" in *tor:-l*) ctl 1 "a pause that marks and does not hold ($gL)" ;;
            *) ctl 0 "a pause that marks and does not hold lets the plane arm before the request, so the tor:-l row fails ($gL)" ;; esac
    else
        bad "pause: the no-hold control build failed"
    fi
else
    bad "pause: the WE_MOD_TEST_PAUSE_TICK build failed"
fi
if build_module "$W/ctl-pause-refused.so" "-DWE_MOD_TEST_PAUSE_TICK" >/dev/null 2>&1; then bad "pause: WE_MOD_TEST_PAUSE_TICK built outside a control build"; else ok "pause: WE_MOD_TEST_PAUSE_TICK is refused outside a control build"; fi
$SUDO rm -f "$PD"/loading "$PD"/held.*
$SUDO chmod 0444 "$TORP"
install_module "$W/mod_whisper_edge.so"
restart_server || bad "pause: the server did not restart with the shipped module"

# ---- 27d. the exit's stop: the core's bounded stop, and the line that names the thread's stage ----------------------
# Each worker's tick is held at `tick`, inside the plane jobs, with no progress, and the server is then stopped. The
# bounded stop grants a window only to progress or to work outside a plane job, so it abandons each held thread after
# one 2 s window, within the 6 s cap, and the worker's line names the stage. The control puts the flat 2 s stop back,
# whose line names none.
STOPLINE="the module's thread was abandoned at exit (the thread was in: a plane job), within the 6000 ms cap"
stop_phase() { # stop_phase <module> -> NHELD NSTAGE NFLAT
    $SUDO rm -f "$PD"/tick "$PD"/held.*
    install_module "$1"
    fresh_start "env WE_MOD_PAUSE_DIR=$PD" || bad "stop: the server did not start ($1)"
    : > "$PD/tick"
    NHELD=0; await "all_held tick" $((2 * REFRESH_S + 8)) && NHELD=$(workers | wc -w)
    FROM_STOP=$(( $(elog_lines) + 1 ))
    $SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1; await '! server_alive' 30 || true
    rm -f "$PD/tick"
    NSTAGE=$($SUDO tail -n +"$FROM_STOP" "$ELOG" 2>/dev/null | grep -cF -- "$STOPLINE")
    NFLAT=$($SUDO tail -n +"$FROM_STOP" "$ELOG" 2>/dev/null | grep -cF -- "the module's thread did not finish within 2000 ms at exit")
}
if [ -f "$W/ctl-pause.so" ]; then
    stop_phase "$W/ctl-pause.so"
    [ "$NHELD" -ge 1 ] && [ "$NSTAGE" = "$NHELD" ] && [ "$NFLAT" = 0 ] \
        && ok "stop: with every worker's tick held in a plane job, each of the $NHELD workers' exits abandons its thread and says so: $STOPLINE" \
        || bad "stop: held $NHELD, stage-named lines $NSTAGE, flat lines $NFLAT"
    if build_module "$W/ctl-flatstop.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK -DWE_LS_TEST_FLAT_STOP"; then
        stop_phase "$W/ctl-flatstop.so"
        if [ "$NHELD" -ge 1 ] && [ "$NSTAGE" = "$NHELD" ]; then ctl 1 "the flat 2 s stop (stage-named lines $NSTAGE)"
        else ctl 0 "the flat 2 s stop names no stage, so the stop row fails (held $NHELD, stage-named $NSTAGE, flat lines $NFLAT)"; fi
    else
        bad "stop: the flat-stop control build failed"
    fi
else
    bad "stop: no WE_MOD_TEST_PAUSE_TICK build to hold the tick with"
fi
if build_module "$W/ctl-flatstop-refused.so" "-DWE_LS_TEST_FLAT_STOP" >/dev/null 2>&1; then bad "stop: WE_LS_TEST_FLAT_STOP built outside a control build"; else ok "stop: WE_LS_TEST_FLAT_STOP is refused outside a control build"; fi
$SUDO rm -f "$PD"/tick "$PD"/held.*
install_module "$W/mod_whisper_edge.so"
restart_server || bad "stop: the server did not restart with the shipped module"

# ---- 27e. the per-plane binding (ABI 5): whisper_edge_data <plane> <file>, and the snapshot beside the directory --
# A per-plane line binds that plane to its own file over the directory's; the snapshot beside a directory is the
# reputation plane's file, never dropped. Refused: the snapshot together with a per-plane reputation line (naming
# both), a relative path, and a per-plane file in a directory others can write. The core's controls
# WE_MOD_TEST_PLANE_FILE_IGNORED and WE_MOD_TEST_SNAPSHOT_DROPPED fail the two binding rows by name.
python3 "$GEN" --plane tor --out "$W/tor7.bin" --format 2 --synthetic 3 3 --generation 7 >/dev/null || bad "binding: the generation-7 tor plane was not written"
python3 "$GEN" --plane reputation --out "$W/rep9.bin" --format 1 --v4-index radix-16 --v6-index none --synthetic 4 4 --generation 9 >/dev/null || bad "binding: the generation-9 reputation plane was not written"
$SUDO install -d -o root -g root -m 0755 "$D/alt"
$SUDO install -o root -g root -m 0444 "$W/tor7.bin" "$D/alt/tor7.bin"
$SUDO install -o root -g root -m 0444 "$W/rep9.bin" "$D/alt/rep9.bin"
# the untrusted directory sits under the trusted fixture directory, so its own mode (0777) is what refuses it
$SUDO install -d -o root -g root -m 0777 "$D/open"
$SUDO install -o root -g root -m 0444 "$W/tor7.bin" "$D/open/tor7.bin"
# the http level's block with extra server-level lines after the data line
bind_main() { BIND_X="$1" awk '{print} /^    whisper_edge_data / && !d {print ENVIRON["BIND_X"]; d=1}' <<<"$(main_block deny)"; }
bind_phase() { # bind_phase <module> <extra lines> -> STARTED, LINE, g, CODES (five more requests), DEATHS
    install_module "$1"
    write_main "$(bind_main "$2")" "useIpInProxyHeader       0"
    STARTED=1; fresh_start || STARTED=0
    sleep 0.5; load_lines
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"; g=$(field "$LINE" gen)
    CODES=""; for _ in 1 2 3 4 5; do CODES="$CODES$(code -H "X-Forwarded-For: $LLOW" "$(u $PDENY /index.html)") "; done
    await_tick || true
    # a worker killed by a signal since this start (the server names each in its log and forks another)
    DEATHS=$($SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | grep -c 'received signal=')
}
conf_plane_line() { local f; f=$($SUDO sh -c 'ls -t "$1"/conf-*.status 2>/dev/null' sh "$D/counters" | head -1); [ -n "$f" ] && $SUDO grep "^plane $1 path " "$f" | head -1; }
PERPLANE="    whisper_edge_data            tor $D/alt/tor7.bin"
SNAPBESIDE="    whisper_edge_snapshot        $D/alt/rep9.bin"
bind_phase "$W/mod_whisper_edge.so" "$PERPLANE"
[ "$STARTED" = 1 ] || bad "binding: the server did not start with the per-plane line"
case "$g" in *tor:7.*) [ "$(conf_plane_line tor)" = "plane tor path \"$D/alt/tor7.bin\"" ] \
        && ok "binding: whisper_edge_data tor <file> binds tor to its own file over the directory's (token $g; the configuration file names $D/alt/tor7.bin)" \
        || bad "binding: tor reads generation 7 but the plane line is $(conf_plane_line tor)" ;;
    *) bad "binding: the per-plane tor line did not bind its file: $g" ;; esac
bind_phase "$W/mod_whisper_edge.so" "$SNAPBESIDE"
case "$g" in *reputation:9.*) [ "$(conf_plane_line reputation)" = "plane reputation path \"$D/alt/rep9.bin\"" ] && [ "$CODE" = 403 ] \
        && ok "binding: whisper_edge_snapshot beside whisper_edge_data binds the snapshot as the reputation file, never dropped (token $g, the LOW client denied)" \
        || bad "binding: reputation reads generation 9 but the plane line is $(conf_plane_line reputation), status $CODE" ;;
    *) bad "binding: the snapshot beside the directory was not bound: $g" ;; esac
if build_module "$W/ctl-fileignored.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PLANE_FILE_IGNORED"; then
    bind_phase "$W/ctl-fileignored.so" "$PERPLANE"
    case "$g" in *tor:7.*) ctl 1 "WE_MOD_TEST_PLANE_FILE_IGNORED ($g)" ;; *) ctl 0 "WE_MOD_TEST_PLANE_FILE_IGNORED reads the per-plane line as nothing and the directory's tor serves, so the per-plane row fails ($g)" ;; esac
else
    bad "binding: the WE_MOD_TEST_PLANE_FILE_IGNORED build failed"
fi
if build_module "$W/ctl-snapdropped.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_SNAPSHOT_DROPPED"; then
    bind_phase "$W/ctl-snapdropped.so" "$SNAPBESIDE"
    case "$g" in *reputation:9.*) ctl 1 "WE_MOD_TEST_SNAPSHOT_DROPPED ($g)" ;; *) ctl 0 "WE_MOD_TEST_SNAPSHOT_DROPPED drops the snapshot beside the directory and the directory's reputation serves, so the snapshot row fails ($g)" ;; esac
else
    bad "binding: the WE_MOD_TEST_SNAPSHOT_DROPPED build failed"
fi
bind_phase "$W/mod_whisper_edge.so" "$SNAPBESIDE
    whisper_edge_data            reputation $D/alt/rep9.bin"
line=$(line_of "both name the reputation plane's file")
case "$line" in "whisper_edge_snapshot $D/alt/rep9.bin and whisper_edge_data reputation $D/alt/rep9.bin both name the reputation plane's file; keep one (the configuration names the reputation plane's file twice); every rule reads unknown and the module denies nothing")
        [ "$STARTED" = 1 ] && [ "$CODE $CODES" = "200 200 200 200 200 200 " ] && [ "$DEATHS" = 0 ] \
        && ok "binding: the snapshot with a per-plane reputation line is the one configuration error refused whole, naming both, and six requests are answered fail open with no worker lost: $(printf '%s' "$line" | cut -c1-150)" \
        || bad "binding: the refused binding: started $STARTED, codes $CODE $CODES, workers killed by a signal $DEATHS" ;;
    *) bad "binding: the snapshot with a reputation line: ${line:-no refusal line}" ;; esac
bind_phase "$W/mod_whisper_edge.so" "    whisper_edge_data            tor alt/tor7.bin"
has_line "the tor file needs an absolute path; \"alt/tor7.bin\" is refused" && case "$g" in *tor:1.*) true ;; *) false ;; esac \
    && ok "binding: a relative per-plane path is refused at the line, and tor stays on the directory's file ($g)" \
    || bad "binding: the relative path: $(line_of 'whisper_edge_data #' | cut -c1-160), token $g"
# per plane (the core's rule): tor, whose file sits in a directory others can write, is refused at configuration in the core's
# words and reads -r, while reputation, armed before it, keeps serving its generation; no worker is lost
TORSENT="whisper edge: plane tor is refused at configuration and reads unknown until it is fixed and the configuration reloaded; every other plane binds and serves: "
bind_phase "$W/mod_whisper_edge.so" "    whisper_edge_data            tor $D/open/tor7.bin"
line=$($SUDO tail -n +"$FROM" "$ELOG" 2>/dev/null | grep -aF -- "$TORSENT" | head -1 | sed 's/^.*\[whisper_edge\] //')
cl=$(conf_plane_line tor)
case "$line|$g|$cl" in *"$D/open"*"|"*"reputation:1."*"tor:-r"*"|plane tor path \"$D/open/tor7.bin\" refused \""*)
        [ "$STARTED" = 1 ] && [ "$CODE $CODES" = "403 403 403 403 403 403 " ] && [ "$DEATHS" = 0 ] \
        && ok "binding: a per-plane file in a directory others can write (0777) refuses that plane alone: tor reads -r while reputation keeps denying (6 of 6 LOW requests 403, no worker lost), and the core's sentence and the configuration file's refused line say why: $(printf '%s' "$line" | cut -c1-120)" \
        || bad "binding: the untrusted directory: started $STARTED, codes $CODE $CODES, workers killed by a signal $DEATHS" ;;
    *) bad "binding: the untrusted directory: token $g, sentence ${line:-none}, plane line ${cl:-none}" ;; esac
# the counters directory with no counters directive: the core's placement (we_mod_bind_counters_dir), the one rule
# every server applies. With per-plane files alone in two directories no one place is beside them, so it is refused
# naming both and no counter file is written; blocking is unaffected. The core's WE_MOD_TEST_COUNTERS_FIRST_DIR takes
# the first file's directory instead and fails the row by name.
$SUDO install -d -o root -g root -m 0755 "$D/alt2"
$SUDO install -o root -g root -m 0444 "$W/tor7.bin" "$D/alt2/tor7.bin"
split_main() { SPLIT_X="    whisper_edge_data            reputation $D/alt/rep9.bin
    whisper_edge_data            tor $D/alt2/tor7.bin" awk '/^    whisper_edge_(data|summary) / {if (!d) {print ENVIRON["SPLIT_X"]; d=1}; next} {print}' <<<"$(main_block deny)"; }
SPLITWHY="the configuration's data files are in more than one directory ($D/alt and $D/alt2), so no one place is beside them; name the counters directory with whisper_edge_summary <dir>; no counter file is written until then, and blocking is unaffected"
split_phase() { # split_phase <module> -> STARTED, CODE, g, SPLITLINE
    install_module "$1"
    write_main "$(split_main)" "useIpInProxyHeader       0"
    STARTED=1; fresh_start || STARTED=0
    sleep 0.5; load_lines
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LLOW"; g=$(field "$LINE" gen)
    SPLITLINE=$(line_of "the configuration's data files are in more than one directory")
}
split_phase "$W/mod_whisper_edge.so"
[ "$STARTED" = 1 ] && [ "$SPLITLINE" = "$SPLITWHY" ] && [ "$CODE" = 403 ] && case "$g" in *reputation:9.*tor:7.*) true ;; *) false ;; esac \
    && ok "binding: per-plane files in two directories, with no counters directive, are refused a counters directory naming both ($D/alt and $D/alt2), while both planes serve (403, $g)" \
    || bad "binding: the split layout: started $STARTED, status $CODE, token $g, line ${SPLITLINE:-none}"
if build_module "$W/ctl-firstdir.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_COUNTERS_FIRST_DIR"; then
    split_phase "$W/ctl-firstdir.so"
    if [ "$SPLITLINE" = "$SPLITWHY" ]; then ctl 1 "WE_MOD_TEST_COUNTERS_FIRST_DIR"
    else ctl 0 "WE_MOD_TEST_COUNTERS_FIRST_DIR takes the first file's directory, no refusal is said, and the split row fails"; fi
else
    bad "binding: the WE_MOD_TEST_COUNTERS_FIRST_DIR build failed"
fi
# a snapshot at the filesystem root with no counters directive: counters beside it would be created at /counters,
# so the core refuses a counters directory (we_mod_bind_counters_dir) in its words, no counter file is written, and
# blocking is unaffected. The core's WE_MOD_TEST_COUNTERS_AT_ROOT gives /counters instead and fails the row by name.
# The file is the legacy snapshot this gate already uses, placed at / under this run's name through sudo and removed
# by the restore whatever happens; /counters existing beforehand makes the row NOT PROVEN, never a pass.
ROOTSNAP="/${D##*/}.bin"
ROOTWHY="$ROOTSNAP is at the filesystem root, so counters beside it would be created at /counters; name the counters directory with whisper_edge_summary <dir>, or move the planes; no counter file is written until then, and blocking is unaffected"
root_main() { ROOT_X="    whisper_edge_snapshot        $ROOTSNAP" awk '/^    whisper_edge_(data|summary) / {if (!d) {print ENVIRON["ROOT_X"]; d=1}; next} {print}' <<<"$(main_block deny)"; }
root_phase() { # root_phase <module> -> STARTED, CODE, ROOTLINE, ROOTCTR (whether /counters exists after a tick)
    install_module "$1"
    write_main "$(root_main)" "useIpInProxyHeader       0"
    STARTED=1; fresh_start || STARTED=0
    sleep 0.5; load_lines
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LHIGH"
    await_tick || true
    ROOTLINE=$(line_of "is at the filesystem root, so counters beside it")
    ROOTCTR=no; [ -e /counters ] && ROOTCTR=yes
}
if [ -e /counters ]; then
    bad "binding: NOT PROVEN by cause: /counters already exists on this host, so the root-snapshot row cannot show that none is created"
elif ! $SUDO install -o root -g root -m 0444 "$W/snapshot-high.bin" "$ROOTSNAP"; then
    bad "binding: NOT PROVEN by cause: the gate could not place $ROOTSNAP at the filesystem root through sudo"
else
    root_phase "$W/mod_whisper_edge.so"
    [ "$ROOTCTR" = yes ] && ROOT_COUNTERS_MADE=1
    [ "$STARTED" = 1 ] && [ "$ROOTLINE" = "$ROOTWHY" ] && [ "$ROOTCTR" = no ] && [ "$CODE" = 403 ] \
        && ok "binding: a snapshot at the filesystem root, with no counters directive, is refused a counters directory in the core's words, no /counters is created, and blocking is unaffected (the HIGH client 403)" \
        || bad "binding: the root snapshot: started $STARTED, status $CODE, /counters created $ROOTCTR, line ${ROOTLINE:-none}"
    if build_module "$W/ctl-countersroot.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_COUNTERS_AT_ROOT"; then
        root_phase "$W/ctl-countersroot.so"
        [ "$ROOTCTR" = yes ] && ROOT_COUNTERS_MADE=1
        if [ "$ROOTLINE" = "$ROOTWHY" ]; then ctl 1 "WE_MOD_TEST_COUNTERS_AT_ROOT"
        else ctl 0 "WE_MOD_TEST_COUNTERS_AT_ROOT gives /counters beside the root file, no refusal is said, and the root-snapshot row fails"; fi
    else
        bad "binding: the WE_MOD_TEST_COUNTERS_AT_ROOT build failed"
    fi
    $SUDO rm -f -- "$ROOTSNAP"
    [ "${ROOT_COUNTERS_MADE:-0}" = 1 ] && $SUDO rmdir -- /counters 2>/dev/null; ROOT_COUNTERS_MADE=0
fi
install_module "$W/mod_whisper_edge.so"
write_main "$(main_block deny)" "useIpInProxyHeader       0"
restart_server || bad "binding: the server did not restart with the shipped module"

# ---- 27e. M3: a plane truncated in place after the main process armed it, and the workers forked after it -------
# The main process verifies and maps the planes at configuration load, before any fork, and every worker inherits that
# mapping. Here the plane is a format-1 reputation plane of 16,384 four-address ranges over 198.18.0.0/16, and it is
# shortened in place at byte 139264 (a page boundary): the range table stays whole and the records of every range from
# 198.18.125.0 up are gone, so a lookup there reads past the new end of file. The tick is held in every worker
# (WE_MOD_TEST_PAUSE_TICK at `tick`) from before the truncate, so only a worker start can notice it. The original
# workers have no start left, so each one that answers a tail request dies of SIGBUS on the read: the known residual,
# certain under the pause rather than a race. The server forks a replacement for each, after the truncate,
# from the main process's mapping; its start must notice the inherited plane changed and disarm it before its first
# accept, so every later tail request is judged without the plane (fail open: the deny host allows) and no replacement
# dies. The client is 198.18.200.7 behind a trusted hop: 198.18.0.0/15 is in the hold-harmless table, and an entry
# reached past a skipped hop is not eligible for it, so the request reaches the plane. The debug build (WE_MOD_DEBUG)
# counts each request judged inside WE_MOD_DEBUG_TAIL before any plane is read, in a page the main process maps
# shared, so a worker that dies on the read keeps its count. The pass build and both controls are one build
# (debug, control, pause) but for the control's define: WE_MOD_TEST_NO_START_STAT (the start looks at nothing) and
# WE_MOD_TEST_SERVE_INHERITED (it notices and keeps serving the inherited mapping), each failing the row by name. The
# legacy snapshot.bin is a private copy, never the file, so the same truncate under it kills no worker.
M3D="$D/m3"; M3CUT=139264; M3K=200; M3C=198.18.200.7; M3TAIL=198.18.125.0-198.18.255.255
M3XFF="X-Forwarded-For: $M3C, 127.0.0.1"
M3LINE="disarmed: the armed file was rewritten in place (its size or mtime changed)"
python3 - "$W/m3.records" <<'PY'
import sys
base = (198 << 24) | (18 << 16)
with open(sys.argv[1], 'w') as f:
    for i in range(16384):
        f.write('4 %d %d sev=3\n' % (base + 4 * i, base + 4 * i + 3))
PY
python3 "$GEN" --plane reputation --out "$W/m3.bin" --format 1 --v4-index none --v6-index none --records "$W/m3.records" >/dev/null \
    || bad "M3: the generator did not write the 16,384-range plane"
# the layout, read from the file rather than assumed: the records follow the range table, one byte each, so the cut
# keeps the records of the first (cut - records offset) ranges, and the first range it strips starts the tail
M3LAY=$(python3 - "$W/m3.bin" "$M3CUT" <<'PY'
import ipaddress, os, sys
size, cut = os.path.getsize(sys.argv[1]), int(sys.argv[2])
recs = size - 16384
first = cut - recs if 0 < cut - recs < 16384 else -1
start = ipaddress.ip_address((198 << 24) | (18 << 16) | (4 * first)) if first >= 0 else '-'
print('%d %d %d %s %d' % (size, recs, first, start, cut % 4096))
PY
)
read -r M3SIZE M3RECS M3FIRST M3START M3PAGE <<<"$M3LAY"
[ "$M3START" = "${M3TAIL%%-*}" ] && [ "$M3PAGE" = 0 ] && [ "$M3SIZE" -gt "$M3CUT" ] \
    && ok "M3: the plane is $M3SIZE bytes with its records from byte $M3RECS, so the cut at $M3CUT (a page boundary) strips the records of range $M3FIRST onward, which starts at $M3START, the debug build's tail ($M3TAIL)" \
    || bad "M3: the plane's layout ($M3LAY) does not put the cut at the tail $M3TAIL"
m3_block() { # m3_block <data|legacy>
    local src
    if [ "$1" = data ]; then src="whisper_edge_data            $M3D"; else src="whisper_edge_snapshot        $M3D/snapshot.bin"; fi
    printf 'module mod_whisper_edge {\n    ls_enabled                   1\n    %s\n    whisper_edge_summary         %s\n    whisper_edge_refresh         10\n    whisper_edge_trusted_proxy   127.0.0.1\n    whisper_edge_trusted_header  X-Forwarded-For\n    whisper_edge_policy          deny if listed >= high\n}\n' "$src" "$D/counters"
}
m3_tail_n() { # the lineage's tail count, from a live worker's status file (the page is shared, so every one agrees)
    local p f
    for p in $(workers); do
        f=$($SUDO find "$D/counters" -maxdepth 1 -name "$p-*.status" 2>/dev/null | head -1)
        [ -n "$f" ] && $SUDO sed -n 's/^debug tail-requests \([0-9]*\)$/\1/p' "$f" | head -1 && return 0
    done
}
m3_log() { $SUDO tail -n +"$M3_FROM" "$ELOG" 2>/dev/null; }
m3_signalled() { m3_log | sed -n 's/.*\[AutoRestarter\] child process with pid=\([0-9]*\) received signal=\([0-9]*\).*/\1 \2/p'; }
# a death after the cut is a process outside the originals: the main process forks nothing after it but replacements
m3_post_dead() { comm -13 <(tr ' ' '\n' <<<"$M3_W0" | grep . | sort -u) <(m3_signalled | awk '{print $1}' | sort -u) | grep -c . || true; }
# M3's two controls are named in full where they are built (the control-bodies guard reads every WE_MOD_TEST_* name
# literally); M3V is the short part their object files and labels carry
m3_short() { case "$M3CTL" in WE_MOD_TEST_NO_START_STAT) M3V=NO_START_STAT ;; WE_MOD_TEST_SERVE_INHERITED) M3V=SERVE_INHERITED ;; esac; }
m3_phase() { # m3_phase <module> <data|legacy> -> M3_* results
    local mod=$1 src=$2 f i c p dead n0
    $SUDO rm -rf -- "$M3D"; $SUDO mkdir -p "$M3D"; $SUDO chmod 0755 "$M3D"
    if [ "$src" = data ]; then f="$M3D/reputation.bin"; else f="$M3D/snapshot.bin"; fi
    M3_NAME=${f##*/}
    $SUDO install -o root -g root -m 0444 "$W/m3.bin" "$f"
    $SUDO rm -f "$PD"/tick "$PD"/held.*
    install_module "$mod"
    write_main "$(m3_block "$src")" "useIpInProxyHeader       0"
    fresh_start "env WE_MOD_PAUSE_DIR=$PD WE_MOD_DEBUG_TAIL=$M3TAIL" || bad "M3: the server did not start ($mod, $src)"
    sleep 0.5; load_lines
    M3_DEBUG=$(count_line 'debug build (WE_MOD_DEBUG)')
    req WhisperDeny "$(u $PDENY /index.html)" -H "$M3XFF"; M3_PRE="$CODE $(field "$LINE" listed) $(field "$LINE" gen)"
    await_tick || true
    M3_N0=$(m3_tail_n)
    : > "$PD/tick"
    M3_HELD=no; await "all_held tick" $((2 * REFRESH_S + 8)) && M3_HELD=yes
    M3_W0=$(workers)
    M3_FROM=$(( $(elog_lines) + 1 ))
    $SUDO sh -c 'chmod 0644 "$1" && truncate -s "$2" "$1" && chmod 0444 "$1"' sh "$f" "$M3CUT"
    M3_TSIZE=$($SUDO stat -c %s "$f")
    # the originals: one tail request at a time until none is left (each that answers one dies on the read), at most 40
    M3_SENT=0; M3_ORIG=""; dead=0
    if [ "$src" = data ]; then
        for i in $(seq 40); do
            dead=0; for p in $M3_W0; do [ -d "/proc/$p" ] || dead=$((dead + 1)); done
            [ "$dead" = "$(wc -w <<<"$M3_W0")" ] && break
            c=$(code -H "$M3XFF" "$(u $PDENY /index.html)"); M3_SENT=$((M3_SENT + 1)); M3_ORIG="$M3_ORIG $c"
            sleep 0.3
        done
        await "[ \"\$(workers | wc -w)\" -ge $WORKERS ]" 20 || true
    fi
    M3_ORIGDEAD=$dead
    # K tail requests: to the replacements forked after the truncate (data), or to the held originals (legacy). The
    # loop stops at the first death of a process forked after the truncate, which already fails the row, so a control
    # build is not driven through K crashes
    n0=$(alog_n WhisperDeny); M3_CODES=""
    for i in $(seq "$M3K"); do
        c=$(code -H "$M3XFF" "$(u $PDENY /index.html)"); M3_SENT=$((M3_SENT + 1)); M3_CODES="$M3_CODES
$c"
        if [ "$src" = data ] && [ "$c" != 200 ] && [ "$(m3_post_dead)" -gt 0 ]; then break; fi
    done
    M3_ANS=$(grep . <<<"$M3_CODES" | sort | uniq -c | awk '{printf "%s%sx%s", s, $1, $2; s=" "}')
    await "[ \"\$(alog_n WhisperDeny)\" -ge $((n0 + $(grep -c . <<<"$M3_CODES"))) ]" 10 || true
    M3_GENS=$(alog WhisperDeny | tail -n +"$((n0 + 1))" | while IFS= read -r l; do field "$l" gen; done | sort | uniq -c | awk '{c=$1; $1=""; printf "%s%sx%s", s, c, $0; s="; "}')
    M3_SIG=$(m3_signalled | awk '{printf "%s%s:%s", s, $1, $2; s=" "}')
    M3_POSTDEAD=$(m3_post_dead)
    M3_ORIGSIG7=$(m3_signalled | awk '$2 == 7 {print $1}' | grep -cxF -f <(tr ' ' '\n' <<<"$M3_W0" | grep .) || true)
    M3_PIDS1=$(m3_log | sed -n 's/^.*\[AutoRestarter\] new child process with pid=\([0-9]*\) is forked.*/\1/p' | sort -u | tr '\n' ' ')
    M3_NSTART=0; M3_NOTICED=0; M3_DISARMED=0
    for p in $M3_PIDS1; do
        M3_NSTART=$((M3_NSTART + 1))
        m3_log | grep -F "] [$p] [whisper_edge]" | grep -F "plane $M3_NAME" | hit -F "rewritten in place" && M3_NOTICED=$((M3_NOTICED + 1))
        m3_log | grep -F "] [$p] [whisper_edge]" | hit -F "plane $M3_NAME $M3LINE" && M3_DISARMED=$((M3_DISARMED + 1))
    done
    rm -f "$PD/tick"
    await_tick || true
    M3_N1=$(m3_tail_n)
    $SUDO rm -f "$PD"/held.*
}
m3_report() { # m3_report <label>: the live figures the row judges, printed beside the verdicts
    echo "    M3 $1: before the cut \"$M3_PRE\", every tick held: $M3_HELD, the file $M3_TSIZE bytes after it, tail count $M3_N0 -> $M3_N1 over $M3_SENT sent"
    echo "    M3 $1: originals [$M3_W0] answered [${M3_ORIG# }], replacements [${M3_PIDS1% }], the K requests answered [$M3_ANS], tokens [$M3_GENS], signals [$M3_SIG]"
    echo "    M3 $1: of $M3_NSTART replacement starts, $M3_NOTICED noticed the rewrite and $M3_DISARMED disarmed it"
}
# the three named checks a data phase is judged by; each prints its own line, and returns 0 when it held
m3_check_notice() { [ "$M3_NSTART" -ge 1 ] && [ "$M3_NOTICED" = "$M3_NSTART" ]; }
m3_check_disarm() { [ "$M3_NSTART" -ge 1 ] && [ "$M3_DISARMED" = "$M3_NSTART" ]; }
m3_check_serve()  { [ "$M3_POSTDEAD" = 0 ] && [ "$M3_ANS" = "${M3K}x200" ] && ! grep -q 'reputation:1\.' <<<"$M3_GENS"; }
m3_failing() { # the row's first failing check, by name, or nothing when it held
    if ! m3_check_notice; then echo "the worker start did not notice the inherited plane truncated in place ($M3_NOTICED of $M3_NSTART replacements)"
    elif ! m3_check_disarm; then echo "the worker start left the truncated inherited mapping serving, not disarmed before the first accept ($M3_DISARMED of $M3_NSTART replacements)"
    elif ! m3_check_serve; then echo "a tail request after the truncate was not judged without the plane by a live replacement (answers $M3_ANS, $M3_POSTDEAD post-truncate deaths)"
    fi
}
if build_debug "$W/dbg-m3.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK"; then
    m3_phase "$W/dbg-m3.so" data
    m3_report "(the debug build)"
    case "$M3_PRE" in "403 high reputation:1."*) [ "$M3_DEBUG" -ge 1 ] \
        && ok "M3: the debug build names itself at load, and before the cut the tail client $M3C (past a trusted hop, so not hold-harmless) is judged on the plane: $M3_PRE" \
        || bad "M3: the object loaded is not the debug build ($M3_DEBUG debug lines)" ;;
        *) bad "M3: before the cut the tail client was not judged on the plane: \"$M3_PRE\"" ;; esac
    [ "$M3_HELD" = yes ] && [ "$M3_TSIZE" = "$M3CUT" ] && [ "$M3_ORIGDEAD" -ge 1 ] && [ "$M3_ORIGSIG7" = "$M3_ORIGDEAD" ] && [ "$M3_ORIGDEAD" -le "$WORKERS" ] \
        && ok "M3: every tick held, the plane cut in place to $M3_TSIZE bytes, and each original worker that answers a tail request dies of signal 7 on the read past the end ($M3_ORIGSIG7 of $(wc -w <<<"$M3_W0")): the residual, certain under the pause" \
        || bad "M3: the residual: held $M3_HELD, size $M3_TSIZE, $M3_ORIGDEAD originals gone, $M3_ORIGSIG7 by signal 7 ($M3_SIG)"
    m3_check_notice && m3_check_disarm \
        && ok "M3: each of the $M3_NSTART workers forked after the cut noticed the inherited plane changed and disarmed it at its start, before its first accept: plane $M3_NAME $M3LINE" \
        || bad "M3: $(m3_failing)"
    m3_check_serve \
        && ok "M3: and all $M3K tail requests after them are judged without the plane, never read past the end: ${M3K} x 200 (fail open on the deny host), tokens [$M3_GENS], no process forked after the cut died" \
        || bad "M3: after the cut: answers [$M3_ANS], tokens [$M3_GENS], $M3_POSTDEAD deaths of processes forked after it ($M3_SIG)"
    [ -n "$M3_N0" ] && [ "$M3_N1" = "$((M3_N0 + M3_SENT))" ] \
        && ok "M3: the debug build counted every tail request, the dying originals' too, in the lineage's shared page: $M3_N0 before the cut, $M3_N1 after $M3_SENT more" \
        || bad "M3: the tail count read $M3_N0 then $M3_N1 over $M3_SENT tail requests"
    # the two controls by their full names, so the control-bodies guard reads each one
    for M3CTL in WE_MOD_TEST_NO_START_STAT WE_MOD_TEST_SERVE_INHERITED; do
        m3_short
        if build_debug "$W/dbg-m3-$M3V.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK -D$M3CTL"; then
            m3_phase "$W/dbg-m3-$M3V.so" data
            m3_report "(control $M3V)"
            M3F=$(m3_failing)
            case "$M3CTL:$M3F" in
                "WE_MOD_TEST_NO_START_STAT:the worker start did not notice"*|"WE_MOD_TEST_SERVE_INHERITED:the worker start left the truncated inherited mapping serving"*)
                    ctl 0 "$M3CTL fails the row by name: $M3F; processes forked after the cut that died: $M3_POSTDEAD (signals $M3_SIG)" ;;
                *) ctl 1 "$M3CTL (the row's verdict: ${M3F:-held})" ;;
            esac
        else
            bad "M3: the $M3CTL control build failed"
        fi
    done
    m3_phase "$W/dbg-m3.so" legacy
    m3_report "(the legacy snapshot)"
    [ "$M3_HELD" = yes ] && [ "$M3_TSIZE" = "$M3CUT" ] && [ "$M3_ANS" = "${M3K}x403" ] && [ -z "$M3_SIG" ] && [ "$M3_N1" = "$((M3_N0 + M3_SENT))" ] \
        && ok "M3: the same cut under the legacy $M3_NAME (a private copy, never the file) kills no worker: the held originals answer all $M3K tail requests from the copy (${M3K} x 403), no signal, every request counted" \
        || bad "M3: the legacy $M3_NAME after the cut: held $M3_HELD, size $M3_TSIZE, answers [$M3_ANS], signals [$M3_SIG], tail count $M3_N0 -> $M3_N1 over $M3_SENT"
else
    bad "M3: the debug build with the tick's pause failed"
fi
for M3CTL in WE_MOD_TEST_NO_START_STAT WE_MOD_TEST_SERVE_INHERITED; do
    m3_short
    if build_module "$W/ctl-m3-$M3V-refused.so" "-D$M3CTL" >/dev/null 2>&1; then bad "M3: $M3CTL built outside a control build"; else ok "M3: $M3CTL is refused outside a control build"; fi
done
$SUDO rm -rf -- "$M3D"; $SUDO rm -f "$PD"/tick "$PD"/held.*
install_module "$W/mod_whisper_edge.so"
write_main "$(main_block deny)" "useIpInProxyHeader       0"
restart_server || bad "M3: the server did not restart with the shipped module"

# ---- 28. the late build: a host's block arriving in a worker after the configuration was built -------------------
# OpenLiteSpeed 1.9.3 never does this (every parse_config precedes MAIN_INITED, measured), so a control build hands
# the module a host named late-test in WORKER_INIT. The late host runs no context rules, one ERROR line names it,
# the process line carries late-build, --status exits 1, and the floor still runs. The file-system-call count on
# the loop that this row also names waits on the core's per-tid counters.
if build_module "$W/ctl-late.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_LATE_BUILD"; then
    install_module "$W/ctl-late.so"
    write_main "$(main_block deny)" "useIpInProxyHeader       0"
    restart_server || bad "late: the server did not start with the late-build control"
    sleep 0.5; load_lines
    line=$(line_of 'vhost late-test: its module block arrived after the configuration was built')
    [ -n "$line" ] && ok "late: one ERROR line names the late host: $(printf '%s' "$line" | cut -c1-140)" || bad "late: no line for the late host"
    await_tick
    LW=$(workers | awk '{print $1}')
    SF=$($SUDO ls "$D/counters" | grep -E "^$LW-[0-9a-f]{16}\.status$" | head -1)
    [ -n "$SF" ] && $SUDO grep -qE "^process .* pid $LW .* late-build" "$D/counters/$SF" && ok "late: the live worker $LW's process line carries late-build" || bad "late: no late-build on the process line of ${SF:-no status file for $LW}: $($SUDO grep '^process' "$D/counters/${SF:-x}" 2>/dev/null | cut -c100-260)"
    STAT=$($SUDO "$SUMMARY_BIN" --status "$D/counters" 2>&1); SRC=$?
    is "$SRC" "1" "late: whisper-edge-summary --status exits 1 on the late-build flag" "late: --status exit"
    req WhisperDeny "$(u $PDENY /index.html)" -H "X-Forwarded-For: $LCRIT"
    want 403 "late: and the floor still runs in that worker (a CRITICAL client is denied)" "the floor stopped with the late build"
    echo "    n/a: the file-system-call count on the loop during the late build waits on the core's per-tid counters"
    if build_module "$W/ctl-late-refused.so" "-DWE_LS_TEST_LATE_BUILD" >/dev/null 2>&1; then bad "late: the control define built outside a control build"; else ok "late: WE_LS_TEST_LATE_BUILD is refused outside a control build"; fi
    install_module "$W/mod_whisper_edge.so"
else
    bad "late: the late-build control did not build"
fi


# ---- 29. the transition line through the server's logger: a roll, the 511-byte bound, the head ------------------
# The core writes one entry per distinct program with a plane-dependent rule when a plane's kind changes, into the
# status file's ring and, byte for byte, to the module's logger, which is the server's own log call. Each phase
# loads a fresh tenant plane and a tor and a reputation generation that go stale fifteen seconds apart, two hosts
# with no listener (a 256-rule program alternating allow and log on tor, and a two-rule program reading both
# planes), and a small rollingSize over an error log emptied before the start, so the server rolls it after the
# workers are up and before the first transition. Nothing is published after the start: tor going stale is the
# first event a worker sees, so its entry proves the baseline is taken at worker start, not at the first apply. The
# 256-rule entry's uncut length is computed before the run from the formatter's grammar; every entry is compared
# with the status file's own text. The server's own error log is set aside for the section and put back after it.
Q6_ROLL=${Q6_ROLL:-4K}
$SUDO mv "$ELOG" "$LSWS/logs/error-pre-q6.log"
q6_alt_rules() { local r=1; while [ $r -le 256 ]; do if [ $((r % 2)) = 1 ]; then echo "    whisper_edge_policy    allow if tor_exit"; else echo "    whisper_edge_policy    log if tor_exit"; fi; r=$((r + 1)); done; }
q6_read() { # q6_read <live log> <rolled logs dir> <status file> -> key=value lines and the entries, parsed in Python
    python3 -I - "$@" <<'PY'
import glob, os, re, sys
live, rdir, status = sys.argv[1], sys.argv[2], sys.argv[3]
MARK = b"whisper edge: policy: plane "
def entries(path):
    out = []
    try:
        data = open(path, "rb").read()
    except OSError:
        return out
    for ln in data.split(b"\n"):
        i = ln.find(MARK)
        if i >= 0:
            out.append(ln[i + len(b"whisper edge: policy: "):])
    return out
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
st = []
for ln in open(status, "rb").read().split(b"\n"):
    m = re.match(rb'^transition [0-9]+ "(.*)"$', ln)
    if m:
        st.append(unesc(m.group(1)))
lv = entries(live)
rolled = [p for p in glob.glob(os.path.join(rdir, "error.log.*"))]
rl = [e for p in rolled for e in entries(p)]
alt = lambda e: b"allow captures; rules 2,4," in e or b"allow captures; rules 2,4," in e[:600]
def first(lst, pred):
    for e in lst:
        if pred(e): return e
    return b""
for name, lst in (("live", lv), ("rolled", rl), ("status", st)):
    print("%s_n=%d" % (name, len(lst)))
tor_head = b"plane tor stale out=tor tenant="
rep_head = b"plane reputation stale out=reputation,tor tenant="
a_live = first(lv, lambda e: e.startswith(tor_head) and b"rules 1,3,5" in e)
a_st = first(st, lambda e: e.startswith(tor_head) and b"rules 1,3,5" in e)
a_rl = first(rl, lambda e: e.startswith(tor_head) and b"rules 1,3,5" in e)
h_live = first(lv, lambda e: e.startswith(rep_head))
h_st = first(st, lambda e: e.startswith(rep_head))
# every transition entry the server's logger wrote, the live file and the rolled ones (the head grammar only: the
# planes' state notices share the prefix and are not ring entries)
al = [e for e in lv + rl if re.match(rb"^plane [a-z-]+ [a-z]+ out=", e)]
a_any = first(al, lambda e: e.startswith(tor_head) and b"rules 1,3,5" in e)
h_any = first(al, lambda e: e.startswith(rep_head))
print("bound_any_len=%d" % len(a_any))
print("bound_any_equal=%d" % (1 if a_any and a_any == a_st else 0))
print("bound_any_head=%s" % a_any.split(b":")[0].decode("ascii", "replace"))
print("head2_any=%s" % h_any.split(b":")[0].decode("ascii", "replace"))
print("head2_any_equal=%d" % (1 if h_any and h_any == h_st else 0))
print("head2_any_text=%d" % (1 if b":" in h_any else 0))
print("all_equal_any=%d" % (1 if al and all(e in st for e in al) else 0))
print("rolled_files=%d" % len(rolled))
print("bound_live_len=%d" % len(a_live))
print("bound_st_len=%d" % len(a_st))
print("bound_rolled_len=%d" % len(a_rl))
print("bound_equal=%d" % (1 if a_live and a_live == a_st else 0))
print("bound_head=%s" % a_live.split(b":")[0].decode("ascii", "replace"))
print("head2_live=%s" % h_live.split(b":")[0].decode("ascii", "replace"))
print("head2_equal=%d" % (1 if h_live and h_live == h_st else 0))
print("head2_has_text=%d" % (1 if b":" in h_live else 0))
print("tenant_word=%s" % (re.search(rb"tenant=([a-z]+)", a_st or h_st or b"tenant=-").group(1).decode()))
print("live_equal_all=%d" % (1 if lv and all(e in st for e in lv) else 0))
PY
}
q6_model() { # the uncut length of the 256-rule entry, from the formatter's grammar, for a tenant word
    python3 -I - "$1" <<'PY'
import sys
head = "plane tor stale out=tor tenant=%s" % sys.argv[1]
odd = ",".join(str(i) for i in range(1, 256, 2)); even = ",".join(str(i) for i in range(2, 257, 2))
line = head + ":" + " rules " + odd + " allow captures" + "; rules " + even + " disarmed"
print("%d %d %d %d" % (len(line), len(head), len(odd), len(even)))
PY
}
q6_phase() { # q6_phase <module .so> <label> <tenant valid-until ms, or 0> -> sets Q_* from q6_read
    local so=$1 lbl=$2 tvu=$3 now t1 t2 hosts sf lw t0
    install_module "$so"
    Q6G=$((Q6G + 1)); now=$(date +%s%3N); t1=$((now + 75000)); t2=$((now + 90000))
    python3 "$GEN" --plane tor --out "$W/q6tor.bin" --format 2 --synthetic 3 3 --generation "$Q6G" --valid-until "$t1" >/dev/null
    python3 "$GEN" --plane reputation --out "$W/q6rep.bin" --format 1 --v4-index radix-16 --v6-index none --synthetic 4 4 --generation "$Q6G" --valid-until "$t2" >/dev/null
    python3 "$GEN" --plane tenant --out "$W/q6ten.bin" --format 2 --synthetic 1 1 --generation "$Q6G" --valid-until "$tvu" >/dev/null
    $SUDO install -o root -g root -m 0444 "$W/q6tor.bin" "$D/planes/tor.bin"
    $SUDO install -o root -g root -m 0444 "$W/q6rep.bin" "$D/planes/reputation.bin"
    $SUDO install -o root -g root -m 0444 "$W/q6ten.bin" "$D/planes/tenant.bin"
    q6_alt_rules > "$W/q6alt.conf"
    printf '    whisper_edge_policy    deny if listed >= high\n    whisper_edge_policy    log if tor_exit\n' > "$W/q6two.conf"
    hosts="$(corpus_vhost q6alt "$W/q6alt.conf")
$(corpus_vhost q6two "$W/q6two.conf")"
    ROLLING=$Q6_ROLL write_main "$(corpus_main)" "useIpInProxyHeader       0
$hosts"
    $SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1; await '! server_alive' 20 || true
    $SUDO sh -c 'rm -f "$1"/error.log.* "$1"/error.log' sh "$LSWS/logs"
    t0=$(now_ms)
    start_server || { bad "Q6 $lbl: the server did not start"; return 1; }
    await "[ \"\$(status_gen tor)\" = $Q6G ]" $((2 * REFRESH_S + 8)) || { bad "Q6 $lbl: tor generation $Q6G not armed: $(status_state tor) $(status_gen tor)"; return 1; }
    # the server rolls the emptied log once its start lines pass rollingSize, after the workers are up
    await "[ \"\$(q6_rolled)\" -ge 1 ]" 70 || true
    echo "    Q6 $lbl: $(q6_rolled) rolled file(s) at rollingSize $Q6_ROLL, $(( ($(now_ms) - t0) / 1000 )) s after the start; tor $(status_state tor) at that moment"
    await "[ \"\$(status_state reputation)\" = stale ]" $(( (t2 - $(date +%s%3N)) / 1000 + 2 * REFRESH_S + 8 )) || echo "    Q6 $lbl: reputation reads $(status_state reputation) at the deadline"
    await_tick
    lw=$(workers | awk '{print $1}')
    sf=$($SUDO find "$D/counters" -maxdepth 1 -name "$lw-*.status" | head -1)
    $SUDO cp "$ELOG" "$W/q6-live.log"; $SUDO sh -c 'mkdir -p "$2" && cp "$1"/error.log.* "$2"/ 2>/dev/null; true' sh "$LSWS/logs" "$W/q6-rolled"
    $SUDO cp "$sf" "$W/q6.status"; $SUDO chown -R "$(id -u)" "$W/q6-live.log" "$W/q6-rolled" "$W/q6.status"
    Q_dropped=$(grep -oE 'log-dropped [0-9]+' "$W/q6.status" | awk '{print $2}')
    unset Q_bound_any_len Q_bound_any_equal Q_bound_any_head Q_head2_any Q_head2_any_equal Q_head2_any_text Q_all_equal_any Q_live_n Q_rolled_n Q_status_n Q_rolled_files Q_bound_live_len Q_bound_st_len Q_bound_rolled_len Q_bound_equal Q_bound_head Q_head2_live Q_head2_equal Q_head2_has_text Q_tenant_word Q_live_equal_all
    while IFS='=' read -r k v; do eval "Q_$k=\$v"; done < <(q6_read "$W/q6-live.log" "$W/q6-rolled" "$W/q6.status")
    rm -rf "$W/q6-rolled"
    echo "    Q6 $lbl: entries live ${Q_live_n:-?}, rolled ${Q_rolled_n:-?}, status ${Q_status_n:-?}; the 256-rule entry live ${Q_bound_live_len:-?} bytes, status ${Q_bound_st_len:-?}, rolled ${Q_bound_rolled_len:-?}; log-dropped ${Q_dropped:-?}"
    return 0
}
q6_rolled() { $SUDO sh -c 'ls "$1"/error.log.* 2>/dev/null | wc -l' sh "$LSWS/logs"; }
Q6G=10
read -r Q6_UNCUT Q6_HEADLEN Q6_ODD Q6_EVEN < <(q6_model fresh)
echo "    Q6 model: the 256-rule entry uncut is $Q6_UNCUT bytes: the head $Q6_HEADLEN + ':' 1 + ' rules ' 7 + the odd rules $Q6_ODD + ' allow captures' 15 + '; rules ' 8 + the even rules $Q6_EVEN + ' disarmed' 9"
is "$Q6_UNCUT" "990" "Q6: the model computes the uncut entry at 990 bytes before the run" "Q6: the model's uncut length"
if q6_phase "$W/mod_whisper_edge.so" "production" 0; then
    # OpenLiteSpeed 1.9.3 rolls the error log by renaming it, and a process that had it open before the roll keeps
    # writing the renamed file until its restart (measured: after a roll past the workers' start, every later line,
    # the server's own and the module's, is in error.log.<date> and the live file stays empty). The module logs through
    # the server's own log call, so its lines go where the server's go; where that is, is printed, never asserted.
    nt=$(grep -c '^transition [0-9]* "plane tor stale' "$W/q6.status"); nr=$(grep -c '^transition [0-9]* "plane reputation stale' "$W/q6.status")
    # the programs with a tor rule are the two fixture hosts (the standard hosts read reputation only, and this
    # configuration has no floor), so the tor transition writes two entries; the reputation one writes $nr
    if [ "$nt" = 2 ]; then
        ok "Q6: the first event after the start (tor stale, nothing applied before it) is in the ring: 2 entries, one per program with a tor rule (the reputation transition after it wrote $nr)"
    else
        bad "Q6: the first transition after the start: $nt tor-stale entries in the ring, wanted 2 (the reputation transition wrote $nr)"
    fi
    echo "    measured: after the roll, transition entries in the live file ${Q_live_n:-?}, in the rolled file ${Q_rolled_n:-?}; the server's logger, which the module uses, did not reopen the live file"
    is "${Q_bound_any_len:-0}|${Q_bound_any_equal:-0}" "511|1" \
        "Q6: the 256-rule entry the server's logger wrote is exactly 511 bytes after the server's prefix, byte-identical to the status file's transition text" \
        "Q6: the 256-rule entry in the log (bytes|equal to the status)"
    is "${Q_bound_any_head:-}" "plane tor stale out=tor tenant=fresh" "Q6: its head is intact: plane tor stale out=tor tenant=fresh" "Q6: the 256-rule entry's head"
    is "${Q_head2_any:-}|${Q_head2_any_equal:-0}" "plane reputation stale out=reputation,tor tenant=fresh|1" \
        "Q6: the second transition's head reads out=reputation,tor in plane order, the entry equal to the status file's" "Q6: the second head"
    is "${Q_all_equal_any:-0}" "1" "Q6: every transition entry in the log is one of the status file's entries, byte for byte" "Q6: a logged entry absent from the status ring"
    is "${Q_dropped:-x}" "0" "Q6: log-dropped 0" "Q6: log-dropped"
fi
if q6_phase "$W/mod_whisper_edge.so" "lapsed tenant" $(( $(date +%s%3N) - 49 * 3600 * 1000 )); then
    is "${Q_tenant_word:-}" "lapsed" "Q6: with tenant.bin past its valid-until and its 48 h grace, the head reads tenant=lapsed" "Q6: the tenant word with a lapsed tenant"
fi
if build_module "$W/ctl-uncut.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_UNCUT_LOG" && q6_phase "$W/ctl-uncut.so" "uncut control" 0; then
    if [ "${Q_bound_any_len:-0}" = "$Q6_UNCUT" ] && [ "${Q_bound_st_len:-0}" = 511 ]; then ctl 0 "the uncut build logs the 256-rule entry at $Q6_UNCUT bytes, the model's figure, against the ring's 511"; else ctl 1 "the uncut build (logged ${Q_bound_any_len:-?}, ring ${Q_bound_st_len:-?})"; fi
fi
if build_module "$W/ctl-head.so" "-DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_HEAD_ALONE" && q6_phase "$W/ctl-head.so" "head-alone control" 0; then
    if [ "${Q_head2_any_text:-1}" = 0 ] && [ "${Q_head2_any_equal:-1}" = 0 ]; then ctl 0 "a build logging the head alone differs from the status entry (no dependents text on the line)"; else ctl 1 "the head-alone build (text ${Q_head2_has_text:-?}, equal ${Q_head2_equal:-?})"; fi
fi
if build_module "$W/ctl-dup.so" "-DWE_MOD_CONTROL_BUILD -DWE_LS_TEST_DUP_LOG" && q6_phase "$W/ctl-dup.so" "dup-descriptor control" 0; then
    # blind on this server: the server's own logger keeps the pre-roll descriptor too, so the two builds land in the
    # same file; printed beside the production phase's figures, never a pass
    echo "    n/a: the descriptor control on OpenLiteSpeed 1.9.3: live ${Q_bound_live_len:-?}, rolled ${Q_bound_rolled_len:-?}, the same file the server's logger uses after a roll, so it cannot fail the production build here"
fi
if build_module "$W/ctl-dup-refused.so" "-DWE_LS_TEST_DUP_LOG" >/dev/null 2>&1; then bad "Q6: WE_LS_TEST_DUP_LOG built outside a control build"; else ok "Q6: WE_LS_TEST_DUP_LOG is refused outside a control build"; fi
$SUDO "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1; await '! server_alive' 20 || true
$SUDO sh -c 'cat "$1"/error.log >> "$1"/error-pre-q6.log 2>/dev/null; rm -f "$1"/error.log.* "$1"/error.log; mv "$1"/error-pre-q6.log "$1"/error.log' sh "$LSWS/logs"
$SUDO install -o root -g root -m 0444 "$W/rep.bin" "$D/planes/reputation.bin"; $SUDO install -o root -g root -m 0444 "$W/tor.bin" "$D/planes/tor.bin"; $SUDO rm -f "$D/planes/tenant.bin"
install_module "$W/mod_whisper_edge.so"

ctl_window_close
[ "$CTL_ARMS" -ge 1 ] && [ -z "$CTL_SIG" ] \
    && ok "controls: every control arm's workers exited normally: $CTL_ARMS control modules served, no worker killed by a signal (M3's debug modules, whose originals dying of signal 7 is the row, are not counted)" \
    || bad "controls: workers killed by a signal under a control arm:${CTL_SIG:- none, but no arm was windowed}"

finish
