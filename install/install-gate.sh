#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Prove the installer and the refresh script against the LIVE feed..
#
# An installer nobody has run is a document, not a deliverable - so this runs the real script
# against the real feed and asserts the properties that make it safe to put on somebody's web
# server. It needs no root and touches nothing outside its own temp directory: every case drives
# the script with --dir, which is the same code path the installed copy takes. The exceptions run
# under passwordless sudo on a fixture of their own under /var/lib, and are SKIPPED without it: the
# keyed unit's sandbox rows (keyed-gate.sh) and the immutable attribute under the refresh units'.
#
# The cases are chosen for what goes wrong in the field, not for coverage:
#   - a feed we cannot reach must leave the installed snapshot alone (fail-open, the core's rule
#     applied to the delivery path)
#   - a snapshot whose signature does not verify must NEVER reach the path the server reads
#   - a second run must not rewrite an unchanged file, because an mtime change makes every module
#     think the policy moved
#   - the resolver half keeps each of a real BIND's policy zones current, verified by its signature,
#     and replaces it by the fleet's empty zone once it is past its validUntil (rpz-bind-gate.sh,
#     which this runs)
#
# The --plane cases run first and need no network: a local stub publishes a signed manifest. With
# INSTALL_GATE_PLANES_ONLY=1 they are the whole run, for a host that cannot reach the live feed.
# The keyed cases (keyed-gate.sh, run right after them) need no network either: a fake feed speaks the
# keyed grammar on two loopback addresses. They run in both modes; the ones under the keyed unit's
# sandbox need passwordless sudo and systemd-run, and without them the gate says INCOMPLETE.
#
# Every check below reads `condition && pass ... || fail ...`. That is an if/else only because pass
# cannot fail (it prints and counts), which is the one thing shellcheck's SC2015 asks to be sure of.
# shellcheck disable=SC2015
set -eu
# A normal operator's permissions for everything the gate creates: a box whose umask is 002 made the
# printed block's directory 0775, and nginx's StrictModes rightly refused it, so the row measured the
# box's umask rather than the module. The printed-block row also proves a 0775 directory is refused.
umask 022

HERE="$(cd "$(dirname "$0")" && pwd)"
REFRESH="${INSTALL_GATE_REFRESH:-$HERE/whisper-edge-refresh}" # (a control points it at another copy)
BASE="${WHISPER_EDGE_BASE:-https://whisper.online/edge}"
# the work directory holds the printed block's data directory, and a plane's directory gets no sticky
# exception (root's /tmp above it is refused by the module's trust walk), so it lives under a base the
# running user owns: the runtime directory, else home; INSTALL_GATE_TMP names another
for WBASE in "${INSTALL_GATE_TMP:-}" "${XDG_RUNTIME_DIR:-}" "${HOME:-}"; do
  [ -n "$WBASE" ] && [ -d "$WBASE" ] && [ -O "$WBASE" ] && break
  WBASE=""
done
[ -n "$WBASE" ] || { echo "install gate: no directory this user owns for the work tree (set INSTALL_GATE_TMP)" >&2; exit 2; }
W="$(mktemp -d "$WBASE/whisper-edge-install-gate.XXXXXX")"
stop_servers() {
  if [ -f "$W/plane-servers.pid" ]; then xargs kill < "$W/plane-servers.pid" 2>/dev/null || true; fi
  rm -f "$W/plane-servers.pid"
}
# The teardown clears the immutable attribute first: a root run installs planes immutable, and rm -rf
# cannot remove one, so a cleanup without the clear would leak the work tree on exactly the host the
# certifying run uses. Anything under sudo (SUDO_DIR) is cleared and removed the same way.
SUDO_DIR=""
# Every step is guarded, because this runs under set -eu: chattr -R exits 1 on a symlink or a fifo
# ("Operation not supported while reading flags"), and an unguarded one would end the trap before the
# rm -rf it exists for. A tree that is still there afterwards is said, and fails the run: a leak is
# never silent.
cleanup() {
  stop_servers
  chattr -R -i "$W" 2>/dev/null || true
  rm -rf "$W" 2>/dev/null || true
  if [ -n "$SUDO_DIR" ]; then
    sudo -n chattr -R -i "$SUDO_DIR" 2>/dev/null || true
    sudo -n rm -rf "$SUDO_DIR" 2>/dev/null || true
  fi
  _left=""
  [ -e "$W" ] && _left="$W"
  [ -n "$SUDO_DIR" ] && [ -e "$SUDO_DIR" ] && _left="$_left $SUDO_DIR"
  if [ -n "$_left" ]; then printf 'install gate: could not remove%s\n' "$_left" >&2; exit 1; fi
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT     # a signal ends the gate; cleaning up and carrying on would run cases on nothing
trap 'exit 143' TERM
ok=0; bad=0
pass() { printf '  ok    %s\n' "$1"; ok=$((ok+1)); }
fail() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; bad=$((bad+1)); }
# says TEXT PATTERN: grep -q over captured output, fed by a here-document rather than a pipe. A
# writer piped into grep -q can take SIGPIPE when grep stops at its first match, and under pipefail
# that turns a match into a miss.
# flip_byte FILE OFFSET: invert one byte in place (XOR 0xff), so it always changes, whatever it held
flip_byte() {
  python3 -I - "$1" "$2" <<'PY'
import sys
p, o = sys.argv[1], int(sys.argv[2])
with open(p, "r+b") as f:
    f.seek(o)
    b = f.read(1)
    if len(b) != 1:
        sys.exit("flip_byte: offset %d is past the end of %s" % (o, p))
    f.seek(o)
    f.write(bytes([b[0] ^ 0xFF]))
PY
}
says() {
  grep -q -- "$2" <<EOF
$1
EOF
}
# hasline TEXT LINE: LINE is one whole line of TEXT, compared as a fixed string
hasline() {
  grep -qxF -- "$2" <<EOF
$1
EOF
}
# facts FILE: what an installed or current line must say about FILE, computed here from the bytes and
# never from the refresh: the header's generation (byte 16), the size, digest16 (the first 16 hex digits
# of the sha256) and the valid-until (byte 32, epoch ms, 0 for no bound) in the manifest's form.
# It never fails: a file that is missing or too short to be a plane renders as a line no refresh prints,
# so the row that asked reads red instead of the assignment ending the gate under set -e.
facts() {
  python3 - "$1" <<'PY'
import datetime, hashlib, struct, sys
try:
    b = open(sys.argv[1], "rb").read()
    if len(b) < 40:
        raise ValueError("%d bytes" % len(b))
except (OSError, ValueError) as e:
    print("no facts: %s: %s" % (sys.argv[1], e)); sys.exit(0)
g, vu = struct.unpack_from("<Q", b, 16)[0], struct.unpack_from("<Q", b, 32)[0]
t = "no bound" if vu == 0 else datetime.datetime.fromtimestamp(vu // 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print("generation %d, %d bytes, digest16 %s, valid until %s" % (g, len(b), hashlib.sha256(b).hexdigest()[:16], t))
PY
}

# ===================================================================================================
# THE PLANE CASES: whisper-edge-refresh --plane against a local feed that publishes a signed manifest.
#
# Offline and first, so they run where the live feed does not publish planes yet. A stub serves
# manifest.json, manifests/<sha>.sig and planes/<sha>.bin(.sig) under a throwaway Ed25519 key, and the
# base names a host that does not resolve, so every case that installs anything also proves the resolver
# override pinned every fetch. The planes are the format-2 tor fixture with its generation (byte 16)
# rewritten, which is all the refresh reads of a header besides the magic, the format and the plane id.
plane_cases() {
  P="$W/planes"
  mkdir -p "$P"
  FIXTURE="$HERE/../core/testdata/format2/tor.bin"
  openssl genpkey -algorithm ed25519 -out "$P/key.pem" 2>/dev/null
  openssl pkey -in "$P/key.pem" -pubout -out "$P/key.pub" 2>/dev/null
  openssl genpkey -algorithm ed25519 -out "$P/other.pem" 2>/dev/null
  PORT1=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  PORT2=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')

  # feed <dir> <generation> [manifest-generation] [withheld|withheld2|edgy|absent|bigvu|badsig|badplanesig|badsha|nohash]
  feed() {
    rm -rf "$1"; mkdir -p "$1/edge/planes" "$1/edge/manifests"
    python3 - "$FIXTURE" "$1/plane.bin" "$2" "${4:-}" <<'PY'
import struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, int(sys.argv[3]))
if sys.argv[4] == "bigvu":
    struct.pack_into("<Q", b, 32, 2**64 - 1)
open(sys.argv[2], "wb").write(bytes(b))
PY
    psha=$(sha256sum < "$1/plane.bin" | cut -d' ' -f1)
    cp "$1/plane.bin" "$1/edge/planes/$psha.bin"
    signer="$P/key.pem"; [ "${4:-}" = badplanesig ] && signer="$P/other.pem"
    openssl pkeyutl -sign -inkey "$signer" -rawin -in "$1/plane.bin" -out "$1/edge/planes/$psha.bin.sig"
    [ "${4:-}" = nohash ] && rm -f "$1/edge/planes/$psha.bin"
    python3 - "$1/edge/manifest.json" "$psha" "$(wc -c < "$1/plane.bin")" "${3:-$2}" "${4:-}" <<'PY'
import json, sys
path, sha, size, gen, mode = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
entry = {"name": "tor", "sha256": sha if mode != "badsha" else "0" * 64, "bytes": size, "generation": gen}
m = {"format": 2, "generation": gen, "planes": [entry], "withheld": []}
if mode == "withheld":
    m["planes"] = []
    m["withheld"] = [{"name": "tor", "reason": "LOW_RECALL", "detail": "recall 0.318 below the floor"}]
if mode == "withheld2":
    m["planes"] = []
    m["withheld"] = [{"name": "tor", "reason": "LOW_RECALL", "reasons": ["LOW_RECALL", "IPV6_NOT_STATED"],
                      "detail": "LOW_RECALL: no recording measured this batch; " + "batch " * 300}]
if mode == "edgy":
    m["planes"] = []
    m["withheld"] = [{"name": "tor", "reason": "",
                      "reasons": ["LOW\u001b[31m", "a\u2028b", {"a": 1}, None, True, "", 0, "x\u00a0y\ttab\nnl"]}]
if mode == "absent":
    m["planes"] = []
json.dump(m, open(path, "w"), ensure_ascii=False)
PY
    msha=$(sha256sum < "$1/edge/manifest.json" | cut -d' ' -f1)
    signer="$P/key.pem"; [ "${4:-}" = badsig ] && signer="$P/other.pem"
    openssl pkeyutl -sign -inkey "$signer" -rawin -in "$1/edge/manifest.json" -out "$1/edge/manifests/$msha.sig"
  }
  serve() { # <dir> <port>
    ( cd "$1" && exec python3 -m http.server "$2" --bind 127.0.0.1 >/dev/null 2>&1 ) &
    echo $! >> "$W/plane-servers.pid"
    i=0; while [ "$i" -lt 50 ]; do
      curl -fsS --max-time 1 -o /dev/null "http://127.0.0.1:$2/edge/manifest.json" 2>/dev/null && return 0
      i=$((i + 1)); sleep 0.1
    done
  }

  DP="$W/plane-lib"; mkdir -p "$DP"; cp "$P/key.pub" "$DP/edge.pub"
  # the base names a host that does not exist; WHISPER_EDGE_RESOLVE is the only way any fetch lands
  R1="edge.plane-gate.invalid:$PORT1:127.0.0.1"
  B1="http://edge.plane-gate.invalid:$PORT1/edge"
  R2="edge.plane-gate.invalid:$PORT2:127.0.0.1"
  B2="http://edge.plane-gate.invalid:$PORT2/edge"
  refresh() { # <resolve> <base> [env...]
    r="$1"; b="$2"; shift 2
    env WHISPER_EDGE_RESOLVE="$r" "$@" "$REFRESH" --plane tor --dir "$DP" --base "$b" 2>&1
  }
  gen_of() { od -An -t u8 -j 16 -N 8 "$1" 2>/dev/null | tr -d ' '; }

  feed "$P/f1" 1791684002; serve "$P/f1" "$PORT1"
  echo "--- --plane, against a local signed manifest"

  # 1. a plane installed by name, through the pinned address only, 0444
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ "$(gen_of "$DP/tor.bin")" = 1791684002 ] && [ "$(stat -c %a "$DP/tor.bin")" = 444 ] \
    && cmp -s "$DP/tor.bin" "$P/f1/plane.bin"; } \
    && pass "--plane tor installs the signed plane as tor.bin, 0444, every fetch pinned by WHISPER_EDGE_RESOLVE" \
    || fail "--plane installs a verified plane" "rc=$rc $out"
  M1=$(stat -c %Y "$DP/tor.bin")

  # 2. unchanged: no rename, mtime kept
  sleep 1
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'already current' && [ "$(stat -c %Y "$DP/tor.bin")" = "$M1" ]; } \
    && pass "a second run finds it current and leaves the file alone, mtime included" \
    || fail "an unchanged plane is left alone" "rc=$rc $out"

  # 3. the same name pinned to a port nothing listens on: fails, untouched
  SUM=$(sha256sum < "$DP/tor.bin")
  out=$(refresh "edge.plane-gate.invalid:$PORT1:127.0.0.2" "$B1") && rc=0 || rc=$?
  { [ "$rc" != 0 ] && [ "$(sha256sum < "$DP/tor.bin")" = "$SUM" ]; } \
    && pass "pinned to an address that does not answer, the run fails and the plane is untouched" \
    || fail "the pin is honoured" "rc=$rc $out"

  # 4-6. each verification refuses, and nothing moves
  for mode in badsig badsha badplanesig; do
    feed "$P/f1" 1791687602 1791687602 "$mode"
    out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
    case "$mode" in
      badsig) what="a manifest signed by another key" ;;
      badsha) what="a plane that does not hash to the manifest's digest" ;;
      badplanesig) what="a plane whose own signature does not verify" ;;
    esac
    { [ "$rc" != 0 ] && [ "$(sha256sum < "$DP/tor.bin")" = "$SUM" ] && [ -z "$(find "$DP" -name '.tor.bin.*')" ]; } \
      && pass "$what is refused, the plane untouched, no dot-temp left" \
      || fail "$what is refused" "rc=$rc $out"
  done

  # 7. the failed-run count: three failed runs above, the fourth prints the alarm
  feed "$P/f1" 1791687602 1791687602 badsig
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$(cat "$DP/.refresh-failures.tor")" = 5 ] && says "$out" 'ALARM tor has failed 5 consecutive runs'; } \
    && pass "failed runs are counted, and from the fourth each prints an ALARM line" \
    || fail "the alarm counts failed runs" "count=$(cat "$DP/.refresh-failures.tor" 2>/dev/null) $out"

  # 8. withheld and absent: untouched, said why, and NOT failures (the count resets)
  feed "$P/f1" 1791687602 1791687602 withheld
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'withheld (LOW_RECALL' && [ ! -e "$DP/.refresh-failures.tor" ] \
    && [ "$(sha256sum < "$DP/tor.bin")" = "$SUM" ]; } \
    && pass "a withheld plane leaves tor.bin untouched, says why, and is not a failed run" \
    || fail "withheld is not a failure" "rc=$rc $out"
  feed "$P/f1" 1791687602 1791687602 absent
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'names no tor plane'; } \
    && pass "an absent plane leaves tor.bin untouched and says so" || fail "absent is not a failure" "rc=$rc $out"

  # 9. the generation that decides is byte 16 of the files, never the manifest's: a manifest generation
  #    far ahead over an older header is refused, and the reverse installs
  feed "$P/f1" 1791680402 1791999999
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'is not newer than the installed 1791684002' \
    && [ "$(gen_of "$DP/tor.bin")" = 1791684002 ]; } \
    && pass "an older header under a newer manifest generation is not installed: byte 16 decides" \
    || fail "byte 16 decides, not the manifest" "rc=$rc $out"
  feed "$P/f1" 1791691202 1791600000
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ "$(gen_of "$DP/tor.bin")" = 1791691202 ]; } \
    && pass "and a newer header under an older manifest generation is" || fail "a newer header installs" "rc=$rc $out"

  # 10. a 404 on the named hash re-runs once, then fails
  feed "$P/f1" 1791694802 1791694802 nohash
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" 're-running once' && [ "$(gen_of "$DP/tor.bin")" = 1791691202 ]; } \
    && pass "a 404 on a hash the manifest names waits, re-runs once, then fails with the plane untouched" \
    || fail "the 404 retry" "rc=$rc $out"

  # 11. two concurrent runs: generation 11 parked under the lock, generation 10 arriving meanwhile,
  #     must end on 11, never on 10 (the lock is the only thing ordering them)
  #     ordered by a file run A writes once it holds the lock, never by a sleep
  feed "$P/f1" 1791701999; feed "$P/f2" 1791701000; serve "$P/f2" "$PORT2"
  rm -f "$W/a-locked"
  WHISPER_EDGE_RESOLVE="$R1" WHISPER_EDGE_REFRESH_TEST_PAUSE_AFTER_LOCK=3 \
    WHISPER_EDGE_REFRESH_TEST_LOCKED_FILE="$W/a-locked" \
    "$REFRESH" --plane tor --dir "$DP" --base "$B1" > "$W/run11" 2>&1 &
  first=$!
  i=0; while [ ! -e "$W/a-locked" ] && [ "$i" -lt 300 ]; do i=$((i + 1)); sleep 0.1; done
  out=$(refresh "$R2" "$B2") && rc=0 || rc=$?
  wait "$first" && rc11=0 || rc11=$?
  { [ "$rc11" = 0 ] && [ "$rc" = 0 ] && [ "$(gen_of "$DP/tor.bin")" = 1791701999 ] \
    && says "$out" 'is not newer than the installed 1791701999'; } \
    && pass "two concurrent runs serialise on the lock: the older generation never lands after the newer" \
    || fail "concurrent runs" "rc=$rc rc11=$rc11 gen=$(gen_of "$DP/tor.bin") $out $(cat "$W/run11")"

  # the same race on a host with no flock: the mkdir lock serialises it, and the lock is gone afterwards
  feed "$P/f1" 1791709999; feed "$P/f2" 1791709000
  rm -f "$W/a-locked"
  WHISPER_EDGE_RESOLVE="$R1" WHISPER_EDGE_REFRESH_TEST_PAUSE_AFTER_LOCK=3 WHISPER_EDGE_REFRESH_TEST_NO_FLOCK=1 \
    WHISPER_EDGE_REFRESH_TEST_LOCKED_FILE="$W/a-locked" \
    "$REFRESH" --plane tor --dir "$DP" --base "$B1" > "$W/run11" 2>&1 &
  first=$!
  i=0; while [ ! -e "$W/a-locked" ] && [ "$i" -lt 300 ]; do i=$((i + 1)); sleep 0.1; done
  out=$(refresh "$R2" "$B2" WHISPER_EDGE_REFRESH_TEST_NO_FLOCK=1) && rc=0 || rc=$?
  wait "$first" && rc11=0 || rc11=$?
  { [ "$rc11" = 0 ] && [ "$rc" = 0 ] && [ "$(gen_of "$DP/tor.bin")" = 1791709999 ] && [ ! -e "$DP/.refresh.lock.d" ]; } \
    && pass "with no flock the mkdir lock serialises the two runs and is released after" \
    || fail "mkdir lock" "rc=$rc rc11=$rc11 gen=$(gen_of "$DP/tor.bin") $out $(cat "$W/run11")"

  # and leftovers: judged by AGE, never by pid. A temp older than any run can live is deleted; a fresh
  # one is kept whoever made it: a run whose pid this one cannot see (another pid namespace), a root run
  # a non-root kill -0 reads as dead (EPERM), or a container's pid 1.
  # The 25-minute one is a run still inside its worst case (about 22 minutes): it pins the threshold
  # above the run bound, where -31 alone would let any threshold from 1 to 30 pass.
  : > "$DP/.tor.bin.oldcrash"; touch -d '-31 minutes' "$DP/.tor.bin.oldcrash"
  : > "$DP/.tor.bin.slowrun"; touch -d '-25 minutes' "$DP/.tor.bin.slowrun"
  : > "$DP/.tor.bin.otherns"
  : > "$DP/.tor.bin.pid1"
  refresh "$R1" "$B1" > /dev/null 2>&1 || true
  { [ ! -e "$DP/.tor.bin.oldcrash" ] && [ -e "$DP/.tor.bin.slowrun" ] && [ -e "$DP/.tor.bin.otherns" ] \
    && [ -e "$DP/.tor.bin.pid1" ]; } \
    && pass "a dot-temp older than any run is deleted; a 25-minute one and fresh ones (another namespace, pid 1) are kept" \
    || fail "leftover dot-temps by age" "$(ls -la "$DP")"
  rm -f "$DP/.tor.bin.slowrun" "$DP/.tor.bin.otherns" "$DP/.tor.bin.pid1"

  # A held mkdir lock (a run with no flock, a container sharing this directory) makes a flock-capable run
  # wait: it reaches the lock with its verified 0444 temp, does not pass it while the lock is held, and
  # installs once it is released.
  feed "$P/f1" 1791719999
  mkdir "$DP/.refresh.lock.d"
  rm -f "$W/b-locked"
  WHISPER_EDGE_RESOLVE="$R1" WHISPER_EDGE_REFRESH_TEST_LOCKED_FILE="$W/b-locked" \
    "$REFRESH" --plane tor --dir "$DP" --base "$B1" > "$W/run12" 2>&1 &
  second=$!
  i=0
  while [ -z "$(find "$DP" -maxdepth 1 -name '.tor.bin.*' -perm 0444)" ] && [ ! -e "$W/b-locked" ] && [ "$i" -lt 300 ]; do
    i=$((i + 1)); sleep 0.1
  done
  sleep 2
  held=no
  if [ ! -e "$W/b-locked" ] && kill -0 "$second" 2>/dev/null; then held=yes; fi
  rmdir "$DP/.refresh.lock.d"
  wait "$second" && rc12=0 || rc12=$?
  { [ "$held" = yes ] && [ "$rc12" = 0 ] && [ -e "$W/b-locked" ] && [ "$(gen_of "$DP/tor.bin")" = 1791719999 ] \
    && [ ! -e "$DP/.refresh.lock.d" ]; } \
    && pass "a held mkdir lock makes a flock-capable run wait, and it installs once the lock is released" \
    || fail "the two lock schemes exclude each other" "held=$held rc=$rc12 gen=$(gen_of "$DP/tor.bin") $(cat "$W/run12")"

  # A failure counter that cannot be kept is an ALARM by name, never a silent zero that never fires.
  out=$(env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$W/no-such-dir" --base "$B1" 2>&1) && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" "ALARM tor cannot count its failures: $W/no-such-dir does not exist"; } \
    && pass "with no directory to count in, the failed run says ALARM by name" \
    || fail "a missing directory is an alarm" "rc=$rc $out"
  mv "$DP/edge.pub" "$DP/edge.pub.away"
  rm -f "$DP/.refresh-failures.lock" "$DP/.refresh-failures.tor"; mkdir "$DP/.refresh-failures.lock"
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" 'ALARM tor cannot count its failures: .*/.refresh-failures.lock cannot be opened'; } \
    && pass "a counter lock that cannot be opened is an ALARM line, not a count of zero" \
    || fail "an unopenable counter lock is an alarm" "rc=$rc $out"
  rmdir "$DP/.refresh-failures.lock"; mkdir "$DP/.refresh-failures.tor"
  out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" 'ALARM tor cannot count its failures: .*/.refresh-failures.tor cannot be read'; } \
    && pass "a counter that cannot be read is an ALARM line, not a count of zero" \
    || fail "an unreadable counter is an alarm" "rc=$rc $out"
  rmdir "$DP/.refresh-failures.tor"
  # A counter the run cannot write. Not root: a 0444 file. Root writes a 0444 file, so as root the
  # counter is made immutable instead, which root cannot write either; both runs count this row, so the
  # README's number is the same for both, and a host where neither can be arranged says SKIPPED.
  echo 2 > "$DP/.refresh-failures.tor"
  unw=""
  if [ "$(id -u)" != 0 ]; then
    chmod 0444 "$DP/.refresh-failures.tor" && unw="a 0444 counter"
  elif chattr +i "$DP/.refresh-failures.tor" 2>/dev/null; then
    unw="an immutable counter, as root"
  fi
  if [ -n "$unw" ]; then
    out=$(refresh "$R1" "$B1") && rc=0 || rc=$?
    { [ "$rc" != 0 ] && [ "$(cat "$DP/.refresh-failures.tor")" = 2 ] \
      && says "$out" 'ALARM tor cannot count its failures: .*/.refresh-failures.tor cannot be written'; } \
      && pass "a counter that cannot be written ($unw) is an ALARM line, not a count frozen below the alarm" \
      || fail "an unwritable counter is an alarm ($unw)" "rc=$rc $out"
  else
    SKIPPED="${SKIPPED:-}the unwritable-counter case (root, and the immutable attribute cannot be set on $DP); "
  fi
  chattr -i "$DP/.refresh-failures.tor" 2>/dev/null || true
  chmod 0644 "$DP/.refresh-failures.tor"
  mv "$DP/edge.pub.away" "$DP/edge.pub"

  # every refusal counts toward the alarm, the prerequisites included
  rm -f "$DP/.refresh-failures.tor"
  mv "$DP/edge.pub" "$DP/edge.pub.away"
  refresh "$R1" "$B1" > /dev/null 2>&1 || true
  [ "$(cat "$DP/.refresh-failures.tor" 2>/dev/null)" = 1 ] \
    && pass "a run with no signing key is a failed run, counted toward the alarm" \
    || fail "a missing key is counted" "count=$(cat "$DP/.refresh-failures.tor" 2>/dev/null)"
  mv "$DP/edge.pub.away" "$DP/edge.pub"
  rm -f "$DP/.refresh-failures.tor"

  # --- what a timer's journal carries. The units run --quiet, which silences routine lines, so every
  #     line a person needs from a timer run is an event: an install, and why a plane is missing. Each
  #     installed or current line names the file it describes. The first-install and newer-generation
  #     lines are each other's control: each arm asserts its own exact line and the absence of the other.
  DQ="$W/plane-quiet"; mkdir -p "$DQ"; cp "$P/key.pub" "$DQ/edge.pub"
  qrefresh() { env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DQ" --base "$B1" --quiet 2>&1; }
  nrefresh() { env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DQ" --base "$B1" 2>&1; }
  echo "--- --plane under --quiet: the lines a timer's journal carries"
  feed "$P/f1" 1791730002
  out=$(qrefresh) && rc=0 || rc=$?
  want="installed tor.bin ($(facts "$P/f1/plane.bin")) - first install of this plane: it stays inert until the server is reloaded; reload the server to arm it"
  { [ "$rc" = 0 ] && cmp -s "$DQ/tor.bin" "$P/f1/plane.bin" && hasline "$out" "$want" \
    && ! says "$out" 'picks it up on its own timer'; } \
    && pass "a first install prints, under --quiet, that the plane stays inert until the server is reloaded, with its generation, size, digest16 and valid-until" \
    || fail "the first-install line under --quiet" "rc=$rc want: $want got: $out"
  # The attribute: set (and then nothing may claim otherwise), or not settable here (not root, or a
  # filesystem without it), and then the journal line names both causes. Without chattr nothing is tried.
  imm="could not set the immutable attribute on $DQ/tor.bin (a missing capability or an unsupported filesystem); installed without it"
  if ! command -v chattr >/dev/null 2>&1; then
    ! says "$out" 'immutable attribute' \
      && pass "with no chattr on this host the refresh tries nothing and claims nothing about the attribute" \
      || fail "no chattr, no attribute line" "$out"
  else
    case "$(lsattr -d "$DQ/tor.bin" 2>/dev/null | cut -d' ' -f1)" in
      *i*) ! hasline "$out" "$imm" \
             && pass "the attribute is set here (lsattr shows i), and no line claims it could not be" \
             || fail "an immutable plane with a could-not line" "$out" ;;
      *) hasline "$out" "$imm" \
           && pass "the attribute cannot be set here, and --quiet still says so, naming a missing capability or an unsupported filesystem" \
           || fail "the could-not-set line under --quiet" "want: $imm got: $out" ;;
    esac
  fi
  feed "$P/f1" 1791733602
  out=$(qrefresh) && rc=0 || rc=$?
  want="installed tor.bin ($(facts "$P/f1/plane.bin")) - the module picks it up on its own timer"
  { [ "$rc" = 0 ] && cmp -s "$DQ/tor.bin" "$P/f1/plane.bin" && hasline "$out" "$want" && ! says "$out" 'first install'; } \
    && pass "a newer generation of an installed plane says the module picks it up on its own timer, under --quiet, and claims no first install" \
    || fail "the newer-generation line under --quiet" "rc=$rc want: $want got: $out"
  out=$(qrefresh) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ -z "$out" ]; } \
    && pass "a plane already current prints nothing under --quiet: routine lines stay routine" \
    || fail "--quiet silences the current line" "rc=$rc $out"
  out=$(nrefresh) && rc=0 || rc=$?
  want="tor.bin unchanged, already current ($(facts "$DQ/tor.bin"))"
  { [ "$rc" = 0 ] && hasline "$out" "$want"; } \
    && pass "and without --quiet the current line names the installed file's generation, size, digest16 and valid-until" \
    || fail "the current line's facts" "rc=$rc want: $want got: $out"
  SUMQ=$(sha256sum < "$DQ/tor.bin")
  feed "$P/f1" 1791737202 1791737202 withheld2
  out=$(qrefresh) && rc=0 || rc=$?
  wantw="tor is withheld (LOW_RECALL, IPV6_NOT_STATED; details: $B1/manifest.json); the installed tor.bin is untouched"
  { [ "$rc" = 0 ] && hasline "$out" "$wantw" && [ "$(sha256sum < "$DQ/tor.bin")" = "$SUMQ" ]; } \
    && pass "a withheld plane says why under --quiet, the manifest's reasons list joined, its detail left in the manifest" \
    || fail "the withheld reasons under --quiet" "rc=$rc want: $wantw got: $out"
  if command -v jq >/dev/null 2>&1; then
    NOPY="$W/no-python"; mkdir -p "$NOPY"
    for t in curl openssl jq sha256sum cut mktemp find rm od head wc tr chmod chown id sync mv chattr flock \
             mkdir rmdir date shuf getent awk sed cat sleep basename cmp env dirname grep; do
      tp=$(command -v "$t" 2>/dev/null) && ln -s "$tp" "$NOPY/$t"
    done
    out=$(env PATH="$NOPY" WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DQ" --base "$B1" --quiet 2>&1) && rc=0 || rc=$?
    { [ ! -e "$NOPY/python3" ] && [ "$rc" = 0 ] && hasline "$out" "$wantw"; } \
      && pass "with jq and no python3 the withheld line is the same line, word for word" \
      || fail "the jq reading of the withheld reasons" "rc=$rc want: $wantw got: $out"
  else
    SKIPPED="${SKIPPED:-}the jq reading of the withheld reasons (no jq on this host); "
  fi
  feed "$P/f1" 1791737202 1791737202 withheld
  out=$(qrefresh) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && hasline "$out" "tor is withheld (LOW_RECALL; details: $B1/manifest.json); the installed tor.bin is untouched"; } \
    && pass "a withheld entry with no reasons list falls back to its singular reason" \
    || fail "the singular-reason fallback" "rc=$rc $out"
  feed "$P/f1" 1791737202 1791737202 absent
  out=$(qrefresh) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && hasline "$out" "the manifest names no tor plane; the installed tor.bin is untouched"; } \
    && pass "an absent plane says so under --quiet" \
    || fail "the absent line under --quiet" "rc=$rc $out"
  # ...and on a box with no file yet (every fresh box, for each plane the manifest does not publish), the
  # same verdicts say nothing is installed, never that a file which does not exist is untouched
  DN="$W/plane-none"; mkdir -p "$DN"; cp "$P/key.pub" "$DN/edge.pub"
  none="nothing is installed yet: tor.bin lands the day the manifest publishes it, and stays inert until the server is reloaded"
  feed "$P/f1" 1791737202 1791737202 withheld2
  out=$(env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DN" --base "$B1" --quiet 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ ! -e "$DN/tor.bin" ] \
    && hasline "$out" "tor is withheld (LOW_RECALL, IPV6_NOT_STATED; details: $B1/manifest.json); $none"; } \
    && pass "a withheld plane with no file installed says nothing is installed yet, never that a missing file is untouched" \
    || fail "the withheld line with no file" "rc=$rc $out"
  feed "$P/f1" 1791737202 1791737202 absent
  out=$(env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DN" --base "$B1" --quiet 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ ! -e "$DN/tor.bin" ] && hasline "$out" "the manifest names no tor plane; $none"; } \
    && pass "and so does an absent plane with no file installed" \
    || fail "the absent line with no file" "rc=$rc $out"
  # The withheld reasons on edge values: python3 and jq render the same line, and no control character
  # (here an ESC, a tab, a newline, U+2028, NBSP) reaches it.
  feed "$P/f1" 1791737202 1791737202 edgy
  wante="tor is withheld (LOW [31m, a b, {\"a\":1}, null, true, , 0, x y tab nl; details: $B1/manifest.json); the installed tor.bin is untouched"
  outp=$(qrefresh) && rc=0 || rc=$?
  if [ -n "${NOPY:-}" ]; then
    outj=$(env PATH="$NOPY" WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DQ" --base "$B1" --quiet 2>&1) && rcj=0 || rcj=$?
    ctl=$(printf '%s' "$outp$outj" | LC_ALL=C tr -d -c '\000-\037\177' | wc -c | tr -d ' ')
    { [ "$rc" = 0 ] && [ "$rcj" = 0 ] && [ "$outp" = "$outj" ] && [ "$outp" = "$wante" ] && [ "$ctl" = 0 ]; } \
      && pass "on edge values (an empty reason, non-strings, an ESC, a tab, a newline, U+2028, NBSP) python3 and jq print the same line, and no control character" \
      || fail "the withheld reasons on edge values" "python3: $(printf '%s' "$outp" | od -c | head -3) jq: $(printf '%s' "$outj" | od -c | head -3)"
  fi
  # A header value past 2^63 is said as out of range, never wrapped into a wrong date.
  DB="$W/plane-bigvu"; mkdir -p "$DB"; cp "$P/key.pub" "$DB/edge.pub"
  feed "$P/f1" 1791740802 1791740802 bigvu
  out=$(env WHISPER_EDGE_RESOLVE="$R1" "$REFRESH" --plane tor --dir "$DB" --base "$B1" --quiet 2>&1) && rc=0 || rc=$?
  want="installed tor.bin (generation 1791740802, $(wc -c < "$P/f1/plane.bin" | tr -d ' ') bytes, digest16 $(sha256sum < "$P/f1/plane.bin" | cut -c1-16), valid until out of range (at or above 2^63)) - first install of this plane: it stays inert until the server is reloaded; reload the server to arm it"
  { [ "$rc" = 0 ] && hasline "$out" "$want" && ! says "$out" '1970-' && ! says "$out" 'arithmetic'; } \
    && pass "a valid-until at or above 2^63 renders as out of range, never as a wrapped date" \
    || fail "the out-of-range valid-until" "rc=$rc want: $want got: $out"
  chattr -R -i "$DB" 2>/dev/null || true
  # A pin for another host would be ignored by curl and leave the run unpinned: refused, and counted.
  rm -f "$DQ/.refresh-failures.tor"; SUMQ=$(sha256sum < "$DQ/tor.bin")
  out=$(env WHISPER_EDGE_RESOLVE="other.plane-gate.invalid:$PORT1:127.0.0.1" "$REFRESH" --plane tor --dir "$DQ" --base "$B1" --quiet 2>&1) && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" "names other.plane-gate.invalid:$PORT1, but the feed is edge.plane-gate.invalid:$PORT1" \
    && [ "$(cat "$DQ/.refresh-failures.tor" 2>/dev/null)" = 1 ] && [ "$(sha256sum < "$DQ/tor.bin")" = "$SUMQ" ]; } \
    && pass "--plane refuses a WHISPER_EDGE_RESOLVE for another host, as a counted failure, the plane untouched" \
    || fail "--plane's pin for another host" "rc=$rc $out"
  rm -f "$DQ/.refresh-failures.tor"
  stop_servers
}

# ===================================================================================================
# THE DEFAULT MODE'S WIRE: the snapshot fetch asks past caches (Cache-Control: no-cache, because
# snapshot.bin is served public, max-age=300) and honours WHISPER_EDGE_RESOLVE as --plane does. A local
# stub records each request's Cache-Control header and the address it was served on; the base names a
# host that does not resolve and the stub listens on 127.0.0.3 alone, so only the pin reaches it. Each
# check has a control built from the refresh in the tree with that one change taken out, which must fail.
default_mode_cases() {
  S="$W/default-feed"; mkdir -p "$S/edge"
  python3 - "$FIXTURE" "$S/edge/snapshot.bin" 1791740002 <<'PY'
import struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, int(sys.argv[3]))
open(sys.argv[2], "wb").write(bytes(b))
PY
  openssl pkeyutl -sign -inkey "$P/key.pem" -rawin -in "$S/edge/snapshot.bin" -out "$S/edge/snapshot.bin.sig"
  PORT3=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.3", 0)); print(s.getsockname()[1])')
  LOG3="$W/default-requests.log"; : > "$LOG3"
  python3 - "$S" "$PORT3" "$LOG3" > /dev/null 2>&1 <<'PY' &
import functools, http.server, json, sys
root, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "cache_control": self.headers.get("Cache-Control"),
                                "served_on": self.connection.getsockname()[0]}) + "\n")
        super().do_GET()
http.server.ThreadingHTTPServer(("127.0.0.3", port), functools.partial(H, directory=root)).serve_forever()
PY
  echo $! >> "$W/plane-servers.pid"
  i=0; while [ "$i" -lt 50 ]; do
    curl -fsS --max-time 1 -o /dev/null "http://127.0.0.3:$PORT3/edge/snapshot.bin.sig" 2>/dev/null && break
    i=$((i + 1)); sleep 0.1
  done
  : > "$LOG3"
  R3="edge.default-gate.invalid:$PORT3:127.0.0.3"
  B3="http://edge.default-gate.invalid:$PORT3/edge"
  # wire <log>: "<requests> <with no-cache> <served on 127.0.0.3>" over the log's lines
  wire() {
    python3 - "$1" <<'PY'
import json, sys
rs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(len(rs), sum(1 for r in rs if r["cache_control"] == "no-cache"), sum(1 for r in rs if r["served_on"] == "127.0.0.3"))
PY
  }
  drun() { # <refresh> <dir>
    mkdir -p "$2"; cp "$P/key.pub" "$2/edge.pub"
    env WHISPER_EDGE_RESOLVE="$R3" "$1" --dir "$2" --base "$B3" 2>&1
  }
  echo "--- the default mode's fetch, against a stub that records what it was asked"

  DD="$W/default-lib"
  out=$(drun "$REFRESH" "$DD") && rc=0 || rc=$?
  w=$(wire "$LOG3")
  { [ "$rc" = 0 ] && cmp -s "$DD/snapshot.bin" "$S/edge/snapshot.bin" && [ "$w" = "2 2 2" ]; } \
    && pass "the default fetch carries Cache-Control: no-cache on both requests and is pinned by WHISPER_EDGE_RESOLVE, and the snapshot verifies and installs" \
    || fail "the default fetch's header and pin" "rc=$rc requests/no-cache/pinned=$w $out"
  want="installed snapshot.bin ($(facts "$S/edge/snapshot.bin")) - the modules pick it up on their own timer, no reload"
  hasline "$out" "$want" \
    && pass "its installed line names the generation, size, digest16 and valid-until, and keeps the no-reload wording" \
    || fail "the default installed line's facts" "want: $want got: $out"
  out=$(drun "$REFRESH" "$DD") && rc=0 || rc=$?
  want="snapshot.bin unchanged, already current ($(facts "$DD/snapshot.bin"))"
  { [ "$rc" = 0 ] && hasline "$out" "$want"; } \
    && pass "and its current line names the installed file the same way" \
    || fail "the default current line's facts" "rc=$rc want: $want got: $out"

  # a pin for another host: refused before any request, by the default mode and by --rpz alike
  : > "$LOG3"
  out=$(env WHISPER_EDGE_RESOLVE="other.default-gate.invalid:$PORT3:127.0.0.3" "$REFRESH" --dir "$DD" --base "$B3" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 1 ] && says "$out" "names other.default-gate.invalid:$PORT3, but the feed is edge.default-gate.invalid:$PORT3" \
    && [ "$(wire "$LOG3")" = "0 0 0" ]; } \
    && pass "the default mode refuses a WHISPER_EDGE_RESOLVE for another host, exit 1, before any request" \
    || fail "the default mode's pin for another host" "rc=$rc requests=$(wire "$LOG3") $out"
  out=$(env WHISPER_EDGE_RESOLVE="other.default-gate.invalid:$PORT3:127.0.0.3" "$REFRESH" --rpz --zone-file "$W/rpz-mismatch/rpz.zone" --base "$B3" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$out" "names other.default-gate.invalid:$PORT3, but the feed is edge.default-gate.invalid:$PORT3" \
    && [ "$(wire "$LOG3")" = "0 0 0" ] && [ ! -e "$W/rpz-mismatch/rpz.zone" ]; } \
    && pass "and so does --rpz, with its usage exit 2, before any request" \
    || fail "--rpz's pin for another host" "rc=$rc requests=$(wire "$LOG3") $out"

  # a signed file too short for a header: its facts are said as such, with nothing on stderr
  mkdir -p "$S/short"; printf 'short' > "$S/short/snapshot.bin"
  openssl pkeyutl -sign -inkey "$P/key.pem" -rawin -in "$S/short/snapshot.bin" -out "$S/short/snapshot.bin.sig"
  mkdir -p "$W/default-short"; cp "$P/key.pub" "$W/default-short/edge.pub"
  out=$(env WHISPER_EDGE_RESOLVE="$R3" "$REFRESH" --dir "$W/default-short" --base "http://edge.default-gate.invalid:$PORT3/short" 2>&1 </dev/null) && rc=0 || rc=$?
  want="installed snapshot.bin (5 bytes, digest16 $(sha256sum < "$S/short/snapshot.bin" | cut -c1-16), too short for a plane header (40 bytes)) - the modules pick it up on their own timer, no reload"
  { [ "$rc" = 0 ] && hasline "$out" "$want" && ! says "$out" 'arithmetic'; } \
    && pass "a file too short for a plane header is said as such on the installed line, with no arithmetic error" \
    || fail "the too-short file's facts" "rc=$rc want: $want got: $out"

  # the controls: the tree's refresh with one change taken out, each of which this section must catch
  sed "s/ -H 'Cache-Control: no-cache'//" "$REFRESH" > "$W/refresh-no-header"
  sed '/WHISPER_EDGE_RESOLVE:-}" \]; then set -- --resolve/d' "$REFRESH" > "$W/refresh-no-pin"
  chmod +x "$W/refresh-no-header" "$W/refresh-no-pin"
  if cmp -s "$REFRESH" "$W/refresh-no-header" || cmp -s "$REFRESH" "$W/refresh-no-pin"; then
    fail "the default-fetch controls" "a control's edit did not apply to $REFRESH, so it proves nothing"
  else
    : > "$LOG3"
    out=$(drun "$W/refresh-no-header" "$W/default-lib-nh") && rc=0 || rc=$?
    w=$(wire "$LOG3")
    { [ "$rc" = 0 ] && [ "$w" = "2 0 2" ]; } \
      && pass "the control: a refresh without the header is caught (the stub recorded 2 requests, 0 with no-cache)" \
      || fail "the header control" "rc=$rc requests/no-cache/pinned=$w $out"
    : > "$LOG3"
    out=$(drun "$W/refresh-no-pin" "$W/default-lib-np") && rc=0 || rc=$?
    w=$(wire "$LOG3")
    { [ "$rc" != 0 ] && [ ! -e "$W/default-lib-np/snapshot.bin" ] && [ "$w" = "0 0 0" ]; } \
      && pass "the control: a refresh that ignores the pin cannot reach the feed, fails, and installs nothing" \
      || fail "the pin control" "rc=$rc requests/no-cache/pinned=$w $out"
  fi
  stop_servers
}

# ===================================================================================================
# THE UNITS' OWN SANDBOX: the immutable attribute under whisper-edge-refresh@.service and the legacy
# whisper-edge-refresh.service. Every [Service] property of the unit file in the tree goes through
# systemd-run, as root, on a fixture under /var/lib (PrivateTmp and ProtectHome hide /tmp and /home),
# with only the paths moved onto it; the template's command is its own ExecStart for instance tor. The
# control variant empties the bounding set, which is each unit as it shipped before. Needs passwordless
# sudo, systemd as PID 1, systemd-run and chattr; without them the rows are SKIPPED and the verdict says
# INCOMPLETE. /run/systemd/system is sd_booted(3)'s own test: a systemd-run binary on a host whose PID 1
# is not systemd (a container, a build VM) has no manager to run a unit.
unit_cases() {
  if ! sudo -n true 2>/dev/null || ! command -v systemd-run >/dev/null 2>&1 || ! command -v chattr >/dev/null 2>&1 \
     || [ ! -d /run/systemd/system ]; then
    SKIPPED="${SKIPPED:-}the immutable attribute under the units' own sandbox (needs passwordless sudo, systemd as PID 1, systemd-run and chattr); "
    return 0
  fi
  U=$(sudo -n mktemp -d /var/lib/whisper-edge-install-gate.XXXXXX); SUDO_DIR=$U
  sudo -n chmod 0755 "$U"
  ub_reset() {
    sudo -n chattr -R -i "$U" 2>/dev/null || true
    sudo -n rm -rf "$U/lib" "$U/sbin"
    sudo -n install -d -o 0 -g 0 -m 0755 "$U/lib" "$U/sbin"
    sudo -n install -o 0 -g 0 -m 0755 "$REFRESH" "$U/sbin/whisper-edge-refresh"
    # the copy sits under /var/lib, labelled var_lib_t, which systemd may not execute under an
    # enforcing policy (exit 203, and no AVC: the rule is a dontaudit); label it as the real install's
    # /usr/local/sbin/whisper-edge-refresh is labelled, so the rows test the sandbox and not the label
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
      sudo -n chcon -t bin_t "$U/sbin/whisper-edge-refresh" \
        || fail "the sandbox fixture's label" "chcon -t bin_t $U/sbin/whisper-edge-refresh failed, so systemd cannot execute it under this policy"
    fi
    sudo -n install -o 0 -g 0 -m 0644 "$P/key.pub" "$U/lib/edge.pub"
  }
  uprops() { # <unit file> <shipped|nocap>
    while IFS= read -r l; do
      case "$l" in ''|'#'*|Type=*|ExecStart=*) continue ;; esac
      l=$(printf '%s' "$l" | sed "s|/var/lib/whisper-edge|$U/lib|g")
      case "$l" in CapabilityBoundingSet=*) [ "$2" = nocap ] && l="CapabilityBoundingSet=" ;; esac
      printf '%s\n' "$l"
    done <<EOF
$(sed -n '/^\[Service\]/,/^\[/p' "$1" | grep -E '^[A-Za-z]+=')
EOF
  }
  T_UNIT="$HERE/whisper-edge-refresh@.service"; L_UNIT="$HERE/whisper-edge-refresh.service"
  # the template's own ExecStart for instance tor, with its binary moved onto the fixture
  TCMD=$(sed -n 's/^ExecStart=//p' "$T_UNIT" | sed "s|/usr/local/sbin/whisper-edge-refresh|$U/sbin/whisper-edge-refresh|; s|%i|tor|g")
  USEQ=0
  urun() { # <unit file> <shipped|nocap> <command words...>: output in $uout, status in $urc
    _uf=$1; _v=$2; shift 2
    USEQ=$((USEQ + 1))
    _args=""
    while IFS= read -r pr; do _args="$_args|-p|$pr"; done <<EOF
$(uprops "$_uf" "$_v")
EOF
    uout=$(IFS='|'; set -f
           # shellcheck disable=SC2086
           sudo -n systemd-run --quiet --wait --pipe --collect --unit="whisper-edge-install-gate-$$-$USEQ" ${_args#|} \
             -E WHISPER_EDGE_RESOLVE="${URESOLVE:-$R1}" -E PATH="/usr/sbin:/usr/bin:/sbin:/bin" "$@" 2>&1) && urc=0 || urc=$?
  }
  attr() { sudo -n lsattr -d "$1" 2>/dev/null | cut -d' ' -f1; }
  feed "$P/f1" 1791750002; serve "$P/f1" "$PORT1"
  echo "--- the immutable attribute under the units' own sandbox (systemd-run, as root, under /var/lib)"

  ub_reset
  # shellcheck disable=SC2086
  urun "$T_UNIT" shipped $TCMD --dir "$U/lib" --base "$B1"
  want="installed tor.bin ($(facts "$P/f1/plane.bin")) - first install of this plane: it stays inert until the server is reloaded; reload the server to arm it"
  { [ "$urc" = 0 ] && sudo -n cmp -s "$U/lib/tor.bin" "$P/f1/plane.bin" && case "$(attr "$U/lib/tor.bin")" in *i*) true ;; *) false ;; esac \
    && hasline "$uout" "$want"; } \
    && pass "the template's own command (--plane %i --quiet, instance tor) under its sandbox installs the plane immutable, and its journal carries the first-install line" \
    || fail "the template sets the immutable attribute" "rc=$urc attr=$(attr "$U/lib/tor.bin") command: $TCMD; $uout"
  feed "$P/f1" 1791753602; cp "$P/f1/plane.bin" "$W/unit-g2.bin"
  # shellcheck disable=SC2086
  urun "$T_UNIT" shipped $TCMD --dir "$U/lib" --base "$B1"
  { [ "$urc" = 0 ] && sudo -n cmp -s "$U/lib/tor.bin" "$W/unit-g2.bin" && case "$(attr "$U/lib/tor.bin")" in *i*) true ;; *) false ;; esac \
    && says "$uout" 'the module picks it up on its own timer'; } \
    && pass "and the replace path clears the attribute, renames the newer generation over the immutable plane and sets it again" \
    || fail "the template replaces an immutable plane" "rc=$urc attr=$(attr "$U/lib/tor.bin") $uout"
  feed "$P/f1" 1791757202
  # shellcheck disable=SC2086
  urun "$T_UNIT" nocap $TCMD --dir "$U/lib" --base "$B1"
  { [ "$urc" != 0 ] && sudo -n cmp -s "$U/lib/tor.bin" "$W/unit-g2.bin" \
    && says "$uout" "$U/lib/tor.bin is immutable and this run could not clear the attribute (a missing CAP_LINUX_IMMUTABLE capability)"; } \
    && pass "the control: with the bounding set empty, as it shipped, the same run cannot replace the immutable plane, fails naming the attribute and the missing capability, and leaves it untouched" \
    || fail "the empty-bounding-set control on the replace path" "rc=$urc $uout"
  ub_reset
  # shellcheck disable=SC2086
  urun "$T_UNIT" nocap $TCMD --dir "$U/lib" --base "$B1"
  imm="could not set the immutable attribute on $U/lib/tor.bin (a missing capability or an unsupported filesystem); installed without it"
  { [ "$urc" = 0 ] && case "$(attr "$U/lib/tor.bin")" in *i*) false ;; *) true ;; esac && hasline "$uout" "$imm"; } \
    && pass "the control: with the bounding set empty a first install has no attribute, and the journal says so, naming a missing capability" \
    || fail "the empty-bounding-set control on a first install" "rc=$urc attr=$(attr "$U/lib/tor.bin") $uout"
  ub_reset
  urun "$L_UNIT" shipped "$U/sbin/whisper-edge-refresh" --plane tor --quiet --dir "$U/lib" --base "$B1"
  { [ "$urc" = 0 ] && case "$(attr "$U/lib/tor.bin")" in *i*) true ;; *) false ;; esac; } \
    && pass "the legacy unit carries the same capability: a plane installed under its sandbox is immutable" \
    || fail "the legacy unit sets the immutable attribute" "rc=$urc attr=$(attr "$U/lib/tor.bin") $uout"
  ub_reset
  urun "$L_UNIT" nocap "$U/sbin/whisper-edge-refresh" --plane tor --quiet --dir "$U/lib" --base "$B1"
  { [ "$urc" = 0 ] && case "$(attr "$U/lib/tor.bin")" in *i*) false ;; *) true ;; esac \
    && hasline "$uout" "could not set the immutable attribute on $U/lib/tor.bin (a missing capability or an unsupported filesystem); installed without it"; } \
    && pass "the control: the legacy unit with its bounding set emptied, as it shipped, leaves the plane without the attribute and says so" \
    || fail "the legacy unit's own empty-bounding-set control" "rc=$urc attr=$(attr "$U/lib/tor.bin") $uout"
  # ...and the command the legacy unit actually runs, its own ExecStart (the default mode), under its own
  # sandbox: the snapshot installs, 0644, with no attribute (the default mode never sets one).
  PORT5=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  ( cd "$S" && exec python3 -m http.server "$PORT5" --bind 127.0.0.1 >/dev/null 2>&1 ) &
  echo $! >> "$W/plane-servers.pid"
  i=0; while [ "$i" -lt 50 ]; do curl -fsS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT5/edge/snapshot.bin.sig" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
  LCMD=$(sed -n 's/^ExecStart=//p' "$L_UNIT" | sed "s|/usr/local/sbin/whisper-edge-refresh|$U/sbin/whisper-edge-refresh|")
  ub_reset
  # shellcheck disable=SC2086
  URESOLVE="edge.legacy-gate.invalid:$PORT5:127.0.0.1" urun "$L_UNIT" shipped $LCMD --dir "$U/lib" --base "http://edge.legacy-gate.invalid:$PORT5/edge"
  { [ "$urc" = 0 ] && sudo -n cmp -s "$U/lib/snapshot.bin" "$S/edge/snapshot.bin" \
    && [ "$(sudo -n stat -c %a "$U/lib/snapshot.bin")" = 644 ] && case "$(attr "$U/lib/snapshot.bin")" in *i*) false ;; *) true ;; esac; } \
    && pass "the legacy unit's own command ($(printf '%s' "$LCMD" | sed "s|$U/sbin/||")) under its own sandbox installs the snapshot, 0644, with no attribute" \
    || fail "the legacy unit's own command under its sandbox" "rc=$urc command: $LCMD; $uout"
  ub_reset
  urun "$L_UNIT" shipped "$U/sbin/whisper-edge-refresh" --plane tor --quiet --dir "$U/lib" --base "$B1"
  # The teardown: a plain rm -rf cannot remove an immutable plane, so a cleanup without the clear would
  # leak the fixture; the gate's own clears the attribute first.
  sudo -n rm -rf "$U" 2>/dev/null || true
  [ -e "$U/lib/tor.bin" ] \
    && pass "the control: a teardown without the clear cannot remove the immutable plane, and the fixture is left behind" \
    || fail "the teardown control" "rm -rf removed an immutable plane: lsattr showed '$(attr "$U/lib/tor.bin")'"
  # The gate's own cleanup(), its source read from this file and run in a fresh sh -eu, as the EXIT trap
  # runs it under set -eu (a subshell on the left of || would not do: errexit is off there, so an
  # unguarded step could never stop it), over fixtures standing in for its two trees: the sudo one
  # holding the immutable plane, both holding a symlink and a fifo (on which chattr -R exits 1,
  # measured), and, as root, an immutable file in the work-tree stand-in too. The control is the same
  # two steps unguarded, in the same kind of shell: they stop at the chattr and leave the tree.
  sudo -n ln -s /nonexistent "$U/lib/a-symlink"; sudo -n mkfifo "$U/lib/a-fifo"
  CW="$W/cleanup-probe"; mkdir -p "$CW"; : > "$CW/file"; ln -s /nonexistent "$CW/a-symlink"; mkfifo "$CW/a-fifo"
  [ "$(id -u)" = 0 ] && chattr +i "$CW/file" 2>/dev/null
  U2=$(sudo -n mktemp -d /var/lib/whisper-edge-install-gate.XXXXXX)
  sudo -n install -d "$U2/lib"; sudo -n touch "$U2/lib/plane"; sudo -n chattr +i "$U2/lib/plane"
  sudo -n ln -s /nonexistent "$U2/lib/a-symlink"
  sh -euc 'sudo -n chattr -R -i "$1" 2>/dev/null; sudo -n rm -rf "$1"' unguarded "$U2" 2>/dev/null || true
  sudo -n test -e "$U2/lib/plane" \
    && pass "the control: chattr -R then rm -rf, unguarded under set -e, stop at the symlink and leave the immutable tree behind" \
    || fail "the unguarded-teardown control" "the tree was removed: $(sudo -n ls -la "$U2" 2>&1 | head -3)"
  sudo -n chattr -R -i "$U2" 2>/dev/null || true; sudo -n rm -rf "$U2"
  CLEANUP_SRC=$(sed -n '/^cleanup() {/,/^}/p' "$HERE/install-gate.sh")
  cout=$(sh -euc "stop_servers() { :; }
$CLEANUP_SRC
W=\$1; SUDO_DIR=\$2; cleanup" cleanup-probe "$CW" "$U" 2>&1) && crc=0 || crc=$?
  { [ "$crc" = 0 ] && [ ! -e "$CW" ] && ! sudo -n test -e "$U"; } \
    && pass "the gate's own cleanup() removes both trees, the immutable plane, a symlink and a fifo included" \
    || fail "cleanup() over the fixtures" "rc=$crc $cout; left: $(ls -d "$CW" "$U" 2>/dev/null)"
  SUDO_DIR=""
  stop_servers
}

plane_cases
default_mode_cases
unit_cases

# The keyed path: --enroll, --keyed-set, --unenroll, --repin, the revocation and the state files.
# INSTALL_GATE_SKIP_KEYED=1 leaves it to a run of keyed-gate.sh of its own (CI's keyed-gate job): the
# --plane-only verdict then names what it left out, and the full gate counts it as INCOMPLETE.
KEYED_LEFT=0
if [ "${INSTALL_GATE_SKIP_KEYED:-0}" = 1 ]; then
  KEYED_LEFT=1
  echo "  (the keyed cases are left to install/keyed-gate.sh's own run: INSTALL_GATE_SKIP_KEYED=1)"
else
  INSTALL_GATE_REFRESH="$REFRESH" "$HERE/keyed-gate.sh" && rc=0 || rc=$?
  case "$rc" in
    0) pass "the keyed cases against a local fake feed: every case and every control behaved (above)" ;;
    77) SKIPPED="${SKIPPED:-}part of the keyed cases (a KEYED_GATE_ROWS subset, or the unit's sandbox rows without passwordless sudo and systemd-run; named above); " ;;
    *) fail "the keyed cases" "keyed-gate.sh exited $rc; its own output above names the case" ;;
  esac
fi

# The installer itself: its pinned policy, its renderings, its dry run against a stub feed, and, on a
# disposable root box, its real runs (installer-gate.sh). INSTALL_GATE_SKIP_INSTALLER=1 leaves it to a run
# of that gate of its own (CI's installer-gate job, on a root runner), and the verdict says so.
INSTALLER_LEFT=0
if [ "${INSTALL_GATE_SKIP_INSTALLER:-0}" = 1 ]; then
  INSTALLER_LEFT=1
  echo "  (the installer's cases are left to install/installer-gate.sh's own run: INSTALL_GATE_SKIP_INSTALLER=1)"
else
  "$HERE/installer-gate.sh" && rc=0 || rc=$?
  case "$rc" in
    0) pass "the installer's cases: its pinned policy, its renderings, its dry run and its real runs (above)" ;;
    77) SKIPPED="${SKIPPED:-}part of the installer's cases (its real runs need a disposable root box; named above); " ;;
    *) fail "the installer's cases" "installer-gate.sh exited $rc; its own output above names the case" ;;
  esac
fi

if [ "${INSTALL_GATE_PLANES_ONLY:-0}" = 1 ]; then
  printf '\n=== install gate, the --plane and keyed cases only: %d ok, %d failed ===\n' "$ok" "$bad"
  [ -n "${SKIPPED:-}" ] && printf 'SKIPPED, and not counted as passing: %s\n' "$SKIPPED"
  if [ "$bad" -ne 0 ]; then echo "INSTALL GATE: FAILED"; exit 1; fi
  if [ -n "${SKIPPED:-}" ]; then echo "INSTALL GATE: INCOMPLETE - everything that ran passed, but part of the gate could not run here"; exit 1; fi
  if [ "$KEYED_LEFT" = 1 ] || [ "$INSTALLER_LEFT" = 1 ]; then
    echo "INSTALL GATE: CLEAR (the --plane cases only; the keyed and installer cases are their own gates' runs, and the live cases were not asked for)"
  else
    echo "INSTALL GATE: CLEAR (the --plane and keyed cases; the live cases were not asked for)"
  fi
  exit 0
fi

[ "$KEYED_LEFT" = 1 ] && SKIPPED="${SKIPPED:-}the keyed cases (INSTALL_GATE_SKIP_KEYED=1); "
[ "$INSTALLER_LEFT" = 1 ] && SKIPPED="${SKIPPED:-}the installer's cases (INSTALL_GATE_SKIP_INSTALLER=1); "
echo "=== install gate: $BASE"

D="$W/lib"
mkdir -p "$D"

# --- the key, fetched once ---------------------------------------------------------------------
curl -fsS --max-time 60 -o "$D/edge.pub" "$BASE/edge-signing-key.pub" 2>/dev/null \
  && [ -s "$D/edge.pub" ] \
  && pass "the signing key fetches from the live feed ($(wc -c <"$D/edge.pub") bytes)" \
  || { fail "the signing key fetches" "cannot reach $BASE"; echo "INSTALL GATE: FAILED"; exit 1; }

# --- a first real refresh ----------------------------------------------------------------------
out=$("$REFRESH" --dir "$D" --base "$BASE" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && [ -s "$D/snapshot.bin" ] && says "$out" "signature verified"; } \
  && pass "a first refresh verifies the signature and installs the snapshot ($(wc -c <"$D/snapshot.bin") bytes)" \
  || fail "a first refresh installs a verified snapshot" "rc=$rc $out"
# The modules re-read the snapshot themselves, so this half says "no reload" and is right to. It is
# also the control for the resolver half, which must never print it: the same grep, the other answer.
says "$out" "no reload" \
  && pass "and says the modules pick it up with no reload, which is true of the snapshot" \
  || fail "the snapshot install says no reload is needed" "$out"

FIRST_MTIME=$(stat -c %Y "$D/snapshot.bin" 2>/dev/null || echo 0)
FIRST_SUM=$(sha256sum "$D/snapshot.bin" | cut -d' ' -f1)

# --- unchanged must stay untouched -------------------------------------------------------------
sleep 1
out=$("$REFRESH" --dir "$D" --base "$BASE" 2>&1) && rc=0 || rc=$?
NOW_MTIME=$(stat -c %Y "$D/snapshot.bin" 2>/dev/null || echo 0)
{ [ "$rc" = 0 ] && says "$out" "unchanged" && [ "$NOW_MTIME" = "$FIRST_MTIME" ]; } \
  && pass "a second refresh leaves an unchanged file alone, mtime included" \
  || fail "an unchanged snapshot is left alone" "rc=$rc mtime $FIRST_MTIME -> $NOW_MTIME; $out"

# --- an unreachable feed must change nothing ----------------------------------------------------
out=$("$REFRESH" --dir "$D" --base "https://edge.invalid.whisper-test.example" 2>&1) && rc=0 || rc=$?
NOW_SUM=$(sha256sum "$D/snapshot.bin" | cut -d' ' -f1)
{ [ "$rc" != 0 ] && [ "$NOW_SUM" = "$FIRST_SUM" ]; } \
  && pass "an unreachable feed fails and leaves the installed snapshot byte-identical" \
  || fail "an unreachable feed changes nothing" "rc=$rc sum changed: $([ "$NOW_SUM" = "$FIRST_SUM" ] && echo no || echo YES)"

# --- a BAD SIGNATURE must never reach the served path -------------------------------------------
#
# The strongest case here, and the reason the download lands on a .new file. A stub feed serves a
# real-looking snapshot with a signature that does not match it; the installed file must not move.
PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)
mkdir -p "$W/stub/edge"
# Real bytes, wrong signature: the snapshot is the live one with a byte flipped, so the signature
# we serve beside it is a genuine signature over DIFFERENT content. That is exactly the shape of a
# tampered or truncated download, which is what this must refuse. The byte is inverted, never
# overwritten with a constant: a constant is a no-op wherever the file already holds it, and the
# live snapshot at generation 497912 held 'x' at offset 64, so the stub served the genuine file.
cp "$D/snapshot.bin" "$W/stub/edge/snapshot.bin"
flip_byte "$W/stub/edge/snapshot.bin" 64
curl -fsS --max-time 60 -o "$W/stub/edge/snapshot.bin.sig" "$BASE/snapshot.bin.sig"
( cd "$W/stub" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$W/stub.pid" )
i=0; while [ "$i" -lt 50 ]; do curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/edge/snapshot.bin" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
if cmp -s "$W/stub/edge/snapshot.bin" "$D/snapshot.bin"; then
  fail "a bad signature is refused" "the fixture: the stub's snapshot is byte-identical to the installed one, so nothing was tampered and the row proves nothing"
else
  out=$("$REFRESH" --dir "$D" --base "http://127.0.0.1:$PORT/edge" 2>&1) && rc=0 || rc=$?
  NOW_SUM=$(sha256sum "$D/snapshot.bin" | cut -d' ' -f1)
  { [ "$rc" != 0 ] && says "$out" "SIGNATURE DID NOT VERIFY" && [ "$NOW_SUM" = "$FIRST_SUM" ]; } \
    && pass "a snapshot whose signature does not verify is REFUSED and never replaces the live one" \
    || fail "a bad signature is refused" "rc=$rc sum_unchanged=$([ "$NOW_SUM" = "$FIRST_SUM" ] && echo yes || echo NO); $out"
fi
# ...and no partial download is left behind for a later run to pick up.
[ -z "$(find "$D" -name 'snapshot.bin.new*' 2>/dev/null)" ] \
  && pass "and it leaves no partial .new file behind" \
  || fail "no partial file is left" "$(find "$D" -name 'snapshot.bin.new*')"
[ -f "$W/stub.pid" ] && kill "$(cat "$W/stub.pid")" 2>/dev/null || true

# --- the resolver half, against the live feed ---------------------------------------------------
# The live reputation zone, by name, has to verify against the key the install fetched, pass its header
# and record checks and named-checkzone, and install; no named loads this copy, and the script has to
# say that rather than claim a reload. Until the feed serves zones by name the refresh answers exit 5,
# "not published yet": that, and only that, leaves the live zone rows unrun, said by name, and the gate
# INCOMPLETE rather than CLEAR, since nothing about the live zone was proven. Any other outcome is a result.
out=$("$REFRESH" --zone rpz.whisper.online --dir "$D" --zone-file "$D/rpz.zone" --base "$BASE" 2>&1) && rc=0 || rc=$?
if [ "$rc" = 5 ] && says "$out" "is not published yet (HTTP 404"; then
  printf '  DARK  the live reputation zone by name: %s/rpz/rpz.whisper.online.zone answers 404 (not served yet)\n' "$BASE"
  SKIPPED="${SKIPPED:-}the live zone rows (the feed does not serve /rpz/<origin>.zone yet); "
else
  { [ "$rc" = 0 ] && [ -s "$D/rpz.zone" ] && says "$out" "signature verified, checked by named-checkzone"; } \
    && pass "the zone half verifies the live reputation zone's signature, checks it and installs it ($(wc -c <"$D/rpz.zone") bytes)" \
    || fail "the zone half installs the live zone" "rc=$rc $out"
  says "$out" "named does not load $D/rpz.zone" \
    && pass "and, with no named loading that file, it says nothing was reloaded" \
    || fail "the zone half says when named does not load the file" "$out"
fi

# --- the policy-zone fetch honours WHISPER_EDGE_RESOLVE: a stub on 127.0.0.4 alone, a base that does not
#     resolve, so only the pin reaches it; the control is the refresh with that one line taken out. The stub
#     serves what the feed serves for per-plane zones: the zone by name and its signature by hash, signed over
#     whisper-edge-zone-v1, one NUL, then the file, with the gate's own key.
RZ="$W/rpz-stub"; mkdir -p "$RZ/edge/rpz" "$RZ/edge/zones"
cp "$HERE/../rpz/testdata/rpz.whisper.online.empty-1791993600.zone" "$RZ/edge/rpz/rpz.whisper.online.zone"
ZSHA=$(sha256sum < "$RZ/edge/rpz/rpz.whisper.online.zone" | cut -d' ' -f1)
{ printf 'whisper-edge-zone-v1\000'; cat "$RZ/edge/rpz/rpz.whisper.online.zone"; } > "$W/rpz-stub.msg"
openssl pkeyutl -sign -inkey "$P/key.pem" -rawin -in "$W/rpz-stub.msg" -out "$RZ/edge/zones/$ZSHA.zone.sig"
PORT4=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.4", 0)); print(s.getsockname()[1])')
( cd "$RZ" && exec python3 -m http.server "$PORT4" --bind 127.0.0.4 >/dev/null 2>&1 ) &
echo $! >> "$W/plane-servers.pid"
i=0; while [ "$i" -lt 50 ]; do curl -fsS --max-time 1 -o /dev/null "http://127.0.0.4:$PORT4/edge/rpz/rpz.whisper.online.zone" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
R4="edge.rpz-gate.invalid:$PORT4:127.0.0.4"; B4="http://edge.rpz-gate.invalid:$PORT4/edge"
mkdir -p "$W/rpz-pin" "$W/rpz-nopin"; cp "$P/key.pub" "$W/rpz-pin/edge.pub"; cp "$P/key.pub" "$W/rpz-nopin/edge.pub"
out=$(env WHISPER_EDGE_RESOLVE="$R4" "$REFRESH" --zone rpz.whisper.online --dir "$W/rpz-pin" --zone-file "$W/rpz-pin/rpz.zone" --base "$B4" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && cmp -s "$W/rpz-pin/rpz.zone" "$RZ/edge/rpz/rpz.whisper.online.zone"; } \
  && pass "the policy-zone fetch is pinned by WHISPER_EDGE_RESOLVE: only the pin reaches the stub, and its signed zone installs" \
  || fail "the policy-zone pin" "rc=$rc $out"
sed '/WHISPER_EDGE_RESOLVE:-}" \] && set -- "\$@" --resolve/d' "$REFRESH" > "$W/refresh-rpz-no-pin"; chmod +x "$W/refresh-rpz-no-pin"
if cmp -s "$REFRESH" "$W/refresh-rpz-no-pin"; then
  fail "the policy-zone pin control" "the control's edit did not apply to $REFRESH, so it proves nothing"
else
  out=$(env WHISPER_EDGE_RESOLVE="$R4" "$W/refresh-rpz-no-pin" --zone rpz.whisper.online --dir "$W/rpz-nopin" --zone-file "$W/rpz-nopin/rpz.zone" --base "$B4" 2>&1) && rc=0 || rc=$?
  { [ "$rc" != 0 ] && [ ! -e "$W/rpz-nopin/rpz.zone" ]; } \
    && pass "the control: a policy-zone fetch without the pin cannot reach the stub and installs nothing" \
    || fail "the policy-zone pin control" "rc=$rc $out"
fi
stop_servers

# --- the resolver half, against a REAL BIND -----------------------------------------------------
#
# Every case below runs the real script against a real named and a stub feed whose zone the gate
# advances, and checks what named says it LOADED (rndc zonestatus, and dig against the zone), never
# what the script says it did. Each check has a control that must fail it, run in the same harness,
# so a check that cannot see the failure it exists for is caught here rather than in the field.
#
# WHY UNDER /var/cache/bind: Ubuntu's AppArmor profile lets named read /etc/bind, /var/lib/bind and
# /var/cache/bind and nothing else. The installer puts the zone under named's own directory for that
# reason, so the gate does too; a gate that ran named from its temp directory would be proving a path
# no installed resolver uses.
"$HERE/rpz-bind-gate.sh" && rc=0 || rc=$?
case "$rc" in
  0) pass "the zone refresh against a real BIND: every case and every control behaved (above)" ;;
  77) SKIPPED="${SKIPPED:-}the real-BIND cases (named, rndc or a /var/cache/bind work directory is unavailable here); " ;;
  *) fail "the zone refresh against a real BIND" "rpz-bind-gate.sh exited $rc; its own output above names the case" ;;
esac

# --- the installer itself, in dry-run, must resolve each server's own user ----------------------
# --no-apply as well: a dry run prints a server's block only when that server's module is installed,
# and the paste rows below are about every server that is here, module or not, which --no-apply prints.
out=$("$HERE/install.sh" --dry-run --no-apply --dir "$D" --base "$BASE" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && says "$out" "== detected"; } \
  && pass "install.sh --dry-run runs end to end and reports what it found" \
  || fail "install.sh --dry-run runs" "rc=$rc"
# It must never claim a user that does not exist on this host: a counters directory granted to a
# name nobody has fails silently, because counting is not on the request path.
badu=0
for u in $(printf '%s' "$out" | sed -n 's/.*runs as \([A-Za-z0-9_-]\{1,\}\)$/\1/p'); do
  id "$u" >/dev/null 2>&1 || { fail "install.sh named a user that does not exist" "$u"; badu=1; }
done
[ "$badu" = 0 ] && pass "every server user it named exists on this host"
# And it must print the paste block for each server that is actually here.
command -v nginx >/dev/null 2>&1 && { says "$out" "load_module" \
  && pass "nginx is here, so the nginx paste block is printed" \
  || fail "the nginx paste block is printed" ""; }
{ command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; } && { says "$out" "LoadModule whisper_edge_module" \
  && pass "Apache is here, so its LoadModule block is printed" \
  || fail "the Apache paste block is printed" ""; }
command -v named >/dev/null 2>&1 && { says "$out" "response-policy" \
  && pass "BIND is here, so the response-policy block is printed" \
  || fail "the BIND paste block is printed" ""; }

# --- what the installer PRINTS, loaded by each server's own configuration test --------------------
#
# A paste block nobody loads is a document. One of these once named a directive no module registers;
# nginx and Apache both refused it, and every row above stayed green, because they only looked for the
# block. So each block goes through the server's own test, verbatim except for the module's path,
# which points at the copy built in this tree. OpenLiteSpeed has no configuration test and needs root
# to start, so here its block is checked statically: the block's name must be the symbol the module
# exports (the server looks that symbol up in modules/<name>.so, and any other name fails to load),
# and every key must be one the module registers (the server accepts an unregistered key silently).
# litespeed/litespeed-gate.sh, which runs the server as root, loads the same printed block for real.
# One server's printed block: its header line and the lines after it, up to the first line that is blank,
# not indented, a report line (three spaces), or the next server's header. The report prints the blocks back to back with nothing
# between them, so a range that waited for a blank line ran on into the next server's block and the
# report's own lines, and handed those to this server's configuration test.
block_of() { # <the output> <server header word, e.g. nginx>
  printf '%s\n' "$1" | awk -v h="  # $2:" '
    !on && index($0, h) == 1 { on = 1; print; next }
    on && ($0 == "" || $0 !~ /^  / || $0 ~ /^   [^ ]/ || $0 ~ /^  # [A-Za-z]+: /) { exit }
    on { print }'
}
printed_block_cases() { # printed_block_cases <the output of install.sh --dry-run>
  Z="$W/printed"; mkdir -p "$Z"
  if says "$1" '^  # nginx:'; then
    # Several trees can leave a built module under /tmp: prefer the one compiled from THIS tree's source.
    ngxmod="${NGX_MODULE:-}"; ngxnote=""
    if [ -z "$ngxmod" ]; then
      ngxnote=" (not built from this tree)"
      ngxsrc="$(cd "$HERE/../nginx" && pwd)/ngx_http_whisper_edge_module.c"
      while IFS= read -r m; do
        [ -n "$m" ] || continue
        [ -z "$ngxmod" ] && ngxmod="$m"
        if grep -qF -- "$ngxsrc" "$(dirname "$m")/Makefile" 2>/dev/null; then ngxmod="$m"; ngxnote=""; break; fi
      done <<EOF
$(find "${NGX_BUILD:-/tmp}" -name ngx_http_whisper_edge_module.so 2>/dev/null)
EOF
    fi
    if [ -z "$ngxmod" ] || [ ! -f "$ngxmod" ]; then
      fail "nginx's printed block loads under nginx -t" "no built module: set NGX_MODULE, or NGX_BUILD to the build directory (nginx/nginx-gate.sh prints how to build one)"
    else
      { printf 'error_log %s/error.log;\npid %s/nginx.pid;\n' "$Z" "$Z"
        block_of "$1" nginx | sed "s#^\( *load_module \)[^;]*;#\1$ngxmod;#"
        printf 'events { }\n'; } > "$Z/nginx.conf"
      t=$(nginx -t -c "$Z/nginx.conf" -p "$Z" 2>&1) && rc=0 || rc=$?
      # named by file and digest, never by path: the path is the host's, and this line is published
      ngxid="module $(basename "$ngxmod") sha256:$(sha256sum "$ngxmod" | cut -c1-12)$ngxnote"
      { [ "$rc" = 0 ] && says "$t" 'test is successful'; } \
        && pass "nginx -t accepts the block the installer prints for nginx ($ngxid)" \
        || fail "nginx -t accepts the printed nginx block ($ngxid)" "rc=$rc $(printf '%s' "$t" | grep -E 'emerg|test failed' | sed "s#$Z/##g" | head -2)"
      # the same block in a directory its group may write: the module's StrictModes must refuse it
      Zg="$W/printed-0775"; rm -rf "$Zg"; mkdir "$Zg"; chmod 0775 "$Zg"
      sed "s#$Z/#$Zg/#g" "$Z/nginx.conf" > "$Zg/nginx.conf"
      t=$(nginx -t -c "$Zg/nginx.conf" -p "$Zg" 2>&1) && rc=0 || rc=$?
      { [ "$rc" != 0 ] && says "$t" 'writable by its group'; } \
        && pass "nginx -t refuses the same block in a directory its group may write (StrictModes, $ngxid)" \
        || fail "nginx -t refuses the printed block in a 0775 directory ($ngxid)" "rc=$rc $(printf '%s' "$t" | grep -E 'emerg|test' | sed "s#$Zg/##g" | head -2)"
    fi
  fi
  if says "$1" '^  # Apache:'; then
    httpd=$(command -v apache2 || command -v httpd)
    apmod="${APACHE_MODULE:-$HERE/../apache/.libs/mod_whisper_edge.so}"
    mods=${APACHE_MODULES:-/usr/lib/apache2/modules}
    [ -d "$mods" ] || mods="$("$httpd" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p')/modules"
    mpm=""
    case "$("$httpd" -l 2>/dev/null)" in
      *prefork.c*|*worker.c*|*event.c*) ;;
      *) for m in event worker prefork; do
           [ -f "$mods/mod_mpm_$m.so" ] && { mpm="LoadModule mpm_${m}_module $mods/mod_mpm_$m.so"; break; }
         done ;;
    esac
    if [ ! -f "$apmod" ]; then
      fail "Apache's printed block loads under $(basename "$httpd") -t" "no built module at ${APACHE_MODULE:-apache/.libs/mod_whisper_edge.so}: run apache/build.sh, or set APACHE_MODULE"
    else
      { printf 'ServerRoot %s\nServerName 127.0.0.1\nPidFile %s/httpd.pid\nErrorLog %s/error.log\n%s\n' \
          "$Z" "$Z" "$Z" "$mpm"
        block_of "$1" Apache | sed "s#^\( *LoadModule whisper_edge_module \).*#\1$apmod#"
      } > "$Z/httpd.conf"
      t=$("$httpd" -t -f "$Z/httpd.conf" 2>&1) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && says "$t" 'Syntax OK'; } \
        && pass "$(basename "$httpd") -t accepts the block the installer prints for Apache" \
        || fail "$(basename "$httpd") -t accepts the printed Apache block" "rc=$rc $(printf '%s' "$t" | sed "s#$Z/##g" | head -2)"
    fi
  fi
  if says "$1" '^  # OpenLiteSpeed:'; then
    olsblock=$(block_of "$1" OpenLiteSpeed)
    name=$(printf '%s\n' "$olsblock" | sed -n 's/^[[:space:]]*module[[:space:]]\{1,\}\([A-Za-z0-9_]*\)[[:space:]]*{.*/\1/p' | head -1)
    symbol=$(sed -n 's/^#define MNAME //p' "$HERE/../litespeed/mod_whisper_edge.c")
    { [ -n "$symbol" ] && [ "$name" = "$symbol" ]; } \
      && pass "the OpenLiteSpeed block the installer prints is named for the module's exported symbol ($symbol)" \
      || fail "the printed OpenLiteSpeed block is named for the module's exported symbol" "printed: module ${name:-(none)} {; the module exports: ${symbol:-(none)}"
    keys=$(printf '%s\n' "$olsblock" | sed -n 's/^[[:space:]]*\(whisper_edge_[a-z_]*\)[[:space:]].*/\1/p')
    known=$(sed -n 's/^[[:space:]]*{ "\(whisper_edge_[a-z_]*\)",.*/\1/p' "$HERE/../litespeed/mod_whisper_edge.c")
    unknown=""
    for k in $keys; do
      if ! grep -qx -- "$k" <<EOF
$known
EOF
      then
        unknown="$unknown $k"
      fi
    done
    { [ -n "$keys" ] && [ -n "$known" ] && [ -z "$unknown" ]; } \
      && pass "every key the installer prints for OpenLiteSpeed is one the module registers ($(echo $keys))" \
      || fail "the printed OpenLiteSpeed keys are registered by the module" "printed: $(echo $keys); not registered:${unknown:- (none)}; registered: $(echo $known)"
  fi
}
printed_block_cases "$out"

# --- what the installer schedules for BIND: the zone template's command and writable path, one timer
# per zone, the block's files, order and RPKI override, read from the unit files a real run writes, are
# installer-gate.sh's rows (the resolver half's units), which run above.

# THE PAGE MUST AGREE WITH THIS RUN. REFERENCE.md prints this line as a transcript, and it said 20 while
# the gate printed 41: a number typed into prose goes stale on the edit that adds a row, and nothing
# noticed. So the gate compares, and the page can only be wrong if this goes red. NOT counted in ok:
# the number being compared IS the ok count.
README="$HERE/../REFERENCE.md"
# The trigger is a real count, digits only: prose that describes the line, or a placeholder such as
# <ok>, must never arm a comparison that only a transcript can pass.
if [ "$bad" -eq 0 ] && [ -z "${SKIPPED:-}" ] && [ -f "$README" ] && grep -Eq '=== install gate: [0-9]+ ok' "$README"; then
  want="=== install gate: $ok ok, 0 failed ==="
  if grep -qF -- "$want" "$README"; then
    printf '  ok    REFERENCE.md prints this run'"'"'s own count, so the page cannot go stale unnoticed\n'
  else
    printf '  FAIL  REFERENCE.md says "%s" and this run is "%s"\n' \
      "$(grep -oE '=== install gate: [0-9]+ ok, [0-9]+ failed ===' "$README" | head -1)" "$want"
    bad=$((bad + 1))
  fi
fi
printf '\n=== install gate: %d ok, %d failed ===\n' "$ok" "$bad"
[ -n "${SKIPPED:-}" ] && printf 'SKIPPED, and not counted as passing: %s\n' "$SKIPPED"
if [ "$bad" -ne 0 ]; then echo "INSTALL GATE: FAILED"; exit 1; fi
if [ -n "${SKIPPED:-}" ]; then
  echo "INSTALL GATE: INCOMPLETE - everything that ran passed, but part of the gate could not run here"
  exit 1
fi
echo "INSTALL GATE: CLEAR - the refresh verifies, replaces atomically, fails without touching anything, and keeps a real BIND's zone current"
