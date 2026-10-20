#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# The gate a capture passes before it is attached anywhere: no key, no part of one, no header file.
#
# By VALUE first: it reads the key files the run used (the owner's and the feed key's) without printing
# them, and refuses a capture that contains any 12-character substring of a key's random tail. The fixed
# "whisper_live_" prefix is left out of that tail, so the value check never fires on a metric name.
# Then by SHAPE, as a second net, for a key no key file names: whisper[-_][A-Za-z0-9_-]{16,}, except the
# identifiers this project ships, which a capture of the keyed unit is made of: the whisper-edge-*
# programs and units and the whisper_ns_ and whisper_edge_ metric names. A
# minted key (whisper_live_, whisper_test_) and any other whisper- or whisper_ run of 16 or more is
# still refused, and the shape net fails closed: a match is a refusal to read, never a pass. The net
# looks for the shape at every position, so a key glued onto a shipped name (whisper-edge-refresh
# followed directly by whisper_live_...) is found as its own match and refused.
# A capture shows a key as "Bearer whisper_live_<redacted>", which neither check matches.
# It reads the plain-text form only: a key that is base64 or percent encoded, reversed, or hard-wrapped
# (a fold right after "whisper_live_" included) is not seen, so attach text as the run printed it.
#
# It never prints what it found, only where: the file, the line, the column, and which check.
#
# Usage:
#   capture-scrub.sh --key-file F [--key-file F ...] CAPTURE...
#   capture-scrub.sh --self-test
#
# Exit 0 CLEAR, 1 refused, 2 usage.
set -uo pipefail

scrub() { # key files, then "--", then captures
  python3 - "$@" <<'PY'
import re, sys
args = sys.argv[1:]
cut = args.index("--")
keyfiles, captures = args[:cut], args[cut + 1:]
PREFIX = "whisper_live_"
# a lookahead, so every starting position is tried and a run inside a shipped name is seen on its own
SHAPE = re.compile(r"(?=(whisper[-_][A-Za-z0-9_-]{16,}))")
# the shipped identifiers: never a key, since a minted key is whisper_live_ or whisper_test_
SHIPPED = re.compile(r"^whisper(-edge-|_ns_|_edge_)")
tails = []
for kf in keyfiles:
    try:
        k = open(kf, encoding="utf-8", errors="replace").read().strip()
    except OSError as e:
        print("capture-scrub: cannot read the key file %s (%s)" % (kf, e.strerror)); sys.exit(2)
    t = k[len(PREFIX):] if k.startswith(PREFIX) else k
    if len(t) < 12:
        print("capture-scrub: %s holds no key long enough to check" % kf); sys.exit(2)
    tails.append(t)
grams = set()
for t in tails:
    for i in range(len(t) - 11):
        grams.add(t[i:i + 12])
bad = 0
for cap in captures:
    try:
        text = open(cap, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print("capture-scrub: cannot read %s (%s)" % (cap, e.strerror)); bad += 1; continue
    for n, line in enumerate(text.splitlines(), 1):
        hit = None
        for i in range(len(line) - 11):
            if line[i:i + 12] in grams:
                hit = ("a 12-character piece of a key", i + 1); break
        if hit is None:
            for m in SHAPE.finditer(line):
                if not SHIPPED.match(m.group(1)):
                    hit = ("the key shape whisper[-_][A-Za-z0-9_-]{16,}", m.start() + 1)
                    break
        if hit:
            print("REFUSED %s:%d:%d: %s" % (cap, n, hit[1], hit[0])); bad += 1
print("capture-scrub: %s (%d capture%s, %d key file%s)" % ("REFUSED" if bad else "CLEAR", len(captures),
      "" if len(captures) == 1 else "s", len(keyfiles), "" if len(keyfiles) == 1 else "s"))
sys.exit(1 if bad else 0)
PY
}

self_test() {
  local W ok=0 bad=0 key rc
  W=$(mktemp -d); trap 'rm -rf "$W"' RETURN
  pass() { ok=$((ok + 1)); printf '  ok    %s\n' "$1"; }
  fail() { bad=$((bad + 1)); printf '  FAIL  %s\n' "$1"; }
  # a key whose first tail characters are "-" and "_", the 22.4% that a pattern without - and _ in its class missed
  key="whisper_live_-_$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(23)).decode().rstrip("=")[:30])')"
  printf '%s\n' "$key" > "$W/key"
  printf 'Authorization: Bearer whisper_live_<redacted>\nwhisper_ns_edge_feed_requests_total{tier="keyed"} 7\n' > "$W/clean"
  printf 'curl -H "Authorization: Bearer %s"\n' "$key" > "$W/whole"
  printf 'the tail ends ...%s\n' "${key: -12}" > "$W/piece"
  printf 'a key from elsewhere: whisper-0123456789abcdefXYZ\n' > "$W/shape"
  scrub "$W/key" -- "$W/whole" > "$W/o" && rc=0 || rc=$?
  [ "$rc" = 1 ] && ! grep -qF -- "${key:13}" "$W/o" && pass "a capture holding the key is refused, and the refusal does not print it" || fail "the whole key"
  scrub "$W/key" -- "$W/piece" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "a capture holding only the last 12 characters of the key is refused (by value)" || fail "a 12-character piece"
  scrub "$W/key" -- "$W/shape" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "a key-shaped string no key file names is refused (by shape)" || fail "the shape net"
  printf 'whisper_ns_edge_feed_requests_total 7\n' > "$W/metric"
  [ "$(python3 -c 'import sys
k = open(sys.argv[1]).read().strip()[13:]
t = open(sys.argv[2]).read()
print("hit" if any(k[i:i+12] in t for i in range(len(k)-11)) else "none")' "$W/key" "$W/metric")" = none ] \
    && pass "the value check alone never fires on a whisper_ns_ metric name (the prefix is not part of the tail)" \
    || fail "the value check and the metric names"
  scrub "$W/key" -- "$W/clean" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 0 ] && pass "a whisper_ns_ metric line and the redacted header are CLEAR" || fail "the shipped metric names"
  printf 'Starting whisper-edge-refresh-keyed.service\nsystemctl list-timers whisper-edge-refresh-keyed.timer\nwhisper_edge_rpz_reloads_total 3\n' > "$W/unit"
  scrub "$W/key" -- "$W/unit" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 0 ] && pass "a capture of the keyed unit (its name in the journal and in list-timers) is CLEAR" || fail "the keyed unit's own names"
  printf 'whisper-%s\n' "$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(24)).decode()[:30])')" > "$W/dashkey"
  scrub "$W/key" -- "$W/dashkey" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "a whisper- prefixed 30-character key no key file names is still REFUSED" || fail "a whisper- key"
  printf 'whisper_test_%s\n' "$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(24)).decode()[:32])')" > "$W/testkey"
  scrub "$W/key" -- "$W/testkey" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "a whisper_test_ key no key file names is REFUSED" || fail "a whisper_test_ key"
  sed 's/^SHIPPED = re.compile(.*$/SHIPPED = re.compile(r"^$")/' "$0" > "$W/broad.sh"
  bash "$W/broad.sh" --key-file "$W/key" "$W/unit" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "control: a shape net with no shipped-name exemption refuses the keyed unit's own capture" || fail "control: the exemption is visible"
  # a key glued onto a shipped name: the shipped prefix exempts the run it starts, never the key inside it
  printf 'whisper-edge-refreshwhisper_test_%s\n' "$(python3 -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(24)).decode()[:32])')" > "$W/glued"
  scrub "$W/key" -- "$W/glued" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 1 ] && pass "a key glued onto a shipped name (whisper-edge-refresh then whisper_test_...) is REFUSED" || fail "a glued key"
  sed 's/^SHAPE = re.compile(.*$/SHAPE = re.compile(r"(whisper[-_][A-Za-z0-9_-]{16,})")/' "$0" > "$W/anchored.sh"
  bash "$W/anchored.sh" --key-file "$W/key" "$W/glued" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 0 ] && pass "control: a net that tries only where a run starts clears the glued key, so the lookahead is what refuses it" || fail "control: the lookahead is visible"
  printf 'Authorization: Bearer whisper_live_<redacted>\n' > "$W/redacted"
  scrub "$W/key" -- "$W/redacted" > /dev/null && rc=0 || rc=$?
  [ "$rc" = 0 ] && pass "a capture with the key redacted as whisper_live_<redacted> is CLEAR" || fail "the redacted form"
  # control: a pattern without - and _ in its class, whisper_live_[A-Za-z0-9]{8,}, misses this key entirely
  grep -Eq 'whisper_live_[A-Za-z0-9]{8,}' "$W/whole" && fail "control: a pattern without - and _ in its class catches the key" \
    || pass "control: a pattern without - and _ in its class, whisper_live_[A-Za-z0-9]{8,}, misses a key whose tail starts with - or _"
  printf '\n=== capture-scrub self-test: %d ok, %d failed ===\n' "$ok" "$bad"
  [ "$bad" = 0 ]
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  ''|-h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2 ;;
esac
KEYS=()
while [ "${1:-}" = --key-file ]; do KEYS+=("$2"); shift 2; done
[ "${#KEYS[@]}" -gt 0 ] && [ $# -gt 0 ] || { echo "usage: capture-scrub.sh --key-file F [--key-file F ...] CAPTURE..." >&2; exit 2; }
scrub "${KEYS[@]}" -- "$@"
