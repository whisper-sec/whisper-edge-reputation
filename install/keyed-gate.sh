#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# The keyed half of the install gate: whisper-edge-refresh with a feed key, against a local fake feed.
#
# Offline, like the --plane cases: testdata/fake-feed.py serves the keyed grammar over TLS on two
# loopback addresses with two Whisper-Node values, with authentication before everything, If-Match,
# the status map, and op:edge's key sub-ops in the front door's envelope. Shims stand in for the three
# things a gate cannot otherwise steer: getent (which addresses the name has), date (the script's clock)
# and curl (to record argv and environment, and to probe the directory lock at every request).
#
# Every case asserts a property and runs a CONTROL that must fail it, most of them a copy of the
# script with one mechanism removed (mutant_* below), so no check here can pass by being unable to
# see the failure it exists for. The cases that need root (the keyed unit's real sandbox through
# systemd-run, the immutable attribute) run under passwordless sudo, and without it the gate says
# it is INCOMPLETE rather than passing.
#
# Run by install-gate.sh in both its modes; on its own: install/keyed-gate.sh
# shellcheck disable=SC2015
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REFRESH="${INSTALL_GATE_REFRESH:-$HERE/whisper-edge-refresh}"
TSC="$HERE/tenant-state-case.sh"
CORE="$HERE/../core"
W="$(mktemp -d -t whisper-edge-keyed-gate.XXXXXX)"
FEED_PID=""
SUDO_DIR=""
stop_feed() { [ -n "$FEED_PID" ] && kill "$FEED_PID" 2>/dev/null; FEED_PID=""; return 0; }
# Every non-zero exit names its cause. Under set -eu an unguarded command that fails ends the gate where it
# stands, and before this the run then stopped with exit 1 and no line saying why (a row expecting output
# the installer no longer printed did exactly that). The EXIT trap reads the status first: a non-zero exit
# that printed no verdict prints one, FAIL naming the row it was in, or NOT PROVEN for a setup stop.
CUR_ROW=""; VERDICT=""
verdict_on_exit() { # <exit status>
  [ "$1" = 0 ] || [ -n "$VERDICT" ] && return 0
  case "$1:$CUR_ROW" in
    2:) printf '  NOT PROVEN: the keyed gate stopped during its setup (exit 2), before any row ran; its line above says what was missing\n' ;;
    *:) printf '  FAIL  the keyed gate ended with exit %s during its setup, before any row ran and before its verdict\n' "$1" ;;
    *) printf '  FAIL  the keyed gate ended with exit %s inside row %s, before its verdict: a command there failed unguarded\n' "$1" "$CUR_ROW" ;;
  esac
  printf '\n=== keyed gate: ENDED EARLY (exit %s), %d ok, %d failed before it ===\n' "$1" "${ok:-0}" "${bad:-0}"
}
cleanup() {
  _rc=$?
  verdict_on_exit "$_rc"
  stop_feed
  for p in "$W"/srv.*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
  chattr -R -i "$W" 2>/dev/null || true
  rm -rf "$W"
  if [ -n "$SUDO_DIR" ]; then sudo -n chattr -R -i "$SUDO_DIR" 2>/dev/null; sudo -n rm -rf "$SUDO_DIR"; fi
  return 0
}
# the gate's own control seam: an unguarded failure planted where the gate stands, read by the row
# 'verdict' below from a child run; it is a test hook of this file and touches no host state
case "${KEYED_GATE_PLANT_ABORT:-}" in
  setup) trap cleanup EXIT; false ;;
  row) trap cleanup EXIT; CUR_ROW=planted; ok=0; bad=0; false ;;
  silent) trap cleanup EXIT; CUR_ROW=planted; VERDICT=suppressed; false ;;
  '') ;;
  *) echo "keyed-gate: KEYED_GATE_PLANT_ABORT=$KEYED_GATE_PLANT_ABORT is not setup, row or silent"; exit 2 ;;
esac
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ok=0; bad=0; SKIPPED=""
pass() { printf '  ok    %s\n' "$1"; ok=$((ok+1)); }
fail() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; bad=$((bad+1)); }
says() { grep -q -- "$2" <<EOF
$1
EOF
}

for t in python3 openssl flock curl cc; do
  command -v "$t" >/dev/null 2>&1 || { echo "keyed-gate: $t is required"; exit 2; }
done
# Concurrent runs are isolated: everything a run writes is under its own mktemp -d ($W, and $R for the root rows),
# its ports are taken from the kernel, its transient units carry its pid. The one shared output is plane_check,
# built in the tree: a run that relinked it while another run's tenant-state check executed it made that check read
# a plane as unarmed (six runs started together after a source change failed rows 74b in three; the same six with
# the binary current all passed). So it is built under a lock on the core directory and each run executes its own
# copy, taken under the same lock.
flock "$CORE" sh -c 'make -s -C "$1" plane_check >/dev/null 2>&1 && cp "$1/plane_check" "$2/plane_check"' sh "$CORE" "$W" \
  || { echo "keyed-gate: cannot build core/plane_check"; exit 2; }
PLANE_CHECK="$W/plane_check"
# the module's side of the revocation mark: one we_mod_bind() as a server's restart runs it (row 56's join)
cc -std=c11 -O1 -o "$W/tenant_arm_probe" "$CORE/tenant_arm_probe.c" "$CORE/we_module.c" "$CORE/whisper_edge.c" \
  "$CORE/we_sha256.c" "$CORE/we_counters.c" "$CORE/we_policy.c" 2> "$W/tenant_arm_probe.err" \
  || { echo "keyed-gate: cannot build core/tenant_arm_probe.c: $(head -2 "$W/tenant_arm_probe.err")"; exit 2; }
REAL_CURL=$(command -v curl)
REAL_DATE=$(command -v date)
REAL_GETENT=$(command -v getent)

# ---- the fake feed: a CA, a signing key, two nodes --------------------------------------------------
F="$W/feed"; mkdir -p "$F/content" "$W/tmp" "$W/home"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=fake-feed \
  -addext "subjectAltName=IP:127.0.0.1,IP:127.0.0.2" -keyout "$W/tls.key" -out "$W/ca.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$W/sign.pem" 2>/dev/null
openssl pkey -in "$W/sign.pem" -pubout -out "$W/sign.pub" 2>/dev/null
# Every feed here is a stub, not the default one, so install.sh needs that feed's signing-key sha256 or it
# refuses the run as a usage error before the case under test (installer-gate.sh exports it the same way).
export WHISPER_EDGE_KEY_SHA256="$(sha256sum < "$W/sign.pub" | cut -c1-64)"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
NODE_A=aaaa1111; NODE_B=bbbb2222
start_feed() {
  stop_feed; rm -f "$F/ready"
  python3 "$HERE/testdata/fake-feed.py" --root "$F" --port "$PORT" --cert "$W/ca.pem" --key "$W/tls.key" \
    --node "127.0.0.1=$NODE_A" --node "127.0.0.2=$NODE_B" > "$W/feed.log" 2>&1 &
  FEED_PID=$!
  i=0; while [ ! -e "$F/ready" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
}
start_feed

# ---- shims --------------------------------------------------------------------------------------------
S="$W/shims"; mkdir -p "$S"
# getent: the feed's name has the addresses in $W/addrs, printed once per socket type as getent does
cat > "$S/getent" <<EOF
#!/bin/sh
if [ "\$1" = ahosts ] && [ -f "$W/addrs.\$2" ]; then
  for a in \$(cat "$W/addrs.\$2"); do printf '%s STREAM \$2\n%s DGRAM\n%s RAW\n' "\$a" "\$a" "\$a"; done
  exit 0
fi
exec "$REAL_GETENT" "\$@"
EOF
# date: the fake clock while $W/clock exists
cat > "$S/date" <<EOF
#!/bin/sh
if [ -f "$W/clock" ]; then
  n=\$(cat "$W/clock")
  case " \$* " in *" +%s "*) echo "\$n"; exit 0 ;; esac
  exec "$REAL_DATE" -d "@\$n" "\$@"
fi
exec "$REAL_DATE" "\$@"
EOF
# curl: record argv and environment; probe the lock for the keyed run's requests; step the fake clock
cat > "$S/curl" <<EOF
#!/bin/sh
if [ "\$1" = --version ] && [ -f "$W/curlver" ]; then echo "curl \$(cat "$W/curlver") (x86_64-pc-linux-gnu)"; exit 0; fi
{ printf 'argv'; for a in "\$@"; do printf ' %s' "\$a"; done; printf '\n'; } >> "$W/curl.argv"
# a transport failure for the control plane's requests (35, 60: TLS; 28: a timeout), as curl reports it
if [ -f "$W/curl.exit" ]; then case "\$*" in *api/query*) exit "\$(cat "$W/curl.exit")" ;; esac; fi
env >> "$W/curl.env"
if [ "\${WHISPER_EDGE_REQUEST:-}" = keyed ]; then
  [ -f "$W/clock" ] && printf '%s\n' "\$(cat "$W/clock")" >> "$W/curl.starts"
  if [ -f "$W/probe" ]; then
    d=\$(cat "$W/probe")
    ( flock -n -s "\$d" true; r=\$?
      if [ "\$r" = 1 ]; then echo "flock-held" >> "$W/probe.log"
      elif [ "\$r" != 0 ]; then echo "harness-error flock \$r" >> "$W/probe.log"; fi
      if mkdir "\$d/.refresh.lock.d" 2>/dev/null; then rmdir "\$d/.refresh.lock.d"
      else echo "mkdir-held" >> "$W/probe.log"; fi
      echo probed >> "$W/probe.log" )
  fi
  if [ -f "$W/clock.step" ] && [ -f "$W/clock" ]; then echo \$(( \$(cat "$W/clock") + \$(cat "$W/clock.step") )) > "$W/clock"; fi
fi
# a curl before 8.4.0, which ignores --max-filesize on an answer of unknown size: the option dropped
if [ -f "$W/curl.old" ]; then
  n=\$#; i=0; skip=0
  for a in "\$@"; do
    i=\$((i + 1))
    if [ "\$skip" = 1 ]; then skip=0
    elif [ "\$a" = --max-filesize ]; then skip=1
    else set -- "\$@" "\$a"; fi
    [ "\$i" = "\$n" ] && break
  done
  shift "\$n"
fi
exec "$REAL_CURL" "\$@"
EOF
cat > "$S/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$W/systemctl.log"
EOF
chmod 0755 "$S"/*
echo "127.0.0.1 127.0.0.2" > "$W/addrs.127.0.0.1"

# ---- the box: a plane directory, /etc/whisper-edge, keys -----------------------------------------------
D="$W/box/lib"; E="$W/box/etc"
BASE="https://127.0.0.1:$PORT/edge"
CTL="https://127.0.0.1:$PORT/api/query"
TENANT_A=0123456789abcdef; TENANT_B=fedcba9876543210
newkey() { python3 -c 'import base64,os; print("whisper_live_" + base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("="))'; }
keysha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
FEEDKEY=$(newkey); OWNERKEY=$(newkey)
fresh_box() {
  chattr -R -i "$W/box" 2>/dev/null || true
  rm -rf "$W/box" "$W/hooks"; mkdir -p "$D" "$E/state" "$W/hooks"; chmod 0755 "$E/state"
  cp "$W/sign.pub" "$D/edge.pub"
  rm -f "$F/state.json" "$F/requests.log" "$W/curl.argv" "$W/curl.env" "$W/systemctl.log" "$W/clock" \
        "$W/clock.step" "$W/curlver" "$W/probe" "$W/probe.log" "$W/curl.starts" "$W/curl.exit"
  echo "127.0.0.1 127.0.0.2" > "$W/addrs.127.0.0.1"
  cfg '{}'
}
place_key() { # the feed key on the box, as --enroll leaves it
  printf '%s\n' "$FEEDKEY" > "$E/key"; chmod 0600 "$E/key"
  printf '%s\n' "ag_gateFeedKey000001" > "$E/key.id"
}
owner_home() { # the CLI's key where the CLI keeps it
  rm -rf "${W:?}/home"; mkdir -p "$W/home/.config/whisper"; chmod 0700 "$W/home/.config/whisper"
  printf '%s\n' "$OWNERKEY" > "$W/home/.config/whisper/key"; chmod 0600 "$W/home/.config/whisper/key"
}
# config.json from a python dict literal; the keys and owners are added here
cfg() {
  python3 - "$F/config.json" "$(keysha "$FEEDKEY")" "$(keysha "$OWNERKEY")" "$1" <<'PY'
import json, sys
path, fk, ok, extra = sys.argv[1:5]
c = {"content": "a", "keys": {fk: "ok"}, "owners": [ok]}
c.update(eval(extra))
for k, v in list(c.get("keys", {}).items()):
    if k == "FEED":
        c["keys"][fk] = v; del c["keys"]["FEED"]
for n in c.get("nodes", {}).values():
    for k, v in list(n.get("auth", {}).items()):
        if k == "FEED":
            n["auth"][fk] = v; del n["auth"]["FEED"]
json.dump(c, open(path, "w"))
PY
}
# A feed content: a signed tenant plane and its signed keyed manifest, or a state:none manifest.
content() { # <name> <generation> <rev> [tenant] [plane maker options...]
  c="$F/content/$1"; g=$2; r=$3; t=${4:-$TENANT_A}
  [ $# -ge 4 ] && shift 4 || shift $#
  rm -rf "$c"; mkdir -p "$c"
  vu=$(( (g - g % 86400 + 8 * 86400) * 1000 ))
  python3 "$HERE/testdata/make-tenant-plane.py" "$c/tenant.bin" --gen "$g" --tenant "$t" --rev "$r" \
    --valid-until "$vu" --deny 2a04:2a01::1234/128 --allow 198.51.100.0/24 "$@"
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$c/tenant.bin" -out "$c/tenant.bin.sig"
  python3 - "$c" "$t" "$g" "$r" "$vu" <<'PY'
import hashlib, json, os, sys
c, t, g, r, vu = sys.argv[1:6]
b = open(os.path.join(c, "tenant.bin"), "rb").read()
m = {"format": 2, "generation": int(g), "tier": "keyed", "tenant": t, "planes": [
     {"name": "tenant", "file": "k/tenant.bin", "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b),
      "rev": r, "cadenceSeconds": 86400, "validUntil": int(vu)}], "withheld": []}
open(os.path.join(c, "manifest.json"), "w").write(json.dumps(m))
PY
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$c/manifest.json" -out "$c/manifest.json.sig"
}
content_none() { # <name> [tenant]
  c="$F/content/$1"; rm -rf "$c"; mkdir -p "$c"
  printf '{"format":2,"generation":1,"tier":"keyed","tenant":"%s","planes":[{"name":"tenant","state":"none"}],"withheld":[]}' \
    "${2:-$TENANT_A}" > "$c/manifest.json"
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$c/manifest.json" -out "$c/manifest.json.sig"
}

# Run a whisper-edge-refresh (this script or a mutant) against the box and the fake feed.
run_with() { # <script> <args...>: output on stdout, the exit code in $rc
  _s=$1; shift
  rc=0
  out=$(env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" \
    HOME="$W/home" SUDO_USER= ${XENV:-} "$_s" "$@" 2>&1) || rc=$?
}
rk() { run_with "$REFRESH" "$@"; }
# the same, in the background, paused at a hook point; resume with go <point>
rk_bg() { # <outfile> <args...>
  _o=$1; shift
  env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" \
    HOME="$W/home" SUDO_USER= "$REFRESH" "$@" > "$_o" 2>&1 &
  BG=$!
}
arm() { rm -f "$W/hooks/$1.reached" "$W/hooks/$1.go"; : > "$W/hooks/$1.wait"; }
reached() { _i=0; while [ ! -e "$W/hooks/$1.reached" ] && [ "$_i" -lt 300 ]; do _i=$((_i + 1)); sleep 0.1; done; [ -e "$W/hooks/$1.reached" ]; }
go() { : > "$W/hooks/$1.go"; }
disarm() { rm -f "$W/hooks/$1.wait" "$W/hooks/$1.reached" "$W/hooks/$1.go"; }

# A mutant: this script with one mechanism removed, by a python replacement that must match.
mutant() { # <name> <old> <new>
  mkdir -p "$W/mut/$1"
  python3 - "$REFRESH" "$W/mut/$1/whisper-edge-refresh" "$2" "$3" <<'PY'
import sys
src, dst, old, new = sys.argv[1:5]
s = open(src).read()
if s.count(old) != 1:
    sys.exit("mutant: the text to replace occurs %d times in the script, not once: %r" % (s.count(old), old[:80]))
open(dst, "w").write(s.replace(old, new))
PY
  chmod 0755 "$W/mut/$1/whisper-edge-refresh"
  printf '%s' "$W/mut/$1/whisper-edge-refresh"
}

present() { if [ -e "$1" ]; then echo "$2"; fi; }   # never a failed status under set -e
HWF="$W/box/etc/state/tenant.high-water"; RECF="$W/box/etc/state/tenant.installed"
set_state() { # <file> <raw content, printf-escaped>: what an operator, a restore or a bit flip leaves
  rm -f "$1"; printf "$2" > "$1"; chmod 0444 "$1"
}
backup() { rm -rf "$W/bk.$1"; cp -a "$D" "$W/bk.$1"; }
# A root run installs tenant.bin immutable (the refresh's chattr +i), so a file the refresh may have pinned is
# made mutable before the gate removes or rewrites it; "not supported" (no attribute, no chattr) is ignored.
mutable() { for _m in "$@"; do chattr -i "$_m" 2>/dev/null || true; done; }
rm_plane() { mutable "$@"; rm -f "$@"; }
writable() { mutable "$@"; chmod u+w "$@"; }
restore() { # <name> [cp|cp-p|tar|cp-a]: put a plane directory back, by the tool named (default cp -a);
  # no time is changed by hand: what a restore leaves is what the tool leaves
  chattr -R -i "$D" 2>/dev/null || true; rm -rf "$D"
  case "${2:-cp-a}" in
    cp) mkdir -p "$D"; for f in "$W/bk.$1"/* "$W/bk.$1"/.[!.]*; do [ -e "$f" ] && cp "$f" "$D/"; done ;;
    cp-p) mkdir -p "$D"; for f in "$W/bk.$1"/* "$W/bk.$1"/.[!.]*; do [ -e "$f" ] && cp -p "$f" "$D/"; done ;;
    tar) mkdir -p "$D"; ( cd "$W/bk.$1" && tar cf - . ) | ( cd "$D" && tar xf - ) ;;
    *) cp -a "$W/bk.$1" "$D" ;;
  esac
}
# the refresh's own python, for calling one of its readers directly
kpyx() { python3 -c "$(sed -n '/^keyed_py() {$/,/^PY$/p' "${KPY_SCRIPT:-$REFRESH}" | sed '1,2d;$d')" "$@"; }
# The value the hand-repair sentence names for one file (hw or rec), and the end it came from.
sent_val() { # <output> <hw|rec>
  python3 - "$1" "$2" <<'PY2'
import re, sys
text, which = sys.argv[1], sys.argv[2]
name = "tenant.high-water" if which == "hw" else "tenant.installed"
cur = None
for line in text.splitlines():
    m = re.search(r"(\S+) is malformed \(", line)
    if m:
        cur = m.group(1)
        continue
    m = re.search(r"if this time is right, write (\d+) into it \(([^)]*)\)", line)
    if m and cur and cur.endswith(name):
        print(m.group(1)); sys.exit(0)
print("none")
PY2
}
shape_label() { printf '%s' "$1" | sed 's/\\n/<NL>/g; s/\\r/<CR>/g'; }
# One more replacement in a mutant already made (two mechanisms removed together).
remut() { # <file> <old> <new>
  python3 - "$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("remut: the text to replace occurs %d times in the mutant, not once: %r" % (s.count(old), old[:80]))
open(p, "w").write(s.replace(old, new, 1))
PY
}
gen_of() { od -An -t u8 -j 16 -N 8 "$1" 2>/dev/null | tr -d ' '; }
word() { "$TSC" --dir "$D" --state "$E/state" --plane-check "$PLANE_CHECK" "$@" 2>/dev/null | tail -1; }
fileval() { cat "$1" 2>/dev/null | tr '\n' '|'; }
reqs() { cat "$F/requests.log" 2>/dev/null; }
nreq() { reqs | python3 -c 'import json,sys
n=0
for l in sys.stdin:
    r=json.loads(l)
    if all(str(r.get(k))==v for k,v in (a.split("=",1) for a in sys.argv[1:])): n+=1
print(n)' "$@"; }

NOW=$(date +%s)
G0=$(( NOW - NOW % 86400 + 3 ))      # today's day-slot generation
REV0=$(( NOW - 4000 ))


# ---- helpers the rows share ----------------------------------------------------------------------
enrol_env() { XENV="SUDO_USER=$(id -un) WHISPER_EDGE_TEST_SUDO_HOME=$W/sudohome"; }
sudo_home() {
  rm -rf "$W/sudohome"; mkdir -p "$W/sudohome/.config/whisper"; chmod 0700 "$W/sudohome/.config/whisper"
  printf '%s\n' "$OWNERKEY" > "$W/sudohome/.config/whisper/key"; chmod 0600 "$W/sudohome/.config/whisper/key"
  rm -rf "${W:?}/home"; mkdir -p "$W/home"
}
installed_box() { # a box with the feed key and tenant.bin installed at G0
  fresh_box; place_key; content a "$G0" "$REV0"; rk --keyed-set
  [ "$rc" = 0 ] && [ -f "$D/tenant.bin" ] || fail "fixture: the plane installs" "rc=$rc $out"
}
seen_rec() { printf '%s\n' "$1" > "$D/.revocation-seen"; }
one_node_revoked() { echo 127.0.0.1 > "$W/addrs.127.0.0.1"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; }
# the script's clock N seconds from now (the date shim), for the next scheduled poll; "now" clears it
at() { if [ "$1" = now ]; then rm -f "$W/clock"; else echo $(( $(date +%s) + $1 )) > "$W/clock"; fi; }
EPOCH_CHECK='if [ "$(rd_epoch)" != "$EPOCH0" ] || [ "$(rd_keyid)" != "$KID_FILE0" ]; then'
race_install() { # <script for the paused run> <the interleaved command...>: a run paused after its fetch
  _rs=$1; shift
  installed_box; content a "$((G0 + 1))" "$REV0"
  arm before-install
  env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" HOME="$W/home" \
    "$_rs" --keyed-set > "$W/paused" 2>&1 &
  BG=$!
  reached before-install || fail "row 57: the paused run reaches its hook" "$(cat "$W/paused")"
  "$@"
  go before-install
  wait "$BG" || true
  disarm before-install
}
interleave_revoke() { cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; }
interleave_unenroll() { owner_home; rk --unenroll; }
interleave_repin() { rk --repin; }
keyless_stub() { # a keyless signed manifest with a tor plane, on 127.0.0.1:$KPORT
  K="$W/keyless"; rm -rf "$K"; mkdir -p "$K/edge/planes" "$K/edge/manifests"
  python3 - "$CORE/testdata/format2/tor.bin" "$K/plane.bin" "$G0" <<'PY'
import struct, sys
b = bytearray(open(sys.argv[1], "rb").read()); struct.pack_into("<Q", b, 16, int(sys.argv[3]))
open(sys.argv[2], "wb").write(bytes(b))
PY
  ps=$(sha256sum < "$K/plane.bin" | cut -d' ' -f1); cp "$K/plane.bin" "$K/edge/planes/$ps.bin"
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$K/plane.bin" -out "$K/edge/planes/$ps.bin.sig"
  printf '{"format":2,"generation":%s,"planes":[{"name":"tor","sha256":"%s","bytes":%s}],"withheld":[]}' \
    "$G0" "$ps" "$(wc -c < "$K/plane.bin")" > "$K/edge/manifest.json"
  ms=$(sha256sum < "$K/edge/manifest.json" | cut -d' ' -f1)
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$K/edge/manifest.json" -out "$K/edge/manifests/$ms.sig"
  if [ -z "${KPORT:-}" ]; then
    KPORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    ( cd "$K" && exec python3 -m http.server "$KPORT" --bind 127.0.0.1 >/dev/null 2>&1 ) & echo $! > "$W/srv.keyless.pid"
    i=0; while ! "$REAL_CURL" -fsS -o /dev/null "http://127.0.0.1:$KPORT/edge/manifest.json" 2>/dev/null && [ "$i" -lt 50 ]; do i=$((i+1)); sleep 0.1; done
  fi
}
keyless_tor() { XENV="WHISPER_EDGE_RESOLVE=edge.keyless.invalid:$KPORT:127.0.0.1"; rk --plane tor --base "http://edge.keyless.invalid:$KPORT/edge"; XENV=""; }

echo "--- the keyed path, against a local fake feed (two nodes, $NODE_A and $NODE_B)"

# ===================================================================================================
# Row 54: the key never reaches argv, the environment or a URL; the header file is 0600 in a 0700
# directory of the run's own, and gone after the run.
row54() {
fresh_box; place_key; content a "$G0" "$REV0"
arm after-first-step
rk_bg "$W/run54" --keyed-set
hdr_mode=""
if reached after-first-step; then
  h=$(find "$W/tmp" -type f -name h 2>/dev/null | head -1)
  [ -n "$h" ] && hdr_mode="$(stat -c %a "$h") $(stat -c %a "$(dirname "$h")")"
fi
go after-first-step; wait "$BG" && rc=0 || rc=$?; disarm after-first-step
key_seen() { grep -F -q -- "$FEEDKEY" "$W/curl.argv" "$W/curl.env" 2>/dev/null || grep -F -q -- "$FEEDKEY" "$F/requests.log" 2>/dev/null; }
{ [ "$rc" = 0 ] && [ "$hdr_mode" = "600 700" ] && [ -z "$(find "$W/tmp" -mindepth 1 2>/dev/null)" ] \
  && ! key_seen && [ "$(nreq path=/edge/k/tenant.bin auth=bearer known_key=True)" = 1 ]; } \
  && pass "row 54: the key reaches the feed only in a header, from a 0600 file in a 0700 directory removed after the run" \
  || fail "row 54: the key stays off argv, the environment and URLs" "rc=$rc hdr=$hdr_mode $(cat "$W/run54")"
M=$(mutant argv-key '-H "@$T/h"' '-H "$(cat "$T/h")"')
fresh_box; place_key; content a "$G0" "$REV0"; run_with "$M" --keyed-set
key_seen && pass "row 54 control: a script that puts the header on argv is caught by the same check" \
         || fail "row 54 control: the argv check sees a key on argv" "rc=$rc"
}

# ===================================================================================================
# Row 55: enrolment, from the CLI key in $SUDO_USER's home; the envelope decides, never the HTTP status.
row55() {
fresh_box; sudo_home; rmdir "$E/state"; enrol_env; rk --enroll --label gate; XENV=""
kid=$(cat "$E/key.id" 2>/dev/null || true)
{ [ "$rc" = 0 ] && [ "$(stat -c %a "$E/key" 2>/dev/null)" = 600 ] && [ "$(stat -c %u "$E/key")" = "$(id -u)" ] \
  && [ "$(printf '%s' "$kid" | grep -Ec '^ag_[A-Za-z0-9_-]{16}$')" = 1 ] && [ "$(wc -l < "$E/key.id")" = 1 ] \
  && [ "$(stat -c %a "$E/state")" = 755 ] && grep -q 'enable --now whisper-edge-refresh-keyed.timer' "$W/systemctl.log" \
  && says "$out" 'whisper-edge-refresh --unenroll' && [ "$(nreq sub=key auth=bearer known_key=True)" = 1 ]; } \
  && pass "row 55: --enroll with the CLI key in \$SUDO_USER's home writes a 0600 key, key.id holding only the id, state/ 0755, enables the keyed timer and names the undo line" \
  || fail "row 55: enrolment" "rc=$rc kid=$kid $(ls -la "$E" 2>&1) $out"
for mode in owner_only unknown_op not_yet; do
  fresh_box; sudo_home; cfg "{'control': {'*': '$mode'}}"; enrol_env; rk --enroll --label gate; XENV=""
  case "$mode" in
    owner_only) want="this is an agent's key; enrol with the account owner's key"; wantrc=1 ;;
    *) want="keyed enrolment is not available on this node yet; run whisper-edge-refresh --enroll later"; wantrc=0 ;;
  esac
  posts=$(nreq method=POST)
  { [ "$rc" = "$wantrc" ] && says "$out" "$want" && [ ! -e "$E/key" ] && [ ! -e "$E/key.id" ] \
    && { [ "$mode" != unknown_op ] || { [ "$posts" = 2 ] && [ "$(nreq method=POST addr=127.0.0.2)" = 1 ]; }; }; } \
    && pass "row 55: an inner ${mode} prints its sentence and writes nothing (exit $wantrc$([ "$mode" = unknown_op ] && echo ', after asking the other address'))" \
    || fail "row 55: ${mode} writes nothing" "rc=$rc posts=$posts $out"
done
fresh_box; rm -rf "$W/sudohome"; rm -rf "${W:?}/home"; mkdir -p "$W/home"; enrol_env; rk --enroll; XENV=""
{ [ "$rc" != 0 ] && says "$out" 'no CLI key found' && [ "$(nreq method=POST)" = 0 ] && [ ! -e "$E/key" ]; } \
  && pass "row 55 control: with no CLI key nothing is asked and nothing written, and it says how to get one" \
  || fail "row 55: no CLI key" "rc=$rc $out"
M=$(mutant status-parser 'if env.get("ok") is True:
        try:
            d = result_rows(env)[0]
            k, kid' 'if status == "200":
        try:
            d = result_rows(env)[0]
            k, kid')
fresh_box; sudo_home; cfg "{'control': {'*': 'owner_only_with_result'}}"; enrol_env; run_with "$M" --enroll; XENV=""
[ -e "$E/key" ] && pass "row 55 control: a parser keyed on the HTTP status writes a key file from a refusal envelope that carries a row" \
                || fail "row 55 control: the status-keyed parser is caught" "rc=$rc $out"
fresh_box; sudo_home; cfg "{'control': {'*': 'owner_only_with_result'}}"; enrol_env; rk --enroll; XENV=""
{ [ ! -e "$E/key" ] && says "$out" "this is an agent's key"; } \
  && pass "row 55: the same refusal envelope, read by the envelope, writes nothing" \
  || fail "row 55: the envelope decides" "rc=$rc $out"
}

# ===================================================================================================
# Row 56: which refusals remove. Only KEY_REVOKED from two different Whisper-Node values (or the next
# poll) removes the tenant plane; every other answer keeps everything.
row56() {
installed_box; cp "$D/tenant.bin" "$W/tenant.pre-revocation"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
{ [ "$rc" = 0 ] && [ ! -e "$D/tenant.bin" ] && [ "$(cat "$E/state/tenant.high-water" 2>/dev/null)" = "$G0" ] \
  && [ "$(stat -c %a "$E/state/tenant.high-water")" = 444 ] && grep -Eq "^[0-9]+ $G0\$" "$D/.tenant-tombstone" \
  && [ "$(cat "$D/.revocation-epoch")" = 1 ] && says "$out" "KEY_REVOKED from Whisper-Node $NODE_A and $NODE_B"; } \
  && pass "row 56: KEY_REVOKED from node a then node b removes tenant.bin, writes the mark ($G0), the tombstone and the epoch" \
  || fail "row 56: a two-node revocation removes" "rc=$rc $(ls -a "$D") $out"
[ "$(word)" = revoked ] && pass "row 56: and the box reads revoked" || fail "row 56: revoked after removal" "$(word)"
# The join of the writer and the reader. The module reads the mark where the refresh writes it, so a restart (a
# fresh bind) over the pre-revocation tenant.bin put back by a backup restore keeps the plane revoked. The bind
# needs a plane directory its trust walk accepts, so the restored copy goes to a private directory under the
# runtime directory; the mark is the refresh's own file. The control reads the old default's place under the same
# root, which the refresh never writes: the same restored file arms there.
ETC_DEFAULT=$(sed -n 's/^ETC="\${WHISPER_EDGE_ETC:-\(.*\)}"$/\1/p' "$REFRESH")
[ -n "$ETC_DEFAULT" ] && [ "$("$W/tenant_arm_probe" --default-path)" = "$ETC_DEFAULT/state/tenant.high-water" ] \
  && pass "row 56: the module reads the revocation mark where the refresh writes it ($ETC_DEFAULT/state/tenant.high-water)" \
  || fail "row 56: the reader's default mark is the writer's" "refresh ETC '$ETC_DEFAULT', module '$("$W/tenant_arm_probe" --default-path)'"
JB=${XDG_RUNTIME_DIR:-}; [ -z "$JB" ] && [ "$(id -u)" = 0 ] && JB=/run
if [ -n "$JB" ] && [ -d "$JB" ] && JD=$(mktemp -d "$JB/keyed-join.XXXXXX" 2>/dev/null); then
  chmod 0755 "$JD"; cp "$W/tenant.pre-revocation" "$JD/tenant.bin"; chmod 0444 "$JD/tenant.bin"
  jo=$("$W/tenant_arm_probe" "$JD" "$E/state/tenant.high-water" 2>&1) && jrc=0 || jrc=$?
  { [ "$jrc" = 1 ] && says "$jo" "is not above $G0"; } \
    && pass "row 56: the restart over the restored pre-revocation tenant.bin keeps it revoked: the module refuses generation $G0 at the mark" \
    || fail "row 56: a restored pre-revocation tenant.bin stays revoked across a restart" "rc=$jrc $jo"
  jo=$("$W/tenant_arm_probe" "$JD" "$E/tenant.high-water" 2>&1) && jrc=0 || jrc=$?
  { [ "$jrc" = 0 ] && says "$jo" "tenant armed generation $G0"; } \
    && pass "row 56 control: a reader at the old default's place, which the refresh never writes, arms the restored plane" \
    || fail "row 56 control: the mark's path decides" "rc=$jrc $jo"
  rm -rf "$JD"
else
  SKIPPED="${SKIPPED}row 56's restart join (needs a private runtime directory the trust walk accepts: XDG_RUNTIME_DIR, or /run as root); "
fi
keep_case() { # <label> <config> <expected sentence>
  installed_box; SUM=$(sha256sum < "$D/tenant.bin"); cfg "$2"; rk --keyed-set
  { [ "$rc" != 0 ] && [ "$(sha256sum < "$D/tenant.bin" 2>/dev/null)" = "$SUM" ] && [ ! -e "$D/.tenant-tombstone" ] \
    && [ ! -e "$E/state/tenant.high-water" ] && says "$out" "$3"; } \
    && pass "row 56: $1 removes nothing and says so" \
    || fail "row 56: $1 keeps everything" "rc=$rc $out"
}
keep_case "KEY_EXPIRED from two nodes" "{'keys': {'FEED': 'KEY_EXPIRED'}}" "feed keys do not expire in this release"
keep_case "invalid_token twice from two nodes" "{'keys': {'FEED': 'invalid_token'}}" "the feed does not recognise this key"
keep_case "malformed_key" "{'rules': [{'path': 'manifest.json', 'status': 401, 'code': 'malformed_key', 'realm': True, 'error': 'invalid_token'}]}" "does not hold a well-formed key"
keep_case "a 403 with an HTML body (a proxy)" "{'rules': [{'path': 'manifest.json', 'status': 403, 'html': True, 'preauth': True}]}" "everything is kept"
keep_case "401 key_required with the key file present" "{'rules': [{'path': 'manifest.json', 'status': 401, 'code': 'key_required', 'realm': True, 'preauth': True}]}" "a proxy may be stripping Authorization"
keep_case "403 FORBIDDEN_SCOPE" "{'keys': {'FEED': 'FORBIDDEN_SCOPE'}}" "this is not a feed key"
installed_box; echo 127.0.0.1 > "$W/addrs.127.0.0.1"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
r1=$rc; o1=$out; seen1=$(cat "$D/.revocation-seen" 2>/dev/null || true); had=$(present "$D/tenant.bin" yes)
at 901; rk --keyed-set; at now
{ [ "$r1" = 0 ] && [ "$had" = yes ] && says "$o1" "from Whisper-Node $NODE_A only" \
  && [ "$(echo "$seen1" | awk '{print $1, $2, $3}')" = "ag_gateFeedKey000001 KEY_REVOKED $NODE_A" ] \
  && [ "$rc" = 0 ] && [ ! -e "$D/tenant.bin" ] && [ -e "$D/.tenant-tombstone" ]; } \
  && pass "row 56: KEY_REVOKED from one node only records .revocation-seen and removes nothing; the next scheduled poll's answer, 901 s later, completes it" \
  || fail "row 56: the single-node revocation waits for the next poll" "r1=$r1 seen=$seen1 rc=$rc $o1 / $out"
# the floor: the next scheduled keyed poll, at least 900 s after the first observation
floor_case() { # <script>
  installed_box; one_node_revoked; T10=$(( $(date +%s) - 10 ))
  seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_A $T10"; run_with "$1" --keyed-set
}
floor_case "$REFRESH"
{ [ -e "$D/tenant.bin" ] && [ "$(cat "$D/.revocation-seen")" = "ag_gateFeedKey000001 KEY_REVOKED $NODE_A $T10" ]; } \
  && pass "row 56: a same-node record 10 s old plus one observation removes nothing, and the first observation's time stands" \
  || fail "row 56: the 900 s floor" "$(cat "$D/.revocation-seen" 2>&1) $out"
M=$(mutant no-floor 'REVOKE_POLL_FLOOR=900' 'REVOKE_POLL_FLOOR=0')
floor_case "$M"
[ ! -e "$D/tenant.bin" ] && pass "row 56 control: without the floor a re-run seconds later completes the removal on one node's word" \
                         || fail "row 56 control: the floor is visible" "$out"
# the floor's edge, on the frozen clock: a record 899 s old removes nothing, 900 s and 901 s remove
edge_case() { # <script> <age>
  installed_box; one_node_revoked; T0=$(date +%s)
  seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_A $T0"; echo "$((T0 + $2))" > "$W/clock"
  run_with "$1" --keyed-set; at now
  if [ -e "$D/tenant.bin" ]; then edge_=kept; else edge_=removed; fi
}
for age in 899 900 901; do
  edge_case "$REFRESH" "$age"
  case $age in 899) want=kept ;; *) want=removed ;; esac
  [ "$edge_" = "$want" ] && pass "row 56: a same-node record $age s old plus one observation: the plane is $want" \
                         || fail "row 56: the floor at $age s" "$edge_ $out"
done
M=$(mutant floor-600 'REVOKE_POLL_FLOOR=900' 'REVOKE_POLL_FLOOR=600')
edge_case "$M" 899
[ "$edge_" = removed ] && pass "row 56 control: with a 600 s floor the 899 s record completes the removal" \
                       || fail "row 56 control: the 900 s floor is what keeps the 899 s case" "$out"
# a black-holed second address costs its run 120 s per request on the fake clock, and moves nothing:
# both observations carry their run's start, so a run 900 s after the first one's start completes it
dead_alt() { # <script>
  installed_box; echo "127.0.0.1 127.0.0.2" > "$W/addrs.127.0.0.1"
  cfg "{'nodes': {'127.0.0.1': {'auth_all': 'KEY_REVOKED'}}, 'rules': [{'addr': '127.0.0.2', 'path': 'manifest.json', 'action': 'reset'}]}"
  T0=$(date +%s); echo "$T0" > "$W/clock"; echo 120 > "$W/clock.step"
  run_with "$1" --keyed-set; stamp_=$(awk '{print $4}' "$D/.revocation-seen" 2>/dev/null)
  echo "$((T0 + 900))" > "$W/clock"; run_with "$1" --keyed-set
  rm -f "$W/clock.step"; at now
  if [ -e "$D/tenant.bin" ]; then dead_=kept; else dead_=removed; fi
}
dead_alt "$REFRESH"
{ [ "$stamp_" = "$T0" ] && [ "$dead_" = removed ]; } \
  && pass "row 56: with the second address black-holed (120 s a request), the first observation carries its run's start and the run 900 s later completes the removal" \
  || fail "row 56: the floor with a dead address" "stamp=$stamp_ T0=$T0 $dead_ $out"
M=$(mutant post-loop-stamp '      put_file "$DIR" .revocation-seen 0644 "$KID0 KEY_REVOKED $_n1 $_now' '      put_file "$DIR" .revocation-seen 0644 "$KID0 KEY_REVOKED $_n1 $(date +%s)')
dead_alt "$M"
{ [ "$stamp_" -gt "$T0" ] && [ "$dead_" = kept ]; } \
  && pass "row 56 control: a stamp taken after the address loop is $((stamp_ - T0)) s late, and the run 900 s later removes nothing" \
  || fail "row 56 control: the stamp time is visible" "stamp=$stamp_ T0=$T0 $dead_"
# the other node is asked first: a record from node a, then a run where a says KEY_REVOKED and b serves the key
other_first() { # <script>
  installed_box; seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_A $(( $(date +%s) - 1000 ))"
  cfg "{'nodes': {'127.0.0.1': {'auth_all': 'KEY_REVOKED'}}}"; run_with "$1" --keyed-set
}
other_first "$REFRESH"
{ [ -e "$D/tenant.bin" ] && [ ! -e "$D/.revocation-seen" ]; } \
  && pass "row 56: a record from node a and a run where a says KEY_REVOKED and b still serves the key: nothing is removed, the record is cleared" \
  || fail "row 56: the other node is asked first" "$out"
M=$(mutant record-first 'if [ -n "$_rnode" ] && [ "$_rnode" != "$_n1" ]; then do_revoke' 'if [ -n "$_rnode" ]; then do_revoke')
other_first "$M"
[ ! -e "$D/tenant.bin" ] && pass "row 56 control: completing on the record before asking the other node removes the plane on one node's word" \
                         || fail "row 56 control: other-node-first is visible" "$out"
installed_box; cfg "{'nodes': {'127.0.0.1': {'auth_all': 'KEY_REVOKED'}}}"; rk --keyed-set
{ [ "$rc" = 0 ] && [ -e "$D/tenant.bin" ] && [ ! -e "$D/.revocation-seen" ] && [ ! -e "$D/.tenant-tombstone" ]; } \
  && pass "row 56: a typed revocation from node a followed by a 200 from node b removes nothing and clears the record" \
  || fail "row 56: a 200 from the other node keeps the plane" "rc=$rc $out"
M=$(mutant invalid-removes 'invalid_token) echo invalid ;;' 'invalid_token) echo revoked ;;')
installed_box; cfg "{'keys': {'FEED': 'invalid_token'}}"; run_with "$M" --keyed-set
[ ! -e "$D/tenant.bin" ] && pass "row 56 control: a client that removes on invalid_token seen twice removes the plane" \
                         || fail "row 56 control: removal on invalid_token is caught" "rc=$rc $out"
}

# ===================================================================================================
# Row 56b: a node-local 503 is retried on the other address in the same run.
row56b() {
fresh_box; place_key; content a "$G0" "$REV0"
cfg "{'rules': [{'addr': '127.0.0.1', 'path': 'manifest.json', 'status': 503, 'code': 'tenant_unavailable', 'retry_after': 60}]}"
rk --keyed-set
{ [ "$rc" = 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] && says "$out" "from 127.0.0.2 (Whisper-Node $NODE_B)"; } \
  && pass "row 56b: 503 tenant_unavailable at address 1 and 200 at address 2: the plane installs in the same run, and the log names address 2" \
  || fail "row 56b: the retry on another address" "rc=$rc $out"
M=$(mutant no-retry '_alt=$(other_addr "$KADDR")
  [ -n "$_alt" ] || return 1' '_alt=""
  [ -n "$_alt" ] || return 1')
fresh_box; place_key; content a "$G0" "$REV0"
cfg "{'rules': [{'addr': '127.0.0.1', 'path': 'manifest.json', 'status': 503, 'code': 'tenant_unavailable'}]}"
run_with "$M" --keyed-set
[ ! -e "$D/tenant.bin" ] && pass "row 56b control: with the retry removed the plane waits for the next poll" \
                        || fail "row 56b control: the retry is what installed it" "rc=$rc $out"
}

# ===================================================================================================
# Row 56c: a stale single observation never completes a removal.
row56c() {
installed_box; one_node_revoked; seen_rec "ag_someOtherKeyAAAA KEY_REVOKED $NODE_B $(( $(date +%s) - 100 ))"; rk --keyed-set
{ [ -e "$D/tenant.bin" ] && [ "$(awk '{print $1}' "$D/.revocation-seen")" = ag_gateFeedKey000001 ]; } \
  && pass "row 56c: a record for another key plus one observation for this one removes nothing" \
  || fail "row 56c: another key's record is ignored" "rc=$rc $out"
installed_box; one_node_revoked; seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_B $(( $(date +%s) - 90000 ))"; rk --keyed-set
[ -e "$D/tenant.bin" ] && pass "row 56c: a record older than 24 h removes nothing" || fail "row 56c: an old record is ignored" "$out"
installed_box; seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_B $(date +%s)"; content a "$((G0 + 1))" "$REV0"; rk --keyed-set
[ ! -e "$D/.revocation-seen" ] && pass "row 56c: a 200 deletes the record" || fail "row 56c: a 200 clears" "$out"
installed_box; seen_rec "ag_gateFeedKey000001 KEY_REVOKED $NODE_B $(date +%s)"; rk --keyed-set
{ [ "$rc" = 0 ] && [ ! -e "$D/.revocation-seen" ] && [ "$(nreq path=/edge/k/manifest.json.sig)" = 1 ]; } \
  && pass "row 56c: a 304 for k/manifest.json deletes it too (authentication runs before the ETag)" \
  || fail "row 56c: a 304 clears" "rc=$rc $out"
three_runs() { # <script>: node a KEY_REVOKED, node b a typed 503 convergence_stale, three runs
  installed_box
  cfg "{'nodes': {'127.0.0.1': {'auth_all': 'KEY_REVOKED'}}, 'rules': [{'addr': '127.0.0.2', 'path': 'manifest.json', 'status': 503, 'code': 'tenant_unavailable', 'retry_after': 60}]}"
  run_with "$1" --keyed-set; t1=$([ -e "$D/tenant.bin" ] && echo kept || echo removed); s1=$(present "$D/.revocation-seen" seen)
  at 901; run_with "$1" --keyed-set; t2=$([ -e "$D/tenant.bin" ] && echo kept || echo removed)
  at 1802; run_with "$1" --keyed-set; t3=$([ -e "$D/tenant.bin" ] && echo kept || echo removed); at now
}
three_runs "$REFRESH"
{ [ "$t1" = kept ] && [ "$s1" = seen ] && [ "$t2" = removed ] && [ "$t3" = removed ]; } \
  && pass "row 56c: node a KEY_REVOKED and node b a typed 503: the record survives the 503 and the removal completes on the second run" \
  || fail "row 56c: the three-run case" "$t1 $s1 $t2 $t3 $out"
M=$(mutant idless 'if rid != kid or code != "KEY_REVOKED"' 'if code != "KEY_REVOKED"')
installed_box; one_node_revoked; seen_rec "ag_someOtherKeyAAAA KEY_REVOKED $NODE_B $(( $(date +%s) - 100 ))"; run_with "$M" --keyed-set
[ ! -e "$D/tenant.bin" ] && pass "row 56c control: an id-less record completes the removal" \
                         || fail "row 56c control: the id binding is what stops it" "$out"
M=$(mutant only-200-clears '    notmod) seen_clear; exit 0 ;;' '    notmod) exit 0 ;;')
for s in "$REFRESH" "$M"; do
  installed_box; one_node_revoked; run_with "$s" --keyed-set
  cfg '{}'; run_with "$s" --keyed-set
  one_node_revoked; at 901; run_with "$s" --keyed-set; at now
  r=$([ -e "$D/tenant.bin" ] && echo kept || echo removed)
  if [ "$s" = "$REFRESH" ]; then
    [ "$r" = kept ] && pass "row 56c: an authorised 304 between two single-node observations clears the first, so nothing is removed" \
                    || fail "row 56c: a 304 resets the observation" "$out"
  else
    [ "$r" = removed ] && pass "row 56c control: a rule where only a 200 clears completes the removal across the 304" \
                       || fail "row 56c control: the 304 rule is caught" "$out"
  fi
done
M=$(mutant any-typed-clears '      *) _nodes="$_nodes$NODE " ;;' '      *) seen_clear; _rnode=""; _nodes="$_nodes$NODE " ;;')
three_runs "$M"
[ "$t2" = kept ] && [ "$t3" = kept ] && pass "row 56c control: a rule where any typed answer clears never completes the three-run case" \
                                    || fail "row 56c control: clearing on a 503 is caught" "$t1 $t2 $t3"
}

# ===================================================================================================
# Row 57: the revocation race. Every locked step that acts on a fetched answer proceeds only when the
# epoch and key.id read under the lock equal the values the run read before its first request.
row57() {
race_install "$REFRESH" interleave_revoke
{ [ ! -e "$D/tenant.bin" ] && [ -e "$D/.tenant-tombstone" ] && says "$(cat "$W/paused")" 'the key changed during this run; the fetched plane was dropped'; } \
  && pass "row 57: a manual run that fetched before a timer run's removal does not reinstall" \
  || fail "row 57: no reinstall after a removal" "$(cat "$W/paused")"
M=$(mutant no-epoch-check "$EPOCH_CHECK
    lk_drop
    kalarm \"the key changed during this run; \$1 was dropped\"" "if false; then
    lk_drop
    kalarm \"the key changed during this run; \$1 was dropped\"")
race_install "$M" interleave_revoke
[ -e "$D/tenant.bin" ] && pass "row 57 control: with the epoch check removed the paused run reinstalls the revoked plane" \
                       || fail "row 57 control: the epoch check is what stops it" "$(cat "$W/paused")"
race_install "$REFRESH" interleave_unenroll
{ [ ! -e "$D/tenant.bin" ] && [ ! -e "$D/.tenant-tombstone" ] && [ "$(cat "$E/state/tenant.high-water")" = "$G0" ] \
  && [ "$(word)" = null ] && says "$out" 'this box is keyless again: the tenant plane is removed and rules on tenant_allow and tenant_deny read null, as before enrolment'; } \
  && pass "row 57: a timer run paused after its fetch does not reinstall after --unenroll, which leaves tenant.bin and the tombstone absent, the mark at $G0 and the word null" \
  || fail "row 57: --unenroll against a paused run" "word=$(word) hw=$(fileval "$E/state/tenant.high-water") $out $(cat "$W/paused")"
M=$(mutant unenroll-tombstones '  rm -f "$TOMBF" "$REVF" "$ETAGF" "$SEENF" || lk_fail "could not remove the tombstone"' \
  '  put_file "$DIR" .tenant-tombstone 0444 "1 1
"; rm -f "$REVF" "$ETAGF" "$SEENF"')
installed_box; owner_home; run_with "$M" --unenroll
[ "$(word)" = revoked ] && pass "row 57 control: an --unenroll that ends REVOKED derives revoked where null is due" \
                        || fail "row 57 control: the word sees a REVOKED --unenroll" "$(word)"
M=$(mutant repin-no-epoch '  epoch_inc || lk_fail "could not write $EPOCHF; nothing was changed"' '  :')
race_install "$REFRESH" interleave_repin
r_real=$([ -e "$D/tenant.bin" ] && echo installed || echo absent)
installed_box; content a "$((G0 + 1))" "$REV0"; arm before-install; rk_bg "$W/paused" --keyed-set; reached before-install
run_with "$M" --repin; go before-install; wait "$BG" || true; disarm before-install
r_mut=$([ -e "$D/tenant.bin" ] && echo installed || echo absent)
{ [ "$r_real" = absent ] && [ "$r_mut" = installed ]; } \
  && pass "row 57: --repin's epoch increment stops a paused run's reinstall; control: without it the paused run reinstalls (for --unenroll the moved key.id stops it too)" \
  || fail "row 57: the repin epoch" "real=$r_real mutant=$r_mut"
revoke_race() { # <script for the paused run> <interleaved command...>
  _rs=$1; shift
  installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"
  arm before-revoke
  env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" HOME="$W/home" \
    "$_rs" --keyed-set > "$W/paused" 2>&1 &
  BG=$!
  reached before-revoke || fail "row 57: the revoking run reaches its hook" "$(cat "$W/paused")"
  "$@"
  go before-revoke; wait "$BG" || true; disarm before-revoke
}
revoke_race "$REFRESH" interleave_unenroll
{ [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = null ] && says "$(cat "$W/paused")" 'the key changed during this run; the revocation answer was dropped'; } \
  && pass "row 57: a run paused after two KEY_REVOKED observations while --unenroll completes writes no tombstone, the box stays null, and it says the answer was dropped" \
  || fail "row 57: a revocation answer after --unenroll" "word=$(word) $(cat "$W/paused")"
M=$(mutant unconditional-revoke "$EPOCH_CHECK
    lk_drop
    kalarm \"the key changed during this run; the revocation answer was dropped\"" "if false; then
    lk_drop
    kalarm \"the key changed during this run; the revocation answer was dropped\"")
revoke_race "$M" interleave_unenroll
[ "$(word)" = revoked ] && pass "row 57 control: the unconditional revoke step tombstones the keyless box (it derives revoked)" \
                        || fail "row 57 control: the revoke's epoch rule is what stops it" "$(word)"
force_race() { # <script for the paused run> [enrolling script]
  installed_box; owner_home
  arm after-first-step
  env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" HOME="$W/home" \
    "$1" --keyed-set > "$W/paused" 2>&1 &
  BG=$!
  reached after-first-step || fail "row 57: the paused run reaches its hook" "$(cat "$W/paused")"
  cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"
  run_with "${2:-$REFRESH}" --enroll --force
  go after-first-step; wait "$BG" || true; disarm after-first-step
}
force_race "$REFRESH"
{ [ ! -e "$D/.tenant-tombstone" ] && [ -e "$D/tenant.bin" ] && [ -e "$E/key" ] \
  && says "$(cat "$W/paused")" 'the key changed during this run; the revocation answer was dropped'; } \
  && pass "row 57: a run that read its key before --enroll --force replaced it, then sees KEY_REVOKED from two nodes, writes no tombstone and installs nothing" \
  || fail "row 57: --enroll --force against a paused run" "$(cat "$W/paused")"
M=$(mutant force-no-epoch '  epoch_inc || lk_fail "cannot write $EPOCHF"' '  :')
M2=$(mutant epoch-only "$EPOCH_CHECK
    lk_drop
    kalarm \"the key changed during this run; the revocation answer was dropped\"" "if [ \"\$(rd_epoch)\" != \"\$EPOCH0\" ]; then
    lk_drop
    kalarm \"the key changed during this run; the revocation answer was dropped\"")
force_race "$M2" "$M"
[ -e "$D/.tenant-tombstone" ] && pass "row 57 control: --enroll --force with no epoch bump, against a revoke checking the epoch alone, tombstones the freshly enrolled box" \
                              || fail "row 57 control: the force race is caught" "$(cat "$W/paused")"
}

# ===================================================================================================
# Row 57b: .keyed-etag is written last, and never outlives its plane.
row57b() {
fresh_box; place_key; content a "$G0" "$REV0"; cfg "{'rules': [{'path': 'tenant.bin', 'status': 503, 'code': 'busy', 'times': 2}]}"
rk --keyed-set; r1=$rc; rk --keyed-set
inm=$(reqs | python3 -c 'import json,sys; print([json.loads(l)["if_none_match"] for l in sys.stdin if json.loads(l)["path"]=="/edge/k/manifest.json"][-1])')
{ [ "$r1" != 0 ] && [ "$inm" = None ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ]; } \
  && pass "row 57b: a 200 manifest then a 503 on tenant.bin saves no ETag: the next run sends no If-None-Match and installs" \
  || fail "row 57b: the ETag is saved last" "r1=$r1 inm=$inm $out"
M=$(mutant etag-early '    PIN_ADDR=$KADDR
    METAG=$KETAG' '    PIN_ADDR=$KADDR
    METAG=$KETAG; put_file "$DIR" .keyed-etag 0644 "$METAG
"')
# The same with a plane already installed, where the first locked step keeps the ETag: a new generation
# whose tenant.bin answers 503 must still be fetched by the next run.
early_etag() { # <script>
  installed_box; content a "$((G0 + 1))" "$REV0"
  cfg "{'rules': [{'path': 'tenant.bin', 'status': 503, 'code': 'busy', 'times': 2}]}"
  run_with "$1" --keyed-set; run_with "$1" --keyed-set
}
early_etag "$REFRESH"
[ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ] && pass "row 57b: over an installed plane, a new manifest whose tenant.bin answered 503 is fetched again and installed by the next run" \
                                                || fail "row 57b: the ETag waits for the install" "$out"
early_etag "$M"
[ "$(gen_of "$D/tenant.bin")" = "$G0" ] && pass "row 57b control: a script that saves the ETag with the manifest gets 304 and installs nothing" \
                                        || fail "row 57b control: the early ETag is caught" "$out"
installed_box; rm_plane "$D/tenant.bin"; rk --keyed-set
inm=$(reqs | python3 -c 'import json,sys; print([json.loads(l)["if_none_match"] for l in sys.stdin if json.loads(l)["path"]=="/edge/k/manifest.json"][-1])')
{ [ "$rc" = 0 ] && [ "$inm" = None ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] && [ "$(word)" = fresh ]; } \
  && pass "row 57b: tenant.bin lost locally with .keyed-etag kept: the first locked step deletes the ETag, the run fetches unconditionally, reinstalls G and reads fresh" \
  || fail "row 57b: a local loss is repaired at the next poll" "inm=$inm word=$(word) $out"
M=$(mutant etag-outlives '  [ -e "$TPLANE" ] || rm -f "$ETAGF"' '  :')
installed_box; rm_plane "$D/tenant.bin"; run_with "$M" --keyed-set
{ [ ! -e "$D/tenant.bin" ] && [ "$(word)" = null ]; } \
  && pass "row 57b control: keeping the ETag after the loss draws a 304, installs nothing, and the word stays null" \
  || fail "row 57b control: the ETag rule is caught" "$out"
}

# ===================================================================================================
# Row 58: the tenant pin and --repin.
row58() {
installed_box; SUM=$(sha256sum < "$D/tenant.bin"); content a "$((G0 + 1))" "$REV0" "$TENANT_B"; rk --keyed-set
{ [ "$rc" != 0 ] && [ "$(sha256sum < "$D/tenant.bin")" = "$SUM" ] && says "$out" "ALARM the feed names tenant $TENANT_B, but this box is pinned to tenant $TENANT_A"; } \
  && pass "row 58: a manifest for another tenant id is refused with an alarm and nothing is installed" \
  || fail "row 58: the tenant pin" "rc=$rc $out"
M=$(mutant no-pin 'if [ -n "$TID0" ] && [ "$TID0" != "$KTEN" ]; then' 'if false; then')
installed_box; content a "$((G0 + 1))" "$REV0" "$TENANT_B"; run_with "$M" --keyed-set
[ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ] && pass "row 58 control: without the pin the other tenant's plane installs silently" \
                                                || fail "row 58 control: the pin is what refuses it" "$out"
GA=$((G0 + 10))
repin_case() { # <script>
  fresh_box; place_key; content a "$GA" "$REV0"; rk --keyed-set
  run_with "$1" --repin; o_repin=$out
  content_none a "$TENANT_B"; rk --keyed-set
}
repin_case "$REFRESH"
{ [ ! -e "$D/tenant.bin" ] && [ "$(word)" = null ] && [ "$(cat "$E/state/tenant.high-water")" = "$GA" ] \
  && says "$o_repin" "the high-water file $E/state/tenant.high-water holds $GA" && [ "$(cat "$D/.tenant-id")" = "$TENANT_B" ]; } \
  && pass "row 58: with A's plane at G_A, --repin to B (state: none) leaves tenant.bin absent, the word null, the mark at G_A and the re-arm sentence naming the file; B becomes the pin" \
  || fail "row 58: --repin to a tenant with no plane yet" "word=$(word) $o_repin / $out"
content a "$((GA - 5))" "$REV0" "$TENANT_B"; rk --keyed-set; below=$(present "$D/tenant.bin" installed)
content a "$((GA + 1))" "$((REV0 + 1))" "$TENANT_B"; rk --keyed-set
{ [ -z "$below" ] && [ "$(gen_of "$D/tenant.bin")" = "$((GA + 1))" ]; } \
  && pass "row 58: B's plane below G_A is refused against the mark, and B's first plane above it installs" \
  || fail "row 58: B arms only above the mark" "below=$below $out"
M=$(mutant repin-keeps '  raise_mark || lk_fail "could not write $HWF"
  rm -f "$IDF" || lk_fail "could not remove $IDF"
  sync "$SD" 2>/dev/null || true
  kkill "$1:after-mark"
  unlink_plane || lk_fail "could not remove $TPLANE"' '  [ "$1" = repin ] || raise_mark || lk_fail "could not write $HWF"
  kkill "$1:after-mark"
  [ "$1" = repin ] || unlink_plane || lk_fail "could not remove $TPLANE"')
repin_case "$M"
[ "$(word)" = fresh ] && pass "row 58 control: a --repin that keeps A's plane armed for B is caught (the word reads fresh)" \
                      || fail "row 58 control: --repin's unlink is what disarms A" "$(word)"
race_install "$REFRESH" interleave_repin
{ [ ! -e "$D/tenant.bin" ] && says "$(cat "$W/paused")" 'the fetched plane was dropped'; } \
  && pass "row 58: a run that fetched A's plane before the --repin cannot install it" \
  || fail "row 58: the epoch after --repin" "$(cat "$W/paused")"
}

# ===================================================================================================
# Row 58b: the run budget. Every request has --max-time 120 and starts only while 1,300 s cover it.
row58b() {
budget_case() { # <script>
  installed_box; content a "$((G0 + 1))" "$REV0"
  cfg "{'rules': [{'addr': '127.0.0.1', 'path': 'manifest.json', 'status': 503, 'code': 'busy'}, {'addr': '127.0.0.2', 'path': 'tenant.bin', 'status': 503, 'code': 'busy'}, {'path': 'tenant.bin.sig', 'status': 412}]}"
  T0=$(date +%s); echo "$T0" > "$W/clock"; echo 120 > "$W/clock.step"; rm -f "$W/curl.starts" "$W/curl.argv"
  run_with "$1" --keyed-set
  rm -f "$W/clock" "$W/clock.step"
  late=$(awk -v t0="$T0" '$1 - t0 > 1300 - 120 { n++ } END { print n + 0 }' "$W/curl.starts")
}
budget_case "$REFRESH"
maxt=$(grep -- '/edge/k/' "$W/curl.argv" | grep -c -- '--max-time 120'); calls=$(grep -c -- '/edge/k/' "$W/curl.argv")
{ [ "$rc" = 0 ] && [ "$late" = 0 ] && [ "$maxt" = "$calls" ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] \
  && says "$out" "budget does not cover another 120 s request; everything is kept"; } \
  && pass "row 58b: with 503s and a 412 in both passes and the clock advancing 120 s a request, the run stops before 1,300 s, keeps everything, logs the budget and exits 0 ($calls requests, each --max-time 120)" \
  || fail "row 58b: the budget" "rc=$rc late=$late maxt=$maxt calls=$calls $out"
M=$(mutant no-budget '  [ $((RUN_START + KEYED_BUDGET - $(date +%s))) -ge "$KEYED_MAX_TIME" ] && return 0' '  return 0')
budget_case "$M"
[ "$late" -gt 0 ] && pass "row 58b control: without the per-request check a request starts past 1,300 s on the shim's clock" \
                  || fail "row 58b control: the budget check is what stops it" "late=$late"
fresh_box; : > "$D/.tenant.bin.Ab12Cd"; touch -d '-25 minutes' "$D/.tenant.bin.Ab12Cd"
XENV="WHISPER_EDGE_RESOLVE=edge.invalid:9:127.0.0.9"; rk --plane tor --base http://edge.invalid:9/edge; XENV=""
[ -e "$D/.tenant.bin.Ab12Cd" ] && pass "row 58b: a keyless run does not delete a live keyed download temp (25 minutes old)" \
                               || fail "row 58b: the keyless reaper spares the keyed temp" "$out"
}

# ===================================================================================================
# Row 59: a 304 writes nothing; a 404 on k/manifest.json (a node before the keyed tier) keeps everything.
row59() {
installed_box; before=$(find "$D" "$E" -type f -printf '%p %T@ %s\n' | sort); sleep 1; rk --keyed-set
after=$(find "$D" "$E" -type f -printf '%p %T@ %s\n' | sort)
{ [ "$rc" = 0 ] && [ "$before" = "$after" ] && [ -z "$out" ]; } \
  && pass "row 59: a 304 exits 0 quietly and writes nothing" || fail "row 59: a 304 writes nothing" "rc=$rc $out"
absent_case() { installed_box; SUM=$(sha256sum < "$D/tenant.bin"); rm -f "$F/requests.log"
  cfg "{'rules': [{'path': 'manifest.json', 'status': 404, 'code': 'not_found', 'preauth': True}]}"; run_with "$1" --keyed-set; }
absent_case "$REFRESH"
{ [ "$rc" = 0 ] && [ "$(sha256sum < "$D/tenant.bin")" = "$SUM" ] && [ "$(nreq path=/edge/k/manifest.json)" = 1 ]; } \
  && pass "row 59: a 404 on k/manifest.json keeps everything, asked once" || fail "row 59: a release-N node" "rc=$rc $out"
M=$(mutant absent-reruns '      absent)
        say "k/manifest.json is 404' '      absent)
        if [ "$attempt" = 1 ]; then attempt=2; continue; fi
        say "k/manifest.json is 404')
absent_case "$M"
[ "$(nreq path=/edge/k/manifest.json)" = 2 ] && pass "row 59 control: a script that treats it like a 404 on a named hash re-runs once (two requests)" \
                                             || fail "row 59 control: the re-run is visible" "$(nreq path=/edge/k/manifest.json)"
}

# ===================================================================================================
# Row 60: an old curl. -H @file arrived in 7.55.0.
row60() {
keyless_stub
installed_box; rm -f "$F/requests.log"; echo 7.54.0 > "$W/curlver"; rk --keyed-set; o60=$out; r60=$rc
keyless_tor
{ [ "$r60" = 0 ] && says "$o60" 'curl 7.54.0 cannot send a header from a file' && [ "$(nreq)" = 0 ] \
  && [ "$rc" = 0 ] && [ -f "$D/tor.bin" ]; } \
  && pass "row 60: curl 7.54.0 refuses the keyed path with the message, makes no keyed request, and the keyless planes still install" \
  || fail "row 60: an old curl" "r60=$r60 $o60 / rc=$rc $out"
echo 7.55.0 > "$W/curlver"; rk --keyed-set
[ "$(nreq path=/edge/k/manifest.json)" -ge 1 ] && pass "row 60 control: curl 7.55.0 takes the keyed path" \
                                               || fail "row 60 control: 7.55.0 is enough" "$out"
rm -f "$W/curlver"
}

# ===================================================================================================
# Row 61: the key file's mode. A key readable by group or other is refused by the run, which continues
# keyless and never changes the mode (the unit case is in the root section below).
row61() {
installed_box; chmod 0644 "$E/key"; rm -f "$F/requests.log"; rk --keyed-set
{ [ "$rc" != 0 ] && says "$out" 'this key may have been read by another user; revoke it with whisper-edge-refresh --unenroll and enrol again' \
  && [ "$(stat -c %a "$E/key")" = 644 ] && [ "$(nreq)" = 0 ]; } \
  && pass "row 61: a 0644 key is refused with the revoke advice, no keyed request is made and the mode is unchanged" \
  || fail "row 61: an exposed key" "rc=$rc $out"
chmod 0600 "$E/key"; content a "$((G0 + 1))" "$REV0"; rk --keyed-set
{ [ "$rc" = 0 ] && ! says "$out" 'another user' && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 61 control: a 0600 key is silent and used" || fail "row 61 control: a 0600 key works" "rc=$rc $out"
}

# ===================================================================================================
# Row 63: generations on the edge.
row63() {
installed_box; rk --keyed-set; content a "$G0" "$REV0" "$TENANT_A" --deny 2a04:2a01::9/128; rk --keyed-set
{ [ "$rc" != 0 ] && says "$out" "the feed names generation $G0, not newer than the installed $G0"; } \
  && pass "row 63: without a revocation an equal generation is not installed (the same bytes are already current, other bytes are refused)" \
  || fail "row 63: an equal generation" "rc=$rc $out"
cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; owner_home; cfg '{}'; rk --enroll --force
r63=""
for g in $((G0 - 1)) "$G0"; do
  content a "$g" "$REV0"; rk --keyed-set
  if [ -e "$D/tenant.bin" ] || ! says "$out" "is at or below the high-water mark $G0 in $E/state/tenant.high-water"; then r63="$r63 $g:$out"; fi
done
content a "$((G0 + 1))" "$REV0"; rk --keyed-set
{ [ -z "$r63" ] && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ] && [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = fresh ]; } \
  && pass "row 63: after a revocation at G with the mark at G, the re-enrolled box refuses G - 1 and G, naming the mark, and installs G + 1 (the tombstone goes with it)" \
  || fail "row 63: the mark after re-enrolment" "$r63 $out"
}

# ===================================================================================================
# Row 74: the high-water file and its record. The mark is max(the file, the installed plane's
# generation, tenant.installed), never lowered; a malformed state file stops every keyed run before any
# request with one per-file hand repair, from file evidence only, through the always-printed path.
row74() {
G=$G0
# the mark's bytes, after a revocation
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
{ [ "$(od -An -c "$HWF" | tr -d ' \n')" = "$G\\n" ] && [ "$(stat -c %a "$HWF")" = 444 ] \
  && [ "$(od -An -c "$RECF" | tr -d ' \n')" = "$G\\n" ] && [ "$(stat -c %a "$RECF")" = 444 ]; } \
  && pass "row 74: after a revocation state/tenant.high-water is 0444 and holds exactly '<G>\\n', and the install wrote state/tenant.installed the same way" \
  || fail "row 74: the bytes" "$(od -c "$HWF" 2>&1) $(od -c "$RECF" 2>&1)"
# a later revocation with a lower installed generation leaves the higher value
lower_case() { # <script>
  fresh_box; place_key; content a "$((G + 5))" "$REV0"; rk --keyed-set
  set_state "$HWF" "$((G + 100))\n"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$1" --keyed-set
}
lower_case "$REFRESH"
[ "$(cat "$HWF")" = "$((G + 100))" ] && pass "row 74: a revocation over a lower installed generation leaves the higher mark" \
                                     || fail "row 74: the mark is never lowered" "$(cat "$HWF") $out"
M=$(mutant mark-from-plane '  KMARK=$(mark_value)
  [ -n "$KMARK" ] || return 0
  if [ "$HW_ST" = ok ] && [ "$HW_V" -ge "$KMARK" ]; then return 0; fi' '  KMARK=$(plane_gen_ok "$TPLANE")
  [ -n "$KMARK" ] || return 0')
lower_case "$M"
[ "$(cat "$HWF")" != "$((G + 100))" ] && pass "row 74 control: a writer that writes the installed generation unconditionally lowers the mark" \
                                      || fail "row 74 control: the never-lower rule is what kept it" "$(cat "$HWF")"
# no plane ever installed: no mark, only the tombstone
fresh_box; place_key; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
{ [ ! -e "$HWF" ] && grep -Eq '^[0-9]+ 0$' "$D/.tenant-tombstone" && [ "$(word)" = revoked ]; } \
  && pass "row 74: a revocation with nothing ever installed writes no mark, only the tombstone '<epoch> 0', and reads revoked" \
  || fail "row 74: the first-poll revocation" "$(ls "$E/state") $(cat "$D/.tenant-tombstone" 2>&1)"
# the record is never lowered by an install, and the install gate never reads it
installed_box; set_state "$RECF" "$((G + 100))\n"; content a "$((G + 1))" "$REV0"; rk --keyed-set
{ [ "$(gen_of "$D/tenant.bin")" = "$((G + 1))" ] && [ "$(cat "$RECF")" = "$((G + 100))" ]; } \
  && pass "row 74: an over-stated record blocks no install and is never lowered by one" \
  || fail "row 74: the record and the install gate" "$(cat "$RECF") $out"
# tenant.bin lost locally, then a revocation or --unenroll: the mark comes from the record
loss_case() { # <script> <revoke|unenroll>
  installed_box; backup preloss; rm_plane "$D/tenant.bin"
  if [ "$2" = revoke ]; then cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$1" --keyed-set; else owner_home; run_with "$1" --unenroll; fi
  restore preloss
}
for how in revoke unenroll; do
  loss_case "$REFRESH" "$how"
  { [ "$(cat "$HWF" 2>/dev/null)" = "$G" ] && [ "$(word)" = revoked ]; } \
    && pass "row 74: tenant.bin lost, then a $how: the mark is G from tenant.installed, and the restored pre-loss directory reads revoked" \
    || fail "row 74: the record seeds the mark ($how)" "hw=$(fileval "$HWF") word=$(word) $out"
done
M=$(mutant mark-plane-only '  for _x in "$( [ "$HW_ST" = ok ] && printf '"'"'%s'"'"' "$HW_V")" "$(plane_gen_ok "$TPLANE")" \
            "$( [ "$REC_ST" = ok ] && printf '"'"'%s'"'"' "$REC_V")"; do' '  for _x in "$(plane_gen_ok "$TPLANE")"; do')
loss_case "$M" revoke
[ "$(word)" = fresh ] && pass "row 74 control: a mark taken from tenant.bin alone writes nothing after the loss, and the restored plane arms" \
                      || fail "row 74 control: the record is what held it" "$(word)"
M=$(mutant no-mark-write '  put_file "$SD" tenant.high-water 0444 "$KMARK
"' '  :')
installed_box; backup prerev; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$M" --keyed-set; restore prerev
[ "$(word)" = fresh ] && pass "row 74 control: with the mark's write removed the file is absent and the restored pre-revocation plane arms" \
                      || fail "row 74 control: the write is what holds it" "$(word)"
installed_box; backup prerev; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; restore prerev
{ [ -e "$HWF" ] && [ "$(word)" = revoked ]; } && pass "row 74: restoring the pre-revocation plane directory leaves the mark (it is not in it) and reads revoked" \
                                           || fail "row 74: the mark survives a restore of the plane directory" "$(word)"

# six malformed shapes, each file: every keyed run logs the sentence and exits non-zero before any
# request, the 304 path included; nothing installs, a revocation refuses, --unenroll and --repin refuse whole
SHAPES="9223372036854775808\n|0\n|012\n|$G|$G \n|123456789012345678901\n"
IFS0=$IFS
for which in hw rec; do
  [ "$which" = hw ] && f=$HWF || f=$RECF
  IFS='|'
  for shp in $SHAPES; do
    IFS=$IFS0
    lab=$(shape_label "$shp")
    installed_box; content a "$((G + 1))" "$REV0"; set_state "$f" "$shp"; rm -f "$F/requests.log"
    rk --quiet --keyed-set
    r_run=$rc; o_run=$out; n_run=$(nreq)
    content a "$G" "$REV0"; rk --quiet --keyed-set; r_304=$rc; n_304=$(nreq)
    cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; r_rev=$rc
    snap=$(find "$D" "$E" -type f -printf '%p %T@\n' | sort)
    owner_home; rk --unenroll; r_un=$rc; o_un=$out
    rk --repin; r_re=$rc
    snap2=$(find "$D" "$E" -type f -printf '%p %T@\n' | sort)
    { [ "$r_run" != 0 ] && [ "$n_run" = 0 ] && [ "$r_304" != 0 ] && [ "$n_304" = 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G" ] \
      && says "$o_run" "$f is malformed" && says "$o_run" 'if this time is right, write' \
      && says "$o_run" 'applies no revocation and no list change until the file is repaired, and says so on every run' \
      && [ "$r_rev" != 0 ] && [ -e "$D/tenant.bin" ] && [ ! -e "$D/.tenant-tombstone" ] \
      && [ "$r_un" != 0 ] && [ "$r_re" != 0 ] && [ "$snap" = "$snap2" ] && ! says "$o_un" 'keyless again' \
      && [ -e "$E/key" ]; } \
      && pass "row 74: $which '$lab': no install, every run (304 included) logs the per-file repair and exits non-zero before any request; the revocation, --unenroll and --repin refuse with every file unchanged" \
      || fail "row 74: $which '$lab'" "run=$r_run/$n_run 304=$r_304/$n_304 rev=$r_rev un=$r_un re=$r_re $o_run / $o_un"
    IFS='|'
  done
  IFS=$IFS0
done
M=$(mutant no-first-check '  if [ "$STATE_OK" = 0 ]; then
    repair_sentence
    plane_failed "a state file is malformed (above)"
  fi' '  :')
installed_box; set_state "$HWF" "0\n"; run_with "$M" --quiet --keyed-set
[ "$rc" = 0 ] && pass "row 74 control: a script that validates the state files only at the install gate exits 0 on the 304 fixture" \
              || fail "row 74 control: the first-step check is what fails the 304 run" "rc=$rc $out"
M2="$M"
remut "$M2" 'locked_state_or_exit() {
  if ! state_check; then' 'locked_state_or_exit() {
  state_check || true
  if false; then'
installed_box; content a "$((G + 1))" "$REV0"; set_state "$HWF" "0\n"; run_with "$M2" --keyed-set
{ says "$out" 'installed tenant.bin' && [ "$(word)" = malformed ]; } \
  && pass "row 74 control: a refresh that installs over a malformed file logs 'installed' while the reader refuses (malformed)" \
  || fail "row 74 control: the state check is what refuses the install" "$out $(word)"
M=$(mutant say-sentence '  kpy repair "$HWF" "$RECF" "$TOMBF" "$TPLANE" "$(date +%s)" "$IDF" >&2' '  [ "$QUIET" = 1 ] || kpy repair "$HWF" "$RECF" "$TOMBF" "$TPLANE" "$(date +%s)" "$IDF"')
installed_box; set_state "$HWF" "0\n"; run_with "$M" --quiet --keyed-set
{ [ "$rc" != 0 ] && ! says "$out" 'if this time is right'; } \
  && pass "row 74 control: the sentence sent through say() prints nothing under --quiet while the exit code still fails" \
  || fail "row 74 control: the always-printed path is what carries it" "$out"
M=$(mutant exits-zero '    plane_failed "a state file is malformed (above)"
  fi
  case "$KST" in' '    exit 0
  fi
  case "$KST" in')
installed_box; set_state "$HWF" "0\n"; run_with "$M" --quiet --keyed-set
[ "$rc" = 0 ] && pass "row 74 control: a run that logs the sentence and exits 0 leaves the keyed timer looking healthy (exit 0)" \
              || fail "row 74 control: the non-zero exit is the detector" "rc=$rc"
# a 0644 key beside a malformed record: both sentences, a non-zero exit
installed_box; chmod 0644 "$E/key"; set_state "$RECF" "0\n"; rk --quiet --keyed-set
{ [ "$rc" != 0 ] && says "$out" 'this key may have been read by another user' && says "$out" "$RECF is malformed"; } \
  && pass "row 74: a 0644 key beside a malformed tenant.installed logs both sentences and exits non-zero" \
  || fail "row 74: the key refusal does not hide the state sentence" "$out"
M=$(mutant key-first '  case "$KST" in
    exposed)' '  case "$KST" in exposed|notkey) plane_failed "no usable key" ;; esac
  case "$KST" in
    exposed)')
installed_box; chmod 0644 "$E/key"; set_state "$RECF" "0\n"; run_with "$M" --quiet --keyed-set
says "$out" "$RECF is malformed" && fail "row 74 control: refusing the key first is caught" "$out" \
  || pass "row 74 control: an implementation that refuses the key first exits without the state-file sentence"

# repairs of the high-water file: to the record's value revokes the armed plane; to G - 1 it stays fresh
installed_box; set_state "$HWF" "0\n"; rk --keyed-set
{ says "$out" 'a value at or above the installed tenant.bin' && [ "$(sent_val "$out" hw)" = "$((G - 1))" ]; } \
  && pass "row 74: the high-water sentence names G - 1 for an armed plane, with its warning" \
  || fail "row 74: the armed-plane repair" "$out"
set_state "$HWF" "$G\n"; w1=$(word); set_state "$HWF" "$((G - 1))\n"; w2=$(word)
{ [ "$w1" = revoked ] && [ "$w2" = fresh ]; } && pass "row 74: a repair to tenant.installed's value reads revoked, to the installed generation minus one reads fresh" \
                                            || fail "row 74: the repair values" "$w1 $w2"
# the record's chain: the high-water value only with a tombstone; tenant.bin's G; never the record itself
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; set_state "$RECF" "0\n"; cfg '{}'; rk --keyed-set
[ "$(sent_val "$out" rec)" = "$G" ] && pass "row 74: a malformed tenant.installed with tenant.bin absent, a tombstone and a well-formed mark: the sentence names the mark ($G)" \
                                   || fail "row 74: the record's mark end" "$out"
installed_box; set_state "$RECF" "0\n"; rk --keyed-set
[ "$(sent_val "$out" rec)" = "$G" ] && pass "row 74: with tenant.bin present at G it names G" || fail "row 74: the record's plane end" "$out"
lr_case() { # --unenroll at G, both files malformed
  installed_box; backup preun; owner_home; rk --unenroll
  set_state "$HWF" "0\n"; set_state "$RECF" "0\n"; rk --keyed-set; o1=$out; v1=$(sent_val "$out" hw)
}
lr_case
{ [ "$v1" -ge "$(( $(date +%s) + 86000 ))" ] && says "$o1" 'the last resort'; } \
  && pass "row 74: --unenroll at G, both files malformed: the high-water sentence names the last resort (UTC now + 86,400)" \
  || fail "row 74: the last resort" "$o1"
set_state "$HWF" "$v1\n"; rk --keyed-set; v2=$(sent_val "$out" rec); set_state "$RECF" "$v2\n"; restore preun
[ "$(word)" = revoked ] && pass "row 74: after both repairs the directory restored from before --unenroll (G, no tombstone) reads revoked" \
                        || fail "row 74: the last resort holds the restore" "v2=$v2 $(word)"
lr_case; set_state "$HWF" "1\n"; set_state "$RECF" "1\n"; restore preun
[ "$(word)" = fresh ] && pass "row 74 control: a repair of both files to 1 arms the restored pre-revocation plane" \
                      || fail "row 74 control: the repair value matters" "$(word)"
# a corrupt-high byte-16 field: above the ceiling it is damage and never a mark; at or below it, the
# not-newer branch refuses and raises nothing, and a later revocation can take it
# a field raised in place on this box (a bit flip): the same inode, and the identity record follows it,
# so the arms below test the ceiling, never the restore guard
corrupt() {
  mutable "$D/tenant.bin"
  python3 -c 'import struct,sys; b=bytearray(open(sys.argv[1],"rb").read()); struct.pack_into("<Q",b,16,int(sys.argv[2])); open(sys.argv[1],"wb").write(bytes(b))' "$D/tenant.bin" "$1"
  set_state "$E/state/tenant.plane-id" "$(kpyx planeid "$D/tenant.bin")\n"
}
hi_case() { # <script> <field>
  # the keyless manifest commits every hour, so a 200 always comes; the gate takes it now
  installed_box; writable "$D/tenant.bin"; corrupt "$2"; content a "$G" "$REV0"; rm -f "$D/.keyed-etag"
  run_with "$1" --keyed-set; o200=$out; r200=$rc; rec_after=$(cat "$RECF")
  cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$1" --keyed-set
}
hi_case "$REFRESH" 4611686018427387904
{ [ "$r200" != 0 ] && says "$o200" 'damaged on this box' && [ "$rec_after" = "$G" ] && [ "$(cat "$HWF")" = "$G" ]; } \
  && pass "row 74: tenant.bin's field raised to 2^62: the 200 run installs the served plane over it, logs the refused line and exits non-zero; the record stays G and the revocation's mark is G" \
  || fail "row 74: an above-ceiling field" "r200=$r200 rec=$rec_after hw=$(fileval "$HWF") $o200"
M=$(mutant trust-field '  [ "${2:-}" = ok ] && printf '"'"'%s'"'"' "$1"' '  [ "${1:-none}" != none ] && printf '"'"'%s'"'"' "$1"')
installed_box; writable "$D/tenant.bin"; corrupt 4611686018427387904; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$M" --keyed-set
[ "$(cat "$HWF" 2>/dev/null)" = 4611686018427387904 ] && pass "row 74 control: a revocation that trusts the byte-16 field above the ceiling writes 2^62 as the mark" \
                                                     || fail "row 74 control: the ceiling is what refuses the field" "$(fileval "$HWF")"
hi_case "$REFRESH" "$((G + 50000))"
{ [ "$r200" != 0 ] && says "$o200" "not newer than the installed $((G + 50000))" && [ "$rec_after" = "$G" ] \
  && [ "$(cat "$HWF")" = "$((G + 50000))" ]; } \
  && pass "row 74: a field raised to G + 50,000 (under the ceiling): the 200 run refuses and leaves the record at G; the revocation's mark is G + 50,000" \
  || fail "row 74: an in-band raised field" "r200=$r200 rec=$rec_after hw=$(fileval "$HWF") $o200"
owner_home; cfg '{}'; rk --enroll --force; content a "$((G + 50001))" "$REV0"; rk --keyed-set
[ "$(gen_of "$D/tenant.bin")" = "$((G + 50001))" ] && pass "row 74: and a generation above it re-arms" || fail "row 74: re-arm above the raised mark" "$out"
M=$(mutant raise-not-newer '      kalarm "the feed names generation $ngen, not newer than the installed $1, and' '      put_file "$SD" tenant.installed 0444 "$1
"; kalarm "the feed names generation $ngen, not newer than the installed $1, and')
installed_box; writable "$D/tenant.bin"; corrupt "$((G + 50000))"; content a "$G" "$REV0"; rm -f "$D/.keyed-etag"; run_with "$M" --keyed-set
[ "$(cat "$RECF")" = "$((G + 50000))" ] && pass "row 74 control: a script raising the record from the not-newer branch writes G + 50,000 into tenant.installed" \
                                        || fail "row 74 control: the not-newer branch raises nothing" "$(cat "$RECF")"
# the same served generation at a lower rev with other bytes: the revision never goes back, so everything is kept, exit 0
installed_box; content a "$G" "$((REV0 - 1))" "$TENANT_A" --deny 2a04:2a01::77/128; rk --quiet --keyed-set
{ [ "$rc" = 0 ] && says "$out" "the feed's lists are older than the installed ones (revision $((REV0 - 1)) below $REV0); keeping them"; } \
  && pass "row 74: the same generation at a lower rev with another sha keeps everything, alarms through the always-printed path and exits 0" \
  || fail "row 74: the rev check runs first" "rc=$rc $out"
M=$(mutant gen-first '    if [ "$REV_ST" = ok ] && [ "$prev" -lt "$REV0" ]; then' '    if false; then')
installed_box; content a "$G" "$((REV0 - 1))" "$TENANT_A" --deny 2a04:2a01::77/128; run_with "$M" --quiet --keyed-set
[ "$rc" != 0 ] && pass "row 74 control: a generation-first ordering exits non-zero against a lower-rev node" \
               || fail "row 74 control: the order is visible" "rc=$rc"
# the hand repair from file evidence only, after a --repin run from a shell
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; owner_home; cfg '{}'; rk --enroll --force
G2=$((G + 7)); content a "$G2" "$REV0"; rk --keyed-set; backup prerepin; rk --repin; set_state "$HWF" "0\n"; rk --keyed-set
v=$(sent_val "$out" hw); set_state "$HWF" "$v\n"; restore prerepin
{ [ "$v" = "$G2" ] && [ "$(word)" = revoked ]; } \
  && pass "row 74: revoke at G1, re-enrol, install G2, --repin by hand, the mark set to 0: the sentence names tenant.installed's G2 and the restored pre-repin directory reads revoked" \
  || fail "row 74: the file-only chain after --repin" "v=$v word=$(word) $out"
# a corrupt-high tenant.bin beside a malformed mark: the record, never 2^62 - 1
installed_box; writable "$D/tenant.bin"; corrupt 4611686018427387904; set_state "$HWF" "0\n"; rk --keyed-set
[ "$(sent_val "$out" hw)" = "$G" ] && pass "row 74: a corrupt-high tenant.bin beside a malformed mark, no tombstone: the sentence names tenant.installed's G, never 2^62 - 1" \
                                  || fail "row 74: the ceiling guards the plane end" "$out"
M=$(mutant no-ceiling-end '    gok = g is not None and 1 <= g <= C and not restored' '    gok = g is not None and 1 <= g and not restored')
installed_box; writable "$D/tenant.bin"; corrupt 4611686018427387904; set_state "$HWF" "0\n"; run_with "$M" --keyed-set
[ "$(sent_val "$out" hw)" = 4611686018427387903 ] && pass "row 74 control: a sentence without the ceiling names 2^62 - 1" \
                                                  || fail "row 74 control: the ceiling is visible" "$out"
for tomb in with without; do
  installed_box; writable "$D/tenant.bin"; corrupt 4611686018427387904; set_state "$RECF" "0\n"
  [ "$tomb" = with ] && set_state "$D/.tenant-tombstone" "1 $G\n" && set_state "$HWF" "$G\n"
  rk --keyed-set; v=$(sent_val "$out" rec)
  if [ "$tomb" = with ]; then
    [ "$v" = "$G" ] && pass "row 74: a corrupt-high tenant.bin beside a malformed record, with a tombstone: the sentence names the mark, never the raised field" \
                    || fail "row 74: the record chain over a raised field (tombstone)" "$out"
  else
    [ "$v" -ge "$(( $(date +%s) + 86000 ))" ] && [ "$v" != 4611686018427387904 ] \
      && pass "row 74: a corrupt-high tenant.bin beside a malformed record, no tombstone: the sentence names the last resort, never the raised field" \
      || fail "row 74: the record chain over a raised field (no tombstone)" "$out"
  fi
done
# A restored plane never passes for this script's install: only the identity record the install wrote
# (state/tenant.plane-id: device, inode, change time) does, so a restore by any tool reads as restored,
# with no time changed by hand.
# (1) a restored older tenant.bin beside a malformed record, the mark below the true record: the last resort
restored_case() { # <script> <restore tool>
  fresh_box; place_key; content a "$G" "$REV0"; rk --keyed-set; backup old
  content a "$((G + 20))" "$REV0"; rk --keyed-set; backup new
  set_state "$HWF" "$((G - 10))\n"; restore old "$2"; set_state "$RECF" "0\n"
  run_with "$1" --keyed-set; v=$(sent_val "$out" rec)
}
for tool in cp cp-p tar cp-a; do
  restored_case "$REFRESH" "$tool"
  [ "$v" -ge "$(( $(date +%s) + 86000 ))" ] \
    && pass "row 74: an older tenant.bin restored by $tool beside a malformed record: the sentence skips the restored plane to the last resort" \
    || fail "row 74: the restore guard ($tool)" "v=$v $out"
done
restored_case "$REFRESH" cp
set_state "$RECF" "$v\n"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; restore new cp
[ "$(word)" = revoked ] && pass "row 74: after that repair and a revocation, the newer directory restored by cp reads revoked" \
                        || fail "row 74: the repaired record holds the restore" "$(word)"
M=$(mutant no-restore-guard '    gok = g is not None and 1 <= g <= C and not restored' '    gok = g is not None and 1 <= g <= C')
restored_case "$M" cp-a
[ "$v" = "$G" ] && pass "row 74 control: without the restore guard the sentence names the restored plane's G_old" \
                || fail "row 74 control: the guard is visible" "v=$v"
CTIME=$(mutant ctime-rule '    return (g, rec != mine)' '    return (g, st.st_ctime - st.st_mtime > 1800)')
restored_case "$CTIME" cp
[ "$v" = "$G" ] && pass "row 74 control: a change-time rule reads a plain cp restore as installed and names G_old" \
                || fail "row 74 control: the change-time rule is caught on the cp arm" "v=$v"
# an older plane written over the installed file in place keeps its device and inode, and only the change
# time tells it from the install
inplace_case() { # <script>
  fresh_box; place_key; content a "$G" "$REV0"; run_with "$1" --keyed-set; backup old
  content a "$((G + 20))" "$REV0"; run_with "$1" --keyed-set
  set_state "$HWF" "$((G - 10))\n"; ino0=$(stat -c %i "$D/tenant.bin")
  chattr -i "$D/tenant.bin" 2>/dev/null || true; chmod u+w "$D/tenant.bin"
  cat "$W/bk.old/tenant.bin" > "$D/tenant.bin"; chmod 0444 "$D/tenant.bin"; set_state "$RECF" "0\n"
  run_with "$1" --keyed-set; v=$(sent_val "$out" rec)
}
inplace_case "$REFRESH"
{ [ "$(stat -c %i "$D/tenant.bin")" = "$ino0" ] && [ "$v" -ge "$(( $(date +%s) + 86000 ))" ]; } \
  && pass "row 74: an older tenant.bin written over the installed one in place (same device and inode) reads as restored: the last resort" \
  || fail "row 74: the in-place restore" "v=$v $out"
M=$(mutant dev-ino-only '    return "%d %d %d" % (st.st_dev, st.st_ino, st.st_ctime_ns)' '    return "%d %d 0" % (st.st_dev, st.st_ino)')
inplace_case "$M"
[ "$v" = "$G" ] && pass "row 74 control: an identity of device and inode alone reads the in-place restore as the install and names G_old" \
                || fail "row 74 control: the change time is visible" "v=$v"
# (2) after --unenroll at G, the mark malformed, tenant.bin put back: never G - 1, which would arm it
unenroll_restore() { # <script> <restore tool>
  installed_box; backup preun; owner_home; rk --unenroll; set_state "$HWF" "0\n"
  restore preun "$2"; run_with "$1" --keyed-set; v=$(sent_val "$out" hw)
}
for tool in cp cp-p tar; do
  unenroll_restore "$REFRESH" "$tool"
  [ "$v" = "$G" ] && pass "row 74: --unenroll at G, the mark malformed, tenant.bin restored by $tool: the sentence names tenant.installed's G, never G - 1" \
                  || fail "row 74: the restore guard after --unenroll ($tool)" "v=$v $out"
done
unenroll_restore "$CTIME" cp
[ "$v" = "$((G - 1))" ] && pass "row 74 control: the change-time rule names G - 1 for the cp restore, which would arm the revoked plane" \
                        || fail "row 74 control: the change-time rule on the --unenroll restore" "v=$v"
# (3) the identity record lives exactly as long as the plane it names: written by the install, equal to
# the installed file's identity, and gone after a revocation, --unenroll and --repin, so no later restore
# of that plane can match it
IDF="$E/state/tenant.plane-id"
# the identity built here, not by the script's ident(): device and inode from stat(1), the change time
# in nanoseconds from python's own os.stat
ident_of() { printf '%s %s\n' "$(stat -c '%d %i' "$1")" "$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_ctime_ns)' "$1")"; }
how_label() { case $1 in revoke) echo "a revocation" ;; *) echo "--$1" ;; esac; }
id_life() { # <script> <revoke|unenroll|repin>: sets before_ (match|absent|other) and after_ (absent|present)
  installed_box
  if [ ! -e "$IDF" ]; then before_=absent
  elif [ "$(cat "$IDF")" = "$(ident_of "$D/tenant.bin")" ]; then before_=match; else before_=other; fi
  case $2 in
    revoke)   cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$1" --keyed-set ;;
    unenroll) owner_home; run_with "$1" --unenroll ;;
    repin)    run_with "$1" --repin ;;
  esac
  cfg '{}'
  if [ -e "$IDF" ]; then after_=present; else after_=absent; fi
}
NOID=$(mutant no-id-removal '  rm -f "$IDF" || lk_fail "could not remove $IDF; the revocation is incomplete and the next run completes it"' '  :')
remut "$NOID" '  rm -f "$IDF" || lk_fail "could not remove $IDF"' '  :'
for how in revoke unenroll repin; do
  id_life "$REFRESH" "$how"
  { [ "$before_" = match ] && [ "$after_" = absent ] && [ ! -e "$D/tenant.bin" ]; } \
    && pass "row 74: the identity record equals the installed tenant.bin's (device, inode, change time) before $(how_label "$how"), and is absent after it" \
    || fail "row 74: the identity record across a $how" "before=$before_ after=$after_ $out"
  id_life "$NOID" "$how"
  [ "$after_" = present ] && pass "row 74 control: with the record's removals made no-ops, the record outlives $(how_label "$how")" \
                          || fail "row 74 control: the removal after a $how is visible" "after=$after_"
done
# the behaviour the removal protects: a rollback of the plane directory that also matches a surviving
# record (a snapshot restoring the same inode, modelled by rewriting the record to the restored file)
# reads as this script's install and names G - 1, which would arm the revoked plane
id_rollback() { # <script>
  installed_box; backup prerev; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$1" --keyed-set; cfg '{}'
  set_state "$HWF" "0\n"; restore prerev cp
  [ -e "$IDF" ] && set_state "$IDF" "$(kpyx planeid "$D/tenant.bin")\n"
  run_with "$1" --keyed-set; v=$(sent_val "$out" hw)
}
id_rollback "$REFRESH"
[ "$v" = "$G" ] && pass "row 74: revoked at G, the mark malformed, the plane directory rolled back: the record is gone, so the sentence names G, never G - 1" \
                || fail "row 74: the rollback after a revocation" "v=$v $out"
id_rollback "$NOID"
[ "$v" = "$((G - 1))" ] && pass "row 74 control: with the record surviving the revocation, the same rollback names G - 1, which would arm the revoked plane" \
                        || fail "row 74 control: the record's removal is what keeps G" "v=$v"
# the state directory is read only as the owner-file rule reads a key's directory: a symlink, or one
# writable by its group, is refused before any state file is read or written
sd_case() { # <script> <symlink|groupw>
  installed_box; content a "$((G0 + 1))" "$REV0"
  case $2 in
    symlink) mv "$E/state" "$E/state.real"; ln -s state.real "$E/state" ;;
    groupw) chmod 0775 "$E/state" ;;
  esac
  run_with "$1" --keyed-set
  sd_gen=$(gen_of "$D/tenant.bin")
  [ -L "$E/state" ] && { rm "$E/state"; mv "$E/state.real" "$E/state"; }; chmod 0755 "$E/state"
}
# the symlink sentence's remedy is one that works: install -d over the link leaves it refused, and the
# named rm then install -d clears it
installed_box; content a "$((G0 + 1))" "$REV0"; mv "$E/state" "$E/state.real"; ln -s state.real "$E/state"
rk --keyed-set; o_link=$out
install -d -m 0755 "$E/state"; rk --keyed-set; o_inst=$out
rm "$E/state" && install -d -m 0755 "$E/state"; cp -p "$E/state.real"/* "$E/state/" 2>/dev/null || true; rm -rf "$E/state.real"; rk --keyed-set
{ says "$o_link" "replace the link with a real directory: rm $E/state && install -d -m 0755 $E/state" && says "$o_inst" 'is a symbolic link' \
  && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 74: the symlink sentence names rm then install -d, which clears it, while install -d over the link alone (the generic remedy) is still refused" \
  || fail "row 74: the symlink remedy" "$o_link / $o_inst / gen=$(gen_of "$D/tenant.bin")"
SDOK=$(mutant sd-unchecked '  _sdc=$(kpy sdcheck "$SD")' '  _sdc=ok')
for how in symlink groupw; do
  sd_case "$REFRESH" "$how"
  case $how in symlink) why='is a symbolic link' ;; *) why='is writable by its group or by others' ;; esac
  { [ "$rc" != 0 ] && [ "$sd_gen" = "$G0" ] && says "$out" "the state directory $E/state $why"; } \
    && pass "row 74: a state directory that $why is refused with the sentence, and nothing installs" \
    || fail "row 74: the state directory ($how)" "rc=$rc gen=$sd_gen $out"
  sd_case "$SDOK" "$how"
  [ "$sd_gen" = "$((G0 + 1))" ] && pass "row 74 control: without the directory check the run installs through a state directory that $why" \
                                || fail "row 74 control: the directory check is visible ($how)" "gen=$sd_gen"
done
# a FIFO in place of the identity record is unreadable, never a hang
installed_box; rm -f "$IDF"; mkfifo "$IDF"
timeout 60 sh -c 'python3 -c "$1" gen "$2" "$3" "$4"' _ "$(sed -n '/^keyed_py() {$/,/^PY$/p' "$REFRESH" | sed '1,2d;$d')" "$D/tenant.bin" "$(date +%s)" "$IDF" > "$W/fifo.out" && frc=0 || frc=$?
{ [ "$frc" = 0 ] && grep -q ' restored$' "$W/fifo.out"; } && pass "row 74: a FIFO at tenant.plane-id reads as no record (restored) at once, never a hang" \
                                                       || fail "row 74: the FIFO record" "rc=$frc $(cat "$W/fifo.out")"
M=$(mutant fifo-open '    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("not a regular file")
        return f.read(n)' '    return open(path, "rb").read(n)')
timeout 60 sh -c 'python3 -c "$1" gen "$2" "$3" "$4"' _ "$(sed -n '/^keyed_py() {$/,/^PY$/p' "$M" | sed '1,2d;$d')" "$D/tenant.bin" "$(date +%s)" "$IDF" > /dev/null 2>&1 && frc=0 || frc=$?
rm -f "$IDF"
[ "$frc" = 124 ] && pass "row 74 control: a plain open of the record hangs on the FIFO (timeout 124 at the unplanted run's own 60 s ceiling)" \
                 || fail "row 74 control: the non-blocking read is visible" "rc=$frc"
# the record chain never takes the mark after a bare local loss (a mark below the true record)
installed_box; rm_plane "$D/tenant.bin"; set_state "$HWF" "$((G - 500))\n"; set_state "$RECF" "0\n"; rk --keyed-set
v=$(sent_val "$out" rec)
[ "$v" -ge "$(( $(date +%s) + 86000 ))" ] && pass "row 74: a malformed record, tenant.bin absent, no tombstone, the mark below the true record: the last resort, never the mark" \
                                          || fail "row 74: the record's mark end needs the tombstone" "v=$v"
M=$(mutant rec-mark-no-tomb '        if v is None and tomb_present and hst == "ok":' '        if v is None and hst == "ok":')
installed_box; rm_plane "$D/tenant.bin"; set_state "$HWF" "$((G - 500))\n"; set_state "$RECF" "0\n"; run_with "$M" --keyed-set
[ "$(sent_val "$out" rec)" = "$((G - 500))" ] && pass "row 74 control: a record chain reading the mark without the tombstone names the lower mark" \
                                              || fail "row 74 control: the tombstone condition is visible" "$out"
# a first-poll revocation, then 0 in the mark: the last resort
fresh_box; place_key; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; set_state "$HWF" "0\n"; cfg '{}'; rk --keyed-set
v=$(sent_val "$out" hw)
[ "$v" -ge "$(( $(date +%s) + 86000 ))" ] && pass "row 74: a first-poll revocation (tombstone '<epoch> 0'), then 0 in the mark: the sentence names the last resort" \
                                          || fail "row 74: the first-poll repair" "v=$v $out"
set_state "$HWF" "$v\n"; owner_home; rk --enroll --force; content a "$((v + 1))" "$REV0"; rk --keyed-set
[ "$(gen_of "$D/tenant.bin")" = "$((v + 1))" ] && pass "row 74: and --enroll followed by a served generation above it re-arms" || fail "row 74: re-arm after the first-poll repair" "$out"
# a record above the ceiling, then a revocation: refused, the mark unchanged
installed_box; set_state "$RECF" "9791772722\n"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
{ [ "$rc" != 0 ] && [ ! -e "$HWF" ] && [ -e "$D/tenant.bin" ] && says "$out" "$RECF is malformed"; } \
  && pass "row 74: tenant.installed holding 9791772722 beside a well-formed state, then a revocation: refused with the sentence, the mark unchanged" \
  || fail "row 74: the record band" "rc=$rc $out"
M=$(mutant trust-record '    if v > now + CEILING:
        return ("bad", "ceiling")' '    if False:
        return ("bad", "ceiling")')
installed_box; set_state "$RECF" "9791772722\n"; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; run_with "$M" --keyed-set
[ "$(cat "$HWF" 2>/dev/null)" = 9791772722 ] && pass "row 74 control: a max(...) that trusts a well-formed record above the ceiling writes 9,791,772,722" \
                                             || fail "row 74 control: the band is visible" "$(fileval "$HWF")"
# the tombstone is not load-bearing for the refresh
for tb in "1 $G\r\n" "1 9791772722\n"; do
  installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; cfg '{}'; set_state "$D/.tenant-tombstone" "$tb"
  owner_home; rk --enroll --force; content a "$((G + 1))" "$REV0"; rk --keyed-set
  { [ "$rc" = 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$((G + 1))" ] && [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = fresh ]; } \
    && pass "row 74: a revoked box whose tombstone reads '$(shape_label "$tb")': the keyed run proceeds, a generation above the mark installs, removes the tombstone, and reads fresh" \
    || fail "row 74: a garbled tombstone blocks nothing" "rc=$rc $out"
done
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; set_state "$D/.tenant-tombstone" "1 9791772722\n"; set_state "$HWF" "0\n"
cfg '{}'; rk --keyed-set
[ "$(sent_val "$out" hw)" = "$G" ] && pass "row 74: beside a mark of 0 the sentence skips a tombstone field above the ceiling and names tenant.installed's value" \
                                  || fail "row 74: the tombstone end is guarded" "$out"
M=$(mutant unguarded-tomb '        if m and int(m.group(2)) != 0 and int(m.group(2)) <= MAXV and int(m.group(2)) <= C:' '        if m and int(m.group(2)) != 0:')
run_with "$M" --keyed-set
[ "$(sent_val "$out" hw)" = 9791772722 ] && pass "row 74 control: an unguarded tombstone end names 9791772722" || fail "row 74 control: the tombstone guard is visible" "$out"
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; set_state "$D/.tenant-tombstone" "garbage\r\n"; owner_home; cfg '{}'; rk --unenroll
{ [ "$rc" = 0 ] && [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = null ]; } \
  && pass "row 74: --unenroll over a garbled tombstone completes, removes it and reads null" || fail "row 74: --unenroll over a garbled tombstone" "$out"
# a restored older tombstone: the tombstone end takes the greater of its G and the record
tomb_case() { # <both files malformed: yes|no> [script for the last run]
  installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; backup B1
  owner_home; cfg '{}'; rk --enroll --force; G2=$((G + 9)); content a "$G2" "$REV0"; rk --keyed-set; backup B2
  if [ "$1" = yes ]; then cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; else rk --unenroll; fi
  restore B1; set_state "$HWF" "0\n"; [ "$1" = yes ] && set_state "$RECF" "0\n"; cfg '{}'
  run_with "${2:-$REFRESH}" --keyed-set
}
tomb_case no
v=$(sent_val "$out" hw); set_state "$HWF" "$v\n"; restore B2
{ [ "$v" = "$G2" ] && [ "$(word)" = revoked ]; } \
  && pass "row 74: B1's older tombstone restored after --unenroll, the mark set to 0: the sentence names G2 (the greater of the tombstone's G1 and the record), and B2 restored reads revoked" \
  || fail "row 74: the restored older tombstone" "v=$v word=$(word)"
M=$(mutant tomb-first '                v, src = max(tg, rv), "the greater of the tombstone'"'"'s generation and tenant.installed"' '                v, src = tg, "the tombstone'"'"'s generation"')
tomb_case no "$M"
[ "$(sent_val "$out" hw)" = "$G" ] && pass "row 74 control: the tombstone-first wording names G1" || fail "row 74 control: the greater-of rule is visible" "$out"
tomb_case yes
v=$(sent_val "$out" hw)
set_state "$HWF" "$v\n"; rk --keyed-set; vr=$(sent_val "$out" rec); set_state "$RECF" "$vr\n"; restore B2
{ [ "$v" -ge "$(( $(date +%s) + 86000 ))" ] && [ "$vr" -ge "$(( $(date +%s) + 86000 ))" ] && [ "$(word)" = revoked ]; } \
  && pass "row 74: B1's tombstone restored beside both files malformed: the mark's repair skips the tombstone to the last resort, never G1, the record's too, and B2 restored reads revoked" \
  || fail "row 74: the tombstone end over an unreadable record" "v=$v vr=$vr word=$(word)"
M=$(mutant field-alone '        if v is None and tg is not None and rst in ("absent", "ok"):
            if rst == "absent":' '        if v is None and tg is not None:
            if rst != "ok":')
tomb_case yes "$M"
[ "$(sent_val "$out" hw)" = "$G" ] && pass "row 74 control: the field-alone wording for a present-but-malformed record names G1" \
                                  || fail "row 74 control: the unreadable-record skip is visible" "$out"
# a clock two days behind over files near true now: the clock line first, the value only on its condition
clock_case() { # <script>
  fresh_box; place_key; GN=$(( $(date +%s) - 1800 )); set_state "$HWF" "$GN\n"; set_state "$RECF" "$GN\n"
  echo $(( $(date +%s) - 172800 )) > "$W/clock"; run_with "$1" --quiet --keyed-set; rm -f "$W/clock"
}
clock_case "$REFRESH"
first=$(printf '%s\n' "$out" | head -1)
cond=$(printf '%s\n' "$out" | grep -n 'if this time is right, write' | head -1 | cut -d: -f1)
{ [ "$rc" != 0 ] && says "$first" "this box's UTC time is" && says "$first" timedatectl && [ "${cond:-0}" -gt 1 ] \
  && says "$out" 'If this clock is behind, fix it with timedatectl and run again, and change nothing: do not lower the files'; } \
  && pass "row 74: a clock two days behind refuses well-formed files near true now; the sentence leads with the box's UTC time and gives its value only on the condition that it is right" \
  || fail "row 74: the clock sentence" "$out"
rk --keyed-set
{ [ "$rc" = 0 ] && [ "$(cat "$HWF")" = "$GN" ] && [ "$(cat "$RECF")" = "$GN" ]; } \
  && pass "row 74: with the clock restored the next run accepts the files unchanged" || fail "row 74: the band follows the clock" "rc=$rc $out"
M=$(mutant no-clock-line '    lines = [P + "this box'"'"'s UTC time is %s (%d s since the epoch); check it with timedatectl." % (iso(now), now)]' '    lines = []')
clock_case "$M"
first=$(printf '%s\n' "$out" | head -1)
says "$first" "this box's UTC time is" && fail "row 74 control: a sentence with no clock line is caught" "$out" \
  || pass "row 74 control: a sentence that names a value with no clock line before it fails the clock arm"
# the reseed step for a mark above the ceiling: the value, then the three server commands in order
installed_box; set_state "$HWF" "9791772722\n"; rk --quiet --keyed-set
p1=$(printf '%s\n' "$out" | grep -n "write $((G - 1)) into it" | cut -d: -f1)
p2=$(printf '%s\n' "$out" | grep -n 'nginx -s reload, apachectl graceful, /usr/local/lsws/bin/lswsctrl restart' | cut -d: -f1)
readme="$HERE/../REFERENCE.md"
r1=$(grep -n 'write the value the sentence names' "$readme" | head -1 | cut -d: -f1)
r2=$(grep -n 'nginx -s reload`, then `apachectl graceful`, then `/usr/local/lsws/bin/lswsctrl restart`' "$readme" | head -1 | cut -d: -f1)
{ [ -n "$p1" ] && [ -n "$p2" ] && [ "$p1" -lt "$p2" ] && [ -n "$r1" ] && [ -n "$r2" ] && [ "$r1" -le "$r2" ]; } \
  && pass "row 74: a mark of 9791772722 beside tenant.bin at G: the journal's sentence names G - 1 and then the reload step with nginx -s reload, apachectl graceful and /usr/local/lsws/bin/lswsctrl restart, in that order, and the README gives the value first and the same commands after it" \
  || fail "row 74: the reseed step" "p1=$p1 p2=$p2 r1=$r1 r2=$r2 $out"
M=$(mutant no-reseed '        if hv == "ceiling":' '        if False:')
installed_box; set_state "$HWF" "9791772722\n"; run_with "$M" --quiet --keyed-set
says "$out" 'lswsctrl restart' && fail "row 74 control: the sentence that stops after G - 1 is caught" "" \
  || pass "row 74 control: a sentence that stops after G - 1 with no reload step fails the reseed arm"
# enrolment over a malformed mark prints the repair, not the promise
fresh_box; owner_home; set_state "$HWF" "0\n"; rk --enroll; o_en=$out; r_en=$rc
{ [ "$r_en" = 0 ] && [ -e "$E/key" ] && grep -q 'enable --now' "$W/systemctl.log" && says "$o_en" "$HWF is malformed" \
  && ! says "$o_en" 'by itself within 24 hours'; } \
  && pass "row 74: --enroll over a malformed mark prints the repair sentence in place of the re-arm promise, and still enrols (key written, timer enabled)" \
  || fail "row 74: enrolment over a malformed mark" "rc=$r_en $o_en"
rk --keyed-set; [ "$rc" != 0 ] && pass "row 74: and every keyed run after it exits non-zero" || fail "row 74: keyed runs fail over the malformed mark" "$out"
fresh_box; owner_home; set_state "$HWF" "$((G - 5))\n"; rk --enroll
says "$out" 'by itself within 24 hours 10 minutes plus one keyed poll' && pass "row 74: over a well-formed mark --enroll prints the re-arm promise" \
                                                                     || fail "row 74: the promise" "$out"
M=$(mutant enroll-no-validate '  if [ "$STATE_OK" = 0 ]; then
    repair_sentence
  elif [ "$HW_ST" = ok ]; then' '  if [ -e "$HWF" ]; then')
fresh_box; owner_home; set_state "$HWF" "0\n"; run_with "$M" --enroll
says "$out" 'by itself within 24 hours' && pass "row 74 control: an --enroll that does not validate prints the 24 h 10 min promise over a malformed file" \
                                        || fail "row 74 control: the validation is visible" "$out"
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; set_state "$HWF" "9791772722\n"; owner_home; cfg '{}'
rk --enroll --force; o_en=$out; content a "$((G + 1))" "$REV0"; rk --keyed-set
{ says "$o_en" "$HWF is malformed" && [ "$rc" != 0 ] && [ ! -e "$D/tenant.bin" ] && [ "$(word)" = revoked ]; } \
  && pass "row 74: a revoked box whose mark is then corrupted: --enroll prints the repair sentence, a generation above the mark is not installed, every run exits non-zero and the box stays revoked" \
  || fail "row 74: the re-arm freeze" "$o_en / $out $(word)"
# tenant.installed alone malformed beside a well-formed mark: no install on the 200 and the 304 run
installed_box; set_state "$RECF" "012\n"; content a "$((G + 1))" "$REV0"; rk --keyed-set; r1=$rc; content a "$G" "$REV0"; rk --keyed-set
{ [ "$r1" != 0 ] && [ "$rc" != 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G" ]; } \
  && pass "row 74: tenant.installed alone malformed: no install, a non-zero exit on the 200 and the 304 run" \
  || fail "row 74: the record alone" "$r1 $rc"
}

# ===================================================================================================
# Row 74c: the tombstone's lifecycle.
row74c() {
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set
t1=$(cat "$D/.tenant-tombstone" 2>/dev/null || true); m1=$(stat -c %a "$D/.tenant-tombstone" 2>/dev/null || true)
owner_home; cfg '{}'; rk --enroll --force; t2=$(cat "$D/.tenant-tombstone" 2>/dev/null || true)
content a "$((G0 + 1))" "$REV0"
XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-plane"; rk --keyed-set; XENV=""
mid=$(present "$D/.tenant-tombstone" kept); midg=$(gen_of "$D/tenant.bin")
rmdir "$D/.refresh.lock.d" 2>/dev/null || true
rk --keyed-set; [ "$rc" = 0 ] || true
rk --keyed-set
{ [ "$(printf '%s' "$t1" | grep -Ec "^[0-9]+ $G0\$")" = 1 ] && [ "$m1" = 444 ] && [ "$t2" = "$t1" ] && [ "$mid" = kept ] \
  && [ "$midg" = "$((G0 + 1))" ] && [ ! -e "$D/.tenant-tombstone" ]; } \
  && pass "row 74c: a revocation writes '<epoch> <G>' 0444; --enroll leaves it; the install of G + 1 removes it in the same locked step, after the rename (a kill between them leaves it, the next run clears it)" \
  || fail "row 74c: the tombstone's lifecycle" "t1=$t1 m1=$m1 t2=$t2 mid=$mid midg=$midg $out"
for tr in repin unenroll; do
  installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; cfg '{}'; owner_home
  XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=$tr:after-unlink"; rk "--$tr"; XENV=""
  k=$(present "$D/.tenant-tombstone" kept); rmdir "$D/.refresh.lock.d" 2>/dev/null || true
  rk "--$tr"
  { [ "$k" = kept ] && [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = null ]; } \
    && pass "row 74c: --$tr removes the tombstone last (a kill before that step leaves it) and reads null" \
    || fail "row 74c: --$tr and the tombstone" "k=$k $out"
done
M=$(mutant never-clears '  kkill install:after-plane
  rm -f "$TOMBF" || lk_fail "could not remove $TOMBF"' '  kkill install:after-plane
  :')
installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; owner_home; cfg '{}'; rk --enroll --force
content a "$((G0 + 1))" "$REV0"; run_with "$M" --keyed-set
[ -e "$D/.tenant-tombstone" ] && pass "row 74c control: a refresh that never clears the tombstone leaves it present after the re-arm" \
                              || fail "row 74c control: the clear is visible" "$out"
# a kill between the install's rename and its unlink leaves the tombstone over an armed plane; the next
# run finds the plane current and finishes the step
crash_rearm() { # <script for the rerun>
  installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; owner_home; cfg '{}'; rk --enroll --force
  content a "$((G0 + 1))" "$REV0"
  XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-plane"; rk --keyed-set; XENV=""
  [ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
  run_with "$1" --keyed-set
}
crash_rearm "$REFRESH"
[ ! -e "$D/.tenant-tombstone" ] && pass "row 74c: after a kill between the rename and the unlink, the next run finds the plane current and removes the tombstone" \
                                || fail "row 74c: the found-current repair" "$out"
M=$(mutant no-current-clear '    rm -f "$TOMBF" || lk_fail "could not remove $TOMBF"' '    :')
crash_rearm "$M"
[ -e "$D/.tenant-tombstone" ] && pass "row 74c control: without the found-current repair the tombstone stays over the armed plane" \
                              || fail "row 74c control: the found-current repair is visible" "$out"
}

# ===================================================================================================
# Row env: --enroll and key.revoke read the front door's envelope as it is written: the outer row an
# object keyed by column (the front door's result writer; the CLI's DecodeEnvelope reads the same), the inner result
# rows positional. The fake feed emits that grammar, and two envelopes captured from the live front
# door (testdata/envelopes/) are fed to the reader as they are.
rowenv() {
EV="$HERE/testdata/envelopes"
a=$(kpyx envelope "$EV/front-door-refusal.200.json" 200 "$W/never.key"); b=$(kpyx envelope "$EV/front-door-unknown-op.400.json" 400 "$W/never.key")
c=$(kpyx revoked "$EV/front-door-refusal.200.json" 200 ag_x)
{ case "$a" in "REFUSED FORBIDDEN_SCOPE "*) true ;; *) false ;; esac; } && [ "$b" = UNKNOWN_OP ] \
  && { case "$c" in "REFUSED FORBIDDEN_SCOPE "*) true ;; *) false ;; esac; } && [ ! -e "$W/never.key" ] \
  && pass "row env: a captured live refusal reads as a refusal with its code (FORBIDDEN_SCOPE) for the mint and for key.revoke, and a captured 400 as unknown_op" \
  || fail "row env: the captured envelopes" "$a / $b / $c"
ZIP=$(mutant zip-only '        return row_of(j["columns"], j["rows"][0])' '        return dict(zip(j["columns"], j["rows"][0]))')
a=$(KPY_SCRIPT=$ZIP kpyx envelope "$EV/front-door-refusal.200.json" 200 "$W/never.key")
case "$a" in "ERROR error"*) true ;; *) false ;; esac && pass "row env control: a zip-only reader reads the live refusal as 'ERROR error'" \
                         || fail "row env control: the zip reader is caught" "$a"
# the third shape the CLI reads: a top-level ok with the payload in the outer row
python3 - "$W/top-ok.json" "$W/top-refused.json" <<'PY'
import json, sys
cols = ["op", "ok", "status", "result", "error", "retry_after", "elapsed_ms"]
res = {"columns": ["id", "api_key", "label", "created_at", "scopes", "use"],
       "rows": [["ag_topLevelOkAAAAAA", "whisper_live_" + "A" * 32, "-", "-", "-", "-"]], "sensitive": ["api_key"]}
json.dump({"ok": True, "columns": cols, "rows": [dict(zip(cols, ["edge", True, 200, res, None, None, 1]))]}, open(sys.argv[1], "w"))
json.dump({"ok": False, "error": {"code": "EDGE_KEY_LIMIT", "message": "ten keys at most", "retryable": False}, "columns": cols,
           "rows": [dict(zip(cols, ["edge", False, 409, None, None, None, 1]))]}, open(sys.argv[2], "w"))
PY
rm -f "$W/top.key"; a=$(kpyx envelope "$W/top-ok.json" 200 "$W/top.key"); b=$(kpyx envelope "$W/top-refused.json" 200 "$W/never.key")
{ [ "$a" = "MINTED ag_topLevelOkAAAAAA" ] && [ -s "$W/top.key" ] && [ "$b" = "REFUSED EDGE_KEY_LIMIT ten keys at most" ]; } \
  && pass "row env: a top-level ok with the payload in the outer row reads as a mint, and a top-level ok:false as a refusal with its code" \
  || fail "row env: the top-level ok shape" "$a / $b"
TOP=$(mutant no-top-merge '        if not isinstance(j.get("result"), dict) and isinstance(j.get("columns"), list) and j.get("rows"):' '        if False:')
rm -f "$W/top.key"; a=$(KPY_SCRIPT=$TOP kpyx envelope "$W/top-ok.json" 200 "$W/top.key")
[ "$a" = LOST ] && pass "row env control: a reader that takes the top-level object as the envelope cannot read that mint (LOST)" \
                || fail "row env control: the top-level merge is visible" "$a"
fresh_box; owner_home; rk --enroll
{ [ "$rc" = 0 ] && [ -e "$E/key" ]; } && pass "row env: a mint answered in the front door's object-row grammar writes the key" \
                                    || fail "row env: the object-row mint" "$out"
fresh_box; owner_home; run_with "$ZIP" --enroll
{ [ ! -e "$E/key" ] && says "$out" 'the mint may have succeeded; key.list shows it'; } \
  && pass "row env control: the zip-only reader cannot read that mint, writes nothing, and says the mint may have succeeded" \
  || fail "row env control: the zip reader against the object-row mint" "$out"
fresh_box; owner_home; cfg "{'positional_rows': True}"; rk --enroll
[ -e "$E/key" ] && pass "row env: the positional outer row, the other shape the CLI accepts, is read by name too" \
                || fail "row env: the positional mint" "$out"
for mode in not_yet owner_only; do
  fresh_box; owner_home; cfg "{'control': {'*': '$mode'}}"; rk --enroll
  case "$mode" in not_yet) want="not available on this node yet"; wrc=0 ;; *) want="this is an agent's key"; wrc=1 ;; esac
  { [ "$rc" = "$wrc" ] && says "$out" "$want" && [ ! -e "$E/key" ]; } \
    && pass "row env: an inner $mode in the object-row grammar reads as itself" || fail "row env: $mode" "$out"
done
# key.revoke in the object-row grammar: --unenroll revokes the minted key on the server
fresh_box; owner_home; rk --enroll; kid=$(cat "$E/key.id"); rk --unenroll
st=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(s["keys"][s["minted"][sys.argv[2]]])' "$F/state.json" "$kid")
{ [ "$st" = KEY_REVOKED ] && says "$out" "feed key $kid revoked"; } \
  && pass "row env: --unenroll's key.revoke is read in the object-row grammar and the key is revoked on the server" \
  || fail "row env: key.revoke" "$st $out"
# a typed refusal is a refusal: the live FORBIDDEN_SCOPE capture, served for the mint, says nothing was
# minted and never that the mint may have succeeded; a lost answer keeps that alarm (row 55's drop)
refused_mint() { # <script>
  fresh_box; owner_home; cfg "{'capture': 'front-door-refusal.200.json'}"; run_with "$1" --enroll; cfg '{}'
}
refused_mint "$REFRESH"
{ [ "$rc" = 1 ] && [ ! -e "$E/key" ] && says "$out" 'the control plane refused the mint (FORBIDDEN_SCOPE: Missing required scope: dns:zone:read); nothing was minted' \
  && ! says "$out" 'may have succeeded'; } \
  && pass "row env: the live FORBIDDEN_SCOPE capture, answered to --enroll, is reported as a refusal with its code (exit 1), writes nothing, and never says the mint may have succeeded" \
  || fail "row env: a typed refusal of the mint" "rc=$rc $out"
M=$(mutant refusal-as-error '        return out("REFUSED", code, re.sub(r"\s+", " ", msg)[:400])' '        return out("ERROR", code, re.sub(r"\s+", " ", msg)[:400])')
refused_mint "$M"
{ [ ! -e "$E/key" ] && says "$out" 'the mint may have succeeded'; } \
  && pass "row env control: a reader that maps the typed refusal to ERROR tells the operator the mint may have succeeded" \
  || fail "row env control: the refusal mapping is visible" "$out"
# a refusal is only what the front door says is final (ok false, retryable false, inner status 4xx):
# INTERNAL (500, retryable) and MALFORMED_RESULT (500, built after dispatch committed) may have minted a
# key nobody holds, so they keep the key.list alarm; both are built in the live capture's grammar
OLDRULE=$(mutant every-code-refuses '    if final_refusal(env) and code not in ("-", ""):' '    if env.get("ok") is False and code not in ("-", ""):')
for cap in built-internal.200.json built-malformed-result.200.json; do
  fresh_box; owner_home; cfg "{'capture': '$cap'}"; rk --enroll; cfg '{}'
  { [ "$rc" != 0 ] && [ ! -e "$E/key" ] && says "$out" 'the mint may have succeeded; key.list shows it' && ! says "$out" 'nothing was minted'; } \
    && pass "row env: an ok:false $(echo "$cap" | cut -d. -f1 | sed 's/^built-//') answer to --enroll keeps the key.list alarm and writes nothing" \
    || fail "row env: an ambiguous server fault ($cap)" "rc=$rc $out"
  fresh_box; owner_home; cfg "{'capture': '$cap'}"; run_with "$OLDRULE" --enroll; cfg '{}'
  says "$out" 'nothing was minted' && pass "row env control: a rule that reads every ok:false code as a refusal reports $(echo "$cap" | cut -d. -f1 | sed 's/^built-//') as a refusal, nothing minted" \
                                   || fail "row env control: the finality rule is visible ($cap)" "$out"
done
# a typed 4xx the front door answers before any dispatch is a refusal, not a possible mint
NOPD=$(mutant no-pre-dispatch '    pd = pre_dispatch(path, status)' '    pd = None')
for cap in built-bad-request.400.json built-rate-limited.429.json built-inner-rate-limited.200.json; do
  fresh_box; owner_home; cfg "{'capture': '$cap'}"; rk --enroll; cfg '{}'
  code_=$(echo "$cap" | sed 's/^built-//; s/^inner-//; s/\..*//; s/-/_/g')
  lab_=$(echo "$cap" | cut -d. -f2)
  [ "$cap" = built-inner-rate-limited.200.json ] && { code_=RATE_LIMITED; lab_="inner 429 in an HTTP 200"; }
  { [ "$rc" = 1 ] && [ ! -e "$E/key" ] && says "$out" "refused the mint ($code_: " && ! says "$out" 'may have succeeded'; } \
    && pass "row env: a pre-dispatch $code_ ($lab_) is reported as a refusal, exit 1, never the key.list alarm" \
    || fail "row env: a pre-dispatch refusal ($cap)" "rc=$rc $out"
  if [ "$cap" = built-inner-rate-limited.200.json ]; then
    M=$(mutant no-inner-shed '    if e.get("code") == "RATE_LIMITED" and st == 429:
        return True' '    if False:
        return True')
    fresh_box; owner_home; cfg "{'capture': '$cap'}"; run_with "$M" --enroll; cfg '{}'
    says "$out" 'may have succeeded' && pass "row env control: without the shed rule the inner 429 RATE_LIMITED (retryable) raises the key.list alarm" \
                                     || fail "row env control: the shed rule is visible" "$out"
    continue
  fi
  fresh_box; owner_home; cfg "{'capture': '$cap'}"; run_with "$NOPD" --enroll; cfg '{}'
  says "$out" 'may have succeeded' && pass "row env control: without the pre-dispatch reading, $code_ raises the key.list alarm" \
                                   || fail "row env control: the pre-dispatch reading is visible ($cap)" "$out"
done
# the front door refusing the key itself (401, 403, no typed body) is a refusal before any dispatch
for st_ in 401 403; do
  fresh_box; owner_home; cfg "{'control': {'*': 'http$st_'}}"; rk --enroll; cfg '{}'
  { [ "$rc" = 1 ] && [ ! -e "$E/key" ] && says "$out" "refused the mint (HTTP_$st_: the front door refused the key)" && ! says "$out" 'may have succeeded'; } \
    && pass "row env: an HTTP $st_ to --enroll is a refusal (HTTP_$st_), exit 1, never the key.list alarm" \
    || fail "row env: an HTTP $st_ refusal" "rc=$rc $out"
done
M=$(mutant no-http-refusal '    if status in ("401", "403"):' '    if False:')
fresh_box; owner_home; cfg "{'control': {'*': 'http401'}}"; run_with "$M" --enroll; cfg '{}'
says "$out" 'may have succeeded' && pass "row env control: without the 401/403 branch an HTTP 401 raises the key.list alarm" \
                                 || fail "row env control: the 401/403 branch is visible" "$out"
# a refusal with no message prints its code alone
fresh_box; owner_home; cfg "{'capture': 'built-no-message.200.json'}"; rk --enroll; cfg '{}'
{ says "$out" 'refused the mint (FORBIDDEN_SCOPE); nothing was minted' && ! says "$out" 'FORBIDDEN_SCOPE: )'; } \
  && pass "row env: a final refusal with no message prints '(FORBIDDEN_SCOPE)', no dangling colon" \
  || fail "row env: the code-only refusal" "$out"
M=$(mutant code-colon '      _r=${_verdict#REFUSED }; _c=${_r%% *}; _m=${_r#"$_c"}; _m=${_m# }
      die "the control plane refused the mint ($_c${_m:+: $_m}); nothing was minted and nothing written" ;;' '      _r=${_verdict#REFUSED }
      die "the control plane refused the mint (${_r%% *}: ${_r#* }); nothing was minted and nothing written" ;;')
fresh_box; owner_home; cfg "{'capture': 'built-no-message.200.json'}"; run_with "$M" --enroll; cfg '{}'
says "$out" '(FORBIDDEN_SCOPE: )' && pass "row env control: printing the code without its detail leaves '(FORBIDDEN_SCOPE: )'" \
                                              || fail "row env control: the printing is visible" "$out"
# a TLS failure (curl 35, 60) happens before any request is sent; a timeout (28) does not
for ce in 35 60 28; do
  fresh_box; owner_home; echo "$ce" > "$W/curl.exit"; rk --enroll; rm -f "$W/curl.exit"
  case $ce in
    28) { [ "$rc" != 0 ] && says "$out" 'may have succeeded'; } \
          && pass "row env: curl 28 (a timeout) keeps the key.list alarm" || fail "row env: curl 28" "$out" ;;
    *)  { [ "$rc" != 0 ] && says "$out" "could not reach .* (curl $ce); nothing was minted" && ! says "$out" 'may have succeeded'; } \
          && pass "row env: curl $ce (a TLS failure) is 'could not reach', nothing minted, no alarm" || fail "row env: curl $ce" "$out" ;;
  esac
done
M=$(mutant tls-alarm '      6|7|35|60) die' '      6|7) die')
fresh_box; owner_home; echo 60 > "$W/curl.exit"; run_with "$M" --enroll; rm -f "$W/curl.exit"
says "$out" 'may have succeeded' && pass "row env control: with only 6 and 7 as 'could not reach', curl 60 raises the alarm" \
                                 || fail "row env control: the TLS codes are visible" "$out"
# the fake checks what the front door checks before dispatch: the one Cypher call and op "edge"
M=$(mutant wrong-body '    print(json.dumps({"query": "CALL whisper.agents($p)", "parameters": {"p": {"op": "edge", "args": args}}}))' '    print(json.dumps({"query": "RETURN 1", "parameters": {"p": {"op": "egde", "args": args}}}))')
fresh_box; owner_home; run_with "$M" --enroll
{ [ "$rc" != 0 ] && [ ! -e "$E/key" ]; } && pass "row env control: a body with query 'RETURN 1' and op 'egde' does not enrol against the fake, as the front door would refuse it" \
                                       || fail "row env control: the fake checks the request body" "rc=$rc $out"
M=$(mutant wrong-op '    print(json.dumps({"query": "CALL whisper.agents($p)", "parameters": {"p": {"op": "edge", "args": args}}}))' '    print(json.dumps({"query": "CALL whisper.agents($p)", "parameters": {"p": {"op": "egde", "args": args}}}))')
fresh_box; owner_home; run_with "$M" --enroll
{ [ ! -e "$E/key" ] && says "$out" 'not available on this node yet'; } \
  && pass "row env control: the right query with op 'egde' reads as unknown_op and writes nothing" || fail "row env control: the op check" "rc=$rc $out"
# key.revoke's answer counts only when it names this key in state revoked: an ok row naming another id,
# or this id still live, leaves the by-hand sentence and never "revoked"
for mode in revoke_other_id revoke_live; do
  fresh_box; owner_home; rk --enroll; kid=$(cat "$E/key.id"); cfg "{'control': {'*': '$mode'}}"; rk --unenroll; cfg '{}'
  { ! says "$out" "feed key $kid revoked" && says "$out" "revoke feed key $kid by hand"; } \
    && pass "row env: key.revoke answered ok with $(case $mode in revoke_other_id) echo 'another id' ;; *) echo 'this id still live' ;; esac): --unenroll names the by-hand revoke and never says revoked" \
    || fail "row env: key.revoke's id and state check ($mode)" "$out"
done
M=$(mutant revoke-any-ok '        if d.get("id") == kid and d.get("state") == "revoked":' '        if True:')
fresh_box; owner_home; rk --enroll; kid=$(cat "$E/key.id"); cfg "{'control': {'*': 'revoke_live'}}"; run_with "$M" --unenroll; cfg '{}'
says "$out" "feed key $kid revoked" && pass "row env control: a reader that takes any ok row reports a live key as revoked" \
                                   || fail "row env control: the id and state check is visible" "$out"
}

# ===================================================================================================
# Row scrub: a real capture of the keyed path passes capture-scrub.sh; the same capture with the key in
# it does not.
rowscrub() {
SCRUB="$HERE/capture-scrub.sh"
fresh_box; owner_home; content a "$G0" "$REV0"; rk --enroll; cap1=$out
cp "$E/key" "$W/feedkey.copy"; rk --keyed-set; cap2=$out; rk --unenroll; cap3=$out
{ printf '%s\n%s\n%s\n' "$cap1" "$cap2" "$cap3"
  echo "Starting whisper-edge-refresh-keyed.service"; cat "$W/systemctl.log"; cat "$F/requests.log"; cat "$W/curl.argv"; } > "$W/capture"
"$SCRUB" --key-file "$W/home/.config/whisper/key" --key-file "$W/feedkey.copy" "$W/capture" > "$W/scrub.out" && src=0 || src=$?
{ cat "$W/capture"; grep -h . "$W/feedkey.copy"; } > "$W/capture.bad"
"$SCRUB" --key-file "$W/home/.config/whisper/key" --key-file "$W/feedkey.copy" "$W/capture.bad" > /dev/null && brc=0 || brc=$?
{ [ "$src" = 0 ] && [ "$brc" = 1 ]; } \
  && pass "row scrub: a capture of --enroll, --keyed-set and --unenroll against the fake (output, requests, argv, the unit's name) is CLEAR; with the feed key in it, REFUSED" \
  || fail "row scrub: capture-scrub on a real capture" "clean=$src bad=$brc $(cat "$W/scrub.out")"
}

# ===================================================================================================
# Row 77: the CLI key file is read one safe way, or not at all, and a refusal makes no request.
row77() {
refused_with() { # <label> <rule text>
  { [ "$rc" != 0 ] && says "$out" "$2" && [ "$(nreq method=POST)" = 0 ] && [ ! -e "$E/key" ]; } \
    && pass "row 77: $1 is refused naming the rule, with zero requests" \
    || fail "row 77: $1" "rc=$rc $out"
}
K="$W/sudohome/.config/whisper/key"
fresh_box; sudo_home; printf '%s\n' "$OWNERKEY" > "$W/elsewhere"; rm -f "$K"; ln -s "$W/elsewhere" "$K"
enrol_env; rk --enroll; XENV=""; refused_with "a symlinked CLI key file" "is a symbolic link"
fresh_box; sudo_home; chmod 0770 "$W/sudohome/.config/whisper"
enrol_env; rk --enroll; XENV=""; refused_with "a key in a group-writable directory" "writable by others"
fresh_box; sudo_home; rm -f "$K"; printf 'not a key\n' > "$K"; chmod 0600 "$K"
enrol_env; rk --enroll; XENV=""; refused_with "a file failing the shape check" "does not hold a key"
if sudo -n true 2>/dev/null; then
  # another user than the one running the gate: root's key is the invoking user's own when the gate runs as root
  other=0; [ "$(id -u)" = 0 ] && other=65534
  fresh_box; sudo_home; sudo -n chown "$other:$other" "$K"; sudo -n chmod 0644 "$K"
  enrol_env; rk --enroll; XENV=""; refused_with "a key file owned by another user" "is owned by another user"
  sudo -n rm -f "$K"
else
  SKIPPED="${SKIPPED}row 77's other-owner arm (needs passwordless sudo to chown); "
fi
swap_case() { # <script>
  fresh_box; sudo_home; printf '%s\n' "$(newkey)" > "$W/elsewhere"
  arm enroll-open
  env PATH="$S:$PATH" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_BASE="$BASE" \
    WHISPER_EDGE_TEST_LOOPBACK=1 WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" \
    WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$W/hooks" CURL_CA_BUNDLE="$W/ca.pem" TMPDIR="$W/tmp" HOME="$W/home" \
    SUDO_USER="$(id -un)" WHISPER_EDGE_TEST_SUDO_HOME="$W/sudohome" "$1" --enroll > "$W/swap" 2>&1 &
  BG=$!
  reached enroll-open || fail "row 77: the swap hook" "$(cat "$W/swap")"
  rm -f "$K"; ln -s "$W/elsewhere" "$K"
  go enroll-open; wait "$BG" && rc=0 || rc=$?; disarm enroll-open; out=$(cat "$W/swap")
}
swap_case "$REFRESH"; refused_with "a key file swapped for a symlink between open and read" "changed while it was being read"
M=$(mutant test-then-cat '        hook("enroll-open")
        data = f.read(4097)
        try:
            now = os.lstat(path)
        except OSError:
            now = None
        if now is None or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
            return (None, "changed while it was being read")' '        hook("enroll-open")
        data = open(path, "rb").read(4097)')
swap_case "$M"
[ "$(nreq method=POST)" -ge 1 ] && pass "row 77 control: a reader that opens the path again after its checks (test, then cat) reads the swapped file and sends it" \
                                || fail "row 77 control: the descriptor read is what refuses it" "$out"
}

# ===================================================================================================
# Row 86: a lost mint response is never retried blind.
row86() {
lost() { fresh_box; owner_home; cfg "{'control': {'*': 'drop'}}"; run_with "$1" --enroll; minted=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("minted", {})))' "$F/state.json"); }
lost "$REFRESH"
{ [ "$rc" != 0 ] && says "$out" 'the mint may have succeeded; key.list shows it; revoke any key you do not use' \
  && [ ! -e "$E/key" ] && [ "$(nreq method=POST sub=key)" = 1 ] && [ "$minted" = 1 ]; } \
  && pass "row 86: a mint whose response is lost makes no second mint, writes no key, prints the key.list sentence and exits non-zero; key.list shows the one orphan" \
  || fail "row 86: the lost mint" "rc=$rc minted=$minted $out"
M=$(mutant blind-retry '      *) kalarm "the mint may have succeeded; key.list shows it; revoke any key you do not use"
         die "no answer from $CONTROL_URL at $_a (curl $CRC); nothing was written" ;;' '      *) continue ;;')
lost "$M"
[ "$minted" = 2 ] && pass "row 86 control: a blind retry leaves two live keys" || fail "row 86 control: the retry is visible" "minted=$minted"
}

# ===================================================================================================
# Row 95: the content revision never goes back on the edge.
row95() {
rev_case() { installed_box; content a "$((G0 + 5))" "$((REV0 - 1))"; run_with "$1" --quiet --keyed-set; }
rev_case "$REFRESH"
{ [ "$rc" = 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] && says "$out" "revision $((REV0 - 1)) below $REV0"; } \
  && pass "row 95: after installing rev R, a higher generation carrying rev R - 1 is refused with the alarm and the plane kept" \
  || fail "row 95: the rev guard" "rc=$rc $out"
M=$(mutant no-rev '    if [ "$REV_ST" = ok ] && [ "$prev" -lt "$REV0" ]; then' '    if false; then')
rev_case "$M"
[ "$(gen_of "$D/tenant.bin")" = "$((G0 + 5))" ] && pass "row 95 control: without the rev guard the older lists install" \
                                                || fail "row 95 control: the rev guard is visible" "$out"
installed_box; set_state "$D/.tenant-rev" "010\n"; content a "$((G0 + 5))" "$REV0"; rk --keyed-set
{ [ "$rc" != 0 ] && says "$out" ".tenant-rev does not hold one content revision" && [ "$(gen_of "$D/tenant.bin")" = "$G0" ]; } \
  && pass "row 95: a malformed .tenant-rev refuses the install with an alarm naming the file and keeps the plane" \
  || fail "row 95: the .tenant-rev grammar" "rc=$rc $out"
fresh_box; place_key; content a "$G0" "$REV0" "$TENANT_A" --names ",tenant:$TENANT_A,rev:0$REV0"; rk --keyed-set
{ [ "$rc" != 0 ] && [ ! -e "$D/tenant.bin" ] && says "$out" "not the manifest's rev:$REV0"; } \
  && pass "row 95: a plane whose feed-name table carries rev:0<R> against the manifest's rev R is refused (the table is parsed in python3, never as octal)" \
  || fail "row 95: the table check" "$out"
for badopt in "--names ,tenant:$TENANT_B,rev:$REV0" "--names ,tenant:$TENANT_A" "--source 2"; do
  fresh_box; place_key
  # shellcheck disable=SC2086
  content a "$G0" "$REV0" "$TENANT_A" $badopt; rk --keyed-set
  { [ "$rc" != 0 ] && [ ! -e "$D/tenant.bin" ]; } && pass "row 95: a plane with $badopt is refused before install" \
                                                 || fail "row 95: the table check ($badopt)" "$out"
done
}

# ===================================================================================================
# Row 96: credentials go only over https to the canonical host.
row96() {
HP=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
cat > "$W/hdrlog.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[2], "a") as f:
            f.write("%s auth=%s xkey=%s\n" % (self.path, "Authorization" in self.headers, "X-API-Key" in self.headers))
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$W/hdrlog.py" "$HP" "$W/hdr.log" & echo $! > "$W/srv.hdr.pid"
i=0; while ! "$REAL_CURL" -s -o /dev/null "http://127.0.0.1:$HP/" 2>/dev/null && [ "$i" -lt 50 ]; do i=$((i+1)); sleep 0.1; done
: > "$W/hdr.log"
installed_box; rm -f "$F/requests.log"
for lb in 1 0; do
  XENV="WHISPER_EDGE_TEST_LOOPBACK=$lb"; rk --keyed-set --base "http://127.0.0.1:$HP/edge"; o_http=$out
  rk --plane tor --base "http://127.0.0.1:$HP/edge"; XENV=""
  n=$(printf '%s\n' "$o_http" | grep -c 'the key is sent only to https://whisper.online; this base gets keyless requests')
  { [ "$n" = 1 ] && ! grep -q 'auth=True\|xkey=True' "$W/hdr.log"; } \
    && pass "row 96: a base on a plain-http listener (test loopback $lb) gets no Authorization and no X-API-Key, keyed or keyless, and the run says so once" \
    || fail "row 96: no credential over http" "n=$n $(cat "$W/hdr.log") $o_http"
done
XENV="WHISPER_EDGE_TEST_LOOPBACK=0"; rk --keyed-set; XENV=""
{ [ "$(nreq)" = 0 ] && says "$out" 'the key is sent only to https://whisper.online'; } \
  && pass "row 96: an https base on a host other than whisper.online (the loopback mode unset) gets no request carrying the key" \
  || fail "row 96: no credential to a non-canonical https host" "$out"
M=$(mutant no-cred-check '  if [ "$UP_HOST" = whisper.online ] && [ "$CRED_PORT" = 443 ]; then return 0; fi' '  return 0')
XENV="WHISPER_EDGE_TEST_LOOPBACK=0"; run_with "$M" --keyed-set; XENV=""
[ "$(nreq auth=bearer known_key=True)" -ge 1 ] && pass "row 96 control: the script without the check sends the feed key to the non-canonical listener" \
                                                || fail "row 96 control: the check is visible" "$out"
installed_box; rk --keyed-set; owner_home; rk --unenroll
bad_argv=$(grep -E '/edge/k/|/api/query' "$W/curl.argv" | grep -v -- '--proto =https --proto-redir =https' | head -1)
lflag=$(grep -E '/edge/k/|/api/query' "$W/curl.argv" | grep -c -- ' -L ' || true)
{ [ -z "$bad_argv" ] && [ "$lflag" = 0 ] && [ "$(grep -cE '/edge/k/|/api/query' "$W/curl.argv")" -ge 2 ]; } \
  && pass "row 96: every credential-carrying curl has --proto =https --proto-redir =https and no -L" \
  || fail "row 96: the credential curl flags" "$bad_argv"
fresh_box; owner_home; echo 127.0.0.3 > "$W/addrs.graph.whisper.online"
XENV="WHISPER_EDGE_CONTROL_URL=https://localhost:$PORT/api/query"; rk --enroll; XENV=""
rm -f "$W/addrs.graph.whisper.online"
{ grep -q 'https://graph.whisper.online/api/query' "$W/curl.argv" && [ "$(nreq method=POST)" = 0 ] && [ ! -e "$E/key" ]; } \
  && pass "row 96: --enroll sends the owner key only to https://graph.whisper.online/api/query: a control URL that is not a loopback address is ignored" \
  || fail "row 96: the owner key's destination" "$out"
ctl_case() { # <script>: the loopback mode unset, a loopback control URL
  fresh_box; owner_home; echo 127.0.0.3 > "$W/addrs.graph.whisper.online"
  XENV="WHISPER_EDGE_TEST_LOOPBACK=0"; run_with "$1" --enroll; XENV=""
  rm -f "$W/addrs.graph.whisper.online"
}
ctl_case "$REFRESH"
{ [ "$(nreq method=POST)" = 0 ] && [ ! -e "$E/key" ]; } \
  && pass "row 96: with the loopback mode unset, a loopback control URL is ignored and the owner key goes to no listener but the canonical host" \
  || fail "row 96: the control URL needs the loopback mode" "$out"
M=$(mutant ctl-no-mode 'if [ "${WHISPER_EDGE_TEST_LOOPBACK:-}" = 1 ] && [ "$UP_SCHEME" = https ] && is_loopback "$UP_HOST"; then' 'if [ "$UP_SCHEME" = https ] && is_loopback "$UP_HOST"; then')
ctl_case "$M"
[ "$(nreq method=POST known_key=True)" -ge 1 ] && pass "row 96 control: honouring the control URL without the loopback mode sends the owner key to the loopback listener" \
                                               || fail "row 96 control: the mode check is visible" "$out"
}

# ===================================================================================================
# Row 105: the keyed path on a host with jq and no python3.
row105() {
NP="$W/nopy"; rm -rf "$NP"; mkdir -p "$NP"
for d in /usr/local/bin /usr/bin /bin; do
  for c in "$d"/*; do
    b=$(basename "$c"); case "$b" in python*) continue ;; esac
    [ -e "$NP/$b" ] || ln -s "$c" "$NP/$b"
  done
done
for c in getent date curl systemctl; do rm -f "$NP/$c"; ln -s "$S/$c" "$NP/$c"; done
rm -f "$NP/cat"   # a symlink to the real cat: never write through it
cat > "$NP/cat" <<EOF
#!/bin/sh
echo "\$*" >> "$W/cat.log"
exec /bin/cat "\$@"
EOF
chmod 0755 "$NP/cat"
nopy() { _s=$1; shift; rc=0
  out=$(env PATH="$NP" WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DIR="$D" WHISPER_EDGE_TEST_LOOPBACK=1 \
    WHISPER_EDGE_CONTROL_URL="$CTL" WHISPER_EDGE_SYSTEMCTL="$S/systemctl" CURL_CA_BUNDLE="$W/ca.pem" \
    TMPDIR="$W/tmp" HOME="$W/home" "$_s" "$@" 2>&1) || rc=$?; }
keyless_stub; fresh_box; owner_home; rm -f "$W/cat.log"
env PATH="$NP" WHISPER_EDGE_RESOLVE="edge.keyless.invalid:$KPORT:127.0.0.1" WHISPER_EDGE_DIR="$D" "$REFRESH" --plane tor \
  --base "http://edge.keyless.invalid:$KPORT/edge" > "$W/np.tor" 2>&1 && tr=0 || tr=$?
nopy "$REFRESH" --enroll
{ [ "$tr" = 0 ] && [ -f "$D/tor.bin" ] && [ "$rc" = 0 ] \
  && says "$out" 'keyed enrolment needs python3; this box stays on the keyless planes' && [ "$(nreq)" = 0 ] \
  && ! grep -q '.config/whisper/key' "$W/cat.log" 2>/dev/null; } \
  && pass "row 105: with jq and no python3 the keyless --plane still installs; --enroll prints the python3 sentence, makes no request, never reads the key file and exits 0" \
  || fail "row 105: the jq-only host" "tor=$tr rc=$rc $out $(cat "$W/np.tor")"
nopy "$HERE/install.sh" --dry-run --dir "$D" --base "http://edge.keyless.invalid:$KPORT/edge"
{ says "$out" 'keyed enrolment needs python3; this box stays on the keyless planes' && ! grep -q '.config/whisper/key' "$W/cat.log" 2>/dev/null; } \
  && pass "row 105: install.sh's enrolment says the same and reads no key file" \
  || fail "row 105: install.sh on a jq-only host" "$out"
M=$(mutant shell-read 'need_python() {
  command -v python3 >/dev/null 2>&1 && return 0' 'need_python() {
  command -v python3 >/dev/null 2>&1 && return 0
  cat "$HOME/.config/whisper/key" > /dev/null')
rm -f "$W/cat.log"; nopy "$M" --enroll
grep -q '.config/whisper/key' "$W/cat.log" 2>/dev/null \
  && pass "row 105 control: a script that falls back to a shell read of the key file reads it (the cat shim records it)" \
  || fail "row 105 control: the cat shim sees a shell read" "$out"
}

# ===================================================================================================
# Row 74b: the REVOKED predicate, the script half (tenant-state-case.sh). The module half runs with the
# web-server module over the same fixtures.
row74b() {
TD="$W/tsc"; TS="$TD/state"
tfix() { rm -rf "$TD"; mkdir -p "$TS"; }
tplane() { # <generation> [maker options]
  _g=$1; shift
  python3 "$HERE/testdata/make-tenant-plane.py" "$TD/tenant.bin" --gen "$_g" --tenant "$TENANT_A" --rev "$REV0" \
    --deny 2a04:2a01::1234/128 "$@"
}
tw() { "${TSCX:-$TSC}" --dir "$TD" --state "$TS" --plane-check "$PLANE_CHECK" 2>/dev/null | tail -1; }
G=$G0
tfix; tplane "$((G + 1))"; printf '%s\n' "$G" > "$TS/tenant.high-water"
[ "$(tw)" = fresh ] && pass "row 74b: re-armed at G + 1 above the mark, tombstone cleared: fresh" || fail "row 74b: re-armed" "$(tw)"
printf '1 %s\n' "$G" > "$TD/.tenant-tombstone"
[ "$(tw)" = fresh ] && pass "row 74b: re-armed at G + 1 with a tombstone a crash left: fresh (the armed clause comes first)" \
                    || fail "row 74b: armed before tombstone" "$(tw)"
sed 's/^WORD=null$/WORD=null; [ "$TOMB_ST" = present ] \&\& WORD=revoked \&\& LOADER=x/' "$TSC" > "$W/tsc-tombfirst"; chmod 0755 "$W/tsc-tombfirst"
[ "$(TSCX="$W/tsc-tombfirst" tw)" = revoked ] && pass "row 74b control: checking the tombstone before the plane derives revoked for the re-armed case" \
                                              || fail "row 74b control: the precedence is visible" "$(TSCX="$W/tsc-tombfirst" tw)"
tfix; tplane "$G"; printf '%s\n' "$G" > "$TS/tenant.high-water"
[ "$(tw)" = revoked ] && pass "row 74b: the restore case (old tenant.bin, no tombstone, the mark at its generation): revoked" || fail "row 74b: restore" "$(tw)"
sed 's|^HW=.*|HW="$STATE/ignored"|' "$TSC" > "$W/tsc-nohw"; chmod 0755 "$W/tsc-nohw"
[ "$(TSCX="$W/tsc-nohw" tw)" = fresh ] && pass "row 74b control: ignoring the high-water file derives an armed word for the restore case" \
                                       || fail "row 74b control: the mark is visible" "$(TSCX="$W/tsc-nohw" tw)"
tfix; printf '1 0\n' > "$TD/.tenant-tombstone"
[ "$(tw)" = revoked ] && pass "row 74b: a first-poll revocation (tombstone generation 0, no mark): revoked" || fail "row 74b: first poll" "$(tw)"
tfix; printf 'garbage' > "$TD/.tenant-tombstone"
[ "$(tw)" = revoked ] && pass "row 74b: a malformed tombstone: revoked" || fail "row 74b: malformed tombstone" "$(tw)"
tfix; printf '%s\n' "$G" > "$TS/tenant.high-water"
[ "$(tw)" = null ] && pass "row 74b: a mark alone, tenant.bin absent: null" || fail "row 74b: mark alone" "$(tw)"
IFS0=$IFS; IFS='|'
for shp in "0\n" "012\n" "9223372036854775808\n" "$G" "$G \n" "123456789012345678901\n"; do
  IFS=$IFS0
  tfix; tplane "$G"; printf "$shp" > "$TS/tenant.high-water"
  w=$(tw); "$TSC" --dir "$TD" --state "$TS" --plane-check "$PLANE_CHECK" >/dev/null 2>"$W/tsc.err" && trc=0 || trc=$?
  { [ "$w" = malformed ] && [ "$trc" = 3 ] && grep -q 'tenant.high-water is malformed' "$W/tsc.err"; } \
    && pass "row 74b: a mark of '$(shape_label "$shp")' beside tenant.bin at G: malformed, no case, a failure naming the file" \
    || fail "row 74b: malformed mark '$(shape_label "$shp")'" "$w $trc"
  IFS='|'
done
IFS=$IFS0
tfix; tplane "$G"; printf '%s\n' "$((G - 1))" > "$TS/tenant.high-water"; w1=$(tw)
printf '%s\n' "$G" > "$TS/tenant.high-water"; w2=$(tw)
printf '9791772722\n' > "$TS/tenant.high-water"; w3=$(tw)
{ [ "$w1" = fresh ] && [ "$w2" = revoked ] && [ "$w3" = revoked ]; } \
  && pass "row 74b: repaired to G - 1 reads fresh, to exactly G revoked (clause 2), and a mark above the refresh's ceiling is read by the grammar alone: revoked" \
  || fail "row 74b: the boundary" "$w1 $w2 $w3"
tfix; tplane "$G"; python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[-1]^=1; open(p,"wb").write(bytes(b))' "$TD/tenant.bin"
[ "$(tw)" = refused ] && pass "row 74b: a digest-flipped tenant.bin at an unchanged header generation: refused, no case" || fail "row 74b: refused" "$(tw)"
tfix; printf '%s\n' "$G" > "$TS/tenant.high-water"; printf '%s\n' "$TENANT_A" > "$TD/.tenant-id"
python3 "$HERE/testdata/make-tenant-plane.py" "$TD/tenant.bin" --gen "$((G + 3))" --tenant "$TENANT_B" --rev "$REV0"
[ "$(tw)" = fresh ] && pass "row 74b: mid-repin (B's plane above the mark, .tenant-id still A): fresh" || fail "row 74b: mid-repin" "$(tw)"
tfix; python3 "$HERE/testdata/make-tenant-plane.py" "$TD/tenant.bin" --gen "$G" --tenant "$TENANT_A" --rev 1 --names ",tenant:$TENANT_A,rev:0"
[ "$(tw)" = fresh ] && pass "row 74b: a hand-placed plane carrying rev:0, no mark: fresh (no term reads the feed-name table)" || fail "row 74b: rev 0" "$(tw)"
# every intermediate state the refresh's revoke and re-arm write, one step at a time
tfix; tplane "$G"; ws=$(tw)
printf '%s\n' "$G" > "$TS/tenant.high-water"; ws="$ws $(tw)"
printf '1 %s\n' "$G" > "$TD/.tenant-tombstone"; ws="$ws $(tw)"
rm_plane "$TD/tenant.bin"; ws="$ws $(tw)"
tplane "$((G + 1))"; ws="$ws $(tw)"
rm -f "$TD/.tenant-tombstone"; ws="$ws $(tw)"
[ "$ws" = "fresh revoked revoked revoked fresh fresh" ] \
  && pass "row 74b: every prefix of the revoke derives revoked, and the re-arm's renamed-before-unlink state fresh ($ws)" \
  || fail "row 74b: the intermediate states" "$ws"
tfix; tplane "$G"; ws=$(tw); rm_plane "$TD/tenant.bin"; ws="$ws $(tw)"
[ "$ws" = "fresh null" ] && pass "row 74b control: the old order (unlink before the tombstone) passes through null" || fail "row 74b control: the order" "$ws"
}

# ===================================================================================================
# Row 94: the oracle's tenant line, written by tenant-state-case.sh from the disk, and only once the
# module's report agrees with it.
row94() {
TD="$W/tsc94"; TS="$TD/state"; rm -rf "$TD"; mkdir -p "$TS"
MS="$W/module.status"
cat > "$W/case.tpl" <<'EOF'
program g1 http
dir mode http deny
dir mode http/server:a deny
dir policy http/server:a deny if tenant_deny
run http/server:a
case c1
addr floor 2a04:2a01::1234
addr server 2a04:2a01::1234
flags 0 0
EOF
ORA="$CORE/policy_ref.py"
G=$G0; VU=$(( (G - G % 86400 + 8 * 86400) * 1000 ))
python3 "$HERE/testdata/make-tenant-plane.py" "$TD/tenant.bin" --gen "$G" --tenant "$TENANT_A" --rev "$REV0" \
  --valid-until "$VU" --deny 2a04:2a01::1234/128
t94() { "$TSC" --dir "$TD" --state "$TS" --plane-check "$PLANE_CHECK" "$@" 2>&1; }
w1=$(t94 | tail -1); w2=$(t94 --now-ms $((VU + 1)) | tail -1)
{ [ "$w1" = fresh ] && [ "$w2" = stale ]; } && pass "row 94: armed and before valid_until_ms: fresh; after it: stale" || fail "row 94: fresh and stale" "$w1 $w2"
printf 'state armed\ngeneration %s\nread_ms 0\n' "$((G - 1))" > "$MS"
o=$(t94 --module-status "$MS" --wait 0 --case-template "$W/case.tpl" --case-out "$W/case" --oracle "$ORA") && r=0 || r=$?
{ [ "$r" = 5 ] && says "$o" converging && says "$o" "generation $((G - 1))" && [ ! -e "$W/case" ]; } \
  && pass "row 94: while the module's armed generation differs from tenant.bin's it prints converging, names both generations and writes no case" \
  || fail "row 94: converging" "$r $o"
printf 'state armed\ngeneration %s\nread_ms 0\n' "$G" > "$MS"
o=$(t94 --module-status "$MS" --wait 0 --case-template "$W/case.tpl" --case-out "$W/case" --oracle "$ORA")
{ says "$o" 'verdict step=4 action=deny program=ctx rule=1 reason=- log_floor=- log_ctx=-' \
  && grep -q '^conf floor 3 0$' "$W/case" && grep -q '^conf ctx 3 0$' "$W/case" && grep -q "^tenant fresh " "$W/case"; } \
  && pass "row 94: once they agree the case carries conf floor 3 0, conf ctx 3 0 and the derived tenant line, and the oracle prints the whole verdict 'action=deny program=ctx rule=1 reason=- log_floor=- log_ctx=-'" \
  || fail "row 94: the emitted case" "$o $(cat "$W/case" 2>&1)"
grep -v '^conf ' "$W/case" > "$W/case.noconf"
says "$(python3 "$ORA" --cases "$W/case.noconf" | grep '^verdict')" 'action=allow .*log_ctx=1' \
  && pass "row 94 control: the same case without the two conf lines prints action=allow ... log_ctx=1" \
  || fail "row 94 control: the conf lines matter" "$(python3 "$ORA" --cases "$W/case.noconf")"
printf '%s\n' "$G" > "$TS/tenant.high-water"
printf 'state revoked\ngeneration %s\nread_ms %s\n' "$G" "$(( ($(date +%s) - 3600) * 1000 ))" > "$MS"
o=$(t94 --module-status "$MS" --wait 0) && r=0 || r=$?
printf 'state revoked\ngeneration %s\nread_ms %s\n' "$G" "$(( ($(date +%s) + 1) * 1000 ))" > "$MS"
o2=$(t94 --module-status "$MS" --wait 0 --case-template "$W/case.tpl" --case-out "$W/case" --oracle "$ORA")
{ [ "$r" = 5 ] && says "$o2" 'verdict step=4 action=allow program=- rule=0 reason=tenant-revoked log_floor=- log_ctx=-'; } \
  && pass "row 94: the restore case (REVOKED through the mark, no tombstone) is emitted once the module's last read is at or after the mark's and tenant.bin's mtimes: action=allow reason=tenant-revoked" \
  || fail "row 94: the restore case" "$r $o / $o2"
rm -f "$TS/tenant.high-water"
printf 'state armed\ngeneration %s\nread_ms 0\n' "$G" > "$MS"
o3=$(t94 --module-status "$MS" --wait 0 --case-template "$W/case.tpl" --case-out "$W/case" --oracle "$ORA")
says "$o3" 'action=deny program=ctx rule=1' && pass "row 94 control: the same directory with the mark removed changes the word and the verdict (revoked allows, fresh denies)" \
                                         || fail "row 94 control: the mark changes the verdict" "$o3"
rm_plane "$TD/tenant.bin"; printf '1 %s\n' "$G" > "$TD/.tenant-tombstone"; touch -d '+2 seconds' "$TD/.tenant-tombstone"
printf 'state revoked\ngeneration %s\nread_ms %s\n' "$G" "$(( $(date +%s) * 1000 - 5000 ))" > "$MS"
o=$(t94 --module-status "$MS" --wait 0) && r=0 || r=$?
printf 'state revoked\ngeneration %s\nread_ms %s\n' "$G" "$(( ($(date +%s) + 3) * 1000 ))" > "$MS"
o2=$(t94 --module-status "$MS" --wait 0) && r2=0 || r2=$?
{ [ "$r" = 5 ] && [ "$r2" = 0 ] && [ "$(printf '%s\n' "$o2" | tail -1)" = revoked ]; } \
  && pass "row 94: a module that went REVOKED before the tombstone was written gets its case emitted after one more tick" \
  || fail "row 94: the early REVOKED module" "$r $r2 $o2"
}

# ===================================================================================================
# Row 120: no torn or crashed state reads NULL. A step injector kills the refresh (SIGKILL: no trap, no
# cleanup) at every step boundary of the revoke, the re-arm, --repin and --unenroll, and inside every
# temp write; the word is read at each boundary with and without the shared flock, and the next run
# converges.
row120() {
crash_then() { # <kill point> <command...>: the crashed run, its word, then the rerun's
  XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=$1"; shift; "$@"; XENV=""
  w_mid=$(word --no-lock)
  # the lock a dead run leaves is cleared once it is older than any run can live
  [ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
  "$@"; w_after=$(word)
}
setup_revoke() { installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; }
setup_rearm() { installed_box; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; owner_home; cfg '{}'; rk --enroll --force; content a "$((G0 + 1))" "$REV0"; }
for pt in temp:tenant.high-water revoke:after-mark temp:.tenant-tombstone revoke:after-tombstone revoke:after-unlink temp:.revocation-epoch; do
  setup_revoke; crash_then "$pt" rk --keyed-set
  { [ "$w_mid" = fresh ] || [ "$w_mid" = revoked ]; } && [ "$w_after" = revoked ] && [ -e "$D/.tenant-tombstone" ] \
    && pass "row 120: the revoke killed at $pt reads $w_mid (before or after, never null), and the next run completes it (revoked, tombstone present)" \
    || fail "row 120: the revoke killed at $pt" "mid=$w_mid after=$w_after $out"
done
for pt in temp:tenant.installed install:after-record install:after-rename temp:tenant.plane-id install:after-plane install:after-unlink temp:.tenant-rev; do
  setup_rearm; crash_then "$pt" rk --keyed-set
  r_ok=$(python3 -c 'import struct,sys
try:
    g=struct.unpack_from("<Q",open(sys.argv[1],"rb").read(24),16)[0]
except Exception:
    g=0
r=int(open(sys.argv[2]).read() or 0)
print("yes" if r >= g else "no")' "$D/tenant.bin" "$RECF")
  { [ "$w_mid" = revoked ] || [ "$w_mid" = fresh ]; } && [ "$w_after" = fresh ] && [ "$r_ok" = yes ] \
    && pass "row 120: the re-arm killed at $pt reads $w_mid, the record stays at or above tenant.bin's generation, and the next run converges to fresh" \
    || fail "row 120: the re-arm killed at $pt" "mid=$w_mid after=$w_after record>=plane=$r_ok $out"
done
# between the plane's rename and its identity record: the previous plane's record is already gone, so
# nothing on disk names any plane (a later hand repair reads the plane as restored, the conservative
# side), and the rerun converges without recording a plane it cannot tell from a restore
IDF="$E/state/tenant.plane-id"
setup_rearm; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-rename"; rk --keyed-set; XENV=""
w_mid=$(word --no-lock); id_mid=$(present "$IDF" record); g_mid=$(gen_of "$D/tenant.bin")
[ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
rk --keyed-set; w_after=$(word)
{ [ "$w_mid" = fresh ] && [ -z "$id_mid" ] && [ "$g_mid" = "$((G0 + 1))" ] && [ "$w_after" = fresh ] && [ ! -e "$IDF" ] \
  && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 120: the re-arm killed between the rename and the identity record: at the kill point G + 1 is in place, no record is on disk and the word is fresh; the rerun converges to fresh at G + 1" \
  || fail "row 120: the re-arm killed at install:after-rename" "mid=$w_mid record@kill=$id_mid gen@kill=$g_mid after=$w_after record=$(fileval "$IDF") $out"
# the same kill on an upgrade over a plane that has a record: the previous record is gone by the rename
upgrade_kill() { # <script>
  installed_box; had_=$(present "$IDF" yes); old_id_=$(cat "$IDF" 2>/dev/null || true); content a "$((G0 + 1))" "$REV0"
  XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-rename"; run_with "$1" --keyed-set; XENV=""
  [ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
}
upgrade_kill "$REFRESH"
{ [ "$had_" = yes ] && [ ! -e "$IDF" ] && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 120: an upgrade from G (record present) to G + 1 killed at install:after-rename leaves G + 1 in place and no record" \
  || fail "row 120: the upgrade killed at install:after-rename" "had=$had_ record=$(fileval "$IDF") gen=$(gen_of "$D/tenant.bin")"
M=$(mutant id-after-rename '  rm -f "$IDF" || lk_fail "could not remove the previous plane'"'"'s identity record $IDF; nothing was installed"' '  :')
upgrade_kill "$M"
{ [ "$had_" = yes ] && [ "$(cat "$IDF" 2>/dev/null)" = "$old_id_" ]; } \
  && pass "row 120 control: with the record's removal left to the write after the rename, the same upgrade killed there leaves the previous plane's record on disk" \
  || fail "row 120 control: the removal before the rename is visible" "had=$had_ $(fileval "$IDF")"
for tr in repin unenroll; do
  for pt in temp:.revocation-epoch "$tr:after-epoch" temp:tenant.high-water "$tr:after-mark" "$tr:after-unlink"; do
    installed_box; owner_home; crash_then "$pt" rk "--$tr"
    # before the mark the word is the before state; once the mark is written the plane sits at or below
    # it (revoked, fail-closed) until the unlink, after which nothing is armed (null)
    case "$pt" in *after-mark) want=revoked ;; *after-unlink) want=null ;; *) want=fresh ;; esac
    { [ "$w_mid" = "$want" ] && [ "$w_after" = null ]; } \
      && pass "row 120: --$tr killed at $pt reads $want, and the rerun converges to null" \
      || fail "row 120: --$tr killed at $pt" "mid=$w_mid (want $want) after=$w_after $out"
  done
done
M=$(mutant unlink-first '  raise_mark || lk_fail "could not write $HWF"
  rm -f "$IDF" || lk_fail "could not remove $IDF"
  sync "$SD" 2>/dev/null || true
  kkill "$1:after-mark"
  unlink_plane || lk_fail "could not remove $TPLANE"' '  unlink_plane || lk_fail "could not remove $TPLANE"
  rm -f "$IDF" || lk_fail "could not remove $IDF"
  sync "$SD" 2>/dev/null || true
  kkill "$1:after-mark"
  raise_mark || lk_fail "could not write $HWF"')
installed_box; owner_home; crash_then repin:after-mark run_with "$M" --repin
[ "$w_mid" = null ] && pass "row 120 control: --repin with the unlink before the mark reads null at the after-mark kill point, where revoked is due" \
                    || fail "row 120 control: the transition's order is visible" "$w_mid"
# a reader that cannot take the shared lock keeps the state it last published
installed_box; word --last "$W/last" > /dev/null
( flock -x 7; : > "$W/held"; i=0; while [ ! -e "$W/release" ] && [ "$i" -lt 100 ]; do i=$((i+1)); sleep 0.1; done ) 7< "$D" &
LP=$!; i=0; while [ ! -e "$W/held" ] && [ "$i" -lt 100 ]; do i=$((i+1)); sleep 0.1; done
rm_plane "$D/tenant.bin"; held_word=$(word --last "$W/last"); : > "$W/release"; wait "$LP" || true; rm -f "$W/held" "$W/release"
[ "$held_word" = fresh ] && pass "row 120: with the directory lock held the reader keeps its last published word (fresh) over a half-changed directory" \
                         || fail "row 120: the reader under the lock" "$held_word"
# between the two renames, then a local loss, a revocation and a restore: revoked, the mark at G + 1 or above
revoke_all() { cfg "{'nodes': {'127.0.0.1': {'auth_all': 'KEY_REVOKED'}, '127.0.0.2': {'auth_all': 'KEY_REVOKED'}}}"; }
rename_gap() { # <script>
  installed_box; content a "$((G0 + 1))" "$REV0"; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-record"; run_with "$1" --keyed-set; XENV=""
  [ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
  backup gap; rm_plane "$D/tenant.bin"; revoke_all; run_with "$1" --keyed-set; restore gap
}
rename_gap "$REFRESH"
{ [ "$(word)" = revoked ] && [ "$(cat "$HWF")" -ge "$((G0 + 1))" ]; } \
  && pass "row 120: a kill between the record's and the plane's renames, a local loss, a revocation and a restore: revoked, the mark at G + 1" \
  || fail "row 120: the rename gap" "$(word) $(fileval "$HWF")"
M=$(mutant plane-first '  if [ "$REC_ST" = absent ] || [ "$1" -gt "$REC_V" ]; then
    put_file "$SD" tenant.installed 0444 "$1
" || lk_fail "could not write $RECF; nothing was installed"
  fi
  kkill install:after-record' '  kkill install:after-record')
remut "$M" '  kkill install:after-plane' '  kkill install:after-plane
  if [ "$REC_ST" = absent ] || [ "$1" -gt "$REC_V" ]; then put_file "$SD" tenant.installed 0444 "$1
"; fi'
installed_box; content a "$((G0 + 1))" "$REV0"; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-plane"; run_with "$M" --keyed-set; XENV=""
[ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
backup gap; rm_plane "$D/tenant.bin"; revoke_all; run_with "$M" --keyed-set; restore gap
[ "$(word)" = fresh ] && pass "row 120 control: the plane-first order leaves the record below the plane, and after the loss, the revocation and the restore the plane arms" \
                      || fail "row 120 control: the record-first order is visible" "$(word)"
M=$(mutant unlink-before-tomb '  put_file "$DIR" .tenant-tombstone 0444 "$(date +%s) ${KMARK:-0}
" || lk_fail "could not write $TOMBF; the revocation is incomplete and the next run completes it"
  kkill revoke:after-tombstone
  unlink_plane || lk_fail "could not remove $TPLANE; the revocation is incomplete and the next run completes it"' '  unlink_plane || lk_fail "could not remove $TPLANE; the revocation is incomplete and the next run completes it"
  kkill revoke:after-tombstone
  put_file "$DIR" .tenant-tombstone 0444 "$(date +%s) ${KMARK:-0}
" || lk_fail "could not write $TOMBF; the revocation is incomplete and the next run completes it"')
setup_revoke
XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=revoke:after-tombstone"; run_with "$M" --keyed-set; XENV=""
w=$(word --no-lock)
[ "$w" = null ] \
  && pass "row 120 control: unlinking before the tombstone reads $w at that boundary, where revoked is due" \
  || fail "row 120 control: the order is visible" "$w"
M=$(mutant tomb-early '  kkill install:after-record' '  rm -f "$TOMBF"; kkill install:after-record')
setup_rearm; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=install:after-record"; run_with "$M" --keyed-set; XENV=""
[ "$(word --no-lock)" = null ] && pass "row 120 control: unlinking the tombstone before the rename shows null mid-re-arm to a reader without the lock" \
                               || fail "row 120 control: the re-arm order is visible" "$(word --no-lock)"
M=$(mutant fixed-temp '  _pt=$(mktemp "$1/.$2.XXXXXX") || return 1' '  _pt="$1/.$2.tmp"; ( set -C; : > "$_pt" ) 2>/dev/null || return 1')
setup_revoke; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=temp:tenant.high-water"; run_with "$M" --keyed-set; XENV=""
[ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
run_with "$M" --keyed-set
{ [ "$rc" != 0 ] && [ -e "$D/tenant.bin" ] && [ ! -e "$D/.tenant-tombstone" ]; } \
  && pass "row 120 control: a fixed-name temp with no stale-temp sweep makes the rerun exit non-zero with tenant.bin present and no tombstone" \
  || fail "row 120 control: the unique temp is visible" "rc=$rc $out"
# the temps: a fresh one survives the rerun, an hour-old one goes, a 25-minute download temp survives
sweep_case() { # <script>
  setup_revoke; XENV="WHISPER_EDGE_REFRESH_TEST_KILL_AT=temp:tenant.high-water"; run_with "$1" --keyed-set; XENV=""
  [ -d "$D/.refresh.lock.d" ] && touch -d '-31 minutes' "$D/.refresh.lock.d"
  tmp=$(find "$E/state" -name '.tenant.high-water.??????' | head -1)
  : > "$D/.tenant.bin.Zz9Yx8"; touch -d '-25 minutes' "$D/.tenant.bin.Zz9Yx8"
  run_with "$1" --keyed-set; fresh_kept=$(present "$tmp" yes); dl_kept=$(present "$D/.tenant.bin.Zz9Yx8" yes)
}
sweep_case "$REFRESH"
{ [ -n "$tmp" ] && [ "$fresh_kept" = yes ] && [ -e "$D/.tenant-tombstone" ] && [ "$dl_kept" = yes ]; } \
  && pass "row 120: after a kill inside the mark's temp write the rerun completes the revocation and spares the seconds-old temp and another run's 25-minute download temp" \
  || fail "row 120: the temps" "tmp=$tmp fresh=$fresh_kept dl=$dl_kept $out"
touch -d '-61 minutes' "$tmp"; rk --keyed-set
[ ! -e "$tmp" ] && pass "row 120: an hour-old temp of its own template is removed by the next locked step" || fail "row 120: the stale temp" "$tmp"
M=$(mutant no-age-sweep "-o -name '.tenant.plane-id.??????' \\) \\
    -mmin +60 -delete" "-o -name '.tenant.plane-id.??????' \\) \\
    -delete")
sweep_case "$M"
[ -z "$fresh_kept" ] && pass "row 120 control: a sweep with no age guard deletes the seconds-old temp the rerun must leave" \
                     || fail "row 120 control: the age guard is visible" "$tmp"
# (with the sweep's hour-long age guard the broadened pattern alone cannot reach a 25-minute temp, so
# the control drops both, as a hand-rolled cleanup would)
M=$(mutant broad-sweep "-name '.tenant-tombstone.??????' -o" "-name '.tenant*' -o")
remut "$M" "-o -name '.tenant-id.??????' \\) -mmin +60 -delete" "-o -name '.tenant-id.??????' \\) -delete"
sweep_case "$M"
[ -z "$dl_kept" ] && pass "row 120 control: a pattern broadened to .tenant* (and unguarded) deletes the 25-minute download temp" \
                  || fail "row 120 control: the pattern is visible" ""
M=$(mutant reaper-20 '  find "$DIR" -maxdepth 1 \( -name ".tenant.bin.*" -o -name ".refresh.*" -o -name ".refresh.lock.d" \) \
    -mmin +30' '  find "$DIR" -maxdepth 1 \( -name ".tenant.bin.*" -o -name ".refresh.*" -o -name ".refresh.lock.d" \) \
    -mmin +20')
sweep_case "$M"
[ -z "$dl_kept" ] && pass "row 120 control: the reaper lowered to -mmin +20 deletes the 25-minute download temp" \
                  || fail "row 120 control: the reaper bound is visible" ""
# live names aged two hours survive a locked step, the word unchanged
setup_revoke; rk --keyed-set; printf '%s\n' "$TENANT_A" > "$D/.tenant-id"; printf '%s\n' "$REV0" > "$D/.tenant-rev"
: > "$D/.keyed-etag"; printf 'x KEY_REVOKED y 1\n' > "$D/.revocation-seen"
for f in "$D/.tenant-tombstone" "$D/.revocation-epoch" "$D/.tenant-id" "$D/.tenant-rev" "$D/.keyed-etag" "$D/.revocation-seen" "$HWF" "$RECF"; do
  touch -d '-2 hours' "$f"
done
w0=$(word); cfg '{}'; rk --keyed-set
gone=""
for f in "$D/.tenant-tombstone" "$D/.revocation-epoch" "$D/.tenant-id" "$D/.tenant-rev" "$HWF" "$RECF"; do [ -e "$f" ] || gone="$gone $f"; done
{ [ -z "$gone" ] && [ "$(word)" = "$w0" ]; } && pass "row 120: every live name aged two hours survives a locked step and the word is unchanged ($w0)" \
                                         || fail "row 120: live names" "gone:$gone"
# the identity record is a live name too: aged two hours beside an armed plane, a keyed run's first
# locked step (which sweeps) leaves it, byte for byte
IDF="$E/state/tenant.plane-id"
id_survives() { # <script>
  installed_box; id0=$(cat "$IDF"); touch -d '-2 hours' "$IDF"; cfg '{}'; run_with "$1" --keyed-set
}
id_survives "$REFRESH"
{ [ "$(cat "$IDF" 2>/dev/null)" = "$id0" ] && [ "$(word)" = fresh ]; } \
  && pass "row 120: tenant.plane-id aged two hours survives a keyed run's sweep unchanged, and the word stays fresh" \
  || fail "row 120: the identity record and the sweep" "$(fileval "$IDF") $out"
M=$(mutant id-swept "-o -name '.tenant.plane-id.??????' \) \\
    -mmin +60 -delete" "-o -name '.tenant.plane-id.??????' -o -name 'tenant.plane-id' \) \\
    -mmin +60 -delete")
id_survives "$M"
[ ! -e "$IDF" ] && pass "row 120 control: a sweep that also matches the live record deletes it" \
                || fail "row 120 control: the sweep's patterns are what keep the record" ""
glob_case() { # <mutant>
  installed_box; backup globpre; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"; rk --keyed-set; printf '%s\n' "$TENANT_A" > "$D/.tenant-id"; printf '%s\n' "$REV0" > "$D/.tenant-rev"
  for f in "$D/.tenant-tombstone" "$D/.tenant-id" "$D/.tenant-rev" "$HWF" "$RECF"; do touch -d '-2 hours' "$f"; done
  cfg '{}'; run_with "$1" --keyed-set
}
M=$(mutant tomb-glob "-name '.tenant-tombstone.??????' -o" "-name '.tenant-tombstone*' -o")
glob_case "$M"; [ ! -e "$D/.tenant-tombstone" ] && [ "$(word)" = null ] \
  && pass "row 120 control: a .tenant-tombstone* glob deletes the live tombstone and derives null" || fail "row 120 control: the tombstone glob" "$(word)"
M=$(mutant dot-glob "-name '.tenant-tombstone.??????' -o" "-name '.*' -o")
glob_case "$M"; [ ! -e "$D/.tenant-id" ] && [ ! -e "$D/.tenant-rev" ] \
  && pass "row 120 control: a .* sweep deletes the pin and the rev guard" || fail "row 120 control: the dot glob" ""
M=$(mutant state-unpatterned "find \"\$SD\" -maxdepth 1 -type f \\( -name '.tenant.high-water.??????' -o -name '.tenant.installed.??????' \\
    -o -name '.tenant.plane-id.??????' \\) \\
    -mmin +60 -delete" "find \"\$SD\" -maxdepth 1 -type f -mmin +60 -delete")
glob_case "$M"; restore globpre
[ "$(word)" = fresh ] && pass "row 120 control: an unpatterned -mmin +60 over state/ deletes the mark, and a restore then arms" \
                      || fail "row 120 control: the state sweep pattern" "$(word)"
}

# ===================================================================================================
# Row 120b: the lock is never held across a request. The fake feed holds k/manifest.json open until a
# second FIFO is written; meanwhile a shared reader and a keyless run must both get the directory.
row120b() {
lock_case() { # <script>: sets finding (none|flock|mkdir) and keyless (ran|skipped)
  keyless_stub; installed_box; keyless_tor
  content a "$((G0 + 1))" "$REV0"; rm -f "$D/.keyed-etag"
  rm -f "$W/fifo1" "$W/fifo2" "$W/probe.log"; mkfifo "$W/fifo1" "$W/fifo2"
  cfg "{'hold': {'path': 'manifest.json', 'started': '$W/fifo1', 'release': '$W/fifo2'}}"
  echo "$D" > "$W/probe"
  run_with "$1" --keyed-set > /dev/null 2>&1 &
  KB=$!
  cat "$W/fifo1" > /dev/null
  # the stall has begun: the shared reader, in a bounded loop, conflicting only on exit 1
  finding=none; i=0
  while [ "$i" -lt 10 ]; do
    flock -n -s "$D" true && r=0 || r=$?
    if [ "$r" = 1 ]; then finding=flock; break; fi
    [ "$r" = 0 ] || { finding="harness-error-$r"; break; }
    i=$((i + 1)); sleep 0.2
  done
  keyless=skipped
  if [ "$finding" = none ]; then
    # a changed keyless plane, so the keyless run reaches its own locked step
    python3 - "$K/plane.bin" "$((G0 + 7))" <<'PY2'
import struct, sys
b = bytearray(open(sys.argv[1], "rb").read()); struct.pack_into("<Q", b, 16, int(sys.argv[2])); open(sys.argv[1], "wb").write(bytes(b))
PY2
    ps=$(sha256sum < "$K/plane.bin" | cut -d' ' -f1); cp "$K/plane.bin" "$K/edge/planes/$ps.bin"
    openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$K/plane.bin" -out "$K/edge/planes/$ps.bin.sig"
    printf '{"format":2,"generation":%s,"planes":[{"name":"tor","sha256":"%s","bytes":%s}],"withheld":[]}' \
      "$((G0 + 7))" "$ps" "$(wc -c < "$K/plane.bin")" > "$K/edge/manifest.json"
    ms=$(sha256sum < "$K/edge/manifest.json" | cut -d' ' -f1)
    openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$K/edge/manifest.json" -out "$K/edge/manifests/$ms.sig"
    keyless_tor; [ "$rc" = 0 ] && [ "$(gen_of "$D/tor.bin")" = "$((G0 + 7))" ] && keyless=ran || keyless="failed($rc)"
  fi
  echo go > "$W/fifo2"
  wait "$KB" || true
  rm -f "$W/probe"
  grep -q '^harness-error' "$W/probe.log" 2>/dev/null && finding="$finding+harness-error"
  grep -q '^flock-held' "$W/probe.log" 2>/dev/null && finding="$finding+flock-at-request"
  grep -q '^mkdir-held' "$W/probe.log" 2>/dev/null && finding="$finding+mkdir-at-request"
  probes=$(grep -c '^probed' "$W/probe.log" 2>/dev/null || echo 0)
}
lock_case "$REFRESH"
{ [ "$finding" = none ] && [ "$keyless" = ran ] && [ "$probes" -ge 4 ] && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 120b: with k/manifest.json held open the shared reader takes the lock and a keyless run installs; no tagged request ($probes of them) found either lock held, and the keyed run then installs" \
  || fail "row 120b: no lock across a request" "finding=$finding keyless=$keyless probes=$probes"
M=$(mutant hold-to-exit 'lk_drop() {
  rmdir "$DIR/.refresh.lock.d" 2>/dev/null' 'lk_drop() {
  return 0
  rmdir "$DIR/.refresh.lock.d" 2>/dev/null')
remut "$M" 'lk_take() {' 'lk_take() {
  [ -n "${MKDIR_LOCK:-}" ] && return 0'
lock_case "$M"
[ "$finding" != none ] && [ "$keyless" = skipped ] && pass "row 120b control: the pin's idiom (fd 9 held to exit) is found by the shared reader during the held fetch ($finding)" \
                                                  || fail "row 120b control: a lock held across the fetch is found" "finding=$finding keyless=$keyless"
M=$(mutant flock-around-plane '    kreq tenant.bin "$KSTAGE" "$PIN_ADDR" -H "If-Match: \"$psha\""' '    lk_take; kreq tenant.bin "$KSTAGE" "$PIN_ADDR" -H "If-Match: \"$psha\""; lk_drop')
lock_case "$M"
case "$finding" in *flock-at-request*) pass "row 120b control: a flock taken around the tenant.bin fetch is recorded by the probe at that request ($finding)" ;;
  *) fail "row 120b control: the flock around the plane fetch" "$finding" ;; esac
M=$(mutant mkdir-around-plane '    kreq tenant.bin "$KSTAGE" "$PIN_ADDR" -H "If-Match: \"$psha\""' '    mkdir "$DIR/.refresh.lock.d"; kreq tenant.bin "$KSTAGE" "$PIN_ADDR" -H "If-Match: \"$psha\""; rmdir "$DIR/.refresh.lock.d"')
lock_case "$M"
case "$finding" in *mkdir-at-request*) pass "row 120b control: the mkdir lock held across the tenant.bin fetch is recorded by the mkdir probe the flock probe cannot replace ($finding)" ;;
  *) fail "row 120b control: the mkdir lock across the plane fetch" "$finding" ;; esac
cfg '{}'
}

# ===================================================================================================
# Row 62: one module. install.sh installs no web-server module (modules are built from edge/ and
# loaded by the operator, "Building the modules" in the README), so what a key could change is what
# install.sh does install: the refresh script and the units. They must be the same files with a key
# and without one; the key changes only the enrolment step.
row62() {
installed_set() { # <with|without> a CLI key: the files install.sh would install and write, and their sha256
  # The dry run says "would install <target>" for the refresh it copies from its own directory and
  # "would write <unit>" for each unit, which WHISPER_EDGE_DRY_UNITDIR leaves whole, rendered by the same
  # code a real run uses; so the set is the installed script by its source and every rendered unit.
  rm -rf "${W:?}/home" "$W/is.units"; mkdir -p "$W/home"
  [ "$1" = with ] && owner_home
  env HOME="$W/home" SUDO_USER= WHISPER_API_KEY= WHISPER_KEY= WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DRY_UNITDIR="$W/is.units" \
    "$2" --dry-run --dir "$D" --base "$BASE" > "$W/is.out" 2>&1 || :
  { sed -n 's/.*would install \([^ ]*whisper-edge-refresh\)$/\1/p' "$W/is.out" | sort -u | while read -r f; do
      _s="$(dirname "$2")/$(basename "$f")"
      printf '%s %s\n' "$(basename "$f")" "$(sha256sum < "$_s" | cut -d' ' -f1)"
    done
    for u in "$W/is.units"/*; do [ -f "$u" ] && printf '%s %s\n' "$(basename "$u")" "$(sha256sum < "$u" | cut -d' ' -f1)"; done
  } | sort -u
}
fresh_box
a=$(installed_set without "$HERE/install.sh"); b=$(installed_set with "$HERE/install.sh")
o_with=$(env HOME="$W/home" SUDO_USER= WHISPER_EDGE_ETC="$E" "$HERE/install.sh" --dry-run --dir "$D" --base "$BASE" 2>&1) || :
# the units are rendered only where systemctl is (without it the installer prints the schedule instead)
_unit_ok=1; command -v systemctl >/dev/null 2>&1 && { says "$a" 'whisper-edge-refresh-keyed.service ' || _unit_ok=0; }
{ [ -n "$a" ] && [ "$a" = "$b" ] && says "$a" 'whisper-edge-refresh ' && [ "$_unit_ok" = 1 ] \
  && says "$o_with" 'would run: .*whisper-edge-refresh --enroll --label'; } \
  && pass "row 62: a keyed and a keyless install of one release install the same files ($(printf '%s\n' "$a" | wc -l | tr -d ' ') of them, by sha256); the key adds only the enrolment" \
  || fail "row 62: one set of files" "$a / $b"
rm -rf "$W/inst2"; cp -a "$HERE" "$W/inst2"; printf '\n# a different build\n' >> "$W/inst2/whisper-edge-refresh"
c=$(installed_set with "$W/inst2/install.sh")
[ "$a" != "$c" ] && pass "row 62 control: a build that differs by one line is told apart by the same comparison" \
                 || fail "row 62 control: the comparison can fail" "$c"
# rows 73 and 75's other artifact: the keyed unit install.sh writes is the tree's unit file with only
# its paths moved (and its ExecStart rendered), so the unit those rows run under is the one hosts get.
# render_diff prints every difference between the rendered unit and the tree file, the tree file's paths
# moved the same way here, ExecStart and the Environment line it brings compared separately.
render_diff() { # <install dir>
  # A dry run on a box with no server here ends non-zero after rendering what it would write; these rows
  # read the rendering, so its status is not theirs to stop on (an empty rendering fails them by name).
  rm -rf "$W/units"; mkdir -p "$W/units"
  env HOME="$W/home" SUDO_USER= WHISPER_EDGE_ETC="$E" WHISPER_EDGE_DRY_UNITDIR="$W/units" \
    "$1/install.sh" --dry-run --dir "$D" --base "$BASE" > "$W/units.out" 2>&1 || :
  _r="$W/units/whisper-edge-refresh-keyed.service"
  [ -s "$_r" ] || { echo "no keyed unit rendered"; return 0; }
  sed -e "s|/etc/whisper-edge/state|$E/state|g" -e "s|/var/lib/whisper-edge|$D|g" -e "s|/etc/whisper-edge|$E|g" \
      -e '/^ExecStart=/d' "$1/whisper-edge-refresh-keyed.service" > "$W/units.want"
  grep -v -e '^ExecStart=' -e "^Environment=WHISPER_EDGE_ETC=$E\$" "$_r" > "$W/units.got"
  diff "$W/units.want" "$W/units.got" || true
  grep -qx "ExecStart=/usr/local/sbin/whisper-edge-refresh --quiet --keyed-set --dir $D --base $BASE" "$_r" \
    || echo "ExecStart: $(grep '^ExecStart=' "$_r")"
  grep -qx "Environment=WHISPER_EDGE_ETC=$E" "$_r" || echo "no Environment=WHISPER_EDGE_ETC=$E line"
}
if command -v systemctl >/dev/null 2>&1; then
  dd_=$(render_diff "$HERE")
  [ -z "$dd_" ] && pass "rows 73, 75: install.sh's keyed unit is the tree's unit file with its paths moved and its ExecStart rendered, line for line" \
                || fail "rows 73, 75: install.sh's keyed unit differs from the tree's unit file" "$dd_"
  # control 1: an edit to the tree's unit reaches the rendered unit, and the comparison still holds
  rm -rf "$W/inst3"; cp -a "$HERE" "$W/inst3"
  sed -i -e 's|^ExecStartPre=+/usr/bin/install -d -o root -g root -m 0755 |ExecStartPre=+/usr/bin/install -d -o root -g root -m 0700 |' \
         -e 's|^ReadWritePaths=/var/lib/whisper-edge -/etc/whisper-edge/state$|ReadWritePaths=/var/lib/whisper-edge -/etc/whisper-edge/state -/run/whisper-edge-gate|' \
         "$W/inst3/whisper-edge-refresh-keyed.service"
  dd_=$(render_diff "$W/inst3")
  if [ -z "$dd_" ] && grep -qx "ExecStartPre=+/usr/bin/install -d -o root -g root -m 0700 $E/state" "$W/units/whisper-edge-refresh-keyed.service" \
     && grep -qx "ReadWritePaths=$D -$E/state -/run/whisper-edge-gate" "$W/units/whisper-edge-refresh-keyed.service"; then
    pass "rows 73, 75 control: a tree unit edited to 0700 and a third writable path is rendered with both edits"
  else fail "rows 73, 75 control: an edited tree unit" "$dd_"; fi
  # control 2: the install.sh of the previous revision, which typed its own ExecStartPre and
  # ReadWritePaths lines, fails the same comparison against that edited unit
  if python3 - "$W/inst3/install.sh" > "$W/inst3.plant" 2>&1 <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = """  move_paths whisper-edge-refresh-keyed.service | RU_FROM=- unit_plain whisper-edge-refresh-keyed.service \\\n"""
new = ("""  unit_plain whisper-edge-refresh-keyed.service \\\n"""
       """    -e "s|^ExecStartPre=.*|ExecStartPre=+/usr/bin/install -d -o root -g root -m 0755 $(sed_rep "$(sd_word "$ETC/state")")|" \\\n"""
       """    -e "s|^ReadWritePaths=.*|ReadWritePaths=$(sed_rep "$(sd_word "$DIR")") -$(sed_rep "$(sd_word "$ETC/state")")|" \\\n""")
if s.count(old) != 1:
    sys.exit("control: the keyed rendering line occurs %d times in install.sh, not once" % s.count(old))
open(p, "w").write(s.replace(old, new))
PY
  then
    dd_=$(render_diff "$W/inst3")
    [ -n "$dd_" ] && pass "rows 73, 75 control: an install.sh with its own ExecStartPre and ReadWritePaths literals fails the comparison" \
                  || fail "rows 73, 75 control: the comparison can fail" ""
  else
    fail "rows 73, 75 control: the previous revision's rendering could not be planted" "$(cat "$W/inst3.plant")"
  fi
else
  SKIPPED="${SKIPPED}install.sh's unit rendering (no systemctl here, so it renders no unit); "
fi
# row 61's installer half: a 0644 key it finds is reset to 0600 with the same advice
fresh_box; place_key; chmod 0644 "$E/key"
o=$(env HOME="$W/home" WHISPER_EDGE_ETC="$E" "$HERE/install.sh" --dry-run --dir "$D" --base "$BASE" 2>&1) || :
# a dry run says what it would do; the revoke advice is the real run's line, printed once the mode is changed
{ says "$o" "would make $E/key 0600: it is readable by its group or by others"; } \
  && pass "row 61: install.sh would reset the mode of a 0644 key file it finds, and says why" \
  || fail "row 61: install.sh and an exposed key" "$o"
chmod 0600 "$E/key"
o=$(env HOME="$W/home" WHISPER_EDGE_ETC="$E" "$HERE/install.sh" --dry-run --dir "$D" --base "$BASE" 2>&1) || :
says "$o" "would make $E/key 0600" && fail "row 61 control: a 0600 key is left alone" "$o" \
  || pass "row 61 control: a 0600 key is left alone by install.sh"
}

# ===================================================================================================
# The published revocation figures: the README paragraph (and any other file named in KEYED_GATE_ALSO_HOLD)
# carries exactly what install/revocation-bounds.py derives from the shipped timer and script.
rowbounds() {
held_to() { # <install dir> <file>: prints each derived string the file does not carry, whitespace aside
  python3 - "$1/revocation-bounds.py" "$2" <<'PY'
import json, re, subprocess, sys
tool, f = sys.argv[1:3]
text = re.sub(r"\s+", " ", open(f).read())
for arg in ([], ["--note"]):
    want = subprocess.run([sys.executable, tool] + arg, capture_output=True, text=True, check=True).stdout.strip()
    if want not in text:
        print("missing: " + want)
# figures earlier revisions published and the derivation has since replaced: present anywhere, they are
# stale text the presence check above cannot see
for old in ("1,382 s", "at most 1,591 s and 2,672 s", "at most 2,672 s", "at most 3,572 s", "about 23 minutes",
            "at most 27 and 45", "at most 27 and 60", "8, 23, 27 and 45 minutes"):
    if old in text:
        print("superseded: " + old)
# every figure-bearing phrase, whatever its wording, compared with --json: a sentence in any of these
# shapes carrying another figure fails, wherever it stands; history names old figures in another shape
b = json.loads(subprocess.run([sys.executable, tool, "--json"], capture_output=True, text=True, check=True).stdout)
num = lambda x: int(x.replace(",", ""))
mt = lambda x: int(round(x / 60.0))
mx = lambda x: int(-(-x // 60))
two_t, one_t, two_m, one_m = b["two_typical"], b["one_typical"], b["two_max"], b["one_max"]
checks = [
    (r"at most (\d+) and (\d+) minutes", lambda g: (num(g[0]), num(g[1])) == (mx(two_m), mx(one_m))),
    (r"bounds of ([\d,]+) s and ([\d,]+) s", lambda g: (num(g[0]), num(g[1])) == (two_m, one_m)),
    (r"(\d+), (\d+), (\d+) and (\d+) minutes", lambda g: tuple(map(num, g)) == (mt(two_t), mt(one_t), mx(two_m), mx(one_m))),
    (r"typical ([\d,]+) s and ([\d,]+) s", lambda g: (num(g[0]), num(g[1])) == (round(two_t), round(one_t))),
    (r"\(two nodes, at most ([\d,]+) s\)", lambda g: num(g[0]) == two_m),
    (r"\(one node, at most ([\d,]+) s\)", lambda g: num(g[0]) == one_m),
    (r"at most ([\d,]+) s, (\d+) minutes", lambda g: (num(g[0]), num(g[1])) in ((two_m, mx(two_m)), (one_m, mx(one_m)))),
]
for pat, good in checks:
    for m in re.finditer(pat, text):
        if not good(m.groups()):
            print("wrong figure: " + m.group(0))
PY
}
m_=$(held_to "$HERE" "$HERE/../REFERENCE.md")
[ -z "$m_" ] && pass "revocation figures: the README carries the sentence and the inputs revocation-bounds.py derives from the shipped timer and script" \
             || fail "revocation figures: the README differs from revocation-bounds.py" "$m_"
# any other file that publishes the figures is held the same way: KEYED_GATE_ALSO_HOLD names them, space
# separated, and a named file that is missing fails rather than being skipped
for f_ in ${KEYED_GATE_ALSO_HOLD:-}; do
  if [ ! -f "$f_" ]; then fail "revocation figures: KEYED_GATE_ALSO_HOLD names $f_, which is not a file" ""; continue; fi
  m_=$(held_to "$HERE" "$f_")
  [ -z "$m_" ] && pass "revocation figures: $(basename "$f_") carries the same derived text" \
               || fail "revocation figures: $(basename "$f_") differs from revocation-bounds.py" "$m_"
done
# control: the shipped README with one superseded sentence added still carries the derived text, and
# fails on the stale figure alone
{ cat "$HERE/../REFERENCE.md"; printf '\nat most 27 and 60 minutes, plus the module'"'"'s reload\n'; } > "$W/README.stale"
m_=$(held_to "$HERE" "$W/README.stale")
{ says "$m_" 'superseded: at most 27 and 60' && ! says "$m_" 'missing:'; } \
  && pass "revocation figures control: a README that also keeps the superseded 60-minute bound fails on that figure alone" \
  || fail "revocation figures control: the superseded figures are visible" "$m_"
# the formula against a simulation of the same timer: 400,000 revocations at uniform times, runs at
# k P + U_k with U_k drawn afresh, the first run starting at or after the memo, the second (one node)
# the first run starting at least F after it; the closed forms must agree within 1 %
simulate() { # <revocation-bounds.py>
  python3 - "$1" <<'PY'
import json, random, subprocess, sys
b = json.loads(subprocess.run([sys.executable, sys.argv[1], "--json"], capture_output=True, text=True, check=True).stdout)
c = b["constants"]; P, J, F, M = c["P"], c["J"], c["F"], c["M"]
rnd = random.Random(7)
two = one = 0.0; n = 400000
for _ in range(n):
    r = rnd.uniform(2 * P, 3 * P)
    starts = [k * P + rnd.uniform(0, J) for k in range(8)]
    first = next(s for s in starts if s >= r + M)
    second = next(s for s in starts if s >= first + F)
    two += first - r; one += second - r
two /= n; one /= n
ok = abs(two - b["two_typical"]) <= 0.01 * two and abs(one - b["one_typical"]) <= 0.01 * one
print("%s simulated %.0f s and %.0f s, formula %.0f s and %.0f s" % ("agree" if ok else "DISAGREE", two, one, b["two_typical"], b["one_typical"]))
PY
}
sim_=$(simulate "$HERE/revocation-bounds.py")
case "$sim_" in agree*) pass "revocation figures: the typical figures $sim_" ;; *) fail "revocation figures: the formula and the simulation" "$sim_" ;; esac
rm -rf "$W/bounds-sim"; mkdir -p "$W/bounds-sim"; cp "$HERE/revocation-bounds.py" "$HERE/whisper-edge-refresh" "$HERE/whisper-edge-refresh-keyed.timer" "$W/bounds-sim/"
python3 - "$W/bounds-sim/revocation-bounds.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = "    EW = P / 2 + J * J / (12 * P)"
assert s.count(old) == 1, "control: the mean-wait line is not in revocation-bounds.py once"
open(p, "w").write(s.replace(old, "    EW = P / 2"))
PY
sim_=$(simulate "$W/bounds-sim/revocation-bounds.py")
case "$sim_" in DISAGREE*) pass "revocation figures control: a mean wait without the jitter term disagrees with the simulation ($sim_)" ;;
  *) fail "revocation figures control: the simulation can catch a formula edit" "$sim_" ;; esac
# control: row 70's own form with the superseded one-node figures, appended to the shipped README, fails
# on the figures although no listed phrase matches it
{ cat "$HERE/../REFERENCE.md"; printf '\n(typical 488 s and 1,880 s, bounds of 1,591 s and 3,572 s with the defaults: 8, 31, 27 and 60 minutes)\n'; } > "$W/README.row70"
m_=$(held_to "$HERE" "$W/README.row70")
{ says "$m_" 'wrong figure: bounds of 1,591 s and 3,572 s' && says "$m_" 'wrong figure: 8, 31, 27 and 60 minutes' && ! says "$m_" 'missing:' && ! says "$m_" 'superseded:'; } \
  && pass "revocation figures control: row 70's form carrying 3,572 s and 60 minutes fails on both figures, with no listed phrase to match" \
  || fail "revocation figures control: the figure regexes are visible" "$m_"
# control: a stale figure introduced as history is still a stale figure
{ cat "$HERE/../REFERENCE.md"; printf '\nSince an earlier release the edge removes the plane at most 27 and 64 minutes after key.revoke.\n'; } > "$W/README.history"
m_=$(held_to "$HERE" "$W/README.history")
says "$m_" 'wrong figure: at most 27 and 64 minutes' \
  && pass "revocation figures control: a line introduced as history ('since an earlier release') carrying 27 and 64 minutes fails on the figure" \
  || fail "revocation figures control: history is no exemption" "$m_"
# controls: a floor of 600 s, or a timer jitter of 600 s, changes the derived figures, and the same
# README then fails the check
for v_ in floor jitter; do
  rm -rf "$W/bounds"; mkdir -p "$W/bounds"; cp "$HERE/revocation-bounds.py" "$HERE/whisper-edge-refresh" "$HERE/whisper-edge-refresh-keyed.timer" "$W/bounds/"
  case $v_ in
    floor)  sed -i 's/^REVOKE_POLL_FLOOR=900$/REVOKE_POLL_FLOOR=600/' "$W/bounds/whisper-edge-refresh" ;;
    jitter) sed -i 's/^RandomizedDelaySec=300$/RandomizedDelaySec=600/' "$W/bounds/whisper-edge-refresh-keyed.timer" ;;
  esac
  cmp -s "$HERE/whisper-edge-refresh" "$W/bounds/whisper-edge-refresh" && cmp -s "$HERE/whisper-edge-refresh-keyed.timer" "$W/bounds/whisper-edge-refresh-keyed.timer" \
    && { fail "revocation figures control ($v_): the edit did not apply" ""; continue; }
  m_=$(held_to "$W/bounds" "$HERE/../REFERENCE.md")
  [ -n "$m_" ] && pass "revocation figures control: a $v_ of 600 s derives other figures, and the shipped README fails the check" \
               || fail "revocation figures control ($v_): the check can fail" ""
done
}

# ===================================================================================================
# Rows 61, 73, 75 and 117 under the keyed unit's own sandbox: every [Service] property of
# whisper-edge-refresh-keyed.service through systemd-run, as root, on an ext4 fixture outside /tmp and
# /home (PrivateTmp and ProtectHome hide both). Needs passwordless sudo, systemd as PID 1 and systemd-run:
# /run/systemd/system is sd_booted(3)'s test, since a systemd-run binary on a host whose PID 1 is not
# systemd (a container, a build VM) has no manager to run the unit.
rowunit() {
if ! sudo -n true 2>/dev/null || ! command -v systemd-run >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  SKIPPED="${SKIPPED}rows 61, 73, 75 and 117 under the keyed unit (need passwordless sudo, systemd as PID 1 and systemd-run); "
  return 0
fi
R=$(sudo -n mktemp -d /var/lib/whisper-edge-keyed-gate.XXXXXX); SUDO_DIR=$R
sudo -n chmod 0755 "$R"
UNIT="$HERE/whisper-edge-refresh-keyed.service"
rb_reset() { # the box as root: plane directory, /etc tree, the script, the CA
  sudo -n chattr -R -i "$R" 2>/dev/null || true
  sudo -n rm -rf "$R/lib" "$R/etc" "$R/sbin"
  sudo -n install -d -o 0 -g 0 -m 0755 "$R/lib" "$R/etc" "$R/etc/state" "$R/sbin" "$R/lib/hooks"
  sudo -n install -o 0 -g 0 -m 0755 "$1" "$R/sbin/whisper-edge-refresh"
  # under /var/lib the copy is var_lib_t, which systemd may not execute under an enforcing policy
  # (exit 203, no AVC: a dontaudit); label it as the real install's /usr/local/sbin copy is labelled
  if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    sudo -n chcon -t bin_t "$R/sbin/whisper-edge-refresh" \
      || fail "the unit fixture's label" "chcon -t bin_t $R/sbin/whisper-edge-refresh failed, so systemd cannot execute it under this policy"
  fi
  sudo -n install -o 0 -g 0 -m 0644 "$W/sign.pub" "$R/lib/edge.pub"
  sudo -n install -o 0 -g 0 -m 0644 "$W/ca.pem" "$R/ca.pem"
  printf '%s\n' "$FEEDKEY" | sudo -n tee "$R/etc/key" > /dev/null; sudo -n chmod 0600 "$R/etc/key"
  printf 'ag_gateFeedKey000001\n' | sudo -n tee "$R/etc/key.id" > /dev/null
  echo 127.0.0.1 > "$W/addrs.127.0.0.1"
}
# Every [Service] property of the unit file in the tree (or $KEYED_UNIT, for a control), with only the
# paths moved onto the fixture; a variant is one edit of the derived line, never a hand-typed copy.
unit_props() { # <variant>
  while IFS= read -r l; do
    case "$l" in ''|'#'*|Type=*|ExecStart=*) continue ;; esac
    l=$(printf '%s' "$l" | sed "s|/var/lib/whisper-edge|$R/lib|g; s|/etc/whisper-edge|$R/etc|g")
    case "$l" in
      ReadWritePaths=*)
        [ "$1" = nominus ] && l=$(printf '%s' "$l" | sed "s| -$R/etc/state| $R/etc/state|")
        [ "$1" = wholedir ] && l=$(printf '%s' "$l" | sed "s|$R/etc/state|$R/etc|") ;;
      ExecStartPre=*) [ "$1" = nopre ] && continue ;;
      CapabilityBoundingSet=*|AmbientCapabilities=*) [ "$1" = nocap ] && l="${l%%=*}=" ;;
    esac
    printf '%s\n' "$l"
  done <<EOF
$(sed -n '/^\[Service\]/,/^\[/p' "${KEYED_UNIT:-$UNIT}" | grep -E '^[A-Za-z]+=')
EOF
}
UNIT_SEQ=0
unit_run() { # <variant> <command...>: one run under the unit's properties; output in $uout, status in $urc,
  # and the transient unit's name in $uname, so a control can read its exit status from the journal
  _v=$1; shift
  UNIT_SEQ=$((UNIT_SEQ + 1)); uname="whisper-edge-keyed-gate-$$-$UNIT_SEQ"
  _props=$(unit_props "$_v")
  _args=""
  while IFS= read -r p; do _args="$_args|-p|$p"; done <<EOF
$_props
EOF
  _o=$(IFS='|'; set -f
       # shellcheck disable=SC2086
       sudo -n systemd-run --quiet --wait --pipe --collect --unit="$uname" ${_args#|} \
         -E WHISPER_EDGE_ETC="$R/etc" -E WHISPER_EDGE_DIR="$R/lib" -E WHISPER_EDGE_BASE="$BASE" \
         -E WHISPER_EDGE_TEST_LOOPBACK=1 -E CURL_CA_BUNDLE="$R/ca.pem" -E PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
         -E WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$R/lib/hooks" "$@" 2>&1) && urc=0 || urc=$?
  uout=$_o
}
unit_journal() { sudo -n journalctl --no-pager -o cat -u "$uname" 2>/dev/null; }
rword() { "$TSC" --dir "$R/lib" --state "$R/etc/state" --plane-check "$PLANE_CHECK" 2>/dev/null | tail -1; }
root_run() { # a run as root outside the unit (the installer, or a person)
  sudo -n env WHISPER_EDGE_ETC="$R/etc" WHISPER_EDGE_DIR="$R/lib" WHISPER_EDGE_BASE="$BASE" WHISPER_EDGE_TEST_LOOPBACK=1 \
    CURL_CA_BUNDLE="$R/ca.pem" PATH="/usr/sbin:/usr/bin:/sbin:/bin" WHISPER_EDGE_REFRESH_TEST_HOOK_DIR="$R/lib/hooks" \
    "$R/sbin/whisper-edge-refresh" "$@" 2>&1
}

# row 75: a tenant.bin made immutable by a root run, revoked by the unit
rb_reset "$REFRESH"; cfg '{}'; content a "$G0" "$REV0"; root_run --keyed-set > "$W/rootrun" || true
attr=$(lsattr -d "$R/lib/tenant.bin" 2>/dev/null | cut -c1-20)
case "$attr" in
  *i*) pass "row 75: the precondition: lsattr shows the root-installed tenant.bin immutable ($attr)" ;;
  *) fail "row 75: this filesystem must carry the immutable attribute for the row to mean anything (never a skip)" "$attr $(cat "$W/rootrun")" ;;
esac
cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"
# one address under the unit: the first observation is the previous scheduled poll's, 1,000 s ago
seen_root() { printf 'ag_gateFeedKey000001 KEY_REVOKED %s %s\n' "$NODE_A" "$(( $(date +%s) - 1000 ))" | sudo -n tee "$R/lib/.revocation-seen" > /dev/null; }
seen_root
unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" = 0 ] && [ ! -e "$R/lib/tenant.bin" ] && [ -e "$R/lib/.tenant-tombstone" ] && [ "$(cat "$R/etc/state/tenant.high-water")" = "$G0" ] \
  && [ "$(rword)" = revoked ]; } \
  && pass "row 75: under the keyed unit's properties the revocation unlinks the immutable plane, writes the tombstone and the mark, exit 0" \
  || fail "row 75: revocation under the real unit" "rc=$urc $uout"
unit_run shipped /bin/sh -c "echo x > $R/etc/policy.conf"; pol=$urc; pol_out=$uout
unit_run shipped /bin/chmod 0644 "$R/etc/key"; km=$urc
{ [ "$pol" != 0 ] && says "$pol_out" 'Read-only file system' && [ "$km" != 0 ] && [ "$(sudo -n stat -c %a "$R/etc/key")" = 600 ]; } \
  && pass "row 75: the same sandbox cannot write /etc/whisper-edge/policy.conf (EROFS) or change the key file's mode" \
  || fail "row 75: the unit's confinement" "policy=$pol $pol_out key=$km"
rb_reset "$REFRESH"; cfg '{}'; root_run --keyed-set > /dev/null || true; cfg "{'keys': {'FEED': 'KEY_REVOKED'}}"
seen_root
unit_run nocap "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" != 0 ] && [ -e "$R/lib/tenant.bin" ]; } \
  && pass "row 75 control: the unit's exact properties with only the capability emptied fail the unlink (EPERM) and the plane stays" \
  || fail "row 75 control: CAP_LINUX_IMMUTABLE is what removes it" "rc=$urc $uout"
unit_run wholedir /bin/sh -c "echo x > $R/etc/policy.conf"
[ "$urc" = 0 ] && pass "row 75 control: a whole-directory ReadWritePaths lets the policy write through" \
               || fail "row 75 control: the narrow path is what refuses it" "$uout"

# row 75: the tenant install under an empty bounding set cannot set the immutable attribute, and the
# journal says why under --quiet, naming the capability as well as the filesystem. The control is the
# refresh with that one line reverted to the old say(), which --quiet silences: the row must fail it.
TIMM="could not set the immutable attribute on $R/lib/tenant.bin (a missing capability or an unsupported filesystem); installed without it"
tenant_imm_row() { # <refresh>: sets ti_ok to yes when the run installs without the attribute and says so
  rb_reset "$1"; cfg '{}'
  unit_run nocap "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
  ti_ok=no
  if [ "$urc" = 0 ] && sudo -n test -e "$R/lib/tenant.bin"; then
    case "$(sudo -n lsattr -d "$R/lib/tenant.bin" 2>/dev/null | cut -d' ' -f1)" in
      *i*) ;;
      *) if grep -qxF -- "$TIMM" <<EOF
$uout
EOF
         then ti_ok=yes; fi ;;
    esac
  fi
}
tenant_imm_row "$REFRESH"
[ "$ti_ok" = yes ] \
  && pass "row 75: with the capability emptied a tenant install has no immutable attribute, and the --quiet journal says so, naming a missing capability" \
  || fail "row 75: the tenant install's attribute line" "rc=$urc $uout"
# the refresh's own two lines, matched literally, $TPLANE and all
# shellcheck disable=SC2016
python3 "$HERE/testdata/revert-line.py" "$REFRESH" "$W/refresh-tenant-say" \
  '      || rpz_event "could not set the immutable attribute on $TPLANE (a missing capability or an unsupported filesystem); installed without it"' \
  '      || say "this filesystem cannot set the immutable attribute on $TPLANE; installed without it"'
chmod +x "$W/refresh-tenant-say"
if cmp -s "$REFRESH" "$W/refresh-tenant-say"; then
  fail "row 75 control: the tenant line's revert" "the edit did not apply to $REFRESH, so it proves nothing"
else
  tenant_imm_row "$W/refresh-tenant-say"
  [ "$ti_ok" = no ] \
    && pass "row 75 control: the tenant install's old line, through say(), leaves the --quiet journal silent and fails the same check" \
    || fail "row 75 control: the revert is caught" "$uout"
fi

# row 73: a missing state directory is recreated before the sandbox is set up
rb_reset "$REFRESH"; cfg '{}'; sudo -n rm -rf "$R/etc/state"; rm -f "$F/requests.log"
unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" = 0 ] && [ -d "$R/etc/state" ] && [ "$(nreq path=/edge/k/manifest.json)" -ge 1 ] \
  && [ "$(cat "$R/etc/state/tenant.installed" 2>/dev/null)" = "$G0" ]; } \
  && pass "row 73: with the state directory removed, the shipped unit's ExecStartPre recreates it, the run polls, and the main process writes tenant.installed into it" \
  || fail "row 73: ExecStartPre" "rc=$urc $uout"
sudo -n rm -rf "$R/etc/state"
unit_run nominus "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" != 0 ] && [ ! -d "$R/etc/state" ] && [ "$(unit_journal | grep -c 'status=226/NAMESPACE')" -gt 0 ]; } \
  && pass "row 73 control: the shipped state path without its '-' fails the unit with status 226/NAMESPACE (from the journal) before even the ExecStartPre recreates it" \
  || fail "row 73 control: a missing ReadWritePaths entry fails the unit with 226" "rc=$urc $uout $(unit_journal | tail -3)"
# the unit as shipped is what the arm ran: a copy of it without the '-' fails the same arm
sed 's| -/etc/whisper-edge/state| /etc/whisper-edge/state|' "$UNIT" > "$W/unit-nominus.service"
sudo -n rm -rf "$R/etc/state"
KEYED_UNIT="$W/unit-nominus.service" unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" != 0 ] && [ ! -d "$R/etc/state" ]; } \
  && pass "row 73 control: a unit file shipped without the '-' fails the shipped arm (the arm reads the unit, not a copy of its lines)" \
  || fail "row 73 control: the arm follows the unit file" "rc=$urc"
sudo -n rm -rf "$R/etc/state"; content a "$((G0 + 1))" "$REV0"
unit_run nopre "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" != 0 ] && [ ! -d "$R/etc/state" ] && [ "$(gen_of "$R/lib/tenant.bin")" != "$((G0 + 1))" ]; } \
  && pass "row 73 control: without the ExecStartPre the state directory stays missing and the run fails before it installs" \
  || fail "row 73 control: the ExecStartPre is what recreates it" "rc=$urc $uout"

# row 61: under the unit, a 0644 key is refused with the revoke advice and its mode is left alone
rb_reset "$REFRESH"; cfg '{}'; sudo -n chmod 0644 "$R/etc/key"; rm -f "$F/requests.log"
unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" != 0 ] && says "$uout" 'this key may have been read by another user' && [ "$(sudo -n stat -c %a "$R/etc/key")" = 644 ] \
  && [ "$(nreq)" = 0 ]; } \
  && pass "row 61: under the keyed unit a 0644 key is refused with the revoke advice, no keyed request is made and its mode is unchanged" \
  || fail "row 61: the unit and an exposed key" "rc=$urc $uout"
sudo -n chmod 0600 "$R/etc/key"; unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set
{ [ "$urc" = 0 ] && [ -e "$R/lib/tenant.bin" ]; } && pass "row 61 control: the same unit with a 0600 key is silent and installs" \
                                             || fail "row 61 control: a 0600 key works under the unit" "rc=$urc $uout"

# row 117: no run removes another run's header file
overlap() { # <script>
  rb_reset "$1"; content a "$((G0 + 1))" "$REV0"; rm -f "$F/requests.log" "$F/state.json"
  # the manual run's tenant.bin request is refused (once), so it exits keeping everything and the
  # request that installs is the timer run's own, made after the manual run's exit
  cfg "{'rules': [{'path': 'tenant.bin', 'status': 503, 'code': 'busy', 'times': 1}]}"
  sudo -n touch "$R/lib/hooks/after-manifest.wait"
  ( unit_run shipped "$R/sbin/whisper-edge-refresh" --quiet --keyed-set; echo "$urc" > "$W/unit.rc" ) &
  UB=$!
  i=0; while ! sudo -n test -e "$R/lib/hooks/after-manifest.reached" && [ "$i" -lt 300 ]; do i=$((i+1)); sleep 0.1; done
  sudo -n rm -f "$R/lib/hooks/after-manifest.wait"
  root_run --keyed-set > "$W/manual" || true
  before=$(nreq path=/edge/k/tenant.bin known_key=True)
  sudo -n touch "$R/lib/hooks/after-manifest.go"; wait "$UB" || true
  after=$(nreq path=/edge/k/tenant.bin known_key=True)
}
overlap "$REFRESH"
{ [ "$(cat "$W/unit.rc")" = 0 ] && [ "$after" -gt "$before" ] \
  && [ "$(gen_of "$R/lib/tenant.bin")" = "$((G0 + 1))" ]; } \
  && pass "row 117: a manual run that exits while the timer run is between two requests leaves the timer's header file: its next request carries the key" \
  || fail "row 117: the header file is the run's own" "unit=$(cat "$W/unit.rc") $(cat "$W/manual")"
M=$(mutant shared-header '  T=$(mktemp -d) || plane_failed "cannot create a temporary directory"
  # shellcheck disable=SC2317
  keyed_cleanup() {' '  T="$DIR/.keyed-run"; mkdir -p "$T"; rm -f "$T/h"
  # shellcheck disable=SC2317
  keyed_cleanup() {')
overlap "$M"
{ [ "$after" = "$before" ] && [ ! -e "$R/lib/tenant.bin" ]; } \
  && pass "row 117 control: a header file at one shared path is removed by the manual run's exit, and the timer run's next request never carries the key" \
  || fail "row 117 control: the shared path is visible" "$(cat "$W/manual")"
cfg '{}'
}

# ===================================================================================================
# Row 116, the client's half: a signature is paired with the revision it signs by
# Whisper-Edge-Plane, and If-Match goes only on tenant.bin. The fake feed implements the feed responder's
# pairing rules (a signature's ETag is "<sha>.<16 hex>", If-Match strict on every name, the pairing header
# quoted or bare, 412 with a body on a mismatch), so a client that pairs signatures by If-Match fails here as
# it fails against the responder.
row116() {
pair_case() { # <script>
  installed_box; content a "$((G0 + 1))" "$REV0"; rm -f "$F/requests.log" "$D/.refresh-failures.tenant"
  run_with "$1" --keyed-set
}
pair_case "$REFRESH"
psha=$(sha256sum < "$F/content/a/tenant.bin" | cut -d' ' -f1)
msha=$(sha256sum < "$F/content/a/manifest.json" | cut -d' ' -f1)
{ [ "$rc" = 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$((G0 + 1))" ] \
  && [ "$(nreq path=/edge/k/manifest.json.sig if_match=None "pairing=\"$msha\"")" = 1 ] \
  && [ "$(nreq path=/edge/k/tenant.bin.sig if_match=None "pairing=\"$psha\"")" = 1 ] \
  && [ "$(nreq path=/edge/k/tenant.bin "if_match=\"$psha\"" pairing=None)" = 1 ]; } \
  && pass "row 116: both signatures are paired by Whisper-Edge-Plane with no If-Match, tenant.bin by If-Match, and the plane installs under the responder's rules" \
  || fail "row 116: the client's pairing" "rc=$rc gen=$(gen_of "$D/tenant.bin") $(reqs | tail -4) $out"
M=$(mutant ifmatch-on-sig '    kreq manifest.json.sig "$T/m.sig" "$PIN_ADDR" -H "Whisper-Edge-Plane: \"$msha\""' '    kreq manifest.json.sig "$T/m.sig" "$PIN_ADDR" -H "If-Match: \"$msha\""')
pair_case "$M"
{ [ "$rc" != 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] && [ "$(nreq path=/edge/k/manifest.json.sig)" = 2 ] \
  && says "$out" "answered 412 on the re-run too" && [ "$(cat "$D/.refresh-failures.tenant" 2>/dev/null)" = 1 ]; } \
  && pass "row 116 control: a client pairing a signature by If-Match meets 412 twice, alarms, counts a failure and keeps its plane" \
  || fail "row 116 control: If-Match on a signature fails closed and loudly" "rc=$rc gen=$(gen_of "$D/tenant.bin") $out"
cfg '{}'
}

# ===================================================================================================
# The keyed download cap: an answer of unknown size (no Content-Length) past
# its cap, from a curl that ignores --max-filesize on such an answer (before 8.4.0, emulated by the shim dropping
# the option), is cut by the script's own byte count: the run fails as curl 63 keeping everything, and stops
# reading a 64 MiB answer (the server's count includes what the loopback socket buffers took, several MiB under
# load, so the bound is half the answer, not the cap). The control: without the byte count it reads all of it.
rowcap() {
cap_case() { # <script>
  installed_box; content a "$((G0 + 1))" "$REV0"; rm -f "$F/requests.log"; : > "$W/curl.old"
  cfg "{'rules': [{'path': 'manifest.json', 'action': 'flood', 'bytes': 67108864}]}"
  run_with "$1" --keyed-set
  rm -f "$W/curl.old"
  sent=$(reqs | python3 -c 'import json,sys
print(max([json.loads(l).get("flood_sent", 0) for l in sys.stdin] or [0]))')
}
cap_case "$REFRESH"
{ [ "$rc" != 0 ] && [ "$(gen_of "$D/tenant.bin")" = "$G0" ] && [ "$sent" -lt 33554432 ] && says "$out" 'curl 63'; } \
  && pass "keyed cap: a 64 MiB manifest of unknown size from a curl that ignores --max-filesize is cut at its 1 MiB cap (curl 63; the server wrote $sent bytes before the reader stopped), and the run keeps everything" \
  || fail "keyed cap: the script's own byte count" "rc=$rc sent=$sent $out"
M=$(mutant no-byte-cap '"$BASE/k/$_name" 2>"$T/cerr"; echo "$?" > "$T/krc"; } | head -c "$((_cap + 1))" > "$_out"' '"$BASE/k/$_name" 2>"$T/cerr"; echo "$?" > "$T/krc"; } | cat > "$_out"')
cap_case "$M"
[ "$sent" -ge 67108864 ] && pass "keyed cap control: without the byte count the same curl takes all $sent bytes" \
                       || fail "keyed cap control: the byte count is what cuts it" "sent=$sent"
cfg '{}'
}

# ---- run them -------------------------------------------------------------------------------------------
# KEYED_GATE_ROWS="57 58" runs a subset while a row is being worked on; the gate runs them all, and a
# subset never reads as the gate: it says SUBSET by name and exits 77, which install-gate.sh reports as
# INCOMPLETE.
if [ -n "${KEYED_GATE_ROWS:-}" ]; then SKIPPED="${SKIPPED}every row but the subset KEYED_GATE_ROWS=\"$KEYED_GATE_ROWS\"; "; fi
# The gate's own exits: a non-zero exit always carries a FAIL or NOT PROVEN line. A child run of this file
# with an unguarded failure planted in its setup, and one planted inside a row, must each exit non-zero
# and say so; the control suppresses the trap's line, and the same check must then call the exit silent.
rowverdict() {
  _named() { # <plant> -> "rc|named" or "rc|silent"
    _o=$(env KEYED_GATE_PLANT_ABORT="$1" sh "$0" 2>&1) && _r=0 || _r=$?
    if [ "$(printf '%s\n' "$_o" | grep -cE '^  (FAIL  |NOT PROVEN: )')" -gt 0 ]; then echo "$_r|named"; else echo "$_r|silent"; fi
  }
  _s=$(_named setup); _w=$(_named row); _c=$(_named silent)
  { [ "${_s#*|}" = named ] && [ "${_s%|*}" != 0 ]; } \
    && pass "the gate's exits: a setup stop exits ${_s%|*} and prints its NOT PROVEN or FAIL line" \
    || fail "the gate's exits: a setup stop is named" "$_s"
  { [ "${_w#*|}" = named ] && [ "${_w%|*}" != 0 ]; } \
    && pass "the gate's exits: an unguarded failure inside a row exits ${_w%|*} and names the row" \
    || fail "the gate's exits: a failure inside a row is named" "$_w"
  { [ "${_c#*|}" = silent ] && [ "${_c%|*}" != 0 ]; } \
    && pass "the gate's exits control: with the trap's line suppressed the same check reads the exit as silent" \
    || fail "the gate's exits control: the check can fail" "$_c"
}

ALL_ROWS="verdict 54 55 56 56b 56c 57 57b 58 58b 59 60 61 63 74 74b 74c 77 86 94 95 96 105 116 120 cap 120b 62 bounds unit env scrub"
# every row this file defines runs, and every row that runs is defined: a row added without its place in
# the list would otherwise pass by never running
defined_=$(sed -n 's/^row\([0-9a-z]*\)() {$/\1/p' "$0" | sort | tr '\n' ' ')
listed_=$(printf '%s\n' $ALL_ROWS | sort | tr '\n' ' ')
[ "$defined_" = "$listed_" ] && pass "the run list is exactly the rows this file defines (${ALL_ROWS})" \
                             || fail "the run list and the defined rows differ" "defined: $defined_/ listed: $listed_"
{ cat "$0"; printf 'rowzz() {\n}\n'; } > "$W/rows.copy"
[ "$(sed -n 's/^row\([0-9a-z]*\)() {$/\1/p' "$W/rows.copy" | sort | tr '\n' ' ')" != "$listed_" ] \
  && pass "control: a row defined but not listed makes the two differ" || fail "control: the run-list check can fail" ""
KG_START=$(date +%s)
for r in ${KEYED_GATE_ROWS:-$ALL_ROWS}; do CUR_ROW=$r; "row$r"; done
VERDICT=printed

if [ -n "${KEYED_GATE_ROWS:-}" ]; then
  printf '\n=== keyed gate SUBSET (rows %s only, not the keyed gate): %d ok, %d failed ===\n' "$KEYED_GATE_ROWS" "$ok" "$bad"
else
  printf '\n=== keyed gate: %d ok, %d failed ===\n' "$ok" "$bad"
fi
printf 'the rows took %d s (load average %s)\n' "$(( $(date +%s) - KG_START ))" "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)"
[ -n "${KEYED_GATE_ROWS:-}" ] && printf 'SUBSET: only rows %s ran; this is not the keyed gate\n' "$KEYED_GATE_ROWS"
[ -n "$SKIPPED" ] && printf 'SKIPPED, and not counted as passing: %s\n' "$SKIPPED"
[ "$bad" = 0 ] || exit 1
[ -z "$SKIPPED" ] || exit 77
exit 0
