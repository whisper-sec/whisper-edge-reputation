#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# The tenant plane's state on an edge, derived from its disk the one way the module derives it, and the
# oracle's case written from it.
#
# The predicate, in this precedence, over three files read under one shared flock on the plane directory:
#   1. ARMED when tenant.bin exists, the loader accepts it (structure, digest, plane id 8) and its
#      generation is above the high-water value, or there is no high-water file: fresh, or stale once
#      past valid_until_ms (0 is no bound).
#   2. REVOKED when the tombstone exists, whatever it holds, or when an accepted tenant.bin sits at or
#      below the high-water value.
#   3. NULL otherwise, a high-water file alone included.
#   4. A tenant.bin the loader refuses is no transition: "refused", and no case.
#   5. A high-water file that is not [1-9][0-9]{0,18} and a newline is no transition either:
#      "malformed", no case, and a failure naming the file. The grammar alone decides here, never a
#      clock: the module has none, and the two readers must agree.
# The feed-name table, .tenant-id and .tenant-rev are the refresh's install-time gates; no term here
# reads them.
#
# With --module-status it compares against the module's report (state, armed generation, mark, the
# time of its last completed reload read) and writes the case only once they agree: the module armed
# at tenant.bin's own generation, or REVOKED with a last completed read at or after the latest mtime
# among the files present, or NULL. Until then it prints "converging" and asks again every 5 s, up to
# --wait seconds (the module's reload tick plus 30 s), then fails naming the cause and both generations.
#
# Usage:
#   tenant-state-case.sh [--dir DIR] [--state DIR] [--plane-check PATH] [--now-ms MS] [--no-lock]
#       [--last FILE] [--module-status FILE] [--wait S] [--case-template FILE] [--case-out FILE]
#       [--oracle policy_ref.py]
#
# The first line of output is the word: fresh, stale, null, revoked, refused, malformed or converging.
# Exit 0 with a word (and the case, when one was asked for), 3 malformed, 4 refused, 5 still converging
# after the wait, 2 usage or a missing reader.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIR=/var/lib/whisper-edge
STATE=/etc/whisper-edge/state
PLANE_CHECK=""
NOW_MS=""
LOCK=1
LAST=""
MODULE=""
WAIT=90
TEMPLATE=""
CASE_OUT=""
ORACLE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift ;;
    --state) STATE="$2"; shift ;;
    --plane-check) PLANE_CHECK="$2"; shift ;;
    --now-ms) NOW_MS="$2"; shift ;;
    --no-lock) LOCK=0 ;;
    --last) LAST="$2"; shift ;;
    --module-status) MODULE="$2"; shift ;;
    --wait) WAIT="$2"; shift ;;
    --case-template) TEMPLATE="$2"; shift ;;
    --case-out) CASE_OUT="$2"; shift ;;
    --oracle) ORACLE="$2"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "tenant-state-case.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$PLANE_CHECK" ]; then
  if [ -x "$HERE/../core/plane_check" ]; then PLANE_CHECK="$HERE/../core/plane_check"
  else PLANE_CHECK=$(command -v plane_check || true); fi
fi
[ -n "$PLANE_CHECK" ] && [ -x "$PLANE_CHECK" ] || { echo "tenant-state-case.sh: no plane_check (make -C $(cd "$HERE/../core" 2>/dev/null && pwd || echo core) plane_check)" >&2; exit 2; }

PLANE="$DIR/tenant.bin"
TOMB="$DIR/.tenant-tombstone"
HW="$STATE/tenant.high-water"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# One read of the three files: the high-water value (grammar only), the tombstone's presence, and
# tenant.bin's acceptance, generation, validity and ranges, all taken while the shared lock is held.
derive() {
  python3 - "$HW" "$TOMB" "$PLANE" > "$T/files" <<'PY'
import os, re, struct, sys
hw, tomb, plane = sys.argv[1:4]
def mtime_ms(p):
    try:
        return int(os.stat(p).st_mtime * 1000)
    except OSError:
        return 0
try:
    b = open(hw, "rb").read(64)
    if re.match(rb"^[1-9][0-9]{0,18}\n$", b) and int(b) <= 2 ** 63 - 1:
        print("hw ok", int(b), mtime_ms(hw))
    else:
        print("hw bad - %d" % mtime_ms(hw))
except FileNotFoundError:
    print("hw absent - 0")
print("tomb", "present" if os.path.lexists(tomb) else "absent", mtime_ms(tomb))
try:
    h = open(plane, "rb").read(40)
    g, vu = struct.unpack_from("<Q", h, 16)[0], struct.unpack_from("<Q", h, 32)[0]
    print("plane present", g, vu, mtime_ms(plane))
except (OSError, struct.error):
    print("plane absent 0 0 0")
PY
  if [ -e "$PLANE" ]; then
    "$PLANE_CHECK" --dump "$PLANE" > "$T/ranges" 2>/dev/null && echo accepted > "$T/loader" || echo refused > "$T/loader"
  else
    echo absent > "$T/loader"
  fi
}
if [ "$LOCK" = 1 ]; then
  if ! { exec 8< "$DIR"; } 2>/dev/null; then echo "tenant-state-case.sh: cannot open $DIR" >&2; exit 2; fi
  if ! flock -n -s 8; then
    # a refresh holds the directory: the reader keeps the state it last published
    if [ -n "$LAST" ] && [ -s "$LAST" ]; then head -1 "$LAST"; exit 0; fi
    echo "tenant-state-case.sh: $DIR is locked by a refresh and there is no last state to keep" >&2; exit 2
  fi
  derive
  flock -u 8; exec 8<&-
else
  derive
fi

read -r _ HW_ST HW_V HW_MT < <(sed -n 1p "$T/files")
read -r _ TOMB_ST TOMB_MT < <(sed -n 2p "$T/files")
read -r _ _ P_GEN P_VU P_MT < <(sed -n 3p "$T/files")
LOADER=$(cat "$T/loader")
[ -n "$NOW_MS" ] || NOW_MS=$(( $(date +%s) * 1000 ))

if [ "$HW_ST" = bad ]; then
  echo malformed
  echo "tenant-state-case.sh: $HW is malformed (not one generation, [1-9][0-9]{0,18} and a newline): no case" >&2
  exit 3
fi
if [ "$LOADER" = refused ]; then
  echo refused
  echo "tenant-state-case.sh: the loader refuses $PLANE: no transition, no case" >&2
  exit 4
fi
WORD=null
if [ "$LOADER" = accepted ] && { [ "$HW_ST" = absent ] || [ "$P_GEN" -gt "$HW_V" ]; }; then
  if [ "$P_VU" = 0 ] || [ "$NOW_MS" -le "$P_VU" ]; then WORD=fresh; else WORD=stale; fi
elif [ "$TOMB_ST" = present ] || [ "$LOADER" = accepted ]; then
  WORD=revoked
fi

if [ -n "$MODULE" ]; then
  # contract 4: the module's published state, armed generation, mark and last completed reload read
  deadline=$(( $(date +%s) + WAIT ))
  while :; do
    M_STATE=$(awk '$1 == "state" { print $2 }' "$MODULE" 2>/dev/null)
    M_GEN=$(awk '$1 == "generation" { print $2 }' "$MODULE" 2>/dev/null)
    M_READ=$(awk '$1 == "read_ms" { print $2 }' "$MODULE" 2>/dev/null)
    LATEST=0
    for m in "$HW_MT" "$TOMB_MT" "$P_MT"; do [ "${m:-0}" -gt "$LATEST" ] && LATEST=$m; done
    case "$WORD" in
      fresh|stale) [ "$M_STATE" = armed ] && [ "$M_GEN" = "$P_GEN" ] && break ;;
      revoked) [ "$M_STATE" = revoked ] && [ "${M_READ:-0}" -ge "$LATEST" ] && break ;;
      null) [ "$M_STATE" = null ] && break ;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo converging
      echo "tenant-state-case.sh: the disk reads $WORD (tenant.bin generation ${P_GEN}) and the module reports ${M_STATE:-nothing} (generation ${M_GEN:-none}, last read ${M_READ:-never}, files changed at $LATEST): no case" >&2
      exit 5
    fi
    echo converging
    sleep 5
  done
fi

echo "$WORD"
[ -n "$LAST" ] && printf '%s\n' "$WORD" > "$LAST"
if [ -n "$TEMPLATE" ]; then
  out="${CASE_OUT:-$T/case}"
  python3 - "$TEMPLATE" "$T/ranges" "$WORD" "$NOW_MS" "$P_VU" > "$out" <<'PY'
import ipaddress, sys
tpl, ranges, word, now_ms, vu = sys.argv[1:6]
rs = []
try:
    for line in open(ranges):
        f = line.split()
        if len(f) == 4 and f[0] in ("4", "6"):
            rs.append((ipaddress.ip_address(f[1]), ipaddress.ip_address(f[2]), int(f[3])))
except OSError:
    pass
lines = [l.rstrip("\n") for l in open(tpl)]
body = [l for l in lines if l.strip() != "end"]
who = [l.split()[1:3] for l in body if l.startswith("addr ")]
body += ["conf floor 3 0", "conf ctx 3 0"]
if word in ("fresh", "stale"):
    body.append("tenant %s %s %s" % (word, now_ms, vu))
else:
    body.append("tenant %s %s 0" % (word, now_ms))
for side, addr in who:
    a = ipaddress.ip_address(addr)
    hit = [fl for lo, hi, fl in rs if word in ("fresh", "stale") and lo.version == a.version and lo <= a <= hi]
    body.append("rec %s tenant flags=%d source=1 reason=0" % (side, hit[0]) if hit else "rec %s tenant none" % side)
body.append("end")
print("\n".join(body))
PY
  if [ -n "$ORACLE" ]; then
    python3 "$ORACLE" --cases "$out" | grep '^verdict '
  fi
fi
exit 0
