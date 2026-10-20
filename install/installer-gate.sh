#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Prove install.sh: the default policy it carries, the files it renders, what it says, and what it does
# to a box, against a local stub feed signed with a throwaway key.
#
# Two kinds of row. The rendering and dry-run rows need no root and run anywhere: they drive the
# installer's render hook and --dry-run with every path redirected into the gate's own work tree. The
# rows that drive a real run need root, because the installer refuses every run but a dry one without
# it; on a host without root they say SKIPPED with that reason and the verdict is INCOMPLETE, never
# CLEAR over rows that did not run. The certifying run is a disposable root guest.
#
# Each row names its negative control, and a control that cannot fail is not a control: the controls
# here run the same check over a planted defect and must see it fail.
#
# INSTALLER_GATE_INSTALL points the gate at another copy of the installer (a control), and
# INSTALLER_GATE_ROWS names a subset of the rows to run (space-separated, e.g. "render dry").
# shellcheck disable=SC2015
set -eu
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }
umask 022
# A gate that stops under set -e before its verdict must say where. Under bash (the gate re-runs itself
# there when it has one, in POSIX mode, so the script is the same) an ERR trap records the line of the
# command that failed, inherited by functions (-E); the EXIT trap below names the last row that
# finished and that line. Without bash the row is still named and the line is said to be unknown.
if [ -z "${BASH_VERSION:-}" ] && [ "${INSTALLER_GATE_NO_BASH:-0}" != 1 ] && command -v bash >/dev/null 2>&1; then
  exec bash --posix "$0" "$@"
fi
GATE_ERR_LINE=""; LAST_ROW="(none: it stopped before the first row)"; ok=0; bad=0
# shellcheck disable=SC3041,SC3047 # bash only, and guarded: -E and the ERR trap run under bash alone
if [ -n "${BASH_VERSION:-}" ]; then set -E; trap 'GATE_ERR_LINE=$LINENO' ERR; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL="${INSTALLER_GATE_INSTALL:-$HERE/install.sh}"
POLICY="$HERE/../core/testdata/policy/default.conf"
ROWS="${INSTALLER_GATE_ROWS:-render dry real server}"
for WBASE in "${INSTALL_GATE_TMP:-}" "${XDG_RUNTIME_DIR:-}" "${HOME:-}" "${TMPDIR:-/tmp}"; do
  [ -n "$WBASE" ] && [ -d "$WBASE" ] && [ -O "$WBASE" ] && break
  WBASE=""
done
[ -n "$WBASE" ] || { echo "installer gate: no directory this user owns for the work tree (set INSTALL_GATE_TMP)" >&2; exit 2; }
W="$(mktemp -d "$WBASE/whisper-edge-installer-gate.XXXXXX")"
stop_servers() {
  if [ -f "$W/servers.pid" ]; then xargs kill < "$W/servers.pid" 2>/dev/null || true; fi
  rm -f "$W/servers.pid"
}
cleanup() {
  _crc=$?
  if [ -n "${CLEAN_RC:-}" ]; then _crc=$CLEAN_RC; fi
  # a gate that ends before its verdict says where: the last row that finished, the line that failed,
  # and the last installer report it saw; and it never ends 0 or 77 that way
  if [ "${VERDICT:-0}" = 0 ]; then
    case "$_crc" in 0|77) _crc=1 ;; esac
    printf '\nINSTALLER GATE: ENDED EARLY after "%s" (exit %s, line %s) with %s ok, %s failed\n' "$LAST_ROW" "$_crc" "${GATE_ERR_LINE:-unknown}" "$ok" "$bad"
    printf 'the last installer report it kept:\n' >&2
    tail -n 40 "$W/last" 2>/dev/null | sed 's/^/  | /' >&2 || :
  fi
  # every report the run saw, kept where the caller asked, for reading a failure after the box is gone
  if [ -n "${INSTALLER_GATE_KEEP_REPORTS:-}" ] && [ -f "$W/reports" ]; then cp "$W/reports" "$INSTALLER_GATE_KEEP_REPORTS" 2>/dev/null || true; fi
  stop_servers
  # this run's own counter drop-ins (they name its work directory, which goes next)
  if [ "$(id -u)" = 0 ]; then
    for _dc in /etc/systemd/system/nginx.service.d/zz-installer-gate-count.conf /etc/systemd/system/apache2.service.d/zz-installer-gate-count.conf /etc/systemd/system/httpd.service.d/zz-installer-gate-count.conf; do
      if [ -f "$_dc" ] && grep -qF -- "$W/" "$_dc"; then rm -f -- "$_dc"; _dcr=1; fi
    done
    if [ -n "${_dcr:-}" ] && [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
  fi
  # the pause point's FIFO and markers, whatever row was holding them: a FIFO left behind blocks the next
  # reader that opens it without a writer
  if [ -n "${PAUSE_DIR:-}" ]; then rm -f "$PAUSE_DIR/pause" "$PAUSE_DIR"/at.* 2>/dev/null || :; fi
  chattr -R -i "$W" 2>/dev/null || true
  rm -rf "$W" 2>/dev/null || true
  if [ -e "$W" ]; then printf 'installer gate: could not remove %s\n' "$W" >&2; exit 1; fi
  if [ "${VERDICT:-0}" = 0 ]; then exit "$_crc"; fi
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
SKIPPED=""
pass() { printf '  ok    %s\n' "$1"; ok=$((ok+1)); LAST_ROW=$1; }
fail() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; bad=$((bad+1)); LAST_ROW=$1; }
skip() { LAST_ROW=$1; printf '  SKIP  %s: %s\n' "$1" "$2"; SKIPPED="$SKIPPED$1 ($2); "; SKIPNAMES="${SKIPNAMES:-}$1
"; }
POS=""
pos_pass() { POS="$POS $1"; pass "$2"; }
# A control is keyed by its arm's name (nginx-apply, ols-apply, nginx-c7, ...): one passing positive
# control admits every negative arm of that name after it in the run. That is coarser than "the same
# fixture for every arm": the arms share the control's server and data, not each its own fixture.
neg() { case " $POS " in *" $1 "*) pass "$2" ;; *) fail "$2" "no positive control ($1) passed before it in this run, so this negative arm proves nothing"; esac; }
# a condition the rows wait on, never a fixed sleep: up to <seconds> (60 or more), polled each second
wait_until() { # <seconds> <command...> -> 0 once the command succeeds, 1 at the ceiling
  _wu_n=$1; shift; _wu_i=0
  while [ "$_wu_i" -lt "$_wu_n" ]; do "$@" && return 0; sleep 1; _wu_i=$((_wu_i + 1)); done
  return 1
}
masters_up() { ps -eo args= | grep_any -E '^(nginx: master process|/usr/sbin/(apache2|httpd)( |$)|openlitespeed \(lshttpd - main\)$)'; }
master_of() { ps -eo args= | grep_any -E "^($1)"; } # <regex of the master's process title>
no_masters() { ! masters_up; }
# A unit command the gate runs to set a row up or put it back: when it fails, a row named for it fails and
# the run goes on; it never ends the run under set -e (testdata/and-tail.py holds every such call to this)
unit_do() { # <verb> <unit>
  [ "$SYSD" = 1 ] || return 0
  _ud=$(systemctl "$1" "$2" 2>&1) || fail "systemctl $1 $2" "$(printf '%s' "$_ud" | head -2)"
  return 0
}
daemon_reload() { [ "$SYSD" = 1 ] || return 0; _ud=$(systemctl daemon-reload 2>&1) || fail "systemctl daemon-reload" "$_ud"; return 0; }
# A unit started after a master the gate started by hand: that master's pid file is the unconfined
# shell's (on SELinux, var_run_t), which the confined unit cannot open, so a start fails on it. When no
# master runs, the stale file goes first, and its directory's labels are put back where SELinux is on.
unit_start_after_hand() { # <unit> <pid file>
  if ! ps -eo args= | grep_any '^nginx: master'; then rm -f "$2"; fi
  command -v restorecon >/dev/null 2>&1 && restorecon -F "$(dirname "$2")" 2>/dev/null || :
  unit_do start "$1"
}
# Every arm that mounts runs with these: the host's mount table (how many, /proc there, selinuxfs there) and
# SELinux's mode, taken before and after, must be the same. A recursive bind of / under systemd's shared
# propagation, unmounted recursively, takes /proc, selinuxfs and devpts off the host with it.
mount_state() {
  printf 'mounts=%s %s %s enforce=%s' "$(grep -c '' /proc/self/mounts 2>/dev/null || echo 0)" \
    "$([ -r /proc/self/mounts ] && echo proc || echo no-proc)" \
    "$(grep -q ' selinuxfs ' /proc/self/mounts 2>/dev/null && echo selinuxfs || echo no-selinuxfs)" \
    "$(getenforce 2>/dev/null || echo none)"
}
mount_guard() { # <arm> <state before>
  _ms=$(mount_state)
  [ "$_ms" = "$2" ] && pass "$1 left the host's mounts as they were ($_ms)" \
    || fail "$1 changed the host's mounts" "before: $2; after: $_ms"
}
# the namespace arm's bind of / and its removal, as text, so the arm and the guard's own row run the same
# lines: the bind made a slave at once, so nothing it unmounts propagates back to the mounts it copied
NS_UP='mkdir -p "$1"; mount --rbind / "$1" || exit 1; mount --make-rslave "$1" || { umount -l "$1"; rmdir "$1"; exit 1; }'
NS_DOWN='umount -R "$1" 2>/dev/null || umount -l "$1" 2>/dev/null || :; rmdir "$1" 2>/dev/null || :'
# The host-impossible allowlist (INSTALLER_GATE_HOST_IMPOSSIBLE names a file of "row|reason" lines): a run
# whose every skipped row is on it, each for a reason the host cannot change, is CLEAR on that host and
# says which rows and why; one skipped row that is not on it leaves the run INCOMPLETE, never CLEAR.
skip_verdict() { # <skipped row names, one per line> <allowlist file> -> 0 when every one is listed
  _sv_bad=""
  while IFS= read -r _sv; do
    [ -n "$_sv" ] || continue
    grep -qF -- "$_sv|" "$2" 2>/dev/null || _sv_bad="$_sv_bad$_sv; "
  done <<SVEOF
$1
SVEOF
  [ -z "$_sv_bad" ] && return 0
  printf '%s' "$_sv_bad"; return 1
}
allow_report() { # <skipped row names, one per line, newline-ended> <allowlist file>: each with its reason
  printf '%s\n' "$1" | while IFS= read -r _n; do
    [ -z "$_n" ] || printf '  %s: %s\n' "$_n" "$(grep -F -- "$_n|" "$2" | sed -n 1p | cut -d'|' -f2-)"
  done
}
says() {
  grep -q -- "$2" <<EOF
$1
EOF
}
hasline() {
  grep -qxF -- "$2" <<EOF
$1
EOF
}
row() { case " $ROWS " in *" $1 "*) return 0 ;; esac; return 1; }
render() { # <artifact> [env...]: the installer's rendering of one artifact
  _a=$1; shift
  env WHISPER_EDGE_INSTALL_TEST_RENDER="$_a" "$@" sh "$INSTALL" 2>&1
}

# ===================================================================================================
# THE RENDERINGS: what the installer would write, for the run's inputs, through its render hook.
# ===================================================================================================
# The rules and comments of the pinned text, read here independently of the installer: a rule line with
# its comment stripped and its whitespace collapsed, and every comment's text.
expected_rules() { sed -n '3,$p' "$POLICY" | sed 's/#.*//; s/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//'; }
expected_comments() { sed -n '2,$p' "$POLICY" | sed -n 's/^[^#]*#[[:space:]]*\(.*\)$/\1/p'; }
# check_translation <idiom> <rendering>: empty when the rendering is the pinned text in that idiom,
# else the first thing wrong with it
check_translation() {
  _i=$1; _r=$2
  case "$_i" in
    nginx) _pre='whisper_edge_policy '; _suf=';'; _mode='whisper_edge_mode deny;'; _n=13 ;;
    apache) _pre='WhisperEdgePolicy "'; _suf='"'; _mode='WhisperEdgeMode deny'; _n=13 ;;
    litespeed) _pre='    whisper_edge_policy '; _suf=''; _mode='    whisper_edge_mode log'; _n=15 ;;
  esac
  _got=$(printf '%s\n' "$_r" | grep -c '')
  [ "$_got" = "$_n" ] || { echo "$_got lines, not $_n"; return 0; }
  hasline "$_r" "$_mode" || { echo "no mode line $_mode"; return 0; }
  _k=0
  while IFS= read -r _e; do
    _k=$((_k + 1))
    hasline "$_r" "$_pre$_e$_suf" || { echo "rule $_k ($_e) is not one directive"; return 0; }
  done <<EOF
$(expected_rules)
EOF
  [ "$(printf '%s\n' "$_r" | grep -c "^$_pre")" = "$_k" ] || { echo "not exactly $_k policy directives"; return 0; }
  while IFS= read -r _c; do
    says "$_r" "# $_c\$" || { echo "the comment '$_c' is not carried"; return 0; }
  done <<EOF
$(expected_comments)
EOF
  # each rule's comment is the line above it, in the pinned order
  _prev=""; _order=""
  while IFS= read -r _l; do
    case "$_l" in "$_pre"*) _order="$_order|$_prev" ;; esac
    _prev=$_l
  done <<EOF
$_r
EOF
  _want=""
  for _c in $(sed -n '3,$p' "$POLICY" | sed -n 's/^[^#]*#[[:space:]]*\(.*\)$/\1/p' | tr ' ' '\001'); do
    _want="$_want|$(printf '%s' "$_c" | tr '\001' ' ')"
  done
  [ "$(printf '%s' "$_order" | sed 's/|[[:space:]]*# /|/g')" = "$_want" ] || { echo "a comment is not above its own rule"; return 0; }
}

render_rows() {
  echo "--- the renderings"
  # W2: the embedded policy is the pinned text, byte for byte
  t=$(render policy) || true
  { printf '%s\n' "$t" | cmp -s - "$POLICY" && [ "$(render policy | wc -c)" = 441 ]; } \
    && pass "the installer's embedded policy is the pinned default.conf, byte for byte (441 bytes)" \
    || fail "the embedded policy is the pinned text" "$(printf '%s\n' "$t" | diff - "$POLICY" | head -4)"
  sed 's/^deny if listed >= high         # cited/deny if listed >= high        # cited/' "$INSTALL" > "$W/install-drift.sh"
  if cmp -s "$INSTALL" "$W/install-drift.sh"; then
    fail "the policy-drift control" "the planted one-byte drift did not apply, so the row proves nothing"
  else
    t=$(INSTALL="$W/install-drift.sh" render policy) || true
    ! printf '%s\n' "$t" | cmp -s - "$POLICY" \
      && pass "the control: one byte of drift in the embedded text is seen" \
      || fail "the policy-drift control" "the drifted copy still compared equal"
  fi

  # W4: the translation into each idiom, and the mark on the files the installer creates
  for i in nginx apache; do
    t=$(render "$i" WHISPER_EDGE_DIR=/var/lib/whisper-edge) || true
    why=$(check_translation "$i" "$t")
    { [ -z "$why" ] && hasline "$t" "$(case $i in nginx) echo 'whisper_edge_data /var/lib/whisper-edge;' ;; *) echo 'WhisperEdgeData /var/lib/whisper-edge' ;; esac)"; } \
      && pass "the $i drop-in: 13 lines, the mode line, one directive per rule, every comment above its rule, the data line binding the directory" \
      || fail "the $i translation" "${why:-no data line}"
    printf '%s\n' "$t" > "$W/$i.conf"
    [ "$(render is-ours WHISPER_EDGE_INSTALL_TEST_FILE="$W/$i.conf")" = ours ] \
      && pass "its first line is the installer's mark, and the digest holds over the rest" \
      || fail "the $i drop-in carries the mark" "$(sed -n 1p "$W/$i.conf")"
    sed '$s/;*$/ /' "$W/$i.conf" > "$W/$i.edited.conf"
    [ "$(render is-ours WHISPER_EDGE_INSTALL_TEST_FILE="$W/$i.edited.conf")" = foreign ] \
      && pass "the control: one byte edited after the mark and the file is no longer the installer's" \
      || fail "the mark's control ($i)" "an edited file still read as the installer's"
    drop=$(printf '%s\n' "$t" | sed '/^# cited, high-confidence listings$/d')
    [ -n "$(check_translation "$i" "$drop")" ] \
      && pass "the control: a $i translation that drops a comment fails the check" \
      || fail "the translation control ($i)" "a rendering missing a comment passed"
    merged=$(printf '%s\n' "$t" | awk '/policy|Policy/ && !m { m = 1; l = $0; next } m == 1 && /policy|Policy/ { print l " " $0; m = 2; next } { print }')
    [ -n "$(check_translation "$i" "$merged")" ] \
      && pass "the control: a $i translation that merges two rules fails the check" \
      || fail "the merge control ($i)" "a rendering with two rules on one line passed"
  done
  t=$(render litespeed WHISPER_EDGE_DIR=/var/lib/whisper-edge) || true
  why=$(check_translation litespeed "$t")
  { [ -z "$why" ] && hasline "$t" 'module mod_whisper_edge {' && hasline "$t" '    whisper_edge_data /var/lib/whisper-edge'; } \
    && pass "the OpenLiteSpeed block: named for the module's symbol, mode log, one key per rule, every comment carried" \
    || fail "the OpenLiteSpeed translation" "${why:-the block name or the data key}"
  t=$(render apache WHISPER_EDGE_INSTALL_TEST_MODULE=/usr/lib/apache2/modules/mod_whisper_edge.so) || true
  says "$t" '^LoadModule whisper_edge_module /usr/lib/apache2/modules/mod_whisper_edge.so$' \
    && [ "$(printf '%s\n' "$t" | grep -c '')" = 14 ] \
    && pass "the Apache drop-in carries the LoadModule line, by absolute path, when the module is not loaded yet" \
    || fail "the Apache LoadModule line" "$t"
  t=$(render nginx "WHISPER_EDGE_DIR=/srv/edge data") || true
  hasline "$t" 'whisper_edge_data "/srv/edge data";' \
    && pass "a data directory with a space is quoted in nginx's own syntax" \
    || fail "the data directory quoting" "$(printf '%s\n' "$t" | sed -n 2p)"

  # the per-plane units: the instance name is passed through, the operator's words are escaped
  t=$(render template-service "WHISPER_EDGE_DIR=/srv/a%b c" "WHISPER_EDGE_BASE=https://feed.example/edge?a=1&b=2") || true
  x=$(printf '%s\n' "$t" | sed -n 's/^ExecStart=//p')
  { [ "$(printf '%s\n' "$t" | grep -c -- '--plane %i ')" = 1 ] && [ "$(printf '%s\n' "$t" | grep -c -- '%%i')" = 0 ] \
    && [ "$x" = '/usr/local/sbin/whisper-edge-refresh --plane %i --quiet --dir "/srv/a%%b c" --base https://feed.example/edge?a=1&b=2' ] \
    && hasline "$t" 'ReadWritePaths="/srv/a%%b c"' && says "$t" '^CapabilityBoundingSet=CAP_LINUX_IMMUTABLE$'; } \
    && pass "the rendered @.service carries --plane %i exactly once, unescaped, beside the escaped --dir and --base, with the capability" \
    || fail "the per-plane service template's rendering" "$x"
  printf '%s\n' "$t" | sed 's/--plane %i/--plane %%i/' > "$W/svc.escaped"
  [ "$(grep -c -- '--plane %i ' "$W/svc.escaped")" != 1 ] \
    && pass "the control: a rendering that sent %i through the escaping reads as --plane %%i and fails the count" \
    || fail "the %i control" "an escaped %i still counted"
  t=$(render template-timer) || true
  { ! says "$t" '^OnCalendar=' && ! says "$t" '^OnUnitActiveSec=' && says "$t" '^OnBootSec=2min$'; } \
    && pass "the @.timer carries no schedule of its own (only the once-at-boot firing), so no drop-in can double it" \
    || fail "the timer template carries a schedule" "$t"
  r=$(render cadence-reputation) || true; o=$(render cadence-tor) || true; k=$(render cadence-rpki-unreachable) || true
  { hasline "$r" 'OnCalendar=hourly' && hasline "$r" 'RandomizedDelaySec=900' && hasline "$o" 'OnCalendar=*:0/30' \
    && hasline "$o" 'RandomizedDelaySec=300' && hasline "$k" 'OnCalendar=*:0/30' \
    && ! says "$r$o$k" '^OnBootSec=' && ! says "$r$o$k" '^OnUnitActiveSec='; } \
    && pass "the schedules: reputation hourly with 900 s of jitter, the format-2 planes every 30 minutes with 300 s, no list setting repeated" \
    || fail "the per-plane schedules" "$r / $o"
  if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze calendar '*:0/30' >/dev/null 2>&1 && ! systemd-analyze calendar 'banana' >/dev/null 2>&1 \
      && pass "systemd parses the 30-minute calendar (and refuses a planted bad one)" \
      || fail "the calendar expression parses" "$(systemd-analyze calendar '*:0/30' 2>&1 | head -2)"
  else
    skip "the calendar expression under systemd-analyze" "systemd-analyze is not on this host"
  fi
  t=$(render memlock WHISPER_EDGE_INSTALL_TEST_MEMLOCK=69206016) || true
  { hasline "$t" 'LimitMEMLOCK=69206016' && hasline "$t" '[Service]'; } \
    && pass "the LimitMEMLOCK drop-in carries the computed value under [Service]" \
    || fail "the LimitMEMLOCK drop-in" "$t"

  # the options: a bad one is one line and the usage, exit 2
  for a in "--bogus" "--server iis" "--dir relative/path" "--dir"; do
    # shellcheck disable=SC2086
    t=$(sh "$INSTALL" $a 2>&1) && rc=0 || rc=$?
    case "$t" in "install.sh: "*) first=yes ;; *) first=no ;; esac
    { [ "$rc" = 2 ] && [ "$first" = yes ] && says "$t" '^Usage: '; } \
      && pass "install.sh $a: one line saying why, the usage, exit 2" \
      || fail "install.sh $a is refused with exit 2" "rc=$rc $(printf '%s' "$t" | head -2)"
  done
  # The installer reads the manifest the one way the refresh does: the two readers, taken from their own
  # files, over the same manifests, through python3 and then through jq alone, must print the same verdict
  # (the installer's PLANE line adds the cadence as a fourth field, which the refresh does not read).
  sed -n '/^manifest_entry() {/,/^}/p' "$HERE/whisper-edge-refresh" > "$W/me.refresh"
  sed -n '/^manifest_entry() {/,/^}/p' "$INSTALL" > "$W/me.install"
  mkdir -p "$W/m" "$W/nopy"
  for t in jq sed cat; do p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$W/nopy/$t" || :; done
  python3 - "$W/m" <<'PY'
import json, os, sys
d = sys.argv[1]
ms = {
  "plane": {"planes": [{"name": "tor", "sha256": "a" * 64, "bytes": 31039, "cadenceSeconds": 1800}]},
  "list": {"withheld": [{"name": "tor", "reason": "LOW_RECALL", "reasons": ["LOW_RECALL", "IPV6_NOT_STATED"]}]},
  "single": {"withheld": [{"name": "tor", "reason": "STALE"}]},
  "null": {"withheld": [{"name": "tor", "reason": None}]},
  "emptylist": {"withheld": [{"name": "tor", "reason": "X", "reasons": []}]},
  "edgy": {"withheld": [{"name": "tor", "reason": "", "reasons": ["LOW\u001b[31m", "a\u2028b", {"a": 1}, None, True, "", 0, "x\u00a0y\ttab\nnl"]}]},
  "absent": {"planes": [{"name": "reputation", "sha256": "b" * 64, "bytes": 1}]},
}
for k, v in ms.items():
    json.dump(v, open(os.path.join(d, k + ".json"), "w"), ensure_ascii=False)
PY
  agree=0; differ=""
  for path in py jq; do
    if [ "$path" = jq ] && [ ! -x "$W/nopy/jq" ]; then skip "the manifest readers agree through jq" "jq is not on this host"; continue; fi
    for m in "$W"/m/*.json; do
      if [ "$path" = py ]; then
        a=$(sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.refresh" "$m" 2>&1)
        b=$(sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.install" "$m" 2>&1)
      else
        a=$(PATH="$W/nopy" /bin/sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.refresh" "$m" 2>&1)
        b=$(PATH="$W/nopy" /bin/sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.install" "$m" 2>&1)
      fi
      case "$b" in PLANE*) b=$(printf '%s' "$b" | cut -d' ' -f1-3) ;; esac
      if [ -n "$a" ] && [ "$a" = "$b" ]; then agree=$((agree + 1)); else differ="$differ [$path $(basename "$m"): refresh '$a' installer '$b']"; fi
    done
  done
  [ -z "$differ" ] && [ "$agree" -ge 7 ] \
    && pass "the installer and the refresh read the manifest alike: $agree verdicts over $(find "$W/m" -name '*.json' | grep -c '') manifests (plane, reasons list, single, null, empty list, control characters, absent), through python3 and jq" \
    || fail "the manifest readers agree" "$differ"
  sed 's/", ".join(r(x) for x in rs)/" + ".join(r(x) for x in rs)/' "$W/me.install" > "$W/me.drift"
  a=$(sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.refresh" "$W/m/list.json" 2>&1)
  b=$(sh -c '. "$1"; have() { command -v "$1" >/dev/null 2>&1; }; manifest_entry "$2" tor' x "$W/me.drift" "$W/m/list.json" 2>&1)
  { ! cmp -s "$W/me.install" "$W/me.drift" && [ "$a" != "$b" ]; } \
    && pass "the control: an installer reader that joins the reasons another way is seen to disagree" \
    || fail "the reader-parity control" "the planted drift did not apply or was not seen"

  # a test hook that acts on a run is honoured only on a disposable box and only with a fixed value
  t=$(env -u INSTALLER_GATE_DISPOSABLE WHISPER_EDGE_INSTALL_TEST_RULE=bad-level sh "$INSTALL" --dry-run 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$t" 'honoured only on a box the install gate declared disposable'; } \
    && pass "a run-acting test hook on a box not declared disposable: refused, exit 2, before anything runs" \
    || fail "a leaked test hook is refused" "rc=$rc $(printf '%s' "$t" | head -1)"
  t=$(env INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_RULE='deny if listed >= none; load_module /x.so' sh "$INSTALL" --dry-run 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$t" 'is not one of its fixed values'; } \
    && pass "a hook value outside its fixed set (free text): refused, exit 2" \
    || fail "a free-text hook value is refused" "rc=$rc $(printf '%s' "$t" | head -1)"
  t=$(env INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_RULE=bad-level sh "$INSTALL" --dry-run --dir /var/lib/whisper-edge 2>&1) && rc=0 || rc=$?
  says "$t" 'test hooks active (a disposable box): WHISPER_EDGE_INSTALL_TEST_RULE=bad-level' \
    && pass "the control: a fixed value on a disposable box passes the hook gate, and the report's first block names it" \
    || fail "an accepted hook is named in the report" "rc=$rc $(printf '%s' "$t" | head -3)"
  # the installer reads nginx's refused-plane sentence by its fixed words; they are the module's,
  # taken here from the core that prints them, so a rewording fails this row instead of the check going dark
  sent=$(sed -n 's/.*"whisper edge: plane %s \(is refused at configuration and reads unknown\) until.*/\1/p' "$HERE/../core/we_module.c" | sed -n 1p)
  { [ -n "$sent" ] && grep -qF "grep -F '$sent'" "$INSTALL"; } \
    && pass "the refused-plane words the installer reads are the core's own ($sent)" \
    || fail "the refused-plane sentence agrees with the core" "core: '${sent:-not found}'"
  # The host-impossible allowlist decides only for the rows it names: a listed skip passes, and one
  # unlisted skip beside it fails the verdict
  printf 'a listed row|a reason the host cannot change\n' > "$W/allow.txt"
  if skip_verdict "a listed row" "$W/allow.txt" >/dev/null && ! skip_verdict "a listed row
an unlisted row" "$W/allow.txt" >/dev/null; then
    pass "the host-impossible allowlist: a listed skip is accepted, and one unlisted skip beside it fails the run"
  else fail "the host-impossible allowlist" "a listed skip was refused, or an unlisted one accepted"; fi
  # and the CLEAR verdict's own report runs to its exit 0 under set -e: the names end with a newline, as
  # skip() writes them, and a loop whose last test was false once ended the gate with 1 after printing CLEAR
  # (set -e is ignored inside a subshell an if or && tests, so it runs as a job whose status is waited for)
  ( set -e; allow_report "a listed row
" "$W/allow.txt" > "$W/allow.out"; exit 0 ) &
  if wait $! && grep -qxF '  a listed row: a reason the host cannot change' "$W/allow.out"; then
    pass "the CLEAR verdict's report names each listed skip with its reason and ends cleanly under set -e"
  else fail "the CLEAR verdict's report" "it ended non-zero or did not name the row: $(cat "$W/allow.out" 2>/dev/null)"; fi
  # The usage text agrees with the script: every option the parser takes is documented and every documented
  # option is taken, and the exit codes the usage table names are exactly the statuses the script can end
  # with (its own `exit N` and the EXIT trap's, outside every quoted helper). Each is checked on a copy with
  # one planted disagreement too, so the row can fail.
  usage_agrees() { # <installer> -> empty when it agrees, else what disagrees
    _io=$(sed -n '/^while \[ \$# -gt 0 \]; do/,/^done/p' "$1" | grep -oE '^    (-h\|)?--[a-z0-9-]+' | grep -oE -- '--[a-z0-9-]+' | sort -u | tr '\n' ' ')
    _do=$(sed -n '/^# Usage:/,/^# Exit codes:/p' "$1" | grep -oE '^#   (-h, )?--[a-z0-9-]+' | grep -oE -- '--[a-z0-9-]+' | sort -u | tr '\n' ' ')
    _ic=$(awk -f "$HERE/testdata/exit-codes.awk" "$1" | sort -un | tr '\n' ' ')
    _dc=$(sed -n '/^# Exit codes:/,/^#   129, 130, 143/p' "$1" | grep -oE '^#   [0-9][0-9, ]*' | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')
    [ -n "$_io" ] && [ "$_io" = "$_do" ] || { echo "options: parsed [$_io] documented [$_do]"; return 0; }
    [ -n "$_ic" ] && [ "$_ic" = "$_dc" ] || { echo "exit codes: in the script [$_ic] documented [$_dc]"; return 0; }
  }
  why=$(usage_agrees "$INSTALL")
  [ -z "$why" ] && pass "the usage text names every option the parser takes and the exact exit codes the script can end with ($(sed -n '/^# Exit codes:/,/^#   129, 130, 143/p' "$INSTALL" | grep -oE '^#   [0-9][0-9, ]*' | grep -oE '[0-9]+' | tr '\n' ' '))" \
    || fail "the usage text agrees with the script" "$why"
  sed '/^#   --arm-deny /d' "$INSTALL" > "$W/usage-noopt.sh"
  sed 's/^\[ -n "\${ARM_UNCONFIRMED:-}" \] && exit 3$/[ -n "${ARM_UNCONFIRMED:-}" ] \&\& exit 6/' "$INSTALL" > "$W/usage-nocode.sh"
  { cmp -s "$INSTALL" "$W/usage-noopt.sh" || cmp -s "$INSTALL" "$W/usage-nocode.sh"; } && fail "the usage controls" "a planted disagreement did not apply"
  { [ -n "$(usage_agrees "$W/usage-noopt.sh")" ] && [ -n "$(usage_agrees "$W/usage-nocode.sh")" ]; } \
    && pass "the controls: an undocumented option, and an exit code the table does not name, each fail the same check" \
    || fail "the usage controls" "a planted disagreement passed"
  # a --dir the by-hand undo would remove whole, or with a .. component, is refused
  for d in / /etc /var/lib /var/lib/whisper-edge/../x; do
    t=$(sh "$INSTALL" --dry-run --dir "$d" 2>&1) && rc=0 || rc=$?
    [ "$rc" = 2 ] && pass "--dir $d: refused, exit 2" || fail "--dir $d is refused" "rc=$rc $(printf '%s' "$t" | head -1)"
  done
  # a newline in --dir would end a directive in Apache's and nginx's files and start another: refused
  t=$(sh "$INSTALL" --dry-run --dir "/var/lib/edge
Include /etc/passwd" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$t" 'has a control character'; } && pass "--dir with a newline: refused, exit 2, for every server" \
    || fail "--dir with a newline is refused" "rc=$rc $(printf '%s' "$t" | head -1)"
  t=$(sh "$INSTALL" --help 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$t" '^Usage: sudo ./install.sh' && ! says "$t" '^set -eu'; } \
    && pass "--help prints the header and the usage" || fail "--help" "rc=$rc"
}
# The early-end guard's own row: the gate run again with one row that passes and then a command that
# fails under set -e; the guard must name that row and the failing line, and the exit must not be 0 or 77
if [ "${INSTALLER_GATE_ENDTEST:-0}" = 1 ]; then
  pass "endtest: the row before the planted failure"
  false   # the planted failure: line ENDTEST_FAIL
  pass "endtest: never reached"
fi
endtest_row() {
  _el=$(grep -n 'the planted failure: line ENDTEST_FAIL' "$HERE/installer-gate.sh" | head -1 | cut -d: -f1)
  _et=$(INSTALLER_GATE_ENDTEST=1 INSTALLER_GATE_ROWS=none INSTALLER_GATE_KEEP_REPORTS="" sh "$HERE/installer-gate.sh" 2>/dev/null) && _erc=0 || _erc=$?
  _ex="INSTALLER GATE: ENDED EARLY after \"endtest: the row before the planted failure\" (exit 1, line $_el)"
  if [ -z "${BASH_VERSION:-}" ]; then _ex="INSTALLER GATE: ENDED EARLY after \"endtest: the row before the planted failure\" (exit 1, line unknown)"; fi
  { [ "$_erc" != 0 ] && [ "$_erc" != 77 ] && printf '%s\n' "$_et" | grep_any -F "$_ex" && ! printf '%s\n' "$_et" | grep_any 'endtest: never reached'; } \
    && pass "the early-end guard: a command failing under set -e between two rows ends the gate naming the row before it and the line (exit $_erc, never 0 or 77)" \
    || fail "the early-end guard" "rc=$_erc, wanted: $_ex; got: $(printf '%s\n' "$_et" | grep 'ENDED EARLY' | head -1)"
}
# Every function the gate (and the installer) calls is defined before the line that first runs it: a
# call that runs earlier is "command not found", silent under `cmd || other`, and the early-end guard
# cannot see it. A static read of the scripts, with a planted copy as its control.
deforder_row() {
  for _sc in "$HERE/installer-gate.sh" "$INSTALL"; do
    _do=$(python3 -I "$HERE/testdata/def-order.py" "$_sc" 2>&1) && _drc=0 || _drc=$?
    [ "$_drc" = 0 ] && pass "every function $(basename "$_sc") calls is defined before the line that first runs it" \
      || fail "a function $(basename "$_sc") runs before its definition" "$(printf '%s\n' "$_do" | head -6)"
  done
  printf 'early() { :; }\nearly\nlate\nlate() { early; }\n' > "$W/deforder.sh"
  _do=$(python3 -I "$HERE/testdata/def-order.py" "$W/deforder.sh" 2>&1) && _drc=0 || _drc=$?
  { [ "$_drc" = 1 ] && printf '%s\n' "$_do" | grep_any -x 'line 3 calls late, defined at line 4'; } \
    && pass "the control: a planted call before its definition is named, with both lines" \
    || fail "the definition-order control" "rc=$_drc $_do"
}
# and no command that acts on the host ends the run from the tail of an AND list (a failed systemctl start
# after a hand-started master ended a whole run on SELinux); the control is a planted one
andtail_row() {
  _do=$(python3 -I "$HERE/testdata/and-tail.py" "$HERE/installer-gate.sh" 2>&1) && _drc=0 || _drc=$?
  [ "$_drc" = 0 ] && pass "no command in installer-gate.sh that acts on the host ends the run from the tail of an AND list" \
    || fail "a host command ends an AND list in installer-gate.sh" "$(printf '%s\n' "$_do" | head -8)"
  _do=$(python3 -I "$HERE/testdata/and-tail.py" "$INSTALL" 2>&1) && _drc=0 || _drc=$?
  [ "$_drc" = 0 ] && pass "no command in install.sh that acts on the host ends the run from the tail of an AND list" \
    || fail "a host command ends an AND list in install.sh" "$(printf '%s\n' "$_do" | head -8)"
  printf 'set -e\n[ "$x" = 1 ] && systemctl start nginx\n[ "$x" = 1 ] && systemctl start nginx || :\n' > "$W/andtail.sh"
  _do=$(python3 -I "$HERE/testdata/and-tail.py" "$W/andtail.sh" 2>&1) && _drc=0 || _drc=$?
  { [ "$_drc" = 1 ] && [ "$(printf '%s\n' "$_do" | grep -c '^line ')" = 1 ] && printf '%s\n' "$_do" | grep_any '^line 2: '; } \
    && pass "the control: a planted systemctl at an AND list's tail is named, and the same line ending in || : is not" \
    || fail "the AND-tail control" "rc=$_drc $_do"
}
# no awk in the shipped scripts takes a value by -v: awk reads an assignment's backslashes as escapes, so a
# regex, a path or a zone name loses them there (gawk warns, mawk is silent), and a file context rule never
# read as the one the installer added (the clean enforcing Rocky 9.8 run). Each value comes through
# ENVIRON. The control is a planted -v, which must be named.
awkv_hits() { # <file>: the lines that hand awk a value by -v
  grep -nE '(^|[^[:alnum:]_-])awk([[:space:]]+-F[^[:space:]]+)*[[:space:]]+-v[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' "$1" || true
}
awkv_row() {
  _ah=""; for _f in "$INSTALL" "$HERE/whisper-edge-refresh"; do _h=$(awkv_hits "$_f"); [ -z "$_h" ] || _ah="$_ah ${_f##*/}: $_h;"; done
  [ -z "$_ah" ] && pass "no awk in install.sh or whisper-edge-refresh takes a value by -v (its backslashes would be read as escapes); each comes through ENVIRON" \
    || fail "an awk takes a value by -v" "$(printf '%s' "$_ah" | cut -c1-400)"
  printf '%s\n' "x | awk -v s=\"\$SPEC\" '\$1 == s'" "y | LC_ALL=C awk -F'\\t' -v z=\"\$Z\" '{ print }'" "od -An -v -t u1 f | awk '{ print }'" > "$W/awkv.sh"
  [ "$(awkv_hits "$W/awkv.sh" | cut -d: -f1 | tr '\n' ' ')" = "1 2 " ] \
    && pass "the control: a planted awk -v is named, with or without -F before it, and od's own -v is not" \
    || fail "the awk -v control" "$(awkv_hits "$W/awkv.sh")"
}
row render && awkv_row
row render && deforder_row
row render && andtail_row
row render && endtest_row
row render && render_rows

# ===================================================================================================
# THE STUB FEED: a signed manifest, the reputation plane and the tor state it is told to state, under
# a throwaway Ed25519 key, served on loopback behind a base that does not resolve, so the run reaches it
# only through WHISPER_EDGE_RESOLVE.
# ===================================================================================================
K="$W/keys"; mkdir -p "$K"
openssl genpkey -algorithm ed25519 -out "$K/key.pem" 2>/dev/null
openssl pkey -in "$K/key.pem" -pubout -out "$K/key.pub" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$K/other.pem" 2>/dev/null
# the stub's key is not the pinned one, so every run against the stub names it, as any other feed must
KS=$(sha256sum < "$K/key.pub" | cut -c1-64); export WHISPER_EDGE_KEY_SHA256="$KS"
FIXTURE="$HERE/../core/testdata/interop.snap"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
RES="edge.installer-gate.invalid:$PORT:127.0.0.1"
FEED="http://edge.installer-gate.invalid:$PORT/edge"
S="$W/feed"
FEED_NOW=$(date +%s)   # one clock for every feed this run builds, so the same inputs make the same bytes
# feed <reputation generation> <mode>: modes are normal, badsig (the manifest signed by another key),
# torpub (tor published too), norep (reputation withheld), nofile (reputation listed, its file not served),
# expired (the plane's own valid-until in the past)
feed() {
  rm -rf "$S"; mkdir -p "$S/edge/planes" "$S/edge/manifests"
  python3 - "$FIXTURE" "$S/rep.bin" "$1" "$2" "$FEED_NOW" <<'PY'
import struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, int(sys.argv[3]))
now = int(sys.argv[5]) * 1000
vu = now - 3600000 if sys.argv[4] == "expired" else now + 86400000
struct.pack_into("<Q", b, 32, vu)
# the header's own digest (offset 104, 32 bytes): SHA-256 over the file with that field zeroed, recomputed
# after the generation and valid-until change, or a real module refuses the plane as a digest mismatch
import hashlib
b[104:136] = bytes(32)
b[104:136] = hashlib.sha256(bytes(b)).digest()
open(sys.argv[2], "wb").write(bytes(b))
PY
  rsha=$(sha256sum < "$S/rep.bin" | cut -d' ' -f1)
  cp "$S/rep.bin" "$S/edge/planes/$rsha.bin"
  openssl pkeyutl -sign -inkey "$K/key.pem" -rawin -in "$S/rep.bin" -out "$S/edge/planes/$rsha.bin.sig"
  if [ "$2" = nofile ]; then rm -f "$S/edge/planes/$rsha.bin" "$S/edge/planes/$rsha.bin.sig"; fi
  tsha=-; tsize=0
  case "$2" in torpub*)
    cp "$HERE/../core/testdata/format2/tor.bin" "$S/tor.bin"
    tsha=$(sha256sum < "$S/tor.bin" | cut -d' ' -f1); tsize=$(wc -c < "$S/tor.bin")
    cp "$S/tor.bin" "$S/edge/planes/$tsha.bin"
    openssl pkeyutl -sign -inkey "$K/key.pem" -rawin -in "$S/tor.bin" -out "$S/edge/planes/$tsha.bin.sig" ;;
  esac
  cp "$K/key.pub" "$S/edge/edge-signing-key.pub"
  python3 - "$S/edge/manifest.json" "$rsha" "$(wc -c < "$S/rep.bin")" "$1" "$2" "$tsha" "$tsize" <<'PY'
import json, sys
path, sha, size, gen, mode = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
tsha, tsize = sys.argv[6], int(sys.argv[7])
# the build generation differs from the plane's own header generation, as it does live: the files decide
m = {"format": 2, "generation": 1791990002, "planes": [
        {"name": "reputation", "sha256": sha, "bytes": size, "headerGeneration": gen, "cadenceSeconds": 3600}],
     "withheld": [{"name": "tor", "reason": "LOW_RECALL", "reasons": ["LOW_RECALL", "IPV6_NOT_STATED"],
                   "detail": "batch " * 200}]}
if mode.startswith("torpub"):
    m["withheld"] = []
    m["planes"].append({"name": "tor", "sha256": tsha, "bytes": tsize, "cadenceSeconds": int(mode[6:])})
if mode == "norep":
    m["planes"] = []
    m["withheld"].append({"name": "reputation", "reason": "STALE"})
json.dump(m, open(path, "w"))
PY
  msha=$(sha256sum < "$S/edge/manifest.json" | cut -d' ' -f1)
  signer="$K/key.pem"; [ "$2" = badsig ] && signer="$K/other.pem"
  openssl pkeyutl -sign -inkey "$signer" -rawin -in "$S/edge/manifest.json" -out "$S/edge/manifests/$msha.sig"
  REP_SHA=$rsha
}
serve() {
  ( cd "$S" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
  echo $! >> "$W/servers.pid"
  i=0; while [ "$i" -lt 600 ]; do
    curl -fsS --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/edge/manifest.json" 2>/dev/null && return 0
    i=$((i + 1)); sleep 0.1
  done
}
# box <name>: a redirected box under the work tree, for the dry runs: every path the installer reads or
# writes moved into it, so "writes nothing" can be checked by listing it
box() {
  B="$W/box-$1"; rm -rf "$B"; mkdir -p "$B"
  BOXENV="WHISPER_EDGE_RESOLVE=$RES WHISPER_EDGE_ETC=$B/etc WHISPER_EDGE_UNITDIR=$B/units WHISPER_EDGE_SBIN=$B/sbin WHISPER_EDGE_LSWS_ROOT=$B/lsws"
}
# every report the gate sees is kept, so the line-pattern row reads all of them; and the installer's stderr
# is kept apart as well, so the stderr row reads every line the installer did not print to its report
# (a child's warning, gawk's on a regex, a tool's own error): each run's stderr follows its stdout in the
# report a row reads
collect_err() { # <out file>: its run's stderr (<out>.err) into $W/stderr, then after the out, then the reports
  cat "$1.err" >> "$W/stderr" 2>/dev/null || :; cat "$1.err" >> "$1" 2>/dev/null || :; rm -f "$1.err"; cat "$1" >> "$W/reports"
}
keep() { _r=0; "$@" > "$W/last" 2> "$W/last.err" || _r=$?; collect_err "$W/last"; cat "$W/last"; return "$_r"; }
dry() { keep dry_run "$@"; }
# Every line the installer prints has a shape it chose: a block header, a report line under one of these
# prefixes, a line of a paste block (two spaces and text, or deeper), the stop line, or the line to watch.
# A child's raw line (the refresh's "installed ...", a "whisper-edge-refresh:" alarm, curl's own words)
# matches none, so a raw line leaking through fails here; the installer re-says each one under a prefix.
REPORT_LINE='^$|^(== (detected|armed|applied|proved|undo)|install\.sh: .*|  [^ ].*|    .*|watch: .* the cycle is T the timer period in s, D the signed cadenceSeconds, A the publication lag \(not measured by this run\), F the refresh fetch budget in s|   (\(nothing\)|already present: .*|wrote .* \(.*, [0-9]+ lines\)|would (write|create|install|enable|make|fetch|leave|stop) .*|would run: .*|enabled whisper-edge-refresh@[a-z-]+\.timer \(.*\).*|signing key: .*|the feed is fetched over plain http: .*|the (installed )?signing key .* is not the pinned key .*|test hooks active \(a disposable box\):.*|refresh: .*|built whisper-edge-(lookup|summary) in .*|installed /.*|edited /.*|enabled /.*|undo, (nginx|Apache|OpenLiteSpeed): sh -c .*|to print these lines again: .*|the run ended unexpectedly .*|could not .*|counters: .*|schedule: .*|tenant plane: .*|enrolment: .*|undo, the shared parts \(after every server line\): sh -c .*|by hand, if you want the data gone too: .*|nothing of the web half was written.*|no shared parts were written .*|wrote /.*/policy\.conf \(the default policy, [0-9]+ bytes, to read and edit\)|the resolver half has no undo line.*|recovered an interrupted run \(run\.[0-9TZ.]+\): .*|labelled (the planes in )?/.*|kept your SELinux file context .*|would label (the planes in )?/.*|took back the SELinux file context rule\(s\) this run added .*|restored /.* to its bytes from before the interrupted run|kept /.*|restored /.* from the copy the interrupted run kept; .*|(reputation|rpki-unreachable|tor)( armed, generation [0-9]+, digest [0-9a-f]{16}, valid until .*| withheld by the signed manifest: .*| kept, generation [0-9]+, digest [0-9a-f]{16} \(computed here over the file\).*| is published.*|\.bin was installed for the first time: .*| already current: .*|: .*)|no web server .*|no web configuration to reconcile .*|no plane fetched: .*|BIND .*|(nginx|Apache|OpenLiteSpeed)( [0-9.]+| \(version unknown\))? at .*|(nginx|Apache|OpenLiteSpeed): .*|fs\.protected_hardlinks is .*|another installer run is in progress, started .*|LimitMEMLOCK: .*|zone .*|zone timers enabled, .*|the signed manifest .*|could not fetch the signing key .*|no systemctl here, .*|--no-timer: .*|the earlier .*|disabled the earlier snapshot timer .*|/.* is not a file this installer wrote; .*|/.* is not root.s alone \(.*|/.* is a symbolic link; .*))$'
stray_line() { # <file>: the first line no shape matches, or nothing
  grep -nvE -- "$REPORT_LINE" "$1" | sed -n 1p || true
}
# a report line whose reason is empty: a colon with nothing after it before the sentence goes on (": ;",
# ": )", ": ."), or empty parentheses. Report lines only (three spaces, then text); the undo lines are
# shell, and a paste block's lines are configuration
empty_reason() { # <file>: the first report line with an empty reason, or nothing
  grep -nE '^   [^ ]' "$1" | grep -vE '^[0-9]+:   (undo, |to print these lines again)' \
    | grep -E '(:[[:space:]]*[;,)])|(\(\))|(:[[:space:]]*\.$)' | sed -n 1p || true
}
# the installer's stderr: its own refusals and stops, each under its name, and nothing else
stray_err() { # <file>: the first line that is not the installer's own, or nothing
  grep -nvE -- '^install\.sh: ' "$1" | sed -n 1p || true
}
dry_run() { # <box> [options]: a dry run against the stub, every path in the box
  _b=$1; shift
  # shellcheck disable=SC2086
  env PATH=/usr/bin:/bin $BOXENV sh "$INSTALL" --dry-run --dir "$_b/lib" --base "$FEED" "$@"
}
feed 497775 normal; serve

dry_rows() {
  echo "--- --dry-run, against the stub feed"
  box first
  out=$(dry "$B") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" "would install reputation.bin ($(wc -c < "$S/rep.bin") bytes, digest $(printf '%s' "$REP_SHA" | cut -c1-16)" \
    && says "$out" 'would leave tor withheld by the signed manifest (LOW_RECALL, IPV6_NOT_STATED); log if tor_exit is inert at launch' \
    && says "$out" 'would leave rpki-unreachable absent: the manifest names no such plane; log if rpki_unreachable is inert at launch' \
    && says "$out" 'a key fetched from .* for this dry run (none is installed here yet)'; } \
    && pass "a dry run on a box with no key: each plane's true state from the manifest it verified, the tor reasons as the signed list, with would" \
    || fail "a first dry run's states" "rc=$rc $(printf '%s' "$out" | grep -E 'would|armed' | head -4)"
  left=$(find "$B" -mindepth 1 2>/dev/null)
  [ -z "$left" ] \
    && pass "and it writes nothing anywhere: no key, plane, unit, drop-in, policy, lock or stamp in the box" \
    || fail "a dry run writes nothing" "$left"
  mkdir -p "$B/lib"; cp "$K/key.pub" "$B/lib/edge.pub"
  out=$(dry "$B") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'verified against the installed key '; } \
    && pass "with a key installed it verifies against that key, read-only, and says so" \
    || fail "a dry run uses the installed key" "rc=$rc $(printf '%s' "$out" | grep -E 'would install|verified' | head -2)"
  [ "$(find "$B" -mindepth 1 | sort | tr '\n' ' ')" = "$B/lib $B/lib/edge.pub " ] \
    && pass "and leaves that box exactly as it found it" || fail "a dry run with a key writes nothing" "$(find "$B" -mindepth 1)"
  # the refusal arm: the installed key is not the one the manifest is signed with
  cp "$K/other.pem" "$W/other.pem"; openssl pkey -in "$K/other.pem" -pubout -out "$B/lib/edge.pub" 2>/dev/null
  out=$(dry "$B") && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" "is not the pinned key (sha256 $KS)" && ! says "$out" 'would install reputation.bin'; } \
    && pass "an installed key that is not the pinned one: refused by its digest, never a would, and a non-zero exit" \
    || fail "a dry run refuses an installed key that is not the pinned one" "rc=$rc $(printf '%s' "$out" | grep -E 'would install|verify|pinned' | head -3)"
  # the pin's own arms: a feed whose served key is not the one named is refused before anything is
  # verified with it; a feed other than the default with no key named is a usage error; and the pin in
  # the script is the key the tree ships (the key whisper.online serves)
  box wrongkey
  # shellcheck disable=SC2086
  out=$(env $BOXENV WHISPER_EDGE_KEY_SHA256="$(printf '%064d' 0)" sh "$INSTALL" --dry-run --dir "$B/lib" --base "$FEED" 2>&1) && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" 'serves is not the pinned key' && ! says "$out" 'would install reputation.bin'; } \
    && pass "a served key whose sha256 is not the pinned one: refused, nothing verified with it" \
    || fail "a dry run refuses a served key that is not the pinned one" "rc=$rc $(printf '%s' "$out" | grep -E 'pinned|would install' | head -2)"
  # shellcheck disable=SC2086
  out=$(env -u WHISPER_EDGE_KEY_SHA256 $BOXENV sh "$INSTALL" --dry-run --dir "$B/lib" --base "$FEED" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$out" 'is not the default feed, so its signing key cannot be the pinned one'; } \
    && pass "a feed other than the default with no --key-sha256: a usage error, exit 2" \
    || fail "a non-default feed needs --key-sha256" "rc=$rc $(printf '%s' "$out" | head -2)"
  # shellcheck disable=SC2086
  out=$(env $BOXENV sh "$INSTALL" --dry-run --dir "$B/lib" --base "ftp://edge.installer-gate.invalid/edge" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$out" 'takes an https:// URL'; } \
    && pass "a feed URL of any other scheme: refused, exit 2" || fail "the feed's scheme" "rc=$rc $(printf '%s' "$out" | head -1)"
  # the offline arm: the feed unreachable
  box offline
  # shellcheck disable=SC2086
  out=$(env $BOXENV WHISPER_EDGE_RESOLVE="edge.installer-gate.invalid:$PORT:127.0.0.2" sh "$INSTALL" --dry-run --dir "$B/lib" --base "$FEED" 2>&1) && rc=0 || rc=$?
  { [ "$rc" != 0 ] && says "$out" "could not fetch the signing key from $FEED, so nothing below could be verified" && says "$out" 'would create'; } \
    && pass "an unreachable feed: one line naming it and what could not be verified, the would-writes still printed, a non-zero exit" \
    || fail "a dry run with the feed unreachable" "rc=$rc $(printf '%s' "$out" | head -3)"
}
row dry && dry_rows

# ===================================================================================================
# THE REAL RUNS: the installer as root, on a disposable box. They write the box's real /etc, /var/lib,
# unit directory and sbin, so they run only where INSTALLER_GATE_DISPOSABLE=1 says the host is one (a
# throwaway guest or container), and as root; anywhere else each says SKIPPED with the reason.
# ===================================================================================================
SH="$W/shim"; SR="$W/shimroot"
mkdir -p "$SH" "$SR"
REAL_DIR=/var/lib/whisper-edge; REAL_ETC=/etc/whisper-edge; REAL_UNITS=/etc/systemd/system; REAL_SBIN=/usr/local/sbin
# The teardown every real arm starts with, and the trap runs: everything the installer may have left,
# the immutable attribute cleared first. Then the clean start is asserted, so an arm never passes on a
# previous run's leftovers.
SYSD=0; [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && SYSD=1
# A gate run killed before its teardown (a TERM the trap could not finish, or a SIGKILL) leaves its counter
# drop-ins behind, naming a work directory that is gone: the next run's reloads then ran an ExecReload into
# it and failed ("Reload failed"), and every Apache arm with them (enforcing Rocky, a killed run before it).
# A drop-in of the gate's name that does not name THIS run's counter file ($W/reloads, which RLC names
# later) is stale: removed, and said.
stale_counters() { # -> the stale drop-ins, one a line
  for _sc in /etc/systemd/system/nginx.service.d/zz-installer-gate-count.conf /etc/systemd/system/apache2.service.d/zz-installer-gate-count.conf /etc/systemd/system/httpd.service.d/zz-installer-gate-count.conf; do
    [ -f "$_sc" ] && ! grep -qF -- "$W/reloads" "$_sc" && printf '%s\n' "$_sc"
  done
  return 0
}
counters_sweep() { # removes the stale drop-ins and names each one, with the directory it pointed at
  _ss=$(stale_counters)
  [ -n "$_ss" ] || return 0
  for _sc in $_ss; do
    echo "  (removed a counter drop-in an earlier gate run left: $_sc, which named $(sed -n 's/.*>> \([^"]*\)".*/\1/p' "$_sc" | head -1))"
    rm -f -- "$_sc"
  done
  [ "$SYSD" = 0 ] || systemctl daemon-reload >/dev/null 2>&1 || :
}
real_teardown() {
  counters_sweep
  # a loaded, active timer keeps firing after its unit file is gone: stopped first, then removed
  if [ "$SYSD" = 1 ]; then
    systemctl stop 'whisper-edge-refresh@*.timer' 'whisper-edge-refresh@*.service' 'whisper-edge-rpz@*.timer' \
      'whisper-edge-refresh-keyed.timer' >/dev/null 2>&1 || true
  fi
  for t in "$REAL_UNITS"/timers.target.wants/whisper-edge-*; do [ -e "$t" ] || [ -L "$t" ] && rm -f "$t"; done
  chattr -R -i "$REAL_DIR" 2>/dev/null || true
  # the SELinux rules a run added go with the record that names them: removing the record alone left them in
  # the host's policy, and the next arm (or a run after the gate) read them as the operator's ("kept your")
  if [ -f "$REAL_ETC/selinux-fcontext.added" ] && command -v semanage >/dev/null 2>&1; then
    while IFS= read -r _sr; do [ -z "$_sr" ] || semanage fcontext -d "$_sr" >/dev/null 2>&1 || :; done < "$REAL_ETC/selinux-fcontext.added"
  fi
  rm -rf "$REAL_DIR" "$REAL_ETC" "$REAL_SBIN/whisper-edge-refresh" /var/cache/bind/whisper-edge
  rm -rf "$REAL_UNITS"/whisper-edge-* "${SR:?}"/* 2>/dev/null || true
  rm -f "$SH"/*
  [ "$SYSD" = 0 ] || systemctl daemon-reload >/dev/null 2>&1 || true
}
clean_start() { # empty when the box carries nothing of the installer's: no file, no enablement, no loaded timer
  _l=$(ls -d "$REAL_UNITS"/whisper-edge-refresh@* "$REAL_UNITS"/timers.target.wants/whisper-edge-* "$REAL_ETC" "$REAL_DIR" 2>/dev/null || true)
  [ "$SYSD" = 0 ] || _l="$_l$(systemctl list-timers --all --no-legend 'whisper-edge-refresh@*' 2>/dev/null | sed -n 's/.*\(whisper-edge-refresh@[^ ]*\.timer\).*/ \1/p')"
  _st=$(stale_counters | tr '\n' ' '); [ -z "$_st" ] || _l="$_l a stale gate counter drop-in: $_st"
  printf '%s' "$_l"
}
REAL_OK=0
if [ "$(id -u)" = 0 ] && [ "${INSTALLER_GATE_DISPOSABLE:-0}" = 1 ]; then
  REAL_OK=1
  # The box's own web servers are stopped first: a package manager starts them on install, and a running
  # master is one the installer would find and act on in rows that plant a server of their own. The
  # server rows below start the ones they test, by hand, and stop them again.
  for _u in nginx apache2 httpd lshttpd lsws; do if [ "$SYSD" = 1 ]; then systemctl stop "$_u" >/dev/null 2>&1 || :; fi; done
  /usr/sbin/nginx -s quit >/dev/null 2>&1 || :
  for _c in apache2ctl apachectl; do if [ -x "/usr/sbin/$_c" ]; then "/usr/sbin/$_c" stop >/dev/null 2>&1 || :; fi; done
  if [ -x /usr/local/lsws/bin/lswsctrl ]; then /usr/local/lsws/bin/lswsctrl stop >/dev/null 2>&1 || :; fi
  wait_until 90 no_masters || echo "  (a web server master is still running 90 s after the stop: $(ps -eo pid=,args= | grep -E 'nginx: master|apache2|httpd|lshttpd - main' | grep -v grep | tr '\n' ';'))"
  # shellcheck disable=SC2154 # _x is assigned by the trap itself
  trap '_x=$?; srv_restore_all; real_teardown; CLEAN_RC=$_x cleanup' EXIT
fi
# shim <name> <script body>: a fake server binary on PATH, so a probe sees a server this box does not have
shim() { printf '#!/bin/sh\n%s\n' "$2" > "$SH/$1"; chmod 0755 "$SH/$1"; }
nginx_shim() { # [with-module]
  mkdir -p "$SR/nginx/modules" "$SR/nginx/modules-enabled" "$SR/nginx/conf.d"
  cat > "$SR/nginx/nginx.conf" <<EOF
include $SR/nginx/modules-enabled/*.conf;
events { }
http {
    include $SR/nginx/conf.d/*.conf;
    include $SR/nginx/sites-enabled/*;
}
EOF
  [ "${1:-}" = with-module ] && : > "$SR/nginx/modules/ngx_http_whisper_edge_module.so"
  shim nginx "case \"\$1\" in
  -V) echo 'nginx version: nginx/1.24.0' >&2; echo 'configure arguments: --conf-path=$SR/nginx/nginx.conf --modules-path=$SR/nginx/modules --pid-path=$SR/nginx.pid' >&2 ;;
  -T) cat '$SR/nginx/nginx.conf' ;;
  *) exit 0 ;;
esac"
}
named_shim() {
  shim named 'exit 0'
  shim named-checkconf 'echo "options {"; echo "	directory \"/var/cache/bind\";"; echo "};"'
  mkdir -p /var/cache/bind
}
real() { keep real_run "$@"; }
real_run() { # [env...]: the installer for real, against the stub, with the shims first on PATH
  # the box's own servers hidden: they live under /usr/sbin, and the tools the run needs do not
  env PATH="$SH:/usr/bin:/bin" WHISPER_EDGE_RESOLVE="$RES" WHISPER_EDGE_LSWS_ROOT="$SR/lsws" \
    WHISPER_EDGE_PROTECTED_HARDLINKS="${HLFILE:-/proc/sys/fs/protected_hardlinks}" "$@" sh "$INSTALL" --base "$FEED"
}
# the header facts, read here and never from the installer; a missing file reads as a value no line
# carries, so the row that asked fails instead of the gate ending without a verdict under set -e
header_gen() { od -An -t u8 -j 16 -N 8 "$1" 2>/dev/null | tr -d ' ' || true; }
header_vu() {
  python3 -c 'import datetime, struct, sys
v = struct.unpack_from("<Q", open(sys.argv[1], "rb").read(), 32)[0]
print(datetime.datetime.fromtimestamp(v // 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"))' "$1" 2>/dev/null || echo "no file"
}
enabled() { [ -L "$REAL_UNITS/timers.target.wants/whisper-edge-refresh@$1.timer" ]; }
# The rows that read the per-plane units the installer writes need systemctl on the box: without it the
# installer writes none (it prints the cron lines instead), so those rows say SKIPPED with that cause.
units_here() { command -v systemctl >/dev/null 2>&1 && return 0; skip "$1" "no systemctl on this box, so the installer writes no units (it prints the cron lines); the certifying run has systemd"; return 1; }
begin_arm() { # <what>: the teardown, then the clean start asserted
  real_teardown
  _c=$(clean_start)
  [ -z "$_c" ] || { fail "$1: the clean start" "left behind: $_c"; return 1; }
  return 0
}

# disposable-root.sh on a systemd-resolved host: /etc/resolv.conf is a link into /run, which the root mounts
# afresh, so a root that kept the link resolved nothing (measured on a test host: apt's "Temporary
# failure resolving" and no module built). Its resolver step, run alone into a directory standing for the
# root: the host's file is a link (to a path the root does not have), the root's copy a dangling link as
# the overlay carries it; the root must end with a plain file of the host's nameservers. A resolver naming
# no nameserver is refused by name.
resolv_rows() {
  rs="$W/resolv"; rm -rf "$rs"; mkdir -p "$rs/host-run" "$rs/root/etc"
  printf 'nameserver 192.0.2.53\nnameserver 2001:db8::53\noptions edns0\n' > "$rs/host-run/stub-resolv.conf"; : > "$rs/host-run/empty.conf"
  ln -s "$rs/host-run/stub-resolv.conf" "$rs/host-resolv.conf"
  ln -s /run/systemd/resolve/stub-resolv.conf.not-here "$rs/root/etc/resolv.conf"
  ro=$(DISPOSABLE_ROOT_RESOLV="$rs/host-resolv.conf" sh "$HERE/disposable-root.sh" --put-resolver "$rs/root" 2>&1) && rrc=0 || rrc=$?
  { [ "$rrc" = 0 ] && [ -f "$rs/root/etc/resolv.conf" ] && [ ! -L "$rs/root/etc/resolv.conf" ] \
    && cmp -s "$rs/root/etc/resolv.conf" "$rs/host-run/stub-resolv.conf" && [ "$(stat -c %a "$rs/root/etc/resolv.conf")" = 644 ]; } \
    && pass "disposable-root.sh on a host whose /etc/resolv.conf is a link the root cannot follow: the root gets a plain file (0644) of the host's nameservers, read through the link" \
    || fail "disposable-root.sh with a linked resolver" "rc=$rrc $(printf '%s' "$ro" | head -2 | tr '\n' ';') root's: $(ls -l "$rs/root/etc/resolv.conf" 2>&1 | cut -c1-160)"
  rm -f "$rs/host-resolv.conf"; ln -s "$rs/host-run/empty.conf" "$rs/host-resolv.conf"
  ro=$(DISPOSABLE_ROOT_RESOLV="$rs/host-resolv.conf" sh "$HERE/disposable-root.sh" --put-resolver "$rs/root" 2>&1) && rrc=0 || rrc=$?
  { [ "$rrc" = 2 ] && says "$ro" "disposable-root: $rs/host-resolv.conf names no nameserver (read through any link: $rs/host-run/empty.conf)"; } \
    && pass "and a host resolver that names no nameserver is refused by name (exit 2), before any command could run" \
    || fail "disposable-root.sh with an empty resolver" "rc=$rrc: $(printf '%s' "$ro" | head -2 | tr '\n' ';')"
  rm -rf "$rs"
}
real_rows() {
  resolv_rows
  # As root (the ownership test is root's). The published repository is edge/ alone: a clone or an extraction of it inside a sticky,
  # world-writable directory (/tmp) must pass the checkout's ownership test, which walks up to the
  # checkout and no further; and the line that names a missing module's fix names a path that exists
  # in that checkout.
  box clone
  # the clone is a directory of /tmp itself, as `git clone` or an extraction there makes it
  CL=$(mktemp -d /tmp/whisper-edge-clone.XXXXXX); cp -a "$HERE/../." "$CL/"; chmod -R go-w "$CL"; chmod 0755 "$CL"
  mkdir -p "$W/clshim" "$W/clmods"
  printf '#!/bin/sh\ncase "$1" in -V) echo "nginx version: nginx/1.24.0" >&2; echo "configure arguments: --conf-path=%s/nginx.conf --modules-path=%s" >&2 ;; *) exit 0 ;; esac\n' "$W/clmods" "$W/clmods" > "$W/clshim/nginx"
  chmod 0755 "$W/clshim/nginx"; printf 'events { }\nhttp { }\n' > "$W/clmods/nginx.conf"
  # shellcheck disable=SC2086
  clo=$(env PATH="$W/clshim:/usr/bin:/bin" $BOXENV sh "$CL/install/install.sh" --dry-run --server nginx --dir "$B/lib" --base "$FEED" 2>&1) && clrc=0 || clrc=$?
  ! says "$clo" 'root will not copy or run it' \
    && pass "a clone of the published tree inside a sticky world-writable /tmp: the checkout's ownership test passes (it walks to the clone's root, not past it)" \
    || fail "a clone in /tmp is refused" "rc=$clrc $(printf '%s' "$clo" | grep -m1 'root will not copy or run it' | cut -c1-200)"
  hint=$(printf '%s\n' "$clo" | sed -n 's/.*nginx: the module is not installed .*build it and run this again: \([^ ]*\) --install.*/\1/p' | sed -n 1p)
  { [ -n "$hint" ] && [ -x "$hint" ] && case "$hint" in "$CL/"*) true ;; *) false ;; esac; } \
    && pass "the missing module's fix names a build script that exists in this checkout ($hint)" \
    || fail "the missing module's fix names a real path" "hint: ${hint:-none}; $(printf '%s' "$clo" | grep -m1 'module is not installed' | cut -c1-200)"
  rm -rf "$CL"
  echo "--- real runs, as root, on this disposable box"
  # The clean-start assert can fail: a planted leftover instance timer must be seen by it.
  real_teardown; mkdir -p "$REAL_UNITS"; : > "$REAL_UNITS/whisper-edge-refresh@tor.timer.d.leftover"
  mkdir -p "$REAL_UNITS/whisper-edge-refresh@tor.timer.d"
  [ -n "$(clean_start)" ] && pass "the control: the clean-start assert sees a planted leftover" \
    || fail "the clean-start control" "a planted leftover was not seen"
  real_teardown
  [ -z "$(clean_start)" ] && pass "and the teardown removes it" || fail "the teardown" "$(clean_start)"

  # The staging case: no web server and no BIND. The feed half is installed and kept fresh, nothing else.
  feed 497775 normal
  if begin_arm "staging"; then
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'no web server and no BIND here: the feed is staged' \
      && says "$out" 'no web configuration to reconcile the planes against yet: the fetch above proved the feed; staged: reputation' \
      && [ -s "$REAL_DIR/edge.pub" ] && [ -x "$REAL_SBIN/whisper-edge-refresh" ] && [ -f "$REAL_DIR/reputation.bin" ]; } \
      && pass "staging: the staging line names the staged plane, the key and the refresh are installed, reputation is fetched and verified" \
      || fail "the staging case" "rc=$rc $(printf '%s' "$out" | grep -E 'stag|FAIL|could' | head -4)"
    # S7: root copies or runs nothing from a checkout another account can change. A copy of this
    # directory with the refresh made group-writable is refused before anything is written; the same copy
    # with the mode put back gets past that check (the control).
    # a copy of the tree install/ ships in (its root is the checkout, in either layout)
    rm -rf "$W/s3"; mkdir -p "$W/s3"; cp -a "$HERE/../." "$W/s3/"; chown -R 0:0 "$W/s3"; chmod -R go-w "$W/s3"
    chmod g+w "$W/s3/install/whisper-edge-refresh"
    isave=$INSTALL; INSTALL=$W/s3/install/install.sh; rsave=$(stat -c '%Y %s' "$REAL_SBIN/whisper-edge-refresh")
    s3out=$(real) && s3rc=0 || s3rc=$?
    { [ "$s3rc" = 1 ] && says "$s3out" "install.sh: $W/s3/install/whisper-edge-refresh, or a directory above it in the checkout, is owned by an account other than root or you, or is writable by a group or others; root will not copy or run it; nothing was written" \
      && [ "$(stat -c '%Y %s' "$REAL_SBIN/whisper-edge-refresh")" = "$rsave" ]; } \
      && pass "a checkout whose refresh is writable by its group: refused before anything is written, the installed refresh untouched (exit 1)" \
      || fail "the checkout's ownership test" "rc=$s3rc $(printf '%s' "$s3out" | head -2 | cut -c1-200)"
    chmod g-w "$W/s3/install/whisper-edge-refresh"
    s3out=$(real) && s3rc=0 || s3rc=$?
    ! says "$s3out" 'root will not copy or run it' \
      && pass "the control: the same copy with its modes put back passes that test" \
      || fail "the checkout test's control" "rc=$s3rc $(printf '%s' "$s3out" | head -2 | cut -c1-200)"
    INSTALL=$isave; rm -rf "$W/s3"
    if command -v systemctl >/dev/null 2>&1; then
      { enabled reputation && enabled tor && enabled rpki-unreachable; } \
        && pass "and the per-plane instances are enabled, one per plane the policy reads" \
        || fail "staging enables the per-plane instances" "$(ls "$REAL_UNITS/timers.target.wants" 2>&1)"
    else
      skip "staging enables the per-plane instances" "no systemctl on this box"
    fi
    if [ "$SYSD" = 1 ]; then
      { systemctl is-active --quiet whisper-edge-refresh@reputation.timer && systemctl is-active --quiet whisper-edge-refresh@tor.timer; } \
        && pass "each enabled instance is active, not only present: started with the install" \
        || fail "the instances are active" "$(systemctl is-active whisper-edge-refresh@reputation.timer whisper-edge-refresh@tor.timer 2>&1 | tr '\n' ' ')"
      # the effective schedule over the template and its drop-in, not the drop-in file alone
      tc=$(systemctl show whisper-edge-refresh@tor.timer -p TimersCalendar --value 2>/dev/null)
      rc_=$(systemctl show whisper-edge-refresh@reputation.timer -p TimersCalendar --value 2>/dev/null)
      { [ "$(printf '%s\n' "$tc" | grep -c 'OnCalendar=')" = 1 ] && says "$tc" 'OnCalendar=\*-\*-\* \*:00/30:00' \
        && [ "$(printf '%s\n' "$rc_" | grep -c 'OnCalendar=')" = 1 ] && says "$rc_" 'OnCalendar=\*-\*-\* \*:00:00'; } \
        && pass "the effective schedule: one calendar per instance, tor every 30 minutes and reputation hourly, nothing doubled" \
        || fail "the effective schedule" "tor=[$tc] reputation=[$rc_]"
    else
      skip "the instances are active, and their effective schedule" "systemd is not running on this box"
    fi
    { [ ! -e "$REAL_ETC/policy.conf" ] && [ ! -e /etc/nginx/conf.d/whisper-edge.conf ] && [ ! -e /etc/apache2/conf-available/whisper-edge.conf ]; } \
      && pass "and no policy.conf and no web drop-in is written" || fail "staging writes no policy" "$(ls "$REAL_ETC")"

    # the armed line: the file's own header generation, never the manifest's build generation
    g=$(header_gen "$REAL_DIR/reputation.bin"); d16=$( { sha256sum < "$REAL_DIR/reputation.bin" || echo none; } 2>/dev/null | cut -c1-16); vu=$(header_vu "$REAL_DIR/reputation.bin")
    { [ "$g" = 497775 ] && says "$out" "reputation armed, generation 497775, digest $d16, valid until $vu" && ! says "$out" 'generation 1791990002'; } \
      && pass "armed: the plane's own header generation (497775, not the manifest's 1791990002), digest16 and valid-until read independently here" \
      || fail "the armed line" "g=$g $(printf '%s' "$out" | grep 'reputation armed')"
    says "$out" 'tor withheld by the signed manifest: LOW_RECALL, IPV6_NOT_STATED; log if tor_exit is inert at launch; it arms at the next reload after the refresh first installs tor.bin' \
      && pass "withheld: the inert words, the signed reasons list joined, and when it arms" \
      || fail "the withheld line" "$(printf '%s' "$out" | grep tor | head -2)"
    says "$out" 'rpki-unreachable: the manifest names no such plane; log if rpki_unreachable is inert at launch' \
      && pass "absent: the manifest names no such plane, and its rule is inert" \
      || fail "the absent line" "$(printf '%s' "$out" | grep rpki | head -2)"
    says "$out" 'reputation.bin was installed for the first time' \
      && pass "the first install of a plane says it binds when the server reads its configuration" \
      || fail "the first-install line" "$(printf '%s' "$out" | grep reputation | head -3)"
    # the report's order, and the line to watch last
    order=$(printf '%s\n' "$out" | sed -n 's/^== //p' | tr '\n' ' ')
    last=$(printf '%s\n' "$out" | sed -n '$p')
    { [ "$order" = "detected armed applied proved undo " ] && case "$last" in "watch: reputation generation 497775, digest $d16"*) true ;; *) false ;; esac; } \
      && pass "the report: detected, armed, applied, proved, undo, and the line to watch last, naming the armed generation and digest" \
      || fail "the report's order" "$order / $last"
    say_undo=$(printf '%s\n' "$out" | sed -n 's/^   undo, the shared parts (after every server line): //p')
    if units_here "the shared undo line, idempotence and the undo of the units"; then
    [ -n "$say_undo" ] && pass "the undo block carries the shared line" || fail "the shared undo line" "$(printf '%s' "$out" | sed -n '/== undo/,$p')"
    [ -z "$(find "$REAL_ETC/undo" -mindepth 1 ! -name last-report 2>/dev/null)" ] && pass "a completed run leaves no stamp in the undo directory" \
      || fail "a completed run removes its stamp" "$(find "$REAL_ETC/undo" -mindepth 1 ! -name last-report)"

    # idempotence: a second run changes no byte and no mtime of anything it owns
    snap=$(find "$REAL_UNITS" "$REAL_ETC" "$REAL_DIR" "$REAL_SBIN/whisper-edge-refresh" -xdev \( -type f -o -type l \) \
      ! -name '*.prom' ! -name '.refresh-*' ! -name install.lock ! -name last-report -exec stat -c '%n %Y %s' {} + 2>/dev/null | sort)
    # the next second, so an mtime the second run touched cannot read the same (the property is an mtime
    # compare at a second's resolution; this is not a wait on anything)
    _s0=$(date +%s); wait_until 60 sh -c "[ \$(date +%s) -gt $_s0 ]" || :
    out2=$(real) && rc=0 || rc=$?
    snap2=$(find "$REAL_UNITS" "$REAL_ETC" "$REAL_DIR" "$REAL_SBIN/whisper-edge-refresh" -xdev \( -type f -o -type l \) \
      ! -name '*.prom' ! -name '.refresh-*' ! -name install.lock ! -name last-report -exec stat -c '%n %Y %s' {} + 2>/dev/null | sort)
    { [ "$rc" = 0 ] && [ "$snap" = "$snap2" ] && says "$out2" "already present: $REAL_UNITS/whisper-edge-refresh@.service" \
      && says "$out2" 'reputation armed, generation 497775'; } \
      && pass "a second run with the same inputs changes no byte and no mtime, and says already present per file" \
      || fail "the second run is idempotent" "rc=$rc $(printf '%s\n%s\n' "$snap" "$snap2" | sort | uniq -u | head -4)"
    [ -z "$(find "$REAL_ETC/undo" -mindepth 1 ! -name last-report 2>/dev/null)" ] && pass "and leaves no new stamp" || fail "the second run's stamp" "$(find "$REAL_ETC/undo" -mindepth 1 ! -name last-report)"

    # the shared undo line, run as printed: the per-plane units gone, the feed products kept
    suo=$(sh -c "$say_undo" 2>&1) && rc=0 || rc=$?
    # what it prints is read by a person: no quoting residue (a doubled-quoted apostrophe printed "\s")
    case "$suo" in *\\*) fail "the shared undo line's words" "it printed a backslash: $(printf '%s' "$suo" | grep -F '\' | head -2)" ;;
      *) pass "the shared undo line prints its words as written, no quoting residue" ;; esac
    { [ "$rc" = 0 ] && [ ! -e "$REAL_UNITS/whisper-edge-refresh@.service" ] && [ ! -e "$REAL_UNITS/whisper-edge-refresh@.timer" ] \
      && [ -z "$(ls -d "$REAL_UNITS"/whisper-edge-refresh@*.timer.d "$REAL_UNITS"/timers.target.wants/whisper-edge-refresh@* 2>/dev/null)" ] \
      && [ -f "$REAL_DIR/reputation.bin" ] && [ -s "$REAL_DIR/edge.pub" ]; } \
      && pass "the shared undo line, run as printed: the template pair, the instances and their schedules gone; the planes and the key kept" \
      || fail "the shared undo line" "rc=$rc $(find "$REAL_UNITS" -name 'whisper-edge-refresh@*')"
    fi
  fi

  # O8, the legacy snapshot timer an earlier install left: the tree's own file, enabled, is disabled (so two
  # fetchers never race for the planes' directory) and the shared undo line enables it again; one that is
  # not the tree's file is only named, and stays as it was
  if [ "$SYSD" = 1 ] && begin_arm "the legacy timer"; then
    cp "$HERE/whisper-edge-refresh.timer" "$HERE/whisper-edge-refresh.service" "$REAL_UNITS/"
    systemctl daemon-reload; systemctl enable whisper-edge-refresh.timer >/dev/null 2>&1 || :
    out=$(real) && rc=0 || rc=$?
    say_undo=$(printf '%s\n' "$out" | sed -n 's/^   undo, the shared parts (after every server line): //p')
    { [ "$rc" = 0 ] && says "$out" 'disabled the earlier snapshot timer' && ! systemctl is-enabled --quiet whisper-edge-refresh.timer \
      && [ -f "$REAL_ETC/legacy-timer.disabled" ]; } \
      && pos_pass legacy-timer "O8: the earlier installer's own snapshot timer, enabled, is disabled and recorded" \
      || fail "O8: the legacy timer is disabled" "rc=$rc enabled=$(systemctl is-enabled whisper-edge-refresh.timer 2>&1) $(printf '%s' "$out" | grep -i 'snapshot timer' | head -2)"
    sh -c "$say_undo" >/dev/null 2>&1 || :
    { systemctl is-enabled --quiet whisper-edge-refresh.timer && [ ! -e "$REAL_ETC/legacy-timer.disabled" ]; } \
      && pass "O8: and the shared undo line enables it again" \
      || fail "O8: the undo re-enables the legacy timer" "enabled=$(systemctl is-enabled whisper-edge-refresh.timer 2>&1)"
    real_teardown
    printf '# the operator changed this\n' >> "$REAL_UNITS/whisper-edge-refresh.timer"; systemctl daemon-reload
    systemctl enable whisper-edge-refresh.timer >/dev/null 2>&1 || :
    out=$(real) && rc=0 || rc=$?
    { says "$out" 'the earlier snapshot timer is still installed and fetches snapshot.bin' && systemctl is-enabled --quiet whisper-edge-refresh.timer \
      && [ ! -e "$REAL_ETC/legacy-timer.disabled" ]; } \
      && neg legacy-timer "O8: a legacy timer that is not the tree's file is named, never disabled" \
      || fail "O8: a changed legacy timer is left alone" "rc=$rc enabled=$(systemctl is-enabled whisper-edge-refresh.timer 2>&1)"
    systemctl disable --now whisper-edge-refresh.timer >/dev/null 2>&1 || :
    rm -f "$REAL_UNITS/whisper-edge-refresh.timer" "$REAL_UNITS/whisper-edge-refresh.service"; systemctl daemon-reload
    real_teardown
  else
    [ "$SYSD" = 1 ] || skip "O8, the legacy snapshot timer" "systemd is not running on this box"
  fi
  # the lock: a held install lock is refused by the run and by an undo line, naming when the holder started
  if units_here "the lock against the undo lines, and the shared line's refusals" && begin_arm "the lock"; then
    out=$(real) && rc=0 || rc=$?
    say_undo=$(printf '%s\n' "$out" | sed -n 's/^   undo, the shared parts (after every server line): //p')
    ( exec 7>>"$REAL_ETC/install.lock"; flock 7; echo 2026-10-16T01:02:03Z > "$REAL_ETC/install.lock"; exec tail -f /dev/null ) &
    hold=$!; i=0; while [ "$i" -lt 600 ] && [ ! -s "$REAL_ETC/install.lock" ]; do sleep 0.1; i=$((i + 1)); done
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" != 0 ] && says "$out" 'another installer run is in progress, started at 2026-10-16T01:02:03Z'; } \
      && pass "a run while another holds the lock: refused in one line naming when the holder started" \
      || fail "the lock refuses a second run" "rc=$rc $(printf '%s' "$out" | grep -i 'another\|progress' | head -2)"
    u=$(sh -c "$say_undo" 2>&1) && rc=0 || rc=$?
    { [ "$rc" = 75 ] && says "$u" 'another installer run is in progress, started at 2026-10-16T01:02:03Z; nothing was removed' \
      && [ -e "$REAL_UNITS/whisper-edge-refresh@.service" ]; } \
      && pass "the shared undo line pasted during an install: refused, naming the holder, nothing removed" \
      || fail "the undo line takes the lock" "rc=$rc $u"
    kill "$hold" 2>/dev/null || true; wait "$hold" 2>/dev/null || true
    # the shared line refuses while a server still applies the policy
    nginx_shim with-module
    out=$(real) && rc=0 || rc=$?
    say_undo=$(printf '%s\n' "$out" | sed -n 's/^   undo, the shared parts (after every server line): //p')
    WHISPER_EDGE_INSTALL_TEST_RENDER=nginx sh "$HERE/install.sh" > "$SR/nginx/conf.d/whisper-edge.conf" || true
    u=$(sh -c "$say_undo" 2>&1) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && says "$u" "nginx still applies the policy" && [ -e "$REAL_UNITS/whisper-edge-refresh@.service" ]; } \
      && pass "the shared line pasted before a server's own: refused, naming that server, nothing removed" \
      || fail "the shared line's out-of-order refusal" "rc=$rc $u $(printf '%s\n' "$out" | grep -E 'install.sh:|nginx:|unexpectedly|could not' | head -8 | cut -c1-300)"
    printf '\n# my edit\n' >> "$SR/nginx/conf.d/whisper-edge.conf"
    u=$(sh -c "$say_undo" 2>&1) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$u" 'kept the refresh units' && enabled reputation && [ -e "$REAL_UNITS/whisper-edge-refresh@.service" ]; } \
      && pass "a server file the operator edited still reads the planes: the shared line keeps the units and the instances, and says why" \
      || fail "the shared line keeps the units under a live reader" "rc=$rc $u"
  fi

  # the module missing: the first line names it, the arm stops before any plane fetch, no instance
  if begin_arm "the module missing"; then
    nginx_shim
    out=$(real) && rc=0 || rc=$?
    first=$(printf '%s\n' "$out" | sed -n '/^== detected/{n;p;}')
    { [ "$rc" = 0 ] && case "$first" in "   nginx: the module is not installed"*"build it and run this again"*) true ;; *) false ;; esac \
      && [ ! -e "$REAL_DIR/reputation.bin" ] && ! enabled reputation \
      && [ -z "$(find "$SR/nginx/conf.d" "$SR/nginx/modules-enabled" -mindepth 1 2>/dev/null)" ]; } \
      && pass "a server without its module: the first line names it and the fix, no plane fetched, no instance, the configuration untouched" \
      || fail "the module-missing stop" "rc=$rc first=[$first] planes: $(ls "$REAL_DIR" 2>&1 | tr '\n' ' ') reputation instance: $(enabled reputation && echo enabled || echo not enabled) left in the shim's tree: $(find "$SR/nginx/conf.d" "$SR/nginx/modules-enabled" -mindepth 1 2>/dev/null | tr '\n' ' ')
     detected: $(printf '%s\n' "$out" | sed -n '/^== detected/,/^== armed/p' | head -8 | tr '\n' ';' | cut -c1-600)"
  fi

  # BIND alone: the resolver half, no plane, one line
  if begin_arm "BIND alone"; then
    named_shim
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'BIND alone: the resolver half is installed, and no plane is fetched' \
      && [ ! -e "$REAL_DIR/reputation.bin" ] && [ -d /var/cache/bind/whisper-edge ] && says "$out" 'zone "rpz.whisper.online"'; } \
      && pass "BIND alone: the zone directory, the zone timers and the block to add; no plane fetched; one line saying so" \
      || fail "the BIND-only case" "rc=$rc $(printf '%s' "$out" | grep -iE 'bind|zone' | head -3)"
  fi

  # the hardlink sysctl, through its twin: warned at 0, silent at 1, never a stop
  if begin_arm "the hardlink sysctl"; then
    HLFILE="$W/hardlinks"; echo 0 > "$HLFILE"
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'fs.protected_hardlinks is 0, not 1: a hard link to an armed plane file can change what the workers serve'; } \
      && pass "fs.protected_hardlinks 0 (through the twin): one warning line naming the consequence, and the install goes on" \
      || fail "the hardlink warning" "rc=$rc"
    echo 1 > "$HLFILE"; real_teardown
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && ! says "$out" 'protected_hardlinks'; } \
      && pass "at 1, no warning line" || fail "no hardlink warning at 1" "$(printf '%s' "$out" | grep hardlinks)"
    HLFILE=""
  fi

  # the failing and the kept states of a plane
  if begin_arm "the published plane that does not arrive"; then
    feed 497775 nofile
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" != 0 ] && says "$out" 'reputation is published but this fetch left no file, so its rules would be inert; nothing is applied' \
      && [ ! -e "$REAL_DIR/reputation.bin" ]; } \
      && pass "published but not fetched: the run fails before any configuration, with the refresh's own line" \
      || fail "the published-but-unfetched state" "rc=$rc $(printf '%s' "$out" | grep -E 'reputation|refresh:' | head -3)"
  fi
  if begin_arm "a prior file, this fetch failed"; then
    feed 497775 normal; real >/dev/null 2>&1 || true
    feed 497775 nofile
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'reputation kept, generation 497775, digest .* (computed here over the file), valid until .*: this fetch failed, and the installed file matches the signed manifest' \
      && ! says "$out" 'reputation armed'; } \
      && pass "a prior file and a failed plane fetch: kept, matching the signed manifest, its digest labelled as computed here" \
      || fail "the kept-and-matching state" "rc=$rc $(printf '%s' "$out" | grep -E 'reputation' | head -3)"
    feed 497776 nofile
    before=$(sha256sum < "$REAL_DIR/reputation.bin" 2>/dev/null || echo none)
    out=$(real) && rc=0 || rc=$?
    { [ "$rc" != 0 ] && says "$out" 'is not the plane the signed manifest now states' && [ "$(sha256sum < "$REAL_DIR/reputation.bin" 2>/dev/null || echo gone)" = "$before" ]; } \
      && pass "a prior file the manifest has moved past and a failed fetch: the run fails, the prior file stays" \
      || fail "the moved-past state" "rc=$rc $(printf '%s' "$out" | grep -E 'reputation' | head -3)"
    out=$(real WHISPER_EDGE_RESOLVE="edge.installer-gate.invalid:$PORT:127.0.0.2") && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'the manifest could not be fetched either, and the file.s header parses and it is inside its own window' \
      && ! says "$out" 'reputation armed' \
      && says "$out" 'tor: no file, and the manifest could not be read; log if tor_exit is inert at launch'; } \
      && pass "a prior file with the feed unreachable: kept on its header and window alone, never called verified; tor, with no file and no manifest, is inert and the run goes on" \
      || fail "the unreachable-feed kept state" "rc=$rc $(printf '%s' "$out" | grep -E 'reputation' | head -3)"
    feed 497775 normal
  fi

  # the seventh state for a plane a deny rule reads: no file, no manifest: the run stops before anything
  if begin_arm "a deny plane with no file and no manifest"; then
    mkdir -p "$REAL_DIR"; cp "$K/key.pub" "$REAL_DIR/edge.pub"
    out=$(real WHISPER_EDGE_RESOLVE="edge.installer-gate.invalid:$PORT:127.0.0.2") && rc=0 || rc=$?
    { [ "$rc" != 0 ] && says "$out" 'reputation: no file, and the manifest could not be read, so its deny rules would be inert; nothing is applied' \
      && [ ! -e "$REAL_ETC/policy.conf" ]; } \
      && pass "a deny plane with no file and the manifest unreadable: the run stops before any configuration" \
      || fail "the seventh state for a deny plane" "rc=$rc $(printf '%s' "$out" | grep -E 'reputation' | head -2)"
  fi

  # a format-2 plane's period, from the cadence the manifest signs: the bound's three outcomes
  for c in 3600:30 2400:13 1800:none; do
    cs=${c%%:*}; want=${c#*:}
    units_here "the cadence bound at $cs s" || continue
    begin_arm "tor published at cadence $cs" || continue
    feed 497775 "torpub$cs"
    out=$(real) && rc=0 || rc=$?
    d="$REAL_UNITS/whisper-edge-refresh@tor.timer.d/tor.conf"
    if [ "$want" = none ]; then
      { [ "$rc" = 0 ] && says "$out" "tor is published, but its signed cadence (cadenceSeconds $cs) leaves no refresh period inside its window" \
        && says "$out" 'log if tor_exit is inert at launch' && [ ! -e "$d" ] && [ ! -e "$REAL_DIR/tor.bin" ] && ! enabled tor && enabled reputation \
        && says "$out" '--cycle tor=none,'; } \
        && pass "cadence $cs s: no period fits, so no schedule, no instance, nothing fetched, the rule inert, and the numbers said" \
        || fail "the cadence bound's no-solution case" "rc=$rc $(printf '%s' "$out" | grep -E '^   tor' | head -2) $(find "$REAL_UNITS" -name '*tor*')"
    else
      { [ "$rc" = 0 ] && hasline "$(cat "$d" 2>/dev/null)" "OnCalendar=*:0/$want" && says "$out" "enabled whisper-edge-refresh@tor.timer (every $want min" \
        && [ -f "$REAL_DIR/tor.bin" ] && says "$out" "--cycle tor=$((want * 60)),$cs,"; } \
        && pass "cadence $cs s: tor's period is $want minutes, the largest whole minute the bound allows up to 30" \
        || fail "the cadence bound at $cs s" "rc=$rc $(tail -n 2 "$d" 2>&1)"
    fi
  done
  feed 497775 normal

  # The resolver half's scheduling, read from the unit files the run wrote: the zone template runs
  # --if-due and the zone from its instance, writes only the zones' directory, and no web-half unit
  # runs a zone; the block names the files that directory holds and never servfail-until-ready.
  if units_here "the resolver half's units" && begin_arm "the resolver half's units"; then
    nginx_shim with-module; named_shim
    out=$(real) && rc=0 || rc=$?
    rz=$(sed -n 's/^ExecStart=//p' "$REAL_UNITS/whisper-edge-rpz@.service" 2>/dev/null)
    rw=$(sed -n 's/^ReadWritePaths=//p' "$REAL_UNITS/whisper-edge-rpz@.service" 2>/dev/null)
    pz=$(sed -n 's/^ExecStart=//p' "$REAL_UNITS/whisper-edge-refresh@.service" 2>/dev/null)
    za=$(printf '%s\n' "$rz" | sed -n 's/.*--zone-file \([^ ]*\).*/\1/p')
    if [ -z "$rz" ] || [ -z "$pz" ]; then
      fail "the resolver half's units are read" "the run wrote no whisper-edge-rpz@.service or no whisper-edge-refresh@.service ExecStart (rc=$rc)"
    else
      case "$rz" in *" --if-due "*"--zone %i") pass "the zone template runs the refresh with --if-due and the zone from its instance" ;;
        *) fail "the zone template runs --zone %i --if-due" "'$rz'" ;; esac
      case "$pz" in *"--zone"*|*"--rpz"*) fail "the control: the per-plane template must not run a zone" "'$pz'" ;;
        *" --plane %i "*) pass "the control: the same check refuses the per-plane template, which carries --plane %i and no zone" ;;
        *) fail "the per-plane template's command is read" "'$pz'" ;; esac
      { [ -n "$rw" ] && [ "${za%/}" = "$rw" ] && [ "$rw" = /var/cache/bind/whisper-edge ]; } \
        && pass "its one writable path is the zones' own directory ($rw)" || fail "the zone unit can write its zones" "ReadWritePaths='$rw' --zone-file='$za'"
      { says "$out" "file \"$rw/rpz.zone\";" && says "$out" "file \"$rw/rpz-rpki-unreachable.whisper.online.zone\";" && ! says "$out" 'servfail-until-ready'; } \
        && pass "the block loads each zone from the file the refresh writes there, and never suggests servfail-until-ready" \
        || fail "the BIND block names the timer's files" "$rw"
      rpol=$(printf '%s\n' "$out" | sed -n '/response-policy {/,/qname-wait-recurse/p')
      { [ "$(printf '%s\n' "$rpol" | grep -n 'zone "rpz.whisper.online";' | cut -d: -f1)" = 2 ] \
        && says "$rpol" 'zone "rpz-rpki-unreachable.whisper.online" policy disabled log yes;'; } \
        && pass "the block lists reputation first, then RPKI-unreachable with policy disabled log yes" \
        || fail "the block's response-policy order and the RPKI log override" "$rpol"
      swapped=$(printf '%s\n' "$rpol" | sed 's/zone "rpz.whisper.online";/@@/; s/zone "rpz-rpki-unreachable.whisper.online" policy disabled log yes;/zone "rpz.whisper.online";/; s/@@/zone "rpz-rpki-unreachable.whisper.online" policy disabled log yes;/')
      [ "$(printf '%s\n' "$swapped" | grep -n 'zone "rpz.whisper.online";' | cut -d: -f1)" != 2 ] \
        && pass "the control: the same check refuses the block with the zones swapped" \
        || fail "the control: the swapped block must fail the order check" "$swapped"
      for z in rpz.whisper.online rpz-rpki-unreachable.whisper.online; do
        [ -L "$REAL_UNITS/timers.target.wants/whisper-edge-rpz@$z.timer" ] \
          && pass "the zone timer whisper-edge-rpz@$z.timer is enabled" || fail "one zone timer per zone" "$z"
      done
    fi
  fi

  # an interrupted run: killed at each point inside one write, then a re-run recovers it
  tgt="$REAL_UNITS/whisper-edge-refresh@tor.timer.d/tor.conf"
  for pt in before-temp before-rename after-rename; do
    units_here "the recovery after a kill $pt" || continue
    begin_arm "killed $pt" || continue
    real_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_KILL="$pt:$tgt" >/dev/null 2>&1 || true
    st=$(find "$REAL_ETC/undo" -maxdepth 1 -name 'run.*' 2>/dev/null | grep -c '' || true)
    tmp=$(find "$(dirname "$tgt")" -maxdepth 1 -name '*.whisper-edge.*' 2>/dev/null | grep -c '' || true)
    out=$(real) && rc=0 || rc=$?
    { [ "$st" = 1 ] && [ "$rc" = 0 ] && says "$out" 'recovered an interrupted run' \
      && [ -z "$(find "$REAL_ETC/undo" -mindepth 1 ! -name last-report)" ] && [ -z "$(find "$(dirname "$tgt")" -maxdepth 1 -name '*.whisper-edge.*')" ] \
      && cmp -s "$tgt" "$(WHISPER_EDGE_INSTALL_TEST_RENDER=cadence-tor sh "$HERE/install.sh" > "$W/want" || true; echo "$W/want")"; } \
      && pass "killed $pt (stamps left: $st, temps left: $tmp): the re-run sweeps the stamp and its temp and applies the write exactly once" \
      || fail "the recovery after a kill $pt" "stamps=$st rc=$rc $(printf '%s' "$out" | grep -E 'recover|kept' | head -2)"
  done
  if units_here "the recovery keeps an operator's file" && begin_arm "an operator's edit after a kill"; then
    real_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_KILL="after-rename:$tgt" >/dev/null 2>&1 || true
    mkdir -p "$(dirname "$tgt")"; printf '[Timer]\nOnCalendar=*:0/15\n' > "$tgt"
    out=$(real) && rc=0 || rc=$?
    { says "$out" "kept $tgt: an interrupted run began writing it and its bytes are not that run's own" && hasline "$(cat "$tgt")" 'OnCalendar=*:0/15'; } \
      && pass "a file the operator changed after the kill: named and left in place, never removed or overwritten" \
      || fail "the recovery keeps an operator's file" "rc=$rc $(printf '%s' "$out" | grep -E 'recover|kept|stop' | head -3)"
  fi
  # The SELinux branch under gawk, the policy tools standing in: selinuxenabled says yes, semanage keeps its
  # local rules in a file, restorecon does nothing. gawk is the awk that warns on an escape it does not know
  # (mawk passes "\." through silently), so every awk of the run is gawk here. The first run adds the rule
  # and labels the planes; the second finds the rule it added and says it is already present. A rule spec
  # that reached awk through -v lost its backslashes there, so it never read as present, and gawk's
  # warning reached the installer's stderr (the clean enforcing Rocky 9.8 run, gawk 5.1).
  if ! command -v gawk >/dev/null 2>&1; then skip "the SELinux branch under gawk" "no gawk on this host"
  elif begin_arm "the SELinux branch under gawk"; then
    SEF="$W/se.rules"; : > "$SEF"; : > "$W/gawk.used"
    shim selinuxenabled 'exit 0'
    shim restorecon 'exit 0'
    shim awk "echo used >> '$W/gawk.used'; exec gawk \"\$@\""
    shim semanage "f='$SEF'
case \"\$1 \$2\" in
  'fcontext -l') while IFS= read -r r; do printf '%s    all files    system_u:object_r:httpd_sys_content_t:s0\\n' \"\$r\"; done < \"\$f\" ;;
  'fcontext -a') printf '%s\\n' \"\$5\" >> \"\$f\" ;;
  'fcontext -d') grep -vxF -- \"\$3\" \"\$f\" > \"\$f.n\"; mv \"\$f.n\" \"\$f\" ;;
esac"
    se1=$(real) && serc1=0 || serc1=$?
    se2=$(real) && serc2=0 || serc2=$?
    sspec='/var/lib/whisper-edge/[^/]+\.bin'; cspec='/var/lib/whisper-edge/counters(/.*)?'
    # two rules: the planes' (read and map) and counters/' (the worker's own state), each added once
    { [ "$serc1" = 0 ] && [ "$serc2" = 0 ] && [ -s "$W/gawk.used" ] \
      && says "$se1" "labelled the planes in /var/lib/whisper-edge httpd_sys_content_t" \
      && says "$se1" "labelled /var/lib/whisper-edge/counters httpd_var_lib_t" \
      && hasline "$se2" "   already present: the SELinux file context for $sspec (httpd_sys_content_t)" \
      && hasline "$se2" "   already present: the SELinux file context for $cspec (httpd_var_lib_t)" \
      && [ "$(cat "$SEF")" = "$(printf '%s\n%s' "$sspec" "$cspec")" ] && ! printf '%s\n' "$se1" "$se2" | grep_any -iE 'awk:|escape sequence'; } \
      && pass "the SELinux branch under gawk ($(grep -c '' "$W/gawk.used") awk runs): each of the two rules (the planes', counters/') added once, found again by the second run (already present), and no awk warns" \
      || fail "the SELinux branch under gawk" "rc=$serc1/$serc2 rules: $(tr '\n' ';' < "$SEF"); $(printf '%s\n' "$se1" "$se2" | grep -iE 'awk|warning|SELinux|labelled' | head -4 | cut -c1-240)"
    real_teardown
  fi
}
# ---- W32, the nginx layouts: the probe's choice of directories, from each distribution's own nginx.conf,
# with no daemon (a shim reports the build's paths; the configuration test passes). Each layout either
# applies into the directories its nginx.conf includes, or prints the block and stops, naming why.
layout_rows() {
  echo "--- W32: the nginx layouts the probe reads"
  for L in debian rhel alpine source nohttp; do
    begin_arm "the $L layout" || continue
    R="$SR/$L"; mkdir -p "$R/modules"
    : > "$R/modules/ngx_http_whisper_edge_module.so"
    case "$L" in
      debian) mkdir -p "$R/modules-enabled" "$R/conf.d" "$R/sites-enabled"
              printf 'include %s/modules-enabled/*.conf;\nevents { }\nhttp {\n    include %s/conf.d/*.conf;\n    include %s/sites-enabled/*;\n}\n' "$R" "$R" "$R" > "$R/nginx.conf"
              want_load="$R/modules-enabled/50-whisper-edge.conf"; want_drop="$R/conf.d/whisper-edge.conf" ;;
      rhel)   mkdir -p "$R/share-modules" "$R/conf.d"
              printf 'include %s/share-modules/*.conf;\nevents { }\nhttp {\n    include %s/conf.d/*.conf;\n}\n' "$R" "$R" > "$R/nginx.conf"
              want_load="$R/share-modules/50-whisper-edge.conf"; want_drop="$R/conf.d/whisper-edge.conf" ;;
      alpine) mkdir -p "$R/http.d"
              printf 'events { }\nhttp {\n    include %s/http.d/*.conf;\n}\n' "$R" > "$R/nginx.conf"
              want_load=""; want_drop="includes no module directory at the main level" ;;
      source) printf 'events { }\nhttp {\n    server { listen 8080; }\n}\n' > "$R/nginx.conf"
              want_load=""; want_drop="includes no directory of \*.conf files" ;;
      nohttp) mkdir -p "$R/conf.d"
              printf 'include %s/conf.d/*.conf;\nevents { }\nhttp {\n    server { listen 8080; }\n}\n' "$R" > "$R/nginx.conf"
              want_load=""; want_drop="includes no directory of \*.conf files" ;;
    esac
    shim nginx "case \"\$1\" in
  -V) echo 'nginx version: nginx/1.24.0' >&2; echo 'configure arguments: --conf-path=$R/nginx.conf --modules-path=$R/modules --pid-path=$R/nginx.pid' >&2 ;;
  -T) cat '$R/nginx.conf'; for f in $R/conf.d/*.conf $R/http.d/*.conf; do [ -f \"\$f\" ] && cat \"\$f\"; done; exit 0 ;;
  *) exit 0 ;;
esac"
    out=$(real) && rc=0 || rc=$?
    if [ -n "$want_load" ]; then
      { [ -f "$want_load" ] && [ -f "$want_drop" ] && says "$out" "wrote $want_drop (the default policy, 13 lines)" \
        && says "$out" "undo, nginx: sh -c"; } \
        && pass "W32 $L: the load line in $(basename "$(dirname "$want_load")")/, the drop-in in $(basename "$(dirname "$want_drop")")/, and an undo line for both" \
        || fail "W32 $L: the directories its nginx.conf includes" "rc=$rc $(printf '%s\n' "$out" | grep -E 'install.sh:|nginx:|unexpectedly|would|could not' | head -8 | cut -c1-300)"
    else
      { says "$out" "nginx: nothing was applied: .*$want_drop" && [ -z "$(find "$R" -name 'whisper-edge.conf' -o -name '50-whisper-edge.conf')" ]; } \
        && pass "W32 $L: nowhere to add a file without editing nginx.conf, so the block is printed and nothing is written" \
        || fail "W32 $L: printed and stopped" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-200)"
    fi
  done
  echo "--- W32: the Apache layouts the probe reads"
  # no daemon: httpd and apachectl are stand-ins on PATH reporting a version and a server root, so the probe
  # reads each layout as a box of that kind lays it out. Debian's (conf-available with a2enconf) is the
  # real Apache's, covered by the server rows; here the others.
  mkdir -p /usr/local/apache2/modules; : > /usr/local/apache2/modules/mod_whisper_edge.so
  hid=""; for d in /etc/httpd /etc/apache2; do [ -e "$d" ] && mv "$d" "$d.w32" && hid="$hid $d"; done
  rm -f "$SH/nginx"
  # rhel-ctl is RHEL's layout with RHEL's own apachectl, a systemd wrapper that refuses every word past its
  # first: the probe passes it by and asks httpd itself, so the module httpd -M lists reads as loaded and
  # the user httpd -S names is the one the counters are granted to (through the wrapper, neither is seen)
  # rhel-plain and rhel-quiet: the configuration test fails, once with only a line no error keyword finds
  # (RHEL's apachectl refusal, word for word) and once printing nothing: the refusal carries that line, or
  # says what was run and that it printed nothing, never an empty reason
  for L in rhel rhel-ctl rhel-plain rhel-quiet upstream unknown; do
    begin_arm "the Apache $L layout" || continue
    R="$SR/ap-$L"; rm -rf "$R"; mkdir -p "$R"
    case "$L" in
      rhel|rhel-ctl|rhel-plain|rhel-quiet) mkdir -p /etc/httpd/conf.d /etc/httpd/conf; printf 'ServerRoot "/etc/httpd"\nIncludeOptional conf.d/*.conf\n' > /etc/httpd/conf/httpd.conf
                want=/etc/httpd/conf.d/whisper-edge.conf ;;
      upstream) mkdir -p "$R/conf/extra"; want="" ;;
      unknown)  mkdir -p /etc/apache2/conf.d; printf 'IncludeOptional /etc/apache2/conf.d/*.conf\n' > /etc/apache2/httpd.conf; want="" ;;
    esac
    shim httpd "case \"\$1\" in -v) echo 'Server version: Apache/2.4.62 (Unix)' ;; -V) echo ' -D HTTPD_ROOT=\"$R\"' ;; esac; exit 0"
    shim apachectl "case \" \$* \" in *' -M '*) echo ' core_module (static)' ;; *' -t '*) echo 'Syntax OK' >&2 ;; esac; exit 0"
    if [ "$L" = rhel-ctl ]; then
      shim httpd "case \" \$* \" in *' -v '*) echo 'Server version: Apache/2.4.62 (Rocky Linux)' ;; *' -V '*) echo ' -D HTTPD_ROOT=\"/etc/httpd\"' ;;
        *' -M '*) echo ' core_module (static)'; echo ' whisper_edge_module (shared)' ;; *' -S '*) echo 'User: name=\"daemon\" id=1' ;; *' -t '*) echo 'Syntax OK' >&2 ;; esac; exit 0"
      shim apachectl '[ "x$1" = x-k ] && shift
if [ -n "$2" ]; then echo Passing arguments to httpd using apachectl is no longer supported.; exit 1; fi
case "$1" in -t|configtest) echo "Syntax OK" >&2 ;; start|stop|restart|status|graceful) ;; -v|-V) exec httpd "$1" ;; *) echo "apachectl: The \"$1\" option is not supported." >&2; exit 2 ;; esac'
    fi
    case "$L" in
      rhel-plain) shim apachectl "case \" \$* \" in *' -t '*) echo 'Passing arguments to httpd using apachectl is no longer supported.'; exit 1 ;; esac; exit 0" ;;
      rhel-quiet) shim apachectl "case \" \$* \" in *' -t '*) exit 1 ;; esac; exit 0" ;;
    esac
    out=$(real) && rc=0 || rc=$?
    if [ "$L" = rhel-plain ] || [ "$L" = rhel-quiet ]; then
      if [ "$L" = rhel-plain ]; then wr='Passing arguments to httpd using apachectl is no longer supported\.'; else wr='apachectl -t exited 1 and printed nothing'; fi
      { [ "$rc" = 1 ] && says "$out" "Apache: your configuration fails its own test before any change: $wr; nothing was written" && [ ! -f "$want" ]; } \
        && pass "W32 Apache $L: a configuration test that fails $( [ "$L" = rhel-plain ] && echo 'with only a line no error keyword finds' || echo 'printing nothing') is refused with $( [ "$L" = rhel-plain ] && echo 'that line' || echo 'what was run and that it printed nothing'), never an empty reason; nothing written" \
        || fail "W32 Apache $L: the refusal's reason" "rc=$rc $(printf '%s\n' "$out" | grep -E 'Apache:' | head -3 | cut -c1-240)"
    elif [ "$L" = rhel-ctl ]; then
      { [ -f "$want" ] && says "$out" 'Apache 2.4.62 at .*(loaded: yes, running: no), runs as daemon' && says "$out" 'Apache: the configuration test passed' \
        && ! grep -q '^LoadModule' "$want" /etc/httpd/conf.d/*.conf 2>/dev/null; } \
        && pass "W32 Apache rhel-ctl: RHEL's apachectl refuses arguments, so the probe asks httpd itself: the module it lists reads as loaded (no second LoadModule) and the user -S names (daemon) is the worker's" \
        || fail "W32 Apache rhel-ctl: the probe through RHEL's apachectl" "rc=$rc $(printf '%s\n' "$out" | grep -E 'Apache|install.sh:' | head -4 | cut -c1-260)"
    elif [ -n "$want" ]; then
      { [ -f "$want" ] && says "$out" "wrote $want (the default policy" && says "$out" 'Apache: the configuration test passed' && says "$out" 'undo, Apache: sh -c'; } \
        && pass "W32 Apache $L: the policy in conf.d/, its LoadModule beside it, the stand-in's test passed, and an undo line" \
        || fail "W32 Apache $L: the directory its main configuration includes" "rc=$rc $(printf '%s\n' "$out" | grep -E 'install.sh:|Apache:|unexpectedly|could not' | head -6 | cut -c1-260)"
    else
      { says "$out" "Apache: nothing was applied: this Apache's layout (" && [ -z "$(find "$R" /etc/apache2 -name 'whisper-edge.conf' 2>/dev/null)" ]; } \
        && pass "W32 Apache $L: no directory its main configuration is known to include, so the block is printed and nothing is written" \
        || fail "W32 Apache $L: printed and stopped" "rc=$rc $(printf '%s' "$out" | grep -E 'Apache:' | head -3 | cut -c1-220)"
    fi
    rm -rf /etc/httpd /etc/apache2 "$R"
  done
  rm -f "$SH/httpd" "$SH/apachectl" /usr/local/apache2/modules/mod_whisper_edge.so
  for d in $hid; do rm -rf "$d"; mv "$d.w32" "$d"; done
  real_teardown
}
if row real; then
  if [ "$REAL_OK" = 1 ]; then real_rows; layout_rows
  elif [ "$(id -u)" != 0 ]; then skip "the real runs" "they need root (install.sh refuses every run but a dry one without it)"
  else skip "the real runs" "this host is not marked disposable (INSTALLER_GATE_DISPOSABLE=1 on a throwaway guest only)"; fi
fi

# ===================================================================================================
# THE SERVERS: the default policy written into a real nginx and a real Apache with their modules built
# from this tree, tested, reloaded on a pass, and taken back by the printed undo line. Root, on a
# disposable box (disposable-root.sh on a host with no container runtime), the servers started by hand.
# Every negative arm runs after its positive control in the same run, and asserts which component
# refused: the installer's own line, the server's test, or the module.
# ===================================================================================================
# The record a server's configuration is compared by: every path under the trees, with its type, owner,
# group, mode, and for a file its sha256 and mtime, for a link its target. Directory mtimes are left out:
# a create and a remove each change them by definition.
record() { # <trees...>
  for _t in "$@"; do [ -e "$_t" ] && find "$_t" \( -name '*.conf0' -o -name '*,v' -o -name '*.conf.txt' -o -name RCS -o -path /etc/whisper-edge/undo -o -path /etc/whisper-edge/state \) -prune -o \
    ! -path /etc/whisper-edge/install.lock ! -path /etc/whisper-edge/key ! -path /etc/whisper-edge/key.id -print; done 2>/dev/null | LC_ALL=C sort | while IFS= read -r _p; do
    if [ -L "$_p" ]; then printf '%s link %s\n' "$_p" "$(readlink "$_p")"
    elif [ -d "$_p" ]; then printf '%s dir %s\n' "$_p" "$(stat -c '%u:%g:%a' "$_p")"
    else printf '%s file %s %s\n' "$_p" "$(stat -c '%u:%g:%a:%Y' "$_p")" "$(sha256sum < "$_p" | cut -c1-64)"; fi
    # what lives beside the bytes, where the host can show it: the SELinux context, the ACL, the xattrs
    if [ "$REC_CTX" = 1 ]; then printf '%s context %s\n' "$_p" "$(stat -c %C "$_p" 2>/dev/null)"; fi
    if [ "$REC_ACL" = 1 ] && [ ! -L "$_p" ]; then printf '%s acl %s\n' "$_p" "$(getfacl -cp "$_p" 2>/dev/null | tr '\n' ',')"; fi
    if [ "$REC_XATTR" = 1 ]; then printf '%s xattr %s\n' "$_p" "$(getfattr -h -d -m - --absolute-names "$_p" 2>/dev/null | grep -v '^#' | tr '\n' ',')"; fi
  done
}
REC_CTX=0; { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; } && REC_CTX=1
# Each server arm's stock configuration, kept when the arm begins and put back when it ends, whether its
# rows passed or failed (and at the gate's exit, for an arm that never reached its end): a failing arm
# must never leave the next run, or the next arm, a configuration that no longer tests clean.
STOCK_ARMS=""
srv_stock() { # <arm> <trees...>: the trees kept, with their record
  _sa=$1; shift
  rm -rf "$W/stock/$_sa"; mkdir -p "$W/stock/$_sa"
  printf '%s\n' "$@" > "$W/stock/$_sa/trees"
  # a tree whose copy failed is marked, and its restore never removes it: a teardown with no copy to put
  # back must not turn into a delete
  _si=0; for _st in "$@"; do _si=$((_si + 1)); if [ -e "$_st" ]; then cp -a "$_st" "$W/stock/$_sa/$_si" || { rm -rf "$W/stock/$_sa/$_si"; : > "$W/stock/$_sa/$_si.uncopied"; fail "keeping the stock $_st" "cp -a failed; the arm's teardown leaves that tree as it is"; }; fi; done
  record "$@" > "$W/stock/$_sa/record"
  STOCK_ARMS="$STOCK_ARMS $_sa"
}
srv_restore() { # <arm>: the trees back as they were kept; 0 when the record reads the same again
  _sa=$1; [ -f "$W/stock/$_sa/trees" ] || return 0
  _si=0
  while IFS= read -r _st; do
    _si=$((_si + 1))
    [ -n "$_st" ] || continue
    if [ -e "$W/stock/$_sa/$_si.uncopied" ]; then continue; fi
    chattr -R -i "$_st" 2>/dev/null || :
    rm -rf "$_st"
    if [ -e "$W/stock/$_sa/$_si" ] || [ -L "$W/stock/$_sa/$_si" ]; then cp -a "$W/stock/$_sa/$_si" "$_st" || return 1; fi
  done < "$W/stock/$_sa/trees"
  # shellcheck disable=SC2046 # the kept tree list, one path a line, none with a space
  [ "$(record $(cat "$W/stock/$_sa/trees"))" = "$(cat "$W/stock/$_sa/record")" ]
}
srv_teardown() { # <arm> <name>: the row every arm ends with, whatever its rows did
  if srv_restore "$1"; then pass "$2: the arm's teardown put its stock configuration back, byte for byte"
  else fail "$2: the arm's teardown" "the configuration does not read as kept: $(cat "$W/stock/$1/trees" | tr '\n' ' ')"; fi
  STOCK_ARMS=$(printf '%s' "$STOCK_ARMS" | tr ' ' '\n' | grep -vx "$1" | tr '\n' ' ')
}
# Apache started by hand with its own arguments, through the command that takes them (APDRV): RHEL's
# apachectl refuses every word past its first and hands a start to systemd, so there it is httpd itself;
# Debian's apache2ctl passes them on and also makes the run and lock directories its envvars name, which
# the bare binary does not (started that way on Ubuntu, the parent never came up, measured on Ubuntu 24.04)
ap_hand() { "/usr/sbin/$APDRV" "$@"; }
plane_at() { # <generation> <out file>: the installed reputation plane at another generation, 0444, root's
  mkdir -p "$(dirname "$2")"
  python3 - /var/lib/whisper-edge/reputation.bin "$2" "$1" <<'PY'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, int(sys.argv[3]))
b[104:136] = bytes(32)
b[104:136] = hashlib.sha256(bytes(b)).digest()
open(sys.argv[2], "wb").write(bytes(b))
PY
  chmod 0755 "$(dirname "$2")"; chmod 0444 "$2"
}
SE_GATE=0; command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null && SE_GATE=1
# on SELinux an operator labels their own plane the type a confined server maps, as the installer labels its
# own (the installer says so, with the lines to run, when it is not)
se_operator_label() { if [ "$SE_GATE" = 1 ]; then chcon -t httpd_sys_content_t "$1" 2>/dev/null || :; fi; return 0; }
srv_restore_all() { for _sa in $STOCK_ARMS; do srv_restore "$_sa" || :; done; STOCK_ARMS=""; }

REC_ACL=0; command -v getfacl >/dev/null 2>&1 && REC_ACL=1
REC_XATTR=0; command -v getfattr >/dev/null 2>&1 && REC_XATTR=1
record_covers() { _c=""; [ "$REC_CTX" = 1 ] && _c="$_c SELinux contexts,"; [ "$REC_ACL" = 1 ] && _c="$_c ACLs,"; [ "$REC_XATTR" = 1 ] && _c="$_c xattrs,"; echo "${_c:- bytes, owner, mode and mtime only (no getfacl, getfattr or SELinux here)}"; }
# The pause point's handshake, with a deadline on every wait: the installer opens the FIFO read-write and
# leaves a marker when it is there; the gate waits for the marker (at most 300 s, and only while the
# installer lives), and releases it by writing through its own read-write open, which never blocks.
PAUSE_DIR=/run/whisper-edge-gate
pause_arm() { mkdir -p "$PAUSE_DIR"; rm -f "$PAUSE_DIR/pause" "$PAUSE_DIR"/at.*; mkfifo "$PAUSE_DIR/pause"; }
pause_wait() { # <point> <installer pid>
  _pw=0
  while [ "$_pw" -lt 3000 ]; do
    [ -e "$PAUSE_DIR/at.$1" ] && return 0
    kill -0 "$2" 2>/dev/null || return 1
    sleep 0.1; _pw=$((_pw + 1))
  done
  return 1
}
pause_release() { exec 9<> "$PAUSE_DIR/pause"; echo go >&9; exec 9>&-; }
pause_done() { rm -f "$PAUSE_DIR/pause" "$PAUSE_DIR"/at.*; }
# a background installer that outlives its arm's deadline is ended by its own pid
bg_wait() { # <pid> -> its exit status, or 124 after 600 s (killed)
  _bw=0
  while kill -0 "$1" 2>/dev/null && [ "$_bw" -lt 600 ]; do sleep 1; _bw=$((_bw + 1)); done
  if kill -0 "$1" 2>/dev/null; then kill -KILL "$1" 2>/dev/null; wait "$1" 2>/dev/null; return 124; fi
  wait "$1"
}
# The reload counter: the server binaries the installer runs, wrapped so every reload is counted, and the
# real binary run underneath. A hand-started server reloads by signal, so the wrapper sees each one.
RLC="$W/reloads"
srv_shims() {
  shim nginx "case \" \$* \" in *' -s reload '*) echo nginx >> '$RLC' ;; esac; exec /usr/sbin/nginx \"\$@\""
  shim "$APCTL" "case \" \$* \" in *' graceful '*|*' -k graceful '*) echo apache >> '$RLC' ;; esac; exec /usr/sbin/$APCTL \"\$@\""
  [ "$APDRV" = "$APCTL" ] || shim "$APDRV" "case \" \$* \" in *' -k graceful '*) echo apache >> '$RLC' ;; esac; exec /usr/sbin/$APDRV \"\$@\""
  for _b in apache2 httpd apachectl a2enconf a2disconf a2query; do if [ -x "/usr/sbin/$_b" ] && [ ! -e "$SH/$_b" ]; then ln -sf "/usr/sbin/$_b" "$SH/$_b"; fi; done
}
# Under systemd the installer reloads through the unit, so the counter is a drop-in on the unit that adds
# one ExecReload line appending to the same file; the server's own reload still runs first.
unit_counter() { # <unit> <name>
  mkdir -p "/etc/systemd/system/$1.d"
  printf '[Service]\nExecReload=/bin/sh -c "echo %s >> %s"\n' "$2" "$RLC" > "/etc/systemd/system/$1.d/zz-installer-gate-count.conf"
  systemctl daemon-reload
}
unit_counters_off() { rm -f /etc/systemd/system/nginx.service.d/zz-installer-gate-count.conf /etc/systemd/system/apache2.service.d/zz-installer-gate-count.conf /etc/systemd/system/httpd.service.d/zz-installer-gate-count.conf; daemon_reload; }
# O11's compare beside the record: the effective configuration (what the server itself reads, every
# include resolved) and the unit's enabled and active states, the same after an undo as before the apply
eff_digest() { # <server>
  case "$1" in
    nginx) /usr/sbin/nginx -T 2>/dev/null | grep -v '^# configuration file ' | sha256sum | cut -c1-16 ;;
    apache) /usr/sbin/$APDRV -t -D DUMP_INCLUDES 2>&1 | sha256sum | cut -c1-16 ;;
  esac
}
unit_state() { if [ "$SYSD" = 1 ]; then printf '%s/%s' "$(systemctl is-enabled "$1" 2>/dev/null || :)" "$(systemctl is-active "$1" 2>/dev/null || :)"; else echo no-systemd; fi; }
srv_start() { # <unit> <name> <start command...>: through its unit when systemd runs it, else by hand
  _u=$1; _nm=$2; shift 2
  # a server that is already up stays up (a second start of it fails, which is not this row's business)
  if [ "$SYSD" = 1 ] && systemctl is-active --quiet "$_u" 2>/dev/null; then unit_counter "$_u" "$_nm"; else "$@" >/dev/null 2>&1 || :; fi
  case "$_nm" in nginx) wait_until 60 master_of 'nginx: master process' || : ;; *) wait_until 60 master_of '/usr/sbin/(apache2|httpd)' || : ;; esac
  # Ubuntu's apache2ctl start hands the start to systemd when it runs, so the unit may be what came up
  if [ "$SYSD" = 1 ] && systemctl is-active --quiet "$_u" 2>/dev/null && ! grep -qF -- "$RLC" "/etc/systemd/system/$_u.d/zz-installer-gate-count.conf" 2>/dev/null; then unit_counter "$_u" "$_nm"; fi
}
reloads() { _rn=$(grep -c "^$1\$" "$RLC" 2>/dev/null) || :; echo "${_rn:-0}"; }   # grep -c prints 0 AND fails on none
srv_run() { # [env...]: the installer for real, the real servers visible through the counting wrappers
  env PATH="$SH:/usr/sbin:/usr/bin:/sbin:/bin" WHISPER_EDGE_RESOLVE="$RES" WHISPER_EDGE_SERVER="${SRVSEL:-}" "$@" sh "$INSTALL" --base "$FEED"
}
undo_of() { printf '%s\n' "$1" | sed -n "s/^   undo, $2: sh -c //p" | sed -n 1p; }
# The Apache layout of this box: Debian's apache2 with conf-available and a2enconf, or RHEL's httpd with
# conf.d; the server rows read every path from here. APDRV is the command that takes Apache's own
# arguments (-f, -t -D DUMP_INCLUDES, -k graceful): Debian's apache2ctl passes them on, but RHEL's apachectl
# is a systemd wrapper that refuses every word past its first, so there it is httpd itself.
if [ -x /usr/sbin/apache2 ]; then
  APX=apache2; APCTL=apache2ctl; APDRV=apache2ctl; APT=/etc/apache2; APU=apache2.service; APPID=/run/apache2/apache2.pid
  APMOD=/usr/lib/apache2/modules; APDROP=/etc/apache2/conf-available/whisper-edge.conf; APOP=/etc/apache2/conf-available/zz-operator.conf
else
  APX=httpd; APCTL=apachectl; APDRV=httpd; APT=/etc/httpd; APU=httpd.service; APPID=/run/httpd/httpd.pid
  APMOD=/usr/lib64/httpd/modules; APDROP=/etc/httpd/conf.d/whisper-edge.conf; APOP=/etc/httpd/conf.d/zz-operator.conf
fi
NGMOD=$(nginx -V 2>&1 | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p' | sed -n 1p); NGMOD=${NGMOD:-/usr/lib/nginx/modules}
NGLOAD=$(sed -n 's/^include[[:space:]]\{1,\}\(\/[^*]*\)\/\*\.conf;.*/\1/p' /etc/nginx/nginx.conf 2>/dev/null | head -1); NGLOAD=${NGLOAD:-/etc/nginx/modules-enabled}
NG_TREES="/etc/nginx /etc/whisper-edge $NGLOAD"
NGU=$(sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^;[:space:]]\{1,\}\).*/\1/p' /etc/nginx/nginx.conf 2>/dev/null | head -1); NGU=${NGU:-www-data}
# The modules under test are this tree's, built before the gate and named in INSTALLER_GATE_MODULES
# ("nginx=<so> apache=<so> litespeed=<so>"); they are put in place here and taken away after, so the real
# rows above, which plant a server without its module, never see one.
mod_of() { printf '%s\n' "${INSTALLER_GATE_MODULES:-}" | tr ' ' '\n' | sed -n "s/^$1=//p"; }
SRV_MODS=""
mods_place() {
  _n=$(mod_of nginx); [ -f "$_n" ] && mkdir -p "$NGMOD" && cp "$_n" "$NGMOD/ngx_http_whisper_edge_module.so" && SRV_MODS="$SRV_MODS $NGMOD/ngx_http_whisper_edge_module.so"
  _a=$(mod_of apache); [ -f "$_a" ] && [ -d "$APMOD" ] && cp "$_a" "$APMOD/mod_whisper_edge.so" && SRV_MODS="$SRV_MODS $APMOD/mod_whisper_edge.so"
  _l=$(mod_of litespeed); [ -f "$_l" ] && [ -d /usr/local/lsws/modules ] && cp "$_l" /usr/local/lsws/modules/mod_whisper_edge.so && SRV_MODS="$SRV_MODS /usr/local/lsws/modules/mod_whisper_edge.so"
  return 0
}
mods_remove() { for _m in $SRV_MODS; do rm -f "$_m"; done; SRV_MODS=""; }
# A negative arm proves something only against its positive control: the same fixture, in the same run,
# without the fault, showing the files present, the record changed and one reload. pos_pass records a
# positive control that passed; neg counts a negative arm as passing only when its control passed before
# it in this run, and FAILS it otherwise, whatever the arm itself saw.
# The guard's own row, never on the host's mounts: a namespace of its own (private from the gate's), its /
# made shared as systemd leaves a host's, and inside it a child namespace that keeps that propagation and
# runs a bind-and-unmount. The parent namespace's table is read before and after, so the child's unmount
# can only ever reach the throwaway parent. Run with the arm's own NS_UP and NS_DOWN it must leave the
# table as it was; run with the bind left shared (the lines the arm first had) it must change it, or the
# guard could not see the fault it is for.
ns_probe() { # <up script> <down script> -> "before|after" as the throwaway parent saw them
  unshare -m --propagation private sh -c '
    st() { printf "mounts=%s %s %s" "$(grep -c "" /proc/self/mounts 2>/dev/null || echo 0)" "$([ -r /proc/self/mounts ] && echo proc || echo no-proc)" "$(grep -q " selinuxfs " /proc/self/mounts 2>/dev/null && echo selinuxfs || echo no-selinuxfs)"; }
    mount --make-rshared /
    a=$(st)
    unshare -m --propagation unchanged sh -c "$1; $2" sh /var/lib/w-nsguard
    b=$(st)
    printf "%s|%s\n" "$a" "$b"' sh "$1" "$2" 2>/dev/null
}
mount_guard_rows() {
  command -v unshare >/dev/null 2>&1 || { skip "the mount guard's own row" "no unshare on this box"; return 0; }
  _np=$(ns_probe "$NS_UP" "$NS_DOWN")
  { [ -n "$_np" ] && [ "${_np%%|*}" = "${_np#*|}" ]; } \
    && pass "the namespace arm's bind of /, in a throwaway namespace with shared propagation: its unmount reaches nothing it copied (${_np%%|*})" \
    || fail "the namespace arm's bind of / reaches the mounts it copied" "before|after in a throwaway namespace: ${_np:-no answer}"
  _np=$(ns_probe 'mkdir -p "$1"; mount --rbind / "$1"' "$NS_DOWN")
  { [ -n "$_np" ] && [ "${_np%%|*}" != "${_np#*|}" ]; } \
    && pass "the control: the same bind left shared does reach them there (${_np%%|*} became ${_np#*|}), so the guard sees this fault" \
    || fail "the mount guard's control" "a shared bind and recursive unmount changed nothing in the throwaway namespace: ${_np:-no answer}"
  rmdir /var/lib/w-nsguard 2>/dev/null || :
}
# The reader's own placement of a writer that names no pid namespace (pidns 0, as a confined worker
# whose stat of /proc/self/ns/pid is denied writes when it cannot read the link either): a status file for
# a live process, its pidns field forced to 0, read as root (pidns-by=stat) and as nobody (pidns-by=nspid,
# the process being another user's); both read it live, none foreign. The control is the same file with
# a pidns that is not this one, which must read foreign.
pidns_rows() {
  _sum=$HERE/../core/whisper-edge-summary
  [ -x "$_sum" ] || { skip "the reader's placement of a writer with no pid namespace" "no whisper-edge-summary built in this tree"; return 0; }
  _pd=$(mktemp -d /tmp/whisper-edge-pidns.XXXXXX); chmod 0755 "$_pd"   # nobody reads it too
  # the binary as well: a checkout under a directory nobody may enter (/root, 0550) cannot be run as
  # nobody from where it was built, so it runs from a copy beside the status files
  _pb_dir=$(mktemp -d /tmp/whisper-edge-sum.XXXXXX); chmod 0755 "$_pb_dir"
  cp "$_sum" "$_pb_dir/whisper-edge-summary" && chmod 0755 "$_pb_dir/whisper-edge-summary" && _sum=$_pb_dir/whisper-edge-summary
  sleep 600 & _pp=$!
  _ps=$(sed -n 's/^[0-9]* (.*) \(.*\)$/\1/p' "/proc/$_pp/stat" | awk '{ print $20 }'); _pb=$(cat /proc/sys/kernel/random/boot_id)
  for _pn in 0 4294967295; do
    printf 'whisper-edge-status 2\nprocess "nginx/1" pid %s boot %s pidns %s starttime %s started 1 written 2 interval 60000 jitter 0 handoff 0 tick 3 config 0123456789abcdef\nplane reputation armed generation 7 digest 0123456789abcdef valid-until 0 remaining -1 since 1 bytes 64 mapped\n' \
      "$_pp" "$_pb" "$_pn" "$_ps" > "$_pd/$_pp-0123456789abcdef.status"; chmod 0644 "$_pd/$_pp-0123456789abcdef.status"
    _r=$("$_sum" --status "$_pd" 2>&1 || :); _n=$(runuser -u nobody -- "$_sum" --status "$_pd" 2>&1 || :)
    if [ "$_pn" = 0 ]; then
      { printf '%s\n' "$_r" | grep_any 'pidns-by=stat$' && printf '%s\n' "$_r" | grep_any '^live 1, gone 0, foreign 0 ' \
        && printf '%s\n' "$_n" | grep_any 'pidns-by=nspid$' && printf '%s\n' "$_n" | grep_any '^live 1, gone 0, foreign 0 '; } \
        && pos_pass pidns "a writer that named no pid namespace (pidns 0) is placed by the reader: live, none foreign, by stat as root and by NSpid as nobody" \
        || fail "the reader's placement of a pidns-0 writer" "root: $(printf '%s\n' "$_r" | grep -E 'pidns-by|^live' | tr '\n' ';'); nobody: $(printf '%s\n' "$_n" | grep -E 'pidns-by|^live' | tr '\n' ';')"
    else
      { printf '%s\n' "$_r" | grep_any '^live 0, gone 0, foreign 1 '; } \
        && neg pidns "the control: the same writer naming a pid namespace that is not this one reads foreign, never placed" \
        || fail "the pidns control" "$(printf '%s\n' "$_r" | grep -E '^live|pidns-by' | tr '\n' ';')"
    fi
  done
  kill "$_pp" 2>/dev/null || :; wait "$_pp" 2>/dev/null || :; rm -rf "$_pd" "$_pb_dir"
}
writer_rows() { # <positive control> <master pid> <which nginx>
  # Every writer of a running nginx, read as root and as nobody: the property C7 stands on. Each worker
  # names its own pid namespace (it reads /proc/self/ns/pid's link where SELinux denies a confined
  # worker the stat), so every worker of this master is listed live, no line says the reader had to
  # place it (no pidns-by=), and none is foreign. Writers of servers earlier rows ran and stopped are
  # gone, and say nothing of this one. The control is the reader's own fallback, which the old
  # writer needed: one worker's status file with its pidns field set to 0, as a writer that named no
  # namespace wrote it, is placed by the reader, by stat as root and by NSpid as nobody, and live.
  ngw=$(ps -eo pid=,ppid=,args= | awk -v m="$2" '$2 == m && $3 == "nginx:" && $4 == "worker" { print $1 }' | tr '\n' ' ')
  cw_read() { if [ "$1" = root ]; then /usr/local/sbin/whisper-edge-summary --status "$2" 2>&1 || :
              else runuser -u nobody -- /usr/local/sbin/whisper-edge-summary --status "$2" 2>&1 || :; fi; }
  cw_all_live() { _so=$(cw_read "$1" /var/lib/whisper-edge/counters); for _w in $ngw; do printf '%s\n' "$_so" | grep_any "^process pid $_w tick " || return 1; done; }
  for su in root nobody; do
    [ -n "$ngw" ] && wait_until 60 cw_all_live "$su" || :
    so=$(cw_read "$su" /var/lib/whisper-edge/counters)
    miss=""; for w in $ngw; do printf '%s\n' "$so" | grep_any "^process pid $w tick " || miss="$miss $w"; done
    np=$(printf '%s\n' "$so" | grep -c '^process .*pidns-by=' || :)
    { [ -n "$ngw" ] && [ -z "$miss" ] && [ "$np" = 0 ] && printf '%s\n' "$so" | grep_any -E '^live [1-9][0-9]*, gone [0-9]+, foreign 0 '; } \
      && neg "$1" "$3: the summary as $su lists every worker live ($(printf '%s' "$ngw" | wc -w)), each naming its own pid namespace (no pidns-by=), none foreign" \
      || fail "$3: the writers read as $su" "workers: ${ngw:-none}; not listed live:${miss:- none}; $np process line(s) with pidns-by=: $(printf '%s\n' "$so" | grep -E '^process |^live ' | head -4 | tr '\n' ';' | cut -c1-300)"
  done
  cw1=${ngw%% *}; cwd=$(mktemp -d /tmp/whisper-edge-cw.XXXXXX); chmod 0755 "$cwd"
  for f in /var/lib/whisper-edge/counters/"${cw1:-none}"-*.status; do
    if [ -f "$f" ]; then sed 's/^\(process .* pidns \)[0-9][0-9]* /\10 /' "$f" > "$cwd/${f##*/}" || :; chmod 0644 "$cwd/${f##*/}" 2>/dev/null || :; fi
  done
  cwr=$(cw_read root "$cwd"); cwn=$(cw_read nobody "$cwd")
  { [ -n "$cw1" ] && grep -q '^process .* pidns 0 ' "$cwd"/*.status 2>/dev/null \
    && printf '%s\n' "$cwr" | grep_any "^process pid $cw1 tick .*pidns-by=stat\$" && printf '%s\n' "$cwr" | grep_any '^live 1, gone 0, foreign 0 ' \
    && printf '%s\n' "$cwn" | grep_any "^process pid $cw1 tick .*pidns-by=nspid\$" && printf '%s\n' "$cwn" | grep_any '^live 1, gone 0, foreign 0 '; } \
    && neg "$1" "$3, the control: worker $cw1's status as a writer that named no pid namespace wrote it (pidns 0) is placed by the reader, live and none foreign, by stat as root and by NSpid as nobody" \
    || fail "$3: the reader's placement of an old-style pidns-0 status file" "worker ${cw1:-none}; root: $(printf '%s\n' "$cwr" | grep -E '^process |^live ' | tr '\n' ';'); nobody: $(printf '%s\n' "$cwn" | grep -E '^process |^live ' | tr '\n' ';')"
  rm -rf "$cwd"
}
# nginx/build.sh --install on a box whose nginx names a modules path that does not exist (Ubuntu 24.04's
# stock nginx 1.24.0 names /usr/lib/nginx/modules and its package makes no such directory): the path
# nginx names is created, 0755 and owned like the directory it is made in, and the module installed into
# it. And a build whose flags need a header the box lacks stops before configure, naming every missing
# piece in one install line for the host's package manager (the stand-in compiler finds no zlib.h).
build_rows() {
  _bmp=$(nginx -V 2>&1 | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p' | sed -n 1p)
  if ! [ -x /usr/sbin/nginx ] || ! [ -x "$HERE/../nginx/build.sh" ]; then skip "nginx/build.sh --install with no modules directory" "no nginx on this box"; return 0; fi
  if [ -z "$_bmp" ]; then skip "nginx/build.sh --install with no modules directory" "this nginx names no --modules-path"; return 0; fi
  _bkeep=""; if [ -e "$_bmp" ]; then _bkeep="$_bmp.installer-gate"; rm -rf "$_bkeep"; mv "$_bmp" "$_bkeep"; fi
  _bup=$(dirname -- "$_bmp"); while [ ! -d "$_bup" ]; do _bup=$(dirname -- "$_bup"); done; _bog=$(stat -c '%u:%g' -- "$_bup")
  bo=$(cd "$HERE/../nginx" && ./build.sh --install 2>&1) && brc=0 || brc=$?
  { [ "$brc" = 0 ] && [ -d "$_bmp" ] && [ "$(stat -c '%a %u:%g' -- "$_bmp")" = "755 $_bog" ] && [ -f "$_bmp/ngx_http_whisper_edge_module.so" ] \
    && says "$bo" "created $_bmp (nginx's --modules-path; 0755, owned $_bog like $_bup)" && says "$bo" "load_module $_bmp/ngx_http_whisper_edge_module.so;"; } \
    && pass "nginx/build.sh --install with nginx's --modules-path ($_bmp) missing: the path nginx names is created, 0755 owned $_bog like $_bup, and the module installed into it" \
    || fail "nginx/build.sh --install with no modules directory" "rc=$brc $(stat -c '%a %u:%g' -- "$_bmp" 2>&1) $(printf '%s\n' "$bo" | grep -E 'nginx/build.sh|created|installed|modules path' | head -3 | cut -c1-240)"
  rm -rf "$_bmp"; [ -z "$_bkeep" ] || mv "$_bkeep" "$_bmp"
  # the stand-in compiler: every header preprocesses as the real one does, but zlib.h is not found
  mkdir -p "$W/ccshim"
  printf '#!/bin/sh\ncase " $* " in *" -E "*) in=$(cat); case "$in" in *zlib.h*) echo "zlib.h: No such file or directory" >&2; exit 1 ;; esac; printf "%%s\\n" "$in" | exec %s "$@" ;; esac\nexec %s "$@"\n' "$(command -v cc)" "$(command -v cc)" > "$W/ccshim/cc"
  chmod 0755 "$W/ccshim/cc"
  if command -v apt-get >/dev/null 2>&1; then _bl='apt-get install -y zlib1g-dev'; elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then _bl='dnf install -y zlib-devel'; else _bl='apk add zlib-dev'; fi
  bo=$(cd "$HERE/../nginx" && PATH="$W/ccshim:$PATH" ./build.sh 2>&1) && brc=0 || brc=$?
  { [ "$brc" = 1 ] && says "$bo" "this nginx's flags need the zlib headers to build against, and they are missing here" && hasline "$bo" "    $_bl" \
    && ! says "$bo" '^== configure'; } \
    && pass "a build whose flags need a header the box lacks (zlib.h) stops before configure and names the one line that installs it: $_bl" \
    || fail "nginx/build.sh's missing-header line" "rc=$brc $(printf '%s\n' "$bo" | head -4 | tr '\n' ';' | cut -c1-300)"
}
# a counter drop-in a killed run left, naming a work directory that is gone: the next arm's teardown removes
# it and says so, and the clean start then holds; never a reload into the dead directory
stale_counter_row() {
  [ "$(id -u)" = 0 ] || { skip "a stale gate counter drop-in" "needs root"; return 0; }
  sd=/etc/systemd/system/httpd.service.d; sdf="$sd/zz-installer-gate-count.conf"; sdx=0; [ -d "$sd" ] || sdx=1
  mkdir -p "$sd"; printf '[Service]\nExecReload=/bin/sh -c "echo apache >> /run/user/0/whisper-edge-installer-gate.gone/reloads"\n' > "$sdf"
  pre=$(clean_start)
  so=$(real_teardown 2>&1); post=$(clean_start)
  { case "$pre" in *"a stale gate counter drop-in: $sdf"*) true ;; *) false ;; esac; } && [ ! -e "$sdf" ] && [ -z "$post" ] \
    && says "$so" "removed a counter drop-in an earlier gate run left: $sdf, which named /run/user/0/whisper-edge-installer-gate.gone/reloads" \
    && pass "a counter drop-in a killed run left (naming a work directory that is gone): the clean start names it, the next teardown removes it and says so, and the clean start then holds" \
    || fail "a stale gate counter drop-in" "clean start before: ${pre:-nothing}; after: ${post:-nothing}; teardown said: $(printf '%s' "$so" | head -2 | tr '\n' ';'); file: $([ -e "$sdf" ] && echo left || echo gone)"
  rm -f "$sdf"; [ "$sdx" = 0 ] || rmdir "$sd" 2>/dev/null || :
}
server_rows() {
  stale_counter_row
  mount_guard_rows
  pidns_rows
  build_rows
  echo "--- the servers, for real (the configuration record covers:$(record_covers))"
  [ "$REC_ACL" = 1 ] || skip "the undo record's ACL arm" "no getfacl on this host"
  [ "$REC_XATTR" = 1 ] || skip "the undo record's extended-attribute arm" "no getfattr on this host"
  [ "$REC_CTX" = 1 ] || skip "the undo record's SELinux arm" "SELinux is not enabled on this host"
  # the rule itself, checked: a negative arm with no control before it fails
  _sv_ok=$ok; _sv_bad=$bad
  t=$( (neg never-passed "a planted negative arm" >/dev/null; echo "$bad") ); ok=$_sv_ok; bad=$_sv_bad
  [ "$t" = "$((bad + 1))" ] && pass "the gate's own rule: a negative arm with no positive control before it in the run fails" \
    || fail "the positive-control rule" "a negative arm with no control was counted ($t)"
  mods_place
  server_arms
  mods_remove
  unit_counters_off
}
server_arms() {
  SRVSEL=nginx
  NGX_SO=$NGMOD/ngx_http_whisper_edge_module.so
  if ! [ -x /usr/sbin/nginx ] || ! [ -f "$NGX_SO" ]; then
    skip "the nginx arm" "no nginx with the module built from this tree at $NGX_SO (nginx/build.sh --install on this disposable box first)"
  else
    feed 497775 normal
    begin_arm "nginx" || return 0
    rm -f "$NGLOAD"/*whisper* /etc/nginx/conf.d/whisper-edge.conf
    srv_shims; : > "$RLC"
    /usr/sbin/nginx -t >/dev/null 2>&1 || { fail "the nginx arm" "the stock configuration does not test clean before the run"; return 0; }
    srv_stock nginx /etc/nginx $NGLOAD
    srv_start nginx.service nginx /usr/sbin/nginx
    before=$(record $NG_TREES); eff0=$(eff_digest nginx); us0=$(unit_state nginx.service)
    # W3, the positive control every nginx arm below is read against
    out=$(keep srv_run) && rc=0 || rc=$?
    after=$(record $NG_TREES); printf '%s\n' "$after" > "$W/rec.after.$$"
    { [ "$rc" = 0 ] && [ -f /etc/nginx/conf.d/whisper-edge.conf ] && [ -f $NGLOAD/50-whisper-edge.conf ] \
      && [ "$before" != "$after" ] && [ "$(reloads nginx)" = 1 ] \
      && says "$out" 'nginx: the configuration test passed' && says "$out" 'nginx: reloaded (' \
      && says "$out" 'nginx: confirmed by the module: worker pid [0-9]*, new since the reload, runs program [0-9a-f]\{16\}, reputation armed at generation 497775' \
      && /usr/sbin/nginx -t >/dev/null 2>&1; } \
      && pos_pass nginx-apply "nginx: the load file and the drop-in written, the test passed, exactly one reload, and the record differs by them (the positive control)" \
      || fail "nginx: apply, test, reload" "rc=$rc reloads=$(reloads nginx)
$(printf '%s\n' "$out" | sed -n '/^== applied/,$p' | head -40)"
    writer_rows nginx-apply "$(ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }')" "the applied nginx"
    # W4: the written drop-in is the pinned policy in nginx's idiom
    { [ "$(grep -c '^whisper_edge_policy ' /etc/nginx/conf.d/whisper-edge.conf)" = 4 ] && grep -qx 'whisper_edge_mode deny;' /etc/nginx/conf.d/whisper-edge.conf; } \
      && pass "the written nginx drop-in carries the mode line and the four rules" || fail "the written nginx drop-in" "$(cat /etc/nginx/conf.d/whisper-edge.conf 2>&1 | head -5)"
    # W34: a re-run with nothing to change reloads nothing
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && [ "$(reloads nginx)" = 1 ] && says "$out" 'nginx: nothing changed in its configuration, so it was not reloaded' \
      && says "$out" 'nginx: confirmed read-only (nothing changed, so nothing was reloaded): .*this checks the program and the plane only, not that the worker is new' \
      && [ "$(record $NG_TREES)" = "$after" ]; } \
      && neg nginx-apply "a second run with nothing to change: no byte changed, no reload (the count stays 1)" \
      || fail "the zero-change re-run" "rc=$rc reloads=$(reloads nginx) (1 is the positive control's own reload; the re-run adds none) \
$(says "$out" 'nginx: nothing changed in its configuration, so it was not reloaded' || echo '     the not-reloaded line is missing')
$(says "$out" 'nginx: confirmed read-only' || echo "     the read-only confirmation is missing: $(printf '%s' "$out" | grep -E 'nginx: (applied|confirmed)' | head -2 | cut -c1-250)")
$([ "$(record $NG_TREES)" = "$after" ] || printf '     the record differs: %s' "$(record $NG_TREES | diff -- - "$W/rec.after.$$" 2>/dev/null | head -6 | tr '\n' ';')")"
    # A module rebuilt and installed under a running nginx: build.sh --install replaces the .so (a new inode),
    # nginx's reload keeps the module its master already loaded (dlopen hands back the handle it holds), and
    # the installer's re-run says the running module is older and names the restart, rather than "nothing
    # changed" alone (exit 3). The control is the same re-run after nginx is restarted: nothing said, exit 0.
    if [ -x "$HERE/../nginx/build.sh" ]; then
      smo=$(cd "$HERE/../nginx" && ./build.sh --install 2>&1) && smrc=0 || smrc=$?
      sm_m=$(ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }')
      /usr/sbin/nginx -s reload >/dev/null 2>&1 || :
      wait_until 60 sh -c "[ -z \"\$(ps -eo ppid=,args= | awk -v m='${sm_m:-0}' '\$1 == m && /worker process is shutting down/')\" ]" || :
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$smrc" = 0 ] && says "$smo" 'a running nginx keeps the module it already loaded across a reload: to load this build, restart it' \
        && [ "$rc" = 3 ] && says "$out" "nginx: the running server (pid [0-9]*) still has the module it loaded before $NGMOD/ngx_http_whisper_edge_module.so was replaced: a reload keeps a module it already loaded, so this build is not the one running; to load it: "; } \
        && neg nginx-apply "a module rebuilt and installed under a running nginx, then a reload: build.sh says a reload keeps the old module, and the installer's re-run says the running module is older and names the restart (exit 3), never only \"nothing changed\"" \
        || fail "the stale module after a rebuild and a reload" "build rc=$smrc rc=$rc $(printf '%s\n' "$smo" | grep -E 'keeps the module|installed into' | head -2 | tr '\n' ';') $(printf '%s\n' "$out" | grep -E 'nginx: (the running|nothing changed|confirmed)' | head -3 | cut -c1-240)"
      if [ "$SYSD" = 1 ] && systemctl is-active --quiet nginx.service 2>/dev/null; then systemctl restart nginx.service >/dev/null 2>&1 || :
      else /usr/sbin/nginx -s quit >/dev/null 2>&1 || :; wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :; /usr/sbin/nginx >/dev/null 2>&1 || :; fi
      wait_until 60 master_of 'nginx: master process' || :
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && ! says "$out" 'still has the module it loaded before'; } \
        && neg nginx-apply "the control: after nginx is restarted the same re-run says nothing of an older module (exit 0)" \
        || fail "the stale-module control" "rc=$rc $(printf '%s\n' "$out" | grep -E 'nginx: ' | head -3 | cut -c1-240)"
    else
      skip "the stale module after a rebuild and a reload" "no nginx/build.sh in this tree"
    fi
    # the server's own realip trust, read at http level only: advised (the module's lines to paste, with
    # the operator's own addresses and header), never written; a server block's own list is that site's
    out0=$out   # the undo below is this run's line
    if /usr/sbin/nginx -V 2>&1 | grep_any 'http_realip_module'; then
      rr0=$(record $NG_TREES); dsum=$(sha256sum < /etc/nginx/conf.d/whisper-edge.conf)
      printf 'set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\nreal_ip_header X-Forwarded-For;\n' > /etc/nginx/conf.d/zz-realip.conf
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && [ "$(reloads nginx)" = 1 ] && [ "$(sha256sum < /etc/nginx/conf.d/whisper-edge.conf)" = "$dsum" ] \
        && says "$out" 'nginx: your set_real_ip_from and real_ip_header at http level trusts 127.0.0.1 ::1 for X-Forwarded-For, .*its floor rules judge the connection.s peer (the proxy)' \
        && printf '%s\n' "$out" | grep_any -x '     whisper_edge_trusted_proxy 127.0.0.1 ::1;' && printf '%s\n' "$out" | grep_any -x '     whisper_edge_trusted_header X-Forwarded-For;' \
        && ! grep -rq 'whisper_edge_trusted' /etc/nginx; } \
        && pass "nginx: an http-level realip trust is advised with its own addresses and header (whisper_edge_trusted_proxy 127.0.0.1 ::1; whisper_edge_trusted_header X-Forwarded-For;), and nothing is written" \
        || fail "nginx: the realip advice" "rc=$rc reloads=$(reloads nginx) $(printf '%s\n' "$out" | grep -E 'realip|trusted' | head -4 | cut -c1-250)"
      printf 'server {\n  listen 127.0.0.1:8098;\n  set_real_ip_from 127.0.0.1;\n  real_ip_header X-Forwarded-For;\n}\n' > /etc/nginx/conf.d/zz-realip.conf
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && ! says "$out" 'real_ip_header at http level' && ! printf '%s\n' "$out" | grep_any 'whisper_edge_trusted'; } \
        && pass "nginx: a server block's own realip list is that site's: no advice" \
        || fail "nginx: no realip advice for a server block" "rc=$rc $(printf '%s\n' "$out" | grep -E 'realip|trusted' | head -3 | cut -c1-250)"
      rm -f /etc/nginx/conf.d/zz-realip.conf
      [ "$(record $NG_TREES)" = "$rr0" ] || fail "the realip rows' cleanup" "the record differs after removing zz-realip.conf"
    else
      skip "nginx: the realip advice" "this nginx is built without the realip module"
    fi
    out=$out0
    # W10: the printed undo line restores the record, then reloads once
    u=$(undo_of "$out" nginx)
    if [ -z "$u" ]; then fail "nginx: the undo line" "no 'undo, nginx' line in the report"
    else
      uo=$(eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" 2>&1) && urc=0 || urc=$?
      { [ "$urc" = 0 ] && [ "$(record $NG_TREES | grep -v '^/etc/whisper-edge')" = "$(printf '%s\n' "$before" | grep -v '^/etc/whisper-edge')" ] \
        && [ "$(reloads nginx)" = 2 ] && /usr/sbin/nginx -t >/dev/null 2>&1 && [ "$(eff_digest nginx)" = "$eff0" ] && [ "$(unit_state nginx.service)" = "$us0" ]; } \
        && pass "nginx: the printed undo line restores the configuration record exactly, the effective configuration (nginx -T, $eff0) and the unit's state ($us0), tests, and reloads once" \
        || fail "nginx: the undo line" "rc=$urc reloads=$(reloads nginx) $uo $(printf '%s\n' "$before" > "$W/rec.b"; record $NG_TREES > "$W/rec.a"; diff "$W/rec.b" "$W/rec.a" | head -4)"
    fi
    # O1, the verdict's own arms (C7). Each starts from an applied, confirmed nginx and takes the drop-in
    # away by hand (no reload), so the next run writes the same bytes again: the same config digest the
    # live workers already report. A reload that does nothing must then read unverified, a forged writer
    # must not count, a draining worker must not be the one that confirms, and a plane the refresh
    # replaces between the reload and the verdict is read as the file is then.
    CNT=/var/lib/whisper-edge/counters; NGUID=$(id -u "$NGU")
    ng_master() { ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }'; }
    ng_workers() { ps -eo pid=,ppid=,args= | awk -v m="$(ng_master)" '$2 == m && $3 == "nginx:" && $4 == "worker" { print $1 }' | tr '\n' ' '; }
    ng_inert() { # reloads that do nothing, by the wrapper and by the unit
      shim nginx "case \" \$* \" in *' -s reload '*) echo nginx >> '$RLC'; exit 0 ;; esac; exec /usr/sbin/nginx \"\$@\""
      if [ "$SYSD" = 1 ]; then mkdir -p /etc/systemd/system/nginx.service.d; printf '[Service]\nExecReload=\nExecReload=/bin/true\n' > /etc/systemd/system/nginx.service.d/zz-installer-gate-inert.conf; systemctl daemon-reload; fi
    }
    ng_live() { rm -f /etc/systemd/system/nginx.service.d/zz-installer-gate-inert.conf; daemon_reload; srv_shims; }
    st_wait() { # <seconds>: until a worker of the current master has written its status file
      _i=0; while [ "$_i" -lt "$1" ]; do
        for _p in $(ng_workers); do ls "$CNT/$_p"-*.status >/dev/null 2>&1 && return 0; done
        sleep 1; _i=$((_i + 1))
      done; return 1
    }
    : > "$RLC"; out=$(keep srv_run) && rc=0 || rc=$?
    st_wait 200 || :
    { [ "$rc" = 0 ] && says "$out" 'nginx: confirmed by the module: worker pid'; } \
      && pos_pass nginx-c7 "C7's arms start from an applied nginx the module confirmed (the positive control for the arms below)" \
      || fail "C7's starting point" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-200)"
    # the stale arm: an inert reload over live workers that already report this very config digest
    ng_inert; rm -f /etc/nginx/conf.d/whisper-edge.conf
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 3 ] && says "$out" 'nginx: reloaded (' && says "$out" 'nginx: applied and serving, but unverified: no new worker named program [0-9a-f]\{16\} in .* within [0-9]* s ([1-9][0-9]* live writer(s) there now; [1-9][0-9]* were there before the reload)'; } \
      && neg nginx-c7 "the stale arm: a reload that changes nothing, over workers already reporting the same config digest: unverified, exit 3 (their status is from before the reload)" \
      || fail "the stale arm" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -4 | cut -c1-250)"
    # the forged writer: a live process that was not there before the reload, written up as a worker (its
    # rules.cnt and status copied from a real worker's, its pid and start time put in) by a uid that is not
    # the worker's. It must not count. The control: the same files owned by the worker's uid do count,
    # so the uid is what refuses them, and --writer-uid is what reads the plane from them.
    id wforge >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin wforge 2>/dev/null || useradd -r -M wforge
    rw=$(for _p in $(ng_workers); do ls "$CNT/$_p"-*.status 2>/dev/null && break; done | sed -n 1p)
    sleep 600 & fpid=$!
    fst=$(sed -n 's/^[0-9]* (.*) \(.*\)$/\1/p' "/proc/$fpid/stat" | awk '{ print $20 }')
    forge() { # <owner>: the worker's files copied under the forging process's pid and start time
      forged=""
      [ -n "$rw" ] || return 0
      rp=$(basename "$rw" | cut -d- -f1); rk=$(basename "$rw" .status | cut -d- -f2)
      for ext in status rules.cnt; do
        [ -f "$CNT/$rp-$rk.$ext" ] || continue
        sed -e "s/\bpid $rp\b/pid $fpid/g" -e "s/starttime [0-9]*/starttime $fst/g" "$CNT/$rp-$rk.$ext" > "$CNT/.$fpid-$rk.$ext"
        chown "$1" "$CNT/.$fpid-$rk.$ext"; chmod 0644 "$CNT/.$fpid-$rk.$ext"; mv -f "$CNT/.$fpid-$rk.$ext" "$CNT/$fpid-$rk.$ext"
        forged="$forged $CNT/$fpid-$rk.$ext"
      done
    }
    forged_run() { # <owner>: the run, its forgery planted after the reload and before the verdict
      forged=""
      rm -f /etc/nginx/conf.d/whisper-edge.conf
      pause_arm
      srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_PAUSE=after-reload > "$W/forge.out" 2> "$W/forge.out.err" &
      _fp=$!
      if pause_wait after-reload "$_fp"; then forge "$1"; pause_release; fi
      bg_wait "$_fp" && rc=0 || rc=$?
      pause_done; collect_err "$W/forge.out"; out=$(cat "$W/forge.out")
      # shellcheck disable=SC2086 # the list of forged paths, none with a space
      [ -z "$forged" ] || rm -f $forged
    }
    forged_run wforge
    { [ -n "$forged" ] && [ "$rc" = 3 ] && says "$out" 'nginx: applied and serving, but unverified: no new worker named program' && ! says "$out" "worker pid $fpid"; } \
      && neg nginx-c7 "a forged writer (a live process new since the reload, its files copied from a worker's, owned by another uid): not counted, still unverified, exit 3" \
      || fail "the forged writer" "rc=$rc forged:${forged:-none} $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-250)"
    forged_run "$NGUID"
    { [ "$rc" = 0 ] && says "$out" "nginx: confirmed by the module: worker pid $fpid, new since the reload"; } \
      && pass "the control: the same forged files owned by the worker's uid are taken (pid $fpid), so the uid check is what refused them" \
      || fail "the forged writer's control" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | sed -n '4,8p' | cut -c1-300)"
    kill "$fpid" 2>/dev/null || :; wait "$fpid" 2>/dev/null || :
    ng_live
    # the draining arm: a real reload while an old worker is still serving a slow download, so a writer
    # from before the reload is alive at the verdict; the worker that confirms must be a new one
    mkdir -p /var/lib/w-drain; head -c 40000000 /dev/zero > /var/lib/w-drain/big
    printf 'server {\n    listen 127.0.0.1:8099;\n    root /var/lib/w-drain;\n    location / { limit_rate 10k; }\n}\n' > /etc/nginx/conf.d/zz-drain.conf
    /usr/sbin/nginx -s reload || :; st_wait 200 || :
    curl -s -o /dev/null http://127.0.0.1:8099/big & cpid=$!
    _i=0; while [ "$_i" -lt 60 ] && ! ss -tn state established '( dport = :8099 )' 2>/dev/null | grep_any 8099; do sleep 1; _i=$((_i + 1)); done
    old=$(ng_workers)
    rm -f /etc/nginx/conf.d/whisper-edge.conf
    out=$(keep srv_run) && rc=0 || rc=$?
    cw=$(printf '%s' "$out" | sed -n 's/.*nginx: confirmed by the module: worker pid \([0-9]*\), new since the reload.*/\1/p' | sed -n 1p)
    alive=""; for _p in $old; do kill -0 "$_p" 2>/dev/null && alive="$alive $_p"; done
    { [ "$rc" = 0 ] && [ -n "$cw" ] && [ -n "$alive" ] && case " $old " in *" $cw "*) false ;; *) true ;; esac; } \
      && neg nginx-c7 "the draining arm: a worker from before the reload still serving (pid$alive), and the one that confirmed is new (pid $cw)" \
      || fail "the draining arm" "rc=$rc confirmed=${cw:-none} before:$old alive:${alive:- none} $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-200)"
    kill "$cpid" 2>/dev/null || :; wait "$cpid" 2>/dev/null || :
    rm -f /etc/nginx/conf.d/zz-drain.conf; rm -rf /var/lib/w-drain; /usr/sbin/nginx -s reload || :
    # the refresh race: between the reload and the verdict the plane is replaced by a newer generation, as
    # the refresh would (a new file renamed over it); the verdict waits for the module to bind it and names
    # the generation the file has then. The file before is put back after the row.
    rm -f /etc/nginx/conf.d/whisper-edge.conf
    cp -p /var/lib/whisper-edge/reputation.bin "$W/rep.save"
    pause_arm
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_PAUSE=after-reload > "$W/race.out" 2> "$W/race.out.err" &
    ipid=$!
    if pause_wait after-reload "$ipid"; then
      python3 - "/var/lib/whisper-edge/reputation.bin" "$W/rep.new" <<'PY'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, struct.unpack_from("<Q", b, 16)[0] + 1)
b[104:136] = bytes(32)
b[104:136] = hashlib.sha256(bytes(b)).digest()
open(sys.argv[2], "wb").write(bytes(b))
PY
      chown --reference=/var/lib/whisper-edge/reputation.bin "$W/rep.new"; chmod --reference=/var/lib/whisper-edge/reputation.bin "$W/rep.new"
      # the installer leaves its planes immutable; the refresh lifts that for its own rename, as this does
      chattr -i /var/lib/whisper-edge/reputation.bin 2>/dev/null || :
      mv -f "$W/rep.new" /var/lib/whisper-edge/reputation.bin
      pause_release
    fi
    bg_wait "$ipid" && rrc=0 || rrc=$?
    collect_err "$W/race.out"
    { [ "$rrc" = 0 ] && says "$(cat "$W/race.out")" 'nginx: confirmed by the module: worker pid [0-9]*, new since the reload, runs program [0-9a-f]\{16\}, reputation armed at generation 497776'; } \
      && neg nginx-c7 "the refresh race: the plane replaced (generation 497776) between the reload and the verdict; the verdict names the generation the file has then" \
      || fail "the refresh race" "rc=$rrc $(grep -E 'nginx:' "$W/race.out" | head -3 | cut -c1-250)"
    pause_done
    chattr -i /var/lib/whisper-edge/reputation.bin 2>/dev/null || :
    cp -p "$W/rep.save" /var/lib/whisper-edge/reputation.bin
    u=$(undo_of "$(cat "$W/race.out")" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    /usr/sbin/nginx -s reload 2>/dev/null || :
    # W18, the operator's own lines kept and verified against what the module reports for them: a policy
    # built from whisper_edge_threshold (no policy line the installer could compile), and a data directory
    # of their own holding another generation than the installer's (a newer one: the module refuses to
    # roll its plane back, so an older one would read refused). Each must confirm, exit 0.
    # the operator's own configuration loads the module itself, as one that uses its directives must
    printf 'load_module %s;\n' "$NGX_SO" > "$NGLOAD/40-zz-w18.conf"
    printf 'whisper_edge_threshold high;\n' > /etc/nginx/conf.d/zz-w18.conf
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'nginx: your policy (.*) is kept' && says "$out" 'nginx: confirmed by the module: worker pid [0-9]*, new since the reload, runs program [0-9a-f]\{16\}'; } \
      && neg nginx-c7 "W18: the operator's whisper_edge_threshold kept: the verdict takes the program their worker reports, confirmed, exit 0" \
      || fail "W18: a kept threshold policy" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -4 | cut -c1-250)"
    u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    rm -rf /var/lib/w18data; mkdir -p /var/lib/w18data
    python3 - /var/lib/whisper-edge/reputation.bin /var/lib/w18data/reputation.bin <<'PY'
import hashlib, struct, sys
b = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<Q", b, 16, 497780)
b[104:136] = bytes(32)
b[104:136] = hashlib.sha256(bytes(b)).digest()
open(sys.argv[2], "wb").write(bytes(b))
PY
    # a mapped plane must be exactly 0444 (the module refuses any other mode)
    chmod 0755 /var/lib/w18data; chmod 0444 /var/lib/w18data/reputation.bin
    printf 'whisper_edge_data /var/lib/w18data;\n' > /etc/nginx/conf.d/zz-w18.conf
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'nginx: kept your whisper_edge_data' && says "$out" 'nginx: confirmed by the module: .*reputation armed at generation 497780'; } \
      && neg nginx-c7 "W18: the operator's own data directory kept (generation 497780 beside the installer's 497775): probed and verified there, confirmed, exit 0" \
      || fail "W18: a kept data directory" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx: (kept|confirmed|applied|nothing|your)|probe' | head -6 | cut -c1-300)
     the module's word: $(grep -h 'whisper edge' /var/log/nginx/error.log 2>/dev/null | grep -i 'w18data\|refus\|rollback\|reputation' | tail -4 | cut -c1-300)
     the plane: $(ls -l /var/lib/w18data 2>&1 | tr '\n' ';')"
    u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    rm -f /etc/nginx/conf.d/zz-w18.conf "$NGLOAD/40-zz-w18.conf"; rm -rf /var/lib/w18data
    # the module now holds generation 497780 and would refuse the installer's 497775 as a rollback until
    # the master starts afresh: stopped and started, not reloaded
    if [ "$SYSD" = 1 ] && systemctl is-active --quiet nginx 2>/dev/null; then systemctl restart nginx >/dev/null 2>&1 || :
    else
      /usr/sbin/nginx -s quit 2>/dev/null || :
      wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
      srv_start nginx.service nginx /usr/sbin/nginx
    fi
    # W18, the per-plane form: the operator names reputation's own file (whisper_edge_data reputation
    # <file>), a newer generation than the installer's; it is kept, the dir probe skipped for it, and the
    # verdict compares that file. The master is started afresh after, as above.
    plane_at 497785 /var/lib/w18p/rep.bin
    printf 'load_module %s;\n' "$NGX_SO" > "$NGLOAD/40-zz-w18.conf"
    printf 'whisper_edge_data reputation /var/lib/w18p/rep.bin;\n' > /etc/nginx/conf.d/zz-w18.conf
    if [ "$SE_GATE" = 1 ]; then
      # unlabelled first: the installer says plainly that a confined server cannot map it, and how to label it
      # the line is said whatever runs the master; what follows it is the master's: a confined one
      # (httpd_t, by its unit) cannot map the file and is never confirmed, an unconfined one started by
      # hand maps it, and the module's confirmation is then the truth
      w18m=$(ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }')
      w18c=$(ps -o label= -p "${w18m:-0}" 2>/dev/null | cut -d: -f3)
      out=$(keep srv_run) && rc=0 || rc=$?
      { says "$out" "nginx: SELinux: your reputation file reads [a-z_]*, which a confined server cannot map; label it as the installer labels its own: semanage fcontext -a -t httpd_sys_content_t '/var/lib/w18p/rep.bin'; restorecon /var/lib/w18p/rep.bin" \
        && if [ "$w18c" = httpd_t ]; then [ "$rc" != 0 ] && ! says "$out" 'nginx: confirmed by the module'
           else [ "$rc" = 0 ] && says "$out" 'nginx: confirmed by the module: .*reputation armed at generation 497785'; fi; } \
        && neg nginx-c7 "W18 on SELinux: a kept reputation file a confined server cannot map is said plainly, with the semanage and restorecon lines; the master here (${w18c:-no context}) $([ "$w18c" = httpd_t ] && echo 'is confined: never confirmed' || echo 'is not confined: it maps the file, and the module confirms it')" \
        || fail "W18 on SELinux: an unmappable kept file" "master ${w18m:-none} context ${w18c:--}; rc=$rc $(printf '%s' "$out" | grep -E 'nginx: (SELinux|confirmed|applied)' | head -3 | cut -c1-300)"
      u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
      printf 'load_module %s;\n' "$NGX_SO" > "$NGLOAD/40-zz-w18.conf"
      printf 'whisper_edge_data reputation /var/lib/w18p/rep.bin;\n' > /etc/nginx/conf.d/zz-w18.conf
      se_operator_label /var/lib/w18p/rep.bin
    fi
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'nginx: your reputation file /var/lib/w18p/rep.bin is kept' && says "$out" 'nginx: confirmed by the module: .*reputation armed at generation 497785'; } \
      && neg nginx-c7 "W18: the operator's own reputation file (the per-plane form, generation 497785): kept, verified against that file, confirmed, exit 0" \
      || fail "W18: a kept per-plane reputation file" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx: (kept|your|confirmed|applied|nothing)' | head -5 | cut -c1-300)"
    u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    rm -f /etc/nginx/conf.d/zz-w18.conf "$NGLOAD/40-zz-w18.conf"; rm -rf /var/lib/w18p
    if [ "$SYSD" = 1 ] && systemctl is-active --quiet nginx 2>/dev/null; then systemctl restart nginx >/dev/null 2>&1 || :
    else
      /usr/sbin/nginx -s quit 2>/dev/null || :
      wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
      srv_start nginx.service nginx /usr/sbin/nginx
    fi
    # W6: a rule the module refuses, planted after the installer's own checks: the server's test refuses
    # it, the writes go, nothing reloads, the record is the one before; the refusing line is nginx's
    : > "$RLC"; before=$(record $NG_TREES)
    out=$(keep srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_RULE=bad-level) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && [ "$(reloads nginx)" = 0 ] && [ "$(record $NG_TREES | grep -v '^/etc/whisper-edge')" = "$(printf '%s\n' "$before" | grep -v '^/etc/whisper-edge')" ] \
      && says "$out" 'nginx: the configuration test refused it: .*emerg' && says "$out" 'the previous configuration is unchanged' \
      && says "$out" 'test hooks active (a disposable box): WHISPER_EDGE_INSTALL_TEST_RULE=bad-level'; } \
      && neg nginx-apply "nginx: a rule only the module refuses: nginx's own test refused it (its emerg line), the writes taken back, no reload, the record unchanged" \
      || fail "nginx: reload only on a pass" "rc=$rc reloads=$(reloads nginx) $(printf '%s' "$out" | grep -E 'nginx:' | head -4 | cut -c1-200) $(printf '%s\n' "$before" > "$W/rec.b"; record $NG_TREES > "$W/rec.a"; diff "$W/rec.b" "$W/rec.a" | head -6)"
    # a configuration that fails its own test before the run is the operator's, said so, nothing written
    printf 'this is not nginx;\n' > /etc/nginx/conf.d/zz-broken.conf; before=$(record $NG_TREES)
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && says "$out" 'nginx: your configuration fails its own test before any change: ' && [ "$(record $NG_TREES)" = "$before" ]; } \
      && neg nginx-apply "nginx: a configuration already broken before the run: said to be the operator's, nothing written" \
      || fail "nginx: the pre-test" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -2)"
    rm -f /etc/nginx/conf.d/zz-broken.conf
    # W25: a data directory the worker cannot reach (its parent is root's alone, 0700): root reads every
    # plane and nginx -t would pass, but the modules' own probe, run as www-data, cannot bind the plane,
    # so the arm stops before it writes anything
    # its parent is the gate's own, under /var/lib, with no ACL: a host's /opt may be group- or world-
    # writable (GitHub's runner image: 0777 with default ACLs), and the installer then refuses the path
    # itself before any probe runs, which is a different property than the one this row is about
    rm -rf /var/lib/w25; mkdir -p /var/lib/w25; chmod 0700 /var/lib/w25
    command -v setfacl >/dev/null 2>&1 && setfacl -b /var/lib/w25 2>/dev/null || :
    before=$(record $NG_TREES)
    out=$(keep srv_run WHISPER_EDGE_DIR=/var/lib/w25/edge) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && says "$out" "nginx: nothing was applied: the module's own probe of /var/lib/w25/edge, run as $NGU" \
      && [ "$(record $NG_TREES)" = "$before" ] && [ "$(reloads nginx)" = 0 ] && [ -f /var/lib/w25/edge/reputation.bin ]; } \
      && neg nginx-apply "W25: a plane root reads but the worker cannot reach: the module's own probe, as www-data, refuses it (as $NGU); nothing written, nothing reloaded" \
      || fail "W25: the binding probe before any write" "rc=$rc reloads=$(reloads nginx) record $([ "$(record $NG_TREES)" = "$before" ] && echo unchanged || echo CHANGED) plane $([ -f /var/lib/w25/edge/reputation.bin ] && echo present || echo absent)
$(printf '%s\n' "$out" | grep -E 'nginx:|install\.sh:|nothing was|not root|could not|refus' | head -6 | cut -c1-300 | sed 's/^/     /')
     the path: $(ls -ld / /var /var/lib /var/lib/w25 2>&1 | awk '{ print $1, $3, $4, $NF }' | tr '\n' ';')$(command -v getfacl >/dev/null 2>&1 && getfacl -pc /var/lib 2>/dev/null | grep -v '^$' | tr '\n' ' ')"
    chattr -R -i /var/lib/w25 2>/dev/null || :; rm -rf /var/lib/w25
    # its run labelled the planes and counters/ of /var/lib/w25/edge on SELinux: those rules go too, from policy and record
    if command -v semanage >/dev/null 2>&1 && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
      semanage fcontext -d '/var/lib/w25/edge/[^/]+\.bin' >/dev/null 2>&1 || :
      semanage fcontext -d '/var/lib/w25/edge/counters(/.*)?' >/dev/null 2>&1 || :
      if [ -f /etc/whisper-edge/selinux-fcontext.added ]; then
        grep -vxF -e '/var/lib/w25/edge/[^/]+\.bin' -e '/var/lib/w25/edge/counters(/.*)?' /etc/whisper-edge/selinux-fcontext.added > "$W/serec" || :
        cat "$W/serec" > /etc/whisper-edge/selinux-fcontext.added; [ -s /etc/whisper-edge/selinux-fcontext.added ] || rm -f /etc/whisper-edge/selinux-fcontext.added
      fi
    fi
    # killed after the load file's rename and before the drop-in: what is left still tests clean,
    # and the next run's sweep takes it back before it writes anything. It starts from no installer file.
    [ -n "${u:-}" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    rm -f /etc/nginx/conf.d/whisper-edge.conf $NGLOAD/50-whisper-edge.conf; /usr/sbin/nginx -s reload 2>/dev/null
    : > "$RLC"; before=$(record $NG_TREES)
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_KILL=after-rename:$NGLOAD/50-whisper-edge.conf >/dev/null 2>&1 || true
    { [ -f $NGLOAD/50-whisper-edge.conf ] && [ ! -f /etc/nginx/conf.d/whisper-edge.conf ] && /usr/sbin/nginx -t >/dev/null 2>&1; } \
      && neg nginx-apply "nginx: killed between the load file and the drop-in, what is left is a configuration that tests clean (the write order)" \
      || fail "nginx: the partial state loads" "$(ls "$NGLOAD" /etc/nginx/conf.d 2>&1 | tr '\n' ' ')"
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'recovered an interrupted run' && [ "$(reloads nginx)" = 1 ]; } \
      && pass "and the next run sweeps it first, then applies, tests and reloads once" \
      || fail "nginx: the sweep after a kill" "rc=$rc reloads=$(reloads nginx) $(printf '%s' "$out" | grep -E 'recover|nginx:' | head -3)"
    u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "sh -c $u" >/dev/null 2>&1 || :
    # INT inside the open window: taken back, said, exit 130
    : > "$RLC"; before=$(record $NG_TREES)
    pause_arm
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_PAUSE=in-window > "$W/int.out" 2> "$W/int.out.err" &
    ipid=$!
    # the installer's sh is the child of env; signal the shell itself, then release the pause so it runs its trap
    if pause_wait in-window "$ipid"; then
      spid=$(pgrep -P "$ipid" -x sh || echo "$ipid")
      kill -TERM "$spid" 2>/dev/null; pause_release
    fi
    bg_wait "$ipid" && irc=0 || irc=$?
    collect_err "$W/int.out"
    { [ "$irc" = 143 ] && says "$(cat "$W/int.out")" 'nginx: interrupted after writing .* (TERM); removed; the previous configuration is unchanged and passes its test' \
      && [ "$(record $NG_TREES | grep -v '^/etc/whisper-edge')" = "$(printf '%s\n' "$before" | grep -v '^/etc/whisper-edge')" ] && [ "$(reloads nginx)" = 0 ]; } \
      && neg nginx-apply "nginx: TERM inside the open window: the writes taken back, the line says so, exit 143, no reload, the record unchanged (a background job ignores INT, so the arm sends TERM; the trap is the same)" \
      || fail "nginx: INT in the window" "rc=$irc $(grep -E 'nginx:' "$W/int.out" | head -3)"
    pause_done
    # The ceilings: a test that never returns is a refusal (nothing written), a reload that never returns
    # keeps the tested configuration and says so (exit 3), and the lock is free afterwards. The real
    # binary runs under a wrapper that sleeps on the one operation the arm is about.
    srv_start nginx.service nginx /usr/sbin/nginx
    shim nginx "case \" \$* \" in *' -t '*|*' -t') exec sleep 600 ;; esac; exec /usr/sbin/nginx \"\$@\""
    before=$(record $NG_TREES)
    out=$(keep srv_run WHISPER_EDGE_CMD_TIMEOUT=60) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && says "$out" 'nginx: its configuration test did not return within 60 s; nothing was written' && [ "$(record $NG_TREES)" = "$before" ]; } \
      && neg nginx-apply "a configuration test that never returns: stopped at the 60 s ceiling, nothing written, exit 1" \
      || fail "the test ceiling" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-200)"
    shim nginx "case \" \$* \" in *' -s reload '*) exec sleep 600 ;; esac; exec /usr/sbin/nginx \"\$@\""
    if [ "$SYSD" = 1 ]; then mkdir -p /etc/systemd/system/nginx.service.d; printf '[Service]\nExecReload=\nExecReload=/bin/sleep 600\n' > /etc/systemd/system/nginx.service.d/zz-installer-gate-hang.conf; daemon_reload; fi
    out=$(keep srv_run WHISPER_EDGE_CMD_TIMEOUT=60) && rc=0 || rc=$?
    out2=$(keep srv_run) && rc2=0 || rc2=$?
    { [ "$rc" = 3 ] && says "$out" 'nginx: reload did not return within 60 s; the configuration tested clean' && ! says "$out2" '^   another installer run is in progress'; } \
      && neg nginx-apply "a reload that never returns: the tested configuration kept, said at the 60 s ceiling, exit 3, and the lock is free for the next run" \
      || fail "the reload ceiling" "rc=$rc rc2=$rc2 $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-200)"
    rm -f /etc/systemd/system/nginx.service.d/zz-installer-gate-hang.conf; daemon_reload
    srv_shims
    u=$(undo_of "$out2" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    # The trap on an error inside the open window, without a signal: the drop-in's directory made
    # unwritable (immutable) after the load file is written, so the drop-in cannot be made; and a full
    # disk there (a 16 KiB tmpfs over it, filled). Each takes the load file back, says so, and exits 4.
    for arm in immutable enospc; do
      : > "$RLC"; before=$(record $NG_TREES); ms0=$(mount_state)
      case "$arm" in
        immutable) chattr +i /etc/nginx/conf.d ;;
        enospc) cp -a /etc/nginx/conf.d "$W/confd.save"; mount -t tmpfs -o size=16k tmpfs /etc/nginx/conf.d && cp -a "$W/confd.save"/. /etc/nginx/conf.d/ || :
                # filled to the last block: dd ends on ENOSPC by design
                dd if=/dev/zero of=/etc/nginx/conf.d/.fill bs=1k count=64 2>/dev/null || : ;;
      esac
      out=$(keep srv_run) && rc=0 || rc=$?
      case "$arm" in immutable) chattr -i /etc/nginx/conf.d ;; enospc) rm -f /etc/nginx/conf.d/.fill; umount /etc/nginx/conf.d; rm -rf "$W/confd.save" ;; esac
      # the first file the window writes depends on the layout (the load file where the module is not yet
      # loaded, else the drop-in itself), so the line is held to its shape, not to one path
      { [ "$rc" = 4 ] && says "$out" "nginx: interrupted after writing .* (" && [ "$(record $NG_TREES)" = "$before" ] && [ "$(reloads nginx)" = 0 ]; } \
        && neg nginx-apply "an error inside the window ($arm): the load file taken back, the line names it and the cause, exit 4, no reload, the record unchanged" \
        || fail "the trap on an error in the window ($arm)" "rc=$rc $(printf '%s' "$out" | grep -E 'nginx:|could not' | head -3 | cut -c1-220)"
      if [ "$arm" = enospc ]; then mount_guard "the full-disk arm (a tmpfs over conf.d)" "$ms0"; fi
    done
    # W33: an nginx started by hand with its own -c and -p and no unit: the installer applies to the
    # configuration that master reads, tests and reloads it with the same -c and -p, and leaves the
    # build's default configuration alone
    unit_do stop nginx; /usr/sbin/nginx -s quit 2>/dev/null || :
    wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
    rm -rf /var/lib/w33; mkdir -p /var/lib/w33; cp -a /etc/nginx/. /var/lib/w33/
    rm -f /var/lib/w33/conf.d/whisper-edge.conf /var/lib/w33/modules-enabled/50-whisper-edge.conf
    sed -i 's#/etc/nginx#/var/lib/w33#g' /var/lib/w33/nginx.conf
    # Debian's /etc/nginx/modules is a relative link to the build's module directory; the copy names it
    # absolutely, so a module the package loads (the stream module) still loads from the copy's prefix
    if [ -L /var/lib/w33/modules ] || [ ! -e /var/lib/w33/modules ]; then rm -f /var/lib/w33/modules; ln -s "$NGMOD" /var/lib/w33/modules; fi
    /usr/sbin/nginx -c /var/lib/w33/nginx.conf -p /var/lib/w33/ 2> "$W/w33.err" || fail "W33: the hand-started nginx starts" "$(head -2 "$W/w33.err")"
    wait_until 60 master_of 'nginx: master process /usr/sbin/nginx -c /var/lib/w33/nginx.conf' || :
    : > "$RLC"; before=$(record /etc/nginx)
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'nginx: the running master reads /var/lib/w33/nginx.conf (its -c)' && [ -f /var/lib/w33/conf.d/whisper-edge.conf ] \
      && [ "$(record /etc/nginx)" = "$before" ] && [ "$(reloads nginx)" = 1 ] && says "$out" 'nginx: reloaded (nginx -c /var/lib/w33/nginx.conf -p /var/lib/w33/ -s reload)'; } \
      && neg nginx-apply "W33: a hand-started nginx (-c /var/lib/w33/nginx.conf -p /var/lib/w33/): its own configuration applied, tested and reloaded with its -c and -p, /etc/nginx untouched" \
      || fail "W33: the hand-started master" "rc=$rc reloads=$(reloads nginx) $(printf '%s' "$out" | grep -E 'nginx:' | head -4 | cut -c1-220)"
    /usr/sbin/nginx -c /var/lib/w33/nginx.conf -p /var/lib/w33/ -s quit 2>/dev/null || :
    wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :; rm -rf /var/lib/w33
    unit_do stop nginx; /usr/sbin/nginx -s quit 2>/dev/null || :
    wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
    # O5's namespace arm: an nginx master whose root is not this one (started chrooted into a bind of /, as
    # a container's master looks from the host) is not this host's server: said, treated as not running,
    # nothing reloaded
    ms0=$(mount_state)
    if ! command -v chroot >/dev/null 2>&1; then skip "O5's namespace arm" "no chroot on this box"
    elif ! sh -c "$NS_UP" sh /var/lib/nsroot; then fail "O5's bind of /" "the bind could not be made a slave, so the arm did not run (its unmount could reach the host's mounts)"
    else
      chroot /var/lib/nsroot /usr/sbin/nginx >/dev/null 2>&1 || :
      wait_until 60 master_of 'nginx: master process' || :
      nsm=$(ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }')
      : > "$RLC"
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ -n "$nsm" ] && [ "$(readlink "/proc/$nsm/root")" = /var/lib/nsroot ] && says "$out" "nginx: the master $nsm is not this host's (another mount namespace, or another binary): treated as not running" \
        && [ "$(reloads nginx)" = 0 ]; } \
        && neg nginx-apply "O5: an nginx master whose root is not this one (pid $nsm, root /var/lib/nsroot): not this host's, said, nothing reloaded" \
        || fail "O5: the namespace check" "rc=$rc master=${nsm:-none} root=$(readlink "/proc/${nsm:-0}/root" 2>&1) $(printf '%s' "$out" | grep -E 'nginx:' | head -3 | cut -c1-220)"
      [ -n "$nsm" ] && kill -QUIT "$nsm" 2>/dev/null || :
      wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
      sh -c "$NS_DOWN" sh /var/lib/nsroot
      mount_guard "O5's namespace arm" "$ms0"
      u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    fi
    /usr/sbin/nginx -s quit 2>/dev/null || :
    wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
    # A confined server: nginx started by its systemd unit (on SELinux it runs as httpd_t, which may read
    # var_lib_t but not map it, so an unlabelled plane leaves the module inert). The installer applies,
    # reloads through the unit, and the module must confirm; on SELinux the plane carries
    # httpd_sys_content_t and counters/ httpd_var_lib_t, and the plane keeps its label across a refresh.
    if [ "$SYSD" = 1 ]; then
      # the earlier arms' workers are gone and their files stay in the shared counters/ (gone is right for
      # them); this arm's property is about its own writers, so it starts from a counters/ with none
      find /var/lib/whisper-edge/counters -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || :
      unit_start_after_hand nginx /run/nginx.pid
      wait_until 60 master_of 'nginx: master process' || :
      ngm=$(ps -eo pid=,args= | awk '$2 == "nginx:" && $3 == "master" { print $1; exit }')
      nctx=$(ps -o label= -p "${ngm:-0}" 2>/dev/null || echo -)
      : > "$RLC"; out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && systemctl is-active --quiet nginx && says "$out" 'nginx: reloaded (systemctl reload ' \
        && says "$out" 'nginx: confirmed by the module: worker pid [0-9]*, new since the reload'; } \
        && pos_pass nginx-unit "nginx started by its systemd unit (master $ngm, context ${nctx:--}): applied, reloaded through the unit, confirmed by the module" \
        || fail "a systemd-started nginx" "rc=$rc master=${ngm:-none} context=${nctx:--} $(printf '%s' "$out" | grep -E 'nginx: [^n]|labelled|SELinux' | grep -v LimitMEMLOCK | head -5 | cut -c1-260)"
      writer_rows nginx-unit "${ngm:-0}" "the systemd-started nginx"
      if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        lab() { stat -c %C -- "$1" 2>/dev/null | cut -d: -f3; }
        { [ "$(lab /var/lib/whisper-edge/reputation.bin)" = httpd_sys_content_t ] && [ "$(lab /var/lib/whisper-edge/counters)" = httpd_var_lib_t ]; } \
          && neg nginx-unit "on SELinux the plane carries httpd_sys_content_t (read and map, no write) and counters/ httpd_var_lib_t (the worker's own state: it creates, rewrites and renames there)" \
          || fail "the planes' SELinux label" "reputation.bin: $(lab /var/lib/whisper-edge/reputation.bin), counters: $(lab /var/lib/whisper-edge/counters)"
        # the worker's state goes on being written, not once: each tick renames a new status over the old,
        # which needs unlink on the target. Under var_lib_t a confined worker writes its first files and is
        # denied every rewrite after (measured on Rocky 9.8: "denied { unlink } comm=nginx", tick 0 at
        # interval 60000 six minutes on). Two ticks on every live writer, a count file rewritten since, and
        # no unlink denial in the audit log over the wait.
        al=/var/log/audit/audit.log; den() { grep -c 'avc: *denied *{ unlink }.*tcontext=[^ ]*:var_lib_t' "$al" 2>/dev/null || :; }
        d0=$(den); : > "$W/tick.mark"
        for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 5 http://127.0.0.1/ || :; done
        ticks() { /usr/local/sbin/whisper-edge-summary --status /var/lib/whisper-edge/counters 2>/dev/null \
          | awk '$1 == "process" { for (i = 2; i < NF; i++) if ($i == "tick") { n++; if ($(i + 1) + 0 < 2) low++ } } END { if (!n || low) exit 1 }'; }
        wait_until 300 ticks && tk=0 || tk=$?
        nrc=$(find /var/lib/whisper-edge/counters -name '*.rules.cnt' -newer "$W/tick.mark" | wc -l); d1=$(den)
        { [ "$tk" = 0 ] && [ "$nrc" -ge 1 ] && [ -f "$al" ] && [ "${d1:-0}" = "${d0:-0}" ]; } \
          && neg nginx-unit "on SELinux the confined workers keep writing their state: every live writer at tick 2 or more, $nrc count file(s) rewritten since, no unlink denial" \
          || fail "the confined workers' state across ticks" "ticks reached: $([ "$tk" = 0 ] && echo yes || echo no) ($(/usr/local/sbin/whisper-edge-summary --status /var/lib/whisper-edge/counters 2>&1 | grep -o '^process pid [0-9]* tick [0-9]*' | tr '\n' ';')); count files rewritten: $nrc; unlink denials $d0 -> $d1$([ -f "$al" ] || echo "; no $al to read")"
        feed 497776 normal
        rfo=$(env WHISPER_EDGE_RESOLVE="$RES" /usr/local/sbin/whisper-edge-refresh --plane reputation --dir /var/lib/whisper-edge --base "$FEED" 2>&1) && rfc=0 || rfc=$?
        { [ "$(header_gen /var/lib/whisper-edge/reputation.bin)" = 497776 ] && [ "$(lab /var/lib/whisper-edge/reputation.bin)" = httpd_sys_content_t ]; } \
          && neg nginx-unit "and a refresh that renames generation 497776 in leaves the plane httpd_sys_content_t" \
          || fail "the plane's label across a refresh" "rc=$rfc generation $(header_gen /var/lib/whisper-edge/reputation.bin), label $(lab /var/lib/whisper-edge/reputation.bin): $(printf '%s' "$rfo" | head -2)"
        feed 497775 normal
      else
        skip "the planes' SELinux labels under a confined server" "SELinux is not enabled on this host"
      fi
      u=$(undo_of "$out" nginx); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
      # on SELinux the shared undo line takes back exactly the file context rule the installer added, and the
      # plane reads the directory's own label again (the planes themselves are kept, as the line says)
      if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v semanage >/dev/null 2>&1; then
        su_l=$(printf '%s\n' "$out" | sed -n 's/^   undo, the shared parts (after every server line): //p' | sed -n 1p)
        pre=0
        semanage fcontext -l -C 2>/dev/null | awk '$1 == "/var/lib/whisper-edge/[^/]+\\.bin" { p = 1 } $1 == "/var/lib/whisper-edge/counters(/.*)?" { c = 1 } END { exit !(p && c) }' && pre=1
        # the line as printed is "sh -c '...'": run it as a paste runs it, never wrapped in a second sh -c
        # (which ran "sh" with nothing to do, so the rules were never removed and the row read the undo as broken)
        [ -n "$su_l" ] && sh -c "$su_l" >/dev/null 2>&1 || :
        { [ "$pre" = 1 ] && ! semanage fcontext -l -C 2>/dev/null | grep_any -F '/var/lib/whisper-edge/' \
          && [ ! -e /etc/whisper-edge/selinux-fcontext.added ] && [ "$(lab /var/lib/whisper-edge/reputation.bin)" = var_lib_t ] \
          && [ "$(lab /var/lib/whisper-edge/counters)" = var_lib_t ]; } \
          && neg nginx-unit "on SELinux the shared undo line removes both file context rules the installer added (the planes', counters/'), and the kept plane and counters/ read var_lib_t again" \
          || fail "the SELinux rule's undo" "rules: $(semanage fcontext -l -C 2>/dev/null | grep -F whisper-edge | tr '\n' ';'); record: $(cat /etc/whisper-edge/selinux-fcontext.added 2>/dev/null | tr '\n' ' '); plane: $(lab /var/lib/whisper-edge/reputation.bin)"
      fi
      unit_do stop nginx
    else
      skip "a systemd-started nginx" "systemd is not running on this box"
    fi
    srv_teardown nginx nginx
  fi
  # ---- Apache (Debian: conf-available then a2enconf; RHEL: conf.d); configtest; graceful on a pass ------
  SRVSEL=apache
  AP_SO=$APMOD/mod_whisper_edge.so
  if ! [ -x /usr/sbin/$APX ] || ! [ -f "$AP_SO" ]; then
    skip "the Apache arm" "no Apache with the module built from this tree at $AP_SO"
  else
    feed 497775 normal
    begin_arm "Apache" || return 0
    AP_TREES="$APT"
    : > "$RLC"; srv_shims
    mkdir -p "$(dirname "$APPID")" /run/lock/apache2 /var/log/apache2
    t=$(/usr/sbin/$APCTL -t 2>&1) || { fail "the Apache arm" "the stock configuration does not test clean before the run: $(printf '%s' "$t" | head -2)"; return 0; }
    srv_stock apache "$APT"
    # the teardown's own row: an Apache arm that fails part-way leaves its drop-in (with a directive the
    # server refuses, as a failing row can) in the configuration; the teardown must put the stock one back,
    # so the next arm's clean-start precondition (configtest passes, the record as kept) holds again
    printf '# left by a failing arm\nThisIsNotADirective on\n' > "$APDROP"
    if [ "$APX" = apache2 ]; then ln -sf ../conf-available/whisper-edge.conf /etc/apache2/conf-enabled/whisper-edge.conf; fi
    if /usr/sbin/$APCTL -t >/dev/null 2>&1; then fail "the teardown row's planted failure" "the planted directive did not break configtest"
    else
      srv_restore apache || :
      t=$(/usr/sbin/$APCTL -t 2>&1) && trc=0 || trc=$?
      { [ "$trc" = 0 ] && [ "$(record "$APT")" = "$(cat "$W/stock/apache/record")" ]; } \
        && pass "a failing Apache arm's leftovers (its drop-in, a directive Apache refuses): the teardown puts the stock configuration back byte for byte, and the next arm's configtest passes" \
        || fail "the teardown after a failing Apache arm" "configtest rc=$trc $(printf '%s' "$t" | head -1); record differs: $(record "$APT" | diff "$W/stock/apache/record" - | head -4 | tr '\n' ';')"
    fi
    srv_restore apache || :; srv_stock apache "$APT"
    srv_start "$APU" apache /usr/sbin/$APCTL start
    before=$(record $AP_TREES); eff0=$(eff_digest apache); us0=$(unit_state "$APU")
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && [ -f "$APDROP" ] && { [ "$APX" = httpd ] || [ -L /etc/apache2/conf-enabled/whisper-edge.conf ]; } \
      && [ "$(record $AP_TREES)" != "$before" ] && [ "$(reloads apache)" = 1 ] && says "$out" 'Apache: the configuration test passed' \
      && says "$out" 'Apache: confirmed by the module: worker pid .*, new since the reload'; } \
      && pos_pass apache-apply "Apache: conf-available written, then a2enconf, configtest passed, exactly one graceful, and the module confirms the new program (the positive control)" \
      || fail "Apache: apply, test, reload" "rc=$rc reloads=$(reloads apache)
$(printf '%s\n' "$out" | sed -n '/^== applied/,$p' | head -40)"
    # W34 for Apache: a re-run with nothing to change. On Debian a2enconf's conf-enabled/whisper-edge.conf is
    # a link to the installer's own file, and Apache lists the file by that name; read as the operator's, it
    # kept the installer's own lines and rewrote the policy empty (measured on Ubuntu 24.04). Nothing may change.
    after=$(record $AP_TREES); psum=$(sha256sum < "$APDROP"); out1=$out
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && [ "$(reloads apache)" = 1 ] && [ "$(record $AP_TREES)" = "$after" ] && [ "$(sha256sum < "$APDROP")" = "$psum" ] \
      && says "$out" 'Apache: nothing changed in its configuration, so it was not reloaded' \
      && ! says "$out" 'Apache: kept your\|Apache: your policy'; } \
      && neg apache-apply "Apache: a second run with nothing to change: its own file (read through a2enconf's link) is not taken for the operator's, no byte changed, no graceful (the count stays 1)" \
      || fail "Apache: the zero-change re-run" "rc=$rc reloads=$(reloads apache) $(printf '%s' "$out" | grep -E 'Apache: (kept|your policy|nothing|applied)|default policy' | head -6 | cut -c1-250)
$([ "$(record $AP_TREES)" = "$after" ] || printf '     the record differs: %s' "$(printf '%s\n' "$after" > "$W/aprec.$$"; record $AP_TREES | diff -- "$W/aprec.$$" - 2>/dev/null | head -6 | tr '\n' ';')")"
    # a re-run whose rewrite of the installer's own drop-in is refused must leave the drop-in that was
    # serving, byte for byte: taken back as "created", it was removed, and Apache was left with no module
    # and no policy behind a dangling a2enconf link (measured on Ubuntu 24.04, configtest still passing)
    out=$(keep srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_RULE=bad-level) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && [ "$(reloads apache)" = 1 ] && [ -f "$APDROP" ] && [ "$(sha256sum < "$APDROP")" = "$psum" ] \
      && says "$out" 'Apache: the configuration test refused it' && says "$out" 'its previous bytes restored' \
      && /usr/sbin/$APCTL -t >/dev/null 2>&1 && [ -z "$(find "$REAL_ETC/undo" -name 'prev.*' 2>/dev/null)" ]; } \
      && neg apache-apply "Apache: a re-run whose rewrite of the drop-in is refused puts the serving drop-in back byte for byte (not removed), no graceful, no kept copy left behind" \
      || fail "Apache: a refused rewrite of the drop-in" "rc=$rc reloads=$(reloads apache) drop-in: $([ -f "$APDROP" ] && { [ "$(sha256sum < "$APDROP")" = "$psum" ] && echo same || echo changed; } || echo gone) $(printf '%s' "$out" | grep -E 'Apache: (the conf|removed|wrote|interrupted)' | head -4 | cut -c1-250); copies: $(find "$REAL_ETC/undo" -name 'prev.*' 2>/dev/null | tr '\n' ' ')"
    # killed after its rewrite of the drop-in landed and before the test: the next run's sweep puts the
    # previous bytes back, and with them the run has nothing to change
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_RULE=bad-level WHISPER_EDGE_INSTALL_TEST_KILL="after-rename:$APDROP" >/dev/null 2>&1 || true
    k1=$( [ -f "$APDROP" ] && sha256sum < "$APDROP" || echo gone)
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$k1" != "$psum" ] && [ "$rc" = 0 ] && [ "$(reloads apache)" = 1 ] && [ "$(sha256sum < "$APDROP")" = "$psum" ] \
      && says "$out" "restored $APDROP to its bytes from before the interrupted run" \
      && says "$out" 'Apache: nothing changed in its configuration, so it was not reloaded' \
      && [ -z "$(find "$REAL_ETC/undo" -name 'prev.*' 2>/dev/null)" ]; } \
      && neg apache-apply "Apache: a re-run killed after replacing the drop-in: the next run's sweep restores the previous bytes, then has nothing to change (no graceful)" \
      || fail "Apache: the sweep of a replaced drop-in" "killed run left $([ "$k1" = "$psum" ] && echo 'the old bytes (the kill point was not reached)' || echo "$k1"); rc=$rc reloads=$(reloads apache) $(printf '%s' "$out" | grep -E 'recovered|restored|kept|Apache: (nothing|wrote)' | head -4 | cut -c1-250)"
    # the server's own mod_remoteip trust, read in the server config only: advised, never written; a
    # virtual host's own list is that site's
    rmd=""; for d in /usr/lib/apache2/modules /usr/lib64/httpd/modules /usr/lib/httpd/modules; do [ -f "$d/mod_remoteip.so" ] && { rmd=$d; break; }; done
    ren=/etc/httpd/conf.d; [ "$APX" = apache2 ] && ren=/etc/apache2/conf-enabled
    if [ -n "$rmd" ]; then
      rl=""; /usr/sbin/$APCTL -M 2>/dev/null | grep_any remoteip_module || rl="LoadModule remoteip_module $rmd/mod_remoteip.so
"
      rr0=$(record $AP_TREES); printf '%sRemoteIPHeader X-Forwarded-For\nRemoteIPInternalProxy 127.0.0.1 ::1\n' "$rl" > "$ren/zz-realip.conf"
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && [ "$(reloads apache)" = 1 ] && [ "$(sha256sum < "$APDROP")" = "$psum" ] \
        && says "$out" 'Apache: your RemoteIPHeader with RemoteIPInternalProxy or RemoteIPTrustedProxy in the server config trusts 127.0.0.1 ::1 for X-Forwarded-For' \
        && printf '%s\n' "$out" | grep_any -x '     WhisperEdgeTrustedProxy 127.0.0.1 ::1' && printf '%s\n' "$out" | grep_any -x '     WhisperEdgeTrustedHeader X-Forwarded-For' \
        && ! grep -rqi 'whisperedgetrusted' "$APDROP"; } \
        && pass "Apache: a server-config mod_remoteip trust is advised with its own addresses and header (WhisperEdgeTrustedProxy 127.0.0.1 ::1, WhisperEdgeTrustedHeader X-Forwarded-For), and nothing is written" \
        || fail "Apache: the remoteip advice" "rc=$rc reloads=$(reloads apache) $(printf '%s\n' "$out" | grep -E 'RemoteIP|Trusted' | head -4 | cut -c1-250)"
      printf '%s<VirtualHost 127.0.0.1:8099>\n  RemoteIPHeader X-Forwarded-For\n  RemoteIPInternalProxy 127.0.0.1\n</VirtualHost>\n' "$rl" > "$ren/zz-realip.conf"
      out=$(keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 0 ] && ! says "$out" 'RemoteIPHeader with' && ! printf '%s\n' "$out" | grep_any 'WhisperEdgeTrusted'; } \
        && pass "Apache: a virtual host's own mod_remoteip list is that site's: no advice" \
        || fail "Apache: no remoteip advice for a virtual host" "rc=$rc $(printf '%s\n' "$out" | grep -E 'RemoteIP|Trusted' | head -3 | cut -c1-250)"
      rm -f "$ren/zz-realip.conf"
      [ "$(record $AP_TREES)" = "$rr0" ] || fail "the remoteip rows' cleanup" "the record differs after removing zz-realip.conf"
    else
      skip "Apache: the remoteip advice" "no mod_remoteip.so on this host"
    fi
    out=$out1   # the undo is the first run's: the line it printed is the one an operator would hold
    u=$(undo_of "$out" Apache)
    if [ -n "$u" ]; then
      uo=$(eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" 2>&1) && urc=0 || urc=$?
      { [ "$urc" = 0 ] && [ "$(record $AP_TREES)" = "$before" ] && [ "$(reloads apache)" = 2 ] && [ "$(eff_digest apache)" = "$eff0" ] && [ "$(unit_state "$APU")" = "$us0" ]; } \
        && neg apache-apply "Apache: the printed undo line (a2disconf, the file, configtest, graceful) restores the record exactly, the effective configuration (its includes, $eff0) and the unit's state ($us0)" \
        || fail "Apache: the undo line" "rc=$urc $uo"
    else fail "Apache: the undo line" "no 'undo, Apache' line"; fi
    # W18 for Apache, the per-plane form: the operator's own LoadModule and WhisperEdgeData reputation <file>
    # at a newer generation; kept, verified against that file, exit 0; Apache started afresh after
    plane_at 497785 /var/lib/w18p/rep.bin; se_operator_label /var/lib/w18p/rep.bin
    printf 'LoadModule whisper_edge_module %s\nWhisperEdgeData reputation /var/lib/w18p/rep.bin\n' "$AP_SO" > "$APOP"
    if [ "$APX" = apache2 ]; then ln -sf ../conf-available/zz-operator.conf /etc/apache2/conf-enabled/zz-operator.conf; fi
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'Apache: your reputation file /var/lib/w18p/rep.bin is kept' && says "$out" 'Apache: confirmed by the module: .*reputation armed at generation 497785'; } \
      && neg apache-apply "W18: Apache with the operator's own reputation file (the per-plane form, generation 497785): kept, verified against that file, confirmed, exit 0" \
      || fail "W18: Apache's kept per-plane reputation file" "rc=$rc $(printf '%s' "$out" | grep -E 'Apache: (kept|your|confirmed|applied|nothing)' | head -5 | cut -c1-300)"
    u=$(undo_of "$out" Apache); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    rm -f "$APOP" /etc/apache2/conf-enabled/zz-operator.conf; rm -rf /var/lib/w18p
    /usr/sbin/$APCTL stop >/dev/null 2>&1 || :
    wait_until 60 sh -c '! ps -eo args= | grep -Eq "^/usr/sbin/(apache2|httpd)"' || :
    srv_start "$APU" apache /usr/sbin/$APCTL start
    # W20 for an arm-local refusal: an operator's own conf-enabled/whisper-edge.conf (not the installer's
    # link) refuses the Apache arm inside its window; Apache's drop-in is taken back and that arm fails,
    # and nginx, named in the same run, still applies and is confirmed. The run's exit is 1 (a refusal),
    # never the 4 of a run interrupted. Debian's layout only: RHEL has no conf-enabled.
    if [ "$APX" = apache2 ] && [ -x /usr/sbin/nginx ] && [ -f "$NGX_SO" ]; then
      printf '# the operator'"'"'s own file\n' > /etc/apache2/conf-enabled/whisper-edge.conf; osum=$(sha256sum < /etc/apache2/conf-enabled/whisper-edge.conf)
      wait_until 60 sh -c '! ps -eo args= | grep -q "^nginx: master"' || :
      srv_start nginx.service nginx /usr/sbin/nginx
      : > "$RLC"
      out=$(SRVSEL=nginx,apache keep srv_run) && rc=0 || rc=$?
      { [ "$rc" = 1 ] && says "$out" "Apache: /etc/apache2/conf-enabled/whisper-edge.conf exists and is not the installer's link; move it aside and run again; removed what this run wrote ($APDROP)" \
        && [ ! -e "$APDROP" ] && [ "$(sha256sum < /etc/apache2/conf-enabled/whisper-edge.conf)" = "$osum" ] && [ "$(reloads apache)" = 0 ] \
        && { says "$out" 'nginx: confirmed by the module: worker pid' || says "$out" 'nginx: the configuration test passed'; } \
        && says "$out" 'undo, the shared parts (after every server line): sh -c'; } \
        && neg apache-apply "an arm-local refusal (an operator's conf-enabled/whisper-edge.conf): Apache's drop-in taken back, no graceful, the operator's file unchanged; nginx in the same run applied, and the run went on to its shared parts (their undo line printed); exit 1, not 4" \
        || fail "an arm-local refusal ends only its arm" "rc=$rc reloads=$(reloads apache) $(printf '%s' "$out" | grep -E 'Apache: [^n]|nginx: (confirmed|applied|nothing|the server)' | grep -v LimitMEMLOCK | head -8 | cut -c1-300)"
      rm -f /etc/apache2/conf-enabled/whisper-edge.conf
      un=$(undo_of "$out" nginx); [ -n "$un" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $un" >/dev/null 2>&1 || :
      /usr/sbin/nginx -s quit 2>/dev/null || :; [ "$SYSD" = 1 ] && systemctl stop nginx >/dev/null 2>&1 || :
    fi
    # W27: an operator's <IfModule whisper_edge_module> holding a status the module refuses; skipped until the
    # installer's LoadModule loads the module, so the pre-test passes and the server's own test refuses
    printf '<IfModule whisper_edge_module>\n    WhisperEdgeDenyStatus 401\n</IfModule>\n' > "$APOP"
    if [ "$APX" = apache2 ]; then ln -sf ../conf-available/zz-operator.conf /etc/apache2/conf-enabled/zz-operator.conf; fi
    : > "$RLC"; before=$(record $AP_TREES)
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && [ "$(reloads apache)" = 0 ] && [ "$(record $AP_TREES)" = "$before" ] \
      && says "$out" 'Apache: the configuration test refused it: .*401' && ! says "$out" 'before any change'; } \
      && neg apache-apply "W27: an operator's <IfModule> block the installer's LoadModule awakens (status 401): the pre-test passed, Apache's own test refused it, the files taken back, no graceful, the record unchanged" \
      || fail "W27: the hook-free refusal" "rc=$rc reloads=$(reloads apache) $(printf '%s' "$out" | grep -E 'Apache:' | head -3)"
    rm -f /etc/apache2/conf-enabled/zz-operator.conf "$APOP"
    # W29: a fault Apache's configtest cannot see, planted after the probe and before the graceful (the
    # plane made unreadable to the worker at the pause in the open window): the graceful runs, the parent
    # stays, a request is answered, and the module's own status says the plane is unreadable (exit 3)
    feed 497775 normal
    srv_start "$APU" apache /usr/sbin/$APCTL start
    wait_until 60 test -s "$APPID" || :; ppid_before=$(cat "$APPID" 2>/dev/null || :)
    pause_arm
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_PAUSE=in-window > "$W/w29.out" 2> "$W/w29.out.err" &
    ipid=$!
    if pause_wait in-window "$ipid"; then
      chattr -i /var/lib/whisper-edge/reputation.bin 2>/dev/null || :; chmod 0400 /var/lib/whisper-edge/reputation.bin
      pause_release
    fi
    bg_wait "$ipid" && wrc=0 || wrc=$?
    collect_err "$W/w29.out"
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1/ || echo none)
    { [ "$wrc" = 3 ] && [ "$(cat $APPID 2>/dev/null)" = "$ppid_before" ] && [ -n "$code" ] && [ "$code" != none ] && [ "$code" != 000 ] \
      && says "$(cat "$W/w29.out")" 'Apache: applied and serving, but the module reports: '; } \
      && neg apache-apply "W29: a plane the worker cannot read, planted after the probe: configtest passed, the graceful kept the parent (pid $ppid_before), a request answered (HTTP $code: the stock site), and the module's status says so (exit 3)" \
      || fail "W29: Apache's real-pass fault under graceful" "rc=$wrc parent $ppid_before -> $(cat $APPID 2>/dev/null) http=$code $(grep -E 'Apache:' "$W/w29.out" | head -3 | cut -c1-220)"
    chmod 0444 /var/lib/whisper-edge/reputation.bin; pause_done
    u=$(undo_of "$(cat "$W/w29.out")" Apache); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    /usr/sbin/$APCTL stop >/dev/null 2>&1 || true
    wait_until 60 sh -c '! ps -eo args= | grep -Eq "^/usr/sbin/(apache2|httpd)"' || :
    # W29b: the other post_config-only fault, a locked-memory limit too low for the plane, set on the
    # running parent (prlimit, as a unit's low LimitMEMLOCK would leave it) after the probe. Measured on
    # 2026-10-18: the module does not refuse the plane for it; it binds it unlocked
    # (evictable) and reports it armed. So the property is the graceful's: the parent stays, a request
    # is answered, the module confirms, and the report carries the locked-memory line that says how much
    # the server needs.
    if command -v prlimit >/dev/null 2>&1; then
      srv_start "$APU" apache /usr/sbin/$APCTL start
      wait_until 60 test -s "$APPID" || :; ppid_before=$(cat "$APPID" 2>/dev/null || :)
      pause_arm
      srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_INSTALL_TEST_PAUSE=in-window > "$W/w29b.out" 2> "$W/w29b.out.err" &
      ipid=$!
      if pause_wait in-window "$ipid"; then prlimit --pid "$ppid_before" --memlock=4096:4096 2>/dev/null || :; pause_release; fi
      bg_wait "$ipid" && wrc=0 || wrc=$?
      collect_err "$W/w29b.out"
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1/ || echo none)
      { [ "$wrc" = 0 ] && [ "$(cat $APPID 2>/dev/null)" = "$ppid_before" ] && [ -n "$code" ] && [ "$code" != none ] && [ "$code" != 000 ] \
        && says "$(cat "$W/w29b.out")" 'Apache: confirmed by the module: worker pid' && { says "$(cat "$W/w29b.out")" 'bytes of locked memory' || says "$(cat "$W/w29b.out")" "LimitMEMLOCK: [0-9]* is $APU's effective limit; twice the armed plane bytes .* is [0-9]*"; }; } \
        && neg apache-apply "W29b: a locked-memory limit too low for the plane, set on the running parent after the probe: the graceful kept the parent (pid $ppid_before), a request answered (HTTP $code), the module confirmed the plane (bound unlocked), and the report names the locked memory the server needs (exit 0)" \
        || fail "W29b: a low memlock under graceful" "rc=$wrc parent $ppid_before -> $(cat $APPID 2>/dev/null) http=$code $(grep -E 'Apache:' "$W/w29b.out" | head -3 | cut -c1-220)"
      pause_done
      u=$(undo_of "$(cat "$W/w29b.out")" Apache); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
      /usr/sbin/$APCTL stop >/dev/null 2>&1 || true
      wait_until 60 sh -c '! ps -eo args= | grep -Eq "^/usr/sbin/(apache2|httpd)"' || :
    else
      skip "W29b, a low locked-memory limit under graceful" "no prlimit on this box"
    fi
    # O5 for Apache: a parent started by hand with its own -f. A copy of the main configuration that still
    # includes the layout's enable directory is applied, tested and gracefully reloaded with that -f; a copy
    # whose includes reach nothing of the layout's is refused, nothing written, exit 1.
    APMAIN=/etc/apache2/apache2.conf; [ "$APX" = httpd ] && APMAIN=/etc/httpd/conf/httpd.conf
    rm -rf /var/lib/w33a; mkdir -p /var/lib/w33a
    cp "$APMAIN" /var/lib/w33a/main.conf
    : > "$RLC"; before=$(record $AP_TREES)
    ap_hand -f /var/lib/w33a/main.conf -k start >/dev/null 2>&1 || :
    wait_until 60 master_of "/usr/sbin/$APX -f /var/lib/w33a/main.conf" || :
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 0 ] && says "$out" 'Apache: the running parent reads /var/lib/w33a/main.conf (its -f)' && [ "$(reloads apache)" = 1 ] \
      && says "$out" "Apache: reloaded ($APDRV -f /var/lib/w33a/main.conf -k graceful)"; } \
      && neg apache-apply "O5: a hand-started Apache (-f /var/lib/w33a/main.conf) whose configuration includes the layout's directory: applied, tested and reloaded with its -f" \
      || fail "O5: a hand-started Apache with -f" "rc=$rc reloads=$(reloads apache) $(printf '%s' "$out" | grep -E 'Apache:' | head -4 | cut -c1-220)"
    u=$(undo_of "$out" Apache); [ -n "$u" ] && eval "PATH=\"$SH:/usr/sbin:/usr/bin:/sbin:/bin\" sh -c $u" >/dev/null 2>&1 || :
    ap_hand -f /var/lib/w33a/main.conf -k stop >/dev/null 2>&1 || :
    wait_until 60 sh -c '! ps -eo args= | grep -Eq "^/usr/sbin/(apache2|httpd)"' || :
    sed -e 's#conf-enabled/#w33a-none/#g' -e 's#conf\.d/#w33a-none/#g' "$APMAIN" > /var/lib/w33a/main.conf
    ap_hand -f /var/lib/w33a/main.conf -k start >/dev/null 2>&1 || :
    wait_until 60 master_of "/usr/sbin/$APX -f /var/lib/w33a/main.conf" || :
    : > "$RLC"; before=$(record $AP_TREES)
    out=$(keep srv_run) && rc=0 || rc=$?
    { [ "$rc" = 1 ] && says "$out" 'Apache: nothing was applied: the running parent reads /var/lib/w33a/main.conf (its -f), which includes nothing from ' \
      && [ "$(record $AP_TREES)" = "$before" ] && [ "$(reloads apache)" = 0 ]; } \
      && neg apache-apply "O5: a hand-started Apache whose -f configuration includes nothing of the layout's: refused, nothing written, no graceful, exit 1" \
      || fail "O5: a hand-started Apache with an unreachable include" "rc=$rc $(printf '%s' "$out" | grep -E 'Apache:' | head -3 | cut -c1-220)"
    ap_hand -f /var/lib/w33a/main.conf -k stop >/dev/null 2>&1 || :
    wait_until 60 sh -c '! ps -eo args= | grep -Eq "^/usr/sbin/(apache2|httpd)"' || :
    rm -rf /var/lib/w33a
    srv_teardown apache Apache
  fi
  # ---- OpenLiteSpeed: the module's word after the restart is the test; conf/ is written as its owner --
  SRVSEL=litespeed
  LSD=/usr/local/lsws
  if ! [ -x "$LSD/bin/lswsctrl" ] || ! [ -f "$LSD/modules/mod_whisper_edge.so" ]; then
    skip "the OpenLiteSpeed arm" "no OpenLiteSpeed with the module built from this tree at $LSD/modules (litespeed/build.sh --install on this disposable box first)"
    return 0
  fi
  feed 497775 normal
  begin_arm "OpenLiteSpeed" || return 0
  OCONF=$LSD/conf/httpd_config.conf; OU=$(stat -c %U "$LSD/conf")
  cp -p "$OCONF" "$W/ols.orig"
  ols_pid() { cat "$LSD/logs/httpd.pid" /tmp/lshttpd/lshttpd.pid 2>/dev/null | sed -n 1p; }
  ols_count() { ps -eo args= | awk '$0 == "openlitespeed (lshttpd - main)" || $0 == "litespeed" { n++ } END { print n + 0 }'; }
  # a restart the rows wait on by its outcome, never by a sleep: a main pid other than the one before,
  # and one main process (the handover over), within 90 s
  ols_restart_wait() {
    _op=$(ols_pid); "$LSD/bin/lswsctrl" restart >/dev/null 2>&1 || :
    _i=0; while [ "$_i" -lt 90 ]; do
      [ "$(ols_pid)" != "$_op" ] && [ "$(ols_count)" = 1 ] && kill -0 "$(ols_pid)" 2>/dev/null && return 0
      sleep 1; _i=$((_i + 1))
    done
    echo "  (OpenLiteSpeed did not settle on a new main within 90 s: pid $(ols_pid), $(ols_count) main(s))"
  }
  # lswsctrl reaches the running server: its status names a live pid that is the one main process
  ols_consistent() {
    _cp=$("$LSD/bin/lswsctrl" status 2>/dev/null | sed -n 's/.*running with PID \([0-9]\{1,\}\).*/\1/p')
    [ -n "$_cp" ] && [ "$(ols_count)" = 1 ] && [ "$(ps -o args= -p "$_cp" 2>/dev/null)" = "openlitespeed (lshttpd - main)" ]
  }
  # a fresh single server for the next row, whatever the last one left: stopped by lswsctrl, then every
  # OpenLiteSpeed process by its own pid, then started and waited for
  ols_reset() {
    "$LSD/bin/lswsctrl" stop >/dev/null 2>&1 || :
    for _p in $(ps -eo pid=,args= | awk '$2 == "openlitespeed" || ($2 == "litespeed" && NF == 2) { print $1 }'); do kill -TERM "$_p" 2>/dev/null || :; done
    wait_until 90 sh -c '[ -z "$(ps -eo args= | awk "/^openlitespeed/ || \$0 == \"litespeed\"")" ]' || :
    for _p in $(ps -eo pid=,args= | awk '$2 == "openlitespeed" || ($2 == "litespeed" && NF == 2) { print $1 }'); do kill -KILL "$_p" 2>/dev/null || :; done
    ols_start_wait
    wait_until 60 ols_consistent || echo "  (OpenLiteSpeed is not in one consistent state after a fresh start: $("$LSD/bin/lswsctrl" status 2>&1 | head -1))"
  }
  ols_clean() { # httpd_config.conf as before the rows, nothing of the installer's, one server running
    # the operator include a later row plants (OPI), named here whether or not that row has run yet
    runuser -u "$OU" -- rm -f "$LSD/conf/whisper-edge.conf" "$LSD/conf/operator-extra.conf"
    cmp -s "$OCONF" "$W/ols.orig" || runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/ols.orig"
    rm -f /etc/whisper-edge/undo/litespeed.facts /etc/whisper-edge/undo/httpd_config.conf.*
    ols_reset
  }
  ols_start_wait() {
    "$LSD/bin/lswsctrl" start >/dev/null 2>&1 || :
    _i=0; while [ "$_i" -lt 90 ]; do
      [ "$(ols_count)" = 1 ] && "$LSD/bin/lswsctrl" status 2>/dev/null | grep_any 'is running' && return 0
      sleep 1; _i=$((_i + 1))
    done
    echo "  (OpenLiteSpeed did not start within 90 s)"
  }
  # one OpenLiteSpeed, started here: any instance a package install or an earlier row left is stopped,
  # by lswsctrl and then by its own pids, so lswsctrl's pid file names the server the rows test
  "$LSD/bin/lswsctrl" stop >/dev/null 2>&1 || :
  for _p in $(ps -eo pid=,args= | awk '$2 == "openlitespeed" || ($2 == "litespeed" && NF == 2) { print $1 }'); do kill -TERM "$_p" 2>/dev/null || :; done
  _i=0; while [ "$_i" -lt 90 ] && [ -n "$(ps -eo args= | awk '/^openlitespeed/ || $0 == "litespeed"')" ]; do sleep 1; _i=$((_i + 1)); done
  ols_start_wait
  OL_TREES="$LSD/conf"
  srv_stock ols "$LSD/conf"
  before=$(record $OL_TREES)
  # OpenLiteSpeed's own copies (<file>0) and RCS histories (<file>0,v), which record leaves out: the set
  # before the install, for the undo row below
  ols_hist() { find "$LSD/conf" -type f \( -name '*0' -o -name '*0,v' \) 2>/dev/null | LC_ALL=C sort; }
  hist0=$(ols_hist)
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  after=$(record $OL_TREES)
  { [ "$rc" = 0 ] && [ -f "$LSD/conf/whisper-edge.conf" ] && grep -qxF "include $LSD/conf/whisper-edge.conf" "$OCONF" \
    && [ "$(stat -c %U "$LSD/conf/whisper-edge.conf")" = "$OU" ] && [ "$(stat -c %U "$OCONF")" = "$OU" ] \
    && says "$out" 'OpenLiteSpeed: confirmed by the module: worker pid .*, new since the reload, runs program' \
    && grep -qx '    ls_enabled 1' "$LSD/conf/whisper-edge.conf" && grep -qx '    whisper_edge_mode log' "$LSD/conf/whisper-edge.conf"; } \
    && pos_pass ols-apply "OpenLiteSpeed: whisper-edge.conf written and the include line added, both owned by $OU as before, the restart's status confirms the program, log mode (the positive control)" \
    || fail "OpenLiteSpeed: apply, restart, confirm" "rc=$rc
$(printf '%s\n' "$out" | sed -n '/^== applied/,$p' | head -40)"
  # A stock httpd_config.conf names no useIpInProxyHeader; a value other than an explicit 0 is not
  # trusted. The installer's file sets it to 0 at the top level and says so; then a request carrying an
  # X-Forwarded-For is logged as the socket's address, and no live writer carries client-ip-from-header,
  # so --status passes. The control is the same probe under an explicit useIpInProxyHeader 1, whose logged
  # address must not be the socket's, so the probe can tell the two apart.
  ols_xff_probe() { # -> the client address the server logged for a request carrying a spoofed X-Forwarded-For
    _xp="/whisper-edge-xff-$$-$(date +%s%N)"
    curl -s -o /dev/null --max-time 10 -H 'X-Forwarded-For: 203.0.113.9' "http://127.0.0.1:8088$_xp" || :
    _xa=""; _xi=0; while [ "$_xi" -lt 20 ] && [ -z "$_xa" ]; do
      _xa=$(cat "$LSD"/logs/access.log "$LSD"/Example/logs/access.log 2>/dev/null | grep -F " $_xp " | sed -n '$p' | cut -d' ' -f1)
      [ -n "$_xa" ] || sleep 0.5; _xi=$((_xi + 1)); done
    echo "${_xa:-none}"
  }
  ols_cw=$(grep -c '^useIpInProxyHeader 0$' "$LSD/conf/whisper-edge.conf" 2>/dev/null || :)
  ols_cl=$(grep -n '^useIpInProxyHeader 0$' "$LSD/conf/whisper-edge.conf" 2>/dev/null | cut -d: -f1); ols_cm=$(grep -n '^module mod_whisper_edge {' "$LSD/conf/whisper-edge.conf" 2>/dev/null | cut -d: -f1)
  { [ "$ols_cw" = 1 ] && [ -n "$ols_cm" ] && [ "${ols_cl:-0}" -lt "$ols_cm" ] \
    && says "$out" "OpenLiteSpeed: $OCONF names no useIpInProxyHeader, and the module trusts only an explicit 0, so $LSD/conf/whisper-edge.conf sets it to 0" \
    && says "$out" "Behind a real proxy or CDN, name its addresses with whisper_edge_trusted_proxy in the module block of $LSD/conf/whisper-edge.conf, .*leave useIpInProxyHeader at 0"; } \
    && neg ols-apply "OpenLiteSpeed on a stock httpd_config.conf (no useIpInProxyHeader): the installer's file sets useIpInProxyHeader 0 at its top level, above the module block, and the report says why and what to name behind a real proxy (whisper_edge_trusted_proxy)" \
    || fail "OpenLiteSpeed: the installer's useIpInProxyHeader 0" "lines: ${ols_cw:-0} at ${ols_cl:-none} (module at ${ols_cm:-none}); $(printf '%s\n' "$out" | grep -F useIpInProxyHeader | head -2 | cut -c1-240)"
  xa=$(ols_xff_probe)
  case "$xa" in 127.0.0.1|::1|::ffff:127.0.0.1) xok=1 ;; *) xok=0 ;; esac
  [ "$xok" = 1 ] && neg ols-apply "and a request spoofing X-Forwarded-For: 203.0.113.9 is logged by the server as its socket's address ($xa), the address the module judges" \
    || fail "OpenLiteSpeed: a spoofed X-Forwarded-For after the install" "the server logged $xa"
  await_c7() { _ss=$(/usr/local/sbin/whisper-edge-summary --status /var/lib/whisper-edge/counters 2>&1) && return 0; return 1; }
  wait_until 60 await_c7 || :
  ss=$(/usr/local/sbin/whisper-edge-summary --status /var/lib/whisper-edge/counters 2>&1) && src=0 || src=$?
  { [ "$src" = 0 ] && ! printf '%s\n' "$ss" | grep_any '^process .*client-ip-from-header'; } \
    && neg ols-apply "and whisper-edge-summary --status passes right after the install: no live writer carries client-ip-from-header" \
    || fail "OpenLiteSpeed: --status after a clean install" "exit $src: $(printf '%s\n' "$ss" | grep -E '^process |^live ' | head -3 | tr '\n' ';' | cut -c1-300)"
  # the printed undo line restores httpd_config.conf byte for byte, as its owner
  u=$(undo_of "$out" OpenLiteSpeed)
  if [ -z "$u" ]; then fail "OpenLiteSpeed: the undo line" "no 'undo, OpenLiteSpeed' line"
  else
    uo=$(eval "sh -c $u" 2>&1) && urc=0 || urc=$?
    { [ "$urc" = 0 ] && cmp -s "$OCONF" "$W/ols.orig" && [ ! -e "$LSD/conf/whisper-edge.conf" ] \
      && [ "$(record $OL_TREES)" = "$before" ]; } \
      && pass "OpenLiteSpeed: the printed undo line restores httpd_config.conf byte for byte (owner, mode, mtime) and removes the file" \
      || fail "OpenLiteSpeed: the undo line" "rc=$urc $uo $(printf '%s\n' "$before" > "$W/rec.b"; record $OL_TREES > "$W/rec.a"; diff "$W/rec.b" "$W/rec.a" | head -4)"
    # and nothing of the installer's is left in the server's own copies: the ones it made of the installer's
    # file are gone, its copy of httpd_config.conf is the restored bytes again (it copies the file only when
    # the file is newer than its copy, and the undo puts the old mtime back, so the undo gives the copy
    # those bytes itself), and every copy and history of the operator's files the install found is still there
    ols_ours_left() { find "$LSD/conf" -type f -exec grep -lE 'mod_whisper_edge|whisper_edge_' {} + 2>/dev/null | LC_ALL=C sort; }
    wait_until 60 sh -c "! grep -qF 'include $LSD/conf/whisper-edge.conf' '$LSD/conf/httpd_config.conf0' 2>/dev/null" || :
    left=$(ols_ours_left); miss=$(printf '%s\n' "$hist0" | while IFS= read -r h; do [ -z "$h" ] || [ -e "$h" ] || echo "$h"; done)
    { [ -z "$left" ] && [ ! -e "$LSD/conf/whisper-edge.conf0" ] && [ ! -e "$LSD/conf/whisper-edge.conf0,v" ] && [ -z "$miss" ] \
      && ! grep -qF "include $LSD/conf/whisper-edge.conf" "$LSD/conf/httpd_config.conf0" 2>/dev/null; } \
      && neg ols-apply "and nothing of the installer's is left under $LSD/conf: OpenLiteSpeed's copies of the installer's file (whisper-edge.conf0 and its history) are gone, its httpd_config.conf0 is the restored file, and the $(printf '%s\n' "$hist0" | grep -c .) copies and histories of the operator's files are all still there" \
      || fail "OpenLiteSpeed: the undo leaves something of the installer's" "files with our directives: ${left:-none}; operator copies gone: ${miss:-none}; our copies: $(ls "$LSD"/conf/whisper-edge.conf0* 2>/dev/null | tr '\n' ' '); httpd_config.conf0 $(grep -cF "include $LSD/conf/whisper-edge.conf" "$LSD/conf/httpd_config.conf0" 2>/dev/null || echo 0) include line(s), mtime $(stat -c %Y "$LSD/conf/httpd_config.conf0" 2>/dev/null) against httpd_config.conf's $(stat -c %Y "$OCONF" 2>/dev/null)"
  fi
  # the control: an explicit useIpInProxyHeader 1, restarted, and the same probe must log an address
  # other than the socket's; then the stock bytes back, with no restart of its own: the next row restarts on them (one
  # restart, as before this control existed, so the apply-after-undo row below is not handed a server
  # still settling from a second one)
  runuser -u "$OU" -- sh -c "sed -i '1i useIpInProxyHeader 1' '$OCONF'"; ols_reset; xa0=$(ols_xff_probe)
  [ "$xa0" = 203.0.113.9 ] && neg ols-apply "the control: under an explicit useIpInProxyHeader 1 the same request is logged as 203.0.113.9, not the socket's address, so the probe can see one" \
    || fail "the X-Forwarded-For probe's control" "under useIpInProxyHeader 1 the server logged $xa0, not 203.0.113.9"
  runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/ols.orig" || fail "the X-Forwarded-For probe's control" "httpd_config.conf could not be put back as its owner"
  # the operator's own value is theirs: 0 is kept and never repeated in the installer's file; any other is
  # refused before anything is written (a value other than an explicit 0 is not trusted)
  runuser -u "$OU" -- sh -c "sed -i '1i useIpInProxyHeader 0' '$OCONF'"; ols_reset
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ -f "$LSD/conf/whisper-edge.conf" ] && ! grep -q 'useIpInProxyHeader' "$LSD/conf/whisper-edge.conf" \
    && ! says "$out" 'names no useIpInProxyHeader'; } \
    && neg ols-apply "an operator's own useIpInProxyHeader 0 is kept: the installer's file carries none of its own, and the report says nothing of it" \
    || fail "OpenLiteSpeed: an operator's useIpInProxyHeader 0" "rc=$rc $(grep -n useIpInProxyHeader "$LSD/conf/whisper-edge.conf" 2>&1 | head -2 | tr '\n' ';')"
  u=$(undo_of "$out" OpenLiteSpeed); [ -n "$u" ] && eval "sh -c $u" >/dev/null 2>&1 || :
  ols_clean
  runuser -u "$OU" -- sh -c "sed -i '1i useIpInProxyHeader 2' '$OCONF'"; cp "$OCONF" "$W/ols.v2"; ols_reset
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  { [ "$rc" = 1 ] && says "$out" 'OpenLiteSpeed: nothing was applied: useIpInProxyHeader is 2 in .*, and the module trusts only an explicit 0' \
    && [ ! -e "$LSD/conf/whisper-edge.conf" ] && cmp -s "$OCONF" "$W/ols.v2"; } \
    && neg ols-apply "an operator's useIpInProxyHeader 2: refused, nothing written, exit 1 (a value other than an explicit 0 is not trusted)" \
    || fail "OpenLiteSpeed: an operator's useIpInProxyHeader 2" "rc=$rc $(printf '%s\n' "$out" | grep -E 'OpenLiteSpeed:' | head -2 | cut -c1-260)"
  ols_clean
  # W35, --arm-deny: on the installer's own file, after the module confirmed log mode, it re-renders in
  # deny and the module confirms again; a second one says already armed and restarts nothing; a plain
  # re-run keeps deny; with nginx or Apache named it is a usage error; on an operator-edited file it stops.
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  # the apply right after the undo line: the undo's restart is still handing over (the new main is titled
  # "litespeed" for its first seconds), and a restart sent into that leaves the half-started main's lscgid
  # with no parent. One server afterwards, and no lscgid of a server that is gone. Its control plants such
  # an orphan and the same check must name it.
  # an orphan is an lscgid whose parent is no OpenLiteSpeed main, not one whose parent is pid 1: on a box
  # where a subreaper (a container's init, a user manager) adopts orphans, the parent is that instead
  ols_orphans() { ps -eo pid=,ppid=,args= | awk '
    { pid[NR] = $1; pp[NR] = $2; a = $3; for (i = 4; i <= NF; i++) a = a " " $i; args[NR] = a
      if (a == "openlitespeed (lshttpd - main)" || a == "litespeed") main[$1] = 1 }
    END { for (i = 1; i <= NR; i++) if (args[i] ~ /^openlitespeed \(lscgid\)/ && !(pp[i] in main)) printf "%s ", pid[i] }'; }

  _i=0; while [ "$_i" -lt 60 ] && [ "$(ols_count)" != 1 ]; do sleep 1; _i=$((_i + 1)); done
  orph=$(ols_orphans); nm=$(ols_count)
  { [ "$rc" = 0 ] && [ "$nm" = 1 ] && [ -z "$orph" ]; } \
    && pos_pass ols-one "OpenLiteSpeed: the apply straight after the undo line: one main process, no lscgid left without its server" \
    || fail "OpenLiteSpeed: the apply straight after the undo line" "rc=$rc, $nm main processes, orphaned lscgid: ${orph:-none}
$(ps -eo pid=,ppid=,args= | awk '$3 == "openlitespeed" || ($3 == "litespeed" && NF == 3)')"
  # the stand-in is a bash renamed by exec -a, never sleep itself: on a coreutils-single box (Rocky 9's
  # container images) sleep picks its applet from argv[0] and, under another name, exits at once without
  # a word (measured in rockylinux:9-ubi-init, coreutils-single 8.32-40.el9). The
  # trailing ":" keeps bash from replacing itself with sleep, which would take the name with it.
  ( bash -c 'exec -a "openlitespeed (lscgid)" bash -c "sleep 60; :"' </dev/null >/dev/null 2>&1 & )
  _i=0; while [ "$_i" -lt 60 ] && [ -z "$(ols_orphans)" ]; do sleep 1; _i=$((_i + 1)); done
  plant=$(ols_orphans)
  [ -n "$plant" ] && neg ols-one "the control: a planted lscgid with no server (pid ${plant% }) is named by the same check" \
    || fail "the orphan control" "a planted orphan lscgid was not seen; what runs: $(ps -eo pid=,ppid=,args= | awk '/lscgid|sleep 60/ && !/awk/' | tr '\n' ';')"
  for _p in $plant; do
    for _c in $(ps -eo pid=,ppid= | awk -v p="$_p" '$2 == p { print $1 }'); do kill "$_c" 2>/dev/null || :; done
    kill "$_p" 2>/dev/null || :
  done
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_ARM_DENY=1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && grep -qx '    whisper_edge_mode deny' "$LSD/conf/whisper-edge.conf" && says "$out" 'OpenLiteSpeed: confirmed read-only' \
    && says "$out" 'OpenLiteSpeed: confirmed by the module: worker pid'; } \
    && neg ols-apply "W35: --arm-deny after the module confirmed log mode: deny written in the installer's own file, restarted, confirmed again" \
    || fail "W35: --arm-deny" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -4 | cut -c1-220)"
  m1=$(ols_pid)
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_ARM_DENY=1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" 'OpenLiteSpeed: already armed' && [ "$(ols_pid)" = "$m1" ]; } \
    && neg ols-apply "W35: a second --arm-deny: already armed, nothing changed, nothing restarted (main pid $m1 unchanged)" \
    || fail "W35: --arm-deny is idempotent" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -2)"
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  { grep -qx '    whisper_edge_mode deny' "$LSD/conf/whisper-edge.conf" && [ "$(ols_pid)" = "$m1" ]; } \
    && neg ols-apply "a plain re-run after --arm-deny keeps deny and restarts nothing" \
    || fail "a re-run keeps the armed mode" "$(grep mode "$LSD/conf/whisper-edge.conf")"
  out=$(env WHISPER_EDGE_SERVER=nginx WHISPER_EDGE_ARM_DENY=1 sh "$INSTALL" --base "$FEED" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 2 ] && says "$out" 'is for OpenLiteSpeed alone'; } && neg ols-apply "--arm-deny with nginx named: a usage error, exit 2" \
    || fail "--arm-deny with nginx is refused" "rc=$rc $(printf '%s' "$out" | head -1)"
  runuser -u "$OU" -- sh -c "sed -i 's/    whisper_edge_mode deny/    whisper_edge_mode log/' '$LSD/conf/whisper-edge.conf'; printf '    whisper_edge_allow_inferred on\n' >> '$LSD/conf/whisper-edge.conf'"
  fsum=$(sha256sum < "$LSD/conf/whisper-edge.conf")
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_ARM_DENY=1) && rc=0 || rc=$?
  { [ "$rc" = 1 ] && says "$out" "OpenLiteSpeed: --arm-deny changes only the installer's own" && [ "$(sha256sum < "$LSD/conf/whisper-edge.conf")" = "$fsum" ]; } \
    && neg ols-apply "W35: --arm-deny on a file the operator edited (allow_inferred on): stopped, the file unchanged" \
    || fail "W35: --arm-deny refuses an edited file" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -2)"
  runuser -u "$OU" -- rm -f "$LSD/conf/whisper-edge.conf"
  kept=$(sed -n 's/^kept //p' /etc/whisper-edge/undo/litespeed.facts 2>/dev/null || :)
  if [ -n "$kept" ] && [ -f "$kept" ]; then runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$kept"; fi
  rm -f /etc/whisper-edge/undo/litespeed.facts ${kept:+"$kept"}; ols_restart_wait
  # W30, the pasted undo line raced: the owner swaps httpd_config.conf for a link to a root-only canary;
  # the line must refuse and the canary must not change. Positive control first: a fresh apply.
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  u=$(undo_of "$out" OpenLiteSpeed)
  [ -n "$u" ] || fail "W30's positive control: a fresh apply printed an OpenLiteSpeed undo line" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -4) error log: $(grep -i 'whisper edge: policy: module loaded\|AutoRestarter\|SIGUSR1\|restart' "$LSD/logs/error.log" 2>/dev/null | tail -4)
     processes: $(ps -eo pid,lstart,args | grep '[l]shttpd' | tr -s ' ' | cut -c1-70 | tr '\n' ';')
     counters: $(ls -l --time-style=+%T /var/lib/whisper-edge/counters 2>/dev/null | awk 'NR > 1 { printf "%s %s; ", $6, $7 }')"
  CAN=/root/whisper-edge-canary; printf 'root only\n' > "$CAN"; chmod 0600 "$CAN"; csum=$(sha256sum < "$CAN")
  runuser -u "$OU" -- sh -c "mv -f '$OCONF' '$OCONF.real' && ln -s '$CAN' '$OCONF'"
  uo=$(eval "sh -c $u" 2>&1) && urc=0 || urc=$?
  { [ "$urc" != 0 ] && [ "$(sha256sum < "$CAN")" = "$csum" ] && [ "$(stat -c '%U %a' "$CAN")" = "root 600" ] && says "$uo" 'no longer the installer'; } \
    && neg ols-apply "W30: the pasted undo line against a link the owner planted: refused, the root-only canary unchanged" \
    || fail "W30: the undo line is not a root write through the owner's link" "rc=$urc $uo"
  # the negative control: the same race against a restore that copies by path as root changes the canary
  kept=$(sed -n 's/^kept //p' /etc/whisper-edge/undo/litespeed.facts 2>/dev/null)
  cp "$CAN" "$W/can.save"; cp "$kept" "$OCONF" 2>/dev/null
  [ "$(sha256sum < "$CAN")" != "$csum" ] \
    && pass "the control: a root cp by path through the same link overwrites the canary, so the row can fail" \
    || fail "W30's control" "the root cp did not reach the canary, so the row proves nothing"
  cp "$W/can.save" "$CAN"; rm -f "$OCONF"; runuser -u "$OU" -- mv -f "$OCONF.real" "$OCONF"
  eval "sh -c $u" >/dev/null 2>&1 || true
  # W30b, the restore failing: the owner's writer cannot make its temp (the directory is not writable for
  # its owner), so the pasted line must stop, keep the bytes from before the install and change nothing.
  # The same line run again once the directory is writable restores them: the positive half.
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  u=$(undo_of "$out" OpenLiteSpeed)
  kept=$(sed -n 's/^kept //p' /etc/whisper-edge/undo/litespeed.facts 2>/dev/null || :)
  if [ -z "$u" ] || [ -z "$kept" ] || [ ! -f "$kept" ]; then
    fail "W30b's apply" "rc=$rc, no undo line or no kept copy ($kept)"
  else
    ksum=$(sha256sum < "$kept"); csum=$(sha256sum < "$OCONF"); dmode=$(stat -c %a "$LSD/conf")
    chmod u-w "$LSD/conf"
    uo=$(eval "sh -c $u" 2>&1) && urc=0 || urc=$?
    chmod "$dmode" "$LSD/conf"
    { [ "$urc" != 0 ] && [ -f "$kept" ] && [ "$(sha256sum < "$kept")" = "$ksum" ] && [ "$(sha256sum < "$OCONF")" = "$csum" ] \
      && [ -f /etc/whisper-edge/undo/litespeed.facts ] && says "$uo" 'the restore did not complete (its writer ended 3)'; } \
      && neg ols-apply "W30b: the pasted undo line whose restore fails (no temp for the owner): stopped, exit $urc, the kept copy and httpd_config.conf unchanged" \
      || fail "W30b: a failed restore keeps the bytes from before the install" "rc=$urc kept: $([ -f "$kept" ] && echo present || echo GONE) $uo"
    uo=$(eval "sh -c $u" 2>&1) && urc=0 || urc=$?
    { [ "$urc" = 0 ] && [ "$(sha256sum < "$OCONF")" = "$ksum" ] && [ ! -e "$kept" ]; } \
      && pass "W30b: the same line, once the directory is writable again, restores the kept bytes and only then removes them" \
      || fail "W30b: the line restores after the fault is gone" "rc=$urc $uo"
  fi
  # R1's residual: INT after the restart and before the verdict; the line names the running server's state
  pause_arm
  srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-restart > "$W/oint.out" 2> "$W/oint.out.err" &
  ipid=$!
  if pause_wait after-restart "$ipid"; then
    spid=$(pgrep -P "$ipid" -x sh || echo "$ipid")
    kill -TERM "$spid" 2>/dev/null; pause_release
  fi
  bg_wait "$ipid" && irc=0 || irc=$?
  collect_err "$W/oint.out"
  { [ "$irc" = 143 ] && says "$(cat "$W/oint.out")" 'OpenLiteSpeed: interrupted after writing .*(TERM); removed; the previous configuration is back on disk; the running server may still be on the edit until its next restart: .*/bin/lswsctrl restart' \
    && cmp -s "$OCONF" "$W/ols.orig"; } \
    && neg ols-apply "OpenLiteSpeed: TERM after the restart and before the verdict: the edit taken back byte for byte, and the line says the running server may still be on it until its next restart, with the command (exit 143)" \
    || fail "OpenLiteSpeed: INT in the window" "rc=$irc $(grep -E 'OpenLiteSpeed' "$W/oint.out" | head -3)"
  pause_done
  # W24: a refusal only the module can make, planted after the installer's own checks. At the pause after
  # layer 1, an operator include (there before the run, so layer 1 passed it) gains a trusted_hops one past
  # the merged module's own range, read from its header, so the arm moves with the module. The module
  # refuses the configuration at the restart and keeps serving; its own error-log line corroborates the
  # status, so the installer takes its edit back and restarts once more.
  hmax=$(sed -n 's/^#define WE_MOD_HOPS_MAX[[:space:]]*\([0-9]*\)u.*/\1/p' "$HERE/../core/we_module.h")
  OPI=$LSD/conf/operator-extra.conf
  runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"
  before=$(record $OL_TREES | grep -v "^$OPI ")
  pause_arm
  srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-layer1 > "$W/orf.out" 2> "$W/orf.out.err" &
  ipid=$!
  if pause_wait after-layer1 "$ipid"; then
    runuser -u "$OU" -- sh -c "printf 'module mod_whisper_edge {\n    whisper_edge_trusted_hops %s\n}\n' '$((hmax + 1))' >> '$OPI'"
    pause_release
  fi
  bg_wait "$ipid" && orc=0 || orc=$?
  collect_err "$W/orf.out"
  # after the refusal, the restore and its restart, lswsctrl must still reach the server the installer
  # left running (a pid file naming a gone process leaves the next run, and the operator, no way to it)
  if wait_until 60 ols_consistent; then pass "W24: after the refusal and the restore's restart, lswsctrl reaches the one running server"
  else fail "W24: the server the restore left is reachable by lswsctrl" "status: $("$LSD/bin/lswsctrl" status 2>&1 | head -1); mains: $(ps -eo pid=,args= | awk '$2 == "openlitespeed" && $5 == "main)" || ($2 == "litespeed" && NF == 2) { printf "%s ", $1 }')"; fi
  { [ -n "$hmax" ] && [ "$orc" = 1 ] && says "$(cat "$W/orf.out")" "OpenLiteSpeed: .*trusted_hops.*takes 1 to $hmax.*; removed what this run wrote" \
    && [ "$(record $OL_TREES | grep -v "^$OPI ")" = "$before" ]; } \
    && neg ols-apply "W24: trusted_hops $((hmax + 1)) (one past the module's 1..$hmax) planted after layer 1: the module refused it at the restart, its own error-log line names the range, the edit taken back, the record unchanged" \
    || fail "W24: the module's refusal after the restart" "rc=$orc hmax=${hmax:-none} $(grep -E 'OpenLiteSpeed' "$W/orf.out" | head -6)
     error log: $(grep -i 'whisper' "$LSD/logs/error.log" 2>/dev/null | tail -4)
     status: $("$LSD/bin/lswsctrl" status 2>&1 | head -1)"
  runuser -u "$OU" -- sh -c "rm -f '$OPI'"; { grep -vxF "include $OPI" "$OCONF" > "$W/oc" || :; runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/oc" || fail "httpd_config.conf put back as its owner" "the write failed"; }
  pause_done
  # W24b, the same refusal with the error log saying nothing about it (the log truncated between the
  # restart and the verdict, as a rotation would leave it; OpenLiteSpeed refuses a log that is a link, so
  # the log stays a plain file). Measured: a configuration the module refuses at load leaves no worker
  # writing and no status file, so the log was the only word. With it gone the installer cannot tell a
  # refusal from a module that did not load; it must keep the configuration, say both and where to look,
  # exit 3, and leave its undo line able to take the edit back.
  ols_clean
  runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"
  ols_reset
  before=$(record $OL_TREES | grep -v "^$OPI ")
  pause_arm
  srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-layer1+after-restart > "$W/orf2.out" 2> "$W/orf2.out.err" &
  ipid=$!
  if pause_wait after-layer1 "$ipid"; then
    runuser -u "$OU" -- sh -c "printf 'module mod_whisper_edge {\n    whisper_edge_trusted_hops %s\n}\n' '$((hmax + 1))' >> '$OPI'"
    pause_release
  fi
  if pause_wait after-restart "$ipid"; then : > "$LSD/logs/error.log"; pause_release; fi
  bg_wait "$ipid" && orc=0 || orc=$?
  collect_err "$W/orf2.out"
  u=$(undo_of "$(cat "$W/orf2.out")" OpenLiteSpeed)
  uo=$( [ -n "$u" ] && eval "sh -c $u" 2>&1) && urc=0 || urc=$?
  { [ "$orc" = 3 ] && says "$(cat "$W/orf2.out")" "OpenLiteSpeed: serving, but the module wrote no status for this configuration and the error log since the restart names no refusal: it did not load, or it refused the configuration where this run could not read it" \
    && [ -n "$u" ] && [ "$urc" = 0 ] && [ "$(record $OL_TREES | grep -v "^$OPI ")" = "$before" ]; } \
    && neg ols-apply "W24b: the module's refusal with the error log silent (truncated after the restart): no status exists to read, so the configuration is kept with both causes named, exit 3, and its printed undo line restores the record" \
    || fail "W24b: a refusal the log does not show" "rc=$orc $(grep -E 'OpenLiteSpeed: [^n]' "$W/orf2.out" | grep -v LimitMEMLOCK | head -6 | cut -c1-300)"
  pause_done
  runuser -u "$OU" -- sh -c "rm -f '$OPI'"; { grep -vxF "include $OPI" "$OCONF" > "$W/oc" || :; runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/oc" || fail "httpd_config.conf put back as its owner" "the write failed"; }
  ols_restart_wait
  # W20 for OpenLiteSpeed's edit: SIGKILL at each point after httpd_config.conf is edited. The next run's
  # sweep (here a --no-apply run, which writes no server file, the case a dangling include would outlive)
  # must put httpd_config.conf back byte for byte from the kept copy and remove the included file, so no
  # include is left naming a file that is gone. Each kill is proved to have landed after the edit.
  for kp in after-include-line after-restart-before-verdict after-restart-before-restore; do
    ols_clean
    cmp -s "$OCONF" "$W/ols.orig" || fail "W20 $kp: the starting point" "httpd_config.conf is not the original before the row"
    kenv=""
    if [ "$kp" = after-restart-before-restore ]; then
      # the restore point is reached only on a refusal: W24's planted trusted_hops, once more
      runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"
      cp "$OCONF" "$W/ols.kp"; pause_arm; kenv="WHISPER_EDGE_INSTALL_TEST_PAUSE=after-layer1"
    else cp "$OCONF" "$W/ols.kp"; fi
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_KILL="$kp" $kenv > "$W/okill.out" 2>&1 &
    ipid=$!
    if [ -n "$kenv" ] && pause_wait after-layer1 "$ipid"; then
      runuser -u "$OU" -- sh -c "printf 'module mod_whisper_edge {\n    whisper_edge_trusted_hops %s\n}\n' '$((hmax + 1))' >> '$OPI'"
      pause_release
    fi
    bg_wait "$ipid" && krc=0 || krc=$?
    [ -n "$kenv" ] && pause_done
    landed=0; grep -qxF "include $LSD/conf/whisper-edge.conf" "$OCONF" && landed=1
    out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_NO_APPLY=1) && rc=0 || rc=$?
    leftover=$(find /etc/whisper-edge/undo -maxdepth 1 \( -name 'httpd_config.conf.*' -o -name 'litespeed.facts' -o -name 'run.*' \) 2>/dev/null | tr '\n' ' ')
    { [ "$krc" = 137 ] && [ "$landed" = 1 ] && cmp -s "$OCONF" "$W/ols.kp" && [ ! -e "$LSD/conf/whisper-edge.conf" ] \
      && says "$out" "restored $OCONF from the copy the interrupted run kept" && [ -z "$leftover" ]; } \
      && neg ols-apply "W20 $kp: SIGKILL there, then a --no-apply run: httpd_config.conf back byte for byte from the kept copy, the included file removed, nothing left in the undo directory" \
      || fail "W20 $kp: the sweep takes the edit back" "kill rc=$krc landed=$landed rc=$rc left: ${leftover:-nothing} $(printf '%s' "$out" | grep -E 'restored|kept|recovered' | head -3)
     $(diff "$W/ols.kp" "$OCONF" 2>&1 | head -4)"
    if [ -n "$kenv" ]; then runuser -u "$OU" -- sh -c "rm -f '$OPI'"; { grep -vxF "include $OPI" "$OCONF" > "$W/oc" || :; runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/oc" || fail "httpd_config.conf put back as its owner" "the write failed"; }; fi
    cp "$W/ols.orig" "$W/oc"; cmp -s "$OCONF" "$W/ols.orig" || runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/oc"
    ols_reset
  done
  # W18 for OpenLiteSpeed: the operator's own module block, with a rule of their own, is kept; nothing is
  # written or restarted, and the read-only verdict takes the program their worker reports (exit 0)
  OWNB=$LSD/conf/operator-whisper.conf; plane_at 497785 /var/lib/w18p/rep.bin; se_operator_label /var/lib/w18p/rep.bin
  runuser -u "$OU" -- sh -c "printf 'module mod_whisper_edge {\n    ls_enabled 1\n    whisper_edge_data /var/lib/whisper-edge\n    whisper_edge_data reputation /var/lib/w18p/rep.bin\n    whisper_edge_summary /var/lib/whisper-edge/counters\n    whisper_edge_policy log if listed >= high\n}\n' > '$OWNB' && printf 'include %s\n' '$OWNB' >> '$OCONF'"
  ols_reset
  m1=$(ols_pid); before=$(record $OL_TREES)
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" "OpenLiteSpeed: your module mod_whisper_edge block ($OWNB) is kept; nothing was written" \
    && says "$out" 'OpenLiteSpeed: confirmed read-only (nothing changed, so nothing was reloaded): a live worker runs program [0-9a-f]\{16\}, reputation armed at generation 497785' \
    && [ "$(ols_pid)" = "$m1" ] && [ "$(record $OL_TREES)" = "$before" ]; } \
    && neg ols-apply "W18: the operator's own OpenLiteSpeed block (a rule of theirs, and reputation's own file at generation 497785) kept: nothing written or restarted, the program their worker reports confirmed read-only, exit 0" \
    || fail "W18: a kept OpenLiteSpeed block" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -4 | cut -c1-250)"
  runuser -u "$OU" -- rm -f "$OWNB"; { grep -vxF "include $OWNB" "$OCONF" > "$W/oc" || :; runuser -u "$OU" -- sh -c "cat > '$OCONF'" < "$W/oc" || fail "httpd_config.conf put back as its owner" "the write failed"; }
  rm -rf /var/lib/w18p; ols_reset
  # O7, OpenLiteSpeed's other states, each from a clean single instance and put back after
  ols_two() { # <plant at after-layer1> <plant at after-restart>: one run paused at both points
    pause_arm
    srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-layer1+after-restart > "$W/two.out" 2> "$W/two.out.err" &
    _tp=$!
    if pause_wait after-layer1 "$_tp"; then eval "$1"; pause_release; fi
    if pause_wait after-restart "$_tp"; then eval "$2"; pause_release; fi
    bg_wait "$_tp" && trc=0 || trc=$?
    pause_done; collect_err "$W/two.out"
  }
  PLANT_HOPS="runuser -u '$OU' -- sh -c \"printf 'module mod_whisper_edge {\\\\n    whisper_edge_trusted_hops %s\\\\n}\\\\n' '$((hmax + 1))' >> '$OPI'\""
  # a stopped server: the included file is written, httpd_config.conf is not, and the lines are printed
  ols_clean; "$LSD/bin/lswsctrl" stop >/dev/null 2>&1 || :
  wait_until 90 sh -c '! ps -eo args= | grep -q "^openlitespeed (lshttpd - main)$"' || :
  out=$(keep srv_run WHISPER_EDGE_LSWS_ROOT="$LSD") && rc=0 || rc=$?
  { [ "$rc" = 0 ] && says "$out" "OpenLiteSpeed: the server is not running, so its configuration is not changed: add these lines to $OCONF" \
    && cmp -s "$OCONF" "$W/ols.orig" && [ -f "$LSD/conf/whisper-edge.conf" ]; } \
    && neg ols-apply "O7, a stopped OpenLiteSpeed: the included file written, httpd_config.conf unchanged, the include lines printed to add" \
    || fail "O7: a stopped OpenLiteSpeed" "rc=$rc $(printf '%s' "$out" | grep -E 'OpenLiteSpeed:' | head -3 | cut -c1-220)"
  ols_start_wait; ols_clean
  # a WebAdmin save inside the window: the module refuses (W24's plant) and, before the verdict, the file
  # is saved again by its owner; nothing is taken back over that save, the diff is named, exit 3
  runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"; ols_reset
  ols_two "$PLANT_HOPS" "runuser -u '$OU' -- sh -c \"printf '# saved by WebAdmin\\\\n' >> '$OCONF'\""
  { [ "$trc" = 3 ] && says "$(cat "$W/two.out")" "OpenLiteSpeed: .*$OCONF changed after this run edited it, so nothing was taken back or restarted; .*compare: diff " \
    && grep -qx '# saved by WebAdmin' "$OCONF" && grep -qxF "include $LSD/conf/whisper-edge.conf" "$OCONF" && [ -f "$LSD/conf/whisper-edge.conf" ]; } \
    && neg ols-apply "O7, a WebAdmin save between the restart and the verdict: nothing taken back over it (the include and its file both kept), the diff named, exit 3" \
    || fail "O7: a save inside the window" "rc=$trc $(grep -E 'OpenLiteSpeed:' "$W/two.out" | head -4 | cut -c1-250)"
  ols_clean
  # up with no writer: the counters directory closed to the worker after layer 1, so the module serves and
  # writes no status; the configuration is kept, said, exit 3, and there is no second restart
  cmode=$(stat -c %a /var/lib/whisper-edge/counters); cacl=$(getfacl -p /var/lib/whisper-edge/counters 2>/dev/null || :)
  pause_arm
  srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-layer1 > "$W/nw.out" 2> "$W/nw.out.err" &
  ipid=$!
  if pause_wait after-layer1 "$ipid"; then chmod 0700 /var/lib/whisper-edge/counters; setfacl -b /var/lib/whisper-edge/counters 2>/dev/null || :; pause_release; fi
  bg_wait "$ipid" && nrc=0 || nrc=$?
  pause_done; collect_err "$W/nw.out"
  m2=$(ols_pid)
  { [ "$nrc" = 3 ] && says "$(cat "$W/nw.out")" 'OpenLiteSpeed: serving, but the module wrote no status for this configuration and the error log since the restart names no refusal: .*the configuration is kept' \
    && [ "$(grep -c 'OpenLiteSpeed: restarted' "$W/nw.out")" = 1 ] && grep -qxF "include $LSD/conf/whisper-edge.conf" "$OCONF"; } \
    && neg ols-apply "O7, up with no writer (the counters closed to the worker): the configuration kept, said, one restart only (main pid $m2), exit 3" \
    || fail "O7: up with no writer" "rc=$nrc $(grep -E 'OpenLiteSpeed:' "$W/nw.out" | head -4 | cut -c1-250)"
  chmod "$cmode" /var/lib/whisper-edge/counters
  # the worker's grant on the counters goes back too (setfacl -b took it), or every later row has no writer
  if [ -n "$cacl" ]; then printf '%s\n' "$cacl" | setfacl --restore=- 2>/dev/null || :; fi
  ols_clean
  # a forged refusal: between the restart and the verdict every conf status is replaced by one saying
  # "refused", owned by an account that is not the worker. It is never read: nothing is taken back and
  # the forged words appear nowhere. (The module writes a conf status once, so the forgery also keeps
  # the confirmation from coming: the run reads unverified, exit 3, and keeps the configuration.)
  id wforge >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin wforge 2>/dev/null || useradd -r -M wforge
  pause_arm
  srv_run INSTALLER_GATE_DISPOSABLE=1 WHISPER_EDGE_LSWS_ROOT="$LSD" WHISPER_EDGE_INSTALL_TEST_PAUSE=after-restart > "$W/fr.out" 2> "$W/fr.out.err" &
  ipid=$!
  if pause_wait after-restart "$ipid"; then
    for _cf in /var/lib/whisper-edge/counters/conf-*.status; do
      [ -f "$_cf" ] || continue
      printf 'whisper-edge-status 2\nrefused forged by another account\n' > "$_cf.f"; chown wforge "$_cf.f"; chmod 0644 "$_cf.f"; mv -f "$_cf.f" "$_cf"
    done
    pause_release
  fi
  bg_wait "$ipid" && frc=0 || frc=$?
  pause_done; collect_err "$W/fr.out"
  { [ "$frc" = 3 ] && ! grep -q 'forged by another account\|removed what this run wrote' "$W/fr.out" \
    && grep -qxF "include $LSD/conf/whisper-edge.conf" "$OCONF" && [ -f "$LSD/conf/whisper-edge.conf" ]; } \
    && neg ols-apply "O7, a forged refusal (the conf status replaced by another account's): never read, nothing taken back, the configuration kept, exit 3" \
    || fail "O7: a forged refusal" "rc=$frc $(grep -E 'OpenLiteSpeed:' "$W/fr.out" | head -4 | cut -c1-250)"
  u=$(undo_of "$(cat "$W/fr.out")" OpenLiteSpeed); [ -n "$u" ] && eval "sh -c $u" >/dev/null 2>&1 || :
  ols_clean
  # not back: the server stopped between the restart and the verdict (measured: making the binary
  # unrunnable at layer 1 does not do it, because OpenLiteSpeed's own restarter brings a main back once it
  # can, which then wrote no status); the edit is taken back and the restart serves the previous
  # configuration (exit 1). The restore's restart failing: the binary made unrunnable after layer 1 and
  # left so; the edit is still taken back, and the run says OpenLiteSpeed did not start (exit 5).
  OBIN=$(readlink -f "/proc/$(ols_pid)/exe" 2>/dev/null || :)
  if [ -n "$OBIN" ] && [ -f "$OBIN" ]; then
    omode=$(stat -c %a "$OBIN")
    runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"; ols_reset; cp "$OCONF" "$W/ols.kp"
    ols_two ":" "'$LSD/bin/lswsctrl' stop >/dev/null 2>&1; wait_until 90 sh -c '! ps -eo args= | grep -q \"^openlitespeed (lshttpd - main)\$\"' || :"
    { [ "$trc" = 1 ] && says "$(cat "$W/two.out")" 'OpenLiteSpeed: the server did not come back after the restart; removed what this run wrote' && cmp -s "$OCONF" "$W/ols.kp"; } \
      && neg ols-apply "O7, not back after the restart: the edit taken back byte for byte, restarted, the previous configuration serving, exit 1" \
      || fail "O7: not back" "rc=$trc $(grep -E 'OpenLiteSpeed: [^n]' "$W/two.out" | grep -v LimitMEMLOCK | head -5 | cut -c1-250)
     status: $("$LSD/bin/lswsctrl" status 2>&1 | head -1); processes: $(ps -eo pid=,ppid=,args= | awk '$3 == "openlitespeed" || $3 == "litespeed"' | tr '\n' ';' | cut -c1-300)
     counters: $(ls -la /var/lib/whisper-edge/counters 2>&1 | head -4 | tr '\n' ';'); acl: $(getfacl -p /var/lib/whisper-edge/counters 2>/dev/null | tr '\n' ';')"
    ols_clean
    runuser -u "$OU" -- sh -c "printf '# an operator include\n' > '$OPI' && printf 'include %s\n' '$OPI' >> '$OCONF'"; ols_reset; cp "$OCONF" "$W/ols.kp"
    ols_two "chmod a-x '$OBIN'" ":"
    chmod "$omode" "$OBIN"
    { [ "$trc" = 5 ] && says "$(cat "$W/two.out")" "OpenLiteSpeed: restored $OCONF byte-identical; OpenLiteSpeed did not start; it was serving before this run; run: $LSD/bin/lswsctrl start" && cmp -s "$OCONF" "$W/ols.kp"; } \
      && neg ols-apply "O7, the restore's restart failing: the edit taken back byte for byte, OpenLiteSpeed said not to have started, with the command, exit 5" \
      || fail "O7: the restore's restart failing" "rc=$trc $(grep -E 'OpenLiteSpeed:' "$W/two.out" | head -4 | cut -c1-250)"
    ols_clean
  else
    fail "O7: not back" "the running server's binary could not be read from /proc"
  fi
  "$LSD/bin/lswsctrl" stop >/dev/null 2>&1
  srv_teardown ols OpenLiteSpeed
}
row server && { if [ "$REAL_OK" = 1 ]; then server_rows; else skip "the server rows" "they need root on a disposable box"; fi; }

# W14: every line of every report this run saw has a shape the installer chose
if [ -s "$W/reports" ]; then
  echo "--- every line of every report above"
  st=$(stray_line "$W/reports")
  [ -z "$st" ] \
    && pass "every one of the $(grep -c '' "$W/reports") report lines this run saw matches a shape the installer chose; no child's raw line got through" \
    || fail "a report line matches no shape" "$st"
  # the installer's path refusals, as its stop renders them (measured on GitHub's runner, whose /opt is 0777
  # with default ACLs: a real operator's host can have the same), are shapes the installer chose
  printf '%s\n' "   /opt/w25, the directory above /opt/w25/edge, is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others); name a data directory under one that is" \
    "   /var/lib/whisper-edge is not root's alone (owned by another account, a link, or writable by a group or others)" \
    "   /usr/local/sbin is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others); the refresh is not installed there" \
    "   /etc/whisper-edge is a symbolic link; the installer's own directories must be real directories owned by root" > "$W/refusals"
  st=$(stray_line "$W/refusals")
  [ -z "$st" ] && pass "the installer's path refusals (a data directory's parent, the data directory, sbin, a linked directory of its own) each match a shape the installer chose" \
    || fail "a path refusal matches no shape" "$st"
  for planted in 'installed reputation.bin (generation 1, 40 bytes, digest16 0123456789abcdef, valid until no bound) - the module picks it up on its own timer' \
                 'whisper-edge-refresh: could not fetch manifest.json' 'curl: (7) Failed to connect' '   a stray line under the report prefix'; do
    { cat "$W/reports"; printf '%s\n' "$planted"; } > "$W/reports.planted"
    [ -n "$(stray_line "$W/reports.planted")" ] \
      && pass "the control: a planted stray line is caught ($(printf '%s' "$planted" | cut -c1-40)...)" \
      || fail "the stray-line control" "a planted line passed: $planted"
  done
fi

# W14c: no refusal or report line has an empty reason ("fails its own test before any change: ; nothing was
# written" on RHEL, where the test's only line named no error); the controls are planted ones
if [ -s "$W/reports" ]; then
  er=$(empty_reason "$W/reports")
  [ -z "$er" ] && pass "no report line of this run's carries an empty reason (a colon or parentheses with nothing in them)" \
    || fail "a report line carries an empty reason" "$er"
  for planted in '   Apache: your configuration fails its own test before any change: ; nothing was written' '   nginx: reload failed (): ' '   OpenLiteSpeed: the restart failed: .'; do
    { cat "$W/reports"; printf '%s\n' "$planted"; } > "$W/reports.er"
    [ -n "$(empty_reason "$W/reports.er")" ] && pass "the control: a planted empty reason is caught ($(printf '%s' "$planted" | cut -c4-50)...)" \
      || fail "the empty-reason control" "a planted line passed: $planted"
  done
fi

# W14b: the installer's stderr carries only its own lines (install.sh: ...), never a child's
if [ -f "$W/stderr" ]; then
  echo "--- every line the installer wrote to stderr above"
  se=$(stray_err "$W/stderr")
  [ -z "$se" ] \
    && pass "every one of the $(grep -c '' "$W/stderr") stderr lines this run's installers wrote is the installer's own (install.sh: ...); no child's warning or error reached it" \
    || fail "the installer's stderr carries a line it did not write" "$se"
  for planted in "awk: cmd. line:1: warning: escape sequence \`\\.' treated as plain \`.'" '  indented: a child line under the report prefix' 'semanage: no such file context'; do
    { cat "$W/stderr"; printf '%s\n' "$planted"; } > "$W/stderr.planted"
    [ -n "$(stray_err "$W/stderr.planted")" ] \
      && pass "the control: a planted stray stderr line is caught ($(printf '%s' "$planted" | cut -c1-40)...)" \
      || fail "the stray-stderr control" "a planted line passed: $planted"
  done
fi

VERDICT=1
printf '\n=== installer gate: %d ok, %d failed ===\n' "$ok" "$bad"
[ -n "$SKIPPED" ] && printf 'SKIPPED, and not counted as passing: %s\n' "$SKIPPED"
if [ "$bad" -ne 0 ]; then echo "INSTALLER GATE: FAILED"; exit 1; fi
if [ -n "$SKIPPED" ]; then
  if [ -n "${INSTALLER_GATE_HOST_IMPOSSIBLE:-}" ]; then
    if unlisted=$(skip_verdict "$SKIPNAMES" "$INSTALLER_GATE_HOST_IMPOSSIBLE"); then
      echo "INSTALLER GATE: CLEAR on this host - every row that did not run is one the host cannot run, each listed with its reason in $(basename "$INSTALLER_GATE_HOST_IMPOSSIBLE"):"
      allow_report "$SKIPNAMES" "$INSTALLER_GATE_HOST_IMPOSSIBLE"
      exit 0
    fi
    echo "INSTALLER GATE: FAILED - rows did not run that this host could run (not on $(basename "$INSTALLER_GATE_HOST_IMPOSSIBLE")): $unlisted"
    exit 1
  fi
  echo "INSTALLER GATE: INCOMPLETE - everything that ran passed, but part of the gate could not run here"; exit 77
fi
echo "INSTALLER GATE: CLEAR"
