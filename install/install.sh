#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Install the Whisper edge on this host: the signed feed and its refresh, the default policy, and a
# server configuration that is tested before anything reloads.
#
# One command. It works in five stages, in this order, and stops an arm rather than guess:
#
#   detected  which servers are here, where each one's module is, whether it is loaded and running
#   armed     the planes the default policy reads, fetched and verified BEFORE any configuration test,
#             each one's state said in plain words: armed, or why its rule is inert
#   applied   the files it wrote, each new file marked as the installer's own by a digest on its first
#             line; nothing it cannot name is ever overwritten
#   proved    the server's own configuration test, and a reload only after a pass; a refused
#             configuration is removed again and the previous one keeps serving
#   undo      the lines that take it back, one per server and then one for the shared parts
#
# and the last line it prints is what to watch. The default policy denies only on a cited listing; it
# logs Tor exits and unreachable routes rather than blocking them, and the pinned text is in
# /etc/whisper-edge/policy.conf to read and edit.
#
# Usage: sudo ./install.sh [--dir DIR] [--base URL --key-sha256 HEX] [--server nginx|apache|litespeed]
#                          [--no-apply] [--named-conf FILE] [--no-timer] [--dry-run] [--arm-deny]
#
#   --dir DIR      where the planes live (default /var/lib/whisper-edge)
#   --base URL     the feed (default https://whisper.online/edge)
#   --key-sha256 H the sha256 of the feed's signing key; needed with any --base but the default, whose
#                  key is pinned in this script
#   --server S     apply to that server only (default: every server found); a comma list is fine
#   --no-apply     install the feed and its refresh, and print the blocks to paste instead of applying
#   --named-conf F the named.conf the resolver half reads (default: the one named-checkconf reads)
#   --no-timer     schedule nothing
#   --dry-run      fetch and verify, say what it would do, and write nothing anywhere (no root needed)
#   --arm-deny     OpenLiteSpeed only: turn the installer's policy there from log to deny, after the module
#                  has confirmed it in log mode (nginx and Apache deny from the start; their configuration
#                  test proves it first)
#   -h, --help     this text
#
# Exit codes:
#   (when arms end differently, one code stands for the run, 5 over 1 over 3 over 0; each arm's own
#   line in the report says how that arm ended)
#   0              applied (or your own policy kept) and confirmed by the module, or nothing to change
#   1              a server was not applied: refused, stopped, or its configuration failed its own test
#                  before any change; its previous configuration is unchanged (its line says which)
#   2              usage: an option or a value this script does not take
#   3              applied and serving, but the deny is not armed: the module did not confirm it in time,
#                  it reported the plane refused or unreadable, or a reload did not return
#   4              interrupted after writing a server's configuration and before its test passed; this
#                  run's writes were taken back
#   5              OpenLiteSpeed: restoring its configuration did not bring it back up
#   129, 130, 143  ended by HUP, INT or TERM; this run's server writes were taken back
#
# Each option has an environment twin: WHISPER_EDGE_DIR, WHISPER_EDGE_BASE, WHISPER_EDGE_SERVER,
# WHISPER_EDGE_NO_APPLY=1, WHISPER_EDGE_NAMED_CONF, WHISPER_EDGE_NO_TIMER=1, WHISPER_EDGE_DRY_RUN=1,
# WHISPER_EDGE_KEY_SHA256, WHISPER_EDGE_ARM_DENY=1.
# Functions reached only through the EXIT trap or passed by name to write_artifact read as unreachable
# to shellcheck, and the word splitting of `set -- $(cadence_of ...)` and `set -- $verdict` is meant.
# shellcheck disable=SC2317,SC2046,SC2086
set -eu
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }
umask 022

BASE="${WHISPER_EDGE_BASE:-https://whisper.online/edge}"
DIR="${WHISPER_EDGE_DIR:-/var/lib/whisper-edge}"
ETC="${WHISPER_EDGE_ETC:-/etc/whisper-edge}"
SBIN="${WHISPER_EDGE_SBIN:-/usr/local/sbin}"
UNITDIR="${WHISPER_EDGE_UNITDIR:-/etc/systemd/system}"
# The OpenLiteSpeed server root the probe reads, and the hardlink sysctl it reads: both have a twin so a
# test can name another, the way WHISPER_EDGE_UNITDIR names another unit directory.
LSWS="${WHISPER_EDGE_LSWS_ROOT:-/usr/local/lsws}"
HARDLINKS="${WHISPER_EDGE_PROTECTED_HARDLINKS:-/proc/sys/fs/protected_hardlinks}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TIMER=1; [ "${WHISPER_EDGE_NO_TIMER:-0}" = 1 ] && TIMER=0
DRY=0;   [ "${WHISPER_EDGE_DRY_RUN:-0}" = 1 ] && DRY=1
DRY_FAIL=0
NOAPPLY=0; [ "${WHISPER_EDGE_NO_APPLY:-0}" = 1 ] && NOAPPLY=1
ARM_DENY=0; [ "${WHISPER_EDGE_ARM_DENY:-0}" = 1 ] && ARM_DENY=1
NAMED_CONF="${WHISPER_EDGE_NAMED_CONF:-}"
SCOPE="${WHISPER_EDGE_SERVER:-}"
KEY_SHA="${WHISPER_EDGE_KEY_SHA256:-}"
# The default feed's signing key, pinned: the sha256 of the key https://whisper.online/edge/ serves. A key
# fetched from the feed is trusted only when it hashes to this, so the feed cannot vouch for itself. Rotating the key is a change to this line (the release playbook says so).
DEFAULT_BASE=https://whisper.online/edge
DEFAULT_KEY_SHA=7d21a0f4b234f514d1a55c6b9fa87c4203dba4b76797b45979058c7219cffe01
# whether the directory was named by the operator, which a kept binding elsewhere must not contradict
# shellcheck disable=SC2034
DIR_GIVEN=0; [ -n "${WHISPER_EDGE_DIR:-}" ] && DIR_GIVEN=1

usage() { sed -n '/^# Usage:/,/^#   129, 130, 143/p' "$0" | sed 's/^# \{0,1\}//' >&2; }
bad() { echo "install.sh: $*" >&2; usage; exit 2; }
# shellcheck disable=SC2034 # DIR_GIVEN: an explicit --dir must not contradict a binding the box already has
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)        [ -n "${2:-}" ] || bad "--dir needs a path"; DIR="$2"; DIR_GIVEN=1; shift ;;
    --dir=*)      DIR="${1#--dir=}"; DIR_GIVEN=1 ;;
    --base)       [ -n "${2:-}" ] || bad "--base needs a URL"; BASE="$2"; shift ;;
    --base=*)     BASE="${1#--base=}" ;;
    --server)     [ -n "${2:-}" ] || bad "--server needs nginx, apache or litespeed"; SCOPE="$SCOPE,$2"; shift ;;
    --server=*)   SCOPE="$SCOPE,${1#--server=}" ;;
    --key-sha256) [ -n "${2:-}" ] || bad "--key-sha256 needs the key's sha256"; KEY_SHA="$2"; shift ;;
    --key-sha256=*) KEY_SHA="${1#--key-sha256=}" ;;
    --named-conf) [ -n "${2:-}" ] || bad "--named-conf needs a path"; NAMED_CONF="$2"; shift ;;
    --named-conf=*) NAMED_CONF="${1#--named-conf=}" ;;
    --no-apply)   NOAPPLY=1 ;;
    --arm-deny)   ARM_DENY=1 ;;
    --no-timer)   TIMER=0 ;;
    --dry-run)    DRY=1 ;;
    -h|--help)    sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) bad "unknown option $1" ;;
  esac
  shift
done
# A trailing slash, or a feed URL with one, is the same place; the paths below join with "/".
case "$DIR" in /) ;; */) DIR="${DIR%/}" ;; esac
case "$BASE" in */) BASE="${BASE%/}" ;; esac
case "$DIR" in /*) ;; *) bad "--dir needs an absolute path, not $DIR" ;; esac
# A directory the by-hand undo would remove whole, or one that names a system tree, is refused, and so is
# a path with a . or .. component: the planes' directory is the installer's alone. OpenLiteSpeed has no
# quoting in its configuration, so a --dir or a server root it would carry must be one plain word there.
case "$DIR" in /|/etc|/var|/usr|/var/lib|/usr/local|/opt|/srv|/home|/root|/boot|/tmp) bad "--dir $DIR is a system directory; name a directory of its own, such as /var/lib/whisper-edge" ;; esac
case "/$DIR/" in */./*|*/../*) bad "--dir $DIR has a . or .. component; name it plainly" ;; esac
# a control character (a newline above all) would end a directive in every server's configuration and
# start another: refused for every server, not only OpenLiteSpeed
if printf '%s' "$DIR" | LC_ALL=C grep -c '[[:cntrl:]]' >/dev/null || [ "$(printf '%s\n' "$DIR" | wc -l)" != 1 ]; then bad "--dir has a control character (a newline, a tab); name it plainly"; fi
# --server: the names people use for each server all mean it
WANT=""
for s in $(printf '%s' "$SCOPE" | tr ',' ' '); do
  case "$s" in
    nginx) WANT="$WANT nginx" ;;
    apache|apache2|httpd) WANT="$WANT apache" ;;
    litespeed|openlitespeed|ols|lsws) WANT="$WANT litespeed" ;;
    *) bad "--server takes nginx, apache or litespeed, not $s" ;;
  esac
done
if [ "$ARM_DENY" = 1 ]; then
  case " $WANT " in *" nginx "*|*" apache "*) bad "--arm-deny is for OpenLiteSpeed alone: nginx and Apache deny from the start, after their own configuration test" ;; esac
  WANT="litespeed"
fi
wanted() { [ -z "$WANT" ] && return 0; case " $WANT " in *" $1 "*) return 0 ;; esac; return 1; }

# ---- the default policy, pinned ----------------------------------------------------------------------
#
# The exact bytes the core's own copy and the policy oracle hold, and the install gate holds this copy
# identical to theirs. The drop-ins are translated from THIS text, never from the operator's edited
# policy.conf: an edit of that file is the operator's, and the server's own configuration test judges it.
policy_text() {
  cat <<'WHISPER_EDGE_POLICY'
whisper_edge_mode deny;
# before any line: the hold-harmless set and the ACME challenge path; your tenant allow list, if installed
deny if listed >= critical     # Spamhaus DROP: the listing itself says do not route or peer
deny if listed >= high         # cited, high-confidence listings
log  if rpki_unreachable       # visible, not blocked: see below
log  if tor_exit               # visible, not blocked: people use Tor for good reasons
WHISPER_EDGE_POLICY
}
# The planes the default policy reads, in the order its rules name them, and the attribute each one
# carries. A plane outside these three gets no refresh from this installer: the set comes from the policy.
PLANES="reputation rpki-unreachable tor"
plane_rule() { # <plane> -> the rules that read it, as the policy writes them
  case "$1" in
    reputation) echo "deny if listed >= critical and deny if listed >= high" ;;
    rpki-unreachable) echo "log if rpki_unreachable" ;;
    tor) echo "log if tor_exit" ;;
  esac
}
plane_denies() { [ "$1" = reputation ]; }

# translate <nginx|apache|litespeed>: the pinned text in that server's idiom. A comment rides above its
# rule, the standalone comment keeps its place after the mode line, and a rule is one directive.
translate() {
  policy_text | WE_AWK_idiom="$1" awk 'BEGIN { idiom = ENVIRON["WE_AWK_idiom"] }
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function squash(s) { gsub(/[ \t]+/, " ", s); return trim(s) }
    function rule(r,   q) {
      if (idiom == "nginx") {
        if (index(r, "{") || index(r, "}") || index(r, ";") || index(r, "\"")) {
          q = r; gsub(/\\/, "\\\\", q); gsub(/"/, "\\\"", q); return "whisper_edge_policy \"" q "\";"
        }
        return "whisper_edge_policy " r ";"
      }
      if (idiom == "apache") { q = r; gsub(/\\/, "\\\\", q); gsub(/"/, "\\\"", q); return "WhisperEdgePolicy \"" q "\"" }
      return "    whisper_edge_policy " r
    }
    function comment(c) { return (idiom == "litespeed" ? "    " : "") c }
    NR == 1 {
      m = squash($0); sub(/;$/, "", m); split(m, w, " ")
      if (idiom == "nginx") print "whisper_edge_mode " w[2] ";"
      else if (idiom == "apache") print "WhisperEdgeMode " w[2]
      else print "    whisper_edge_mode log"
      next
    }
    /^[ \t]*#/ { print comment(trim($0)); next }
    /^[ \t]*$/ { next }
    {
      r = $0; c = ""
      if ((i = index(r, "#")) > 0) { c = trim(substr(r, i + 1)); r = substr(r, 1, i - 1) }
      if (c != "") print comment("# " c)
      print rule(squash(r))
    }'
}

# ---- words, for where each one lands ------------------------------------------------------------------
#
# Paths and the feed URL come from the operator, so every word is escaped for where it lands. In a
# unit's ExecStart, % and $ are systemd specifiers (doubled) and a word with whitespace, a quote or a
# backslash is double-quoted. In a sed replacement, \ & and the | delimiter are escaped, so a --base
# carrying a query string such as ?a=1&b=2 is written as given and not as sed's own "&". In the shell
# line printed for cron, a word is single-quoted when it needs to be, and % is escaped for crontab.
sd_word() {
  _w=$(printf '%s' "$1" | sed -e 's/%/%%/g' -e 's/\$/$$/g')
  case "$_w" in
    *[[:space:]\"\'\\]*) printf '"%s"' "$(printf '%s' "$_w" | sed -e 's/[\\"]/\\&/g')" ;;
    *) printf '%s' "$_w" ;;
  esac
}
sh_word() {
  case "$1" in
    "") printf "''" ;;
    *[!A-Za-z0-9_./:=@,+-]*) printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")" ;;
    *) printf '%s' "$1" ;;
  esac
}
# nginx and Apache read a word with a space, a quote, a brace, a semicolon or a hash only when quoted
cf_word() {
  case "$1" in
    *[[:space:]]*|*[\"\'\\\;{}#]*) printf '"%s"' "$(printf '%s' "$1" | sed -e 's/[\\"]/\\&/g')" ;;
    *) printf '%s' "$1" ;;
  esac
}
join_words() {  # $1 = sd_word or sh_word, then the words
  _f=$1; shift; _o=""
  for _a in "$@"; do _o="$_o${_o:+ }$("$_f" "$_a")"; done
  printf '%s' "$_o"
}
sed_rep() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }
cron_line() { printf '%s' "$1" | sed 's/%/\\%/g'; }
sha256_of() { sha256sum | cut -c1-64; }

# ---- the installer's mark on the files it creates ---------------------------------------------------
#
# Every file this installer creates opens with one comment carrying the sha256 of the rest of the file.
# That is how a later run tells its own file, from any version of this installer, from an operator's:
# the digest holds over bytes the installer wrote and over nothing else, so an operator's file, or an
# operator's edit of one of ours, is never overwritten or removed by a run that cannot prove it wrote it.
prov_wrap() { # <what the file is>; the body on stdin -> the file on stdout
  _b=$(cat; echo x); _b=${_b%x}
  printf '# Whisper edge: %s, written by the installer; sha256 %s of the lines below proves it wrote them.\n%s' \
    "$1" "$(printf '%s' "$_b" | sha256_of)" "$_b"
}
is_ours() { # <file>: its first line is the mark, and the digest holds over the rest
  [ -f "$1" ] || return 1
  _h=$(sed -n '1s/^# Whisper edge: .*, written by the installer; sha256 \([0-9a-f]\{64\}\) of the lines below proves it wrote them\.$/\1/p' "$1")
  [ -n "$_h" ] && [ "$(tail -n +2 "$1" | sha256_of)" = "$_h" ]
}

# ---- what the installer writes, rendered: one function per artifact ----------------------------------
#
# Every rendering is a pure function of the run's inputs (the options, the paths, and for LimitMEMLOCK the
# value it computed), so a later run can re-render an interrupted run's files from that run's own inputs.
refresh_bin() { printf '%s/whisper-edge-refresh' "$SBIN"; }
render_template_service() {
  # The instance name is the plane, %i, appended after the escaped words: no escaping may touch it, or
  # systemd would expand a doubled %% to a literal percent and every instance would run "--plane %i".
  _x="$(sd_word "$(refresh_bin)") --plane %i --quiet $(join_words sd_word --dir "$DIR" --base "$BASE")"
  sed -e "s|^ExecStart=.*|ExecStart=$(sed_rep "$_x")|" \
      -e "s|^ReadWritePaths=.*|ReadWritePaths=$(sed_rep "$(sd_word "$DIR")")|" \
      "$HERE/whisper-edge-refresh@.service" | prov_wrap "the per-plane refresh service"
}
render_template_timer() { prov_wrap "the per-plane refresh timer" < "$HERE/whisper-edge-refresh@.timer"; }
# The schedule of one plane, in a drop-in of its own: the template carries none, because schedule
# settings are lists that accumulate across drop-ins and a template schedule would fire twice.
cadence_of() { # <plane> -> "<OnCalendar> <RandomizedDelaySec> <what it reads as> <period in s>"
  case "$1" in
    reputation) echo "hourly 900 hourly 3600" ;;   # the reputation image is valid 24h: 23 misses still serve
    *) eval "_m=\${period_$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _):-30}"
       echo "*:0/$_m 300 every_${_m}_min $((_m * 60))" ;;
  esac
}
# A format-2 plane's period, from the cadence the manifest signs for it. Its window from publication is
# 4 x cadence less the data lag d, the fetched copy is up to one cadence old when it is fetched, and the
# next install can come a timer period plus the timer's own delays later:
#   T + RandomizedDelaySec (300) + AccuracySec (60) + the refresh's worst run (1300) <= 3c - d - lag
# d is the latest measured data lag, 4740 s (79 minutes, measured 2026-10-12T05:00:02Z); the lag is
# unmeasured, so the supply below is an upper bound by it. The period is 30 minutes, or the largest
# whole minute the bound allows below that, and when not even one minute fits there is no period: no
# schedule is written, the instance is not enabled, and the plane's rules are inert.
D_LAG=4740; T_DELAYS=1660
cadence_bound() { # <plane> <cadenceSeconds>: sets period_<plane>, or REFUSED_<plane> with the numbers
  _v=$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _)
  case "$2" in ''|*[!0-9]*) return 0 ;; esac
  _sup=$((3 * $2 - D_LAG)); _room=$((_sup - T_DELAYS))
  if [ "$_room" -lt 60 ]; then
    eval "REFUSED_$_v=\"its signed cadence (cadenceSeconds $2) leaves no refresh period inside its window: 3 x $2 - $D_LAG (the data lag) = $_sup s, before the publication lag, against $T_DELAYS s of the timer's own delays and the refresh's worst run\""
    return 0
  fi
  _m=$((_room / 60)); [ "$_m" -gt 30 ] && _m=30
  eval "period_$_v=\$_m"
}
render_cadence() { # <plane>
  set -- "$1" $(cadence_of "$1")
  printf '[Timer]\nOnCalendar=%s\nRandomizedDelaySec=%s\n' "$2" "$3" | prov_wrap "the $1 plane's refresh schedule"
}
cadence_dropin() { printf '%s/whisper-edge-refresh@%s.timer.d/%s.conf' "$UNITDIR" "$1" "$1"; }
render_memlock() { # <unit> <value>
  printf '[Service]\n# Twice the armed plane bytes: a plane swap locks the old image and the new one at once.\nLimitMEMLOCK=%s\n' "$2" \
    | prov_wrap "the memory lock $1 needs for the planes it serves"
}
memlock_dropin() { printf '%s/%s.d/whisper-edge.conf' "$UNITDIR" "$1"; }

# The drop-ins each server reads, from the pinned text. The data line binds the directory by name, so
# every plane the policy reads is bound from the files present when the configuration is read.
render_nginx_body() {
  printf 'whisper_edge_data %s;\nwhisper_edge_summary %s;\n' "$(cf_word "$DIR")" "$(cf_word "$DIR/counters")"
  translate nginx
}
render_nginx() { render_nginx_body | prov_wrap "the default policy for nginx"; }
render_nginx_load() { printf 'load_module %s;\n' "$(cf_word "$1")" | prov_wrap "the Whisper edge module for nginx"; }
render_apache_body() { # [the module path, when it is not loaded yet]
  [ -n "${1:-}" ] && printf 'LoadModule whisper_edge_module %s\n' "$(cf_word "$1")"
  printf 'WhisperEdgeData %s\nWhisperEdgeSummary %s\n' "$(cf_word "$DIR")" "$(cf_word "$DIR/counters")"
  translate apache
}
render_apache() { render_apache_body "${1:-}" | prov_wrap "the default policy for Apache"; }
# The module trusts only an explicit useIpInProxyHeader 0. Where no file of the operator's names the key,
# the installer's own file sets it to 0, at the top level it is included at (measured: an included line
# takes effect); the undo takes it back with the file. An operator's own value is never overridden: any
# value but 0 is refused.
ols_proxy_value() { # the useIpInProxyHeader the operator's files name, last one wins; empty when none does
  for _pf in $(ols_files); do [ "$_pf" = "$LSWS/conf/whisper-edge.conf" ] || rd_file "$_pf"; done \
    | sed -n 's/^[[:space:]]*useIpInProxyHeader[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' | tail -n 1
}
render_litespeed_proxy() { # the installer's own useIpInProxyHeader line, when the operator names none
  [ -n "$(ols_proxy_value)" ] && return 0
  printf '%s\n' "# The module trusts only an explicit useIpInProxyHeader 0. Behind a proxy or CDN, name it with" \
    "# whisper_edge_trusted_proxy below." 'useIpInProxyHeader 0'
}
render_litespeed_body() {
  printf 'module mod_whisper_edge {\n    ls_enabled 1\n    whisper_edge_data %s\n    whisper_edge_summary %s\n' "$DIR" "$DIR/counters"
  translate litespeed
  printf '}\n'
}

# The gate's hooks that act on a run (a kill point, a pause point, a fixed invalid rule) are honoured only
# on a box the gate has declared disposable, and each takes one of a fixed set of values: no hook carries
# free text into a server's configuration, and on any other box a leaked hook variable is refused, never
# silently followed or ignored. The rendering hook below prints and exits and touches nothing, so it is
# not one of them.
HOOKS=""
for _h in KILL PAUSE RULE; do
  eval "_v=\${WHISPER_EDGE_INSTALL_TEST_$_h:-}"
  [ -n "$_v" ] || continue
  [ "${INSTALLER_GATE_DISPOSABLE:-0}" = 1 ] \
    || { echo "install.sh: WHISPER_EDGE_INSTALL_TEST_$_h is a test hook, honoured only on a box the install gate declared disposable; unset it" >&2; exit 2; }
  case "$_h:$_v" in
    KILL:before-temp:/*|KILL:before-rename:/*|KILL:after-rename:/*|KILL:after-a2enconf|KILL:after-include-line|KILL:after-test-before-reload|KILL:after-reload-before-status|KILL:after-restart-before-verdict|KILL:after-restart-before-restore) ;;
    PAUSE:after-layer1|PAUSE:after-restart|PAUSE:after-layer1+after-restart|PAUSE:after-reload|PAUSE:in-window) ;;
    RULE:bad-level|RULE:bad-attribute|RULE:trailing) ;;
    *) echo "install.sh: WHISPER_EDGE_INSTALL_TEST_$_h=$_v is not one of its fixed values" >&2; exit 2 ;;
  esac
  HOOKS="$HOOKS WHISPER_EDGE_INSTALL_TEST_$_h=$_v"
done
# the one invalid rule each _RULE value stands for, fixed here
test_rule() {
  case "${WHISPER_EDGE_INSTALL_TEST_RULE:-}" in
    bad-level) echo 'deny if listed >= nonsense' ;;
    bad-attribute) echo 'deny if no_such_attribute' ;;
    trailing) echo 'log if tor_exit garbage' ;;
  esac
}
# the pause point: blocks on the gate's FIFO, at a fixed path, until the gate has planted its fault
# (opened read-write, so neither side ever blocks in open; a marker file says the run is there)
test_pause() {
  # one point, or two in the run's order joined by "+" (a fault planted at each)
  case "+${WHISPER_EDGE_INSTALL_TEST_PAUSE:-}+" in *"+$1+"*) ;; *) return 0 ;; esac
  [ -p /run/whisper-edge-gate/pause ] || return 0
  exec 8<> /run/whisper-edge-gate/pause
  : > "/run/whisper-edge-gate/at.$1"
  read -r _ <&8 || :
  exec 8<&-
}

# The test hook, in the refresh's own style: print one rendering for the run's inputs and stop. The
# install gate holds the translations, the marks and the recovery's re-rendering against it, unprivileged.
if [ -n "${WHISPER_EDGE_INSTALL_TEST_RENDER:-}" ]; then
  case "$WHISPER_EDGE_INSTALL_TEST_RENDER" in
    policy) policy_text ;;
    nginx) render_nginx ;;
    nginx-load) render_nginx_load "${WHISPER_EDGE_INSTALL_TEST_MODULE:-/usr/lib/nginx/modules/ngx_http_whisper_edge_module.so}" ;;
    apache) render_apache "${WHISPER_EDGE_INSTALL_TEST_MODULE:-}" ;;
    litespeed) render_litespeed_body ;;
    template-service) render_template_service ;;
    template-timer) render_template_timer ;;
    cadence-*) render_cadence "${WHISPER_EDGE_INSTALL_TEST_RENDER#cadence-}" ;;
    memlock) render_memlock nginx.service "${WHISPER_EDGE_INSTALL_TEST_MEMLOCK:-16777216}" ;;
    is-ours) is_ours "${WHISPER_EDGE_INSTALL_TEST_FILE:?}" && echo ours || echo foreign ;;
    *) echo "install.sh: no rendering named $WHISPER_EDGE_INSTALL_TEST_RENDER" >&2; exit 2 ;;
  esac
  exit 0
fi

plain_word() { ! printf '%s' "$1" | LC_ALL=C grep -c '[[:space:]#{}[:cntrl:]]' >/dev/null; }
# A file in a directory another account owns (OpenLiteSpeed's conf/), read by root: only a plain file,
# never a link, and under a ceiling, so a FIFO planted in its place cannot hold the run (prints nothing)
rd_file() { [ -f "$1" ] && [ ! -L "$1" ] && timeout --kill-after=5 20 cat -- "$1" 2>/dev/null; return 0; }
# The feed's key: the default feed's is pinned above; any other feed names its own, as 64 hex digits.
case "$KEY_SHA" in '') ;; *[!0-9a-f]*) bad "--key-sha256 takes 64 lowercase hex digits" ;; *) [ "${#KEY_SHA}" = 64 ] || bad "--key-sha256 takes 64 lowercase hex digits" ;; esac
if [ -z "$KEY_SHA" ]; then
  [ "$BASE" = "$DEFAULT_BASE" ] || bad "--base $BASE is not the default feed, so its signing key cannot be the pinned one: give --key-sha256 <the sha256 of that feed's edge-signing-key.pub>"
  KEY_SHA=$DEFAULT_KEY_SHA
fi
# https for every fetch, at TLS 1.2 or later. A plain-http feed is accepted only with a key named for it
# (--key-sha256), because then its signatures, not the transport, are what the run trusts; it is said.
case "$BASE" in
  https://*) CURL_PROTO="--proto =https --tlsv1.2" ;;
  http://*) CURL_PROTO="--proto =http" ;;   # only ever with --key-sha256: a non-default base requires it
  *) bad "--base takes an https:// URL" ;;
esac

[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "install.sh: run as root (or --dry-run, which needs no root)" >&2; exit 2; }

# ---- the report -----------------------------------------------------------------------------------------
#
# Five blocks and a last line, always in this order: detected, armed, applied, proved, undo, and the line
# to watch. Each stage adds its lines to its block, and the report is printed whole at the end, or, when a
# stage stops the run, printed as far as it got with the line that says why. Nothing a child process
# prints reaches the terminal raw: the refresh's lines and a server's refusal are captured and said
# again under a fixed prefix, so every line of the report is one the installer chose the shape of.
RT=$(mktemp -d "${TMPDIR:-/tmp}/whisper-edge-install.XXXXXX")
for b in detected armed applied proved undo monitor; do : > "$RT/$b"; done
LOCKED=0
[ -n "$HOOKS" ] && printf '   test hooks active (a disposable box):%s\n' "$HOOKS" >> "$RT/detected"
rep() { _b=$1; shift; printf '   %s\n' "$*" >> "$RT/$_b"; }
# Every byte a child process, a server or a status file printed is re-said with every C0 control byte
# but the tab, and DEL, removed: a carriage return or a backspace could otherwise overwrite a line the
# installer printed on the operator's terminal.
ctl_strip() { LC_ALL=C tr -d '\000-\010\013-\037\177'; }
quoted() { # <block> <prefix> <captured text>: each captured line said again, under the prefix
  printf '%s\n' "$3" | while IFS= read -r _l; do
    [ -n "$_l" ] && printf '   %s %s\n' "$2" "$(printf '%s' "$_l" | ctl_strip | sed 's/^whisper-edge-refresh: //')" >> "$RT/$1"
  done
  return 0
}
print_report() {
  { for b in detected armed applied proved undo; do
      printf '\n== %s\n' "$b"
      if [ -s "$RT/$b" ]; then cat "$RT/$b"; else printf '   (nothing)\n'; fi
    done
    printf '\n'
    cat "$RT/monitor" 2>/dev/null || :
  } > "$RT/report.all"
  # kept first, then printed: after a hangup the terminal is gone, and the report must survive it
  if [ "${DRY:-1}" = 0 ] && [ -n "${UNDO:-}" ] && [ -d "$UNDO" ] && [ ! -L "$UNDO/last-report" ]; then
    cp -- "$RT/report.all" "$UNDO/.last-report.new" 2>/dev/null && chmod 0600 "$UNDO/.last-report.new" && mv -f "$UNDO/.last-report.new" "$UNDO/last-report" 2>/dev/null || :
  fi
  cat "$RT/report.all"
}
REPORTED=0
finish() { # the EXIT trap: an open window taken back, the report as far as the run got, the lock released
  _rc=$?
  if [ -n "${WIN_SERVER:-}" ]; then
    win_rollback "${WIN_CAUSE:-the run ended unexpectedly, exit $_rc}"
    case "$_rc" in 129|130|143) ;; *) _rc=4 ;; esac
  elif [ "$_rc" != 0 ] && [ -z "${WIN_CAUSE:-}" ] && [ "$REPORTED" = 0 ] && [ "${ENDED:-0}" = 0 ]; then
    # an end no line of this script chose: said, so the report never stops without a reason
    printf '   the run ended unexpectedly (exit %s) after the last line above; nothing after that point was done\n' "$_rc" >> "$RT/proved"
  fi
  if [ "$REPORTED" = 0 ]; then REPORTED=1; print_report; fi
  if [ "$LOCKED" = 1 ]; then : > "$LOCK" 2>/dev/null || true; fi
  rm -rf "$RT"
  exit "$_rc"
}
trap finish EXIT
trap 'WIN_CAUSE=INT; exit 130' INT
trap 'WIN_CAUSE=TERM; exit 143' TERM
trap 'WIN_CAUSE=HUP; exit 129' HUP
# stop <block> <line>: the run ends here, with this line in its block and the report printed
stop() { WIN_CAUSE=$2; rep "$1" "$2"; printf 'install.sh: %s\n' "$2" >&2; exit 1; }
would() { if [ "$DRY" = 1 ]; then printf 'would %s' "$1"; else printf '%s' "$2"; fi; }

# ---- where root may write, and as whom -------------------------------------------------------------------
#
# Root never writes, reads for a kept copy, edits, restores or removes a path in a directory another
# account can change. A directory whose whole real path, itself included, is owned by root and writable by
# no group or other is root's, and root writes there. A server's configuration directory that a non-root
# account owns (OpenLiteSpeed's conf/, owned by its WebAdmin account) is written BY that account: the work
# runs under setpriv as that uid, so whatever it does, including following a link that account planted, it
# can only do with that account's own rights. Any other directory is not written at all: the block is
# printed and that server's arm stops. Temp files are made by mktemp (O_EXCL) under a dot-name no include
# glob reads, and nothing is ever chmod'ed or chown'ed by root through a path.
mode_gow() { [ $(( 0$1 & 022 )) -ne 0 ]; }            # a stat %a mode writable by group or other
# a file of this checkout root may copy or run: it and every directory above it up to the checkout owned by
# root or by the person running this (SUDO_UID), and writable by no one else
# the checkout is the tree this script ships in (install/'s parent): every file it copies or builds lives
# there, and the ownership walk stops at it, never at the directory a clone or an extraction sits in
CHECKOUT=$(cd "$HERE/.." && pwd)
tree_ok() { # <path in the checkout>
  _tp=$1; _ok_u="0 ${SUDO_UID:-0} $(id -u)"
  while :; do
    # shellcheck disable=SC2046
    set -- $(stat -L -c '%u %a' -- "$_tp" 2>/dev/null) || return 1
    case " $_ok_u " in *" $1 "*) ;; *) return 1 ;; esac
    mode_gow "$2" && return 1
    [ "$_tp" = "$CHECKOUT" ] || [ "$_tp" = / ] && return 0
    _tp=$(dirname -- "$_tp")
  done
}
chain_root() { # <path>: every component of its real path, the path itself included, root's and not g/o-writable
  _cr=$(realpath -e -- "$1" 2>/dev/null) || return 1
  while :; do
    # shellcheck disable=SC2046
    set -- $(stat -c '%u %a' -- "$_cr" 2>/dev/null) || return 1
    [ "${1:-x}" = 0 ] || return 1
    mode_gow "$2" && return 1
    [ "$_cr" = / ] && return 0
    _cr=$(dirname -- "$_cr")
  done
}
writer_of() { # <dir> [the non-root uid the server already trusts] -> "<uid> <gid>" of who writes there, or fails
  _wd=$(realpath -e -- "$1" 2>/dev/null) || return 1
  chain_root "$_wd" && { echo "0 0"; return 0; }
  [ -n "${2:-}" ] || return 1
  # shellcheck disable=SC2046
  set -- $(stat -c '%u %g %a' -- "$_wd") "$2"
  [ "$1" = "$4" ] || return 1
  mode_gow "$3" && return 1
  chain_root "$(dirname -- "$_wd")" || return 1
  echo "$1 $2"
}
as_user() { # <uid> <gid> <command...>: the command as that account, its own groups, no new privileges
  _au=$1; _ag=$2; shift 2
  if [ "$_au" = 0 ]; then "$@"; return; fi
  if have setpriv; then setpriv --reuid="$_au" --regid="$_ag" --init-groups --no-new-privs -- "$@"; return; fi
  _an=$(getent passwd "$_au" | cut -d: -f1); [ -n "$_an" ] || return 126
  if have runuser; then runuser -u "$_an" -- "$@"; return; fi
  su -s /bin/sh "$_an" -c "$(join_words sh_word "$@")"
}
# The one writer, run as the directory's owner: the bytes on stdin into the target through a fresh mktemp
# temp in the target's own directory, its mode (and, given, its mtime) set on that temp, flushed, renamed
# over the target, the directory flushed. The temp's path and inode go out on fd 3 the moment it exists, so
# the run's stamp names it; the target's inode after the rename must be the temp's.
OWNER_PUT='d=$(dirname -- "$1"); t=$(mktemp -- "$d/.whisper-edge.XXXXXXXXXX") || exit 3
i=$(stat -c %i -- "$t"); printf "%s %s\n" "$t" "$i" >&3
cat > "$t" && chmod "$2" -- "$t" || { rm -f -- "$t"; exit 4; }
if [ -n "${3:-}" ]; then touch -h -d "@$3" -- "$t" || { rm -f -- "$t"; exit 4; }; fi
sync -- "$t" 2>/dev/null || :
[ "$(stat -c %i -- "$t")" = "$i" ] || exit 5
mv -f -T -- "$t" "$1" || { rm -f -- "$t"; exit 4; }
sync -- "$d" 2>/dev/null || :
[ "$(stat -c %i -- "$1")" = "$i" ] || exit 5'
# The kept copy's reader, run as the directory's owner: refuses a link, reads the file through a descriptor
# whose inode must be the one it stat'ed, and refuses when the file changed while it was read. Its
# "dev:ino:size:mtime context" goes out on fd 3.
OWNER_READ='[ -L "$1" ] && exit 4; [ -f "$1" ] || exit 4
a=$(stat -c %d:%i:%s:%.9Y -- "$1"); exec 4< "$1" || exit 4
[ "$(stat -L -c %d:%i -- /proc/self/fd/4)" = "${a%:*:*}" ] || exit 5
cat <&4 || exit 4
[ "$(stat -c %d:%i:%s:%.9Y -- "$1")" = "$a" ] || exit 5
printf "%s %s\n" "$a" "$(stat -c %C -- "$1" 2>/dev/null || echo -)" >&3'
# shellcheck disable=SC2034 # OWNER_INODE and OWNER_FACTS are read by the OpenLiteSpeed arm's edit and restore
# The same writer in two steps for the run itself, so the stamp names the temp before it is renamed and a
# kill can land between the two: the temp written and flushed, then (checked by its inode) renamed.
OWNER_TEMP='d=$(dirname -- "$1"); t=$(mktemp -- "$d/.whisper-edge.XXXXXXXXXX") || exit 3
i=$(stat -c %i -- "$t"); printf "%s %s\n" "$t" "$i" >&3
cat > "$t" && chmod "$2" -- "$t" || { rm -f -- "$t"; exit 4; }
if [ -n "${3:-}" ]; then touch -h -d "@$3" -- "$t" || { rm -f -- "$t"; exit 4; }; fi
sync -- "$t" 2>/dev/null || :'
OWNER_MV='[ ! -L "$1" ] && [ "$(stat -c %i -- "$1")" = "$3" ] || exit 5
if [ -n "${4:-}" ] && [ "$(stat -c %d:%i:%s:%.9Y -- "$2" 2>/dev/null)" != "$4" ]; then rm -f -- "$1"; exit 5; fi
mv -f -T -- "$1" "$2" || exit 4
sync -- "$(dirname -- "$2")" 2>/dev/null || :
[ "$(stat -c %i -- "$2")" = "$3" ] || exit 5'
owner_put() { # <uid> <gid> <target> <mode> [mtime] [dev:ino:size:mtime the target must still have]: stdin into the target as that account; the stamp names the temp
  _op=$RT/op.$$; : > "$_op"
  _orc=0; as_user "$1" "$2" sh -c "$OWNER_TEMP" sh "$3" "$4" "${5:-}" 3> "$_op" 2> "$RT/op.err" || _orc=$?
  OWNER_ERR=$(ctl_strip < "$RT/op.err" | sed -n 1p | cut -c1-200)
  _ot=$(cut -d' ' -f1 "$_op" 2>/dev/null); OWNER_INODE=$(cut -d' ' -f2 "$_op" 2>/dev/null); rm -f "$_op"
  [ -n "$STAMPF" ] && [ -n "$_ot" ] && stamp_line temp "$3" "$_ot"
  [ "$_orc" = 0 ] || return "$_orc"
  test_kill "before-rename:$3"
  as_user "$1" "$2" sh -c "$OWNER_MV" sh "$_ot" "$3" "$OWNER_INODE" "${6:-}" 2> "$RT/op.err" || { _orc=$?; OWNER_ERR=$(ctl_strip < "$RT/op.err" | sed -n 1p | cut -c1-200); return "$_orc"; }
}
# shellcheck disable=SC2034 # OWNER_FACTS is read by the OpenLiteSpeed arm's edit
owner_read() { # <uid> <gid> <file> > bytes: the file as that account; sets OWNER_FACTS ("dev:ino:size:mtime context")
  _or=$RT/or.$$; : > "$_or"
  _orc=0; as_user "$1" "$2" sh -c "$OWNER_READ" sh "$3" 3> "$_or" || _orc=$?
  OWNER_FACTS=$(cat "$_or"); rm -f "$_or"
  return "$_orc"
}
owner_rm() { as_user "$1" "$2" rm -f -- "$3"; }        # unlinks the name, never what a link points at
# The SELinux context back on a restored file, through a descriptor: only when the inode at the path is the
# one the writer reported and has exactly one link, so a link or a hard link swapped in is never relabelled.
fd_chcon() { # <path> <inode> <context>
  case "${3:--}" in -|'?') return 0 ;; esac
  have chcon || return 0
  exec 6< "$1" || return 1
  if [ "$(stat -L -c '%i %h' -- /proc/self/fd/6)" != "$2 1" ]; then exec 6<&-; return 1; fi
  chcon -- "$3" /proc/self/fd/6; _cc=$?
  exec 6<&-
  return "$_cc"
}
# A real directory owned by root and writable by no one else, made when missing: $ETC, the undo directory,
# the unit directory. install -d alone keeps a pre-existing owner and follows a pre-existing link.
root_dir() { # <dir> <mode>
  if [ -L "$1" ]; then stop applied "$1 is a symbolic link; the installer's own directories must be real directories owned by root"; fi
  if [ ! -d "$1" ]; then
    chain_root "$(dirname -- "$1")" || stop applied "$(dirname -- "$1") is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others), so the installer will not create $1 in it"
    mkdir -m "$2" -- "$1"
  fi
  chain_root "$1" || stop applied "$1 is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others); fix that, or remove it, and run this again"
}

# ---- the run's own lock -------------------------------------------------------------------------------
#
# Installer runs serialise on /etc/whisper-edge/install.lock: flock on a file that is created once and
# never removed, so every run and every undo line locks the same inode. The holder writes its start time
# into the file; a run that finds it held says when that run started, and a completed run clears the time
# by truncating the file in place. This is the installer's own lock and never the data directory's, which
# the refresh takes itself: holding that one across the refresh's own fetch would block the child.
LOCK="$ETC/install.lock"
UNDO="$ETC/undo"
take_lock() {
  command -v flock >/dev/null 2>&1 || stop detected "flock (util-linux) is needed to keep two installer runs apart; install it and run again"
  root_dir "$ETC" 0755
  [ -L "$LOCK" ] && stop detected "$LOCK is a symbolic link; remove it and run again"
  [ -e "$LOCK" ] || { (umask 077; : >> "$LOCK"); }
  exec 7>> "$LOCK"
  if ! flock -n 7; then
    _t=$(sed -n 1p "$LOCK" 2>/dev/null || true)
    if [ -n "$_t" ]; then _t="at $_t"; else _t="moments ago"; fi
    stop detected "another installer run is in progress, started $_t; it ends by removing its stamp"
  fi
  LOCKED=1
  date -u +%Y-%m-%dT%H:%M:%SZ > "$LOCK"
}

# ---- the run's stamp, and the recovery of an interrupted one -------------------------------------------
#
# Before it writes anything, the run opens a stamp in /etc/whisper-edge/undo (0700) whose first line is
# the inputs it renders with, and every write appends one line naming its target and its temp BEFORE the
# temp exists. Every write is a temp in the target's own directory renamed over the target, so a write
# that began left either no file or the whole rendering. A completed run removes its stamp. A run that
# finds a stamp an interrupted run left re-renders that run's files from that run's own inputs and:
# removes a created file only when its bytes are exactly that rendering; restores an edited file from
# its kept copy only when the file is still that run's edit or still the original; and names, and leaves
# alone, anything else, because the only person who changes those files afterwards is the operator.
STAMP=""; STAMPF=""
# The gate's kill point, in the refresh's test-hook style: WHISPER_EDGE_INSTALL_TEST_KILL=<point>:<path>
# ends the run there with SIGKILL, which no trap sees, exactly as a power cut or an OOM kill would.
test_kill() { if [ "${WHISPER_EDGE_INSTALL_TEST_KILL:-}" = "$1" ]; then kill -KILL $$; fi; return 0; }
stamp_open() { # the inputs every rendering below is a function of
  root_dir "$UNDO" 0700
  STAMP=$(date -u +%Y%m%dT%H%M%SZ).$$
  STAMPF="$UNDO/run.$STAMP"
  { printf 'inputs'
    for _kv in "dir=$DIR" "base=$BASE" "sbin=$SBIN" "unitdir=$UNITDIR" "etc=$ETC" "lsws=$LSWS" \
               "scope=$WANT" ${MEMLOCK_INPUTS:-} ${PERIOD_INPUTS:-}; do
      printf ' %s' "$(sh_word "$_kv")"
    done
    printf '\n'; } > "$STAMPF.new"
  chmod 0600 "$STAMPF.new"; mv -f "$STAMPF.new" "$STAMPF"
}
stamp_line() { printf '%s\n' "$(join_words sh_word "$@")" >> "$STAMPF"; }
stamp_close() { if [ -n "$STAMPF" ]; then rm -f "$STAMPF" || :; fi; STAMPF=""; }

# put <target> <what it is> <mode>: the rendering in $RT/new written to the target, or not
#   0  written            3  a file the installer cannot prove it wrote is there: nothing is written
#   1  already present (the same bytes: not rewritten, so its mtime says nothing moved)

#   4  the target's directory is not one the installer may write: nothing is written
# A target in a directory a non-root account owns is written by that account: PUT_U and PUT_G name it.
PUT_U=0; PUT_G=0
put() { # <target> <what> <mode>
  _pu=$PUT_U; _pg=$PUT_G; _d=$(dirname -- "$1")
  if [ "$_pu" = 0 ]; then
    # made here only under a parent root alone writes; refused (4) otherwise, never a stop: a put runs
    # inside an arm's window, where a refusal is that arm's alone
    if [ ! -d "$_d" ]; then { [ ! -L "$_d" ] && chain_root "$(dirname -- "$_d")" && mkdir -m 0755 -- "$_d"; } || return 4; fi
    chain_root "$_d" || return 4
  fi
  if [ -L "$1" ]; then return 3; fi
  if [ -e "$1" ]; then
    [ -f "$1" ] || return 3                   # a FIFO or a device at the name: never read, never replaced
    if cmp -s "$RT/new" "$1"; then return 1; fi
    is_ours "$1" || return 3
  fi
  stamp_line created "$1" -
  test_kill "before-temp:$1"
  _prc=0; owner_put "$_pu" "$_pg" "$1" "$3" < "$RT/new" || _prc=$?
  [ "$_prc" = 0 ] || stop applied "could not write $1 (the writer exited $_prc: $(case $_prc in 5) echo 'the file changed under it' ;; 3) echo 'no temp file could be made there' ;; *) echo 'a write failed, perhaps a full disk' ;; esac)${OWNER_ERR:+: $OWNER_ERR}); nothing else was written to it"
  test_kill "after-rename:$1"
  return 0
}
# write_artifact <target> <what> <mode> <renderer...>: render, put, and say which happened
WROTE=""
write_artifact() {
  _t=$1; _w=$2; _m=$3; shift 3
  "$@" > "$RT/new"
  if [ "$DRY" = 1 ]; then
    if [ -e "$_t" ] && cmp -s "$RT/new" "$_t"; then rep applied "already present: $_t ($_w)"
    elif [ -e "$_t" ] && ! is_ours "$_t"; then rep applied "would stop: $_t is not a file this installer wrote ($_w); move it aside first"
    else rep applied "would write $_t ($_w, $(grep -c '' "$RT/new") lines)"; fi
    return 0
  fi
  put "$_t" "$_w" "$_m" && _rc=0 || _rc=$?
  case "$_rc" in
    0) rep applied "wrote $_t ($_w, $(grep -c '' "$RT/new") lines)"; WROTE="$WROTE $_t" ;;
    1) rep applied "already present: $_t ($_w)" ;;
    *) return "$_rc" ;;
  esac
}

# the sweep of every stamp an interrupted run left, each with its own line
render_for() { # <target>, in a subshell whose inputs are the interrupted run's -> its rendering
  case "$1" in
    "$UNITDIR/whisper-edge-refresh@.service") render_template_service ;;
    "$UNITDIR/whisper-edge-refresh@.timer") render_template_timer ;;
    "$UNITDIR"/whisper-edge-refresh@*.timer.d/*.conf)
      _p=${1#"$UNITDIR/whisper-edge-refresh@"}; render_cadence "${_p%%.timer.d/*}" ;;
    "$UNITDIR"/*.d/whisper-edge.conf)
      _u=${1#"$UNITDIR/"}; _u=${_u%.d/whisper-edge.conf}
      eval "_v=\${memlock_$(printf '%s' "$_u" | tr -c 'A-Za-z0-9' _):-}"
      [ -n "$_v" ] && render_memlock "$_u" "${_v%%,*}" ;;
    "$ETC/policy.conf") policy_text ;;
    *) return 1 ;;
  esac
}
sweep_inputs() { # <the stamp's inputs>: the interrupted run's own, in place of this run's
  eval "set -- $1"
  for _kv in "$@"; do
    _v=${_kv#*=}
    case "${_kv%%=*}" in
      dir) DIR=$_v ;; base) BASE=$_v ;; sbin) SBIN=$_v ;; unitdir) UNITDIR=$_v ;; etc) ETC=$_v ;;
      lsws) LSWS=$_v ;; memlock_*|period_*) eval "${_kv%%=*}=\$_v" ;;
    esac
  done
}
# httpd_config.conf back from the kept copy, by the facts the edit recorded: only while the file is still
# this run's edit (its bytes, its inode), written as its owner, its mode, mtime and SELinux context back
ols_restore() {
  _ff="$UNDO/litespeed.facts"; [ -f "$_ff" ] || return 1
  _fp=$(sed -n 's/^path //p' "$_ff"); _fk=$(sed -n 's/^kept //p' "$_ff"); _fa=$(sed -n 's/^after //p' "$_ff")
  _fm=$(sed -n 's/^mode //p' "$_ff"); _fu=$(sed -n 's/^uid //p' "$_ff"); _fg=$(sed -n 's/^gid //p' "$_ff")
  _ft=$(sed -n 's/^mtime //p' "$_ff"); _fc=$(sed -n 's/^context //p' "$_ff")
  [ -f "$_fk" ] && [ ! -L "$_fp" ] && [ "$(rd_file "$_fp" | sha256_of)" = "$_fa" ] || return 1
  owner_put "$_fu" "$_fg" "$_fp" "$_fm" "$_ft" < "$_fk" || return 1
  fd_chcon "$_fp" "$OWNER_INODE" "$_fc" || :
  ols_copy_back "$_fu" "$_fg" "$_fp" "$_fa" "$_ft" "$_fk"
  rm -f -- "$_fk" "$_ff"
}
# OpenLiteSpeed copies httpd_config.conf to httpd_config.conf0 at a start only when the file is NEWER than
# its copy (measured on 1.9.3: a file put back with its own, older mtime is never copied again), so after the
# edit is taken back its copy would carry the installer's include line for good. When that copy is exactly
# the installer's edit, it is given the bytes and the mtime put back, which is the copy the server makes of
# a file it has loaded; a copy that is anything else is the operator's, and is left alone.
ols_copy_back() { # <uid> <gid> <httpd_config.conf> <digest of the installer's edit> <mtime> <the bytes put back>
  _cb="${3}0"
  [ -f "$_cb" ] && [ ! -L "$_cb" ] && [ "$(rd_file "$_cb" | sha256_of)" = "$4" ] || return 0
  owner_put "$1" "$2" "$_cb" "$(stat -c %a -- "$_cb")" "$5" < "$6" || :
}
sweep_one() { # <stamp file>
  _sf=$1; _n=0; _kept=0
  _in=$(sed -n '1s/^inputs //p' "$_sf")
  # the server files the interrupted run wrote are known by the digest of the bytes it wrote, which proves
  # them its own more strictly than a re-rendering could; its later inputs (what it kept) are appended
  _wr=$(sed -n 's/^wrote //p' "$_sf")
  for _i in $(sed -n 's/^input //p' "$_sf"); do _in="$_in $_i"; done
  # the edit first (OpenLiteSpeed's httpd_config.conf), so the include line never outlives the file it names
  while IFS= read -r _l; do
    [ -n "$_l" ] || continue
    eval "set -- $_l"
    [ "$1" = edited ] || continue
    # edited <file> <kept copy> <digest after the edit> <digest before it>
    if [ -L "$2" ] || [ ! -f "$2" ]; then
      rep applied "kept $2 as it is: it is no longer a plain file; the bytes from before the interrupted run are at $3"
      _kept=$((_kept + 1)); continue
    fi
    _ed=$(rd_file "$2" | sha256_of)
    if [ "$_ed" = "$5" ]; then
      # the edit never landed: nothing to take back but the kept copy and the record
      rm -f -- "$3"
      if [ "$(sed -n 's/^kept //p' "$UNDO/litespeed.facts" 2>/dev/null)" = "$3" ]; then rm -f -- "$UNDO/litespeed.facts"; fi
    elif [ "$_ed" = "$4" ] && [ "$(sed -n 's/^kept //p' "$UNDO/litespeed.facts" 2>/dev/null)" = "$3" ] && ols_restore; then
      _n=$((_n + 1))
      rep applied "restored $2 from the copy the interrupted run kept; a server it restarted runs the include until its next restart (${LSWS:-/usr/local/lsws}/bin/lswsctrl restart)"
    else
      rep applied "kept $2: it changed after the interrupted run edited it, or its restore did not complete; the bytes from before that run are at $3; compare: diff $3 $2"
      _kept=$((_kept + 1))
    fi
  done <<EOF
$(sed -n '2,$p' "$_sf")
EOF
  while IFS= read -r _l; do
    [ -n "$_l" ] || continue
    eval "set -- $_l"
    case "$1" in
      temp)
        # the temp, by the path the stamp names and never by a scan of the directory, removed as the
        # directory's own writer would (a link there is unlinked, never followed)
        [ -L "$3" ] || [ -f "$3" ] || continue
        _tw=$(writer_of "$(dirname -- "$3")" "$(stat -c %u -- "$(dirname -- "$3")" 2>/dev/null)") || continue
        # shellcheck disable=SC2086
        owner_rm $_tw "$3" ;;
      link)
        # a link the run made (a2enconf), removed while it still points where the run pointed it
        if [ -L "$2" ] && [ "$(readlink -- "$2")" = "$3" ]; then rm -f -- "$2"; _n=$((_n + 1)); fi ;;
      created)
        [ -L "$2" ] && continue
        [ -e "$2" ] || continue
        _cf=$2
        _ws=$(printf '%s\n' "$_wr" | WE_AWK_t="$2" awk 'BEGIN { t = ENVIRON["WE_AWK_t"] } { n = split($0, w, " ") } w[1] == t || w[1] == "\x27" t "\x27" { print w[n] }' | tail -n 1)
        # a file of the installer's own that the run replaced: "prev <file> <kept copy> <mode>"
        _pv=""; _pm=""
        while IFS= read -r _pl; do
          eval "set -- $_pl"; [ "$1" = prev ] && [ "$2" = "$_cf" ] && { _pv=$3; _pm=$4; }
        done <<EOP
$(sed -n '2,$p' "$_sf")
EOP
        eval "set -- $_l"
        if [ -n "$_ws" ] && [ "$(rd_file "$2" | sha256_of)" = "$_ws" ] && [ -n "$_pv" ] && [ -s "$_pv" ]; then
          _cw=$(writer_of "$(dirname -- "$2")" "$(stat -c %u -- "$(dirname -- "$2")" 2>/dev/null)") || { rep applied "kept $2: its directory can be written by an account other than its owner; its bytes from before the interrupted run are at $_pv"; continue; }
          # shellcheck disable=SC2086
          if owner_put $_cw "$2" "${_pm:-644}" < "$_pv"; then rm -f -- "$_pv"; _n=$((_n + 1)); rep applied "restored $2 to its bytes from before the interrupted run"
          else rep applied "kept $2: its bytes from before the interrupted run could not be put back; they are at $_pv"; _kept=$((_kept + 1)); fi
          continue
        fi
        if [ -n "$_pv" ] && [ -f "$_pv" ] && rd_file "$2" | cmp -s "$_pv" -; then rm -f -- "$_pv"; continue; fi
        if [ -n "$_ws" ] && [ "$(rd_file "$2" | sha256_of)" = "$_ws" ]; then
          # removed as the directory's own writer would: root in a directory root alone writes, else its
          # owner (OpenLiteSpeed's conf/), the same rule the run wrote it under
          _cw=$(writer_of "$(dirname -- "$2")" "$(stat -c %u -- "$(dirname -- "$2")" 2>/dev/null)") || { rep applied "kept $2: its directory can be written by an account other than its owner"; continue; }
          # shellcheck disable=SC2086
          owner_rm $_cw "$2"; _n=$((_n + 1)); continue
        fi
        if ( sweep_inputs "$_in"; render_for "$2" ) > "$RT/swept" 2>/dev/null && rd_file "$2" | cmp -s "$RT/swept" -; then
          _cw=$(writer_of "$(dirname -- "$2")" "$(stat -c %u -- "$(dirname -- "$2")" 2>/dev/null)") || { rep applied "kept $2: its directory is not one the installer may write"; continue; }
          # shellcheck disable=SC2086
          owner_rm $_cw "$2"; _n=$((_n + 1))
        else
          rep applied "kept $2: an interrupted run began writing it and its bytes are not that run's own; it is yours to keep or remove"
          _kept=$((_kept + 1))
        fi ;;
    esac
  done <<EOF
$(sed -n '2,$p' "$_sf")
EOF
  rm -f "$_sf"
  rep applied "recovered an interrupted run ($(basename "$_sf")): removed $_n file(s) it had written, kept $_kept"
}
sweep() {
  [ -d "$UNDO" ] || return 0
  for _sf in "$UNDO"/run.*; do
    [ -f "$_sf" ] || continue
    sweep_one "$_sf"
  done
}
# ---- which servers are here, and which user each one runs as -------------------------------
#
# The user is RESOLVED, never assumed. It is www-data on Debian nginx and Apache, apache on RHEL,
# lsadm or nobody on OpenLiteSpeed, bind on Debian named and named on RHEL - and a hardcoded guess
# produces a counters directory the server cannot write, which fails silently because counting is
# not on the request path. So: ask the running process first, since that is ground truth, and fall
# back to the configuration only if the server is not up.
# CONFIG first, process second, candidate list last - in that order, and the order is the whole
# point. The first draft asked `ps` first and on this build host it answered a developer's login, because a
# gate run had left an unprivileged test nginx running: it would have granted the counters
# directory to a developer account on a production box. The configured user is what the server
# WILL run as; a running process is only what it happens to be now.
cfg_user() {  # $1 = server -> the user its own configuration names, or empty
  case "$1" in
    nginx)
      # `nginx -T` dumps the whole effective config, so this sees an include too. Falls back to
      # the main file if -T is refused (it needs read access to every included file).
      { nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf 2>/dev/null; } \
        | sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^;[:space:]]\{1,\}\).*/\1/p' | head -1
      ;;
    apache)
      # apachectl -S prints `User: name="www-data" id=33`; envvars is the Debian source of truth. The
      # probe's choice of control (AP_CTL) asks it: RHEL's apachectl refuses -S, its httpd answers.
      { [ -n "${AP_CTL:-}" ] && "$AP_CTL" -S 2>/dev/null; } \
        | sed -n 's/.*User: name="\([^"]*\)".*/\1/p' | head -1
      ;;
    litespeed)
      # httpd_config.conf names the user its workers run as; a process name anyone can set is never asked first
      sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([A-Za-z0-9_.-]\{1,\}\).*/\1/p' "$LSWS/conf/httpd_config.conf" 2>/dev/null | head -1
      ;;
    named)
      # Debian passes -u on the command line from the unit or the defaults file.
      { systemctl cat named.service 2>/dev/null; cat /etc/default/named 2>/dev/null; } \
        | sed -n 's/.*-u[[:space:]]\{1,\}\([A-Za-z0-9_-]\{1,\}\).*/\1/p' | head -1
      ;;
  esac
}
proc_user() {  # $1 = process name -> the non-root user running it, or empty
  ps -o user= -C "$1" 2>/dev/null | sort -u | grep -v '^root$' | head -1 || true
}
conf_user() {  # $1..$n = candidate users -> the first that exists on this host
  for u in "$@"; do
    if id "$u" >/dev/null 2>&1; then printf '%s' "$u"; return; fi
  done
}
resolve_user() {  # $1 = server key, $2 = process name, $3.. = candidates
  _k="$1"; _p="$2"; shift 2
  _u="$(cfg_user "$_k")"
  [ -n "$_u" ] && id "$_u" >/dev/null 2>&1 && { printf '%s' "$_u"; return; }
  _u="$(proc_user "$_p")"
  [ -n "$_u" ] && id "$_u" >/dev/null 2>&1 && { printf '%s' "$_u"; return; }
  conf_user "$@"
}


# ---- the probe ---------------------------------------------------------------------------------------
#
# Per server, three facts: installed or not, the module binary present where it was looked for or not,
# and loaded or not; plus running or not, and where the distribution's own configuration includes a
# drop-in from. "Running" is the unit OR a live master process: a server started by hand, as in many
# containers, is running with its unit inactive. The master is the pid its pidfile records when that pid
# is alive and is the server, else the oldest process of that name whose parent is 1, so orphaned workers
# of a killed master never read as a running server.
have() { command -v "$1" >/dev/null 2>&1; }
SYSTEMD=0; have systemctl && [ -d /run/systemd/system ] && SYSTEMD=1
unit_active() { [ "$SYSTEMD" = 1 ] || return 1; systemctl is-active --quiet "$1" 2>/dev/null; }
master_pid() { # <process name> <pidfile>...
  _n=$1; shift
  for _pf in "$@"; do
    [ -r "$_pf" ] || continue
    _p=$(sed -n '1s/[^0-9]//gp' "$_pf")
    [ -n "$_p" ] && [ -r "/proc/$_p/comm" ] && [ "$(cat "/proc/$_p/comm" 2>/dev/null)" = "$_n" ] && { echo "$_p"; return 0; }
  done
  ps -eo pid=,ppid=,etimes=,comm= 2>/dev/null | WE_AWK_n="$_n" awk 'BEGIN { n = ENVIRON["WE_AWK_n"] } $2 == 1 && $4 == n && ($3 + 0) >= best { best = $3 + 0; p = $1 } END { if (p) print p }'
}
first_file() { for _f in "$@"; do [ -f "$_f" ] && { echo "$_f"; return 0; }; done; return 1; }

# nginx: where the main context includes module files from, and where http {} includes drop-ins from,
# read from the main configuration itself (Debian: modules-enabled and conf.d; RHEL: /usr/share/nginx/modules
# and conf.d; Alpine: modules and http.d). A relative include is relative to the configuration's directory.
nginx_includes() { # <main conf> -> "main <dir>" and "http <dir>" lines, for each "include <dir>/*.conf;"
  WE_AWK_base="$(dirname "$1")" awk 'BEGIN { base = ENVIRON["WE_AWK_base"] }
    { l = $0; sub(/#.*/, "", l) }
    { while (match(l, /[{};]|include[ \t]+[^;{}]+;|http[ \t]*\{/)) {
        t = substr(l, RSTART, RLENGTH); l = substr(l, RSTART + RLENGTH)
        if (t ~ /^http/) { depth++; if (depth == 1) inhttp = 1; continue }
        if (t == "{") { depth++; continue }
        if (t == "}") { if (depth == 1) inhttp = 0; depth--; continue }
        if (t ~ /^include/) {
          p = t; sub(/^include[ \t]+/, "", p); sub(/[ \t]*;$/, "", p); gsub(/["\047]/, "", p)
          if (p !~ /\/\*\.conf$/ && p !~ /^\*\.conf$/) continue
          d = p; sub(/\/?\*\.conf$/, "", d); if (d !~ /^\//) d = base "/" d
          if (depth == 0) print "main " d; else if (depth == 1 && inhttp) print "http " d
        }
      } }' "$1"
}
probe_nginx() {
  NGX=0; NGX_MOD=""; NGX_MODS=""; NGX_LOADED=no; NGX_RUNNING=no; NGX_MAIN_INC=""; NGX_HTTP_INC=""; NGX_VER=""
  have nginx || return 0
  NGX=1
  _v=$(nginx -V 2>&1 || true)
  NGX_VER=$(printf '%s\n' "$_v" | sed -n 's|^nginx version: nginx/\([^ ]*\).*|\1|p' | sed -n 1p)
  NGX_BIN=$(command -v nginx)
  _mp=$(printf '%s\n' "$_v" | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p' | sed -n 1p)
  _cp=$(printf '%s\n' "$_v" | sed -n 's/.*--conf-path=\([^ ]*\).*/\1/p' | sed -n 1p)
  _pp=$(printf '%s\n' "$_v" | sed -n 's/.*--pid-path=\([^ ]*\).*/\1/p' | sed -n 1p)
  NGX_CONF=${_cp:-/etc/nginx/nginx.conf}
  for _d in $_mp /usr/lib/nginx/modules /usr/lib64/nginx/modules /usr/share/nginx/modules /usr/local/nginx/modules /etc/nginx/modules; do
    case " $NGX_MODS " in *" $_d "*) continue ;; esac
    NGX_MODS="$NGX_MODS $_d"
    [ -z "$NGX_MOD" ] && [ -f "$_d/ngx_http_whisper_edge_module.so" ] && NGX_MOD="$_d/ngx_http_whisper_edge_module.so"
  done
  NGX_MODS=${NGX_MODS# }
  _t=$(nginx -T 2>/dev/null || cat "$NGX_CONF" 2>/dev/null || true)
  case "$_t" in *ngx_http_whisper_edge_module*) NGX_LOADED=yes ;; esac
  if [ -f "$NGX_CONF" ]; then
    _inc=$(nginx_includes "$NGX_CONF")
    # shellcheck disable=SC2034 # the module include, where the load file goes when the arm applies
    NGX_MAIN_INC=$(printf '%s\n' "$_inc" | sed -n 's/^main //p' | sed -n 1p)
    # Debian's http block includes conf.d and sites-enabled; a drop-in belongs in conf.d
    NGX_HTTP_INC=$(printf '%s\n' "$_inc" | sed -n 's/^http //p' | grep -v 'sites-enabled' | sed -n 1p || true)
  fi
  NGX_UNIT=nginx.service; NGX_PIDFILE=${_pp:-/run/nginx.pid}
  if unit_active nginx.service || [ -n "$(master_pid nginx ${_pp:-} /run/nginx.pid /var/run/nginx.pid)" ]; then NGX_RUNNING=yes; fi
}
probe_apache() {
  AP=0; AP_MOD=""; AP_MODS=""; AP_LOADED=no; AP_RUNNING=no; AP_LAYOUT=""; AP_INC=""; AP_VER=""; AP_CTL=""
  for _a in apache2 httpd; do have "$_a" && { AP_BIN=$(command -v "$_a"); AP_NAME=$_a; AP=1; break; }; done
  [ "$AP" = 1 ] || return 0
  for _c in apache2ctl apachectl; do have "$_c" && { AP_CTL=$_c; break; }; done
  # RHEL's apachectl is a systemd wrapper that refuses every word past its first ("Passing arguments to
  # httpd using apachectl is no longer supported", exit 1), so -M, -S, -t -D DUMP_INCLUDES and a hand-started
  # parent's -f never reach httpd through it, and its start and graceful act on httpd.service whatever was
  # asked. A control script that will not pass two words on is passed by, as is a missing one: the binary
  # is driven itself, by name, so the PATH the run was given decides which one.
  if [ -z "$AP_CTL" ] || ! "$AP_CTL" -v -v >/dev/null 2>&1; then AP_CTL=$AP_NAME; fi
  AP_VER=$("$AP_BIN" -v 2>/dev/null | sed -n 's|^Server version: Apache/\([^ ]*\).*|\1|p' | sed -n 1p)
  _lx=""
  for _x in apxs apxs2; do have "$_x" && { _lx=$("$_x" -q LIBEXECDIR 2>/dev/null || true); break; }; done
  for _d in $_lx /usr/lib/apache2/modules /usr/lib64/httpd/modules /usr/lib/httpd/modules /etc/httpd/modules /usr/local/apache2/modules; do
    case " $AP_MODS " in *" $_d "*) continue ;; esac
    AP_MODS="$AP_MODS $_d"
    [ -z "$AP_MOD" ] && [ -f "$_d/mod_whisper_edge.so" ] && AP_MOD="$_d/mod_whisper_edge.so"
  done
  AP_MODS=${AP_MODS# }
  _m=$( { [ -n "$AP_CTL" ] && "$AP_CTL" -M 2>/dev/null; } || true)
  case "$_m" in *whisper_edge_module*) AP_LOADED=yes ;; esac
  # the three layouts: Debian's conf-available with a2enconf, RHEL's conf.d, upstream's conf/extra
  # shellcheck disable=SC2034 # the layout decides the enable step when the arm applies
  if [ -d /etc/apache2/conf-available ] && have a2enconf; then AP_LAYOUT=debian; AP_INC=/etc/apache2/conf-available
  elif [ -d /etc/httpd/conf.d ]; then AP_LAYOUT=rhel; AP_INC=/etc/httpd/conf.d
  else
    _r=$("$AP_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p' | sed -n 1p)
    [ -n "$_r" ] && [ -d "$_r/conf/extra" ] && { AP_LAYOUT=upstream; AP_INC="$_r/conf/extra"; }
  fi
  AP_UNIT=$AP_NAME.service
  if unit_active "$AP_UNIT" || [ -n "$(master_pid "$AP_NAME" /run/apache2/apache2.pid /var/run/apache2/apache2.pid /run/httpd/httpd.pid /var/run/httpd/httpd.pid)" ]; then AP_RUNNING=yes; fi
}
probe_litespeed() {
  OLS=0; OLS_MOD=""; OLS_LOADED=no; OLS_RUNNING=no; OLS_CONF=""
  if [ -x "$LSWS/bin/openlitespeed" ] || [ -x "$LSWS/bin/lshttpd" ] || { [ -z "${WHISPER_EDGE_LSWS_ROOT:-}" ] && have openlitespeed; }; then
    OLS=1
  fi
  [ "$OLS" = 1 ] || return 0
  [ -f "$LSWS/modules/mod_whisper_edge.so" ] && OLS_MOD="$LSWS/modules/mod_whisper_edge.so"
  OLS_CONF="$LSWS/conf/httpd_config.conf"
  [ -f "$OLS_CONF" ] && case "$(rd_file "$OLS_CONF")" in *"module mod_whisper_edge"*) OLS_LOADED=yes ;; esac
  for _u in lshttpd.service lsws.service; do unit_active "$_u" && { OLS_RUNNING=yes; OLS_UNIT=$_u; }; done
  [ -n "$(master_pid litespeed "$LSWS/logs/httpd.pid" /tmp/lshttpd/lshttpd.pid)" ] && OLS_RUNNING=yes
  : "${OLS_UNIT:=lshttpd.service}"
}

# ---- the resolver half and the keyed tier: their commands, as before ---------------------------------
# The default paths in a shipped unit, moved to this install's, as whole tokens and in one pass, so a
# --dir that itself contains a default path is never rewritten twice. Each moved path is a unit word
# (sd_word): a path with whitespace or a quote is quoted, % and $ doubled.
move_paths() {  # $1 = unit file name; prints the unit with its paths moved
  MP_S=$(sd_word "$ETC/state") MP_D=$(sd_word "$DIR") MP_E=$(sd_word "$ETC") awk '
    BEGIN { n = split("/etc/whisper-edge/state /var/lib/whisper-edge /etc/whisper-edge", from, " ")
            to[1] = ENVIRON["MP_S"]; to[2] = ENVIRON["MP_D"]; to[3] = ENVIRON["MP_E"] }
    { out = ""; rest = $0
      while (rest != "") {
        best = 0; at = 0
        for (i = 1; i <= n; i++) { p = index(rest, from[i]); if (p && (!at || p < at)) { at = p; best = i } }
        if (!best) { out = out rest; break }
        out = out substr(rest, 1, at - 1) to[best]; rest = substr(rest, at + length(from[best]))
      }
      print out }' "$HERE/$1"
}
keyed_cmd() { join_words "$1" "$SBIN/whisper-edge-refresh" --quiet --keyed-set --dir "$DIR" --base "$BASE"; }
# The zone refresh, for one zone: $2 is its origin, or %i in the unit template, which systemd fills in
# with the instance (the origin) and which no escaping may touch, so it is appended after the escaped
# words. --zone-file names the directory, and the refresh picks each zone's file inside it.
rpz_cmd() {  # $1 = sd_word or sh_word, $2 = the origin or %i
  _f=$1; _z=$2
  set -- "$SBIN/whisper-edge-refresh" --if-due --quiet --dir "$DIR" --zone-file "$ZDIR/"
  if [ -n "$NAMED_CONF" ]; then set -- "$@" --named-conf "$NAMED_CONF"; fi
  printf '%s --zone %s' "$(join_words "$_f" "$@" --base "$BASE")" "$_z"
}

# ---- BIND: the policy zones and where they live, as before -------------------------------------------
#
# The policy zones, in the order named should consult them (first match wins, so an operator's own
# zones go above these): reputation, then RPKI-unreachable, which is logged rather than enforced by
# default (`policy disabled log yes`) because a route that comes back is still blocked for REFRESH
# plus a TTL in every resolver cache. Each has its own file and its own timer instance.
NAMED_DIR=""; NAMED_GROUP=""; NAMED_USER=""; ZDIR=""
ZONES="rpz.whisper.online rpz-rpki-unreachable.whisper.online"
zone_file() { if [ "$1" = rpz.whisper.online ]; then printf '%s/rpz.zone' "$ZDIR"; else printf '%s/%s.zone' "$ZDIR" "$1"; fi; }
NAMED=0
if command -v named >/dev/null 2>&1; then
  NAMED=1
  NAMED_USER="$(resolve_user named named bind named)"
  [ -n "$NAMED_USER" ] && NAMED_GROUP="$(id -gn "$NAMED_USER" 2>/dev/null || true)"
  # The zone goes under named's OWN directory, because that is the one tree a confined named may
  # read: Ubuntu's AppArmor profile allows /etc/bind, /var/lib/bind and /var/cache/bind and nothing
  # else, and SELinux on RHEL labels /var/named for it. A zone anywhere else is refused with a
  # "permission denied" in named's log and nothing on the terminal, and the policy never loads.
  NAMED_DIR="$(named-checkconf -p ${NAMED_CONF:+"$NAMED_CONF"} 2>/dev/null \
    | sed -n 's/^[[:space:]]*directory[[:space:]]\{1,\}"\([^"]*\)";.*/\1/p' | head -1)"
  if [ -z "$NAMED_DIR" ]; then
    for d in /var/cache/bind /var/named; do [ -d "$d" ] && { NAMED_DIR="$d"; break; }; done
  fi
  ZDIR="${NAMED_DIR:-$DIR}/whisper-edge"
fi

# ---- the manifest, read the one way the refresh reads it ---------------------------------------------
#
# The verdict on one plane: "PLANE <sha256> <bytes> <cadenceSeconds>", "WITHHELD <reasons>" or "ABSENT".
# The reasons are rendered exactly as the refresh renders them (the list joined with ", ", else the
# singular reason, else "-"; control characters and Unicode spaces made spaces), and the install gate
# holds the two renderings equal over the same edge manifests.
manifest_entry() {
  if have python3; then
    python3 - "$1" "$2" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
for e in m.get("planes") or []:
    if e.get("name") == sys.argv[2]:
        print("PLANE %s %s %s" % (e["sha256"], e["bytes"], e.get("cadenceSeconds") or "-")); sys.exit(0)
for w in m.get("withheld") or []:
    if w.get("name") == sys.argv[2]:
        def r(v):
            return v if isinstance(v, str) else json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        def norm(t):
            sp = lambda c: (c <= 32 or 127 <= c <= 160 or c == 0x1680 or 0x2000 <= c <= 0x200A
                            or c in (0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF))
            t = "".join(" " if sp(ord(ch)) else ch for ch in t)
            return " ".join(x for x in t.split(" ") if x)
        rs = w.get("reasons")
        if isinstance(rs, list) and rs:
            why = ", ".join(r(x) for x in rs)
        elif w.get("reason") is None or w.get("reason") == "":
            why = "-"
        else:
            why = r(w.get("reason"))
        print("WITHHELD %s" % norm(why)); sys.exit(0)
print("ABSENT")
PY
  elif have jq; then
    jq -r --arg p "$2" '
      ([.planes[]? | select(.name == $p) | "PLANE \(.sha256) \(.bytes) \(.cadenceSeconds // "-")"] +
       [.withheld[]? | select(.name == $p)
        | def r: if type == "string" then . else tojson end;
          def norm: explode | map(if (. <= 32) or (. >= 127 and . <= 160) or . == 5760
                                    or (. >= 8192 and . <= 8202) or . == 8232 or . == 8233 or . == 8239
                                    or . == 8287 or . == 12288 or . == 65279 then 32 else . end)
                    | implode | split(" ") | map(select(. != "")) | join(" ");
          "WITHHELD " + ((if ((.reasons | type) == "array") and ((.reasons | length) > 0)
                          then (.reasons | map(r) | join(", "))
                          elif (.reason == null) or (.reason == "") then "-"
                          else (.reason | r) end) | norm)] +
       ["ABSENT"])[0]' "$1"
  else
    return 2
  fi
}
# A plane file's own facts, from its header, as the refresh reads them: generation at byte 16 and
# valid-until at byte 32 (epoch ms, 0 for no bound), little-endian.
le_u64() { od -An -v -t u1 -j "$2" -N 8 "$1" 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) b[n++] = $i } END { if (n == 8) { v = 0; for (i = 7; i >= 0; i--) v = v * 256 + b[i]; printf "%.0f\n", v } }'; }
utc_ms() {
  case "$1" in ''|*[!0-9]*) echo "unreadable"; return 0 ;; 0) echo "no bound"; return 0 ;; esac
  date -u -d "@$(($1 / 1000))" +%Y-%m-%dT%H:%MZ 2>/dev/null || echo "$1 ms"
}
in_window() { # <file>: its header parses, and now is before its valid-until
  [ "$(head -c 8 "$1" 2>/dev/null)" = WEDGSNP1 ] || return 1
  _vu=$(le_u64 "$1" 32); [ -n "$_vu" ] || return 1
  [ "$_vu" = 0 ] || [ "$(date +%s)" -lt "$((_vu / 1000))" ]
}
# re-said from the refresh's own line: "(generation G, B bytes, digest16 X, valid until T)"
fact() { printf '%s\n' "$1" | sed -n "s/.*$2 \([^,)]*\).*/\1/p" | sed -n 1p; }

# ---- 1. the lock; an interrupted run's leftovers ----------------------------------------------------------
# Every file this run copies from the checkout or runs from it (the refresh and the unit sources; the
# tools are checked where they are built) passes the same ownership test before anything is written; a
# dry run runs the checkout's refresh too, so it is held to the same test. The test is root's: a run as
# another user copies and runs nothing with more than that user's own rights.
if [ "$(id -u)" = 0 ]; then
  for _hf in "$HERE"/whisper-edge-refresh "$HERE"/whisper-edge-*.service "$HERE"/whisper-edge-*.timer; do
    [ -e "$_hf" ] || continue
    tree_ok "$_hf" || { echo "install.sh: $_hf, or a directory above it in the checkout, is owned by an account other than root or you, or is writable by a group or others; root will not copy or run it; nothing was written" >&2; exit 1; }
  done
fi
if [ "$DRY" = 0 ]; then take_lock; sweep; fi

# ---- 2. the probe ---------------------------------------------------------------------------------------
probe_nginx; probe_apache; probe_litespeed
NGINX_USER=""; APACHE_USER=""; OLS_USER=""
[ "$NGX" = 1 ] && NGINX_USER="$(resolve_user nginx nginx www-data nginx http)"
[ "$AP" = 1 ] && APACHE_USER="$(resolve_user apache "$AP_NAME" www-data apache httpd)"
[ "$OLS" = 1 ] && OLS_USER="$(resolve_user litespeed litespeed nobody)"

# Every arm the run may apply, and every missing binary first, each with its one-command fix.
ARMS=""; MISSING=""
arm_missing() { # <server> <the module file> <where it was looked for> <the fix>
  MISSING="$MISSING $1"
  rep detected "$1: the module is not installed ($2 is in none of $3); build it and run this again: $4"
}
if wanted nginx && [ "$NGX" = 1 ]; then
  if [ -n "$NGX_MOD" ] || [ "$NGX_LOADED" = yes ]; then ARMS="$ARMS nginx"
  else arm_missing nginx ngx_http_whisper_edge_module.so "$NGX_MODS" "$CHECKOUT/nginx/build.sh --install"; fi
fi
if wanted apache && [ "$AP" = 1 ]; then
  if [ -n "$AP_MOD" ] || [ "$AP_LOADED" = yes ]; then ARMS="$ARMS apache"
  else arm_missing Apache mod_whisper_edge.so "$AP_MODS" "$CHECKOUT/apache/build.sh --install"; fi
fi
if wanted litespeed && [ "$OLS" = 1 ]; then
  if [ -n "$OLS_MOD" ]; then ARMS="$ARMS litespeed"
  else arm_missing OpenLiteSpeed mod_whisper_edge.so "$LSWS/modules" "$CHECKOUT/litespeed/build.sh --install"; fi
fi
for s in $WANT; do
  case "$s" in
    nginx) [ "$NGX" = 1 ] || rep detected "nginx: not installed here, so --server nginx applies to nothing" ;;
    apache) [ "$AP" = 1 ] || rep detected "Apache: not installed here, so --server apache applies to nothing" ;;
    litespeed) [ "$OLS" = 1 ] || rep detected "OpenLiteSpeed: not installed here (looked in $LSWS), so --server litespeed applies to nothing" ;;
  esac
done
ARMS=${ARMS# }
[ "$NGX" = 1 ] && rep detected "nginx ${NGX_VER:-(version unknown)} at $NGX_BIN, module ${NGX_MOD:-missing} (loaded: $NGX_LOADED, running: $NGX_RUNNING), runs as ${NGINX_USER:-<unknown>}"
[ "$AP" = 1 ] && rep detected "Apache ${AP_VER:-(version unknown)} at $AP_BIN, module ${AP_MOD:-missing} (loaded: $AP_LOADED, running: $AP_RUNNING), runs as ${APACHE_USER:-<unknown>}"
[ "$OLS" = 1 ] && rep detected "OpenLiteSpeed at $LSWS, module ${OLS_MOD:-missing} (loaded: $OLS_LOADED, running: $OLS_RUNNING), runs as ${OLS_USER:-<unknown>}"
[ "$NAMED" = 1 ] && rep detected "BIND (named) runs as ${NAMED_USER:-<unknown>}, zones under ${NAMED_DIR:-<unknown>}"
WEB=0; { [ "$NGX" = 1 ] || [ "$AP" = 1 ] || [ "$OLS" = 1 ]; } && WEB=1
# which case this box is: the planes are fetched only where something will read them
if [ "$WEB" = 0 ] && [ "$NAMED" = 0 ]; then
  CASE=staging
  rep detected "no web server and no BIND here: the feed is staged and kept fresh, and nothing else is written; the server arms when it arrives and this is run again"
elif [ "$WEB" = 0 ]; then
  CASE=resolver
  rep detected "BIND alone: the resolver half is installed, and no plane is fetched (nothing on this box reads one)"
elif [ -z "$ARMS" ]; then
  CASE=nomodule
  rep detected "no web server here has its module, so no plane is fetched and nothing is applied until one does"
else
  CASE=apply
fi
FETCH=0; case "$CASE" in staging|apply) FETCH=1 ;; esac
# a hard link to an armed plane can change what the workers serve; the immutable attribute already makes
# linking to one fail, so this is said, never a stop (the sysctl is global, and often read-only here)
HL=$(cat "$HARDLINKS" 2>/dev/null || echo unreadable)
[ "$HL" = 1 ] || rep detected "fs.protected_hardlinks is $HL, not 1: a hard link to an armed plane file can change what the workers serve; the immutable attribute on each plane refuses that link, and setting the sysctl to 1 refuses it everywhere"
# the tools the fetch needs, named before any fetch
[ "$FETCH" = 0 ] || have python3 || have jq || stop detected "reading the signed manifest needs python3 or jq; install one (apt install python3, dnf install python3, apk add python3) and run again"
have openssl || stop detected "verifying the feed needs openssl; install it and run again"
have curl || stop detected "fetching the feed needs curl; install it and run again"

# ---- 3. the feed half: directories, the signing key (fetched once), the refresh ------------------------
#
# The planes are world-readable on purpose: they are public files and every worker reads them. The
# counters directory is the one each server must write: setfacl where available, because two servers on
# one host need two writers and a single chown cannot express that; group-writable otherwise, said aloud.
mkd() { # <dir> [install -d options]: created, or said
  _d=$1; shift
  if [ "$DRY" = 1 ]; then [ -d "$_d" ] || rep applied "would create $_d"; return 0; fi
  install -d "$@" "$_d"
}
# root writes the key and the planes into $DIR by path, so the directory above it must be root's alone,
# as the configuration directories are (C1); $DIR itself is made here, or must be root's alone too
if [ "$DRY" = 0 ]; then
  chain_root "$(dirname -- "$DIR")" || stop applied "$(dirname -- "$DIR"), the directory above $DIR, is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others); name a data directory under one that is"
  if [ -e "$DIR" ] || [ -L "$DIR" ]; then chain_root "$DIR" || stop applied "$DIR is not root's alone (owned by another account, a link, or writable by a group or others)"; fi
fi
mkd "$DIR" -m 0755
mkd "$DIR/counters" -m 0755
# SELinux: a confined web server (httpd_t, which nginx and Apache run as when systemd starts them) may
# read var_lib_t but not map it, so a plane under the default label leaves the module inert (measured on
# RHEL 9, enforcing: "denied { map } ... tcontext=...var_lib_t"). Nor may it unlink var_lib_t, so under the
# default label counters/ takes each worker's first status file and refuses every rewrite after it, the
# rename over the old file (measured on Rocky 9.8, enforcing: "denied { unlink } comm=httpd ... var_lib_t",
# every status left at tick 0). Two file context rules for exactly this directory, never a global boolean:
# the planes httpd_sys_content_t (read and map, never write), counters/ httpd_var_lib_t (create, write,
# rename, unlink: the worker's own state). Each rule is recorded before it is added, so the shared undo
# line removes the rules it added and nothing else; a rule the operator already has for a spec is kept.
# The refresh relabels each plane it renames in; a file the worker makes in counters/ takes its label.
SE_ON=0; command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null && SE_ON=1
SE_DIRX=$(printf '%s' "$DIR" | sed 's/[][\\.*^$+?(){}|]/\\&/g')
SE_SPEC="$SE_DIRX/[^/]+\\.bin"
SE_TYPE=httpd_sys_content_t
SE_CSPEC="$SE_DIRX/counters(/.*)?"
SE_CTYPE=httpd_var_lib_t
_serec="$ETC/selinux-fcontext.added"
# relabel the directory to what policy now says; a plane is immutable once installed (chattr +i), and a
# relabel of an immutable file fails, so each such file is opened for the relabel and closed again. The
# same text runs here and in the printed undo line (with $1 the directory).
SE_RELABEL='restorecon -R -- "$1" 2>/dev/null; for f in "$1"/*.bin; do [ -f "$f" ] || continue; case "$(lsattr -d -- "$f" 2>/dev/null)" in ????i*) chattr -i -- "$f" 2>/dev/null && { restorecon -- "$f" 2>/dev/null; chattr +i -- "$f" 2>/dev/null; } ;; esac; done; :'
se_relabel_dir() { sh -c "$SE_RELABEL" sh "$1"; }
SE_ADDED=""   # the specs this run added, taken back if every server it applied to was refused
se_rule() { # <spec> <type> <what it labels> <why>: add the rule unless one for the spec is there, recorded first
  # the spec through the environment: awk's -v would read its backslashes as escapes (gawk says so on
  # stderr, which reached the report), so the rule this run added would never read as present
  if semanage fcontext -l -C 2>/dev/null | S="$1" awk '$1 == ENVIRON["S"] { f = 1 } END { exit !f }'; then
    if [ -f "$_serec" ] && grep -qxF -- "$1" "$_serec"; then rep applied "already present: the SELinux file context for $1 ($2)"
    else rep applied "kept your SELinux file context for $1: $(semanage fcontext -l -C 2>/dev/null | S="$1" awk '$1 == ENVIRON["S"] { print $NF; exit }')"; fi
    return 0
  fi
  # the record first, one rule a line: a run interrupted between the two still leaves the undo able to
  # find its rule, and a run with another --dir adds its own beside it. The record as it was is kept
  # (bytes and mtime) before this run's first line, so a take-back leaves it exactly as found.
  if [ -z "$SE_ADDED" ]; then if [ -f "$_serec" ]; then cp -p -- "$_serec" "$RT/serec.orig"; else rm -f -- "$RT/serec.orig"; fi; fi
  printf '%s\n' "$1" >> "$_serec"
  if ! _se=$(semanage fcontext -a -t "$2" "$1" 2>&1); then
    grep -vxF -- "$1" "$_serec" > "$_serec.new" 2>/dev/null || :; mv -f "$_serec.new" "$_serec"; [ -s "$_serec" ] || rm -f "$_serec"
    stop applied "could not add the SELinux file context for $3 (semanage fcontext -a -t $2 '$1': $(printf '%s' "$_se" | ctl_strip | head -1 | cut -c1-200))"
  fi
  SE_ADDED="$SE_ADDED$1
"
  rep applied "labelled $3 $2 (semanage fcontext -a -t $2 '$1'), $4; the shared undo line removes this rule"
}
if [ "$SE_ON" = 1 ]; then
  if [ "$DRY" = 1 ]; then
    rep applied "would label the planes in $DIR $SE_TYPE (semanage fcontext -a -t $SE_TYPE '$SE_SPEC'), so a confined server can map them"
    rep applied "would label $DIR/counters $SE_CTYPE (semanage fcontext -a -t $SE_CTYPE '$SE_CSPEC'; restorecon -R $DIR), so a confined worker can rewrite its own status"
  else
    command -v semanage >/dev/null 2>&1 || stop applied "SELinux is enabled here, and a confined web server (httpd_t) can read a plane under $DIR's default label but not map it, so the module would be inert; labelling the planes needs semanage: install policycoreutils-python-utils (dnf install policycoreutils-python-utils), then run this again"
    se_rule "$SE_SPEC" "$SE_TYPE" "the planes in $DIR" "so a confined server maps them, and writes none"
    se_rule "$SE_CSPEC" "$SE_CTYPE" "$DIR/counters" "so a confined worker rewrites its own status and counts there"
    se_relabel_dir "$DIR"
  fi
fi
_seen=""
# the users of the servers this run applies to (every detected one when it applies to none, as staging)
_cu=""
for _a in $ARMS; do case "$_a" in nginx) _cu="$_cu $NGINX_USER" ;; apache) _cu="$_cu $APACHE_USER" ;; litespeed) _cu="$_cu $OLS_USER" ;; esac; done
[ -n "$_cu" ] || _cu="$NGINX_USER $APACHE_USER $OLS_USER"
for u in $_cu; do
  [ -n "$u" ] || continue
  case " $_seen " in *" $u "*) continue ;; esac
  _seen="$_seen $u"
  if [ "$DRY" = 1 ]; then rep applied "would make $DIR/counters writable by $u"; continue; fi
  if have setfacl; then
    setfacl -m "u:$u:rwx" -m "d:u:$u:rwx" "$DIR/counters"
    rep applied "counters: $DIR/counters writable by $u (ACL)"
  else
    chgrp "$(id -gn "$u")" "$DIR/counters"; chmod 0775 "$DIR/counters"
    rep applied "counters: $DIR/counters group-writable by $u (no setfacl on this host; install acl for per-user grants)"
  fi
done
# The keyed tier's state directory: root-owned, 0755, the only part of $ETC the keyed timer may write.
# It holds the module's high-water mark, so configuration management must leave it unmanaged.
mkd "$ETC" -o 0 -g 0 -m 0755
mkd "$ETC/state" -o 0 -g 0 -m 0755
if [ -e "$ETC/key" ] && [ -n "$(find "$ETC/key" -perm /044 2>/dev/null)" ]; then
  # The timer refuses such a key and never changes its mode; the installer, run by a person, does.
  if [ "$DRY" = 1 ]; then rep applied "would make $ETC/key 0600: it is readable by its group or by others"
  else
    chmod 0600 "$ETC/key"
    rep applied "$ETC/key was readable by its group or by others, now 0600: it may have been read by another user; revoke it with whisper-edge-refresh --unenroll and enrol again"
  fi
fi
if [ -n "$ZDIR" ]; then
  # Root-owned: the zone unit runs as root with NO capabilities, and root without CAP_DAC_OVERRIDE cannot
  # write a directory it does not own. `install -d` alone keeps an existing owner, so the owner is set.
  mkd "$ZDIR" -o 0 -g 0 -m 0755
fi

# The signing key, fetched ONCE. A refresh must never re-fetch it: verifying the feed against a key the
# feed just served is a round trip, not a verification. A dry run verifies against the installed key when
# there is one, and fetches one into its own temporary directory only on a box that has none.
KEY="$DIR/edge.pub"
PIN=""
if [ -n "${WHISPER_EDGE_RESOLVE:-}" ]; then PIN="$WHISPER_EDGE_RESOLVE"; fi
fetch() { # <path under the base> <file>
  # shellcheck disable=SC2086 # CURL_PROTO is two options, split on purpose
  curl -q -fsS $CURL_PROTO --max-time 120 ${PIN:+--resolve "$PIN"} -H 'Cache-Control: no-cache' -o "$2" "$BASE/$1"
}
[ "${BASE%%://*}" = http ] && rep applied "the feed is fetched over plain http: its signatures are verified against the key you pinned (--key-sha256), which is what this run trusts"
if [ -s "$KEY" ]; then
  # an installed key is trusted only when it is the pinned one: a key planted by anyone else is refused
  [ "$(sha256_of < "$KEY")" = "$KEY_SHA" ] \
    || stop applied "the installed signing key $KEY is not the pinned key (sha256 $KEY_SHA); if you did not put it there, remove it (rm $KEY) and run this again"
  KEYSAID="the installed key $KEY"
  rep applied "signing key: already present at $KEY, and it is the pinned key, left alone"
elif [ "$DRY" = 1 ]; then
  KEY="$RT/edge.pub"; KEYSAID="a key fetched from $BASE for this dry run (none is installed here yet)"
  if ! fetch edge-signing-key.pub "$KEY" 2>/dev/null; then
    rep armed "could not fetch the signing key from $BASE, so nothing below could be verified"
    KEY=""; DRY_FAIL=1
  elif [ "$(sha256_of < "$KEY")" != "$KEY_SHA" ]; then
    rep armed "the signing key $BASE serves is not the pinned key (sha256 $KEY_SHA): a real run would refuse it"
    KEY=""; DRY_FAIL=1
  fi
else
  _e=$(fetch edge-signing-key.pub "$KEY.new" 2>&1) || { rm -f "$KEY.new"; stop applied "could not fetch the signing key from $BASE/edge-signing-key.pub: $(printf '%s' "$_e" | sed -n 1p | ctl_strip)"; }
  if [ "$(sha256_of < "$KEY.new")" != "$KEY_SHA" ]; then
    rm -f "$KEY.new"
    stop applied "the signing key $BASE/edge-signing-key.pub serves is not the pinned key (sha256 $KEY_SHA); nothing was installed"
  fi
  chmod 0644 "$KEY.new"; mv -f "$KEY.new" "$KEY"
  KEYSAID="the key fetched from $BASE"
  rep applied "signing key: fetched from $BASE/edge-signing-key.pub into $KEY (once; a refresh never re-fetches it)"
fi
REFRESH="$SBIN/whisper-edge-refresh"
if [ "$DRY" = 1 ]; then
  if cmp -s "$HERE/whisper-edge-refresh" "$REFRESH" 2>/dev/null; then rep applied "already present: $REFRESH"; else rep applied "would install $REFRESH"; fi
  REFRESH="$HERE/whisper-edge-refresh"
elif cmp -s "$HERE/whisper-edge-refresh" "$REFRESH" 2>/dev/null; then
  rep applied "already present: $REFRESH"
else
  install -d -m 0755 "$SBIN"
  # as the tools are: into a directory root alone can write, through a temp mktemp names, root's own file
  chain_root "$SBIN" || stop applied "$SBIN is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others); the refresh is not installed there"
  _rt=$(mktemp "$SBIN/.whisper-edge.XXXXXXXXXX")
  { install -o 0 -g 0 -m 0755 "$HERE/whisper-edge-refresh" "$_rt" && mv -f -T "$_rt" "$REFRESH"; } || { rm -f "$_rt"; stop applied "could not install $REFRESH"; }
  rep applied "refresh: installed $REFRESH (verify, then atomic replace; it never reloads a web server)"
fi

# ---- 4. arm the data: every plane the policy reads, fetched and verified BEFORE any configuration test --
#
# The run reads the signed manifest itself, so it knows what the feed states about each plane, and then
# lets the refresh fetch each one exactly as its timer will. A plane whose file is absent when a server
# reads its configuration stays inert in the running workers until the next reload, whatever the timer
# does, so the file must be there first. Each plane ends in exactly one state, said in plain words:
#   armed     the file is in place and verified: its generation, digest16 and valid-until
#   withheld  the signed manifest withholds it, and says why: its rules are inert at launch
#   absent    the manifest names no such plane: its rules are inert at launch
#   failed    the manifest publishes it and the fetch left no file, or left a file the manifest has moved
#             past: the run stops here, before any configuration is touched
#   kept      a prior file, and this fetch failed: valid data still arms the rule (fail open), said with
#             exactly what was proven about it, never "verified"
MANIFEST=""; MANIFEST_OK=0
if [ -n "$KEY" ] && { [ "$FETCH" = 1 ] || [ "$DRY" = 1 ]; }; then
  if fetch manifest.json "$RT/manifest.json" 2>/dev/null; then
    _msha=$(sha256_of < "$RT/manifest.json")
    if fetch "manifests/$_msha.sig" "$RT/manifest.sig" 2>/dev/null \
       && openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin -in "$RT/manifest.json" -sigfile "$RT/manifest.sig" >/dev/null 2>&1; then
      MANIFEST="$RT/manifest.json"; MANIFEST_OK=1
    elif [ -s "$RT/manifest.sig" ]; then
      [ "$DRY" = 1 ] && { rep armed "the signed manifest did not verify against $KEYSAID: a real run would refuse it"; DRY_FAIL=1; }
      MANIFEST_OK=2
    fi
  fi
  [ "$MANIFEST_OK" = 0 ] && { rep armed "the signed manifest could not be fetched from $BASE"; DRY_FAIL=1; }
fi
pv() { printf '%s' "$1" | tr -c 'A-Za-z0-9\n' _; }   # a plane name as a variable name
ARMED_BYTES=0; ARMED=""; INERT=""
inert_words() { # <plane>: the rules that read it, inert, and when they arm
  printf '%s is inert at launch; it arms at the next reload after the refresh first installs %s.bin: when it does, run this installer again, which re-sizes the memory lock, tests and reloads' \
    "$(plane_rule "$1")" "$1"
}
arm_bytes() { ARMED_BYTES=$((ARMED_BYTES + $2)); ARMED="$ARMED $1"; eval "BYTES_$(pv "$1")=\$2"; }
arm_plane() { # <plane>
  _p=$1; _f="$DIR/$_p.bin"
  _verdict=""
  [ "$MANIFEST_OK" = 1 ] && _verdict=$(manifest_entry "$MANIFEST" "$_p" 2>/dev/null || true)
  case "$_verdict" in PLANE*) cadence_bound "$_p" "$(printf '%s' "$_verdict" | cut -d' ' -f4)" ;; esac
  eval "_ref=\${REFUSED_$(pv "$_p"):-}"
  if [ -n "$_ref" ]; then
    rep armed "$_p is published, but $_ref; no schedule is written for it and nothing is fetched; $(plane_rule "$_p") is inert at launch"
    INERT="$INERT $_p"; NOSCHED="${NOSCHED:-} $_p"
    plane_denies "$_p" && stop armed "$_p cannot be kept fresh, so its deny rules would read a stale plane; nothing is applied"
    return 0
  fi
  if [ "$DRY" = 1 ]; then
    case "$_verdict" in
      PLANE*) set -- $_verdict
              if [ -f "$_f" ] && [ "$(sha256_of < "$_f")" = "$2" ]; then
                rep armed "$_p already current: $_f, generation $(le_u64 "$_f" 16), digest $(printf '%s' "$2" | cut -c1-16), valid until $(utc_ms "$(le_u64 "$_f" 32)") (verified against $KEYSAID)"
              else
                rep armed "would install $_p.bin ($3 bytes, digest $(printf '%s' "$2" | cut -c1-16), published in the manifest verified against $KEYSAID)"
              fi
              ARMED_BYTES=$((ARMED_BYTES + $3)); ARMED="$ARMED $_p"; eval "BYTES_$(pv "$_p")=\$3" ;;
      WITHHELD*) rep armed "would leave $_p withheld by the signed manifest (${_verdict#WITHHELD }); $(inert_words "$_p")"; INERT="$INERT $_p" ;;
      ABSENT) rep armed "would leave $_p absent: the manifest names no such plane; $(inert_words "$_p")"; INERT="$INERT $_p" ;;
      *) rep armed "$_p: its state could not be read, because the manifest above could not be verified" ;;
    esac
    return 0
  fi
  _out=$("$REFRESH" --plane "$_p" --dir "$DIR" --base "$BASE" 2>&1) && _rc=0 || _rc=$?
  if [ "$_rc" = 0 ]; then
    case "$_out" in
      *"is withheld ("*)
        _why=$(printf '%s\n' "$_out" | sed -n 's/.* is withheld (\(.*\); details: .*/\1/p' | sed -n 1p)
        rep armed "$_p withheld by the signed manifest: ${_why:--}; $(inert_words "$_p")"; INERT="$INERT $_p"; return 0 ;;
      *"names no $_p plane"*)
        rep armed "$_p: the manifest names no such plane; $(inert_words "$_p")"; INERT="$INERT $_p"; return 0 ;;
    esac
    if [ -f "$_f" ]; then
      _ln=$(printf '%s\n' "$_out" | grep -E "installed $_p\.bin|$_p\.bin unchanged|$_p\.bin: generation" | sed -n 1p)
      _gen=$(le_u64 "$_f" 16); _vu=$(le_u64 "$_f" 32)
      rep armed "$_p armed, generation $_gen, digest $(fact "$_ln" digest16), valid until $(utc_ms "$_vu") ($_f, verified against $KEYSAID)"
      case "$_ln" in *"first install of this plane"*) rep armed "$_p.bin was installed for the first time: it binds when the server reads its configuration, which this run does next" ;; esac
      arm_bytes "$_p" "$(wc -c < "$_f" | tr -d ' ')"
      return 0
    fi
  fi
  # the fetch failed: what the refresh said, and what a prior file can still prove
  quoted armed "refresh:" "$(printf '%s\n' "$_out" | grep -v '^$' | tail -n 2)"
  case "$_verdict" in
    WITHHELD*|ABSENT) rep armed "$_p: the manifest does not publish it, and the refresh failed; $(inert_words "$_p")"; INERT="$INERT $_p"; return 0 ;;
  esac
  if [ -f "$_f" ]; then
    _self=$(sha256_of < "$_f"); _gen=$(le_u64 "$_f" 16); _vu=$(le_u64 "$_f" 32)
    case "$_verdict" in
      PLANE*)
        set -- $_verdict
        if [ "$_self" = "$2" ]; then
          rep armed "$_p kept, generation $_gen, digest $(printf '%s' "$_self" | cut -c1-16) (computed here over the file), valid until $(utc_ms "$_vu"): this fetch failed, and the installed file matches the signed manifest"
          arm_bytes "$_p" "$(wc -c < "$_f" | tr -d ' ')"; return 0
        fi
        stop armed "$_p: this fetch failed, and the installed $_f is not the plane the signed manifest now states (its bytes have been moved past); nothing is applied, and the servers keep what they already serve" ;;
    esac
    if [ "$MANIFEST_OK" != 1 ] && in_window "$_f"; then
      rep armed "$_p kept, generation $_gen, digest $(printf '%s' "$_self" | cut -c1-16) (computed here over the file), valid until $(utc_ms "$_vu"): the manifest could not be fetched either, and the file's header parses and it is inside its own window; that is all that is proven about it"
      arm_bytes "$_p" "$(wc -c < "$_f" | tr -d ' ')"; return 0
    fi
    plane_denies "$_p" && stop armed "$_p: this fetch failed and the installed $_f is outside its own validity window; nothing is applied"
    rep armed "$_p: this fetch failed and the installed file is outside its window; $(inert_words "$_p")"; INERT="$INERT $_p"; return 0
  fi
  if [ "${_verdict%% *}" = PLANE ]; then
    stop armed "$_p is published but this fetch left no file, so its rules would be inert; nothing is applied (the refresh's own line is above)"
  fi
  # the seventh state: no file, and no manifest to say what the feed states about the plane. A plane only
  # log rules read can block no one, so the run goes on with it inert; one a deny rule reads stops it.
  plane_denies "$_p" && stop armed "$_p: no file, and the manifest could not be read, so its deny rules would be inert; nothing is applied (the refresh's own line is above); run sudo $HERE/install.sh again once $BASE is reachable"
  rep armed "$_p: no file, and the manifest could not be read; $(inert_words "$_p")"; INERT="$INERT $_p"
}
if [ "$FETCH" = 1 ] || { [ "$DRY" = 1 ] && [ "$CASE" != resolver ] && [ "$CASE" != nomodule ]; }; then
  for p in $PLANES; do arm_plane "$p"; done
  [ "$CASE" = staging ] && rep armed "no web configuration to reconcile the planes against yet: the fetch above proved the feed; staged:${ARMED:- none}"
elif [ "$CASE" = nomodule ]; then
  rep armed "no plane fetched: no web server here can read one until its module is installed"
fi
ARMED=${ARMED# }; INERT=${INERT# }

display() { case "$1" in nginx) echo nginx ;; apache) echo Apache ;; litespeed) echo OpenLiteSpeed ;; *) echo "$1" ;; esac; }

# ---- 5. apply ---------------------------------------------------------------------------------------------
#
# Every file below is new, in a directory the distribution's own configuration already reads; each is
# written through put() (temp and rename, stamped first, never over a file the installer cannot prove it
# wrote). The memory lock is computed from what was armed: twice the armed plane bytes per worker,
# because a swap locks the old image and the new one at once, and never below what the unit already has.
memlock_line() { # <server> <unit> -> sets ML_V, ML_E, ML_NEED; adds the line
  ML_NEED=$((2 * ARMED_BYTES)); ML_E=""; ML_V=""
  [ "$SYSTEMD" = 1 ] || { rep applied "$1: not run by systemd here, so no LimitMEMLOCK drop-in; give the server at least $ML_NEED bytes of locked memory (ulimit -l $(( (ML_NEED + 1023) / 1024 ))) where it starts, or the planes run evictable"; return 0; }
  ML_E=$(systemctl show "$2" -p LimitMEMLOCK --value 2>/dev/null || true)
  case "$ML_E" in
    infinity) rep applied "LimitMEMLOCK: $2 already allows unlimited locked memory, so no drop-in is needed"; ML_E=""; return 0 ;;
    ''|*[!0-9]*) rep applied "LimitMEMLOCK: could not read $2's effective limit, so no drop-in is written; it needs at least $ML_NEED bytes"; ML_E=""; return 0 ;;
  esac
  _d=""; for p in $ARMED; do eval "_b=\${BYTES_$(pv "$p"):-0}"; _d="$_d${_d:+ + }$p $_b"; done
  if [ "$ML_NEED" -gt "$ML_E" ]; then
    ML_V=$ML_NEED
    MEMLOCK_INPUTS="${MEMLOCK_INPUTS:-} memlock_$(pv "$2")=$ML_V,$ML_E,$ARMED_BYTES"
    rep applied "LimitMEMLOCK: $ML_E is $2's effective limit; twice the armed plane bytes (2 x (${_d:-nothing})) is $ML_NEED, above it, so the drop-in sets $ML_V; it takes effect at the service's next full start, not at this reload, and until then the planes run under the previous limit"
  else
    rep applied "LimitMEMLOCK: $ML_E is $2's effective limit; twice the armed plane bytes (2 x (${_d:-nothing})) is $ML_NEED, below it, so no drop-in is written (a drop-in takes effect at the service's next full start)"
  fi
}

# The per-plane refresh: one instance of the template per plane the policy reads, each with its own
# schedule, started now so it runs from the install rather than first at the next boot.
UNITS=0; [ "$TIMER" = 1 ] && have systemctl && UNITS=1
# the manager re-reads the units only where it runs; with no systemd up (a container, an image being
# built) the files and the enablement links are all there is, and both are written
sd_reload() { [ "$DRY" = 1 ] || [ "$SYSTEMD" = 0 ] || systemctl daemon-reload; }
INSTANCES=""
units_install() {
  write_artifact "$UNITDIR/whisper-edge-refresh@.service" "the per-plane refresh service" 0644 render_template_service \
    || stop applied "$UNITDIR/whisper-edge-refresh@.service is not a file this installer wrote; move it aside and run again"
  write_artifact "$UNITDIR/whisper-edge-refresh@.timer" "the per-plane refresh timer" 0644 render_template_timer \
    || stop applied "$UNITDIR/whisper-edge-refresh@.timer is not a file this installer wrote; move it aside and run again"
  [ "$1" = instances ] || return 0
  for p in $PLANES; do
    case " ${NOSCHED:-} " in *" $p "*) continue ;; esac
    write_artifact "$(cadence_dropin "$p")" "the $p plane's schedule" 0644 render_cadence "$p" \
      || stop applied "$(cadence_dropin "$p") is not a file this installer wrote; move it aside and run again"
    INSTANCES="$INSTANCES $p"
  done
}
units_enable() {
  sd_reload
  for p in $INSTANCES; do
    set -- $(cadence_of "$p"); set -- "$1" "$2" "$(printf '%s' "$3" | tr _ ' ' | sed 's/^every 60 min$/hourly/')"
    if [ "$DRY" = 1 ]; then rep applied "would enable whisper-edge-refresh@$p.timer ($3, jitter $2s)"; continue; fi
    if [ "$SYSTEMD" = 1 ]; then
      systemctl enable --now "whisper-edge-refresh@$p.timer" >/dev/null 2>&1 \
        || stop applied "could not enable whisper-edge-refresh@$p.timer: $(systemctl enable --now "whisper-edge-refresh@$p.timer" 2>&1 | sed -n 1p)"
      rep applied "enabled whisper-edge-refresh@$p.timer ($3, jitter $2s)"
    else
      systemctl enable "whisper-edge-refresh@$p.timer" >/dev/null 2>&1 \
        || stop applied "could not enable whisper-edge-refresh@$p.timer"
      rep applied "enabled whisper-edge-refresh@$p.timer ($3, jitter $2s); systemd is not running here, so it first fires when it is"
    fi
  done
}
plane_cmd() { printf '%s --plane %s --quiet %s' "$(sh_word "$REFRESH_AT")" "$1" "$(join_words sh_word --dir "$DIR" --base "$BASE")"; }
REFRESH_AT="$SBIN/whisper-edge-refresh"

# The block for one server, in the idiom it would have been written in, for the operator to add by hand.
paste() { printf '%s\n' "$@" >> "$RT/applied"; }   # shadows paste(1): never call that by name here
print_arm() { # <server> <why it is printed rather than applied>
  case "$1" in
    nginx)
      paste "" "  # nginx: the load line in the MAIN context, the rest inside http {}; then nginx -t and a reload ($2)"
      paste "  load_module ${NGX_MOD:-${NGX_MODS%% *}/ngx_http_whisper_edge_module.so};"
      paste "  http {"
      render_nginx_body | sed 's/^/      /' >> "$RT/applied"
      paste "  }" ;;
    apache)
      paste "" "  # Apache: one file the main configuration includes; then apachectl configtest and a graceful reload ($2)"
      if [ "$AP_LOADED" = yes ]; then render_apache_body; else render_apache_body "${AP_MOD:-${AP_MODS%% *}/mod_whisper_edge.so}"; fi \
        | sed 's/^/  /' >> "$RT/applied" ;;
    litespeed)
      paste "" "  # OpenLiteSpeed: at the top level of $OLS_CONF, then $LSWS/bin/lswsctrl restart ($2)"
      { render_litespeed_proxy; render_litespeed_body; } | sed 's/^/  /' >> "$RT/applied"
      paste "  # it starts in log mode: OpenLiteSpeed has no configuration test to prove a deny first; to deny, set whisper_edge_mode deny and restart" ;;
  esac
}

# The resolver half's and the keyed tier's units, rendered as before: each names the script path, the
# paths it writes and the feed base explicitly, so a host installed with --dir or --base refreshes the
# place it was told to. ReadWritePaths is the sandbox's one writable path and must be the same directory.
unit_plain() {  # $1 = unit file name, then sed expressions; RU_FROM=- reads the source from stdin
  _u="$1"; shift
  if [ "${RU_FROM:-}" = - ]; then cat > "$RT/unit.src"; _src="$RT/unit.src"; else _src="$HERE/$_u"; fi
  sed "$@" "$_src" > "$RT/unit.out"
  if cmp -s "$RT/unit.out" "$UNITDIR/$_u" 2>/dev/null; then rep applied "already present: $UNITDIR/$_u"; return 0; fi
  if [ "$DRY" = 1 ]; then
    # A dry run says the lines it would write, rendered by the same code, so what it shows is what you
    # would get; WHISPER_EDGE_DRY_UNITDIR also leaves each unit there whole, for a gate to read
    rep applied "would write $UNITDIR/$_u"
    grep -E '^(ExecStart|ExecStartPre|ReadWritePaths|SupplementaryGroups|Environment)=' "$RT/unit.out" \
      | while IFS= read -r _l; do rep applied "would write $UNITDIR/$_u: $_l"; done
    if [ -n "${WHISPER_EDGE_DRY_UNITDIR:-}" ]; then
      mkdir -p "$WHISPER_EDGE_DRY_UNITDIR" 2>/dev/null \
        || { echo "install.sh: cannot create WHISPER_EDGE_DRY_UNITDIR=$WHISPER_EDGE_DRY_UNITDIR for the rendered units" >&2; exit 2; }
      cp "$RT/unit.out" "$WHISPER_EDGE_DRY_UNITDIR/$_u"
    fi
    return 0
  fi
  cp "$RT/unit.out" "$UNITDIR/.$_u.new"; chmod 0644 "$UNITDIR/.$_u.new"; mv -f "$UNITDIR/.$_u.new" "$UNITDIR/$_u"
}
copy_plain() { # <unit file name>
  if cmp -s "$HERE/$1" "$UNITDIR/$1" 2>/dev/null; then rep applied "already present: $UNITDIR/$1"; return 0; fi
  if [ "$DRY" = 1 ]; then rep applied "would write $UNITDIR/$1"; return 0; fi
  install -m 0644 "$HERE/$1" "$UNITDIR/.$1.new"; mv -f "$UNITDIR/.$1.new" "$UNITDIR/$1"
}
dosys() { if [ "$DRY" = 1 ]; then rep applied "would run: $*"; else "$@" >/dev/null 2>&1 || stop applied "$* failed: $("$@" 2>&1 | sed -n 1p)"; fi; }

PERIOD_INPUTS=""
for p in $PLANES; do
  _pv=$(pv "$p"); eval "_pm=\${period_$_pv:-}"
  [ -n "$_pm" ] && PERIOD_INPUTS="$PERIOD_INPUTS period_$_pv=$_pm"
done
[ "$DRY" = 1 ] || stamp_open
case "$CASE" in
  apply|staging) PLANE_UNITS=instances ;;
  *) PLANE_UNITS=templates ;;
esac
if [ "$UNITS" = 1 ] && [ "$CASE" != resolver ]; then
  units_install "$PLANE_UNITS"
  units_enable
elif [ "$TIMER" = 1 ] && [ "$CASE" != resolver ] && [ "$PLANE_UNITS" = instances ]; then
  rep applied "no systemctl here, so no timer was installed; schedule each plane yourself, with the jitter its timer would have had:"
  for p in $PLANES; do
    set -- $(cadence_of "$p")
    case "$p" in
      reputation) rep applied "  0 * * * * sleep \$(shuf -i 0-899 -n 1) && $(cron_line "$(plane_cmd "$p")")" ;;
      *) case " ${NOSCHED:-} " in *" $p "*) continue ;; esac
         rep applied "  */$(($4 / 60)) * * * * sleep \$(shuf -i 0-299 -n 1) && $(cron_line "$(plane_cmd "$p")")" ;;
    esac
  done
elif [ "$TIMER" = 0 ]; then
  rep applied "--no-timer: nothing scheduled; run $REFRESH_AT --plane <name> yourself for each of: $PLANES"
fi
# A legacy snapshot timer from an earlier install keeps fetching a file nothing here reads now.
# An earlier installer's own timer (the tree's file, byte for byte) is disabled wherever this run fetches
# planes on its own timers (staging and apply), so two fetchers never race for the planes' directory, and
# the shared undo line re-enables it; one that is not the tree's is named. The disable is read back: the
# line says it was disabled only when systemd says so, and otherwise says what systemd answered.
if [ "$UNITS" = 1 ] && [ -e "$UNITDIR/whisper-edge-refresh.timer" ]; then
  if cmp -s "$HERE/whisper-edge-refresh.timer" "$UNITDIR/whisper-edge-refresh.timer" && [ "$FETCH" = 1 ]; then
    if systemctl is-enabled --quiet whisper-edge-refresh.timer 2>/dev/null; then
      if [ "$DRY" = 1 ]; then rep applied "would disable the earlier snapshot timer (it fetches snapshot.bin, which nothing here reads now)"
      else
        _ld=$(systemctl disable --now whisper-edge-refresh.timer 2>&1 | ctl_strip | tr '\n' ' ' | cut -c1-200) || :
        _le=$(systemctl is-enabled whisper-edge-refresh.timer 2>/dev/null || :)
        if systemctl is-enabled --quiet whisper-edge-refresh.timer 2>/dev/null; then
          rep applied "could not disable the earlier snapshot timer: systemd still reads it $_le after systemctl disable --now${_ld:+ ($_ld)}; two fetchers may race for $DIR until it is: systemctl disable --now whisper-edge-refresh.timer"
        else
          : > "$ETC/legacy-timer.disabled"
          rep applied "disabled the earlier snapshot timer (it fetched snapshot.bin, which nothing here reads now; systemd reads it ${_le:-disabled}); the shared undo line enables it again"
        fi
      fi
    fi
  else
    rep applied "the earlier snapshot timer is still installed and fetches snapshot.bin, which the default policy does not read; when nothing of yours reads it: systemctl disable --now whisper-edge-refresh.timer"
  fi
fi

# the planes' label read back once they are installed: what a confined server will be handed
if [ "$SE_ON" = 1 ] && [ "$DRY" = 0 ] && [ -f "$DIR/reputation.bin" ]; then
  se_relabel_dir "$DIR"
  _st=$(stat -c %C -- "$DIR/reputation.bin" 2>/dev/null | cut -d: -f3)
  [ "$_st" = "$SE_TYPE" ] \
    || rep applied "could not give the planes in $DIR the label $SE_TYPE (reputation.bin reads ${_st:-no label} after restorecon -R); a confined server will not map them: semanage fcontext -l | grep $DIR"
fi
# ---- 5b. the servers: the default policy written in each one's own idiom, tested, and reloaded on a pass --
#
# Per server: the operator's own whisper_edge lines read from the effective configuration (kept, never
# redefined); the server's own test on the configuration as it stands, before anything is written; the
# files written in an order in which every partial state is a configuration that still loads; the
# server's own test; a reload only on a pass. Every server command has a ceiling.
#
# From the first write into a server's configuration until its test has passed, that server's window is
# open: an error, INT, TERM or HUP in it takes this run's server writes back, in the reverse order, tests
# what is left and says so (finish() below). A SIGKILL is never seen by a trap: the stamp names every
# write, and the next run's sweep takes them back before it writes anything.
T_CMD=${WHISPER_EDGE_CMD_TIMEOUT:-120}
case "$T_CMD" in ''|*[!0-9]*) T_CMD=120 ;; esac
[ "$T_CMD" -ge 60 ] || T_CMD=60
# Every server command runs with the run's lock descriptor closed: a server a restart starts must never
# inherit it, or it would hold the lock for its whole life (measured: OpenLiteSpeed's restart did, and
# every later run read "another installer run is in progress").
tmo() { timeout --kill-after=10 "$T_CMD" "$@" 7>&-; }
WIN_SERVER=""; WIN_LIST=""; WIN_CAUSE=""
win_open() { WIN_SERVER=$1; WIN_LIST=""; ARM_REFUSED=""; }
win_add() { WIN_LIST="$*
$WIN_LIST"; }                                          # newest first: the rollback walks it in order
win_close() { win_prev_clean; WIN_SERVER=""; WIN_LIST=""; }
# the kept copies of replaced files, removed once the window closes with nothing left to put back
win_prev_clean() {
  printf '%s\n' "$WIN_LIST" | while IFS= read -r _w; do
    # shellcheck disable=SC2086
    set -- $_w
    if [ "${1:-}" = created ] && [ -n "${6:-}" ] && [ "$6" != - ]; then rm -f -- "$6"; fi
  done
  return 0
}
# a created entry whose put did not happen: its kept copy is gone, so the rollback must not restore from it
win_drop_prev() { # <target>
  WIN_LIST=$(printf '%s\n' "$WIN_LIST" | WE_AWK_t="$1" awk 'BEGIN { t = ENVIRON["WE_AWK_t"] } $1 == "created" && $2 == t { $6 = "-" } { print }')
}
# A refusal of one arm inside its open window (a path that is not the installer's, a directory that is not
# root's alone, an a2enconf that fails, an edit that cannot be made): that arm's writes are taken back, the
# arm is marked failed and the run goes on to the next arm. Only a signal or an error no line chose ends
# the whole run inside a window (exit 4); a refusal is exit 1, per arm.
arm_refuse() { # <line>
  _as=$WIN_SERVER
  win_rollback_quiet
  rep proved "$(display "$_as"): $1; removed what this run wrote (${ROLLED:-nothing}); its configuration is as it was"
  ARM_FAILED="$ARM_FAILED $_as"; win_close; ARM_REFUSED=1
}
# a write into a server's configuration: the rendering in $RT/new, recorded for the rollback by its digest
srv_put() { # <target> <what> <mode>
  _sha=$(sha256_of < "$RT/new")
  if [ -e "$1" ] && [ ! -L "$1" ] && cmp -s "$RT/new" "$1"; then rep applied "already present: $1 ($2)"; return 1; fi
  # a file of the installer's own that this write replaces: its bytes are kept first, so a refused test or
  # an interruption puts them back rather than leaving the server with none (a re-run that is refused
  # must leave the configuration that was serving, not remove it)
  _prev=-
  if [ -f "$1" ] && [ ! -L "$1" ] && is_ours "$1"; then
    _prev=$(mktemp "$UNDO/prev.XXXXXXXXXX") && rd_file "$1" > "$_prev" && [ -s "$_prev" ] \
      || { [ "$_prev" = - ] || rm -f -- "$_prev"; arm_refuse "could not keep a copy of $1 in $UNDO before replacing it; nothing was written"; return 2; }
    [ -n "$STAMPF" ] && stamp_line prev "$1" "$_prev" "$(stat -c %a -- "$1")"
  fi
  win_add created "$1" "$_sha" "$PUT_U" "$PUT_G" "$_prev" "$3"
  [ -n "$STAMPF" ] && stamp_line wrote "$1" "$_sha"
  put "$1" "$2" "$3" && _sr=0 || _sr=$?
  [ "$_sr" = 0 ] || [ "$_prev" = - ] || { rm -f -- "$_prev"; win_drop_prev "$1"; }
  case "$_sr" in
    0) rep applied "wrote $1 ($2, $(grep -c '' "$RT/new") lines)"; WROTE_SRV=1; return 0 ;;
    3) arm_refuse "$1 is not a file this installer wrote ($2); move it aside and run again"; return 2 ;;
    *) arm_refuse "$1: its directory is not root's alone, so the installer will not write there"; return 2 ;;
  esac
}
# The rollback, from what this run recorded: a created file removed while its bytes are still the ones
# this run wrote; a link removed while it still points where this run pointed it; an edited file restored
# from its kept copy while it is still this run's edit. Anything else is the operator's and is named.
win_rollback() { # <cause>: the trap's rollback, the test of what is left, and the line that says so
  _srv=$WIN_SERVER
  win_rollback_quiet
  if [ "$_srv" = litespeed ]; then
    _after="the previous configuration is back on disk"
    [ "${OLS_RESTARTED:-0}" = 1 ] && _after="$_after; the running server may still be on the edit until its next restart: $LSWS/bin/lswsctrl restart"
  else
  _t=$(srv_test "$_srv" 2>&1) && _tr=0 || _tr=$?
  if [ "$_tr" = 0 ]; then _after="the previous configuration is unchanged and passes its test"
  else _after="what is left does not pass its test: $(printf '%s' "$_t" | srv_refusal "$(srv_test_cmd "$_srv")" "$_tr")"; fi
  fi
  rep proved "$(display "$_srv"): interrupted after writing ${ROLLED:-nothing} ($1); removed; $_after"
  WIN_SERVER=""; WIN_LIST=""
  if [ -n "$STAMPF" ]; then rm -f "$STAMPF" || :; fi; STAMPF=""
}
# the server's refusing line; Apache's "AH00526: Syntax error on line N of <file>:" carries its reason on
# the line after it, so that one is joined on
# srv_refusal [<command> <exit>]: the server's own words for a refusal, from its output on stdin: the first
# line that names an error, else the first line it printed at all (RHEL's apachectl says "Passing
# arguments to httpd using apachectl is no longer supported." and nothing a keyword finds), else what was
# run and that it printed nothing. A refusal never reads as an empty reason.
srv_refusal() {
  _srw=$(ctl_strip | awk 'NF && first == "" { first = $0 }
    p != "" { print p " " $0; f = 1; exit }
    /emerg|\[crit\]|AH0|error|whisper edge/ { if ($0 ~ /:$/) { p = $0; next } print; f = 1; exit }
    END { if (!f && p != "") print p; else if (!f && first != "") print first }' | cut -c1-400)
  if [ -n "$_srw" ]; then printf '%s' "$_srw"; else printf '%s exited %s and printed nothing' "${1:-the command}" "${2:-non-zero}"; fi
}
srv_test_cmd() { # <server>: the test srv_test runs, as words for a report line
  case "$1" in nginx) echo "nginx ${NGX_ARGS:+$NGX_ARGS }-t" ;; apache) echo "$AP_CTL ${AP_ARGS:+$AP_ARGS }-t" ;; esac
}

# ---- the operator's own whisper_edge lines, read from the effective configuration ---------------------
# nginx: the main file with every include expanded where it stands, then the http-level statements.
ngx_flat() { # <file> [depth]
  [ "${2:-0}" -lt 16 ] || return 0
  WE_AWK_f="$1" awk 'BEGIN { f = ENVIRON["WE_AWK_f"] } { l = $0; sub(/#.*/, "", l)
      if (match(l, /^[ \t]*include[ \t]+[^;]+;/)) { p = substr(l, RSTART, RLENGTH); sub(/^[ \t]*include[ \t]+/, "", p)
        sub(/[ \t]*;.*$/, "", p); gsub(/["\047]/, "", p); print "@INC\t" p } else print f ":" NR "\t" l }' "$1" \
  | while IFS= read -r _ln; do
      case "$_ln" in
        "@INC	"*) _g=${_ln#*	}; case "$_g" in /*) ;; *) _g="$(dirname -- "$NGX_CONF")/$_g" ;; esac
          for _f in $_g; do [ -f "$_f" ] && ngx_flat "$_f" $(( ${2:-0} + 1 )); done ;;
        *) printf '%s\n' "$_ln" ;;
      esac
    done
}
ngx_http_lines() { # <our drop-in> [directive regex] -> "<directive>\t<file:line>\t<args>" for each at http level but ours
  ngx_flat "$NGX_CONF" | K="${2:-^whisper_edge_}" WE_AWK_ours="$1" awk -F'\t' 'BEGIN { ours = ENVIRON["WE_AWK_ours"] }
    { src = $1; l = $2
      while (length(l)) {
        c = substr(l, 1, 1)
        if (c ~ /[ \t]/) { l = substr(l, 2); continue }
        if (c == "{") { depth++; if (pend == "http") inhttp = depth; pend = ""; l = substr(l, 2); continue }
        if (c == "}") { if (depth == inhttp) inhttp = 0; depth--; l = substr(l, 2); continue }
        if (c == ";") { l = substr(l, 2); continue }
        if (match(l, /^[^;{}]+/)) {
          st = substr(l, 1, RLENGTH); l = substr(l, RLENGTH + 1); n = split(st, w, /[ \t]+/)
          if (substr(l, 1, 1) == "{") { pend = w[1]; continue }
          if (inhttp && depth == inhttp && w[1] ~ ENVIRON["K"] && index(src, ours ":") != 1) {
            a = st; sub(/^[^ \t]+[ \t]*/, "", a); print w[1] "\t" src "\t" a }
          continue }
        l = substr(l, 2) } }' | not_ours "$1"
}
# drop the lines read from the installer's own file, known by what it is rather than by the name an include
# reached it through (a symlinked directory, a link to it, a hard link): read as the operator's, its own
# lines would be kept and the policy rewritten without them
not_ours() { # <our file>: "<directive>\t<file:line>\t<args>" lines in, those from other files out
  while IFS='	' read -r _no_d _no_at _no_a; do
    if [ -e "$1" ] && [ "${_no_at%:*}" -ef "$1" ]; then continue; fi
    printf '%s\t%s\t%s\n' "$_no_d" "$_no_at" "$_no_a"
  done
}
# Apache: every file the configuration reads, in the order it reads them, and the main-level statements
# (outside every <VirtualHost>, <Directory>, <Location>, <Files> and <If>; <IfModule> and <IfDefine> are
# read through), each directive named the module's way: lowercased, underscores dropped.
ap_include_walk() { # <main config> <server root> -> it and every file its Include lines name, three deep
  [ -f "$1" ] || return 0
  _iw_list=$1; _iw_next=$1; _iw_d=0
  while [ -n "$_iw_next" ] && [ "$_iw_d" -lt 3 ]; do
    _iw_new=""
    for _iw_f in $_iw_next; do
      for _iw_p in $(rd_file "$_iw_f" | sed -n 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee]\([Oo][Pp][Tt][Ii][Oo][Nn][Aa][Ll]\)\{0,1\}[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\).*/\2/p'); do
        case "$_iw_p" in /*) ;; *) _iw_p="$2/$_iw_p" ;; esac
        for _iw_g in $_iw_p; do if [ -f "$_iw_g" ]; then _iw_new="$_iw_new $_iw_g"; fi; done
      done
    done
    _iw_list="$_iw_list$_iw_new"; _iw_next=$_iw_new; _iw_d=$((_iw_d + 1))
  done
  printf '%s\n' $_iw_list
}
ap_files() { # -> the files Apache reads, as it lists them (on either stream: where the list goes differs by
  # build), else the main configuration and every file its Include lines name, read against its ServerRoot
  _af_l=$(tmo "$AP_CTL" ${AP_ARGS:-} -t -D DUMP_INCLUDES 2>&1 | sed -n 's/^[[:space:]]*([^)]*)[[:space:]]*\(\/.*\)$/\1/p')
  if [ -z "$_af_l" ]; then
    _am=""; [ "$AP_LAYOUT" = debian ] && _am=/etc/apache2/apache2.conf; [ "$AP_LAYOUT" = rhel ] && _am=/etc/httpd/conf/httpd.conf
    _ar=$(dirname -- "${_am:-/}"); [ "$AP_LAYOUT" = rhel ] && _ar=/etc/httpd
    _af_l=$(ap_include_walk "$_am" "$_ar")
  fi
  [ -z "$_af_l" ] || printf '%s\n' "$_af_l"
}
# Is the module loaded by a file other than the installer's own drop-in? "apache2ctl -M" names it loaded
# when the drop-in's own LoadModule loads it, and a re-run that took that for the operator's load would
# write the drop-in without it: configtest then refuses every WhisperEdge line (measured on Ubuntu 24.04)
ap_loaded_elsewhere() { # <our drop-in>: fails only when the drop-in's own LoadModule is the one loading it
  # no LoadModule in the drop-in: what apache2ctl -M says stands (a module built in, or loaded where the
  # files cannot be listed, is loaded all the same, and a second LoadModule would be one too many)
  rd_file "$1" | grep_any -E '^[[:space:]]*[Ll][Oo][Aa][Dd][Mm][Oo][Dd][Uu][Ll][Ee][[:space:]]+whisper_edge_module[[:space:]]' || return 0
  for _le in $(ap_files); do
    [ -f "$_le" ] && ! [ "$_le" -ef "$1" ] || continue
    rd_file "$_le" | grep_any -E '^[[:space:]]*[Ll][Oo][Aa][Dd][Mm][Oo][Dd][Uu][Ll][Ee][[:space:]]+whisper_edge_module[[:space:]]' && return 0
  done
  return 1
}
ap_main_lines() { # <our drop-in> [directive regex, the module's spelling] -> "<directive>\t<file:line>\t<args>"
  _files=$(ap_files)
  # the installer's own file is skipped by what it IS, not by its name: Debian's Apache lists it by a2enconf's
  # conf-enabled link, and read under that name it would be taken for the operator's (a re-run then kept its
  # own lines and wrote the policy empty)
  for _f in $_files; do [ -f "$_f" ] && ! [ "$_f" -ef "$1" ] && WE_AWK_f="$_f" awk 'BEGIN { f = ENVIRON["WE_AWK_f"] } { print f ":" NR "\t" $0 }' "$_f"; done \
  | K="${2:-^whisperedge}" awk -F'\t' '
    { l = $2; sub(/^[ \t]+/, "", l); if (l ~ /^#/ || l == "") next
      # a closing tag names its block whole: "</If" must not match "</IfModule>", which would count
      # every </IfModule> as a closed block and leave the depth below zero, so no top-level line is read
      if (l ~ /^<\/(VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|If|ElseIf|Else|Proxy|ProxyMatch|Macro)[ \t]*>/) { d--; next }
      if (l ~ /^<(VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|If|ElseIf|Else|Proxy|ProxyMatch|Macro)[ \t>]/) { d++; next }
      if (l ~ /^<\/?(IfModule|IfDefine|IfVersion|IfFile|IfDirective|IfSection)/) next
      n = split(l, w, /[ \t]+/); k = tolower(w[1]); gsub(/_/, "", k)
      if (d == 0 && k ~ ENVIRON["K"]) { a = l; sub(/^[^ \t]+[ \t]*/, "", a); print k "\t" $1 "\t" a } }'
}
# The server's own trust of a proxy, read where it is server-wide (nginx's http level, Apache's server
# config; never a virtual host's, which is that site's alone). The module's context rules judge the client
# the server has resolved, but its floor rules judge the TCP peer, the proxy, until the module has a trust
# list of its own. The installer never writes one (who may speak for a client is the operator's decision):
# it says what the server trusts and prints the module's lines that would make the floor trust the same.
realip_advice() { # <server> <our drop-in>
  [ -z "${K_TPROXY:-}" ] || return 0
  _rx=""; _rh=""
  case "$1" in
    nginx)
      _rl=$(ngx_http_lines "$2" '^(set_real_ip_from|real_ip_header)$')
      _rx=$(printf '%s\n' "$_rl" | awk -F'\t' '$1 == "set_real_ip_from" { a = $3; sub(/[ \t]*;.*$/, "", a); o = o (o == "" ? "" : " ") a } END { print o }')
      _rh=$(printf '%s\n' "$_rl" | awk -F'\t' '$1 == "real_ip_header" { a = $3; sub(/[ \t]*;.*$/, "", a); h = a } END { print h }')
      _rw="set_real_ip_from and real_ip_header at http level" ;;
    apache)
      _rl=$(ap_main_lines "$2" '^remoteip(header|internalproxy|trustedproxy|internalproxylist|trustedproxylist)$')
      _rx=$(printf '%s\n' "$_rl" | awk -F'\t' '$1 == "remoteipinternalproxy" || $1 == "remoteiptrustedproxy" { gsub(/"/, "", $3); o = o (o == "" ? "" : " ") $3 } END { print o }')
      for _rf in $(printf '%s\n' "$_rl" | awk -F'\t' '$1 ~ /proxylist$/ { gsub(/"/, "", $3); print $3 }'); do
        case "$_rf" in /*) ;; *) _rf="$(dirname -- "${AP_INC:-/etc/apache2/x}")/$_rf" ;; esac
        _rx="$_rx $(rd_file "$_rf" | sed 's/#.*//' | tr -s ' \t' '\n\n' | sed '/^$/d' | tr '\n' ' ')"
      done
      _rx=$(printf '%s' "$_rx" | tr -s ' ' | sed 's/^ //; s/ $//')
      _rh=$(printf '%s\n' "$_rl" | awk -F'\t' '$1 == "remoteipheader" { a = $3; gsub(/"/, "", a); sub(/[ \t].*$/, "", a); h = a } END { print h }')
      _rw="RemoteIPHeader with RemoteIPInternalProxy or RemoteIPTrustedProxy in the server config" ;;
    *) return 0 ;;
  esac
  [ -n "$_rx" ] && [ -n "$_rh" ] || return 0
  # the PROXY protocol is the listener's, not a header: the module reads that source itself
  case "$_rh" in proxy_protocol) return 0 ;; esac
  rep applied "$(display "$1"): your $_rw trusts $_rx for $_rh, so the module's rules judge the client that names; its floor rules judge the connection's peer (the proxy) unless the module trusts the same; to have the floor judge the client too, add these yourself (the installer writes none):"
  case "$1" in
    nginx) printf '     whisper_edge_trusted_proxy %s;\n     whisper_edge_trusted_header %s;\n' "$_rx" "$_rh" >> "$RT/applied" ;;
    apache) printf '     WhisperEdgeTrustedProxy %s\n     WhisperEdgeTrustedHeader %s\n' "$_rx" "$_rh" >> "$RT/applied" ;;
  esac
}
# what the operator's lines mean for what the installer writes: sets K_POLICY (their own rules),
# K_DATA, K_SUMMARY (the counters directory they name), K_MODE, and says each one kept
keep_scan() { # <server> <lines>
  K_POLICY=""; K_DATA=""; K_SUMMARY=""; K_MODE=""; K_DATAV=""; K_SNAPV=""; K_REPF=""; K_TPROXY=""
  _ks=$1; _kl=$2
  [ -n "$_kl" ] || return 0
  while IFS='	' read -r _d _at _a; do
    _k=$(printf '%s' "$_d" | tr -d _ | tr 'A-Z' 'a-z')
    case "$_k" in
      whisperedgepolicy|whisperedgeset|whisperedgethreshold) [ -n "$K_POLICY" ] || K_POLICY="$_at" ;;
      whisperedgedata|whisperedgesnapshot)
        # three forms: <dir> (every plane there), <plane> <file> (that plane's file alone) and the legacy
        # snapshot <file>. A plane's own line other than reputation's leaves the installer's directory line
        # in place for the rest; a directory, a snapshot or reputation's own file is the data kept.
        _dv=$(printf '%s' "$_a" | sed 's/[;"]//g'); set -- $_dv
        if [ "$_k" = whisperedgesnapshot ]; then K_SNAPV=$1
        elif [ $# -ge 2 ]; then
          case "$1" in
            reputation) K_REPF=$2 ;;
            *) rep applied "$(display "$_ks"): kept your $_d $_a ($_at): that plane's own file; the installer's data line names the directory for the rest"; continue ;;
          esac
        else K_DATAV=$1; fi
        [ -n "$K_DATA" ] || { K_DATA="$_at"; rep applied "$(display "$_ks"): kept your $_d $_a ($_at): no data line is written beside it" ; } ;;
      whisperedgesummary) K_SUMMARY=$(printf '%s' "$_a" | sed 's/[;"]//g'); rep applied "$(display "$_ks"): kept your $_d $_a ($_at): the counters are read there" ;;
      whisperedgemode) K_MODE="$_at"; rep applied "$(display "$_ks"): kept your $_d $_a ($_at)" ;;
      whisperedgetrustedproxy) K_TPROXY="$_at"; rep applied "$(display "$_ks"): kept your $_d $_a ($_at)" ;;
      whisperedgeallowinferred) rep applied "$(display "$_ks"): kept your $_d $_a ($_at); with it on, an inferred range can deny, which the default never does" ;;
      *) rep applied "$(display "$_ks"): kept your $_d $_a ($_at)" ;;
    esac
  done <<KEOF
$_kl
KEOF
}

# ---- each server's test and reload, with the arguments its running master was started with ------------
# A master counts as this host's only when it lives in this mount namespace (its root is /) and runs the
# binary the probe found; its own -c/-p (nginx) or -f/-d (Apache) are then passed to every test and signal.
master_args() { # <pid> <binary> <flags...> -> the master's own values of those flags, as words
  _mp=$1; _mb=$2; shift 2
  [ -n "$_mp" ] && [ -r "/proc/$_mp/cmdline" ] || return 1
  [ "$(readlink "/proc/$_mp/root" 2>/dev/null)" = / ] || return 2
  # its own root is this one (a container's master seen from the host is not), and it runs this server
  [ "$(basename "$(readlink -f "/proc/$_mp/exe" 2>/dev/null)")" = "$(basename "$_mb")" ] || return 2
  # nginx rewrites its argv into its process title ("nginx: master process /usr/sbin/nginx -c ..."), so the
  # words are read from that one string; a path with a space in it is not one this reads back
  tr '\0' ' ' < "/proc/$_mp/cmdline" | sed 's/^nginx: master process //' | tr ' ' '\n' \
    | WE_AWK_want=" $* " awk 'BEGIN { want = ENVIRON["WE_AWK_want"] } p { print p; print $0; p = ""; next } index(want, " " $0 " ") { p = $0 }'
}
srv_test() { # <server>: its own configuration test, under the ceiling
  case "$1" in
    nginx) # shellcheck disable=SC2086
           tmo nginx ${NGX_ARGS:-} -t ;;
    apache) # shellcheck disable=SC2086
            tmo "$AP_CTL" ${AP_ARGS:-} -t ;;
  esac
}
srv_reload() { # <server> -> sets RL_CMD; returns the reload's status
  case "$1" in
    nginx) if unit_active "$NGX_UNIT"; then RL_CMD="systemctl reload $NGX_UNIT"; else RL_CMD="nginx ${NGX_ARGS:+$NGX_ARGS }-s reload"; fi ;;
    apache) if unit_active "$AP_UNIT"; then RL_CMD="systemctl reload $AP_UNIT"; else RL_CMD="$AP_CTL ${AP_ARGS:+$AP_ARGS }-k graceful"; fi ;;
  esac
  # shellcheck disable=SC2086
  tmo $RL_CMD
}
srv_running() { case "$1" in nginx) [ "$NGX_RUNNING" = yes ] ;; apache) [ "$AP_RUNNING" = yes ] ;; *) return 1 ;; esac; }

# ---- the renderings, with what the operator's configuration already says left out ---------------------
render_nginx_keep() { # K_* from the stamp or the scan
  [ -n "${K_DATA:-}" ] || printf 'whisper_edge_data %s;\n' "$(cf_word "$DIR")"
  [ -n "${K_SUMMARY:-}" ] || printf 'whisper_edge_summary %s;\n' "$(cf_word "$DIR/counters")"
  if [ -n "${K_POLICY:-}" ]; then return 0; fi
  if [ -n "${K_MODE:-}" ]; then translate nginx | sed 1d; else translate nginx; fi
}
render_apache_keep() { # [module path]
  [ -n "${1:-}" ] && printf 'LoadModule whisper_edge_module %s\n' "$(cf_word "$1")"
  [ -n "${K_DATA:-}" ] || printf 'WhisperEdgeData %s\n' "$(cf_word "$DIR")"
  [ -n "${K_SUMMARY:-}" ] || printf 'WhisperEdgeSummary %s\n' "$(cf_word "$DIR/counters")"
  if [ -n "${K_POLICY:-}" ]; then return 0; fi
  if [ -n "${K_MODE:-}" ]; then translate apache | sed 1d; else translate apache; fi
}
# the gate's fixed invalid rule, in place of the last rule of a rendering, only where it is honoured
with_test_rule() { # <idiom>
  _tr=$(test_rule)
  if [ -z "$_tr" ]; then cat; return 0; fi
  case "$1" in
    nginx) WE_AWK_r="whisper_edge_policy $_tr;" awk 'BEGIN { r = ENVIRON["WE_AWK_r"] } /^whisper_edge_policy /{ last = NR } { l[NR] = $0 } END { for (i = 1; i <= NR; i++) print (i == last ? r : l[i]) }' ;;
    apache) WE_AWK_r="WhisperEdgePolicy \"$_tr\"" awk 'BEGIN { r = ENVIRON["WE_AWK_r"] } /^WhisperEdgePolicy /{ last = NR } { l[NR] = $0 } END { for (i = 1; i <= NR; i++) print (i == last ? r : l[i]) }' ;;
  esac
}

# ---- the operator tools, and the module's own word after a reload --------------------------------
#
# whisper-edge-lookup compiles the rules a server now holds into the program digest its module will name;
# whisper-edge-summary reads the module's live status. Both come from this checkout (built here when a
# toolchain is, as the checkout's owner, never as root) and are installed beside the refresh. Nothing in
# the checkout is copied or run unless it and every directory above it up to the checkout are owned by
# root or by the person running this, and writable by no one else.
TOOL_LOOKUP=""; TOOL_SUMMARY=""
tools_ready() { # finds, builds or installs the two tools; empty TOOL_* when it cannot, with the reason in TOOL_WHY
  [ -n "$TOOL_SUMMARY" ] && return 0
  TOOL_WHY=""
  _core="$HERE/../core"
  for _t in whisper-edge-lookup whisper-edge-summary; do
    if [ ! -x "$_core/$_t" ] && [ ! -x "$SBIN/$_t" ]; then
      if have make && have cc && [ -f "$_core/Makefile" ]; then
        tree_ok "$_core/Makefile" || { TOOL_WHY="$_core is not owned by root or by you, or is writable by others, so nothing in it is built or run"; return 1; }
        _bu=$(stat -c %u "$_core"); _bg=$(stat -c %g "$_core")
        as_user "$_bu" "$_bg" make -C "$_core" tools >"$RT/tools.log" 2>&1 \
          || { TOOL_WHY="building the tools failed ($(ctl_strip < "$RT/tools.log" | tail -n 1)); build them with: make -C $(cd "$_core" && pwd) tools"; return 1; }
        rep applied "built $_t in $(cd "$_core" && pwd) as $(id -nu "$_bu" 2>/dev/null || echo "uid $_bu")"
      fi
    fi
    if [ -x "$_core/$_t" ]; then
      tree_ok "$_core/$_t" || { TOOL_WHY="$_core/$_t is not owned by root or by you, or is writable by others"; return 1; }
      if ! cmp -s "$_core/$_t" "$SBIN/$_t" 2>/dev/null; then
        chain_root "$SBIN" || { TOOL_WHY="$SBIN is not root's alone"; return 1; }
        _tt=$(mktemp "$SBIN/.whisper-edge.XXXXXXXXXX")
        install -o 0 -g 0 -m 0755 "$_core/$_t" "$_tt" && mv -f -T "$_tt" "$SBIN/$_t" || { rm -f "$_tt"; TOOL_WHY="could not install $SBIN/$_t"; return 1; }
        rep applied "installed $SBIN/$_t"
      fi
    fi
    [ -x "$SBIN/$_t" ] || { TOOL_WHY="$_t is not built and there is no toolchain (make, cc) here to build it: make -C $(cd "$_core" 2>/dev/null && pwd || echo "$CHECKOUT/core") tools, then run this again"; return 1; }
  done
  # the status read ignores entries a worker did not write (--writer-uid); a summary built before that option
  # would read every entry, so it is refused here by name rather than trusted
  grep -aqF -- '--writer-uid' "$SBIN/whisper-edge-summary" \
    || { TOOL_WHY="$SBIN/whisper-edge-summary predates --writer-uid, which the status read needs; build it from this checkout (make -C $(cd "$_core" 2>/dev/null && pwd || echo "$CHECKOUT/core") tools) and run this again"; return 1; }
  TOOL_LOOKUP="$SBIN/whisper-edge-lookup"; TOOL_SUMMARY="$SBIN/whisper-edge-summary"
}
# The program digest the module will name for the http-level rules: the rules in the corpus form, compiled
# by the same compiler the module carries, in the data directory's environment.
c7_program() { # <rule texts, one per line> -> the 16-hex digest, or nothing
  printf '%s\n' "$1" | awk 'NF { printf "policy http %s\036\n", $0 }' > "$RT/c7.corpus"
  tmo "$TOOL_LOOKUP" --probe-dir "$DIR" --programs "$RT/c7.corpus" 2>/dev/null | sed -n 's/^program http \([0-9a-f]\{16\}\) .*/\1/p' | sed -n 1p
}
# the plane's header digest, recomputed here by root from the file: SHA-256 over the header with its digest
# field zeroed and the body, the first 16 hex digits; never read back from what a status file claims
hdr_digest16() { { head -c 104 "$1"; head -c 32 /dev/zero; tail -c +137 "$1"; } 2>/dev/null | sha256_of | cut -c1-16; }
proc_start() { sed -n 's/^[0-9]* (.*) \(.*\)$/\1/p' "/proc/$1/stat" 2>/dev/null | awk '{ print $20 }'; }
# The live writers in the counters directory, read as nobody, entries owned by the worker's uid only:
# "<pid> <starttime> <config digest16>" per rules file whose writer is alive with that very start time.
c7_writers() { # <counters dir> <worker uid>
  as_user "$(id -u nobody)" "$(id -g nobody)" sh -c 'find "$1" -maxdepth 1 -type f -user "$2" -links 1 -name "*.rules.cnt" ! -perm /022 2>/dev/null | while IFS= read -r f; do
      head -c 4096 -- "$f" 2>/dev/null | sed -n "s/^pidns [0-9]* starttime \([0-9]*\)$/S \1/p; s/^pid \([0-9]*\)$/P \1/p; s/^config \([0-9a-f]\{16\}\)$/C \1/p" | tr "\n" " "; echo
    done' sh "$1" "$2" 2>/dev/null \
  | awk '{ s = p = c = ""; for (i = 1; i < NF; i += 2) { if ($i == "S") s = $(i + 1); if ($i == "P") p = $(i + 1); if ($i == "C") c = $(i + 1) } if (s != "" && p != "" && c != "") print p, s, c }' \
  | while read -r _p _s _c; do [ "$(proc_start "$_p")" = "$_s" ] && echo "$_p $_s $_c"; done | sort -u
}
c7_conf_has() { # <counters dir> <worker uid> <config digest16> <program digest16|any> -> "ok <program>" | "refused <line>" | "missing" | "other"
  # read in one open: the owner is the open file's (fstat through /proc/self/fd), so a file renamed into
  # place between a check and a read cannot be the one read; under a ceiling, so a FIFO cannot hold it
  as_user "$(id -u nobody)" "$(id -g nobody)" timeout --kill-after=5 20 sh -c 'f="$1/conf-$3.status"; [ -f "$f" ] && [ ! -L "$f" ] || { echo missing; exit 0; }
    exec 3< "$f" || { echo missing; exit 0; }
    [ "$(stat -L -c "%u %h %F" /proc/self/fd/3)" = "$2 1 regular file" ] || [ "$(stat -L -c "%u %h %F" /proc/self/fd/3)" = "$2 1 regular empty file" ] || { echo missing; exit 0; }
    c=$(head -c 65536 <&3); exec 3<&-
    r=$(printf "%s\n" "$c" | grep -m1 -e "^refused " -e " unreadable \"")
    if [ -n "$r" ]; then echo "refused $r"; exit 0; fi
    if [ "$4" = any ]; then p=$(printf "%s\n" "$c" | sed -n "s/^program \([0-9a-f]\{16\}\) context .*/\1/p" | sed -n 1p); [ -n "$p" ] && echo "ok $p" || echo other; exit 0; fi
    printf "%s\n" "$c" | grep -q "^program $4 context " && echo "ok $4" || echo other' sh "$1" "$2" "$3" "$4" 2>/dev/null | ctl_strip | cut -c1-300
}
C7_BEFORE=""; C7_T0=0
c7_before() { C7_T0=$(date +%s); C7_BEFORE=$(c7_writers "$1" "$2" | awk '{ print $1 ":" $2 }' | tr '\n' ' '); }
# A refusal with no writer to name its configuration (a module that refused it has no live worker
# writing counters): any conf status the worker's uid wrote since the reload that says refused or
# unreadable, read as nobody, each file in one open, its owner and mtime from the open file
c7_refused_any() { # <counters dir> <worker uid> -> the first such line, or nothing
  as_user "$(id -u nobody)" "$(id -g nobody)" timeout --kill-after=5 20 sh -c 'for f in "$1"/conf-*.status; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      exec 3< "$f" || continue
      set -- "$1" "$2" "$3" $(stat -L -c "%u %h %Y" /proc/self/fd/3)
      if [ "${4:-}" = "$2" ] && [ "${5:-}" = 1 ] && [ "${6:-0}" -ge "$3" ]; then
        r=$(head -c 65536 <&3 | grep -m1 -e "^refused " -e " unreadable \"")
        exec 3<&-
        if [ -n "$r" ]; then echo "$r"; exit 0; fi
      else exec 3<&-; fi
    done' sh "$1" "$2" "${C7_T0:-0}" 2>/dev/null | ctl_strip | cut -c1-300 | sed -n 1p
}
# The verdict: fresh (after a reload: a writer that was not there before must name the program) or
# readonly (a run that changed nothing: any live writer naming the program will do; it says so).
# A server that loaded the module keeps that copy for as long as its master lives: nginx's reload asks
# dlopen for a path it already holds, and gets the handle it has, so a module rebuilt and installed under
# the same name is not what runs until the server is restarted. Each process of the running server is read
# for the module it has mapped; a mapping whose inode is not the installed file's (or whose file was
# replaced, "(deleted)") is an older build, said plainly with the restart that loads the new one. A server
# that maps no copy of the module says nothing. Nothing is restarted here: that is the operator's call.
stale_module() { # <server>: say so when the running server's module is not the installed file
  case "$1" in
    nginx) _sm_so=$NGX_MOD; _sm_m=$(master_pid nginx "${NGX_PIDFILE:-/run/nginx.pid}" /run/nginx.pid /var/run/nginx.pid)
           if unit_active "$NGX_UNIT"; then _sm_cmd="systemctl restart $NGX_UNIT"; else _sm_cmd="nginx ${NGX_ARGS:+$NGX_ARGS }-s quit, then start it again as you started it"; fi ;;
    apache) _sm_so=$AP_MOD; _sm_m=$(master_pid "$AP_NAME" /run/apache2/apache2.pid /var/run/apache2/apache2.pid /run/httpd/httpd.pid /var/run/httpd/httpd.pid)
            if unit_active "$AP_UNIT"; then _sm_cmd="systemctl restart $AP_UNIT"; else _sm_cmd="$AP_CTL ${AP_ARGS:+$AP_ARGS }-k restart"; fi ;;
    litespeed) _sm_so=$LSWS/modules/mod_whisper_edge.so; _sm_m=$(ols_main); _sm_cmd="$LSWS/bin/lswsctrl restart" ;;
    *) return 0 ;;
  esac
  [ -n "$_sm_so" ] && [ -f "$_sm_so" ] && [ -n "$_sm_m" ] || return 0
  _sm_rp=$(readlink -f -- "$_sm_so" 2>/dev/null) || return 0
  _sm_in=$(stat -L -c %i -- "$_sm_rp" 2>/dev/null) || return 0
  _sm_old=""
  for _sm_p in "$_sm_m" $(ps -eo pid=,ppid= 2>/dev/null | WE_AWK_m="$_sm_m" awk 'BEGIN { m = ENVIRON["WE_AWK_m"] } $2 == m { print $1 }'); do
    # maps: address perms offset dev inode path; the path may carry " (deleted)"
    _sm_l=$(WE_AWK_f="$_sm_rp" awk 'BEGIN { f = ENVIRON["WE_AWK_f"] }
      { p = $0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[0-9]+ +/, "", p) }
      p == f || p == f " (deleted)" { print $5, (p == f ? "live" : "deleted") }' "/proc/$_sm_p/maps" 2>/dev/null | sort -u)
    [ -n "$_sm_l" ] || continue
    [ -n "$(printf '%s\n' "$_sm_l" | while read -r _sm_i _sm_s; do [ "$_sm_s" = deleted ] || [ "$_sm_i" != "$_sm_in" ] && echo x; done)" ] && { _sm_old="$_sm_p"; break; }
  done
  [ -n "$_sm_old" ] || return 0
  rep proved "$(display "$1"): the running server (pid $_sm_old) still has the module it loaded before $_sm_so was replaced: a reload keeps a module it already loaded, so this build is not the one running; to load it: $_sm_cmd"
  ARM_UNCONFIRMED="$ARM_UNCONFIRMED $1"
}
c7_verdict() { # <server> <counters dir> <worker uid> <program digest16> <fresh|readonly>
  _cs=$1; _cd=$2; _cu=$3; _cp=$4; _cm=$5; C7_REFUSED=""
  _rep=${C7_REP:-$DIR/reputation.bin}
  # the status interval the writers state (ms), else the module's 60 s; a new writer's first file can come
  # one interval plus up to one interval of jitter after it starts, so the ceiling is three intervals and a
  # minute, never below two and a minute
  _iv=$(as_user "$(id -u nobody)" "$(id -g nobody)" sh -c 'cat -- "$1"/*.status 2>/dev/null' sh "$_cd" | sed -n 's/.* interval \([0-9]\{1,\}\) .*/\1/p' | sort -n | tail -n 1)
  case "$_iv" in ''|*[!0-9]*) _iv=60 ;; *) _iv=$(( (_iv + 999) / 1000 )) ;; esac
  [ "$_iv" -ge 1 ] || _iv=60
  _ceil=$((3 * _iv + 60)); _t0=$(date +%s); _last=""
  while :; do
    _hit=""; _why=""
    for _w in $(c7_writers "$_cd" "$_cu" | tr ' ' ':'); do
      _wp=${_w%%:*}; _r=${_w#*:}; _ws=${_r%%:*}; _wc=${_r#*:}
      if [ "$_cm" = fresh ]; then case " $C7_BEFORE " in *" $_wp:$_ws "*) continue ;; esac; fi
      _h=$(c7_conf_has "$_cd" "$_cu" "$_wc" "$_cp")
      case "$_h" in
        ok\ *) _hit="$_wp $_wc"; _cp=${_h#ok }; break ;;
        refused*) _why="${_h#refused }" ;;
      esac
    done
    if [ -n "$_hit" ]; then
      # the plane, as the module's status says it for that writer, against root's own read of the file
      _st=$(as_user "$(id -u nobody)" "$(id -g nobody)" timeout --kill-after=10 "$T_CMD" "$TOOL_SUMMARY" --status "$_cd" --writer-uid "$_cu" 2>/dev/null | ctl_strip)
      _pl=$(printf '%s\n' "$_st" | WE_AWK_p="${_hit%% *}" awk 'BEGIN { p = ENVIRON["WE_AWK_p"] } $1 == "process" && $2 == "pid" { cur = ($3 == p) } cur && $1 == "plane" && $2 == "reputation" { print $3, $5, $7; exit }')
      _g=$(le_u64 "$_rep" 16); _d=$(hdr_digest16 "$_rep")
      set -- $_pl
      # a generation that is not a number (a malformed status line) compares as no generation, quietly
      _gn=${2:-}; case "$_gn" in ''|*[!0-9]*) _gn=-1 ;; esac
      _cg=${C7_GEN:-0}; case "$_cg" in ''|*[!0-9]*) _cg=0 ;; esac
      if [ "${1:-}" = armed ] && [ "$_gn" -ge 0 ] && [ "$_gn" -ge "$_cg" ] && [ "${3:-}" = "$_d" ] && [ "$_gn" = "$_g" ]; then
        if [ "$_cm" = fresh ]; then
          rep proved "$(display "$_cs"): confirmed by the module: worker pid ${_hit%% *}, new since the reload, runs program $_cp, reputation armed at generation $2, header digest $3 (the file here reads the same)"
        else
          rep proved "$(display "$_cs"): confirmed read-only (nothing changed, so nothing was reloaded): a live worker runs program $_cp, reputation armed at generation $2, header digest $3; this checks the program and the plane only, not that the worker is new"
        fi
        return 0
      fi
      _why="reputation reads ${1:-not bound} generation ${2:--} digest ${3:--} in the module, and the file here is generation $_g digest $_d"
    fi
    [ -n "$_why" ] && _last=$_why
    if [ $(( $(date +%s) - _t0 )) -ge "$_ceil" ]; then
      [ -n "$_last" ] || _last=$(c7_refused_any "$_cd" "$_cu")
      if [ -n "$_last" ]; then
        case "$_last" in reputation\ reads*) ;; *) C7_REFUSED=$_last ;; esac
        rep proved "$(display "$_cs"): applied and serving, but the module reports: $_last; the deny rules are inert until that is fixed"
      else
        _nw=$(c7_writers "$_cd" "$_cu" | grep -c . || :)
        rep proved "$(display "$_cs"): applied and serving, but unverified: no ${_cm:+$( [ "$_cm" = fresh ] && echo 'new ' || :)}worker named $( [ "$_cp" = any ] && echo 'a program of your policy' || echo "program $_cp") in $_cd within $_ceil s ($_nw live writer(s) there now; $(printf '%s' "$C7_BEFORE" | wc -w) were there before the reload)"
      fi
      ARM_UNCONFIRMED="$ARM_UNCONFIRMED $_cs"
      return 1
    fi
    sleep 2
  done
}

# ---- OpenLiteSpeed: no configuration test, so the module's own word after the restart is the test ------
#
# Measured on 1.9.3: a configuration OpenLiteSpeed's own parser refuses does not take it down; it
# warns and keeps serving, so a restart is never an outage. Its conf/ belongs to the WebAdmin account
# (lsadm), so every read, write and restore there runs as that account. The policy goes into a new
# file of its own, whisper-edge.conf, and httpd_config.conf gains one include line; the block is written in
# log mode (no configuration test can prove a deny first), and --arm-deny later turns it to deny.
ols_files() { # httpd_config.conf and every file it includes, by the include lines OpenLiteSpeed reads
  echo "$OLS_CONF"
  rd_file "$OLS_CONF" | sed -n 's/^[[:space:]]*include[[:space:]]\{1,\}\([^[:space:]#]\{1,\}\).*/\1/p' | while IFS= read -r _i; do
    case "$_i" in /*) ;; *) _i="$LSWS/conf/$_i" ;; esac
    for _f in $_i; do [ -f "$_f" ] && echo "$_f"; done
  done
}
ols_status() { tmo "$LSWS/bin/lswsctrl" status 2>/dev/null | ctl_strip | sed -n 1p; }
ols_up() { case "$(ols_status)" in *"is running"*) return 0 ;; esac; return 1; }
ols_main() { ols_status | sed -n 's/.*running with PID \([0-9]\{1,\}\).*/\1/p'; }
# A graceful restart (lswsctrl restart: SIGUSR1 to the main process) replaces the main process when it is
# done; the restart is proven by a new main pid, never assumed. When the main process is still the old
# one after the ceiling, the restart did not happen, so the server is cycled for real (stop, then start)
# and the report says so, with how long it was down: a configuration that is on disk but not running is
# the one state the installer must never leave behind silently.
# Measured on a test host (2026-10-17): a graceful restart replaces the main process over a few seconds, and
# a second restart sent while the previous main is still draining is lost; so is a start sent while the
# old main is still stopping. Each step therefore waits for the server to settle first: one main process.
# The new main is not named like one while it takes over: for its first seconds its title is the bare
# "litespeed" it was started as, beside the old "openlitespeed (lshttpd - main)" (measured 2026-10-17, an
# undo line run 5 s after an apply). Counting the title alone read that handover as settled, and the next
# restart, sent into it, left the half-started main's lscgid behind with no parent. Both names count.
ols_mains() { ps -eo args= 2>/dev/null | grep -c -e '^openlitespeed (lshttpd - main)$' -e '^litespeed$' || :; }
ols_settle() { # up to the command ceiling (60 s or more) for at most one main process
  _st=$(date +%s)
  while [ "$(ols_mains)" -gt 1 ] && [ $(( $(date +%s) - _st )) -lt "$T_CMD" ]; do sleep 1; done
}
OLS_CYCLED=""
ols_restart() {
  OLS_CYCLED=""
  ols_settle
  _om=$(ols_main)
  tmo "$LSWS/bin/lswsctrl" restart >/dev/null 2>&1 || :
  [ -n "$_om" ] || return 0
  _t0=$(date +%s)
  while [ $(( $(date +%s) - _t0 )) -lt 60 ]; do
    _nm=$(ols_main)
    [ -n "$_nm" ] && [ "$_nm" != "$_om" ] && return 0
    sleep 1
  done
  _d0=$(date +%s)
  tmo "$LSWS/bin/lswsctrl" stop >/dev/null 2>&1 || :
  _st=$(date +%s)
  while [ "$(ols_mains)" -gt 0 ] && [ $(( $(date +%s) - _st )) -lt "$T_CMD" ]; do sleep 1; done
  tmo "$LSWS/bin/lswsctrl" start >/dev/null 2>&1 || :
  OLS_CYCLED="lswsctrl restart left the main process at pid $_om after 60 s, so it was stopped and started (about $(( $(date +%s) - _d0 )) s without service)"
  rep proved "OpenLiteSpeed: $OLS_CYCLED"
}
OLS_INC_BEGIN="# whisper edge: the default policy, included by the installer (its undo line takes this back)"
OLS_INC_END="# whisper edge: end"
apply_litespeed() {
  _f="$LSWS/conf/whisper-edge.conf"; _stop=""
  plain_word "$DIR" || _stop="the data directory $DIR has whitespace, a #, a brace or a control character, which OpenLiteSpeed's configuration cannot carry"
  plain_word "$LSWS" || _stop="the server root $LSWS has whitespace, a #, a brace or a control character"
  [ -n "$_stop" ] || [ -f "$OLS_CONF" ] && [ ! -L "$OLS_CONF" ] || _stop="$OLS_CONF is missing or a link"
  if [ -z "$_stop" ]; then
    # shellcheck disable=SC2046
    set -- $(stat -c '%u %g %a' -- "$OLS_CONF") $(stat -c '%u' -- "$LSWS/conf")
    OLS_FU=$1; OLS_FG=$2; OLS_FM=$3
    if [ "$1" != "$4" ]; then _stop="$OLS_CONF is owned by uid $1 and its directory by uid $4; the installer writes there only as the one account that owns both"
    elif ! _w=$(writer_of "$LSWS/conf" "$OLS_FU"); then _stop="$LSWS/conf, or a directory above it, can be written by an account other than its owner"
    elif mode_gow "$OLS_FM"; then _stop="$OLS_CONF is writable by its group or others"; fi
  fi
  # the module trusts only an explicit 0, so an operator's other value is refused, never overridden
  _pv=$(ols_proxy_value)
  [ -n "$_stop" ] || [ -z "$_pv" ] || [ "$_pv" = 0 ] \
    || _stop="useIpInProxyHeader is $_pv in $OLS_CONF or a file it includes, and the module trusts only an explicit 0; set it to 0 and name your proxies with whisper_edge_trusted_proxy"
  if [ -z "$_stop" ] && ! tools_ready; then _stop="the installer proves what it applied with whisper-edge-lookup and whisper-edge-summary, and $TOOL_WHY"; fi
  if [ -z "$_stop" ]; then probe_planes "$(cfg_user litespeed || :)" || probe_planes nobody || _stop=$PROBE_WHY; fi
  if [ -n "$_stop" ]; then
    print_arm litespeed "$_stop: add it yourself"
    rep proved "OpenLiteSpeed: nothing was applied: $_stop"
    ARM_FAILED="$ARM_FAILED litespeed"; return 0
  fi
  rd_file "$OLS_CONF" | grep_any -E '^[[:space:]]*proxyProtocol[[:space:]]' \
    && rep applied "OpenLiteSpeed: a listener has proxyProtocol set: the module judges the PROXY header's source address, so only your load balancer may reach that listener"
  C7_CNT=$DIR/counters
  _ou=$(cfg_user litespeed); [ -n "$_ou" ] || _ou=nobody
  C7_UID=$(id -u "$_ou" 2>/dev/null || :)
  C7_REP=$DIR/reputation.bin; C7_GEN=$(le_u64 "$C7_REP" 16)
  # the operator's own block: kept, verified read-only, nothing written and nothing restarted
  _own=""
  for _of in $(ols_files); do rd_file "$_of" | grep_any '^[[:space:]]*module[[:space:]]\{1,\}mod_whisper_edge\b' && ! [ "$_of" -ef "$_f" ] && _own=$_of; done
  if [ -n "$_own" ]; then
    rep applied "OpenLiteSpeed: your module mod_whisper_edge block ($_own) is kept; nothing was written; to adopt the default, put these keys in it and restart:"
    render_litespeed_body | sed 's/^/     /' >> "$RT/applied"
    [ -n "$(ols_proxy_value)" ] || rep applied "OpenLiteSpeed: $OLS_CONF names no useIpInProxyHeader, and the module trusts only an explicit 0; add useIpInProxyHeader 0 at its top level and restart, and name your proxies with whisper_edge_trusted_proxy"
    if ols_up; then
      # their block, their program and their data: the verdict takes what their live worker reports
      # its data lines in either form: a directory, or reputation's own file (another plane's own file is
      # not the reputation plane, and leaves the directory the module's own default)
      _od=$(rd_file "$_own" | awk '$1 == "whisper_edge_data" && NF == 2 { print $2; exit }')
      _of=$(rd_file "$_own" | awk '$1 == "whisper_edge_data" && $2 == "reputation" && NF >= 3 { print $3; exit }')
      _os=$(sed -n 's/^[[:space:]]*whisper_edge_summary[[:space:]]\{1,\}\([^[:space:]#]\{1,\}\).*/\1/p' "$_own" | sed -n 1p)
      C7_PROG=any; C7_CNT=${_os:-$C7_CNT}; C7_REP=${_of:-${_od:+$_od/reputation.bin}}; C7_REP=${C7_REP:-$DIR/reputation.bin}
      C7_GEN=$(le_u64 "$C7_REP" 16)
      if [ -n "$C7_UID" ]; then c7_verdict litespeed "$C7_CNT" "$C7_UID" any readonly || :; fi
    fi
    return 0
  fi
  C7_PROG=$(c7_program "$(policy_text | sed -n '3,$p' | sed 's/#.*//; s/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//')")
  # the mode the installer's own file already carries survives a plain re-run; only --arm-deny changes it
  OLS_MODE=log
  if is_ours "$_f" && grep -q '^    whisper_edge_mode deny$' "$_f"; then OLS_MODE=deny; fi
  if [ "${ARM_DENY:-0}" = 1 ]; then
    # never creates the block, acts only on the installer's own file, and only after the module has
    # confirmed the policy in log mode; every check above (layer 1) has already run again
    is_ours "$_f" && rd_file "$OLS_CONF" | grep_any -xF "include $_f" \
      || { rep proved "OpenLiteSpeed: --arm-deny changes only the installer's own $_f, included from $OLS_CONF; it is not there, or it was edited since (compare it with: sudo $HERE/install.sh --server litespeed --dry-run); nothing was changed"; ARM_FAILED="$ARM_FAILED litespeed"; return 0; }
    if [ "$OLS_MODE" = deny ]; then
      rep proved "OpenLiteSpeed: already armed: the policy is in deny mode; nothing was changed and nothing was restarted"
      return 0
    fi
    ols_up && [ -n "$C7_UID" ] && c7_verdict litespeed "$C7_CNT" "$C7_UID" "${C7_PROG:-none}" readonly \
      || { rep proved "OpenLiteSpeed: --arm-deny needs the module to confirm the policy in log mode first, and it did not; nothing was changed"; ARM_FAILED="$ARM_FAILED litespeed"; return 0; }
    OLS_MODE=deny
  fi
  # the pre-test: the server is up before any restart cycle (a stopped one gets the file and the line).
  # An OpenLiteSpeed that is running but that lswsctrl does not know (its pid file names another process,
  # measured: a start that failed on a port the running one held left the file pointing at itself) cannot
  # be restarted by anything here, so nothing is written and the line says so.
  _running=0; ols_up && _running=1
  if [ "$_running" = 0 ] && [ "$(ols_mains)" -gt 0 ]; then
    rep proved "OpenLiteSpeed: a main process is running ($(ps -eo pid=,args= | awk '($2 == "openlitespeed" && $3 == "(lshttpd" && $5 == "main)") || ($2 == "litespeed" && NF == 2) { printf "pid %s ", $1 }')) that lswsctrl does not know (its pid file names no running server), so no restart can reach it; nothing was written; stop it, then $LSWS/bin/lswsctrl start, then run this again"
    ARM_FAILED="$ARM_FAILED litespeed"; win_close; return 0
  fi
  win_open litespeed; OLS_RESTARTED=0
  PUT_U=$OLS_FU; PUT_G=$OLS_FG
  if [ -z "$(ols_proxy_value)" ]; then
    rep applied "OpenLiteSpeed: $OLS_CONF names no useIpInProxyHeader, and the module trusts only an explicit 0, so $_f sets it to 0. Behind a real proxy or CDN, name its addresses with whisper_edge_trusted_proxy in the module block of $_f, and the module takes the client from X-Forwarded-For through them alone; leave useIpInProxyHeader at 0, and the server's own log keeps the proxy's address"
  fi
  { render_litespeed_proxy; render_litespeed_body | sed "s/^    whisper_edge_mode log\$/    whisper_edge_mode $OLS_MODE/"; } | prov_wrap "the default policy for OpenLiteSpeed" > "$RT/new"
  srv_put "$_f" "the default policy" "$OLS_FM" || [ -z "$ARM_REFUSED" ] || return 0
  PUT_U=0; PUT_G=0
  if rd_file "$OLS_CONF" | grep_any -xF "include $_f" && [ "$WROTE_SRV" = 0 ]; then
    # nothing changed: no restart, the module's word read as it stands
    win_close
    rep applied "already present: the include line in $OLS_CONF"
    rep proved "OpenLiteSpeed: nothing changed in its configuration, so it was not restarted"
    if ols_up && [ -n "$C7_UID" ]; then c7_verdict litespeed "$C7_CNT" "$C7_UID" "${C7_PROG:-none}" readonly || :; fi
    ols_up && stale_module litespeed
    return 0
  elif rd_file "$OLS_CONF" | grep_any -xF "include $_f"; then
    rep applied "already present: the include line in $OLS_CONF"
  elif [ "$_running" = 0 ]; then
    win_close
    rep proved "OpenLiteSpeed: the server is not running, so its configuration is not changed: add these lines to $OLS_CONF, then $LSWS/bin/lswsctrl start, then run sudo $HERE/install.sh --server litespeed, which verifies it:"
    printf '     %s\n     include %s\n     %s\n' "$OLS_INC_BEGIN" "$_f" "$OLS_INC_END" >> "$RT/proved"
    return 0
  else
    test_pause after-layer1
    # the one edit: read as the owner (no link, the inode it stat'ed, unchanged while read), kept by root
    _kept=$(mktemp "$UNDO/httpd_config.conf.XXXXXXXXXX")
    owner_read "$OLS_FU" "$OLS_FG" "$OLS_CONF" > "$_kept" || { rm -f "$_kept"; arm_refuse "$OLS_CONF changed, or is a link, while it was read; nothing was edited"; return 0; }
    _facts=$OWNER_FACTS; _before=$(sha256_of < "$_kept")
    { cat "$_kept"; printf '%s\ninclude %s\n%s\n' "$OLS_INC_BEGIN" "$_f" "$OLS_INC_END"; } > "$RT/new"
    _after=$(sha256_of < "$RT/new")
    # the record the trap, the sweep and the undo line restore from
    printf '%s\n' "path $OLS_CONF" "kept $_kept" "mode $OLS_FM" "uid $OLS_FU" "gid $OLS_FG" "mtime $(stat -c %.9Y -- "$OLS_CONF" 2>/dev/null || stat -c %Y -- "$OLS_CONF")" \
      "context ${_facts#* }" "before $_before" "after $_after" > "$UNDO/litespeed.facts.new" \
      || { rm -f "$_kept"; arm_refuse "could not write the record of the edit in $UNDO; nothing was edited"; return 0; }
    mv -f "$UNDO/litespeed.facts.new" "$UNDO/litespeed.facts" || { rm -f "$_kept"; arm_refuse "could not put the record of the edit in place in $UNDO; nothing was edited"; return 0; }
    win_add edited "$OLS_CONF" "$_after"
    [ -n "$STAMPF" ] && stamp_line edited "$OLS_CONF" "$_kept" "$_after" "$_before"
    # the file as it was read, still: a WebAdmin save between the read and the rename is refused (exit 5),
    # never overwritten
    _orc=0; owner_put "$OLS_FU" "$OLS_FG" "$OLS_CONF" "$OLS_FM" "" "${_facts%% *}" < "$RT/new" || _orc=$?
    if [ "$_orc" != 0 ]; then
      arm_refuse "could not edit $OLS_CONF (its owner's writer exited $_orc${OWNER_ERR:+: $OWNER_ERR})"
      # an edit that never landed leaves its kept copy and record behind; they go when the file is the one before
      if [ "$(rd_file "$OLS_CONF" | sha256_of)" = "$_before" ]; then rm -f -- "$_kept" "$UNDO/litespeed.facts"; fi
      return 0
    fi
    rep applied "edited $OLS_CONF: one include line between two marker comments (the bytes before are kept at $_kept)"
    test_kill after-include-line
  fi
  # the restart, then the module's own word: that is the test OpenLiteSpeed does not have
  _off=$(wc -c < "$LSWS/logs/error.log" 2>/dev/null || echo 0)
  [ -n "$C7_UID" ] && c7_before "$C7_CNT" "$C7_UID"
  ols_restart || :; OLS_RESTARTED=1
  rep proved "OpenLiteSpeed: restarted ($LSWS/bin/lswsctrl restart)"
  test_pause after-restart
  test_kill after-restart-before-verdict
  if c7_verdict litespeed "$C7_CNT" "${C7_UID:-}" "${C7_PROG:-none}" fresh; then
    win_close
    stale_module litespeed
    [ "$OLS_MODE" = log ] && rep proved "OpenLiteSpeed: the policy is in log mode, which denies nothing; to deny, after reading what it logs: sudo $HERE/install.sh --server litespeed --arm-deny"
    return 0
  fi
  # not confirmed: up with no writer is kept and said; a refusal the error log corroborates, or a server
  # that did not come back, is taken back and restarted once more
  # a refusal is the module's word in the error log or in its status file (C7_REFUSED); either one is
  # taken, so a rotated log or a quieter log level cannot hide it (the log line first: it names the cause)
  _new=$(tail -c +"$((_off + 1))" "$LSWS/logs/error.log" 2>/dev/null | ctl_strip | grep -m1 'whisper edge.*refus' | cut -c1-300)
  [ -n "$_new" ] || _new=${C7_REFUSED:+the module reports in its status: $C7_REFUSED}
  if ols_up && [ -z "$_new" ]; then
    win_close
    # A configuration the module refuses at load leaves no worker writing and no status file (measured on
    # a test host: a refusal is in the error log alone), so with no status and no refusal in the log the two
    # cannot be told apart from here: the configuration is kept, and the line says both and where to look.
    rep proved "OpenLiteSpeed: serving, but the module wrote no status for this configuration and the error log since the restart names no refusal: it did not load, or it refused the configuration where this run could not read it (check ls_enabled 1, $LSWS/modules/mod_whisper_edge.so and $LSWS/logs/error.log); the configuration is kept"
    return 0
  fi
  test_kill after-restart-before-restore
  # httpd_config.conf changed since this run's edit (a WebAdmin save, a hand edit): nothing is taken back,
  # not even the included file its include line names; the change is said, with the diff to read
  _fa=$(sed -n 's/^after //p' "$UNDO/litespeed.facts" 2>/dev/null); _fk=$(sed -n 's/^kept //p' "$UNDO/litespeed.facts" 2>/dev/null)
  if [ -L "$OLS_CONF" ] || [ ! -f "$OLS_CONF" ] || [ "$(rd_file "$OLS_CONF" | sha256_of)" != "$_fa" ]; then
    rep proved "OpenLiteSpeed: ${_new:-the server did not come back after the restart}; $OLS_CONF changed after this run edited it, so nothing was taken back or restarted; the bytes from before this run are at ${_fk:-the kept copy}; compare: diff ${_fk:-<kept>} $OLS_CONF"
    ARM_UNCONFIRMED="$ARM_UNCONFIRMED litespeed"; win_close; return 0
  fi
  win_rollback_quiet
  ols_restart || :
  if ols_up; then
    rep proved "OpenLiteSpeed: ${_new:-the server did not come back after the restart}; removed what this run wrote ($ROLLED); restarted, and the previous configuration is serving"
    ARM_FAILED="$ARM_FAILED litespeed"
  else
    rep proved "OpenLiteSpeed: restored $OLS_CONF byte-identical; OpenLiteSpeed did not start; it was serving before this run; run: $LSWS/bin/lswsctrl start; see $LSWS/logs/error.log"
    OLS_DOWN=1
  fi
  win_close
}

# Before any server write: the modules' own probe of the data directory, run as the server's worker user (its own groups,
# no new privileges), before anything is written: the plane the deny rules read must be present and read
# as the module would bind it. Sets PROBE_WHY when it is not.
probe_planes() { # <worker user> [data directory, else the installer's]
  PROBE_WHY=""; _pd=${2:-$DIR}
  _pu=$(id -u "$1" 2>/dev/null || :); _pg=$(id -g "$1" 2>/dev/null || :)
  [ -n "$_pu" ] || { PROBE_WHY="the worker user $1 does not exist here"; return 1; }
  _po=$(as_user "$_pu" "$_pg" timeout --kill-after=10 "$T_CMD" "$TOOL_LOOKUP" --probe-dir "$_pd" 2>&1 | ctl_strip) || :
  printf '%s\n' "$_po" | grep_any -E '^[[:space:]]*plane reputation[[:space:]]+state=present probe=present,schema-ok' && return 0
  PROBE_WHY="the module's own probe of $_pd, run as $1, does not read the reputation plane as bound: $(printf '%s\n' "$_po" | grep -E 'reputation|refus|denied|error' | sed -n 1p | cut -c1-240)"
  return 1
}
# ---- one server's arm ---------------------------------------------------------------------------------
WROTE_SRV=0
apply_arm() { # <server>
  _s=$1; WROTE_SRV=0; _stop=""
  case "$_s" in
    nginx)
      NGX_ARGS=""
      _mp=$(master_pid nginx "${NGX_PIDFILE:-/run/nginx.pid}" /run/nginx.pid /var/run/nginx.pid)
      if [ -n "$_mp" ]; then
        _ma=$(master_args "$_mp" "$NGX_BIN" -c -p) && _mr=0 || _mr=$?
        if [ "$_mr" = 2 ]; then rep detected "nginx: the master $_mp is not this host's (another mount namespace, or another binary): treated as not running"; NGX_RUNNING=no
        else NGX_ARGS=$(printf '%s\n' "$_ma" | tr '\n' ' '); NGX_ARGS=${NGX_ARGS% }; fi
      fi
      # a master started with its own -c reads that file, so the includes, the loaded check and every test
      # and reload are that configuration's, not the build's default
      _mc=$(printf '%s\n' "${_ma:-}" | awk 'p { print; exit } $0 == "-c" { p = 1 }')
      _mpx=$(printf '%s\n' "${_ma:-}" | awk 'p { print; exit } $0 == "-p" { p = 1 }')
      if [ -n "$_mc" ]; then
        case "$_mc" in /*) ;; *) _mc="${_mpx:-/usr/share/nginx/}/$_mc" ;; esac
        if [ "$_mc" != "$NGX_CONF" ] && [ -f "$_mc" ]; then
          rep detected "nginx: the running master reads $_mc (its -c), so that configuration is the one applied, tested and reloaded"
          NGX_CONF=$_mc
          _inc=$(nginx_includes "$NGX_CONF")
          NGX_MAIN_INC=$(printf '%s\n' "$_inc" | sed -n 's/^main //p' | sed -n 1p)
          NGX_HTTP_INC=$(printf '%s\n' "$_inc" | sed -n 's/^http //p' | grep -v 'sites-enabled' | sed -n 1p || :)
          # shellcheck disable=SC2086
          case "$(tmo nginx $NGX_ARGS -T 2>/dev/null || :)" in *ngx_http_whisper_edge_module*) NGX_LOADED=yes ;; *) NGX_LOADED=no ;; esac
        fi
      fi
      _drop="$NGX_HTTP_INC/whisper-edge.conf"
      [ -n "$NGX_HTTP_INC" ] || _stop="the http {} block of $NGX_CONF includes no directory of *.conf files, so there is nowhere to add a file without editing $NGX_CONF"
      [ -n "$_stop" ] || [ "$NGX_LOADED" = yes ] || [ -n "$NGX_MAIN_INC" ] || _stop="$NGX_CONF includes no module directory at the main level, so the module's load line has nowhere to go"
      [ -n "$_stop" ] || chain_root "$NGX_HTTP_INC" || _stop="$NGX_HTTP_INC is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others)"
      [ -n "$_stop" ] || [ "$NGX_LOADED" = yes ] || chain_root "$NGX_MAIN_INC" || _stop="$NGX_MAIN_INC is not root's alone"
      ;;
    apache)
      AP_ARGS=""
      _drop="$AP_INC/whisper-edge.conf"
      case "$AP_LAYOUT" in
        debian|rhel) chain_root "$AP_INC" || _stop="$AP_INC is not root's alone (it, or a directory above it, is owned by another account or writable by a group or others)" ;;
        *) _stop="this Apache's layout (${AP_LAYOUT:-unknown}) has no directory its main configuration is known to include" ;;
      esac
      # a parent started by hand with its own -f (and -d) reads that file: its test and graceful carry them,
      # and the installer's file is applied only when that configuration includes the layout's directory
      _mp=$(master_pid "$AP_NAME" /run/apache2/apache2.pid /var/run/apache2/apache2.pid /run/httpd/httpd.pid /var/run/httpd/httpd.pid)
      [ -n "$_mp" ] || _mp=$(ps -eo pid=,ppid=,args= | WE_AWK_b="$AP_BIN" awk 'BEGIN { b = ENVIRON["WE_AWK_b"] } $2 == 1 && $3 == b { print $1; exit }')
      if [ -z "$_stop" ] && [ -n "$_mp" ]; then
        _ma=$(master_args "$_mp" "$AP_BIN" -f -d) && _mr=0 || _mr=$?
        if [ "$_mr" = 2 ]; then rep detected "Apache: the parent $_mp is not this host's (another mount namespace, or another binary): treated as not running"; AP_RUNNING=no
        else
          _af=$(printf '%s\n' "${_ma:-}" | awk 'p { print; exit } $0 == "-f" { p = 1 }')
          _ad=$(printf '%s\n' "${_ma:-}" | awk 'p { print; exit } $0 == "-d" { p = 1 }')
          if [ -n "$_af" ]; then
            case "$_af" in /*) ;; *) _af="${_ad:-$("$AP_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p' | sed -n 1p)}/$_af" ;; esac
            _en=$AP_INC; [ "$AP_LAYOUT" = debian ] && _en=/etc/apache2/conf-enabled
            AP_ARGS="-f $_af${_ad:+ -d $_ad}"
            rep detected "Apache: the running parent reads $_af (its -f), so that configuration is the one tested and reloaded"
            # its Include lines, a relative one read against its ServerRoot (the file's own, else -d, else
            # the build's), must reach the directory the installer's file is enabled in
            _sr=$(sed -n 's/^[[:space:]]*ServerRoot[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\)"\{0,1\}.*/\1/p' "$_af" 2>/dev/null | sed -n 1p)
            _sr=${_sr:-${_ad:-$("$AP_BIN" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\([^"]*\)".*/\1/p' | sed -n 1p)}}
            sed -n 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee]\([Oo][Pp][Tt][Ii][Oo][Nn][Aa][Ll]\)\{0,1\}[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\).*/\2/p' "$_af" 2>/dev/null \
              | WE_AWK_r="$_sr" WE_AWK_e="$_en/" awk 'BEGIN { r = ENVIRON["WE_AWK_r"]; e = ENVIRON["WE_AWK_e"] } { p = $0; if (substr(p, 1, 1) != "/") p = r "/" p; if (index(p, e) == 1) f = 1 } END { exit !f }' \
              || _stop="the running parent reads $_af (its -f), which includes nothing from $_en, so a file there would not load"
          fi
        fi
      fi
      [ -n "$_stop" ] || [ "$AP_LAYOUT" != debian ] || chain_root /etc/apache2/conf-enabled || _stop="/etc/apache2/conf-enabled is not root's alone"
      # read again under the parent's own -f: the module counts as loaded only by a file other than ours
      if [ -z "$_stop" ] && [ "$AP_LOADED" = yes ] && ! ap_loaded_elsewhere "$_drop"; then AP_LOADED=no; fi
      ;;
    litespeed) apply_litespeed; return 0 ;;
  esac
  if [ -z "$_stop" ] && ! tools_ready; then
    _stop="the installer proves what it applied with whisper-edge-lookup and whisper-edge-summary, and $TOOL_WHY"
  fi
  # the operator's own lines first: a data directory they keep is the one the worker must reach
  if [ -z "$_stop" ]; then
    case "$_s" in
      nginx) keep_scan nginx "$(ngx_http_lines "$_drop")"; realip_advice nginx "$_drop" ;;
      apache) keep_scan apache "$(ap_main_lines "$_drop")"; realip_advice apache "$_drop" ;;
    esac
  fi
  if [ -z "$_stop" ]; then
    case "$_s" in nginx) _wu=${NGINX_USER:-www-data} ;; *) _wu=${APACHE_USER:-www-data} ;; esac
    if [ -n "$K_REPF" ]; then
      rep proved "$(display "$_s"): your reputation file $K_REPF is kept; the probe reads directories, so the module's own status after the reload is what proves it"
      if [ "$SE_ON" = 1 ]; then
        _kl=$(stat -c %C -- "$K_REPF" 2>/dev/null | cut -d: -f3)
        case "$_kl" in "$SE_TYPE"|httpd_var_lib_t) ;; *) rep proved "$(display "$_s"): SELinux: your reputation file reads ${_kl:-no label}, which a confined server cannot map; label it as the installer labels its own: semanage fcontext -a -t $SE_TYPE '$K_REPF'; restorecon $K_REPF" ;; esac
      fi
    elif [ -n "$K_SNAPV" ]; then
      rep proved "$(display "$_s"): your snapshot file $K_SNAPV is kept; the probe reads directories, so the module's own status after the reload is what proves it"
    else
      probe_planes "$_wu" "${K_DATAV:-$DIR}" || _stop=$PROBE_WHY
    fi
  fi
  if [ -n "$_stop" ]; then
    print_arm "$_s" "$_stop: add it yourself"
    rep proved "$(display "$_s"): nothing was applied: $_stop; the block to add is printed above"
    ARM_FAILED="$ARM_FAILED $_s"
    return 0
  fi
  # what the operator keeps, recorded, then the test of the configuration as it stands
  STAMP_KEEP="keep_$_s="
  [ -z "$K_POLICY" ] || STAMP_KEEP="${STAMP_KEEP}p"
  [ -z "$K_DATA" ] || STAMP_KEEP="${STAMP_KEEP}d"
  [ -z "$K_SUMMARY" ] || STAMP_KEEP="${STAMP_KEEP}s"
  [ -z "$K_MODE" ] || STAMP_KEEP="${STAMP_KEEP}m"
  [ -n "$STAMPF" ] && stamp_line input "$STAMP_KEEP"
  if [ -n "$K_POLICY" ]; then
    rep applied "$(display "$_s"): your policy ($K_POLICY) is kept; the default's four rules were not written; to adopt them, put these in place of yours:"
    case "$_s" in nginx) translate nginx | sed 's/^/     /' >> "$RT/applied" ;; apache) translate apache | sed 's/^/     /' >> "$RT/applied" ;; esac
  fi
  # what the module must name after the reload: the program of the http-level rules, from the pinned
  # text or the operator's kept lines, compiled before anything is written; the counters it writes to
  if [ -n "$K_POLICY" ]; then
    case "$_s" in
      nginx) _rules=$(ngx_http_lines "$_drop" | awk -F'\t' '$1 == "whisper_edge_policy" { a = $3; sub(/;[ \t]*$/, "", a); gsub(/^"|"$/, "", a); print a }') ;;
      apache) _rules=$(ap_main_lines "$_drop" | awk -F'\t' '$1 == "whisperedgepolicy" { a = $3; gsub(/^"|"$/, "", a); print a }') ;;
    esac
  else
    _rules=$(policy_text | sed -n '3,$p' | sed 's/#.*//; s/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//')
  fi
  # with the operator's own policy kept, the program is theirs (built from policy, set and threshold lines
  # the installer does not compile); the verdict then takes the program their live worker reports
  if [ -n "$K_POLICY" ]; then C7_PROG=any; else C7_PROG=$(c7_program "$_rules"); fi
  C7_CNT=${K_SUMMARY:-$DIR/counters}
  case "$_s" in nginx) C7_UID=$(id -u "${NGINX_USER:-www-data}" 2>/dev/null || :) ;; apache) C7_UID=$(id -u "${APACHE_USER:-www-data}" 2>/dev/null || :) ;; esac
  # the plane the module binds: the operator's kept data directory or snapshot, else the installer's
  C7_REP=$DIR/reputation.bin
  if [ -n "$K_REPF" ]; then C7_REP=$K_REPF; elif [ -n "$K_DATAV" ]; then C7_REP=$K_DATAV/reputation.bin; elif [ -n "$K_SNAPV" ]; then C7_REP=$K_SNAPV; fi
  C7_GEN=$(le_u64 "$C7_REP" 16)
  _pt=$(srv_test "$_s" 2>&1) && _pr=0 || _pr=$?
  if [ "$_pr" != 0 ]; then
    if [ "$_pr" = 124 ] || [ "$_pr" = 137 ]; then _why="its configuration test did not return within $T_CMD s"; else _why="your configuration fails its own test before any change: $(printf '%s' "$_pt" | srv_refusal "$(srv_test_cmd "$_s")" "$_pr")"; fi
    rep proved "$(display "$_s"): $_why; nothing was written"
    ARM_FAILED="$ARM_FAILED $_s"
    return 0
  fi
  # the writes, in the order that keeps every partial state loadable, inside the open window
  win_open "$_s"
  case "$_s" in
    nginx)
      if [ -n "$ML_V" ]; then render_memlock "$NGX_UNIT" "$ML_V" > "$RT/new"; srv_put "$(memlock_dropin "$NGX_UNIT")" "the memory lock" 0644 || [ -z "$ARM_REFUSED" ] || return 0; fi
      if [ "$NGX_LOADED" != yes ]; then
        render_nginx_load "$NGX_MOD" > "$RT/new"; srv_put "$NGX_MAIN_INC/50-whisper-edge.conf" "the module's load line" 0644 || [ -z "$ARM_REFUSED" ] || return 0
      fi
      render_nginx_keep | prov_wrap "the default policy for nginx" | with_test_rule nginx > "$RT/new"
      srv_put "$_drop" "the default policy" 0644 || [ -z "$ARM_REFUSED" ] || return 0
      test_pause in-window ;;
    apache)
      if [ -n "$ML_V" ]; then render_memlock "$AP_UNIT" "$ML_V" > "$RT/new"; srv_put "$(memlock_dropin "$AP_UNIT")" "the memory lock" 0644 || [ -z "$ARM_REFUSED" ] || return 0; fi
      _lm=""; [ "$AP_LOADED" = yes ] || _lm=$AP_MOD
      render_apache_keep "$_lm" | prov_wrap "the default policy for Apache" | with_test_rule apache > "$RT/new"
      srv_put "$_drop" "the default policy" 0644 || [ -z "$ARM_REFUSED" ] || return 0
      test_pause in-window
      if [ "$AP_LAYOUT" = debian ]; then
        _ln=/etc/apache2/conf-enabled/whisper-edge.conf
        if [ -L "$_ln" ] && [ "$(readlink -- "$_ln")" = ../conf-available/whisper-edge.conf ]; then rep applied "already present: $_ln (enabled)"
        elif [ -e "$_ln" ] || [ -L "$_ln" ]; then arm_refuse "$_ln exists and is not the installer's link; move it aside and run again"; return 0
        else
          win_add link "$_ln" ../conf-available/whisper-edge.conf
          [ -n "$STAMPF" ] && stamp_line link "$_ln" ../conf-available/whisper-edge.conf
          tmo a2enconf -q whisper-edge >/dev/null 2>&1 || { arm_refuse "a2enconf whisper-edge failed"; return 0; }
          test_kill after-a2enconf
          rep applied "enabled $_ln (a2enconf whisper-edge)"; WROTE_SRV=1
        fi
      fi ;;
  esac
  # the test, on what was written ; a refusal takes this run's writes back
  if [ "$WROTE_SRV" = 0 ]; then
    win_close
    rep proved "$(display "$_s"): nothing changed in its configuration, so it was not reloaded"
    if srv_running "$_s" && [ -n "$C7_PROG" ] && [ -n "$C7_UID" ]; then c7_verdict "$_s" "$C7_CNT" "$C7_UID" "$C7_PROG" readonly || :; fi
    srv_running "$_s" && stale_module "$_s"
    return 0
  fi
  _t=$(srv_test "$_s" 2>&1) && _tr=0 || _tr=$?
  _refused_plane=""
  [ "$_s" = nginx ] && _refused_plane=$(printf '%s\n' "$_t" | grep -F 'is refused at configuration and reads unknown' | ctl_strip | sed -n 1p)
  if [ "$_tr" != 0 ] || [ -n "$_refused_plane" ]; then
    if [ "$_tr" = 124 ] || [ "$_tr" = 137 ]; then _why="the configuration test did not return within $T_CMD s"
    elif [ -n "$_refused_plane" ]; then _why="the module refused a plane: $(printf '%s' "$_refused_plane" | cut -c1-300)"
    else _why="the configuration test refused it: $(printf '%s' "$_t" | srv_refusal "$(srv_test_cmd "$_s")" "$_tr")"; fi
    win_rollback_quiet
    rep proved "$(display "$_s"): $_why; removed what this run wrote ($ROLLED); the previous configuration is unchanged"
    win_close; ARM_FAILED="$ARM_FAILED $_s"
    return 0
  fi
  win_close
  rep proved "$(display "$_s"): the configuration test passed"
  test_kill after-test-before-reload
  if ! srv_running "$_s"; then
    rep proved "$(display "$_s"): the server is not running; the configuration was applied and tested; it arms when the server starts"
    return 0
  fi
  [ -n "$C7_UID" ] && c7_before "$C7_CNT" "$C7_UID"
  if srv_reload "$_s" >"$RT/reload.out" 2>&1; then
    rep proved "$(display "$_s"): reloaded ($RL_CMD)"
    RELOADED="$RELOADED $_s"
    test_kill after-reload-before-status
    test_pause after-reload
    if [ -z "$C7_PROG" ] || [ -z "$C7_UID" ]; then
      rep proved "$(display "$_s"): applied and serving, but unverified: the program digest or the worker's uid could not be read"
      ARM_UNCONFIRMED="$ARM_UNCONFIRMED $_s"
    else
      c7_verdict "$_s" "$C7_CNT" "$C7_UID" "$C7_PROG" fresh || :
    fi
    stale_module "$_s"
    return 0
  else
    _rr=$?
    if [ "$_rr" = 124 ] || [ "$_rr" = 137 ]; then
      rep proved "$(display "$_s"): reload did not return within $T_CMD s; the configuration tested clean; check: systemctl status $(case $_s in nginx) echo "$NGX_UNIT" ;; *) echo "$AP_UNIT" ;; esac)"
    else
      rep proved "$(display "$_s"): reload failed ($RL_CMD): $(srv_refusal "$RL_CMD" "$_rr" < "$RT/reload.out"); the configuration tested clean and stays; retry: $RL_CMD"
    fi
    ARM_UNCONFIRMED="$ARM_UNCONFIRMED $_s"
  fi
  test_kill after-reload-before-status
}
# the rollback after a refused test, quietly: sets ROLLED to what it removed
win_rollback_quiet() {
  printf '%s\n' "$WIN_LIST" | while IFS= read -r _w; do
    [ -n "$_w" ] || continue
    # shellcheck disable=SC2086
    set -- $_w
    case "$1" in
      created)
        if [ -f "$2" ] && [ ! -L "$2" ] && [ "$(sha256_of < "$2")" = "$3" ]; then
          if [ -n "${6:-}" ] && [ "$6" != - ] && [ -s "$6" ]; then
            # a file this run replaced: its previous bytes back, as the same writer, then the copy goes
            if owner_put "${4:-0}" "${5:-0}" "$2" "${7:-0644}" < "$6"; then rm -f -- "$6"; echo "$2 (its previous bytes restored)"
            else echo "NOT $2: its previous bytes could not be put back; they are at $6; restore: cp $6 $2"; fi
          else
            owner_rm "${4:-0}" "${5:-0}" "$2"; echo "$2"
            # the copies OpenLiteSpeed made of the installer's own file, if it loaded it in the window
            if [ "$2" = "$LSWS/conf/whisper-edge.conf" ]; then
              for _c in "${2}0" "${2}0,v"; do if [ -f "$_c" ] && [ ! -L "$_c" ]; then owner_rm "${4:-0}" "${5:-0}" "$_c"; fi; done
            fi
          fi
        elif [ -n "${6:-}" ] && [ "$6" != - ] && [ -f "$6" ]; then
          # never written (its bytes are still the previous ones: the copy is not needed), or changed since
          # this run wrote it (the copy is the only record of what was there: named, never removed)
          if [ -f "$2" ] && rd_file "$2" | cmp -s "$6" -; then rm -f -- "$6"
          else echo "NOT $2: it changed after this run wrote it, so it was not restored; its bytes from before this run are at $6"; fi
        fi ;;
      link) if [ -L "$2" ] && [ "$(readlink -- "$2")" = "$3" ]; then rm -f -- "$2"; echo "$2"; fi ;;
      edited)
        if ols_restore >/dev/null; then echo "$2 (restored)"
        else
          # changed since this run edited it (a WebAdmin save, a hand edit): never overwritten; named instead
          _k=$(sed -n 's/^kept //p' "$UNDO/litespeed.facts" 2>/dev/null)
          echo "NOT $2: it changed after this run edited it, so it was not restored; the bytes from before are at ${_k:-the kept copy}; compare: diff ${_k:-<kept>} $2"
        fi ;;
    esac
  done > "$RT/rolled" || :
  ROLLED=$(tr '\n' ' ' < "$RT/rolled"); ROLLED=${ROLLED% }
  # walked: a kept copy it names is the operator's record now, which a later win_close must not remove
  WIN_LIST=""
}

# Each web arm. The memory lock first: its value is a function of what was armed.
ARM_FAILED=""; ARM_UNCONFIRMED=""; RELOADED=""
# "loaded" from apache2ctl -M counts the installer's own drop-in's LoadModule; what is written and shown
# needs the operator's (the arm reads it again under a hand-started parent's -f)
if [ "$AP_LOADED" = yes ] && [ -n "$AP_INC" ] && ! ap_loaded_elsewhere "$AP_INC/whisper-edge.conf"; then AP_LOADED=no; fi
for s in $ARMS; do
  case "$s" in
    nginx) memlock_line nginx "$NGX_UNIT" ;;
    apache) memlock_line Apache "$AP_UNIT" ;;
    litespeed) memlock_line OpenLiteSpeed "${OLS_UNIT:-lshttpd.service}" ;;
  esac
  if [ "$NOAPPLY" = 1 ]; then
    print_arm "$s" "--no-apply: nothing of this was written; the deny arms after your own configuration test passes"
    rep proved "$(display "$s"): nothing was applied (--no-apply), so there is no configuration test to run and nothing was reloaded"
  elif [ "$DRY" = 1 ]; then
    print_arm "$s" "--dry-run: this is what would be written, then tested, then reloaded on a pass"
    case "$s" in
      nginx) [ -z "$NGX_HTTP_INC" ] || { K_TPROXY=$(ngx_http_lines "$NGX_HTTP_INC/whisper-edge.conf" '^whisper_edge_trusted_proxy$'); realip_advice nginx "$NGX_HTTP_INC/whisper-edge.conf"; } ;;
      apache) [ -z "$AP_INC" ] || { K_TPROXY=$(ap_main_lines "$AP_INC/whisper-edge.conf" '^whisperedgetrustedproxy$'); realip_advice apache "$AP_INC/whisper-edge.conf"; } ;;
    esac
    rep proved "$(display "$s"): a dry run applies nothing, so there is no configuration test to run and nothing was reloaded"
  else
    apply_arm "$s"
  fi
done
# The policy itself, as a file to read and edit, once a server applies it: the pinned bytes, never
# overwritten (an edited one is the operator's and is kept, said so); the undo's shared line removes it
# only while it is still those bytes.
APPLIED_ANY=0
for s in $ARMS; do case " $ARM_FAILED " in *" $s "*) ;; *) [ "$NOAPPLY" = 0 ] && [ "$DRY" = 0 ] && APPLIED_ANY=1 ;; esac; done
# SELinux rules this run added for servers it then applied none of: taken back, the record exactly as it
# was, so a run that says "nothing was applied" leaves no change in the host's policy. (A run with no
# server to apply to, staging the planes, keeps them: a server installed later maps what is there.)
if [ -n "$SE_ADDED" ] && [ -n "$ARMS" ] && [ "$APPLIED_ANY" = 0 ] && [ "$NOAPPLY" = 0 ]; then
  printf '%s' "$SE_ADDED" | while IFS= read -r _sp; do [ -z "$_sp" ] || semanage fcontext -d "$_sp" >/dev/null 2>&1 || :; done
  if [ -f "$RT/serec.orig" ]; then cp -p -- "$RT/serec.orig" "$_serec"; else rm -f -- "$_serec"; fi
  se_relabel_dir "$DIR"
  rep applied "took back the SELinux file context rule(s) this run added ($(printf '%s' "$SE_ADDED" | awk 'NF { printf "%s%s", (n++ ? ", " : ""), $0 }')): no server it applied to was applied"
fi
if [ "$APPLIED_ANY" = 1 ]; then
  if [ ! -e "$ETC/policy.conf" ]; then
    policy_text > "$RT/new"; stamp_line created "$ETC/policy.conf" -
    owner_put 0 0 "$ETC/policy.conf" 0644 < "$RT/new" && rep applied "wrote $ETC/policy.conf (the default policy, $(wc -c < "$RT/new" | tr -d ' ') bytes, to read and edit)"
  elif [ "$(sha256_of < "$ETC/policy.conf")" = "$(policy_text | sha256_of)" ]; then rep applied "already present: $ETC/policy.conf (the default policy)"
  else rep applied "kept $ETC/policy.conf: it has your edits"; fi
fi
for s in $MISSING; do
  case "$s" in
    nginx) [ "$NOAPPLY" = 1 ] && print_arm nginx "the planes this binds are not fetched until the module is installed and this is run again, so the deny lines stay inert until then" ;;
    Apache) [ "$NOAPPLY" = 1 ] && print_arm apache "the planes this binds are not fetched until the module is installed and this is run again, so the deny lines stay inert until then" ;;
    OpenLiteSpeed) [ "$NOAPPLY" = 1 ] && print_arm litespeed "the planes this binds are not fetched until the module is installed and this is run again, so the deny lines stay inert until then" ;;
  esac
done

# ---- the resolver half, unchanged: the zone timers, a first fetch of each zone, and the block to add ---
if [ -n "$ZDIR" ] && [ "$TIMER" = 1 ] && have systemctl; then
  # One template, one instance per zone. SupplementaryGroups is named's own group, so rndc can read the
  # control key without the unit holding a single capability. Dropped when there is no such group.
  unit_plain whisper-edge-rpz@.service \
    -e "s|^ExecStart=.*|ExecStart=$(sed_rep "$(rpz_cmd sd_word %i)")|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$(sed_rep "$(sd_word "$ZDIR")")|" \
    -e "s|^SupplementaryGroups=.*|${NAMED_GROUP:+SupplementaryGroups=$(sed_rep "$NAMED_GROUP")}|"
  copy_plain whisper-edge-rpz@.timer
  # The single-zone unit an earlier install wrote is the reputation instance now: stopped and removed,
  # so one zone is never refreshed by two timers.
  if [ -e "$UNITDIR/whisper-edge-rpz.timer" ] || [ -e "$UNITDIR/whisper-edge-rpz.service" ]; then
    dosys systemctl disable --now whisper-edge-rpz.timer
    [ "$DRY" = 1 ] || rm -f "$UNITDIR/whisper-edge-rpz.timer" "$UNITDIR/whisper-edge-rpz.service"
    rep applied "the earlier single-zone unit whisper-edge-rpz is replaced by whisper-edge-rpz@rpz.whisper.online"
  fi
  sd_reload
  for z in $ZONES; do
    if [ "$SYSTEMD" = 1 ]; then dosys systemctl enable --now "whisper-edge-rpz@$z.timer"; else dosys systemctl enable "whisper-edge-rpz@$z.timer"; fi
  done
  rep applied "$(would "enable the zone timers" "zone timers enabled"), one per zone: every 5 minutes, fetching only when the zone's own SOA REFRESH (or RETRY, after a failure) says it is due, and reloading that one zone in named when its serial moved"
elif [ -n "$ZDIR" ] && [ "$TIMER" = 1 ]; then
  rep applied "no systemctl here, so no zone timer was installed; schedule each zone yourself:"
  for z in $ZONES; do rep applied "  */5 * * * * $(cron_line "$(rpz_cmd sh_word "$z")")"; done
fi
if [ -n "$ZDIR" ]; then
  for z in $ZONES; do
    if [ "$DRY" = 1 ]; then rep armed "would fetch the zone $z into $(zone_file "$z")"; continue; fi
    set -- --zone "$z" --zone-file "$ZDIR/" --dir "$DIR"
    if [ -n "$NAMED_CONF" ]; then set -- "$@" --named-conf "$NAMED_CONF"; fi
    _out=$("$REFRESH" "$@" --base "$BASE" 2>&1) && rc=0 || rc=$?
    # Not fatal to the install: until the block below is added, named does not load the zone and the
    # refresh says so; a reload it could not confirm is the timer's to retry, and it will.
    case "$rc" in
      0) rep armed "zone $z installed at $(zone_file "$z")" ;;
      5) rep armed "zone $z has no zone yet; its timer installs it when its plane first publishes" ;;
      *) rep armed "zone $z: the refresh reported a problem; its timer retries it"; quoted armed "refresh:" "$(printf '%s\n' "$_out" | tail -n 2)" ;;
    esac
  done
  paste "" "  # BIND: load each fetched zone as a local master and reference it as a policy zone, in this" \
    "  # order, below any policy zones of your own (first match wins). The files are under named's own" \
    "  # directory on purpose; see the note in the README on AppArmor. A zone loads under its own name" \
    "  # only: the refresh refuses a file named loads as anything else." \
    "  zone \"rpz.whisper.online\" {" \
    "      type master;" \
    "      file \"$(zone_file rpz.whisper.online)\";" \
    "  };" \
    "  zone \"rpz-rpki-unreachable.whisper.online\" {" \
    "      type master;" \
    "      file \"$(zone_file rpz-rpki-unreachable.whisper.online)\";" \
    "  };" \
    "  options {                     # into your existing options { } block, not a second one" \
    "      response-policy {" \
    "          zone \"rpz.whisper.online\";" \
    "          zone \"rpz-rpki-unreachable.whisper.online\" policy disabled log yes;   # logged, not enforced" \
    "      } qname-wait-recurse no;" \
    "  };" \
    "  # Then, once: named-checkconf && rndc reload" \
    "  # Until a zone's plane first publishes, its file is absent: named logs that it did not load and" \
    "  # resolves without it, and the other zone still applies. Its timer installs it when it appears." \
    "  # Read the resolver notes in the README first: a DNSSEC-validating stub gets the unrewritten" \
    "  # answer for a signed name, which is a real limit and not a bug in this zone."
fi

# ---- a feed key, when the Whisper CLI is logged in here -----------------------------------------------
#
# A key buys this box its own tenant plane: the account's allow and deny lists. The CLI's key is never
# copied here; it is used once, by whisper-edge-refresh --enroll, to mint a feed key that can read the feed
# and nothing else. Only its PRESENCE is checked here: the key file is read by the refresh, never a shell.
cli_key_present() {
  [ -n "${WHISPER_API_KEY:-}" ] || [ -n "${WHISPER_KEY:-}" ] && return 0
  if [ -n "${SUDO_USER:-}" ]; then
    _h=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
    [ -n "$_h" ] && [ -e "$_h/.config/whisper/key" ] && return 0
  fi
  [ -n "${HOME:-}" ] && [ -e "$HOME/.config/whisper/key" ]
}
edge_label() { # the short hostname, at most 64 characters and 192 UTF-8 bytes
  _l=$(hostname -s 2>/dev/null || true)
  [ -n "$_l" ] || { _l=$(hostname 2>/dev/null || echo edge); _l=${_l%%.*}; }
  printf '%s' "$_l" | python3 -c 'import sys
s = sys.stdin.read()[:64]
while len(s.encode()) > 192:
    s = s[:-1]
print(s)'
}
if [ "$TIMER" = 1 ] && have systemctl; then
  # The keyed unit is the file in this tree with its paths moved, and nothing else.
  _etc_env=""
  [ "$ETC" = /etc/whisper-edge ] || _etc_env="Environment=WHISPER_EDGE_ETC=$(sed_rep "$(sd_word "$ETC")")"
  move_paths whisper-edge-refresh-keyed.service | RU_FROM=- unit_plain whisper-edge-refresh-keyed.service \
    -e "s|^ExecStart=.*|ExecStart=$(sed_rep "$(keyed_cmd sd_word)")${_etc_env:+\\n$_etc_env}|"
  copy_plain whisper-edge-refresh-keyed.timer
  sd_reload
fi
if [ -e "$ETC/key" ]; then
  rep applied "tenant plane: enrolled already, feed key $(cat "$ETC/key.id" 2>/dev/null || echo '(no key.id)') in $ETC/key; to return this box to keyless: whisper-edge-refresh --unenroll"
  if [ "$TIMER" = 1 ] && [ "$SYSTEMD" = 1 ]; then dosys systemctl enable --now whisper-edge-refresh-keyed.timer; fi
elif ! have python3; then
  rep applied "tenant plane: keyed enrolment needs python3; this box stays on the keyless planes"
elif cli_key_present; then
  LBL=$(edge_label)
  set -- --enroll --label "$LBL" --dir "$DIR"
  [ "$TIMER" = 1 ] || set -- "$@" --no-timer
  if [ "$DRY" = 1 ]; then
    rep applied "would run: $REFRESH_AT $(join_words sh_word "$@")"
  else
    _out=$(WHISPER_EDGE_ETC="$ETC" WHISPER_EDGE_BASE="$BASE" "$REFRESH_AT" "$@" 2>&1) && rc=0 || rc=$?
    quoted applied "enrolment:" "$_out"
    [ "$rc" = 0 ] || rep applied "tenant plane: enrolment did not complete; this box stays keyless; run whisper-edge-refresh --enroll to try again"
  fi
else
  rep applied "tenant plane: no Whisper CLI key on this host, so this box is keyless; to add your own allow and deny lists later: whisper-edge-refresh --enroll"
fi
[ "$UNITS" = 1 ] && rep applied "schedule: systemctl list-timers 'whisper-edge-*'"
stamp_close

# ---- 6. the undo block ---------------------------------------------------------------------------------
#
# Built from everything this installer would have written on this box, filtered to what exists and is
# still its own (never from what this one run wrote, so a re-run's lines undo the first run too). Each
# line takes the run's lock first and refuses while an installer run holds it. The shared line refuses
# while a server still applies the policy, and keeps the refresh units while anything it does not name
# still reads them. The planes, the key and the refresh are data, not configuration, and stay.
undo_line() { # <label> <script>: one pasteable line, the script under the installer's lock
  _s="exec 7>>$(sh_word "$LOCK"); if ! flock -n 7; then t=\$(cat $(sh_word "$LOCK")); if [ -n \"\$t\" ]; then t=\"at \$t\"; else t=\"moments ago\"; fi; echo \"another installer run is in progress, started \$t; nothing was removed\"; exit 75; fi; $2"
  rep undo "$1: sh -c $(sh_word "$_s")"
}
ours_check() { # <file> -> a shell test: the file is there and still the installer's own
  # shellcheck disable=SC2016 # the test is printed for the undo line to run, so it must not expand here
  printf '[ -f %s ] && [ "$(tail -n +2 %s | sha256sum | cut -c1-64)" = "$(sed -n %s %s)" ]' \
    "$(sh_word "$1")" "$(sh_word "$1")" "'1s/.* sha256 \\([0-9a-f]\\{64\\}\\) of the lines below.*/\\1/p'" "$(sh_word "$1")"
}
SERVER_FILES=""
[ -n "${NGX_HTTP_INC:-}" ] && SERVER_FILES="$SERVER_FILES nginx=$NGX_HTTP_INC/whisper-edge.conf"
[ -n "${AP_INC:-}" ] && SERVER_FILES="$SERVER_FILES Apache=$AP_INC/whisper-edge.conf"
[ "${OLS:-0}" = 1 ] && SERVER_FILES="$SERVER_FILES OpenLiteSpeed=$LSWS/conf/whisper-edge.conf"
# One line per server, built from what is on this box and still the installer's (never from what this run
# alone wrote, so a re-run's line undoes the first run too): its files removed in the reverse of the order
# they were written, the server's own test, then its reload when it runs; the unit's memory-lock drop-in
# last, with a daemon-reload. Every directory these touch is root's alone, so root removes by name.
srv_undo_line() { # <server> <test command> <reload command or -> <link or -> <files, newest first...>
  _us=$1; _ut=$2; _ur=$3; _ul=$4; shift 4
  _b=""; _any=0
  if [ "$_ul" != - ] && [ -L "$_ul" ]; then _b="$_b if [ -L $(sh_word "$_ul") ] && [ \"\$(readlink $(sh_word "$_ul"))\" = ../conf-available/whisper-edge.conf ]; then a2disconf -q whisper-edge >/dev/null 2>&1 || rm -f $(sh_word "$_ul"); fi;"; _any=1; fi
  _ml=0
  for _f in "$@"; do
    is_ours "$_f" || continue
    _b="$_b if $(ours_check "$_f"); then rm -f $(sh_word "$_f"); fi;"; _any=1
    case "$_f" in "$UNITDIR"/*) _ml=1 ;; esac
  done
  [ "$_any" = 1 ] || return 0
  _b="$_b if $_ut >/dev/null 2>&1; then"
  [ "$_ur" = - ] || _b="$_b $_ur >/dev/null 2>&1 || echo 'the configuration is restored and tests clean, but the reload failed: run $_ur';"
  [ "$_ml" = 1 ] && _b="$_b systemctl daemon-reload;"
  _b="$_b echo '$(display "$_us"): the installer'\''s files are removed and the previous configuration is serving'; else echo '$(display "$_us"): the files are removed, but the configuration does not pass its test now; nothing was reloaded'; exit 1; fi"
  undo_line "undo, $(display "$_us")" "$_b"
}
# OpenLiteSpeed's line: httpd_config.conf put back from the kept copy and whisper-edge.conf removed, both
# done AS the directory's owner (the bytes piped in by root, never a path root writes through), only while
# the file is still the installer's edit, its context set back through a descriptor; then a restart.
ols_undo_line() {
  _f="$LSWS/conf/whisper-edge.conf"; _ff="$UNDO/litespeed.facts"
  { [ -f "$_ff" ] || is_ours "$_f"; } || return 0
  _fp=""; _fk=""; _fa=""; _fm=""; _ft=""; _fc=""; _fu=""; _fg=""
  if [ -f "$_ff" ]; then
    _fp=$(sed -n 's/^path //p' "$_ff"); _fk=$(sed -n 's/^kept //p' "$_ff"); _fa=$(sed -n 's/^after //p' "$_ff")
    _fm=$(sed -n 's/^mode //p' "$_ff"); _ft=$(sed -n 's/^mtime //p' "$_ff"); _fc=$(sed -n 's/^context //p' "$_ff")
    _fu=$(sed -n 's/^uid //p' "$_ff"); _fg=$(sed -n 's/^gid //p' "$_ff")
  fi
  [ -n "$_fu" ] || { _fu=$(stat -c %u -- "$LSWS/conf"); _fg=$(stat -c %g -- "$LSWS/conf"); }
  _as="if command -v setpriv >/dev/null 2>&1; then AS=\"setpriv --reuid=$_fu --regid=$_fg --init-groups --no-new-privs --\"; else AS=\"runuser -u \$(getent passwd $_fu | cut -d: -f1) --\"; fi;"
  _b="$_as"
  if [ -n "$_fp" ]; then
    _b="$_b if [ -f $(sh_word "$_fk") ]; then"
    _b="$_b if [ -L $(sh_word "$_fp") ] || [ \"\$(\$AS sha256sum -- $(sh_word "$_fp") | cut -c1-64)\" != $_fa ]; then echo $(sh_word "$_fp is no longer the installer's edit (a link, or changed since); nothing was restored; compare: diff $_fk $_fp"); exit 1; fi;"
    # one line: the writer's script with its line ends made command separators (each line ends a command)
    # the writer's own status decides, never a pipeline's (whose status is its last command's): its
    # "temp inode" line goes to a file, and the kept copy is removed only after an exit 0 with an inode
    _b="$_b o=\$(mktemp) || exit 1; \$AS sh -c $(sh_word "$(printf '%s' "$OWNER_PUT" | tr '\n' ';')") sh $(sh_word "$_fp") $_fm $(sh_word "$_ft") < $(sh_word "$_fk") 3> \"\$o\" >/dev/null; r=\$?; i=\$(cut -d' ' -f2 \"\$o\"); rm -f \"\$o\";"
    _b="$_b if [ \"\$r\" != 0 ] || [ -z \"\$i\" ]; then echo $(sh_word "the restore did not complete (its writer ended") \"\$r)\"$(sh_word "; the bytes before the install are still at $_fk; compare: diff $_fk $_fp"); exit 1; fi;"
    [ "${_fc:--}" != - ] && [ "$_fc" != '?' ] && _b="$_b if command -v chcon >/dev/null 2>&1; then exec 6< $(sh_word "$_fp"); [ \"\$(stat -L -c '%i %h' /proc/self/fd/6)\" = \"\$i 1\" ] && chcon -- $(sh_word "$_fc") /proc/self/fd/6; exec 6<&-; fi;"
    # the server's copy of the file, when it is exactly the installer's edit (see ols_copy_back)
    _b="$_b c=$(sh_word "${_fp}0"); if [ -f \"\$c\" ] && [ ! -L \"\$c\" ] && [ \"\$(\$AS sha256sum -- \"\$c\" | cut -c1-64)\" = $_fa ]; then o=\$(mktemp) || exit 1; \$AS sh -c $(sh_word "$(printf '%s' "$OWNER_PUT" | tr '\n' ';')") sh \"\$c\" \$(stat -c %a -- \"\$c\") $(sh_word "$_ft") < $(sh_word "$_fk") 3> \"\$o\" >/dev/null; rm -f \"\$o\"; fi;"
    _b="$_b rm -f $(sh_word "$_fk") $(sh_word "$_ff"); fi;"
  fi
  _b="$_b if $(ours_check "$_f"); then \$AS rm -f -- $(sh_word "$_f"); fi;"
  # OpenLiteSpeed keeps a copy of each configuration file it loads (<file>0) and its RCS history (<file>0,v):
  # the two it made of the installer's own file carry nothing but the installer's lines, so they go with
  # it. Its copies of httpd_config.conf are the operator's history and are left alone; the restart below
  # rewrites httpd_config.conf0 to the bytes put back (measured on 1.9.3).
  _b="$_b for c in $(sh_word "${_f}0") $(sh_word "${_f}0,v"); do if [ -f \"\$c\" ] && [ ! -L \"\$c\" ]; then \$AS rm -f -- \"\$c\"; fi; done;"
  _b="$_b n=0; while [ \"\$(ps -eo args= | grep -c -e '^openlitespeed (lshttpd - main)\$' -e '^litespeed\$')\" -gt 1 ] && [ \$n -lt 120 ]; do sleep 1; n=\$((n + 1)); done;"
  _b="$_b if $(sh_word "$LSWS/bin/lswsctrl") status 2>/dev/null | grep -q 'is running'; then $(sh_word "$LSWS/bin/lswsctrl") restart >/dev/null 2>&1 7>&-; fi;"
  _b="$_b echo 'OpenLiteSpeed: the installer'\''s file is removed and httpd_config.conf is back, byte for byte'"
  undo_line "undo, OpenLiteSpeed" "$_b"
}
for s in $ARMS; do
  case "$s" in
    litespeed) ols_undo_line ;;
    nginx)
      _r=-; srv_running nginx && { if unit_active "$NGX_UNIT"; then _r="systemctl reload $NGX_UNIT"; else _r="nginx ${NGX_ARGS:+$NGX_ARGS }-s reload"; fi; }
      srv_undo_line nginx "nginx ${NGX_ARGS:+$NGX_ARGS }-t" "$_r" - \
        "${NGX_HTTP_INC:-/nonexistent}/whisper-edge.conf" "${NGX_MAIN_INC:-/nonexistent}/50-whisper-edge.conf" "$(memlock_dropin "$NGX_UNIT")" ;;
    apache)
      _r=-; srv_running apache && { if unit_active "$AP_UNIT"; then _r="systemctl reload $AP_UNIT"; else _r="$AP_CTL ${AP_ARGS:+$AP_ARGS }-k graceful"; fi; }
      _l=-; [ "$AP_LAYOUT" = debian ] && _l=/etc/apache2/conf-enabled/whisper-edge.conf
      srv_undo_line apache "$AP_CTL ${AP_ARGS:+$AP_ARGS }-t" "$_r" "$_l" "${AP_INC:-/nonexistent}/whisper-edge.conf" "$(memlock_dropin "$AP_UNIT")" ;;
  esac
done
shared=""; names=""
for f in "$UNITDIR/whisper-edge-refresh@.service" "$UNITDIR/whisper-edge-refresh@.timer"; do
  is_ours "$f" && { shared="$shared $(sh_word "$f")"; names="$names $(basename "$f")"; }
done
dropins=""; timers=""
for p in $PLANES; do
  _c=$(cadence_dropin "$p")
  if is_ours "$_c"; then dropins="$dropins $(sh_word "$_c")"; timers="$timers whisper-edge-refresh@$p.timer"; fi
done
if [ -n "$shared$dropins" ] || [ -f "$ETC/policy.conf" ]; then
  _g=""
  for sf in $SERVER_FILES; do
    _g="$_g if $(ours_check "${sf#*=}"); then echo \"${sf%%=*} still applies the policy ($(sh_word "${sf#*=}")): run its undo line first; nothing was removed\"; exit 1; fi;"
  done
  _keep=""
  for sf in $SERVER_FILES; do
    _keep="$_keep if [ -f $(sh_word "${sf#*=}") ] && ! { $(ours_check "${sf#*=}"); }; then keep=\"\$keep $(sh_word "${sf#*=}")\"; fi;"
  done
  _r="keep=\"\"; $_keep others=\$(ls $(sh_word "$UNITDIR") 2>/dev/null | grep '^whisper-edge-refresh@.*\\.timer\$' | grep -v -x -e 'whisper-edge-refresh@.timer'$(for p in $PLANES; do printf " -e 'whisper-edge-refresh@%s.timer'" "$p"; done) || true);"
  _body="$_g $_r if [ -n \"\$keep\" ]; then echo \"kept the refresh units: \$keep still reads the planes (your edit of a file the installer wrote); remove it first to remove them\"; exit 0; fi;"
  [ -n "$timers" ] && _body="$_body systemctl stop$timers 2>/dev/null; systemctl disable$timers >/dev/null 2>&1; rm -f$dropins; rmdir$(for p in $PLANES; do printf ' %s' "$(sh_word "$UNITDIR/whisper-edge-refresh@$p.timer.d")"; done) 2>/dev/null;"
  _body="$_body if [ -n \"\$others\" ]; then echo \"kept the refresh templates: \$(echo \$others) still use them\"; else rm -f$shared; fi;"
  _body="$_body if [ -f $(sh_word "$ETC/policy.conf") ]; then if [ \"\$(sha256sum < $(sh_word "$ETC/policy.conf") | cut -c1-64)\" = $(policy_text | sha256_of) ]; then rm -f $(sh_word "$ETC/policy.conf"); else echo \"kept $(sh_word "$ETC/policy.conf"): it has your edits\"; fi; fi;"
  [ -f "$ETC/legacy-timer.disabled" ] && _body="$_body if [ -f $(sh_word "$ETC/legacy-timer.disabled") ]; then systemctl enable --now whisper-edge-refresh.timer >/dev/null 2>&1; rm -f $(sh_word "$ETC/legacy-timer.disabled"); fi;"
  # the SELinux file context this installer added (and only that one), then the directory relabelled
  if [ -f "$ETC/selinux-fcontext.added" ]; then
    _body="$_body if [ -f $(sh_word "$ETC/selinux-fcontext.added") ]; then while IFS= read -r s; do [ -n \"\$s\" ] && semanage fcontext -d \"\$s\" >/dev/null 2>&1; done < $(sh_word "$ETC/selinux-fcontext.added"); rm -f $(sh_word "$ETC/selinux-fcontext.added"); sh -c $(sh_word "$SE_RELABEL") sh $(sh_word "$DIR"); fi;"
  fi

  _body="$_body [ -d /run/systemd/system ] && systemctl daemon-reload; echo 'the shared parts are removed: the per-plane refresh units and the policy file, where the installer wrote them'"
  undo_line "$(would "undo, the shared parts (after every server line)" "undo, the shared parts (after every server line)")" "$_body"
else
  rep undo "no shared parts were written (no refresh units here, no policy file), so there is no shared line"
fi
[ -n "$ZDIR" ] && rep undo "the resolver half has no undo line: nothing was written in named's configuration, and the zone files live under named's own directory"
rep undo "to print these lines again: sudo $HERE/install.sh --dry-run (this run's whole report is also kept at $UNDO/last-report)"
rep undo "by hand, if you want the data gone too: systemctl disable --now whisper-edge-refresh-keyed.timer; chattr -i $(sh_word "$DIR")/*.bin; rm -rf $(sh_word "$DIR") $(sh_word "$REFRESH_AT")"

# ---- the line to watch -----------------------------------------------------------------------------------
#
# Recorded values only: what each timer was set to, and each plane's state as this run measured it, with
# the arguments of the refresh cycle each plane runs on (T the timer period, D the cadence the signed
# manifest states, A the publication lag, F the refresh's own fetch budget). A value this run did not
# measure is said to be unmeasured, never filled in.
_m="watch:"
for p in $PLANES; do
  set -- $(cadence_of "$p"); _T=$4
  case " ${NOSCHED:-} " in *" $p "*) _T=none ;; esac
  _D=-; if [ "$MANIFEST_OK" = 1 ]; then set -- $(manifest_entry "$MANIFEST" "$p" 2>/dev/null || echo ABSENT); [ "${1:-}" = PLANE ] && _D=${4:--}; fi
  _f="$DIR/$p.bin"
  case " $ARMED " in
    *" $p "*)
      if [ "$DRY" = 1 ] || [ ! -f "$_f" ]; then _s="published, not fetched by a dry run"
      else _s="generation $(le_u64 "$_f" 16), digest $(sha256_of < "$_f" | cut -c1-16), valid until $(utc_ms "$(le_u64 "$_f" 32)")"; fi ;;
    *) case " $INERT " in *" $p "*) _s="inert" ;; *) _s="not fetched" ;; esac ;;
  esac
  _m="$_m $p $_s, --cycle $p=$_T,$_D,unmeasured,1300;"
done
printf '%s the cycle is T the timer period in s, D the signed cadenceSeconds, A the publication lag (not measured by this run), F the refresh fetch budget in s\n' "$_m" > "$RT/monitor"

# A dry run that could not fetch or verify what it was asked to preview says so above, and fails: a
# preview that could not see the feed is not a preview of a run that would succeed.
ENDED=1   # every exit below is one this script chose, with the arm's own line above it
if [ "$DRY" = 1 ] && [ "$DRY_FAIL" = 1 ]; then exit 1; fi
# 1: an arm was not applied (refused, stopped, or its configuration failed its own test first; each arm's
# line says which, and its previous configuration is unchanged); 3: applied and serving, but not confirmed
[ "${OLS_DOWN:-0}" = 1 ] && exit 5
[ -n "${ARM_FAILED:-}" ] && exit 1
[ -n "${ARM_UNCONFIRMED:-}" ] && exit 3
exit 0
