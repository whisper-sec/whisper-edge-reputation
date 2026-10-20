#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Prove `whisper-edge-refresh --zone ORIGIN` against a REAL BIND: each policy zone is fetched by name on
# the timer's own command, its signature fetched from the node the body came from and verified, its
# header and records checked, the file installed atomically, reloaded in named only when it changed,
# confirmed by what named says it loaded, and replaced by the fleet's empty zone once its validUntil
# has passed.
#
# Two named instances, because RPZ applies during recursion and never to a server's own authoritative
# answers: one is authoritative for example.test, the other is the resolver under test, carrying the
# policy zones and forwarding to the first. That is also the shape of a real deployment.
#
# The feed is a stub on the loopback serving zones this script writes and signs with a key it makes
# for the run, the way the feed serves them: /edge/rpz/<origin>.zone with a strong ETag and no
# Last-Modified, /edge/zones/<sha256>.zone.sig beside it. So it can advance the serial, serve one
# serial twice, go backwards, serve garbage or a body past the size cap, hang half way through, sign
# the wrong bytes, answer from a second node without the signature, or vanish.
#
# Every check has a control that must FAIL it, run in the same harness: most are a copy of the refresh
# with the one line that carries the property changed back (each patch is asserted to have applied, so
# a control can never pass by patching nothing). A check that cannot see the failure it exists for is a
# check that always passes, and this gate exists because the last one did.
#
# Exit 0 all passed, 1 something failed, 77 could not run here (named, rndc, dig, openssl, curl or
# python3 missing, or no directory named may read from). Called by install-gate.sh; runnable on its own.
#
# Every check reads `condition && pass ... || fail ...`. That is an if/else only because pass cannot
# fail (it prints and counts), which is the one thing shellcheck's SC2015 asks to be sure of.
# The controls carry lines of the refresh verbatim, $ and all, so they are single-quoted on purpose.
# shellcheck disable=SC2015,SC2016
set -u
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }

HERE="$(cd "$(dirname "$0")" && pwd)"
REFRESH="$HERE/whisper-edge-refresh"
ok=0; bad=0
pass() { printf '  ok    %s\n' "$1"; ok=$((ok+1)); }
fail() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; bad=$((bad+1)); }
note() { printf '  NOTE  %s\n' "$1"; }
# says TEXT PATTERN: grep -q over captured output, fed by a here-document rather than a pipe. A
# writer piped into grep -q can take SIGPIPE when grep stops at its first match, and under pipefail
# that turns a match into a miss.
says() {
  grep -q -- "$2" <<EOF
$1
EOF
}
skip() { printf '  SKIP  the real-BIND zone cases: %s\n' "$1"; exit 77; }

for t in named named-checkzone named-compilezone named-checkconf rndc dig python3 setsid openssl curl sha256sum; do
  command -v "$t" >/dev/null 2>&1 || skip "$t is not installed"
done

echo "=== the zone refresh against a real BIND ($(named -v | awk '{print $2}'), $(curl --version | head -1 | awk '{print $1, $2}'))"

# ---- a work directory named may read: under /var/cache/bind, for AppArmor's sake ------------------
G="/var/cache/bind/whisper-edge-gate.$$"
if [ -w /var/cache/bind ]; then mkdir -p "$G" || skip "cannot create $G"
else sudo -n mkdir -p "$G" 2>/dev/null && sudo -n chown "$(id -u):$(id -g)" "$G" 2>/dev/null \
  || skip "cannot create $G (no write access to /var/cache/bind and no passwordless sudo)"; fi
W="$(mktemp -d -t whisper-edge-rpz-gate.XXXXXX)"
# shellcheck disable=SC2317  # reached only through the EXIT trap below, which shellcheck cannot follow
cleanup() {
  for p in "$G/auth.pid" "$G/rec.pid"; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
  for p in "$W"/*.srvpid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
  sleep 1
  rm -rf "$W"
  rm -rf "${G:?}"/* "${G:?}"/.[!.]* 2>/dev/null
  # The unit case leaves root-owned files behind, as the timer would; those need root to remove.
  rmdir "$G" 2>/dev/null || sudo -n rm -rf "${G:?}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT     # Ctrl-C ends the gate: cleanup runs once, on EXIT, and no case runs after it
trap 'exit 143' TERM

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
AP=$(free_port); RP=$(free_port); CP=$(free_port); SP=$(free_port); KP=$(free_port)

O=rpz.whisper.online
OK=rpz-rpki-unreachable.whisper.online
ZD="$G/whisper-edge"; ZF="$ZD/rpz.zone"; ZK="$ZD/$OK.zone"; PROM="$ZF.prom"
KDIR="$W/dir"   # the refresh's --dir: where edge.pub lives
mkdir -p "$ZD" "$KDIR" "$W/A/edge/rpz" "$W/A/edge/zones" "$W/B/edge/rpz" "$W/B/edge/zones"

# The run's own signing key, never written anywhere but this run's temp directory.
openssl genpkey -algorithm ed25519 -out "$W/sign.pem" 2>/dev/null \
  && openssl pkey -in "$W/sign.pem" -pubout -out "$KDIR/edge.pub" 2>/dev/null \
  || skip "this openssl cannot make an Ed25519 key"
# The installer pins the feed's key, and a base other than the default needs its sha256 given, or the
# dry run below is a usage refusal with no unit in it: the stub feed's key is this run's own.
KSHA=$(sha256sum < "$KDIR/edge.pub" | cut -c1-64)

SECRET=$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')
BADSECRET=$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')
cat > "$G/rndc.conf" <<EOF
key "gate" { algorithm hmac-sha256; secret "$SECRET"; };
options { default-key "gate"; default-server 127.0.0.1; default-port $CP; };
EOF
cat > "$G/bad-rndc.conf" <<EOF
key "gate" { algorithm hmac-sha256; secret "$BADSECRET"; };
options { default-key "gate"; default-server 127.0.0.1; default-port $CP; };
EOF

cat > "$G/example.test.zone" <<'EOF'
$TTL 300
@        IN SOA  ns.example.test. hostmaster.example.test. ( 1 3600 600 86400 300 )
@        IN NS   ns.example.test.
ns       IN A    127.0.0.1
blocked  IN A    192.0.2.5
blocked  IN AAAA 2001:db8::5
clean    IN A    203.0.113.9
EOF
cat > "$G/named-auth.conf" <<EOF
options {
    directory "$G"; pid-file "$G/auth.pid";
    listen-on port $AP { 127.0.0.1; }; listen-on-v6 { none; };
    recursion no; allow-query { 127.0.0.1; }; dnssec-validation no;
    managed-keys-directory "$G"; session-keyfile "$G/auth.session.key";
};
zone "example.test" { type master; file "$G/example.test.zone"; };
EOF
# The resolver under test, carrying both zones in the order install.sh prints. Its directory is $G, so
# the installer's rule (the zones live under <named's directory>/whisper-edge/) gives exactly $ZD.
# min-update-interval 0 so a reloaded policy is applied at once; BIND's default defers it up to 60 s,
# which the README states. The RPKI zone's file is absent until a case installs it: named logs that it
# did not load and resolves without it, and the reputation zone still applies (measured, BIND 9.18).
cat > "$G/named-rec.conf" <<EOF
key "gate" { algorithm hmac-sha256; secret "$SECRET"; };
controls { inet 127.0.0.1 port $CP allow { 127.0.0.1; } keys { "gate"; }; };
options {
    directory "$G"; pid-file "$G/rec.pid";
    listen-on port $RP { 127.0.0.1; }; listen-on-v6 { none; };
    recursion yes; allow-query { 127.0.0.1; }; allow-recursion { 127.0.0.1; };
    dnssec-validation no; qname-minimization off;
    forward only; forwarders { 127.0.0.1 port $AP; };
    managed-keys-directory "$G"; session-keyfile "$G/rec.session.key";
    response-policy {
        zone "$O";
        zone "$OK" policy disabled log yes;
    } qname-wait-recurse no min-update-interval 0;
};
zone "$O" { type master; file "whisper-edge/rpz.zone"; };
zone "$OK" { type master; file "whisper-edge/$OK.zone"; };
EOF
named-checkconf "$G/named-rec.conf" || { fail "the gate's own resolver config is valid" "named-checkconf refused it"; exit 1; }

# rndc, wrapped: every call is logged, so "no reload happened" is a count and not an absence of
# evidence, and GATE_FAKE_UPTODATE makes `reload` answer the way BIND does when it keeps the old zone.
cat > "$W/rndc" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$W/rndc.calls"
if [ -n "\${GATE_FAKE_UPTODATE:-}" ] && [ "\$1" = reload ]; then echo "zone reload up-to-date"; exit 0; fi
exec rndc -c "\${GATE_RNDC_CONF:-$G/rndc.conf}" "\$@"
EOF
chmod 0755 "$W/rndc"
reloads() { grep -c '^reload' "$W/rndc.calls" 2>/dev/null || true; }

# ---- the stub feed ------------------------------------------------------------------------------
# One node per root and address. A answers on 127.0.0.1 and B on ::1, on the same port, so a name
# that reaches both (localhost) is two nodes and an address literal is one. Every request is logged
# with the validators it carried and the bytes it was sent.
cat > "$W/stub.py" <<'PY'
import hashlib, http.server, os, socket, sys
ADDR, PORT, ROOT, LOG = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def note(self, status, n):
        with open(LOG, "a") as f:
            f.write("%s %s inm=%s ims=%s status=%d bytes=%d ua=%s\n" % (self.command, self.path,
                    self.headers.get("If-None-Match", "-"), self.headers.get("If-Modified-Since", "-"), status, n,
                    self.headers.get("User-Agent", "-")))
    def send(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers: self.send_header(k, v)
        if status != 304: self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 304: self.wfile.write(body)
        self.note(status, 0 if status == 304 else len(body))
    def do_GET(self):
        p = self.path.split("?", 1)[0]
        rel = p[len("/edge/"):] if p.startswith("/edge/") else None
        if rel is None or ".." in rel.split("/"):
            return self.send(404, b"no\n", [("Cache-Control", "no-store")])
        chunked = os.path.join(ROOT, "chunked")
        if rel.startswith("rpz/") and os.path.exists(chunked):
            n = int(open(chunked).read().strip()); sent = 0
            self.send_response(200); self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            line = b"; padding padding padding padding padding padding padding padding padding\n"
            try:
                while sent < n:
                    piece = line[: min(len(line), n - sent)]
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece)); sent += len(piece)
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return self.note(200, sent)
        f = os.path.join(ROOT, "edge", rel)
        if not os.path.isfile(f):
            return self.send(404, b"not published\n", [("Cache-Control", "no-store")])
        body = open(f, "rb").read()
        if rel.startswith("rpz/"):
            sha = hashlib.sha256(body).hexdigest()
            etag = '"%s"' % sha
            ov = os.path.join(ROOT, "etag")
            if os.path.exists(ov): etag = open(ov, "rb").read().decode("latin-1")
            if self.headers.get("If-None-Match") == '"%s"' % sha:
                return self.send(304, headers=[("ETag", etag), ("Cache-Control", "no-cache")])
            return self.send(200, body, [("ETag", etag), ("Cache-Control", "no-cache")])
        return self.send(200, body, [("Cache-Control", "max-age=31536000, immutable")])
class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if ":" in ADDR else socket.AF_INET
    allow_reuse_address = True
S((ADDR, PORT), H).serve_forever()
PY
python3 "$W/stub.py" 127.0.0.1 "$SP" "$W/A" "$W/A.log" >"$W/stubA.err" 2>&1 & echo $! > "$W/stubA.srvpid"
V6=1
python3 "$W/stub.py" ::1 "$SP" "$W/B" "$W/B.log" >"$W/stubB.err" 2>&1 & echo $! > "$W/stubB.srvpid"
STUB="http://127.0.0.1:$SP/edge"
DEAD="http://127.0.0.1:$(free_port)/edge"
i=0; while [ "$i" -lt 50 ]; do curl -s -o /dev/null "$STUB/rpz/x.zone" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
# ::1 is polled like 127.0.0.1, so a slow stub start on a loaded box is never read as a host without it.
i=0; while [ "$i" -lt 50 ]; do curl -s -g -o /dev/null "http://[::1]:$SP/edge/rpz/x.zone" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
[ "$i" -lt 50 ] || V6=0
SKIPS=""
requests() { grep -c "GET /edge/rpz/" "$W/A.log" 2>/dev/null || true; }

# ---- the zones ------------------------------------------------------------------------------------
# Serials are this hour's slot plus a few seconds, as the nameservers publish them, so content is valid
# for a day from the slot start (EXPIRE 86400). The header is the published format, line for line.
NOW=$(date +%s); SL=$((NOW / 3600 * 3600)); DAY=86400
iso() { date -u -d "@$1" '+%Y-%m-%dT%H:%M:%SZ'; }
# wz ORIGIN SERIAL content|empty [EXPIRE] [TRIGGER...]: a zone file on stdout. A trigger is an rpz-ip
# owner prefix (24.0.2.0.192 for 192.0.2.0/24), given NODATA (CNAME *.).
wz() {
  _o=$1 _s=$2 _st=$3; shift 3
  if [ "$_st" = empty ]; then _e=$DAY; else _e=${1:-$DAY}; [ "$#" -gt 0 ] && shift; fi
  printf '; v=wedge-rpz1\n; origin=%s\n; state=%s\n; generation=%s\n' "$_o" "$_st" "$_s"
  if [ "$_st" = content ]; then
    printf '; validUntil=%s\n; triggers=%s\n; sources=documentation fixture\n' "$(iso $(( _s / 3600 * 3600 + _e )))" "$#"
  fi
  # shellcheck disable=SC2016  # $TTL is the zone-file directive, written literally
  printf '$TTL 300\n%s.\tIN\tSOA\tns1.whisper.online. hostmaster.whisper.online. ( %s 900 300 %s 300 )\n' "$_o" "$_s" "$_e"
  printf '%s.\tIN\tNS\tns1.whisper.online.\n%s.\tIN\tNS\tns2.whisper.online.\n' "$_o" "$_o"
  for _t in "$@"; do printf '%s.rpz-ip.%s.\t300\tIN\tCNAME\t*.\n' "$_t" "$_o"; done
}
# sign FILE [prefix|raw]: the signature the feed publishes, Ed25519 over whisper-edge-zone-v1, NUL, bytes.
sign() {
  if [ "${2:-prefix}" = raw ]; then cp "$1" "$W/msg"; else { printf 'whisper-edge-zone-v1\000'; cat "$1"; } > "$W/msg"; fi
  openssl pkeyutl -sign -inkey "$W/sign.pem" -rawin -in "$W/msg" -out "$1.sig.tmp" && cat "$1.sig.tmp" && rm -f "$1.sig.tmp"
}
# pub ROOT FILE ORIGIN: publish a zone on one node, by name and by hash, with its signature.
pub() {
  _sha=$(sha256sum < "$2" | cut -d' ' -f1)
  cp "$2" "$1/edge/zones/$_sha.zone"
  sign "$2" > "$1/edge/zones/$_sha.zone.sig"
  cp "$2" "$1/edge/rpz/$3.zone"
}
# feed SERIAL [TRIGGER...]: the reputation zone, content, published on node A.
feed() { _s=$1; shift; wz "$O" "$_s" content "$DAY" "$@" > "$W/z"; pub "$W/A" "$W/z" "$O"; }

# The refresh as a test drives it: the gate's named.conf, its rndc, its key, a short confirmation wait.
rz() { WHISPER_EDGE_RNDC="$W/rndc" WHISPER_EDGE_RELOAD_WAIT=8 "${GATE_REFRESH:-$REFRESH}" --dir "$KDIR" --named-conf "$G/named-rec.conf" "$@"; }
run() { out=$(rz --rpz "$@" 2>&1) && rc=0 || rc=$?; }
loaded()  { rndc -c "$G/rndc.conf" zonestatus "$O" 2>/dev/null | sed -n 's/^serial: //p'; }
# the serial named serves for a zone. An EMPTY answer is a query that did not complete (one try of two
# seconds, on a loaded host, just after a reload), not a serial, so it is asked again, three times at
# most; any serial that does come back is returned at once, so a wrong one is never retried away
served()  {
  _sv=""; _sn=0
  while [ -z "$_sv" ] && [ "$_sn" -lt 3 ]; do
    _sv=$(dig +short +norecurse +time=2 +tries=1 -p "$RP" @127.0.0.1 "${1:-$O}" SOA | awk '{print $3}')
    _sn=$((_sn + 1))
  done
  printf '%s\n' "$_sv"
}
# The answer the resolver gives for blocked.example.test: NODATA, NXDOMAIN, or the address.
answer() {
  _o=$(dig +time=2 +tries=1 -p "$RP" @127.0.0.1 blocked.example.test "$1")
  _st=$(printf '%s\n' "$_o" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  _a=$(printf '%s\n' "$_o" | awk '/^;; ANSWER SECTION/ { f = 1; next } /^$/ { f = 0 } f { print $NF }' | head -1)
  if [ "$_st" = NOERROR ] && [ -z "$_a" ]; then echo NODATA; elif [ "$_st" = NOERROR ]; then echo "$_a"; else echo "$_st"; fi
}
# A series of the state file, label or none: whisper_edge_rpz_<key>{zone="<origin>"} <value>.
st()      { sed -n "s/^whisper_edge_rpz_$1\({[^}]*}\)\{0,1\} //p" "${2:-$PROM}" 2>/dev/null | tail -1; }
set_st()  { if grep -q "^whisper_edge_rpz_$1[{ ]" "${3:-$PROM}" 2>/dev/null; then
              sed -i "s/^\(whisper_edge_rpz_$1\({[^}]*}\)\{0,1\}\) .*/\1 $2/" "${3:-$PROM}"
            else printf 'whisper_edge_rpz_%s %s\n' "$1" "$2" >> "${3:-$PROM}"; fi; }
sha() { sha256sum < "$1" | cut -d' ' -f1; }
wait_answer() { _i=0; while [ "$_i" -lt 20 ] && [ "$(answer "$1")" != "$2" ]; do _i=$((_i+1)); sleep 0.25; done; }

# A control: the refresh with one line put back the way the defect had it. $1 names it, then pairs of
# (exact text, replacement). Each pair must match exactly once, or the gate fails: a control whose
# patch matched nothing is the unpatched script and proves nothing.
CTL_OK=1
control() {
  _name=$1; shift
  CTL="$W/ctl-$_name"
  cp "$REFRESH" "$CTL"
  while [ "$#" -ge 2 ]; do
    _n=$(python3 - "$CTL" "$1" "$2" <<'PY'
import sys
p, a, b = sys.argv[1:4]
s = open(p).read()
n = s.count(a)
if n == 1:
    open(p, "w").write(s.replace(a, b))
print(n)
PY
)
    [ "$_n" = 1 ] || { fail "the control '$_name' patches exactly one place" "the text matched $_n times: $1"; CTL_OK=0; }
    shift 2
  done
  chmod 0755 "$CTL"
}

S0=$((SL + 10))

# ---- 1. named is down: the zone installs, the reload cannot be confirmed, and that is counted -----
feed "$S0" 24.0.2.0.192
run --base "$STUB"
{ [ "$rc" = 3 ] && [ "$(st reload_failures_total)" = 1 ] && named-checkzone -q "$O" "$ZF" \
  && says "$out" "did NOT load serial $S0" && says "$out" "signature verified"; } \
  && pass "with named down: serial $S0 is verified, installed and checked; the unconfirmed reload exits 3 and is counted" \
  || fail "named down is a counted alarm" "rc=$rc failures=$(st reload_failures_total) $out"

named -c "$G/named-auth.conf" -f >"$W/auth.log" 2>&1 &
named -c "$G/named-rec.conf"  -f >"$W/rec.log"  2>&1 &
i=0; while [ "$i" -lt 60 ]; do [ "$(served)" = "$S0" ] && break; i=$((i+1)); sleep 0.25; done
[ "$(served)" = "$S0" ] || { fail "the gate's named came up" "$(tail -5 "$W/rec.log")"; exit 1; }

# ---- 2. the policy: NODATA on the listed family, an answer on the other ---------------------------
{ [ "$(answer A)" = NODATA ] && [ "$(answer AAAA)" = 2001:db8::5 ]; } \
  && pass "loaded: blocked.example.test is NODATA on A (192.0.2.5 is listed) and answers 2001:db8::5 on AAAA" \
  || fail "the trigger gives NODATA on its family only" "A=$(answer A) AAAA=$(answer AAAA)"
[ "$(served "$OK")" = "" ] \
  && pass "and with the RPKI zone's file still absent, named serves no such zone and the reputation zone applies" \
  || fail "an absent zone file leaves the other zone in force" "served $OK=$(served "$OK")"

# ---- 3. nothing changed: a 304 to If-None-Match, 0 bytes, no reload ------------------------------
: > "$W/rndc.calls"; : > "$W/A.log"
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(reloads)" = 0 ] && says "$out" "not modified" \
  && grep -q "status=304 bytes=0" "$W/A.log" && grep -q "inm=\"$(sha "$ZF")\"" "$W/A.log"; } \
  && pass "an unchanged feed: If-None-Match is the installed file's own sha256, the answer a 304 with 0 bytes, no reload" \
  || fail "an unchanged feed costs a 304 and nothing else" "rc=$rc reloads=$(reloads) log=$(cat "$W/A.log") $out"
# The control: a client sending only If-Modified-Since on a by-name path, which carries no Last-Modified
# to compare with, so the feed answers 200 with the whole body every time.
control ims 'set -- "$@" -H "If-None-Match: \"$_inm\""' 'set -- "$@" -H "If-Modified-Since: $(date -u -R)"'; C=$CTL
: > "$W/A.log"
GATE_REFRESH=$C run --base "$STUB"
grep -q "status=200 bytes=[1-9]" "$W/A.log" \
  && pass "the control: If-Modified-Since alone on the by-name path gets the full body again (200, $(sed -n 's/.*status=200 bytes=\([0-9]*\).*/\1/p' "$W/A.log" | head -1) bytes)" \
  || fail "the control: If-Modified-Since alone must not get a 304" "$(cat "$W/A.log")"

# ---- 4. a changed fetch: reloaded once, named confirms; the trigger removed resolves ------------------
feed $((S0 + 1))
: > "$W/rndc.calls"
run --base "$STUB"
wait_answer A 192.0.2.5
{ [ "$rc" = 0 ] && [ "$(reloads)" = 1 ] && [ "$(loaded)" = $((S0 + 1)) ] && [ "$(served)" = $((S0 + 1)) ] \
  && says "$out" "reloaded zone $O, serial $((S0 + 1)) (named confirms)" && [ "$(answer A)" = 192.0.2.5 ]; } \
  && { pass "a changed fetch reloads that one zone once; at serial $((S0 + 1)) the trigger is gone and blocked.example.test resolves"
       # The transcript, verbatim: it is what the README quotes, so the README quotes a run, not a memory.
       printf '%s\n' "$out" | sed 's/^/        | /'; } \
  || fail "a changed fetch is reloaded" "rc=$rc reloads=$(reloads) loaded=$(loaded) served=$(served) A=$(answer A) $out"
feed $((S0 + 2)) 24.0.2.0.192
run --base "$STUB"
wait_answer A NODATA
[ "$(answer A)" = NODATA ] && pass "and the trigger back at serial $((S0 + 2)): NODATA again" \
  || fail "the trigger re-arms" "A=$(answer A) $out"

# ---- 5. the timer's own command ---------------------------------------------------------------------
# install.sh renders the unit template; its dry run prints the ExecStart it would write. That exact
# command, with %i as systemd fills it in for the reputation instance, runs here.
dry=$(WHISPER_EDGE_SBIN="$HERE" "$HERE/install.sh" --dry-run --dir "$KDIR" --base "$STUB" --key-sha256 "$KSHA" --named-conf "$G/named-rec.conf" 2>&1)
TEXEC=$(printf '%s\n' "$dry" | sed -n 's/.*whisper-edge-rpz@\.service: ExecStart=//p')
EXEC=$(printf '%s' "$TEXEC" | sed "s/%i/$O/")
case "$TEXEC" in
  *"--zone-file $ZD/ "*"--zone %i") pass "the rendered template names named's own zone directory and takes the zone from the instance" ;;
  *) if command -v systemctl >/dev/null 2>&1; then _why=""
     else _why="this host has no systemctl, so install.sh renders no zone unit and prints the schedule instead (install the systemd package; PID 1 need not be systemd); "; fi
     fail "the rendered template names named's directory and %i" "${_why}ExecStart='$TEXEC'; the dry run said: $(printf '%s\n' "$dry" | tail -n 2 | tr '\n' ' ')" ;;
esac
# the same dry run with no key named for the stub feed: a usage refusal that names --key-sha256, exit 2,
# and no unit line at all, never an empty ExecStart (the template row above read '' from exactly this)
dryk=$(WHISPER_EDGE_SBIN="$HERE" "$HERE/install.sh" --dry-run --dir "$KDIR" --base "$STUB" --named-conf "$G/named-rec.conf" 2>&1) && dkrc=0 || dkrc=$?
{ [ "$dkrc" = 2 ] && printf '%s\n' "$dryk" | grep_any 'is not the default feed, so its signing key cannot be the pinned one: give --key-sha256' \
  && ! printf '%s\n' "$dryk" | grep_any 'ExecStart='; } \
  && pass "the control: the dry run with no --key-sha256 for the stub feed is refused by name (exit 2) and renders no unit, so an empty ExecStart is a refusal read, never a unit" \
  || fail "the dry run's refusal without --key-sha256" "rc=$dkrc $(printf '%s\n' "$dryk" | grep -E 'install.sh:|ExecStart' | head -2 | cut -c1-200)"
feed $((S0 + 3)) 24.0.2.0.192
before=$(requests)
# shellcheck disable=SC2086  # the unit's command line, word-split exactly as systemd splits it
o=$(WHISPER_EDGE_RNDC="$W/rndc" $EXEC 2>&1); r=$?
{ [ "$r" = 0 ] && [ "$(requests)" = "$before" ] && [ "$(served)" = $((S0 + 2)) ]; } \
  && pass "the timer's command inside the zone's REFRESH asks the feed for nothing" \
  || fail "--if-due respects REFRESH" "rc=$r requests $before -> $(requests); served $(served); $o"
set_st last_ok_seconds $(( $(date +%s) - 901 ))
# The control first: a reload that answers "up-to-date" and loads nothing (a stubbed reload).
# shellcheck disable=SC2086
o=$(GATE_FAKE_UPTODATE=1 WHISPER_EDGE_RNDC="$W/rndc" $EXEC 2>&1); r=$?
{ [ "$r" = 3 ] && [ "$(served)" = $((S0 + 2)) ]; } \
  && pass "the control: with the reload stubbed, one timer run leaves named at $((S0 + 2)) and exits 3" \
  || fail "the control: a stubbed reload must not look like a new serial" "rc=$r served=$(served) $o"
# shellcheck disable=SC2086
o=$(WHISPER_EDGE_RNDC="$W/rndc" $EXEC 2>&1); r=$?
{ [ "$r" = 0 ] && [ "$(served)" = $((S0 + 3)) ] && [ "$(loaded)" = $((S0 + 3)) ] \
  && says "$o" "reloaded zone $O, serial $((S0 + 3)) (named confirms)"; } \
  && pass "one timer run once REFRESH has passed: named serves the new serial $((S0 + 3)), and --quiet still logs the reload" \
  || fail "the timer's command fetches the zone" "rc=$r served=$(served) $o"

# ---- 6. rndc's exit code proves nothing --------------------------------------------------------------
feed $((S0 + 4)) 24.0.2.0.192
GATE_FAKE_UPTODATE=1 run --base "$STUB"
{ [ "$rc" = 3 ] && [ "$(loaded)" = $((S0 + 3)) ] && says "$out" "did NOT load serial $((S0 + 4))"; } \
  && pass "a reload that says 'up-to-date' with exit 0 is NOT taken as success (named still at $((S0 + 3)))" \
  || fail "an exit-0 reload that loaded nothing is detected" "rc=$rc loaded=$(loaded) $out"
touch -d '2020-01-01' "$ZF"
: > "$W/rndc.calls"
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(loaded)" = $((S0 + 4)) ] && [ "$(reloads)" = 2 ]; } \
  && pass "BIND's own 'up-to-date' on a stale mtime is healed on the next run: two reloads, named at $((S0 + 4))" \
  || fail "a stale-mtime reload is retried" "rc=$rc loaded=$(loaded) reloads=$(reloads) $out"

# ---- 6b. the feed is down: counted, the zone untouched -----------------------------------------------
sum=$(sha "$ZF"); ff=$(st fetch_failures_total)
run --base "$DEAD"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && [ "$(st fetch_failures_total)" = $(( ${ff:-0} + 1 )) ] \
  && says "$out" "could not fetch $DEAD/rpz/$O.zone"; } \
  && pass "the feed down: exit 1, the failed fetch counted, the installed zone untouched and still loaded" \
  || fail "a dead feed is a counted failure" "rc=$rc failures=$(st fetch_failures_total) $out"

# ---- 7. a refused rndc ----------------------------------------------------------------------------------
feed $((S0 + 5)) 24.0.2.0.192
fails=$(st reload_failures_total)
GATE_RNDC_CONF="$G/bad-rndc.conf" run --base "$STUB"
{ [ "$rc" = 3 ] && [ "$(st reload_failures_total)" = $((fails + 1)) ] && [ "$(loaded)" = $((S0 + 4)) ] \
  && named-checkzone -q "$O" "$ZF"; } \
  && pass "rndc refused (wrong key): exit 3, counted, the file is complete and checked, named keeps $((S0 + 4))" \
  || fail "a refused rndc is a counted alarm" "rc=$rc failures $fails -> $(st reload_failures_total) loaded=$(loaded) $out"
run --base "$STUB"
[ "$(loaded)" = $((S0 + 5)) ] && pass "and the next run, with rndc working, brings named to $((S0 + 5)) without a new fetch" \
  || fail "a failed reload is retried" "loaded=$(loaded) $out"

# ---- 8. the serial discipline -------------------------------------------------------------------------
sum=$(sha "$ZF")
wz "$O" $((S0 + 5)) content "$DAY" 24.0.2.0.192 24.0.100.51.198 > "$W/z"; pub "$W/A" "$W/z" "$O"
: > "$W/rndc.calls"
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(sha "$ZF")" = "$sum" ] && [ "$(reloads)" = 0 ] && says "$out" "a body other than the installed"; } \
  && pass "the same serial with another body is refused and said: no install, no reload, the installed zone kept" \
  || fail "one serial is installed once" "rc=$rc reloads=$(reloads) $out"
feed $((S0 + 5)) 24.0.2.0.192
cur=$(st current_total)
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(st current_total)" = $(( ${cur:-0} + 1 )) ]; } \
  && pass "the same serial with the same bytes: a 304 to the file's own sha256, counted current" \
  || fail "one serial, one body, is current" "rc=$rc current=$(st current_total) $out"
feed $((S0 + 1)) 24.0.2.0.192
stale=$(st stale_feed_total)
: > "$W/rndc.calls"
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(sha "$ZF")" = "$sum" ] && [ "$(reloads)" = 0 ] \
  && [ "$(st stale_feed_total)" = $(( ${stale:-0} + 1 )) ]; } \
  && pass "an older serial ($((S0 + 1)) after $((S0 + 5)), a node a publication behind) is kept out, counted as stale, and the run succeeds" \
  || fail "an older serial is a counted no-op" "rc=$rc stale=$(st stale_feed_total) reloads=$(reloads) $out"
printf 'this is not a zone file\n' > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && [ "$(loaded)" = $((S0 + 5)) ] && says "$out" "no wedge-rpz1 header"; } \
  && pass "a signed file with no header never reaches the zone file" \
  || fail "a headerless file is refused" "rc=$rc $out"

# ---- 9. the signature: from the body's node, over the prefixed bytes ------------------------------------
# A correct pair first, the control for every refusal below: it installs.
feed $((S0 + 6)) 24.0.2.0.192
run --base "$STUB"
{ [ "$rc" = 0 ] && [ "$(served)" = $((S0 + 6)) ]; } \
  && pass "the control: a correct body and signature install (serial $((S0 + 6)))" \
  || fail "a correct pair installs" "rc=$rc served=$(served) $out"
sum=$(sha "$ZF")
feed $((S0 + 7)) 24.0.2.0.192
rm -f "$W/A/edge/zones/$(sha "$W/A/edge/rpz/$O.zone").zone.sig"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "signature is HTTP 404"; } \
  && pass "the signature 404: nothing installed, the refusal names it" \
  || fail "no signature, no install" "rc=$rc $out"
feed $((S0 + 7)) 24.0.2.0.192
wz "$O" $((S0 + 7)) content "$DAY" 24.0.100.51.198 > "$W/other"
sign "$W/other" > "$W/A/edge/zones/$(sha "$W/A/edge/rpz/$O.zone").zone.sig"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "DID NOT VERIFY"; } \
  && pass "a signature over other bytes (the sha in its name does not match what it signs): nothing installed" \
  || fail "a mismatched signature is refused" "rc=$rc $out"
: > "$W/A/edge/zones/$(sha "$W/A/edge/rpz/$O.zone").zone.sig"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "signature is 0 bytes"; } \
  && pass "an empty signature: nothing installed" \
  || fail "an empty signature is refused" "rc=$rc $out"
# A signed snapshot served as a zone: the same key signed it, with no prefix. The prefix is what stops it.
cp "$HERE/../core/testdata/interop.snap" "$W/snap" 2>/dev/null || head -c 4096 /dev/urandom > "$W/snap"
cp "$W/snap" "$W/A/edge/rpz/$O.zone"
sign "$W/snap" raw > "$W/A/edge/zones/$(sha "$W/snap").zone.sig"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "DID NOT VERIFY"; } \
  && pass "a snapshot signed by the same key, served as a zone, fails the zone signature (no prefix)" \
  || fail "an unprefixed signature never verifies as a zone" "rc=$rc $out"
control unprefixed "{ printf '%s\\000' \"\$ZONE_SIG_PREFIX\"; cat \"\$NEW\"; } > \"\$NEW.msg\"" "cat \"\$NEW\" > \"\$NEW.msg\""; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
{ [ "$rc" = 1 ] && ! says "$out" "DID NOT VERIFY" && says "$out" "no wedge-rpz1 header"; } \
  && pass "the control: a refresh verifying unprefixed bytes accepts the snapshot's signature (stopped only by the header)" \
  || fail "the control: an unprefixed verifier must accept the snapshot's signature" "rc=$rc $out"

# ---- 10. two nodes: the signature comes from the node that served the body --------------------------
# Node A (127.0.0.1) has the body and its signature; node B (::1, the same port) has the body only. The
# body is pinned to A; the signature must follow it.
feed $((S0 + 8)) 24.0.2.0.192
cp "$W/A/edge/rpz/$O.zone" "$W/B/edge/rpz/$O.zone"
LB="http://localhost:$SP/edge"
if [ "$V6" = 1 ]; then
  out=$(WHISPER_EDGE_RESOLVE="localhost:$SP:127.0.0.1" rz --rpz --base "$LB" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ "$(served)" = $((S0 + 8)) ] && ! grep -q '\.zone\.sig' "$W/B.log" 2>/dev/null; } \
    && pass "IPv4: the body from node A, the signature absent on node B: it is fetched from A and installs" \
    || fail "the signature follows the body over IPv4" "rc=$rc served=$(served) B: $(cat "$W/B.log" 2>/dev/null) $out"
  # The control: two unpinned requests. This curl prefers ::1 for localhost, so the signature request
  # lands on B, which has none.
  feed $((S0 + 9)) 24.0.2.0.192; cp "$W/A/edge/rpz/$O.zone" "$W/B/edge/rpz/$O.zone"
  control unpinned '  _lit=1
  case "$_host" in' '  _lit=1; F_ADDR=""
  case "$_host" in'; C=$CTL
  out=$(WHISPER_EDGE_RESOLVE="localhost:$SP:127.0.0.1" GATE_REFRESH=$C rz --rpz --base "$LB" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 1 ] && [ "$(served)" = $((S0 + 8)) ] && grep -q '\.zone\.sig.*status=404' "$W/B.log"; } \
    && pass "the control: an unpinned signature request reaches node B, gets 404, and nothing installs" \
    || fail "the control: unpinned requests must split across nodes" "rc=$rc served=$(served) $out"
  # IPv6 the other way round, on a second port: node A6 on ::1 has both, node B4 on 127.0.0.1 the body only.
  SP2=$(free_port); mkdir -p "$W/A6/edge/rpz" "$W/A6/edge/zones" "$W/B4/edge/rpz" "$W/B4/edge/zones"
  python3 "$W/stub.py" ::1 "$SP2" "$W/A6" "$W/A6.log" >/dev/null 2>&1 & echo $! > "$W/stubA6.srvpid"
  python3 "$W/stub.py" 127.0.0.1 "$SP2" "$W/B4" "$W/B4.log" >/dev/null 2>&1 & echo $! > "$W/stubB4.srvpid"
  # both stubs, the ::1 one included, polled before the rows that need them
  i=0; while [ "$i" -lt 50 ]; do curl -s -o /dev/null "http://127.0.0.1:$SP2/edge/x" 2>/dev/null \
    && curl -s -g -o /dev/null "http://[::1]:$SP2/edge/x" 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
  [ "$i" -lt 50 ] || fail "the second pair of stand-in nodes came up" "nothing answered on [::1]:$SP2 or 127.0.0.1:$SP2 within 5 s"
  feed6() { wz "$O" "$1" content "$DAY" 24.0.2.0.192 > "$W/z"; pub "$W/A6" "$W/z" "$O"; cp "$W/z" "$W/B4/edge/rpz/$O.zone"; }
  L6="http://localhost:$SP2/edge"
  feed6 $((S0 + 9))
  out=$(WHISPER_EDGE_RESOLVE="localhost:$SP2:[::1]" rz --rpz --base "$L6" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ "$(served)" = $((S0 + 9)) ] && ! grep -q '\.zone\.sig' "$W/B4.log" 2>/dev/null; } \
    && pass "IPv6: the body from node [::1], the signature absent on 127.0.0.1: pinned as [::1], it installs" \
    || fail "the signature follows the body over IPv6" "rc=$rc served=$(served) $out"
  control unbracketed '*:*) _pin="[$F_ADDR]" ;;' '*:*) _pin=$F_ADDR ;;'; C=$CTL
  feed6 $((S0 + 10))
  out=$(WHISPER_EDGE_RESOLVE="localhost:$SP2:[::1]" GATE_REFRESH=$C rz --rpz --base "$L6" 2>&1) && rc=0 || rc=$?
  if [ "$rc" = 0 ]; then
    note "the control, an unbracketed IPv6 pin, still installs on this curl ($(curl --version | head -1 | awk '{print $2}')), which accepts an IPv6 --resolve address without brackets; the refresh brackets it, the form curl documents from 7.57"
  else
    pass "the control: an unbracketed IPv6 pin fails on this curl (rc=$rc)"
  fi
  note "the unpinned control runs over IPv4 only: this curl tries ::1 first for localhost, so from an IPv6 body an unpinned request lands on the right node by luck, not by the pin"
  feed $((S0 + 11)) 24.0.2.0.192
  run --base "$STUB"
else
  # A section that could not run is never a pass: it makes the gate exit 77, NOT PROVEN.
  SKIPS="${SKIPS}the two-node rows (no answer on ::1 within 5 s: they need a second loopback address); "
  printf '  SKIP  the two-node rows: nothing answered on ::1 within 5 s\n'
fi
TOP=$(served)

# ---- 11. validity, one rule: content past its validUntil is the fleet's empty zone ------------------
# The fixture's EXPIRE is 7200, so its validUntil lies a slot after its serial's slot, and the serial
# the fleet sweeps to, slotStart(validUntil), is not the installed serial plus one.
OLD=$((SL - 3 * 3600 + 2)); VU=$((OLD / 3600 * 3600 + 7200)); SW=$((VU / 3600 * 3600))
wz "$O" "$OLD" content 7200 24.0.2.0.192 > "$W/expired"
mkdir -p "$W/v"; cp "$W/expired" "$W/v/rpz.zone"
printf 'whisper_edge_rpz_last_attempt_ok 1\nwhisper_edge_rpz_last_ok_seconds %s\n' "$(date +%s)" > "$W/v/rpz.zone.prom"
NORNDC="$W/no-such-rndc"
vrun() { out=$(WHISPER_EDGE_RNDC="$NORNDC" "${GATE_REFRESH:-$REFRESH}" --dir "$KDIR" --zone "$O" --if-due --zone-file "$W/v/rpz.zone" --base "$DEAD" 2>&1) && rc=0 || rc=$?; }
vrun
wedge_ref() { wz "$1" "$2" empty; }
wedge_ref "$O" "$SW" > "$W/want-empty"
{ cmp -s "$W/v/rpz.zone" "$W/want-empty" && says "$out" "EXPIRED zone $O" && ! says "$out" "could not fetch"; } \
  && { pass "past validUntil with no fetch due: the empty zone at serial $SW = slotStart(validUntil), byte for byte the fleet's (not $((OLD + 1)))"
       printf '%s\n' "$out" | sed 's/^/        | /'; } \
  || fail "an expired installed zone becomes the fleet's empty zone" "rc=$rc serial=$(sed -n 's/.*( \([0-9]*\) .*/\1/p' "$W/v/rpz.zone" | head -1) $out"
# The empty zone this script writes is the published golden, byte for byte: the file every writer of an
# empty zone is held to (rpz/testdata), here through the refresh's own function.
GOLD="$HERE/../rpz/testdata/rpz.whisper.online.empty-1791993600.zone"
sed -n '/^wedge_empty() {/,/^}/p' "$REFRESH" > "$W/we.sh"
# shellcheck disable=SC1091  # the function, cut from the refresh at run time
( . "$W/we.sh"; wedge_empty rpz.whisper.online 1791993600 ) > "$W/we.out"
{ [ -s "$W/we.sh" ] && [ -f "$GOLD" ] && cmp -s "$W/we.out" "$GOLD"; } \
  && pass "the refresh's empty zone is the published golden ($(basename "$GOLD")), byte for byte" \
  || fail "the refresh's empty zone matches the golden" "$(cmp "$W/we.out" "$GOLD" 2>&1)"
sed 's/ 86400 300 )/ 86401 300 )/' "$W/we.out" > "$W/we.bad"
cmp -s "$W/we.bad" "$GOLD" \
  && fail "the control: an empty zone with another EXPIRE must differ from the golden" "it matched" \
  || pass "the control: the same empty zone with EXPIRE 86401 differs from the golden"
cp "$W/expired" "$W/v/rpz.zone"
control loaded-plus-one '  if serial_gt "$_s" "$1"; then printf' '  if false; then printf'; C=$CTL
GATE_REFRESH=$C vrun
cmp -s "$W/v/rpz.zone" "$W/want-empty" \
  && fail "the control: a sweep to loaded + 1 must not match the fleet's empty zone" "it matched" \
  || pass "the control: the sweep at loaded + 1 writes serial $(sed -n 's/.*( \([0-9]*\) .*/\1/p' "$W/v/rpz.zone" | head -1), not the fleet's $SW"
# An empty zone left alone for twice its EXPIRE is not swept again: its serial is the fleet's, for good.
wedge_ref "$O" "$SW" > "$W/v/rpz.zone"
set_st last_advance_seconds $(( $(date +%s) - 2 * DAY - 60 )) "$W/v/rpz.zone.prom"
vrun
cmp -s "$W/v/rpz.zone" "$W/want-empty" && ! says "$out" "DISARMED" \
  && pass "an empty zone left 2 x EXPIRE without an advance is left as it is (no second empty at another serial)" \
  || fail "an empty zone is never re-disarmed" "$out"
control redisarm '  [ "$CUR_STATE" = legacy ] && [ "$DISARMED" = 0 ] || return 0' '  [ "$DISARMED" = 0 ] || return 0'; C=$CTL
GATE_REFRESH=$C vrun
cmp -s "$W/v/rpz.zone" "$W/want-empty" \
  && fail "the control: the no-advance rule applied to an empty zone must move it" "it did not" \
  || pass "the control: the old no-advance rule re-disarms the empty zone at serial $((SW + 1)), off the fleet's"
# Self-swept, then the fleet's own empty file at that serial arrives: it is current, not a refusal.
wedge_ref "$O" "$SW" > "$W/v/rpz.zone"
wedge_ref "$O" "$SW" > "$W/z"; pub "$W/A" "$W/z" "$O"
vfetch() { out=$(WHISPER_EDGE_RNDC="$NORNDC" "${GATE_REFRESH:-$REFRESH}" --dir "$KDIR" --zone "$O" --zone-file "$W/v/rpz.zone" --base "$STUB" 2>&1) && rc=0 || rc=$?; }
vfetch
{ [ "$rc" = 0 ] && cmp -s "$W/v/rpz.zone" "$W/want-empty" && says "$out" "not modified"; } \
  && pass "self-swept to the empty zone, then the fleet's file at serial $SW: the feed answers 304 to the file's own sha256" \
  || fail "the fleet's empty file at the swept serial matches the self-swept one" "rc=$rc $out"
cur=$(st current_total "$W/v/rpz.zone.prom")
# a fetch, not a 304: the client's If-None-Match is dropped for this one run, so the body is compared
control no-inm '  if [ -s "$TARGET" ]; then
    _inm=' '  if false; then
    _inm='; C=$CTL
GATE_REFRESH=$C vfetch
{ [ "$rc" = 0 ] && [ "$(st current_total "$W/v/rpz.zone.prom")" = $(( ${cur:-0} + 1 )) ] && cmp -s "$W/v/rpz.zone" "$W/want-empty"; } \
  && pass "and fetched whole (no If-None-Match), the same bytes at the same serial are counted current, not refused" \
  || fail "the fleet's empty file at the swept serial is current" "rc=$rc $out"
control strict-advance '          if cmp -s "$NEW" "$TARGET"; then' '          if false; then'; C=$CTL
control strict-advance-noinm '          if cmp -s "$NEW" "$TARGET"; then' '          if false; then' '  if [ -s "$TARGET" ]; then
    _inm=' '  if false; then
    _inm='; C2=$CTL
cur=$(st current_total "$W/v/rpz.zone.prom")
GATE_REFRESH=$C2 vfetch
[ "$(st current_total "$W/v/rpz.zone.prom")" = "${cur:-}" ] \
  && pass "the control: a refresh that only takes a strictly newer serial does not count it current ($(printf '%s' "$out" | head -1 | cut -c1-70))" \
  || fail "the control: strict advance must not count the swept file current" "$out"
# A fetched content zone NEWER than anything installed but already past its validUntil is refused, never
# turned into anything: the node that served it has not published since.
EXP2=$((SL - DAY + 3))
wz "$O" "$EXP2" content "$DAY" 24.0.2.0.192 > "$W/z"; pub "$W/A" "$W/z" "$O"
rm -f "$W/v/rpz.zone" "$W/v/rpz.zone.prom"
vfetch
{ [ "$rc" = 1 ] && [ ! -e "$W/v/rpz.zone" ] && [ "$(st expired_on_fetch_total "$W/v/rpz.zone.prom")" = 1 ] \
  && says "$out" "refused serial $EXP2 of $O: it was valid until"; } \
  && pass "a fetched zone past its own validUntil is refused before anything is installed (exit 1, counted, said)" \
  || fail "an expired fetch is refused" "rc=$rc $out"
# The control: the same zone later, inside its validity, installs as content. Dated from now, not from
# the gate's start, so a run that crosses an hour boundary cannot age it out.
wz "$O" $(( $(date +%s) / 3600 * 3600 - DAY + 7200 + 3 )) content "$DAY" 24.0.2.0.192 > "$W/z"; pub "$W/A" "$W/z" "$O"
vfetch
grep -q '^; state=content' "$W/v/rpz.zone" \
  && pass "the control: the same zone an hour later, still inside its validity, installs as content" \
  || fail "the control: valid content installs" "$out"
# A REPLAY: valid content installed, then a node serves an older, correctly signed zone that has since
# expired. Generation first: it is not newer, so it is refused as such, said under --quiet, and the
# installed zone stays byte for byte. (The order this replaces turned the replay into the empty zone at
# slotStart(its validUntil), which outranked the valid zone and disarmed it until the feed caught up.)
wz "$O" $((SL - 7200 + 5)) content "$DAY" 24.0.2.0.192 > "$W/v/rpz.zone"
cp "$W/v/rpz.zone" "$W/valid.keep"
wz "$O" $((SL - DAY + 5)) content "$DAY" 24.0.2.0.192 > "$W/z"; pub "$W/A" "$W/z" "$O"
qfetch() { out=$(WHISPER_EDGE_RNDC="$NORNDC" "${GATE_REFRESH:-$REFRESH}" --quiet --dir "$KDIR" --zone "$O" --zone-file "$W/v/rpz.zone" --base "$STUB" 2>&1 >/dev/null) && rc=0 || rc=$?; }
stale=$(st stale_feed_total "$W/v/rpz.zone.prom")
qfetch
{ cmp -s "$W/v/rpz.zone" "$W/valid.keep" && [ "$(st stale_feed_total "$W/v/rpz.zone.prom")" = $(( ${stale:-0} + 1 )) ] \
  && says "$out" "refused serial $((SL - DAY + 5)) of $O: it is not newer than the installed $((SL - 7200 + 5))"; } \
  && pass "a replayed, older, signed and expired zone is refused as not newer: the valid zone stays byte for byte, counted, said under --quiet" \
  || fail "a replay never moves the zone backwards" "rc=$rc $out"
control no-generation-first '        elif [ -n "$CUR_SERIAL" ] && ! serial_gt "$NEW_SERIAL" "$CUR_SERIAL"; then' '        elif false; then'; C=$CTL
GATE_REFRESH=$C qfetch
says "$out" "it is not newer than the installed" \
  && fail "the control: without the generation compared first the replay must not be refused as not newer" "$out" \
  || pass "the control: without the generation compared first, the replay is judged on its validity instead ($(printf '%s' "$out" | head -1 | cut -c1-60))"

# Self-swept, and the feed still serves the very content this resolver swept: not a node a publication
# behind and not a replay, but a feed whose zone has expired with nothing published since. Said as that,
# under --quiet, and the empty zone stays. The control: an older replay on the same host keeps the
# replay message, so the new one is keyed on the swept serial and nothing looser.
cp "$W/expired" "$W/v/rpz.zone"
printf 'whisper_edge_rpz_last_attempt_ok 1\nwhisper_edge_rpz_last_ok_seconds %s\n' "$(date +%s)" > "$W/v/rpz.zone.prom"
vrun
pub "$W/A" "$W/expired" "$O"
qfetch
{ cmp -s "$W/v/rpz.zone" "$W/want-empty" && says "$out" "refused serial $OLD of $O: it is the content this resolver swept" \
  && says "$out" "the feed's zone has expired and it has not published since" && ! says "$out" "a publication behind"; } \
  && { pass "self-swept, then the feed still serves the swept content $OLD: said as an expired feed that has not published since, the empty zone kept"
       printf '%s\n' "$out" | sed 's/^/        | /'; } \
  || fail "the swept content served again is named as the feed's expiry" "rc=$rc $out"
wz "$O" $((OLD - 3600)) content 7200 24.0.2.0.192 > "$W/z"; pub "$W/A" "$W/z" "$O"
qfetch
{ cmp -s "$W/v/rpz.zone" "$W/want-empty" && says "$out" "a node a publication behind or a replay" \
  && ! says "$out" "it is the content this resolver swept"; } \
  && pass "the control: an older serial than the swept content on the same host is still refused as a node behind or a replay" \
  || fail "the control: only the swept serial reads as the feed's expiry" "rc=$rc $out"

# ---- 12. zero triggers is content, and it replaces content ---------------------------------------------
wz "$O" $((TOP + 1)) content "$DAY" > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
wait_answer A 192.0.2.5
{ [ "$rc" = 0 ] && [ "$(served)" = $((TOP + 1)) ] && [ "$(answer A)" = 192.0.2.5 ] && grep -q '^; triggers=0' "$ZF"; } \
  && pass "a content zone with zero triggers (SOA and NS only) replaces the armed one: serial $((TOP + 1)), the name resolves" \
  || fail "zero-trigger content installs" "rc=$rc served=$(served) A=$(answer A) $out"
control zero-is-empty '    [ "$_body" = "$H_TRIG" ] || {' '    [ "$_body" = "$H_TRIG" ] && [ "$_body" -gt 0 ] || {'; C=$CTL
wz "$O" $((TOP + 2)) content "$DAY" > "$W/z"; pub "$W/A" "$W/z" "$O"
GATE_REFRESH=$C run --base "$STUB"
[ "$(served)" = $((TOP + 1)) ] \
  && pass "the control: a refresh reading SOA-and-NS-only as no content refuses it, and named keeps $((TOP + 1))" \
  || fail "the control: zero-trigger content must be refused by the defect" "served=$(served) $out"
run --base "$STUB"
TOP=$(served)

# ---- 13. what the header promises, the records must be ------------------------------------------------
wz "$O" $((TOP + 1)) empty > "$W/z"; printf '24.0.2.0.192.rpz-ip.%s.\t300\tIN\tCNAME\t*.\n' "$O" >> "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" "state=empty, but 1 record"; } \
  && pass "state=empty with a trigger in it is refused" \
  || fail "an empty header with content is refused" "rc=$rc served=$(served) $out"
control header-only '    [ "$_body" = 0 ] || { H_WHY="state=empty, but $_body record(s) below the apex"; return 1; }' '    :'; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
[ "$(served)" = $((TOP + 1)) ] \
  && pass "the control: a refresh that trusts the header alone installs the 'empty' zone with its trigger" \
  || fail "the control: the header-only check must install it" "served=$(served) $out"
run --base "$STUB"; TOP=$(served)
# validUntil far past the slot start plus EXPIRE (the year 9999: what a milliseconds-for-seconds slip
# reads as), every other field consistent.
wz "$O" $((TOP + 1)) content "$DAY" 24.0.2.0.192 | sed "s/^; validUntil=.*/; validUntil=9999-12-31T00:00:00Z/" > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" "is not the serial's slot start plus EXPIRE"; } \
  && pass "a validUntil far past the serial's slot start plus EXPIRE is refused" \
  || fail "validUntil is cross-checked" "rc=$rc served=$(served) $out"
control no-cross-check '    [ "$H_VALID" = "$_want" ] || {' '    true || {'; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
[ "$(served)" = $((TOP + 1)) ] \
  && pass "the control: without the cross-check it installs, valid until the year 9999" \
  || fail "the control: no cross-check installs it" "served=$(served) $out"
feed $((TOP + 2)) 24.0.2.0.192; run --base "$STUB"; TOP=$(served)
# A header line longer than 255 bytes.
wz "$O" $((TOP + 1)) content "$DAY" 24.0.2.0.192 | sed "s/^; sources=.*/; sources=$(printf '%0255d' 0)/" > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
{ [ "$rc" = 1 ] && says "$out" "longer than 255 bytes"; } \
  && pass "a header line of 265 bytes is refused" || fail "header lines are at most 255 bytes" "rc=$rc $out"
wz "$O" $((TOP + 1)) content "$DAY" 24.0.2.0.192 | sed "s/^; sources=.*/; sources=$(printf '%0245d' 0)/" > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
[ "$(served)" = $((TOP + 1)) ] && pass "the control: a header line of exactly 255 bytes installs" \
  || fail "a 255-byte header line installs" "$out"
TOP=$(served)
# Nothing but $TTL, and no owner outside the zone: an $INCLUDE (its one trigger in a file nobody signed),
# a $GENERATE, an out-of-zone A record, each correctly signed, and each refused before any BIND tool
# reads the file.
printf '24.0.2.0.192.rpz-ip.%s.\t300\tIN\tCNAME\t*.\n' "$O" > "$G/inc.txt"   # where named may read it
wz "$O" $((TOP + 1)) content "$DAY" | sed 's/^; triggers=0$/; triggers=1/' > "$W/z"; printf '$INCLUDE %s\n' "$G/inc.txt" >> "$W/z"
pub "$W/A" "$W/z" "$O"; cp "$W/z" "$W/z.include"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" 'is a $INCLUDE directive'; } \
  && pass "a signed zone pulling its trigger in through \$INCLUDE is refused before named reads the included file" \
  || fail "an \$INCLUDE is refused" "rc=$rc $out"
wz "$O" $((TOP + 1)) content "$DAY" | sed 's/^; triggers=0$/; triggers=1/' > "$W/z"; printf '$GENERATE 1-1 $.0.2.0.192.rpz-ip CNAME *.\n' >> "$W/z"
pub "$W/A" "$W/z" "$O"; run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" 'is a $GENERATE directive'; } \
  && pass "a signed zone with a \$GENERATE line is refused" || fail "a \$GENERATE is refused" "rc=$rc $out"
wz "$O" $((TOP + 1)) content "$DAY" > "$W/z"; printf 'evil.example.com.\t300\tIN\tA\t192.0.2.66\n' >> "$W/z"
pub "$W/A" "$W/z" "$O"; run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" 'owner evil.example.com. is outside'; } \
  && pass "a signed zone with a record outside the zone (which named-compilezone drops unseen) is refused" \
  || fail "an out-of-zone record is refused" "rc=$rc $out"
# An escaped dot: the TEXT ends in .rpz.whisper.online. and the labels put it outside the zone.
wz "$O" $((TOP + 1)) content "$DAY" > "$W/z"; printf 'evil\\.com\\.rpz.whisper.online.\t300\tIN\tA\t192.0.2.66\n' >> "$W/z"
pub "$W/A" "$W/z" "$O"; cp "$W/z" "$W/z.escape"; run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(served)" = "$TOP" ] && says "$out" 'carries an escape'; } \
  && pass "an owner with escaped dots (evil\\.com\\.rpz.whisper.online., outside the zone by its labels) is refused" \
  || fail "an escaped owner is refused" "rc=$rc $out"
# The control: the text check without its escape rule passes the same file (named-compilezone refuses
# it further on here, which is BIND's behaviour, not this check's).
control no-escape-check '    $1 ~ /\\/ { printf "line %d owner %s carries an escape, which the format never writes", NR, $1; exit }' '    0 { }'; C=$CTL
sed -n '/^raw_check() {/,/^}/p' "$C" > "$W/rc.sh"
# shellcheck disable=SC1091,SC2034  # the function, cut from the control copy at run time, reads ZDOT
if ( . "$W/rc.sh"; ZDOT="$O."; raw_check "$W/z.escape" ); then
  pass "the control: the text check without its escape rule passes the escaped owner as inside the zone"
else fail "the control: without the escape rule the text check must pass it" "$(sed -n 1,2p "$W/rc.sh")"; fi
cp "$W/z.include" "$W/z"; pub "$W/A" "$W/z" "$O"
control no-raw-check '      elif ! raw_check "$NEW"; then _why=$H_WHY' '      elif false; then :'; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
{ [ "$(served)" = $((TOP + 1)) ] && grep -q '^\$INCLUDE' "$ZF"; } \
  && pass "the control: without the text check the \$INCLUDE zone installs and named serves it, its trigger from a file nobody signed" \
  || fail "the control: an \$INCLUDE must install without the check" "served=$(served) $out"
feed $((TOP + 2)) 24.0.2.0.192; run --base "$STUB"; TOP=$(served)

# ---- 14. the ETag is never stored or echoed -----------------------------------------------------------
feed $((TOP + 1)) 24.0.2.0.192
printf '"x\001y" W/"\042' > "$W/A/etag"
run --base "$STUB"
: > "$W/A.log"; run --base "$STUB"
{ [ "$(served)" = $((TOP + 1)) ] && ! grep -rl "$(printf '\001')" "$ZD" >/dev/null 2>&1 \
  && grep -q "inm=\"$(sha "$ZF")\"" "$W/A.log"; } \
  && pass "a quote and a control byte in the feed's ETag change nothing on disk; the next request sends the file's own sha256" \
  || fail "the ETag is never stored" "served=$(served) log=$(cat "$W/A.log")"
control store-etag '  F_ADDR=$(cat "$NEW.ip" 2>/dev/null)' '  F_ADDR=$(cat "$NEW.ip" 2>/dev/null); sed -n "s/^[Ee][Tt][Aa][Gg]: //p" "$NEW.hdr" > "$TARGET.etag"'; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
grep -rl "$(printf '\001')" "$ZD" >/dev/null 2>&1 \
  && pass "the control: a header-storing client writes the control byte into $ZD" \
  || fail "the control: storing the ETag must put its bytes on disk" "$out"
rm -f "$ZF.etag" "$W/A/etag"
TOP=$(served)

# ---- 15. the size cap, on a body of unknown length ------------------------------------------------------
sum=$(sha "$ZF")
echo 5208705 > "$W/A/chunked"
run --base "$STUB"
{ [ "$rc" = 1 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "over the 5208704-byte cap" \
  && [ "$(find "$ZD" -maxdepth 1 -name '.rpz.zone.new.*' | wc -l)" = 0 ]; } \
  && pass "a chunked body of 5,208,705 bytes is refused at the cap: nothing installed, no temp file left" \
  || fail "the cap bounds a chunked body" "rc=$rc $out"
control cap-plus-one 'RPZ_CAP=5208704 ' 'RPZ_CAP=5208705 '; C=$CTL
GATE_REFRESH=$C run --base "$STUB"
says "$out" "over the" \
  && fail "the control: with the cap one byte higher the body must pass the cap" "$out" \
  || pass "the control: with the cap one byte higher the same body passes the cap (and is refused later, for its header)"
rm -f "$W/A/chunked"

# ---- 16. the origin: checked before anything else, and the file and the fetch follow it ----------------
# --zone RPKI before --rpz, after it, and alone: each fetches the RPKI zone and installs its own file.
wz "$OK" $((SL + 3000)) content "$DAY" 24.0.2.0.192 > "$W/zk"; pub "$W/A" "$W/zk" "$OK"
OSER=$(served); : > "$W/rndc.calls"
for form in "--zone $OK --rpz" "--rpz --zone $OK" "--zone $OK"; do
  rm -f "$ZK" "$ZK.prom"; : > "$W/A.log"
  # shellcheck disable=SC2086  # the form is a list of words
  out=$(rz $form --base "$STUB" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 0 ] && [ -s "$ZK" ] && grep -q "GET /edge/rpz/$OK.zone" "$W/A.log" && ! grep -q "GET /edge/rpz/$O.zone" "$W/A.log"; } \
    && pass "'$form' fetches /edge/rpz/$OK.zone and installs $ZK" \
    || fail "'$form' fetches the RPKI zone" "rc=$rc log=$(cat "$W/A.log") $out"
done
i=0; while [ "$i" -lt 20 ] && [ "$(served "$OK")" != $((SL + 3000)) ]; do i=$((i+1)); sleep 0.25; done
[ "$(served "$OK")" = $((SL + 3000)) ] && pass "named loaded the RPKI zone at $((SL + 3000)) beside the reputation zone" \
  || fail "named loads the RPKI zone" "served=$(served "$OK")"
# One zone's refresh touches that zone only: the reputation zone's serial unmoved, and every rndc call
# the three runs made names the RPKI zone.
{ [ "$(served)" = "$OSER" ] && [ -s "$W/rndc.calls" ] && [ "$(grep -vc "$OK" "$W/rndc.calls")" = 0 ]; } \
  && pass "the RPKI runs left the reputation zone at $OSER and asked rndc about $OK only ($(wc -l < "$W/rndc.calls") calls)" \
  || fail "one zone's refresh leaves the other alone" "served=$(served) calls=$(sort -u "$W/rndc.calls" | tr '\n' ';')"
: > "$W/rndc.calls"; feed $((TOP + 1)) 24.0.2.0.192; run --base "$STUB"; TOP=$(served)
grep -q "reload $O\$\|zonestatus $O\$" "$W/rndc.calls" \
  && pass "the control: the same reading of a reputation run's calls sees $O" \
  || fail "the control: a reputation run must call rndc about $O" "$(cat "$W/rndc.calls")"
control assigning-rpz '    --rpz)        RPZ_FLAG=1 ;;' '    --rpz)        RPZ_FLAG=1; ZONE_ARG=rpz.whisper.online; ZONE_GIVEN=1 ;;'; C=$CTL
: > "$W/A.log"
out=$(GATE_REFRESH=$C rz --zone "$OK" --rpz --base "$STUB" 2>&1)
grep -q "GET /edge/rpz/$O.zone" "$W/A.log" \
  && pass "the control: an --rpz that assigns the zone makes '--zone $OK --rpz' fetch the reputation zone" \
  || fail "the control: the assigning --rpz must fetch the wrong zone" "$(cat "$W/A.log")"
control zone-not-mode '    snapshot) MODE=rpz ;;' '    snapshot) [ "$RPZ_FLAG" = 1 ] && MODE=rpz ;;'; C=$CTL
out=$(GATE_REFRESH=$C rz --zone "$OK" --base "$STUB" 2>&1) && rc=0 || rc=$?
says "$out" "snapshot\|edge.pub\|does not exist" && ! says "$out" "installed zone $OK" \
  && pass "the control: a parser where --zone alone is not the zone mode runs the snapshot path instead" \
  || fail "the control: --zone without --rpz must miss the zone under the old parser" "rc=$rc $out"
# The RPKI zone with no --zone-file and no zone statement for it: its own file, not rpz.zone.
grep -v 'zone "'"$OK"'" {' "$G/named-rec.conf" | grep -v "zone \"$O\" {" | sed '/response-policy/,/qname-wait-recurse/d' > "$G/named-none.conf"
rm -f "$ZK" "$ZK.prom"; zsum=$(sha "$ZF")
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$OK" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && [ -s "$ZK" ] && [ "$(sha "$ZF")" = "$zsum" ]; } \
  && pass "with no --zone-file, the RPKI zone goes to $ZK, its own file under named's directory" \
  || fail "the RPKI zone gets its own default file" "rc=$rc $out"
control one-default "origin_file() { if [ \"\$1\" = rpz.whisper.online ]; then printf 'rpz.zone'; else printf '%s.zone' \"\$1\"; fi; }" "origin_file() { printf 'rpz.zone'; }" \
  '  if [ -n "$CUR_ORIGIN" ] && [ "$CUR_ORIGIN" != "$ZONE" ]; then' '  if false; then'; C=$CTL
cp "$ZF" "$W/zf.keep"; cp "$PROM" "$W/prom.keep"
out=$(WHISPER_EDGE_RNDC="$NORNDC" GATE_REFRESH=$C "$C" --dir "$KDIR" --zone "$OK" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
[ "$(sha "$ZF")" != "$zsum" ] \
  && pass "the control: one default file for every zone writes the RPKI zone over $ZF" \
  || fail "the control: the single default must collide" "$out"
cp "$W/zf.keep" "$ZF"; cp "$W/prom.keep" "$PROM"; touch "$ZF"; run --base "$STUB"

# ---- 16b. a zone not published yet: exit 5, said once even under --quiet, then asked once a slot --------
mkdir -p "$W/np"; rm -f "$W/A/edge/rpz/$OK.zone"
nprun() { out=$(WHISPER_EDGE_RNDC="$NORNDC" "${GATE_REFRESH:-$REFRESH}" --if-due --quiet --dir "$KDIR" --zone "$OK" --zone-file "$W/np/" --base "$STUB" 2>&1) && rc=0 || rc=$?; }
NPROM="$W/np/$OK.zone.prom"
: > "$W/A.log"; nprun
{ [ "$rc" = 5 ] && [ ! -e "$W/np/$OK.zone" ] && says "$out" "zone $OK is not published yet (HTTP 404" \
  && [ "$(printf '%s\n' "$out" | grep -c .)" = 1 ] && [ "$(st not_published_total "$NPROM")" = 1 ]; } \
  && pass "a 404 for a published origin, nothing installed: exit 5, one line under --quiet, counted not_published" \
  || fail "a zone not published yet is said once and counted" "rc=$rc $out"
: > "$W/A.log"; nprun
{ [ "$rc" = 0 ] && [ -z "$out" ] && [ ! -s "$W/A.log" ]; } \
  && pass "the next timer run inside the hour asks the feed nothing and says nothing (the backoff)" \
  || fail "a zone not published yet is asked once a slot" "rc=$rc log=$(cat "$W/A.log") $out"
set_st last_attempt_seconds $(( $(date +%s) - 3601 )) "$NPROM"
: > "$W/A.log"; nprun
{ [ "$rc" = 5 ] && [ -z "$out" ] && grep -q "GET /edge/rpz/$OK.zone" "$W/A.log" && [ "$(st not_published_total "$NPROM")" = 2 ]; } \
  && pass "the control: an hour on it asks again, gets the 404, and only counts it (no second line)" \
  || fail "the backoff ends after an hour, quietly" "rc=$rc log=$(cat "$W/A.log") $out"
control quiet-404 '        rpz_event "zone $ZONE is not published yet (HTTP 404 for $BASE/rpz/$ZONE.zone); nothing installed$_then"' '        rpz_note "zone $ZONE is not published yet (HTTP 404 for $BASE/rpz/$ZONE.zone); nothing installed$_then"'; C=$CTL
rm -f "$W/np"/*; GATE_REFRESH=$C nprun
[ -z "$out" ] && pass "the control: a refresh saying it through the --quiet channel leaves the journal empty on the first 404" \
  || fail "the control: the quiet channel must print nothing" "$out"
control no-backoff '  elif [ "$IF_DUE" = 1 ] && [ -n "${st_not_published_since_seconds:-}" ]; then' '  elif false; then'; C=$CTL
GATE_REFRESH=$C nprun; : > "$W/A.log"; GATE_REFRESH=$C nprun
grep -q "GET /edge/rpz/$OK.zone" "$W/A.log" && pass "the control: without the backoff every timer run asks the feed again" \
  || fail "the control: no backoff must ask again" "$(cat "$W/A.log")"
# After a 404 with nothing installed, a failed fetch (a timeout, a 503) ends the back-off: the next run
# is RETRY's, not an hour on.
rm -f "$W/np"/*; nprun
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --quiet --dir "$KDIR" --zone "$OK" --zone-file "$W/np/" --base "$DEAD" 2>&1); set_st last_attempt_seconds $(( $(date +%s) - 301 )) "$NPROM"
: > "$W/A.log"; nprun
grep -q "GET /edge/rpz/$OK.zone" "$W/A.log" \
  && pass "a fetch failure after a 404 ends the back-off: the next run, RETRY's 300 s on, asks the feed" \
  || fail "a fetch failure ends the back-off" "log=$(cat "$W/A.log")"
control keep-backoff '      st_last_attempt_ok=0; st_bump fetch_failures_total; st_not_published_since_seconds=""   # RETRY, not the back-off' '      st_last_attempt_ok=0; st_bump fetch_failures_total'; C=$CTL
rm -f "$W/np"/*; GATE_REFRESH=$C nprun
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --quiet --dir "$KDIR" --zone "$OK" --zone-file "$W/np/" --base "$DEAD" 2>&1); set_st last_attempt_seconds $(( $(date +%s) - 301 )) "$NPROM"
: > "$W/A.log"; GATE_REFRESH=$C nprun
[ ! -s "$W/A.log" ] && pass "the control: a failure that leaves the back-off set waits the hour" \
  || fail "the control: the kept back-off must ask nothing" "$(cat "$W/A.log")"
# A 404 for a zone this box HAS installed: the feed stopped publishing it. A failure, every run, on stderr.
wz "$OK" $((SL + 3000)) content "$DAY" 24.0.2.0.192 > "$W/np/$OK.zone"; rm -f "$NPROM"
wdrun() { out=$(WHISPER_EDGE_RNDC="$NORNDC" "${GATE_REFRESH:-$REFRESH}" --quiet --dir "$KDIR" --zone "$OK" --zone-file "$W/np/" --base "$STUB" 2>&1 >/dev/null) && rc=0 || rc=$?; }
wdrun; r1=$rc; o1=$out; wdrun
{ [ "$r1" = 1 ] && [ "$rc" = 1 ] && says "$o1" "the zone is no longer published" && says "$out" "the zone is no longer published" \
  && [ "$(st withdrawn_total "$NPROM")" = 2 ] && [ "$(st last_attempt_ok "$NPROM")" = 0 ] && [ -s "$W/np/$OK.zone" ]; } \
  && pass "a 404 for an installed zone: exit 1 and an alarm on stderr under --quiet on every run, counted withdrawn, the zone kept" \
  || fail "a withdrawn zone is an alarm" "rc=$r1,$rc withdrawn=$(st withdrawn_total "$NPROM") $out"
control withdrawn-is-unpublished '    elif [ "$F_CODE" = 404 ] && [ -n "$CUR_SERIAL" ]; then' '    elif false; then'; C=$CTL
GATE_REFRESH=$C wdrun
{ [ "$rc" = 5 ] && [ -z "$out" ]; } && pass "the control: reading it as not published yet exits 5 (a successful unit) with nothing on stderr" \
  || fail "the control: the old reading must be silent" "rc=$rc $out"
wz "$OK" $((SL + 3000)) content "$DAY" 24.0.2.0.192 > "$W/zk"; pub "$W/A" "$W/zk" "$OK"

# --zone policy.local, and named loading policy.local: refused before any fetch, nothing touched.
sed "s|zone \"$O\" { type master;|zone \"policy.local\" { type master;|; s|zone \"$O\";|zone \"policy.local\";|" "$G/named-rec.conf" > "$G/named-local.conf"
zsum=$(sha "$ZF"); : > "$W/A.log"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone policy.local --named-conf "$G/named-local.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 6 ] && [ ! -s "$W/A.log" ] && [ "$(sha "$ZF")" = "$zsum" ] && says "$out" "not a zone the feed publishes" \
  && says "$out" "$O $OK"; } \
  && pass "--zone policy.local exits 6 before any fetch, naming the published zones, the installed zone untouched" \
  || fail "an unlisted origin is refused first" "rc=$rc log=$(cat "$W/A.log") $out"
control any-origin 'origin_listed() { case " $RPZ_ORIGINS " in *" $1 "*) return 0 ;; esac; return 1; }' 'origin_listed() { return 0; }' \
  '  if [ -n "$CUR_ORIGIN" ] && [ "$CUR_ORIGIN" != "$ZONE" ]; then' '  if false; then'; C=$CTL
: > "$W/A.log"; cp "$PROM" "$W/prom.keep"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone policy.local --named-conf "$G/named-local.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
cp "$W/prom.keep" "$PROM"   # the defective copy wrote the reputation zone's state under another name
grep -q "GET /edge/rpz/policy.local.zone" "$W/A.log" \
  && pass "the control: with no list, --zone policy.local reaches the network" \
  || fail "the control: an unchecked origin must be fetched" "rc=$rc $out"
# named loads the file as another zone: exit 7, both names said, and an expired file emptied first.
cp "$G/named-local.conf" "$G/named-renamed.conf"
cp "$ZF" "$W/zf.keep"
cp "$W/expired" "$ZF"
: > "$W/A.log"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$O" --named-conf "$G/named-renamed.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 7 ] && says "$out" "as zone \"policy.local\"" && says "$out" "holds zone $O" && [ ! -s "$W/A.log" ] \
  && cmp -s "$ZF" "$W/want-empty"; } \
  && pass "named loading the file as policy.local: exit 7 naming both, nothing fetched, the expired content emptied first" \
  || fail "a renamed zone is refused after the sweep" "rc=$rc fetched=$(cat "$W/A.log") $out"
cp "$W/expired" "$ZF"
control refuse-first '  if [ -n "$RENAMED" ]; then
    validity_sweep || true' '  if [ -n "$RENAMED" ]; then
    :'; C=$CTL
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone "$O" --named-conf "$G/named-renamed.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
cmp -s "$ZF" "$W/expired" \
  && pass "the control: refusing before the sweep leaves the expired content on disk" \
  || fail "the control: refusing first must strand the expired file" "$out"
control rename '    [ "$(fold_name "$_zn")" = "$ZONE" ] || RENAMED="$_zn"' '    :'; C=$CTL
cp "$W/zf.keep" "$ZF"; : > "$W/A.log"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone "$O" --named-conf "$G/named-renamed.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
[ "$rc" != 7 ] && [ -s "$W/A.log" ] \
  && pass "the control: a refresh that renames goes on and fetches (rc=$rc)" \
  || fail "the control: renaming must reach the network" "rc=$rc $out"
cp "$W/zf.keep" "$ZF"; touch "$ZF"
# A mixed-case zone statement is the same zone.
sed "s|zone \"$O\" { type master;|zone \"RPZ.Whisper.Online.\" { type master;|" "$G/named-rec.conf" > "$G/named-mixed.conf"
feed $((TOP + 2)) 24.0.2.0.192
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$O" --named-conf "$G/named-mixed.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" != 7 ] && grep -q "^; generation=$((TOP + 2))\$" "$ZF"; } \
  && pass "a zone statement spelled \"RPZ.Whisper.Online.\" is the same zone: serial $((TOP + 2)) installs" \
  || fail "a mixed-case zone statement installs" "rc=$rc $out"
control byte-compare "fold_name() { printf '%s' \"\$1\" | LC_ALL=C tr '[:upper:]' '[:lower:]' | sed 's/\\.\$//'; }" "fold_name() { printf '%s' \"\$1\"; }"; C=$CTL
feed $((TOP + 3)) 24.0.2.0.192
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone "$O" --named-conf "$G/named-mixed.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
[ "$rc" = 7 ] && pass "the control: a byte compare of the names refuses the mixed-case statement as a rename" \
  || fail "the control: a byte compare must refuse it" "rc=$rc $out"
run --base "$STUB"; TOP=$(served)
# The same with a file from before per-zone files, which has no header: it loads as the reputation zone,
# so it is the reputation zone's, and the RPKI zone is not written over it.
mkdir -p "$W/leg"
{ printf '$TTL 300\n%s.\tIN\tSOA\tns1.whisper.online. hostmaster.whisper.online. ( 1791990000 900 300 86400 300 )\n' "$O"
  printf '%s.\tIN\tNS\tns1.whisper.online.\n24.0.2.0.192.rpz-ip.%s.\t300\tIN\tCNAME\t.\n' "$O" "$O"; } > "$W/leg/rpz.zone"
cp "$W/leg/rpz.zone" "$W/leg.keep"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$OK" --zone-file "$W/leg/rpz.zone" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 4 ] && cmp -s "$W/leg/rpz.zone" "$W/leg.keep" && says "$out" "holds zone $O, not $OK"; } \
  && pass "a headerless reputation file named as the RPKI zone's: exit 4, untouched (it loads as $O)" \
  || fail "a legacy file of another zone is never overwritten" "rc=$rc $out"
control legacy-other-zone '  if [ -z "$CUR_ORIGIN" ] && [ -s "$TARGET" ] && [ -z "$CUR_SOA" ]; then' '  if false; then'; C=$CTL
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone "$OK" --zone-file "$W/leg/rpz.zone" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1)
grep -q "^; origin=$OK\$" "$W/leg/rpz.zone" && pass "the control: header-only detection writes the RPKI zone over the legacy reputation file" \
  || fail "the control: without the legacy check it must overwrite" "$out"
printf 'not a zone at all\n' > "$W/leg/rpz.zone"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$OK" --zone-file "$W/leg/rpz.zone" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
grep -q "^; origin=$OK\$" "$W/leg/rpz.zone" && pass "and a file that loads as no zone at all is nobody's: it is replaced" \
  || fail "a non-zone file is replaced" "rc=$rc $out"
# --zone-file naming another zone's file (named's configuration silent about it): refused, exit 4,
# that file and its state untouched.
cp "$ZF" "$W/zf.keep"; cp "$PROM" "$W/prom.keep"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --dir "$KDIR" --zone "$OK" --zone-file "$ZF" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 4 ] && cmp -s "$ZF" "$W/zf.keep" && cmp -s "$PROM" "$W/prom.keep" && says "$out" "holds zone $O, not $OK"; } \
  && pass "--zone $OK --zone-file naming the reputation zone's file: exit 4, that file and its state untouched" \
  || fail "one zone is never written over another's file" "rc=$rc $out"
control other-zone-file '  if [ -n "$CUR_ORIGIN" ] && [ "$CUR_ORIGIN" != "$ZONE" ]; then' '  if false; then'; C=$CTL
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$C" --dir "$KDIR" --zone "$OK" --zone-file "$ZF" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1)
grep -q "^; origin=$OK\$" "$ZF" && pass "the control: without the check the RPKI zone is written over the reputation zone's file" \
  || fail "the control: the unchecked refresh must overwrite it" "$out"
cp "$W/zf.keep" "$ZF"; cp "$W/prom.keep" "$PROM"; touch "$ZF"
# A ~/.curlrc never applies to the zone's requests (curl -q), and the base's scheme is the only one.
mkdir -p "$W/home"; printf 'user-agent = "curlrc-was-read"\n' > "$W/home/.curlrc"
feed $((TOP + 5)) 24.0.2.0.192; : > "$W/A.log"
out=$(HOME="$W/home" CURL_HOME="$W/home" rz --rpz --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && [ -s "$W/A.log" ] && ! grep -q curlrc-was-read "$W/A.log"; } \
  && pass "a ~/.curlrc is not read on the zone's requests (its user-agent line never reached the feed)" \
  || fail "curl -q on the zone path" "rc=$rc $(cat "$W/A.log")"
control curlrc '  set -- -q -sS --proto "=$BASE_SCHEME" --max-time 120' '  set -- -sS --proto "=$BASE_SCHEME" --max-time 120'; C=$CTL
feed $((TOP + 6)) 24.0.2.0.192; : > "$W/A.log"
out=$(HOME="$W/home" CURL_HOME="$W/home" GATE_REFRESH=$C rz --rpz --base "$STUB" 2>&1)
grep -q curlrc-was-read "$W/A.log" && pass "the control: without -q the curlrc's user-agent reaches the feed" \
  || fail "the control: curl without -q must read the curlrc" "$(cat "$W/A.log")"
out=$(rz --rpz --base "ftp://127.0.0.1:$SP/edge" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 2 ] && says "$out" "neither https:// nor http://"; } && pass "a --base of another scheme is refused before any request (exit 2)" \
  || fail "the zone path takes https and http only" "rc=$rc $out"
run --base "$STUB"; TOP=$(served)
# --zone RPZ.WHISPER.ONLINE under a Turkish locale: the C locale's fold, not the ambient one.
LOC="$W/locale"; mkdir -p "$LOC"
if [ "$(locale -a 2>/dev/null | grep -ci '^tr_TR.iso88599$')" -gt 0 ]; then TRL=tr_TR.ISO-8859-9; LOCP=""
elif command -v localedef >/dev/null 2>&1 && localedef -i tr_TR -f ISO-8859-9 "$LOC/tr_TR.ISO-8859-9" >/dev/null 2>&1; then TRL=tr_TR.ISO-8859-9; LOCP=$LOC
else TRL=""; fi
if [ -n "$TRL" ] && [ "$(printf 'I' | LOCPATH=${LOCP:-/usr/lib/locale} LC_ALL=$TRL tr '[:upper:]' '[:lower:]' | od -An -tx1 | tr -d ' ')" = fd ]; then
  feed $((TOP + 1)) 24.0.2.0.192
  out=$(LOCPATH=${LOCP:-/usr/lib/locale} LC_ALL=$TRL WHISPER_EDGE_RNDC="$W/rndc" WHISPER_EDGE_RELOAD_WAIT=8 "$REFRESH" --dir "$KDIR" --named-conf "$G/named-rec.conf" --zone RPZ.WHISPER.ONLINE --base "$STUB" 2>&1) && rc=0 || rc=$?
  sv=$(served)
  { [ "$rc" = 0 ] && [ "$sv" = $((TOP + 1)) ]; } \
    && pass "--zone RPZ.WHISPER.ONLINE under LC_ALL=$TRL (where I lowers to a dotless i) installs $O" \
    || fail "the origin folds in the C locale" "rc=$rc served=$sv (wanted $((TOP + 1)), and $(served) on a second read) $out"
  control ambient-fold "  _o=\$(printf '%s' \"\$1\" | LC_ALL=C tr '[:upper:]' '[:lower:]')" "  _o=\$(printf '%s' \"\$1\" | tr '[:upper:]' '[:lower:]')"; C=$CTL
  out=$(LOCPATH=${LOCP:-/usr/lib/locale} LC_ALL=$TRL "$C" --dir "$KDIR" --zone RPZ.WHISPER.ONLINE --base "$STUB" 2>&1) && rc=0 || rc=$?
  [ "$rc" = 6 ] && pass "the control: folding in the ambient locale turns WHISPER into whısper and refuses it (exit 6)" \
    || fail "the control: the ambient fold must refuse it" "rc=$rc $out"
else
  fail "the Turkish-locale case could run" "no tr_TR.ISO-8859-9 locale and localedef could not build one"
fi
TOP=$(served)
# '/', '..' and an option word as the origin: refused before any fetch.
for badz in "a/b" "rpz..whisper.online" "-o" "../rpz.whisper.online"; do
  : > "$W/A.log"
  out=$("$REFRESH" --dir "$KDIR" --zone "$badz" --base "$STUB" 2>&1) && rc=0 || rc=$?
  { [ "$rc" = 6 ] && [ ! -s "$W/A.log" ]; } && pass "--zone '$badz' exits 6 before any fetch" \
    || fail "--zone '$badz' is refused first" "rc=$rc log=$(cat "$W/A.log") $out"
done
control loose '    if ! ZONE=$(canon_origin "$ZONE_ARG"); then' '    ZONE=$ZONE_ARG; if false; then' \
                  'origin_listed() { case " $RPZ_ORIGINS " in *" $1 "*) return 0 ;; esac; return 1; }' 'origin_listed() { return 0; }'; C=$CTL
: > "$W/A.log"
out=$("$C" --dir "$KDIR" --zone "../rpz.whisper.online" --zone-file "$W/loose.zone" --base "$STUB" 2>&1)
[ -s "$W/A.log" ] && pass "the control: the loose class (any token) sends '../rpz.whisper.online' to the network" \
  || fail "the control: a loose origin must reach the network" "$out"

# ---- 17. an atomic install: a download killed half way ----------------------------------------------
cat > "$W/slow.py" <<'PY'
import http.server, sys, time
body = open(sys.argv[2], "rb").read()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body[: len(body) // 2]); self.wfile.flush()
        time.sleep(60)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
feed $((TOP + 1)) 24.0.2.0.192
i=0; while [ "$i" -lt 400 ]; do printf '%d.0.0.10.rpz-ip.%s.\t300\tIN\tCNAME\t*.\n' "$i" "$O"; i=$((i+1)); done >> "$W/z"
python3 "$W/slow.py" "$KP" "$W/z" & echo $! > "$W/slow.srvpid"
sleep 0.5
sum=$(sha "$ZF")
setsid env WHISPER_EDGE_RNDC="$W/rndc" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-rec.conf" --base "http://127.0.0.1:$KP/edge" >/dev/null 2>&1 &
victim=$!
part=""; i=0
while [ "$i" -lt 50 ]; do
  part=$(find "$ZD" -maxdepth 1 -name '.rpz.zone.new.*' ! -name '*.hdr' ! -name '*.err' ! -name '*.ip' \
    ! -name '*.rc' ! -name '*.sig' ! -name '*.shdr' ! -name '*.msg' -size +0 2>/dev/null | head -1)
  [ -n "$part" ] && break; i=$((i+1)); sleep 0.1
done
# The whole process group, the refresh and its curl. No `--` before the negative pid: dash's kill
# rejects it as "Illegal number".
kill -9 "-$victim" 2>/dev/null; sleep 0.3
dead=yes; kill -0 "$victim" 2>/dev/null && dead=no
full=$(wc -c < "$W/z")
psize=$( [ -n "$part" ] && [ -f "$part" ] && wc -c < "$part" || echo 0)
{ [ "$dead" = yes ] && [ -n "$part" ] && [ "$psize" -gt 0 ] && [ "$psize" -lt "$full" ]; } \
  && pass "the control: the refresh is dead by SIGKILL mid-write ($psize of $full bytes on disk in a temp file)" \
  || fail "the kill interrupted a download" "dead=$dead partial='$part' size=$psize full=$full"
{ [ "$(sha "$ZF")" = "$sum" ] && [ "$(served)" = "$TOP" ]; } \
  && pass "and the zone file is byte-identical, and named still serves serial $TOP" \
  || fail "a killed download leaves the zone alone" "served=$(served)"
# SIGTERM, as systemd sends it at TimeoutStartSec, to the whole group: the run exits and its state is
# saved first (its last_attempt_seconds is this run's), where the SIGKILL above saves nothing.
termrun() {
  set_st last_attempt_seconds 1 "$PROM"; touch "$W/term.mark"; sleep 1
  setsid env WHISPER_EDGE_RNDC="$W/rndc" "${GATE_REFRESH:-$REFRESH}" --rpz --dir "$KDIR" --named-conf "$G/named-rec.conf" --base "http://127.0.0.1:$KP/edge" >/dev/null 2>&1 &
  tv=$!; i=0
  while [ "$i" -lt 50 ] && [ -z "$(find "$ZD" -maxdepth 1 -name '.rpz.zone.new.*' -newer "$W/term.mark" -size +0 2>/dev/null | head -1)" ]; do i=$((i+1)); sleep 0.1; done
  kill -TERM "-$tv" 2>/dev/null; i=0
  while [ "$i" -lt 50 ] && kill -0 "$tv" 2>/dev/null; do i=$((i+1)); sleep 0.1; done
}
termrun
la=$(st last_attempt_seconds)
{ [ "${la:-1}" -gt 1 ] && ! kill -0 "$tv" 2>/dev/null; } \
  && pass "a SIGTERM mid-download (TimeoutStartSec) ends the run and saves its state first (last_attempt_seconds $la)" \
  || fail "a TERM saves the state" "last_attempt=$la alive=$(kill -0 "$tv" 2>/dev/null && echo yes || echo no)"
control term-no-save '  if [ -n "${ST_LOADED:-}" ]; then
    trap '"'"'st_save; exit 130'"'"' INT' '  if false; then
    trap '"'"'st_save; exit 130'"'"' INT'; C=$CTL
GATE_REFRESH=$C termrun
[ "$(st last_attempt_seconds)" = 1 ] && pass "the control: a TERM trap that only exits loses the run's state" \
  || fail "the control: without the save the state must stay as it was" "$(st last_attempt_seconds)"
kill "$(cat "$W/slow.srvpid")" 2>/dev/null
feed $((TOP + 1)) 24.0.2.0.192
run --base "$STUB"
{ [ "$(find "$ZD" -maxdepth 1 -name '.rpz.zone.new.*' | wc -l)" = 0 ] && [ "$(served)" = $((TOP + 1)) ]; } \
  && pass "the next run sweeps the abandoned temp file and installs serial $((TOP + 1))" \
  || fail "the next run cleans up" "left: $(find "$ZD" -maxdepth 1 -name '.rpz.zone.new.*') served=$(served) $out"
TOP=$(served)

# ---- 18. what the configuration says ------------------------------------------------------------------
sum=$(sha "$ZF")
feed $((TOP + 1)) 24.0.2.0.192
sed "s|zone \"$O\" { type master; file \"whisper-edge/rpz.zone\"; };|zone \"$O\" { type secondary; primaries { 127.0.0.1 port 1; }; file \"whisper-edge/rpz.zone\"; };|" \
  "$G/named-rec.conf" > "$G/named-sec.conf"
out=$(WHISPER_EDGE_RNDC="$W/rndc" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-sec.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && [ "$(sha "$ZF")" = "$sum" ] && says "$out" "as a secondary"; } \
  && pass "a zone named loads as a SECONDARY is never written, even with a newer serial on offer" \
  || fail "a secondary's file is left alone" "rc=$rc $out"
run --base "$STUB"
[ "$(served)" = $((TOP + 1)) ] && pass "the control: the same zone as a primary takes serial $((TOP + 1))" \
  || fail "a primary takes the newer serial" "served=$(served) $out"
TOP=$(served)
sed "s|file \"whisper-edge/rpz.zone\";|file \"elsewhere.zone\";|" "$G/named-rec.conf" > "$G/named-other.conf"
out=$(WHISPER_EDGE_RNDC="$W/rndc" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-other.conf" --zone-file "$ZF" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 4 ] && says "$out" "loads zone $O from $G/elsewhere.zone"; } \
  && pass "named loading the zone from a different file is refused with exit 4 and both paths named" \
  || fail "a file mismatch is refused" "rc=$rc $out"
mkdir -p "$G/alt"
sed "s|file \"whisper-edge/rpz.zone\";|file \"alt/policy.zone\";|" "$G/named-rec.conf" > "$G/named-alt.conf"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-alt.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ -s "$G/alt/policy.zone" ] && grep -q "^; generation=$TOP\$" "$G/alt/policy.zone"; } \
  && pass "with no --zone-file, the zone is written to the file named's configuration names ($G/alt/policy.zone)" \
  || fail "the zone file is derived from named's configuration" "rc=$rc $out"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-none.conf" --base "$STUB" 2>&1) && rc=0 || rc=$?
says "$out" "named does not load $ZF" \
  && pass "the control: with no zone statement, the default under named's directory is used and nothing reloaded" \
  || fail "the default zone path applies when named names none" "rc=$rc $out"
# What named ITSELF serves outranks a configuration that says nothing.
mkdir -p "$G/elsewhere"
out=$(WHISPER_EDGE_RNDC="$W/rndc" "$REFRESH" --rpz --quiet --dir "$KDIR" --named-conf "$G/named-none.conf" \
  --zone-file "$G/elsewhere/rpz.zone" --base "$STUB" 2>&1 >/dev/null) && rc=0 || rc=$?
{ [ "$rc" = 4 ] && [ ! -e "$G/elsewhere/rpz.zone" ] && says "$out" "named is serving zone $O from"; } \
  && pass "rndc reporting the zone from another file is an alarm (exit 4, on stderr under --quiet), nothing written" \
  || fail "rndc's file outranks a silent configuration" "rc=$rc $out"
feed $((TOP + 1)) 24.0.2.0.192
run --base "$STUB" --named-conf "$G/named-none.conf" --zone-file "$ZF"
{ [ "$rc" = 0 ] && [ "$(served)" = $((TOP + 1)) ]; } \
  && pass "the control: the same configuration with rndc's own file fetches $((TOP + 1)) and named serves it" \
  || fail "rndc's matching file lets the refresh proceed" "rc=$rc served=$(served) $out"
TOP=$(served)
# A configuration that cannot be READ is not an empty one. chmod 000 stops every reader but root, so
# run as root (the certifying run) the refresh reads named's configuration through a named-checkconf
# that drops to nobody (setpriv), the reading step the row is about: root's own refresh still runs,
# counts and writes its state, and only the read of the locked include is refused, as it is for
# anyone else. Without setpriv a root run cannot build the condition honestly, and says n/a.
CPATH=$PATH; LOCKROW=run
if [ "$(id -u)" = 0 ]; then
  if command -v setpriv >/dev/null 2>&1 && nid=$(id -u nobody 2>/dev/null) && ngid=$(id -g nobody 2>/dev/null); then
    mkdir -p "$W/shim"
    printf '#!/bin/sh\nexec setpriv --reuid=%s --regid=%s --clear-groups %s "$@"\n' "$nid" "$ngid" "$(command -v named-checkconf)" > "$W/shim/named-checkconf"
    chmod 0755 "$W/shim/named-checkconf"; CPATH="$W/shim:$PATH"
  else
    LOCKROW=na
  fi
fi
feed $((TOP + 1)) 24.0.2.0.192
printf 'zone "unrelated.test" { type master; file "x.zone"; };\n' > "$G/locked.conf"
sed "s|zone \"$O\" { type master; file \"whisper-edge/rpz.zone\"; };|zone \"$O\" { type secondary; primaries { 127.0.0.1 port 1; }; file \"whisper-edge/rpz.zone\"; };|" \
  "$G/named-rec.conf" > "$G/named-locked.conf"
printf 'include "%s";\n' "$G/locked.conf" >> "$G/named-locked.conf"
sum=$(sha "$ZF")
out=$(PATH=$CPATH WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-locked.conf" --zone-file "$ZF" --base "$STUB" 2>&1) && rc=0 || rc=$?
{ [ "$rc" = 0 ] && says "$out" "as a secondary" && [ "$(sha "$ZF")" = "$sum" ]; } \
  && pass "the control: with the include readable, the secondary is recognised and left alone$([ "$CPATH" = "$PATH" ] || echo ' (configuration read as nobody)')" \
  || fail "a readable configuration finds the secondary" "rc=$rc $out"
chmod 000 "$G/locked.conf"
if [ "$LOCKROW" = na ]; then
  note "n/a: the unreadable-include row, run as root with no setpriv: chmod 000 does not stop root, and nothing here can drop the read to another uid"
else
  cf=$(st config_failures_total)
  out=$(PATH=$CPATH WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --rpz --quiet --dir "$KDIR" --named-conf "$G/named-locked.conf" --zone-file "$ZF" --base "$STUB" 2>&1 >/dev/null) && rc=0 || rc=$?
  { [ "$rc" = 4 ] && [ "$(sha "$ZF")" = "$sum" ] \
    && says "$out" "could not read named's configuration" && [ "$(st config_failures_total)" = $(( ${cf:-0} + 1 )) ]; } \
    && pass "an unreadable include: exit 4, an alarm on stderr under --quiet, counted, and the zone file untouched$([ "$CPATH" = "$PATH" ] || echo ' (read as nobody, the gate running as root)')" \
    || fail "an unreadable configuration writes nothing" "rc=$rc $out"
fi
chmod 644 "$G/locked.conf"

# ---- 19. RFC 1982: a serial that wraps past 2^32 still advances -------------------------------------
# TOP -> TOP + 2^31 - 1 -> 4294967009 -> 500, each newer under RFC 1982. The first two are content valid
# into this century and the next; 500 is the empty zone, which carries no validUntil, since content at
# serial 500 would be valid until 1970 and is refused as expired.
W1=$(( (TOP + 2147483647) % 4294967296 ))
for s in "$W1" 4294967009; do
  feed "$s" 24.0.2.0.192
  run --base "$STUB"
done
wz "$O" 500 empty > "$W/z"; pub "$W/A" "$W/z" "$O"
run --base "$STUB"
{ [ "$rc" = 0 ] && grep -q '^; state=empty' "$ZF" && grep -q '^; generation=500$' "$ZF" && [ "$(served)" = 500 ]; } \
  && pass "serial arithmetic is RFC 1982: $TOP -> $W1 -> 4294967009 -> 500 each advances and named serves 500" \
  || fail "the serial wraps" "served=$(served) rc=$rc $out"

# ---- 20. a file from before per-zone files keeps its own rule: glue for an in-zone nameserver ---------
mkdir -p "$G/glue"
{
  # shellcheck disable=SC2016  # $TTL is the zone-file directive, written literally
  printf '$TTL 300\n@ IN SOA ns.%s. hostmaster.whisper.online. ( 77 900 300 86400 300 )\n' "$O"
  printf '@ IN NS ns.%s.\nns IN A 192.0.2.53\nns IN AAAA 2001:db8::53\n' "$O"
  printf '24.0.2.0.192.rpz-ip CNAME .\n'
} > "$G/glue/rpz.zone"
printf 'whisper_edge_rpz_last_advance_seconds %s\n' $(( $(date +%s) - 90000 )) > "$G/glue/rpz.zone.prom"
out=$(WHISPER_EDGE_RNDC="$NORNDC" "$REFRESH" --rpz --dir "$KDIR" --named-conf "$G/named-none.conf" --zone-file "$G/glue/rpz.zone" --base "$DEAD" 2>&1) && rc=0 || rc=$?
{ says "$out" "DISARMED" && named-checkzone -q "$O" "$G/glue/rpz.zone" \
  && grep -q '192.0.2.53' "$G/glue/rpz.zone" && ! grep -q 'rpz-ip' "$G/glue/rpz.zone"; } \
  && pass "an installed file with no header (an earlier install) keeps its no-advance rule: emptied with its in-zone glue" \
  || fail "the legacy empty zone carries glue" "rc=$rc $out"
grep -v -E '[[:space:]](A|AAAA)[[:space:]]' "$G/glue/rpz.zone" > "$G/glue/noglue.zone"
named-checkzone -q "$O" "$G/glue/noglue.zone" \
  && fail "the control: without glue the empty zone must not load" "it loaded" \
  || pass "the control: the same empty zone without the glue fails named-checkzone"

# ---- 21. the state file is what a textfile collector can read ------------------------------------------
badl=$(grep -v '^#' "$PROM" | grep -cvE '^whisper_edge_rpz_[a-z_]+\{zone="rpz\.whisper\.online"\} -?[0-9]+$' || true)
{ [ "$badl" = 0 ] && [ -n "$(st reloads_total)" ] && [ -n "$(st refused_total)" ]; } \
  && pass "the state file is valid Prometheus text ($(grep -vc '^#' "$PROM") samples; reloads $(st reloads_total), refused $(st refused_total))" \
  || fail "the state file parses" "$(cat "$PROM")"
# Two zones, one directory: every series of each file carries its own zone label, so a textfile
# collector reading the directory sees two label sets and no duplicate.
dup=$(cat "$PROM" "$ZK.prom" 2>/dev/null | grep -v '^#' | sed 's/ .*//' | sort | uniq -d | wc -l)
{ [ -s "$ZK.prom" ] && [ "$dup" = 0 ] && grep -q "^whisper_edge_rpz_[a-z_]*{zone=\"$OK\"} " "$ZK.prom" \
  && [ "$(grep -v '^#' "$ZK.prom" | grep -cv "{zone=\"$OK\"}")" = 0 ]; } \
  && pass "the two zones' state files carry zone=\"$O\" and zone=\"$OK\" on every series: no series appears twice" \
  || fail "each zone's series is labelled with its zone" "dup=$dup $(head -3 "$ZK.prom" 2>/dev/null)"
# The control: the unlabelled form both files used to write collides on every name they share.
dupc=$(cat "$PROM" "$ZK.prom" 2>/dev/null | grep -v '^#' | sed 's/{[^}]*}//; s/ .*//' | sort | uniq -d | wc -l)
[ "$dupc" -gt 0 ] && pass "the control: with the labels stripped, $dupc series names appear in both files" \
  || fail "the control: unlabelled series must collide" "dupc=$dupc"

# ---- 22. the SHIPPED UNIT, sandbox and all ------------------------------------------------------------
# Everything above runs the script as the gate's user. The timer runs it as root with no capabilities,
# a read-only filesystem but for ReadWritePaths, and named's group for the control key. This runs the
# rendered ExecStart, %i filled in as systemd fills it, under every [Service] property of
# whisper-edge-rpz@.service, through systemd-run, so an edit to the unit that breaks the refresh fails
# here. The control drops SupplementaryGroups, with the control key made named's group 0640 as each
# distribution ships it (bind:bind on Debian and Ubuntu, named:named on the RHEL family): rndc can no
# longer read the key.
# /run/systemd/system is sd_booted(3)'s own test: a systemctl binary on a host whose PID 1 is not systemd
# (a container, a build VM) has no manager for systemd-run to talk to.
# named's own group, by the name this distribution gives it, the one install.sh puts in SupplementaryGroups
NG=""; for _g in bind named; do getent group "$_g" >/dev/null 2>&1 && { NG=$_g; break; }; done
if ! sudo -n true 2>/dev/null || ! command -v systemd-run >/dev/null 2>&1 || [ -z "$NG" ] \
   || [ ! -d /run/systemd/system ]; then
  SKIPS="${SKIPS}the shipped unit under systemd-run (needs passwordless sudo, systemd-run as PID 1 and named's group, bind or named); "
  printf '  SKIP  the shipped unit under systemd-run (needs passwordless sudo, systemd as PID 1, systemd-run and named'"'"'s group, bind or named)\n'
else
  UNIT="$HERE/whisper-edge-rpz@.service"
  sudo -n install -d -o 0 -g 0 -m 0755 "$G/sbin" "$G/keydir"
  sudo -n install -o 0 -g 0 -m 0755 "$REFRESH" "$G/sbin/whisper-edge-refresh"   # ProtectHome hides $HOME
  # under /var/cache/bind the copy is named_cache_t, which systemd may not execute under an enforcing
  # policy (exit 203, no AVC: a dontaudit); label it as the real install's /usr/local/sbin copy is labelled
  if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    sudo -n chcon -t bin_t "$G/sbin/whisper-edge-refresh" \
      || fail "the unit fixture's label" "chcon -t bin_t $G/sbin/whisper-edge-refresh failed, so systemd cannot execute it under this policy"
  fi
  sudo -n install -o 0 -g 0 -m 0644 "$KDIR/edge.pub" "$G/keydir/edge.pub"
  dry=$(WHISPER_EDGE_SBIN="$G/sbin" "$HERE/install.sh" --dry-run --dir "$G/keydir" --base "$STUB" --key-sha256 "$KSHA" --named-conf "$G/named-rec.conf" 2>&1)
  UEXEC=$(printf '%s\n' "$dry" | sed -n 's/.*whisper-edge-rpz@\.service: ExecStart=//p' | sed "s/%i/$O/")
  URW=$(printf '%s\n' "$dry" | sed -n 's/.*whisper-edge-rpz@\.service: ReadWritePaths=//p')
  UGRP=$(printf '%s\n' "$dry" | sed -n 's/.*whisper-edge-rpz@\.service: SupplementaryGroups=//p')
  # A serial of this hour again (the wrap case above left the empty zone at 500, which it is newer than).
  PREV=$(served); UN=$(( $(date +%s) / 3600 * 3600 + 50 ))
  feed "$UN" 24.0.2.0.192
  set_st last_ok_seconds $(( $(date +%s) - 901 ))
  sudo -n chown -R 0:0 "$ZD"
  sudo -n chown "$NG:$NG" "$G/rndc.conf"; sudo -n chmod 0640 "$G/rndc.conf"
  [ "$UGRP" = "$NG" ] || fail "the unit's group is named's" "install.sh renders SupplementaryGroups=$UGRP, but named's group here is $NG"
  unit_run() {  # UNIT_GROUPS = "with" or "without" SupplementaryGroups
    set --
    while IFS= read -r l; do
      case "$l" in ''|'#'*|Type=*|ExecStart=*|TimeoutStartSec=*|ReadWritePaths=*|SupplementaryGroups=*|Description=*) continue ;; esac
      case "$l" in "${UNIT_DROP:-@none@}="*) continue ;; esac
      set -- "$@" -p "$l"
    done <<EOF
$(sed -n '/^\[Service\]/,/^\[/p' "$UNIT" | grep -E '^[A-Za-z]+=')
EOF
    set -- "$@" -p "ReadWritePaths=$URW"
    if [ "$UNIT_GROUPS" = with ]; then set -- "$@" -p "SupplementaryGroups=$UGRP"; fi
    # shellcheck disable=SC2086  # UEXEC is the rendered command line, split as systemd splits it
    sudo -n systemd-run --quiet --wait --pipe --collect "$@" \
      -E "WHISPER_EDGE_RNDC=rndc -c $G/rndc.conf" $UEXEC 2>&1
  }
  UNIT_GROUPS=without; uout=$(unit_run) && urc=0 || urc=$?
  { [ "$urc" != 0 ] && [ "$(served)" = "$PREV" ] && says "$uout" "did NOT load serial $UN"; } \
    && pass "the control: the unit WITHOUT SupplementaryGroups cannot read the control key; named stays at $PREV, the unit fails" \
    || fail "the unit needs named's group" "rc=$urc served=$(served) $uout"
  UNIT_GROUPS=with; uout=$(unit_run) && urc=0 || urc=$?
  UOK=$urc; UOUT=$uout
  # The RPKI instance, its zone not published and nothing installed: the unit's own ExecStart and
  # SuccessExitStatus. It succeeds and says so once; without SuccessExitStatus=5 it is a failed unit.
  rm -f "$W/A/edge/rpz/$OK.zone"; sudo -n rm -f "$ZK" "$ZK.prom"
  UEXEC_K=$(printf '%s\n' "$dry" | sed -n 's/.*whisper-edge-rpz@\.service: ExecStart=//p' | sed "s/%i/$OK/")
  UEXEC_O=$UEXEC; UEXEC=$UEXEC_K
  uout=$(unit_run) && urc=0 || urc=$?
  { [ "$urc" = 0 ] && says "$uout" "zone $OK is not published yet"; } \
    && pass "the shipped unit, instance $OK, a 404 with nothing installed: the unit succeeds and the journal has one line" \
    || fail "a zone not published yet is a successful unit" "rc=$urc $uout"
  sudo -n rm -f "$ZK.prom"
  UNIT_DROP=SuccessExitStatus; uout=$(unit_run) && urc=0 || urc=$?; UNIT_DROP=""
  [ "$urc" = 5 ] && pass "the control: the same unit without SuccessExitStatus=5 fails with status 5" \
    || fail "the control: without SuccessExitStatus the unit must fail" "rc=$urc $uout"
  UEXEC=$UEXEC_O; urc=$UOK; uout=$UOUT
  { [ "$urc" = 0 ] && [ "$(served)" = "$UN" ] && says "$uout" "reloaded zone $O, serial $UN (named confirms)"; } \
    && pass "the shipped unit, instance $O, every sandbox property applied, root with no capabilities: named serves $UN" \
    || fail "the shipped unit refreshes the zone" "rc=$urc served=$(served) $uout"
fi

[ "$CTL_OK" = 1 ] || fail "every control patched exactly what it names" "see the control failures above"
printf '  --- real BIND: %d ok, %d failed\n' "$ok" "$bad"
[ "$bad" = 0 ] || exit 1
[ -z "$SKIPS" ] || { printf '  NOT PROVEN: %s\n' "$SKIPS"; exit 77; }
exit 0
