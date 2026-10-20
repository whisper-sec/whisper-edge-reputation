#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# rpz-gate.sh - load each policy zone into a REAL BIND and query it, one zone at a time.
#
#   ./rpz/rpz-gate.sh                          every zone's checked-in fixture, plus the never-published case
#   ./rpz/rpz-gate.sh --zone <origin>          one zone's fixture
#   RPZ_BODY=<zone file> RPZ_PROBES=<probes> RPZ_PLANE=<plane.bin> ./rpz/rpz-gate.sh --zone <origin>
#                                              a zone from a live build, held to the plane it was written from
#   RPZ_ABSENT=1 ./rpz/rpz-gate.sh --zone <origin>
#                                              the zone is expected NOT to be published: no file may exist
#
# The README tells an operator their whole integration is a zone statement and a response-policy line.
# That is a claim about somebody else's software, so it is proved against that software rather than
# against our own reading of the RPZ specification.
#
# RPZ APPLIES DURING RECURSION, not to authoritative answers, so a single named serving the test names
# locally would answer from its own zone and never consult the policy: the test would pass while
# proving nothing. Hence an authoritative instance for example.test and recursive instances carrying the
# policy and forwarding to it. rpz-nsip is the exception: it judges the address of a NAMESERVER, which a
# forwarding resolver never looks up, so it is proved by a resolver that really recurses, from a local
# root, in a network namespace of its own (that part needs passwordless sudo; without it the gate says
# so and exits 77, never CLEAR).
#
# Per zone, each check beside the control that must fail it:
#   the header is the published one (v=wedge-rpz1, the origin, the state, the generation, every line at
#     most 255 bytes) [a 256-byte header line];
#   the SOA serial equals the header's generation [an SOA serial one higher];
#   a content zone's validUntil is its serial's slot start plus EXPIRE, EXPIRE at most 86400 [EXPIRE
#     1,418 s late];
#   the header's trigger count is the zone's [one more in the header];
#   BIND loads the file verbatim, logs no dropped trigger and accepts the file's count [a trigger whose
#     owner names bits below its prefix];
#   NODATA on the listed family, an answer on the other, boundary probes either side of every range
#     [the same zone with CNAME . answers NXDOMAIN, which the NODATA check refuses];
#   with the policy removed, every blocked name resolves;
#   the zone equals the plane at every breakpoint (plane_check --rpz-oracle) [a trigger dropped];
#   rpz-nsip answers NXDOMAIN for a name delegated into a listed nameserver address, through a resolver
#     that recurses from the root [the same resolver without the policy answers it];
#   expired, the zone is the empty zone at max(slotStart(validUntil), serial + 1), byte for byte, and
#     BIND serves it with no trigger [the expired serial plus one, the old disarm's rule].
# And a zone never published: no file, said so, and a file where none may be is refused.
#
# Every check reads `condition && ok ... || bad ...`, an if/else only because ok and bad cannot fail
# (each prints, and bad sets a variable). And `$TTL` in a single-quoted printf is the zone-file
# directive, written literally.
# shellcheck disable=SC2015,SC2016
set -euo pipefail

cd "$(dirname "$0")/.."            # the edge directory: the work directory default and core/ hang off it
FIX="${WHISPER_EDGE_RPZ_FIXTURE:-./rpz/testdata}"
ORIGINS="rpz.whisper.online rpz-rpki-unreachable.whisper.online"
SLOT=3600
MAX_EXPIRE=86400

usage() { sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; }

#
# THE ORIGIN, CHECKED BEFORE ANYTHING RUNS. LDH labels (RFC 5890: letters, digits, hyphen, no hyphen at
# either end, 63 octets a label, 253 in all), lower-cased in the C locale so no ambient locale folds a
# letter differently, one trailing dot removed, and then it must be a zone we publish.
#
canon_origin() {
    local o
    o=$(LC_ALL=C printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]')
    o=${o%.}
    if [ -z "$o" ] || [ "${#o}" -gt 253 ] \
       || ! LC_ALL=C grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' <<<"$o"; then
        echo "RPZ GATE: FAILED - '$1' is not a zone name (letters, digits and inner hyphens, dot-separated)" >&2
        return 2
    fi
    case " $ORIGINS " in
        *" $o "*) printf '%s\n' "$o" ;;
        *) echo "RPZ GATE: FAILED - $o is not a zone this feed publishes; the published zones are: $ORIGINS" >&2
           return 2 ;;
    esac
}

ZONES=""
POS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --zone) [ $# -ge 2 ] || { echo "RPZ GATE: FAILED - --zone needs a zone name" >&2; exit 2; }
                z=$(canon_origin "$2") || exit 2
                ZONES="$ZONES $z"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "RPZ GATE: FAILED - unknown option $1" >&2; exit 2 ;;
        *) POS="$1" ;;
    esac
    shift
done
LIVE=0
if [ -n "${RPZ_BODY:-}" ] || [ -n "${RPZ_PROBES:-}" ] || [ -n "${RPZ_ABSENT:-}" ]; then
    LIVE=1
    read -r -a ZA <<<"$ZONES"
    if [ "${#ZA[@]}" -ne 1 ]; then
        echo "RPZ GATE: FAILED - RPZ_BODY, RPZ_PROBES and RPZ_ABSENT name ONE zone: pass exactly one --zone" >&2
        exit 2
    fi
fi
[ -n "$ZONES" ] || ZONES=" $ORIGINS"
# RPZ_ABSENT needs no BIND: the answer is whether a file exists, and it is given before anything runs.
if [ "$LIVE" = 1 ] && [ -n "${RPZ_ABSENT:-}" ]; then
    if [ -e "${RPZ_BODY:-/nonexistent}" ]; then echo "RPZ GATE: FAILED -$ZONES is published: a file exists at $RPZ_BODY"; exit 1; fi
    echo "RPZ GATE: CLEAR -$ZONES is not published: no file at ${RPZ_BODY:-<none>}, as expected"; exit 0
fi
# A live run with no zone file is refused here, before anything is created: asked to certify a file
# that is not there, the gate fails, and RPZ_ABSENT=1 is how a run says absence is the expectation.
if [ "$LIVE" = 1 ] && [ -z "${RPZ_ABSENT:-}" ]; then
    [ -f "${RPZ_BODY:-}" ] || { echo "RPZ GATE: FAILED - no zone file at '${RPZ_BODY:-}' (RPZ_ABSENT=1 says a zone is expected not to exist)"; exit 1; }
    [ -f "${RPZ_PROBES:-}" ] || { echo "RPZ GATE: FAILED - RPZ_PROBES names no probe file"; exit 1; }
fi

#
# WHERE THE WORK LIVES IS NOT A FREE CHOICE on a distro that confines named.
#
# Ubuntu ships an AppArmor profile for named in enforce mode. It grants "/var/cache/bind/** lrw" and
# "/etc/bind/** r" and nothing else, so named started from a checkout under $HOME dies reading its own
# config, with an EMPTY log, because it never gets far enough to open one. So: probe for a directory this
# machine's named can actually read from, preferring the checkout and falling back to /var/cache/bind.
# PROBE rather than detect, because "is AppArmor enforcing for named" has a different answer on every
# distro and the question we care about is only ever "can named read a config from here".
#
# And VALIDATE THE WORK DIRECTORY BEFORE TOUCHING IT: this script deletes files there and reaches for
# sudo, so a typo in its argument must not be able to name /.
#
require_safe_workdir() {
    case "$1" in
        "$PWD"/*|"$PWD") return 0 ;;
        /var/cache/bind/whisper-rpz-gate*) return 0 ;;
    esac
    echo "RPZ GATE: FAILED - refusing to use '$1' as a work directory."
    echo "  This script creates and deletes files there, so it must be inside the checkout or under"
    echo "  /var/cache/bind/whisper-rpz-gate. Pass one of those, or no argument at all."
    return 1
}
if [ -n "$POS" ]; then
    require_safe_workdir "$(cd "$(dirname "$POS")" 2>/dev/null && pwd)/$(basename "$POS")" \
        || require_safe_workdir "$POS" || exit 1
fi

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

probe_workdir() {
    local dir=$1 port
    port=$(free_port)
    mkdir -p "$dir" 2>/dev/null || return 1
    cat > "$dir/probe.conf" <<PEOF
options {
    directory "$dir"; pid-file "$dir/probe.pid";
    listen-on port $port { 127.0.0.1; }; listen-on-v6 { none; };
    recursion no; allow-query { 127.0.0.1; }; dnssec-validation no;
    managed-keys-directory "$dir"; session-keyfile "$dir/probe.session.key";
};
PEOF
    named -c "$dir/probe.conf" -f >/dev/null 2>&1 &
    local pid=$! ok=1
    for _ in $(seq 1 20); do
        if dig +short +time=1 +tries=1 -p "$port" @127.0.0.1 . SOA >/dev/null 2>&1 && kill -0 "$pid" 2>/dev/null; then
            ok=0; break
        fi
        sleep 0.25
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$dir/probe.conf" "$dir/probe.pid" "$dir/probe.session.key"
    return $ok
}

for t in named named-checkzone named-checkconf dig python3; do
    command -v "$t" >/dev/null || { echo "RPZ GATE: FAILED - $t is not installed"; exit 1; }
done

WORK=""
for candidate in "${POS:-$PWD/core/.testtmp/rpz}" /var/cache/bind/whisper-rpz-gate; do
    if [ "$candidate" = /var/cache/bind/whisper-rpz-gate ]; then
        [ -d /var/cache/bind ] || continue
        if [ ! -w /var/cache/bind ] && [ ! -w "$candidate" ]; then
            sudo -n mkdir -p "$candidate" 2>/dev/null && sudo -n chown "$(id -u):$(id -g)" "$candidate" 2>/dev/null || continue
        fi
    fi
    if probe_workdir "$candidate"; then
        WORK="$candidate"
        [ "$candidate" = /var/cache/bind/whisper-rpz-gate ] \
            && echo "note: named cannot read a config from the checkout on this machine (AppArmor);" \
            && echo "      using $candidate, which its profile permits"
        break
    fi
done
if [ -z "$WORK" ]; then
    echo "RPZ GATE: FAILED - no directory on this machine that named will read a config from."
    sudo -n dmesg 2>/dev/null | grep -i 'apparmor.*named' | tail -3 || echo "  (dmesg not readable)"
    exit 1
fi
require_safe_workdir "$WORK" || exit 1
WORK=$(cd "$WORK" && pwd)
# Only the subdirectory this run owns is cleared, by name, never the work directory's other contents.
RUN="$WORK/run"
rm -rf "${RUN:?}"
mkdir -p "$RUN"
echo "work directory: $RUN"

PIDS=()
cleanup() {
    local p
    for p in "${PIDS[@]}"; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done
    sleep 0.5
    for p in "${PIDS[@]}"; do [ -f "$p" ] && kill -9 "$(cat "$p")" 2>/dev/null || true; done
    return 0
}
trap cleanup EXIT

fail=0
skipped=""
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; fail=1; }

# ==== the published format, read and rendered in one place ============================================
#
# A zone file is a pure function of one manifest entry: its comment header, one `; key=value` line each
# in a fixed order, then $TTL 300, the SOA and the two NS with no TTL field, then the triggers.
# testdata/README.md writes the contract down; this is its reader and its reference renderer.

# The leading `;` block, verbatim.
header_of() { awk '/^;/ { print; next } { exit }' "$1"; }
hdr() { header_of "$1" | sed -n "s/^; $2=//p" | sed -n 1p; }
has_header() { [ "$(head -1 "$1")" = "; v=wedge-rpz1" ]; }

# Every header line in the published order, each at most 255 bytes. Prints the first fault.
header_check() { # <file> <origin>
    local f=$1 o=$2 state n i line
    local -a want
    if ! has_header "$f"; then echo "the first line is not '; v=wedge-rpz1'"; return 1; fi
    while IFS= read -r line; do
        if [ "$(printf '%s' "$line" | wc -c)" -gt 255 ]; then echo "a header line is over 255 bytes"; return 1; fi
    done < <(header_of "$f")
    state=$(hdr "$f" state)
    case "$state" in
        content) want=(v origin state generation validUntil triggers) ;;
        empty)   want=(v origin state generation) ;;
        *) echo "state is '$state', neither content nor empty"; return 1 ;;
    esac
    n=0
    while IFS= read -r line; do
        i=${line#; }; i=${i%%=*}
        if [ "$n" -lt "${#want[@]}" ]; then
            [ "$i" = "${want[$n]}" ] || { echo "header line $((n + 1)) is '$i', the format says '${want[$n]}'"; return 1; }
        elif [ "$state" = content ] && [ "$i" = sources ] && [ "$n" -lt $(( ${#want[@]} + 16 )) ]; then
            :
        else
            echo "an unexpected header line '$i' (line $((n + 1)))"; return 1
        fi
        n=$((n + 1))
    done < <(header_of "$f")
    [ "$n" -ge "${#want[@]}" ] || { echo "the header has $n lines, a $state zone has ${#want[@]}"; return 1; }
    [ "$(hdr "$f" origin)" = "$o" ] || { echo "origin=$(hdr "$f" origin), the zone is $o"; return 1; }
    grep -Eq '^[0-9]{1,10}$' <<<"$(hdr "$f" generation)" || { echo "generation is not a serial"; return 1; }
    if [ "$state" = content ]; then
        grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' <<<"$(hdr "$f" validUntil)" \
            || { echo "validUntil is not RFC 3339 UTC to the second"; return 1; }
        grep -Eq '^[0-9]{1,6}$' <<<"$(hdr "$f" triggers)" || { echo "triggers is not a count"; return 1; }
    fi
    return 0
}

epoch_of() { date -u -d "$1" +%s; }
slot_start() { echo $(( $1 / SLOT * SLOT )); }
# Content EXPIRE: the validity left at the serial's slot start, never more than a day.
expire_of() { # <serial> <validUntil seconds>
    local e=$(( $2 - $(slot_start "$1") ))
    [ "$e" -le "$MAX_EXPIRE" ] || e=$MAX_EXPIRE
    echo "$e"
}
# The sweep serial: the validity's slot start, or one past the serial if that is not newer.
sweep_of() { # <serial> <validUntil seconds>
    local s v
    s=$(slot_start "$2"); v=$(( $1 + 1 ))
    [ "$s" -gt "$v" ] && echo "$s" || echo "$v"
}

apex() { # <origin> <serial> <expire>
    printf '$TTL 300\n'
    printf '%s.\tIN\tSOA\tns1.whisper.online. hostmaster.whisper.online. ( %s 900 300 %s 300 )\n' "$1" "$2" "$3"
    printf '%s.\tIN\tNS\t%s\n' "$1" ns1.whisper.online. "$1" ns2.whisper.online.
}
# A checked-in body (the header and the triggers) to the file the feed would serve.
render() { # <body> <out>
    local g v
    g=$(hdr "$1" generation); v=$(epoch_of "$(hdr "$1" validUntil)")
    { header_of "$1"; apex "$(hdr "$1" origin)" "$g" "$(expire_of "$g" "$v")"; awk '!/^;/' "$1"; } > "$2"
}
# The empty zone: a function of (origin, serial) and of nothing else.
render_empty() { # <origin> <serial>
    printf '; v=wedge-rpz1\n; origin=%s\n; state=empty\n; generation=%s\n' "$1" "$2"
    apex "$1" "$2" "$MAX_EXPIRE"
}

# BIND's own reading of the file: the SOA's numbers, and the records that are not the apex.
soa_of() { named-checkzone -D -o - "$1" "$2" 2>/dev/null | awk -v a="$1." 'tolower($1) == a && $4 == "SOA" && !seen++ { print $7, $8, $9, $10, $11 }'; }
nonapex_of() { named-checkzone -D -o - "$1" "$2" 2>/dev/null | awk -v a="$1." 'tolower($1) != a' | grep -c . || true; }
triggers_in() { grep -cE '\.rpz-(ip|nsip)\.' "$1" || true; }

# ==== named instances ===================================================================================
start_named() { # <conf> <pidfile> <port>
    named-checkconf "$1"
    named -c "$1" -d 3 -f > "$1.out" 2>&1 &
    PIDS+=("$2")
}
wait_up() { # <port>
    local i
    for i in $(seq 1 60); do
        grep -q 127.0.0.1 <<<"$(dig +short +time=1 +tries=1 -p "$1" @127.0.0.1 ns.example.test A 2>/dev/null)" && return 0
        sleep 0.25
    done
    return 1
}
# A recursive resolver forwarding to the authoritative instance, with or without a policy zone.
rec_conf() { # <name> <port> <auth port> <origin or ""> <zone file or "">
    local n=$1
    {
        cat <<EOF
options {
    directory "$RUN"; pid-file "$RUN/$n.pid";
    listen-on port $2 { 127.0.0.1; }; listen-on-v6 { none; };
    recursion yes; allow-query { 127.0.0.1; }; allow-recursion { 127.0.0.1; };
    dnssec-validation no; qname-minimization off;
    forward only; forwarders { 127.0.0.1 port $3; };
    managed-keys-directory "$RUN/$n.mk"; session-keyfile "$RUN/$n.session.key";
EOF
        [ -z "$4" ] || printf '    response-policy { zone "%s"; } qname-wait-recurse no;\n' "$4"
        printf '};\ncontrols { };\n'
        [ -z "$4" ] || printf 'zone "%s" { type primary; file "%s"; };\n' "$4" "$5"
        # An explicit logging stanza: named -f logs to syslog, so without one the BIND-said-so check
        # reads an empty file and, as this check first shipped, prints ok.
        cat <<EOF
logging {
    channel gate { file "$RUN/$n.log" versions 1 size 50m; severity dynamic; print-category yes; print-severity yes; };
    category default { gate; }; category general { gate; }; category rpz { gate; };
    category zoneload { gate; }; category config { gate; };
};
EOF
    } > "$RUN/$n.conf"
    mkdir -p "$RUN/$n.mk"
}

# READ BIND'S OWN LOG. BIND reports owner-name problems to the log and nowhere else: a non-canonical or
# invalid rpz-ip name is logged, the record is DROPPED, and the zone load still reports success. So the
# probes alone are compatible with an arbitrary fraction of the policy being dead, and it was: the IPv6
# encoder was once wrong on 12.5% of prefixes while the probes passed. The accepted count is held to the
# file's own count of policy nodes too. BIND 9.18 prints no accepted count: at debug level 3 it logs one
# "adding node <owner>" line per node of the policy zone as it builds the policy, BEFORE judging the
# owner, and a refused owner is then a warning ("invalid rpz IP address ..."). So the two halves are:
# every trigger reached BIND's policy build (distinct node owners below the apex equal the file's
# triggers; the resolvers run at -d 3 for it), and BIND refused none of them (no warning). An earlier
# version read a "processing N" line BIND 9.18 never prints and skipped the comparison when the line was
# absent, so its count passed on every run.
bind_accepted() { # <log> <zone file> <origin> -> prints the count or the fault
    local log=$1 body=$2 origin=$3 bad want got
    [ -s "$log" ] || { echo "BIND's log at $log is empty, so this check proves nothing"; return 1; }
    bad=$(grep -iE 'invalid rpz|is not the canonical|rpz .*failed|not loaded due to errors|multiple RRs of singleton' "$log" || true)
    [ -z "$bad" ] || { echo "BIND rejected or dropped records: $(head -1 <<<"$bad")"; return 1; }
    grep -q "rpz: $origin: reload done: success" "$log" || { echo "BIND never reported the policy zone loaded"; return 1; }
    want=$(triggers_in "$body")
    got=$(sed -n "s/.*rpz: $origin: adding node //p" "$log" | LC_ALL=C tr '[:upper:]' '[:lower:]' | grep -vxF "$origin" | sort -u | grep -c . || true)
    [ "$got" = "$want" ] || { echo "BIND's policy build reached $got of the file's $want triggers"; return 1; }
    echo "$want"
}

# One query: "<rcode> <answer count> <answers...>".
ask() { # <port> <name> <type>
    local out rcode ans
    out=$(dig +time=2 +tries=1 -p "$1" @127.0.0.1 "$2" "$3" 2>/dev/null || true)
    rcode=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out" | sed -n 1p)
    ans=$(awk -v t="$3" '/^;; ANSWER SECTION/ { f = 1; next } /^$/ { f = 0 } f && $4 == t { print $NF }' <<<"$out" | tr '\n' ' ')
    printf '%s %s\n' "${rcode:-NONE}" "${ans% }"
}
# A blocked answer: NODATA (NOERROR, nothing of the type) for a published zone, whose rpz-ip action is
# CNAME *.; NXDOMAIN for a file without the header, the legacy feed's CNAME . action.
is_blocked() { # <"rcode answers"> <mode: nodata|nxdomain>
    case "$2:$1" in
        nodata:"NOERROR ") return 0 ;;
        nxdomain:NXDOMAIN*) return 0 ;;
    esac
    return 1
}

# ==== probes from a plane's ranges ======================================================================
# Every range's first and last address and one address either side, each with the outcome the RANGES
# say (never the zone): blocked when an enforced range holds it. Each name also carries a record of the
# other family at an address nothing lists, which must keep answering.
probes_from_ranges() { # <ranges file> <out>
    python3 - "$1" > "$2" <<'PY'
import ipaddress, sys
ranges = []
for line in open(sys.argv[1]):
    f = line.split()
    if not f or f[0].startswith("#"):
        continue
    fam, first, last = f[0], ipaddress.ip_address(f[1]), ipaddress.ip_address(f[2])
    sev = int(f[3]) if len(f) > 3 else 1
    ranges.append((fam, first, last, sev > 0))
def enforced(a):
    return any(r[3] and r[1] <= a <= r[2] for r in ranges if r[1].version == a.version)
seen, n = set(), 0
for fam, first, last, _ in ranges:
    top = (1 << (32 if fam == "4" else 128)) - 1
    for v in (int(first) - 1, int(first), int(last), int(last) + 1):
        if v < 0 or v > top or (fam, v) in seen:
            continue
        seen.add((fam, v))
        a = ipaddress.ip_address(v)
        lab = "p%d" % n
        n += 1
        t, ot, oa = ("A", "AAAA", "2001:db8:ffff::1") if fam == "4" else ("AAAA", "A", "203.0.113.250")
        print(lab, t, a, "block" if enforced(a) else "allow", "the range %s-%s" % (first, last))
        print(lab, ot, oa, "allow", "the other family, listed nowhere")
PY
}

# The authoritative example.test from a probe file: "<label> <type> <address> <block|allow> <description>".
auth_up() { # <probes> <port>
    {
        printf '$TTL 300\n@ IN SOA ns.example.test. hostmaster.example.test. ( 1 3600 600 86400 300 )\n'
        printf '@ IN NS ns.example.test.\nns IN A 127.0.0.1\n'
        local label type addr expect desc
        while read -r label type addr expect desc; do
            case "$label" in ''|'#'*) continue ;; esac
            printf '%s IN %s %s\n' "$label" "$type" "$addr"
        done < "$1"
    } > "$RUN/example.test.zone"
    named-checkzone -q example.test "$RUN/example.test.zone" || { named-checkzone example.test "$RUN/example.test.zone"; return 1; }
    cat > "$RUN/auth.conf" <<EOF
options {
    directory "$RUN"; pid-file "$RUN/auth.pid";
    listen-on port $2 { 127.0.0.1; }; listen-on-v6 { none; };
    recursion no; allow-query { 127.0.0.1; }; dnssec-validation no;
    managed-keys-directory "$RUN"; session-keyfile "$RUN/auth.session.key";
};
controls { };
zone "example.test" { type primary; file "$RUN/example.test.zone"; };
EOF
    start_named "$RUN/auth.conf" "$RUN/auth.pid" "$2"
}

# The plane a fixture's ranges describe, written by the independent writer (make-test-snapshot.py), for
# the oracle: format 1 with each range's severity for the reputation zone, format 2 for the others.
plane_from_ranges() { # <origin> <ranges> <out>
    python3 - "$PWD/core/make-test-snapshot.py" "$1" "$2" "$3" <<'PY'
import importlib.util, ipaddress, os, sys
spec = importlib.util.spec_from_file_location("mts", sys.argv[1]); mts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mts)
plane = "reputation" if sys.argv[2] == "rpz.whisper.online" else "rpki-unreachable"
fmt = 1 if plane == "reputation" else 2
ranges, sev = {4: [], 6: []}, {4: [], 6: []}
for line in open(sys.argv[3]):
    f = line.split()
    if not f or f[0].startswith("#"):
        continue
    fam = int(f[0]); kb = mts.key_bytes(plane, fmt, fam); shift = 8 * ((16 if fam == 6 else 4) - kb)
    ranges[fam].append((int(ipaddress.ip_address(f[1])) >> shift, int(ipaddress.ip_address(f[2])) >> shift))
    sev[fam].append(int(f[3]) if len(f) > 3 else 1)
kinds = {4: ("radix", 16), 6: ("radix", 16)} if fmt == 1 else {4: ("radix", 16), 6: ("none", None)}
mts.write_plane(sys.argv[4], plane, fmt, fmt == 1, kinds, ranges, records=sev if fmt == 1 else None)
os.chmod(sys.argv[4], 0o644)
PY
}

PLANE_CHECK=""
need_plane_check() {
    [ -z "$PLANE_CHECK" ] || return 0
    command -v cc >/dev/null || { echo "RPZ GATE: FAILED - a C compiler is needed to build core/plane_check for the oracle"; exit 1; }
    make -s -C core plane_check >/dev/null || { echo "RPZ GATE: FAILED - core/plane_check did not build"; exit 1; }
    PLANE_CHECK="$PWD/core/plane_check"
}

# ==== rpz-nsip, through a resolver that really recurses =================================================
# A network namespace of its own, so every server listens on port 53 at the address the delegation
# names, as on the internet: a root on 127.0.0.2, a child zone delegated to a nameserver INSIDE the
# first listed nameserver prefix (its first address plus 53), another delegated to an address nothing
# lists, and two resolvers recursing from the root, one with the policy and one without. named runs as
# the invoking user (-u), so nothing it writes is root's.
nsip_check() { # <origin> <zone file>
    local origin=$1 zf=$2 owner badns d u out
    owner=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.rpz-nsip\.' "$zf" | head -1 || true)
    if [ -z "$owner" ]; then
        ok "rpz-nsip: the zone carries no IPv4 nameserver trigger, nothing to prove"
        return 0
    fi
    badns=$(awk -F. '{ print $5 "." $4 "." $3 "." ($2 + 53) }' <<<"$owner")
    if ! sudo -n true 2>/dev/null || ! command -v unshare >/dev/null; then
        skipped="$skipped rpz-nsip($origin)"
        printf '  SKIP  rpz-nsip needs passwordless sudo and unshare for a network namespace; not proved here\n'
        return 0
    fi
    d="$RUN/nsip"; u=$(id -un)
    mkdir -p "$d"
    printf '$TTL 300\n. IN SOA a.root. h.root. ( 1 3600 600 86400 300 )\n. IN NS a.root.\na.root. IN A 127.0.0.2\n' > "$d/root.zone"
    printf 'nsbad.test. IN NS ns.nsbad.test.\nns.nsbad.test. IN A %s\nnsgood.test. IN NS ns.nsgood.test.\nns.nsgood.test. IN A 203.0.113.53\n' "$badns" >> "$d/root.zone"
    printf '. 3600000 NS a.root.\na.root. 3600000 A 127.0.0.2\n' > "$d/hints"
    local z a
    for z in nsbad nsgood; do
        a=$([ "$z" = nsbad ] && echo "$badns" || echo 203.0.113.53)
        printf '$TTL 300\n@ IN SOA ns h ( 1 3600 600 86400 300 )\n@ IN NS ns\nns IN A %s\nwww IN A 203.0.113.7\n' "$a" > "$d/$z.zone"
    done
    local common="listen-on-v6 { none; }; dnssec-validation no; managed-keys-directory \"$d\";"
    printf 'options { directory "%s"; pid-file "%s/root.pid"; listen-on { 127.0.0.2; }; recursion no; session-keyfile "%s/r.key"; %s };\ncontrols { };\nzone "." { type primary; file "%s/root.zone"; };\n' "$d" "$d" "$d" "$common" "$d" > "$d/root.conf"
    printf 'options { directory "%s"; pid-file "%s/kids.pid"; listen-on { %s; 203.0.113.53; }; recursion no; session-keyfile "%s/k.key"; %s };\ncontrols { };\nzone "nsbad.test" { type primary; file "%s/nsbad.zone"; };\nzone "nsgood.test" { type primary; file "%s/nsgood.zone"; };\n' "$d" "$d" "$badns" "$d" "$common" "$d" "$d" > "$d/kids.conf"
    printf 'options { directory "%s"; pid-file "%s/pol.pid"; listen-on { 127.0.0.1; }; recursion yes; allow-recursion { 127.0.0.0/8; }; session-keyfile "%s/p.key"; %s response-policy { zone "%s"; }; };\ncontrols { };\nzone "." { type hint; file "%s/hints"; };\nzone "%s" { type primary; file "%s"; };\n' "$d" "$d" "$d" "$common" "$origin" "$d" "$origin" "$zf" > "$d/pol.conf"
    printf 'options { directory "%s"; pid-file "%s/nopol.pid"; listen-on { 127.0.0.3; }; recursion yes; allow-recursion { 127.0.0.0/8; }; session-keyfile "%s/n.key"; %s };\ncontrols { };\nzone "." { type hint; file "%s/hints"; };\n' "$d" "$d" "$d" "$common" "$d" > "$d/nopol.conf"
    for z in root kids pol nopol; do named-checkconf "$d/$z.conf"; done
    out=$(sudo -n unshare -n bash -c '
        d=$1; u=$2; badns=$3
        trap '"'"'for c in root kids pol nopol; do [ -f "$d/$c.pid" ] && kill "$(cat "$d/$c.pid")" 2>/dev/null; done; sleep 0.5'"'"' EXIT
        ip link set lo up && ip addr add 127.0.0.2/8 dev lo && ip addr add 127.0.0.3/8 dev lo \
          && ip addr add "$badns/32" dev lo && ip addr add 203.0.113.53/32 dev lo || exit 3
        for c in root kids pol nopol; do named -u "$u" -c "$d/$c.conf" || exit 4; done
        for i in $(seq 1 40); do
            dig +short +time=1 +tries=1 @127.0.0.3 www.nsgood.test A 2>/dev/null | grep -q 203.0.113.7 && break
            sleep 0.25
        done
        q() { dig +time=3 +tries=1 @"$1" "$2" A 2>/dev/null | sed -n "s/.*status: \([A-Z]*\).*/\1/p" | head -1; }
        echo "policy-bad $(q 127.0.0.1 www.nsbad.test)"
        echo "policy-good $(q 127.0.0.1 www.nsgood.test)"
        echo "nopolicy-bad $(q 127.0.0.3 www.nsbad.test)"
    ' nsip "$d" "$u" "$badns" 2>&1) || true
    local pb pg nb
    pb=$(sed -n 's/^policy-bad //p' <<<"$out"); pg=$(sed -n 's/^policy-good //p' <<<"$out"); nb=$(sed -n 's/^nopolicy-bad //p' <<<"$out")
    if [ "$nb" = NOERROR ]; then
        ok "the control: without the policy, www.nsbad.test (delegated to $badns) resolves through a recursion from the root"
    else
        bad "the nameserver-trigger control resolver resolves www.nsbad.test" "got '${nb:-nothing}': $(tail -2 <<<"$out")"
    fi
    if [ "$pb" = NXDOMAIN ] && [ "$pg" = NOERROR ]; then
        ok "rpz-nsip: www.nsbad.test, whose nameserver $badns is in ${owner%.rpz-nsip.}, is NXDOMAIN; www.nsgood.test still resolves"
    else
        bad "rpz-nsip answers NXDOMAIN for a name delegated into a listed nameserver address" "listed '$pb', clean '$pg'"
    fi
}

# ==== one zone ==========================================================================================
run_zone() { # <origin> <zone file as served> <probes> <plane or "">
    local origin=$1 zf=$2 probes=$3 plane=$4 mode serial gen soa msg n acc
    echo
    echo "==== $origin ($zf)"
    named-checkzone "$origin" "$zf" || { bad "named-checkzone loads $origin"; return 0; }
    soa=$(soa_of "$origin" "$zf"); serial=${soa%% *}
    if has_header "$zf"; then
        mode=nodata
        if msg=$(header_check "$zf" "$origin"); then ok "the header is the published one (v=wedge-rpz1, $origin, state=$(hdr "$zf" state))"
        else bad "the header is the published one" "$msg"; fi
        gen=$(hdr "$zf" generation)
        [ "$serial" = "$gen" ] && ok "the SOA serial $serial is the header's generation" \
            || bad "the SOA serial is the header's generation" "SOA $serial, generation $gen"
        if [ "$(hdr "$zf" state)" = content ]; then
            local vu ex
            vu=$(epoch_of "$(hdr "$zf" validUntil)"); ex=$(awk '{ print $4 }' <<<"$soa")
            if [ "$ex" -le "$MAX_EXPIRE" ] && [ "$vu" = $(( $(slot_start "$serial") + ex )) ]; then
                ok "validUntil $(hdr "$zf" validUntil) is the serial's slot start plus EXPIRE $ex"
            else
                bad "validUntil is the serial's slot start plus EXPIRE, at most $MAX_EXPIRE" "validUntil $vu, slot $(slot_start "$serial"), EXPIRE $ex"
            fi
            n=$(nonapex_of "$origin" "$zf")
            [ "$n" = "$(hdr "$zf" triggers)" ] && ok "the header's triggers=$n is the number of records below the apex" \
                || bad "the header's trigger count is the zone's" "header $(hdr "$zf" triggers), zone $n"
        fi
    else
        mode=nxdomain
        ok "no wedge-rpz1 header: a legacy file, whose rpz-ip action is NXDOMAIN; the header checks do not apply"
    fi

    local AP RP NP
    AP=$(free_port); RP=$(free_port); NP=$(free_port); AUTH_PORT=$AP
    auth_up "$probes" "$AP" || { bad "the probe zone loads"; return 0; }
    rec_conf rec "$RP" "$AP" "$origin" "$zf"
    rec_conf nopol "$NP" "$AP" "" ""
    start_named "$RUN/rec.conf" "$RUN/rec.pid" "$RP"
    start_named "$RUN/nopol.conf" "$RUN/nopol.pid" "$NP"
    wait_up "$AP" && wait_up "$RP" && wait_up "$NP" || { bad "the resolvers came up in 15 s" "$(tail -3 "$RUN/rec.log" 2>/dev/null)"; return 0; }

    if acc=$(bind_accepted "$RUN/rec.log" "$zf" "$origin"); then
        ok "BIND loaded the file verbatim, built all $acc of its triggers into the policy and refused none"
    else
        bad "BIND accepted every trigger" "$acc"
    fi

    local label type addr expect desc got nb=0 na=0 pf=0 nores=0
    while read -r label type addr expect desc; do
        case "$label" in ''|'#'*) continue ;; esac
        got=$(ask "$RP" "$label.example.test" "$type")
        if [ "$expect" = block ]; then
            nb=$((nb + 1))
            is_blocked "$got" "$mode" || { bad "$label.example.test $type ($addr, $desc) is blocked ($mode)" "got: $got"; pf=1; }
            [ "$(ask "$NP" "$label.example.test" "$type")" = "NOERROR $addr" ] || nores=$((nores + 1))
        else
            na=$((na + 1))
            [ "$got" = "NOERROR $addr" ] || { bad "$label.example.test $type ($addr, $desc) answers" "got: $got"; pf=1; }
        fi
    done < "$probes"
    [ "$pf" != 0 ] || ok "$nb blocked probes answer $( [ "$mode" = nodata ] && echo NODATA || echo NXDOMAIN ), $na others answer$( [ "$LIVE" = 1 ] || echo " (boundaries either side of every range, the other family on every name)")"
    [ "$nb" -gt 0 ] || bad "at least one probe is blocked" "a gate whose probes block nothing proves nothing"
    [ "$nores" = 0 ] && ok "the control: with the policy removed, all $nb blocked probes resolve" \
        || bad "every blocked probe resolves without the policy" "$nores did not, so their block proved nothing"

    if [ -n "$plane" ]; then
        need_plane_check
        if out=$("$PLANE_CHECK" --rpz-oracle "$plane" "$zf" 2>&1); then
            ok "the zone equals the plane at every breakpoint: $(tail -1 <<<"$out" | sed 's/.*: //')"
        else
            bad "the zone equals the plane (plane_check --rpz-oracle)" "$out"
        fi
    fi
    nsip_check "$origin" "$zf"
}

# ==== the controls, each against the fixture it mutates ================================================
run_controls() { # <origin> <zone file> <probes> <plane>
    local origin=$1 zf=$2 probes=$3 plane=$4 c msg soa serial ex
    echo "  -- the controls: each must FAIL its check"
    c="$RUN/ctl.zone"
    { header_of "$zf"; printf '; sources=%0250d\n' 0; awk '!/^;/' "$zf"; } > "$c"
    msg=$(header_check "$c" "$origin") && bad "the control: a 256-byte header line is refused" "accepted" \
        || ok "the control: a 256-byte header line is refused ($msg)"
    soa=$(soa_of "$origin" "$zf"); serial=${soa%% *}
    sed "s/( $serial /( $((serial + 1)) /" "$zf" > "$c"
    [ "$(soa_of "$origin" "$c" | cut -d' ' -f1)" != "$(hdr "$c" generation)" ] \
        && ok "the control: an SOA serial one above the generation is told apart ($((serial + 1)) against $(hdr "$c" generation))" \
        || bad "the control: an SOA serial off the generation is seen"
    ex=$(awk '{ print $4 }' <<<"$soa")
    sed "s/ $ex 300 )/ $((ex + 1418)) 300 )/" "$zf" > "$c"
    [ "$(epoch_of "$(hdr "$c" validUntil)")" != $(( $(slot_start "$serial") + $(soa_of "$origin" "$c" | cut -d' ' -f4) )) ] \
        && ok "the control: EXPIRE 1,418 s late no longer matches validUntil" \
        || bad "the control: an EXPIRE off validUntil is seen"
    sed "s/^; triggers=\([0-9]*\)/; triggers=9\1/" "$zf" > "$c"
    [ "$(hdr "$c" triggers)" != "$(nonapex_of "$origin" "$c")" ] \
        && ok "the control: a header claiming $(hdr "$c" triggers) triggers is told apart from the zone's $(nonapex_of "$origin" "$c")" \
        || bad "the control: a wrong trigger count is seen"
    if [ -n "$plane" ]; then
        need_plane_check
        awk 'f == 0 && /\.rpz-ip\./ { f = 1; next } { print }' "$zf" > "$c"
        "$PLANE_CHECK" --rpz-oracle "$plane" "$c" > "$c.out" 2>&1 \
            && bad "the control: a trigger dropped fails the oracle" "it agreed" \
            || ok "the control: a trigger dropped fails the oracle ($(grep -m1 DISAGREE "$c.out" | sed 's/^ *//'))"
    fi

    # Two more resolvers: the zone with the legacy CNAME . action, and the zone with a trigger BIND drops.
    local AP=$AUTH_PORT XP HP first got
    XP=$(free_port); HP=$(free_port)
    sed 's/\tCNAME\t\*\.$/\tCNAME\t./' "$zf" > "$RUN/ctl-nx.zone"
    { cat "$zf"; printf '24.1.2.0.192.rpz-ip.%s.\t300\tIN\tCNAME\t*.\n' "$origin"; } > "$RUN/ctl-hb.zone"
    rec_conf ctlnx "$XP" "$AP" "$origin" "$RUN/ctl-nx.zone"
    rec_conf ctlhb "$HP" "$AP" "$origin" "$RUN/ctl-hb.zone"
    start_named "$RUN/ctlnx.conf" "$RUN/ctlnx.pid" "$XP"
    start_named "$RUN/ctlhb.conf" "$RUN/ctlhb.pid" "$HP"
    wait_up "$XP" && wait_up "$HP" || { bad "the control resolvers came up"; return 0; }
    local fl ft
    read -r fl ft _ <<<"$(awk '$4 == "block" { print $1, $2; exit }' "$probes")"
    first="$fl $ft"
    got=$(ask "$XP" "$fl.example.test" "$ft")
    is_blocked "$got" nodata && bad "the control: CNAME . is not NODATA" "the NODATA check accepted '$got'" \
        || ok "the control: the same zone with CNAME . answers '${got% }' for ${first% *}, which the NODATA check refuses"
    msg=$(bind_accepted "$RUN/ctlhb.log" "$RUN/ctl-hb.zone" "$origin") && bad "the control: a dropped trigger is seen" "accepted: $msg" \
        || ok "the control: a trigger naming bits below its /24 is caught ($msg)"
    # The count, on its own: the policy zone's log with one trigger's node line taken out, the shape of a
    # trigger BIND never reached, must fail the comparison.
    awk '!d && /adding node [0-9]/ { d = 1; next } { print }' "$RUN/rec.log" > "$RUN/rec-short.log"
    msg=$(bind_accepted "$RUN/rec-short.log" "$zf" "$origin") && bad "the control: the node count sees a trigger BIND never built" "accepted: $msg" \
        || ok "the control: one trigger missing from BIND's policy build fails the count ($msg)"
}

# ==== expiry: the empty zone ===========================================================================
check_expiry() { # <origin> <zone file> <probes>
    local origin=$1 zf=$2 probes=$3 serial vu sweep e golden AP EP first got
    [ "$(hdr "$zf" state)" = content ] || return 0
    serial=$(hdr "$zf" generation); vu=$(epoch_of "$(hdr "$zf" validUntil)")
    sweep=$(sweep_of "$serial" "$vu")
    e="$RUN/empty.zone"
    render_empty "$origin" "$sweep" > "$e"
    for golden in "$FIX"/rpz.whisper.online.empty-*.zone; do break; done
    if [ "$origin" = rpz.whisper.online ] && [ "$golden" = "$FIX/rpz.whisper.online.empty-$sweep.zone" ]; then
        cmp -s "$e" "$golden" && ok "expired, the zone is the empty zone at serial $sweep, byte for byte the golden $(basename "$golden")" \
            || bad "the expired zone's empty file is the golden bytes" "$(diff "$golden" "$e" | head -4)"
    else
        local gs
        gs=$(basename "$golden" .zone); gs=${gs##*-}
        sed "s/rpz\.whisper\.online/$origin/g; s/$gs/$sweep/g" "$golden" | cmp -s - "$e" \
            && ok "expired, the zone is the empty zone at serial $sweep: the golden with only (origin, serial) changed" \
            || bad "the empty zone is a function of (origin, serial)" "$(sed "s/rpz\.whisper\.online/$origin/g; s/$gs/$sweep/g" "$golden" | diff - "$e" | head -4)"
    fi
    [ "$sweep" != $((serial + 1)) ] \
        && ok "the control: the old disarm's serial, $((serial + 1)), is not the sweep serial $sweep" \
        || bad "the control: the sweep serial differs from the expired serial plus one" "both are $sweep"
    AP=$AUTH_PORT; EP=$(free_port)
    rec_conf empty "$EP" "$AP" "$origin" "$e"
    start_named "$RUN/empty.conf" "$RUN/empty.pid" "$EP"
    wait_up "$EP" || { bad "the empty-zone resolver came up"; return 0; }
    local fl ft fa
    read -r fl ft fa _ <<<"$(awk '$4 == "block" { print $1, $2, $3; exit }' "$probes")"
    first="$fl $ft $fa"
    got=$(ask "$EP" "$fl.example.test" "$ft")
    if [ "$(soa_of "$origin" "$e" | cut -d' ' -f1)" = "$sweep" ] && [ "$(nonapex_of "$origin" "$e")" = 0 ] \
       && [ "$got" = "NOERROR ${first##* }" ] && bind_accepted "$RUN/empty.log" "$e" "$origin" >/dev/null; then
        ok "BIND serves the empty zone at $sweep with 0 triggers, and ${first%% *}.example.test answers ${first##* } again"
    else
        bad "BIND serves the empty zone with no policy" "serial $(soa_of "$origin" "$e" | cut -d' ' -f1), below-apex $(nonapex_of "$origin" "$e"), probe '$got'"
    fi
}

stop_all() { cleanup; PIDS=(); [ -n "${RPZ_GATE_KEEP:-}" ] || rm -rf "${RUN:?}"/*; }

# ==== never published ==================================================================================
# A zone whose plane never published has no file. The gate must not certify an absent file as a zone
# (FAILED without RPZ_ABSENT), must say so when absence is the expectation, and must refuse a file
# where absence was expected.

# ==== main =============================================================================================
echo "RPZ gate: BIND $(named -v | awk '{ print $2 }')"
if [ "$LIVE" = 1 ]; then
    read -r -a ZA <<<"$ZONES"; Z=${ZA[0]}
    cp "${RPZ_BODY}" "$RUN/zone"
    if [ -z "${RPZ_PLANE:-}" ]; then skipped="$skipped oracle(no RPZ_PLANE)"; fi
    run_zone "$Z" "$RUN/zone" "$RPZ_PROBES" "${RPZ_PLANE:-}"
else
    for Z in $ZONES; do
        stop_all
        body="$FIX/$Z.body"; rng="$FIX/$Z.ranges"
        [ -f "$body" ] && [ -f "$rng" ] || { bad "$Z has a fixture" "missing $body or $rng"; continue; }
        render "$body" "$RUN/$Z.zone"
        cp "$RUN/$Z.zone" "$RUN/zone"
        probes_from_ranges "$rng" "$RUN/probes"
        plane_from_ranges "$Z" "$rng" "$RUN/plane.bin"
        run_zone "$Z" "$RUN/zone" "$RUN/probes" "$RUN/plane.bin"
        run_controls "$Z" "$RUN/zone" "$RUN/probes" "$RUN/plane.bin"
        check_expiry "$Z" "$RUN/zone" "$RUN/probes"
    done
    stop_all
    echo
    echo "==== a zone never published"
    np="$RUN/never-published"; mkdir -p "$np"
    if RPZ_ABSENT=1 RPZ_BODY="$np/rpz-rpki-unreachable.whisper.online.zone" "$0" --zone rpz-rpki-unreachable.whisper.online >/dev/null 2>&1; then
        ok "a zone never published: no file, and the gate says so (RPZ_ABSENT=1 passes on an empty published set)"
    else
        bad "a never-published zone with no file passes RPZ_ABSENT"
    fi
    # The control: a file where none may be is refused.
    cp "$FIX"/rpz.whisper.online.empty-*.zone "$np/rpz-rpki-unreachable.whisper.online.zone"
    if RPZ_ABSENT=1 RPZ_BODY="$np/rpz-rpki-unreachable.whisper.online.zone" "$0" --zone rpz-rpki-unreachable.whisper.online >/dev/null 2>&1; then
        bad "the control: a file where none may be is refused" "RPZ_ABSENT passed with a file present"
    else
        ok "the control: a file where none may be is refused"
    fi
    rm -f "$np/rpz-rpki-unreachable.whisper.online.zone"
    echo
    echo "==== the zone argument"
    if out=$(RPZ_ABSENT=1 RPZ_BODY="$np/none" "$0" --zone 'RPZ-RPKI-Unreachable.Whisper.Online.' 2>&1) \
       && grep -q 'rpz-rpki-unreachable.whisper.online is not published' <<<"$out"; then
        ok "a mixed-case origin with a trailing dot is the published zone, folded in the C locale"
    else
        bad "a mixed-case origin is folded" "$out"
    fi
    # The control: the same run with the fold taken out compares bytes, and refuses the mixed case.
    sed "s/LC_ALL=C tr '\[:upper:\]' '\[:lower:\]')/cat)/" "$0" > "$RUN/nofold.sh"
    if ! grep -q "tr '\[:upper:\]' '\[:lower:\]')" "$RUN/nofold.sh" \
       && ! RPZ_ABSENT=1 RPZ_BODY="$np/none" bash "$RUN/nofold.sh" --zone 'RPZ-RPKI-Unreachable.Whisper.Online.' >/dev/null 2>&1; then
        ok "the control: without the fold, the same mixed-case origin is refused"
    else
        bad "the control: a byte compare refuses a mixed-case origin"
    fi
    local_rc() { RPZ_ABSENT=1 RPZ_BODY="$np/none" "$0" --zone "$1" >/dev/null 2>&1 && echo 0 || echo $?; }
    for z in policy.local -o ../rpz.whisper.online rpz..whisper.online "rpz.whisper.online/x" -rpz.whisper.online; do
        r=$(local_rc "$z")
        [ "$r" = 2 ] && ok "--zone '$z' is refused before anything runs (exit 2)" \
            || bad "--zone '$z' is refused" "exit $r"
    done
    # And without RPZ_ABSENT an absent body is a failure of the live mode, never a pass.
    if RPZ_BODY="$np/rpz-rpki-unreachable.whisper.online.zone" RPZ_PROBES=/dev/null "$0" --zone rpz-rpki-unreachable.whisper.online >/dev/null 2>&1; then
        bad "the control: an absent zone is never certified as a zone" "the live mode passed with no file"
    else
        ok "the control: asked to certify an absent file as a zone, the gate fails"
    fi
fi

echo
if [ "$fail" != 0 ]; then
    echo "RPZ GATE: FAILED"
    exit 1
fi
if [ -n "$skipped" ]; then
    echo "RPZ GATE: NOT PROVEN IN FULL - everything run held, but these were not run:$skipped"
    exit 77
fi
echo "RPZ GATE: CLEAR - BIND $(named -v | awk '{ print $2 }') loaded and enforced:$ZONES"
exit 0
