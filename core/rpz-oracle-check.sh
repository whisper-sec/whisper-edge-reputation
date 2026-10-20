#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Prove `plane_check --rpz-oracle` can see what it exists for: a policy zone that says something other
# than the plane it was written from.
#
# The planes come from make-test-snapshot.py, the independent writer. Each zone is written from the
# plane's own --dump by a separate encoder below: every range decomposed into its minimal CIDR cover,
# one rpz-ip trigger per block. Then, each check beside the control that must fail it:
#
#   a faithful zone agrees, for a format-1 reputation plane and a format-2 rpki-unreachable plane;
#   an UNCOVERED trigger dropped fails, at that block's first address [the faithful zone, green];
#   a COVERED trigger (inside another) added, then dropped, still agrees [the uncovered drop, red];
#   a passthru carved inside a block fails [the same zone without it, green];
#   a trigger owner with bits below its prefix fails as unparseable [the canonical owner, green].
#
# Usage: rpz-oracle-check.sh <plane_check binary> <work dir>. Exit 0 when every check held.
#
# Every check reads `condition && pass ... || fail ...`, an if/else only because pass cannot fail.
# shellcheck disable=SC2015
set -u
PC=$1
T=$2
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$T"
ok=0; bad=0
pass() { printf '  ok    %s\n' "$1"; ok=$((ok + 1)); }
fail() { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; bad=$((bad + 1)); }

plane() { # <name> <format> <v4 index> <v6 index> <out>
  python3 "$HERE/make-test-snapshot.py" --plane "$1" --out "$5" --format "$2" --v4-index "$3" \
    --v6-index "$4" --synthetic 40 40 ${6:+"$6"} >/dev/null || return 1
  chmod 0644 "$5"
}

# The encoder: the plane's ranges, as --dump prints them, to a zone of minimal-cover rpz-ip triggers.
encode() { # <plane> <zone>
  # shellcheck disable=SC2016  # the program is Python, and $TTL a zone-file directive it prints
  "$PC" --dump "$1" 2>/dev/null | python3 -c '
import ipaddress, sys
def owner(net):
    if net.version == 4:
        return "%d.%s.rpz-ip.rpz.example." % (net.prefixlen, ".".join(reversed(str(net.network_address).split("."))))
    w = [int(net.network_address.packed[i:i + 2].hex(), 16) for i in range(0, 16, 2)]
    best, bl, i = -1, 1, 0
    while i < 8:
        j = i
        while j < 8 and w[j] == 0:
            j += 1
        if j - i > bl:
            best, bl = i, j - i
        i = j + 1 if j == i else j
    labels = ["%x" % x for x in w]
    if best >= 0:
        labels = labels[:best] + ["zz"] + labels[best + bl:]
    return "%d.%s.rpz-ip.rpz.example." % (net.prefixlen, ".".join(reversed(labels)))
print("$TTL 300")
print("rpz.example.\tIN\tSOA\tns.rpz.example. hostmaster.rpz.example. ( 1 900 300 86400 300 )")
print("rpz.example.\tIN\tNS\tns.rpz.example.")
for line in sys.stdin:
    fam, first, last = line.split()[:3]
    a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
    for net in ipaddress.summarize_address_range(a, b):
        print("%s\t300\tIN\tCNAME\t*." % owner(net))
' > "$2"
}
run() { out=$("$PC" --rpz-oracle "$@" 2>&1) && rc=0 || rc=$?; }
# grep over a here-document, never a pipe a stopping grep could cut short
says() {
  grep -q -- "$2" <<SAYS
$1
SAYS
}

plane reputation 1 radix-16 radix-16 "$T/rep.bin" --schema || { echo "CHECK FAIL: make-test-snapshot.py"; exit 1; }
plane rpki-unreachable 2 radix-16 none "$T/rpki.bin" || { echo "CHECK FAIL: make-test-snapshot.py"; exit 1; }
encode "$T/rep.bin" "$T/rep.zone"
encode "$T/rpki.bin" "$T/rpki.zone"
n=$(grep -c 'rpz-ip' "$T/rep.zone")

run "$T/rep.bin" "$T/rep.zone"
{ [ "$rc" = 0 ] && says "$out" "$n rpz-ip triggers" && says "$out" ", 0 disagreements"; } \
  && pass "a faithful zone agrees with a format-1 reputation plane ($n triggers): $(printf '%s' "$out" | tail -1 | sed 's/.*: //')" \
  || fail "a faithful reputation zone agrees" "rc=$rc $out"
nk=$(grep -c 'rpz-ip' "$T/rpki.zone")
run "$T/rpki.bin" "$T/rpki.zone"
{ [ "$rc" = 0 ] && says "$out" "$nk rpz-ip triggers" && says "$out" ", 0 disagreements"; } \
  && pass "a faithful zone agrees with a format-2 rpki-unreachable plane ($nk triggers, 0 disagreements)" \
  || fail "a faithful rpki zone agrees" "rc=$rc $out"
# Its control: the same format-2 plane, one uncovered trigger dropped from its zone, fails at that block.
kvictim=$(awk 'NF && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.rpz-ip/' "$T/rpki.zone" | sed -n 3p)
kfirst=$(printf '%s\n' "$kvictim" | awk '{ split($1, l, "."); print l[5] "." l[4] "." l[3] "." l[2] }')
grep -vF -- "$kvictim" "$T/rpki.zone" > "$T/rpki-drop.zone"
run "$T/rpki.bin" "$T/rpki-drop.zone"
{ [ -n "$kvictim" ] && [ "$rc" = 1 ] && says "$out" "DISAGREE 4 $kfirst: the plane enforces it, the zone does not"; } \
  && pass "the control: the format-2 zone with one trigger dropped fails at its block's first address ($kfirst)" \
  || fail "a dropped format-2 trigger is seen" "rc=$rc victim='$kvictim' $out"

# An uncovered trigger dropped: the 7th IPv4 trigger, whose block nothing else in the zone covers.
victim=$(grep '\.rpz-ip\.' "$T/rep.zone" | grep -v 'zz\|\.[0-9a-f]*[a-f][0-9a-f]*\.' | awk 'NF && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.rpz-ip/' | sed -n 7p)
vfirst=$(printf '%s\n' "$victim" | awk '{ split($1, l, "."); print l[5] "." l[4] "." l[3] "." l[2] }')
grep -vF -- "$victim" "$T/rep.zone" > "$T/drop.zone"
run "$T/rep.bin" "$T/drop.zone"
{ [ "$rc" = 1 ] && says "$out" "DISAGREE 4 $vfirst: the plane enforces it, the zone does not"; } \
  && pass "the control: an uncovered trigger dropped fails at its block's first address ($vfirst)" \
  || fail "an uncovered dropped trigger is seen" "rc=$rc victim='$victim' $out"

# A covered trigger: the same block's first half, one bit longer, inside the trigger that stays.
len=$(printf '%s' "$victim" | cut -d. -f1)
if [ "$len" -lt 32 ]; then
  covered="$((len + 1))${victim#"$len"}"
  covered=$(printf '%s\n' "$covered" | awk '{ print $1 "\t300\tIN\tCNAME\t*." }')
  { cat "$T/rep.zone"; printf '%s\n' "$covered"; } > "$T/covered.zone"
  run "$T/rep.bin" "$T/covered.zone"; c1=$rc
  grep -vF -- "$covered" "$T/covered.zone" > "$T/covered-drop.zone"
  run "$T/rep.bin" "$T/covered-drop.zone"
  { [ "$c1" = 0 ] && [ "$rc" = 0 ]; } \
    && pass "a covered trigger (/$((len + 1)) inside the /$len) added agrees, and dropped still agrees" \
    || fail "a covered trigger changes nothing" "with=$c1 without=$rc $out"
else
  fail "a covered trigger changes nothing" "the chosen trigger is a /32, nothing fits inside it"
fi

# A passthru carved inside a block: the plane enforces those addresses, the zone exempts them.
pt=$(printf '%s' "$covered" | awk '{ print $1 "\t300\tIN\tCNAME\trpz-passthru." }')
{ cat "$T/rep.zone"; printf '%s\n' "$pt"; } > "$T/passthru.zone"
run "$T/rep.bin" "$T/passthru.zone"
{ [ "$rc" = 1 ] && says "$out" "DISAGREE 4 $vfirst: the plane enforces it, the zone does not"; } \
  && pass "a passthru carved inside an enforced block fails at its first address (the faithful zone above is the green control)" \
  || fail "a passthru carve is seen" "rc=$rc $out"

# An owner naming bits below its prefix length is not a trigger BIND would load; never skipped.
printf '24.1.2.0.192.rpz-ip.rpz.example.\t300\tIN\tCNAME\t*.\n' > "$T/hostbits.line"
cat "$T/rep.zone" "$T/hostbits.line" > "$T/hostbits.zone"
run "$T/rep.bin" "$T/hostbits.zone"
{ [ "$rc" = 1 ] && says "$out" "bits below its /24"; } \
  && pass "an owner with bits below its prefix is a disagreement, not a skip (192.0.2.1/24)" \
  || fail "a non-canonical owner is refused" "rc=$rc $out"

printf '  --- rpz oracle: %d ok, %d failed\n' "$ok" "$bad"
[ "$bad" = 0 ]
