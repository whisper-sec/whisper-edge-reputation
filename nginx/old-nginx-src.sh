#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# old-nginx-src.sh - a VERIFIED nginx source tree older than 1.23, for the nginx gate's pre-1.23 rows.
#
#   ./old-nginx-src.sh <dir>     prints the path of the unpacked tree (RHEL 9's nginx 1.20.1) on stdout
#
# RHEL 9 ships nginx 1.20.1, and nginx.org no longer publishes the key that signed that release, so a
# nginx.org download of it cannot be verified. Rocky Linux's source RPM of the same package carries the
# release tarball and is signed with Rocky's release key, which is pinned here by fingerprint: the key is
# fetched, its fingerprint must be the pin, the source RPM must verify against it with rpmkeys -K (in a
# private key database, so the host's own is never touched), and only then is anything unpacked. Any
# failure refuses with the reason; nothing is ever compiled from an unverified tree.
#
# Needs: curl, gpg, rpmkeys and rpm2cpio (the rpm package on Debian and Ubuntu), cpio, tar.
set -euo pipefail

OUT="${1:?usage: old-nginx-src.sh <dir>}"
# Rocky Enterprise Software Foundation, the Rocky Linux 9 release key: the fingerprint read from
# dl.rockylinux.org's RPM-GPG-KEY-Rocky-9 when this pin was written
PIN=21CB256AE16FC54C6E652949702D426D350D275D
BASE=https://dl.rockylinux.org/pub/rocky
VER=1.20.1

die() { echo "old-nginx-src: $*" >&2; exit 1; }
for t in curl gpg rpmkeys rpm2cpio cpio tar; do command -v "$t" >/dev/null 2>&1 || die "need $t"; done
mkdir -p "$OUT"
T=$(mktemp -d -t old-nginx.XXXXXX)
trap 'rm -rf "$T"' EXIT
# a keyring of this run's own: the caller's gpg home is neither read nor written, and need not be writable
export GNUPGHOME="$T/gnupg"
mkdir -m 0700 "$GNUPGHOME"

curl -fsSL --max-time 60 -o "$T/key.asc" "$BASE/RPM-GPG-KEY-Rocky-9" || die "could not fetch Rocky's release key"
KEYS=$(gpg --batch --show-keys --with-colons "$T/key.asc" 2>&1) || die "gpg could not read Rocky's release key: $(printf '%s' "$KEYS" | tail -1)"
FPR=$(awk -F: '$1 == "fpr" { print $10; exit }' <<<"$KEYS")
[ "$FPR" = "$PIN" ] || die "Rocky's release key has fingerprint ${FPR:-none}, not the pinned $PIN; nothing is trusted"

LIST=$(curl -fsSL --max-time 60 "$BASE/9/AppStream/source/tree/Packages/n/") || die "could not list Rocky's nginx source RPMs"
SRPM=$(grep -o "nginx-$VER-[^\"]*\.src\.rpm" <<<"$LIST" | sort -u -V | tail -n 1 || true)
[ -n "$SRPM" ] || die "Rocky lists no nginx-$VER source RPM"
curl -fsSL --max-time 300 -o "$T/$SRPM" "$BASE/9/AppStream/source/tree/Packages/n/$SRPM" || die "could not fetch $SRPM"

mkdir -p "$T/rpmdb"
rpmkeys --dbpath "$T/rpmdb" --import "$T/key.asc" || die "could not import the pinned key into a private key database"
CHECK=$(rpmkeys --dbpath "$T/rpmdb" -K "$T/$SRPM" 2>&1) || die "$SRPM did NOT verify: $CHECK"
case "$CHECK" in
    *"NOT OK"*) die "$SRPM did NOT verify: $CHECK" ;;
    *"signatures OK"*) echo "old-nginx-src: $CHECK" >&2 ;;
    *) die "$SRPM: no signature verified: $CHECK" ;;
esac

( cd "$T" && rpm2cpio "$T/$SRPM" > "$T/srpm.cpio" && cpio -idm --quiet < "$T/srpm.cpio" ) || die "could not unpack $SRPM"
[ -f "$T/nginx-$VER.tar.gz" ] || die "$SRPM carries no nginx-$VER.tar.gz"
rm -rf "$OUT/nginx-$VER"
tar xzf "$T/nginx-$VER.tar.gz" -C "$OUT" || die "could not unpack nginx-$VER.tar.gz"
[ -f "$OUT/nginx-$VER/src/core/nginx.h" ] || die "the unpacked tree is not nginx $VER"
echo "$OUT/nginx-$VER"
