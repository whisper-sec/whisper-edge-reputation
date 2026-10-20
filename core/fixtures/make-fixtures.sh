#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# make-fixtures.sh - build the live-shaped fixtures (fixtures/README.md), or fail and say why.
#
# The inputs are fetched from CAIDA when they are not already in the RIB directory (pass a directory
# that holds a cached copy to stay offline), checked against the pinned digests, flattened, and the
# outputs checked against theirs. A digest that does not match FAILS: a fixture that silently moved
# would move every live-shaped number the test prints with it.
#
# Usage: fixtures/make-fixtures.sh [rib-dir]     (default: fixtures/rib)
set -eu

cd "$(dirname "$0")"
RIB=${1:-rib}
CAIDA=https://publicdata.caida.org/datasets/routing
RV4=routeviews-rv2-20261009-1200.pfx2as.gz
RV6=routeviews-rv6-20261009-1200.pfx2as.gz

mkdir -p rib
for f in "$RV4" "$RV6"; do
    if [ ! -s "rib/$f" ]; then
        if [ "$RIB" != rib ] && [ -s "$RIB/$f" ]; then
            cp "$RIB/$f" "rib/$f"
        else
            case "$f" in
                *rv2*) url="$CAIDA/routeviews-prefix2as/2026/10/$f" ;;
                *) url="$CAIDA/routeviews6-prefix2as/2026/10/$f" ;;
            esac
            echo "fetching $url"
            curl -fsS -o "rib/$f.part" "$url"
            mv "rib/$f.part" "rib/$f"
        fi
    fi
done

if ! grep ' rib/' SHA256SUMS | sha256sum -c --quiet -; then
    echo "FIXTURES FAILED: the RouteViews inputs do not match their pinned digests" >&2
    exit 1
fi
python3 flatten-routeviews.py rib .
if ! grep -v ' rib/' SHA256SUMS | sha256sum -c --quiet -; then
    echo "FIXTURES FAILED: the flattened outputs do not match their pinned digests" >&2
    exit 1
fi
echo "fixtures: inputs and outputs match fixtures/SHA256SUMS"
