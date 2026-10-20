#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Build and optionally install mod_whisper_edge.so for the Apache httpd ON THIS HOST..
#
# Apache is the easy one of the three and it is worth saying why, because it shapes what an
# operator should expect: httpd ships `apxs`, which already knows this build's include paths,
# compiler flags and module directory, so there is no source tree to match and no flag archaeology.
# One command, and the only real decision is whether to install it.
#
# Usage: ./build.sh [--install]
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "build.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
die() { printf 'apache/build.sh: %s\n' "$*" >&2; exit 1; }

APXS=""
for c in apxs apxs2; do command -v "$c" >/dev/null 2>&1 && { APXS="$c"; break; }; done
[ -n "$APXS" ] || die "apxs is not on PATH.
    Debian/Ubuntu: apt-get install apache2-dev
    RHEL/Fedora:   dnf install httpd-devel"

SERVER="$( { apache2ctl -v 2>/dev/null || apachectl -v 2>/dev/null || httpd -v 2>/dev/null; } \
  | sed -n 's/^Server version: *//p' | head -1)"
echo "== ${SERVER:-Apache httpd} via $APXS"

# The core is compiled IN rather than linked, so there is nothing of ours to install first and no
# shared-library versioning to get wrong. This is the line apache-gate.sh already proves.
cd "$HERE"
# -ffunction-sections puts every function in a section of its own, which is how apache-gate.sh finds the
# decide wrapper and each handler in the built object; -Wall -Wextra -Werror because this ends up inside
# somebody's production web server, and a warning there is a defect to fix, not a note to scroll past.
# The policy compiler, the module glue (we_module.c: the arena, the binding, the thread, the writers) and
# the core are compiled in, so there is nothing of ours to install first.
set -- -c -I../core -Wc,-ffunction-sections -Wc,-Wall -Wc,-Wextra -Wc,-Werror -Wc,-std=gnu11 \
       mod_whisper_edge.c ../core/whisper_edge.c ../core/we_sha256.c ../core/we_counters.c ../core/we_policy.c \
       ../core/we_module.c
if [ "$INSTALL" = 1 ]; then
  # -i installs into apxs's own LIBEXECDIR, which is the one this httpd actually loads from, so it
  # is read from the build rather than guessed at /usr/lib/apache2/modules.
  set -- -i "$@"
fi
echo "== $APXS $*"
"$APXS" "$@" || die "the build failed; the compiler output is above"

SO="$(find "$HERE" -name 'mod_whisper_edge.so' -newermt '-5 minutes' 2>/dev/null | head -1)"
[ -n "$SO" ] || SO="$HERE/.libs/mod_whisper_edge.so"
[ -f "$SO" ] || die "the build reported success but produced no mod_whisper_edge.so"
echo "== built $SO ($(wc -c <"$SO") bytes)"

LIBEXEC="$("$APXS" -q LIBEXECDIR 2>/dev/null || echo /usr/lib/apache2/modules)"
echo
if [ "$INSTALL" = 1 ]; then
  echo "   installed into $LIBEXEC"
  echo "   Add a conf.d drop-in, then reload:"
else
  echo "   Next: sudo ./build.sh --install   (apxs -i puts it in $LIBEXEC)"
  echo "   Then add a conf.d drop-in, and reload:"
fi
cat <<EOF
     LoadModule whisper_edge_module $LIBEXEC/mod_whisper_edge.so
     WhisperEdgeSnapshot /var/lib/whisper-edge/snapshot.bin
     WhisperEdgeSummary /var/lib/whisper-edge/counters
     # WhisperEdgeMode deny     # it defaults to log, which blocks nothing
EOF
