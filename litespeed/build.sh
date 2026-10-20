#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Build mod_whisper_edge.so for OpenLiteSpeed / LiteSpeed.
#
# Two things make this one different from the other two, and both are stated because an operator
# who assumes otherwise loses an afternoon:
#
#   LiteSpeed is NOT Apache-module-compatible. It reads Apache DIRECTIVES, which makes it very easy
#   to assume it loads Apache .so modules too. It does not: it has its own module API (LSIAPI), so
#   litespeed/mod_whisper_edge.c is a real module and not a copy of the Apache one.
#
#   The LSIAPI header is NOT vendored here. OpenLiteSpeed is GPLv3 and this subtree is
#   MIT, so the header is fetched from a PINNED release with its digest verified before
#   anything is unpacked - pinned rather than taken from a branch, because these headers are
#   compiled into a module that will run inside somebody's production web server.
#
# The build prints its compiler, version and flags: the module gate judges the built object by the
# toolchain leg it reports, and a build is reproducible under SOURCE_DATE_EPOCH (the same bytes with or
# without a key anywhere in the environment, which the gate's K1 row compares).
#
# Usage: ./build.sh [--install] [--out FILE] [--cc COMPILER] [--cflags "EXTRA FLAGS"] [--debug]
#
# --debug builds the gate's DEBUG object: -DWE_MOD_DEBUG, the core's debug counters and assertions on,
# written to mod_whisper_edge-debug.so unless --out names a file. It is never the release build, and
# --debug with --install is refused, so it cannot replace the installed module.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
INSTALL=0
DEBUG=0
OUT=""
CC="${CC:-gcc}"
EXTRA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1 ;;
    --out) OUT=$2; shift ;;
    --cc) CC=$2; shift ;;
    --cflags) EXTRA=$2; shift ;;
    --debug) DEBUG=1 ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "build.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
die() { printf 'litespeed/build.sh: %s\n' "$*" >&2; exit 1; }
if [ "$DEBUG" = 1 ]; then
  [ "$INSTALL" = 0 ] || die "--debug with --install is refused: the debug build is the gate's, never the installed module"
  EXTRA="-DWE_MOD_DEBUG${EXTRA:+ $EXTRA}"
  : "${OUT:=$HERE/mod_whisper_edge-debug.so}"
fi
: "${OUT:=$HERE/mod_whisper_edge.so}"

LSWS="${LSWS:-/usr/local/lsws}"

# The SDK: the vendored copy if a previous run fetched it, the installed server's own headers if it
# has them, else fetch the pinned release through the Makefile target that verifies the digest.
SDK=""
for c in "$HERE/sdk/include" "$LSWS/include"; do
  [ -f "$c/ls.h" ] && { SDK="$c"; break; }
done
if [ -z "$SDK" ]; then
  echo "== fetching the pinned LSIAPI header (digest verified by the Makefile target)"
  make -C "$ROOT" litespeed-sdk >/dev/null || die "could not fetch the SDK; see make -C $ROOT litespeed-sdk"
  [ -f "$HERE/sdk/include/ls.h" ] || die "the SDK fetch reported success but produced no ls.h"
  SDK="$HERE/sdk/include"
fi
echo "== sdk  $SDK"

VER="$( "$LSWS/bin/openlitespeed" -v 2>/dev/null | head -1 || true)"
[ -n "$VER" ] && echo "== $VER"

# The exact line litespeed-gate.sh proves. -Werror on purpose: this compiles into somebody's web
# server, so a warning here is a defect to fix rather than a note to scroll past. -ffunction-sections so
# the decide wrapper has a section of its own (the gate checks its relocations by section); -g so the
# gate can read the symbol table and DWARF of the object it judges, which the install strips if it wants.
FLAGS="-std=gnu11 -O2 -g -Wall -Wextra -Werror -fPIC -shared -ffunction-sections"
# Reproducible: a fixed epoch unless the caller set one, so two builds of one tree are one file.
: "${SOURCE_DATE_EPOCH:=0}"
export SOURCE_DATE_EPOCH
REPRO="-fdebug-prefix-map=$ROOT=/edge -ffile-prefix-map=$ROOT=/edge -frandom-seed=whisper-edge-litespeed"
echo "== cc   $($CC --version | head -1)"
echo "== flags $FLAGS $REPRO${EXTRA:+ $EXTRA}"
echo "== compile"
# The core: the loader, the digest, the per-range counters, the policy compiler and evaluator, and the
# modules' shared configuration-time half (we_module.c). Compiled in, not linked, so there is nothing of
# ours to install first.
set -- "$ROOT/core/whisper_edge.c" "$ROOT/core/we_sha256.c" "$ROOT/core/we_counters.c" \
       "$ROOT/core/we_policy.c" "$ROOT/core/we_module.c"
# shellcheck disable=SC2086
$CC $FLAGS $REPRO $EXTRA \
    -I"$SDK" -I"$ROOT/core" \
    -o "$OUT" \
    "$HERE/mod_whisper_edge.c" "$@" \
  || die "the compile failed; the output is above"
echo "== built $OUT ($(wc -c <"$OUT") bytes)"

if [ "$INSTALL" = 1 ]; then
  [ -d "$LSWS/modules" ] || die "$LSWS/modules does not exist; set LSWS=<install dir>"
  install -m 0755 "$OUT" "$LSWS/modules/mod_whisper_edge.so" \
    || die "could not install into $LSWS/modules (run with sudo)"
  echo "   installed as $LSWS/modules/mod_whisper_edge.so"
  echo "   (LiteSpeed opens modules/<name>.so for a \`module <name> {}\` block and looks up the"
  echo "    symbol <name> in it, so the block name must be the module's exported symbol,"
  echo "    mod_whisper_edge; any other name fails to load and the server starts without it)"
else
  echo
  echo "   Next: sudo ./build.sh --install   (into $LSWS/modules/mod_whisper_edge.so)"
fi
cat <<EOF

   Then, at the SERVER level and per virtual host - control is per-site here, NOT per-location:
     module mod_whisper_edge {
         whisper_edge_data        /var/lib/whisper-edge
         whisper_edge_summary     /var/lib/whisper-edge/counters
         whisper_edge_policy      deny if listed >= high
         whisper_edge_policy      log if tor_exit
         # whisper_edge_mode      deny
     }
EOF
