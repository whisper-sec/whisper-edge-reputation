#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Build ngx_http_whisper_edge_module.so for the nginx ON THIS HOST..
#
# nginx has no stable module ABI, so a dynamic module must be compiled against the SAME SOURCE
# VERSION and the SAME CONFIGURE FLAGS as the running binary. The README explained that correctly
# and left four steps to the reader, one of which has a trap sharp enough that it needed its own
# warning: `nginx -V` prints QUOTED values (`--with-cc-opt='-g -O2 ...'`), so without `eval` the
# shell splits on whitespace, ./configure receives a bare `-O2`, and it stops with
# `invalid option "-O2"`. A step that needs a warning is a step that should not be manual.
#
# Usage: ./build.sh [--src DIR] [--keep] [--install] [--debug]
#   --src      an nginx source tree you already have (default: find or fetch the matching one)
#   --install  copy the built .so next to nginx's other modules and print the load_module line
#   --debug    the debug build (WE_MOD_DEBUG: the core's debug counters and assertions on), written as
#              ngx_http_whisper_edge_module.debug.so, for the gates; never installed
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC=""
KEEP=0
INSTALL=0
DEBUG=0
while [ $# -gt 0 ]; do
  case "$1" in
    --src)     SRC="${2:?--src needs a path}"; shift ;;
    --keep)    KEEP=1 ;;
    --install) INSTALL=1 ;;
    --debug)   DEBUG=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "build.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

die() { printf 'nginx/build.sh: %s\n' "$*" >&2; exit 1; }
[ "$DEBUG" = 1 ] && [ "$INSTALL" = 1 ] && die "--debug and --install together: the debug build is the gates', never installed"

command -v nginx >/dev/null 2>&1 || die "nginx is not on PATH; nothing to build against"
VER="$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p')"
[ -n "$VER" ] || die "could not read a version out of \`nginx -v\`"
ARGS="$(nginx -V 2>&1 | sed -n 's/^configure arguments: //p')"
[ -n "$ARGS" ] || die "\`nginx -V\` printed no configure arguments; cannot match this build"
echo "== nginx $VER on this host"

# --with-compat is what makes a module loadable by a binary it was not built with in one step. If
# the distro built without it, say so now rather than after a successful compile and a refusing
# load, which is the confusing order.
case "$ARGS" in
  *--with-compat*) ;;
  *) echo "   note: this nginx was NOT built --with-compat. The module is still built with it," ;
     echo "   which is the compatible direction, but if the load fails with \"module is not binary" ;
     echo "   compatible\" that is why, and the fix is a distro nginx that has it (Debian/Ubuntu do)." ;;
esac

# 0. what the build needs, before anything is fetched or configured: a compiler, make, and the headers of
# every library this nginx's own flags compile in. configure would stop on a missing one with its own
# words and no install line; this names every missing piece at once, in the host's package manager.
# Each check asks the compiler itself (the header must preprocess), so a header in a place the
# compiler does not search reads as missing, as it would to configure.
have() { command -v "$1" >/dev/null 2>&1; }
hdr() { # <header> [cflags]: whether the compiler finds it
  have cc || return 1
  printf '#include <%s>\n' "$1" | cc ${2:-} -E -x c - >/dev/null 2>&1
}
flag() { case " $ARGS " in *" $1"[\ =]*) return 0 ;; esac; return 1; }
PM=""; have apt-get && PM=apt; [ -z "$PM" ] && { have dnf || have yum; } && PM=dnf; [ -z "$PM" ] && have apk && PM=apk
MISS=""; need() { # <what> <apt package(s)> <dnf package(s)> <apk package(s)>
  MISS="$MISS$1|$2|$3|$4
"; }
have cc || need "a C compiler" gcc gcc "gcc musl-dev"
have make || need make make make make
if ! flag --without-http_rewrite_module || flag --with-pcre; then
  if flag --without-pcre2; then hdr pcre.h || need "the PCRE headers" libpcre3-dev pcre-devel pcre-dev
  else { hdr pcre2.h -DPCRE2_CODE_UNIT_WIDTH=8 || hdr pcre.h; } || need "the PCRE2 headers" libpcre2-dev pcre2-devel pcre2-dev; fi
fi
if { flag --with-http_ssl_module || flag --with-stream_ssl_module || flag --with-mail_ssl_module || flag --with-http_v3_module; } \
   && ! flag --with-openssl; then hdr openssl/ssl.h || need "the OpenSSL headers" libssl-dev openssl-devel openssl-dev; fi
flag --without-http_gzip_module || flag --with-zlib || hdr zlib.h || need "the zlib headers" zlib1g-dev zlib-devel zlib-dev
if flag --with-http_xslt_module; then
  hdr libxslt/xslt.h -I/usr/include/libxml2 || need "the libxslt headers" libxslt1-dev libxslt-devel libxslt-dev
  hdr libxml/parser.h -I/usr/include/libxml2 || need "the libxml2 headers" libxml2-dev libxml2-devel libxml2-dev
fi
flag --with-http_image_filter_module && { hdr gd.h || need "the GD headers" libgd-dev gd-devel gd-dev; }
{ flag --with-http_geoip_module || flag --with-stream_geoip_module; } && { hdr GeoIP.h || need "the GeoIP headers" libgeoip-dev GeoIP-devel geoip-dev; }
if flag --with-http_perl_module; then
  _pc=$(perl -MConfig -e 'print $Config{archlibexp}' 2>/dev/null || :)
  { [ -n "$_pc" ] && [ -f "$_pc/CORE/EXTERN.h" ] && perl -MExtUtils::Embed -e 1 >/dev/null 2>&1; } \
    || need "the Perl headers and ExtUtils::Embed" libperl-dev "perl-devel perl-ExtUtils-Embed" perl-dev
fi
if [ -n "$MISS" ]; then
  _what=$(printf '%s' "$MISS" | cut -d'|' -f1 | sed '/^$/d' | tr '\n' ',' | sed 's/,$//; s/,/, /g; s/, \([^,]*\)$/ and \1/')
  case "$PM" in
    apt) _line="apt-get install -y $(printf '%s' "$MISS" | cut -d'|' -f2 | tr '\n' ' ' | sed 's/ *$//')" ;;
    dnf) _line="dnf install -y $(printf '%s' "$MISS" | cut -d'|' -f3 | tr '\n' ' ' | sed 's/ *$//')" ;;
    apk) _line="apk add $(printf '%s' "$MISS" | cut -d'|' -f4 | tr '\n' ' ' | sed 's/ *$//')" ;;
    *) _line="" ;;
  esac
  [ -n "$_line" ] || die "this nginx's flags need $_what to build against, and they are missing here; install them with your package manager and run this again"
  die "this nginx's flags need $_what to build against, and they are missing here. As root:
    $_line
    then run this again"
fi

# 1. the sources, MATCHING. Preference order is cheapest-and-most-likely-correct first.
WORK=""
if [ -n "$SRC" ]; then
  [ -f "$SRC/src/core/nginx.h" ] || die "$SRC is not an nginx source tree"
  SVER="$(sed -n 's/^#define NGINX_VERSION *"\([0-9.]*\)".*/\1/p' "$SRC/src/core/nginx.h")"
  [ "$SVER" = "$VER" ] || die "the tree at $SRC is nginx $SVER but this host runs $VER.
    A module built against a different source version will not load. Point --src at $VER."
  echo "   sources: $SRC (given, version matches)"
elif [ -f /usr/share/nginx/src/src/core/nginx.h ] \
  && [ "$(sed -n 's/^#define NGINX_VERSION *"\([0-9.]*\)".*/\1/p' /usr/share/nginx/src/src/core/nginx.h)" = "$VER" ]; then
  # The distro's own sources, which are by construction the ones this binary was built from. This
  # is the shortest and the most trustworthy route, so it is tried before the network.
  WORK="$(mktemp -d -t whisper-edge-ngx.XXXXXX)"
  cp -r /usr/share/nginx/src/. "$WORK/"
  SRC="$WORK"
  echo "   sources: /usr/share/nginx/src (the nginx-dev package, version matches) -> $WORK"
elif command -v rpm >/dev/null 2>&1 && rpm -q nginx >/dev/null 2>&1; then
  # AN RPM DISTRIBUTION (RHEL, Rocky, Alma, Fedora): the distribution's own source RPM of the installed
  # package, verified with `rpm -K` against the distribution's signing key, carries the release tarball this
  # binary was built from. It is used before nginx.org because it matches the package exactly, and because
  # nginx.org no longer publishes the key that signed releases before 1.23 (RHEL 9 ships 1.20.1), so a
  # nginx.org download of those cannot be verified at all. Nothing is compiled from a source RPM whose
  # signature did not verify, and this script never imports a key itself.
  for t in dnf rpm2cpio cpio; do
    command -v "$t" >/dev/null 2>&1 || die "need $t to fetch and unpack the distribution's nginx source RPM, or pass --src
    with a tree you have verified yourself"
  done
  PKG="$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' nginx)"
  WORK="$(mktemp -d -t whisper-edge-ngx.XXXXXX)"
  echo "   sources: the distribution's source RPM of $PKG (nginx.org's key for this release is not published)"
  ( cd "$WORK" && dnf download -q --source --enablerepo='*-source' "$PKG" ) >/dev/null 2>&1 \
    || die "could not download the source RPM of $PKG. It needs dnf-plugins-core and the distribution's source
    repository; or pass --src with a tree you have verified yourself"
  SRPM="$(ls "$WORK"/*.src.rpm 2>/dev/null | sed -n 1p)"
  [ -n "$SRPM" ] || die "dnf download left no source RPM in $WORK"
  CHECK="$(rpm -K "$SRPM" 2>&1)" && KRC=0 || KRC=$?
  case "$CHECK" in
    *"NOT OK"*) KRC=1 ;;
    *"signatures OK"*) ;;
    *) KRC=1 ;;
  esac
  [ "$KRC" = 0 ] || die "the source RPM did NOT verify: $CHECK
    Nothing is compiled from it. If the distribution's key is not imported, import it as root
    (rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-<distribution>) and run this again."
  echo "   signature: $CHECK"
  ( cd "$WORK" && rpm2cpio "$SRPM" > "$WORK/srpm.cpio" && cpio -idm --quiet < "$WORK/srpm.cpio" ) \
    || die "could not unpack $SRPM"
  [ -f "$WORK/nginx-$VER.tar.gz" ] || die "the source RPM carries no nginx-$VER.tar.gz"
  mkdir -p "$WORK/tree"
  tar xzf "$WORK/nginx-$VER.tar.gz" -C "$WORK/tree" --strip-components=1 || die "could not unpack nginx-$VER.tar.gz"
  SRC="$WORK/tree"
else
  command -v curl >/dev/null 2>&1 || die "need curl to fetch nginx-$VER sources, or pass --src"
  command -v gpg  >/dev/null 2>&1 || die "need gpg to VERIFY the nginx-$VER tarball before compiling it, or pass --src
    with a tree you have verified yourself. On Debian/Ubuntu \`apt-get install nginx-dev\` is the shorter route."
  WORK="$(mktemp -d -t whisper-edge-ngx.XXXXXX)"
  echo "   sources: fetching nginx-$VER from nginx.org (no matching nginx-dev found)"
  echo "            on Debian/Ubuntu \`apt-get install nginx-dev\` is the shorter route"
  curl -fsSL --max-time 300 -o "$WORK/nginx-$VER.tar.gz"     "https://nginx.org/download/nginx-$VER.tar.gz" \
    || die "could not fetch nginx-$VER.tar.gz"
  curl -fsSL --max-time 60  -o "$WORK/nginx-$VER.tar.gz.asc" "https://nginx.org/download/nginx-$VER.tar.gz.asc" \
    || die "could not fetch the signature for nginx-$VER.tar.gz"
  # The release signers' keys travel with this script (fingerprints and where each was checked are
  # in the file's header). A tarball that does not verify against them is not
  # compiled: a module an operator loads into a production web server is the wrong place to trust
  # a download, and a pipe from curl into tar was exactly that.
  GNUPGHOME="$(mktemp -d -t whisper-edge-gpg.XXXXXX)"; export GNUPGHOME
  gpg --batch --quiet --import "$HERE/nginx-signing-keys.asc" >/dev/null 2>&1 \
    || { rm -rf "$GNUPGHOME"; die "could not import $HERE/nginx-signing-keys.asc"; }
  # VALIDSIG is also printed beside EXPKEYSIG and REVKEYSIG, so a signature from a key this keyring
  # later marks revoked or expired must not pass on VALIDSIG alone.
  STATUS="$(gpg --batch --status-fd 1 --verify "$WORK/nginx-$VER.tar.gz.asc" "$WORK/nginx-$VER.tar.gz" 2>/dev/null || true)"
  if [ "$(printf '%s\n' "$STATUS" | grep -c '^\[GNUPG:\] VALIDSIG ')" -gt 0 ] \
     && ! [ "$(printf '%s\n' "$STATUS" | grep -c -E '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG) ')" -gt 0 ]; then
    rm -rf "$GNUPGHOME"; unset GNUPGHOME
    echo "   signature: nginx-$VER.tar.gz verified against the nginx release signing keys"
  else
    rm -rf "$GNUPGHOME"; unset GNUPGHOME
    die "nginx-$VER.tar.gz did NOT verify against the nginx release signing keys in $HERE/nginx-signing-keys.asc.
    Either the download was altered in transit, or nginx has a release signer this script does not know yet.
    Check https://nginx.org/en/pgp_keys.html; to build now anyway, pass --src with a tree you have verified."
  fi
  tar xzf "$WORK/nginx-$VER.tar.gz" -C "$WORK" --strip-components=1 || die "could not unpack nginx-$VER.tar.gz"
  rm -f "$WORK/nginx-$VER.tar.gz" "$WORK/nginx-$VER.tar.gz.asc"
  SRC="$WORK"
fi
[ "$KEEP" = 1 ] || [ -z "$WORK" ] || trap 'rm -rf "$WORK"' EXIT INT TERM

# 2. configure with THIS host's flags. eval is load-bearing; see the header.
echo "== configure (this host's own flags, plus --with-compat and the module)"
( cd "$SRC" && eval "./configure $ARGS --with-compat --add-dynamic-module=$HERE" ) >"$SRC/configure.log" 2>&1 \
  || { tail -25 "$SRC/configure.log" >&2; die "configure failed; the tail is above, the full log is $SRC/configure.log"; }

# 3. the .so by its explicit target, out of the GENERATED objs/Makefile.
#
# Not `make modules`, which is the conventional incantation and the one I reached for first: this
# source tree has no such target and the build stopped with "No rule to make target 'modules'".
# nginx-gate.sh already recorded the line that works, and it is the explicit object path - the
# generated objs/Makefile always has a rule for the artifact it was told to produce, whatever the
# top-level Makefile of that particular release does or does not expose.
echo "== build the module (objs/Makefile, explicit target)"
DBG=""
if [ "$DEBUG" = 1 ]; then
  DBG="CFLAGS=$(sed -n 's/^CFLAGS *= *//p' "$SRC/objs/Makefile" | sed -n 1p) -DWE_MOD_DEBUG"
  echo "== the debug build: -DWE_MOD_DEBUG"
fi
( cd "$SRC" && make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" ${DBG:+"$DBG"} \
    -f objs/Makefile objs/ngx_http_whisper_edge_module.so ) >"$SRC/make.log" 2>&1 \
  || { tail -25 "$SRC/make.log" >&2; die "the module build failed; the tail is above, full log $SRC/make.log"; }

SO="$SRC/objs/ngx_http_whisper_edge_module.so"
[ -f "$SO" ] || die "the build reported success but produced no .so at $SO"
OUT="$HERE/ngx_http_whisper_edge_module.so"
[ "$DEBUG" = 1 ] && OUT="$HERE/ngx_http_whisper_edge_module.debug.so"
cp "$SO" "$OUT"
echo "== built $OUT ($(wc -c <"$SO") bytes)"

if [ "$INSTALL" = 1 ]; then
  # nginx's module path is a compile-time constant, so it is read back out of the flags, never guessed.
  # A distribution can name a path its package does not create: Ubuntu 24.04's nginx 1.24.0 names
  # /usr/lib/nginx/modules and ships no directory there until a module package makes it. A path nginx
  # names is the one it was built to load from, so it is made, 0755 and owned like the directory it is
  # made in. With no --modules-path nginx loads from <prefix>/modules (its own default; the prefix is
  # --prefix, else /usr/local/nginx), and that one is used only if it is there: nginx named no path.
  MODPATH="$(printf '%s' "$ARGS" | sed -n "s/.*--modules-path=\\([^ ']*\\).*/\\1/p")"
  if [ -n "$MODPATH" ]; then
    if [ ! -d "$MODPATH" ]; then
      [ "$(id -u)" = 0 ] || die "nginx's modules path $MODPATH (its --modules-path) does not exist yet; run this with sudo to create it"
      _up=$(dirname -- "$MODPATH"); while [ ! -d "$_up" ]; do _up=$(dirname -- "$_up"); done
      _og=$(stat -c '%u:%g' -- "$_up")
      install -d -m 0755 -o "${_og%%:*}" -g "${_og#*:}" -- "$MODPATH" || die "could not create nginx's modules path $MODPATH"
      echo "   created $MODPATH (nginx's --modules-path; 0755, owned $_og like $_up)"
    fi
  else
    _pf="$(printf '%s' "$ARGS" | sed -n "s/.*--prefix=\\([^ ']*\\).*/\\1/p")"; MODPATH="${_pf:-/usr/local/nginx}/modules"
    [ -d "$MODPATH" ] || die "nginx names no --modules-path, and its default, $MODPATH, does not exist; copy the .so where your load_module line will name it"
  fi
  install -m 0644 "$HERE/ngx_http_whisper_edge_module.so" "$MODPATH/" \
    || die "could not install into $MODPATH (run with sudo)"
  echo "   installed into $MODPATH"
  echo "   a running nginx keeps the module it already loaded across a reload: to load this build, restart it"
  echo "   (systemctl restart nginx, or nginx -s quit and start it again)"
  echo
  echo "   Add this in the MAIN context, above http {}, then reload:"
  echo "     load_module $MODPATH/ngx_http_whisper_edge_module.so;"
else
  echo
  echo "   Next: ./build.sh --install   (or copy the .so into nginx's modules path yourself)"
fi
