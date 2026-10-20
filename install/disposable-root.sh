#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# Run a command as root on a box that is thrown away afterwards, on a host that has no container runtime:
# a private mount namespace (and pid namespace) over an overlay of /, so everything the command writes
# under /etc, /var, /usr and the rest lands in a scratch upper layer that is deleted when it exits, and
# the processes it starts (a web server under test) die with the namespace. The current directory's tree
# is bind-mounted at the same path, so the command runs the checkout it was given.
#
#   sudo ./disposable-root.sh '<command>'     the command's exit status is this script's
#
# The installer gate's real rows need exactly this: root, real /etc, nothing left on the host. systemd is
# not PID 1 inside, so the rows that need a unit environment say SKIPPED there, by name.
set -eu
# grep_any [grep options] PATTERN: grep -q's answer, from a grep that reads all of its input, so the
# writer piped into it never takes SIGPIPE and no pipefail can turn a match into a miss
grep_any() { grep -c "$@" >/dev/null; }
# the resolver, by its content: on a systemd-resolved host (Ubuntu's default) /etc/resolv.conf is a link to
# /run/systemd/resolve/stub-resolv.conf, and /run in the root is a fresh tmpfs, so the link the overlay
# carries would dangle and every name fail to resolve ("Temporary failure resolving", from apt, far from the
# cause). The host's file is read through the link and written into the root as a plain file; with no
# nameserver to read, it says so and fails, and the run stops before the command.
put_resolver() { # <root>
  _rf=${DISPOSABLE_ROOT_RESOLV:-/etc/resolv.conf}
  _rv=$(cat -- "$_rf" 2>/dev/null || :)
  if ! printf '%s\n' "$_rv" | grep_any '^[[:space:]]*nameserver[[:space:]]'; then
    echo "disposable-root: $_rf names no nameserver (read through any link: $(readlink -f -- "$_rf" 2>/dev/null || echo unreadable)), so nothing inside could resolve a name; fix the host's resolver first" >&2
    return 1
  fi
  rm -f -- "$1/etc/resolv.conf"
  printf '%s\n' "$_rv" > "$1/etc/resolv.conf"; chmod 0644 "$1/etc/resolv.conf"
}
# the resolver step alone, into a directory standing for the root (the gate's row; no root needed)
if [ "${1:-}" = --put-resolver ] && [ $# = 2 ]; then put_resolver "$2" && exit 0; exit 2; fi
[ "$(id -u)" = 0 ] || { echo "disposable-root: run as root" >&2; exit 2; }
[ $# = 1 ] || { echo "usage: disposable-root.sh '<command>'" >&2; exit 2; }
if [ "${DISPOSABLE_ROOT_INNER:-0}" != 1 ]; then
  exec env DISPOSABLE_ROOT_INNER=1 unshare --mount --pid --fork --propagation private "$0" "$1"
fi
TREE=$(pwd)
S=$(mktemp -d "${DISPOSABLE_ROOT_SCRATCH:-/var/tmp}/disposable-root.XXXXXX")
mkdir "$S/up" "$S/wk" "$S/root"
mount -t overlay overlay -o "lowerdir=/,upperdir=$S/up,workdir=$S/wk" "$S/root"
mount -t proc proc "$S/root/proc"
# the namespace is private already (unshare --propagation private); each recursive bind is made a slave
# too, so no unmount below can ever reach the host's /sys or /dev, whatever the namespace was made with
mount --rbind /sys "$S/root/sys" && mount --make-rslave "$S/root/sys"
mount --rbind /dev "$S/root/dev" && mount --make-rslave "$S/root/dev"
mount -t tmpfs -o mode=0755 tmpfs "$S/root/run"
if ! put_resolver "$S/root"; then
  umount -R "$S/root" 2>/dev/null || umount -l "$S/root" 2>/dev/null || true
  mountpoint -q "$S/root" || { rm -rf --one-file-system "$S/up" "$S/wk"; rmdir "$S/root" "$S" 2>/dev/null || :; }
  exit 2
fi
mount -t tmpfs -o mode=1777 tmpfs "$S/root/tmp"
mkdir -p "$S/root$TREE"
mount --bind "$TREE" "$S/root$TREE" && mount --make-slave "$S/root$TREE"
rc=0
chroot "$S/root" /bin/sh -c 'cd "$1" && exec /bin/sh -c "$2"' sh "$TREE" "$1" || rc=$?
# the namespace's mounts go with it; the scratch layer is removed here, and only once nothing is mounted
# on the root: while it is (a detach that failed), the tree under it holds the bind-mounted checkout and
# the host's /dev, so nothing is removed and the line says where the scratch is. The removal never leaves
# its own filesystem either way.
umount -R "$S/root" 2>/dev/null || umount -l "$S/root" 2>/dev/null || true
if mountpoint -q "$S/root" || grep -qF " $S/root" /proc/self/mounts; then
  echo "disposable-root: $S/root is still mounted, so the scratch layer was left in place; remove it once nothing is mounted there: umount -R $S/root; rm -rf --one-file-system $S" >&2
else
  rm -rf --one-file-system "$S/up" "$S/wk"
  rmdir "$S/root" "$S" 2>/dev/null || echo "disposable-root: $S was not empty after the scratch layer went; left in place" >&2
fi
exit "$rc"
