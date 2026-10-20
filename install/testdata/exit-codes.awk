# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# the exit statuses the script itself can end with: `exit N` and the EXIT trap's `_rc=N`, outside every
# quoted string (the helper scripts and the printed undo lines carry their own, which are not the script's)
{ l = $0
  gsub(/'\\''/, "", l); gsub(/'"'"'/, "", l)
  if (inq) { i = index(l, "'"); if (!i) next; l = substr(l, i + 1); inq = 0 }
  gsub(/"([^"\\]|\\.)*"/, "", l)
  out = ""
  while ((i = index(l, "'")) > 0) { out = out substr(l, 1, i - 1); l = substr(l, i + 1); j = index(l, "'"); if (!j) { inq = 1; l = ""; break } l = substr(l, j + 1) }
  out = out l
  sub(/#.*/, "", out)
  while (match(out, /(exit|_rc=)[ ]*[0-9]+/)) { t = substr(out, RSTART, RLENGTH); gsub(/[^0-9]/, "", t); print t; out = substr(out, RSTART + RLENGTH) } }
