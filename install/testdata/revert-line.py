#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
revert-line.py - write a copy of a script with one exact line replaced, for a gate's revert control.

Usage: revert-line.py SRC DST LINE REPLACEMENT

LINE must occur in SRC exactly once; otherwise DST is a byte copy of SRC, so the caller's cmp sees
that the control's edit did not apply and says so instead of passing on nothing.
"""
import sys

src, dst, line, repl = sys.argv[1:5]
s = open(src).read()
if s.count(line + "\n") == 1:
    s = s.replace(line + "\n", repl + "\n")
open(dst, "w").write(s)
