# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""A command that acts on the host never ends a set -e script from the tail of an AND list.

Under set -e a statement `a && b` ends the script when `b` fails (only `a`'s failure is forgiven), so
`[ "$SYSD" = 1 ] && systemctl start nginx` ended a gate run when the start failed. This reads a script
statically, joins continued lines, splits each line into its top-level statements, and names every one
that is an AND list with no `||` after it whose last command is one that acts on the host and can fail:
systemctl, a server's own control (nginx, apachectl, apache2ctl, lswsctrl), mount, umount, rm, mv, cp,
ln, mkdir, chmod, chown, chattr, setfacl, kill, useradd, runuser, eval, curl. Such a command belongs in
a row that names what failed, or ends in `|| :` where its failure is not the row's business.

usage: python3 and-tail.py <script>     exit 0 when clean, 1 with one line per finding
"""
import re
import sys

OPS = {"systemctl", "nginx", "/usr/sbin/nginx", "apachectl", "apache2ctl", "lswsctrl", "mount", "umount", "rm",
       "mv", "cp", "ln", "mkdir", "chmod", "chown", "chattr", "setfacl", "kill", "useradd", "runuser", "eval",
       "curl"}


def strip(line):
    """The line with quoted text blanked (kept the same length) and a trailing comment removed."""
    out, i, q = [], 0, None
    while i < len(line):
        c = line[i]
        if q is None and c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        if c == "\\" and i + 1 < len(line):
            out.append("xx")
            i += 2
            continue
        if q is None and c in "'\"":
            q = c
            out.append(" ")
        elif q is not None and c == q:
            q = None
            out.append(" ")
        elif q is not None:
            out.append(" ")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def main(path):
    raw = open(path, encoding="utf-8").read().split("\n")
    logical, start, buf = [], 0, ""
    for n, line in enumerate(raw, 1):
        s = strip(line)
        if not buf:
            start = n
        cont = s.rstrip().endswith("\\")
        buf += (" " + s.rstrip()[:-1]) if cont else (" " + s)
        nxt = strip(raw[n]).lstrip() if n < len(raw) else ""
        if cont or nxt.startswith(("&&", "||")):
            continue
        logical.append((start, buf))
        buf = ""
    bad = []
    for ln, text in logical:
        t = text.strip()
        if "&&" not in t:
            continue
        depth, cur, parts = 0, "", []
        for c in t:                                  # top-level statements only: not inside ( ) or { }
            if c in "({":
                depth += 1
            elif c in ")}":
                depth -= 1
            if c == ";" and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += c
        parts.append(cur)
        for st in (p.strip() for p in parts):
            if "&&" not in st or "||" in st or st.startswith(("if ", "while ", "until ", "elif ", "{", "(")):
                continue
            depth, last, k = 0, "", 0
            tail = st[st.rfind("&&") + 2:].strip()
            if tail.startswith(("{", "(")) or "|" in tail:
                continue
            words = tail.split()
            w = words[0].split("/")[-1] if words else ""
            if words and (words[0] in OPS or w in OPS):
                bad.append("line %d: `%s` ends an AND list with %s, which can fail and end the run under set -e"
                           % (ln, re.sub(r"\s+", " ", st)[:100], words[0]))
    for b in bad:
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
