# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""Every shell function a script calls is defined before the line that first runs it.

A POSIX shell defines a function when it executes the definition, so a call that runs earlier fails with
"command not found", and under `cmd || other` that failure is silent. This reads the script statically:
the top-level definitions (`name() {` at the first column) with their bodies, the calls in each body and
in the top-level code, and reports every top-level line that calls, directly or through the bodies it
reaches, a function whose definition comes later. Quoted text is not a call; command substitutions
inside double quotes are. A `trap` line registers a handler for later and is not read as a call.

usage: python3 def-order.py <script>     exit 0 when clean, 1 with one line per violation
"""
import re
import sys

# a word as a command could name it: not inside another word, an option (--dry-run), a path, a
# variable ($name, ${name}) or an assignment (name=)
NAME = re.compile(r"(?<![A-Za-z0-9_$\-{/.])([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_\-./=])")
DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{")


def code_of(line):
    """The line with comments and quoted text removed, keeping $( ... ) inside double quotes."""
    out, i, n, dq, depth = [], 0, len(line), False, 0
    while i < n:
        c = line[i]
        if not dq and c == "#" and (i == 0 or line[i - 1] in " \t;|&(") and depth == 0:
            break
        if c == "\\":
            i += 2
            continue
        if not dq and c == "'":
            j = line.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"' and depth == 0:
            dq = not dq
            i += 1
            continue
        if dq and line.startswith("$(", i):
            depth += 1
            out.append(" ")
            i += 2
            continue
        if dq and depth and c == ")":
            depth -= 1
            out.append(" ")
            i += 1
            continue
        if not dq or depth:
            out.append(c)
        i += 1
    return "".join(out)


def main(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    defs, bodies, top = {}, {}, []           # name -> line; name -> [code]; [(line, code)]
    i = 0
    while i < len(lines):
        m = DEF.match(lines[i])
        if m:
            name, start = m.group(1), i + 1
            defs.setdefault(name, start)
            rest = code_of(lines[i][m.end():])
            if rest.rstrip().endswith("}"):
                bodies[name] = [rest]
                i += 1
                continue
            body = [rest]
            i += 1
            while i < len(lines) and not lines[i].startswith("}"):
                body.append(code_of(lines[i]))
                i += 1
            bodies[name] = body
            i += 1
            continue
        # a trap names a handler it runs later, at a signal or the exit, not at this line
        if not re.match(r"^\s*trap\s", lines[i]):
            top.append((i + 1, code_of(lines[i])))
        i += 1
    calls = {n: {t for b in body for t in NAME.findall(b) if t in defs and t != n} for n, body in bodies.items()}

    def reach(name, seen):
        for c in calls.get(name, ()):
            if c not in seen:
                seen.add(c)
                reach(c, seen)
        return seen

    bad = []
    for ln, code in top:
        for t in set(NAME.findall(code)):
            if t not in defs:
                continue
            for f in {t} | reach(t, set()):
                if defs[f] > ln:
                    via = "" if f == t else " (through %s)" % t
                    bad.append("line %d calls %s%s, defined at line %d" % (ln, f, via, defs[f]))
    for b in sorted(set(bad), key=lambda s: int(s.split()[1])):
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
