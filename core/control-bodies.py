#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
Every control build a gate names must have a body: a WE_MOD_TEST_* name that reaches a compiler with no
#if, #ifdef, #ifndef or #elif reading it builds the production code, so the row it should fail passes
and the control reads as caught or dark for nothing.

Two rules, over the edge tree given (default: the directory above this script):
  1. every WE_MOD_TEST_* token in a file of the tree has a body in the sources the gate naming it compiles:
     for a server's gate, the shipped core (whisper_edge and we_* in core/, never a test harness, fuzzer or
     the cachegrind driver) and that server's module; for the core's own files, any core source
     (core/*.c, core/*.h outside we_module.h's guard list, core/gate/*.c); at the edge root, the shipped
     core and every server's module;
  2. every name we_module.h's guard list declares has a body in the core or in a server's module; the
     servers' own (SERVER_OWNED below) are exempt where this tree's copy of that server predates the
     body, and rule 1 holds each to its body wherever its gate builds it.
The WE_MOD_TEST_ prefix is the control defines' namespace and nothing else's: every token carrying it,
in any file of the tree (a build line, a probe, a comment, an environment variable, a sentence), is held
to rule 1, so no name means a define in one place and something else in another.
Exit 0 and one ok line, or 1 naming every name without a body and where it was named.
"""
import os
import re
import stat
import subprocess
import sys

SERVER_OWNED = {
    "DROP_LOG": "apache", "MPM_SLOT": "apache", "NO_RELEASE": "apache", "SHARD_OWNER": "apache",
    "LEXICAL": "nginx apache", "INLINE_HANDLER": "litespeed", "LEGACY_HOLD": "litespeed",
    "LEGACY_LOOP_FREES": "litespeed",
}
SERVERS = ("nginx", "apache", "litespeed")
PREFIX = "WE_MOD_TEST" + "_"                 # written split, so this guard holds no computed name itself
NAME = re.compile(PREFIX + r"([A-Z0-9_]+)")
COND = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif)\b")


def logical_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        buf = ""
        for line in f:
            line = line.rstrip("\n")
            if line.endswith("\\"):
                buf += line[:-1] + " "
                continue
            yield buf + line
            buf = ""
        if buf:
            yield buf


def bodies(paths, header):
    out = set()
    for p in paths:
        in_guard = False
        for line in logical_lines(p):
            if p == header and line.startswith("#if !defined(WE_MOD_CONTROL_BUILD)"):
                in_guard = True              # the guard list: a declaration, not a body
                continue
            if COND.match(line) and not in_guard:
                out.update(NAME.findall(line))
            in_guard = False
    return out


def tree_files(edge):
    """the files the guard reads: exactly the tracked ones (git ls-files), the tree that ships and is reviewed,
    so an untracked fetch beside it (the LiteSpeed SDK's dangling links) is never opened; in an export with no
    repository, every file present, since an export holds only what was tracked"""
    try:
        out = subprocess.run(["git", "-C", edge, "ls-files", "-z", "--", "."], check=True, capture_output=True).stdout
        tracked = sorted(os.path.join(edge, f) for f in out.decode("utf-8", "replace").split("\0") if f)
        if tracked:
            return tracked
        raise OSError("no tracked file: an export inside another repository")   # never a vacuous pass
    except (OSError, subprocess.CalledProcessError):
        # the walk keeps to what an export ships: no dot directories (.git, .testtmp, the gates' scratch, which
        # holds FIFOs a gate plants), no build output, and only regular files, never opening a FIFO, a socket
        # or a device, whose open can block for ever
        files = []
        for root, dirs, names in os.walk(edge):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("target", "objs", "sdk")]
            for n in names:
                f = os.path.join(root, n)
                try:
                    if stat.S_ISREG(os.stat(f).st_mode):
                        files.append(f)
                except OSError:
                    files.append(f)          # dangling or unreadable: readable() names it
        return sorted(files)


TREE = []
UNREADABLE = []


def readable(path):
    """a tracked file the guard cannot open is an error with its name, never a crash and never a skip; and
    nothing that is not a regular file is ever opened (a FIFO's open waits for a writer that never comes)"""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            UNREADABLE.append("%s: not a regular file" % path)
            return False
        with open(path, "rb"):
            return True
    except OSError as e:
        UNREADABLE.append("%s: %s" % (path, e.strerror or e))
        return False


def c_files(d):
    return [f for f in TREE if os.path.dirname(f) == d and f.endswith((".c", ".h")) and readable(f)]


# a name built at run time (the prefix followed by $x, ${x}, %s, $(x), or a string joined to it) hides what a
# gate builds from this guard, so it is refused wherever it is written
COMPUTED = re.compile(PREFIX + r"(?:[A-Z0-9_]*[$%{(]|[A-Z0-9_]*['\"]\s*[+%])")


def computed(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if "/cb-" in line:
                continue                    # this guard's own plants, in the Makefile that runs it
            if COMPUTED.search(line):
                out.append(i)
    return out


def file_names(path):
    """every WE_MOD_TEST_* token in a file: the namespace is the control defines' alone, so each is one"""
    names = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    for line in text.split("\n"):
        if "/cb-" in line:
            continue                        # this guard's own two plants, in the Makefile that runs it
        names.update(NAME.findall(line))
    if os.path.basename(path) == "module-controls.sh":
        names.update(n for n in re.findall(r'^\s*"([A-Z0-9_]+):FAIL', text, re.M) if not n.startswith("WE_"))
    return names


def main():
    edge = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
    core = os.path.join(edge, "core")
    TREE[:] = tree_files(edge)
    header = os.environ.get("WE_CB_HEADER", os.path.join(core, "we_module.h"))   # the guard's own control plants one
    core_src = [header if f == os.path.join(core, "we_module.h") else f
                for f in c_files(core) + c_files(os.path.join(core, "gate"))]
    core_bodies = bodies(core_src, header)
    # the core a server module compiles: its shipped sources only (whisper_edge, we_*), never a test harness,
    # a fuzzer or the cachegrind driver, which no module links
    shipped = [f for f in core_src if os.path.dirname(f) == core
               and re.match(r"(whisper_edge|we_[a-z0-9_]+)\.[ch]$", os.path.basename(f))]
    shipped_bodies = bodies(shipped, header)
    server_bodies = {s: bodies(c_files(os.path.join(edge, s)), header) for s in SERVERS}
    bad = []

    # rule 1: what each gate names
    gates = [f for f in TREE if (f.endswith((".sh", ".c", ".h", ".py", ".md", ".txt", ".conf", ".tsv"))
                                 or os.path.basename(f) == "Makefile") and readable(f)]
    if os.environ.get("WE_CB_EXTRA_GATE"):
        gates.append(os.environ["WE_CB_EXTRA_GATE"])  # the guard's own control: a gate building a name no source reads
    for g in sorted(gates):
        rel = os.path.relpath(g, edge) if g.startswith(edge + os.sep) else os.path.basename(g)
        if g == os.environ.get("WE_CB_EXTRA_GATE") and os.environ.get("WE_CB_EXTRA_GATE_AS"):
            rel = os.environ["WE_CB_EXTRA_GATE_AS"]   # the plant read as a gate of that directory
        top = rel.split(os.sep)[0]
        at_root = os.sep not in rel
        beside = server_bodies[top] if top in SERVERS else set().union(*server_bodies.values())
        # a server's gate builds that server's module over the shipped core; the core's own gates build the
        # harnesses too, so a body there counts for them
        core_here = shipped_bodies if top in SERVERS or at_root else core_bodies
        for ln in computed(g):
            bad.append("a computed control name at %s:%d: name the define in full, so the guard can read it" % (rel, ln))
        for n in sorted(file_names(g)):
            if n not in core_here and n not in beside and not (top not in SERVERS and n in SERVER_OWNED):
                bad.append("%s%s: named in %s, no body in %s or beside it" % (
                    PREFIX, n, rel, "the shipped core" if top in SERVERS or at_root else "the core"))

    # rule 2: what the guard list declares
    declared = set()
    for line in logical_lines(header):
        if line.startswith("#if !defined(WE_MOD_CONTROL_BUILD)"):
            declared.update(NAME.findall(line))
    any_server = set().union(*server_bodies.values())
    for n in sorted(declared):
        if n in SERVER_OWNED or n in core_bodies or n in any_server:
            continue
        bad.append("%s%s: declared in we_module.h's guard list, no body in the core" % (PREFIX, n))

    for u in sorted(set(UNREADABLE)):
        bad.append("a tracked file the guard cannot read: %s" % os.path.relpath(u.split(": ")[0], edge) + u[len(u.split(": ")[0]):])
    if bad:
        for b in bad:
            print("FAIL control bodies: " + b)
        print("FAIL control bodies: %d finding(s)" % len(bad))
        return 1
    print("ok   control bodies: every WE_MOD_TEST_ token in the tree, and every name the guard list declares, is a define with a body "
          "(%d declared, %d server-owned)" % (len(declared), len(SERVER_OWNED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
