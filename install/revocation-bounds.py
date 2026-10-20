#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
revocation-bounds.py - how long an edge keeps its tenant plane after its feed key is revoked, derived
from the constants the edge ships, in one place.

The README's sentence is printed from here, and the install gate fails if the README says anything
else, so the published figures cannot drift from the mechanism.

Read from the shipped files:
    P  the keyed timer's period             whisper-edge-refresh-keyed.timer   OnCalendar=*:0/15  (900 s)
    J  its randomized delay                 whisper-edge-refresh-keyed.timer   RandomizedDelaySec (300 s)
    A  its accuracy                         whisper-edge-refresh-keyed.timer   AccuracySec        (1 s)
    F  the single-node floor                whisper-edge-refresh               REVOKE_POLL_FLOOR  (900 s)
    T  one request's ceiling                whisper-edge-refresh               KEYED_MAX_TIME     (120 s)
    B  one run's budget                     whisper-edge-refresh               KEYED_BUDGET       (1,300 s)
and two constants from outside the edge:
    M  the revocation memo                  the feed server's memo             30 s
    N  the addresses whisper.online has     getent ahosts, 12 Oct 2026         3 (two A, one AAAA)

A run asks each address in turn until one answers for another node, so a run that meets dead addresses
lasts up to min(N x T, B). Both observations are stamped with their run's start, the time this model
uses, so the floor is measured start to start and a dead address delays only the run's end.

The model. A key is revoked at a time uniform over the schedule; a node answers KEY_REVOKED once the
memo has passed. The keyed runs start at k*P + U_k, each U_k uniform on [0, J] and drawn afresh at every
elapse (systemd re-draws RandomizedDelaySec per iteration).

Two nodes reachable: the first run after the memo asks both and removes the plane. Its wait W from a
uniform time to the next run has
    E[W] = P/2 + J^2/(12 P)                      (458 s with P = 900, J = 300)
    max W = P + J
so typically M + E[W], at most M + (P + J) + A + R, with R = min(N x T, B) the longest run.

One node reachable: the first run records the observation; a later run removes the plane only when it
starts at least F after it. With U_a the first run's delay, distributed g(u) = (u/P + 1 - J/(2P)) / J on
[0, J] (a run late in its slot is the first after a uniform time more often), the next run is
G = P + U_b - U_a later and completes when U_b >= s, s = clamp(F - P + U_a, 0, J); otherwise the run
after that, 2P + U_c - U_a later, does (it is at least 2P - J >= F later, which the derivation requires).
    E[extra | U_a = u] = ((P - u)(J - s) + (J^2 - s^2)/2) / J + (s / J)(2P + J/2 - u)
and E[extra] is its integral against g, computed exactly here (a piecewise polynomial, integrated by
Simpson's rule on each piece, which is exact for it). The worst extra is P + J when F <= P - J, else
2P + J. So typically M + E[W] + E[extra], at most M + (P + J) + A + max extra + A + R. The first run's
own request time is not a term: its observation carries the run's start, which the extra wait is
measured from, so only the second run's length R follows the floor.

The maxima are bounds, not suprema: they add the worst wait to the first run and the worst extra wait
independently, while one timer cannot reach both (the joint supremum is near M + 3P + J plus the run's
own time). The typical figures assume every address answers.

Usage: revocation-bounds.py [--addresses N] [--json | --note]
    (no option: the README sentence; --json: the figures and every input, B and N included; --note: the
    README's statement of the inputs. --addresses replaces the default N, the VIP's published count.)
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MEMO = 30  # the feed server's revocation memo, 30 s
ADDRS = 3  # whisper.online's addresses (two A, one AAAA), read with getent ahosts on 12 Oct 2026


def shipped():
    timer = open(os.path.join(HERE, "whisper-edge-refresh-keyed.timer")).read()
    script = open(os.path.join(HERE, "whisper-edge-refresh")).read()
    m = re.search(r"^OnCalendar=\*:0/(\d+)$", timer, re.M)
    if not m:
        sys.exit("revocation-bounds: the keyed timer's OnCalendar is not *:0/N")
    P = int(m.group(1)) * 60
    J = int(re.search(r"^RandomizedDelaySec=(\d+)$", timer, re.M).group(1))
    A = int(re.search(r"^AccuracySec=(\d+)s$", timer, re.M).group(1))
    F = int(re.search(r"^REVOKE_POLL_FLOOR=(\d+)$", script, re.M).group(1))
    T = int(re.search(r"^KEYED_MAX_TIME=(\d+)$", script, re.M).group(1))
    B = int(re.search(r"^KEYED_BUDGET=(\d+)$", script, re.M).group(1))
    return P, J, A, F, T, B


def simpson(f, a, b, n=2000):
    if b <= a:
        return 0.0
    h = (b - a) / n
    s = f(a) + f(b)
    for i in range(1, n):
        s += (4 if i % 2 else 2) * f(a + i * h)
    return s * h / 3


def bounds(P, J, A, F, T, B, M=MEMO, N=ADDRS):
    if not 0 < J < P or F > 2 * P - J:
        sys.exit("revocation-bounds: the derivation needs 0 < J < P and F <= 2P - J")
    EW = P / 2 + J * J / (12 * P)

    def g(u):
        return (u / P + 1 - J / (2 * P)) / J

    def extra(u):
        s = min(max(F - P + u, 0), J)
        return ((P - u) * (J - s) + (J * J - s * s) / 2) / J + (s / J) * (2 * P + J / 2 - u)

    # the pieces on which s = clamp(F - P + u, 0, J) is one polynomial
    cuts = sorted({0.0, float(J), *[x for x in (P - F, P - F + J) if 0 < x < J]})
    Eextra = sum(simpson(lambda u: extra(u) * g(u), a, b) for a, b in zip(cuts, cuts[1:]))
    max_extra = P + J if F <= P - J else 2 * P + J
    R = min(N * T, B)  # the longest run: every address asked, each up to T, within the budget
    return {
        "two_typical": M + EW,
        "two_max": M + (P + J) + A + R,
        "one_typical": M + EW + Eextra,
        "one_max": M + (P + J) + A + max_extra + A + R,
        "constants": {"P": P, "J": J, "A": A, "F": F, "T": T, "B": B, "M": M, "N": N},
    }


def minutes_typical(sec):
    return int(round(sec / 60.0))


def minutes_max(sec):
    return int(-(-sec // 60))


def sentence(b):
    c = b["constants"]
    return ("typically within about %d minutes when the edge can reach both nodes and about %d minutes "
            "otherwise (an IPv6-only edge, whose second observation waits for a keyed poll at least %d s "
            "after the first), at most %d and %d minutes, plus the module's reload" % (
                minutes_typical(b["two_typical"]), minutes_typical(b["one_typical"]), c["F"],
                minutes_max(b["two_max"]), minutes_max(b["one_max"])))


def note(b):
    c = b["constants"]
    return ("derived from the keyed timer (every %d s with up to %d s of jitter, drawn afresh each time), "
            "that %d s floor, the %d s request ceiling over the %s addresses whisper.online has, and the "
            "server's %d s memo" % (c["P"], c["J"], c["F"], c["T"],
                                    {2: "two", 3: "three", 4: "four"}.get(c["N"], str(c["N"])), c["M"]))


if __name__ == "__main__":
    args = sys.argv[1:]
    n = ADDRS
    if len(args) >= 2 and args[0] == "--addresses":
        if not args[1].isdigit() or int(args[1]) < 1:
            sys.exit("revocation-bounds: --addresses needs a count of at least 1")
        n = int(args[1]); args = args[2:]
    b = bounds(*shipped(), N=n)
    arg = args[0] if args else ""
    if arg == "--json":
        print(json.dumps(b, sort_keys=True))
    elif arg == "--note":
        print(note(b))
    elif arg == "":
        print(sentence(b))
    else:
        sys.exit("revocation-bounds: unknown option %s (use [--addresses N] [--json | --note])" % arg)
