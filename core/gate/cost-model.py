#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
"""cost-model.py - the arithmetic behind cachegrind-gate.sh's policy-evaluator slots.

cachegrind counts instructions exactly, so the per-request cost of the evaluator is a linear function of
what a request executes, and the constants of that function can be SOLVED, not fitted. This file does the
three pieces of arithmetic the gate needs, in exact rationals, and nothing else:

  solve   the identifiable basis (BASIS below, and why it is not POLICY.md 3.7's list). Each basis row is a
          program whose per-request instruction count is measured and whose executed count vector is
          known, and the rows must determine every constant of the basis: the rank check FAILS the gate
          if they do not, naming the constants left undetermined. The rows not marked held=1 are solved
          exactly; every row marked held=1 is HELD OUT and must be predicted EXACTLY (cachegrind counts
          exactly, and each measurement is a difference of two request counts, so a per-run constant
          cannot hide in it). A held-out row off by one instruction fails the gate: the basis is then
          not the cost function, whatever it solves to.

  sound   the soundness inequality of the composed bound (POLICY.md 3.7), per slot: measured instructions per
          request <= the sum over every named term of count times constant, and >= 0.8 times that sum
          (the tightness floor). Every term is named on the line, so a slot that exercises a term nobody
          measured fails by name instead of being priced at zero.

  worst   the instruction maximum over the FEASIBLE count vectors under the program limits (256 rules,
          4,096 operations and 8,448 instructions per context, 64 operations per rule, nesting 16), for
          the solved constants of one toolchain, with each atom's OUTCOME chosen by where the nots go.
          The checked-in worst-case fixture must attain it.

  gate    all of the above for one toolchain's measured evaluator rows: every constant derived (the basis,
          c_fill per schema as the slope less the find, c_prestage less its finds, every L), each held to its committed
          value, the soundness inequality on every slot that names its terms, the worst fixture held to
          the enumerated maximum.

  selftest  the negative controls of the three: a planted system is recovered exactly; a rank-deficient
          row set is refused naming its undetermined constants; a measurement above the bound, and one
          below the tightness floor, are each refused; a fixture one atom short of the enumerated maximum
          is refused; POLICY.md 3.7's own basis over legal programs is refused by the rank check. selftest
          exits non-zero unless every control behaves.

  module  the module rows (gate/cg_driver.c, the modules' slots). c_harness_view first, the harness's own
          view stores: evaluator-views@1 less its static-views twin, one program and one path, so the figure
          is exact (the default stream's own pair is printed as a note: the evaluator is inlined into each
          harness function and compiled differently in each, so over that stream's many request shapes
          the pair differs by more than the view stores). Then every module row less its evaluator twin,
          plus that, is the module's work alone. It is so by construction: the module rows and their twins
          run ONE noinline compiled copy of the decision (cg_decide in gate/cg_driver.c), so the decision's
          instructions are the same instructions in both, plus the call into the copy and minus one
          inlining. Before that copy each inlined the decision into its own function, the two compiled one
          instruction apart on some paths, and the basis read that as the module's cost. The module's
          inlined shape is held by hotpath-gate.sh's hpmod; the gate's CS, CM and CX controls show a cost
          regression inside the copy, in the module's own path, and a held-out row one instruction off
          are each still refused. That work is a linear function of MOD_BASIS: c_mod_fixed, c_view per
          bound plane a program references and c_view@tenant for the tenant's (its mask bit is a constant
          the compiler may fold: clang 18 on x86_64 reads it 2 cheaper than a program's view), and for each
          of the eight bitmap words w, floor0 to floor3 and ctx0 to ctx3, c_word@w for the word non-empty
          over empty and c_count@w per bit set in it, because the scan over the words is unrolled and each
          word's copy has its own cost (on x86_64 gcc 13.3 the floor's words 1 to 3 cost 15 over the first
          word's figure; on aarch64 gcc a floor bit costs 9 against a context bit's 11), c_cnt_rule and
          c_cnt_exempt for the decision's one direct count (two code paths); solved from the rows not
          marked held and held exactly on the rest, as the evaluator's basis is. Then the remainders
          c_export, c_export_all, c_lazy, c_prerewrite and c_prerewrite@1: a row less every term it
          names, over the coefficient the row gives its own constant. A twin:<slot> or slot:<slot> term
          is that slot's own measurement, with its sign.

Inputs are tab-separated, `#` comments allowed. A measurement is given as `total/requests` (the
cachegrind Ir total of the run and the request count), so nothing is rounded before it is solved.
"""

import sys
from fractions import Fraction

# THE IDENTIFIABLE BASIS, in this order everywhere.
#
# POLICY.md 3.7's list (an atom constant per kind, c(NOT), an `and` link, an `or` link and a per-rule term)
# is NOT identifiable, and this file's selftest proves it: a rule's connectives form a binary tree over
# its atoms, so in every execution with no jump taken, links = atoms - rules visited, whatever the shape,
# and that identity holds across every legal program, so no set of rows can separate an atom from a link
# from a rule. The basis below is the same cost function with the identity factored out, and it carries
# what the measurements showed that list leaves out: an atom's cost depends on its OUTCOME
# (`is unknown` TRUE runs the NULL-view path, 3 instructions more than FALSE under gcc 13 at -O2), and a
# rule's ending depends on how it ends (a `log` that fires, a `deny` that fires and ends the request, or
# FALSE).
#
#   fixed       the per-request cost every basis row pays (the harness, the pre-stage, the floor program
#               and its fills: the basis rows run on one address, so no context atom fills anything)
#   <kind>.T    one atom of that kind evaluating TRUE, TOGETHER with the `and` link that would follow it
#   <kind>.F    the same evaluating FALSE
#   NOT         one NOT instruction (a unary `not`, or the extra NOT of `!=` and `is not unknown`)
#   or_link     what an `or` link (OR plus a JT not taken) costs beyond an `and` link
#   end         a rule that ends FALSE (END, the rule's overhead) LESS one `and` link
#   fire_log    a `log` rule that ends TRUE and fires, LESS one `and` link
#   fire_deny   a `deny` rule that ends TRUE under mode deny, ending the request, LESS one `and` link
#   jump        a JF or JT that is taken: what it runs, and what it does not (the operands it skips are
#               not executed, so they are not counted)
#
# Check: an and-chain of a atoms ending FALSE is (a-1)*c(k.T) + c(k.F) + c(end) =
# a*atom + (a-1)*and + END, the form of POLICY.md 3.7; an or-chain adds (a-1)*or_link on top.
ATOMS = ["BOOL", "SEV", "EQ8", "EQ16", "EQ32", "INSET_ENUM", "INSET_COUNTRY", "INSET_ASN", "ISUNK"]
OUTCOMES = ["T", "F"]
BASIS_PASS = (["fixed"] + ["%s.%s" % (k, o) for k in ATOMS for o in OUTCOMES]
              + ["NOT", "or_link", "end", "fire_log", "fire_deny", "jump"])
# every term twice: as the context pass runs it, and as the floor pass does (`<term>@floor`), because an
# operation's cost depends on the pass (gcc 13: about an instruction an atom dearer in the floor pass)
BASIS = BASIS_PASS + [n + "@floor" for n in BASIS_PASS]
# POLICY.md 3.7's own list, kept so the selftest can show the rank check refusing it
PLAN_BASIS = ["fixed"] + ATOMS + ["NOT", "and_link", "or_link", "rule"]
# THE MODULE BASIS (core/gate/cg_driver.c, the modules' slots): what a module row costs over its twin
MOD_WORDS = ["%s%d" % (p, w) for p in ("floor", "ctx") for w in range(4)]
MOD_BASIS = (["c_mod_fixed", "c_view", "c_view@tenant", "c_cnt_rule", "c_cnt_exempt"]
             + ["c_word@" + w for w in MOD_WORDS] + ["c_count@" + w for w in MOD_WORDS])
MOD_REMAINDERS = [("module-export", "c_export"), ("module-export-all", "c_export_all"),
                  ("module-export-prestage", "c_lazy"), ("module-var-prerewrite", "c_prerewrite"),
                  ("module-var-prerewrite@1", "c_prerewrite@1")]

# The planes of each fill schema (the format-1 reputation plane; the two routing-schema planes; the
# membership planes), for c_fill:<schema> = the costliest of them.
SCHEMA_PLANES = {"format1": ["reputation"], "routing": ["routing", "registry"],
                 "membership": ["tor", "rpki-unreachable", "anonymizer", "threat", "tenant"]}

# The limits the verifier refuses at (POLICY.md section 2.1), per context.
MAX_RULES = 256
MAX_OPS = 4096
MAX_OPS_RULE = 64
MAX_INSTR = 8448
# atom kinds that have a one-op form compiling to one more instruction: `!=` is EQ*;NOT, and
# `is not unknown` is ISUNK;NOT (an instruction, not an operation)
NEGATABLE = {"EQ8", "EQ16", "EQ32", "ISUNK"}


class GateError(Exception):
    pass


def num(s):
    if isinstance(s, (Fraction, int)):
        return Fraction(s)
    s = s.strip()
    if "/" in s:
        a, b = s.split("/", 1)
        return Fraction(int(a), int(b))
    return Fraction(s)


def read_table(path):
    """Rows of a TSV with a `#`-prefixed header line naming the columns."""
    header, rows = None, []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                cols = line[1:].strip().split("\t")
                if len(cols) > 1:
                    header = [c.strip() for c in cols]
                continue
            if header is None:
                raise GateError("%s: data before a header line" % path)
            f = line.split("\t")
            if len(f) != len(header):
                raise GateError("%s: %d fields where the header has %d: %s" % (path, len(f), len(header), line))
            rows.append(dict(zip(header, f)))
    return rows


def rank_select(vectors):
    """Gaussian elimination over the rationals. Returns (rank, the indices of a maximal independent
    subset in input order, and the reduced pivot rows)."""
    pivots = []          # (pivot column, reduced row)
    chosen = []
    for idx, v in enumerate(vectors):
        r = list(v)
        for col, p in pivots:
            if r[col] != 0:
                k = r[col] / p[col]
                r = [a - k * b for a, b in zip(r, p)]
        nz = next((c for c, a in enumerate(r) if a != 0), None)
        if nz is not None:
            pivots.append((nz, r))
            chosen.append(idx)
    return len(pivots), chosen, pivots


def undetermined(vectors, names):
    """The basis constants the rows do not determine: e_i is outside the row space."""
    rank, _, _ = rank_select(vectors)
    out = []
    for i, n in enumerate(names):
        e = [Fraction(1 if j == i else 0) for j in range(len(names))]
        r2, _, _ = rank_select(vectors + [e])
        if r2 > rank:
            out.append(n)
    return out


def solve_square(a, b):
    """Exact solve of a non-singular square system."""
    n = len(a)
    m = [list(row) + [rhs] for row, rhs in zip(a, b)]
    for c in range(n):
        p = next(r for r in range(c, n) if m[r][c] != 0)
        m[c], m[p] = m[p], m[c]
        for r in range(n):
            if r != c and m[r][c] != 0:
                k = m[r][c] / m[c][c]
                m[r] = [x - k * y for x, y in zip(m[r], m[c])]
    return [m[i][n] / m[i][i] for i in range(n)]


def solve(rows, out=sys.stdout, basis=None):
    """Solve the rows not marked held=1; assert every held=1 row is predicted exactly. With no row marked,
    the first full-rank subset in the given order is solved (the selftest's planted systems)."""
    basis = BASIS if basis is None else basis
    # the terms the rows name: a basis term no row mentions is not part of this system (the floor-pass
    # twins when only context-pass rows were measured), and a term a row mentions must be determined
    named = set(k for r in rows for k in r if k not in ("slot", "measured", "held") and num(r[k]) != 0)
    basis = [n for n in basis if n in named or n == "fixed"]
    for r in rows:
        extra = [k for k in r if k not in basis and k not in ("slot", "measured", "held") and num(r[k]) != 0]
        if extra:
            raise GateError("%s names %s, which is not in the basis" % (r["slot"], ", ".join(sorted(extra))))
    vectors = [[num(r.get(n, "0")) for n in basis] for r in rows]
    meas = [num(r["measured"]) for r in rows]
    solvable = [i for i, r in enumerate(rows) if r.get("held", "0") in ("0", "")]
    missing = undetermined([vectors[i] for i in solvable], basis)
    if missing:
        raise GateError("RANK: the basis rows do not determine %s (rank %d of %d); add a row whose count "
                        "vector moves them" % (", ".join(missing), rank_select([vectors[i] for i in solvable])[0],
                                               len(basis)))
    _, chosen_sub, _ = rank_select([vectors[i] for i in solvable])
    chosen = [solvable[j] for j in chosen_sub]
    consts = solve_square([vectors[i] for i in chosen], [meas[i] for i in chosen])
    c = dict(zip(basis, consts))
    for n in basis:
        print("const\t%s\t%s\t%.4f" % (n, c[n], float(c[n])), file=out)
    off = []
    for i, r in enumerate(rows):
        pred = sum(v * c[n] for v, n in zip(vectors[i], basis))
        role = "solved" if i in chosen else "held-out"
        print("row\t%s\t%s\tmeasured %.4f\tpredicted %.4f" % (r["slot"], role, float(meas[i]), float(pred)), file=out)
        if i not in chosen and pred != meas[i]:
            off.append("%s measured %s, predicted %s (%+.4f)" % (r["slot"], meas[i], pred, float(meas[i] - pred)))
    if off:
        raise GateError("EXACT: %d row(s) the basis does not predict exactly, so it is not the cost function: %s"
                        % (len(off), "; ".join(off)))
    return c


def sound(consts, slots, out=sys.stdout, floor=Fraction(4, 5)):
    """Each slot row: slot, measured, then term=count pairs. Every term must have a constant."""
    bad = []
    for s in slots:
        measured = num(s["measured"])
        total = Fraction(0)
        named = []
        for part in s["terms"].split():
            t, cnt = part.split("=", 1)
            if t not in consts:
                bad.append("%s: term %s has no measured constant" % (s["slot"], t))
                continue
            total += num(cnt) * consts[t]
            named.append(t)
        if total <= 0:
            bad.append("%s: the composed bound is %s, which bounds nothing" % (s["slot"], total))
            continue
        ratio = measured / total
        line = "sound\t%s\tmeasured %.2f\tbound %.2f\tratio %.3f\tterms %s" % (
            s["slot"], float(measured), float(total), float(ratio), ",".join(named))
        print(line, file=out)
        if measured > total:
            bad.append("%s: measured %.2f is ABOVE the composed bound %.2f" % (s["slot"], float(measured), float(total)))
        elif measured < floor * total:
            bad.append("%s: measured %.2f is below %s of the bound %.2f (tightness)" % (
                s["slot"], float(measured), floor, float(total)))
    if bad:
        raise GateError("SOUNDNESS: " + "; ".join(bad))


def flip_gain(fstar, ue):
    """How many operands of the beneficial class end up flipped, given ue nots and negated forms in all.
    Each flips an operand while it has one; past fstar the nots go in pairs (parity kept), and an odd one
    left over must flip one operand the wrong way or unflip a good one, losing one."""
    if ue <= fstar:
        return ue
    return fstar - ((ue - fstar) & 1)


def ctx_cost(consts, kind, link, r, a, ue, smooth=False):
    """One context of r rules, a atoms of `kind`, ue NOT instructions, every rule ending FALSE, no jump:
    the atoms run TRUE or FALSE by the chain's needs, and the nots flip the costlier way where they can.
    With smooth, the parity loss of flip_gain is left out (the concave surrogate the search runs on)."""
    t, f = consts[kind + ".T"], consts[kind + ".F"]
    if link == "and":
        base_t, base_f = a - r, r              # TRUE until the last operand, which is FALSE
    else:
        base_t, base_f = 0, a                  # FALSE throughout
    if f > t:
        fstar, delta = base_t, f - t
    elif t > f:
        fstar, delta = base_f, t - f
    else:
        fstar, delta = 0, Fraction(0)
    g = min(fstar, ue) if smooth else flip_gain(fstar, ue)
    n_t = base_t - g if f > t else base_t + g
    n_f = a - n_t
    cost = (n_t * t + n_f * f + ue * consts["NOT"] + r * consts["end"]
            + ((a - r) * consts["or_link"] if link == "or" else 0))
    return cost, n_t, n_f, ("T" if (f > t) else "F") if delta else "T"


def worst(consts, out=sys.stdout):
    """The maximum per-context program cost over every FEASIBLE count vector, executed with no jump
    taken (a definite F never comes before the last operand of an and-chain, a definite T never before
    the last of an or-chain, so every instruction of every visited rule runs) and every rule ending
    FALSE (a rule that fires is a `log` that runs nothing more, or a `deny` that ends the request).

    A context of R rules holding A atoms in all (one kind and one link type: cost is linear in the
    counts, so one of each wins), U unary nots and E atoms written in their one-op negated form (`!=`,
    `is not unknown`, an extra NOT instruction that is not an operation) executes A atoms, U + E NOTs,
    A - R links and R rule endings, under the limits as aggregates:

        operations    2A - R + U        <= 4,096, and <= 64 R (64 per rule, spread evenly)
        instructions  3A - R + U + E    <= 8,448
        rules         R                 <= 256,  A >= R
        nesting       U <= 16 A;  E <= A, and E = 0 for a kind with no negated form

    Each atom runs TRUE or FALSE: an and-chain needs A - R TRUE and R FALSE operands, an or-chain A
    FALSE, and an operand with an odd number of nots runs its atom the other way, so where a kind's two
    outcomes cost differently the nots go first to the operands whose flip pays (flip_gain).

    For each (kind, negatable, link) case and each R, the best U + E is the most the caps allow (a NOT
    costs more than any flip gains, which is checked), the cost without the parity term is concave
    piecewise-linear in A, its maximum is found by a binary search on the forward difference, and the
    cost, parity included, is then maximised over a neighbourhood of that point and over U + E and
    U + E - 1. The search runs in floating point for speed; every candidate within a hair of the best is
    then re-priced in exact rationals, and the exact maximum is what is reported and compared."""
    exact = consts
    consts = {k: float(v) for k, v in consts.items()}
    cands = []
    cn = consts["NOT"]
    for kind in ATOMS:
        if kind + ".T" not in consts:
            continue
        delta = abs(exact[kind + ".T"] - exact[kind + ".F"])
        if delta >= exact["NOT"] and exact["NOT"] > 0:
            raise GateError("WORST: %s's two outcomes differ by %s, at least a NOT (%s), so spending every not "
                            "is no longer the maximum and this enumeration does not hold" % (kind, delta, exact["NOT"]))
        for link in ("and", "or"):
            for neg in (True, False):
                if neg and kind not in NEGATABLE:
                    continue
                for r in range(1, MAX_RULES + 1):
                    def caps(a):
                        ucap = min(MAX_OPS - 2 * a + r, MAX_OPS_RULE * r - 2 * a + r, 16 * a)
                        icap = MAX_INSTR - 3 * a + r
                        return ucap, min(icap, ucap + (a if neg else 0))

                    def smooth(a):
                        ue = caps(a)[1]
                        return ctx_cost(consts, kind, link, r, a, ue, smooth=True)[0]

                    amax = min((min(MAX_OPS, MAX_OPS_RULE * r) + r) // 2, (MAX_INSTR + r) // 3)
                    if amax < r:
                        continue
                    lo, hi = r, amax
                    while lo < hi:
                        mid = (lo + hi) // 2
                        if smooth(mid + 1) > smooth(mid):
                            lo = mid + 1
                        else:
                            hi = mid
                    for a in range(max(r, lo - 3), min(amax, lo + 3) + 1):
                        ucap, ue_max = caps(a)
                        for ue in (ue_max, ue_max - 1):
                            if ue < 0:
                                continue
                            u = min(ucap, ue)
                            e = ue - u
                            total = ctx_cost(consts, kind, link, r, a, ue)[0]
                            cands.append((total, r, a, u, e, kind, link))
    top = max(c[0] for c in cands)
    best = None
    for c in cands:
        if c[0] < top - 1e-6 * max(1.0, abs(top)):
            continue
        _, r, a, u, e, kind, link = c
        total, n_t, n_f, flip = ctx_cost(exact, kind, link, r, a, u + e)
        if best is None or total > best[0]:
            best = (total, r, a, u, e, kind, link, n_t, n_f, flip)
    total, r, a, u, e, kind, link, n_t, n_f, flip = best
    print("worst\t%.2f\t%d rules, %d %s atoms (%d TRUE, %d FALSE; %d negated), %d unary not, %d %s links, nots "
          "first on the %s operands: %d operations, %d instructions" % (
              float(total), r, a, kind, n_t, n_f, e, u, a - r, link, flip, 2 * a - r + u, 3 * a - r + u + e), file=out)
    print("shape\t%s\t%d\t%d\t%d\t%d\t%s\t%s" % (kind, r, a, u, e, link, flip), file=out)
    return best


def pass_consts(consts, suffix):
    """One pass's constants under the context-pass names, for the enumeration."""
    return {n: consts[n + suffix] for n in BASIS_PASS if n + suffix in consts}


def check_fixture(consts, vector, out=sys.stdout):
    """The checked-in worst fixture's program must attain the enumerated maximum in each pass it runs in:
    the context pass, and the floor pass where its floor-pass constants were measured."""
    for suffix, label in (("", "context"), ("@floor", "floor")):
        pc = pass_consts(consts, suffix)
        if "NOT" not in pc:
            continue
        print("pass\t%s" % label, file=out)
        vec = {n: vector.get(n + suffix, "0") for n in BASIS_PASS}
        check_fixture_pass(pc, vec, out, label)


def check_fixture_pass(consts, vector, out=sys.stdout, label="context"):
    best = worst(consts, out)
    got = sum(num(vector.get(n, "0")) * consts[n] for n in BASIS_PASS if n != "fixed" and n in consts)
    print("fixture\t%.2f" % float(got), file=out)
    if got < best[0]:
        total, r, a, u, e, kind, link, n_t, n_f, flip = best
        raise GateError("WORST: in the %s pass the checked-in fixture's program costs %.2f, below the enumerated "
                        "maximum %.2f; set this toolchain's row of gate/evaluator-worst.tsv to: %s %d %d %d %d %s %s" % (
                            label, float(got), float(best[0]), kind, r, a, u, e, link, flip))


def vector_of(s):
    """`name=count name=count ...` into a dict of Fractions."""
    out = {}
    for part in s.split():
        k, v = part.split("=", 1)
        out[k] = out.get(k, Fraction(0)) + num(v)
    return out


def derive(meas, out=sys.stdout):
    """Every constant the composed bound names, from one toolchain's measured evaluator rows:

      the basis              solved from the evaluator-basis-* rows (rank-checked)
      L(<lookup slot>)       a lookup-only row's measurement, under its own slot name
      c_fill@<plane>@<o>     per plane and outcome of the atom that triggers the fill, the
                             evaluator-fill-<plane>@<o> row less every term it names (its find included);
                             c_fill:<schema> is the costliest of every plane and outcome of the schema
      c_prestage             the evaluator-prestage row LESS the finds it names (the hold-harmless lookup
                             and the tenant's): the pre-stage's own work, so a slot that names
                             c_prestage and those two lookups counts each find once
    """
    by = {r["slot"]: r for r in meas}
    consts = {}
    basis_rows = [dict(slot=r["slot"], measured=r["measured"], **{k: str(v) for k, v in vector_of(r["vector"]).items()})
                  for r in meas if r["slot"].startswith("evaluator-basis-")]
    for b in basis_rows:
        if "held" in b:
            b["held"] = "1" if num(b["held"]) else "0"
    if not basis_rows:
        raise GateError("no evaluator-basis-* row was measured, so no basis constant exists")
    consts.update(solve(basis_rows, out))
    for r in meas:
        if r["slot"].startswith("lookup-"):
            consts[r["slot"]] = num(r["measured"])
    # The remainders, in the driver's order: each row names every measured term it runs, and the one it is
    # named for is what is left. c_prestage less its finds; the program runs; each plane's fill.
    order = [("evaluator-prestage", "c_prestage"), ("evaluator-run-ctx", "c_run_ctx"),
             ("evaluator-run-key2", "c_key2"), ("evaluator-run-floor", "c_run_floor")]
    order += [(r["slot"], "c_fill@" + r["slot"][len("evaluator-fill-"):]) for r in meas
              if r["slot"].startswith("evaluator-fill-")]          # c_fill@<plane>@<outcome>
    def slot_value(name, key):
        if key not in by:
            raise GateError("%s names %s, which was not measured" % (name, key))
        return num(by[key]["measured"])

    def remainder(name, const):
        """The row less every term it names, over the coefficient it gives its own constant."""
        row = by[name]
        v = vector_of(row["vector"]) if row.get("vector", "-") != "-" else {}
        known = Fraction(0)
        coef = Fraction(1)
        for k, cnt in v.items():
            if k == const:
                coef = cnt
                continue
            if k.startswith("slot:") or k.startswith("twin:"):
                known += cnt * slot_value(name, k.split(":", 1)[1])
                continue
            key = k.split(":", 1)[1] if k.startswith("find:") else k
            if key not in consts:
                raise GateError("%s names %s, which was not measured before it" % (name, key))
            known += cnt * consts[key]
        consts[const] = (num(row["measured"]) - known) / coef
        print("const\t%s\t%s\t%.4f\t(%s, %.4f, less every term it names, %.4f%s)" % (
            const, consts[const], float(consts[const]), name, float(num(row["measured"])), float(known),
            "" if coef == 1 else ", over %s" % coef), file=out)

    for name, const in order:
        if name in by:
            remainder(name, const)
    # the term the composed bound names, per schema: the costliest plane of it, so the bound stays an upper
    # bound whichever plane a slot fills
    for schema, planes in SCHEMA_PLANES.items():
        per = {p: [v for k, v in consts.items() if k.startswith("c_fill@%s@" % p)] for p in planes}
        got = [v for vs in per.values() for v in vs]
        if not got:
            continue
        missing = [p for p, vs in per.items() if not vs]
        if missing:
            raise GateError("c_fill:%s needs every plane of the schema; %s %s not measured" % (
                schema, ", ".join(missing), "is" if len(missing) == 1 else "are"))
        consts["c_fill:" + schema] = max(got)
        print("const\tc_fill:%s\t%s\t%.4f\t(the costliest of %s, every outcome measured)" % (
            schema, consts["c_fill:" + schema], float(consts["c_fill:" + schema]), ", ".join(planes)), file=out)
    # THE MODULE ROWS. The harness's own view work where it is exact; the default stream's pair as a note.
    if "evaluator-views@1" in by and "evaluator-views@1-sv" in by:
        consts["c_harness_view"] = num(by["evaluator-views@1"]["measured"]) - num(by["evaluator-views@1-sv"]["measured"])
        print("const\tc_harness_view\t%s\t%.4f\t(evaluator-views@1 less evaluator-views@1-sv: the harness's view stores)" % (
            consts["c_harness_view"], float(consts["c_harness_view"])), file=out)
        if "evaluator-default" in by and "evaluator-default-sv" in by:
            d = num(by["evaluator-default"]["measured"]) - num(by["evaluator-default-sv"]["measured"])
            print("note\tthe default stream's own pair, evaluator-default less evaluator-default-sv, is %s (%.4f): the "
                  "inlined evaluator differs between the two harness functions over that stream's shapes" % (d, float(d)), file=out)
    mod_rows = []
    for r in meas:
        v = vector_of(r["vector"]) if r.get("vector", "-") != "-" else {}
        if not any(k.startswith("twin:") for k in v):
            continue
        adj = num(r["measured"])
        row = {"slot": r["slot"], "held": "1" if num(v.get("held", "0")) else "0"}
        for k, cnt in v.items():
            if k == "held":
                continue
            if k.startswith("twin:") or k.startswith("slot:"):
                adj -= cnt * slot_value(r["slot"], k.split(":", 1)[1])
            elif k in MOD_BASIS:
                row[k] = str(cnt)
            elif k in consts:
                adj -= cnt * consts[k]
            else:
                raise GateError("%s names %s, which was not measured before it" % (r["slot"], k))
        row["measured"] = str(adj)
        mod_rows.append(row)
    if mod_rows:
        consts.update(solve(mod_rows, out, basis=MOD_BASIS))
        for name, const in MOD_REMAINDERS:
            if name in by:
                remainder(name, const)
    return consts


def gate(meas_path, base_path, arch, compiler, tol_pct, write, out=sys.stdout):
    """The whole evaluator half of cachegrind-gate.sh for one toolchain: derive every constant, hold each
    to its committed value within tol_pct, run the soundness inequality on every slot that carries
    `sound` terms, and hold the worst-case fixture to the enumerated maximum. With write, print the
    rows to commit instead of comparing."""
    meas = read_table(meas_path)
    consts = derive(meas, out)
    tol = Fraction(tol_pct, 100)
    bad = []
    committed = {}
    fixed_all = []
    try:
        for r in read_table(base_path):
            if r["arch"] == arch and r["compiler"] == compiler:
                committed[r["name"]] = num(r["value"])
            if r["name"] == "c_mod_fixed":
                fixed_all.append(num(r["value"]))
    except FileNotFoundError:
        pass
    # c_mod_fixed is a few dozen instructions, so its band is the wider of the tolerance and the spread of its
    # committed values across the toolchains (hotpath-gate.sh derives its bands from such a range), printed
    slack = max(fixed_all) - min(fixed_all) if len(fixed_all) > 1 else Fraction(0)
    if "c_mod_fixed" in consts and not write:
        print("band\tc_mod_fixed\t+-max(%d%%, %.4f): the spread over %d committed toolchain%s" % (
            tol_pct, float(slack), len(fixed_all), "" if len(fixed_all) == 1 else "s"), file=out)
    for name in sorted(consts):
        if write:
            print("baseline\t%s\t%s\t%s\t%.4f" % (arch, compiler, name, float(consts[name])), file=out)
            continue
        if name not in committed:
            bad.append("no committed value for %s (derived %.4f)" % (name, float(consts[name])))
            continue
        allowed = tol * abs(committed[name])
        if name == "c_mod_fixed" and slack > allowed:
            allowed = slack
        if abs(consts[name] - committed[name]) > allowed:
            bad.append("%s is %.4f against the committed %.4f, outside +-%s" % (
                name, float(consts[name]), float(committed[name]),
                "%d%%" % tol_pct if allowed == tol * abs(committed[name]) else "%.4f" % float(allowed)))
    slots = [{"slot": r["slot"], "measured": r["measured"], "terms": r["sound"]} for r in meas if r.get("sound", "-") != "-"]
    try:
        if slots:
            sound(consts, slots, out)
        else:
            bad.append("no slot carries soundness terms, so the composed bound was never held to a measurement")
    except GateError as e:
        bad.append(str(e))
    for r in meas:
        if r["slot"] == "evaluator-worst" and r.get("program", "-") != "-":
            try:
                check_fixture(consts, vector_of(r["program"]), out)
            except GateError as e:
                bad.append(str(e))
    if bad:
        raise GateError("; ".join(bad))


def legal_rows(true_c, outcome_blind=False):
    """The driver's own basis rows (cg_driver.c, BASIS) as count vectors, priced by a PHYSICAL model:
    an atom per kind and outcome, an and-link, an or-link, a FALSE ending, two firing endings, a NOT and
    a taken jump. Returns rows in the factored basis, held=1 where the driver holds them out."""
    def phys(atoms, la, lo, ends, nots, jumps, fl, fd):
        c = true_c["fixed"] + la * true_c["and"] + lo * true_c["or"] + ends * true_c["END"]
        c += fl * true_c["FIRE_LOG"] + fd * true_c["FIRE_DENY"] + nots * true_c["NOT"] + jumps * true_c["jump"]
        for (k, o), n in atoms.items():
            c += n * true_c[(k, "T" if outcome_blind else o)]
        return c

    rows = []

    def add(slot, held, atoms, la, lo, ends, nots, jumps, fl=0, fd=0):
        v = {"fixed": "1"}
        for (k, o), n in atoms.items():
            v["%s.%s" % (k, o)] = str(int(v.get("%s.%s" % (k, o), "0")) + n)
        # factored: an and-link folds into the atom it follows; each ending carries one link less
        if nots:
            v["NOT"] = str(nots)
        if lo:
            v["or_link"] = str(lo)
        if ends:
            v["end"] = str(ends)
        if fl:
            v["fire_log"] = str(fl)
        if fd:
            v["fire_deny"] = str(fd)
        if jumps:
            v["jump"] = str(jumps)
        rows.append(dict(slot=slot, measured=str(phys(atoms, la, lo, ends, nots, jumps, fl, fd)),
                         held="1" if held else "0", **v))

    # a FALSE-ending rule of a atoms runs a-1 links; a firing rule of a atoms runs a-1 links too
    add("BOOL-F", 0, {("BOOL", "F"): 1}, 0, 0, 1, 0, 0)
    add("rules-2", 0, {("BOOL", "F"): 2}, 0, 0, 2, 0, 0)
    add("BOOL-TF", 0, {("BOOL", "T"): 1, ("BOOL", "F"): 1}, 1, 0, 1, 0, 0)
    add("BOOL-T", 0, {("BOOL", "T"): 1}, 0, 0, 0, 0, 0, fl=1)
    add("BOOL-notT", 0, {("BOOL", "T"): 1}, 0, 0, 1, 1, 0)
    add("not-2", 0, {("BOOL", "F"): 1}, 0, 0, 1, 2, 0)
    add("BOOL-or2", 0, {("BOOL", "F"): 2}, 0, 1, 1, 0, 0)
    # `F and T`: F, a taken JF, the ending; the skipped operand and its link are not run
    add("BOOL-jump", 0, {("BOOL", "F"): 1}, 0, 0, 1, 0, 1)
    add("BOOL-deny", 0, {("BOOL", "T"): 1}, 0, 0, 0, 0, 0, fd=1)
    for k in ATOMS[1:]:
        add(k + "-F", 0, {(k, "F"): 1}, 0, 0, 1, 0, 0)
        add(k + "-TF", 0, {(k, "T"): 1, (k, "F"): 1}, 1, 0, 1, 0, 0)
    add("rules-4", 1, {("BOOL", "F"): 4}, 0, 0, 4, 0, 0)
    for i, k in enumerate(ATOMS):
        add(k + "-TTF", 1, {(k, "T"): 2, (k, "F"): 1}, 2, 0, 1, 0, 0)
        if i == 0:
            continue
        add(k + "-T", 1, {(k, "T"): 1}, 0, 0, 0, 0, 0, fl=1)
        add(k + "-notT", 1, {(k, "T"): 1}, 0, 0, 1, 1, 0)
        add(k + "-or2", 1, {(k, "F"): 2}, 0, 1, 1, 0, 0)
        add(k + "-jump", 1, {(k, "F"): 1}, 0, 0, 1, 0, 1)
    add("SEV-deny", 1, {("SEV", "T"): 1}, 0, 0, 0, 0, 0, fd=1)
    return rows


def selftest():
    failures = []
    sink = open("/dev/null", "w")

    # 0. the module basis: a planted system over the module rows' own shapes is recovered exactly, and a
    # held-out module row one instruction off is refused by name
    mplant = {"c_mod_fixed": Fraction(31), "c_view": Fraction(3), "c_view@tenant": Fraction(2), "c_cnt_rule": Fraction(3),
              "c_cnt_exempt": Fraction(9)}
    for i, w in enumerate(MOD_WORDS):
        mplant["c_word@" + w] = Fraction(1 + (i % 3))
        mplant["c_count@" + w] = Fraction(9 + i)
    f = Fraction
    shapes = [("module-allow", {"c_mod_fixed": 1, "c_view": 1}, 0),
              ("module-views@1", {"c_mod_fixed": 1, "c_view": 1, "c_cnt_rule": 1}, 0),
              ("module-views@2", {"c_mod_fixed": 1, "c_view": 2, "c_cnt_rule": 1}, 0),
              ("module-views@4", {"c_mod_fixed": 1, "c_view": 4, "c_cnt_rule": 1}, 0),
              ("module-default-tenant", {"c_view@tenant": 1}, 0),
              ("module-default", {"c_mod_fixed": 1, "c_view": 3, "c_cnt_rule": f(25168, 200000),
                                  "c_cnt_exempt": f(9324, 200000), "c_count@ctx0": f(98541, 200000), "c_word@ctx0": f(80000, 200000)}, 0),
              ("module-views@3", {"c_mod_fixed": 1, "c_view": 3, "c_cnt_rule": 1}, 1),
              ("module-views@8", {"c_mod_fixed": 1, "c_view": 7, "c_view@tenant": 1, "c_cnt_rule": 1}, 1)]
    for p in ("floor", "ctx"):
        for n in (1, 64, 65, 96, 128, 129, 192, 193, 224, 256):
            sh = {"c_mod_fixed": 1, "c_view": 1}
            for w in range(n // 64):
                sh["c_word@%s%d" % (p, w)] = 1
                sh["c_count@%s%d" % (p, w)] = 64
            if n % 64:
                sh["c_word@%s%d" % (p, n // 64)] = 1
                sh["c_count@%s%d" % (p, n // 64)] = n % 64
            shapes.append(("module-count@%d-%s" % (n, p), sh, 1 if n in (96, 224) else 0))
    wshape = {"c_mod_fixed": 1, "c_view": 1, "c_cnt_rule": 1}
    for w in MOD_WORDS:
        wshape["c_word@" + w] = 1
        wshape["c_count@" + w] = 63 if w == "ctx3" else 64
    shapes.append(("module-worst", wshape, 1))
    mrows = [dict(slot=n, held=str(h), measured=str(sum(mplant[k] * f(v) for k, v in sh.items())),
                  **{k: str(f(v)) for k, v in sh.items()}) for n, sh, h in shapes]
    try:
        got = solve(mrows, sink, basis=MOD_BASIS)
        if any(got[n] != mplant[n] for n in MOD_BASIS):
            failures.append("a planted module system was not recovered exactly")
    except GateError as e:
        failures.append("a full-rank planted module system was refused: %s" % e)
    mrows[-1]["measured"] = str(num(mrows[-1]["measured"]) + 1)
    try:
        solve(mrows, sink, basis=MOD_BASIS)
        failures.append("a held-out module row one instruction off was accepted")
    except GateError as e:
        if "module-worst" not in str(e):
            failures.append("a held-out module row one instruction off was refused without its name: %s" % e)

    # 1. a planted system is recovered exactly
    planted = dict(zip(BASIS, [Fraction(40 + 3 * i, 1 + (i % 3)) for i in range(len(BASIS))]))
    rows = []
    for i in range(len(BASIS)):
        v = [Fraction(1 if (j == 0 or j == i) else 0) for j in range(len(BASIS))]
        rows.append({"slot": "p%d" % i, "measured": str(sum(a * planted[n] for a, n in zip(v, BASIS))),
                     **{n: str(a) for a, n in zip(v, BASIS)}})
    try:
        got = solve(rows, sink)
        if any(got[n] != planted[n] for n in BASIS):
            failures.append("a planted system was not recovered exactly")
    except GateError as e:
        failures.append("a full-rank planted system was refused: %s" % e)

    # 2. the driver's own rows under a physical model with an outcome-dependent kind: the factored basis
    # determines every constant from the solved rows and predicts every held-out row EXACTLY; POLICY.md 3.7's
    # basis over the same programs is refused by the rank check; one held-out row off by one instruction
    # is refused; and a basis blind to outcome cannot predict the rows of a kind whose outcomes differ
    true_c = {"fixed": Fraction(2041), "NOT": Fraction(24), "and": Fraction(9), "or": Fraction(11),
              "END": Fraction(7), "FIRE_LOG": Fraction(17), "FIRE_DENY": Fraction(40), "jump": Fraction(26)}
    for i, k in enumerate(ATOMS):
        true_c[(k, "T")] = Fraction(100 + 3 * i)
        true_c[(k, "F")] = Fraction(100 + 3 * i) - (3 if k == "ISUNK" else 0)
    legal = legal_rows(true_c)
    try:
        got = solve(legal, sink)
        want = {"end": true_c["END"] - true_c["and"], "or_link": true_c["or"] - true_c["and"],
                "fire_log": true_c["FIRE_LOG"] - true_c["and"], "ISUNK.T": true_c[("ISUNK", "T")] + true_c["and"],
                "ISUNK.F": true_c[("ISUNK", "F")] + true_c["and"], "NOT": true_c["NOT"]}
        wrong = [n for n, w in want.items() if got[n] != w]
        if wrong:
            failures.append("the driver's rows solved %s to the wrong constants" % ", ".join(wrong))
    except GateError as e:
        failures.append("the driver's rows under a model the basis can express were refused: %s" % e)
    plan_rows = []
    for r in legal:
        v = {"fixed": "1", "slot": r["slot"], "measured": r["measured"], "held": r["held"]}
        for k in ATOMS:
            n = int(r.get(k + ".T", "0")) + int(r.get(k + ".F", "0"))
            if n:
                v[k] = str(n)
        atoms = sum(int(r.get(k + "." + o, "0")) for k in ATOMS for o in OUTCOMES)
        rules = int(r.get("end", "0")) + int(r.get("fire_log", "0")) + int(r.get("fire_deny", "0"))
        v.update({"NOT": r.get("NOT", "0"), "or_link": r.get("or_link", "0"), "rule": str(rules),
                  "and_link": str(atoms - rules - int(r.get("or_link", "0")) - int(r.get("jump", "0")))})
        plan_rows.append(v)
    # over the programs where links = atoms - rules holds (no jump taken, no rule firing), the rank check
    # refuses it; over all of them (the jump and firing rows break the identity) it is refused as inexact
    plain = [p for p, r in zip(plan_rows, legal)
             if not any(k in r for k in ("jump", "fire_log", "fire_deny"))]
    for p in plain:
        p["held"] = "0"
    for name, rowset, want in (("no-jump", plain, "RANK"), ("all", plan_rows, "EXACT")):
        try:
            solve(rowset, sink, PLAN_BASIS)
            failures.append("POLICY.md 3.7's basis over the %s programs was ACCEPTED" % name)
        except GateError as e:
            if want not in str(e):
                failures.append("POLICY.md 3.7's basis over the %s programs was refused, but not by %s: %s" % (name, want, e))
    nudged = [dict(r) for r in legal]
    for r in nudged:
        if r["slot"] == "INSET_ASN-TTF":
            r["measured"] = str(num(r["measured"]) + 1)
    try:
        solve(nudged, sink)
        failures.append("a held-out row one instruction off its prediction was ACCEPTED")
    except GateError as e:
        if "EXACT" not in str(e) or "INSET_ASN-TTF" not in str(e):
            failures.append("the off-by-one held-out row was refused, but not by name: %s" % e)
    blind_basis = ["fixed"] + ATOMS + ["NOT", "or_link", "end", "fire_log", "fire_deny", "jump"]
    blind = []
    for r in legal:
        v = {k: r[k] for k in ("slot", "measured", "held")}
        for k in ATOMS:
            n = int(r.get(k + ".T", "0")) + int(r.get(k + ".F", "0"))
            if n:
                v[k] = str(n)
        for n in ("fixed", "NOT", "or_link", "end", "fire_log", "fire_deny", "jump"):
            if n in r:
                v[n] = r[n]
        blind.append(v)
    try:
        solve(blind, sink, blind_basis)
        failures.append("a basis blind to outcome was ACCEPTED over rows where ISUNK's outcomes differ")
    except GateError as e:
        if "EXACT" not in str(e) or "ISUNK" not in str(e):
            failures.append("the outcome-blind basis was refused, but not for ISUNK's rows: %s" % e)

    # 3. soundness: inside passes, above fails, below the floor fails, an unmeasured term fails
    consts = {"a": Fraction(10), "b": Fraction(3)}
    cases = [("inside", "95", True), ("above", "101", False), ("loose", "79", False)]
    for name, m, ok in cases:
        try:
            sound(consts, [{"slot": name, "measured": m, "terms": "a=7 b=10"}], sink)
            if not ok:
                failures.append("soundness accepted %s" % name)
        except GateError:
            if ok:
                failures.append("soundness refused %s" % name)
    try:
        sound(consts, [{"slot": "unpriced", "measured": "95", "terms": "a=7 c=10"}], sink)
        failures.append("soundness accepted a term with no constant")
    except GateError:
        pass

    # 4. the worst case: the enumerated maximum is attained by its own shape, one atom short is refused,
    # and where a kind's outcomes differ the nots must land on the operands whose flip pays
    wc = {n: Fraction(1) for n in BASIS_PASS}
    wc.update({"NOT": Fraction(2), "or_link": Fraction(1), "end": Fraction(5),
               "INSET_ASN.T": Fraction(9), "INSET_ASN.F": Fraction(9)})
    best = worst(wc, sink)
    total, r, a, u, e, kind, link, n_t, n_f, flip = best
    vec = {kind + ".T": str(n_t), kind + ".F": str(n_f), "NOT": str(u + e), "end": str(r)}
    if link == "or":
        vec["or_link"] = str(a - r)
    try:
        check_fixture(wc, vec, sink)
        short = dict(vec)
        short[kind + ".F"] = str(n_f - 1)
        try:
            check_fixture(wc, short, sink)
            failures.append("a fixture one atom short of the maximum was ACCEPTED")
        except GateError:
            pass
    except GateError as e:
        failures.append("the attaining fixture was refused: %s" % e)
    wd = dict(wc)
    wd.update({"INSET_ASN.T": Fraction(5), "INSET_ASN.F": Fraction(5), "ISUNK.T": Fraction(12), "ISUNK.F": Fraction(11)})
    total, r, a, u, e, kind, link, n_t, n_f, flip = worst(wd, sink)
    if kind != "ISUNK" or flip != "F":
        failures.append("with ISUNK costliest and TRUE dearer than FALSE, the maximum did not flip FALSE operands "
                        "(got %s, nots first on %s)" % (kind, flip))
    if total != ctx_cost(wd, kind, link, r, a, u + e)[0]:
        failures.append("the enumerated maximum disagrees with its own shape's cost")
    try:
        worst(dict(wd, **{"ISUNK.T": Fraction(40)}), sink)
        failures.append("a kind whose outcomes differ by more than a NOT was ACCEPTED by the enumeration")
    except GateError:
        pass

    # 5. the whole evaluator half: derive every constant from planted rows (c_prestage LESS its finds),
    # hold them to their committed values, run the soundness inequality; then a committed value moved
    # 20% and a run with no sound terms must each be refused
    import os
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        look, pre, hh, run = Fraction(50), Fraction(30), Fraction(70), Fraction(11)
        fills = {"tor": Fraction(9), "rpki-unreachable": Fraction(10), "anonymizer": Fraction(8),
                 "threat": Fraction(12), "tenant": Fraction(7)}
        cfill = max(fills.values())
        g = solve(legal, sink)
        lines = ["# slot\tmeasured\tvector\tsound\tprogram"]
        for r in legal:
            vec = " ".join("%s=%s" % (n, r[n]) for n in BASIS if n in r and r[n] != "0")
            if r["held"] == "1":
                vec += " held=1"
            lines.append("evaluator-basis-%s\t%s\t%s\t-\t-" % (r["slot"], r["measured"], vec))
        for p in fills:
            lines.append("lookup-%s@basis\t%s\t-\t-\t-" % (p, look))
        lines.append("lookup-hh@basis\t%s\t-\t-\t-" % hh)
        lines.append("evaluator-prestage\t%s\tfind:lookup-hh@basis=1 find:lookup-tenant@basis=1\t-\t-" % (pre + hh + look))
        lines.append("evaluator-run-ctx\t%s\tc_prestage=1 find:lookup-hh@basis=1 find:lookup-tenant@basis=1 "
                     "ISUNK.F=1 end=1\t-\t-" % (pre + hh + look + g["ISUNK.F"] + g["end"] + run))
        for p, c in fills.items():
            lines.append("evaluator-fill-%s@F\t%s\tc_prestage=1 find:lookup-hh@basis=1 find:lookup-tenant@basis=1 "
                         "c_run_ctx=1 BOOL.F=1 end=1 find:lookup-%s@basis=1\t-\t-" % (
                             p, pre + hh + look + run + g["BOOL.F"] + g["end"] + c + look, p))
        bound = 3 * g["BOOL.F"] + 4 * g["end"] + 4 * cfill + pre + hh + 4 * look
        lines.append("evaluator-default\t%s\t-\tBOOL.F=3 end=4 c_fill:membership=4 c_prestage=1 lookup-hh@basis=1 "
                     "lookup-threat@basis=4\t-" % (bound * Fraction(9, 10)))
        mp = os.path.join(tmp, "m.tsv")
        with open(mp, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        import io
        buf = io.StringIO()
        gate(mp, os.path.join(tmp, "none.tsv"), "a", "c", 10, True, buf)
        if "const\tc_prestage\t%s\t" % pre not in buf.getvalue():
            failures.append("c_prestage was not derived as the pre-stage row LESS its named finds")
        if "const\tc_run_ctx\t%s\t" % run not in buf.getvalue():
            failures.append("c_run_ctx was not derived as its row's remainder")
        if "const\tc_fill:membership\t%s\t" % cfill not in buf.getvalue():
            failures.append("c_fill:membership is not the costliest membership plane's fill (%s)" % cfill)
        base = ["# arch\tcompiler\tname\tvalue"] + ["\t".join(l.split("\t")[1:]) for l in buf.getvalue().splitlines() if l.startswith("baseline\t")]
        bp = os.path.join(tmp, "b.tsv")
        with open(bp, "w") as fh:
            fh.write("\n".join(base) + "\n")
        try:
            gate(mp, bp, "a", "c", 10, False, sink)
        except GateError as e:
            failures.append("the planted evaluator rows were refused: %s" % e)
        moved = [l if not l.endswith("\tc_fill:membership\t%.4f" % float(cfill)) else l.replace("%.4f" % float(cfill), "%.4f" % float(cfill * Fraction(6, 5)))
                 for l in base]
        if moved == base:
            failures.append("the selftest could not find c_fill:membership in its own baseline")
        with open(bp, "w") as fh:
            fh.write("\n".join(moved) + "\n")
        try:
            gate(mp, bp, "a", "c", 10, False, sink)
            failures.append("a derived constant 20% off its committed value was ACCEPTED")
        except GateError:
            pass
        with open(bp, "w") as fh:
            fh.write("\n".join(base) + "\n")
        with open(mp, "w") as fh:
            fh.write("\n".join(l for l in lines if not l.startswith("evaluator-default")) + "\n")
        try:
            gate(mp, bp, "a", "c", 10, False, sink)
            failures.append("a run with no soundness terms was ACCEPTED")
        except GateError:
            pass
    finally:
        for f in os.listdir(tmp):
            os.unlink(os.path.join(tmp, f))
        os.rmdir(tmp)

    if failures:
        for f in failures:
            print("SELFTEST FAIL: " + f)
        return 1
    print("ok   cost-model selftest: a planted basis recovered exactly; the driver's own rows, priced by a "
          "physical model with an outcome-dependent kind, solved to the right constants with every held-out "
          "row predicted exactly; POLICY.md 3.7's basis refused by the rank check over the rows that take no jump and "
          "fire nothing, and as inexact over all of them; a held-out row one instruction off refused by name, and an outcome-blind basis refused on ISUNK's rows; a bound "
          "exceeded, a bound below the 0.8 floor and an unpriced term each refused; the worst shape attains "
          "the enumerated maximum, one atom short is refused, the nots flip the costlier way, and outcomes "
          "a NOT apart are refused; the evaluator half derives every planted constant with c_prestage less "
          "its find, and refuses one moved 20% and a run with no soundness terms; the module basis recovers a planted system exactly and refuses a held-out module row one instruction off by name")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    try:
        if cmd == "selftest":
            return selftest()
        if cmd == "solve" and len(argv) == 3:
            solve(read_table(argv[2]))
            return 0
        if cmd == "sound" and len(argv) == 4:
            consts = {r["name"]: num(r["value"]) for r in read_table(argv[2])}
            sound(consts, read_table(argv[3]))
            return 0
        if cmd == "worst" and len(argv) in (3, 4):
            consts = {r["name"]: num(r["value"]) for r in read_table(argv[2])}
            if len(argv) == 4:
                vec = read_table(argv[3])[0]
                check_fixture(consts, vec)
            else:
                worst(consts)
            return 0
        if cmd == "gate" and len(argv) in (7, 8):
            gate(argv[2], argv[3], argv[4], argv[5], int(argv[6]), len(argv) == 8 and argv[7] == "--write")
            return 0
    except GateError as e:
        print("GATE FAIL: %s" % e)
        return 1
    print("usage: cost-model.py selftest | solve ROWS | sound CONSTS SLOTS | worst CONSTS [FIXTURE]\n"
          "       | gate MEASUREMENTS COMMITTED ARCH COMPILER TOLERANCE_PCT [--write]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
