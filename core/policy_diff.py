#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
policy_diff.py - the policy language's differential: two readings of one specification, compared per case.

  policy_diff.py A B                 compare two outputs of the case format (policy_ref.py's, and the
                                     C test_policy's once it exists): every line of every program and
                                     every case must be equal, `msg` lines aside (the wording of what
                                     and fix is each implementation's; the fragment on the refusal line
                                     is POLICY.md's and is compared). Exit 1 on any disagreement.
  policy_diff.py --coverage F        every cell of the coverage matrix (policy_ref.expected_cells) must be
                                     non-zero; prints the cell counts. Exit 1 on a zero cell.
  policy_diff.py --coverage-control F
                                     the negative control of the line above: for each cell in turn, the
                                     same check with that one cell zeroed must fail.
  policy_diff.py --mutants CASES...  run the oracle under each of its mutants over the case files and
                                     require a disagreement with the production oracle, with the catch
                                     count printed (and, for the cost mutants, disagreement on the cost
                                     line ONLY, row X1). NO_EXHAUSTIVE must leave a zero cell (row K7).
  policy_diff.py --list-mutants      print the mutant table below.
  policy_diff.py --self-test         the comparison's controls: empty against empty, a case-less program,
                                     a line before the first program, a duplicated program id and a
                                     duplicated case id are each refused, never compared.

Every mode ends with one `N checks, F failures` line for `make check`'s published count.

THE MUTANT TABLE (POLICY.md section 5.4). Each mutant is a `-D` build of test_policy on the C side; the
differential must report disagreements per mutant and the named matrix row must fail on its own. The
`oracle` column says whether policy_ref.py carries the same defect behind --mutant, so the generated
set's power to catch it is asserted today; the three it does not carry are about memory and context
reuse, which a value-level interpreter has no way to get wrong.
"""

import io
import os
import sys
import time

import policy_ref as R

# (name, the change, the defect it stands for, the row that must fail, the oracle carries it, the
# lines the oracle mutant must disagree on (None: any), the catch count measured when the floor was set,
# and the floor: half that count). The counts are blocks of the generated cases at --every 4 (make
# check's POLICY_EVERY) plus the whole exhaustive leg; for NO_EXHAUSTIVE they are zero coverage cells.
# A mutant caught below its floor fails: the set lost power against that defect. A larger POLICY_EVERY
# samples less and can fall under a floor; re-measure and reset the floors with the change.
MUTANTS = (
    ('WE_TEST_K3_WEAK', 'exact weak Kleene: U if either operand is U, classical otherwise',
     'the mask / unknown-mask encoding', 'K2', True, None, 11593, 5796),
    ('WE_TEST_ALLOW_U_FALLTHROUGH', 'an allow at U is treated as no match',
     'the fail-closed allow at U', 'K4', True, None, 4375, 2187),
    ('WE_TEST_LOG_TERMINATES', 'log ends evaluation',
     'the iptables LOG analogy', 'F1', True, None, 5187, 2593),
    ('WE_TEST_POLARITY_NO_ALLOW', 'the polarity pass ignores allow',
     'the allow side of the polarity pass', 'N4', True, None, 2, 1),
    ('WE_TEST_ISNOTUNK_POSITIVE', 'is not unknown treated as positive polarity',
     "the design example", 'N4', True, None, 14, 7),
    ('WE_TEST_BOOL_NOT', 'not is (t, ~t)',
     'boolean negation under K3', 'K2', True, None, 13714, 6857),
    ('WE_TEST_SENTINEL_NE', '!= undetermined TRUE at the sentinel',
     '!= read at the sentinel', 'P2', True, None, 157, 78),
    ('WE_TEST_SHORTCIRCUIT_U', 'JF jumps on U',
     'unsound short-circuit', 'K3', True, None, 15300, 7650),
    ('WE_TEST_NO_CLAMP', 'the fill clamps nothing',
     'every record byte unclamped', 'M4', True, None, 321, 160),
    ('WE_TEST_NO_MEMO_HIT', 'every atom looks up again',
     'the memo', 'X1 (cost columns only)', True, ('cost',), 2189, 1094),
    ('WE_TEST_NO_SHORTCIRCUIT', 'JF/JT never taken',
     'short-circuit', 'X1 (cost columns only)', True, ('cost',), 17745, 8872),
    ('WE_TEST_NO_MEMO_RESET', 'a re-keyed slot is not reset',
     'an unkeyed slot read across addresses', 'M1', False, None, None, None),
    ('WE_TEST_CLASSIFY_ISUNK_U', 'the classifier reads ISUNK as U',
     'monotonicity misapplied to ISUNK', 'D2', True, None, 326, 163),
    ('WE_TEST_NO_CAPTURES', 'the classifier has no captures class',
     'the captures effect missed', 'D1', True, None, 9775, 4887),
    ('WE_TEST_CLASSIFY_SINGLE_EVAL', 'one evaluation at the most favourable values instead of value sets',
     'the capture under or', 'D2', True, None, 4176, 2088),
    ('WE_TEST_SENTINEL_PADDING', 'INSET_ASN returns found for 0xFFFFFFFF',
     'padding read as the sentinel', 'S2', True, None, 29, 14),
    ('WE_TEST_TENANT_ATOM_U', 'the bounded occurrence reads U in every stale state',
     'the unbounded stale allow', 'F4, D1', True, None, 113, 56),
    ('WE_TEST_TENANT_BIT_IGNORED', 'the bounded reading on every tenant occurrence',
     'the bounded reading on every tenant occurrence', 'F4, X5', True, None, 1888, 944),
    ('WE_TEST_SPLUS_NO_CLAMP', "the S+ search runs on a, not a'",
     'the sentinel read out of bounds', 'S2, C5', False, None, None, None),
    ('WE_TEST_NO_EXHAUSTIVE', 'the exhaustive leg is skipped (standing)',
     'a control that cannot rot', 'K7', True, None, 30, 15),
    ('WE_TEST_PLANTED_STORE', 'one store into a plane buffer (standing)',
     'the store the gate cannot see', 'H3', False, None, None, None),
)


def parse_output(path):
    """Program id -> (program lines, ordered case ids, case id -> lines)."""
    with open(path, encoding='latin-1') as f:
        return parse_lines(f, path)


class Malformed(Exception):
    """An output the differential refuses to compare, because comparing it could pass vacuously."""


def parse_lines(lines, side='input'):
    """Refuses a line before the first `program`, a program id seen twice and a case id seen twice: each
    would let a comparison pass that compared nothing, or compared the wrong copy."""
    progs = {}
    order = []
    cases = set()
    cur = None
    case = None
    for n, line in enumerate(lines, 1):
        line = line.rstrip('\n')
        if not line or line.startswith('msg '):
            continue
        if line.startswith('program '):
            pid = line[8:]
            if pid in progs:
                raise Malformed('%s line %d: program %s appears twice' % (side, n, pid))
            cur = ([], [], {})
            progs[pid] = cur
            order.append(pid)
            case = None
        elif cur is None:
            raise Malformed('%s line %d: %r comes before the first program' % (side, n, line[:60]))
        elif line.startswith('case '):
            case = line[5:]
            if case in cases:
                raise Malformed('%s line %d: case %s appears twice' % (side, n, case))
            cases.add(case)
            cur[1].append(case)
            cur[2][case] = []
        elif case is not None:
            cur[2][case].append(line)
        else:
            cur[0].append(line)
    return progs, order


def tag(line):
    return line.split(' ', 1)[0]


def compare(a, b, show=10, quiet=False):
    """Returns (blocks compared, disagreements, by tag)."""
    pa, oa = parse_output(a) if isinstance(a, str) else a
    pb, ob = parse_output(b) if isinstance(b, str) else b
    blocks = dis = 0
    by_tag = {}
    shown = 0

    def note(where, la, lb, tags=None):
        nonlocal dis, shown
        dis += 1
        if tags is None:
            tags = {tag(x) for x, y in zip(la, lb) if x != y}
            tags |= {tag(x) for x in la[len(lb):]} | {tag(x) for x in lb[len(la):]}
            tags = sorted(tags)
        for t in tags or ['shape']:
            by_tag[t] = by_tag.get(t, 0) + 1
        if shown < show and not quiet:
            shown += 1
            print('DISAGREE %s' % where)
            for x, y in zip(la, lb):
                if x != y:
                    print('  - %s\n  + %s' % (x, y))
            for x in la[len(lb):]:
                print('  - %s' % x)
            for y in lb[len(la):]:
                print('  + %s' % y)
    for pid in oa:
        blocks += 1
        if pid not in pb:
            note('program %s (absent on the right)' % pid, pa[pid][0], [])
            continue
        if pa[pid][0] != pb[pid][0]:
            note('program %s' % pid, pa[pid][0], pb[pid][0])
        if pa[pid][1] != pb[pid][1]:
            note('program %s: the case lists differ' % pid, pa[pid][1], pb[pid][1], ['cases'])
            continue
        for cid in pa[pid][1]:
            blocks += 1
            if pa[pid][2][cid] != pb[pid][2][cid]:
                note('program %s case %s' % (pid, cid), pa[pid][2][cid], pb[pid][2][cid])
    for pid in ob:
        if pid not in pa:
            blocks += 1
            note('program %s (absent on the left)' % pid, [], pb[pid][0])
    n_cases = sum(len(pa[pid][1]) for pid in oa)
    if blocks == 0 or n_cases == 0:
        raise Malformed('nothing to compare: %d blocks, %d cases' % (blocks, n_cases))
    return blocks, dis, by_tag


def coverage_report(path):
    cov = R.read_coverage(path)
    cells, zero = R.check_coverage(cov)
    groups = {}
    for leg, cell in cells:
        g = '%s %s' % (leg, cell[0])
        n = cov.get((leg, ' '.join(map(str, cell))), 0)
        lo, hi, cnt = groups.get(g, (None, 0, 0))
        groups[g] = (n if lo is None else min(lo, n), max(hi, n), cnt + 1)
    print('coverage matrix: %d cells, %d zero' % (len(cells), len(zero)))
    for g in sorted(groups):
        lo, hi, cnt = groups[g]
        print('  %-24s %3d cells, counts %d .. %d' % (g, cnt, lo, hi))
    for z in zero:
        print('ZERO CELL %s' % z)
    return len(cells), zero


def coverage_control(path):
    """Each cell zeroed in turn must make the check fail: no cell of the matrix is vacuous."""
    cov = R.read_coverage(path)
    cells = R.expected_cells()
    missed = []
    for leg, cell in cells:
        k = (leg, ' '.join(map(str, cell)))
        c2 = dict(cov)
        c2[k] = 0
        _, zero = R.check_coverage(c2)
        if not zero:
            missed.append(k)
    print('coverage control: %d of %d cells, each zeroed alone, fail the check' % (len(cells) - len(missed), len(cells)))
    for m in missed:
        print('FAIL coverage control: zeroing %s %s did not fail the check' % m)
    return len(cells), len(missed)


def oracle_run(paths, mutant, every=1):
    R.set_mutant(mutant)
    try:
        buf = io.StringIO()
        cov = {}
        for p in paths:
            r = R.run_cases(p, buf, None, every=every)
            for leg, cells in r[6].items():
                for k, n in cells.items():
                    key = (leg, ' '.join(map(str, k)))
                    cov[key] = cov.get(key, 0) + n
    finally:
        R.set_mutant(None)
    return buf.getvalue(), cov


def _mutant_worker(job):
    """One mutant in its own process: run the oracle with the defect, compare with production."""
    prod_path, paths, every, name, row, only, floor = job
    short = name[len('WE_TEST_'):]
    out, cov = oracle_run(paths, short, every)
    if short == 'NO_EXHAUSTIVE':
        _, zero = R.check_coverage(cov)
        return name, row, only, None, len(zero), None, floor
    blocks, dis, by_tag = compare(parse_output(prod_path), parse_lines(out.split('\n')), show=0, quiet=True)
    return name, row, only, blocks, dis, by_tag, floor


def run_mutants(paths, every=1, workers=None):
    import multiprocessing
    import tempfile
    t0 = time.time()
    prod, _ = oracle_run(paths, None, every)
    fd, prod_path = tempfile.mkstemp(suffix='.oracle')
    with os.fdopen(fd, 'w', encoding='latin-1') as f:
        f.write(prod)
    jobs = []
    for name, change, defect, row, oracle, only, measured, floor in MUTANTS:
        if oracle:
            jobs.append((prod_path, paths, every, name, row, only, floor))
        else:
            print('  %-30s C only (%s); row %s' % (name, defect, row))
    workers = workers or min(len(jobs), max(1, (os.cpu_count() or 2) - 1))
    try:
        with multiprocessing.Pool(workers) as pool:
            results = pool.map(_mutant_worker, jobs)
    finally:
        os.unlink(prod_path)
    checks = fails = 0
    for name, row, only, blocks, dis, by_tag, floor in results:
        checks += 1
        if blocks is None:
            if dis >= floor:
                print('  %-30s caught: the exhaustive leg missing leaves %d zero cells, floor %d (row %s)'
                      % (name, dis, floor, row))
            else:
                fails += 1
                print('FAIL %-30s left %d zero cells, under its floor of %d (row %s)' % (name, dis, floor, row))
            continue
        tags = ', '.join('%s %d' % kv for kv in sorted(by_tag.items()))
        if dis < floor:
            fails += 1
            print('FAIL %-30s caught in %d blocks, under its floor of %d (row %s)' % (name, dis, floor, row))
        elif only is not None and set(by_tag) - set(only):
            fails += 1
            print('FAIL %-30s disagrees outside %s: %s' % (name, '/'.join(only), tags))
        else:
            print('  %-30s caught in %d of %d blocks, floor %d (%s); row %s' % (name, dis, blocks, floor, tags, row))
    print('mutants: %d run in %d processes, %.1f s' % (len(jobs), workers, time.time() - t0))
    return checks, fails


def self_test():
    """The comparison's own controls: each way it could pass vacuously must fail, and a real disagreement
    must be counted."""
    good = ['program p1', 'text ctx 1 deny if c2', 'case 1', 'verdict a', 'cost b', 'case 2', 'verdict c']
    checks = fails = 0

    def expect(name, a, b, want):
        nonlocal checks, fails
        checks += 1
        try:
            blocks, dis, _ = compare(parse_lines(a, 'left'), parse_lines(b, 'right'), show=0, quiet=True)
            got = 'disagree' if dis else 'agree'
        except Malformed:
            got = 'malformed'
        if got != want:
            fails += 1
            print('FAIL policy_diff self-test: %s: %s, expected %s' % (name, got, want))
    expect('two equal outputs agree', good, good, 'agree')
    expect('one changed line disagrees', good, good[:3] + ['verdict X'] + good[4:], 'disagree')
    expect('control: empty against empty is refused', [], [], 'malformed')
    expect('control: a program with no case is refused', ['program p1', 'text x'], ['program p1', 'text x'],
           'malformed')
    expect('control: a line before the first program is refused', good, ['verdict stray'] + good, 'malformed')
    expect('control: a duplicated program id is refused, whichever copy is wrong',
           good, good[:3] + ['verdict WRONG'] + good[4:] + good, 'malformed')
    expect('control: a duplicated case id is refused', good, good + ['case 1', 'verdict a'], 'malformed')
    print('policy_diff self-test: %d checks, %d failed' % (checks, fails))
    return checks, fails


def main(argv):
    if argv[:1] == ['--list-mutants']:
        print('%-30s %-6s %-8s %-6s %s' % ('mutant', 'oracle', 'row', 'floor', 'change'))
        for name, change, defect, row, oracle, only, measured, floor in MUTANTS:
            print('%-30s %-6s %-8s %-6s %s (%s)' % (name, 'yes' if oracle else 'C', row,
                                                   floor if floor is not None else '-', change, defect))
        print('%d mutants' % len(MUTANTS))
        return 0
    if argv[:1] == ['--coverage']:
        n, zero = coverage_report(argv[1])
        print('%d checks, %d failures' % (n, len(zero)))
        return 1 if zero else 0
    if argv[:1] == ['--coverage-control']:
        n, missed = coverage_control(argv[1])
        print('%d checks, %d failures' % (n, missed))
        return 1 if missed else 0
    if argv[:1] == ['--mutants']:
        every = 1
        rest = argv[1:]
        if rest[:1] == ['--every']:
            every, rest = int(rest[1]), rest[2:]
        checks, fails = run_mutants(rest, every)
        print('%d checks, %d failures' % (checks, fails))
        return 1 if fails else 0
    if argv[:1] == ['--self-test']:
        checks, fails = self_test()
        print('%d checks, %d failures' % (checks, fails))
        return 1 if fails else 0
    if len(argv) == 2:
        try:
            blocks, dis, by_tag = compare(argv[0], argv[1])
        except Malformed as e:
            print('DIFF FAIL: %s' % e)
            print('1 checks, 1 failures')
            return 1
        print('differential: %d blocks, %d disagreements%s' % (
            blocks, dis, (' (' + ', '.join('%s %d' % kv for kv in sorted(by_tag.items())) + ')') if dis else ''))
        print('%d checks, %d failures' % (blocks, dis))
        return 1 if dis else 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
