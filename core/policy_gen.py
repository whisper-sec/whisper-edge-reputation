#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
policy_gen.py - the seeded case generator for the policy language's differential.

From the pinned xorshift seed bench_core.c uses (0x9e3779b97f4a7c15), it writes the case files that
policy_ref.py and the C test_policy both evaluate, line for line, so a disagreement is a defect in one
of the two readings of POLICY.md. Python's own `random` is not used: the stream is the 64-bit xorshift
written out below, so the same seed gives the same bytes on every Python.

Three legs:

  generated   programs drawn from the whole grammar (every attribute, every literal form and spelling,
              inline and named sets declared before and after use, floor and context programs, the
              tenant atoms), each run under EVERY reduced plane-state vector of section 3.5: two states
              per referenced non-tenant plane and the five tenant states (fresh, stale within the
              48-hour grace, stale past it, null, revoked), so a program reading k non-tenant planes
              has 2^k * 5 cases. Per case: records per (address, plane) with every byte value drawn
              (country 0..65535), the floor and server records drawn DIFFERENT for every referenced
              plane in half the cases with distinct addresses, the two addresses EQUAL in a quarter of
              the cases (and a third of the programs have floor and context plane sets overlapping in
              exactly one plane, so the shared slot is exercised), the ::ffff:a.b.c.d, ::a.b.c.d, ::
              and ::1 forms among the addresses, hold-harmless addresses, ACME, raw configuration values
              outside the domain.
  limits      every limit at its boundary and one past it.
  mutations   generated rules with one byte inserted, replaced or deleted, or one word's case changed,
              so the refusal line is compared over inputs nobody wrote by hand.
  rows        POLICY.md's named matrix rows as programs, under every state vector.
  phrases     one program per phrase of section 1.5's table, so every phrase is emitted (the coverage
              matrix requires it), and the interleaved-context polarity case.
  absent      programs with planes absent at configuration time: inert rules, their reports.
  files       every .policy file under testdata/policy/ (the corpus, the seeds and the adversarial inputs)
              as a program, its verdicts under four tenant states when it compiles.
  exhaustive  every expression of up to 3 atoms and nesting 2, x atom values {T, F, U}, x action, x
              position (before or after a deny), written to its own file.

Fractions, stated as POLICY.md asks: equal addresses 1/4; distinct-address cases with independent
server records 1/2; a record absent (no range) 1/4 per (address, plane); programs whose floor and
context plane sets overlap in exactly one plane 1/3; a refused program kept 1/4 (the rest redrawn).

Self-checks (each a check in the `N checks` line): every generated program runs under exactly 2^k * 5
state vectors, k counted from the program's TEXT by this file's own attribute table (never from the
oracle's compiled planes); every phrase program emits its phrase; every rule's canonical text recompiles
to itself and to the same instruction stream (R1); a second generation from the same seed is byte-
identical; every boundary program compiles and every one-past program is refused in the layer POLICY.md
names; and the value-set classifier's soundness against the exact brute force (section 2.5, property 2)
over every rule of at most 8 atoms, every subset of its non-tenant planes and every tenant state: never
inert where exact is narrowed, never missing captures where exact has it.
"""

import hashlib
import io
import ipaddress
import os
import sys
import time

import policy_ref as R

SEED = 0x9e3779b97f4a7c15
GRACE = R.GRACE_MS
NOW = 1_800_000_000_000
U64 = (1 << 64) - 1


class Rng(object):
    def __init__(self, seed=SEED):
        self.s = seed & U64

    def u32(self):
        s = self.s
        s ^= (s << 13) & U64
        s ^= s >> 7
        s ^= (s << 17) & U64
        self.s = s
        return s >> 32

    def below(self, n):
        return self.u32() % n if n > 0 else 0

    def chance(self, num, den):
        return self.below(den) < num

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def u64(self):
        return (self.u32() << 32) | self.u32()


DOC_ASNS = list(range(64496, 64512)) + list(range(65536, 65552))
SOME_COUNTRIES = ['NL', 'BE', 'DE', 'RU', 'SY', 'KP', 'CU', 'US', 'GB', 'IN', 'IS', 'NO', 'AS', 'DO', 'EU',
                  'AP', 'ZZ', 'XK', 'FR', 'CN', 'BR', 'JP']
BOOL_BY_PLANE = {}
for _a, (_p, _m) in R.BOOLS.items():
    BOOL_BY_PLANE.setdefault(_p, []).append(_a)
VALUED_BY_PLANE = {}
for _a, (_p, _c, _f) in R.VALUED.items():
    VALUED_BY_PLANE.setdefault(_p, []).append(_a)


# ---------------------------------------------------------------------------------------------------
# Programs from the grammar
# ---------------------------------------------------------------------------------------------------

class Meta(object):
    """What a program's literals are, so records can be drawn to make atoms TRUE as well as FALSE."""

    def __init__(self):
        self.asns = set()
        self.countries = set()
        self.sets = []          # (context, name, cls, members text)
        self.isunk = False


def spell_country(rng, cc):
    k = rng.below(4)
    return cc if k < 2 else (cc.lower() if k == 2 else cc[0] + cc[1].lower())


def spell_asn(rng, n):
    k = rng.below(5)
    return ('as%d', 'AS%d', 'As%d', '%d', '%d')[k] % n


def draw_asn(rng):
    k = rng.below(10)
    if k < 5:
        return rng.pick(DOC_ASNS)
    if k == 5:
        return 0
    if k == 6:
        return 4294967294
    if k == 7:
        return rng.below(1000)
    return rng.u32() % 4294967295


def draw_country(rng):
    if rng.chance(3, 4):
        return rng.pick(SOME_COUNTRIES)
    return rng.pick(sorted(R.COUNTRY))


def enum_lits(dom):
    vals = list(R.ENUMS[dom][1:]) + ['undetermined']
    if dom == 'rpki':
        vals += ['not_found', 'notfound']
    return vals


def set_members(rng, cls, meta, n=None):
    if n is None:
        n = 1 + rng.below(6)
    out = []
    if cls == 'asn':
        for _ in range(n):
            a = draw_asn(rng)
            meta.asns.add(a)
            out.append(spell_asn(rng, a))
    elif cls == 'country':
        for _ in range(n):
            c = draw_country(rng)
            meta.countries.add(c)
            out.append(spell_country(rng, c))
    elif cls == 'level':
        out = [rng.pick(R.LEVELS) for _ in range(n)]
    else:
        out = [rng.pick(enum_lits(cls)) for _ in range(n)]
    if cls != 'level' and rng.chance(1, 4):
        out.insert(rng.below(len(out) + 1), 'undetermined')
    return out


def join_members(rng, ms):
    k = rng.below(4)
    if k == 0:
        return ','.join(ms)
    if k == 1:
        return ', '.join(ms) + (',' if rng.chance(1, 2) else '')
    return ' '.join(ms)


def gen_atom(rng, planes, action, meta, sets_ctx, allow_isunk):
    p = rng.pick(planes)
    choices = list(BOOL_BY_PLANE.get(p, [])) * 2 + list(VALUED_BY_PLANE.get(p, [])) * 3
    attr = rng.pick(choices)
    if allow_isunk and rng.chance(1, 12):
        meta.isunk = True
        return '%s is %sunknown' % (attr, 'not ' if rng.chance(1, 3) else '')
    if attr in R.BOOLS:
        return attr
    cls = R.VALUED[attr][1]
    sp = '' if rng.chance(1, 6) else ' '
    k = rng.below(10)
    if cls == 'level':
        if k < 6:
            return 'listed%s%s%s%s' % (sp, rng.pick(R.OPS), sp, rng.pick(R.LEVELS))
        if k < 9:
            return 'listed in {%s}' % join_members(rng, set_members(rng, 'level', meta, 1 + rng.below(3)))
    elif k < 5:
        op = rng.pick(('==', '!='))
        if cls == 'asn':
            v = 'undetermined' if rng.chance(1, 8) else None
            if v is None:
                a = draw_asn(rng)
                meta.asns.add(a)
                v = spell_asn(rng, a)
        elif cls == 'country':
            if rng.chance(1, 8):
                v = 'undetermined'
            else:
                c = draw_country(rng)
                meta.countries.add(c)
                v = spell_country(rng, c)
        else:
            v = rng.pick(enum_lits(cls))
        return '%s%s%s%s%s' % (attr, sp, op, sp, v)
    elif k < 8:
        return '%s in {%s}' % (attr, join_members(rng, set_members(rng, cls, meta)))
    elif k < 9:
        if cls == 'asn' and rng.chance(1, 3):
            n = rng.pick((1, 16, 17, 40, 272, 273))
        else:
            n = None
        name = 's%d' % len(meta.sets)
        mem = set_members(rng, cls, meta, n)
        if cls == 'asn' and n and n >= 272:
            mem = [str(x) for x in sorted({rng.below(100000) for _ in range(n * 2)})[:n]]
            meta.asns.update(int(x) for x in mem[:8])
        meta.sets.append((sets_ctx, name, cls, ' '.join(mem)))
        return '%s in @%s' % (attr, name)
    if allow_isunk:
        meta.isunk = True
        return '%s is %sunknown' % (attr, 'not ' if rng.chance(1, 2) else '')
    return 'listed >= low' if cls == 'level' else '%s == undetermined' % attr


def gen_expr(rng, planes, action, meta, sets_ctx, depth, budget, allow_isunk):
    k = rng.below(10)
    if depth >= 3 or budget[0] < 3 or k < 5:
        budget[0] -= 1
        return gen_atom(rng, planes, action, meta, sets_ctx, allow_isunk), False
    if k < 7:
        budget[0] -= 1
        e, chain = gen_expr(rng, planes, action, meta, sets_ctx, depth + 1, budget, allow_isunk)
        return 'not ' + ('(%s)' % e if chain else e), False
    conn = rng.pick(('and', 'or'))
    n = 2 + rng.below(3)
    parts = []
    for _ in range(n):
        budget[0] -= 1
        e, chain = gen_expr(rng, planes, action, meta, sets_ctx, depth + 1, budget, allow_isunk)
        parts.append('(%s)' % e if chain else e)
    return (' %s ' % conn).join(parts), True


CTXS = ('http/server:a', 'http/server:a/location:api')


def gen_program(rng, pid):
    """One program: the floor, the context's rules, its sets, its modes. Returns (dirs, run, meta,
    floor planes, ctx planes)."""
    meta = Meta()
    nonten = [1, 2, 3, 4, 5, 6, 7]
    kp = 1 + rng.below(4) if rng.chance(7, 8) else 5 + rng.below(3)
    cplanes = []
    while len(cplanes) < kp:
        p = rng.pick(nonten)
        if p not in cplanes:
            cplanes.append(p)
    if rng.chance(1, 3):
        cplanes.append(8)
    overlap = rng.chance(1, 3)
    if overlap:
        shared = rng.pick(cplanes)
        others = [p for p in nonten if p not in cplanes]
        fplanes = [shared] + ([rng.pick(others)] if others else [])
    else:
        fplanes = [rng.pick(cplanes)] if rng.chance(1, 2) else [rng.pick(nonten)]
    run = rng.pick(CTXS)
    pctx = run if rng.chance(3, 4) else 'http/server:a'
    dirs = []
    late = []
    nf = rng.below(3)
    for _ in range(nf):
        b = [6]
        e, _ = gen_expr(rng, fplanes, 'deny', meta, 'http', 1, b, True)
        act = rng.pick(('deny', 'log', 'log'))
        dirs.append(('floor', 'http', '%s if %s' % (act, e)))
    nr = 1 + rng.below(6)
    for i in range(nr):
        act = rng.pick(('allow', 'deny', 'deny', 'log'))
        b = [5 + rng.below(8)]
        sctx = rng.pick((pctx, 'http')) if pctx != 'http' else 'http'
        e, _ = gen_expr(rng, cplanes, act, meta, sctx, 1 if rng.chance(1, 2) else 0, b,
                        act == 'log' or rng.chance(1, 3))
        sep = rng.pick((' ', ' ', '  ', '\t'))
        dirs.append(('policy', pctx, '%s%sif %s' % (act, sep, e)))
    for (sctx, name, cls, mem) in meta.sets:
        d = ('set', sctx, '@%s %s' % (name, mem))
        if rng.chance(1, 3):
            late.append(d)            # declared after the rule that uses it
        else:
            dirs.insert(0, d)
    dirs += late
    if rng.chance(3, 4):
        dirs.insert(0, ('mode', 'http', rng.pick(('deny', 'deny', 'log', 'off'))))
    if rng.chance(1, 2):
        dirs.insert(0, ('mode', pctx, rng.pick(('deny', 'deny', 'deny', 'log', 'off'))))
    return dirs, run, meta


# ---------------------------------------------------------------------------------------------------
# Requests: state vectors, addresses, records
# ---------------------------------------------------------------------------------------------------

def plain_v4(rng):
    """An IPv4 address outside every hold-harmless entry (reserved space is in the list)."""
    while True:
        a = ipaddress.IPv4Address(rng.u32())
        if not R.hh_member(a):
            return str(a)


def draw_addr(rng):
    """Ordinary addresses are drawn outside hold-harmless, so step 1 decides only where it is meant to:
    in the 1/32 of draws taken from inside a hold-harmless entry (and then only when eligible), and for
    the ::, ::1 forms, which the list holds."""
    k = rng.below(32)
    if k < 14:
        return plain_v4(rng)
    if k < 24:
        while True:
            a = ipaddress.IPv6Address((0x2a10 << 112) | (rng.u64() << 48) | (rng.u32() << 16) | rng.below(65536))
            if not R.hh_member(a):
                return str(a)
    if k < 27:
        return '::ffff:' + plain_v4(rng)
    if k < 29:
        return '::' + str(ipaddress.IPv4Address(rng.u32() | 0x01000000))
    if k < 30:
        return '::'
    if k < 31:
        return '::1'
    net = rng.pick(R.HH_NETS)
    return str(net[rng.below(min(net.num_addresses, 1 << 30))])


def draw_record(rng, plane, meta):
    s = R.SCHEMA[plane]
    if s == 'f1':
        if rng.chance(1, 2):
            return {'sev': rng.below(5) | rng.pick((0, 0, 0x80, 0x40, 0x10, 0x20))}
        return {'sev': rng.below(256)}
    if s == 'member':
        m = R.MEMBER_MASK[plane]
        k = rng.below(10)
        fl = rng.below(m + 1) if k < 5 else (rng.below(256) if k < 8 else rng.u32())
        reason = rng.below(3) if rng.chance(1, 2) else rng.below(256)
        return {'flags': fl, 'source': rng.below(256), 'reason': reason if plane == 3 else
                (0 if rng.chance(3, 4) else rng.below(256))}
    k = rng.below(10)
    if k < 2:
        asn = R.ASN_SENTINEL
    elif k < 6 and meta.asns:
        asn = rng.pick(sorted(meta.asns))
    else:
        asn = draw_asn(rng)
    k = rng.below(20)
    if k < 8 and meta.countries:
        country = R.COUNTRY[rng.pick(sorted(meta.countries))]
    elif k < 13:
        country = R.COUNTRY[rng.pick(sorted(R.COUNTRY))]
    elif k < 15:
        country = 0
    elif k < 17:
        country = rng.below(1000)
    else:
        country = rng.below(65536)
    return {'asn': asn, 'country': country,
            'rov': rng.below(4) if rng.chance(3, 5) else rng.below(256),
            'rir': rng.below(6) if rng.chance(3, 5) else rng.below(256),
            'flags': rng.below(8) if rng.chance(1, 2) else rng.below(256),
            'asn_rep': rng.below(5) if rng.chance(3, 5) else rng.below(256)}


def rec_line(who, plane, rec):
    if rec is None:
        return 'rec %s %s none' % (who, R.PLANES[plane - 1])
    fields = R.REC_FIELDS[R.SCHEMA[plane]]
    return 'rec %s %s %s' % (who, R.PLANES[plane - 1], ' '.join('%s=%d' % (f, rec[f]) for f in fields))


def same_key(a, b, plane):
    """Do two canonical addresses necessarily read one record of `plane`? (64-bit IPv6 keys)"""
    if a == b:
        return True
    if R.SCHEMA[plane] == 'routing' and a.version == 6 and b.version == 6:
        return (int(a) >> 64) == (int(b) >> 64)
    return False


def tenant_line(rng, st):
    if st == 'fresh':
        # valid_until 0 is no bound: fresh at any now, the reading a `now > valid_until` test gets wrong
        k = rng.below(8)
        vu = 0 if k == 0 else (U64 - 1 if k == 1 else NOW + rng.below(10 ** 7))
        return 'tenant fresh %d %d' % (NOW, vu)
    if st == 'grace':
        d = GRACE if rng.chance(1, 6) else 1 + rng.below(GRACE)
        return 'tenant stale %d %d' % (NOW, NOW - d)
    if st == 'lapsed':
        k = rng.below(6)
        # valid_until 0 is no bound (FORMAT.md, we_is_stale()), never a lapse: the earliest lapsed bound is 1
        vu = 1 if k == 0 else (NOW - GRACE - 1 if k == 1 else NOW - GRACE - 1 - rng.below(10 ** 9))
        return 'tenant stale %d %d' % (NOW, vu)
    return 'tenant %s %d %d' % (st, NOW, rng.below(1 << 40))


MODE_NUM = {'off': 1, 'log': 2, 'deny': 3}


def conf_for(rng, dirs, ctx):
    mode = 0
    for c in R.ancestors(ctx):
        found = [d for d in dirs if d[0] == 'mode' and d[1] == c]
        if found:
            mode = MODE_NUM[found[-1][2]]
            break
    ai = 1 if rng.chance(1, 4) else 0
    if rng.chance(1, 16):
        mode, ai = rng.pick(((0, 0), (4, 0), (7, 1), (255, 0), (3, 2), (2, 255)))
    return mode, ai


def case_rng(cid):
    """Each case draws from its own stream, derived from its id, so what a case draws (addresses,
    records, times) never shifts the program stream: an edit to hold-harmless.txt, which the address
    draws consult, changes case contents but never which programs are generated or how many cases."""
    return Rng(((SEED ^ (cid * 0x632BE59BD9B4E019)) & U64) or 1)


def write_cases(rng, out, pid, leg, dirs, run, cfg, meta, cid, absent=(), legacy=False):
    out.write('program %s %s\n' % (pid, leg))
    for k, c, a in dirs:
        out.write('dir %s %s %s\n' % (k, c, R.escape(a if isinstance(a, bytes) else a.encode())))
    out.write('run %s\n' % run)
    if absent:
        out.write('absent %s\n' % ' '.join(absent))
    if legacy:
        out.write('legacy\n')
    if cfg is None:
        return cid, 0
    prog = cfg.effective(run)
    planes = set()
    for p in (cfg.floor, prog):
        if p is not None:
            for r in p.rules:
                planes |= r.dep
    nonten = sorted(x for x in planes if x != R.TENANT)
    n = 0
    for mask in range(1 << len(nonten)):
        for tst in R.TENANT_STATES:
            cid += 1
            n += 1
            rng = case_rng(cid)
            out.write('case %d\n' % cid)
            out.write('conf floor %d %d\n' % conf_for(rng, dirs, 'http'))
            out.write('conf ctx %d %d\n' % conf_for(rng, dirs, run))
            for i, p in enumerate(nonten):
                if mask >> i & 1:
                    # one unknown plane in four is a generation-0 map, which still carries its records:
                    # an evaluator that reads them (or the template) as definite disagrees (D-ae)
                    out.write('plane %s %s\n' % (R.PLANES[p - 1], 'gen0' if rng.chance(1, 4) else 'stale'))
            out.write(tenant_line(rng, tst) + '\n')
            fa = draw_addr(rng)
            if rng.chance(1, 4):
                sa = fa
                if '.' in fa and ':' not in fa and rng.chance(1, 2):
                    sa = '::ffff:' + fa
            else:
                sa = draw_addr(rng)
                while R.canon(sa) == R.canon(fa):
                    sa = draw_addr(rng)
            ca, cb = R.canon(fa), R.canon(sa)
            out.write('addr floor %s\naddr server %s\n' % (fa, sa))
            out.write('flags %d %d\n' % (rng.below(2), 1 if rng.chance(1, 32) else 0))
            # the unspecified address names no client: the server slot names the floor's (POLICY.md section
            # 3.2), so its records are the floor's
            equal = ca == cb or int(cb) == 0
            indep = (not equal) and rng.chance(1, 2)
            for p in sorted(planes | {R.TENANT}):
                fr = None if rng.chance(1, 4) else draw_record(rng, p, meta)
                out.write(rec_line('floor', p, fr) + '\n')
                if equal or not indep or same_key(ca, cb, p):
                    sr = fr
                else:
                    sr = None if rng.chance(1, 4) else draw_record(rng, p, meta)
                out.write(rec_line('server', p, sr) + '\n')
            out.write('end\n')
    return cid, n


# ---------------------------------------------------------------------------------------------------
# The limit programs (N3): each at the boundary and one past
# ---------------------------------------------------------------------------------------------------

def limit_programs():
    """(name, dirs, run, expected layer or None for accepted)."""
    P = 'http/server:a'
    out = []

    def pol(texts):
        return [('policy', P, t) for t in texts]
    out.append(('rules-256', pol(['deny if c2'] * 256), P, None))
    out.append(('rules-257', pol(['deny if c2'] * 257), P, 'program'))
    r64 = 'deny if not ' + ' or '.join(['c2'] * 32)       # 64 operations
    out.append(('ops-4096', pol([r64] * 64), P, None))
    out.append(('ops-4097', pol([r64] * 64 + ['deny if c2']), P, 'program'))
    out.append(('rule-ops-64', pol([r64]), P, None))
    out.append(('rule-ops-65', pol([' or '.join(['c2'] * 33)]), P, 'parsing'))
    out.append(('nest-16-paren', pol(['deny if ' + '(' * 16 + 'tor_exit' + ')' * 16]), P, None))
    out.append(('nest-17-paren', pol(['deny if ' + '(' * 17 + 'tor_exit' + ')' * 17]), P, 'parsing'))
    out.append(('nest-16-not', pol(['deny if ' + 'not ' * 16 + 'tor_exit']), P, None))
    out.append(('nest-17-not', pol(['deny if ' + 'not ' * 17 + 'tor_exit']), P, 'parsing'))
    out.append(('nest-16-mixed', pol(['deny if ' + 'not (' * 8 + 'c2' + ')' * 8]), P, None))
    out.append(('nest-17-mixed', pol(['deny if not ' + 'not (' * 8 + 'c2' + ')' * 8]), P, 'parsing'))
    sets = [('set', 'http', '@s%d KP' % i) for i in range(1024)]
    out.append(('sets-1024', sets + pol(['deny if country in @s1023']), P, None))
    out.append(('sets-1025', sets + [('set', 'http', '@s1024 KP')] + pol(['deny if country in @s0']), P, 'sets'))
    k = 0
    while len('log if asn in {' + ','.join(str(i) for i in range(k + 1)) + '}') <= 2048:
        k += 1
    arg = 'log if asn in {' + ','.join(str(i) for i in range(k))
    arg += ' ' * (2047 - len(arg)) + '}'
    assert len(arg) == 2048
    out.append(('arg-2048', pol([arg]), P, None))
    out.append(('arg-2049', pol([arg[:-1] + ' }']), P, 'length'))
    out.append(('ident-64', [('set', P, '@' + 'a' * 64 + ' KP')] + pol(['deny if country in @' + 'a' * 64]), P, None))
    out.append(('ident-65', [('set', P, '@' + 'a' * 65 + ' KP')], P, 'lexing'))
    mem = ' '.join(str(i) for i in range(538))
    out.append(('asn-set-538', [('set', P, '@big ' + mem)] + pol(['log if asn in @big']), P, None))
    # The per-rule instruction maximum: 32 `!=` atoms in an or-chain, 63 operations, 127 instructions.
    neq32 = 'log if ' + ' or '.join('asn != %d' % (64496 + i) for i in range(32))
    out.append(('instr-127-rule', pol([neq32]), P, None))
    # The context's instruction maximum, 8,448 = 2 x 4,096 + 256: every operation an `!=` atom or a
    # connective, 4,096 operations over 256 rules, which 128 rules of 9 atoms (17 operations, 35
    # instructions) and 128 of 8 (15 operations, 31 instructions) reach exactly. (256 rules of the
    # 127-instruction shape would be 16,128 operations, far past the 4,096 limit.)
    neq9 = 'deny if ' + ' or '.join('asn != %d' % (64496 + i) for i in range(9))
    neq8 = 'deny if ' + ' or '.join('asn != %d' % (64496 + i) for i in range(8))
    out.append(('instr-8448', pol([neq9] * 128 + [neq8] * 128), P, None))
    out.append(('instr-8448-then-rule-257', pol([neq9] * 128 + [neq8] * 128 + ['deny if c2']), P, 'program'))
    return out


# ---------------------------------------------------------------------------------------------------
# POLICY.md's named rows (section 9), as programs the differential runs under every state vector
# ---------------------------------------------------------------------------------------------------

ROWS = (
    ('N4-deny-positive', ['deny if tor_exit is unknown']),
    ('N4-design-example', ['allow if tor_exit is not unknown and not tor_exit', 'deny if listed >= low']),
    ('N4-design-example-alone', ['allow if tor_exit is not unknown and not tor_exit']),
    ('N4-allow-negative-later-deny', ['allow if not tor_exit is unknown', 'deny if c2']),
    ('N4-log-either', ['log if tor_exit is unknown', 'log if c2 is not unknown', 'deny if listed >= high']),
    ('K2-K4-allow-at-U', ['allow if tor_exit or c2', 'deny if listed >= low']),
    ('K2-U-and-F', ['allow if tor_exit and c2', 'deny if listed >= low']),
    ('K3-jumps', ['deny if tor_exit and c2', 'deny if tor_exit or c2']),
    ('F1-log-then-deny', ['log if tor_exit', 'log if c2', 'deny if listed >= low', 'allow if proxy']),
    ('F4-tenant', ['allow if tenant_allow', 'deny if not tenant_allow', 'allow if not tenant_allow',
                   'deny if tenant_deny', 'allow if not tenant_deny', 'allow if tenant_allow is unknown',
                   'deny if listed >= low']),
    ('F4-tenant-deny-not-allow', ['deny if not tenant_allow']),
    ('F4-tenant-positive-allow', ['allow if tenant_allow', 'deny if listed >= low']),
    ('D2-capture-under-or', ['allow if tor_exit or asn in @partners', 'deny if listed >= low']),
    ('D2-correlated', ['deny if (asn == 64496 and not asn == 64496) or tor_exit']),
    ('S2-sets', ['deny if asn in { 64496 64497 }', 'deny if asn in { 64496 undetermined }',
                 'deny if asn in { undetermined }', 'deny if asn in { 4294967294 }']),
    ('S2-set-without-undetermined', ['deny if asn in { 64496 64497 }']),
    ('P2-sentinel', ['deny if country != undetermined', 'deny if rpki != undetermined',
                     'deny if asn != undetermined', 'deny if registry_rir != undetermined']),
    ('M4-clamps', ['log if rpki == undetermined', 'log if rir == undetermined', 'log if asn_rep == undetermined',
                   'log if rpki_reason == undetermined', 'log if country == undetermined',
                   'log if listed == critical', 'deny if rpki == unrouted']),
    ('N5-sentinel-warning', ['allow if asn_rep != highly_suspicious', 'allow if not country in { NL }',
                             'allow if not (country == NL or country == BE)', 'deny if asn_rep != reputable']),
    ('N8-all-absent', ['deny if listed >= none', 'deny if listed < low', 'deny if not tor_exit',
                       'deny if not country in { NL }', 'deny if tor_exit']),
    ('D1-capturing-allow', ['deny if c2', 'allow if tor_exit or proxy', 'deny if listed >= low', 'log if spam']),
    ('Dz-undetermined-in-sentinel-sets', ['log if asn in { undetermined 0 }', 'deny if country in { undetermined NL }',
                                          'log if asn in @u', 'deny if rpki in { undetermined invalid }']),
)


def row_programs():
    P = 'http/server:a'
    for name, rules in ROWS:
        dirs = [('mode', 'http', 'deny'), ('mode', P, 'deny'), ('set', P, '@partners 64496 64497'),
                ('set', P, '@u undetermined')]
        dirs += [('policy', P, r) for r in rules]
        if name.startswith('F1'):
            dirs.insert(0, ('floor', 'http', 'log if listed >= low'))
        yield name, dirs, P


# ---------------------------------------------------------------------------------------------------
# One program per phrase of section 1.5's table, so every phrase is emitted (the coverage matrix's
# phrase cells), plus the interleaved-context polarity case of D-x
# ---------------------------------------------------------------------------------------------------

def phrase_programs():
    P = 'http/server:a'

    def pol(*texts, ctx=P):
        return [('policy', ctx, t) for t in texts]
    big = []
    for i in range(200):                       # 200 ASN sets of 280 members, 21 nodes each: past 256 KiB
        mem = ' '.join(str(i * 300 + k) for k in range(280))
        big.append(('set', P, '@b%d %s' % (i, mem)))
    # a refusal in a context longer than the error's 128 bytes: both readings render it the one way (D-ad)
    long_ctx = 'http/server:' + 'long-name.example' * 6 + '/location:/' + 'deep/' * 12 + 'end'
    assert len(long_ctx) > 127
    yield 'byte 0xHH is not allowed', pol('deny if tor_\x01exit', ctx=long_ctx)
    # one program per phrase this oracle adds to the table (D-k), so each is compared and has its cell
    yield 'a non-digit in a number', [('policy', P, 'deny if asn == 12x4')]
    yield 'unbalanced parentheses', [('policy', P, 'deny if (tor_exit or c2')]
    yield 'is not a boolean', [('policy', P, 'deny if asn')]
    yield 'only literals inside braces', [('policy', P, 'deny if country in { NL ( }')]
    yield 'only literals in a set declaration', [('set', P, '@s NL ( BE'), ('policy', P, 'deny if country in @s')]
    yield 'a set declaration names its set with @', [('set', P, 's NL BE')]
    yield 'is takes unknown or not unknown', [('policy', P, 'deny if tor_exit is known')]
    yield 'a mode of off, log or deny', [('mode', P, 'block')]
    yield 'a threshold of off, low, medium, high or critical', [('threshold', P, 'severe')]
    yield 'allow_inferred takes on or off', [('allow_inferred', P, 'maybe')]
    yield 'a floor is http-level only', [('floor', P, 'deny if c2')]
    yield 'an unknown directive', [('limit', P, 'deny if c2')]
    yield 'argument over 2,048 bytes', pol('log if asn in {' + ','.join(['1'] * 1100) + '}')
    yield 'byte 0xHH is not allowed', pol('deny if tor_\x00exit')
    yield 'identifier over 64 bytes', pol('deny if asn in @' + 'a' * 65)
    yield 'a number with a sign', pol('deny if asn == -1')
    yield 'a leading zero other than 0', pol('deny if asn == 010')
    yield 'more than 10 digits', pol('deny if asn == 12345678901')
    yield 'above 2^32 - 1', pol('deny if asn == 4294967296')
    yield 'the sentinel 4294967295', pol('deny if asn == 4294967295')
    yield 'asdot', pol('deny if asn == as1.10')
    yield 'an unknown country code', pol('deny if country in { NL XX }')
    yield 'uk', pol('deny if country == uk')
    yield 'an upper-case keyword or literal', pol('deny if rpki == Valid')
    yield 'a bare literal in expression mode', pol('deny if valid')
    yield 'a stray @', pol('deny if asn in @ x')
    yield 'an unknown operator', pol('deny if rpki === valid')
    yield 'trailing input', pol('deny if tor_exit garbage')
    yield 'and/or mixed in a chain', pol('deny if tor_exit and c2 or spam')
    yield 'unbalanced or nested braces', pol('deny if country in { NL')
    yield 'a stray }', pol('deny if (tor_exit })')
    yield 'nesting over 16', pol('deny if ' + '(' * 17 + 'c2' + ')' * 17)
    yield 'over 64 operations in a rule', pol(' or '.join(['deny if c2'] + ['c2'] * 32))
    yield 'an action without if', pol('deny')
    yield 'an empty expression', pol('deny if')
    yield 'an unknown attribute or word', pol('deny if tor_exits')
    yield 'a literal of the wrong class', pol('deny if rpki == NL')
    yield 'an ordered comparison on anything but listed', pol('deny if asn >= 64496')
    yield 'in or == on a bool', pol('deny if tor_exit == valid')
    yield 'undetermined on a bool', pol('deny if tor_exit == undetermined')
    yield 'undetermined on a bool | in', pol('deny if tor_exit in { undetermined }')
    yield 'a literal of the wrong class | undetermined in a level set', pol('log if listed in { low undetermined }')
    yield 'a set used against an attribute of another class | undetermined against listed', \
        [('set', P, '@u undetermined')] + pol('log if listed in @u')
    yield 'an ordered comparison on anything but listed | before the operand', pol('deny if tor_exit >= undetermined')
    yield 'an inline set whose members are not all of one class', pol('deny if asn in { 64496 NL }')
    yield '@set undefined in this context or an enclosing one', pol('deny if asn in @nosuch')
    yield 'a duplicate definition in one scope', [('set', P, '@x KP'), ('set', P, '@x SY')] + pol('deny if country in @x')
    yield 'a definition shadowing an outer set', [('set', 'http', '@x KP'), ('set', P, '@x SY')]
    yield 'an empty set', pol('deny if country in { }')
    yield 'a declaration with no members', [('set', P, '@e')]
    yield 'a declared set whose members are not of one class', [('set', P, '@e KP 64496')]
    yield 'a set used against an attribute of another class', [('set', P, '@e KP')] + pol('deny if asn in @e')
    yield 'more than 1,024 sets in the configuration', [('set', 'http', '@s%d KP' % i) for i in range(1025)]
    yield 'over 256 rules in a context', pol(*(['deny if c2'] * 257))
    yield 'over 4,096 operations in a context', pol(*(['deny if not ' + ' or '.join(['c2'] * 32)] * 64 + ['deny if c2']))
    yield 'over 256 KiB of program bytes', big + pol(*['log if asn in @b%d' % i for i in range(200)])
    yield 'allow in a floor program', [('floor', 'http', 'allow if tor_exit')]
    yield 'whisper_edge_threshold in a context with policy lines', pol('deny if c2') + [('threshold', P, 'high')]
    yield 'is unknown whose polarity lets a deny fire because of an outage', pol('deny if tor_exit is unknown')
    # D-x: interleaved contexts, the earlier fault in the file is the one reported (server:a rule 2)
    yield 'polarity in file order across contexts', [
        ('policy', P, 'deny if c2'), ('policy', 'http/server:b', 'deny if c2'),
        ('policy', P, 'deny if tor_exit is unknown'), ('policy', 'http/server:b', 'deny if proxy is unknown')]


# ---------------------------------------------------------------------------------------------------
# Planes absent at configuration time: inert rules, the x class, the two reports
# ---------------------------------------------------------------------------------------------------

def threshold_programs():
    """A context holding only a mode and a threshold, as the RUN context, under every environment the
    sugar's reading depends on (D-af): all planes present (armed), reputation absent (inert, reported as
    the written rule would be), another plane absent (armed), and the legacy synonym with reputation
    absent (never inert); each threshold level, and beside it the written rule under the same absence."""
    P = 'http/server:t'
    for lvl in ('low', 'medium', 'high', 'critical'):
        dirs = [('mode', 'http', 'deny'), ('mode', P, 'deny'), ('threshold', P, lvl)]
        yield 'thr-%s-present' % lvl, dirs, P, (), False
        yield 'thr-%s-absent-reputation' % lvl, dirs, P, ('reputation',), False
        yield 'thr-%s-absent-routing' % lvl, dirs, P, ('routing',), False
        yield 'thr-%s-legacy-absent-reputation' % lvl, dirs, P, ('reputation',), True
    yield 'thr-off-absent-reputation', [('mode', P, 'deny'), ('threshold', P, 'off')], P, ('reputation',), False
    yield 'written-high-absent-reputation', [('mode', P, 'deny'), ('policy', P, 'deny if listed >= high')], P, \
        ('reputation',), False


def absent_programs():
    P = 'http/server:a'
    yield ['routing'], [('set', P, '@partners 64496 64497'), ('policy', P, 'allow if asn in @partners'),
                        ('policy', P, 'deny if listed >= low'), ('policy', P, 'log if tor_exit')]
    yield ['tor'], [('policy', P, 'deny if tor_exit'), ('policy', P, 'deny if listed >= high'),
                    ('policy', P, 'log if tor_exit is unknown')]
    yield ['threat', 'anonymizer'], [('floor', 'http', 'deny if c2'), ('policy', P, 'allow if proxy or vpn'),
                                     ('policy', P, 'deny if c2'), ('policy', P, 'deny if rpki_unreachable')]
    yield ['tenant'], [('policy', P, 'allow if tenant_allow'), ('policy', P, 'deny if listed >= medium')]
    yield ['registry', 'routing'], [('policy', P, 'deny if rpki == invalid and listed >= high'),
                                    ('policy', P, 'deny if listed >= high'),
                                    ('policy', P, 'log if registry_country in { RU }')]


# ---------------------------------------------------------------------------------------------------
# The state-vector expectation, derived from the program TEXT and nothing the oracle computed
# ---------------------------------------------------------------------------------------------------

GEN_PLANE = {
    'listed': 1, 'inferred': 1, 'tor_exit': 2, 'rpki_unreachable': 3, 'rpki_reason': 3, 'rpki': 4, 'asn': 4,
    'asn_rep': 4, 'country': 4, 'rir': 4, 'anycast': 4, 'moas': 4, 'narrowed': 4, 'proxy': 5, 'vpn': 5,
    'c2': 6, 'bruteforce': 6, 'spam': 6, 'phishing': 6, 'scanner': 6, 'state_actor': 6,
    'registry_country': 7, 'registry_rir': 7, 'tenant_allow': 8, 'tenant_deny': 8,
}


def text_planes(texts):
    """The non-tenant planes a set of rule texts names: attribute words outside braces, outside the
    literal after an operator, and outside set names."""
    import re
    planes = set()
    for t in texts:
        t = re.sub(r'\{[^}]*\}', ' ', t)
        t = re.sub(r'@\S+', ' ', t)
        t = re.sub(r'(==|!=|>=|<=|>|<)\s*\S+', ' ', t)
        for w in re.findall(r'[a-z0-9_]+', t):
            if w in GEN_PLANE and GEN_PLANE[w] != 8:
                planes.add(GEN_PLANE[w])
    return planes


def expected_cases(dirs, run):
    """2^k x 5: k the non-tenant planes the floor and the run context's rules name (the generator puts a
    program's policy lines in one context, which is the run context or its parent), 5 tenant states."""
    texts = [a for k, c, a in dirs if k == 'floor' or (k == 'policy' and run.startswith(c))]
    return (1 << len(text_planes(texts))) * 5


# ---------------------------------------------------------------------------------------------------
# Lexical mutations of generated rules
# ---------------------------------------------------------------------------------------------------

def mutate(rng, text):
    b = bytearray(text.encode())
    k = rng.below(5)
    pos = rng.below(len(b) + 1)
    if k == 0:
        b.insert(pos, rng.below(256))
    elif k == 1 and b:
        b[min(pos, len(b) - 1)] = rng.below(256)
    elif k == 2 and b:
        del b[min(pos, len(b) - 1)]
    elif k == 3:
        words = bytes(b).split(b' ')
        i = rng.below(len(words))
        words[i] = words[i].upper() if rng.chance(1, 2) else words[i].capitalize()
        b = bytearray(b' '.join(words))
    else:
        b.insert(pos, rng.pick(b'(){},@=!<>#;"\\'))
    if 0x1E in b:
        b = b.replace(b'\x1e', b'\x1f')
    return bytes(b)


# ---------------------------------------------------------------------------------------------------
# The exhaustive K3 leg
# ---------------------------------------------------------------------------------------------------

EX_ATOMS = ('tor_exit', 'c2', 'proxy')          # three planes, so each atom's value is independent
EX_PLANES = ('tor', 'threat', 'anonymizer')


def compositions(n):
    """Every ordered split of n atom slots into at least two chain operands."""
    out = []

    def rec(rem, cur):
        if rem == 0:
            if len(cur) >= 2:
                out.append(cur)
            return
        for k in range(1, rem + 1):
            rec(rem - k, cur + [k])
    rec(n, [])
    return out


def ex_shapes(n, nest):
    """Every expression with exactly n atom slots (written A) whose nesting, `not` and parentheses
    together on any path, is at most `nest`. Returns a list of (text, is_chain)."""
    res = []
    if n == 1:
        res.append(('A', False))
    if nest >= 1:
        for t, ch in ex_shapes(n, nest - 1):
            if not ch:
                res.append(('not ' + t, False))
        if nest >= 2:
            for t, ch in ex_shapes(n, nest - 2):
                if ch:
                    res.append(('not (%s)' % t, False))
    for conn in ('and', 'or'):
        for parts in compositions(n):
            combos = ['']
            for i, p in enumerate(parts):
                opts = [t for t, ch in ex_shapes(p, nest) if not ch]
                if nest >= 1:
                    opts += ['(%s)' % t for t, ch in ex_shapes(p, nest - 1) if ch]
                sep = '' if i == 0 else ' %s ' % conn
                combos = [c + sep + o for c in combos for o in opts]
            res += [(c, True) for c in combos]
    return res


def ex_exprs(max_atoms=3, max_nest=2):
    """Every expression of up to 3 atoms and nesting 2, the atoms on three distinct planes."""
    out = []
    for n in range(1, max_atoms + 1):
        for t, _ in sorted(set(ex_shapes(n, max_nest))):
            s = t
            for i in range(n):
                s = s.replace('A', '{%d}' % i, 1)
            out.append((s.format(*EX_ATOMS[:n]), n))
    return out


def write_exhaustive(out):
    cid = 0
    pid = 0
    n_expr = 0
    for text, k in ex_exprs():
        n_expr += 1
        for action in ('allow', 'deny', 'log'):
            for position in ('before', 'after'):
                pid += 1
                rules = ['%s if %s' % (action, text)]
                if position == 'before':
                    rules = rules + ['deny if rpki_unreachable']
                else:
                    rules = ['deny if rpki_unreachable'] + rules
                out.write('program x%d exhaustive\n' % pid)
                for r in rules:
                    out.write('dir policy http/server:a %s\n' % r)
                out.write('run http/server:a\n')
                for vals in range(3 ** k):
                    v = []
                    x = vals
                    for _ in range(k):
                        v.append('TFU'[x % 3])
                        x //= 3
                    cid += 1
                    out.write('case x%d\nconf floor 3 0\nconf ctx 3 0\n' % cid)
                    for i in range(k):
                        if v[i] == 'U':
                            out.write('plane %s stale\n' % EX_PLANES[i])
                    out.write('tenant fresh %d %d\naddr floor 192.0.2.1\naddr server 198.51.100.1\nflags 0 0\n'
                              % (NOW, NOW + 1))
                    for i in range(k):
                        out.write(rec_line('server', R.PLANE_ID[EX_PLANES[i]],
                                           {'flags': 1 if v[i] == 'T' else 0, 'source': 0, 'reason': 0}) + '\n')
                    # the companion deny fires after the rule under test, never before it
                    out.write(rec_line('server', 3, {'flags': 1 if position == 'before' else 0,
                                                     'source': 0, 'reason': 0}) + '\n')
                    out.write('end\n')
    return n_expr, pid, cid


# ---------------------------------------------------------------------------------------------------

POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata', 'policy')


def policy_files():
    """Every .policy file under testdata/policy/, in a fixed order."""
    out = []
    for sub in ('accept', 'refuse', 'seeds', 'adversarial'):
        d = os.path.join(POLICY_DIR, sub)
        if os.path.isdir(d):
            out += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith('.policy')]
    return out


def generate(out, n_programs, n_mutations, rng=None):
    rng = rng or Rng()
    cid = 0
    pid = 0
    stats = {'generated': 0, 'limits': 0, 'mutations': 0, 'refused': 0}
    checks = fails = 0
    problems = []
    soundness = [0, 0]
    texts = []
    while stats['generated'] < n_programs:
        dirs, run, meta = gen_program(rng, pid)
        recs = [(k, c, a.encode() if isinstance(a, str) else a) for k, c, a in dirs]
        try:
            cfg = R.compile_config(recs)
        except R.Refusal:
            if not rng.chance(1, 4):
                continue
            cfg = None
            stats['refused'] += 1
        pid += 1
        stats['generated'] += 1
        cid, n = write_cases(rng, out, 'g%d' % pid, 'generated', dirs, run, cfg, meta, cid)
        if cfg is not None:
            checks += 1
            want = expected_cases(dirs, run)
            if n != want:
                fails += 1
                problems.append('program g%d ran %d state vectors; its text names planes for %d' % (pid, n, want))
            soundness_check(cfg, soundness)
            for prob in round_trip(cfg):
                fails += 1
                problems.append('program g%d: %s' % (pid, prob))
            checks += sum(len(p.rules) for p in [cfg.floor] + list(cfg.programs.values()) if p is not None)
            for k, c, a in dirs:
                if k == 'policy':
                    texts.append(a)
    for name, dirs, run in row_programs():
        pid += 1
        stats['rows'] = stats.get('rows', 0) + 1
        meta = Meta()
        meta.asns.update({64496, 64497, 4294967294})
        meta.countries.update({'NL', 'BE'})
        recs = [(k, c, a.encode()) for k, c, a in dirs]
        try:
            cfg = R.compile_config(recs)
        except R.Refusal:
            cfg = None
        cid, _ = write_cases(rng, out, 'r%d-%s' % (pid, name), 'rows', dirs, run, cfg, meta, cid)
    # the text-derived plane count reads attribute words only: a literal `asn` after rpki_reason is not
    # the routing plane, a set name is not a plane, and `c2` is the threat plane
    for texts, want in ((['deny if rpki_reason in { asn length }'], {3}), (['deny if c2'], {6}),
                        (['log if rpki_reason == asn or asn in @asn'], {3, 4}),
                        (['allow if tenant_allow', 'deny if registry_country != as'], {7})):
        checks += 1
        if text_planes(texts) != want:
            fails += 1
            problems.append('text_planes(%r) is %r, not %r' % (texts, text_planes(texts), want))
    for name, dirs in phrase_programs():
        pid += 1
        stats['phrases'] = stats.get('phrases', 0) + 1
        recs = [(k, c, a.encode()) for k, c, a in dirs]
        checks += 1
        try:
            cfg = R.compile_config(recs)
            fails += 1
            problems.append('phrase program %r compiled' % name)
        except R.Refusal as e:
            cfg = None
            want = name.split(' | ')[0] if name != 'polarity in file order across contexts' else \
                'is unknown whose polarity lets a deny fire because of an outage'
            if R.table_phrase(e.fragment) != want:
                fails += 1
                problems.append('phrase program %r emitted %r' % (name, e.fragment))
            if name == 'polarity in file order across contexts' and (e.context, e.rule) != ('http/server:a', 2):
                fails += 1
                problems.append('D-x: the polarity fault reported is %s rule %d, not the first in the file'
                                % (e.context, e.rule))
        write_cases(rng, out, 'p%d' % pid, 'phrases', dirs, 'http/server:a', cfg, Meta(), cid)
    for name, dirs, run, absent, legacy in threshold_programs():
        pid += 1
        stats['absent'] = stats.get('absent', 0) + 1
        recs = [(k, c, a.encode()) for k, c, a in dirs]
        cfg = R.compile_config(recs, absent, legacy)
        cid, _ = write_cases(rng, out, 'a%d-%s' % (pid, name), 'absent', dirs, run, cfg, Meta(), cid, absent, legacy)
    for absent, dirs in absent_programs():
        pid += 1
        stats['absent'] = stats.get('absent', 0) + 1
        recs = [(k, c, a.encode()) for k, c, a in dirs]
        cfg = R.compile_config(recs, absent)
        meta = Meta()
        meta.asns.update({64496, 64497})
        cid, _ = write_cases(rng, out, 'a%d' % pid, 'absent', dirs, 'http/server:a', cfg, meta, cid, absent)
    # files: every .policy file the tree holds (the corpus, the seeds, the adversarial inputs written
    # against the compiler) as a program both readings compile, so a file nobody generated is compared
    # line for line too, its refusal or its text and reports, and its verdicts under four tenant states
    for path in policy_files():
        recs = R.read_records(open(path, 'rb').read())
        if any(' ' in c or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in c) or not k for k, c, _ in recs):
            continue                       # a context the case format cannot carry is the corpus's alone
        pid += 1
        stats['files'] = stats.get('files', 0) + 1
        name = 'f-' + os.path.relpath(path, POLICY_DIR).replace(os.sep, '/')
        try:
            cfg = R.compile_config(recs)
        except R.Refusal:
            cfg = None
        out.write('program %s files\n' % name)
        for k, c, a in recs:
            out.write('dir %s %s %s\n' % (k, c, R.escape(a)))
        run = next((c for k, c, _ in recs if k == 'policy'), 'http')
        out.write('run %s\n' % run)
        if cfg is not None:
            for t in ('fresh', 'grace', 'null', 'revoked'):
                cid += 1
                out.write('case %d\nconf floor 3 0\nconf ctx 3 0\n%s\naddr floor 192.0.2.9\naddr server 198.51.100.9\n'
                          'flags 0 0\nend\n' % (cid, tenant_line(case_rng(cid), t)))
    # cases: every .case seed, verbatim but for its program line, so the record shapes they pin (the
    # zero and maximal bounds, the ::ffff forms, every enum value) are compared line for line as well.
    # Their leg is `cases`, which owns no coverage cell: a seed file is a handful of programs, and the
    # cells stay the generated leg's to fill.
    for path in sorted(os.path.join(POLICY_DIR, 'seeds', n) for n in os.listdir(os.path.join(POLICY_DIR, 'seeds'))
                       if n.endswith('.case')):
        stats['cases'] = stats.get('cases', 0) + 1
        for line in open(path).read().splitlines():
            if line.startswith('program '):
                pid += 1
                line = 'program c%d-%s cases' % (pid, line.split()[1])
            out.write(line + '\n')
    for name, dirs, run, layer in limit_programs():
        pid += 1
        stats['limits'] += 1
        recs = [(k, c, a.encode()) for k, c, a in dirs]
        checks += 1
        try:
            cfg = R.compile_config(recs)
            if layer is not None and layer != 'skip':
                fails += 1
                problems.append('limit %s compiled; expected a %s refusal' % (name, layer))
        except R.Refusal as e:
            cfg = None
            if layer != e.layer:
                fails += 1
                problems.append('limit %s: %s refusal, expected %s (%s)' % (name, e.layer, layer, e.what))
        if cfg is not None:
            # a large program runs a handful of vectors, not all of them
            out.write('program l%d limits\n' % pid)
            for k, c, a in dirs:
                out.write('dir %s %s %s\n' % (k, c, R.escape(a.encode())))
            out.write('run %s\n' % run)
            for t in ('fresh', 'grace', 'null', 'revoked'):
                cid += 1
                out.write('case %d\nconf floor 3 0\nconf ctx 3 0\n%s\naddr floor 192.0.2.9\naddr server 192.0.2.9\n'
                          'flags 0 0\nend\n' % (cid, tenant_line(case_rng(cid), t)))
        else:
            write_cases(rng, out, 'l%d' % pid, 'limits', dirs, run, None, None, cid)
    for i in range(n_mutations):
        pid += 1
        stats['mutations'] += 1
        base = rng.pick(texts)
        arg = mutate(rng, base)
        dirs = [('policy', 'http/server:a', arg)]
        try:
            cfg = R.compile_config(dirs)
        except R.Refusal:
            cfg = None
        cid, _ = write_cases(rng, out, 'm%d' % pid, 'mutations', dirs, 'http/server:a', cfg, Meta(), cid)
    checks += soundness[0]
    fails += soundness[1]
    return stats, cid, checks, fails, problems, soundness


def round_trip(cfg):
    """R1 over every rule: the canonical text recompiles to itself and to the same instruction stream."""
    probs = []
    for p in [cfg.floor] + list(cfg.programs.values()):
        if p is None:
            continue
        for r in p.rules:
            try:
                r2 = R.recompile_canonical(cfg, p, r)
            except R.Refusal as e:
                probs.append('rule %d: the canonical text %r is refused: %s' % (r.n, r.text, e.what))
                continue
            if R.render_rule(r2) != r.text or [(x[0], x[2]) for x in r2.instrs] != [(x[0], x[2]) for x in r.instrs]:
                probs.append('rule %d: the canonical text %r does not round-trip' % (r.n, r.text))
    return probs


def soundness_check(cfg, acc):
    progs = [p for p in [cfg.floor] + list(cfg.programs.values()) if p is not None]
    for p in progs:
        for r in p.rules:
            if len(r.atoms) > 8:
                continue
            planes = sorted(x for x in r.dep if x != R.TENANT)
            tenants = R.TENANT_STATES if R.TENANT in r.dep else ('fresh',)
            for mask in range(1 << len(planes)):
                out = {planes[i] for i in range(len(planes)) if mask >> i & 1}
                for ts in tenants:
                    acc[0] += 1
                    c = R.rule_class(r, out, ts)
                    x = R.exact_class(r, out, ts)
                    if (c == 'i' and x == 'n') or (x == 'c' and c != 'c'):
                        acc[1] += 1


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='the policy differential case generator')
    ap.add_argument('--out', required=True)
    ap.add_argument('--exhaustive', required=True)
    ap.add_argument('--programs', type=int, default=600)
    ap.add_argument('--mutations', type=int, default=400)
    a = ap.parse_args(argv)
    t0 = time.time()
    buf = io.StringIO()
    stats, n_cases, checks, fails, problems, sound = generate(buf, a.programs, a.mutations)
    data = buf.getvalue()
    # determinism: the same seed gives the same bytes
    buf2 = io.StringIO()
    generate(buf2, a.programs, a.mutations)
    checks += 1
    if hashlib.sha256(buf2.getvalue().encode('latin-1')).digest() != hashlib.sha256(data.encode('latin-1')).digest():
        fails += 1
        problems.append('a second generation from the same seed differs')
    with open(a.out, 'w', encoding='latin-1') as f:
        f.write(data)
    with open(a.exhaustive, 'w') as f:
        n_expr, n_ex_prog, n_ex_cases = write_exhaustive(f)
    for p in problems:
        print('FAIL generator: ' + p)
    print('generator: seed 0x%x; %d generated programs (%d kept refused), %d matrix-row programs, %d phrase programs, '
          '%d absent-plane programs, %d limit programs, %d mutations; %d cases'
          % (SEED, stats['generated'], stats['refused'], stats.get('rows', 0), stats.get('phrases', 0),
             stats.get('absent', 0), stats['limits'], stats['mutations'], n_cases))
    print('generator: exhaustive leg: %d expressions x 3 actions x 2 positions = %d programs, %d cases'
          % (n_expr, n_ex_prog, n_ex_cases))
    print('generator: classifier soundness against the exact brute force: %d (rule, out-set, tenant state) '
          'triples, %d unsound' % tuple(sound))
    print('generator: %.1f s' % (time.time() - t0))
    print('%d checks, %d failures' % (checks, fails))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
