#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
xserver_cases.py - the cross-server differential's case producer, run by xserver-cases.sh.

It writes the INPUT half of a run directory (what every server producer sends and serves) and the
reference columns (what the servers' answers are held to), from ONE source of everything:

  programs    the policy language's seeded generator (policy_gen.gen_program, a pinned seed), each program
              placed in an ordinal context of its own (a virtual host, or a location under one), beside the
              fixed virtual hosts the case families need (mode off, the threshold sugar, deny statuses,
              the floor's status, ACME, the header walk, address forms);
  directives  rendered once per server in that server's own syntax, with parallel structure, so ordinal
              context paths correspond (http/s3 on nginx and Apache is http/v3 on LiteSpeed, which has no
              per-location policy, so a location-level program is sent to nginx and Apache only);
  records     drawn per (plane, key) and written into the plane files by make-test-snapshot.py --records,
              the independent writer, and handed to the reference interpreter directly (never through a C
              lookup), so a lookup defect shared by the C paths is visible;
  requests    the TCP peer (a loopback address inside or outside the trusted list), the X-Forwarded-For
              lines that carry the judged address, the Host that selects the virtual host, the URI that
              selects the location or the ACME form;
  states      a plane-state schedule (a stale generation installed, a plane deleted, one rewritten in
              place, a ctime-only chown, a mode refusal, the tenant list revoked, a same-generation
              rewrite, a fresh generation), each step followed by a batch of cases evaluated under it.

The columns: `oracle.col` is the reference interpreter's action per case (policy_ref.decide over the
records); `python.col` is the twin's rendering of every variable (section 3.9 of POLICY.md: the renderer,
the walk, the formatter, ACME) with the decision's words taken from the interpreter's verdict line; the
counter totals are summed per server over the cases that server is sent, keyed by the program digests the
shipped tool compiles from the same directive lines (`whisper-edge-lookup --programs`, the one C reading
here, named in the gate's header, and held to the interpreter's canonical text line for line).

Every number here is derived; nothing is measured against a server. The server producers measure.
"""
import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import policy_ref as R      # noqa: E402
import policy_gen as G      # noqa: E402

SEED = (G.SEED ^ 0x78736572766572) & G.U64      # "xserver": a stream of its own, beside the differential's
NOW = G.NOW                                     # the interpreter's clock for the tenant's grace
SERVERS = ('nginx', 'apache', 'litespeed')
HOST_SUFFIX = 'xserver.test'
TRUST = ['127.0.0.0/24', 'unix:']               # loopback, which a producer sources with no privilege, and the
                                                # unix-socket peer (POLICY.md 3.9: judged as `::` with no header,
                                                # as the header's client with one; nginx and LiteSpeed listen on it)
UNIX_PEER = 'unix:'                             # cases.in's spelling of a request over a unix socket
HOPS = 0                                        # the hops run: `trusted_hops N` at the http level (--hops)
PRODUCE_NOW = 0                                 # the clock at produce time (--now pins it), for the grace step
GRACE_MS = 48 * 3600 * 1000
GRACE_VU = 0                                    # the grace tenant's valid-until: PRODUCE_NOW less one hour
TRUSTED_PEERS = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5']
TRUSTED_HOP = '127.0.0.9'                       # an entry inside the trusted list: a skipped hop
UNTRUSTED_PEER = '127.1.0.1'                    # loopback, outside the trusted list: the header is not read
HEADER = 'X-Forwarded-For'
FLOOR = [b'deny if listed >= critical', b'log if tor_exit']
HTTP_MODE = b'deny'
N_VHOST = 18                # generated programs placed at the virtual host
N_LOC = 6                   # generated programs placed in a location of their virtual host
CASES_PER_PROGRAM = 5
EXCLUDED_PLANES = {5, 7}    # anonymizer and registry: read by no generated program, so the default export
                            # set is smaller than `export all` and the two runs differ
BATCH_EVERY = 3             # every third base case is re-sent under each later plane state

# the module's attribute table, in its order (we_module.h, held equal to the core's by test_module)
ATTR_ORDER = ('inferred', 'rpki_unreachable', 'tor_exit', 'proxy', 'vpn', 'c2', 'bruteforce', 'spam',
              'phishing', 'scanner', 'state_actor', 'anycast', 'moas', 'narrowed', 'tenant_allow', 'tenant_deny',
              'listed', 'rpki_reason', 'rpki', 'asn', 'asn_rep', 'country', 'registry_country', 'rir', 'registry_rir')
DECISION_VARS = ('action', 'rule', 'rule_id', 'reason', 'program', 'logged', 'floor_addr', 'generations', 'verdict')
ACME_TOKEN = 'Ab_9-x'
ACME_PATH = '/.well-known/acme-challenge/' + ACME_TOKEN


def die(msg):
    sys.stderr.write('xserver-cases: %s\n' % msg)
    sys.exit(1)


def esc(v):
    """the column contract's escape: a TAB, a newline and a backslash in a value"""
    return v.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n')


def attr_plane(name):
    return R.BOOLS[name][0] if name in R.BOOLS else R.VALUED[name][0]


# ---------------------------------------------------------------------------------------------------
# The configuration: one source of directives, placed in ordinal contexts
# ---------------------------------------------------------------------------------------------------

class Vhost(object):
    """One virtual host: its ordinal n (http/s<n>), its directives per context path, its module settings,
    the servers its cases go to, and the meta the generator drew its literals with."""

    def __init__(self, n, name, kind):
        self.n = n
        self.name = name                       # a short word, for case ids
        self.kind = kind                       # 'vhost' or 'location' (the rules live in l1)
        self.path = 'http/s%d' % n
        self.dirs = []                         # (kind, context path, arg bytes), compiler directives only
        self.deny_status = {}                  # context path -> status
        self.meta = G.Meta()
        self.cases = []                        # (case name, request dict)
        self.only = None                       # the servers alone that carry this host (the unix listener's)

    @property
    def host(self):
        return 's%d.%s' % (self.n, HOST_SUFFIX)

    @property
    def rule_path(self):
        return self.path + '/l1' if self.kind == 'location' else self.path

    @property
    def servers(self):
        if self.only is not None:
            return self.only
        return ('nginx', 'apache') if self.kind == 'location' else SERVERS

    @property
    def uri_prefix(self):
        return '/l1/' if self.kind == 'location' else '/'


def remap_generated(dirs, n):
    """A generated program's directives, re-homed from the generator's two names to this host's ordinal
    paths. The floor and the http-level mode are the configuration's, drawn once, so a program's own are
    dropped; a set declared at the http level moves to the program's rule context, so set names never
    collide across programs (sibling contexts, never shadowing)."""
    loc = 'http/server:a/location:api'
    rule_ctx = loc if any(k == 'policy' and c == loc for k, c, _ in dirs) else 'http/server:a'
    kind = 'location' if rule_ctx == loc else 'vhost'
    out = []
    for k, c, a in dirs:
        a = (a if isinstance(a, bytes) else a.encode()).replace(b'\t', b' ')
        if k in ('floor',) or (k == 'mode' and c == 'http'):
            continue
        if k == 'set' and c == 'http':
            c = rule_ctx
        if c not in ('http/server:a', loc):
            continue
        if c == loc and rule_ctx != loc:
            continue                           # a mode on a location that holds no rule: no context there
        path = 'http/s%d' % n + ('/l1' if c == loc else '')
        out.append((k, path, a))
    return out, kind


def http_dirs():
    return [('mode', 'http', HTTP_MODE)] + [('floor', 'http', f) for f in FLOOR]


def compiles(dirs):
    try:
        R.compile_config(dirs)
        return True
    except R.Refusal:
        return False


def planes_of(dirs):
    """the planes a directive list's rules read, by the interpreter's compiled programs"""
    cfg = R.compile_config(dirs)
    planes = set()
    for p in [cfg.floor] + [cfg.effective(c) for c in {c for _, c, _ in dirs}]:
        if p is None:
            continue
        for r in p.rules:
            for a in r.atoms:
                planes.add(a.plane)
    return planes


def build_config(rng):
    """The virtual hosts, in ordinal order: generated vhost programs, generated location programs, then the
    fixed hosts of the case families. Returns (vhosts, every directive in file order)."""
    vhosts = []
    pid = 0
    need = {'vhost': N_VHOST, 'location': N_LOC}
    got = {'vhost': 0, 'location': 0}
    while got['vhost'] < need['vhost'] or got['location'] < need['location']:
        pid += 1
        dirs, _run, meta = G.gen_program(rng, pid)
        n = len(vhosts) + 1
        remapped, kind = remap_generated(dirs, n)
        if got[kind] >= need[kind] or not remapped:
            continue
        if not compiles(http_dirs() + remapped):
            continue                           # the generator keeps a quarter of its programs refused
        if planes_of(http_dirs() + remapped) & EXCLUDED_PLANES:
            continue
        v = Vhost(n, 'g%d' % pid, kind)
        v.dirs = remapped
        v.meta = meta
        if got[kind] % 5 == 2:
            v.dirs.append(('allow_inferred', v.rule_path, b'on'))
        if got[kind] % 3 == 1:
            v.deny_status[v.path] = 429 if got[kind] % 2 else 451
        got[kind] += 1
        vhosts.append(v)

    def fixed(name, lines, mode=None, status=None, threshold=None, inferred=None):
        v = Vhost(len(vhosts) + 1, name, 'vhost')
        if mode is not None:
            v.dirs.append(('mode', v.path, mode))
        if threshold is not None:
            v.dirs.append(('threshold', v.path, threshold))
        for line in lines:
            v.dirs.append(('policy', v.path, line))
        if inferred is not None:
            v.dirs.append(('allow_inferred', v.path, inferred))
        if status is not None:
            v.deny_status[v.path] = status
        vhosts.append(v)
        return v

    fixed('off', [b'deny if listed >= low'], mode=b'off')
    fixed('thr', [], threshold=b'high')
    fixed('st429', [b'deny if listed >= low'], status=429)
    fixed('st451', [b'deny if listed >= low'], status=451)
    fixed('fst', [b'deny if listed >= low'], status=451)
    fixed('acme', [b'deny if listed >= low'])
    fixed('hdr', [b'deny if listed >= high', b'log if tor_exit'])
    fixed('addr', [b'deny if listed >= medium'])
    fixed('inf', [b'deny if listed >= low'], inferred=b'on')
    fixed('log', [b'deny if listed >= low', b'log if listed >= medium'], mode=b'log')
    fixed('head', [b'deny if listed >= low'])
    fixed('unx', [b'deny if listed >= low']).only = ('nginx', 'litespeed')
    fixed('hop', [b'deny if listed >= high', b'log if tor_exit'])
    alldirs = http_dirs()
    for v in vhosts:
        alldirs += v.dirs
    return vhosts, alldirs


def effective_conf(alldirs, path):
    """(mode, allow_inferred) as the compiler's we_policy_conf: each its own, or the nearest enclosing one's;
    an unset mode reads as the dry-run log, with allow_inferred off."""
    mode = ai = None
    for c in R.ancestors(path):
        if mode is None:
            found = [a for k, cc, a in alldirs if k == 'mode' and cc == c]
            if found:
                mode = R.MODES[found[-1].decode()]
        if ai is None:
            found = [a for k, cc, a in alldirs if k == 'allow_inferred' and cc == c]
            if found:
                ai = 1 if found[-1] == b'on' else 0
    return (mode if mode is not None else 2, ai if ai is not None else 0)


def effective_status(vhost, path, http_status=403):
    for c in R.ancestors(path):
        if c in vhost.deny_status:
            return vhost.deny_status[c]
    return http_status


# ---------------------------------------------------------------------------------------------------
# Records: one set, keyed per plane, written to the planes and handed to the interpreter
# ---------------------------------------------------------------------------------------------------

class Records(object):
    """records[(plane id, family, key)] -> record dict or None (no range covers the key)."""

    def __init__(self, rng):
        self.rng = rng
        self.recs = {}

    @staticmethod
    def key(plane, addr):
        """the plane's key for an address: the address, or its top 64 bits on the 8-byte-key planes"""
        if addr.version == 4:
            return 4, int(addr)
        kb = 8 if R.PLANES[plane - 1] in ('routing', 'registry') else 16
        return 6, int(addr) >> (128 - 8 * kb)

    def draw(self, addr, meta, force=None):
        """draw every plane's record for an address once; `force` pins fields ({plane: {field: value}})"""
        for p in range(1, 9):
            fam, k = self.key(p, addr)
            if (p, fam, k) in self.recs:
                continue
            # a quarter of the (address, plane) pairs have no range; the tenant list covers an address only
            # when a case asks (its allow flag decides before the floor and the context, so a drawn list
            # would hide the programs behind `tenant` allows) or, for a quarter of the pairs, as a record
            # whose allow bit is clear (its deny bit and source still render)
            if p == R.TENANT and not (force and p in force):
                if self.rng.chance(1, 4):
                    rec = draw_record(self.rng, p, fam, meta)
                    rec['flags'] &= ~0x01
                else:
                    rec = None
            elif self.rng.chance(1, 4) and not (force and p in force):
                rec = None
            else:
                rec = draw_record(self.rng, p, fam, meta)
                if force and p in force:
                    rec.update(force[p])
            self.recs[(p, fam, k)] = rec

    def get(self, plane, addr):
        fam, k = self.key(plane, addr)
        return self.recs.get((plane, fam, k))

    def ranges(self, plane):
        out = {4: [], 6: []}
        for (p, fam, k), rec in sorted(self.recs.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
            if p == plane and rec is not None:
                out[fam].append((k, k, rec))
        return out


# the planes' attribute bits (FORMAT.md section 3): a plane FILE may carry no other bit, no source past the
# writer's seven feed names, no routing field outside its domain; the reader's record-domain scan refuses the
# whole file otherwise, so the records drawn here stay inside the file's domain (the clamps the evaluator
# applies to a raw block are the policy differential's business, not this one's)
MEMBER_MASK = {2: 0x01, 3: 0x01, 5: 0x03, 6: 0x3f, 8: 0x03}
FEED_COUNT = 7


def draw_record(rng, plane, fam, meta):
    """a record inside the plane file's domain, its literals drawn to meet the program's where it has any"""
    s = R.SCHEMA[plane]
    if s == 'f1':
        return G.draw_record(rng, plane, meta)
    if s == 'member':
        return {'flags': rng.below(MEMBER_MASK[plane] + 1), 'source': rng.below(FEED_COUNT),
                'reason': rng.below(3) if plane == 3 else 0}
    k = rng.below(10)
    if k < 2:
        asn = R.ASN_SENTINEL
    elif k < 6 and meta.asns:
        asn = rng.pick(sorted(meta.asns))
    else:
        asn = G.draw_asn(rng)
    k = rng.below(20)
    if k < 8 and meta.countries:
        country = R.COUNTRY[rng.pick(sorted(meta.countries))]
    elif k < 14:
        country = R.COUNTRY[rng.pick(sorted(R.COUNTRY))]
    elif k < 17:
        country = 0
    else:
        country = rng.below(1000)              # inside the domain, assigned to nothing: undetermined
    return {'asn': asn, 'country': country, 'rov': rng.below(4), 'rir': rng.below(6),
            'flags': rng.below(8 if fam == 6 else 4), 'asn_rep': rng.below(5)}


def rec_fields(plane, rec):
    return ' '.join('%s=%d' % (f, rec[f]) for f in R.REC_FIELDS[R.SCHEMA[plane]])


def write_records_file(path, plane, ranges):
    """the writer's --records input; beside it the writer leaves <name>.expect, the addresses that decide each
    range's outcome and the record bytes the C reader must find there (plane_check reads it)"""
    with open(path, 'w') as f:
        f.write('# %s: <family> <start key> <end key> field=value ...; written by xserver-cases.sh\n' % R.PLANES[plane - 1])
        for fam in (4, 6):
            for s, e, rec in ranges[fam]:
                f.write('%d %d %d %s\n' % (fam, s, e, rec_fields(plane, rec)))


def write_plane(writer, out, plane, ranges, generation, valid_until, records_path):
    name = R.PLANES[plane - 1]
    fmt = 1 if plane == 1 else 2
    write_records_file(records_path, plane, ranges)
    cmd = [sys.executable, writer, '--plane', name, '--out', out, '--format', str(fmt), '--schema',
           '--v4-index', 'radix-16', '--v6-index', 'radix-16' if fmt == 1 else 'rank',
           '--generation', str(generation), '--valid-until', str(valid_until), '--records', records_path,
           '--expect', records_path[:-4] + '.expect']
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        die('make-test-snapshot.py refused %s: %s' % (name, r.stdout.strip()))
    os.chmod(out, 0o444)


def plane_d8(path):
    """the first four bytes of the plane's header digest (FORMAT.md: offset 104), as the token renders them"""
    with open(path, 'rb') as f:
        h = f.read(192)
    return h[104:108].hex()


# ---------------------------------------------------------------------------------------------------
# Requests: the walk, ACME, the twin's rendering
# ---------------------------------------------------------------------------------------------------

TRUST_LIST, UNIX_OK = R.m_trust_list(TRUST)


def walk(peer, lines):
    """(floor (16 bytes, family) or None, mark, eligible, note) by the twin's walk over the newest 16
    lines, `older` set when a line was dropped (the servers hand the module at most 16); a unix-socket
    peer is None (judged as `::` with no header, POLICY.md 3.9); the hops run's N is the http level's."""
    p = None if peer == UNIX_PEER else R.m_entry(peer.encode())
    newest = [x.encode() for x in lines[-16:]]
    return R.m_walk(TRUST_LIST, UNIX_OK, HOPS, 1, p, newest, 1 if len(lines) > 16 else 0)


def addr_of(a):
    """(16 bytes, family) -> ipaddress object, canonical (an IPv4 key for a mapped address)"""
    b, fam = a
    return ipaddress.IPv4Address(b[:4]) if fam == 4 else ipaddress.IPv6Address(b)


def normalise_path(target):
    """the server's normalised path of a request target: percent-decoding, dot segments removed, repeated
    slashes merged (nginx merge_slashes and Apache MergeSlashes, both on by default); the query dropped"""
    path = target.split('?', 1)[0]
    path = re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), path)
    out = []
    for seg in path.split('/'):
        if seg in ('', '.'):
            continue
        if seg == '..':
            if out:
                out.pop()
            continue
        out.append(seg)
    return '/' + '/'.join(out)


def acme_exempt(method, target):
    return R.m_acme(method.encode(), target.encode(), normalise_path(target).encode())


def block_bytes(plane, rec, lapsed=0):
    """the 16-byte normalised block the module's memo holds for a record (POLICY.md section 2.7), clamped as
    the fill clamps it; the template on no range"""
    b = bytearray(16)
    n = R.normalise(plane, rec, None)
    s = R.SCHEMA[plane]
    if s == 'f1':
        b[0] = n['sev'] & 0xFF
    elif s == 'member':
        b[0:4] = (n['flags'] & 0xFFFFFFFF).to_bytes(4, 'little')
        b[5] = n['reason'] & 0xFF
    else:
        b[0:4] = (n['asn'] & 0xFFFFFFFF).to_bytes(4, 'little')
        b[4:6] = (n['country'] & 0xFFFF).to_bytes(2, 'little')
        b[6], b[7], b[8], b[9] = n['rov'] & 0xFF, n['rir'] & 0xFF, n['flags'] & 0xFF, n['asn_rep'] & 0xFF
    b[14] = lapsed
    return bytes(b)


def level_word(sev):
    lv = sev & 0x0F
    return R.LEVELS[lv if lv <= 4 else 4]


class PlaneState(object):
    """one plane's state at a batch: kind in fresh, stale, grace (the tenant, stale within its 48 h), absent,
    disarmed, revoked; generation; d8"""

    def __init__(self, kind, generation=0, d8=''):
        self.kind, self.generation, self.d8 = kind, generation, d8


def gen_token(plane, st, lazy):
    name = R.PLANES[plane - 1]
    if st.kind == 'absent':
        tok = '%s:-a' % name
    elif st.kind == 'disarmed':
        tok = '%s:-d' % name
    elif st.kind == 'revoked':
        tok = 'tenant:0'
    else:
        tok = '%s:%d.%s%s' % (name, st.generation, st.d8, '~' if st.kind in ('stale', 'grace') else '')
    return tok + ('*' if lazy else '')


def memo_state(plane, st, rec):
    """the twin renderer's state index (M_STATES) for a plane's record under a plane state"""
    if st.kind == 'revoked':
        return R.M_STATES.index('revoked')
    if st.kind == 'grace':
        return R.M_STATES.index('stale-hit' if rec is not None else 'stale-nr')   # `stale:true`, `stale:false`
    if st.kind != 'fresh':
        return R.M_STATES.index('unknown')
    return R.M_STATES.index('fresh-hit' if rec is not None else 'fresh-nr')


def verdict_word(st, rec):
    if st.kind == 'disarmed':
        return 'unknown,disarmed'
    if st.kind == 'stale':
        return 'unknown,stale'
    if st.kind != 'fresh':
        return 'unknown'
    if rec is None:
        return 'none'
    sev = rec['sev']
    return level_word(sev) + (',drop' if sev & 0x40 else '') + (',inferred' if sev & 0x80 else '')


# ---------------------------------------------------------------------------------------------------
# The interpreter, instrumented for the planes a decision touched
# ---------------------------------------------------------------------------------------------------

TOUCHED = set()
_orig_atom = R.Eval.atom


def _atom(self, a, s, ai, uniform=False):
    TOUCHED.add(a.plane)
    return _orig_atom(self, a, s, ai, uniform)


R.Eval.atom = _atom

VLINE = re.compile(r'^verdict step=(\S+) action=(\S+) program=(\S+) rule=(\d+) reason=(\S+) log_floor=(\S+) log_ctx=(\S+)$')


def decide(cfg, prog_ctx, case):
    """the interpreter's verdict for a case dict (make_request's shape) and the planes it touched"""
    TOUCHED.clear()
    req = R.make_request(case)
    vline, cline, _ev = R.decide(cfg, prog_ctx, req, None)
    m = VLINE.match(vline)
    if m is None:
        die('the interpreter printed a verdict line outside its grammar: %s' % vline)
    step, action, program, rule, reason, log_f, log_c = m.groups()
    touched = set(TOUCHED) | {R.TENANT}          # the pre-stage fills the tenant on every request
    return {'step': step, 'action': action, 'program': program, 'rule': int(rule), 'reason': reason,
            'log_floor': [int(x) for x in log_f.split(',')] if log_f != '-' else [],
            'log_ctx': [int(x) for x in log_c.split(',')] if log_c != '-' else [],
            'vline': vline, 'cline': cline, 'touched': touched}


# ---------------------------------------------------------------------------------------------------
# Rendering the configuration per server
# ---------------------------------------------------------------------------------------------------

NGX_NAMES = {'policy': 'whisper_edge_policy', 'set': 'whisper_edge_set', 'floor': 'whisper_edge_policy_floor',
             'threshold': 'whisper_edge_threshold', 'mode': 'whisper_edge_mode', 'allow_inferred': 'whisper_edge_allow_inferred'}
APACHE_NAMES = {'policy': 'WhisperEdgePolicy', 'set': 'WhisperEdgeSet', 'floor': 'WhisperEdgePolicyFloor',
                'threshold': 'WhisperEdgeThreshold', 'mode': 'WhisperEdgeMode', 'allow_inferred': 'WhisperEdgeAllowInferred'}


def q(a):
    """a directive argument quoted for nginx and Apache (no quote, backslash or dollar appears in a rule)"""
    t = a.decode('latin-1')
    for bad in ('"', '\\', '$', '\n'):
        if bad in t:
            die('a directive argument holds %r, which this renderer does not quote: %r' % (bad, t))
    return '"%s"' % t


def export_arg(export, planes):
    if export == 'all':
        return 'all'
    return ' '.join(n for n in ATTR_ORDER if attr_plane(n) in planes)


def log_vars(server, attrs):
    """the access-log fields: the case, the status, then every variable, as that server spells it"""
    fields = ['case=' + {'nginx': '$http_x_case', 'apache': '%{X-Case}i', 'litespeed': '%{X-Case}i'}[server],
              'status=' + {'nginx': '$status', 'apache': '%>s', 'litespeed': '%>s'}[server]]
    for name in DECISION_VARS + tuple(attrs):
        if server == 'nginx':
            fields.append('var_%s=$whisper_edge_%s' % (name, name))
        elif server == 'apache':
            fields.append('var_%s=%%{WHISPER_EDGE_%s}n' % (name, name.upper()))
        else:
            fields.append('var_%s=%%{WHISPER_EDGE_%s}e' % (name, name.upper()))
    return '\t'.join(fields)


def render_nginx(vhosts, alldirs, export, planes, attrs):
    o = ['# Rendered by core/xserver-cases.sh for the cross-server differential: the http-level lines and',
         '# every server block, to be included inside the producer\'s http { } after it substitutes the',
         '# placeholders (@PLANES@ @COUNTERS@ @LOGS@ @ROOT@ @PORT@ @SOCK@ @SERVER_EXTRA@; see xserver-gate.sh).',
         'whisper_edge_data @PLANES@;', 'whisper_edge_summary @COUNTERS@;', 'whisper_edge_refresh 1s;',
         'whisper_edge_trusted_proxy %s;' % ' '.join(TRUST), 'whisper_edge_trusted_header %s;' % HEADER,
         'whisper_edge_export %s;' % export_arg(export, planes)]
    if HOPS:
        o.append('whisper_edge_trusted_hops %d;' % HOPS)
    for k, c, a in alldirs:
        if c == 'http':
            o.append('%s %s;' % (NGX_NAMES[k], q(a) if k in ('policy', 'set', 'floor') else a.decode()))
    o += ['set_real_ip_from %s;' % TRUST[0], 'set_real_ip_from unix:;', 'real_ip_header %s;' % HEADER, 'real_ip_recursive on;',
          "log_format xserver escape=none '%s';" % log_vars('nginx', attrs),
          'access_log @LOGS@/xserver.log xserver;']
    for v in vhosts:
        o += ['server {', '    listen @PORT@;', '    server_name %s;' % v.host, '    root @ROOT@;', '    @SERVER_EXTRA@']
        if v.name == 'unx':
            o.append('    listen unix:@SOCK@;')  # the unix-socket peer's host: the producer's socket path
        if v.path in v.deny_status:
            o.append('    whisper_edge_deny_status %d;' % v.deny_status[v.path])
        for k, c, a in v.dirs:
            if c == v.path:
                o.append('    %s %s;' % (NGX_NAMES[k], q(a) if k in ('policy', 'set') else a.decode()))
        if v.kind == 'location':
            o.append('    location /l1/ {')
            for k, c, a in v.dirs:
                if c == v.path + '/l1':
                    o.append('        %s %s;' % (NGX_NAMES[k], q(a) if k in ('policy', 'set') else a.decode()))
            o.append('    }')
        o.append('}')
    return '\n'.join(o) + '\n'


def render_apache(vhosts, alldirs, export, planes, attrs):
    o = ['# Rendered by core/xserver-cases.sh for the cross-server differential: the server-level lines and',
         '# every <VirtualHost>, to be Included by the producer at server-config level after it substitutes the',
         '# placeholders (@PLANES@ @COUNTERS@ @LOGS@ @ROOT@ @PORT@ @SERVER_EXTRA@; see xserver-gate.sh).',
         'WhisperEdgeData @PLANES@', 'WhisperEdgeSummary @COUNTERS@', 'WhisperEdgeRefresh 10',
         'WhisperEdgeTrustedProxy %s' % ' '.join(TRUST), 'WhisperEdgeTrustedHeader %s' % HEADER,
         'WhisperEdgeExport %s' % export_arg(export, planes)]
    if HOPS:
        o.append('WhisperEdgeTrustedHops %d' % HOPS)
    for k, c, a in alldirs:
        if c == 'http':
            o.append('%s %s' % (APACHE_NAMES[k], q(a) if k in ('policy', 'set', 'floor') else a.decode()))
    o += ['RemoteIPHeader %s' % HEADER, 'RemoteIPInternalProxy %s' % TRUST[0],
          'LogFormat "%s" xserver' % log_vars('apache', attrs), 'CustomLog @LOGS@/xserver.log xserver',
          '<Directory @ROOT@>', '    Require all granted', '</Directory>']
    for v in vhosts:
        o += ['<VirtualHost *:@PORT@>', '    ServerName %s' % v.host, '    DocumentRoot @ROOT@', '    @SERVER_EXTRA@']
        if v.path in v.deny_status:
            o.append('    WhisperEdgeDenyStatus %d' % v.deny_status[v.path])
        for k, c, a in v.dirs:
            if c == v.path:
                o.append('    %s %s' % (APACHE_NAMES[k], q(a) if k in ('policy', 'set') else a.decode()))
        if v.kind == 'location':
            o.append('    <Location /l1>')
            for k, c, a in v.dirs:
                if c == v.path + '/l1':
                    o.append('        %s %s' % (APACHE_NAMES[k], q(a) if k in ('policy', 'set') else a.decode()))
            o.append('    </Location>')
        o.append('</VirtualHost>')
    return '\n'.join(o) + '\n'


def render_litespeed(vhosts, alldirs, export, planes, attrs):
    """the server-level fragment; the virtual hosts' files come from render_litespeed_vhost"""
    o = ['# Rendered by core/xserver-cases.sh for the cross-server differential: appended by the producer to',
         '# its httpd_config.conf after it substitutes the placeholders (@PLANES@ @COUNTERS@ @ROOT@ @CONF@ @PORT@ @SOCK@;',
         '# see xserver-gate.sh). Each virtual host\'s file is conf/litespeed/s<n>.conf.',
         'useIpInProxyHeader 0', 'module mod_whisper_edge {', '    ls_enabled 1',
         '    whisper_edge_data @PLANES@', '    whisper_edge_summary @COUNTERS@', '    whisper_edge_refresh 10',
         '    whisper_edge_trusted_proxy %s' % ' '.join(TRUST), '    whisper_edge_trusted_header %s' % HEADER,
         '    whisper_edge_export %s' % export_arg(export, planes)]
    if HOPS:
        o.append('    whisper_edge_trusted_hops %d' % HOPS)
    for k, c, a in alldirs:
        if c == 'http':
            o.append('    %s %s' % (NGX_NAMES[k], a.decode('latin-1')))
    o.append('}')
    for v in vhosts:
        o += ['virtualHost s%d {' % v.n, '    vhRoot @ROOT@/', '    configFile @CONF@/litespeed/s%d.conf' % v.n,
              '    allowSymbolLink 1', '    enableScript 0', '    restrained 0', '}']
    o += ['listener xserver {', '    address *:@PORT@', '    secure 0']
    for v in vhosts:
        o.append('    map s%d %s' % (v.n, v.host))
    o.append('}')
    for v in vhosts:
        if v.name == 'unx':                     # the unix-socket peer's host, on the producer's socket path
            o += ['listener xunix {', '    address UDS://@SOCK@', '    secure 0', '    map s%d %s' % (v.n, v.host), '}']
    return '\n'.join(o) + '\n'


def render_litespeed_vhost(v, attrs):
    o = ['# Rendered by core/xserver-cases.sh: the virtual host %s (http/v%d, which is http/s%d on nginx and Apache).' % (v.host, v.n, v.n),
         'docRoot $VH_ROOT/', 'enableGzip 0',
         'accessLog @LOGS@/xserver-s%d.log {' % v.n, '    useServer 0', '    logFormat "%s"' % log_vars('litespeed', attrs), '}']
    lines = [(k, a) for k, c, a in v.dirs if c == v.path]
    if lines or v.path in v.deny_status:
        o += ['module mod_whisper_edge {', '    ls_enabled 1']
        if v.path in v.deny_status:
            o.append('    whisper_edge_deny_status %d' % v.deny_status[v.path])
        for k, a in lines:
            o.append('    %s %s' % (NGX_NAMES[k], a.decode('latin-1')))
        o.append('}')
    o += ['context / {', '    location $DOC_ROOT/', '    allowBrowse 1', '}']
    return '\n'.join(o) + '\n'


# ---------------------------------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------------------------------

def draw_entry(rng):
    """an address as an X-Forwarded-For entry, outside hold-harmless: IPv4, IPv6 in 2a10::/16, or an
    IPv4 address in its mapped form (an IPv4-mapped address is judged as its IPv4 address)"""
    k = rng.below(20)
    if k < 12:
        return G.plain_v4(rng)
    if k < 17:
        while True:
            a = ipaddress.IPv6Address((0x2a10 << 112) | (rng.u64() << 48) | (rng.u32() << 16) | rng.below(65536))
            if not R.hh_member(a):
                return str(a)
    return '::ffff:' + G.plain_v4(rng)


def request(peer, lines, uri, method='GET'):
    return {'peer': peer, 'lines': list(lines), 'uri': uri, 'method': method}


def generated_cases(rng, vhosts, records):
    """five requests per generated program: a drawn address each, one floor-listed (critical), one on the
    tenant's allow list when the program reads the tenant, one past a skipped trusted hop"""
    for v in vhosts:
        if not v.name.startswith('g'):
            continue
        planes = planes_of(http_dirs() + v.dirs)
        for i in range(CASES_PER_PROGRAM):
            e = draw_entry(rng)
            force = None
            if i == 1:
                force = {1: {'sev': 4}}
            elif i == 2 and R.TENANT in planes:
                force = {8: {'flags': 1}}
            records.draw(addr_of(R.m_entry(e.encode())), v.meta, force)
            lines = [e] if i != 3 else [e + ', ' + TRUSTED_HOP]
            v.cases.append(('c%d' % i, request(TRUSTED_PEERS[i % len(TRUSTED_PEERS)], lines, '%sx%d.html' % (v.uri_prefix, i))))


def listed_entry(rng, records, sev, meta):
    """an IPv4 entry whose reputation record carries the level `sev` (0 for no range)"""
    e = G.plain_v4(rng)
    a = ipaddress.ip_address(e)
    records.draw(a, meta, {1: {'sev': sev}} if sev else None)
    if sev == 0:
        records.recs[(1,) + records.key(1, a)] = None
    return e


def family_cases(rng, vhosts, records):
    by = {v.name: v for v in vhosts}
    crit = listed_entry(rng, records, 4, G.Meta())
    high = listed_entry(rng, records, 3, G.Meta())
    med = listed_entry(rng, records, 2, G.Meta())
    low = listed_entry(rng, records, 1, G.Meta())
    none = listed_entry(rng, records, 0, G.Meta())
    inferred = listed_entry(rng, records, 1 | 0x80, G.Meta())
    peer = TRUSTED_PEERS[0]
    for name, pairs in (('off', (('crit', crit), ('low', low))), ('thr', (('high', high), ('med', med), ('none', none))),
                        ('st429', (('low', low), ('none', none))), ('st451', (('low', low), ('none', none))),
                        ('fst', (('crit', crit), ('low', low))), ('inf', (('inferred', inferred), ('low', low), ('none', none))),
                        ('log', (('crit', crit), ('med', med), ('low', low), ('none', none)))):
        for cname, e in pairs:
            by[name].cases.append((cname, request(peer, [e], '/%s.html' % cname)))
    # ACME: the exact form is exempt from the floor and the context alike; every other form is judged
    v = by['acme']
    for cname, target in (('exact', ACME_PATH), ('query', ACME_PATH + '?'), ('dotseg', '/.well-known/%2e/acme-challenge/' + ACME_TOKEN),
                          ('pct', '/.well-known/acme-challenge/%41b_9-x'), ('slashes', '/' + ACME_PATH),
                          ('twoseg', '/.well-known/acme-challenge/a/b')):
        v.cases.append(('crit-' + cname, request(peer, [crit], target)))
        v.cases.append(('low-' + cname, request(peer, [low], target)))
    # address forms: the formatter's own cases, each judged as written (the mapped one as its IPv4)
    v = by['addr']
    for cname, e in (('v4compat', '::102:304'), ('zeros', '2001:db8:0:0:1:0:0:1'), ('ones', '2001:db8:0:1:1:1:1:1'),
                     ('mapped', '::ffff:192.0.2.1'), ('drawn6', draw_entry(rng))):
        a = addr_of(R.m_entry(e.encode()))
        records.draw(a, v.meta, {1: {'sev': 2}})
        v.cases.append((cname, request(peer, [e], '/%s.html' % cname)))
    # the header walk: the shapes of POLICY.md section 3.9's table that a loopback peer can send
    v = by['hdr']
    judged = listed_entry(rng, records, 3, G.Meta())          # high: denied by this host's rule when reached
    other = listed_entry(rng, records, 1, G.Meta())
    v6 = draw_entry(rng)
    while ':' not in v6 or v6.startswith('::ffff:'):
        v6 = draw_entry(rng)
    records.draw(addr_of(R.m_entry(v6.encode())), v.meta, {1: {'sev': 3}})
    shapes = [('absent', []), ('empty', ['']), ('commas', [' , ,']), ('plain', [judged]),
              ('skipped-hop', [judged + ', ' + TRUSTED_HOP]), ('junk-right', [judged + ', junk']),
              ('junk-left', ['junk, ' + judged]), ('two-lines', [other, judged]), ('empty-last', [judged, '']),
              ('port4', [judged + ':443']), ('bracket6', ['[' + v6 + ']:8443']), ('bare6', [v6]),
              ('mapped', ['::ffff:' + judged]), ('zone', ['fe80::1%eth0']),
              ('limit-53', ['[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535']),
              ('limit-54', ['[0000:0000:0000:0000:0000:ffff:255.255.255.255]:655350']),
              ('seventeen', [other] * 16 + [judged]), ('forty', [other] * 39 + [judged]),
              ('sixteen-forged', [judged] + [other] * 15), ('untrusted-peer', [judged])]
    for cname, lines in shapes:
        v.cases.append((cname, request(UNTRUSTED_PEER if cname == 'untrusted-peer' else peer, lines, '/%s.html' % cname)))
    # HEAD: judged like GET (the policy reads no method; the ACME exemption admits GET and HEAD), with no body
    # to classify, so every server's expected class is `-`
    v = by['head']
    for cname, e in (('crit', crit), ('low', low), ('none', none)):
        v.cases.append((cname, request(peer, [e], '/%s.html' % cname, method='HEAD')))
    v.cases.append(('crit-acme-exact', request(peer, [crit], ACME_PATH, method='HEAD')))
    v.cases.append(('crit-acme-query', request(peer, [crit], ACME_PATH + '?', method='HEAD')))
    # the unix-socket peer (nginx `listen unix:`, LiteSpeed's UDS listener): `unix:` is in the trusted list,
    # so the header's client is judged when a line is there and `::` with the header missing when none is
    v = by['unx']
    for cname, lines in (('hdr-high', [judged]), ('hdr-low', [other]), ('absent', []), ('skipped-hop', [judged + ', ' + TRUSTED_HOP])):
        v.cases.append((cname, request(UNIX_PEER, lines, '/%s.html' % cname)))
    # the hops shapes (POLICY.md 3.9's trusted_hops rows): under the default run hops is 0 and the walk
    # skips trusted entries; under the hops run (--hops 2) the Nth entry from the right is judged, fewer
    # than N entries judge the leftmost with the unparsed note, so `two-plain` and `one` flip between the runs
    v = by['hop']
    for cname, lines in (('two-right', [judged, TRUSTED_HOP]), ('three', [other, judged, TRUSTED_HOP]),
                         ('two-plain', [other, judged]), ('one', [judged]), ('junk-mid', [judged, 'junk', TRUSTED_HOP]),
                         ('none', []), ('seventeen', [other] * 15 + [judged, TRUSTED_HOP])):
        v.cases.append((cname, request(peer, lines, '/%s.html' % cname)))


# ---------------------------------------------------------------------------------------------------
# The plane-state schedule
# ---------------------------------------------------------------------------------------------------

def schedule_steps():
    """(op, plane, from-file or None, the states it leaves) in order; a batch of cases follows each"""
    return [('install', 1, 'next/reputation-stale.bin', {1: 'stale'}),
            ('delete', 2, None, {2: 'absent'}),
            ('rewrite', 4, 'next/routing-rewrite.bin', {4: 'disarmed'}),
            ('ctime', 5, None, {}),
            ('refuse', 6, None, {6: 'disarmed'}),
            ('install', 8, 'next/tenant-grace.bin', {8: 'grace'}),
            ('delete', 8, None, {8: 'revoked'}),
            ('install', 7, 'next/registry-samegen.bin', {}),
            ('install', 1, 'next/reputation-gen3.bin', {1: 'fresh3'})]


# ---------------------------------------------------------------------------------------------------
# The producer
# ---------------------------------------------------------------------------------------------------

def run_tool(tool, out, planes_dir, alldirs, contexts):
    path = os.path.join(out, 'programs.in')
    with open(path, 'w') as f:
        f.write('# the configuration as the compiler reads it, one directive per line; whisper-edge-lookup --programs prints its programs\n')
        for k, c, a in alldirs:
            f.write('dir %s %s %s\n' % (k, c, R.escape(a)))
        for c in contexts:
            f.write('context %s\n' % c)
    r = subprocess.run([tool, '--probe-dir', planes_dir, '--programs', path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    with open(os.path.join(out, 'programs.out'), 'w') as f:
        # the run directory's own path is not part of the record (two runs from one seed are byte-identical):
        # the data-directory line names it, and so does a plane line's bind verdict when the module's trust
        # walk refuses the directory the run was written in
        f.write(r.stdout.replace(planes_dir, 'planes'))
    if r.returncode != 0:
        die('whisper-edge-lookup --programs exited %d: %s' % (r.returncode, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ''))
    floor = None
    progs, texts = {}, {}
    for line in r.stdout.splitlines():
        w = line.split(' ', 3)
        if w[0] == 'floor':
            floor = (None if w[1] == '-' else w[1], int(w[3]))
        elif w[0] == 'program':
            rest = w[3].split()
            progs[w[1]] = {'d16': None if w[2] == '-' else w[2], 'rules': int(rest[1]), 'mode': int(rest[3]), 'ai': int(rest[5])}
        elif w[0] == 'text':
            texts.setdefault(w[1], []).append((int(w[2]), w[3]))
    if floor is None:
        die('whisper-edge-lookup --programs printed no floor line')
    return floor, progs, texts


def check_texts(cfg, floor, progs, texts, contexts):
    """the tool's canonical text equals the interpreter's, rule for rule; the tool's effective conf equals
    this producer's reading of the directives"""
    want = {}
    for ctx in contexts:
        for line in R.program_lines(cfg, cfg.effective(ctx)):
            w = line.split(' ', 3)
            if w[0] != 'text' or w[2] == 'set':
                continue
            d16 = floor[0] if w[1] == 'floor' else progs[ctx]['d16']
            if d16 is None:
                die('the interpreter prints a %s rule for %s and the tool compiled no program there' % (w[1], ctx))
            want.setdefault(d16, {})[int(w[2])] = w[3]
    for d16, rules in want.items():
        got = dict(texts.get(d16, []))
        if got != rules:
            die('program %s: the interpreter\'s canonical text differs from the compiler\'s:\n  interpreter %r\n  compiler    %r' % (d16, rules, got))
    if PLANT == 'text':
        die('planted: the canonical texts were declared unequal')


def main(argv):
    ap = argparse.ArgumentParser(description='the cross-server differential\'s case producer')
    ap.add_argument('--out', required=True)
    ap.add_argument('--export', choices=('default', 'all'), default='default')
    ap.add_argument('--hops', type=int, default=0, help='the hops run: whisper_edge_trusted_hops N at the http level (0: none)')
    ap.add_argument('--now', type=int, default=0, help='the produce clock in epoch ms (0: read it); pins the grace step for a byte-identical rerun')
    ap.add_argument('--tool', required=True, help='the whisper-edge-lookup binary (its --probe-dir and --programs modes)')
    ap.add_argument('--writer', default=os.path.join(HERE, 'make-test-snapshot.py'))
    ap.add_argument('--oracle', default=os.path.join(HERE, 'policy_ref.py'))
    a = ap.parse_args(argv)
    global PLANT, HOPS, PRODUCE_NOW, GRACE_VU
    PLANT = os.environ.get('XSERVER_CASES_PLANT', '')
    if a.hops < 0 or a.hops > 16:
        die('--hops takes 0 to 16')
    HOPS = a.hops
    PRODUCE_NOW = a.now if a.now else int(time.time() * 1000)
    GRACE_VU = PRODUCE_NOW - 3600 * 1000       # stale an hour ago: inside the 48 h grace for the next 47 h
    out = a.out
    for d in ('conf', 'conf/litespeed', 'planes', 'next', 'records', 'www'):
        os.makedirs(os.path.join(out, d), exist_ok=True)

    rng = G.Rng(SEED)
    vhosts, alldirs = build_config(rng)
    cfg = R.compile_config(alldirs)
    contexts = ['http'] + [v.path for v in vhosts] + [v.path + '/l1' for v in vhosts if v.kind == 'location']
    records = Records(rng)
    generated_cases(rng, vhosts, records)
    family_cases(rng, vhosts, records)

    # the export set: the union of every context's default set (nginx makes its generations token set the
    # union of every attribute the configuration names, so the three servers are given the same set), or all
    planes = set(range(1, 9)) if a.export == 'all' else planes_of(alldirs) | {R.TENANT}
    attrs = [n for n in ATTR_ORDER if attr_plane(n) in planes]

    # the planes at step 0, and the files the schedule installs or rewrites later
    d8 = {}
    for p in range(1, 9):
        path = os.path.join(out, 'planes', R.PLANES[p - 1] + '.bin')
        write_plane(a.writer, path, p, records.ranges(p), 1, 0, os.path.join(out, 'records', R.PLANES[p - 1] + '.txt'))
        d8[(p, 1)] = plane_d8(path)
    stale = os.path.join(out, 'next', 'reputation-stale.bin')
    write_plane(a.writer, stale, 1, records.ranges(1), 2, 1, os.path.join(out, 'records', 'reputation-stale.txt'))
    d8[(1, 2)] = plane_d8(stale)
    gen3 = os.path.join(out, 'next', 'reputation-gen3.bin')
    write_plane(a.writer, gen3, 1, records.ranges(1), 3, 0, os.path.join(out, 'records', 'reputation-gen3.txt'))
    d8[(1, 3)] = plane_d8(gen3)
    # the tenant plane stale within its grace: the same allow list at generation 2, valid-until an hour before
    # the produce clock, so the servers read `stale` and the twin reads grace until 47 h after this produce
    # (the gate's --check-inputs refuses an older run directory by name)
    grace = os.path.join(out, 'next', 'tenant-grace.bin')
    write_plane(a.writer, grace, 8, records.ranges(8), 2, GRACE_VU, os.path.join(out, 'records', 'tenant-grace.txt'))
    d8[(8, 2)] = plane_d8(grace)
    # a same-generation registry with different bytes (a same generation is refused as not newer, so its token keeps the old
    # digest), and a routing plane to rewrite in place (different bytes, same generation: disarmed)
    other = Records(G.Rng(SEED ^ 1))
    for (p, fam, k) in list(records.recs):
        if p in (4, 7):
            other.recs[(p, fam, k)] = draw_record(other.rng, p, fam, G.Meta())
    write_plane(a.writer, os.path.join(out, 'next', 'registry-samegen.bin'), 7, other.ranges(7), 1, 0, os.path.join(out, 'records', 'registry-samegen.txt'))
    write_plane(a.writer, os.path.join(out, 'next', 'routing-rewrite.bin'), 4, other.ranges(4), 1, 0, os.path.join(out, 'records', 'routing-rewrite.txt'))

    floor, progs, texts = run_tool(a.tool, out, os.path.join(out, 'planes'), alldirs, contexts)
    check_texts(cfg, floor, progs, texts, contexts)
    for ctx in contexts:
        mine = effective_conf(alldirs, ctx)
        if (progs[ctx]['mode'], progs[ctx]['ai']) != mine:
            die('context %s: the compiler\'s effective conf is %r, this producer read %r' % (ctx, (progs[ctx]['mode'], progs[ctx]['ai']), mine))
    http_conf = effective_conf(alldirs, 'http')

    # the batches: every case at step 0, then every third case under each later plane state
    states = {p: PlaneState('fresh', 1, d8[(p, 1)]) for p in range(1, 9)}
    base = [(v, cname, rq) for v in vhosts for cname, rq in v.cases]
    batches = [('b0', dict(states), None)]
    for k, (op, plane, src, leaves) in enumerate(schedule_steps(), 1):
        states = dict(states)
        for p, kind in leaves.items():
            if kind == 'stale':
                states[p] = PlaneState('stale', 2, d8[(1, 2)])
            elif kind == 'grace':
                states[p] = PlaneState('grace', 2, d8[(8, 2)])
            elif kind == 'fresh3':
                states[p] = PlaneState('fresh', 3, d8[(1, 3)])
            else:
                states[p] = PlaneState(kind)
        batches.append(('b%d' % k, dict(states), (op, plane, src)))

    cases_in, cases_col, python_col, oracle_col, oracle_cases, schedule = [], [], [], [], [], []
    counters = {s: {} for s in SERVERS}
    www = {}
    verdicts = {}
    for bi, (bname, st, step) in enumerate(batches):
        first = None
        for idx, (v, cname, rq) in enumerate(base):
            if bi > 0 and idx % BATCH_EVERY != bi % BATCH_EVERY:
                continue
            for h2 in (0, 1):
                cid = '%s.%s.%s%s' % (v.name, cname, bname, '.h2' if h2 else '')
                if first is None:
                    first = cid
                produce_case(cid, v, rq, h2, st, cfg, alldirs, http_conf, floor, progs, attrs, planes, records,
                             cases_in, cases_col, python_col, oracle_col, oracle_cases, counters, www, verdicts)
        if step is not None:
            op, plane, src = step
            line = '%d\tbefore=%s\tplane=%s.bin\top=%s' % (bi, first, R.PLANES[plane - 1], op)
            if src is not None:
                line += '\tfrom=%s' % src
            schedule.append(line)

    for name, lines in (('cases.in', cases_in), ('cases.col', cases_col), ('python.col', python_col),
                        ('oracle.col', oracle_col), ('schedule.in', schedule)):
        with open(os.path.join(out, name), 'w') as f:
            f.write(''.join(l + '\n' for l in lines))
    for s in SERVERS:
        with open(os.path.join(out, 'oracle-%s.counters' % s), 'w') as f:
            for (d16, rule), n in sorted(counters[s].items()):
                f.write('%s:%d\tcount=%d\n' % (d16, rule, n))
    for path, body in www.items():
        full = os.path.join(out, 'www', path.lstrip('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(body)
    with open(os.path.join(out, 'conf', 'nginx.conf'), 'w') as f:
        f.write(render_nginx(vhosts, alldirs, a.export, planes, attrs))
    with open(os.path.join(out, 'conf', 'apache.conf'), 'w') as f:
        f.write(render_apache(vhosts, alldirs, a.export, planes, attrs))
    with open(os.path.join(out, 'conf', 'litespeed.conf'), 'w') as f:
        f.write(render_litespeed(vhosts, alldirs, a.export, planes, attrs))
    for v in vhosts:
        with open(os.path.join(out, 'conf', 'litespeed', 's%d.conf' % v.n), 'w') as f:
            f.write(render_litespeed_vhost(v, attrs))
    write_oracle_cases(os.path.join(out, 'oracle-cases.txt'), alldirs, oracle_cases)
    check_oracle_file(a.oracle, os.path.join(out, 'oracle-cases.txt'), verdicts)
    print('xserver-cases: %d cases (%d at step 0, %d batches, h2 twins included), %d virtual hosts (%d location programs), '
          '%d records, export %s (%d attributes over %d planes), %d schedule steps, hops %d, produced at %d' % (
              len(cases_in), sum(1 for l in cases_in if '.b0\t' in l or '.b0.h2\t' in l), len(batches), len(vhosts),
              sum(1 for v in vhosts if v.kind == 'location'), sum(1 for r in records.recs.values() if r is not None),
              a.export, len(attrs), len(planes), len(schedule), HOPS, PRODUCE_NOW))
    return 0


def produce_case(cid, v, rq, h2, st, cfg, alldirs, http_conf, floor, progs, attrs, planes, records,
                 cases_in, cases_col, python_col, oracle_col, oracle_cases, counters, www, verdicts):
    lines = rq['lines']
    fl, mark, elig, note = walk(rq['peer'], lines)
    ctx_path = v.rule_path
    ctx = progs[ctx_path]
    acme = acme_exempt(rq['method'], rq['uri'])
    # the interpreter's case: the floor and server addresses equal (the context's address is the trusted
    # header's client on every server; a skipped trusted hop leaves it equal), so one memo slot
    if fl is None:
        die('case %s: the walk found no address, which no case of this set is meant to produce' % cid)
    addr = addr_of(fl)
    case = {'conf': {'floor': http_conf, 'ctx': effective_conf(alldirs, ctx_path)}, 'planes': {}, 'addr': {'floor': str(addr), 'server': str(addr)},
            'flags': (elig, acme), 'rec': {}}
    for p in range(1, 8):
        if st[p].kind != 'fresh':
            case['planes'][p] = 'stale'
    if st[8].kind == 'grace':
        case['tenant'] = ('stale', PRODUCE_NOW, GRACE_VU)          # within the 48 h: the interpreter reads grace
    else:
        case['tenant'] = ('revoked' if st[8].kind == 'revoked' else 'fresh', NOW, 0)
    for p in range(1, 9):
        rec = records.get(p, addr)
        case['rec'][('floor', p)] = rec
        case['rec'][('server', p)] = rec
    d = decide(cfg, cfg.effective(ctx_path), case)
    verdicts[cid] = d['vline']
    oracle_cases.append((cid, ctx_path, case))

    # the twin's variables
    ctx_conf = case['conf']['ctx']
    enforce = d['action'] == 'deny'
    log_rules = {('floor', r) for r in d['log_floor']} | {('ctx', r) for r in d['log_ctx']}
    would = False
    for who, r in log_rules:
        prog = cfg.floor if who == 'floor' else cfg.effective(ctx_path)
        rule = [x for x in prog.rules if x.n == r]
        if rule and rule[0].action == 'deny':
            would = True
    action = 'deny' if enforce else 'would-deny' if would else 'allow'
    if d['rule']:
        rule_id = '%s:%d' % (d['program'], d['rule'])
        prog = cfg.floor if d['program'] == 'floor' else cfg.effective(ctx_path)
        rule_text = [x.text for x in prog.rules if x.n == d['rule']][0]
    else:
        rule_id = rule_text = '-'
    words = []
    if d['reason'].startswith('allow-by-unknown'):
        words.append('allow-by-unknown')
    elif d['reason'] == 'allow-by-hold-harmless':
        words.append('hold-harmless')
    elif d['reason'] == 'allow-by-acme':
        words.append('acme')
    elif d['reason'] == 'allow-by-tenant':
        words.append('tenant' if d['step'] == '2' else 'stale-tenant')
    if note == 1:
        words.append('floor-header-unparsed')
    elif note == 2:
        words.append('floor-header-capped')
    elif mark == 1:
        words.append('floor-header-missing')
    if st[8].kind == 'revoked':
        words.append('tenant-revoked')
    reason = ','.join(words) or '-'
    floor_part = 'floor:%s' % (floor[0] or '-')
    ctx_ran = d['step'] == '4' and ctx['d16'] is not None and ctx_conf[0] != R.MODES['off']
    program = '%s ctx:%s' % (floor_part, ctx['d16'] if ctx_ran else '-')
    logged = ' '.join(x for x in ('floor:' + ','.join(map(str, d['log_floor'])) if d['log_floor'] else '',
                                 'ctx:' + ','.join(map(str, d['log_ctx'])) if d['log_ctx'] else '') if x) or '-'
    floor_addr = R.m_addr_text(fl)
    tokens = [gen_token(p, st[p], p not in d['touched']) for p in range(1, 9) if p in planes]
    generations = ' '.join(tokens) or '-'
    verdict = verdict_word(st[1], records.get(1, addr))
    var = {'action': action, 'rule': rule_text, 'rule_id': rule_id, 'reason': reason, 'program': program,
           'logged': logged, 'floor_addr': floor_addr, 'generations': generations, 'verdict': verdict}
    for name in attrs:
        p = attr_plane(name)
        rec = records.get(p, addr)
        var[name] = R.m_render(name, block_bytes(p, rec), memo_state(p, st[p], rec))

    # the columns
    kv = ['servers=' + ','.join(v.servers), 'peer=' + rq['peer'], 'method=' + rq['method'], 'uri=' + rq['uri'],
          'host=' + v.host, 'h2=%d' % h2, 'xff=%d' % len(lines)]
    kv += ['xff_%d=%s' % (i + 1, esc(l)) for i, l in enumerate(lines)]
    cases_in.append('\t'.join([cid] + kv))
    classes = []
    for s in v.servers:
        if rq['method'] == 'HEAD':
            cls = '-'                            # no body to classify: `-` on both sides, compared like a value
        elif enforce:
            cls = 'built-in' if s == 'nginx' else 'module' if (s == 'litespeed' or d['program'] == 'floor') else 'built-in'
        else:
            cls = 'application'
        classes.append('class_%s=%s' % (s, cls))
    cases_col.append('\t'.join([cid, 'servers=' + ','.join(v.servers)] + classes + ['context=' + ctx_path]))
    python_col.append('\t'.join([cid] + ['var_%s=%s' % (k, esc(var[k])) for k in DECISION_VARS + tuple(attrs)]))
    oracle_col.append('%s\taction=%s' % (cid, action))
    for s in v.servers:
        c = counters[s]
        if d['rule']:
            d16 = floor[0] if d['program'] == 'floor' else ctx['d16']
            c[(d16, d['rule'])] = c.get((d16, d['rule']), 0) + 1
        for r in d['log_floor']:
            c[(floor[0], r)] = c.get((floor[0], r), 0) + 1
        for r in d['log_ctx']:
            c[(ctx['d16'], r)] = c.get((ctx['d16'], r), 0) + 1
    path = normalise_path(rq['uri'])
    www.setdefault(path, 'xserver %s\n' % path)


def write_oracle_cases(path, alldirs, oracle_cases):
    """the interpreter's own case file for the record: `policy_ref.py --cases` over it reproduces every
    verdict line the columns were built from (check_oracle_file holds it so)"""
    by_ctx = {}
    for cid, ctx, case in oracle_cases:
        by_ctx.setdefault(ctx, []).append((cid, case))
    with open(path, 'w') as f:
        f.write('# the cross-server differential\'s cases, as policy_ref.py --cases reads them; one program block per context\n')
        for ctx in sorted(by_ctx):
            f.write('program %s xserver\n' % ctx)
            for k, c, a in alldirs:
                f.write('dir %s %s %s\n' % (k, c, R.escape(a)))
            f.write('run %s\n' % ctx)
            for cid, case in by_ctx[ctx]:
                f.write('case %s\n' % cid)
                f.write('conf floor %d %d\nconf ctx %d %d\n' % (case['conf']['floor'] + case['conf']['ctx']))
                for p, s in sorted(case['planes'].items()):
                    f.write('plane %s %s\n' % (R.PLANES[p - 1], s))
                f.write('tenant %s %d %d\n' % case['tenant'])
                f.write('addr floor %s\naddr server %s\n' % (case['addr']['floor'], case['addr']['server']))
                f.write('flags %d %d\n' % case['flags'])
                for (w, p), rec in sorted(case['rec'].items(), key=lambda kv: (kv[0][1], kv[0][0])):
                    f.write('%s\n' % G.rec_line(w, p, rec))
                f.write('end\n')


def check_oracle_file(oracle, path, verdicts):
    r = subprocess.run([sys.executable, oracle, '--cases', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode != 0:
        die('policy_ref.py --cases over the written case file exited %d: %s' % (r.returncode, r.stderr.strip()[-400:]))
    got = {}
    cid = None
    for line in r.stdout.splitlines():
        if line.startswith('case '):
            cid = line[5:]
        elif line.startswith('verdict ') and cid is not None:
            got[cid] = line
    missing = [c for c in verdicts if c not in got]
    differ = [c for c in verdicts if c in got and got[c] != verdicts[c]]
    if missing or differ:
        die('the written case file does not reproduce the verdicts: %d missing, %d differ (first: %s)' % (
            len(missing), len(differ), (missing or differ)[0]))


PLANT = ''

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
