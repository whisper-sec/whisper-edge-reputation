#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# xserver-gate.sh - the three modules, one configuration, one plane directory, the same requests: every
# answer and every variable equal across nginx, Apache and OpenLiteSpeed, and equal to the reference
# interpreter's verdict and the Python twin's rendering.
#
#   ./xserver-gate.sh                  run: invoke every column producer into a fresh run directory, compare;
#                                      twice, once under the default export set and once under `export all`
#   ./xserver-gate.sh --compare DIR    compare the columns a run (or a fixture) left in DIR
#   ./xserver-gate.sh --check-inputs DIR   validate the input half of a run directory against its grammar
#   ./xserver-gate.sh --selftest       the comparator, and each of its controls, over canned columns
#
# Exit 0: every expected column was present and nothing disagreed. Exit 1: a disagreement (printed, one
# line each). Exit 2: NOT PROVEN, an expected file, case, field or value absent (printed by name), and
# never a pass: an empty run directory compares nothing and says so.
#
# THE RUN DIRECTORY, INPUT HALF: written by core/xserver-cases.sh before any server producer runs,
# and the ONLY thing a server producer reads to build its side of the run (the request, the configuration,
# the planes, when each plane changes). --check-inputs validates it; a server producer refuses a run
# directory that does not pass.
#
#   cases.in                   one line per case, the line format below: `servers=` as in cases.col, then the
#                              request: `peer=` the TCP peer's address (IPv4 dotted or IPv6 text, no port), or
#                              `unix:` for a request over a unix socket (nginx `listen unix:`, the walk's
#                              unix-socket peer, judged as `::` only when `unix:` is trusted),
#                              `method=` (an upper-case token), `uri=` the request target as sent (begins
#                              with `/`, bytes as on the wire, percent-encoding untouched), `host=` the Host
#                              header; a `peer=unix:` case lists nginx and LiteSpeed alone, Apache having
#                              no unix listener), `h2=` 0 (HTTP/1.1) or 1 (HTTP/2), `xff=` the number of X-Forwarded-For
#                              header LINES (0 to 64) and then `xff_1=` to `xff_<n>=` each line's value in the
#                              order sent (an empty value is an empty line, and is present), and any further
#                              request header as `hdr_<Name>=<value>` (`hdr_X_Real_IP=`, sent byte for byte);
#                              `proxy=` (optional) the PROXY protocol v1 source address for a PROXY listener
#   conf/<server>.conf         the configuration rendered for each server any case names, in that server's own
#                              syntax, from one source of directives, with parallel structure so the ordinal
#                              context paths of cases.col correspond: a FRAGMENT the producer includes in its
#                              base configuration (nginx: inside http { }; Apache: at server-config level;
#                              LiteSpeed: appended to httpd_config.conf, with each virtual host's own file at
#                              conf/litespeed/s<n>.conf, placed where the fragment's configFile names it).
#                              The fragment carries every module directive, the realip or remoteip lines that
#                              make the context's address the trusted header's client, the access-log format
#                              (TAB-separated `case=`, `status=` and every `var_<name>=` of the run's export
#                              set, as that server spells its variables) and the server or virtual-host
#                              blocks, with these PLACEHOLDERS, which the producer substitutes before loading
#                              and which are the only `@WORD@` tokens a fragment may hold: @PLANES@ (its copy
#                              of planes/), @COUNTERS@ (its summary directory), @LOGS@ (where the access log
#                              goes), @ROOT@ (its copy of www/), @CONF@ (its copy of conf/), @PORT@ (the one
#                              plain listener every virtual host maps), @SOCK@ (the path of the unix socket
#                              the producer listens on for the `peer=unix:` cases: nginx `listen unix:`,
#                              LiteSpeed `address UDS://`; Apache's fragment never names it), @SERVER_EXTRA@ (a line inside every
#                              server or virtual-host block for the producer's own listener or TLS lines, or
#                              nothing). The producer sends `X-Case: <case>` with every request; the format
#                              logs it first, so one log line names its case. LiteSpeed's ordinal paths are
#                              http/v<n> where the others' are http/s<n>; a location-level program has no
#                              LiteSpeed counterpart (one program per virtual host), so its cases list nginx
#                              and Apache only
#   www/                       the document root every server serves: one static file per path a case names,
#                              unique bytes per file, so an allowed request's body is the `application` class
#   planes/                    the one plane directory every server binds (its *.bin files, as at step 0,
#                              mode 0444). A producer COPIES planes/ and next/ into its own working directory
#                              and applies the schedule to its copy, so the run directory stays at step 0 for
#                              the next producer
#   next/                      the files the schedule installs or rewrites from (`from=` names them)
#   schedule.in                the plane-state schedule: one line per step, `<step>` (1, 2, ... in order),
#                              then `before=` the case the step is applied before, `plane=` a file name in
#                              planes/, and `op=` one of install (rename `from=`, a path relative to the run
#                              directory, into place), delete, rewrite (the same inode rewritten in place from
#                              `from=`), ctime (a chown to its own owner), refuse (chmod 0644: refused by mode);
#                              the gate's barrier follows every step. An empty schedule is written as an empty
#                              file, never left absent. A tenant.bin installed or rewritten STALE (its header's
#                              valid-until behind the clock) is the grace step: the servers read it `stale`
#                              for 48 h after that valid-until and `lapsed` from then on, so --check-inputs
#                              refuses a run directory whose grace file is more than 36 h past its
#                              valid-until (the run would compare a grace column with a lapsed server)
#
# THE RUN DIRECTORY, OUTPUT HALF, the contract every producer writes to:
#
#   cases.col                  the case set: one line per case, `servers=` the servers it is sent to
#                              (comma-separated, from nginx, apache, litespeed), `class_<server>=` that
#                              server's expected body class for every server listed (one of built-in,
#                              error-document, application, module, or `-` for a HEAD, which has no body
#                              to classify: the producer writes `class=-` back and the two compare whole),
#                              and `context=` the ordinal context path the case is expected to select
#   <server>.col               one line per case sent to <server>: `status=`, `nostore=` (0 or 1),
#                              `class=` (the body class served) and every variable the module exported,
#                              as `var_<name>=` (`var_verdict=`, `var_action=`, `var_rule=`, ...), read from
#                              the server's own access log
#   python.col                 one line per case: every variable the twin renders for that case's records,
#                              as `var_<name>=` (policy_ref.py, from POLICY.md section 3.9)
#   oracle.col                 one line per case: `action=` (deny, would-deny or allow), the reference
#                              interpreter's decision for the case's chain on that server's mapping
#   <server>.counters          one line per (digest, rule) the server counted over the run: `<16 hex>:<rule>`
#                              then `count=`, read from whisper-edge-summary --rules after the tick barrier
#   oracle-<server>.counters   the oracle's totals for the cases that server was sent, same format
#
# THE LINE FORMAT. `<case>` then TAB-separated `<key>=<value>` fields. A value is everything after the
# first `=` up to the next TAB or the end of the line, so a value may hold spaces (a rule's text, the
# `floor:<d16> ctx:<d16>` program) and is compared whole. A producer escapes a TAB, a newline and a
# backslash in a value as `\t`, `\n` and `\\`; nothing else is rewritten. A variable the module renders
# EMPTY (generations for a context whose gen_mask is 0) is written `-`, by every producer and the twin
# alike, as nginx and Apache write an empty variable in an access log: so `-` is a value, compared like any
# other, and an empty field stays what it says, absent.
#
# THE RULES for this row:
#
#   - every file above is required, and every case of cases.col must have its line in each column it
#     belongs to; an absent file, case, field or value (an empty value is an absent one) is NOT PROVEN,
#     named;
#   - status and the presence of `no-store` are compared across the servers that share the case's hop
#     structure (the servers the case lists);
#   - the body class is compared per server against that server's expected class for the case, never one
#     server's class name against another's;
#   - every server exports exactly the variables the twin renders: one the twin renders and a server does
#     not export is NOT PROVEN by name, one a server exports and the twin does not is a disagreement;
#     every variable is compared across servers and with the twin, `verdict` after mapping
#     `,spamhaus-drop` to `,drop`;
#   - the action is compared with the oracle's;
#   - a server's answer for a case the case set does not hold is a disagreement;
#   - the counters are compared per server against the oracle's totals for the cases that server was
#     sent, never across servers.
#
# THE PRODUCERS. `run` creates the run directory and invokes each producer that declares the contract by
# carrying the line `XSERVER_COLUMNS_VERSION=1` (an assignment at the start of a line, not a comment):
#
#   core/xserver-cases.sh --xserver-columns DIR [--export default|all]
#                                                      the input half, then cases.col, python.col, oracle.col
#                                                      and oracle-*.counters (xserver_cases.py does the work)
#   <server>/<server>-gate.sh --xserver-columns DIR   <server>.col and <server>.counters
#
# The run is made twice, into two run directories: under the default export set (the union of every
# context's default set, pinned by one http-level export line, because nginx's generations token set is the
# union of every attribute the configuration names) and under `export all`; each must pass.
#
# THE ONE C READING on the reference side: the program digests the counters are keyed by, and the
# `floor:<d16> ctx:<d16>` the twin renders, come from the shipped tool, `whisper-edge-lookup --programs FILE
# --dir DIR`, which compiles the SAME directive lines through we_policy_build() in the SAME plane
# environment the servers probe (the tool's `--dir` is also what the module gates hold a module's
# environment and plane digests to, and its `--policy` digests are what the program digests are compared to); the producer
# holds its canonical rule text equal to the reference interpreter's, line for line, and refuses the run
# otherwise. The reference interpreter computes no digest (section 0.2), so this is a C-only consistency
# check, named so here, and never a comparison the interpreter makes.
#
# A producer that does not declare the contract, or exits non-zero, or leaves its files absent, makes the
# run NOT PROVEN by its name, never a pass; the comparator then still names every absent column.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVERS=(nginx apache litespeed)

compare() { # dir -> prints every disagreement and absence; exit 0, 1 (disagreement) or 2 (NOT PROVEN)
    python3 - "$1" <<'PY'
import os, sys

d = sys.argv[1]
SERVERS = ('nginx', 'apache', 'litespeed')
bad = 0
absent = 0


def say(case, what):
    global bad
    bad += 1
    print('DISAGREE %s: %s' % (case, what))


def missing(what):
    global absent
    absent += 1
    print('NOT PROVEN: %s' % what)


def read(name):
    """the file's lines as {case: {key: value}}, or None when the file is absent"""
    path = os.path.join(d, name)
    if not os.path.isfile(path):
        return None
    out = {}
    with open(path, encoding='utf-8', errors='surrogateescape') as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line:
                continue
            fields = line.split('\t')
            case, kv = fields[0], {}
            for x in fields[1:]:
                if '=' not in x:
                    say(case, '%s line %d: a field without `=`: %r' % (name, n, x))
                    continue
                k, v = x.split('=', 1)
                kv[k] = v
            if case in out:
                say(case, '%s line %d: the case appears twice' % (name, n))
            out[case] = kv
    return out


def need(table, name, case, key):
    """the value, or None after naming its absence"""
    if case not in table:
        missing('%s has no line for case %s' % (name, case))
        return None
    v = table[case].get(key)
    if v is None or v == '':
        missing('%s case %s has no %s' % (name, case, key))
        return None
    return v


def norm(k, v):
    return v.replace(',spamhaus-drop', ',drop') if k == 'var_verdict' and v is not None else v


cases = read('cases.col')
if cases is None or not cases:
    missing('cases.col is %s: there is no case set, so nothing was compared' %
            ('absent' if cases is None else 'empty'))
    cases = {}
py = read('python.col')
oracle = read('oracle.col')
if py is None:
    missing('python.col is absent: no variable can be compared with the twin')
if oracle is None:
    missing('oracle.col is absent: no action can be compared with the oracle')
sent = {s: [] for s in SERVERS}
for case, spec in cases.items():
    on = [s for s in spec.get('servers', '').split(',') if s]
    if not on:
        missing('cases.col case %s names no server' % case)
    for s in on:
        if s not in SERVERS:
            say(case, 'cases.col names an unknown server %r' % s)
        else:
            sent[s].append(case)
used = [s for s in SERVERS if sent[s]]
cols = {}
for s in used:
    cols[s] = read(s + '.col')
    if cols[s] is None:
        missing('%s.col is absent: %s answered none of its %d cases' % (s, s, len(sent[s])))
for s in SERVERS:
    c = cols.get(s) if s in cols else read(s + '.col')
    if c is not None:
        for case in c:
            if case not in cases or s not in [x for x in cases[case].get('servers', '').split(',') if x]:
                say(case, '%s.col answers a case the case set does not send it' % s)

for case, spec in cases.items():
    on = [s for s in spec.get('servers', '').split(',') if s in SERVERS]
    rows = {}
    for s in on:
        if cols.get(s) is None:
            continue
        if case not in cols[s]:
            missing('%s.col has no line for case %s' % (s, case))
            continue
        rows[s] = cols[s][case]
    for field in ('status', 'nostore'):
        vals = {}
        for s in rows:
            v = need(cols[s], s + '.col', case, field)
            if v is not None:
                vals[s] = v
        if len(set(vals.values())) > 1:
            say(case, '%s differs: %s' % (field, ' '.join('%s=%s' % kv for kv in sorted(vals.items()))))
    for s in rows:
        want = need(cases, 'cases.col', case, 'class_' + s)
        got = need(cols[s], s + '.col', case, 'class')
        if want is not None and got is not None and got != want:
            say(case, '%s served class %s, its expected class is %s' % (s, got, want))
    want_vars = None
    if py is not None:
        if case not in py:
            missing('python.col has no line for case %s' % case)
        else:
            want_vars = {k: v for k, v in py[case].items() if k.startswith('var_')}
            if not want_vars:
                missing('python.col case %s renders no variable' % case)
    keys = set(want_vars or {})
    for s in rows:
        keys |= {k for k in rows[s] if k.startswith('var_')}
    for k in sorted(keys):
        vals = {}
        for s in rows:
            if want_vars is not None and k not in want_vars and k in rows[s]:
                say(case, '%s exports %s, which the twin does not render' % (s, k))
            v = rows[s].get(k)
            if v is None or v == '':
                if want_vars is not None and k in want_vars:
                    missing('%s.col case %s has no %s, which the twin renders' % (s, case, k))
                continue
            vals[s] = norm(k, v)
        if len(set(vals.values())) > 1:
            say(case, '%s differs: %s' % (k, ' '.join('%s=%s' % kv for kv in sorted(vals.items()))))
        if want_vars is not None and k in want_vars:
            w = norm(k, want_vars[k])
            for s in sorted(vals):
                if vals[s] != w:
                    say(case, '%s on %s is %s, the Python column renders %s' % (k, s, vals[s], w))
    if oracle is not None:
        w = need(oracle, 'oracle.col', case, 'action')
        if w is not None:
            held = 0
            for s in sorted(rows):
                got = rows[s].get('var_action')
                if got is not None and got != '':
                    held += 1
                    if got != w:
                        say(case, 'action on %s is %s, the oracle decided %s' % (s, got, w))
            if rows and not held:
                # absence on both sides is never equality: no server exported the action to hold to the oracle
                missing('case %s: no server exports var_action, so the oracle\'s %s was held to nothing' % (case, w))
# the counters: per server against the oracle's totals for that server's cases, never across servers
for s in used:
    got, want = read(s + '.counters'), read('oracle-' + s + '.counters')
    if got is None:
        missing('%s.counters is absent: %s\'s counters were not read' % (s, s))
    if want is None:
        missing('oracle-%s.counters is absent: there is no total to hold %s\'s counters to' % (s, s))
    if got is None or want is None:
        continue
    if not got and not want:
        missing('%s.counters and oracle-%s.counters are both empty: nothing counted is not a count that agrees'
                % (s, s))
        continue
    for key in sorted(set(got) | set(want)):
        g = got.get(key, {}).get('count', '0')
        w = want.get(key, {}).get('count', '0')
        if g != w:
            say(key, '%s counted %s, the oracle sums %s' % (s, g, w))
if absent:
    print('NOT PROVEN: %d expected inputs absent (named above)' % absent)
print('xserver comparator: %d cases, %d disagreements, %d absent' % (len(cases), bad, absent))
sys.exit(1 if bad else 2 if absent else 0)
PY
}

check_inputs() { # dir -> validates the input half; exit 0, 1 (malformed) or 2 (NOT PROVEN: absent)
    python3 - "$1" <<'PY'
import ipaddress, os, re, struct, sys, time

d = sys.argv[1]
SERVERS = ('nginx', 'apache', 'litespeed')
OPS = ('install', 'delete', 'rewrite', 'ctime', 'refuse')
REQUIRED = ('servers', 'peer', 'method', 'uri', 'host', 'h2', 'xff')
bad = absent = 0


def malformed(what):
    global bad
    bad += 1
    print('MALFORMED: %s' % what)


def missing(what):
    global absent
    absent += 1
    print('NOT PROVEN: %s' % what)


def lines(name):
    path = os.path.join(d, name)
    if not os.path.isfile(path):
        return None
    out = []
    with open(path, encoding='utf-8', errors='surrogateescape') as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line:
                continue
            fields = line.split('\t')
            kv = {}
            for x in fields[1:]:
                if '=' not in x:
                    malformed('%s line %d: a field without `=`: %r' % (name, n, x))
                    continue
                k, v = x.split('=', 1)
                if k in kv:
                    malformed('%s line %d: %s appears twice' % (name, n, k))
                kv[k] = v
            out.append((n, fields[0], kv))
    return out


cases = lines('cases.in')
named, ids = set(), set()
if cases is None or not cases:
    missing('cases.in is %s: there is no request to send' % ('absent' if cases is None else 'empty'))
    cases = []
for n, case, kv in cases:
    where = 'cases.in line %d (case %s)' % (n, case)
    if case in ids:
        malformed('%s: the case appears twice' % where)
    ids.add(case)
    for k in REQUIRED:
        if kv.get(k, '') == '':
            missing('%s has no %s' % (where, k))
    for x in [x for x in kv.get('servers', '').split(',') if x]:
        if x not in SERVERS:
            malformed('%s: an unknown server %r' % (where, x))
        else:
            named.add(x)
    for k in ('peer', 'proxy'):
        if k == 'peer' and kv.get(k) == 'unix:':
            if 'apache' in kv.get('servers', '').split(','):
                malformed('%s: peer=unix: lists apache, which has no unix listener' % where)
            continue                   # a unix-socket peer: no address, by design
        if kv.get(k):
            try:
                ipaddress.ip_address(kv[k])
            except ValueError:
                malformed('%s: %s=%r is not an address' % (where, k, kv[k]))
    if kv.get('method') and not re.fullmatch(r'[A-Z]+', kv['method']):
        malformed('%s: method=%r is not an upper-case token' % (where, kv['method']))
    if kv.get('uri') and not kv['uri'].startswith('/'):
        malformed('%s: uri=%r does not begin with /' % (where, kv['uri']))
    if kv.get('host') and re.search(r'\s', kv['host']):
        malformed('%s: host=%r holds white space' % (where, kv['host']))
    if kv.get('h2', '') not in ('', '0', '1'):
        malformed('%s: h2=%r is neither 0 nor 1' % (where, kv['h2']))
    x = kv.get('xff', '')
    if x != '':
        if not re.fullmatch(r'[0-9]+', x) or int(x) > 64:
            malformed('%s: xff=%r is not a line count from 0 to 64' % (where, x))
        else:
            have = sorted(int(k[4:]) for k in kv if re.fullmatch(r'xff_[0-9]+', k))
            if have != list(range(1, int(x) + 1)):
                malformed('%s: xff=%s, and the lines given are %s' % (where, x, have))
    for k in kv:
        if not (k in REQUIRED or k == 'proxy' or re.fullmatch(r'xff_[0-9]+', k)
                or re.fullmatch(r'hdr_[A-Za-z0-9_-]+', k)):
            malformed('%s: an unknown field %r' % (where, k))
PLACEHOLDERS = {'PLANES', 'COUNTERS', 'LOGS', 'ROOT', 'CONF', 'PORT', 'SOCK', 'SERVER_EXTRA'}
for x in sorted(named):
    cf = os.path.join(d, 'conf', x + '.conf')
    if not os.path.isfile(cf):
        missing('conf/%s.conf is absent: %s has cases and no configuration' % (x, x))
        continue
    text = open(cf, encoding='utf-8', errors='surrogateescape').read()
    for ph in sorted(set(re.findall(r'@([A-Z_]+)@', text)) - PLACEHOLDERS):
        malformed('conf/%s.conf names a placeholder @%s@ outside the closed set (%s)' % (x, ph, ' '.join(sorted(PLACEHOLDERS))))
    if x == 'litespeed':
        for vf in re.findall(r'configFile\s+@CONF@/(\S+)', text):
            if not os.path.isfile(os.path.join(d, 'conf', vf)):
                missing('conf/litespeed.conf names conf/%s, which is absent' % vf)
wd = os.path.join(d, 'www')
if cases and not os.path.isdir(wd):
    missing('www/ is absent: there is no document root to serve')
elif cases and not any(files for _, _, files in os.walk(wd)):
    missing('www/ holds no file')
pd = os.path.join(d, 'planes')
if not os.path.isdir(pd):
    missing('planes/ is absent: there is no plane directory to bind')
elif not [f for f in os.listdir(pd) if f.endswith('.bin')]:
    missing('planes/ holds no plane file')
sched = lines('schedule.in')
if sched is None:
    missing('schedule.in is absent (an empty schedule is an empty file)')
    sched = []
for step, (n, s, kv) in enumerate(sched, 1):
    where = 'schedule.in line %d (step %s)' % (n, s)
    if s != str(step):
        malformed('%s: the steps are not 1, 2, ... in order' % where)
    if kv.get('before') not in ids:
        malformed('%s: before=%r names no case of cases.in' % (where, kv.get('before')))
    pf = kv.get('plane', '')
    if not pf or '/' in pf or not pf.endswith('.bin'):
        malformed('%s: plane=%r is not a file name in planes/' % (where, pf))
    op = kv.get('op')
    if op not in OPS:
        malformed('%s: op=%r is not one of %s' % (where, op, ', '.join(OPS)))
    if op in ('install', 'rewrite'):
        f = kv.get('from', '')
        if not f or f.startswith('/') or '..' in f.split('/') or not os.path.isfile(os.path.join(d, f)):
            malformed('%s: from=%r is not a file under the run directory' % (where, f))
        elif pf == 'tenant.bin':
            # the grace step: a stale tenant plane is read `stale` for 48 h after its valid-until, then `lapsed`
            hdr = open(os.path.join(d, f), 'rb').read(40)
            vu = struct.unpack_from('<Q', hdr, 32)[0] if len(hdr) >= 40 else 0
            now_ms = int(time.time() * 1000)
            if vu and now_ms > vu and now_ms - vu > 36 * 3600 * 1000:
                malformed('%s: %s went stale %d h ago; the servers would read it lapsed from 48 h, the oracle reads grace: produce the run directory again'
                          % (where, f, (now_ms - vu) // 3600000))
print('xserver inputs: %d cases, %d steps, %d malformed, %d absent' % (len(cases), len(sched), bad, absent))
sys.exit(1 if bad else 2 if absent else 0)
PY
}

selftest() {
    local t fails=0 out rc s cls
    t=$(mktemp -d)
    trap 'rm -rf "$t"' RETURN
    T=$'\t'
    printf 'c1%sservers=nginx,apache,litespeed%sclass_nginx=built-in%sclass_apache=module%sclass_litespeed=module%scontext=http/s1\n' \
        "$T" "$T" "$T" "$T" "$T" > "$t/cases.col"
    printf 'c2%sservers=apache%sclass_apache=application%scontext=http/s1/l1\n' "$T" "$T" "$T" >> "$t/cases.col"
    for s in nginx apache litespeed; do
        cls=module
        [ "$s" = nginx ] && cls=built-in
        printf 'c1%sstatus=403%snostore=1%sclass=%s%svar_action=deny%svar_country=NL%svar_verdict=high,drop%svar_rule=deny if tor_exit\n' \
            "$T" "$T" "$T" "$cls" "$T" "$T" "$T" "$T" > "$t/$s.col"
        printf 'ba7816bf8f01cfea:1%scount=3\n' "$T" > "$t/$s.counters"
        printf 'ba7816bf8f01cfea:1%scount=3\n' "$T" > "$t/oracle-$s.counters"
    done
    sed -i 's/,drop/,spamhaus-drop/' "$t/apache.col" "$t/litespeed.col"
    printf 'c2%sstatus=200%snostore=0%sclass=application%svar_action=allow%svar_country=BE%svar_verdict=none%svar_rule=-\n' \
        "$T" "$T" "$T" "$T" "$T" "$T" "$T" >> "$t/apache.col"
    printf 'c1%svar_action=deny%svar_country=NL%svar_verdict=high,drop%svar_rule=deny if tor_exit\n' "$T" "$T" "$T" "$T" > "$t/python.col"
    printf 'c2%svar_action=allow%svar_country=BE%svar_verdict=none%svar_rule=-\n' "$T" "$T" "$T" "$T" >> "$t/python.col"
    printf 'c1%saction=deny\nc2%saction=allow\n' "$T" "$T" > "$t/oracle.col"
    out=$(compare "$t"); rc=$?
    if [ "$rc" = 0 ]; then
        echo "ok   selftest: equal columns compare equal (the drop spellings mapped): $(tail -1 <<<"$out")"
    else
        echo "FAIL selftest: equal columns do not compare equal (exit $rc): $out"
        fails=$((fails + 1))
    fi
    # control NAME WANT-EXIT WANT-TEXT -- a shell command that changes the fixture; the fixture is restored
    control() {
        local name=$1 want_rc=$2 want=$3
        shift 3
        rm -rf "$t.keep" && cp -a "$t" "$t.keep"
        "$@"
        out=$(compare "$t"); rc=$?
        if [ "$rc" != "$want_rc" ]; then
            echo "FAIL selftest control $name: exit $rc, not $want_rc: $(head -1 <<<"$out")"
            fails=$((fails + 1))
        elif ! grep -q -- "$want" <<<"$out"; then
            echo "FAIL selftest control $name: reported as something else: $(head -1 <<<"$out")"
            fails=$((fails + 1))
        else
            echo "ok   selftest control $name: $(grep -m1 -- "$want" <<<"$out")"
        fi
        rm -rf "$t" && mv "$t.keep" "$t"
    }
    control "one character of one server's rendering" 1 'var_country differs' sed -i 's/var_country=NL/var_country=NM/' "$t/litespeed.col"
    control "a value differing after a space" 1 'var_rule differs' sed -i 's/deny if tor_exit/deny if vpn/' "$t/nginx.col"
    control "a status on one server" 1 'status differs' sed -i 's/status=403/status=451/' "$t/nginx.col"
    control "a deny without no-store" 1 'nostore differs' sed -i 's/nostore=1/nostore=0/' "$t/apache.col"
    control "a body class against the server's own expectation" 1 'expected class' sed -i 's/class=module/class=built-in/' "$t/litespeed.col"
    control "the Python column" 1 'the Python column renders' sed -i 's/var_country=NL/var_country=BE/' "$t/python.col"
    control "the oracle's decision" 1 'the oracle decided' sed -i "s/^c1${T}action=deny/c1${T}action=allow/" "$t/oracle.col"
    control "a counter one off the oracle's total" 1 'counted 4' sed -i 's/count=3/count=4/' "$t/nginx.counters"
    control "a variable every server exports and the twin does not render" 1 'which the twin does not render' \
        sed -i "s/\$/${T}var_extra=x/" "$t/nginx.col" "$t/apache.col" "$t/litespeed.col"
    control "an answer for a case the case set does not send" 1 'does not send it' \
        sed -i "\$a c9${T}status=200${T}nostore=0${T}class=module${T}var_action=allow" "$t/nginx.col"
    control "an empty run directory" 2 'there is no case set' find "$t" -mindepth 1 -delete
    control "one server's column missing" 2 'litespeed.col is absent' rm "$t/litespeed.col"
    control "one variable missing on one server" 2 'has no var_country, which the twin renders' \
        sed -i "s/${T}var_country=NL//" "$t/apache.col"
    control "a variable every server drops" 2 'has no var_rule, which the twin renders' \
        sed -i "s/${T}var_rule=[^${T}]*//" "$t/nginx.col" "$t/apache.col" "$t/litespeed.col"
    control "the Python column missing" 2 'python.col is absent' rm "$t/python.col"
    control "the oracle column missing" 2 'oracle.col is absent' rm "$t/oracle.col"
    control "a case the oracle does not decide" 2 'oracle.col has no line for case c2' sed -i '/^c2/d' "$t/oracle.col"
    control "a server's counters missing" 2 'nginx.counters is absent' rm "$t/nginx.counters"
    control "an expected class not stated" 2 'has no class_apache' sed -i "s/${T}class_apache=module//" "$t/cases.col"
    control "the action absent everywhere (no server, not the twin)" 2 'so the oracle' \
        sed -i "s/${T}var_action=[a-z-]*//" "$t/nginx.col" "$t/apache.col" "$t/litespeed.col" "$t/python.col"
    control "the counters empty everywhere" 2 'are both empty' \
        truncate -s 0 "$t/nginx.counters" "$t/apache.counters" "$t/litespeed.counters" \
        "$t/oracle-nginx.counters" "$t/oracle-apache.counters" "$t/oracle-litespeed.counters"
    # the input half: a fixture that passes, and each of its controls refused by name
    local i="$t.in"
    rm -rf "$i" && mkdir -p "$i/conf" "$i/planes" "$i/next" "$i/www"
    echo "fixture" > "$i/www/x.html"
    {
        printf 'c1%sservers=nginx,apache,litespeed%speer=192.0.2.1%smethod=GET%suri=/a/%%2e/x%shost=a.test%sh2=1' \
            "$T" "$T" "$T" "$T" "$T" "$T"
        printf '%sxff=3%sxff_1=203.0.113.9%sxff_2=%sxff_3=[2001:db8::1]:80\n' "$T" "$T" "$T" "$T"
        printf 'c2%sservers=apache%speer=2001:db8::5%smethod=HEAD%suri=/b%shost=b.test%sh2=0%sxff=0' \
            "$T" "$T" "$T" "$T" "$T" "$T" "$T"
        printf '%shdr_X_Real_IP=198.51.100.7\n' "$T"
    } > "$i/cases.in"
    for s in nginx apache litespeed; do echo "# $s: whisper_edge_data @PLANES@; root @ROOT@;" > "$i/conf/$s.conf"; done
    : > "$i/planes/reputation.bin"
    : > "$i/next/reputation.bin"
    printf '1%sbefore=c2%splane=reputation.bin%sop=install%sfrom=next/reputation.bin\n' "$T" "$T" "$T" "$T" > "$i/schedule.in"
    out=$(check_inputs "$i"); rc=$?
    if [ "$rc" = 0 ]; then
        echo "ok   selftest inputs: the fixture's input half passes: $(tail -1 <<<"$out")"
    else
        echo "FAIL selftest inputs: the fixture's input half does not pass (exit $rc): $out"
        fails=$((fails + 1))
    fi
    icontrol() {
        local name=$1 want_rc=$2 want=$3
        shift 3
        rm -rf "$i.keep" && cp -a "$i" "$i.keep"
        "$@"
        out=$(check_inputs "$i"); rc=$?
        if [ "$rc" != "$want_rc" ] || ! grep -q -- "$want" <<<"$out"; then
            echo "FAIL selftest input control $name: exit $rc (want $want_rc): $(head -1 <<<"$out")"
            fails=$((fails + 1))
        else
            echo "ok   selftest input control $name: $(grep -m1 -- "$want" <<<"$out")"
        fi
        rm -rf "$i" && mv "$i.keep" "$i"
    }
    icontrol "a request without its peer" 2 'has no peer' sed -i "s/${T}peer=192.0.2.1//" "$i/cases.in"
    # a unix-socket peer is a peer: the fixture with c2 over a unix socket, on a server with a unix listener, still passes
    sed -i "s/servers=apache${T}peer=2001:db8::5/servers=nginx${T}peer=unix:/" "$i/cases.in"
    out=$(check_inputs "$i"); rc=$?
    if [ "$rc" = 0 ]; then
        echo "ok   selftest inputs: a unix-socket peer (peer=unix:) is a request the input half carries"
    else
        echo "FAIL selftest inputs: a unix-socket peer is refused (exit $rc): $(head -1 <<<"$out")"
        fails=$((fails + 1))
    fi
    sed -i "s/servers=nginx${T}peer=unix:/servers=apache${T}peer=2001:db8::5/" "$i/cases.in"
    icontrol "a peer that is not an address" 1 'is not an address' sed -i 's/peer=192.0.2.1/peer=192.0.2.300/' "$i/cases.in"
    icontrol "an X-Forwarded-For count the lines do not match" 1 'and the lines given are' sed -i 's/xff=3/xff=4/' "$i/cases.in"
    icontrol "a step before a case that does not exist" 1 'names no case' sed -i 's/before=c2/before=c9/' "$i/schedule.in"
    icontrol "a server with cases and no configuration" 2 'conf/litespeed.conf is absent' rm "$i/conf/litespeed.conf"
    icontrol "no plane directory" 2 'planes/ is absent' rm -r "$i/planes"
    icontrol "the schedule left absent" 2 'schedule.in is absent' rm "$i/schedule.in"
    icontrol "a placeholder outside the closed set" 1 'outside the closed set' sed -i 's/@ROOT@/@DOCROOT@/' "$i/conf/nginx.conf"
    # the socket placeholder is inside the closed set: a fragment naming @SOCK@ passes
    sed -i 's/root @ROOT@;/root @ROOT@; listen unix:@SOCK@;/' "$i/conf/nginx.conf"
    out=$(check_inputs "$i"); rc=$?
    if [ "$rc" = 0 ]; then
        echo "ok   selftest inputs: a fragment naming @SOCK@ (the unix listener's path) passes"
    else
        echo "FAIL selftest inputs: @SOCK@ is refused (exit $rc): $(head -1 <<<"$out")"
        fails=$((fails + 1))
    fi
    sed -i 's/ listen unix:@SOCK@;//' "$i/conf/nginx.conf"
    icontrol "a unix-socket peer sent to apache" 1 'lists apache, which has no unix listener' sed -i "s/servers=apache${T}peer=2001:db8::5/servers=apache${T}peer=unix:/" "$i/cases.in"
    # the grace step's age: a stale tenant plane 40 h past its valid-until is refused by name, one 1 h past it passes
    grace_fixture() { # grace_fixture <hours ago>
        python3 -I -c "import struct,sys,time; h=bytearray(40); struct.pack_into('<Q', h, 32, int(time.time()*1000) - int(sys.argv[1])*3600*1000); open(sys.argv[2],'wb').write(bytes(h))" "$1" "$i/next/tenant-grace.bin"
        : > "$i/planes/tenant.bin"
        printf '2%sbefore=c2%splane=tenant.bin%sop=install%sfrom=next/tenant-grace.bin\n' "$T" "$T" "$T" "$T" >> "$i/schedule.in"
    }
    icontrol "a grace step 40 h past its valid-until" 1 'the servers would read it lapsed' grace_fixture 40
    grace_fixture 1
    out=$(check_inputs "$i"); rc=$?
    if [ "$rc" = 0 ]; then
        echo "ok   selftest inputs: a grace step 1 h past its valid-until passes (inside the 36 h bound)"
    else
        echo "FAIL selftest inputs: a 1 h old grace step is refused (exit $rc): $(head -1 <<<"$out")"
        fails=$((fails + 1))
    fi
    sed -i '$d' "$i/schedule.in"; rm -f "$i/next/tenant-grace.bin" "$i/planes/tenant.bin"
    icontrol "no document root" 2 'www/ is absent' rm -r "$i/www"
    icontrol "a LiteSpeed virtual-host file the fragment names and does not ship" 2 'which is absent' \
        sed -i 's/$/ configFile @CONF@\/litespeed\/s1.conf/' "$i/conf/litespeed.conf"
    rm -rf "$i"
    echo "selftest: $fails failures"
    [ "$fails" = 0 ]
}

run_one() { # EXPORT [HOPS] -> one run directory under that export set (and, for the hops run, trusted_hops N
            # at the http level), every producer, then the comparison
    local export=$1 hops=${2:-0} run_dir p name producers=() notp=0 rc
    run_dir=$(mktemp -d "${TMPDIR:-/tmp}/xserver-run-$export${2:+-hops$2}.XXXXXX")
    echo "run directory ($export export set${2:+, trusted_hops $2}): $run_dir"
    producers=("$HERE/core/xserver-cases.sh")
    for name in "${SERVERS[@]}"; do
        producers+=("$HERE/$name/$name-gate.sh")
    done
    for p in "${producers[@]}"; do
        name=${p#"$HERE"/}
        if [ ! -f "$p" ]; then
            echo "NOT PROVEN: $name is not in this tree yet, so its columns were not produced"
            notp=1
            continue
        fi
        if ! grep -qx 'XSERVER_COLUMNS_VERSION=1' "$p"; then
            echo "NOT PROVEN: $name does not declare the column contract (XSERVER_COLUMNS_VERSION=1), so it produced nothing"
            notp=1
            continue
        fi
        if [ "$p" = "$HERE/core/xserver-cases.sh" ]; then
            bash "$p" --xserver-columns "$run_dir" --export "$export" --hops "$hops"
        else
            bash "$p" --xserver-columns "$run_dir"
        fi
        if [ $? -ne 0 ]; then
            echo "NOT PROVEN: $name --xserver-columns exited non-zero"
            notp=1
        fi
    done
    compare "$run_dir"
    rc=$?
    [ "$rc" = 0 ] && [ "$notp" = 1 ] && rc=2
    return "$rc"
}

run() { # both export sets and the hops configuration; the worst verdict of the three is the run's
    local rc1 rc2 rc3 worst
    run_one default; rc1=$?
    run_one all; rc2=$?
    run_one default 2; rc3=$?
    worst=$rc1
    [ "$rc2" -gt "$worst" ] && worst=$rc2
    [ "$rc3" -gt "$worst" ] && worst=$rc3
    return "$worst"
}

case "${1:-}" in
    --selftest) selftest ;;
    --compare)  compare "${2:?--compare needs the run directory}" ;;
    --check-inputs) check_inputs "${2:?--check-inputs needs the run directory}" ;;
    '')         run ;;
    *)          echo "usage: $0 [--compare DIR | --check-inputs DIR | --selftest]" >&2; exit 2 ;;
esac
