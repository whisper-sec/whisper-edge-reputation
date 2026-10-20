#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
"""
policy_ref.py - the reference interpreter for the edge policy language. Python 3, standard library only.

A second implementation of the language, written from POLICY.md's text and POLICY.md (decision 2), never
from the C compiler. It exists so that two independent readings of one specification meet in a
differential, and so the independent corpus under testdata/policy/ has a second reader beside the C.
Where it had to choose because POLICY.md is silent, the choice is listed under DECISIONS below, so the
C side adopts the same one or POLICY.md is changed first.

What it implements, in POLICY.md's order:
  1.2  the lexer: the byte-class table, the alphabet, literal mode after an operator, inside braces and
       in a set declaration, `in` followed only by `@` or `{`, maximal munch over `= ! < >`, the
       number checks in their stated order, country codes against the ISO table where a country is
       expected and as a literal of the wrong class elsewhere;
  1.1  the parser: action if expr, homogeneous and/or chains reduced left to right, `not` looser than a
       comparison, the nesting bound on descent, operations counted per token in source order;
  1.5  the refusals in their order (length, alphabet, lexing, parsing, typing per directive; then sets,
       program limits and polarity over the configuration), with the normative locations and strings;
  1.3, 1.4  typing, set resolution and the definite values with the clamps applied at fill;
  2.5  the polarity pass, the value-set outage classifier with the tenant sub-state seeds, an exact
       brute-force classifier for the soundness property, the shadowing procedure and the reports;
  2.2, 3.2, 3.3  the instruction stream (for the cost line), the K3 evaluator over the normalised
       attribute block in the fixed order, with the polarity-scoped tenant reading and ISUNK;
  5.1  the per-case cost line, computed from the program and the atom values alone;
  7    the canonical text.

Usage:
  policy_ref.py --corpus DIR              replay the independent corpus: 20 accept, 50 refuse
  policy_ref.py --self-test               the oracle's own checks, each with its negative control
  policy_ref.py --cases FILE [--out F] [--coverage F] [--mutant NAME] [--attrs]
                                          evaluate a case file (policy_gen.py writes them)
  policy_ref.py --compile FILE            compile one .policy file and print its listing or refusal
  policy_ref.py --expect FILE             print one .policy file's refusal as an .expect file would hold it
  policy_ref.py --seeds DIR --floor N     replay the seed list: compile or a located refusal, never a crash
  policy_ref.py --default-conf FILE       decision 3's default compiles, to the program of accept/01

Every run that checks something ends with one `N checks, F failures` line, the line `make check` sums
into the README's published count.

THE CASE FILE (input) is line based. A program block is followed by the cases that run it:

  program <id> <leg>
  dir <kind> <context> <argument, bytes outside 0x20..0x7E and the backslash written \\xHH>
  run <context>                    the context whose effective program runs in step 4
  absent <plane> ...               planes absent at configuration time (optional)
  legacy                           the configuration names the legacy synonym, so no rule is inert
                                   whatever is absent (optional; D-af)
  case <id>
  conf <floor|ctx> <mode> <allow_inferred>     raw integers, so the domain rule is exercised
  plane <name> <fresh|stale|gen0>  the seven non-tenant planes (absent lines mean fresh); gen0 is a
                                   map armed at generation 0, "nothing armed", which reads UNKNOWN
                                   exactly as a stale non-tenant plane does (D-ae)
  tenant <fresh|stale|null|revoked> <now_ms> <valid_until_ms>
                                   fresh needs valid_until 0 (no bound) or now <= valid_until, and stale
                                   needs 0 < valid_until < now; a word its times contradict is a
                                   malformed case, refused
  addr <floor|server> <address>
  flags <hold_harmless_eligible 0|1> <acme_exempt 0|1>
  rec <floor|server> <plane> none
  rec <floor|server> <plane> <field>=<value> ...
  sweep <floor|server> <plane> <field> <lo> <hi>   expands this case into one per value, ids <id>.<value>
  end

THE OUTPUT, per program and per case; every line but `msg` is compared by policy_diff.py, which also
refuses an output with a line before the first `program`, a program or case id seen twice, or no case.
Each format line is followed by an example from a real run.

  program <id>
      program g1
  refusal layer=<l> kind=<k> context=<c> rule=<n> line=<l> col=<c> token="<rendered>" | <fragment>
      refusal layer=polarity kind=policy context=http/server:a/location:api rule=1 line=1 col=85 token="is" | that is a fail-closed rule
    <fragment> is the corpus-style message (the six fixed strings, or the table phrase); a refused
    program has no case lines
  msg <what>. <fix>                                  not compared: the wording is each side's own
  text <floor|ctx> <rule> <canonical rule text>
      text ctx 3 deny if not listed in {high} and tenant_allow and vpn
  text <floor|ctx> set <canonical set declaration>   one per named set the program uses, by name
      text ctx set @s0 reputable neutral suspicious
  report set <context>/@<name> duplicate-member <m>,<m>,...      the members seen again, as written
      report set http/@s0 duplicate-member reputable,suspicious,suspicious
  report <floor|ctx> <context> <rule> <kind> [<detail>], one line per finding, kinds and details:
    inert-at-config <plane>,...                the absent planes the rule reads
      report ctx http/server:a 1 inert-at-config routing
    inert-allow-exposes <rule ranges>|-        for an inert allow, the later denies it no longer exempts
      report ctx http/server:a 1 inert-allow-exposes 2
    shadowed-by <rule>                         the earliest shadowing rule (section 2.5's procedure, D-aa)
      report ctx http/server:a/location:api 2 shadowed-by 1
    tautology <attr>                           an `in` whose set is the whole possible-values mask (D-q)
      report ctx http/server:a 3 tautology rpki_reason
    coverage <attr> <k>/<n>                    an enum `in` matches k of the n values a fresh plane yields
      report ctx http/server:a 3 coverage listed 1/5
    duplicate-member <m>,...                   inside an inline set
    sentinel-negative <attr>                   once per attribute, in an allow (D-r)
      report ctx http/server:a 4 sentinel-negative asn_rep
    denies-all-absent                          a deny or log TRUE on the all-fresh, all-absent record
      report floor http 1 denies-all-absent
    capturing-allow <plane>[(keyed)],...       the single planes whose outage makes the allow capture,
                                               printed only when a deny follows
      report ctx http/server:a 4 capturing-allow routing(keyed)
    unbounded <plane>,...                      TRUE only through an ISUNK on that plane, or for the
                                               tenant plane a capture under LAPSED
      report ctx http/server:a 2 unbounded tenant
    adds-nothing                               an allow on a positive tenant_allow (D-s)
      report ctx http/server:a 6 adds-nothing
  case <id>
  verdict step=<1|2|3|3.5|4> action=<allow|deny> program=<floor|ctx|-> rule=<n> reason=<r>
          log_floor=<rules>|- log_ctx=<rules>|-
      verdict step=4 action=allow program=ctx rule=4 reason=allow-by-unknown:routing log_floor=- log_ctx=-
    <r> is `-`, or comma-joined: the deciding marker first (allow-by-hold-harmless, allow-by-acme,
    allow-by-tenant, allow-by-unknown:<lowest-id UNKNOWN plane the rule references>), then
    tenant-revoked when the pre-stage ran under a revoked tenant plane; rule 0 is no rule (steps 1, 2,
    3.5 and the default allow, which is step=4 program=-). we_verdict_format() also writes
    allow-by-no-address, step 1's exemption for a request with no floor address; a case always gives
    one, so it never reaches a compared line
      verdict step=4 action=allow program=- rule=0 reason=tenant-revoked log_floor=- log_ctx=-
  cost ops=<floor>/<ctx> jumps=<floor>/<ctx> probes=<floor>/<ctx> lookups=<8 counts>/<8 counts>
      cost ops=3/22 jumps=0/2 probes=0/1 lookups=0,0,0,1,0,0,0,1/0,0,0,1,0,0,0,1
    ops counts every instruction EXECUTED, END included and every JF and JT whether or not it jumps;
    an instruction a jump skips is not counted, a rule inert at config or a program under mode off
    executes nothing; jumps counts the JF and JT taken; probes per D-n; lookups per plane 1..8 for the
    floor's slot then the server's (D-l, D-m; with equal keys every lookup is the floor's, D-o)
  attr <name> <value>|UNKNOWN [bounded=<true|false|unknown>]
    under --attrs only: 25 lines after `cost`, in the vocabulary's order, the floor address's attributes
    as whisper-edge-lookup prints them; UNKNOWN for a plane absent at config, stale, refused or generation
    0, and `bounded` on tenant_allow when the tenant plane is present and stale (GRACE: the stale
    record's value; LAPSED: false) or null (unknown)
      attr rpki unrouted
      attr tenant_allow UNKNOWN bounded=true
  invariant checked=<n> failed=<n>
      invariant checked=13 failed=0
    n counts, over the floor program and the run context's program, every atom occurrence but `is
    unknown` (inert rules included) times the states of its plane (5 for the tenant plane, 2 for any
    other); it is computed whatever decided the request, step 1 included
  classes floor=<letters>|- ctx=<letters>|-          one letter per rule: n narrowed, i inert, c captures,
                                                     x inert at config; - for no program
      classes floor=- ctx=xnn
  dependents <floor|ctx> out=<planes>|- tenant=<state>: <groups>|none
      dependents ctx out=routing tenant=fresh: rule 4 allow captures; rules 1-3,5-6 disarmed
    the groups in this order, each omitted when empty: rule(s) <ranges> allow captures; rule(s) <ranges>
    disarmed; rule(s) <ranges> narrowed

DECISIONS (where POLICY.md leaves a choice; each is reported upstream so both sides read it one way).
Adopted into POLICY.md: D-a, D-e, D-g's order, D-l to D-p, D-t's member order; D-x, D-y, D-z and D-aa
are settled here and read the same way by the C compiler.
  D-a  Steps 1 to 5 run per directive in file order (the way a server hands directives to a module one
       at a time); steps 6, 7 and 8 run over the whole configuration after every directive is seen.
  D-b  Step 6 checks every set declaration in file order (count, duplicate, shadowing, no members, mixed
       class), then every set use in file order (empty inline set, undefined, class mismatch).
  D-c  Step 7 walks the directives in file order (rules over 256, the operation that crosses 4,096,
       `allow` in a floor, `threshold` beside policy lines, instructions, hot bytes).
  D-d  A byte in 0x21..0x7E that belongs to no token class (every one of  " # $ % & ' * / : ; ? [ \\ ] ^ `
       | ~ ) is refused by the lexer as `byte 0xHH is not allowed`, as section 1.2 rules for `#`.
  D-e  Word characters are [A-Za-z0-9_.+-]; a word is a maximal run of them. `+` and `.` are word
       characters so that `+1` is a signed number and `as1.10` is asdot.
  D-f  After `@` the identifier is the maximal run of [a-z0-9_-]; an empty run is `a stray @`
       (so `@Embargo` is a stray `@`); `@` inside braces, after a comparison operator and in a set
       declaration after its name is `a stray @`.
  D-g  A number with a non-digit after its digits (`1e3`, `0x10`, `1_000`) is refused at the first
       non-digit, with the rest of the word as the token, as `a non-digit in a number`; within a
       number token the checks run sign, asdot, non-digit, leading zero, digit count, value, sentinel.
  D-h  In expression mode a word is a keyword, then an attribute, then a bare literal, then an
       upper-case spelling of the vocabulary, then a two-letter bare literal, then an unknown word.
       So `IN` there is an upper-case keyword and `NL` a bare literal. In literal mode a number is
       an AS number, two letters are a country code, then the literal vocabulary, then upper case.
  D-i  Where a country is expected (after country/registry_country with == or !=, inside the braces
       that follow `in` or `==`/`!=` on them, and in every set declaration) `uk` and unknown codes are
       lexing refusals; elsewhere a two-letter token is a country literal and typing judges it.
  D-j  `()` and an operator, `is` or `in` with nothing after them are `an empty expression` at the
       token where the expression was expected: the `)` for `()`, one past the end at end of input.
  D-k  Phrases the table of section 1.5 does not carry are this file's: `a non-digit in a number`,
       `unbalanced parentheses`, `is not a boolean`, `only literals inside braces`,
       `only literals in a set declaration`, `a set declaration names its set with @`,
       `is takes unknown or not unknown`, `a mode of off, log or deny`,
       `a threshold of off, low, medium, high or critical`, `allow_inferred takes on or off`,
       `a floor is http-level only`, `an unknown directive`. Each is compared and has a coverage cell,
       as the table's phrases do.
  D-l  The tenant plane is looked up whenever it has a map (fresh, or stale within or past the grace)
       and an instruction or a pre-stage step reads it; a stale non-tenant plane is never looked up
       (it reads UNKNOWN, which is what lets the state space reduce to two states per plane); ISUNK
       reads the plane's state and never fills; a revoked tenant plane is never looked up.
  D-m  The pre-stage fills the tenant entry on the floor's address at step 2 whenever the tenant plane
       has a map, so the lookup happens once whether step 2 or step 3.5 then reads it.
  D-n  set_probes counts one per executed INSET_COUNTRY and the level count per executed INSET_ASN,
       whatever the plane's state, because the search is fixed-iteration and data-free.
  D-o  When the two keys are equal the one slot is the floor's and its lookups are counted there.
  D-p  JF and JT jump to the instruction after the chain's last connective, never threaded further.
  D-q  The tautology report fires on every `in` occurrence whose set is the attribute's whole
       possible-values mask; the shadowing procedure reads `listed >= a` only, as written.
  D-r  The negative-polarity sentinel warning is skipped when the compared values include
       `undetermined`, and when the rule's root and-chain carries `x != undetermined` for that
       attribute (the guard the warning suggests).
  D-s  `adds-nothing` fires for an allow whose root is `tenant_allow` or an and-chain with a positive
       `tenant_allow` operand.
  D-t  A canonical rule keeps parentheses only where a chain is an operand of a chain or of `not`;
       set members are de-duplicated and sorted (undetermined first, levels and enums in domain order,
       AS numbers ascending, country codes alphabetically).
  D-v  Shadowing: R1 qualifies only when its condition is one positive atom or an and-chain of positive
       atoms; R2 may be an and-chain with non-atom operands (a parenthesised or-chain), whose positive
       atom operands are the ones R1's atoms must subsume, since R2 implies each of them.
  D-w  POLICY.md's N3 row asks for 256 rules each an or-chain of 32 `!=` atoms; that is 16,128
       operations, past the 4,096 limit, so it cannot compile. The generator builds the per-rule
       maximum (one rule, 63 operations, 127 instructions) and the context maximum (128 rules of 9
       `!=` atoms and 128 of 8: exactly 4,096 operations and 8,448 instructions) as two programs.
       8,449 instructions cannot be reached under the operation and rule limits, so that limit has
       no one-past case.
  D-x  Step 8 reports the first polarity fault in FILE order across the whole configuration (the
       directive's position, then the `is` token's), not the first fault of the first program, so with
       interleaved contexts an earlier directive's fault wins whichever context it is in; consistent
       with D-a.
  D-y  `undetermined on a bool` is the refusal when the operand compared with a bool is `undetermined`,
       located at that literal; `in or == on a bool` covers every other operand and every `in`, located
       at the operator or `in`.
  D-z  An inline set's own class is checked before the attribute's: a set whose members are not all of
       one class is refused `an inline set whose members are not all of one class` at the first member
       whose class differs from the first classed member's (`undetermined` takes any class); a uniform
       set of the wrong class is the wrong-class refusal at its first member of that class.
  D-aa A rule inert at configuration shadows nothing, since it never fires; a later rule it would have
       subsumed is reported against the earliest LIVE rule that shadows it, if any.
  D-y (continued). The operator is judged before the operand: `tor_exit >= undetermined` is refused
       `an ordered comparison on anything but listed`. `undetermined on a bool` applies when the operator
       is `==`, `!=` or `in` and the operand is `undetermined` (for `in`, an inline set whose every member
       is `undetermined`, located at its first member); any other operand of those three is `in or == on
       a bool`.
  D-z (continued). `undetermined` is a legal set member only for a class whose attribute is sentinel-bearing
       under section 1.3 (rpki, rpki_reason, asn, asn_rep, country, registry_country, rir, registry_rir);
       against `listed`, the one attribute without a sentinel, it is the wrong-class refusal at that
       member. The check runs AFTER the mixed-class check: a mixed inline set is refused `an inline set
       whose members are not all of one class` first, and a set otherwise uniform and of the right class
       that carries `undetermined` against `listed` is refused wrong-class at the `undetermined` member. A
       declared set holding `undetermined` used against `listed` is refused `a set used against an
       attribute of another class` at the use (step 6, where a declared set's class is known). This keeps
       one invariant: `x in { v }` and `x == v` agree on legality for every attribute x and literal v.
  D-aa (continued). An inert rule is neither a shadower nor shadowed: no shadowing report names an inert
       rule in either role.
  D-ac Every `listed` test is one SEV over a level mask, `listed in {...}` included, which is the
       compiler's encoding (the inferred rule applied in one place); the instruction count is the same as
       an INSET_ENUM's, so only the opcode's name in the coverage cells reads differently, and there is
       one: `plane-state SEV reputation <state>`.
  D-ab A `log` rule is never shadowed (POLICY.md section 11, decision D2): it records and continues and
       decides nothing, so "never decides" says nothing of it, and it is skipped as R2 as it already was
       as R1.
  D-ad A refusal line's context is the C error's 128-byte field: up to 127 bytes verbatim, a longer one
       its first 61 bytes, `...` and its last 63 (the server and the innermost block both survive).
  D-ae Generation 0 is the revoked map's "nothing armed" (section 2.7). On the tenant plane it is
       REVOKED, definite, with the tenant-revoked mark; on every other plane it is UNKNOWN: nothing armed
       is not a measurement, so its attributes are undetermined, `is unknown` is T, and the record a
       generation-0 file still carries is never read. A case marks it `plane <name> gen0`.
  D-af The threshold sugar is a rule like any other: in a configuration that does not name the legacy
       synonym, a whisper_edge_threshold whose directory lacks reputation.bin at config test is
       inert-at-config and reported exactly as `deny if listed >= <level>` would be (the block is
       byte-identical to that rule compiled in the same environment). Only the legacy synonym makes
       it never inert. A case marks the synonym with a `legacy` line.
  D-u  Hot bytes are the C block's hot_len, which section 2.1 defines: header 64, rules 16 each,
       instructions 8 each, bindings 256, one 16-byte descriptor per distinct set that has a payload (a
       country bitmap, or an ASN S+ tree with members; an enum set is a mask in the instruction and an
       ASN set of `undetermined` alone is an EQ32), each table rounded up to 64, then the payloads (a
       country bitmap as 128, an S+ tree as 64 per node) and, in a FLOOR program, the hold-harmless
       arrays (section 3.8): a 64-byte header, per family the merged starts and ends rounded up to 64
       each and the S-tree's nodes, from the same hold-harmless.txt this file reads (3,968 bytes today).
       The hold-harmless arrays count because a floor carries them in its block: a floor of 141 rules
       fits 256 KiB without them and not with them, and testdata/policy/adversarial/h1, h2 and h3 hold
       that boundary.
"""

import bisect
import ipaddress
import os
import sys
import time

# ---------------------------------------------------------------------------------------------------
# The vocabulary (POLICY.md, the attribute vocabulary; FORMAT.md section 3)
# ---------------------------------------------------------------------------------------------------

PLANES = ('reputation', 'tor', 'rpki-unreachable', 'routing', 'anonymizer', 'threat', 'registry', 'tenant')
PLANE_ID = {p: i + 1 for i, p in enumerate(PLANES)}
TENANT = 8
KEYED = {'routing', 'anonymizer', 'threat', 'registry', 'tenant'}
SCHEMA = {1: 'f1', 2: 'member', 3: 'member', 4: 'routing', 5: 'member', 6: 'member', 7: 'routing', 8: 'member'}
MEMBER_MASK = {2: 0x01, 3: 0x01, 5: 0x03, 6: 0x3F, 8: 0x03}

# bool attribute -> (plane id, bit mask in the normalised block's flags, or 0x80 of sev for inferred)
BOOLS = {
    'inferred': (1, 0x80), 'rpki_unreachable': (3, 0x01), 'tor_exit': (2, 0x01), 'proxy': (5, 0x01),
    'vpn': (5, 0x02), 'c2': (6, 0x01), 'bruteforce': (6, 0x02), 'spam': (6, 0x04), 'phishing': (6, 0x08),
    'scanner': (6, 0x10), 'state_actor': (6, 0x20), 'anycast': (4, 0x01), 'moas': (4, 0x02),
    'narrowed': (4, 0x04), 'tenant_allow': (8, 0x01), 'tenant_deny': (8, 0x02),
}
# non-bool attribute -> (plane id, class, normalised field)
VALUED = {
    'listed': (1, 'level', 'sev'), 'rpki_reason': (3, 'rpki_reason', 'reason'), 'rpki': (4, 'rpki', 'rov'),
    'asn': (4, 'asn', 'asn'), 'asn_rep': (4, 'asn_rep', 'asn_rep'), 'country': (4, 'country', 'country'),
    'registry_country': (7, 'country', 'country'), 'rir': (4, 'rir', 'rir'),
    'registry_rir': (7, 'rir', 'rir'),
}
ATTRS = set(BOOLS) | set(VALUED)
COUNTRY_ATTRS = ('country', 'registry_country')
SENTINEL_ATTRS = {'rpki', 'asn', 'asn_rep', 'country', 'rir', 'rpki_reason', 'registry_country', 'registry_rir'}
# the classes whose attributes carry a sentinel (section 1.3): every class but `level`, which `listed` alone has
SENTINEL_CLASSES = ('rpki', 'rpki_reason', 'asn_rep', 'rir', 'asn', 'country')

LEVELS = ('none', 'low', 'medium', 'high', 'critical')
ENUMS = {
    'rpki': ('undetermined', 'valid', 'invalid', 'not-found', 'unrouted'),
    'rpki_reason': ('undetermined', 'asn', 'length'),
    'asn_rep': ('undetermined', 'reputable', 'neutral', 'suspicious', 'highly_suspicious'),
    'rir': ('undetermined', 'afrinic', 'apnic', 'arin', 'lacnic', 'ripe'),
}
ENUM_LITS = {}
for _dom, _vals in ENUMS.items():
    for _i, _v in enumerate(_vals):
        if _i:
            ENUM_LITS[_v] = (_dom, _i)
ENUM_LITS['not_found'] = ENUM_LITS['notfound'] = ENUM_LITS['not-found']
LEVEL_LITS = {v: i for i, v in enumerate(LEVELS)}
KEYWORDS = {'allow', 'deny', 'log', 'if', 'and', 'or', 'not', 'in', 'is', 'unknown', 'undetermined'}
ACTIONS = ('allow', 'deny', 'log')
VOCAB = KEYWORDS | ATTRS | set(LEVEL_LITS) | set(ENUM_LITS)

DOMAIN_TEXT = {
    'level': 'none, low, medium, high or critical',
    'rpki': 'valid, invalid, not-found, unrouted or undetermined',
    'rpki_reason': 'asn, length or undetermined',
    'asn_rep': 'reputable, neutral, suspicious, highly_suspicious or undetermined',
    'rir': 'afrinic, apnic, arin, lacnic, ripe or undetermined',
    'asn': 'an AS number (64496 or as64496) or undetermined',
    'country': 'a two-letter country code or undetermined',
}
# the possible-values mask a fresh plane can produce (section 2.6), over the value indices
POSSIBLE = {'level': 5, 'rpki': 5, 'rpki_reason': 3, 'asn_rep': 5, 'rir': 6}

ASN_SENTINEL = 0xFFFFFFFF
GRACE_MS = 48 * 3600 * 1000
ROUTING_TEMPLATE = {'asn': ASN_SENTINEL, 'country': 0, 'rov': 4, 'rir': 0, 'flags': 0, 'asn_rep': 0}

LIMIT_ARG = 2048
LIMIT_NEST = 16
LIMIT_RULE_OPS = 64
LIMIT_RULES = 256
LIMIT_CTX_OPS = 4096
LIMIT_INSTRS = 8448
LIMIT_HOT = 256 * 1024
LIMIT_SETS = 1024

# ISO 3166-1, alpha-2 to numeric: the iso-codes list gen-country-table.py reads (249 codes, the
# 2023-12 table), written out here so this file needs nothing installed. The four user-assigned codes
# FORMAT.md gives a meaning follow. --self-test holds the numeric set to we_country_table.h's bitmap.
_ISO = """
AD20 AE784 AF4 AG28 AI660 AL8 AM51 AO24 AQ10 AR32 AS16 AT40 AU36 AW533 AX248 AZ31 BA70 BB52 BD50
BE56 BF854 BG100 BH48 BI108 BJ204 BL652 BM60 BN96 BO68 BQ535 BR76 BS44 BT64 BV74 BW72 BY112 BZ84
CA124 CC166 CD180 CF140 CG178 CH756 CI384 CK184 CL152 CM120 CN156 CO170 CR188 CU192 CV132 CW531
CX162 CY196 CZ203 DE276 DJ262 DK208 DM212 DO214 DZ12 EC218 EE233 EG818 EH732 ER232 ES724 ET231
FI246 FJ242 FK238 FM583 FO234 FR250 GA266 GB826 GD308 GE268 GF254 GG831 GH288 GI292 GL304 GM270
GN324 GP312 GQ226 GR300 GS239 GT320 GU316 GW624 GY328 HK344 HM334 HN340 HR191 HT332 HU348 ID360
IE372 IL376 IM833 IN356 IO86 IQ368 IR364 IS352 IT380 JE832 JM388 JO400 JP392 KE404 KG417 KH116
KI296 KM174 KN659 KP408 KR410 KW414 KY136 KZ398 LA418 LB422 LC662 LI438 LK144 LR430 LS426 LT440
LU442 LV428 LY434 MA504 MC492 MD498 ME499 MF663 MG450 MH584 MK807 ML466 MM104 MN496 MO446 MP580
MQ474 MR478 MS500 MT470 MU480 MV462 MW454 MX484 MY458 MZ508 NA516 NC540 NE562 NF574 NG566 NI558
NL528 NO578 NP524 NR520 NU570 NZ554 OM512 PA591 PE604 PF258 PG598 PH608 PK586 PL616 PM666 PN612
PR630 PS275 PT620 PW585 PY600 QA634 RE638 RO642 RS688 RU643 RW646 SA682 SB90 SC690 SD729 SE752
SG702 SH654 SI705 SJ744 SK703 SL694 SM674 SN686 SO706 SR740 SS728 ST678 SV222 SX534 SY760 SZ748
TC796 TD148 TF260 TG768 TH764 TJ762 TK772 TL626 TM795 TN788 TO776 TR792 TT780 TV798 TW158 TZ834
UA804 UG800 UM581 US840 UY858 UZ860 VA336 VC670 VE862 VG92 VI850 VN704 VU548 WF876 WS882 YE887
YT175 ZA710 ZM894 ZW716 EU900 AP901 ZZ902 XK903
"""
COUNTRY = {t[:2]: int(t[2:]) for t in _ISO.split()}
COUNTRY_ALPHA = {v: k for k, v in COUNTRY.items()}
COUNTRY_KNOWN = frozenset(COUNTRY.values())

T, F, U = 'T', 'F', 'U'
TFU = (T, F, U)

# ---------------------------------------------------------------------------------------------------
# Mutants: the oracle's own negative controls (section 5.4's names, where the defect is one a
# value-level interpreter can carry). Set by --mutant; the production run has none.
# ---------------------------------------------------------------------------------------------------

ORACLE_MUTANTS = (
    'K3_WEAK', 'ALLOW_U_FALLTHROUGH', 'LOG_TERMINATES', 'POLARITY_NO_ALLOW', 'ISNOTUNK_POSITIVE',
    'BOOL_NOT', 'SENTINEL_NE', 'SHORTCIRCUIT_U', 'NO_CLAMP', 'NO_MEMO_HIT', 'NO_SHORTCIRCUIT',
    'CLASSIFY_ISUNK_U', 'NO_CAPTURES', 'CLASSIFY_SINGLE_EVAL', 'SENTINEL_PADDING', 'TENANT_ATOM_U',
    'TENANT_BIT_IGNORED', 'NO_EXHAUSTIVE',
)
MUTANT = None


def k3_tables(mutant=None):
    """K3 by its truth tables, as values. The mutants are the encodings POLICY.md names as wrong."""
    nt = {T: F, F: T, U: U}
    an = {}
    orr = {}
    for a in TFU:
        for b in TFU:
            if a == F or b == F:
                an[(a, b)] = F
            elif a == T and b == T:
                an[(a, b)] = T
            else:
                an[(a, b)] = U
            if a == T or b == T:
                orr[(a, b)] = T
            elif a == F and b == F:
                orr[(a, b)] = F
            else:
                orr[(a, b)] = U
    if mutant == 'K3_WEAK':
        for a in TFU:
            for b in TFU:
                if U in (a, b):
                    an[(a, b)] = U
                    orr[(a, b)] = U
    if mutant == 'BOOL_NOT':
        nt[U] = T
    return nt, an, orr


K3_NOT, K3_AND, K3_OR = k3_tables()


def set_mutant(name):
    global MUTANT, K3_NOT, K3_AND, K3_OR
    if name is not None and name not in ORACLE_MUTANTS:
        raise SystemExit('policy_ref.py: no oracle mutant %r (have: %s)' % (name, ', '.join(ORACLE_MUTANTS)))
    MUTANT = name
    K3_NOT, K3_AND, K3_OR = k3_tables(name)


# ---------------------------------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------------------------------

def render_token(raw):
    """Section 1.5: truncate at 64 bytes, then every byte outside 0x20..0x7E, `"` and `\\` as \\xHH."""
    out = []
    for b in raw[:64]:
        if b < 0x20 or b > 0x7E or b in (0x22, 0x5C):
            out.append('\\x%02X' % b)
        else:
            out.append(chr(b))
    return ''.join(out)


def position(arg, off):
    """1-based line and byte column of offset `off`; only LF starts a line."""
    line = arg.count(b'\n', 0, off) + 1
    nl = arg.rfind(b'\n', 0, off)
    return line, off - nl if nl >= 0 else off + 1


class Refusal(Exception):
    def __init__(self, layer, fragment, what, fix='', off=0, raw=b'', line=None, col=None):
        Exception.__init__(self, what)
        self.layer, self.fragment, self.what, self.fix = layer, fragment, what, fix
        self.off, self.raw, self.line, self.col = off, raw, line, col
        self.kind = self.context = None
        self.rule = 0

    def locate(self, arg):
        if self.line is None:
            self.line, self.col = position(arg, self.off)

    def line_out(self):
        return 'refusal layer=%s kind=%s context=%s rule=%d line=%d col=%d token="%s" | %s' % (
            self.layer, self.kind, error_context(self.context), self.rule, self.line, self.col,
            render_token(self.raw), self.fragment)

    def message(self):
        return 'rule %d, line %d, column %d: near "%s": %s.%s' % (
            self.rule, self.line, self.col, render_token(self.raw), self.what,
            (' ' + self.fix) if self.fix else '')


def error_context(ctx):
    """A refusal line's context as the C error holds it (128 bytes): verbatim up to 127 bytes, else the
    first 61, `...` and the last 63, so the server and the innermost block both survive (D-ad)."""
    if ctx is None or len(ctx) <= 127:
        return ctx
    return ctx[:61] + '...' + ctx[-63:]


# Section 1.5's table, the one source of the strings: every refusal names the table phrase it stands
# for, and the coverage matrix requires each phrase to be emitted by the generated set. One phrase is
# structurally unreachable from source text and is held by the verifier only (D-w).
TABLE_PHRASES = (
    'argument over 2,048 bytes',
    'byte 0xHH is not allowed',
    'identifier over 64 bytes', 'a number with a sign', 'a leading zero other than 0', 'more than 10 digits',
    'above 2^32 - 1', 'the sentinel 4294967295', 'asdot', 'an unknown country code', 'uk',
    'an upper-case keyword or literal', 'a bare literal in expression mode', 'a stray @', 'an unknown operator',
    'trailing input', 'and/or mixed in a chain', 'unbalanced or nested braces', 'a stray }', 'nesting over 16',
    'over 64 operations in a rule', 'an action without if', 'an empty expression', 'an unknown attribute or word',
    'a literal of the wrong class', 'an ordered comparison on anything but listed', 'in or == on a bool',
    'undetermined on a bool', 'an inline set whose members are not all of one class',
    '@set undefined in this context or an enclosing one', 'a duplicate definition in one scope',
    'a definition shadowing an outer set', 'an empty set', 'a declaration with no members',
    'a declared set whose members are not of one class', 'a set used against an attribute of another class',
    'more than 1,024 sets in the configuration',
    'over 256 rules in a context', 'over 4,096 operations in a context', 'over 8,448 instructions',
    'over 256 KiB of program bytes', 'allow in a floor program',
    'whisper_edge_threshold in a context with policy lines',
    'is unknown whose polarity lets a deny fire because of an outage',
)
UNREACHABLE_PHRASES = ('over 8,448 instructions',)
# The phrases this file adds to the table (D-k): pinned the same way, a program and a coverage cell each.
DK_PHRASES = (
    'a non-digit in a number',
    'unbalanced parentheses',
    'is not a boolean',
    'only literals inside braces',
    'only literals in a set declaration',
    'a set declaration names its set with @',
    'is takes unknown or not unknown',
    'a mode of off, log or deny',
    'a threshold of off, low, medium, high or critical',
    'allow_inferred takes on or off',
    'a floor is http-level only',
    'an unknown directive',
)


def table_phrase(fragment):
    """The section 1.5 table phrase a refusal's fragment stands for, or None for this file's own (D-k)."""
    if fragment in DK_PHRASES:
        return fragment                   # exact first: two of them hold ' takes ' and are not a wrong class
    if fragment.startswith('byte 0x'):
        return 'byte 0xHH is not allowed'
    if ' takes ' in fragment:
        return 'a literal of the wrong class'
    if fragment == 'did you mean GB':
        return 'uk'
    if fragment == RU_FIX:
        return 'a bare literal in expression mode'
    if fragment == 'deny if not <condition>':
        return 'an action without if'
    if fragment == 'that is a fail-closed rule':
        return 'is unknown whose polarity lets a deny fire because of an outage'
    if fragment.startswith('deny if listed >= ') or fragment.startswith('no rule (threshold off'):
        return 'whisper_edge_threshold in a context with policy lines'
    if fragment == 'undefined in this context or an enclosing one':
        return '@set undefined in this context or an enclosing one'
    return fragment if fragment in TABLE_PHRASES or fragment in DK_PHRASES else None


def refuse_tok(layer, fragment, what, tok, fix=''):
    return Refusal(layer, fragment, what, fix, tok.off, tok.raw)


# ---------------------------------------------------------------------------------------------------
# The lexer (section 1.2)
# ---------------------------------------------------------------------------------------------------

WS = frozenset(b' \t\n\x0b\x0c\r')
ALPHABET = frozenset(range(0x20, 0x7F)) | frozenset(b'\t\n\x0b\x0c\r')
WORDCH = frozenset(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.+')
IDENTCH = frozenset(b'abcdefghijklmnopqrstuvwxyz0123456789_-')
PUNCT = frozenset(b'(){},')
OPCH = frozenset(b'=!<>')
OPS = ('==', '!=', '>=', '>', '<=', '<')
DIGITS = frozenset(b'0123456789')
AT = 0x40
RU_FIX = 'write country in { RU } or country == RU'


class Tok(object):
    __slots__ = ('kind', 'raw', 'off', 'value')

    def __init__(self, kind, raw, off, value=None):
        self.kind, self.raw, self.off, self.value = kind, raw, off, value

    def __repr__(self):
        return 'Tok(%s,%r)' % (self.kind, self.raw)


def check_length_alphabet(arg):
    if len(arg) > LIMIT_ARG:
        raise Refusal('length', 'argument over 2,048 bytes',
                      'argument over 2,048 bytes (%d bytes)' % len(arg),
                      'shorten it, or move members into a whisper_edge_set', 0, b'', 1, 1)
    for i, b in enumerate(arg):
        if b not in ALPHABET:
            m = 'byte 0x%02X is not allowed' % b
            raise Refusal('alphabet', m, m, 'the language is printable ASCII', i, bytes([b]))


def number_shaped(w):
    s = w[1:] if w[:1] in ('+', '-') else w
    if s[:2].lower() == 'as':
        s = s[2:]
    return s[:1].isdigit() and s[:1] in '0123456789'


def check_number(w, off):
    """The number token checks in section 1.2's order (D-g). Returns the value or raises."""
    raw = w.encode()
    if w[0] in '+-':
        raise Refusal('lexing', 'a number with a sign', 'a number with a sign',
                      'AS numbers are unsigned', off, raw)
    s = w[2:] if w[:2].lower() == 'as' else w
    k = 0
    while k < len(s) and s[k] in '0123456789':
        k += 1
    digits, tail = s[:k], s[k:]
    if tail[:1] == '.' and tail[1:].isdigit() and tail[1:].isascii():
        hi, lo = int(digits), int(tail[1:])
        if hi > 65535 or lo > 65535:
            fix = 'each part of an asdot number is 0..65535 and %s is not; write the asplain value' % (
                tail[1:] if lo > 65535 else digits)
        else:
            fix = 'write the asplain value %d' % (hi * 65536 + lo)
        raise Refusal('lexing', 'asdot', 'asdot is not accepted', fix, off, raw)
    if tail:
        at = off + (len(w) - len(tail))
        raise Refusal('lexing', 'a non-digit in a number',
                      'a non-digit in a number (%r)' % tail[0], 'AS numbers are base 10 digits',
                      at, tail.encode())
    if len(digits) > 1 and digits[0] == '0':
        raise Refusal('lexing', 'a leading zero other than 0',
                      'a leading zero other than 0 (strtoul with base 0 would read %s as octal)' % digits,
                      'write %d' % int(digits), off, raw)
    if len(digits) > 10:
        raise Refusal('lexing', 'more than 10 digits', 'more than 10 digits', 'an AS number is 32 bits',
                      off, raw)
    v = int(digits)
    if v > 0xFFFFFFFF:
        raise Refusal('lexing', 'above 2^32 - 1', 'above 2^32 - 1', 'an AS number is 32 bits', off, raw)
    if v == ASN_SENTINEL:
        raise Refusal('lexing', 'the sentinel 4294967295', 'the sentinel 4294967295 is not addressable',
                      'write undetermined', off, raw)
    return v


def classify_literal(w, off, country_expected):
    """A word in literal mode (D-h). Returns a Tok kind and value, or raises a lexing refusal."""
    raw = w.encode()
    if number_shaped(w):
        return 'lit', ('asn', check_number(w, off))
    if len(w) == 2 and w.isalpha() and w.isascii():
        up = w.upper()
        if country_expected:
            if up == 'UK':
                raise Refusal('lexing', 'did you mean GB', 'uk is not an ISO 3166-1 code', 'did you mean GB',
                              off, raw)
            if up not in COUNTRY:
                raise Refusal('lexing', 'an unknown country code', 'an unknown country code %s' % up,
                              'the codes are ISO 3166-1 alpha-2, plus EU AP ZZ XK', off, raw)
        return 'lit', ('country', COUNTRY.get(up), up)
    if w in LEVEL_LITS:
        return 'lit', ('level', LEVEL_LITS[w])
    if w in ENUM_LITS:
        d, i = ENUM_LITS[w]
        return 'lit', ('enum', d, i)
    if w == 'undetermined':
        return 'lit', ('undet',)
    if w != w.lower() and w.lower() in VOCAB:
        raise Refusal('lexing', 'an upper-case keyword or literal', 'an upper-case keyword or literal',
                      'write %s' % w.lower(), off, raw)
    return 'unknown', w


def classify_word(w, off):
    """A word in expression mode (D-h)."""
    raw = w.encode()
    if number_shaped(w):
        check_number(w, off)
        raise Refusal('lexing', 'a bare literal in expression mode', 'a bare literal in expression mode',
                      'compare it: asn == %s' % w, off, raw)
    if w in KEYWORDS and w != 'undetermined':
        return 'kw', w
    if w in ATTRS:
        return 'attr', w
    if w in LEVEL_LITS or w in ENUM_LITS or w == 'undetermined':
        raise Refusal('lexing', 'a bare literal in expression mode', 'a bare literal in expression mode',
                      'a literal follows a comparison: rpki == valid', off, raw)
    if w != w.lower() and w.lower() in VOCAB:
        raise Refusal('lexing', 'an upper-case keyword or literal', 'an upper-case keyword or literal',
                      'write %s' % w.lower(), off, raw)
    if len(w) == 2 and w.isalpha() and w.isascii():
        raise Refusal('lexing', RU_FIX, 'a bare literal in expression mode', RU_FIX, off, raw)
    return 'unknown', w


def lex(arg, mode):
    """mode 'expr' (a policy or floor rule) or 'decl' (a whisper_edge_set argument)."""
    toks = []
    i, n = 0, len(arg)
    depth = 0                 # brace depth: inside braces every word is a literal
    brace_country = False
    literal_next = None       # the operator the next token is the literal of
    after_in = False
    last_attr = None
    prev = None
    first = True
    while True:
        while i < n and arg[i] in WS:
            i += 1
        if i >= n:
            toks.append(Tok('eof', b'', n))
            return toks
        c = arg[i]
        if not (c in WORDCH or c in PUNCT or c in OPCH or c == AT):
            m = 'byte 0x%02X is not allowed' % c
            raise Refusal('lexing', m, m, 'this byte belongs to no token of the language', i, bytes([c]))
        if after_in and c not in (AT, 0x7B):
            j = i + 1
            if c in WORDCH:
                while j < n and arg[j] in WORDCH:
                    j += 1
            elif c in OPCH:
                while j < n and arg[j] in OPCH:
                    j += 1
            raise Refusal('lexing', RU_FIX, 'a set after in: in takes @name or { ... }', RU_FIX, i, arg[i:j])
        after_in = False
        if c in PUNCT:
            ch = chr(c)
            if ch == '{':
                if depth == 0:
                    brace_country = (mode == 'decl') or (last_attr in COUNTRY_ATTRS and prev is not None and (
                        (prev.kind == 'kw' and prev.value == 'in') or
                        (prev.kind == 'op' and prev.value in ('==', '!='))))
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
            literal_next = None
            t = Tok('punct', arg[i:i + 1], i, ch)
            i += 1
        elif c in OPCH:
            j = i
            while j < n and arg[j] in OPCH:
                j += 1
            op = arg[i:j].decode()
            if op not in OPS:
                raise Refusal('lexing', 'an unknown operator', 'an unknown operator %s' % op,
                              'the operators are == != >= > <= <', i, arg[i:j])
            t = Tok('op', arg[i:j], i, op)
            if depth == 0:
                literal_next = op
            i = j
        elif c == AT:
            j = i + 1
            while j < n and arg[j] in IDENTCH:
                j += 1
            name = arg[i + 1:j]
            stray = depth > 0 or literal_next is not None or (mode == 'decl' and not first) or not name
            if stray:
                raise Refusal('lexing', 'a stray @', 'a stray @',
                              'a set is named @name, 1 to 64 bytes of a-z, 0-9, _ and -', i, b'@')
            if len(name) > 64:
                raise Refusal('lexing', 'identifier over 64 bytes', 'identifier over 64 bytes',
                              'a set name is at most 64 bytes', i, arg[i:j])
            t = Tok('setname' if mode == 'decl' else 'setref', arg[i:j], i, name.decode())
            i = j
        else:
            j = i
            while j < n and arg[j] in WORDCH:
                j += 1
            w = arg[i:j].decode()
            if depth > 0 or literal_next is not None or mode == 'decl':
                ce = (depth > 0 and brace_country) or mode == 'decl' or (
                    literal_next in ('==', '!=') and last_attr in COUNTRY_ATTRS)
                kind, value = classify_literal(w, i, ce)
                literal_next = None
            else:
                kind, value = classify_word(w, i)
                if kind == 'kw' and value == 'in':
                    after_in = True
                elif kind == 'attr':
                    last_attr = value
            t = Tok(kind, arg[i:j], i, value)
            i = j
        toks.append(t)
        prev = t
        first = False


# ---------------------------------------------------------------------------------------------------
# The parser (section 1.1)
# ---------------------------------------------------------------------------------------------------

class Atom(object):
    """One atom occurrence. form: bool | isunk | cmp | in."""
    __slots__ = ('attr', 'form', 'neg', 'op', 'lit', 'members', 'setname', 'brace', 'tok', 'optok',
                 'littok', 'istok', 'intok', 'resolved', 'plane', 'pol', 'bounded', 'idx', 'rule')

    def __init__(self, attr, tok):
        self.attr, self.tok = attr, tok
        self.form = 'bool'
        self.neg = False
        self.op = self.lit = self.members = self.setname = self.brace = None
        self.optok = self.littok = self.istok = self.intok = None
        self.resolved = None
        self.plane = BOOLS[attr][0] if attr in BOOLS else VALUED[attr][0]
        self.pol = True
        self.bounded = False
        self.idx = 0
        self.rule = None


class Not(object):
    __slots__ = ('child', 'tok')

    def __init__(self, child, tok):
        self.child, self.tok = child, tok


class Chain(object):
    __slots__ = ('conn', 'children', 'toks')

    def __init__(self, conn, children, toks):
        self.conn, self.children, self.toks = conn, children, toks


class Rule(object):
    __slots__ = ('action', 'actok', 'expr', 'ops', 'atoms', 'n', 'kind', 'context', 'directive', 'instrs',
                 'dep', 'inert', 'n_instr', 'text', 'program')

    def __init__(self):
        self.action = self.actok = self.expr = self.kind = self.context = self.directive = None
        self.ops, self.atoms, self.n = [], [], 0
        self.instrs, self.dep, self.inert, self.n_instr, self.text, self.program = None, frozenset(), False, 0, '', None


class Parser(object):
    def __init__(self, toks, arg):
        self.toks, self.arg, self.i = toks, arg, 0
        self.ops = []
        self.atoms = []

    def peek(self):
        return self.toks[self.i]

    def take(self):
        t = self.toks[self.i]
        if t.kind != 'eof':
            self.i += 1
        return t

    def is_kw(self, t, *words):
        return t.kind == 'kw' and t.value in words

    def count_op(self, t):
        self.ops.append(t)
        if len(self.ops) > LIMIT_RULE_OPS:
            raise refuse_tok('parsing', 'over 64 operations in a rule', 'over 64 operations in a rule', t,
                             'split it into two rules, or move members into a set')

    def empty(self, t):
        return refuse_tok('parsing', 'an empty expression', 'an empty expression', t,
                          'a rule is action if condition')

    def rule(self):
        t = self.take()
        if t.kind == 'eof':
            raise self.empty(t)
        if not self.is_kw(t, *ACTIONS):
            raise refuse_tok('parsing', 'an unknown attribute or word', 'an unknown attribute or word', t,
                             'a rule starts with allow, deny or log')
        r = Rule()
        r.action, r.actok = t.value, t
        t2 = self.take()
        if t2.kind == 'eof' or not self.is_kw(t2, 'if'):
            fix = {'deny': 'deny if not <condition>', 'allow': 'allow if <condition>',
                   'log': 'log if <condition>'}[r.action]
            raise refuse_tok('parsing', 'an action without if' if t2.kind != 'eof' or r.action != 'deny'
                             else 'deny if not <condition>', 'an action without if', t2, fix)
        r.expr = self.expr(0)
        t = self.peek()
        if t.kind != 'eof':
            if t.kind == 'punct' and t.value == ')':
                raise refuse_tok('parsing', 'unbalanced parentheses', 'unbalanced parentheses: a ) with no (',
                                 t)
            if t.kind == 'punct' and t.value == '}':
                raise refuse_tok('parsing', 'a stray }', 'a stray }', t)
            raise refuse_tok('parsing', 'trailing input', 'trailing input', t,
                             'join conditions with and or or')
        r.ops = self.ops
        r.atoms = self.atoms
        return r

    def expr(self, depth):
        first = self.unary(depth)
        t = self.peek()
        if not self.is_kw(t, 'and', 'or'):
            return first
        conn = t.value
        children, ctoks = [first], []
        while True:
            t = self.peek()
            if not self.is_kw(t, 'and', 'or'):
                break
            if t.value != conn:
                raise refuse_tok('parsing', 'and/or mixed in a chain', 'and/or mixed in a chain', t,
                                 'add parentheses: (a %s b) %s c' % (conn, t.value))
            self.take()
            self.count_op(t)
            ctoks.append(t)
            children.append(self.unary(depth))
        return Chain(conn, children, ctoks)

    def unary(self, depth):
        t = self.peek()
        if self.is_kw(t, 'not'):
            if depth + 1 > LIMIT_NEST:
                raise refuse_tok('parsing', 'nesting over 16', 'nesting over 16', t,
                                 'parentheses and not together nest at most 16 deep')
            self.take()
            self.count_op(t)
            return Not(self.unary(depth + 1), t)
        return self.primary(depth)

    def primary(self, depth):
        t = self.peek()
        if t.kind == 'punct' and t.value == '(':
            if depth + 1 > LIMIT_NEST:
                raise refuse_tok('parsing', 'nesting over 16', 'nesting over 16', t,
                                 'parentheses and not together nest at most 16 deep')
            self.take()
            if self.peek().kind == 'punct' and self.peek().value == ')':
                raise self.empty(self.peek())
            e = self.expr(depth + 1)
            c = self.peek()
            if c.kind == 'punct' and c.value == ')':
                self.take()
                return e
            if c.kind == 'eof':
                raise refuse_tok('parsing', 'unbalanced parentheses', 'unbalanced parentheses: this ( is never closed', t)
            if c.kind == 'punct' and c.value == '}':
                raise refuse_tok('parsing', 'a stray }', 'a stray }', c)
            raise refuse_tok('parsing', 'unbalanced parentheses',
                             'unbalanced parentheses: expected ) here', c)
        if t.kind == 'eof' or (t.kind == 'punct' and t.value == ')'):
            raise self.empty(t)
        if t.kind == 'punct' and t.value == '}':
            raise refuse_tok('parsing', 'a stray }', 'a stray }', t)
        if t.kind == 'punct' and t.value == '{':
            raise refuse_tok('parsing', 'unbalanced or nested braces',
                             'unbalanced or nested braces: a set follows in', t)
        if t.kind == 'attr':
            return self.atom()
        raise refuse_tok('parsing', 'an unknown attribute or word', 'an unknown attribute or word', t,
                         'the attributes are listed in the README')

    def atom(self):
        t = self.take()
        self.count_op(t)
        a = Atom(t.value, t)
        a.idx = len(self.atoms)
        self.atoms.append(a)
        n = self.peek()
        if self.is_kw(n, 'is'):
            a.istok = self.take()
            a.form = 'isunk'
            m = self.peek()
            if self.is_kw(m, 'not'):
                self.take()
                a.neg = True
                m = self.peek()
            if not self.is_kw(m, 'unknown'):
                if m.kind == 'eof':
                    raise self.empty(m)
                raise refuse_tok('parsing', 'is takes unknown or not unknown', 'is takes unknown or not unknown', m)
            self.take()
            return a
        if n.kind == 'op':
            a.optok = self.take()
            a.form, a.op = 'cmp', n.value
            m = self.peek()
            if m.kind == 'lit':
                a.littok = self.take()
                a.lit = m.value
                return a
            if m.kind == 'eof':
                raise self.empty(m)
            if m.kind == 'punct' and m.value == '{':
                raise refuse_tok('parsing', 'unbalanced or nested braces',
                                 'unbalanced or nested braces: a set follows in, not %s' % n.value, m,
                                 'write %s in { ... }' % a.attr)
            raise refuse_tok('parsing', 'an unknown attribute or word', 'an unknown attribute or word', m)
        if self.is_kw(n, 'in'):
            a.intok = self.take()
            a.form = 'in'
            m = self.peek()
            if m.kind == 'setref':
                self.take()
                a.setname = m.value
                a.brace = m
                return a
            if m.kind == 'punct' and m.value == '{':
                a.brace = self.take()
                a.members = self.set_body(a.brace)
                return a
            raise self.empty(m)
        if a.attr not in BOOLS:
            raise refuse_tok('parsing', 'is not a boolean', '%s is not a boolean; compare it' % a.attr, t,
                             'for example %s is unknown, or a comparison' % a.attr)
        return a

    def set_body(self, brace):
        members = []
        while True:
            t = self.take()
            if t.kind == 'punct' and t.value == ',':
                continue
            if t.kind == 'punct' and t.value == '}':
                return members
            if t.kind == 'lit':
                members.append(t)
                continue
            if t.kind == 'eof':
                raise refuse_tok('parsing', 'unbalanced or nested braces',
                                 'unbalanced or nested braces: this { is never closed', brace)
            if t.kind == 'punct' and t.value == '{':
                raise refuse_tok('parsing', 'unbalanced or nested braces',
                                 'unbalanced or nested braces: braces do not nest', t)
            if t.kind == 'unknown':
                raise refuse_tok('parsing', 'an unknown attribute or word', 'an unknown attribute or word', t)
            raise refuse_tok('parsing', 'only literals inside braces', 'only literals inside braces', t)


class SetDecl(object):
    __slots__ = ('name', 'nametok', 'members', 'context', 'directive', 'cls', 'values', 'has_undet',
                 'mixed', 'dups')


def parse_decl(toks):
    t = toks[0]
    if t.kind != 'setname':
        raise refuse_tok('parsing', 'a set declaration names its set with @',
                         'a set declaration names its set with @', t, 'whisper_edge_set "@name members"')
    d = SetDecl()
    d.name, d.nametok = t.value, t
    d.members = []
    for t in toks[1:]:
        if t.kind == 'eof':
            break
        if t.kind == 'punct' and t.value == ',':
            continue
        if t.kind == 'lit':
            d.members.append(t)
            continue
        if t.kind == 'unknown':
            raise refuse_tok('parsing', 'an unknown attribute or word', 'an unknown attribute or word', t)
        raise refuse_tok('parsing', 'only literals in a set declaration', 'only literals in a set declaration', t)
    return d


# ---------------------------------------------------------------------------------------------------
# Typing (section 1.3) and literal classes
# ---------------------------------------------------------------------------------------------------

def lit_class(lit):
    k = lit[0]
    if k == 'level':
        return 'level'
    if k == 'enum':
        return lit[1]
    if k == 'asn':
        return 'asn'
    if k == 'country':
        return 'country'
    return None


def attr_class(attr):
    return 'bool' if attr in BOOLS else VALUED[attr][1]


def lit_index(lit):
    """The normalised value a literal compares against."""
    k = lit[0]
    if k == 'level':
        return lit[1]
    if k == 'enum':
        return lit[2]
    if k == 'asn':
        return lit[1]
    if k == 'country':
        return lit[1]
    return None


def undet_value(cls):
    return ASN_SENTINEL if cls == 'asn' else 0


def wrong_class(attr, tok):
    cls = attr_class(attr)
    m = '%s takes %s' % (attr, DOMAIN_TEXT[cls])
    return refuse_tok('typing', m, m, tok)


def type_rule(rule):
    for a in rule.atoms:
        cls = attr_class(a.attr)
        if a.form in ('bool', 'isunk'):
            continue
        if cls == 'bool':
            if a.form == 'cmp' and a.op not in ('==', '!='):
                raise refuse_tok('typing', 'an ordered comparison on anything but listed',
                                 'an ordered comparison on anything but listed', a.optok)
            undet_tok = None
            if a.form == 'cmp' and a.lit[0] == 'undet':
                undet_tok = a.littok
            elif a.form == 'in' and a.members and all(m.value[0] == 'undet' for m in a.members):
                undet_tok = a.members[0]
            if undet_tok is not None:
                raise refuse_tok('typing', 'undetermined on a bool', 'undetermined on a bool', undet_tok,
                                 'a bool has no sentinel: write %s or not %s' % (a.attr, a.attr))
            tok = a.optok if a.form == 'cmp' else a.intok
            raise refuse_tok('typing', 'in or == on a bool', 'in or == on a bool', tok,
                             'write %s or not %s' % (a.attr, a.attr))
        if a.form == 'cmp':
            if a.op not in ('==', '!=') and a.attr != 'listed':
                raise refuse_tok('typing', 'an ordered comparison on anything but listed',
                                 'an ordered comparison on anything but listed', a.optok)
            lc = lit_class(a.lit)
            if lc is None:
                if cls == 'level':
                    raise wrong_class(a.attr, a.littok)
            elif lc != cls:
                raise wrong_class(a.attr, a.littok)
        elif a.form == 'in' and a.members is not None:
            first = None
            for m in a.members:
                lc = lit_class(m.value)
                if lc is None:
                    continue
                if first is None:
                    first = lc
                elif lc != first:
                    raise refuse_tok('typing', 'an inline set whose members are not all of one class',
                                     'an inline set whose members are not all of one class', m,
                                     'one set holds values of one kind')
            for m in a.members:
                lc = lit_class(m.value)
                if (lc is None and cls not in SENTINEL_CLASSES) or (lc is not None and lc != cls):
                    raise wrong_class(a.attr, m)


def set_values(lits, cls):
    """Normalised values of a set's members against class cls; (values, has_undet, dups)."""
    seen = []
    vals = set()
    has_undet = False
    dups = []
    for t in lits:
        lit = t.value
        if lit[0] == 'undet':
            v = ('undet',)
            if has_undet:
                dups.append('undetermined')
            has_undet = True
        else:
            v = lit_index(lit)
            if v in vals:
                dups.append(render_lit(lit))
            vals.add(v)
        seen.append(v)
    return frozenset(vals), has_undet, dups


# ---------------------------------------------------------------------------------------------------
# The configuration: records, directives, steps 1 to 8
# ---------------------------------------------------------------------------------------------------

class Directive(object):
    __slots__ = ('kind', 'context', 'arg', 'rule', 'index', 'parsed', 'toks')

    def __init__(self, kind, context, arg, index):
        self.kind, self.context, self.arg, self.index = kind, context, arg, index
        self.rule = 0
        self.parsed = None


def read_records(data):
    """The corpus format: <kind> SP <context> SP <argument bytes> 0x1E 0x0A per directive."""
    out = []
    for chunk in data.split(b'\x1e\n'):
        if chunk == b'' or chunk == b'\n':
            continue
        sp1 = chunk.find(b' ')
        sp2 = chunk.find(b' ', sp1 + 1) if sp1 >= 0 else -1
        if sp1 < 0:
            kind, ctx, arg = chunk, b'', b''
        elif sp2 < 0:
            kind, ctx, arg = chunk[:sp1], chunk[sp1 + 1:], b''
        else:
            kind, ctx, arg = chunk[:sp1], chunk[sp1 + 1:sp2], chunk[sp2 + 1:]
        out.append((kind.decode('ascii', 'replace').lstrip('\n'), ctx.decode('ascii', 'replace'), arg))
    return out


def ancestors(ctx):
    """ctx itself first, then each enclosing context."""
    parts = ctx.split('/')
    return ['/'.join(parts[:k]) for k in range(len(parts), 0, -1)]


THRESHOLDS = {'off': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
MODES = {'off': 1, 'log': 2, 'deny': 3}


def parse_word_arg(arg, choices, fragment):
    words = arg.split()
    if len(words) == 1 and words[0].decode().lower() in choices:
        return words[0].decode().lower()
    i = 0
    while i < len(arg) and arg[i] in WS:
        i += 1
    j = i
    while j < len(arg) and arg[j] not in WS:
        j += 1
    if len(words) > 1:
        k = arg.find(words[1], j)
        raise Refusal('parsing', fragment, fragment, '', k, words[1])
    raise Refusal('parsing', fragment, fragment, '', i, arg[i:j])


class Program(object):
    __slots__ = ('kind', 'context', 'rules', 'sets', 'sugar', 'ops', 'instrs')

    def __init__(self, kind, context):
        self.kind, self.context = kind, context
        self.rules = []
        self.sets = {}
        self.sugar = None


class Config(object):
    def __init__(self):
        self.directives = []
        self.decls = {}           # (context, name) -> SetDecl
        self.floor = None
        self.programs = {}        # context -> Program (its own policy lines or threshold sugar)
        self.modes = {}
        self.inferred = {}
        self.absent = set()
        self.reports = []

    def effective(self, ctx):
        for c in ancestors(ctx):
            if c in self.programs:
                return self.programs[c]
        return None


def compile_text_rule(text):
    """Compile one rule's text alone (the sugar and the canonical re-parse)."""
    arg = text.encode()
    toks = lex(arg, 'expr')
    r = Parser(toks, arg).rule()
    type_rule(r)
    return r


def compile_config(records, absent=(), legacy=False):
    """Raises Refusal (located) or returns a Config. `records` as read_records returns them."""
    cfg = Config()
    cfg.absent = set(absent)
    cfg.legacy = bool(legacy)
    counts = {}
    for idx, (kind, ctx, arg) in enumerate(records):
        d = Directive(kind, ctx, arg, idx)
        counts[(kind, ctx)] = counts.get((kind, ctx), 0) + 1
        d.rule = counts[(kind, ctx)]
        cfg.directives.append(d)
        try:
            check_length_alphabet(arg)
            if kind in ('policy', 'floor'):
                if kind == 'floor' and ctx != 'http':
                    raise Refusal('parsing', 'a floor is http-level only', 'a floor is http-level only', '', 0,
                                  b'', 1, 1)
                toks = lex(arg, 'expr')
                r = Parser(toks, arg).rule()
                type_rule(r)
                r.kind, r.context, r.directive, r.n = kind, ctx, d, d.rule
                for a in r.atoms:
                    a.rule = r
                d.parsed = r
            elif kind == 'set':
                toks = lex(arg, 'decl')
                sd = parse_decl(toks)
                sd.context, sd.directive = ctx, d
                d.parsed = sd
            elif kind == 'threshold':
                d.parsed = parse_word_arg(arg, THRESHOLDS, 'a threshold of off, low, medium, high or critical')
            elif kind == 'mode':
                d.parsed = parse_word_arg(arg, MODES, 'a mode of off, log or deny')
            elif kind == 'allow_inferred':
                d.parsed = parse_word_arg(arg, ('on', 'off'), 'allow_inferred takes on or off')
            else:
                raise Refusal('parsing', 'an unknown directive', 'an unknown directive %s' % kind, '', 0, b'', 1, 1)
        except Refusal as e:
            e.locate(arg)
            e.kind, e.context, e.rule = kind, ctx, d.rule
            raise
    step6_sets(cfg)
    build_programs(cfg)
    step7_limits(cfg)
    step8_polarity(cfg)
    finish(cfg)
    return cfg


def located(e, d):
    e.locate(d.arg)
    e.kind, e.context, e.rule = d.kind, d.context, d.rule
    return e


def decl_refusal(d, fragment, what, fix=''):
    sd = d.parsed
    e = Refusal('sets', fragment, what, fix, 0, ('@' + sd.name).encode(), 1, 1)
    return located(e, d)


def decl_class(sd):
    classes = set()
    for t in sd.members:
        c = lit_class(t.value)
        if c is not None:
            classes.add(c)
    if len(classes) > 1:
        return 'mixed'
    if not classes:
        return 'undet'
    return classes.pop()


def step6_sets(cfg):
    """D-b: declarations first, then uses, each in file order."""
    count = 0
    for d in cfg.directives:
        if d.kind != 'set':
            continue
        sd = d.parsed
        count += 1
        if count > LIMIT_SETS:
            raise decl_refusal(d, 'more than 1,024 sets in the configuration',
                               'more than 1,024 sets in the configuration (%s declares the 1,025th)' % d.context)
        if (d.context, sd.name) in cfg.decls:
            raise decl_refusal(d, 'a duplicate definition in one scope', 'a duplicate definition in one scope',
                               '@%s is already declared in %s' % (sd.name, d.context))
        cfg.decls[(d.context, sd.name)] = sd
    for d in cfg.directives:
        if d.kind != 'set':
            continue
        sd = d.parsed
        for anc in ancestors(d.context)[1:]:
            if (anc, sd.name) in cfg.decls:
                raise decl_refusal(d, 'a definition shadowing an outer set', 'a definition shadowing an outer set',
                                   '@%s is already declared in %s' % (sd.name, anc))
        if not sd.members:
            raise decl_refusal(d, 'a declaration with no members', 'a declaration with no members')
        sd.cls = decl_class(sd)
        if sd.cls == 'mixed':
            raise decl_refusal(d, 'a declared set whose members are not of one class',
                               'a declared set whose members are not of one class')
        sd.values, sd.has_undet, sd.dups = set_values(sd.members, sd.cls)
    for d in cfg.directives:
        if d.kind not in ('policy', 'floor'):
            continue
        for a in d.parsed.atoms:
            if a.form != 'in':
                continue
            cls = attr_class(a.attr)
            if a.members is not None:
                if not a.members:
                    raise located(refuse_tok('sets', 'an empty set', 'an empty set', a.brace,
                                             'an empty set matches nothing; remove the rule'), d)
                vals, hu, dups = set_values(a.members, cls)
                a.resolved = ('inline', vals, hu, dups, None)
                continue
            sd = None
            for anc in ancestors(d.context):
                if (anc, a.setname) in cfg.decls:
                    sd = cfg.decls[(anc, a.setname)]
                    break
            if sd is None:
                raise located(refuse_tok('sets', 'undefined in this context or an enclosing one',
                                         '@%s undefined in this context or an enclosing one' % a.setname,
                                         a.brace, 'declare it with whisper_edge_set'), d)
            ok = (sd.cls == cls or sd.cls == 'undet') and not (sd.has_undet and cls not in SENTINEL_CLASSES)
            if not ok:
                raise located(refuse_tok('sets', 'a set used against an attribute of another class',
                                         'a set used against an attribute of another class',
                                         a.brace, '%s takes %s' % (a.attr, DOMAIN_TEXT[cls])), d)
            a.resolved = ('named', sd.values, sd.has_undet, sd.dups, sd)


def build_programs(cfg):
    for d in cfg.directives:
        if d.kind == 'floor':
            if cfg.floor is None:
                cfg.floor = Program('floor', 'http')
            cfg.floor.rules.append(d.parsed)
        elif d.kind == 'policy':
            p = cfg.programs.get(d.context)
            if p is None or p.sugar is not None:
                p = Program('ctx', d.context)
                cfg.programs[d.context] = p
            p.rules.append(d.parsed)
        elif d.kind == 'threshold':
            if d.context not in cfg.programs:
                p = Program('ctx', d.context)
                p.sugar = d.parsed
                cfg.programs[d.context] = p
        elif d.kind == 'mode':
            cfg.modes[d.context] = MODES[d.parsed]
        elif d.kind == 'allow_inferred':
            cfg.inferred[d.context] = 1 if d.parsed == 'on' else 0
    for p in cfg.programs.values():
        if p.sugar is not None and p.sugar != 'off':
            r = compile_text_rule('deny if listed >= %s' % p.sugar)
            r.kind, r.context, r.directive, r.n = 'policy', p.context, None, 1
            for a in r.atoms:
                a.rule = r
            p.rules = [r]
    for p in [cfg.floor] + list(cfg.programs.values()):
        if p is None:
            continue
        for i, r in enumerate(p.rules):
            r.n = i + 1
            r.program = p


def hh_bytes():
    """The hold-harmless region of a floor block (section 3.8), as the compiler lays it out."""
    def r64(x):
        return (x + 63) // 64 * 64

    def depth(m, fanout):
        p, d = 1, 0
        while p < m:
            p *= fanout
            d += 1
        return d
    n4, n6 = len(HH_RANGES[4][0]), len(HH_RANGES[6][0])
    m4, m6 = (n4 + 15) // 16, (n6 + 3) // 4
    d4, d6 = depth(m4, 17), depth(m6, 5)
    nodes4, nodes6 = (17 ** d4 - 1) // 16, (5 ** d6 - 1) // 4
    return 64 + r64(4 * n4) * 2 + nodes4 * 64 + r64(16 * n6) * 2 + nodes6 * 64


def hot_bytes(rules, floor=False):
    """D-u: the block's hot_len."""
    def r64(x):
        return (x + 63) // 64 * 64
    n_instr = sum(r.n_instr for r in rules)
    sets = {}
    for r in rules:
        for a in r.atoms:
            if a.form == 'in':
                key = ('named', id(a.resolved[4])) if a.resolved[0] == 'named' else ('inline', id(a))
                sets[key] = a
    data = 0
    payloads = 0
    for a in sets.values():
        cls = attr_class(a.attr)
        if cls == 'country':
            data += 128
            payloads += 1
        elif cls == 'asn':
            n = len(a.resolved[1])
            if n:
                data += splus_nodes(n) * 64
                payloads += 1
    return (64 + r64(16 * len(rules)) + r64(8 * n_instr) + 256 + r64(16 * payloads) + data
            + (hh_bytes() if floor else 0))


def splus_levels(n):
    lv, cap = 1, 16
    while cap < n:
        lv += 1
        cap *= 17
    return lv


def splus_nodes(n):
    nodes, per = 0, 16
    for _ in range(splus_levels(n)):
        nodes += -(-n // per)
        per *= 17
    return nodes


def step7_limits(cfg):
    """D-c: the directives in file order against their context's counters."""
    rules_seen, ops_seen, ins_seen, hot_rules = {}, {}, {}, {}
    policy_ctx = {d.context for d in cfg.directives if d.kind == 'policy'}
    for d in cfg.directives:
        if d.kind in ('policy', 'floor'):
            r = d.parsed
            key = (d.kind, d.context)
            nrules = rules_seen.get(key, 0) + 1
            rules_seen[key] = nrules
            if nrules > LIMIT_RULES:
                raise located(refuse_tok('program', 'over 256 rules in a context', 'over 256 rules in a context',
                                         r.actok), d)
            before = ops_seen.get(key, 0)
            if before + len(r.ops) > LIMIT_CTX_OPS:
                t = r.ops[LIMIT_CTX_OPS - before]
                raise located(refuse_tok('program', 'over 4,096 operations in a context',
                                         'over 4,096 operations in a context', t), d)
            ops_seen[key] = before + len(r.ops)
            if d.kind == 'floor' and r.action == 'allow':
                raise located(refuse_tok('program', 'allow in a floor program', 'allow in a floor program',
                                         r.actok, 'the floor only tightens: deny or log'), d)
            compile_rule(r)
            ins = ins_seen.get(key, 0) + r.n_instr
            ins_seen[key] = ins
            if ins > LIMIT_INSTRS:
                raise located(refuse_tok('program', 'over 8,448 instructions', 'over 8,448 instructions',
                                         r.actok), d)
            hot_rules.setdefault(key, []).append(r)
            hb = hot_bytes(hot_rules[key], d.kind == 'floor')
            if hb > LIMIT_HOT:
                raise located(refuse_tok('program', 'over 256 KiB of program bytes',
                                         'over 256 KiB of program bytes (%d hot bytes)' % hb, r.actok), d)
        elif d.kind == 'threshold' and d.context in policy_ctx:
            eq = ('deny if listed >= %s' % d.parsed) if d.parsed != 'off' else 'no rule (threshold off denies nothing)'
            i = 0
            while i < len(d.arg) and d.arg[i] in WS:
                i += 1
            j = i
            while j < len(d.arg) and d.arg[j] not in WS:
                j += 1
            raise located(Refusal('program', eq, 'whisper_edge_threshold in a context with policy lines',
                                  'write the equivalent rule: %s' % eq, i, d.arg[i:j]), d)
    for p in cfg.programs.values():
        for r in p.rules:
            if r.instrs is None:
                compile_rule(r)


def walk_atoms(e, pol, out):
    """Every atom occurrence with its polarity in the rule (positive at the root, flipped under not)."""
    if isinstance(e, Atom):
        out.append((e, pol))
    elif isinstance(e, Not):
        walk_atoms(e.child, not pol, out)
    else:
        for c in e.children:
            walk_atoms(c, pol, out)
    return out


def isunk_polarity(a, pol):
    """The polarity of the ISUNK inside the atom: `is not unknown` flips it once more."""
    if MUTANT == 'ISNOTUNK_POSITIVE':
        return pol
    return pol if not a.neg else (not pol)


def step8_polarity(cfg):
    progs = []
    if cfg.floor is not None:
        progs.append(cfg.floor)
    progs += [p for p in cfg.programs.values() if p.sugar is None]
    faults = []
    for p in progs:
        for i, r in enumerate(p.rules):
            later = [q for q in p.rules[i + 1:] if q.action == 'deny']
            for a, pol in walk_atoms(r.expr, True, []):
                if a.form != 'isunk':
                    continue
                ip = isunk_polarity(a, pol)
                bad = None
                if r.action == 'deny' and ip:
                    bad = r.n
                elif r.action == 'allow' and not ip and later and MUTANT != 'POLARITY_NO_ALLOW':
                    bad = later[0].n
                if bad is not None:
                    faults.append((r.directive.index, a.istok.off, r, a, bad))
    if faults:
        _, _, r, a, bad = min(faults, key=lambda f: (f[0], f[1]))
        what = ('rule %d: "is unknown" here lets rule %d deny exactly when the %s plane is missing or '
                'stale; that is a fail-closed rule' % (r.n, bad, PLANES[a.plane - 1]))
        raise located(refuse_tok('polarity', 'that is a fail-closed rule', what, a.istok,
                                 'Use it in a log rule, or in an allow rule that no later deny '
                                 'depends on.'), r.directive)


# ---------------------------------------------------------------------------------------------------
# The instruction stream (section 2.2): the shape the cost line is computed from
# ---------------------------------------------------------------------------------------------------

def opcode_of(a):
    if a.form == 'isunk':
        return 'ISUNK'
    if a.form == 'bool':
        return 'BOOL'
    cls = attr_class(a.attr)
    if cls == 'level':
        return 'SEV'               # every `listed` test, `in` included (D-ac)
    if a.form == 'cmp':
        return {'country': 'EQ16', 'asn': 'EQ32'}.get(cls, 'EQ8')
    if cls == 'country':
        return 'INSET_COUNTRY'
    if cls == 'asn':
        return 'INSET_ASN' if a.resolved[1] else 'EQ32'
    return 'INSET_ENUM'


def compile_expr(e, out):
    if isinstance(e, Atom):
        op = opcode_of(e)
        out.append([op, e, None])
        if (e.form == 'cmp' and e.op == '!=') or (e.form == 'isunk' and e.neg):
            out.append(['NOT', None, None])
        return
    if isinstance(e, Not):
        compile_expr(e.child, out)
        out.append(['NOT', None, None])
        return
    jump = 'JF' if e.conn == 'and' else 'JT'
    conn = 'AND' if e.conn == 'and' else 'OR'
    compile_expr(e.children[0], out)
    jumps = []
    for c in e.children[1:]:
        j = [jump, None, None]
        out.append(j)
        jumps.append(j)
        compile_expr(c, out)
        out.append([conn, None, None])
    for j in jumps:
        j[2] = len(out)


def compile_rule(r):
    # the tenant polarity bit: tenant_allow, positive, inside an allow
    for a, pol in walk_atoms(r.expr, True, []):
        a.pol = pol
        a.bounded = (a.attr == 'tenant_allow' and a.form == 'bool' and pol and r.action == 'allow')
    out = []
    compile_expr(r.expr, out)
    out.append(['END', None, None])
    r.instrs = [tuple(x) for x in out]
    r.n_instr = len(out)
    r.dep = frozenset(a.plane for a in r.atoms)
    r.inert = False


def finish(cfg):
    progs = ([cfg.floor] if cfg.floor else []) + list(cfg.programs.values())
    for p in progs:
        for r in p.rules:
            if r.instrs is None:
                compile_rule(r)
            # D-af: the threshold sugar is a rule like any other; only the legacy synonym arms everything
            r.inert = bool(r.dep & {PLANE_ID[x] for x in cfg.absent}) and not cfg.legacy
            r.text = render_rule(r)
    cfg.reports = make_reports(cfg)


# ---------------------------------------------------------------------------------------------------
# The canonical text (section 7, D-t)
# ---------------------------------------------------------------------------------------------------

def render_lit(lit):
    k = lit[0]
    if k == 'level':
        return LEVELS[lit[1]]
    if k == 'enum':
        return ENUMS[lit[1]][lit[2]]
    if k == 'asn':
        return str(lit[1])
    if k == 'country':
        return lit[2]
    return 'undetermined'


def lit_sort_key(lit):
    k = lit[0]
    if k == 'undet':
        return (0, 0, '')
    if k == 'country':
        return (1, 0, lit[2])
    if k == 'asn':
        return (1, lit[1], '')
    return (1, lit[-1], '')


def render_members(lits):
    seen = {}
    for lit in lits:
        key = render_lit(lit)
        if key not in seen:
            seen[key] = lit
    return ' '.join(render_lit(x) for x in sorted(seen.values(), key=lit_sort_key))


def render_expr(e, nested):
    if isinstance(e, Atom):
        if e.form == 'bool':
            return e.attr
        if e.form == 'isunk':
            return '%s is %sunknown' % (e.attr, 'not ' if e.neg else '')
        if e.form == 'cmp':
            return '%s %s %s' % (e.attr, e.op, render_lit(e.lit))
        if e.setname is not None:
            return '%s in @%s' % (e.attr, e.setname)
        return '%s in {%s}' % (e.attr, render_members([m.value for m in e.members]))
    if isinstance(e, Not):
        return 'not ' + render_expr(e.child, True)
    s = (' %s ' % e.conn).join(render_expr(c, True) for c in e.children)
    return '(' + s + ')' if nested else s


def render_rule(r):
    return '%s if %s' % (r.action, render_expr(r.expr, False))


def render_decl(sd):
    return '@%s %s' % (sd.name, render_members([m.value for m in sd.members]))


# ---------------------------------------------------------------------------------------------------
# The value-set classifier (section 2.5), the exact brute force, the dependents line
# ---------------------------------------------------------------------------------------------------

TENANT_STATES = ('fresh', 'grace', 'lapsed', 'null', 'revoked')


def seed(a, out, tenant):
    """The value set of one occurrence under out-set `out` (non-tenant plane ids) and tenant state."""
    if a.plane == TENANT:
        if a.form == 'isunk':
            v = {T} if tenant in ('grace', 'lapsed', 'null') else {F}
        elif tenant == 'fresh':
            v = {T, F}
        elif a.bounded or MUTANT == 'TENANT_BIT_IGNORED':
            v = {T, F} if tenant == 'grace' else ({F} if tenant in ('lapsed', 'revoked') else {U})
            if MUTANT == 'TENANT_ATOM_U' and a.bounded and tenant in ('grace', 'lapsed'):
                v = {U}
        else:
            v = {F} if tenant == 'revoked' else {U}
    elif a.form == 'isunk':
        v = {T} if a.plane in out else {F}
        if MUTANT == 'CLASSIFY_ISUNK_U' and a.plane in out:
            v = {U}
    else:
        v = {U} if a.plane in out else {T, F}
    if a.form == 'isunk' and a.neg or (a.form == 'cmp' and a.op == '!='):
        v = {K3_NOT[x] for x in v}
    return v


def value_set(e, out, tenant):
    if isinstance(e, Atom):
        return seed(e, out, tenant)
    if isinstance(e, Not):
        return {K3_NOT[x] for x in value_set(e.child, out, tenant)}
    tab = K3_AND if e.conn == 'and' else K3_OR
    acc = value_set(e.children[0], out, tenant)
    for c in e.children[1:]:
        b = value_set(c, out, tenant)
        acc = {tab[(x, y)] for x in acc for y in b}
    return acc


def single_eval_set(r, out, tenant):
    """WE_TEST_CLASSIFY_SINGLE_EVAL: one evaluation, every other atom at its most favourable value."""
    def ev(e, want):
        if isinstance(e, Atom):
            s = seed(e, out, tenant)
            if len(s) == 1:
                return next(iter(s))
            return want if want in s else next(iter(sorted(s)))
        if isinstance(e, Not):
            return K3_NOT[ev(e.child, K3_NOT[want])]
        tab = K3_AND if e.conn == 'and' else K3_OR
        acc = ev(e.children[0], want)
        for c in e.children[1:]:
            acc = tab[(acc, ev(c, want))]
        return acc
    return {ev(r.expr, T)}


def rule_class(r, out, tenant):
    vs = single_eval_set(r, out, tenant) if MUTANT == 'CLASSIFY_SINGLE_EVAL' else value_set(r.expr, out, tenant)
    if r.action == 'allow':
        if U in vs and MUTANT != 'NO_CAPTURES':
            return 'c'
        return 'n' if T in vs else 'i'
    return 'n' if T in vs else 'i'


def atom_key(a):
    """Atom identity for the exact classifier: the positive atom's text and the polarity bit."""
    if a.form == 'isunk':
        return (a.attr, 'isunk')
    if a.form == 'bool':
        return (a.attr, 'bool', a.bounded)
    if a.form == 'cmp':
        op = '==' if a.op == '!=' else a.op
        return (a.attr, op, render_lit(a.lit))
    return (a.attr, 'in', tuple(sorted(map(str, a.resolved[1]))), a.resolved[2])


def exact_class(r, out, tenant):
    """Brute force over atoms (identical atoms share a value), for the soundness property."""
    occ = walk_atoms(r.expr, True, [])
    keys = []
    doms = {}
    for a, _ in occ:
        k = atom_key(a)
        s = seed(a, out, tenant)
        if a.form == 'cmp' and a.op == '!=' or a.form == 'isunk' and a.neg:
            s = {K3_NOT[x] for x in s}
        if k not in doms:
            keys.append(k)
            doms[k] = sorted(s)
    vals = set()

    def ev(e, asg):
        if isinstance(e, Atom):
            v = asg[atom_key(e)]
            if e.form == 'cmp' and e.op == '!=' or e.form == 'isunk' and e.neg:
                v = K3_NOT[v]
            return v
        if isinstance(e, Not):
            return K3_NOT[ev(e.child, asg)]
        tab = K3_AND if e.conn == 'and' else K3_OR
        acc = ev(e.children[0], asg)
        for c in e.children[1:]:
            acc = tab[(acc, ev(c, asg))]
        return acc

    def rec(i, asg):
        if i == len(keys):
            vals.add(ev(r.expr, asg))
            return
        for v in doms[keys[i]]:
            asg[keys[i]] = v
            rec(i + 1, asg)
    rec(0, {})
    if r.action == 'allow':
        return 'c' if U in vals else ('n' if T in vals else 'i')
    return 'n' if T in vals else 'i'


def ranges(ns):
    out = []
    ns = sorted(ns)
    i = 0
    while i < len(ns):
        j = i
        while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1:
            j += 1
        out.append(str(ns[i]) if i == j else '%d-%d' % (ns[i], ns[j]))
        i = j + 1
    return ','.join(out)


def classes_and_dependents(prog, out, tenant):
    if prog is None:
        return '-', None
    letters = []
    captures, disarmed, narrowed = [], [], []
    captured = False
    outp = set(out)
    if tenant != 'fresh':
        outp.add(TENANT)
    for r in prog.rules:
        if r.inert:
            letters.append('x')
            continue
        c = rule_class(r, out, tenant)
        letters.append(c)
        if r.action in ('deny', 'log') and captured:
            disarmed.append(r.n)
            continue
        if not (r.dep & outp):
            continue
        if c == 'c':
            captures.append(r.n)
            captured = True
        elif c == 'i':
            disarmed.append(r.n)
        else:
            narrowed.append(r.n)
    parts = []
    if captures:
        parts.append('rule%s %s allow captures' % ('s' if len(captures) > 1 else '', ranges(captures)))
    if disarmed:
        parts.append('rule%s %s disarmed' % ('s' if len(disarmed) > 1 else '', ranges(disarmed)))
    if narrowed:
        parts.append('rule%s %s narrowed' % ('s' if len(narrowed) > 1 else '', ranges(narrowed)))
    head = 'out=%s tenant=%s:' % (','.join(PLANES[p - 1] for p in sorted(out)) or '-', tenant)
    return ''.join(letters) or '-', head + ' ' + ('; '.join(parts) if parts else 'none')


# ---------------------------------------------------------------------------------------------------
# Reports (section 1.5, reported never refused)
# ---------------------------------------------------------------------------------------------------

def positive_atom(e):
    if isinstance(e, Atom) and e.form in ('bool', 'in') or (isinstance(e, Atom) and e.form == 'cmp' and e.op != '!='):
        return e
    return None


def flat_and(e):
    """A single atom or an and-chain of atoms (parentheses around a single atom are transparent)."""
    if isinstance(e, Atom):
        return [e]
    if isinstance(e, Chain) and e.conn == 'and' and all(isinstance(c, Atom) for c in e.children):
        return list(e.children)
    if isinstance(e, Chain) and e.conn == 'and':
        return [c if isinstance(c, Atom) else None for c in e.children]
    return None


def atom_values(a):
    """(class, values set, has_undet) of a positive == or in atom."""
    cls = attr_class(a.attr)
    if a.form == 'cmp':
        if a.lit[0] == 'undet':
            return cls, frozenset(), True
        return cls, frozenset([lit_index(a.lit)]), False
    return cls, a.resolved[1], a.resolved[2]


def subsumes(a1, a2):
    if a1.attr != a2.attr:
        return False
    if a1.form == 'bool' and a2.form == 'bool':
        return a1.attr != 'tenant_allow' or a1.bounded == a2.bounded
    if a1.form == 'cmp' and a1.op == '>=' and a1.attr == 'listed':
        return a2.form == 'cmp' and a2.op == '>=' and lit_index(a1.lit) <= lit_index(a2.lit)
    if a1.form == 'cmp' and a1.op == '==':
        return a2.form == 'cmp' and a2.op == '==' and render_lit(a1.lit) == render_lit(a2.lit)
    if a1.form == 'in':
        if a2.form == 'in':
            _, v1, u1 = atom_values(a1)
            _, v2, u2 = atom_values(a2)
            return v1 >= v2 and (u1 or not u2)
        if a2.form == 'cmp' and a2.op == '==':
            _, v1, u1 = atom_values(a1)
            if a2.lit[0] == 'undet':
                return u1
            return lit_index(a2.lit) in v1
    return False


def all_absent_value(r):
    """The rule on the all-fresh, all-absent record (every plane fresh, no range anywhere)."""
    def ev(e):
        if isinstance(e, Atom):
            if e.form == 'isunk':
                v = F
            else:
                v = definite(e, template_block(e.plane), 0)
            if e.form == 'cmp' and e.op == '!=' or e.form == 'isunk' and e.neg:
                v = K3_NOT[v]
            return v
        if isinstance(e, Not):
            return K3_NOT[ev(e.child)]
        tab = K3_AND if e.conn == 'and' else K3_OR
        acc = ev(e.children[0])
        for c in e.children[1:]:
            acc = tab[(acc, ev(c))]
        return acc
    return ev(r.expr)


def make_reports(cfg):
    reps = []
    for d in cfg.directives:
        if d.kind == 'set' and d.parsed.dups:
            reps.append('report set %s/@%s duplicate-member %s' % (d.context, d.parsed.name,
                                                                ','.join(d.parsed.dups)))
    progs = []
    if cfg.floor is not None:
        progs.append(cfg.floor)
    progs += sorted(cfg.programs.values(), key=lambda p: p.context)
    for p in progs:
        tag = '%s %s' % (p.kind, p.context)
        denies = [r.n for r in p.rules if r.action == 'deny']
        for i, r in enumerate(p.rules):
            if r.inert:
                planes = sorted(r.dep & {PLANE_ID[x] for x in cfg.absent})
                reps.append('report %s %d inert-at-config %s' % (tag, r.n, ','.join(PLANES[x - 1] for x in planes)))
                if r.action == 'allow':
                    later = [q.n for q in p.rules[i + 1:] if q.action == 'deny']
                    reps.append('report %s %d inert-allow-exposes %s' % (tag, r.n, ranges(later) or '-'))
            # shadowing: the earliest R1 only
            atoms2 = flat_and(r.expr) if not r.inert and r.action != 'log' else None
            if atoms2 is not None:
                pos2 = [x for x in atoms2 if x is not None and positive_atom(x)]
                for q in p.rules[:i]:
                    if q.action == 'log' or q.inert:
                        continue
                    atoms1 = flat_and(q.expr)
                    if atoms1 is None or any(x is None or not positive_atom(x) for x in atoms1):
                        continue
                    if all(any(subsumes(a1, a2) for a2 in pos2) for a1 in atoms1):
                        reps.append('report %s %d shadowed-by %d' % (tag, r.n, q.n))
                        break
            occ = walk_atoms(r.expr, True, [])
            for a, pol in occ:
                if a.form == 'in':
                    cls = attr_class(a.attr)
                    if cls in POSSIBLE:
                        n = len(a.resolved[1]) + (1 if a.resolved[2] and cls != 'level' else 0)
                        if cls == 'level':
                            n = len(a.resolved[1])
                        if n == POSSIBLE[cls]:
                            reps.append('report %s %d tautology %s' % (tag, r.n, a.attr))
                        reps.append('report %s %d coverage %s %d/%d' % (tag, r.n, a.attr, n, POSSIBLE[cls]))
                    if a.resolved[3] and a.resolved[0] == 'inline':
                        reps.append('report %s %d duplicate-member %s' % (tag, r.n, ','.join(a.resolved[3])))
            if r.action == 'allow':
                guards = set()
                if isinstance(r.expr, Chain) and r.expr.conn == 'and':
                    for c in r.expr.children:
                        if isinstance(c, Atom) and c.form == 'cmp' and c.op == '!=' and c.lit[0] == 'undet':
                            guards.add(c.attr)
                warned = []
                for a, pol in occ:
                    if a.attr not in SENTINEL_ATTRS or a.form not in ('cmp', 'in'):
                        continue
                    if a.form == 'cmp' and a.op not in ('==', '!='):
                        continue
                    eff = pol if not (a.form == 'cmp' and a.op == '!=') else (not pol)
                    if eff:
                        continue
                    _, _, hu = atom_values(a)
                    if hu or a.attr in guards:
                        continue
                    if a.attr not in warned:
                        warned.append(a.attr)
                for at in warned:
                    reps.append('report %s %d sentinel-negative %s' % (tag, r.n, at))
            if r.action in ('deny', 'log') and not r.inert and all_absent_value(r) == T:
                reps.append('report %s %d denies-all-absent' % (tag, r.n))
            if r.action == 'allow' and not r.inert:
                later_deny = any(q.action == 'deny' for q in p.rules[i + 1:])
                cap, unb = [], []
                for pl in sorted(r.dep):
                    if pl == TENANT:
                        st = [s for s in ('grace', 'lapsed', 'null') if U in value_set(r.expr, set(), s)]
                        if st:
                            cap.append(pl)
                        if U in value_set(r.expr, set(), 'lapsed'):
                            unb.append(pl)
                        if isunk_only(r, set(), 'null', pl):
                            if pl not in unb:
                                unb.append(pl)
                        continue
                    if U in value_set(r.expr, {pl}, 'fresh'):
                        cap.append(pl)
                    if isunk_only(r, {pl}, 'fresh', pl):
                        unb.append(pl)
                if cap and later_deny:
                    reps.append('report %s %d capturing-allow %s' % (
                        tag, r.n, ','.join(PLANES[x - 1] + ('(keyed)' if PLANES[x - 1] in KEYED else '') for x in cap)))
                if unb:
                    reps.append('report %s %d unbounded %s' % (tag, r.n, ','.join(PLANES[x - 1] for x in unb)))
                fa = flat_and(r.expr)
                if fa is not None and any(x is not None and x.form == 'bool' and x.attr == 'tenant_allow'
                                          and x.bounded for x in fa):
                    reps.append('report %s %d adds-nothing' % (tag, r.n))
    return reps


def isunk_only(r, out, tenant, pl):
    """T reachable, and not once every ISUNK on plane pl reads F instead of T."""
    vs = value_set(r.expr, out, tenant)
    if T not in vs:
        return False
    has = any(a.form == 'isunk' and a.plane == pl for a, _ in walk_atoms(r.expr, True, []))
    if not has:
        return False

    def vs2(e):
        if isinstance(e, Atom):
            if e.form == 'isunk' and e.plane == pl:
                s = {F}
                return {K3_NOT[x] for x in s} if e.neg else s
            return seed(e, out, tenant)
        if isinstance(e, Not):
            return {K3_NOT[x] for x in vs2(e.child)}
        tab = K3_AND if e.conn == 'and' else K3_OR
        acc = vs2(e.children[0])
        for c in e.children[1:]:
            b = vs2(c)
            acc = {tab[(x, y)] for x in acc for y in b}
        return acc
    return T not in vs2(r.expr)


# ---------------------------------------------------------------------------------------------------
# Records, the memo fill, the definite values (section 1.4, 2.7)
# ---------------------------------------------------------------------------------------------------

def template_block(plane):
    s = SCHEMA[plane]
    if s == 'routing':
        return ROUTING_TEMPLATE
    if s == 'member':
        return {'flags': 0, 'reason': 0}
    return {'sev': 0}


def normalise(plane, rec, clamps):
    """The fill: a hit is copied and clamped, no range writes the template unclamped (section 2.7)."""
    if rec is None:
        return template_block(plane)
    s = SCHEMA[plane]
    noclamp = MUTANT == 'NO_CLAMP'
    if s == 'routing':
        rov, rir, rep, fl = rec['rov'], rec['rir'], rec['asn_rep'], rec['flags']
        c = rec['country']
        cn = c if (c <= 999 and c in COUNTRY_KNOWN) else 0
        if clamps is not None:
            if rov > 3:
                clamps.add('rov')
            if rir > 5:
                clamps.add('rir')
            if rep > 4:
                clamps.add('asn_rep')
            if cn != c:
                clamps.add('country')
            if fl & ~0x07:
                clamps.add('routing-flags')
        if noclamp:
            return {'asn': rec['asn'], 'country': c, 'rov': rov, 'rir': rir, 'flags': fl, 'asn_rep': rep}
        return {'asn': rec['asn'], 'country': cn, 'rov': rov if rov <= 3 else 0, 'rir': rir if rir <= 5 else 0,
                'flags': fl & 0x07, 'asn_rep': rep if rep <= 4 else 0}
    if s == 'member':
        fl, reason = rec['flags'], rec['reason']
        m = MEMBER_MASK[plane]
        if clamps is not None:
            if fl & ~m:
                clamps.add('membership-flags')
            if reason > 2 and plane == 3:
                clamps.add('reason')
        if noclamp:
            return {'flags': fl, 'reason': reason}
        return {'flags': fl & m, 'reason': reason if (reason <= 2) else 0}
    if clamps is not None and (rec['sev'] & 0x0F) > 4:
        clamps.add('sev')
    return {'sev': rec['sev']}


def level_of(block, allow_inferred):
    sev = block['sev']
    if (sev & 0x80) and not allow_inferred:
        return 0
    lv = sev & 0x0F
    if MUTANT == 'NO_CLAMP':
        return lv
    return lv if lv <= 4 else 4


def field_value(a, block):
    f = VALUED[a.attr][2]
    return block[f]


def definite(a, block, allow_inferred):
    """The definite value of a non-ISUNK atom over a normalised block (before a != or `not`)."""
    if a.form == 'bool':
        if a.attr == 'inferred':
            return T if block['sev'] & 0x80 else F
        return T if block['flags'] & BOOLS[a.attr][1] else F
    cls = attr_class(a.attr)
    if cls == 'level':
        v = level_of(block, allow_inferred)
        if a.form == 'in':
            return T if v in a.resolved[1] else F
        lit = lit_index(a.lit)
        op = '==' if a.op == '!=' else a.op
        if op == '==':
            return T if v == lit else F
        if op == '>=':
            return T if v >= lit else F
        if op == '>':
            return T if v > lit else F
        if op == '<=':
            return T if v <= lit else F
        return T if v < lit else F
    v = field_value(a, block)
    if a.form == 'cmp':
        if MUTANT == 'SENTINEL_NE' and a.op == '!=' and a.lit[0] == 'undet':
            return F
        lit = undet_value(cls) if a.lit[0] == 'undet' else lit_index(a.lit)
        return T if v == lit else F
    vals, hu = a.resolved[1], a.resolved[2]
    if cls == 'asn':
        if not vals:
            return T if v == ASN_SENTINEL else F
        if v == ASN_SENTINEL:
            return T if (hu or MUTANT == 'SENTINEL_PADDING') else F
        return T if v in vals else F
    if v == undet_value(cls):
        return T if hu else F
    return T if v in vals else F


# ---------------------------------------------------------------------------------------------------
# The evaluator (section 3.2, 3.3) with the cost line (section 5.1)
# ---------------------------------------------------------------------------------------------------

class Request(object):
    __slots__ = ('floor_conf', 'ctx_conf', 'states', 'tenant', 'now', 'vu', 'addrs', 'keys', 'records',
                 'hh_eligible', 'acme', 'tstate')


def conf_of(raw):
    """we_ctx_conf_t's domain (D31): anything undefined reads as dry-run log, allow_inferred off."""
    if raw is None:
        return 2, 0
    mode, ai = raw
    if mode not in (1, 2, 3) or ai not in (0, 1):
        return 2, 0
    return mode, ai


def tenant_state(req):
    """The tenant state from the case's word AND its times: `fresh` needs valid_until 0 (no bound) or
    now <= valid_until, `stale` needs a non-zero valid_until below now (checked before the subtraction,
    so it cannot wrap), and a word the times contradict is a malformed case, refused rather than
    trusted. This is the evaluator's reading (we_eval_peek): a zero bound never lapses."""
    t = req.tenant
    if t in ('null', 'revoked'):
        return t
    if t not in ('fresh', 'stale'):
        raise ValueError('tenant state %r is not fresh, stale, null or revoked' % t)
    stale = req.vu != 0 and req.now > req.vu       # valid_until 0 is no bound (FORMAT.md), never stale
    if (t == 'stale') != stale:
        raise ValueError('tenant %s contradicts now %d and valid_until %d' % (t, req.now, req.vu))
    if not stale:
        return 'fresh'
    return 'grace' if req.now - req.vu <= GRACE_MS else 'lapsed'


class Eval(object):
    """One request: two memo slots (aliased when the keys are equal), the counters, the coverage."""

    def __init__(self, req, coverage):
        self.req = req
        self.cov = coverage
        self.alias = req.keys[0] == req.keys[1]
        self.memo = [{}, {}]
        self.lookups = [[0] * 8, [0] * 8]
        self.ops = [0, 0]
        self.jumps = [0, 0]
        self.probes = [0, 0]
        self.clamps = set()
        self.ts = req.tstate

    def slot(self, addr_idx):
        return 0 if (addr_idx == 0 or self.alias) else 1

    def readable(self, p):
        if p == TENANT:
            return self.ts in ('fresh', 'grace', 'lapsed')
        return self.req.states[p] == 'fresh'

    def fill(self, s, p):
        m = self.memo[s]
        if p in m and MUTANT != 'NO_MEMO_HIT':
            return m[p]
        if self.readable(p):
            self.lookups[s][p - 1] += 1
            rec = self.req.records[s][p] if not self.alias else self.req.records[0][p]
            b = normalise(p, rec, self.clamps)
        else:
            b = None
        m[p] = b
        return b

    def plane_state(self, p):
        if p == TENANT:
            return self.ts
        return 'fresh' if self.req.states[p] == 'fresh' else 'unknown'

    def isunk(self, p):
        if p == TENANT:
            return T if self.ts in ('grace', 'lapsed', 'null') else F
        return F if self.req.states[p] == 'fresh' else T

    def atom(self, a, s, ai, uniform=False):
        p = a.plane
        if p == TENANT:
            ts = self.ts
            if ts == 'revoked':
                return F
            if ts == 'null':
                return U
            b = self.fill(s, p)
            if ts == 'fresh':
                return definite(a, b, ai)
            bounded = a.bounded and not uniform
            if MUTANT == 'TENANT_BIT_IGNORED':
                bounded = True
            if bounded and MUTANT != 'TENANT_ATOM_U':
                return definite(a, b, ai) if ts == 'grace' else F
            return U
        if self.req.states[p] != 'fresh':
            return U
        b = self.fill(s, p)
        return definite(a, b, ai)

    def run_rule(self, r, s, pi, ai):
        ins = r.instrs
        stack = []
        pc = 0
        cov = self.cov
        while True:
            op, a, tgt = ins[pc]
            self.ops[pi] += 1
            if op == 'END':
                return stack[-1]
            if a is not None:
                if op == 'ISUNK':
                    v = self.isunk(a.plane)
                    if cov is not None:
                        kk = ('polarity', r.action, 'positive' if isunk_polarity(a, a.pol) else 'negative')
                        cov[kk] = cov.get(kk, 0) + 1
                else:
                    v = self.atom(a, s, ai)
                    if op == 'INSET_COUNTRY':
                        self.probes[pi] += 1
                    elif op == 'INSET_ASN':
                        self.probes[pi] += splus_levels(len(a.resolved[1]))
                if cov is not None:
                    k = ('plane-state', op, PLANES[a.plane - 1], self.plane_state(a.plane))
                    cov[k] = cov.get(k, 0) + 1
                stack.append(v)
            elif op == 'NOT':
                x = stack.pop()
                if cov is not None:
                    kk = ('op', 'NOT', x)
                    cov[kk] = cov.get(kk, 0) + 1
                stack.append(K3_NOT[x])
            elif op in ('AND', 'OR'):
                y = stack.pop()
                x = stack.pop()
                if cov is not None:
                    kk = ('op', op, x, y)
                    cov[kk] = cov.get(kk, 0) + 1
                stack.append((K3_AND if op == 'AND' else K3_OR)[(x, y)])
            else:
                top = stack[-1]
                if cov is not None:
                    kk = ('op', op, top)
                    cov[kk] = cov.get(kk, 0) + 1
                want = F if op == 'JF' else T
                take = top == want
                if MUTANT == 'SHORTCIRCUIT_U' and top == U:
                    take = True
                if MUTANT == 'NO_SHORTCIRCUIT':
                    take = False
                if take:
                    self.jumps[pi] += 1
                    pc = tgt
                    continue
            pc += 1

    def run_program(self, prog, conf, s, pi):
        """Returns (action, rule, reason) when a rule decides, else None; and the log bitmap."""
        logs = []
        if prog is None:
            return None, logs
        mode, ai = conf
        if mode == 1:
            return None, logs
        for r in prog.rules:
            if r.inert:
                if self.cov is not None:
                    self.cov[('inert', 'skipped')] = self.cov.get(('inert', 'skipped'), 0) + 1
                continue
            v = self.run_rule(r, s, pi, ai)
            if self.cov is not None:
                kk = ('action-final', r.action, v)
                self.cov[kk] = self.cov.get(kk, 0) + 1
            eff = r.action
            if eff == 'deny' and mode == 2:
                eff = 'log'
            if eff == 'deny' and v == T:
                return ('deny', r.n, '-'), logs
            if eff == 'log' and v == T:
                logs.append(r.n)
                if MUTANT == 'LOG_TERMINATES':
                    return ('allow', r.n, 'log-terminated'), logs
            if eff == 'allow':
                if v == T:
                    return ('allow', r.n, '-'), logs
                if v == U and MUTANT != 'ALLOW_U_FALLTHROUGH':
                    unk = [p for p in sorted(r.dep) if self.isunk(p) == T]
                    return ('allow', r.n, 'allow-by-unknown:%s' % (PLANES[unk[0] - 1] if unk else '-')), logs
        return None, logs


def hh_member(addr):
    starts, ends = HH_RANGES[addr.version]
    v = int(addr)
    i = bisect.bisect_right(starts, v) - 1
    return i >= 0 and v <= ends[i]


def load_hold_harmless():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, '..', 'hold-harmless.txt')
    nets = []
    with open(path) as f:                      # an unreadable list is an error, never an empty table
        for n, line in enumerate(f, 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            tok = line.split()[0]
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError as e:
                raise ValueError('%s:%d: %r is not an address or prefix (%s)' % (path, n, tok, e))
    if not nets:
        raise ValueError('%s holds no entries' % path)
    return nets


HH_NETS = load_hold_harmless()


def merge_ranges(nets):
    """The hold-harmless entries merged into sorted, non-overlapping [start, end] ranges per family,
    as gen-hold-harmless.py lays them out for the C (section 3.8)."""
    out = {4: ([], []), 6: ([], [])}
    for ver in (4, 6):
        rs = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == ver)
        starts, ends = out[ver]
        for a, b in rs:
            if starts and a <= ends[-1] + 1:
                ends[-1] = max(ends[-1], b)
            else:
                starts.append(a)
                ends.append(b)
    return out


HH_RANGES = merge_ranges(HH_NETS)


def canon(addr):
    """we_addr_canon: ::ffff:0:0/96 unmaps to IPv4; nothing else does (D24)."""
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def decide(cfg, prog_ctx, req, coverage):
    ev = Eval(req, coverage)
    floor_conf = conf_of(req.floor_conf)
    ctx_conf = conf_of(req.ctx_conf)
    reasons = []
    log_f, log_c = [], []
    verdict = None
    if coverage is not None:
        kk = ('slot', 'shared' if ev.alias else 'distinct')
        coverage[kk] = coverage.get(kk, 0) + 1
    floor_addr = req.keys[0]
    # Step 1's hold-harmless lookup is on the floor's address (POLICY.md section 3.2): a hit ends steps 2
    # to 3.5, and ends the request when the server judges the same address. Step 4 has no exemption of
    # its own: behind a proxy the server's realip trusts it judges the server's address by the rules.
    floor_hh = bool(req.hh_eligible and hh_member(floor_addr))
    if floor_hh and ev.alias:
        verdict = ('1', 'allow', '-', 0, 'allow-by-hold-harmless')
    elif req.acme:
        verdict = ('1', 'allow', '-', 0, 'allow-by-acme')
    if verdict is None:
        ts = ev.ts
        tb = None
        if not floor_hh:
            if ts in ('fresh', 'grace', 'lapsed'):
                tb = ev.fill(0, TENANT)
            if ts == 'revoked':
                reasons.append('tenant-revoked')
            if ts == 'fresh' and tb['flags'] & 0x01:
                verdict = ('2', 'allow', '-', 0, 'allow-by-tenant')
            if verdict is None:
                d, log_f = ev.run_program(cfg.floor, floor_conf, 0, 0)
                if d is not None:
                    verdict = ('3', d[0], 'floor', d[1], d[2])
            if verdict is None and ts == 'grace' and tb['flags'] & 0x01:
                verdict = ('3.5', 'allow', '-', 0, 'allow-by-tenant')
        if verdict is None:
            if coverage is not None and not ev.alias:
                # the two paths behind a proxy, each reaching step 4: a hold-harmless floor before a
                # distinct server address, and a hold-harmless server address judged by the rules
                for px, hit in (('floor-hold-harmless', floor_hh), ('server-hold-harmless-judged', hh_member(req.keys[1]))):
                    if hit:
                        coverage[('proxy', px)] = coverage.get(('proxy', px), 0) + 1
            s = ev.slot(1)
            d, log_c = ev.run_program(prog_ctx, ctx_conf, s, 1)
            if d is not None:
                verdict = ('4', d[0], 'ctx', d[1], d[2])
        if verdict is None:
            verdict = ('4', 'allow', '-', 0, '-')
    if coverage is not None:
        for c in ev.clamps:
            coverage[('clamp', c)] = coverage.get(('clamp', c), 0) + 1
    reason = [verdict[4]] if verdict[4] != '-' else []
    reason += reasons
    vline = 'verdict step=%s action=%s program=%s rule=%d reason=%s log_floor=%s log_ctx=%s' % (
        verdict[0], verdict[1], verdict[2], verdict[3], ','.join(reason) or '-',
        ','.join(map(str, log_f)) or '-', ','.join(map(str, log_c)) or '-')
    cline = 'cost ops=%d/%d jumps=%d/%d probes=%d/%d lookups=%s/%s' % (
        ev.ops[0], ev.ops[1], ev.jumps[0], ev.jumps[1], ev.probes[0], ev.probes[1],
        ','.join(map(str, ev.lookups[0])), ','.join(map(str, ev.lookups[1])))
    return vline, cline, ev


def invariant(cfg, prog_ctx, req):
    """X5: for every atom the programs read and every state of its plane, ISUNK(x) == (K3value(x) == U),
    K3value the uniform reading. Computed through the evaluator's own two paths on a probe request."""
    checked = failed = 0
    progs = [p for p in (cfg.floor, prog_ctx) if p is not None]
    for p in progs:
        for r in p.rules:
            for a in r.atoms:
                if a.form == 'isunk':
                    continue
                states = TENANT_STATES if a.plane == TENANT else ('fresh', 'stale')
                for st in states:
                    probe = Request()
                    probe.states = dict(req.states)
                    probe.tenant = req.tenant
                    probe.now, probe.vu = req.now, req.vu
                    probe.keys = req.keys
                    probe.records = req.records
                    probe.tstate = req.tstate
                    if a.plane == TENANT:
                        probe.tstate = st
                    else:
                        probe.states[a.plane] = st
                    ev = Eval(probe, None)
                    isu = ev.isunk(a.plane)
                    k3 = ev.atom(a, 0, 0, uniform=True)
                    checked += 1
                    if (isu == T) != (k3 == U):
                        failed += 1
    return 'invariant checked=%d failed=%d' % (checked, failed), failed


# ---------------------------------------------------------------------------------------------------
# The case file
# ---------------------------------------------------------------------------------------------------

def unescape(s):
    out = bytearray()
    i = 0
    b = s.encode('latin-1')
    while i < len(b):
        if b[i] == 0x5C and i + 3 < len(b) + 0 and b[i + 1] == 0x78:
            out.append(int(b[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def escape(b):
    return ''.join(chr(x) if 0x20 <= x <= 0x7E and x != 0x5C else '\\x%02X' % x for x in b)


REC_FIELDS = {'f1': ('sev',), 'member': ('flags', 'source', 'reason'),
              'routing': ('asn', 'country', 'rov', 'rir', 'flags', 'asn_rep')}


def parse_cases(path):
    """Yields ('program', id, leg, records, run, absent, cases) blocks."""
    prog = None
    case = None
    with open(path, encoding='latin-1') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            head, _, rest = line.partition(' ')
            if head == 'program':
                if prog is not None:
                    yield prog
                pid, _, leg = rest.partition(' ')
                prog = {'id': pid, 'leg': leg, 'dirs': [], 'run': 'http', 'absent': [], 'legacy': False,
                        'cases': []}
            elif head == 'dir':
                k, _, r2 = rest.partition(' ')
                c, _, a = r2.partition(' ')
                prog['dirs'].append((k, c, unescape(a)))
            elif head == 'run':
                prog['run'] = rest
            elif head == 'absent':
                prog['absent'] = rest.split()
            elif head == 'legacy':
                prog['legacy'] = True
            elif head == 'case':
                case = {'id': rest, 'conf': {}, 'planes': {}, 'tenant': ('fresh', 0, 1), 'addr': {},
                        'flags': (0, 0), 'rec': {}}
            elif head == 'conf':
                w, m, ai = rest.split()
                case['conf'][w] = (int(m), int(ai))
            elif head == 'plane':
                n, st = rest.split()
                if st not in ('fresh', 'stale', 'gen0'):
                    raise ValueError('plane state %r is not fresh, stale or gen0' % st)
                case['planes'][PLANE_ID[n]] = st
            elif head == 'tenant':
                st, now, vu = rest.split()
                case['tenant'] = (st, int(now), int(vu))
            elif head == 'addr':
                w, a = rest.split()
                case['addr'][w] = a
            elif head == 'flags':
                h, a = rest.split()
                case['flags'] = (int(h), int(a))
            elif head == 'rec':
                parts = rest.split()
                w, pl = parts[0], PLANE_ID[parts[1]]
                if parts[2] == 'none':
                    case['rec'][(w, pl)] = None
                else:
                    case['rec'][(w, pl)] = {k: int(v) for k, v in (x.split('=') for x in parts[2:])}
            elif head == 'sweep':
                w, pl, field, lo, hi = rest.split()
                case['sweep'] = (w, PLANE_ID[pl], field, int(lo), int(hi))
            elif head == 'end':
                sw = case.pop('sweep', None)
                if sw is None:
                    prog['cases'].append(case)
                else:
                    w, pl, field, lo, hi = sw
                    for v in range(lo, hi + 1):
                        c2 = dict(case, rec=dict(case['rec']), id='%s.%d' % (case['id'], v))
                        r = dict(c2['rec'].get((w, pl)) or {f: 0 for f in REC_FIELDS[SCHEMA[pl]]})
                        r[field] = v
                        c2['rec'][(w, pl)] = r
                        prog['cases'].append(c2)
                case = None
            else:
                raise SystemExit('policy_ref.py: %s: unknown line %r' % (path, line))
    if prog is not None:
        yield prog


def make_request(c):
    req = Request()
    req.floor_conf = c['conf'].get('floor')
    req.ctx_conf = c['conf'].get('ctx')
    req.states = {p: 'fresh' for p in range(1, 8)}
    for p, st in c['planes'].items():
        req.states[p] = 'fresh' if st == 'fresh' else 'stale'     # gen0 reads as stale does (D-ae)
    req.tenant, req.now, req.vu = c['tenant']
    req.tstate = tenant_state(req)
    fa = c['addr'].get('floor', '192.0.2.1')
    sa = c['addr'].get('server', fa)
    req.keys = (canon(fa), canon(sa))
    if int(req.keys[1]) == 0:
        # the unspecified address names no client: the server slot names the floor's (section 3.2)
        req.keys = (req.keys[0], req.keys[0])
    req.records = [{}, {}]
    for (w, p), rec in c['rec'].items():
        req.records[0 if w == 'floor' else 1][p] = rec
    for s in (0, 1):
        for p in range(1, 9):
            req.records[s].setdefault(p, None)
    req.hh_eligible, req.acme = c['flags']
    return req


def program_lines(cfg, prog_ctx):
    out = []
    for p in (cfg.floor, prog_ctx):
        if p is None:
            continue
        names = {}
        for r in p.rules:
            out.append('text %s %d %s' % (p.kind, r.n, r.text))
            for a in r.atoms:
                if a.form == 'in' and a.resolved[0] == 'named':
                    names[a.setname] = a.resolved[4]
        for nm in sorted(names):
            out.append('text %s set %s' % (p.kind, render_decl(names[nm])))
    out += cfg.reports
    return out


# ---------------------------------------------------------------------------------------------------
# --attrs: every attribute's value on the floor address's slot, as the lookup tool prints it. Derived from
# normalise() and the plane states here, from the evaluator's memo and its renderer in test_policy.
# ---------------------------------------------------------------------------------------------------

ATTR_ORDER = ('listed inferred tor_exit rpki_unreachable rpki_reason rpki asn asn_rep country registry_country '
              'rir registry_rir proxy vpn c2 bruteforce spam phishing scanner state_actor anycast moas narrowed '
              'tenant_allow tenant_deny').split()
COUNTRY_NAME = {v: k for k, v in COUNTRY.items()}


def attr_text(a, block):
    """An attribute's value over a normalised block, as the rule language writes it."""
    if a in BOOLS:
        if a == 'inferred':
            return 'true' if block['sev'] & 0x80 else 'false'
        return 'true' if block['flags'] & BOOLS[a][1] else 'false'
    _, cls, field = VALUED[a]
    v = block[field]
    if cls == 'level':
        return LEVELS[min(v & 0x0F, 4)]
    if cls == 'asn':
        return 'undetermined' if v == ASN_SENTINEL else str(v)
    if cls == 'country':
        return 'undetermined' if v == 0 else COUNTRY_NAME.get(v, str(v))
    return ENUMS[cls][v]


def attr_lines(absent, req):
    """`attr <name> <value>`, or `attr <name> UNKNOWN` with ` bounded=` on a present tenant plane's
    tenant_allow when the plane is stale (GRACE: the stale record's value; LAPSED: false) or refused."""
    out = []
    for a in ATTR_ORDER:
        p = BOOLS[a][0] if a in BOOLS else VALUED[a][0]
        rec = req.records[0][p]
        if PLANES[p - 1] in absent:
            out.append('attr %s UNKNOWN' % a)
        elif p == TENANT:
            ts = req.tstate
            if ts == 'fresh':
                out.append('attr %s %s' % (a, attr_text(a, normalise(p, rec, None))))
            elif ts == 'revoked':
                out.append('attr %s revoked' % a)
            elif a == 'tenant_allow':
                b = {'null': 'unknown', 'lapsed': 'false'}.get(ts) or attr_text(a, normalise(p, rec, None))
                out.append('attr %s UNKNOWN bounded=%s' % (a, b))
            else:
                out.append('attr %s UNKNOWN' % a)
        elif req.states[p] != 'fresh':
            out.append('attr %s UNKNOWN' % a)
        else:
            out.append('attr %s %s' % (a, attr_text(a, normalise(p, rec, None))))
    return out


def run_cases(path, out, cov_path=None, quiet=False, every=1, attrs=False):
    t0 = time.time()
    coverage = {}
    n_prog = n_case = n_ref = 0
    failures = 0
    legs = {}
    for k, blk in enumerate(parse_cases(path)):
        if every > 1 and blk['leg'] == 'generated' and k % every:
            continue
        n_prog += 1
        out.write('program %s\n' % blk['id'])
        try:
            cfg = compile_config(blk['dirs'], blk['absent'], blk['legacy'])
        except Refusal as e:
            n_ref += 1
            out.write(e.line_out() + '\n')
            out.write('msg %s\n' % e.message())
            tp = table_phrase(e.fragment)
            if tp is not None and blk['leg'] != 'exhaustive':
                cell = coverage.setdefault('refusals', {})
                cell[('phrase', tp)] = cell.get(('phrase', tp), 0) + 1
            continue
        prog_ctx = cfg.effective(blk['run'])
        legcov = coverage.setdefault(blk['leg'], {})
        for line in program_lines(cfg, prog_ctx):
            out.write(line + '\n')
            if line.startswith('report '):
                w = line.split()
                kind = w[2] if w[1] == 'set' else w[4]
                legcov[('report', kind)] = legcov.get(('report', kind), 0) + 1
        for c in blk['cases']:
            n_case += 1
            legs[blk['leg']] = legs.get(blk['leg'], 0) + 1
            req = make_request(c)
            if req.keys[0] == req.keys[1] and any(
                    c['rec'].get(('floor', p), None) != c['rec'].get(('server', p), None)
                    for p in range(1, 9) if ('server', p) in c['rec']):
                raise SystemExit('policy_ref.py: case %s: equal keys with different records' % c['id'])
            cov = coverage.setdefault(blk['leg'], {})
            if MUTANT == 'NO_EXHAUSTIVE' and blk['leg'] == 'exhaustive':
                cov = None
            vline, cline, ev = decide(cfg, prog_ctx, req, cov)
            iline, bad = invariant(cfg, prog_ctx, req)
            failures += 1 if bad else 0
            out_set = {p for p in range(1, 8) if req.states[p] != 'fresh'}
            cf, df = classes_and_dependents(cfg.floor, out_set, req.tstate)
            cc, dc = classes_and_dependents(prog_ctx, out_set, req.tstate)
            if cov is not None and 'x' in cf + cc:
                cov[('class', 'x')] = cov.get(('class', 'x'), 0) + 1
            out.write('case %s\n%s\n%s\n' % (c['id'], vline, cline))
            if attrs:
                out.write(''.join(line + '\n' for line in attr_lines(blk['absent'], req)))
            out.write('%s\nclasses floor=%s ctx=%s\n' % (iline, cf, cc))
            if df is not None:
                out.write('dependents floor %s\n' % df)
            if dc is not None:
                out.write('dependents ctx %s\n' % dc)
    if cov_path:
        write_coverage(cov_path, coverage)
    dt = time.time() - t0
    return n_prog, n_case, n_ref, failures, legs, dt, coverage


def write_coverage(path, coverage):
    with open(path, 'w') as f:
        for leg in sorted(coverage):
            for k in sorted(coverage[leg], key=lambda x: tuple(map(str, x))):
                f.write('%s\t%s\t%d\n' % (leg, ' '.join(map(str, k)), coverage[leg][k]))


def expected_cells():
    """The coverage matrix of section 5.2, the cells `make check` requires non-zero, per leg.

    The K3 cells must be populated by the exhaustive leg on its own (so a run without it leaves them
    empty, which is the WE_TEST_NO_EXHAUSTIVE control); the plane, polarity, slot and clamp cells by the
    generated leg. An AND whose left operand is F, and an OR whose left operand is T, never execute:
    the JF or JT before them has jumped, so those pairs are the jump's cells and not the connective's."""
    cells = []
    for x in (T, U):
        for y in TFU:
            cells.append(('exhaustive', ('op', 'AND', x, y)))
    for x in (F, U):
        for y in TFU:
            cells.append(('exhaustive', ('op', 'OR', x, y)))
    for o in ('NOT', 'JF', 'JT'):
        for x in TFU:
            cells.append(('exhaustive', ('op', o, x)))
    for act in ACTIONS:
        for v in TFU:
            cells.append(('exhaustive', ('action-final', act, v)))
    pairs = set()
    for a, (pl, _) in BOOLS.items():
        pairs.add(('BOOL', pl))
    for a, (pl, cls, _) in VALUED.items():
        if cls == 'level':
            pairs.add(('SEV', pl))                    # `listed in {...}` too (D-ac)
        elif cls == 'country':
            pairs.update({('EQ16', pl), ('INSET_COUNTRY', pl)})
        elif cls == 'asn':
            pairs.update({('EQ32', pl), ('INSET_ASN', pl)})
        else:
            pairs.update({('EQ8', pl), ('INSET_ENUM', pl)})
    for pl in range(1, 9):
        pairs.add(('ISUNK', pl))
    for op, pl in sorted(pairs):
        for st in (TENANT_STATES if pl == TENANT else ('fresh', 'unknown')):
            cells.append(('generated', ('plane-state', op, PLANES[pl - 1], st)))
    for act, pol in (('deny', 'negative'), ('log', 'positive'), ('log', 'negative'), ('allow', 'positive'),
                     ('allow', 'negative')):
        cells.append(('generated', ('polarity', act, pol)))
    for sl in ('shared', 'distinct'):
        cells.append(('generated', ('slot', sl)))
    # behind a proxy the server's realip trusts: a hold-harmless floor before a distinct server address,
    # and a hold-harmless server address step 4 judges by the rules
    for px in ('floor-hold-harmless', 'server-hold-harmless-judged'):
        cells.append(('generated', ('proxy', px)))
    for c in ('rov', 'rir', 'asn_rep', 'reason', 'country', 'routing-flags', 'membership-flags', 'sev'):
        cells.append(('generated', ('clamp', c)))
    # planes absent at configuration time: the inert path, its class and its two reports
    cells.append(('absent', ('inert', 'skipped')))
    cells.append(('absent', ('class', 'x')))
    cells.append(('absent', ('report', 'inert-at-config')))
    cells.append(('absent', ('report', 'inert-allow-exposes')))
    # every phrase of section 1.5's table is emitted by the generated cases, so a phrase that cannot fire
    # fails the build; the one structurally unreachable phrase is the verifier's alone (D-w)
    for ph in TABLE_PHRASES + DK_PHRASES:
        if ph not in UNREACHABLE_PHRASES:
            cells.append(('refusals', ('phrase', ph)))
    return cells


def read_coverage(path):
    cov = {}
    with open(path) as f:
        for line in f:
            leg, cell, n = line.rstrip('\n').split('\t')
            cov[(leg, cell)] = cov.get((leg, cell), 0) + int(n)
    return cov


def check_coverage(cov):
    """Returns (cells, zero cells). `cov` maps (leg, 'cell words') to a count."""
    zero = []
    cells = expected_cells()
    for leg, cell in cells:
        if cov.get((leg, ' '.join(map(str, cell))), 0) == 0:
            zero.append('%s: %s' % (leg, ' '.join(map(str, cell))))
    return cells, zero


# ---------------------------------------------------------------------------------------------------
# The corpus (testdata/policy/), N1
# ---------------------------------------------------------------------------------------------------

CORPUS_FLOOR_ACCEPT = 20
CORPUS_FLOOR_REFUSE = 50
# The six messages section 1.5 fixes word for word. The first five must EQUAL `what` or `fix`; the
# polarity sentence is matched by its clause, as the corpus README says. Every other message must be
# contained in `what` or `fix`; an absent or empty message never matches.
EXACT_FIXED = ('did you mean GB', RU_FIX, 'deny if not <condition>')


def message_matches(msg, what, fix):
    if not msg:
        return False
    if msg in EXACT_FIXED or msg.startswith('byte 0x') or ' takes ' in msg:
        return msg == what or msg == fix
    return msg in what or msg in fix


def read_expect(path):
    e = {}
    with open(path, 'rb') as f:
        for line in f.read().decode('ascii').split('\n'):
            if line:
                k, _, v = line.partition('\t')
                e[k] = v
    return e


def compare_refusal(e, exp):
    """N1's matching rule: every field equal; the message contained in what or fix, byte for byte."""
    bad = []
    got = {'layer': e.layer, 'kind': e.kind, 'context': e.context, 'rule': str(e.rule), 'line': str(e.line),
           'col': str(e.col), 'token': render_token(e.raw)}
    for k in ('layer', 'kind', 'context', 'rule', 'line', 'col', 'token'):
        if got[k] != exp.get(k, ''):
            bad.append('%s: expected %r, got %r' % (k, exp.get(k, ''), got[k]))
    msg = exp.get('message', '')
    if not message_matches(msg, e.what, e.fix):
        bad.append('message: %r does not match %r or %r' % (msg, e.what, e.fix))
    return bad


def run_corpus(root, verbose=True):
    acc = sorted(x for x in os.listdir(os.path.join(root, 'accept')) if x.endswith('.policy'))
    ref = sorted(x for x in os.listdir(os.path.join(root, 'refuse')) if x.endswith('.policy'))
    checks = fails = 0
    lines = []
    ok_acc = ok_ref = 0
    for name in acc:
        checks += 1
        with open(os.path.join(root, 'accept', name), 'rb') as f:
            recs = read_records(f.read())
        try:
            cfg = compile_config(recs)
        except Refusal as e:
            fails += 1
            lines.append('FAIL accept/%s refused: %s' % (name, e.line_out()))
            continue
        # R1 on every rule: the canonical text recompiles to itself
        rt = []
        for p in ([cfg.floor] if cfg.floor else []) + list(cfg.programs.values()):
            for r in p.rules:
                try:
                    r2 = recompile_canonical(cfg, p, r)
                except Refusal as e:
                    rt.append('rule %d: canonical %r refused: %s' % (r.n, r.text, e.what))
                    continue
                if render_rule(r2) != r.text or [x[0] for x in r2.instrs] != [x[0] for x in r.instrs]:
                    rt.append('rule %d: canonical %r does not round-trip' % (r.n, r.text))
        if rt:
            fails += 1
            lines.append('FAIL accept/%s: %s' % (name, '; '.join(rt)))
            continue
        ok_acc += 1
        lines.append('ok   accept/%s (%d rules%s)' % (name, sum(len(p.rules) for p in (
            [cfg.floor] if cfg.floor else []) + list(cfg.programs.values())),
            ', %d reports' % len(cfg.reports) if cfg.reports else ''))
    tsv = {}
    with open(os.path.join(root, 'refusals.tsv'), 'rb') as f:
        rows = f.read().decode('ascii').split('\n')
        hdr = rows[0].split('\t')
        for row in rows[1:]:
            if row:
                v = row.split('\t')
                tsv[v[0]] = dict(zip(hdr[1:], v[1:]))
    for name in ref:
        checks += 1
        exp_path = os.path.join(root, 'refuse', name[:-len('.policy')] + '.expect')
        if not os.path.exists(exp_path):
            fails += 1
            lines.append('FAIL refuse/%s has no .expect' % name)
            continue
        exp = read_expect(exp_path)
        if tsv.get(name) != exp:
            fails += 1
            lines.append('FAIL refuse/%s: refusals.tsv and the .expect disagree' % name)
            continue
        with open(os.path.join(root, 'refuse', name), 'rb') as f:
            recs = read_records(f.read())
        try:
            compile_config(recs)
        except Refusal as e:
            bad = compare_refusal(e, exp)
            if bad:
                fails += 1
                lines.append('FAIL refuse/%s: %s' % (name, '; '.join(bad)))
            else:
                ok_ref += 1
                lines.append('ok   refuse/%s %s' % (name, e.line_out()))
            continue
        fails += 1
        lines.append('FAIL refuse/%s compiled; expected %s' % (name, exp.get('message')))
    floor_ok = len(acc) >= CORPUS_FLOOR_ACCEPT and len(ref) >= CORPUS_FLOOR_REFUSE
    checks += 1
    if not floor_ok:
        fails += 1
        lines.append('FAIL the corpus holds %d accept and %d refuse files, under the seed floor of %d and %d'
                     % (len(acc), len(ref), CORPUS_FLOOR_ACCEPT, CORPUS_FLOOR_REFUSE))
    if verbose:
        for l in lines:
            print(l)
    print('corpus: %d of %d accept files compile, %d of %d refuse files refused with every .expect field equal'
          % (ok_acc, len(acc), ok_ref, len(ref)))
    return checks, fails


def recompile_canonical(cfg, p, r):
    """R1: the canonical text, compiled again with the same sets in scope (D32: no length check)."""
    arg = r.text.encode()
    toks = lex(arg, 'expr')
    r2 = Parser(toks, arg).rule()
    type_rule(r2)
    for a in r2.atoms:
        if a.form == 'in':
            if a.members is not None:
                vals, hu, dups = set_values(a.members, attr_class(a.attr))
                a.resolved = ('inline', vals, hu, dups, None)
            else:
                sd = None
                for anc in ancestors(p.context):
                    if (anc, a.setname) in cfg.decls:
                        sd = cfg.decls[(anc, a.setname)]
                        break
                a.resolved = ('named', sd.values, sd.has_undet, sd.dups, sd)
    compile_rule(r2)
    return r2


def expect_file(path):
    """Print a .policy file's refusal in the corpus's .expect format (key TAB value), or `accept`."""
    with open(path, 'rb') as f:
        recs = read_records(f.read())
    try:
        compile_config(recs)
    except Refusal as e:
        for k, v in (('layer', e.layer), ('kind', e.kind), ('context', e.context), ('rule', e.rule),
                     ('line', e.line), ('col', e.col), ('token', render_token(e.raw)), ('message', e.fragment)):
            print('%s\t%s' % (k, v))
        return 0
    print('accept')
    return 0


LAYERS = ('length', 'alphabet', 'lexing', 'parsing', 'typing', 'sets', 'program', 'polarity')


def run_seeds(root, floor, verbose=True):
    """X3: every seed compiles or is refused with a located refusal in one of section 1.5's layers; the
    case seeds evaluate; the C-only seeds are counted and named. Fails below the seed floor."""
    names = sorted(os.listdir(root))
    seeds = [n for n in names if n.endswith(('.policy', '.case', '.c-only'))]
    checks = fails = 0
    tally = {'accept': 0, 'refused': 0, 'cases': 0, 'c-only': 0}
    for n in seeds:
        path = os.path.join(root, n)
        checks += 1
        try:
            if n.endswith('.policy'):
                with open(path, 'rb') as f:
                    recs = read_records(f.read())
                try:
                    compile_config(recs)
                    tally['accept'] += 1
                    line = 'accept'
                except Refusal as e:
                    if e.layer not in LAYERS or e.line < 1 or e.col < 1 or e.kind is None:
                        raise AssertionError('an unlocated refusal: %s' % e.line_out())
                    tally['refused'] += 1
                    line = e.line_out()
            elif n.endswith('.case'):
                import io
                buf = io.StringIO()
                r = run_cases(path, buf, None)
                if r[3]:
                    raise AssertionError('%d invariant failures' % r[3])
                tally['cases'] += r[1]
                line = '%d cases' % r[1]
            else:
                tally['c-only'] += 1
                line = 'evaluated by the C harness only'
            if verbose:
                print('ok   seeds/%s: %s' % (n, line))
        except Exception as x:  # a crash of the oracle on a seed is the failure this replay exists to find
            fails += 1
            print('FAIL seeds/%s: %s: %s' % (n, type(x).__name__, x))
    checks += 1
    if len(seeds) < floor:
        fails += 1
        print('FAIL seeds: %d files, under the seed floor of %d' % (len(seeds), floor))
    print('seeds: %d files (floor %d): %d compile, %d refused with a located error, %d record cases, %d C only'
          % (len(seeds), floor, tally['accept'], tally['refused'], tally['cases'], tally['c-only']))
    return checks, fails


def conf_records(text):
    """The installer's policy.conf (decision 3's text) as directives at http: `#` to the end of a line is
    a comment of the CONFIGURATION file, removed before the language sees a byte (in the language `#` is
    refused); `whisper_edge_mode X;` is the mode; every other non-empty line is one policy rule."""
    recs = []
    for line in text.split(b'\n'):
        line = line.split(b'#', 1)[0].strip()
        if not line:
            continue
        if line.startswith(b'whisper_edge_mode'):
            recs.append(('mode', 'http', line[len(b'whisper_edge_mode'):].strip().rstrip(b';').strip()))
        else:
            recs.append(('policy', 'http', line))
    return recs


def run_default_conf(path, corpus_root):
    """The default policy compiles, and to exactly the program of the corpus's accept/01."""
    checks = fails = 0
    with open(path, 'rb') as f:
        cfg = compile_config(conf_records(f.read()))
    with open(os.path.join(corpus_root, 'accept', '01-default-policy.policy'), 'rb') as f:
        ref = compile_config(read_records(f.read()))
    mine = [r.text for r in cfg.programs['http'].rules]
    theirs = [r.text for r in ref.programs['http/server:a'].rules]
    for name, cond in (('default.conf compiles to four rules', len(mine) == 4),
                       ('default.conf is the program of accept/01, rule for rule', mine == theirs),
                       ('default.conf sets mode deny', cfg.modes.get('http') == 3)):
        checks += 1
        if not cond:
            fails += 1
            print('FAIL default.conf: ' + name)
    print('default.conf: %s' % ' | '.join(mine))
    return checks, fails


def compile_file(path):
    with open(path, 'rb') as f:
        recs = read_records(f.read())
    try:
        cfg = compile_config(recs)
    except Refusal as e:
        print(e.line_out())
        print('msg ' + e.message())
        return 1
    for p in ([cfg.floor] if cfg.floor else []) + [cfg.programs[k] for k in sorted(cfg.programs)]:
        print('program %s %s' % (p.kind, p.context))
        for r in p.rules:
            print('  %3d  %s' % (r.n, r.text))
            print('       %s' % ' '.join(
                (op if tgt is None else '%s->%d' % (op, tgt)) for op, a, tgt in r.instrs))
    for line in cfg.reports:
        print(line)
    return 0


# ---------------------------------------------------------------------------------------------------
# The oracle's own checks (--self-test), each with a negative control
# ---------------------------------------------------------------------------------------------------

def pair_k3():
    """K3 as the (true, false) bit pair POLICY.md specifies for the C, to hold the value tables to."""
    enc = {T: (1, 0), F: (0, 1), U: (0, 0)}
    dec = {v: k for k, v in enc.items()}
    nt = {x: dec[(enc[x][1], enc[x][0])] for x in TFU}
    an = {(x, y): dec[(enc[x][0] & enc[y][0], enc[x][1] | enc[y][1])] for x in TFU for y in TFU}
    orr = {(x, y): dec[(enc[x][0] | enc[y][0], enc[x][1] & enc[y][1])] for x in TFU for y in TFU}
    return nt, an, orr


def country_header_codes():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, 'we_country_table.h')) as f:
        text = f.read()
    body = text.split('we_country_known_table[125] = {', 1)[1].split('};', 1)[0]
    bits = [int(x, 16) for x in body.replace(',', ' ').split()]
    return {c for c in range(1000) if (bits[c >> 3] >> (c & 7)) & 1}


def compile_rules(lines, absent=()):
    recs = []
    for l in lines:
        kind, ctx, arg = l.split(' ', 2)
        recs.append((kind, ctx, arg.encode()))
    return compile_config(recs, absent)


def mk_req(states=None, tenant=('fresh', 10, 20), floor=None, server=None, recs=None, conf=None,
           fconf=None, hh=0, acme=0):
    c = {'conf': {}, 'planes': {}, 'tenant': tenant, 'addr': {}, 'flags': (hh, acme), 'rec': {}}
    if conf is not None:
        c['conf']['ctx'] = conf
    if fconf is not None:
        c['conf']['floor'] = fconf
    for name, st in (states or {}).items():
        c['planes'][PLANE_ID[name]] = st
    c['addr']['floor'] = floor or '192.0.2.10'
    c['addr']['server'] = server or c['addr']['floor']
    for (w, pl), r in (recs or {}).items():
        c['rec'][(w, PLANE_ID[pl])] = r
        if c['addr']['server'] == c['addr']['floor'] and w == 'floor':
            c['rec'][('server', PLANE_ID[pl])] = r
    return make_request(c)


def verdict_of(lines, req, ctx='http/server:a', absent=()):
    cfg = compile_rules(lines, absent)
    v, c, ev = decide(cfg, cfg.effective(ctx), req, None)
    return v, c, cfg


def self_test(verbose=False):
    checks = [0]
    fails = []

    def ok(cond, name):
        checks[0] += 1
        if not cond:
            fails.append(name)
        elif verbose:
            print('ok   ' + name)

    # K1, K2: the value tables against the bit-pair encoding, and the weak-Kleene control differs
    pn, pa, po = pair_k3()
    ok(pn == K3_NOT and pa == K3_AND and po == K3_OR, 'K1: the K3 value tables equal the (true, false) pair encoding')
    wn, wa, wo = k3_tables('K3_WEAK')
    ok(wa[(U, F)] == U and K3_AND[(U, F)] == F and wa[(T, F)] == F,
       'K2 control: weak Kleene reads U and F as U (the defect), and T and F as F (the mutant is exact)')
    bn, _, _ = k3_tables('BOOL_NOT')
    ok(bn[U] != K3_NOT[U], 'K1 control: boolean not reads not U as T and differs from K3')
    ok(K3_AND[(U, T)] == U and K3_OR[(U, T)] == T and K3_OR[(U, F)] == U and K3_NOT[K3_NOT[U]] == U,
       'K2: U and T = U, U or T = T, U or F = U, not not U = U')

    # the country table against the C reader's bitmap, with a perturbed table as the control
    hdr = country_header_codes()
    ok(set(COUNTRY.values()) == hdr, 'the ISO alpha-2 table carries exactly the numeric codes of we_country_table.h')
    ok((set(COUNTRY.values()) - {528}) != hdr, 'control: the same comparison fails with one code removed')

    # N2: every byte value at three positions of a rule
    base = b'deny if tor_exit'
    for pos in (0, 7, len(base)):
        bad = 0
        for b in range(256):
            arg = base[:pos] + bytes([b]) + base[pos:]
            try:
                check_length_alphabet(arg)
                lex(arg, 'expr')
                outcome = 'pass'
            except Refusal as e:
                outcome = e.layer
                if b not in ALPHABET and (e.layer != 'alphabet' or e.off != pos
                                          or e.what != 'byte 0x%02X is not allowed' % b):
                    bad += 1
                if b in ALPHABET and e.layer == 'alphabet':
                    bad += 1
                if '\\x' not in render_token(bytes([b])) and (b < 0x20 or b > 0x7E or b in (0x22, 0x5C)):
                    bad += 1
            if b not in ALPHABET and outcome == 'pass':
                bad += 1
        ok(bad == 0, 'N2: every byte 0x00..0xFF at offset %d refused or lexed by the alphabet rule' % pos)
    ok(render_token(b'a\r\nb"\\') == 'a\\x0D\\x0Ab\\x22\\x5C', 'N2: CR, LF, quote and backslash render as \\xHH')

    # P3: the one-token forms
    for text, want in (('deny if country == IN', 356), ('deny if asn == As64496', 64496),
                       ('deny if asn == 0', 0), ('deny if asn == as0', 0),
                       ('deny if rpki == notfound', 3), ('deny if rpki == not_found', 3)):
        r = compile_text_rule(text)
        ok(lit_index(r.atoms[0].lit) == want, 'P3: %s is one token with value %d' % (text, want))

    # N7: the refusal order
    def refusal_of(lines):
        try:
            compile_rules(lines)
        except Refusal as e:
            return e
        return None
    e = refusal_of(['policy http/server:a deny if rpki == XX'])
    ok(e is not None and e.layer == 'typing', 'N7: rpki == XX is a typing refusal')
    e = refusal_of(['policy http/server:a deny if country in { NL XX }'])
    ok(e is not None and e.layer == 'lexing', 'N7: country in { NL XX } is a lexing refusal')
    e = refusal_of(['policy http/server:a deny if tor_exit garbage DENY'])
    ok(e is not None and e.layer == 'lexing', 'N7: a lexing fault after a parsing fault is reported first')
    e = refusal_of(['policy http/server:a deny if rpki == deny'])
    ok(e is not None and e.layer == 'parsing' and e.fragment == 'an unknown attribute or word',
       'a lower-case keyword where a literal belongs is an unknown word, not an upper-case spelling')
    e = refusal_of(['policy http/server:a deny if rpki == Valid'])
    ok(e is not None and e.layer == 'lexing' and e.fragment == 'an upper-case keyword or literal',
       'Valid is an upper-case literal')
    e = refusal_of(['policy http/server:a deny if asn in @late', 'set http/server:a @late 64496'])
    ok(e is None, 'N7: a set declared after its use resolves')

    # N4 and its controls
    for text, refused in (('deny if tor_exit is unknown', True), ('log if tor_exit is unknown', False),
                          ('log if tor_exit is not unknown', False), ('deny if not tor_exit is unknown', False)):
        e = refusal_of(['policy http/server:a ' + text])
        ok((e is not None and e.layer == 'polarity') == refused, 'N4: %s %s' % (text, 'refused' if refused else 'accepted'))
    design = ['policy http/server:a allow if tor_exit is not unknown and not tor_exit',
           'policy http/server:a deny if listed >= low']
    ok(refusal_of(design) is not None and refusal_of(design[:1]) is None,
       'N4: the design example is refused with the later deny and accepted without it')
    set_mutant('POLARITY_NO_ALLOW')
    ok(refusal_of(design) is None, 'N4 control: WE_TEST_POLARITY_NO_ALLOW accepts the design example')
    set_mutant('ISNOTUNK_POSITIVE')
    ok(refusal_of(design) is None, 'N4 control: WE_TEST_ISNOTUNK_POSITIVE accepts the design example')
    set_mutant(None)

    # K3, K4, K5, F1 through the evaluator
    v, c, _ = verdict_of(['policy http/server:a allow if tor_exit and c2',
                          'policy http/server:a deny if listed >= low'],
                         mk_req({'tor': 'stale'}, recs={('floor', 'reputation'): {'sev': 1}}, conf=(3, 0)),
                         'http/server:a')
    ok('action=deny' in v, 'K2: U and F is F, so the allow falls through and the deny fires')
    v, c, _ = verdict_of(['policy http/server:a allow if tor_exit or c2',
                          'policy http/server:a deny if listed >= low'],
                         mk_req({'tor': 'stale'}, recs={('floor', 'reputation'): {'sev': 1}}, conf=(3, 0)),
                         'http/server:a')
    ok('reason=allow-by-unknown:tor' in v and 'rule=1' in v, 'K4: an allow at U ends evaluation, allow-by-unknown, the plane named')
    set_mutant('ALLOW_U_FALLTHROUGH')
    v2, _, _ = verdict_of(['policy http/server:a allow if tor_exit or c2',
                           'policy http/server:a deny if listed >= low'],
                          mk_req({'tor': 'stale'}, recs={('floor', 'reputation'): {'sev': 1}}, conf=(3, 0)),
                          'http/server:a')
    set_mutant(None)
    ok('action=deny' in v2, 'K4 control: WE_TEST_ALLOW_U_FALLTHROUGH lets the deny fire')
    v, c, _ = verdict_of(['policy http/server:a deny if tor_exit and c2'],
                         mk_req({'tor': 'stale'}, recs={('floor', 'threat'): {'flags': 0, 'source': 0, 'reason': 0}}))
    ok('jumps=0/0' in c, 'K3: U and F does not jump on the U')
    v, c, _ = verdict_of(['policy http/server:a log if tor_exit', 'policy http/server:a deny if c2'],
                         mk_req(recs={('floor', 'tor'): {'flags': 1, 'source': 0, 'reason': 0},
                                      ('floor', 'threat'): {'flags': 1, 'source': 0, 'reason': 0}}, conf=(3, 0)))
    ok('action=deny' in v and 'log_ctx=1' in v, 'F1: log then deny: the log fires and continues, the deny decides')
    set_mutant('LOG_TERMINATES')
    v2, _, _ = verdict_of(['policy http/server:a log if tor_exit', 'policy http/server:a deny if c2'],
                          mk_req(recs={('floor', 'tor'): {'flags': 1, 'source': 0, 'reason': 0},
                                       ('floor', 'threat'): {'flags': 1, 'source': 0, 'reason': 0}}, conf=(3, 0)))
    set_mutant(None)
    ok('action=deny' not in v2, 'F1 control: WE_TEST_LOG_TERMINATES loses the deny')

    # F2: mode log downgrades, mode off evaluates nothing in step 4 while the floor runs
    lines = ['floor http deny if c2', 'policy http/server:a deny if tor_exit']
    recs = {('floor', 'tor'): {'flags': 1, 'source': 0, 'reason': 0}}
    v, c, _ = verdict_of(lines, mk_req(recs=recs, conf=(2, 0), fconf=(3, 0)))
    ok('action=allow' in v and 'log_ctx=1' in v, 'F2: mode log downgrades the deny to a log')
    v, c, _ = verdict_of(lines, mk_req(recs=recs, conf=(1, 0), fconf=(3, 0)))
    ok(c.startswith('cost ops=2/0'), 'F2: mode off: step 4 executes nothing while the floor executed')
    v, c, _ = verdict_of(lines, mk_req(recs=recs, conf=(7, 0), fconf=(3, 0)))
    ok('action=allow' in v and 'log_ctx=1' in v, 'D6: mode 7 reads as dry-run log')
    v, c, _ = verdict_of(lines, mk_req(recs=recs, conf=(0, 0), fconf=(3, 0)))
    ok('action=allow' in v and 'log_ctx=1' in v, 'D6: a zeroed conf reads as dry-run log')

    # P2 / SENTINEL_NE: != undetermined is not TRUE at the sentinel
    v, _, _ = verdict_of(['policy http/server:a deny if country != undetermined'], mk_req(conf=(3, 0)))
    ok('action=allow' in v, 'P2: country != undetermined is FALSE at the sentinel (no range)')
    v, _, _ = verdict_of(['policy http/server:a deny if country != NL'], mk_req(conf=(3, 0)))
    ok('action=deny' in v, 'P2: country != NL is TRUE at the sentinel')

    # M4: clamps; a record's rov 4 reads undetermined while no range reads unrouted
    rrec = {'asn': 64496, 'country': 528, 'rov': 4, 'rir': 9, 'flags': 0xFF, 'asn_rep': 200}
    v, _, _ = verdict_of(['policy http/server:a deny if rpki == undetermined and rir == undetermined'],
                         mk_req(recs={('floor', 'routing'): rrec}, conf=(3, 0)))
    ok('action=deny' in v, 'M4: rov 4 and rir 9 in a record clamp to undetermined')
    v, _, _ = verdict_of(['policy http/server:a deny if rpki == unrouted'], mk_req(conf=(3, 0)))
    ok('action=deny' in v, 'M4: no range writes the template unclamped: rpki == unrouted')
    v, _, _ = verdict_of(['policy http/server:a deny if rpki == unrouted'],
                         mk_req(recs={('floor', 'routing'): rrec}, conf=(3, 0)))
    ok('action=allow' in v, 'M4: the record with rov 4 is not unrouted')
    for nib in range(16):
        for inf in (0, 1):
            for thr in range(1, 5):
                sev = nib | (0x80 if inf else 0) | 0x30
                v, _, _ = verdict_of(['policy http/server:a deny if listed >= %s' % LEVELS[thr]],
                                     mk_req(recs={('floor', 'reputation'): {'sev': sev}}, conf=(3, 0)))
                want = (nib != 0 and not inf and nib >= thr)
                ok(('action=deny' in v) == want, 'G1: sev 0x%02X threshold %d agrees with we_should_deny' % (sev, thr))

    # S2: the ASN set at the sentinel
    for hu, want in ((False, 'allow'), (True, 'deny')):
        members = '64496 64497' + (' undetermined' if hu else '')
        v, _, _ = verdict_of(['policy http/server:a deny if asn in { %s }' % members], mk_req(conf=(3, 0)))
        ok(('action=' + want) in v, 'S2: an unrouted address against a set with has_undetermined %d' % hu)
    set_mutant('SENTINEL_PADDING')
    v, _, _ = verdict_of(['policy http/server:a deny if asn in { 64496 64497 }'], mk_req(conf=(3, 0)))
    set_mutant(None)
    ok('action=deny' in v, 'S2 control: WE_TEST_SENTINEL_PADDING admits the unrouted address')
    r = compile_text_rule('deny if asn in { undetermined }')
    r.atoms[0].resolved = ('inline', frozenset(), True, [], None)
    compile_rule(r)
    ok(r.instrs[0][0] == 'EQ32', 'S2: an ASN set with no numeric member compiles to EQ32 against the sentinel')
    v, _, _ = verdict_of(['policy http/server:a deny if asn in { 4294967294 }'],
                         mk_req(recs={('floor', 'routing'): dict(rrec, asn=4294967294)}, conf=(3, 0)))
    ok('action=deny' in v, 'S2: AS4294967294 is a member of its own set')

    # D2: the classifier rows
    def cls(text, out, tenant='fresh', extra=()):
        cfg = compile_rules(list(extra) + ['policy http/server:a ' + text])
        r = cfg.programs['http/server:a'].rules[-1]
        return rule_class(r, {PLANE_ID[x] for x in out}, tenant), exact_class(r, {PLANE_ID[x] for x in out}, tenant)
    ok(cls('log if tor_exit is unknown', ['tor'])[0] == 'n', 'D2: log if tor_exit is unknown is narrowed under tor')
    ok(cls('deny if tor_exit or c2', ['tor'])[0] == 'n' and cls('deny if tor_exit or c2', ['tor', 'threat'])[0] == 'i',
       'D2: deny if tor_exit or c2 is narrowed under tor, inert under tor and threat')
    partners = ['set http/server:a @partners 64496 64497']
    ok(cls('allow if tor_exit or asn in @partners', ['tor'], extra=partners)[0] == 'c',
       'D2: allow if tor_exit or asn in @partners captures under tor')
    c1 = cls('deny if (asn == 1 and not asn == 1) or tor_exit', [])
    ok(c1 == ('n', 'n'), 'D2: the correlated rule, nothing out: narrowed both ways')
    c1 = cls('deny if (asn == 1 and not asn == 1) or tor_exit', ['tor'])
    ok(c1 == ('n', 'i'), 'D2: the correlated rule under tor: narrowed per occurrence, inert per atom')
    for st, want in (('fresh', 'n'), ('grace', 'n'), ('lapsed', 'i'), ('null', 'c')):
        ok(cls('allow if tenant_allow', [], st)[0] == want, 'D2: the bounded allow under %s is %s' % (st, want))
    ok(cls('deny if not tenant_allow', [], 'lapsed')[0] == 'i', 'D2: deny if not tenant_allow under LAPSED is inert')
    ok(cls('allow if not tenant_deny', [], 'grace')[0] == 'c', 'D2: allow if not tenant_deny captures under GRACE')
    set_mutant('CLASSIFY_ISUNK_U')
    ok(cls('log if tor_exit is unknown', ['tor'])[0] == 'i', 'D2 control: WE_TEST_CLASSIFY_ISUNK_U classes the log rule inert')
    set_mutant('CLASSIFY_SINGLE_EVAL')
    ok(cls('allow if tor_exit or asn in @partners', ['tor'], extra=partners)[0] == 'n',
       'D2 control: WE_TEST_CLASSIFY_SINGLE_EVAL classes the or allow narrowed')
    set_mutant(None)

    # F4: the tenant rules, per state, on a listed address
    def tenant_case(rules, st, listed=True, sev=0):
        now = 10 ** 12
        vu = {'fresh': now + 1, 'grace': now - GRACE_MS, 'lapsed': now - GRACE_MS - 1,
              'null': 0, 'revoked': 0}[st]
        tst = 'stale' if st in ('grace', 'lapsed') else st
        recs = {('floor', 'tenant'): {'flags': 1 if listed else 0, 'source': 0, 'reason': 0},
                ('floor', 'reputation'): {'sev': sev}}
        req = mk_req(tenant=(tst, now, vu), recs=recs, conf=(3, 0))
        return verdict_of(['policy http/server:a ' + x for x in rules], req)[0]
    for st in TENANT_STATES:
        v = tenant_case(['allow if tenant_allow', 'deny if listed >= none'], st)
        want = {'fresh': 'step=2', 'grace': 'step=3.5', 'lapsed': 'action=deny', 'null': 'allow-by-unknown',
                'revoked': 'action=deny'}[st]
        ok(want in v, 'F4: allow if tenant_allow above a deny, %s: %s' % (st, want))
        v = tenant_case(['deny if not tenant_allow'], st, listed=False)
        ok(('action=deny' in v) == (st in ('fresh', 'revoked')),
           'F4: deny if not tenant_allow on an unlisted address fires only in FRESH and REVOKED (%s)' % st)
    ok('step=3.5' in tenant_case(['deny if listed >= none'], 'grace') and
       'action=deny' in tenant_case(['deny if listed >= none'], 'lapsed'),
       'F4: the stale tenant allow is inclusive at valid_until + 48 h and gone 1 ms later')
    set_mutant('TENANT_BIT_IGNORED')
    v = tenant_case(['deny if not tenant_allow'], 'lapsed', listed=False)
    set_mutant(None)
    ok('action=deny' in v, 'F4 control: WE_TEST_TENANT_BIT_IGNORED denies at lapse + 1 ms')

    # M1: lookups, equal keys aliased, distinct keys summed, ::ffff: unmapped
    lines2 = ['floor http log if listed >= low or tor_exit', 'policy http/server:a log if tor_exit or rpki == valid']
    for f, s, want in (('192.0.2.7', '::ffff:192.0.2.7', 'lookups=1,1,0,1,0,0,0,1/0,0,0,0,0,0,0,0'),
                       ('192.0.2.7', '192.0.2.8', 'lookups=1,1,0,0,0,0,0,1/0,1,0,1,0,0,0,0'),
                       ('::1', '0.0.0.1', 'lookups=1,1,0,0,0,0,0,1/0,1,0,1,0,0,0,0')):
        v, c, _ = verdict_of(lines2, mk_req(floor=f, server=s, conf=(3, 0), fconf=(3, 0)))
        ok(c.endswith(want), 'M1: %s and %s: %s' % (f, s, want))
    set_mutant('NO_MEMO_HIT')
    v, c, _ = verdict_of(lines2, mk_req(floor='192.0.2.7', server='192.0.2.7', conf=(3, 0), fconf=(3, 0)))
    set_mutant(None)
    ok(not c.endswith('lookups=1,1,0,1,0,0,0,1/0,0,0,0,0,0,0,0'), 'M1 control: WE_TEST_NO_MEMO_HIT looks up twice')

    # F3: fixed order
    ok(len(HH_NETS) > 0, 'F3: the hold-harmless list loaded')
    hh = str(next(iter(HH_NETS))[0])
    if True:
        v, _, _ = verdict_of(['floor http deny if listed >= none'], mk_req(floor=hh, hh=1, fconf=(3, 0)))
        ok('allow-by-hold-harmless' in v, 'F3: a hold-harmless address with the bit set is exempt')
        v, _, _ = verdict_of(['floor http deny if listed >= none'], mk_req(floor=hh, hh=0, fconf=(3, 0)))
        ok('action=deny' in v, 'F3: the same address with the bit clear is denied')
    v, _, _ = verdict_of(['floor http deny if listed >= none'], mk_req(acme=1, fconf=(3, 0)))
    ok('allow-by-acme' in v, 'F3: ACME under a deny')

    # N8 and the reports
    cfg = compile_rules(['policy http/server:a deny if listed >= none', 'policy http/server:a deny if listed < low',
                         'policy http/server:a deny if not tor_exit',
                         'policy http/server:a deny if not country in { NL }',
                         'policy http/server:a deny if tor_exit'])
    got = sorted(int(x.split()[3]) for x in cfg.reports if x.endswith('denies-all-absent'))
    ok(got == [1, 2, 3, 4], 'N8: the all-absent warning on the first four rules and not the fifth')
    cfg = compile_rules(['policy http/server:a allow if asn_rep != highly_suspicious',
                         'policy http/server:a allow if not country in { NL }',
                         'policy http/server:a allow if not (country == NL or country == BE)',
                         'policy http/server:a allow if asn_rep == reputable',
                         'policy http/server:a deny if asn_rep != reputable',
                         'policy http/server:a allow if asn_rep != reputable and asn_rep != undetermined'])
    got = sorted(int(x.split()[3]) for x in cfg.reports if ' sentinel-negative ' in x)
    ok(got == [1, 2, 3], 'N5: the sentinel warning on the three negative forms in an allow, not elsewhere')
    cfg = compile_rules(['policy http/server:a deny if listed >= high', 'policy http/server:a deny if listed >= critical',
                         'policy http/server:a deny if rpki in { valid invalid not-found unrouted undetermined }'])
    ok(any(x.endswith('2 shadowed-by 1') for x in cfg.reports) and any(' tautology rpki' in x for x in cfg.reports),
       'D2: the shadowing and the tautology POLICY.md names are reported')
    cfg = compile_rules(['policy http/server:a allow if tenant_allow is unknown',
                         'policy http/server:a allow if not tenant_deny',
                         'policy http/server:a allow if tenant_allow',
                         'policy http/server:a deny if listed >= low'])
    rep = ' | '.join(cfg.reports)
    ok('1 unbounded tenant' in rep and '2 unbounded tenant' in rep and '3 adds-nothing' in rep
       and '2 capturing-allow tenant(keyed)' in rep, 'F4: the unbounded, capturing and adds-nothing reports')

    # R1 / N3: the unspaced 2,048-byte argument round-trips though its canonical text is longer
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, 'testdata', 'policy', 'accept', '17-argument-2048-unspaced.policy'), 'rb') as f:
        cfg = compile_config(read_records(f.read()))
    r = cfg.programs['http/server:a'].rules[0]
    ok(len(r.text) > 2048 and render_rule(recompile_canonical(cfg, cfg.programs['http/server:a'], r)) == r.text,
       'N3: the 2,048-byte unspaced argument re-parses although its canonical text is %d bytes' % len(r.text))

    # D-x: with interleaved contexts the polarity fault reported is the first in FILE order
    e = refusal_of(['policy http/server:a deny if c2', 'policy http/server:b deny if c2',
                    'policy http/server:a deny if tor_exit is unknown',
                    'policy http/server:b deny if proxy is unknown'])
    ok(e is not None and e.context == 'http/server:a' and e.rule == 2,
       'D-x: the earlier polarity fault in the file wins across contexts')
    e = refusal_of(['policy http/server:b deny if c2', 'policy http/server:a deny if c2',
                    'policy http/server:b deny if proxy is unknown',
                    'policy http/server:a deny if tor_exit is unknown'])
    ok(e is not None and e.context == 'http/server:b' and e.rule == 2,
       'D-x control: swapping the two directives swaps the answer')
    # D-y and D-z: the two typing phrases that could not fire
    e = refusal_of(['policy http/server:a deny if tor_exit == undetermined'])
    ok(e is not None and e.fragment == 'undetermined on a bool' and e.col == 21,
       'D-y: tor_exit == undetermined is undetermined on a bool, at the literal')
    e = refusal_of(['policy http/server:a deny if tor_exit == valid'])
    ok(e is not None and e.fragment == 'in or == on a bool', 'D-y control: any other operand is in or == on a bool')
    e = refusal_of(['policy http/server:a deny if asn in { 64496 NL 64497 }'])
    ok(e is not None and e.fragment == 'an inline set whose members are not all of one class' and e.col == 24,
       'D-z: a mixed inline set is refused at its first member of another class')
    e = refusal_of(['policy http/server:a deny if asn in { undetermined NL BE }'])
    ok(e is not None and ' takes ' in e.fragment and e.col == 31,
       'D-z: a uniform set of the wrong class is wrong-class at its first classed member')
    # the addenda: the operator first; undetermined in any set; inert in neither shadowing role
    e = refusal_of(['policy http/server:a deny if tor_exit >= undetermined'])
    ok(e is not None and e.fragment == 'an ordered comparison on anything but listed',
       'D-y addendum: the operator is judged before the operand')
    e = refusal_of(['policy http/server:a deny if tor_exit in { undetermined }'])
    ok(e is not None and e.fragment == 'undetermined on a bool' and e.col == 23,
       'D-y addendum: in { undetermined } on a bool is undetermined on a bool, at the member')
    e = refusal_of(['policy http/server:a deny if tor_exit in { valid undetermined }'])
    ok(e is not None and e.fragment == 'in or == on a bool', 'D-y addendum control: a mixed operand is in or ==')
    e = refusal_of(['policy http/server:a log if listed in { low undetermined }'])
    ok(e is not None and ' takes ' in e.fragment and e.col == 24 and e.raw == b'undetermined',
       'D-z addendum: undetermined in a level set is wrong-class at the undetermined member')
    e = refusal_of(['policy http/server:a log if listed in { low NL undetermined }'])
    ok(e is not None and e.fragment == 'an inline set whose members are not all of one class',
       'D-z addendum: a mixed set is refused not-all-of-one-class first')
    e = refusal_of(['set http/server:a @u undetermined', 'policy http/server:a log if listed in @u'])
    ok(e is not None and e.fragment == 'a set used against an attribute of another class',
       'D-z addendum: a declared undetermined set against listed is refused at the use')
    ok(refusal_of(['policy http/server:a log if asn in { undetermined 0 }',
                   'policy http/server:a log if country in { undetermined NL }',
                   'policy http/server:a log if rpki in { undetermined }']) is None,
       'D-z addendum: undetermined is legal in sets of sentinel-bearing attributes')
    bad = []
    lits = ['undetermined', 'low', 'valid', 'asn', 'reputable', 'ripe', '64496', 'NL']
    for attr in sorted(VALUED):
        for lit in lits:
            eq = refusal_of(['policy http/server:a log if %s == %s' % (attr, lit)])
            st = refusal_of(['policy http/server:a log if %s in { %s }' % (attr, lit)])
            if (eq is None) != (st is None):
                bad.append('%s/%s' % (attr, lit))
    ok(not bad, 'D-z invariant: x in { v } and x == v agree on legality for every attribute and literal (%s)'
       % (','.join(bad) or 'all agree'))
    cfg = compile_rules(['policy http/server:a deny if listed >= high',
                         'policy http/server:a deny if listed >= high and rpki == invalid'], absent=('routing',))
    ok(not any('shadowed-by' in x for x in cfg.reports), 'D-aa addendum: an inert rule is never reported shadowed')

    # N1's exact rule and its controls
    ok(message_matches('did you mean GB', 'uk is not an ISO 3166-1 code', 'did you mean GB'),
       'N1: an exact message equal to the fix matches')
    ok(not message_matches('did you mean GB', 'x', 'perhaps: did you mean GB?'),
       'N1 control: an exact message merely contained does not match')
    ok(not message_matches('', 'anything', 'anything'), 'N1 control: an absent message never matches')
    ok(message_matches('a leading zero other than 0', 'a leading zero other than 0 (strtoul ...)', ''),
       'N1: a table phrase contained in what matches')
    # asdot with a part over 65535
    try:
        check_number('as1.70000', 0)
        e = None
    except Refusal as x:
        e = x
    ok(e is not None and '70000 is not' in e.fix and 'asplain value 1' not in e.fix,
       'asdot: a low part over 65535 is named, never converted')
    # the tenant word is checked against the times
    bad = 0
    for word, now, vu in (('fresh', 20, 10), ('stale', 10, 20)):
        try:
            tenant_state(type('R', (), {'tenant': word, 'now': now, 'vu': vu})())
        except ValueError:
            bad += 1
    ok(bad == 2, 'the tenant word a case gives is checked against its times, both ways')
    # D-aa: an inert R1 shadows nothing
    cfg = compile_rules(['policy http/server:a deny if rpki == invalid and listed >= high',
                         'policy http/server:a deny if listed >= high'], absent=('routing',))
    cfg2 = compile_rules(['policy http/server:a deny if listed >= low',
                          'policy http/server:a deny if listed >= high'], absent=('routing',))
    ok(not any('shadowed-by' in x for x in cfg.reports) and any('2 shadowed-by 1' in x for x in cfg2.reports),
       'D-aa: an inert rule shadows nothing; a live one still does')
    cfg = compile_rules(['policy http/server:a deny if listed >= high',
                         'policy http/server:a deny if listed >= critical'], absent=())
    cfg3 = compile_rules(['policy http/server:a deny if asn == 64496', 'policy http/server:a deny if asn == 64496'],
                         absent=('routing',))
    ok(not any('shadowed-by' in x for x in cfg3.reports), 'D-aa: two inert rules report no shadowing')
    # D-ab: a log rule is never shadowed; the same rule as a deny is (the control)
    cfg = compile_rules(['policy http/server:a deny if listed >= low',
                         'policy http/server:a log if listed >= high'], absent=())
    cfg2 = compile_rules(['policy http/server:a deny if listed >= low',
                          'policy http/server:a deny if listed >= high'], absent=())
    ok(not any('shadowed-by' in x for x in cfg.reports) and any('2 shadowed-by 1' in x for x in cfg2.reports),
       'D-ab: a log rule is never shadowed; a deny in its place is')

    # N1 and X3: the corpus runner can fail. A shifted column, a message that is not contained, and a
    # corpus with one refuse file removed (the seed floor) must each be reported.
    rdir = os.path.join(here, 'testdata', 'policy')
    exp = read_expect(os.path.join(rdir, 'refuse', '09-lexing-number-00.expect'))
    with open(os.path.join(rdir, 'refuse', '09-lexing-number-00.policy'), 'rb') as f:
        try:
            compile_config(read_records(f.read()))
            e = None
        except Refusal as x:
            e = x
    ok(e is not None and compare_refusal(e, exp) == [], 'N1: refuse/09 matches its .expect')
    ok(e is not None and compare_refusal(e, dict(exp, col=str(int(exp['col']) + 1))) != [],
       'N1 control: a column one byte off is reported')
    ok(e is not None and compare_refusal(e, dict(exp, message='a leading zero other than 1')) != [],
       'N1 control: a message the refusal does not contain is reported')
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        shutil.copytree(rdir, os.path.join(tmp, 'policy'))
        os.unlink(os.path.join(tmp, 'policy', 'refuse', '50-polarity-design-example.policy'))
        out = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        try:
            _, f_floor = run_corpus(os.path.join(tmp, 'policy'), verbose=False)
        finally:
            sys.stdout.close()
            sys.stdout = out
        ok(f_floor >= 1, 'X3 control: removing one corpus file fails the seed floor')
    finally:
        shutil.rmtree(tmp)

    if fails:
        for f in fails:
            print('FAIL self-test: ' + f)
    print('self-test: %d checks, %d failed' % (checks[0], len(fails)))
    return checks[0], len(fails)


def decision_list(text, start):
    """The decision list in `text` after offset `start`: from the first `  D-a ` line to the end of its
    block (the docstring's closing quotes, or the closing fence in POLICY.md)."""
    i = text.index('\n  D-a ', start) + 1
    ends = [k for k in (text.find('"""', i), text.find('```', i)) if k >= 0]
    return text[i:min(ends) if ends else len(text)]


def decisions_match(policy_md):
    """POLICY.md section 5.6 carries this file's decision list byte for byte: this docstring is the one
    source, and the published copy is checked against it, with a one-byte control."""
    mine = decision_list(__doc__, 0)
    with open(policy_md) as f:
        doc = f.read()
    theirs = decision_list(doc, doc.index('### 5.6'))
    checks = fails = 0
    checks += 1
    if mine != theirs:
        fails += 1
        a, b = mine.split('\n'), theirs.split('\n')
        k = next((n for n in range(min(len(a), len(b))) if a[n] != b[n]), min(len(a), len(b)))
        print('FAIL decisions: POLICY.md 5.6 differs from policy_ref.py at decision-list line %d:' % (k + 1))
        print('  policy_ref.py: %r' % (a[k] if k < len(a) else '<end>'))
        print('  POLICY.md:     %r' % (b[k] if k < len(b) else '<end>'))
    checks += 1
    flipped = theirs[:-2] + ('x' if theirs[-2] != 'x' else 'y') + theirs[-1:]
    if mine == flipped:
        fails += 1
        print('FAIL decisions: the control (one byte changed) compared equal')
    print('decisions: %d lines, %d decisions, %s' % (mine.count('\n'), mine.count('\n  D-') + 1,
                                                   'equal to POLICY.md 5.6' if not fails else 'NOT equal'))
    return checks, fails


# ---------------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------------------
# THE MODULES' TWIN: what a module renders and how it finds the floor's address (POLICY.md section 3.9),
# written from that section and from section 2.7's byte layout, never from we_module.h. The C side is
# test_module --module-cases; the two outputs are compared line for line.
#
# Every address here is sixteen bytes and a family, the C's canonical form, and is parsed by the grammar
# below BEFORE anything else looks at it: ipaddress, which accepts zone ids and drops them, is never used
# to decide whether an entry parses.

M_STATES = ('none', 'fresh-hit', 'fresh-nr', 'stale-hit', 'stale-nr', 'unknown', 'revoked')
# section 2.7: the normalised block's bytes, per schema
M_ROUTING_OFF = {'asn': 0, 'country': 4, 'rov': 6, 'rir': 7, 'flags': 8, 'asn_rep': 9}
M_MEMBER_OFF = {'flags': 0, 'source': 4, 'reason': 5}
M_ENUM_FIELD = {'rpki': 'rpki', 'rpki_reason': 'rpki_reason', 'asn_rep': 'asn_rep', 'rir': 'rir',
                'registry_rir': 'rir'}


def m_attr_bytes(name):
    """(plane id, class, offset, mask) of an attribute in the 16-byte block."""
    if name in BOOLS:
        plane, mask = BOOLS[name]
        if name == 'inferred':
            return plane, 'bool', 0, 0x80
        off = M_ROUTING_OFF['flags'] if SCHEMA[plane] == 'routing' else M_MEMBER_OFF['flags']
        return plane, 'bool', off, mask
    plane, cls, field = VALUED[name]
    if cls == 'level':
        return plane, 'level', 0, 0
    if SCHEMA[plane] == 'routing':
        return plane, cls, M_ROUTING_OFF[field], 0
    return plane, cls, M_MEMBER_OFF[field], 0


def m_render(name, block, state):
    """The rendering table of section 3.9, for one attribute, a 16-byte block and a memo state."""
    plane, cls, off, mask = m_attr_bytes(name)
    st = M_STATES[state]
    if st == 'none':
        return 'unread'
    if st == 'revoked':
        return 'revoked'
    stale = st in ('stale-hit', 'stale-nr')
    if st == 'unknown' or (stale and plane != TENANT):
        return 'unknown'
    if stale:
        v = 'true' if block[off] & mask else 'false'
        return ('lapsed:' if block[14] else 'stale:') + v
    if cls == 'bool':
        return 'true' if block[off] & mask else 'false'
    if cls == 'level':
        lv = block[0] & 0x0F
        return LEVELS[lv if lv <= 4 else 4]
    if cls in ENUMS:
        vals = ENUMS[cls]
        return vals[block[off]] if block[off] < len(vals) else '?'
    if cls == 'asn':
        a = int.from_bytes(block[off:off + 4], 'little')
        return 'undetermined' if a == ASN_SENTINEL else str(a)
    c = int.from_bytes(block[off:off + 2], 'little')
    if c == 0 or c > 999 or c not in COUNTRY_ALPHA:
        return 'undetermined'
    return COUNTRY_ALPHA[c]


# ---- the grammar of one entry: RFC 3986's IPv4address and IPv6address, a port, no zone ----

M_DIGIT = frozenset(b'0123456789')
M_HEX = frozenset(b'0123456789abcdefABCDEF')


def m_dec_octet(s):
    if not s or len(s) > 3 or any(c not in M_DIGIT for c in s):
        return None
    if len(s) > 1 and s[0] == 0x30 and M_TWIN_MUTANT != 'LEADING_ZERO':
        return None                    # no leading zeros
    v = int(s)
    return v if v <= 255 else None


def m_ipv4(s):
    parts = s.split(b'.')
    if len(parts) != 4:
        return None
    out = [m_dec_octet(p) for p in parts]
    return None if None in out else bytes(out)


def m_h16(s):
    if not 1 <= len(s) <= 4 or any(c not in M_HEX for c in s):
        return None
    return int(s, 16)


def m_ipv6(s):
    """RFC 3986 IPv6address: eight groups, or fewer around one `::` that stands for at least one."""
    if b'::' in s:
        if s.count(b'::') != 1:
            return None
        head, tail = s.split(b'::')
        left = head.split(b':') if head else []
        right = tail.split(b':') if tail else []
    else:
        left, right = s.split(b':'), None
    groups = []

    def take(parts, last):
        for i, p in enumerate(parts):
            if last and i == len(parts) - 1 and b'.' in p:
                v4 = m_ipv4(p)
                if v4 is None:
                    return False
                groups.append(v4[0] << 8 | v4[1])
                groups.append(v4[2] << 8 | v4[3])
            else:
                g = m_h16(p)
                if g is None:
                    return False
                groups.append(g)
        return True

    if right is None:
        if not take(left, True) or len(groups) != 8:
            return None
        g = groups
    else:
        if not take(left, not right):
            return None
        n_left = len(groups)
        if left and b'.' in left[-1]:
            return None                # an IPv4 tail only at the very end
        if not take(right, True):
            return None
        n_right = len(groups) - n_left
        if n_left + n_right > (8 if M_TWIN_MUTANT == 'DC_ZERO_GROUPS' else 7):
            return None                # `::` never stands for zero groups
        g = groups[:n_left] + [0] * (8 - n_left - n_right) + groups[n_left:]
    return b''.join(x.to_bytes(2, 'big') for x in g)


def m_port(s):
    return 1 <= len(s) <= 5 and all(c in M_DIGIT for c in s) and int(s) <= (65536 if M_TWIN_MUTANT == 'PORT_65536'
                                                                          else 65535)


def m_canon(b, fam):
    """we_addr_canon's rule, from section 2.7: ::ffff:0:0/96 unmapped, nothing else."""
    if fam == 6 and b[:12] == bytes(10) + b'\xff\xff':
        return (b[12:16] + bytes(12), 4)
    if fam == 4:
        return (b[:4] + bytes(12), 4)
    return (b, 6)


# 'IPADDRESS_ONLY': the control, an entry parsed through ipaddress alone. The four grammar mutants, modelled
# from the defect each C mutant is documented to plant, so the C mutant's output is DERIVED here, line for
# line, rather than counted: 'LEADING_ZERO' (a leading zero in an octet accepted), 'PORT_65536' (one past
# the port's range), 'DC_ZERO_GROUPS' (`::` allowed to stand for no group), 'NO_LINE_CLAMP' (every line
# walked, none dropped as older)
M_TWIN_MUTANT = None


def m_entry(s):
    """One trimmed entry: (canonical 16 bytes, family) or None."""
    if M_TWIN_MUTANT == 'IPADDRESS_ONLY':
        try:
            t = s.decode('ascii')
            if t.startswith('[') and ']' in t:
                t = t[1:t.index(']')]
            elif t.count(':') == 1 and '.' in t:
                t = t.split(':')[0]
            ip = ipaddress.ip_address(t)
        except (ValueError, UnicodeDecodeError):
            return None
        return m_canon(ip.packed if ip.version == 6 else ip.packed + bytes(12), ip.version)
    if not s or len(s) > 53:
        return None
    if s[:1] == b'[':
        close = s.find(b']')
        if close < 0:
            return None
        v6 = m_ipv6(s[1:close])
        rest = s[close + 1:]
        if v6 is None or (rest and not (rest[:1] == b':' and m_port(rest[1:]))):
            return None
        return m_canon(v6, 6)
    colon = s.find(b':')
    if colon < 0:
        v4 = m_ipv4(s)
        return m_canon(v4, 4) if v4 else None
    v4 = m_ipv4(s[:colon])
    if v4 is not None:
        return m_canon(v4, 4) if m_port(s[colon + 1:]) else None
    v6 = m_ipv6(s)
    return m_canon(v6, 6) if v6 else None


# ---- the formatter ----

def m_format(b, fam):
    """The judged address as every surface prints it: dotted quad, or RFC 5952 section 4."""
    if fam == 4:
        return '.'.join(str(x) for x in b[:4])
    g = [b[2 * i] << 8 | b[2 * i + 1] for i in range(8)]
    best, blen, i = -1, 0, 0
    while i < 8:
        if g[i] == 0:
            j = i
            while j < 8 and g[j] == 0:
                j += 1
            if j - i > blen:           # strictly longer: the first run of the longest wins
                best, blen = i, j - i
            i = j
        else:
            i += 1
    if blen < 2:
        return ':'.join('%x' % x for x in g)
    return ':'.join('%x' % x for x in g[:best]) + '::' + ':'.join('%x' % x for x in g[best + blen:])


# ---- the walk ----

def m_trusted(trust, a):
    """A linear scan of the CONFIGURED prefixes, canonicalised: never a merged table."""
    b, fam = a
    v = int.from_bytes(b if fam == 6 else b[:4], 'big')
    for pb, pfam, plen in trust:
        if pfam != fam:
            continue
        bits = 128 if fam == 6 else 32
        base = int.from_bytes(pb if fam == 6 else pb[:4], 'big')
        if (v >> (bits - plen) if plen else 0) == (base >> (bits - plen) if plen else 0):
            return True
    return False


def m_trust_list(items):
    """The configured prefixes, each canonicalised the way the configuration test does."""
    out, unix_ok = [], False
    for it in items:
        if it == 'unix:':
            unix_ok = True
            continue
        addr, _, plen = it.partition('/')
        v4 = m_ipv4(addr.encode())
        if v4 is not None:
            out.append((v4 + bytes(12), 4, int(plen) if plen else 32))
            continue
        v6 = m_ipv6(addr.encode())
        n = int(plen) if plen else 128
        if v6[:12] == bytes(10) + b'\xff\xff' and n >= 96:
            out.append((v6[12:] + bytes(12), 4, n - 96))
        else:
            out.append((v6, 6, n))
    return out, unix_ok


def m_walk(trust, unix_ok, hops, header_set, peer, lines, older):
    """POLICY.md section 3.9's table, row for row: (floor, walk mark, eligible, note).
    `peer` is (16 bytes, family) or None for a unix socket; `lines` oldest first."""
    OK, MISSING, NOADDR = 0, 1, 2
    if peer is None:
        if not header_set or not unix_ok:
            return None, NOADDR, 0, 0
        peer_floor = (bytes(16), 6)
    else:
        peer_floor = peer
        if not header_set or not m_trusted(trust, peer):
            return peer, OK, 1, 0
    if not lines:
        return peer_floor, MISSING, 1 if peer is not None else 0, 0
    # the line cap: the newest 16 lines, and any older ones count as lines not kept (POLICY.md 3.9)
    if len(lines) > 16 and M_TWIN_MUTANT != 'NO_LINE_CLAMP':
        lines = lines[-16:]
        older = 1
    # the elements, newest first, with the bytes the walk examines counted against its 1,024
    budget = [1024]
    reached = []                       # (entry or 'bad'), right to left
    cap = False
    entries = 0

    def spend(n):
        if budget[0] < n:
            budget[0] = 0
            return False
        budget[0] -= n
        return True

    done = False
    for li in range(len(lines) - 1, -1, -1):
        line = lines[li]
        elems = line.split(b',')
        for k in range(len(elems) - 1, -1, -1):
            el = elems[k]
            body = el.strip(b' \t')
            # the bytes of this element the walk examines: trailing OWS, the element up to its 54th
            # non-space byte, and the comma before it
            stripped_r = el.rstrip(b' \t')
            trail = len(el) - len(stripped_r)
            core_len = len(stripped_r)
            toolong = len(body) > 53
            seen = trail + (min(core_len, 54) if toolong else core_len)
            if not spend(trail):
                cap = True
                done = True
                break
            if toolong:
                if not spend(min(core_len, 54)):
                    cap = True
                    done = True
                    break
            elif not spend(core_len):
                cap = True
                done = True
                break
            if body or toolong:
                if entries == 16:
                    cap = True
                    done = True
                    break
                entries += 1
                a = None if toolong else m_entry(body)
                reached.append(a if a is not None else 'bad')
                if a is None:
                    done = True
                    break
                parsed = [x for x in reached if x != 'bad']
                if hops:
                    if len(parsed) == hops:
                        return a, OK, 1 if len(parsed) == 1 else 0, 0
                elif not m_trusted(trust, a):
                    return a, OK, 1 if len(parsed) == 1 else 0, 0
            if k > 0 and not spend(1):
                cap = True
                done = True
                break
            del seen
        if done:
            break
    if not done and older:
        cap = True
    parsed = [x for x in reached if x != 'bad']
    bad = 'bad' in reached
    if not parsed:
        return peer_floor, MISSING, 0, 1
    if bad:
        return parsed[-1], OK, 0, 1
    if not hops:
        return parsed[0], OK, 0, 2 if cap else 0
    return parsed[-1], OK, 0, 2 if cap else 1


# ---- ACME ----

def m_acme(method, target, norm):
    if method not in (b'GET', b'HEAD') or not target or b'?' in target:
        return 0
    raw = target
    if target[:1] != b'/':
        i = 0
        if not (target[:1].isalpha()):
            return 0
        while i < len(target) and (chr(target[i]).isalnum() or target[i:i + 1] in (b'+', b'-', b'.')):
            i += 1
        if target[i:i + 3] != b'://':
            return 0
        j = target.find(b'/', i + 3)
        if j < 0:
            return 0
        raw = target[j:]
    pfx = b'/.well-known/acme-challenge/'
    if not norm.startswith(pfx) or len(norm) == len(pfx):
        return 0
    tok = norm[len(pfx):]
    if any(not (chr(c).isalnum() and c < 0x80 or c in b'_-') for c in tok):
        return 0
    return 1 if raw == norm else 0


# ---- the corpus and the runner the C side mirrors ----

def m_hex(b):
    return b.hex() if b else '-'


def m_unhex(s):
    return b'' if s == '-' else bytes.fromhex(s)


def m_addr_text(a):
    return '-' if a is None else m_format(*a)


def _mutant_named(name, text):
    """does this entry text carry the boundary the C grammar mutant NAME plants?"""
    import re
    if name == 'PORT_65536':
        return re.search(r':65536$', text) is not None
    if name == 'LEADING_ZERO':
        return any(len(o) > 1 and o[0] == '0'
                   for q in re.findall(r'(?<![0-9])[0-9]+(?:\.[0-9]+){3}(?![0-9])', text) for o in q.split('.'))
    if name == 'DC_ZERO_GROUPS':
        a = text.split(']')[0].lstrip('[').split('%')[0]
        if '::' not in a:
            return False
        tail = a.rsplit(':', 1)[-1]
        groups = [g for g in a.split(":") if g]
        return len(groups) + (1 if '.' in tail else 0) == 8
    raise SystemExit('module_mutant_check: no boundary is defined for %s' % name)


def _case_entries(case):
    """the header entries a corpus case feeds the grammar: an entry case's one, a walk case's every one"""
    w = case.split(' ')
    if w[0] == 'entry' and len(w) > 1:
        return [bytes.fromhex(w[1]).decode('latin-1')]
    if w[0] == 'walk':
        for x in w[2:]:
            if x.startswith('lines='):
                out = []
                for h in ([] if x[6:] == '-' else x[6:].split('/')):
                    out += [e.strip(' \t') for e in m_unhex(h).decode('latin-1').split(',')]
                return out
    return []


def _case_on_boundary(name, case):
    """the mutant's boundary: a walk of more than 16 lines for the line cap, else an entry that carries it"""
    if name == 'NO_LINE_CLAMP':
        w = case.split(' ')
        return w[0] == 'walk' and any(x.startswith('lines=') and x != 'lines=-' and len(x[6:].split('/')) > 16
                                      for x in w[2:])
    return any(_mutant_named(name, e) for e in _case_entries(case))


def module_mutant_check(name, corpus_path, c_path, py_path, mut_path=None):
    """A C grammar mutant must disagree with the twin on its named boundary and on nothing else: every
    differing line is a case one of whose header entries carries the boundary, and there is at least one.
    With the twin run under the same mutant (mut_path), the C mutant's output must EQUAL it line for line,
    so the number of disagreements is derived, not just counted."""
    corpus = open(corpus_path).read().splitlines()
    c = open(c_path).read().splitlines()
    py = open(py_path).read().splitlines()
    if not (len(corpus) == len(c) == len(py)):
        print('FAIL mutant %s: %d cases, %d C lines and %d twin lines' % (name, len(corpus), len(c), len(py)))
        return 1
    if mut_path is not None:
        mut = open(mut_path).read().splitlines()
        want = sum(1 for x, y in zip(mut, py) if x != y)
        bad = [i for i, (x, y) in enumerate(zip(c, mut)) if x != y]
        if len(mut) != len(c) or bad:
            print('FAIL mutant %s: the C mutant and the twin under the same mutant differ on %d cases (first: %s)'
                  % (name, len(bad), c[bad[0]][:100] if bad else 'a line count'))
            return 1
        if want == 0:
            print('FAIL mutant %s: the twin under the mutant changes no case, so the derivation proves nothing' % name)
            return 1
        print('ok   the C grammar mutant %s equals the twin under the same mutant on every case: %d '
              'disagreements with the unmutated twin, derived' % (name, want))
    on = off = 0
    for case, x, y in zip(corpus, c, py):
        if x == y:
            continue
        if _case_on_boundary(name, case):
            on += 1
        else:
            off += 1
            if off <= 3:
                print('FAIL mutant %s differs off its boundary: %s' % (name, x[:120]))
    if on == 0:
        print('FAIL mutant %s: no disagreement on its boundary, so the twin cannot see it' % name)
        return 1
    if off:
        print('FAIL mutant %s: %d disagreements off its boundary' % (name, off))
        return 1
    print('ok   the C grammar mutant %s reported on %d cases, each on its boundary, none elsewhere' % (name, on))
    return 0


def module_corpus(path, seed=0x5eed5eed):
    """Every class and boundary the grammar, the walk, the renderer, the formatter and ACME have, then
    seeded mutations of them. One case per line; the C and this file read the same lines."""
    import random
    rnd = random.Random(seed)
    lines = []
    ent = [
        '0.0.0.0', '9.9.9.9', '10.10.10.10', '99.99.99.99', '100.200.150.100', '199.0.0.1', '200.0.0.1',
        '249.0.0.1', '250.0.0.1', '255.255.255.255', '256.0.0.1', '01.2.3.4', '1.02.3.4', '1.2.3.004', '00.0.0.0',
        '1.2.3', '1.2.3.4.5', '1..3.4', '.1.2.3', '1.2.3.4:0', '1.2.3.4:65535', '1.2.3.4:65536', '1.2.3.4:00080',
        '1.2.3.4:12345', '1.2.3.4:123456', '1.2.3.4:', '1.2.3.4:x', '[1.2.3.4]', '[1.2.3.4]:80',
        '::', '::1', '1::', '::ffff:1.2.3.4', '::ffff:0:0', '::1.2.3.4', '::1.2.3.04', '::a.b.c.d',
        '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8',
        '::1:2:3:4:5:6:7:8', '1::2:3:4:5:6:7:8', '1:2:3:4:5:6:1.2.3.4', '1:2:3:4:5:6:7:1.2.3.4',
        '::3:4:5:6:7:1.2.3.4', '1::4:5:6:7:1.2.3.4', ':::1', '1:::2', '1::2::3', '12345::1', 'g::1', 'ABCD::EF',
        'fe80::1%eth0', '[fe80::1%25eth0]:80', '[2001:db8::1]', '[2001:db8::1]:443', '[2001:db8::1]:65536',
        '[2001:db8::1]:', '[2001:db8::1', '2001:db8::1]', '2001:db8::1:443', 'unknown', 'for=1.2.3.4',
        '_hidden', '1:', ':1', '0000:0000:0000:0000:0000:ffff:255.255.255.255',
        '[0000:0000:0000:0000:0000:ffff:255.255.255.255]:65535',
        '[0000:0000:0000:0000:0000:ffff:255.255.255.255]:655350', '1.2.3.4 5', '',
    ]
    alts = ['1:2:3:4:5:6:7:8', '::2:3:4:5:6:7:8', '1::3:4:5:6:7:8', '1:2::4:5:6:7:8', '1:2:3::5:6:7:8',
            '1:2:3:4::6:7:8', '1:2:3:4:5::7:8', '1:2:3:4:5:6::8', '1:2:3:4:5:6:7::']
    ent += alts + [a.replace('::', ':0:') if a.startswith('::') is False else a for a in alts]
    alphabet = '0123456789abcdefABCDEF:.[]%x '
    for _ in range(3000):
        base = list(rnd.choice(ent) or '1')
        for _k in range(rnd.randint(1, 3)):
            op = rnd.randint(0, 2)
            pos = rnd.randint(0, len(base))
            if op == 0:
                base.insert(pos, rnd.choice(alphabet))
            elif op == 1 and base:
                del base[min(pos, len(base) - 1)]
            elif base:
                base[min(pos, len(base) - 1)] = rnd.choice(alphabet)
        ent.append(''.join(base))
    for e in ent:
        lines.append('entry %s' % m_hex(e.encode()))
    # the formatter, every run shape of zero groups
    for k in range(256):
        g = [(0x1 + i * 0x1111) if (k >> i) & 1 else 0 for i in range(8)]
        b = b''.join(x.to_bytes(2, 'big') for x in g)
        if b[:12] == bytes(10) + b'\xff\xff':
            continue
        lines.append('format 6 %s' % b.hex())
    for v4 in ('0.0.0.0', '192.0.2.1', '255.255.255.255', '10.0.0.10'):
        lines.append('format 4 %s' % (m_ipv4(v4.encode()) + bytes(12)).hex())
    # the walk: peers, trust lists, hops, and lines drawn from parsing, trusted and junk entries
    trusts = ['10.0.0.0/8', '10.0.0.0/8,10.1.0.0/16', '10.0.0.0/9,10.128.0.0/9', '0.0.0.0/0',
              '::ffff:10.0.0.0/104', '10.0.0.0/8,2001:db8:ffff::/48,unix:', '192.0.2.5']
    pool = ['203.0.113.5', '198.51.100.7', '10.0.0.7', '10.1.2.3', '10.200.0.1', '[2001:db8::7]:80',
            '2001:db8:ffff::9', '::ffff:10.0.0.3', 'junk', '', ' ', '1.2.3.04', '203.0.113.5:443', '192.0.2.5']
    peers = ['10.0.0.1', '192.0.2.9', '::ffff:10.0.0.1', '192.0.2.5', 'unix']
    for i in range(2500):
        n = rnd.choice([0, 1, 1, 2, 3])
        ls = []
        for _ in range(n):
            k = rnd.choice([1, 1, 2, 3, 6, 17, 20])
            ls.append(', '.join(rnd.choice(pool) for _ in range(k)) + rnd.choice(['', ' ', ',']))
        lines.append('walk w%d peer=%s header=%d hops=%d older=%d trust=%s lines=%s' % (
            i, rnd.choice(peers), rnd.choice([0, 1, 1, 1]), rnd.choice([0, 0, 0, 1, 2, 3]), rnd.choice([0, 0, 1]),
            rnd.choice(trusts), '/'.join(m_hex(x.encode()) for x in ls) if ls else '-'))
    # the line cap: 17 and 40 lines, the oldest holding the only address, the rest empty or forged, from a
    # trusted peer; and 16 lines exactly, which the cap leaves alone
    for k, (count, oldest, rest) in enumerate([(17, '203.0.113.9', ''), (40, '203.0.113.9', ''),
                                              (17, '203.0.113.9', '198.51.100.7'), (40, '198.51.100.7', '10.0.0.7'),
                                              (16, '203.0.113.9', '')]):
        ls = [oldest] + [rest] * (count - 1)
        for hops in (0, 1, 2):
            for older in (0, 1):
                lines.append('walk cap%d.%d.%d peer=10.0.0.1 header=1 hops=%d older=%d trust=10.0.0.0/8 lines=%s' % (
                    k, hops, older, hops, older, '/'.join(m_hex(x.encode()) if x else '-' for x in ls)))
    # the renderer: every attribute, every state, a spread of bytes, the lapsed byte set and clear
    names = sorted(ATTRS)
    for name in names:
        for st in range(7):
            for _ in range(24):
                b = bytearray(rnd.getrandbits(8) for _ in range(16))
                b[15] = 0
                b[14] = rnd.choice([0, 1])
                plane, cls, off, _m = m_attr_bytes(name)
                if cls == 'country':
                    c = rnd.choice([0, 528, 999, 1000, 65535, 4, 840, 903, 904])
                    b[off:off + 2] = c.to_bytes(2, 'little')
                if cls == 'asn' and rnd.random() < 0.3:
                    b[off:off + 4] = ASN_SENTINEL.to_bytes(4, 'little')
                lines.append('render %s %d %s' % (name, st, bytes(b).hex()))
    # ACME
    tok = '/.well-known/acme-challenge/Ab_9-x'
    for m, t, nrm in [('GET', tok, tok), ('HEAD', tok, tok), ('POST', tok, tok), ('get', tok, tok),
                      ('GET', 'http://h/.well-known/acme-challenge/Ab_9-x', tok),
                      ('GET', 'HTTPS://h:8443/.well-known/acme-challenge/Ab_9-x', tok), ('GET', tok + '?', tok),
                      ('GET', tok + '?x=1', tok), ('GET', '/.well-known/%2e/acme-challenge/Ab_9-x', tok),
                      ('GET', '/.well-known/acme-challenge/%41b_9-x', tok), ('GET', '/' + tok, '/' + tok),
                      ('GET', '/.well-known/acme-challenge/a/b', '/.well-known/acme-challenge/a/b'),
                      ('GET', '/.well-known/acme-challenge/', '/.well-known/acme-challenge/'),
                      ('GET', '/.well-known/acme-challenge/a.b', '/.well-known/acme-challenge/a.b'),
                      ('GET', '/.well-known/acme-challenge/missing', '/index.php'),
                      ('GET', 'h/.well-known/acme-challenge/Ab_9-x', tok), ('GET', 'http://h', tok)]:
        lines.append('acme %s %s %s' % (m, m_hex(t.encode()), m_hex(nrm.encode())))
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return len(lines)


def module_cases(path, out):
    """One output line per input line, in the format test_module --module-cases prints."""
    n = 0
    for line in open(path):
        w = line.split()
        if not w:
            continue
        n += 1
        if w[0] == 'entry':
            a = m_entry(m_unhex(w[1]))
            out.write('entry %s %s\n' % (w[1], 'refused' if a is None else m_format(*a)))
        elif w[0] == 'format':
            out.write('format %s %s %s\n' % (w[1], w[2], m_format(bytes.fromhex(w[2]), int(w[1]))))
        elif w[0] == 'render':
            out.write('render %s %s %s %s\n' % (w[1], w[2], w[3], m_render(w[1], bytes.fromhex(w[3]), int(w[2]))))
        elif w[0] == 'acme':
            out.write('acme %s %s %s %d\n' % (w[1], w[2], w[3], m_acme(w[1].encode(), m_unhex(w[2]), m_unhex(w[3]))))
        elif w[0] == 'walk':
            kv = dict(x.split('=', 1) for x in w[2:])
            trust, unix_ok = m_trust_list(kv['trust'].split(','))
            peer = None if kv['peer'] == 'unix' else m_entry(kv['peer'].encode())
            ls = [] if kv['lines'] == '-' else [m_unhex(x) for x in kv['lines'].split('/')]
            fl, mark, elig, note = m_walk(trust, unix_ok, int(kv['hops']), int(kv['header']), peer, ls, int(kv['older']))
            out.write('walk %s floor=%s walk=%d eligible=%d note=%d\n' % (w[1], m_addr_text(fl), mark, elig, note))
    return n


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='the edge policy language reference interpreter')
    ap.add_argument('--corpus')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--cases')
    ap.add_argument('--attrs', action='store_true')
    ap.add_argument('--out')
    ap.add_argument('--coverage')
    ap.add_argument('--mutant')
    ap.add_argument('--compile')
    ap.add_argument('--expect')
    ap.add_argument('--seeds')
    ap.add_argument('--floor', type=int, default=0)
    ap.add_argument('--default-conf')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--decisions-match')
    ap.add_argument('--module-corpus')
    ap.add_argument('--module-cases')
    ap.add_argument('--twin-mutant')
    ap.add_argument('--mutant-check', nargs='+', metavar='ARG', help='NAME CORPUS C_LINES TWIN_LINES [TWIN_MUTANT_LINES]')
    a = ap.parse_args(argv)
    set_mutant(a.mutant)
    if a.compile:
        return compile_file(a.compile)
    if a.mutant_check:
        return module_mutant_check(*a.mutant_check)
    if a.module_corpus:
        print('module corpus: %d cases written to %s' % (module_corpus(a.module_corpus), a.module_corpus))
        return 0
    if a.module_cases:
        global M_TWIN_MUTANT
        M_TWIN_MUTANT = a.twin_mutant
        out = open(a.out, 'w') if a.out else sys.stdout
        n = module_cases(a.module_cases, out)
        if a.out:
            out.close()
        sys.stderr.write('module twin: %d cases\n' % n)
        return 0
    if a.expect:
        return expect_file(a.expect)
    total = fails = 0
    did = False
    if a.self_test:
        c, f = self_test(verbose=not a.quiet)
        total += c
        fails += f
        did = True
    if a.corpus:
        c, f = run_corpus(a.corpus, verbose=not a.quiet)
        total += c
        fails += f
        did = True
    if a.seeds:
        c, f = run_seeds(a.seeds, a.floor, verbose=not a.quiet)
        total += c
        fails += f
        did = True
    if a.decisions_match:
        c, f = decisions_match(a.decisions_match)
        total += c
        fails += f
        did = True
    if a.default_conf:
        c, f = run_default_conf(a.default_conf, os.path.join(os.path.dirname(a.default_conf)))
        total += c
        fails += f
        did = True
    if a.cases:
        out = open(a.out, 'w') if a.out else sys.stdout
        n_prog, n_case, n_ref, f, legs, dt, cov = run_cases(a.cases, out, a.coverage, attrs=a.attrs)
        if a.out:
            out.close()
        sys.stderr.write('oracle: %d programs (%d refused), %d cases (%s) in %.1f s\n' % (
            n_prog, n_ref, n_case, ', '.join('%s %d' % kv for kv in sorted(legs.items())), dt))
        # The cases are compared by the differential (policy_diff.py against test_policy); evaluating them
        # here asserts only the invariant line, which compares two of this file's own paths, so the
        # oracle's run adds nothing to the published count. Its failures still fail the run.
        fails += f
        did = True
    if not did:
        ap.print_help()
        return 2
    # with the case output on stdout, the summary goes to stderr so the output stays comparable
    print('%d checks, %d failures' % (total, fails), file=sys.stderr if (a.cases and not a.out) else sys.stdout)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
