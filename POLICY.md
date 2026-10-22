# The rule language

**Write firewall rules about who is asking, not just their IP address.**

```
allow if asn in @partners
deny  if listed >= high
deny  if rpki == invalid
log   if tor_exit or vpn
```

Every rule is `action if condition`. The first rule that matches decides; if none matches, the request is allowed.

## Rules in five minutes

### The three actions

| action | what happens |
|---|---|
| `allow` | let it through, and stop checking |
| `deny` | answer 403, and log why |
| `log` | let it through, and log what you saw |

### What you can ask about an address

| ask | means | example |
|---|---|---|
| `listed` | rated on a cited public blocklist: `none`, `low`, `medium`, `high`, `critical` | `deny if listed >= high` |
| `inferred` | flagged by our graph without a public listing behind it | `log if inferred` |
| `rpki` | is the route it came from valid: `valid`, `invalid`, `not-found`, `unrouted` | `deny if rpki == invalid` |
| `rpki_unreachable` | no valid route reaches it at all | `deny if rpki_unreachable` |
| `asn` | the network it is announced from | `allow if asn in @partners` |
| `asn_rep` | that network's reputation: `reputable` to `highly_suspicious` | `log if asn_rep == highly_suspicious` |
| `country` | where it is routed from | `deny if country in @blocked` |
| `tor_exit`, `proxy`, `vpn` | anonymising services | `log if tor_exit or proxy or vpn` |
| `c2`, `phishing`, `bruteforce`, `scanner`, `spam`, `state_actor` | known attack infrastructure | `deny if c2 or phishing` |
| `anycast`, `moas` | served from many places, or announced by more than one network | `log if moas` |
| `rir`, `registry_country`, `registry_rir` | who registered the address, and where | `log if registry_country in @watch` |
| `tenant_allow`, `tenant_deny` | your own lists, delivered to every server you run | `allow if tenant_allow` |

Combine them with `and`, `or`, `not` and brackets. Name a group once with a set: `@partners AS64496 AS64497`, `@blocked KP SY CU`.

`listed`, `inferred`, `tor_exit` and `rpki_unreachable` need no key. The rest come with a free key; see [DATA.md](DATA.md).

### Recipes

Every one of these is checked by the real compiler.

**Let your partners in, whatever else is true:**
```nginx
whisper_edge_set    "@partners AS64496 AS64497";
whisper_edge_policy "allow if asn in @partners";      # first, because the first match decides
```

**Block what is publicly listed, and route hijacks:**
```nginx
whisper_edge_policy "deny if listed >= high";
whisper_edge_policy "deny if rpki == invalid";
```

**Keep attack infrastructure out:**
```nginx
whisper_edge_policy "deny if c2 or phishing or bruteforce";
```

**Watch anonymisers without blocking them:**
```nginx
whisper_edge_policy "log if tor_exit or proxy or vpn";
```

**Be stricter on your login page than on the rest of the site:**
```nginx
location /login {
    whisper_edge_policy "deny if country in @blocked";
    whisper_edge_policy "log  if listed >= medium";
}
```

**Use your own lists, on every server at once:**
```nginx
whisper_edge_policy "allow if tenant_allow";
whisper_edge_policy "deny  if tenant_deny";
```

### It stops you from hurting yourself

Mistakes are caught when your server loads its configuration, never while it serves. For example, this rule would block everyone the moment the routing data was missing, so it is refused, with the reason and the fix:

```
whisper-edge-lookup: the policy (file) is refused: rule 1, line 1, column 17: near "is": rule 1: "is unknown" here lets rule 1 deny exactly when the routing plane is missing or stale; that is a fail-closed rule. Use it in a log rule, or in an allow rule that no later deny depends on.
```

And whatever you write, some things are never blocked: DNS root and TLD servers, public resolvers, certificate authorities and ACME, NTP, and registry infrastructure ([the list](hold-harmless.txt)).

### Try a rule before you use it

```sh
whisper-edge-lookup --policy my-rules.conf 192.0.2.10
```

shows which rule would fire for that address, and why.

---

# The specification

The rest of this document is the formal specification: the grammar, the compiled program, the evaluator and how both implementations are held to one reading. You do not need it to write rules.


This document specifies the policy language the edge modules run: its grammar, the meaning of every
literal, the refusals and their exact wording, the compiled program's bytes, the evaluator's order and
logic, its cost, and the checks that hold the two implementations to one reading.

There are two implementations, and both are normative only through this text:

- the C compiler, verifier and evaluator: `core/we_policy.h`, `core/we_policy.c` (the cold
  side: lexer, parser, typing, sets, encoder, verifier, printer, classifier, reports) and
  `core/we_eval.h` (the request path, header-only and force-inlined);
- the reference interpreter, `core/policy_ref.py`, written from this text and never from the C.

The two meet in a differential (§5.2) that compares every output line per case. Where this document
would leave a choice, §5.6 fixes the reading (decisions D-a to D-af) and both implementations take
it. If the two implementations and this document ever disagree, this document
is changed first, then the implementations, then the independent corpus under
`core/testdata/policy/`, and a corpus file is never edited to make a build pass.

The byte-exact contract of the plane files the evaluator reads is `core/FORMAT.md`; this document
cites it where the language depends on a record field.

**How citations resolve.** Source files cite this document as `POLICY.md §N` or `section N` (the
sections below), `D1` to `D36` (the decisions of §11), `D-a` to `D-af` (the reference interpreter's
readings, §5.6), and two-character row ids such as `N3`, `K7`, `X5` or `HH1` (the test matrix, §9). Rows
`D1` to `D6`, `D21` and `D23` of §9 share their spelling with decisions of §11; a test section or check
labelled with one of those ids is the row, and a sentence that states a rule is the decision. A few
comments cite a numbered design decision of the record this language came from; as they bear on the
language, decision 1 is the plane file layout (`FORMAT.md`), decision 2 is this language, decision 3
is the default policy (§7), decision 4 is the tenant plane (§4.2), and decision 7 is the plane
publication state machine and its writer discipline (§2.4, §3.5).

## 1. The grammar

### 1.1 EBNF

One `whisper_edge_policy` directive is one rule; a context's program is its directives in order.
`whisper_edge_set` declares a named set in the context that contains it. `whisper_edge_policy_floor`
writes a rule of the floor program, at http level only. The only rule form is `action if expr`; there
is no unconditional rule (decision D1).

```
program      = { rule } ;
rule         = action , "if" , expr ;                   (* one directive argument *)
action       = "allow" | "deny" | "log" ;

expr         = conj | disj | unary ;                    (* a chain is homogeneous: and-chain or or-chain *)
conj         = unary , "and" , unary , { "and" , unary } ;
disj         = unary , "or"  , unary , { "or"  , unary } ;
unary        = "not" , unary | primary ;                (* not binds looser than a comparison, tighter than and *)
primary      = "(" , expr , ")" | atom ;

atom         = bool_attr
             | attr , "is" , [ "not" ] , "unknown"
             | attr , ( "==" | "!=" ) , literal
             | "listed" , ( ">=" | ">" | "<=" | "<" ) , level
             | attr , "in" , set ;

set          = "@" , ident | "{" , members , "}" ;
members      = { "," } , literal , { { "," } , literal } , { "," } ;   (* commas are optional separators *)
set_decl     = "@" , ident , members ;                  (* the whisper_edge_set argument *)

literal      = level | enum_lit | country | asn | "undetermined" ;
level        = "none" | "low" | "medium" | "high" | "critical" ;
enum_lit     = "valid" | "invalid" | "not-found" | "unrouted"           (* rpki *)
             | "asn" | "length"                                          (* rpki_reason *)
             | "reputable" | "neutral" | "suspicious" | "highly_suspicious"   (* asn_rep *)
             | "afrinic" | "apnic" | "arin" | "lacnic" | "ripe" ;        (* rir, registry_rir *)
country      = letter , letter ;                       (* ISO 3166-1 alpha-2, EU AP ZZ XK *)
asn          = [ "as" ] , digits ;                      (* base 10, unsigned, "0" allowed, no other leading zero *)
ident        = 1*64 ( "a".."z" | "0".."9" | "_" | "-" ) ;

bool_attr    = "inferred" | "rpki_unreachable" | "tor_exit" | "proxy" | "vpn" | "c2" | "bruteforce"
             | "spam" | "phishing" | "scanner" | "state_actor" | "anycast" | "moas" | "narrowed"
             | "tenant_allow" | "tenant_deny" ;
attr         = bool_attr | "listed" | "rpki_reason" | "rpki" | "asn" | "asn_rep" | "country"
             | "registry_country" | "rir" | "registry_rir" ;
```

Chains are reduced left-associatively: the compiler emits `AND` (or `OR`) after each operand from the
second on, so the stack holds at most one pending value per nesting level and the depth bound of §3.3
follows. Mixing `and` and `or` in one chain without parentheses has no parse; the refusal names the
second connective. `{ , }` and `{ }` are both the empty set, refused in the **sets** layer with `an
empty set`, at the `{`.

The directives a configuration may carry, and the record kinds the corpus and the fuzz harness use
for them:

| directive | kind | argument |
|---|---|---|
| `whisper_edge_policy` | `policy` | one rule |
| `whisper_edge_set` | `set` | one `set_decl` |
| `whisper_edge_policy_floor` | `floor` | one rule of the floor program, http level only, `deny` and `log` only |
| `whisper_edge_threshold` | `threshold` | `off`, `low`, `medium`, `high` or `critical` (§7) |
| `whisper_edge_mode` | `mode` | `off`, `log` or `deny` |
| `whisper_edge_allow_inferred` | `allow_inferred` | `on` or `off` |

### 1.2 The lexical contract, byte by byte

Both implementations are written from this table, and the fuzz corpus seeds every row.

| item | rule |
|---|---|
| alphabet | bytes 0x20..0x7E plus the whitespace set below; any other byte, NUL included, is refused at its byte offset as `byte 0xHH is not allowed`, whatever surrounds it (a Cyrillic letter inside braces, a U+200B between tokens, a NBSP, ESC) |
| whitespace | SP, HT, LF, CR, VT, FF separate tokens; nothing else does |
| line breaks | LF only; CR is whitespace, so CRLF and CR-only arguments lex the same and `line` counts LFs; `line` and `col` are 1-based, `col` in bytes |
| self-delimiting | `( ) { } ,` and the operators `== != >= > <= <` end the token before them, so `deny if(tor_exit)`, `{RU,SY}` and `listed>=high` parse; an operator token is the **maximal munch** over a run of `= ! < >`, so `===`, `=>`, `<>` and a lone `=` or `!` are one token each, refused as an unknown operator at the run's first byte |
| keyword case | keywords (`allow deny log if and or not in is unknown undetermined`), attribute names, levels and enum literals are **lower-case only**; `DENY`, `Valid`, `RIPE` are refused as unknown words with the lower-case spelling as the fix (the RIR literals are therefore written `ripe`, `arin`; an upper-case rendering elsewhere is a label, not a spelling) |
| country case | a two-letter code is accepted in any case (`nl`, `Nl`, `NL`) and rendered upper-case; `uk` is refused with `did you mean GB`; **unknown codes, one rule**: where the parser already knows a country is expected (after `country` or `registry_country` with `==`, `!=` or `in {`, and inside a set declared or used against one of them) a two-letter token not in the reader's table is a **lexing** refusal, `an unknown country code`; against any other attribute (`rpki == XX`) the two-letter token is a literal of the wrong class, a **typing** refusal naming the attribute's domain (the liberal reading of unknown codes applies to records, `FORMAT.md` §3, never to the program) |
| literal mode | after `==`, `!=`, `>=`, `>`, `<=`, `<`, inside `{ }` and in a `whisper_edge_set` argument the next token is a literal, so `country == IN` and `{ in is no as do }` parse; after `in` the next token must be `@` or `{`, and anything else (`country in RU`) is refused with the fix `write country in { RU } or country == RU`; a bare two-letter token anywhere else in expression mode is refused with the same fix |
| `not-found` | `not-found`, `not_found` and `notfound` lex as one token |
| numbers | base 10, unsigned, no sign; `0` and `as0` are accepted (AS0 is a real value, RFC 7607); within one number token the checks run in the order of decision D-g: sign, asdot, a non-digit, a leading zero (`00`, `010`, `04294967295` are leading-zero refusals), the digit count (more than 10 digits is overflow), the value (above `2^32 - 1` is overflow), and `4294967295`, refused as the sentinel; `as1.10` (asdot) is refused with the asplain value as the fix; `1e3`, `0x10` and `1_000` are refused at the first non-digit; `as 64496` with a space is two tokens and refused |
| ASN forms | `as64496`, `AS64496`, `As64496` and `64496` are the one literal (the prefix is case-insensitive because it is a prefix, not a word) |
| identifiers | `[a-z0-9_-]`, 1 to 64 bytes, case-sensitive (`@embargo` and `@Embargo`: the second is refused, upper case is outside the class); a set name may equal a keyword (`@in`, `@country`) because it is always preceded by `@` |
| `@` | `@` alone, `@@x`, `@ x`, `@` inside braces are refused at the `@` |
| braces | an unterminated `{`, a stray `}`, nested braces, `country == { NL }` are refused at the offending brace |
| empty input | an empty or whitespace-only argument is a **parsing** refusal, `an empty expression`, located at the end of input with no token (an empty argument at line 1, column 1; a whitespace-only one at the position one past its last byte); `deny if`, `()` and a trailing `not` are the same refusal at their end of input; `deny x` and `deny if if x` are refused at the stray token; the bare action `deny` keeps its own fix text, `deny if not <condition>`, at column 5, one past its last byte |
| trailing input | anything after a complete rule is refused, never truncated: `deny if tor_exit garbage` names `garbage` |
| `#` | not a comment character; 0x23 is inside the alphabet but belongs to no token class, so the **lexer** refuses it, in the lexing layer, with the alphabet layer's own words, `byte 0x23 is not allowed` (every other byte of 0x21..0x7E outside a token class is refused the same way, decision D-d) |

### 1.3 Literal forms per attribute type, and the attribute vocabulary

| type | attributes | literal forms | comparisons |
|---|---|---|---|
| bool | the sixteen `bool_attr` names | none (bare atom; `not x`) | bare, `is unknown` |
| ordered | `listed` | `none low medium high critical` | `== != >= > <= <`, `in`, `is unknown` |
| enum | `rpki`, `rpki_reason`, `asn_rep`, `rir`, `registry_rir` | the attribute's domain and `undetermined` | `== !=`, `in`, `is unknown` |
| u32 | `asn` | `as64496`, `64496`, `undetermined` | `== !=`, `in`, `is unknown` |
| country | `country`, `registry_country` | alpha-2, `EU AP ZZ XK`, `undetermined` | `== !=`, `in`, `is unknown` |

`undetermined` is granted on every attribute whose record field has a sentinel in `FORMAT.md` §3:
`rpki`, `asn`, `asn_rep`, `country`, `rir` (sentinel 0 or `0xFFFFFFFF`), `rpki_reason` (`reason` 0),
`registry_country` and `registry_rir` (the registry plane carries the routing record). Absence from
`rpki-unreachable` and from `registry` produces values that could otherwise not be named, and the
compiler's own warning (`and x != undetermined`, §2.5) must suggest a spelling the typing pass
accepts. `listed` is the one valued attribute without a sentinel. A literal of the wrong class for the
attribute is refused naming the attribute's domain (`rpki == NL`: `rpki takes valid, invalid,
not-found, unrouted or undetermined`). `undetermined` on a bool is refused.

The vocabulary, 25 attributes over eight planes (`we_attr_count()` returns 25). Plane ids run 1..8
(`FORMAT.md`); the three keyless planes are the ones the default policy reads, and every other plane
needs a key.

| attribute | plane (id) | class | `undetermined` | normalised block bytes (§2.7) |
|---|---|---|---|---|
| `listed`, `inferred` | `reputation` (1), format 1 | level; bool | no | `sev` +0: low nibble the level, 0x80 `inferred` |
| `tor_exit` | `tor` (2), membership | bool | no | flags +0, bit 0x01 |
| `rpki_unreachable`, `rpki_reason` | `rpki-unreachable` (3), membership | bool; enum | `rpki_reason` only | flags +0 bit 0x01; `reason` +5 |
| `asn`, `country`, `rpki`, `rir`, `anycast`, `moas`, `narrowed`, `asn_rep` | `routing` (4) | u32, country, enum, enum, bool, bool, bool, enum | all valued ones | `asn` +0, `country` +4, `rov` +6, `rir` +7, flags +8 (0x01 `anycast`, 0x02 `moas`, 0x04 `narrowed`), `asn_rep` +9 |
| `proxy`, `vpn` | `anonymizer` (5), membership | bool | no | flags +0, 0x01 and 0x02 |
| `c2`, `bruteforce`, `spam`, `phishing`, `scanner`, `state_actor` | `threat` (6), membership | bool | no | flags +0, 0x01 to 0x20 |
| `registry_country`, `registry_rir` | `registry` (7), routing schema | country, enum | yes | `country` +4, `rir` +7 |
| `tenant_allow`, `tenant_deny` | `tenant` (8), membership | bool | no | flags +0, 0x01 and 0x02 |

The keyless planes are `reputation`, `tor` and `rpki-unreachable`. Membership planes carry a flag mask
the loader holds a record to: 0x01 for `tor` and `rpki-unreachable`, 0x03 for `anonymizer` and
`tenant`, 0x3F for `threat`. An address or CIDR is not a literal of this language (§4.2).

The enum domains, in domain order (index 0 is `undetermined`):

| class | domain |
|---|---|
| `rpki` | `undetermined valid invalid not-found unrouted` |
| `rpki_reason` | `undetermined asn length` |
| `asn_rep` | `undetermined reputable neutral suspicious highly_suspicious` |
| `rir` | `undetermined afrinic apnic arin lacnic ripe` |
| level | `none low medium high critical` |

### 1.4 What the literals mean, the definite values

UNKNOWN is a plane or transport state only (a plane that is stale, refused, loading, or armed at
generation 0 off the tenant plane, §2.7); absence from a fresh plane is definite.

- At a record, an enum field at its sentinel is the definite value `undetermined`. `x ==
  undetermined` is TRUE there; every other `==`, `in` and ordered comparison is FALSE; `!=` is
  `not ==`, so `country != NL` is TRUE at the sentinel and `country != undetermined` FALSE.
- Absence from a fresh membership plane (`FORMAT.md` §3) is FALSE for every bit; `rpki_reason` is
  `undetermined`. A tenant record with both bits set is legal to the loader (the plane's mask is
  `0x03`) and means what the fixed order makes it mean: `tenant_allow` is consulted in step 2 and wins.
- Absence from the fresh routing plane is `rpki == unrouted`, `asn`, `country`, `rir`, `asn_rep`
  `undetermined`, `anycast`, `moas`, `narrowed` FALSE. Absence from `registry` is `registry_country`
  and `registry_rir` `undetermined`.
- Absence from the fresh reputation plane is `listed == none`, `inferred` FALSE. A range flagged
  `WE_F_INFERRED` (0x80) reads `inferred` TRUE and `listed == none` unless the running context's
  `allow_inferred` is set, in which case `listed` is the severity.
- **`listed` over every `sev` byte.** The loader checks range order and not `sev[]`, so the evaluator
  defines every value: the low nibble 0..4 is `none` to `critical`; nibbles 5..15 read `critical`;
  bits 0x10 and 0x20 are ignored; 0x40 (`WE_F_DROP`) is not an attribute and is ignored; 0x80 is
  `inferred`. With that, every comparison form agrees with `we_should_deny()`'s raw `>=` on the nibble
  over all 256 bytes (row G1).
- Every record field is **clamped at memo fill** (§2.7) before any shift or index: `rov` above 3,
  `rir` above 5, `asn_rep` above 4, `reason` above 2 read `undetermined`; `country` goes through
  `we_country()` for `==` and `in` alike; routing `flags` are masked to bits 0..2 and membership
  `flags` to the plane's mask. The loader refuses these values in a file it arms, so the clamp defends
  the one-tick window in which an in-place rewrite is readable through an armed descriptor, and the
  generator draws every byte value so the clamp is exercised (§5.2).

### 1.5 Refusals: shape, rendering, order, and the complete list

A refusal is a `we_policy_error_t`: `layer`; `phrase` (the normative phrase of the table below);
`kind` (the directive kind); `directive` (its index in the source); `rule` (the 1-based ordinal of
the directive among the directives of its kind in its context; for a `whisper_edge_set` refusal the
ordinal of that set declaration); `line` and `col` (1-based, `col` in bytes); `context` (the
directive's context path, rendered as below); `token` (the lexeme, rendered as below); `what` and
`fix`. A refused configuration allocates nothing.

**Order**, so an input with two faults has one answer in both implementations: (1) the argument
length, 2,048 bytes, before anything is read; (2) the first byte outside the alphabet, in source order;
(3) the first lexing refusal in source order; (4) parsing; (5) typing, in source order within the
rule; (6) set resolution, once every directive of the configuration has been seen (a set may be
declared after the rule that uses it); (7) the program limits; (8) polarity, last. Steps 1 to 5 run
per directive in file order; steps 6, 7 and 8 run over the whole configuration after every directive
is seen (D-a, D-b, D-c, D-x). `rpki == XX` is therefore a typing refusal (step 5: `XX` is a country
literal, the wrong class), while `country in { NL XX }` is a lexing refusal (step 3: the parser knew
a country was expected, §1.2); a 2,049-byte argument with non-ASCII is a length refusal.

**Locations and strings, normative**, so the compiler, the reference interpreter and the corpus agree
by construction (`core/testdata/policy/README.md` pins the same rules):

- a **length** refusal happens before anything is read: line 1, column 1, no token;
- an **alphabet** refusal reports the single offending byte as its token, and the `#` refusal of §1.2
  does the same from the lexing layer;
- `line` and `col` point at the first byte of the offending token, or one past the last byte of the
  argument when the refusal is at the end of input; only LF starts a new line;
- a **set reference** token includes its `@`; a **set declaration** is refused at column 1 with the
  set's name as the token;
- an **unterminated `{`** is refused at the brace; a stray `}` at the brace;
- a **program-limit** refusal points at the first directive past the limit: the 257th rule at its
  first token, and for the operation limit the token that brings the context's count to 4,097;
  operations are counted **per token in source order** as the parser reads them (atoms, connectives
  and unary `not` each count at their token), and the per-rule limit the same way, so a 65-operation
  rule is refused at its 33rd atom;
- a **polarity** refusal points at the `is` of the offending `is unknown`, in the rule that contains it;
- the layer is one of `length`, `alphabet`, `lexing`, `parsing`, `typing`, `sets`, `program`,
  `polarity`, the group names of the table below (the verifier's own refusals, §5.5, use the layer
  `verify`).

**Token rendering.** The lexeme is truncated at 64 bytes on a character boundary first; then every
byte outside 0x20..0x7E, and the two bytes `"` and `\`, are written as `\xHH` with **upper-case** hex
digits. So a tenant-writable include cannot forge log lines through CR, LF or ESC, and a token cannot
close the quoted `near "..."` field. An empty token means none (end of input, or a length refusal).

**Context rendering** (decision D-ad). The context is the C error's 128-byte field: a path of up to 127
bytes is printed verbatim; a longer one is printed as its first 61 bytes, `...`, and its last 63, so
the server and the innermost block both survive.

**The module message.** The three server modules print one line per refusal, formatted by
`we_policy_error_format()`:

```
rule N, line L, column C: near "token": what. fix
```

with ` fix` omitted when the refusal has none. Example:
`rule 1, line 1, column 85: near "is": rule 1: "is unknown" here lets rule 1 deny exactly when the
tor plane is missing or stale; that is a fail-closed rule. Use it in a log rule, or in an allow rule
that no later deny depends on.`

**The refusal line.** The differential (§5.2) compares refusals in this form, which both
implementations print (`Refusal.line_out` in `policy_ref.py`, and the same fields of
`we_policy_error_t` in `test_policy`):

```
refusal layer=<l> kind=<k> context=<c> rule=<n> line=<l> col=<c> token="<rendered>" | <fragment>
```

`<fragment>` is the corpus-style message: one of the six fixed strings below, or the table phrase. A
refused program has no case lines. The prose of `what` and `fix` is each implementation's own and is
not compared (it travels on a separate `msg` line).

**Strings.** Six messages are fixed word for word and appear exactly, in `what` or `fix`:

1. `byte 0xHH is not allowed` (with the byte's value);
2. `did you mean GB`;
3. `write country in { RU } or country == RU`;
4. `rpki takes valid, invalid, not-found, unrouted or undetermined`, and the same shape for every
   other attribute's domain: `listed takes none, low, medium, high or critical`, `rpki_reason takes
   asn, length or undetermined`, `asn_rep takes reputable, neutral, suspicious, highly_suspicious or
   undetermined`, `rir takes afrinic, apnic, arin, lacnic, ripe or undetermined`, `asn takes an AS
   number (64496 or as64496) or undetermined`, `country takes a two-letter country code or
   undetermined` (and `registry_rir`, `registry_country` the same as `rir`, `country`);
5. `deny if not <condition>`;
6. the polarity sentence, matched by its clause `that is a fail-closed rule`; in full, `rule N: "is
   unknown" here lets rule M deny exactly when the P plane is missing or stale; that is a fail-closed
   rule`, with the fix `Use it in a log rule, or in an allow rule that no later deny depends on.`

Every other refusal's `what` or `fix` **contains**, byte for byte, the phrase that names it in the table
below with the code formatting removed, so the table is the one source of the strings. The threshold
refusal's fragment is the equivalent rule it prints (`deny if listed >= high`, or `no rule (threshold
off denies nothing)`). The set-undefined refusal's fragment is `undefined in this context or an
enclosing one`, the table phrase without its leading `@set`.

**The compile-time refusals, the complete list.** Each cell is the exact phrase, as `TABLE_PHRASES` in
`policy_ref.py` holds it. The `message` column of `core/testdata/policy/refusals.tsv` holds something
else: the fragment or the rendered instance the compiler prints (`byte 0x00 is not allowed`, `did you
mean GB`), which maps to its phrase by the rules above.

| layer | phrases |
|---|---|
| length | `argument over 2,048 bytes` |
| alphabet | `byte 0xHH is not allowed` (any byte outside §1.2's alphabet, NUL included) |
| lexing | `identifier over 64 bytes`; `a number with a sign`; `a leading zero other than 0`; `more than 10 digits`; `above 2^32 - 1`; `the sentinel 4294967295`; `asdot`; `an unknown country code`; `uk` (fragment `did you mean GB`); `an upper-case keyword or literal`; `a bare literal in expression mode` (fragment `write country in { RU } or country == RU`); `a stray @`; `an unknown operator`; and `byte 0xHH is not allowed` for a byte in the alphabet that belongs to no token class |
| parsing | `trailing input`; `and/or mixed in a chain`; `unbalanced or nested braces`; `a stray }`; `nesting over 16` (parentheses and `not` together, on descent); `over 64 operations in a rule`; `an action without if` (fragment `deny if not <condition>`, decision D1); `an empty expression`; `an unknown attribute or word` |
| typing | `a literal of the wrong class` (fragment: the attribute's `takes` sentence); `an ordered comparison on anything but listed`; `in or == on a bool`; `undetermined on a bool`; `an inline set whose members are not all of one class` (`undetermined` takes the class of the other members, or of the use site when alone; D-y, D-z) |
| sets | `@set undefined in this context or an enclosing one`; `a duplicate definition in one scope`; `a definition shadowing an outer set`; `an empty set`; `a declaration with no members`; `a declared set whose members are not of one class`; `a set used against an attribute of another class` (a declared set's class is known only here, so this check belongs to step 6, not step 5); `more than 1,024 sets in the configuration` (the message names the context that crossed it) |
| program | `over 256 rules in a context`; `over 4,096 operations in a context`; `over 8,448 instructions`; `over 256 KiB of program bytes` (the hot size printed); `allow in a floor program`; `whisper_edge_threshold in a context with policy lines` (the message prints the equivalent rule) |
| polarity | `is unknown whose polarity lets a deny fire because of an outage` (fragment `that is a fail-closed rule`, §2.5) |

`over 8,448 instructions` is unreachable from source text under the operation and rule limits (D-w),
so it fires only in the verifier.

Phrases the table does not carry, which both implementations emit with these exact words (D-k), all
in the parsing layer unless noted: `a non-digit in a number` (lexing), `unbalanced parentheses`, `is
not a boolean`, `only literals inside braces`, `only literals in a set declaration`, `a set declaration
names its set with @`, `is takes unknown or not unknown`, `a mode of off, log or deny`, `a threshold of
off, low, medium, high or critical`, `allow_inferred takes on or off`, `a floor is http-level only`,
and `an unknown directive`. Each is compared by the differential and has a coverage cell, as the
table's phrases do: the generator carries one program per phrase. An address-shaped literal is refused with a fix naming `tenant_allow` and
the server-side `op:policy` write (decision D5, row S3).

**Reported, never refused**, each printed once at config test with the rule named, through
`we_policy_report_t` (one call per report; `code` and `detail` are the machine form the differential
compares, `msg` the sentence). The codes, with the line the differential compares in §5.6:

- `inert-at-config`: a referenced plane is not installed; the rule is inert until a reload, and for an
  inert `allow` the report `inert-allow-exposes` **names the later denies the inert allow would have
  exempted addresses from**;
- `shadowed-by`: a shadowed rule (definition and decision procedure D2, §2.5);
- `tautology`: an `in` whose set is the attribute's whole possible-values mask (D-q);
- `coverage`: an enum `in` matches k of the n values a fresh plane yields (§2.6);
- `duplicate-member`: a member repeated inside one set (harmless, the set is the same);
- `sentinel-negative`: a negative-polarity `!=` or `in` over a sentinel-bearing attribute inside an
  `allow` (D-r);
- `denies-all-absent`: a `deny` or `log` rule that is TRUE on the all-fresh, all-absent record
  (`listed >= none`, `listed < low`, `deny if not tor_exit`, and `deny if not country in { NL }`, which
  is TRUE there because `country` is `undetermined`), printed as `rule N denies every address no plane
  lists`;
- `capturing-allow`: an `allow` whose value set (§2.5) contains U under the outage of any single plane
  it reads and that stands above at least one `deny`, naming the planes, keyed planes flagged;
- `unbounded`: an `allow` whose value set reaches T only through an `is unknown` on an out plane
  (`allow if tenant_allow is unknown` fires for every request while the tenant plane is stale or
  unarmed), and `allow if not tenant_deny`, which reads U for as long as the plane is stale;
- `adds-nothing`: a step-4 `allow` whose condition is a positive occurrence of `tenant_allow` (the one
  bounded occurrence, §3.2), printed as `rule N adds nothing the tenant pre-stage does not already
  allow` (D-s).

A missing plane is never a compile error.

## 2. The bytecode

### 2.1 Program layout

A program is one contiguous read-only block the compiler builds at configuration time and the
evaluator reads through one pointer. Nothing in it is a pointer; every reference is a `u32` byte
offset from the block's start, so a program is position-independent, comparable byte for byte (the
sugar identity, §7) and printable by the disassembler. Every table is 64-byte aligned and padding is
zero (the verifier checks both), so two compiles of one text are byte-identical. **The block carries
no per-context switch**: `mode` and `allow_inferred` are properties of the context that runs the
program, not of the program, and reach `we_decide()` through the context's own `we_ctx_conf_t`
(§3.1); a child context with no lines runs its parent's block under its own mode. The `floor` and
`legacy` flags stay in the header because they change what the compiler accepts.

```
header (64 B, we_program_t)
                   : magic u32 0x31475057 ("WPG1"), version u16 (1), flags u16 (WE_PF_FLOOR 0x0001,
                     WE_PF_LEGACY 0x0002; nothing else), rule_count u16, set_count u16, instr_count
                     u16, op_count u16, plane_mask u8 (bit plane_id - 1, the union of every dep_mask),
                     reserved u8[3], hot_len u32, total_len u32, rules_off, instrs_off, bindings_off,
                     sets_off, hh_off, setdata_off, text_off, text_len (u32 each), reserved u32;
                     the interning key is the sha256 of the whole verified block, computed over the
                     block, never stored in it
rules[]  (we_rule_t, 16 B each)
                   : action u8 (1 allow, 2 deny, 3 log), flags u8 (0x01 inert), dep_mask u8,
                     reserved u8, instr_start u16, instr_count u16, counter u16, src_len u16,
                     src_off u32 (from text_off); the outage class is computed, never stored (§2.5)
instrs[] (we_instr_t, 8 B each, §2.2)
bindings[8] (we_binding_t, 32 B each)
                   : schema_id u8, width u8 (the attribute block: 1 format 1, 10 routing, 6 membership),
                     key6 u8 (IPv6 key bytes: 8 routing and registry, 16 otherwise), inert u8 (absent
                     at config test), stride4 u16, stride6 u16, off4 u8, off6 u8 (the attribute
                     block's offset in the record, per family), reserved u8[2], flag_mask u32,
                     tmpl u8[14] (the no-range template, written unclamped), reserved u8[2]
sets[]  (we_setdesc_t, 16 B each; cold: the verifier and the reports read it, the request path never)
                   : kind u8 (1 country, 2 ASN), has_undetermined u8, levels u8, reserved u8,
                     count u32 (members, undetermined excluded), data_off u32, data_len u32
hold-harmless      : floor blocks only (§3.8), and EVERY configuration has a floor block, with zero
                     rules when the operator wrote none: a 64-byte we_hh_hdr_t, then per family the
                     merged start[] and end[] arrays and the S-tree, as OFFSETS; the we_map_t view is
                     built outside the block by we_program_place()
set data           : country bitmaps of exactly 125 B (padded to 128); ASN S+ trees of 64-B nodes (§4.1)
                     --- end of the hot region (hot_len) ---
canonical text     : every rule's canonical line, LF-terminated, then the declaration of every named
                     set the rules use (sorted by name, members canonical), in a COLD region after
                     every hot table and outside the hot-bytes limit
```

**Limits** the compiler and the verifier refuse: 256 rules per context; 4,096 operations per context;
64 operations per rule; nesting 16 (parentheses and `not` together); 1,024 declared sets per
configuration; 2,048 bytes per argument; 64 bytes per identifier; **8,448 instructions**; **256 KiB of
hot bytes** (`hot_len`: header, rules, instructions, bindings, set descriptors, set data and the
hold-harmless arrays, decision D-u), refused at config test with the hot size, the cold text size and
each set's padded size beside its member count, computed before anything is allocated. The text is
not counted: 256 rules at 2,048 bytes are up to 512 KiB of text the request path never reads, and a
program the limits permit is never refused for cold bytes. The 8,448 is exact under these counting
rules: a unary `not` is an operation; the `NOT` the compiler emits for `!=` and for `is not unknown`
is an instruction but not an operation; so a rule of k operations compiles to at most `2k + 1`
instructions (every operation, one jump per connective operand, the extra `NOT`s, and `END`), and 256
rules at the 4,096-operation ceiling reach 4,096 + 4,096 + 256. The evaluation stack is at most 18 deep
at nesting 16. The default policy (§7) is four rules, four operations, eight instructions.

**Placement and interning.** The block is page-aligned, allocated through the caller's allocator
(`we_alloc_t`), and placed by the module in a region mapped for the interned blocks, so after fork its
pages stay `Shared_Clean` in every worker (row G4). Byte-identical programs across contexts are
**interned on the digest of the whole verified block**, confirmed by `memcmp` before sharing, never on
the text alone (decision D21): with `mode` outside the block the only header bits are `floor` and
`legacy`, and two blocks that differ in them are different programs. Per configuration the compiler
reports the total hot bytes after interning (`we_policy_hot_total()`); the real per-configuration
bound is the configuration's text plus one page-rounded block per distinct program. Instructions are 8
bytes, so the largest legal instruction block is 66 KiB (8,448 × 8); the program's lines are counted
as L2 lines, never as hot lines, in the bound of §3.7.

### 2.2 The instruction set and its encoding

Every instruction is 8 bytes: `op u16, plane u8, off u8, imm u32`. `op` is **one-hot**: one bit per
opcode, tested as `op & WE_OP_X` in a chain of `if`s. An equality chain on one variable is what gcc's
if-to-switch pass and LLVM's SimplifyCFG fold into a `switch` and then a `.rodata` jump table, which
the hot-path gate refuses as a relocation; bit tests on distinct bits are not foldable by either pass.
`plane` is `plane_id - 1` (0..7), the same mapping as `plane_mask` and the memo. `off` is a byte
offset into the **normalised attribute block** of §2.7, which is identical for both families, so no
instruction branches on family and no instruction reads the bindings table except through the fill.

| op | bit | stack | semantics |
|---|---|---|---|
| `BOOL off imm` | 0x0001 | push | `imm` bits 0..7 the mask, bit 8 (`WE_BOOL_POLARITY`) the tenant polarity bit; plane UNKNOWN: U; else `(block[off] & mask) != 0` (no range: the template's zero bits give F). **The tenant exception** (§3.2, decision D16): the compiler sets the polarity bit exactly when the occurrence is `tenant_allow`, positive, inside an `allow`; with the bit set and the plane STALE the instruction reads the stale record within the 48-hour grace and F past it, selected without a branch; every other tenant occurrence, and `tenant_deny` always, reads uniform K3 (definite when FRESH, U when STALE or NULL, F when REVOKED). The verifier checks the bit against the occurrence's polarity (step 9) |
| `SEV off imm` | 0x0002 | push | `listed`: `imm` is the set of levels that read TRUE, bit L for level L; the level is `block[0] & 0x0F` (clamped at fill), read as `none` when the range is `inferred` and the running context's `allow_inferred` is off; plane UNKNOWN: U. Every `listed` test, `listed in {...}` included, is one `SEV` over a level mask (D-ac) |
| `EQ8 off imm` | 0x0004 | push | enum `==`; plane UNKNOWN: U; the no-range template supplies the value (`unrouted` for `rpki`, the sentinel otherwise) |
| `EQ16 off imm` | 0x0008 | push | `country ==` on the already-normalised code; plane UNKNOWN: U |
| `EQ32 off imm` | 0x0010 | push | `asn ==`, `0xFFFFFFFF` for `undetermined`; plane UNKNOWN: U; no range: the template's `0xFFFFFFFF`, so `asn == undetermined` is TRUE there |
| `INSET_ENUM off imm` | 0x0020 | push | `imm` is the mask over the domain (bit 0 is `undetermined`); `(imm >> value) & 1` on the clamped value; plane UNKNOWN: U |
| `INSET_COUNTRY off imm` | 0x0040 | push | `imm` is the block offset of a 125-byte bitmap; the bit of the normalised code (§2.7, at most 999, so byte 124), so no record byte indexes the bitmap; plane UNKNOWN: U |
| `INSET_ASN off imm` | 0x0080 | push | `imm` packs the payload offset (bits 0..17, under 256 KiB), the level count (bits 18..20), `has_undetermined` (bit 21) and **n, the member count (bits 22..31; n ≤ 539 < 1,024)**, from which the level offsets are computed, so the descriptor is never read on the request path; the search of §4.1 runs on **`a' = a - (a == 0xFFFFFFFF)`**, branch-free, so the halving count never includes the `0xFFFFFFFF` padding slots and every node index stays inside the level's real nodes; then **`(a == 0xFFFFFFFF) ? has_undetermined : found`**, branch-free, because the padding key is the sentinel and an unrouted address would otherwise be a member of every padded set; plane UNKNOWN: U |
| `ISUNK` | 0x0100 | push | T when the plane is UNKNOWN (STALE, NULL, or generation 0 off the tenant plane), else F; never U, and never a lookup. On the tenant plane this holds **whatever the bounded reading**: `tenant_allow is unknown` is T whenever the plane is STALE or NULL, including inside the grace where the one bounded occurrence reads a definite value, so the polarity pass, which treats `is unknown` as plane state, stays correct. The differential asserts, over every atom and every state, `ISUNK(x) == (K3value(x) == U)`, where `K3value` is the uniform reading every non-bounded occurrence takes (row X5) |
| `NOT` | 0x0200 | 1 to 1 | swap the pair |
| `AND`, `OR` | 0x0400, 0x0800 | 2 to 1 | the pair formulas of §3.3 |
| `JF imm`, `JT imm` | 0x1000, 0x2000 | peek | forward jump within the rule to instruction `imm` when the top is definitely F (or T); U never jumps; the target is the instruction after the chain's last connective (D-p) |
| `END` | 0x4000 | pop | the rule's value; the rule record says what the action does with it |

`!=` compiles to `EQ* ; NOT`; `is not unknown` to `ISUNK ; NOT`. `imm` means **one thing per
opcode**: a mask for `BOOL`, `SEV` and `INSET_ENUM`, a literal for `EQ*`, a payload offset (packed as
above for the tree) for the other two set kinds, a target for `JF`/`JT`. Jumps are forward-only and
inside the rule that owns them. Short-circuit is sound in K3 because a definite F dominates `and` and a
definite T dominates `or`; an UNKNOWN never jumps, so `U and F` reaches the F. Every instruction that
reads a plane says what it does on UNKNOWN, and the answer is always U, with `ISUNK` the one exception
by design. An ASN set with no numeric member (`asn in { undetermined }`, or a declared set holding only
`undetermined`) compiles to `EQ32` against the sentinel, never to an `INSET_ASN` (decision D34).

### 2.3 Operation and instruction counting

One **operation** is one atom with its lookup, one connective, one unary `not`, or one set test,
whatever the set's size. Jumps, `END`, and the `NOT` the compiler adds for `!=` and `is not unknown`
are **instructions** the compiler inserts, not operations: the operation limit is the operator's budget
and the instruction limit (§2.1) is the machine's. The cost line's `ops` column counts instructions
executed (§5.6): `END` included, every `JF` and `JT` whether or not it jumps; an instruction a jump
skips is not counted; a rule inert at config, or a program under mode `off`, executes nothing.

### 2.4 Binding: the header and the tail, never the digest

At config test the compiler looks for `<plane>.bin` for the eight names in the data directory and
**peeks** each file through `we_policy_env_probe()`: the 192-byte header and its 56-byte tail
(`FORMAT.md` §1), the owner and mode checks, and nothing else. No digest, no record scan. Every file is
opened through `we_open_regular()`, so a FIFO or a device at a plane path is reported present with the
wrong schema and never blocks the probe (row D23). The binding itself (`schema_id`, the two record
strides, the two attribute-block offsets, the key width, the no-range template) comes from a
**compiled-in per-plane table** that is `FORMAT.md` §2 and §3 in C, because every attribute's plane and
offsets are fixed by the format; the file's tail only confirms it, so a file whose header fails still
binds and simply cannot arm. Four outcomes:

- **absent**: every rule referencing the plane is `inert-at-config` and reported with the denies it
  exposes (§1.5); the flag lives in the interned, read-only block, so nothing flips it in place: a
  reload **builds a new block** with the bindings recomputed (row D4);
- **present and the header says what the name says**: bound;
- **present but the header or tail fails** (a wrong magic, a wrong `plane_id`, a `schema_id` the
  attribute does not live in): logged with the `we_strerror` text and the plane is **REFUSED** at run
  time (UNKNOWN), never a configuration error, because a data defect must not stop a reload;
- **named where the path or the trust rule refuses it** (a relative path, a directory others can write,
  the data directory itself for every plane it holds): nothing is opened and the plane is **REFUSED at
  configuration** (UNKNOWN, `-r`), with the reason and its fix on the plane's status line, on its line in
  the configuration file and in one log line, while every other plane binds and serves. The only
  configuration error a binding refuses whole is the snapshot and a `reputation` line both naming the
  reputation plane's file. A configuration test runs the same checks without mapping anything
  (`we_mod_bind_check()`), so it reports exactly what the reload will.

A block is armed only in the environment it was compiled for: `we_program_env_matches()` checks the
block's legacy flag and each binding's inert byte against the environment, and the module calls it
after `we_program_verify()` (row D4). Only a configuration that names the legacy
`whisper_edge_snapshot <file>` synonym (§7, `we_policy_env_t.legacy`) has rules that are **never
`inert-at-config`**: the module arms that path on appearance, so under the synonym the sugar program
binds to `reputation` whatever the directory holds at config test. Without the synonym the threshold
sugar is a rule like any other: where the directory lacks `reputation.bin` at config test it is
`inert-at-config` and reported exactly as `deny if listed >= <level>` would be, and its block is
byte-identical to that rule compiled in the same environment (decision D-af). The arm-time check confirms
`schema_id` and strides against the binding before a plane serves; a mismatch refuses the arm and the
plane is UNKNOWN until a reload.

### 2.5 The polarity pass and the outage classification

**Polarity.** Every atom occurrence gets a polarity within its rule: positive at the root, flipped
under each `not`, unchanged under `and`, `or` and parentheses. Against the program: a `deny` or `log`
condition is positive; an `allow` condition is **negative in every later deny**. The pass refuses an
`is unknown` that is positive in a `deny`, or negative in an `allow` followed by a `deny`, with the
polarity sentence of §1.5; `is unknown` in a `log` rule is allowed in either polarity (decision D10),
and so is one in an `allow` with no later deny. With interleaved contexts the first fault in file
order is reported (D-x). The same pass emits the `sentinel-negative` warning for negative-polarity `==`
or `in` over a sentinel-bearing attribute inside an `allow`: `!=`, a negated `in`, `not (a == x or a ==
y)`.

The pass runs over the **effective program of a context**, which on every server is that context's
own directives: policy lines **replace** inherited lines, never append (decision D13), and a context
with no lines inherits the parent's compiled program. The floor is its own program. So the pass always
sees the whole program a request will run.

**Outage classification**, the compile-time half of the disarm rule, by **value sets**. A single
evaluation with every other atom at its most favourable value finds whether TRUE is reachable, which
decides inert, but it cannot say whether U is reachable, which is what captures means: `allow if
tor_exit or asn in @partners` with tor out evaluates to `U or T = T` under that rule and would be
classed narrowed, while every non-partner request evaluates to `U or F = U` and is captured. So the
classifier takes a rule R and an **out-set** S of planes and propagates, bottom-up over atom
**occurrences** treated as independent variables, the **set of values each subformula can reach**:

- an occurrence on a plane in S: `{U}`; `ISUNK` on a plane in S: `{T}`; `ISUNK` on a plane not in S:
  `{F}` (the one atom that is not monotone: an outage makes it definitely TRUE);
- every other occurrence: `{T, F}`;
- **the tenant plane is seeded from its sub-state**, not from one bit: the classifier and
  `we_program_dependents()` take `tenant_state ∈ {FRESH, GRACE, LAPSED, NULL, REVOKED}`; the one
  bounded occurrence (`tenant_allow`, positive, inside an `allow`, §3.2) gets `{T, F}` under GRACE,
  `{F}` under LAPSED and REVOKED, `{U}` under NULL; every other `tenant_allow` and every `tenant_deny`
  occurrence gets `{U}` under GRACE, LAPSED and NULL and `{F}` under REVOKED; under FRESH every tenant
  occurrence gets `{T, F}`; `ISUNK` on tenant gets `{T}` under GRACE, LAPSED and NULL and `{F}` under
  FRESH and REVOKED; **`tenant_state` alone governs the tenant plane**: its bit in `out_mask` is
  ignored by both implementations, so two inputs never describe one plane;
- `and`, `or`, `not` combine the operand sets pointwise by the K3 tables of §3.3.

The class is read from the root's set: a `deny` or `log` is **inert** under S iff T is not in it,
else **narrowed**; an `allow` **captures** iff U is in it (an allow that evaluates to U ends evaluation
with allow for every request, and so disarms **every later `deny` and `log` whatever their
`dep_mask`**), is **narrowed** iff T is in it and U is not, and is inert otherwise. The dependents of S
are every rule with `dep_mask ∩ S ≠ ∅` plus every `deny` and `log` after a capturing allow. The log
line prints ranges after a head naming the plane, the kind, the out set in plane order and the
tenant state the classification used: `plane tor stale out=tor tenant=fresh: rule 5 allow captures; rules 6-9 disarmed; rule 2 narrowed`.
This is linear in the rule and exact under per-occurrence independence (decision D17).

Three properties, so both implementations hold the same definition:

1. The per-occurrence value-set rule is **normative** in both implementations; neither brute-forces
   atom assignments (2^32 at the 32-atom ceiling of a rule, and different on correlated atoms: `deny if (asn == 1 and not
   asn == 1) or tor_exit` is narrowed per occurrence and inert per atom).
2. **Soundness**, a separate test over cases with at most 8 atoms against an exact brute force over
   atoms: the per-occurrence class is never `inert` where exact is `narrowed`, and **never omits
   `captures` where exact has it**; it may say `narrowed` where exact says `inert`, and may say
   `captures` where exact does not, which are the stated incompletenesses.
3. Monotonicity (F < U < T) is claimed only for `is unknown`-free subformulas.

**Shadowing, the decision procedure** (decisions D2 and D22). The semantic definition (R1 shadows R2
iff R1 is not a `log` and, wherever R2 is TRUE, R1 is TRUE for a `deny` or TRUE-or-U for an `allow`) is
the specification; the report is produced by a **syntactic** procedure both implementations run
identically, which under-approximates it: R1 reports R2 as shadowed iff R1 is not a `log`, R1's
condition is a single positive atom or an and-chain of positive atoms, and each of R1's atoms
**subsumes** a positive atom operand of R2's condition, where R2's condition is a single atom or an
and-chain (whose non-atom operands, such as a parenthesised or-chain, are skipped, D-v). Subsumption is
per attribute: `listed >= a` subsumes `listed >= b` when `a <= b` (the procedure reads `listed >= a`
only, as written, D-q); `x == v` subsumes `x == v`; `x in S1` subsumes `x in S2` and `x == v` when `S1 ⊇
S2` or `v ∈ S1`; a bare bool subsumes the same bare bool, except that a `tenant_allow` atom subsumes
another only when both carry the same polarity bit (a uniform `deny if tenant_allow`, U in GRACE, does
not shadow a later `allow if tenant_allow and asn in @p`, whose bounded occurrence is TRUE in GRACE).
Nothing else is reported, and these details close the procedure: only positive atoms count for
subsumption (`not x`, `x != v` and `is unknown` occurrences are never subsuming or subsumed),
parentheses around a single atom are transparent, a `log` rule is never shadowed (D-ab), an inert rule
neither shadows nor is shadowed (D-aa), and when several earlier rules shadow R2 the **earliest** live
one is named, one line per R2. A tautology is a single `in` whose set equals the attribute's whole
possible-values mask. Both reports are lines the differential compares, because the procedure is
normative.

The classification is **computed at transition time**, on the module's cold tick, by
`we_program_dependents(p, out_mask, tenant_state, ...)`, which is linear in the program; nothing is
stored per rule, so the rule record stays 16 bytes and a two-plane outage is classified against both
planes together (`deny if tor_exit or c2` is narrowed under tor alone and inert under tor and threat).
The module's tick also fires the line when the tenant plane crosses `valid_until_ms + 48 h` (GRACE to
LAPSED), because the bounded occurrence changes value there without any plane state changing.

**Allow short-circuit.** An `allow` at U ends evaluation and marks `allow-by-unknown`, naming the rule
and `unknown_plane`, which is **the lowest-id UNKNOWN plane the rule referenced**, not the cause (an F
may have dominated that plane's U); the differential asserts the field as defined. Every `allow` whose
value set contains U under the out-set of any single plane it reads, and that stands above at least
one `deny`, is reported at config test as a capturing allow naming those planes, keyed planes flagged
in addition, and an `allow` that reaches T only through an `ISUNK` on an out plane is reported as
unbounded in time (§1.5). The one occurrence that does not read U while stale is the positive
`tenant_allow` inside an `allow` (§3.2).

### 2.6 The possible-values mask: report only, never fold

Every enum binding carries a bit mask over the attribute's domain of the values a fresh plane can
produce: `rpki` from `routing` is all five (`rov` 0..3 from records, `FORMAT.md` §3, and `unrouted`
from no range), `rpki_reason` `{undetermined, asn, length}`, `asn_rep` and `rir` their full domains,
`listed` its five levels. The compiler uses it to **report**: the rule's coverage of the attribute's
possible values (`deny if rpki in { invalid not-found }` matches 2 of the 5 states `rpki` can take),
a comparison against a value outside the mask (never TRUE on a fresh plane), and the tautology. It
**never folds** an atom to a constant: a folded F would read F where K3 must read U during an outage,
which in an `allow` turns allow-by-unknown into fall-through to later denies, a fail-closed change;
and masks are arbitrated at arm time, so a mask fixed at compile time can be stale by the time the
plane arms. Today every attribute has one source, so arbitration has no live case. The routing-table
share of a coverage figure is a build-time figure outside the compiler (decision D4).

### 2.7 The memo, the record copy, the pointer lifetime

**Normalised attribute block.** Measured from the end of `end`, the two families lay their attributes
out identically (`FORMAT.md` §3): routing `asn` +0, `country` +4, `rov` +6, `rir` +7, `flags` +8,
`asn_rep` +9 (10 bytes; IPv4 from record offset 4, IPv6 from 8); membership `flags` +0, `source` +4,
`reason` +5 (6 bytes; IPv4 from 4, IPv6 from 16); format-1 reputation is the one `sev` byte. The memo
entry holds that block, at most 14 bytes, and every instruction's `off` indexes it. The fill copies
**exactly the family's block**, with moves that are aligned in the record: IPv4 routing (block at record
offset 4, which is 4-aligned, not 8-aligned) as `u32`, `u32`, `u16`; IPv6 routing (8-aligned) as `u64`
and `u16`; membership as `u32` and `u16`; reputation as one byte. Each move is a constant-size
`__builtin_memcpy`, never a pointer cast (undefined behaviour at the IPv4 offset, and reorderable under
strict aliasing), inlined at `-O1` and above; row M4 runs under `-fsanitize=alignment`. Every move goes
through `WE_TRACE_READ` so the trace counts it, and never past the record. **Order**: on a hit, the
copied record bytes are clamped in place as §1.4 says and `country` is normalised through
`we_country()`; on no range, the plane's template from `bindings[]` is written **unclamped**, so
routing's template `rov = 4` stays `unrouted` (a clamp after the template would turn it into
`undetermined` and `rpki == unrouted` would never match). No instruction branches on no-range. One
fill block sits at the loop head (state `not looked up` and the instruction reads a plane), with exactly
one force-inlined find per key width (`we_find4`, `we_find6_64`, `we_find6`, and the format-1 lookups),
so the inlined lookups appear once each and not once per opcode.

**Slot layout** (`we_memo_slot_t`, 320 bytes, 64-byte aligned), **eight fixed entries indexed by
`plane_id - 1`** (decision D19):

```
line 0 (64 B)  : addr[16] (the canonical key), family u8, flags u8, key_valid u8, pad[5],
                 state[8] u8 at offset 24 (one aligned word, so a reset is two stores), pad[32]
                 states: 0 not looked up | 1 fresh-hit | 2 fresh-no-range | 3 stale-hit |
                 4 stale-no-range | 5 unknown | 6 revoked; the two stale states exist for the tenant
                 plane only, whose stale record step 3.5 and the bounded occurrence read
entry p (32 B) : at 64 + 32·p for plane_id p + 1 (we_memo_entry_t): block[14] u8, lapsed u8 (tenant,
                 stale: now - valid_until_ms > 48 h), pad u8, generation u64 (the map's that produced
                 this copy), range u32 (index or WE_NO_RANGE), family u8, pad[3]
```

The entry's position depends on the plane alone, never on a program: the floor program, the context
program, the tenant pre-stage and a log-phase lazy fill all find a plane's entry at the same place, so
two programs with different `plane_mask`s can share a slot. The state lives in line 0's `state[]`
only. A request touches line 0 plus one line per pair of **filled** entries, so the default policy
touches 1 + 3 lines; an untouched entry costs bytes, not lines. `we_eval_ctx_t` holds **two** slots;
the server-address slot **aliases** the floor slot when the two canonical keys are equal (the common
case with no proxy), so a plane the floor already filled is not looked up again for the context, and
the lookup count is the union of both programs' planes. A slot is re-keyed by comparing the full
address and family, and re-keying resets it; a new request starts unkeyed, so the memo lives for one
request and its log-phase lazy fills, never longer. **Canonicalisation is the core's** (decision D24):
`we_addr_canon()` unmaps `::ffff:0:0/96` to IPv4 and nothing else: the deprecated `::a.b.c.d` form is
**not** mapped, because no stack produces it as a peer address and RFC 4291 excludes `::` and `::1`
from it, so a local `::1` health check stays IPv6 and is never judged as 0.0.0.1. A dual-stack
listener's IPv4 client is thus judged in the IPv4 half of every plane and keeps its hold-harmless
exemption. A canonical address defines every one of its 24 bytes: the sixteen address bytes (IPv4 in
the first four, the rest zero), the family, and the seven pad bytes written zero, so a caller may
compare two `we_addr_t` with `memcmp` (row A1); the evaluator's own key test reads the two words and
the family. `we_decide()` applies the same canonicalisation to both addresses it is handed.

**Pointer lifetime: one handler invocation.** `WE_DEFAULT_GRACE_MS` is 30,000, and the retire
contract assumes a reader holds a map pointer for nanoseconds. A log-phase variable on a plane the
evaluator never touched, after a slow body or a long download, must not dereference a pointer taken at
request start. So:

- the module fills `we_plane_view_t` for the planes the two programs read **and always the tenant
  plane** (steps 2 and 3.5 need it whether or not a program mentions it) **immediately before**
  `we_decide()` (one `we_current()` each) and nulls the views when `we_decide()` returns;
- a later lazy fill (`we_eval_lazy_fill()`) re-takes `we_current()` for that plane in its own handler
  invocation and records the map's `generation` in the entry, so a copy made earlier is still valid
  data (it is a copy) and a reader can tell which generation produced it;
- **state is published with the pointer**, so the evaluator reads no shared mutable byte and the
  disarm needs no atomic: a NULL view means REFUSED or LOADING (the module knows which, for the log
  line); STALE is computed per request from the arm-time `valid_until_ms` (`valid_until_ms` 0 means no
  bound); REVOKED is a heap-allocated `we_map_t` with both families `n = 0`, `plane_id` 8, `base` NULL,
  `h` NULL, generation 0 and a `revoked` flag, built by `we_map_new_revoked()` and published through
  `we_handle_publish_map()`, retired like any map, and checked **before** `we_is_stale()`, which
  reports stale whenever `h == NULL` (decision D25).

**The publish path.** `we_handle_publish_plane()` loads through `we_plane_open()` and is the entry
point the publication state machine uses for every plane, format 1 or 2; `we_handle_publish()` keeps
the format-1 legacy contract and refuses format-2 files (decision D30). The rollback check compares
against the **current map's** generation and against the handle's `high_water`, the highest generation
ever armed. `we_handle_publish_map()` does not reset `high_water` and does not write
`h->generation`, so a re-arm after a revocation must exceed the mark, and a pre-revocation `tenant.bin`
put back by a backup restore, an rsync or configuration management cannot re-arm the revoked allow
list. Across restarts and reloads the module seeds `high_water` from a root-owned, mode 0444
fixed-format file outside the plane directory, `/etc/whisper-edge/state/tenant.high-water`, written by
the refresh when it revokes, so a whole-directory restore of the pre-revocation data directory still
finds the mark and the old file is refused (decision D35, row D3). The file lives in the root-owned
`state/` subdirectory because that subdirectory is the only part of `/etc/whisper-edge` the keyed
refresh unit may write: the policy program beside it stays read-only to the network-facing timer. Its
bytes are ASCII `[1-9][0-9]{0,18}` and a newline, at most 19 digits with no leading zero, 2 to 20 bytes in
all and nothing else; any other content is **malformed**. The refresh never lowers it.

**The revocation mark is three files, read together.** Beside the high-water file the refresh keeps a
tombstone in the plane directory, `.tenant-tombstone`, root-owned, mode 0444, ASCII `<epoch-seconds>
<generation>` and a newline (each field in the high-water digit grammar, except that the generation may
be 0), 4 to 40 bytes. The tenant state is one predicate over `tenant.bin`, the tombstone and the
high-water file, in this precedence: (1) **armed** when `tenant.bin` exists, `we_plane_open()` accepts
it, and its generation is above the high-water value or no high-water file exists, FRESH or STALE by its
`valid_until_ms` and the 48-hour rule; (2) **REVOKED** when the tombstone exists, whatever it holds, or
when a `tenant.bin` the loader accepts sits at or below the high-water value; (3) **NULL** otherwise, a
high-water file alone included; (4) a `tenant.bin` the loader refuses is **no transition**: the module
keeps the state it last published and logs once; (5) a malformed high-water file is likewise **no
transition**. No term reads the plane's feed-name table or any other file. The refresh removes the
tombstone only when it installs a plane above the mark, and on its own transitions to NULL (unenrolling,
re-pinning to another tenant), which also raise the mark first.

**When the module reads the files, and what it does with them.** At configuration load **and at every
tenant plane reload**, never at configuration load only (a first revocation creates the high-water file
after the module has loaded), the module takes a non-blocking shared `flock` on the plane directory,
reads the three files and releases it; when it cannot take the lock (the refresh holds it for a local
multi-file step) it keeps the state it last published and tries at the next reload. Under that one hold:

- for a well-formed high-water value v it raises the handle's mark itself, `h->high_water =
  max(h->high_water, v)`, by an atomic compare-exchange loop on `we_handle_t.high_water`, before any
  publish in that reload, never by a plain store and never lowering it (the core has no setter and needs
  none: its only write of the mark is `we_handle_publish_plane()` arming a plane);
- a malformed high-water file causes no transition: the module keeps the state it last published, logs
  once, counts it, and leaves the mark untouched, so the repaired file is read at the next reload;
- at configuration load nothing has been published on the handle that will serve, so under a malformed
  high-water file the module arms nothing, leaves the mark at 0, logs once, counts it, and publishes NULL;
- when the predicate reads armed, the module opens and publishes `tenant.bin` through
  `we_handle_publish_plane()` inside the same hold as the three reads, so a revocation landing between
  the read and the open cannot arm a revoked plane for one reload;
- when the predicate reads REVOKED and the current map is not already revoked, it publishes
  `we_map_new_revoked()` unchanged, at generation 0, through `we_handle_publish_map()`, on that
  transition only and never at every reload (each publish retires a map, and four retirements inside the
  grace are the retire ring's limit);
- when the predicate reads NULL and the module last published anything but NULL, the reload thread
  starts a fresh handle whose current map is NULL, with `grace_ms` copied from the old handle and its
  `high_water` set to **the high-water file's value** (0 when the file is absent; the file alone, never
  the old mark), and publishes it with a release store through the one pointer by which every request
  reaches the tenant handle, read with one acquire load per `we_current()` call. The old handle is
  neither freed nor reused at the swap, because a reader may still hold it: the reload thread keeps it,
  calls `we_handle_retire()` on it at every reload, and once the grace has passed since the swap (the
  retirer's own rule: `grace_ms` if non-zero, else `WE_DEFAULT_GRACE_MS`) and its retire slots are empty,
  closes and frees its current map with `we_map_close()` and `free()` and only then releases it.

**Exactly one thread per handle** runs this reload step and every publish on that handle, because the
core's own write of the mark when a plane is armed is an unconditional atomic store, not a
read-modify-write, and a second publisher could lower what the compare-exchange raised.

**Generation 0** (decision D-ae). Generation 0 is the revoked map's "nothing armed". The loader refuses
generation 0 in a format-2 header and `we_handle_publish_plane()` refuses it in format 1, so the two
meanings cannot collide on a published plane. What the evaluator reads at generation 0, in
`we_eval_peek()` and `we_eval_fill()`:

- **on the tenant plane, REVOKED**: a definite state with the tenant-revoked mark; `tenant_allow` and
  `tenant_deny` read F, `is unknown` reads F, the pre-stage allows nothing;
- **on every other plane, UNKNOWN**: never REVOKED, and never the file's records or the template read
  as definite, because "nothing armed" is not a measurement: its attributes are undetermined, `is
  unknown` reads T, and a rule testing `listed` does not fire on it.

The legacy request path that predates the evaluator enforces the threshold against a format-1 file
armed at generation 0 as though it were a measurement; that reading is fail-closed, and wrong under
the rule that a missing or unarmed plane never blocks, so the evaluator does not reproduce it. A view
is `{ m }` only: a NULL map where the module meant FRESH reads UNKNOWN (row D5), and there is no state
byte to be out of range.

**Every `we_map_t` is allocated `aligned_alloc(64, ...)`** by the core (decision D28): the struct
`we_handle_publish_plane()` allocates, the REVOKED map, and the hold-harmless view
`we_program_place()` builds (whose 64-byte alignment is inside its page of the mapped region, §3.8).
Every publish path asserts `((uintptr_t)m & 63) == 0` at run time, and `test_core` and `test_policy`
assert it too (row M5).

The two memo slots and the plane views are the only thing the evaluator writes besides `*out`.

## 3. The evaluator on the request path

### 3.1 The API

```c
/* cold: compile, verify, print; `alloc` is the caller's (nginx cycle pool, Apache pconf, LiteSpeed
   malloc/free); the compiler frees on every error path */
int  we_policy_build(const we_policy_source_t *src, const we_policy_env_t *env, const we_alloc_t *alloc,
                     we_policy_build_t **out, we_policy_error_t *err, we_policy_report_t *rep);
int  we_policy_compile(const we_policy_source_t *src, const we_policy_env_t *env,
                       const we_alloc_t *alloc, we_program_t **out,
                       we_policy_error_t *err, we_policy_report_t *rep);
int  we_program_verify(const we_program_t *p, size_t len, we_policy_error_t *err);
int  we_program_print(const we_program_t *p, char *buf, size_t n);          /* the canonical text */
int  we_policy_sugar(uint8_t threshold, const we_alloc_t *alloc, we_program_t **out);   /* §7 */
int  we_policy_sugar_env(uint8_t threshold, const we_policy_env_t *env, const we_alloc_t *alloc,
                         we_program_t **out);                                           /* §7, D-af */
int  we_program_place(const we_program_t *floor, we_hh_view_t *hh);
int  we_handle_publish_plane(we_handle_t *h, const char *path, uint64_t now_ms,
                             we_load_detail_t *detail);                      /* §2.7: format 1 or 2 */
int  we_handle_publish_map(we_handle_t *h, we_map_t *map, uint64_t now_ms);   /* §2.7, REVOKED */
uint32_t we_program_dependents(const we_program_t *p, uint8_t out_mask, we_tenant_state_t tenant,
                               we_rule_class_t *out, uint32_t n);            /* §2.5, transition time */

/* hot, in we_eval.h, header-only, force-inlined */
WE_HOT_INLINE void we_addr_canon(const uint8_t in[16], int in_family, we_addr_t *out);   /* §2.7 */
WE_HOT_INLINE void we_decide(const we_program_t *floor, const we_ctx_conf_t *floor_conf,
                             const we_program_t *ctx_program, const we_ctx_conf_t *ctx_conf,
                             const we_hh_view_t *hh, const we_request_t *req, we_eval_ctx_t *ctx,
                             uint64_t now_ms, we_verdict_t *out);
```

`we_ctx_conf_t` is `{ mode, allow_inferred }`, the context's own, read from the module's merged
per-context configuration and never from the block: the floor runs under the http-level pair, the
context's rules under the context's. **Its domain is the pair** (decision D31): `mode` is 0 (unset), 1
`off`, 2 `log`, 3 `deny`; `allow_inferred` is 0 or 1; a NULL conf, a zeroed conf, and a pair with
either field outside its domain all read as the **shipped default, dry-run `log` with
`allow_inferred` off** (row D6); a half-valid pair is not half honoured. `we_hh_view_t` is the
hold-harmless `we_map_t` view the module built once at configuration load with `we_program_place()`
(§3.8), after `we_program_verify()` and never before it; it lives beside the interned blocks,
read-only after fork, and is passed to every `we_decide()` whether or not either program is NULL.

`we_request_t`: the floor address and the server address, each as `we_addr_t` (canonical, with
family); `hold_harmless_eligible` (the module computes it from the trusted-header walk: clear when the
judged entry was reached past a skipped hop); `acme_exempt` (the module owns the request line); and
`walk`, the walk's outcome the module already decided (`WE_WALK_OK`, `WE_WALK_FLOOR_HEADER_MISSING`, a
trusted peer sent no header and the request is judged as the TCP peer and marked, or
`WE_WALK_NO_ADDRESS`, the client address did not parse and the request is allowed, marked
`allow-by-no-address`). `we_eval_ctx_t`: eight plane views (`{ const we_map_t *m; }` only), the two
memo slots, nothing else. `now_ms` is epoch milliseconds, passed in, never read. The evaluator lives in
`we_eval.h`, which includes `whisper_edge.h` and `we_policy.h` (decision D6).

**What the hot-path gate proves about `we_decide()`, exactly**: no call, no relocation (so no global,
GOT, PLT, jump table or outline atomic), no atomic or fence instruction, no local on the stack, a frame
under 256 bytes. It cannot see a store **through** a pointer; the plane buffers are writable copies and
the program block is ordinary memory. So the claim "no store outside `*ctx` and `*out`" is proven by
two things together: the gate for the classes it can see, and `test_policy` plus the differential
running with the program block, the hold-harmless view and every plane buffer under
`mprotect(PROT_READ)`, so a stray store faults (row H3).

**The frozen API summary.** Everything public in `we_policy.h`, the evaluator's entry points in
`we_eval.h`, and the four `whisper_edge.h` entry points the language added or depends on.

Types, `we_policy.h`:

| type | what it is |
|---|---|
| `we_program_t` | the 64-byte block header (§2.1) |
| `we_rule_t` | a 16-byte rule record |
| `we_instr_t` | an 8-byte instruction (§2.2) |
| `we_binding_t` | a 32-byte per-plane binding, `FORMAT.md` §2 and §3 compiled in |
| `we_setdesc_t` | a 16-byte set descriptor, cold |
| `we_hh_hdr_t` | the 64-byte header of a floor block's hold-harmless arrays |
| `we_ctx_conf_t` | a context's `mode` and `allow_inferred`, never the block's |
| `we_addr_t` | a canonical address: IPv4 in `b[0..3]` with the rest zero, or IPv6 in `b[0..15]`, and the family |
| `we_request_t` | the two addresses, `hold_harmless_eligible`, `acme_exempt`, `walk` |
| `we_memo_entry_t` | one 32-byte memo entry (§2.7) |
| `we_memo_slot_t` | one 320-byte memo slot: line 0 and eight entries |
| `we_plane_view_t` | a plane view, the map pointer only |
| `we_eval_ctx_t` | the per-request context: eight views and two slots |
| `we_hh_view_t` | the hold-harmless table as a 64-byte aligned `we_map_t` view into the floor block, with the floor's bindings |
| `we_verdict_t` | the verdict (§3.4), the evaluator's parked scratch (D9), and the trace counters in a `WE_TRACE` build |
| `we_alloc_t` | the caller's allocator: `alloc(ud, size, align)` and `free(ud, p)`; NULL means the C library |
| `we_policy_directive_t` | one directive: kind, context path, argument bytes and length |
| `we_policy_source_t` | a configuration in file order, and which program a compile returns |
| `we_policy_env_t` | the plane environment at config test: `present`, `schema_ok`, `legacy`, `canonical` |
| `we_policy_error_t` | a refusal (§1.5) |
| `we_policy_report_line_t` | one report: context, kind, rule, set name, `code`, `detail`, `msg` |
| `we_policy_report_t` | the report callback and its user data |
| `we_policy_build_t` | an opaque compiled configuration |
| `we_tenant_state_t` | the tenant sub-state: FRESH, GRACE, LAPSED, NULL, REVOKED |
| `we_rule_class_t` | one rule's outage class, dependency bit and root value set |
| `we_attr_info_t` | one attribute's name, plane, plane id, class, block offset, bool mask and sentinel flag |
| `we_rule_counters_t` | the per-rule counters, sharded per thread (§3.6) |

Functions, `we_policy.h` (every one cold; none is called on the request path):

| function | what it does |
|---|---|
| `we_policy_env_probe(dir, env)` | peeks the eight plane files in `dir`: header, tail, owner and mode, nothing else (§2.4) |
| `we_policy_error_format(e, buf, n)` | renders a refusal as the module prints it: `rule N, line L, column C: near "token": what. fix` |
| `we_policy_kind_name(kind)` | the directive kind's name (`policy`, `set`, `floor`, `threshold`, `mode`, `allow_inferred`); `?` for any other value |
| `we_policy_build(src, env, alloc, out, err, rep)` | compiles a whole configuration: every context's program, the floor (always), the sugar and the modes; interns identical blocks; any refusal refuses the build |
| `we_policy_compile(src, env, alloc, out, err, rep)` | as the build, returning the one program `src` selects in its own allocation; `*out` NULL with `WE_POLICY_OK` when the context runs none |
| `we_policy_build_free(b)` | frees a build |
| `we_policy_program(b, context)` | the program a context runs: its own lines, or the nearest enclosing context's; NULL for none |
| `we_policy_floor(b)` | the floor block, never NULL in a build |
| `we_policy_conf(b, context)` | the context's conf: its own mode, or the nearest enclosing one's |
| `we_policy_block_count(b)` | distinct blocks after interning |
| `we_policy_hot_total(b)` | their hot bytes in total |
| `we_program_verify(p, len, err)` | the twenty-two checks of §5.5 in order; 0 on accept, else `-(step)` |
| `we_program_print(p, buf, n)` | the canonical text, every rule's line LF-terminated; its length, or -1 when `n` is too small |
| `we_program_print_sets(p, buf, n)` | the canonical declarations of the named sets the rules use |
| `we_program_disasm(p, buf, n)` | an instruction listing |
| `we_policy_sugar(threshold, alloc, out)` | the program `whisper_edge_threshold` means (§7), compiled as though every plane were present and no synonym named; threshold 0 is the empty program. It is the block for the equivalent line a module logs and for byte identity with the written rule (row G1); it matches only an all-present, non-legacy environment |
| `we_policy_sugar_env(threshold, env, alloc, out)` | the same program compiled for `env`, exactly as `we_policy_build()` compiles a context holding the threshold: the block a module arms. Outside the legacy synonym its rule is inert where reputation is absent (D-af). `env` NULL is every plane present |
| `we_program_free(alloc, p)` | frees a program from `we_policy_compile()`, `we_policy_sugar()` or `we_policy_sugar_env()` |
| `we_program_size(p)` | the block's `total_len`, the length a caller compares or copies |
| `we_program_place(floor, hh)` | builds the hold-harmless view from a verified floor block; -1 for a block that is not a floor or an unaligned `hh` |
| `we_program_env_matches(p, env)` | 0 when the block was compiled for this environment (legacy flag and inert bytes), else -1 and the block must not be armed |
| `we_program_dependents(p, out_mask, tenant, out, n)` | classifies every rule against an out-set and tenant sub-state (§2.5); returns the dependent count |
| `we_program_dependents_line(p, out_mask, tenant, what, buf, n)` | the one transition log line, `<what>: <classes>`; a module passes the head as `what`: `plane tor stale out=tor tenant=fresh: rule 5 allow captures; rules 6-9 disarmed; rule 2 narrowed` |
| `we_attr_count()` | the number of attributes, 25; for tools only, never the request path |
| `we_attr_info(i, out)` | attribute `i`'s description; -1 for an index out of range; tools only |
| `we_attr_render(i, block, state, buf, n)` | attribute `i`'s value from a memo block under a memo state, as the language writes it (`true`, a level, an enum word, a decimal ASN, an alpha-2, `undetermined`), or the state where it decides (`unread`, `unknown`, `stale:<value>` and `lapsed:<value>` on the tenant plane, `revoked`), as section 3.9 tables it; tools only, the request path renders through `we_attr_render_fast()` in `we_module.h`, byte-equal |
| `we_verdict_format(v, verdict_line, cost_line, n)` | the verdict's two lines in the differential's format (§5.6); `cost untraced` outside a `WE_TRACE` build; tools only |
| `WE_VERDICT_LINE_MAX` | 2,560: a buffer of this many bytes always holds either line `we_verdict_format()` writes; a smaller one is reported (-1) and still terminated |
| `we_rule_counters_new(p, shards, now_ms)`, `we_rule_counters_free(c)` | allocate and free the sharded counters |
| `we_rule_count(c, shard, rule)` | counts one firing in this thread's shard: a relaxed load and a relaxed store, never a locked add (inline) |
| `we_rule_counters_sum(c, rule)` | a rule's count over every shard |
| `we_rule_counters_write(c, p, dir, now_ms)` | sums the shards into `<dir>/<pid>-<16 hex>.rules.cnt` (the pid and a digest of the process's identity) by an O_EXCL temp file and rename, on the refresh tick only |

Functions, `we_eval.h` (hot, header-only, force-inlined):

| function | what it does |
|---|---|
| `we_addr_canon(in, in_family, out)` | unmaps `::ffff:0:0/96` to IPv4 and maps nothing else; writes every byte of the `we_addr_t`, the seven pad bytes as zero, so two canonical addresses compare equal by `memcmp` exactly when they are the same address (row A1) |
| `we_decide(floor, floor_conf, ctx_program, ctx_conf, hh, req, ctx, now_ms, out)` | the whole decision in the fixed order of §3.2; writes `*out` and `*ctx` only |
| `we_eval_lazy_fill(ctx, hh, which, plane_id, now_ms, out)` | a later fill in its own handler invocation, for a plane the evaluator never touched |

The evaluator's internal steps (`we_eval_prestage`, `we_eval_run`, `we_eval_fill`, `we_eval_peek`,
`we_eval_stale_tenant`) are inline helpers that the hot-path gate's wrappers hold one at a time; they
are not a calling interface.

Functions, `whisper_edge.h`, that the language depends on:

| function | what it does |
|---|---|
| `we_handle_publish_plane(h, path, now_ms, detail)` | the publish path for every plane, format 1 or 2; refuses a rollback against the current map and `high_water`, and generation 0 in either format |
| `we_handle_publish_map(h, map, now_ms)` | publishes the REVOKED tenant map; keeps `h->generation` and `high_water` |
| `we_map_new_revoked()` | the REVOKED tenant map, `aligned_alloc(64)` and filled |
| `we_open_regular(path, why)` | opens a file that must be regular without ever blocking on a FIFO or a device: stat, refuse a non-regular target, open `O_NONBLOCK`, fstat and refuse again, clear `O_NONBLOCK`; every loader opens a plane only through it |

### 3.2 The fixed order

`we_decide()` runs this order; both programs may be NULL (a context with no lines and no floor
evaluates steps 1 to 3.5 and default-allows), and the hold-harmless table is the configuration's
`we_hh_view_t`, which exists whether or not any program does (§3.8):

0. **No address.** When the walk could not parse the client address (`WE_WALK_NO_ADDRESS`), the
   request is allowed at step 1, marked `allow-by-no-address`. A missing floor header marks the
   verdict `floor-header-missing` and evaluation continues on the TCP peer.
1. **Fixed exemptions**, data-free: the hold-harmless lookup on the floor's address, applied only
   when `hold_harmless_eligible` is set; then `acme_exempt`. A hold-harmless floor address ends the
   request, `allow-by-hold-harmless`, only when the server judges the same address: the same canonical
   address, or a server slot with no address (step 4). Otherwise it exempts the floor's steps 2 to
   3.5 (the tenant entry is not filled and the floor's program does not run), and step 4 judges the
   server's address by the context's rules with no exemption of its own. This is the only
   hold-harmless lookup a request makes. `acme_exempt` exempts the request either way,
   `allow-by-acme`.
2. **Tenant allow** when the tenant plane is FRESH: `tenant_allow` on the floor's address,
   `allow-by-tenant`. The pre-stage fills the tenant entry on the floor's address here whenever the
   tenant plane has a map, so the lookup happens once whether step 2 or step 3.5 then reads it (D-m).
   A REVOKED tenant plane marks `tenant-revoked`.
3. **The floor**, http level only, `deny` and `log` only, under `floor_conf` (the http-level mode and
   `allow_inferred`), on the floor's address. Mode `off` skips it.
3.5. **Stale tenant allow**, on the **floor's** address: when the tenant plane is STALE and, having
   confirmed staleness first so the arithmetic cannot wrap, `now_ms - valid_until_ms <= 48 h`
   (inclusive), `tenant_allow` ends evaluation with allow after the floor. A STALE tenant slot still
   performs the lookup, or this step has no record to read. REVOKED skips the step.
4. **The context's rules**, first match wins, on the server's address, under `ctx_conf`: mode `off`
   evaluates nothing here (the trace build asserts `ops_executed == 0` for step 4); mode `log`
   downgrades every `deny` to `log` while keeping the action byte `deny` (§7). Default allow. Step 4
   takes no hold-harmless exemption: the server's address is the server's `realip` result, which a
   header supplies, and no address a header carries earns one. A server slot with no address (a family
   other than 4 or 6, which a unix-socket listener with no `realip` hands in, or the unspecified
   address) names the floor's address: the server has no opinion of its own about who connected, so
   step 4 judges the floor's address, on the floor's slot. Read as `::` it would be judged as an address
   no feed lists: a rule that denies a listing would never fire, and a rule that denies unless an address
   is allowed would fire for every client.

Steps 1 to 3.5 never read the server's `realip` result; they read the floor address the module
computed from the connection and the trusted-proxy walk (decision D7).

**Amended 2026-10-18, revised 2026-10-19 before release: a hold-harmless floor address exempts the
floor's steps, and ends the request only when the server judges the same address.** Both revisions
were made before the edge modules' first release, so no release carried the earlier order. In that
order step 1's exemption ended evaluation whatever the server's address. A live run found what that
did behind nginx `realip` or Apache `mod_remoteip` trusting 127.0.0.1 with no
`whisper_edge_trusted_proxy`: the floor's address is the loopback peer, which is hold-harmless, so step 4
never judged the client and a DROP-listed `X-Forwarded-For` source was allowed with
`$whisper_edge_verdict` reading `high,drop`, while the same address connecting directly was denied.
Every site behind a same-box proxy would have failed open for every listed client. Step 4 has no hold-harmless
lookup of its own, because the server's address comes from a header: on a vhost that trusts
`X-Forwarded-For` from anyone, an exemption there would let a client naming 127.0.0.1, 8.8.8.8 or
10.0.0.1 skip an allowlist rule such as `deny if not tenant_allow` that an arbitrary forged address
cannot, whatever `hold_harmless_eligible` says. So the amendment closes the fail-open and adds no
exemption a header can reach. The one hold-harmless lookup is still step 1's, on the floor's address,
gated by `hold_harmless_eligible`, and steps 1 to 3.5 still never read the server's `realip` result. A
header can at most name the floor's own address, or no address (0.0.0.0, `::`), which names the floor's
too; either gets back the exemption every request behind that floor had before the amendment. A genuine hold-harmless client behind a proxy is still allowed by the
default policy, because the feed never lists a hold-harmless prefix (§3.8): it is allowed as unlisted,
not as exempt, and an operator's own rules apply to it as written. The cost is unchanged: one
hold-harmless find a request, and a hold-harmless floor before a distinct server address does less work
than the bound of §3.7 prices (no tenant find, no floor run), measured by the cachegrind slot
`evaluator-hh-key2`. The test rows are `[F6]` in test_policy, each control caught there:
`WE_TEST_HH_FLOOR_ENDS_ALL`, the old order; `WE_TEST_HH_SERVER_EXEMPT`, a hold-harmless lookup at step
4; `WE_TEST_HH_RAW_COMPARE`, the two forms of one address compared as bytes;
`WE_TEST_SERVER_UNSET_KEYED`, a server slot with no address judged as `::`. The generated differential
holds the same through its `proxy` coverage cells, a hold-harmless floor before a distinct server and a
hold-harmless server address judged by the rules.

**The tenant atoms in step 4: bounded only where F can at most remove an exemption** (decision D16).
Under uniform K3 a stale tenant plane makes `allow if tenant_allow` U for every address, an unbounded
universal allow for as long as the plane is stale. Applying the pre-stage's bounded table to every
tenant occurrence instead opens a fail-closed path: past the lapse `tenant_allow` would read F
everywhere, so `deny if not tenant_allow`, the natural allowlist-only rule, would deny the whole site
49 hours into a feed outage, and inside the grace an address added after the plane went stale would
read a definite F from the stale record and be denied. The bounded reading is right exactly where F
can only remove an exemption, a **positive occurrence of `tenant_allow` inside an `allow`**, and wrong
everywhere else. So, on the server's address:

| tenant plane state | `tenant_allow`, positive inside an `allow` (the bounded occurrence) | every other `tenant_allow` occurrence | `tenant_deny` |
|---|---|---|---|
| FRESH | definite, from the record | definite, from the record | definite, from the record |
| STALE, `now_ms - valid_until_ms <= 48 h` (GRACE) | definite, from the stale record | U | U |
| STALE, past 48 h (LAPSED) | F (lapsed) | U | U |
| REVOKED | F | F | F |
| NULL (REFUSED or LOADING) | U | U | U |

The compiler knows every occurrence's polarity, so the bounded reading is one bit in the tenant
`BOOL`'s `imm` (§2.2), checked by the verifier and selected without a branch; it is not an evaluator
mode. With it the lapse can still stop an allow firing and can no longer make an allow capture or a
deny fire: `deny if not tenant_allow` past the grace reads `not U = U` and does not fire, and the later
denies that F exposes under a positive allow are the lapse doing its job. `tenant_deny` keeps the
table's column: a stale deny is unknown. `tenant_allow is unknown` reads T whenever the plane is
STALE or NULL whatever the bounded reading (§2.2), so `allow if tenant_allow is unknown`, the
unbounded stale allow one token away, is visible to the polarity pass as what it is and is reported as
unbounded in time (§1.5). K3 stays uniform for every other atom. The compiler reports a step-4 `allow`
on a positive `tenant_allow` as adding nothing the pre-stage does not already allow: with equal
addresses step 2 or 3.5 has already allowed every address the rule would match, and with distinct
addresses the rule allowlists the address the server's `realip` derived. The module logs the crossing
of `valid_until_ms + 48 h` as a transition (§2.5, §3.5).

### 3.3 K3 as it is implemented

Kleene's strong three-valued logic, as a (true, false) bit pair per stack entry. The stack is two
`uint64_t`, `T` and `F`; the top is bit 0 of each; a push shifts both left. TRUE = (1, 0), FALSE =
(0, 1), UNKNOWN = (0, 0); (1, 1) is unreachable and the trace build asserts `T & F == 0` after every
instruction (row K6). Over- and underflow are memory-safe by construction (a shift of two registers),
so the verifier's stack pass (§5.5) is about meaning, not memory.

| op | t | f |
|---|---|---|
| `and` | `t1 & t2` | `f1 \| f2` |
| `or` | `t1 \| t2` | `f1 & f2` |
| `not` | `f` | `t` |

| | result | | result |
|---|---|---|---|
| `not U` | U | `U and T` | U |
| `U and F` | F | `U or F` | U |
| `U or T` | T | `not not U` | U |

Chains reduce left-associatively (§1.1), so a nesting level holds one pending value and the depth bound
is 18 at nesting 16; the compiler computes the exact depth per rule and the verifier recomputes it by
abstract interpretation (§5.5). `deny` and `log` act only on TRUE; `allow` acts on TRUE, and at
UNKNOWN ends evaluation with allow marked `allow-by-unknown`; `log` records and continues. There is no
fail-closed path.

### 3.4 The per-rule verdict

`we_verdict_t`, written into `*out`: `step` (the step that decided: step 1, 2, 3, 3.5 or 4, the last including
its default allow), `action` (the deciding rule's action byte, allow or deny), `program` (floor,
context, or none), `reason` (`allow-by-unknown` with `unknown_plane` as §2.5 defines it,
`allow-by-hold-harmless`, `allow-by-acme`, `allow-by-tenant`, `allow-by-no-address`, or a rule's TRUE),
`marks` (`floor-header-missing`, `tenant-revoked`), `enforce` (1 for a deny under mode `deny`), `rule`
(1-based, 0 for the pre-stage and the default allow), **two** 256-bit `log_fired` bitmaps (floor and
context; bit r - 1 for every `log`, and every downgraded `deny`, that fired), the evaluator's parked
scratch (`sc`, decision D9; a caller never reads or clears it), and the cost counters the trace build
reads (`ops_executed`, `ops_floor`, `ops_ctx`, `jumps_taken`, `set_probes`, `jumps[2]`, `probes[2]`,
`lookups[2][8]`), which exist only in a `WE_TRACE` build, like `WE_TRACE_READ`. The `$whisper_edge_*`
variables read the memo copies, never a mapping, and `$whisper_edge_rule` renders the rule's canonical
text from the block.

### 3.5 The disarm rule as a state machine

The module owns plane transitions and publishes state with the pointer (§2.7); the core refines ARMED
into FRESH or STALE per request.

| state | published as | atoms on the plane | `is unknown` | log line (module, on the edge) |
|---|---|---|---|---|
| ABSENT at config test | `inert` in `bindings[]` | the rule is skipped; counted under `inert` | n/a | once at config test, per rule, naming the denies it exposes |
| FRESH | a map, `valid_until_ms` 0 or `now_ms <= valid_until_ms` | definite values (§1.4) | F | none |
| STALE | a map, `now_ms > valid_until_ms` | U | T | once per transition, from `we_program_dependents(p, out_mask, ...)` with ranges after the head: `plane tor stale out=tor tenant=fresh: rule 5 allow captures; rules 6-9 disarmed; rule 2 narrowed` |
| STALE past 48 h (tenant plane only) | the same map, `now_ms - valid_until_ms > 48 h` | the bounded occurrence reads F; every other occurrence U | T | once, at the crossing, from `we_program_dependents(p, out_mask, LAPSED)` |
| REFUSED | NULL, nothing ever armed | U | T | once, with `we_strerror` and the record index |
| LOADING | NULL, first verification in flight | U | T | none (the master verifies before fork) |
| generation 0, not the tenant plane | a map armed at generation 0 | U | T | as REFUSED |
| REVOKED (tenant plane) | the heap-allocated empty map with `revoked` set and generation 0, through `we_handle_publish_map()` | tenant bits F, pre-stage empty, `tenant-revoked` | F | once |
| any, then a fresh file verifies | a new map | definite again | F | once: `plane P armed, generation G` |

"Exactly the rules that depend on it, once, nothing else": the dependents are §2.5's set under the
**whole out-set** (so two outages are classified together); "once" is the module's transition edge;
"nothing else" is asserted by the differential comparing the **final verdict** against the reference
interpreter over every plane-state vector, not against `dep_mask`, because a capturing allow changes
verdicts of rules whose `dep_mask` excludes the plane (row D1). The state space is reduced before
enumeration: for the seven non-tenant planes STALE, REFUSED, LOADING and generation 0 are one class
(U) and ABSENT is config-time, so each has two states; a stale non-tenant plane is never looked up
(D-l); the **tenant plane enumerates five**: FRESH, STALE within the 48-hour grace, STALE past it, NULL
(REFUSED or LOADING), REVOKED, because steps 2, 3.5 and the step-4 atoms (§3.2) distinguish them. A
program referencing k non-tenant planes therefore has 2^k · 5 state vectors, and the generator prints
the case count and runtime.

### 3.6 Counters

Per rule, never per range. The evaluator **increments nothing**. The module increments after the
verdict, for the rules that fired (the deciding `deny` or `allow`, every `log` rule in the two bitmaps,
`allow-by-unknown` under its rule), and stores nothing on the default-allow path (decision D3). In
Apache's worker and event MPMs one process's threads share the counters, so `we_rule_counters_t` is
**sharded per thread**: each shard is `rule_count` entries of `uint64_t`, 64-byte aligned and padded to
a line multiple, with **one writer per shard**, so an increment is a relaxed load plus a relaxed store
(a plain add on x86-64 and aarch64, tear-free for the reader on 64-bit targets), never a locked add.
The window header (`started_ms`, `generation`, the shard count) has its own line;
`we_rule_counters_write()` sums the shards on the refresh tick into the `.cnt` file
`whisper-edge-summary` reads, in a `rule` section beside the range section. The shard index is the
thread's, supplied by the module (nginx and LiteSpeed: one shard per worker; Apache: a per-thread
index).

### 3.7 Hot-path constraints and the composed per-request bound

By construction and by disassembly: no call (the record copy is fixed-width moves, the set search a
fixed-iteration loop, §4.1), no atomic, no fence, no `switch`, no `.rodata` reference on the legs named below (every table the
evaluator reads is in the program block, a plane, or the caller's context), no local on the stack on
the legs named below, a frame under `STACK_MAX_EVAL` 256 bytes, no allocation, no syscall.

**Where "no local on the stack" holds, measured.** The hot-path gate runs gcc 13 and 14 and clang 18,
19 and 20 on aarch64 and x86_64, at `-O`, `-O2`, `-Os` and `-O3`, with the base flags, the Ubuntu and
Fedora distribution module sets, and on x86_64 `-march=x86-64-v3`, `-mtune=znver3` and
`-mtune=znver4`. That result on the Zen and x86-64-v3 legs depends on the rank searches' descent staying
rolled: `whisper_edge.h` wraps its three loops in `WE_NO_UNROLL` (clang's `loop unroll(disable)`, empty
for other compilers), because clang unrolled them under those tunings and the unrolled body
spilled in `hpfloor`, `hpeval`, `hpeval_ops` and two fill rows. `WE_NO_UNROLL` is a header
macro of the `WE_` namespace, not an API. Every evaluator row holds zero locals on every one of those legs except the
frame-pointer ones on clang x86_64, which the gate holds exactly, per level, as these bytes of locals:

| compiler and set | `hpeval` | `hpeval_ops` at `-O` | `hpeval_ops` at `-O2`, `-Os`, `-O3` |
|---|---|---|---|
| clang 18, Ubuntu x86_64 | 8 | 8 | 12 |
| clang 19 and 20, Ubuntu or Fedora x86_64 | 8 | 16 | 4 |

(clang 18 does not accept the Fedora set; every other row of every other leg is 0.) Both sets carry `-fno-omit-frame-pointer`, which
takes `%rbp`, and the instruction loop then needs one register more than x86_64 has left. Bringing
those to zero would mean parking the loop's state around every atom, a memory round trip on every
instruction, so the claim is this measured one instead. aarch64 holds zero everywhere.

The modules' decision (`we_mod_decide()`, the gate's `hpmod` row) holds zero locals on aarch64 under both
compilers and on x86_64 at `-O2`, `-Os` and `-O3` with gcc, every operand parked in the scratch. These x86_64
legs keep a spill, which the gate holds exactly and every change to the function re-measures:

| compiler and set | `hpmod` |
|---|---|
| gcc 13, every x86_64 set | 8 at `-O` (the verdict pointer kept across the rule loop), 0 at `-O2`, `-Os`, `-O3` |
| gcc 14, every x86_64 set | 8 at `-O` (the same verdict-pointer spill), 0 at `-O2`, `-Os`, `-O3` |
| clang 18, Ubuntu x86_64 | 16 at every level (`-fno-omit-frame-pointer` takes `%rbp`) |
| clang 19, Ubuntu and Fedora x86_64 | 16 at every level (the same) |
| clang 20, Ubuntu and Fedora x86_64 | 16 at every level (the same); at `-march=x86-64-v3` 0, with 14 constant-pool relocations at `-O2`, `-Os` and `-O3` |

nginx's own default is `-O`, so the gcc row is on a shipping path. `make check` holds this table, the
header's opening comment and the gate's expected-locals table to each other (`locals-claims.sh`).

**Where "no `.rodata` reference" holds, measured.** On every leg the gate runs but one. With clang 20
and `-march=x86-64-v3`, at `-O2`, `-Os` and `-O3` (not `-O`), the SLP vectoriser packs the K3 pair
(T, F, two 64-bit bit stacks, §3.3) into one xmm register in `hpeval` and `hpeval_ops`, and the lane
masks it needs come from a constant pool: `R_X86_64_PC32` relocations to `.rodata` and its `.LCPI`
entries, 14 in `hpeval` and 7 in `hpeval_ops`, which the gate holds exactly. The constants are read-only, are not evaluator tables, and
change no result; a loop pragma cannot reach them because no loop is vectorised, and keeping the pair
out of vector registers by hand would contort the interpreter's hottest lines for one tuning, so the
claim is this measured one instead. The candidate fix is a per-function target attribute on the two
evaluator entry points that keeps the AVX2-level codegen out of them, measured before it is adopted. clang 18 and 19 at the same flags, and every other leg, reference
no `.rodata`.

**Decision D9: no `locals-ok`, scratch into `*out` first.** Where a plane lookup would leave more
values live than a toolchain has registers, the evaluator parks them in the verdict's scratch block,
`out->sc`, and reads them back after the search behind a compiler barrier that emits no instruction,
so only `out` crosses a search and the search has every other register. The loop's invariants are read
from `*out` where they are used, through volatile lvalues, never held in a register across the
program; whether a step decided is read back from the verdict, not carried as a return value. A spill
to the stack is what the hot-path gate refuses. The parking is not free: the volatile reloads and the
parked state measure more data references under cachegrind than the same loop holding its state in
registers. That is the price of the gate's zero-locals claim, paid in loads from the verdict's own
scratch block, and it is taken knowingly.

**What one request costs.** The bound is **composed over the whole request**, printed at config test
in two forms (warm: `maxColdLines`; cold: `maxLines64`, with `maxLines128` beside it), and held per
request by the trace build against a data-free model per outcome class (`FORMAT.md` §5):

```
lookups(request) = equal keys:    |floor_planes ∪ {tenant} ∪ ctx_planes|          [one aliased slot]
                   distinct keys: |floor_planes ∪ {tenant}| + |ctx_planes|          [two slots]
                   (the larger is the printed worst case; row M1 holds both forms)
lines(request)   = Σ_{p filled on the floor address} maxLines(p)
                 + Σ_{p filled on the server address, distinct keys only} maxLines(p)
                 + HH(d)                                                 [the hold-harmless lookup, §3.8: d + 2 per family]
                 + Σ_{(p, address) filled} D(family)                     [descriptor lines, PER FAMILY of a we_map_t allocated
                                                                         aligned_alloc(64): f4 (bytes 0..95) reads lines {0, 1}
                                                                         plus valid_until_ms (offset 296, line 4): 3; f6
                                                                         (96..191) reads {1, 2} plus line 4: 3; f6w (192..287)
                                                                         reads {3, 4} and valid_until_ms shares line 4: 2;
                                                                         plus one bindings[] line for the template]
                 + Σ_{INSET_ASN executed} levels(set) + Σ_{INSET_COUNTRY executed} 1   [§4.1]
                 + L_prog                                                [instruction lines, as L2 lines: ceil(8 · instr_count / 64)]
                 + W(ctx)                                                [write lines: the views (8 · 8 B, 1 line); per slot
                                                                         1 + |{floor((plane_id - 1) / 2) : filled}|, because two
                                                                         32-byte entries share a line (the default policy fills
                                                                         four entries, reputation, tor, rpki-unreachable and
                                                                         tenant, in 1 + 3 lines); the verdict with its two
                                                                         32-byte bitmaps]
instructions(request) ≤ Σ_{k ∈ atom kinds} count(k) · c(k)              [the form of the cost. gate/cost-model.py solves it on
                      + count(NOT) · c(NOT)                              an identifiable basis: with no jump taken, links =
                      + links_and · c_and + links_or · c_or              atoms - rules visited, so each atom kind is priced
                      + rules_visited · c_rule                           per outcome with its `and` link, beside NOT, the `or`
                                                                         link's extra, each way a rule ends, and a taken jump]
                      + Σ_{schema} fills(schema) · c_fill(schema)         [per schema: routing, membership, format 1; the
                                                                         plane-count slope MINUS the find]
                      + c_prestage                                       [the pre-stage without the tenant find and without
                                                                         the hold-harmless find]
                      + L_HH                                             [the hold-harmless find, at its maximum outcome class]
                      + Σ_{fills} L(p)                                   [every plane find once, the tenant's included]
                      and ≥ 0.8 × the same sum                           [tightness]
```

Each lookup is counted once: the find in `L(p)` (or `L_HH`), its surrounding fill in `c_fill`, and
the pre-stage's non-lookup work in `c_prestage`. `maxLines(p)` and `maxColdLines(p)` are the plane
files' own per-file bounds (`FORMAT.md` §5; for the live-shaped files IPv4 radix-18 probes 7, cold 5;
IPv6 rank-64s probes 10, cold 6, `core/bench/expected-counts.tsv`). The descriptor figures
rest on `sizeof(we_fam_t) == 96` and `offsetof(we_map_t, f4/f6/f6w) == 0, 96, 192`,
`offsetof(we_map_t, valid_until_ms) == 296`, pinned by static assertions, and on every `we_map_t`
being 64-byte aligned (§2.7), so the per-family counts 3, 3 and 2 hold by assertion. The constants
`c(class)`, `c_rule`, `c_fill` and `c_prestage` are measured and committed by the cachegrind gate
(§6), and the inequality is asserted per slot (row C1). The worst case per request is the constructed
`evaluator-worst` program, asserted maximal over the feasible count vectors, and its figure is what
is published, not guessed. **The whole bound is held per request** by row C5: the trace build hooks
every evaluator load through `WE_TRACE_EVAL(p)`, an expression that is `((void)0)` in production, over
the program block, the hold-harmless arrays, the set nodes, `bindings[]` and the descriptor fields,
and asserts traced distinct lines per request **equal** the data-free model for that request's
outcome class, with the maximum over the exhaustive vectors equal to the printed bound.

**What one configuration costs to compile.** The compile is linear in the directives. Every
per-directive step is O(1) or O(its own bytes): the context lookup is a hash over the name, each
context's directives are linked once in file order, the later-deny ordinal for polarity is one reverse
pass with a per-(context, kind) slot, the named sets a program has paid for are one table over
(program, set), identical blocks are found by digest, and the reports' context order is a merge sort,
O(n log n). What stays bounded rather than constant is the set table: a set reference resolves against
at most 1,024 declarations (the configuration's limit) per ancestor. Measured once with callgrind, on
2026-10-11, on the mass-hosting shape (one server context per four directives: a mode and three policy
lines), the build plus a never-named child's program and conf looked up per server took about 287 M,
575 M and 1.15 G instructions at 10,000, 20,000 and 40,000 directives, with one shared block and with a
block each alike: each doubling of the directives doubled the cost, and about a third of it was SHA-256
over the distinct blocks. The harness that took it is not in the tree, no gate re-measures it, and the
compile path has changed since, so it is the shape of the cost on that date, not a figure for today's
build.

### 3.8 The hold-harmless table

`hold-harmless.txt` holds 265 entries (IPv4 145, IPv6 120), 250 of them distinct (IPv4 139, IPv6
111), and 192 ranges once merged (IPv4 110, IPv6 82), mostly prefixes. A linear scan would be the
largest term in the default policy's cost, so `gen-hold-harmless.py` merges the entries at generation
into sorted, non-overlapping `[start, end]` ranges per family (`we_hold_harmless.h`, regenerated with
`make hold-harmless`, never by hand), and the compiler lays each family out as `FORMAT.md` §4.2's rank
structure with the **stride equal to one node's capacity** (16 keys at 32 bits, 4 at 128 bits): the
descent reads one 64-byte node per level, the window is one line, the end check one line, so the lookup
costs **d + 2 lines** where d is the smallest integer with `(B+1)^d ≥ m`. For today's file that is **3
lines for IPv4** (110 merged ranges, m = 7, d = 1) and **4 for IPv6** (82 merged ranges, m = 21, d =
2), pinned by row HH1 against the generated header. The lookup is the force-inlined `we_find4` /
`we_find6` unchanged: they honour any power-of-two span and shift from the descriptor; only the
**loader** refuses a rank parameter other than 6 and 5, and the loader never sees this table
(decision D20).

**The block holds offsets only.** `we_fam_t` carries absolute pointers, so it cannot live in a
pointer-free, byte-identical, interned block. The floor block stores the arrays (`start[]`, the end
column, the S-tree) and their offsets in a `we_hh_hdr_t`; at configuration load the module calls
`we_program_place()` once, which builds the `we_hh_view_t` (a `we_map_t` whose two families point into
the block) in a per-configuration region beside the interned blocks, read-only after fork, and passes
it to every `we_decide()`. The verifier runs the loader's own family checks over the in-block arrays
(sorted, non-overlapping, samples equal to `start[j·s]`, depth equal to the formula, 64-byte
alignment, a span of 16 or 4) and refuses a block whose offsets do not describe such a table;
`we_program_place()` runs only after `we_program_verify()` has accepted the block. **Every
configuration has a floor block** (decision D29): when the operator wrote no
`whisper_edge_policy_floor`, the compiler builds an empty floor (zero rules) carrying the table, so
the table and its view exist whatever the operator wrote, and step 1 always runs (row F5). The view is
**placed in the page-aligned region with the interned blocks**, on its own page after the floor block,
64-byte aligned inside it, never on an ordinary heap page: heap neighbours written after fork would
break copy-on-write for the page, and `mprotect` works on whole pages (decision D34). The table never
enters `.rodata`: the evaluator reaches it through the view pointer.

### 3.9 What the modules' variables render

Every value a module exposes (nginx's `$whisper_edge_*` variables, Apache's `WHISPER_EDGE_*` notes,
LiteSpeed's request environment) renders from the request's **record**, the copy of the decision a
module keeps for the life of the request, and never from a mapping, which may be past its grace by the
time a log line is written. The record holds the server address's memo slot, the verdict's fixed
fields and two bitmaps, the judged floor address, and per plane four marks: whether the entry came
from a lazy fill, whether it came from the plane's **stand-in** (a disarmed plane), why no map backed
it, and the first four bytes of the backing map's header digest. One renderer writes every value
(`we_attr_render_fast()` in `we_module.h`, a pointer into static storage and no copy); the tools render
through `we_attr_render()`, and the two are held byte-equal over every attribute, state and block
class. `policy_ref.py` carries a third renderer written from this section, and the differential
compares all three.

**The names, per server.** One value per attribute, named the same way on every server: nginx prefixes
`$whisper_edge_`, Apache's notes and LiteSpeed's request environment prefix `WHISPER_EDGE_` and upper-case
the rest. Which attributes a request carries beyond the planes its rules read is set by
`whisper_edge_export`.

| attribute | plane | nginx | Apache note, LiteSpeed environment |
|---|---|---|---|
| `inferred` | `reputation` | `$whisper_edge_inferred` | `WHISPER_EDGE_INFERRED` |
| `rpki_unreachable` | `rpki-unreachable` | `$whisper_edge_rpki_unreachable` | `WHISPER_EDGE_RPKI_UNREACHABLE` |
| `tor_exit` | `tor` | `$whisper_edge_tor_exit` | `WHISPER_EDGE_TOR_EXIT` |
| `proxy` | `anonymizer` | `$whisper_edge_proxy` | `WHISPER_EDGE_PROXY` |
| `vpn` | `anonymizer` | `$whisper_edge_vpn` | `WHISPER_EDGE_VPN` |
| `c2` | `threat` | `$whisper_edge_c2` | `WHISPER_EDGE_C2` |
| `bruteforce` | `threat` | `$whisper_edge_bruteforce` | `WHISPER_EDGE_BRUTEFORCE` |
| `spam` | `threat` | `$whisper_edge_spam` | `WHISPER_EDGE_SPAM` |
| `phishing` | `threat` | `$whisper_edge_phishing` | `WHISPER_EDGE_PHISHING` |
| `scanner` | `threat` | `$whisper_edge_scanner` | `WHISPER_EDGE_SCANNER` |
| `state_actor` | `threat` | `$whisper_edge_state_actor` | `WHISPER_EDGE_STATE_ACTOR` |
| `anycast` | `routing` | `$whisper_edge_anycast` | `WHISPER_EDGE_ANYCAST` |
| `moas` | `routing` | `$whisper_edge_moas` | `WHISPER_EDGE_MOAS` |
| `narrowed` | `routing` | `$whisper_edge_narrowed` | `WHISPER_EDGE_NARROWED` |
| `tenant_allow` | `tenant` | `$whisper_edge_tenant_allow` | `WHISPER_EDGE_TENANT_ALLOW` |
| `tenant_deny` | `tenant` | `$whisper_edge_tenant_deny` | `WHISPER_EDGE_TENANT_DENY` |
| `listed` | `reputation` | `$whisper_edge_listed` | `WHISPER_EDGE_LISTED` |
| `rpki_reason` | `rpki-unreachable` | `$whisper_edge_rpki_reason` | `WHISPER_EDGE_RPKI_REASON` |
| `rpki` | `routing` | `$whisper_edge_rpki` | `WHISPER_EDGE_RPKI` |
| `asn` | `routing` | `$whisper_edge_asn` | `WHISPER_EDGE_ASN` |
| `asn_rep` | `routing` | `$whisper_edge_asn_rep` | `WHISPER_EDGE_ASN_REP` |
| `country` | `routing` | `$whisper_edge_country` | `WHISPER_EDGE_COUNTRY` |
| `registry_country` | `registry` | `$whisper_edge_registry_country` | `WHISPER_EDGE_REGISTRY_COUNTRY` |
| `rir` | `routing` | `$whisper_edge_rir` | `WHISPER_EDGE_RIR` |
| `registry_rir` | `registry` | `$whisper_edge_registry_rir` | `WHISPER_EDGE_REGISTRY_RIR` |

| decision value | nginx | Apache note, LiteSpeed environment |
|---|---|---|
| verdict | `$whisper_edge_verdict` | `WHISPER_EDGE_VERDICT` |
| action | `$whisper_edge_action` | `WHISPER_EDGE_ACTION` |
| reason | `$whisper_edge_reason` | `WHISPER_EDGE_REASON` |
| rule id | `$whisper_edge_rule_id` | `WHISPER_EDGE_RULE_ID` |
| rule | `$whisper_edge_rule` | `WHISPER_EDGE_RULE` |
| program | `$whisper_edge_program` | `WHISPER_EDGE_PROGRAM` |
| logged | `$whisper_edge_logged` | `WHISPER_EDGE_LOGGED` |
| generations | `$whisper_edge_generations` | `WHISPER_EDGE_GENERATIONS` |
| floor addr | `$whisper_edge_floor_addr` | `WHISPER_EDGE_FLOOR_ADDR` |

**An attribute, per memo state of its plane.**

| state of the plane, for this request | renders |
|---|---|
| fresh, a record covers the address | the value as the language writes it: `true` or `false`, a level (`none` .. `critical`, a low nibble above 4 read `critical`), an enum word, an AS number in decimal with no `as` prefix, a country's alpha-2 in upper case; `undetermined` at a sentinel (`FORMAT.md` §3) |
| fresh, no record covers the address | the definite absence: `false`, `none`, `unrouted` for `rpki`, `undetermined` for the routing and registry fields |
| a country code the compiled table does not know, or above 999 | `undetermined`, whatever the block holds; never the decimal code |
| an enum byte outside its domain (a raw block only; the fill clamps every record) | `?` |
| stale, refused, loading, or generation 0, off the tenant plane | `unknown` |
| disarmed (the entry came from the plane's stand-in), any plane, the tenant's included | `unknown` |
| tenant, stale within the 48-hour grace | `stale:true` or `stale:false` |
| tenant, stale past the grace (the entry's `lapsed` byte) | `lapsed:true` or `lapsed:false` |
| tenant, revoked | `revoked` |
| not looked up | `unread`: a tool's rendering only; a module fills the plane first and never writes it |

`listed` renders the stored level, the data: under `whisper_edge_allow_inferred off` a rule's `listed`
test reads `none` for an inferred range, and that belongs to the evaluator, not to this rendering, so a
log line can show `listed` = `high` beside a rule that did not fire on it.

**`$whisper_edge_verdict`**, the shipped variable, keeps its spelling per server for a fresh plane: the
server address's reputation level from the memo's clamped byte, then the drop flag from the
**unclamped** byte at the entry's range (the memo's clamp drops it), then `,inferred`. The drop flag is
`,drop` on nginx and `,spamhaus-drop` on Apache and LiteSpeed, as they shipped: `critical,drop,inferred`
on nginx is `critical,spamhaus-drop,inferred` on the others. Then: `none` for an address no range
covers, `unknown` for a plane with no map (refused, loading, absent), `unknown,stale` for a stale one
and `unknown,disarmed` for a disarmed one. 23 strings per server spelling, all static.

**The deny and WOULD DENY log lines spell the verdict one way on every server**, `,spamhaus-drop`: the
same core renderer over the request's record (the server address's entry), so for one listing the
token after `verdict ` is byte-identical on nginx, Apache and LiteSpeed (`high,spamhaus-drop`,
`critical,spamhaus-drop,inferred`, `none`, `unknown,stale`). The two spellings are on purpose: the variable
keeps each server's shipped spelling because operators parse it in their access logs, and the log line
keeps the word both shipped deny lines carried (nginx's and Apache's lines both read `spamhaus-drop`
before this release), so an existing search for `spamhaus-drop` in the error log still matches. Both lines
are written at error on all three servers: on nginx and Apache that is the server's own level for a
denial (nginx's access module, httpd's AH01797), and on OpenLiteSpeed it is seen at every `logLevel` the
server takes, ERROR the strictest, so a stock error log shows them on each server, log mode is seen there
too, and one level is one search. Each is rate-limited to one line a second per outcome per worker.

**The decision.** `$whisper_edge_action` is `allow`, `deny` (a deny enforced under mode `deny`) or
`would-deny` (a deny rule that fired under mode `log`, where it is downgraded to a log line and
evaluation goes on); `-` before the decision has run. `$whisper_edge_reason` is the decision's own word
(`allow-by-unknown`, `hold-harmless`, `acme`, `tenant`, `stale-tenant`, `no-address`; none for a rule's
TRUE or the default allow), then the walk's (`floor-header-missing`, `floor-header-unparsed`,
`floor-header-capped`, at most one), then `tenant-revoked`, comma-joined, `-` when there is none.
`$whisper_edge_rule_id` is `floor:N` or `ctx:N` and `$whisper_edge_rule` the rule's canonical text, `-`
for none. `$whisper_edge_logged` lists every `log` rule (and downgraded `deny`) that fired as `floor:1,3
ctx:2`, `-` for none. Across an internal redirect the record keeps the most severe evaluation (deny,
then would-deny, then allow; at equal severity the latest), for the variables only.

**`$whisper_edge_program`** names both blocks: `floor:<d16> ctx:<d16>`, each the first eight bytes of
the block's SHA-256 in byte order as lowercase hex (`sha256sum | cut -c1-16`, the one rendering of a
digest on every surface). `ctx:<d16>` appears only when the context's program ran; a decision taken
before it (hold-harmless, ACME, the tenant, the floor), and every decision in a context whose mode is
`off`, renders `floor:<d16> ctx:-`, and `floor:- ctx:-` when there is no floor. A decision taken before
the context's program uses the http level's mode and deny status.

**`$whisper_edge_generations`** is one token per plane in the context's token set, fixed at
configuration time (so the line does not depend on the order of variables in a log format), in plane
order, space separated, every such plane filled before the token renders:

```
<plane>:<g>.<d8><mark>        a map backed the entry: its generation, and its header digest's first 4 bytes
<plane>:-<letter>             none did: a absent or not bound, u unreadable, r refused, l loading, d disarmed
<mark>                        empty for fresh, ~ stale, ^ a tenant past its 48-hour grace; then * after a lazy fill
tenant:0                      a revoked tenant (and every tenant_* attribute renders `revoked`)
```

Example: `reputation:497716.bad76c5e tor:-l routing:-a tenant:41.0a1b2c3d^`. The digest is there because
one generation can carry two data sets: the join key is the `snapshot.bin` door's `ETag` after `we1-`,
or, for a plane installed from the manifest, the plane entry's `contentDigest` with `<g>` equal to its
`headerGeneration`.

**`$whisper_edge_floor_addr`** is the judged floor address, written by the one formatter every surface
uses: IPv4 in dotted decimal; IPv6 by RFC 5952 section 4, lower case, leading zeros dropped, the longest
run of two or more zero groups compressed (the first on a tie), and never the mixed notation of section
5, so `::102:304`, `::ffff:0:c000:201` and `64:ff9b::c000:201` print as written here (`::ffff:0:0/96`
is unmapped to IPv4 first and never reaches the formatter). `-` for a request with no address.

**The floor's address**, by the trusted-header walk. The header is read only when the TCP peer
(canonical: `::ffff:0:0/96` unmapped) is in `whisper_edge_trusted_proxy`; the walk goes right to left
over the newest 16 lines of the configured header and their comma-separated elements, OWS trimmed and
empty elements skipped, reaches at most 16 entries and examines at most 1,024 bytes. One entry:

```
entry     = ipv4 [ ":" port ] / ipv6 / "[" ipv6 "]" [ ":" port ]
ipv4      = RFC 3986's IPv4address (dec-octet: no leading zeros)
ipv6      = RFC 3986's IPv6address (`::` stands for at least one zero group; no zone identifier)
port      = 1*5DIGIT, the value 0 to 65535; read and ignored
```

An element longer than 53 bytes does not parse; a bare IPv6 has no port (`2001:db8::1:443` is that
address). The outcomes, row by row:

| peer | header | judged | walk mark | hold-harmless eligible | note |
|---|---|---|---|---|---|
| not trusted, or no trusted header configured | (not read) | the peer | OK | yes | |
| trusted | absent | the peer | header missing | yes | |
| trusted | zero entries, the rightmost element bad, or the cap before any entry parsed | the peer | header missing | no | unparsed |
| trusted | the walk ends on an untrusted entry, no hop skipped | that entry | OK | yes | |
| trusted | the judged entry reached past a skipped hop | that entry | OK | no | |
| trusted | a bad entry after a parsed one | the last parsed (its right neighbour) | OK | no | unparsed |
| trusted, `trusted_hops 1` | at least one entry | the rightmost | OK | yes | |
| trusted, `trusted_hops N`, N of 2 or more | at least N entries | the Nth from the right | OK | no | |
| trusted, `trusted_hops N` | fewer than N entries | the leftmost | OK | no | unparsed |
| trusted, `trusted_hops N` | the cap before the Nth, after an entry parsed | the last parsed | OK | no | capped |
| trusted, skip mode | every reached entry trusted, header exhausted | the rightmost reached | OK | no | |
| trusted, skip mode | every reached entry trusted, the cap reached | the rightmost reached | OK | no | capped |
| a trusted unix socket (`unix:`) | absent | `::` | header missing | no | |
| a trusted unix socket | present | as the rows above, `::` for the peer | | | |
| a unix socket, no trusted header | (not read) | none | no address | no | |

No header content ever produces "no address"; a request noted `unparsed` counts
`floor-header-unparsed` only, never also `floor-header-missing`.

**ACME.** A request is exempt when it is `GET` or `HEAD`, its request-target holds no `?` (an empty
query, `tok?`, is a query), the normalised path is exactly `/.well-known/acme-challenge/` and one segment
of `[A-Za-z0-9_-]+`, and the raw path (the request-target as received, an absolute-form
`scheme://authority` removed) is byte-equal to the normalised one. So `%2e` dot segments, a
percent-encoded token character and a leading `//` are never exempt.

## 4. Named sets

### 4.1 Value sets: `@name` over literals

`whisper_edge_set "@embargo KP SY CU"` and `"@partners AS64496 AS64497"` are sets of **attribute
values** of one class per set (country codes, AS numbers, enum literals or levels; `undetermined`
takes the class of the other members, or of the use site when alone, and is a legal member only for a
sentinel-bearing class, D-z). A set is scoped to the defining context and every context below it;
duplicates and shadowing are refused; 1,024 sets per configuration (the refusal names the context that
crossed it); members are bounded by the 2,048-byte argument; a set test is one operation. A duplicate
member is reported and dropped. Layouts, by kind:

| kind | payload | `has_undetermined` | cost per test |
|---|---|---|---|
| enum or level mask | none: `imm` holds the mask over the domain (bit 0 is `undetermined`), `SEV` for `listed` | in the mask | 0 lines |
| country bitmap | exactly 125 bytes (1,000 bits, padded to 128) over ISO numeric codes, the alpha-2 mapping from `we_country_table.h` | bit 0 | 1 line |
| ASN S+ tree | the members as an **S+ tree**: the keys in 16-key 64-byte leaves in order, separators in the levels above, root first (`ceil(n/16) + ceil(n/272) + ...` nodes); the descent searches on **`a' = a - (a == 0xFFFFFFFF)`**, reading one node per level with the branchless halving count of keys ≤ a', the level offsets computed from the member count n packed in `imm`, then the leaf's **`k[max(c, 1) - 1] == a'`**, the clamp branch-free, because in the first leaf a probe below the smallest member gives c = 0 and `k[-1]` would read before the payload; a **fixed-iteration** search whose cost is independent of the data; **then `(a == 0xFFFFFFFF) ? has_undetermined : found`**, branch-free (decisions D23, D26) | the bit packed into `imm` (§2.2) | lines = the level count: 1 up to 16 members, 2 up to 272, 3 up to 4,624 |

A set with no numeric member against `asn` has n = 0 and no payload; the compiler emits it as `EQ32`
against the sentinel, never as an `INSET_ASN` (§2.2).

**The largest ASN set** follows from the argument limit and the verifier's strictly-increasing rule,
and is `WE_LIM_ASN_MEMBERS`, 539: `@s` is 2 bytes; each member costs its digits plus one separator
before it: the 10 one-digit values 2 bytes each, the 90 two-digit 3, then three-digit values at 4,
which leaves 2,048 - 2 - 20 - 270 = 1,756 bytes, 439 of them; 10 + 90 + 439 = 539. That is three
levels. `test_policy` builds the 2,048-byte argument that reaches it and the one past it (row N3); the
corpus file `accept/16` declares 538. The payload offset, the level count and `has_undetermined` are in
the instruction's `imm`, so the request path never reads the descriptor.

### 4.2 Address lists: the tenant plane

An address or CIDR is **not a literal** of this language; the answer to "use my own list" is a plane
(decision 4): `tenant.bin`, the membership schema (`FORMAT.md` §3), `plane_id` 8, 128-bit IPv6 keys,
bit 0 `tenant_allow`, bit 1 `tenant_deny`. The language reaches it through the two booleans and the
pre-stage (§3.2). The refresh fetches it with a key and installs it by name under the writer
discipline of the publication state machine; the server builds it from the `op:policy` edge allow and
deny lists within the limits it enforces at write time: 1,024 entries after canonicalisation, allows no
broader than /16 (IPv4) or /32 (IPv6), allow coverage capped at 2^20 IPv4 addresses and 2^20 IPv6 /64s,
and a deny covering a hold-harmless address refused. The compiler refuses an address-shaped literal
with a fix naming `tenant_allow` and the `op:policy` write (decision D5, row S3).

## 5. The reference interpreter, the differential, the fuzz harnesses, the negative controls

### 5.1 The reference interpreter

`core/policy_ref.py` (Python 3, standard library only) is a second implementation of §1 to §3,
written from this document and never from the C. It has its own recursive-descent parser over §1.1 and
the byte table of §1.2, the refusal order of §1.5, the definite values and clamps of §1.4, K3 by the
truth tables as values (not bit pairs, so an encoding defect cannot be shared), the polarity pass, the
per-occurrence outage classification of §2.5 as the normative definition plus a brute-force exact
classifier for the soundness property, the shadowing procedure and the reports, the instruction stream
of §2.2 (for the cost line), and the fixed order of §3.2. Per program it prints the refusal line or the
canonical text and reports; per case the verdict line, the cost line, the invariant line, and the
classification lines (§5.6). It computes the cost columns from the program and the atom values alone
(which jumps are taken, which planes each address fills, the S-tree depth per set), the way
`test_trace.c`'s model works from a structure's integers.

Its modes: `--corpus DIR` replays the independent corpus (20 accept, 50 refuse); `--self-test` runs
its own checks, each with its negative control; `--cases FILE` evaluates a case file (with
`--mutant NAME` to plant one of its 18 mutants); `--compile FILE` and `--expect FILE` print one
`.policy` file's listing or refusal; `--seeds DIR --floor N` replays the seed list; `--default-conf
FILE` checks that the default policy compiles to the program of `accept/01`. Every checking run ends
with one `N checks, F failures` line, which `make check` sums into the published count in REFERENCE.md.

### 5.2 The differential, with cost equality per request

`policy_gen.py` generates case files from the pinned xorshift seed `0x9e3779b97f4a7c15` (the one
`bench_core.c` uses; Python's own `random` is not used, so the same seed gives the same bytes on every
Python). Its legs:

- **generated**: programs drawn from the whole grammar (every attribute, every literal form and
  spelling, inline and named sets declared before and after use, floor and context programs, the
  tenant atoms), each run under **every** reduced plane-state vector of §3.5, so a program reading k
  non-tenant planes has 2^k · 5 cases; records per (address, plane) with every byte value drawn
  (`country` 0..65535) so the clamps are exercised; the floor and server records drawn different for
  every referenced plane in half the distinct-address cases; the two addresses equal in a quarter of
  the cases, with a third of the programs having floor and context plane sets that overlap in exactly
  one plane (the shared slot); `::ffff:a.b.c.d`, `::a.b.c.d`, `::` and `::1` among the addresses (the
  first unmaps, the other three stay IPv6); hold-harmless addresses, ACME, and raw configuration
  values outside the domain; a record absent in a quarter of the (address, plane) pairs;
- **limits**: every limit at its boundary and one past it;
- **mutations**: generated rules with one byte inserted, replaced or deleted, or one word's case
  changed, so the refusal line is compared over inputs nobody wrote by hand;
- **rows**: the named matrix rows of §9 as programs, under every state vector;
- **phrases**: one program per phrase of §1.5's table, so every phrase is emitted;
- **absent**: programs with planes absent at configuration time;
- **files**: every `.policy` file under `testdata/policy/` as a program;
- **exhaustive**: every expression of up to 3 atoms and nesting 2, × atom values {T, F, U}, ×
  action, × position (before or after a deny).

`test_policy` compiles and evaluates each case and prints the same lines as the reference
interpreter, including one **invariant line** per case: for every atom x the programs read and every
state, `ISUNK(x) == (K3value(x) == U)`, the uniform reading (row X5). `policy_diff.py` requires
**equality per case on every line** but `msg`, so losing the memo (a second lookup per atom), losing a
short-circuit (`JF` never taken) or doubling a lookup on an equal key is a disagreement even when the
verdict is unchanged. It also refuses an output with a line before the first `program`, a program or
case id seen twice, or no case.

The trace build records a **coverage matrix**, and `check-policy` fails if any reachable cell is zero:
(op, input pair) for `AND`, `OR`, `NOT`, `JF`, `JT` (JF and JT precede every later operand, so an AND
whose left operand is F and an OR whose left operand is T never execute the right operand, and those
pairs belong to the jump cells); (action, final value); (plane, state) per opcode; (polarity, `is
unknown`); (slot shared, slot distinct); (clamp fired, per field); and one cell per §1.5 phrase, so a
phrase the generated set never emits fails the check. The cell counts print beside the case count, and
`policy_diff.py --coverage-control` zeroes each cell in turn and requires the check to fail. A missing
`python3` is a failure, never a skip. A further leg runs under `check-live`: the routing attributes over
the live-shaped fixtures, with the cost columns (decision D11).

The cost line both sides print is

```
cost ops=<floor>/<ctx> jumps=<floor>/<ctx> probes=<floor>/<ctx> lookups=<8 per-plane counts for the floor slot>/<8 for the server slot>
```

and the verdict line

```
verdict step=<1|2|3|3.5|4> action=<allow|deny> program=<floor|ctx|-> rule=<n> reason=<...> log_floor=<list|-> log_ctx=<list|->
```

as `we_verdict_format()` writes them (the counts as decimal integers, the per-plane counts
comma-separated in plane-id order 1..8, the fired lists as ascending comma-separated rule numbers;
`reason` per §5.6). An untraced build writes `cost untraced`.

The `.case` seeds under `testdata/policy/seeds/` join the generated file in their own `cases` leg,
which owns no coverage cell. `test_policy --cases` run on one of them alone fails K7 by design: the
matrix requires every cell of each leg the file holds, and a seed of a few programs fills almost none.

### 5.3 The fuzz harnesses

`fuzz_policy.c` takes **one input as a whole configuration**, so it reaches what a single argument
cannot: several directives and contexts, set scoping, duplicates, multi-rule polarity, the 256-rule
and 4,096-operation limits, and plane environments with planes absent or present under the wrong
schema. Byte 0 is the planes present at configuration time (bit `plane_id - 1`), byte 1 the planes of
those whose header carries the wrong schema, and the rest is directives in the corpus record format
below. It ships a dictionary (every keyword, attribute, enum literal, level, the country codes, `as`,
`@`, `{`, `}`, the operators) and a 64 KiB maximum input. On every input it asserts: no crash, no
sanitizer report, no read past the input; every configuration compiles or is refused with a located
error (a layer of §1.5, a rule ordinal, a line and column of at least 1, a token of at most 64 bytes);
every accepted program passes `we_program_verify()` and compiles twice to identical bytes; every
accepted program's canonical text is printed, compiled again, and gives the same text and a
byte-identical block (row R1, verifier step 22); every accepted program is evaluated by `we_decide()`
over all eight planes at their deciding addresses with every view write-protected, the planes the
environment lacks as NULL views, and again with every view NULL.

`fuzz_program.c` (rows R2, X4) takes blocks the compiler produced from the corpus's accept files,
mutates them, and holds one property: if verify accepts a block, evaluating it is memory-safe. Every
accepted block is placed (a floor) and run through `we_decide()` under ASan, the block copied into its
own write-protected pages, the evaluation context flush against a `PROT_NONE` guard page, and every
plane a real write-protected view. Plain byte flips mostly die at verifier step 5, so most mutations
are made field by field within each field's own domain (rule records, instructions, bindings, set
descriptors and payloads, the hold-harmless arrays), also as an `LLVMFuzzerCustomMutator`, so steps 6
to 22 are reached.

Two ways to run each; `make check` always runs the first:

- **without a fuzzer**: `fuzz_policy --replay DIR --planes PLANES --floor N` runs the same checks over
  every file under `testdata/policy/` (the corpus, the seeds and the adversarial inputs) in the default
  environment: every `accept/` file must compile, verify, compile twice to identical bytes and survive
  the disassembler round trip; every `refuse/` file must be refused with every `.expect` field equal
  (row N1); the replay fails below a **seed-count floor**, so deleting a file cannot pass silently.
  `fuzz_program --replay DIR --planes PLANES --mutations N` compiles every accept file and mutates it a
  pinned number of times from the pinned seed, printing how many mutants verify refused and how many it
  accepted and were evaluated;
- **with a fuzzer**: `make fuzz` detects `clang -fsanitize=fuzzer,address,undefined`, runs for
  `WE_FUZZ_SECONDS` (default 60), and fails on any crash or sanitizer report; findings are minimised
  and committed by hand, and the differential runs over committed findings too.

**The corpus.** `core/testdata/policy/` holds the independent corpus: 20 `accept/NN-<slug>.policy`,
50 `refuse/NN-<slug>.policy` each with its `.expect`, `refusals.tsv`, `README.md`, the seed list under
`seeds/`, and adversarial inputs under `adversarial/`. It was written from §1.2, §1.5 and the design
record before either implementation existed, so row N1 is an independent third leg (decision D18). A
`.policy` file is a sequence of records, one per directive:

```
<kind> SP <context> SP <argument bytes> 0x1E 0x0A
```

where `kind` is `policy`, `set`, `floor`, `threshold` or `mode`, `context` is a path (`http`,
`http/server:<name>`, `http/server:<name>/location:<name>`; a set is visible in its own context and
below), the argument is every byte up to the record separator exactly as the server hands it to the
module after its own quoting, and the ordinal of a directive among those of the same kind in the same
context is its `rule`. **0x1E** is the separator because it lies outside the language's alphabet, so no
argument can contain it; `test_policy` tests every single byte value directly (row N2). An `.expect`
file is one `key<TAB>value` per line, `layer`, `kind`, `context`, `rule`, `line`, `col`, `token`,
`message`; `refusals.tsv` holds the same fields with the file name first. Matching follows §1.5: the
six exactly-worded messages exact, every other message contained word for word in `what` or `fix`.
Every file compiles in the **default environment** (all eight planes present with the schema their
name requires). Two files are regression checks: `accept/08` (a set holding only `undetermined` used
against `asn`, the n = 0 ASN set) for the `EQ32`-against-the-sentinel encoding, and `accept/04`
(`listed` under every comparison, including the report-only rules) for the rule that reports are
printed and never refused.

### 5.4 The negative controls: mutants, each mapped to a row that must fail

Each mutant is a `-D` build of `test_policy` in its `WE_TRACE` build that plants one known defect in
the compiler, the verifier, the evaluator or the classifier. `policy-mutants.sh` builds every one; each
must make `test_policy` fail, and fail on the named row: a mutant that fails some other row has shown
nothing about the row that claims to catch it, and a process that dies of a signal is never a catch
(the two defects a fault exposes, a store into a write-protected plane and a search that reads past its
payload into a guard page, are caught inside `test_policy` and reported on rows H3 and S2). The
differential reports disagreements per mutant with the catch count from the generated set
(`policy_diff.py --mutants`); for the two cost mutants the disagreement must be on the cost line only.
Twenty-five in all, and `we_policy.h` refuses every one of them outside the traced build, so a stray
`-D` can never ship one in a copied core; the cachegrind driver alone may define
`WE_TEST_NO_MEMO_HIT`. Every server module meets that guard through `we_eval.h`, and
`policy-mutants.sh` proves it on a module translation unit (`we_module.c`, each mutant defined, no
`WE_TRACE`, refused by that `#error`). The guard holds outside `WE_TRACE` only, the harnesses' build, so
every server module's source refuses `WE_TRACE` as its first directive, and the script proves that on
each. It also holds its rows, the guard and every `WE_TEST_*` name the evaluator, the compiler and
`test_policy` test to one set, so a new mutant cannot be added without its row and its refusal. The driver has one more control of its own, outside the twenty-five because it
changes no verdict: `WE_TEST_EXTRA_LOAD` reads one byte no other code reads (the rule's `reserved`)
at the head of every rule and feeds it, shifted out to zero, into the rule pointer, so each program run
costs one more data reference per rule, and the per-rule
data-reference row of the cachegrind gate must move by one. The byte must reach a real instruction: a
load whose result nothing uses, `ldrb wzr` or a register an empty asm only pretends to read, is dead to
Valgrind's IR and never counted. A plain build refuses it too.

| mutant | what it plants | the defect it stands for | row that must fail |
|---|---|---|---|
| `WE_TEST_K3_WEAK` | exact weak Kleene: U if either operand is U, classical otherwise | a mask / unknown-mask encoding | K2 |
| `WE_TEST_ALLOW_U_FALLTHROUGH` | an allow at U is treated as no match | a fail-closed path | K4 |
| `WE_TEST_LOG_TERMINATES` | `log` ends evaluation | the iptables LOG analogy | F1 |
| `WE_TEST_POLARITY_NO_ALLOW` | the polarity pass ignores `allow` | polarity over part of the program | N4 |
| `WE_TEST_ISNOTUNK_POSITIVE` | `is not unknown` treated as positive polarity | a flipped polarity | N4 |
| `WE_TEST_BOOL_NOT` | `not` is `(t, ~t)` | boolean negation under K3 | K1 |
| `WE_TEST_SENTINEL_NE` | `!= undetermined` TRUE at the sentinel | `!=` that is not `not ==` | P2 |
| `WE_TEST_SHORTCIRCUIT_U` | `JF` jumps on U | unsound short-circuit | K3 |
| `WE_TEST_NO_CLAMP` | the fill clamps nothing | an out-of-domain record byte used as an index | M4 |
| `WE_TEST_NO_MEMO_HIT` | every atom looks up again | the memo | X1 (cost columns only) |
| `WE_TEST_NO_SHORTCIRCUIT` | `JF`/`JT` never taken | short-circuit | X1 (cost columns only) |
| `WE_TEST_NO_MEMO_RESET` | a re-keyed slot is not reset | an unkeyed shared slot | M1 |
| `WE_TEST_CLASSIFY_ISUNK_U` | the classifier reads `ISUNK` as U | the one non-monotone atom | D2 |
| `WE_TEST_NO_CAPTURES` | the classifier has no `captures` class | an allow at U disarming later rules | D1 |
| `WE_TEST_CLASSIFY_SINGLE_EVAL` | the classifier evaluates once at the most favourable values instead of propagating value sets | U reachability | D2 (`allow if tor_exit or asn in @partners`) |
| `WE_TEST_SENTINEL_PADDING` | `INSET_ASN` returns `found` for `0xFFFFFFFF` | the padding key is the sentinel | S2 (an unrouted address against a padded set) |
| `WE_TEST_TENANT_ATOM_U` | the bounded occurrence (positive `tenant_allow` in an `allow`) reads U in every stale state | stale allows lost inside the grace | F4 (the allow decides for listed addresses within the grace) |
| `WE_TEST_TENANT_BIT_IGNORED` | the bounded reading is applied to every tenant occurrence | the fail-closed path under negative polarity | F4 (`deny if not tenant_allow` at lapse + 1 ms denies) |
| `WE_TEST_SPLUS_NO_CLAMP` | the S+ search runs on `a`, not `a'` | the sentinel's halving count past the payload | S2 (the guard-page row), C5 (that line's reads) |
| `WE_TEST_NO_EXHAUSTIVE` | the exhaustive leg is skipped | a standing control on the coverage matrix | K7 (at least one zero cell) |
| `WE_TEST_PLANTED_STORE` | one store into a plane buffer | a standing control on the no-store claim | H3 (faults under `mprotect`) |
| `WE_TEST_HH_FLOOR_ENDS_ALL` | a hold-harmless floor address ends the request whatever the server's address | the fail-open behind a same-box proxy (§3.2's amendment) | F6 (a listed client behind a loopback proxy is denied) |
| `WE_TEST_HH_SERVER_EXEMPT` | step 4 runs a hold-harmless lookup on the server's address | an exemption a header reaches | F6 (a spoofed hold-harmless address under `deny if not tenant_allow` is denied) |
| `WE_TEST_HH_RAW_COMPARE` | the floor's and the server's addresses compared as bytes, not canonically | two forms of one address read as two | F6 (`::ffff:127.0.0.1` behind 127.0.0.1 is the proxy's own request) |
| `WE_TEST_SERVER_UNSET_KEYED` | a server slot with no address keyed as `::` | every context rule skipped on a unix-socket listener | F6 (a server slot with no address judges the floor's listed client) |

`NO_EXHAUSTIVE` and `PLANTED_STORE` are standing builds in `make check`, never a once-by-hand check. The
reference interpreter carries 18 of these behind `--mutant`. Three it does not carry (`NO_MEMO_RESET`,
`SPLUS_NO_CLAMP`, `PLANTED_STORE`) are about memory and context reuse, which a value-level interpreter
cannot get wrong; the four of §3.2's amendment (`HH_*`, `SERVER_UNSET_KEYED`) are caught by row F6, which
runs each scenario through both the C evaluator and the reference, so the reference's own reading of
the order is held there and by the differential's `proxy` cells.

### 5.5 The verifier's refusals, in order

`we_program_verify()` runs before a program is armed, the way `FORMAT.md` §6 orders the loader's
checks. Steps 1 to 5 refuse at the first failure, because nothing later can be read safely until they
hold; once they hold, every later step runs and the verifier reports the **lowest-numbered** step that
failed, so a block with two defects has one answer. A refusal returns `-(step)` and fills the error with
layer `verify`, phrase `a program the verifier refused`, `rule` set to the step, the step's own `what`,
and the fix `verifier step N`. The twenty-two steps:

1. magic, version, total length against the buffer;
2. every table offset and length inside the block, 64-byte aligned, no overlap, in the layout order
   of §2.1;
3. `rule_count`, `instr_count`, `op_count`, `set_count` against their tables and the limits, and
   `op_count` inside the range the instructions hold;
4. rule instruction ranges contiguous, non-overlapping, covering `instr_count`, each ending in exactly
   one `END`;
5. each opcode exactly one bit of the known set;
6. `plane` 0..7 and in the rule's `dep_mask`, the plane's binding present; a connective carries no
   operand;
7. `off` plus the opcode's width within the plane's block width, width in {1, 2, 4}; `ISUNK` carries
   no operand;
8. `SEV` only on the reputation binding, its mask in domain;
9. `EQ8` immediates inside the attribute's domain, enum masks inside the domain, `EQ16` and
   `INSET_COUNTRY` on the country attributes only, `EQ32` and `INSET_ASN` on `asn` only, a bool mask
   inside its plane's mask, and on the tenant plane the `BOOL` polarity bit set exactly on an
   occurrence that is `tenant_allow`, positive, inside an `allow` (the verifier recomputes the polarity
   from the rule's instructions);
10. each set payload named by a descriptor, kind known, payload offset and length inside the set data
    and aligned, a country bitmap of exactly 125 bytes in 128, an ASN tree whose keys are strictly
    increasing with padding at the maximum key and whose separators are the S+ tree's;
11. jump targets forward, inside the rule;
12. the abstract stack pass: no underflow, no jump on an empty stack, height at most 18, equal heights
    at every join point, height exactly 1 at `END`, and no rule longer than any legal rule;
13. `dep_mask` equal to the planes the rule's instructions read, and `plane_mask` equal to the union of
    every `dep_mask`;
14. `counter` below `rule_count`, `src_off`/`src_len` inside the cold text;
15. every padding and reserved byte zero;
16. the header `flags` domain (only `floor` and `legacy`), each rule's `action` in {allow, deny, log},
    its `flags` domain, and its inert flag equal to what the bindings say;
17. **no `allow` in a block flagged `floor`**, so the floor-only-tightens property does not rest on the
    compiler alone;
18. `bindings[]` equal, field by field, to the compiled-in `FORMAT.md` table, and each no-range
    template in domain with routing's `rov` exactly 4;
19. `INSET_ASN`'s packed `imm`: the payload offset inside the set data, the member count n **at least
    1** and at most 539 and equal to the payload's key count (an ASN set with no numeric member
    compiles to `EQ32` against the sentinel, so an `INSET_ASN` with n = 0 is refused), the level count
    equal to the formula for n, the flag in {0, 1}, and the payload's length equal to the S+ formula
    for n;
20. the hold-harmless arrays, by the loader's own family checks over the in-block offsets: present
    only in a floor block, the header fits, sorted and disjoint ranges, samples equal to
    `start[j·stride]`, depth and window count equal to the formula, 64-byte aligned, a span of 16 or 4,
    and the region ending at the set data;
21. `hot_len` equal to the end of the last hot table and under the limit;
22. **re-parse to byte identity**: the canonical text, compiled again with the same bindings, is
    byte-identical to the block, which proves the instructions match the text `$whisper_edge_rule`
    prints and is the cheapest complete check of everything above; this re-parse (and row R1's) is
    **exempt from the argument-length check** (decision D32), because that limit governs operator input
    and the canonical form lengthens unspaced operators (`listed>=high` renders as `listed >= high`),
    so a legal 2,048-byte argument may render longer. The compiler marks such input through
    `we_policy_env_t.canonical`.

### 5.6 The output formats and the readings pinned by the reference interpreter

The C core agrees with `policy_ref.py` line for line, so the lines both emit, and every reading
that fixes a place where the rules above would otherwise leave a choice, are recorded here. The one
source is `policy_ref.py`'s module docstring: the decision list below is its list byte for byte, and
`make check` holds that (`policy_ref.py --decisions-match`, with a one-byte control). A change to any
of these is a change to that docstring and this section together, then to both implementations.

```text
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

DECISIONS: the readings that fix every place where the rules above would otherwise leave a choice, so
the two implementations read each one the same way. Each is normative.
  D-a  Steps 1 to 5 run per directive in file order (the way a server hands directives to a module one
       at a time); steps 6, 7 and 8 run over the whole configuration after every directive is seen.
  D-b  Step 6 checks every set declaration in file order (count, duplicate, shadowing, no members, mixed
       class), then every set use in file order (empty inline set, undefined, class mismatch).
  D-c  Step 7 walks the directives in file order (rules over 256, the operation that crosses 4,096,
       `allow` in a floor, `threshold` beside policy lines, instructions, hot bytes).
  D-d  A byte in 0x21..0x7E that belongs to no token class (every one of  " # $ % & ' * / : ; ? [ \ ] ^ `
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
       each and the S-tree's nodes, from the same hold-harmless.txt this file reads (4,096 bytes today).
       The hold-harmless arrays count because a floor carries them in its block: a floor of 141 rules
       fits 256 KiB without them and not with them, and testdata/policy/adversarial/h1, h2 and h3 hold
       that boundary.
```

## 6. Gates and benchmarks

The evaluator's cost and shape claims are held by four gates beside the differential, all run by
`make -C core` and in CI, none of them `continue-on-error`:

- **`hotpath-gate.sh`** disassembles wrappers in `hp.c` (`hpeval`, the whole `we_decide()`;
  `hpeval_ops`, the instruction loop; `hpfill4`, `hpfill6`, `hpfill6w`, `hpfill1`, the memo fill per
  key width and format 1; `hpfloor`, steps 1 to 3.5; `hpaddr`, `we_addr_canon`) at several optimisation
  levels on several toolchains, and proves the list of §3.1: no reloc, branch to a call, class,
  barrier, lock, fence or xchg; no locals, on the legs §3.7 names; a frame under 256 bytes. Its controls under `gate/` (a
  `switch` on an opcode byte, an atomic counter, a `memcpy` call, a `static const` table, an equality
  chain on an opcode byte) must each be refused by their named check (rows H1, H2).
- **`cachegrind-gate.sh`** measures every evaluator slot, verified before measurement against
  `policy_ref.py` output committed with the fixture: the identifiable basis of §3.7, solved as an exact
  linear system with a rank check, each constant gated at ±10%; `c_fill` per schema; `c_prestage`;
  lookup-only rows `L(p)` and `L_HH`; `evaluator-default` over live-shaped planes; `evaluator-worst`,
  asserted maximal over the feasible count vectors; and `evaluator-worst-lines`, the lines-and-lookups
  maximum with 16 fills (rows C1 to C4). The module rows and their evaluator twins run one noinline
  compiled copy of the decision (`cg_decide` in `gate/cg_driver.c`), so a module row less its twin is the
  module's own work by construction, the call into the copy included and one inlining fewer, never the
  difference between two inlinings of the decision. The module's inlined shape stays held by
  `hotpath-gate.sh`'s `hpmod`, and three of the gate's controls show the copy hides no cost: the decision's
  hold-harmless search run twice inside it moves `c_prestage` out of its band (CS); 128 instructions of
  the module's own work outside it move the module row, leave its twin unmoved and move `c_mod_fixed` out
  of its band (CM); and this run's own `module-worst` one instruction dearer is refused by name by the
  module basis (CX).
- **The trace build** holds every lookup and every evaluator load to the data-free model per request
  (rows C5, HH1, M3, M5).
- **`bench_core`** prints, for the default policy, the design example and the constructed worst case,
  every term of §3.7's bound computed from the compiled program and the plane files, held against the
  trace build's maxima, and writes a machine-readable record keyed by commit, compiler, flags and
  plane generation (row B1).

`make check` compares the sum of the `N checks` lines with the published count in `REFERENCE.md`
(row Z1).

## 7. The old directives as sugar, the legacy synonym, and the default policy

`we_policy_sugar(threshold)` returns the program the equivalent text compiles to; `mode` and
`allow_inferred` are not part of it, because they are the context's `we_ctx_conf_t` (§2.1):

| threshold | program | and the context's conf does the rest |
|---|---|---|
| `high` (and every level) | `deny if listed >= high` | `mode deny` enforces it; `mode log` downgrades it with the action byte still `deny`, so `$whisper_edge_verdict` and the counter keep the would-deny identity; `mode off` skips step 4 |
| `off` | an empty program (threshold 0 denies nothing) | |
| any | `allow_inferred` is read from the conf by `SEV` | |

Byte identity is possible because the block stores the **canonical** text (§2.1), not the operator's
spelling. The canonical form is one space between tokens, bare digits for ASNs, and `{a b}` without
commas; parentheses only where a chain is an operand of a chain or of `not`; set members de-duplicated
and sorted (D-t). It is **longer than an unspaced source** (`listed>=high` renders as `listed >=
high`), so the compiler's own output is not held to the operator's 2,048-byte limit: the re-parse in
verifier step 22 and in row R1 is exempt from the argument-length check (decision D32), and row N3 runs
R1 on a 2,048-byte argument written with no optional whitespace. `test_policy` asserts the five
threshold programs byte-identical to the compiled canonical text and, for all 3 × 5 × 2 (mode,
threshold, `allow_inferred`) combinations, verdict-identical to `we_should_deny()` over all 256
severity bytes (row G1). `whisper_edge_threshold` in a context that also has policy lines is refused,
and the message prints the equivalent rule (§1.5).

The legacy `whisper_edge_snapshot <file>` is a synonym for a data directory holding only
`reputation.bin`; under it the sugar program binds to `reputation` and is never `inert-at-config`
(§2.4). That is the only case in which the sugar is never inert: without the synonym, a threshold whose
directory lacks `reputation.bin` at config test is inert-at-config and reported as its written rule
would be (decision D-af). The modules log the equivalent line once per context from
`we_policy_sugar()`, and arm the block `we_policy_sugar_env()` compiles for the configuration's
environment, the same block `we_policy_build()` gives the context (decision D8).

**The default policy** (decision 3), as the installer writes it (`testdata/policy/default.conf`), is
four rules over the three keyless planes under `whisper_edge_mode deny`; before any line come the
hold-harmless set and the ACME challenge path, and the tenant allow list if one is installed:

```
deny if listed >= critical
deny if listed >= high
log  if rpki_unreachable
log  if tor_exit
```

It compiles to the program of `accept/01`: four rules, four operations, eight instructions.

## 8. Files

| file | what it holds |
|---|---|
| `core/we_policy.h` | the block's layout, the request-path types, the cold API (§3.1) |
| `core/we_policy.c` | the lexer, parser, typing, sets, limits, polarity, encoder, verifier, printer, disassembler, classifier, reports, sugar, counters |
| `core/we_eval.h` | the evaluator, header-only and force-inlined |
| `core/we_hold_harmless.h` | the merged hold-harmless table, generated by `gen-hold-harmless.py` from `hold-harmless.txt` |
| `core/we_country_table.h` | the ISO 3166-1 table, generated by `gen-country-table.py` |
| `core/policy_ref.py` | the reference interpreter |
| `core/policy_gen.py`, `policy_diff.py` | the case generator and the differential |
| `core/test_policy.c` | the C test of every row in §9, and the C half of the differential |
| `core/fuzz_policy.c`, `fuzz_program.c`, `fuzz_common.h`, `fuzz_policy.dict` | the fuzz harnesses |
| `core/policy-mutants.sh` | the negative controls of §5.4 |
| `core/testdata/policy/` | the independent corpus, the seeds and the adversarial inputs |
| `core/FORMAT.md` | the plane files the evaluator reads |

## 9. Test matrix

Every row names the assertion that can fail; a row that only confirms an accept also carries the
negative that would fail on a wrong implementation. `test_policy` prints each row's checks under a
section named by its id (`== N3: the limits at the boundary and one past ==`). Rows `D1` to `D6`,
`D21` and `D23` are test rows; the decisions with the same spelling are in §11.

| id | case | harness | the assertion that can fail |
|---|---|---|---|
| P1 | the 20 corpus accepts (`accept/01` to `accept/20`), the default policy, the design example; `accept/08` as the regression check for the n = 0 ASN set compiling to `EQ32` against the sentinel; `accept/04` as the check that report-only rules compile | `test_policy`, reference | both compile in the default environment; listings identical; recompiling the listing is byte-identical; a one-byte change to the text changes the digest; `accept/08`'s program carries no `INSET_ASN`; `accept/04` prints its reports and refuses nothing |
| P2 | every literal form of §1.3, including `undetermined` on all eight sentinel attributes and on none of the bools | both | the encoded immediate equals the reference's; `tor_exit == undetermined` refused; `WE_TEST_SENTINEL_NE` disagrees here |
| P3 | `country == IN`, `{ in is no as do }`, `nl`/`Nl`/`NL`, `as64496`/`AS64496`/`As64496`/`64496`, `0`/`as0`, the three `not-found` spellings | both | one token each; `0` is AS0; `00`, `010`, `as1.10`, `as 64496` refused with their fix |
| N1 | the 50 corpus refusals (`refuse/01` to `refuse/50`), and decisions D-y and D-z | corpus replay, `test_policy`, reference | every `.expect` field equal in both implementations: `layer`, `kind`, `context`, `rule`, `line`, `col`, `token` (upper-case `\xHH`), and `message` by §1.5's matching rule; the byte-exact files (`refuse/02` to `refuse/06`, `refuse/31`, `refuse/32`) checked by length and `od -c`, never by an editor |
| N2 | every row of §1.5's table not in the corpus, plus every byte 0x00..0x1F and 0x7F..0xFF at three positions | `test_policy` | refused at the right byte offset with `\xHH` rendering; an injected CR in a token never reaches the log unescaped |
| N3 | each limit of §2.1 at the boundary and one past; the per-rule maximum (one rule as an or-chain of 32 `!=` atoms: 63 operations, 127 instructions) and the context maximum (128 rules of 9 `!=` atoms plus 128 of 8: exactly 4,096 operations and 8,448 instructions) as two programs (D-w); the ASN set of 539 members and of 540; a 2,048-byte argument written with no optional whitespace run through R1 end to end | both | boundary accepted; one past refused naming the limit and printing the hot and cold sizes and each set's padded size; the text size alone never refuses; the re-parse of the legal maximal argument succeeds although its canonical text exceeds 2,048 bytes; 8,449 instructions is unreachable under the operation and rule limits, so that limit has no one-past case |
| N4 | `is unknown` positive in `deny`; negative in `allow` + later `deny`; the design example; the same allow with no later deny; positive in `log` | both | the first two refused with the polarity sentence; the others accepted; `WE_TEST_POLARITY_NO_ALLOW` and `WE_TEST_ISNOTUNK_POSITIVE` accept one of the first two |
| N5 | `!=`, negated `in`, `not (a == x or a == y)` over `asn_rep`/`country` in `allow`; the same with positive polarity; the same in `deny` | both | warning on the first three only; **no** warning on the others; the fix text is a program the typing pass accepts |
| N6 | `threshold` in a context with lines; `allow` in a floor; the bare action `deny` | `test_policy` | refused; the messages print the equivalent rule, and `deny if not <condition>` for the bare action |
| N7 | the refusal order: `rpki == XX`; a 2,049-byte argument with non-ASCII; the 257th rule with a lexing error; a set declared after use; two faults in one rule | both | the one refusal §1.5's order names, identical in both |
| N8 | `listed >= none`, `listed < low`, `deny if not tor_exit`, `deny if not country in { NL }`, and `deny if tor_exit` | both | the `denies-all-absent` warning on the first **four**; **no** warning on the fifth |
| R1 | compile, print, re-parse, print | both | byte-identical block; identical listing; zero padding verified |
| R2 | `we_program_verify()` against each of §5.5's twenty-two steps, one mutation each, including an `allow` planted in a floor block, a template with `rov` 3 for routing, a `plane_mask` missing a used plane, a hold-harmless array with a wrong span, a tenant `BOOL` whose polarity bit disagrees with its occurrence, an `INSET_ASN` whose packed n disagrees with its payload, and a block whose re-parse differs by one byte | `test_policy`, `fuzz_program` | each refused by its own step; anything accepted evaluates under ASan without a fault |
| K1 | the six truth-table rows | both | value equality; `WE_TEST_BOOL_NOT` fails `not U` |
| K2 | U on each side of `and`, `or`; `not U`; `not not U`; `(U and F) or T`; `U and (F or U)`; `T and F` | both | K3 value; `WE_TEST_K3_WEAK` fails on `U and F` and **not** on `T and F` |
| K3 | `U and F` with the F right of a `JF`; `U or T` with the T right of a `JT` | both, trace | F and T; `jumps_taken == 0` on the U; `WE_TEST_SHORTCIRCUIT_U` jumps |
| K4 | `allow` at U: ends evaluation, `allow-by-unknown`, `unknown_plane` as §2.5 defines it; a later deny that would fire does not | both | fields exact; `WE_TEST_ALLOW_U_FALLTHROUGH` lets the deny fire |
| K5 | `deny` and `log` at U | both | neither fires; evaluation continues; the counters say so |
| K6 | the (1, 1) invariant | trace build | `T & F == 0` after every instruction over every leg |
| K7 | the coverage matrix | trace build, `WE_TEST_NO_EXHAUSTIVE` | every reachable cell of §5.2 non-zero in the production build; the standing `WE_TEST_NO_EXHAUSTIVE` build leaves at least one zero cell, every run |
| F1 | allow above deny, deny above allow, log then deny, two logs then default allow | both | first match; both bitmaps exact; `WE_TEST_LOG_TERMINATES` loses the deny |
| F2 | `mode log`; `mode off` with a floor | both, trace | every deny downgraded with action byte `deny`; step 4 `ops_executed == 0` under `off` while the floor's count is non-zero |
| F3 | fixed order: hold-harmless under a matching deny with the eligibility bit set and **clear**; ACME under a deny; tenant allow under a floor deny; floor deny under a context allow; a `::ffff:` hold-harmless address | both | steps 1, (none: denied), 1, 2, 3 decide; the mapped form is exempt |
| F4 | stale tenant allow at `valid_until_ms + 48 h` exactly, one ms past, with a floor deny; `valid_until_ms` 0 and `UINT64_MAX - 1`; in each of the five tenant states the step-4 rules `allow if tenant_allow`, `deny if not tenant_allow`, `allow if not tenant_allow` above a deny, `deny if tenant_deny`, `allow if not tenant_deny`, `allow if tenant_allow is unknown`, `deny if tenant_deny is unknown`; an address added after the plane went stale | both | inclusive boundary; after the floor; no wrap; per rule: `allow if tenant_allow` decides for listed addresses in FRESH and GRACE and for none in LAPSED and REVOKED, and captures under NULL; `deny if not tenant_allow` never fires in GRACE, LAPSED or NULL, and at lapse + 1 ms does not deny (U); `allow if not tenant_allow` captures in GRACE, LAPSED and NULL; `deny if tenant_deny` fires only in FRESH; `allow if not tenant_deny` captures while STALE and is reported; `allow if tenant_allow is unknown` fires in GRACE, LAPSED and NULL and is reported as unbounded; `deny if tenant_deny is unknown` is refused by the polarity pass; a STALE tenant fill writes `stale-hit` or `stale-no-range`, never `unknown`; `WE_TEST_TENANT_ATOM_U` lets the bounded allow miss a listed address inside the grace; `WE_TEST_TENANT_BIT_IGNORED` denies at lapse + 1 ms |
| F5 | two NULL programs; floor NULL with a context program; a configuration with no floor directive anywhere | `test_policy`, module gates | steps 1 to 3.5 still run with the configuration's `we_hh_view_t` (built from the empty floor block); a hold-harmless floor address is exempt from steps 2 to 3.5 in every case, and the whole request is exempt when the server judges the same address (the same canonical address, or a server slot with no address); the tenant entry is filled with both programs NULL |
| F6 | behind a proxy the server's `realip` trusts: a listed client behind a loopback proxy and through the module's trust list; a hold-harmless client behind a public and a loopback proxy under `deny if not tor_exit` and under the default policy; the proxy's own request; ACME through the proxy; a forged server address (8.8.8.8, 127.0.0.1, 10.0.0.1, 198.41.0.4) under `deny if not tenant_allow`, with the floor eligible and not; a server slot with no address (family 0 or 5, `::` and 0.0.0.0), alone and behind a hold-harmless floor; `::ffff:127.0.0.1`, IPv4 junk tails, `::ffff:0:127.0.0.1` and `::127.0.0.1` against 127.0.0.1; the tenant's allow behind a hold-harmless floor in three tenant states | `test_policy`, reference | the listed client is denied at step 4; the hold-harmless client is denied by the operator's rule and allowed by the default policy with no reason (unlisted, not exempt); the proxy's own request and ACME are exempt; every forged address is denied at step 4 as an arbitrary one is; a slot with no address judges the floor's address and is exempt behind a hold-harmless floor; the mapped form and junk tails are one address, the SIIT and IPv4-compatible forms two; the tenant's allow never allows the client behind a hold-harmless floor; `WE_TEST_HH_FLOOR_ENDS_ALL`, `WE_TEST_HH_SERVER_EXEMPT`, `WE_TEST_HH_RAW_COMPARE` and `WE_TEST_SERVER_UNSET_KEYED` each fail here |
| D1 | each non-tenant plane × its two states, the tenant plane × its five, × a program with a dependent rule, an independent rule, a capturing allow above an independent deny, and a positive `allow if tenant_allow` above a deny | both, all state vectors | final verdicts equal the reference's; the independent deny's verdict **does** move under the capturing allow; the tenant property in two parts: (1) no `deny` or `log` rule's own value moves toward TRUE because of any tenant state; (2) the final verdict moves toward deny only when the bounded allow reads F (LAPSED, REVOKED, or an address added after the plane went stale, in GRACE) and the deny's own condition is TRUE on definite data; `WE_TEST_NO_CAPTURES` names the deny as unaffected |
| D2 | inert / narrowed / captures per (rule, out-set, tenant sub-state): `log if tor_exit is unknown`; `deny if tor_exit or c2` under tor, under threat, under both; `allow if tor_exit or asn in @partners` under tor (captures); the correlated-atom rule; the tenant rows; the tenant plane's `out_mask` bit set and clear with the same `tenant_state`; an inert rule neither shadows nor is shadowed | both | value-set class equal in both; soundness against brute force: never `inert` where exact is `narrowed`, never omits `captures` where exact has it; `WE_TEST_CLASSIFY_ISUNK_U` classes the log rule inert; `WE_TEST_CLASSIFY_SINGLE_EVAL` classes the `or` allow narrowed |
| D3 | REVOKED tenant: arm generation G, revoke through `we_handle_publish_map()`, evaluate, offer a verified `tenant.bin` of generation G - 1, then G, then G + 1; restart with the high-water file present; restore the pre-revocation directory snapshot and reload; a format-2 file with generation 0 | both, ASan | `tenant_allow` F, `tenant_deny` F, `tenant-revoked`, `is unknown` F while revoked; G - 1 and G refused, G + 1 arms; `h->generation` still reads G after the revoke; after the restart and after the restore the old file is refused; the generation-0 file is refused by the loader; the retirer frees the heap map without a fault |
| D4 | ABSENT at config; reload with the plane present; a block offered to an environment it was not compiled for | `test_policy` | the rule is inert in the first block; the reload produces a **new block** in which the rule is armed, the old one unchanged byte for byte; the report names the absent plane and the exposed denies; `we_program_env_matches()` refuses the block where routing is absent and in a legacy configuration |
| D5 | a NULL map in a view the module filled | `test_policy` | reads UNKNOWN; no fault |
| D6 | `we_ctx_conf_t`: a zeroed conf, `mode` 7, a NULL `ctx_conf` beside a non-NULL context program, a NULL `floor_conf` beside a non-NULL floor | `test_policy`, reference | each reads as dry-run `log` with `allow_inferred` off: the verdict is logged, never a deny; no fault |
| D21 | the attribute table and the verdict lines a tool renders | `test_policy` | `we_attr_count()` is 25 and an index past it is refused; every attribute is described, and `registry_country` and `registry_rir` read the registry plane; `we_attr_render` renders `asn` 0xFFFFFFFF and `country` 0 as `undetermined`, a country code the table does not know (999) and one above 999 as `undetermined`, never in decimal, `asn` 64496 in decimal, `country` 528 as `NL`, a level, `rpki` 3 as `not-found`, a set bool as `true`, a bool on an unknown or stale non-tenant plane as `unknown`, an unread plane as `unread`, a stale tenant plane as `stale:<value>` within its grace and `lapsed:<value>` past it, a revoked one as `revoked`; `we_verdict_format()` writes both lines and reports a short buffer while still terminating it |
| D23 | a FIFO at `tor.bin`, a device link at `threat.bin`, an empty regular `anonymizer.bin`, an absent `reputation.bin` | `test_policy` | `we_policy_env_probe()` returns without blocking; the FIFO and the device are present and not schema-ok; the empty file is present and not ok; the absent file stays absent |
| M1 | floor ≠ server address, same plane: two slots; equal addresses: one slot; equal addresses with the floor reading {reputation, tor} and the context {tor, routing}; `::ffff:a.b.c.d` and `a.b.c.d`: one key; `::`, `::1` and `::a.b.c.d`: IPv6 keys; IPv6 at every key width | both, trace | `lookups` equal the union form for equal keys and the sum form for distinct keys (§3.7); each program reads its own planes' entries (tor filled once, read by both; routing filled by the context only); `WE_TEST_NO_MEMO_RESET` fails when the records differ per address |
| M2 | the mapping overwritten after the fill; a retire between `we_decide` and a log-phase read | `test_policy` under ASan | the variables read the copy; the log-phase fill re-takes `we_current()` and records a new generation |
| M3 | the last record of each family and stride flush against a guard page | `test_policy` | no fault; the copy's traced reads equal the record lines the plane model counts for a hit |
| M4 | every record byte value: `rov`, `rir`, `asn_rep`, `reason` 0..255, `country` 0..65535, flags with undefined bits, sev 0x05..0x0F and 0x10/0x20; a record with `rov` 4 beside a no-range address | both, UBSan with `-fsanitize=alignment` | clamped values equal the reference's; no undefined shift and no misaligned load; the record's `rov` 4 reads `undetermined` while no range reads `unrouted` (the template is unclamped); `WE_TEST_NO_CLAMP` reads past the bitmap under ASan |
| M5 | slot and descriptor layout | `test_policy`, `test_core` | static assertions on 32-byte entries at `64 + 32·(plane_id - 1)`, the 64-byte line 0, `sizeof(we_fam_t) == 96`, `offsetof(we_map_t, f4/f6/f6w) == 0, 96, 192`, `offsetof(we_map_t, valid_until_ms) == 296`; the run-time assert `((uintptr_t)m & 63) == 0` on every map the publish paths and `we_program_place` produce; a reset touches two stores (traced); the traced descriptor lines per fill equal 3, 3 and 2 by family |
| S1 | value sets of each class; wrong class; inner-context use; shadowing; duplicate definition; a duplicate member; `@s undetermined`, `@s undetermined KP`; a context of any depth and length, and one the configuration never named | both | accepted, refused or reported per §1.5 and §4.1; `has_undetermined` encoded per kind; an unnamed context resolves to its nearest named ancestor |
| S2 | ASN sets at n in {1, 16, 17, 272, 273, 538, 539}, every member and a non-member at each leaf, a probe below the smallest member with the payload's front against a guard page; an unrouted address against a padded set with `has_undetermined` 0 and 1, with the largest payload's end flush against a guard page; n = 0 for a routed and an unrouted address; a set containing AS4294967294 with `has_undetermined` 0 and 1, probed with `0xFFFFFFFE` and the sentinel; the country bitmap at every known code and an unknown one | both, trace, ASan | membership exact; the probe below the minimum is a non-member and its traced reads stay inside the payload; the unrouted address is a member iff `has_undetermined`, including against the AS4294967294 set; n = 0 compiles to `EQ32` and reads no payload; no fault at either guard page; traced lines equal the level count per lookup; the payload bytes equal the S+ formula; `WE_TEST_SENTINEL_PADDING` admits the unrouted address; `WE_TEST_SPLUS_NO_CLAMP` is caught at the guard page |
| S3 | an address literal in a set | `test_policy` | refused with the fix naming `tenant_allow` and `op:policy` |
| G1 | sugar: the five threshold programs, then 3 × 5 × 2 (mode, threshold, `allow_inferred`) through the conf | `test_policy` | bytes equal the compiled canonical text; verdicts equal `we_should_deny` over all 256 sev bytes × 2 inferred flags; `mode log` keeps action `deny` |
| G2 | the three modules' config-test line; the legacy synonym with the file absent at config test | module gates | the line present once per context; the sugar rule is **not** inert |
| G3 | two contexts with the same text under `mode log` and `mode deny`; a parent in `deny` and a child in `log` with no lines; two contexts whose text differs only in a `floor`/`legacy` flag | `test_policy`, module gates | the first pair shares **one** block (`memcmp` equal) and gives different verdicts through their confs; the child runs the parent's block under its own `log`; the flag pair gets two blocks |
| G4 | the block's and the hold-harmless view's pages after fork | module gates | `Shared_Clean` for both ranges in two workers' `/proc/<pid>/smaps`; the configuration's hot-bytes total printed at config test |
| X1 | the differential, all legs, every line per case | `policy_diff.py` | zero disagreements; `WE_TEST_NO_MEMO_HIT` and `WE_TEST_NO_SHORTCIRCUIT` disagree on the cost line only |
| X2 | the twenty-five mutants | `policy_diff.py` per mutant, `policy-mutants.sh` | each caught with the catch count above its floor; its named row fails; the two standing controls fail their rows on every run |
| X3 | corpus replay without a fuzzer | `make check` | the invariants of §5.3 hold over every corpus, seed and adversarial file; the seed floor is met; removing one file fails the floor |
| X4 | `make fuzz`, `fuzz_program` | CI | no crash, no sanitizer report |
| X5 | the invariant line `ISUNK(x) == (K3value(x) == U)` over every atom and state | `policy_diff.py`, `test_policy` | equal in both and TRUE on every case, the tenant plane's five states included |
| H1 | the evaluator wrappers at four levels on five compilers, both architectures, every flag set of §3.7 | `hotpath-gate.sh` | no reloc, branch to a call, class, barrier, lock, fence, xchg; no locals except the measured clang x86_64 frame-pointer legs of §3.7 and `hpmod`'s two x86_64 legs there, and no `.rodata` except clang 20 x86-64-v3 (§3.7); frame under 256 |
| H2 | the evaluator controls under `gate/` | `hotpath-gate.sh` | each refused by its named check at every level where it builds |
| H3 | `mprotect(PROT_READ)` on the block, the hold-harmless view and every plane | `test_policy`, differential, `WE_TEST_PLANTED_STORE` | every leg passes in the production build; the standing `WE_TEST_PLANTED_STORE` build faults, caught and reported on this row, every run |
| HH1 | every hold-harmless lookup over every outcome class of the merged table, both families, at strides 16 and 4; a block with a wrong span | trace build, `test_policy` | traced probes and lines equal the model per lookup; the maxima equal the generated header's (3 lines IPv4, 4 lines IPv6 for today's file); the wrong span is refused by verifier step 20 |
| A1 | a canonical address defines every byte: `198.51.100.7` and `::ffff:198.51.100.7` through `we_addr_canon()` into buffers holding different bytes, and a third address as the control | `test_policy` | the pad bytes are written zero and the two forms compare equal by `memcmp` while the control compares unequal |
| C1 | every evaluator slot | `cachegrind-gate.sh` | every slot within ±10% per compiler on both architectures; the soundness inequality of §3.7 holds per slot with every named term and tightness ≥ 0.8; the basis system has full rank; every derived constant within ±10% of its committed value; `evaluator-worst` attains the maximum of the composed bound over the feasible count vectors |
| C2 | `WE_TEST_NO_MEMO_HIT` on `evaluator-default` | `cachegrind-gate.sh` | outside the band |
| C3 | `evaluator-worst` and `evaluator-worst-lines` construction | trace | instructions executed == `floor_instr + ctx_instr`; `jumps_taken == 0`; on `evaluator-worst-lines`, `lookups == 16` and every fill and the hold-harmless lookup at the maximum-lines class of its fixture |
| C4 | residency rows | `cachegrind-gate.sh` | alone-rows present for each default plane with the level stated; program misses zero in the LLC run; plane-index misses beside the program within ±10% of their alone-rows |
| C5 | the whole bound per request, every slot and every exhaustive vector | trace build with `WE_TRACE_EVAL` | traced distinct lines per request **equal** the model per outcome class; the maximum equals the printed bound in both forms (64- and 128-byte lines) |
| B1 | `bench_core`'s policy table | `make bench` | computed columns equal the trace build's maxima over the exhaustive vectors; the keyed record is written and re-read |
| Z1 | the published check count in REFERENCE.md | `make check` | equals this run's sum of `N checks` lines |

## 10. What is not claimed

- The outage classifier is exact under per-occurrence independence and sound against the exact
  classifier in the two directions §2.5 states; it may say `narrowed` where the exact answer is
  `inert`, and `captures` where the exact answer does not capture.
- The shadowing report under-approximates the semantic definition: it reports only what the syntactic
  procedure of §2.5 proves.
- Monotonicity (F < U < T) holds only for `is unknown`-free subformulas.
- On live planes, Σ maxLines is an upper bound one address may never reach; a printed live bound says
  so.
- The worst case's first-level-cache misses per request are published separately and never composed:
  a 66 KiB instruction block streams through a 32 KiB D1, so its per-operation figure is not a constant.
- The hot-path gate cannot see a store through a pointer; that half of the no-store claim rests on the
  `mprotect` legs (row H3).

## 11. Decisions

Each decision is a rule both implementations follow; the section that carries it is named.

- **D1.** No unconditional rule. `action if expr` is the only form; a bare `deny` would have an empty
  `dep_mask` and would deny a whole site while its earlier allow is inert at config, which is a
  fail-closed path; the refusal's fix prints `deny if not <condition>` (§1.1, §1.5).
- **D2.** Shadowing is reported, never refused, with this definition: R1 shadows R2 iff R1 is not a
  `log` and, for every record and plane state where R2 is TRUE, R1 is TRUE (a `deny`) or TRUE-or-U
  (an `allow`); `log` rules are never shadowed; both implementations print the same report (§1.5,
  §2.5).
- **D3.** Explicit `allow` hits are counted, by the module, on fired rules only, into sharded
  per-thread counters (§3.6).
- **D4.** The compiler prints possible-values coverage; the routing-table share of a coverage figure is
  a build-time figure outside the compiler (§2.6).
- **D5.** There is no keyless local address list; an address-shaped literal is refused with a fix that
  names the tenant plane (§4.2).
- **D6.** The evaluator lives in `we_eval.h`, header-only (§3.1).
- **D7.** The core owns steps 1 to 3.5, with `hold_harmless_eligible` and canonical addresses in
  `we_request_t` (§3.1, §3.2).
- **D8.** The modules use the compiler at configuration time for the threshold sugar: they log the
  equivalent line from `we_policy_sugar()` and arm the block `we_policy_sugar_env()` compiles for the
  configuration's environment (§7, D-af).
- **D9.** No `locals-ok` allowance on the evaluator: where a toolchain would spill, scratch moves into
  `*out` (the verdict's `sc` block) first, and the measured price, more data references under
  cachegrind than a register-held loop, is accepted (§3.7).
- **D10.** `is unknown` in a `log` rule is allowed in either polarity, with `ISUNK = T` in the
  classifier; a server `if` on `$whisper_edge_rule` turns such a log into enforcement outside the
  language, and the README says so (§2.5).
- **D11.** The differential runs over the live-shaped fixtures too, with the cost columns, and the
  `evaluator-default` slot uses live-shaped planes (§5.2, §6).
- **D12.** Sets are S-trees with a fixed-iteration search; lines equal depth (§4.1).
- **D13.** Policy lines replace inherited lines on all three servers; a lineless context inherits the
  parent's program (§2.5).
- **D14.** `listed` reads `critical` for sev nibbles 5..15; flag bits 0x10, 0x20, 0x40 are ignored
  (§1.4).
- **D15.** Program limits include 8,448 instructions and 256 KiB of hot bytes; the canonical text is
  cold and uncounted; both sizes are printed, and the limits are refused before anything is allocated
  (§2.1).
- **D16.** The tenant atoms: the pre-stage's bounded five-state reading applies to one occurrence only,
  `tenant_allow`, positive, inside an `allow` (definite in FRESH; the stale record within the 48-hour
  grace; F past it; F under REVOKED; U under NULL). Every other occurrence of `tenant_allow`, and
  `tenant_deny` always, follows uniform K3 (U when STALE or NULL, F when REVOKED). The compiler sets one
  polarity bit in the tenant `BOOL`'s `imm`, the verifier checks it, the evaluator selects without a
  branch; `tenant_allow is unknown` reads T whenever the plane is STALE or NULL; the classifier and
  `we_program_dependents()` take the tenant sub-state; the 48-hour edge is logged as a transition; the
  `adds-nothing` report covers positive allow uses only (§2.2, §2.5, §3.2).
- **D17.** Classification is by value sets per occurrence; the soundness property covers `captures`;
  the capturing-allow report fires for every plane (§2.5).
- **D18.** The independent corpus under `core/testdata/policy/` is the third leg; neither
  implementation's authors edit it to make a build pass; row N1 replays it (§5.3).
- **D19.** Memo entries are indexed by `plane_id - 1`, eight fixed entries per slot (§2.7).
- **D20.** The hold-harmless table is offsets in the floor block and a `we_map_t` view built once per
  configuration outside the block; strides 16 and 4, with the trace model extended to them (§3.8).
- **D21.** Programs are interned on the digest of the whole verified block, confirmed by `memcmp`;
  `mode` and `allow_inferred` live in the context's `we_ctx_conf_t`, never in the block (§2.1).
- **D22.** The shadowing report is produced by the syntactic subsumption procedure of §2.5, normative
  in both implementations; the semantic definition is the specification it under-approximates.
- **D23.** ASN sets are S+ trees (keys in the leaves); `(a == 0xFFFFFFFF) ? has_undetermined : found`
  is the membership result (§4.1).
- **D24.** `we_addr_canon` unmaps `::ffff:0:0/96` only; `::a.b.c.d`, `::` and `::1` stay IPv6 (§2.7).
- **D25.** REVOKED is published through `we_handle_publish_map()` and checked before `we_is_stale()`
  (§2.7).
- **D26.** The S+ search runs on `a' = a - (a == 0xFFFFFFFF)`, and the member count n is packed into
  `imm`'s ten high bits (§2.2, §4.1).
- **D27.** The soundness inequality has one measured constant per identifiable basis term, `c_fill`
  is the slope minus the find, `c_prestage` excludes the tenant and hold-harmless finds, `L(p)` comes
  from lookup-only rows on each slot's own fixtures, and the worst case is asserted maximal;
  `evaluator-worst-lines` carries the lines-and-lookups maximum (§3.7, §6).
- **D28.** The core allocates every `we_map_t` with `aligned_alloc(64)`, with a run-time alignment
  assert; `D(family)` is 3, 3 and 2 lines; `W(ctx)` counts shared lines (§2.7, §3.7).
- **D29.** Every configuration has a floor block, empty when none was written; the hold-harmless view
  is protected and shared like the block; `we_program_place()` runs after `we_program_verify()` (§3.8).
- **D30.** The format-2 publish path is `we_handle_publish_plane()`; the rollback check uses the
  current map's generation; the high-water mark survives revocation (§2.7).
- **D31.** `we_ctx_conf_t` has a defined domain, the pair, and every undefined value reads as the
  shipped dry-run default (§3.1).
- **D32.** The compiler's canonical text is exempt from the argument-length check on re-parse
  (`we_policy_env_t.canonical`), because the canonical form may be longer than a legal unspaced source
  (§5.5, §7).
- **D33.** The soundness constants are `gate/cost-model.py`'s identifiable basis (each atom kind by
  outcome with its `and` link, `NOT`, the `or` link's extra, each way a rule ends, a taken jump),
  solved jointly as an exact linear system with a rank check; `c_fill` per schema; the worst case
  maximal over feasible count vectors; the worst fixtures synthetic so one address attains every
  plane's maximum class (§3.7, §6).
- **D34.** The hold-harmless view lives in the mapped region with the blocks; the leaf compare is
  `k[max(c, 1) - 1]`; an ASN set with no numeric member compiles to `EQ32` against the sentinel (§2.2,
  §3.8, §4.1, §5.5).
- **D35.** The high-water generation is persisted outside the plane directory in a root-owned file,
  `/etc/whisper-edge/state/tenant.high-water`, in the one subdirectory the keyed refresh unit may write,
  written by the refresh and read with the tombstone and `tenant.bin` at configuration load and at every
  tenant plane reload under a shared `flock`; the module raises its mark by an atomic compare-exchange
  max, a malformed file causes no transition (NULL at configuration load), REVOKED is published on a
  transition only, NULL through a fresh handle seeded from the file, and one thread per handle runs the
  reload and every publish; generation 0 is refused in format-2 headers and by
  `we_handle_publish_plane()` in format 1 (§2.7).
- **D36.** The memo has `stale-hit` and `stale-no-range` states for the tenant plane; row D1's tenant
  property is two-part; `deny if not tenant_allow` under LAPSED is inert; subsumption is
  polarity-bit-aware (§2.5, §2.7, §9).
