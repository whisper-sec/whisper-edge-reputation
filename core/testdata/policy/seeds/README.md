# The seed list

These are adversarial seeds against POLICY.md §1, committed as written, one file per seed, with the
three number forms `1e3`, `0x10` and `1_000` beside them. They are inputs, not expectations: a seed carries no `.expect`, because what it
must do is the same for every one of them. It compiles, or it is refused with a located error in one of
the eight layers, and it never crashes either implementation. The corpus beside this directory says what
the right answer is; the seeds say where to push.

Three kinds of file:

| suffix | what it is | who replays it |
|---|---|---|
| `.policy` | directives in the corpus's record format (`<kind> SP <context> SP <argument> 0x1E 0x0A`) | `policy_ref.py --seeds`, and the parser fuzz harness's replay mode and its fuzzer corpus |
| `.case` | records for the evaluator, in the case format `policy_ref.py` documents; a `sweep` line expands one case into one per field value | `policy_ref.py --seeds`, and `test_policy` |
| `.c-only` | a construction only the C harness can make (a guard page, a NULL view, a state byte), described in words | `test_policy` |

The replay fails when this directory holds fewer files than the seed floor in `../../../Makefile`
(`POLICY_SEED_FLOOR`), so a deleted seed cannot pass silently.

## The list, as written

- **Nesting:** 16 and 17 levels each of `(`, of `not`, and of the two mixed; a run of 1,000 `(`; `not not x is not unknown`.
- **Lengths:** an argument of exactly 2,048 bytes and of 2,049; identifiers of 64 and 65 bytes; a 65-byte non-ASCII token.
- **Bytes and line endings:** NUL in the middle of an argument; CR-only, CRLF and lone LF; HT, VT and NBSP as separators; U+200B; Cyrillic letters inside `{ }`; `#`; an empty argument; a whitespace-only argument.
- **Keyword collisions:** `IN`, `DENY`, `AND` in expression mode; `{ in is or no as do }`; `asn == AS` and `country == AS`; `{ AS64496 AS }`; `asn in { asn length }`; `rpki == XX`; `uk`.
- **Numbers:** `0`, `AS0`, `00`, `010`, `-1`, `+1`, `AS1.10`, `4294967294`, `4294967295`, `4294967296`, a 25-digit number.
- **Commas and braces:** `{ , NL }`, `{ NL, }`, `{ NL,,,BE }`, `{ }`, `{ , }`, `{ { NL } }`, `{ NL` with no closing brace, `country == { NL }`.
- **Sets:** `@`, `@@x`, `@ x`, `@a @a`, `@b @a`, `@s undetermined`, `@s undetermined KP`; a set used before it is defined (the design example does this); a duplicate set; shadowing an outer set; 1,024 and 1,025 sets; an ASN set filling 2,048 bytes; `{ NL NL nl }`.
- **Operators:** `===`, `=>`, `<>`, `!`, `rpki==valid` with no spaces, `deny if if x`, `deny if`, `deny x`.
- **Limits and polarity:** 256 and 257 rules; 4,096 and 4,097 ops; every rule reading all 8 planes; the design example's allow/`is not unknown`; the same allow with and without a later deny; `listed >= none`; `listed < low`; `deny if (tor_exit and not tor_exit) or listed >= low`.
- **Records:** every enum field at 0..255, country at 0..65535, sev bytes 0x05..0x0F and 0x10/0x20; a last record ending at a page boundary; `::ffff:` forms; a NULL map marked FRESH; a plane state of 7; `valid_until_ms` of 0 and `UINT64_MAX - 1`.

Added in the second round: `1e3`, `0x10` and `1_000`.

## Where each item went

The file names follow the list's groups: `nest-*`, `length-*`, `bytes-*`, `keyword-*`, `number-*`,
`comma-*` and `braces-*`, `set-*`, `op-*`, `limit-*` and `polarity-*`, `records-*`. Where the list names a
fragment rather than a whole rule, the seed puts it in the smallest rule that reaches it (`deny if asn ==
<number>` for the numbers, `deny if country in { ... }` for the brace forms, a `whisper_edge_set`
argument for `@a @a`). `!` is written `deny if ! tor_exit`, a lone `!` where a word belongs. "Every
enum field at 0..255" is five sweeps (routing `rov`, `rir`, `asn_rep`; rpki-unreachable `reason`;
registry `rir`); "country at 0..65535" sweeps the routing record's country; the sev seed sweeps
0x05..0x0F and adds 0x10 and 0x20 alone and beside a severity.

## Found by the fuzzer

- `context-deeper-than-the-table.policy`: libFuzzer's first find, in its first minute against the C
  compiler. A context with more path segments than the compiler's context table had rows (it was sized
  by a guess, four per directive) wrote past the table into the directive array. The table is now
  sized from the source, one row per path prefix, and this input stays as a seed so the fuzzer's corpus
  starts from it.
