# The policy corpus

Seventy programs for the edge policy language, written against POLICY.md's grammar, lexical contract
and refusal list (§1) before the compiler or the reference interpreter existed. Twenty must compile. Fifty must be refused, each in a stated layer with a stated message.

## Written independently

The corpus is the third leg beside the C compiler and the Python reference interpreter, and it only
counts as a leg if it shares a misreading with neither. So it was written by someone who wrote
neither implementation, from POLICY.md's lexical table (§1.2), its refusal shape, order and list
(§1.5), and never from code. If an implementation and this corpus disagree, POLICY.md
decides. When POLICY.md is wrong, POLICY.md is changed first, then the corpus. A file is never edited
just to make a build pass.

## Layout

| path | what it is |
|---|---|
| `accept/NN-<slug>.policy` | a program that must compile in the default environment (below); it may also print reports |
| `refuse/NN-<slug>.policy` | a program that must be refused |
| `refuse/NN-<slug>.expect` | the one refusal that file must produce |
| `refusals.tsv` | the same expectations, one row per refuse file, for tools that want a table |

The two-digit numbers in `refuse/` follow the refusal order of §1.5: argument length, then a byte
outside the alphabet, then lexing, parsing, typing, set resolution (after every directive of the
context has been seen), program limits and polarity last.

## The `.policy` format

A `.policy` file is a sequence of directives. Each directive is one record:

```
<kind> SP <context> SP <argument bytes> 0x1E 0x0A
```

- `kind` is `policy` (`whisper_edge_policy`), `set` (`whisper_edge_set`), `floor`
  (`whisper_edge_policy_floor`), `threshold` (`whisper_edge_threshold`) or `mode`
  (`whisper_edge_mode`).
- `context` is a path: `http`, `http/server:<name>`, `http/server:<name>/location:<name>`. A set is
  visible in its own context and in every context below it.
- The argument is every byte after the second space, up to the record separator 0x1E. It is exactly
  what the server hands the module after its own quoting has been removed. It can contain LF, CR, NUL
  and any other byte. It never contains 0x1E, which is why 0x1E was chosen as the separator: the byte
  lies outside the language's alphabet, so the corpus cannot test it. `test_policy` tests every
  single byte value directly.
- Records keep their file order, and the ordinal of a directive among the directives of the same
  kind in the same context is its `rule` number.

Every file compiles in the **default environment**: all eight plane files present, each with the
schema its name requires. It is the environment the fuzz harness must use when its selector byte
asks for every plane.

## The `.expect` format and `refusals.tsv`

An `.expect` file is one `key<TAB>value` pair per line: `layer`, `kind`, `context`, `rule`, `line`,
`col`, `token` and `message`. `refusals.tsv` holds the same fields, with the file name first and a
header row. The fields are compared like this:

- `layer` is the group of §1.5's table that refuses the input: `length`, `alphabet`, `lexing`,
  `parsing`, `typing`, `sets`, `program` or `polarity`.
- `kind`, `context` and `rule` name the directive the refusal points at.
- `line` and `col` are 1-based. Only LF starts a new line, and `col` counts bytes. Both point at the
  first byte of the offending token, or one past the last byte of the argument when the refusal is
  "at the end of input".
- `token` is the lexeme as the modules print it: truncated at 64 bytes, every byte outside
  0x20..0x7E and every `"` and `\` written as `\xHH` with upper-case hex digits. An empty field means
  no token (end of input, or a length refusal).
- `message` is a phrase taken verbatim from §1.2 or §1.5, with POLICY.md's code formatting removed.
  The refusal's `what` or `fix` must **contain** it byte for byte. Some messages are fixed by POLICY.md
  word for word: `byte 0xHH is not allowed`, `did you mean GB`,
  `write country in { RU } or country == RU`, `rpki takes valid, invalid, not-found, unrouted or
  undetermined`, `deny if not <condition>`, and POLICY.md's polarity sentence, matched here by its
  clause `that is a fail-closed rule`. For every other refusal the message is the phrase that names
  the refusal in §1.5's table, so the table is the one source of the strings.

These conventions are this corpus's, and they are pinned here so both implementations meet them:

- A **length** refusal happens before anything is read, so it reports line 1, column 1 and no token.
- An **alphabet** refusal reports the single offending byte as its token.
- A **set** reference token includes its `@`, and a set declaration is refused at column 1 with the
  set's name as the token.
- A **program limit** reports the first directive past the limit: the 257th rule at its first token,
  and for the operation limit the token that brings the context's count to 4,097. Operations are
  counted in source order: atoms, connectives and unary `not` each count when their token is read.
  The per-rule limit is counted the same way.
- A **polarity** refusal points at the `is` of the offending `is unknown`, in the rule that contains
  it.

## How `make check` uses it

`fuzz_policy`, built with a plain `main()`, replays every file here. Every `accept/` file must
compile, pass `we_program_verify()`, compile twice to identical bytes, and survive the round trip
through the disassembler. Every `refuse/` file must be refused, and its refusal must match the
`.expect` fields above (row N1 of POLICY.md's matrix). The reference interpreter replays the same
files and must print the same refusal line, so the corpus also feeds the differential. The replay
fails if this directory holds fewer files than the seed floor, so deleting a file cannot pass
silently.

A replay result means something only from the commit that made `fuzz_policy.c` compile onward: when
the harnesses first met the C core, `fuzz_policy.c` did not compile, so no replay or fuzzing run from
before that commit exercised the compiler.

## Byte-exact files

Most files are printable ASCII. These are not, and they matter to the byte. Check them with
`od -c` before you trust an editor, because many editors normalise exactly these bytes. Each one can
be rebuilt with `printf`. The 0x1E 0x0A at the end of every record is written `\036\n` below:

| file | the bytes that matter | rebuild |
|---|---|---|
| `refuse/02-length-before-alphabet.policy` | NBSP (0xC2 0xA0) at column 7, inside a 2,049-byte argument | not by hand: 2,049 bytes |
| `refuse/03-alphabet-nul.policy` | NUL at column 13 | `printf 'policy http/server:a deny if tor_\000exit\036\n'` |
| `refuse/04-alphabet-nbsp.policy` | 0xC2 0xA0 at column 8 | `printf 'policy http/server:a deny if\302\240tor_exit\036\n'` |
| `refuse/05-alphabet-zero-width-space.policy` | U+200B (0xE2 0x80 0x8B) at column 17 | `printf 'policy http/server:a deny if tor_exit\342\200\213 or c2\036\n'` |
| `refuse/06-alphabet-cyrillic-in-braces.policy` | U+0412 (0xD0 0x92) at column 25 | `printf 'policy http/server:a deny if country in { NL \320\222E }\036\n'` |
| `refuse/31-parsing-whitespace-only-argument.policy` | SP HT CR LF VT FF | `printf 'policy http/server:a  \t\r\n\v\f\036\n'` |
| `refuse/32-parsing-cr-only-is-whitespace.policy` | CR as the only separator | `printf 'policy http/server:a deny\rif\rtor_exit\rgarbage\036\n'` |

The four files at a limit are long and regular: `accept/16`, `accept/17`, `refuse/01` and
`refuse/02`. The limit is in the length, so check the length, not the look. `accept/17` is exactly
2,048 argument bytes with no optional whitespace (`listed>=high`, `in{0,1,...}`). `refuse/01` and
`refuse/02` are exactly 2,049. `accept/16` declares 538 distinct ASNs, POLICY.md's maximum set
size. Its members are the integers 0 to 537 rather than documentation AS numbers (RFC 5398), because
the size limit depends on digit counts and there are only 32 documentation numbers. Elsewhere the
corpus uses documentation AS numbers.

## What the accept files cover

Every attribute type and every literal form of §1.3. `not-found` in all three spellings. Every ASN
form: `0`, `as0`, `4294967294` and `undetermined`. Country codes in every case, `EU AP ZZ XK`, and the
keyword collisions `IN IS NO AS DO` inside braces and after `==`. Named sets holding `undetermined`
and `AS0`, a set holding only `undetermined` used against `asn`, and sets declared after the rule
that uses them. Commas leading, trailing and doubled. The tenant idioms, including `deny if not
tenant_allow`. `is unknown` in log rules, in a floor log rule, and in an `allow` with no later deny.
The terminal `deny if not <condition>` form. Nesting at 16 with parentheses, with `not`, and with
the two mixed. 64 operations in one rule. 256 rules with 4,096 operations in one context. The
538-member set and the unspaced 2,048-byte argument. Floor, server, location, a context with only a
`mode`, and one with only a `threshold`. Some accept files must also print a report (for example
`deny if listed >= none`, `deny if not tenant_allow`, and the capturing and "adds nothing" reports);
the corpus asserts only that they compile.

Hold-harmless has no syntax in the language: it is the data-free step 1 before any rule. So no
corpus file can express it. Rows F3 and F5 of POLICY.md's matrix cover it.
