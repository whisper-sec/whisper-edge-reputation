# Adversarial inputs

These were written against the policy compiler and verifier, each to push one place where the
compiler and the reference interpreter could part ways or where the compiler could crash. They are in
the corpus's record format (`<kind> SP <context> SP <argument> 0x1E 0x0A`) and carry no `.expect`. Each
one runs three ways:

- the differential: `policy_gen.py` writes every `.policy` file under `testdata/policy/` as a program
  (the `files` leg), so the compiler and `policy_ref.py` must print the same refusal, or the same text,
  reports and verdicts;
- the parser fuzz harness's replay, under ASan and UBSan, which compiles each one in every program it
  holds and evaluates what compiles;
- `test_policy`, which holds the hot-byte boundary to `h1`, `h2` and `h3` by name.

| prefix | what it pushes |
|---|---|
| `a` | the 2,048-byte argument limit, with multi-byte UTF-8 straddling it |
| `b` | `@` inside braces and in a set declaration |
| `c` | a set declared after its use, in a parent, of the wrong class or domain, `undetermined` alone against `listed` |
| `d` | nesting at 15, 16 and 17 levels of `not` and parentheses, mixed |
| `e` | `undetermined` as a set member, inline and named, against `asn`, `listed` and a bool |
| `h` | the 256 KiB hot-byte limit: exactly at it, 64 bytes over, and a floor whose hold-harmless arrays cross it |
| `m` | mixed-class sets, inline and declared, and the uniform set of the wrong class |
| `o` | the order of the refusal layers across directives and contexts |
| `x` | asdot, `1e3`, and the AS set of 539 and 540 members |
| `z` | contexts nested deeper than the compiler's first context table could hold (`z1`, `zz`), and six nested locations as nginx writes them |

`z1` and `zz` crashed the first compiler: its context table was sized by a guess and a deep context wrote
past it. `h3` found that the reference interpreter left the floor's hold-harmless arrays out of the hot
bytes. Both are fixed, and these files keep them fixed.
