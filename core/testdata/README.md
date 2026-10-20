# Test fixtures

Checked in so the gates in this directory are runnable with nothing but a C compiler. The count used
to be written here as a word and went stale on the edit that added the fourth file, which is the
defect this README's own last paragraph warns about; the table is the count.

| file | what it is |
|---|---|
| `interop.snap` | a snapshot in the published binary format |
| `expected.txt` | the verdict each address must get from it, one per line |
| `disarmed.snap` | an ENTRY-LESS snapshot: the shape the break-glass publishes, which a reader must accept and answer `allow` from |
| `rpz.zone` | the same policy as a complete, loadable Response Policy Zone |
| `format2/routing.bin` | a format-2 `routing` plane: IPv4 radix-18, IPv6 rank-64s at 64-bit keys, a narrowed /64, the feed table with one entry |
| `format2/routing-expected.txt` | per address: `family address 0`, or `family address 1 asn country rov rir flags asn_rep` |
| `format2/routing.manifest.json` | the plane's manifest object: index kinds, the lookup bounds per family, `sha256` and `contentDigest` |
| `format2/tor.bin` | a format-2 `tor` plane: IPv4 radix-12, IPv6 rank-32s at 128-bit keys, a 13-entry feed-name table |
| `format2/tor-expected.txt` | per address: `family address 0`, or `family address 1 flags source reason` |
| `format2/tor.manifest.json` | as for routing |
| `format2/tenant.bin` | a format-2 `tenant` plane from the on-demand tenant builder: allows and denies in both families, overlaps, adjacent equal neighbours merged, rank in both families, the three-entry feed-name table `""`, `tenant:<id>`, `rev:<edge.at>` and source 1 on every record |
| `format2/tenant-expected.txt` | per address: `family address 0`, or `family address 1 flags source reason`, computed from the prefixes and never from the plane |
| `format2/tenant.manifest.json` | as for routing |
| `format2/tenant-full.txt` | exactly what `plane_check --dump-full tenant.bin` must print |
| `format2/tenant-w1.bin`, `-w64.bin`, `-w65.bin` | tenant planes at the rank strides' edges: 1, 64 and 65 IPv4 ranges and 1, 32 and 33 IPv6 ranges, single-window (depth 0, no separators) up to the stride and two-window past it; each with its `-expected.txt` and `.manifest.json` |
| `format2/tenant-empty.bin` | a tenant plane with no ranges, index kind none in both families, and its `.manifest.json`; it has nothing to hit, so no expectations file |
| `format2/names.bin` | a `tor` plane whose feed names hold a space and a newline, a literal backslash before `x41`, a plain `A`, and two double quotes; with `-expected.txt`, `.manifest.json`, and `names-full.txt`, what `--dump-full` must print, each name one escaped token |
| `policy/` | the independent policy-language corpus: 20 programs that must compile under `accept/`, 50 that must be refused under `refuse/` with a sibling `.expect` naming the layer, line, column, token and message, and `refusals.tsv` as the one table; written against POLICY.md §1 before the compiler or the reference interpreter existed, so it counts as a third leg; its own `README.md` records the record format and every byte-exact file's `printf` recipe |

The `format2/` files are written by the Java builder's writer, and the builder's own fixture test fails
if they differ by one byte from what the writer produces now, so they cannot drift; after a deliberate
format change the builder regenerates them.
The tenant planes bind the tenant id of one documented fixture owner, `user_edge_fixture`: the first 16
lower-case hex characters of `SHA-256("whisper-edge-tenant-v1" || 0x00 || "user_edge_fixture")`, which
the interop gate derives on its own and holds every tenant plane's feed-name entry 1 to.
Like the others they use documentation space only (RFC 5737, RFC 3849, RFC 5398 AS numbers) and the end
points of the address space.

`interop-gate.sh` loads the snapshot with the real reader and checks every line of `expected.txt`,
plus one evidence lookup. It prints the count it checked rather than relying on a number written here,
because a count in a README goes stale on the edit that changes it - this line used to say 41 where
the file had 39 and the gate reported 40.
`../../rpz/rpz-gate.sh` loads it into a real BIND as a legacy file when pointed at it with `RPZ_BODY`; the
per-zone fixtures it proves by default live in `../../rpz/testdata/`.

## Why they are checked in rather than generated

The snapshots we publish are produced by a builder that reads our graph, and that
builder is not in this repository. If these gates could only run against its output, nobody outside
could run them - and a gate a reader cannot run is a claim rather than a check.

So the fixtures are fixed, small, and deliberately boring. Every address in them is from documentation
space (RFC 5737, RFC 3849) or is a well-known address, and `expected.txt` was produced by the real
builder and then frozen. Point the gates at your own files with `WHISPER_EDGE_FIXTURE=<dir>` or
`RPZ_BODY=<file>` if you want to check something else.

They are NOT a sample of the real feed and are not useful as one. For that, fetch
`https://whisper.online/edge/snapshot.bin`.
