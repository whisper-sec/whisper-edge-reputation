# The whisper edge plane format

This is the byte-exact contract between the builder (Java) and every reader
(`whisper_edge.h`, C; the install script's checks; the interop gate's independent writer). The design
it implements is decision 1 of a design record that is not published; a source comment that cites a
numbered design decision refers to that record, and [POLICY.md](../POLICY.md) ("How citations
resolve") maps each cited decision to the published document that carries it. If this file and that record ever
disagree, the disagreement is a bug, fixed here first, so a reader of this tree can take this file as
the contract.

Everything is **little-endian**. All offsets are from byte 0 of the file. `end` bounds are
**inclusive**. A reader that finds any rule below violated refuses the whole file with the named
error; it never reads around a defect.

## 1. The header, 192 bytes, unchanged in shape since format 1

| offset | size | field | rule |
|---|---|---|---|
| 0 | 8 | `magic` | `0x31504e5347444557` (`WEDGSNP1`) or `WE_ERR_MAGIC` |
| 8 | 4 | `format` | **1** or **2**; anything else `WE_ERR_FORMAT` |
| 12 | 4 | `flags` | bits below; unknown bits are ignored by a reader, which is the compatibility mechanism |
| 16 | 8 | `generation` | a strictly increasing per-plane epoch-seconds value, never 0: for a slot-built plane the slot start plus the offset of the kind of commit (the serial space, [ARCHITECTURE.md](../ARCHITECTURE.md)), for the tenant plane the keyed tier's rule (`max(edge.at, daySlot(fetch) + 3)`, the tenant plane, [POLICY.md](../POLICY.md) section 4.2); a reader refuses a publish whose generation is not greater than the one it has armed |
| 24 | 8 | `built_at_ms` | epoch milliseconds |
| 32 | 8 | `valid_until_ms` | epoch milliseconds; `now_ms > valid_until_ms` is **stale**, and 0 means no bound (`we_is_stale()`) (the clock a reader passes in is epoch milliseconds, `ngx_time() * 1000`, never a monotonic one) |
| 40 | 4 | `tier` | format 1: the reputation plane's evidence tier (1 = a citable listing at HIGH or above), informational; format 2: 0 for a keyless plane, 1 for a keyed one, written from the plane's tier. No reader gates on it: keyed-ness is decided from the manifest's `tier` and the plane's name, never from this byte |
| 44 | 4 | `v4_count` | n4 |
| 48 | 4 | `v6_count` | n6 |
| 52 | 4 | `v4_index_off` | radix: the bucket table; rank: unused, must be 0 (the samples live at `v4_sample_off` in the tail) |
| 56 | 4 | `v4_start_off` | `start[]`, **64-byte aligned** |
| 60 | 4 | `v4_end_off` | format 1: `end[]`; format 2: must be 0 (the end lives in the record) |
| 64 | 4 | `v4_sev_off` | format 1: `sev[]`; format 2: must be 0 |
| 68 | 4 | `v4_meta_off` | `meta[]`, u32 per range, offset into the blob; a cold column; 0 when absent |
| 72 | 4 | `v6_index_off` | as v4 |
| 76 | 4 | `v6_start_off` | as v4, 64-byte aligned |
| 80 | 4 | `v6_end_off` | as v4 |
| 84 | 4 | `v6_sev_off` | as v4 |
| 88 | 4 | `v6_meta_off` | as v4 |
| 92 | 4 | `blob_off` | evidence strings, NUL-terminated; never on the hot path |
| 96 | 4 | `blob_len` | |
| 100 | 4 | `file_len` | must equal the file size |
| 104 | 32 | `digest` | SHA-256 over the header with these 32 bytes zeroed, followed by the body; an **integrity** check, not authenticity |
| 136 | 56 | the schema tail | zero in a pre-schema format-1 file; described in §2 when `WE_H_SCHEMA` is set |

Header flags:

| bit | name | meaning |
|---|---|---|
| `0x0001` | `WE_H_V4_INDEXED` | format 1: a 65,537-entry u32 bucket table at `v4_index_off` (radix-16); format 2: a radix table whose k is in the tail |
| `0x0002` | `WE_H_V6_INDEXED` | as above for IPv6 |
| `0x0004` | `WE_H_SCHEMA` | the 56-byte tail describes the plane (§2). Set on every file the new builder writes, format 1 included |

**Format 1** is the shipped layout and is used by exactly one plane, `reputation`: `start[]` (u32 /
u128), `end[]` (u32 / u128), `sev[]` (u8: severity in the low nibble, `WE_F_DROP` 0x40, `WE_F_INFERRED`
0x80), `meta[]`, a radix-16 index when flagged. **Format 1 keeps the 65,537-entry index**: the shipped
loader validates `WE_V4_INDEX_ENTRIES * 4` bytes and requires `idx[65536] == count`, so a format-1
file may not carry any other index kind. A reader built from the shipped tag loads a format-1 file
with `WE_H_SCHEMA` set unchanged, because it ignores the bit and the tail.

**Format 2** is every other plane. There is no `sev[]` and no `end[]`; the end is the first field of
the per-range **record**, and the plane's attributes follow it. A format-1 reader refuses a format-2
file with `WE_ERR_FORMAT`, which is what an operator who points a legacy directive at `routing.bin`
should get.

## 2. The schema tail, 56 bytes at offset 136

Valid only when `WE_H_SCHEMA` is set. All fields that do not apply to a plane are zero.

| offset | size | field | domain |
|---|---|---|---|
| 136 | 1 | `plane_id` | 1 reputation, 2 tor, 3 rpki-unreachable, 4 routing, 5 anonymizer, 6 threat, 7 registry, 8 tenant. A file installed under a known plane name (`routing.bin`) must carry that plane's id or `WE_ERR_FORMAT`; a file under any other name (the published `snapshot.bin`, an interop fixture) is checked by the loader only for an id in this range. **A server module binding a plane is stricter**: whatever the file is called, a file bound to a plane must carry that plane's id, and a pre-schema format-1 file (this tail zero, so no id) is accepted for `reputation` only |
| 137 | 1 | `schema_id` | 0 = the format-1 layout (reputation only); 1 = the **routing record** (§3.1); 2 = the **membership record** (§3.2) |
| 138 | 1 | `v4_key_bits` | 32 |
| 139 | 1 | `v6_key_bits` | **64** (routing, registry: `start`/`end` are the top 64 bits of the address) or **128** (every single-address plane, and format 1) |
| 140 | 1 | `v4_index_kind` | 0 none, 1 **radix**, 2 **rank**; any other value `WE_ERR_FORMAT` and the plane is `refused` |
| 141 | 1 | `v4_index_param` | radix: k, in {12, 16, 18} (format 1: must be 16); rank: log2 of the stride, 6 for stride 64, 5 for stride 32 |
| 142 | 1 | `v6_index_kind` | as v4 |
| 143 | 1 | `v6_index_param` | as v4; rank stride is **64 for 32- and 64-bit keys and 32 for 128-bit keys** |
| 144 | 2 | `v4_record_stride` | bytes per record; 0 for schema 0; 16 for schema 1 and 2 |
| 146 | 2 | `v6_record_stride` | 0 for schema 0; 24 for schema 1 (64-bit keys); 32 for schema 2 (128-bit keys) |
| 148 | 4 | `v4_record_off` | the record column, **64-byte aligned**; 0 for schema 0 |
| 152 | 4 | `v6_record_off` | as v4 |
| 156 | 4 | `v4_sample_off` | rank only: the S-tree, **64-byte aligned**; 0 for radix |
| 160 | 4 | `v6_sample_off` | as v4 |
| 164 | 4 | `v4_sample_count` | rank only: m = ceil(n4 / stride), the number of windows |
| 168 | 4 | `v6_sample_count` | as v4 |
| 172 | 2 | `country_table_version` | the ISO 3166-1 numeric table the builder used, as `YYYYMM` modulo 65536 (202609 → 6001); a reader whose compiled table is older reads codes it does not know as `undetermined` and logs once |
| 174 | 1 | `v4_depth` | rank only: the S-tree depth the builder computed (§4.2), for the gate's record; 0 for radix |
| 175 | 1 | `v6_depth` | as v4 |
| 176 | 16 | reserved | must be zero, or `WE_ERR_FORMAT` |

## 3. Records (format 2)

A record is one per range, at `record_off + i * record_stride`, i in `[0, count)`. Its first field is
the range's inclusive end, in the key width. Every enumerated field has an **`undetermined`
sentinel**, and the loader's O(n) scan refuses any value outside the stated domain, naming the index
of the record. Reserved bytes and bits must be zero.

### 3.1 Schema 1, the routing record (planes `routing`, `registry`)

IPv4, 16 bytes:

| offset | size | field | domain |
|---|---|---|---|
| 0 | 4 | `end` | u32, inclusive, ≥ `start[i]`, < `start[i+1]` |
| 4 | 4 | `asn` | origin AS; `0xFFFFFFFF` = undetermined (RFC 7300 reserved); 0 is AS0 (RFC 7607) |
| 8 | 2 | `country` | ISO 3166-1 numeric 4..894 from the assigned table; 0 = undetermined; 900 EU, 901 AP, 902 ZZ, 903 XK; **> 999 refused**; an in-range code not in the reader's table reads as undetermined |
| 10 | 1 | `rov` | 0 undetermined, 1 valid, 2 invalid, 3 not-found; **4 (unrouted) never appears in a record** (records cover announced space) and is refused |
| 11 | 1 | `rir` | 0 undetermined, 1 AFRINIC, 2 APNIC, 3 ARIN, 4 LACNIC, 5 RIPE |
| 12 | 1 | `flags` | bit 0 anycast, bit 1 moas, bit 2 narrowed (IPv6 only); bits 3..7 must be zero |
| 13 | 1 | `asn_rep` | 0 undetermined, 1 reputable, 2 neutral, 3 suspicious, 4 highly_suspicious |
| 14 | 2 | reserved | zero |

IPv6, 24 bytes, 64-bit keys: `end` is u64 at offset 0 (the top 64 bits of the inclusive end), then the
same fields at offsets 8..21, then 6 reserved bytes (18..23 after the 4+2+1+1+1+1 attribute block,
which starts at 8: `asn` 8, `country` 12, `rov` 14, `rir` 15, `flags` 16, `asn_rep` 17, reserved 18..23).
A range narrower than a /64 is recorded at its /64 with `narrowed` set; the loader refuses starts that
are not strictly increasing after truncation.

For a MOAS range, `rov` is the RFC 6811 state of the route whose origin is in `asn`, and `moas` says
there were others.

### 3.2 Schema 2, the membership record (planes `tor`, `rpki-unreachable`, `anonymizer`, `threat`, `tenant`)

IPv4, 16 bytes:

| offset | size | field | domain |
|---|---|---|---|
| 0 | 4 | `end` | u32, inclusive |
| 4 | 4 | `flags` | the plane's attribute bits, below; undefined bits must be zero |
| 8 | 1 | `source` | index into the blob's feed-name table; 0 = none |
| 9 | 1 | `reason` | `rpki-unreachable` only: 0 undetermined, 1 asn, 2 length (Routinator's invalid-asn / invalid-length); other planes 0 |
| 10 | 6 | reserved | zero |

IPv6, 32 bytes, 128-bit keys: `end` is u128 at offset 0, then `flags` at 16, `source` at 20,
`reason` at 21, reserved 22..31.

Attribute bits by plane (one plane per file, so the sets do not overlap in practice; a reader maps
them by `plane_id`):

| plane | bit 0 | bit 1 | bit 2 | bit 3 | bit 4 | bit 5 |
|---|---|---|---|---|---|---|
| tor | `tor_exit` | | | | | |
| rpki-unreachable | `rpki_unreachable` | | | | | |
| anonymizer | `proxy` | `vpn` | | | | |
| threat | `c2` | `bruteforce` | `spam` | `phishing` | `scanner` | `state_actor` |
| tenant | `tenant_allow` | `tenant_deny` | | | | |

Absence from a fresh membership plane is a **definite negative** for every bit (POLICY.md §2).

### 3.3 The blob (format 2)

The blob begins with a **feed-name table**: `u16 count`, then `count` NUL-terminated UTF-8 names,
entry 0 reserved as the empty string meaning "none". The membership record's `source` byte indexes
it; `source >= count` is a record-domain `WE_ERR_FORMAT` naming the record, and a table that runs past
`blob_len` is `WE_ERR_OFFSETS`. An absent blob (`blob_len` 0) counts as a table of one entry, so every
`source` must then be 0. `meta[]` offsets are 0 or point into the blob past the table. Format 1 keeps
its existing blob layout unchanged.

**The tenant plane's table, a writer rule.** For `plane_id` 8 the builder writes `count` 3: entry 0
empty, entry 1 `tenant:` followed by exactly 16 lower-case hex digits (the tenant id, compared byte for
byte with the keyed manifest's `tenant`), entry 2 `rev:` followed by `[1-9][0-9]{0,18}` with a value at
most 2^63 - 1 (the content revision, `edge.at`, with no leading zero so no reader can take it for
octal), and `source` 1 on every record. The refresh checks the same rules before it installs the plane
and compares entries 1 and 2 with the manifest's `tenant` and `rev` strings byte for byte. The loader
keeps checking the table's **structure** only, for every plane (the count, entry 0 empty, every name
terminated inside the blob), and no module decision reads the table's content: a plane whose table
breaks this rule still loads, and it is the writer and the refresh that refuse it.

## 4. Index kinds

The lookup for a family is one force-inlined function with a two-armed `if` on the kind byte. Both
arms share the window search and the record read; only the step that picks the window differs. The
`else` arm (an unknown kind) is unreachable because the loader refuses it, and returns "no range" as
memory safety only.

### 4.1 Radix-k

A table of `2^k + 1` u32 entries at `index_off`: `idx[b]` is the index of the first range whose start
has top-k bits ≥ b, and `idx[2^k] == count`. For a key `a`, `b = a >> (bits - k)`, the window is
`[idx[b], idx[b+1])` plus the still-open entry at `idx[b] - 1`, searched by binary search. Format 1 is
radix-16 (65,537 entries) and nothing else. The worst-case probes are
`ceil(log2(k_max + 1))` where `k_max` is the largest window `idx[b+1] - idx[b]`; the release gate
refuses more than 12. The build **selects** k as the smallest of {12, 16, 18} whose worst case is 7
or fewer, records it in the plane profile, and thereafter uses the profile's value, reporting a
disagreement as a counter and a log line, never switching.

### 4.2 Rank-s (the static B-tree over samples)

Windows are the fixed stride `s` (64 for 32- and 64-bit keys, 32 for 128-bit keys): window j is
`start[j*s .. min((j+1)*s, n))`, and `m = ceil(n / s)` windows exist. The **separators** are
`start[j*s]` for j in `[1, m)`, m − 1 keys; window 0 is implied. They are laid out as a **complete (B+1)-ary
static search tree** of 64-byte nodes, B = 64 / key_bytes keys per node (16 for 32-bit, 8 for 64-bit,
4 for 128-bit), `((B+1)^d − 1) / B` nodes in level order, the m − 1 separators placed in **in-order**
position, and every slot past the last separator in in-order position filled with the maximum key
value. A descent reads exactly one node per level, d nodes; at each node the child index is the
branchless count of keys ≤ `a` (written as a halving search over the node's keys, never as B summed
compares, which auto-vectorize on aarch64 and load a mask constant from `.rodata`, a relocation the
hot-path gate refuses); the d child indices read as base-(B+1) digits, clamped to m − 1, are the window
index j. The depth is the smallest integer d with `(B+1)^d ≥ m`, computed in integers, never
with a floating-point `log`; the builder writes it into the tail and the loader recomputes and
refuses a mismatch. Then the window is binary-searched: `log2(s)` probes, 6 at stride 64 and 5 at
stride 32, over `[j·s + 1, min((j+1)·s, n))` for every window, because the separator `start[j·s]`
is already proven by the descent (window 0's first entry is proven by the arm-time copy). The lookup never reads `start[0]` from the mapping: the armed descriptor keeps an arm-time copy
of it (the publication rule, POLICY.md §2.4), so for `a < start[0]` the lookup costs 0 probes and 0 loads, and for
`a ≥ start[0]` in window 0 the search runs over `[1, min(s, n))`; the cost model and the C trace
count it the same way. A window
of 4-byte keys is 4 lines of which a search touches at most 3; of 8-byte keys 8 lines, 4 touched; of
16-byte keys at stride 32, 8 lines, 4 touched. The release gate refuses a depth above the formula, or `maxColdLines` above 6, where the
cold lines are the window's lines plus the record's (one window touches at most 4 lines at 64-bit
keys and 5 at 128-bit; a 24-byte record straddles a line for 2 of every 8 records).

The loader refuses a sample that does not equal `start[j*s]`, and a sample or record array whose
offset is not a multiple of 64.

## 5. Layout order and alignment (format 2)

```
header (192) | pad to 64
v4: index (radix) | start[] (64-aligned) | record column (64-aligned) | S-tree (64-aligned, rank) | meta[]
v6: index (radix) | start[] (64-aligned) | record column (64-aligned) | S-tree (64-aligned, rank) | meta[]
blob
```

`start[]`, the record column, the S-tree **and the radix table** are 64-byte aligned because the
published line counts depend on it: a record column 16 bytes off alignment raises the measured IPv6
cold-line bound from 5 to 6. A rank family with a single window (m = 1) has no separators and writes
`sample_off = 0`, `sample_count = 1`, depth 0. The digest covers everything; the padding bytes are zero.
A writer emits country codes only from {0, 4..894, 900..903}; a reader accepts anything up to 999 and
reads an unknown in-range code as `undetermined`, which is the asymmetry the compatibility rule wants.

## 6. What the loader refuses, in order

`WE_ERR_TOO_SMALL` (under 192 bytes), `WE_ERR_MAGIC`, `WE_ERR_FORMAT` (format not 1 or 2; a
format-2 header with `generation` 0, which is reserved for the in-memory revoked tenant map and means
"nothing armed"; an unknown index kind; a schema tail field outside its domain; a non-zero reserved byte; a `plane_id`
that does not match the file name), `WE_ERR_TRUNCATED` (`file_len` ≠ size), `WE_ERR_OFFSETS` (any
region outside the file or overlapping another; an alignment violation; a format-1 index that is not
65,537 entries), `WE_ERR_UNSORTED` (starts not strictly increasing, after /64 truncation for 64-bit
keys), `WE_ERR_OVERLAP` (an end at or past the next start), `WE_ERR_DIGEST`, and the record-domain
refusals of §3 (`WE_ERR_FORMAT`, naming the record index). A refused file never arms; the previously
armed plane keeps serving until its own `valid_until_ms`.

## 7. Counting what a lookup costs

The hook `WE_TRACE_READ(p)` is an expression, `((void)0)` in production, placed inside the existing
ternaries at every load from the mapping (index entry, S-tree node, `start[mid]`, the record or `end`,
`sev`). The production object code is byte-identical with and without it (checked by the gate with
`objdump -d -r` on three toolchains at four levels). Under `-DWE_TRACE` the test build records every
address and derives, per lookup: probes, S-tree depth, distinct 64- and 128-byte lines, distinct 4 KiB
pages, and cold lines (lines outside the index and S-tree regions). **What a lookup reads of a record
is defined**: on a miss (the address is above the window's last end, or below the found start's end
check fails) it reads the record's `end` field only, so the lines are those the end field occupies;
on a hit it reads the whole record; in format 1 a hit also reads the `sev` byte. Lines and pages are
counted from **file offsets**, not from the buffer's address, because `mmap` places file offset 0 on a
page boundary and the manifest's figures are computed that way. The writer's cost model follows the same three rules, and the interop gate compares the manifest's maxima
with the traced maxima of the same file. The deterministic test enumerates
every outcome class (§7's cost model) and asserts **equality per lookup** against a data-free
model, and equality of the maximum with the manifest.
