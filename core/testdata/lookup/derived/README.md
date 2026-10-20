# testdata/lookup/derived

The manifests the lookup gate binds planes against. Every one is the feed writer's own output from
`../writer/`, either verbatim or with one edit, because the writer cannot produce most of the shapes a
reader must handle (a disagreement, a duplicate entry, a future build time, a fresh plane the feed now
withholds). `lookup-check.py derive <writer-dir> <tor-plane> <out-dir>` writes them into the gate's work
directory on every run; the gate checks that the set it writes is exactly the list below.

`../writer/` is committed and is written by the real writer, through the builder's own fixture test in the
builder's test suite, which also holds the committed bytes to what the writer produces now:

- `keyless/`: what the publisher commits for one slot in which a reputation build, the tor job and the ROV
  job each staged a plane. Reputation is published, in `planes[]` and as `snapshot.bin` in `legacy[]`;
  tor (`LOW_RECALL`, `IPV6_NOT_STATED`), routing and rpki-unreachable (`BGP_CLOCK_UNKNOWN`, `UNPINNED`,
  `VRP_CAP_UNSET`) are withheld on the jobs' own reasons. Beside it, the published `reputation.bin`.
- `disarm/`: the same publisher's disarm manifest, committed after it.
- `jobs/`: a manifest composed from the ROV and tor jobs' own stages, both planes published, so their
  entries carry the jobs' facts (routing's two sources and its six-counter coverage object, tor's one source
  and null coverage). Beside it, `routing.bin` and `tor.bin`.

In the table, "the reputation entry" means the base's `planes[]` entry for reputation, and "the snapshot
entry" its `legacy[]` entry named `snapshot.bin`; both name the bytes of `../writer/keyless/reputation.bin`.

| file | what it is |
|---|---|
| `base.json` | `../writer/keyless/manifest.json`, verbatim |
| `disarm.json` | `../writer/disarm/manifest.json`, verbatim |
| `jobs.json` | `../writer/jobs/manifest.json`, verbatim |
| `not-named.json` | the base without the reputation entry and the snapshot entry: the plane is named nowhere |
| `other-bytes.json` | the reputation entry names another sha256 and a header generation one higher; no snapshot entry |
| `duplicate-entry.json` | a second reputation entry, naming other bytes, ahead of the real one; no snapshot entry |
| `planes-and-withheld.json` | reputation also listed in `withheld[]` (`SOURCE_STALE`) |
| `legacy-only.json` | the base without the reputation entry: the plane binds only through the snapshot entry |
| `valid-until-differs.json` | the reputation entry's `validUntil` a day later than the plane's header |
| `withheld-one-reason.json` | tor withheld for `LOW_RECALL` alone |
| `withheld-reasons-invalid.json` | tor's `reason` and its one `reasons[]` element a 10,240-byte lower-case token, which no reader accepts |
| `withheld-reasons-empty.json` | tor's `reason` null and its `reasons[]` empty |
| `withheld-reasons-null.json` | tor's `reason` and `reasons[]` both null |
| `withheld-reputation.json` | reputation named nowhere but in `withheld[]` (`SOURCE_STALE`, with a last published validity) |
| `withheld-reputation-two.json` | the same with two reasons, `LOW_RECALL` and `SOURCE_STALE` |
| `tor-as-routing.json` | a routing entry naming the bytes of the gate's tor plane |
| `numeric-times.json` | the jobs manifest with routing's second source's `observedAt` as integer milliseconds |
| `observed-at-zero.json` | the jobs manifest with tor's source's `observedAt` the integer 0 |
| `future.json` | the base built a year (365 days) later |
| `keyed.json` | the base with `tier` keyed, no snapshot entry, and only routing withheld |
| `tor-withheld-only.json` | the base with `withheld[]` holding tor alone, so rpki-unreachable is named nowhere |
| `built-at-floored.json` | the reputation entry's `builtAt` written with a `.0009` fraction, which floors to the header's millisecond |
| `coverage-large.json` | the reputation entry's `coverage.v6Addresses` written `4722366482869645213696`, above 2^53 |
