# How the edge feed is built and served

This file is the system around the data, as a reader of the feed can see and check it: how the planes
are laid out on disk, what a published commit looks like, what break-glass does, and how the feed is
served. The planes themselves are in [DATA.md](DATA.md) and the policy language is in
[POLICY.md](POLICY.md). Where this file and the code disagree, the code is right and this file has a
bug.

## The shape

Three layers, each usable without the next:

- **Typed data planes on disk.** Each plane is one file of sorted address ranges with a small record per
  range, laid out so a lookup is a handful of cache-line reads into a memory-mapped file.
- **A policy language over them**, compiled once, when the server reads its configuration, into a
  small verified program. On nginx and Apache a policy error is a configuration error: the
  configuration test refuses it with the rule, the line, the column and a fix. OpenLiteSpeed has no
  configuration test, so a context whose lines are refused runs the empty program and the error log
  says so.
- **The decision**, per request, inside the web server, against the planes the module has bound and
  the compiled program.

The builder that writes the planes, the manifest that names them and the signature over the manifest
live on the feed's side. A server that uses the planes never talks to anything at request time: it
reads files it has already verified.

## The planes on disk

[`core/FORMAT.md`](core/FORMAT.md) is the byte-exact contract between the builder and every reader, and
it is normative: this section summarises it and never overrides it.

- Every plane file starts with the same 192-byte header, little-endian, carrying the format, the
  plane's generation, when it was built, when it stops being valid, the range counts per family, and a
  digest over the header and the body. A reader that finds any rule violated refuses the whole file; it
  never reads around a defect.
- The `reputation` plane is format 1, the layout the first modules shipped with, so every deployed
  module keeps loading it. Every other plane is format 2, which an old module refuses cleanly rather
  than misreading.
- A file is stale once its validity has passed. A stale plane reads as `unknown`, a state of the plane
  and never a verdict about an address; what a rule does with `unknown` is the language's rule, in
  [POLICY.md](POLICY.md). The tenant plane is the one exception, read for a grace after it goes stale,
  as [DATA.md](DATA.md) describes.

## What a commit looks like from outside

The feed is published as commits, and everything below is visible in what the feed serves; how the
builder is run is not part of the published contract.

- **One node builds; every node serves the same signed bytes.** The other node copies the builder's
  set (the manifest, its signature and every file the manifest names, each checked against the
  manifest's digest) and builds only when the builder has stopped, so `/edge/manifest.json`, its
  signature and every file it names are identical whichever node answers, the legacy `snapshot.bin`
  and its signature included. The exception is a window, not a difference in kind: after a build and
  before the copy lands, or across a hand-over, one node can serve the previous generation, which is
  why a reader fetches a file and its signature on one connection (README.md).
- **A file's name is its content.** Every plane file is named by the SHA-256 of its bytes, under
  `planes/`, and never changes once published. The manifest names the set, so a reader that fetches the
  manifest and then the files it names always gets one consistent build, never a mixture of two.
- **The manifest says who built it and whether building is alive.** Its `builder` field names the kind
  of commit, and `lastBuildGeneration` advances only when a build completes, so a manifest whose
  `lastBuildGeneration` stops moving is a feed whose data has stopped moving, even while it keeps
  being served.

### The serial space

Every commit's generation is in epoch seconds: the start of its hourly slot plus an offset that says
what kind of commit it is, so the generation alone tells a reader what happened in that slot.

| commit | `builder` | offset |
|---|---|---|
| a content build | `primary` | +2 |
| a content build from the standby builder | `secondary` | +3 |
| a disarm | `disarm` | +4 |
| a commit that only lifts a withheld plane | | +5 |
| the re-arm after a disarm | | +6 |

A generation never goes backwards: every commit is strictly above the one before it.

## Break-glass

A disarm is a commit like any other, and it always wins: no content build can land over it, it is
never refused for a bad clock, and it is never dated in the future. While a feed is disarmed its
manifest says so (`builder` is `disarm`), the text index prints a DISARMED line, and the legacy
snapshot blocks nothing. The re-arm is the next content commit, at offset +6 in its slot.

## The module

One core in C (`core/`) holds the planes, the compiler and the decision; each server has a shim of its
own (`nginx/`, `apache/`, `litespeed/`) that reads the directives, hooks the request and renders the
values. The shims share one header, `core/we_module.h`, at ABI version 5: a module built against
another version refuses to bind before it writes anything.

- **At configuration time** the module compiles every context's policy lines and the floor, and
  counts the rule slots the whole configuration needs; above 65,536 slots the configuration is
  refused. It binds the planes the data directory or the per-plane lines name. A format 2 plane is
  mapped from its file; the legacy `snapshot.bin` is read into a private copy and never mapped.
- **In the background** each server process runs one thread of the module's own, which re-reads the
  bound planes on the refresh interval, checks each one fully, and swaps it in; a request never
  waits for it, and a plane that fails its checks leaves the last good one in place.
- **Per request** the decision reads the planes and the program it already holds. Looking up a
  verdict makes no system call, takes no lock and allocates nothing; the README's "Proven, not
  described" section shows the gates that count it.
- **The client address** the floor judges is the TCP peer, or, when that peer is a trusted proxy, an
  entry of the forwarding header found by walking it from the right: at most 16 entries and 1,024
  bytes examined, and `whisper_edge_trusted_hops` names one entry from 1 to 16. The context's rules
  judge the address the server itself reports.
- **What it exposes**: 25 attribute values and the decision's own values per request, under each
  server's names ([POLICY.md](POLICY.md), section 3.9), and per-worker counter and status files that
  `whisper-edge-summary` reads.

## The transport

The feed is static files under `https://whisper.online/edge/`, served by every node behind one name.

- **Content-addressed files** (each plane file, named by its SHA-256 under `planes/`, and its
  signature) never change, so they are served with `Cache-Control: public, max-age=31536000, immutable`,
  with a gzip copy negotiated by `Accept-Encoding` and `Vary: Accept-Encoding` set.
- **The manifest** is served with `Cache-Control: no-cache` and a strong ETag over its bytes, so a
  conditional fetch costs a `304 Not Modified`.
- **The zones**, one per verdict plane the manifest lists, are served by name at
  `/edge/rpz/<origin>.zone`, and the reputation zone also at `/edge/rpz.zone`. A name answers with
  `Cache-Control: no-cache` and a strong ETag over the zone's SHA-256. Each zone file and its detached
  signature are also content-addressed under `zones/` and served immutable like the planes;
  [rpz/README.md](rpz/README.md) has the signed bytes and the two `openssl` lines that check them.
- **The keyed tier**, `/edge/k/`, serves a keyed manifest, `tenant.bin` and a signature for each, and
  only to a request carrying a feed key in a header; a key in a URL is refused. Every keyed answer is
  `private, no-cache` and varies on the credential headers.
- **The index**, `/edge/`, is plain text rendered from the live files, and never names a path that would
  not answer.
- **Limits.** Each source address gets a bucket of fetches that refills over the hour, and the responder
  serves a bounded number of requests at once. The page, its Markdown twin, the documents and the text
  index have a bucket and a cap of their own, so reading about the feed can never starve an installed
  edge's polls. Past any limit the answer is `503 Service Unavailable` with `Retry-After`, never a queue.
- **A node's own name** serves that node's manifest and its signature, a few kilobytes, and nothing
  else, so you can check a node directly without fetching the feed from it.
