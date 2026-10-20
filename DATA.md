# The edge data planes

This file describes every data plane the edge feed can carry: where its data comes from, how often it
is rebuilt and on which clock, whether it needs a key, what it covers, and what keeps it withheld when
it is. The language that reads the planes is in [POLICY.md](POLICY.md); how they are built, signed and
served is in [ARCHITECTURE.md](ARCHITECTURE.md).

The counts here are the feed build at generation 1791990002, built at 2026-10-14T15:00:00Z. The
served `/edge/manifest.json` is rebuilt every hour and carries the current counts; it is the figure to
trust over anything written in this file.

## The planes

| plane | key | rebuilt | at this build | withheld because |
|---|---|---|---|---|
| `reputation` | none | hourly | live: 1,027 IPv4 ranges and 36 IPv6 ranges, covering 1,149,952 IPv4 addresses | |
| `tor` | none | hourly | withheld | `LOW_RECALL`, `IPV6_NOT_STATED` |
| `rpki-unreachable` | none | daily | not shipped at this build | |
| `routing` | required | daily | not shipped at this build | |
| `anonymizer` | required | | not shipped at this build | |
| `threat` | required | | not shipped at this build | |
| `registry` | required | | not shipped at this build | |
| `tenant` | required | | not shipped at this build | |

A plane that is "not shipped at this build" is absent from the manifest altogether, neither live nor
withheld, and a policy rule that reads it is inert: it does not fire, and the policy compiler reports
it as inert when the configuration is tested ([POLICY.md](POLICY.md), section 1.5). A row with an empty "rebuilt" cell has no builder in this release; the row is here
so the list of planes the language can name is complete, and it states nothing about data that does
not exist yet.

## reputation

**Source.** Listings with a citable source behind them, joined against the routing table in the graph.
Nothing enters the plane without a listing a reader can look up.

**Rebuilt** hourly, on the build's own slot clock.

**Covers** the prefixes with such a listing, and nothing else: at this build 1,027 IPv4 ranges covering
1,149,952 IPv4 addresses, and 36 IPv6 ranges. An address the plane does not list is "not listed", which
is not the same as "known good".

**Recall** is not measured. No independent list of every address that deserves a block exists to
measure it against.

**Format 1**, the layout every deployed module already reads. Its header keeps the original generation
unit, a slot index: at this build the plane's header says 497775 while the manifest's generation, in
epoch seconds, is 1791990002. The manifest carries both, the second as the plane entry's
`headerGeneration`, and nothing ever compares one unit against the other.

## tor

**Source.** The Tor relay data in the graph, the exit relays and their addresses, as one ingestion
batch. The plane is rebuilt hourly on the batch's own clock (its `ingestedAt`), so two planes built in
the same second can carry data from different hours, and the manifest says which.

**Withheld**, for both of the reasons the manifest carries:

- `LOW_RECALL`: the plane publishes only when its recall, measured against the Tor Project's own exit
  list for the same batch, clears the configured floor on two consecutive recordings taken from two
  separate fetches of that list. A recording is honoured for 48 hours. The floor cannot be set below
  0.90, and the floor proposed for the plane is 0.95. At a lower floor a plane named "Tor exits"
  would miss one exit in ten.
- `IPV6_NOT_STATED`: the source carries no IPv6 exit addresses, and the Tor Project's bulk list is
  IPv4 only, so the plane cannot say what it covers in IPv6. Absence from a published membership plane
  reads as a definite "not a member", so a plane silent on a family it never measured would answer
  wrongly for every address in it. The reason lifts only when the plane states its IPv6 coverage.

**Format 2**: its generation is in epoch seconds, the slot start plus the offset of the kind of commit
that published it.

## rpki-unreachable and routing

One walk of the routing table builds both. `routing` carries each announced prefix's route origin
validation state, its picked origin AS and that AS's reputation category, its country, its registry,
and whether it is anycast or announced from more than one origin. `rpki-unreachable` is the subset no
valid route reaches: every route on the prefix's covering chain is invalid, none is anycast, and the
prefix is no broader than the guard allows.

Neither plane is in the manifest yet. Each stays withheld while the graph does not state where its
routing view comes from and when it was taken: without that, a validation state cannot name the
collectors that saw the route, and a plane that cannot say what it measured does not publish.
The walk is daily.

`rpki-unreachable` needs no key, like `reputation` and `tor`; `routing` needs one.

## anonymizer, threat and registry

Keyed planes with no builder in this release. They are listed so that a policy which names them reads
as inert rather than failing to load, and so this file does not have to change shape when they ship.
`registry` will carry a dataset clock only once the graph states one; until then the manifest carries a
null there, and this file will say so beside the count.

## tenant

Your own allow and deny lists, published as a plane only for your key. It needs a key, it is rebuilt
when you change it, and it is valid for a fixed number of days from the day it was built, so a node
that stops hearing from you stops honouring an old list rather than enforcing it forever. An enrolled
box polls for it on the keyed timer, `whisper-edge-refresh-keyed.timer`.

**What the lists may hold**, checked when you write them and again when the plane is built:

- at most 1,024 entries across the allow and deny lists after they are canonicalised, and at most
  4,096 as written, before any is parsed;
- an allow no broader than a /16 for IPv4 or a /32 for IPv6, and allows covering at most 2^20
  addresses in all (counted in IPv4 addresses, and in IPv6 /64s);
- a deny broader than a /8 for IPv4 or a /16 for IPv6 is accepted, with a warning;
- a plane is valid for 8 days past the day it was built.

The plane is in one of four states on a box, and a rule reads them differently
([POLICY.md](POLICY.md), section 4.2):

- **fresh**: inside its validity; every rule reads it.
- **stale**: past its validity. Within a grace of 48 hours an allow that names `tenant_allow` still
  reads it, so a box that loses the feed does not suddenly start refusing your partners; every other
  reading is unknown. Past the grace it has lapsed, and nothing reads it.
- **revoked**: the key was revoked, or the plane is no newer than the last one this box saw revoked.
  The refresh leaves a root-owned `.tenant-tombstone` beside the planes, and the lists stop applying
  even if an old `tenant.bin` is put back.
- **null**: no plane at all, as on a box that never enrolled.

## Generations, and why there are two units

A plane's generation is in its own unit. Format 2 planes count in epoch seconds: the start of the build
slot plus the offset of the kind of commit (see [ARCHITECTURE.md](ARCHITECTURE.md), the serial space). The
format 1 `reputation` plane keeps the slot index its header has always carried, and the manifest names
that one `headerGeneration`. Compare generations only within one plane and one unit.
