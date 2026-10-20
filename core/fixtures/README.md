# Live-shaped fixtures

The deterministic bound test (`make check-live`) runs the shipped lookup over every outcome class of
the real routing table, so the maxima it prints are the ones a production plane of that shape costs:
IPv4 radix-18 and IPv6 rank-64 on the flattened RouteViews tables of 2026-10-09 12:00 UTC.

| file | what it is |
|---|---|
| `flatten-routeviews.py` | the flattening, deterministic; only origin ASN and MOAS come from the data, the other attributes are synthetic per ASN |
| `make-fixtures.sh` | fetches the two CAIDA inputs if they are not cached, checks both digests sets, runs the flattening |
| `SHA256SUMS` | the two inputs and the four outputs |

Nothing generated is committed. The inputs are CAIDA's RouteViews prefix-to-AS files, whose terms
cover use and not redistribution, and the outputs are 2.4 to 18.7 MB each. `make fixtures` builds
them, fetching about 4.8 MB on the first run; `make fixtures RIB_DIR=/path` uses a cached copy of the
inputs instead. A digest that does not match is a failure, never a skip.

Counts, for the record: 1,169,047 IPv4 ranges (32-bit keys) and 298,246 IPv6 ranges (64-bit keys,
with 16 narrowed /64s).
