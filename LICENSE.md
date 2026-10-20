# Licence

Everything in this directory is **MIT**. See [LICENSE](LICENSE).

## Why this licence, and why it is separate

This code is developed in the private `whisper-ns` repository; the rest of that repository is
proprietary, and that is deliberate: the builder, the graph queries, the tier arithmetic and the
tier guards' thresholds are not published.

This directory is the opposite, and it has to be. You are being asked to compile it into your own
nginx and run it in front of your own traffic. A licence that says "you may not copy, modify or
distribute" would make that unlawful, which would make the whole thing pointless. MIT is the licence
all of Whisper's own open code carries, and it is as permissive as nginx's own licence, so a module
compiled into nginx carries no new obligation and no new question for anyone's legal review.

So: take it, read it, change it, ship it in your own product if you want to. The only thing we ask is
the attribution the licence already asks for.

## What this covers

Everything in this directory and below it, including but not limited to:

- `core/` - the lookup, the snapshot format, the integrity check, the test suite, the gates, the
  operator diagnostic, and the checked-in fixtures in `core/testdata/`
- `nginx/` - the nginx module, its worked configuration and its verification harness
- `rpz/` - the Response Policy Zones: their verification harness, fixtures and format
- `hold-harmless.txt` - the set of infrastructure this feed will never block

"Including but not limited to", deliberately: an enumerated list in a licence goes stale the moment a
file is added or moved, and a licence that names a file which is not there is worse than one that
names the directory. The grant is the directory.

The hold-harmless set is published on purpose. It is a promise, and a promise you cannot read is not
worth much.

## What it does not cover

The snapshots and zones served from `whisper.online` are data, not software, and this licence says
nothing about them. They are free to use, with no account and no key. If you redistribute them,
please say where they came from and when you fetched them, because a stale blocklist presented as a
current one is the one way this data can do harm.
