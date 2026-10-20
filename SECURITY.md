# Security and false positives

Two different problems, two different addresses, and the second one is the one most people need.

## "You blocked my network"

**abuse@whisper.security**

Include the prefix. You will get a reply from a person.

We would rather hear from you than be right, and the design assumes we will sometimes be wrong:

- Every entry has a citable listing behind it. Build the reader with `make -C core tools` and run
  `whisper-edge-lookup snapshot.bin {your-address}`
  and it will print the verdict and the evidence, for IPv4 and IPv6 alike - usually a Spamhaus SBL id
  you can look up yourself. If the listing is Spamhaus's, their removal process is the faster route
  and we follow it.
- `/edge/snapshot.json` publishes what each build contained and how many prefixes every safety guard
  refused, so you can see the shape of what we are doing without asking us.
- If your prefix is in the snapshot and you believe the listing is wrong or withdrawn, say so and we
  will carry the correction in the next build rather than waiting for the upstream source.

Infrastructure that we will never block, whatever our data says, is listed in
[`hold-harmless.txt`](hold-harmless.txt) with the date and method each entry was measured. If you
operate something that belongs there and is missing, that is a bug in that file and we want the report.
The standing rule is that an exemption has to be unoccupiable - if an attacker could rent space inside
it, it is not a safe exemption and we will say so rather than quietly add it.

## A vulnerability in this code

**security@whisper.security**

PGP, if you want it: our release key is on the keyservers and its fingerprint is printed on every
signed artifact we publish. We will not send you a fingerprint by mail - a fingerprint delivered over
the channel you are trying to authenticate authenticates nothing.

Please do not open a public issue first. We will acknowledge within two working days and tell you what
we think the impact is; if we disagree with your assessment we will say why rather than go quiet.

What we consider most serious here, in order, because it is worth being explicit about where this code
can hurt someone:

1. **Memory safety in `core/`.** This runs inside other people's web servers, parsing a file fetched
   over a network. A crash or worse is the highest-severity class and we treat it that way.
2. **Anything that makes the module deny when it should allow.** Fail-open is the design's central
   invariant - an absent, corrupt, stale or unreadable snapshot must allow everything - and a path
   that denies on bad data is a defect even if it never crashes.
3. **Anything that lets a third party choose whom we block.** The snapshot is integrity-checked but
   the digest is *unkeyed*, so whoever can write the file controls the policy. The loader refuses a
   group- or world-writable snapshot for that reason. If you find another way in, that is the finding
   we most want.
4. **Anything that makes us a tool against the operator**, such as turning our own logging into a
   disk-fill. The log lines are rate-limited for exactly this reason.
5. **Anything that lets a feed key do more than read its own lists.** A box enrolled with
   `whisper-edge-refresh --enroll` holds a feed key in `/etc/whisper-edge/key`, root-only. It reads the
   feed and your tenant plane and nothing else, so a web server that leaks it leaks your allow and deny
   lists, not your account. If you think one leaked, run `whisper-edge-refresh --unenroll` on the box
   and enrol again; the revoked key stops working and the box drops the lists it was given. A way to
   use a feed key for anything else, or to read another tenant's lists with it, is the finding we want.

The policy zones are signed files, and the refresh checks the signature before it installs one. A
resolver that fetches a zone by URL for itself, as Unbound does, does not check that signature, so for
it the only protection is TLS with a CA bundle that verifies the name; the README's resolver notes give
the line that turns that on.

## What we will not do

We will not ask you to sign anything before we will read your report, and we will not treat a report
as a disclosure of confidential information. If you want credit you will get it; if you want anonymity
you will get that instead.
