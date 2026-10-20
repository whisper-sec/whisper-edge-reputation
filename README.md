# Whisper edge reputation

Block the networks that reputable third parties have listed, with the listing shown. Every entry has a
citable listing behind it, such as a Spamhaus SBL id or a DROP entry you can look up yourself. It is
free, keyless and needs no account. It runs as a module in nginx, Apache httpd and OpenLiteSpeed, and
as a Response Policy Zone for BIND and Unbound.

## Quick start

The installer configures modules that are already built, so build the one for your server first
([details](REFERENCE.md#building-the-modules)):

```
git clone https://github.com/whisper-sec/whisper-edge-reputation
cd whisper-edge-reputation
./nginx/build.sh && sudo ./nginx/build.sh --install    # or apache/build.sh, litespeed/build.sh
sudo ./install/install.sh
```

What the installer does:

- finds the servers on the host, the module each one has and the user each one runs as;
- fetches the signing key, refuses it unless its hash is the one pinned in the script, and verifies
  every plane the default policy reads before installing it, with a refresh timer for each;
- writes the default policy into each server's own configuration;
- runs that server's own configuration test, and reloads only when the test passes. If your
  configuration already fails its test, nothing is written;
- reads the module's own status after the reload and says whether the policy is running;
- ends with an `undo` block: one line per server to paste, which takes it all back.

`sudo ./install/install.sh --help` lists every option. The full walk-through, with a real run, is in
[REFERENCE.md](REFERENCE.md#start-here-one-command).

### Without the installer

The module on its own blocks nothing until you tell it to. Its default mode is `log`, which writes what
it would have done and lets the request through. For nginx:

```
load_module modules/ngx_http_whisper_edge_module.so;              # main level

http {
    whisper_edge_snapshot /var/lib/whisper-edge/snapshot.bin;
    whisper_edge_mode log;                                        # deny, once you have read the log
}
```

`whisper-edge-refresh` fetches and verifies `snapshot.bin`; run it from a timer to keep the file
fresh ([how](REFERENCE.md#getting-the-snapshot-and-keeping-it-fresh)). Worked configurations are in
[`nginx/example.conf`](nginx/example.conf), [`apache/example.conf`](apache/example.conf) and
[`litespeed/example.conf`](litespeed/example.conf).

## How it works

```
https://whisper.online/edge/      a signed manifest and one file per data plane
        |
        |  whisper-edge-refresh, on a timer: fetch, verify the signature, rename into place
        v
/var/lib/whisper-edge/*.bin
        |
        |  the module's own thread re-reads each plane, checks it in full, swaps it in
        v
each request: look up the client address, run the policy, then allow, log or deny
```

- The policy is compiled once, when the server reads its configuration. On nginx and Apache a bad
  policy is a configuration error, reported with the rule, the line, the column and a fix.
- At request time the server talks to nothing. It reads files it has already verified, and the lookup
  makes no system call, takes no lock and allocates nothing.
- It fails open. A missing plane allows everything, a corrupt one is refused and the last good one
  keeps serving, and one past its own validity window stops enforcing.

The planes are described in [DATA.md](DATA.md), the policy language in [POLICY.md](POLICY.md), and the
feed itself in [ARCHITECTURE.md](ARCHITECTURE.md).

## What it blocks, and what it never blocks

| | what happens |
|---|---|
| a cited listing: Spamhaus DROP, or another listing at high or above | denied by the default policy on nginx and Apache |
| a Tor exit | logged, let through |
| an address no valid route covers | logged, let through |
| a verdict inferred from graph structure, with no citable listing | ignored unless you opt in |
| OpenLiteSpeed, any of the above | logged until you run the `--arm-deny` line the report prints |

On nginx and Apache the installer's policy answers 403 to a source on a cited listing, and to nothing else.

Some things are never blocked, whatever our data says, because blocking them breaks far more than one
site:

- the DNS root servers, and the TLD and registry nameservers;
- the major public resolvers, and NTP;
- CA, ACME, OCSP and CRL endpoints, and RPKI repositories;
- RIR and IANA service infrastructure;
- reserved, documentation and special-purpose space.

The full list is [`hold-harmless.txt`](hold-harmless.txt), each entry with the date and the method it
was measured by. The reasoning is in [REFERENCE.md](REFERENCE.md#what-it-will-never-block), and the
known limits are in [Honest limits](REFERENCE.md#honest-limits).

## Per server

**nginx.** nginx has no stable module ABI, so `nginx/build.sh` builds against the same source version
and the same configure flags as your running binary, and reads both off it. Control is per `location`,
and the verdict is `$whisper_edge_verdict` for your access log.
[Build](REFERENCE.md#nginx).

**Apache httpd.** `apache/build.sh` uses `apxs`, which already knows your build's paths and flags.
Control is per `<Location>` or `<Directory>`. If `mod_cache` is loaded, set `CacheQuickHandler off`, or a
cached page can reach a listed client before any check runs; the configuration test warns about it.
[Build](REFERENCE.md#apache-httpd).

**OpenLiteSpeed and LiteSpeed.** A real LSIAPI module, not an Apache module. Control is per virtual
host. There is no configuration test, so the installer starts it in `log` and you arm `deny` yourself.
[Build](REFERENCE.md#openlitespeed--litespeed).

All three take the same directives ([table](REFERENCE.md#the-directives-for-reference)) and share one
core in C. A side-by-side of what each server gives you is in
[REFERENCE.md](REFERENCE.md#the-three-servers-and-exactly-what-each-one-gives-you).

## For a resolver

The same policy ships as a Response Policy Zone, which protects every device behind the resolver.
`rpz.whisper.online` is the reputation zone; `rpz-rpki-unreachable.whisper.online` covers answers no
valid route covers and loads log-only. The installer fetches each zone, verifies its signature, checks
it with `named-checkzone`, installs it under named's own directory and keeps it current with a timer.
It writes nothing in named's configuration: it prints the block for you to add. Unbound fetches the
zone itself.

Two things to know first: a zone blocks a whole name, not one address, and BIND does not rewrite
answers for clients that ask for DNSSEC unless you set `break-dnssec`. The zone files and the paste are
in [`rpz/README.md`](rpz/README.md); BIND, Unbound and the other resolvers are in
[REFERENCE.md](REFERENCE.md#for-a-resolver-as-a-response-policy-zone).

On a serverless runtime that cannot load a module, use [`whisper-edge`](https://github.com/whisper-sec/whisper-edge)
(`npm i whisper-edge`) in your handler instead.

## FAQ

**Does it phone home?** No. At request time the module reads local files and talks to nothing. The only
network traffic is the refresh downloading the published files from `whisper.online/edge/`, which
sends no key unless you enrol one, and `whisper-edge-summary` counts your blocks on the host with nothing leaving it.
[Architecture](ARCHITECTURE.md#the-shape).

**What happens if the feed is down?** It fails open. The planes already on disk keep serving until
their own validity window ends, then the module stops enforcing and allows everything. No code path
denies a request on missing or bad data. [Details](REFERENCE.md#it-fails-open-always).

**I am behind a proxy or a CDN.** If your server already trusts a proxy on the same box (nginx
`realip`, Apache `mod_remoteip`), your policy judges the client it names. To have the floor, the rules every context runs first, judge
that client too, name the proxy with `whisper_edge_trusted_proxy` and `whisper_edge_trusted_header`.
Behind a caching proxy or a CDN, the module judges only the requests that reach it.
[Details](REFERENCE.md#behind-a-proxy-on-the-same-box).

**What does it cost per request?** A verdict is a lookup in a memory-mapped file: no system call, no
lock, no allocation, checked by disassembling the compiled lookup rather than asserted. The worst case
for any address is published with every build in `/edge/snapshot.json`.
[Details](REFERENCE.md#start-here-one-command).

**How do I undo it?** Paste the lines from the `undo` block the installer printed: one per server, and
one for the shared parts. Each server is left serving its previous configuration.
[Details](REFERENCE.md#start-here-one-command).

**Can I see why an address was blocked?** Yes. Every deny and every would-deny writes a line to your
error log with the rule and the listing behind it, such as the Spamhaus SBL id. Or ask the reader
directly: `whisper-edge-lookup /var/lib/whisper-edge/snapshot.bin {your-address}`. If we got
your network wrong, write to `abuse@whisper.security`. [SECURITY.md](SECURITY.md).

**What is the licence?** The code is MIT ([LICENSE](LICENSE), and why: [LICENSE.md](LICENSE.md)). The
data is free to use with no account and no key; if you redistribute it, say where and when you
fetched it.

**What does a key add?** Your own allow and deny lists, delivered to every edge you run as a tenant
plane, and a faster poll. The module is the same binary with or without a key. If the Whisper CLI is
logged in on the machine, the installer enrols it by itself.
[Details](REFERENCE.md#with-a-key-your-own-tenant-plane).

## Documentation

- [REFERENCE.md](REFERENCE.md): the full manual. Installing, every server, the resolver, the
  directives and tools, and how we check our work.
- [POLICY.md](POLICY.md): the policy language, every refusal and every limit.
- [DATA.md](DATA.md): every data plane, its source, its cadence and why a plane is withheld.
- [ARCHITECTURE.md](ARCHITECTURE.md): how the feed is built, signed and served.
- [SECURITY.md](SECURITY.md): false positives, and reporting a vulnerability.
- [core/FORMAT.md](core/FORMAT.md): the byte-exact plane format.
- [rpz/README.md](rpz/README.md): the policy zones.
- [`nginx/example.conf`](nginx/example.conf), [`apache/example.conf`](apache/example.conf),
  [`litespeed/example.conf`](litespeed/example.conf): worked configurations.
- [LICENSE](LICENSE) and [LICENSE.md](LICENSE.md).
