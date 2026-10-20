# Response Policy Zones

One zone per verdict plane, each a signed file you load into BIND as a primary:

```sh
sudo sh ../install/install.sh            # prints the named.conf lines and starts one refresh timer per zone
whisper-edge-refresh --zone rpz.whisper.online
```

| zone | blocks | answer |
|---|---|---|
| `rpz.whisper.online` | answers whose address has a citable listing | NODATA (`CNAME *.`); a name delegated into a nameserver prefix on the DROP list is NXDOMAIN (`CNAME .`) |
| `rpz-rpki-unreachable.whisper.online` | answers whose address no valid route covers | NODATA; the printed block loads it with `policy disabled log yes`, so it logs and blocks nothing until you choose |

`install.sh` prints the block to paste. On Debian and Ubuntu, where named's directory is
`/var/cache/bind`, it is:

```
zone "rpz.whisper.online" {
    type master;
    file "/var/cache/bind/whisper-edge/rpz.zone";
};
zone "rpz-rpki-unreachable.whisper.online" {
    type master;
    file "/var/cache/bind/whisper-edge/rpz-rpki-unreachable.whisper.online.zone";
};
options {
    response-policy {
        zone "rpz.whisper.online";
        zone "rpz-rpki-unreachable.whisper.online" policy disabled log yes;
    } qname-wait-recurse no;
};
```

The `response-policy` statement goes into your existing `options { }` block, not a second one, below
any policy zones of your own (first match wins). On RHEL the directory is `/var/named`. Then, once:
`named-checkconf && rndc reload`.

- **Validity.** Each file says until when it may be enforced (`; validUntil=` in its header). The
  refresh empties a zone past that time by itself. A file fetched any other way must be checked against
  its `validUntil` by whoever fetched it, or it will enforce a stale list for ever: nothing else expires
  a primary zone.
- **The name is the zone's own.** A file is refused when named loads it under another name. Rename the
  zone statement in named.conf to the published one, as in the block above.
- **The signature.** `zones/<sha256>.zone.sig` is Ed25519 over `whisper-edge-zone-v1`, one NUL byte, then
  the file's bytes, with the key `install.sh` fetched as `edge.pub`:
  ```sh
  { printf 'whisper-edge-zone-v1\0'; cat zone; } > signed
  openssl pkeyutl -verify -pubin -inkey edge.pub -rawin -in signed -sigfile zone.sig
  ```
- **BIND** is the path we test end to end: signature, timer and expiry.
- **Unbound** can fetch the reputation zone by URL itself; the README's resolver notes give the
  configuration and what was measured. It checks neither the signature nor `validUntil`.
- **PowerDNS Recursor** slaves a policy zone by transfer, and we do not hand out transfer keys yet.
- **Knot Resolver 5.x** applies only QNAME triggers, and every record here is an IP trigger, so it gets
  no policy from these zones.
- **A keyed subscription** (transfer by TSIG, NOTIFY) is not offered yet. Today, the signed file.

`rpz-gate.sh` proves each zone against a real BIND; `testdata/README.md` is the file format.
