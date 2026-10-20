# Policy zone fixtures

Documentation space only (RFC 5737, RFC 3849). `../rpz-gate.sh` renders each body below into the file
the feed serves and proves it against a real BIND; the table is the count.

| file | what it is |
|---|---|
| `rpz.whisper.online.body` | the reputation zone's header and triggers: IPv4 and IPv6 `rpz-ip`, one `rpz-nsip` |
| `rpz.whisper.online.ranges` | the plane it was written from, one range a line with its severity; a NONE range has no trigger |
| `rpz-rpki-unreachable.whisper.online.body` | the rpki-unreachable zone: a range as its minimal CIDR cover, EXPIRE 7200 |
| `rpz-rpki-unreachable.whisper.online.ranges` | its plane, a membership plane: every range enforced |
| `rpz.whisper.online.empty-1791993600.zone` | the golden empty zone: the reputation fixture swept at its validity, byte for byte |

## The file format

UTF-8, LF line ends, every owner absolute, no `$ORIGIN`. In this order:

1. The header, one `; key=value` line each, every line at most 255 bytes:
   ```
   ; v=wedge-rpz1
   ; origin=<origin>
   ; state=content | empty
   ; generation=<the SOA serial>
   ; validUntil=<YYYY-MM-DDTHH:MM:SSZ>     content only
   ; triggers=<records below the apex>    content only, zero allowed
   ; sources=<...>                        content only, 0 to 16 lines
   ```
2. `$TTL 300`
3. `<origin>.<TAB>IN<TAB>SOA<TAB><mname> <rname> ( <serial> 900 300 <EXPIRE> 300 )`, no TTL field, the
   mname and rname the two names in `../rpz-gate.sh`'s `apex`
4. `<origin>.<TAB>IN<TAB>NS<TAB><first nameserver>` and the same for the second, no TTL field
5. The triggers, `<owner><TAB>300<TAB>IN<TAB>CNAME<TAB><target>`: `*.` for `rpz-ip` (NODATA), `.` for
   `rpz-nsip` (NXDOMAIN)

The serial is the generation, an epoch second at or above 1,000,000,000. For content, `validUntil` is
the serial's slot start (the hour) plus EXPIRE, and EXPIRE is at most 86400. The empty zone is the first
four header lines, `$TTL 300`, the SOA with EXPIRE 86400 and the two NS, nothing else: a function of the
origin and the serial alone. Expired content becomes the empty zone at
`max(slotStart(validUntil), serial + 1)`; `rpz.whisper.online.empty-1791993600.zone` is that file for
`rpz.whisper.online.body`, and every writer of an empty zone must produce it byte for byte.
