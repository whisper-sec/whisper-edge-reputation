# Whisper edge reputation

Block the networks that reputable third parties have listed, with the listing shown. Free,
keyless, no account. For nginx, Apache and OpenLiteSpeed, one command:

```
sudo ./install/install.sh
```

It installs the signed feed and its refresh, writes the default policy into each server it finds,
runs that server's own configuration test, and reloads only when the test passes. On nginx and Apache
the default policy answers 403 to a source on a cited listing, Spamhaus DROP or another listing at high
or above, and to nothing else. Tor exits and unreachable routes are logged and let through. On
OpenLiteSpeed, which has no configuration test, the policy starts in `log`: it writes what it would deny
and denies once you run the `--arm-deny` line the report prints. The report's `undo` block takes it all
back, one pasted line per server.

Without the installer, the module on its own blocks nothing until you tell it to: its default mode is
`log`, which writes what it would have done and does nothing. The nginx form is one module and one
line:

```
load_module modules/ngx_http_whisper_edge_module.so;
whisper_edge_snapshot /var/lib/whisper-edge/snapshot.bin;
```

Worked configurations are in [`nginx/example.conf`](nginx/example.conf),
[`apache/example.conf`](apache/example.conf) and [`litespeed/example.conf`](litespeed/example.conf).

## Start here: one command

The installer finds the servers on the host and the user each one runs as, fetches the signing key once (and
refuses it unless its sha256 is the one pinned in the script), fetches and verifies every plane the
default policy reads, and then, for each server whose module is installed, writes the default policy
into that server's own configuration, runs the server's own configuration test, and reloads only when
the test passes. After the reload it reads the module's own status and says whether the policy is
running. It ends with the `undo` block, the lines that take it all back, and a last `watch:` line
recording each plane's state and refresh cycle.

This is a real run against the live feed (2026-10-17T21:01:50Z, a throwaway Ubuntu 24.04 box with nginx
1.24.0 and the module built from this tree; `--server nginx`, because that was the server with its
module there). What it found and armed:

```
== detected
   nginx 1.24.0 at /usr/sbin/nginx, module /usr/lib/nginx/modules/ngx_http_whisper_edge_module.so (loaded: no, running: yes), runs as www-data
== armed
   reputation armed, generation 497852, digest 2992a455ceeab14c, valid until 2026-10-18T20:00Z (/var/lib/whisper-edge/reputation.bin, verified against the key fetched from https://whisper.online/edge)
   reputation.bin was installed for the first time: it binds when the server reads its configuration, which this run does next
   rpki-unreachable: the manifest names no such plane; log if rpki_unreachable is inert at launch; it arms at the next reload after the refresh first installs rpki-unreachable.bin: when it does, run this installer again, which re-sizes the memory lock, tests and reloads
   tor withheld by the signed manifest: LOW_RECALL, IPV6_NOT_STATED; log if tor_exit is inert at launch; it arms at the next reload after the refresh first installs tor.bin: when it does, run this installer again, which re-sizes the memory lock, tests and reloads
```

What it wrote, and what nginx and the module then said:

```
== applied
   installed /usr/local/sbin/whisper-edge-lookup
   installed /usr/local/sbin/whisper-edge-summary
   wrote /etc/nginx/modules-enabled/50-whisper-edge.conf (the module's load line, 2 lines)
   wrote /etc/nginx/conf.d/whisper-edge.conf (the default policy, 13 lines)
   wrote /etc/whisper-edge/policy.conf (the default policy, 441 bytes, to read and edit)

== proved
   nginx: the configuration test passed
   nginx: reloaded (nginx -s reload)
   nginx: confirmed by the module: worker pid 5285, new since the reload, runs program 17740565c00d8971, reputation armed at generation 497852, header digest fd78f6ae5314710f (the file here reads the same)
```

`wrote` means a new file: nginx gets a `load_module` file in the directory its `nginx.conf` already
includes at the main level, and a 13-line file of the policy in the directory it includes inside
`http {}`. Nothing else in your configuration is opened for writing. If your configuration already fails
its own test, nothing is written and the report says the failure is yours; if the test refuses what was
written, those files are taken out again and nothing is reloaded. The `confirmed by the module` line is
read from the module's own status after the reload, from a worker that did not exist before it: a
configuration that tested clean but whose plane the module could not bind reads `unverified` there,
exit 3, never success. Its header digest is the plane header's own; the `armed` line's digest is the
file's sha256, which is what the feed publishes.

Run it again and nothing is rewritten and nothing reloads:

```
== proved
   nginx: nothing changed in its configuration, so it was not reloaded
   nginx: confirmed read-only (nothing changed, so nothing was reloaded): a live worker runs program 17740565c00d8971, reputation armed at generation 497852, header digest fd78f6ae5314710f; this checks the program and the plane only, not that the worker is new
```

The `undo` block prints one line per server (a long `sh -c '...'` you paste as is) and, where there are
any, one for the shared parts. The nginx line from the run above, pasted:

```
nginx: the installer's files are removed and the previous configuration is serving
```

On OpenLiteSpeed, which has no configuration test, the policy goes in a file of its own with one
`include` line added to `httpd_config.conf`, both written as the account that owns `conf/`, in `log`
mode; the module's status after the restart is the test, and `--arm-deny` turns it to `deny` once you
have read what it logs. `sudo ./install/install.sh --help` lists every option and what each exit code
means.

The zone goes under named's own directory (`/var/cache/bind` on Debian and Ubuntu, `/var/named` on
RHEL), because that is the only tree a confined named may read: Ubuntu's AppArmor profile allows
`/etc/bind`, `/var/lib/bind` and `/var/cache/bind`, and a zone anywhere else fails to load with a
"permission denied" in named's log and nothing on your terminal.

**On RHEL and other SELinux hosts** a web server started by systemd runs confined, as `httpd_t`, which
may read a file labelled `var_lib_t` but not map it, nor write one. When SELinux is enabled the installer
adds two local file-context rules and relabels with `restorecon`: the plane files become
`httpd_sys_content_t` (read and map, never write), and `counters/` becomes `httpd_var_lib_t`, so a
confined worker can rewrite its own status and counts there. It changes no boolean and loads no policy
module. On an enforcing Rocky Linux 9 host with nginx, Apache httpd and OpenLiteSpeed all started by
systemd, every server armed its planes and the module confirmed it, `getenforce` stayed `Enforcing`, and
the audit log held no `map` denial under the data directory. The report says what it labelled (nginx,
2026-10-19):

```
   labelled the planes in /var/lib/whisper-edge httpd_sys_content_t (semanage fcontext -a -t httpd_sys_content_t '/var/lib/whisper-edge/[^/]+\.bin'), so a confined server maps them, and writes none; the shared undo line removes this rule
   labelled /var/lib/whisper-edge/counters httpd_var_lib_t (semanage fcontext -a -t httpd_var_lib_t '/var/lib/whisper-edge/counters(/.*)?'), so a confined worker rewrites its own status and counts there; the shared undo line removes this rule
```

The rules, as `semanage fcontext -l -C` lists them:

```
/var/lib/whisper-edge/[^/]+\.bin                   all files          system_u:object_r:httpd_sys_content_t:s0
/var/lib/whisper-edge/counters(/.*)?               all files          system_u:object_r:httpd_var_lib_t:s0
```

A refresh that renames a new plane into place keeps the label. `whisper-edge-summary --status` reads
each worker's line as `process pid <pid> tick <n>`, and counts every worker live, with `foreign 0`.

On a freshly booted enforcing Rocky Linux 9 host, with confined nginx and Apache httpd serving
through the installer's whole run, `ausearch -m avc -ts boot` read no denial at all.

Without `semanage` the installer stops before writing anything and names the package to install.

The undo lines take both rules out again. On the same host, after pasting them as the report printed
them, `semanage fcontext -l -C` lists no local rule, the files left in the data directory read
`var_lib_t` again, the audit log held no new denial and `getenforce` still read `Enforcing`. The shared
line's own report names the units and the policy file, not the rules:

```
nginx: the installer's files are removed and the previous configuration is serving
the shared parts are removed: the per-plane refresh units and the policy file, where the installer wrote them
```

A plane file you keep yourself outside `/var/lib/whisper-edge`, bound with `whisper_edge_data <plane>
<file>`, is not covered by the rule. The installer keeps your line and says so, naming the file and
the two commands that label it the way it labels its own. For a reputation file kept at
`{your-file}`, the line reads:

```
   nginx: SELinux: your reputation file reads var_lib_t, which a confined server cannot map; label it as the installer labels its own: semanage fcontext -a -t httpd_sys_content_t '{your-file}'; restorecon {your-file}
```

Until those two commands run, a confined server cannot map the file, so the installer does not report
the plane confirmed after that line.

The user is **resolved, not assumed** - the server's own configuration is asked first, the running
process second, a candidate list last. It matters because the counters directory has to be writable
by the server, and a directory granted to the wrong name fails silently: counting is not on the
request path, so nothing breaks, you just get an empty report.

The module itself is one build command per server, [below](#building-the-modules).

**On a serverless runtime there is no module to load.** Cloudflare Workers, Vercel, Deno,
Netlify, Lambda and Supabase Edge Functions cannot load a `.so`, so the check belongs in your
handler instead, and [`whisper-edge`](https://github.com/whisper-sec/whisper-edge)
(`npm i whisper-edge`) is where it lives. It asks the same Whisper graph this snapshot is built
from, live and per address, over one `fetch` and with no key. The trade is the plain one: a
network round trip per lookup there, a snapshot built ahead of time and no syscall here.

Looking up a verdict makes no syscall, takes no lock and allocates nothing, which is checked by
disassembling the compiled lookup at three optimisation levels on both x86_64 and aarch64 rather than
asserted. Every compiled copy of the policy decision also leaves a four-byte record in a section of its
own, `.we_eval_sites`, which a module's gate reads to prove that the module evaluates in exactly one
place, its gated wrapper; the record adds no instruction (`core/gate/eval-sites.sh` builds the wrapper
as the modules are built, with the record and without it, and reads the same instruction count on both
compilers). That is about the verdict specifically: the log line a match produces costs what any nginx
log line costs, and in `log` mode every match writes one. **No address in
the IPv4 space can take more binary-search probes than the `maxProbes` `/edge/snapshot.json` publishes
for the current build** - computed over all 65,536 index buckets rather than sampled,
with the builder refusing to publish a snapshot where it exceeds 12. That is the number worth quoting,
because it covers every address rather than the ones a benchmark happened to draw. For scale, the
bench record measures 31.1 ns per lookup for the layout the feed ships (format 1, radix-16) at 120,000
ranges, a sampled mean on an idle aarch64 machine; we do not quote a percentile from that measurement,
because it is derived from batch means and is not a sound tail.

### The three servers, and exactly what each one gives you

One core, three hooks. The core holds the format, the integrity check, the loading, the atomic swap,
the lookup and the deny rule; each shim only knows where to hook, how to get the client address, how
to log, and how to schedule a refresh.

| | nginx | Apache httpd | OpenLiteSpeed / LiteSpeed |
|---|---|---|---|
| default mode, the module alone | `log`, blocks nothing | `log`, blocks nothing | `log`, blocks nothing |
| the installer's default policy | `deny` on a cited listing | `deny` on a cited listing | `log` until `--arm-deny` |
| finest control | per `location` | per `<Location>` / `<Directory>` | **per virtual host** |
| verdict exposed as | `$whisper_edge_verdict` | `%{WHISPER_EDGE_VERDICT}n` note | `%{WHISPER_EDGE_VERDICT}e` env |
| client address | the floor: the TCP peer, or a trusted proxy's header entry; the context's rules: the peer `realip` rewrites | the floor: as nginx; the context's rules: `r->useragent_addr`, which `mod_remoteip` sets | the floor: as nginx; the context's rules: the address the server reports |
| refresh | the module's own thread in each worker | the module's own thread in each child | the module's own thread |
| threading | one thread per worker | **prefork, worker and event all proven** | threaded |

**LiteSpeed is not Apache-module-compatible.** It reads Apache *directives*, which makes it easy to
assume it loads Apache `.so` modules too, and it does not; it has its own module API, so
`litespeed/` is a real module and not a copy of the Apache one.

**The LiteSpeed granularity really is per-site, not per-location.** A per-context module block is read
by OpenLiteSpeed's config parser and never reaches a module, which is a property of the server rather
than of this code; the detail and the source reference are in the comment at the top of
`litespeed/mod_whisper_edge.c`. Per-virtual-host is one site, which is the unit that matters on a web
host, but it is not the same thing as the other two and the table says so.

**Where a rewritten request is judged, on the two servers whose mapping differs.** On nginx a `try_files`
match is judged by the location the request selected, so a rule for the matched file belongs on that
location. OpenLiteSpeed judges a request under the virtual host's one policy each time its request
processing passes `HTTP_AUTH`; an internal rewrite or index selection may pass it one or more times
depending on how OpenLiteSpeed maps the result; the decision is the same whichever context a pass
selects, and the per-rule counters count each pass.

**LiteSpeed's own cache module does not take the decision away.** A cache hit still passes the same
`HTTP_AUTH` step where the module judges, so a cached page is judged like any other request: a listed
client gets the deny on the cached URL, and the unlisted client after it still gets the cached bytes.
Only dynamic responses are stored at all, the server's own debug line being "cacheTofile to be
cancelled for static file type". Behind any cache this module judges only the requests that reach the
server, and on this one every request does. Apache's `mod_cache` quick handler is the case to watch
there: it can serve a cached response before any access hook can judge it, while this cache changes
only where the body comes from.

**The request path makes no system call of its own, counted rather than argued.** A test build of the
LiteSpeed module brackets its one request hook with two marker calls (`getpgid` of a pid above the
kernel's limit, which does nothing and answers ESRCH), and `litespeed/litespeed-gate.sh` traces the one
worker's event-loop thread under ptrace while a sequential client sends 1,000 warm-up requests and then
10,000 more, one connection each, `Connection: close`. What the trace shows, from the gate's own output:

```
  ok    R1s: H_server measured 1 on every one of the 1000 warm-up windows, equal to the table's t = 1
  ok    R1s: the run holds exactly N x t = 10000 entry markers and as many exits, each inside its own window
  ok    R1s: exactly 0 syscalls between any entry marker and its exit marker over the 10000 requests (and 0 over W + N)
  ok    control: a getpid() planted in the decision is read exactly 1000 x H_server = 1000 times inside the brackets (1000 calls inside them in all)
```

The count is a count, never a difference between two runs, and the production module traced the same way
makes no marker-valued call at all; a listed client under `mode log` shows the one rate-limited log write
inside its bracket, printed beside the figure rather than hidden by an allow-list.

**The policy corpus loads on this server exactly as the compiler's own tests read it.** Each of the fifty
refusals in `core/testdata/policy/refuse` is rendered into a virtual host and loaded for real, and the
module's refusal line must carry the host, the directive's ordinal and then, byte for byte, the rule,
line, column and token the corpus expects, with its message; the twenty accepted programs load the same
way with no refusal. Three records cannot be carried by a plain-conf parameter at all, a NUL byte, a CR
and a lone LF inside the argument (OpenLiteSpeed's configuration parser drops the NUL and cuts at the
CR, measured), and the gate prints what the module received for those instead of asserting either way.
One more is a property of the server worth knowing before writing a large block: **OpenLiteSpeed 1.9.3
caps a module block at 300 parameters.** Past that it gives the block's parameters up with one ERROR
line of its own (`preParseModuleParam get more items than defined max count 300, have to give up`) and
still hands the host to the module, which then reports it with no lines of its own and runs the server's
program; the gate loads blocks of 299, 300 and 301 parameters and asserts exactly that, so the corpus
record with 1,025 declarations is reported, not asserted, on this server.

**The counter cap on this server is reached only across 256 virtual hosts, and the crossing host is the one
refused.** A configuration may count 65,536 rule slots (8 pre-stage slots, the floor's rules and every
context's own rules); a block holds at most 300 parameters here and a context at most 256 rules, so the cap
takes at least 256 hosts. The gate loads 256 hosts that land exactly on it, then a 257th with one rule:

```
    at the cap: 256 hosts, 65523 fixture rules, the server up in 3763 ms
  ok    cap: exactly 65,536 slots (8 pre-stage + 65,528 rules) is accepted; the configuration-wide line counts every context and rule
  ok    cap: and prints the stride's bytes, the per-worker ceiling on this server (one shard per worker): 524288
    one over the cap: 257 hosts, 65524 fixture rules, the server up in 4067 ms
  ok    cap: the 257th host, with one rule, crosses and is refused with the core's line naming the five largest contexts: http/v8 (256) http/v9 (256) http/v10 (256) http/v11 (256) http/v12 (256). The 
  ok    cap: and the build stands at 65,528 rules with the crossing host running the empty program
  ok    cap: this configuration's file (conf-acd4ba7f0de49c0d.status, 3241903 bytes) carries the crossing host's refused line, naming the cap
```

The host that crosses runs the empty program and is listed `refused` in the configuration file; every other
host and the floor stand, and the line names the five largest contexts so the operator knows where the
slots went. Before this the module refused the whole configuration, floor included, which was the wrong
way round.

**StrictModes on the files OpenLiteSpeed reads for module keys.** The main `httpd_config.conf`, every file it
includes and every host's `configFile` must be owned by root or the server's admin account (the owner of
`conf/`, `lsadm` on a stock install), writable by neither group nor world, under directories held to the same
rule. The main file or an include failing it refuses the http level, with the file, its owner and mode and the
fix in the error log, and the module runs no program until it is fixed; a host's file failing it refuses that
host alone. Measured by the gate:

```
  ok    strict: the main file group-writable: refused naming the file, its owner and mode, and the fix: /usr/local/lsws/conf/httpd_config.conf: is writable by group or world (mode 0660); the file is o
  ok    strict: the main file's mode restored: accepted, the floor denies the CRITICAL client
  ok    strict: a host's group-writable configuration file refuses that host alone, with mode and fix: policy refused: "WhisperPolicy": its configuration file fails the trust rule: /usr/local/lsws/con
  ok    strict: whisper_edge_data through a tenant-owned symlink in a tenant-writable directory is refused at binding: the planes are not bound: whisper_edge_data /tmp/whisper-edge-ols-gate.jkmTlj/sit
  ok    strict: a root-owned symlink in a root-owned directory binds
  ok    strict: the symlink repointed at an empty directory after binding changes nothing the module reads (the held descriptor; a LOW client is still denied after a tick)
```

The data directory follows the same idea through a symlink: a tenant-owned link in a tenant-writable directory
is refused at binding, a root-owned link in a root-owned directory binds, and repointing the link afterwards
changes nothing the module reads, because it holds the directory's descriptor.

**A host's block arriving after the configuration was built** never happens on OpenLiteSpeed 1.9.3 (every
`parse_config` precedes `MAIN_INITED`, measured), but a server release could change that, so the module says
what it would do and the gate forces the case with a control build: the late host runs no context rules,
the error log names it, the process line carries `late-build`, `whisper-edge-summary --status` exits 1 and
the floor still runs.

**A plane's transition is one line per program, through the server's own logger, the same bytes as the status
file.** When a plane goes stale the module writes, for each distinct program with a rule on that plane, the head
(`plane <name> <state> out=<planes out> tenant=<state>`) and which rules now capture or are disarmed, cut at 511
bytes, and `whisper-edge-summary --status` shows the same text. The gate builds a 256-rule program whose line
would run to 990 bytes and checks the cut and the bytes:

```
    Q6 model: the 256-rule entry uncut is 990 bytes: the head 36 + ':' 1 + ' rules ' 7 + the odd rules 456 + ' allow captures' 15 + '; rules ' 8 + the even rules 458 + ' disarmed' 9
  ok    Q6: the 256-rule entry the server's logger wrote is exactly 511 bytes after the server's prefix, byte-identical to the status file's transition text
  ok    Q6: its head is intact: plane tor stale out=tor tenant=fresh
  ok    Q6: the second transition's head reads out=reputation,tor in plane order, the entry equal to the status file's
  ok    Q6: with tenant.bin past its valid-until and its 48 h grace, the head reads tenant=lapsed
  ok    control: the uncut build logs the 256-rule entry at 990 bytes, the model's figure, against the ring's 511
    measured: after the roll, transition entries in the live file 0, in the rolled file 25; the server's logger, which the module uses, did not reopen the live file
```

On OpenLiteSpeed 1.9.3 a size-based roll of the error log renames the file, and a process that had it open keeps
writing the renamed one until it restarts, the server's own lines included; the module writes through the server's
log call, so its lines go wherever the server's go, which after a mid-run roll is the rolled file.

## For a resolver, as a Response Policy Zone

This is the better mechanism - it protects every device behind the resolver rather than one web server
- and today you use it by **fetching a file**, not by slaving the zone. Being precise about what exists,
because a dead pointer is worse than no pointer:

- **The zone files work now, one per verdict plane.** `rpz.whisper.online` is the reputation policy:
  an answer whose address has a citable listing becomes NODATA, and a name delegated into a nameserver
  prefix on the DROP list NXDOMAIN. `rpz-rpki-unreachable.whisper.online` covers answers whose address
  no valid route covers, and the block `install.sh` prints for named loads it log-only (`policy disabled
  log yes`), so it logs and blocks nothing until you choose; the installer writes nothing in named's
  configuration itself. [`rpz/README.md`](rpz/README.md) has the table and the paste.
  Each is a complete, loadable policy zone, apex and all, at `/edge/rpz/<origin>.zone`, with a detached
  signature beside it (below); `/edge/rpz.zone` is the same bytes as the reputation zone, for the
  installs that fetch it under that name. `install.sh` fetches each zone, verifies its signature,
  checks it with `named-checkzone`, and installs a timer per zone that keeps it current in named
  (below). They are for a resolver that supports IP triggers; see the resolver notes below.
- **The zone resolves, and we are not issuing transfer keys yet.** `rpz.whisper.online` is served by
  our nameservers, the very file you fetch, so you can look at it and see for yourself that it is live,
  what its serial is and what its timers are (the RPKI zone is published as a file only, for now):

  ```
  dig +tcp @ns1.whisper.online rpz.whisper.online SOA
  dig +tcp @ns2.whisper.online rpz.whisper.online SOA
  ```

  A zone transfer needs a TSIG key, and **we are not handing those out yet**, though the reason has
  changed and it is worth separating the two halves.

  The MECHANISM is built. A transfer key is now authorised per zone, against the exact apex it was
  issued for: a key for `rpz.whisper.online` transfers that zone and nothing else, cannot be used
  from an address it was not issued to, and transfers are bounded both globally and per peer so one
  slaving resolver cannot crowd out the others. Each of those three is tested against the case it
  exists for rather than only the happy path.

  What is NOT built is the OFFER: there is no way for you to ask for a key and get one. Keys are
  configured by us, which means a conversation, which is not something we are going to pretend is
  self-service. Until it is, fetch the zone by name and load it locally; it is the same policy, and
  the recipe below keeps it fresh.

  We used to say the reason was that our authorisation model was not ready. That stopped being true
  on 9 October 2026 and this paragraph is the correction.
- **The zone is deliberately unsigned.** It sits under a signed parent as an insecure delegation
  (NS, no DS), which is a defined and valid DNSSEC outcome rather than an oversight, and you can
  check it: `dig +tcp +dnssec @ns1.whisper.online rpz.whisper.online DS` answers NOERROR with no DS
  and an NSEC3 proving there is none, which is what lets a validator mark the zone Insecure rather
  than Bogus. A resolver does not DNSSEC-validate a policy zone it consumes as local policy, it
  authenticates the transfer, so a signature there would be bytes nothing reads - at the cost of tens
  of thousands of signatures per rebuild and a signing load any stranger could drive by querying names
  that do not exist. The file form is where the integrity that reaches you lives: each zone file has a
  detached Ed25519 signature at `/edge/zones/<sha256>.zone.sig`, by the same key as the snapshot, over
  the bytes `whisper-edge-zone-v1`, one NUL, then the file. The prefix means a signature over a zone can
  never pass for one over anything else the key signs. The refresh verifies it before it looks at
  anything else in the file; [`rpz/README.md`](rpz/README.md) shows the two `openssl` lines that check
  it by hand.
- **Why not simply open the transfer to everyone.** An unauthenticated transfer gives a slaving
  resolver nothing to verify the zone with - the same fact as the bullet above, cutting the other way -
  so anyone in front of our nameservers could hand you an RPZ that NXDOMAINs the internet for everyone
  behind it. So the transfer has to be authenticated, which means a key, and a key for one zone must
  not be a key for every zone we hold. That scoping is the part that is now built; see above for what
  is still missing, which is the request path rather than the mechanism.

### The timers you inherit, and why they are what they are

```
rpz.whisper.online. SOA ns1.whisper.online. hostmaster.whisper.online. (
    <serial> 900 300 <expire> 300 )
```

The serial is the publication: an epoch second, the start of the hour the build was for plus a few
seconds that say which build it was, at least 1,000,000,000 and newer under RFC 1982 than every serial
before it. It is the same number in the file you fetch and in the zone our nameservers serve, because
they serve that file, so compare either with either.

**Each zone says how long it may be enforced.** Its header carries `; validUntil=` (RFC 3339, UTC),
and its SOA EXPIRE is that span counted from the start of the hour the serial falls in, capped at a
day: 86400 for the reputation zone, and less for a zone whose plane is valid for less. A zone normally inherits something like a
fortnight, which is right for infrastructure: a secondary that loses its primary keeps answering
rather than going dark. For a BLOCKLIST the same number means that if you stop being able to reach us,
your resolver keeps blocking on data it cannot refresh, and there is nothing we can do about it from
here. For the reputation zone, one day is the same clock the snapshot's own 24-hour validity uses, so
both halves of the reputation feed stop enforcing together rather than one failing open while the
other does not.

**But BIND applies EXPIRE only to a secondary**, and a zone loaded from a file is a primary: named would
enforce it for ever. So the refresh enforces the zone's validity instead. Once the installed zone is
past its `validUntil`, it is replaced by the empty zone (SOA and NS only) at serial
max(the start of the hour `validUntil` falls in, serial + 1), and named is told to reload it. Those are
the bytes and the serial our nameservers sweep the zone to themselves, within seconds of the same
moment, so a resolver that lost the feed and one that kept it end up holding the same file.

On a resolver that cannot reach the feed, the timer's run says it could not fetch the zone and leaves
the installed one untouched; once that zone is past its `validUntil`, the run installs the empty zone at
the fleet's serial, says the zone has EXPIRED and which serial it now holds, and reloads it in named. The
first run that reaches the feed again, once the feed has built a newer zone, installs it, says which
serial it replaced, and reloads. Each step is a row of `install/rpz-bind-gate.sh` against a real BIND:
"the feed down: exit 1, the failed fetch counted, the installed zone untouched and still loaded"; "past
validUntil with no fetch due: the empty zone at serial = slotStart(validUntil), byte for byte the
fleet's"; and "a changed fetch reloads that one zone once".

The clock is the zone's own `validUntil`, fixed when it was published, not the last successful fetch,
so a feed that answers "not modified" until then is treated exactly like one that does not answer. A
zone fetched already past its `validUntil` is refused and nothing is installed (exit 1): the node that
served it has not published since. The next newer zone puts the policy back with no step from you. The
worst case, from a build to the moment nothing behind your resolver is blocked by it any more, is
EXPIRE from the start of the build's hour, plus up to about six minutes of timer granularity on the
expiry check (a five-minute timer with up to a minute of jitter), plus the record TTL (300 s) for
answers already cached downstream, plus BIND's `min-update-interval` (60 s by default) before a
reloaded policy takes effect.

A serial older than the installed one is what a feed node one publication behind looks like (the name
fronts two nodes), so it is left alone, counted as `whisper_edge_rpz_stale_feed_total`, and the run
succeeds. When it is the very content this resolver swept, the message says the feed's zone has expired
and it has not published since, which is a different problem from a node behind. A zone file from
before per-zone files (no `; v=wedge-rpz1` header) keeps the rule it was installed under: it is emptied
once its serial has not advanced for longer than its own EXPIRE, and the first newer zone replaces it.

REFRESH is 900, and the zone timer honours it: it fires every 5 minutes and fetches only when the
installed zone's own REFRESH has passed, or its RETRY after a failure, which is a secondary's schedule
read from the zone. An unchanged feed costs a `304 Not Modified` to an `If-None-Match` carrying the
installed file's sha256. If one day we NOTIFY you, BIND still waits up to `min-update-interval` before
applying the new policy, so "within about a minute", not "in seconds".

### The other resolvers, accurately

- **Unbound** fetches the file itself with an `rpz:` clause and a `url:` line, and re-downloads it on
  the zone's own SOA REFRESH, so it needs neither the timer nor a reload:

  ```
  server:
      module-config: "respip validator iterator"
      tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
  rpz:
      name: rpz.whisper.online
      url: https://whisper.online/edge/rpz.zone
  ```

  `tls-cert-bundle` is not optional here. Unbound authenticates an `https` url with that bundle and
  the URL's hostname, and the bundle defaults to none, so without the line the zone is fetched over
  TLS that verifies nothing. Unbound does not check the zone's detached signature, so TLS is all that
  stands between it and anyone on the path handing your resolver a policy that blocks whatever they
  like. (On RHEL the bundle is
  `/etc/pki/tls/certs/ca-bundle.crt`.) One thing measured on Unbound 1.19.2 you should know: past
  the zone's EXPIRE with the feed unreachable, `unbound-control list_auth_zones` reports the zone
  `expired`, and Unbound **keeps applying the policy** anyway. Nor does it read the zone's
  `validUntil`. The refresh's empty-zone rule does not reach a zone Unbound fetches for itself, so on
  Unbound a stale list stays in force until the feed comes back.
- **PowerDNS Recursor** slaves an RPZ with `rpzPrimary()` in its Lua config, which needs a zone
  transfer, and we do not hand out transfer keys yet (above). Not tested by us.
- **Knot Resolver 5.x does not apply to this feed.** Its policy module watches the file and reloads it
  by itself, but supports only the QNAME trigger - a left-hand side that is a domain name - and every
  record we publish is an `rpz-ip` or `rpz-nsip` trigger, so a Knot 5.x operator loading our zone gets
  zero policy, silently. Checked against the 5.x documentation, not against a later release; if that
  has changed, tell us and we will correct this line.

We have tested the BIND path end to end, signature, timer and expiry included, and claim that one. Unbound's
refresh and expiry behaviour above was measured; its policy path otherwise is not yet claimed.

### One thing to know before you rely on it

**BIND does not rewrite answers for DNSSEC-aware clients by default.** `break-dnssec` defaults to `no`,
which means RPZ actions apply only to queries that do not request DNSSEC metadata, or to names with no
DNSSEC records. So a validating client behind your resolver - another BIND with validation on,
`systemd-resolved` with DNSSEC, `dnsmasq --dnssec` - will get the unrewritten answer for a *signed*
attacker domain, and the block quietly does not apply to it.

If that matters to you:

```
response-policy { zone "rpz.whisper.online"; } break-dnssec yes;
```

with the consequence stated plainly: a rewritten answer cannot validate, so a validating client sees a
SERVFAIL rather than an NXDOMAIN. That is a real trade and we are not going to make it for you. We
would rather you know the limit than discover it.

## What it denies, and what it only logs

What the installer writes, per server: on nginx and Apache the policy is in `deny` mode and denies, with a
403, only a source on a cited listing at high or above; its Tor and unreachable-route rules are `log`
rules, which record and let through. On OpenLiteSpeed the same policy runs in `log` until you run
`--arm-deny`. The module on its own, with no policy written, defaults to `log` on all three.

In `log`, a rule that would deny writes the verdict it *would* have acted on into your error log,
exposes it for your access log, and blocks nothing.

In the access log, through whichever variable your server uses (`$whisper_edge_verdict` in nginx, the
`%{WHISPER_EDGE_VERDICT}n` note in Apache, the `%{WHISPER_EDGE_VERDICT}e` environment variable in
LiteSpeed), here with every decision value the module exports written into one line:

```
127.0.0.1 200 action=would-deny rule="-" id=- reason=- program="floor:254b0a5033f18114
ctx:31df7b9abad409f5" logged="ctx:1,2" gen="reputation:1.9e520733 tor:1.0a52b7bb tenant:-a"
floor=153.153.153.153 verdict=high listed=high tor=false inferred=false asn=- country=-
```

And into your error log, with the citable evidence attached, so the answer to "why would you have
blocked this?" is in your own logs rather than in a support ticket:

```
2026/10/19 03:04:25 [error] 43918#43918: *8 whisper edge: WOULD DENY 2.26.75.1, rule 0 "-" of floor:- ctx:17740565c00d8971, verdict high,spamhaus-drop, evidence SBL698389 (DROP) (mode is log, request allowed; 1 would-deny so far, 1 since the last line), client: 2.26.75.1, server: localhost, request: "GET / HTTP/1.1", host: "127.0.0.1"
```

The access-log line is from `litespeed/litespeed-gate.sh`, running the module inside a real
OpenLiteSpeed, which is why the peer is the loopback and the judged address (`floor=`) is the gate's
client behind its trusted proxy. That client is a real address because it has to be: on OpenLiteSpeed
the floor judges the client itself, every IPv4 documentation, benchmarking and private range is in
the hold-harmless set ([`hold-harmless.txt`](hold-harmless.txt)), and a hold-harmless client is exempt
before any rule runs, so the gate's listed client must be global unicast space. 153.153.153.153 is in
someone else's network and on no Spamhaus list; it is `high` only because the gate's own fixture
snapshot lists it. The line says: the default allow decided
(`action=would-deny`, no deciding rule), because the deny rule and the log rule of the program the host
runs (the server's, inherited by a site that writes no policy of its own) both fired under the dry-run
default (`logged=ctx:1,2`), on a client the reputation plane lists at `high`, with the two bound planes'
generations and digests named and the tenant plane absent (`tenant:-a`). An nginx reader following
`nginx/example.conf` sees `whisper=high` inside their own combined-log line rather than this exact
shape, because the format is theirs to choose. The only edit is the line wrapping, which your terminal
will not do.

The error-log line is from nginx 1.30.6 on Rocky Linux 9 with the installer's policy switched to `log`,
against the live feed on 2026-10-19: 2.26.75.1 is on Spamhaus DROP as SBL698389, sent through a proxy
nginx trusts (see [Behind a proxy on the same box](#behind-a-proxy-on-the-same-box)), and the request
was allowed. In `log` nothing decides, so the line reads `rule 0 "-"`, the default allow; the same request
in `deny` names the rule that denied it, `rule 2 "deny if listed >= high"`. All three servers write this
line, and the deny line, at `error`, the level nginx and Apache use for their own denials, so a stock
error log shows it.

Run it that way against your own traffic for a week. Read what we say about your real visitors. Then
turn on `deny` yourself, if you want to.

We would rather you never enable it than enable it on our word and lose a customer.

The log lines are rate-limited to one per second per worker, each carrying the count it suppressed,
because an unlimited line per matching request would turn our own logging into a disk-fill against
you under a flood from listed space - which is precisely the traffic this exists for.

## Behind a proxy on the same box

When a proxy on the same machine sits in front of your server, and the server already trusts it (nginx
`realip`, or Apache `mod_remoteip`), your policy lines (the context's rules, which is where the
installer's default policy goes) judge the client the server's `realip` names, not the proxy. A
listed client is denied through the proxy just as it is when it connects directly. The floor rules judge the TCP peer, the proxy, unless you also name the proxy to the module
with `whisper_edge_trusted_proxy` and `whisper_edge_trusted_header`: then the floor judges the client
too, from the header entry the module reads itself. The hold-harmless exemption follows the address
each step judges, so a hold-harmless proxy such as the loopback does not exempt the client behind it
from your policy lines.

What a request got, with the installer's policy in `deny`, measured on an enforcing Rocky Linux 9 host
(nginx 1.30.6 and Apache httpd 2.4.62, both started by systemd) against the live feed on 2026-10-19,
with the server trusting 127.0.0.1 as its proxy:

| request | nginx | Apache |
|---|---|---|
| through the proxy, `X-Forwarded-For: 2.26.75.1` (on Spamhaus DROP as SBL698389 on 2026-10-19) | 403 | 403 |
| directly from 2.26.75.1 | 403 | 403 |
| an unlisted client, through the proxy and directly | 200 | 200 |
| the proxy itself, 127.0.0.1, with no header | 200 | 200 |
| a hold-harmless client through the proxy (8.8.8.8, and 193.0.14.129, K-root) | 200 | 200 |

The test trusts 127.0.0.1 only because the proxy in it was `curl` on the same box. On a real host,
trust exactly the address your proxy connects from, and nothing a client can reach directly: whoever
the server trusts chooses the address the module judges.

The nginx error log, for the proxied request:

```
2026/10/19 03:04:22 [error] 43666#43666: *1 whisper edge: denied 2.26.75.1, rule 2 "deny if listed >= high" of floor:- ctx:17740565c00d8971, verdict high,spamhaus-drop, evidence SBL698389 (DROP) (1 denied so far, 1 since the last line), client: 2.26.75.1, server: localhost, request: "GET / HTTP/1.1", host: "127.0.0.1"
```

And its access log, proxied then direct (the last field is the `X-Forwarded-For` header):

```
2.26.75.1 - - [19/Oct/2026:03:04:22 +0000] "GET / HTTP/1.1" 403 153 "-" "curl/7.76.1" "2.26.75.1"
2.26.75.1 - - [19/Oct/2026:03:04:22 +0000] "GET / HTTP/1.1" 403 153 "-" "curl/7.76.1" "-"
```

The Apache error log, proxied then direct:

```
[Mon Oct 19 03:04:22.197957 2026] [:error] [pid 43692:tid 43794] [client 2.26.75.1:0] whisper edge: denied 2.26.75.1: rule ctx:2 (deny if listed >= high), program floor:- ctx:17740565c00d8971, verdict high,spamhaus-drop, evidence SBL698389 (DROP)
[Mon Oct 19 03:04:22.208606 2026] [:error] [pid 43694:tid 43848] [client 2.26.75.1:47426] whisper edge: denied 2.26.75.1: rule ctx:2 (deny if listed >= high), program floor:- ctx:17740565c00d8971, verdict high,spamhaus-drop, evidence SBL698389 (DROP)
```

The log line spells the verdict the same way on every server, `high,spamhaus-drop`; the
`$whisper_edge_verdict` variable keeps nginx's shorter `high,drop`.

Apache logs the proxied client as `[client 2.26.75.1:0]` because `mod_remoteip` sets the client's
address but not its port; the direct request shows its real one.

## The number you can paste into a chat

Nobody installs a blocklist because it works. They install it because somebody they trust showed them
a number. So the module produces that number itself, on your host, with no console, no account and
nothing leaving the machine:

```
$ whisper-edge-summary core/.testtmp/nginx/counters
Whisper edge, 16 minutes of blocking
counting since 2026-10-18 05:43 UTC, across 59 worker processes

  381 requests denied
  (a deny under mode log is counted too: that request was allowed, and logged as a would-deny)
  from 1 network

worst offenders:
  198.18.0.0/24      381  high     SBL-EXAMPLE-EVIDENCE-12345 abuse@example.net

Every number here was counted on this host. Nothing was sent anywhere to produce it.
```

That is a real capture, the summary run over the counters `nginx/nginx-gate.sh` left after running
the module inside a real nginx - which is why the window is the gate's sixteen minutes, the workers
are the gate's many restarts, the network is the gate's synthetic listed client and the evidence id
is the gate's synthetic one. The gate runs in log mode, so every one of those requests was allowed and
counted as a would-deny, which is what the second line says. Against your own traffic the window is however long you have been running, the
networks are your real visitors', and the evidence is the listing id and abuse contact the snapshot
carries for each one.

Four things about it are deliberate:

- **The numbers are counted, not estimated.** There is one counter per range in the snapshot, and a
  range IS a network: the build resolves every prefix into a disjoint interval, so "how many distinct
  networks" is how many counters are non-zero and "the worst offenders" is the same array, sorted. No
  sampling, no cardinality estimator, no reservoir.
- **The window is stated rather than rounded up.** It says what it actually counted. A report that
  called six hours "this week" would be the most quietly dishonest thing we could ship, so the first
  line is the real elapsed time and the second is the wall-clock instant counting began.
- **Nothing is counted on the allow path.** The counter is incremented where the module has already
  decided to deny, which is also where it already writes a log line. `core/hotpath-gate.sh` fails the
  build on an atomic instruction inside the lookup, for exactly this reason: an increment there would
  be paid by every allowed request - all of them - to measure the rare one.
- **An empty directory says so.** "I blocked nothing" and "I cannot find your counters" are different
  sentences, and you are entitled to tell them apart.

**Where the counters live.** Each worker process writes its own file, named for its pid, into one
directory; the tool sums them. A worker writes on every refresh, and under nginx and OpenLiteSpeed
once more as it exits, so a reload or a graceful restart keeps what it counted since its last
refresh, unless OpenLiteSpeed's restart script gives up waiting for the new instance
and kills the old one with `pkill -9`, which no module survives. The directory defaults to
`counters` inside the data directory, or beside the snapshot you configured, so if you followed the
recipe below there is nothing to set. A configuration that binds its planes only by per-plane
`whisper_edge_data <plane> <file>` lines gets `counters` beside those files when they share one
directory. When they are in more than one, no one place is beside them; and a module never creates
`/counters`, so a data directory of `/` or a snapshot at the filesystem root has no default either.
In both cases the error log names the files and the directive, counting is off until the directive
names a directory, and blocking is unaffected:

| server | directive | default |
|---|---|---|
| nginx | `whisper_edge_summary <dir>;` or `off` | `counters` in the data directory, or beside the snapshot or the bound files |
| Apache | `WhisperEdgeSummary <dir>` or `off` | `counters` in the data directory, or beside the snapshot or the bound files |
| OpenLiteSpeed | `whisper_edge_summary <dir>` or `off` | `counters` in the data directory, or beside the snapshot or the bound files |

**One thing to do on a server that drops privileges.** The module creates the directory when it can,
which covers an unprivileged server and a container. A server started as root and dropping to a
worker user (`www-data`, `nobody`) cannot write a directory root created, so create it yourself and
give it to that user:

```
install -d -o www-data -g www-data /var/lib/whisper-edge/counters
```

Without it the module logs one line naming the directory and carries on. Blocking is unaffected; you
just get no report. That is the direction we would rather fail in, and it is why the line is a
warning and not an error.

**Reading health from a directory others can write.** Every server user can write the counters
directory, so on a shared host a status file there may not be your server's. Name the worker's uid
and `--status` reads only that uid's own files:

```
whisper-edge-summary --status /var/lib/whisper-edge/counters --writer-uid 33
```

A file another uid owns, a symbolic link, a second hard link or a file open to group or world write
is refused by name and never read, and a `foreign entries N` line counts them. The verdict and the
exit code are otherwise what they are without the option, and the tool needs no privilege for it:
it runs the same as `nobody`. The uid may also be given as a user name.

## What is in it

Every entry has a citable listing behind it. Not a score, not a category, not a hunch: a Spamhaus SBL
id or a DROP entry you can look up yourself.

A real build, 8 October 2026:

```
2273 candidate prefixes  ->  1864 admitted  ->  971 IPv4 + 27 IPv6 ranges
1,112,832 addresses, 0.026% of IPv4
refused: 303 below tier, 98 anycast, 8 too broad
```

The refusals matter more than the admissions. **98 anycast prefixes were refused on that build** -
each one a network with a real listing somewhere in it that we will not let you black-hole globally.
Those counts move between builds, because the graph is live; `/edge/snapshot.json` carries the current
ones and is the figure to trust over anything written here.

**IPv6 evidence reads the same as IPv4's.** The snapshot carries evidence for IPv6 ranges as it does
for IPv4, and nginx, Apache and OpenLiteSpeed all name it in their deny and WOULD DENY lines for both
families. `whisper-edge-lookup` reads it out too. Against the checked-in fixture (documentation space,
a synthetic listing id; in a checkout made under umask 002, run `chmod 644 core/testdata/interop.snap`
first, because the loader refuses a group-writable plane on purpose):

  ```
  $ whisper-edge-lookup core/testdata/interop.snap 2001:db8:beef::1 | grep -E '^(address|attr listed|decision)'
  address 2001:db8:beef::1 family=6 canonical=2001:db8:beef::1
  attr listed critical plane=reputation range=2001:db8:beef::-2001:db8:beef:ffff:ffff:ffff:ffff:ffff record="sev=4" drop=no evidence=EXAMPLE-7
  decision log would-deny=yes step=sugar rule=0 log=ctx:1 would-deny-rule=ctx:1 would-deny-text="deny if listed >= high"
  ```

## What it will never block

A blocklist a stranger installs is a loaded weapon pointed at the internet, so some things are simply
not in it, whatever our data says:

- **The DNS root servers**, from the published root hints.
- **TLD and registry nameservers** - the prefixes serving .com, .net, .org, .de, .uk, .jp, .fr, .nl
  and others. This category was *missing* from the first draft of the list, and it was the largest hole in the
  design: the anycast signal we carry is clear for most of them, so a listing on one would have taken a
  whole TLD dark for every device behind a slaving resolver.
- **The major public resolvers** - Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D, AliDNS,
  DNSPod, Yandex, CleanBrowsing, NextDNS and PCH's anycast cloud - because blocking one of those does
  not break a site, it breaks every name your host can look up.
- **NTP**, because no time means DNSSEC validation fails for every name, which takes the house dark one
  remove from anything you would think to look at.
- **CA, ACME, OCSP and CRL endpoints**, because an NXDOMAIN there breaks nothing today and breaks every
  certificate behind your resolver at renewal, ninety days later.
- **RPKI repositories**, because a stalled validator past VRP expiry starts dropping *routes*.
- **RIR and IANA service infrastructure** - the registries this feed's own evidence comes from.
- **Reserved, documentation and special-purpose space**, per RFC 6890 and friends. A listing against
  TEST-NET is a sign the source is wrong, not that the space is dangerous.
- **Our own resolver**, for the same reason as anyone else's. **Not** the address space we hand out to
  agents: exempting that would mean anyone with a free key sat in a range this feed will never flag,
  and a reputation feed exempting its own customers' traffic is not a feed. Our agents are subject to
  it like anybody's.

The full list is [`hold-harmless.txt`](hold-harmless.txt), 248 distinct prefixes, each with the date and method
it was measured - including the registry entries where writing the file from memory got four of
thirteen wrong, which is why every line now cites how it was checked.

Those are refused even when handed the strongest verdict the feed can carry. Verify it yourself -
`make -C core tools` builds the reader and the summary tool, each a single C file with no
dependencies:

```
$ whisper-edge-lookup core/testdata/interop.snap 192.0.2.0 1.1.1.1 8.8.8.8 193.0.14.129 \
    | grep -E '^(address|attr listed|hold-harmless|decision)'
address 192.0.2.0 family=4 canonical=192.0.2.0
attr listed critical plane=reputation range=192.0.2.0-192.0.2.255 record="sev=68" drop=yes evidence=EXAMPLE-DROP-1
hold-harmless yes eligible=yes applies=no range=192.0.2.0-192.0.2.255
decision log would-deny=yes step=sugar rule=0 log=ctx:1 would-deny-rule=ctx:1 would-deny-text="deny if listed >= high"
address 1.1.1.1 family=4 canonical=1.1.1.1
attr listed none plane=reputation
hold-harmless yes eligible=yes applies=no range=1.1.1.1-1.1.1.1
decision allow step=sugar rule=0
address 8.8.8.8 family=4 canonical=8.8.8.8
attr listed none plane=reputation
hold-harmless yes eligible=yes applies=no range=8.8.8.8-8.8.8.8
decision allow step=sugar rule=0
address 193.0.14.129 family=4 canonical=193.0.14.129
attr listed none plane=reputation
hold-harmless yes eligible=yes applies=no range=193.0.0.0-193.0.15.255
decision allow step=sugar rule=0
```

The same binary answers two more questions, the ones the module gates and the cross-server
differential ask of it, each given alone with no address. `--probe-dir DIR` is the data model as
`whisper_edge_data` probes it: one line per plane, in plane order, with the configuration probe's class,
the header's generation, validity and digest (the sixteen hex digits the status file and the
`generations` variable render), owner and mode. Each plane's state is the module's own bind verdict,
from the same check a configuration test runs: the directory walk, mode exactly 0444, an owner of root
or the workers' uid (`--uid` names it; the default is the uid running the tool), no link, and the file
verified. So a plane the module will not map reads `refused`, with the module's reason and fix. A
directory holding only `snapshot.bin` binds no plane and says so with the fix. `--programs FILE` prints the programs a configuration compiles to, through the
same compiler the modules carry, in `--probe-dir`'s environment when both are given: the floor's and each
context's digest, rule count and effective mode, every program's canonical rule text, every report; a
refused line prints the refusal and exits 2. A real capture, from the planes the differential's producer
wrote:

```
$ whisper-edge-lookup --probe-dir planes
data-directory planes
  environment present=0xff schema-ok=0xff (we_policy_env_probe, the modules' configuration environment)
  bind uid=1000 (each state is the module's bind verdict for workers of this uid; --uid names theirs)
  plane reputation       state=present probe=present,schema-ok format=1 schema=yes generation=1 built=1 valid-until=0 digest=3bd8c8458cda0e77 owner=1000 mode=0444 size=526060
  plane tor              state=present probe=present,schema-ok format=2 schema=yes generation=1 built=1 valid-until=0 digest=2fa6e217ffee8a61 owner=1000 mode=0444 size=265229
  ...
$ chmod 644 planes/tor.bin; whisper-edge-lookup --probe-dir planes | grep 'plane tor'
  plane tor              state=refused probe=present,schema-ok why="mode 0644: a mapped plane must be exactly 0444, so no writer but root can change its bytes under the mapping; chmod 0444 the file" owner=1000 mode=0644 size=265229
$ whisper-edge-lookup --programs core/testdata/policy/accept/01-default-policy.policy
env present ff schema_ok ff
floor - rules 0
program http - rules 0 mode 3 allow_inferred 0 (deny)
program http/server:a 7c98881e5da33d35 rules 4 mode 3 allow_inferred 0 (deny)
text 7c98881e5da33d35 1 deny if listed >= critical
text 7c98881e5da33d35 2 deny if listed >= high
text 7c98881e5da33d35 3 log if rpki_unreachable
text 7c98881e5da33d35 4 log if tor_exit
```

That is a real capture, pasted from the run, against the checked-in test fixture, filtered to four
kinds of line (the full output carries every attribute of every plane, its provenance and the cost) -
so you can reproduce it exactly, which you cannot do with a transcript about our live feed. `192.0.2.0` is
documentation space (RFC 5737) and `EXAMPLE-DROP-1` is a synthetic listing id, because a listing is
withdrawn and this file is not, and a prefix printed as listed here would outlive the fact. The one
real address on a public list that this file names is in the dated live captures above, 2.26.75.1,
which was on Spamhaus DROP as SBL698389 on 2026-10-19 when they were taken; check the current list
before reading anything into that address today. Point the tool at `snapshot.bin` from the live feed
and it answers the same way about real addresses.

The tool reads two environment variables, and names each one in a note when it chose a path the run
looked at: `WHISPER_EDGE_DIR`, the directory it reads when given neither `--dir` nor `--snapshot`
(default `/var/lib/whisper-edge`), and `WHISPER_EDGE_ETC`, the directory holding the installed
`policy.conf` (default `/etc/whisper-edge`), looked at on every run because the policy line reports
`installed=`. `whisper-edge-lookup --help` lists them beside every option.

Every plane the tool reads for an address is one the module would map. Before any address is judged,
each plane goes through the module's own bind check, the one `--probe-dir` reports: a plane the module
refuses (a mode other than 0444, an owner other than root or the workers' uid, a link, a directory
that fails the walk) reads `refused:trust` with the module's reason and fix, and the address is judged
without it, as the server judges it. `--uid` names the workers' uid; the default is the uid running the
tool. From the checked-in fixture, `core/testdata/format2/tor.bin` copied into `data`:

```
$ whisper-edge-lookup --dir data 198.51.100.1 | grep -E '^(plane tor|attr tor_exit) '
plane tor id=2 state=fresh file=tor.bin format=2 generation=1791655200 unit=epoch-seconds built=2026-10-10T18:00:00Z valid-until=2096-10-02T07:06:40Z ranges-v4=201 ranges-v6=201 manifest=unbound why=no-manifest
attr tor_exit true plane=tor range=198.51.100.1-198.51.100.1 record="flags=1,source=0,reason=0"
$ chmod 644 data/tor.bin
$ whisper-edge-lookup --dir data 198.51.100.1 | grep -E '^(plane tor|attr tor_exit) '
plane tor id=2 state=refused file=tor.bin manifest=unbound why=refused:trust refused=trust refused-detail="mode 0644: a mapped plane must be exactly 0444, so no writer but root can change its bytes under the mapping; chmod 0444 the file"
attr tor_exit UNKNOWN plane=tor why=refused:trust
```

(This paragraph used to show a hand-written transcript labelled "Real output". It was not: the real
tool prints a header that version omitted, pads the address column wider than it did, and cannot
produce the `evidence: SBL{id} (DROP)` shape at all, because the reader emits the
evidence string verbatim with no parenthesised source.)

## It fails open, always

There is no code path that denies a request on missing or bad data. An absent snapshot allows
everything. A corrupt one is refused at load and the previous one keeps serving. A snapshot past its
own validity window - the bound travels inside the file, so we cannot be left enforcing month-old data
by a config value somebody forgot - stops enforcing and allows everything.

That is checked rather than asserted: `make -C core check` runs 67,989,865 cases, including single-bit
corruptions across a valid snapshot's body - every one refused - and a set of hostile snapshots built
byte by byte with valid digests, because a mutation of a good file cannot express a hostile offset and
that is exactly where the bugs were. Most of the count is one comparison per lookup: the lookup's
recorded memory reads against a model of the structure, for every address that decides an outcome.
The policy language is held the same way: its corpus, every expression of up to three atoms in every
value against a second evaluator, the verifier's refusals one mutation each, and every planted defect in
`core/policy-mutants.sh`, each of which must fail the row that claims to catch it.

## Honest limits

- **A cache in front of the module can serve a page this module never judged.** `mod_cache`'s quick
  handler is on by default and answers from the cache before any access hook runs, so with it left
  on, a URL cached from an unlisted request reaches a listed client with no decision taken. The
  Apache configuration test warns whenever `mod_cache` is loaded together with the floor or any
  rule, and names the fix: `CacheQuickHandler off`. The same holds behind any caching proxy or CDN:
  the module judges the requests that reach it, no more.
- **IPv6 coverage is thin.** 36 IPv6 ranges against 1,027 IPv4 ranges in the build that
  [DATA.md](DATA.md) records, built at 2026-10-14T15:00:00Z. The listings we can cite are
  overwhelmingly IPv4 today. We would rather tell you that than imply parity.
- **We are not a general-purpose blocklist.** This is network-level reputation on announced prefixes.
  It will not catch a compromised host inside a clean network.
- **The DNS half blocks slightly more than the web-server half.** For the strongest entries - the ones
  on Spamhaus DROP - the zone also carries an `rpz-nsip` trigger, which stops a name resolving when its
  *nameserver* lives in that space. The snapshot has no concept of a nameserver address, so the two
  artifacts are the same policy for answer addresses and not for those. It is restricted to DROP, and
  never to a prefix shorter than a /24, because nameserver policy catches every domain delegated into
  the prefix.
- **An RPZ blocks a whole name, not one address.** If a name resolves to several addresses and one is
  listed, the name goes dark for a resolver applying the policy - where the web-server module would
  only have judged the address the connection actually came from. A dual-homed site with one address
  in listed space is the likeliest false-positive complaint on the DNS side.
- **The inference tier is not enforceable by default.** We can infer a verdict from graph structure for
  many prefixes, and every one of those entries is flagged so the module refuses to act on it
  unless you explicitly opt in. We do not think you should.
- **The cost gate's band does not see every regression on the default policy.** Each evaluator slot's
  instructions per request, measured under cachegrind for each architecture and compiler, must stay
  within 10% of its committed figure in `core/gate/cachegrind-baseline.tsv`: for the default policy
  that is 1058.01 on aarch64 and 1261.26 on x86_64, both under gcc 13.3. An evaluator that stopped
  reusing a value it had already fetched adds one refill there, because the default policy reads each
  of its planes once, and stays inside the band by construction, so the gate records that figure and
  does not judge it. The regression is caught on `evaluator-memo`, a policy whose rules read one plane
  for one address, where the same defect refills on every rule and must fall outside the band, and
  by an exact count of the fetches.

## Building the modules
<a id="building-the-modules"></a>

### nginx

```
./nginx/build.sh            # then: sudo ./nginx/build.sh --install
```

It needs a C compiler, make and the headers of every library your nginx's flags compile in; it checks
them first and, if any is missing, prints the one line that installs them (`apt-get install -y ...`,
`dnf install -y ...` or `apk add ...`). `--install` puts the module where `nginx -V`'s `--modules-path`
says, and creates that directory when your distribution's package names it but did not make it
(Ubuntu 24.04's nginx 1.24.0 does this). To upgrade, run it again and restart nginx (`systemctl restart
nginx`): a reload keeps the module nginx already loaded, and `install.sh` says so when the running one is
older.

nginx has no stable module ABI, so a dynamic module must be built against the **same source version
and the same configure flags** as the running binary. The script reads both off the installed
server: it prefers the distro's own sources (`nginx-dev` ships them, and they are by construction
the ones your binary was built from), falls back to fetching the matching tarball from nginx.org
and verifying its detached signature against the release signing keys shipped beside the script
(`nginx-signing-keys.asc`, fingerprints and sources in its header; a tarball that does not verify
is not compiled), and re-uses `nginx -V`'s flags verbatim. Real output here:

```
== nginx 1.24.0 on this host
   sources: /usr/share/nginx/src (the nginx-dev package, version matches) -> /tmp/whisper-edge-ngx.iSsV1K
== configure (this host's own flags, plus --with-compat and the module)
== build the module (objs/Makefile, explicit target)
== built nginx/ngx_http_whisper_edge_module.so (1290664 bytes)
```

It refuses rather than guesses: a source tree whose `NGINX_VERSION` does not match the installed
binary is rejected with both numbers, because a module built against the wrong version compiles
fine and then will not load.

The module builds against the nginx a mainstream enterprise distribution ships, not only the latest:
RHEL 9's nginx 1.20.1 as well as 1.24. nginx 1.23 changed how a response's repeated headers are held,
and the module takes the older form behind nginx's own version macro. The nginx gate builds nginx 1.20.1
and the module from a verified tree and checks that a listed client is denied with its
`Cache-Control: no-store`. On an RPM distribution (RHEL, Rocky, Alma, Fedora), `build.sh` takes the
distribution's own source RPM of the installed package, verified with `rpm -K` against the
distribution's signing key, before trying nginx.org. That is also the only verifiable route for 1.20.1,
whose signing key nginx.org no longer publishes. A source RPM that does not verify is not compiled; if
the key is not imported yet, the script says so and names the `rpm --import` line to run as root.

Two details that used to be the reader's problem and are now the script's. `eval` is load-bearing -
`nginx -V` prints quoted values (`--with-cc-opt='-g -O2 ...'`), so an unquoted split hands
`./configure` a bare `-O2` and it stops with `invalid option "-O2"`. And the target is
`make -f objs/Makefile objs/ngx_http_whisper_edge_module.so`, not `make modules`: this source tree
has no such target, and reaching for the conventional one is how the first version of this script
failed with `No rule to make target 'modules'`.

<details><summary>By hand, if you would rather</summary>

```sh
cp -r /usr/share/nginx/src {build-dir} && cd {build-dir}
ARGS=$(nginx -V 2>&1 | sed -n 's/^configure arguments: //p')
eval "./configure $ARGS --with-compat --add-dynamic-module={edge-checkout}/nginx"
make -f objs/Makefile objs/ngx_http_whisper_edge_module.so
```
</details>

### Apache httpd

```
./apache/build.sh          # then: sudo ./apache/build.sh --install
```

This is the easy one, and it is worth saying why: httpd ships `apxs`, which already knows this
build's include paths, compiler flags and module directory. There is no source tree to match and no
flag archaeology. Real output here:

```
== Apache/2.4.58 (Ubuntu) via apxs
== apxs -c -I../core -Wc,-ffunction-sections -Wc,-Wall -Wc,-Wextra -Wc,-Werror -Wc,-std=gnu11 mod_whisper_edge.c ../core/whisper_edge.c ../core/we_sha256.c ../core/we_counters.c ../core/we_policy.c ../core/we_module.c
== built apache/.libs/mod_whisper_edge.so (1249008 bytes)
```

`--install` uses `apxs -i`, so the module lands in the `LIBEXECDIR` **this** httpd loads from, read
out of the build rather than guessed at `/usr/lib/apache2/modules`. The core is compiled in rather
than linked, so there is nothing of ours to install first and no shared-library versioning to get
wrong.

Restart it with `apachectl graceful`, which tests the configuration first and leaves the running
server alone when the test fails, and never with a raw signal to the parent: `kill -USR1` skips the
test, and httpd then exits on any configuration error, its own as well as this module's.

### OpenLiteSpeed / LiteSpeed

```
./litespeed/build.sh       # then: sudo ./litespeed/build.sh --install
```

```
== sdk  litespeed/sdk/include
== compile
== built litespeed/mod_whisper_edge.so (1207920 bytes)
```

Two things make this one different, and both cost an afternoon if assumed otherwise.

**LiteSpeed is not Apache-module-compatible.** It reads Apache *directives*, which makes it very
easy to assume it loads Apache `.so` modules too. It does not - it has its own module API - so
`litespeed/mod_whisper_edge.c` is a real module and not a copy of the Apache one.

**The LSIAPI header is not vendored here.** OpenLiteSpeed is GPLv3 and this subtree is
MIT, so the script fetches it from a *pinned* release with its digest verified before
anything is unpacked - pinned rather than taken from a branch, because these headers are compiled
into a module that will run inside somebody's production web server. If the installed server has
its own headers, those are used instead and nothing is fetched.

It compiles with `-Werror`, deliberately: this ends up inside a web server, so a warning is a defect
to fix rather than a note to scroll past.

**The installer binds the per-plane directory, and refreshes each plane on its own timer.** The block
`install.sh` writes binds `whisper_edge_data /var/lib/whisper-edge` (`WhisperEdgeData` on Apache), which
reads one file per plane, and it writes and enables `whisper-edge-refresh@<plane>.timer` for each plane
the default policy reads: hourly for reputation, and for the others a period of at most 30 minutes that
the installer derives from the cadence the manifest signs. `whisper_edge_snapshot <file>` binds the single
snapshot file, which carries the reputation plane alone. When your configuration already names a data
source, the installer keeps it and says so in the report. An earlier installer's `whisper-edge-refresh.timer`,
which fetched `snapshot.bin`, is disabled so two fetchers never race for the directory, and the shared undo
line enables it again.

**Write `useIpInProxyHeader 0` at the top level of `httpd_config.conf`, explicitly; the module trusts
only an explicit 0.** LSIAPI hands a module one client address, the one the server reports. Any other
setting, or none, and the module says so at ERROR, and `whisper-edge-summary --status` exits 1 with
`client-ip-from-header`. `install.sh` writes `useIpInProxyHeader 0` into its own included file when your
configuration names none, says so in one line, and refuses to apply over any other value you set. Name
your proxies with `whisper_edge_trusted_proxy` instead, which the module walks itself and no site can
change.

## Getting the snapshot, and keeping it fresh

The feed lives at `https://whisper.online/edge/`. It is keyless; there is nothing to sign up for.
`install.sh` has already set this up: one `whisper-edge-refresh@<plane>.timer` for each plane the
default policy reads, each running `whisper-edge-refresh --plane <name> --quiet`, which fetches that
plane from the signed manifest and installs it as `<name>.bin`. This section is the same by hand, in
case you would rather run it yourself or put it somewhere other than systemd.

```
whisper-edge-refresh --plane reputation              # one plane, as each of the installer's timers runs it
whisper-edge-refresh                                 # the single-file snapshot, for whisper_edge_snapshot
whisper-edge-refresh --zone rpz.whisper.online       # a resolver's policy zone, one run per zone
```

The bare form fetches the snapshot, and this is what it prints:

```
signature verified (551226 bytes)
installed snapshot.bin (generation 497776, 551226 bytes, digest16 398d6cea02c233bc, valid until 2026-10-15T16:00:00Z) - the modules pick it up on their own timer, no reload
```

The line names what it installed the way the modules and the manifest do: the header's generation,
the first 16 hex digits of the file's sha256, and the time its validity ends. Run it again and it says
`snapshot.bin unchanged, already current (generation 497776, ...)` and leaves the file alone, mtime
included - a no-op rewrite would make every module think the policy had moved.

The zone half, on a resolver whose named loads the zone, prints two lines when a feed build moves
the zone's serial: `installed zone <origin> serial <new> (content, <bytes> bytes, signature verified,
checked by named-checkzone), replacing serial <old>`, once the file is verified, checked and renamed
into place, and then `reloaded zone <origin>, serial <new> (named confirms)` once named reports the new
serial loaded. `install/rpz-bind-gate.sh` proves both against a real BIND, in its rows "a changed fetch
reloads that one zone once" and "one timer run once REFRESH has passed: named serves the new serial",
and the install gate fetches the live zone itself in "the zone half verifies the live reputation zone's
signature, checks it and installs it".

`(named confirms)` means `rndc zonestatus` reported the new serial loaded, not that `rndc reload`
exited 0: BIND answers `zone reload up-to-date` and `zone reload queued` with exit 0 while keeping the
old zone, so the exit code proves nothing. If named does not confirm within 30 seconds, or rndc is
missing or refused, the script says which serial named is actually serving, counts the failure in
`rpz.zone.prom` beside the zone (a Prometheus textfile; point a node_exporter textfile collector at
the directory; each zone has its own file, `<file>.prom`, and every series carries `zone="<origin>"`,
for example `whisper_edge_rpz_reload_failures_total{zone="rpz.whisper.online"} 1`, so the zones never
collide), exits 3, and retries the reload on the next run. The zone refresh's exit codes, with the
LSB names systemd prints for them (3 is NOTIMPLEMENTED there, 7 NOTRUNNING, neither meaning that), are
listed in `whisper-edge-rpz@.service`; 5, a zone not published yet, counts as success, but a 404 for a
zone this box has already installed is the zone withdrawn: exit 1, counted as `withdrawn_total`, and
the installed zone keeps serving until its `validUntil`. It reloads that one zone with
`rndc reload rpz.whisper.online`, never the whole server, and never `rndc reconfig`, which does not
re-read a changed file of a zone named already has. It finds the zone's name, its file and its type in
named's own configuration (`named-checkconf -p`), and it never writes a zone named loads as a
secondary.

Four properties, and each one is a mistake somebody has already made by hand:

- **Verify before replace.** The download lands on a `.new` file and only a passing Ed25519 check
  moves it into place. An unverified snapshot never touches the path the server reads.
- **Atomic replace.** `mv` within one directory is a rename, so a worker reading mid-refresh sees
  the old file or the new one, never half of one. Downloading straight onto the live path is the
  commonest way to make a server read a truncated snapshot, which the core then correctly refuses -
  leaving you enforcing nothing and wondering why.
- **Fail without touching anything.** Every failure leaves the installed snapshot exactly where it
  was. A feed we cannot reach must not disarm a policy that is already loaded and working, until that
  policy is past its own validity.
- **Tell each server only what it needs.** None of the three modules needs a reload; each re-reads
  the file on its own timer, and a refresh that bounced the server would turn a routine data update
  into an availability event. named never re-reads a zone file by itself, so the zone half reloads
  that one zone, and only when its serial moved.

The key is fetched **once**, at install. A refresh that re-fetched the key would be verifying the
feed against whatever the feed served, which is a round trip and not a verification.

The timer is hourly with up to fifteen minutes of jitter, so a thousand installations do not all
ask for the same snapshot in the same second. The snapshot carries its own 24-hour validity window,
so a host that misses twenty-three refreshes in a row is still enforcing a policy it is entitled to
enforce: the timer is for freshness, not for correctness.

Each zone has its own instance of one unit and timer, `whisper-edge-rpz@<origin>`
(`whisper-edge-rpz@rpz.whisper.online.timer` and `whisper-edge-rpz@rpz-rpki-unreachable.whisper.online.timer`),
so a failing zone refresh shows up as that instance failing and never stops the planes' refresh or
the other zone. It runs every five minutes and fetches only
when the zone's SOA says it is due (above). The unit is sandboxed like the planes' one, but with no
capabilities at all, so it needs two things spelled out: its one writable path is the zone's directory
under named's own, and it joins named's group, because Debian and Ubuntu ship named's control key as
`bind:bind 0640` and root without capabilities cannot read a file it does not own. `install.sh` fills
in both for your host. `journalctl -u whisper-edge-rpz@rpz.whisper.online.service` shows only what
changed: an install, a reload, an expiry, or a failure.

The zone half makes the snapshot's promise. The body is fetched by name, its signature by hash
(`/edge/zones/<sha256>.zone.sig`) from the address the body came from, so the pair always comes from
one node, and the signature must verify against the key fetched at install before anything else about
the file is believed. Then the header must name the zone, its records must be what the header says,
`named-checkzone` must accept it (mandatory: without `named-checkzone` the zone half refuses to run,
because a broken file keeps the OLD policy loaded with nothing saying so), and the serial must move
forward under RFC 1982 (it wraps at 2^32 and still counts as newer). A fetched zone that is not newer
is left alone, and so is one with the same serial and different bytes.

Before it writes anything, the script asks two sources how named loads the zone: its configuration
(`named-checkconf -p`) and named itself (`rndc zonestatus`). If the configuration cannot be read, for
example because an include is readable by neither root nor named's group, it writes nothing, alarms
on stderr and exits 4. The same happens if named serves the zone from a different file than this one,
so nothing is ever kept current in one place while named enforces a stale copy from another. If named
loads the zone as a secondary, the script leaves it to named. If the zone's nameserver lives inside
the zone, the empty zone keeps its glue so that it still loads.

### Proven, not described

`make install-gate` runs the install gate and ends with a count line, how many rows passed and how many
failed, and a verdict. `INSTALL GATE: CLEAR` means every row ran and passed; `INSTALL GATE:
INCOMPLETE` means everything that ran passed but part of the gate could not run on that host, and the
line before it names what was skipped; `INSTALL GATE: FAILED` means a row failed. The live zone rows run
against the feed's own `/edge/rpz/<origin>.zone`, so on a feed that does not serve a zone yet they are
skipped by name and the gate reads INCOMPLETE, never CLEAR.

<!-- recapture-before-publish: replace this paragraph with what the G1 run on both fresh guests, Ubuntu 24.04 and Rocky Linux 9 Enforcing, shows at the final pin -->
A release's own run of it is taken on two fresh, disposable hosts with nginx, Apache httpd and
OpenLiteSpeed installed and each module built from the tree: Ubuntu 24.04, where the two rows skipped,
by name, are the SELinux arms (the undo record's, and the planes' labels under a confined server),
because SELinux is not enabled there; and Rocky Linux 9 with SELinux Enforcing, where nothing is skipped
and both run.

It runs against the live feed and asserts the two cases that matter: an **unreachable feed** fails
and leaves the installed snapshot byte-identical, and a snapshot whose **signature does not verify**
is refused and never replaces the live one - driven by a stub serving real bytes with a genuine
signature over *different* content, which is the shape of a tampered or truncated download. It also
checks that no partial `.new` file is left behind for a later run to pick up, that every server user
the installer names actually exists on the host, and that the paste block appears for each server
that is really there. Each printed block then goes through its own server's configuration test,
verbatim apart from the module's path: `nginx -t` and `apache2 -t` must accept it. OpenLiteSpeed has
no configuration test, so here its block is checked statically: the block must be named for the
symbol the module exports, `mod_whisper_edge` (the server looks that symbol up in
`modules/{name}.so`, and under any other name it logs "Failed to load module" and starts without
it), and every key must be one the module registers, because the server takes any key without
complaint. The LiteSpeed gate, which runs the server as root, then loads that same printed block and
asserts the module initialises and judges. `make proof` runs it alongside the five module gates.

The zone half is proven against a real BIND (`install/rpz-bind-gate.sh`, which the install gate runs):
the timer's own rendered command fetching a newer serial, named confirming the reload, no reload when
nothing changed, the signature fetched from the node the body came from and nothing installed when it is
missing, empty, over other bytes or the snapshot's own signature served as a zone's, a refresh killed
with SIGKILL half way through a download leaving the zone byte-identical, the zone past its `validUntil`
becoming the fleet's empty zone byte for byte and the name resolving again, a zone fetched already
expired refused, a replayed older zone refused, re-arming on a newer serial, a secondary never written,
and a refused rndc counted. Each of those checks has a control in the same run that must fail it, such
as the timer's OLD command, which leaves named on the old serial, and an `rndc reload` that answers
`up-to-date` with exit 0 and changes nothing. It runs named under `/var/cache/bind` for the same
AppArmor reason the installer puts the zone there. Its last case runs the shipped
`whisper-edge-rpz@.service` itself, one instance per zone, through `systemd-run`, with every sandbox
property applied: once without `SupplementaryGroups`, where rndc cannot read the control key and the
unit fails, and once as shipped, where named loads the new serial. That case needs passwordless sudo
and a host whose PID 1 is systemd; without them the gate reports itself incomplete rather than passing.

### Checking it on your resolver

The gate proves the mechanism on a test BIND. On your own resolver, after one feed build, check:

```
systemctl show whisper-edge-rpz@rpz.whisper.online.service -p Result -p ExecMainStatus   # Result=success, ExecMainStatus=0
journalctl -u whisper-edge-rpz@rpz.whisper.online.service       # installed ... / reloaded ... (named confirms)
rndc zonestatus rpz.whisper.online | grep serial                # the serial in the file
dig +norecurse @127.0.0.1 rpz.whisper.online SOA                # the same serial, served here
dig +tcp @ns1.whisper.online rpz.whisper.online SOA             # and the same serial at the source
```

Then, at least 60 seconds after the reload (BIND applies a reloaded policy only after
`min-update-interval`), query a name that resolves into a listed prefix and see it rewritten, not
only the SOA move. A later run with nothing new shows in `rpz.zone.prom`: `last_ok_seconds` advances
while `reloads_total` stays where it was. `journalctl -k | grep -i 'apparmor.*named'` should print
nothing; a line there means named was refused the file.

Upgrading from an installation whose named.conf still loads the zone from
`/var/lib/whisper-edge/rpz.zone` gives exit 4 and an alarm naming both paths, and the zone is not
written anywhere until the zone statement points at the new file.

What has not been proven outside the gate: RHEL (`/var/named`, the `named` group and SELinux), and a
live expiry on a real resolver. The expiry is proven on the gate's BIND with a zone already past its
`validUntil`, not by a day without the feed.

## With a key: your own tenant plane

Everything above is keyless and stays keyless. A key buys the tenant plane and a faster poll: your
own allow and deny lists, written with `op:policy` under `edge`, delivered to every edge you run as
`tenant.bin`, so `allow if tenant_allow` and `deny if tenant_deny` mean something on your servers. The
module binary is the same file with or without a key; the key only changes which files land in
`/var/lib/whisper-edge`. `routing` stays withheld until its source is complete, whichever tier it sits
on, and it joins the keyed set then.

### Enrolment

If you have the Whisper CLI logged in on the machine, `install.sh` enrols the box by itself: it finds
the CLI's key (`WHISPER_API_KEY`, `WHISPER_KEY`, then `~/.config/whisper/key` of the user who ran
`sudo`, then root's), uses it once to mint a **feed key** for this box, and prints the feed key's id,
what it adds and the one line that undoes it. Without a CLI key it installs keyless and prints the
command that adds one later:

```
sudo whisper-edge-refresh --enroll
```

When the control plane refuses the mint for good (a missing scope, an agent's key, too many feed keys),
it says so with the reason and exits 1: nothing was minted. When the answer is lost or the server
faults, a key may exist that this box never received, so it says `key.list` shows it; revoke any key you
do not use.

Your own key is read once, used from a 0600 header file in the command's own temporary directory that
the command removes, and never kept on the box. The feed key is
`/etc/whisper-edge/key` (root, 0600) with its id in `/etc/whisper-edge/key.id`; it can read the feed
and nothing else, so a web server that leaks it leaks your lists, not your account. It is sent only to
`https://whisper.online`, from a 0600 header file, never on a command line, in the environment or in a
URL; with any other `--base` the keyed run is keyless and says so. A key file that its group or anyone
else can read is refused ("this key may have been read by another user; revoke it with
whisper-edge-refresh --unenroll and enrol again") and the run continues keyless; the timer never
changes its mode, `install.sh` and `--enroll` do. The keyed path needs python3, flock and curl 7.55.0
or later; on a host without them it says so and the keyless planes carry on as before.

`whisper-edge-refresh-keyed.timer` runs `whisper-edge-refresh --quiet --keyed-set` every 15 minutes
with up to 5 minutes of jitter. An edit you make reaches the edge's disk at the first keyed poll after
the feed has published it, plus the module's reload. An edge whose state file (tenant.high-water or
tenant.installed) is malformed applies no revocation and no list change until the file is repaired,
and says so on every run. A web server restarted or reloaded under a state file malformed by the
grammar stops applying the tenant lists until the repair (a well-formed value above the ceiling instead
holds every address denied until the repair and a web server reload).

To return the box to keyless:

```
sudo whisper-edge-refresh --unenroll
```

It revokes the feed key, removes the key file and the tenant plane, and says what that leaves:

```
this box is keyless again: the tenant plane is removed and rules on tenant_allow and tenant_deny read null, as before enrolment
```

### Revocation, and what it leaves behind

`op:edge{sub:'key.revoke'}` revokes a feed key. Edges using it remove the tenant plane once two nodes
have confirmed the revocation (a second node in the same run, or, when no other node answers, a keyed
poll at least 900 s after the first observation): typically within about 8 minutes when the edge can
reach both nodes and about 31 minutes otherwise (an IPv6-only edge, whose second observation waits for
a keyed poll at least 900 s after the first), at most 27 and 62 minutes, plus the module's reload; an
edge whose state file (tenant.high-water or tenant.installed) is malformed applies no revocation and no
list change until the file is repaired, and says so on every run. The figures are derived from the
keyed timer (every 900 s with up to 300 s of jitter, drawn afresh each time), that 900 s floor, the
120 s request ceiling over the three addresses whisper.online has, and the server's 30 s memo, by
`install/revocation-bounds.py`, which the install gate holds this paragraph to. The typical figures
assume every address answers; the maxima are bounds that also cover a run waiting on dead addresses.

Only that revocation removes anything. A key the feed does not recognise (deleted outside `op:edge`, or
an auth-store fault) is an alarm, and the tenant plane is kept and ages out by its own validity: at
most 8 days and then 48 hours of bounded allows. Revoke a key with `key.revoke` to remove it at once.
A key revoked while the feed's stores are unreachable keeps the feed until they are back.

A revocation writes the module's high-water mark, `/etc/whisper-edge/state/tenant.high-water`, and a
tombstone beside the plane. The tenant plane comes back only above the mark: at the next list change,
or by itself within 24 hours 10 minutes plus one keyed poll. `--repin`, which accepts a different
account's plane on this box, carries the mark across for the same reason.

`/etc/whisper-edge/state` holds three files: `tenant.high-water` (the mark), `tenant.installed` (the
generation of the last plane this script installed) and `tenant.plane-id` (that plane's device, inode
and change time, so a plane put back by any restore is never mistaken for this script's install).
Configuration management must leave the directory unmanaged: pruning it loses the mark, after which a
restore of an old plane directory re-arms a revoked plane. The identity record guards a restore of the
plane directory; a rollback of the whole box, `/etc` included, brings back the record with the plane and
is indistinguishable from the install. On a filesystem whose device number can change across a remount
(btrfs subvolumes, ZFS, overlayfs) the record stops matching and the plane reads as restored, which only
makes a hand repair more conservative. The directory itself is read like the CLI's key directory: a
symlink, or a directory another user owns or can write, is refused before any state file in it is read,
and a state file that is not a regular file (a FIFO, say) reads as unreadable, never as a hang.

### When a state file is malformed

Every keyed run reads `tenant.high-water` and `tenant.installed` before it asks the feed for anything,
and refuses both a value that is not one generation and a newline and one above this box's UTC time
plus 86,400 s. It then installs and revokes nothing, fails the unit (`systemctl --failed` shows it every
15 minutes), and logs one sentence per malformed file, from what is on the disk alone. The sentence
leads with this box's UTC time: if that time is right, write the value the sentence names into the
file it names; if the clock is behind, fix it with `timedatectl` and run again, and change nothing.
When the refused `tenant.high-water` held a well-formed value above the ceiling (a flipped bit, or a
large value written to be safe), the module has already taken it as its mark and holds the tenant plane
revoked, so reload the web server after the repair: `nginx -s reload`, then `apachectl graceful`, then `/usr/local/lsws/bin/lswsctrl restart`, whichever of them this box runs. A
value at or above the installed `tenant.bin`'s generation revokes this box's tenant plane, and a
value too low lets a restored plane arm, which is why the sentence names one and why a bigger number
is not safer.

## The directives, for reference

The same fifteen directives on every server. nginx and OpenLiteSpeed spell them as below; Apache takes
each in CamelCase (`WhisperEdgePolicy`) or as written here. "http level" is nginx's `http {}`,
Apache's main server, OpenLiteSpeed's server level: a directive marked so is refused anywhere else,
so that no virtual host can change the floor. These names are held to the three modules' directive
tables by a check, both ways.

| directive | where | arguments | default |
|---|---|---|---|
| `whisper_edge_policy` | any level | one rule: `allow`, `deny` or `log if <expression>` ([POLICY.md](POLICY.md)) | none: the threshold sugar runs |
| `whisper_edge_set` | any level | `@name member...` | none |
| `whisper_edge_policy_floor` | http level | one `deny` or `log` rule every context runs first | none |
| `whisper_edge_mode` | any level | `off`, `log` or `deny` | `log` |
| `whisper_edge_threshold` | any level | `off`, `low`, `medium`, `high` or `critical`: sugar for `deny if listed >= <level>`, refused beside policy lines | `high` |
| `whisper_edge_allow_inferred` | any level | `on` or `off`: act on verdicts with no citable listing behind them | `off` |
| `whisper_edge_deny_status` | any level | the status a deny sends: 400, 403, 404, 406, 409, 410, 413, 415, 422, 428, 429 or 451, and 444 on nginx | 403 |
| `whisper_edge_export` | any level | attribute names, or `all` | the attributes of the planes the rules read |
| `whisper_edge_data` | http level | a directory of `<plane>.bin` files, or `<plane> <file>` | none |
| `whisper_edge_snapshot` | http level | the path to `snapshot.bin` (the reputation plane, the legacy form) | none |
| `whisper_edge_refresh` | http level | the interval between the module thread's ticks: an nginx time value, raised to 1s; whole seconds on Apache, 10 to 86400; whole seconds on OpenLiteSpeed, clamped to 10 to 86400 | 60 seconds |
| `whisper_edge_summary` | http level | a directory for the counter and status files, or `off` | `counters` in the data directory, or beside the snapshot or the bound files |
| `whisper_edge_trusted_proxy` | http level | addresses, CIDR prefixes, `unix:`: the peers whose header the floor reads | none: the TCP peer is judged |
| `whisper_edge_trusted_header` | http level | the header a trusted proxy appends the client to; `Forwarded` is refused | none |
| `whisper_edge_trusted_hops` | http level | judge exactly the Nth entry from the right, 1 to 16 | none: the walk skips trusted entries |

## The tools, for reference

Each tool prints the same with `--help`. These tables are held to the tools' own option parsers and
exit-code statements by a check, so a name here exists in the code and a name in the code is here.

### install.sh

| option | what it does |
|---|---|
| `--dir DIR` | where the planes live (default `/var/lib/whisper-edge`) |
| `--base URL` | the feed (default `https://whisper.online/edge`) |
| `--key-sha256 HEX` | the sha256 of the feed's signing key; needed with any `--base` but the default, whose key is pinned in the script |
| `--server S` | apply to that server only (default: every server found); a comma list is fine |
| `--no-apply` | install the feed and its refresh, and print the blocks to paste instead of applying |
| `--named-conf FILE` | the `named.conf` the resolver half reads (default: the one `named-checkconf` reads) |
| `--no-timer` | schedule nothing |
| `--dry-run` | fetch and verify, say what it would do, and write nothing anywhere (no root needed) |
| `--arm-deny` | OpenLiteSpeed only: turn the installer's policy there from log to deny, after the module has confirmed it in log mode |

When the servers end differently, one code stands for the run, 5 over 1 over 3 over 0, and each
server's own line in the report says how it ended.

| exit | meaning |
|---|---|
| 0 | applied (or your own policy kept) and confirmed by the module, or nothing to change |
| 1 | a server was not applied: refused, stopped, or its configuration failed its own test before any change; its previous configuration is unchanged |
| 2 | usage: an option or a value the script does not take |
| 3 | applied and serving, but the deny is not armed: the module did not confirm it in time, reported the plane refused or unreadable, or a reload did not return |
| 4 | interrupted after writing a server's configuration and before its test passed; the run's writes were taken back |
| 5 | OpenLiteSpeed: restoring its configuration did not bring it back up |

An undo line refuses to run while another installer run holds the lock, and says which run.

| environment | what it changes |
|---|---|
| `WHISPER_EDGE_DIR`, `WHISPER_EDGE_BASE`, `WHISPER_EDGE_KEY_SHA256`, `WHISPER_EDGE_SERVER`, `WHISPER_EDGE_NAMED_CONF` | as the options |
| `WHISPER_EDGE_NO_APPLY=1`, `WHISPER_EDGE_NO_TIMER=1`, `WHISPER_EDGE_DRY_RUN=1`, `WHISPER_EDGE_ARM_DENY=1` | as the options |
| `WHISPER_EDGE_ETC` | the configuration tree (default `/etc/whisper-edge`) |
| `WHISPER_EDGE_SBIN` | where the tools are installed (default `/usr/local/sbin`) |
| `WHISPER_EDGE_UNITDIR` | where the systemd units are written (default `/etc/systemd/system`) |
| `WHISPER_EDGE_LSWS_ROOT` | the OpenLiteSpeed installation (default `/usr/local/lsws`) |
| `WHISPER_EDGE_CMD_TIMEOUT` | seconds each server command the installer runs may take (default 120, at least 60) |

### whisper-edge-refresh

| option | what it does |
|---|---|
| `--dir DIR` | where the planes live (default `/var/lib/whisper-edge`) |
| `--base URL` | the feed (default `https://whisper.online/edge`) |
| `--quiet` | print only what changed, and failures |
| `--plane NAME` | fetch one plane from the signed manifest and install it as `NAME.bin`; `--plane tenant` is `--keyed-set` |
| `--zone ORIGIN` | fetch one policy zone by its origin, check it, install it and reload it in named |
| `--rpz` | the same as `--zone rpz.whisper.online`, when no `--zone` is given |
| `--zone-file PATH` | where the zone lives, or the directory it lives in (default: the file named loads for the zone, else `whisper-edge/<origin>.zone` under named's directory) |
| `--named-conf FILE` | the `named.conf` to read (default: the one `named-checkconf` reads) |
| `--if-due` | fetch the zone only when its SOA REFRESH (RETRY after a failure) has passed; the timer passes this |
| `--enroll` | mint a feed key with your CLI key |
| `--label L` | with `--enroll`: the key's label |
| `--force` | with `--enroll`: mint a new key even when this box holds one |
| `--no-timer` | with `--enroll`: schedule nothing |
| `--keyed-set` | fetch and install your tenant plane, `tenant.bin` |
| `--unenroll` | revoke the feed key; this box is keyless again |
| `--repin` | accept a different account's tenant plane |
| `--key-file F` | the feed key's file (default `/etc/whisper-edge/key`) |

| exit | meaning |
|---|---|
| 0 | a verified artifact is in place: fetched now, or unchanged and already current (a zone: loaded, or not due) |
| 1 | nothing changed, because the fetch or its check failed; whatever was installed is untouched |
| 2 | a usage error or a missing tool |
| 3 | the zone is installed but named did not confirm loading it |
| 4 | named loads this zone from a different file, or the file holds another zone |
| 5 | the origin is one we publish, but its zone is not published yet; nothing is installed, and the unit counts it as success |
| 6 | the origin is not one we publish; refused before any network call |
| 7 | named loads this file under another zone name |

| environment | what it changes |
|---|---|
| `WHISPER_EDGE_BASE`, `WHISPER_EDGE_DIR` | as `--base` and `--dir` |
| `WHISPER_EDGE_KEY_FILE` | as `--key-file` |
| `WHISPER_EDGE_ETC` | the configuration tree (default `/etc/whisper-edge`): the feed key and the keyed tier's state |
| `WHISPER_EDGE_RESOLVE` | `host:port:addr`, pinning every fetch of the run to one address, as curl's resolve option does; a pin naming another host than the feed's is refused |
| `WHISPER_EDGE_RELOAD_WAIT` | seconds to wait for named to confirm the serial it was asked to load (default 30) |
| `WHISPER_EDGE_RNDC` | the `rndc` command, word-split, so a configuration file or a port can ride along |
| `WHISPER_EDGE_SYSTEMCTL` | the `systemctl` command used to schedule the keyed timer |

### whisper-edge-lookup

| option | what it does |
|---|---|
| `--dir DIR` | the data model: the `<plane>.bin` files in `DIR`, as the modules read them |
| `--snapshot FILE` | the legacy model: `FILE` as `whisper_edge_snapshot` reads it (reputation only) |
| `--probe-dir DIR` | with no address: the data model as `whisper_edge_data` probes `DIR`, one line per plane |
| `--programs FILE` | with no address: the programs `FILE`'s directive lines compile to, in `--probe-dir`'s environment or every plane present |
| `--prestage absent\|present` | the legacy model: whether the module has the pre-stage (default `absent`) |
| `--policy FILE\|default\|none` | the policy to evaluate: a file, the shipped default, or no rules (default: the installed `/etc/whisper-edge/policy.conf`, else the threshold sugar) |
| `--threshold L` | the sugar: `off`, `low`, `medium`, `high` or `critical` (default `high`) |
| `--mode log\|deny` | the sugar's mode (default `log`) |
| `--context CTX` | the context whose program runs (default `http`) |
| `--allow-inferred` | the context's `allow_inferred`, when the policy does not set it |
| `--skipped-hop` | the client was reached past a skipped trusted hop: no hold-harmless |
| `--acme` | the request is an ACME HTTP-01 challenge |
| `--now T` | epoch milliseconds or RFC 3339, instead of the clock |
| `--json` | one JSON document instead of lines |
| `--fields` | per plane per address, the plane checker's fields line and its expect line |
| `--uid UID` | with `--probe-dir`: the workers' uid or user name, the owner the module's bind accepts besides root (default: the uid running the tool) |
| `--case` | the evaluated request as a reference-interpreter case block |

| exit | meaning |
|---|---|
| 0 | every address allowed (a log rule, or a deny downgraded by mode `log`, is allowed) |
| 1 | an address denied with enforcement; the old form, when the snapshot is fresh and the threshold denies |
| 2 | a usage error, an unreadable or refused policy, a path that cannot be looked at, an address that is not one, or an internal error |

| environment | what it changes |
|---|---|
| `WHISPER_EDGE_DIR` | the directory read when neither `--dir` nor `--snapshot` is given (default `/var/lib/whisper-edge`) |
| `WHISPER_EDGE_ETC` | the directory holding the installed `policy.conf` (default `/etc/whisper-edge`) |

Stability of the output, within one `lookup format=N`:

1. A kind and its positional fields never change meaning.
2. Keys are only appended to a kind, never renamed, reordered or removed; every key is always
   present in JSON (null when it does not apply), so an appended key has a defined position.
3. A consumer ignores kinds and keys it does not know.
4. A change that breaks 1 or 2 raises `lookup format=N`.
5. The verdict, cost, report and dependents lines are the reference interpreter's own lines.
6. --probe-dir and --programs print their own line forms (data-directory, environment, plane and
   note; env, floor, program, text and refused) and no `lookup format=` line; their columns change
   only with the module gates that read them.

### whisper-edge-summary

| form | what it prints |
|---|---|
| `whisper-edge-summary <counters-dir> [top-n]` | the requests denied and the networks they came from, summed over every worker's counters |
| `whisper-edge-summary --rules <counters-dir>` | per-rule counts, every writer, live or gone |
| `whisper-edge-summary --status <counters-dir>` | plane health |
| `whisper-edge-summary --status <counters-dir> --writer-uid <uid>` | the same, reading only the files that uid owns |
| `whisper-edge-summary --help` | the usage, on stdout |

2 is no answer in every form.

| exit | form | meaning |
|---|---|---|
| 0 | `<counters-dir>` | the summary was printed, an empty one included |
| 2 | `<counters-dir>` | the directory cannot be read |
| 0 | `--rules` | every counter file was read and summed |
| 1 | `--rules` | a counter file was refused, or a configuration file's name is not its digest |
| 2 | `--rules` | the directory cannot be read |
| 0 | `--status` | every live writer is healthy |
| 1 | `--status` | a live writer is not: a flag on its process line, a plane stale, refused, lapsed, revoked, disarmed, stuck loading or behind its refresh, or a configuration refused, unreadable or not named by its digest |
| 2 | `--status` | the directory cannot be read, or no writer is live |
| 0 | `--status --writer-uid` | every live writer is healthy, on the files that uid owns; any other entry is refused by name, never read, and counted under foreign entries |
| 1 | `--status --writer-uid` | a live writer is not healthy, read from the files that uid owns |
| 2 | `--status --writer-uid` | the directory cannot be read, no writer of that uid is live (its status file owned by another uid, open to another uid's write, linked twice or a link), or the uid is neither a number nor a user this host knows |
| 0 | `--help` | always |
| 2 | any other form | the arguments are none of the forms above; the usage goes to stderr |

Any tool killed by a signal exits 128 plus the signal's number, the shell's convention.

## Checking our work

The feed is a claim, so here is how to audit it rather than trust it:

- `/edge/snapshot.json` says what the snapshot contains, including how many prefixes each safety guard
  refused and why, and the worst-case probe count for any address in the space.
- `/edge/rpz/<origin>.zone` is the same policy as a complete, loadable zone file, apex included, so you
  can `named-checkzone` it and read it by hand before trusting anything, and check its signature at
  `/edge/zones/<sha256>.zone.sig` with the two `openssl` lines in [`rpz/README.md`](rpz/README.md).
- `/edge/snapshot.bin.sha256` is the plain `sha256sum` of `snapshot.bin`, in `sha256sum -c` format,
  so you can confirm the snapshot you are running is byte-for-byte the one we published with one
  command. The snapshot ALSO carries a digest in its own header, which is a different function of the
  same file - it covers the file with that field zeroed, because a file cannot contain its own digest -
  and the loader verifies that one before using the file. Between them they catch the failures that
  actually happen to a file: a truncated download, a partial write, a corrupt page.

  To be precise about what that is and is not: a digest is an **integrity** check, not proof of origin.
  Anyone who can rewrite the file can rewrite the digest with it - which is why the loader refuses a
  snapshot that is group- or world-writable, and why you should fetch it as root and write it 0644.

  **Every published snapshot is now anchored in our transparency ledger**, which is the half of this
  that used to say "designed and does not exist". The ledger is append-only, its checkpoints are
  cosigned by independent witnesses, and the anchor is keyless like the rest of the feed:

  ```
  $ curl -s https://whisper.online/edge/snapshot.ledger.json
  {
    "generation": 497650,
    "node": "ns1-ams",
    "sha256": "2fcc426e87499a5a0494044bdd9a6ebbd4a88a8a38d52b23ebad27dfe9004445",
    "entryId": "0873c748cf9bef5c92fe7b036a4fe1bab6db17e89b6930f0268741639101955f",
    "proof": "/inclusion?leaf=0873c748cf9bef5c92fe7b036a4fe1bab6db17e89b6930f0268741639101955f"
  }

  $ curl -s "https://whisper.online/inclusion?leaf=0873c748cf9b...1955f"
  {
      "object": "ledger-inclusion",
      "leaf": 438301,
      "tree_size": 438302,
      "leaf_hash": "05dc8bbb604316f6d09a65ebb2489774fdb742ed47806d15e6e6938a687bb1ea",
      "proof": [
          "a77b7b5c3f2bb46abf45707b0b29a436ccb6be21f217a7bdfb22cd0abf1b7234",
          "766169c6bc76e0a4f047a763529c5172a58a258f079f3f29e7d159210458a053",
          ... seven more ...
      ],
      "checkpoint": "whisper.online/ledger/g2\n438302\n22saILJHhO6r8//wkP5e7xGwmNTZ7UhWP3EfVlNSqoQ=\n\n(two signature lines, elided here)"
  }
  ```

  A real capture, with the audit path and the two base64 signature lines shortened and marked. Fold
  `leaf_hash` up `proof` to the root and compare it with the root in `checkpoint`. The checkpoint is a
  C2SP signed note and it carried **two** signatures when this was taken: ours
  (`whisper.online/ledger/g2`) and an independent witness (`markovianprotocol.com/witness`). The
  second one is the point. A log only we sign is a log we could rewrite; a cosignature from somebody
  who is not us means a rewrite would have to be agreed to by somebody who has no reason to agree.

  The same `entryId` also resolves at `/entries/{entryId}`, which returns the RFC 9942 receipt rather
  than the raw proof. That is what makes "we cannot silently rewrite what we served" a check rather
  than a promise: a snapshot we later changed our mind about is still in the log, and a snapshot that
  is not in the log is not one we published.

  Both nameservers anchor independently, so one build hour normally has two leaves, one per node, and
  they sit next to each other in the same tree. That is deliberate: the log records what each node
  actually served rather than one tidy number that would be wrong for whichever node you fetched
  from.

  The `entryId` is published rather than left for you to derive, because deriving it would mean
  reimplementing our leaf encoding, and a claim that is only checkable by people willing to do that
  is not really checkable.

  **If `snapshot.ledger.json` is a 404, this snapshot is published but not yet anchored**, and that is
  the honest answer rather than a missing feature. The commonest cause is a node that restarted
  minutes ago: the ledger replays its whole tree before it will accept an append, and a blocklist
  update is never held back waiting for it. The next hourly publication carries the anchor.

  **And the snapshot is SIGNED**, which is the piece this paragraph used to say was missing.
  `snapshot.bin.sig` is a detached Ed25519 signature over the whole file, and
  `edge-signing-key.pub` is the key that verifies it:

  ```
  $ curl -fsS https://whisper.online/edge/edge-signing-key.pub -o edge.pub
  $ curl -fsS https://whisper.online/edge/snapshot.bin.sig -o snapshot.bin.sig
  $ openssl pkeyutl -verify -pubin -inkey edge.pub \
        -rawin -in snapshot.bin -sigfile snapshot.bin.sig
  Signature Verified Successfully
  ```

  Fetch the key ONCE and keep it. Fetching it every time only proves that whoever served you the
  snapshot also served you the key, which is not a thing worth proving.

  **And check the key itself, on that first fetch.** That is the one real weakness of any published
  key: trusting it because it arrived. The Ed25519 key above is signed with our RELEASE key, the one
  the Whisper CLI installer verifies every CLI download against, so you can break that circle with
  something you already have:

  ```
  $ curl -fsS https://as219419.net/whisper-release.asc | gpg --import
  $ curl -fsS https://whisper.online/edge/edge-signing-key.pub.asc -o edge.pub.asc
  $ gpg --verify edge.pub.asc edge.pub
  gpg: Good signature from "Whisper Security ... AS219419 <security@whisper.security>"
  ```

  The signature is made offline, because that release key is not on a nameserver and must not be. One
  consequence worth knowing: it covers a FIXED key, so if we ever roll the snapshot signing key the
  nameserver compares the key it holds against the key the attestation covers and **publishes no
  attestation at all** rather than one that vouches for a different key. A missing
  `edge-signing-key.pub.asc` therefore means exactly that, and never that the chain was quietly
  weakened.

  The four checks are not the same check. The digest says the bytes did not get corrupted on the way.
  The transport says they came from whisper.online at the moment you asked. The ledger says we
  published exactly these bytes and have not rewritten that claim since. The signature says the file
  came from the holder of that key - and that one is the only one that still works when the file
  reaches you from somewhere else: a mirror, an internal artifact store, a configuration-management
  checkout, a copy a colleague took last month. For a file this cheap to pass around, that is how it
  will usually reach you.

  **The module does not check the signature, and that is a decision rather than an omission.** The
  threat an in-process check would add cover for is somebody who can write `snapshot.bin` on your
  host; the loader already refuses a group- or world-writable snapshot, so on a correct install that
  somebody has to be root, and a root attacker can replace the module, its configuration or your
  server binary - none of which a signature over the data file would stop. The alternative costs
  either a vendored Ed25519 implementation inside a file we tell you to copy into your build, or a
  libcrypto dependency in a core whose whole build instruction is one command with no dependencies. A
  verification bug in either would be worse than no signature, because this page would claim
  verification. So the check lives where the file arrives, in the recipe above, as one command you
  can read.

  **If `snapshot.bin.sig` is a 404, the snapshot is published and NOT signed**, and like the ledger
  404 above that is an honest state rather than a missing feature. It means one of three things, and
  none of them is tampering:

  - the node you reached has nothing to sign with, so it publishes unsigned rather than not
    publishing. A blocklist is worth more than a signature on it, and we would rather you got the
    data;
  - the node restarted in the last few minutes and has not finished its first publication;
  - the node CAN no longer sign, and has therefore REMOVED a signature it can no longer stand
    behind. That one is deliberate: a signature left beside bytes it does not cover verifies against
    nothing, and "the signature does not match" is exactly what tampering looks like. An absent
    signature is a fact; a stale one is a false alarm you would have no way to tell from a real one.

  So treat a 404 as "no signature available here" and fall back to `snapshot.bin.sha256`, which is
  always published.

  **Fetch the snapshot and its signature on ONE connection.** The public name fronts two nodes. One
  builds the feed and the other copies that node's set, the manifest and every file it names checked
  against the manifest's digests, so in the steady state both serve the same bytes. For the short
  window after a build, before the copy lands, and across a hand-over to the second node when the
  first has stopped building, one node can serve a newer generation than the other, each correctly
  signed. Two separate requests can then land on two nodes and hand you one node's snapshot with the
  other's signature, which fails to verify although nothing is wrong. One invocation with both URLs
  (`curl -o snapshot.bin URL1 -o snapshot.bin.sig URL2`) reuses the connection and gets both from
  one node. `whisper-edge-refresh` does exactly that, and re-fetches the pair once before it
  calls a mismatch an alarm. With that done, what you should NOT do is treat a *failing* signature as
  any of the above: a signature that is present and does not verify means those bytes are not the bytes we signed, and
  that is the one case worth stopping for.
- **The file permissions matter more than people expect.** Whoever can write `snapshot.bin` decides
  whom your site blocks, with nothing anywhere to detect it. Root-owned, mode 0644, replaced by
  rename. The loader enforces the writability half and refuses the file otherwise.
- `core/test_core.c` and the gate scripts are the tests, not a summary of them. `make` builds and
  checks in one command; `make proof` additionally verifies the published formats against the real
  consumers: the reader against a builder-produced snapshot, a real BIND against the policy zone, and
  the module inside a real nginx, a real Apache and a real OpenLiteSpeed.

  Each of those is a separate target, so you can run the one you care about. `make proof` runs them
  in order: the interop gate (the reader against a builder-produced snapshot, IPv4 and IPv6 probes
  both, and the disarmed snapshot), the RPZ gate (a real BIND loading and enforcing both policy zones),
  the nginx, Apache and OpenLiteSpeed gates (each module inside the real server, Apache's under the
  prefork, worker and event MPMs), and the install gate. Each module gate and the install gate print
  a count line, how many assertions held and how many failed, and every gate ends with one verdict
  line that names it: `CLEAR` when everything it asserts held, `FAILED` when anything did not, and
  otherwise a verdict that says what could not be proven on that host (`RPZ GATE: NOT PROVEN IN FULL`,
  `INSTALL GATE: INCOMPLETE`), never a pass.

  **Every number on this page is taken from a run, and the runs are how they get corrected.** A count
  typed into prose goes stale on the edit that adds the assertions it counts, and nothing notices, so
  whenever this README quotes a gate's count line, that gate compares it with its own run and fails
  when they differ.

- **The concurrency is tested, not reasoned about.** `make race` (part of the default `make`) runs the
  snapshot swap and retirement under eight threads at once and asserts that no mapping is ever lost
  and none is ever freed twice. Two of its four checks are decisive and negative-controlled; the other
  two are stress, and the file says which is which rather than letting a reader assume all four are
  proof. Its own output:

  ```
  $ make race
  0. the accounting invariant, 10 publications, nothing reclaimed
    ok: 10 published, 4 in slots, 5 leaked, 1 current, none lost
  1. the retire-slot CLAIM, 8 threads publishing distinct generations
    ok: 200 rounds, every published mapping accounted for
  2. the slot RECLAIM, 8 threads retiring the same mapping
    ok: 200 rounds, exactly one reclaim per mapping and no double free
  3. readers, publishers and retirers together on one handle
    ok: 906975471 lookups against 33 publications with retirement running
  race_core: CLEAR
  ```
