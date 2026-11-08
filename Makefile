# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# The edge subtree. `make` builds the core, runs its suite, and checks the hot path. `make proof`
# additionally verifies the published formats against the real consumers: the reader against a
# builder-produced snapshot, and a real BIND against the generated policy zone.
#
# The split is deliberate, and `proof` FAILS rather than skips when a fixture or a tool is absent, so a
# green `make` is never mistaken for a green `make proof`.

.PHONY: all proof core interop rpz rpz-concurrency rpz-live nginx apache litespeed litespeed-sdk install-gate clean

# The servers live in sbin (named, nginx, apache2 and httpd in /usr/sbin), which Debian leaves off an
# unprivileged user's PATH, so a gate run there by anyone but root found no nginx and no named. The sbin
# directories go on the END of the PATH, so whatever the caller's own PATH finds first still wins.
export PATH := $(PATH):/usr/local/sbin:/usr/sbin:/sbin

all: core

core:
	$(MAKE) -C core

# Format agreement: a snapshot the real builder produced, read by the real reader.
interop:
	./core/interop-gate.sh

# The RPZ half, through a real BIND: every policy zone's fixture (rpz/testdata), one at a time. Needs
# named and a C compiler; the nameserver-address trigger needs passwordless sudo for a network namespace,
# and without it the gate exits 77 rather than claim it. See rpz/README.md.
rpz:
	./rpz/rpz-gate.sh

# The control for two overlapping runs: both must finish CLEAR and leave no named behind.
rpz-concurrency:
	./rpz/rpz-gate-concurrency.sh

# The same gate against a zone from a live build rather than the checked-in fixture:
#   make rpz-live ZONE=/path/to/zone PROBES=/path/to/probes.txt PLANE=/path/to/plane.bin [ORIGIN=rpz.whisper.online]
#
# The probe file format is one line per check: <label> <type> <address> <block|allow> <description>.
# Every "block" line is additionally re-queried with the policy REMOVED, because an answer that never
# resolved in the first place proves nothing. PLANE is the plane the zone was written from, for the
# breakpoint oracle; without it the run says the oracle was not run and exits 77.
ORIGIN ?= rpz.whisper.online
rpz-live:
	RPZ_BODY="$(ZONE)" RPZ_PROBES="$(PROBES)" RPZ_PLANE="$(PLANE)" ./rpz/rpz-gate.sh --zone "$(ORIGIN)"

# The module inside a real nginx. Needs a built .so; see the message the gate prints if it cannot
# find one. This is the gate that would have caught the non-cancelable refresh timer - the defect that
# makes `nginx -s reload` hang forever - on its first run, and it did catch it when negative-controlled.
nginx:
	./nginx/nginx-gate.sh

# The module inside a real Apache, under EVERY MPM the host has. The threaded MPMs (worker, event)
# are the reason the core's retire-slot lifecycle had to be made thread-safe; a run that only
# exercised prefork would certify the one configuration that was never at risk, so the gate says
# which MPMs it ran and fails if it only got prefork.
apache:
	./apache/apache-gate.sh

# The module inside a real OpenLiteSpeed. Needs the LSIAPI header; it is NOT vendored here, because
# OpenLiteSpeed is GPLv3 and this subtree is MIT. With OpenLiteSpeed installed and no header anywhere
# the gate looks (LS_SDK, litespeed/sdk/include, the server's own include/), the pinned SDK is fetched
# first, digest verified, exactly as `make litespeed-sdk` does; if that cannot run, the gate says what
# it needs. Without OpenLiteSpeed nothing is fetched and the gate says that instead.
LSWS ?= /usr/local/lsws
litespeed:
	@if [ -z "$${LS_SDK:-}" ] && [ -x "$(LSWS)/bin/lswsctrl" ] && [ ! -f litespeed/sdk/include/ls.h ] \
	    && [ ! -f "$(LSWS)/include/ls.h" ]; then \
	  echo "litespeed: no LSIAPI header here; fetching the pinned SDK ($(LS_TAG))"; \
	  $(MAKE) --no-print-directory litespeed-sdk || echo "litespeed: the pinned SDK could not be fetched; the gate says what it needs"; \
	fi
	./litespeed/litespeed-gate.sh

# The LSIAPI header, from a PINNED OpenLiteSpeed release, digest VERIFIED before anything is unpacked.
# Not vendored, because OpenLiteSpeed is GPLv3 and this subtree is MIT; pinned rather than
# taken from a branch, because these headers are compiled into a module that runs inside somebody's
# production web server, so upstream drift or an upstream compromise would silently change the build.
LS_TAG    = v1.9.3
LS_DIR    = openlitespeed-1.9.3
LS_SHA256 = cc533f370298e0b8b3a0e9bed11a0ffedd5731624664c2d5091967c4114f98ca

litespeed-sdk:
	@set -e; \
	t=$$(mktemp -d); \
	trap 'rm -rf "$$t"' EXIT; \
	curl -fsSLo "$$t/ols.tar.gz" \
	  "https://github.com/litespeedtech/openlitespeed/archive/refs/tags/$(LS_TAG).tar.gz"; \
	echo "$(LS_SHA256)  $$t/ols.tar.gz" | sha256sum -c -; \
	mkdir -p litespeed/sdk; \
	tar xz --strip-components=1 -C litespeed/sdk -f "$$t/ols.tar.gz" "$(LS_DIR)/include"; \
	echo "LSIAPI headers from $(LS_TAG) are in litespeed/sdk/include"


# The DELIVERY path, against the live feed: the refresh script verifies before it replaces,
# replaces atomically, and fails without touching anything. An installer nobody has run is a
# document rather than a deliverable, so it gets a gate like every module here. Needs no root and
# writes only inside its own temp directory.
install-gate:
	./install/install-gate.sh

# Every gate runs, whatever an earlier one said, and the run ends with each gate's own verdict line: a
# host that cannot run one row of one gate still gets the other gates' verdicts, and a gate that did
# not pass is named with the reason it gave (FAILED, or what this host could not prove), never hidden
# behind the first stop. The exit status is 0 only when every gate passed.
PROOF_GATES = interop rpz nginx apache litespeed install-gate
proof:
	@t=$$(mktemp -d); trap 'rm -rf "$$t"' EXIT; failed=""; \
	for g in $(PROOF_GATES); do \
	  { $(MAKE) --no-print-directory $$g; echo $$? > "$$t/rc"; } 2>&1 | tee "$$t/log"; \
	  rc=$$(cat "$$t/rc"); v=$$(grep -E '^[A-Z]+ GATE: ' "$$t/log" | tail -1 | cut -c1-160); \
	  printf '  %-13s %s\n' "$$g" "$${v:-exit $$rc, and no verdict line}" >> "$$t/verdicts"; \
	  [ "$$rc" = 0 ] || failed="$$failed $$g"; \
	done; \
	echo; echo "== make proof: each gate's verdict"; cat "$$t/verdicts"; \
	if [ -n "$$failed" ]; then echo "make proof: did not pass:$$failed"; exit 1; fi; \
	echo "make proof: every gate CLEAR"

clean:
	$(MAKE) -C core clean
	rm -rf core/.testtmp

# The development tree's own targets (the page's build-time numbers and the documentation gate) live in
# development.mk, which is left out of the published tree on purpose: they read records and sources that
# exist only where the tree is maintained. A standalone copy has no such file, so nothing here names or
# invokes anything it does not ship.
-include development.mk
