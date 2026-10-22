# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# whisper edge core. No dependencies, no configure step, one command.
#
# The default target BUILDS AND PROVES: it compiles the core, runs the acceptance suite (the
# correctness and chaos criteria) and runs the hot-path gate (its zero-allocation criterion). There is
# no way to "build" without checking, because a reputation feed that silently stops meeting its
# latency or fail-open guarantees is worse than one that does not build.
#
# `make tools` builds the two operator binaries. whisper-edge-lookup is the diagnostic for "your feed
# broke my site, what does it say about this address?". whisper-edge-summary is the weekly report
# somebody pastes into a chat: how many requests denied, from how many networks, and the worst few
# with their evidence. Both are part of the default target, because a blocklist that cannot explain
# itself is one nobody keeps installed - and the lookup tool had no build rule at all until somebody
# checked, while the README told people to run it.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Werror
TMPDIR_ ?= $(CURDIR)/.testtmp

CORE_SRC = whisper_edge.c we_sha256.c we_counters.c
CORE_HDR = whisper_edge.h we_sha256.h we_country_table.h we_procid.h

# The policy language: the compiler and verifier (cold) and the evaluator (we_eval.h, header-only,
# force-inlined into whatever calls we_decide). The hold-harmless table is generated from
# ../hold-harmless.txt and committed, so a build needs no Python.
POLICY_SRC = we_policy.c
# Whether the compiler and its test are in this tree. Defined here, ahead of every rule that names them
# as prerequisites: make expands a rule's prerequisite list when it reads the rule, so a variable
# defined below one reads as empty there, and check-policy would run a harness it never built.
WE_POLICY_C = $(wildcard we_policy.c)
POLICY_C    = $(wildcard test_policy.c)
POLICY_HDR = we_policy.h we_eval.h we_hold_harmless.h

.PHONY: all check check-policy check-lookup gen-lookup-guard lookup-headers fuzz fuzz-replay fuzz-planes check-py dump-full-san check-rpz-oracle check-live fixtures race bench gate interop tools clean lib country-table hold-harmless policy-mutants check-module-fuzz check-module-twin
all: check check-py race gate tools

lib: libwhisperedge.a

libwhisperedge.a: $(CORE_SRC:.c=.o)
	$(AR) rcs $@ $^

%.o: %.c $(CORE_HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

TEST_SRC = we_writer.c
TEST_HDR = we_writer.h

test_core: test_core.c $(TEST_SRC) $(CORE_SRC) $(CORE_HDR) $(TEST_HDR) we_map_fields.h
	$(CC) $(CFLAGS) -DWE_COUNT_DIGEST -o $@ test_core.c $(TEST_SRC) $(CORE_SRC)

# The deterministic bound tests (FORMAT.md §7): the SAME lookup source with WE_TRACE_READ recording
# every load, compared per lookup with a data-free model. test_mutant is that build with a window one
# entry longer, and it must fail the comparison; it exits non-zero if it does not.
test_trace: test_trace.c $(TEST_SRC) $(CORE_SRC) $(CORE_HDR) $(TEST_HDR)
	$(CC) $(CFLAGS) -DWE_TRACE -o $@ test_trace.c $(TEST_SRC) $(CORE_SRC)

test_mutant: test_trace.c $(TEST_SRC) $(CORE_SRC) $(CORE_HDR) $(TEST_HDR)
	$(CC) $(CFLAGS) -DWE_TRACE -DWE_TEST_WINDOW_SLACK=1u -o $@ test_trace.c $(TEST_SRC) $(CORE_SRC)

# The policy language held to POLICY.md row by row (§9; test_policy.c says which). A WE_TRACE build: the
# evaluator's cost counters and the coverage taps exist only there. `--cases FILE` is the C side of the
# differential against policy_ref.py, and `--c-only DIR` runs the seeds only this harness can build.
test_policy: test_policy.c $(TEST_SRC) $(CORE_SRC) $(POLICY_SRC) $(CORE_HDR) $(POLICY_HDR) $(TEST_HDR)
	$(CC) $(CFLAGS) -DWE_TRACE -o $@ test_policy.c $(TEST_SRC) $(CORE_SRC) $(POLICY_SRC)

# The modules' shared half (we_module.h, we_module.c) against the core and POLICY.md's rendering
# section: the decision against we_decide() and an independent recount of its counters, the walk, the
# grammar of one entry, the formatter, ACME, the request path's renderer against the tools', the
# record. It reads the eight fixture planes fuzz-planes writes.
MODULE_SRC = we_module.c
MODULE_HDR = we_module.h walk_classes.h

# test_module writes the planes its lifecycle rows arm with the core's own writer (we_writer.c)
test_module: test_module.c $(MODULE_SRC) $(CORE_SRC) $(POLICY_SRC) $(CORE_HDR) $(POLICY_HDR) $(MODULE_HDR) we_writer.c we_writer.h
	$(CC) $(CFLAGS) -DWE_MOD_DEBUG -o $@ test_module.c $(MODULE_SRC) $(CORE_SRC) $(POLICY_SRC) we_writer.c

# The summary's readers on planted directories: a refused file contributes nothing. Its control,
# WE_SUM_TEST_EAGER_SUM, sums each line as it is read, and `check` requires the rows to fail under it.
# --status --writer-uid reads only the writer's own files; WE_MOD_TEST_WRITER_UID_UNCHECKED skips the
# owner, link and mode check and WE_MOD_TEST_STATUS_FOLLOWS opens entries without O_NOFOLLOW, and
# `check` requires each to fail the rows it plants for.
# The usage text's exit table and the codes each form returns agree; its control, WE_SUM_TEST_EXIT_DRIFT,
# changes one code and not the table, and `check` requires the row to name both halves. A writer that
# named no pid namespace (pidns 0, a confined worker denied the stat) is placed by the reader itself: the
# rows run again with the namespace stat refused (WE_SUM_TEST_NS_STAT_DENIED, the NSpid fallback), and the
# control WE_SUM_TEST_PIDNS_TRUSTED, the writer's 0 taken as this namespace, must fail the other-namespace row.
# The fallback is sound only on the reader's own namespace's procfs: the procfs row runs the stat-refused
# build in a pid namespace below its procfs's (unshare -p --fork, no --mount-proc), where a pidns-0 writer
# must be refused, and its control WE_SUM_TEST_NO_PROCFS_CHECK must read it live.
test_summary: test_summary.c we_summary_cli.c we_summary_read.h we_sha256.c we_sha256.h
	$(CC) $(CFLAGS) -o $@ test_summary.c we_sha256.c

# Every defect POLICY.md §5.4 names, planted by a -D build of test_policy, each of which must fail
# the row that claims to catch it (policy-mutants.sh). Part of `check`.
policy-mutants: test_policy
	@mkdir -p $(TMPDIR_)
	@./policy-mutants.sh $(TMPDIR_) $(CC) $(CFLAGS)

# bench_core's record is keyed by the commit and the flags it was built with. A vendored copy has no
# git, so its commit reads "unknown", which the record says rather than hides. The policy table needs
# the policy compiler and is reported DARK until we_eval.h is in the tree.
#
# Recursive (=), so git runs only when bench_core is built, never on every make; and only when this
# directory is core of its own repository, at a prefix this tree names as its own (core/ standing alone;
# a tree that carries this one elsewhere adds its prefix to WE_COMMIT_PREFIXES in development.mk), because
# a copy vendored into somebody else's tree would otherwise record the HOST repository's commit as ours.
# -dirty covers this directory's own files.
WE_COMMIT_PREFIXES ?= core/
WE_COMMIT = $(if $(filter $(WE_COMMIT_PREFIXES),$(shell git rev-parse --show-prefix 2>/dev/null)),$(shell git rev-parse HEAD)$(if $(shell git status --porcelain -- . 2>/dev/null),-dirty,),unknown)
BENCH_EVAL := $(if $(wildcard we_eval.h),-DWE_HAVE_EVAL -I. we_policy.c,)

# The commit is compiled in. The stamp under $(TMPDIR_) changes when the tree's commit does, so make
# bench rebuilds the binary for a new commit; a binary run from elsewhere still carries its own, and
# check-record.py refuses it against the tree's by name.
$(TMPDIR_)/bench-commit: FORCE
	@mkdir -p $(TMPDIR_)
	@echo '$(WE_COMMIT)' | cmp -s - $@ || echo '$(WE_COMMIT)' > $@
.PHONY: FORCE
FORCE:

bench_core: bench_core.c gate/eval_programs.h $(TEST_SRC) $(CORE_SRC) $(CORE_HDR) $(TEST_HDR) $(TMPDIR_)/bench-commit
	$(CC) $(CFLAGS) -DWE_BENCH_COMMIT='"$(WE_COMMIT)"' -DWE_BENCH_FLAGS='"$(CFLAGS)"' -o $@ bench_core.c \
	  $(BENCH_EVAL) $(TEST_SRC) $(CORE_SRC)

# The operator diagnostic: every attribute of an address with its plane and provenance, and the decision
# the policy evaluator makes, through the compiler and evaluator the modules use. It is a TRACE build
# (-DWE_TRACE: the evaluator keeps its cost counters, the read hooks are no-ops), so the hot-path gates,
# which are about the module's build, do not describe it. -DWE_LOOKUP_TOOL turns on its hashed-bytes
# count in we_sha256.c. It links the modules' shared half too, so --probe-dir's verdict on each plane is
# we_mod_bind_check()'s, the bind's own checks, never a copy of their rules.
#
# The mutant guard, enforced twice. This rule refuses any WE_TEST_* or WE_LOOKUP_TEST_* name, with or
# without -D, in $(CC), CFLAGS or CPPFLAGS, unless WE_LOOKUP_MUTANT_BUILD is set; and we_lookup_guard.h
# holds an #error per mutant name found in the tool's inputs, regenerated and compared by check-lookup,
# for a definition that arrives some other way. The shipped tool is never a mutant.
LOOKUP_HDR    = we_lookup_guard.h we_record_fields.h we_plane_tier.h we_hold_harmless_cite.h we_default_policy.h
LOOKUP_DEPS   = we_lookup_cli.c $(LOOKUP_HDR) $(CORE_SRC) $(CORE_HDR) $(POLICY_SRC) $(POLICY_HDR) $(MODULE_SRC) $(MODULE_HDR)
# The modules' half linked in brings its own namespace: any WE_MOD_ define (its controls, the control
# build, the debug build) is refused for the shipped tool too
LOOKUP_BAD    = $(filter -DWE_TEST_% -DWE_LOOKUP_TEST_% -DWE_MOD_% WE_TEST_% WE_LOOKUP_TEST_% WE_MOD_%,$(CC) $(CFLAGS) $(CPPFLAGS))
LOOKUP_GUARD_INPUTS = we_lookup_cli.c we_record_fields.h we_plane_tier.h we_hold_harmless_cite.h \
                      we_default_policy.h $(CORE_SRC) $(CORE_HDR) $(POLICY_SRC) $(POLICY_HDR) $(MODULE_SRC) $(MODULE_HDR)

whisper-edge-lookup: $(LOOKUP_DEPS)
	$(if $(and $(LOOKUP_BAD),$(if $(WE_LOOKUP_MUTANT_BUILD),,x)),$(error refusing to build the shipped whisper-edge-lookup with $(LOOKUP_BAD)))
	$(CC) $(CFLAGS) $(CPPFLAGS) -DWE_TRACE -DWE_LOOKUP_TOOL -o $@ we_lookup_cli.c $(CORE_SRC) $(POLICY_SRC) $(MODULE_SRC)

# The three generated headers the tool compiles in. Committed, so a build needs no Python; check-lookup
# regenerates each and fails when the committed copy differs. we_plane_tier.h is maintained by hand and
# checked for self-consistency here and against its sources by the builder's own tier-table test.
gen-lookup-guard:
	python3 gen-lookup-headers.py guard $(LOOKUP_GUARD_INPUTS) > we_lookup_guard.h

# The list's distinct-prefix count is published in ../REFERENCE.md; the generator holds the list to it. A
# vendored copy of the core has no README, and then only the list itself is read.
HH_PUBLISHED = $(if $(wildcard ../REFERENCE.md),--published ../REFERENCE.md)

lookup-headers:
	python3 gen-lookup-headers.py cite ../hold-harmless.txt $(HH_PUBLISHED) > we_hold_harmless_cite.h
	python3 gen-lookup-headers.py default-policy testdata/policy/default.conf > we_default_policy.h

# THE LOOKUP TOOL'S GATE (lookup-gate.sh). One line, `N checks, F failures, I invocations, C cases,
# M mutant compiles`, which `check` adds to the published case count. Before the gate: the generated
# headers regenerate to their committed bytes, the tier table is eight rows in plane-id order, and the
# build refuses a mutant name in both spellings.
LOOKUP_DIR = $(TMPDIR_)/lookup

check-lookup: whisper-edge-lookup
	@command -v python3 >/dev/null 2>&1 || { echo "CHECK FAIL: check-lookup needs python3; a missing interpreter is a failure, not a skip"; exit 1; }
	@rm -rf $(LOOKUP_DIR) && mkdir -p $(LOOKUP_DIR)/b1
	@set -e; out=$(LOOKUP_DIR)/check-lookup.out; n=0; f=0; \
	chk() { n=$$((n + 1)); if eval "$$2" >/dev/null 2>&1; then :; else f=$$((f + 1)); echo "CHECK FAIL: $$1"; fi; }; \
	tiers() { sed -n 's/^    { \([1-8]\), "[a-z-]*", "\(keyless\|keyed\)" },$$/\1/p' "$$1" | tr -d '\n'; }; \
	python3 gen-lookup-headers.py guard $(LOOKUP_GUARD_INPUTS) > $(LOOKUP_DIR)/guard.h; \
	python3 gen-lookup-headers.py cite ../hold-harmless.txt $(HH_PUBLISHED) > $(LOOKUP_DIR)/cite.h; \
	python3 gen-lookup-headers.py default-policy testdata/policy/default.conf > $(LOOKUP_DIR)/default.h; \
	chk "B1: we_lookup_guard.h is the regenerated guard (make gen-lookup-guard)" "cmp -s we_lookup_guard.h $(LOOKUP_DIR)/guard.h"; \
	chk "H2: we_hold_harmless_cite.h is regenerated from ../hold-harmless.txt (make lookup-headers)" "cmp -s we_hold_harmless_cite.h $(LOOKUP_DIR)/cite.h"; \
	chk "H2: REFERENCE.md publishes a distinct-prefix count for the list" "[ -z '$(HH_PUBLISHED)' ] || grep -qE '[0-9]+ distinct prefixes' ../REFERENCE.md"; \
	printf 'The full list holds 1 distinct prefixes.\n' > $(LOOKUP_DIR)/b1/readme-wrong.md; \
	chk "H2 control: a published count the list does not hold stops the generator" "! python3 gen-lookup-headers.py cite ../hold-harmless.txt --published $(LOOKUP_DIR)/b1/readme-wrong.md"; \
	chk "P3: we_default_policy.h is testdata/policy/default.conf (make lookup-headers)" "cmp -s we_default_policy.h $(LOOKUP_DIR)/default.h"; \
	chk "the tier table: eight rows, ids 1 to 8 in order, each keyless or keyed" "[ \"\$$(tiers we_plane_tier.h)\" = 12345678 ]"; \
	sed 's/{ 1, "reputation"/{ 2, "reputation"/; s/{ 2, "tor"/{ 1, "tor"/' we_plane_tier.h > $(LOOKUP_DIR)/tier-swapped.h; \
	chk "control: the tier check fails two rows with their ids swapped" "[ \"\$$(tiers $(LOOKUP_DIR)/tier-swapped.h)\" != 12345678 ]"; \
	chk "B1: the same preprocess with no mutant name succeeds" "$(CC) -E -DWE_LOOKUP_TOOL -DWE_TRACE -o /dev/null we_lookup_cli.c"; \
	for name in $$(grep -ohE '\bWE_(LOOKUP_)?TEST_[A-Z0-9_]+' $(LOOKUP_GUARD_INPUTS) | sort -u); do \
	  chk "B1: the shipped tool refuses to compile with $$name, by the guard's own error" "$(CC) -E -DWE_LOOKUP_TOOL -DWE_TRACE -D$$name -o /dev/null we_lookup_cli.c 2>&1 | grep -q '$$name is a test mutant; the shipped whisper-edge-lookup is never built with one'"; \
	done; \
	awk '/defined\(WE_LOOKUP_TEST_JR_CESU\)/ { skip = 3 } skip { skip--; next } { print }' $(LOOKUP_DIR)/guard.h > $(LOOKUP_DIR)/b1/dropped.h; \
	chk "B1 control: a guard with one name dropped lets that name through" "$(CC) -E -DWE_LOOKUP_TOOL -DWE_TRACE -DWE_LOOKUP_TEST_JR_CESU -o /dev/null $(LOOKUP_DIR)/b1/dropped.h"; \
	printf '#ifdef WE_TEST_B1_CONTROL\n#endif\n' > $(LOOKUP_DIR)/b1/new.c; \
	python3 gen-lookup-headers.py guard $(LOOKUP_GUARD_INPUTS) $(LOOKUP_DIR)/b1/new.c > $(LOOKUP_DIR)/b1/guard-new.h; \
	chk "B1 control: a new mutant name without regeneration fails the guard comparison" "! cmp -s we_lookup_guard.h $(LOOKUP_DIR)/b1/guard-new.h"; \
	chk "B1: the build refuses CFLAGS=\"-D WE_TEST_X\"" "! $(MAKE) -s -n -B whisper-edge-lookup CFLAGS='-std=c11 -D WE_TEST_X'"; \
	chk "B1: the build refuses CC=\"cc -DWE_TEST_X\"" "! $(MAKE) -s -n -B whisper-edge-lookup CC='$(CC) -DWE_TEST_X'"; \
	chk "B1: the build admits a mutant only with WE_LOOKUP_MUTANT_BUILD" "$(MAKE) -s -n -B whisper-edge-lookup CC='$(CC) -DWE_TEST_X' WE_LOOKUP_MUTANT_BUILD=1"; \
	chk "B1 control: a filter matching only -D words misses the spaced spelling" "[ -z \"\$$(printf '%s\n' -std=c11 -D WE_TEST_X | grep -E '^-DWE_TEST_')\" ]"; \
	echo "$$n checks, $$f failures" > $$out; cat $$out; [ $$f -eq 0 ]
	@if ./lookup-gate.sh $(LOOKUP_DIR)/gate > $(LOOKUP_DIR)/gate.out 2>&1; then rc=0; else rc=$$?; fi; \
	sed -n '/^FAIL\|^DARK\|^  mutant phase\|checks, .* failures/p' $(LOOKUP_DIR)/gate.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: lookup-gate.sh exited $$rc"; exit 1; fi; \
	tail -1 $(LOOKUP_DIR)/gate.out >> $(LOOKUP_DIR)/check-lookup.out

# The weekly summary. It reads the counter files the module writes and the module's own evidence
# strings; it needs no snapshot and no core, which is why it links nothing.
whisper-edge-summary: we_summary_cli.c we_summary_read.h we_sha256.c we_sha256.h
	$(CC) $(CFLAGS) -o $@ we_summary_cli.c we_sha256.c

tools: whisper-edge-lookup whisper-edge-summary

# The ISO 3166-1 known-code bitmap the reader compiles in (FORMAT.md 3.1). Generated and committed, so
# a build needs no Python; regenerate it here when the iso-codes list moves, never by hand.
country-table:
	python3 gen-country-table.py > we_country_table.h

# The hold-harmless table every floor block carries (POLICY.md §3.8), from ../hold-harmless.txt.
# Generated and committed like the country table; regenerate it here when that list moves.
hold-harmless:
	python3 gen-hold-harmless.py ../hold-harmless.txt > we_hold_harmless.h

#
# `check` also makes the README's published case count AGREE WITH THIS RUN.
#
# That number was wrong for exactly one commit: the commit that added the cases it counts. A count
# typed into prose goes stale on the edit that changes it and nothing notices, so the comparison is
# part of the build rather than a thing to remember. The guard is skipped - not failed - when the
# README is absent, because the core is meant to be COPIED into somebody else's build and a vendored
# copy has no page to check against.
#
# The count is the SUM over every `N [mutant ]checks, F failures` line the run prints: one per C
# binary, and one per leg of check-policy below. The case count a README states is the count `check`
# runs, not one binary's share of it, so a leg that adds cases moves the published number in the same
# commit.
#
# EACH BINARY'S EXIT STATUS IS CHECKED. This rule used to run `./test_core ... | tee check.out`, and
# a pipeline's status is its last command's, so a run with failures, or one that died of a signal
# before printing its summary, passed `make check` whenever the README's count still matched. The
# output now goes to a file and the status is read from the binary itself.
#
check: test_core test_trace test_mutant test_policy test_module test_summary check-policy check-lookup fuzz-planes fuzz_walk_replay fuzz_summary_replay
	@mkdir -p $(TMPDIR_)
	@: > $(TMPDIR_)/check.out
	@set -e; for t in test_core test_trace test_mutant test_policy test_module test_summary; do \
	  if ./$$t $(TMPDIR_) > $(TMPDIR_)/$$t.out 2>&1; then rc=0; else rc=$$?; fi; \
	  cat $(TMPDIR_)/$$t.out; cat $(TMPDIR_)/$$t.out >> $(TMPDIR_)/check.out; \
	  if [ $$rc -ne 0 ]; then echo "CHECK FAIL: $$t exited $$rc"; exit 1; fi; \
	done
	@cat $(TMPDIR_)/policy/check-policy.out >> $(TMPDIR_)/check.out
	@cat $(LOOKUP_DIR)/check-lookup.out >> $(TMPDIR_)/check.out
	@set -e; \
	if python3 gen-abi-layout.py --check > $(TMPDIR_)/abi-layout.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/abi-layout.out; grep -E '^[0-9]+ checks, ' $(TMPDIR_)/abi-layout.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: gen-abi-layout.py --check exited $$rc"; exit 1; fi; \
	cp we_procid.h $(TMPDIR_)/abi-procid.h; \
	sed '0,/^typedef struct {$$/s//typedef struct {\n    uint32_t we_planted_field;/' we_module.h > $(TMPDIR_)/abi-planted.h; \
	if WE_ABI_HEADER=$(TMPDIR_)/abi-planted.h WE_ABI_PROCID=$(TMPDIR_)/abi-procid.h python3 gen-abi-layout.py --check > $(TMPDIR_)/abi-planted.out 2>&1 \
	   || ! grep -q '^FAIL abi layout: a recorded layout changed' $(TMPDIR_)/abi-planted.out \
	   || WE_ABI_HEADER=$(TMPDIR_)/abi-planted.h WE_ABI_PROCID=$(TMPDIR_)/abi-procid.h python3 gen-abi-layout.py --write > $(TMPDIR_)/abi-planted-w.out 2>&1; then \
	  echo "CHECK FAIL: a field planted in we_module.h's first struct was not refused as a change under one major: $$(head -1 $(TMPDIR_)/abi-planted.out)"; exit 1; fi; \
	echo "ok   abi layout control: a field planted in the first struct is a change, refused by --check and by --write"; \
	awk '/ABI-LAYOUT: generated/ && !d { print "typedef struct {\n    uint64_t a;\n} we_mod_planted_added_t;\n"; d = 1 } { print }' we_module.h > $(TMPDIR_)/abi-added.h; \
	if WE_ABI_HEADER=$(TMPDIR_)/abi-added.h WE_ABI_PROCID=$(TMPDIR_)/abi-procid.h python3 gen-abi-layout.py --check > $(TMPDIR_)/abi-added.out 2>&1 \
	   || ! grep -q 'added assertions, nothing recorded changed' $(TMPDIR_)/abi-added.out \
	   || ! WE_ABI_HEADER=$(TMPDIR_)/abi-added.h WE_ABI_PROCID=$(TMPDIR_)/abi-procid.h python3 gen-abi-layout.py --write > $(TMPDIR_)/abi-added-w.out 2>&1 \
	   || ! WE_ABI_HEADER=$(TMPDIR_)/abi-added.h WE_ABI_PROCID=$(TMPDIR_)/abi-procid.h python3 gen-abi-layout.py --check > /dev/null 2>&1 \
	   || ! grep -q "define WE_MOD_ABI_LAYOUT_MAJOR $$(sed -n 's/^#define WE_MODULE_ABI_VERSION \([0-9]*\)u$$/\1/p' we_module.h)u" $(TMPDIR_)/abi-added.h; then \
	  echo "CHECK FAIL: an added type was not written under the same major: $$(head -1 $(TMPDIR_)/abi-added.out) $$(head -1 $(TMPDIR_)/abi-added-w.out 2>/dev/null)"; exit 1; fi; \
	echo "ok   abi layout: an added type is written under the same major, and the check then passes"; \
	echo "2 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	if python3 gen-map-fields.py --check > $(TMPDIR_)/map-fields.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/map-fields.out; grep -E '^[0-9]+ checks, ' $(TMPDIR_)/map-fields.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: gen-map-fields.py --check exited $$rc"; exit 1; fi; \
	sed '/WE_MAP_FIELD(blob)/d' we_map_fields.h > $(TMPDIR_)/map-fields-planted.h; \
	if WE_MAP_FIELDS=$(TMPDIR_)/map-fields-planted.h python3 gen-map-fields.py --check > $(TMPDIR_)/map-fields-planted.out 2>&1 \
	   || ! grep -q '^FAIL map fields' $(TMPDIR_)/map-fields-planted.out; then \
	  echo "CHECK FAIL: a field list missing blob was not refused as other than the scan"; exit 1; fi; \
	echo "ok   map fields control: a list missing blob is not the scan"; \
	echo "1 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	$(CC) $(CFLAGS) -DWE_COUNT_DIGEST -DWE_TEST_CORE_CONTROL -DWE_TEST_REBASE_DROP -o $(TMPDIR_)/test_core_rebase_drop test_core.c $(TEST_SRC) $(CORE_SRC); \
	if $(TMPDIR_)/test_core_rebase_drop $(TMPDIR_) > $(TMPDIR_)/rebase-drop.out 2>&1 \
	   || ! grep -q 'rebase: blob still points into the old buffer' $(TMPDIR_)/rebase-drop.out; then \
	  echo "CHECK FAIL: a rebase that leaves blob behind was not caught by the rebase row"; exit 1; fi; \
	echo "ok   rebase control: a rebase that leaves blob in the old buffer is caught by the row"; \
	echo "1 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	$(CC) $(CFLAGS) -DWE_COUNT_DIGEST -DWE_TEST_CORE_CONTROL -DWE_TEST_EXTRA_VERIFY_PASS -o $(TMPDIR_)/test_core_extra_pass test_core.c $(TEST_SRC) $(CORE_SRC); \
	if $(TMPDIR_)/test_core_extra_pass $(TMPDIR_) > $(TMPDIR_)/extra-pass.out 2>&1 \
	   || ! grep -q 'load+verify: [0-9]* digest blocks for a' $(TMPDIR_)/extra-pass.out; then \
	  echo "CHECK FAIL: a load that digests the file twice was not caught by the load+verify row"; exit 1; fi; \
	echo "ok   load+verify control: $$(grep -m1 -o 'load+verify: [0-9]* digest blocks for a [0-9]*-byte file, not the one pass.s [0-9]*' $(TMPDIR_)/extra-pass.out)"; \
	echo "1 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	pc() { $(CC) $(CFLAGS) -DWE_COUNT_DIGEST -DWE_TEST_CORE_CONTROL "$$@" test_core.c $(TEST_SRC) $(CORE_SRC); }; \
	pc -DWE_TEST_PIDNS_READLINK_DENIED -o $(TMPDIR_)/test_core_pidns_stat; \
	if ! $(TMPDIR_)/test_core_pidns_stat $(TMPDIR_) > $(TMPDIR_)/pidns-stat.out 2>&1 \
	   || ! grep -q 'the link refused: the inode above came from the stat' $(TMPDIR_)/pidns-stat.out; then \
	  grep FAIL $(TMPDIR_)/pidns-stat.out | head -5; \
	  echo "CHECK FAIL: with the namespace link refused (WE_TEST_PIDNS_READLINK_DENIED) the writer did not name its namespace from the stat"; exit 1; fi; \
	echo "ok   with the namespace link refused, the writer names its namespace from the stat"; \
	pc -DWE_TEST_PIDNS_READLINK_DENIED -DWE_TEST_PIDNS_STAT_DENIED -o $(TMPDIR_)/test_core_pidns_none; \
	if ! $(TMPDIR_)/test_core_pidns_none $(TMPDIR_) > $(TMPDIR_)/pidns-none.out 2>&1 \
	   || ! grep -q 'the link and the stat refused: the writer names no namespace' $(TMPDIR_)/pidns-none.out; then \
	  grep FAIL $(TMPDIR_)/pidns-none.out | head -5; \
	  echo "CHECK FAIL: with the link and the stat refused the writer did not name pidns 0"; exit 1; fi; \
	echo "ok   with the link and the stat both refused, the writer names pidns 0, and the summary's reader places it"; \
	echo "4 checks, 0 failures" >> $(TMPDIR_)/check.out; \
	pc -DWE_TEST_PIDNS_STAT_DENIED -DWE_TEST_PIDNS_NO_READLINK -o $(TMPDIR_)/test_core_pidns_noread; \
	if $(TMPDIR_)/test_core_pidns_noread $(TMPDIR_) > $(TMPDIR_)/pidns-noread.out 2>&1 \
	   || ! grep -q 'pidns: the writer names 0, and the namespace' $(TMPDIR_)/pidns-noread.out; then \
	  echo "CHECK FAIL: the control WE_TEST_PIDNS_NO_READLINK (no link read, the stat refused) passed the pidns rows"; exit 1; fi; \
	echo "ok   pidns control: with no link read and the stat refused, $$(grep -m1 -o 'the writer names 0, and the namespace.s inode is [0-9]*' $(TMPDIR_)/pidns-noread.out)"; \
	pc -DWE_TEST_PIDNS_STAT_FIRST -o $(TMPDIR_)/test_core_pidns_statfirst; \
	if $(TMPDIR_)/test_core_pidns_statfirst $(TMPDIR_) > $(TMPDIR_)/pidns-statfirst.out 2>&1 \
	   || ! grep -q 'naming the namespace made 1 stat() call(s) on /proc/self/ns/pid' $(TMPDIR_)/pidns-statfirst.out; then \
	  echo "CHECK FAIL: the control WE_TEST_PIDNS_STAT_FIRST (the stat before the link) passed the no-stat row"; exit 1; fi; \
	echo "ok   pidns control: the stat tried first makes 1 stat() of /proc/self/ns/pid, which the no-stat row names"; \
	pc -DWE_TEST_PIDNS_LOOSE -o $(TMPDIR_)/test_core_pidns_loose; \
	if $(TMPDIR_)/test_core_pidns_loose $(TMPDIR_) > $(TMPDIR_)/pidns-loose.out 2>&1 \
	   || ! grep -q 'pidns link: the malformed "pid:\[18446744073709551616\]" read as an inode' $(TMPDIR_)/pidns-loose.out; then \
	  echo "CHECK FAIL: the control WE_TEST_PIDNS_LOOSE (an overflowing or zero inode taken as read) passed the link rows"; exit 1; fi; \
	echo "ok   pidns control: a parse without the bounds reads $$(grep -c 'pidns link: the malformed' $(TMPDIR_)/pidns-loose.out) malformed links as inodes"; \
	echo "3 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@./snapshot-cli-selftest.sh $(TMPDIR_) > $(TMPDIR_)/snapshot-cli.out 2>&1 || { cat $(TMPDIR_)/snapshot-cli.out; echo "CHECK FAIL: snapshot-cli-selftest.sh"; exit 1; }; \
	cat $(TMPDIR_)/snapshot-cli.out; grep -E '^[0-9]+ checks, ' $(TMPDIR_)/snapshot-cli.out >> $(TMPDIR_)/check.out
	@set -e; \
	./locals-claims.sh > $(TMPDIR_)/locals-claims.out 2>&1 || { cat $(TMPDIR_)/locals-claims.out; echo "CHECK FAIL: locals-claims.sh"; exit 1; }; \
	cat $(TMPDIR_)/locals-claims.out; grep -E '^[0-9]+ checks, ' $(TMPDIR_)/locals-claims.out >> $(TMPDIR_)/check.out; \
	lc() { name=$$1; want=$$2; shift 2; \
	  if ./locals-claims.sh "$$@" > $(TMPDIR_)/locals-claims-control.out 2>&1 \
	     || ! grep -q -- "$$want" $(TMPDIR_)/locals-claims-control.out; then \
	    echo "CHECK FAIL: the locals-claims control ($$name) was not refused by \"$$want\""; exit 1; fi; \
	  echo "ok   the locals-claims control ($$name) refused: $$(grep -m1 -- "$$want" $(TMPDIR_)/locals-claims-control.out | cut -c1-120)"; }; \
	sed 's/keeps 8 bytes/keeps no bytes/' we_module.h > $(TMPDIR_)/we_module_claims_control.h; \
	lc "the header's gcc 13 sentence dropped" 'does not say on x86_64 gcc 13 keeps 8 bytes' --header $(TMPDIR_)/we_module_claims_control.h; \
	sed 's/keeps 16 bytes/keeps 24 bytes/' we_module.h > $(TMPDIR_)/we_module_claims_control.h; \
	lc "the header claiming a spill the table does not hold" "which the gate's table does not hold" --header $(TMPDIR_)/we_module_claims_control.h; \
	sed 's/^\(    \["clang-18|ubuntu-x86_64|hpmod"\]=16\)$$/\1\n    ["gcc-13@aarch64|base|-O|hpmod"]=8/' hotpath-gate.sh > $(TMPDIR_)/hotpath-gate-claims-control.sh; \
	lc "an aarch64 spill in the table beside none on aarch64" 'says none on aarch64, and the gate' --gate $(TMPDIR_)/hotpath-gate-claims-control.sh; \
	echo "3 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	$(CC) $(CFLAGS) -DWE_SUM_TEST_EAGER_SUM -o $(TMPDIR_)/test_summary_eager test_summary.c we_sha256.c; \
	if $(TMPDIR_)/test_summary_eager $(TMPDIR_) > $(TMPDIR_)/test_summary_eager.out 2>&1 \
	   || ! grep -q 'so the refused file was counted' $(TMPDIR_)/test_summary_eager.out; then \
	  echo "CHECK FAIL: the summary control WE_SUM_TEST_EAGER_SUM (each line summed as read) passed the refusal rows"; exit 1; fi; \
	echo "ok   the summary control WE_SUM_TEST_EAGER_SUM fails its rows: $$(grep -c 'so the refused file was counted' $(TMPDIR_)/test_summary_eager.out) refused files counted, e.g. $$(grep -m1 '^r 0123456789abcdef 1 1000' $(TMPDIR_)/test_summary_eager.out)"; \
	$(CC) $(CFLAGS) -DWE_SUM_TEST_EXIT_DRIFT -o $(TMPDIR_)/test_summary_exit_drift test_summary.c we_sha256.c; \
	if $(TMPDIR_)/test_summary_exit_drift $(TMPDIR_) > $(TMPDIR_)/test_summary_exit_drift.out 2>&1 \
	   || ! grep -q 'over a missing directory returned 1, which the usage text' $(TMPDIR_)/test_summary_exit_drift.out \
	   || ! grep -q 'the usage text gives 2 for `<counters-dir>`, and no case returned it' $(TMPDIR_)/test_summary_exit_drift.out; then \
	  echo "CHECK FAIL: the summary control WE_SUM_TEST_EXIT_DRIFT (a code changed, the usage table not) passed the exit-table row"; exit 1; fi; \
	echo "ok   the summary control WE_SUM_TEST_EXIT_DRIFT fails the exit-table row both ways: $$(grep -m1 'over a missing directory returned 1' $(TMPDIR_)/test_summary_exit_drift.out | sed 's/^ *FAIL //')"; \
	$(CC) $(CFLAGS) -DWE_SUM_TEST_NS_STAT_DENIED -o $(TMPDIR_)/test_summary_nsdenied test_summary.c we_sha256.c; \
	if ! $(TMPDIR_)/test_summary_nsdenied $(TMPDIR_) > $(TMPDIR_)/test_summary_nsdenied.out 2>&1; then \
	  grep FAIL $(TMPDIR_)/test_summary_nsdenied.out; \
	  echo "CHECK FAIL: test_summary with the namespace stat refused (WE_SUM_TEST_NS_STAT_DENIED, the NSpid fallback) failed"; exit 1; fi; \
	echo "ok   test_summary with the namespace stat refused, every pidns-0 writer placed by its NSpid: $$(tail -1 $(TMPDIR_)/test_summary_nsdenied.out)"; \
	tail -1 $(TMPDIR_)/test_summary_nsdenied.out >> $(TMPDIR_)/check.out; \
	$(CC) $(CFLAGS) -DWE_SUM_TEST_PIDNS_TRUSTED -o $(TMPDIR_)/test_summary_pidns_trusted test_summary.c we_sha256.c; \
	if $(TMPDIR_)/test_summary_pidns_trusted $(TMPDIR_) > $(TMPDIR_)/test_summary_pidns_trusted.out 2>&1 \
	   || ! grep -q 'a writer in another pid namespace was read as live' $(TMPDIR_)/test_summary_pidns_trusted.out; then \
	  echo "CHECK FAIL: the summary control WE_SUM_TEST_PIDNS_TRUSTED (a writer's pidns 0 read as this namespace) passed the other-namespace row"; exit 1; fi; \
	echo "ok   the summary control WE_SUM_TEST_PIDNS_TRUSTED fails the other-namespace row: $$(grep -m1 'another pid namespace was read as live' $(TMPDIR_)/test_summary_pidns_trusted.out | sed 's/^ *FAIL //' | cut -c1-120)"; \
	run=; if [ "$$(id -u)" = 0 ]; then run=env; elif sudo -n true 2>/dev/null; then run="sudo -n"; fi; \
	if [ -z "$$run" ]; then echo "CHECK FAIL: the procfs row needs root or passwordless sudo to make a pid namespace"; exit 1; fi; \
	pf=$$(mktemp -d $(TMPDIR_)/procfs-row.XXXXXX); chmod 755 $$pf; \
	$$run unshare -p --fork $(TMPDIR_)/test_summary_nsdenied $$pf --procfs-not-mine > $(TMPDIR_)/test_summary_procfs.out 2>&1 && prc=0 || prc=$$?; \
	$(CC) $(CFLAGS) -DWE_SUM_TEST_NS_STAT_DENIED -DWE_SUM_TEST_NO_PROCFS_CHECK -o $(TMPDIR_)/test_summary_noprocfs test_summary.c we_sha256.c; \
	$$run unshare -p --fork $(TMPDIR_)/test_summary_noprocfs $$pf --procfs-not-mine > $(TMPDIR_)/test_summary_noprocfs.out 2>&1 && crc=0 || crc=$$?; \
	$$run rm -rf $$pf; \
	if [ $$prc -ne 0 ]; then grep FAIL $(TMPDIR_)/test_summary_procfs.out; \
	  echo "CHECK FAIL: the procfs row (the NSpid fallback inside a pid namespace below its procfs's) failed"; exit 1; fi; \
	echo "ok   inside a pid namespace with its parent's procfs, the NSpid fallback refuses a pidns-0 writer as foreign: $$(tail -1 $(TMPDIR_)/test_summary_procfs.out)"; \
	tail -1 $(TMPDIR_)/test_summary_procfs.out >> $(TMPDIR_)/check.out; \
	if [ $$crc -eq 0 ] || ! grep -q 'a pidns-0 writer was not refused as foreign' $(TMPDIR_)/test_summary_noprocfs.out; then \
	  echo "CHECK FAIL: the summary control WE_SUM_TEST_NO_PROCFS_CHECK (any procfs taken as the reader's own) passed the procfs row"; exit 1; fi; \
	echo "ok   the summary control WE_SUM_TEST_NO_PROCFS_CHECK fails the procfs row: $$(grep -m1 '^process pid' $(TMPDIR_)/test_summary_noprocfs.out) read live"; \
	echo "4 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	$(CC) $(CFLAGS) -DWE_MOD_TEST_WRITER_UID_UNCHECKED -o $(TMPDIR_)/test_summary_uid test_summary.c we_sha256.c; \
	if $(TMPDIR_)/test_summary_uid $(TMPDIR_) > $(TMPDIR_)/test_summary_uid.out 2>&1 \
	   || [ "$$(grep -c "was read as the writer's" $(TMPDIR_)/test_summary_uid.out)" -ne 4 ]; then \
	  echo "CHECK FAIL: the summary control WE_MOD_TEST_WRITER_UID_UNCHECKED (--writer-uid taken, the owner never compared) did not fail its four rows"; exit 1; fi; \
	echo "ok   the summary control WE_MOD_TEST_WRITER_UID_UNCHECKED fails its four rows: another uid's, a group-writable, a hard-linked and a forged-refusal file read as the writer's"; \
	$(CC) $(CFLAGS) -DWE_MOD_TEST_STATUS_FOLLOWS -o $(TMPDIR_)/test_summary_follows test_summary.c we_sha256.c; \
	if $(TMPDIR_)/test_summary_follows $(TMPDIR_) > $(TMPDIR_)/test_summary_follows.out 2>&1 \
	   || ! grep -q 'the link was followed' $(TMPDIR_)/test_summary_follows.out; then \
	  echo "CHECK FAIL: the summary control WE_MOD_TEST_STATUS_FOLLOWS (a status entry opened without O_NOFOLLOW) passed the symbolic-link row"; exit 1; fi; \
	echo "ok   the summary control WE_MOD_TEST_STATUS_FOLLOWS fails the symbolic-link row: the link was followed"; \
	echo "2 mutant checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	if ./policy-mutants.sh $(TMPDIR_) $(CC) $(CFLAGS) > $(TMPDIR_)/policy-mutants.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/policy-mutants.out; cat $(TMPDIR_)/policy-mutants.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: policy-mutants.sh exited $$rc"; exit 1; fi
	@set -e; \
	san=$$(d=$$(mktemp -d) && printf 'int main(void){return 0;}' > $$d/p.c && $(CC) -fsanitize=address,undefined -o $$d/p $$d/p.c 2>/dev/null && echo yes; rm -rf $$d); \
	if [ "$$san" != yes ]; then echo "CHECK FAIL: the recover-mode sanitizer builds need -fsanitize=address,undefined, and $(CC) has none"; exit 1; fi; \
	n=0; for o in -O1 -O2; do for f in $(CORE_SRC) $(POLICY_SRC) $(MODULE_SRC) we_summary_cli.c we_lookup_cli.c; do \
	  n=$$((n + 1)); def=; [ $$f = we_lookup_cli.c ] && def="-DWE_TRACE -DWE_LOOKUP_TOOL"; \
	  if ! $(CC) -std=c11 $$o -Wall -Wextra -Werror -fsanitize=address,undefined $$def -c -o /dev/null $$f 2> $(TMPDIR_)/san-recover.err; then \
	    echo "CHECK FAIL: $$f does not build with -Werror under recover-mode ASan and UBSan ($$o): $$(grep -m1 -E 'error|warning' $(TMPDIR_)/san-recover.err | cut -c1-200)"; exit 1; fi; \
	done; done; \
	echo "ok   every shipped source builds with -Werror under ASan and UBSan in recover mode, at -O1 and -O2 ($$n builds)"; \
	echo "$$n checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	if ./control-builds.sh $(CC) $(CFLAGS) > $(TMPDIR_)/control-builds.out 2>&1; then rc=0; else rc=$$?; fi; \
	grep -E '^FAIL|control builds' $(TMPDIR_)/control-builds.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: a declared control does not compile alone with -Werror (control-builds.sh)"; exit 1; fi; \
	sed -n 's/^\([0-9]*\) control builds, 0 failures$$/\1 checks, 0 failures/p' $(TMPDIR_)/control-builds.out >> $(TMPDIR_)/check.out
	@set -e; \
	if python3 control-bodies.py .. > $(TMPDIR_)/control-bodies.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/control-bodies.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: control-bodies.py exited $$rc"; exit 1; fi; \
	sed 's/^#if !defined(WE_MOD_CONTROL_BUILD) \&\& ( \\$$/#if !defined(WE_MOD_CONTROL_BUILD) \&\& ( defined(WE_MOD_TEST_PLANTED_NO_BODY) || \\/' we_module.h > $(TMPDIR_)/cb-planted.h; \
	if WE_CB_HEADER=$(TMPDIR_)/cb-planted.h python3 control-bodies.py .. > $(TMPDIR_)/cb-planted.out 2>&1 \
	   || ! grep -q 'WE_MOD_TEST_PLANTED_NO_BODY: declared' $(TMPDIR_)/cb-planted.out; then \
	  echo "CHECK FAIL: a control declared with no body was not refused by control-bodies.py"; exit 1; fi; \
	printf 'cc -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PLANTED_GATE_ONLY x.c\n' > $(TMPDIR_)/cb-gate.sh; \
	if WE_CB_EXTRA_GATE=$(TMPDIR_)/cb-gate.sh python3 control-bodies.py .. > $(TMPDIR_)/cb-gate.out 2>&1 \
	   || ! grep -q 'WE_MOD_TEST_PLANTED_GATE_ONLY: named in ' $(TMPDIR_)/cb-gate.out; then \
	  echo "CHECK FAIL: a gate building a control with no body was not refused by control-bodies.py"; exit 1; fi; \
	printf 'm=PAUSE_TICK; cc -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_$$m x.c\n' > $(TMPDIR_)/cb-computed.sh; \
	if WE_CB_EXTRA_GATE=$(TMPDIR_)/cb-computed.sh python3 control-bodies.py .. > $(TMPDIR_)/cb-computed.out 2>&1 \
	   || ! grep -q 'a computed control name at .*cb-computed.sh:1' $(TMPDIR_)/cb-computed.out; then \
	  echo "CHECK FAIL: a gate building a computed control name was not refused by control-bodies.py"; exit 1; fi; \
	printf 'cc -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_EAGER_EXPORT x.c\n' > $(TMPDIR_)/cb-server.sh; \
	if WE_CB_EXTRA_GATE=$(TMPDIR_)/cb-server.sh WE_CB_EXTRA_GATE_AS=nginx/cb-server.sh python3 control-bodies.py .. > $(TMPDIR_)/cb-server.out 2>&1 \
	   || ! grep -q 'WE_MOD_TEST_EAGER_EXPORT: named in nginx/cb-server.sh, no body in the shipped core' $(TMPDIR_)/cb-server.out; then \
	  echo "CHECK FAIL: a server gate naming a control whose only body is in a harness was not refused by control-bodies.py"; exit 1; fi; \
	rm -f ./cb-fifo.conf; mkfifo ./cb-fifo.conf; \
	if timeout 60 env GIT_DIR=/nonexistent python3 control-bodies.py .. > $(TMPDIR_)/cb-fifo.out 2>&1; then rc=0; else rc=$$?; fi; \
	rm -f ./cb-fifo.conf; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: a FIFO in the walked tree stopped control-bodies.py (exit $$rc; 124 is the 60 s ceiling: an open() waiting for a writer)"; exit 1; fi; \
	rm -f ./cb-untracked-dangling.h ./cb-tracked-dangling.h; \
	G=$(TMPDIR_)/cb-git; rm -rf $$G; W=$$(cd .. && pwd); \
	if ! { git init -q --bare $$G && GIT_DIR=$$G GIT_WORK_TREE=$$W git add -A -- $$W ':(exclude)core/.testtmp' \
	         ':(exclude)litespeed/sdk' ':(exclude)**/.libs' ':(exclude)**/objs'; } > $(TMPDIR_)/cb-git.out 2>&1; then \
	  echo "CHECK FAIL: the tracked-file plants cannot build their private index: $$(tail -1 $(TMPDIR_)/cb-git.out)"; exit 1; fi; \
	ln -s ../lsquic/absent.h ./cb-untracked-dangling.h; \
	if ! GIT_DIR=$$G GIT_WORK_TREE=$$W python3 control-bodies.py .. > $(TMPDIR_)/cb-untracked.out 2>&1; then \
	  rm -f ./cb-untracked-dangling.h; \
	  echo "CHECK FAIL: an untracked dangling link under edge/ stopped control-bodies.py: $$(tail -1 $(TMPDIR_)/cb-untracked.out)"; exit 1; fi; \
	rm -f ./cb-untracked-dangling.h; \
	ln -s ../lsquic/absent.h ./cb-tracked-dangling.h; \
	GIT_DIR=$$G GIT_WORK_TREE=$$W git add -- $$W/core/cb-tracked-dangling.h; \
	if GIT_DIR=$$G GIT_WORK_TREE=$$W python3 control-bodies.py .. > $(TMPDIR_)/cb-tracked.out 2>&1 \
	   || ! grep -q 'a tracked file the guard cannot read: core/cb-tracked-dangling.h' $(TMPDIR_)/cb-tracked.out; then \
	  rm -f ./cb-tracked-dangling.h; \
	  echo "CHECK FAIL: a tracked dangling link was not refused by name by control-bodies.py"; exit 1; fi; \
	rm -rf ./cb-tracked-dangling.h $$G; \
	echo "ok   control bodies controls: a declared name and a gate-built name with no body, and a computed name, are each refused; a server gate's control with a body only in a harness is refused; a FIFO in the walked tree is never opened; an untracked dangling link is not read, a tracked one is refused by name"; \
	echo "8 checks, 0 failures" >> $(TMPDIR_)/check.out
	@set -e; \
	if ./module-controls.sh $(TMPDIR_) $(FUZZ_PLANES) $(CC) $(CFLAGS) > $(TMPDIR_)/module-controls.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/module-controls.out; cat $(TMPDIR_)/module-controls.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: module-controls.sh exited $$rc"; exit 1; fi
	@set -e; \
	if $(MAKE) --no-print-directory check-module-twin > $(TMPDIR_)/module-twin.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/module-twin.out; grep -E '^[0-9]+ (mutant )?checks, ' $(TMPDIR_)/module-twin.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: check-module-twin exited $$rc"; exit 1; fi
	@set -e; \
	if $(MAKE) --no-print-directory check-module-fuzz > $(TMPDIR_)/module-fuzz.out 2>&1; then rc=0; else rc=$$?; fi; \
	cat $(TMPDIR_)/module-fuzz.out; grep -E '^[0-9]+ (mutant )?checks, ' $(TMPDIR_)/module-fuzz.out >> $(TMPDIR_)/check.out; \
	if [ $$rc -ne 0 ]; then echo "CHECK FAIL: check-module-fuzz exited $$rc"; exit 1; fi
	@set -e; \
	if [ -f ../REFERENCE.md ] && grep -q 'runs [0-9,]* cases' ../REFERENCE.md; then \
	  ran=$$(sed -n 's/^\([0-9]*\) \(mutant \)\{0,1\}checks, .*/\1/p' $(TMPDIR_)/check.out | awk '{s+=$$1} END {print s}'); \
	  said=$$(sed -n 's/.*runs \([0-9,]*\) cases.*/\1/p' ../REFERENCE.md | head -1 | tr -d ,); \
	  if [ "$$ran" != "$$said" ]; then \
	    echo "CHECK FAIL: REFERENCE.md says $$said cases and this run has $$ran"; \
	    exit 1; \
	  fi; \
	  echo "ok   REFERENCE.md's published case count ($$said) is this run's, so the page cannot go stale"; \
	fi

# THE POLICY LANGUAGE, read twice. policy_ref.py is the reference interpreter, written from POLICY.md
# and never from the C; the corpus under testdata/policy/ was written by a third author
# before either. Every leg prints one `N checks, F failures` line, and every leg fails the build:
#
#   self-test     the oracle's own checks, each beside the negative control that shows it can fail
#   corpus        20 programs that must compile, 50 that must be refused with every .expect field equal
#   generator     the seeded cases: every reduced plane-state vector per program, POLICY.md's named rows,
#                 every limit at its boundary and one past, lexical mutations, and the exhaustive K3 leg;
#                 with the classifier's soundness against an exact brute force
#   oracle        the reference interpreter over both case files, writing the coverage matrix; it adds
#                 NOTHING to the published count, because evaluating a case checks nothing until the
#                 differential compares it (its invariant line compares two of its own paths)
#   diff-self-test  the comparison refuses empty input, a line before the first program, duplicated
#                 program and case ids, and counts a real disagreement
#   coverage      every cell of the matrix non-zero (the K3, plane, slot, clamp and absent-plane cells
#                 and one per phrase of section 1.5's table), and each cell zeroed alone must fail
#   mutants       the oracle under each defect POLICY.md names must disagree with itself unmutated, in
#                 at least its floor of blocks (half the count measured when the floor was set)
#   seeds         the adversarial seed list under testdata/policy/seeds/: every seed compiles or is
#                 refused with a located error, the record seeds evaluate, the seed floor holds
#   default-conf  decision 3's default policy, testdata/policy/default.conf (the file the Java builder's
#                 default-policy constant is pinned to), compiles to exactly the program of accept/01
#   fuzz replay   once we_policy.c exists: fuzz_policy and fuzz_program without a fuzzer, see `fuzz`
#   differential  the C test_policy against the oracle, every line of every case equal, the cost line
#                 included; it runs as soon as test_policy.c is in the tree and cannot be skipped then
#
# python3 absent is a FAILURE, never a skip: a gate that quietly does not run reads as a gate that
# passed. POLICY_EVERY subsamples the random leg for the mutant runs only; every named row, every limit
# program and the whole exhaustive leg stay in, and the run prints each mutant's catch count.
POLICY_DIR    = $(TMPDIR_)/policy
POLICY_EVERY ?= 4

check-policy: $(if $(POLICY_C),test_policy) $(if $(WE_POLICY_C),fuzz_policy_replay fuzz_program_replay fuzz-planes)
	@mkdir -p $(POLICY_DIR)
	@command -v python3 >/dev/null 2>&1 || { echo "CHECK FAIL: check-policy needs python3; a missing interpreter is a failure, not a skip"; exit 1; }
	@set -e; out=$(POLICY_DIR)/check-policy.out; : > $$out; \
	run() { name=$$1; shift; \
	  if PYTHONDONTWRITEBYTECODE=1 "$$@" > $(POLICY_DIR)/$$name.log 2>&1; then rc=0; else rc=$$?; fi; \
	  grep -v '^ok ' $(POLICY_DIR)/$$name.log || true; \
	  grep -E '^[0-9]+ checks, [0-9]+ failures$$' $(POLICY_DIR)/$$name.log >> $$out || { echo "CHECK FAIL: policy $$name printed no checks line"; exit 1; }; \
	  if [ $$rc -ne 0 ]; then echo "CHECK FAIL: policy $$name exited $$rc"; exit 1; fi; }; \
	run self-test python3 policy_ref.py --self-test; \
	run corpus python3 policy_ref.py --corpus testdata/policy; \
	run generator python3 policy_gen.py --out $(POLICY_DIR)/cases.txt --exhaustive $(POLICY_DIR)/exhaustive.txt; \
	run oracle python3 policy_ref.py --cases $(POLICY_DIR)/cases.txt --out $(POLICY_DIR)/oracle.txt --coverage $(POLICY_DIR)/coverage.txt; \
	run oracle-exhaustive python3 policy_ref.py --cases $(POLICY_DIR)/exhaustive.txt --out $(POLICY_DIR)/oracle-exhaustive.txt --coverage $(POLICY_DIR)/coverage-exhaustive.txt; \
	cat $(POLICY_DIR)/coverage.txt $(POLICY_DIR)/coverage-exhaustive.txt > $(POLICY_DIR)/coverage-all.txt; \
	run diff-self-test python3 policy_diff.py --self-test; \
	run coverage python3 policy_diff.py --coverage $(POLICY_DIR)/coverage-all.txt; \
	run coverage-control python3 policy_diff.py --coverage-control $(POLICY_DIR)/coverage-all.txt; \
	run mutants python3 policy_diff.py --mutants --every $(POLICY_EVERY) $(POLICY_DIR)/cases.txt $(POLICY_DIR)/exhaustive.txt; \
	run seeds python3 policy_ref.py --seeds testdata/policy/seeds --floor $(POLICY_SEED_FLOOR); \
	run default-conf python3 policy_ref.py --default-conf testdata/policy/default.conf; \
	run decisions python3 policy_ref.py --decisions-match ../POLICY.md; \
	if [ -n "$(WE_POLICY_C)" ]; then \
	  run fuzz-policy-replay ./fuzz_policy_replay --replay testdata --planes $(FUZZ_PLANES) --floor $(POLICY_REPLAY_FLOOR); \
	  run fuzz-program-replay ./fuzz_program_replay --replay testdata/policy/accept --planes $(FUZZ_PLANES) --mutations $(FUZZ_MUTATIONS); \
	else \
	  echo "DARK the fuzz replays: we_policy.c is not in this tree, so fuzz_policy and fuzz_program (over the corpus, the seeds and all eight planes) did not run"; \
	fi; \
	if [ -n "$(POLICY_C)" ]; then \
	  ./test_policy --cases $(POLICY_DIR)/cases.txt > $(POLICY_DIR)/c.txt || { echo "CHECK FAIL: test_policy exited non-zero on the generated cases"; exit 1; }; \
	  ./test_policy --cases $(POLICY_DIR)/exhaustive.txt > $(POLICY_DIR)/c-exhaustive.txt || { echo "CHECK FAIL: test_policy exited non-zero on the exhaustive leg"; exit 1; }; \
	  run differential python3 policy_diff.py $(POLICY_DIR)/oracle.txt $(POLICY_DIR)/c.txt; \
	  run differential-exhaustive python3 policy_diff.py $(POLICY_DIR)/oracle-exhaustive.txt $(POLICY_DIR)/c-exhaustive.txt; \
	  ./test_policy --c-only testdata/policy/seeds > $(POLICY_DIR)/c-only.txt || { echo "CHECK FAIL: test_policy --c-only exited non-zero"; exit 1; }; \
	  for f in testdata/policy/seeds/*.c-only; do n=$$(basename "$$f" .c-only); \
	    grep -qx "c-only $$n ok" $(POLICY_DIR)/c-only.txt || { echo "CHECK FAIL: test_policy did not account for the seed $$n (expected the line: c-only $$n ok)"; exit 1; }; \
	  done; \
	  echo "$$(ls testdata/policy/seeds/*.c-only | wc -l) checks, 0 failures" >> $$out; \
	else \
	  echo "DARK the differential proper: test_policy.c is not in this tree yet, so the reference interpreter ran ALONE over the corpus and the generated cases, and nothing has compared it with a C compiler and evaluator"; \
	  echo "DARK the C-only seeds: test_policy must print 'c-only <name> ok' for each of $$(ls testdata/policy/seeds/*.c-only | xargs -n1 basename | sed 's/\.c-only$$//' | tr '\n' ' ')and nothing has run them"; \
	fi
	@echo "ok   check-policy: $$(awk '{s+=$$1} END {print s}' $(POLICY_DIR)/check-policy.out) policy checks"

# THE PARSER AND VERIFIER FUZZ HARNESSES (fuzz_policy.c, fuzz_program.c). They are written against the
# compiler's API, so they cannot build before it does. What lights them up is the FILE we_policy.c in
# this directory (WE_POLICY_C below): while it is absent, `make fuzz` holds the seed floor and then
# prints a DARK line saying exactly that, and that explicit branch is the only way it exits 0 without
# fuzzing. Once it is present:
#   - the replay builds (no fuzzer, under ASan and UBSan when the toolchain has them) run in check-policy
#     and here: fuzz_policy over every corpus and seed .policy file (the .expect fields equal on refuse/,
#     at least POLICY_REPLAY_FLOOR files), fuzz_program over FUZZ_MUTATIONS field-level mutants per
#     accept file, every block verify accepts evaluated against a guard page;
#   - with clang's libFuzzer, both run for WE_FUZZ_SECONDS each from the corpus and seeds (-max_len 64 KiB,
#     the dictionary fuzz_policy.dict), and any crash or sanitizer report fails the target.
# POLICY_SEED_FLOOR is the file count of testdata/policy/seeds/, and POLICY_REPLAY_FLOOR the .policy files
# the replay reads (20 accept + 50 refuse + 90 seeds + 48 adversarial); deleting one fails the build. Raise them with the
# files, never lower them to make a build pass.
POLICY_SEED_FLOOR   = 98
POLICY_REPLAY_FLOOR = 208
WE_FUZZ_SECONDS    ?= 60
FUZZ_MUTATIONS     ?= 2000
FUZZ_DIR            = $(TMPDIR_)/fuzz
FUZZ_PLANES         = $(FUZZ_DIR)/planes
FUZZ_SRC            = $(CORE_SRC) we_policy.c
FUZZ_HDR            = $(CORE_HDR) fuzz_common.h we_policy.h we_eval.h
FUZZ_SAN            = $(shell d=$$(mktemp -d) && printf 'int main(void){return 0;}' > $$d/p.c && $(CC) -fsanitize=address,undefined -o $$d/p $$d/p.c 2>/dev/null && echo -fsanitize=address,undefined -fno-sanitize-recover=all; rm -rf $$d)
FUZZ_CFLAGS         = -std=c11 -O1 -g -fno-omit-frame-pointer -Wall -Wextra -Werror $(FUZZ_SAN)

fuzz_policy_replay: fuzz_policy.c $(FUZZ_SRC) $(FUZZ_HDR)
	$(CC) $(FUZZ_CFLAGS) -o $@ fuzz_policy.c $(FUZZ_SRC)

fuzz_program_replay: fuzz_program.c $(FUZZ_SRC) $(FUZZ_HDR)
	$(CC) $(FUZZ_CFLAGS) -o $@ fuzz_program.c $(FUZZ_SRC)

fuzz:
	@set -e; n=$$(ls testdata/policy/seeds | grep -cE '\.(policy|case|c-only)$$'); \
	if [ "$$n" -lt $(POLICY_SEED_FLOOR) ]; then \
	  echo "FUZZ FAIL: testdata/policy/seeds/ holds $$n seeds, under the seed floor of $(POLICY_SEED_FLOOR)"; exit 1; \
	fi; \
	echo "ok   the seed list: $$n files, floor $(POLICY_SEED_FLOOR)"
	@if [ -z "$(WE_POLICY_C)" ]; then \
	  echo "DARK make fuzz: we_policy.c is not in this tree, so fuzz_policy and fuzz_program have no compiler to run against; only the seed floor was checked. The harnesses light up, here and in check-policy, the moment we_policy.c exists."; \
	  exit 0; \
	fi; \
	$(MAKE) --no-print-directory fuzz-replay; \
	if printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){(void)d;(void)n;return 0;}' > $(TMPDIR_)/libfuzzer-probe.c \
	    && clang -fsanitize=fuzzer,address,undefined -o $(TMPDIR_)/libfuzzer-probe $(TMPDIR_)/libfuzzer-probe.c 2>/dev/null; then \
	  set -e; mkdir -p $(FUZZ_DIR)/policy $(FUZZ_DIR)/program; \
	  for f in testdata/policy/accept/*.policy testdata/policy/refuse/*.policy testdata/policy/seeds/*.policy; do \
	    { printf '\377\000'; cat "$$f"; } > $(FUZZ_DIR)/policy/$$(basename "$$f"); \
	  done; \
	  clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -DFZ_LIBFUZZER -o $(FUZZ_DIR)/fuzz_policy fuzz_policy.c $(FUZZ_SRC); \
	  clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -DFZ_LIBFUZZER -o $(FUZZ_DIR)/fuzz_program fuzz_program.c $(FUZZ_SRC); \
	  FZ_ABORT=1 FZ_PLANES=$(FUZZ_PLANES) $(FUZZ_DIR)/fuzz_policy -max_total_time=$(WE_FUZZ_SECONDS) -max_len=65536 \
	    -dict=fuzz_policy.dict $(FUZZ_DIR)/policy; \
	  ./fuzz_program_replay --emit-seeds $(FUZZ_DIR)/program testdata/policy/accept; \
	  clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -DFZ_LIBFUZZER -o $(FUZZ_DIR)/fuzz_walk fuzz_walk.c $(MODULE_FUZZ_SRC); \
	  clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -DFZ_LIBFUZZER -o $(FUZZ_DIR)/fuzz_summary fuzz_summary.c we_sha256.c; \
	  mkdir -p $(FUZZ_DIR)/walk $(FUZZ_DIR)/summary; \
	  $(MAKE) --no-print-directory fuzz_walk_replay fuzz_summary_replay; \
	  ./fuzz_walk_replay --seeds $(FUZZ_DIR)/walk > /dev/null; ./fuzz_summary_replay --seeds $(FUZZ_DIR)/summary > /dev/null; \
	  $(FUZZ_DIR)/fuzz_walk -max_total_time=$(WE_FUZZ_SECONDS) -max_len=8192 $(FUZZ_DIR)/walk; \
	  $(FUZZ_DIR)/fuzz_summary -max_total_time=$(WE_FUZZ_SECONDS) -max_len=16384 -timeout=10 $(FUZZ_DIR)/summary; \
	  FZ_PLANES=$(FUZZ_PLANES) $(FUZZ_DIR)/fuzz_program -max_total_time=$(WE_FUZZ_SECONDS) -max_len=1048576 $(FUZZ_DIR)/program; \
	  echo "ok   make fuzz: both harnesses ran $(WE_FUZZ_SECONDS) s under libFuzzer with no crash and no sanitizer report"; \
	else \
	  echo "  (no libFuzzer in this toolchain: the replay builds above ran; CI's clang job runs the fuzzer)"; \
	fi

# The eight planes both harnesses evaluate against (fuzz_common.h): the builder's committed format-2
# routing and tor, and the six others written by the independent Python writer. The loader refuses a
# group- or world-writable plane, and a checkout made under umask 002 is 664, so the copies are made
# go-w here rather than trusted to the checkout's mode.
fuzz-planes:
	@mkdir -p $(FUZZ_PLANES)
	@set -e; \
	cp testdata/format2/routing.bin testdata/format2/tor.bin $(FUZZ_PLANES)/; \
	cp testdata/format2/routing-expected.txt $(FUZZ_PLANES)/routing.txt; \
	cp testdata/format2/tor-expected.txt $(FUZZ_PLANES)/tor.txt; \
	w() { python3 make-test-snapshot.py --plane $$1 --out $(FUZZ_PLANES)/$$1.bin --format $$2 --v4-index $$3 \
	        --v6-index $$4 $$5 --expect $(FUZZ_PLANES)/$$1.txt > /dev/null; }; \
	w reputation 1 radix-16 radix-16 --schema; \
	w rpki-unreachable 2 radix-16 none; \
	w anonymizer 2 rank radix-18; \
	w threat 2 none radix-16; \
	w registry 2 radix-16 rank; \
	w tenant 2 rank rank; \
	chmod go-w $(FUZZ_PLANES)/*.bin; \
	echo "ok   the eight fuzz planes: $$(ls $(FUZZ_PLANES)/*.bin | wc -l) files under $(FUZZ_PLANES)"

# THE MODULES' TWIN. policy_ref.py carries a second reading of we_module.h's cold half (the attribute
# renderer, the entry grammar, the walk, ACME, the formatter), written from POLICY.md section 3.9 and never
# from the C. Both read one seeded corpus (every class and boundary, then mutations of them) and print one
# line per case; every line must be equal. The controls: a twin that parses through ipaddress alone (which
# accepts a zone id and drops it), three C grammar mutants (port 65536, a leading zero, `::` standing for no
# group) and the walk without its line cap must each be reported on its named boundary and on no other case.
check-module-twin: test_module
	@mkdir -p $(POLICY_DIR)
	@set -e; \
	command -v python3 >/dev/null 2>&1 || { echo "CHECK FAIL: the twin differential needs python3"; exit 1; }; \
	PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --module-corpus $(POLICY_DIR)/module-corpus.txt; \
	./test_module --module-cases $(POLICY_DIR)/module-corpus.txt > $(POLICY_DIR)/module-c.txt; \
	PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --module-cases $(POLICY_DIR)/module-corpus.txt --out $(POLICY_DIR)/module-py.txt; \
	n=$$(wc -l < $(POLICY_DIR)/module-c.txt); \
	if ! cmp -s $(POLICY_DIR)/module-c.txt $(POLICY_DIR)/module-py.txt; then \
	  echo "CHECK FAIL: the C and the twin disagree on $$(diff $(POLICY_DIR)/module-c.txt $(POLICY_DIR)/module-py.txt | grep -c '^<') of $$n cases:"; \
	  diff $(POLICY_DIR)/module-c.txt $(POLICY_DIR)/module-py.txt | head -8; exit 1; fi; \
	echo "ok   the twin differential: $$n cases, the C and the Python twin equal line for line"; \
	echo "$$n checks, 0 failures"; \
	PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --module-cases $(POLICY_DIR)/module-corpus.txt --twin-mutant IPADDRESS_ONLY \
	  --out $(POLICY_DIR)/module-py-mut.txt; \
	z=$$(printf 'fe80::1%%eth0' | od -An -tx1 | tr -d ' \n'); \
	if cmp -s $(POLICY_DIR)/module-c.txt $(POLICY_DIR)/module-py-mut.txt \
	   || ! diff $(POLICY_DIR)/module-c.txt $(POLICY_DIR)/module-py-mut.txt | grep -q "entry $$z fe80::1"; then \
	  echo "CHECK FAIL: a twin parsing through ipaddress alone was not reported on the zone-id case"; exit 1; fi; \
	echo "ok   the twin control (ipaddress alone) reported on the zone-id case"; \
	m=1; \
	for macro in WE_MOD_TEST_PORT_65536 WE_MOD_TEST_LEADING_ZERO WE_MOD_TEST_DC_ZERO_GROUPS WE_MOD_TEST_NO_LINE_CLAMP; do \
	  name=$${macro#WE_MOD_TEST_}; \
	  $(CC) $(CFLAGS) -DWE_MOD_CONTROL_BUILD -D$$macro -o $(POLICY_DIR)/test_module_$$name test_module.c $(MODULE_SRC) $(CORE_SRC) $(POLICY_SRC) we_writer.c; \
	  $(POLICY_DIR)/test_module_$$name --module-cases $(POLICY_DIR)/module-corpus.txt > $(POLICY_DIR)/module-c-$$name.txt; \
	  PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --module-cases $(POLICY_DIR)/module-corpus.txt --twin-mutant $$name \
	    --out $(POLICY_DIR)/module-py-$$name.txt 2>/dev/null; \
	  if ! PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --mutant-check $$name $(POLICY_DIR)/module-corpus.txt \
	       $(POLICY_DIR)/module-c-$$name.txt $(POLICY_DIR)/module-py.txt $(POLICY_DIR)/module-py-$$name.txt; then \
	    echo "CHECK FAIL: the C grammar mutant $$macro was not reported on its named boundary alone"; exit 1; fi; \
	  m=$$((m + 1)); \
	done; \
	if PYTHONDONTWRITEBYTECODE=1 python3 policy_ref.py --mutant-check PORT_65536 $(POLICY_DIR)/module-corpus.txt \
	     $(POLICY_DIR)/module-c-NO_LINE_CLAMP.txt $(POLICY_DIR)/module-py.txt > $(POLICY_DIR)/mutant-misattributed.out 2>&1; then \
	  echo "CHECK FAIL: the mutant checker credited NO_LINE_CLAMP's disagreements to PORT_65536's boundary"; exit 1; fi; \
	echo "ok   the mutant checker refuses a misattribution: $$(grep -m1 FAIL $(POLICY_DIR)/mutant-misattributed.out | cut -c1-100)"; \
	m=$$((m + 1)); \
	echo "$$m mutant checks, 0 failures"

# THE MODULES' TWO HARNESSES, fuzz_walk (the trusted-header walk, each line in its own unterminated
# allocation) and fuzz_summary (the summary's three readers over a hostile directory), replayed under ASan
# and UBSan over their seeds in `check`, each beside the controls that must stop it: a one-byte over-read,
# a span one byte off, the peer judged on an unparsed header, an unmerged trust table, and a reader with no
# line bound. libFuzzer runs them under `make fuzz` like the others.
MODULE_FUZZ_SRC = we_module.c $(CORE_SRC) we_policy.c

fuzz_walk_replay: fuzz_walk.c $(MODULE_FUZZ_SRC) $(MODULE_HDR) $(CORE_HDR) we_policy.h we_eval.h
	$(CC) $(FUZZ_CFLAGS) -o $@ fuzz_walk.c $(MODULE_FUZZ_SRC)

fuzz_summary_replay: fuzz_summary.c we_summary_cli.c we_summary_read.h we_sha256.c we_sha256.h
	$(CC) $(FUZZ_CFLAGS) -o $@ fuzz_summary.c we_sha256.c

check-module-fuzz: fuzz_walk_replay fuzz_summary_replay
	@mkdir -p $(FUZZ_DIR)/walk-seeds $(FUZZ_DIR)/summary-seeds
	@set -e; \
	[ -n "$(FUZZ_SAN)" ] || { echo "CHECK FAIL: the module fuzz replays need ASan and UBSan, and $(CC) has neither"; exit 1; }; \
	./fuzz_walk_replay --seeds $(FUZZ_DIR)/walk-seeds > /dev/null; \
	./fuzz_summary_replay --seeds $(FUZZ_DIR)/summary-seeds > /dev/null; \
	./fuzz_walk_replay --replay $(FUZZ_DIR)/walk-seeds; \
	./fuzz_summary_replay --replay $(FUZZ_DIR)/summary-seeds; \
	n=0; \
	for c in WE_MOD_TEST_OVERREAD:AddressSanitizer WE_MOD_TEST_SPAN_OFF:"the judged span" \
	         WE_MOD_TEST_PEER_ON_UNPARSED:"newest entry parses" WE_MOD_TEST_UNMERGED_TRUST:"linear scan disagree"; do \
	  m=$${c%%:*}; want=$${c#*:}; \
	  $(CC) $(FUZZ_CFLAGS) -DWE_MOD_CONTROL_BUILD -D$$m -o $(FUZZ_DIR)/fuzz_walk_$$m fuzz_walk.c $(MODULE_FUZZ_SRC); \
	  if $(FUZZ_DIR)/fuzz_walk_$$m --replay $(FUZZ_DIR)/walk-seeds > $(FUZZ_DIR)/fuzz_walk_$$m.out 2>&1 \
	     || ! grep -q "$$want" $(FUZZ_DIR)/fuzz_walk_$$m.out; then \
	    echo "CHECK FAIL: the fuzz_walk control $$m was not stopped by \"$$want\""; exit 1; fi; \
	  echo "ok   fuzz_walk control $$m stopped: $$(grep -m1 "$$want" $(FUZZ_DIR)/fuzz_walk_$$m.out | cut -c1-100)"; \
	  n=$$((n + 1)); \
	done; \
	$(CC) $(FUZZ_CFLAGS) -DWE_SUM_TEST_NO_LINE_BOUND -o $(FUZZ_DIR)/fuzz_summary_NO_LINE_BOUND fuzz_summary.c we_sha256.c; \
	if $(FUZZ_DIR)/fuzz_summary_NO_LINE_BOUND --replay $(FUZZ_DIR)/summary-seeds > $(FUZZ_DIR)/fuzz_summary_ctl.out 2>&1 \
	   || ! grep -q AddressSanitizer $(FUZZ_DIR)/fuzz_summary_ctl.out; then \
	  echo "CHECK FAIL: the fuzz_summary control (no line bound) was not stopped by ASan"; exit 1; fi; \
	echo "ok   fuzz_summary control WE_SUM_TEST_NO_LINE_BOUND stopped by ASan"; \
	echo "$$((n + 1)) mutant checks, 0 failures"

fuzz-replay: fuzz_policy_replay fuzz_program_replay fuzz-planes
	./fuzz_policy_replay --replay testdata --planes $(FUZZ_PLANES) --floor $(POLICY_REPLAY_FLOOR)
	./fuzz_program_replay --replay testdata/policy/accept --planes $(FUZZ_PLANES) --mutations $(FUZZ_MUTATIONS)

# The reader against the INDEPENDENT writer: make-test-snapshot.py writes every plane in both formats
# with every index kind, and plane_check holds the reader to the answer and the record bytes the writer
# says each deciding address must get. Part of `all`; it needs python3, which every gate here does.
plane_check: plane_check.c we_record_fields.h $(CORE_SRC) $(CORE_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ plane_check.c $(CORE_SRC)

check-py: plane_check
	@mkdir -p $(TMPDIR_)/py
	@set -e; \
	run() { \
	  python3 make-test-snapshot.py --plane $$1 --out $(TMPDIR_)/py/$$1.bin --format $$2 \
	    --v4-index $$3 --v6-index $$4 $$5 --expect $(TMPDIR_)/py/$$1.txt; \
	  ./plane_check $(TMPDIR_)/py/$$1.bin $(TMPDIR_)/py/$$1.txt; \
	}; \
	run reputation 1 none none --schema; \
	run reputation 1 radix-16 radix-16 --schema; \
	run reputation 1 radix-16 none; \
	run routing 2 radix-18 rank; \
	run routing 2 rank radix-12; \
	run registry 2 radix-16 rank; \
	run tor 2 radix-12 rank; \
	run anonymizer 2 rank radix-18; \
	run threat 2 none radix-16; \
	run rpki-unreachable 2 radix-16 none; \
	run tenant 2 rank rank; \
	./xserver-cases.sh --selftest
	@$(MAKE) --no-print-directory dump-full-san
	@$(MAKE) --no-print-directory check-rpz-oracle

# plane_check --rpz-oracle, the policy zone held to the plane it was written from: a faithful zone agrees
# and every disagreement its controls plant is seen (rpz-oracle-check.sh says which), with the plain build
# and again under the sanitizers, since the oracle parses owner names and walks a trie it grew itself.
check-rpz-oracle: plane_check
	@mkdir -p $(TMPDIR_)/rpzoracle
	@$(CC) $(FUZZ_CFLAGS) -o $(TMPDIR_)/rpzoracle/plane_check plane_check.c $(CORE_SRC)
	@./rpz-oracle-check.sh ./plane_check $(TMPDIR_)/rpzoracle/plain
	@./rpz-oracle-check.sh $(TMPDIR_)/rpzoracle/plane_check $(TMPDIR_)/rpzoracle/san
	@echo "ok   plane_check --rpz-oracle, plain and $(if $(FUZZ_SAN),under ASan and UBSan,unsanitized: no ASan/UBSan in this toolchain)"

# plane_check --dump-full under the sanitizers (ASan and UBSan where the toolchain has them, the fuzz
# replays' flags) over every committed format-2 fixture and the fuzz-planes corpus: the escape path walks
# every feed name byte by byte and the header and record reads index the mapping, so a read past a name or
# a record is a sanitizer report, not a quiet wrong line. Every plane must load and print, and every --dump
# line must stay four fields, the interface a deployed consumer parses.
dump-full-san: fuzz-planes
	@mkdir -p $(TMPDIR_)/dumpfull
	@$(CC) $(FUZZ_CFLAGS) -o $(TMPDIR_)/dumpfull/plane_check plane_check.c $(CORE_SRC)
	@set -e; n=0; \
	if [ -z "$(FUZZ_SAN)" ]; then echo "  (no ASan/UBSan in this toolchain: --dump-full ran unsanitized)"; fi; \
	for f in testdata/format2/*.bin $(FUZZ_PLANES)/*.bin; do \
	  p=$$(python3 -c 'import struct,sys; d=open(sys.argv[1],"rb").read(192); \
	    print({1:"reputation",2:"tor",3:"rpki-unreachable",4:"routing",5:"anonymizer",6:"threat",7:"registry",8:"tenant"}.get(d[136],"reputation") if struct.unpack_from("<I",d,12)[0] & 4 else "reputation")' "$$f"); \
	  d=$(TMPDIR_)/dumpfull/$$n; mkdir -p $$d; cp "$$f" $$d/$$p.bin; chmod 0644 $$d/$$p.bin; \
	  $(TMPDIR_)/dumpfull/plane_check --dump-full $$d/$$p.bin > $$d/full.txt 2> $$d/err.txt \
	    || { cat $$d/err.txt; echo "CHECK FAIL: plane_check --dump-full on $$f"; exit 1; }; \
	  $(TMPDIR_)/dumpfull/plane_check --dump $$d/$$p.bin > $$d/dump.txt 2> /dev/null; \
	  awk 'NF != 4 { bad = 1 } END { exit bad }' $$d/dump.txt \
	    || { echo "CHECK FAIL: plane_check --dump printed a line that is not four fields on $$f"; exit 1; }; \
	  n=$$((n + 1)); \
	done; \
	echo "ok   plane_check --dump-full over $$n planes (the format-2 fixtures and the fuzz corpus), $(if $(FUZZ_SAN),under ASan and UBSan,unsanitized), --dump four fields each"

# The LIVE-SHAPED bound: the same per-lookup equality over every outcome class of the flattened
# RouteViews tables, and the maxima a production plane of that shape costs (IPv4 radix-18, IPv6
# rank-64). Not part of `check`, because its inputs are fetched (fixtures/README.md says why they are
# not committed): `make fixtures` builds them, from RIB_DIR when a cached copy is there, and fails on
# any digest that does not match. The mutant must fail on the live table too.
#
# And the policy evaluator over the same live table (gate/live-legs.sh, POLICY.md section 6): the
# DIFFERENTIAL, the C evaluator's verdicts on 2,000 requests against the live routing plane equal to the
# reference interpreter's, and the COST, every request's 64-byte lines equal to the line model's (rows
# C3 and C5). Each DARK by name until the evaluator, and for the differential the interpreter, is here.
RIB_DIR ?= rib

fixtures:
	@./fixtures/make-fixtures.sh $(RIB_DIR)

check-live: test_trace test_mutant fixtures
	@mkdir -p $(TMPDIR_)
	./test_trace $(TMPDIR_) --live fixtures
	./test_mutant $(TMPDIR_) --live fixtures
	@./gate/live-legs.sh $(TMPDIR_)/live

# The LIFECYCLE concurrency, which `check` is single-threaded and cannot reach. It is part of `all`
# because the header promises the core is safe "in a thread" and nothing used to look: both retire-slot
# transitions were a load-then-store, which is an unbounded invisible leak on the claim side and a
# DOUBLE FREE on the reclaim side. nginx has one thread per worker so it could not fire there; Apache
# worker/event and LiteSpeed are threaded.
#
# Built TWICE when the toolchain has ThreadSanitizer, and it says which it ran. The plain build is the
# one that must always work: it detects the claim bug by ACCOUNTING (a mapping that is neither current,
# nor in a slot, nor counted as leaked has been overwritten) and the reclaim bug by surviving, since a
# double free of a heap pointer aborts. TSan turns both into a direct race report instead of a
# consequence, which is better, but a test only run under a sanitizer is a test most people never run.
RACE_CFLAGS = -std=c11 -O1 -g -Wall -Wextra -Werror -pthread

race_core: race_core.c $(CORE_SRC) $(CORE_HDR)
	$(CC) $(RACE_CFLAGS) -o $@ race_core.c $(CORE_SRC)

race: race_core
	@mkdir -p $(TMPDIR_)
	./race_core $(TMPDIR_) testdata/interop.snap
	@if printf 'int main(void){return 0;}' > $(TMPDIR_)/tsan.c \
	    && $(CC) -fsanitize=thread -o $(TMPDIR_)/tsan $(TMPDIR_)/tsan.c 2>/dev/null \
	    && $(TMPDIR_)/tsan; then \
	    echo "  and again under ThreadSanitizer:"; \
	    $(CC) $(RACE_CFLAGS) -fsanitize=thread -o race_core_tsan race_core.c $(CORE_SRC); \
	    ./race_core_tsan $(TMPDIR_) testdata/interop.snap; \
	else \
	    echo "  (no ThreadSanitizer in this toolchain; the accounting and abort checks above ran)"; \
	fi

gate:
	@./hotpath-gate.sh $(TMPDIR_)/gate
	@./gate/eval-sites.sh $(TMPDIR_)/eval-sites

# Cross-language format agreement against the BUILDER'S fixture: testdata/interop.snap was written by
# the real Java builder and frozen there, so the gate needs no JDK, only a C compiler. It is its own
# target rather than part of `all` (CI runs it as a separate step, `make interop` at the tree's root), and it
# fails rather than skips when the fixture is absent. The second independent writer, the Python one,
# is held to the reader by `check-py`, which is part of `all`.
# For format 2 it also reads the builder's planes under testdata/format2/ ({routing,tor}.bin with their
# expected answers and manifest object) and requires: the file's sha256 is the manifest's, the reader
# answers every expected line, and the trace build's maxima over every outcome class of the file EQUAL
# the manifest's lookup block and workingSetBytes.
interop:
	@./interop-gate.sh $(TMPDIR_)/interop

# The development tree's own tooling (a gate that holds what its CI measures stable against a base
# revision) lives in development.mk, which is left out of the published tree on purpose; nothing
# here needs it, and make reads on without it.
-include development.mk

# THE COST ROWS. cachegrind-gate.sh on this host's architecture, then a refusal to read CLEAR while any
# evaluator or module slot lacks a baseline on either architecture, naming the slot and the architecture.
# Not part of `all`: valgrind runs for a long while, so the merge runs it explicitly.
.PHONY: cachegrind
cachegrind:
	@./cachegrind-target.sh $(TMPDIR_)/cachegrind

# The reference interpreter's verdicts for every evaluator slot of the cachegrind driver, which the
# cachegrind gate holds the C evaluator to before it prices a slot; DARK by name until policy_ref.py
# is in the tree. Rewritten files are committed with the change that moved them.
.PHONY: verdicts
verdicts:
	@./gate/reference-verdicts.sh $(TMPDIR_)/verdicts

# The record is written and READ BACK: check-record.py holds it to its shape, after its own controls
# (a record missing its commit, a layout row, or with a rule under its instruction floor is refused).
bench: bench_core
	@mkdir -p $(TMPDIR_)
	@echo "run this on an idle box; see the note at the top of bench_core.c"
	./bench_core $(TMPDIR_) $(TMPDIR_)/bench-record.json
	python3 bench/check-record.py --selftest $(TMPDIR_)/bench-record.json
	python3 bench/check-record.py $(TMPDIR_)/bench-record.json '$(WE_COMMIT)'

clean:
	rm -f *.o *.a test_core test_trace test_mutant test_policy test_module test_summary plane_check bench_core whisper-edge-lookup whisper-edge-summary race_core race_core_tsan
	rm -f fuzz_policy_replay fuzz_program_replay fuzz_walk_replay fuzz_summary_replay
	rm -rf __pycache__ gate/__pycache__ bench/__pycache__
	rm -rf $(TMPDIR_)
