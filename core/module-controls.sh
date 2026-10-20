#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
#
# module-controls.sh - the negative controls for test_module, every run.
#
# Each control is a -D build of test_module that plants one known defect in we_module.h or we_module.c.
# It must FAIL, and fail on the check named for it below: a control that fails some other check has
# shown nothing about the check that claims to catch it. Two are stopped by a sanitizer instead, because
# what they plant is a memory error only a sanitizer build sees: the country control reads past the
# renderer's table, and the spec control writes a counter past a shard of the configured length. Each
# must be stopped by its named report, in its named frame, and never pass.
#
# Then the guard on the controls themselves: a build without WE_MOD_CONTROL_BUILD must refuse every one.
#
# Prints one `N mutant checks, F failures` line for the README count; exits non-zero if any control was
# not caught where it is named.
#
# Usage: module-controls.sh <workdir> <planes dir> <cc> <cflags...>
set -u

OUT=$1
PLANES=$2
shift 2
CC=$1
shift
CFLAGS=("$@")
SRC=(test_module.c we_module.c whisper_edge.c we_sha256.c we_counters.c we_policy.c we_writer.c)

# control : the check that must fail, as test_module prints it (a bare name is WE_MOD_TEST_<name>)
CONTROLS=(
    "WE_MOD_TEST_UNMERGED_TRUST:FAIL trust build 10.0.0.0/8 ...: 10.2.0.1 not trusted"
    "WE_MOD_TEST_PEER_ON_UNPARSED:FAIL walk C, junk, T1:"
    "WE_MOD_TEST_NO_HOP_CAP:FAIL walk 17 trusted, skip mode:"
    "WE_MOD_TEST_COUNT_DEFAULT:FAIL decide default allow:"
    "WE_MOD_TEST_NO_LAZY:FAIL record write: the lazy fill:"
    "WE_MOD_TEST_NO_LINE_CLAMP:FAIL walk cap: 17 lines do not walk as the newest 16"
    "WE_MOD_TEST_SEVERITY_SCAN:FAIL severity: the all-clear allow tested 512 bits"
    "WE_MOD_TEST_ALLOW_NETFS:FAIL binding: NFS (0x6969), FUSE and CIFS are not recognised"
    "WE_MOD_TEST_RAW_NAMES:FAIL config: the escaped name is"
    "WE_MOD_TEST_NO_PIN:FAIL thread: not started: the object was not pinned"
    "WE_MOD_TEST_NO_THREAD:FAIL thread: not started: pthread_create"
    "WE_MOD_PLANT_CALL:FAIL V2 (seccomp: any system call kills): the decision and the cold half did not run clean (killed by signal"
    "WE_MOD_PLANT_CALL_WALK:FAIL V2 (seccomp: any system call kills): the decision and the cold half did not run clean (killed by signal"
    "WE_MOD_TEST_PLANT_ALLOC:FAIL N2 (malloc, calloc, realloc and free abort): the decision and the cold half did not run clean (killed by signal 6)"
    "WE_MOD_TEST_PRINT_UNMEASURED:FAIL writers: the status file prints a field nobody measured"
    "WE_MOD_TEST_TENANT_BY_MASK:FAIL tenant: a listed tenant.bin with no caller bit was not bound"
    "WE_MOD_TEST_RETIRE_UNCHECKED:FAIL retire bound: the plane held"
    "WE_MOD_TEST_LOG_LIFO:FAIL log order: one tick's lines reached the logger out of tick order"
    "WE_MOD_TEST_RETIRE_LOCKED:FAIL retire bound: the locked bytes"
    "WE_MOD_TEST_UNCUT_LOG:FAIL transitions: the logger's line is not the ring's entry"
    "WE_MOD_TEST_HEAD_ALONE:FAIL transitions: the logger's line is not the ring's entry"
    "WE_MOD_TEST_UNREADABLE_BOUND:FAIL unreadable: a plane the configuration reader cannot open is bound 1"
    "WE_MOD_TEST_NOMAP_CLAMP:FAIL unfilled snapshot: the token of a bound path with no file is \"reputation:-l\""
    "WE_MOD_TEST_ABSENT_REFUSED:FAIL unfilled snapshot: a snapshot path with no file yet reads \"refused\", not absent"
    "WE_MOD_TEST_BIND_LEAVES_POINTERS:FAIL bind refused: a refused binding left the configuration changed"
    "WE_MOD_TEST_PLANE_REFUSAL_WHOLE:FAIL plane refused: one refused plane refused the whole binding"
    "WE_MOD_TEST_REFUSED_UNSAID:FAIL plane refused: the status file does not name the refused plane"
    "WE_MOD_TEST_CHECK_NO_VERIFY:FAIL bind check: the check-only bind and the bind disagree"
    "WE_MOD_TEST_PATH_TWICE:FAIL bind paths: form 1 plane 0: configuration time"
    "WE_MOD_TEST_COUNTERS_FIRST_DIR:FAIL bind paths: per-plane files in two directories were not refused naming the counters directive"
    "WE_MOD_TEST_APPEND:FAIL replace: a child's one line ran 5 rule(s) under a parent of 4"
    "WE_MOD_TEST_SNAPSHOT_FALLBACK:FAIL plane file: a directory holding only snapshot.bin bound the reputation plane"
    "WE_MOD_TEST_FIRST_LINE:FAIL walk lines: after one forged field line the proxy's line was not the one judged"
    "WE_MOD_TEST_FIRST_16_LINES:FAIL walk lines: after sixteen forged field lines the proxy's line was not the one judged"
    "WE_MOD_TEST_WORKER_SCRATCH_FILL:FAIL interleave: A's record filled after B's decision renders"
    "WE_MOD_TEST_RESOLVED_CHAIN_ONLY:FAIL binding: a link inside a world-writable directory is followed"
    "WE_MOD_TEST_REOPEN_BY_PATH:FAIL repointed: repointing the data directory's link at another directory revoked the live allow list"
    "WE_MOD_TEST_CAP_OFF:FAIL config cap: 65,800 slots were not refused naming the contexts"
    "WE_MOD_TEST_THREAD_MASK:FAIL thread: the module thread does not hold the full asynchronous mask"
    "WE_MOD_TEST_CTIME_NO_DIGEST:FAIL planes: bytes rewritten in place with the mtime restored still serve"
    "WE_MOD_TEST_DROP_ARMED:FAIL planes: a corrupt candidate replaced the armed map"
    "WE_MOD_TEST_HW_LOOSE:FAIL high-water: 6 malformed mark(s) armed the tenant plane"
    "WE_MOD_TEST_HW_ROOT_ONLY:FAIL high-water: a mark owned by the trusted uid at 6 did not let generation 7 arm"
    "WE_MOD_TEST_LEGACY_OWNER_SILENT:FAIL legacy owner: a snapshot owned by uid"
    "WE_MOD_TEST_DIGEST_SILENT:FAIL digest progress: the bind left the digest without a progress mark"
    "WE_MOD_TEST_FORK_KEEPS_MONITOR:FAIL monitor: a child forked mid-verification kept the parent's verification"
    "WE_MOD_TEST_SPSC_UNCHECKED:FAIL spsc: a second posting thread on one slot was not refused"
    "WE_MOD_TEST_FAIL_IDENT_ONLY:FAIL fail identity: a new generation carrying a remembered failure's identity was skipped"
    "WE_MOD_TEST_DIGEST_UNCOUNTED:FAIL digest counts: the worker start's digest of a touched plane reads digests 0"
    "WE_MOD_TEST_COUNTERS_AT_ROOT:FAIL bind paths: a snapshot at the filesystem root gave the counters directory /counters"
    "WE_MOD_TEST_PLANE_FILE_IGNORED:FAIL plane file: a per-plane file over the directory bound generation"
    "WE_MOD_TEST_SNAPSHOT_DROPPED:FAIL plane file: a snapshot beside a directory bound generation 100"
    "WE_MOD_TEST_NO_START_STAT:FAIL start truncate: the worker start did not notice the inherited plane truncated in place"
    "WE_MOD_TEST_SERVE_INHERITED:FAIL start truncate: the worker start left the truncated inherited mapping serving"
    "WE_MOD_TEST_LEN_OFF:FAIL word lengths: 1 length(s) are not their word's"
    "WE_MOD_TEST_FLAT_DEADLINE:FAIL bounded stop: a slow progressing final write was abandoned"
    "WE_MOD_TEST_NULL_WORD_UNPOSTED:FAIL no-map reason: a plane refused at load whose next generation is being verified reads \"loading\" and \"reputation:-r\""
)
macro_of() { printf '%s' "$1"; }   # every entry names its define in full: the guard reads each literally
# the controls whose rows live in the debug build alone (their seam, check or counters exist only there), so
# they are built with WE_MOD_DEBUG; in a release harness those rows say they are covered by the debug build
DEBUG_CONTROLS=" WE_MOD_TEST_SPSC_UNCHECKED WE_MOD_TEST_FAIL_IDENT_ONLY WE_MOD_TEST_DIGEST_UNCOUNTED "

mkdir -p "$OUT/module-controls"
checks=0
fails=0
for row in "${CONTROLS[@]}"; do
    name=${row%%:*}
    want=${row#*:}
    macro=$(macro_of "$name")
    bin="$OUT/module-controls/test_module_$name"
    checks=$((checks + 1))
    dbg=(); case "$DEBUG_CONTROLS" in *" $macro "*) dbg=(-DWE_MOD_DEBUG) ;; esac
    if ! "$CC" "${CFLAGS[@]}" "${dbg[@]}" -DWE_MOD_CONTROL_BUILD -D"$macro" -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
        echo "CONTROL FAIL: $macro does not build: $(head -1 "$bin.err")"
        fails=$((fails + 1))
        continue
    fi
    "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1
    rc=$?
    line=$(grep -F -m1 -- "$want" "$bin.out" || true)
    if [ "$rc" -eq 0 ] || [ -z "$line" ]; then
        echo "CONTROL FAIL: $macro was not caught by \"$want\" (exit $rc; first failure: $(grep -m1 '^FAIL' "$bin.out" || echo none))"
        fails=$((fails + 1))
    elif [ "$rc" -gt 1 ] || grep -q -e '^==[0-9]*==ERROR' -e 'runtime error:' "$bin.out"; then
        # a control fails by the property it plants, read by its row, and exits as a failed run does (1);
        # a signal, an abort or a sanitizer report is undefined behaviour reading as a catch
        echo "CONTROL FAIL: $macro failed its row but did not exit normally (exit $rc): a control must fail by value, never by a crash"
        fails=$((fails + 1))
    else
        echo "ok   $macro caught: $line"
    fi
done

# the retire bound in the debug build: a publish that finds no free slot is unreachable there, so the
# unchecked control aborts at the push rather than losing the map quietly
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_RETIRE_UNCHECKED_DEBUG"
if "$CC" "${CFLAGS[@]}" -DWE_MOD_DEBUG -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_RETIRE_UNCHECKED -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
    # The binary is EXPECTED to die of SIGABRT. It runs as the grandchild of this script, inside a subshell
    # that waits for it, so bash's job-control line for a child killed by a signal ("Aborted (core dumped)")
    # lands in the control's own output file and never in this harness's log, where it once read as an
    # unnamed failure beside the one control that did fail by name. The subshell records the binary's pid,
    # which names the row's base directory below.
    (ulimit -c 0; "$bin" "$OUT" "$PLANES" & p=$!; echo "$p" >"$bin.pid"; wait "$p") >"$bin.out" 2>&1 &
    wait $!
    rc=$?
    pid=$(cat "$bin.pid" 2>/dev/null || echo 0)
    # an abort runs no cleanup: the row's base is removed here (wherever trusted_base put it)
    for b in "$OUT" "${XDG_RUNTIME_DIR:-}" "/run/user/$(id -u)" "${HOME:-}"; do
        if [ "$pid" != 0 ] && [ -n "$b" ] && [ -d "$b/we-test-module.$pid" ]; then
            chmod -R u+w "$b/we-test-module.$pid" && rm -rf -- "$b/we-test-module.$pid"
        fi
    done
    if [ "$rc" -eq 134 ]; then
        echo "ok   WE_MOD_TEST_RETIRE_UNCHECKED (debug build) caught: the failed push aborted (exit 134, SIGABRT; the binary's own output holds the shell's job line)"
    else
        echo "CONTROL FAIL: WE_MOD_TEST_RETIRE_UNCHECKED in the debug build did not abort at the push (exit $rc)"
        fails=$((fails + 1))
    fi
else
    echo "CONTROL FAIL: the debug control build does not build: $(head -1 "$bin.err")"
    fails=$((fails + 1))
fi

# the root refusal's typed return, through the seam build that reads its euid as 0 (the row cannot run as
# root, so the seam is how a non-root gate proves it), and the same mode in a build without the seam refused
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_EUID0"
if "$CC" "${CFLAGS[@]}" -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_EUID0 -o "$bin" "${SRC[@]}" 2>"$bin.err" \
   && "$bin" --root-refusal "$OUT" >"$bin.out" 2>&1 && grep -q '^ok   root refusal: WE_ERR_PERMISSIONS' "$bin.out"; then
    head -1 "$bin.out"
else
    echo "CONTROL FAIL: the root refusal row: $(grep -m1 -E '^(FAIL|ok)' "$bin.out" 2>/dev/null || head -1 "$bin.err")"
    fails=$((fails + 1))
fi

# the clean arm of the next control: the same trace build WITHOUT the mutant passes every row, so the
# control moves one variable (the reset), not two (the reset and WE_TRACE)
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_TRACE_CLEAN"
if "$CC" "${CFLAGS[@]}" -DWE_TRACE -o "$bin" "${SRC[@]}" 2>"$bin.err" && "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1; then
    echo "ok   the trace build of test_module passes clean: $(tail -1 "$bin.out")"
else
    echo "CONTROL FAIL: the trace build of test_module does not pass clean, so the memo control moves two variables: $(grep -m1 '^FAIL' "$bin.out" 2>/dev/null || head -1 "$bin.err")"
    fails=$((fails + 1))
fi

# a scratch reused across requests: the trace build without the evaluator's memo reset serves the stale memo,
# and the reuse row must say so (the control lives in the evaluator, so it is a trace build, not a module one)
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_NO_MEMO_RESET"
want="FAIL scratch reuse: a reused scratch served the previous request's tor entry"
if "$CC" "${CFLAGS[@]}" -DWE_TRACE -DWE_TEST_NO_MEMO_RESET -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
    "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] && grep -qF -- "$want" "$bin.out"; then
        echo "ok   WE_TEST_NO_MEMO_RESET (trace build) caught: $(grep -F -m1 -- "$want" "$bin.out")"
    else
        echo "CONTROL FAIL: WE_TEST_NO_MEMO_RESET was not caught by the scratch reuse row (exit $rc)"
        fails=$((fails + 1))
    fi
else
    echo "CONTROL FAIL: the trace build of test_module does not build: $(head -1 "$bin.err")"
    fails=$((fails + 1))
fi

# N2's interleave arm: two writers on one shard lose exactly the interleaved increments, which is why each
# thread counts into its own shard (WE_MOD_TEST_INTERLEAVE puts a barrier between the load and the store)
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_INTERLEAVE"
if "$CC" "${CFLAGS[@]}" -pthread -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_INTERLEAVE -o "$bin" "${SRC[@]}" 2>"$bin.err" \
   && "$bin" --interleave >"$bin.out" 2>&1 && grep -q '4 lost, exactly the 4 interleaved' "$bin.out"; then
    echo "ok   WE_MOD_TEST_INTERLEAVE: $(head -1 "$bin.out")"
else
    echo "CONTROL FAIL: WE_MOD_TEST_INTERLEAVE did not lose exactly the interleaved increments: $(head -1 "$bin.out" 2>/dev/null)"
    fails=$((fails + 1))
fi

# E1: the decision and the record under memcheck with the scratch and the record undefined; clean, and its
# control (the reputation view left as the scratch held it) reported as an uninitialised read
if command -v valgrind >/dev/null 2>&1; then
    # the release build clean and three controls, then the trace build clean and the lazy fill's control
    # (row E1: the unwritten view, sc.ss copied on a pre-stage outcome, a lazy fill without its clear)
    for arm in clean WE_MOD_TEST_PLANT_UNINIT WE_MOD_TEST_SS_UNCONDITIONAL trace-clean trace-WE_MOD_TEST_LAZY_NO_CLEAR; do
        checks=$((checks + 1))
        bin="$OUT/module-controls/test_module_memcheck_$arm"
        def=()
        case "$arm" in
            clean) ;;
            trace-clean) def=(-DWE_TRACE) ;;
            trace-*) def=(-DWE_TRACE -DWE_MOD_CONTROL_BUILD "-D${arm#trace-}") ;;
            *) def=(-DWE_MOD_CONTROL_BUILD "-D$arm") ;;
        esac
        if ! "$CC" -std=c11 -O1 -g -DWE_TEST_NO_ALLOC_TRAP "${def[@]}" -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
            echo "CONTROL FAIL: the memcheck build ($arm) does not build: $(head -1 "$bin.err")"
            fails=$((fails + 1))
            continue
        fi
        # a control may go on to dereference what it read uninitialised (SS_UNCONDITIONAL does): no core file,
        # and the outer subshell is the one that waits on a death by signal, so bash's job notice for it
        # ("Segmentation fault") lands in $bin.out and the outer subshell exits 128+N without one of its own
        ( (ulimit -c 0; exec valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes "$bin" --memcheck "$PLANES")
          exit $? ) >"$bin.out" 2>&1
        rc=$?
        if [ "$arm" = clean ] || [ "$arm" = trace-clean ]; then
            if [ "$rc" -eq 0 ] && grep -q 'ERROR SUMMARY: 0 errors' "$bin.out"; then
                echo "ok   E1 memcheck ($arm): the decision, the record and the lazy fill read nothing uninitialised: $(grep -m1 'ERROR SUMMARY' "$bin.out" | sed 's/^==[0-9]*== //')"
            else
                echo "CONTROL FAIL: E1 memcheck reported on the $arm build (exit $rc): $(grep -m1 -E 'uninitialised|ERROR SUMMARY' "$bin.out")"
                fails=$((fails + 1))
            fi
        elif [ "$rc" -ne 0 ] && grep -qE 'depends on uninitialised value|Use of uninitialised value' "$bin.out"; then
            echo "ok   ${arm#trace-} ($arm) caught by memcheck: $(grep -m1 -E 'depends on uninitialised value|Use of uninitialised value' "$bin.out" | sed 's/^==[0-9]*== //')"
            if [ "$arm" = WE_MOD_TEST_SS_UNCONDITIONAL ] && [ "$rc" -eq 139 ]; then
                echo "ok   $arm then died of SIGSEGV, as expected: it dereferences the view memcheck just reported, which the step guard in production never reaches"
            fi
        else
            echo "CONTROL FAIL: ${arm#trace-} ($arm) was not reported by memcheck (exit $rc)"
            fails=$((fails + 1))
        fi
    done
else
    checks=$((checks + 5))
    fails=$((fails + 5))
    echo "CONTROL FAIL: E1 needs valgrind, which is not installed"
fi

# the sanitizer controls: control : the report that must stop it, and the frame it must name
SAN_CONTROLS=(
    "WE_MOD_TEST_NO_COUNTRY_COMPARE:runtime error|AddressSanitizer:we_attr_render_fast"
    "WE_MOD_TEST_SPEC_UNCHECKED:AddressSanitizer: heap-buffer-overflow:t_config_spec"
)
san=$(d=$(mktemp -d) && printf 'int main(void){return 0;}' > "$d/p.c" && "$CC" -fsanitize=address,undefined -o "$d/p" "$d/p.c" 2>/dev/null && echo yes; rm -rf "$d")
for row in "${SAN_CONTROLS[@]}"; do
    name=${row%%:*}
    rest=${row#*:}
    want=${rest%:*}
    frame=${rest##*:}
    checks=$((checks + 1))
    if [ "$san" != yes ]; then
        echo "CONTROL FAIL: $name needs a sanitizer build, and $CC has none"
        fails=$((fails + 1))
        continue
    fi
    bin="$OUT/module-controls/test_module_$name"
    "$CC" -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -DWE_MOD_CONTROL_BUILD \
        -D"$name" -o "$bin" "${SRC[@]}" 2>"$bin.err"
    UBSAN_OPTIONS=print_stacktrace=1 "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1
    rc=$?
    # the first report that is not a forked child's planted store into a sealed block (a SEGV row of its own)
    report=$(grep -E "$want" "$bin.out" | grep -v 'SEGV' | head -1 || true)
    if [ "$rc" -ne 0 ] && [ -n "$report" ] && grep -q " in $frame " <<<"$(grep -A12 -F -- "$report" "$bin.out")"; then
        echo "ok   $name stopped by the sanitizer in $frame: $(cut -c1-140 <<<"$report")"
    else
        echo "CONTROL FAIL: $name was not stopped by \"$want\" in $frame (exit $rc)"
        fails=$((fails + 1))
    fi
done

# the gates' pause: WE_MOD_TEST_PAUSE_TICK's own rows hold at both points (tick, loading) and read the held
# plane as loading and -l; its control, the same build whose hook never holds, fails them by name; and the
# two other pause builds compile, link and pass clean when nothing asks them to hold
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_PAUSE_TICK"
if "$CC" "${CFLAGS[@]}" -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK -o "$bin" "${SRC[@]}" 2>"$bin.err" \
   && "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1 && [ "$(grep -c '^ok   pause: ' "$bin.out")" = 3 ]; then
    echo "ok   WE_MOD_TEST_PAUSE_TICK holds: $(grep '^ok   pause: ' "$bin.out" | cut -c13- | tr '\n' ';' | sed 's/;$//')"
else
    echo "CONTROL FAIL: the pause rows: $(grep -m1 '^FAIL' "$bin.out" 2>/dev/null || head -1 "$bin.err")"
    fails=$((fails + 1))
fi
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_PAUSE_NO_HOLD"
want="FAIL pause: the tick was not held at loading"
if "$CC" "${CFLAGS[@]}" -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_PAUSE_TICK -DWE_MOD_TEST_PAUSE_NO_HOLD -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
    "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] && grep -qF -- "$want" "$bin.out" && grep -qF -- "FAIL pause: the tick was not held at tick" "$bin.out" \
       && grep -qF -- "FAIL pause: the supervisor's monitor was not held at monitor" "$bin.out"; then
        echo "ok   WE_MOD_TEST_PAUSE_NO_HOLD caught at all three points: $want"
    else
        echo "CONTROL FAIL: WE_MOD_TEST_PAUSE_NO_HOLD was not caught by \"$want\" and its tick twin (exit $rc)"
        fails=$((fails + 1))
    fi
else
    echo "CONTROL FAIL: WE_MOD_TEST_PAUSE_NO_HOLD does not build: $(head -1 "$bin.err")"
    fails=$((fails + 1))
fi
for name in WE_MOD_TEST_PAUSE_BEFORE_RENAME WE_MOD_TEST_PAUSE_AFTER_FSTAT; do
    checks=$((checks + 1))
    bin="$OUT/module-controls/test_module_$name"
    if "$CC" "${CFLAGS[@]}" -DWE_MOD_CONTROL_BUILD -D"$name" -o "$bin" "${SRC[@]}" 2>"$bin.err" \
       && "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1; then
        echo "ok   $name builds and passes clean with no hold: $(tail -1 "$bin.out")"
    else
        echo "CONTROL FAIL: $name: $(grep -m1 '^FAIL' "$bin.out" 2>/dev/null || head -1 "$bin.err")"
        fails=$((fails + 1))
    fi
done

# the debug build's tail count (the truncate row): a counter a worker keeps in its own memory dies with
# the worker that touched the truncated tail, so the private-page control must lose the dead child's count
checks=$((checks + 1))
bin="$OUT/module-controls/test_module_TAIL_PRIVATE"
want="FAIL debug tail: a worker that counted its request and died of signal 7 left 1 counted, not 2"
if "$CC" "${CFLAGS[@]}" -DWE_MOD_DEBUG -DWE_MOD_CONTROL_BUILD -DWE_MOD_TEST_TAIL_PRIVATE -o "$bin" "${SRC[@]}" 2>"$bin.err"; then
    "$bin" "$OUT" "$PLANES" >"$bin.out" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] && grep -qF -- "$want" "$bin.out"; then
        echo "ok   WE_MOD_TEST_TAIL_PRIVATE (debug build) caught: $want"
    else
        echo "CONTROL FAIL: WE_MOD_TEST_TAIL_PRIVATE was not caught by \"$want\" (exit $rc)"
        fails=$((fails + 1))
    fi
else
    echo "CONTROL FAIL: WE_MOD_TEST_TAIL_PRIVATE does not build: $(head -1 "$bin.err")"
    fails=$((fails + 1))
fi

# a build that is not a control build refuses every control
for row in "${CONTROLS[@]}" "${SAN_CONTROLS[@]}" "WE_MOD_TEST_PLANT_UNINIT:" "WE_MOD_TEST_PAUSE_NO_HOLD:" "WE_MOD_TEST_PAUSE_TICK:" "WE_MOD_TEST_TAIL_PRIVATE:"; do
    name=${row%%:*}
    macro=$(macro_of "$name")
    checks=$((checks + 1))
    # refused by the guard's own #error, not by any other compile failure
    if "$CC" "${CFLAGS[@]}" -D"$macro" -c -o /dev/null we_module.c 2>"$OUT/module-controls/guard_$name.err" \
       || ! grep -q 'exist only in a gate.s control build' "$OUT/module-controls/guard_$name.err"; then
        echo "CONTROL FAIL: a build without WE_MOD_CONTROL_BUILD was not refused by the guard for $macro"
        fails=$((fails + 1))
    fi
done
echo "$checks mutant checks, $fails failures"
[ "$fails" -eq 0 ]
