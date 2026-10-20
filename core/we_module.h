/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_module.h - what the nginx, Apache and LiteSpeed modules share on and around the request path.
 *
 * ONE DECISION FUNCTION, GATED TWICE. we_mod_decide() is the whole request path from "the module has
 * the two canonical addresses and the clock" to "the verdict is written and the fired rules are
 * counted": it fills the views of exactly the planes the two programs read, runs the evaluator, and
 * counts into the calling thread's shard. It is server-free and force-inlined; each module wraps it
 * once in a `noinline` symbol of its own and calls that wrapper from every place it evaluates, and the
 * hot-path gate disassembles the generic wrapper (hp_mod.c) while each module gate disassembles its
 * own. What the gates prove is the evaluator's list: no call, no relocation beyond the expected
 * table, no atomic other than the acquire loads of the view pointers, no fence, and a frame under the
 * evaluator's bound. Locals: none on aarch64 under gcc and clang; the x86_64 legs below keep a measured spill
 * the gate's expected-locals table holds exactly (on x86_64 gcc 13 at -O keeps 8 bytes, the verdict pointer
 * across the rule loop; on x86_64 gcc 14 at -O keeps 8 bytes, the same spill; on x86_64 clang 18 under
 * -fno-omit-frame-pointer keeps 16 bytes; on x86_64 clang 19 under the same flag keeps 16 bytes; on
 * x86_64 clang 20 under the same flag keeps 16 bytes), so a byte more or a byte fewer fails by name and
 * every change to this function re-measures it; locals-claims.sh holds this
 * sentence and that table to each other, in both directions.
 *
 * EVERYTHING ELSE HERE IS COLD, and none of it is in the gated function: the trusted-header walk and
 * the grammar of one entry, the ACME test, the RFC 5952 address formatter, the request record that
 * outlives the handler, and the renderers the variables read through. What is proven of them, and of
 * the decision, is bounded by the inputs the rows run: over the walk corpus's 20 input classes
 * (walk_classes.h: IPv4 and IPv6 peers and trust lists, each class's server apart from its floor and
 * aliased to it) and six ACME shapes carried into the decision, test_module runs the walk, the decision,
 * the record, a lazy fill on a stack local and every request-path renderer under a seccomp filter that
 * kills the process on any system call (V2), with malloc, calloc, realloc and free interposed to abort
 * (N2), and under Valgrind memcheck with the scratch marked undefined before each decision, in the
 * release and the trace build (E1), each beside the controls that plant the call, the allocation or the
 * uninitialised read. Each has an independent twin in
 * policy_ref.py, written from POLICY.md's rendering section and this file's comments, never from this
 * code.
 *
 * The configuration-time half (the arena, the binding of the planes, the trust checks, the module's
 * thread, the writers) is we_module.c, declared at the end.
 */
#ifndef WE_MODULE_H
#define WE_MODULE_H

#ifdef __cplusplus
#error "we_module.h is C11 (it uses _Alignof and C11 atomics): compile the module as C, not C++"
#endif

#include "we_eval.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* first, so a 32-bit build stops on what is wrong rather than on a record offset: the layouts below,
 * the 1,024-byte scratch and the tear-free relaxed 64-bit counter all assume 8-byte pointers */
WE_STATIC_ASSERT(sizeof(void *) == 8u && sizeof(uint64_t) == 8u,
                 "we_module.h is for 64-bit (LP64) targets only; a 32-bit armhf or i386 build is not supported");

#define WE_COUNTRY_DIRECT_ONLY
#define WE_COUNTRY_DIRECT
#include "we_country_table.h"
#undef WE_COUNTRY_DIRECT_ONLY

/*
 * THE ABI. This header is copied into three builds that compile apart, so it carries a major version.
 * THE RULE: changing or removing a declaration, a type or a field, or moving a layout, raises the major;
 * ADDING a declaration (a new call, a new type, a new constant) does not, because nothing compiled
 * against the old header can call what it never saw. A module passes the major it compiled with to the
 * first call that writes anything, we_mod_config_build(), and again to we_mod_bind(); each refuses a
 * mismatch with WE_MOD_ERR_ABI, naming both, before it writes a byte. Every public struct's size,
 * alignment and field offsets are recorded at the end of this file under the major they were measured
 * under (gen-abi-layout.py), so a layout change fails to compile until the major moves.
 */
#define WE_MODULE_ABI_VERSION 5u

/* The constants this header builds in, tied to the core's so a change there fails the build here. */
WE_STATIC_ASSERT(WE_PLANE_MAX == 8u, "eight planes: the masks are bytes and the per-plane arrays are 8 long");
WE_STATIC_ASSERT(WE_WHY_HOLD_HARMLESS == 2u && WE_WHY_ACME == 3u && WE_WHY_NO_ADDRESS == 5u,
                 "the exempt reasons map to counters 0, 1 and 4 by `reason - 2 + (reason == 5)`");
WE_STATIC_ASSERT(WE_STEP_TENANT == 2u && WE_STEP_STALE_TENANT == 4u,
                 "the tenant steps map to counters 2 and 3 by `step - (step == 4)`");
WE_STATIC_ASSERT(WE_ERR_MODULE_FIRST == -32 && WE_ERR_MODULE_LAST == -63, "the module's error range is -32 to -63");

/*
 * THE CONTROLS. Each WE_MOD_TEST_* and WE_MOD_PLANT_CALL plants a known defect that a named row of a gate
 * must catch. None of them may reach a shipped module: every one is refused here unless the build says
 * it is a gate's control build, and WE_TEST_MOD_ALL_VIEWS is the cachegrind driver's alone.
 */
#if !defined(WE_MOD_CONTROL_BUILD) && ( \
        defined(WE_MOD_PLANT_CALL) || defined(WE_MOD_PLANT_CALL_WALK) || defined(WE_MOD_TEST_COUNT_DEFAULT) || defined(WE_MOD_TEST_INTERLEAVE) \
        || defined(WE_MOD_TEST_LOCKED_COUNT) || defined(WE_MOD_TEST_GLOBAL_SHARD) \
        || defined(WE_MOD_TEST_OVERREAD) || defined(WE_MOD_TEST_SPAN_OFF) || defined(WE_MOD_TEST_SPEC_UNCHECKED) \
        || defined(WE_MOD_TEST_NO_LINE_CLAMP) || defined(WE_MOD_TEST_SEVERITY_SCAN) \
        || defined(WE_MOD_TEST_PRINT_UNMEASURED) || defined(WE_MOD_TEST_RETIRE_UNCHECKED) \
        || defined(WE_MOD_TEST_TENANT_BY_MASK) || defined(WE_MOD_TEST_EUID0) || defined(WE_MOD_TEST_LOG_LIFO) \
        || defined(WE_MOD_TEST_SS_UNCONDITIONAL) || defined(WE_MOD_TEST_LAZY_NO_CLEAR) || defined(WE_MOD_TEST_RETIRE_LOCKED) \
        || defined(WE_MOD_TEST_PLANT_ALLOC) || defined(WE_MOD_TEST_PLANT_UNINIT) \
        || defined(WE_MOD_TEST_PORT_65536) || defined(WE_MOD_TEST_LEADING_ZERO) || defined(WE_MOD_TEST_DC_ZERO_GROUPS) \
        || defined(WE_MOD_TEST_PEER_ON_UNPARSED) || defined(WE_MOD_TEST_NO_HOP_CAP) \
        || defined(WE_MOD_TEST_UNMERGED_TRUST) || defined(WE_MOD_TEST_NO_COUNTRY_COMPARE) \
        || defined(WE_MOD_TEST_NO_LAZY) || defined(WE_MOD_TEST_EAGER_EXPORT) || defined(WE_MOD_TEST_RAW_NAMES) \
        || defined(WE_MOD_TEST_LAZY_PER_PLANE) || defined(WE_MOD_TEST_COUNTRY_SCAN) \
        || defined(WE_MOD_TEST_ALLOW_NETFS) \
        || defined(WE_MOD_TEST_PAUSE_TICK) || defined(WE_MOD_TEST_PAUSE_BEFORE_RENAME) \
        || defined(WE_MOD_TEST_PAUSE_AFTER_FSTAT) || defined(WE_MOD_TEST_NO_THREAD) || defined(WE_MOD_TEST_NO_PIN) \
        || defined(WE_MOD_TEST_SHARD_OWNER) || defined(WE_MOD_TEST_MPM_SLOT) \
        || defined(WE_MOD_TEST_DROP_ARMED) || defined(WE_MOD_TEST_CTIME_NO_DIGEST) || defined(WE_MOD_TEST_DROP_LOG) \
        || defined(WE_MOD_TEST_UNCUT_LOG) || defined(WE_MOD_TEST_HEAD_ALONE) || defined(WE_MOD_TEST_SNAPSHOT_FALLBACK) \
        \
        || defined(WE_MOD_TEST_INLINE_HANDLER) || defined(WE_MOD_TEST_LEGACY_HOLD) || defined(WE_MOD_TEST_LEGACY_LOOP_FREES) \
        \
        || defined(WE_MOD_TEST_FIRST_LINE) || defined(WE_MOD_TEST_FIRST_16_LINES) || defined(WE_MOD_TEST_LEXICAL) \
        || defined(WE_MOD_TEST_APPEND) || defined(WE_MOD_TEST_MONITOR_BYTES) \
        || defined(WE_MOD_TEST_NO_RELEASE) || defined(WE_MOD_TEST_NO_START_STAT) || defined(WE_MOD_TEST_SERVE_INHERITED) \
        || defined(WE_MOD_TEST_THREAD_MASK) || defined(WE_MOD_TEST_WORKER_SCRATCH_FILL) \
        || defined(WE_MOD_TEST_UNREADABLE_BOUND) || defined(WE_MOD_TEST_NULL_WORD_UNPOSTED) \
        || defined(WE_MOD_TEST_PAUSE_NO_HOLD) || defined(WE_MOD_TEST_ABSENT_REFUSED) \
        || defined(WE_MOD_TEST_NOMAP_CLAMP) || defined(WE_MOD_TEST_TAIL_PRIVATE) || defined(WE_MOD_TEST_FLAT_DEADLINE) \
        || defined(WE_MOD_TEST_PLANE_FILE_IGNORED) || defined(WE_MOD_TEST_SNAPSHOT_DROPPED) \
        || defined(WE_MOD_TEST_PATH_TWICE) || defined(WE_MOD_TEST_BIND_LEAVES_POINTERS) \
        || defined(WE_MOD_TEST_PLANE_REFUSAL_WHOLE) || defined(WE_MOD_TEST_REFUSED_UNSAID) \
        || defined(WE_MOD_TEST_CHECK_NO_VERIFY) || defined(WE_MOD_TEST_COUNTERS_FIRST_DIR) \
        || defined(WE_MOD_TEST_RESOLVED_CHAIN_ONLY) || defined(WE_MOD_TEST_REOPEN_BY_PATH) \
        || defined(WE_MOD_TEST_CAP_OFF) || defined(WE_MOD_TEST_COUNTERS_AT_ROOT) || defined(WE_MOD_TEST_HW_ROOT_ONLY) \
        || defined(WE_MOD_TEST_HW_LOOSE) || defined(WE_MOD_TEST_LEGACY_OWNER_SILENT) \
        || defined(WE_MOD_TEST_DIGEST_SILENT) || defined(WE_MOD_TEST_FORK_KEEPS_MONITOR) \
        || defined(WE_MOD_TEST_SPSC_UNCHECKED) || defined(WE_MOD_TEST_FAIL_IDENT_ONLY) || defined(WE_MOD_TEST_DIGEST_UNCOUNTED) || defined(WE_MOD_TEST_LEN_OFF) \
        || defined(WE_MOD_TEST_SLOW_STOP) || defined(WE_MOD_TEST_STALL_STOP) || defined(WE_MOD_TEST_STALL_WRITE) \
        || defined(WE_MOD_TEST_SUBBLOCK_UNLOCKED) || defined(WE_MOD_TEST_FINAL_BLOCKING) \
        || defined(WE_MOD_TEST_HOLD_MU_AT_STOP) || defined(WE_MOD_TEST_DECIDE_INLINED) \
        || defined(WE_MOD_TEST_WRITER_UID_UNCHECKED) || defined(WE_MOD_TEST_STATUS_FOLLOWS) \
        || defined(WE_MOD_TEST_TICK_AT_STOP) || defined(WE_MOD_TEST_TICK_BLOCKING) || defined(WE_MOD_TEST_DENY_AT_WARN))
#error "the WE_MOD_TEST_* controls and WE_MOD_PLANT_CALL exist only in a gate's control build (WE_MOD_CONTROL_BUILD)"
#endif
#ifdef WE_MOD_TEST_WORKER_SCRATCH_FILL
/* the WORKER_SCRATCH_FILL control's state: the last decision's memo slot, per translation unit (the module's) */
static we_memo_slot_t we_mod_test_last_slot __attribute__((unused));
static int we_mod_test_last_valid __attribute__((unused));
#endif
#if defined(WE_TEST_MOD_ALL_VIEWS) && !defined(WE_CG_DRIVER)
#error "WE_TEST_MOD_ALL_VIEWS is the cachegrind driver's control alone"
#endif
#if defined(WE_TEST_MOD_PRESTAGE_WORK) && !defined(WE_CG_DRIVER)
#error "WE_TEST_MOD_PRESTAGE_WORK is the cachegrind driver's control alone"
#endif
/*
 * The decision's one call. A server module inlines we_decide() into its request path here. The cachegrind
 * driver alone (WE_CG_DRIVER) names a noinline copy of its own, which its evaluator rows call too, so a
 * module row less its evaluator twin is the module's own work by construction, never the difference
 * between two inlinings of the decision (gate/cg_driver.c, at cg_decide, says what each row then measures).
 */
#ifndef WE_MOD_DECIDE_COPY
#define WE_MOD_DECIDE_COPY we_decide
#elif !defined(WE_CG_DRIVER)
#error "WE_MOD_DECIDE_COPY is the cachegrind driver's alone: a server module inlines we_decide()"
#endif
#if defined(WE_MOD_PLANT_CALL) || defined(WE_MOD_PLANT_CALL_WALK)
/* declared, not included: the gate's cross builds compile against a libc shim with no unistd.h */
int getpid(void);
#endif
#ifdef WE_MOD_TEST_PLANT_ALLOC
#include <stdlib.h>                  /* the control's allocation in the cold half (row N2) */
#endif

/* ---- the counters' fixed layout ---- */

/*
 * A configuration's counter array, per shard: the eight pre-stage counters in the first line, the
 * floor's rules from index 8, then every context that has lines of its own, each at its ctr_off. A
 * context with no lines counts into the context it inherits from. The default allow writes nothing.
 */
#define WE_MOD_CTR_HOLD_HARMLESS          0u
#define WE_MOD_CTR_ACME                   1u
#define WE_MOD_CTR_TENANT                 2u
#define WE_MOD_CTR_STALE_TENANT           3u
#define WE_MOD_CTR_NO_ADDRESS             4u
#define WE_MOD_CTR_FLOOR_HEADER_MISSING   5u
#define WE_MOD_CTR_FLOOR_HEADER_UNPARSED  6u
#define WE_MOD_CTR_FLOOR_HEADER_CAPPED    7u
#define WE_MOD_CTR_PRESTAGE               8u   /* the pre-stage counters, one line */
#define WE_MOD_CTR_FLOOR                  8u   /* the floor's rule 1 */
#define WE_MOD_STRIDE_MAX             65536u   /* counted rule slots per configuration, a refusal above */

/*
 * The walk's note: why the judged address is not simply the walk's answer. Counted, and rendered. A
 * request's note is one of these three and nothing else (we_mod_walk() sets no other value; a module that
 * builds a request itself must not either): we_mod_decide() counts it at WE_MOD_CTR_FLOOR_HEADER_MISSING
 * plus its value, with no branch, so a 3 would count into the floor's rule 1.
 */
#define WE_MOD_NOTE_NONE      0u
#define WE_MOD_NOTE_UNPARSED  1u
#define WE_MOD_NOTE_CAPPED    2u

/*
 * Why a memo entry has no map behind it, recorded per plane at every memo write into the record's
 * provenance line (three bits each), so `$whisper_edge_generations` names the state as of the fill,
 * never as of the log line. 0: a map backed the entry. The disarmed state is not a reason code: it
 * is its own bit, set when the map that produced the entry was the plane's stand-in.
 */
/*
 * The tenant plane's revocation mark, where the keyed refresh writes it: ETC/state/tenant.high-water with
 * ETC its default /etc/whisper-edge (state/ is the one subdirectory the keyed unit may write). The bind
 * reads it when the server names no other (we_mod_bind_args_t.high_water_file NULL), so a restored
 * pre-revocation tenant.bin cannot re-arm across a restart; the keyed gate holds the two paths equal.
 */
#define WE_MOD_HIGH_WATER_DEFAULT "/etc/whisper-edge/state/tenant.high-water"

#define WE_MOD_NOMAP_NONE        0u
#define WE_MOD_NOMAP_ABSENT      1u   /* not installed, present and not bound, or bound with no file: `-a` */
#define WE_MOD_NOMAP_UNREADABLE  2u   /* present, unreadable by the configuration reader: `-u` */
#define WE_MOD_NOMAP_REFUSED     3u   /* `-r` */
#define WE_MOD_NOMAP_LOADING     4u   /* `-l` */

/*
 * The body every Apache and LiteSpeed floor or pre-stage deny sends, alone, with `Cache-Control:
 * no-store`: the module's own fixed text, so the response does not depend on an error document a
 * context below the floor could configure. nginx sends its own special-response page instead.
 */
#define WE_MOD_DENY_TEXT "Forbidden by the Whisper edge policy floor.\n"

/* ---- the configuration and the context, as the request path reads them ---- */

/*
 * The cold half of a context: what the variables render that does not change per request. Built once
 * per configuration by we_module.c into configuration-lifetime memory; the request path never reads it,
 * the renderers do.
 */
typedef struct {
    const char        *name;          /* the operator's: `server "example.com"`, already escaped */
    const char        *path;          /* the ordinal path the compiler was given: `http/s3/l7` */
    const char        *program_ctx;   /* `floor:<d16> ctx:<d16>` (`ctx:-` when the context runs no block) */
    const char        *program_floor; /* `floor:<d16> ctx:-`: a decision taken before the context program */
    const char *const *rule_id;       /* `ctx:N`, index N - 1 */
    const char *const *rule_text;     /* the canonical text of rule N, index N - 1 */
    uint32_t           rule_count;
    uint32_t           own;           /* 1: the context has lines of its own */
} we_mod_ctx_cold_t;

typedef struct {
    const char        *program_none;  /* `floor:- ctx:-` or `floor:<d16> ctx:-` for a pre-stage step */
    const char *const *rule_id;       /* `floor:N` */
    const char *const *rule_text;
    uint32_t           rule_count;
    const char        *plane_name[8]; /* in plane order, for the generations token */
} we_mod_cfg_cold_t;

/*
 * Per configuration, sealed read-only before any worker starts. `handle[p]` is NULL for a plane that is
 * not bound; `standin[p]` is the plane's header-only stand-in, the map a disarm installs, which nothing
 * renders from (a memo write that finds it sets the plane's disarmed bit instead). `null_reason` points
 * at eight process-lifetime words, one per plane, which the plane's single writer stores (release)
 * before every publication that leaves or keeps the view NULL: WE_MOD_NOMAP_REFUSED or _LOADING.
 * `static_reason[p]` is the configuration-time reason of a plane with no handle: WE_MOD_NOMAP_ABSENT (not
 * installed, or read by no program) or WE_MOD_NOMAP_UNREADABLE (present, and its open refused with EACCES or
 * EPERM).
 */
typedef struct we_mod_arena we_mod_arena_t;   /* the configuration's blocks (defined with the arena below) */
typedef struct {
    const we_program_t      *floor;
    we_ctx_conf_t            floor_conf;    /* the http level's: the floor and every pre-stage step */
    uint16_t                 floor_status;  /* the http level's deny status */
    const we_hh_view_t      *hh;
    we_handle_t             *handle[8];
    uint8_t                  bound_mask;
    uint8_t                  static_reason[8];
    const we_map_t          *standin[8];
    uint32_t                *null_reason;
    const we_mod_cfg_cold_t *cold;
    const we_mod_arena_t    *arena;         /* the configuration's blocks, every distinct program once: the
                                             * transition lines are written per program from here (set by
                                             * we_mod_config_build; NULL binds planes with no programs) */
} we_mod_cfg_t;

/*
 * Per context, sealed with the configuration. `prog` is the block the context runs (its own, or the
 * nearest enclosing context's), NULL for none; `ctr_off` the shard index of its rule 1 (the owning
 * context's, for a context without lines); `export_mask` the planes of its default export set and
 * `gen_mask` the planes its generations token names, both fixed at configuration time.
 */
typedef struct {
    const we_program_t      *prog;
    we_ctx_conf_t            conf;
    uint16_t                 deny_status;
    uint32_t                 ctr_off;
    uint16_t                 rule_count;
    uint8_t                  export_mask;
    uint8_t                  gen_mask;
    const we_mod_ctx_cold_t *cold;
} we_mod_ctx_t;

/* The request as the core reads it, and the walk's note, which we_mod_decide() counts. */
typedef struct {
    we_request_t r;
    uint8_t      note;     /* WE_MOD_NOTE_*; there is no subrequest field: a subrequest is never judged */
    uint8_t      pad[7];
} we_mod_req_t;

/*
 * The decision's scratch: a local of the handler's own `noinline` decision frame, 64-byte aligned, so
 * the eight view stores are one line. Nothing in it survives the handler. `park` is the module's own
 * corner of the evaluator's rule (POLICY.md section 3.7): the context and the shard cross the
 * evaluator in memory the scratch already owns, never in a register the evaluator would have to save
 * on the stack. It sits in what was the type's tail padding, so the size stays 1,024.
 */
typedef struct {
    WE_ALIGN64 we_eval_ctx_t e;
    we_verdict_t             v;
    struct {
        const void *c;       /* const we_mod_cfg_t * */
        const void *x;       /* const we_mod_ctx_t * */
        uint64_t   *shard;
        const void *req;     /* const we_mod_req_t * */
        uint64_t    now_ms;
    } park;
} we_mod_scratch_t;
#ifndef WE_TRACE
/*
 * 1,024 bytes, held: the decision chain's bound is at most 10% of the target's PTHREAD_STACK_MIN, never
 * above 2,048 bytes, with a ratchet on the measured value per architecture (x86_64 1,592, aarch64 1,488;
 * the module gates hold both). The x86_64 chain is the scratch, about 250 bytes of the frame's spills and
 * the evaluation's own noinline frame. Shrinking the scratch instead would move we_mod_record_t's layout.
 */
WE_STATIC_ASSERT(sizeof(we_mod_scratch_t) == 1024u, "the scratch is 1,024 bytes as laid out");
#else
/* the trace build's verdict carries its cost counters, so its scratch is larger; still whole lines */
WE_STATIC_ASSERT(sizeof(we_mod_scratch_t) % 64u == 0u, "the trace build's scratch is whole lines");
#endif
WE_STATIC_ASSERT(_Alignof(we_mod_scratch_t) == 64u, "the scratch is 64-byte aligned");
WE_STATIC_ASSERT(offsetof(we_mod_scratch_t, e) == 0u, "the views are the scratch's first line");

/*
 * One counter increment: one writer per shard, so a relaxed load and a relaxed store, never a locked
 * add (the hot-path gate's atomic class refuses one, and so does its outline-atomic relocation check).
 */
#ifdef WE_MOD_TEST_INTERLEAVE
void we_mod_test_interleave(void);   /* test_module's barrier between the load and the store */
#define WE_MOD_INTERLEAVE() we_mod_test_interleave()
#else
#define WE_MOD_INTERLEAVE() ((void)0)
#endif
#ifdef WE_MOD_TEST_GLOBAL_SHARD
extern uint64_t we_mod_test_shard[];   /* the gate's control: the counters reached through a global */
#endif
#ifdef WE_TRACE
/* the trace build's hook on every counter write (the cachegrind gate's C5+ module half), as we_eval.h's
 * WE_TRACE_EVAL is on every evaluator load: the traced driver records the line; a release build has none */
void we_trace_count(const void *p);
#define WE_TRACE_COUNT(p) we_trace_count((const void *)(p))
#else
#define WE_TRACE_COUNT(p) ((void)0)
#endif
WE_HOT_INLINE void we_mod_count(uint64_t *shard, uint32_t i)
{
#ifdef WE_MOD_TEST_GLOBAL_SHARD
    shard = we_mod_test_shard;
#endif
    WE_TRACE_COUNT(&shard[i]);
#ifdef WE_MOD_TEST_LOCKED_COUNT
    __atomic_fetch_add(&shard[i], 1u, __ATOMIC_RELAXED);   /* the gate's control: a read-modify-write */
#else
    uint64_t v = __atomic_load_n(&shard[i], __ATOMIC_RELAXED);

    WE_MOD_INTERLEAVE();
    __atomic_store_n(&shard[i], v + 1u, __ATOMIC_RELAXED);
#endif
}

/*
 * THE REQUEST PATH. Writes all eight view pointers of the scratch (we_current() for each plane in
 * (floor | context | tenant) & bound, NULL for the others), runs we_decide(), and counts: the walk's
 * one counter, the pre-stage's decision, the deciding rule (allow-by-unknown under its rule) and every
 * bit of both log bitmaps. The default allow counts nothing. `shard` is never NULL: a thread with no
 * shard of its own counts into the configuration's sink, which nothing reads. A shard is the caller's to
 * provide and must be 64-byte aligned, `stride` words long (we_mod_config_build()'s *stride, a multiple of
 * 8) and owned by one thread: the decision writes up to shard[stride - 1] with plain relaxed stores, so a
 * shorter one is overrun and two threads on one lose counts (a plain malloc per thread is neither aligned
 * nor line-padded: aligned_alloc(64, stride * 8) is). `now_ms` is the server's own time for the
 * request (epoch milliseconds): the module reads no clock.
 */
#ifdef WE_MOD_DEBUG
/* the debug build's tail count (the truncate row): we_module.c says how it is kept and where it is printed */
void     we_mod_debug_tail_note(const we_request_t *r);
int      we_mod_debug_tail_on(void);
uint64_t we_mod_debug_tail_count(void);
#endif
WE_HOT_INLINE void we_mod_decide(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                 uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms)
{
    uint32_t mask, p, w;

#ifdef WE_MOD_PLANT_CALL
    (void)getpid();                  /* the gates' planted call: every row that reads calls must refuse it */
#endif
#ifdef WE_MOD_DEBUG
    we_mod_debug_tail_note(&req->r); /* before any plane is read: a request that dies on the read is counted */
#endif
    /* every operand parked first: each step below reads what it needs back from the scratch */
    s->park.c = c;
    s->park.x = x;
    s->park.shard = shard;
    s->park.req = req;
    s->park.now_ms = now_ms;
    /* the walk's counter, at most one: the note first (unparsed, capped), else a header-missing mark */
    if ((req->note | (uint32_t)(req->r.walk == WE_WALK_FLOOR_HEADER_MISSING)) != 0u) {
        we_mod_count(shard, WE_MOD_CTR_FLOOR_HEADER_MISSING + (req->note & 3u));
    }
    mask = (uint32_t)(c->floor != NULL ? c->floor->plane_mask : 0u)
         | (uint32_t)(x->prog != NULL ? x->prog->plane_mask : 0u) | 0x80u;
    mask &= c->bound_mask;
#ifdef WE_TEST_MOD_PRESTAGE_WORK
    {
        /* the cachegrind control: 128 instructions of the module's own work before the decision, outside
         * the decision's copy, which the module rows must see and their twins must not */
        uint32_t n;

        for (n = 0u; n < 32u; n++) {
            __asm__ __volatile__("nop\n\tnop\n\tnop\n\tnop");
        }
    }
#endif
#ifdef WE_TEST_MOD_ALL_VIEWS
    /* the cachegrind control: the production mask computed and kept live, then every plane read */
    __asm__ __volatile__("" : "+r"(mask));
    mask |= 0xffu;
    __asm__ __volatile__("" : "+r"(mask));
#endif
#ifndef WE_MOD_TEST_PLANT_UNINIT
    for (p = 0u; p < 8u; p++) {
#else
    for (p = 1u; p < 8u; p++) {          /* the control: the reputation view left as the scratch held it (row E1) */
#endif
        s->e.view[p].m = ((mask >> p) & 1u) != 0u ? we_current(c->handle[p]) : (const we_map_t *)NULL;
    }
    /*
     * Only the scratch crosses the evaluator (POLICY.md section 3.7's rule, here for the module's own
     * operands): each argument is read back from the park after a barrier that emits nothing, so no
     * compiler keeps a copy of one live across the decision, which is the stack slot the gate refuses.
     */
    {
        we_eval_ctx_t *e = &s->e;
        we_verdict_t *v = &s->v;

        __asm__ __volatile__("" : "+r"(e), "+r"(v) : : "memory");
        c = (const we_mod_cfg_t *)*(const void *const volatile *)&s->park.c;
        x = (const we_mod_ctx_t *)*(const void *const volatile *)&s->park.x;
        req = (const we_mod_req_t *)*(const void *const volatile *)&s->park.req;
        WE_MOD_DECIDE_COPY(c->floor, &c->floor_conf, x->prog, &x->conf, c->hh, &req->r, e,
                           *(const volatile uint64_t *)&s->park.now_ms, v);
        /* the verdict is the one pointer that crossed; the scratch is re-derived from it */
        __asm__ __volatile__("" : "+r"(v) : : "memory");
        s = (we_mod_scratch_t *)(void *)((uint8_t *)v - offsetof(we_mod_scratch_t, v));
    }
    x = (const we_mod_ctx_t *)*(const void *const volatile *)&s->park.x;
    shard = *(uint64_t *const volatile *)&s->park.shard;
    if (s->v.rule != 0u) {
        /* the deciding rule, allow-by-unknown included; a pre-stage step has rule 0 */
        we_mod_count(shard, (s->v.program == WE_VPROG_FLOOR ? WE_MOD_CTR_FLOOR : x->ctr_off) + s->v.rule - 1u);
    } else if (s->v.step == WE_STEP_EXEMPT) {
        /* reasons 2, 3 and 5 (hold-harmless, ACME, no address) to counters 0, 1 and 4: no table */
        we_mod_count(shard, (uint32_t)s->v.reason - 2u + (uint32_t)(s->v.reason == WE_WHY_NO_ADDRESS));
    } else if (s->v.step == WE_STEP_TENANT || s->v.step == WE_STEP_STALE_TENANT) {
        /* steps 2 and 4 to counters 2 and 3 */
        we_mod_count(shard, (uint32_t)s->v.step - (uint32_t)(s->v.step == WE_STEP_STALE_TENANT));
    }
#ifdef WE_MOD_TEST_COUNT_DEFAULT
    else if (s->v.step == WE_STEP_CONTEXT) {
        we_mod_count(shard, x->ctr_off);       /* the control: the default allow counted */
    }
#endif
    /* every log (and downgraded deny) that fired, floor bitmap then context bitmap, by a ctz loop */
    for (w = 0u; w < 8u; w++) {
        uint64_t bits;
        uint32_t base = w < 4u ? WE_MOD_CTR_FLOOR + 64u * w : x->ctr_off + 64u * (w - 4u);

        __builtin_memcpy(&bits, &s->v.log_fired[0][0] + 8u * w, 8);
        while (bits != 0u) {
            we_mod_count(shard, base + (uint32_t)__builtin_ctzll(bits));
            bits &= bits - 1u;
        }
    }
#ifdef WE_MOD_TEST_WORKER_SCRATCH_FILL
    if (s->v.step != WE_STEP_EXEMPT && s->v.step != WE_STEP_TENANT && s->v.sc.ss != NULL) {
        /* the control's copy of this decision's slot, taken while the decision's own scratch holds it, into
         * memory the core owns on every server; the fill reads only this copy. sc.ss names a slot only when
         * the decision keyed one, the record write's own rule (a pre-stage outcome writes none) */
        we_mod_test_last_slot = *(const we_memo_slot_t *)s->v.sc.ss;
        we_mod_test_last_valid = 1;
    }
#endif
}

/* ==================================================================================================
 * Everything below is COLD: outside the gated function, allocation- and syscall-free.
 * ================================================================================================ */

/* ---- the RFC 5952 formatter ---- */

#define WE_ADDR_TEXT_MAX 46u   /* INET6_ADDRSTRLEN: the longest text plus its terminator */

/*
 * Every address the module prints. IPv4 in dotted decimal; IPv6 by RFC 5952 section 4: lower case,
 * leading zeros dropped, the longest run of two or more zero groups compressed (the first on a tie), a
 * single zero group never compressed, and never the mixed notation of section 5 (so `::ffff:0:c000:201`
 * and `64:ff9b::c000:201` print as hex like every other address; `::ffff:0:0/96` never reaches here,
 * because canonicalisation unmaps it to IPv4). Writes a NUL-terminated string; returns its length.
 */
static inline size_t we_addr_format(const we_addr_t *a, char out[WE_ADDR_TEXT_MAX])
{
    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    size_t o = 0u;
    uint32_t i;

    if (a->family == 4u) {
        for (i = 0u; i < 4u; i++) {
            uint32_t v = a->b[i];

            if (i != 0u) {
                out[o++] = '.';
            }
            if (v >= 100u) {
                out[o++] = (char)('0' + v / 100u);
            }
            if (v >= 10u) {
                out[o++] = (char)('0' + (v / 10u) % 10u);
            }
            out[o++] = (char)('0' + v % 10u);
        }
        out[o] = '\0';
        return o;
    }
    {
        uint32_t g[8], best = 8u, bestlen = 0u, run = 8u, runlen = 0u;

        for (i = 0u; i < 8u; i++) {
            g[i] = (uint32_t)a->b[2u * i] << 8 | a->b[2u * i + 1u];
            if (g[i] == 0u) {
                if (runlen == 0u) {
                    run = i;
                }
                runlen++;
                if (runlen > bestlen) {      /* strictly longer: the first run wins a tie */
                    best = run;
                    bestlen = runlen;
                }
            } else {
                runlen = 0u;
            }
        }
        if (bestlen < 2u) {
            best = 8u;                       /* a single zero group is written as 0 */
        }
        for (i = 0u; i < 8u; i++) {
            if (i == best) {
                out[o++] = ':';
                out[o++] = ':';
                i += bestlen - 1u;
                continue;
            }
            if (i != 0u && i != best + bestlen) {
                out[o++] = ':';
            }
            {
                uint32_t v = g[i];
                int started = 0, k;

                for (k = 12; k >= 0; k -= 4) {
                    uint32_t d = (v >> k) & 15u;

                    if (d != 0u || started || k == 0) {
                        out[o++] = hex[d];
                        started = 1;
                    }
                }
            }
        }
        out[o] = '\0';
        return o;
    }
}

/* ---- the grammar of one entry (RFC 3986's IPv4address and IPv6address, a port, no zone) ---- */

#define WE_MOD_ENTRY_MAX 53u   /* "[" + 45 + "]" + ":" + 5: the longest entry that parses */

WE_STATIC_ASSERT(WE_MOD_ENTRY_MAX == 1u + (WE_ADDR_TEXT_MAX - 1u) + 1u + 1u + 5u, "the entry bound");

/* dec-octet "." dec-octet "." dec-octet "." dec-octet, no leading zeros; 0 when s[0..n) is exactly one */
static inline int we_mod_parse4(const uint8_t *s, size_t n, uint8_t out[4])
{
    size_t i = 0u;
    uint32_t k;

    for (k = 0u; k < 4u; k++) {
        uint32_t v = 0u, d = 0u;

        if (k != 0u) {
            if (i >= n || s[i] != '.') {
                return -1;
            }
            i++;
        }
        while (i < n && s[i] >= '0' && s[i] <= '9' && d < 4u) {
            v = v * 10u + (uint32_t)(s[i] - '0');
            i++;
            d++;
        }
#ifdef WE_MOD_TEST_LEADING_ZERO
        if (d == 0u || d > 3u || v > 255u) {          /* the control: a leading zero accepted */
#else
        if (d == 0u || d > 3u || v > 255u || (d > 1u && s[i - d] == '0')) {
#endif
            return -1;
        }
        out[k] = (uint8_t)v;
    }
    return i == n ? 0 : -1;
}

static inline int we_mod_hexval(uint8_t c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/*
 * RFC 3986 IPv6address, verbatim: eight groups, or fewer with one `::` standing for AT LEAST one zero
 * group, the last two groups optionally an IPv4 address. h16 is one to four hex digits, either case.
 * No zone identifier. 0 when s[0..n) is exactly one, out[] the sixteen bytes.
 */
static inline int we_mod_parse6(const uint8_t *s, size_t n, uint8_t out[16])
{
    uint16_t g[8];
    uint32_t ng = 0u, k;
    int dc = -1;
    size_t i = 0u;

    if (n < 2u) {
        return -1;
    }
    if (s[0] == ':') {
        if (s[1] != ':') {
            return -1;
        }
        dc = 0;
        i = 2u;
        if (i == n) {
            goto expand;
        }
    }
    for (;;) {
        size_t j = i;
        int dot = 0;

        while (j < n && s[j] != ':') {
            dot |= s[j] == '.';
            j++;
        }
        if (dot) {
            uint8_t v4[4];

            /* an IPv4 tail is the last thing in the text, and stands for groups 7 and 8 */
            if (j != n || ng > 6u || we_mod_parse4(s + i, n - i, v4) != 0) {
                return -1;
            }
            g[ng++] = (uint16_t)(v4[0] << 8 | v4[1]);
            g[ng++] = (uint16_t)(v4[2] << 8 | v4[3]);
            break;
        }
        if (j == i || j - i > 4u || ng == 8u) {
            return -1;
        }
        {
            uint32_t v = 0u;

            for (k = (uint32_t)i; k < j; k++) {
                int h = we_mod_hexval(s[k]);

                if (h < 0) {
                    return -1;
                }
                v = v << 4 | (uint32_t)h;
            }
            g[ng++] = (uint16_t)v;
        }
        i = j;
        if (i == n) {
            break;
        }
        i++;                                  /* the ':' */
        if (i < n && s[i] == ':') {
            if (dc >= 0) {
                return -1;
            }
            dc = (int)ng;
            i++;
            if (i == n) {
                break;
            }
        } else if (i == n) {
            return -1;                        /* a single trailing ':' */
        }
    }
expand:
#ifdef WE_MOD_TEST_DC_ZERO_GROUPS
    if (dc < 0 ? ng != 8u : ng > 8u) {
        return -1;                            /* the control: `::` allowed to stand for no group */
    }
#else
    if (dc < 0 ? ng != 8u : ng > 7u) {
        return -1;                            /* `::` never stands for zero groups */
    }
#endif
    {
        uint32_t head = dc < 0 ? ng : (uint32_t)dc, tail = ng - head;
        uint16_t w[8] = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };

        if (head > 8u || tail > 8u - head) {
            return -1;                        /* never: ng is at most 8 here; stated so every compiler sees the bound */
        }
        /* the groups before `::` from the left, the groups after it against the right; every index masked to
         * the eight groups, which the bound above already guarantees, so no compiler reads a path past them */
        for (k = 0u; k < head; k++) {
            w[k & 7u] = (uint16_t)g[k & 7u];
        }
        for (k = 0u; k < tail; k++) {
            w[(8u - tail + k) & 7u] = (uint16_t)g[(head + k) & 7u];
        }
        for (k = 0u; k < 8u; k++) {
            out[2u * k] = (uint8_t)(w[k] >> 8);
            out[2u * k + 1u] = (uint8_t)w[k];
        }
    }
    return 0;
}

/* port = 1*5DIGIT, the value 0 to 65535, leading zeros allowed; read and ignored */
static inline int we_mod_parse_port(const uint8_t *s, size_t n)
{
    uint32_t v = 0u;
    size_t i;

    if (n == 0u || n > 5u) {
        return -1;
    }
    for (i = 0u; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        v = v * 10u + (uint32_t)(s[i] - '0');
    }
#ifdef WE_MOD_TEST_PORT_65536
    return v <= 65536u ? 0 : -1;                       /* the control: one past the port's range */
#else
    return v <= 65535u ? 0 : -1;
#endif
}

/*
 * One entry, its OWS already trimmed:
 *   entry = ipv4 [ ":" port ] / ipv6 / "[" ipv6 "]" [ ":" port ]
 * A bare IPv6 has no port (`::1:80` is that address), a bracketed IPv4, an empty port, a zone id, the
 * RFC 7239 `for=` syntax and anything over 53 bytes do not parse. On success the address is written
 * CANONICAL (::ffff:0:0/96 unmapped to IPv4), so it compares and searches like a peer.
 */
static inline int we_mod_entry_parse(const uint8_t *s, size_t n, we_addr_t *out)
{
    uint8_t b[16];
    size_t i;

    if (n == 0u || n > WE_MOD_ENTRY_MAX) {
        return -1;
    }
    if (s[0] == '[') {
        for (i = 1u; i < n && s[i] != ']'; i++) {
        }
        if (i == n || we_mod_parse6(s + 1, i - 1u, b) != 0) {
            return -1;
        }
        if (i + 1u != n && (s[i + 1u] != ':' || we_mod_parse_port(s + i + 2u, n - i - 2u) != 0)) {
            return -1;
        }
        we_addr_canon(b, 6, out);
        return 0;
    }
    for (i = 0u; i < n && s[i] != ':'; i++) {
    }
    if (i == n || (i > 0u && we_mod_parse4(s, i, b) == 0)) {
        /* no colon: an IPv4 or nothing; a colon after an IPv4: its port */
        if (we_mod_parse4(s, i, b) != 0) {
            return -1;
        }
        if (i != n && we_mod_parse_port(s + i + 1u, n - i - 1u) != 0) {
            return -1;
        }
        memset(b + 4, 0, 12);
        we_addr_canon(b, 4, out);
        return 0;
    }
    if (we_mod_parse6(s, n, b) != 0) {
        return -1;
    }
    we_addr_canon(b, 6, out);
    return 0;
}

/* ---- the trusted-proxy table: merged disjoint intervals per family, searched in O(log P) ---- */

typedef struct { uint32_t lo, hi; } we_mod_iv4_t;                 /* host order, inclusive */
typedef struct { uint64_t lo_hi, lo_lo, hi_hi, hi_lo; } we_mod_iv6_t;   /* the two bounds, as two words each */

typedef struct {
    const we_mod_iv4_t *v4;
    const we_mod_iv6_t *v6;
    uint32_t            n4, n6;
    uint8_t             unix_ok;    /* `unix:` is listed: a unix-socket peer is trusted */
    uint8_t             pad[7];
} we_mod_trust_t;

static inline int we_mod_iv6_le(uint64_t ah, uint64_t al, uint64_t bh, uint64_t bl)
{
    return ah < bh || (ah == bh && al <= bl);
}

/* Is the canonical address `a` inside a trusted interval? `searches` counts the binary searches. */
static inline int we_mod_trusted(const we_mod_trust_t *t, const we_addr_t *a, uint32_t *searches)
{
    if (searches != NULL) {
        (*searches)++;
    }
    if (a->family == 4u) {
        uint32_t v = (uint32_t)a->b[0] << 24 | (uint32_t)a->b[1] << 16 | (uint32_t)a->b[2] << 8 | a->b[3];
        uint32_t lo = 0u, hi = t->n4;

        /* the last interval whose start is at or below v, then one compare with its end */
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2u;

            if (t->v4[mid].lo <= v) {
                lo = mid + 1u;
            } else {
                hi = mid;
            }
        }
        return lo > 0u && v <= t->v4[lo - 1u].hi;
    } else {
        uint64_t h = 0u, l = 0u;
        uint32_t k, lo = 0u, hi = t->n6;

        for (k = 0u; k < 8u; k++) {
            h = h << 8 | a->b[k];
            l = l << 8 | a->b[8u + k];
        }
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2u;

            if (we_mod_iv6_le(t->v6[mid].lo_hi, t->v6[mid].lo_lo, h, l)) {
                lo = mid + 1u;
            } else {
                hi = mid;
            }
        }
        return lo > 0u && we_mod_iv6_le(h, l, t->v6[lo - 1u].hi_hi, t->v6[lo - 1u].hi_lo);
    }
}

/* ---- the trusted-header walk ---- */

#define WE_MOD_WALK_LINES    16u     /* the newest field lines a server keeps for the walk */
#define WE_MOD_WALK_ENTRIES  16u     /* entries the walk reaches at most */
#define WE_MOD_WALK_BYTES  1024u     /* bytes it examines at most: 16 entries of 53, separators, OWS */
#define WE_MOD_HOPS_MAX      16u     /* `whisper_edge_trusted_hops` 1..16 */

/* One field line's value, as the server holds it; never NUL-terminated, never copied. */
typedef struct {
    const uint8_t *p;
    size_t         len;
} we_mod_line_t;

/*
 * The walk's result. `floor` is the judged address, `walk` the core's walk mark, `eligible` whether
 * hold-harmless may apply, `note` why it is not simply the walk's answer. `line` is the index (in the
 * caller's array) of the line holding the judged entry, -1 when the peer is judged, with `off` and
 * `len` the entry's trimmed bytes there. The three counts are what the walk spent, for the trace rows.
 */
typedef struct {
    we_addr_t floor;
    uint8_t   walk;
    uint8_t   eligible;
    uint8_t   note;
    uint8_t   pad;
    int32_t   line;
    uint32_t  off, len;
    uint32_t  entries, bytes, searches;
} we_mod_walk_t;

static inline int we_mod_ows(uint8_t c)
{
    return c == ' ' || c == '\t';
}

/*
 * THE WALK, right to left over the lines and their comma-separated elements, OWS trimmed, empty elements
 * skipped across line boundaries. `lines[0..n)` are the newest n lines of the configured header in
 * arrival order (so the walk starts at lines[n - 1]'s last element); `older` says that lines older than
 * lines[0] exist and were not kept, so reaching lines[0]'s first element is reaching the cap. `peer` is
 * the canonical TCP peer, or NULL for a unix-socket peer. `header_set` is whether
 * whisper_edge_trusted_header is configured; `hops` is whisper_edge_trusted_hops, 0 for skip mode.
 *
 * The outcomes are the table in POLICY.md's rendering section, row for row:
 *  - an untrusted peer, or no trusted header: the peer, OK, eligible (a unix peer: no address);
 *  - a trusted peer and the header absent (n == 0): the peer (`::` for a unix peer), FLOOR_HEADER_MISSING,
 *    eligible for an IP peer and not for a unix one;
 *  - no entry parses (zero entries, the rightmost element bad, or the cap first): the peer,
 *    FLOOR_HEADER_MISSING, not eligible, `unparsed`; no header content ever yields NO_ADDRESS;
 *  - skip mode: trusted entries are skipped and the first untrusted one judged, eligible only when no
 *    hop was skipped; every reached entry trusted: the RIGHTMOST reached, not eligible, `capped` when the
 *    cap was the reason;
 *  - `hops` N: the Nth entry from the right, every entry passed over a skipped hop, so eligible only for
 *    N = 1; fewer than N entries: the leftmost, `unparsed`; the cap before the Nth: the last parsed,
 *    `capped`;
 *  - a bad entry after a parsed one: the last parsed (the nearest to its right), not eligible, `unparsed`.
 * At most 16 entries, 1,024 bytes and 17 binary searches (the peer's, then one per entry); an element
 * longer than 53 bytes after trimming is not scanned past its 54th byte.
 *
 * THE LINE CAP is the walk's own: given more than WE_MOD_WALK_LINES lines it walks the newest
 * WE_MOD_WALK_LINES and treats the rest as older lines not kept (`older` set), so a module that hands it
 * every line and one that keeps the newest sixteen get the same verdict for the same request.
 */
static inline void we_mod_walk(const we_mod_trust_t *t, uint32_t hops, int header_set, const we_addr_t *peer,
                               const we_mod_line_t *lines, uint32_t n, int older, we_mod_walk_t *out)
{
    we_addr_t first, last;           /* the rightmost and the last (leftmost so far) entries that parsed */
    int32_t first_line = -1, last_line = -1, li;
    uint32_t first_off = 0u, first_len = 0u, last_off = 0u, last_len = 0u, parsed = 0u, skipped = 0u;
    uint32_t lo = n > WE_MOD_WALK_LINES ? n - WE_MOD_WALK_LINES : 0u;   /* the line cap: the newest 16 */
    int cap = 0, bad = 0;

#ifdef WE_MOD_TEST_NO_LINE_CLAMP
    lo = 0u;                                 /* the control: every line walked */
#endif
#ifdef WE_MOD_TEST_FIRST_LINE
    n = n > 1u ? 1u : n;                     /* the control: the first field line alone, the client's own */
    lo = 0u;
#endif
#ifdef WE_MOD_TEST_FIRST_16_LINES
    n = n > WE_MOD_WALK_LINES ? WE_MOD_WALK_LINES : n;   /* the control: the oldest sixteen, not the newest */
    lo = 0u;
#endif
    if (lo != 0u) {
        older = 1;                           /* the lines below the cap are older lines not kept */
    }
    memset(out, 0, sizeof *out);
    memset(&first, 0, sizeof first);
    memset(&last, 0, sizeof last);
    out->line = -1;
    if (peer == NULL) {
        /* a unix-socket peer is judged only as `::`, and only when it is trusted and the header is set */
        if (!header_set || !t->unix_ok) {
            out->walk = WE_WALK_NO_ADDRESS;
            return;
        }
        out->floor.family = 6u;
    } else {
        out->floor = *peer;
        if (!header_set || !we_mod_trusted(t, peer, &out->searches)) {
            out->walk = WE_WALK_OK;
            out->eligible = 1u;
            return;
        }
    }
    if (n == 0u) {
        out->walk = WE_WALK_FLOOR_HEADER_MISSING;
        out->eligible = (uint8_t)(peer != NULL);
        return;
    }
/* one byte examined: the budget is checked BEFORE the byte is read, so exactly 1,024 can be */
#define WE_MOD_TAKE() do { if (out->bytes == WE_MOD_WALK_BYTES) { cap = 1; goto stop; } out->bytes++; } while (0)
    for (li = (int32_t)n - 1; li >= (int32_t)lo; li--) {
        const uint8_t *p = lines[li].p;
        size_t pos = lines[li].len;          /* the bytes [0, pos) are still to the left */

        for (;;) {
            size_t e, ws;
            int toolong = 0;

            while (pos > 0u && we_mod_ows(p[pos - 1u])) {
                WE_MOD_TAKE();
                pos--;
            }
            e = pos;
#ifdef WE_MOD_TEST_OVERREAD
            if (e == lines[li].len) {
                (void)*(const volatile uint8_t *)&p[e];   /* the control: one byte past the line's end */
            }
#endif
            while (pos > 0u && p[pos - 1u] != ',') {
                WE_MOD_TAKE();
                if (e - pos >= WE_MOD_ENTRY_MAX && !we_mod_ows(p[pos - 1u])) {
                    toolong = 1;             /* a 54th byte of one element: it cannot parse; not read further */
                    break;
                }
                pos--;
            }
            ws = pos;
            while (!toolong && ws < e && we_mod_ows(p[ws])) {
                ws++;                        /* leading OWS, already counted */
            }
            if (toolong || e > ws) {
                we_addr_t a;

#ifndef WE_MOD_TEST_NO_HOP_CAP
                if (out->entries == WE_MOD_WALK_ENTRIES) {
                    cap = 1;                 /* a 17th entry: the cap, whatever it holds */
                    goto stop;
                }
#endif
                out->entries++;
#ifdef WE_MOD_PLANT_CALL_WALK
                (void)getpid();              /* the control: a call inside the parse loop (row V2's walk classes) */
#endif
                if (toolong || we_mod_entry_parse(p + ws, e - ws, &a) != 0) {
                    bad = 1;
                    goto stop;
                }
                if (parsed++ == 0u) {
                    first = a;
                    first_line = li;
                    first_off = (uint32_t)ws;
                    first_len = (uint32_t)(e - ws);
                }
                last = a;
                last_line = li;
                last_off = (uint32_t)ws;
                last_len = (uint32_t)(e - ws);
                if (hops != 0u ? parsed == hops : !we_mod_trusted(t, &a, &out->searches)) {
                    out->floor = a;
                    out->walk = WE_WALK_OK;
                    out->eligible = (uint8_t)(skipped == 0u);
                    out->line = li;
                    out->off = (uint32_t)ws;
                    out->len = (uint32_t)(e - ws);
#ifdef WE_MOD_TEST_SPAN_OFF
                    out->len++;                  /* the control: a span one byte long */
#endif
                    return;
                }
                skipped++;
            }
            if (pos == 0u) {
                break;                       /* this line's first element: on to the next older line */
            }
            WE_MOD_TAKE();                   /* the comma */
            pos--;
        }
    }
    if (older) {
        cap = 1;                             /* lines older than the kept ones exist: their entries are the cap's */
    }
stop:
#undef WE_MOD_TAKE
    if (parsed == 0u) {
        /* nothing in the header vouches for an address: the peer, marked, never NO_ADDRESS */
        out->walk = WE_WALK_FLOOR_HEADER_MISSING;
        out->eligible = 0u;
        out->note = WE_MOD_NOTE_UNPARSED;
        return;
    }
    out->walk = WE_WALK_OK;
    out->eligible = 0u;
    if (bad) {
#ifdef WE_MOD_TEST_PEER_ON_UNPARSED
        out->walk = WE_WALK_FLOOR_HEADER_MISSING;
        out->note = WE_MOD_NOTE_UNPARSED;
        return;                              /* the control: the peer judged, the last parsed entry dropped */
#endif
        out->note = WE_MOD_NOTE_UNPARSED;    /* the last entry that parsed, the bad one's right neighbour */
    } else if (hops == 0u) {
        /* skip mode, every reached entry trusted: the RIGHTMOST reached entry, never the last reached */
        out->floor = first;
        out->line = first_line;
        out->off = first_off;
        out->len = first_len;
        out->note = (uint8_t)(cap ? WE_MOD_NOTE_CAPPED : WE_MOD_NOTE_NONE);
        return;
    } else {
        /* fewer than N entries (the leftmost), or the cap first (the last parsed) */
        out->note = (uint8_t)(cap ? WE_MOD_NOTE_CAPPED : WE_MOD_NOTE_UNPARSED);
    }
    out->floor = last;
    out->line = last_line;
    out->off = last_off;
    out->len = last_len;
}

/* ---- ACME HTTP-01 ---- */

/*
 * The exemption: GET or HEAD; a request-target with no `?` anywhere (an empty query, `tok?`, is a query);
 * the normalised path exactly `/.well-known/acme-challenge/` and one segment of [A-Za-z0-9_-]+; and the
 * raw path byte-equal to the normalised one. The raw path is the request-target as received, an
 * absolute-form `scheme://authority` prefix removed. So `%2e` dot segments, a percent-encoded token
 * character and a leading `//` are never exempt, because each makes the raw path differ.
 * `norm` is the server's normalised, percent-decoded path for this evaluation.
 */
static inline int we_mod_acme(const uint8_t *method, size_t mlen, const uint8_t *target, size_t tlen,
                              const uint8_t *norm, size_t nlen)
{
    static const char pfx[] = "/.well-known/acme-challenge/";
    size_t i, plen = sizeof pfx - 1u, r = 0u;

    if (!((mlen == 3u && memcmp(method, "GET", 3) == 0) || (mlen == 4u && memcmp(method, "HEAD", 4) == 0))) {
        return 0;
    }
    if (tlen == 0u) {
        return 0;
    }
    for (i = 0u; i < tlen; i++) {
        if (target[i] == '?') {
            return 0;                        /* any query, an empty one included */
        }
    }
    if (target[0] != '/') {
        /* absolute-form: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), then "://", the authority */
        if (!((target[0] | 0x20) >= 'a' && (target[0] | 0x20) <= 'z')) {
            return 0;
        }
        for (i = 1u; i < tlen; i++) {
            uint8_t c = target[i];

            if (!(((c | 0x20) >= 'a' && (c | 0x20) <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
                break;
            }
        }
        if (i + 3u > tlen || memcmp(target + i, "://", 3) != 0) {
            return 0;
        }
        for (r = i + 3u; r < tlen && target[r] != '/'; r++) {
        }
        if (r == tlen) {
            return 0;
        }
    }
    if (nlen <= plen || memcmp(norm, pfx, plen) != 0) {
        return 0;
    }
    for (i = plen; i < nlen; i++) {
        uint8_t c = norm[i];

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return 0;
        }
    }
    return tlen - r == nlen && memcmp(target + r, norm, nlen) == 0;
}

/* The request the core reads, from the walk, the ACME test and the server's own address after its realip. */
static inline void we_mod_req_build(we_mod_req_t *q, const we_mod_walk_t *w, const we_addr_t *server, int acme)
{
    memset(q, 0, sizeof *q);
    q->r.floor = w->floor;
    if (server != NULL) {
        q->r.server = *server;
    }
    q->r.hold_harmless_eligible = w->eligible;
    q->r.acme_exempt = (uint8_t)(acme != 0);
    q->r.walk = w->walk;
    q->note = w->note;
}

/* ---- the attributes, rendered on the request path without a copy ---- */

/*
 * The attribute vocabulary as the request path renders it: the same 25 entries, in the same order, as
 * the core's we_attr_info() (test_module holds every field equal). `plane` is plane_id - 1.
 */
typedef struct {
    const char *name;
    uint8_t     plane, cls, off, mask, dom;
} we_mod_attr_t;
#define WE_MOD_ATTRS 25u
#define WE_MOD_DOM_RPKI   1u
#define WE_MOD_DOM_REASON 2u
#define WE_MOD_DOM_REP    3u
#define WE_MOD_DOM_RIR    4u

static inline const we_mod_attr_t *we_mod_attr(uint32_t i)
{
    static const we_mod_attr_t a[WE_MOD_ATTRS] = {
        { "inferred",         0, WE_ATTR_BOOL,    0, 0x80u, 0 },
        { "rpki_unreachable", 2, WE_ATTR_BOOL,    0, 0x01u, 0 },
        { "tor_exit",         1, WE_ATTR_BOOL,    0, 0x01u, 0 },
        { "proxy",            4, WE_ATTR_BOOL,    0, 0x01u, 0 },
        { "vpn",              4, WE_ATTR_BOOL,    0, 0x02u, 0 },
        { "c2",               5, WE_ATTR_BOOL,    0, 0x01u, 0 },
        { "bruteforce",       5, WE_ATTR_BOOL,    0, 0x02u, 0 },
        { "spam",             5, WE_ATTR_BOOL,    0, 0x04u, 0 },
        { "phishing",         5, WE_ATTR_BOOL,    0, 0x08u, 0 },
        { "scanner",          5, WE_ATTR_BOOL,    0, 0x10u, 0 },
        { "state_actor",      5, WE_ATTR_BOOL,    0, 0x20u, 0 },
        { "anycast",          3, WE_ATTR_BOOL,    8, 0x01u, 0 },
        { "moas",             3, WE_ATTR_BOOL,    8, 0x02u, 0 },
        { "narrowed",         3, WE_ATTR_BOOL,    8, 0x04u, 0 },
        { "tenant_allow",     7, WE_ATTR_BOOL,    0, 0x01u, 0 },
        { "tenant_deny",      7, WE_ATTR_BOOL,    0, 0x02u, 0 },
        { "listed",           0, WE_ATTR_LEVEL,   0, 0,     0 },
        { "rpki_reason",      2, WE_ATTR_ENUM,    5, 0,     WE_MOD_DOM_REASON },
        { "rpki",             3, WE_ATTR_ENUM,    6, 0,     WE_MOD_DOM_RPKI },
        { "asn",              3, WE_ATTR_ASN,     0, 0,     0 },
        { "asn_rep",          3, WE_ATTR_ENUM,    9, 0,     WE_MOD_DOM_REP },
        { "country",          3, WE_ATTR_COUNTRY, 4, 0,     0 },
        { "registry_country", 6, WE_ATTR_COUNTRY, 4, 0,     0 },
        { "rir",              3, WE_ATTR_ENUM,    7, 0,     WE_MOD_DOM_RIR },
        { "registry_rir",     6, WE_ATTR_ENUM,    7, 0,     WE_MOD_DOM_RIR },
    };

    return i < WE_MOD_ATTRS ? &a[i] : (const we_mod_attr_t *)NULL;
}

/* The words a value renders as: one static table, so a rendering is a pointer and a length. */
static inline const char *we_mod_enum_word(uint32_t dom, uint32_t v)
{
    static const char *const rpki[5] = { "undetermined", "valid", "invalid", "not-found", "unrouted" };
    static const char *const reason[3] = { "undetermined", "asn", "length" };
    static const char *const rep[5] = { "undetermined", "reputable", "neutral", "suspicious", "highly_suspicious" };
    static const char *const rir[6] = { "undetermined", "afrinic", "apnic", "arin", "lacnic", "ripe" };

    return dom == WE_MOD_DOM_RPKI ? (v < 5u ? rpki[v] : "?")
         : dom == WE_MOD_DOM_REASON ? (v < 3u ? reason[v] : "?")
         : dom == WE_MOD_DOM_REP ? (v < 5u ? rep[v] : "?")
         : (v < 6u ? rir[v] : "?");
}

static inline const char *we_mod_level_word(uint32_t v)
{
    static const char *const level[5] = { "none", "low", "medium", "high", "critical" };

    return level[(v & 0x0fu) <= 4u ? (v & 0x0fu) : 4u];
}

/*
 * The lengths of the words above, in the same order: a rendering's length is known, never measured. A
 * libc strlen over a static word costs instructions that follow the word's address (the x86_64 string
 * routines take an alignment-dependent path), so the cachegrind rows read link layout as code. Measured:
 * a 1,000-byte plant linked before the core moved gcc x86_64 module-export by 1.49 instructions a request.
 */
static inline size_t we_mod_enum_len(uint32_t dom, uint32_t v)
{
    static const uint8_t rpki[5] = { 12u, 5u, 7u, 9u, 8u };
    static const uint8_t reason[3] = { 12u, 3u, 6u };
    static const uint8_t rep[5] = { 12u, 9u, 7u, 10u, 17u };
    static const uint8_t rir[6] = { 12u, 7u, 5u, 4u, 6u, 4u };

    return dom == WE_MOD_DOM_RPKI ? (v < 5u ? rpki[v] : 1u)
         : dom == WE_MOD_DOM_REASON ? (v < 3u ? reason[v] : 1u)
         : dom == WE_MOD_DOM_REP ? (v < 5u ? rep[v] : 1u)
         : (v < 6u ? rir[v] : 1u);
}

static inline size_t we_mod_level_len(uint32_t v)
{
#ifndef WE_MOD_TEST_LEN_OFF
    static const uint8_t level[5] = { 4u, 3u, 6u, 4u, 8u };
#else
    static const uint8_t level[5] = { 4u, 3u, 6u, 3u, 8u };   /* the control: "high" one byte short */
#endif

    return level[(v & 0x0fu) <= 4u ? (v & 0x0fu) : 4u];
}

#define WE_MOD_ASN_BUF 11u   /* 4294967294 and its terminator */

/*
 * Attribute i's value from a memo block (the entry's block[14], then its `lapsed` byte, then a pad)
 * under the plane's memo state, exactly as the core's we_attr_render() writes it, without a copy: *s
 * points into static storage, or into `asn` for the one computed value, an AS number. 0, or -1 for an
 * index out of range. The tools render through we_attr_render(); test_module holds the two byte-equal
 * over every (attribute, state, block) class.
 */
static inline int we_attr_render_fast(uint32_t i, const uint8_t block[16], uint32_t state, char asn[WE_MOD_ASN_BUF],
                                      const char **s, size_t *len)
{
    const we_mod_attr_t *t = we_mod_attr(i);
    const char *w;
    size_t l;

/* a word and its length, both from the literal: never measured at run time (see we_mod_enum_len) */
#define WE_MOD_WORD(lit) (w = (lit), l = sizeof(lit) - 1u)
    if (t == NULL || block == NULL) {
        return -1;
    }
    if (state == WE_ST_NONE) {
        WE_MOD_WORD("unread");
    } else if (state == WE_ST_REVOKED) {
        WE_MOD_WORD("revoked");
    } else if (state == WE_ST_UNKNOWN || ((state == WE_ST_STALE_HIT || state == WE_ST_STALE_NR) && t->plane != 7u)) {
        WE_MOD_WORD("unknown");
    } else if (state == WE_ST_STALE_HIT || state == WE_ST_STALE_NR) {
        /* the tenant's stale record: within the 48-hour grace `stale:`, past it (byte 14) `lapsed:` */
        if (block[14] != 0u) {
            if ((block[t->off] & t->mask) != 0u) { WE_MOD_WORD("lapsed:true"); } else { WE_MOD_WORD("lapsed:false"); }
        } else {
            if ((block[t->off] & t->mask) != 0u) { WE_MOD_WORD("stale:true"); } else { WE_MOD_WORD("stale:false"); }
        }
    } else if (t->cls == WE_ATTR_BOOL) {
        if ((block[t->off & 15u] & t->mask) != 0u) { WE_MOD_WORD("true"); } else { WE_MOD_WORD("false"); }
    } else if (t->cls == WE_ATTR_LEVEL) {
        w = we_mod_level_word(block[t->off & 15u]);
        l = we_mod_level_len(block[t->off & 15u]);
    } else if (t->cls == WE_ATTR_ENUM) {
        w = we_mod_enum_word(t->dom, block[t->off & 15u]);
        l = we_mod_enum_len(t->dom, block[t->off & 15u]);
    } else if (t->cls == WE_ATTR_ASN) {
        uint32_t a, k = 0u;
        char tmp[WE_MOD_ASN_BUF];

        __builtin_memcpy(&a, block + (t->off & 15u), 4);
        if (a == 0xffffffffu) {
            WE_MOD_WORD("undetermined");
        } else {
            do {
                tmp[k++] = (char)('0' + a % 10u);
                a /= 10u;
            } while (a != 0u);
            *len = k;
            while (k > 0u) {
                asn[*len - k] = tmp[k - 1u];
                k--;
            }
            asn[*len] = '\0';
            *s = asn;
            return 0;
        }
    } else {
        uint16_t c;

        __builtin_memcpy(&c, block + (t->off & 15u), 2);
#ifdef WE_MOD_TEST_NO_COUNTRY_COMPARE
        w = c == 0u ? "undetermined" : we_country_a2_table()[c];   /* the control: the compare removed */
        l = 2u;
#elif defined(WE_MOD_TEST_COUNTRY_SCAN)
        {
            /* the control: the pin's renderer, which walked a code-ordered list entry by entry to the
             * code; here the direct table's known entries are walked up to the code the same way (the
             * cachegrind gate's country class must see it) */
            const we_country_a2_t *tab = we_country_a2_table();
            uint32_t j, seen = 0u;

            for (j = 1u; j < 1000u && j < c; j++) {
                seen += tab[j][0] != '\0';
            }
            __asm__ __volatile__("" : : "r"(seen));
            w = c == 0u || c > 999u ? "undetermined" : tab[c];
        }
#else
        w = c == 0u || c > 999u ? "undetermined" : we_country_a2_table()[c];
#endif
        /* a country entry is two letters and its terminator, or empty, which reads undetermined; the
         * one other word here is "undetermined" itself, whose third byte is a letter */
        if (w[0] == '\0') {
            WE_MOD_WORD("undetermined");
        } else {
            l = w[2] == '\0' ? 2u : 12u;
        }
    }
#undef WE_MOD_WORD
    *s = w;
    *len = l;
    return 0;
}

/* ---- the request record ---- */

/*
 * What outlives the handler: 576 bytes, nine lines, allocated 64-byte aligned BY HAND from the server's
 * ordinary pool (576 + 63 bytes, the pointer rounded up), never through an aligned allocator. The
 * verdict's fixed fields and bitmaps, the floor address and Apache's two last-evaluation pointers fill
 * the first two lines; the server address's memo slot the next five; the tail and the provenance line
 * the last two. Every variable renders from here, when it is read, through the renderers below.
 */
typedef struct {
    /* lines 0 and 1 */
    WE_ALIGN64 uint8_t step;
    uint8_t            action, program, reason, unknown_plane, marks, enforce, pad0;
    uint16_t           rule;
    uint8_t            pad1[6];
    uint8_t            log_fired[2][32];
    we_addr_t          floor;              /* the judged floor address */
    const void        *per_dir_config;     /* Apache: the last evaluation's, for the REALLY_LAST fixups */
    const void        *uri;
    uint8_t            pad2[8];
    /* lines 2 to 6 */
    we_memo_slot_t     slot;               /* the server address's */
    /* line 7, the tail */
    const we_mod_ctx_t *ctx;
    uint64_t           generation;         /* the generation of the decision: its reputation entry's */
    uint8_t            lazy_mask;          /* per plane: the entry came from a lazy fill (`*`) */
    uint8_t            disarmed_mask;      /* per plane: the entry came from the stand-in */
    uint8_t            severity;           /* 0 allow, 1 would-deny, 2 deny: the chain's fold */
    uint8_t            decided;            /* a decision has been written */
    uint8_t            raw_rep;            /* the unclamped reputation byte, for the drop flag */
    uint8_t            flags;              /* bit 0: Apache's notes written for this request_rec */
    uint8_t            eval_action;        /* Apache: this request_rec's own evaluation */
    uint8_t            eval_mode;
    uint16_t           eval_status;
    uint8_t            pad3[6];
    const void        *chain;              /* Apache: the chain's view, copied forward along r->prev */
    char               asn[WE_MOD_ASN_BUF];
    uint8_t            pad4[13];
    /* line 8, the provenance */
    uint8_t            digest4[8][4];      /* per plane: the backing map's header digest, first four bytes */
    uint8_t            nomap[3];           /* per plane: a WE_MOD_NOMAP_* code, three bits each */
    uint8_t            gen_mask;           /* the context's, copied */
    uint8_t            pad5[28];
} we_mod_record_t;
WE_STATIC_ASSERT(sizeof(we_mod_record_t) == 576u, "the record is nine lines");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, log_fired) == 16u, "the bitmaps follow the fixed fields");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, floor) == 80u, "the floor address at 80");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, per_dir_config) == 104u, "Apache's pointers at 104");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, uri) == 112u, "Apache's uri at 112");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, slot) == 128u, "the memo slot at 128");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, ctx) == 448u, "the tail at 448");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, generation) == 456u, "tail 8");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, lazy_mask) == 464u, "tail 16");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, disarmed_mask) == 465u, "tail 17");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, severity) == 466u, "tail 18");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, decided) == 467u, "tail 19");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, raw_rep) == 468u, "tail 20");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, flags) == 469u, "tail 21");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_action) == 470u, "tail 22");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_mode) == 471u, "tail 23");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_status) == 472u, "tail 24");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, chain) == 480u, "tail 32");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, asn) == 488u, "tail 40");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, digest4) == 512u, "the provenance line at 512");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, nomap) == 544u, "provenance 32");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, gen_mask) == 547u, "provenance 35");
WE_STATIC_ASSERT(offsetof(we_verdict_t, log_fired) == 16u, "the verdict's bitmaps at 16, as the record's");
/* the record write copies the verdict's first 80 bytes onto the record's: every field at the same place */
WE_STATIC_ASSERT(offsetof(we_verdict_t, step) == offsetof(we_mod_record_t, step)
                 && offsetof(we_verdict_t, action) == offsetof(we_mod_record_t, action)
                 && offsetof(we_verdict_t, program) == offsetof(we_mod_record_t, program)
                 && offsetof(we_verdict_t, reason) == offsetof(we_mod_record_t, reason)
                 && offsetof(we_verdict_t, unknown_plane) == offsetof(we_mod_record_t, unknown_plane)
                 && offsetof(we_verdict_t, marks) == offsetof(we_mod_record_t, marks)
                 && offsetof(we_verdict_t, enforce) == offsetof(we_mod_record_t, enforce)
                 && offsetof(we_verdict_t, rule) == offsetof(we_mod_record_t, rule)
                 && sizeof(((we_verdict_t *)0)->log_fired) == sizeof(((we_mod_record_t *)0)->log_fired)
                 && offsetof(we_mod_record_t, floor) == 80u, "the verdict's 80 bytes lie on the record's");
#define WE_MOD_RECORD_ALLOC (sizeof(we_mod_record_t) + 63u)   /* the bytes a module asks its pool for */
#define WE_MOD_FLAG_NOTES_WRITTEN 0x01u

/* The 64-byte aligned record inside a pool allocation of WE_MOD_RECORD_ALLOC bytes. */
static inline we_mod_record_t *we_mod_record_at(void *raw)
{
    return (we_mod_record_t *)(void *)(((uintptr_t)raw + 63u) & ~(uintptr_t)63u);
}

static inline uint32_t we_mod_nomap_get(const we_mod_record_t *rec, uint32_t p)
{
    uint32_t w = (uint32_t)rec->nomap[0] | (uint32_t)rec->nomap[1] << 8 | (uint32_t)rec->nomap[2] << 16;

    return (w >> (3u * (p & 7u))) & 7u;
}

static inline void we_mod_nomap_set(we_mod_record_t *rec, uint32_t p, uint32_t code)
{
    uint32_t w = (uint32_t)rec->nomap[0] | (uint32_t)rec->nomap[1] << 8 | (uint32_t)rec->nomap[2] << 16;

    w = (w & ~(7u << (3u * (p & 7u)))) | (code & 7u) << (3u * (p & 7u));
    rec->nomap[0] = (uint8_t)w;
    rec->nomap[1] = (uint8_t)(w >> 8);
    rec->nomap[2] = (uint8_t)(w >> 16);
}

/* A fresh record for one request: everything zero, the context's pointer and token set. */
static inline void we_mod_record_init(we_mod_record_t *rec, const we_mod_ctx_t *x)
{
    memset(rec, 0, sizeof *rec);
    rec->ctx = x;
    rec->gen_mask = x != NULL ? x->gen_mask : 0u;
}

/* Key the record's slot to the server address, as a read before the decision does; a re-key resets every plane. */
static inline void we_mod_record_key(we_mod_record_t *rec, const we_addr_t *server)
{
    uint64_t hi, lo;
    int was = rec->slot.key_valid;
    uint8_t before[16], fam = rec->slot.family;

    __builtin_memcpy(before, rec->slot.addr, 16);
    __builtin_memcpy(&hi, server->b, 8);
    __builtin_memcpy(&lo, server->b + 8, 8);
    we_slot_key(&rec->slot, hi, lo, server->family);
    if (!was || fam != server->family || memcmp(before, server->b, 16) != 0) {
        /* a re-key resets every per-plane mark with the states */
        rec->lazy_mask = 0u;
        rec->disarmed_mask = 0u;
        rec->raw_rep = 0u;
        memset(rec->digest4, 0, sizeof rec->digest4);
        memset(rec->nomap, 0, sizeof rec->nomap);
    }
}

/*
 * THE ONE RULE for every memo write of plane p into the record (the decision's merge, a lazy fill, a
 * re-key's replacement): the entry and state are copied, and p's lazy bit, its disarmed bit (set exactly
 * when the map that produced the entry is p's stand-in, the entry then stored UNKNOWN at generation 0),
 * its no-map reason, its digest prefix and, for reputation, the raw byte are all RECOMPUTED from `view`,
 * the map pointer that produced the entry. Never read through a map later: the log phase may run past
 * the map's grace.
 */
static inline void we_mod_memo_put(we_mod_record_t *rec, const we_mod_cfg_t *c, uint32_t p, const we_memo_entry_t *e,
                                   uint32_t state, const we_map_t *view, int lazy)
{
    uint8_t bit = (uint8_t)(1u << (p & 7u));
    uint32_t code = WE_MOD_NOMAP_NONE;

    p &= 7u;
    rec->slot.e[p] = *e;
    rec->slot.state[p] = (uint8_t)state;
    rec->lazy_mask = (uint8_t)(lazy ? rec->lazy_mask | bit : rec->lazy_mask & (uint8_t)~bit);
    memset(rec->digest4[p], 0, 4);
    if (view != NULL && view == c->standin[p]) {
        rec->disarmed_mask = (uint8_t)(rec->disarmed_mask | bit);
        rec->slot.state[p] = (uint8_t)WE_ST_UNKNOWN;
        rec->slot.e[p].generation = 0u;
    } else {
        rec->disarmed_mask = (uint8_t)(rec->disarmed_mask & (uint8_t)~bit);
        if (view != NULL) {
            __builtin_memcpy(rec->digest4[p], view->digest, 4);
        } else if (c->handle[p] == NULL) {
            code = c->static_reason[p] != 0u ? c->static_reason[p] : WE_MOD_NOMAP_ABSENT;
        } else {
            code = c->null_reason != NULL ? __atomic_load_n(&c->null_reason[p], __ATOMIC_ACQUIRE) : WE_MOD_NOMAP_LOADING;
#ifndef WE_MOD_TEST_NOMAP_CLAMP
            /* absent, refused or loading, as the single writer stored it; the mask keeps it in the 3-bit field.
             * Measured cheaper than the two-way clamp it replaces (module-export, gcc -1.9 and clang -1.0
             * instructions a request), which a third state could not keep: its select folded two constants */
            code &= 7u;
#else
            code = code == WE_MOD_NOMAP_REFUSED ? WE_MOD_NOMAP_REFUSED : WE_MOD_NOMAP_LOADING;   /* the control: -a lost */
#endif
        }
    }
    we_mod_nomap_set(rec, p, code);
    if (p == 0u) {
        uint8_t raw = 0u;

        /* the drop flag lives only in the unclamped byte, read through the exact view the fill used */
        if (state == WE_ST_FRESH_HIT && view != NULL && view != c->standin[0] && e->range != WE_NO_RANGE) {
            const we_fam_t *f = e->family == 4u ? &view->f4 : &view->f6;

            if (f->sev != NULL && e->range < f->n) {
                raw = f->sev[e->range];
            }
        }
        rec->raw_rep = raw;
    }
}

/* A program's rule r (0-based) is a deny: what makes a fired log bit a would-deny. */
static inline int we_mod_rule_is_deny(const we_program_t *p, uint32_t r)
{
    const we_rule_t *rules;

    if (p == NULL || r >= p->rule_count) {
        return 0;
    }
    rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    return rules[r].action == WE_ACT_DENY;
}

/*
 * 2 deny (enforced), 1 would-deny (a downgraded deny fired), 0 allow. The bitmaps are read a 64-bit word
 * at a time and only their set bits are visited, so the common case, an allow with no log bit, is eight
 * loads and an OR, whatever the programs' sizes. WE_MOD_SEVERITY_STEP() marks one bit tested, for
 * test_module's operation count.
 */
#ifndef WE_MOD_SEVERITY_STEP
#define WE_MOD_SEVERITY_STEP() ((void)0)
#endif
static inline uint32_t we_mod_severity(const we_mod_cfg_t *c, const we_mod_ctx_t *x, const we_verdict_t *v)
{
    uint32_t k, w;

    if (v->enforce != 0u) {
        return 2u;
    }
#ifdef WE_MOD_TEST_SEVERITY_SCAN
    for (k = 0u; k < 2u; k++) {             /* the control: all 512 bits tested, one by one */
        const we_program_t *p = k == 0u ? c->floor : x->prog;

        for (w = 0u; w < 256u; w++) {
            WE_MOD_SEVERITY_STEP();
            if (((v->log_fired[k][w >> 3] >> (w & 7u)) & 1u) != 0u && we_mod_rule_is_deny(p, w)) {
                return 1u;
            }
        }
    }
    return 0u;
#else
    {
        uint64_t word[8], any = 0u;

        __builtin_memcpy(word, &v->log_fired[0][0], sizeof word);
        for (w = 0u; w < 8u; w++) {
            any |= word[w];
        }
        if (any == 0u) {
            return 0u;                          /* the all-clear: no log bit fired anywhere */
        }
        for (w = 0u; w < 8u; w++) {
            const we_program_t *p = w < 4u ? c->floor : x->prog;
            uint64_t bits = word[w];

            k = 64u * (w & 3u);
            while (bits != 0u) {
                WE_MOD_SEVERITY_STEP();
                if (we_mod_rule_is_deny(p, k + (uint32_t)__builtin_ctzll(bits))) {
                    return 1u;
                }
                bits &= bits - 1u;
            }
        }
        return 0u;
    }
#endif
}

/*
 * THE RECORD WRITE, after we_mod_decide() returns, outside the gated function, while the decision's
 * views are still inside their grace. The verdict's fixed fields and bitmaps are copied; then the
 * server address's slot: the slot the decision keyed (out->sc.ss) when it keyed one, never a fixed
 * index; for a pre-stage decision, which keys no server slot, the record's slot is keyed to the server
 * address with every state NONE. Where the record already holds an earlier fill for the same address and
 * the decision did not read that plane, the earlier fill is kept. Returns 1 when written, 0 when the
 * record's chain already holds a more severe evaluation (deny over would-deny over allow; at equal
 * severity the latest wins), which enforcement never reads.
 */
static inline int we_mod_record_write(we_mod_record_t *rec, const we_mod_cfg_t *c, const we_mod_ctx_t *x,
                                      const we_mod_scratch_t *s, const we_addr_t *floor, const we_addr_t *server)
{
    const we_verdict_t *v = &s->v;
    uint32_t sev = we_mod_severity(c, x, v), p;

    if (rec->decided && sev < rec->severity) {
        return 0;
    }
#ifdef WE_MOD_TEST_PLANT_ALLOC
    {
        void *volatile planted = malloc(16);   /* the control: an allocation in the cold half (row N2) */

        free(planted);
    }
#endif
    __builtin_memcpy(rec, v, 80);
    rec->floor = *floor;
    rec->ctx = x;
    rec->gen_mask = x->gen_mask;
    rec->severity = (uint8_t)sev;
    rec->decided = 1u;
#ifndef WE_MOD_TEST_SS_UNCONDITIONAL
    if (v->step != WE_STEP_EXEMPT && v->step != WE_STEP_TENANT) {
#else
    if (1) {                             /* the control: sc.ss copied on a pre-stage outcome too (row E1) */
#endif
        const we_memo_slot_t *ss = (const we_memo_slot_t *)v->sc.ss;
        we_addr_t key;

        memset(&key, 0, sizeof key);
        __builtin_memcpy(key.b, ss->addr, 16);
        key.family = ss->family;
        we_mod_record_key(rec, &key);
        for (p = 0u; p < 8u; p++) {
            if (ss->state[p] != WE_ST_NONE) {
                we_mod_memo_put(rec, c, p, &ss->e[p], ss->state[p], s->e.view[p].m, 0);
            }
        }
    } else {
        we_mod_record_key(rec, server);
    }
    rec->generation = rec->slot.state[0] != WE_ST_NONE ? rec->slot.e[0].generation : 0u;
    return 1;
}

/*
 * The lazy fill, for every plane in `mask` the record does not hold yet: through ONE local context
 * (`local`, a 64-byte aligned scratch the caller owns: a stack local in a variable handler, the
 * decision's own scratch in the export pass), one verdict clear and one slot copy, whatever the plane
 * count, each plane's view re-taken with we_current() in this invocation. A read before the decision
 * keys the record first (we_mod_record_key()).
 */
static inline void we_mod_fill(we_mod_record_t *rec, const we_mod_cfg_t *c, we_mod_scratch_t *local, uint32_t mask,
                               uint64_t now_ms)
{
    uint32_t p, todo = 0u;

#ifdef WE_MOD_TEST_NO_LAZY
    return;                          /* the control: nothing filled, every unread plane renders `unread` */
#endif
    for (p = 0u; p < 8u; p++) {
        if (((mask >> p) & 1u) != 0u && rec->slot.state[p] == WE_ST_NONE) {
            todo |= 1u << p;
        }
    }
    if (todo == 0u || rec->slot.key_valid == 0u) {
        return;
    }
#ifndef WE_MOD_TEST_LAZY_NO_CLEAR
    we_verdict_clear(&local->v);
#endif
#ifndef WE_MOD_TEST_WORKER_SCRATCH_FILL
    local->e.slot[1] = rec->slot;
#else
    /* the control: the fill keyed by the worker's last decision, not the record's own. It reads only the
     * core's copy of that decision's slot (we_mod_test_last_slot), never the caller's `local`, which is a
     * stack local in a variable handler whose sc.ss no decision wrote */
    local->e.slot[1] = we_mod_test_last_valid ? we_mod_test_last_slot : rec->slot;
#endif
    for (p = 0u; p < 8u; p++) {
        const we_map_t *m;

        if (((todo >> p) & 1u) == 0u) {
            continue;
        }
#ifdef WE_MOD_TEST_LAZY_PER_PLANE
        if ((todo & ((1u << p) - 1u)) != 0u) {
            /* the control: the local context rebuilt for every plane after the first, the 80-byte clear
             * and the 320-byte slot copy again per extra fill (the cachegrind gate's C2+ Dw row) */
            we_verdict_clear(&local->v);
            local->e.slot[1] = rec->slot;
        }
#endif
        m = we_current(c->handle[p]);
        local->e.view[p].m = m;
        we_eval_lazy_fill(&local->e, c->hh, 1u, p + 1u, now_ms, &local->v);
        local->e.view[p].m = NULL;
        if (local->e.slot[1].state[p] != WE_ST_NONE) {
            we_mod_memo_put(rec, c, p, &local->e.slot[1].e[p], local->e.slot[1].state[p], m, 1);
        }
    }
}

/* ---- the renderers the variables read through ---- */

#define WE_MOD_SPELL_NGINX     0u   /* `,drop`, as the shipped nginx module spells the drop flag */
#define WE_MOD_SPELL_SPAMHAUS  1u   /* `,spamhaus-drop`, as the shipped Apache and LiteSpeed modules do */

/* `$whisper_edge_verdict`: the reputation severity of the server's address, by its record entry. */
static inline const char *we_mod_render_verdict(const we_mod_record_t *rec, uint32_t spelling)
{
    static const char *const fresh[2][5][4] = {
        { { "none", "none,drop", "none,inferred", "none,drop,inferred" },
          { "low", "low,drop", "low,inferred", "low,drop,inferred" },
          { "medium", "medium,drop", "medium,inferred", "medium,drop,inferred" },
          { "high", "high,drop", "high,inferred", "high,drop,inferred" },
          { "critical", "critical,drop", "critical,inferred", "critical,drop,inferred" } },
        { { "none", "none,spamhaus-drop", "none,inferred", "none,spamhaus-drop,inferred" },
          { "low", "low,spamhaus-drop", "low,inferred", "low,spamhaus-drop,inferred" },
          { "medium", "medium,spamhaus-drop", "medium,inferred", "medium,spamhaus-drop,inferred" },
          { "high", "high,spamhaus-drop", "high,inferred", "high,spamhaus-drop,inferred" },
          { "critical", "critical,spamhaus-drop", "critical,inferred", "critical,spamhaus-drop,inferred" } },
    };
    uint32_t st = rec->slot.state[0], b;

    if ((rec->disarmed_mask & 1u) != 0u) {
        return "unknown,disarmed";
    }
    if (st == WE_ST_FRESH_HIT) {
        b = rec->slot.e[0].block[0];
        /* the level from the memo's CLAMPED byte, the drop flag from the raw one */
        return fresh[spelling & 1u][(b & 0x0fu) <= 4u ? (b & 0x0fu) : 4u]
                    [((rec->raw_rep & WE_F_DROP) != 0u ? 1u : 0u) | ((b & WE_F_INFERRED) != 0u ? 2u : 0u)];
    }
    if (st == WE_ST_FRESH_NR) {
        return "none";
    }
    return st == WE_ST_UNKNOWN && rec->slot.e[0].generation != 0u ? "unknown,stale" : "unknown";
}

/* `$whisper_edge_<name>`: attribute i of the record's server-address entry; a disarmed plane is `unknown`. */
static inline int we_mod_render_attr(we_mod_record_t *rec, uint32_t i, const char **s, size_t *len)
{
    const we_mod_attr_t *t = we_mod_attr(i);

    if (t == NULL) {
        return -1;
    }
    if (((rec->disarmed_mask >> t->plane) & 1u) != 0u) {
        *s = "unknown";
        *len = 7u;
        return 0;
    }
    /* the entry's first sixteen bytes are the block, its `lapsed` byte and a pad: what the renderer reads */
    return we_attr_render_fast(i, (const uint8_t *)(const void *)&rec->slot.e[t->plane], rec->slot.state[t->plane],
                               rec->asn, s, len);
}

/* `$whisper_edge_action`: allow, deny, would-deny; `-` before a decision. */
static inline const char *we_mod_render_action(const we_mod_record_t *rec)
{
    return !rec->decided ? "-" : rec->severity == 2u ? "deny" : rec->severity == 1u ? "would-deny" : "allow";
}

/*
 * `$whisper_edge_reason`: the decision's own word (empty for a rule's TRUE and the default allow), the
 * walk's word, and `tenant-revoked`, comma-joined; `-` when there is none. Static strings, one per
 * combination. `note` and `walk` are the request's.
 */
static inline const char *we_mod_render_reason(const we_mod_record_t *rec, uint32_t walk, uint32_t note)
{
    static const char *const words[7 * 4 * 2] = {
        "-", "tenant-revoked", "floor-header-missing", "floor-header-missing,tenant-revoked",
        "floor-header-unparsed", "floor-header-unparsed,tenant-revoked", "floor-header-capped", "floor-header-capped,tenant-revoked",
        "allow-by-unknown", "allow-by-unknown,tenant-revoked", "allow-by-unknown,floor-header-missing", "allow-by-unknown,floor-header-missing,tenant-revoked",
        "allow-by-unknown,floor-header-unparsed", "allow-by-unknown,floor-header-unparsed,tenant-revoked", "allow-by-unknown,floor-header-capped", "allow-by-unknown,floor-header-capped,tenant-revoked",
        "hold-harmless", "hold-harmless,tenant-revoked", "hold-harmless,floor-header-missing", "hold-harmless,floor-header-missing,tenant-revoked",
        "hold-harmless,floor-header-unparsed", "hold-harmless,floor-header-unparsed,tenant-revoked", "hold-harmless,floor-header-capped", "hold-harmless,floor-header-capped,tenant-revoked",
        "acme", "acme,tenant-revoked", "acme,floor-header-missing", "acme,floor-header-missing,tenant-revoked",
        "acme,floor-header-unparsed", "acme,floor-header-unparsed,tenant-revoked", "acme,floor-header-capped", "acme,floor-header-capped,tenant-revoked",
        "tenant", "tenant,tenant-revoked", "tenant,floor-header-missing", "tenant,floor-header-missing,tenant-revoked",
        "tenant,floor-header-unparsed", "tenant,floor-header-unparsed,tenant-revoked", "tenant,floor-header-capped", "tenant,floor-header-capped,tenant-revoked",
        "stale-tenant", "stale-tenant,tenant-revoked", "stale-tenant,floor-header-missing", "stale-tenant,floor-header-missing,tenant-revoked",
        "stale-tenant,floor-header-unparsed", "stale-tenant,floor-header-unparsed,tenant-revoked", "stale-tenant,floor-header-capped", "stale-tenant,floor-header-capped,tenant-revoked",
        "no-address", "no-address,tenant-revoked", "no-address,floor-header-missing", "no-address,floor-header-missing,tenant-revoked",
        "no-address,floor-header-unparsed", "no-address,floor-header-unparsed,tenant-revoked", "no-address,floor-header-capped", "no-address,floor-header-capped,tenant-revoked",
    };
    uint32_t d = 0u, w;

    if (!rec->decided) {
        return "-";
    }
    if (rec->reason == WE_WHY_ALLOW_BY_UNKNOWN) {
        d = 1u;
    } else if (rec->step == WE_STEP_EXEMPT) {
        d = rec->reason == WE_WHY_HOLD_HARMLESS ? 2u : rec->reason == WE_WHY_ACME ? 3u : 6u;
    } else if (rec->step == WE_STEP_TENANT) {
        d = 4u;
    } else if (rec->step == WE_STEP_STALE_TENANT) {
        d = 5u;
    }
    w = note == WE_MOD_NOTE_UNPARSED ? 2u : note == WE_MOD_NOTE_CAPPED ? 3u : walk == WE_WALK_FLOOR_HEADER_MISSING ? 1u : 0u;
    return words[(d * 4u + w) * 2u + ((rec->marks & WE_MARK_TENANT_REVOKED) != 0u ? 1u : 0u)];
}

/* Did the context's program run for this decision (not a pre-stage step, not the floor, not mode off)? */
static inline int we_mod_ctx_ran(const we_mod_record_t *rec)
{
    return rec->decided && rec->step == WE_STEP_CONTEXT && rec->ctx != NULL && rec->ctx->prog != NULL
        && we_conf_mode(&rec->ctx->conf) != WE_MODE_OFF;
}

/* `$whisper_edge_program`: `floor:<d16> ctx:<d16>`, `ctx:-` unless the context program ran. */
static inline const char *we_mod_render_program(const we_mod_record_t *rec, const we_mod_cfg_t *c)
{
    if (!rec->decided || rec->ctx == NULL || rec->ctx->cold == NULL) {
        return c->cold != NULL ? c->cold->program_none : "-";
    }
    return we_mod_ctx_ran(rec) ? rec->ctx->cold->program_ctx : rec->ctx->cold->program_floor;
}

/* `$whisper_edge_rule_id` and `$whisper_edge_rule`: the deciding rule's id and canonical text, `-` for none. */
static inline const char *we_mod_render_rule(const we_mod_record_t *rec, const we_mod_cfg_t *c, int text)
{
    const char *const *tab;
    uint32_t n;

    if (!rec->decided || rec->rule == 0u) {
        return "-";
    }
    if (rec->program == WE_VPROG_FLOOR) {
        if (c->cold == NULL) {
            return "-";
        }
        tab = text ? c->cold->rule_text : c->cold->rule_id;
        n = c->cold->rule_count;
    } else {
        if (rec->ctx == NULL || rec->ctx->cold == NULL) {
            return "-";
        }
        tab = text ? rec->ctx->cold->rule_text : rec->ctx->cold->rule_id;
        n = rec->ctx->cold->rule_count;
    }
    return tab != NULL && rec->rule <= n ? tab[rec->rule - 1u] : "-";
}

static inline size_t we_mod_put_u64(char *out, uint64_t v)
{
    char tmp[20];
    size_t k = 0u, o = 0u;

    do {
        tmp[k++] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v != 0u);
    while (k > 0u) {
        out[o++] = tmp[--k];
    }
    return o;
}

#define WE_MOD_LOGGED_MAX 2112u   /* "floor:" and "ctx:" with 256 rule numbers each, and the terminator */

/* `$whisper_edge_logged`: `floor:1,3 ctx:2`, `-` for none. Writes a NUL-terminated string; returns its length. */
static inline size_t we_mod_render_logged(const we_mod_record_t *rec, char out[WE_MOD_LOGGED_MAX])
{
    size_t o = 0u;
    uint32_t k, r;

    for (k = 0u; k < 2u; k++) {
        int any = 0;

        for (r = 0u; r < 256u; r++) {
            if (((rec->log_fired[k][r >> 3] >> (r & 7u)) & 1u) == 0u) {
                continue;
            }
            if (!any) {
                if (o != 0u) {
                    out[o++] = ' ';
                }
                memcpy(out + o, k == 0u ? "floor:" : "ctx:", k == 0u ? 6u : 4u);
                o += k == 0u ? 6u : 4u;
                any = 1;
            } else {
                out[o++] = ',';
            }
            o += we_mod_put_u64(out + o, r + 1u);
        }
    }
    if (o == 0u) {
        out[o++] = '-';
    }
    out[o] = '\0';
    return o;
}

static inline const char *we_mod_plane_word(uint32_t p)
{
    static const char *const name[8] = {
        "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
    };

    return name[p & 7u];
}

/* the plane words' lengths, in the same order: never measured at run time (see we_mod_enum_len) */
static inline size_t we_mod_plane_word_len(uint32_t p)
{
    static const uint8_t len[8] = { 10u, 3u, 16u, 7u, 10u, 6u, 8u, 6u };

    return len[p & 7u];
}

#define WE_MOD_GEN_MAX 512u   /* eight tokens of at most 52 bytes and their separators */

/*
 * `$whisper_edge_generations`: one `<plane>:<g>.<d8><mark>` per plane in the context's token set, in
 * plane order, space separated, AFTER the caller has filled every such plane (we_mod_fill()). `<g>` is the
 * generation of the map that backed the entry and `<d8>` its header digest's first four bytes; with no
 * map, a dash and one letter: `-a` absent or not bound, `-u` unreadable, `-r` refused, `-l` loading,
 * `-d` disarmed. `<mark>`: nothing for fresh, `~` stale, `^` a tenant past its 48 h grace; then `*`
 * after a lazy fill. A revoked tenant is `tenant:0`. Writes a NUL-terminated string; returns its length.
 */
static inline size_t we_mod_render_generations(const we_mod_record_t *rec, char out[WE_MOD_GEN_MAX])
{
    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    static const char letter[5] = { 'a', 'a', 'u', 'r', 'l' };
    size_t o = 0u;
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        const char *nm;
        uint32_t st, code;
        size_t l;

        if (((rec->gen_mask >> p) & 1u) == 0u) {
            continue;
        }
        if (o != 0u) {
            out[o++] = ' ';
        }
        nm = we_mod_plane_word(p);
        l = we_mod_plane_word_len(p);
        memcpy(out + o, nm, l);
        o += l;
        out[o++] = ':';
        st = rec->slot.state[p];
        code = we_mod_nomap_get(rec, p);
        if (((rec->disarmed_mask >> p) & 1u) != 0u) {
            out[o++] = '-';
            out[o++] = 'd';
        } else if (st == WE_ST_NONE || code != WE_MOD_NOMAP_NONE) {
            out[o++] = '-';
            out[o++] = letter[code <= 4u ? code : 0u];
        } else if (st == WE_ST_REVOKED) {
            out[o++] = '0';
        } else {
            uint32_t k;

            o += we_mod_put_u64(out + o, rec->slot.e[p].generation);
            out[o++] = '.';
            for (k = 0u; k < 4u; k++) {
                out[o++] = hex[rec->digest4[p][k] >> 4];
                out[o++] = hex[rec->digest4[p][k] & 15u];
            }
            if ((st == WE_ST_STALE_HIT || st == WE_ST_STALE_NR) && p == WE_TENANT_IX && rec->slot.e[p].lapsed != 0u) {
                out[o++] = '^';
            } else if (st == WE_ST_STALE_HIT || st == WE_ST_STALE_NR
                       || (st == WE_ST_UNKNOWN && rec->slot.e[p].generation != 0u)) {
                out[o++] = '~';
            }
        }
        if (((rec->lazy_mask >> p) & 1u) != 0u) {
            out[o++] = '*';
        }
    }
    out[o] = '\0';
    return o;
}

/* `$whisper_edge_floor_addr`: the judged floor address by the RFC 5952 formatter; `-` for none. */
static inline size_t we_mod_render_floor(const we_mod_record_t *rec, char out[WE_ADDR_TEXT_MAX])
{
    if (rec->floor.family != 4u && rec->floor.family != 6u) {
        out[0] = '-';
        out[1] = '\0';
        return 1u;
    }
    return we_addr_format(&rec->floor, out);
}

/* ---- the configuration-time half, in we_module.c ---- */

/* What building the trusted-proxy table found worth a configuration-test line. */
typedef struct {
    uint32_t configured4, configured6;   /* entries as written, after ::ffff:0:0/96 prefixes became IPv4 */
    uint32_t broad;                      /* prefixes broader than /16 (IPv4) or /32 (IPv6): a warning each */
    uint32_t covers_mapped;              /* IPv6 prefixes covering ::ffff:0:0/96: cannot match an IPv4 peer */
} we_mod_trust_report_t;

/*
 * `whisper_edge_trusted_proxy`'s arguments into the walk's table: each an address, a CIDR prefix, or
 * `unix:`. A prefix inside ::ffff:0:0/96 of length 96 or more becomes the IPv4 prefix it names; then each
 * family's intervals are sorted and merged (duplicates, nested and adjacent ones), so containment is one
 * binary search. 0, or -1 with `err` naming the argument. The arrays are malloc'd: we_mod_trust_free().
 */
int  we_mod_trust_build(const char *const *items, size_t n, we_mod_trust_t *out, we_mod_trust_report_t *rep,
                        char *err, size_t errn);
void we_mod_trust_free(we_mod_trust_t *t);

/*
 * The first eight digest bytes in byte order as lowercase hex, equal to `sha256sum | cut -c1-16`: the one
 * rendering of a digest on every surface (the configuration line, `$whisper_edge_program`, the status and
 * counter files, the summary).
 */
void we_digest16(const uint8_t dg[32], char out[17]);

/*
 * THE ARENA: every distinct block of a configuration once, in page-aligned anonymous chunks, interned on
 * the SHA-256 of the whole block and confirmed by memcmp, each copy verified where it will be read; the
 * configuration's own lifetime bytes (the hold-harmless view on a page of its own, the contexts, the cold
 * strings) beside them. Sealed PROT_READ before any worker starts (on LiteSpeed in WORKER_INIT, after the
 * last virtual host's build), so the pages stay shared after fork. No region cap.
 */
we_mod_arena_t     *we_mod_arena_new(void);
const we_program_t *we_mod_arena_place(we_mod_arena_t *a, const we_program_t *p);
const we_program_t *we_mod_arena_block(const we_mod_arena_t *a, uint32_t i);   /* block i of we_mod_arena_blocks(), or NULL */
void               *we_mod_arena_alloc(we_mod_arena_t *a, size_t len, size_t align);
int                 we_mod_arena_seal(we_mod_arena_t *a);
size_t              we_mod_arena_pages(const we_mod_arena_t *a);
uint32_t            we_mod_arena_blocks(const we_mod_arena_t *a);
void                we_mod_arena_free(we_mod_arena_t *a);

/* One context as the module names it: the ordinal path it gave the compiler, and what it configured. */
typedef struct {
    const char *path;          /* "http", "http/s3", "http/s3/l7": never an operator's text */
    const char *name;          /* the operator's name for it, raw; written escaped wherever it is printed */
    uint16_t    deny_status;   /* its nearest whisper_edge_deny_status, 0 for the http level's */
    uint8_t     export_mask;   /* its default export set's planes */
    uint8_t     gen_mask;      /* the planes its generations token names */
} we_mod_ctx_spec_t;

/*
 * The request path's configuration from one compiled configuration (we_policy_build()): every block in
 * the arena, the floor's hold-harmless view, one we_mod_ctx_t per spec (in the arena; *ctxs) with its
 * counter offset (a context with no lines of its own counts into the nearest enclosing context that has
 * some), and the cold strings. The handles, stand-ins and reasons of cfg are the binding's to fill.
 * *stride is the counter array's length per shard, a multiple of 8. 0, or with msg: WE_MOD_ERR_CAP over
 * WE_MOD_STRIDE_MAX counted slots, the configuration refused naming its five largest contexts; WE_ERR_MMAP
 * when a block cannot be placed or printed (out of memory, or a block that does not verify); or
 * WE_MOD_ERR_SPEC with msg: the spec must list every context that carries lines and is an ancestor of a
 * listed context running them, because only a listed context's rules are counted into the stride; or
 * WE_MOD_ERR_ABI, before anything is written, when `abi` is not this file's WE_MODULE_ABI_VERSION.
 */
int we_mod_config_build(uint32_t abi, we_mod_arena_t *a, const we_policy_build_t *b, const we_policy_source_t *src,
                        const we_mod_ctx_spec_t *spec, size_t n, uint16_t http_status, we_mod_cfg_t *cfg,
                        we_mod_ctx_t **ctxs, uint32_t *stride, char *msg, size_t msgn);

/* ---- binding (no system type here: the gate's cross builds compile this header against a bare shim) ---- */

struct stat;

/* Every file and directory the module opens: openat with O_CLOEXEC added. */
int we_openat_cloexec(int dirfd, const char *name, int flags, unsigned mode);

/*
 * The data directory, walked LEXICALLY from `/` with O_NOFOLLOW | O_DIRECTORY, every directory owned by
 * root or `uid` and writable by neither group nor world (no sticky exception), a link followed only when a
 * trusted owner made it. *out is the held directory's descriptor. 0, or -1 with `why`.
 */
int we_mod_dir_open(const char *path, unsigned uid, int *out, char *why, size_t whyn);
/*
 * The RESOLVED chain of a CONFIGURATION file, realpath() component by component, under the same rule
 * with the trust rule's one exception: a root-owned sticky ancestor (/tmp, as sshd allows above a key file) passes,
 * because the file is found by an explicit path the operator wrote. A plane's directory never gets it:
 * that is we_mod_dir_open's walk. 0, or -1 with `why`.
 */
int we_mod_chain_check(const char *path, unsigned uid, char *why, size_t whyn);

/* What a plane file's header says, read without digesting anything. */
typedef struct {
    uint64_t generation, built_at_ms, valid_until_ms, size;
    uint8_t  digest[32];
    uint32_t format, uid, mode, err;
    uint16_t country_table_version;
    uint8_t  plane_id, schema, absent;
} we_mod_peek_t;
int we_plane_peek(int dirfd, const char *name, uint32_t plane, we_mod_peek_t *out, char *why, size_t whyn);
/*
 * Section 3.2's checks on a bound plane, in order (link, regular file, size, mode 0444 and a trusted owner,
 * or for the legacy file only no group or world write, and no network file system); the descriptor
 * returned open on success. 0, or -1 with `why` naming the fix.
 */
int we_mod_plane_trust(int dirfd, const char *name, unsigned uid, int legacy, int *fdout, struct stat *st,
                       char *why, size_t whyn);

/* ---- the writers: the process's files and the configuration's ---- */

/* The identity that names this process's files, <pid>-<id16>.status and .rules.cnt (we_procid.h's type). */
typedef struct we_procid we_mod_procid_t;
int we_mod_procid(we_mod_procid_t *id);

/*
 * Write a whole file under `name` in `dirfd` through `.<pid>-<starttime>-<kind>.tmp`, created O_EXCL |
 * O_NOFOLLOW and renamed into place; as root, only into a root-owned directory closed to group and world.
 * 0; WE_ERR_PERMISSIONS for that root refusal, which is the directory being provisioned for the workers'
 * user and NOT a reason to stop writing (a module never latches on it: its workers can write there);
 * WE_ERR_OPEN for every other failure, with `why`.
 */
int we_mod_write_file(int dirfd, const we_mod_procid_t *id, const char *kind, const char *name, const char *data,
                      size_t len, char *why, size_t whyn);

/* A text buffer the writers fill; `over` set when it was too small (the file is then not written). */
typedef struct {
    char  *buf;
    size_t len, cap;
    int    over;
} we_mod_text_t;

/* Which counter indexes belong to which block: one entry per context that owns lines, the floor first. */
typedef struct {
    uint32_t ctr_off, rule_count;
    char     digest16[17];
} we_mod_ctrmap_entry_t;
typedef struct {
    const we_mod_ctrmap_entry_t *e;
    uint32_t                     n;
} we_mod_ctrmap_t;

void we_mod_render_rules(we_mod_text_t *t, const we_mod_procid_t *id, const we_mod_ctrmap_t *map, const uint64_t *sum,
                         uint64_t started_ms, uint64_t tick, uint64_t snapshot_ms, uint64_t written_ms, const char *config16);
void we_mod_render_conf(we_mod_text_t *t, const we_mod_cfg_t *c, const we_mod_ctx_t *x, size_t n,
                        const char *const plane_path[8], const char *const unreadable[8],
                        const char *const refused[8]);
void we_mod_conf_name(const we_mod_text_t *t, char out[29]);

/*
 * One plane's line of the status file, and the process's. A field the writer cannot measure is never
 * printed as a number: the measured bits say which were measured, and an unset bit leaves its field out.
 */
#define WE_MOD_MEASURED_IMMUTABLE   0x01u   /* the immutable flag, read from the armed inode */
#define WE_MOD_MEASURED_NONRESIDENT 0x02u   /* mincore over the mapping */
#define WE_MOD_MEASURED_SLOT_AGE    0x04u   /* the format-1 slot's age */
#define WE_MOD_MEASURED_TICKS       0x08u   /* ticks in the current state */
#define WE_MOD_MEASURED_MAJFLT      0x10u   /* the process's major faults since the last tick (process line) */
typedef struct {
    uint8_t  bound, pending, mapped, locked, immutable, dir_replaced;
    char     state[16];          /* absent loading armed stale lapsed refused revoked disarmed */
    char     reason[256];        /* refused's and disarmed's text, raw; written escaped */
    uint64_t generation, posted, pending_ticks, valid_until_ms, since_ms, ticks, bytes, nonresident, eio_backoff_ms;
    uint64_t deferred;           /* results not started for want of a free retire slot */
    uint32_t measured;           /* WE_MOD_MEASURED_*: the fields above that were measured */
    int64_t  remaining_ms, slot_age_ms;
    uint16_t country_table;
    char     digest16[17];
} we_mod_plane_status_t;

#define WE_MOD_TRANSITIONS 16u
#define WE_MOD_RING_ENTRY 512u
typedef struct {
    const char           *server;   /* "nginx/1.24.0" */
    uint64_t              started_ms, written_ms, interval_ms, jitter_ms, handoff_ms, tick;
    char                  config16[17];
    uint8_t               no_thread, late_build, client_ip_from_header, single_process_stale;
    uint32_t              shards;
    uint64_t              retired, failure_evicted, log_dropped, majflt_delta;
    uint64_t              retire_lost;   /* a displaced map with no slot: 0, by the retire precondition */
    uint32_t              measured;      /* WE_MOD_MEASURED_MAJFLT when majflt_delta was measured */
    uint64_t              ticks_before_start;   /* ticks refused because the worker start had not run */
    uint64_t              verify_held;   /* the verification buffer's bytes held now: 0 between verifications */
    uint64_t              verify_peak;   /* and at most, this process: one plane's size, never the planes' sum */
    we_mod_plane_status_t plane[8];
    uint32_t              ntransitions;
    uint64_t              transition_ms[WE_MOD_TRANSITIONS];
    char                  transition[WE_MOD_TRANSITIONS][WE_MOD_RING_ENTRY];
} we_mod_status_t;
void we_mod_render_status(we_mod_text_t *t, const we_mod_procid_t *id, const we_mod_status_t *s);

#if defined(WE_MOD_TEST_PAUSE_TICK) || defined(WE_MOD_TEST_PAUSE_BEFORE_RENAME) || defined(WE_MOD_TEST_PAUSE_AFTER_FSTAT)
void we_mod_test_pause(const char *where);   /* the gate's debug hook: held here until released (we_module.c) */
#endif

/* ---- the planes' publication: the stand-in, the two compare-and-swap calls, the retire list ---- */

/* The module's return codes, in the range whisper_edge.h reserves for them (-32 to -63). */
#define WE_MOD_ERR_RACE (-32)    /* the compare-and-swap found another map current: nothing changed */
#define WE_MOD_ERR_SPEC (-33)    /* the context spec omits a context whose lines a listed context runs */
#define WE_MOD_ERR_ABI  (-34)    /* the module was compiled against another we_module.h ABI */
#define WE_MOD_ERR_ARG  (-35)    /* a caller's error: a NULL handle or map, a misaligned map, no binding */
#define WE_MOD_ERR_CONFIG (-36)  /* an operator's: the data directory or snapshot path the configuration names */
#define WE_MOD_ERR_CAP  (-37)    /* the configuration counts more rule slots than one may hold */
#define WE_MOD_ERR_THREAD (-38)  /* the module's thread could not be started (pipe, pin or create) */
/* out of memory is the core's WE_ERR_MMAP ("cannot allocate") everywhere in this file */
WE_STATIC_ASSERT(WE_MOD_ERR_THREAD >= WE_ERR_MODULE_LAST && WE_MOD_ERR_RACE <= WE_ERR_MODULE_FIRST,
                 "the module's codes stay inside the reserved range");
/* the text of a WE_ERR_* or a WE_MOD_ERR_* code, for the one log line a refusal writes */
const char *we_mod_strerror(int rc);

/* A plane's stand-in: header-only, generation 1, valid_until_ms 1, both families empty; never retired. */
we_map_t *we_mod_standin_new(uint32_t plane_id);
/*
 * Publish a module-owned map: the rollback and high-water rules, then one release compare-and-swap from
 * `expected`; the displaced map comes back to the module (*displaced), never to the core's retire ring.
 * WE_MOD_ERR_ARG for a NULL handle or map or a map not 64-byte aligned, WE_ERR_FORMAT for generation 0,
 * WE_ERR_ROLLBACK, WE_MOD_ERR_RACE.
 */
int we_handle_publish_mapped(we_handle_t *h, const we_map_t *expected, we_map_t *m, const we_map_t **displaced);
/*
 * One release compare-and-swap, no generation check: disarm, re-arm, the tenant's revoked map.
 * WE_MOD_ERR_ARG for a NULL handle or map or a map not 64-byte aligned, WE_MOD_ERR_RACE.
 */
int we_handle_set_view(we_handle_t *h, const we_map_t *expected, we_map_t *m);

#define WE_MOD_RETIRE_SLOTS 4u
typedef struct {
    struct {
        we_map_t *map;
        void    (*release)(we_map_t *m, void *ud);   /* munlock, munmap, close: the thread's alone */
        void     *ud;
        uint64_t  at_ms;                              /* CLOCK_MONOTONIC */
    } slot[WE_MOD_RETIRE_SLOTS];
} we_mod_retire_t;
/* `m` as we_handle_publish_mapped() handed it back (const): the list owns it from here, and frees it */
int      we_mod_retire_push(we_mod_retire_t *r, const we_map_t *m, void (*release)(we_map_t *m, void *ud), void *ud,
                            uint64_t mono_ms);
uint32_t we_mod_retire_sweep(we_mod_retire_t *r, uint64_t mono_ms, uint64_t grace_ms);
uint64_t we_mod_monotonic_ms(void);

/* ---- the two single-producer, single-consumer lists: a pointer slot holding an intrusive list ---- */

typedef struct we_mod_item {
    struct we_mod_item *next;
} we_mod_item_t;
void           we_mod_list_post(we_mod_item_t **slot, we_mod_item_t *it);
we_mod_item_t *we_mod_list_take(we_mod_item_t **slot);

/* ---- the module's thread ---- */

typedef struct we_mod_thread we_mod_thread_t;
/* a tick, or the final write; `stop` is read with __atomic_load_n, and a long job checks it per 1 MiB */
typedef void (*we_mod_tick_fn)(void *ud, uint64_t tick, const int *stop);
/*
 * Start the thread: the module's object pinned first, close-on-exec pipes, every asynchronous signal blocked
 * around a DETACHED create, nice 10 inside. `on_tick` runs at once (the first status write, before the first
 * sleep), then every interval after `offset_ms`, on CLOCK_MONOTONIC. 0, or with `why` and no thread: WE_ERR_MMAP
 * (out of memory) or WE_MOD_ERR_THREAD (the pin, the pipes or the create refused).
 */
int      we_mod_thread_start(we_mod_thread_t **out, uint64_t interval_ms, uint64_t offset_ms, we_mod_tick_fn on_tick,
                             we_mod_tick_fn on_final, void *ud, char *why, size_t whyn);
/*
 * The stop, async-signal-safe: an atomic store, a write(2), a poll(2) on the done pipe against a deadline on
 * CLOCK_MONOTONIC across EINTR. 0 the thread finished, 1 abandoned at the deadline.
 */
int      we_mod_thread_stop(we_mod_thread_t *t, uint64_t deadline_ms);
uint64_t we_mod_thread_ticks(const we_mod_thread_t *t);
/*
 * What the module's thread is doing, which the bounded stop reads: between ticks, a tick's plane jobs
 * (verification reads of plane files, marked by we_mod_planes_tick() itself), the rest of a tick (the
 * module's own work and files), or the final write after the stop. The thread loop sets each; a module
 * may mark its own work with we_mod_thread_stage() from inside on_tick or on_final, which is a no-op on
 * any other thread. Every mark, and every 1 MiB a verification reads, is progress.
 */
#define WE_MOD_STAGE_WAIT   0u
#define WE_MOD_STAGE_PLANES 1u
#define WE_MOD_STAGE_TICK   2u
#define WE_MOD_STAGE_FINAL  3u
void        we_mod_thread_stage(uint32_t stage);
/*
 * THE STOP EVERY SERVER CALLS: we_mod_thread_stop() in windows of WE_MOD_STOP_WINDOW_MS, to
 * WE_MOD_STOP_CAP_MS in all. A window that ends with the thread's progress moved, or with the thread
 * outside a plane job (waiting, its own files, its final write), is granted again, so a thread slow to
 * stop on a loaded host still writes the counts its process served; a plane job with no progress for a
 * window (a read stuck in the kernel, the stall the bound exists for) is abandoned. Async-signal-safe
 * (atomic loads, write, poll, clock_gettime). 0 the thread finished; 1 abandoned, with the stage it was
 * in at *stage (NULL allowed), whose words we_mod_stage_text() gives for the abandonment line.
 */
#define WE_MOD_STOP_WINDOW_MS 2000u
#define WE_MOD_STOP_CAP_MS    6000u
int         we_mod_thread_stop_bounded(we_mod_thread_t *t, uint32_t *stage);
/* " (the thread was in: <stage>)": a constant, safe to write(2) from a signal handler */
const char *we_mod_stage_text(uint32_t stage);

/* A free-text field as every file and log line writes it: quoted, `\\`, `\"` and \xHH escaped. */
size_t we_mod_escape(const char *s, char *out, size_t n);

/*
 * The name of a network or FUSE file system by its statfs magic (NFS, SMB, CIFS, SMB2, FUSE, Ceph, 9P,
 * AFS), NULL for a local one: what we_mod_plane_trust() refuses a plane on.
 */
const char *we_mod_netfs_name(long f_type);

/* ==================================================================================================
 * THE PLANES, bound and kept (the mapped planes of the publication rule, POLICY.md §2.4 and §3.5). One implementation for every
 * server: a module calls these and writes none of it.
 *
 *   supervisor, at configuration load    we_mod_bind()          every bound plane verified by pread into
 *                                                               a transient buffer, then mapped and
 *                                                               published, before any worker exists
 *   worker, before its first accept      we_mod_worker_start()  section 3.3's worker-start check, mlock
 *   the module's thread, every tick      we_mod_planes_tick()   a we_mod_tick_fn: the stats, the jobs
 *                                                               (verify, map, arm, re-digest), the results
 *                                                               posted to the loop, the retire sweep
 *   the planes' single writer            we_mod_planes_apply()  the loop (nginx, LiteSpeed) or the
 *                                                               refresher (Apache): every posted result's
 *                                                               compare-and-swap, its log line handed to
 *                                                               the server's logger
 *
 * A plane has at most one result in flight; the loop answers each on the same item, which goes back to
 * the thread with the map it displaced, and the thread alone unmaps (after the core's 30 s grace).
 * ================================================================================================ */

#define WE_MOD_FAIL_MEMORY 8u    /* failures remembered per plane, the oldest evicted first */
#define WE_MOD_RING_LINES 32u    /* log lines the thread hands the loop per tick; more are counted, dropped */

typedef struct we_mod_planes we_mod_planes_t;
typedef void (*we_mod_log_fn)(void *ud, const char *entry);   /* one entry, NUL-terminated, at most 511 bytes */
typedef void (*we_mod_wake_fn)(void *ud);                     /* the thread posted: wake the loop (nginx's eventfd) */

typedef struct {
    uint32_t      abi;              /* WE_MODULE_ABI_VERSION as the module compiled this header */
    const char   *data_dir;         /* whisper_edge_data, or NULL */
    const char   *legacy_file;      /* the legacy single-file directive (the reputation plane), or NULL */
    uint8_t       read_mask;        /* the planes some program reads: bit p - 1; the tenant plane (bit 7) is bound
                                     * whenever present, whatever this says, because the tenant step reads it */
    unsigned      uid;              /* the workers' uid: the owner the trust checks accept besides root */
    const char   *high_water_file;  /* the tenant high-water file; NULL for WE_MOD_HIGH_WATER_DEFAULT */
    uint64_t      now_ms;           /* epoch milliseconds; 0 reads the clock */
    we_mod_log_fn log;              /* the configuration's logger, called during the binding */
    void         *log_ud;
    /*
     * ABI 5: `whisper_edge_data <plane> <absolute file>`, http level only: plane p bound to that file,
     * overriding data_dir for it, its directory trust-walked as data_dir is (no sticky exception), and
     * bound by the line itself whatever read_mask says. NULL for a plane the directory (or nothing) binds.
     * legacy_file beside any other data directive is the reputation plane's file, never legacy: the
     * legacy flag is the snapshot's only when it is the configuration's only data directive.
     */
    const char   *plane_file[8];
} we_mod_bind_args_t;
#define WE_MOD_BIND_ARGS_INIT { WE_MODULE_ABI_VERSION, NULL, NULL, 0u, 0u, NULL, 0u, NULL, NULL, \
                                { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } }

/*
 * Bind the configuration's planes into cfg: its handles (module-owned: a core publish on one refuses with
 * WE_ERR_OWNERSHIP), stand-ins, bound mask, static and null reasons. An absent plane is inert; a present
 * one that fails is bound and REFUSED, never a configuration error. A plane whose file is named in a way
 * the path or trust rule refuses (a relative path, a directory the trust walk refuses, the data directory
 * itself for every plane it holds) is refused AT CONFIGURATION: nothing opened, no handle, `-r` from its
 * static reason, the reason with the fix on its status line, its configuration-file plane line
 * (we_mod_plane_config_refusal) and one log line (we_mod_refused_sentence), while every other plane binds
 * and serves. 0, or with msg: WE_MOD_ERR_ABI (an ABI mismatch), WE_MOD_ERR_CONFIG (the one configuration
 * error refused whole: the snapshot and a reputation line both naming the reputation plane's file),
 * WE_ERR_MMAP (out of memory) or WE_MOD_ERR_ARG (cfg, args or out NULL). A refused binding leaves cfg as it
 * was before the call. Run once per configuration, before fork. Every string in args is
 * copied: none needs to outlive the call. msg is never NULL; msgn may be 0.
 *
 * THE ORDER, a precondition every call holds and none of them races: we_mod_bind() (the supervisor, once),
 * then in each serving process we_mod_worker_start() BEFORE the thread is started, then the thread's
 * we_mod_planes_tick() and the writer's we_mod_planes_apply(). A worker start after the first tick is
 * refused (WE_MOD_ERR_ARG, "the thread already ticks"); a tick before the worker start does nothing and
 * is counted (`ticks-before-start` on the process line); a NULL planes pointer to any call is refused or
 * ignored, never dereferenced. Anything else (two threads ticking one binding, an apply on a thread that
 * is not the planes' writer) is undefined, and the rows do not exercise it.
 */
int we_mod_bind(we_mod_cfg_t *cfg, const we_mod_bind_args_t *args, we_mod_planes_t **out, char *msg, size_t msgn);
/*
 * The file plane p is bound to, as the configuration named it (a per-plane file, the snapshot, or
 * <data_dir>/<plane>.bin), for the configuration file's `plane <p> path` line; NULL when nothing names
 * one. Whether the plane is bound is the handle's business, not this string's.
 */
const char *we_mod_plane_path(const we_mod_planes_t *pl, uint32_t p);
#ifdef WE_MOD_DEBUG
int we_mod_debug_remember_other(we_mod_planes_t *pl, uint32_t p);   /* the identity-collision row's seam */
#endif
/*
 * The same path, composed from the bind arguments alone, at configuration time and before any bind: the
 * composition we_mod_bind() itself uses, so a server's configuration test and the bound planes can never
 * name a plane's file two ways. plane_file[p] as given; for the reputation plane the snapshot when no
 * reputation line names a file; else the data directory with its trailing slashes stripped ("/" kept)
 * and the plane's file name. 1 with the path in buf, 0 when nothing names a file for the plane, -1 when
 * buf is too short.
 */
int we_mod_bind_plane_path(const we_mod_bind_args_t *a, uint32_t p, char *buf, size_t len);

/*
 * The reason, with its fix, of plane p refused at configuration by we_mod_bind() (see there), for the
 * configuration file's `plane <p> path "<path>" refused "<reason>"` line; NULL for every other plane, a
 * file refused on its bytes included (that one can change on a tick, so it is the status file's).
 */
const char *we_mod_plane_config_refusal(const we_mod_planes_t *pl, uint32_t p);
/*
 * The one error-log sentence for a plane refused at configuration, the same words on every server:
 * we_mod_bind() hands it to the bind's logger once per refused plane, and a configuration test prints it
 * for a we_mod_bind_check() result with config_refused set. 0, or -1 when buf is too short (truncated).
 */
int we_mod_refused_sentence(char *buf, size_t len, uint32_t p, const char *reason);
/*
 * The legacy snapshot's owner WARNING, the same words on every server: the snapshot named as the one data
 * directive keeps its 0644 mode, and an owner other than root or the workers' uid can rewrite it, so the
 * bind writes this sentence to its logger once, and a configuration test prints it. Its directory chain
 * is not a warning: the bind's trust walk already refuses the plane on an untrusted directory. 1 with the
 * sentence in buf (naming the owner and the chown fix), 0 when none applies.
 */
int we_mod_legacy_warning(const we_mod_bind_args_t *a, char *buf, size_t len);

/* One plane's result from we_mod_bind_check(). */
typedef struct {
    char    path[4096];          /* the file the configuration names for the plane, "" for none (Linux PATH_MAX) */
    char    state[16];           /* absent (or read by nothing), unreadable, refused, verified */
    char    reason[256];         /* refused's reason with the fix, unreadable's errno text */
    uint8_t code;                /* the token the bind would give it before any tick: WE_MOD_NOMAP_NONE
                                  * (verified: it would arm), _ABSENT, _UNREADABLE or _REFUSED */
    uint8_t config_refused;      /* refused at configuration (we_mod_plane_config_refusal would name it) */
} we_mod_plane_check_t;
/*
 * The check-only bind, for a configuration test (Apache's configtest, nginx -t): every check
 * we_mod_bind() makes (the ABI, the path rules, every trust walk, the conflict, each plane refused at
 * configuration, and each plane's file verified as the bind's load verifies it, its bytes digested into a
 * private buffer), in the same pass, with nothing mapped, armed, bound or logged. The return is
 * we_mod_bind()'s for the same arguments; on 0, out[p] is each plane's result.
 */
int we_mod_bind_check(const we_mod_bind_args_t *args, we_mod_plane_check_t out[8], char *msg, size_t msgn);

/*
 * The counters directory a configuration with no counters directive writes into: `counters` beside the
 * data it names (the README's rule: inside the data directory, or beside the snapshot), and with only
 * per-plane files, beside them when they share one directory. 1 with the directory in buf; 0 when the
 * configuration names no data at all; -1 with `why` when its files are in different directories, so no
 * one place is beside them and the operator must name one with the counters directive, and -1 too when
 * the directory would be /counters (a data directory of /, or a file at the filesystem root), since a
 * module never creates a directory at /; counting is then off and blocking unaffected; -2 when buf is
 * too short.
 */
int we_mod_bind_counters_dir(const we_mod_bind_args_t *a, char *buf, size_t len, char *why, size_t whyn);

typedef struct {
    uint64_t       now_ms;          /* epoch milliseconds; 0 reads the clock */
    uint64_t       interval_ms;     /* the thread's tick, for the EIO backoff's ceiling and the status line */
    we_mod_wake_fn wake;            /* NULL where the writer polls (LiteSpeed: we_mod_planes_pending()) */
    void          *wake_ud;
    we_mod_log_fn  log;             /* the worker's logger, for the start check's lines */
    void          *log_ud;
} we_mod_worker_args_t;
/* The worker-start check of section 3.3 and the arm-time mlock, on the loop before its first accept. */
int we_mod_worker_start(we_mod_planes_t *pl, const we_mod_worker_args_t *w, char *msg, size_t msgn);
/* The thread's tick (a we_mod_tick_fn with the planes as its user data). */
void we_mod_planes_tick(void *planes, uint64_t tick, const int *stop);
/*
 * The single writer's apply: the number of results applied; each one's log line handed to `log`. Then the
 * TRANSITIONS (POLICY.md §2.5): each bound plane's state is read off its handle (armed, stale by the clock,
 * disarmed, refused or loading; the tenant plane's fresh, grace, lapsed, null or revoked); the first call
 * takes the baseline, and on a change every later call writes, per plane that changed, one entry per
 * distinct program of the configuration with a plane-dependent rule (`plane <P> <kind> out=<planes or ->
 * tenant=<state>: <we_program_dependents_line text>`, the first 511 bytes), or one summary entry when
 * more than WE_MOD_TRANSITIONS programs are affected. Each entry goes into the status ring (the newest
 * WE_MOD_TRANSITIONS kept) and to `log`, byte for byte the same; an entry identical to one already written
 * for the same plane's change (two programs with the same dependents) is written once.
 */
uint32_t we_mod_planes_apply(we_mod_planes_t *pl, we_mod_log_fn log, void *ud);
/* One relaxed load: a result waits (LiteSpeed's 100 ms timer reads this, then applies). */
int  we_mod_planes_pending(const we_mod_planes_t *pl);
/* The planes' lines of the status file, and the process line's counters; read on the thread. */
void we_mod_planes_status(const we_mod_planes_t *pl, we_mod_status_t *s, uint64_t now_ms);
/* Everything the binding holds, released: the supervisor's, when its cycle is released. */
void we_mod_planes_release(we_mod_planes_t *pl);

/*
 * THE SUPERVISOR'S BUDGETED VERIFICATION (Apache's ap_hook_monitor): verify and
 * arm, in the supervisor, a new generation at a bound name, spending at most `budget_ms` per call and
 * resuming on the next call at the 1 MiB chunk it stopped at; the transient buffer is an anonymous mapping
 * marked MADV_DONTFORK, so a child forked between calls inherits none of it. The armed inode's own drift
 * (a chmod, an in-place rewrite) is watched the same way: trust-checked at once, re-digested budgeted,
 * and a confirming digest refreshes the supervisor's own I, so children forked after it inherit the
 * refreshed identity and pay no start-path digest. The budget is checked before every chunk, so a zero
 * budget reads nothing and never arms. Bind-time rules hold inside a call: results apply at once, lines
 * go to the supervisor's logger, and the arm-time mlock stays each serving process's worker-start job.
 * A serving process is refused with WE_MOD_ERR_ARG (its worker started, or its thread ticked), and so
 * are a NULL binding and a NULL mask. Returns 1 when this call armed something (the planes in
 * *armed_mask), 0 when nothing is due or the work continues next call, or a WE_ERR_* or WE_MOD_ERR_*
 * code. we_mod_planes_monitor_release() drops a verification in progress and its buffer: the pconf
 * cleanup a graceful restart runs. we_mod_planes_monitor_counts() reads the monitor's own counters
 * (calls taken, the bytes the last call read, the bytes read in all calls, and the verifications
 * completed), which the debug build's prefork row reads; each out-pointer may be NULL.
 */
int  we_mod_planes_monitor(we_mod_planes_t *pl, uint64_t budget_ms, uint32_t *armed_mask);
void we_mod_planes_monitor_release(we_mod_planes_t *pl);
void we_mod_planes_monitor_counts(const we_mod_planes_t *pl, uint64_t *calls, uint64_t *bytes_last_call,
                                  uint64_t *bytes_total, uint64_t *verifications);

/* ---- ABI-LAYOUT: generated by gen-abi-layout.py from the compiler's own measurement; do not edit ---- */
/* not in a WE_TRACE build: the trace build is a test build whose scratch carries the trace's own
 * fields; it never ships, and the release layout is the one a module is built against */
#if !defined(WE_MOD_ABI_LAYOUT_MEASURING) && !defined(WE_TRACE)
#define WE_MOD_ABI_LAYOUT_MAJOR 5u
WE_STATIC_ASSERT(WE_MODULE_ABI_VERSION == WE_MOD_ABI_LAYOUT_MAJOR, "the layout below was measured under another major: regenerate it with gen-abi-layout.py --write");
WE_STATIC_ASSERT(sizeof(void *) == 8u, "the module ABI is LP64");
WE_STATIC_ASSERT(sizeof(we_mod_ctx_cold_t) == 56u && _Alignof(we_mod_ctx_cold_t) == 8u, "we_mod_ctx_cold_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, name) == 0u, "we_mod_ctx_cold_t.name: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, path) == 8u, "we_mod_ctx_cold_t.path: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, program_ctx) == 16u, "we_mod_ctx_cold_t.program_ctx: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, program_floor) == 24u, "we_mod_ctx_cold_t.program_floor: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, rule_id) == 32u, "we_mod_ctx_cold_t.rule_id: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, rule_text) == 40u, "we_mod_ctx_cold_t.rule_text: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, rule_count) == 48u, "we_mod_ctx_cold_t.rule_count: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_cold_t, own) == 52u, "we_mod_ctx_cold_t.own: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_cfg_cold_t) == 96u && _Alignof(we_mod_cfg_cold_t) == 8u, "we_mod_cfg_cold_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_cold_t, program_none) == 0u, "we_mod_cfg_cold_t.program_none: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_cold_t, rule_id) == 8u, "we_mod_cfg_cold_t.rule_id: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_cold_t, rule_text) == 16u, "we_mod_cfg_cold_t.rule_text: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_cold_t, rule_count) == 24u, "we_mod_cfg_cold_t.rule_count: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_cold_t, plane_name) == 32u, "we_mod_cfg_cold_t.plane_name: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_cfg_t) == 192u && _Alignof(we_mod_cfg_t) == 8u, "we_mod_cfg_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, floor) == 0u, "we_mod_cfg_t.floor: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, floor_conf) == 8u, "we_mod_cfg_t.floor_conf: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, floor_status) == 10u, "we_mod_cfg_t.floor_status: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, hh) == 16u, "we_mod_cfg_t.hh: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, handle) == 24u, "we_mod_cfg_t.handle: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, bound_mask) == 88u, "we_mod_cfg_t.bound_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, static_reason) == 89u, "we_mod_cfg_t.static_reason: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, standin) == 104u, "we_mod_cfg_t.standin: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, null_reason) == 168u, "we_mod_cfg_t.null_reason: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, cold) == 176u, "we_mod_cfg_t.cold: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_cfg_t, arena) == 184u, "we_mod_cfg_t.arena: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_ctx_t) == 32u && _Alignof(we_mod_ctx_t) == 8u, "we_mod_ctx_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, prog) == 0u, "we_mod_ctx_t.prog: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, conf) == 8u, "we_mod_ctx_t.conf: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, deny_status) == 10u, "we_mod_ctx_t.deny_status: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, ctr_off) == 12u, "we_mod_ctx_t.ctr_off: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, rule_count) == 16u, "we_mod_ctx_t.rule_count: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, export_mask) == 18u, "we_mod_ctx_t.export_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, gen_mask) == 19u, "we_mod_ctx_t.gen_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_t, cold) == 24u, "we_mod_ctx_t.cold: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_req_t) == 64u && _Alignof(we_mod_req_t) == 1u, "we_mod_req_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_req_t, r) == 0u, "we_mod_req_t.r: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_req_t, note) == 56u, "we_mod_req_t.note: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_req_t, pad) == 57u, "we_mod_req_t.pad: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_scratch_t) == 1024u && _Alignof(we_mod_scratch_t) == 64u, "we_mod_scratch_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_scratch_t, e) == 0u, "we_mod_scratch_t.e: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_scratch_t, v) == 704u, "we_mod_scratch_t.v: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_scratch_t, park) == 976u, "we_mod_scratch_t.park: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_iv4_t) == 8u && _Alignof(we_mod_iv4_t) == 4u, "we_mod_iv4_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv4_t, lo) == 0u, "we_mod_iv4_t.lo: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv4_t, hi) == 4u, "we_mod_iv4_t.hi: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_iv6_t) == 32u && _Alignof(we_mod_iv6_t) == 8u, "we_mod_iv6_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv6_t, lo_hi) == 0u, "we_mod_iv6_t.lo_hi: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv6_t, lo_lo) == 8u, "we_mod_iv6_t.lo_lo: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv6_t, hi_hi) == 16u, "we_mod_iv6_t.hi_hi: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_iv6_t, hi_lo) == 24u, "we_mod_iv6_t.hi_lo: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_trust_t) == 32u && _Alignof(we_mod_trust_t) == 8u, "we_mod_trust_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, v4) == 0u, "we_mod_trust_t.v4: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, v6) == 8u, "we_mod_trust_t.v6: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, n4) == 16u, "we_mod_trust_t.n4: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, n6) == 20u, "we_mod_trust_t.n6: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, unix_ok) == 24u, "we_mod_trust_t.unix_ok: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_t, pad) == 25u, "we_mod_trust_t.pad: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_line_t) == 16u && _Alignof(we_mod_line_t) == 8u, "we_mod_line_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_line_t, p) == 0u, "we_mod_line_t.p: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_line_t, len) == 8u, "we_mod_line_t.len: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_walk_t) == 52u && _Alignof(we_mod_walk_t) == 4u, "we_mod_walk_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, floor) == 0u, "we_mod_walk_t.floor: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, walk) == 24u, "we_mod_walk_t.walk: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, eligible) == 25u, "we_mod_walk_t.eligible: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, note) == 26u, "we_mod_walk_t.note: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, pad) == 27u, "we_mod_walk_t.pad: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, line) == 28u, "we_mod_walk_t.line: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, off) == 32u, "we_mod_walk_t.off: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, len) == 36u, "we_mod_walk_t.len: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, entries) == 40u, "we_mod_walk_t.entries: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, bytes) == 44u, "we_mod_walk_t.bytes: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_walk_t, searches) == 48u, "we_mod_walk_t.searches: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_attr_t) == 16u && _Alignof(we_mod_attr_t) == 8u, "we_mod_attr_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, name) == 0u, "we_mod_attr_t.name: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, plane) == 8u, "we_mod_attr_t.plane: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, cls) == 9u, "we_mod_attr_t.cls: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, off) == 10u, "we_mod_attr_t.off: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, mask) == 11u, "we_mod_attr_t.mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_attr_t, dom) == 12u, "we_mod_attr_t.dom: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_record_t) == 576u && _Alignof(we_mod_record_t) == 64u, "we_mod_record_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, step) == 0u, "we_mod_record_t.step: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, action) == 1u, "we_mod_record_t.action: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, program) == 2u, "we_mod_record_t.program: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, reason) == 3u, "we_mod_record_t.reason: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, unknown_plane) == 4u, "we_mod_record_t.unknown_plane: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, marks) == 5u, "we_mod_record_t.marks: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, enforce) == 6u, "we_mod_record_t.enforce: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad0) == 7u, "we_mod_record_t.pad0: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, rule) == 8u, "we_mod_record_t.rule: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad1) == 10u, "we_mod_record_t.pad1: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, log_fired) == 16u, "we_mod_record_t.log_fired: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, floor) == 80u, "we_mod_record_t.floor: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, per_dir_config) == 104u, "we_mod_record_t.per_dir_config: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, uri) == 112u, "we_mod_record_t.uri: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad2) == 120u, "we_mod_record_t.pad2: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, slot) == 128u, "we_mod_record_t.slot: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, ctx) == 448u, "we_mod_record_t.ctx: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, generation) == 456u, "we_mod_record_t.generation: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, lazy_mask) == 464u, "we_mod_record_t.lazy_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, disarmed_mask) == 465u, "we_mod_record_t.disarmed_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, severity) == 466u, "we_mod_record_t.severity: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, decided) == 467u, "we_mod_record_t.decided: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, raw_rep) == 468u, "we_mod_record_t.raw_rep: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, flags) == 469u, "we_mod_record_t.flags: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_action) == 470u, "we_mod_record_t.eval_action: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_mode) == 471u, "we_mod_record_t.eval_mode: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, eval_status) == 472u, "we_mod_record_t.eval_status: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad3) == 474u, "we_mod_record_t.pad3: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, chain) == 480u, "we_mod_record_t.chain: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, asn) == 488u, "we_mod_record_t.asn: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad4) == 499u, "we_mod_record_t.pad4: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, digest4) == 512u, "we_mod_record_t.digest4: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, nomap) == 544u, "we_mod_record_t.nomap: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, gen_mask) == 547u, "we_mod_record_t.gen_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_record_t, pad5) == 548u, "we_mod_record_t.pad5: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_trust_report_t) == 16u && _Alignof(we_mod_trust_report_t) == 4u, "we_mod_trust_report_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_report_t, configured4) == 0u, "we_mod_trust_report_t.configured4: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_report_t, configured6) == 4u, "we_mod_trust_report_t.configured6: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_report_t, broad) == 8u, "we_mod_trust_report_t.broad: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_trust_report_t, covers_mapped) == 12u, "we_mod_trust_report_t.covers_mapped: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_ctx_spec_t) == 24u && _Alignof(we_mod_ctx_spec_t) == 8u, "we_mod_ctx_spec_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_spec_t, path) == 0u, "we_mod_ctx_spec_t.path: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_spec_t, name) == 8u, "we_mod_ctx_spec_t.name: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_spec_t, deny_status) == 16u, "we_mod_ctx_spec_t.deny_status: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_spec_t, export_mask) == 18u, "we_mod_ctx_spec_t.export_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctx_spec_t, gen_mask) == 19u, "we_mod_ctx_spec_t.gen_mask: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_peek_t) == 88u && _Alignof(we_mod_peek_t) == 8u, "we_mod_peek_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, generation) == 0u, "we_mod_peek_t.generation: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, built_at_ms) == 8u, "we_mod_peek_t.built_at_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, valid_until_ms) == 16u, "we_mod_peek_t.valid_until_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, size) == 24u, "we_mod_peek_t.size: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, digest) == 32u, "we_mod_peek_t.digest: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, format) == 64u, "we_mod_peek_t.format: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, uid) == 68u, "we_mod_peek_t.uid: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, mode) == 72u, "we_mod_peek_t.mode: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, err) == 76u, "we_mod_peek_t.err: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, country_table_version) == 80u, "we_mod_peek_t.country_table_version: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, plane_id) == 82u, "we_mod_peek_t.plane_id: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, schema) == 83u, "we_mod_peek_t.schema: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_peek_t, absent) == 84u, "we_mod_peek_t.absent: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_text_t) == 32u && _Alignof(we_mod_text_t) == 8u, "we_mod_text_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_text_t, buf) == 0u, "we_mod_text_t.buf: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_text_t, len) == 8u, "we_mod_text_t.len: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_text_t, cap) == 16u, "we_mod_text_t.cap: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_text_t, over) == 24u, "we_mod_text_t.over: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_ctrmap_entry_t) == 28u && _Alignof(we_mod_ctrmap_entry_t) == 4u, "we_mod_ctrmap_entry_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctrmap_entry_t, ctr_off) == 0u, "we_mod_ctrmap_entry_t.ctr_off: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctrmap_entry_t, rule_count) == 4u, "we_mod_ctrmap_entry_t.rule_count: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctrmap_entry_t, digest16) == 8u, "we_mod_ctrmap_entry_t.digest16: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_ctrmap_t) == 16u && _Alignof(we_mod_ctrmap_t) == 8u, "we_mod_ctrmap_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctrmap_t, e) == 0u, "we_mod_ctrmap_t.e: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_ctrmap_t, n) == 8u, "we_mod_ctrmap_t.n: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_plane_status_t) == 408u && _Alignof(we_mod_plane_status_t) == 8u, "we_mod_plane_status_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, bound) == 0u, "we_mod_plane_status_t.bound: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, pending) == 1u, "we_mod_plane_status_t.pending: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, mapped) == 2u, "we_mod_plane_status_t.mapped: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, locked) == 3u, "we_mod_plane_status_t.locked: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, immutable) == 4u, "we_mod_plane_status_t.immutable: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, dir_replaced) == 5u, "we_mod_plane_status_t.dir_replaced: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, state) == 6u, "we_mod_plane_status_t.state: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, reason) == 22u, "we_mod_plane_status_t.reason: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, generation) == 280u, "we_mod_plane_status_t.generation: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, posted) == 288u, "we_mod_plane_status_t.posted: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, pending_ticks) == 296u, "we_mod_plane_status_t.pending_ticks: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, valid_until_ms) == 304u, "we_mod_plane_status_t.valid_until_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, since_ms) == 312u, "we_mod_plane_status_t.since_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, ticks) == 320u, "we_mod_plane_status_t.ticks: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, bytes) == 328u, "we_mod_plane_status_t.bytes: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, nonresident) == 336u, "we_mod_plane_status_t.nonresident: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, eio_backoff_ms) == 344u, "we_mod_plane_status_t.eio_backoff_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, deferred) == 352u, "we_mod_plane_status_t.deferred: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, measured) == 360u, "we_mod_plane_status_t.measured: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, remaining_ms) == 368u, "we_mod_plane_status_t.remaining_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, slot_age_ms) == 376u, "we_mod_plane_status_t.slot_age_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, country_table) == 384u, "we_mod_plane_status_t.country_table: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_status_t, digest16) == 386u, "we_mod_plane_status_t.digest16: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_status_t) == 11752u && _Alignof(we_mod_status_t) == 8u, "we_mod_status_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, server) == 0u, "we_mod_status_t.server: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, started_ms) == 8u, "we_mod_status_t.started_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, written_ms) == 16u, "we_mod_status_t.written_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, interval_ms) == 24u, "we_mod_status_t.interval_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, jitter_ms) == 32u, "we_mod_status_t.jitter_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, handoff_ms) == 40u, "we_mod_status_t.handoff_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, tick) == 48u, "we_mod_status_t.tick: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, config16) == 56u, "we_mod_status_t.config16: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, no_thread) == 73u, "we_mod_status_t.no_thread: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, late_build) == 74u, "we_mod_status_t.late_build: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, client_ip_from_header) == 75u, "we_mod_status_t.client_ip_from_header: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, single_process_stale) == 76u, "we_mod_status_t.single_process_stale: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, shards) == 80u, "we_mod_status_t.shards: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, retired) == 88u, "we_mod_status_t.retired: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, failure_evicted) == 96u, "we_mod_status_t.failure_evicted: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, log_dropped) == 104u, "we_mod_status_t.log_dropped: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, majflt_delta) == 112u, "we_mod_status_t.majflt_delta: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, retire_lost) == 120u, "we_mod_status_t.retire_lost: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, measured) == 128u, "we_mod_status_t.measured: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, ticks_before_start) == 136u, "we_mod_status_t.ticks_before_start: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, verify_held) == 144u, "we_mod_status_t.verify_held: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, verify_peak) == 152u, "we_mod_status_t.verify_peak: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, plane) == 160u, "we_mod_status_t.plane: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, ntransitions) == 3424u, "we_mod_status_t.ntransitions: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, transition_ms) == 3432u, "we_mod_status_t.transition_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_status_t, transition) == 3560u, "we_mod_status_t.transition: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_retire_t) == 128u && _Alignof(we_mod_retire_t) == 8u, "we_mod_retire_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_retire_t, slot) == 0u, "we_mod_retire_t.slot: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_item_t) == 8u && _Alignof(we_mod_item_t) == 8u, "we_mod_item_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_item_t, next) == 0u, "we_mod_item_t.next: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_bind_args_t) == 128u && _Alignof(we_mod_bind_args_t) == 8u, "we_mod_bind_args_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, abi) == 0u, "we_mod_bind_args_t.abi: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, data_dir) == 8u, "we_mod_bind_args_t.data_dir: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, legacy_file) == 16u, "we_mod_bind_args_t.legacy_file: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, read_mask) == 24u, "we_mod_bind_args_t.read_mask: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, uid) == 28u, "we_mod_bind_args_t.uid: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, high_water_file) == 32u, "we_mod_bind_args_t.high_water_file: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, now_ms) == 40u, "we_mod_bind_args_t.now_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, log) == 48u, "we_mod_bind_args_t.log: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, log_ud) == 56u, "we_mod_bind_args_t.log_ud: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_bind_args_t, plane_file) == 64u, "we_mod_bind_args_t.plane_file: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_plane_check_t) == 4370u && _Alignof(we_mod_plane_check_t) == 1u, "we_mod_plane_check_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_check_t, path) == 0u, "we_mod_plane_check_t.path: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_check_t, state) == 4096u, "we_mod_plane_check_t.state: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_check_t, reason) == 4112u, "we_mod_plane_check_t.reason: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_check_t, code) == 4368u, "we_mod_plane_check_t.code: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_plane_check_t, config_refused) == 4369u, "we_mod_plane_check_t.config_refused: ABI layout");
WE_STATIC_ASSERT(sizeof(we_mod_worker_args_t) == 48u && _Alignof(we_mod_worker_args_t) == 8u, "we_mod_worker_args_t: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, now_ms) == 0u, "we_mod_worker_args_t.now_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, interval_ms) == 8u, "we_mod_worker_args_t.interval_ms: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, wake) == 16u, "we_mod_worker_args_t.wake: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, wake_ud) == 24u, "we_mod_worker_args_t.wake_ud: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, log) == 32u, "we_mod_worker_args_t.log: ABI layout");
WE_STATIC_ASSERT(offsetof(we_mod_worker_args_t, log_ud) == 40u, "we_mod_worker_args_t.log_ud: ABI layout");
#endif
/* ---- ABI-LAYOUT end ---- */

#endif /* WE_MODULE_H */
