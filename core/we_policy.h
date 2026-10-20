/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_policy.h - the edge policy language: the compiled program's layout, the compiler, the verifier.
 *
 * A configuration's `whisper_edge_policy` lines compile, at configuration time, into one contiguous
 * read-only block per distinct program. Nothing in a block is a pointer: every reference is a u32 byte
 * offset from the block's start, so two compiles of one text are byte-identical, a block can be
 * interned on its digest and compared with memcmp, and the verifier can check every offset against
 * the block's own length. The evaluator that runs a block on the request path is header-only, in
 * we_eval.h; everything here is the cold side.
 *
 * The language and every byte below are specified in POLICY.md; the section numbers in comments
 * (section 2.1, D9) are that document's.
 */
#ifndef WE_POLICY_H
#define WE_POLICY_H

#include "whisper_edge.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A 64-byte aligned member, so the type that holds it is aligned wherever it is declared. */
#if defined(__cplusplus)
#define WE_ALIGN64 alignas(64)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define WE_ALIGN64 _Alignas(64)
#else
#define WE_ALIGN64 __attribute__((aligned(64)))
#endif

/*
 * The POLICY.md section 5.4 mutants plant known defects in the compiler, the verifier, the evaluator and
 * the classifier. They exist only in test_policy's traced build, so a stray -D can never ship one in a
 * copied core: every one of the 25 is refused here, in the header both we_policy.c and we_eval.h
 * include. The one exception is the cachegrind driver's two controls: WE_CG_DRIVER, which only that
 * driver defines, admits WE_TEST_NO_MEMO_HIT and WE_TEST_EXTRA_LOAD (exactly one more data reference
 * per rule, the per-rule row's source-level control) and nothing else. policy-mutants.sh holds both
 * halves.
 */
#if !defined(WE_TRACE) && ( \
        defined(WE_TEST_K3_WEAK) || defined(WE_TEST_ALLOW_U_FALLTHROUGH) || defined(WE_TEST_LOG_TERMINATES) \
        || defined(WE_TEST_POLARITY_NO_ALLOW) || defined(WE_TEST_ISNOTUNK_POSITIVE) || defined(WE_TEST_BOOL_NOT) \
        || defined(WE_TEST_SENTINEL_NE) || defined(WE_TEST_SHORTCIRCUIT_U) || defined(WE_TEST_NO_CLAMP) \
        || defined(WE_TEST_NO_SHORTCIRCUIT) || defined(WE_TEST_NO_MEMO_RESET) || defined(WE_TEST_CLASSIFY_ISUNK_U) \
        || defined(WE_TEST_NO_CAPTURES) || defined(WE_TEST_CLASSIFY_SINGLE_EVAL) || defined(WE_TEST_SENTINEL_PADDING) \
        || defined(WE_TEST_TENANT_ATOM_U) || defined(WE_TEST_TENANT_BIT_IGNORED) || defined(WE_TEST_SPLUS_NO_CLAMP) \
        || defined(WE_TEST_NO_EXHAUSTIVE) || defined(WE_TEST_PLANTED_STORE) || defined(WE_TEST_HH_FLOOR_ENDS_ALL) \
        || defined(WE_TEST_HH_SERVER_EXEMPT) || defined(WE_TEST_HH_RAW_COMPARE) || defined(WE_TEST_SERVER_UNSET_KEYED) \
        || (defined(WE_TEST_NO_MEMO_HIT) && !defined(WE_CG_DRIVER)))
#error "the WE_TEST_* mutants exist only in test_policy's WE_TRACE build (and NO_MEMO_HIT in the cachegrind driver)"
#endif
#if defined(WE_TEST_EXTRA_LOAD) && !defined(WE_CG_DRIVER)
#error "WE_TEST_EXTRA_LOAD is the cachegrind driver's control alone"
#endif

/* ---- limits, POLICY.md §2.1 ---- */
#define WE_LIM_ARG        2048u   /* bytes per directive argument */
#define WE_LIM_IDENT        64u   /* bytes per set name */
#define WE_LIM_NEST         16u   /* parentheses and `not` together, on descent */
#define WE_LIM_OPS_RULE     64u
#define WE_LIM_RULES       256u   /* per context */
#define WE_LIM_OPS_CTX    4096u
#define WE_LIM_STACK        18u   /* derived: the evaluation stack at nesting 16 */
#define WE_LIM_INSTRS     8448u   /* 2 * 4,096 + 256: every operation, one jump per link, the NOTs, END */
#define WE_LIM_HOT_BYTES  (256u * 1024u)
#define WE_LIM_SETS       1024u   /* declared sets per configuration */
/*
 * The most distinct members an ASN set can hold: what the argument limit admits under the verifier's
 * strictly-increasing rule. `@s` is 2 bytes; each member costs its digits plus one separator before
 * it: the 10 one-digit values 2 bytes each, the 90 two-digit 3, then three-digit values at 4, which
 * leaves 2,048 - 2 - 20 - 270 = 1,756 bytes, 439 of them. 10 + 90 + 439 = 539. test_policy builds the
 * 2,048-byte argument that reaches it and the one past it.
 */
#define WE_LIM_ASN_MEMBERS 539u

/* ---- the block, POLICY.md §2.1 ---- */
#define WE_PROG_MAGIC    0x31475057u   /* "WPG1" */
#define WE_PROG_VERSION  1u
#define WE_PF_FLOOR      0x0001u       /* compiled as a floor: deny and log only */
#define WE_PF_LEGACY     0x0002u       /* bound through the legacy snapshot synonym: never inert */
#define WE_PF_KNOWN      (WE_PF_FLOOR | WE_PF_LEGACY)

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;          /* WE_PF_*; nothing else, and never a context's mode */
    uint16_t rule_count;
    uint16_t set_count;
    uint16_t instr_count;
    uint16_t op_count;
    uint8_t  plane_mask;     /* bit plane_id - 1: the union of every rule's dep_mask */
    uint8_t  reserved0[3];
    uint32_t hot_len;        /* every byte the request path can read: header .. end of set data */
    uint32_t total_len;      /* hot_len, padding, then the cold canonical text */
    uint32_t rules_off;      /* every offset 64-byte aligned, in this order */
    uint32_t instrs_off;
    uint32_t bindings_off;
    uint32_t sets_off;
    uint32_t hh_off;         /* the hold-harmless arrays: floor blocks only, empty otherwise */
    uint32_t setdata_off;
    uint32_t text_off;       /* cold: the canonical text, outside hot_len */
    uint32_t text_len;
    uint32_t reserved1;
} we_program_t;
WE_STATIC_ASSERT(sizeof(we_program_t) == 64, "the program header is one line");

/* A rule, 16 bytes. The outage class is computed at transition time, never stored (POLICY.md §2.5). */
#define WE_ACT_ALLOW  1u
#define WE_ACT_DENY   2u
#define WE_ACT_LOG    3u
#define WE_RF_INERT   0x01u   /* references a plane absent at config test: skipped, reported */
#define WE_RF_KNOWN   WE_RF_INERT
typedef struct {
    uint8_t  action;
    uint8_t  flags;
    uint8_t  dep_mask;       /* the planes the rule's instructions read, bit plane_id - 1 */
    uint8_t  reserved;
    uint16_t instr_start;
    uint16_t instr_count;
    uint16_t counter;        /* the rule's counter index, below rule_count */
    uint16_t src_len;        /* the rule's canonical line, without its LF */
    uint32_t src_off;        /* from text_off */
} we_rule_t;
WE_STATIC_ASSERT(sizeof(we_rule_t) == 16, "a rule is 16 bytes");

/*
 * An instruction, 8 bytes. `op` is ONE-HOT: one bit per opcode, tested as `op & WE_OP_X` in a chain of
 * ifs, because an equality chain on one variable is what gcc's if-to-switch pass and LLVM's
 * SimplifyCFG fold into a jump table, a .rodata relocation the hot-path gate refuses (POLICY.md §2.2).
 */
#define WE_OP_BOOL          0x0001u   /* off, imm: mask (bits 0..7), the tenant polarity bit (bit 8) */
#define WE_OP_SEV           0x0002u   /* imm: the set of levels that read TRUE, bit L for level L */
#define WE_OP_EQ8           0x0004u   /* off, imm: the value */
#define WE_OP_EQ16          0x0008u   /* off, imm: the normalised country code */
#define WE_OP_EQ32          0x0010u   /* off, imm: the AS number, 0xFFFFFFFF for undetermined */
#define WE_OP_INSET_ENUM    0x0020u   /* off, imm: mask over the domain, bit 0 undetermined */
#define WE_OP_INSET_COUNTRY 0x0040u   /* off, imm: the block offset of a 125-byte bitmap */
#define WE_OP_INSET_ASN     0x0080u   /* off, imm: packed, see WE_ASN_IMM_* */
#define WE_OP_ISUNK         0x0100u
#define WE_OP_NOT           0x0200u
#define WE_OP_AND           0x0400u
#define WE_OP_OR            0x0800u
#define WE_OP_JF            0x1000u   /* imm: the target instruction index */
#define WE_OP_JT            0x2000u
#define WE_OP_END           0x4000u
#define WE_OP_KNOWN         0x7fffu
/* the opcodes that push an atom; every one of them reads a plane */
#define WE_OP_ATOM          (WE_OP_BOOL | WE_OP_SEV | WE_OP_EQ8 | WE_OP_EQ16 | WE_OP_EQ32 \
                             | WE_OP_INSET_ENUM | WE_OP_INSET_COUNTRY | WE_OP_INSET_ASN | WE_OP_ISUNK)
#define WE_BOOL_POLARITY    0x0100u   /* tenant_allow, positive, inside an allow: the bounded reading */

/* INSET_ASN's imm: payload offset (18 bits), level count (3), has_undetermined (1), member count (10) */
#define WE_ASN_IMM_OFF(i)     ((i) & 0x3ffffu)
#define WE_ASN_IMM_LEVELS(i)  (((i) >> 18) & 0x7u)
#define WE_ASN_IMM_HASU(i)    (((i) >> 21) & 0x1u)
#define WE_ASN_IMM_N(i)       (((i) >> 22) & 0x3ffu)
#define WE_ASN_IMM(off, lv, hu, n) \
    ((uint32_t)(off) | ((uint32_t)(lv) << 18) | ((uint32_t)(hu) << 21) | ((uint32_t)(n) << 22))

typedef struct {
    uint16_t op;
    uint8_t  plane;          /* plane_id - 1, 0..7 */
    uint8_t  off;            /* into the normalised attribute block (POLICY.md §2.7) */
    uint32_t imm;
} we_instr_t;
WE_STATIC_ASSERT(sizeof(we_instr_t) == 8, "an instruction is 8 bytes");

/*
 * Per plane, 32 bytes: FORMAT.md §2 and §3 in C, compiled in. The file's tail only confirms it at
 * config test (POLICY.md §2.4).
 */
typedef struct {
    uint8_t  schema_id;      /* WE_SCHEMA_* */
    uint8_t  width;          /* the attribute block: 1 format 1, 10 routing, 6 membership */
    uint8_t  key6;           /* IPv6 key bytes: 8 routing and registry, 16 otherwise */
    uint8_t  inert;          /* absent at config test */
    uint16_t stride4;        /* record strides: 0 format 1 */
    uint16_t stride6;
    uint8_t  off4;           /* the attribute block's offset in the record, per family */
    uint8_t  off6;
    uint8_t  reserved[2];
    uint32_t flag_mask;      /* membership: the plane's attribute bits; routing: the flags byte's */
    uint8_t  tmpl[14];       /* the no-range template, written UNCLAMPED (routing's rov 4 is unrouted) */
    uint8_t  reserved2[2];
} we_binding_t;
WE_STATIC_ASSERT(sizeof(we_binding_t) == 32, "a binding is 32 bytes");

/* A set's descriptor, 16 bytes: cold, the verifier and the reports read it, the request path never. */
#define WE_SET_COUNTRY  1u
#define WE_SET_ASN      2u
typedef struct {
    uint8_t  kind;
    uint8_t  has_undetermined;
    uint8_t  levels;         /* ASN trees: the level count */
    uint8_t  reserved;
    uint32_t count;          /* members, undetermined excluded */
    uint32_t data_off;       /* the payload, 64-byte aligned, inside the set data */
    uint32_t data_len;       /* padded to 64 */
} we_setdesc_t;
WE_STATIC_ASSERT(sizeof(we_setdesc_t) == 16, "a set descriptor is 16 bytes");

/* The hold-harmless arrays' header, at hh_off in a floor block (POLICY.md §3.8). Offsets from the block. */
typedef struct {
    uint32_t v4_n, v6_n;
    uint32_t v4_start_off, v4_end_off, v4_tree_off;
    uint32_t v6_start_off, v6_end_off, v6_tree_off;
    uint32_t v4_m, v6_m;            /* windows */
    uint8_t  v4_span, v6_span;      /* 16 at 32 bits, 4 at 128: one S-tree node's capacity */
    uint8_t  v4_depth, v6_depth;
    uint8_t  reserved[20];
} we_hh_hdr_t;
WE_STATIC_ASSERT(sizeof(we_hh_hdr_t) == 64, "the hold-harmless header is one line");

/* ---- the request path's types; the evaluator itself is in we_eval.h ---- */

/*
 * The context's own mode and allow_inferred, never the block's (POLICY.md §2.1, §3.1). Its domain is
 * the PAIR: mode 1..3 (0 is unset) with allow_inferred 0 or 1. A NULL conf, a zeroed one, and a pair
 * with EITHER field outside its domain all read as the shipped default, dry-run log with
 * allow_inferred off; a half-valid pair is not half honoured.
 */
#define WE_MODE_UNSET 0u
#define WE_MODE_OFF   1u
#define WE_MODE_LOG   2u
#define WE_MODE_DENY  3u
typedef struct {
    uint8_t mode;            /* WE_MODE_* */
    uint8_t allow_inferred;  /* 0 or 1 */
} we_ctx_conf_t;

/* A canonical address: IPv4 in b[0..3] (network order) with the rest zero, or IPv6 in b[0..15]. */
typedef struct {
    uint8_t b[16];
    uint8_t family;          /* 4 or 6 */
    uint8_t pad[7];          /* zero after we_addr_canon(), so memcmp of two canonical addresses is exact */
} we_addr_t;
/* we_addr_canon() writes family and pad as one 8-byte store at offset 16 */
_Static_assert(sizeof(we_addr_t) == 24u && __builtin_offsetof(we_addr_t, family) == 16u, "we_addr_t layout");

#define WE_WALK_OK                    0u
#define WE_WALK_FLOOR_HEADER_MISSING  1u   /* a trusted peer sent no header: judged as the TCP peer */
#define WE_WALK_NO_ADDRESS            2u   /* the client address did not parse: allow, marked */
typedef struct {
    we_addr_t floor;    /* the floor's: the connection and the module's trusted walk */
    we_addr_t server;   /* the server's own realip result: step 4 only */
    uint8_t   hold_harmless_eligible;  /* clear when the judged entry was reached past a skipped hop */
    uint8_t   acme_exempt;   /* the module recognised an ACME HTTP-01 challenge request */
    uint8_t   walk;          /* WE_WALK_* */
    uint8_t   pad[5];
} we_request_t;

/* Memo states (POLICY.md §2.7). The two stale states exist for the tenant plane only. */
#define WE_ST_NONE        0u   /* not looked up */
#define WE_ST_FRESH_HIT   1u
#define WE_ST_FRESH_NR    2u
#define WE_ST_STALE_HIT   3u
#define WE_ST_STALE_NR    4u
#define WE_ST_UNKNOWN     5u   /* NULL (refused or loading), or a stale non-tenant plane */
#define WE_ST_REVOKED     6u

typedef struct {
    uint8_t  block[14];      /* the normalised attribute block, clamped on a hit, the template otherwise */
    uint8_t  lapsed;         /* tenant, stale: now - valid_until_ms > 48 h */
    uint8_t  pad;
    uint64_t generation;     /* the map's that produced this copy */
    uint32_t range;          /* the index, or WE_NO_RANGE */
    uint8_t  family;
    uint8_t  pad2[3];
} we_memo_entry_t;
WE_STATIC_ASSERT(sizeof(we_memo_entry_t) == 32, "a memo entry is 32 bytes");

typedef struct {
    uint8_t  addr[16];       /* the canonical key */
    uint8_t  family;
    uint8_t  flags;
    uint8_t  key_valid;
    uint8_t  pad0[5];
    uint8_t  state[8];       /* WE_ST_*, indexed plane_id - 1; one u64, so a reset is two stores */
    uint8_t  pad1[32];
    we_memo_entry_t e[8];    /* at 64 + 32 * (plane_id - 1) */
} we_memo_slot_t;
WE_STATIC_ASSERT(sizeof(we_memo_slot_t) == 320, "a memo slot is five lines");
WE_STATIC_ASSERT(offsetof(we_memo_slot_t, state) == 24, "the state bytes are one aligned word");
WE_STATIC_ASSERT(offsetof(we_memo_slot_t, e) == 64, "entry p sits at 64 + 32 p");

/*
 * The caller's per-request context: eight plane views and two memo slots, nothing else. The module
 * fills the views for the planes the two programs read, and always the tenant plane, IMMEDIATELY
 * before we_decide() (one we_current() each) and nulls them after; a later lazy fill re-takes
 * we_current() for its plane. A view is the map pointer only: state is published with the pointer
 * (NULL is refused or loading, generation 0 is revoked, staleness is computed per request).
 */
typedef struct {
    const we_map_t *m;
} we_plane_view_t;

typedef struct {
    we_plane_view_t view[8];
    we_memo_slot_t  slot[2];   /* the floor address's, and the server address's when it differs */
} we_eval_ctx_t;

/* The hold-harmless table as a we_map_t view into the floor block, built by we_program_place(). */
typedef struct {
    WE_ALIGN64 we_map_t map;        /* the type is 64-byte aligned, so a view declared anywhere is */
    const we_binding_t *bindings;   /* the floor block's, for the fills the pre-stage makes */
    const we_program_t *floor;      /* the block the view points into */
} we_hh_view_t;

/* What decided, POLICY.md §3.4 */
#define WE_STEP_EXEMPT      1u   /* hold-harmless, ACME, no address */
#define WE_STEP_TENANT      2u
#define WE_STEP_FLOOR       3u
#define WE_STEP_STALE_TENANT 4u  /* POLICY.md's step 3.5 */
#define WE_STEP_CONTEXT     5u   /* POLICY.md's step 4, including its default allow */

#define WE_VPROG_NONE       0u
#define WE_VPROG_FLOOR      1u
#define WE_VPROG_CONTEXT    2u

#define WE_WHY_NONE              0u
#define WE_WHY_ALLOW_BY_UNKNOWN  1u
#define WE_WHY_HOLD_HARMLESS     2u
#define WE_WHY_ACME              3u
#define WE_WHY_TENANT            4u
#define WE_WHY_NO_ADDRESS        5u
#define WE_WHY_RULE              6u   /* a rule's TRUE decided */

#define WE_MARK_FLOOR_HEADER_MISSING 0x01u
#define WE_MARK_TENANT_REVOKED       0x02u

typedef struct {
    uint8_t  step;           /* WE_STEP_* */
    uint8_t  action;         /* WE_ACT_ALLOW or WE_ACT_DENY: the deciding rule's action byte */
    uint8_t  program;        /* WE_VPROG_* */
    uint8_t  reason;         /* WE_WHY_* */
    uint8_t  unknown_plane;  /* allow-by-unknown: the lowest-id UNKNOWN plane the rule referenced */
    uint8_t  marks;          /* WE_MARK_* */
    uint8_t  enforce;        /* 1: a deny under mode deny, to be enforced */
    uint8_t  pad;
    uint16_t rule;           /* 1-based; 0 for the pre-stage and the default allow */
    uint8_t  pad2[6];
    uint8_t  log_fired[2][32];   /* [0] floor, [1] context: bit r - 1 for every log (and downgraded deny) that fired */
    /*
     * The evaluator's scratch, not a result (POLICY.md D9). Where a plane lookup would leave more values
     * live than a toolchain has registers, the evaluator parks them here and reads them back after it,
     * so nothing is ever spilled to the stack; a caller never reads or clears these.
     */
    struct {
        /* the fill's operands across the plane search */
        const we_map_t     *m;
        const we_binding_t *b;
        void               *s;          /* we_memo_slot_t */
        uint32_t            p;
        /* the instruction loop's state across a fill */
        uint32_t            pc;
        const void         *prog;       /* we_program_t */
        const void         *ctx;        /* we_eval_ctx_t */
        void               *slot;       /* we_memo_slot_t */
        const we_binding_t *bind;
        uint64_t            t, f;       /* the K3 stack */
        uint32_t            r, mode, allow_inf, which, si;
        uint32_t            sentinel;   /* the S+ search's one operand that crosses it */
        uint32_t            decided;    /* we_eval_run's result, written where a rule decides */
        uint32_t            pad2;
        /* we_decide's operands across each step */
        uint64_t            now_ms;
        const void         *floor, *floor_conf, *ctx_prog, *ctx_conf, *hh, *req;   /* their own types */
        void               *ectx;       /* we_eval_ctx_t */
        const we_binding_t *dbind;
        void               *ss;         /* we_memo_slot_t: the server address's */
    } sc;
#ifdef WE_TRACE
    uint32_t ops_executed;   /* instructions executed, both programs */
    uint32_t ops_floor;
    uint32_t ops_ctx;
    uint32_t jumps_taken;
    uint32_t set_probes;     /* set payload lines read: one per INSET_COUNTRY, the levels per INSET_ASN */
    uint32_t jumps[2];       /* the same two, by program: [0] the floor, [1] the context */
    uint32_t probes[2];
    uint8_t  lookups[2][8];  /* finds run, by slot (0 the floor address's) and plane_id - 1 */
#endif
} we_verdict_t;

/* ---- the cold side ---- */

/* The caller's allocator: nginx's cycle pool, Apache's pconf, LiteSpeed's malloc. NULL: the C library. */
typedef struct {
    void *(*alloc)(void *ud, size_t size, size_t align);   /* NULL on failure */
    void  (*free)(void *ud, void *p);
    void   *ud;
} we_alloc_t;

/* One directive, as the server hands it to the module after its own quoting. */
#define WE_DIR_POLICY     1u   /* whisper_edge_policy */
#define WE_DIR_SET        2u   /* whisper_edge_set */
#define WE_DIR_FLOOR      3u   /* whisper_edge_policy_floor, http level only */
#define WE_DIR_THRESHOLD  4u   /* whisper_edge_threshold */
#define WE_DIR_MODE       5u   /* whisper_edge_mode */
#define WE_DIR_ALLOW_INFERRED 6u   /* whisper_edge_allow_inferred on|off */
typedef struct {
    uint8_t        kind;
    const char    *context;  /* "http", "http/server:a", "http/server:a/location:b" */
    const uint8_t *arg;
    size_t         len;
} we_policy_directive_t;

/*
 * A configuration, every directive in file order, and the program of it a we_policy_compile() call
 * returns: the floor when `floor` is set, else the program `context` runs. we_policy_build() compiles
 * every program at once and ignores the last two.
 */
typedef struct {
    const we_policy_directive_t *d;
    size_t                       n;
    const char                  *context;
    int                          floor;
} we_policy_source_t;

/*
 * The plane environment at config test (POLICY.md §2.4), one bit per plane, bit plane_id - 1. A plane is
 * present when <plane>.bin is in the data directory; of those, schema_ok holds the ones whose header
 * and tail say what the name says. A present plane with the wrong schema is bound (UNKNOWN at run time,
 * never a configuration error); an absent plane makes every rule that reads it inert until a reload.
 */
typedef struct {
    uint8_t present;
    uint8_t schema_ok;
    uint8_t legacy;          /* the whisper_edge_snapshot synonym: nothing is inert */
    uint8_t canonical;       /* 1: the arguments are canonical text this compiler printed, re-parsed (R1),
                                so the 2,048-byte argument limit is not applied (POLICY.md D32); 0 for operator input */
} we_policy_env_t;

/* The environment the corpus compiles in: every plane present with the schema its name requires. */
#define WE_POLICY_ENV_ALL { 0xffu, 0xffu, 0u, 0u }

/* Peek the eight files in `dir`: the 192-byte header and its tail, the owner and mode, nothing else. */
int we_policy_env_probe(const char *dir, we_policy_env_t *env);

/*
 * A refusal: POLICY.md §1.5. `phrase` is the normative phrase (the corpus's `message`), which `what` or
 * `fix` contains byte for byte; `token` is already rendered (bytes outside 0x20..0x7E, `"` and `\` as
 * \xHH, upper-case hex, the lexeme truncated at 64 bytes first).
 */
typedef struct {
    const char *layer;       /* length alphabet lexing parsing typing sets program polarity; verify */
    char        phrase[160];
    uint8_t     kind;        /* WE_DIR_* of the directive the refusal points at */
    uint32_t    directive;   /* its index in the source */
    uint32_t    rule;        /* its ordinal among the directives of its kind in its context */
    uint32_t    line;
    uint32_t    col;
    char        context[128];    /* over 127 bytes: the first 61, "...", the last 63 */
    char        token[260];
    size_t      token_len;   /* the raw lexeme's bytes before rendering, at most 64 */
    char        what[1024];
    char        fix[256];
} we_policy_error_t;

/* `rule N, line L, column C: near "token": what. fix`, as the modules print it. */
int we_policy_error_format(const we_policy_error_t *e, char *buf, size_t n);
const char *we_policy_kind_name(uint8_t kind);

/*
 * Reported, never refused (POLICY.md §1.5): one call per report, each printed once at config test with the
 * rule named. `code` and `detail` are the machine form the differential compares; `msg` is the sentence.
 * The codes: inert-at-config, inert-allow-exposes, shadowed-by, tautology, coverage, duplicate-member,
 * sentinel-negative, denies-all-absent, capturing-allow, unbounded, adds-nothing.
 */
typedef struct {
    const char *context;     /* the program's context ("http" for the floor), or a declaration's */
    uint8_t     kind;        /* WE_DIR_POLICY, WE_DIR_FLOOR, or WE_DIR_SET for a declaration */
    uint32_t    rule;        /* 1-based; 0 for a declaration */
    const char *name;        /* a declaration's set name without its @; NULL otherwise */
    const char *code;
    const char *detail;      /* "" when the code carries none */
    const char *msg;
} we_policy_report_line_t;

typedef struct {
    void (*line)(void *ud, const we_policy_report_line_t *r);
    void  *ud;
} we_policy_report_t;

typedef struct we_policy_build we_policy_build_t;

#define WE_POLICY_OK      0
#define WE_POLICY_REFUSED (-1)   /* *err says why; nothing is allocated */
#define WE_POLICY_NOMEM   (-2)

/*
 * Compile a configuration: every context's program, the http floor (always, empty when none was
 * written, so the hold-harmless table exists in every configuration), threshold sugar, and the modes.
 * Byte-identical blocks are interned on the digest of the whole block and confirmed by memcmp. The
 * whole configuration is checked: any refusal anywhere refuses the build.
 */
int we_policy_build(const we_policy_source_t *src, const we_policy_env_t *env, const we_alloc_t *alloc,
                    we_policy_build_t **out, we_policy_error_t *err, we_policy_report_t *rep);
/*
 * POLICY.md §3.1: compile the configuration as we_policy_build() does and return the one program the source
 * selects, in its own allocation from `alloc` (one block, freed with alloc->free or
 * we_program_free). *out is NULL with WE_POLICY_OK when the context runs no program.
 */
int we_policy_compile(const we_policy_source_t *src, const we_policy_env_t *env, const we_alloc_t *alloc,
                      we_program_t **out, we_policy_error_t *err, we_policy_report_t *rep);
void we_policy_build_free(we_policy_build_t *b);

/* The program a context runs: its own lines, or the nearest enclosing context's. NULL: none. */
const we_program_t *we_policy_program(const we_policy_build_t *b, const char *context);
/* The floor, compiled at http level. Never NULL in a build. */
const we_program_t *we_policy_floor(const we_policy_build_t *b);
/* The context's conf: its own mode, or the nearest enclosing one's. */
we_ctx_conf_t we_policy_conf(const we_policy_build_t *b, const char *context);
/* Distinct blocks after interning, and their hot bytes in total. */
uint32_t we_policy_block_count(const we_policy_build_t *b);
size_t   we_policy_hot_total(const we_policy_build_t *b);

/* §5.5's twenty-two steps, in order; 0 on accept, else -(step) with *err filled. */
int we_program_verify(const we_program_t *p, size_t len, we_policy_error_t *err);

/*
 * The canonical text (POLICY.md §2.1, §7): every rule's line, LF-terminated, in order, NUL-terminated;
 * returns its length, or -1 when n is too small. The cold region also holds, after the rules, the
 * declaration of every named set the rules use (sorted by name, members canonical), which the
 * verifier's re-parse needs; we_program_print_sets() returns those lines.
 */
int we_program_print(const we_program_t *p, char *buf, size_t n);
int we_program_print_sets(const we_program_t *p, char *buf, size_t n);
/* An instruction listing, for the disassembler and the reports. */
int we_program_disasm(const we_program_t *p, char *buf, size_t n);

/*
 * §7: the program `whisper_edge_threshold <level>` means; threshold 0 (off) is the empty program.
 * we_policy_sugar_env() compiles it for an environment, exactly as we_policy_build() does for a context
 * holding the threshold: that is the block a module arms, and outside the legacy synonym its rule is
 * inert where reputation is absent (D-af). we_policy_sugar() compiles it as though every plane were
 * present and no synonym named; it stays for the equivalent line a module logs and for byte identity
 * with the written rule (row G1), and its block matches only an all-present, non-legacy environment.
 */
int we_policy_sugar(uint8_t threshold, const we_alloc_t *alloc, we_program_t **out);
int we_policy_sugar_env(uint8_t threshold, const we_policy_env_t *env, const we_alloc_t *alloc, we_program_t **out);
void we_program_free(const we_alloc_t *alloc, we_program_t *p);
/* The length a caller compares or copies: the block's total_len. */
size_t we_program_size(const we_program_t *p);

/*
 * Build the hold-harmless view from a VERIFIED floor block, once per configuration, outside the
 * block. `hh` must be 64-byte aligned; the module places it on its own page of the region it maps for
 * the interned blocks, so it is shared and write-protected with them. Returns 0, or -1 for a block
 * that is not a floor or an `hh` that is not aligned.
 */
int we_program_place(const we_program_t *floor, we_hh_view_t *hh);

/*
 * Was this block compiled for this environment? The verifier holds a block to itself, so it cannot
 * know which planes the module has: a block's legacy flag and each binding's inert byte must equal what
 * we_policy_build() would write for `env` (inert exactly when the plane is absent and the block is not
 * legacy). 0 when they do, -1 when the block was compiled for another environment and must not be armed.
 * The module calls it after we_program_verify(), once per block, at configuration load.
 */
int we_program_env_matches(const we_program_t *p, const we_policy_env_t *env);

/* ---- the outage classification, POLICY.md §2.5 ---- */
typedef enum {
    WE_TENANT_FRESH = 0,
    WE_TENANT_GRACE,         /* stale, within 48 h of valid_until_ms */
    WE_TENANT_LAPSED,        /* stale, past it */
    WE_TENANT_NULL,          /* refused or loading */
    WE_TENANT_REVOKED
} we_tenant_state_t;

#define WE_CLASS_UNAFFECTED  0u
#define WE_CLASS_INERT       1u
#define WE_CLASS_NARROWED    2u
#define WE_CLASS_CAPTURES    3u
#define WE_CLASS_INERT_AT_CONFIG 4u
typedef struct {
    uint16_t rule;           /* 1-based */
    uint8_t  action;
    uint8_t  cls;            /* WE_CLASS_* */
    uint8_t  dependent;      /* reads an out plane, or is a deny or log below a capturing allow */
    uint8_t  values;         /* the root's value set: bit 0 T, bit 1 F, bit 2 U */
    uint8_t  pad[2];
} we_rule_class_t;

/*
 * Classify every rule against the out-set (the seven non-tenant planes' bits in out_mask; the tenant
 * plane's bit is ignored and `tenant` alone governs it). Writes min(rule_count, n) entries and returns
 * the number of dependent rules. Linear in the program; cold, run on the module's transition tick.
 */
uint32_t we_program_dependents(const we_program_t *p, uint8_t out_mask, we_tenant_state_t tenant,
                               we_rule_class_t *out, uint32_t n);
/*
 * The one log line for a transition, `<what>: <classes>`. A module passes the head as `what`, so the line is
 * "plane tor stale out=tor tenant=fresh: rule 5 allow captures; rules 6-9 disarmed; rule 2 narrowed".
 */
int we_program_dependents_line(const we_program_t *p, uint8_t out_mask, we_tenant_state_t tenant,
                               const char *what, char *buf, size_t n);

/*
 * ---- the language's attributes and the verdict, for tools (never the request path) ----
 * The attribute table the compiler types against, and the two lines the differential compares, so a
 * tool shows exactly what the evaluator read and decided without restating either.
 */
#define WE_ATTR_BOOL     1u
#define WE_ATTR_LEVEL    2u
#define WE_ATTR_ENUM     3u
#define WE_ATTR_ASN      4u
#define WE_ATTR_COUNTRY  5u

typedef struct {
    const char *name;        /* the word a rule writes: "tor_exit", "registry_country" */
    const char *plane;       /* its plane's file name without .bin: "tor", "registry" */
    uint8_t     plane_id;    /* 1..8; the memo block to render from is e[plane_id - 1] */
    uint8_t     cls;         /* WE_ATTR_* */
    uint8_t     off;         /* its bytes in the normalised 16-byte block */
    uint8_t     mask;        /* a bool's bit */
    uint8_t     sentinel;    /* 1: it has `undetermined` */
} we_attr_info_t;

/* The number of attributes: 25. */
uint32_t we_attr_count(void);
/* Attribute i (0 .. we_attr_count() - 1) into *out: 0, or -1 for an index out of range. */
int we_attr_info(uint32_t i, we_attr_info_t *out);
/*
 * Attribute i's value from its plane's memo block (we_memo_entry_t.block, the CLAMPED block the fill
 * wrote) under that plane's memo state (WE_ST_*), as the rule language writes it: `true`/`false`,
 * a level, an enum word, an ASN in decimal, a country's alpha-2, `undetermined` for a sentinel and for a
 * country code the compiled table does not know; the plane's state where it decides instead: `unread`
 * (not looked up), `unknown` (NULL, stale, generation 0 off the tenant plane), `stale:true` or
 * `stale:false` (a tenant bool within its 48-hour grace), `lapsed:true` or `lapsed:false` (past it, the
 * block's byte 14) or `revoked`. `listed` renders the record's clamped level nibble as written: the
 * inferred flag is the separate attribute `inferred`, and what a rule's `listed` test reads under
 * allow_inferred off (an inference reads `none`) is the evaluator's, not this rendering's.
 * The length written (as snprintf), or -1 for an index out of range.
 */
int we_attr_render(uint32_t i, const uint8_t block[16], uint32_t state, char *buf, size_t n);
/*
 * The verdict's two lines, in the differential's format (POLICY.md section 5.6): `verdict step=...` and
 * `cost ops=...`, without newlines. The cost counts exist in a WE_TRACE build only (the request path
 * counts nothing), so an untraced build writes `cost untraced`. Each buffer holds n bytes; WE_VERDICT_LINE_MAX always fits both.
 * 0, or -1 if n was too small (the lines are then truncated, still terminated).
 */
#define WE_VERDICT_LINE_MAX 2560u
int we_verdict_format(const we_verdict_t *v, char *verdict_line, char *cost_line, size_t n);

/* ---- per-rule counters, sharded per thread (POLICY.md §3.6) ---- */
typedef struct {
    uint64_t  started_ms;
    uint64_t  generation;      /* the program's identity, for the summary: its digest's first 8 bytes */
    uint32_t  shards;
    uint32_t  rule_count;
    uint32_t  stride;          /* u64 entries per shard, padded to a 64-byte multiple */
    uint32_t  pad;
    uint64_t *hits;            /* shards * stride, 64-byte aligned */
} we_rule_counters_t;

we_rule_counters_t *we_rule_counters_new(const we_program_t *p, uint32_t shards, uint64_t now_ms);
void                we_rule_counters_free(we_rule_counters_t *c);
/*
 * Count one firing of rule (1-based) in this thread's shard. One writer per shard, so a relaxed load
 * and a relaxed store, never a locked add; tear-free for the reader on every 64-bit target.
 */
static inline void we_rule_count(we_rule_counters_t *c, uint32_t shard, uint32_t rule)
{
    uint64_t *slot;

    if (c == NULL || shard >= c->shards || rule == 0u || rule > c->rule_count) {
        return;
    }
    slot = c->hits + (size_t)shard * c->stride + (rule - 1u);
    __atomic_store_n(slot, __atomic_load_n(slot, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELAXED);
}
uint64_t we_rule_counters_sum(const we_rule_counters_t *c, uint32_t rule);
/* Sum the shards into <dir>/<pid>.rules.cnt by temp file and rename; refresh tick only. WE_OK, or
 * WE_ERR_PERMISSIONS and WE_ERR_OPEN as we_counters_write() returns them. */
int we_rule_counters_write(const we_rule_counters_t *c, const we_program_t *p, const char *dir, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif /* WE_POLICY_H */
