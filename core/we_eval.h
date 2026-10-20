/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_eval.h - the policy evaluator on the request path: header-only, force-inlined.
 *
 * WHAT IS CLAIMED, EXACTLY. hotpath-gate.sh disassembles the wrappers in hp.c and proves, for the
 * classes it can see: no call, no relocation (so no global, GOT, PLT, jump table or outline atomic),
 * no atomic or fence instruction, no local on the stack, a frame under 256 bytes. It cannot see a
 * store THROUGH a pointer, so the claim "no store outside *ctx and *out" is proven by the gate for the
 * classes it sees together with test_policy, which runs every leg with the program block, the
 * hold-harmless view and every plane buffer under mprotect(PROT_READ), so a stray store faults.
 *
 * THE ORDER IS FIXED (POLICY.md (decision 2); POLICY.md §3.2): (1) the fixed exemptions, hold-harmless on the
 * floor's address when the walk made it eligible, then ACME; (2) the tenant allow list while the tenant
 * plane is fresh; (3) the floor, deny and log only, under the http-level conf; (3.5) the stale tenant
 * allow, within 48 hours of valid_until_ms; (4) the context's rules on the server's address under the
 * context's conf, first match wins; default allow. Nothing here reads a clock: now_ms is EPOCH
 * milliseconds, passed in.
 *
 * KLEENE STRONG THREE-VALUED LOGIC as a (T, F) bit pair per stack entry: TRUE (1, 0), FALSE (0, 1),
 * UNKNOWN (0, 0). `and` is (t1 & t2, f1 | f2), `or` (t1 | t2, f1 & f2), `not` swaps the pair. The stack
 * is two 64-bit words, so an over- or underflow is a shift, never a stray store; the verifier's stack
 * pass is about meaning, not memory. deny and log act on TRUE only; an allow at UNKNOWN ends evaluation
 * with allow (allow-by-unknown): there is no fail-closed path.
 *
 * Every table this reads is in the program block, a plane buffer or the caller's context: nothing in
 * .rodata, so nothing the gate would refuse as a relocation. The opcode is one-hot and tested bit by
 * bit, never compared for equality, so no compiler folds the dispatch into a jump table.
 */
#ifndef WE_EVAL_H
#define WE_EVAL_H

#include "whisper_edge.h"
#include "we_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * WE_TRACE_EVAL(p, n): the evaluator's own loads (instructions, rules, bindings, set nodes and
 * bitmaps, the descriptor fields a fill reads), placed like WE_TRACE_READ as an expression and
 * ((void)0) in production. The plane lookups keep WE_TRACE_READ.
 */
#ifdef WE_TRACE
void we_trace_eval(const void *p, size_t len);
void we_trace_k3(uint64_t t, uint64_t f);
void we_trace_op(uint32_t op, uint64_t t, uint64_t f);
#define WE_TRACE_EVAL(p, n)   we_trace_eval((const void *)(p), (n))
#define WE_TRACE_K3(t, f)     we_trace_k3((t), (f))
#define WE_TRACE_OP(o, t, f)  we_trace_op((o), (t), (f))
#define WE_EVAL_COUNT(x)      (x)
#else
#define WE_TRACE_EVAL(p, n)   ((void)0)
#define WE_TRACE_K3(t, f)     ((void)0)
#define WE_TRACE_OP(o, t, f)  ((void)0)
#define WE_EVAL_COUNT(x)      ((void)0)
#endif

/* The mutants' guard is we_policy.h's, which this header includes. */

#ifdef WE_TEST_PLANTED_STORE
extern volatile int we_test_planted;        /* the harness's: nonzero in H3's child alone */
#endif

/*
 * THE EVALUATION-SITE RECORD. Every inlined copy of we_decide() leaves one 4-byte PC-relative record in
 * the section .we_eval_sites and adds no instruction: a numeric local label at the site, then a
 * `.long 1b - .` pushed into that section, resolved by the static link (so the module's dynamic
 * relocations are what they were) and read by the module gates with `objdump -s -j .we_eval_sites`,
 * each record mapped to the symbol holding its site, which must be the module's decide wrapper and no
 * other function, exactly once per module; the gates strip the section before they compare builds.
 * gate/eval-sites.sh holds the mechanism here: one record inside hpeval of a shared build, zero
 * RELATIVE relocations, the wrapper's instruction count equal with the record and without it. The
 * control, WE_TEST_NO_EVAL_SITES, compiles the record out and exists only in that check's control build.
 */
#if defined(WE_TEST_NO_EVAL_SITES) && !defined(WE_EVAL_SITES_CONTROL)
#error "WE_TEST_NO_EVAL_SITES is the evaluation-site check's control alone"
#endif
#ifdef WE_TEST_NO_EVAL_SITES
#define WE_EVAL_SITE() ((void)0)
#else
#define WE_EVAL_SITE() __asm__ __volatile__("1:\n\t.pushsection .we_eval_sites,\"a\"\n\t.balign 4\n\t.long 1b - .\n\t.popsection")
#endif

#define WE_TENANT_IX       7u                       /* plane_id 8, tenant, as an index */
#define WE_TENANT_GRACE_MS (48ull * 3600ull * 1000ull)

/*
 * Canonicalise an address: ::ffff:0:0/96 is unmapped to IPv4 and nothing else is touched. The
 * deprecated ::a.b.c.d form is NOT mapped, because no stack produces it as a peer address and RFC 4291
 * excludes :: and ::1 from it, so a local ::1 health check stays IPv6 and is never judged as 0.0.0.1.
 * `in` is 16 bytes; for in_family 4 the address is in[0..3], network order.
 */
WE_HOT_INLINE void we_addr_canon(const uint8_t in[16], int in_family, we_addr_t *out)
{
    uint64_t hi, lo, h2, l2;
    uint8_t fam;
    int mapped;

    __builtin_memcpy(&hi, in, 8);
    __builtin_memcpy(&lo, in + 8, 8);
    /* little-endian loads: bytes 8..11 of ::ffff:a.b.c.d are 00 00 ff ff, which read 0xffff0000 */
    mapped = in_family != 4 && hi == 0u && (uint32_t)lo == 0xffff0000u;
    h2 = in_family == 4 ? (hi & 0xffffffffull) : mapped ? (lo >> 32) : hi;
    l2 = (in_family == 4 || mapped) ? 0u : lo;
    fam = (uint8_t)((in_family == 4 || mapped) ? 4u : 6u);
    __builtin_memcpy(out->b, &h2, 8);
    __builtin_memcpy(out->b + 8, &l2, 8);
    /*
     * The family and the padding as one 8-byte store: every byte of a canonical address is defined, so
     * two of them compare equal with memcmp exactly when they are the same address (the evaluator's own
     * key test reads the words and the family; a caller comparing whole structs read the pad).
     */
    {
        uint64_t tail = fam;

        __builtin_memcpy(&out->family, &tail, 8);
    }
}

/* The binding table of a program block. */
WE_HOT_INLINE const we_binding_t *we_prog_bindings(const we_program_t *p)
{
    return (const we_binding_t *)(const void *)((const uint8_t *)p + p->bindings_off);
}

/*
 * The state a plane would fill to, without the lookup: what ISUNK reads on a plane nothing has filled.
 * Only the unknown-or-not distinction is used: NULL and stale read unknown, fresh does not, and
 * generation 0 is REVOKED (definite) on the tenant plane and UNKNOWN on every other (D-ae).
 */
WE_HOT_INLINE uint32_t we_eval_peek(const we_map_t *m, uint64_t now_ms, uint32_t p)
{
    uint64_t vu, gen;

    if (m == NULL) {
        return WE_ST_UNKNOWN;
    }
    vu = (WE_TRACE_EVAL(&m->valid_until_ms, 8), m->valid_until_ms);
    gen = (WE_TRACE_EVAL(&m->generation, 8), m->generation);
    if (gen == 0u) {
        return (p & 7u) == WE_TENANT_IX ? WE_ST_REVOKED : WE_ST_UNKNOWN;
    }
    return (vu != 0u && now_ms > vu) ? WE_ST_UNKNOWN : WE_ST_FRESH_NR;
}

/*
 * Fill one memo entry: the plane's lookup on the slot's address, the record's attribute block copied
 * by fixed-width moves (never a cast: the IPv4 routing block is 4- but not 8-aligned), clamped in
 * place, the template written UNCLAMPED on no range. A NULL map is UNKNOWN; generation 0 is the revoked
 * map's "nothing armed" (POLICY.md §2.7), so it is REVOKED on the tenant plane, a definite state
 * with its mark, and UNKNOWN on every other plane, because nothing armed is not a measurement and its
 * attributes are undetermined (D-ae); a stale non-tenant plane is UNKNOWN without a lookup, and a stale
 * tenant plane is still looked up, because step 3.5 and the bounded occurrence read its record.
 */
WE_HOT_INLINE void we_eval_fill(const we_map_t *m, we_memo_slot_t *s, uint32_t p, const we_binding_t *b,
                                uint64_t now_ms, we_verdict_t *out, uint32_t si)
{
    we_memo_entry_t *e = &s->e[p & 7u];
    uint64_t w0, w1;
    uint32_t i;

    (void)si;
    /*
     * The operands, parked in out->sc on entry and read back after the search behind a compiler
     * barrier (no instruction), so the search has every other register (POLICY.md D9); a caller that
     * crosses a fill reads its slot back from out->sc.s on every path.
     */
    out->sc.m = m;
    out->sc.b = b;
    out->sc.s = s;
    out->sc.p = p;
    /*
     * Everything the lookup does not decide is stored before it, into the entry and the state byte,
     * so what stays live across the search is the map, the slot, the plane and the binding: the
     * search's own registers plus four, which is what keeps the fill off the stack (POLICY.md D9).
     */
    __builtin_memcpy(&w0, (WE_TRACE_EVAL(b->tmpl, 16), b->tmpl), 8);
    __builtin_memcpy(&w1, b->tmpl + 8, 8);
    __builtin_memcpy(e->block, &w0, 8);
    __builtin_memcpy(e->block + 8, &w1, 8);       /* block[8..13], lapsed and pad: the zero tail */
    e->range = WE_NO_RANGE;
    e->family = s->family;
    e->generation = 0u;
    s->state[p & 7u] = (uint8_t)WE_ST_UNKNOWN;
    if (m == NULL) {
        return;
    }
    {
        uint64_t vu = (WE_TRACE_EVAL(&m->valid_until_ms, 8), m->valid_until_ms);
        uint64_t gen = (WE_TRACE_EVAL(&m->generation, 8), m->generation);
        uint32_t stale = vu != 0u && now_ms > vu;

        e->generation = gen;
        if (gen == 0u) {
            s->state[p & 7u] = (uint8_t)((p & 7u) == WE_TENANT_IX ? WE_ST_REVOKED : WE_ST_UNKNOWN);
            return;
        }
        if (stale && (p & 7u) != WE_TENANT_IX) {
            return;                                /* a stale non-tenant plane: UNKNOWN, no lookup */
        }
        /* staleness is confirmed first, so the subtraction cannot wrap */
        e->lapsed = (uint8_t)(stale && now_ms - vu > WE_TENANT_GRACE_MS);
        s->state[p & 7u] = (uint8_t)(stale ? WE_ST_STALE_HIT : WE_ST_FRESH_HIT);
    }
    /* across the search only `out` stays live: the operands were parked on entry (POLICY.md D9) */
    if (s->family == 4u) {
        uint32_t a;

        __builtin_memcpy(&a, s->addr, 4);
        i = we_find4(m, __builtin_bswap32(a));
    } else if (b->key6 == 8u) {
        i = we_find6_64(m, s->addr);
    } else {
        i = we_find6(m, s->addr);
    }
    __asm__ __volatile__("" ::: "memory");
    m = out->sc.m;
    b = out->sc.b;
    s = (we_memo_slot_t *)out->sc.s;
    p = out->sc.p;
    e = &s->e[p & 7u];
    WE_EVAL_COUNT(out->lookups[si & 1u][p & 7u]++);
#ifdef WE_TEST_PLANTED_STORE
    /*
     * The standing negative control for H3: one store into a plane buffer, which mprotect faults.
     * Armed by the harness for H3's own child only, so the fault is that row's.
     */
    if (we_test_planted && m->f4.n != 0u) {
        *(volatile uint8_t *)(uintptr_t)m->f4.start = 0u;
    }
#endif
    if (i == WE_NO_RANGE) {
        s->state[p & 7u] = (uint8_t)(s->state[p & 7u] + 1u);   /* the hit state's no-range twin */
        return;
    }
    e->range = i;
    if (b->schema_id == WE_SCHEMA_FORMAT1) {
        const uint8_t *sv = (s->family == 4u ? m->f4.sev : m->f6.sev) + i;
        uint8_t v = (WE_TRACE_READ(sv), *sv);
#ifdef WE_TEST_NO_CLAMP
        e->block[0] = v;
#else
        /* low nibble 0..4 as written, 5..15 read critical; 0x10, 0x20, 0x40 dropped */
        uint8_t nib = (uint8_t)(v & 0x0fu);

        nib = nib > 4u ? (uint8_t)4u : nib;
        e->block[0] = (uint8_t)((v & 0x80u) | nib);
#endif
    } else if (b->schema_id == WE_SCHEMA_ROUTING) {
        uint16_t cc;

        if (s->family == 4u) {
            const uint8_t *rec = m->f4.records + (size_t)i * m->f4.stride;
            const uint32_t *r0 = (const uint32_t *)(const void *)(rec + 4);
            const uint32_t *r1 = (const uint32_t *)(const void *)(rec + 8);
            const uint16_t *r2 = (const uint16_t *)(const void *)(rec + 12);
            uint32_t a, c;
            uint16_t d;

            __builtin_memcpy(&a, (WE_TRACE_READ(r0), r0), 4);
            __builtin_memcpy(&c, (WE_TRACE_READ(r1), r1), 4);
            __builtin_memcpy(&d, (WE_TRACE_READ(r2), r2), 2);
            __builtin_memcpy(e->block, &a, 4);
            __builtin_memcpy(e->block + 4, &c, 4);
            __builtin_memcpy(e->block + 8, &d, 2);
        } else {
            const uint8_t *rec = m->f6w.records + (size_t)i * m->f6w.stride;
            const uint64_t *r0 = (const uint64_t *)(const void *)(rec + 8);
            const uint16_t *r1 = (const uint16_t *)(const void *)(rec + 16);
            uint64_t a;
            uint16_t d;

            __builtin_memcpy(&a, (WE_TRACE_READ(r0), r0), 8);
            __builtin_memcpy(&d, (WE_TRACE_READ(r1), r1), 2);
            __builtin_memcpy(e->block, &a, 8);
            __builtin_memcpy(e->block + 8, &d, 2);
        }
#ifndef WE_TEST_NO_CLAMP
        __builtin_memcpy(&cc, e->block + 4, 2);
        cc = we_country(m, cc);                 /* > 999 and codes this reader does not know: 0 */
        __builtin_memcpy(e->block + 4, &cc, 2);
        e->block[6] = e->block[6] > 3u ? (uint8_t)0u : e->block[6];   /* rov: a record never holds 4 */
        e->block[7] = e->block[7] > 5u ? (uint8_t)0u : e->block[7];   /* rir */
        e->block[8] = (uint8_t)(e->block[8] & b->flag_mask);           /* anycast, moas, narrowed */
        e->block[9] = e->block[9] > 4u ? (uint8_t)0u : e->block[9];   /* asn_rep */
#else
        (void)cc;
#endif
    } else {
        const uint8_t *rec;
        const uint32_t *r0;
        const uint16_t *r1;
        uint32_t fl;
        uint16_t d;

        if (s->family == 4u) {
            rec = m->f4.records + (size_t)i * m->f4.stride;
            r0 = (const uint32_t *)(const void *)(rec + 4);
            r1 = (const uint16_t *)(const void *)(rec + 8);
        } else {
            rec = m->f6.records + (size_t)i * m->f6.stride;
            r0 = (const uint32_t *)(const void *)(rec + 16);
            r1 = (const uint16_t *)(const void *)(rec + 20);
        }
        __builtin_memcpy(&fl, (WE_TRACE_READ(r0), r0), 4);
        __builtin_memcpy(&d, (WE_TRACE_READ(r1), r1), 2);
#ifndef WE_TEST_NO_CLAMP
        fl &= b->flag_mask;
#endif
        __builtin_memcpy(e->block, &fl, 4);
        __builtin_memcpy(e->block + 4, &d, 2);
#ifndef WE_TEST_NO_CLAMP
        e->block[5] = e->block[5] > 2u ? (uint8_t)0u : e->block[5];   /* reason */
#endif
    }
}

/*
 * The decision's four bytes (step, action, program, reason) as ONE 32-bit immediate store. Written as
 * four byte stores, gcc merges the constant ones into a 16-bit load from .rodata, a relocation the
 * hot-path gate refuses; one computed word cannot be pooled.
 */
WE_HOT_INLINE void we_out_set(we_verdict_t *out, uint32_t step, uint32_t action, uint32_t program, uint32_t reason)
{
    uint32_t w = (step & 0xffu) | (action & 0xffu) << 8 | (program & 0xffu) << 16 | (reason & 0xffu) << 24;

    __builtin_memcpy(out, &w, 4);              /* little-endian: step, action, program, reason */
}

/*
 * Key a slot to a canonical address. A slot already keyed to it keeps its memo; any other key resets
 * it, which is two stores: key_valid, and the eight state bytes as one word. The stored key is compared
 * only behind key_valid: an unkeyed slot's address bytes may never have been written (a fresh scratch),
 * and a branch on them would read memory nothing defined.
 */
WE_HOT_INLINE void we_slot_key(we_memo_slot_t *s, uint64_t hi, uint64_t lo, uint8_t fam)
{
    uint64_t kh, kl, z = 0u;

    if (s->key_valid) {
        __builtin_memcpy(&kh, s->addr, 8);
        __builtin_memcpy(&kl, s->addr + 8, 8);
        if (kh == hi && kl == lo && s->family == fam) {
            return;
        }
    }
    __builtin_memcpy(s->addr, &hi, 8);
    __builtin_memcpy(s->addr + 8, &lo, 8);
    s->family = fam;
    s->key_valid = 1u;
#ifndef WE_TEST_NO_MEMO_RESET
    __builtin_memcpy(s->state, &z, 8);
#else
    (void)z;
#endif
}

/*
 * The instruction loop's state across a search (POLICY.md D9): parked in out->sc before it, read back
 * after a compiler barrier that emits nothing, so that only `out` crosses the search and the search
 * has every other register. A spill to the stack is what the hot-path gate refuses. The parking is not
 * free: the volatile reloads and the parked state measured 23% more data references under cachegrind
 * than the same loop holding its state in registers. That is the price of
 * the gate's zero-locals claim, paid in loads from the verdict's own scratch block, and it is
 * taken knowingly rather than called negligible.
 */
/*
 * A log (or a downgraded deny) that fired: its bit in the program's bitmap. `out` passes through an
 * empty volatile asm at the store, which emits nothing but makes the pointer a value born there, so no
 * compiler can hoist &out->log_fired out of the loop and keep it in a register across the program
 * (clang 19 and 20 did, and spilled it: 8 bytes of locals in hpeval and hpeval_ops).
 */
#define WE_LOG_MARK(r) do { \
        we_verdict_t *ov_ = out; \
        uint32_t r_ = (r); \
        __asm__ __volatile__("" : "+r"(ov_)); \
        ov_->log_fired[WE_RWHICH & 1u][(r_ >> 3) & 31u] |= (uint8_t)(1u << (r_ & 7u)); \
    } while (0)
#define WE_RUN_PARK() do { out->sc.t = T; out->sc.f = F; out->sc.pc = pc; } while (0)
#define WE_RUN_UNPARK() do { \
        __asm__ __volatile__("" ::: "memory"); \
        p = (const we_program_t *)out->sc.prog; \
        T = out->sc.t; \
        F = out->sc.f; \
        pc = out->sc.pc; \
        I = WE_RINS + pc; \
        op = I->op; \
        pl = I->plane & 7u; \
        imm = I->imm; \
    } while (0)

/*
 * One program's rules, first match wins. Returns 1 when a rule decided (and *out says how), 0 to go
 * on. `which` is 0 for the floor and 1 for the context; `mode` and `allow_inf` are the running
 * context's own, normalised.
 */
WE_HOT_INLINE int we_eval_run(const we_program_t *p, uint32_t mode, uint32_t allow_inf, uint32_t which,
                              const we_eval_ctx_t *ctx, we_memo_slot_t *s, uint32_t si,
                              const we_binding_t *bind, uint64_t now_ms, we_verdict_t *out)
{

    /* parked once; a fill reads them back (POLICY.md D9: the loop's state crosses a search in *out) */
    out->sc.prog = p;
    out->sc.ctx = ctx;
    out->sc.slot = s;
    out->sc.bind = bind;
    out->sc.now_ms = now_ms;
    out->sc.mode = mode;
    out->sc.allow_inf = allow_inf;
    out->sc.which = which;
    out->sc.si = si;
/*
 * The loop's invariants, read from *out where they are used (POLICY.md D9), never held in a register: each
 * through a volatile lvalue, the same plain load pinned to its use, so no compiler keeps the value it
 * stored on entry in a register across the whole program and spills it.
 */
#define WE_RCTX   ((const we_eval_ctx_t *)*(const void *const volatile *)&out->sc.ctx)
#define WE_RS     ((we_memo_slot_t *)*(void *const volatile *)&out->sc.slot)
#define WE_RBIND  (*(const we_binding_t *const volatile *)&out->sc.bind)
#define WE_RNOW   (*(const volatile uint64_t *)&out->sc.now_ms)
#define WE_RMODE  (*(const volatile uint32_t *)&out->sc.mode)
#define WE_RINF   (*(const volatile uint32_t *)&out->sc.allow_inf)
#define WE_RWHICH (*(const volatile uint32_t *)&out->sc.which)
#define WE_RSI    (*(const volatile uint32_t *)&out->sc.si)
#define WE_RRULES ((const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off))
#define WE_RINS   ((const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off))
    /* the rule index lives in out->sc.r alone, and the rule is re-derived where it is read (D9) */
    /*
     * One exit, and its result is read from the verdict: the decisions set out->sc.decided and jump
     * there, so neither the loop's comparison nor the return value is a value any compiler carries
     * through a rule (each was, under clang at -O, the one byte it spilled).
     */
    out->sc.decided = 0u;
    for (out->sc.r = 0u;; out->sc.r++) {
        const we_rule_t *R;
        uint64_t T = 0u, F = 0u;
        uint32_t pc;

        if (*(const volatile uint32_t *)&out->sc.r >= *(const volatile uint16_t *)&p->rule_count) {
            goto done;
        }
        R = (WE_TRACE_EVAL(WE_RRULES + out->sc.r, 16), WE_RRULES + out->sc.r);
#ifdef WE_TEST_EXTRA_LOAD
        {
            /*
             * The control: one more data reference per rule, from a byte nothing else reads. The byte must
             * feed a real instruction: a load whose result nothing uses (`ldrb wzr` from clang on
             * aarch64, or a register an empty asm only pretends to read) is dead to Valgrind's IR and
             * dropped before cachegrind counts it. So the byte, hidden from the compiler by the asm, is
             * shifted right by 8 (always 0) and added to R: one load, two ALU instructions, no store.
             */
            uint32_t xl_ = *(const volatile uint8_t *)&R->reserved;

            __asm__ __volatile__("" : "+r"(xl_));
            R += xl_ >> 8;
        }
#endif

        if ((R->flags & WE_RF_INERT) != 0u) {
            continue;                          /* a plane absent at config test: the rule is inert */
        }
        pc = R->instr_start;
        for (;;) {
            const we_instr_t *I;

            __asm__ __volatile__("" ::: "memory");     /* nothing invariant is held across instructions */
            I = (WE_TRACE_EVAL(WE_RINS + pc, 8), WE_RINS + pc);
            uint32_t op = I->op;
            uint32_t pl = I->plane & 7u;
            uint32_t imm = I->imm;

            WE_EVAL_COUNT(out->ops_executed++);
            WE_EVAL_COUNT(WE_RWHICH ? out->ops_ctx++ : out->ops_floor++);
            WE_TRACE_OP(op, T, F);
            if ((op & WE_OP_ATOM) != 0u) {
                const uint8_t *blk;
                uint32_t st, unk, known, v = 0u, t, f;

                /* ISUNK reads the plane's state and never looks anything up */
#ifdef WE_TEST_NO_MEMO_HIT
                if ((op & WE_OP_ISUNK) == 0u) {
                    WE_RUN_PARK();
                    we_eval_fill(WE_RCTX->view[pl].m, WE_RS, pl, WE_RBIND + pl, WE_RNOW, out, WE_RSI);
                    WE_RUN_UNPARK();
                }
#else
                if (WE_RS->state[pl] == WE_ST_NONE && (op & WE_OP_ISUNK) == 0u) {
                    WE_RUN_PARK();
                    we_eval_fill(WE_RCTX->view[pl].m, WE_RS, pl, WE_RBIND + pl, WE_RNOW, out, WE_RSI);
                    WE_RUN_UNPARK();
                }
#endif
                st = WE_RS->state[pl];
                st = st != WE_ST_NONE ? st : we_eval_peek(WE_RCTX->view[pl].m, WE_RNOW, pl);
                blk = WE_RS->e[pl].block + (I->off & 15u);
                unk = (uint32_t)(uint8_t)(st - WE_ST_STALE_HIT) <= 2u;   /* stale (tenant) or unknown */
                known = unk ^ 1u;
                if ((op & WE_OP_BOOL) != 0u) {
                    /* the tenant exception: the bounded reading, on the one occurrence the polarity bit names */
                    uint32_t stale_t = (uint32_t)(uint8_t)(st - WE_ST_STALE_HIT) <= 1u;
#if defined(WE_TEST_TENANT_ATOM_U)
                    uint32_t bnd = 0u;
#elif defined(WE_TEST_TENANT_BIT_IGNORED)
                    uint32_t bnd = stale_t & (pl == WE_TENANT_IX ? 1u : 0u);
#else
                    uint32_t bnd = ((imm >> 8) & 1u) & stale_t;
#endif
                    (void)stale_t;
                    v = (blk[0] & imm & 0xffu) != 0u;
                    known |= bnd;
                    v &= (bnd & WE_RS->e[pl].lapsed) ^ 1u;
                }
                if ((op & WE_OP_SEV) != 0u) {
                    uint32_t lvl = blk[0] & 0x0fu;
                    uint32_t inferred = (uint32_t)blk[0] >> 7;

                    lvl = (inferred & (WE_RINF ^ 1u)) != 0u ? 0u : lvl;   /* an inference reads `none` */
                    v = (imm >> (lvl & 31u)) & 1u;
                }
                if ((op & WE_OP_EQ8) != 0u) {
                    v = blk[0] == (uint8_t)imm;
                }
                if ((op & WE_OP_EQ16) != 0u) {
                    uint16_t c;

                    __builtin_memcpy(&c, blk, 2);
                    v = c == (uint16_t)imm;
                }
                if ((op & WE_OP_EQ32) != 0u) {
                    uint32_t a;

                    __builtin_memcpy(&a, blk, 4);
                    v = a == imm;
                }
                if ((op & WE_OP_INSET_ENUM) != 0u) {
                    v = (imm >> (blk[0] & 31u)) & 1u;
                }
                if ((op & WE_OP_INSET_COUNTRY) != 0u) {
                    uint16_t c;
                    const uint8_t *bm;

                    __builtin_memcpy(&c, blk, 2);
                    bm = ((const uint8_t *)p) + imm + (c >> 3);            /* c is normalised: at most 999, so byte 124 */
                    v = ((WE_TRACE_EVAL(bm, 1), *bm) >> (c & 7u)) & 1u;
                    WE_EVAL_COUNT(out->set_probes++);
                    WE_EVAL_COUNT(out->probes[WE_RWHICH & 1u]++);
                }
                if ((op & WE_OP_INSET_ASN) != 0u) {
                    /*
                     * The S+ tree (POLICY.md §4.1): keys in 16-key leaves, separators above, root first. The
                     * search runs on a' = a - (a == 0xFFFFFFFF), because the padding key IS the sentinel:
                     * on `a` the halving count would include every padding slot and index past the
                     * level's real nodes. The leaf compares k[max(c, 1) - 1], so a probe below the
                     * smallest member never reads k[-1]. Then the sentinel answers has_undetermined,
                     * never `found`, or an unrouted address would be a member of every padded set.
                     */
                    const uint8_t *pay = ((const uint8_t *)p) + WE_ASN_IMM_OFF(imm);
                    uint32_t a, ap, lv = WE_ASN_IMM_LEVELS(imm), c = 0u, found;
                    const we_node32_t *nd = (const we_node32_t *)(const void *)pay;

                    __builtin_memcpy(&a, blk, 4);
#ifdef WE_TEST_SPLUS_NO_CLAMP
                    ap = a;
#else
                    ap = a - (a == 0xffffffffu ? 1u : 0u);
#endif
                    WE_RUN_PARK();
                    out->sc.sentinel = a == 0xffffffffu;
                    /*
                     * The levels written out, at most three (n <= 539 < 16 * 17 * 17): no loop counter, no
                     * running offset and no level size live across the search. The root is line 0; the
                     * level below starts at line 1; under three levels the leaves start after the m1
                     * nodes of level 2, m1 = (m0 + 16) / 17 with m0 = (n + 15) / 16 the leaves.
                     */
#define WE_SPLUS_STEP() do { \
        WE_TRACE_EVAL(nd, 64); \
        WE_EVAL_COUNT(out->set_probes++); \
        WE_EVAL_COUNT(out->probes[WE_RWHICH & 1u]++); \
        c = 0u; \
        c += (nd->k[c + 7u] <= ap) ? 8u : 0u; \
        c += (nd->k[c + 3u] <= ap) ? 4u : 0u; \
        c += (nd->k[c + 1u] <= ap) ? 2u : 0u; \
        c += (nd->k[c] <= ap) ? 1u : 0u; \
        c += (nd->k[c] <= ap) ? 1u : 0u; \
    } while (0)
                    WE_SPLUS_STEP();
                    if (lv >= 2u) {
                        uint32_t idx = c, base = 64u;

                        if (lv == 3u) {
                            nd = (const we_node32_t *)(const void *)(pay + 64u + (size_t)idx * 64u);
                            WE_SPLUS_STEP();
                            base = 64u + ((((WE_ASN_IMM_N(imm) + 15u) >> 4) + 16u) / 17u) * 64u;
                            idx = idx * 17u + c;
                        }
                        nd = (const we_node32_t *)(const void *)(pay + base + (size_t)idx * 64u);
                        WE_SPLUS_STEP();
                    }
#undef WE_SPLUS_STEP
                    found = nd->k[c - (c != 0u ? 1u : 0u)] == ap;
                    WE_RUN_UNPARK();
#ifdef WE_TEST_SENTINEL_PADDING
                    v = found;
#else
                    v = out->sc.sentinel != 0u ? WE_ASN_IMM_HASU(imm) : found;
#endif
                    /* an INSET_ASN plane was filled, so its state byte is set: the reading is known or not */
                    st = WE_RS->state[pl];
                    unk = (uint32_t)(uint8_t)(st - WE_ST_STALE_HIT) <= 2u;
                    known = unk ^ 1u;
                }
                {
                    /*
                     * ISUNK: never U, the plane state whatever the bounded reading. Selected by the op's
                     * own bit, not a branch: a branch arm writing the constant 1 is a constant gcc -O
                     * keeps in a register across the whole program, and that register is a spill.
                     */
                    uint32_t isu = (op & WE_OP_ISUNK) >> 8;

                    v = (v & (isu ^ 1u)) | (unk & isu);
                    known |= isu;
                }
                t = v & known;
                f = (v ^ 1u) & known;
                T = (T << 1) | t;
                F = (F << 1) | f;
            }
            if ((op & WE_OP_NOT) != 0u) {
#ifdef WE_TEST_BOOL_NOT
                uint64_t nt = (T & 1u) ^ 1u, nf = T & 1u;
#else
                uint64_t nt = F & 1u, nf = T & 1u;
#endif
                T = (T & ~(uint64_t)1u) | nt;
                F = (F & ~(uint64_t)1u) | nf;
            }
            if ((op & (WE_OP_AND | WE_OP_OR)) != 0u) {
                uint64_t t1 = (T >> 1) & 1u, t2 = T & 1u, f1 = (F >> 1) & 1u, f2 = F & 1u, t, f;

                if ((op & WE_OP_AND) != 0u) {
                    t = t1 & t2;
                    f = f1 | f2;
                } else {
                    t = t1 | t2;
                    f = f1 & f2;
                }
#ifdef WE_TEST_K3_WEAK
                if (((t1 | f1) & (t2 | f2)) == 0u || (t1 | f1) == 0u || (t2 | f2) == 0u) {
                    t = 0u;
                    f = 0u;
                }
#endif
                T = ((T >> 2) << 1) | t;
                F = ((F >> 2) << 1) | f;
            }
            if ((op & (WE_OP_JF | WE_OP_JT)) != 0u) {
#if defined(WE_TEST_NO_SHORTCIRCUIT)
                uint32_t take = 0u;
#elif defined(WE_TEST_SHORTCIRCUIT_U)
                uint32_t take = (op & WE_OP_JF) != 0u ? (uint32_t)((T & 1u) ^ 1u) : (uint32_t)((F & 1u) ^ 1u);
#else
                uint32_t take = (op & WE_OP_JF) != 0u ? (uint32_t)(F & 1u) : (uint32_t)(T & 1u);
#endif
                /* forward, inside the rule (the verifier's step 11), so imm >= pc + 1 and imm - 1 cannot wrap */
                pc = take != 0u ? imm - 1u : pc;
                WE_EVAL_COUNT(out->jumps_taken += take);
                WE_EVAL_COUNT(out->jumps[WE_RWHICH & 1u] += take);
            }
            WE_TRACE_K3(T, F);
            if ((op & WE_OP_END) != 0u) {
                break;
            }
            pc = pc + 1u;
        }
        {
            uint32_t t = (uint32_t)(T & 1u), f = (uint32_t)(F & 1u);
            uint32_t r = *(const volatile uint32_t *)&out->sc.r;
            uint32_t act;

            R = WE_RRULES + r;
            act = *(const volatile uint8_t *)&R->action;   /* read here, never carried from the rule's head */

            if (act == WE_ACT_DENY && t != 0u) {
                if (WE_RMODE != WE_MODE_DENY) {
                    /* mode log: the deny is downgraded to a log that records and continues; the action
                     * byte stays deny, so the variables and the counter keep the would-deny identity */
                    WE_LOG_MARK(r);
                    continue;
                }
                we_out_set(out, WE_RWHICH ? WE_STEP_CONTEXT : WE_STEP_FLOOR, WE_ACT_DENY,
                           WE_RWHICH ? WE_VPROG_CONTEXT : WE_VPROG_FLOOR, WE_WHY_RULE);
                out->rule = (uint16_t)(r + 1u);
                out->enforce = 1u;
                out->sc.decided = 1u;
                goto done;
            }
            if (act == WE_ACT_LOG && t != 0u) {
                WE_LOG_MARK(r);
#ifdef WE_TEST_LOG_TERMINATES
                we_out_set(out, WE_RWHICH ? WE_STEP_CONTEXT : WE_STEP_FLOOR, WE_ACT_ALLOW,
                           WE_RWHICH ? WE_VPROG_CONTEXT : WE_VPROG_FLOOR, WE_WHY_RULE);
                out->rule = (uint16_t)(r + 1u);
                out->sc.decided = 1u;
                goto done;
#endif
            }
            if (act == WE_ACT_ALLOW && (t != 0u || f == 0u)) {
#ifdef WE_TEST_ALLOW_U_FALLTHROUGH
                if (t == 0u) {
                    continue;
                }
#endif
                we_out_set(out, WE_RWHICH ? WE_STEP_CONTEXT : WE_STEP_FLOOR, WE_ACT_ALLOW,
                           WE_RWHICH ? WE_VPROG_CONTEXT : WE_VPROG_FLOOR, t != 0u ? WE_WHY_RULE : WE_WHY_ALLOW_BY_UNKNOWN);
                out->rule = (uint16_t)(r + 1u);
                if (t == 0u) {
                    /*
                     * The lowest-id UNKNOWN plane the rule referenced: documented as that, not as the cause.
                     * A plane the short-circuit never looked up has no memo state, so its state is read
                     * from the view as the fill would have: NULL, or stale (revoked is definite). This is
                     * the allow-by-unknown path only.
                     */
                    uint32_t unk = 0u, q;

                    /*
                     * One accumulator, the mask of UNKNOWN planes, and the lowest set bit of it under the
                     * rule's dep_mask at the end: a per-plane running answer is a value per iteration,
                     * which clang 20 unrolled at -O3 and spilled (2 bytes in hpeval and hpeval_ops).
                     */
                    for (q = 0u; q < 8u; q++) {
                        uint32_t sq = WE_RS->state[q];

                        sq = sq != WE_ST_NONE ? sq : we_eval_peek(WE_RCTX->view[q].m, WE_RNOW, q);
                        unk |= (uint32_t)((uint32_t)(uint8_t)(sq - WE_ST_STALE_HIT) <= 2u) << q;
                    }
                    unk &= *(const volatile uint8_t *)&R->dep_mask;
                    /* bit 8 stands for "none": ctz lands on it at 8, and 9 mod 9 is plane 0. No branch and
                     * no zero held for an else arm (gcc kept that zero in a stack byte across the rule) */
                    out->unknown_plane = (uint8_t)(((uint32_t)__builtin_ctz(unk | 0x100u) + 1u) % 9u);
                }
                out->sc.decided = 1u;
                goto done;
            }
        }
    }
done:
    return (int)*(const volatile uint32_t *)&out->sc.decided;
}
#undef WE_RUN_PARK
#undef WE_LOG_MARK
#undef WE_RUN_UNPARK
#undef WE_RCTX
#undef WE_RS
#undef WE_RBIND
#undef WE_RNOW
#undef WE_RMODE
#undef WE_RINF
#undef WE_RWHICH
#undef WE_RSI
#undef WE_RRULES
#undef WE_RINS

/*
 * The conf a context runs under, as a pair: a NULL conf, a zeroed one, and a conf with EITHER field
 * outside its domain all read as the shipped default, dry-run log with allow_inferred off (POLICY.md §3.1).
 * A pair that is half valid is not half honoured: the module wrote nothing that means it.
 */
WE_HOT_INLINE uint32_t we_conf_valid(const we_ctx_conf_t *c)
{
    return c != NULL && (uint32_t)(c->mode - 1u) <= 2u && c->allow_inferred <= 1u;
}

WE_HOT_INLINE uint32_t we_conf_mode(const we_ctx_conf_t *c)
{
    return we_conf_valid(c) ? c->mode : WE_MODE_LOG;
}

WE_HOT_INLINE uint32_t we_conf_inferred(const we_ctx_conf_t *c)
{
    return we_conf_valid(c) ? c->allow_inferred : 0u;
}

/* Clear the verdict: fixed fields and the two bitmaps, as explicit stores (never a memset call). */
WE_HOT_INLINE void we_verdict_clear(we_verdict_t *out)
{
    uint64_t z = 0u;
    uint8_t *lf = &out->log_fired[0][0];

    __builtin_memcpy(out, &z, 8);
    __builtin_memcpy((uint8_t *)out + 8, &z, 8);
    __builtin_memcpy(lf, &z, 8);
    __builtin_memcpy(lf + 8, &z, 8);
    __builtin_memcpy(lf + 16, &z, 8);
    __builtin_memcpy(lf + 24, &z, 8);
    __builtin_memcpy(lf + 32, &z, 8);
    __builtin_memcpy(lf + 40, &z, 8);
    __builtin_memcpy(lf + 48, &z, 8);
    __builtin_memcpy(lf + 56, &z, 8);
#ifdef WE_TRACE
    out->ops_executed = 0u;
    out->ops_floor = 0u;
    out->ops_ctx = 0u;
    out->jumps_taken = 0u;
    out->set_probes = 0u;
    out->jumps[0] = out->jumps[1] = 0u;
    out->probes[0] = out->probes[1] = 0u;
    __builtin_memcpy(&out->lookups[0][0], &z, 8);
    __builtin_memcpy(&out->lookups[1][0], &z, 8);
#endif
}

/*
 * The server's address, canonical as the floor's is, and whether it names the floor's slot: the same
 * canonical address, or no address at all. A family other than 4 or 6 (a unix-socket listener with no
 * realip hands in a zeroed slot) or the unspecified address names no client, so the server has no
 * opinion of its own about who connected and every step judges the floor's address (POLICY.md section
 * 3.2). Judged as `::` instead, it would be an address no feed lists: a deny on a listing would never
 * fire for a client the floor's walk found, and a deny unless allowed would fire for every client.
 */
WE_HOT_INLINE int we_server_canon(const we_request_t *req, const we_memo_slot_t *fs, uint64_t *ph, uint64_t *pl,
                                  uint8_t *pf)
{
    uint64_t hi, lo, kh, kl, m;
    uint8_t raw = req->server.family, fam;
    int mapped;

    __builtin_memcpy(&hi, req->server.b, 8);
    __builtin_memcpy(&lo, req->server.b + 8, 8);
    mapped = raw != 4u && hi == 0u && (uint32_t)lo == 0xffff0000u;
    hi = raw == 4u ? (hi & 0xffffffffull) : mapped ? (lo >> 32) : hi;
    lo = (raw == 4u || mapped) ? 0u : lo;
    fam = (uint8_t)((raw == 4u || mapped) ? 4u : 6u);
    __builtin_memcpy(&kh, fs->addr, 8);
    __builtin_memcpy(&kl, fs->addr + 8, 8);
#ifndef WE_TEST_SERVER_UNSET_KEYED
    /* no address (a family other than 4 or 6, or the unspecified one) takes the floor's key, branch-free */
    m = (uint64_t)0 - (uint64_t)(((raw | 2u) != 6u) | ((hi | lo) == 0u));
    hi = (hi & ~m) | (kh & m);
    lo = (lo & ~m) | (kl & m);
    fam = (uint8_t)((fam & ~(uint8_t)m) | (fs->family & (uint8_t)m));
#else
    (void)m;
#endif
    *ph = hi;
    *pl = lo;
    *pf = fam;
    return kh == hi && kl == lo && fs->family == fam;
}

WE_HOT_INLINE int we_server_is_floor(const we_request_t *req, const we_memo_slot_t *fs)
{
    uint64_t hi, lo;
    uint8_t fam;

    return we_server_canon(req, fs, &hi, &lo, &fam);
}

/*
 * Steps 1 to 3.5 on the floor's address, and the slots keyed. Returns 1 when the pre-stage decided.
 * Split out so the gate can hold it alone (hpfloor); we_decide inlines it.
 */
WE_HOT_INLINE int we_eval_prestage(const we_hh_view_t *hh, const we_binding_t *bind, const we_request_t *req,
                                   we_eval_ctx_t *ctx, uint64_t now_ms, we_verdict_t *out)
{
    we_memo_slot_t *fs = &ctx->slot[0];
    uint64_t hi, lo;
    uint8_t fam;
    uint32_t st;

    /*
     * A new request starts unkeyed, so the keying below resets both slots: a memo kept across
     * requests for a repeated address would answer from the previous request's fill, after a
     * republish too. The memo lives for one request (and its log-phase lazy fills), never longer.
     */
    ctx->slot[0].key_valid = 0u;
    ctx->slot[1].key_valid = 0u;
    __builtin_memcpy(&hi, req->floor.b, 8);
    __builtin_memcpy(&lo, req->floor.b + 8, 8);
    fam = req->floor.family;
    {
        /* canonical, whatever the module handed in: ::ffff:0:0/96 unmapped, IPv4 zero-extended */
        int mapped = fam != 4u && hi == 0u && (uint32_t)lo == 0xffff0000u;

        hi = fam == 4u ? (hi & 0xffffffffull) : mapped ? (lo >> 32) : hi;
        lo = (fam == 4u || mapped) ? 0u : lo;
        fam = (uint8_t)((fam == 4u || mapped) ? 4u : 6u);
    }
    we_slot_key(fs, hi, lo, fam);
    if (req->walk == WE_WALK_NO_ADDRESS) {
        we_out_set(out, WE_STEP_EXEMPT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_NO_ADDRESS);
        return 1;
    }
    out->marks = (uint8_t)(req->walk == WE_WALK_FLOOR_HEADER_MISSING ? WE_MARK_FLOOR_HEADER_MISSING : 0u);
    /* step 1: the fixed exemptions, data-free */
    if (req->hold_harmless_eligible != 0u && hh != NULL) {
        uint32_t i;

        /* across the search only `out` stays live (POLICY.md D9) */
        out->sc.ectx = ctx;
        out->sc.dbind = bind;
        out->sc.req = req;
        out->sc.now_ms = now_ms;
        if (fam == 4u) {
            i = we_find4(&hh->map, __builtin_bswap32((uint32_t)hi));
        } else {
            i = we_find6(&hh->map, fs->addr);
        }
        __asm__ __volatile__("" ::: "memory");
        ctx = (we_eval_ctx_t *)out->sc.ectx;
        bind = out->sc.dbind;
        req = (const we_request_t *)out->sc.req;
        now_ms = out->sc.now_ms;
        fs = &ctx->slot[0];
        if (i != WE_NO_RANGE) {
#ifndef WE_TEST_HH_FLOOR_ENDS_ALL
            /*
             * The floor's address is exempt, which ends the floor's steps (2 to 3.5). It ends the request
             * only when the server judges the same address (POLICY.md section 3.2, step 1). Behind a proxy
             * the server's realip trusts (a loopback peer above all) the peer is the proxy, and step 4
             * judges the client the server derived by the context's rules as written, with no exemption
             * of its own: no address a header carries earns one.
             */
#ifndef WE_TEST_HH_RAW_COMPARE
            if (we_server_is_floor(req, fs)) {
#else
            if (__builtin_memcmp(req->server.b, req->floor.b, 16) == 0 && req->server.family == req->floor.family) {
#endif
                we_out_set(out, WE_STEP_EXEMPT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_HOLD_HARMLESS);
                return 1;
            }
            out->sc.floor = NULL;                /* no floor program for a hold-harmless floor address, */
            bind = NULL;                         /* and no tenant fill, so steps 2 and 3.5 read nothing */
#else
            we_out_set(out, WE_STEP_EXEMPT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_HOLD_HARMLESS);
            return 1;                            /* the control: the floor's exemption ends every step */
#endif
        }
    }
    if (req->acme_exempt != 0u) {
        we_out_set(out, WE_STEP_EXEMPT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_ACME);
        return 1;
    }
    if (bind == NULL) {
        return 0;
    }
    /* step 2: the tenant allow list while the plane is fresh; the entry is filled whatever the programs */
    if (fs->state[WE_TENANT_IX] == WE_ST_NONE) {
        we_eval_fill(ctx->view[WE_TENANT_IX].m, fs, WE_TENANT_IX, bind + WE_TENANT_IX, now_ms, out, 0u);
        __asm__ __volatile__("" ::: "memory");
        fs = (we_memo_slot_t *)out->sc.s;     /* the fill parked its slot: only `out` crossed it */
    }
    st = fs->state[WE_TENANT_IX];
    out->marks = (uint8_t)(out->marks | (st == WE_ST_REVOKED ? WE_MARK_TENANT_REVOKED : 0u));
    if (st == WE_ST_FRESH_HIT && (fs->e[WE_TENANT_IX].block[0] & WE_MF_TENANT_ALLOW) != 0u) {
        we_out_set(out, WE_STEP_TENANT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_TENANT);
        return 1;
    }
    return 0;
}

/* Step 3.5: a stale tenant plane's allow entries, after the floor, within the 48-hour grace. */
WE_HOT_INLINE int we_eval_stale_tenant(const we_eval_ctx_t *ctx, we_verdict_t *out)
{
    const we_memo_slot_t *fs = &ctx->slot[0];

    if (fs->state[WE_TENANT_IX] == WE_ST_STALE_HIT && fs->e[WE_TENANT_IX].lapsed == 0u
            && (fs->e[WE_TENANT_IX].block[0] & WE_MF_TENANT_ALLOW) != 0u) {
        we_out_set(out, WE_STEP_STALE_TENANT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_TENANT);
        return 1;
    }
    return 0;
}

/*
 * The whole decision. Either program may be NULL (a context with no lines, a test); the
 * hold-harmless view is the configuration's, built once by we_program_place() from the floor block,
 * which every configuration has. The verdict is written to *out; nothing else but *ctx is written.
 */
WE_HOT_INLINE void we_decide(const we_program_t *floor, const we_ctx_conf_t *floor_conf,
                             const we_program_t *ctx_program, const we_ctx_conf_t *ctx_conf,
                             const we_hh_view_t *hh, const we_request_t *req, we_eval_ctx_t *ctx,
                             uint64_t now_ms, we_verdict_t *out)
{
    const we_binding_t *bind;
    we_memo_slot_t *ss;
    uint32_t mode;

    we_verdict_clear(out);
    bind = hh != NULL ? hh->bindings
         : floor != NULL ? we_prog_bindings(floor)
         : ctx_program != NULL ? we_prog_bindings(ctx_program) : (const we_binding_t *)NULL;
    /* every operand parked once: each step below reads them back, so only `out` crosses a step (D9) */
    out->sc.floor = floor;
    out->sc.floor_conf = floor_conf;
    out->sc.ctx_prog = ctx_program;
    out->sc.ctx_conf = ctx_conf;
    out->sc.hh = hh;
    out->sc.req = req;
    out->sc.ectx = ctx;
    out->sc.dbind = bind;
    out->sc.now_ms = now_ms;
    if (we_eval_prestage(hh, bind, req, ctx, now_ms, out)) {
        return;
    }
    __asm__ __volatile__("" ::: "memory");
    /*
     * The evaluation-site record, here and not at the function's head: placed before the pre-stage it
     * moved gcc 13.3's schedule of the module's inlined copy by two executed instructions a request
     * (every module row of the cachegrind gate read +2.00 on gcc, none on clang, on the first run that
     * measured it); after this barrier every row reads what it read without the record, on both compilers.
     */
    WE_EVAL_SITE();
    req = (const we_request_t *)out->sc.req;
    ctx = (we_eval_ctx_t *)out->sc.ectx;
    {
        /* the server's slot ALIASES the floor's when it names the floor's address, or none */
        uint64_t hi, lo;
        uint8_t fam;

        if (we_server_canon(req, &ctx->slot[0], &hi, &lo, &fam)) {
            ss = &ctx->slot[0];
        } else {
            ss = &ctx->slot[1];
            we_slot_key(ss, hi, lo, fam);
        }
    }
    out->sc.ss = ss;
    if (out->sc.dbind == NULL) {
        we_out_set(out, WE_STEP_CONTEXT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_NONE);
        return;
    }
    /* step 3: the floor, on the floor address's slot */
    floor = (const we_program_t *)out->sc.floor;
    floor_conf = (const we_ctx_conf_t *)out->sc.floor_conf;
    mode = we_conf_mode(floor_conf);
    /*
     * Whether a step decided is read back from the verdict (a decision sets its step, which
     * we_verdict_clear zeroed), not carried as the run's return value: carried, it is one more value
     * live across the whole program, and that is the stack slot the gate refuses (POLICY.md D9).
     */
    if (floor != NULL && mode != WE_MODE_OFF) {
        (void)we_eval_run(floor, mode, we_conf_inferred(floor_conf), 0u, ctx, &ctx->slot[0], 0u, out->sc.dbind,
                          out->sc.now_ms, out);
        if (*(const volatile uint8_t *)&out->step != 0u) {
            return;
        }
    }
    __asm__ __volatile__("" ::: "memory");
    ctx = (we_eval_ctx_t *)out->sc.ectx;
    /* step 3.5, then step 4: the context's program on the server address's slot */
    if (we_eval_stale_tenant(ctx, out)) {
        return;
    }
    ctx_program = (const we_program_t *)out->sc.ctx_prog;
    ctx_conf = (const we_ctx_conf_t *)out->sc.ctx_conf;
    mode = we_conf_mode(ctx_conf);
    ss = (we_memo_slot_t *)out->sc.ss;
#ifdef WE_TEST_HH_SERVER_EXEMPT
    if (ss != &ctx->slot[0] && out->sc.hh != NULL) {
        /* the control: the hold-harmless lookup on the server's address, the exemption a header reaches */
        const we_hh_view_t *hv = (const we_hh_view_t *)out->sc.hh;
        uint64_t kh;
        uint32_t i;

        __builtin_memcpy(&kh, ss->addr, 8);
        i = ss->family == 4u ? we_find4(&hv->map, __builtin_bswap32((uint32_t)kh)) : we_find6(&hv->map, ss->addr);
        if (i != WE_NO_RANGE) {
            we_out_set(out, WE_STEP_EXEMPT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_HOLD_HARMLESS);
            return;
        }
    }
#endif
    if (ctx_program != NULL && mode != WE_MODE_OFF) {
        (void)we_eval_run(ctx_program, mode, we_conf_inferred(ctx_conf), 1u, ctx, ss,
                          (uint32_t)(ss - &ctx->slot[0]), out->sc.dbind, out->sc.now_ms, out);
        if (*(const volatile uint8_t *)&out->step != 0u) {
            return;
        }
    }
    we_out_set(out, WE_STEP_CONTEXT, WE_ACT_ALLOW, WE_VPROG_NONE, WE_WHY_NONE);
}

/*
 * A later fill in its own handler invocation (a log-phase variable on a plane the evaluator never
 * touched): the module re-takes we_current() for that plane into the view first, and the entry
 * records the generation that produced it. `which` is 0 for the floor's slot, 1 for the server's.
 */
WE_HOT_INLINE void we_eval_lazy_fill(we_eval_ctx_t *ctx, const we_hh_view_t *hh, uint32_t which,
                                     uint32_t plane_id, uint64_t now_ms, we_verdict_t *out)
{
    we_memo_slot_t *s = &ctx->slot[which & 1u];
    uint32_t p = (plane_id - 1u) & 7u;

    if (hh == NULL || s->key_valid == 0u || s->state[p] != WE_ST_NONE) {
        return;
    }
    we_eval_fill(ctx->view[p].m, s, p, hh->bindings + p, now_ms, out, which & 1u);
}

#ifdef __cplusplus
}
#endif
#endif /* WE_EVAL_H */
