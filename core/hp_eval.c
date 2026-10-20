/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * hp_eval.c - the policy evaluator's wrappers, which hotpath-gate.sh disassembles beside hp.c's.
 *
 * WHAT THE GATE PROVES ABOUT THESE, EXACTLY, and nothing broader: no call, no relocation (so no
 * global, GOT, PLT, jump table or outline atomic), no atomic or fence instruction, no string
 * instruction, no local on the stack, and a frame under STACK_MAX_EVAL (256 bytes). It cannot see a
 * store THROUGH a pointer: the plane buffers and the program block are ordinary memory. So "no store
 * outside *ctx and *out" is proven by two things together: this gate for the classes it can see, and
 * the policy test and the differential running with the program block, the hold-harmless view and
 * every plane buffer under mprotect(PROT_READ), where a stray store faults.
 *
 * The gate disassembles GENERIC code. The program is runtime data, so "three planes referenced" and "a
 * 64-operation rule" are properties the cachegrind slots and the trace build prove, not this file.
 *
 * A separate translation unit from hp.c, so the lookup wrappers' gate does not depend on the
 * evaluator's header: until we_eval.h is in the tree, hotpath-gate.sh reports every row below DARK by
 * name, and the rows light up, with no edit here, the moment the header lands. No row carries the
 * locals-ok allowance: if a toolchain spills, the scratch moves into *ctx first (POLICY.md decision
 * D9), and the gate refuses an evaluator row that asks for the allowance.
 *
 * THE WRAPPERS, each over the evaluator's own entry point:
 *   hpeval      we_decide(): the whole request, steps 1 to 4, both programs passed by pointer
 *   hpeval_ops  we_eval_run(): one program's instruction loop against one memo slot
 *   hpfill4     we_eval_fill() for an IPv4 key, on a format-2 plane
 *   hpfill6w    we_eval_fill() for an IPv6 key at 64 bits (the routing and registry planes)
 *   hpfill6     we_eval_fill() for an IPv6 key at 128 bits (the membership planes)
 *   hpfill1     we_eval_fill() for the format-1 reputation plane, either family
 *   hpfloor     we_eval_prestage(): steps 1 to 3.5, hold-harmless, ACME and the tenant pre-stage
 *   hpaddr      we_addr_canon(): ::ffff:0:0/96 unmapped to IPv4, nothing else
 * The fill is one function that branches on the key width and the schema; each fill wrapper pins its
 * case with __builtin_unreachable(), as hp.c's radix and rank wrappers pin theirs. Whether a compiler
 * USES the pin is its own business, so the four fill rows are kept and what they show is stated as
 * measured (address-normalised bodies compared, gcc 13 and clang 18, against the evaluator):
 *   clang, both architectures, every level: three distinct bodies, hpfill4, hpfill6w = hpfill6, hpfill1
 *   gcc, both architectures, -O2, -Os and -O3: one body; all four rows hold the same code
 *   gcc -O: aarch64 two bodies (hpfill4 = hpfill1, hpfill6w = hpfill6), x86_64 one
 * hpfill6w and hpfill6 are the same code under every toolchain and level: the IPv6 key width is not
 * specialised by any of them. So under gcc each fill row bounds the WHOLE fill, every width at once,
 * and only clang's rows are per width; their bands in hotpath-gate.sh are read that way.
 */
#include "we_eval.h"

#ifdef WE_TRACE
#error "the hot-path gate must never see a traced build"
#endif

/* the whole request: steps 1 to 4 over a floor program and a context program passed by pointer */
__attribute__((noinline)) void hpeval(const we_program_t *floor, const we_ctx_conf_t *floor_conf,
                                      const we_program_t *prog, const we_ctx_conf_t *ctx_conf,
                                      const we_hh_view_t *hh, const we_request_t *req, we_eval_ctx_t *ctx,
                                      uint64_t now_ms, we_verdict_t *out)
{
    we_decide(floor, floor_conf, prog, ctx_conf, hh, req, ctx, now_ms, out);
}

/* the instruction loop alone, over one program and one memo slot */
__attribute__((noinline)) int hpeval_ops(const we_program_t *p, uint32_t mode, uint32_t allow_inf, uint32_t which,
                                         const we_eval_ctx_t *ctx, we_memo_slot_t *s, uint32_t si,
                                         const we_binding_t *bind, uint64_t now_ms, we_verdict_t *out)
{
    return we_eval_run(p, mode, allow_inf, which, ctx, s, si, bind, now_ms, out);
}

/* the memo fill, one per key width and the format-1 case, each proven copy-by-moves by the undef and
 * string checks */
__attribute__((noinline)) void hpfill4(const we_map_t *m, we_memo_slot_t *s, uint32_t p, const we_binding_t *b,
                                       uint64_t now_ms, we_verdict_t *out, uint32_t si)
{
    if (s->family != 4u || b->schema_id == WE_SCHEMA_FORMAT1) {
        __builtin_unreachable();
    }
    we_eval_fill(m, s, p, b, now_ms, out, si);
}

__attribute__((noinline)) void hpfill6w(const we_map_t *m, we_memo_slot_t *s, uint32_t p, const we_binding_t *b,
                                        uint64_t now_ms, we_verdict_t *out, uint32_t si)
{
    if (s->family == 4u || b->key6 != 8u || b->schema_id == WE_SCHEMA_FORMAT1) {
        __builtin_unreachable();
    }
    we_eval_fill(m, s, p, b, now_ms, out, si);
}

__attribute__((noinline)) void hpfill6(const we_map_t *m, we_memo_slot_t *s, uint32_t p, const we_binding_t *b,
                                       uint64_t now_ms, we_verdict_t *out, uint32_t si)
{
    if (s->family == 4u || b->key6 != 16u || b->schema_id == WE_SCHEMA_FORMAT1) {
        __builtin_unreachable();
    }
    we_eval_fill(m, s, p, b, now_ms, out, si);
}

__attribute__((noinline)) void hpfill1(const we_map_t *m, we_memo_slot_t *s, uint32_t p, const we_binding_t *b,
                                       uint64_t now_ms, we_verdict_t *out, uint32_t si)
{
    if (b->schema_id != WE_SCHEMA_FORMAT1) {
        __builtin_unreachable();
    }
    we_eval_fill(m, s, p, b, now_ms, out, si);
}

/* steps 1 to 3.5 alone: hold-harmless, ACME, the tenant pre-stage */
__attribute__((noinline)) int hpfloor(const we_hh_view_t *hh, const we_binding_t *bind, const we_request_t *req,
                                      we_eval_ctx_t *ctx, uint64_t now_ms, we_verdict_t *out)
{
    return we_eval_prestage(hh, bind, req, ctx, now_ms, out);
}

/* the address canonicalisation: ::ffff:0:0/96 unmapped to IPv4, nothing else */
__attribute__((noinline)) void hpaddr(const uint8_t in[16], int in_family, we_addr_t *out)
{
    we_addr_canon(in, in_family, out);
}
