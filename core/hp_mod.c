/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * hp_mod.c - the modules' decision function's wrapper, which hotpath-gate.sh disassembles beside the
 * evaluator's (hp_eval.c). The same claim, for the same classes: no call, no relocation beyond the
 * expected table, no atomic beyond the acquire loads of the view pointers (on aarch64 between one and
 * eight, `acquire-views`), no fence, no local on the stack beyond exactly the spills the gate's
 * expected-locals table holds (we_module.h's opening comment says which, and locals-claims.sh holds that
 * sentence to the table), a frame under STACK_MAX_EVAL. Programs,
 * handles, the scratch and the shard are all passed by pointer, so the wrapper is generic code: what a
 * real configuration does per request is the trace build's and the cachegrind slots' to show.
 */
#include "we_module.h"

#ifdef WE_TRACE
#error "the hot-path gate must never see a traced build"
#endif

/* the whole module request path: views, the decision, the counts */
__attribute__((noinline)) void hpmod(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s,
                                     uint64_t *shard, const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}
