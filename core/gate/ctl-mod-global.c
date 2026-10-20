/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The modules' decision (hp_mod.c's hpmod) with one planted defect: the counter array reached through a
 * global, a relocation against it.
 * The decision's own acquire loads are allowed here as they are for hpmod, so the check named below,
 * and not those loads, is what refuses it.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 * @allow acquire-views
 */
#define WE_MOD_CONTROL_BUILD 1
#define WE_MOD_TEST_GLOBAL_SHARD 1
#include "we_module.h"

uint64_t we_mod_test_shard[1024];

__attribute__((noinline)) void hpk(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s, uint64_t *shard,
                                   const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}
