/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The modules' decision (hp_mod.c's hpmod) with one planted defect: the locked increment of ctl-mod-lock.c
 * built with -march=armv8.1-a, where it is one LSE instruction the relocation check is blind to, so the
 * atomic class must refuse it.
 * The decision's own acquire loads are allowed here as they are for hpmod, so the check named below,
 * and not those loads, is what refuses it.
 *
 * @expect aarch64 class
 * @expect x86_64 lock
 * @cflags aarch64 -march=armv8.1-a
 * @allow acquire-views
 */
#define WE_MOD_CONTROL_BUILD 1
#define WE_MOD_TEST_LOCKED_COUNT 1
#include "we_module.h"

__attribute__((noinline)) void hpk(const we_mod_cfg_t *c, const we_mod_ctx_t *x, we_mod_scratch_t *s, uint64_t *shard,
                                   const we_mod_req_t *req, uint64_t now_ms)
{
    we_mod_decide(c, x, s, shard, req, now_ms);
}
