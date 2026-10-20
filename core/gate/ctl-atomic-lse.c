/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The relaxed add of ctl-atomic.c built with -march=armv8.1-a, where it is ONE LSE instruction
 * (ldadd) with no relocation and no call. Measured: the relocation check alone does not see it, so
 * the atomic class pattern must. On x86 the flag does not apply and it is the lock form again.
 *
 * @expect aarch64 class
 * @expect x86_64 lock
 * @cflags aarch64 -march=armv8.1-a
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned *ctx)
{
    uint32_t r = we_find4(m, a);
    __atomic_fetch_add(ctx, r, __ATOMIC_RELAXED);
    return r;
}
