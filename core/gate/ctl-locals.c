/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * An 8-byte local array, far under every byte bound (the lookups' 64, the evaluator's 256), so only the
 * locals check can see it. volatile keeps it in memory. On x86_64 a leaf keeps it in the red zone below
 * %rsp without moving %rsp, which is why the check reads red-zone offsets and not only `sub %rsp`; on
 * aarch64 it is a `sub sp, sp, #16` that saves no register.
 *
 * @expect aarch64 locals
 * @expect x86_64 locals
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    volatile uint8_t v[8];
    v[a & 7u] = (uint8_t)a;
    return we_find4(m, a) + v[(a >> 3) & 7u];
}
