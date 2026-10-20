/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The LSE min/max family (ldumax under -march=armv8.1-a), which a list of the add, clear, eor and set
 * mnemonics missed. gcc 13 has no __atomic_fetch_max, so on gcc this control stops at the #error below
 * and the gate reports it NOT APPLICABLE there: the min/max family is proven on clang only. On x86 it
 * is a lock cmpxchg loop.
 *
 * @expect aarch64 class
 * @expect x86_64 lock
 * @cflags aarch64 -march=armv8.1-a
 */
#include "whisper_edge.h"

#if !defined(__has_builtin) || !__has_builtin(__atomic_fetch_max)
#error "WE_GATE_NOT_APPLICABLE: this compiler has no __atomic_fetch_max"
#endif

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned *ctx)
{
    uint32_t r = we_find4(m, a);
    __atomic_fetch_max(ctx, r, __ATOMIC_RELAXED);
    return r;
}
