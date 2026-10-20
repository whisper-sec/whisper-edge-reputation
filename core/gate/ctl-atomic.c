/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A relaxed atomic add, at each compiler's default -march. On aarch64 gcc and clang both emit an
 * outline-atomics helper call (bl __aarch64_ldadd4_relax), so a relocation; on x86 it is a
 * lock-prefixed add. ctl-atomic-lse.c is the same edit built where the relocation check is blind.
 *
 * @expect aarch64 reloc
 * @expect x86_64 lock
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned *ctx)
{
    uint32_t r = we_find4(m, a);
    __atomic_fetch_add(ctx, r, __ATOMIC_RELAXED);
    return r;
}
