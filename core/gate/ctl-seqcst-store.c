/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A seq_cst store into the CALLER's context: no lock prefix, no relocation, no call. x86 compiles it
 * to `xchgl %ecx, (%rdx)`, the memory operand AFTER the comma, which the earlier `xchg [^,]*\(`
 * passed; aarch64 compiles it to stlr, which no mnemonic list before the class pattern banned.
 *
 * @expect aarch64 class
 * @expect x86_64 xchg
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned *ctx)
{
    uint32_t r = we_find4(m, a);
    __atomic_store_n(ctx, r, __ATOMIC_SEQ_CST);
    return r;
}
