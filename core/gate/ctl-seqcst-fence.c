/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A seq_cst fence after a plain store to the caller's context: `dmb ish` on aarch64, neither form of
 * which carries a relocation on x86 either. clang emits `mfence` on x86 at every level; gcc 13 emits
 * `mfence` at -Os and `lock orq $0x0,(%rsp)` at -O, -O2 and -O3 (measured), so on x86 either check
 * is the right one and the expectation names both.
 *
 * @expect aarch64 barrier
 * @expect x86_64 fence|lock
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned *ctx)
{
    uint32_t r = we_find4(m, a);
    *ctx = r;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return r;
}
