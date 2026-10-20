/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A 128-bit acquire load and release store under -march=armv8.4-a+rcpc3+lse128, where clang 18, 19
 * and 20 emit the RCpc3 pair instructions ldiapp and stilp at every level: no relocation, no fence, no
 * call, so only the ldiap|stil group of the class pattern sees them, and clang is held to class. gcc 14
 * accepts the flags but emits no pair: it lowers both atomics to __atomic_load_16 and
 * __atomic_store_16 calls at every level, so gcc is held to reloc. gcc 13 does not know rcpc3 and the
 * gate reports the control NOT APPLICABLE there. armv8.4-a rather than armv9.4-a: at armv9.4-a gcc 14
 * also emits the CSSC `umin`, which the assembler of Ubuntu 24.04 (binutils 2.42) cannot assemble, so
 * the control failed to COMPILE and proved nothing. x86 has no such instruction: a 16-byte atomic at the
 * baseline -march is a libatomic call, which the relocation check catches.
 *
 * @expect clang-aarch64 class
 * @expect gcc-aarch64 reloc
 * @expect aarch64 class
 * @expect x86_64 reloc
 * @cflags aarch64 -march=armv8.4-a+rcpc3+lse128
 */
#include "whisper_edge.h"

/* clang warns that a 16-byte atomic is not lock-free on baseline x86-64; the control is that call */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Watomic-alignment"
#endif

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, unsigned __int128 *ctx)
{
    uint32_t r = we_find4(m, a);
    unsigned __int128 v = __atomic_load_n(ctx, __ATOMIC_ACQUIRE);
    __atomic_store_n(ctx + 1, v + r, __ATOMIC_RELEASE);
    return r;
}
