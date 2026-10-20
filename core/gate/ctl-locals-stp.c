/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * Locals in a frame the prologue allocates with a PRE-INDEX store, `stp x29, x30, [sp, #-48]!`, which
 * is how gcc lays out every frame under the frame-pointer flags Ubuntu builds modules with
 * (-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer): measured at -O1, -O2, -O3 and -Os on gcc 13.
 * The locals check once read that immediate with its sign, so the allocation came out negative and the
 * locals at zero, and an evaluator wrapper with a 256-byte frame of argument spills read clean on
 * aarch64 while x86 caught the same code's `sub $0x70,%rsp`. clang allocates with `sub sp` and an
 * offset store here, which the check already read; the control holds both prologue forms.
 *
 * @expect aarch64 locals
 * @expect x86_64 locals
 * @cflags aarch64 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    volatile uint8_t v[32];
    v[a & 31u] = (uint8_t)a;
    return we_find4(m, a) + v[(a >> 5) & 31u];
}
