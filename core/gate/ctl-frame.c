/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A 544-byte frame (68 eight-byte slots), over every wrapper's stack bound including the evaluator's
 * 256 bytes: -Wstack-usage on gcc and -Wframe-larger-than on clang must refuse it at compile time.
 *
 * @expect aarch64 stack
 * @expect x86_64 stack
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    volatile uint64_t v[68];
    v[a % 68u] = a;
    return we_find4(m, a) + (uint32_t)v[(a >> 7) % 68u];
}
