/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A per-rule counter incremented INSIDE the evaluator. The evaluator increments nothing: the module
 * counts the rules that fired after the verdict, into a shard with one writer, so the request path
 * pays no atomic. This is the edit that would undo that, built with -march=armv8.1-a on aarch64 so it
 * is one inlined LSE `ldadd` with no relocation and no call: only the atomic class pattern can see it
 * (at the default -march it is an outline-atomics call, which ctl-atomic.c already covers). On x86 it
 * is a lock-prefixed add.
 *
 * @expect aarch64 class
 * @expect x86_64 lock
 * @cflags aarch64 -march=armv8.1-a
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, uint64_t *counters, uint32_t rule)
{
    uint32_t r = we_find4(m, a);

    if (r != WE_NO_RANGE) {
        __atomic_fetch_add(&counters[rule & 255u], 1u, __ATOMIC_RELAXED);
    }
    return r;
}
