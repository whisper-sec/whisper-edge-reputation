/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * Dispatch through a function pointer in the plane, the design FORMAT.md does not use for the two index
 * kinds. At -O2 and above it is an indirect TAIL call (`br x2`, `jmpq *%rax`), which the earlier
 * pattern missed on every toolchain; at -O it can be an indirect call (`blr`, `callq *`). There is no
 * relocation either way, so the branch pattern must catch it.
 *
 * @expect aarch64 branch
 * @expect x86_64 branch
 */
#include "whisper_edge.h"

/* a per-plane find resolved at publish time: the dispatch the format replaced with a kind byte */
typedef struct { uint32_t (*find)(const we_map_t *, uint32_t); } gate_dispatch_t;

__attribute__((noinline)) uint32_t hpk(const gate_dispatch_t *d, const we_map_t *m, uint32_t a)
{
    return d->find(m, a);
}
