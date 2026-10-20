/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A call out of the hot path. The callee is an undefined symbol, so .rela.text.hpk exists on every
 * target and the relocation check is the one that must catch it.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 */
#include "whisper_edge.h"

extern void gate_ext(void);

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    uint32_t r = we_find4(m, a);
    if (r == 0u) {
        gate_ext();
    }
    return r;
}
