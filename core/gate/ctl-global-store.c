/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A store to a global counter, the edit most likely to be made to a hot path. Under -fPIC it is a GOT
 * or PC-relative relocation against the global.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 */
#include "whisper_edge.h"

unsigned long gate_hits;

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    uint32_t r = we_find4(m, a);
    gate_hits += r != 0u;
    return r;
}
