/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * ctl-eval-memcpy.c's variable-length record copy built with -march=armv8.8-a+mops, where gcc 13.3 and
 * clang 18.1 both inline it as the FEAT_MOPS triple cpyfp / cpyfm / cpyfe (measured): no call, no
 * relocation, no branch, nothing the relocation or branch checks can see. The string check exists for
 * this, and for x86's `rep movs` family: a fixed-width copy never compiles to a string instruction, so
 * one in a hot wrapper means a copy whose length the data decides. On x86 the flag does not apply and
 * it is ctl-eval-memcpy.c again.
 *
 * @expect aarch64 string
 * @expect x86_64 reloc|string
 * @cflags aarch64 -march=armv8.8-a+mops
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a, uint8_t *entry)
{
    uint32_t r = we_find4(m, a);

    if (r != WE_NO_RANGE) {
        memcpy(entry, m->f4.records + (size_t)r * m->f4.stride, m->f4.stride);
    }
    return r;
}
