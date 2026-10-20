/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * What a record copy that is NOT fixed-width looks like to the gate. The evaluator's memo fill copies
 * the family's attribute block with constant-size moves (a u32, u32, u16 for IPv4 routing, a u64 and
 * a u16 for IPv6, and so on), which every compiler inlines; this copies the record by a length only the
 * plane knows, which no compiler can inline as moves. Measured, gcc 13.3 and clang 18.1: a call to
 * memcpy (a relocation) at every level on aarch64 and on clang for x86_64, and on gcc for x86_64 a call
 * at -O, -O2 and -O3 but an inline `rep movsb` at -Os, which is no call and no relocation, so only the
 * string check sees it there. ctl-eval-mops.c is the same copy where aarch64 inlines it.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc|string
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
