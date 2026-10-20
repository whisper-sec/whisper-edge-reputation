/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The hold-harmless table compiled in as `static const`, the shortcut the design refuses: the table
 * lives in the configuration's floor block and the evaluator reaches it through the view pointer the
 * caller passes, so no evaluator code references .rodata. A compiled-in table is a PC-relative
 * relocation against .rodata from the wrapper's own section, at every level on both architectures
 * (measured with gcc 13.3 and clang 18.1). The search is the fixed-iteration halving the real lookup
 * uses, over 64 entries indexed by the probe, so no compiler can fold the table into immediates.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 */
#include <stdint.h>

static const uint32_t gate_hh_start[64] = {
    0x01000000u, 0x02000000u, 0x05000000u, 0x08080800u, 0x0a000000u, 0x0b000000u, 0x0c000000u, 0x0d000000u,
    0x14000000u, 0x17000000u, 0x18000000u, 0x1a000000u, 0x1f000000u, 0x22000000u, 0x26000000u, 0x2b000000u,
    0x2e000000u, 0x30000000u, 0x34000000u, 0x36000000u, 0x3a000000u, 0x40000000u, 0x42000000u, 0x45000000u,
    0x48000000u, 0x4a000000u, 0x4d000000u, 0x50000000u, 0x55000000u, 0x58000000u, 0x5b000000u, 0x60000000u,
    0x64400000u, 0x68000000u, 0x6c000000u, 0x70000000u, 0x74000000u, 0x78000000u, 0x7c000000u, 0x80000000u,
    0x84000000u, 0x88000000u, 0x8c000000u, 0x90000000u, 0x94000000u, 0x98000000u, 0x9c000000u, 0xa0000000u,
    0xa9fe0000u, 0xac100000u, 0xb0000000u, 0xb4000000u, 0xb8000000u, 0xbc000000u, 0xc0000000u, 0xc0a80000u,
    0xc6120000u, 0xcb007100u, 0xd0000000u, 0xd8000000u, 0xe0000000u, 0xe8000000u, 0xf0000000u, 0xf8000000u,
};

__attribute__((noinline)) uint32_t hpk(uint32_t a)
{
    uint32_t lo = 0, h;

    for (h = 32; h != 0; h >>= 1) {
        lo += (gate_hh_start[lo + h - 1u] <= a) ? h : 0u;
    }
    return lo;
}
