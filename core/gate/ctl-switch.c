/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * A dense switch on a value the lookup produced, which lowers to a jump table: a relocation against .rodata and an
 * indirect branch through it. That is why the dispatch on the index kind is a branch chain. It has
 * 24 cases because clang 18 on aarch64 lowered a 12-case switch to a compare tree at -O and -Os
 * (measured), and a control must carry its hazard at every level the gate checks.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 */
#include "whisper_edge.h"

__attribute__((noinline)) uint32_t hpk(const we_map_t *m, uint32_t a)
{
    uint32_t r = we_find4(m, a);
    switch ((r ^ a) & 31u) {
    case 0:  return r;
    case 1:  return r + 3u;
    case 2:  return r ^ 7u;
    case 3:  return r * 5u;
    case 4:  return r - 9u;
    case 5:  return r | 64u;
    case 6:  return r << 2;
    case 7:  return r >> 1;
    case 8:  return r + 11u;
    case 9:  return r ^ 0x55u;
    case 10: return r * 13u;
    case 11: return r - 17u;
    case 12: return r + 19u;
    case 13: return r ^ 0x1234u;
    case 14: return r * 29u;
    case 15: return r - 31u;
    case 16: return r | 0x400u;
    case 17: return r << 5;
    case 18: return r >> 3;
    case 19: return r + 37u;
    case 20: return r ^ 0xabcdu;
    case 21: return r * 41u;
    case 22: return r - 43u;
    case 23: return r | 0x8000u;
    default: return 0u;
    }
}
