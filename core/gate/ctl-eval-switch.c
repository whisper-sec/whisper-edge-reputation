/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * The policy evaluator's dispatch written the way it must NOT be: a `switch` on the opcode inside an
 * evaluator-shaped loop (an 8-byte instruction, a K3 stack of two 64-bit words, a memo read per atom).
 * A dense switch lowers to a jump table, which is a relocation against .rodata and an indirect branch
 * through it. That is why the real evaluator tests one-hot opcode bits in a chain of `if`s. 24 cases,
 * as ctl-switch.c has, because a shorter switch is lowered to a compare tree at some levels on some
 * toolchains and a control must carry its hazard at every level the gate checks. Measured: a table at
 * every level on gcc and clang, both architectures.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 */
#include <stdint.h>

typedef struct { uint16_t op; uint8_t plane; uint8_t off; uint32_t imm; } gate_ins_t;

__attribute__((noinline)) uint32_t hpk(const gate_ins_t *ip, uint32_t n, const uint8_t *memo, uint64_t *tf)
{
    uint64_t t = 0, f = 0;
    uint32_t i;

    for (i = 0; i < n; i++) {
        uint8_t v = memo[ip[i].plane * 32u + ip[i].off];
        uint32_t imm = ip[i].imm;

        switch (ip[i].op & 0xffu) {
        case 0:  t = (t << 1) | (v != 0); f = (f << 1) | (v == 0); break;
        case 1:  t = (t << 1) | ((v & 15u) >= imm); f = (f << 1) | ((v & 15u) < imm); break;
        case 2:  t = (t << 1) | ((v & 15u) > imm); f = (f << 1) | ((v & 15u) <= imm); break;
        case 3:  t = (t << 1) | ((v & 15u) <= imm); f = (f << 1) | ((v & 15u) > imm); break;
        case 4:  t = (t << 1) | ((v & 15u) < imm); f = (f << 1) | ((v & 15u) >= imm); break;
        case 5:  t = (t << 1) | ((v & 15u) == imm); f = (f << 1) | ((v & 15u) != imm); break;
        case 6:  t = (t << 1) | (v == imm); f = (f << 1) | (v != imm); break;
        case 7:  t = (t << 1) | ((imm >> (v & 31u)) & 1u); f = (f << 1) | (~(imm >> (v & 31u)) & 1u); break;
        case 8:  { uint64_t x = t; t = (t & ~1ull) | (f & 1u); f = (f & ~1ull) | (x & 1u); } break;
        case 9:  t = (t >> 1) & (t | ~1ull); f = (f >> 1) | (f & 1u); break;
        case 10: t = (t >> 1) | (t & 1u); f = (f >> 1) & (f | ~1ull); break;
        case 11: if (f & 1u) { i += imm; } break;
        case 12: if (t & 1u) { i += imm; } break;
        case 13: tf[0] = t; tf[1] = f; return i;
        case 14: t = t << 1; f = (f << 1) | 1u; break;
        case 15: t = (t << 1) | 1u; f = f << 1; break;
        case 16: t ^= imm; break;
        case 17: f ^= imm; break;
        case 18: t = (t << 2) | (v & 3u); break;
        case 19: f = (f << 2) | (v & 3u); break;
        case 20: t += v; break;
        case 21: f += v; break;
        case 22: t |= (uint64_t)imm << 32; break;
        case 23: f |= (uint64_t)imm << 32; break;
        default: tf[0] = t; tf[1] = f; return n;
        }
    }
    tf[0] = t;
    tf[1] = f;
    return n;
}
