/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * NEGATIVE CONTROL for hotpath-gate.sh, which must refuse it by the named check.
 *
 * An EQUALITY CHAIN on the opcode: `if (op == 0) ... else if (op == 1) ...`. It contains no `switch`,
 * and it is still the form gcc's if-to-switch pass and LLVM's SimplifyCFG fold into a switch and then
 * into a .rodata jump table, which is why the real evaluator encodes each opcode as one bit and tests
 * `op & OP_X`: tests on distinct bits are not an equality chain on one variable and neither pass can
 * fold them. This control proves the gate would see the table if the dispatch were ever rewritten into
 * this shape.
 *
 * Whether the fold happens is the compiler's decision, per toolchain and level, so this control is
 * marked @fold: a level at which no table was formed must build CLEAN (nothing for the gate to
 * refuse, and nothing it refuses), is reported n/a, and the control must still be refused at some
 * level on some toolchain of each architecture. Measured with gcc 13.3 and clang 18.1: gcc folds it
 * at -O, -O2, -Os and -O3 on both architectures; clang folds it at every level on x86_64 and at none
 * on aarch64, where it keeps a compare tree.
 *
 * @expect aarch64 reloc
 * @expect x86_64 reloc
 * @fold
 */
#include <stdint.h>

typedef struct { uint16_t op; uint8_t plane; uint8_t off; uint32_t imm; } gate_ins_t;

__attribute__((noinline)) uint32_t hpk(const gate_ins_t *ip, uint32_t n, const uint8_t *memo, uint64_t *tf)
{
    uint64_t t = 0, f = 0;
    uint32_t i;

    for (i = 0; i < n; i++) {
        uint16_t op = ip[i].op;
        uint8_t v = memo[ip[i].plane * 32u + ip[i].off];
        uint32_t imm = ip[i].imm;

        if (op == 0) { t = (t << 1) | (v != 0); f = (f << 1) | (v == 0); }
        else if (op == 1) { t = (t << 1) | ((v & 15u) >= imm); f = (f << 1) | ((v & 15u) < imm); }
        else if (op == 2) { t = (t << 1) | (v == imm); f = (f << 1) | (v != imm); }
        else if (op == 3) { t = (t << 1) | ((imm >> (v & 31u)) & 1u); f = (f << 1) | (~(imm >> (v & 31u)) & 1u); }
        else if (op == 4) { uint64_t x = t; t = (t & ~1ull) | (f & 1u); f = (f & ~1ull) | (x & 1u); }
        else if (op == 5) { t = (t >> 1) & (t | ~1ull); f = (f >> 1) | (f & 1u); }
        else if (op == 6) { t = (t >> 1) | (t & 1u); f = (f >> 1) & (f | ~1ull); }
        else if (op == 7) { if (f & 1u) { i += imm; } }
        else if (op == 8) { if (t & 1u) { i += imm; } }
        else if (op == 9) { tf[0] = t; tf[1] = f; return i; }
        else if (op == 10) { t = t << 1; f = (f << 1) | 1u; }
        else if (op == 11) { t = (t << 1) | 1u; f = f << 1; }
        else { break; }
    }
    tf[0] = t;
    tf[1] = f;
    return n;
}
