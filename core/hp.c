/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * hp.c - the hot-path wrappers hotpath-gate.sh disassembles.
 *
 * __attribute__((noinline)) so the force-inlined lookup is inlined INTO these and each wrapper
 * survives as a symbol with its own section (-ffunction-sections), which is what lets the gate ask
 * "does THIS function carry a relocation" instead of asking it of the whole object, where
 * .rela.eh_frame makes the answer always yes.
 *
 * The publication read is its own wrapper. we_current() is one acquire load of the handle's current
 * map, and on aarch64 that is `ldar`, which the atomic class pattern matches by design (it is the
 * acquire form the pattern exists to catch anywhere else). So hpcur is checked for exactly that one
 * load and nothing more, and every lookup wrapper takes the map pointer it would have been handed, and
 * is checked with no allowance at all. A module's request path is the composition of the two, both
 * force-inlined.
 */
#include "whisper_edge.h"

#ifdef WE_TRACE
#error "the hot-path gate must never see a traced build"
#endif

__attribute__((noinline)) const we_map_t *hpcur(we_handle_t *h)
{
    return we_current(h);
}

__attribute__((noinline)) uint8_t hp4(const we_map_t *m, uint32_t a)
{
    return we_lookup4(m, a);
}

__attribute__((noinline)) uint8_t hp6(const we_map_t *m, const uint8_t *a)
{
    return we_lookup6(m, a);
}

__attribute__((noinline)) int hpdeny(const we_map_t *m, uint32_t a, uint8_t thr, uint64_t now)
{
    if (we_is_stale(m, now)) {
        return 0;
    }
    return we_should_deny(we_lookup4(m, a), thr, 0);
}

/*
 * The two-armed find itself, both arms and each arm alone. Under __builtin_unreachable() the compiler
 * drops the other arm, so each arm has an instruction band of its own and a radix change cannot hide
 * inside the rank arm's budget. These replace the gate's earlier copy of the lookup: every wrapper here
 * compiles the one in whisper_edge.h.
 */
__attribute__((noinline)) uint32_t hpf4(const we_map_t *m, uint32_t a)
{
    return we_find4(m, a);
}

__attribute__((noinline)) uint32_t hpf4_radix(const we_map_t *m, uint32_t a)
{
    if (m->f4.kind != WE_KIND_RADIX) {
        __builtin_unreachable();
    }
    return we_find4(m, a);
}

__attribute__((noinline)) uint32_t hpf4_rank(const we_map_t *m, uint32_t a)
{
    if (m->f4.kind != WE_KIND_RANK) {
        __builtin_unreachable();
    }
    return we_find4(m, a);
}

/*
 * IPv6 with 64-bit keys: the routing and registry planes. we_find6_64 is the IPv6 routing plane's
 * lookup (rank-64s), and until it had a wrapper here it was in no gate.
 */
__attribute__((noinline)) uint32_t hp6w(const we_map_t *m, const uint8_t *a)
{
    return we_find6_64(m, a);
}

__attribute__((noinline)) uint32_t hp6w_radix(const we_map_t *m, const uint8_t *a)
{
    if (m->f6w.kind != WE_KIND_RADIX) {
        __builtin_unreachable();
    }
    return we_find6_64(m, a);
}

__attribute__((noinline)) uint32_t hp6w_rank(const we_map_t *m, const uint8_t *a)
{
    if (m->f6w.kind != WE_KIND_RANK) {
        __builtin_unreachable();
    }
    return we_find6_64(m, a);
}
