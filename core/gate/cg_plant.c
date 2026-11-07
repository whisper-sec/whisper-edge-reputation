/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * cg_plant.c - the link-order control's plant (cachegrind-gate.sh): 1,000 read-only bytes that no
 * measured loop reads, linked AFTER the driver (where they must move nothing of the core's) and inside
 * the core, after its first object (where they must move the data objects of the core's other objects
 * and the evaluator's, the arm that shows the comparison can see a move). Not before the core: its first
 * object starts with a table aligned to a page, which re-aligns whatever follows it. A separate object,
 * unaligned, so no page-aligned static sits between it and the objects it moves.
 */
#ifndef WE_CG_PLANT_BYTES
#define WE_CG_PLANT_BYTES 1000           /* the conflict row's placements build it at 2,000 and 3,500 too */
#endif
const char we_cg_plant_rodata[WE_CG_PLANT_BYTES] = { 1 };
