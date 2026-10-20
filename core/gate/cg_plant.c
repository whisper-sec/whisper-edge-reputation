/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * cg_plant.c - the link-order control's plant (cachegrind-gate.sh): 1,000 read-only bytes that no
 * measured loop reads, linked AFTER the driver (where they must move nothing of the core's) and BEFORE
 * the core (where they must move the core's data objects, the arm that shows the comparison can see a
 * move). A separate object, unaligned, so no page-aligned driver static sits between it and the core.
 */
#ifndef WE_CG_PLANT_BYTES
#define WE_CG_PLANT_BYTES 1000           /* the conflict row's placements build it at 2,000 and 3,500 too */
#endif
const char we_cg_plant_rodata[WE_CG_PLANT_BYTES] = { 1 };
