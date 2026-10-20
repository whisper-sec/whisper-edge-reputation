/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_plane_tier.h - each plane's wire id, its name and the tier its data is published under.
 *
 * The id and name are the wire table (FORMAT.md section 2, plane_id); the tier is the design's plane
 * table: keyless planes anyone may fetch, keyed planes only a key-holder's feed carries.
 * whisper-edge-lookup prints a plane's tier from the manifest that binds it, and from this table only
 * for a plane nothing binds, as the word `keyed` after any withhold reason.
 *
 * Maintained by hand and held two ways: `make check-lookup` checks the rows are self-consistent (eight
 * rows, ids 1 to 8 in order, each tier keyless or keyed), and the builder's test suite checks every
 * row against the builder's own plane enumeration and the design table's tier column, so a plane that
 * moves tier in the design and not here fails a build.
 */
#ifndef WE_PLANE_TIER_H
#define WE_PLANE_TIER_H

#include <stdint.h>

#define WE_PLANE_COUNT 8u

typedef struct {
    uint8_t     id;
    const char *name;
    const char *tier;
} we_plane_tier_t;

static const we_plane_tier_t we_plane_tier[WE_PLANE_COUNT] = {
    { 1, "reputation", "keyless" },
    { 2, "tor", "keyless" },
    { 3, "rpki-unreachable", "keyless" },
    { 4, "routing", "keyed" },
    { 5, "anonymizer", "keyed" },
    { 6, "threat", "keyed" },
    { 7, "registry", "keyed" },
    { 8, "tenant", "keyed" },
};

#endif /* WE_PLANE_TIER_H */
