/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * plane_bind_probe.c - what does the module make of this data directory? One we_mod_bind() of DIR with
 * every plane read, exactly as a server binds it at a restart (not the check-only bind: the real one, which
 * maps and arms), for the lookup gate's agreement row against `whisper-edge-lookup --probe-dir`.
 *
 *   plane_bind_probe DIR UID
 *
 * One line per plane, in plane order: `plane <name> armed`, or `plane <name> <state> <reason>` from the
 * module's status when the bind did not arm it. Exit 0; 2 when the bind itself is refused or the arguments
 * are wrong. The bind's own log lines go to stderr.
 */
#include "we_module.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const pbp_plane[8] = {
    "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

static void pbp_log(void *ud, const char *line)
{
    (void)ud;
    fprintf(stderr, "%s\n", line);
}

int main(int argc, char **argv)
{
    we_mod_cfg_t cfg;
    we_mod_bind_args_t args = WE_MOD_BIND_ARGS_INIT;
    we_mod_planes_t *pl = NULL;
    static we_mod_status_t st;
    char why[512], *end = NULL;
    unsigned long uid;
    unsigned p;

    if (argc != 3 || (uid = strtoul(argv[2], &end, 10), end == argv[2] || *end != '\0')) {
        fprintf(stderr, "usage: plane_bind_probe DIR UID\n");
        return 2;
    }
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = argv[1];
    args.read_mask = 0xffu;
    args.uid = (unsigned)uid;
    args.log = pbp_log;
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        printf("bind refused: %s\n", why);
        return 2;
    }
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, 0u);
    for (p = 0u; p < 8u; p++) {
        const we_map_t *cur = cfg.handle[p] != NULL ? we_current(cfg.handle[p]) : NULL;

        if (cur != NULL && cur != cfg.standin[p]) {
            printf("plane %s armed\n", pbp_plane[p]);
        } else {
            printf("plane %s %s %s\n", pbp_plane[p], st.plane[p].state, st.plane[p].reason);
        }
    }
    we_mod_planes_release(pl);
    return 0;
}
