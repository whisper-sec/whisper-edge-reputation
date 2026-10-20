/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * tenant_arm_probe.c - does the module arm this tenant.bin? The keyed gate's join between the refresh,
 * which writes the revocation mark, and the module, which reads it: one we_mod_bind() of DIR, exactly as
 * a server binds it at a restart, with the high-water file the server would read.
 *
 *   tenant_arm_probe DIR [HIGH_WATER_FILE | --default-path]
 *
 * With --default-path it prints the path the bind reads when a server names none
 * (WE_MOD_HIGH_WATER_DEFAULT) and exits 0, so the gate can hold it equal to the refresh's. Otherwise it
 * prints "tenant armed generation N" (exit 0) or "tenant not armed: <state> <reason>" (exit 1); 2 when
 * the bind itself is refused. The bind's own log lines go to stderr.
 */
#include "we_module.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void probe_log(void *ud, const char *line)
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
    const we_map_t *cur;
    char why[512];

    if (argc == 2 && strcmp(argv[1], "--default-path") == 0) {
        printf("%s\n", WE_MOD_HIGH_WATER_DEFAULT);
        return 0;
    }
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: tenant_arm_probe DIR [HIGH_WATER_FILE] | --default-path\n");
        return 2;
    }
    memset(&cfg, 0, sizeof cfg);
    args.abi = WE_MODULE_ABI_VERSION;
    args.data_dir = argv[1];
    args.read_mask = 0u;                          /* the tenant plane is bound whenever present */
    args.uid = (unsigned)geteuid();
    args.high_water_file = argc == 3 ? argv[2] : NULL;
    args.log = probe_log;
    if (we_mod_bind(&cfg, &args, &pl, why, sizeof why) != 0 || pl == NULL) {
        printf("bind refused: %s\n", why);
        return 2;
    }
    cur = cfg.handle[7] != NULL ? we_current(cfg.handle[7]) : NULL;
    if (cur != NULL && cur != cfg.standin[7]) {
        printf("tenant armed generation %llu\n", (unsigned long long)cur->generation);
        we_mod_planes_release(pl);
        return 0;
    }
    memset(&st, 0, sizeof st);
    we_mod_planes_status(pl, &st, 0u);
    printf("tenant not armed: %s %s\n", st.plane[7].state, st.plane[7].reason);
    we_mod_planes_release(pl);
    return 1;
}
