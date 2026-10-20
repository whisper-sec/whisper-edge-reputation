/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * fuzz_summary - whisper-edge-summary's readers under libFuzzer, ASan and UBSan.
 *
 * One input is up to five files, separated by the byte 0x1E: a process status file, a version 2 rule
 * counter file, a version 1 one, a configuration file and a range-counter file, written into an empty directory under the
 * names the module uses. All three modes run over it (the default range summary, --rules, --status), with
 * stdout captured, and then:
 *
 *   no crash and no hang (the harness's own timeout)
 *   stdout carries no byte below 0x20 but the newline, no DEL and no C1 byte, whatever the files held
 *
 * Seeded from the real writers' shapes, with a seed whose context name carries escaped C0, DEL and C1
 * bytes. Without libFuzzer: `fuzz_summary_replay --replay <dir>` and `--seeds <dir>`.
 */
#define main we_summary_main
#include "we_summary_cli.c"
#undef main

#include <sys/types.h>

static char fs_dir[256];

static void fs_fail(const char *what)
{
    fprintf(stderr, "fuzz_summary: %s\n", what);
    abort();
}

static void fs_write(const char *name, const uint8_t *p, size_t n)
{
    char path[512];
    int fd;

    snprintf(path, sizeof path, "%s/%s", fs_dir, name);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0 || (n > 0u && write(fd, p, n) != (ssize_t)n)) {
        fs_fail("cannot write the input's file");
    }
    close(fd);
}

static void fs_check_stdout(const char *path)
{
    FILE *f = fopen(path, "rb");
    int c;

    if (f == NULL) {
        fs_fail("cannot read back the captured stdout");
    }
    while ((c = fgetc(f)) != EOF) {
        if ((c < 0x20 && c != '\n') || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
            fclose(f);
            fs_fail("a raw control byte reached stdout");
        }
    }
    fclose(f);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    static const char *const names[5] = {
        "100-0123456789abcdef.status", "100-0123456789abcdef.rules.cnt", "101.rules.cnt",
        "conf-ba7816bf8f01cfea.status", "102-0123456789abcdef.cnt"
    };
    char out[300], *argv1[3], *argv2[3], *argv3[2];
    size_t at = 0u, k;
    int saved;

    if (fs_dir[0] == '\0') {
        snprintf(fs_dir, sizeof fs_dir, "/tmp/fuzz_summary.%ld", (long)getpid());
        mkdir(fs_dir, 0700);
    }
    for (k = 0u; k < 5u; k++) {
        const uint8_t *e = at < n ? memchr(d + at, 0x1E, n - at) : NULL;
        size_t len = at < n ? (e != NULL ? (size_t)(e - (d + at)) : n - at) : 0u;

        fs_write(names[k], d + at, len);
        at += len + 1u;
    }
    snprintf(out, sizeof out, "%s.out", fs_dir);
    fflush(stdout);
    saved = dup(1);
    if (freopen(out, "w", stdout) == NULL) {
        fs_fail("cannot capture stdout");
    }
    argv1[0] = "whisper-edge-summary";
    argv1[1] = "--rules";
    argv1[2] = fs_dir;
    argv2[0] = argv1[0];
    argv2[1] = "--status";
    argv2[2] = fs_dir;
    argv3[0] = argv1[0];
    argv3[1] = fs_dir;
    sum_reset();
    we_summary_main(3, argv1);
    sum_reset();
    we_summary_main(3, argv2);
    sum_reset();
    we_summary_main(2, argv3);
    sum_reset();
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    fs_check_stdout(out);
    return 0;
}

#ifndef FZ_LIBFUZZER
#include <dirent.h>

static void fs_seed(const char *dir, const char *name, const char *body)
{
    char path[1024];
    FILE *f;

    snprintf(path, sizeof path, "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (f == NULL || fwrite(body, 1, strlen(body), f) != strlen(body)) {
        fprintf(stderr, "fuzz_summary: cannot write the seed %s\n", path);
        exit(2);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--seeds") == 0) {
        fs_seed(argv[2], "real", "whisper-edge-status 2\n"
                "process \"nginx/1.24.0\" pid 100 boot 0123 pidns 4026531836 starttime 99 started 1 written 2 interval 60000 "
                "jitter 0 handoff 0 tick 3 config ba7816bf8f01cfea shards 1 retired 0 failure-evicted 0 log-dropped 0\n"
                "plane reputation armed generation 497716 digest bad76c5e8609e5d7 valid-until 1 remaining -1 slot-age 0 "
                "since 1 ticks 3 bytes 550829 mapped locked yes immutable no nonresident 0 country-table 5704 eio-backoff 0\n"
                "transition 1 \"plane tor stale out=tor tenant=fresh: rule 5 allow captures\"\n"
                "\x1e" "whisper-edge-rule-counters 2\npidns 4026531836 starttime 99\nstarted 1\ntick 3\nsnapshot 1\nwritten 2\npid 100\n"
                "config ba7816bf8f01cfea\nr ba7816bf8f01cfea 1 7\npre acme 2\n"
                "\x1e" "whisper-edge-rule-counters 1\nstarted 1\nwritten 2\nprogram eacf018fbf1678ba\nr 1 3 deny if tor_exit\n"
                "\x1e" "whisper-edge-config 2\nplane reputation path \"/var/lib/whisper-edge/reputation.bin\"\n"
                "program ba7816bf8f01cfea context \"server \\\"a\\\"\" path \"http/s1\" mode deny rules 1\n"
                "text ba7816bf8f01cfea 1 \"deny if tor_exit\"\n");
        fs_seed(argv[2], "escapes", "whisper-edge-status 2\n\x1e\x1e\x1e" "whisper-edge-config 2\n"
                "program ba7816bf8f01cfea context \"a\\x1b[2J\\x7f\\x9b\\x1b]52;c;x\\x07\" path \"http/s1\" mode log rules 0\n");
        fs_seed(argv[2], "raw-bytes", "whisper-edge-rule-counters 1\nprogram eacf018fbf1678ba\nr 1 3 \x1b[2Jtext\x7f\x9b\n"
                "\x1e\x1e" "whisper-edge-rule-counters 1\nstarted 1\nprogram 0000000000000000\nr 1 18446744073709551615 x\n");
        {
            static char longline[9200];

            memset(longline, 'a', sizeof longline - 1u);
            memcpy(longline, "whisper-edge-status 2\nplane ", 28);
            fs_seed(argv[2], "long-line", longline);
        }
        fs_seed(argv[2], "ranges", "\x1e\x1e\x1e\x1e" "whisper-edge-counters 1\npidns 4026531836 starttime 99\nstarted 1\nwritten 2\npid 102\ndenied 5\n"
                "4 192.0.2.0/24 3 5 SBL\x1b[2J\x7f\x9b evidence\n6 2001:db8::/32 4 1 x\n");
        printf("fuzz_summary: 5 seeds written to %s\n", argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--replay") == 0) {
        /* the seeds in name order, so a control trips on the same input on every file system */
        struct dirent **ents = NULL;
        int ne = scandir(argv[2], &ents, NULL, alphasort), i;
        unsigned n = 0u;

        if (ne < 0) {
            return 2;
        }
        for (i = 0; i < ne; i++) {
            struct dirent *e = ents[i];
            char path[1024];
            static uint8_t buf[1u << 20];
            size_t len;
            FILE *f;

            if (e->d_name[0] == '.') {
                free(e);
                continue;
            }
            snprintf(path, sizeof path, "%s/%s", argv[2], e->d_name);
            free(e);
            f = fopen(path, "rb");
            if (f == NULL) {
                continue;
            }
            len = fread(buf, 1, sizeof buf, f);
            fclose(f);
            LLVMFuzzerTestOneInput(buf, len);
            n++;
        }
        free(ents);
        printf("%u checks, 0 failures\n", n);
        return n > 0u ? 0 : 1;
    }
    fprintf(stderr, "usage: fuzz_summary_replay --seeds <dir> | --replay <dir>\n");
    return 2;
}
#endif /* FZ_LIBFUZZER */
