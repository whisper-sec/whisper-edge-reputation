/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * test_summary - whisper-edge-summary's readers on planted directories: a file the reader refuses
 * contributes nothing, wherever in the file the refusal falls.
 *
 * Each row writes a directory, runs one mode with stdout captured, and checks both halves: the refused
 * file is listed with its reason, and the totals are exactly the good files' totals. The control build
 * (-DWE_SUM_TEST_EAGER_SUM) sums each line as it is read, which is the defect these rows exist for: the
 * rows must fail under it, naming the total that includes the refused file.
 *
 * The usage text's exit table is parsed, and every form is run into each code: a code returned that the
 * table does not give, or a code the table gives that no case returns, fails the row. Its control
 * (-DWE_SUM_TEST_EXIT_DRIFT) changes one code and not the table.
 *
 *   test_summary <tmpdir>
 */
#define main we_summary_main
#include "we_summary_cli.c"
#undef main

#include <sys/wait.h>

static int checks, failures;

#define CHECK(cond, ...) do {                                   \
        checks++;                                               \
        if (!(cond)) {                                          \
            failures++;                                         \
            printf("  FAIL ");                                  \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        }                                                       \
    } while (0)

static char ts_base[512];

static void unlink_in(const char *dir, const char *name)
{
    char path[1024];

    snprintf(path, sizeof path, "%s/%s", dir, name);
    unlink(path);
}

static void ts_put(const char *dir, const char *name, const char *body)
{
    char path[1024];
    FILE *f;

    snprintf(path, sizeof path, "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (f == NULL || fwrite(body, 1, strlen(body), f) != strlen(body)) {
        printf("test_summary: cannot write %s\n", path);
        exit(2);
    }
    fclose(f);
}

/* a fresh directory under the base, named for the row */
static void ts_dir(char *dir, size_t n, const char *row)
{
    snprintf(dir, n, "%s/%s", ts_base, row);
    mkdir(dir, 0700);
}

/* run the summary with argv (argv[0] supplied here) and stdout and stderr captured into out, through
 * the file at capture; the exit status returned */
static int ts_run_argv(const char *capture, int nargs, char *const *args, char *out, size_t n)
{
    char path[1024];
    char *argv[8];
    int saved_out, saved_err, rc, argc = 0, i;
    FILE *f;
    size_t got;

    snprintf(path, sizeof path, "%s.out", capture);
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(1);
    saved_err = dup(2);
    if (freopen(path, "w", stdout) == NULL) {
        exit(2);
    }
    dup2(1, 2);
    argv[argc++] = "whisper-edge-summary";
    for (i = 0; i < nargs && argc < 7; i++) {
        argv[argc++] = args[i];
    }
    argv[argc] = NULL;
    sum_reset();
    rc = we_summary_main(argc, argv);
    sum_reset();
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, 1);
    dup2(saved_err, 2);
    close(saved_out);
    close(saved_err);
    f = fopen(path, "rb");
    got = f != NULL ? fread(out, 1, n - 1u, f) : 0u;
    out[got] = '\0';
    if (f != NULL) {
        fclose(f);
    }
    return rc;
}

/* run --status over dir with --writer-uid <uid> appended (the uid given as text, so a malformed one can be
 * passed); `first` puts the option before --status instead, the order an operator may type */
static int ts_run_uid(const char *dir, const char *uid, int first, char *out, size_t n)
{
    char path[1024];
    char *argv[5];
    int saved_out, saved_err, rc;
    FILE *f;
    size_t got;

    snprintf(path, sizeof path, "%s.out", dir);
    fflush(stdout);
    fflush(stderr);
    saved_out = dup(1);
    saved_err = dup(2);
    if (freopen(path, "w", stdout) == NULL) {
        exit(2);
    }
    dup2(1, 2);
    argv[0] = "whisper-edge-summary";
    argv[first ? 3 : 1] = "--status";
    argv[first ? 4 : 2] = (char *)dir;
    argv[first ? 1 : 3] = "--writer-uid";
    argv[first ? 2 : 4] = (char *)uid;
    sum_reset();
    rc = we_summary_main(5, argv);
    sum_reset();
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, 1);
    dup2(saved_err, 2);
    close(saved_out);
    close(saved_err);
    f = fopen(path, "rb");
    got = f != NULL ? fread(out, 1, n - 1u, f) : 0u;
    out[got] = '\0';
    if (f != NULL) {
        fclose(f);
    }
    return rc;
}

/* the output with its `foreign entries` line removed, which only --writer-uid prints */
static void ts_drop_foreign_line(char *s)
{
    char *l = strstr(s, "foreign entries ");

    if (l != NULL && (l == s || l[-1] == '\n')) {
        char *e = strchr(l, '\n');

        memmove(l, e != NULL ? e + 1 : l + strlen(l), strlen(e != NULL ? e + 1 : l + strlen(l)) + 1u);
    }
}

/* run one mode over dir (mode NULL for the range summary) */
static int ts_run(const char *mode, const char *dir, char *out, size_t n)
{
    char *args[2];
    int k = 0;

    if (mode != NULL) {
        args[k++] = (char *)mode;
    }
    args[k++] = (char *)dir;
    return ts_run_argv(dir, k, args, out, n);
}

#define RULES_HEAD(pid) "whisper-edge-rule-counters 2\npidns 4026531836 starttime 99\nstarted 1\ntick 3\nsnapshot 1\n" \
                        "written 2\npid " pid "\nconfig ba7816bf8f01cfea\n"
#define GOOD_101 RULES_HEAD("101") "r 0123456789abcdef 1 5\npre acme 2\n"

/* one rule-counter row: the good file plus one bad file, which must be refused and add nothing */
static void ts_rules_row(const char *row, const char *bad_name, const char *bad, const char *reason)
{
    char dir[600], out[16384];
    int rc;

    ts_dir(dir, sizeof dir, row);
    ts_put(dir, "101-0123456789abcdef.rules.cnt", GOOD_101);
    ts_put(dir, bad_name, bad);
    rc = ts_run("--rules", dir, out, sizeof out);
    CHECK(strstr(out, reason) != NULL && strstr(out, "refused \"") != NULL,
          "rules, %s: the file is not listed refused with \"%s\":\n%s", row, reason, out);
    CHECK(strstr(out, "\nr 0123456789abcdef 1 5 -\n") != NULL && strstr(out, "\npre acme 2\n") != NULL,
          "rules, %s: the totals are not the good file's alone (r ... 1 5, pre acme 2), so the refused file was "
          "counted:\n%s", row, out);
    CHECK(strstr(out, "gone writers' files 1,") != NULL,
          "rules, %s: the refused file was filed under a writer:\n%s", row, out);
    CHECK(rc == 1, "rules, %s: exit %d, not 1 for a refused file", row, rc);
}

/* this process's own key, as the reader derives it (sum_my_key, sum_proc_starttime): the boot id, the pid
 * namespace's inode and field 22 of /proc/self/stat, so a staged status file reads as a LIVE writer */
static void ts_live_process(char *out, size_t n)
{
    char boot[64] = "", st[1024], *p;
    struct stat ns;
    FILE *f;
    unsigned long long starttime = 0ull, pidns = 0ull;
    int k;

    f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (f != NULL) {
        if (fgets(boot, sizeof boot, f) == NULL) {
            boot[0] = '\0';
        }
        fclose(f);
        boot[strcspn(boot, "\n")] = '\0';
    }
    if (stat("/proc/self/ns/pid", &ns) == 0) {
        pidns = (unsigned long long)ns.st_ino;
    }
    f = fopen("/proc/self/stat", "r");
    if (f != NULL) {
        size_t got = fread(st, 1, sizeof st - 1u, f);

        fclose(f);
        st[got] = '\0';
        p = strrchr(st, ')');
        for (k = 2; k < 22 && p != NULL; k++) {
            p = strchr(p + 1, ' ');
        }
        if (p != NULL) {
            starttime = strtoull(p + 1, NULL, 10);
        }
    }
    snprintf(out, n, "process \"test/1\" pid %ld boot %s pidns %llu starttime %llu started 1 written 2 interval 60000 "
             "jitter 0 handoff 0 tick 3 config 0123456789abcdef", (long)getpid(), boot, pidns, starttime);
}

/* a configuration file under its own name: the first 16 hex digits of the SHA-256 of its bytes */
static void ts_put_conf(const char *dir, const char *body, char name[64])
{
    uint8_t dg[32];
    unsigned k;

    we_sha256(body, strlen(body), dg);
    memcpy(name, "conf-", 5);
    for (k = 0u; k < 8u; k++) {
        snprintf(name + 5u + 2u * k, 3, "%02x", dg[k]);
    }
    snprintf(name + 21, 11, ".status");
    ts_put(dir, name, body);
}

/* the usage text's exit table: one (form, code) claim per line under the `exit codes` line. A line that
 * starts at column 2 names its form (up to two spaces); a line with only a code under it belongs to the
 * form above; a continuation line (no code) is skipped */
#define TS_MAX_CLAIMS 32
static struct { char form[32]; int code; int seen; } ts_claim[TS_MAX_CLAIMS];
static int ts_nclaims;

static void ts_parse_exit_table(const char *usage)
{
    const char *p = strstr(usage, "\nexit codes");
    char form[32] = "";

    ts_nclaims = 0;
    if (p == NULL) {
        return;
    }
    p = strchr(p + 1, '\n');
    if (p == NULL) {
        return;
    }
    for (p++; *p != '\0'; ) {
        const char *eol = strchr(p, '\n'), *q = p + 2;
        size_t len = eol != NULL ? (size_t)(eol - p) : strlen(p);

        if (len > 2u && p[0] == ' ' && p[1] == ' ' && p[2] != ' ') {
            const char *gap = strstr(q, "  ");
            size_t fl = gap != NULL && gap < p + len ? (size_t)(gap - q) : 0u;

            if (fl == 0u || fl >= sizeof form) {
                break;
            }
            memcpy(form, q, fl);
            form[fl] = '\0';
            q = gap;
        }
        while (q < p + len && *q == ' ') {
            q++;
        }
        if (q + 3 <= p + len && *q >= '0' && *q <= '9' && q[1] == ' ' && q[2] == ' ' && form[0] != '\0'
                && ts_nclaims < TS_MAX_CLAIMS) {
            snprintf(ts_claim[ts_nclaims].form, sizeof ts_claim[0].form, "%s", form);
            ts_claim[ts_nclaims].code = *q - '0';
            ts_claim[ts_nclaims].seen = 0;
            ts_nclaims++;
        }
        if (eol == NULL) {
            break;
        }
        p = eol + 1;
    }
}

/* the --status --writer-uid form's codes, taken in its own section and held to the table in the table's:
 * the writer's own healthy files, its own refused configuration, another uid's file, a uid that is no uid */
static int ts_wu_rc[4] = { -1, -1, -1, -1 };

/* one case: the code it returned must be one the table claims for its form, and that claim is now seen */
static void ts_exit_case(const char *form, const char *what, int rc)
{
    int i, found = 0;

    for (i = 0; i < ts_nclaims; i++) {
        if (strcmp(ts_claim[i].form, form) == 0 && ts_claim[i].code == rc) {
            ts_claim[i].seen = 1;
            found = 1;
        }
    }
    CHECK(found, "exit table: %s %s returned %d, which the usage text's table does not give for `%s`", form, what, rc, form);
}

/* field 22 of /proc/<pid>/stat, the start time the reader compares; 0 when it cannot be read */
static unsigned long long ts_starttime(long pid)
{
    char path[64], st[1024], *p;
    FILE *f;
    int k;
    size_t got;

    snprintf(path, sizeof path, "/proc/%ld/stat", pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return 0ull;
    }
    got = fread(st, 1, sizeof st - 1u, f);
    fclose(f);
    st[got] = '\0';
    p = strrchr(st, ')');
    for (k = 2; k < 22 && p != NULL; k++) {
        p = strchr(p + 1, ' ');
    }
    return p != NULL ? strtoull(p + 1, NULL, 10) : 0ull;
}

/* a process line for `pid` with the given pidns and start time, on this boot */
static void ts_process_line(char *out, size_t n, long pid, unsigned long long pidns, unsigned long long starttime)
{
    char boot[64] = "";
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");

    if (f != NULL) {
        if (fgets(boot, sizeof boot, f) == NULL) {
            boot[0] = '\0';
        }
        fclose(f);
        boot[strcspn(boot, "\n")] = '\0';
    }
    snprintf(out, n, "process \"test/1\" pid %ld boot %s pidns %llu starttime %llu started 1 written 2 interval 60000 "
             "jitter 0 handoff 0 tick 3 config 0123456789abcdef", pid, boot, pidns, starttime);
}

/*
 * A process in another pid namespace, as this namespace numbers it: `unshare -p --fork --kill-child sleep
 * <marker>` as root, through sudo -n, or in a new user namespace, and the sleep found by its marker with
 * two NSpid fields. *launcher is the child to signal and reap; -1 when nothing could be started.
 */
static long ts_other_ns(pid_t *launcher)
{
    char secs[32], want[64];
    size_t wn;
    int tries, how;
    pid_t l;

    snprintf(secs, sizeof secs, "60.%ld", (long)getpid());
    wn = (size_t)snprintf(want, sizeof want, "sleep%c%s%c", 0, secs, 0);
    how = geteuid() == 0 ? 0 : system("sudo -n true >/dev/null 2>&1") == 0 ? 1 : 2;
    fflush(stdout);
    l = fork();
    if (l == 0) {
        int dn = open("/dev/null", O_RDWR);

        dup2(dn, 0);
        dup2(dn, 1);
        dup2(dn, 2);
        if (how == 0) {
            execlp("unshare", "unshare", "-p", "--fork", "--kill-child", "sleep", secs, (char *)NULL);
        } else if (how == 1) {
            execlp("sudo", "sudo", "-n", "unshare", "-p", "--fork", "--kill-child", "sleep", secs, (char *)NULL);
        } else {
            execlp("unshare", "unshare", "-U", "-r", "-p", "--fork", "--kill-child", "sleep", secs, (char *)NULL);
        }
        _exit(127);
    }
    *launcher = l;
    if (l < 0) {
        return -1;
    }
    /* the sleep appears once unshare has forked it: looked for every 50 ms, for at most 60 s */
    for (tries = 0; tries < 1200; tries++) {
        DIR *d = opendir("/proc");
        struct dirent *e;
        long found = -1;

        while (d != NULL && (e = readdir(d)) != NULL) {
            char path[300], buf[64];
            FILE *f;
            size_t got;
            uint64_t first = 0u;

            if (e->d_name[0] < '1' || e->d_name[0] > '9') {
                continue;
            }
            snprintf(path, sizeof path, "/proc/%s/cmdline", e->d_name);
            f = fopen(path, "rb");
            if (f == NULL) {
                continue;
            }
            got = fread(buf, 1, sizeof buf, f);
            fclose(f);
            snprintf(path, sizeof path, "/proc/%s/status", e->d_name);
            if (got == wn && memcmp(buf, want, wn) == 0 && sum_nspid(path, &first) == 2) {
                found = strtol(e->d_name, NULL, 10);
                break;
            }
        }
        if (d != NULL) {
            closedir(d);
        }
        if (found > 0) {
            return found;
        }
        if (waitpid(l, NULL, WNOHANG) == l) {
            *launcher = -1;
            return -1;                          /* the launcher gave up: no namespace could be made */
        }
        {
            struct timespec ts = { 0, 50000000L };

            nanosleep(&ts, NULL);
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    char dir[600], out[16384];
    int rc;

    if (argc != 2 && !(argc == 3 && strcmp(argv[2], "--procfs-not-mine") == 0)) {
        fprintf(stderr, "usage: test_summary <tmpdir> [--procfs-not-mine]\n");
        return 2;
    }
    snprintf(ts_base, sizeof ts_base, "%s/test_summary.XXXXXX", argv[1]);
    if (mkdtemp(ts_base) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    if (argc == 3) {
        /*
         * Run inside a new pid namespace whose /proc is still the parent's (unshare -p --fork, no
         * --mount-proc): this reader's own NSpid names two pids, so its procfs is not its namespace's, and
         * the NSpid fallback must refuse a pidns-0 writer as foreign rather than read the parent's
         * /proc/<pid> as the writer's. The writer is this process, live, with its own start time.
         */
        static char line[512], status[1024];
        char name[64];
        uint64_t first = 0u;
        int self_fields = sum_nspid("/proc/self/status", &first);

        printf("== --status: the NSpid fallback refuses on a procfs that is not the reader's namespace's ==\n");
        CHECK(self_fields == 2, "procfs row: the reader's own NSpid names %d pid(s), not 2: this run is not inside a "
              "pid namespace below its procfs's, so the row proves nothing", self_fields);
        ts_dir(dir, sizeof dir, "procfs-not-mine");
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        ts_process_line(line, sizeof line, (long)getpid(), 0ull, ts_starttime((long)getpid()));
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n", line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 2 && strstr(out, "live 0, gone 0, foreign 1") != NULL,
              "procfs row: on a procfs that is not the reader's namespace's, a pidns-0 writer was not refused as "
              "foreign (exit %d):\n%s", rc, out);
        printf("%d checks, %d failures\n", checks, failures);
        return failures == 0 ? 0 : 1;
    }
    printf("== --rules: a refused file adds nothing, wherever the refusal falls ==\n");
    /* the baseline: the good file alone */
    ts_dir(dir, sizeof dir, "good");
    ts_put(dir, "101-0123456789abcdef.rules.cnt", GOOD_101);
    rc = ts_run("--rules", dir, out, sizeof out);
    CHECK(rc == 0 && strstr(out, "\nr 0123456789abcdef 1 5 -\n") != NULL && strstr(out, "refused") == NULL,
          "rules, the good file alone: exit %d:\n%s", rc, out);
    /* a pid line naming another process, after the counter lines it would otherwise have added */
    ts_rules_row("pid-mismatch", "100-0123456789abcdef.rules.cnt",
                 "whisper-edge-rule-counters 2\npidns 4026531836 starttime 98\nstarted 1\ntick 3\nsnapshot 1\n"
                 "written 2\nconfig ba7816bf8f01cfea\nr 0123456789abcdef 1 1000000\npre acme 77\npid 999\n",
                 "a pid line that is not the file name's process");
    /* no pid line at all */
    ts_rules_row("pid-missing", "100-0123456789abcdef.rules.cnt",
                 "whisper-edge-rule-counters 2\npidns 4026531836 starttime 98\nstarted 1\ntick 3\nsnapshot 1\n"
                 "written 2\nconfig ba7816bf8f01cfea\nr 0123456789abcdef 1 1000000\npre acme 77\n",
                 "no pid line");
    /* a malformed counter line after a good one */
    ts_rules_row("malformed", "100-0123456789abcdef.rules.cnt",
                 RULES_HEAD("100") "r 0123456789abcdef 1 1000000\npre acme 77\nr zz 2 7\n",
                 "a counter line whose digest is not 16 hex digits");
    /* no writer key line */
    ts_rules_row("pidns-missing", "100-0123456789abcdef.rules.cnt",
                 "whisper-edge-rule-counters 2\nstarted 1\ntick 3\nsnapshot 1\nwritten 2\npid 100\n"
                 "config ba7816bf8f01cfea\nr 0123456789abcdef 1 1000000\npre acme 77\n",
                 "no pidns line");
    /* a line over the bound after the counts */
    {
        static char big[12000];
        size_t h;

        snprintf(big, sizeof big, RULES_HEAD("100") "r 0123456789abcdef 1 1000000\npre acme 77\nx ");
        h = strlen(big);
        memset(big + h, 'a', sizeof big - h - 2u);
        big[sizeof big - 2u] = '\n';
        big[sizeof big - 1u] = '\0';
        ts_rules_row("over-bound", "100-0123456789abcdef.rules.cnt", big, "a line over the bound");
    }

    printf("== the configuration file: a refused file files no rule text ==\n");
    ts_dir(dir, sizeof dir, "conf");
    ts_put(dir, "101-0123456789abcdef.rules.cnt", GOOD_101);
    ts_put(dir, "conf-0000000000000000.status",
           "whisper-edge-config 2\ntext 0123456789abcdef 1 \"deny if tor_exit\"\ntext zz 2 \"x\"\n");
    rc = ts_run("--rules", dir, out, sizeof out);
    CHECK(strstr(out, "a text line outside the grammar") != NULL && strstr(out, "\nr 0123456789abcdef 1 5 -\n") != NULL
          && strstr(out, "deny if tor_exit") == NULL,
          "conf: a refused configuration file still filed its rule text:\n%s", out);

    printf("== --status: a file with no process line is refused, not counted foreign ==\n");
    ts_dir(dir, sizeof dir, "status");
    ts_put(dir, "100-0123456789abcdef.status", "whisper-edge-status 2\n");
    rc = ts_run("--status", dir, out, sizeof out);
    CHECK(strstr(out, "no process line") != NULL && strstr(out, "foreign 0") != NULL,
          "status: a status file with no process line was not refused, or was counted foreign:\n%s", out);

    printf("== the range summary: a refused file adds nothing, and a pid line must agree with the name ==\n");
    ts_dir(dir, sizeof dir, "range");
    ts_put(dir, "101-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\npid 101\ndenied 5\n4 192.0.2.0/24 3 5 good\n");
    ts_put(dir, "100-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\ndenied 1000000\n4 198.51.100.0/24 3 1000000 forged\npid 999\n");
    rc = ts_run(NULL, dir, out, sizeof out);
    CHECK(strstr(out, "a pid line that is not the file name's process") != NULL && strstr(out, "  5 requests denied") != NULL
          && strstr(out, "198.51.100.0/24") == NULL && strstr(out, "across 1 worker process\n") != NULL,
          "range: a refused range file was counted:\n%s", out);
    ts_dir(dir, sizeof dir, "range-old");
    ts_put(dir, "102.cnt", "whisper-edge-counters 1\nstarted 1\nwritten 2\ndenied 3\n4 192.0.2.0/24 3 3 old\n");
    rc = ts_run(NULL, dir, out, sizeof out);
    CHECK(strstr(out, "  3 requests denied") != NULL, "range: a record from before the pid line is not read:\n%s", out);
    CHECK(strstr(out, "  3 requests denied\n  (a deny under mode log is counted too: that request was allowed, and logged as a would-deny)\n") != NULL
          && strstr(out, "dropped") == NULL,
          "headline: the summary does not say denied with the mode-log line, or still says dropped:\n%s", out);
    ts_dir(dir, sizeof dir, "range-nopid");
    ts_put(dir, "101-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\npid 101\ndenied 5\n4 192.0.2.0/24 3 5 good\n");
    ts_put(dir, "103-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\ndenied 1000000\n4 198.51.100.0/24 3 1000000 forged\n");
    rc = ts_run(NULL, dir, out, sizeof out);
    CHECK(strstr(out, "no pid line: the record does not name its process") != NULL && strstr(out, "  5 requests denied") != NULL
          && strstr(out, "198.51.100.0/24") == NULL,
          "range: a new-name record without its pid line was counted:\n%s", out);
    ts_dir(dir, sizeof dir, "range-malformed");
    ts_put(dir, "101-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\npid 101\ndenied 5\n4 192.0.2.0/24 3 5 good\n");
    ts_put(dir, "104-0123456789abcdef.cnt",
           "whisper-edge-counters 1\nstarted 1\nwritten 2\npid 104\ndenied 1000000\n4 198.51.100.0/24 3 1000000 forged\n6 junk\n");
    rc = ts_run(NULL, dir, out, sizeof out);
    CHECK(strstr(out, "a range line outside the grammar") != NULL && strstr(out, "  5 requests denied") != NULL
          && strstr(out, "198.51.100.0/24") == NULL,
          "range: a record with a range line outside the grammar was counted:\n%s", out);
    printf("== --status: the configuration file's refused line (a host whose policy was refused) is unhealthy ==\n");
    {
        static char proc_line[512], status[1024], conf[1024];
        char name[64];
        static const char conf_body[] = "whisper-edge-config 2\n"
            "program 0123456789abcdef context \"floor\" path \"http\" mode 1 rules 1\n"
            "text 0123456789abcdef 1 \"deny if tor_exit\"\n";

        ts_dir(dir, sizeof dir, "conf-refused");
        ts_live_process(proc_line, sizeof proc_line);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation armed generation 1 digest 0123456789abcdef valid-until 0 remaining -1 since 1 bytes 64 mapped\n",
                 proc_line);
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        ts_put(dir, name, status);
        /* the control: the same host with nothing refused is healthy, so the row below can fail */
        ts_put_conf(dir, conf_body, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "conf-mismatch") == NULL && strstr(out, "refused") == NULL,
              "status: the control host (nothing refused) reads unhealthy (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* a host's policy refused at the build: the configuration file says so, and --status must too */
        snprintf(conf, sizeof conf, "%srefused \"http/s7\" \"a directive this build does not know\"\n", conf_body);
        ts_put_conf(dir, conf, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 1 && strstr(out, "configuration refused \"http/s7\" \"a directive this build does not know\"") != NULL,
              "status: a configuration file's refused line left the host healthy (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* a refused line outside the grammar refuses the file like a text line outside it */
        snprintf(conf, sizeof conf, "%srefused \"http/s7\"\n", conf_body);
        ts_put_conf(dir, conf, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(strstr(out, "a refused line outside the grammar") != NULL,
              "status: a refused line with one field was read as the grammar's (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* a plane present and unreadable by the configuration reader: its rules are inert, a misconfiguration
         * the operator must see; the control first, the same plane with no unreadable field (bound, or absent)
         * is silent and healthy */
        snprintf(conf, sizeof conf, "%splane tor path \"/var/lib/whisper-edge/tor.bin\"\n", conf_body);
        ts_put_conf(dir, conf, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "unreadable") == NULL,
              "status: a plane line with no unreadable field reads unhealthy or unreadable (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        snprintf(conf, sizeof conf, "%splane tor path \"/var/lib/whisper-edge/tor.bin\" unreadable \"Permission denied\"\n",
                 conf_body);
        ts_put_conf(dir, conf, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 1 && strstr(out, "configuration unreadable tor \"/var/lib/whisper-edge/tor.bin\" \"Permission denied\"\n")
              != NULL, "status: an unreadable plane was not reported with its path and errno, unhealthy (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* the unreadable field with no errno text is outside the grammar, and refuses the file */
        snprintf(conf, sizeof conf, "%splane tor path \"/var/lib/whisper-edge/tor.bin\" unreadable\n", conf_body);
        ts_put_conf(dir, conf, name);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(strstr(out, "a plane line outside the grammar") != NULL && strstr(out, "configuration unreadable") == NULL,
              "status: an unreadable field with no errno was read as the grammar's (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
    }
    printf("== --status: a writer that named no pid namespace is placed by the reader itself ==\n");
    {
        static char line[512], status[1024];
        char name[64], want_by[32];
        unsigned long long me = ts_starttime((long)getpid());
        long other;
        pid_t launcher = -1, dead;

#ifdef WE_SUM_TEST_NS_STAT_DENIED
        snprintf(want_by, sizeof want_by, "pidns-by=nspid");   /* the stat refused: the fallback decides */
#else
        snprintf(want_by, sizeof want_by, "pidns-by=stat");
#endif
        ts_dir(dir, sizeof dir, "pidns-zero");
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        /* this process, pidns 0, its own start time: live, and the line says how it was placed */
        ts_process_line(line, sizeof line, (long)getpid(), 0ull, me);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n", line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "live 1, gone 0, foreign 0") != NULL && strstr(out, want_by) != NULL,
              "pidns 0: a live writer in this namespace was not read as live by %s (exit %d):\n%s", want_by, rc, out);
        /* the same process, a start time one tick off: not this writer, so gone */
        ts_process_line(line, sizeof line, (long)getpid(), 0ull, me + 1ull);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n", line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 2 && strstr(out, "live 0, gone 1, foreign 0") != NULL,
              "pidns 0: a start time that is not the process's was read as live (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* a pid that has exited: gone, never foreign */
        fflush(stdout);
        dead = fork();
        if (dead == 0) {
            _exit(0);
        }
        waitpid(dead, NULL, 0);
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)dead);
        ts_process_line(line, sizeof line, (long)dead, 0ull, me);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n", line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 2 && strstr(out, "live 0, gone 1, foreign 0") != NULL,
              "pidns 0: a pid that has exited was not read as gone (exit %d):\n%s", rc, out);
        unlink_in(dir, name);
        /* a process in another pid namespace, its real start time: refused as foreign */
        other = ts_other_ns(&launcher);
        CHECK(other > 0, "pidns 0: no process in another pid namespace could be started (as root, through sudo -n, or "
              "in a user namespace); the other-namespace row did not run");
        if (other > 0) {
            snprintf(name, sizeof name, "%ld-0123456789abcdef.status", other);
            ts_process_line(line, sizeof line, other, 0ull, ts_starttime(other));
            snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n", line);
            ts_put(dir, name, status);
            rc = ts_run("--status", dir, out, sizeof out);
            CHECK(rc == 2 && strstr(out, "live 0, gone 0, foreign 1") != NULL,
                  "pidns 0: a writer in another pid namespace was read as live (exit %d):\n%s", rc, out);
            unlink_in(dir, name);
        }
        if (launcher > 0) {
            kill(launcher, SIGTERM);
            waitpid(launcher, NULL, 0);
        }
    }
    printf("== --status: an absent plane (a snapshot path the refresh has not filled) is not unhealthy ==\n");
    {
        static char proc_line[512], status[1024];
        char name[64];

        ts_dir(dir, sizeof dir, "status-absent");
        ts_live_process(proc_line, sizeof proc_line);
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        /* the control: the same host with the plane refused is unhealthy, so the row below can fail */
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation refused \"digest mismatch\" generation 0 digest -\n", proc_line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 1, "status: the control host (a refused plane) reads healthy (exit %d):\n%s", rc, out);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation absent generation 0 digest -\n", proc_line);
        ts_put(dir, name, status);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "plane reputation absent") != NULL,
              "status: an absent plane (nothing installed yet) reads unhealthy (exit %d):\n%s", rc, out);
    }
    printf("== --status --writer-uid: only the writer's own files are read; anything else is refused by name ==\n");
    {
        static char proc_line[512], status[1024], conf[1024], plain[16384], again[16384];
        char name[64], cname[64], path[1024], link_to[1024], me[32], other[32], tdir[600];
        static const char conf_body[] = "whisper-edge-config 2\n"
            "program 0123456789abcdef context \"floor\" path \"http\" mode 1 rules 1\n"
            "text 0123456789abcdef 1 \"deny if tor_exit\"\n";
        int rc0;

        snprintf(me, sizeof me, "%lu", (unsigned long)getuid());
        snprintf(other, sizeof other, "%lu", (unsigned long)getuid() + 1ul);
        ts_dir(dir, sizeof dir, "writer-uid");
        ts_live_process(proc_line, sizeof proc_line);
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation armed generation 7 digest 0123456789abcdef valid-until 0 since 1 bytes 64 mapped\n",
                 proc_line);
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        ts_put(dir, name, status);
        snprintf(path, sizeof path, "%s/%s", dir, name);
        chmod(path, 0644);

        /* the control for every row below: without the option the file is read, a live armed writer */
        rc0 = ts_run("--status", dir, plain, sizeof plain);
        CHECK(rc0 == 0 && strstr(plain, "plane reputation armed generation 7") != NULL && strstr(plain, "foreign entries") == NULL,
              "writer-uid control: without the option the writer's file is not read as live and armed (exit %d):\n%s", rc0, plain);

        /* the writer's own uid: the same verdict, line for line, plus the count of what was refused (none) */
        rc = ts_run_uid(dir, me, 0, out, sizeof out);
        ts_wu_rc[0] = rc;
        CHECK(rc == rc0 && strstr(out, "foreign entries 0 (") != NULL && strstr(out, "refused \"") == NULL,
              "writer-uid, the right uid: exit %d (without it %d), or a refusal, or no `foreign entries 0`:\n%s", rc, rc0, out);
        ts_drop_foreign_line(out);
        CHECK(strcmp(out, plain) == 0, "writer-uid, the right uid: the verdict differs from the no-option path:\n%s\n--- without:\n%s",
              out, plain);
        /* the option first, the order an operator may type: the same */
        rc = ts_run_uid(dir, me, 1, again, sizeof again);
        CHECK(rc == rc0 && strstr(again, "foreign entries 0 (") != NULL,
              "writer-uid given before --status: exit %d (without it %d):\n%s", rc, rc0, again);

        /* the writer named by its user name: the same */
        {
            struct passwd *pw = getpwuid(getuid());

            rc = pw != NULL ? ts_run_uid(dir, pw->pw_name, 0, again, sizeof again) : -1;
            CHECK(rc == rc0 && strstr(again, "foreign entries 0 (") != NULL,
                  "writer-uid given as the user name %s: exit %d (without it %d):\n%s", pw != NULL ? pw->pw_name : "?", rc, rc0, again);
        }

        /* another uid's file (the writer is named as someone else, so this file's owner is not the writer):
         * refused by name, never read, so no live writer and exit 2 */
        rc = ts_run_uid(dir, other, 0, out, sizeof out);
        ts_wu_rc[2] = rc;
        {
            char want[256];

            snprintf(want, sizeof want, "refused \"%s\": owned by uid %s, not the writer uid %s", name, me, other);
            CHECK(rc == 2 && strstr(out, want) != NULL && strstr(out, "foreign entries 1 (") != NULL
                  && strstr(out, "plane reputation armed") == NULL,
                  "writer-uid, a file the writer does not own was read as the writer's (exit %d; want `%s`):\n%s", rc, want, out);
        }

        /* the writer's uid but open to another uid's write (mode 0664): refused; the control is 0644, above */
        chmod(path, 0664);
        rc = ts_run_uid(dir, me, 0, out, sizeof out);
        CHECK(rc == 2 && strstr(out, "open to another uid's write") != NULL && strstr(out, "foreign entries 1 (") != NULL
              && strstr(out, "plane reputation armed") == NULL,
              "writer-uid, a group-writable file was read as the writer's (exit %d):\n%s", rc, out);
        chmod(path, 0644);

        /* the writer's uid but a second name linked to it (a writer renames each file into place, one link):
         * both names refused; the control is the one-link file, above */
        {
            char lpath[1024];

            snprintf(lpath, sizeof lpath, "%s/9-0123456789abcdef.status", dir);
            if (link(path, lpath) == 0) {
                rc = ts_run_uid(dir, me, 0, out, sizeof out);
                CHECK(rc == 2 && strstr(out, "2 links") != NULL && strstr(out, "foreign entries 2 (") != NULL
                      && strstr(out, "plane reputation armed") == NULL,
                      "writer-uid, a hard-linked file was read as the writer's (exit %d):\n%s", rc, out);
                unlink(lpath);
            } else {
                CHECK(0, "writer-uid: cannot make the hard link the row needs: %s", strerror(errno));
            }
        }

        /* a forged refusal: a configuration file open to another uid's write carrying a `refused` line. The
         * control: without the option it is read, and the host reads unhealthy on it */
        snprintf(conf, sizeof conf, "%srefused \"http/s7\" \"forged\"\n", conf_body);
        ts_put_conf(dir, conf, cname);
        snprintf(link_to, sizeof link_to, "%s/%s", dir, cname);
        chmod(link_to, 0666);
        rc = ts_run("--status", dir, out, sizeof out);
        CHECK(rc == 1 && strstr(out, "configuration refused \"http/s7\" \"forged\"") != NULL,
              "writer-uid control: without the option the configuration file's refused line is not read (exit %d):\n%s", rc, out);
        rc = ts_run_uid(dir, me, 0, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "configuration refused") == NULL && strstr(out, "open to another uid's write") != NULL
              && strstr(out, "foreign entries 1 (") != NULL,
              "writer-uid, a forged refused line in a file open to another uid's write was read as the writer's (exit %d):\n%s",
              rc, out);
        /* the same refused line in the writer's own file (0644, one link): read, and the host is unhealthy */
        chmod(link_to, 0644);
        rc = ts_run_uid(dir, me, 0, out, sizeof out);
        ts_wu_rc[1] = rc;
        CHECK(rc == 1 && strstr(out, "configuration refused \"http/s7\" \"forged\"") != NULL && strstr(out, "foreign entries 0 (") != NULL,
              "writer-uid, a refused line in the writer's own configuration file was not read as unhealthy (exit %d):\n%s", rc, out);
        unlink(link_to);

        /* a symbolic link at a status file's name, to a writer-owned file elsewhere: refused, never followed.
         * The control: the same target read in its own directory is a live armed writer */
        snprintf(tdir, sizeof tdir, "%s/writer-uid-target", ts_base);
        mkdir(tdir, 0700);
        ts_put(tdir, name, status);
        snprintf(link_to, sizeof link_to, "%s/%s", tdir, name);
        chmod(link_to, 0644);
        rc = ts_run_uid(tdir, me, 0, out, sizeof out);
        CHECK(rc == 0 && strstr(out, "plane reputation armed generation 7") != NULL,
              "writer-uid control: the link's target, read in its own directory, is not a live armed writer (exit %d):\n%s", rc, out);
        unlink(path);
        if (symlink(link_to, path) == 0) {
            char want[256];

            snprintf(want, sizeof want, "refused \"%s\": a symbolic link", name);
            rc = ts_run_uid(dir, me, 0, out, sizeof out);
            CHECK(rc == 2 && strstr(out, want) != NULL && strstr(out, "foreign entries 1 (") != NULL
                  && strstr(out, "plane reputation armed") == NULL,
                  "writer-uid, a symbolic link at a status name: the link was followed (exit %d; want `%s`):\n%s", rc, want, out);
            unlink(path);
        } else {
            CHECK(0, "writer-uid: cannot make the symbolic link the row needs: %s", strerror(errno));
        }

        /* the option's own grammar: a uid that is not a number, or the option without --status, is a usage error */
        rc = ts_run_uid(dir, "nobody-at-all-x", 0, out, sizeof out);
        ts_wu_rc[3] = rc;
        CHECK(rc == 2 && strstr(out, "--writer-uid") != NULL, "writer-uid, a malformed uid: exit %d, not 2 with the usage:\n%s",
              rc, out);
        rc = ts_run_uid(dir, "4294967296", 0, out, sizeof out);
        CHECK(rc == 2 && strstr(out, "--writer-uid") != NULL, "writer-uid, a uid past 32 bits: exit %d, not 2:\n%s", rc, out);
    }
    printf("== the usage text's exit table and the codes every form returns agree ==\n");
    {
        static char proc_line[512], status[1024];
        char name[64], missing[700];
        char *a[4];
        int i;

        ts_parse_exit_table(sum_usage);
        CHECK(ts_nclaims >= 10, "exit table: the usage text has %d (form, code) lines under `exit codes`, not the "
              "table of every form:\n%s", ts_nclaims, sum_usage);
        snprintf(missing, sizeof missing, "%s/no-such-directory", ts_base);
        /* the range summary: an empty directory (0), a missing one (2) */
        ts_dir(dir, sizeof dir, "exit-range");
        ts_exit_case("<counters-dir>", "over an empty directory", ts_run(NULL, dir, out, sizeof out));
        ts_exit_case("<counters-dir>", "over a missing directory", ts_run(NULL, missing, out, sizeof out));
        /* --rules: the good file (0), a refused file beside it (1), a missing directory (2) */
        ts_dir(dir, sizeof dir, "exit-rules");
        ts_put(dir, "101-0123456789abcdef.rules.cnt", GOOD_101);
        ts_exit_case("--rules", "over a good file", ts_run("--rules", dir, out, sizeof out));
        ts_put(dir, "102-0123456789abcdef.rules.cnt", "whisper-edge-rule-counters 9\n");
        ts_exit_case("--rules", "over a refused file", ts_run("--rules", dir, out, sizeof out));
        ts_exit_case("--rules", "over a missing directory", ts_run("--rules", missing, out, sizeof out));
        /* --status: a live healthy writer (0), the same writer's plane refused (1), no writer live (2), a missing
         * directory (2) */
        ts_dir(dir, sizeof dir, "exit-status");
        ts_exit_case("--status", "over a directory with no writer", ts_run("--status", dir, out, sizeof out));
        ts_live_process(proc_line, sizeof proc_line);
        snprintf(name, sizeof name, "%ld-0123456789abcdef.status", (long)getpid());
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation armed generation 1 digest 0123456789abcdef valid-until 0 remaining -1 since 1 bytes 64 mapped\n",
                 proc_line);
        ts_put(dir, name, status);
        ts_exit_case("--status", "over a healthy live writer", ts_run("--status", dir, out, sizeof out));
        snprintf(status, sizeof status, "whisper-edge-status 2\n%s\n"
                 "plane reputation refused \"digest mismatch\" generation 0 digest -\n", proc_line);
        ts_put(dir, name, status);
        ts_exit_case("--status", "over a refused plane", ts_run("--status", dir, out, sizeof out));
        ts_exit_case("--status", "over a missing directory", ts_run("--status", missing, out, sizeof out));
        /* --help: the text itself, on stdout */
        a[0] = "--help";
        rc = ts_run_argv(dir, 1, a, out, sizeof out);
        ts_exit_case("--help", "", rc);
        CHECK(strcmp(out, sum_usage) == 0, "exit table: --help did not print the usage text:\n%s", out);
        /* every other form: the usage, never a read of a directory named after an option */
        ts_exit_case("any other form", "(no arguments)", ts_run_argv(dir, 0, a, out, sizeof out));
        CHECK(strcmp(out, sum_usage) == 0, "exit table: no arguments did not print the usage text:\n%s", out);
        a[0] = "--status";
        rc = ts_run_argv(dir, 1, a, out, sizeof out);
        ts_exit_case("any other form", "(--status with no directory)", rc);
        CHECK(strstr(out, "cannot read") == NULL, "exit table: --status with no directory was read as a directory:\n%s", out);
        a[0] = "--rules";
        ts_exit_case("any other form", "(--rules with no directory)", ts_run_argv(dir, 1, a, out, sizeof out));
        a[0] = "--no-such-option";
        a[1] = dir;
        ts_exit_case("any other form", "(an option this tool does not have)", ts_run_argv(dir, 2, a, out, sizeof out));
        a[0] = "--status";
        a[1] = dir;
        a[2] = "extra";
        ts_exit_case("any other form", "(a third argument)", ts_run_argv(dir, 3, a, out, sizeof out));
        ts_exit_case("--status --writer-uid", "over the writer's own healthy files", ts_wu_rc[0]);
        ts_exit_case("--status --writer-uid", "over the writer's own refused configuration", ts_wu_rc[1]);
        ts_exit_case("--status --writer-uid", "over a status file another uid owns", ts_wu_rc[2]);
        ts_exit_case("--status --writer-uid", "with a uid that is neither a number nor a user", ts_wu_rc[3]);
        /* and the other way: a code the table gives that no case above returned is a claim nothing backs */
        for (i = 0; i < ts_nclaims; i++) {
            CHECK(ts_claim[i].seen, "exit table: the usage text gives %d for `%s`, and no case returned it",
                  ts_claim[i].code, ts_claim[i].form);
        }
    }
    (void)rc;

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
