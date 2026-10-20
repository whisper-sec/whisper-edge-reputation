/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * whisper-edge-summary - the artifact somebody pastes into a chat.
 *
 * Nobody installs a blocklist because it works; they install it because a person they trust showed
 * them a number. This prints that number, from counters the module wrote on its own host, with no
 * console, no account, and nothing leaving the machine.
 *
 *   whisper-edge-summary /var/lib/whisper-edge/counters
 *
 * WHAT IT WILL NOT DO. It will not round a window up to "this week", it will not print a total it
 * did not sum, and it prints nothing at all rather than a zero when there are no counters to read -
 * because "0 requests denied" and "I could not find your counters" are different sentences and an
 * operator is entitled to tell them apart.
 *
 * It takes a DIRECTORY, because a server is several worker processes and each one writes its own
 * file. Summing them is this tool's whole job beyond formatting.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "we_summary_read.h"
#include "we_sha256.h"

#include <dirent.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_RANGES 4096
#define MAX_RANGE_TEXT 128
#define MAX_EVIDENCE 256

struct row {
    char     range[MAX_RANGE_TEXT];
    char     evidence[MAX_EVIDENCE];
    uint64_t hits;
    unsigned sev;
    int      family;
};

static struct row rows[MAX_RANGES];
static size_t nrows;
static uint64_t total_denied;
static uint64_t earliest_started;
static uint64_t latest_written;
static size_t files_read;
static size_t ranges_dropped;

static struct row *find_row(int family, const char *range)
{
    size_t i;

    for (i = 0; i < nrows; i++) {
        if (rows[i].family == family && strcmp(rows[i].range, range) == 0) {
            return &rows[i];
        }
    }
    if (nrows >= MAX_RANGES) {
        /*
         * A bound, and a counted one. Silently dropping past the limit would make the summary
         * understate the fleet exactly when there is most to report, and the operator would have no
         * way to know. The footer says how many were dropped.
         */
        ranges_dropped++;
        return NULL;
    }
    rows[nrows].family = family;
    snprintf(rows[nrows].range, sizeof(rows[nrows].range), "%s", range);
    rows[nrows].hits = 0;
    rows[nrows].sev = 0;
    rows[nrows].evidence[0] = '\0';
    return &rows[nrows++];
}

/*
 * One range-counter file, through the hostile-directory reader (we_summary_read.h): opened relative to
 * the directory, never through a link, never blocking on a FIFO; a line over the bound refuses the file.
 * Its figures are staged and reach the totals only when the whole file has read and passed, so a file
 * refused on its last line adds nothing. A `pid` line must name the process the file name's leading
 * digits do, and a file named `<pid>-<16 hex>.cnt` (only the writer that writes the line names a file
 * so) must carry one; a bare `<pid>.cnt` is a record from before the line existed and may not. A range
 * line that does not parse refuses the file, as a line outside the grammar does in --rules.
 */
typedef struct {
    int      family;
    unsigned sev;
    uint64_t hits;
    char     range[MAX_RANGE_TEXT];
    char     evidence[MAX_EVIDENCE];
} range_stage_t;

static range_stage_t *range_stage;
static size_t range_stage_cap;

static void range_refuse(const char *name, const char *why)
{
    fprintf(stderr, "whisper-edge-summary: refused \"");
    we_sum_print_escaped(stderr, name);
    fprintf(stderr, "\": %s\n", why);
}

static void read_file(int dirfd, const char *name)
{
    static we_sum_file_t f;
    struct stat st;
    const char *why = NULL;
    char *line;
    int header_ok = 0, rc, said_pid = 0;
    uint64_t started = 0u, written = 0u, denied = 0u, said;
    size_t n = 0u, i;
    const char *dash = strchr(name, '-');
    int new_name = dash != NULL && dash > name && strspn(name, "0123456789") == (size_t)(dash - name);

    if (we_sum_open(dirfd, name, &f, &st, &why) != 0) {
        fprintf(stderr, "whisper-edge-summary: skipped \"");
        we_sum_print_escaped(stderr, name);
        fprintf(stderr, "\": %s\n", why);
        return;
    }
    line = f.line;
    while ((rc = we_sum_line(&f)) > 0) {
        size_t len = strlen(line);
        uint64_t v;

        while (len > 0 && line[len - 1] == '\r') {
            line[--len] = '\0';
        }
        if (!header_ok) {
            /* The first line must be the magic. A file that is not ours is skipped, not guessed at. */
            if (strncmp(line, "whisper-edge-counters ", 22) != 0) {
                we_sum_close(&f);
                return;
            }
            header_ok = 1;
            continue;
        }
        if (sscanf(line, "started %" SCNu64, &v) == 1) {
            started = v;
            continue;
        }
        if (sscanf(line, "written %" SCNu64, &v) == 1) {
            written = v;
            continue;
        }
        if (sscanf(line, "pid %" SCNu64, &said) == 1) {
            if (said != strtoull(name, NULL, 10)) {
                range_refuse(name, "a pid line that is not the file name's process");
                we_sum_close(&f);
                return;
            }
            said_pid = 1;
            continue;
        }
        if (sscanf(line, "denied %" SCNu64, &v) == 1) {
            denied = we_sum_add(denied, v);
            continue;
        }
        if (line[0] == '4' || line[0] == '6') {
            char range[MAX_RANGE_TEXT];
            unsigned sev;
            uint64_t hits;
            int consumed = 0;

            if (sscanf(line + 2, "%127s %u %" SCNu64 " %n", range, &sev, &hits, &consumed) >= 3) {
                if (n >= range_stage_cap) {
                    size_t cap = range_stage_cap != 0u ? 2u * range_stage_cap : 64u;
                    range_stage_t *g = cap <= 4u * MAX_RANGES ? realloc(range_stage, cap * sizeof *g) : NULL;

                    if (g == NULL) {
                        range_refuse(name, "more range lines than this reader stages");
                        we_sum_close(&f);
                        return;
                    }
                    range_stage = g;
                    range_stage_cap = cap;
                }
                range_stage[n].family = line[0] == '4' ? 4 : 6;
                range_stage[n].sev = sev;
                range_stage[n].hits = hits;
                memcpy(range_stage[n].range, range, sizeof range);
                range_stage[n].evidence[0] = '\0';
                if (consumed > 0) {
                    snprintf(range_stage[n].evidence, sizeof range_stage[n].evidence, "%.*s",
                             (int)(sizeof range_stage[n].evidence - 1u), line + 2 + consumed);
                }
                n++;
            } else {
                range_refuse(name, "a range line outside the grammar");
                we_sum_close(&f);
                return;
            }
        }
    }
    if (rc < 0) {
        fprintf(stderr, "whisper-edge-summary: refused \"");
        we_sum_print_escaped(stderr, name);
        fprintf(stderr, "\": a line over %u bytes, a NUL byte or a read error\n", WE_SUM_LINE_MAX);
        we_sum_close(&f);
        return;
    }
    if (header_ok && rc == 0 && new_name && !said_pid) {
        range_refuse(name, "no pid line: the record does not name its process");
        we_sum_close(&f);
        return;
    }
    we_sum_close(&f);
    if (!header_ok) {
        return;
    }
    /* the whole file read and passed: only now do its figures count */
    files_read++;
    if (started != 0u && (earliest_started == 0 || started < earliest_started)) {
        earliest_started = started;
    }
    if (written > latest_written) {
        latest_written = written;
    }
    total_denied = we_sum_add(total_denied, denied);
    for (i = 0u; i < n; i++) {
        struct row *r = find_row(range_stage[i].family, range_stage[i].range);

        if (r != NULL) {
            r->hits = we_sum_add(r->hits, range_stage[i].hits);
            if (range_stage[i].sev > r->sev) {
                r->sev = range_stage[i].sev;
            }
            if (r->evidence[0] == '\0') {
                memcpy(r->evidence, range_stage[i].evidence, sizeof r->evidence);
            }
        }
    }
}

static int by_hits(const void *a, const void *b)
{
    const struct row *x = (const struct row *) a;
    const struct row *y = (const struct row *) b;

    if (x->hits != y->hits) {
        return x->hits < y->hits ? 1 : -1;
    }
    return strcmp(x->range, y->range);     /* stable output for equal counts */
}

static const char *sev_name(unsigned sev)
{
    switch (sev & 0x0fu) {
    case 0:  return "none";
    case 1:  return "low";
    case 2:  return "medium";
    case 3:  return "high";
    default: return "critical";
    }
}

/* "4 days, 3 hours" - the window, in the units a human reads, never rounded up to a week. */
static void human_window(uint64_t ms, char *buf, size_t n)
{
    uint64_t mins = ms / 60000ull;
    uint64_t days = mins / 1440ull;
    uint64_t hours = (mins % 1440ull) / 60ull;

    if (days > 0) {
        snprintf(buf, n, "%" PRIu64 " day%s, %" PRIu64 " hour%s",
                 days, days == 1 ? "" : "s", hours, hours == 1 ? "" : "s");
    } else if (hours > 0) {
        uint64_t rem = mins % 60ull;
        snprintf(buf, n, "%" PRIu64 " hour%s, %" PRIu64 " minute%s",
                 hours, hours == 1 ? "" : "s", rem, rem == 1 ? "" : "s");
    } else if (mins > 0) {
        snprintf(buf, n, "%" PRIu64 " minute%s", mins, mins == 1 ? "" : "s");
    } else {
        /* "0 minutes of blocking" is the first line an operator reads, and it reads as an error.
         * Under a minute is a real and common state - a server that has just started - so say it. */
        snprintf(buf, n, "under a minute");
    }
}

static void iso_utc(uint64_t ms, char *buf, size_t n)
{
    time_t secs = (time_t)(ms / 1000ull);
    struct tm tm;

    if (gmtime_r(&secs, &tm) == NULL) {
        snprintf(buf, n, "unknown");
        return;
    }
    strftime(buf, n, "%Y-%m-%d %H:%M UTC", &tm);
}

/* ==================================================================================================
 * --rules and --status: the module's per-rule counters and its status files. The configuration file's
 * `refused` lines (a context whose policy the build refused) make --status read the host unhealthy.
 * ================================================================================================ */

#include <signal.h>

#define SUM_MAX_ENTRIES 100000u     /* directory entries read; a planted flood stops here, printed */
#define SUM_MAX_KEYS    1000000u    /* (digest, rule) keys and texts summed; the cap printed when hit */
#define SUM_MAX_PROCS   65536u      /* process status files */

/* the identity of a writer: its pid namespace and start time, and its pid */
typedef struct {
    uint64_t pidns, starttime, pid;
    uint64_t bytes;                 /* every file it left, for the gone-writer line */
    uint32_t files;
    int      has_status, live, foreign, flagged;
} sum_writer_t;

typedef struct {
    uint8_t  used;
    char     digest[17];
    uint32_t rule;
    uint64_t count;
    char    *text;                  /* escaped, from a configuration file or a version 1 counter file */
} sum_key_t;

static sum_key_t *sum_keys;
static size_t sum_cap, sum_n;
static int sum_key_full;
static sum_writer_t *sum_w;
static size_t sum_nw;
static uint64_t sum_pre[8];
static const char *const sum_pre_name[8] = {
    "hold-harmless", "acme", "tenant", "stale-tenant", "no-address",
    "floor-header-missing", "floor-header-unparsed", "floor-header-capped"
};
static unsigned sum_refused;
static int sum_conf_mismatch;

/*
 * The configuration file's `refused "<ordinal path>" "<reason>"` lines (written once per configuration): a context whose policy the
 * build refused runs the empty program, and the module says so once per configuration. --status repeats
 * each as `configuration refused <path> <reason>` and reads the host unhealthy: a host whose policy was
 * refused is not a healthy one, whatever its planes say. Kept as the file escaped them, up to a cap.
 */
#define SUM_MAX_CONF_REFUSED 64u
static char  *sum_conf_refused_line[SUM_MAX_CONF_REFUSED];
static size_t sum_nconf_refused;
static int    sum_conf_refused_full;

/*
 * The configuration file's `plane <name> path "<path>" unreadable "<errno text>"` lines: a plane present
 * on disk that the configuration reader could not open, so it is not bound and its rules are inert.
 * --status repeats each as `configuration unreadable <name> "<path>" "<errno text>"` and reads the host
 * unhealthy, as it did when such a plane was bound and refused. A plane line with no unreadable field is
 * a bound or an absent plane, and says nothing here (an absent plane is inert by design).
 */
static char  *sum_conf_unreadable_line[SUM_MAX_CONF_REFUSED];
static size_t sum_nconf_unreadable;
static int    sum_conf_unreadable_full;

static void sum_ref_drop(char **r, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        free(r[i]);
        r[i] = NULL;
    }
}
static uint64_t sum_my_pidns, sum_my_boot_hash;
static char sum_my_boot[64];

static uint64_t sum_hash(const char *d, uint32_t r)
{
    uint64_t h = 1469598103934665603ull;

    for (; *d != '\0'; d++) {
        h = (h ^ (uint8_t)*d) * 1099511628211ull;
    }
    return (h ^ r) * 1099511628211ull;
}

static sum_key_t *sum_key(const char *digest, uint32_t rule)
{
    size_t i;

    if (sum_keys == NULL) {
        sum_cap = 1u << 16;
        sum_keys = calloc(sum_cap, sizeof *sum_keys);
        if (sum_keys == NULL) {
            return NULL;
        }
    }
    if (2u * (sum_n + 1u) > sum_cap) {
        sum_key_t *old = sum_keys;
        size_t oc = sum_cap, k;

        if (sum_n >= SUM_MAX_KEYS) {
            sum_key_full = 1;
            return NULL;
        }
        sum_cap *= 2u;
        sum_keys = calloc(sum_cap, sizeof *sum_keys);
        if (sum_keys == NULL) {
            sum_keys = old;
            sum_cap = oc;
            sum_key_full = 1;
            return NULL;
        }
        for (k = 0u; k < oc; k++) {
            if (old[k].used) {
                for (i = sum_hash(old[k].digest, old[k].rule) & (sum_cap - 1u); sum_keys[i].used; i = (i + 1u) & (sum_cap - 1u)) {
                }
                sum_keys[i] = old[k];
            }
        }
        free(old);
    }
    for (i = sum_hash(digest, rule) & (sum_cap - 1u); sum_keys[i].used; i = (i + 1u) & (sum_cap - 1u)) {
        if (sum_keys[i].rule == rule && strcmp(sum_keys[i].digest, digest) == 0) {
            return &sum_keys[i];
        }
    }
    sum_keys[i].used = 1u;
    memcpy(sum_keys[i].digest, digest, 17);
    sum_keys[i].rule = rule;
    sum_n++;
    return &sum_keys[i];
}

static sum_writer_t *sum_writer(uint64_t pidns, uint64_t starttime, uint64_t pid)
{
    size_t i;

    for (i = 0u; i < sum_nw; i++) {
        if (sum_w[i].pidns == pidns && sum_w[i].starttime == starttime && sum_w[i].pid == pid) {
            return &sum_w[i];
        }
    }
    if (sum_nw >= SUM_MAX_PROCS) {
        return NULL;
    }
    if (sum_w == NULL) {
        sum_w = calloc(SUM_MAX_PROCS, sizeof *sum_w);
        if (sum_w == NULL) {
            return NULL;
        }
    }
    memset(&sum_w[sum_nw], 0, sizeof sum_w[sum_nw]);
    sum_w[sum_nw].pidns = pidns;
    sum_w[sum_nw].starttime = starttime;
    sum_w[sum_nw].pid = pid;
    return &sum_w[sum_nw++];
}

static void sum_refuse(const char *name, const char *why)
{
    sum_refused++;
    printf("refused \"");
    we_sum_print_escaped(stdout, name);
    printf("\": %s\n", why);
}

/*
 * --writer-uid <uid> (S3): the counters directory is writable by every server user, so a file in it is
 * only the writer's when the writer's uid owns it, it has the one link a rename into place leaves, and no
 * other uid can write it (no group or world write bit). Anything else is refused by name before a byte of
 * it is read, and counted in the `foreign entries` line: a forged `armed` cannot report a deny that never
 * armed, and a forged `refused` cannot make a healthy host read unhealthy. The owner is the descriptor's
 * (fstat on the file opened O_NOFOLLOW), so nothing can be swapped in between the check and the read.
 * Without the option nothing changes: every regular file is read, as before.
 */
static int sum_uid_set;
static uid_t sum_uid;
static size_t sum_foreign_entries;

static int sum_open(int dirfd, const char *name, we_sum_file_t *f, struct stat *st)
{
    const char *why;
    char text[160];

    if (we_sum_open(dirfd, name, f, st, &why) != 0) {
        if (sum_uid_set && (strcmp(why, "a symbolic link") == 0 || strcmp(why, "not a regular file") == 0)) {
            sum_foreign_entries++;               /* a writer leaves only regular files: this one was planted */
        }
        sum_refuse(name, why);
        return -1;
    }
    if (!sum_uid_set) {
        return 0;
    }
#ifdef WE_MOD_TEST_WRITER_UID_UNCHECKED
    if (sum_uid_set) {
        return 0;                                /* the control: the option taken, the owner never compared */
    }
#endif
    if (st->st_uid != sum_uid) {
        snprintf(text, sizeof text, "owned by uid %lu, not the writer uid %lu: not read",
                 (unsigned long)st->st_uid, (unsigned long)sum_uid);
    } else if (st->st_nlink != 1u) {
        snprintf(text, sizeof text, "%lu links: a writer renames each file into place with one, so another uid "
                 "could have linked this name: not read", (unsigned long)st->st_nlink);
    } else if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
        snprintf(text, sizeof text, "mode %04o, open to another uid's write: not read",
                 (unsigned)(st->st_mode & 07777u));
    } else {
        return 0;
    }
    sum_foreign_entries++;
    sum_refuse(name, text);
    we_sum_close(f);
    return -1;
}

/* this reader's own namespace key: the boot id and the pid namespace's inode */
static void sum_my_key(void)
{
    struct stat st;
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        ssize_t n = read(fd, sum_my_boot, sizeof sum_my_boot - 1u);

        sum_my_boot[n > 0 ? (size_t)n : 0u] = '\0';
        sum_my_boot[strcspn(sum_my_boot, "\n")] = '\0';
        close(fd);
    }
    sum_my_pidns = stat("/proc/self/ns/pid", &st) == 0 ? (uint64_t)st.st_ino : 0u;
    sum_my_boot_hash = sum_hash(sum_my_boot, 0u);
}

/* field 22 of /proc/<pid>/stat, after the parenthesised command, which may hold spaces */
static int sum_proc_starttime(uint64_t pid, uint64_t *st)
{
    char path[64], buf[1024], *p;
    int fd, k;
    ssize_t n;

    snprintf(path, sizeof path, "/proc/%llu/stat", (unsigned long long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    n = read(fd, buf, sizeof buf - 1u);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    p = strrchr(buf, ')');
    if (p == NULL) {
        return -1;
    }
    for (k = 2; k < 22 && p != NULL; k++) {
        p = strchr(p + 1, ' ');
    }
    if (p == NULL) {
        return -1;
    }
    *st = strtoull(p + 1, NULL, 10);
    return 0;
}

/* live: kill(pid, 0) answers 0 or EPERM, and the process's start time is the file's */
static int sum_live(uint64_t pid, uint64_t starttime)
{
    uint64_t now;

    if (pid == 0u || pid > 4194304u || (kill((pid_t)pid, 0) != 0 && errno != EPERM)) {
        return 0;
    }
    return sum_proc_starttime(pid, &now) == 0 && now == starttime;
}

/*
 * A writer that could not name its pid namespace writes pidns 0: a confined worker whose policy denies it
 * the stat of /proc/self/ns/pid, as SELinux's httpd_t does (getattr on nsfs). This reader places it itself,
 * which is a stronger check than any value the writer reports: /proc/<pid>/ns/pid stat'ed and compared
 * with its own; and when that stat is refused (a reader that is not root may not stat another uid's
 * namespace, which needs ptrace read access), the NSpid line of /proc/<pid>/status, which is world-readable
 * and names one pid exactly when the process is in the namespace of the procfs it is read from. That is
 * sound only when this procfs is the reader's own namespace's, so the reader's own NSpid must name one pid
 * too; when it does not, the fallback refuses rather than guesses. The start time is checked after, as for
 * every writer.
 */
enum { SUM_NS_SAME, SUM_NS_OTHER, SUM_NS_GONE, SUM_NS_UNKNOWN };

/* the NSpid line of /proc/<path>/status: the number of fields, and the first */
static int sum_nspid(const char *status_path, uint64_t *first)
{
    char buf[4096], *p;
    int fd = open(status_path, O_RDONLY | O_CLOEXEC), n = 0;
    ssize_t got;

    if (fd < 0) {
        return -1;
    }
    got = read(fd, buf, sizeof buf - 1u);
    close(fd);
    if (got <= 0) {
        return -1;
    }
    buf[got] = '\0';
    p = strstr(buf, "\nNSpid:");
    if (p == NULL) {
        return -1;                              /* a kernel before 4.1 says nothing: no answer */
    }
    p += 7;
    while (*p != '\0' && *p != '\n') {
        char *end;
        unsigned long long v;

        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n') {
            break;
        }
        v = strtoull(p, &end, 10);
        if (end == p) {
            return -1;
        }
        if (n++ == 0) {
            *first = (uint64_t)v;
        }
        p = end;
    }
    return n;
}

static int sum_reader_ns(uint64_t pid, const char **by)
{
    char path[64];
    struct stat st;
    uint64_t first = 0u;
    int n, err;

    *by = NULL;
    if (pid == 0u || pid > 4194304u) {
        return SUM_NS_GONE;
    }
#ifdef WE_SUM_TEST_PIDNS_TRUSTED
    *by = "writer";                             /* the control: the writer's 0 read as this namespace */
    return SUM_NS_SAME;
#endif
    snprintf(path, sizeof path, "/proc/%llu/ns/pid", (unsigned long long)pid);
#ifdef WE_SUM_TEST_NS_STAT_DENIED
    errno = EACCES;                             /* the seam: this reader may not stat the namespace */
    err = -1;
#else
    err = stat(path, &st);
#endif
    if (err == 0 && sum_my_pidns != 0u) {
        *by = "stat";
        return (uint64_t)st.st_ino == sum_my_pidns ? SUM_NS_SAME : SUM_NS_OTHER;
    }
    if (err != 0 && errno == ENOENT) {
        return SUM_NS_GONE;
    }
    if (err == 0 || errno == EACCES || errno == EPERM) {
        uint64_t self = 0u;

        /* the fallback, sound only on this reader's own namespace's procfs: its own NSpid names one pid */
#ifndef WE_SUM_TEST_NO_PROCFS_CHECK
        if (sum_nspid("/proc/self/status", &self) != 1 || self != (uint64_t)getpid()) {
            return SUM_NS_UNKNOWN;
        }
#else
        (void)self;                             /* the control: any procfs taken as the reader's own */
#endif
        snprintf(path, sizeof path, "/proc/%llu/status", (unsigned long long)pid);
        n = sum_nspid(path, &first);
        if (n < 0) {
            return errno == ENOENT ? SUM_NS_GONE : SUM_NS_UNKNOWN;
        }
        *by = "nspid";
        return n == 1 && first == pid ? SUM_NS_SAME : SUM_NS_OTHER;
    }
    return SUM_NS_UNKNOWN;
}

/*
 * A file's counts are STAGED and reach the totals only when the whole file has read and passed: a file
 * refused on any line, wherever the line is, contributes nothing to the totals, files no rule text and
 * is filed under no writer. A file that says it is refused and is still counted would publish bytes the reader rejected.
 */
typedef struct {
    char     digest[17];
    uint32_t rule;
    uint64_t count;
    char    *text;                  /* a configuration file's rule text, escaped; NULL for a count */
} sum_stage_t;

static sum_stage_t *sum_stage;
static size_t sum_stage_cap;

static int sum_stage_put(size_t n, const char *digest, uint32_t rule, uint64_t count, char *text)
{
    if (n >= sum_stage_cap) {
        size_t cap = sum_stage_cap != 0u ? 2u * sum_stage_cap : 256u;
        sum_stage_t *g;

        if (cap > SUM_MAX_KEYS) {
            return -1;
        }
        g = realloc(sum_stage, cap * sizeof *g);
        if (g == NULL) {
            return -1;
        }
        sum_stage = g;
        sum_stage_cap = cap;
    }
    memcpy(sum_stage[n].digest, digest, 17);
    sum_stage[n].rule = rule;
    sum_stage[n].count = count;
    sum_stage[n].text = text;
    return 0;
}

/* a refused file's staged entries, discarded: the texts it would have filed freed */
static void sum_stage_drop(size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        free(sum_stage[i].text);
        sum_stage[i].text = NULL;
    }
}

/* the configuration file: its name is the first 16 hex digits of the SHA-256 of its bytes */
static void sum_read_conf(int dirfd, const char *name)
{
    static we_sum_file_t f;
    struct stat st;
    we_sha256_ctx h;
    uint8_t dg[32];
    char want[17];
    int rc, first = 1, ref_full = 0;
    uint32_t k;
    size_t n = 0u, i, nref = 0u, nunr = 0u;
    char *ref[SUM_MAX_CONF_REFUSED], *unr[SUM_MAX_CONF_REFUSED];
    int unr_full = 0;

    if (sum_open(dirfd, name, &f, &st) != 0) {
        return;
    }
#define SUM_CONF_REFUSE(r) do { sum_stage_drop(n); sum_ref_drop(ref, nref); sum_ref_drop(unr, nunr); sum_refuse(name, (r)); \
                                we_sum_close(&f); return; } while (0)
    we_sha256_init(&h);
    while ((rc = we_sum_line(&f)) > 0) {
        char *p = f.line, *w[4];

        we_sha256_update(&h, f.line, strlen(f.line));
        we_sha256_update(&h, "\n", 1);
        if (first) {
            if (strcmp(f.line, "whisper-edge-config 2") != 0) {
                SUM_CONF_REFUSE("not a configuration file of this version");
            }
            first = 0;
            continue;
        }
        if (strncmp(p, "text ", 5) == 0) {
            uint64_t rule;
            char *t;

            p += 5;
            if (we_sum_field(&p, &w[0]) != 0 || we_sum_hex16(w[0]) != 0 || we_sum_field(&p, &w[1]) != 0
                    || we_sum_u64(w[1], &rule) != 0 || rule == 0u || rule > 65536u || we_sum_field(&p, &w[2]) != 0
                    || w[2][0] != '"') {
                SUM_CONF_REFUSE("a text line outside the grammar");
            }
            t = strdup(w[2]);
            if (t == NULL || sum_stage_put(n, w[0], (uint32_t)rule, 0u, t) != 0) {
                free(t);
                SUM_CONF_REFUSE("more text lines than this reader stages");
            }
            n++;
        } else if (strncmp(p, "refused ", 8) == 0) {
            /* exactly two quoted fields, the ordinal path and the reason; staged like the texts, filed
             * only when the whole file has passed */
            p += 8;
            if (we_sum_field(&p, &w[0]) != 0 || w[0][0] != '"' || we_sum_field(&p, &w[1]) != 0 || w[1][0] != '"'
                    || we_sum_field(&p, &w[2]) == 0) {
                SUM_CONF_REFUSE("a refused line outside the grammar");
            }
            if (nref < SUM_MAX_CONF_REFUSED) {
                size_t ln = strlen(w[0]) + 1u + strlen(w[1]) + 1u;
                char *t = malloc(ln);

                if (t == NULL) {
                    SUM_CONF_REFUSE("a refused line this reader cannot keep (out of memory)");
                }
                snprintf(t, ln, "%s %s", w[0], w[1]);
                ref[nref++] = t;
            } else {
                ref_full = 1;
            }
        } else if (strncmp(p, "plane ", 6) == 0) {
            /* `plane <name> path "<path>"`, then optional fields; only `unreadable "<errno text>"` is read */
            char *k, *v;

            p += 6;
            if (we_sum_field(&p, &w[0]) != 0 || we_sum_field(&p, &w[1]) != 0 || strcmp(w[1], "path") != 0
                    || we_sum_field(&p, &w[2]) != 0 || w[2][0] != '"') {
                SUM_CONF_REFUSE("a plane line outside the grammar");
            }
            while (we_sum_field(&p, &k) == 0) {
                if (strcmp(k, "unreadable") != 0) {
                    continue;                    /* another field (revoked-at <ms>): not this reader's */
                }
                if (we_sum_field(&p, &v) != 0 || v[0] != '"') {
                    SUM_CONF_REFUSE("a plane line outside the grammar");
                }
                if (nunr < SUM_MAX_CONF_REFUSED) {
                    size_t ln = strlen(w[0]) + 1u + strlen(w[2]) + 1u + strlen(v) + 1u;
                    char *t = malloc(ln);

                    if (t == NULL) {
                        SUM_CONF_REFUSE("an unreadable line this reader cannot keep (out of memory)");
                    }
                    snprintf(t, ln, "%s %s %s", w[0], w[2], v);
                    unr[nunr++] = t;
                } else {
                    unr_full = 1;
                }
            }
        }
    }
    if (rc < 0) {
        SUM_CONF_REFUSE("a line over the bound, a NUL byte or a read error");
    }
    if (first) {
        SUM_CONF_REFUSE("an empty file");
    }
#undef SUM_CONF_REFUSE
    /* the whole file read and passed: only now are its texts and its refusals filed */
    for (i = 0u; i < nref; i++) {
        if (sum_nconf_refused < SUM_MAX_CONF_REFUSED) {
            sum_conf_refused_line[sum_nconf_refused++] = ref[i];
        } else {
            free(ref[i]);
            sum_conf_refused_full = 1;
        }
        ref[i] = NULL;
    }
    if (ref_full) {
        sum_conf_refused_full = 1;
    }
    for (i = 0u; i < nunr; i++) {
        if (sum_nconf_unreadable < SUM_MAX_CONF_REFUSED) {
            sum_conf_unreadable_line[sum_nconf_unreadable++] = unr[i];
        } else {
            free(unr[i]);
            sum_conf_unreadable_full = 1;
        }
        unr[i] = NULL;
    }
    if (unr_full) {
        sum_conf_unreadable_full = 1;
    }
    for (i = 0u; i < n; i++) {
        sum_key_t *kk = sum_key(sum_stage[i].digest, sum_stage[i].rule);

        if (kk != NULL && kk->text == NULL) {
            kk->text = sum_stage[i].text;
        } else {
            free(sum_stage[i].text);
        }
        sum_stage[i].text = NULL;
    }
    we_sha256_final(&h, dg);
    for (k = 0u; k < 8u; k++) {
        snprintf(want + 2u * k, 3, "%02x", dg[k]);
    }
    if (strncmp(name + 5, want, 16) != 0) {
        sum_conf_mismatch = 1;
        printf("conf-mismatch \"");
        we_sum_print_escaped(stdout, name);
        printf("\": its bytes digest to %s\n", want);
    }
    we_sum_close(&f);
}

/*
 * A rule-counter file, version 1 (one program, its digest byte-reversed) or version 2. Version 2 must
 * carry its writer's key line (`pidns <n> starttime <n>`) and a `pid` line naming the process the file
 * name's leading digits do; a missing line is refused like a wrong one.
 */
static void sum_read_rules(int dirfd, const char *name)
{
    static we_sum_file_t f;
    struct stat st;
    int rc, version = 0, keyed = 0, said_pid = 0;
    char program[17] = "";
    uint64_t pidns = 0u, starttime = 0u, pid, said, pre[8] = { 0 };
    size_t n = 0u, i;
    sum_writer_t *wr;

    if (sum_open(dirfd, name, &f, &st) != 0) {
        return;
    }
    pid = strtoull(name, NULL, 10);
#define SUM_RULES_REFUSE(r) do { sum_refuse(name, (r)); we_sum_close(&f); return; } while (0)
    while ((rc = we_sum_line(&f)) > 0) {
        char *p = f.line, *w[6];

        if (version == 0) {
            version = strcmp(p, "whisper-edge-rule-counters 2") == 0 ? 2 : strcmp(p, "whisper-edge-rule-counters 1") == 0 ? 1 : -1;
            if (version < 0) {
                SUM_RULES_REFUSE("not a rule-counter file");
            }
            continue;
        }
        if (we_sum_field(&p, &w[0]) != 0) {
            continue;
        }
        if (version == 2 && strcmp(w[0], "pidns") == 0) {
            if (we_sum_field(&p, &w[1]) != 0 || we_sum_u64(w[1], &pidns) != 0 || we_sum_field(&p, &w[2]) != 0
                    || strcmp(w[2], "starttime") != 0 || we_sum_field(&p, &w[3]) != 0 || we_sum_u64(w[3], &starttime) != 0) {
                SUM_RULES_REFUSE("a pidns line outside the grammar");
            }
            keyed = 1;
        } else if (version == 2 && strcmp(w[0], "pid") == 0) {
            /* the record names its writer; a file whose record names another process is not that file */
            if (we_sum_field(&p, &w[1]) != 0 || we_sum_u64(w[1], &said) != 0 || said != pid) {
                SUM_RULES_REFUSE("a pid line that is not the file name's process");
            }
            said_pid = 1;
        } else if (version == 1 && strcmp(w[0], "program") == 0) {
            uint64_t v = 0u;
            uint32_t k;

            /* a version 1 file printed the first eight digest bytes as one little-endian integer */
            if (we_sum_field(&p, &w[1]) != 0 || we_sum_hex16(w[1]) != 0) {
                SUM_RULES_REFUSE("a program line outside the grammar");
            }
            v = strtoull(w[1], NULL, 16);
            for (k = 0u; k < 8u; k++) {
                snprintf(program + 2u * k, 3, "%02x", (unsigned)((v >> (8u * k)) & 0xffu));
            }
        } else if (strcmp(w[0], "r") == 0) {
            uint64_t rule, count;
            const char *dg = version == 2 ? NULL : program;

            if (version == 2) {
                if (we_sum_field(&p, &w[1]) != 0 || we_sum_hex16(w[1]) != 0) {
                    SUM_RULES_REFUSE("a counter line whose digest is not 16 hex digits");
                }
                dg = w[1];
            }
            if (we_sum_field(&p, &w[2]) != 0 || we_sum_u64(w[2], &rule) != 0 || rule == 0u || rule > 65536u
                    || we_sum_field(&p, &w[3]) != 0 || we_sum_u64(w[3], &count) != 0 || dg[0] == '\0') {
                SUM_RULES_REFUSE("a counter line outside the grammar, or a count that overflows");
            }
#ifndef WE_SUM_TEST_EAGER_SUM
            if (sum_stage_put(n++, dg, (uint32_t)rule, count, NULL) != 0) {
                SUM_RULES_REFUSE("more counter lines than this reader stages");
            }
#else
            {   /* the control: every line summed as it is read, before the file is known to be good */
                sum_key_t *kk = sum_key(dg, (uint32_t)rule);

                if (kk != NULL) {
                    kk->count = we_sum_add(kk->count, count);
                }
            }
#endif
        } else if (version == 2 && strcmp(w[0], "pre") == 0) {
            uint64_t count;
            uint32_t k;

            if (we_sum_field(&p, &w[1]) != 0 || we_sum_field(&p, &w[2]) != 0 || we_sum_u64(w[2], &count) != 0) {
                SUM_RULES_REFUSE("a pre-stage line outside the grammar");
            }
            for (k = 0u; k < 8u && strcmp(sum_pre_name[k], w[1]) != 0; k++) {
            }
            if (k < 8u) {
#ifndef WE_SUM_TEST_EAGER_SUM
                pre[k] = we_sum_add(pre[k], count);
#else
                sum_pre[k] = we_sum_add(sum_pre[k], count);
#endif
            }
        }
    }
    if (rc < 0) {
        SUM_RULES_REFUSE("a line over the bound, a NUL byte or a read error");
    }
    if (version == 0) {
        SUM_RULES_REFUSE("an empty file");
    }
    if (version == 2 && !keyed) {
        SUM_RULES_REFUSE("no pidns line: the record does not name its writer");
    }
    if (version == 2 && !said_pid) {
        SUM_RULES_REFUSE("no pid line: the record does not name its process");
    }
#undef SUM_RULES_REFUSE
    /* the whole file read and passed: only now do its counts reach the totals and its writer */
    for (i = 0u; i < n; i++) {
        sum_key_t *kk = sum_key(sum_stage[i].digest, sum_stage[i].rule);

        if (kk != NULL) {
            kk->count = we_sum_add(kk->count, sum_stage[i].count);
        }
    }
    for (i = 0u; i < 8u; i++) {
        sum_pre[i] = we_sum_add(sum_pre[i], pre[i]);
    }
    wr = keyed ? sum_writer(pidns, starttime, pid) : NULL;
    if (wr != NULL) {
        wr->files++;
        wr->bytes += (uint64_t)st.st_size;
    }
    we_sum_close(&f);
}

/* ---- the process status files ---- */

#define SUM_MAX_PLANES 8u
typedef struct {
    char     name[24];
    char     state[24];
    uint64_t generation, ticks, pending, valid_until;
    char     digest[17];
} sum_plane_t;

typedef struct {
    char        file[256];
    uint64_t    pid, pidns, starttime, tick;
    char        boot[64];
    char        flags[128];
    int         live, foreign;
    const char *pidns_by;          /* for a writer that named no pid namespace: how this reader placed it */
    uint32_t    nplanes;
    sum_plane_t planes[SUM_MAX_PLANES];
} sum_proc_t;

static sum_proc_t *sum_procs;
static size_t sum_nprocs;

/* a bounded copy of a field the file supplied: truncated to the destination, always terminated */
static void sum_cpy(char *d, size_t n, const char *s)
{
    size_t l = strnlen(s, n - 1u);

    memcpy(d, s, l);
    d[l] = '\0';
}

static int sum_word_in(const char *w, const char *const *set)
{
    for (; *set != NULL; set++) {
        if (strcmp(w, *set) == 0) {
            return 1;
        }
    }
    return 0;
}

static void sum_read_status(int dirfd, const char *name)
{
    static we_sum_file_t f;
    struct stat st;
    int rc, first = 1, has_process = 0;
    sum_proc_t *pr;
    static const char *const flagwords[] = { "no-thread", "late-build", "client-ip-from-header", "single-process-stale", NULL };

    if (sum_nprocs >= SUM_MAX_PROCS) {
        return;
    }
    if (sum_procs == NULL && (sum_procs = calloc(SUM_MAX_PROCS, sizeof *sum_procs)) == NULL) {
        return;
    }
    if (sum_open(dirfd, name, &f, &st) != 0) {
        return;
    }
    pr = &sum_procs[sum_nprocs];
    memset(pr, 0, sizeof *pr);
    sum_cpy(pr->file, sizeof pr->file, name);
    while ((rc = we_sum_line(&f)) > 0) {
        char *p = f.line, *w;

        if (first) {
            if (strcmp(p, "whisper-edge-status 2") != 0) {
                sum_refuse(name, "not a status file of this version");
                we_sum_close(&f);
                return;
            }
            first = 0;
            continue;
        }
        if (we_sum_field(&p, &w) != 0) {
            continue;
        }
        if (strcmp(w, "process") == 0) {
            char *k, *v;

            if (we_sum_field(&p, &k) != 0) {
                break;
            }
            has_process = 1;
            while (we_sum_field(&p, &k) == 0) {
                if (sum_word_in(k, flagwords)) {
                    snprintf(pr->flags + strlen(pr->flags), sizeof pr->flags - strlen(pr->flags), "%s ", k);
                    continue;
                }
                if (we_sum_field(&p, &v) != 0) {
                    break;
                }
                if (strcmp(k, "pid") == 0) { we_sum_u64(v, &pr->pid); }
                else if (strcmp(k, "pidns") == 0) { we_sum_u64(v, &pr->pidns); }
                else if (strcmp(k, "starttime") == 0) { we_sum_u64(v, &pr->starttime); }
                else if (strcmp(k, "tick") == 0) { we_sum_u64(v, &pr->tick); }
                else if (strcmp(k, "boot") == 0) { sum_cpy(pr->boot, sizeof pr->boot, v); }
            }
        } else if (strcmp(w, "plane") == 0 && pr->nplanes < SUM_MAX_PLANES) {
            sum_plane_t *pl = &pr->planes[pr->nplanes];
            char *k, *v;

            memset(pl, 0, sizeof *pl);
            if (we_sum_field(&p, &k) != 0 || we_sum_field(&p, &v) != 0) {
                continue;
            }
            sum_cpy(pl->name, sizeof pl->name, k);
            sum_cpy(pl->state, sizeof pl->state, v);
            sum_cpy(pl->digest, sizeof pl->digest, "-");
            while (we_sum_field(&p, &k) == 0) {
                if (k[0] == '"' || strcmp(k, "data-directory-replaced") == 0 || strcmp(k, "mapped") == 0
                        || strcmp(k, "private") == 0) {
                    if (strcmp(k, "data-directory-replaced") == 0) {
                        snprintf(pr->flags + strlen(pr->flags), sizeof pr->flags - strlen(pr->flags), "%s ", k);
                    }
                    continue;
                }
                if (we_sum_field(&p, &v) != 0) {
                    break;
                }
                if (strcmp(k, "generation") == 0) { we_sum_u64(v, &pl->generation); }
                else if (strcmp(k, "ticks") == 0) { we_sum_u64(v, &pl->ticks); }
                else if (strcmp(k, "pending-ticks") == 0) { we_sum_u64(v, &pl->pending); }
                else if (strcmp(k, "valid-until") == 0) { we_sum_u64(v, &pl->valid_until); }
                else if (strcmp(k, "digest") == 0 && we_sum_hex16(v) == 0) { sum_cpy(pl->digest, sizeof pl->digest, v); }
            }
            pr->nplanes++;
        }
    }
    if (rc < 0) {
        sum_refuse(name, "a line over the bound, a NUL byte or a read error");
        we_sum_close(&f);
        return;
    }
    we_sum_close(&f);
    if (!has_process) {
        /* a status file that names no process is malformed, not a writer from another boot */
        sum_refuse(name, first ? "an empty file" : "no process line: the file names no writer");
        return;
    }
    pr->pidns_by = NULL;
    if (strcmp(pr->boot, sum_my_boot) != 0) {
        pr->foreign = 1;
    } else if (pr->pidns != 0u) {
        pr->foreign = pr->pidns != sum_my_pidns;
    } else {
        /* the writer named no namespace: this reader places the process itself (sum_reader_ns) */
        int ns = sum_reader_ns(pr->pid, &pr->pidns_by);

        pr->foreign = ns == SUM_NS_OTHER || ns == SUM_NS_UNKNOWN;
        if (ns == SUM_NS_GONE) {
            pr->pidns_by = NULL;
        }
    }
    pr->live = !pr->foreign && sum_live(pr->pid, pr->starttime);
    {
        sum_writer_t *wr = sum_writer(pr->pidns, pr->starttime, pr->pid);

        if (wr != NULL) {
            wr->has_status = 1;
            wr->live = pr->live;
            wr->foreign = pr->foreign;
            wr->files++;
            wr->bytes += (uint64_t)st.st_size;
        }
    }
    sum_nprocs++;
}

/* every entry of the directory, read once, by name class; the caps printed when hit */
static int sum_scan(const char *dir, int want_status)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int lfd;
    DIR *d;
    struct dirent *e;
    unsigned n = 0u;

    if (dfd < 0) {
        fprintf(stderr, "whisper-edge-summary: cannot read the directory\n");
        return -1;
    }
    lfd = dup(dfd);
    d = lfd >= 0 ? fdopendir(lfd) : NULL;
    if (d == NULL) {
        close(dfd);
        if (lfd >= 0) {
            close(lfd);
        }
        return -1;
    }
    sum_my_key();
    /* the status files first, so the counter files can be attributed to their writers */
    for (int pass = 0; pass < 2; pass++) {
        rewinddir(d);
        n = 0u;
        while ((e = readdir(d)) != NULL) {
            size_t len = strlen(e->d_name);

            if (e->d_name[0] == '.') {
                continue;
            }
            if (++n > SUM_MAX_ENTRIES) {
                printf("entry cap: %u directory entries read; the rest were not\n", SUM_MAX_ENTRIES);
                break;
            }
            if (pass == 0) {
                if (len == 28u && strncmp(e->d_name, "conf-", 5) == 0 && strcmp(e->d_name + 21, ".status") == 0) {
                    sum_read_conf(dfd, e->d_name);
                } else if (len > 7u && strcmp(e->d_name + len - 7u, ".status") == 0) {
                    sum_read_status(dfd, e->d_name);
                }
            } else if (len > 10u && strcmp(e->d_name + len - 10u, ".rules.cnt") == 0) {
                sum_read_rules(dfd, e->d_name);
            }
        }
    }
    (void)want_status;
    closedir(d);
    close(dfd);
    return 0;
}

static int sum_key_cmp(const void *a, const void *b)
{
    const sum_key_t *x = *(const sum_key_t *const *)a, *y = *(const sum_key_t *const *)b;
    int c = strcmp(x->digest, y->digest);

    return c != 0 ? c : x->rule < y->rule ? -1 : x->rule > y->rule;
}

static int mode_rules(const char *dir)
{
    size_t i, k = 0u, unattributed = 0u, gone_files = 0u;
    uint64_t gone_bytes = 0u;

    if (sum_scan(dir, 0) != 0) {
        return 2;
    }
    sum_key_t **order = sum_n > 0u ? malloc(sum_n * sizeof *order) : NULL;

    for (i = 0u; order != NULL && i < sum_cap; i++) {
        if (sum_keys[i].used && sum_keys[i].count != 0u) {
            order[k++] = &sum_keys[i];
        }
    }
    if (k > 1u) {
        qsort(order, k, sizeof *order, sum_key_cmp);
    }
    printf("whisper-edge rule counters, summed over every writer's file, live or gone\n");
    for (i = 0u; i < k; i++) {
        printf("r %s %u %llu %s\n", order[i]->digest, order[i]->rule, (unsigned long long)order[i]->count,
               order[i]->text != NULL ? order[i]->text : "-");
    }
    free(order);
    for (i = 0u; i < 8u; i++) {
        if (sum_pre[i] != 0u) {
            printf("pre %s %llu\n", sum_pre_name[i], (unsigned long long)sum_pre[i]);
        }
    }
    for (i = 0u; i < sum_nw; i++) {
        if (!sum_w[i].has_status) {
            unattributed++;
        }
        if (!sum_w[i].live && !sum_w[i].foreign) {
            gone_files += sum_w[i].files;
            gone_bytes += sum_w[i].bytes;
        }
    }
    printf("unattributed %zu\n", unattributed);
    printf("gone writers' files %zu, %llu bytes\n", gone_files, (unsigned long long)gone_bytes);
    if (sum_key_full) {
        printf("key cap: %u (digest, rule) keys summed; the rest were not\n", SUM_MAX_KEYS);
    }
    return sum_refused != 0u || sum_conf_mismatch ? 1 : 0;
}

static int mode_status(const char *dir)
{
    /* not `absent`: a bound path with no file yet (a fresh install before its first refresh) failed nothing */
    static const char *const bad[] = { "stale", "refused", "lapsed", "revoked", "disarmed", NULL };
    size_t i, live = 0u, gone = 0u, foreign = 0u, gone_files = 0u;
    uint64_t gone_bytes = 0u;
    uint32_t p;
    int unhealthy = 0;
    struct timespec ts;
    uint64_t now;

    if (sum_scan(dir, 1) != 0) {
        return 2;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    for (i = 0u; i < sum_nprocs; i++) {
        sum_proc_t *pr = &sum_procs[i];

        if (pr->foreign) {
            foreign++;
            continue;
        }
        if (!pr->live) {
            gone++;
            continue;
        }
        live++;
        printf("process pid %llu tick %llu%s%s%s%s\n", (unsigned long long)pr->pid, (unsigned long long)pr->tick,
               pr->flags[0] != '\0' ? " " : "", pr->flags,
               /* the flags end in a space of their own */
               pr->pidns_by == NULL ? "" : pr->flags[0] != '\0' ? "pidns-by=" : " pidns-by=",
               pr->pidns_by != NULL ? pr->pidns_by : "");
        if (pr->flags[0] != '\0') {
            unhealthy = 1;
        }
        for (p = 0u; p < pr->nplanes; p++) {
            sum_plane_t *pl = &pr->planes[p];
            int64_t remaining = pl->valid_until != 0u ? (int64_t)(pl->valid_until - now) : INT64_MAX;
            int stale = pl->valid_until != 0u && remaining < 0;

            printf("  plane %s %s generation %llu digest %s", pl->name, stale && strcmp(pl->state, "armed") == 0 ? "stale" : pl->state,
                   (unsigned long long)pl->generation, pl->digest);
            if (pl->valid_until != 0u) {
                printf(" remaining %lld", (long long)remaining);
            }
            printf("\n");
            if (sum_word_in(pl->state, bad) || stale || (strcmp(pl->state, "loading") == 0 && pl->ticks >= 2u)
                    || pl->pending >= 2u) {
                unhealthy = 1;
            }
        }
    }
    for (i = 0u; i < sum_nw; i++) {
        if (!sum_w[i].live && !sum_w[i].foreign) {
            gone_files += sum_w[i].files;
            gone_bytes += sum_w[i].bytes;
        }
    }
    printf("live %zu, gone %zu, foreign %zu (another boot or pid namespace: listed by count, never checked)\n",
           live, gone, foreign);
    printf("gone writers' files %zu, %llu bytes\n", gone_files, (unsigned long long)gone_bytes);
    printf("liveness checks made: kill(pid, 0) and /proc/<pid>/stat's start time; for a writer that named no pid "
           "namespace, /proc/<pid>/ns/pid or its NSpid (pidns-by=); /proc/<pid>/exe not compared\n");
    if (sum_uid_set) {
        printf("foreign entries %zu (not the writer uid %lu's own file: refused by name above, never read)\n",
               sum_foreign_entries, (unsigned long)sum_uid);
    }
    for (i = 0u; i < sum_nconf_refused; i++) {
        printf("configuration refused %s\n", sum_conf_refused_line[i]);   /* a host whose policy was refused */
        unhealthy = 1;
    }
    if (sum_conf_refused_full) {
        printf("configuration refused: more than %u lines; the rest were not listed\n", SUM_MAX_CONF_REFUSED);
        unhealthy = 1;
    }
    for (i = 0u; i < sum_nconf_unreadable; i++) {
        printf("configuration unreadable %s\n", sum_conf_unreadable_line[i]);   /* present, inert: misconfigured */
        unhealthy = 1;
    }
    if (sum_conf_unreadable_full) {
        printf("configuration unreadable: more than %u lines; the rest were not listed\n", SUM_MAX_CONF_REFUSED);
        unhealthy = 1;
    }
    if (sum_conf_mismatch) {
        unhealthy = 1;
    }
    if (live == 0u) {
        printf("exit 2: no live status file\n");
        return 2;
    }
    return unhealthy ? 1 : 0;
}

/* every table back to empty, for a harness that runs the modes more than once in one process */
__attribute__((unused)) static void sum_reset(void)
{
    size_t i;

    if (sum_keys != NULL) {
        for (i = 0u; i < sum_cap; i++) {
            free(sum_keys[i].text);
        }
    }
    free(sum_keys);
    free(sum_w);
    free(sum_procs);
    free(sum_stage);
    sum_stage = NULL;
    sum_stage_cap = 0u;
    free(range_stage);
    range_stage = NULL;
    range_stage_cap = 0u;
    sum_keys = NULL;
    sum_w = NULL;
    sum_procs = NULL;
    sum_cap = sum_n = sum_nw = sum_nprocs = 0u;
    sum_key_full = sum_conf_mismatch = 0;
    sum_uid_set = 0;
    sum_uid = 0;
    sum_foreign_entries = 0u;
    sum_refused = 0u;
    sum_ref_drop(sum_conf_refused_line, sum_nconf_refused);
    sum_nconf_refused = 0u;
    sum_conf_refused_full = 0;
    sum_ref_drop(sum_conf_unreadable_line, sum_nconf_unreadable);
    sum_nconf_unreadable = 0u;
    sum_conf_unreadable_full = 0;
    memset(sum_pre, 0, sizeof sum_pre);
    nrows = 0u;
    total_denied = earliest_started = latest_written = 0u;
    files_read = ranges_dropped = 0u;
}

/* the usage text, and the one place the exit codes are written down: test_summary parses the table and
 * fails if a code a mode returns is not in it, or a code in it is one no case returns */
static const char sum_usage[] =
    "usage: whisper-edge-summary <counters-dir> [top-n]   who was denied, and how often\n"
    "       whisper-edge-summary --rules <counters-dir>    per-rule counts, every writer, live or gone\n"
    "       whisper-edge-summary --status <counters-dir>   plane health\n"
    "       whisper-edge-summary --status <counters-dir> --writer-uid <uid>\n"
    "                                                      the same, reading only the files that uid owns\n"
    "       whisper-edge-summary --help                    this text, on stdout\n"
    "       the directory the module writes, e.g. /var/lib/whisper-edge/counters\n"
    "\n"
    "exit codes (2 is no answer in every form):\n"
    "  <counters-dir>  0  the summary was printed, an empty one included\n"
    "                  2  the directory cannot be read\n"
    "  --rules         0  every counter file was read and summed\n"
    "                  1  a counter file was refused, or a configuration file's name is not its digest\n"
    "                  2  the directory cannot be read\n"
    "  --status        0  every live writer is healthy\n"
    "                  1  a live writer is not: a flag on its process line, a plane stale, refused, lapsed,\n"
    "                     revoked, disarmed, stuck loading or behind its refresh, or a configuration\n"
    "                     refused, unreadable or not named by its digest\n"
    "                  2  the directory cannot be read, or no writer is live\n"
    "  --status --writer-uid  0  every live writer is healthy, on the files that uid owns; any other entry\n"
    "                     is refused by name, never read, and counted under foreign entries\n"
    "                  1  a live writer is not healthy, read from the files that uid owns\n"
    "                  2  the directory cannot be read, no writer of that uid is live (its status file\n"
    "                     owned by another uid, open to another uid's write, linked twice or a link), or\n"
    "                     the uid is neither a number nor a user this host knows\n"
    "  --help          0  always\n"
    "  any other form  2  the arguments are none of the forms above; this text goes to stderr\n";

int main(int argc, char **argv)
{
    const char *dir;
    DIR *d;
    struct dirent *e;
    size_t i, shown;
    size_t top = 5;
    char since[64], window[64];

    if (argc == 3 && strcmp(argv[1], "--rules") == 0) {
        return mode_rules(argv[2]);
    }
    if (argc == 3 && strcmp(argv[1], "--status") == 0) {
        return mode_status(argv[2]);
    }
    if (argc == 5 && (strcmp(argv[1], "--writer-uid") == 0 || strcmp(argv[3], "--writer-uid") == 0)) {
        /* --status <dir> --writer-uid <uid>, in either order; a uid as a decimal number or a user name */
        int at = strcmp(argv[1], "--writer-uid") == 0 ? 1 : 3, st = at == 1 ? 3 : 1;
        uint64_t v;

        if (strcmp(argv[st], "--status") != 0) {
            fprintf(stderr, "whisper-edge-summary: --writer-uid goes with --status <counters-dir>\n");
            return 2;
        }
        if (we_sum_u64(argv[at + 1], &v) == 0) {
            if (v >= (uint64_t)(uid_t)-1 || (uint64_t)(uid_t)v != v) {
                fprintf(stderr, "whisper-edge-summary: --writer-uid %s: not a uid\n", argv[at + 1]);
                return 2;
            }
            sum_uid = (uid_t)v;
        } else {
            struct passwd *pw = getpwnam(argv[at + 1]);

            if (pw == NULL) {
                fprintf(stderr, "whisper-edge-summary: --writer-uid ");
                we_sum_print_escaped(stderr, argv[at + 1]);
                fprintf(stderr, ": neither a uid nor a user this host knows\n");
                return 2;
            }
            sum_uid = pw->pw_uid;
        }
        sum_uid_set = 1;
        return mode_status(argv[st + 1]);
    }
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        fputs(sum_usage, stdout);
        return 0;
    }
    /* a mode without its directory, an option this tool does not have, or nothing at all: the usage, never
     * an attempt to read a directory named `--status` (a directory whose name starts with '-' is ./-name) */
    if (argc < 2 || argv[1][0] == '-' || argc > 3) {
        fputs(sum_usage, stderr);
        return 2;
    }
    dir = argv[1];
    if (argc > 2) {
        long n = strtol(argv[2], NULL, 10);

        if (n > 0 && (size_t) n < MAX_RANGES) {
            top = (size_t) n;
        }
    }
    d = opendir(dir);
    if (d == NULL) {
        fprintf(stderr, "whisper-edge-summary: cannot read %s\n", dir);
        fprintf(stderr,
                "  This is the directory the module writes its counters into. If the module has not\n"
                "  been given one, or cannot write to it, there is nothing to summarise - which is a\n"
                "  different thing from having blocked nothing.\n");
#ifdef WE_SUM_TEST_EXIT_DRIFT
        return 1;   /* the control: a code changed and the usage table not */
#endif
        return 2;   /* no answer, as in every form */
    }
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);

        if (len < 5 || strcmp(e->d_name + len - 4, ".cnt") != 0 || e->d_name[0] == '.'
                || (len > 10 && strcmp(e->d_name + len - 10, ".rules.cnt") == 0)) {
            continue;
        }
        read_file(dirfd(d), e->d_name);
    }
    closedir(d);

    if (files_read == 0) {
        printf("No Whisper edge counters in %s yet.\n", dir);
        printf("The module writes one file per worker process when it reloads the snapshot, so a\n");
        printf("freshly started server has nothing here until its first refresh.\n");
        return 0;
    }

    iso_utc(earliest_started, since, sizeof(since));
    human_window(latest_written > earliest_started ? latest_written - earliest_started : 0,
                 window, sizeof(window));

    if (nrows > 1u) {
        qsort(rows, nrows, sizeof(rows[0]), by_hits);
    }

    printf("Whisper edge, %s of blocking\n", window);
    printf("counting since %s, across %zu worker process%s\n\n",
           since, files_read, files_read == 1 ? "" : "es");
    printf("  %" PRIu64 " request%s denied\n", total_denied, total_denied == 1 ? "" : "s");
    printf("  (a deny under mode log is counted too: that request was allowed, and logged as a would-deny)\n");
    printf("  from %zu network%s\n", nrows, nrows == 1 ? "" : "s");
    if (nrows == 0) {
        printf("\nNothing was denied in this window. That is the normal state of a small site.\n");
        printf("\nEvery number here was counted on this host. Nothing was sent anywhere to produce it.\n");
        return 0;
    }
    printf("\nworst offenders:\n");
    shown = nrows < top ? nrows : top;
    for (i = 0; i < shown; i++) {
        /* the range and its evidence come from a file anyone on the host could have written: escaped */
        printf("  ");
        we_sum_print_escaped(stdout, rows[i].range);
        printf(" %8" PRIu64 "  %-8s ", rows[i].hits, sev_name(rows[i].sev));
        if (rows[i].evidence[0] == '\0') {
            printf("(no evidence recorded)");
        } else {
            we_sum_print_escaped(stdout, rows[i].evidence);
        }
        printf("\n");
    }
    if (nrows > shown) {
        printf("  ... and %zu more network%s\n", nrows - shown, (nrows - shown) == 1 ? "" : "s");
    }
    if (ranges_dropped > 0) {
        printf("\n%zu range%s past this tool's %d-row limit were NOT counted in the figures above.\n",
               ranges_dropped, ranges_dropped == 1 ? "" : "s", MAX_RANGES);
    }
    printf("\nEvery number here was counted on this host. Nothing was sent anywhere to produce it.\n");
    return 0;
}
