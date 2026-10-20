/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * lookup_shim.c - an LD_PRELOAD shim the lookup gate puts under whisper-edge-lookup alone.
 *
 * Two parts, each switched on by its own variable, and a count file that proves which process it ran in.
 *
 * The clock part (LOOKUP_SHIM_CLOCK=1) interposes every wall-clock entry point: clock_gettime for every
 * clock but the monotonic, boot-time and CPU ones, gettimeofday, time, timespec_get and ftime. It counts
 * the calls, and with LOOKUP_SHIM_ADVANCE_MS=<ms> every call after the first returns that instant, so a
 * tool that read the clock twice would judge a plane at two instants and the gate would see it.
 *
 * The open part (LOOKUP_SHIM_PATHS=<path>[:<path>...]) interposes open, open64, openat, openat64,
 * __open_2 and __open64_2, and counts the calls naming each listed path. A relative name is resolved
 * first: against getcwd() for AT_FDCWD, against readlink(/proc/self/fd/<dirfd>) for a directory
 * descriptor, because the tool reaches its manifests through descriptors. LOOKUP_SHIM_FAIL_PATH=<path>
 * with LOOKUP_SHIM_FAIL_AT=<n>[,<n>...] and LOOKUP_SHIM_FAIL_ERRNO=EACCES|ENOENT fails those ordinals of
 * that path's opens with that errno.
 *
 * The appear part (LOOKUP_SHIM_APPEAR_PATH=<path>, LOOKUP_SHIM_APPEAR_AFTER=<n>,
 * LOOKUP_SHIM_APPEAR_FROM=<file>) interposes stat and stat64, counts the calls naming <path>, and
 * hard-links <file> to <path> as the n-th returns, so a plane appears at an exact point between the
 * tool's looks at it (every look at an absent plane path begins with a stat()). It needs glibc 2.33 or
 * later, where stat and stat64 are exported functions; before that they were inline wrappers over
 * __xstat, which this part does not interpose, so on an older libc the count stays 0 and W13 says so.
 *
 * The deny part (LOOKUP_SHIM_DENY_DIR=<dir>) makes <dir> one this uid cannot search or read, at any uid,
 * root included: open, open64, openat, openat64, __open_2, __open64_2, stat, stat64, lstat, lstat64,
 * fstatat and fstatat64 of a path inside it fail with EACCES, and an open of <dir> itself fails with
 * EACCES, while a stat of <dir> itself answers, as for a mode-000 directory in a searchable parent. It
 * does NOT cover access, faccessat, statx, opendir or readlink: a caller of those inside <dir> sees the
 * real directory, so a case that reaches one of them is not proved by this part until it is added here.
 *
 * The owner part (LOOKUP_SHIM_FOREIGN=<path>) interposes fstat, fstat64, fstatat and fstatat64, and
 * reports the file at <path> as owned by another user (st_uid one above the caller's, or 65534), so the
 * gate can show a manifest another user owns being refused without making one: no privilege needed.
 *
 * LOOKUP_SHIM_OUT=<file>: the constructor creates <file>.<pid> and the exit path writes the counts into
 * it, one `clock <n>` line and one `open <n> <path>` line per listed path. Exactly one such file after a
 * run is the gate's proof that the shim was loaded into exactly one process; zero or two fail the row.
 *
 * Built with -DLOOKUP_SHIM_PROBE it is instead the control program: `probe clock`, `probe open <file>`,
 * `probe openat <dir> <name>` and `probe openat-cwd <dir> <name>` each make exactly one such call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef LOOKUP_SHIM_PROBE

#define MAX_PATHS 16

static unsigned long clock_calls;
static unsigned long path_opens[MAX_PATHS];
static char *paths[MAX_PATHS];
static int npaths = -1;
static char out_path[PATH_MAX];
static int clock_on;
static long long advance_ms = -1;
static int fail_idx = -1;
static unsigned long fail_at[32];
static int nfail;
static int fail_errno = EACCES;
static char foreign[PATH_MAX];
static char deny_dir[PATH_MAX];
static int appear_idx = -1;
static unsigned long appear_after;
static char appear_from[PATH_MAX];
static int appear_pending;
static unsigned long appear_stats;

static void shim_init(void)
{
    const char *s;

    if (npaths >= 0) {
        return;
    }
    npaths = 0;
    clock_on = (s = getenv("LOOKUP_SHIM_CLOCK")) != NULL && s[0] == '1';
    if ((s = getenv("LOOKUP_SHIM_ADVANCE_MS")) != NULL && s[0]) {
        advance_ms = atoll(s);
    }
    if ((s = getenv("LOOKUP_SHIM_PATHS")) != NULL && s[0]) {
        char *copy = strdup(s), *tok, *save = NULL;

        for (tok = strtok_r(copy, ":", &save); tok && npaths < MAX_PATHS; tok = strtok_r(NULL, ":", &save)) {
            paths[npaths++] = strdup(tok);
        }
        free(copy);
    }
    if ((s = getenv("LOOKUP_SHIM_FAIL_PATH")) != NULL && s[0]) {
        int i;

        for (i = 0; i < npaths; i++) {
            if (strcmp(paths[i], s) == 0) {
                fail_idx = i;
            }
        }
        if (fail_idx < 0 && npaths < MAX_PATHS) {
            paths[npaths] = strdup(s);
            fail_idx = npaths++;
        }
    }
    if ((s = getenv("LOOKUP_SHIM_FAIL_AT")) != NULL && s[0]) {
        char *copy = strdup(s), *tok, *save = NULL;

        for (tok = strtok_r(copy, ",", &save); tok && nfail < 32; tok = strtok_r(NULL, ",", &save)) {
            fail_at[nfail++] = strtoul(tok, NULL, 10);
        }
        free(copy);
    }
    if ((s = getenv("LOOKUP_SHIM_FAIL_ERRNO")) != NULL && strcmp(s, "ENOENT") == 0) {
        fail_errno = ENOENT;
    }
    if ((s = getenv("LOOKUP_SHIM_FOREIGN")) != NULL && s[0]) {
        snprintf(foreign, sizeof foreign, "%s", s);
    }
    if ((s = getenv("LOOKUP_SHIM_DENY_DIR")) != NULL && s[0]) {
        snprintf(deny_dir, sizeof deny_dir, "%s", s);
    }
    if ((s = getenv("LOOKUP_SHIM_APPEAR_PATH")) != NULL && s[0]) {
        const char *from = getenv("LOOKUP_SHIM_APPEAR_FROM"), *after = getenv("LOOKUP_SHIM_APPEAR_AFTER");
        int i;

        for (i = 0; i < npaths; i++) {
            if (strcmp(paths[i], s) == 0) {
                appear_idx = i;
            }
        }
        if (appear_idx < 0 && npaths < MAX_PATHS) {
            paths[npaths] = strdup(s);
            appear_idx = npaths++;
        }
        appear_after = after != NULL ? strtoul(after, NULL, 10) : 0;
        snprintf(appear_from, sizeof appear_from, "%s", from != NULL ? from : "");
    }
}

static void write_counts(void)
{
    FILE *f;
    int i;

    if (out_path[0] == '\0') {
        return;
    }
    f = fopen(out_path, "w");
    if (f == NULL) {
        return;
    }
    fprintf(f, "clock %lu\n", clock_calls);
    for (i = 0; i < npaths; i++) {
        fprintf(f, "open %lu %s\n", path_opens[i], paths[i]);
    }
    if (appear_idx >= 0) {
        fprintf(f, "stat %lu %s\n", appear_stats, paths[appear_idx]);
    }
    fclose(f);
}

__attribute__((constructor)) static void shim_ctor(void)
{
    const char *o = getenv("LOOKUP_SHIM_OUT");

    shim_init();
    if (o != NULL && o[0]) {
        FILE *f;

        snprintf(out_path, sizeof out_path, "%s.%ld", o, (long)getpid());
        f = fopen(out_path, "w");
        if (f != NULL) {
            fclose(f);
        }
        atexit(write_counts);
    }
}

/* "/a/./b//c" -> "/a/b/c": enough normalisation for paths the gate builds */
static void tidy(char *p)
{
    char *r = p, *w = p;

    while (*r) {
        if (r[0] == '/' && r[1] == '/') {
            r++;
            continue;
        }
        if (r[0] == '/' && r[1] == '.' && (r[2] == '/' || r[2] == '\0')) {
            r += 2;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static int resolve(int dirfd, const char *name, char *out, size_t n)
{
    char base[PATH_MAX];

    if (name == NULL) {
        return 0;
    }
    if (name[0] == '/') {
        snprintf(out, n, "%s", name);
    } else if (dirfd == AT_FDCWD) {
        if (getcwd(base, sizeof base) == NULL) {
            return 0;
        }
        snprintf(out, n, "%s/%s", base, name);
    } else {
        char link[64];
        ssize_t k;

        snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
        k = readlink(link, base, sizeof base - 1);
        if (k < 0) {
            return 0;
        }
        base[k] = '\0';
        snprintf(out, n, "%s/%s", base, name);
    }
    tidy(out);
    return 1;
}

/* the deny part: 1 (errno EACCES) when this look at `name` is refused; `self` when the dir itself counts */
static int denied(int dirfd, const char *name, int self)
{
    char full[2 * PATH_MAX + 2];
    size_t n;

    shim_init();
    if (deny_dir[0] == '\0' || !resolve(dirfd, name, full, sizeof full)) {
        return 0;
    }
    n = strlen(deny_dir);
    if (strncmp(full, deny_dir, n) == 0 && (full[n] == '/' || (self && full[n] == '\0'))) {
        errno = EACCES;
        return 1;
    }
    return 0;
}

/* count an open of `name`; returns -1 with errno set when this ordinal is to fail */
static int count_open(int dirfd, const char *name)
{
    char full[2 * PATH_MAX + 2];
    int i, k;

    shim_init();
    if (denied(dirfd, name, 1)) {
        return -1;
    }
    if (npaths <= 0 || !resolve(dirfd, name, full, sizeof full)) {
        return 0;
    }
    for (i = 0; i < npaths; i++) {
        if (strcmp(paths[i], full) == 0) {
            path_opens[i]++;
            if (i == fail_idx) {
                for (k = 0; k < nfail; k++) {
                    if (fail_at[k] == path_opens[i]) {
                        errno = fail_errno;
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

/* after a stat returns: make the planted file appear when this was the chosen call; errno is kept */
static int after_stat(int r)
{
    if (appear_pending) {
        int e = errno;

        appear_pending = 0;
        if (link(appear_from, paths[appear_idx]) != 0) {
            fprintf(stderr, "lookup_shim: cannot link %s to %s\n", appear_from, paths[appear_idx]);
        }
        errno = e;
    }
    return r;
}

#define NEXT(name, type) static type real_##name; if (real_##name == NULL) real_##name = (type)dlsym(RTLD_NEXT, #name)

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef int (*open2_fn)(const char *, int);

static mode_t mode_arg(int flags, va_list ap)
{
    return (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE ? (mode_t)va_arg(ap, int) : 0;
}

int open(const char *path, int flags, ...)
{
    va_list ap;
    mode_t m;
    NEXT(open, open_fn);

    va_start(ap, flags);
    m = mode_arg(flags, ap);
    va_end(ap);
    if (count_open(AT_FDCWD, path) < 0) {
        return -1;
    }
    return real_open(path, flags, m);
}

int open64(const char *path, int flags, ...)
{
    va_list ap;
    mode_t m;
    NEXT(open64, open_fn);

    va_start(ap, flags);
    m = mode_arg(flags, ap);
    va_end(ap);
    if (count_open(AT_FDCWD, path) < 0) {
        return -1;
    }
    return real_open64(path, flags, m);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t m;
    NEXT(openat, openat_fn);

    va_start(ap, flags);
    m = mode_arg(flags, ap);
    va_end(ap);
    if (count_open(dirfd, path) < 0) {
        return -1;
    }
    return real_openat(dirfd, path, flags, m);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t m;
    NEXT(openat64, openat_fn);

    va_start(ap, flags);
    m = mode_arg(flags, ap);
    va_end(ap);
    if (count_open(dirfd, path) < 0) {
        return -1;
    }
    return real_openat64(dirfd, path, flags, m);
}

int __open_2(const char *path, int flags);
int __open_2(const char *path, int flags)
{
    NEXT(__open_2, open2_fn);

    if (count_open(AT_FDCWD, path) < 0) {
        return -1;
    }
    return real___open_2(path, flags);
}

int __open64_2(const char *path, int flags);
int __open64_2(const char *path, int flags)
{
    NEXT(__open64_2, open2_fn);

    if (count_open(AT_FDCWD, path) < 0) {
        return -1;
    }
    return real___open64_2(path, flags);
}

/* ---- the appearance ---- */

typedef int (*stat_fn)(const char *, struct stat *);
typedef int (*stat64_fn)(const char *, struct stat64 *);

static void count_stat(const char *name)
{
    char full[2 * PATH_MAX + 2];

    shim_init();
    if (appear_idx >= 0 && appear_from[0] != '\0' && resolve(AT_FDCWD, name, full, sizeof full)
        && strcmp(full, paths[appear_idx]) == 0 && ++appear_stats == appear_after) {
        appear_pending = 1;
    }
}

int stat(const char *path, struct stat *st)
{
    NEXT(stat, stat_fn);

    if (denied(AT_FDCWD, path, 0)) {
        return -1;
    }
    count_stat(path);
    return after_stat(real_stat(path, st));
}

int stat64(const char *path, struct stat64 *st)
{
    NEXT(stat64, stat64_fn);

    if (denied(AT_FDCWD, path, 0)) {
        return -1;
    }
    count_stat(path);
    return after_stat(real_stat64(path, st));
}

int lstat(const char *path, struct stat *st)
{
    NEXT(lstat, stat_fn);

    if (denied(AT_FDCWD, path, 0)) {
        return -1;
    }
    return real_lstat(path, st);
}

int lstat64(const char *path, struct stat64 *st)
{
    NEXT(lstat64, stat64_fn);

    if (denied(AT_FDCWD, path, 0)) {
        return -1;
    }
    return real_lstat64(path, st);
}

/* ---- the owner ---- */

typedef int (*fstat_fn)(int, struct stat *);
typedef int (*fstat64_fn)(int, struct stat64 *);
typedef int (*fstatat_fn)(int, const char *, struct stat *, int);
typedef int (*fstatat64_fn)(int, const char *, struct stat64 *, int);

/* a uid that is neither the caller's nor root's */
static uid_t other_uid(void)
{
    uid_t me = getuid();

    return me == 65534 ? (uid_t)65533 : me == 0 ? (uid_t)65534 : me + 1;
}

/* whether the file behind a descriptor is the one to report as foreign */
static int foreign_fd(int fd)
{
    char link[64], full[PATH_MAX];
    ssize_t k;

    shim_init();
    if (foreign[0] == '\0') {
        return 0;
    }
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    k = readlink(link, full, sizeof full - 1);
    if (k < 0) {
        return 0;
    }
    full[k] = '\0';
    return strcmp(full, foreign) == 0;
}

static int foreign_at(int dirfd, const char *name)
{
    char full[2 * PATH_MAX + 2];

    shim_init();
    return foreign[0] != '\0' && resolve(dirfd, name, full, sizeof full) && strcmp(full, foreign) == 0;
}

int fstat(int fd, struct stat *st)
{
    int rc;
    NEXT(fstat, fstat_fn);

    rc = real_fstat(fd, st);
    if (rc == 0 && foreign_fd(fd)) {
        st->st_uid = other_uid();
    }
    return rc;
}

int fstat64(int fd, struct stat64 *st)
{
    int rc;
    NEXT(fstat64, fstat64_fn);

    rc = real_fstat64(fd, st);
    if (rc == 0 && foreign_fd(fd)) {
        st->st_uid = other_uid();
    }
    return rc;
}

int fstatat(int dirfd, const char *name, struct stat *st, int flags)
{
    int rc;
    NEXT(fstatat, fstatat_fn);

    if (name[0] != '\0' && denied(dirfd, name, 0)) {
        return -1;
    }
    rc = real_fstatat(dirfd, name, st, flags);
    if (rc == 0 && foreign_at(dirfd, name)) {
        st->st_uid = other_uid();
    }
    return rc;
}

int fstatat64(int dirfd, const char *name, struct stat64 *st, int flags)
{
    int rc;
    NEXT(fstatat64, fstatat64_fn);

    if (name[0] != '\0' && denied(dirfd, name, 0)) {
        return -1;
    }
    rc = real_fstatat64(dirfd, name, st, flags);
    if (rc == 0 && foreign_at(dirfd, name)) {
        st->st_uid = other_uid();
    }
    return rc;
}

/* ---- the clock ---- */

static int wall_clock(clockid_t c)
{
    return c != CLOCK_MONOTONIC && c != CLOCK_MONOTONIC_RAW && c != CLOCK_MONOTONIC_COARSE
        && c != CLOCK_BOOTTIME && c != CLOCK_PROCESS_CPUTIME_ID && c != CLOCK_THREAD_CPUTIME_ID;
}

/* counts a wall-clock read; returns 1 when the reading is to be replaced by the advanced instant */
static int clock_read(void)
{
    shim_init();
    if (!clock_on) {
        return 0;
    }
    clock_calls++;
    return advance_ms >= 0 && clock_calls > 1;
}

typedef int (*cg_fn)(clockid_t, struct timespec *);
typedef int (*gtod_fn)(struct timeval *, void *);
typedef time_t (*time_fn)(time_t *);
typedef int (*tsg_fn)(struct timespec *, int);
typedef int (*ftime_fn)(void *);

int clock_gettime(clockid_t c, struct timespec *ts)
{
    int rc;
    NEXT(clock_gettime, cg_fn);

    rc = real_clock_gettime(c, ts);
    if (rc == 0 && wall_clock(c) && clock_read()) {
        ts->tv_sec = (time_t)(advance_ms / 1000);
        ts->tv_nsec = (long)(advance_ms % 1000) * 1000000L;
    }
    return rc;
}

int gettimeofday(struct timeval *tv, void *tz)
{
    int rc;
    NEXT(gettimeofday, gtod_fn);

    rc = real_gettimeofday(tv, tz);
    if (rc == 0 && clock_read()) {
        tv->tv_sec = (time_t)(advance_ms / 1000);
        tv->tv_usec = (suseconds_t)((advance_ms % 1000) * 1000);
    }
    return rc;
}

time_t time(time_t *t)
{
    time_t v;
    NEXT(time, time_fn);

    v = real_time(NULL);
    if (clock_read()) {
        v = (time_t)(advance_ms / 1000);
    }
    if (t != NULL) {
        *t = v;
    }
    return v;
}

int timespec_get(struct timespec *ts, int base)
{
    int rc;
    NEXT(timespec_get, tsg_fn);

    rc = real_timespec_get(ts, base);
    if (rc != 0 && clock_read()) {
        ts->tv_sec = (time_t)(advance_ms / 1000);
        ts->tv_nsec = (long)(advance_ms % 1000) * 1000000L;
    }
    return rc;
}

int ftime(void *tp);
int ftime(void *tp)
{
    NEXT(ftime, ftime_fn);

    (void)clock_read();
    return real_ftime != NULL ? real_ftime(tp) : -1;
}

#else /* LOOKUP_SHIM_PROBE: the control program */

int main(int argc, char **argv)
{
    int fd = -1;

    if (argc >= 2 && strcmp(argv[1], "clock") == 0) {
        struct timespec ts;

        return clock_gettime(CLOCK_REALTIME, &ts) == 0 ? 0 : 1;
    }
    if (argc >= 3 && strcmp(argv[1], "open") == 0) {
        fd = open(argv[2], O_RDONLY);
    } else if (argc >= 4 && strcmp(argv[1], "openat") == 0) {
        int d = open(argv[2], O_RDONLY | O_DIRECTORY);

        fd = openat(d, argv[3], O_RDONLY);
        close(d);
    } else if (argc >= 4 && strcmp(argv[1], "openat-cwd") == 0) {
        if (chdir(argv[2]) != 0) {
            return 1;
        }
        fd = openat(AT_FDCWD, argv[3], O_RDONLY);
    } else {
        fprintf(stderr, "usage: probe clock | open <file> | openat <dir> <name> | openat-cwd <dir> <name>\n");
        return 2;
    }
    if (fd >= 0) {
        close(fd);
    }
    return fd >= 0 ? 0 : 1;
}
#endif
