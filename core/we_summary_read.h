/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_summary_read.h - the summary's reader of the counters directory, which it treats as HOSTILE.
 *
 * The directory is writable by every server user, which on a shared host is tenant code. So every entry
 * is opened with O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC relative to the directory's own
 * descriptor and must be a regular file by fstat, so a FIFO, a device or a symlink is refused without
 * blocking; a file is read as a stream of lines, each at most WE_SUM_LINE_MAX bytes, so memory is one
 * line plus the tables, which are capped; and a refusal names the file and never echoes its bytes.
 * Every free-text field is kept and printed in its escaped form (`\\`, `\"`, `\xHH` for every byte
 * outside 0x20..0x7e), whatever the output is, so no byte a tenant planted reaches a terminal raw.
 *
 * Header-only and static, so whisper-edge-summary and fuzz_summary read files the same way.
 */
#ifndef WE_SUMMARY_READ_H
#define WE_SUMMARY_READ_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* the longest line a writer emits: a 2,048-byte rule text escaped to at most 8,192, and its fields */
#define WE_SUM_LINE_MAX 8320u

typedef struct {
    int      fd;
    size_t   off, len;          /* the buffered bytes [off, len) */
    int      eof, bad;          /* bad: a line over the bound, a NUL, or a read error */
    uint64_t bytes;
    char     buf[2u * WE_SUM_LINE_MAX];
    char     line[WE_SUM_LINE_MAX + 1u];
} we_sum_file_t;

/*
 * Open `name` in the directory `dirfd` as the reader must: never following a link, never blocking on a
 * FIFO, a regular file or nothing. 0, or -1 with *why set to a fixed reason (never the file's bytes).
 */
static inline int we_sum_open(int dirfd, const char *name, we_sum_file_t *f, struct stat *st, const char **why)
{
#ifndef WE_MOD_TEST_STATUS_FOLLOWS
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
#else
    int fd = openat(dirfd, name, O_RDONLY | O_NONBLOCK | O_CLOEXEC);    /* the control: a link followed */
#endif

    memset(f, 0, sizeof *f);
    f->fd = -1;
    if (fd < 0) {
        *why = errno == ELOOP ? "a symbolic link" : "cannot be opened";
        return -1;
    }
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        *why = "not a regular file";
        return -1;
    }
    f->fd = fd;
    return 0;
}

static inline void we_sum_close(we_sum_file_t *f)
{
    if (f->fd >= 0) {
        close(f->fd);
    }
    f->fd = -1;
}

/*
 * The next line, without its LF, in f->line. 1 for a line, 0 at the end, -1 for a line over the bound,
 * a NUL byte or a read error (the file is then refused whole).
 */
static inline int we_sum_line(we_sum_file_t *f)
{
    for (;;) {
        char *nl = f->off < f->len ? memchr(f->buf + f->off, '\n', f->len - f->off) : NULL;

        if (nl != NULL || (f->eof && f->off < f->len)) {
            size_t n = nl != NULL ? (size_t)(nl - (f->buf + f->off)) : f->len - f->off;

#ifndef WE_SUM_TEST_NO_LINE_BOUND
            if (n > WE_SUM_LINE_MAX || memchr(f->buf + f->off, '\0', n) != NULL) {
#else
            if (memchr(f->buf + f->off, '\0', n) != NULL) {     /* the control: no bound on a line */
#endif
                f->bad = 1;
                return -1;
            }
            memcpy(f->line, f->buf + f->off, n);
            f->line[n] = '\0';
            f->off += n + (nl != NULL ? 1u : 0u);
            return 1;
        }
        if (f->eof) {
            return 0;
        }
#ifndef WE_SUM_TEST_NO_LINE_BOUND
        if (f->len - f->off > WE_SUM_LINE_MAX) {
            f->bad = 1;
            return -1;
        }
#else
        if (f->len == sizeof f->buf && f->off == 0u) {
            f->eof = 1;                       /* the control reads on past the bound instead */
            continue;
        }
#endif
        memmove(f->buf, f->buf + f->off, f->len - f->off);
        f->len -= f->off;
        f->off = 0u;
        {
            ssize_t r = read(f->fd, f->buf + f->len, sizeof f->buf - f->len);

            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                f->bad = 1;
                return -1;
            }
            if (r == 0) {
                f->eof = 1;
            }
            f->len += (size_t)r;
            f->bytes += (uint64_t)r;
        }
    }
}

/* a decimal uint64 that fits, the whole token; 0 or -1 */
static inline int we_sum_u64(const char *s, uint64_t *v)
{
    uint64_t x = 0u;

    if (*s == '\0') {
        return -1;
    }
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9' || x > (UINT64_MAX - (uint64_t)(*s - '0')) / 10u) {
            return -1;
        }
        x = x * 10u + (uint64_t)(*s - '0');
    }
    *v = x;
    return 0;
}

/* a signed decimal int64 */
static inline int we_sum_i64(const char *s, int64_t *v)
{
    uint64_t u;
    int neg = *s == '-';

    if (we_sum_u64(s + neg, &u) != 0 || u > (uint64_t)INT64_MAX) {
        return -1;
    }
    *v = neg ? -(int64_t)u : (int64_t)u;
    return 0;
}

/* exactly 16 lowercase hex digits */
static inline int we_sum_hex16(const char *s)
{
    size_t i;

    for (i = 0u; i < 16u; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return -1;
        }
    }
    return s[16] == '\0' ? 0 : -1;
}

/*
 * The next whitespace-separated field of a line, a quoted string kept in its ESCAPED form and checked
 * against the grammar (only \\, \" and \xHH escapes, no raw byte outside 0x20..0x7e). Advances *p.
 * 0, or -1 for a malformed field.
 */
static inline int we_sum_field(char **p, char **out)
{
    char *s = *p;

    while (*s == ' ') {
        s++;
    }
    if (*s == '\0') {
        return -1;
    }
    *out = s;
    if (*s == '"') {
        s++;
        for (;;) {
            if (*s == '\0') {
                return -1;
            }
            if ((unsigned char)*s < 0x20u || (unsigned char)*s > 0x7eu) {
                return -1;
            }
            if (*s == '\\') {
                if (s[1] == '\\' || s[1] == '"') {
                    s += 2;
                    continue;
                }
                if (s[1] == 'x' && s[2] != '\0' && s[3] != '\0'
                        && strchr("0123456789abcdefABCDEF", s[2]) != NULL && strchr("0123456789abcdefABCDEF", s[3]) != NULL) {
                    s += 4;
                    continue;
                }
                return -1;
            }
            if (*s == '"') {
                s++;
                break;
            }
            s++;
        }
        if (*s != '\0' && *s != ' ') {
            return -1;
        }
    } else {
        while (*s != '\0' && *s != ' ') {
            if ((unsigned char)*s <= 0x20u || (unsigned char)*s > 0x7eu) {
                return -1;
            }
            s++;
        }
    }
    if (*s == ' ') {
        *s++ = '\0';
    }
    *p = s;
    return 0;
}

/* a + b, saturating: a planted near-maximal count never wraps a total */
static inline uint64_t we_sum_add(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

/*
 * Print bytes escaped: every byte outside 0x20..0x7e, and `\` and `"`, as an escape. For a name read
 * from a directory listing, which is not a field and so was never escaped by a writer.
 */
static inline void we_sum_print_escaped(FILE *o, const char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;

        if (c == '\\' || c == '"') {
            fprintf(o, "\\%c", c);
        } else if (c < 0x20u || c > 0x7eu) {
            fprintf(o, "\\x%02x", c);
        } else {
            fputc(c, o);
        }
    }
}

#endif /* WE_SUMMARY_READ_H */
