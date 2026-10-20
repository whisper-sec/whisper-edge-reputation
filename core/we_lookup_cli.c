/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * we_lookup_cli.c - whisper-edge-lookup: every attribute of an address, with its plane and provenance.
 *
 * The question it answers is the one an operator asks when a request was refused or let through: what
 * did each data plane on this disk say about this address, which of those planes were fresh, stale,
 * absent or refused, what does the feed's manifest say about where each plane came from, and what does
 * the module decide. It reads the directory the way the module does (the same loader, the same plane
 * names, the same staleness test), it never fetches anything, never holds a key and never verifies a
 * signature: a manifest it finds is read, bound to a plane only through an entry naming that plane's
 * exact bytes, and printed as `verified=not-by-this-tool`, which is true in every case.
 *
 * Two output forms, one content: lines (`<kind> <positional>... <key>=<value>...`) and one JSON
 * document, both stable across releases under the rules `--help` prints. An attribute whose plane is
 * stale, absent, refused or withheld prints UNKNOWN with the reason, never a value.
 *
 * Nothing it prints about a decision is its own reckoning. The policy is compiled by the policy compiler
 * the modules use, the planes are armed through the module's own handles, every attribute value is the
 * one the evaluator's fill wrote into its memo, rendered by the evaluator's exported renderer, and the
 * verdict and cost lines are the evaluator's own, formatted by its exported formatter. `--case` prints
 * the request it judged as a case block the reference interpreter reads, so a second evaluator can judge
 * the same request without this tool.
 *
 * Exit status: 0 every address allowed, 1 an address denied with enforcement, 2 a usage error or an
 * address that is not one. The old form, `whisper-edge-lookup [--threshold L] <file> <address>...`,
 * keeps its contract: 1 when the snapshot is fresh and the threshold denies, whatever the mode.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE                /* inet_aton, to name the four-part form of a short IPv4 address */
#endif

#include "whisper_edge.h"
#include "we_policy.h"
#include "we_eval.h"
#include "we_sha256.h"
#include "we_record_fields.h"
#include "we_plane_tier.h"
#include "we_hold_harmless_cite.h"
#include "we_default_policy.h"
#include "we_lookup_guard.h"
#include "we_module.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef WE_TRACE
/*
 * The trace build's hooks. The tool is a WE_TRACE build so that the evaluator keeps its cost counters;
 * the read and instruction hooks count nothing, and the K3 hook counts the one state the evaluator can
 * never reach, (1, 1): true and false at once. A nonzero count is an internal error the run reports.
 */
static unsigned long g_k3_impossible;

void we_trace_read(const void *p, size_t len)
{
    (void)p;
    (void)len;
}

void we_trace_eval(const void *p, size_t len)
{
    (void)p;
    (void)len;
}

void we_trace_op(uint32_t op, uint64_t t, uint64_t f)
{
    (void)op;
    (void)t;
    (void)f;
}

void we_trace_k3(uint64_t t, uint64_t f)
{
#ifdef WE_LOOKUP_TEST_K3_HOOK_NOOP
    (void)t;
    (void)f;
#else
    if ((t & f) != 0u) {
        g_k3_impossible++;
    }
#endif
}
#endif

#define LOOKUP_FORMAT      1
#define MAX_MS             253402300799999LL      /* 9999-12-31T23:59:59.999Z */
#define MANIFEST_MAX       (1024u * 1024u)
#define POLICY_MAX         (1024u * 1024u)
#define DIR_MAX            1002u                  /* "<dir>/rpki-unreachable.bin" fits the module's 1,024 */
#define JSON_MAX_DEPTH     32
#define JSON_MAX_MEMBERS   1024u
#define JSON_MAX_ELEMENTS  4096u
#define JSON_MAX_KEY       256u
#define MAX_REASONS        8
#define TENANT_GRACE_MS    (48LL * 3600LL * 1000LL)

/* A helper the tool uses and the manifest fuzz harness, which includes this file for its reader, does
 * not: marked so the harness's build stays free of unused-function warnings without silencing any. */
#ifdef WE_LOOKUP_READER_ONLY
#define TOOL_FN static __attribute__((unused))
#else
#define TOOL_FN static
#endif

/* Both operands of a manifest's age are capped below 2^48 by the reader's domains, so the difference
 * and its floor cannot overflow an int64_t. The largest instant the reader produces is
 * 9999-12-31T23:59:60 at offset -23:59, 253,402,387,140,000 ms. */
#ifdef WE_LOOKUP_TEST_AGE_CAP_2_62
#define AGE_OPERAND_CAP    (1LL << 62)            /* the control: a cap this wide must not compile */
#else
#define AGE_OPERAND_CAP    253402387140000LL
#endif
_Static_assert(AGE_OPERAND_CAP < (1LL << 48) && MAX_MS < (1LL << 48), "age operands stay below 2^48");

/* ======================================================================================================
 * A growable string. Everything printed is built here first, so a write error is one place to check.
 * ==================================================================================================== */

typedef struct {
    char  *p;
    size_t n, cap;
} sb_t;

static void die_oom(void)
{
    fputs("whisper-edge-lookup: out of memory\n", stderr);
    exit(2);
}

static void sb_grow(sb_t *s, size_t more)
{
    if (s->n + more + 1 > s->cap) {
        size_t c = s->cap ? s->cap : 64;
        char *q;

        while (c < s->n + more + 1) {
            c *= 2;
        }
        q = (char *)realloc(s->p, c);
        if (q == NULL) {
            die_oom();
        }
        s->p = q;
        s->cap = c;
    }
}

static void sb_putn(sb_t *s, const char *p, size_t n)
{
    sb_grow(s, n);
    memcpy(s->p + s->n, p, n);
    s->n += n;
    s->p[s->n] = '\0';
}

TOOL_FN void sb_puts(sb_t *s, const char *p)
{
    sb_putn(s, p, strlen(p));
}

static void sb_putc(sb_t *s, char c)
{
    sb_putn(s, &c, 1);
}

TOOL_FN void sb_printf(sb_t *s, const char *fmt, ...)
{
    va_list ap;
    int w;
    char tmp[256];

    va_start(ap, fmt);
    w = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (w < 0) {
        return;
    }
    if ((size_t)w < sizeof tmp) {
        sb_putn(s, tmp, (size_t)w);
        return;
    }
    sb_grow(s, (size_t)w);
    va_start(ap, fmt);
    vsnprintf(s->p + s->n, (size_t)w + 1, fmt, ap);
    va_end(ap);
    s->n += (size_t)w;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);

    if (p == NULL) {
        die_oom();
    }
    memcpy(p, s, n + 1);
    return p;
}

static char *xstrndup(const char *s, size_t n)
{
    char *p = (char *)malloc(n + 1);

    if (p == NULL) {
        die_oom();
    }
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static char *xprintf(const char *fmt, ...)
{
    va_list ap;
    int w;
    char *p;

    va_start(ap, fmt);
    w = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (w < 0) {
        return xstrdup("");
    }
    p = (char *)malloc((size_t)w + 1);
    if (p == NULL) {
        die_oom();
    }
    va_start(ap, fmt);
    vsnprintf(p, (size_t)w + 1, fmt, ap);
    va_end(ap);
    return p;
}

/* ======================================================================================================
 * Rendering. Every byte outside 0x20..0x7E, and `"` and `\`, prints as \xHH (upper-case hex), with no
 * truncation, so nothing a file or an argument holds can forge a line, a field or a terminal sequence.
 * ==================================================================================================== */

TOOL_FN void render(sb_t *o, const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
            sb_printf(o, "\\x%02X", c);
        } else {
            sb_putc(o, (char)c);
        }
    }
}

/* A line-form token: rendered, and quoted when it is empty or holds a space, `\` or `=`. */
TOOL_FN void line_token(sb_t *o, const char *s, int force_raw)
{
    sb_t r = {0};
    int q;

    render(&r, s, strlen(s));
    q = r.n == 0 || strpbrk(r.p, " \\=") != NULL;
    if (force_raw) {
        q = 0;
    }
    if (q) {
        sb_putc(o, '"');
    }
    if (r.n) {
        sb_putn(o, r.p, r.n);
    }
    if (q) {
        sb_putc(o, '"');
    }
    free(r.p);
}

/* A JSON string: the same rendering, so the document is ASCII, with `\` escaped for JSON. */
TOOL_FN void json_string(sb_t *o, const char *s)
{
    sb_t r = {0};
    size_t i;

    render(&r, s, strlen(s));
    sb_putc(o, '"');
    for (i = 0; i < r.n; i++) {
        if (r.p[i] == '\\') {
            sb_putc(o, '\\');
        }
        sb_putc(o, r.p[i]);
    }
    sb_putc(o, '"');
    free(r.p);
}

/* Standard error, rendered: argv bytes and file bytes never reach a terminal raw. */
TOOL_FN void err_rendered(const char *prefix, const char *s, const char *suffix)
{
    sb_t r = {0};

    sb_puts(&r, "whisper-edge-lookup: ");
    sb_puts(&r, prefix);
#ifdef WE_LOOKUP_TEST_STDERR_RAW
    sb_puts(&r, s);
#else
    render(&r, s, strlen(s));
#endif
    sb_puts(&r, suffix);
    sb_putc(&r, '\n');
    fputs(r.p, stderr);
    free(r.p);
}

/* ======================================================================================================
 * Instants: epoch milliseconds, written YYYY-MM-DDTHH:MM:SSZ, with .mmm only when the milliseconds are
 * nonzero. The civil-date arithmetic is the proleptic Gregorian calendar in integers.
 * ==================================================================================================== */

static int64_t days_from_civil(int64_t y, int64_t m, int64_t d)
{
    int64_t era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

TOOL_FN void civil_from_days(int64_t z, int64_t *y, int64_t *m, int64_t *d)
{
    int64_t era, doe, yoe, doy, mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    *y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp + (mp < 10 ? 3 : -9);
    *y += *m <= 2;
}

TOOL_FN int floor_div(int64_t a, int64_t b, int64_t *q)
{
    *q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0))) {
        (*q)--;
    }
    return 0;
}

/* An instant in 0..MAX_MS, as text. */
TOOL_FN void fmt_instant(sb_t *o, int64_t ms)
{
    int64_t days, rem, y, mo, d, msec;

    floor_div(ms, 86400000LL, &days);
    rem = ms - days * 86400000LL;
    civil_from_days(days, &y, &mo, &d);
    msec = rem % 1000;
    sb_printf(o, "%04" PRId64 "-%02" PRId64 "-%02" PRId64 "T%02" PRId64 ":%02" PRId64 ":%02" PRId64, y, mo, d,
              rem / 3600000, (rem / 60000) % 60, (rem / 1000) % 60);
    if (msec != 0) {
#ifdef WE_LOOKUP_TEST_INSTANT_SHORT_FRACTION
        char f[8];
        int k;

        snprintf(f, sizeof f, "%03" PRId64, msec);
        for (k = 2; k > 0 && f[k] == '0'; k--) {
            f[k] = '\0';
        }
        sb_printf(o, ".%s", f);
#else
        sb_printf(o, ".%03" PRId64, msec);
#endif
    }
    sb_putc(o, 'Z');
}

static int is_leap(int64_t y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int days_in_month(int64_t y, int64_t m)
{
    static const int dm[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    return m == 2 && is_leap(y) ? 29 : dm[m - 1];
}

static int digits(const char *s, int n, int64_t *v)
{
    int i;

    *v = 0;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        *v = *v * 10 + (s[i] - '0');
    }
    return 1;
}

/*
 * RFC 3339 section 5.6, with section 5.7's limits: a day within its month (leap years included), hour at
 * most 23, minute at most 59, a :60 second read as the next :00, offset hours at most 23. The fraction is
 * floored to milliseconds. Returns 1 with the normalised instant in *ms (any value; the caller judges the
 * range on the instant, never on the written year), or 0 when the text is not such a date-time.
 * *year gets the written year, for the one mutant that judges it.
 */
static int parse_rfc3339(const char *s, size_t n, int64_t *ms, int64_t *year)
{
    int64_t y, mo, d, h, mi, se, frac = 0, oh = 0, om = 0, sign = 0, local;
    size_t i = 19;

    if (n < 20 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't') || s[13] != ':'
        || s[16] != ':') {
        return 0;
    }
    if (!digits(s, 4, &y) || !digits(s + 5, 2, &mo) || !digits(s + 8, 2, &d) || !digits(s + 11, 2, &h)
        || !digits(s + 14, 2, &mi) || !digits(s + 17, 2, &se)) {
        return 0;
    }
    if (i < n && s[i] == '.') {
        int k = 0;

        i++;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            if (k < 3) {
                frac = frac * 10 + (s[i] - '0');
            }
            k++;
            i++;
        }
        if (k == 0) {
            return 0;
        }
        while (k < 3) {
            frac *= 10;
            k++;
        }
    }
    if (i >= n) {
        return 0;
    }
    if (s[i] == 'Z' || s[i] == 'z') {
        i++;
    } else if (s[i] == '+' || s[i] == '-') {
        sign = s[i] == '+' ? 1 : -1;
        if (n - i != 6 || s[i + 3] != ':' || !digits(s + i + 1, 2, &oh) || !digits(s + i + 4, 2, &om)) {
            return 0;
        }
        i += 6;
    } else {
        return 0;
    }
    if (i != n) {
        return 0;
    }
    if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 60 || oh > 23 || om > 59) {
        return 0;
    }
#ifdef WE_LOOKUP_TEST_MDAY_UNCHECKED
    (void)days_in_month;
#else
    if (d > days_in_month(y, mo)) {
        return 0;
    }
#endif
    local = days_from_civil(y, mo, d) * 86400000LL + h * 3600000LL + mi * 60000LL + se * 1000LL + frac;
    *ms = local - sign * (oh * 60 + om) * 60000LL;
    *year = y;
    return 1;
}

/* ======================================================================================================
 * Addresses: the classifier (liberal in what it takes, a fix in every refusal) and RFC 5952 text.
 * ==================================================================================================== */

typedef struct {
    int     ok;
    int     family;
    uint8_t b[16];        /* network order; IPv4 in b[0..3] */
    char    canon[64];
    char   *err;          /* malloc'd refusal text */
    char   *note;         /* malloc'd note, or NULL */
    char   *note2;
} addr_t;

TOOL_FN void fmt_v4(const uint8_t *b, char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* RFC 5952 section 4: lower case, no leading zeros, `::` on the longest run of two or more zero groups
 * (the leftmost on a tie), mixed notation only for ::ffff:0:0/96. */
TOOL_FN void fmt_v6(const uint8_t *b, char *out, size_t n)
{
#ifdef WE_LOOKUP_TEST_INET_NTOP
    inet_ntop(AF_INET6, b, out, (socklen_t)n);
#else
    unsigned g[8];
    int i, best = -1, bestlen = 0, cur = -1, curlen = 0;
    size_t at = 0;
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    if (memcmp(b, mapped, 12) == 0) {
        snprintf(out, n, "::ffff:%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
        return;
    }
    for (i = 0; i < 8; i++) {
        g[i] = ((unsigned)b[2 * i] << 8) | b[2 * i + 1];
    }
    for (i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur < 0) {
                cur = i;
                curlen = 0;
            }
            curlen++;
            if (curlen > bestlen) {
                best = cur;
                bestlen = curlen;
            }
        } else {
            cur = -1;
        }
    }
    if (bestlen < 2) {
        best = -1;
    }
    out[0] = '\0';
    for (i = 0; i < 8; i++) {
        if (i == best) {
            at += (size_t)snprintf(out + at, n - at, "::");
            i += bestlen - 1;
            continue;
        }
        if (at > 0 && out[at - 1] != ':') {
            at += (size_t)snprintf(out + at, n - at, ":");
        }
        at += (size_t)snprintf(out + at, n - at, "%x", g[i]);
    }
#endif
}

TOOL_FN void fmt_addr(int family, const uint8_t *b, char *out, size_t n)
{
    if (family == 4) {
        fmt_v4(b, out, n);
    } else {
        fmt_v6(b, out, n);
    }
}

TOOL_FN int is_digits(const char *s, size_t n)
{
    size_t i;

    if (n == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return 1;
}

/* a.b.c.d with four decimal parts, each 1..3 digits; parts[] gets their spans */
TOOL_FN int dotted4(const char *s, size_t n, size_t pos[4], size_t len[4])
{
    size_t i = 0, k;

    for (k = 0; k < 4; k++) {
        pos[k] = i;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            i++;
        }
        len[k] = i - pos[k];
        if (len[k] == 0) {
            return 0;
        }
        if (k < 3) {
            if (i >= n || s[i] != '.') {
                return 0;
            }
            i++;
        }
    }
    return i == n;
}

/* LDH labels, at least one letter somewhere, after at most one trailing dot: a host name. */
TOOL_FN int hostname_like(const char *s, size_t n)
{
    size_t i, lab = 0;
    int letter = 0;

    if (n > 0 && s[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > 253) {
        return 0;
    }
    for (i = 0; i <= n; i++) {
        char c = i < n ? s[i] : '.';

        if (c == '.') {
            if (lab == 0 || lab > 63 || s[i - 1] == '-' || s[i - lab] == '-') {
                return 0;
            }
            lab = 0;
            continue;
        }
        if (isalpha((unsigned char)c)) {
            letter = 1;
        } else if (!isdigit((unsigned char)c) && c != '-') {
            return 0;
        }
        lab++;
    }
    return letter;
}

TOOL_FN void addr_refuse(addr_t *a, const char *fmt, const char *arg)
{
    sb_t r = {0};

    a->ok = 0;
    sb_printf(&r, fmt, arg);
    a->err = r.p;
}

/*
 * Liberal in what it takes, a fix in every refusal: strip surrounding whitespace; refuse a port with the
 * address to give instead; strip brackets and a zone (with a note); /32 on IPv4 and /128 on IPv6 are the
 * address, any other prefix is refused with its first address, a zone before it included (RFC 4007
 * section 11 writes the zone ahead of the prefix length); a leading-zero, short or numeric IPv4 form is
 * refused naming the four-part form; a host name is refused with the fix; IPv4-mapped is the IPv4
 * address; NAT64 (RFC 6052, RFC 8215) and IPv4-compatible stay IPv6 with a note.
 */
TOOL_FN void classify(const char *in, addr_t *a)
{
    char buf[512], tmp[80];
    size_t n, i;
    char *s = buf;
    struct in_addr a4;
    struct in6_addr a6;
    size_t pos[4], len[4];

    memset(a, 0, sizeof *a);
    n = strlen(in);
    if (n >= sizeof buf) {
        addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
        return;
    }
    memcpy(buf, in, n + 1);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[--n] = '\0';
    }
    while (*s && isspace((unsigned char)*s)) {
        s++;
        n--;
    }
    if (n == 0) {
        addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
        return;
    }
    /* [v6]:port and [v6] */
    if (s[0] == '[') {
        char *close = strchr(s, ']');

        if (close == NULL) {
            addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
            return;
        }
        *close = '\0';
        if (close[1] == ':' && is_digits(close + 2, strlen(close + 2))) {
            char *z = strchr(s + 1, '%');

            if (z) {
                *z = '\0';
            }
            if (inet_pton(AF_INET6, s + 1, &a6) != 1) {
                /* only an address that parses is offered back as the fix */
                addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
                return;
            }
            fmt_v6((const uint8_t *)&a6, tmp, sizeof tmp);
#ifdef WE_LOOKUP_TEST_PORT_GENERIC
            addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
#else
            addr_refuse(a, "a port is not part of the address; give %s", tmp);
#endif
            return;
        }
#ifndef WE_LOOKUP_TEST_BRACKET_PREFIX_REFUSED
        if (close[1] == '/') {
            memmove(close, close + 1, strlen(close + 1) + 1);   /* [addr]/len is addr/len */
        } else
#endif
        if (close[1] != '\0') {
            addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
            return;
        }
        s++;
        n = strlen(s);
    } else {
        char *colon = strrchr(s, ':');

#ifdef WE_LOOKUP_TEST_PORT_STRIPS_DIGITS
        if (colon != NULL && is_digits(colon + 1, strlen(colon + 1))) {
            *colon = '\0';
            addr_refuse(a, "a port is not part of the address; give %s", s);
            return;
        }
#else
        if (colon != NULL && strchr(s, ':') == colon && is_digits(colon + 1, strlen(colon + 1))
            && dotted4(s, (size_t)(colon - s), pos, len)) {
            *colon = '\0';
#ifdef WE_LOOKUP_TEST_PORT_GENERIC
            addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
#else
            addr_refuse(a, "a port is not part of the address; give %s", s);
#endif
            return;
        }
#endif
    }
    /* a zone, with a prefix length after it kept for the prefix rule below */
    {
        char *z = strchr(s, '%');

#ifndef WE_LOOKUP_TEST_ZONE_SWALLOWS_PREFIX
        if (z != NULL && strchr(z, '/') != NULL) {
            char *sl = strchr(z, '/');
#ifdef WE_LOOKUP_TEST_ZONE_PREFIX_TRUNCATED
            char *plen = xprintf("%.30s", sl);
#else
            char *plen = xstrdup(sl);       /* the whole length, as the path without a zone reads it */
#endif

            *sl = '\0';
            if (z[1] == '\0') {
                free(plen);
                addr_refuse(a, "%s", "an empty zone; give the address without the %");
                return;
            }
            a->note = xprintf("the zone %s is not part of the address and was stripped", z);
            *z = '\0';
            if (strchr(s, ':') == NULL) {
                free(plen);
                free(a->note);
                a->note = NULL;
                addr_refuse(a, "a zone applies only to an IPv6 address; give %s", s);
                return;
            }
            memmove(z, plen, strlen(plen) + 1);
            free(plen);
            z = NULL;
            n = strlen(s);
        }
#endif
        if (z != NULL) {
            if (z[1] == '\0') {
                addr_refuse(a, "%s", "an empty zone; give the address without the %");
                return;
            }
            a->note = xprintf("the zone %s is not part of the address and was stripped", z);
            *z = '\0';
            n = strlen(s);
            if (strchr(s, ':') == NULL) {
                free(a->note);
                a->note = NULL;
                addr_refuse(a, "a zone applies only to an IPv6 address; give %s", s);
                return;
            }
        }
    }
    /* a prefix length */
    {
        char *slash = strchr(s, '/');

        if (slash != NULL) {
            int fam = 0;

            *slash = '\0';
            if (inet_pton(AF_INET, s, &a4) == 1) {
                fam = 4;
            } else if (inet_pton(AF_INET6, s, &a6) == 1) {
                fam = 6;
            }
            if (fam == 0) {
                /* the address part is no address: its own refusal names the fix (a leading zero, a host) */
                n = strlen(s);
                goto not_parsed;
            }
            if (is_digits(slash + 1, strlen(slash + 1))) {
                const char *d = slash + 1;
                unsigned long pl;

                while (d[0] == '0' && d[1] != '\0') {
                    d++;                               /* /032 is /32, as /0128 is /128 */
                }
                pl = strlen(d) <= 3 ? strtoul(d, NULL, 10) : 999ul;
                if ((fam == 4 && pl > 32) || (fam == 6 && pl > 128)) {
#ifdef WE_LOOKUP_TEST_PREFIX_LEN_QUOTES_RAW
                    char lenbuf[16];

                    snprintf(lenbuf, sizeof lenbuf, "%.8s", slash + 1);
                    addr_refuse(a, fam == 4 ? "a prefix length of %s is longer than an IPv4 address's 32 bits"
                                            : "a prefix length of %s is longer than an IPv6 address's 128 bits", lenbuf);
#else
                    /* the length as read, leading zeros gone; past three digits, how many, never a cut number */
                    if (strlen(d) <= 3) {
                        addr_refuse(a, fam == 4 ? "a prefix length of %s is longer than an IPv4 address's 32 bits"
                                                : "a prefix length of %s is longer than an IPv6 address's 128 bits", d);
                    } else {
                        char nd[24];

                        snprintf(nd, sizeof nd, "%zu", strlen(d));
                        addr_refuse(a, fam == 4 ? "a prefix length of %s digits is longer than an IPv4 address's 32 bits"
                                                : "a prefix length of %s digits is longer than an IPv6 address's 128 bits",
                                    nd);
                    }
#endif
                    return;
                }
                if ((fam == 4 && pl == 32) || (fam == 6 && pl == 128)) {
                    n = strlen(s);
                } else if ((fam == 4 && pl < 32) || (fam == 6 && pl < 128)) {
                    uint8_t b[16];
                    size_t nb = fam == 4 ? 4 : 16;

                    memcpy(b, fam == 4 ? (const void *)&a4 : (const void *)&a6, nb);
                    for (i = 0; i < nb * 8; i++) {
                        if (i >= pl) {
                            b[i / 8] = (uint8_t)(b[i / 8] & ~(0x80u >> (i % 8)));
                        }
                    }
                    fmt_addr(fam, b, tmp, sizeof tmp);
                    addr_refuse(a, "a prefix is many addresses; give one, for example its first, %s", tmp);
                    return;
                } else {
                    addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
                    return;
                }
            } else {
                addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
                return;
            }
        }
    }
    if (inet_pton(AF_INET, s, &a4) == 1) {
        a->ok = 1;
        a->family = 4;
        memcpy(a->b, &a4, 4);
        goto formatted;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        static const uint8_t nat64[12] = { 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 };
        static const uint8_t nat64_local[6] = { 0, 0x64, 0xff, 0x9b, 0, 0x01 };   /* 64:ff9b:1::/48 */
        static const uint8_t zero12[12] = { 0 };
        const uint8_t *b = (const uint8_t *)&a6;

        a->ok = 1;
        if (memcmp(b, mapped, 12) == 0) {
            a->family = 4;
            memcpy(a->b, b + 12, 4);
        } else {
            a->family = 6;
            memcpy(a->b, b, 16);
#ifdef WE_LOOKUP_TEST_NAT64_AS_V4
            if (memcmp(b, nat64, 12) == 0) {
                a->family = 4;
                memset(a->b, 0, 16);
                memcpy(a->b, b + 12, 4);
            }
#endif
#ifdef WE_LOOKUP_TEST_NAT64_LOCAL_NO_NOTE
            (void)nat64_local;
            if (a->family == 6 && (memcmp(b, nat64, 12) == 0
#else
            if (a->family == 6 && (memcmp(b, nat64, 12) == 0 || memcmp(b, nat64_local, 6) == 0
#endif
                                   || (memcmp(b, zero12, 12) == 0 && (b[12] | b[13] | b[14]) != 0))) {
                a->note2 = xstrdup("the embedded IPv4 address is not looked up");
            }
        }
        goto formatted;
    }
not_parsed:
    if (n > 1 && s[n - 1] == '.' && dotted4(s, n - 1, pos, len)) {
        s[n - 1] = '\0';
        addr_refuse(a, "a trailing dot after an IPv4 address; give %s", s);
        return;
    } else if (dotted4(s, n, pos, len)) {
        int k;

        for (k = 0; k < 4; k++) {
            if (len[k] > 1 && s[pos[k]] == '0') {
                char part[8];

                snprintf(part, sizeof part, "%.*s", (int)(len[k] > 3 ? 3 : len[k]), s + pos[k]);
                addr_refuse(a, "the part %s has a leading zero, which some software reads as octal; give the "
                               "address without leading zeros", part);
                return;
            }
        }
        addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
        return;
    } else if (strpbrk(s, " \t\r\n\v\f") == NULL && inet_aton(s, &a4) != 0) {
        fmt_v4((const uint8_t *)&a4, tmp, sizeof tmp);
        addr_refuse(a, "a short or numeric IPv4 form; give all four parts, %s", tmp);
        return;
    } else if (hostname_like(s, n)) {
#ifdef WE_LOOKUP_TEST_TRAILING_DOT_GENERIC
        if (s[n - 1] == '.') {
            addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
            return;
        }
#endif
        {
            sb_t r = {0};

            render(&r, s, n);
            a->ok = 0;
            a->err = xprintf("%s is a hostname; resolve it first and give its addresses", r.p);
            free(r.p);
        }
        return;
    } else {
        addr_refuse(a, "%s", "not an IPv4 or IPv6 address");
        return;
    }
formatted:
    fmt_addr(a->family, a->b, a->canon, sizeof a->canon);
}

TOOL_FN void addr_free(addr_t *a)
{
    free(a->err);
    free(a->note);
    free(a->note2);
}

/* ======================================================================================================
 * The manifest reader: RFC 8259 exactly, bounded, with the field rules on top. A refusal names its rule;
 * nothing of a refused file is echoed.
 * ==================================================================================================== */

enum { J_NULL, J_FALSE, J_TRUE, J_NUM, J_STR, J_ARR, J_OBJ };

typedef struct jnode jnode_t;
struct jnode {
    uint8_t   t;
    uint32_t  n;            /* members or elements */
    char     *s;            /* J_STR: decoded bytes; J_NUM: the token */
    uint32_t  slen;
    jnode_t **kid;
    char    **key;          /* J_OBJ: decoded keys */
    uint32_t *klen;
};

typedef struct {
    const uint8_t *b, *p, *e;
    int            depth;
    char           why[96];
} jp_t;

/* The names the reader reads anywhere. Two members of one object with one of these names refuse the
 * manifest, compared after \u decoding: python3 and jq keep the LAST duplicate, a reader keeping the
 * first would bind other bytes, so the only safe reading is none. */
static const char *const READ_NAMES[] = {
    "generation", "builtAt", "builder", "tier", "planes", "legacy", "withheld", "name", "sha256", "bytes",
    "headerGeneration", "validUntil", "coverage", "v4Addresses", "v6Addresses", "v6Slash32s", "sources",
    "kind", "count", "observedAt", "recall", "precision", "reason", "reasons", "detail", "since",
    "builtGeneration", "lastPublishedValidUntil"
};
#define N_READ_NAMES (sizeof READ_NAMES / sizeof READ_NAMES[0])
_Static_assert(N_READ_NAMES <= 32, "the duplicate-key check keeps one bit per read name in a uint32_t");

static void jfree(jnode_t *v)
{
    uint32_t i;

    if (v == NULL) {
        return;
    }
    for (i = 0; i < v->n; i++) {
        jfree(v->kid ? v->kid[i] : NULL);
        if (v->key) {
            free(v->key[i]);
        }
    }
    free(v->kid);
    free(v->key);
    free(v->klen);
    free(v->s);
    free(v);
}

static int jfail(jp_t *j, const char *why)
{
    if (j->why[0] == '\0') {
        snprintf(j->why, sizeof j->why, "%s", why);
    }
    return 0;
}

static void jws(jp_t *j)
{
    while (j->p < j->e && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) {
        j->p++;
    }
}

static jnode_t *jnew(uint8_t t)
{
    jnode_t *v = (jnode_t *)calloc(1, sizeof *v);

    if (v == NULL) {
        die_oom();
    }
    v->t = t;
    return v;
}

static int hexval(int c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static int hex4(const uint8_t *p, const uint8_t *e, unsigned *v)
{
    int k;

    if (e - p < 4) {
        return 0;
    }
    *v = 0;
    for (k = 0; k < 4; k++) {
        int h = hexval(p[k]);

        if (h < 0) {
            return 0;
        }
        *v = (*v << 4) | (unsigned)h;
    }
    return 1;
}

static void utf8_put(sb_t *o, unsigned cp)
{
    if (cp < 0x80) {
        sb_putc(o, (char)cp);
    } else if (cp < 0x800) {
        sb_putc(o, (char)(0xc0 | (cp >> 6)));
        sb_putc(o, (char)(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        sb_putc(o, (char)(0xe0 | (cp >> 12)));
        sb_putc(o, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_putc(o, (char)(0x80 | (cp & 0x3f)));
    } else {
        sb_putc(o, (char)(0xf0 | (cp >> 18)));
        sb_putc(o, (char)(0x80 | ((cp >> 12) & 0x3f)));
        sb_putc(o, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_putc(o, (char)(0x80 | (cp & 0x3f)));
    }
}

/* A string after its opening quote; the decoded bytes in *out. */
static int jstring(jp_t *j, sb_t *out)
{
    while (j->p < j->e) {
        uint8_t c = *j->p;

        if (c == '"') {
            j->p++;
            if (out->p == NULL) {
                sb_grow(out, 0);
                out->p[0] = '\0';
            }
            return 1;
        }
        if (c < 0x20) {
#ifdef WE_LOOKUP_TEST_JR_RAW_TAB
            if (c == '\t') {
                sb_putc(out, (char)c);
                j->p++;
                continue;
            }
#endif
            return jfail(j, "control-byte");
        }
        if (c != '\\') {
            const uint8_t *run = j->p;

            while (j->p < j->e && *j->p != '"' && *j->p != '\\' && *j->p >= 0x20) {
                j->p++;
            }
            sb_putn(out, (const char *)run, (size_t)(j->p - run));
            continue;
        }
        j->p++;
        if (j->p >= j->e) {
            return jfail(j, "syntax");
        }
        c = *j->p++;
        switch (c) {
        case '"': sb_putc(out, '"'); break;
        case '\\': sb_putc(out, '\\'); break;
        case '/': sb_putc(out, '/'); break;
        case 'b': sb_putc(out, '\b'); break;
        case 'f': sb_putc(out, '\f'); break;
        case 'n': sb_putc(out, '\n'); break;
        case 'r': sb_putc(out, '\r'); break;
        case 't': sb_putc(out, '\t'); break;
        case 'u': {
            unsigned u, lo;

            if (!hex4(j->p, j->e, &u)) {
                return jfail(j, "syntax");
            }
            j->p += 4;
            if (u >= 0xd800 && u <= 0xdbff) {
                if (j->e - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u' && hex4(j->p + 2, j->e, &lo)
                    && lo >= 0xdc00 && lo <= 0xdfff) {
                    j->p += 6;
                    u = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
                } else {
#ifndef WE_LOOKUP_TEST_JR_LONE_SURROGATE
                    return jfail(j, "lone-surrogate");
#endif
                }
            } else if (u >= 0xdc00 && u <= 0xdfff) {
#ifndef WE_LOOKUP_TEST_JR_LONE_SURROGATE
                return jfail(j, "lone-surrogate");
#endif
            } else if (u == 0) {
#ifndef WE_LOOKUP_TEST_JR_NUL_ESCAPE
                return jfail(j, "nul");
#endif
            }
            utf8_put(out, u);
            break;
        }
        default:
            return jfail(j, "syntax");
        }
    }
    return jfail(j, "syntax");
}

static int jnumber(jp_t *j, jnode_t *v)
{
    const uint8_t *s = j->p;

    if (j->p < j->e && *j->p == '-') {
        j->p++;
    }
    if (j->p >= j->e || !isdigit(*j->p)) {
        return jfail(j, "syntax");
    }
    if (*j->p == '0') {
        j->p++;
#ifdef WE_LOOKUP_TEST_JR_LEADING_ZERO
        while (j->p < j->e && isdigit(*j->p)) {
            j->p++;
        }
#endif
    } else {
        while (j->p < j->e && isdigit(*j->p)) {
            j->p++;
        }
    }
    if (j->p < j->e && *j->p == '.') {
        j->p++;
        if (j->p >= j->e || !isdigit(*j->p)) {
            return jfail(j, "syntax");
        }
        while (j->p < j->e && isdigit(*j->p)) {
            j->p++;
        }
    }
    if (j->p < j->e && (*j->p == 'e' || *j->p == 'E')) {
        j->p++;
        if (j->p < j->e && (*j->p == '+' || *j->p == '-')) {
            j->p++;
        }
        if (j->p >= j->e || !isdigit(*j->p)) {
            return jfail(j, "syntax");
        }
        while (j->p < j->e && isdigit(*j->p)) {
            j->p++;
        }
    }
    v->s = xstrndup((const char *)s, (size_t)(j->p - s));
    v->slen = (uint32_t)(j->p - s);
    return 1;
}

static jnode_t *jvalue(jp_t *j);

static int read_name_index(const char *k, size_t n)
{
    size_t i;

    for (i = 0; i < N_READ_NAMES; i++) {
        if (strlen(READ_NAMES[i]) == n && memcmp(READ_NAMES[i], k, n) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static jnode_t *jcontainer(jp_t *j, int obj)
{
    jnode_t *v = jnew(obj ? J_OBJ : J_ARR);
    uint32_t cap = 0;
    uint32_t seen = 0;

    if (++j->depth > JSON_MAX_DEPTH) {
        jfail(j, "too-deep");
        jfree(v);
        return NULL;
    }
    j->p++;
    jws(j);
    if (j->p < j->e && *j->p == (obj ? '}' : ']')) {
        j->p++;
        j->depth--;
        return v;
    }
    for (;;) {
        jnode_t *kid;
        sb_t key = {0};
#ifdef WE_LOOKUP_TEST_RAW_SPAN_KEYS
        const uint8_t *raw0 = NULL, *raw1 = NULL;
#endif

        if (v->n >= (obj ? JSON_MAX_MEMBERS : JSON_MAX_ELEMENTS)) {
            jfail(j, "too-wide");
            jfree(v);
            return NULL;
        }
        if (obj) {
            jws(j);
            if (j->p >= j->e || *j->p != '"') {
                jfail(j, "syntax");
                jfree(v);
                return NULL;
            }
            j->p++;
#ifdef WE_LOOKUP_TEST_RAW_SPAN_KEYS
            raw0 = j->p;
#endif
            if (!jstring(j, &key)) {
                free(key.p);
                jfree(v);
                return NULL;
            }
#ifdef WE_LOOKUP_TEST_RAW_SPAN_KEYS
            raw1 = j->p - 1;
#endif
            if (key.n > JSON_MAX_KEY) {
                free(key.p);
                jfail(j, "too-long");
                jfree(v);
                return NULL;
            }
            {
#ifdef WE_LOOKUP_TEST_RAW_SPAN_KEYS
                int ri = read_name_index((const char *)raw0, (size_t)(raw1 - raw0));
#else
                int ri = read_name_index(key.p, key.n);
#endif

                if (ri >= 0) {
#ifndef WE_LOOKUP_TEST_JR_DUP_READ_NAME
                    if (seen & (1u << ri)) {
                        char w[96];

                        snprintf(w, sizeof w, "duplicate-key:%s", READ_NAMES[ri]);
                        free(key.p);
                        jfail(j, w);
                        jfree(v);
                        return NULL;
                    }
#endif
                    seen |= 1u << ri;
                }
            }
            jws(j);
            if (j->p >= j->e || *j->p != ':') {
                free(key.p);
                jfail(j, "syntax");
                jfree(v);
                return NULL;
            }
            j->p++;
        }
        kid = jvalue(j);
        if (kid == NULL) {
            free(key.p);
            jfree(v);
            return NULL;
        }
        if (v->n == cap) {
            uint32_t nc = cap ? cap * 2 : 8;
            jnode_t **nk = (jnode_t **)realloc(v->kid, nc * sizeof *nk);

            if (nk == NULL) {
                die_oom();
            }
            v->kid = nk;
            if (obj) {
                char **kk = (char **)realloc(v->key, nc * sizeof *kk);
                uint32_t *kl = (uint32_t *)realloc(v->klen, nc * sizeof *kl);

                if (kk == NULL || kl == NULL) {
                    die_oom();
                }
                v->key = kk;
                v->klen = kl;
            }
            cap = nc;
        }
        v->kid[v->n] = kid;
        if (obj) {
            v->key[v->n] = key.p;
            v->klen[v->n] = (uint32_t)key.n;
        }
        v->n++;
        jws(j);
        if (j->p < j->e && *j->p == ',') {
            j->p++;
            jws(j);
            continue;
        }
        if (j->p < j->e && *j->p == (obj ? '}' : ']')) {
            j->p++;
            j->depth--;
            return v;
        }
        jfail(j, "syntax");
        jfree(v);
        return NULL;
    }
}

static jnode_t *jvalue(jp_t *j)
{
    jnode_t *v;

    jws(j);
    if (j->p >= j->e) {
        jfail(j, "syntax");
        return NULL;
    }
    switch (*j->p) {
    case '{':
        return jcontainer(j, 1);
    case '[':
        return jcontainer(j, 0);
    case '"': {
        sb_t s = {0};

        j->p++;
        if (!jstring(j, &s)) {
            free(s.p);
            return NULL;
        }
        v = jnew(J_STR);
        v->s = s.p;
        v->slen = (uint32_t)s.n;
        return v;
    }
    case 't':
        if (j->e - j->p >= 4 && memcmp(j->p, "true", 4) == 0) {
            j->p += 4;
            return jnew(J_TRUE);
        }
        break;
    case 'f':
        if (j->e - j->p >= 5 && memcmp(j->p, "false", 5) == 0) {
            j->p += 5;
            return jnew(J_FALSE);
        }
        break;
    case 'n':
        if (j->e - j->p >= 4 && memcmp(j->p, "null", 4) == 0) {
            j->p += 4;
            return jnew(J_NULL);
        }
        break;
#ifdef WE_LOOKUP_TEST_JR_NAN
    case 'N':
        if (j->e - j->p >= 3 && memcmp(j->p, "NaN", 3) == 0) {
            j->p += 3;
            v = jnew(J_NUM);
            v->s = xstrdup("NaN");
            return v;
        }
        break;
#endif
#ifdef WE_LOOKUP_TEST_JR_INFINITY
    case 'I':
        if (j->e - j->p >= 8 && memcmp(j->p, "Infinity", 8) == 0) {
            j->p += 8;
            v = jnew(J_NUM);
            v->s = xstrdup("Infinity");
            return v;
        }
        break;
#endif
    default:
        if (*j->p == '-' || isdigit(*j->p)) {
            v = jnew(J_NUM);
            if (!jnumber(j, v)) {
                jfree(v);
                return NULL;
            }
            return v;
        }
        break;
    }
    jfail(j, "syntax");
    return NULL;
}

/* Strict UTF-8: no overlong forms, no encoded surrogates, nothing above U+10FFFF. */
static int utf8_ok(const uint8_t *p, size_t n)
{
    size_t i = 0;

    while (i < n) {
        uint8_t c = p[i];
        unsigned cp, need, k;

        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) {
            need = 1;
            cp = c & 0x1fu;
        } else if (c >= 0xe0 && c <= 0xef) {
            need = 2;
            cp = c & 0x0fu;
        } else if (c >= 0xf0 && c <= 0xf4) {
            need = 3;
            cp = c & 0x07u;
        } else {
#ifdef WE_LOOKUP_TEST_JR_OVERLONG
            if (c == 0xc0 || c == 0xc1) {
                i += 2;
                continue;
            }
#endif
            return 0;
        }
        for (k = 1; k <= need; k++) {
            if (i + k >= n || (p[i + k] & 0xc0) != 0x80) {
                return 0;
            }
            cp = (cp << 6) | (p[i + k] & 0x3fu);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10ffff))) {
            return 0;
        }
        if (cp >= 0xd800 && cp <= 0xdfff) {
#ifndef WE_LOOKUP_TEST_JR_CESU
            return 0;
#endif
        }
        i += need + 1;
    }
    return 1;
}

/* Parse a whole manifest text. Returns the root, or NULL with *why the rule it broke. */
static jnode_t *json_parse(const uint8_t *buf, size_t n, char *why, size_t whylen)
{
    jp_t j;
    jnode_t *v;
    size_t i;

    why[0] = '\0';
    if (n > MANIFEST_MAX) {
        snprintf(why, whylen, "too-large");
        return NULL;
    }
#ifndef WE_LOOKUP_TEST_JR_BOM
    if ((n >= 3 && buf[0] == 0xef && buf[1] == 0xbb && buf[2] == 0xbf)
        || (n >= 2 && ((buf[0] == 0xfe && buf[1] == 0xff) || (buf[0] == 0xff && buf[1] == 0xfe)))) {
        snprintf(why, whylen, "bom");
        return NULL;
    }
#else
    if (n >= 3 && buf[0] == 0xef && buf[1] == 0xbb && buf[2] == 0xbf) {
        buf += 3;
        n -= 3;
    }
#endif
#ifndef WE_LOOKUP_TEST_JR_UTF16
    for (i = 0; i < n; i++) {
        if (buf[i] == 0) {
            snprintf(why, whylen, "nul-byte");
            return NULL;
        }
    }
#else
    (void)i;
#endif
    if (!utf8_ok(buf, n)) {
        snprintf(why, whylen, "bad-utf8");
        return NULL;
    }
    memset(&j, 0, sizeof j);
    j.b = j.p = buf;
    j.e = buf + n;
    v = jvalue(&j);
    if (v == NULL) {
        snprintf(why, whylen, "%s", j.why[0] ? j.why : "syntax");
        return NULL;
    }
    jws(&j);
#ifndef WE_LOOKUP_TEST_JR_TRAILING
    if (j.p != j.e) {
        jfree(v);
        snprintf(why, whylen, "trailing-bytes");
        return NULL;
    }
#endif
    return v;
}

static jnode_t *jget(const jnode_t *o, const char *name)
{
    uint32_t i;
    size_t n = strlen(name);

    if (o == NULL || o->t != J_OBJ) {
        return NULL;
    }
    for (i = 0; i < o->n; i++) {
        if (o->klen[i] == n && memcmp(o->key[i], name, n) == 0) {
            return o->kid[i];
        }
    }
    return NULL;
}

/* ---- the field rules ---- */

/* a time field's reading */
enum { T_ABSENT, T_NULL, T_OK, T_MS, T_REFUSED };

typedef struct {
    int     st;          /* T_* */
    int64_t ms;
} tval_t;

/* a count or integer field: the decimal text, or NULL for not-stated */
typedef struct {
    char *dec;
} dval_t;

typedef struct {
    char  *name, *kind, *count, *recall, *precision;
    tval_t observed;
} src_t;

typedef struct {
    char    *name;
    int      sha_ok;
    char     sha[65];
    int      bytes_ok;
    uint64_t bytes;
    char    *generation, *hgen;      /* decimal, or NULL */
    tval_t   built, valid;
    int      coverage_null;          /* the object is null or absent */
    int      cov_obj;                /* coverage is an object */
    char    *cov_v4, *cov_v6, *cov_s32;
    uint32_t nsrc;
    src_t   *src;
} pentry_t;

typedef struct {
    char    *name;
    int      sha_ok;
    char     sha[65];
    int      bytes_ok;
    uint64_t bytes;
    char    *hgen;
} lentry_t;

typedef struct {
    char   *name;
    int     reasons_state;           /* 0 not-stated, 1 ok, 2 refused */
    char   *reasons[MAX_REASONS];
    int     nreasons;
    char   *reason, *detail;
    tval_t  since, lpvu;
    char   *built_gen;
} wentry_t;

enum { M_ABSENT, M_READ, M_UNREADABLE, M_REFUSED };

typedef struct {
    const char *file;                /* "manifest.json" or "k/manifest.json" */
    int         keyed;
    int         state;
    char        why[96];
    char       *generation;
    tval_t      built;
    char       *builder, *tier;
    pentry_t   *planes;
    uint32_t    nplanes;
    lentry_t   *legacy;
    uint32_t    nlegacy;
    wentry_t   *withheld;
    uint32_t    nwithheld;
    char      **fnotes;              /* field refusals: "<path>: <rule>" */
    uint32_t    nfnotes;
} manifest_t;

static void mnote(manifest_t *m, const char *path, const char *rule)
{
    char **n = (char **)realloc(m->fnotes, (m->nfnotes + 1) * sizeof *n);

    if (n == NULL) {
        die_oom();
    }
    m->fnotes = n;
    m->fnotes[m->nfnotes++] = xprintf("%s %s: %s", m->file, path, rule);
}

static int reserved_token(const char *s)
{
    return strcmp(s, "not-stated") == 0 || strcmp(s, "none") == 0 || strncmp(s, "ms:", 3) == 0;
}

/* A string field: NULL when absent, null, refused (a note says which). */
static char *f_string(manifest_t *m, const jnode_t *v, const char *path)
{
    if (v == NULL || v->t == J_NULL) {
        return NULL;
    }
    if (v->t != J_STR) {
        mnote(m, path, "not-a-string");
        return NULL;
    }
#ifndef WE_LOOKUP_TEST_RESERVED_TOKEN_PASSED
    if (reserved_token(v->s)) {
        mnote(m, path, "reserved-token");
        return NULL;
    }
#endif
    return xstrndup(v->s, v->slen);
}

/* An integer field: the integer form only, 0..2^63-1, `-0` refused. */
static int int_token(const char *t, uint64_t *out)
{
    size_t n = strlen(t), i;
    uint64_t v = 0;

    if (n == 0 || t[0] == '-' || (n > 1 && t[0] == '0')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (t[i] < '0' || t[i] > '9') {
            return 0;
        }
        if (v > (UINT64_C(0x7fffffffffffffff) - (uint64_t)(t[i] - '0')) / 10) {
            return 0;
        }
        v = v * 10 + (uint64_t)(t[i] - '0');
    }
    *out = v;
    return 1;
}

static char *f_integer(manifest_t *m, const jnode_t *v, const char *path, uint64_t *out, int *ok)
{
    uint64_t x = 0;

    *ok = 0;
    if (v == NULL || v->t == J_NULL) {
        return NULL;
    }
    if (v->t != J_NUM) {
        mnote(m, path, "not-an-integer");
        return NULL;
    }
#if defined(WE_LOOKUP_TEST_JR_GEN_FLOAT)
    if (strchr(v->s, 'e') != NULL || strchr(v->s, '.') != NULL) {
        double d = strtod(v->s, NULL);

        if (d >= 0 && d < 9.2e18) {
            x = (uint64_t)d;
            *ok = 1;
            if (out) {
                *out = x;
            }
            return xprintf("%" PRIu64, x);
        }
    }
#endif
#if defined(WE_LOOKUP_TEST_JR_GEN_2_64)
    if (strcmp(v->s, "18446744073709551616") == 0) {
        *ok = 1;
        return xstrdup(v->s);
    }
#endif
#if defined(WE_LOOKUP_TEST_JR_NEG_ZERO)
    if (strcmp(v->s, "-0") == 0) {
        *ok = 1;
        if (out) {
            *out = 0;
        }
        return xstrdup("0");
    }
#endif
    if (strchr(v->s, '.') != NULL || strchr(v->s, 'e') != NULL || strchr(v->s, 'E') != NULL) {
        mnote(m, path, "not-an-integer");
        return NULL;
    }
    if (!int_token(v->s, &x)) {
        mnote(m, path, strcmp(v->s, "-0") == 0 ? "not-an-integer" : "out-of-range");
        return NULL;
    }
    *ok = 1;
    if (out) {
        *out = x;
    }
    return xprintf("%" PRIu64, x);
}

/* 2^128, the largest count (the whole IPv6 space). */
static const char *const TWO_128 = "340282366920938463463374607431768211456";

static int count_string_ok(const char *s)
{
    size_t n = strlen(s), i;

    if (n == 0 || n > 39 || (n > 1 && s[0] == '0')) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
    }
    return n < 39 || strcmp(s, TWO_128) <= 0;
}

/* A count: a JSON integer within 0..2^63-1, or a decimal string up to 2^128. */
static char *f_count(manifest_t *m, const jnode_t *v, const char *path)
{
    uint64_t x;

    if (v == NULL || v->t == J_NULL) {
        return NULL;
    }
    if (v->t == J_NUM && int_token(v->s, &x)) {
        return xprintf("%" PRIu64, x);
    }
#ifdef WE_LOOKUP_TEST_COUNT_STRING_PASSTHROUGH
    if (v->t == J_STR) {
        return xstrndup(v->s, v->slen);
    }
#endif
    if (v->t == J_STR && strlen(v->s) == v->slen && count_string_ok(v->s)) {
        return xstrndup(v->s, v->slen);
    }
    mnote(m, path, "not-a-count");
    return NULL;
}

/* A time: RFC 3339 judged on its instant, or an integer from 10^12 to the last millisecond of 9999. */
static tval_t f_time(manifest_t *m, const jnode_t *v, const char *path, int allow_int)
{
    tval_t t = { T_ABSENT, 0 };
    int64_t ms, year;
    uint64_t x;

    if (v == NULL) {
        return t;
    }
    if (v->t == J_NULL) {
        t.st = T_NULL;
        return t;
    }
    if (v->t == J_NUM && allow_int) {
        if (int_token(v->s, &x)) {
            if (x < UINT64_C(1000000000000)) {
#ifdef WE_LOOKUP_TEST_SMALL_INT_AS_INSTANT
                t.st = T_OK;
                t.ms = (int64_t)x;
                return t;
#endif
                mnote(m, path, "not-an-instant");
                t.st = T_REFUSED;
                return t;
            }
            if (x <= (uint64_t)MAX_MS) {
                t.st = T_OK;
                t.ms = (int64_t)x;
                return t;
            }
            mnote(m, path, "out-of-range");
            t.st = T_REFUSED;
            return t;
        }
        mnote(m, path, (strchr(v->s, '-') == v->s || strpbrk(v->s, ".eE") != NULL) ? "not-an-instant"
                                                                                : "out-of-range");
        t.st = T_REFUSED;
        return t;
    }
    if (v->t != J_STR) {
        mnote(m, path, "bad-time");
        t.st = T_REFUSED;
        return t;
    }
    if (strlen(v->s) != v->slen || !parse_rfc3339(v->s, v->slen, &ms, &year)) {
        mnote(m, path, reserved_token(v->s) ? "reserved-token" : "bad-time");
        t.st = T_REFUSED;
        return t;
    }
#ifdef WE_LOOKUP_TEST_YEAR_NOT_INSTANT
    if (year < 1970) {
        mnote(m, path, "before-1970");
        t.st = T_REFUSED;
        return t;
    }
    if (year <= 9999) {
        t.st = T_OK;
        t.ms = ms;
        return t;
    }
#endif
    if (ms < 0) {
#ifdef WE_LOOKUP_TEST_PRE_1970_ACCEPTED
        t.st = T_MS;
        t.ms = ms;
        return t;
#endif
        mnote(m, path, "before-1970");
        t.st = T_REFUSED;
        return t;
    }
    t.st = ms > MAX_MS ? T_MS : T_OK;
    t.ms = ms;
    return t;
}

static int sha_ok(const char *s, size_t n)
{
    size_t i;

    if (n != 64) {
        return 0;
    }
    for (i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int reason_token_ok(const char *s)
{
    size_t n = strlen(s), i;

    if (n == 0 || n > 64) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (!((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_')) {
            return 0;
        }
    }
    return 1;
}

/*
 * A withheld entry's reasons: reasons[] in the writer's order, with `reason` prepended when present and
 * missing from them, and [reason] when reasons[] is absent. At most eight, each [A-Z0-9_]{1,64}; a
 * non-string element, a ninth reason or a bad token refuses the field (not-stated), and so does an
 * invalid `reason`, which also prints not-stated itself.
 */
static void extract_withheld(manifest_t *m, const jnode_t *e, wentry_t *w, uint32_t idx)
{
    char path[96], rpath[96];
    const jnode_t *rs = jget(e, "reasons"), *r1 = jget(e, "reason");
    char *list[MAX_REASONS];
    int nlist = 0, k, refused = 0, reason_bad = 0;
    uint32_t i;

    snprintf(path, sizeof path, "withheld[%u].name", idx);
    w->name = f_string(m, jget(e, "name"), path);
    snprintf(rpath, sizeof rpath, "withheld[%u].reason", idx);
    snprintf(path, sizeof path, "withheld[%u].reasons", idx);
    if (r1 != NULL && r1->t == J_STR) {
#ifndef WE_LOOKUP_TEST_BAD_REASON_TOKEN
        if (strlen(r1->s) != r1->slen || !reason_token_ok(r1->s)) {
            mnote(m, rpath, "bad-token");
            reason_bad = 1;
        } else
#endif
        {
            w->reason = xstrndup(r1->s, r1->slen);
        }
    } else if (r1 != NULL && r1->t != J_NULL) {
        mnote(m, rpath, "not-a-string");
    }
#ifdef WE_LOOKUP_TEST_FIRST_REASON_ONLY
    rs = NULL;
#endif
#ifdef WE_LOOKUP_TEST_BAD_REASON_TOKEN
    (void)reason_token_ok;
#endif
    w->reasons_state = 1;
    if (reason_bad) {
        refused = 1;
    } else if (rs == NULL || rs->t == J_NULL) {
        if (w->reason != NULL) {
            list[nlist++] = xstrdup(w->reason);
        } else {
            w->reasons_state = 0;
        }
    } else if (rs->t != J_ARR) {
        mnote(m, path, "not-an-array");
        refused = 1;
    } else {
        int found = 0;
        uint32_t total;

        for (i = 0; i < rs->n; i++) {
            if (rs->kid[i]->t != J_STR) {
                mnote(m, path, "not-a-string");
                refused = 1;
                break;
            }
            if (w->reason != NULL && strcmp(rs->kid[i]->s, w->reason) == 0) {
                found = 1;
            }
        }
        total = w->reason != NULL && !found ? 1u : 0u;
        for (i = 0; i < rs->n && !refused; i++) {
            uint32_t q;
            int dup = 0;

            for (q = 0; q < i; q++) {
                dup |= strcmp(rs->kid[q]->s, rs->kid[i]->s) == 0;
            }
            total += dup ? 0u : 1u;
        }
#ifndef WE_LOOKUP_TEST_JR_NINE_REASONS
        if (!refused && total > MAX_REASONS) {
            mnote(m, path, "too-many");
            refused = 1;
        }
#else
        (void)total;
#endif
        if (!refused) {
            if (w->reason != NULL && !found) {
                list[nlist++] = xstrdup(w->reason);
            }
            for (i = 0; i < rs->n && nlist < MAX_REASONS; i++) {
                int seen = 0;

                for (k = 0; k < nlist; k++) {
                    seen |= strcmp(list[k], rs->kid[i]->s) == 0;   /* a reason repeated is one reason */
                }
                if (!seen) {
                    list[nlist++] = xstrndup(rs->kid[i]->s, rs->kid[i]->slen);
                }
            }
#ifndef WE_LOOKUP_TEST_BAD_REASON_TOKEN
            for (k = 0; k < nlist; k++) {
                if (!reason_token_ok(list[k])) {
                    mnote(m, path, "bad-token");
                    refused = 1;
                    break;
                }
            }
#endif
        }
    }
    if (refused) {
        w->reasons_state = 2;
        for (k = 0; k < nlist; k++) {
            free(list[k]);
        }
        nlist = 0;
    }
    for (k = 0; k < nlist; k++) {
        w->reasons[k] = list[k];
    }
    w->nreasons = nlist;
    snprintf(path, sizeof path, "withheld[%u].detail", idx);
    w->detail = f_string(m, jget(e, "detail"), path);
    snprintf(path, sizeof path, "withheld[%u].since", idx);
    w->since = f_time(m, jget(e, "since"), path, 1);
    snprintf(path, sizeof path, "withheld[%u].lastPublishedValidUntil", idx);
    w->lpvu = f_time(m, jget(e, "lastPublishedValidUntil"), path, 1);
    snprintf(path, sizeof path, "withheld[%u].builtGeneration", idx);
    {
        int ok;

        w->built_gen = f_integer(m, jget(e, "builtGeneration"), path, NULL, &ok);
    }
}

static void extract_entry(manifest_t *m, const jnode_t *e, pentry_t *p, uint32_t idx)
{
    char path[128];
    const jnode_t *sh = jget(e, "sha256"), *cov, *srcs;
    int ok;

    snprintf(path, sizeof path, "planes[%u].name", idx);
    p->name = f_string(m, jget(e, "name"), path);
    if (sh != NULL && sh->t == J_STR && sha_ok(sh->s, sh->slen)) {
        p->sha_ok = 1;
        memcpy(p->sha, sh->s, 64);
        p->sha[64] = '\0';
    } else {
        snprintf(path, sizeof path, "planes[%u].sha256", idx);
        mnote(m, path, "bad-sha256");
    }
    snprintf(path, sizeof path, "planes[%u].bytes", idx);
    free(f_integer(m, jget(e, "bytes"), path, &p->bytes, &p->bytes_ok));
    snprintf(path, sizeof path, "planes[%u].generation", idx);
    p->generation = f_integer(m, jget(e, "generation"), path, NULL, &ok);
    snprintf(path, sizeof path, "planes[%u].headerGeneration", idx);
    p->hgen = f_integer(m, jget(e, "headerGeneration"), path, NULL, &ok);
    snprintf(path, sizeof path, "planes[%u].builtAt", idx);
    p->built = f_time(m, jget(e, "builtAt"), path, 1);
    snprintf(path, sizeof path, "planes[%u].validUntil", idx);
    p->valid = f_time(m, jget(e, "validUntil"), path, 1);
    cov = jget(e, "coverage");
    p->coverage_null = cov == NULL || cov->t == J_NULL;
    if (cov != NULL && cov->t == J_OBJ) {
        p->cov_obj = 1;
#ifdef WE_LOOKUP_TEST_COVERAGE_SHAPE_REFUSED
        if (jget(cov, "v4Addresses") == NULL || jget(cov, "v6Addresses") == NULL
            || jget(cov, "v6Slash32s") == NULL) {
            m->state = M_REFUSED;
            snprintf(m->why, sizeof m->why, "coverage-shape");
        }
#endif
        snprintf(path, sizeof path, "planes[%u].coverage.v4Addresses", idx);
        p->cov_v4 = f_count(m, jget(cov, "v4Addresses"), path);
        snprintf(path, sizeof path, "planes[%u].coverage.v6Addresses", idx);
        p->cov_v6 = f_count(m, jget(cov, "v6Addresses"), path);
        snprintf(path, sizeof path, "planes[%u].coverage.v6Slash32s", idx);
        p->cov_s32 = f_count(m, jget(cov, "v6Slash32s"), path);
    } else if (cov != NULL && cov->t != J_NULL) {
        snprintf(path, sizeof path, "planes[%u].coverage", idx);
        mnote(m, path, "not-an-object");
    }
    srcs = jget(e, "sources");
    if (srcs != NULL && srcs->t == J_ARR) {
        uint32_t i;

        p->src = (src_t *)calloc(srcs->n ? srcs->n : 1, sizeof *p->src);
        if (p->src == NULL) {
            die_oom();
        }
        for (i = 0; i < srcs->n; i++) {
            const jnode_t *s = srcs->kid[i];
            src_t *o = &p->src[p->nsrc++];

            if (s->t != J_OBJ) {
                snprintf(path, sizeof path, "planes[%u].sources[%u]", idx, i);
                mnote(m, path, "not-an-object");
                o->observed.st = T_ABSENT;
                continue;
            }
            snprintf(path, sizeof path, "planes[%u].sources[%u].name", idx, i);
            o->name = f_string(m, jget(s, "name"), path);
            snprintf(path, sizeof path, "planes[%u].sources[%u].kind", idx, i);
            o->kind = f_string(m, jget(s, "kind"), path);
            snprintf(path, sizeof path, "planes[%u].sources[%u].count", idx, i);
            o->count = f_count(m, jget(s, "count"), path);
            snprintf(path, sizeof path, "planes[%u].sources[%u].observedAt", idx, i);
#ifdef WE_LOOKUP_TEST_OBSERVED_AT_AS_T
            o->observed = f_time(m, jget(s, "observedAt"), path, 0);
#else
            o->observed = f_time(m, jget(s, "observedAt"), path, 1);
#endif
            {
                const jnode_t *r = jget(s, "recall"), *pr = jget(s, "precision");

                o->recall = (r != NULL && r->t == J_NUM) ? xstrdup(r->s) : NULL;
                o->precision = (pr != NULL && pr->t == J_NUM) ? xstrdup(pr->s) : NULL;
                if (r != NULL && r->t != J_NUM && r->t != J_NULL) {
                    snprintf(path, sizeof path, "planes[%u].sources[%u].recall", idx, i);
                    mnote(m, path, "not-a-number");
                }
                if (pr != NULL && pr->t != J_NUM && pr->t != J_NULL) {
                    snprintf(path, sizeof path, "planes[%u].sources[%u].precision", idx, i);
                    mnote(m, path, "not-a-number");
                }
            }
        }
    } else if (srcs != NULL && srcs->t != J_NULL) {
        snprintf(path, sizeof path, "planes[%u].sources", idx);
        mnote(m, path, "not-an-array");
    }
}

/* Extract the fields the tool reads from a parsed manifest. */
static void extract(manifest_t *m, const jnode_t *root)
{
    const jnode_t *v;
    uint32_t i;
    int ok;

    if (root->t != J_OBJ) {
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "not-an-object");
        return;
    }
    m->generation = f_integer(m, jget(root, "generation"), "generation", NULL, &ok);
    m->built = f_time(m, jget(root, "builtAt"), "builtAt", 1);
    m->builder = f_string(m, jget(root, "builder"), "builder");
    m->tier = f_string(m, jget(root, "tier"), "tier");
    v = jget(root, "planes");
    if (v != NULL && v->t == J_ARR) {
        m->planes = (pentry_t *)calloc(v->n ? v->n : 1, sizeof *m->planes);
        if (m->planes == NULL) {
            die_oom();
        }
        for (i = 0; i < v->n; i++) {
            if (v->kid[i]->t != J_OBJ) {
                char path[48];

                snprintf(path, sizeof path, "planes[%u]", i);
                mnote(m, path, "not-an-object");
                continue;
            }
            extract_entry(m, v->kid[i], &m->planes[m->nplanes], i);
            m->nplanes++;
        }
    } else if (v != NULL && v->t != J_NULL) {
        mnote(m, "planes", "not-an-array");
    }
    v = jget(root, "legacy");
    if (v != NULL && v->t == J_ARR) {
        m->legacy = (lentry_t *)calloc(v->n ? v->n : 1, sizeof *m->legacy);
        if (m->legacy == NULL) {
            die_oom();
        }
        for (i = 0; i < v->n; i++) {
            const jnode_t *e = v->kid[i], *sh;
            lentry_t *l = &m->legacy[m->nlegacy];
            char path[64];

            if (e->t != J_OBJ) {
                snprintf(path, sizeof path, "legacy[%u]", i);
                mnote(m, path, "not-an-object");
                continue;
            }
            snprintf(path, sizeof path, "legacy[%u].name", i);
            l->name = f_string(m, jget(e, "name"), path);
            sh = jget(e, "sha256");
            if (sh != NULL && sh->t == J_STR && sha_ok(sh->s, sh->slen)) {
                l->sha_ok = 1;
                memcpy(l->sha, sh->s, 64);
                l->sha[64] = '\0';
            } else {
                snprintf(path, sizeof path, "legacy[%u].sha256", i);
                mnote(m, path, "bad-sha256");
            }
            snprintf(path, sizeof path, "legacy[%u].bytes", i);
            free(f_integer(m, jget(e, "bytes"), path, &l->bytes, &l->bytes_ok));
            snprintf(path, sizeof path, "legacy[%u].headerGeneration", i);
            l->hgen = f_integer(m, jget(e, "headerGeneration"), path, NULL, &ok);
            m->nlegacy++;
        }
    } else if (v != NULL && v->t != J_NULL) {
        mnote(m, "legacy", "not-an-array");
    }
    v = jget(root, "withheld");
    if (v != NULL && v->t == J_ARR) {
        m->withheld = (wentry_t *)calloc(v->n ? v->n : 1, sizeof *m->withheld);
        if (m->withheld == NULL) {
            die_oom();
        }
        for (i = 0; i < v->n; i++) {
            if (v->kid[i]->t != J_OBJ) {
                char path[48];

                snprintf(path, sizeof path, "withheld[%u]", i);
                mnote(m, path, "not-an-object");
                continue;
            }
            extract_withheld(m, v->kid[i], &m->withheld[m->nwithheld], i);
            {
                const char *nm = m->withheld[m->nwithheld].name;
                uint32_t q;

                for (q = 0; nm != NULL && q < m->nwithheld; q++) {
                    if (m->withheld[q].name != NULL && strcmp(m->withheld[q].name, nm) == 0) {
                        char path[48];

                        snprintf(path, sizeof path, "withheld[%u].name", i);
                        mnote(m, path, "duplicate-entry-ignored");
                        break;
                    }
                }
            }
            m->nwithheld++;
        }
    } else if (v != NULL && v->t != J_NULL) {
        mnote(m, "withheld", "not-an-array");
    }
#ifdef WE_LOOKUP_TEST_NULL_REFUSED
    if (m->built.st == T_NULL || (m->nwithheld && m->withheld[0].lpvu.st == T_NULL)) {
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "null");
    }
#endif
}

static void manifest_free(manifest_t *m)
{
    uint32_t i, k;

    free(m->generation);
    free(m->builder);
    free(m->tier);
    for (i = 0; i < m->nplanes; i++) {
        pentry_t *p = &m->planes[i];

        free(p->name);
        free(p->generation);
        free(p->hgen);
        free(p->cov_v4);
        free(p->cov_v6);
        free(p->cov_s32);
        for (k = 0; k < p->nsrc; k++) {
            free(p->src[k].name);
            free(p->src[k].kind);
            free(p->src[k].count);
            free(p->src[k].recall);
            free(p->src[k].precision);
        }
        free(p->src);
    }
    free(m->planes);
    for (i = 0; i < m->nlegacy; i++) {
        free(m->legacy[i].name);
        free(m->legacy[i].hgen);
    }
    free(m->legacy);
    for (i = 0; i < m->nwithheld; i++) {
        wentry_t *w = &m->withheld[i];

        free(w->name);
        for (k = 0; k < (uint32_t)w->nreasons; k++) {
            free(w->reasons[k]);
        }
        free(w->reason);
        free(w->detail);
        free(w->built_gen);
    }
    free(m->withheld);
    for (i = 0; i < m->nfnotes; i++) {
        free(m->fnotes[i]);
    }
    free(m->fnotes);
    memset(m, 0, sizeof *m);
}

/* Parse and extract a manifest held in memory: the part the fuzz harness drives. */
static void manifest_from_bytes(manifest_t *m, const uint8_t *buf, size_t n)
{
    jnode_t *root = json_parse(buf, n, m->why, sizeof m->why);

    if (root == NULL) {
        m->state = M_REFUSED;
        return;
    }
    m->state = M_READ;
    extract(m, root);
    jfree(root);
}

/*
 * Read one manifest through its directory's descriptor: no symlink, a regular file, no group or world
 * write bit on it or its directory, owned by the directory's owner or root, at most 1 MiB.
 */
TOOL_FN void manifest_read_at(manifest_t *m, int dfd, const struct stat *dst, const char *dirpath)
{
    struct stat st;
    int fd;
    uint8_t *buf;
    size_t got = 0;

    (void)dirpath;
    if (fstatat(dfd, "manifest.json", &st, AT_SYMLINK_NOFOLLOW) != 0) {
        m->state = M_ABSENT;
        return;
    }
#ifndef WE_LOOKUP_TEST_MANIFEST_NO_MODE
    if (S_ISLNK(st.st_mode)) {
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "symlink");
        return;
    }
    fd = openat(dfd, "manifest.json", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
#else
    fd = openat(dfd, "manifest.json", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
#endif
    if (fd < 0) {
        m->state = errno == ELOOP ? M_REFUSED : M_UNREADABLE;
        snprintf(m->why, sizeof m->why, "%s", errno == ELOOP ? "symlink" : errno == EACCES ? "permission" : "open");
        return;
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        m->state = M_UNREADABLE;
        snprintf(m->why, sizeof m->why, "open");
        return;
    }
#ifndef WE_LOOKUP_TEST_MANIFEST_NO_MODE
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "not-regular");
        return;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "group-or-world-writable");
        return;
    }
    if ((dst->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "directory-writable");
        return;
    }
    if (st.st_uid != dst->st_uid && st.st_uid != 0) {
        close(fd);
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "foreign-owner");
        return;
    }
#else
    (void)dst;
#endif
    if ((uint64_t)st.st_size > MANIFEST_MAX) {
        close(fd);
        m->state = M_REFUSED;
        snprintf(m->why, sizeof m->why, "too-large");
        return;
    }
    buf = (uint8_t *)malloc((size_t)st.st_size + 1);
    if (buf == NULL) {
        die_oom();
    }
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
    }
    close(fd);
    if (got != (size_t)st.st_size) {
        free(buf);
        m->state = M_UNREADABLE;
        snprintf(m->why, sizeof m->why, "read");
        return;
    }
    manifest_from_bytes(m, buf, got);
    free(buf);
}

/* ======================================================================================================
 * Everything below main's helpers is the tool proper; a fuzz harness that includes this file for the
 * manifest reader defines WE_LOOKUP_READER_ONLY and stops here.
 * ==================================================================================================== */
#ifndef WE_LOOKUP_READER_ONLY

/* ---- the output model: a line is a kind, positionals and keys; it prints as a line or a JSON object ---- */

typedef struct {
    const char *name;     /* the key's name in the line form */
    char        type;     /* n s d b t l u (attr value) */
    char       *v;        /* NULL: does not apply in this state */
    char       *ms;       /* t: the Ms sibling */
    int         pos;      /* a positional */
} fld_t;

typedef struct {
    const char *kind;
    int         n;
    fld_t       f[40];
} line_t;

static int g_json;
static sb_t g_out;
static int g_write_failed;

static void out_flush(void)
{
    if (g_out.n) {
        if (fwrite(g_out.p, 1, g_out.n, stdout) != g_out.n) {
            g_write_failed = 1;
        }
        g_out.n = 0;
        g_out.p[0] = '\0';
    }
}

static void L_init(line_t *l, const char *kind)
{
    memset(l, 0, sizeof *l);
    l->kind = kind;
}

static fld_t *L_add(line_t *l, const char *name, char type, char *v, int pos)
{
    fld_t *f = &l->f[l->n++];

    f->name = name;
    f->type = type;
    f->v = v;
    f->pos = pos;
    return f;
}

static void L_pos(line_t *l, const char *name, char type, const char *v)
{
    L_add(l, name, type, v ? xstrdup(v) : NULL, 1);
}

static void L_key(line_t *l, const char *name, char type, const char *v)
{
    L_add(l, name, type, v ? xstrdup(v) : NULL, 0);
}

static void L_keyn(line_t *l, const char *name, uint64_t v)
{
    L_add(l, name, 'n', xprintf("%" PRIu64, v), 0);
}

static void L_keyd(line_t *l, const char *name, uint64_t v)
{
#ifdef WE_LOOKUP_TEST_TYPE_BY_MAGNITUDE
    L_add(l, name, v < (UINT64_C(1) << 53) ? 'n' : 'd', xprintf("%" PRIu64, v), 0);
#else
    L_add(l, name, 'd', xprintf("%" PRIu64, v), 0);
#endif
}

static void L_keyb(line_t *l, const char *name, int v)
{
    L_add(l, name, 'b', xstrdup(v ? "yes" : "no"), 0);
}

static void L_null(line_t *l, const char *name, char type)
{
    L_add(l, name, type, NULL, 0);
}

/* A t field from an epoch-millisecond value: `none` for 0 when `zero_none`, ms:<decimal> past 9999. */
static void L_keyt_u64(line_t *l, const char *name, uint64_t ms, int zero_none)
{
    fld_t *f = L_add(l, name, 't', NULL, 0);

    if (zero_none && ms == 0) {
        f->v = xstrdup("none");
        f->ms = xstrdup("none");
    } else if (ms > (uint64_t)MAX_MS) {
        f->v = xprintf("ms:%" PRIu64, ms);
        f->ms = xprintf("%" PRIu64, ms);
    } else {
        sb_t s = {0};

        fmt_instant(&s, (int64_t)ms);
        f->v = s.p;
        f->ms = xprintf("%" PRIu64, ms);
    }
}

static void L_keyt(line_t *l, const char *name, tval_t t)
{
    fld_t *f = L_add(l, name, 't', NULL, 0);

    switch (t.st) {
    case T_OK: {
        sb_t s = {0};

        fmt_instant(&s, t.ms);
        f->v = s.p;
        f->ms = xprintf("%" PRId64, t.ms);
        break;
    }
    case T_MS:
        f->v = xprintf("ms:%" PRId64, t.ms);
        f->ms = xprintf("%" PRId64, t.ms);
        break;
    default:
        f->v = xstrdup("not-stated");
        f->ms = xstrdup("not-stated");
        break;
    }
}

static void L_free(line_t *l)
{
    int i;

    for (i = 0; i < l->n; i++) {
        free(l->f[i].v);
        free(l->f[i].ms);
    }
    l->n = 0;
}

/* `model-from` -> `modelFrom` */
static void camel(sb_t *o, const char *name)
{
#ifdef WE_LOOKUP_TEST_JSON_SNAKE_CASE
    for (; *name; name++) {
        sb_putc(o, *name == '-' ? '_' : *name);
    }
#else
    int up = 0;

    for (; *name; name++) {
        if (*name == '-') {
            up = 1;
            continue;
        }
        sb_putc(o, up ? (char)toupper((unsigned char)*name) : *name);
        up = 0;
    }
#endif
}

static void print_line(sb_t *o, const line_t *l)
{
    int i;

    sb_puts(o, l->kind);
    for (i = 0; i < l->n; i++) {
        const fld_t *f = &l->f[i];

        if (f->pos) {
            sb_putc(o, ' ');
            if (f->type == 'u' && f->v == NULL) {
                sb_puts(o, "UNKNOWN");
            } else {
#ifdef WE_LOOKUP_TEST_UNQUOTED_POSITIONAL
                line_token(o, f->v ? f->v : "", strcmp(f->name, "input") == 0);
#else
                line_token(o, f->v ? f->v : "", 0);
#endif
            }
            continue;
        }
        if (f->v == NULL) {
            continue;
        }
        sb_putc(o, ' ');
        sb_puts(o, f->name);
        sb_putc(o, '=');
        line_token(o, f->v, 0);
    }
    sb_putc(o, '\n');
}

static void json_value(sb_t *o, const fld_t *f)
{
    if (f->v == NULL) {
        sb_puts(o, "null");
    } else if (f->type == 'n') {
        sb_puts(o, f->v);
    } else if (f->type == 'b') {
        sb_puts(o, strcmp(f->v, "yes") == 0 ? "true" : "false");
    } else {
        json_string(o, f->v);
    }
}

/* the fields of a line as JSON members, no braces; *first tracks the comma */
static void print_members(sb_t *o, const line_t *l, int *first)
{
    int i;

    for (i = 0; i < l->n; i++) {
        const fld_t *f = &l->f[i];

#ifdef WE_LOOKUP_TEST_JSON_DROP_KEY
        if (strcmp(f->name, "range") == 0) {
            continue;
        }
#endif
        if (!*first) {
            sb_putc(o, ',');
        }
        *first = 0;
        sb_putc(o, '"');
        camel(o, f->name);
        sb_puts(o, "\":");
        if (f->type == 't') {
            if (f->v != NULL && strncmp(f->v, "ms:", 3) == 0) {
                sb_puts(o, "null");
            } else {
                json_value(o, f);
            }
            sb_putc(o, ',');
            sb_putc(o, '"');
            camel(o, f->name);
            sb_puts(o, "Ms\":");
            if (f->ms == NULL) {
                sb_puts(o, "null");
            } else {
                json_string(o, f->ms);
            }
        } else {
            json_value(o, f);
        }
    }
}

static void print_obj(sb_t *o, const line_t *l)
{
    int first = 1;

    sb_putc(o, '{');
    print_members(o, l, &first);
    sb_putc(o, '}');
}

/* ---- notes ---- */

typedef struct {
    char   **v;
    uint32_t n;
} notes_t;

static void note_add(notes_t *ns, char *text)
{
    char **v = (char **)realloc(ns->v, (ns->n + 1) * sizeof *v);

    if (v == NULL) {
        die_oom();
    }
    ns->v = v;
    ns->v[ns->n++] = text;
}

static void notes_free(notes_t *ns)
{
    uint32_t i;

    for (i = 0; i < ns->n; i++) {
        free(ns->v[i]);
    }
    free(ns->v);
    memset(ns, 0, sizeof *ns);
}

/* ======================================================================================================
 * The run's configuration
 * ==================================================================================================== */

enum { MODEL_DATA, MODEL_LEGACY };
enum { PS_ABSENT, PS_FRESH, PS_STALE, PS_REFUSED };
enum { RF_NONE, RF_PRESENT, RF_NOT_PRESENT, RF_PERMISSION };

typedef struct {
    int         idx;              /* 0..7 */
    const char *name;
    int         state;            /* PS_* */
    int         refused_kind;     /* RF_* */
    char        refused[32];
    char       *refused_detail;
    char       *path;
    char        file[64];
    int         armed;
    we_map_t    map;              /* a copy of the armed map's descriptor, for the plane line */
    const we_map_t *view;         /* what the evaluator reads: the handle's current map, or the generation-0 copy */
    int         hashed;
    char        digest[65];
    /* binding */
    int         bound;            /* 1 bound */
    int         bound_m;          /* manifest index 0 keyless, 1 keyed */
    int         bound_legacy;
    const pentry_t *entry;
    const lentry_t *lentry;
    char        why_bind[32];
    char       *entry_generation;
    int         manifest_refused;
    int         named_any;
} plane_t;

typedef struct {
    int         model;
    const char *model_from;
    int         prestage;         /* 1 present */
    char       *dir;              /* the data model's directory, or dirname(FILE) */
    char       *snapshot;
    int         dir_writable;
    int64_t     now_ms;
    int         json;
    int         fields;
    int         want_case;
    int         old_form;
    int         threshold;        /* WE_SEV_* or 0 for off */
    const char *threshold_name;
    int         mode_deny;
    int         allow_inferred;
    int         skipped_hop;
    int         acme;
    const char *context;
    const char *policy;
    int         policy_given;
    int         threshold_given;
    int         mode_given;
    manifest_t  man[2];
    int         any_read;
    plane_t     planes[8];
    notes_t     notes;
    /* the policy: the compiled configuration, the two programs step 3 and step 4 run, their confs */
    we_policy_env_t env;          /* the first probe's (the data model), or the legacy directive's */
    we_policy_build_t *build;
    const we_program_t *floor;
    const we_program_t *ctx;
    we_ctx_conf_t floor_conf;
    we_ctx_conf_t ctx_conf;
    const char *policy_source;    /* builtin-default sugar none file policy-conf */
    int         installed;        /* the installed policy.conf: 1 there, 0 absent, -1 this uid cannot look */
    int         sugar;
    int         has_floor;        /* the configuration writes floor lines */
    char        digest[65];       /* sha256 of the policy text as read */
    char       *floor_text;       /* we_program_print of each program, one rule per line */
    char       *ctx_text;
    sb_t        reports;          /* the compiler's report lines, oracle form, LF-separated */
    /* the directives, for --case */
    we_policy_directive_t *dirs;
    size_t      ndirs;
    char      **dir_ctx;
} run_t;

static run_t R;

/* ---- the clock: one sample per run (or --now) ---- */

static int64_t clock_now_ms(void)
{
#ifdef WE_LOOKUP_TEST_NOW_GETTIMEOFDAY
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* ---- the module's own verdict on the planes ---- */

/* the workers' uid the bind's checks are made for (--uid; the uid running the tool by default) */
static unsigned g_bind_uid;

/*
 * The module's bind verdict on every plane, from we_mod_bind_check(): the check-only bind a configuration
 * test runs, the same code as the bind, so a plane this tool reads is one the module would map. `dir` is a
 * data directory, or NULL with `legacy` the whisper_edge_snapshot file. A relative path is anchored at the
 * working directory, lexically, so the walk still sees every link. 0, or -1 with `msg`.
 */
static int lk_bind_verdict(const char *dir, const char *legacy, we_mod_plane_check_t out[8], char *msg, size_t msgn)
{
    static char abs_dir[PATH_MAX], abs_file[PATH_MAX];
    char cwd[PATH_MAX];
    we_mod_bind_args_t a;
    const char *have_cwd = getcwd(cwd, sizeof cwd) != NULL ? (strcmp(cwd, "/") == 0 ? "" : cwd) : NULL;

    memset(&a, 0, sizeof a);
    a.abi = WE_MODULE_ABI_VERSION;
    a.read_mask = 0xffu;
    a.uid = g_bind_uid;
    if (dir != NULL) {
        a.data_dir = dir;
        if (dir[0] != '/' && have_cwd != NULL
                && (size_t)snprintf(abs_dir, sizeof abs_dir, "%s/%s", have_cwd, dir) < sizeof abs_dir) {
            a.data_dir = abs_dir;
        }
    } else {
        a.legacy_file = legacy;
        if (legacy != NULL && legacy[0] != '/' && have_cwd != NULL
                && (size_t)snprintf(abs_file, sizeof abs_file, "%s/%s", have_cwd, legacy) < sizeof abs_file) {
            a.legacy_file = abs_file;
        }
    }
    return we_mod_bind_check(&a, out, msg, msgn) == 0 ? 0 : -1;
}

/* ---- the plane loads ---- */

/* the module's staleness test, the one the request path runs */
static int plane_stale(const we_map_t *m)
{
#ifdef WE_LOOKUP_TEST_STALE_NO_ZERO
    return (uint64_t)R.now_ms > m->valid_until_ms;
#else
    return we_is_stale(m, (uint64_t)R.now_ms);
#endif
}

static const char *refused_code(int rc, const we_load_detail_t *d)
{
    const char *what = d != NULL ? d->what : NULL;

    switch (rc) {
    case WE_ERR_PERMISSIONS: return "mode";
    case WE_ERR_FORMAT:      return what != NULL && strncmp(what, "generation 0", 12) == 0 ? "generation" : "format";
    case WE_ERR_OPEN:        return what != NULL && (strcmp(what, "not a regular file") == 0
                                                     || strncmp(what, "changed to a non-regular", 24) == 0)
                                    ? "not-regular" : "open";
    case WE_ERR_TOO_SMALL:   return "too-small";
    case WE_ERR_MAGIC:       return "magic";
    case WE_ERR_TRUNCATED:   return "truncated";
    case WE_ERR_OFFSETS:     return "offsets";
    case WE_ERR_UNSORTED:    return "unsorted";
    case WE_ERR_OVERLAP:     return "overlap";
    case WE_ERR_DIGEST:      return "digest";
    case WE_ERR_MMAP:        return "memory";
    case WE_ERR_ROLLBACK:    return "rollback";
    default:                 return "unknown";
    }
}

static char *detail_text(int rc, const we_load_detail_t *d)
{
    if (d == NULL || d->what == NULL) {
        return xstrdup(we_strerror(rc));
    }
    if (d->record >= 0) {
#ifdef WE_LOOKUP_TEST_DETAIL_FROM_OTHER
        if (strncmp(d->what, "rov outside", 11) == 0) {
            return xprintf("rir outside 0..5: IPv%d record %" PRId64, d->family, d->record);
        }
#endif
        return xprintf("%s: IPv%d record %" PRId64, d->what, d->family, d->record);
    }
    return xstrdup(d->what);
}

/*
 * The core's "cannot open" text, with the reason: the path cannot be looked at (stat fails), it is a
 * directory (named from its mode, nothing opened), or it is a regular file this uid cannot open (one
 * non-blocking open, closed at once if it succeeds). Anything else at the path, a FIFO among them, keeps
 * the core's text as it is.
 */
static char *open_detail(int rc, char *det, const char *path)
{
    struct stat st;

#ifndef WE_LOOKUP_TEST_SNAPSHOT_OPEN_NO_ERRNO
    if (rc == WE_ERR_OPEN) {
        int err = 0;

        if (stat(path, &st) != 0) {
            err = errno;
        } else if (S_ISDIR(st.st_mode)) {
            err = EISDIR;                   /* named from the mode; nothing is opened */
        } else if (S_ISREG(st.st_mode)) {
            int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);

            if (fd < 0) {
                err = errno;
            } else {
                close(fd);
            }
        }
        if (err != 0) {
            char *withwhy = xprintf("%s: %s", det, strerror(err));

            free(det);
            return withwhy;
        }
    }
#else
    (void)rc;
    (void)path;
    (void)st;
#endif
    return det;
}

/*
 * What a failed look at a path says. ENOENT and ENOTDIR: nothing is there. EACCES and EPERM: this uid
 * may not look, and another uid (the one the module loads as) may see something. Anything else (a
 * symlink loop, a name too long, an I/O error) fails for every uid alike.
 */
enum { LOOK_ABSENT, LOOK_DENIED, LOOK_BROKEN };

static int look_class(int e)
{
    if (e == ENOENT || e == ENOTDIR) {
        return LOOK_ABSENT;
    }
#ifdef WE_LOOKUP_TEST_LOOP_AS_PERMISSION
    return LOOK_DENIED;
#else
    return e == EACCES || e == EPERM ? LOOK_DENIED : LOOK_BROKEN;
#endif
}

/*
 * The installed policy.conf, looked at once per run and the answer kept: 1 there, 0 absent, -1 this
 * uid cannot look (the errno in *err). A look that cannot answer is neither present nor absent.
 */
static int installed_look(const char *conf, int *err)
{
    static int done, state, saved;
    struct stat st;

    if (!done) {
        done = 1;
        state = 0;
        if (stat(conf, &st) == 0) {
            state = 1;
        } else if (look_class(errno) != LOOK_ABSENT) {
            saved = errno;
            state = -1;
#ifdef WE_LOOKUP_TEST_INSTALLED_IGNORES_ERRNO
            state = 0;
#endif
        }
    }
    *err = saved;
    return state;
}

/* "cannot look at <what> <path>: <errno>" on standard error; returns 2 */
static int cannot_look(const char *what, const char *path, int err)
{
    char why[160];

    snprintf(why, sizeof why, ": %s", strerror(err));
    err_rendered(what, path, why);
    return 2;
}

/*
 * What the probe could not tell apart, for a plane path it found absent: a regular file this uid cannot
 * open, or a path this uid may not look at (EACCES or EPERM: a directory it cannot search), either of
 * which the module, loading as another user, may arm; or something at the path no uid can follow (a
 * dangling symlink, a loop, a name too long), whose rules are inert at config. Only stat() and lstat(),
 * so the path is opened exactly as often as the module opens it: the probe, the load, the probe again.
 */
static int classify_absent(const char *path, int *err)
{
    struct stat st, lst;

    *err = 0;
    if (stat(path, &st) == 0) {
        return S_ISREG(st.st_mode) ? RF_PERMISSION : RF_NONE;
    }
    *err = errno;
    if (lstat(path, &lst) == 0) {
        return RF_NOT_PRESENT;
    }
#ifndef WE_LOOKUP_TEST_CLASSIFY_IGNORES_ERRNO
    *err = errno;
    switch (look_class(errno)) {
    case LOOK_DENIED:
        return RF_PERMISSION;
    case LOOK_BROKEN:
        return RF_NOT_PRESENT;
    default:
        break;
    }
#endif
    return RF_NONE;
}

static void hash_plane(plane_t *p)
{
    we_sha256_ctx c;
    uint8_t d[32];
    int i;

    we_sha256_init(&c);
    we_sha256_update(&c, p->map.base, p->map.len);
    we_sha256_final(&c, d);
    for (i = 0; i < 32; i++) {
        snprintf(p->digest + 2 * i, 3, "%02x", d[i]);
    }
    p->hashed = 1;
}

/* One handle per plane, as the module keeps them; the run arms each at most once. */
static we_handle_t g_h[8];
#ifndef WE_LOOKUP_TEST_GEN0_AS_REVOKED
/* a generation-0 format-1 snapshot armed by the legacy loader, copied with generation 1 */
static we_map_t g_gen0_copy;
#endif

#ifdef WE_LOOKUP_TEST_LOAD_AROUND_MODE
/* the mutant: a group-writable plane copied to a private 0644 file and loaded from there */
static int load_around_mode(int i, const char *path, we_load_detail_t *d)
{
    char tmp[] = "/tmp/we-lookup-mutant-XXXXXX";
    int in = open(path, O_RDONLY), out = mkstemp(tmp), rc;
    char buf[65536];
    ssize_t r;

    while (in >= 0 && out >= 0 && (r = read(in, buf, sizeof buf)) > 0) {
        if (write(out, buf, (size_t)r) != r) {
            break;
        }
    }
    if (in >= 0) {
        close(in);
    }
    if (out >= 0) {
        fchmod(out, 0644);
        close(out);
    }
    rc = we_handle_publish_plane(&g_h[i], tmp, (uint64_t)R.now_ms, d);
    unlink(tmp);
    return rc;
}
#endif

static void plane_set_refused(plane_t *p, int kind, const char *code, char *detail)
{
    p->state = PS_REFUSED;
    p->refused_kind = kind;
    {
        /* a refusal code is a short word from refused_code(); copied bounded, never truncated mid-word */
        size_t n = strlen(code);

        n = n < sizeof p->refused - 1 ? n : sizeof p->refused - 1;
        memcpy(p->refused, code, n);
        p->refused[n] = '\0';
    }
    free(p->refused_detail);
    p->refused_detail = detail;
}

static void plane_arm(plane_t *p, const we_map_t *cur)
{
    p->armed = 1;
    p->map = *cur;
    p->view = cur;
}

/* classify_absent() over every plane path the first probe found absent */
static void classify_all(int kinds[8], int errs[8])
{
    int i;

    for (i = 0; i < 8; i++) {
        kinds[i] = RF_NONE;
        errs[i] = 0;
        if (!((R.env.present >> i) & 1u)) {
            kinds[i] = classify_absent(R.planes[i].path, &errs[i]);
        }
    }
}

/*
 * The data model, in the module's order: the probe ran before the policy was built (main), so here the
 * load, then the probe again, and the blocks are held to the second probe with we_program_env_matches()
 * as a module holds them at load. Presence is the first probe's; the state is the loader's; a plane the
 * probe found absent is never read, whatever its load did.
 */
static int load_data_model(void)
{
    int i, rc[8], kinds[8], errs[8];
    char code[8][32], msg[512];
    char *detail[8];
    we_policy_env_t env2;
    static we_mod_plane_check_t bind[8];

    for (i = 0; i < 8; i++) {
        plane_t *p = &R.planes[i];
        we_load_detail_t d;

        p->idx = i;
        p->name = we_plane_tier[i].name;
        snprintf(p->file, sizeof p->file, "%s.bin", p->name);
        p->path = xprintf("%s/%s.bin", R.dir, p->name);
        memset(&d, 0, sizeof d);
        detail[i] = NULL;
        rc[i] = we_handle_publish_plane(&g_h[i], p->path, (uint64_t)R.now_ms, &d);
#ifdef WE_LOOKUP_TEST_LOAD_AROUND_MODE
        if (rc[i] == WE_ERR_PERMISSIONS) {
            rc[i] = load_around_mode(i, p->path, &d);
        }
#endif
        if (rc[i] == WE_OK) {
            plane_arm(p, we_current(&g_h[i]));
        } else {
            snprintf(code[i], sizeof code[i], "%s", refused_code(rc[i], &d));
            detail[i] = detail_text(rc[i], &d);
        }
    }
    /* the module's own verdict, inside the run's two probes: a plane the bind would refuse is not read */
    if (lk_bind_verdict(R.dir, NULL, bind, msg, sizeof msg) != 0) {
        fprintf(stderr, "whisper-edge-lookup: cannot check %s as the module binds it: %s\n", R.dir, msg);
        for (i = 0; i < 8; i++) {
            free(detail[i]);
        }
        return 2;
    }
    /*
     * What sits at each path the first probe found absent is looked at now, before the second probe: a
     * plane that appears after this look changes the second probe, and the run says the directory changed
     * rather than blaming a permission or a dangling link; one that appears after the second probe is
     * outside the run, as it is for the module, and reads absent.
     */
#ifndef WE_LOOKUP_TEST_CLASSIFY_AFTER_PROBE
    classify_all(kinds, errs);
#endif
    memset(&env2, 0, sizeof env2);
    we_policy_env_probe(R.dir, &env2);
#ifdef WE_LOOKUP_TEST_CLASSIFY_AFTER_PROBE
    classify_all(kinds, errs);
#endif
#ifdef WE_LOOKUP_TEST_NO_SECOND_PROBE
    (void)env2;
    (void)detail;
#else
    if (env2.present != R.env.present
        || (R.floor != NULL && we_program_env_matches(R.floor, &env2) != 0)
        || (R.ctx != NULL && we_program_env_matches(R.ctx, &env2) != 0)) {
        fputs("whisper-edge-lookup: the directory changed during this run (a plane appeared or "
              "disappeared); re-run\n", stderr);
        for (i = 0; i < 8; i++) {
            free(detail[i]);
        }
        return 2;
    }
#endif
    for (i = 0; i < 8; i++) {
        plane_t *p = &R.planes[i];
        int present = (R.env.present >> i) & 1u, err = errs[i];

#ifdef WE_LOOKUP_TEST_PROBE_FROM_LOAD
        present = p->armed;
#endif
        if (!present) {
            int kind = kinds[i];

            p->armed = 0;               /* the probe found it absent: its handle is never read */
            p->view = NULL;
            if (kind == RF_PERMISSION) {
#ifdef WE_LOOKUP_TEST_PERMISSION_AS_INERT
                plane_set_refused(p, RF_NOT_PRESENT, "open", xstrdup("cannot open"));
#else
                plane_set_refused(p, RF_PERMISSION, "permission",
                                  err != 0 ? xprintf("cannot open: %s", strerror(err)) : xstrdup("cannot open"));
#endif
            } else if (kind == RF_NOT_PRESENT) {
                plane_set_refused(p, RF_NOT_PRESENT, "open", xstrdup(strerror(err)));
#ifndef WE_LOOKUP_TEST_ADDR_OWN_RULES
            } else if (strcmp(bind[i].state, "refused") == 0) {
                /* nothing here, and the module refuses the plane anyway: its directory fails the walk */
                plane_set_refused(p, RF_NOT_PRESENT, "trust", xstrdup(bind[i].reason));
#endif
            } else {
                p->state = PS_ABSENT;
                p->refused_kind = RF_NONE;
            }
            free(detail[i]);
            continue;
        }
#ifndef WE_LOOKUP_TEST_ADDR_OWN_RULES
        if (p->armed && strcmp(bind[i].state, "verified") != 0) {
            /* the loader read it, and the module would not map it (mode, owner, link, directory, file
             * system): refused with the module's reason, and never read for an address */
            p->armed = 0;
            p->view = NULL;
            free(detail[i]);
            plane_set_refused(p, RF_PRESENT, "trust", xstrdup(bind[i].reason[0] != '\0' ? bind[i].reason
                                                              : "the module does not bind it"));
            continue;
        }
#endif
        if (p->armed) {
            p->state = plane_stale(&p->map) ? PS_STALE : PS_FRESH;
            free(detail[i]);
        } else {
            plane_set_refused(p, RF_PRESENT, code[i], detail[i]);
        }
#ifdef WE_LOOKUP_TEST_REFUSED_ALWAYS_STALE
        if (p->state == PS_REFUSED) {
            p->state = PS_STALE;
        }
#endif
    }
    /* snapshot.bin is never a plane under the data directive */
    {
        char *snap = xprintf("%s/snapshot.bin", R.dir);
        struct stat st;

        if (R.planes[0].state == PS_ABSENT && stat(snap, &st) == 0) {
#ifdef WE_LOOKUP_TEST_SNAPSHOT_AS_REPUTATION
            we_load_detail_t d;

            memset(&d, 0, sizeof d);
            if (we_handle_publish_plane(&g_h[0], snap, (uint64_t)R.now_ms, &d) == WE_OK) {
                plane_arm(&R.planes[0], we_current(&g_h[0]));
                R.planes[0].state = plane_stale(&R.planes[0].map) ? PS_STALE : PS_FRESH;
            }
#else
            note_add(&R.notes, xstrdup("snapshot.bin is read only through whisper_edge_snapshot; see --snapshot"));
#endif
        }
        free(snap);
    }
    return 0;
}

/*
 * The legacy model: FILE as whisper_edge_snapshot reads it, as reputation; every other plane absent.
 * Without the pre-stage, through we_handle_publish(), the call every shipped module makes; with it,
 * through we_handle_publish_plane(), which takes format 2 and refuses generation 0.
 */
static int load_legacy_model(void)
{
    int i, rc;
    plane_t *p = &R.planes[0];
    we_load_detail_t d;
    const char *base = strrchr(R.snapshot, '/');

    for (i = 0; i < 8; i++) {
        R.planes[i].idx = i;
        R.planes[i].name = we_plane_tier[i].name;
        snprintf(R.planes[i].file, sizeof R.planes[i].file, "%s.bin", R.planes[i].name);
        R.planes[i].state = PS_ABSENT;
    }
    snprintf(p->file, sizeof p->file, "%.60s", base ? base + 1 : R.snapshot);
    p->path = xstrdup(R.snapshot);
    memset(&d, 0, sizeof d);
#ifdef WE_LOOKUP_TEST_LEGACY_LOADER_IS_PLANE
    if (1) {
#else
    if (R.prestage) {
#endif
        rc = we_handle_publish_plane(&g_h[0], R.snapshot, (uint64_t)R.now_ms, &d);
        if (rc != WE_OK) {
            plane_set_refused(p, RF_PRESENT, refused_code(rc, &d), open_detail(rc, detail_text(rc, &d), R.snapshot));
            return 0;
        }
        plane_arm(p, we_current(&g_h[0]));
    } else {
        rc = we_handle_publish(&g_h[0], R.snapshot, (uint64_t)R.now_ms);
        if (rc != WE_OK) {
            plane_set_refused(p, RF_PRESENT, refused_code(rc, NULL), open_detail(rc, xstrdup(we_strerror(rc)), R.snapshot));
            return 0;
        }
        plane_arm(p, we_current(&g_h[0]));
#ifndef WE_LOOKUP_TEST_GEN0_AS_REVOKED
        if (p->map.generation == 0) {
            /*
             * The legacy request path reads a generation-0 file like any other; the evaluator reads
             * generation 0 as nothing armed. The copy (pointers into the same buffer) is what this
             * module generation's lookup reads, so the verdict and the decision describe one request.
             */
            g_gen0_copy = p->map;
            g_gen0_copy.generation = 1;
            p->view = &g_gen0_copy;
        }
#endif
    }
#ifndef WE_LOOKUP_TEST_ARM_NO_SCHEMA_CHECK
    {
        uint32_t id = (p->map.h->flags & WE_H_SCHEMA) != 0u ? p->map.h->schema.plane_id : 1u;

        if (id != 1u || p->map.format != WE_FORMAT_1) {
            char *det = id != 1u ? xprintf("carries plane %u, not reputation's 1", id)
                                 : xprintf("format %u, not reputation's 1", p->map.format);

            p->armed = 0;
            p->view = NULL;
            plane_set_refused(p, RF_PRESENT, "binding", det);
            return 0;
        }
    }
#endif
#ifndef WE_LOOKUP_TEST_ADDR_OWN_RULES
    if (R.prestage) {
        /* the module's own verdict on the snapshot file, after the loader's and the binding's, which name a
         * refusal more finely: its directory chain walked, its mode checked. Only for the module this build
         * is (the pre-stage present): without it the model is an earlier generation's, whose loader is the
         * core's alone */
        static we_mod_plane_check_t bind[8];
        char msg[512];

        if (lk_bind_verdict(NULL, R.snapshot, bind, msg, sizeof msg) != 0) {
            p->armed = 0;
            p->view = NULL;
            plane_set_refused(p, RF_PRESENT, "trust", xprintf("the module refuses the configuration: %s", msg));
            return 0;
        }
        if (strcmp(bind[0].state, "verified") != 0) {
            p->armed = 0;
            p->view = NULL;
            plane_set_refused(p, RF_PRESENT, "trust", xstrdup(bind[0].reason[0] != '\0' ? bind[0].reason
                                                              : "the module does not bind it"));
            return 0;
        }
    }
#endif
    p->state = plane_stale(&p->map) ? PS_STALE : PS_FRESH;
    if (p->map.generation == 0) {
        note_add(&R.notes, xstrdup("format-1 generation 0: a module with the policy evaluator refuses this "
                                   "file, and its evaluator reads generation 0 as nothing armed"));
    }
    return 0;
}

/* ---- manifests and binding ---- */

static void read_manifests(void)
{
    int dfd;
    struct stat dst, kst;

    R.man[0].file = "manifest.json";
    R.man[1].file = "k/manifest.json";
    R.man[1].keyed = 1;
    dfd = open(R.dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
#ifndef WE_LOOKUP_TEST_DIR_OPEN_NO_NOTE
        if (look_class(errno) == LOOK_DENIED) {
            note_add(&R.notes, xprintf("the directory %s cannot be opened by this uid (%s): its manifests are not "
                                       "read, and what this run shows of the directory depends on the uid; run it "
                                       "as the user the module loads as", R.dir, strerror(errno)));
        } else if (look_class(errno) == LOOK_BROKEN) {
            note_add(&R.notes, xprintf("the directory %s cannot be opened (%s): its manifests are not read, and "
                                       "every plane in it reads as the module would find it", R.dir, strerror(errno)));
        }
#endif
        return;
    }
    if (fstat(dfd, &dst) != 0) {
        close(dfd);
        return;
    }
    manifest_read_at(&R.man[0], dfd, &dst, R.dir);
#ifdef WE_LOOKUP_TEST_DIR_PATH_OPEN
    {
        char *kp = xprintf("%s/k", R.dir);
        int kd = open(kp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

        free(kp);
        if (kd >= 0 && fstat(kd, &kst) == 0) {
            manifest_read_at(&R.man[1], kd, &kst, R.dir);
        }
        if (kd >= 0) {
            close(kd);
        }
    }
#else
    if (fstatat(dfd, "k", &kst, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISLNK(kst.st_mode)) {
            R.man[1].state = M_REFUSED;
            snprintf(R.man[1].why, sizeof R.man[1].why, "symlink");
        } else if (!S_ISDIR(kst.st_mode)) {
            R.man[1].state = M_REFUSED;
            snprintf(R.man[1].why, sizeof R.man[1].why, "not-directory");
        } else {
            int kfd = openat(dfd, "k", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

            if (kfd < 0) {
                R.man[1].state = errno == ELOOP ? M_REFUSED : M_UNREADABLE;
                snprintf(R.man[1].why, sizeof R.man[1].why, "%s", errno == ELOOP ? "symlink" : "open");
            } else if (fstat(kfd, &kst) != 0 || !S_ISDIR(kst.st_mode)) {
                R.man[1].state = M_REFUSED;
                snprintf(R.man[1].why, sizeof R.man[1].why, "not-directory");
                close(kfd);
            } else if ((kst.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
                R.man[1].state = M_REFUSED;
                snprintf(R.man[1].why, sizeof R.man[1].why, "directory-writable");
                close(kfd);
            } else if (kst.st_uid != dst.st_uid && kst.st_uid != 0) {
                R.man[1].state = M_REFUSED;
                snprintf(R.man[1].why, sizeof R.man[1].why, "foreign-owner");
                close(kfd);
            } else {
                manifest_read_at(&R.man[1], kfd, &kst, R.dir);
                close(kfd);
            }
        }
    }
#endif
    close(dfd);
    R.any_read = R.man[0].state == M_READ || R.man[1].state == M_READ;
}

/* the manifest of this plane's catalogue tier: 0 keyless, 1 keyed */
static int own_tier(int idx)
{
    return strcmp(we_plane_tier[idx].tier, "keyed") == 0;
}

/* first planes[] entry with this name (later duplicates are ignored, as the refresh reads it) */
static const pentry_t *first_entry(const manifest_t *m, const char *name, uint32_t *dups)
{
    const pentry_t *first = NULL;
    uint32_t i;

    *dups = 0;
    for (i = 0; i < m->nplanes; i++) {
        if (m->planes[i].name != NULL && strcmp(m->planes[i].name, name) == 0) {
#ifdef WE_LOOKUP_TEST_LAST_ENTRY_BINDS
            first = &m->planes[i];
            continue;
#endif
            if (first == NULL) {
                first = &m->planes[i];
            } else {
                (*dups)++;
            }
        }
    }
    return first;
}

static const lentry_t *legacy_entry(const manifest_t *m)
{
    uint32_t i;

    for (i = 0; i < m->nlegacy; i++) {
        if (m->legacy[i].name != NULL && strcmp(m->legacy[i].name, "snapshot.bin") == 0) {
            return &m->legacy[i];
        }
    }
    return NULL;
}

static const wentry_t *withheld_entry(const manifest_t *m, const char *name)
{
    uint32_t i;

    for (i = 0; i < m->nwithheld; i++) {
        if (m->withheld[i].name != NULL && strcmp(m->withheld[i].name, name) == 0) {
            return &m->withheld[i];
        }
    }
    return NULL;
}

static int entry_matches(const plane_t *p, int sha_ok, const char *sha, int bytes_ok, uint64_t bytes)
{
#ifdef WE_LOOKUP_TEST_NO_DIGEST_BIND
    (void)p; (void)sha_ok; (void)sha; (void)bytes_ok; (void)bytes;
    return 1;
#else
    return p->hashed && sha_ok && strcmp(sha, p->digest) == 0 && bytes_ok && bytes == p->map.len;
#endif
}

static void bind_plane(plane_t *p)
{
    int order[2], k, any_named = 0;
    int keyedp = own_tier(p->idx);
    const char *pname = p->name;

    order[0] = keyedp;            /* own tier first */
    order[1] = !keyedp;
#ifdef WE_LOOKUP_TEST_LAST_RENAMED_TIER
    order[0] = 1;
    order[1] = 0;
#endif
    if (!p->armed || (p->state != PS_FRESH && p->state != PS_STALE)) {
        return;
    }
    for (k = 0; k < 2; k++) {
        const manifest_t *m = &R.man[order[k]];
        const pentry_t *e;
        uint32_t dups = 0;

        if (m->state != M_READ) {
            continue;
        }
        e = first_entry(m, pname, &dups);
#ifdef WE_LOOKUP_TEST_BIND_BY_DIGEST_ONLY
        {
            uint32_t i;

            for (i = 0; i < m->nplanes; i++) {
                if (entry_matches(p, m->planes[i].sha_ok, m->planes[i].sha, m->planes[i].bytes_ok,
                                  m->planes[i].bytes)) {
                    e = &m->planes[i];
                }
            }
        }
#endif
        if (dups > 0) {
            note_add(&R.notes, xprintf("%s: %s names %s %u more time%s; only its first planes[] entry is read",
                                       pname, m->file, pname, dups, dups == 1 ? "" : "s"));
        }
        if (e != NULL) {
            any_named = 1;
        }
#ifdef WE_LOOKUP_TEST_LEGACY_FIRST
        if (p->idx == 0 && legacy_entry(m) != NULL) {
            const lentry_t *l = legacy_entry(m);

            if (entry_matches(p, l->sha_ok, l->sha, l->bytes_ok, l->bytes)) {
                p->bound = 1;
                p->bound_m = order[k];
                p->bound_legacy = 1;
                p->lentry = l;
                return;
            }
        }
#endif
        if (e != NULL && e->sha_ok && entry_matches(p, e->sha_ok, e->sha, e->bytes_ok, e->bytes)) {
            p->bound = 1;
            p->bound_m = order[k];
            p->entry = e;
            return;
        }
        if (e != NULL && p->entry_generation == NULL && e->sha_ok) {
            p->entry_generation = xstrdup(e->hgen && p->map.format == WE_FORMAT_1 ? e->hgen
                                          : e->generation ? e->generation : "not-stated");
        }
        if (p->idx == 0) {
            const lentry_t *l = legacy_entry(m);

            if (l != NULL) {
                any_named = 1;
                if (entry_matches(p, l->sha_ok, l->sha, l->bytes_ok, l->bytes)) {
                    p->bound = 1;
                    p->bound_m = order[k];
                    p->bound_legacy = 1;
                    p->lentry = l;
                    return;
                }
                if (p->entry_generation == NULL && l->sha_ok) {
                    p->entry_generation = xstrdup(l->hgen ? l->hgen : "not-stated");
                }
            }
        }
    }
    p->named_any = any_named;
#ifdef WE_LOOKUP_TEST_UNBOUND_ONE_REASON
    snprintf(p->why_bind, sizeof p->why_bind, "other-bytes");
    return;
#endif
    /*
     * A manifest that was read and names other bytes for the plane is the most specific cause. Short of
     * that, a refused or unreadable manifest may be the one that would have bound the plane, so the
     * refusal is reported ahead of "not named": the read manifest's silence says nothing about the other.
     */
#ifdef WE_LOOKUP_TEST_REFUSED_AS_NOT_NAMED
    if (p->entry_generation != NULL || (R.any_read && any_named)) {
        snprintf(p->why_bind, sizeof p->why_bind, "other-bytes");
    } else if (R.any_read) {
        snprintf(p->why_bind, sizeof p->why_bind, "not-named");
    } else if (R.man[0].state == M_REFUSED || R.man[1].state == M_REFUSED || R.man[0].state == M_UNREADABLE
               || R.man[1].state == M_UNREADABLE) {
#else
    if (p->entry_generation != NULL) {
        snprintf(p->why_bind, sizeof p->why_bind, "other-bytes");
    } else if (R.man[0].state == M_REFUSED || R.man[1].state == M_REFUSED || R.man[0].state == M_UNREADABLE
               || R.man[1].state == M_UNREADABLE) {
#endif
        snprintf(p->why_bind, sizeof p->why_bind, "refused");
        p->manifest_refused = 1;
    } else if (R.any_read && any_named) {
        snprintf(p->why_bind, sizeof p->why_bind, "other-bytes");
    } else if (R.any_read) {
        snprintf(p->why_bind, sizeof p->why_bind, "not-named");
    } else {
        snprintf(p->why_bind, sizeof p->why_bind, "no-manifest");
    }
}

static const char *bind_note(const char *why)
{
    if (strcmp(why, "no-manifest") == 0) {
        return "no manifest in the directory, so nothing states this plane's provenance";
    }
    if (strcmp(why, "not-named") == 0) {
        return "the manifest in the directory does not list this plane";
    }
    if (strcmp(why, "other-bytes") == 0) {
        return "the manifest names other bytes for this plane: the plane and the manifest came from different "
               "generations or nodes, or one was replaced during this run";
    }
    return "a manifest in the directory was refused, and it may be the one that binds this plane; see its "
           "manifest line";
}

/* ---- the reasons a plane is not known, in a fixed order, as a comma list ---- */

static void add_member(sb_t *w, const char *m)
{
    if (w->n) {
        sb_putc(w, ',');
    }
    sb_puts(w, m);
}

/* withheld:<R> for every reason of every read manifest naming the plane, own tier first */
static int withheld_members(sb_t *w, int idx, int feed)
{
    int k, any = 0, order[2];

    (void)feed;            /* `feed` matters only to the mutants that mishandle the feed key */
    order[0] = own_tier(idx);
    order[1] = !order[0];
    for (k = 0; k < 2; k++) {
        const manifest_t *m = &R.man[order[k]];
        const wentry_t *e;
        int r;

        if (m->state != M_READ || (e = withheld_entry(m, we_plane_tier[idx].name)) == NULL) {
            continue;
        }
        any = 1;
#ifdef WE_LOOKUP_TEST_WITHHOLD_MASKED_BY_TIER
        if (!feed && own_tier(idx) && R.man[1].state != M_READ) {
            continue;
        }
#endif
        for (r = 0; r < e->nreasons; r++) {
            char *mm = xprintf("withheld:%s", e->reasons[r]);

#ifdef WE_LOOKUP_TEST_FEED_ONE_MEMBER
            if (feed && r > 0) {
                sb_putc(w, ',');
                sb_puts(w, e->reasons[r]);
                free(mm);
                continue;
            }
#endif
            add_member(w, mm);
            free(mm);
        }
#ifndef WE_LOOKUP_TEST_WITHHELD_NO_MEMBER
        if (e->nreasons == 0) {
            /* withheld, for reasons the entry does not state readably: still withheld, never silent */
            add_member(w, "withheld:not-stated");
        }
#endif
    }
    return any;
}

static int named_anywhere(const manifest_t *m, int idx)
{
    uint32_t dups;

    if (first_entry(m, we_plane_tier[idx].name, &dups) != NULL || withheld_entry(m, we_plane_tier[idx].name)) {
        return 1;
    }
    return idx == 0 && legacy_entry(m) != NULL;
}

static void absent_why(sb_t *w, int idx)
{
    int own = own_tier(idx);

    add_member(w, "absent");
    if (R.model == MODEL_LEGACY) {
        add_member(w, "legacy-directive");
    }
    withheld_members(w, idx, 0);
    if (own && R.man[1].state != M_READ) {
        add_member(w, "keyed");
    }
    if (R.man[own].state == M_READ && !named_anywhere(&R.man[own], idx)) {
        add_member(w, "not-published");
    }
}

/* the `why` of a plane that is not fresh and bound */
static void plane_why(sb_t *w, const plane_t *p)
{
    switch (p->state) {
    case PS_ABSENT:
        absent_why(w, p->idx);
        return;
    case PS_REFUSED: {
#ifdef WE_LOOKUP_TEST_WHY_FREE_TEXT
        char *m = xprintf("refused:%s", p->refused_detail ? p->refused_detail : p->refused);
#else
        char *m = xprintf("refused:%s", p->refused);
#endif

        add_member(w, m);
        free(m);
        if (p->refused_kind == RF_NOT_PRESENT) {
            add_member(w, "inert-at-config");
        } else if (p->refused_kind == RF_PERMISSION) {
            add_member(w, "uid-dependent");
        }
        return;
    }
    case PS_STALE:
        add_member(w, "stale");
        break;
    default:
        break;
    }
    if (!p->bound && p->why_bind[0]) {
        add_member(w, p->why_bind);
    }
}

/* feed=published or withheld:<R>,... when any manifest names the plane or one of its tier was read */
static int plane_feed(sb_t *w, int idx, const plane_t *p)
{
    int own = own_tier(idx), k;
    int published = 0;

    for (k = 0; k < 2; k++) {
        uint32_t d;

        if (R.man[k].state == M_READ && (first_entry(&R.man[k], we_plane_tier[idx].name, &d) != NULL
                                         || (idx == 0 && legacy_entry(&R.man[k]) != NULL))) {
            published = 1;
        }
    }
    if (published && p != NULL && p->bound) {
        add_member(w, "published");
        return 1;
    }
    if (withheld_members(w, idx, 1)) {
        return 1;
    }
    if (published) {
        add_member(w, "published");
        return 1;
    }
    if (R.man[own].state == M_READ) {
        add_member(w, "not-published");
        return 1;
    }
    return 0;
}

static const wentry_t *withheld_any(int idx, const manifest_t **from)
{
    int k, order[2];

    order[0] = own_tier(idx);
    order[1] = !order[0];
    for (k = 0; k < 2; k++) {
        const wentry_t *e;

        if (R.man[order[k]].state == M_READ && (e = withheld_entry(&R.man[order[k]], we_plane_tier[idx].name))) {
            *from = &R.man[order[k]];
            return e;
        }
    }
    return NULL;
}

/* ======================================================================================================
 * The lines
 * ==================================================================================================== */

static void emit_lookup(line_t *l)
{
    L_init(l, "lookup");
    L_keyn(l, "format", LOOKUP_FORMAT);
    L_keyt_u64(l, "now", (uint64_t)R.now_ms, 0);
    L_key(l, "model", 's', R.model == MODEL_DATA ? "data" : "legacy");
    L_key(l, "model-from", 's', R.model_from);
    L_key(l, "prestage", 's', R.prestage ? "present" : "absent");
    L_key(l, "dir", 's', R.model == MODEL_DATA ? R.dir : NULL);
    L_key(l, "snapshot", 's', R.model == MODEL_LEGACY ? R.snapshot : NULL);
    L_keyb(l, "dir-writable", R.dir_writable);
    L_key(l, "view", 's', "disk");
}

static int64_t age_seconds(int64_t now_ms, int64_t built_ms)
{
    int64_t d = now_ms - built_ms, q;

#ifdef WE_LOOKUP_TEST_AGE_TRUNCATED
    return d / 1000;
#endif
    floor_div(d, 1000, &q);
    return q;
}

static void emit_manifest(line_t *l, const manifest_t *m)
{
    L_init(l, "manifest");
    L_key(l, "state", 's', m->state == M_READ ? "read" : m->state == M_UNREADABLE ? "unreadable" : "refused");
    L_key(l, "why", 's', m->state == M_READ ? NULL : m->why);
    L_key(l, "file", 's', m->file);
    if (m->state == M_READ) {
        L_key(l, "generation", 'd', m->generation ? m->generation : "not-stated");
        L_key(l, "builder", 's', m->builder ? m->builder : "not-stated");
        L_key(l, "tier", 's', m->tier ? m->tier : "not-stated");
        L_keyt(l, "built", m->built);
        if (m->built.st == T_OK || m->built.st == T_MS) {
            L_add(l, "age", 'd', xprintf("%" PRId64, age_seconds(R.now_ms, m->built.ms)), 0);
        } else {
            L_key(l, "age", 'd', "not-stated");
        }
        L_key(l, "verified", 's', "not-by-this-tool");
    } else {
        L_null(l, "generation", 'd');
        L_null(l, "builder", 's');
        L_null(l, "tier", 's');
        L_null(l, "built", 't');
        L_null(l, "age", 'd');
        L_null(l, "verified", 's');
    }
}

static void tval_cmp(sb_t *dis, const char *name, tval_t t, uint64_t header_ms, int zero_none)
{
    int differ;

    if (t.st != T_OK && t.st != T_MS) {
        return;
    }
    if (zero_none && header_ms == 0) {
        differ = 1;
    } else {
        differ = t.ms < 0 || (uint64_t)t.ms != header_ms;
    }
    if (differ) {
        add_member(dis, name);
    }
}

static void emit_plane(line_t *l, plane_t *p)
{
    sb_t w = {0}, feed = {0}, dis = {0};
    int armed = p->armed && (p->state == PS_FRESH || p->state == PS_STALE);
    int has_feed;
    const manifest_t *bm = p->bound ? &R.man[p->bound_m] : NULL;

    L_init(l, "plane");
    L_pos(l, "name", 's', p->name);
    L_keyn(l, "id", (uint64_t)p->idx + 1);
    L_key(l, "state", 's', p->state == PS_FRESH ? "fresh" : p->state == PS_STALE ? "stale"
                          : p->state == PS_REFUSED ? "refused" : "absent");
    L_key(l, "file", 's', p->state == PS_ABSENT ? NULL : p->file);
    if (armed) {
        const we_map_t *m = &p->map;

        L_keyn(l, "format", m->format);
        L_keyd(l, "generation", m->generation);
#ifdef WE_LOOKUP_TEST_GEN_UNIT
        L_key(l, "unit", 's', "epoch-seconds");
#else
        L_key(l, "unit", 's', m->format == WE_FORMAT_1 ? "slot-index" : "epoch-seconds");
#endif
        L_keyt_u64(l, "built", m->h->built_at_ms, 0);
        L_keyt_u64(l, "valid-until", m->valid_until_ms, 1);
        if (m->format == WE_FORMAT_1) {
            L_keyn(l, "admission-tier", m->h->tier);
        } else {
            L_null(l, "admission-tier", 'n');
        }
        L_keyn(l, "ranges-v4", m->v4_count);
        L_keyn(l, "ranges-v6", m->v6_count);
        if (m->f6w.n > 0u || (m->h->flags & WE_H_SCHEMA && m->h->schema.v6_key_bits == 64)) {
            L_keyn(l, "key-bits-v6", 64);
        } else {
            L_null(l, "key-bits-v6", 'n');
        }
    } else {
        L_null(l, "format", 'n');
        L_null(l, "generation", 'd');
        L_null(l, "unit", 's');
        L_null(l, "built", 't');
        L_null(l, "valid-until", 't');
        L_null(l, "admission-tier", 'n');
        L_null(l, "ranges-v4", 'n');
        L_null(l, "ranges-v6", 'n');
        L_null(l, "key-bits-v6", 'n');
    }
#ifdef WE_LOOKUP_TEST_WITHHELD_VALUE
    if (p->state == PS_ABSENT && R.any_read) {
        uint32_t d;
        int k;

        for (k = 0; k < 2; k++) {
            if (R.man[k].state == M_READ && first_entry(&R.man[k], p->name, &d) != NULL) {
                p->bound = 1;
                p->bound_m = k;
                p->entry = first_entry(&R.man[k], p->name, &d);
                bm = &R.man[k];
            }
        }
    }
#endif
    L_key(l, "manifest", 's', p->bound ? "bound" : p->manifest_refused ? "refused" : "unbound");
    if (!(p->state == PS_FRESH && p->bound)) {
        plane_why(&w, p);
    }
    L_key(l, "why", 'l', w.n ? w.p : NULL);
    L_key(l, "entry-generation", 'd', strcmp(p->why_bind, "other-bytes") == 0 && !p->bound
                                      ? (p->entry_generation ? p->entry_generation : "not-stated") : NULL);
#ifdef WE_LOOKUP_TEST_NO_BOUND_TO
    L_null(l, "bound-to", 's');
#else
    L_key(l, "bound-to", 's', bm ? bm->file : NULL);
#endif
    if (bm != NULL) {
        const pentry_t *e = p->entry;

#ifdef WE_LOOKUP_TEST_TIER_BY_KEY_PRESENCE
        L_key(l, "tier", 's', R.man[1].state == M_READ ? "keyed" : "keyless");
#else
        L_key(l, "tier", 's', p->bound_legacy || bm->tier == NULL ? "not-stated" : bm->tier);
#endif
        if (e != NULL) {
            L_add(l, "sources", 'd', xprintf("%u", e->nsrc), 0);
            L_key(l, "coverage-v4", 'd', e->cov_v4 ? e->cov_v4 : "not-stated");
            L_key(l, "coverage-v6", 'd', e->cov_v6 ? e->cov_v6 : "not-stated");
            L_key(l, "coverage-v6-slash32s", 'd', e->cov_s32 ? e->cov_s32 : "not-stated");
        } else {
            L_key(l, "sources", 'd', "not-stated");
            L_key(l, "coverage-v4", 'd', "not-stated");
            L_key(l, "coverage-v6", 'd', "not-stated");
            L_key(l, "coverage-v6-slash32s", 'd', "not-stated");
        }
    } else {
        L_null(l, "tier", 's');
        L_null(l, "sources", 'd');
        L_null(l, "coverage-v4", 'd');
        L_null(l, "coverage-v6", 'd');
        L_null(l, "coverage-v6-slash32s", 'd');
    }
    has_feed = plane_feed(&feed, p->idx, p);
    L_key(l, "feed", 's', has_feed ? feed.p : NULL);
    {
        const manifest_t *from = NULL;
        const wentry_t *we = withheld_any(p->idx, &from);

        /* until: a fresh plane the feed withholds (not one it also publishes, which binds as published) */
        if (p->state == PS_FRESH && we != NULL && has_feed && strncmp(feed.p, "withheld:", 9) == 0) {
            L_keyt(l, "until", we->lpvu);
        } else {
            L_null(l, "until", 't');
        }
    }
    L_key(l, "refused", 's', p->state == PS_REFUSED ? p->refused : NULL);
    L_key(l, "refused-detail", 's', p->state == PS_REFUSED ? p->refused_detail : NULL);
    if (armed && p->bound) {
        if (p->entry != NULL) {
            const char *eg = p->map.format == WE_FORMAT_1 ? p->entry->hgen : p->entry->generation;
            char hg[24];

            snprintf(hg, sizeof hg, "%" PRIu64, p->map.generation);
            if (eg != NULL && strcmp(eg, hg) != 0) {
                add_member(&dis, "generation");
            }
            tval_cmp(&dis, "built", p->entry->built, p->map.h->built_at_ms, 0);
            tval_cmp(&dis, "valid-until", p->entry->valid, p->map.valid_until_ms, 1);
        } else if (p->lentry != NULL && p->lentry->hgen != NULL) {
            char hg[24];

            snprintf(hg, sizeof hg, "%" PRIu64, p->map.generation);
            if (strcmp(p->lentry->hgen, hg) != 0) {
                add_member(&dis, "generation");
            }
        }
    }
    L_key(l, "disagree", 'l', dis.n ? dis.p : NULL);
    free(w.p);
    free(feed.p);
    free(dis.p);
}

static void emit_source(line_t *l, const char *plane, uint32_t idx, const src_t *s)
{
    L_init(l, "source");
    L_pos(l, "plane", 's', plane);
    L_add(l, "index", 'n', xprintf("%u", idx), 1);
    L_key(l, "name", 's', s->name ? s->name : "not-stated");
    L_key(l, "kind", 's', s->kind ? s->kind : "not-stated");
    L_key(l, "count", 'd', s->count ? s->count : "not-stated");
    L_keyt(l, "observed-at", s->observed);
    L_key(l, "recall", 's', s->recall ? s->recall : "not-stated");
    L_key(l, "precision", 's', s->precision ? s->precision : "not-stated");
}

static void emit_withheld(line_t *l, const char *plane, const wentry_t *w, int keyed)
{
    sb_t rs = {0};
    int k;

    for (k = 0; k < w->nreasons; k++) {
        add_member(&rs, w->reasons[k]);
    }
    L_init(l, "withheld");
    L_pos(l, "plane", 's', plane);
    L_key(l, "reasons", 'l', rs.n ? rs.p : "not-stated");
    L_key(l, "reason", 's', w->reason ? w->reason : "not-stated");
    L_key(l, "detail", 's', w->detail ? w->detail : "not-stated");
    L_keyt(l, "since", w->since);
    L_key(l, "built-generation", 'd', w->built_gen ? w->built_gen : "not-stated");
    L_key(l, "built-generation-unit", 's', "epoch-seconds");
    L_keyt(l, "last-published-valid-until", w->lpvu);
    L_key(l, "from", 's', keyed ? "keyed" : "keyless");
    free(rs.p);
}

/* ---- the hold-harmless set ---- */

static int in_range(int family, const uint8_t *a, const uint8_t *s, const uint8_t *e)
{
    size_t n = family == 4 ? 4u : 16u;

    return memcmp(a, s, n) >= 0 && memcmp(a, e, n) <= 0;
}

static const we_hh_range_t *hh_member(const addr_t *a)
{
    uint32_t i;

    for (i = 0; i < WE_HH_RANGE_COUNT; i++) {
        if (we_hh_ranges[i].family == a->family && in_range(a->family, a->b, we_hh_ranges[i].start,
                                                              we_hh_ranges[i].end)) {
            return &we_hh_ranges[i];
        }
    }
    return NULL;
}

/* ---- per-address output ---- */

/*
 * The 25 attributes, in the vocabulary's order. Only the order is this file's: each attribute's plane,
 * class and block offset come from the evaluator's own table (we_attr_info), and every value from its
 * renderer (we_attr_render), so the tool prints what a rule reads and never restates the table.
 */
static const char *const ATTR_ORDER[25] = {
    "listed", "inferred", "tor_exit", "rpki_unreachable", "rpki_reason", "rpki", "asn", "asn_rep", "country",
    "registry_country", "rir", "registry_rir", "proxy", "vpn", "c2", "bruteforce", "spam", "phishing",
    "scanner", "state_actor", "anycast", "moas", "narrowed", "tenant_allow", "tenant_deny"
};
static uint32_t g_attr_ix[25];
static we_attr_info_t g_attr[25];

/* Bind the order to the evaluator's table; -1 names the attribute it does not hold. */
static int attrs_bind(const char **missing)
{
    uint32_t k, j, n = we_attr_count();

    if (n != 25u) {
        *missing = "the attribute count";
        return -1;
    }
    for (k = 0; k < 25u; k++) {
        int found = 0;

        for (j = 0; j < n && !found; j++) {
            we_attr_info_t ai;

            if (we_attr_info(j, &ai) == 0 && strcmp(ai.name, ATTR_ORDER[k]) == 0) {
                g_attr_ix[k] = j;
                g_attr[k] = ai;
                found = 1;
            }
        }
        if (!found || g_attr[k].plane_id < 1u || g_attr[k].plane_id > 8u) {
            *missing = ATTR_ORDER[k];
            return -1;
        }
    }
    return 0;
}

#if defined(WE_LOOKUP_TEST_NO_UNCHECKED_QUALIFIER)
#define TENANT_IDENTITY "revocation-not-checked"
#elif defined(WE_LOOKUP_TEST_REVOCATION_QUALIFIER_DROPPED)
#define TENANT_IDENTITY "unchecked"
#else
#define TENANT_IDENTITY "unchecked,revocation-not-checked"
#endif

/* the tenant plane is present: armed, or refused with something at its path the probe found */
static int tenant_identity_applies(void)
{
    const plane_t *t = &R.planes[7];

    return t->state != PS_ABSENT && !(t->state == PS_REFUSED && t->refused_kind != RF_PRESENT);
}

/* a key, big-endian, from a u32, u64 or u128 read in host order */
static void key_bytes_be(const uint8_t *src, unsigned kb, uint8_t out[16])
{
    unsigned i;

    memset(out, 0, 16);
    if (kb == 4) {
        uint32_t v;

        memcpy(&v, src, 4);
        for (i = 0; i < 4; i++) {
            out[i] = (uint8_t)(v >> (24 - 8 * i));
        }
    } else if (kb == 8) {
        uint64_t v;

        memcpy(&v, src, 8);
        for (i = 0; i < 8; i++) {
            out[i] = (uint8_t)(v >> (56 - 8 * i));
        }
    } else {
        __uint128_t v;

        memcpy(&v, src, 16);
        for (i = 0; i < 16; i++) {
            out[i] = (uint8_t)(v >> (120 - 8 * i));
        }
    }
}

/* Range i of a family as `start-end`, RFC 5952; a 64-bit-keyed IPv6 family's end widened by 64 one bits. */
static char *range_text(const we_map_t *m, int family, uint32_t i, int *key_bits)
{
    const we_fam_t *f = family == 4 ? &m->f4 : we_family6(m);
    unsigned kb = family == 4 ? 4u : f->key_bits / 8u;
    uint8_t s[16], e[16];
    char st[64], en[64];

    key_bytes_be(f->start + (size_t)i * kb, kb, s);
    key_bytes_be(f->end + (size_t)i * f->stride, kb, e);
    *key_bits = 0;
    if (family == 6 && kb == 8) {
        memset(e + 8, 0xff, 8);
        *key_bits = 64;
    }
    fmt_addr(family, s, st, sizeof st);
    fmt_addr(family, e, en, sizeof en);
    return xprintf("%s-%s", st, en);
}

/* the clock the evaluator is given: the run's single sample */
static uint64_t judge_now(void)
{
#ifdef WE_LOOKUP_TEST_NOW_CLOCK
    return (uint64_t)clock_now_ms();
#else
    return (uint64_t)R.now_ms;
#endif
}

/* the context, the request and the hold-harmless view the evaluator reads; one request at a time */
static we_eval_ctx_t g_ectx __attribute__((aligned(64)));
static we_hh_view_t g_hh;
static int g_internal;          /* an internal error: finish the address, close the document, exit 2 */

/*
 * In this order: build the request, fill the views, decide, format the verdict, then the display fills
 * for every plane the decision did not read, into a scratch verdict whose counters are never printed.
 */
static void judge(const addr_t *a, we_verdict_t *v, char *vl, char *cl)
{
    we_request_t req;
    we_verdict_t scratch;
    uint64_t now = judge_now();
    uint32_t i;

    memset(&req, 0, sizeof req);
    we_addr_canon(a->b, a->family, &req.floor);
    req.server = req.floor;
#ifndef WE_LOOKUP_TEST_NO_PRESTAGE_ELIGIBLE
    req.hold_harmless_eligible = (uint8_t)(R.prestage && !R.skipped_hop);
#endif
#ifndef WE_LOOKUP_TEST_FLAG_DROP
    req.acme_exempt = (uint8_t)(R.prestage && R.acme);
#endif
    req.walk = WE_WALK_OK;
    memset(&g_ectx, 0, sizeof g_ectx);
    for (i = 0; i < 8; i++) {
        g_ectx.view[i].m = R.planes[i].armed ? R.planes[i].view : NULL;
    }
    we_decide(R.floor, &R.floor_conf, R.ctx, &R.ctx_conf, &g_hh, &req, &g_ectx, now, v);
#ifdef WE_LOOKUP_TEST_K3_PLANT
    we_trace_k3(1u, 1u);        /* the planted unreachable state the gate holds the K3 report to */
#endif
#ifdef WE_LOOKUP_TEST_DISPLAY_FILL_COUNTED
    for (i = 1; i <= 8; i++) {
        we_eval_lazy_fill(&g_ectx, &g_hh, 0, i, now, v);
    }
#endif
    if (we_verdict_format(v, vl, cl, WE_VERDICT_LINE_MAX) != 0) {
        g_internal = 1;
    }
    memset(&scratch, 0, sizeof scratch);
    for (i = 1; i <= 8; i++) {
        we_eval_lazy_fill(&g_ectx, &g_hh, 0, i, now, &scratch);
    }
    for (i = 0; i < 8; i++) {
        g_ectx.view[i].m = NULL;
    }
}

/* the hours of GRACE a stale tenant plane has left, floored, 0 at its last millisecond */
static int64_t grace_hours_left(const plane_t *p)
{
    int64_t left = (int64_t)p->map.valid_until_ms + TENANT_GRACE_MS - R.now_ms, h;

#ifdef WE_LOOKUP_TEST_GRACE_ROUNDED_UP
    h = (left + 3599999) / 3600000;
#else
    floor_div(left, 3600000, &h);
#endif
    return h;
}

/* the 25 attribute lines, from the memo the evaluator filled */
static void emit_attrs(sb_t *o, const addr_t *a)
{
    const we_memo_slot_t *s = &g_ectx.slot[0];
    int k, first = 1;

    for (k = 0; k < 25; k++) {
        const we_attr_info_t *ai = &g_attr[k];
        int pi = ai->plane_id - 1;
        const plane_t *p = &R.planes[pi];
        const we_memo_entry_t *e = &s->e[pi];
        uint32_t st = s->state[pi];
        uint8_t blk[16];
        char val[64];
        line_t l;
        sb_t w = {0}, feed = {0};
        const char *bounded = NULL;
        int known = 0;

        memcpy(blk, e, sizeof blk);           /* the block, then `lapsed` and the pad: the 16 bytes rendered */
        if (we_attr_render(g_attr_ix[k], blk, st, val, sizeof val) < 0) {
            snprintf(val, sizeof val, "unread");
        }
#ifdef WE_LOOKUP_TEST_STALE_AS_VALUE
        if (p->state == PS_STALE && pi != 7) {
            static we_memo_slot_t ms __attribute__((aligned(64)));
            we_verdict_t sv;

            memset(&ms, 0, sizeof ms);
            memset(&sv, 0, sizeof sv);
            memcpy(ms.addr, s->addr, 16);
            ms.family = s->family;
            ms.key_valid = 1;
            we_eval_fill(p->view, &ms, (uint32_t)pi, g_hh.bindings + pi, p->map.valid_until_ms, &sv, 0);
            memcpy(blk, &ms.e[pi], sizeof blk);
            we_attr_render(g_attr_ix[k], blk, ms.state[pi], val, sizeof val);
        }
#endif
        L_init(&l, "attr");
        L_pos(&l, "name", 's', ai->name);
        if (strcmp(val, "unread") == 0) {
            add_member(&w, "internal:not-filled");
            g_internal = 1;
        } else if (strcmp(val, "unknown") == 0 || strcmp(val, "revoked") == 0) {
            if (strcmp(val, "revoked") == 0) {
                add_member(&w, "revoked");
            } else if (p->state == PS_STALE) {
                add_member(&w, "stale");
            } else {
                plane_why(&w, p);
            }
            if (pi == 7 && p->state == PS_REFUSED && p->refused_kind == RF_PRESENT
                && strcmp(ai->name, "tenant_allow") == 0) {
                bounded = "unknown";
            }
        } else if (strncmp(val, "stale:", 6) == 0 || strncmp(val, "lapsed:", 7) == 0) {
            /* a stale tenant plane: a positive tenant_allow inside an allow reads the bounded value. The
             * renderer writes `stale:<b>` within the grace and `lapsed:<b>` past it (POLICY.md section
             * 3.9); either way this tool's line is the plane's state and the bounded value it reads */
            int lapsed = e->lapsed || strncmp(val, "lapsed:", 7) == 0;

            if (lapsed) {
                add_member(&w, "lapsed");
            } else {
                char *m;

#ifdef WE_LOOKUP_TEST_GRACE_AS_MEMBER
                m = xprintf("grace,%" PRId64, grace_hours_left(p));
#else
                m = xprintf("grace:%" PRId64, grace_hours_left(p));
#endif
                add_member(&w, m);
                free(m);
            }
            if (strcmp(ai->name, "tenant_allow") == 0) {
                bounded = lapsed ? "false" : val + 6;
            }
#ifdef WE_LOOKUP_TEST_BOUNDED_AS_UNIFORM
            snprintf(val, sizeof val, "%s", lapsed ? "false" : val + 6);
            known = 1;
            free(w.p);
            w.p = NULL;
            w.n = 0;
            bounded = NULL;
#endif
        } else {
            known = 1;
        }
        if (known) {
#ifdef WE_LOOKUP_TEST_VALUE_TYPE_BY_STATE
            L_add(&l, "value", ai->cls == WE_ATTR_ASN && strcmp(val, "undetermined") != 0 ? 'n' : 'u',
                  xstrdup(val), 1);
#else
            L_add(&l, "value", 'u', xstrdup(val), 1);
#endif
        } else {
            L_add(&l, "value", 'u', NULL, 1);
        }
        L_key(&l, "plane", 's', ai->plane);
        if (known && (st == WE_ST_FRESH_HIT || st == WE_ST_STALE_HIT) && e->range != WE_NO_RANGE && p->armed) {
            const we_map_t *m = &p->map;
            int kbits;
            char rec[256];

            L_add(&l, "range", 's', range_text(m, a->family, e->range, &kbits), 0);
            if (kbits) {
                L_keyn(&l, "key-bits", (uint64_t)kbits);
            } else {
                L_null(&l, "key-bits", 'n');
            }
            we_record_render(m, a->family, e->range, rec, sizeof rec);
            L_key(&l, "record", 's', rec);
            if (strcmp(ai->name, "listed") == 0 && m->format == WE_FORMAT_1) {
                uint8_t raw = (a->family == 4 ? m->f4.sev : m->f6.sev)[e->range];
                const char *ev;

#ifdef WE_LOOKUP_TEST_DROP_FROM_BLOCK
                raw = e->block[0];
#endif
                L_keyb(&l, "drop", (raw & 0x40u) != 0u);
#ifdef WE_LOOKUP_TEST_NO_EVIDENCE_CALL
                ev = NULL;
#else
                ev = a->family == 4 ? we_evidence4(m, ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16)
                                                      | ((uint32_t)a->b[2] << 8) | a->b[3])
                                    : we_evidence6(m, a->b);
#endif
                L_key(&l, "evidence", 's', ev != NULL ? ev : "");
            } else {
                L_null(&l, "drop", 'b');
                L_null(&l, "evidence", 's');
            }
        } else {
            L_null(&l, "range", 's');
            L_null(&l, "key-bits", 'n');
            L_null(&l, "record", 's');
            L_null(&l, "drop", 'b');
            L_null(&l, "evidence", 's');
        }
        L_key(&l, "why", 'l', known ? NULL : w.p);
        if (known && p->state == PS_FRESH && plane_feed(&feed, pi, p) && strncmp(feed.p, "withheld:", 9) == 0) {
            L_key(&l, "feed", 'l', feed.p);
        } else {
            L_null(&l, "feed", 'l');
        }
        L_key(&l, "bounded", 's', bounded);
        L_key(&l, "identity", 'l', pi == 7 && tenant_identity_applies() ? TENANT_IDENTITY : NULL);
        if (g_json) {
            if (!first) {
                sb_putc(o, ',');
            }
            print_obj(o, &l);
        } else {
            print_line(o, &l);
        }
        first = 0;
        L_free(&l);
        free(w.p);
        free(feed.p);
    }
}

/* The legacy request path every module built before the evaluator runs: no map or a refused map allows,
 * a stale map allows, then the threshold and the mode decide. */
typedef struct {
    const char *action;
    int         enforce, would_deny, rule;
    const char *reason;
    int         sev;
} sugar_t;

static sugar_t sugar_decide(const addr_t *a)
{
    sugar_t s = { "allow", 0, 0, 0, NULL, -1 };
    const plane_t *p = &R.planes[0];
    const we_map_t *m;
    uint8_t v;

    if (!p->armed) {
        s.reason = "no-map";
        return s;
    }
    m = &p->map;
#ifndef WE_LOOKUP_TEST_LEGACY_STALE_ENFORCED
    if (plane_stale(m)) {
        s.reason = "stale";
        return s;
    }
#endif
    v = a->family == 4 ? we_lookup4(m, ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16)
                                         | ((uint32_t)a->b[2] << 8) | a->b[3])
                       : we_lookup6(m, a->b);
    s.sev = v;
    if (R.threshold != 0 && we_should_deny(v, (uint8_t)R.threshold, R.allow_inferred)) {
        s.rule = 1;
        if (R.mode_deny) {
            s.action = "deny";
            s.enforce = 1;
        } else {
            s.action = "log";
            s.would_deny = 1;
        }
    }
    return s;
}

/* ---- --fields: the plane_check --fields line and the --expect line, per armed plane ---- */

static void emit_fields(sb_t *o, const addr_t *a)
{
    int i;

    for (i = 0; i < 8; i++) {
        const plane_t *p = &R.planes[i];
        const we_map_t *m = &p->map;
        uint32_t got;
        const char *names[WE_RECORD_MAX_FIELDS];
        unsigned long vals[WE_RECORD_MAX_FIELDS];
        char rec[256];
        int nf, k;

        if (!p->armed || p->state == PS_ABSENT || p->state == PS_REFUSED) {
            continue;
        }
        if (a->family == 4) {
            got = we_find4(m, ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16) | ((uint32_t)a->b[2] << 8)
                               | a->b[3]);
        } else {
            got = m->f6w.n > 0u ? we_find6_64(m, a->b) : we_find6(m, a->b);
        }
        sb_printf(o, "fields %s %d %s %d", p->name, a->family, a->canon, got != WE_NO_RANGE);
        if (got != WE_NO_RANGE) {
            nf = we_record_values(m, a->family, got, names, vals);
            for (k = 0; k < nf; k++) {
                sb_printf(o, " %lu", vals[k]);
            }
        }
        sb_putc(o, '\n');
        sb_printf(o, "expect %s %d %s ", p->name, a->family, a->canon);
        if (got == WE_NO_RANGE) {
            sb_puts(o, "-\n");
            continue;
        }
        we_record_render(m, a->family, got, rec, sizeof rec);
        if (m->format == WE_FORMAT_1) {
            sb_printf(o, "%u sev=%u fields=%s\n", got, (a->family == 4 ? m->f4.sev : m->f6.sev)[got], rec);
        } else {
            const we_fam_t *f = a->family == 4 ? &m->f4 : we_family6(m);
            const uint8_t *r = we_record_of(f, got);
            uint32_t b;

            sb_printf(o, "%u rec=", got);
            for (b = 0; r != NULL && b < f->stride; b++) {
                sb_printf(o, "%02x", r[b]);
            }
            sb_printf(o, " fields=%s\n", rec);
        }
    }
}

/* ---- the case block: the request as the reference interpreter (policy_ref.py --cases) reads it ---- */

/* the tenant as a case states it, and as the evaluator's outage classification names it */
static const char *tenant_word(we_tenant_state_t *ts)
{
    const plane_t *t = &R.planes[7];

    if (t->armed && t->state == PS_FRESH) {
        *ts = WE_TENANT_FRESH;
        return "fresh";
    }
    if (t->armed && t->state == PS_STALE) {
        *ts = (uint64_t)R.now_ms - t->map.valid_until_ms <= (uint64_t)TENANT_GRACE_MS ? WE_TENANT_GRACE
                                                                                      : WE_TENANT_LAPSED;
        return "stale";
    }
    *ts = WE_TENANT_NULL;
    return "null";
}

/* the planes the configuration has: the first probe's (data model), reputation alone (legacy) */
static int plane_configured(int i)
{
    return R.model == MODEL_DATA ? (int)((R.env.present >> i) & 1u) : i == 0;
}

static void case_escape(sb_t *o, const uint8_t *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (b[i] >= 0x20 && b[i] <= 0x7e && b[i] != '\\') {
            sb_putc(o, (char)b[i]);
        } else {
            sb_printf(o, "\\x%02X", b[i]);
        }
    }
}

static void emit_case_program(sb_t *o)
{
    size_t i;
    int k, any = 0;

    sb_puts(o, "program lookup cases\n");
    for (i = 0; i < R.ndirs; i++) {
        sb_printf(o, "dir %s %s ", we_policy_kind_name(R.dirs[i].kind), R.dirs[i].context);
        case_escape(o, R.dirs[i].arg, R.dirs[i].len);
        sb_putc(o, '\n');
    }
    sb_printf(o, "run %s\n", R.context);
    for (k = 0; k < 8; k++) {
        if (!plane_configured(k)) {
            sb_puts(o, any ? " " : "absent ");
            sb_puts(o, we_plane_tier[k].name);
            any = 1;
        }
    }
    if (any) {
        sb_putc(o, '\n');
    }
    if (R.model == MODEL_LEGACY) {
        sb_puts(o, "legacy\n");
    }
}

static void emit_case(sb_t *o, const addr_t *a, int index)
{
    we_tenant_state_t ts;
    const char *tw = tenant_word(&ts);
    const plane_t *t = &R.planes[7];
    int k;

    sb_printf(o, "case %d\n", index);
    sb_printf(o, "conf floor %u %u\n", R.floor_conf.mode, R.floor_conf.allow_inferred);
    sb_printf(o, "conf ctx %u %u\n", R.ctx_conf.mode, R.ctx_conf.allow_inferred);
    for (k = 0; k < 7; k++) {
        const plane_t *p = &R.planes[k];

        if (!plane_configured(k)) {
            continue;
        }
        sb_printf(o, "plane %s %s\n", p->name, p->armed && p->state == PS_FRESH ? "fresh" : "stale");
    }
    sb_printf(o, "tenant %s %" PRId64 " %" PRIu64 "\n", tw, R.now_ms, t->armed ? t->map.valid_until_ms : 0u);
    sb_printf(o, "addr floor %s\n", a->canon);
    sb_printf(o, "flags %d %d\n", R.prestage && !R.skipped_hop, R.prestage && R.acme);
    for (k = 0; k < 8; k++) {
        const plane_t *p = &R.planes[k];
        uint32_t got = WE_NO_RANGE;

        if (!plane_configured(k)) {
            continue;
        }
        if (p->armed) {
            const we_map_t *m = &p->map;

            got = a->family == 4 ? we_find4(m, ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16)
                                                | ((uint32_t)a->b[2] << 8) | a->b[3])
                                 : (m->f6w.n > 0u ? we_find6_64(m, a->b) : we_find6(m, a->b));
        }
        sb_printf(o, "rec floor %s", p->name);
        if (got == WE_NO_RANGE) {
            sb_puts(o, " none\n");
        } else {
            const char *names[WE_RECORD_MAX_FIELDS];
            unsigned long vals[WE_RECORD_MAX_FIELDS];
            int nf = we_record_values(&p->map, a->family, got, names, vals), f;

            for (f = 0; f < nf; f++) {
                sb_printf(o, " %s=%lu", names[f], vals[f]);
            }
            sb_putc(o, '\n');
        }
    }
    sb_puts(o, "end\n");
}

/* ---- the decision ---- */

/* the rule's canonical text, line `rule` of a program's printed text */
static char *rule_text(const char *text, unsigned rule)
{
    const char *p = text;
    unsigned r;

    for (r = 1; p != NULL && *p != '\0'; r++) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);

        if (r == rule) {
            char *s = (char *)malloc(n + 1);

            if (s == NULL) {
                die_oom();
            }
            memcpy(s, p, n);
            s[n] = '\0';
            return s;
        }
        p = nl ? nl + 1 : NULL;
    }
    return xstrdup("");
}

static int rule_is_deny(const we_program_t *p, unsigned r)
{
    const we_rule_t *rules;

    if (p == NULL || r == 0 || r > p->rule_count) {
        return 0;
    }
    rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    return rules[r - 1].action == WE_ACT_DENY;
}

/* the decision's step, a function of the verdict's (step, program, reason) */
static const char *step_word(const we_verdict_t *v)
{
#ifdef WE_LOOKUP_TEST_STEP_NUMERIC
    if (v->step == WE_STEP_STALE_TENANT) {
        return "3.5";
    }
#endif
    switch (v->step) {
    case WE_STEP_EXEMPT:
#ifdef WE_LOOKUP_TEST_ACME_AS_HOLD_HARMLESS
        return "hold-harmless";
#else
        return v->reason == WE_WHY_HOLD_HARMLESS ? "hold-harmless" : v->reason == WE_WHY_ACME ? "acme" : NULL;
#endif
    case WE_STEP_TENANT:
        return "tenant";
    case WE_STEP_FLOOR:
#ifdef WE_LOOKUP_TEST_FLOOR_AS_ACME
        return "acme";
#else
        return v->program == WE_VPROG_FLOOR ? "floor" : NULL;
#endif
    case WE_STEP_STALE_TENANT:
        return "tenant-grace";
    case WE_STEP_CONTEXT:
        return v->program == WE_VPROG_CONTEXT ? "context" : v->program == WE_VPROG_NONE ? "default" : NULL;
    default:
        return NULL;
    }
}

/* the decision line from the evaluator's verdict; returns the address's exit status */
/*
 * The decision line, one format in both models. `step` names what decided the request, and `rule` and
 * `text` are always the deciding rule (rule 0 and no text when the default decided). `log` lists every
 * rule that recorded, log rules and denies that mode log downgraded alike, as `<floor|ctx>:<rule>`. A
 * `log` decision names the first downgraded deny, floor before context, in its own keys, qualified the
 * way `log` qualifies its members: `would-deny-rule=<floor|ctx>:<rule>` and `would-deny-text`.
 */
static int g_enforced;          /* the address's decision was an enforced deny */

static int decision_from_verdict(line_t *l, const we_verdict_t *v)
{
    const char *step = step_word(v);
    int would_deny = 0, prog, rc = 0, wd_prog = 0;
    unsigned r, wd_rule = 0;
    sb_t log = {0};
    const char *action;

    for (prog = 0; prog < 2; prog++) {
        const we_program_t *p = prog == 0 ? R.floor : R.ctx;

        for (r = 1; r <= 256; r++) {
            if ((v->log_fired[prog][(r - 1) >> 3] >> ((r - 1) & 7u)) & 1u) {
                char *m = xprintf("%s:%u", prog == 0 ? "floor" : "ctx", r);

                add_member(&log, m);
                free(m);
                if (rule_is_deny(p, r) && !would_deny) {
                    would_deny = 1;
                    wd_prog = prog;
                    wd_rule = r;
                }
            }
        }
    }
    action = v->action == WE_ACT_DENY && v->enforce ? "deny" : would_deny ? "log" : "allow";
    g_enforced = strcmp(action, "deny") == 0;
    L_init(l, "decision");
    L_pos(l, "action", 's', action);
    if (strcmp(action, "deny") == 0) {
        L_keyb(l, "enforce", 1);
        rc = 1;
    } else {
        L_null(l, "enforce", 'b');
    }
    if (strcmp(action, "log") == 0) {
        L_keyb(l, "would-deny", 1);
    } else {
        L_null(l, "would-deny", 'b');
    }
    if (step == NULL) {
        step = "internal:step-unmapped";
        g_internal = 1;
    }
    L_key(l, "step", 's', step);
#ifdef WE_LOOKUP_TEST_WOULD_DENY_UNQUALIFIED
    /* the earlier form: the downgraded deny's bare number and text in `rule` and `text` */
    if (would_deny && strcmp(action, "log") == 0) {
        L_keyn(l, "rule", wd_rule);
        L_add(l, "text", 's', rule_text(wd_prog == 0 ? R.floor_text : R.ctx_text, wd_rule), 0);
        would_deny = 0;
    } else
#endif
    {
        L_keyn(l, "rule", v->rule);
        if (v->rule != 0) {
            L_add(l, "text", 's', rule_text(v->program == WE_VPROG_FLOOR ? R.floor_text : R.ctx_text, v->rule), 0);
        } else {
            L_null(l, "text", 's');
        }
    }
    if (v->reason == WE_WHY_ALLOW_BY_UNKNOWN) {
        L_add(l, "reason", 's', xprintf("allow-by-unknown:%s", v->unknown_plane >= 1 && v->unknown_plane <= 8
                                                                ? we_plane_tier[v->unknown_plane - 1].name : "-"), 0);
    } else {
        L_null(l, "reason", 's');
    }
    L_key(l, "log", 's', log.n ? log.p : NULL);
#ifdef WE_LOOKUP_TEST_IDENTITY_TENANT_STEP_ONLY
    L_key(l, "identity", 'l', v->step == WE_STEP_TENANT && tenant_identity_applies() ? TENANT_IDENTITY : NULL);
#else
    L_key(l, "identity", 'l', tenant_identity_applies() ? TENANT_IDENTITY : NULL);
#endif
#ifdef WE_LOOKUP_TEST_DOWNGRADE_NO_RULE
    would_deny = 0;
#endif
    if (would_deny && strcmp(action, "log") == 0) {
        L_add(l, "would-deny-rule", 's', xprintf("%s:%u", wd_prog == 0 ? "floor" : "ctx", wd_rule), 0);
        L_add(l, "would-deny-text", 's', rule_text(wd_prog == 0 ? R.floor_text : R.ctx_text, wd_rule), 0);
    } else {
        L_null(l, "would-deny-rule", 's');
        L_null(l, "would-deny-text", 's');
    }
    free(log.p);
    return rc;
}

static int decision_from_sugar(line_t *l, const addr_t *a)
{
    sugar_t s = sugar_decide(a);
    int rc = 0;

    L_init(l, "decision");
    L_pos(l, "action", 's', s.action);
    if (s.enforce) {
        L_keyb(l, "enforce", 1);
    } else {
        L_null(l, "enforce", 'b');
    }
    if (s.would_deny) {
        L_keyb(l, "would-deny", 1);
    } else {
        L_null(l, "would-deny", 'b');
    }
    L_key(l, "step", 's', "sugar");
    /* under mode log the sugar's deny recorded and the default decided, as the evaluator's verdict says
     * (rule=0 log_ctx=1): `rule` stays the deciding rule and the deny is named in its own keys */
    L_keyn(l, "rule", s.enforce ? (uint64_t)s.rule : 0);
    if (s.enforce) {
        L_add(l, "text", 's', rule_text(R.ctx_text, (unsigned)s.rule), 0);
    } else {
        L_null(l, "text", 's');
    }
    L_key(l, "reason", 's', s.reason);
    L_key(l, "log", 's', s.would_deny ? "ctx:1" : NULL);
    L_null(l, "identity", 'l');
    if (s.would_deny) {
        L_key(l, "would-deny-rule", 's', "ctx:1");
        L_add(l, "would-deny-text", 's', rule_text(R.ctx_text, (unsigned)s.rule), 0);
    } else {
        L_null(l, "would-deny-rule", 's');
        L_null(l, "would-deny-text", 's');
    }
    g_enforced = s.enforce;
    if (s.enforce) {
        rc = 1;
    } else {
#ifndef WE_LOOKUP_TEST_OLD_FORM_EXIT_FLIPPED
        if (R.old_form && s.would_deny) {
            rc = 1;
        }
#endif
#ifdef WE_LOOKUP_TEST_EXIT_ON_LOG
        if (s.would_deny) {
            rc = 1;
        }
#endif
    }
    return rc;
}

/* the dependents lines, floor then ctx, as the evaluator's dependents line writes them */
static int dependents(char out[2][4096])
{
    uint8_t mask = 0;
    we_tenant_state_t ts;
    const char *tw = tenant_word(&ts);
    sb_t what = {0};
    int k, n = 0;
    static const char *const tname[5] = { "fresh", "grace", "lapsed", "null", "revoked" };

    (void)tw;
    sb_puts(&what, "out=");
    for (k = 0; k < 7; k++) {
        const plane_t *p = &R.planes[k];

        if (plane_configured(k) && !(p->armed && p->state == PS_FRESH)) {
            mask = (uint8_t)(mask | (1u << k));
            sb_printf(&what, "%s%s", what.n > 4 ? "," : "", p->name);
        }
    }
    if (what.n == 4) {
        sb_putc(&what, '-');
    }
    sb_printf(&what, " tenant=%s", tname[ts]);
    out[0][0] = out[1][0] = '\0';
#ifndef WE_LOOKUP_TEST_DEPENDENTS_CTX_ONLY
    if (R.has_floor && we_program_dependents_line(R.floor, mask, ts, what.p, out[0], 4096) >= 0) {
        n |= 1;
    }
#endif
    if (R.ctx != NULL && we_program_dependents_line(R.ctx, mask, ts, what.p, out[1], 4096) >= 0) {
        n |= 2;
    }
    free(what.p);
    return n;
}

/* an oracle kind: its own bytes after the kind word, never quoted */
static void emit_oracle(sb_t *o, const char *kind, const char *text)
{
    if (strncmp(text, kind, strlen(kind)) == 0 && text[strlen(kind)] == ' ') {
        text += strlen(kind) + 1;
    }
    if (g_json) {
        json_string(o, text);
        return;
    }
    sb_puts(o, kind);
    sb_putc(o, ' ');
#ifdef WE_LOOKUP_TEST_ORACLE_LINE_QUOTED
    line_token(o, text, 0);
#else
    sb_puts(o, text);
#endif
    sb_putc(o, '\n');
}

/* the counts on standard error */
static unsigned long n_allowed, n_denied, n_refused;

static int emit_address(sb_t *o, const char *input, int first_addr, int index)
{
    addr_t a;
    line_t l;
    int rc = 0, first;
    we_verdict_t v;
    static char vl[WE_VERDICT_LINE_MAX], cl[WE_VERDICT_LINE_MAX];

    classify(input, &a);
#ifdef WE_LOOKUP_TEST_NOW_PER_ADDRESS
    R.now_ms = clock_now_ms();
#endif
#ifdef WE_LOOKUP_TEST_NOW_GETTIMEOFDAY
    R.now_ms = clock_now_ms();
#endif
    if (R.fields || R.want_case) {
        if (a.ok) {
            if (R.fields) {
                emit_fields(o, &a);
            } else {
                emit_case(o, &a, index);
            }
        } else {
            sb_t r = {0}, e = {0};

            /* these modes print no address line, so the refusal and its fix go to standard error */
            render(&r, input, strlen(input));
            render(&e, a.err, strlen(a.err));
            fprintf(stderr, "whisper-edge-lookup: %s: %s\n", r.p, e.p);
            free(r.p);
            free(e.p);
            n_refused++;
            rc = 2;
        }
        addr_free(&a);
        return rc;
    }
    L_init(&l, "address");
    L_pos(&l, "input", 's', input);
    if (a.ok) {
        L_keyn(&l, "family", (uint64_t)a.family);
        L_key(&l, "canonical", 's', a.canon);
        L_null(&l, "error", 's');
    } else {
        L_null(&l, "family", 'n');
        L_null(&l, "canonical", 's');
        L_key(&l, "error", 's', a.err);
    }
    if (g_json) {
        if (!first_addr) {
            sb_putc(o, ',');
        }
        first = 1;
        sb_putc(o, '{');
        print_members(o, &l, &first);
    } else {
        print_line(o, &l);
    }
    L_free(&l);
    if (!a.ok) {
        n_refused++;
        if (g_json) {
#ifdef WE_LOOKUP_TEST_REFUSED_ADDRESS_KEYS_OMITTED
            sb_puts(o, ",\"notes\":[]}");
#else
            sb_puts(o, ",\"attributes\":[],\"holdHarmless\":null,\"verdict\":null,\"cost\":null,"
                       "\"dependents\":[],\"decision\":null,\"notes\":[]}");
#endif
        }
        addr_free(&a);
        return 2;
    }
    judge(&a, &v, vl, cl);
#if defined(WE_TRACE) && defined(WE_LOOKUP_TEST_EXIT_MID_DOCUMENT)
    if (g_k3_impossible != 0) {
        out_flush();
        fprintf(stderr, "whisper-edge-lookup: internal: K3 state (1,1) reached %lu times\n", g_k3_impossible);
        exit(2);
    }
#endif
    /* attributes */
    if (g_json) {
        sb_puts(o, ",\"attributes\":[");
    }
    emit_attrs(o, &a);
    if (g_json) {
        sb_putc(o, ']');
    }
    /* hold-harmless and its citations */
    {
        const we_hh_range_t *hr = hh_member(&a);
        int eligible = !R.skipped_hop;
        int applies = hr != NULL && eligible && R.prestage;
        uint32_t i;
        int firstc = 1;

#ifdef WE_LOOKUP_TEST_PRESTAGE_IN_LEGACY
        applies = hr != NULL && eligible;
#endif
        L_init(&l, "hold-harmless");
        L_add(&l, "member", 'b', xstrdup(hr ? "yes" : "no"), 1);
        L_keyb(&l, "eligible", eligible);
        L_keyb(&l, "applies", applies);
        if (hr != NULL) {
            char s[64], e[64];

            fmt_addr(hr->family, hr->start, s, sizeof s);
            fmt_addr(hr->family, hr->end, e, sizeof e);
            L_add(&l, "range", 's', xprintf("%s-%s", s, e), 0);
        } else {
            L_null(&l, "range", 's');
        }
        if (g_json) {
            first = 1;
            sb_puts(o, ",\"holdHarmless\":{");
            print_members(o, &l, &first);
            sb_puts(o, ",\"cites\":[");
        } else {
            print_line(o, &l);
        }
        L_free(&l);
        for (i = 0; i < WE_HH_CITE_COUNT; i++) {
            const we_hh_cite_t *c = &we_hh_cites[i];

            if (c->family != a.family || !in_range(a.family, a.b, c->start, c->end)) {
                continue;
            }
            L_init(&l, "cite");
            L_pos(&l, "entry", 's', c->entry);
            L_key(&l, "method", 's', c->method);
            L_key(&l, "note", 's', c->note);
            if (g_json) {
                if (!firstc) {
                    sb_putc(o, ',');
                }
                print_obj(o, &l);
            } else {
                print_line(o, &l);
            }
            firstc = 0;
            L_free(&l);
        }
        if (g_json) {
            sb_puts(o, "]}");
        }
    }
    /* the verdict, its cost and the dependents: the evaluator's lines */
    {
        char dl[2][4096];
        int dn = dependents(dl), d, firstd = 1;

        if (g_json) {
            sb_puts(o, ",\"verdict\":");
        }
        emit_oracle(o, "verdict", vl);
        if (g_json) {
            sb_puts(o, ",\"cost\":");
        }
        emit_oracle(o, "cost", cl);
        if (g_json) {
            sb_puts(o, ",\"dependents\":[");
        }
        for (d = 0; d < 2; d++) {
            if (dn & (1 << d)) {
                char *t = xprintf("%s %s", d == 0 ? "floor" : "ctx", dl[d]);

                if (g_json && !firstd) {
                    sb_putc(o, ',');
                }
                emit_oracle(o, "dependents", t);
                firstd = 0;
                free(t);
            }
        }
        if (g_json) {
            sb_putc(o, ']');
        }
    }
    /* the decision */
    {
        notes_t an = {0};
        uint32_t i;

        if (a.note) {
            note_add(&an, xstrdup(a.note));
        }
        if (a.note2) {
            note_add(&an, xstrdup(a.note2));
        }
        rc = R.model == MODEL_LEGACY && !R.prestage ? decision_from_sugar(&l, &a) : decision_from_verdict(&l, &v);
        if (g_json) {
            sb_puts(o, ",\"decision\":");
            print_obj(o, &l);
        } else {
            print_line(o, &l);
        }
        L_free(&l);
        /* counted by what the line says; the old form's exit 1 on a would-deny is its own contract */
        if (g_enforced) {
            n_denied++;
        } else {
            n_allowed++;
        }
        if (g_json) {
            sb_puts(o, ",\"notes\":[");
            for (i = 0; i < an.n; i++) {
                if (i) {
                    sb_putc(o, ',');
                }
                json_string(o, an.v[i]);
            }
            sb_puts(o, "]}");
        } else {
            for (i = 0; i < an.n; i++) {
                L_init(&l, "note");
                L_pos(&l, "text", 's', an.v[i]);
                print_line(o, &l);
                L_free(&l);
            }
        }
        notes_free(&an);
    }
    addr_free(&a);
    return rc;
}

/* ---- the policy: read, compiled by the policy compiler, its lines ---- */

static int context_ok(const char *c, unsigned *bad);

static char *g_policy_text;     /* the bytes the directives point into */
static size_t g_policy_len;

static void dir_add(uint8_t kind, const char *ctx, const uint8_t *arg, size_t len)
{
    we_policy_directive_t *d = (we_policy_directive_t *)realloc(R.dirs, (R.ndirs + 1) * sizeof *d);
    char **c = (char **)realloc(R.dir_ctx, (R.ndirs + 1) * sizeof *c);

    if (d == NULL || c == NULL) {
        die_oom();
    }
    R.dirs = d;
    R.dir_ctx = c;
    R.dir_ctx[R.ndirs] = xstrdup(ctx);
    R.dirs[R.ndirs].kind = kind;
    R.dirs[R.ndirs].context = R.dir_ctx[R.ndirs];
    R.dirs[R.ndirs].arg = arg;
    R.dirs[R.ndirs].len = len;
    R.ndirs++;
}

static uint8_t kind_of_word(const char *w, size_t n)
{
    static const struct { const char *w; uint8_t k; } t[] = {
        { "policy", WE_DIR_POLICY }, { "set", WE_DIR_SET }, { "floor", WE_DIR_FLOOR },
        { "threshold", WE_DIR_THRESHOLD }, { "mode", WE_DIR_MODE }, { "allow_inferred", WE_DIR_ALLOW_INFERRED }
    };
    size_t i;

    for (i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (strlen(t[i].w) == n && memcmp(t[i].w, w, n) == 0) {
            return t[i].k;
        }
    }
    return 0xEEu;                    /* a kind no directive has: the compiler refuses it */
}

static int is_ws(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/*
 * The installer's policy.conf: `#` to the end of a line is the CONFIGURATION file's comment, removed
 * before the language sees a byte; `whisper_edge_mode X;` is the mode; every other non-empty line is
 * one policy rule, at http.
 */
static void parse_conf(char *t, size_t n)
{
    size_t i = 0;

    while (i < n) {
        size_t s = i, e;

        while (i < n && t[i] != '\n') {
            i++;
        }
        e = i;
        if (i < n) {
            i++;
        }
#ifndef WE_LOOKUP_TEST_CONF_KEEPS_COMMENTS
        {
            size_t h;

            for (h = s; h < e; h++) {
                if (t[h] == '#') {
                    e = h;
                    break;
                }
            }
        }
#endif
        while (s < e && is_ws((uint8_t)t[s])) {
            s++;
        }
        while (e > s && is_ws((uint8_t)t[e - 1])) {
            e--;
        }
        if (s == e) {
            continue;
        }
        if (e - s >= 17 && memcmp(t + s, "whisper_edge_mode", 17) == 0) {
            size_t a = s + 17, b = e;

            while (a < b && is_ws((uint8_t)t[a])) {
                a++;
            }
            while (b > a && t[b - 1] == ';') {
                b--;
            }
            while (b > a && is_ws((uint8_t)t[b - 1])) {
                b--;
            }
            dir_add(WE_DIR_MODE, "http", (const uint8_t *)t + a, b - a);
        } else {
            dir_add(WE_DIR_POLICY, "http", (const uint8_t *)t + s, e - s);
        }
    }
}

/* the corpus form: `<kind> SP <context> SP <argument> 0x1E 0x0A`, repeated */
static int parse_records(char *t, size_t n)
{
    size_t i = 0;

    while (i < n) {
        size_t s = i, sp1, sp2, end;
        char ctx[256];

        end = s;
        while (end + 1 < n && !(t[end] == 0x1e && t[end + 1] == '\n')) {
            end++;
        }
        if (end + 1 >= n) {
            /* a trailing chunk without its separator: only a final newline is allowed */
            while (s < n && t[s] == '\n') {
                s++;
            }
            return s == n ? 0 : -1;
        }
        i = end + 2;
        while (s < end && t[s] == '\n') {
            s++;
        }
        if (s == end) {
            continue;
        }
        sp1 = s;
        while (sp1 < end && t[sp1] != ' ') {
            sp1++;
        }
        sp2 = sp1 < end ? sp1 + 1 : end;
        while (sp2 < end && t[sp2] != ' ') {
            sp2++;
        }
        if (sp1 >= end || sp2 - sp1 - 1 >= sizeof ctx) {
            return -1;
        }
        memcpy(ctx, t + sp1 + 1, sp2 - sp1 - 1);
        ctx[sp2 - sp1 - 1] = '\0';
        dir_add(kind_of_word(t + s, sp1 - s), ctx, (const uint8_t *)t + (sp2 < end ? sp2 + 1 : end),
                sp2 < end ? end - sp2 - 1 : 0);
    }
    return 0;
}

/* one report from the compiler, in the reference interpreter's line form */
static void collect_report(void *ud, const we_policy_report_line_t *r)
{
    const char *sp = r->detail != NULL && r->detail[0] != '\0' ? " " : "";
    const char *dt = r->detail != NULL ? r->detail : "";

    (void)ud;
    if (r->kind == WE_DIR_SET) {
        sb_printf(&R.reports, "report set %s/@%s %s%s%s\n", r->context, r->name != NULL ? r->name : "", r->code, sp,
                  dt);
    } else {
        sb_printf(&R.reports, "report %s %s %u %s%s%s\n", r->kind == WE_DIR_FLOOR ? "floor" : "ctx", r->context,
                  r->rule, r->code, sp, dt);
    }
}

static char *program_text(const we_program_t *p)
{
    size_t n = 65536;

    if (p == NULL) {
        return xstrdup("");
    }
    for (;;) {
        char *b = (char *)malloc(n);

        if (b == NULL) {
            die_oom();
        }
        if (we_program_print(p, b, n) >= 0) {
            return b;
        }
        free(b);
        n *= 2;
    }
}

/* bytes outside 0x20..0x7E as \xHH, the rest as they are: a compiler message keeps its quotes */
static void put_printable(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (c >= 0x20 && c <= 0x7e) {
            fputc(c, f);
        } else {
            fprintf(f, "\\x%02X", c);
        }
    }
}

/* the record form's separator, 0x1E 0x0A, anywhere in the text */
static int has_record_separator(const char *t, size_t n)
{
    size_t i;

    for (i = 0; i + 1 < n; i++) {
        if (t[i] == 0x1e && t[i + 1] == '\n') {
            return 1;
        }
    }
    return 0;
}

/* the policy source: a regular file of at most 1 MiB, symlinks followed, a FIFO never waited on */
static int read_text(const char *path, char **out, size_t *len)
{
    int fd;
    struct stat st;
    char *b;
    size_t got = 0;

#ifdef WE_LOOKUP_TEST_POLICY_NOFOLLOW
    fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
#else
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
#endif
    if (fd < 0) {
        char why[160];

        snprintf(why, sizeof why, ": %s", errno == ELOOP ? "not-regular (a symlink)" : strerror(errno));
        err_rendered("cannot read the policy ", path, why);
        return 2;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        err_rendered("the policy ", path, " is not-regular: give a regular file");
        return 2;
    }
    if ((uint64_t)st.st_size > POLICY_MAX) {
        close(fd);
        err_rendered("the policy ", path, " is larger than the 1 MiB bound");
        return 2;
    }
    b = (char *)malloc((size_t)st.st_size + 1);
    if (b == NULL) {
        die_oom();
    }
    while (got < (size_t)st.st_size) {
        ssize_t r = read(fd, b + got, (size_t)st.st_size - got);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
    }
    close(fd);
    if (got != (size_t)st.st_size) {
        free(b);
        err_rendered("cannot read the policy ", path, ": it changed while it was read");
        return 2;
    }
    b[got] = '\0';
    *out = b;
    *len = got;
    return 0;
}

/*
 * The configuration the run evaluates, compiled by the policy compiler exactly as a module compiles it:
 * a policy file, the shipped default, no rules, or the threshold sugar a module with no policy lines
 * runs. Returns 0, or 2 with the refusal printed.
 */
static int build_policy(void)
{
    we_policy_source_t src;
    we_policy_error_t err;
    we_policy_report_t rep = { collect_report, NULL };
    int rc, ai_written = 0;
    size_t i;

    if (R.model == MODEL_LEGACY) {
        R.sugar = 1;
        R.policy_source = "sugar";
    } else if (R.policy_given && strcmp(R.policy, "none") == 0) {
        R.policy_source = "none";
    } else if (R.policy_given && strcmp(R.policy, "default") == 0) {
        R.policy_source = "builtin-default";
        g_policy_text = xstrdup(we_default_policy);
        g_policy_len = WE_DEFAULT_POLICY_LEN;
    } else if (R.policy_given || R.installed > 0) {
        const char *etc = getenv("WHISPER_EDGE_ETC");
        char *conf = R.policy_given ? xstrdup(R.policy) : xprintf("%s/policy.conf", etc && etc[0] ? etc
                                                                                     : "/etc/whisper-edge");

        R.policy_source = R.policy_given ? "file" : "policy-conf";
        rc = read_text(conf, &g_policy_text, &g_policy_len);
        free(conf);
        if (rc != 0) {
            return 2;
        }
    } else {
#ifdef WE_LOOKUP_TEST_DEFAULT_WITHOUT_POLICY
        R.policy_source = "builtin-default";
        g_policy_text = xstrdup(we_default_policy);
        g_policy_len = WE_DEFAULT_POLICY_LEN;
#else
        R.sugar = 1;
        R.policy_source = "sugar";
#endif
    }
    if (R.sugar) {
        g_policy_text = xstrdup(R.threshold_name);
        g_policy_len = strlen(g_policy_text);
        dir_add(WE_DIR_THRESHOLD, "http", (const uint8_t *)g_policy_text, g_policy_len);
    } else if (g_policy_text != NULL) {
        if (has_record_separator(g_policy_text, g_policy_len)) {
            if (parse_records(g_policy_text, g_policy_len) != 0) {
                fputs("whisper-edge-lookup: the policy is in the record form (<kind> <context> <argument>, each "
                      "ended by 0x1E 0x0A) and a record in it is incomplete\n", stderr);
                return 2;
            }
        } else {
            parse_conf(g_policy_text, g_policy_len);
        }
    }
    for (i = 0; i < R.ndirs; i++) {
        R.has_floor |= R.dirs[i].kind == WE_DIR_FLOOR;
        ai_written |= R.dirs[i].kind == WE_DIR_ALLOW_INFERRED;
        {
            unsigned bad = 0;

            if (!context_ok(R.dirs[i].context, &bad)) {
#ifndef WE_LOOKUP_TEST_CONTEXT_BYTES_PASSED
                sb_t r = {0};

                render(&r, R.dirs[i].context, strlen(R.dirs[i].context));
                fprintf(stderr, "whisper-edge-lookup: context %s holds byte 0x%02X; a context is printable ASCII "
                                "without spaces\n", r.p, bad);
                free(r.p);
                return 2;
#endif
            }
        }
    }
    /* the digest of the configuration compiled: its directives in the record form */
    {
        we_sha256_ctx c;
        uint8_t d[32];
        int k;

        we_sha256_init(&c);
        for (i = 0; i < R.ndirs; i++) {
            const char *kw = we_policy_kind_name(R.dirs[i].kind);

            we_sha256_update(&c, (const uint8_t *)kw, strlen(kw));
            we_sha256_update(&c, (const uint8_t *)" ", 1);
            we_sha256_update(&c, (const uint8_t *)R.dirs[i].context, strlen(R.dirs[i].context));
            we_sha256_update(&c, (const uint8_t *)" ", 1);
            we_sha256_update(&c, R.dirs[i].arg, R.dirs[i].len);
            we_sha256_update(&c, (const uint8_t *)"\x1e\n", 2);
        }
        we_sha256_final(&c, d);
        for (k = 0; k < 32; k++) {
            snprintf(R.digest + 2 * k, 3, "%02x", d[k]);
        }
    }
    if (R.model == MODEL_LEGACY) {
        memset(&R.env, 0, sizeof R.env);
        R.env.present = 0x01u;
        R.env.schema_ok = 0x01u;
        R.env.legacy = 1u;
    }
    src.d = R.dirs;
    src.n = R.ndirs;
    src.context = NULL;
    src.floor = 0;
    memset(&err, 0, sizeof err);
    rc = we_policy_build(&src, &R.env, NULL, &R.build, &err, &rep);
    if (rc != WE_POLICY_OK) {
        char msg[2048];

        if (rc == WE_POLICY_NOMEM) {
            die_oom();
        }
        we_policy_error_format(&err, msg, sizeof msg);
#ifdef WE_LOOKUP_TEST_REFUSAL_GENERIC
        (void)put_printable;
        fputs("whisper-edge-lookup: the policy is refused\n", stderr);
#else
        fprintf(stderr, "whisper-edge-lookup: the policy (%s) is refused: ", R.policy_source);
        put_printable(stderr, msg);
        fputc('\n', stderr);
#endif
        return 2;
    }
    R.floor = we_policy_floor(R.build);
#ifdef WE_LOOKUP_TEST_CONTEXT_HTTP
    R.ctx = we_policy_program(R.build, "http");
#else
    R.ctx = we_policy_program(R.build, R.context);
#endif
    if (we_program_place(R.floor, &g_hh) != 0) {
        fputs("whisper-edge-lookup: internal: the hold-harmless view could not be placed\n", stderr);
        return 2;
    }
    if (R.sugar) {
        R.floor_conf.mode = (uint8_t)(R.mode_deny ? WE_MODE_DENY : WE_MODE_LOG);
        R.floor_conf.allow_inferred = (uint8_t)R.allow_inferred;
        R.ctx_conf = R.floor_conf;
    } else {
        R.floor_conf = we_policy_conf(R.build, "http");
        R.ctx_conf = we_policy_conf(R.build, R.context);
        if (R.allow_inferred && !ai_written) {
            R.ctx_conf.allow_inferred = 1u;
            if (R.ctx_conf.mode < WE_MODE_OFF || R.ctx_conf.mode > WE_MODE_DENY) {
                R.ctx_conf.mode = WE_MODE_LOG;      /* the pair's domain: an unset mode reads as log */
            }
        }
    }
    R.floor_text = program_text(R.has_floor ? R.floor : NULL);
    R.ctx_text = program_text(R.ctx);
    return 0;
}

static const char *mode_word(we_ctx_conf_t c)
{
    if (c.mode < WE_MODE_OFF || c.mode > WE_MODE_DENY || c.allow_inferred > 1u) {
        return "log";
    }
    return c.mode == WE_MODE_OFF ? "off" : c.mode == WE_MODE_DENY ? "deny" : "log";
}

static void emit_policy(sb_t *o)
{
    line_t l;
    int k;
    const char *text[2];
    int firstr = 1;

    L_init(&l, "policy");
    L_key(&l, "source", 's', R.policy_source);
    L_key(&l, "installed", 's', R.installed > 0 ? "yes" : R.installed < 0 ? "unknown" : "no");
    /* whether the server loads the installed policy is the server's to say; this tool never claims it */
    L_key(&l, "applied", 's', R.installed > 0 ? "not-verified" : NULL);
    L_key(&l, "threshold", 's', R.sugar ? R.threshold_name : NULL);
    L_key(&l, "defaults", 's', R.sugar ? (R.threshold_given || R.mode_given ? "option" : "module") : NULL);
    L_key(&l, "context", 's', R.context);
    L_key(&l, "mode", 's', mode_word(R.ctx_conf));
    L_keyb(&l, "allow-inferred", R.ctx_conf.allow_inferred == 1u && R.ctx_conf.mode >= WE_MODE_OFF
                                     && R.ctx_conf.mode <= WE_MODE_DENY);
    L_keyn(&l, "rules", R.ctx != NULL ? R.ctx->rule_count : 0u);
    L_keyn(&l, "floor-rules", R.has_floor ? R.floor->rule_count : 0u);
    L_key(&l, "digest", 's', R.digest);
    if (g_json) {
        int first = 1;

        sb_puts(o, ",\"policy\":{");
        print_members(o, &l, &first);
        sb_puts(o, ",\"ruleList\":[");
    } else {
        print_line(o, &l);
    }
    L_free(&l);
    text[0] = R.floor_text;
    text[1] = R.ctx_text;
    for (k = 0; k < 2; k++) {
        const we_program_t *p = k == 0 ? (R.has_floor ? R.floor : NULL) : R.ctx;
        unsigned r;

        for (r = 1; p != NULL && r <= p->rule_count; r++) {
            L_init(&l, "rule");
            L_pos(&l, "program", 's', k == 0 ? "floor" : "ctx");
            L_add(&l, "n", 'n', xprintf("%u", r), 1);
#ifdef WE_LOOKUP_TEST_RULE_NO_TEXT
            (void)text;
            L_null(&l, "text", 's');
#else
            L_add(&l, "text", 's', rule_text(text[k], r), 0);
#endif
            if (g_json) {
                if (!firstr) {
                    sb_putc(o, ',');
                }
                print_obj(o, &l);
            } else {
                print_line(o, &l);
            }
            firstr = 0;
            L_free(&l);
        }
    }
    if (g_json) {
        sb_puts(o, "],\"reports\":[");
    }
    {
        const char *p = R.reports.p;
        int firstp = 1;

        while (p != NULL && *p != '\0') {
            const char *nl = strchr(p, '\n');
            size_t n = nl ? (size_t)(nl - p) : strlen(p);
            char *t = (char *)malloc(n + 1);

            if (t == NULL) {
                die_oom();
            }
            memcpy(t, p, n);
            t[n] = '\0';
            if (g_json && !firstp) {
                sb_putc(o, ',');
            }
            emit_oracle(o, "report", t);
            firstp = 0;
            free(t);
            p = nl ? nl + 1 : NULL;
        }
    }
    if (g_json) {
        sb_puts(o, "]}");
    }
}

/* ======================================================================================================
 * Options
 * ==================================================================================================== */

static const char *const OPTS[] = {
    "--dir", "--snapshot", "--prestage", "--policy", "--threshold", "--mode", "--context", "--allow-inferred",
    "--skipped-hop", "--acme", "--now", "--json", "--fields", "--case", "--help", "--probe-dir", "--programs",
    "--uid"
};
#define N_OPTS (sizeof OPTS / sizeof OPTS[0])

static int takes_value(const char *o)
{
    return strcmp(o, "--dir") == 0 || strcmp(o, "--snapshot") == 0 || strcmp(o, "--prestage") == 0
        || strcmp(o, "--policy") == 0 || strcmp(o, "--threshold") == 0 || strcmp(o, "--mode") == 0
        || strcmp(o, "--context") == 0 || strcmp(o, "--now") == 0 || strcmp(o, "--probe-dir") == 0
        || strcmp(o, "--programs") == 0 || strcmp(o, "--uid") == 0;
}

static size_t edit_distance(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b), i, j;
    size_t prev[64], cur[64];

    if (la > 60 || lb > 60) {
        return 99;
    }
    for (j = 0; j <= lb; j++) {
        prev[j] = j;
    }
    for (i = 1; i <= la; i++) {
        cur[0] = i;
        for (j = 1; j <= lb; j++) {
            size_t c = prev[j - 1] + (a[i - 1] != b[j - 1]);

            if (prev[j] + 1 < c) {
                c = prev[j] + 1;
            }
            if (cur[j - 1] + 1 < c) {
                c = cur[j - 1] + 1;
            }
            cur[j] = c;
        }
        memcpy(prev, cur, (lb + 1) * sizeof prev[0]);
    }
    return prev[lb];
}

static const char *closest_option(const char *o)
{
    size_t i, best = 0, bd = 999;

    for (i = 0; i < N_OPTS; i++) {
        size_t d = edit_distance(o, OPTS[i]);

        if (d < bd) {
            bd = d;
            best = i;
        }
    }
    return OPTS[best];
}

/* ---- --probe-dir and --programs: what a data directory holds and what a configuration compiles to ----
 *
 * Two inspection modes with no address, for the module gates and the cross-server differential's case
 * producer: --probe-dir prints the data model as whisper_edge_data probes it (one line per plane, the
 * probe's class, the header's generation, validity and digest16, owner and mode), each plane's state the
 * module's own bind verdict (we_mod_bind_check: the directory walk, the plane's mode, owner, link and file
 * system rules and its verification, the function the modules' configuration test calls, never a copy of
 * its rules), and --programs prints
 * the programs a configuration compiles to through we_policy_build() in that environment (every plane
 * present without --probe-dir): the floor's and each context's digest16, rule count and effective conf,
 * and every program's canonical rule text. */

typedef struct {
    uint64_t generation, built_at_ms, valid_until_ms, size;
    uint8_t  digest[32];
    uint32_t format, uid, mode, err;
    uint8_t  plane_id, schema, absent;
} lk_peek_t;

/* the module's peek (we_plane_peek), read the same way: the 192-byte header, nothing digested */
static int lk_peek(int dirfd, const char *name, uint32_t plane, lk_peek_t *out, char *why, size_t whyn)
{
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    we_header_t h;
    ssize_t got;

    memset(out, 0, sizeof *out);
    if (fd < 0) {
        out->absent = errno == ENOENT;
        out->err = (uint32_t)errno;
        snprintf(why, whyn, "%s", strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        snprintf(why, whyn, "not a regular file");
        return -1;
    }
    got = pread(fd, &h, sizeof h, 0);
    close(fd);
    out->uid = st.st_uid;
    out->mode = st.st_mode & 07777u;
    out->size = (uint64_t)st.st_size;
    if (got != (ssize_t)sizeof h || h.magic != WE_MAGIC || (h.format != WE_FORMAT_1 && h.format != WE_FORMAT_2)) {
        snprintf(why, whyn, "not a plane file (its header is not this format's)");
        return -1;
    }
    out->format = h.format;
    out->generation = h.generation;
    out->built_at_ms = h.built_at_ms;
    out->valid_until_ms = h.valid_until_ms;
    memcpy(out->digest, h.digest, 32);
    out->schema = (h.flags & WE_H_SCHEMA) != 0u;
    out->plane_id = out->schema ? h.schema.plane_id : 0u;
    if (out->schema ? out->plane_id != plane : !(plane == WE_PLANE_REPUTATION && h.format == WE_FORMAT_1)) {
        snprintf(why, whyn, out->schema ? "its header names plane %u, and it is bound as plane %u"
                                        : "a pre-schema file can only be bound as reputation, and it is bound as plane %u",
                 out->schema ? out->plane_id : plane, plane);
        return -1;
    }
    return 0;
}

/* the first 16 hex digits of a digest, as the status and the generations token render it */
static void lk_hex16(const uint8_t dg[32], char out[17])
{
    static const char hx[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 8; i++) {
        out[2 * i] = hx[dg[i] >> 4];
        out[2 * i + 1] = hx[dg[i] & 15];
    }
    out[16] = '\0';
}

static const char *const lk_plane[8] = {
    "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};

/* the probe's class of plane p (0-based) in `env`, as we_policy_env_probe() classified it */
static const char *lk_probe_class(const we_policy_env_t *env, uint32_t p)
{
    if (((env->present >> p) & 1u) == 0u) {
        return "absent";
    }
    return ((env->schema_ok >> p) & 1u) != 0u ? "present,schema-ok" : "present,schema-bad";
}

static int lk_dir(const char *dir, we_policy_env_t *env)
{
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    uint32_t p;
    struct stat st;
    char snap[PATH_MAX], msg[512];
    static we_mod_plane_check_t bind[8];

    if (dirfd < 0) {
        fprintf(stderr, "cannot open the data directory %s: %s\n", dir, strerror(errno));
        return 2;
    }
    if (we_policy_env_probe(dir, env) != 0) {
        close(dirfd);
        fprintf(stderr, "cannot probe the data directory %s\n", dir);
        return 2;
    }
    /* the verdict is the module's: the bind's own check over this directory, every plane read. A
     * configuration must name the directory from /, but an operator here may name it from where they stand */
    if (lk_bind_verdict(dir, NULL, bind, msg, sizeof msg) != 0) {
        close(dirfd);
        fprintf(stderr, "cannot check the data directory %s as the module binds it: %s\n", dir, msg);
        return 2;
    }
    printf("data-directory %s\n", dir);
    printf("  environment present=0x%02x schema-ok=0x%02x (we_policy_env_probe, the modules' configuration environment)\n",
           (unsigned)env->present, (unsigned)env->schema_ok);
    printf("  bind uid=%u (each state is the module's bind verdict for workers of this uid; --uid names theirs)\n", g_bind_uid);
    for (p = 0u; p < 8u; p++) {
        lk_peek_t pk;
        char name[40], why[256], d16[17];

        snprintf(name, sizeof name, "%s.bin", lk_plane[p]);
#ifndef WE_LOOKUP_TEST_PROBE_OWN_RULES
        if (strcmp(bind[p].state, "verified") != 0) {
            /* the module would not bind it: absent, unreadable, or refused with the bind's own reason */
            struct stat ps;
            int have = fstatat(dirfd, name, &ps, AT_SYMLINK_NOFOLLOW) == 0;

            if (strcmp(bind[p].state, "absent") == 0) {
                printf("  plane %-16s state=absent probe=%s\n", lk_plane[p], lk_probe_class(env, p));
            } else if (strcmp(bind[p].state, "unreadable") == 0) {
                printf("  plane %-16s state=unreadable probe=%s why=\"%s\" (rules on it are inert)\n", lk_plane[p],
                       lk_probe_class(env, p), bind[p].reason);
            } else if (have) {
                printf("  plane %-16s state=refused probe=%s why=\"%s\" owner=%u mode=%04o size=%" PRIu64 "\n", lk_plane[p],
                       lk_probe_class(env, p), bind[p].reason, (unsigned)ps.st_uid, (unsigned)(ps.st_mode & 07777u),
                       (uint64_t)ps.st_size);
            } else {
                printf("  plane %-16s state=refused probe=%s why=\"%s\"\n", lk_plane[p], lk_probe_class(env, p),
                       bind[p].reason);
            }
            continue;
        }
#endif
        if (lk_peek(dirfd, name, p + 1u, &pk, why, sizeof why) != 0) {
            if (pk.absent) {
                printf("  plane %-16s state=absent probe=%s\n", lk_plane[p], lk_probe_class(env, p));
            } else if (pk.err != 0u) {
                printf("  plane %-16s state=unreadable probe=%s why=\"%s\" (rules on it are inert)\n", lk_plane[p],
                       lk_probe_class(env, p), why);
            } else {
                printf("  plane %-16s state=refused probe=%s why=\"%s\" owner=%u mode=%04o size=%" PRIu64 "\n", lk_plane[p],
                       lk_probe_class(env, p), why, pk.uid, pk.mode, pk.size);
            }
            continue;
        }
        lk_hex16(pk.digest, d16);
        printf("  plane %-16s state=present probe=%s format=%u schema=%s generation=%" PRIu64 " built=%" PRIu64
               " valid-until=%" PRIu64 " digest=%s owner=%u mode=%04o size=%" PRIu64 "\n",
               lk_plane[p], lk_probe_class(env, p), pk.format, pk.schema ? "yes" : "no", pk.generation, pk.built_at_ms,
               pk.valid_until_ms, d16, pk.uid, pk.mode, pk.size);
    }
    /* the legacy file: snapshot.bin is read only through whisper_edge_snapshot, never as a plane of a directory */
    if (snprintf(snap, sizeof snap, "%s/snapshot.bin", dir) < (int)sizeof snap && stat(snap, &st) == 0 && S_ISREG(st.st_mode)
            && ((env->present & 1u) == 0u)) {
        printf("  note snapshot.bin is here and reputation.bin is not: a data directory binds <plane>.bin names only; "
               "add \"whisper_edge_snapshot %s\" to read it, or --snapshot here\n", snap);
    }
    close(dirfd);
    return 0;
}

/* ---- --policy: the programs a configuration compiles to -------------------------------------------- */

#define LK_MAX_DIRS   4096u
#define LK_MAX_CTX    512u
#define LK_MAX_LINE   8192u

static we_policy_directive_t lk_dirs[LK_MAX_DIRS];
static size_t lk_ndirs;
static char *lk_contexts[LK_MAX_CTX];
static size_t lk_nctx;

static void lk_report_line(void *ud, const we_policy_report_line_t *r)
{
    (void)ud;
    printf("report %s %s %u %s %s\n", r->context, we_policy_kind_name(r->kind), r->rule, r->code,
           r->detail != NULL && r->detail[0] != '\0' ? r->detail : "-");
}

static int lk_hexval(int c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* the interpreter's escape(): a printable byte as itself, the backslash and the rest as \xHH */
static uint8_t *lk_unescape(const char *s, size_t *len)
{
    size_t n = strlen(s), o = 0u, i;
    uint8_t *out = malloc(n + 1u);

    if (out == NULL) {
        return NULL;
    }
    for (i = 0u; i < n; i++) {
        if (s[i] == '\\' && i + 3u < n + 0u && s[i + 1] == 'x' && lk_hexval(s[i + 2]) >= 0 && lk_hexval(s[i + 3]) >= 0) {
            out[o++] = (uint8_t)(lk_hexval(s[i + 2]) * 16 + lk_hexval(s[i + 3]));
            i += 3u;
        } else {
            out[o++] = (uint8_t)s[i];
        }
    }
    out[o] = 0u;
    *len = o;
    return out;
}

static int lk_kind_of(const char *w)
{
    if (strcmp(w, "policy") == 0) { return WE_DIR_POLICY; }
    if (strcmp(w, "set") == 0) { return WE_DIR_SET; }
    if (strcmp(w, "floor") == 0) { return WE_DIR_FLOOR; }
    if (strcmp(w, "threshold") == 0) { return WE_DIR_THRESHOLD; }
    if (strcmp(w, "mode") == 0) { return WE_DIR_MODE; }
    if (strcmp(w, "allow_inferred") == 0) { return WE_DIR_ALLOW_INFERRED; }
    return -1;
}

static int lk_add_dir(const char *kindw, const char *ctx, const uint8_t *arg, size_t len, const char *where)
{
    int kind = lk_kind_of(kindw);
    uint8_t *copy;

    if (kind < 0 || lk_ndirs == LK_MAX_DIRS) {
        fprintf(stderr, "%s: a directive outside the grammar (%s), or over %u directives\n", where, kindw, LK_MAX_DIRS);
        return -1;
    }
    copy = malloc(len + 1u);
    if (copy == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    memcpy(copy, arg, len);
    copy[len] = 0u;
    lk_dirs[lk_ndirs].kind = (uint8_t)kind;
    lk_dirs[lk_ndirs].context = strdup(ctx);
    lk_dirs[lk_ndirs].arg = copy;
    lk_dirs[lk_ndirs].len = len;
    if (lk_dirs[lk_ndirs].context == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    lk_ndirs++;
    return 0;
}

static int lk_add_context(const char *ctx)
{
    size_t i;

    for (i = 0u; i < lk_nctx; i++) {
        if (strcmp(lk_contexts[i], ctx) == 0) {
            return 0;
        }
    }
    if (lk_nctx == LK_MAX_CTX) {
        fprintf(stderr, "over %u contexts\n", LK_MAX_CTX);
        return -1;
    }
    lk_contexts[lk_nctx++] = strdup(ctx);
    return 0;
}

/* the corpus form: <kind> SP <context> SP <argument bytes>, each directive ended by 0x1E 0x0A */
static int lk_read_corpus(const uint8_t *data, size_t n, const char *path)
{
    size_t i = 0u;
    unsigned k = 0u;

    while (i < n) {
        size_t j = i, sp1, sp2;
        char kind[32], ctx[256], where[300];

        while (j < n && !(data[j] == 0x1Eu && j + 1u < n && data[j + 1] == '\n')) {
            j++;
        }
        k++;
        snprintf(where, sizeof where, "%s: directive %u", path, k);
        if (j > i && data[i] == '\n') {
            i++;
        }
        if (j == i) {
            i = j + 2u;
            continue;
        }
        for (sp1 = i; sp1 < j && data[sp1] != ' '; sp1++) { }
        for (sp2 = sp1 + 1u; sp2 < j && data[sp2] != ' '; sp2++) { }
        if (sp1 >= j || sp1 - i >= sizeof kind || (sp2 > sp1 + 1u ? sp2 - sp1 - 1u : 0u) >= sizeof ctx) {
            fprintf(stderr, "%s: outside the corpus grammar (<kind> <context> <argument>)\n", where);
            return -1;
        }
        memcpy(kind, data + i, sp1 - i);
        kind[sp1 - i] = '\0';
        memcpy(ctx, data + sp1 + 1u, sp2 - sp1 - 1u);
        ctx[sp2 - sp1 - 1u] = '\0';
        if (lk_add_dir(kind, ctx, data + (sp2 < j ? sp2 + 1u : j), sp2 < j ? j - sp2 - 1u : 0u, where) != 0
                || lk_add_context(ctx) != 0) {
            return -1;
        }
        i = j + 2u;
    }
    return 0;
}

/* the interpreter's case-file lines: `dir <kind> <context> <arg, \xHH escaped>`, `context <path>`, `#...` */
static int lk_read_lines(const char *text, const char *path)
{
    char *copy = strdup(text), *save, *line;
    unsigned ln = 0u;
    int rc = 0;

    if (copy == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    for (line = strtok_r(copy, "\n", &save); line != NULL && rc == 0; line = strtok_r(NULL, "\n", &save)) {
        char *w, *ctx, *arg, *s2;
        char where[300];

        ln++;
        snprintf(where, sizeof where, "%s:%u", path, ln);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        w = strtok_r(line, " ", &s2);
        if (strcmp(w, "context") == 0) {
            ctx = strtok_r(NULL, "", &s2);
            rc = ctx != NULL ? lk_add_context(ctx) : -1;
            continue;
        }
        if (strcmp(w, "dir") != 0) {
            fprintf(stderr, "%s: unknown line %s (dir <kind> <context> <arg>, or context <path>)\n", where, w);
            rc = -1;
            break;
        }
        w = strtok_r(NULL, " ", &s2);
        ctx = w != NULL ? strtok_r(NULL, " ", &s2) : NULL;
        arg = ctx != NULL ? strtok_r(NULL, "", &s2) : NULL;
        if (w == NULL || ctx == NULL) {
            fprintf(stderr, "%s: a dir line outside the grammar (dir <kind> <context> <arg>)\n", where);
            rc = -1;
            break;
        }
        {
            size_t len = 0u;
            uint8_t *raw = lk_unescape(arg != NULL ? arg : "", &len);

            if (raw == NULL) {
                rc = -1;
                break;
            }
            rc = lk_add_dir(w, ctx, raw, len, where);
            free(raw);
            if (rc == 0) {
                rc = lk_add_context(ctx);
            }
        }
    }
    free(copy);
    return rc;
}

static void lk_digest16(const we_program_t *p, char out[17])
{
    uint8_t dg[32];

    we_sha256(p, we_program_size(p), dg);
    lk_hex16(dg, out);
}

static void lk_print_texts(const we_program_t *p, const char *d16, char **seen, size_t *nseen)
{
    static char buf[1u << 20];
    size_t i;
    char *line, *save;
    unsigned n = 0u;

    for (i = 0u; i < *nseen; i++) {
        if (strcmp(seen[i], d16) == 0) {
            return;
        }
    }
    seen[(*nseen)++] = strdup(d16);
    if (we_program_print(p, buf, sizeof buf) < 0) {
        printf("text %s - (the canonical text is longer than this tool's buffer)\n", d16);
        return;
    }
    for (line = strtok_r(buf, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        printf("text %s %u %s\n", d16, ++n, line);
    }
}

static const char *lk_mode_word(uint32_t m)
{
    return m == WE_MODE_OFF ? "off" : m == WE_MODE_LOG ? "log" : m == WE_MODE_DENY ? "deny" : "unset";
}

/* the programs a configuration compiles to, in the environment `env` (the probe's, or every plane present) */
static int lk_policy(const char *path, const we_policy_env_t *env)
{
    FILE *f = fopen(path, "rb");
    uint8_t *data;
    size_t n = 0u, cap = 1u << 16, i;
    we_policy_source_t src;
    we_policy_build_t *b = NULL;
    we_policy_error_t err;
    we_policy_report_t rep = { lk_report_line, NULL };
    const we_program_t *floor;
    char d16[17];
    static char *seen[LK_MAX_CTX + 1u];
    size_t nseen = 0u;
    int rc, corpus = 0;

    if (f == NULL) {
        fprintf(stderr, "cannot read the policy %s: %s\n", path, strerror(errno));
        return 2;
    }
    data = malloc(cap);
    while (data != NULL) {
        size_t got = fread(data + n, 1, cap - n - 1u, f);

        n += got;
        if (n < cap - 1u) {
            break;
        }
        if (cap >= (1u << 24)) {
            fprintf(stderr, "the policy %s is over 16 MiB; nothing that large is a configuration\n", path);
            fclose(f);
            free(data);
            return 2;
        }
        cap *= 2u;
        data = realloc(data, cap);
    }
    fclose(f);
    if (data == NULL) {
        fprintf(stderr, "out of memory\n");
        return 2;
    }
    data[n] = 0u;
    for (i = 0u; i < n; i++) {
        if (data[i] == 0x1Eu) {
            corpus = 1;
            break;
        }
    }
    rc = corpus ? lk_read_corpus(data, n, path) : lk_read_lines((const char *)data, path);
    free(data);
    if (rc != 0) {
        return 2;
    }
    src.d = lk_dirs;
    src.n = lk_ndirs;
    src.context = NULL;
    src.floor = 0;
    memset(&err, 0, sizeof err);
    rc = we_policy_build(&src, env, NULL, &b, &err, &rep);
    if (rc != WE_POLICY_OK) {
        char text[1400];

        if (rc == WE_POLICY_REFUSED) {
            we_policy_error_format(&err, text, sizeof text);
            printf("refused %s %s %s\n", we_policy_kind_name(err.kind), err.context, text);
        } else {
            printf("refused - - out of memory\n");
        }
        return 2;
    }
    printf("env present %02x schema_ok %02x\n", (unsigned)env->present, (unsigned)env->schema_ok);
    floor = we_policy_floor(b);
    if (floor->rule_count > 0u) {
        lk_digest16(floor, d16);
        printf("floor %s rules %u\n", d16, (unsigned)floor->rule_count);
        lk_print_texts(floor, d16, seen, &nseen);
    } else {
        printf("floor - rules 0\n");
    }
    if (lk_add_context("http") != 0) {
        we_policy_build_free(b);
        return 2;
    }
    for (i = 0u; i < lk_nctx; i++) {
        const we_program_t *p = we_policy_program(b, lk_contexts[i]);
        we_ctx_conf_t conf = we_policy_conf(b, lk_contexts[i]);

        if (p != NULL) {
            lk_digest16(p, d16);
            printf("program %s %s rules %u mode %u allow_inferred %u (%s)\n", lk_contexts[i], d16, (unsigned)p->rule_count,
                   (unsigned)conf.mode, (unsigned)conf.allow_inferred, lk_mode_word(conf.mode));
            lk_print_texts(p, d16, seen, &nseen);
        } else {
            printf("program %s - rules 0 mode %u allow_inferred %u (%s)\n", lk_contexts[i], (unsigned)conf.mode,
                   (unsigned)conf.allow_inferred, lk_mode_word(conf.mode));
        }
    }
    we_policy_build_free(b);
    return 0;
}


static void usage_help(void)
{
    fputs(
"usage: whisper-edge-lookup [options] <address>...\n"
"       whisper-edge-lookup [--threshold L] <file> <address>...   the old form, the same as --snapshot <file>\n"
"       whisper-edge-lookup --probe-dir DIR [--uid UID] [--programs FILE]\n"
"       whisper-edge-lookup --programs FILE\n"
"\n"
"Prints what each data plane on this disk says about each address, every plane's state and provenance,\n"
"and what the module decides. It reads files only: it fetches nothing, holds no key and verifies no\n"
"signature.\n"
"\n"
"  --dir DIR            the data model: <plane>.bin files in DIR, as whisper_edge_data reads them\n"
"  --snapshot FILE      the legacy model: FILE as whisper_edge_snapshot reads it (reputation only)\n"
"  --probe-dir DIR      no address: the data model as whisper_edge_data probes DIR, one line per plane,\n"
"                       each state the module's own bind verdict (mode 0444, owner, links, the walk)\n"
"  --uid UID            the workers' uid or user name, the owner the module's bind accepts besides root\n"
"                       (default: the uid running this); every plane's state is the bind's verdict for it\n"
"  --programs FILE      no address: the programs FILE's directive lines compile to (the corpus form or the\n"
"                       case-file `dir` lines), in --probe-dir's environment or every plane present\n"
"  --prestage absent|present\n"
"                       legacy model: whether the module has the pre-stage (default absent: every\n"
"                       module built before the policy evaluator); the data model is always present\n"
"  --policy FILE|default|none\n"
"                       data model: policy.conf or .policy form; default = the shipped default policy;\n"
"                       none = no rules. Without the option: /etc/whisper-edge/policy.conf when it is\n"
"                       installed, else what a module with no policy lines runs (the threshold sugar,\n"
"                       high, mode log)\n"
"  --threshold L        sugar: off|low|medium|high|critical (default high, the module's)\n"
"  --mode log|deny      sugar: the mode (default log, the module's)\n"
"  --context CTX        the context whose program runs (default: http)\n"
"  --allow-inferred     the context's allow_inferred, when the policy does not set it\n"
"  --skipped-hop        the client was reached past a skipped trusted hop: no hold-harmless\n"
"  --acme               the request is an ACME HTTP-01 challenge\n"
"  --now T              epoch milliseconds (0..253402300799999) or RFC 3339, instead of the clock\n"
"  --json               one JSON document instead of lines\n"
"  --fields             per plane per address: the plane_check --fields line and the --expect line\n"
"  --case               the evaluated request as a reference-interpreter case block\n"
"  --help               this text\n"
"\n"
"With neither --dir nor --snapshot the directory is /var/lib/whisper-edge, read as the data model when\n"
"/etc/whisper-edge/policy.conf is installed, else as the legacy model when it holds snapshot.bin, else as\n"
"the data model; the lookup line says which (model-from).\n"
"\n"
"Environment, each named in a note when it chose a path this run looked at:\n"
"  WHISPER_EDGE_DIR     the directory read when neither --dir nor --snapshot is given\n"
"                       (default /var/lib/whisper-edge)\n"
"  WHISPER_EDGE_ETC     the directory holding the installed policy.conf (default /etc/whisper-edge);\n"
"                       looked at on every run, since the policy line reports installed=\n"
"\n"
"Exit status: 0 every address allowed (a log rule or a deny downgraded by mode log is allowed),\n"
"1 an address denied with enforcement, 2 a usage error, an unreadable or refused policy, a path the\n"
"chosen model or policy rests on that cannot be looked at, an address that is not one, or an internal\n"
"error. The old form exits 1 when the snapshot is fresh and the\n"
"threshold denies, whatever the mode.\n"
"\n"
"Stability of the output, within one `lookup format=N`:\n"
"  1. A kind and its positional fields never change meaning.\n"
"  2. Keys are only appended to a kind, never renamed, reordered or removed; every key is always\n"
"     present in JSON (null when it does not apply), so an appended key has a defined position.\n"
"  3. A consumer ignores kinds and keys it does not know.\n"
"  4. A change that breaks 1 or 2 raises `lookup format=N`.\n"
"  5. The verdict, cost, report and dependents lines are the reference interpreter's own lines.\n"
"  6. --probe-dir and --programs print their own line forms (data-directory, environment, plane and\n"
"     note; env, floor, program, text and refused) and no `lookup format=` line; their columns change\n"
"     only with the module gates that read them.\n",
        stdout);
}

/* --now: epoch milliseconds or RFC 3339, in 0..253402300799999 */
static int parse_now(const char *v, int64_t *ms, int *seconds_note)
{
    int64_t year;
    uint64_t x;

    *seconds_note = 0;
    if (is_digits(v, strlen(v)) && strlen(v) <= 19) {
        if (!int_token(v, &x) || x > (uint64_t)MAX_MS) {
            return 0;
        }
        *ms = (int64_t)x;
#ifndef WE_LOOKUP_TEST_NOW_SECONDS_NO_NOTE
        *seconds_note = x < UINT64_C(1000000000000);
#endif
        return 1;
    }
    if (!parse_rfc3339(v, strlen(v), ms, &year)) {
        return 0;
    }
#ifdef WE_LOOKUP_TEST_YEAR_NOT_INSTANT
    return year >= 1970 && year <= 9999;
#endif
#ifdef WE_LOOKUP_TEST_PRE_1970_ACCEPTED
    return *ms <= MAX_MS;
#endif
    return *ms >= 0 && *ms <= MAX_MS;
}

/* a context is printable ASCII without spaces */
static int context_ok(const char *c, unsigned *bad)
{
    for (; *c; c++) {
        unsigned char b = (unsigned char)*c;

        if (b < 0x21 || b > 0x7e) {
            *bad = b;
            return 0;
        }
    }
    return 1;
}

/* the old form's file: a `/`, or a .bin or .snap name, naming an existing regular file */
static int old_form_file(const char *arg, int *ambiguous, int *missing)
{
    struct stat st;
    size_t n = strlen(arg);
    int marked = strchr(arg, '/') != NULL || (n > 4 && strcmp(arg + n - 4, ".bin") == 0)
                 || (n > 5 && strcmp(arg + n - 5, ".snap") == 0);
    addr_t a;
    int addr_like, regular;

    *ambiguous = 0;
    *missing = 0;
    classify(arg, &a);
    addr_like = a.ok || (a.err != NULL && strncmp(a.err, "a prefix", 8) == 0);
    {
        int host = a.err != NULL && strstr(a.err, "is a hostname") != NULL;

        addr_free(&a);
#ifdef WE_LOOKUP_TEST_SLASH_MARKS_FILE
        (void)addr_like;
#else
        if (addr_like) {
            return 0;
        }
#endif
        regular = stat(arg, &st) == 0 && S_ISREG(st.st_mode);
        if (regular && marked) {
            return 1;
        }
        if (regular && host) {
            *ambiguous = 1;
        }
#ifndef WE_LOOKUP_TEST_MISSING_FILE_AS_ADDRESS
        if (marked && !regular) {
            *missing = 1;
        }
#endif
    }
    return 0;
}

static int arg_error(const char *what, const char *arg)
{
    err_rendered(what, arg, "");
    return 2;
}

int main(int argc, char **argv)
{
    const char **addrs;
    int naddr = 0, i, rc = 0, first_nonopt = -1;
    int64_t now = 0;
    int have_now = 0, now_note = 0, dir_given = 0, snap_given = 0, prestage_given = -1;
    const char *dir = NULL, *snap = NULL, *mode = NULL, *thr = NULL;
    const char *probe_dir = NULL, *programs = NULL;
    int uid_given = 0;
    line_t l;
    sb_t *o = &g_out;
    int end_opts = 0;

    addrs = (const char **)calloc((size_t)argc + 1, sizeof *addrs);
    if (addrs == NULL) {
        die_oom();
    }
    R.context = "http";
    g_bind_uid = (unsigned)getuid();
    for (i = 1; i < argc; i++) {
        const char *a = argv[i], *val = NULL;
        char opt[64];

        if (end_opts || a[0] != '-' || a[1] != '-' || a[2] == '\0') {
            if (strcmp(a, "--") == 0 && !end_opts) {
                end_opts = 1;
                continue;
            }
            if (first_nonopt < 0) {
                first_nonopt = naddr;
            }
            addrs[naddr++] = a;
            continue;
        }
        {
            const char *eq = strchr(a, '=');
            size_t n = eq ? (size_t)(eq - a) : strlen(a);

            if (n >= sizeof opt) {
                n = sizeof opt - 1;
            }
            memcpy(opt, a, n);
            opt[n] = '\0';
            if (eq) {
                val = eq + 1;
            }
        }
        {
            size_t k;
            int known = 0;

            for (k = 0; k < N_OPTS; k++) {
                if (strcmp(opt, OPTS[k]) == 0) {
                    known = 1;
                }
            }
            if (!known) {
                sb_t r = {0};

                render(&r, a, strlen(a));
                fprintf(stderr, "whisper-edge-lookup: unknown option %s; did you mean %s? (--help lists them)\n",
                        r.p, closest_option(opt));
                free(r.p);
                return 2;
            }
        }
        if (takes_value(opt)) {
            if (val == NULL) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "whisper-edge-lookup: %s needs a value (--help)\n", opt);
                    return 2;
                }
                val = argv[++i];
            }
        } else if (val != NULL) {
            fprintf(stderr, "whisper-edge-lookup: %s takes no value\n", opt);
            return 2;
        }
        if (strcmp(opt, "--help") == 0) {
            usage_help();
            return 0;
        } else if (strcmp(opt, "--probe-dir") == 0) {
            probe_dir = val;
        } else if (strcmp(opt, "--programs") == 0) {
            programs = val;
        } else if (strcmp(opt, "--uid") == 0) {
            /* a number or a user name: the workers' uid, the owner the bind accepts besides root */
            char *end = NULL;

            uid_given = 1;
            unsigned long u = strtoul(val, &end, 10);
            struct passwd *pw;

            if (val[0] != '\0' && val[0] != '-' && end != NULL && *end == '\0' && u <= 0xfffffffeul) {
                g_bind_uid = (unsigned)u;
            } else if ((pw = getpwnam(val)) != NULL) {
                g_bind_uid = (unsigned)pw->pw_uid;
            } else {
                fprintf(stderr, "whisper-edge-lookup: --uid %s is neither a uid nor a user on this host\n", val);
                return 2;
            }
        } else if (strcmp(opt, "--dir") == 0) {
            dir = val;
            dir_given = 1;
        } else if (strcmp(opt, "--snapshot") == 0) {
            snap = val;
            snap_given = 1;
        } else if (strcmp(opt, "--prestage") == 0) {
            if (strcmp(val, "absent") == 0) {
                prestage_given = 0;
            } else if (strcmp(val, "present") == 0) {
                prestage_given = 1;
            } else {
                return arg_error("--prestage takes absent or present, not ", val);
            }
        } else if (strcmp(opt, "--policy") == 0) {
            R.policy = val;
            R.policy_given = 1;
        } else if (strcmp(opt, "--threshold") == 0) {
            thr = val;
            R.threshold_given = 1;
        } else if (strcmp(opt, "--mode") == 0) {
            mode = val;
            R.mode_given = 1;
        } else if (strcmp(opt, "--context") == 0) {
            R.context = val;
        } else if (strcmp(opt, "--allow-inferred") == 0) {
            R.allow_inferred = 1;
        } else if (strcmp(opt, "--skipped-hop") == 0) {
            R.skipped_hop = 1;
        } else if (strcmp(opt, "--acme") == 0) {
            R.acme = 1;
        } else if (strcmp(opt, "--now") == 0) {
            if (!parse_now(val, &now, &now_note)) {
                return arg_error("--now takes epoch milliseconds (0..253402300799999) or an RFC 3339 date-time "
                                 "in that range, not ", val);
            }
            have_now = 1;
        } else if (strcmp(opt, "--json") == 0) {
            R.json = 1;
        } else if (strcmp(opt, "--fields") == 0) {
            R.fields = 1;
        } else if (strcmp(opt, "--case") == 0) {
            R.want_case = 1;
        }
    }
    /* the context, before anything is read or printed */
    {
        unsigned bad = 0;

#ifndef WE_LOOKUP_TEST_CONTEXT_BYTES_PASSED
        if (!context_ok(R.context, &bad)) {
            sb_t r = {0};

            render(&r, R.context, strlen(R.context));
            fprintf(stderr, "whisper-edge-lookup: context %s holds byte 0x%02X; a context is printable ASCII "
                            "without spaces\n", r.p, bad);
            free(r.p);
            return 2;
        }
#else
        (void)bad;
        (void)context_ok;
#endif
    }
    if (thr == NULL || strcmp(thr, "high") == 0) {
        R.threshold = WE_SEV_HIGH;
        R.threshold_name = "high";
    } else if (strcmp(thr, "low") == 0) {
        R.threshold = WE_SEV_LOW;
        R.threshold_name = "low";
    } else if (strcmp(thr, "medium") == 0) {
        R.threshold = WE_SEV_MEDIUM;
        R.threshold_name = "medium";
    } else if (strcmp(thr, "critical") == 0) {
        R.threshold = WE_SEV_CRITICAL;
        R.threshold_name = "critical";
    } else if (strcmp(thr, "off") == 0) {
#ifdef WE_LOOKUP_TEST_THRESHOLD_OFF_AS_HIGH
        R.threshold = WE_SEV_HIGH;
        R.threshold_name = "high";
#else
        R.threshold = 0;
        R.threshold_name = "off";
#endif
    } else {
        return arg_error("--threshold takes off, low, medium, high or critical, not ", thr);
    }
    if (mode == NULL || strcmp(mode, "log") == 0) {
        R.mode_deny = 0;
    } else if (strcmp(mode, "deny") == 0) {
        R.mode_deny = 1;
    } else {
        return arg_error("--mode takes log or deny, not ", mode);
    }
    if (dir_given && snap_given) {
        fputs("whisper-edge-lookup: --dir and --snapshot name two configurations; give one\n", stderr);
        return 2;
    }
    /* the old form: the first non-option argument, when it is a file and not an address */
    if (!dir_given && !snap_given && naddr > 0) {
        int amb = 0, missing = 0;

        if (old_form_file(addrs[0], &amb, &missing)) {
            snap = addrs[0];
            snap_given = 1;
            R.old_form = 1;
            memmove(addrs, addrs + 1, (size_t)naddr * sizeof *addrs);
            naddr--;
        } else if (missing) {
            err_rendered("", addrs[0], " names no regular file, and it is not an address; give an existing "
                                       "snapshot file, or --dir <dir> or --snapshot <file>");
            return 2;
        } else if (amb) {
            err_rendered("", addrs[0], " is both a file here and a host name; for the file, give "
                                       "--snapshot ./<name>; for the host, resolve it and give its addresses");
            return 2;
        }
    }
    (void)first_nonopt;
    if (uid_given && probe_dir == NULL && naddr == 0) {
        fputs("whisper-edge-lookup: --uid names the workers' uid for the planes' checks, and nothing here reads a "
              "plane (--help)\n", stderr);
        return 2;
    }
    if (probe_dir != NULL || programs != NULL) {
        /* the two inspection modes: no address, nothing decided */
        we_policy_env_t env = WE_POLICY_ENV_ALL;

        if (naddr != 0) {
            fputs("whisper-edge-lookup: --probe-dir and --programs take no address; give them alone (--help)\n", stderr);
            return 2;
        }
        if (probe_dir != NULL && (rc = lk_dir(probe_dir, &env)) != 0) {
            return rc;
        }
        return programs != NULL ? lk_policy(programs, &env) : 0;
    }
    if (naddr == 0 && (dir_given || R.policy_given)) {
        /* the inspection modes' old names: say where they went rather than only that an address is missing */
        fputs("whisper-edge-lookup: give at least one address (--help); to inspect without one, the data model is "
              "--probe-dir DIR and the compiled programs --programs FILE\n", stderr);
        return 2;
    }
    if (naddr == 0) {
        fputs("whisper-edge-lookup: give at least one address (--help)\n", stderr);
        return 2;
    }
    if (R.fields && R.json) {
        fputs("whisper-edge-lookup: --fields prints the reader's check lines, which have no JSON form; give "
              "--fields or --json, not both\n", stderr);
        return 2;
    }
    if (R.want_case && (R.json || R.fields)) {
        fputs("whisper-edge-lookup: --case prints a case block for the reference interpreter, which has no JSON "
              "form; give --case alone\n", stderr);
        return 2;
    }
    {
        const char *missing = NULL;

        if (attrs_bind(&missing) != 0) {
            fprintf(stderr, "whisper-edge-lookup: internal: the policy evaluator's attribute table does not hold "
                            "%s\n", missing);
            return 2;
        }
    }
    /* the model */
    if (dir_given) {
        R.model = MODEL_DATA;
        R.model_from = "option";
        R.dir = xstrdup(dir);
    } else if (snap_given) {
        R.model = MODEL_LEGACY;
        R.model_from = "option";
        R.snapshot = xstrdup(snap);
    } else {
        const char *env = getenv("WHISPER_EDGE_DIR");
        const char *etc = getenv("WHISPER_EDGE_ETC");
        char *conf, *sp;
        struct stat st;

        R.dir = xstrdup(env && env[0] ? env : "/var/lib/whisper-edge");
        conf = xprintf("%s/policy.conf", etc && etc[0] ? etc : "/etc/whisper-edge");
        sp = xprintf("%s/snapshot.bin", R.dir);
        /* here the installed file and the directory's contents pick the model, each looked at once and the
         * answer kept: a look that cannot answer stops the run, since any model chosen past it could be the
         * wrong one */
        int ist, ierr, sp_there = 0;

        ist = installed_look(conf, &ierr);
        if (ist < 0) {
            cannot_look("cannot look at the installed policy ", conf, ierr);
            free(conf);
            free(sp);
            return 2;
        }
        if (ist == 0) {
            sp_there = stat(sp, &st) == 0;
            if (!sp_there && look_class(errno) != LOOK_ABSENT) {
                int e = errno;

#ifdef WE_LOOKUP_TEST_MODEL_LOOK_IGNORES_ERRNO
                (void)e;
#else
                cannot_look("cannot look at ", sp, e);
                free(conf);
                free(sp);
                return 2;
#endif
            }
        }
        if (ist > 0) {
            R.model = MODEL_DATA;
            R.model_from = "policy-conf";
        } else if (sp_there) {
            int k, other = 0;

            for (k = 0; k < 8; k++) {
                char *pp = xprintf("%s/%s.bin", R.dir, we_plane_tier[k].name);

                other |= stat(pp, &st) == 0;
                free(pp);
            }
            R.model = MODEL_LEGACY;
            R.model_from = other ? "ambiguous" : "snapshot-only";
            R.snapshot = sp;
            sp = NULL;
#ifdef WE_LOOKUP_TEST_AMBIGUOUS_AS_DATA
            if (other) {
                R.model = MODEL_DATA;
                free(R.snapshot);
                R.snapshot = NULL;
                other = 0;
            }
#endif
            if (other) {
                note_add(&R.notes, xstrdup("the directory holds snapshot.bin and plane files: this reads "
                                           "snapshot.bin as whisper_edge_snapshot does; give --dir for the "
                                           "planes"));
            }
        } else {
            R.model = MODEL_DATA;
            R.model_from = "default";
        }
        free(conf);
        free(sp);
    }
    if (R.model == MODEL_DATA) {
        size_t dl = strlen(R.dir);

        if (prestage_given == 0) {
            fputs("whisper-edge-lookup: the data model always has the pre-stage; --prestage absent applies to "
                  "--snapshot\n", stderr);
            return 2;
        }
        R.prestage = 1;
#ifdef WE_LOOKUP_TEST_LONG_DIR_ACCEPTED
        (void)dl;
#else
        if (dl > DIR_MAX) {
            fprintf(stderr, "whisper-edge-lookup: the directory is %zu bytes; the module builds plane paths of at "
                            "most 1,024 bytes, so a directory of at most 1,002 bytes\n", dl);
            return 2;
        }
#endif
    } else {
        char *slash;

        R.prestage = prestage_given == 1;
        R.dir = xstrdup(R.snapshot);
        slash = strrchr(R.dir, '/');
        if (slash == NULL) {
            free(R.dir);
            R.dir = xstrdup(".");
        } else if (slash == R.dir) {
            R.dir[1] = '\0';
        } else {
            *slash = '\0';
        }
        if (R.policy_given) {
            fputs("whisper-edge-lookup: --policy applies to the data model; the legacy model is the threshold "
                  "sugar (--threshold, --mode)\n", stderr);
            return 2;
        }
    }
    {
        const char *etc = getenv("WHISPER_EDGE_ETC");
        char *conf = xprintf("%s/policy.conf", etc && etc[0] ? etc : "/etc/whisper-edge");
        int ierr = 0;

        R.installed = installed_look(conf, &ierr);
        if (R.installed < 0 && !R.policy_given && R.model == MODEL_DATA) {
            /* the installed file is the policy this run evaluates: no answer is honest without it */
            cannot_look("cannot look at the installed policy ", conf, ierr);
            free(conf);
            return 2;
        }
#ifdef WE_LOOKUP_TEST_INSTALLED_UNKNOWN_EXITS
        if (R.installed < 0) {
            cannot_look("cannot look at the installed policy ", conf, ierr);
            free(conf);
            return 2;
        }
#endif
        if (R.installed < 0) {
            /* only the installed= field rests on it: say so, and print the result the run does decide; the
             * uid clause only where another uid could see it (EACCES, EPERM), as the directory note reads */
            note_add(&R.notes, xprintf(
#ifdef WE_LOOKUP_TEST_INSTALLED_NOTE_UID_ALWAYS
                                       1
#else
                                       look_class(ierr) == LOOK_DENIED
#endif
                                       ? "the installed policy %s cannot be looked at by this uid (%s): installed is "
                                         "unknown, and nothing this run decides reads it"
                                       : "the installed policy %s cannot be looked at (%s): installed is unknown, "
                                         "and nothing this run decides reads it", conf, strerror(ierr)));
        }
        /* an override never changes the answer silently: the output names it and the path it chose */
        if (etc && etc[0]) {
            note_add(&R.notes, xprintf("WHISPER_EDGE_ETC is set: the installed policy is looked for at %s, not at "
                                       "/etc/whisper-edge/policy.conf", conf));
        }
        if (R.installed > 0 && !R.policy_given && R.model == MODEL_DATA) {
            note_add(&R.notes, xprintf("the policy evaluated is the installed %s", conf));
        }
        free(conf);
    }
    if (!dir_given && !snap_given && getenv("WHISPER_EDGE_DIR") && getenv("WHISPER_EDGE_DIR")[0]) {
        note_add(&R.notes, xprintf("WHISPER_EDGE_DIR is set: the directory read is %s, not /var/lib/whisper-edge",
                                   getenv("WHISPER_EDGE_DIR")));
    }
    if (R.policy_given && (R.threshold_given || R.mode_given)) {
        note_add(&R.notes, xstrdup("--threshold and --mode describe the threshold sugar; with --policy they change "
                                   "nothing, and the policy's own lines decide"));
    }
    if (dir_given) {
        struct stat st;

        /* only where the look answers: a directory this uid cannot reach gets the open's own note */
#ifdef WE_LOOKUP_TEST_DIR_NOTE_ON_ANY_ERRNO
        if (stat(R.dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
#else
        if ((stat(R.dir, &st) != 0 && look_class(errno) == LOOK_ABSENT)
            || (stat(R.dir, &st) == 0 && !S_ISDIR(st.st_mode))) {
#endif
            note_add(&R.notes, xstrdup("the --dir directory does not exist or is not a directory, so every plane "
                                       "reads absent"));
        }
    }
    g_json = R.json;
    /* one clock sample for the whole run */
    R.now_ms = have_now ? now : clock_now_ms();
    if (now_note && now != 0) {
        sb_t d = {0};

        fmt_instant(&d, now);
        note_add(&R.notes, xprintf("--now %" PRId64 " is %s; if that was epoch seconds, give %" PRId64 "000", now,
                                   d.p, now));
        free(d.p);
    }
    {
        struct stat st;

        R.dir_writable = stat(R.dir, &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    }
    /* the module's order: the probe, the policy built against it, the load, the probe again */
    if (R.model == MODEL_DATA) {
        memset(&R.env, 0, sizeof R.env);
        we_policy_env_probe(R.dir, &R.env);
    }
    if ((rc = build_policy()) != 0) {
        return rc;
    }
    if (R.model == MODEL_DATA) {
        if ((rc = load_data_model()) != 0) {
            return rc;
        }
    } else {
        load_legacy_model();
        if (!R.prestage && (R.acme || R.skipped_hop)) {
            note_add(&R.notes, xstrdup("this module generation has no pre-stage; --acme and --skipped-hop change "
                                       "nothing"));
        }
    }
    read_manifests();
    for (i = 0; i < 8; i++) {
        plane_t *p = &R.planes[i];

#ifdef WE_LOOKUP_TEST_HASH_WITHOUT_MANIFEST
        if (p->armed && (p->state == PS_FRESH || p->state == PS_STALE)) {
#else
        if (R.any_read && p->armed && (p->state == PS_FRESH || p->state == PS_STALE)) {
#endif
            hash_plane(p);
        }
        bind_plane(p);
    }
    /* notes the planes and manifests carry */
    for (i = 0; i < 2; i++) {
        uint32_t k;

        for (k = 0; k < R.man[i].nfnotes; k++) {
            note_add(&R.notes, xstrdup(R.man[i].fnotes[k]));
        }
    }
    for (i = 0; i < 8; i++) {
        plane_t *p = &R.planes[i];

        if (p->armed && !p->bound && p->why_bind[0] && (p->state == PS_FRESH || p->state == PS_STALE)) {
            note_add(&R.notes, xprintf("%s: %s", p->name, bind_note(p->why_bind)));
        }
        if (p->refused_kind == RF_PERMISSION) {
            note_add(&R.notes, xprintf("%s: whether the module arms these rules depends on the user it loads "
                                       "as; re-run as that user", p->name));
        }
        if (p->bound && p->entry != NULL) {
            const manifest_t *from = NULL;

            if (withheld_any(i, &from) != NULL) {
                note_add(&R.notes, xprintf("%s: %s also lists it as withheld; it is bound through planes[], "
                                           "as the refresh reads it", p->name, from->file));
            }
        }
        if (p->state == PS_FRESH) {
            int k;

            for (k = 0; k < 2; k++) {
                if (R.man[k].state == M_READ && R.man[k].builder != NULL
                    && strcmp(R.man[k].builder, "disarm") == 0 && own_tier(i) == k) {
                    sb_t v = {0}, path = {0};

                    if (p->map.valid_until_ms == 0) {
                        sb_puts(&v, "none");
                    } else if (p->map.valid_until_ms > (uint64_t)MAX_MS) {
                        sb_printf(&v, "ms:%" PRIu64, p->map.valid_until_ms);
                    } else {
                        fmt_instant(&v, (int64_t)p->map.valid_until_ms);
                    }
#ifndef WE_LOOKUP_TEST_DISARM_PATH_UNQUOTED
                    sb_putc(&path, '"');
#endif
                    sb_puts(&path, p->path);
#ifndef WE_LOOKUP_TEST_DISARM_PATH_UNQUOTED
                    sb_putc(&path, '"');
#endif
#ifdef WE_LOOKUP_TEST_DISARM_NO_NOTE
                    free(v.p);
                    free(path.p);
                    continue;
#endif
                    note_add(&R.notes, xprintf("%s: the feed is disarmed, and this plane is still fresh on disk "
                                               "until %s at %s; remove it (the refresh sets the immutable flag, "
                                               "so chattr -i it first) and reload the server", p->name, v.p,
                                               path.p));
                    free(v.p);
                    free(path.p);
                }
            }
        }
    }
    if (R.planes[7].state != PS_ABSENT) {
        note_add(&R.notes, xstrdup("high-water not read: revocation is not checked by this tool"));
    }
    if (strcmp(R.policy_source, "builtin-default") == 0 && R.policy_given) {
#ifndef WE_LOOKUP_TEST_ENFORCED_WITHOUT_POLICY
        note_add(&R.notes, xstrdup("the decision below is the shipped default's, chosen with --policy default, not "
                                   "your server's configuration"));
#endif
    } else if (R.model == MODEL_DATA && R.sugar) {
        note_add(&R.notes, xstrdup("no policy.conf is installed and no --policy was given: this is what a module "
                                   "with no policy lines runs, the threshold sugar"));
    }

    /* ---- print: the header part ---- */
    if (R.fields) {
        goto addresses;
    }
    if (R.want_case) {
        emit_case_program(o);
        goto addresses;
    }
    emit_lookup(&l);
    if (g_json) {
        int first = 1;

        sb_putc(o, '{');
        print_members(o, &l, &first);
        sb_puts(o, ",\"manifests\":[");
    } else {
        print_line(o, &l);
    }
    L_free(&l);
    {
        int k, firstm = 1;

        for (k = 0; k < 2; k++) {
            if (R.man[k].state == M_ABSENT) {
                continue;
            }
            emit_manifest(&l, &R.man[k]);
            if (g_json) {
                if (!firstm) {
                    sb_putc(o, ',');
                }
                print_obj(o, &l);
            } else {
                print_line(o, &l);
            }
            firstm = 0;
            L_free(&l);
        }
    }
    if (g_json) {
        sb_puts(o, "],\"planes\":[");
    }
    for (i = 0; i < 8; i++) {
        plane_t *p = &R.planes[i];

        emit_plane(&l, p);
        if (g_json) {
            int first = 1;
            uint32_t s;

            if (i) {
                sb_putc(o, ',');
            }
            sb_putc(o, '{');
            print_members(o, &l, &first);
            sb_puts(o, ",\"sourceList\":[");
            for (s = 0; p->bound && p->entry && s < p->entry->nsrc; s++) {
                line_t sl;

                emit_source(&sl, p->name, s + 1, &p->entry->src[s]);
                if (s) {
                    sb_putc(o, ',');
                }
                print_obj(o, &sl);
                L_free(&sl);
            }
            sb_puts(o, "]}");
        } else {
            print_line(o, &l);
        }
        L_free(&l);
    }
    if (!g_json) {
        for (i = 0; i < 8; i++) {
            plane_t *p = &R.planes[i];
            uint32_t s;

            for (s = 0; p->bound && p->entry && s < p->entry->nsrc; s++) {
                emit_source(&l, p->name, s + 1, &p->entry->src[s]);
                print_line(o, &l);
                L_free(&l);
            }
        }
    }
    if (g_json) {
        sb_puts(o, "],\"withheld\":[");
    }
    {
        int firstw = 1, k, order;

        for (i = 0; i < 8; i++) {
            for (order = 0; order < 2; order++) {
                const wentry_t *w;

                k = order == 0 ? own_tier(i) : !own_tier(i);
                if (R.man[k].state != M_READ || (w = withheld_entry(&R.man[k], we_plane_tier[i].name)) == NULL) {
                    continue;
                }
                emit_withheld(&l, we_plane_tier[i].name, w, k);
                if (g_json) {
                    if (!firstw) {
                        sb_putc(o, ',');
                    }
                    print_obj(o, &l);
                } else {
                    print_line(o, &l);
                }
                firstw = 0;
                L_free(&l);
            }
        }
    }
    if (g_json) {
        uint32_t k;

        sb_putc(o, ']');
        emit_policy(o);
        sb_puts(o, ",\"notes\":[");
        for (k = 0; k < R.notes.n; k++) {
            if (k) {
                sb_putc(o, ',');
            }
            json_string(o, R.notes.v[k]);
        }
        sb_puts(o, "],\"addresses\":[");
    } else {
        uint32_t k;

        emit_policy(o);
        for (k = 0; k < R.notes.n; k++) {
            L_init(&l, "note");
            L_pos(&l, "text", 's', R.notes.v[k]);
            print_line(o, &l);
            L_free(&l);
        }
    }
    out_flush();
addresses:
    rc = 0;
    for (i = 0; i < naddr; i++) {
        int r;

#ifdef WE_LOOKUP_TEST_MANIFEST_PER_ADDRESS
        {
            manifest_t keep0 = R.man[0], keep1 = R.man[1];

            memset(&R.man, 0, sizeof R.man);
            read_manifests();
            manifest_free(&R.man[0]);
            manifest_free(&R.man[1]);
            R.man[0] = keep0;
            R.man[1] = keep1;
        }
#endif
#ifdef WE_LOOKUP_TEST_REHASH_DIRECT
        if (R.planes[0].armed) {
            we_sha256_ctx c;
            uint8_t d[32];

            we_sha256_init(&c);
            we_sha256_update(&c, R.planes[0].map.base, R.planes[0].map.len);
            we_sha256_final(&c, d);
        }
#endif
#ifdef WE_LOOKUP_TEST_RELOAD_SECOND_PUBLISH
        if (R.planes[0].armed && R.planes[0].path != NULL) {
            (void)we_handle_publish_plane(&g_h[0], R.planes[0].path, (uint64_t)R.now_ms, NULL);
        }
#endif
        r = emit_address(o, addrs[i], i == 0, i + 1);
        if (r > rc) {
            rc = r;
        }
        out_flush();
#ifdef WE_TRACE
        if (g_k3_impossible != 0) {
            fprintf(stderr, "whisper-edge-lookup: internal: K3 state (1,1) reached %lu times\n", g_k3_impossible);
            g_internal = 1;
        }
#endif
        if (g_internal) {
            fputs("whisper-edge-lookup: internal error: the remaining addresses are not judged\n", stderr);
            break;
        }
    }
    if (g_json && !R.fields) {
        sb_puts(o, "]}\n");
        out_flush();
    }
#ifdef WE_LOOKUP_TOOL
    if (R.fields || R.want_case) {
        /* these modes print what an address's planes hold, or its request; they judge nothing */
        fprintf(stderr, "whisper-edge-lookup: %d address%s: not judged (%s), %lu refused; hashed-bytes=%" PRIu64 "\n",
                naddr, naddr == 1 ? "" : "es", R.fields ? "--fields" : "--case", n_refused, we_lookup_hashed_bytes);
    } else {
        fprintf(stderr, "whisper-edge-lookup: %d address%s: %lu allowed, %lu denied, %lu refused; hashed-bytes=%" PRIu64
                        "\n", naddr, naddr == 1 ? "" : "es", n_allowed, n_denied, n_refused, we_lookup_hashed_bytes);
    }
#endif
#ifndef WE_LOOKUP_TEST_NO_OUTPUT_CHECK
    if (fflush(stdout) != 0 || ferror(stdout) || g_write_failed || fclose(stdout) != 0) {
        fprintf(stderr, "whisper-edge-lookup: cannot write output: %s\n", strerror(errno ? errno : EIO));
        return 2;
    }
#endif
    if (g_internal && rc < 2) {
        rc = 2;
    }
    for (i = 0; i < 8; i++) {
        /* each handle's current mapping: the core retires replaced ones and never frees the last */
        we_map_t *cur = g_h[i].current;

        we_handle_retire(&g_h[i], UINT64_MAX);
        if (cur != NULL) {
            we_map_close(cur);
            free(cur);
        }
        free(R.planes[i].path);
        free(R.planes[i].refused_detail);
        free(R.planes[i].entry_generation);
    }
    we_policy_build_free(R.build);
    for (i = 0; i < (int)R.ndirs; i++) {
        free(R.dir_ctx[i]);
    }
    free(R.dirs);
    free(R.dir_ctx);
    free(g_policy_text);
    free(R.floor_text);
    free(R.ctx_text);
    free(R.reports.p);
    manifest_free(&R.man[0]);
    manifest_free(&R.man[1]);
    notes_free(&R.notes);
    free(R.dir);
    free(R.snapshot);
    free(addrs);
    free(g_out.p);
    return rc;
}

#endif /* WE_LOOKUP_READER_ONLY */
