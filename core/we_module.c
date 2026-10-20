/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_module.c - the configuration-time and thread-side half of what the three server modules share.
 * Nothing here is on the request path; we_module.h says what is.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1         /* dladdr, realpath, MAP_ANONYMOUS, statfs: the Linux calls a module thread makes */
#endif

#include "we_module.h"
#include "we_sha256.h"
#include "we_procid.h"
#include "we_country_table.h"   /* the known-code bitmap a stand-in points at */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#ifdef WE_MOD_DEBUG
#include <arpa/inet.h>                          /* the debug tail range, parsed at bind */
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/fs.h>                    /* FS_IOC_GETFLAGS, FS_IMMUTABLE_FL: the immutable flag the status reads */
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/* the first eight digest bytes in byte order, lowercase hex: `sha256sum | cut -c1-16` */
void we_digest16(const uint8_t dg[32], char out[17])
{
    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    uint32_t i;

    for (i = 0u; i < 8u; i++) {
        out[2u * i] = hex[dg[i] >> 4];
        out[2u * i + 1u] = hex[dg[i] & 15u];
    }
    out[16] = '\0';
}

/* ==================================================================================================
 * The trusted-proxy table, at configuration time
 * ================================================================================================ */

/* the inclusive range of a canonical prefix, as two 64-bit words per bound */
static void v6_bounds(const uint8_t b[16], uint32_t len, uint64_t lo[2], uint64_t hi[2])
{
    uint32_t k;

    lo[0] = lo[1] = 0u;
    for (k = 0u; k < 8u; k++) {
        lo[0] = lo[0] << 8 | b[k];
        lo[1] = lo[1] << 8 | b[8u + k];
    }
    if (len == 0u) {
        lo[0] = lo[1] = 0u;
        hi[0] = hi[1] = ~(uint64_t)0;
    } else if (len <= 64u) {
        uint64_t m = len == 64u ? ~(uint64_t)0 : ~(~(uint64_t)0 >> len);

        lo[0] &= m;
        lo[1] = 0u;
        hi[0] = lo[0] | ~m;
        hi[1] = ~(uint64_t)0;
    } else {
        uint64_t m = len == 128u ? ~(uint64_t)0 : ~(~(uint64_t)0 >> (len - 64u));

        lo[1] &= m;
        hi[0] = lo[0];
        hi[1] = lo[1] | ~m;
    }
}

static int cmp_iv4(const void *a, const void *b)
{
    const we_mod_iv4_t *x = a, *y = b;

    return x->lo < y->lo ? -1 : x->lo > y->lo ? 1 : 0;
}

static int cmp_iv6(const void *a, const void *b)
{
    const we_mod_iv6_t *x = a, *y = b;

    if (x->lo_hi != y->lo_hi) {
        return x->lo_hi < y->lo_hi ? -1 : 1;
    }
    return x->lo_lo < y->lo_lo ? -1 : x->lo_lo > y->lo_lo ? 1 : 0;
}

/* a + 1 over the two words; 1 when it wrapped past the top */
static inline int v6_succ(uint64_t *h, uint64_t *l)
{
    if (++*l != 0u) {
        return 0;
    }
    return ++*h == 0u;
}

int we_mod_trust_build(const char *const *items, size_t n, we_mod_trust_t *out, we_mod_trust_report_t *rep,
                       char *err, size_t errn)
{
    we_mod_iv4_t *v4 = NULL;
    we_mod_iv6_t *v6 = NULL;
    size_t i, n4 = 0u, n6 = 0u, w;

    memset(out, 0, sizeof *out);
    if (rep != NULL) {
        memset(rep, 0, sizeof *rep);
    }
    if (n > 0u) {
        v4 = (we_mod_iv4_t *)calloc(n, sizeof *v4);
        v6 = (we_mod_iv6_t *)calloc(n, sizeof *v6);
        if (v4 == NULL || v6 == NULL) {
            free(v4);
            free(v6);
            snprintf(err, errn, "out of memory");
            return -1;
        }
    }
    for (i = 0u; i < n; i++) {
        const char *s = items[i], *slash = strchr(s, '/');
        size_t al = slash != NULL ? (size_t)(slash - s) : strlen(s);
        uint8_t b[16];
        unsigned long len;
        char *end = NULL;
        int fam;

        if (strcmp(s, "unix:") == 0) {
            out->unix_ok = 1u;
            continue;
        }
        if (we_mod_parse4((const uint8_t *)s, al, b) == 0) {
            fam = 4;
        } else if (we_mod_parse6((const uint8_t *)s, al, b) == 0) {
            fam = 6;
        } else {
            snprintf(err, errn, "\"%s\" is not an address or a prefix (a CIDR such as 10.0.0.0/8, or unix:)", s);
            goto bad;
        }
        len = fam == 4 ? 32u : 128u;
        if (slash != NULL) {
            if (slash[1] < '0' || slash[1] > '9') {
                snprintf(err, errn, "\"%s\": the prefix length is not a number", s);
                goto bad;
            }
            len = strtoul(slash + 1, &end, 10);
            if (*end != '\0' || len > (fam == 4 ? 32u : 128u)) {
                snprintf(err, errn, "\"%s\": the prefix length is out of range", s);
                goto bad;
            }
        }
        if (fam == 6) {
            /* inside ::ffff:0:0/96 with a length of 96 or more: the IPv4 prefix it names */
            static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

            if (len >= 96u && memcmp(b, mapped, 12) == 0) {
                memmove(b, b + 12, 4);
                fam = 4;
                len -= 96u;
            } else if (rep != NULL && len < 96u) {
                uint64_t lo[2], hi[2];

                v6_bounds(b, (uint32_t)len, lo, hi);
                /* a family-6 prefix that covers ::ffff:0:0/96 cannot match an IPv4 peer after canonicalising */
                if (we_mod_iv6_le(lo[0], lo[1], 0u, 0x0000ffff00000000ull)
                        && we_mod_iv6_le(0u, 0x0000ffffffffffffull, hi[0], hi[1])) {
                    rep->covers_mapped++;
                }
            }
        }
        if (fam == 4) {
            uint32_t a = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
            uint32_t m = len == 0u ? 0u : ~(uint32_t)0 << (32u - len);

            v4[n4].lo = a & m;
            v4[n4].hi = (a & m) | ~m;
            n4++;
            if (rep != NULL && len < 16u) {
                rep->broad++;
            }
        } else {
            uint64_t lo[2], hi[2];

            v6_bounds(b, (uint32_t)len, lo, hi);
            v6[n6].lo_hi = lo[0];
            v6[n6].lo_lo = lo[1];
            v6[n6].hi_hi = hi[0];
            v6[n6].hi_lo = hi[1];
            n6++;
            if (rep != NULL && len < 32u) {
                rep->broad++;
            }
        }
    }
    if (rep != NULL) {
        rep->configured4 = (uint32_t)n4;
        rep->configured6 = (uint32_t)n6;
    }
#ifndef WE_MOD_TEST_UNMERGED_TRUST
    /* sorted by start, then merged: duplicates, nested and ADJACENT intervals become one. A list of one
     * needs no sort and a list of none has no array (v4 and v6 stay NULL when nothing was configured),
     * and qsort's array is declared nonnull, so nothing is sorted below two entries. */
    if (n4 > 1u) {
        qsort(v4, n4, sizeof *v4, cmp_iv4);
    }
    for (i = 0u, w = 0u; i < n4; i++) {
        if (w > 0u && (v4[w - 1u].hi == 0xffffffffu || v4[i].lo <= v4[w - 1u].hi + 1u)) {
            if (v4[i].hi > v4[w - 1u].hi) {
                v4[w - 1u].hi = v4[i].hi;
            }
        } else {
            v4[w++] = v4[i];
        }
    }
    n4 = w;
    if (n6 > 1u) {
        qsort(v6, n6, sizeof *v6, cmp_iv6);
    }
    for (i = 0u, w = 0u; i < n6; i++) {
        if (w > 0u) {
            uint64_t sh = v6[w - 1u].hi_hi, sl = v6[w - 1u].hi_lo;
            int top = v6_succ(&sh, &sl);

            if (top || we_mod_iv6_le(v6[i].lo_hi, v6[i].lo_lo, sh, sl)) {
                if (!we_mod_iv6_le(v6[i].hi_hi, v6[i].hi_lo, v6[w - 1u].hi_hi, v6[w - 1u].hi_lo)) {
                    v6[w - 1u].hi_hi = v6[i].hi_hi;
                    v6[w - 1u].hi_lo = v6[i].hi_lo;
                }
                continue;
            }
        }
        v6[w++] = v6[i];
    }
    n6 = w;
#else
    /* the control: the list as configured, sorted but never merged, so a nested prefix hides its parent */
    if (n4 > 1u) {
        qsort(v4, n4, sizeof *v4, cmp_iv4);
    }
    if (n6 > 1u) {
        qsort(v6, n6, sizeof *v6, cmp_iv6);
    }
    (void)w;
#endif
    out->v4 = v4;
    out->v6 = v6;
    out->n4 = (uint32_t)n4;
    out->n6 = (uint32_t)n6;
    return 0;
bad:
    free(v4);
    free(v6);
    return -1;
}

void we_mod_trust_free(we_mod_trust_t *t)
{
    free((void *)(uintptr_t)t->v4);
    free((void *)(uintptr_t)t->v6);
    memset(t, 0, sizeof *t);
}

/* ==================================================================================================
 * The arena: every distinct block once per configuration, interned on its digest, sealed read-only
 * ================================================================================================ */


#define WE_MOD_CHUNK (256u * 1024u)       /* one chunk's size; a block larger gets a chunk of its own */

typedef struct we_mod_chunk {
    struct we_mod_chunk *next;
    uint8_t             *base;
    size_t               len, used;
    int                  sealed;
} we_mod_chunk_t;

typedef struct {
    uint8_t             dg[32];
    const we_program_t *copy;
} we_mod_intern_t;

struct we_mod_arena {
    we_mod_chunk_t  *chunks;
    we_mod_intern_t *tab;
    uint32_t         n, cap;
    size_t           page;
};

static void *mod_chunk_take(we_mod_arena_t *a, size_t len, size_t align)
{
    we_mod_chunk_t *c = a->chunks;
    size_t at;

    if (c == NULL || c->sealed || ((c->used + align - 1u) & ~(align - 1u)) + len > c->len) {
        size_t want = len > WE_MOD_CHUNK ? len : WE_MOD_CHUNK;
        we_mod_chunk_t *nc = (we_mod_chunk_t *)calloc(1, sizeof *nc);

        if (nc == NULL) {
            return NULL;
        }
        nc->len = (want + a->page - 1u) & ~(a->page - 1u);
        nc->base = (uint8_t *)mmap(NULL, nc->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (nc->base == MAP_FAILED) {
            free(nc);
            return NULL;
        }
        nc->next = a->chunks;
        a->chunks = nc;
        c = nc;
    }
    at = (c->used + align - 1u) & ~(align - 1u);
    c->used = at + len;
    return c->base + at;
}

we_mod_arena_t *we_mod_arena_new(void)
{
    we_mod_arena_t *a = (we_mod_arena_t *)calloc(1, sizeof *a);

    if (a != NULL) {
        a->page = (size_t)sysconf(_SC_PAGESIZE);
    }
    return a;
}

/*
 * The block's copy in the arena: an identical block placed before is shared (found by the SHA-256 of the
 * whole block, confirmed by memcmp), any other is copied in and verified THERE, where it will be read.
 * NULL when the copy does not verify or the arena cannot grow.
 */
const we_program_t *we_mod_arena_place(we_mod_arena_t *a, const we_program_t *p)
{
    uint8_t dg[32];
    size_t len = we_program_size(p);
    uint32_t i;
    we_program_t *c;
    we_policy_error_t e;

    if (a == NULL || p == NULL || len == 0u) {
        return NULL;
    }
    we_sha256(p, len, dg);
    for (i = 0u; i < a->n; i++) {
        if (memcmp(a->tab[i].dg, dg, 32) == 0 && we_program_size(a->tab[i].copy) == len
                && memcmp(a->tab[i].copy, p, len) == 0) {
            return a->tab[i].copy;
        }
    }
    if (a->n == a->cap) {
        uint32_t nc = a->cap != 0u ? 2u * a->cap : 16u;
        we_mod_intern_t *t = (we_mod_intern_t *)realloc(a->tab, nc * sizeof *t);

        if (t == NULL) {
            return NULL;
        }
        a->tab = t;
        a->cap = nc;
    }
    c = (we_program_t *)mod_chunk_take(a, len, 64u);
    if (c == NULL) {
        return NULL;
    }
    memcpy(c, p, len);
    memset(&e, 0, sizeof e);
    if (we_program_verify(c, len, &e) != 0) {
        return NULL;
    }
    memcpy(a->tab[a->n].dg, dg, 32);
    a->tab[a->n].copy = c;
    a->n++;
    return c;
}

/* configuration-lifetime bytes beside the blocks (the hold-harmless view, the contexts, the cold strings) */
void *we_mod_arena_alloc(we_mod_arena_t *a, size_t len, size_t align)
{
    void *p = a != NULL ? mod_chunk_take(a, len == 0u ? 1u : len, align < 8u ? 8u : align) : NULL;

    if (p != NULL) {
        memset(p, 0, len);
    }
    return p;
}

/* every chunk read-only; 0, or -1 when one cannot be */
int we_mod_arena_seal(we_mod_arena_t *a)
{
    we_mod_chunk_t *c;

    for (c = a != NULL ? a->chunks : NULL; c != NULL; c = c->next) {
        if (!c->sealed) {
            if (mprotect(c->base, c->len, PROT_READ) != 0) {
                return -1;
            }
            c->sealed = 1;
        }
    }
    return 0;
}

size_t we_mod_arena_pages(const we_mod_arena_t *a)
{
    const we_mod_chunk_t *c;
    size_t n = 0u;

    for (c = a != NULL ? a->chunks : NULL; c != NULL; c = c->next) {
        n += c->len / a->page;
    }
    return n;
}

uint32_t we_mod_arena_blocks(const we_mod_arena_t *a)
{
    return a != NULL ? a->n : 0u;
}

const we_program_t *we_mod_arena_block(const we_mod_arena_t *a, uint32_t i)
{
    return a != NULL && i < a->n ? a->tab[i].copy : NULL;
}

void we_mod_arena_free(we_mod_arena_t *a)
{
    we_mod_chunk_t *c, *n;

    if (a == NULL) {
        return;
    }
    for (c = a->chunks; c != NULL; c = n) {
        n = c->next;
        munmap(c->base, c->len);
        free(c);
    }
    free(a->tab);
    free(a);
}

/* ==================================================================================================
 * The configuration: the compiled build, placed in the arena, as the request path reads it
 * ================================================================================================ */

/* a context's own lines: a policy or a threshold directive written in exactly that context */
static int mod_owns_lines(const we_policy_source_t *src, const char *path)
{
    size_t i;

    for (i = 0u; i < src->n; i++) {
        if ((src->d[i].kind == WE_DIR_POLICY || src->d[i].kind == WE_DIR_THRESHOLD)
                && strcmp(src->d[i].context, path) == 0) {
            return 1;
        }
    }
    return 0;
}

/* the nearest enclosing ordinal path ("http/s3/l7" -> "http/s3"), in place; 0 at the top */
static int mod_parent(char *path)
{
    char *s = strrchr(path, '/');

    if (s == NULL) {
        return 0;
    }
    *s = '\0';
    return 1;
}

static const char *mod_strdup(we_mod_arena_t *a, const char *s)
{
    size_t n = strlen(s) + 1u;
    char *c = (char *)we_mod_arena_alloc(a, n, 1u);

    if (c != NULL) {
        memcpy(c, s, n);
    }
    return c;
}

/* `\\`, `\"` and every byte outside 0x20..0x7e as \xHH, in double quotes: one line whatever it holds */
size_t we_mod_escape(const char *s, char *out, size_t n)
{
    static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    size_t o = 0u;

    if (n < 3u) {
        return 0u;
    }
    out[o++] = '"';
    for (; *s != '\0' && o + 6u < n; s++) {
        unsigned char c = (unsigned char)*s;

#ifdef WE_MOD_TEST_RAW_NAMES
        out[o++] = (char)c;                  /* the control: a name written raw */
        continue;
#endif
        if (c == '\\' || c == '"') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20u || c > 0x7eu) {
            out[o++] = '\\';
            out[o++] = 'x';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15u];
        } else {
            out[o++] = (char)c;
        }
    }
    out[o++] = '"';
    out[o] = '\0';
    return o;
}

static void mod_digest16(const we_program_t *p, char out[17])
{
    uint8_t dg[32];

    we_sha256(p, we_program_size(p), dg);
    we_digest16(dg, out);
}

/* the rule ids and canonical texts of a block, one string each, in the arena */
static int mod_rule_strings(we_mod_arena_t *a, const we_program_t *p, const char *kind, const char *const **ids,
                            const char *const **texts)
{
    const char **id, **tx;
    char *text, *line, *save = NULL;
    uint32_t r, n = p != NULL ? p->rule_count : 0u;
    size_t tl;

    *ids = *texts = NULL;
    if (n == 0u) {
        return 0;
    }
    id = (const char **)we_mod_arena_alloc(a, n * sizeof *id, 8u);
    tx = (const char **)we_mod_arena_alloc(a, n * sizeof *tx, 8u);
    tl = (size_t)p->text_len + 1u;
    text = (char *)malloc(tl);
    if (id == NULL || tx == NULL || text == NULL || we_program_print(p, text, tl) < 0) {
        free(text);
        return -1;
    }
    for (r = 0u, line = strtok_r(text, "\n", &save); r < n; r++, line = strtok_r(NULL, "\n", &save)) {
        char b[16];

        snprintf(b, sizeof b, "%s:%u", kind, r + 1u);
        id[r] = mod_strdup(a, b);
        tx[r] = mod_strdup(a, line != NULL ? line : "-");
        if (id[r] == NULL || tx[r] == NULL) {
            free(text);
            return -1;
        }
    }
    free(text);
    *ids = id;
    *texts = tx;
    return 0;
}

/*
 * Build the request path's configuration from one compiled configuration: every block placed in the
 * arena, the floor's hold-harmless view on its own page, one we_mod_ctx_t per context the module names
 * with its counter offset (a context with no lines of its own counts into the context it inherits from),
 * and the cold strings the variables render. 0, or -1 with `msg` saying why; the stride cap is refused
 * here, naming the five contexts that contribute most.
 */
int we_mod_config_build(uint32_t abi, we_mod_arena_t *a, const we_policy_build_t *b, const we_policy_source_t *src,
                        const we_mod_ctx_spec_t *spec, size_t n, uint16_t http_status, we_mod_cfg_t *cfg,
                        we_mod_ctx_t **ctxs, uint32_t *stride, char *msg, size_t msgn)
{
    const we_program_t *floor;
    we_hh_view_t *hh;
    we_mod_cfg_cold_t *cc;
    we_mod_ctx_t *x;
    uint32_t *own_off;
    size_t i;
    uint32_t off;
    char d16[17], fl[24];

    if (abi != WE_MODULE_ABI_VERSION) {
        snprintf(msg, msgn, "the module was built against we_module.h ABI %u, and this we_module.c is ABI %u: rebuild "
                 "the module from one tree", (unsigned)abi, (unsigned)WE_MODULE_ABI_VERSION);
        return WE_MOD_ERR_ABI;                   /* before anything is written */
    }
    memset(cfg, 0, sizeof *cfg);
    floor = we_mod_arena_place(a, we_policy_floor(b));
    hh = (we_hh_view_t *)(void *)mod_chunk_take(a, sizeof *hh, a->page);   /* a page of its own */
    cc = (we_mod_cfg_cold_t *)we_mod_arena_alloc(a, sizeof *cc, 8u);
    x = (we_mod_ctx_t *)we_mod_arena_alloc(a, (n > 0u ? n : 1u) * sizeof *x, 64u);
    own_off = (uint32_t *)calloc(n > 0u ? n : 1u, sizeof *own_off);
    if (floor == NULL || hh == NULL || cc == NULL || x == NULL || own_off == NULL) {
        free(own_off);
        snprintf(msg, msgn, "the configuration's blocks cannot be placed (out of memory, or a block does not verify)");
        return WE_ERR_MMAP;
    }
    memset(hh, 0, sizeof *hh);
    if (we_program_place(floor, hh) != 0) {
        free(own_off);
        snprintf(msg, msgn, "the floor's hold-harmless view cannot be placed");
        return WE_ERR_MMAP;
    }
    if (floor->rule_count > 0u) {
        mod_digest16(floor, d16);
        snprintf(fl, sizeof fl, "floor:%s", d16);
    } else {
        snprintf(fl, sizeof fl, "floor:-");
    }
    {
        char t[64];

        snprintf(t, sizeof t, "%s ctx:-", fl);
        cc->program_none = mod_strdup(a, t);
    }
    if (mod_rule_strings(a, floor, "floor", &cc->rule_id, &cc->rule_text) != 0) {
        free(own_off);
        snprintf(msg, msgn, "the floor's rule texts cannot be printed");
        return WE_ERR_MMAP;
    }
    cc->rule_count = floor->rule_count;
    for (i = 0u; i < 8u; i++) {
        cc->plane_name[i] = we_mod_plane_word((uint32_t)i);
    }
    cfg->floor = floor;
    cfg->floor_conf = we_policy_conf(b, "http");
    cfg->floor_status = http_status;
    cfg->hh = hh;
    cfg->cold = cc;
    cfg->arena = a;                          /* every distinct program once: the transition lines' set */
    /* the counters: the pre-stage line, the floor, then every context with lines of its own */
    off = WE_MOD_CTR_FLOOR + floor->rule_count;
    for (i = 0u; i < n; i++) {
        const we_program_t *p = we_policy_program(b, spec[i].path);

        own_off[i] = UINT32_MAX;
        if (p != NULL && mod_owns_lines(src, spec[i].path)) {
            own_off[i] = off;
            off += p->rule_count;
        }
    }
    *stride = (off + 7u) & ~7u;
#ifndef WE_MOD_TEST_CAP_OFF
    if (off > WE_MOD_STRIDE_MAX) {
#else
    if (off > WE_MOD_STRIDE_MAX && 0) {         /* the control: the cap lifted, every configuration admitted */
#endif
        size_t o = (size_t)snprintf(msg, msgn, "%u counted rule slots, over the %u a configuration may hold; the largest contexts:",
                                    off, WE_MOD_STRIDE_MAX);
        uint32_t k;

        for (k = 0u; k < 5u && o < msgn; k++) {
            size_t best = n;
            uint32_t bc = 0u;

            for (i = 0u; i < n; i++) {
                const we_program_t *p = we_policy_program(b, spec[i].path);

                if (own_off[i] != UINT32_MAX && p != NULL && p->rule_count > bc) {
                    best = i;
                    bc = p->rule_count;
                }
            }
            if (best == n) {
                break;
            }
            o += (size_t)snprintf(msg + o, msgn - o, " %s (%u)", spec[best].path, bc);
            own_off[best] = UINT32_MAX;
        }
        free(own_off);
        return WE_MOD_ERR_CAP;
    }
    for (i = 0u; i < n; i++) {
        const we_program_t *p = we_policy_program(b, spec[i].path);
        we_mod_ctx_cold_t *xc = (we_mod_ctx_cold_t *)we_mod_arena_alloc(a, sizeof *xc, 8u);
        char path[1024], t[64];
        size_t owner = i;

        if (xc == NULL) {
            free(own_off);
            snprintf(msg, msgn, "out of memory");
            return WE_ERR_MMAP;
        }
        /*
         * The owner of the counters: this context, or the nearest enclosing one with lines, which must be
         * in the spec. A context running a program whose lines live in a context the spec omits has no
         * counters to count into: the stride never counted that program's rules, so the configuration is
         * refused, naming both, rather than given an offset past the shard or another context's counters.
         */
        snprintf(path, sizeof path, "%s", spec[i].path);
        while (p != NULL && own_off[owner] == UINT32_MAX && mod_parent(path)) {
            size_t k;

            if (!mod_owns_lines(src, path)) {
                continue;
            }
            for (k = 0u; k < n && strcmp(spec[k].path, path) != 0; k++) {
            }
#ifdef WE_MOD_TEST_SPEC_UNCHECKED
            if (k == n) {
                continue;                     /* the control: the omitted owner passed over, as before */
            }
#endif
            if (k == n || own_off[k] == UINT32_MAX) {
                free(own_off);
                snprintf(msg, msgn, "context %s runs the lines of %s, which the spec does not list; list every "
                         "context that carries lines", spec[i].path, path);
                return WE_MOD_ERR_SPEC;
            }
            owner = k;
        }
#ifndef WE_MOD_TEST_SPEC_UNCHECKED
        if (p != NULL && own_off[owner] == UINT32_MAX) {
#else
        if (0) {                              /* the control: the floor's slots taken, as before */
#endif
            free(own_off);
            snprintf(msg, msgn, "context %s runs a program whose lines no listed context carries", spec[i].path);
            return WE_MOD_ERR_SPEC;
        }
        x[i].prog = p != NULL ? we_mod_arena_place(a, p) : NULL;
        x[i].conf = we_policy_conf(b, spec[i].path);
        x[i].deny_status = spec[i].deny_status != 0u ? spec[i].deny_status : http_status;
        x[i].ctr_off = own_off[owner] != UINT32_MAX ? own_off[owner] : WE_MOD_CTR_FLOOR + floor->rule_count;
        x[i].rule_count = p != NULL ? p->rule_count : 0u;
        x[i].export_mask = spec[i].export_mask;
        x[i].gen_mask = spec[i].gen_mask;
        x[i].cold = xc;
        xc->name = mod_strdup(a, spec[i].name != NULL ? spec[i].name : spec[i].path);
        xc->path = mod_strdup(a, spec[i].path);
        xc->own = own_off[i] != UINT32_MAX;
        if (x[i].prog != NULL) {
            mod_digest16(x[i].prog, d16);
            snprintf(t, sizeof t, "%s ctx:%s", fl, d16);
        } else {
            snprintf(t, sizeof t, "%s ctx:-", fl);
        }
        xc->program_ctx = mod_strdup(a, t);
        snprintf(t, sizeof t, "%s ctx:-", fl);
        xc->program_floor = mod_strdup(a, t);
        xc->rule_count = x[i].rule_count;
        if ((p != NULL && x[i].prog == NULL) || mod_rule_strings(a, x[i].prog, "ctx", &xc->rule_id, &xc->rule_text) != 0) {
            free(own_off);
            snprintf(msg, msgn, "context %s: its block cannot be placed or printed", spec[i].path);
            return -1;
        }
    }
    free(own_off);
    *ctxs = x;
    return 0;
}

/* ==================================================================================================
 * Binding: the descriptors, the lexical walk, the trust checks, the header peek
 * ================================================================================================ */


/* every descriptor the module opens is close-on-exec, so no exec'd child (a CGI, a piped logger, a new
 * nginx master after a binary upgrade) inherits a plane or a directory */
int we_openat_cloexec(int dirfd, const char *name, int flags, unsigned mode)
{
    return openat(dirfd, name, flags | O_CLOEXEC, (mode_t)mode);
}

/* a directory a plane may sit under: owned by root or the trusted uid, writable by neither group nor world */
static int mod_dir_trusted(const struct stat *st, unsigned uid)
{
    return S_ISDIR(st->st_mode) && (st->st_uid == 0u || st->st_uid == uid) && (st->st_mode & (S_IWGRP | S_IWOTH)) == 0u;
}

#define MOD_LINK_HOPS 40u

/*
 * The configured path walked LEXICALLY from `/`, every component opened with O_NOFOLLOW | O_DIRECTORY
 * relative to its parent's descriptor, every directory held to the trust rule with no sticky exception.
 * A symbolic link component is followed only when it is owned by a trusted owner (its directory already
 * passed). The data directory's descriptor is returned: every later open, peek and stat is relative to
 * it, so nothing done to a path component after binding changes which directory is read. -1 with `why`.
 */
int we_mod_dir_open(const char *path, unsigned uid, int *out, char *why, size_t whyn)
{
    char work[PATH_MAX], comp[NAME_MAX + 1u];
    const char *p;
    int fd, hops = 0;
    struct stat st;

    if (path == NULL || path[0] != '/') {
        snprintf(why, whyn, "the data directory must be an absolute path");
        return -1;
    }
    if (strlen(path) >= sizeof work) {
        snprintf(why, whyn, "the data directory's path is too long");
        return -1;
    }
    snprintf(work, sizeof work, "%s", path);
#ifdef WE_MOD_TEST_RESOLVED_CHAIN_ONLY
    {
        /* the control: the resolved chain judged alone, so a link a tenant owns in a directory it can write is
         * followed to wherever it points */
        char real[PATH_MAX];

        if (realpath(path, real) == NULL) {
            snprintf(why, whyn, "the data directory does not resolve");
            return -1;
        }
        snprintf(work, sizeof work, "%s", real);
    }
#endif
restart:
    fd = we_openat_cloexec(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0 || fstat(fd, &st) != 0 || !mod_dir_trusted(&st, uid)) {
        if (fd >= 0) {
            close(fd);
        }
        snprintf(why, whyn, "/ is not owned by root or uid %u, or is writable by others", (unsigned)uid);
        return -1;
    }
    p = work;
    for (;;) {
        size_t n;
        int next;

        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        n = strcspn(p, "/");
        if (n > NAME_MAX) {
            close(fd);
            snprintf(why, whyn, "a component of the data directory's path is too long");
            return -1;
        }
        memcpy(comp, p, n);
        comp[n] = '\0';
        p += n;
        if (strcmp(comp, ".") == 0) {
            continue;
        }
        if (strcmp(comp, "..") == 0) {
            close(fd);
            snprintf(why, whyn, "the data directory's path holds \"..\": name the directory itself");
            return -1;
        }
        next = we_openat_cloexec(fd, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        if (next < 0 && (errno == ELOOP || errno == ENOTDIR)) {
            /* a link: followed only when a trusted owner made it, in a directory that already passed */
            char target[PATH_MAX], rest[PATH_MAX];
            ssize_t tl;

            if (fstatat(fd, comp, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISLNK(st.st_mode)) {
                close(fd);
                snprintf(why, whyn, "\"%s\" in the data directory's path is not a directory", comp);
                return -1;
            }
            if (++hops > (int)MOD_LINK_HOPS) {
                close(fd);
                snprintf(why, whyn, "the data directory's path follows more than %u links; point the directive at "
                         "the directory itself", (unsigned)MOD_LINK_HOPS);
                return -1;
            }
            if (st.st_uid != 0u && st.st_uid != uid) {
                close(fd);
                snprintf(why, whyn, "the link \"%s\" in the data directory's path is owned by uid %u, which is "
                         "not trusted (root or uid %u); point the directive at the directory itself",
                         comp, (unsigned)st.st_uid, (unsigned)uid);
                return -1;
            }
            tl = readlinkat(fd, comp, target, sizeof target - 1u);
            if (tl <= 0) {
                close(fd);
                snprintf(why, whyn, "the link \"%s\" cannot be read", comp);
                return -1;
            }
            target[tl] = '\0';
            if (target[0] == '/') {
                if ((size_t)tl + strlen(p) + 1u >= sizeof rest) {
                    close(fd);
                    snprintf(why, whyn, "the data directory's path is too long once its links are followed");
                    return -1;
                }
                memcpy(rest, target, (size_t)tl);
                memcpy(rest + tl, p, strlen(p) + 1u);
                memcpy(work, rest, strlen(rest) + 1u);
                close(fd);
                goto restart;
            }
            /* relative: the target's components, then the rest, from this directory */
            if ((size_t)tl + strlen(p) + 2u >= sizeof rest) {
                close(fd);
                snprintf(why, whyn, "the data directory's path is too long once its links are followed");
                return -1;
            }
            memcpy(rest, target, (size_t)tl);
            memcpy(rest + tl, p, strlen(p) + 1u);
            memcpy(work, rest, strlen(rest) + 1u);
            p = work;
            continue;
        }
        close(fd);
        if (next < 0) {
            snprintf(why, whyn, "\"%s\" in the data directory's path cannot be opened: %s", comp, strerror(errno));
            return -1;
        }
        fd = next;
        if (fstat(fd, &st) != 0 || !mod_dir_trusted(&st, uid)) {
            close(fd);
            /* short, the fix first after the fact: the plane's reason carries it whole in 256 bytes */
            snprintf(why, whyn, "directory \"%s\" is owned by uid %u or writable by others: chown it to root "
                     "(or uid %u) and chmod go-w it", comp, (unsigned)st.st_uid, (unsigned)uid);
            return -1;
        }
    }
    *out = fd;
    return 0;
}

/*
 * The trust rule's one exception, for a CONFIGURATION file's chain: a root-owned sticky directory (/tmp above a key
 * file, as sshd allows it) may be an ancestor, because the file is found by an explicit path the operator
 * wrote and the sticky bit keeps another user from renaming or unlinking what root or the owner put there.
 * Never for a plane's directory: that walk is we_mod_dir_open's, which knows no exception.
 */
static int mod_dir_root_sticky(const struct stat *st)
{
    return S_ISDIR(st->st_mode) && st->st_uid == 0u && (st->st_mode & S_ISVTX) != 0u;
}

/*
 * The RESOLVED chain of a CONFIGURATION file: every directory of realpath(path), from `/`, owned by root
 * or `uid` and writable by neither group nor world, or root's sticky directory (the trust rule for the files
 * that hold http-level directives, the legacy snapshot's warning, and a counters directory an installer
 * placed). The callers are the modules' configuration checks; a plane's directory is we_mod_dir_open's.
 */
int we_mod_chain_check(const char *path, unsigned uid, char *why, size_t whyn)
{
    char real[PATH_MAX], pre[PATH_MAX];
    size_t i, n;
    struct stat st;

    if (realpath(path, real) == NULL) {
        snprintf(why, whyn, "the path cannot be resolved: %s", strerror(errno));
        return -1;
    }
    n = strlen(real);
    for (i = 0u; i <= n; i++) {
        if (i == n || (real[i] == '/' && i > 0u)) {
            memcpy(pre, real, i == 0u ? 1u : i);
            pre[i == 0u ? 1u : i] = '\0';
            if (stat(pre, &st) != 0) {
                snprintf(why, whyn, "\"%s\" cannot be read: %s", pre, strerror(errno));
                return -1;
            }
            if (S_ISDIR(st.st_mode) && !mod_dir_trusted(&st, uid) && !mod_dir_root_sticky(&st)) {
                snprintf(why, whyn, "\"%s\" is owned by uid %u or writable by others", pre, (unsigned)st.st_uid);
                return -1;
            }
        }
    }
    if (stat("/", &st) != 0 || !mod_dir_trusted(&st, uid)) {
        snprintf(why, whyn, "/ is not owned by root or uid %u, or is writable by others", (unsigned)uid);
        return -1;
    }
    return 0;
}

/* the network and FUSE file systems a plane may not sit on, by statfs magic */
const char *we_mod_netfs_name(long t)
{
#ifdef WE_MOD_TEST_ALLOW_NETFS
    (void)t;
    return NULL;                             /* the control: no file system is a network one */
#endif
    switch ((unsigned long)t & 0xffffffffu) {
    case 0x6969u:     return "NFS";
    case 0x517Bu:     return "SMB";
    case 0xFF534D42u: return "CIFS";
    case 0xFE534D42u: return "SMB2";
    case 0x65735546u: return "FUSE";
    case 0x00C36400u: return "Ceph";
    case 0x01021997u: return "9P";
    case 0x5346414Fu: return "AFS";
    default:          return NULL;
    }
}

/*
 * The 192-byte header of the plane file `name` in `dirfd`, without digesting anything: what the
 * configuration test prints, what binds the environment, what a verifier refuses on before any pread of
 * the body. 0, or -1 with `why`.
 */
int we_plane_peek(int dirfd, const char *name, uint32_t plane, we_mod_peek_t *out, char *why, size_t whyn)
{
    int fd = we_openat_cloexec(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    struct stat st;
    we_header_t h;
    ssize_t got;

    memset(out, 0, sizeof *out);
    if (fd < 0) {
        out->absent = errno == ENOENT;
        out->err = errno;
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
    out->country_table_version = out->schema ? h.schema.country_table_version : 0u;
    /* the plane id: a schema file must carry the plane it is bound to, whatever it is called; a
     * pre-schema format-1 file is accepted for reputation alone */
    if (out->schema ? out->plane_id != plane : !(plane == WE_PLANE_REPUTATION && h.format == WE_FORMAT_1)) {
        snprintf(why, whyn, out->schema ? "its header names plane %u, and it is bound as plane %u"
                                        : "a pre-schema file can only be bound as reputation, and it is bound as plane %u",
                 out->schema ? out->plane_id : plane, plane);
        return -1;
    }
    return 0;
}

/*
 * The trust checks of a plane bound through whisper_edge_data, in order, each a named refusal with its
 * fix: opened without following a link and fstat'ed; a regular file; a size between the header and
 * 0x7fffffff; mode exactly 0444 and a trusted owner; not on a network or FUSE file system. The resolved
 * chain and the plane id are the caller's (we_mod_chain_check, we_plane_peek). The descriptor is
 * returned open (close-on-exec) on success, so the caller verifies and maps exactly this inode.
 */
int we_mod_plane_trust(int dirfd, const char *name, unsigned uid, int legacy, int *fdout, struct stat *st,
                       char *why, size_t whyn)
{
    int fd = we_openat_cloexec(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    struct statfs fs;
    const char *net;

    *fdout = -1;
    if (fd < 0) {
        snprintf(why, whyn, errno == ELOOP ? "a symbolic link: install the plane file itself, not a link to it"
                                           : "cannot be opened: %s", strerror(errno));
        return -1;
    }
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        snprintf(why, whyn, "not a regular file");
        return -1;
    }
    if (st->st_size < (off_t)sizeof(we_header_t) || st->st_size > (off_t)0x7fffffff) {
        close(fd);
        snprintf(why, whyn, "%lld bytes: a plane is between 192 bytes and 2 GiB", (long long)st->st_size);
        return -1;
    }
    if (legacy) {
        if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
            close(fd);
            snprintf(why, whyn, "writable by group or world: chmod go-w the file");
            return -1;
        }
    } else if ((st->st_mode & 07777u) != 0444u) {
        close(fd);
        snprintf(why, whyn, "mode %04o: a mapped plane must be exactly 0444, so no writer but root can change "
                 "its bytes under the mapping; chmod 0444 the file", (unsigned)(st->st_mode & 07777u));
        return -1;
    } else if (st->st_uid != 0u && st->st_uid != uid) {
        close(fd);
        snprintf(why, whyn, "owned by uid %u: a mapped plane must be owned by root or uid %u; chown root the file",
                 (unsigned)st->st_uid, (unsigned)uid);
        return -1;
    }
    if (fstatfs(fd, &fs) == 0 && (net = we_mod_netfs_name((long)fs.f_type)) != NULL) {
        close(fd);
        snprintf(why, whyn, "on %s, a network file system: rules on it are inert; keep the data directory on a "
                 "local file system", net);
        return -1;
    }
    *fdout = fd;
    return 0;
}

/* ==================================================================================================
 * The writers: the process's identity, the temp-file discipline, and the three file formats
 * ================================================================================================ */

/* the identity that names this process's files: we_procid.h's, one computation for every writer */
int we_mod_procid(we_mod_procid_t *id)
{
    return we_proc_id(id);
}

/*
 * Write `data` to `name` in `dirfd` so that no planted name is ever followed and no reader sees half a
 * file: a temp `.<pid>-<starttime>-<kind>.tmp` created with O_EXCL | O_NOFOLLOW (so a link or a file
 * planted at the temp name refuses the create, never redirects it), written whole, then renamed over the
 * name. A writer running as root writes only into a directory that passes the trust rule (root-owned, not
 * group- or world-writable), because the counters directory is writable by every server user. 0, or -1
 * with `why` (and nothing written).
 */
int we_mod_write_file(int dirfd, const we_mod_procid_t *id, const char *kind, const char *name, const char *data,
                      size_t len, char *why, size_t whyn)
{
    char tmp[96];
    int fd;
    size_t done = 0u;
    struct stat st;

#ifdef WE_MOD_TEST_EUID0
    const uid_t euid = 0u;                       /* the gate's seam: the root refusal, run without root */
#else
    const uid_t euid = geteuid();
#endif

    if (euid == 0u && (fstat(dirfd, &st) != 0 || st.st_uid != 0u || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u)) {
        snprintf(why, whyn, "the counters directory is not root-owned and closed to group and world, and this "
                 "process runs as root: nothing is written there");
        return WE_ERR_PERMISSIONS;
    }
    fd = we_proc_tmp_open(dirfd, id, kind, tmp);
    if (fd < 0) {
        snprintf(why, whyn, "cannot create %s: %s", tmp, strerror(errno));
        return WE_ERR_OPEN;
    }
    while (done < len) {
        ssize_t w = write(fd, data + done, len - done);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            snprintf(why, whyn, "cannot write %s: %s", tmp, w < 0 ? strerror(errno) : "short write");
            close(fd);
            unlinkat(dirfd, tmp, 0);
            return WE_ERR_OPEN;
        }
        done += (size_t)w;
    }
    if (close(fd) != 0) {
        snprintf(why, whyn, "cannot close %s: %s", tmp, strerror(errno));
        unlinkat(dirfd, tmp, 0);
        return WE_ERR_OPEN;
    }
#ifdef WE_MOD_TEST_PAUSE_BEFORE_RENAME
    we_mod_test_pause("rename");
#endif
    if (renameat(dirfd, tmp, dirfd, name) != 0) {
        snprintf(why, whyn, "cannot rename %s into place: %s", tmp, strerror(errno));
        unlinkat(dirfd, tmp, 0);
        return WE_ERR_OPEN;
    }
    return 0;
}

#if defined(WE_MOD_TEST_PAUSE_TICK) || defined(WE_MOD_TEST_PAUSE_BEFORE_RENAME) || defined(WE_MOD_TEST_PAUSE_AFTER_FSTAT)
/*
 * The gates' pause, in control builds only. With WE_MOD_PAUSE_DIR naming a directory, a call at
 * `where` finds <dir>/<where>: while that file exists the caller is held, polling every 5 ms, and says so
 * by <dir>/held.<where>.<pid>, removed when it goes on. The gate creates the hold, waits for the marker,
 * does what the pause is for, and removes the hold. No directory, or no hold file: the call returns at
 * once. Points: `tick` (the module thread's whole tick), `loading` (a candidate with no map, its -l
 * word posted and the loop woken, before its verification), `rename` and `after-fstat`.
 */
void we_mod_test_pause(const char *where)
{
    const char *dir = getenv("WE_MOD_PAUSE_DIR");
    char hold[PATH_MAX], held[PATH_MAX];
    struct timespec ts = { 0, 5000000 };
    int fd;

    if (dir == NULL || dir[0] == '\0') {
        return;
    }
    snprintf(hold, sizeof hold, "%s/%s", dir, where);
    if (access(hold, F_OK) != 0) {
        return;
    }
    snprintf(held, sizeof held, "%s/held.%s.%ld", dir, where, (long)getpid());
    fd = open(held, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd >= 0) {
        close(fd);
    }
#ifndef WE_MOD_TEST_PAUSE_NO_HOLD
    while (access(hold, F_OK) == 0) {
        nanosleep(&ts, NULL);
    }
#else
    nanosleep(&ts, NULL);                        /* the control: the marker appears, and nothing is held */
#endif
    unlink(held);
}
#endif

/* a growing text buffer over caller memory: writes stop at the end and the overflow is reported */
static void mod_put(we_mod_text_t *t, const char *fmt, ...)
{
    va_list ap;
    int w;

    if (t->len >= t->cap) {
        t->over = 1;
        return;
    }
    va_start(ap, fmt);
    w = vsnprintf(t->buf + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= t->cap - t->len) {
        t->over = 1;
        t->len = t->cap;
        return;
    }
    t->len += (size_t)w;
}

static void mod_put_escaped(we_mod_text_t *t, const char *s)
{
    char e[4 * 2048 + 3];

    we_mod_escape(s, e, sizeof e);
    mod_put(t, "%s", e);
}

/*
 * The rule-counter file, version 2: the writer's key, its tick, the configuration's digest, then ONLY the
 * non-zero counts, each `r <digest> <rule> <count>` against the block that owns the rule, and the
 * pre-stage's named lines. `sum` is the configuration's counter array summed over the shards.
 */
void we_mod_render_rules(we_mod_text_t *t, const we_mod_procid_t *id, const we_mod_ctrmap_t *map, const uint64_t *sum,
                         uint64_t started_ms, uint64_t tick, uint64_t snapshot_ms, uint64_t written_ms, const char *config16)
{
    static const char *const pre[8] = {
        "hold-harmless", "acme", "tenant", "stale-tenant", "no-address",
        "floor-header-missing", "floor-header-unparsed", "floor-header-capped"
    };
    uint32_t i, r;

    /* the `pid` line as the core's counter record writes it, so a record copied out of its file still
     * says whose it is, and the summary reads the modules' records and the core's alike */
    mod_put(t, "whisper-edge-rule-counters 2\npidns %llu starttime %llu\nstarted %llu\ntick %llu\nsnapshot %llu\n"
            "written %llu\npid %llu\nconfig %s\n", (unsigned long long)id->pidns, (unsigned long long)id->starttime,
            (unsigned long long)started_ms, (unsigned long long)tick, (unsigned long long)snapshot_ms,
            (unsigned long long)written_ms, (unsigned long long)id->pid, config16);
    for (i = 0u; i < map->n; i++) {
        for (r = 0u; r < map->e[i].rule_count; r++) {
            uint64_t c = sum[map->e[i].ctr_off + r];

            if (c != 0u) {
                mod_put(t, "r %s %u %llu\n", map->e[i].digest16, r + 1u, (unsigned long long)c);
            }
        }
    }
    for (i = 0u; i < 8u; i++) {
        if (sum[i] != 0u) {
            mod_put(t, "pre %s %llu\n", pre[i], (unsigned long long)sum[i]);
        }
    }
}

/*
 * The configuration file, `conf-<16 hex>.status`: every line that does not change per tick, written once
 * per configuration by the first worker that finds it absent. Its name is the first 16 hex digits of the
 * SHA-256 of its own bytes (we_mod_conf_name), which the summary recomputes.
 */
void we_mod_render_conf(we_mod_text_t *t, const we_mod_cfg_t *c, const we_mod_ctx_t *x, size_t n,
                        const char *const plane_path[8], const char *const unreadable[8],
                        const char *const refused[8])
{
    size_t i;
    uint32_t p, r;

    mod_put(t, "whisper-edge-config 2\n");
    for (p = 0u; p < 8u; p++) {
        if (plane_path[p] == NULL) {
            continue;
        }
        mod_put(t, "plane %s path ", we_mod_plane_word(p));
        mod_put_escaped(t, plane_path[p]);
        if (unreadable != NULL && unreadable[p] != NULL) {
            mod_put(t, " unreadable ");
            mod_put_escaped(t, unreadable[p]);
        }
#ifndef WE_MOD_TEST_REFUSED_UNSAID
        if (refused != NULL && refused[p] != NULL) {
            mod_put(t, " refused ");             /* a plane refused at configuration: its reason and fix */
            mod_put_escaped(t, refused[p]);
        }
#else
        (void)refused;                           /* the control: the refusal said nowhere */
#endif
        mod_put(t, "\n");
    }
    if (c->floor != NULL && c->floor->rule_count > 0u) {
        uint8_t dg[32];
        char d16[17];

        we_sha256(c->floor, we_program_size(c->floor), dg);
        we_digest16(dg, d16);
        mod_put(t, "program %s context \"floor\" path \"http\" mode %u rules %u\n", d16, we_conf_mode(&c->floor_conf),
                c->floor->rule_count);
        for (r = 0u; r < c->floor->rule_count && c->cold != NULL; r++) {
            mod_put(t, "text %s %u ", d16, r + 1u);
            mod_put_escaped(t, c->cold->rule_text[r]);
            mod_put(t, "\n");
        }
    }
    for (i = 0u; i < n; i++) {
        uint8_t dg[32];
        char d16[17];

        if (x[i].prog == NULL || x[i].cold == NULL) {
            continue;
        }
        we_sha256(x[i].prog, we_program_size(x[i].prog), dg);
        we_digest16(dg, d16);
        mod_put(t, "program %s context ", d16);
        mod_put_escaped(t, x[i].cold->name);
        mod_put(t, " path ");
        mod_put_escaped(t, x[i].cold->path);
        mod_put(t, " mode %u rules %u\n", we_conf_mode(&x[i].conf), x[i].rule_count);
        if (!x[i].cold->own) {
            continue;                           /* an inheriting context's texts are its owner's */
        }
        for (r = 0u; r < x[i].rule_count; r++) {
            mod_put(t, "text %s %u ", d16, r + 1u);
            mod_put_escaped(t, x[i].cold->rule_text[r]);
            mod_put(t, "\n");
        }
    }
}

/* the configuration file's name: `conf-` and the first 16 hex digits of the SHA-256 of its bytes */
void we_mod_conf_name(const we_mod_text_t *t, char out[29])
{
    uint8_t dg[32];
    char d16[17];

    we_sha256(t->buf, t->len, dg);
    we_digest16(dg, d16);
    snprintf(out, 29, "conf-%s.status", d16);
}

/* the process line and its flags, then one line per plane, the transitions and the fault delta */
#ifdef WE_MOD_DEBUG
/*
 * The debug build's tail count, for the truncate row (M3): every request whose judged address lies in the
 * range WE_MOD_DEBUG_TAIL names (`<first>-<last>`, one family, read at bind) is counted BEFORE the decision
 * reads any plane, so a request whose lookup then dies on a truncated mapping (signal 7) is counted all the
 * same. The counter lives in one shared anonymous page the supervisor maps at its first bind, so every
 * worker it forks, and every one those replace, adds to the same total: the count of the process lineage.
 * Each live worker's status file carries it as `debug tail-requests <n>`.
 */
static uint64_t *mod_tail_ctr;
static uint8_t   mod_tail_lo[16], mod_tail_hi[16], mod_tail_family;

static void mod_debug_tail_setup(void)
{
    const char *v = getenv("WE_MOD_DEBUG_TAIL");
    char a[64], b[64];
    const char *dash;
    int fam;

    if (v == NULL || (dash = strchr(v, '-')) == NULL || (size_t)(dash - v) >= sizeof a || strlen(dash + 1) >= sizeof b) {
        return;
    }
    memcpy(a, v, (size_t)(dash - v));
    a[dash - v] = '\0';
    snprintf(b, sizeof b, "%s", dash + 1);
    fam = strchr(a, ':') != NULL ? 6 : 4;
    memset(mod_tail_lo, 0, sizeof mod_tail_lo);
    memset(mod_tail_hi, 0, sizeof mod_tail_hi);
    if (inet_pton(fam == 6 ? AF_INET6 : AF_INET, a, mod_tail_lo) != 1
            || inet_pton(fam == 6 ? AF_INET6 : AF_INET, b, mod_tail_hi) != 1) {
        return;
    }
    if (mod_tail_ctr == NULL) {
#ifndef WE_MOD_TEST_TAIL_PRIVATE
        void *pg = mmap(NULL, 4096u, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
#else
        void *pg = mmap(NULL, 4096u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   /* the control */
#endif

        if (pg == MAP_FAILED) {
            return;
        }
        mod_tail_ctr = (uint64_t *)pg;
    }
    mod_tail_family = (uint8_t)fam;
}

int we_mod_debug_tail_on(void)
{
    return mod_tail_ctr != NULL && mod_tail_family != 0u;
}

uint64_t we_mod_debug_tail_count(void)
{
    return mod_tail_ctr != NULL ? __atomic_load_n(mod_tail_ctr, __ATOMIC_RELAXED) : 0u;
}

void we_mod_debug_tail_note(const we_request_t *r)
{
    if (mod_tail_family == 0u || r->floor.family != mod_tail_family || mod_tail_ctr == NULL) {
        return;
    }
    if (memcmp(r->floor.b, mod_tail_lo, 16) >= 0 && memcmp(r->floor.b, mod_tail_hi, 16) <= 0) {
        __atomic_fetch_add(mod_tail_ctr, 1u, __ATOMIC_RELAXED);
    }
}
#endif

#ifdef WE_MOD_DEBUG
static uint64_t g_mod_digests, g_mod_digests_start;   /* the debug build's digest counts, defined below */
#endif
void we_mod_render_status(we_mod_text_t *t, const we_mod_procid_t *id, const we_mod_status_t *s)
{
    uint32_t p, k;

    mod_put(t, "whisper-edge-status 2\nprocess ");
    mod_put_escaped(t, s->server);
    mod_put(t, " pid %llu boot %s pidns %llu starttime %llu started %llu written %llu interval %llu jitter %llu "
            "handoff %llu tick %llu config %s", (unsigned long long)id->pid, id->boot, (unsigned long long)id->pidns,
            (unsigned long long)id->starttime, (unsigned long long)s->started_ms, (unsigned long long)s->written_ms,
            (unsigned long long)s->interval_ms, (unsigned long long)s->jitter_ms, (unsigned long long)s->handoff_ms,
            (unsigned long long)s->tick, s->config16);
    if (s->no_thread) { mod_put(t, " no-thread"); }
    if (s->late_build) { mod_put(t, " late-build"); }
    if (s->client_ip_from_header) { mod_put(t, " client-ip-from-header"); }
    if (s->single_process_stale) { mod_put(t, " single-process-stale"); }
    mod_put(t, " shards %u retired %llu retire-lost %llu failure-evicted %llu log-dropped %llu ticks-before-start %llu "
            "verify-held %llu verify-peak %llu\n", s->shards, (unsigned long long)s->retired,
            (unsigned long long)s->retire_lost, (unsigned long long)s->failure_evicted,
            (unsigned long long)s->log_dropped, (unsigned long long)s->ticks_before_start,
            (unsigned long long)s->verify_held, (unsigned long long)s->verify_peak);
#ifdef WE_MOD_DEBUG
    t->len = t->len > 0u && !t->over ? t->len - 1u : t->len;   /* the process line's newline, reopened */
    mod_put(t, " digests %llu start-digests %llu\n",
            (unsigned long long)__atomic_load_n(&g_mod_digests, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_mod_digests_start, __ATOMIC_RELAXED));
#endif
    for (p = 0u; p < 8u; p++) {
        const we_mod_plane_status_t *pl = &s->plane[p];

#ifndef WE_MOD_TEST_REFUSED_UNSAID
        if (!pl->bound && strcmp(pl->state, "refused") != 0) {
            continue;                            /* a plane refused at configuration is said, bound or not */
        }
#else
        if (!pl->bound) {
            continue;                            /* the control: the refused plane missing from the status */
        }
#endif
        mod_put(t, "plane %s %s", we_mod_plane_word(p), pl->state);
        if (pl->reason[0] != '\0') {
            mod_put(t, " ");
            mod_put_escaped(t, pl->reason);
        }
        mod_put(t, " generation %llu digest %s", (unsigned long long)pl->generation, pl->digest16[0] != '\0' ? pl->digest16 : "-");
        if (pl->pending) {
            mod_put(t, " posted %llu pending-ticks %llu", (unsigned long long)pl->posted, (unsigned long long)pl->pending_ticks);
        }
#ifndef WE_MOD_TEST_PRINT_UNMEASURED
        uint32_t m = pl->measured;
#else
        uint32_t m = 0xffu;                      /* the control: every field printed, measured or not */
#endif
        mod_put(t, " valid-until %llu remaining %lld", (unsigned long long)pl->valid_until_ms, (long long)pl->remaining_ms);
        if (m & WE_MOD_MEASURED_SLOT_AGE) {
            mod_put(t, " slot-age %lld", (long long)pl->slot_age_ms);
        }
        mod_put(t, " since %llu", (unsigned long long)pl->since_ms);
        if (m & WE_MOD_MEASURED_TICKS) {
            mod_put(t, " ticks %llu", (unsigned long long)pl->ticks);
        }
        mod_put(t, " bytes %llu %s locked %s", (unsigned long long)pl->bytes, pl->mapped ? "mapped" : "private",
                pl->locked ? "yes" : "no");
        if (m & WE_MOD_MEASURED_IMMUTABLE) {
            mod_put(t, " immutable %s", pl->immutable ? "yes" : "no");
        }
        if (m & WE_MOD_MEASURED_NONRESIDENT) {
            mod_put(t, " nonresident %llu", (unsigned long long)pl->nonresident);
        }
        mod_put(t, " country-table %u eio-backoff %llu deferred %llu%s\n", (unsigned)pl->country_table,
                (unsigned long long)pl->eio_backoff_ms, (unsigned long long)pl->deferred,
                pl->dir_replaced ? " data-directory-replaced" : "");
    }
    for (k = 0u; k < s->ntransitions; k++) {
        mod_put(t, "transition %llu ", (unsigned long long)s->transition_ms[k]);
        mod_put_escaped(t, s->transition[k]);
        mod_put(t, "\n");
    }
#ifndef WE_MOD_TEST_PRINT_UNMEASURED
    if (s->measured & WE_MOD_MEASURED_MAJFLT) {
#else
    {
#endif
        mod_put(t, "majflt-delta %llu\n", (unsigned long long)s->majflt_delta);
    }
#ifdef WE_MOD_DEBUG
    if (we_mod_debug_tail_on()) {
        mod_put(t, "debug tail-requests %llu\n", (unsigned long long)we_mod_debug_tail_count());
    }
#endif
}

/* ==================================================================================================
 * The planes' publication: the stand-in, the two compare-and-swap calls, the bounded retire list
 * ================================================================================================ */


/* the stand-in's families answer "no range" before any index load; the table is valid all the same */
static const uint32_t mod_whole_window[2] = { 0u, 0xffffffffu };

/*
 * A plane's stand-in: header-only, both families empty, generation 1 and valid_until_ms 1, so every
 * plane reads it as stale (UNKNOWN) and the tenant plane as lapsed (no allow granted), never revoked.
 * Built once per plane at binding and never retired. What a request renders is never read from it: a
 * memo write that finds it sets the plane's disarmed bit (we_mod_memo_put).
 */
we_map_t *we_mod_standin_new(uint32_t plane_id)
{
    size_t bytes = (sizeof(we_map_t) + 63u) & ~(size_t)63u;
    we_map_t *m = (we_map_t *)aligned_alloc(64, bytes);

    if (m == NULL) {
        return NULL;
    }
    memset(m, 0, bytes);
    m->f4.kind = WE_KIND_RADIX;
    m->f4.idx = mod_whole_window;
    m->f4.key_bits = 32u;
    m->f6.kind = WE_KIND_RADIX;
    m->f6.idx = mod_whole_window;
    m->f6.key_bits = 128u;
    m->f6w.kind = WE_KIND_RADIX;
    m->f6w.idx = mod_whole_window;
    m->f6w.key_bits = 64u;
    m->generation = 1u;
    m->valid_until_ms = 1u;
    m->format = WE_FORMAT_2;
    m->plane_id = (uint8_t)plane_id;
    m->schema_id = (uint8_t)(plane_id == WE_PLANE_REPUTATION ? WE_SCHEMA_FORMAT1
                           : (plane_id == WE_PLANE_ROUTING || plane_id == WE_PLANE_REGISTRY) ? WE_SCHEMA_ROUTING
                           : WE_SCHEMA_MEMBERSHIP);
    m->country_known = we_country_known_table;
    return m;
}

/*
 * Publish a map the module owns: the core's rollback and high-water rules (the generation above the
 * handle's high-water mark and above the current map's), then ONE release compare-and-swap from
 * `expected` to `m`. On success the displaced map is handed back to the module, never to the core's retire
 * ring; the high-water mark and the generation metric move to m's. Called by the plane's single writer.
 */
int we_handle_publish_mapped(we_handle_t *h, const we_map_t *expected, we_map_t *m, const we_map_t **displaced)
{
    we_map_t *exp = (we_map_t *)(uintptr_t)expected;

    if (h == NULL || m == NULL || ((uintptr_t)m & 63u) != 0u) {
        return WE_MOD_ERR_ARG;
    }
    if (m->generation == 0u) {
        return WE_ERR_FORMAT;                  /* 0 is the revoked map's "nothing armed" */
    }
    if ((expected != NULL && m->generation <= expected->generation)
            || m->generation <= __atomic_load_n(&h->high_water, __ATOMIC_RELAXED)) {
        WE_COUNT(h->rejected_rollbacks);
        return WE_ERR_ROLLBACK;
    }
    if (!__atomic_compare_exchange_n(&h->current, &exp, m, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        return WE_MOD_ERR_RACE;
    }
    __atomic_store_n(&h->high_water, m->generation, __ATOMIC_RELAXED);
    __atomic_store_n(&h->generation, m->generation, __ATOMIC_RELEASE);
    WE_COUNT(h->loads_ok);
    if (displaced != NULL) {
        *displaced = expected;
    }
    return WE_OK;
}

/*
 * One release compare-and-swap with no generation check, for exactly three moves: disarm (the armed map
 * to the stand-in), re-arm (the stand-in back to the armed map, when nothing was published or revoked
 * since) and the tenant's revoked map (whatever is current, to the revoked map, generation 0 by design).
 * Retires nothing.
 */
int we_handle_set_view(we_handle_t *h, const we_map_t *expected, we_map_t *m)
{
    we_map_t *exp = (we_map_t *)(uintptr_t)expected;

    if (h == NULL || m == NULL || ((uintptr_t)m & 63u) != 0u) {
        return WE_MOD_ERR_ARG;
    }
    return __atomic_compare_exchange_n(&h->current, &exp, m, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED) ? WE_OK
                                                                                                    : WE_MOD_ERR_RACE;
}

/*
 * The module's own retire list, per plane: four slots, each a displaced map and the release that undoes
 * it (munlock, munmap, close: the thread's, never an event loop's), freed after the grace on the
 * MONOTONIC clock, so a wall-clock step can neither hold a slot for an hour nor free one at once.
 * 0, or -1 when every slot is taken: the caller defers the new publish and keeps the armed map serving.
 */
int we_mod_retire_push(we_mod_retire_t *r, const we_map_t *m, void (*release)(we_map_t *m, void *ud), void *ud,
                       uint64_t mono_ms)
{
    uint32_t i;

    for (i = 0u; i < WE_MOD_RETIRE_SLOTS; i++) {
        if (r->slot[i].map == NULL) {
            r->slot[i].map = (we_map_t *)(uintptr_t)m;   /* the module's own map: it alone frees it */
            r->slot[i].release = release;
            r->slot[i].ud = ud;
            r->slot[i].at_ms = mono_ms;
            return 0;
        }
    }
    return -1;
}

/* every slot older than the grace released; the number released */
uint32_t we_mod_retire_sweep(we_mod_retire_t *r, uint64_t mono_ms, uint64_t grace_ms)
{
    uint32_t i, n = 0u;

    for (i = 0u; i < WE_MOD_RETIRE_SLOTS; i++) {
        if (r->slot[i].map != NULL && mono_ms - r->slot[i].at_ms >= grace_ms) {
            if (r->slot[i].release != NULL) {
                r->slot[i].release(r->slot[i].map, r->slot[i].ud);
            }
            r->slot[i].map = NULL;
            n++;
        }
    }
    return n;
}

uint64_t we_mod_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ==================================================================================================
 * The two single-producer, single-consumer lists: a pointer slot holding an intrusive list
 * ================================================================================================ */

#ifdef WE_MOD_DEBUG
/*
 * The single-producer rule, enforced in the debug build: each slot has one posting thread per process. Two
 * producers on one slot lose items (the second store overwrites the first's merged list), so the first
 * post records the poster's thread and process, and a post from another thread of the same process aborts
 * naming the slot. A forked child posts from its own thread, so an entry from another process is re-taken.
 */
#define MOD_SPSC_SLOTS 64u
static struct { we_mod_item_t **slot; long tid; long pid; } mod_spsc[MOD_SPSC_SLOTS];

static __attribute__((unused)) void mod_spsc_check(we_mod_item_t **slot)
{
    long me = (long)syscall(SYS_gettid), pid = (long)getpid();
    uint32_t i;

    for (i = 0u; i < MOD_SPSC_SLOTS; i++) {
        we_mod_item_t **s = __atomic_load_n(&mod_spsc[i].slot, __ATOMIC_ACQUIRE);

        if (s == NULL) {
            we_mod_item_t **want = NULL;

            if (__atomic_compare_exchange_n(&mod_spsc[i].slot, &want, slot, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&mod_spsc[i].pid, pid, __ATOMIC_RELAXED);
                __atomic_store_n(&mod_spsc[i].tid, me, __ATOMIC_RELEASE);
                return;
            }
            s = want;
        }
        if (s != slot) {
            continue;
        }
        if (__atomic_load_n(&mod_spsc[i].pid, __ATOMIC_RELAXED) != pid) {
            __atomic_store_n(&mod_spsc[i].pid, pid, __ATOMIC_RELAXED);
            __atomic_store_n(&mod_spsc[i].tid, me, __ATOMIC_RELEASE);
            return;
        }
        if (__atomic_load_n(&mod_spsc[i].tid, __ATOMIC_ACQUIRE) != me) {
            fprintf(stderr, "we_mod_list_post: slot %p has a second producer (thread %ld after thread %ld): the "
                    "lists are single-producer\n", (void *)slot, me, __atomic_load_n(&mod_spsc[i].tid, __ATOMIC_RELAXED));
            abort();
        }
        return;
    }
}
#endif

/* the producer: take the slot, link the item onto what it took, store the merged list back (release) */
void we_mod_list_post(we_mod_item_t **slot, we_mod_item_t *it)
{
#if defined(WE_MOD_DEBUG) && !defined(WE_MOD_TEST_SPSC_UNCHECKED)
    mod_spsc_check(slot);
#endif
    we_mod_item_t *taken = __atomic_exchange_n(slot, (we_mod_item_t *)NULL, __ATOMIC_ACQ_REL);
    we_mod_item_t *tail = it;

    while (tail->next != NULL) {
        tail = tail->next;
    }
    tail->next = taken;
    __atomic_store_n(slot, it, __ATOMIC_RELEASE);
}

/*
 * The consumer: the whole list in one acquire exchange, oldest first. Neither side waits or retries.
 * A post that lands between the producer's exchange and its store is in neither half for that instant,
 * and is taken whole by the next take, because the store puts it back: nothing is dropped.
 */
we_mod_item_t *we_mod_list_take(we_mod_item_t **slot)
{
    we_mod_item_t *l = __atomic_exchange_n(slot, (we_mod_item_t *)NULL, __ATOMIC_ACQUIRE), *rev = NULL;

    while (l != NULL) {
        we_mod_item_t *n = l->next;

        l->next = rev;
        rev = l;
        l = n;
    }
    return rev;
}

/* ==================================================================================================
 * The module's thread, and a stop that may run inside a signal handler
 * ================================================================================================ */

struct we_mod_thread {
    int              wake[2];    /* the stop path writes [1]; the thread polls [0] */
    int              done[2];    /* the thread writes [1] when it is finished; the stop path polls [0] */
    int              stop;       /* touched only through the __atomic builtins */
    uint64_t         interval_ms, offset_ms, tick;
    we_mod_tick_fn   on_tick, on_final;
    void            *ud;
    uint32_t         stage, progress;   /* WE_MOD_STAGE_* and a mark count: the thread writes, the stop reads */
};

/* the thread running now, if it is a module thread: what we_mod_thread_stage() and the core's own marks reach */
static __thread we_mod_thread_t *mod_cur_thread;

static void mod_progress(void)
{
    we_mod_thread_t *t = mod_cur_thread;

    if (t != NULL) {
        __atomic_store_n(&t->progress, __atomic_load_n(&t->progress, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELEASE);
    }
}

void we_mod_thread_stage(uint32_t stage)
{
    we_mod_thread_t *t = mod_cur_thread;

    if (t != NULL) {
        __atomic_store_n(&t->stage, stage <= WE_MOD_STAGE_FINAL ? stage : WE_MOD_STAGE_TICK, __ATOMIC_RELEASE);
        mod_progress();
    }
}

/* the stage the calling module thread is in, for a mark that restores it (WE_MOD_STAGE_WAIT on any other thread) */
static uint32_t mod_stage_now(void)
{
    return mod_cur_thread != NULL ? __atomic_load_n(&mod_cur_thread->stage, __ATOMIC_RELAXED) : WE_MOD_STAGE_WAIT;
}

/*
 * The object this code lives in, pinned: a detached thread that has written its done byte can still be
 * executing module text when the server unloads the module (nginx unloads it as the cycle pool goes), so
 * every process that starts a thread first takes a reference the unload cannot drop.
 */
__attribute__((unused)) static int mod_pin_self(char *why, size_t whyn)
{
    Dl_info info;
    void *h;

    if (dladdr((const void *)(uintptr_t)&mod_pin_self, &info) == 0 || info.dli_fname == NULL) {
        snprintf(why, whyn, "dladdr cannot name this module's object");
        return -1;
    }
    h = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    if (h == NULL) {
        char exe[PATH_MAX], lib[PATH_MAX];

        /* linked into the program itself (a harness, a static build): the program is never unloaded */
        if (realpath("/proc/self/exe", exe) != NULL && realpath(info.dli_fname, lib) != NULL && strcmp(exe, lib) == 0) {
            return 0;
        }
        snprintf(why, whyn, "the module's object cannot be pinned: %s", dlerror());
        return -1;
    }
    return 0;                                    /* the handle is never closed: that is the pin */
}

__attribute__((unused)) static void *mod_thread_main(void *arg)
{
    we_mod_thread_t *t = (we_mod_thread_t *)arg;
    uint64_t next = we_mod_monotonic_ms() + t->offset_ms;
    char b = 0;

    /* per thread on Linux: a digest yields the worker's core to its event loop */
    setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), 10);
    mod_cur_thread = t;
    we_mod_thread_stage(WE_MOD_STAGE_TICK);
    t->on_tick(t->ud, __atomic_load_n(&t->tick, __ATOMIC_RELAXED), &t->stop);   /* the first status write */
    __atomic_store_n(&t->tick, __atomic_load_n(&t->tick, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELEASE);
    we_mod_thread_stage(WE_MOD_STAGE_WAIT);
    while (!__atomic_load_n(&t->stop, __ATOMIC_ACQUIRE)) {
        struct pollfd pf;
        uint64_t now = we_mod_monotonic_ms();
        int wait = next > now ? (int)(next - now > 3600000u ? 3600000u : next - now) : 0;

        pf.fd = t->wake[0];
        pf.events = POLLIN;
        pf.revents = 0;
        if (poll(&pf, 1, wait) > 0) {
            ssize_t r = read(t->wake[0], &b, 1);

            (void)r;
            continue;                            /* the stop flag is read at the top */
        }
        if (we_mod_monotonic_ms() >= next) {
            we_mod_thread_stage(WE_MOD_STAGE_TICK);
            t->on_tick(t->ud, __atomic_load_n(&t->tick, __ATOMIC_RELAXED), &t->stop);
            __atomic_store_n(&t->tick, __atomic_load_n(&t->tick, __ATOMIC_RELAXED) + 1u, __ATOMIC_RELEASE);
            we_mod_thread_stage(WE_MOD_STAGE_WAIT);
            next += t->interval_ms;
            if (next < we_mod_monotonic_ms()) {
                next = we_mod_monotonic_ms() + t->interval_ms;   /* a stalled tick does not burst */
            }
        }
    }
    we_mod_thread_stage(WE_MOD_STAGE_FINAL);
    if (t->on_final != NULL) {
        t->on_final(t->ud, __atomic_load_n(&t->tick, __ATOMIC_RELAXED), &t->stop);   /* the thread is the only writer of its files */
    }
    b = 1;
    while (write(t->done[1], &b, 1) < 0 && errno == EINTR) {
    }
    return NULL;
}

/*
 * Start the module's thread: the object pinned, two close-on-exec pipes, every asynchronous signal blocked
 * around the create (the full set but SIGILL, SIGFPE, SIGSEGV and SIGBUS, nginx's own pool-thread mask),
 * detached, so nothing ever joins it: reading `done` is the join. `on_tick` runs once at once, then every
 * interval on the monotonic clock after `offset_ms`. All its memory is malloc'd and process-lifetime.
 * 0, or -1 with `why` (no thread: the caller serves its inherited planes and reports `no-thread`).
 */
int we_mod_thread_start(we_mod_thread_t **out, uint64_t interval_ms, uint64_t offset_ms, we_mod_tick_fn on_tick,
                        we_mod_tick_fn on_final, void *ud, char *why, size_t whyn)
{
    we_mod_thread_t *t;
    pthread_attr_t attr;
    pthread_t tid;
    sigset_t all, old;
    int rc;

    *out = NULL;
#ifdef WE_MOD_TEST_NO_PIN
    snprintf(why, whyn, "the object was not pinned (the control)");
    return WE_MOD_ERR_THREAD;
#else
    if (mod_pin_self(why, whyn) != 0) {
        return WE_MOD_ERR_THREAD;
    }
#endif
    t = (we_mod_thread_t *)calloc(1, sizeof *t);
    if (t == NULL) {
        snprintf(why, whyn, "out of memory");
        return WE_ERR_MMAP;
    }
    if (pipe2(t->wake, O_CLOEXEC | O_NONBLOCK) != 0 || pipe2(t->done, O_CLOEXEC | O_NONBLOCK) != 0) {
        snprintf(why, whyn, "pipe2: %s", strerror(errno));
        return WE_MOD_ERR_THREAD;                                /* the descriptors and the state are process-lifetime */
    }
    t->interval_ms = interval_ms != 0u ? interval_ms : 60000u;
    t->offset_ms = offset_ms;
    t->on_tick = on_tick;
    t->on_final = on_final;
    t->ud = ud;
    sigfillset(&all);
    sigdelset(&all, SIGILL);
    sigdelset(&all, SIGFPE);
    sigdelset(&all, SIGSEGV);
    sigdelset(&all, SIGBUS);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#ifndef WE_MOD_TEST_THREAD_MASK
    pthread_sigmask(SIG_SETMASK, &all, &old);
#else
    pthread_sigmask(SIG_SETMASK, NULL, &old);    /* the control: the thread inherits the caller's mask */
#endif
#ifdef WE_MOD_TEST_NO_THREAD
    rc = EAGAIN;                                 /* the control: no thread */
    (void)tid;
#else
    rc = pthread_create(&tid, &attr, mod_thread_main, t);
#endif
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        snprintf(why, whyn, "pthread_create: %s", strerror(rc));
        return WE_MOD_ERR_THREAD;
    }
    *out = t;
    return 0;
}

/*
 * THE STOP, safe inside a signal handler (Apache prefork runs it in its SIGTERM handler): an atomic
 * store, one write(2), and poll(2) on the done pipe against a deadline on CLOCK_MONOTONIC carried across
 * EINTR. Nothing here joins, locks or allocates. 0 when the thread finished (its final files are
 * written), 1 when the deadline passed (abandoned: the caller writes no file, closes nothing the thread
 * may still write, and reports the window of counts at risk).
 */
int we_mod_thread_stop(we_mod_thread_t *t, uint64_t deadline_ms)
{
    struct timespec ts;
    uint64_t end, now;
    char b = 1;

    if (t == NULL) {
        return 0;
    }
    __atomic_store_n(&t->stop, 1, __ATOMIC_RELEASE);
    while (write(t->wake[1], &b, 1) < 0 && errno == EINTR) {
    }
    if (deadline_ms > 86400000u) {
        deadline_ms = 86400000u;                 /* a day: far past any server's own stop timeout, and no overflow */
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u + deadline_ms;
    for (;;) {
        struct pollfd pf;
        int r;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
        if (now >= end) {
            return 1;
        }
        pf.fd = t->done[0];
        pf.events = POLLIN;
        pf.revents = 0;
        r = poll(&pf, 1, (int)(end - now > 3600000u ? 3600000u : end - now));
        if (r > 0) {
            return 0;
        }
        if (r < 0 && errno != EINTR) {
            return 1;
        }
    }
}

/*
 * The bounded stop (we_module.h says the rule). Both words are read with acquire loads, plain loads on
 * every target, so the stop path's calls are the primitive's: a write and polls.
 */
int we_mod_thread_stop_bounded(we_mod_thread_t *t, uint32_t *stage)
{
    uint32_t seen, now, st = WE_MOD_STAGE_WAIT, waited = 0u;

    if (stage != NULL) {
        *stage = WE_MOD_STAGE_WAIT;
    }
    if (t == NULL) {
        return 0;
    }
    seen = __atomic_load_n(&t->progress, __ATOMIC_ACQUIRE);
    for (;;) {
        if (we_mod_thread_stop(t, WE_MOD_STOP_WINDOW_MS) == 0) {
            return 0;
        }
        waited += WE_MOD_STOP_WINDOW_MS;
        now = __atomic_load_n(&t->progress, __ATOMIC_ACQUIRE);
        st = __atomic_load_n(&t->stage, __ATOMIC_ACQUIRE);
#ifdef WE_MOD_TEST_FLAT_DEADLINE
        now = seen;                              /* the control: one flat window, whatever the thread is doing */
        st = WE_MOD_STAGE_PLANES;
#endif
        if (waited >= WE_MOD_STOP_CAP_MS || (now == seen && st == WE_MOD_STAGE_PLANES)) {
            if (stage != NULL) {
                *stage = st <= WE_MOD_STAGE_FINAL ? st : WE_MOD_STAGE_TICK;
            }
            return 1;
        }
        seen = now;
    }
}

const char *we_mod_stage_text(uint32_t stage)
{
    static const char *const text[4] = {
        " (the thread was in: its wait between ticks)",
        " (the thread was in: a plane job)",
        " (the thread was in: a tick's own work)",
        " (the thread was in: its final write)",
    };

    return text[stage <= WE_MOD_STAGE_FINAL ? stage : WE_MOD_STAGE_TICK];
}

/* the thread's tick count, for the status line and the gate's barrier */
uint64_t we_mod_thread_ticks(const we_mod_thread_t *t)
{
    return t != NULL ? __atomic_load_n(&t->tick, __ATOMIC_ACQUIRE) : 0u;
}

const char *we_mod_strerror(int rc)
{
    switch (rc) {
    case WE_MOD_ERR_RACE: return "another map became current first: nothing changed";
    case WE_MOD_ERR_SPEC: return "the context spec omits a context that carries lines";
    case WE_MOD_ERR_ABI:  return "the module was built against another we_module.h";
    case WE_MOD_ERR_ARG:  return "a NULL or misaligned argument, or nothing bound";
    case WE_MOD_ERR_CONFIG: return "the configuration names the reputation plane's file twice";
    case WE_MOD_ERR_CAP:  return "the configuration counts more rule slots than one may hold";
    case WE_MOD_ERR_THREAD: return "the module's thread could not be started";
    default:              return we_strerror(rc);
    }
}

/* ==================================================================================================
 * The planes, bound and kept: the supervisor's verification, the worker-start check, the thread's jobs
 * and the loop's compare-and-swaps (the publication rule's mapped planes, POLICY.md §2.4 and §3.5)
 * ================================================================================================ */

static const char *const mod_plane_file[8] = {
    "reputation.bin", "tor.bin", "rpki-unreachable.bin", "routing.bin", "anonymizer.bin", "threat.bin",
    "registry.bin", "tenant.bin"
};

/* the five fields of an inode's identity the publication rule compares: st_dev, st_ino, st_size, st_mtim, st_ctim */
typedef struct {
    uint64_t dev, ino, size;
    int64_t  mt_s, mt_ns, ct_s, ct_ns;
} mod_ident_t;

static mod_ident_t mod_ident(const struct stat *st)
{
    mod_ident_t i;

    i.dev = (uint64_t)st->st_dev;
    i.ino = (uint64_t)st->st_ino;
    i.size = (uint64_t)st->st_size;
    i.mt_s = (int64_t)st->st_mtim.tv_sec;
    i.mt_ns = (int64_t)st->st_mtim.tv_nsec;
    i.ct_s = (int64_t)st->st_ctim.tv_sec;
    i.ct_ns = (int64_t)st->st_ctim.tv_nsec;
    return i;
}

static int mod_ident_eq(const mod_ident_t *a, const mod_ident_t *b)
{
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size && a->mt_s == b->mt_s && a->mt_ns == b->mt_ns
        && a->ct_s == b->ct_s && a->ct_ns == b->ct_ns;
}

/* a mapping the module owns, and its release: munlock, munmap, close, the thread's alone */
typedef struct {
    void    *addr;
    size_t   len;
    int      fd;
    int      locked;
    int      private;        /* the legacy file's storage is the verified copy, an anonymous mapping, never the file */
    uint64_t built_at_ms;    /* the header's, copied from the verified buffer: the status never reads the mapping */
} mod_mapping_t;

static void mod_mapping_release(we_map_t *m, void *ud)
{
    mod_mapping_t *mp = (mod_mapping_t *)ud;

    if (mp != NULL) {
        if (mp->locked) {
            munlock(mp->addr, mp->len);
        }
        if (mp->addr != NULL) {
            munmap(mp->addr, mp->len);
        }
        if (mp->fd >= 0) {
            close(mp->fd);
        }
        free(mp);
    }
    free(m);
}

/* the revoked tenant map, the heap descriptor the core builds: freed, never unmapped */
static void mod_heap_release(we_map_t *m, void *ud)
{
    (void)ud;
    free(m);
}

/* one remembered failure, keyed on what fstatat alone returns, never on the digest */
typedef struct {
    mod_ident_t key;
    uint8_t     digest[32];
    char        reason[16];        /* digest, structure, trust, header, rollback, unchanged, committed, eio */
    uint64_t    retry_tick;        /* an EIO's: retried at this tick (0: never, the entry is permanent) */
    uint64_t    backoff;           /* an EIO's current backoff, in ticks */
} mod_fail_t;

enum { MOD_VIEW_NULL, MOD_VIEW_ARMED, MOD_VIEW_STANDIN, MOD_VIEW_REVOKED };
enum { MOD_RES_PUBLISH = 1, MOD_RES_DISARM, MOD_RES_REARM, MOD_RES_REVOKE, MOD_RES_NULL, MOD_RES_LOG };

/* one result from the thread to the loop and back: the loop applies it and answers on the same item */
typedef struct {
    we_mod_item_t   link;
    uint32_t        p, kind;
    uint64_t        seq;             /* the plane's arm sequence when it was queued */
    we_map_t       *map;             /* the map to install */
    const we_map_t *expected;
    uint32_t        null_reason;     /* MOD_RES_NULL: the word stored */
    int             final;           /* MOD_RES_DISARM: the disarm is final (the bytes changed) */
    int             rc;              /* the loop's answer */
    const we_map_t *displaced;
    char            log[WE_MOD_RING_ENTRY];
} mod_result_t;

typedef struct {
    uint32_t       p;
    const char    *name;
    int            dirfd;            /* the held directory's descriptor: the data directory's, or the legacy file's */
    int            bound, legacy;
    int            own_dir;          /* the plane holds a directory descriptor of its own (a per-plane file) */
    char           path[PATH_MAX];   /* the file the configuration names for the plane, or empty */
    we_handle_t    h;                /* module-owned: the loop (Apache: the refresher) is its single writer */
    we_map_t      *standin;
    /* what is armed, as the thread knows it; the loop's view agrees once the last result is applied */
    we_map_t      *armed;
    mod_mapping_t *armed_mp;
    mod_ident_t    I;
    uint8_t        arm_digest[32];
    uint64_t       arm_seq;
    int            view, final;
    /* the one result in flight (a plane never has two), and the candidate mapping it carries */
    mod_result_t  *inflight;
    mod_mapping_t *cand_mp;
    mod_ident_t    cand_I;
    /* a queued re-digest of the armed inode: 1 its ctime changed (row b), 2 its bytes did (row c) */
    int            rehash;
    uint64_t       rehash_seq;
    mod_fail_t     fail[WE_MOD_FAIL_MEMORY];
    uint32_t       nfail;
    uint64_t       evicted;
    char           state[16], reason[256];
    uint64_t       since_ms, posted, pending_ticks, state_ticks;
    uint64_t       eio_backoff_ticks;
    int            said_stale, said_errno, said_absent, said_deferred;
    int            config_refused;   /* refused at configuration: no file opened, no handle, `-r`, its reason kept */
    uint64_t       deferred;         /* results not started because every retire slot was inside its grace */
    uint32_t       null_word;        /* the no-map reason this side last posted for the plane (the loop stores it) */
    we_mod_retire_t retire;
} mod_plane_t;

/*
 * The supervisor's budgeted verification, ONE at a time, resumed across monitor calls: the
 * candidate's descriptor, identity and peek digest, the DONTFORK buffer, and the digest's mid-state
 * with the chunk it stopped at. `p` is 8u when none is in flight. `redigest` selects the armed
 * inode's confirming re-digest, which refreshes this process's I instead of publishing; the buffer
 * is held between calls by design, so a child forked mid-verification inherits none of it.
 */
typedef struct {
    uint32_t     p;
    int          redigest;
    int          fd;                /* the candidate's descriptor, held across calls; -1 when none */
    struct stat  st;                /* the identity the verification started from */
    mod_ident_t  I;                 /* the candidate's identity, for the failure memory */
    uint8_t      peek[32];          /* the header's digest, from the peek */
    uint8_t     *buf;               /* the DONTFORK buffer, or NULL */
    size_t       len, off;          /* its size; the bytes read and digested so far */
    int          hdr;               /* the bare header's contribution made (the first 192 bytes) */
    we_sha256_ctx ctx;              /* the digest's mid-state, valid while off < len */
    uint8_t      digest[32];        /* the computed digest, valid once off reached len */
    /* the monitor's own counters, kept across drops, read by the prefork re-verification row: calls taken, the bytes the last call
     * read, the bytes read in all calls, and the verifications completed, published or not */
    uint64_t     calls, bytes_last, bytes_total, verify_done;
} mod_monitor_t;

struct we_mod_planes {
    uint32_t       abi;
    uint32_t       null_reason[8];   /* cfg->null_reason: the loop stores, the request path reads */
    uint64_t       nulls_posted;     /* no-map words posted: they wake the loop, and hold no plane in flight */
    uint64_t       applied[8];       /* per plane, the arm sequence of the result the loop last applied */
    mod_plane_t    plane[8];
    we_mod_cfg_t  *cfg;
    unsigned       uid;
    char           data_dir[PATH_MAX];
    uint64_t       dir_dev, dir_ino;
    int            dir_replaced, sync;
    int            worker_started, ticked;   /* the order: worker start, then the thread's first tick */
    uint64_t       ticks_before_start;
    we_mod_item_t *to_loop, *to_thread;
    int            dirfd;            /* the data directory's held descriptor, -1 for none */
    we_mod_wake_fn wake;
    void          *wake_ud;
    we_mod_log_fn  log;              /* the synchronous calls' logger: the supervisor's, then the worker's */
    void          *log_ud;
    uint64_t       tick, interval_ms, log_dropped, retired, now_ms, retire_lost;
    uint64_t       majflt_last;      /* getrusage's ru_majflt at the last status, for the delta */
    int            majflt_seen;
    uint32_t       lines_this_tick;
    char           pending_log[WE_MOD_RING_LINES][WE_MOD_RING_ENTRY];
    uint32_t       npending_log;     /* the lines written: [log_head, npending_log) wait, oldest first */
    uint32_t       log_head;
    mod_monitor_t  mon;             /* the supervisor's budgeted verification, resumed across calls */
    /* the transitions (POLICY.md §2.5), computed on the loop at every apply from the handles' current maps */
    int            trans_init;      /* the baseline taken at the first apply; lines are written on a change from it */
    uint8_t        trans_out;       /* the out mask the last entries were written from (planes 1..7) */
    uint8_t        trans_tenant;    /* and the tenant state then (we_tenant_state_t) */
    uint8_t        trans_kind[8];   /* each plane's kind then (MOD_TK_*) */
    uint32_t       ntransitions;    /* the ring: the newest WE_MOD_TRANSITIONS entries, copied into the status */
    uint64_t       transition_ms[WE_MOD_TRANSITIONS];
    char           transition[WE_MOD_TRANSITIONS][WE_MOD_RING_ENTRY];
};

/* what a plane's view pointer is, as the thread knows it */
static const we_map_t *mod_view_ptr(const mod_plane_t *pp)
{
    switch (pp->view) {
    case MOD_VIEW_ARMED:   return pp->armed;
    case MOD_VIEW_STANDIN: return pp->standin;
    case MOD_VIEW_REVOKED: return pp->armed;
    default:               return NULL;
    }
}

static uint64_t mod_epoch_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void mod_null_word(we_mod_planes_t *pl, mod_plane_t *pp, const char *state);

/*
 * The plane's state word and reason, for the status file. A plane with no map also has a no-map reason the
 * request path renders (`-r` refused, `-l` loading), stored by the plane's single writer; the word is
 * posted from here, the one place the state changes, so the status and the token cannot say two things.
 */
static void mod_state(we_mod_planes_t *pl, mod_plane_t *pp, const char *state, const char *fmt, ...)
{
    va_list ap;

    if (strcmp(pp->state, state) != 0) {
        pp->since_ms = pl->now_ms;
        pp->state_ticks = 0u;
    }
    snprintf(pp->state, sizeof pp->state, "%s", state);
    pp->reason[0] = '\0';
    if (fmt != NULL) {
        va_start(ap, fmt);
        vsnprintf(pp->reason, sizeof pp->reason, fmt, ap);
        va_end(ap);
    }
    mod_null_word(pl, pp, state);
}

/* a log line, handed to the loop with the next result (a ring of WE_MOD_RING_LINES per tick) */
static void mod_log(we_mod_planes_t *pl, const char *fmt, ...)
{
    va_list ap;

    if (pl->sync) {
        char line[WE_MOD_RING_ENTRY];

        va_start(ap, fmt);
        vsnprintf(line, sizeof line, fmt, ap);
        va_end(ap);
        if (pl->log != NULL) {
            pl->log(pl->log_ud, line);           /* before the thread exists: the caller's logger at once */
        }
        return;
    }
    if (pl->npending_log == WE_MOD_RING_LINES && pl->log_head > 0u) {
        memmove(pl->pending_log[0], pl->pending_log[pl->log_head], (size_t)(pl->npending_log - pl->log_head)
                * WE_MOD_RING_ENTRY);            /* the taken lines' room back, the order kept */
        pl->npending_log -= pl->log_head;
        pl->log_head = 0u;
    }
    if (pl->npending_log >= WE_MOD_RING_LINES || pl->lines_this_tick >= WE_MOD_RING_LINES) {
        pl->log_dropped++;
        return;
    }
    va_start(ap, fmt);
    vsnprintf(pl->pending_log[pl->npending_log], WE_MOD_RING_ENTRY, fmt, ap);
    va_end(ap);
    pl->npending_log++;
    pl->lines_this_tick++;
}

/* ---- the failure memory ---- */

static mod_fail_t *mod_fail_find(mod_plane_t *pp, const mod_ident_t *k)
{
    uint32_t i;

    for (i = 0u; i < pp->nfail; i++) {
        if (mod_ident_eq(&pp->fail[i].key, k)) {
            return &pp->fail[i];
        }
    }
    return NULL;
}

static void mod_fail_drop(mod_plane_t *pp, mod_fail_t *f)
{
    uint32_t i = (uint32_t)(f - pp->fail);

    memmove(&pp->fail[i], &pp->fail[i + 1u], (pp->nfail - i - 1u) * sizeof pp->fail[0]);
    pp->nfail--;
}

/*
 * Is the remembered failure still the file at the name? fstatat's identity can recur: a new file that reuses
 * a freed inode number inside one timestamp tick, at the same size, reads as the old one (measured on an
 * x86_64 ext4 host: generation 400 written right after a refused generation 150 carried its identity and was
 * skipped as remembered). So a match on the identity is confirmed by the header: one 192-byte peek, never a
 * digest, and the same header digest (or, for a header refusal, a header still refused) is the same file.
 */
static int mod_fail_still(mod_plane_t *pp, const mod_fail_t *f)
{
#ifndef WE_MOD_TEST_FAIL_IDENT_ONLY
    we_mod_peek_t pk;
    char why[256];
    int ok = we_plane_peek(pp->dirfd, pp->name, pp->p + 1u, &pk, why, sizeof why) == 0;

    if (strcmp(f->reason, "header") == 0) {
        return !ok;
    }
    return ok && memcmp(pk.digest, f->digest, 32) == 0;
#else
    (void)pp;
    (void)f;
    return 1;                                    /* the control: the identity alone decides */
#endif
}

static mod_fail_t *mod_fail_remember(mod_plane_t *pp, const mod_ident_t *k, const char *reason, const uint8_t *digest)
{
    mod_fail_t *f = mod_fail_find(pp, k);

    if (f == NULL) {
        if (pp->nfail == WE_MOD_FAIL_MEMORY) {
            memmove(&pp->fail[0], &pp->fail[1], (WE_MOD_FAIL_MEMORY - 1u) * sizeof pp->fail[0]);   /* the oldest */
            pp->nfail--;
            pp->evicted++;
        }
        f = &pp->fail[pp->nfail++];
        memset(f, 0, sizeof *f);
        f->key = *k;
    }
    snprintf(f->reason, sizeof f->reason, "%s", reason);
    if (digest != NULL) {
        memcpy(f->digest, digest, 32);
    }
    return f;
}

/* ---- the verification: a pread buffer verified, then the file mapped and described, never read ---- */

#define MOD_CHUNK (1u << 20)
#define MOD_VERIFY_MAX 0x7fffffffu   /* the loader's own bound on a plane: a larger file is refused unread */

/* the verification buffer's bytes held now and at most, in this process: one buffer at a time, the plane's size */
static uint64_t g_mod_verify_now, g_mod_verify_peak;
#ifdef WE_MOD_DEBUG
/*
 * The debug build's digest counts, per process: every whole-file digest this process ran (a candidate's
 * verification, an armed inode's re-digest, the parent monitor's budgeted one), and those run by the worker
 * start's check. Zeroed at the worker start, so a forked worker counts its own. The status file's process
 * line carries both (`digests N start-digests M`), the counters M8 and M10 read.
 */
static uint64_t g_mod_digests, g_mod_digests_start;
static int g_mod_in_start;
static void mod_count_digest(void)
{
#ifndef WE_MOD_TEST_DIGEST_UNCOUNTED
    __atomic_add_fetch(&g_mod_digests, 1u, __ATOMIC_RELAXED);
    if (__atomic_load_n(&g_mod_in_start, __ATOMIC_RELAXED)) {
        __atomic_add_fetch(&g_mod_digests_start, 1u, __ATOMIC_RELAXED);
    }
#endif
}
#define MOD_COUNT_DIGEST() mod_count_digest()
#else
#define MOD_COUNT_DIGEST() ((void)0)
#endif

static void mod_verify_free(uint8_t *buf, size_t len)
{
    munmap(buf, len);
    __atomic_sub_fetch(&g_mod_verify_now, (uint64_t)len, __ATOMIC_RELAXED);
}

/*
 * Verify the plane open at `fd` (identity `before`) and map it: the whole file read with pread into an
 * anonymous MAP_PRIVATE buffer marked MADV_DONTFORK (never malloc: a buffer a supervisor's heap kept would be
 * inherited by every child), in 1 MiB chunks with the stop flag read between them; the buffer verified by
 * the loader's rules (we_map_from_buffer: structure, domain, then the digest); the buffer released; the
 * file mapped PROT_READ, MAP_SHARED; the descriptor re-fstat'ed and required unchanged; and the verified
 * description moved onto the mapping without reading it. 0 with *mo and *mpo the module's, or a WE_ERR_*
 * code with `why` (WE_ERR_OPEN for EIO, `*eio` set).
 */
/*
 * The verification buffer, taken: an explicit anonymous mapping marked MADV_DONTFORK (never malloc: a
 * buffer a supervisor's heap kept would be inherited by every child), accounted in the process's
 * verify-held and verify-peak. Both verifiers take it: the thread for one shot, the monitor across
 * its calls. NULL with `why` when the mapping is refused.
 */
static uint8_t *mod_verify_take(size_t len, char *why, size_t whyn)
{
    uint8_t *buf = (uint8_t *)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t now;

    if (buf == MAP_FAILED) {
        snprintf(why, whyn, "cannot allocate a %zu-byte verification buffer", len);
        return NULL;
    }
    madvise(buf, len, MADV_DONTFORK);
    now = __atomic_add_fetch(&g_mod_verify_now, (uint64_t)len, __ATOMIC_RELAXED);
    if (now > __atomic_load_n(&g_mod_verify_peak, __ATOMIC_RELAXED)) {
        __atomic_store_n(&g_mod_verify_peak, now, __ATOMIC_RELAXED);
    }
    return buf;
}

/*
 * The verification's tail, shared by the thread's one-shot path and the monitor's budgeted one: the
 * file mapped PROT_READ, MAP_SHARED; the descriptor re-fstat'ed and required unchanged (the truncate
 * row's test pause sits right after that check, so a gate may shrink the file between the identity
 * check and the arm, and only a verifier that never dereferences the mapping survives); the verified
 * description moved onto the mapping without reading it; the buffer released; the module's map and
 * mapping taken. The buffer is released on EVERY exit: the caller hands it over once. The descriptor
 * is consumed only on success. 0, or a WE_ERR_* with `why`.
 *
 * THE LEGACY FILE IS NEVER MAPPED: the legacy file keeps today's private copy. With
 * `keep_private` the verified buffer itself becomes the storage: an anonymous mapping, marked
 * MADV_DOFORK so every child forked after the arm inherits it (the verifier marks it DONTFORK while it
 * is transient), made PROT_READ, locked at worker start like a mapping, released by the same munmap,
 * accounted out of verify-held now that it is no longer transient. The file's descriptor is still
 * held, for the watch (fstat against the armed identity). A `whisper_edge_snapshot` file is the one an
 * operator's cron rewrites in place with cp, curl -o or rsync --inplace, root rewriting a 0444 inode;
 * a worker serving a MAP_SHARED mapping of it dies of SIGBUS on the first page past the new end
 * (measured, signal 7, in the nginx gate's truncation row and in test_module's `legacy truncate`),
 * where the copy serves on until the watch disarms the plane on the drift.
 */
static int mod_verify_tail(int fd, const struct stat *before, const uint8_t *buf, size_t len, int keep_private,
                           we_map_t *tmp, we_map_t **mo, mod_mapping_t **mpo, char *why, size_t whyn)
{
    uint64_t built;
    we_map_t *m;
    mod_mapping_t *mp;
    struct stat after;
    void *addr;

    *mo = NULL;
    *mpo = NULL;
    if (keep_private) {
        addr = (void *)buf;
    } else {
        addr = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
            mod_verify_free((uint8_t *)buf, len);
            snprintf(why, whyn, "mmap: %s", strerror(errno));
            return WE_ERR_MMAP;
        }
    }
    if (fstat(fd, &after) != 0) {
        memset(&after, 0, sizeof after);
    }
    {
        mod_ident_t a = mod_ident(before), b = mod_ident(&after);

        if (!mod_ident_eq(&a, &b)) {
            if (!keep_private) {
                munmap(addr, len);
            }
            mod_verify_free((uint8_t *)buf, len);
            snprintf(why, whyn, "the file changed while it was verified");
            return WE_ERR_TRUNCATED;
        }
    }
#ifdef WE_MOD_TEST_PAUSE_AFTER_FSTAT
    we_mod_test_pause("after-fstat");               /* the gate's debug hook: held here until it releases */
#endif
    built = tmp->h != NULL ? tmp->h->built_at_ms : 0u;   /* still the verified buffer's header, not the mapping */
    m = (we_map_t *)aligned_alloc(64, (sizeof *m + 63u) & ~(size_t)63u);
    mp = (mod_mapping_t *)calloc(1, sizeof *mp);
    if (m == NULL || mp == NULL) {
        free(m);
        free(mp);
        if (!keep_private) {
            munmap(addr, len);
        }
        mod_verify_free((uint8_t *)buf, len);
        snprintf(why, whyn, "out of memory");
        return WE_ERR_MMAP;
    }
    if (keep_private) {
        /* the copy is the storage from here: inheritable, read-only, no longer a verification buffer */
        madvise((void *)buf, len, MADV_DOFORK);
        if (mprotect((void *)buf, len, PROT_READ) != 0) {
            free(m);
            free(mp);
            mod_verify_free((uint8_t *)buf, len);
            snprintf(why, whyn, "mprotect: %s", strerror(errno));
            return WE_ERR_MMAP;
        }
        __atomic_sub_fetch(&g_mod_verify_now, (uint64_t)len, __ATOMIC_RELAXED);
    } else {
        we_map_rebase(tmp, addr);                   /* described from the verified buffer, never read here */
        mod_verify_free((uint8_t *)buf, len);
    }
    *m = *tmp;
    mp->addr = addr;
    mp->len = len;
    mp->fd = fd;
    mp->private = keep_private;
    mp->built_at_ms = built;
    *mo = m;
    *mpo = mp;
    return WE_OK;
}

static int mod_verify_map(int fd, const char *name, const struct stat *before, const int *stop, int keep_private,
                          we_map_t **mo, mod_mapping_t **mpo, int *eio, char *why, size_t whyn)
{
    size_t len = (size_t)before->st_size, got = 0u;
    uint8_t *buf;
    we_map_t tmp;
    we_load_detail_t d;
    int rc;

    *mo = NULL;
    *mpo = NULL;
    *eio = 0;
    if (before->st_size < (off_t)sizeof(we_header_t) || (uint64_t)before->st_size > MOD_VERIFY_MAX) {
        snprintf(why, whyn, "%lld bytes: a plane is %zu to %u bytes, so nothing was read", (long long)before->st_size,
                 sizeof(we_header_t), MOD_VERIFY_MAX);
        return before->st_size < (off_t)sizeof(we_header_t) ? WE_ERR_TOO_SMALL : WE_ERR_FORMAT;
    }
    buf = mod_verify_take(len, why, whyn);
    if (buf == NULL) {
        return WE_ERR_MMAP;
    }
    while (got < len) {
        size_t want = len - got < MOD_CHUNK ? len - got : MOD_CHUNK;
        ssize_t n;

        if (stop != NULL && __atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
            mod_verify_free(buf, len);
            snprintf(why, whyn, "stopped");
            return WE_ERR_OPEN;
        }
        n = pread(fd, buf + got, want, (off_t)got);
        mod_progress();                          /* a read that returns is progress; one stuck in the kernel is not */
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            *eio = n < 0 && errno == EIO;
            mod_verify_free(buf, len);
            snprintf(why, whyn, n < 0 ? "read: %s" : "the file shrank while it was read%s", n < 0 ? strerror(errno) : "");
            return n < 0 ? WE_ERR_OPEN : WE_ERR_TRUNCATED;
        }
        got += (size_t)n;
    }
    MOD_COUNT_DIGEST();
    rc = we_map_from_buffer(buf, len, name, &tmp, &d);
    if (rc != WE_OK) {
        mod_verify_free(buf, len);
        snprintf(why, whyn, "%s%s%s", we_strerror(rc), d.what != NULL ? ": " : "", d.what != NULL ? d.what : "");
        return rc;
    }
    return mod_verify_tail(fd, before, buf, len, keep_private, &tmp, mo, mpo, why, whyn);
}

/* a re-digest of the armed inode by pread: its bytes verify and carry the arm-time digest */
static int mod_redigest(mod_plane_t *pp, const int *stop, struct stat *now_st, char *why, size_t whyn)
{
    we_map_t *m = NULL;
    mod_mapping_t *mp = NULL;
    int eio, rc, dupfd;

    if (fstat(pp->armed_mp->fd, now_st) != 0) {
        snprintf(why, whyn, "fstat: %s", strerror(errno));
        return -1;
    }
    dupfd = fcntl(pp->armed_mp->fd, F_DUPFD_CLOEXEC, 0);
    if (dupfd < 0) {
        snprintf(why, whyn, "dup: %s", strerror(errno));
        return -1;
    }
    rc = mod_verify_map(dupfd, pp->name, now_st, stop, pp->legacy, &m, &mp, &eio, why, whyn);
    if (rc != WE_OK) {
        close(dupfd);
        return -1;
    }
    rc = memcmp(m->digest, pp->arm_digest, 32) == 0 ? 0 : -1;
    if (rc != 0) {
        snprintf(why, whyn, "its bytes no longer carry the arm-time digest");
    }
    mod_mapping_release(m, mp);                  /* the re-digest's own mapping: never published */
    return rc;
}

/* the trust checks on a descriptor already open (an armed inode whose ctime changed): mode and owner */
static int mod_trust_fd(const mod_plane_t *pp, const struct stat *st, unsigned uid, char *why, size_t whyn)
{
    if (pp->legacy) {
        if ((st->st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
            snprintf(why, whyn, "writable by group or world: chmod go-w the file");
            return -1;
        }
        return 0;
    }
    if ((st->st_mode & 07777u) != 0444u) {
        snprintf(why, whyn, "mode %04o: chmod 0444 the file", (unsigned)(st->st_mode & 07777u));
        return -1;
    }
    if (st->st_uid != 0u && st->st_uid != uid) {
        snprintf(why, whyn, "owned by uid %u: chown root the file", (unsigned)st->st_uid);
        return -1;
    }
    return 0;
}

/* ---- the retire list's precondition ---- */

/*
 * A result that will displace the armed map (a publish, a final disarm, a revocation) is started only when
 * the plane's retire list has a free slot, the sweep run first: the displaced map then always has a slot to
 * go to, and nothing leaks. Otherwise the result is deferred: nothing is verified or posted, the armed map
 * keeps serving, the deferral is counted and said once until a slot frees. 1 when the result may start.
 */
static int mod_retire_ready(we_mod_planes_t *pl, mod_plane_t *pp, const char *what)
{
    uint32_t i;

    if (pp->armed == NULL) {
        return 1;                                /* nothing to displace: no slot needed */
    }
    we_mod_retire_sweep(&pp->retire, we_mod_monotonic_ms(), WE_DEFAULT_GRACE_MS);
#ifndef WE_MOD_TEST_RETIRE_UNCHECKED
    for (i = 0u; i < WE_MOD_RETIRE_SLOTS && pp->retire.slot[i].map != NULL; i++) {
    }
    if (i == WE_MOD_RETIRE_SLOTS) {
        pp->deferred++;
        if (!pp->said_deferred) {
            pp->said_deferred = 1;
            mod_log(pl, "plane %s: %s deferred, because every retire slot holds a displaced map still inside its grace; "
                    "the armed generation serves until one frees", pp->name, what);
        }
        return 0;
    }
#else
    (void)i;
    (void)pl;
    (void)what;
#endif
    pp->said_deferred = 0;
    return 1;
}

/* the displaced armed map into the retire list, whose free slot mod_retire_ready() guaranteed */
static void mod_retire_armed(we_mod_planes_t *pl, mod_plane_t *pp, uint64_t mono)
{
#ifndef WE_MOD_TEST_RETIRE_LOCKED
    if (pp->view != MOD_VIEW_REVOKED && pp->armed_mp != NULL && pp->armed_mp->locked) {
        munlock(pp->armed_mp->addr, pp->armed_mp->len);   /* retired: only in-flight readers touch it now */
        pp->armed_mp->locked = 0;
    }
#endif
    if (we_mod_retire_push(&pp->retire, pp->armed, pp->view == MOD_VIEW_REVOKED ? mod_heap_release : mod_mapping_release,
                           pp->view == MOD_VIEW_REVOKED ? NULL : pp->armed_mp, mono) != 0) {
#ifdef WE_MOD_DEBUG
        abort();                                 /* unreachable: the slot was taken before the result started */
#endif
        pl->retire_lost++;                       /* counted, and on the process line: never silent */
        return;
    }
    pl->retired++;
}

/* ---- posting results; the loop's apply ---- */

static void mod_apply_one(we_mod_planes_t *pl, mod_result_t *r);
static void mod_ack(we_mod_planes_t *pl, mod_result_t *r);

static mod_result_t *mod_result(uint32_t p, uint32_t kind, uint64_t seq)
{
    mod_result_t *r = (mod_result_t *)calloc(1, sizeof *r);

    if (r != NULL) {
        r->p = p;
        r->kind = kind;
        r->seq = seq;
    }
    return r;
}

/*
 * The thread's post (or, synchronously, the supervisor's and the worker start's: applied at once).
 * Synchronously it returns the apply's own rc, so the monitor knows whether a publish armed its plane;
 * asynchronously it returns 0, and the callers that ignore it are unaffected.
 */
static int mod_post(we_mod_planes_t *pl, mod_plane_t *pp, mod_result_t *r)
{
    int rc;

    if (!pl->sync && pl->log_head < pl->npending_log && r->log[0] == '\0') {
#ifndef WE_MOD_TEST_LOG_LIFO
        memcpy(r->log, pl->pending_log[pl->log_head++], WE_MOD_RING_ENTRY);   /* the OLDEST line rides first */
#else
        memcpy(r->log, pl->pending_log[--pl->npending_log], WE_MOD_RING_ENTRY);   /* the control: the newest */
#endif
        if (pl->log_head == pl->npending_log) {
            pl->log_head = pl->npending_log = 0u;
        }
    }
    if (pl->sync) {
        mod_apply_one(pl, r);
        rc = r->rc;                            /* captured before the ack frees the item */
        mod_ack(pl, r);
        return rc;
    }
    if (r->kind == MOD_RES_NULL) {
        pl->nulls_posted++;                    /* a word, not a result the plane waits on: never in flight */
    } else if (r->kind != MOD_RES_LOG && pp != NULL) {
        pp->inflight = r;
        pp->posted = pl->tick;
    }
    we_mod_list_post(&pl->to_loop, &r->link);
    return 0;
}

/*
 * The no-map reason for a plane whose view is NULL, posted when its state word moves to `refused` or
 * `loading` and the word differs from the one last posted: stored by the loop before any later result of
 * the plane, in post order, so a verification in flight reads -l and a refusal -r, as the status says.
 * Nothing is posted for a plane with a map (the word is never read then) or for any other state.
 */
static void mod_null_word(we_mod_planes_t *pl, mod_plane_t *pp, const char *state)
{
    uint32_t code;
    mod_result_t *r;

#ifdef WE_MOD_TEST_NULL_WORD_UNPOSTED
    return;                                    /* the control: the word stays the one bind stored */
#endif
    if (pp->view != MOD_VIEW_NULL || !pp->bound) {
        return;
    }
    if (strcmp(state, "refused") == 0) {
        code = WE_MOD_NOMAP_REFUSED;
    } else if (strcmp(state, "absent") == 0) {
        code = WE_MOD_NOMAP_ABSENT;              /* bound, and no file at the name: -a, as the status says */
    } else if (strcmp(state, "loading") == 0) {
        code = WE_MOD_NOMAP_LOADING;
    } else {
        return;
    }
    if (code == pp->null_word) {
        return;
    }
    r = mod_result(pp->p, MOD_RES_NULL, pp->arm_seq);
    if (r == NULL) {
        return;                                /* the word is retried at the next state change */
    }
    r->null_reason = code;
    pp->null_word = code;
    (void)mod_post(pl, pp, r);
}

/* every pending log line the thread holds, posted as log-only items, so none waits for a result */
static void mod_flush_log(we_mod_planes_t *pl)
{
    while (pl->log_head < pl->npending_log) {
        mod_result_t *r = mod_result(0u, MOD_RES_LOG, 0u);

        if (r == NULL) {
            pl->log_dropped += pl->npending_log - pl->log_head;
            pl->log_head = pl->npending_log = 0u;
            return;
        }
        mod_post(pl, NULL, r);
    }
}

/* the loop: one result applied by the plane's single writer, the answer written on the item */
static void mod_apply_one(we_mod_planes_t *pl, mod_result_t *r)
{
    mod_plane_t *pp = &pl->plane[r->p];

    r->rc = WE_OK;
    r->displaced = NULL;
    switch (r->kind) {
    case MOD_RES_PUBLISH:
        r->rc = we_handle_publish_mapped(&pp->h, r->expected, r->map, &r->displaced);
        break;
    case MOD_RES_DISARM:
    case MOD_RES_REARM:
    case MOD_RES_REVOKE:
        r->rc = we_handle_set_view(&pp->h, r->expected, r->map);
        r->displaced = r->expected;
        break;
    case MOD_RES_NULL:
        __atomic_store_n(&pl->null_reason[r->p], r->null_reason, __ATOMIC_RELEASE);
        break;
    default:
        break;
    }
    if (r->rc == WE_OK && r->kind != MOD_RES_LOG && r->kind != MOD_RES_NULL) {
        __atomic_store_n(&pl->applied[r->p], r->seq, __ATOMIC_RELEASE);
    }
}

/* ---- the transitions (POLICY.md §2.5): the ring entry is the record, and the error-log line is the entry ---- */

enum { MOD_TK_UNBOUND, MOD_TK_ARMED, MOD_TK_STALE, MOD_TK_DISARMED, MOD_TK_REFUSED, MOD_TK_LOADING, MOD_TK_NULL,
       MOD_TK_FRESH, MOD_TK_GRACE, MOD_TK_LAPSED, MOD_TK_REVOKED, MOD_TK_ABSENT };
static const char *const mod_tk_word[] = { "unbound", "armed", "stale", "disarmed", "refused", "loading", "null",
                                           "fresh", "grace", "lapsed", "revoked", "absent" };
static const char *const mod_tenant_word[] = { "fresh", "grace", "lapsed", "null", "revoked" };   /* we_tenant_state_t */

/*
 * A bound plane's kind, read off its handle's current map exactly as a request would see it: NULL is
 * refused or loading (the null reason the writer stored), the stand-in is a disarm, a valid-until behind
 * the clock is stale, anything else is armed. The tenant plane has the evaluator's five states instead
 * (we_eval.h: generation 0 is revoked; past valid-until by more than the grace is lapsed, by less is grace).
 */
static int mod_plane_kind(const we_mod_planes_t *pl, uint32_t p, uint64_t now_ms)
{
    const we_mod_cfg_t *c = pl->cfg;
    const we_map_t *m;

    if (c == NULL || c->handle[p] == NULL) {
        return MOD_TK_UNBOUND;
    }
    m = we_current(c->handle[p]);
    if (p + 1u == WE_PLANE_TENANT) {
        if (m == NULL) {
            return MOD_TK_NULL;
        }
        if (m->revoked || m->generation == 0u) {
            return MOD_TK_REVOKED;
        }
        if (m->valid_until_ms != 0u && now_ms > m->valid_until_ms) {
            return now_ms - m->valid_until_ms > WE_TENANT_GRACE_MS ? MOD_TK_LAPSED : MOD_TK_GRACE;
        }
        return MOD_TK_FRESH;
    }
    if (m == NULL) {
        uint32_t r = __atomic_load_n(&pl->null_reason[p], __ATOMIC_ACQUIRE);

        return r == WE_MOD_NOMAP_LOADING ? MOD_TK_LOADING : r == WE_MOD_NOMAP_REFUSED ? MOD_TK_REFUSED
             : r == WE_MOD_NOMAP_ABSENT ? MOD_TK_ABSENT : MOD_TK_NULL;
    }
    if (m == c->standin[p]) {
        return MOD_TK_DISARMED;
    }
    if (m->valid_until_ms != 0u && now_ms > m->valid_until_ms) {
        return MOD_TK_STALE;
    }
    return MOD_TK_ARMED;
}

static we_tenant_state_t mod_tenant_state(int kind)
{
    switch (kind) {
    case MOD_TK_FRESH:   return WE_TENANT_FRESH;
    case MOD_TK_GRACE:   return WE_TENANT_GRACE;
    case MOD_TK_LAPSED:  return WE_TENANT_LAPSED;
    case MOD_TK_REVOKED: return WE_TENANT_REVOKED;
    default:             return WE_TENANT_NULL;
    }
}

/* the newest WE_MOD_TRANSITIONS entries kept, the oldest dropped; the entry is the first 511 bytes and a NUL */
static void mod_transition_push(we_mod_planes_t *pl, uint64_t now_ms, const char *entry)
{
    uint32_t k = pl->ntransitions;

    if (k == WE_MOD_TRANSITIONS) {
        memmove(pl->transition[0], pl->transition[1], (size_t)(WE_MOD_TRANSITIONS - 1u) * WE_MOD_RING_ENTRY);
        memmove(pl->transition_ms, pl->transition_ms + 1, (size_t)(WE_MOD_TRANSITIONS - 1u) * sizeof pl->transition_ms[0]);
        k = WE_MOD_TRANSITIONS - 1u;
    }
    snprintf(pl->transition[k], WE_MOD_RING_ENTRY, "%s", entry);
    pl->transition_ms[k] = now_ms;
    pl->ntransitions = k + 1u;
}

/*
 * A program a transition line is written for: one with a dependent rule under the new state, or under the
 * state the last entries were written from (POLICY.md §2.5: "one line per distinct program that has a dependent
 * rule"). So a plane coming back is logged, as `none`, for the programs its outage touched, and a program
 * the change never reaches (it reads other planes alone) gets no line at all.
 */
static int mod_program_affected(const we_program_t *p, uint8_t out, we_tenant_state_t ts, uint8_t was_out,
                                we_tenant_state_t was_ts)
{
    return p != NULL && (we_program_dependents(p, out, ts, NULL, 0u) != 0u
                         || we_program_dependents(p, was_out, was_ts, NULL, 0u) != 0u);
}

/* each plane's kind and the out mask and tenant state they make, read off the handles at `now` */
static void mod_transition_state(const we_mod_planes_t *pl, uint64_t now, uint8_t kind[8], uint8_t *out,
                                 we_tenant_state_t *ts)
{
    uint32_t p;

    *out = 0u;
    for (p = 0u; p < 8u; p++) {
        kind[p] = (uint8_t)mod_plane_kind(pl, p, now);
        if (p + 1u != WE_PLANE_TENANT && kind[p] != MOD_TK_UNBOUND && kind[p] != MOD_TK_ARMED) {
            *out |= (uint8_t)(1u << p);
        }
    }
    *ts = mod_tenant_state(kind[WE_PLANE_TENANT - 1u]);
}

/*
 * The baseline: the planes' state when the worker starts, which it inherited from the supervisor's binding
 * with no apply of its own. Taken here and not at the first apply, because the first apply may already be
 * the change (a plane armed at the start and stale by then), and that transition must be logged.
 */
static void mod_transitions_baseline(we_mod_planes_t *pl, uint64_t now)
{
    uint8_t kind[8], out;
    we_tenant_state_t ts;

    mod_transition_state(pl, now, kind, &out, &ts);
    pl->trans_init = 1;
    pl->trans_out = out;
    pl->trans_tenant = (uint8_t)ts;
    memcpy(pl->trans_kind, kind, sizeof kind);
}

/*
 * On every apply: each bound plane's kind off its handle; the first call takes the baseline; a change
 * writes, per plane whose kind changed, one entry per distinct program of the configuration with a
 * plane-dependent rule (the head `plane <P> <kind> out=<the out planes in plane order, or -> tenant=<state>`,
 * then we_program_dependents_line()'s text), or ONE summary entry when more than WE_MOD_TRANSITIONS
 * programs are affected. Each entry goes into the ring and to the loop's logger, byte for byte the same.
 * The entry names no program, so two programs whose dependents read the same write the same bytes: that
 * text is written once for the plane's change, not once per program.
 */
static void mod_transitions(we_mod_planes_t *pl, we_mod_log_fn log, void *ud)
{
    uint64_t now = mod_epoch_ms();
    uint8_t kind[8], out;
    we_tenant_state_t ts, was_ts = (we_tenant_state_t)pl->trans_tenant;
    uint32_t p, i, nprog = 0u, nblocks;
    const we_mod_arena_t *arena = pl->cfg != NULL ? pl->cfg->arena : NULL;
    char outs[96], head[160], entry[WE_MOD_RING_ENTRY];
    size_t o = 0u;

    if (!pl->trans_init) {
        mod_transitions_baseline(pl, now);       /* no worker start ran: this apply is the baseline */
        return;
    }
    mod_transition_state(pl, now, kind, &out, &ts);
    if (out == pl->trans_out && ts == was_ts && memcmp(kind, pl->trans_kind, sizeof kind) == 0) {
        return;
    }
    {
        outs[0] = '\0';
        for (p = 0u; p + 1u < WE_PLANE_TENANT; p++) {
            if ((out >> p) & 1u) {
                o += (size_t)snprintf(outs + o, sizeof outs - o, "%s%s", o != 0u ? "," : "", we_mod_plane_word(p));
            }
        }
        if (o == 0u) {
            snprintf(outs, sizeof outs, "-");
        }
        nblocks = we_mod_arena_blocks(arena);
        for (i = 0u; i < nblocks; i++) {
            nprog += mod_program_affected(we_mod_arena_block(arena, i), out, ts, pl->trans_out, was_ts) != 0;
        }
        for (p = 0u; p < 8u; p++) {
            if (kind[p] == pl->trans_kind[p] || kind[p] == MOD_TK_UNBOUND) {
                continue;                        /* this plane did not change */
            }
            snprintf(head, sizeof head, "plane %s %s out=%s tenant=%s", we_mod_plane_word(p), mod_tk_word[kind[p]], outs,
                     mod_tenant_word[ts]);
            if (nprog == 0u) {
                continue;                        /* no program reads what changed: nothing to say */
            }
            if (nprog > WE_MOD_TRANSITIONS) {
                snprintf(entry, sizeof entry, "%s: %u programs affected; whisper-edge-summary --status lists them", head, nprog);
                mod_transition_push(pl, now, entry);
                if (log != NULL) {
                    log(ud, entry);
                }
                continue;
            }
            uint32_t written = 0u;               /* this plane's entries so far: the ring's newest `written` */

            for (i = 0u; i < nblocks; i++) {
                const we_program_t *pg = we_mod_arena_block(arena, i);
                const char *logged = entry;
                uint32_t k;
                int same = 0;

                if (!mod_program_affected(pg, out, ts, pl->trans_out, was_ts)) {
                    continue;
                }
                entry[0] = '\0';
                (void)we_program_dependents_line(pg, out, ts, head, entry, sizeof entry);   /* -1 is a cut: kept */
                if (entry[0] == '\0') {
                    continue;
                }
                /* the line names no program, so two programs with the same dependents give the same bytes: one
                 * line says it, and a second copy at the same millisecond reads as the transition emitted twice
                 * (at most WE_MOD_TRANSITIONS lines are written here, so the ring's tail holds every one) */
                for (k = 0u; k < written && k < pl->ntransitions && !same; k++) {
                    same = strcmp(pl->transition[pl->ntransitions - 1u - k], entry) == 0;
                }
                if (same) {
                    continue;
                }
                written++;
#ifdef WE_MOD_TEST_UNCUT_LOG
                {
                    static char uncut[4096];     /* the control: the uncut text handed to the logger, the ring cut */

                    (void)we_program_dependents_line(pg, out, ts, head, uncut, sizeof uncut);
                    logged = uncut;
                }
#endif
#ifdef WE_MOD_TEST_HEAD_ALONE
                logged = head;                   /* the control: the head alone, no dependents text, to the logger */
#endif
                mod_transition_push(pl, now, entry);
                if (log != NULL) {
                    log(ud, logged);
                }
            }
        }
    }
    pl->trans_init = 1;
    pl->trans_out = out;
    pl->trans_tenant = (uint8_t)ts;
    memcpy(pl->trans_kind, kind, sizeof kind);
}

uint32_t we_mod_planes_apply(we_mod_planes_t *pl, we_mod_log_fn log, void *ud)
{
    we_mod_item_t *l = we_mod_list_take(&pl->to_loop), *back = NULL, *tail = NULL;
    uint32_t n = 0u;

    while (l != NULL) {
        mod_result_t *r = (mod_result_t *)(void *)l;

        l = l->next;
        r->link.next = NULL;
        mod_apply_one(pl, r);
        if (r->log[0] != '\0' && log != NULL) {
            log(ud, r->log);
        }
        n++;
        if (back == NULL) {
            back = &r->link;
        } else {
            tail->next = &r->link;
        }
        tail = &r->link;
    }
    if (back != NULL) {
        we_mod_list_post(&pl->to_thread, back);  /* the answers and the displaced maps go back together */
    }
    mod_transitions(pl, log, ud);                /* the planes' states after these results, logged on a change */
    return n;
}

int we_mod_planes_pending(const we_mod_planes_t *pl)
{
    return pl != NULL && __atomic_load_n(&pl->to_loop, __ATOMIC_RELAXED) != NULL;
}

/* the thread: an answered result folded into what the thread knows */
static void mod_ack(we_mod_planes_t *pl, mod_result_t *r)
{
    mod_plane_t *pp = &pl->plane[r->p];
    uint64_t mono = we_mod_monotonic_ms();

    if (r->kind == MOD_RES_LOG || r->kind == MOD_RES_NULL) {
        if (pp->inflight == r) {
            pp->inflight = NULL;
        }
        free(r);
        return;
    }
    pp->inflight = NULL;
    switch (r->kind) {
    case MOD_RES_PUBLISH:
        if (r->rc != WE_OK) {
            mod_fail_remember(pp, &pp->cand_I, r->rc == WE_ERR_ROLLBACK ? (pp->final ? "committed" : "rollback") : "publish",
                              r->map->digest);
            mod_mapping_release(r->map, pp->cand_mp);   /* never visible: released at once */
            pp->cand_mp = NULL;
            break;
        }
        if (pp->armed != NULL) {
            mod_retire_armed(pl, pp, mono);
        }
        pp->armed = r->map;
        pp->armed_mp = pp->cand_mp;
        pp->cand_mp = NULL;
        pp->I = pp->cand_I;
        memcpy(pp->arm_digest, r->map->digest, 32);
        pp->arm_seq++;
        pp->view = MOD_VIEW_ARMED;
        pp->final = 0;
        pp->rehash = 0;                          /* a publish cancels a queued re-digest */
        if (pl->cfg != NULL && pp->armed_mp != NULL && pl->sync == 0) {
            pp->armed_mp->locked = mlock(pp->armed_mp->addr, pp->armed_mp->len) == 0;
        }
        mod_state(pl, pp, "armed", NULL);
        break;
    case MOD_RES_DISARM:
        if (r->rc == WE_OK) {
            pp->view = MOD_VIEW_STANDIN;
            if (r->final) {
                pp->final = 1;
            }
            if (pp->final && pp->armed != NULL) {
                /* the bytes changed under the armed map: it is retired, and only a reload or the next
                 * generation re-arms: a copy at the name is remembered `committed`) */
                mod_retire_armed(pl, pp, mono);
                pp->armed = NULL;
                pp->armed_mp = NULL;
                pp->rehash = 0;
            }
        }
        break;
    case MOD_RES_REARM:
        if (r->rc == WE_OK) {
            pp->view = MOD_VIEW_ARMED;
            mod_state(pl, pp, "armed", NULL);
        }
        break;
    case MOD_RES_REVOKE:
        if (r->rc != WE_OK) {
            free(r->map);
            break;
        }
        if (pp->armed != NULL) {
            mod_retire_armed(pl, pp, mono);
        }
        pp->armed = r->map;
        pp->armed_mp = NULL;
        pp->arm_seq++;
        pp->view = MOD_VIEW_REVOKED;
        pp->rehash = 0;
        mod_state(pl, pp, "revoked", "tenant.bin is gone: the allow list is revoked");
        break;
    default:
        break;
    }
    free(r);
}

/* ---- arming a candidate, the one job a name change starts ---- */

/*
 * The candidate at the plane's name, identity `n` (from fstatat), admitted: the header first (a generation
 * not above the armed one and the high-water mark, or the armed digest again, refused without digesting
 * and remembered), a retire slot guaranteed, the trust checks, then the file opened and its identity
 * re-read. 0 with the descriptor left open and the peek in `pk`, `st` the identity the verification must
 * start from; non-zero when the candidate was refused or deferred, already remembered and logged by the
 * same rules the thread's tick uses. The caller owns the descriptor on 0. Shared by the thread's tick and
 * the monitor's discovery: neither digests what the other already refused.
 */
static int mod_candidate_admit(we_mod_planes_t *pl, mod_plane_t *pp, const mod_ident_t *n, we_mod_peek_t *pk,
                               struct stat *st, int *fd)
{
    char why[256];
    uint64_t above = __atomic_load_n(&pp->h.high_water, __ATOMIC_RELAXED);

    if (pp->armed != NULL && pp->view != MOD_VIEW_REVOKED && pp->armed->generation > above) {
        above = pp->armed->generation;
    }
    if (we_plane_peek(pp->dirfd, pp->name, pp->p + 1u, pk, why, sizeof why) != 0) {
        mod_fail_remember(pp, n, "header", NULL);
        mod_log(pl, "plane %s refused: %s", pp->name, why);
        if (pp->view == MOD_VIEW_NULL) {
            mod_state(pl, pp, "refused", "%s", why);
        }
        return -1;
    }
    if (pk->generation <= above) {
        mod_fail_remember(pp, n, pp->final ? "committed" : "rollback", pk->digest);
        mod_log(pl, "plane %s: generation %llu is not above %llu; refused by its header, not digested", pp->name,
                (unsigned long long)pk->generation, (unsigned long long)above);
        if (pp->view == MOD_VIEW_NULL) {
            mod_state(pl, pp, "refused", "generation %llu is not above %llu", (unsigned long long)pk->generation,
                      (unsigned long long)above);
        }
        return -1;
    }
    if (pp->armed != NULL && pp->view != MOD_VIEW_REVOKED && memcmp(pk->digest, pp->arm_digest, 32) == 0) {
        mod_fail_remember(pp, n, "unchanged", pk->digest);
        return -1;
    }
    if (!mod_retire_ready(pl, pp, "a new generation")) {
        return -1;                               /* nothing verified, nothing posted; retried next tick */
    }
    if (we_mod_plane_trust(pp->dirfd, pp->name, pl->uid, pp->legacy, fd, st, why, sizeof why) != 0) {
        mod_fail_remember(pp, n, "trust", pk->digest);
        mod_log(pl, "plane %s refused: %s", pp->name, why);
        if (pp->view == MOD_VIEW_NULL) {
            mod_state(pl, pp, "refused", "%s", why);
        }
        return -1;
    }
    {
        mod_ident_t got = mod_ident(st);

        if (!mod_ident_eq(&got, n)) {
            close(*fd);                          /* replaced between the fstatat and the open: next tick */
            return -1;
        }
    }
    return 0;
}

/*
 * A verification that failed: remembered with the reason the peek's digest earned, an EIO's backoff
 * bounded by what the armed data has left, said once. Shared by the thread's tick and the monitor, so a
 * candidate refused on one path is not digested again on the other: the failure memory holds it.
 */
#ifdef WE_MOD_TEST_DROP_ARMED
static void mod_disarm(we_mod_planes_t *pl, mod_plane_t *pp, int final, const char *why);
#endif
static void mod_verify_failed(we_mod_planes_t *pl, mod_plane_t *pp, const mod_ident_t *n, const uint8_t *peek_digest,
                              int eio, int rc, const char *why)
{
    mod_fail_t *f = mod_fail_remember(pp, n, eio ? "eio" : rc == WE_ERR_DIGEST ? "digest" : "structure", peek_digest);

    if (eio) {
        /* an EIO is retried after a backoff: one tick, doubling, never past what the armed data has left */
        uint64_t ceiling = pl->interval_ms != 0u ? 3600000u / pl->interval_ms : 60u;

        if (pp->armed != NULL && pp->view == MOD_VIEW_ARMED && pp->armed->valid_until_ms > pl->now_ms
                && pl->interval_ms != 0u) {
            uint64_t half = (pp->armed->valid_until_ms - pl->now_ms) / 2u / pl->interval_ms;

            ceiling = half < ceiling ? half : ceiling;
        } else {
            ceiling = 1u;                        /* stale, lapsed, disarmed or absent: exactly one tick */
        }
        f->backoff = f->backoff == 0u ? 1u : f->backoff * 2u;
        if (f->backoff > ceiling) {
            f->backoff = ceiling > 0u ? ceiling : 1u;
        }
        f->retry_tick = pl->tick + f->backoff;
        pp->eio_backoff_ticks = f->backoff;
    }
    mod_log(pl, "plane %s refused: %s", pp->name, why);
    if (pp->view == MOD_VIEW_NULL) {
        mod_state(pl, pp, "refused", "%s", why);
    }
#ifdef WE_MOD_TEST_DROP_ARMED
    if (pp->view == MOD_VIEW_ARMED) {
        mod_disarm(pl, pp, 0, why);              /* the control: a failed candidate drops the armed generation */
    }
#endif
}

/*
 * A verified candidate published: the result taken, the plane's candidate fields set, the state and the
 * line said, the post made. Returns the apply's rc when synchronous (the monitor's test for "this call
 * armed the plane"), 0 when asynchronous, -1 when the result could not be taken (the mapping released,
 * the candidate retried on a later pass).
 */
static int mod_candidate_publish(we_mod_planes_t *pl, mod_plane_t *pp, const mod_ident_t *n, we_map_t *m,
                                 mod_mapping_t *mp)
{
    mod_result_t *r = mod_result(pp->p, MOD_RES_PUBLISH, pp->arm_seq + 1u);

    pp->eio_backoff_ticks = 0u;
    if (r == NULL) {
        mod_mapping_release(m, mp);
        return -1;
    }
    r->map = m;
    r->expected = mod_view_ptr(pp);
    pp->cand_mp = mp;
    pp->cand_I = *n;
    if (pp->view == MOD_VIEW_NULL) {
        mod_state(pl, pp, "loading", NULL);    /* verified and posted: still -l until the loop arms it */
    }
    mod_log(pl, "plane %s: generation %llu verified, arming", pp->name, (unsigned long long)m->generation);
    return mod_post(pl, pp, r);
}

/*
 * The thread's one shot at a candidate: admit, verify the whole file in a buffer, publish. The monitor
 * shares every leg but drives them one budgeted chunk at a time.
 */
static void mod_candidate(we_mod_planes_t *pl, mod_plane_t *pp, const mod_ident_t *n, const int *stop)
{
    we_map_t *m;
    mod_mapping_t *mp;
    char why[256];
    struct stat st;
    we_mod_peek_t pk;
    int fd, eio, rc;

    if (mod_candidate_admit(pl, pp, n, &pk, &st, &fd) != 0) {
        return;
    }
    if (pp->view == MOD_VIEW_NULL) {
        mod_state(pl, pp, "loading", NULL);    /* being verified: -l until it arms or is refused */
    }
#ifdef WE_MOD_TEST_PAUSE_TICK
    if (!pl->sync) {
        if (pl->wake != NULL) {
            pl->wake(pl->wake_ud);             /* the word reaches the loop while the tick is held */
        }
        we_mod_test_pause("loading");
    }
#endif
    rc = mod_verify_map(fd, pp->name, &st, stop, pp->legacy, &m, &mp, &eio, why, sizeof why);
    if (rc != WE_OK) {
        close(fd);
        if (stop != NULL && __atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
            return;
        }
        mod_verify_failed(pl, pp, n, pk.digest, eio, rc, why);
        return;
    }
    (void)mod_candidate_publish(pl, pp, n, m, mp);
}

/* ---- the per-plane checks: the armed inode, a queued re-digest, then the name ---- */

static void mod_disarm(we_mod_planes_t *pl, mod_plane_t *pp, int final, const char *why)
{
    mod_result_t *r = mod_result(pp->p, MOD_RES_DISARM, pp->arm_seq);

    if (r == NULL) {
        return;
    }
    r->map = pp->standin;
    r->expected = pp->armed;
    r->final = final;
    mod_state(pl, pp, "disarmed", "%s", why);
    mod_log(pl, "plane %s disarmed: %s", pp->name, why);
    mod_post(pl, pp, r);
}

/* one plane's tick; `start` selects the worker-start check's rules (section 3.3) */
static void mod_plane_check(we_mod_planes_t *pl, mod_plane_t *pp, const int *stop, int start)
{
    struct stat st;
    char why[256];
    mod_ident_t n;

    if (!pp->bound || pp->inflight != NULL) {
        if (pp->inflight != NULL) {
            pp->pending_ticks++;
        }
        return;
    }
    pp->pending_ticks = 0u;
#ifdef WE_MOD_TEST_NO_START_STAT
    if (start) {
        return;                                  /* the control: the worker start looks at nothing; the inherited mapping serves */
    }
#endif
    /* 1. the armed inode, by its own descriptor */
    if (pp->armed_mp != NULL && !pp->final && (pp->view == MOD_VIEW_ARMED || pp->view == MOD_VIEW_STANDIN)
            && fstat(pp->armed_mp->fd, &st) == 0) {
        mod_ident_t d = mod_ident(&st);

        if (d.size != pp->I.size || d.size < pp->armed_mp->len || d.mt_s != pp->I.mt_s || d.mt_ns != pp->I.mt_ns) {
            if (start && d.size == pp->I.size && d.size >= pp->armed_mp->len) {
                /* worker start, the mtime alone: digested now, before the first accept */
                if (mod_redigest(pp, stop, &st, why, sizeof why) == 0) {
                    pp->I = mod_ident(&st);
                } else if (pp->view == MOD_VIEW_ARMED) {
                    /* final when a retire slot is free; else disarmed now and the final disarm retried */
                    if (mod_retire_ready(pl, pp, "final disarm")) {
                        mod_disarm(pl, pp, 1, why);
                    } else {
                        mod_disarm(pl, pp, 0, why);
                        pp->rehash = 2;
                        pp->rehash_seq = pp->arm_seq;
                    }
                    return;
                }
            } else if (pp->view == MOD_VIEW_ARMED) {
#ifdef WE_MOD_TEST_SERVE_INHERITED
                if (start) {
                    /* the control: noticed at the worker start, and the inherited mapping served until its job ends */
                    mod_log(pl, "plane %s: the armed file was rewritten in place; the inherited mapping serves until its "
                            "re-digest (the control)", pp->name);
                    pp->rehash = 2;
                    pp->rehash_seq = pp->arm_seq;
                    return;
                }
#endif
                /* row (c): rewritten in place; disarmed at once, re-digested by the next tick's job */
                mod_disarm(pl, pp, 0, "the armed file was rewritten in place (its size or mtime changed)");
                pp->rehash = 2;
                pp->rehash_seq = pp->arm_seq;
                return;
            }
        } else if (d.ct_s != pp->I.ct_s || d.ct_ns != pp->I.ct_ns) {
            /* row (b): ctime alone; the trust checks at once, then a re-digest */
            if (mod_trust_fd(pp, &st, pl->uid, why, sizeof why) != 0) {
                if (pp->view == MOD_VIEW_ARMED) {
                    mod_disarm(pl, pp, 0, why);
                }
                pp->I.ct_s = d.ct_s;             /* the disarm is for this ctime; a fix changes it again */
                pp->I.ct_ns = d.ct_ns;
                return;
            }
#ifndef WE_MOD_TEST_CTIME_NO_DIGEST
            if (pp->rehash == 0) {
                pp->rehash = 1;
                pp->rehash_seq = pp->arm_seq;
            }
#else
            pp->I.ct_s = d.ct_s;                 /* the control: the trust checks alone; the bytes never re-digested */
            pp->I.ct_ns = d.ct_ns;
#endif
        }
    }
    /* 2. a queued re-digest: equal re-arms (only if nothing was published or revoked since), else final */
    if (pp->rehash != 0 && pp->armed_mp != NULL && !start) {
        int kind = pp->rehash;

        pp->rehash = 0;
        if (mod_redigest(pp, stop, &st, why, sizeof why) == 0) {
            pp->I = mod_ident(&st);              /* the confirmed inode: the next tick finds nothing new */
            if (pp->view == MOD_VIEW_STANDIN && pp->rehash_seq == pp->arm_seq
                    && mod_trust_fd(pp, &st, pl->uid, why, sizeof why) == 0) {
                mod_result_t *r = mod_result(pp->p, MOD_RES_REARM, pp->arm_seq);

                if (r != NULL) {
                    r->map = pp->armed;
                    r->expected = pp->standin;
                    mod_log(pl, "plane %s re-armed: its bytes still carry the arm-time digest", pp->name);
                    mod_post(pl, pp, r);
                    return;
                }
            }
            /* confirmed and nothing posted: the name is still to be looked at this tick */
        } else {
            char fin[256];

            snprintf(fin, sizeof fin, "final: generation %llu is committed; a reload or generation %llu re-arms",
                     (unsigned long long)(pp->armed != NULL ? pp->armed->generation : 0u),
                     (unsigned long long)(pp->armed != NULL ? pp->armed->generation + 1u : 0u));
            if (!mod_retire_ready(pl, pp, "final disarm")) {
                /* no slot for the armed map: stop serving its changed bytes now, and retire it when one frees */
                if (pp->view == MOD_VIEW_ARMED) {
                    mod_disarm(pl, pp, 0, why);
                }
                pp->rehash = kind;
                return;
            }
            if (pp->view == MOD_VIEW_ARMED) {
                mod_disarm(pl, pp, 1, fin);
            } else {
                mod_result_t *r = mod_result(pp->p, MOD_RES_DISARM, pp->arm_seq);

                if (r != NULL) {                 /* already the stand-in: the disarm becomes final */
                    r->map = pp->standin;
                    r->expected = pp->standin;
                    r->final = 1;
                    mod_state(pl, pp, "disarmed", "%s", fin);
                    mod_log(pl, "plane %s disarmed: %s (%s)", pp->name, fin, why);
                    mod_post(pl, pp, r);
                }
            }
            (void)kind;
            return;
        }
    }
    /* 3. the name, through the held directory descriptor */
#ifndef WE_MOD_TEST_REOPEN_BY_PATH
    if (fstatat(pp->dirfd, pp->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
#else
    /* the control: the name reopened by its path string, so whatever the configured path names NOW is
     * read: a repointed link reads another directory, and its missing tenant.bin revokes */
    if (pp->path[0] != '\0' ? fstatat(AT_FDCWD, pp->path, &st, AT_SYMLINK_NOFOLLOW) != 0
                             : fstatat(pp->dirfd, pp->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
#endif
        if (errno == ENOENT) {
            if (pp->p + 1u == WE_PLANE_TENANT) {
                if (pp->view == MOD_VIEW_REVOKED || !mod_retire_ready(pl, pp, "revocation")) {
                    return;                      /* revoked already, or deferred: retried next tick */
                }
            }
            if (pp->p + 1u == WE_PLANE_TENANT) {
                mod_result_t *r = mod_result(pp->p, MOD_RES_REVOKE, pp->arm_seq + 1u);
                we_map_t *rv = we_map_new_revoked();

                if (r == NULL || rv == NULL) {
                    free(r);
                    free(rv);
                    return;
                }
                r->map = rv;
                r->expected = mod_view_ptr(pp);
                mod_log(pl, "plane tenant.bin is gone: the allow list is revoked");
                mod_post(pl, pp, r);
            } else if (!pp->said_absent) {
                pp->said_absent = 1;
                mod_log(pl, "plane %s is gone from the data directory; the armed generation serves until its valid-until",
                        pp->name);
                if (pp->view == MOD_VIEW_NULL) {
                    mod_state(pl, pp, "absent", NULL);
                }
            }
        } else if (!pp->said_errno) {
            pp->said_errno = 1;
            mod_log(pl, "plane %s: %s; nothing changes", pp->name, strerror(errno));
        }
        return;
    }
    pp->said_absent = pp->said_errno = 0;
    n = mod_ident(&st);
    if (pp->armed_mp != NULL && mod_ident_eq(&n, &pp->I)) {
        if (pp->view == MOD_VIEW_ARMED && pp->armed->valid_until_ms != 0u && pp->armed->valid_until_ms < pl->now_ms
                && !pp->said_stale) {
            pp->said_stale = 1;                  /* stale at once, never digested: the file is the verified one */
            mod_log(pl, "plane %s is stale: generation %llu's valid-until passed", pp->name,
                    (unsigned long long)pp->armed->generation);
        }
        return;
    }
    {
        mod_fail_t *f = mod_fail_find(pp, &n);

        if (f != NULL && !mod_fail_still(pp, f)) {
            mod_fail_drop(pp, f);                /* the same identity, another file: not remembered */
            f = NULL;
        }
        if (f != NULL) {
            if (f->retry_tick == 0u || pl->tick < f->retry_tick) {
                return;                          /* remembered: no digest */
            }
            /* an EIO's backoff has run out: retried; a successful read clears it */
            mod_fail_drop(pp, f);
        }
    }
    if (start && !(pp->armed == NULL || pp->view != MOD_VIEW_ARMED || pp->armed->valid_until_ms < pl->now_ms)) {
        return;                                  /* worker start, rule 6: the inherited mapping serves */
    }
    pp->said_stale = 0;
    mod_candidate(pl, pp, &n, stop);
}

/* ---- the supervisor's budgeted verification: the two the header declared ahead of their body ---- */

/*
 * The verification in progress dropped: its buffer released, its descriptor closed, its slot emptied.
 * The pconf cleanup runs this on a graceful restart mid-verification (row R2) and so does the binding's
 * own release, so nothing outlives the cycle that bound the planes. NULL and an empty slot are safe.
 */
static void mod_monitor_drop(we_mod_planes_t *pl)
{
    if (pl == NULL || pl->mon.p >= 8u) {
        return;
    }
    if (pl->mon.buf != NULL) {
        mod_verify_free(pl->mon.buf, pl->mon.len);
        pl->mon.buf = NULL;
    }
    if (pl->mon.fd >= 0) {
        close(pl->mon.fd);
        pl->mon.fd = -1;
    }
    pl->mon.p = 8u;
    pl->mon.redigest = 0;
    pl->mon.off = 0u;
    pl->mon.hdr = 0;
}

/*
 * A verification started: the descriptor held for the leg's duration, the identity and the peek's
 * digest kept for the failure memory (the armed inode's re-digest keeps neither: its failure disarms),
 * the DONTFORK buffer taken and the digest's mid-state initialised at zero bytes. `redigest` is 0 for a
 * candidate at the name, or the transition row's kind (1 ctime alone, 2 size or mtime) for the armed
 * inode's confirming re-digest. 0, or -1 with `why` when the size is out of bounds or the buffer
 * cannot be taken: nothing is remembered, so the next call attempts it again.
 */
static int mod_monitor_start(we_mod_planes_t *pl, uint32_t p, int redigest, int fd, const struct stat *st,
                             const mod_ident_t *I, const uint8_t peek[32], char *why, size_t whyn)
{
    mod_monitor_t *m = &pl->mon;
    size_t len = (size_t)st->st_size;

    if (st->st_size < (off_t)sizeof(we_header_t) || (uint64_t)st->st_size > MOD_VERIFY_MAX) {
        snprintf(why, whyn, "%lld bytes: a plane is %zu to %u bytes, so nothing was read", (long long)st->st_size,
                 sizeof(we_header_t), MOD_VERIFY_MAX);
        return -1;
    }
    m->buf = mod_verify_take(len, why, whyn);
    if (m->buf == NULL) {
        return -1;
    }
    m->p = p;
    m->redigest = redigest;
    m->fd = fd;
    m->st = *st;
    if (I != NULL) {
        m->I = *I;
    } else {
        memset(&m->I, 0, sizeof m->I);
    }
    if (peek != NULL) {
        memcpy(m->peek, peek, 32);
    } else {
        memset(m->peek, 0, 32);
    }
    m->len = len;
    m->off = 0u;
    m->hdr = 0;
    we_sha256_init(&m->ctx);
    return 0;
}

/*
 * One call's share of the read: 1 MiB chunks, each read by pread and fed to the digest's mid-state the
 * moment it lands. The bare 192-byte header with its digest field zeroed is the digest's first
 * contribution, made once the whole header is in the buffer (a short first read defers it; the body
 * bytes already read follow it then), and every body byte follows as it is read. The budget is checked
 * BEFORE each chunk, so a zero budget reads nothing: the buffer the call took is still held, and the
 * next call resumes at the chunk it stopped at. Under WE_MOD_TEST_MONITOR_BYTES the byte budget
 * stands in for the time budget (M8's determinism): the call reads chunks until it has read that many
 * bytes, so it stops at the first 1 MiB chunk boundary at or after the budget. 1 when the whole file
 * is read, 0 when the budget ran out with more to read, or the WE_ERR_* of the failed read (`*eio`
 * set, `why` in the one-shot path's own words).
 */
static int mod_monitor_read(we_mod_planes_t *pl, uint64_t deadline, int *eio, char *why, size_t whyn)
{
    mod_monitor_t *m = &pl->mon;

    *eio = 0;
    while (m->off < m->len) {
        size_t want = m->len - m->off < MOD_CHUNK ? m->len - m->off : MOD_CHUNK;
        ssize_t n;

#ifdef WE_MOD_TEST_MONITOR_BYTES
        (void)deadline;                      /* the control's budget is bytes, not the clock */
        if (m->bytes_last >= (uint64_t)WE_MOD_TEST_MONITOR_BYTES) {
            return 0;                        /* the byte budget spent: resumed on the next call */
        }
#else
        if (we_mod_monotonic_ms() >= deadline) {
            return 0;                        /* the time budget spent: resumed on the next call */
        }
#endif
        n = pread(m->fd, m->buf + m->off, want, (off_t)m->off);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            *eio = n < 0 && errno == EIO;
            snprintf(why, whyn, n < 0 ? "read: %s" : "the file shrank while it was read%s", n < 0 ? strerror(errno) : "");
            return n < 0 ? WE_ERR_OPEN : WE_ERR_TRUNCATED;
        }
        if (!m->hdr && m->off + (size_t)n >= sizeof(we_header_t)) {
            we_header_t bare;

            memcpy(&bare, m->buf, sizeof bare);
            memset(bare.digest, 0, 32);
            we_sha256_update(&m->ctx, &bare, sizeof bare);
            m->hdr = 1;
            if (m->off + (size_t)n > sizeof(we_header_t)) {
                we_sha256_update(&m->ctx, m->buf + sizeof(we_header_t), m->off + (size_t)n - sizeof(we_header_t));
            }
        } else if (m->hdr) {
            we_sha256_update(&m->ctx, m->buf + m->off, (size_t)n);
        }
        m->off += (size_t)n;
        m->bytes_last += (uint64_t)n;
        m->bytes_total += (uint64_t)n;
    }
    return 1;
}

/*
 * The armed inode's confirming re-digest failed: its bytes are not the armed ones any more, or could
 * not be read at all. The thread's own step 2 does the same: a retire slot frees the final disarm,
 * else the plane is disarmed now and the job queued again (`kind`) for the next pass. Logged once per
 * attempt, in the words the tick uses.
 */
static void mod_redigest_failed(we_mod_planes_t *pl, mod_plane_t *pp, int kind, const char *why)
{
    char fin[256];

    snprintf(fin, sizeof fin, "final: generation %llu is committed; a reload or generation %llu re-arms",
             (unsigned long long)(pp->armed != NULL ? pp->armed->generation : 0u),
             (unsigned long long)(pp->armed != NULL ? pp->armed->generation + 1u : 0u));
    if (!mod_retire_ready(pl, pp, "final disarm")) {
        /* no slot for the armed map: stop serving its changed bytes now, and retire it when one frees */
        if (pp->view == MOD_VIEW_ARMED) {
            mod_disarm(pl, pp, 0, why);
        }
        pp->rehash = kind;
        return;
    }
    if (pp->view == MOD_VIEW_ARMED) {
        mod_disarm(pl, pp, 1, fin);
    } else {
        mod_result_t *r = mod_result(pp->p, MOD_RES_DISARM, pp->arm_seq);

        if (r != NULL) {                     /* already the stand-in: the disarm becomes final */
            r->map = pp->standin;
            r->expected = pp->standin;
            r->final = 1;
            mod_state(pl, pp, "disarmed", "%s", fin);
            mod_log(pl, "plane %s disarmed: %s (%s)", pp->name, fin, why);
            mod_post(pl, pp, r);
        }
    }
}

/*
 * A completed read, finished: the digest finalised, then the buffer scanned through the loader's own
 * check, where the digest is CHECKED against the header's field, never recomputed, so no caller can
 * pass a buffer it did not digest; then the shared tail, where the file is mapped and the descriptor
 * re-fstat'ed and required unchanged. A candidate publishes through the same post the thread's tick
 * uses and sets the mask bit when the apply armed the plane; the armed inode's re-digest confirms by
 * comparing the computed digest with the arm-time digest: equal refreshes this process's I with the
 * identity its own re-fstat took (children forked after inherit it and pay no start-path digest),
 * re-arming through the conditional set-view (a compare-and-swap from the expected map, never retiring) when the drift had disarmed the plane, and anything
 * else disarms, final, by the thread's own arm. The monitor's slot is emptied either way.
 */
static void mod_monitor_finish(we_mod_planes_t *pl, uint32_t *armed_mask)
{
    mod_monitor_t *m = &pl->mon;
    mod_plane_t *pp = &pl->plane[m->p];
    we_map_t tmp, *map = NULL;
    mod_mapping_t *mp = NULL;
    we_load_detail_t d;
    char why[256];
    int rc;

    we_sha256_final(&m->ctx, m->digest);
    MOD_COUNT_DIGEST();
    rc = we_map_from_buffer_digest(m->buf, m->len, pp->name, &tmp, &d, m->digest);
    if (rc != WE_OK) {
        snprintf(why, sizeof why, "%s%s%s", we_strerror(rc), d.what != NULL ? ": " : "", d.what != NULL ? d.what : "");
        mod_verify_free(m->buf, m->len);
        m->buf = NULL;
        close(m->fd);
        m->fd = -1;
        m->verify_done++;
        if (m->redigest == 0) {
            mod_verify_failed(pl, pp, &m->I, m->peek, 0, rc, why);
        } else {
            mod_redigest_failed(pl, pp, m->redigest, why);
        }
        m->p = 8u;
        return;
    }
    rc = mod_verify_tail(m->fd, &m->st, m->buf, m->len, pp->legacy, &tmp, &map, &mp, why, sizeof why);
    m->buf = NULL;                             /* the tail released the buffer on every one of its paths */
    if (rc != WE_OK) {
        close(m->fd);                          /* the tail consumes the descriptor only on success */
        m->fd = -1;
        m->verify_done++;
        if (m->redigest == 0) {
            mod_verify_failed(pl, pp, &m->I, m->peek, 0, rc, why);
        } else {
            mod_redigest_failed(pl, pp, m->redigest, why);
        }
        m->p = 8u;
        return;
    }
    m->fd = -1;
    m->verify_done++;
    if (m->redigest != 0) {
        if (memcmp(map->digest, pp->arm_digest, 32) == 0) {
            pp->I = mod_ident(&m->st);         /* the confirmed inode: the next call finds nothing new */
            if (pp->view == MOD_VIEW_STANDIN && pp->rehash_seq == pp->arm_seq
                    && mod_trust_fd(pp, &m->st, pl->uid, why, sizeof why) == 0) {
                mod_result_t *r = mod_result(pp->p, MOD_RES_REARM, pp->arm_seq);

                if (r != NULL) {
                    r->map = pp->armed;
                    r->expected = pp->standin;
                    mod_log(pl, "plane %s re-armed: its bytes still carry the arm-time digest", pp->name);
                    if (mod_post(pl, pp, r) == 0) {
                        *armed_mask |= 1u << pp->p;
                    }
                }
            } else if (pp->view == MOD_VIEW_ARMED) {
                mod_log(pl, "plane %s: its bytes still carry the arm-time digest; the armed inode is confirmed", pp->name);
            }
        } else {
            mod_redigest_failed(pl, pp, m->redigest, "its bytes no longer carry the arm-time digest");
        }
        mod_mapping_release(map, mp);          /* the re-digest's own mapping: never published */
        m->p = 8u;
        return;
    }
    rc = mod_candidate_publish(pl, pp, &m->I, map, mp);
    if (rc == 0) {
        *armed_mask |= 1u << pp->p;            /* this call armed the plane */
    }
    m->p = 8u;
}

/*
 * A verification that failed mid-read: the candidate is remembered exactly as the thread's one shot
 * remembers it (the EIO's backoff bounded by what the armed data has left, the words kept); the armed
 * inode's re-digest runs the thread's own failure arm. The slot is emptied either way.
 */
static void mod_monitor_abort(we_mod_planes_t *pl, int rc, int eio, const char *why)
{
    mod_plane_t *pp = &pl->plane[pl->mon.p];

    if (pl->mon.redigest == 0) {
        mod_verify_failed(pl, pp, &pl->mon.I, pl->mon.peek, eio, rc, why);
    } else {
        mod_redigest_failed(pl, pp, pl->mon.redigest, why);
    }
    pl->mon.verify_done++;
    mod_monitor_drop(pl);
}

/*
 * One plane's armed inode, watched (rows (b) and (c) of the transition table): the descriptor's own
 * fstat against I. A ctime-only drift runs the trust checks at once; an untrusted inode disarms and
 * adopts the ctime, so the fix is a new drift, never a hammer. Any other drift disarms an armed plane
 * at once. Either way the confirming re-digest starts, budgeted, on a descriptor of its own, and a
 * job the last pass deferred (the rehash marker) runs when this pass reaches it. 1 when the
 * re-digest started, 0 when nothing is due.
 */
static int mod_monitor_armed(we_mod_planes_t *pl, mod_plane_t *pp, char *why, size_t whyn)
{
    mod_ident_t d;
    struct stat st;
    int kind, dupfd;

    if (pp->armed_mp == NULL || pp->final || (pp->view != MOD_VIEW_ARMED && pp->view != MOD_VIEW_STANDIN)
            || fstat(pp->armed_mp->fd, &st) != 0) {
        return 0;
    }
    d = mod_ident(&st);
    if (d.size == pp->I.size && d.size >= pp->armed_mp->len && d.mt_s == pp->I.mt_s && d.mt_ns == pp->I.mt_ns) {
        if (d.ct_s == pp->I.ct_s && d.ct_ns == pp->I.ct_ns) {
            return 0;                         /* the confirmed inode: nothing new */
        }
        /* row (b): ctime alone; the trust checks at once */
        if (mod_trust_fd(pp, &st, pl->uid, why, whyn) != 0) {
            if (pp->view == MOD_VIEW_ARMED) {
                mod_disarm(pl, pp, 0, why);
            }
            pp->I.ct_s = d.ct_s;               /* the disarm is for this ctime; a fix changes it again */
            pp->I.ct_ns = d.ct_ns;
            return 0;
        }
        kind = 1;
    } else {
        /* row (c): rewritten in place; disarmed at once, re-digested by this very job */
        if (pp->view == MOD_VIEW_ARMED) {
            mod_disarm(pl, pp, 0, "the armed file was rewritten in place (its size or mtime changed)");
        }
        kind = 2;
    }
    if (pp->rehash != 0) {
        kind = pp->rehash;                     /* a deferred pass's job: the kind it was queued with */
        pp->rehash = 0;                       /* the job runs now, cleared at run like the thread's step 2 */
    } else {
        pp->rehash_seq = pp->arm_seq;          /* the conditional set-view's key: nothing published or revoked since */
    }
    dupfd = fcntl(pp->armed_mp->fd, F_DUPFD_CLOEXEC, 0);
    if (dupfd < 0) {
        snprintf(why, whyn, "dup: %s", strerror(errno));
        pp->rehash = kind;                     /* not started: queued for the next call */
        return 0;
    }
    if (mod_monitor_start(pl, pp->p, kind, dupfd, &st, NULL, NULL, why, whyn) != 0) {
        pp->rehash = kind;                     /* the buffer could not be taken: queued for the next call */
        return 0;
    }
    return 1;
}

/*
 * One plane's bound name, watched: a new inode the thread's own rules admit is verified budgeted (the
 * admit peeks and remembers exactly as the tick does, so neither verifier digests what the other
 * refused); a candidate that verifies publishes through the same post the tick uses. The tenant
 * plane's absence revokes it, an absent data plane is said once, and any other errno is said once
 * and changes nothing, each as the tick says it. 1 when a verification started, 0 when nothing is due.
 */
static int mod_monitor_name(we_mod_planes_t *pl, mod_plane_t *pp, char *why, size_t whyn)
{
    we_mod_peek_t pk;
    mod_ident_t n;
    mod_fail_t *f;
    struct stat st;
    int fd;

    if (fstatat(pp->dirfd, pp->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            if (pp->p + 1u == WE_PLANE_TENANT) {
                if (pp->view == MOD_VIEW_REVOKED || !mod_retire_ready(pl, pp, "revocation")) {
                    return 0;                 /* revoked already, or deferred: the next call retries */
                }
                {
                    mod_result_t *r = mod_result(pp->p, MOD_RES_REVOKE, pp->arm_seq + 1u);
                    we_map_t *rv = we_map_new_revoked();

                    if (r != NULL && rv != NULL) {
                        r->map = rv;
                        r->expected = mod_view_ptr(pp);
                        mod_log(pl, "plane tenant.bin is gone: the allow list is revoked");
                        mod_post(pl, pp, r);
                    } else {
                        free(r);
                        free(rv);
                    }
                }
            } else if (!pp->said_absent) {
                pp->said_absent = 1;
                mod_log(pl, "plane %s is gone from the data directory; the armed generation serves until its valid-until",
                        pp->name);
                if (pp->view == MOD_VIEW_NULL) {
                    mod_state(pl, pp, "absent", NULL);
                }
            }
        } else if (!pp->said_errno) {
            pp->said_errno = 1;
            mod_log(pl, "plane %s: %s; nothing changes", pp->name, strerror(errno));
        }
        return 0;
    }
    pp->said_absent = pp->said_errno = 0;
    n = mod_ident(&st);
    if (pp->armed_mp != NULL && mod_ident_eq(&n, &pp->I)) {
        if (pp->view == MOD_VIEW_ARMED && pp->armed->valid_until_ms != 0u && pp->armed->valid_until_ms < pl->now_ms
                && !pp->said_stale) {
            pp->said_stale = 1;               /* stale at once, never digested: the file is the verified one */
            mod_log(pl, "plane %s is stale: generation %llu's valid-until passed", pp->name,
                    (unsigned long long)pp->armed->generation);
        }
        return 0;
    }
    f = mod_fail_find(pp, &n);
    if (f != NULL && !mod_fail_still(pp, f)) {
        mod_fail_drop(pp, f);                  /* the same identity, another file: not remembered */
        f = NULL;
    }
    if (f != NULL) {
        if (f->retry_tick == 0u || pl->tick < f->retry_tick) {
            return 0;                         /* remembered: no digest */
        }
        mod_fail_drop(pp, f);                  /* an EIO's backoff has run out: retried */
    }
    if (mod_candidate_admit(pl, pp, &n, &pk, &st, &fd) != 0) {
        return 0;
    }
    if (mod_monitor_start(pl, pp->p, 0, fd, &st, &n, pk.digest, why, whyn) != 0) {
        close(fd);
        mod_verify_failed(pl, pp, &n, pk.digest, 0, WE_ERR_MMAP, why);
        return 0;
    }
    if (pp->view == MOD_VIEW_NULL) {
        mod_state(pl, pp, "loading", NULL);    /* being verified across calls: -l until it arms or is refused */
    }
    return 1;
}

/*
 * What is due, found and driven: the in-flight verification first, then each bound plane's armed inode
 * ahead of its name, ONE verification at a time, each given the call's whole remaining budget; a
 * verification that completes with budget left lets the search continue, so a call spends its budget
 * the way the budget formula counts it (a 34 MB plane in ceil(B / (rate x budget)) calls, all of them).
 */
static void mod_monitor_due(we_mod_planes_t *pl, uint64_t deadline, uint32_t *armed_mask)
{
    mod_monitor_t *m = &pl->mon;
    char why[256];

    for (;;) {
        int eio = 0, rc;

        if (m->p >= 8u) {
            uint32_t p;

            for (p = 0u; p < 8u; p++) {
                mod_plane_t *pp = &pl->plane[p];

                if (!pp->bound || pp->inflight != NULL) {
                    continue;
                }
                if (mod_monitor_armed(pl, pp, why, sizeof why) != 0) {
                    break;                    /* the armed inode's re-digest started */
                }
                if (mod_monitor_name(pl, pp, why, sizeof why) != 0) {
                    break;                    /* a candidate at the name started */
                }
            }
        }
        if (m->p >= 8u) {
            return;                           /* nothing due: the mask says whether this call armed */
        }
        rc = mod_monitor_read(pl, deadline, &eio, why, sizeof why);
        if (rc == 0) {
            return;                           /* the budget spent mid-read: resumed on the next call */
        }
        if (rc < 0) {
            mod_monitor_abort(pl, rc, eio, why);
        } else {
            mod_monitor_finish(pl, armed_mask);
        }
    }
}

/* ---- the public calls ---- */

/*
 * The tenant high-water file, the revocation mark the keyed refresh writes (WE_MOD_HIGH_WATER_DEFAULT):
 * regular, owned by root or the trusted uid (the plane files' rule), closed to group and world, and holding
 * exactly [1-9][0-9]{0,18} and a newline, the grammar the keyed tier's oracle reads (tenant-state-case.sh),
 * so the two readers agree. 0 with the mark set, or none to read (no file: the line says a restored
 * pre-revocation tenant.bin would re-arm); -1 for a file present and malformed or untrusted, which is no
 * transition: the caller arms nothing on the tenant plane.
 */
static int mod_seed_high_water(we_mod_planes_t *pl, mod_plane_t *pp, const char *path)
{
    char buf[32];
    int fd = we_openat_cloexec(AT_FDCWD, path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    struct stat st;
    ssize_t r;
    size_t i, n;
    uint64_t v = 0u;

    if (fd < 0) {
        if (errno == ENOENT) {
            mod_log(pl, "tenant high-water: none (a restored pre-revocation tenant.bin would re-arm)");
            return 0;
        }
        snprintf(pp->reason, sizeof pp->reason, "the tenant high-water file %s cannot be read: %s; fix it and reload",
                 path, strerror(errno));
        return -1;
    }
#ifndef WE_MOD_TEST_HW_ROOT_ONLY
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_uid != 0u && st.st_uid != pl->uid)
            || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
#else
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0u || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u) {
#endif
        close(fd);
        snprintf(pp->reason, sizeof pp->reason, "the tenant high-water file %s is not a regular file owned by root "
                 "or uid %u and closed to group and world: chown root and chmod 0444 it, then reload", path, pl->uid);
        return -1;
    }
    r = read(fd, buf, sizeof buf - 1u);
    close(fd);
    n = r > 0 ? (size_t)r : 0u;
#ifndef WE_MOD_TEST_HW_LOOSE
    /* [1-9][0-9]{0,18}\n, nothing else: no sign, no space, no leading zero, at most 19 digits */
    for (i = 0u; i + 1u < n && buf[i] >= '0' && buf[i] <= '9'; i++) {
        v = v * 10u + (uint64_t)(buf[i] - '0');
    }
    if (r <= 0 || n < 2u || n > 20u || i != n - 1u || buf[n - 1u] != '\n' || buf[0] == '0') {
#else
    {
        char *end = NULL;

        buf[n] = '\0';
        errno = 0;
        v = strtoull(buf, &end, 10);          /* the control: the old reader, sign, space and zeros accepted */
        i = (size_t)(end - buf);
    }
    if (r <= 0 || i == 0u || errno != 0) {
#endif
        snprintf(pp->reason, sizeof pp->reason, "the tenant high-water file %s is not one generation and a newline "
                 "([1-9][0-9]{0,18}): rewrite it with the generation the revocation recorded, then reload", path);
        return -1;
    }
    pp->h.high_water = v;
    return 0;
}

/* the snapshot is the configuration's only data directive: no directory and no per-plane file */
static int mod_only_data_directive(const we_mod_bind_args_t *args)
{
    uint32_t p;

    if (args->data_dir != NULL) {
        return 0;
    }
    for (p = 0u; p < 8u; p++) {
        if (args->plane_file[p] != NULL) {
            return 0;
        }
    }
    return 1;
}

/* a directory path with its trailing slashes stripped, "/" itself kept: "/dir//" is "/dir" */
static size_t mod_dir_len(const char *d)
{
    size_t n = strlen(d);

    while (n > 1u && d[n - 1u] == '/') {
        n--;
    }
    return n;
}

int we_mod_bind_plane_path(const we_mod_bind_args_t *a, uint32_t p, char *buf, size_t len)
{
    const char *file = NULL;
    int n;

    if (a == NULL || p >= 8u || buf == NULL || len == 0u) {
        return 0;
    }
    buf[0] = '\0';
    file = a->plane_file[p];
    if (p == 0u && file == NULL && a->legacy_file != NULL) {
        file = a->legacy_file;
    }
    if (file != NULL) {
        n = snprintf(buf, len, "%s", file);
    } else if (a->data_dir != NULL) {
        size_t dl = mod_dir_len(a->data_dir);

        n = dl == 1u && a->data_dir[0] == '/' ? snprintf(buf, len, "/%s", mod_plane_file[p])
                                              : snprintf(buf, len, "%.*s/%s", (int)dl, a->data_dir, mod_plane_file[p]);
    } else {
        return 0;
    }
    return n < 0 || (size_t)n >= len ? -1 : 1;
}

#ifndef WE_MOD_TEST_COUNTERS_AT_ROOT                 /* its only callers are the two root refusals */
/* is DIR the filesystem root: the same (dev, ino) as "/", or, when it cannot be looked at, every component "" or "." */
static int mod_dir_is_root(const char *dir)
{
    struct stat a, r;
    const char *c;

    if (stat(dir, &a) == 0 && stat("/", &r) == 0) {
        return a.st_dev == r.st_dev && a.st_ino == r.st_ino;
    }
    for (c = dir; *c != '\0'; c++) {
        if (*c != '/' && !(*c == '.' && (c[1] == '/' || c[1] == '\0') && (c == dir || c[-1] == '/'))) {
            return 0;
        }
    }
    return dir[0] == '/';
}
#endif

#ifndef WE_MOD_TEST_COUNTERS_FIRST_DIR               /* its only caller is the one-directory rule */
/* the same directory: one (dev, ino), or, when either cannot be looked at, the same spelling */
static int mod_dir_same(const char *x, const char *y)
{
    struct stat a, b;

    if (stat(x, &a) == 0 && stat(y, &b) == 0) {
        return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    }
    return strcmp(x, y) == 0;
}
#endif

int we_mod_bind_counters_dir(const we_mod_bind_args_t *a, char *buf, size_t len, char *why, size_t whyn)
{
    char one[PATH_MAX], first[PATH_MAX];
    uint32_t p;
    int n, have = 0;

    if (a == NULL || buf == NULL || len == 0u) {
        return 0;
    }
    buf[0] = '\0';
    if (a->data_dir != NULL) {
        size_t dl = mod_dir_len(a->data_dir);

#ifndef WE_MOD_TEST_COUNTERS_AT_ROOT
        if (mod_dir_is_root(a->data_dir)) {
            /* never a directory created at /, however it is spelled: counting off, blocking unaffected */
            snprintf(why, whyn, "the data directory %s is /, so counters beside it would be created at /counters; "
                     "name the counters directory with whisper_edge_summary <dir>, or move the planes", a->data_dir);
            return -1;
        }
#endif
        n = dl == 1u && a->data_dir[0] == '/' ? snprintf(buf, len, "/counters")
                                              : snprintf(buf, len, "%.*s/counters", (int)dl, a->data_dir);
        return n < 0 || (size_t)n >= len ? -2 : 1;
    }
    /* no directory: beside the files the configuration names (the snapshot is the reputation plane's) */
    for (p = 0u; p < 8u; p++) {
        char path[PATH_MAX], dir[PATH_MAX];
        const char *slash;
        size_t dl;

        if (we_mod_bind_plane_path(a, p, path, sizeof path) != 1) {
            continue;
        }
        slash = strrchr(path, '/');
        dl = slash == NULL ? 0u : (size_t)(slash - path);
        snprintf(dir, sizeof dir, "%.*s", (int)(dl == 0u ? 1u : dl), dl == 0u ? "/" : path);
        if (!have) {
            snprintf(first, sizeof first, "%s", path);
            snprintf(one, sizeof one, "%s", dir);
            have = 1;
#ifndef WE_MOD_TEST_COUNTERS_FIRST_DIR
        } else if (!mod_dir_same(dir, one)) {
#else
        } else if (0) {                          /* the control: the first file's directory, whatever the others say */
#endif
            snprintf(why, whyn, "the configuration's data files are in more than one directory (%s and %s), so no "
                     "one place is beside them; name the counters directory with whisper_edge_summary <dir>", one, dir);
            return -1;
        }
    }
    if (!have) {
        return 0;
    }
#ifndef WE_MOD_TEST_COUNTERS_AT_ROOT
    if (mod_dir_is_root(one)) {
        /* a file at the filesystem root, however it is spelled: never a directory created at /; counting off */
        snprintf(why, whyn, "%s is at the filesystem root, so counters beside it would be created at /counters; "
                 "name the counters directory with whisper_edge_summary <dir>, or move the planes", first);
        return -1;
    }
#endif
    n = strcmp(one, "/") == 0 ? snprintf(buf, len, "/counters") : snprintf(buf, len, "%s/counters", one);
    return n < 0 || (size_t)n >= len ? -2 : 1;
}

const char *we_mod_plane_path(const we_mod_planes_t *pl, uint32_t p)
{
    return pl != NULL && p < 8u && pl->plane[p].path[0] != '\0' ? pl->plane[p].path : NULL;
}

/* a refused binding: the caller's configuration back to what it was before the call (see we_mod_bind) */
static void mod_bind_restore(we_mod_cfg_t *cfg, const we_mod_cfg_t *saved)
{
#ifndef WE_MOD_TEST_BIND_LEAVES_POINTERS
    *cfg = *saved;
#else
    (void)cfg;                                  /* the control: the configuration left pointing at the freed planes */
    (void)saved;
#endif
}

int we_mod_legacy_warning(const we_mod_bind_args_t *a, char *buf, size_t len)
{
    struct stat st;

    if (len > 0u) {
        buf[0] = '\0';
    }
    if (a == NULL || a->legacy_file == NULL || !mod_only_data_directive(a) || a->legacy_file[0] != '/'
            || stat(a->legacy_file, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;                                /* no legacy file, or one the bind refuses or finds absent */
    }
#ifndef WE_MOD_TEST_LEGACY_OWNER_SILENT
    if (st.st_uid != 0u && st.st_uid != a->uid) {
        snprintf(buf, len, "whisper edge: WARNING: the snapshot %s is owned by uid %u, neither root nor the workers' "
                 "uid %u, so that uid can rewrite it and decide whom this site blocks: chown root %s",
                 a->legacy_file, (unsigned)st.st_uid, a->uid, a->legacy_file);
        return 1;
    }
#endif
    return 0;
}

int we_mod_refused_sentence(char *buf, size_t len, uint32_t p, const char *reason)
{
    int n = snprintf(buf, len, "whisper edge: plane %s is refused at configuration and reads unknown until it is "
                     "fixed and the configuration reloaded; every other plane binds and serves: %s",
                     p < 8u ? we_mod_plane_word(p) : "?", reason != NULL ? reason : "");

    return n < 0 || (size_t)n >= len ? -1 : 0;
}

/*
 * Plane p refused at configuration: a file named in a way the trust rule or the path rule refuses, so
 * nothing is opened and nothing is bound. The plane reads `-r` (its static reason), its status and the
 * configuration file's plane line carry the reason with the fix, the caller's logger gets the one
 * sentence (we_mod_refused_sentence), and every other plane binds. 0; -1 under the control, which
 * refuses the whole binding instead, as the core did before.
 */
static int mod_bind_refuse_plane(we_mod_planes_t *pl, mod_plane_t *pp, we_mod_cfg_t *cfg, const char *reason,
                                 char *msg, size_t msgn)
{
    char line[WE_MOD_RING_ENTRY];

#ifdef WE_MOD_TEST_PLANE_REFUSAL_WHOLE
    snprintf(msg, msgn, "%s", reason);           /* the control: one refused plane refuses the binding */
    (void)pl; (void)pp; (void)cfg; (void)line;
    return -1;
#else
    (void)msg; (void)msgn;
    if (pp->own_dir && pp->dirfd >= 0) {
        close(pp->dirfd);
    }
    pp->dirfd = -1;
    pp->own_dir = 0;
    pp->legacy = 0;
    pp->config_refused = 1;
    mod_state(pl, pp, "refused", "%s", reason);   /* not bound: no word is posted, the static reason is the token */
    cfg->static_reason[pp->p] = WE_MOD_NOMAP_REFUSED;
    pl->null_reason[pp->p] = WE_MOD_NOMAP_REFUSED;
    if (we_mod_refused_sentence(line, sizeof line, pp->p, reason) == 0 || line[0] != '\0') {
        mod_log(pl, "%s", line);
    }
    return 0;
#endif
}

/*
 * The check-only bind's verification of one plane's file: what the bind's supervisor verification
 * does at configuration load (the header, the generation against the high-water mark, the trust checks,
 * every byte digested), read into a private buffer and released, so nothing is mapped and nothing armed.
 * The state is left "verified" or "refused" with the bind's own words.
 */
static void mod_check_file(we_mod_planes_t *pl, mod_plane_t *pp)
{
    struct stat st;
    mod_ident_t n;
    we_mod_peek_t pk;
    we_map_t *m = NULL;
    mod_mapping_t *mp = NULL;
    char why[256];
    int fd = -1, eio = 0, rc;

#ifndef WE_MOD_TEST_CHECK_NO_VERIFY
    if (fstatat(pp->dirfd, pp->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return;                                  /* gone between the peek and here: the fallback below names it */
    }
    n = mod_ident(&st);
    if (mod_candidate_admit(pl, pp, &n, &pk, &st, &fd) != 0) {
        return;
    }
    rc = mod_verify_map(fd, pp->name, &st, NULL, 1, &m, &mp, &eio, why, sizeof why);
    close(fd);
    if (rc != WE_OK) {
        mod_verify_failed(pl, pp, &n, pk.digest, eio, rc, why);
        return;
    }
    mod_mapping_release(m, mp);
#else
    (void)st; (void)n; (void)pk; (void)m; (void)mp; (void)why; (void)fd; (void)eio; (void)rc; (void)pl;
    /* the control: the check stops at the paths and the trust walks; the file is taken as verified */
#endif
    snprintf(pp->state, sizeof pp->state, "verified");
    pp->reason[0] = '\0';
}

/*
 * The bind, and the check-only bind (chk non-NULL): one pass, so the two cannot disagree on a path, a
 * trust walk, the conflict or a plane refused at configuration. In the check the configuration written
 * is a scratch one and nothing is logged; each plane's file is verified by mod_check_file instead of
 * being bound, and the planes are released before the call returns.
 */
static int mod_bind_run(we_mod_cfg_t *cfg, const we_mod_bind_args_t *args, we_mod_planes_t **out,
                        we_mod_plane_check_t *chk, char *msg, size_t msgn)
{
    we_mod_planes_t *pl;
    uint32_t p;
    int dirfd = -1;
    char why[256], dir_refused[PATH_MAX + 320];
    we_mod_cfg_t saved;

    if (out != NULL) {
        *out = NULL;
    }
    if (cfg == NULL || args == NULL) {
        snprintf(msg, msgn, "no configuration to bind");
        return WE_MOD_ERR_ARG;
    }
    if (args->abi != WE_MODULE_ABI_VERSION) {
        snprintf(msg, msgn, "the module was built against we_module.h ABI %u, and this we_module.c is ABI %u: "
                 "rebuild the module from one tree", (unsigned)args->abi, (unsigned)WE_MODULE_ABI_VERSION);
        return WE_MOD_ERR_ABI;
    }
    /*
     * A refused binding leaves the caller's configuration exactly as it was before the call: nothing bound,
     * or the previous binding intact. Every handle, stand-in and reason this call writes points into the
     * planes it releases on a refusal, so the configuration is restored before they go, on every path.
     */
    saved = *cfg;
    pl = (we_mod_planes_t *)calloc(1, sizeof *pl);
    if (pl == NULL) {
        snprintf(msg, msgn, "out of memory");
        return WE_ERR_MMAP;
    }
    pl->abi = args->abi;
    pl->cfg = cfg;
    pl->uid = args->uid;
    pl->now_ms = args->now_ms != 0u ? args->now_ms : mod_epoch_ms();
    pl->sync = 1;
    pl->dirfd = -1;
    pl->mon.p = 8u;                             /* no verification in flight; 8u is the none sentinel */
    pl->mon.fd = -1;
    pl->log = chk == NULL ? args->log : NULL;    /* the check says nothing: its caller prints the results */
#ifndef WE_MOD_TEST_DIGEST_SILENT
    /* a whole-buffer digest marks progress per MiB, so the bounded stop never abandons a thread digesting */
    we_sha256_progress = mod_progress;
#endif
    pl->log_ud = args->log_ud;
#ifdef WE_MOD_DEBUG
    if (chk == NULL) {
        mod_debug_tail_setup();                 /* the supervisor's: its forked workers inherit the page */
    }
#endif
    dir_refused[0] = '\0';
    if (args->data_dir != NULL) {
        struct stat st;

        /* the trailing slashes stripped, "/" kept, as every path composed over it is (we_mod_bind_plane_path) */
        snprintf(pl->data_dir, sizeof pl->data_dir, "%.*s", (int)mod_dir_len(args->data_dir), args->data_dir);
        if (we_mod_dir_open(pl->data_dir, args->uid, &dirfd, why, sizeof why) != 0) {
            /* refused for the planes it holds, each by name below; a plane with a file of its own still binds */
            snprintf(dir_refused, sizeof dir_refused, "whisper_edge_data %s: %s", args->data_dir, why);
            dirfd = -1;
        } else {
            if (fstat(dirfd, &st) == 0) {
                pl->dir_dev = (uint64_t)st.st_dev;
                pl->dir_ino = (uint64_t)st.st_ino;
            }
            pl->dirfd = dirfd;
        }
    }
    cfg->null_reason = pl->null_reason;
    cfg->bound_mask = 0u;
    for (p = 0u; p < 8u; p++) {
        mod_plane_t *pp = &pl->plane[p];
        we_mod_peek_t pk;
        int by_line = 0, named = 0;
        char refused[PATH_MAX + 320];

        refused[0] = '\0';
        pp->p = p;
        pp->name = mod_plane_file[p];
        pp->dirfd = dirfd;
        pp->view = MOD_VIEW_NULL;
        pp->h.module_owned = 1u;                 /* the core's publishes refuse on this handle */
        snprintf(pp->state, sizeof pp->state, "absent");
        cfg->handle[p] = NULL;
        cfg->standin[p] = NULL;
        cfg->static_reason[p] = WE_MOD_NOMAP_ABSENT;
        /* the one composition the configuration test uses too: the two can never name a file two ways */
#ifndef WE_MOD_TEST_PATH_TWICE
        if (we_mod_bind_plane_path(args, p, pp->path, sizeof pp->path) != 1) {
            pp->path[0] = '\0';
        }
#else
        if (args->data_dir != NULL) {            /* the control: the bind composing its own way, over the raw path */
            snprintf(pp->path, sizeof pp->path, "%s/%s", args->data_dir, mod_plane_file[p]);
        }
#endif
        {
            /* a file of the plane's own: a per-plane line, or the snapshot (the reputation plane's file) */
            const char *file = args->plane_file[p];
            const char *what = "whisper_edge_data";
            int legacy = 0;

#ifdef WE_MOD_TEST_PLANE_FILE_IGNORED
            file = NULL;                         /* the control: the per-plane line read as nothing */
#endif
#ifndef WE_MOD_TEST_SNAPSHOT_DROPPED
            if (p == 0u && args->legacy_file != NULL) {
#else
            if (p == 0u && args->legacy_file != NULL && args->data_dir == NULL) {   /* the control: ABI 4's silent drop */
#endif
                if (file != NULL) {
                    /* the one configuration error a binding refuses whole: two files for one plane */
                    snprintf(msg, msgn, "whisper_edge_snapshot %s and whisper_edge_data reputation %s both name the "
                             "reputation plane's file; keep one", args->legacy_file, file);
                    mod_bind_restore(cfg, &saved);
                    we_mod_planes_release(pl);
                    return WE_MOD_ERR_CONFIG;
                }
                file = args->legacy_file;
                what = "the snapshot file";
                legacy = mod_only_data_directive(args);   /* the legacy flag only as the one data directive */
                if (legacy && chk == NULL) {
                    char warn[WE_MOD_RING_ENTRY];

                    if (we_mod_legacy_warning(args, warn, sizeof warn) == 1) {
                        mod_log(pl, "%s", warn);      /* the file's owner: a warning, since the snapshot keeps 0644 */
                    }
                }
            }
            if (file != NULL) {
                char dir[PATH_MAX], *slash;
                int fd = -1;

                named = 1;
                pp->dirfd = -1;                  /* the data directory is not this plane's */
                snprintf(pp->path, sizeof pp->path, "%s", file);
                snprintf(dir, sizeof dir, "%s", file);
                slash = strrchr(dir, '/');
                if (file[0] != '/' || slash == NULL || slash[1] == '\0') {
                    snprintf(refused, sizeof refused, "%s %s must be an absolute path to a file: name it from /",
                             what, file);
                } else {
                    *slash = '\0';
                    pp->name = pp->path + (slash - dir) + 1;
                    if (we_mod_dir_open(dir[0] != '\0' ? dir : "/", args->uid, &fd, why, sizeof why) != 0) {
                        /* the walk's text names the component and the rule; the path is the operator's own */
                        snprintf(refused, sizeof refused, "%s %s: %s", what, file, why);
                    } else {
                        pp->dirfd = fd;
                        pp->own_dir = !legacy;
                        pp->legacy = legacy;
                        by_line = !legacy;       /* a per-plane line binds its plane, whatever reads it */
                    }
                }
            }
        }
        if (refused[0] == '\0' && !named && dir_refused[0] != '\0'
#ifndef WE_MOD_TEST_TENANT_BY_MASK
                && (((args->read_mask >> p) & 1u) != 0u || p + 1u == WE_PLANE_TENANT)) {
#else
                && ((args->read_mask >> p) & 1u) != 0u) {
#endif
            snprintf(refused, sizeof refused, "%s", dir_refused);   /* a plane the refused directory holds */
        }
        if (refused[0] != '\0') {
            if (mod_bind_refuse_plane(pl, pp, cfg, refused, msg, msgn) != 0) {
                mod_bind_restore(cfg, &saved);
                we_mod_planes_release(pl);
                return WE_MOD_ERR_CONFIG;
            }
            continue;
        }
#ifndef WE_MOD_TEST_TENANT_BY_MASK
        /* the tenant plane is read by the tenant step, before any program, so it is bound whenever present */
        if ((!by_line && ((args->read_mask >> p) & 1u) == 0u && p + 1u != WE_PLANE_TENANT) || pp->dirfd < 0) {
#else
        if ((!by_line && ((args->read_mask >> p) & 1u) == 0u) || pp->dirfd < 0) {  /* the control: tenant only on the caller's bit */
#endif
            continue;                            /* read by no program, or no directory: never bound */
        }
        if (we_plane_peek(pp->dirfd, pp->name, p + 1u, &pk, why, sizeof why) != 0) {
#ifdef WE_MOD_TEST_SNAPSHOT_FALLBACK
            /* the control: an earlier rule, a directory's snapshot.bin bound when reputation.bin is
             * absent, which the bind refuses (the tool and the probe report those rules inert) */
            if (pk.absent && p == 0u && !pp->legacy && !pp->own_dir && args->data_dir != NULL
                    && we_plane_peek(pp->dirfd, "snapshot.bin", 1u, &pk, why, sizeof why) == 0) {
                pp->name = "snapshot.bin";
            } else
#endif
            if (pk.absent && !pp->legacy) {
                continue;                        /* absent: inert, reported, not watched until a reload */
            }
#ifndef WE_MOD_TEST_UNREADABLE_BOUND
            if (pk.err == EACCES || pk.err == EPERM) {
                /* present and unreadable by the configuration reader: not absent, since the file is
                 * there, and not refused, since nothing was verified. Inert like an absent plane, its token
                 * `-u` from this static reason, and the configuration line says which uid and errno */
                cfg->static_reason[p] = WE_MOD_NOMAP_UNREADABLE;
                snprintf(pp->state, sizeof pp->state, "unreadable");
                snprintf(pp->reason, sizeof pp->reason, "%s", strerror((int)pk.err));
                continue;
            }
#endif
        }
        if (chk != NULL) {
            /* the check: the file verified as the bind's load would, nothing bound */
            if (p + 1u == WE_PLANE_TENANT
                    && mod_seed_high_water(pl, pp, args->high_water_file != NULL ? args->high_water_file
                                                                                 : WE_MOD_HIGH_WATER_DEFAULT) != 0) {
                snprintf(pp->state, sizeof pp->state, "refused");   /* no transition: nothing armed */
                continue;
            }
            pp->said_absent = 0;
            mod_check_file(pl, pp);
            if (strcmp(pp->state, "verified") != 0 && strcmp(pp->state, "refused") != 0) {
                if (pk.absent) {
                    snprintf(pp->state, sizeof pp->state, "absent");   /* the snapshot path not filled yet */
                } else {
                    snprintf(pp->state, sizeof pp->state, "refused");
                    snprintf(pp->reason, sizeof pp->reason, "no generation was verified at configuration load");
                }
            }
            continue;
        }
        pp->standin = we_mod_standin_new(p + 1u);
        if (pp->standin == NULL) {
            snprintf(msg, msgn, "out of memory");
            mod_bind_restore(cfg, &saved);
            we_mod_planes_release(pl);
            return WE_ERR_MMAP;
        }
        pp->bound = 1;
        cfg->handle[p] = &pp->h;
        cfg->standin[p] = pp->standin;
        cfg->static_reason[p] = WE_MOD_NOMAP_NONE;
        cfg->bound_mask = (uint8_t)(cfg->bound_mask | (1u << p));
        pl->null_reason[p] = WE_MOD_NOMAP_LOADING;
        pp->null_word = WE_MOD_NOMAP_LOADING;
        if (p + 1u == WE_PLANE_TENANT
                && mod_seed_high_water(pl, pp, args->high_water_file != NULL ? args->high_water_file
                                                                             : WE_MOD_HIGH_WATER_DEFAULT) != 0) {
            /* a malformed or untrusted mark is no transition: nothing armed, the plane refused with the fix */
            char why[sizeof pp->reason];

            snprintf(why, sizeof why, "%s", pp->reason);
            mod_state(pl, pp, "refused", "%s", why);
            mod_log(pl, "plane tenant.bin refused: %s", why);
            pl->null_reason[p] = WE_MOD_NOMAP_REFUSED;
            pp->null_word = WE_MOD_NOMAP_REFUSED;
            continue;
        }
        mod_plane_check(pl, pp, NULL, 0);        /* the supervisor's verification, before fork */
#ifndef WE_MOD_TEST_ABSENT_REFUSED
        if (pp->view == MOD_VIEW_NULL && strcmp(pp->state, "refused") != 0 && !pp->said_absent) {
#else
        if (pp->view == MOD_VIEW_NULL && strcmp(pp->state, "refused") != 0) {   /* the control: absent refused */
#endif
            /* a file there, nothing armed and nothing refused by name (replaced between its stat and its
             * open, or no retire slot): refused all the same, and the status says so as the token does.
             * No file at all (a snapshot path the refresh has not filled) stays absent: nothing failed */
            mod_state(pl, pp, "refused", "no generation was verified at configuration load");
        }
        if (pp->view == MOD_VIEW_NULL) {
            uint32_t w = pp->said_absent ? WE_MOD_NOMAP_ABSENT : WE_MOD_NOMAP_REFUSED;

            pl->null_reason[p] = w;
            pp->null_word = w;
        }
    }
    pl->sync = 0;
    if (chk != NULL) {
        for (p = 0u; p < 8u; p++) {
            const mod_plane_t *pp = &pl->plane[p];
            we_mod_plane_check_t *c = &chk[p];

            memset(c, 0, sizeof *c);
            snprintf(c->path, sizeof c->path, "%s", pp->path);
            snprintf(c->reason, sizeof c->reason, "%s", pp->reason);
            c->config_refused = (uint8_t)pp->config_refused;
            if (strcmp(pp->state, "verified") == 0) {
                c->code = WE_MOD_NOMAP_NONE;
            } else if (strcmp(pp->state, "refused") == 0) {
                c->code = WE_MOD_NOMAP_REFUSED;
            } else if (strcmp(pp->state, "unreadable") == 0) {
                c->code = WE_MOD_NOMAP_UNREADABLE;
            } else {
                c->code = WE_MOD_NOMAP_ABSENT;
            }
            snprintf(c->state, sizeof c->state, "%s", pp->state);
        }
        we_mod_planes_release(pl);
        return 0;
    }
    *out = pl;
    return 0;
}

int we_mod_bind(we_mod_cfg_t *cfg, const we_mod_bind_args_t *args, we_mod_planes_t **out, char *msg, size_t msgn)
{
    if (out == NULL) {
        snprintf(msg, msgn, "no planes pointer to bind into");
        return WE_MOD_ERR_ARG;
    }
    return mod_bind_run(cfg, args, out, NULL, msg, msgn);
}

int we_mod_bind_check(const we_mod_bind_args_t *args, we_mod_plane_check_t out[8], char *msg, size_t msgn)
{
    we_mod_cfg_t scratch;

    if (out == NULL) {
        snprintf(msg, msgn, "no results to fill");
        return WE_MOD_ERR_ARG;
    }
    memset(&scratch, 0, sizeof scratch);
    memset(out, 0, 8u * sizeof *out);
    return mod_bind_run(&scratch, args, NULL, out, msg, msgn);
}

const char *we_mod_plane_config_refusal(const we_mod_planes_t *pl, uint32_t p)
{
    return pl != NULL && p < 8u && pl->plane[p].config_refused ? pl->plane[p].reason : NULL;
}

int we_mod_worker_start(we_mod_planes_t *pl, const we_mod_worker_args_t *w, char *msg, size_t msgn)
{
    uint32_t p;

    if (pl == NULL || w == NULL) {
        snprintf(msg, msgn, "no planes bound");
        return WE_MOD_ERR_ARG;
    }
    if (__atomic_load_n(&pl->ticked, __ATOMIC_ACQUIRE)) {
        snprintf(msg, msgn, "the thread already ticks: we_mod_worker_start() runs before the thread is started");
        return WE_MOD_ERR_ARG;
    }
#ifndef WE_MOD_TEST_FORK_KEEPS_MONITOR
    if (pl->mon.p < 8u) {
        /* a verification the parent's monitor had in flight when this process forked: its buffer was
         * MADV_DONTFORK and is not here, so it is forgotten, never unmapped (the address may be reused); its
         * descriptor would hold a replaced plane's inode open for this process's life, so it is closed; and
         * the held figure it added is the parent's, not this process's */
        if (pl->mon.fd >= 0) {
            close(pl->mon.fd);
        }
        if (pl->mon.buf != NULL) {
            __atomic_sub_fetch(&g_mod_verify_now, (uint64_t)pl->mon.len, __ATOMIC_RELAXED);
        }
        pl->mon.buf = NULL;
        pl->mon.fd = -1;
        pl->mon.p = 8u;
        pl->mon.redigest = 0;
        pl->mon.off = 0u;
        pl->mon.hdr = 0;
    }
#endif
    pl->wake = w->wake;
    pl->wake_ud = w->wake_ud;
    pl->log = w->log;
    pl->log_ud = w->log_ud;
    pl->interval_ms = w->interval_ms;
    pl->now_ms = w->now_ms != 0u ? w->now_ms : mod_epoch_ms();
    pl->sync = 1;
#ifdef WE_MOD_DEBUG
    __atomic_store_n(&g_mod_digests, 0u, __ATOMIC_RELAXED);   /* this process's own counts from here */
    __atomic_store_n(&g_mod_digests_start, 0u, __ATOMIC_RELAXED);
    __atomic_store_n(&g_mod_in_start, 1, __ATOMIC_RELAXED);
#endif
    for (p = 0u; p < 8u; p++) {
        mod_plane_t *pp = &pl->plane[p];

        mod_plane_check(pl, pp, NULL, 1);
        if (pp->armed_mp != NULL && pp->view == MOD_VIEW_ARMED && !pp->armed_mp->locked) {
            pp->armed_mp->locked = mlock(pp->armed_mp->addr, pp->armed_mp->len) == 0;
            if (!pp->armed_mp->locked) {
                mod_log(pl, "plane %s: mlock of %zu bytes failed (%s); the pages may be evicted under memory pressure",
                        pp->name, pp->armed_mp->len, strerror(errno));
            }
        }
    }
    pl->sync = 0;
#ifdef WE_MOD_DEBUG
    __atomic_store_n(&g_mod_in_start, 0, __ATOMIC_RELAXED);
#endif
    mod_transitions_baseline(pl, mod_epoch_ms());   /* what this worker inherited: its first apply compares to it */
    __atomic_store_n(&pl->worker_started, 1, __ATOMIC_RELEASE);
    msg[0] = '\0';
    return 0;
}

static void mod_planes_tick_body(void *planes, uint64_t tick, const int *stop);

void we_mod_planes_tick(void *planes, uint64_t tick, const int *stop)
{
    uint32_t was = mod_stage_now();

    we_mod_thread_stage(WE_MOD_STAGE_PLANES);   /* the plane jobs: the one stage a stalled stop abandons */
    mod_planes_tick_body(planes, tick, stop);
    we_mod_thread_stage(was);
}

static void mod_planes_tick_body(void *planes, uint64_t tick, const int *stop)
{
    we_mod_planes_t *pl = (we_mod_planes_t *)planes;
    we_mod_item_t *l;
    uint64_t mono = we_mod_monotonic_ms();
    uint32_t p;
    int posted = 0;
    uint64_t nulls;

    if (pl == NULL) {
        return;
    }
    nulls = pl->nulls_posted;
    if (!__atomic_load_n(&pl->worker_started, __ATOMIC_ACQUIRE)) {
        pl->ticks_before_start++;                /* the order broken: nothing done, counted */
        return;
    }
    __atomic_store_n(&pl->ticked, 1, __ATOMIC_RELEASE);
#ifdef WE_MOD_TEST_PAUSE_TICK
    we_mod_test_pause("tick");                   /* the gate's debug hook: the whole tick held until released */
#endif
    pl->tick = tick;
    pl->now_ms = mod_epoch_ms();
    pl->lines_this_tick = 0u;
    /* the loop's answers, and the maps it displaced */
    for (l = we_mod_list_take(&pl->to_thread); l != NULL;) {
        mod_result_t *r = (mod_result_t *)(void *)l;

        l = l->next;
        mod_ack(pl, r);
    }
    for (p = 0u; p < 8u; p++) {
        we_mod_retire_sweep(&pl->plane[p].retire, mono, WE_DEFAULT_GRACE_MS);
    }
    /* a data directory swapped under its path changes nothing read, and is said */
    if (pl->data_dir[0] != '\0') {
        struct stat st;

        if (stat(pl->data_dir, &st) == 0 && ((uint64_t)st.st_dev != pl->dir_dev || (uint64_t)st.st_ino != pl->dir_ino)) {
            if (!pl->dir_replaced) {
                mod_log(pl, "the data directory %s was replaced under its path; reload to apply", pl->data_dir);
            }
            pl->dir_replaced = 1;
        }
    }
    for (p = 0u; p < 8u; p++) {
        mod_plane_t *pp = &pl->plane[p];
        mod_result_t *before = pp->inflight;

        pp->state_ticks++;

        if (stop != NULL && __atomic_load_n(stop, __ATOMIC_ACQUIRE)) {
            break;
        }
        mod_plane_check(pl, pp, stop, 0);
        posted |= pp->inflight != NULL && pp->inflight != before;
    }
    if (pl->log_head < pl->npending_log) {
        mod_flush_log(pl);
        posted = 1;
    }
    posted |= pl->nulls_posted != nulls;
    if (posted && pl->wake != NULL) {
        pl->wake(pl->wake_ud);
    }
}

void we_mod_planes_status(const we_mod_planes_t *pl, we_mod_status_t *s, uint64_t now_ms)
{
    uint32_t p;

    if (pl == NULL) {
        return;
    }
    for (p = 0u; p < 8u; p++) {
        const mod_plane_t *pp = &pl->plane[p];
        we_mod_plane_status_t *ps = &s->plane[p];
        const we_map_t *m = pp->armed;

        memset(ps, 0, sizeof *ps);
        ps->bound = (uint8_t)pp->bound;
        snprintf(ps->state, sizeof ps->state, "%s", pp->state);
        snprintf(ps->reason, sizeof ps->reason, "%s", pp->reason);
        if (pp->view == MOD_VIEW_ARMED && m != NULL && m->valid_until_ms != 0u && m->valid_until_ms < now_ms) {
            snprintf(ps->state, sizeof ps->state, "stale");
        }
        ps->pending = pp->inflight != NULL;
        ps->pending_ticks = pp->pending_ticks;
        ps->deferred = pp->deferred;
        ps->posted = pp->posted;
        ps->since_ms = pp->since_ms;
        ps->eio_backoff_ms = pp->eio_backoff_ticks * pl->interval_ms;
        ps->dir_replaced = (uint8_t)pl->dir_replaced;
        if (m != NULL && pp->view != MOD_VIEW_REVOKED) {
            ps->generation = m->generation;
            ps->valid_until_ms = m->valid_until_ms;
            ps->remaining_ms = (int64_t)(m->valid_until_ms - now_ms);
            ps->country_table = m->country_table_version;
            we_digest16(m->digest, ps->digest16);
        } else {
            snprintf(ps->digest16, sizeof ps->digest16, "-");
        }
        ps->ticks = pp->state_ticks;
        ps->measured |= WE_MOD_MEASURED_TICKS;
        if (pp->armed_mp != NULL && pp->view == MOD_VIEW_ARMED && pp->armed_mp->built_at_ms != 0u) {
            /* signed: a publisher's clock ahead of this host's reads negative, and that is the point of it */
            ps->slot_age_ms = (int64_t)(now_ms - pp->armed_mp->built_at_ms);
            ps->measured |= WE_MOD_MEASURED_SLOT_AGE;
        }
        if (pp->armed_mp != NULL) {
            int fl = 0;
            long pg = sysconf(_SC_PAGESIZE);

            ps->mapped = (uint8_t)!pp->armed_mp->private;   /* the legacy file's private copy prints `private` */
            ps->locked = (uint8_t)pp->armed_mp->locked;
            ps->bytes = pp->armed_mp->len;
            if (ioctl(pp->armed_mp->fd, FS_IOC_GETFLAGS, &fl) == 0) {
                ps->immutable = (uint8_t)((fl & FS_IMMUTABLE_FL) != 0);
                ps->measured |= WE_MOD_MEASURED_IMMUTABLE;
            }
            if (pg > 0) {
                size_t npg = (pp->armed_mp->len + (size_t)pg - 1u) / (size_t)pg, i;
                unsigned char *v = (unsigned char *)malloc(npg != 0u ? npg : 1u);

                if (v != NULL && mincore(pp->armed_mp->addr, pp->armed_mp->len, v) == 0) {
                    for (i = 0u; i < npg; i++) {
                        ps->nonresident += (v[i] & 1u) == 0u;
                    }
                    ps->measured |= WE_MOD_MEASURED_NONRESIDENT;
                }
                free(v);
            }
        }
    }
    {
        struct rusage ru;
        we_mod_planes_t *w = (we_mod_planes_t *)(uintptr_t)pl;   /* the delta's last value: the thread's own */

        if (getrusage(RUSAGE_SELF, &ru) == 0) {
            if (w->majflt_seen) {
                s->majflt_delta = (uint64_t)ru.ru_majflt - w->majflt_last;
                s->measured |= WE_MOD_MEASURED_MAJFLT;
            }
            w->majflt_last = (uint64_t)ru.ru_majflt;
            w->majflt_seen = 1;
        }
    }
    s->retired = pl->retired;
    s->retire_lost = pl->retire_lost;
    s->ticks_before_start = pl->ticks_before_start;
    s->verify_held = __atomic_load_n(&g_mod_verify_now, __ATOMIC_RELAXED);
    s->verify_peak = __atomic_load_n(&g_mod_verify_peak, __ATOMIC_RELAXED);
    s->log_dropped = pl->log_dropped;
    s->failure_evicted = 0u;
    for (p = 0u; p < 8u; p++) {
        s->failure_evicted += pl->plane[p].evicted;
    }
    s->ntransitions = pl->ntransitions;          /* the ring, the newest WE_MOD_TRANSITIONS entries */
    memcpy(s->transition_ms, pl->transition_ms, sizeof s->transition_ms);
    memcpy(s->transition, pl->transition, sizeof s->transition);
}

/*
 * The supervisor's budgeted verification, one call of it (the header's contract): bind-time rules
 * hold for the call's duration, so every result applies at once and every line goes to the supervisor's
 * own logger, and the arm-time mlock stays each serving process's worker-start job. The parent's tick
 * advances one per call, so an EIO's backoff elapses across monitor calls exactly as it elapses across
 * the thread's ticks. A serving process is refused: one whose worker started, or whose thread ticked,
 * has no supervisor's job. Returns 1 when this call armed something (the planes in *armed_mask), 0 when
 * nothing is due or the work continues on the next call, WE_MOD_ERR_ARG on misuse.
 */
int we_mod_planes_monitor(we_mod_planes_t *pl, uint64_t budget_ms, uint32_t *armed_mask)
{
    uint64_t deadline;

    if (armed_mask != NULL) {
        *armed_mask = 0u;
    }
    if (pl == NULL || armed_mask == NULL) {
        return WE_MOD_ERR_ARG;               /* no binding to watch, or nowhere to say what armed */
    }
    if (__atomic_load_n(&pl->worker_started, __ATOMIC_ACQUIRE)
            || __atomic_load_n(&pl->ticked, __ATOMIC_ACQUIRE)) {
        return WE_MOD_ERR_ARG;               /* a serving process has no supervisor's job */
    }
#ifdef WE_MOD_TEST_PAUSE_TICK
    we_mod_test_pause("monitor");                /* the gate's debug hook: the supervisor's check held until released */
#endif
    pl->mon.calls++;
    pl->now_ms = mod_epoch_ms();
    deadline = we_mod_monotonic_ms() + budget_ms;
    pl->mon.bytes_last = 0u;
    pl->sync = 1;                            /* bind-time rules: apply at once, log at once, no mlock */
    pl->tick++;
    mod_monitor_due(pl, deadline, armed_mask);
    pl->sync = 0;
    return *armed_mask != 0u ? 1 : 0;
}

/* the pconf cleanup: a verification in progress and its DONTFORK buffer, dropped */
void we_mod_planes_monitor_release(we_mod_planes_t *pl)
{
    mod_monitor_drop(pl);
}

/* the monitor's own counters, read by the debug build for the prefork re-verification row */
void we_mod_planes_monitor_counts(const we_mod_planes_t *pl, uint64_t *calls, uint64_t *bytes_last_call,
                                  uint64_t *bytes_total, uint64_t *verifications)
{
    uint64_t z = 0u;

    if (calls != NULL) {
        *calls = pl != NULL ? pl->mon.calls : z;
    }
    if (bytes_last_call != NULL) {
        *bytes_last_call = pl != NULL ? pl->mon.bytes_last : z;
    }
    if (bytes_total != NULL) {
        *bytes_total = pl != NULL ? pl->mon.bytes_total : z;
    }
    if (verifications != NULL) {
        *verifications = pl != NULL ? pl->mon.verify_done : z;
    }
}

/*
 * Every mapping, descriptor and item the binding holds, released: the supervisor's, when the cycle that
 * bound the planes is released (nginx keeps it until then). Never on a worker's live configuration.
 */
void we_mod_planes_release(we_mod_planes_t *pl)
{
    uint32_t p, i;
    we_mod_item_t *l;

    if (pl == NULL) {
        return;
    }
    mod_monitor_drop(pl);                     /* a verification in progress and its buffer: part of what the binding holds */
    for (l = we_mod_list_take(&pl->to_loop); l != NULL;) {
        mod_result_t *r = (mod_result_t *)(void *)l;

        l = l->next;
        free(r);
    }
    for (l = we_mod_list_take(&pl->to_thread); l != NULL;) {
        mod_result_t *r = (mod_result_t *)(void *)l;

        l = l->next;
        free(r);
    }
    for (p = 0u; p < 8u; p++) {
        mod_plane_t *pp = &pl->plane[p];

        for (i = 0u; i < WE_MOD_RETIRE_SLOTS; i++) {
            if (pp->retire.slot[i].map != NULL && pp->retire.slot[i].release != NULL) {
                pp->retire.slot[i].release(pp->retire.slot[i].map, pp->retire.slot[i].ud);
            }
        }
        if (pp->armed != NULL) {
            if (pp->armed_mp != NULL) {
                mod_mapping_release(pp->armed, pp->armed_mp);
            } else {
                free(pp->armed);
            }
        }
        free(pp->standin);
        if ((pp->legacy || pp->own_dir) && pp->dirfd >= 0) {
            close(pp->dirfd);
        }
    }
    if (pl->dirfd >= 0) {
        close(pl->dirfd);
    }
    free(pl);
}

#ifdef WE_MOD_DEBUG
/*
 * The debug build's seam for the identity-collision row: remember the file now at plane p's name as a
 * failure of another file, under its fstatat identity and a header digest it does not carry, which is the
 * state an inode reused inside one timestamp tick leaves. 0, or -1 when nothing is at the name.
 */
int we_mod_debug_remember_other(we_mod_planes_t *pl, uint32_t p)
{
    mod_plane_t *pp;
    struct stat st;
    mod_ident_t n;
    uint8_t other[32];

    if (pl == NULL || p >= 8u) {
        return -1;
    }
    pp = &pl->plane[p];
    if (fstatat(pp->dirfd, pp->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    n = mod_ident(&st);
    memset(other, 0xA5, sizeof other);
    (void)mod_fail_remember(pp, &n, "digest", other);
    return 0;
}
#endif
