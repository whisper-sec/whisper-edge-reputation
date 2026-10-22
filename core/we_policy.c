/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The full licence text is in LICENSE.
 */
/*
 * we_policy.c - the policy compiler, the verifier, the printer and the outage classifier. Cold: none of
 * this runs in a request.
 *
 * A configuration's directives go through eight layers, in this order, so an input with two faults has
 * one answer (POLICY.md §1.5): (1) the argument length, before anything is read; (2) the first byte outside
 * the alphabet; (3) lexing; (4) parsing; (5) typing; (6) set resolution, once every directive has been
 * seen, because a set may be declared after the rule that uses it; (7) the program limits; (8) the
 * polarity pass. Each layer runs over every directive in source order before the next layer starts.
 *
 * The compiler never recurses without a depth check (the grammar's only recursion is bounded by the
 * nesting limit, 16), never keeps a pointer into the caller's directive buffers once it returns, never
 * accepts trailing input, and frees everything it allocated on every path.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#define WE_COUNTRY_ALPHA2 1
#include "we_policy.h"
#include "we_sha256.h"
#include "we_procid.h"
#include "we_country_table.h"
#include "we_hold_harmless.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Under AddressSanitizer every arena request is its own heap allocation, so ASan's redzones sit after
 * each temporary and a write past one is reported at the write as a heap-buffer-overflow, instead of
 * landing silently in the next temporary of the same 64 KiB chunk; the rounding to 16 bytes is
 * poisoned too, so a write into it is reported (use-after-poison) rather than absorbed.
 */
#if defined(__SANITIZE_ADDRESS__)
#define WE_ARENA_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define WE_ARENA_ASAN 1
#endif
#endif
#ifdef WE_ARENA_ASAN
#include <sanitizer/asan_interface.h>
#define WE_ARENA_ONE_EACH 1                    /* one heap allocation per request */
#define WE_ARENA_POISON(p, n)   ASAN_POISON_MEMORY_REGION((p), (n))
#define WE_ARENA_UNPOISON(p, n) ASAN_UNPOISON_MEMORY_REGION((p), (n))
#else
#define WE_ARENA_ONE_EACH 0
#define WE_ARENA_POISON(p, n)   ((void)(p), (void)(n))
#define WE_ARENA_UNPOISON(p, n) ((void)(p), (void)(n))
#endif

/* ======================================================================================================
 * The vocabulary
 * ==================================================================================================== */

#define NPLANES 8u
static const char *const plane_name[NPLANES] = {
    "reputation", "tor", "rpki-unreachable", "routing", "anonymizer", "threat", "registry", "tenant"
};
/* the keyless planes decision 3's default reads; every other plane needs a key */
#define KEYED_MASK 0xf8u   /* routing, anonymizer, threat, registry, tenant */

/* attribute classes */
#define AC_BOOL    1u
#define AC_LEVEL   2u
#define AC_ENUM    3u
#define AC_ASN     4u
#define AC_COUNTRY 5u

/* enum domains */
#define D_RPKI   1u
#define D_REASON 2u
#define D_REP    3u
#define D_RIR    4u

typedef struct {
    const char *name;
    uint8_t     cls;
    uint8_t     dom;
    uint8_t     plane;      /* plane_id - 1 */
    uint8_t     off;        /* in the normalised block */
    uint8_t     mask;       /* bool: the bit */
    uint8_t     sentinel;   /* has `undetermined` */
    uint8_t     ndom;       /* enum: values 0..ndom-1 (0 is undetermined) */
} attr_t;

#define A_INFERRED 0
static const attr_t attrs[] = {
    { "inferred",         AC_BOOL,    0,        0, 0, 0x80u, 0, 0 },
    { "rpki_unreachable", AC_BOOL,    0,        2, 0, 0x01u, 0, 0 },
    { "tor_exit",         AC_BOOL,    0,        1, 0, 0x01u, 0, 0 },
    { "proxy",            AC_BOOL,    0,        4, 0, 0x01u, 0, 0 },
    { "vpn",              AC_BOOL,    0,        4, 0, 0x02u, 0, 0 },
    { "c2",               AC_BOOL,    0,        5, 0, 0x01u, 0, 0 },
    { "bruteforce",       AC_BOOL,    0,        5, 0, 0x02u, 0, 0 },
    { "spam",             AC_BOOL,    0,        5, 0, 0x04u, 0, 0 },
    { "phishing",         AC_BOOL,    0,        5, 0, 0x08u, 0, 0 },
    { "scanner",          AC_BOOL,    0,        5, 0, 0x10u, 0, 0 },
    { "state_actor",      AC_BOOL,    0,        5, 0, 0x20u, 0, 0 },
    { "anycast",          AC_BOOL,    0,        3, 8, 0x01u, 0, 0 },
    { "moas",             AC_BOOL,    0,        3, 8, 0x02u, 0, 0 },
    { "narrowed",         AC_BOOL,    0,        3, 8, 0x04u, 0, 0 },
    { "tenant_allow",     AC_BOOL,    0,        7, 0, 0x01u, 0, 0 },
    { "tenant_deny",      AC_BOOL,    0,        7, 0, 0x02u, 0, 0 },
    { "listed",           AC_LEVEL,   0,        0, 0, 0,     0, 5 },
    { "rpki_reason",      AC_ENUM,    D_REASON, 2, 5, 0,     1, 3 },
    { "rpki",             AC_ENUM,    D_RPKI,   3, 6, 0,     1, 5 },
    { "asn",              AC_ASN,     0,        3, 0, 0,     1, 0 },
    { "asn_rep",          AC_ENUM,    D_REP,    3, 9, 0,     1, 5 },
    { "country",          AC_COUNTRY, 0,        3, 4, 0,     1, 0 },
    { "registry_country", AC_COUNTRY, 0,        6, 4, 0,     1, 0 },
    { "rir",              AC_ENUM,    D_RIR,    3, 7, 0,     1, 6 },
    { "registry_rir",     AC_ENUM,    D_RIR,    6, 7, 0,     1, 6 },
};
#define NATTRS (sizeof attrs / sizeof attrs[0])
#define A_TENANT_ALLOW 14
#define A_LISTED       16

static const char *attr_domain_msg(uint32_t a, char *buf, size_t n)
{
    const attr_t *t = &attrs[a];

    switch (t->cls) {
    case AC_LEVEL:
        snprintf(buf, n, "%s takes none, low, medium, high or critical", t->name);
        break;
    case AC_ENUM:
        snprintf(buf, n, "%s takes %s", t->name,
                 t->dom == D_RPKI ? "valid, invalid, not-found, unrouted or undetermined"
               : t->dom == D_REASON ? "asn, length or undetermined"
               : t->dom == D_REP ? "reputable, neutral, suspicious, highly_suspicious or undetermined"
               : "afrinic, apnic, arin, lacnic, ripe or undetermined");
        break;
    case AC_ASN:
        snprintf(buf, n, "%s takes an AS number (64496 or as64496) or undetermined", t->name);
        break;
    case AC_COUNTRY:
        snprintf(buf, n, "%s takes a two-letter country code or undetermined", t->name);
        break;
    default:
        snprintf(buf, n, "%s is a bool and takes no value", t->name);
        break;
    }
    return buf;
}

/* literal classes */
#define LC_LEVEL   1u
#define LC_ENUM    2u
#define LC_COUNTRY 3u
#define LC_ASN     4u
#define LC_UNDET   5u
#define LC_BAD     6u   /* a word in a literal position that is no literal */
#define COUNTRY_UNKNOWN 0xffffu

typedef struct { const char *w; uint8_t cls; uint8_t dom; uint8_t val; } litword_t;
static const litword_t litwords[] = {
    { "none", LC_LEVEL, 0, 0 }, { "low", LC_LEVEL, 0, 1 }, { "medium", LC_LEVEL, 0, 2 },
    { "high", LC_LEVEL, 0, 3 }, { "critical", LC_LEVEL, 0, 4 },
    { "valid", LC_ENUM, D_RPKI, 1 }, { "invalid", LC_ENUM, D_RPKI, 2 }, { "not-found", LC_ENUM, D_RPKI, 3 },
    { "not_found", LC_ENUM, D_RPKI, 3 }, { "notfound", LC_ENUM, D_RPKI, 3 }, { "unrouted", LC_ENUM, D_RPKI, 4 },
    { "asn", LC_ENUM, D_REASON, 1 }, { "length", LC_ENUM, D_REASON, 2 },
    { "reputable", LC_ENUM, D_REP, 1 }, { "neutral", LC_ENUM, D_REP, 2 }, { "suspicious", LC_ENUM, D_REP, 3 },
    { "highly_suspicious", LC_ENUM, D_REP, 4 },
    { "afrinic", LC_ENUM, D_RIR, 1 }, { "apnic", LC_ENUM, D_RIR, 2 }, { "arin", LC_ENUM, D_RIR, 3 },
    { "lacnic", LC_ENUM, D_RIR, 4 }, { "ripe", LC_ENUM, D_RIR, 5 },
    { "undetermined", LC_UNDET, 0, 0 },
};
#define NLITWORDS (sizeof litwords / sizeof litwords[0])

static const char *const level_name[5] = { "none", "low", "medium", "high", "critical" };
static const char *enum_name(uint32_t dom, uint32_t v)
{
    static const char *const rpki[5] = { "undetermined", "valid", "invalid", "not-found", "unrouted" };
    static const char *const reason[3] = { "undetermined", "asn", "length" };
    static const char *const rep[5] = { "undetermined", "reputable", "neutral", "suspicious", "highly_suspicious" };
    static const char *const rir[6] = { "undetermined", "afrinic", "apnic", "arin", "lacnic", "ripe" };

    switch (dom) {
    case D_RPKI:   return v < 5u ? rpki[v] : "?";
    case D_REASON: return v < 3u ? reason[v] : "?";
    case D_REP:    return v < 5u ? rep[v] : "?";
    default:       return v < 6u ? rir[v] : "?";
    }
}

/* keywords */
#define KW_ALLOW 1u
#define KW_DENY  2u
#define KW_LOG   3u
#define KW_IF    4u
#define KW_AND   5u
#define KW_OR    6u
#define KW_NOT   7u
#define KW_IN    8u
#define KW_IS    9u
#define KW_UNKNOWN 10u
static const char *const kw_name[11] = { "", "allow", "deny", "log", "if", "and", "or", "not", "in", "is", "unknown" };

/* operators */
#define OP_EQ 1u
#define OP_NE 2u
#define OP_GE 3u
#define OP_GT 4u
#define OP_LE 5u
#define OP_LT 6u
static const char *const op_name[7] = { "", "==", "!=", ">=", ">", "<=", "<" };

/* ======================================================================================================
 * Allocation: the caller's, or the C library's; temporaries come from an arena freed on every path
 * ==================================================================================================== */

static void *a_alloc(const we_alloc_t *a, size_t n, size_t align)
{
    size_t r;

    if (a != NULL && a->alloc != NULL) {
        return a->alloc(a->ud, n, align);
    }
    r = (n + align - 1u) & ~(align - 1u);
    return aligned_alloc(align, r == 0u ? align : r);
}

static void a_free(const we_alloc_t *a, void *p)
{
    if (p == NULL) {
        return;
    }
    if (a != NULL && a->alloc != NULL) {
        if (a->free != NULL) {
            a->free(a->ud, p);
        }
        return;
    }
    free(p);
}

typedef struct chunk {
    struct chunk *next;
    size_t        used;
    size_t        cap;
} chunk_t;

typedef struct {
    const we_alloc_t *alloc;
    chunk_t          *head;
    int               nomem;
} arena_t;

#define AR_DATA(c) ((uint8_t *)(c) + ((sizeof(chunk_t) + 15u) & ~(size_t)15u))

static void *ar_get(arena_t *ar, size_t n)
{
    chunk_t *c = ar->head;
    uint8_t *p;
    size_t want = n;

    n = (n + 15u) & ~(size_t)15u;
    if (n == 0u) {
        n = 16u;
    }
    if (WE_ARENA_ONE_EACH || c == NULL || c->used + n > c->cap) {
        size_t cap = WE_ARENA_ONE_EACH || n > 65536u ? n : 65536u;

        c = (chunk_t *)a_alloc(ar->alloc, sizeof(chunk_t) + 16u + cap, 16u);
        if (c == NULL) {
            ar->nomem = 1;
            return NULL;
        }
        c->next = ar->head;
        c->used = 0u;
        c->cap = cap;
        ar->head = c;
        WE_ARENA_POISON(AR_DATA(c), cap);      /* nothing handed out yet */
    }
    p = AR_DATA(c) + c->used;
    c->used += n;
    WE_ARENA_UNPOISON(p, want);                /* exactly what was asked for: the padding stays poisoned */
    memset(p, 0, want);
    return p;
}

static void ar_free(arena_t *ar)
{
    chunk_t *c = ar->head;

    while (c != NULL) {
        chunk_t *nx = c->next;

        WE_ARENA_UNPOISON(AR_DATA(c), c->cap);
        a_free(ar->alloc, c);
        c = nx;
    }
    ar->head = NULL;
}

/* ======================================================================================================
 * Tokens, nodes, directives
 * ==================================================================================================== */

#define TK_EOF     0u
#define TK_LPAREN  1u
#define TK_RPAREN  2u
#define TK_LBRACE  3u
#define TK_RBRACE  4u
#define TK_COMMA   5u
#define TK_OP      6u
#define TK_SETREF  7u
#define TK_KW      8u
#define TK_ATTR    9u
#define TK_LIT     10u
#define TK_WORD    11u

typedef struct {
    uint8_t  type;
    uint8_t  sub;      /* keyword, operator, attribute, or literal class */
    uint8_t  dom;      /* an enum literal's domain */
    uint8_t  pad;
    uint32_t val;      /* a literal's value */
    uint32_t off;
    uint32_t len;
    uint32_t line;
    uint32_t col;
} tok_t;

#define N_ATOM 1u
#define N_NOT  2u
#define N_AND  3u
#define N_OR   4u

#define F_BARE  1u
#define F_ISUNK 2u
#define F_CMP   3u
#define F_IN    4u

typedef struct {
    uint8_t  type;
    uint8_t  form;
    uint8_t  attr;
    uint8_t  op;
    uint8_t  negated;  /* is not unknown */
    uint8_t  named;
    uint16_t pad;
    int32_t  first;    /* NOT and chains: the first child */
    int32_t  next;     /* the next sibling in a chain */
    uint32_t tok;      /* the node's first token (an atom's attribute; `not`; a chain's first child's) */
    uint32_t optok;    /* the operator, `in` or `is` */
    uint32_t littok;   /* the literal, the set reference, or the `{` */
    uint32_t endtok;   /* an inline set's `}` */
    int32_t  set;      /* a named set, resolved in the sets layer */
} node_t;

typedef struct {
    const we_policy_directive_t *d;
    const uint8_t *arg;        /* the caller's bytes; never kept past compile */
    uint32_t       len;
    uint32_t       index;      /* in the source */
    uint32_t       ctx;        /* the context's index */
    uint32_t       ordinal;    /* among the directives of its kind in its context */
    tok_t         *tok;
    uint32_t       ntok;
    node_t        *nodes;
    uint32_t       nnodes;
    int32_t        root;
    uint8_t        action;
    uint8_t        value;      /* a mode (0 off, 1 log, 2 deny), threshold (0 off .. 4) or allow_inferred */
    uint8_t        pad[2];
    uint16_t       ops;
    uint16_t       op_tok[WE_LIM_OPS_RULE];
    int32_t        decl;       /* a set directive's index in the set table */
} dir_t;

typedef struct {
    char    *name;
    int32_t  parent;
    uint8_t  has_policy;
    uint8_t  has_threshold;
    uint8_t  threshold;
    uint8_t  has_mode;
    uint8_t  mode;
    uint8_t  has_inferred;
    uint8_t  inferred;
    uint8_t  pad;
    uint32_t len;              /* strlen(name) */
    uint32_t hash;             /* name_hash(name, len) */
    uint32_t seen[8];          /* directives of each kind (WE_DIR_*, an unknown kind at 0) seen so far */
} ctxent_t;

/* a declared set's class: the class of its non-undetermined members; ANY when it holds only undetermined */
#define SC_ANY 0xffu
typedef struct {
    uint32_t dir;
    uint32_t ctx;
    uint32_t name_off;     /* in the directive's argument, after the `@` */
    uint32_t name_len;
    uint8_t  cls;          /* LC_* or SC_ANY */
    uint8_t  dom;
    uint8_t  mixed;        /* members of more than one class */
    uint8_t  has_undet;
    uint32_t nlits;
} setdecl_t;

typedef struct {
    const we_policy_source_t *src;
    const we_policy_env_t    *env;
    const we_alloc_t         *alloc;
    const we_policy_report_t *rep;
    we_policy_error_t        *err;
    arena_t                   ar;
    dir_t                    *dirs;
    uint32_t                  ndirs;
    ctxent_t                 *ctxs;
    uint32_t                  nctx;
    size_t                    ctxcap;   /* the table's size: context_capacity() of the source */
    setdecl_t                *sets;
    uint32_t                  nsets;
    int                       exempt_length;   /* the verifier's re-parse of the canonical text */
    int                       failed;
    /* scratch for a set's members, never live across a recursive call, so no frame carries 16 KiB */
    const tok_t             **mem;
    const tok_t             **mem2;
    uint32_t                 *keys;
    void                     *vals;     /* three vals_t, the reports' scratch: [0] the walks, [1] [2] subsumption */
    void                    **vc_sets;  /* the shadowing procedure's value cache: per named set */
    void                   ***vc_nodes; /* ... and per inline atom, by directive and node */
    /*
     * The indexes that keep a compile linear in the directives (each built once, each O(1) to probe):
     * the contexts by name, each context's directives in file order, and the distinct blocks by digest.
     */
    uint32_t                 *cht;      /* open addressing: a context's index + 1, 0 empty */
    uint32_t                  cmask;
    uint32_t                 *chead;    /* per context: its first directive + 1, 0 none */
    uint32_t                 *dnext;    /* per directive: the next one of its context + 1, 0 none */
} cc_t;

/* ======================================================================================================
 * Refusals
 * ==================================================================================================== */

const char *we_policy_kind_name(uint8_t kind)
{
    switch (kind) {
    case WE_DIR_POLICY:    return "policy";
    case WE_DIR_SET:       return "set";
    case WE_DIR_FLOOR:     return "floor";
    case WE_DIR_THRESHOLD: return "threshold";
    case WE_DIR_MODE:      return "mode";
    case WE_DIR_ALLOW_INFERRED: return "allow_inferred";
    default:               return "?";
    }
}

/* every byte outside 0x20..0x7E, and `"` and `\`, as \xHH with upper-case digits; at most 64 raw bytes */
static void render_token(const uint8_t *p, uint32_t len, char *out, size_t n)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0u;
    uint32_t i;

    if (len > WE_LIM_IDENT) {
        len = WE_LIM_IDENT;
    }
    for (i = 0u; i < len && o + 5u < n; i++) {
        uint8_t c = p[i];

        if (c < 0x20u || c > 0x7eu || c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = 'x';
            out[o++] = hx[c >> 4];
            out[o++] = hx[c & 15u];
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* line and column (1-based, LF only, column in bytes) of byte offset `off` */
static void pos_of(const uint8_t *arg, uint32_t off, uint32_t *line, uint32_t *col)
{
    uint32_t i, l = 1u, ls = 0u;

    for (i = 0u; i < off; i++) {
        if (arg[i] == '\n') {
            l++;
            ls = i + 1u;
        }
    }
    *line = l;
    *col = off - ls + 1u;
}

/*
 * A refusal's context in the error's 128 bytes: verbatim up to 127, else its first 61 bytes, `...` and its
 * last 63, so both the server and the innermost block survive. The reference interpreter renders the
 * refusal line's context by the same rule (WE_ERR_CTX_HEAD, WE_ERR_CTX_TAIL there too).
 */
#define WE_ERR_CTX_HEAD 61u
#define WE_ERR_CTX_TAIL 63u

static void error_context(char out[128], const char *ctx)
{
    size_t n = strlen(ctx);

    if (n <= 127u) {
        memcpy(out, ctx, n + 1u);
        return;
    }
    memcpy(out, ctx, WE_ERR_CTX_HEAD);
    memcpy(out + WE_ERR_CTX_HEAD, "...", 3u);
    memcpy(out + WE_ERR_CTX_HEAD + 3u, ctx + n - WE_ERR_CTX_TAIL, WE_ERR_CTX_TAIL);
    out[WE_ERR_CTX_HEAD + 3u + WE_ERR_CTX_TAIL] = '\0';
}

static void fail_at(cc_t *c, const char *layer, const char *phrase, const dir_t *d, uint32_t off, uint32_t len,
                    int has_token, const char *fix, const char *fmt, ...)
{
    we_policy_error_t *e = c->err;
    va_list ap;

    c->failed = 1;
    if (e == NULL) {
        return;
    }
    memset(e, 0, sizeof *e);
    e->layer = layer;
    snprintf(e->phrase, sizeof e->phrase, "%s", phrase);
    e->kind = d->d->kind;
    e->directive = d->index;
    e->rule = d->ordinal;
    error_context(e->context, d->d->context != NULL ? d->d->context : "");
    if (has_token) {
        pos_of(d->arg, off, &e->line, &e->col);
        render_token(d->arg + off, len, e->token, sizeof e->token);
        e->token_len = len > WE_LIM_IDENT ? WE_LIM_IDENT : len;
    } else {
        pos_of(d->arg, off, &e->line, &e->col);
    }
    va_start(ap, fmt);
    vsnprintf(e->what, sizeof e->what, fmt, ap);
    va_end(ap);
    snprintf(e->fix, sizeof e->fix, "%s", fix != NULL ? fix : "");
}

/* at a token; or at end of input when the token is the EOF */
static void fail_tok(cc_t *c, const char *layer, const char *phrase, const dir_t *d, const tok_t *t,
                     const char *fix, const char *what)
{
    if (t->type == TK_EOF) {
        fail_at(c, layer, phrase, d, d->len, 0u, 0, fix, "%s", what);
    } else {
        fail_at(c, layer, phrase, d, t->off, t->len, 1, fix, "%s", what);
    }
}

int we_policy_error_format(const we_policy_error_t *e, char *buf, size_t n)
{
    if (e == NULL || buf == NULL || n == 0u) {
        return -1;
    }
    return snprintf(buf, n, "rule %u, line %u, column %u: near \"%s\": %s.%s%s", e->rule, e->line, e->col,
                    e->token, e->what, e->fix[0] != '\0' ? " " : "", e->fix);
}

/* ======================================================================================================
 * Layers 1 and 2: length and alphabet
 * ==================================================================================================== */

static int in_alphabet(uint8_t ch)
{
    return (ch >= 0x20u && ch <= 0x7eu) || (ch >= 0x09u && ch <= 0x0du);
}

static int is_ws(uint8_t ch)
{
    return ch == ' ' || (ch >= 0x09u && ch <= 0x0du);
}

/* ======================================================================================================
 * Layer 3: the lexer, POLICY.md §1.2
 *
 * The byte classes: a word is a maximal run of [A-Za-z0-9_.+-] (`+` and `.` belong to words so that
 * `+1` is a signed number and `as1.10` is asdot); `( ) { } ,` delimit themselves; an operator is the
 * maximal munch over `= ! < >`; `@` opens a set name, the maximal run of [a-z0-9_-]. Every other byte of
 * the alphabet belongs to no token: " # $ % & ' * / : ; ? [ \ ] ^ ` | ~ are refused where they stand,
 * as POLICY.md rules for `#`, with the alphabet's own words.
 * ==================================================================================================== */

static int is_word_byte(uint8_t ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
        || ch == '_' || ch == '.' || ch == '+' || ch == '-';
}

static int is_op_byte(uint8_t ch)
{
    return ch == '=' || ch == '!' || ch == '<' || ch == '>';
}

static int is_punct(uint8_t ch)
{
    return ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == ',';
}

static int is_digit(uint8_t ch)
{
    return ch >= '0' && ch <= '9';
}

static int is_alpha(uint8_t ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

static int is_ident(uint8_t ch)
{
    return (ch >= 'a' && ch <= 'z') || is_digit(ch) || ch == '_' || ch == '-';
}

/* does this word, lower-cased, spell something of the language? */
static int lower_eq(const uint8_t *w, uint32_t n, const char *s)
{
    uint32_t i;

    if (strlen(s) != n) {
        return 0;
    }
    for (i = 0u; i < n; i++) {
        uint8_t ch = w[i];

        if (ch >= 'A' && ch <= 'Z') {
            ch = (uint8_t)(ch + 32u);
        }
        if (ch != (uint8_t)s[i]) {
            return 0;
        }
    }
    return 1;
}

static int exact_eq(const uint8_t *w, uint32_t n, const char *s)
{
    return strlen(s) == n && memcmp(w, s, n) == 0;
}

/* the lower-case spelling, when the word has an upper-case byte and that spelling is the vocabulary's */
static const char *upper_spelling(const uint8_t *w, uint32_t n)
{
    uint32_t i;
    int upper = 0;

    for (i = 0u; i < n; i++) {
        upper |= w[i] >= 'A' && w[i] <= 'Z';
    }
    if (!upper) {
        return NULL;
    }
    for (i = 1u; i < 11u; i++) {
        if (lower_eq(w, n, kw_name[i])) {
            return kw_name[i];
        }
    }
    for (i = 0u; i < NATTRS; i++) {
        if (lower_eq(w, n, attrs[i].name)) {
            return attrs[i].name;
        }
    }
    for (i = 0u; i < NLITWORDS; i++) {
        if (lower_eq(w, n, litwords[i].w)) {
            return litwords[i].w;
        }
    }
    return NULL;
}

static int country_lookup(uint8_t a, uint8_t b, uint16_t *num)
{
    int lo = 0, hi = (int)WE_COUNTRY_ALPHA2_COUNT - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const we_country_alpha2_t *e = &we_country_alpha2_table[mid];
        int cmp = (int)a - (int)(uint8_t)e->a2[0];

        if (cmp == 0) {
            cmp = (int)b - (int)(uint8_t)e->a2[1];
        }
        if (cmp == 0) {
            *num = e->num;
            return 1;
        }
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return 0;
}

static const char *country_alpha2(uint32_t num, char out[3])
{
    uint32_t i;

    for (i = 0u; i < WE_COUNTRY_ALPHA2_COUNT; i++) {
        if (we_country_alpha2_table[i].num == num) {
            out[0] = we_country_alpha2_table[i].a2[0];
            out[1] = we_country_alpha2_table[i].a2[1];
            out[2] = '\0';
            return out;
        }
    }
    out[0] = '?';
    out[1] = '?';
    out[2] = '\0';
    return out;
}

static int is_country_attr(int a)
{
    return a >= 0 && attrs[a].cls == AC_COUNTRY;
}

/* a sign (followed by a digit), an optional `as` in any case, then a digit */
static int number_shaped(const uint8_t *w, uint32_t n)
{
    uint32_t p = 0u;

    if (n > 0u && (w[0] == '+' || w[0] == '-')) {
        p = 1u;
    }
    if (n >= p + 2u && (w[p] | 0x20u) == 'a' && (w[p + 1u] | 0x20u) == 's') {
        p += 2u;
    }
    return p < n && is_digit(w[p]);
}

#define ADDR_FIX "an address or CIDR is not a literal of this language: list it in the tenant plane, written " \
                 "through op:policy{edge:{allow,deny}}, and test it with tenant_allow or tenant_deny"
#define BARE_FIX "write country in { RU } or country == RU"

/*
 * A number token, in this order: a sign; asdot (digits, a dot, digits); any other byte after the
 * digits; a leading zero; the digit count; the value; the sentinel. Returns 0 and the value, or -1 after
 * refusing. Within the digit checks the order is POLICY.md's (sign, leading zero, count, value); asdot and
 * the non-digit are decided on the token's shape before its digits are judged.
 */
static int lex_number(cc_t *c, const dir_t *d, uint32_t off, uint32_t n, uint32_t *val)
{
    const uint8_t *w = d->arg + off;
    uint32_t p = 0u, dl = 0u, i, dots = 0u;
    uint64_t v = 0u;

    if (w[0] == '+' || w[0] == '-') {
        fail_at(c, "lexing", "a number with a sign", d, off, n, 1, "AS numbers are unsigned", "a number with a sign");
        return -1;
    }
    for (i = 0u; i < n; i++) {
        dots += w[i] == '.';
    }
    if (n >= 2u && (w[0] | 0x20u) == 'a' && (w[1] | 0x20u) == 's') {
        p = 2u;
    }
    while (p + dl < n && is_digit(w[p + dl])) {
        dl++;
    }
    if (p + dl < n) {
        const uint8_t *r = w + p + dl;
        uint32_t rn = n - p - dl, k;
        int asdot = r[0] == '.' && rn > 1u;

        for (k = 1u; k < rn && asdot; k++) {
            asdot = is_digit(r[k]);
        }
        if (asdot) {
            uint64_t hi = 0u, lo = 0u;
            char fix[96];

            for (k = 0u; k < dl && hi < 0xffffffffffull; k++) {
                hi = hi * 10u + (uint64_t)(w[p + k] - '0');
            }
            for (k = 1u; k < rn && lo < 0xffffffffffull; k++) {
                lo = lo * 10u + (uint64_t)(r[k] - '0');
            }
            if (hi > 65535u || lo > 65535u) {
                /* never converted: a part over 65535 has no asplain value, so the fix names the part */
                const uint8_t *pp = lo > 65535u ? r + 1 : w + p;
                int pl = (int)(lo > 65535u ? rn - 1u : dl);

                snprintf(fix, sizeof fix, "each part of an asdot number is 0..65535 and %.*s is not; "
                         "write the asplain value", pl > 24 ? 24 : pl, (const char *)pp);
            } else {
                snprintf(fix, sizeof fix, "write the asplain value %" PRIu64, hi * 65536u + lo);
            }
            fail_at(c, "lexing", "asdot", d, off, n, 1, fix, "asdot is not accepted");
            return -1;
        }
        fail_at(c, "lexing", "a non-digit in a number", d, off + p + dl, rn, 1,
                dots >= 2u ? ADDR_FIX : "AS numbers are base 10 digits: no exponent, no hex, no separators",
                "a non-digit in a number");
        return -1;
    }
    if (dl > 1u && w[p] == '0') {
        fail_at(c, "lexing", "a leading zero other than 0", d, off, n, 1,
                "numbers are base 10: strtoul with base 0 would read 010 as 8, so write it without the zero",
                "a leading zero other than 0");
        return -1;
    }
    if (dl > 10u) {
        fail_at(c, "lexing", "more than 10 digits", d, off, n, 1, "an AS number is 32 bits", "more than 10 digits");
        return -1;
    }
    for (i = 0u; i < dl; i++) {
        v = v * 10u + (uint64_t)(w[p + i] - '0');
    }
    if (v > 0xffffffffull) {
        fail_at(c, "lexing", "above 2^32 - 1", d, off, n, 1, "an AS number is 32 bits", "above 2^32 - 1");
        return -1;
    }
    if (v == 0xffffffffull) {
        fail_at(c, "lexing", "the sentinel 4294967295", d, off, n, 1, "write undetermined",
                "the sentinel 4294967295 is not addressable");
        return -1;
    }
    *val = (uint32_t)v;
    return 0;
}

/* a word in literal mode: a number, a country code, the literal vocabulary, or an unknown word */
static int lex_literal(cc_t *c, const dir_t *d, tok_t *t, int country_expected)
{
    const uint8_t *w = d->arg + t->off;
    uint32_t wl = t->len, k;
    const char *sp;

    if (number_shaped(w, wl)) {
        if (lex_number(c, d, t->off, wl, &t->val) != 0) {
            return -1;
        }
        t->type = TK_LIT;
        t->sub = LC_ASN;
        return 0;
    }
    if (wl == 2u && is_alpha(w[0]) && is_alpha(w[1])) {
        uint8_t u0 = (uint8_t)(w[0] & 0xdfu), u1 = (uint8_t)(w[1] & 0xdfu);
        uint16_t num;
        int known = country_lookup(u0, u1, &num);

        if (country_expected && u0 == 'U' && u1 == 'K') {
            fail_at(c, "lexing", "did you mean GB", d, t->off, wl, 1, "did you mean GB", "uk is not an ISO 3166-1 code");
            return -1;
        }
        if (country_expected && !known) {
            fail_at(c, "lexing", "an unknown country code", d, t->off, wl, 1,
                    "the codes are ISO 3166-1 alpha-2, plus EU AP ZZ XK", "an unknown country code");
            return -1;
        }
        t->type = TK_LIT;
        t->sub = LC_COUNTRY;
        t->val = known ? num : COUNTRY_UNKNOWN;
        return 0;
    }
    for (k = 0u; k < NLITWORDS; k++) {
        if (exact_eq(w, wl, litwords[k].w)) {
            t->type = TK_LIT;
            t->sub = litwords[k].cls;
            t->dom = litwords[k].dom;
            t->val = litwords[k].val;
            return 0;
        }
    }
    if ((sp = upper_spelling(w, wl)) != NULL) {
        char fix[64];

        snprintf(fix, sizeof fix, "write %s", sp);
        fail_at(c, "lexing", "an upper-case keyword or literal", d, t->off, wl, 1, fix, "an upper-case keyword or literal");
        return -1;
    }
    t->type = TK_WORD;
    return 0;
}

/* a word in expression mode: a keyword, an attribute, or an unknown word; a literal here is refused */
static int lex_expression(cc_t *c, const dir_t *d, tok_t *t)
{
    const uint8_t *w = d->arg + t->off;
    uint32_t wl = t->len, k;
    const char *sp;

    if (number_shaped(w, wl)) {
        char fix[96];

        if (lex_number(c, d, t->off, wl, &t->val) != 0) {
            return -1;
        }
        snprintf(fix, sizeof fix, "compare it: asn == %.*s", (int)(wl > 40u ? 40u : wl), (const char *)w);
        fail_at(c, "lexing", "a bare literal in expression mode", d, t->off, wl, 1, fix,
                "a bare literal in expression mode");
        return -1;
    }
    for (k = 1u; k < 11u; k++) {
        if (exact_eq(w, wl, kw_name[k])) {
            t->type = TK_KW;
            t->sub = (uint8_t)k;
            return 0;
        }
    }
    for (k = 0u; k < NATTRS; k++) {
        if (exact_eq(w, wl, attrs[k].name)) {
            t->type = TK_ATTR;
            t->sub = (uint8_t)k;
            return 0;
        }
    }
    for (k = 0u; k < NLITWORDS; k++) {
        if (exact_eq(w, wl, litwords[k].w)) {
            fail_at(c, "lexing", "a bare literal in expression mode", d, t->off, wl, 1,
                    "a literal follows a comparison: rpki == valid", "a bare literal in expression mode");
            return -1;
        }
    }
    if ((sp = upper_spelling(w, wl)) != NULL) {
        char fix[64];

        snprintf(fix, sizeof fix, "write %s", sp);
        fail_at(c, "lexing", "an upper-case keyword or literal", d, t->off, wl, 1, fix, "an upper-case keyword or literal");
        return -1;
    }
    if (wl == 2u && is_alpha(w[0]) && is_alpha(w[1])) {
        fail_at(c, "lexing", BARE_FIX, d, t->off, wl, 1, BARE_FIX, "a bare literal in expression mode");
        return -1;
    }
    t->type = TK_WORD;
    return 0;
}

/* lex one directive's argument into d->tok; 0, or -1 after refusing */
static int lex_dir(cc_t *c, dir_t *d, tok_t *scratch, uint32_t cap)
{
    const uint8_t *a = d->arg;
    uint32_t n = d->len, pos = 0u, line = 1u, ls = 0u, nt = 0u, depth = 0u;
    int decl = d->d->kind == WE_DIR_SET;
    int literal_next = 0, after_in = 0, first = 1, brace_country = 0, last_attr = -1;
    const tok_t *prev = NULL;

    for (;;) {
        uint8_t ch;
        tok_t t;
        uint32_t start;

        while (pos < n && is_ws(a[pos])) {
            if (a[pos] == '\n') {
                line++;
                ls = pos + 1u;
            }
            pos++;
        }
        if (pos >= n) {
            break;
        }
        ch = a[pos];
        start = pos;
        memset(&t, 0, sizeof t);
        t.off = start;
        t.line = line;
        t.col = start - ls + 1u;
        if (!(is_word_byte(ch) || is_punct(ch) || is_op_byte(ch) || ch == '@')) {
            char what[40];

            snprintf(what, sizeof what, "byte 0x%02X is not allowed", ch);
            fail_at(c, "lexing", what, d, start, 1u, 1,
                    (ch == ':' || ch == '/') ? ADDR_FIX : "this byte belongs to no token of the language", "%s", what);
            return -1;
        }
        if (after_in && ch != '@' && ch != '{') {
            uint32_t j = start + 1u;

            if (is_word_byte(ch)) {
                while (j < n && is_word_byte(a[j])) {
                    j++;
                }
            } else if (is_op_byte(ch)) {
                while (j < n && is_op_byte(a[j])) {
                    j++;
                }
            }
            fail_at(c, "lexing", BARE_FIX, d, start, j - start, 1, BARE_FIX,
                    "a set after in: in takes @name or { ... }");
            return -1;
        }
        after_in = 0;
        if (is_punct(ch)) {
            t.type = ch == '(' ? TK_LPAREN : ch == ')' ? TK_RPAREN : ch == '{' ? TK_LBRACE : ch == '}' ? TK_RBRACE
                   : TK_COMMA;
            t.len = 1u;
            if (ch == '{') {
                if (depth == 0u) {
                    brace_country = decl || (is_country_attr(last_attr) && prev != NULL
                                             && ((prev->type == TK_KW && prev->sub == KW_IN)
                                                 || (prev->type == TK_OP && (prev->sub == OP_EQ || prev->sub == OP_NE))));
                }
                depth++;
            } else if (ch == '}' && depth > 0u) {
                depth--;
            }
            literal_next = 0;
            pos++;
        } else if (is_op_byte(ch)) {
            uint32_t j = start;

            while (j < n && is_op_byte(a[j])) {
                j++;
            }
            t.type = TK_OP;
            t.len = j - start;
            if (exact_eq(a + start, t.len, "==")) {
                t.sub = OP_EQ;
            } else if (exact_eq(a + start, t.len, "!=")) {
                t.sub = OP_NE;
            } else if (exact_eq(a + start, t.len, ">=")) {
                t.sub = OP_GE;
            } else if (exact_eq(a + start, t.len, ">")) {
                t.sub = OP_GT;
            } else if (exact_eq(a + start, t.len, "<=")) {
                t.sub = OP_LE;
            } else if (exact_eq(a + start, t.len, "<")) {
                t.sub = OP_LT;
            } else {
                fail_at(c, "lexing", "an unknown operator", d, start, t.len, 1, "the operators are == != >= > <= <",
                        "an unknown operator");
                return -1;
            }
            if (depth == 0u) {
                literal_next = t.sub;
            }
            pos = j;
        } else if (ch == '@') {
            uint32_t j = start + 1u;

            while (j < n && is_ident(a[j])) {
                j++;
            }
            if (depth > 0u || literal_next || (decl && !first) || j == start + 1u) {
                fail_at(c, "lexing", "a stray @", d, start, 1u, 1,
                        "a set is named @name, 1 to 64 bytes of a-z, 0-9, _ and -, once, after in", "a stray @");
                return -1;
            }
            if (j - start - 1u > WE_LIM_IDENT) {
                fail_at(c, "lexing", "identifier over 64 bytes", d, start, j - start, 1, "a set name is at most 64 bytes",
                        "identifier over 64 bytes");
                return -1;
            }
            t.type = TK_SETREF;
            t.len = j - start;
            pos = j;
        } else {
            uint32_t j = start;

            while (j < n && is_word_byte(a[j])) {
                j++;
            }
            t.len = j - start;
            pos = j;
            if (depth > 0u || literal_next || decl) {
                int ce = (depth > 0u && brace_country) || decl
                      || ((literal_next == (int)OP_EQ || literal_next == (int)OP_NE) && is_country_attr(last_attr));

                if (lex_literal(c, d, &t, ce) != 0) {
                    return -1;
                }
                literal_next = 0;
            } else {
                if (lex_expression(c, d, &t) != 0) {
                    return -1;
                }
                if (t.type == TK_KW && t.sub == KW_IN) {
                    after_in = 1;
                } else if (t.type == TK_ATTR) {
                    last_attr = t.sub;
                }
            }
        }
        if (nt + 1u >= cap) {
            return -1;                         /* unreachable: at most one token per byte */
        }
        scratch[nt++] = t;
        prev = &scratch[nt - 1u];
        first = 0;
    }
    {
        tok_t t;

        memset(&t, 0, sizeof t);
        t.type = TK_EOF;
        t.off = n;
        t.line = line;
        t.col = n - ls + 1u;
        scratch[nt++] = t;
    }
    d->tok = (tok_t *)ar_get(&c->ar, sizeof(tok_t) * nt);
    if (d->tok == NULL) {
        return -2;
    }
    memcpy(d->tok, scratch, sizeof(tok_t) * nt);
    d->ntok = nt;
    return 0;
}

/* mode, threshold and allow_inferred arguments: one word, in any case */
static int lex_word_arg(cc_t *c, dir_t *d)
{
    static const char *const modes[3] = { "off", "log", "deny" };
    static const char *const thresholds[5] = { "off", "low", "medium", "high", "critical" };
    static const char *const onoff[2] = { "off", "on" };
    const char *const *choices;
    const char *phrase;
    uint32_t nchoice, s = 0u, e, k, words = 0u, w2 = 0u, w2e = 0u, p;

    if (d->d->kind == WE_DIR_MODE) {
        choices = modes;
        nchoice = 3u;
        phrase = "a mode of off, log or deny";
    } else if (d->d->kind == WE_DIR_THRESHOLD) {
        choices = thresholds;
        nchoice = 5u;
        phrase = "a threshold of off, low, medium, high or critical";
    } else {
        choices = onoff;
        nchoice = 2u;
        phrase = "allow_inferred takes on or off";
    }
    while (s < d->len && is_ws(d->arg[s])) {
        s++;
    }
    e = s;
    while (e < d->len && !is_ws(d->arg[e])) {
        e++;
    }
    for (p = 0u; p < d->len;) {
        while (p < d->len && is_ws(d->arg[p])) {
            p++;
        }
        if (p >= d->len) {
            break;
        }
        words++;
        if (words == 2u) {
            w2 = p;
        }
        while (p < d->len && !is_ws(d->arg[p])) {
            p++;
        }
        if (words == 2u) {
            w2e = p;
        }
    }
    if (words == 1u) {
        for (k = 0u; k < nchoice; k++) {
            if (lower_eq(d->arg + s, e - s, choices[k])) {
                d->value = (uint8_t)k;
                return 0;
            }
        }
    }
    if (words > 1u) {
        fail_at(c, "parsing", phrase, d, w2, w2e - w2, 1, "", "%s", phrase);
    } else {
        fail_at(c, "parsing", phrase, d, s, e - s, e > s, "", "%s", phrase);
    }
    return -1;
}

/* ======================================================================================================
 * Layer 4: the parser, POLICY.md §1.1
 * ==================================================================================================== */

typedef struct {
    cc_t     *c;
    dir_t    *d;
    uint32_t  k;
} ps_t;

static const tok_t *ps_tok(const ps_t *s)
{
    return &s->d->tok[s->k];
}

static int32_t new_node(ps_t *s, uint8_t type, uint32_t tok)
{
    node_t *n = &s->d->nodes[s->d->nnodes];

    memset(n, 0, sizeof *n);
    n->type = type;
    n->tok = tok;
    n->first = -1;
    n->next = -1;
    n->set = -1;
    return (int32_t)s->d->nnodes++;
}

static int is_kw(const tok_t *t, uint32_t kw)
{
    return t->type == TK_KW && t->sub == kw;
}

static int is_punct_tok(const tok_t *t, uint8_t type)
{
    return t->type == type;
}

/* an operation, counted at its token in source order */
static int count_op(ps_t *s, uint32_t at)
{
    if (s->d->ops >= WE_LIM_OPS_RULE) {
        fail_tok(s->c, "parsing", "over 64 operations in a rule", s->d, &s->d->tok[at],
                 "split it into two rules, or move members into a set: a set test is one operation",
                 "over 64 operations in a rule");
        return -1;
    }
    s->d->op_tok[s->d->ops++] = (uint16_t)at;
    return 0;
}

static void empty_expr(ps_t *s, const tok_t *t)
{
    fail_tok(s->c, "parsing", "an empty expression", s->d, t, "a rule is action if condition", "an empty expression");
}

static int32_t parse_expr(ps_t *s, uint32_t depth);

static int32_t parse_atom(ps_t *s)
{
    uint32_t at = s->k;
    const tok_t *t = ps_tok(s);
    int32_t id;
    node_t *n;

    s->k++;
    if (count_op(s, at) != 0) {
        return -1;
    }
    id = new_node(s, N_ATOM, at);
    n = &s->d->nodes[id];
    n->attr = t->sub;
    t = ps_tok(s);
    if (is_kw(t, KW_IS)) {
        n->form = F_ISUNK;
        n->optok = s->k++;
        t = ps_tok(s);
        if (is_kw(t, KW_NOT)) {
            n->negated = 1u;
            s->k++;
            t = ps_tok(s);
        }
        if (!is_kw(t, KW_UNKNOWN)) {
            if (t->type == TK_EOF) {
                empty_expr(s, t);
            } else {
                fail_tok(s->c, "parsing", "is takes unknown or not unknown", s->d, t, "write is unknown or is not unknown",
                         "is takes unknown or not unknown");
            }
            return -1;
        }
        s->k++;
        return id;
    }
    if (t->type == TK_OP) {
        n->form = F_CMP;
        n->op = t->sub;
        n->optok = s->k++;
        t = ps_tok(s);
        if (t->type == TK_LIT) {
            n->littok = s->k++;
            return id;
        }
        if (t->type == TK_EOF) {
            empty_expr(s, t);
        } else if (t->type == TK_LBRACE) {
            char fix[96];

            snprintf(fix, sizeof fix, "write %s in { ... }", attrs[n->attr].name);
            fail_tok(s->c, "parsing", "unbalanced or nested braces", s->d, t, fix,
                     "unbalanced or nested braces: a set follows in, not a comparison");
        } else {
            fail_tok(s->c, "parsing", "an unknown attribute or word", s->d, t, "a literal follows the operator",
                     "an unknown attribute or word");
        }
        return -1;
    }
    if (is_kw(t, KW_IN)) {
        n->form = F_IN;
        n->optok = s->k++;
        t = ps_tok(s);
        if (t->type == TK_SETREF) {
            n->named = 1u;
            n->littok = s->k++;
            return id;
        }
        if (t->type == TK_LBRACE) {
            uint32_t open = s->k++;

            n->littok = open;
            for (;;) {
                t = ps_tok(s);
                if (t->type == TK_COMMA || t->type == TK_LIT) {
                    s->k++;
                    continue;
                }
                if (t->type == TK_RBRACE) {
                    n->endtok = s->k++;
                    return id;
                }
                if (t->type == TK_EOF) {
                    const tok_t *o = &s->d->tok[open];

                    fail_at(s->c, "parsing", "unbalanced or nested braces", s->d, o->off, o->len, 1, "close the set with }",
                            "unbalanced or nested braces: this { is never closed");
                } else if (t->type == TK_LBRACE) {
                    fail_tok(s->c, "parsing", "unbalanced or nested braces", s->d, t, "a set holds literals",
                             "unbalanced or nested braces: braces do not nest");
                } else if (t->type == TK_WORD) {
                    fail_tok(s->c, "parsing", "an unknown attribute or word", s->d, t, "a set holds literals",
                             "an unknown attribute or word");
                } else {
                    fail_tok(s->c, "parsing", "only literals inside braces", s->d, t,
                             "a set holds literals, separated by spaces or commas", "only literals inside braces");
                }
                return -1;
            }
        }
        empty_expr(s, t);
        return -1;
    }
    if (attrs[n->attr].cls != AC_BOOL) {
        char what[96], fix[96];

        snprintf(what, sizeof what, "%s is not a boolean; compare it", attrs[n->attr].name);
        snprintf(fix, sizeof fix, "for example %s is unknown, or a comparison", attrs[n->attr].name);
        fail_tok(s->c, "parsing", "is not a boolean", s->d, &s->d->tok[at], fix, what);
        return -1;
    }
    n->form = F_BARE;
    return id;
}

static int32_t parse_unary(ps_t *s, uint32_t depth)
{
    const tok_t *t = ps_tok(s);

    if (is_kw(t, KW_NOT)) {
        uint32_t at = s->k;
        int32_t id, child;

        if (depth + 1u > WE_LIM_NEST) {
            fail_tok(s->c, "parsing", "nesting over 16", s->d, t, "parentheses and not together nest at most 16 deep",
                     "nesting over 16");
            return -1;
        }
        s->k++;
        if (count_op(s, at) != 0) {
            return -1;
        }
        id = new_node(s, N_NOT, at);
        child = parse_unary(s, depth + 1u);
        if (child < 0) {
            return -1;
        }
        s->d->nodes[id].first = child;
        return id;
    }
    if (is_punct_tok(t, TK_LPAREN)) {
        uint32_t open = s->k;
        int32_t e;

        if (depth + 1u > WE_LIM_NEST) {
            fail_tok(s->c, "parsing", "nesting over 16", s->d, t, "parentheses and not together nest at most 16 deep",
                     "nesting over 16");
            return -1;
        }
        s->k++;
        if (is_punct_tok(ps_tok(s), TK_RPAREN)) {
            empty_expr(s, ps_tok(s));
            return -1;
        }
        e = parse_expr(s, depth + 1u);
        if (e < 0) {
            return -1;
        }
        t = ps_tok(s);
        if (is_punct_tok(t, TK_RPAREN)) {
            s->k++;
            return e;
        }
        if (t->type == TK_EOF) {
            const tok_t *o = &s->d->tok[open];

            fail_at(s->c, "parsing", "unbalanced parentheses", s->d, o->off, o->len, 1, "close it with )",
                    "unbalanced parentheses: this ( is never closed");
        } else if (is_punct_tok(t, TK_RBRACE)) {
            fail_tok(s->c, "parsing", "a stray }", s->d, t, "remove it", "a stray }");
        } else {
            fail_tok(s->c, "parsing", "unbalanced parentheses", s->d, t, "a ) is expected here",
                     "unbalanced parentheses: expected ) here");
        }
        return -1;
    }
    if (t->type == TK_EOF || is_punct_tok(t, TK_RPAREN)) {
        empty_expr(s, t);
        return -1;
    }
    if (is_punct_tok(t, TK_RBRACE)) {
        fail_tok(s->c, "parsing", "a stray }", s->d, t, "remove it", "a stray }");
        return -1;
    }
    if (is_punct_tok(t, TK_LBRACE)) {
        fail_tok(s->c, "parsing", "unbalanced or nested braces", s->d, t, "a set goes after in: country in { NL }",
                 "unbalanced or nested braces: a set follows in");
        return -1;
    }
    if (t->type == TK_ATTR) {
        return parse_atom(s);
    }
    fail_tok(s->c, "parsing", "an unknown attribute or word", s->d, t, "the attributes are listed in POLICY.md",
             "an unknown attribute or word");
    return -1;
}

static int32_t parse_expr(ps_t *s, uint32_t depth)
{
    int32_t first = parse_unary(s, depth), chain, last;
    const tok_t *t = ps_tok(s);
    uint32_t conn;

    if (first < 0) {
        return -1;
    }
    if (!(is_kw(t, KW_AND) || is_kw(t, KW_OR))) {
        return first;
    }
    conn = t->sub;
    chain = new_node(s, conn == KW_AND ? N_AND : N_OR, s->d->nodes[first].tok);
    s->d->nodes[chain].first = first;
    last = first;
    while (is_kw(t, KW_AND) || is_kw(t, KW_OR)) {
        uint32_t at = s->k;
        int32_t nx;

        if (t->sub != conn) {
            char fix[64];

            snprintf(fix, sizeof fix, "add parentheses: (a %s b) %s c", kw_name[conn], kw_name[t->sub]);
            fail_tok(s->c, "parsing", "and/or mixed in a chain", s->d, t, fix, "and/or mixed in a chain");
            return -1;
        }
        s->k++;
        if (count_op(s, at) != 0) {
            return -1;
        }
        nx = parse_unary(s, depth);
        if (nx < 0) {
            return -1;
        }
        s->d->nodes[last].next = nx;
        last = nx;
        t = ps_tok(s);
    }
    return chain;
}

static int parse_policy(cc_t *c, dir_t *d)
{
    ps_t s;
    const tok_t *t;

    s.c = c;
    s.d = d;
    s.k = 0u;
    d->nodes = (node_t *)ar_get(&c->ar, sizeof(node_t) * (d->ntok + 1u));
    if (d->nodes == NULL) {
        return -2;
    }
    d->root = -1;
    t = ps_tok(&s);
    if (t->type == TK_EOF) {
        empty_expr(&s, t);
        return -1;
    }
    if (!(is_kw(t, KW_ALLOW) || is_kw(t, KW_DENY) || is_kw(t, KW_LOG))) {
        fail_tok(c, "parsing", "an unknown attribute or word", d, t, "a rule starts with allow, deny or log",
                 "an unknown attribute or word");
        return -1;
    }
    d->action = t->sub == KW_ALLOW ? WE_ACT_ALLOW : t->sub == KW_DENY ? WE_ACT_DENY : WE_ACT_LOG;
    s.k++;
    t = ps_tok(&s);
    if (!is_kw(t, KW_IF)) {
        const char *fix = d->action == WE_ACT_DENY ? "deny if not <condition>"
                        : d->action == WE_ACT_ALLOW ? "allow if <condition>" : "log if <condition>";

        fail_tok(c, "parsing", (t->type == TK_EOF && d->action == WE_ACT_DENY) ? "deny if not <condition>"
                                                                                : "an action without if",
                 d, t, fix, "an action without if: there is no unconditional rule");
        return -1;
    }
    s.k++;
    d->root = parse_expr(&s, 0u);
    if (d->root < 0) {
        return -1;
    }
    t = ps_tok(&s);
    if (t->type != TK_EOF) {
        if (is_punct_tok(t, TK_RPAREN)) {
            fail_tok(c, "parsing", "unbalanced parentheses", d, t, "remove it", "unbalanced parentheses: a ) with no (");
        } else if (is_punct_tok(t, TK_RBRACE)) {
            fail_tok(c, "parsing", "a stray }", d, t, "remove it", "a stray }");
        } else {
            fail_tok(c, "parsing", "trailing input", d, t, "join conditions with and or or",
                     "trailing input after a complete rule");
        }
        return -1;
    }
    return 0;
}

static int parse_set(cc_t *c, dir_t *d)
{
    const tok_t *t = &d->tok[0];
    uint32_t k;

    if (t->type != TK_SETREF) {
        fail_tok(c, "parsing", "a set declaration names its set with @", d, t, "whisper_edge_set \"@name members\"",
                 "a set declaration names its set with @");
        return -1;
    }
    for (k = 1u; k < d->ntok; k++) {
        t = &d->tok[k];
        if (t->type == TK_EOF) {
            break;
        }
        if (t->type == TK_LIT || t->type == TK_COMMA) {
            continue;
        }
        if (t->type == TK_WORD) {
            fail_tok(c, "parsing", "an unknown attribute or word", d, t, "a declaration lists literals",
                     "an unknown attribute or word");
        } else {
            fail_tok(c, "parsing", "only literals in a set declaration", d, t,
                     "a declaration lists literals, separated by spaces or commas, without braces",
                     "only literals in a set declaration");
        }
        return -1;
    }
    return 0;
}

/* ======================================================================================================
 * Layer 5: typing
 * ==================================================================================================== */

/* is a literal token of a class the attribute takes? undetermined is a value of every sentinel attribute */
static int lit_fits(uint32_t a, const tok_t *t)
{
    const attr_t *at = &attrs[a];

    if (t->sub == LC_UNDET) {
        return at->sentinel;
    }
    switch (at->cls) {
    case AC_LEVEL:   return t->sub == LC_LEVEL;
    case AC_ENUM:    return t->sub == LC_ENUM && t->dom == at->dom;
    case AC_ASN:     return t->sub == LC_ASN;
    case AC_COUNTRY: return t->sub == LC_COUNTRY;
    default:         return 0;
    }
}

/* a literal's class key for the one-class rule: class and enum domain */
static uint32_t lit_key(const tok_t *t)
{
    return (uint32_t)t->sub * 16u + (t->sub == LC_ENUM ? t->dom : 0u);
}

static void wrong_class(cc_t *c, dir_t *d, uint32_t attr, const tok_t *t)
{
    char msg[160];

    attr_domain_msg(attr, msg, sizeof msg);
    fail_tok(c, "typing", msg, d, t, "", msg);
}

/* every atom, in source order (atoms are created in source order, so their node order is it) */
static int type_rule(cc_t *c, dir_t *d)
{
    uint32_t k;

    for (k = 0u; k < d->nnodes; k++) {
        node_t *n = &d->nodes[k];
        const attr_t *at;

        if (n->type != N_ATOM || n->form == F_BARE || n->form == F_ISUNK) {
            continue;
        }
        at = &attrs[n->attr];
        if (at->cls == AC_BOOL) {
            char fix[96];

            if (n->form == F_CMP && n->op >= OP_GE) {
                fail_tok(c, "typing", "an ordered comparison on anything but listed", d, &d->tok[n->optok],
                         "only listed is ordered: use == or in", "an ordered comparison on anything but listed");
                return -1;
            }
            {
                /* the operand: a literal, or the first member of an inline set every member of which is it */
                const tok_t *ut = NULL;

                if (n->form == F_CMP && d->tok[n->littok].sub == LC_UNDET) {
                    ut = &d->tok[n->littok];
                } else if (n->form == F_IN && !n->named) {
                    uint32_t m, lits = 0u, und = 0u;
                    const tok_t *first = NULL;

                    for (m = n->littok + 1u; m < n->endtok; m++) {
                        if (d->tok[m].type == TK_LIT) {
                            first = first != NULL ? first : &d->tok[m];
                            lits++;
                            und += d->tok[m].sub == LC_UNDET;
                        }
                    }
                    ut = lits != 0u && und == lits ? first : NULL;
                }
                if (ut != NULL) {
                    /* a bool is TRUE or FALSE once its plane is read; the outage is `is unknown` */
                    snprintf(fix, sizeof fix, "write %s, not %s, or %s is unknown", at->name, at->name, at->name);
                    fail_tok(c, "typing", "undetermined on a bool", d, ut, fix, "undetermined on a bool");
                    return -1;
                }
            }
            snprintf(fix, sizeof fix, "write %s or not %s", at->name, at->name);
            fail_tok(c, "typing", "in or == on a bool", d, &d->tok[n->optok], fix, "in or == on a bool");
            return -1;
        }
        if (n->form == F_CMP) {
            if (n->op >= OP_GE && at->cls != AC_LEVEL) {
                fail_tok(c, "typing", "an ordered comparison on anything but listed", d, &d->tok[n->optok],
                         "only listed is ordered: use == or in", "an ordered comparison on anything but listed");
                return -1;
            }
            if (!lit_fits(n->attr, &d->tok[n->littok])) {
                wrong_class(c, d, n->attr, &d->tok[n->littok]);
                return -1;
            }
            continue;
        }
        if (!n->named) {
            uint32_t m, key = 0u;

            /*
             * One class first, then the attribute's: a set of two classes is refused at the first member
             * whose class differs from the first member's (undetermined takes the others' class), and
             * a set of one wrong class at its first member.
             */
            for (m = n->littok + 1u; m < n->endtok; m++) {
                const tok_t *t = &d->tok[m];

                if (t->type != TK_LIT || t->sub == LC_UNDET) {
                    continue;
                }
                if (key == 0u) {
                    key = lit_key(t) + 1u;
                } else if (lit_key(t) + 1u != key) {
                    fail_tok(c, "typing", "an inline set whose members are not all of one class", d, t,
                             "a set holds one class of value: split it, or use two in tests joined by or",
                             "an inline set whose members are not all of one class");
                    return -1;
                }
            }
            for (m = n->littok + 1u; m < n->endtok; m++) {
                if (d->tok[m].type == TK_LIT && !lit_fits(n->attr, &d->tok[m])) {
                    wrong_class(c, d, n->attr, &d->tok[m]);
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* ======================================================================================================
 * Contexts
 * ==================================================================================================== */

/* FNV-1a over a context name's bytes; incremental, so every prefix of a path is hashed in one pass */
#define NAME_HASH0 2166136261u
static uint32_t name_hash_step(uint32_t h, uint8_t b)
{
    return (h ^ b) * 16777619u;
}

static uint32_t name_hash(const char *s, size_t n)
{
    uint32_t h = NAME_HASH0;
    size_t i;

    for (i = 0u; i < n; i++) {
        h = name_hash_step(h, (uint8_t)s[i]);
    }
    return h;
}

/* a power of two at least twice n, so an open-addressed table stays at most half full */
static uint32_t table_size(size_t n)
{
    uint32_t t = 16u;

    while (t < 2u * n + 2u) {
        t <<= 1;
    }
    return t;
}

/* the context named by name[0..len), whose hash is h; -1 with *slot the empty slot it would take */
static int32_t ctx_find(const cc_t *c, const char *name, size_t len, uint32_t h, uint32_t *slot)
{
    uint32_t i = h & c->cmask;

    while (c->cht[i] != 0u) {
        const ctxent_t *e = &c->ctxs[c->cht[i] - 1u];

        if (e->hash == h && e->len == len && memcmp(e->name, name, len) == 0) {
            return (int32_t)(c->cht[i] - 1u);
        }
        i = (i + 1u) & c->cmask;
    }
    *slot = i;
    return -1;
}

/* intern a context and every ancestor; "a/b/c" has parents "a/b" and "a" */
static int32_t ctx_intern(cc_t *c, const char *name)
{
    size_t len = strlen(name), at;
    int32_t parent = -1;
    uint32_t h = NAME_HASH0;

    /*
     * Every prefix that ends before a '/', then the name itself, each with the one before as its
     * parent. Iterative, and with no buffer: a context is the server's own name for a block and may be
     * as long and as deep as it likes. The table was sized for every such prefix (context_capacity()),
     * so the bound below is the table's own and a full table is an allocation failure, never a write
     * past it.
     */
    for (at = 0u; at <= len; at++) {
        int32_t id;
        uint32_t slot = 0u;

        if (at != len && name[at] != '/') {
            h = name_hash_step(h, (uint8_t)name[at]);
            continue;
        }
        id = ctx_find(c, name, at, h, &slot);
        if (id < 0) {
            ctxent_t *e;

            if (c->nctx >= c->ctxcap) {
                return -1;
            }
            e = &c->ctxs[c->nctx];
            memset(e, 0, sizeof *e);
            e->name = (char *)ar_get(&c->ar, at + 1u);
            if (e->name == NULL) {
                return -1;
            }
            memcpy(e->name, name, at);
            e->name[at] = '\0';
            e->len = (uint32_t)at;
            e->hash = h;
            e->parent = parent;
            id = (int32_t)c->nctx++;
            c->cht[slot] = (uint32_t)id + 1u;
        }
        parent = id;
        if (at != len) {
            h = name_hash_step(h, (uint8_t)name[at]);     /* the '/' belongs to the longer prefixes */
        }
    }
    return parent;
}

/* the contexts a source can intern: "http" and, per directive, every prefix of its context's path */
static size_t context_capacity(const we_policy_source_t *src)
{
    size_t n = 1u, i;

    for (i = 0u; i < src->n; i++) {
        const char *x = src->d[i].context != NULL ? src->d[i].context : "http";

        n += 1u;
        for (; *x != '\0'; x++) {
            n += *x == '/';
        }
    }
    return n;
}

/* ======================================================================================================
 * Layer 6: sets
 * ==================================================================================================== */

static int set_name_eq(const cc_t *c, const setdecl_t *s, const uint8_t *nm, uint32_t nl)
{
    return s->name_len == nl && memcmp(c->dirs[s->dir].arg + s->name_off, nm, nl) == 0;
}

/* the nearest visible declaration of a name from context `ctx`, or -1 */
static int32_t set_resolve(const cc_t *c, uint32_t ctx, const uint8_t *nm, uint32_t nl)
{
    int32_t x = (int32_t)ctx;

    while (x >= 0) {
        uint32_t i;

        for (i = 0u; i < c->nsets; i++) {
            if (c->sets[i].ctx == (uint32_t)x && set_name_eq(c, &c->sets[i], nm, nl)) {
                return (int32_t)i;
            }
        }
        x = c->ctxs[x].parent;
    }
    return -1;
}

/*
 * Does a set fit the attribute? A set holding only undetermined (SC_ANY) fits every attribute with a
 * sentinel; a level set may not hold undetermined, because listed has no sentinel.
 */
static int set_fits(uint32_t a, const setdecl_t *s)
{
    const attr_t *at = &attrs[a];

    if (s->cls == SC_ANY) {
        return at->sentinel;
    }
    switch (at->cls) {
    case AC_LEVEL:   return s->cls == LC_LEVEL && !s->has_undet;
    case AC_ENUM:    return s->cls == LC_ENUM && s->dom == at->dom;
    case AC_ASN:     return s->cls == LC_ASN;
    case AC_COUNTRY: return s->cls == LC_COUNTRY;
    default:         return 0;
    }
}

/* a declaration's refusal: at line 1, column 1, with the set's name as the token */
static void fail_decl(cc_t *c, const dir_t *d, const char *phrase, const char *fix, const char *what)
{
    const tok_t *nt = &d->tok[0];

    fail_at(c, "sets", phrase, d, nt->off, nt->len, 1, fix, "%s", what);
    if (c->err != NULL) {
        c->err->line = 1u;
        c->err->col = 1u;
    }
}

/*
 * Step 6, once every directive is seen: every declaration in source order (the configuration's count,
 * then a duplicate in one scope), every declaration again (a shadowing of an outer set, no members,
 * members of more than one class), then every use in source order (an empty inline set, an undefined
 * name, a set of another class than its attribute).
 */
static int sets_layer(cc_t *c)
{
    uint32_t i, j, declared = 0u;

    for (i = 0u; i < c->nsets; i++) {
        setdecl_t *s = &c->sets[i];
        const dir_t *d = &c->dirs[s->dir];
        int have = 0;
        uint32_t key = 0u;

        s->cls = SC_ANY;
        s->mixed = 0u;
        s->has_undet = 0u;
        s->nlits = 0u;
        for (j = 1u; j < d->ntok; j++) {
            const tok_t *m = &d->tok[j];

            if (m->type != TK_LIT) {
                continue;
            }
            s->nlits++;
            if (m->sub == LC_UNDET) {
                s->has_undet = 1u;
                continue;
            }
            if (have && lit_key(m) != key) {
                s->mixed = 1u;
            }
            if (!have) {
                have = 1;
                key = lit_key(m);
                s->cls = m->sub;
                s->dom = m->dom;
            }
        }
    }
    for (i = 0u; i < c->nsets; i++) {
        const setdecl_t *s = &c->sets[i];
        const dir_t *d = &c->dirs[s->dir];

        declared++;
        if (declared > WE_LIM_SETS) {
            char what[256];

            snprintf(what, sizeof what, "more than 1,024 sets in the configuration (%s declares the 1,025th)",
                     c->ctxs[s->ctx].name);
            fail_decl(c, d, "more than 1,024 sets in the configuration", "declare fewer sets", what);
            return -1;
        }
        for (j = 0u; j < i; j++) {
            if (c->sets[j].ctx == s->ctx && set_name_eq(c, &c->sets[j], d->arg + s->name_off, s->name_len)) {
                char fix[256];

                snprintf(fix, sizeof fix, "it is already declared in %s", c->ctxs[s->ctx].name);
                fail_decl(c, d, "a duplicate definition in one scope", fix, "a duplicate definition in one scope");
                return -1;
            }
        }
    }
    for (i = 0u; i < c->nsets; i++) {
        const setdecl_t *s = &c->sets[i];
        const dir_t *d = &c->dirs[s->dir];
        int32_t x = c->ctxs[s->ctx].parent;

        while (x >= 0) {
            for (j = 0u; j < c->nsets; j++) {
                if (c->sets[j].ctx == (uint32_t)x && set_name_eq(c, &c->sets[j], d->arg + s->name_off, s->name_len)) {
                    char fix[256];

                    snprintf(fix, sizeof fix, "it is already declared in %s; give the inner set its own name",
                             c->ctxs[x].name);
                    fail_decl(c, d, "a definition shadowing an outer set", fix, "a definition shadowing an outer set");
                    return -1;
                }
            }
            x = c->ctxs[x].parent;
        }
        if (s->nlits == 0u) {
            fail_decl(c, d, "a declaration with no members", "list the members after the name",
                      "a declaration with no members");
            return -1;
        }
        if (s->mixed) {
            fail_decl(c, d, "a declared set whose members are not of one class", "a set holds values of one class",
                      "a declared set whose members are not of one class");
            return -1;
        }
    }
    for (i = 0u; i < c->ndirs; i++) {
        dir_t *d = &c->dirs[i];
        uint32_t k;

        if (d->d->kind != WE_DIR_POLICY && d->d->kind != WE_DIR_FLOOR) {
            continue;
        }
        for (k = 0u; k < d->nnodes; k++) {
            node_t *n = &d->nodes[k];
            const tok_t *rt;

            if (n->type != N_ATOM || n->form != F_IN) {
                continue;
            }
            rt = &d->tok[n->littok];
            if (!n->named) {
                uint32_t m, lits = 0u;

                for (m = n->littok + 1u; m < n->endtok; m++) {
                    lits += d->tok[m].type == TK_LIT;
                }
                if (lits == 0u) {
                    fail_tok(c, "sets", "an empty set", d, rt, "an empty set matches nothing; remove the rule",
                             "an empty set");
                    return -1;
                }
                continue;
            }
            {
                int32_t sx = set_resolve(c, d->ctx, d->arg + rt->off + 1u, rt->len - 1u);
                char what[200];

                if (sx < 0) {
                    render_token(d->arg + rt->off, rt->len, what, sizeof what);
                    fail_tok(c, "sets", "undefined in this context or an enclosing one", d, rt,
                             "declare it with whisper_edge_set", "");
                    if (c->err != NULL) {
                        snprintf(c->err->what, sizeof c->err->what, "%s undefined in this context or an enclosing one",
                                 what);
                    }
                    return -1;
                }
                n->set = sx;
                if (!set_fits(n->attr, &c->sets[sx])) {
                    /*
                     * Including a declared set holding undetermined used against listed: POLICY.md 5.6's
                     * D-z addendum refuses it here, at the use, where a declared set's class is known.
                     */
                    attr_domain_msg(n->attr, what, sizeof what);
                    fail_tok(c, "sets", "a set used against an attribute of another class", d, rt, what,
                             "a set used against an attribute of another class");
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* ======================================================================================================
 * The encoder: one context's program as a block, POLICY.md §2
 * ==================================================================================================== */

/* the compiled-in table: FORMAT.md §2 and §3 in C */
static void binding_of(uint32_t p, we_binding_t *b)
{
    memset(b, 0, sizeof *b);
    if (p == 0u) {
        b->schema_id = WE_SCHEMA_FORMAT1;
        b->width = 1u;
        b->key6 = 16u;
        return;
    }
    if (p == 3u || p == 6u) {
        b->schema_id = WE_SCHEMA_ROUTING;
        b->width = 10u;
        b->key6 = 8u;
        b->stride4 = 16u;
        b->stride6 = 24u;
        b->off4 = 4u;
        b->off6 = 8u;
        b->flag_mask = WE_RF_ANYCAST | WE_RF_MOAS | WE_RF_NARROWED;
        b->tmpl[0] = 0xffu;   /* asn: undetermined */
        b->tmpl[1] = 0xffu;
        b->tmpl[2] = 0xffu;
        b->tmpl[3] = 0xffu;
        b->tmpl[6] = 4u;      /* rov: unrouted, which only absence produces */
        return;
    }
    b->schema_id = WE_SCHEMA_MEMBERSHIP;
    b->width = 6u;
    b->key6 = 16u;
    b->stride4 = 16u;
    b->stride6 = 32u;
    b->off4 = 4u;
    b->off6 = 16u;
    b->flag_mask = p == 1u ? WE_MF_TOR_EXIT
                 : p == 2u ? WE_MF_RPKI_UNREACHABLE
                 : p == 4u ? (WE_MF_PROXY | WE_MF_VPN)
                 : p == 5u ? (WE_MF_C2 | WE_MF_BRUTEFORCE | WE_MF_SPAM | WE_MF_PHISHING | WE_MF_SCANNER | WE_MF_STATE_ACTOR)
                 : (WE_MF_TENANT_ALLOW | WE_MF_TENANT_DENY);
}

/* a growable byte buffer from the arena */
typedef struct {
    arena_t *ar;
    uint8_t *p;
    size_t   len;
    size_t   cap;
} buf_t;

static int buf_put(buf_t *b, const void *data, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap * 2u + n + 256u;
        uint8_t *np = (uint8_t *)ar_get(b->ar, cap);

        if (np == NULL) {
            return -1;
        }
        if (b->len > 0u) {
            memcpy(np, b->p, b->len);
        }
        b->p = np;
        b->cap = cap;
    }
    if (n > 0u) {
        memcpy(b->p + b->len, data, n);
    }
    b->len += n;
    return 0;
}

static int buf_str(buf_t *b, const char *s)
{
    return buf_put(b, s, strlen(s));
}

/* one payload: a country bitmap or an ASN tree, keyed by what produced it */
typedef struct {
    int32_t  set;          /* a named set, or -1 for an inline one */
    uint32_t dir;          /* the inline set's directive and its { token */
    uint32_t tok;
    uint8_t  kind;
    uint8_t  hasu;
    uint8_t  levels;
    uint8_t  pad;
    uint32_t count;
    uint32_t data_off;     /* from the start of the set data */
    uint32_t data_len;
    uint8_t *data;
} payload_t;

typedef struct {
    cc_t        *c;
    buf_t        ins;       /* we_instr_t */
    buf_t        rules;     /* we_rule_t */
    buf_t        text;      /* the canonical text */
    buf_t        sdata;     /* set payloads */
    payload_t   *pay;
    uint32_t     npay;
    uint32_t     cappay;
    int32_t     *named;     /* the named sets the text declares, in order of first reference */
    uint32_t     nnamed;
    int32_t     *named_text; /* the same, in the order of their names, as the text declares them */
    uint32_t     ops;
    uint8_t      plane_mask;
    uint8_t      floor;
    uint8_t      legacy;
    uint8_t      inert_mask;
} enc_t;

/* the members of an IN atom as token pointers (named or inline), into a caller array */
static uint32_t members_of(const cc_t *c, const dir_t *d, const node_t *n, const tok_t **out, uint32_t cap)
{
    uint32_t k = 0u, m;

    if (n->named) {
        const setdecl_t *s = &c->sets[n->set];
        const dir_t *sd = &c->dirs[s->dir];

        for (m = 1u; m < sd->ntok && k < cap; m++) {
            if (sd->tok[m].type == TK_LIT) {
                out[k++] = &sd->tok[m];
            }
        }
        return k;
    }
    for (m = n->littok + 1u; m < n->endtok && k < cap; m++) {
        if (d->tok[m].type == TK_LIT) {
            out[k++] = &d->tok[m];
        }
    }
    return k;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

    return x < y ? -1 : x > y;
}

/* the S+ tree of POLICY.md §4.1, root first; returns the node count, writes into out (nodes * 64 bytes) */
static uint32_t splus_levels(uint32_t n)
{
    return n <= 16u ? 1u : n <= 272u ? 2u : 3u;
}

static uint32_t splus_nodes(uint32_t n)
{
    uint32_t m0 = (n + 15u) / 16u, m1 = (m0 + 16u) / 17u, lv = splus_levels(n);

    return m0 + (lv >= 2u ? m1 : 0u) + (lv >= 3u ? 1u : 0u);
}

static void splus_build(const uint32_t *keys, uint32_t n, uint8_t *out)
{
    uint32_t lv = splus_levels(n), m0 = (n + 15u) / 16u, m1 = (m0 + 16u) / 17u;
    uint32_t size[3], off[3], l, j, i;

    size[0] = m0;
    size[1] = lv >= 2u ? m1 : 0u;
    size[2] = lv >= 3u ? 1u : 0u;
    /* root first: level lv-1 at 0 */
    off[lv - 1u] = 0u;
    for (l = lv - 1u; l > 0u; l--) {
        off[l - 1u] = off[l] + size[l] * 64u;
    }
    for (l = 0u; l < lv; l++) {
        uint32_t span = 1u, q;

        for (q = 0u; q + 1u < l; q++) {
            span *= 17u;              /* leaves under one node of level l - 1 */
        }
        for (j = 0u; j < size[l]; j++) {
            uint32_t *node = (uint32_t *)(void *)(out + off[l] + j * 64u);

            for (i = 0u; i < 16u; i++) {
                uint32_t v = 0xffffffffu;

                if (l == 0u) {
                    if (j * 16u + i < n) {
                        v = keys[j * 16u + i];
                    }
                } else {
                    uint32_t child = j * 17u + i + 1u;

                    if (child < size[l - 1u]) {
                        v = keys[child * span * 16u];
                    }
                }
                memcpy(&node[i], &v, 4);
            }
        }
    }
}

/* add (or find) the payload for an IN atom of country or ASN class; returns its index, or -1 */
static int32_t payload_for(enc_t *e, const dir_t *d, const node_t *n, uint32_t ni)
{
    cc_t *c = e->c;
    const tok_t **mem = c->mem;
    uint32_t nm = members_of(c, d, n, mem, WE_LIM_ARG), k;
    uint8_t kind = attrs[n->attr].cls == AC_COUNTRY ? WE_SET_COUNTRY : WE_SET_ASN;
    payload_t *p;

    for (k = 0u; k < e->npay; k++) {
        p = &e->pay[k];
        if (n->named ? (p->set == n->set && p->kind == kind) : (p->set < 0 && p->dir == d->index && p->tok == ni)) {
            return (int32_t)k;
        }
    }
    if (e->npay == e->cappay) {
        uint32_t cap = e->cappay * 2u + 8u;
        payload_t *np = (payload_t *)ar_get(&c->ar, sizeof(payload_t) * cap);

        if (np == NULL) {
            return -2;
        }
        if (e->npay > 0u) {
            memcpy(np, e->pay, sizeof(payload_t) * e->npay);
        }
        e->pay = np;
        e->cappay = cap;
    }
    p = &e->pay[e->npay];
    memset(p, 0, sizeof *p);
    p->set = n->named ? n->set : -1;
    p->dir = d->index;
    p->tok = ni;
    p->kind = kind;
    if (kind == WE_SET_COUNTRY) {
        p->data_len = 128u;
        p->data = (uint8_t *)ar_get(&c->ar, 128u);
        if (p->data == NULL) {
            return -2;
        }
        for (k = 0u; k < nm; k++) {
            uint32_t code = mem[k]->sub == LC_UNDET ? 0u : mem[k]->val;

            if (mem[k]->sub == LC_UNDET) {
                p->hasu = 1u;
            }
            if ((p->data[code >> 3] & (1u << (code & 7u))) == 0u && code != 0u) {
                p->count++;
            }
            p->data[code >> 3] = (uint8_t)(p->data[code >> 3] | (1u << (code & 7u)));
        }
    } else {
        uint32_t *keys = c->keys, nk = 0u, u = 0u;

        for (k = 0u; k < nm; k++) {
            if (mem[k]->sub == LC_UNDET) {
                p->hasu = 1u;
            } else {
                keys[nk++] = mem[k]->val;
            }
        }
        qsort(keys, nk, sizeof keys[0], cmp_u32);
        for (k = 0u; k < nk; k++) {
            if (u == 0u || keys[u - 1u] != keys[k]) {
                keys[u++] = keys[k];
            }
        }
        p->count = u;
        p->levels = (uint8_t)splus_levels(u);
        p->data_len = splus_nodes(u) * 64u;
        p->data = (uint8_t *)ar_get(&c->ar, p->data_len);
        if (p->data == NULL) {
            return -2;
        }
        splus_build(keys, u, p->data);
    }
    p->data_off = (uint32_t)e->sdata.len;
    if (buf_put(&e->sdata, p->data, p->data_len) != 0) {
        return -2;
    }
    return (int32_t)e->npay++;
}

static int emit(enc_t *e, uint16_t op, uint32_t plane, uint32_t off, uint32_t imm)
{
    we_instr_t i;

    i.op = op;
    i.plane = (uint8_t)plane;
    i.off = (uint8_t)off;
    i.imm = imm;
    if ((op & WE_OP_ATOM) != 0u) {
        e->plane_mask = (uint8_t)(e->plane_mask | (1u << plane));
    }
    return buf_put(&e->ins, &i, sizeof i);
}

static uint32_t ins_count(const enc_t *e)
{
    return (uint32_t)(e->ins.len / sizeof(we_instr_t));
}

static void patch_imm(enc_t *e, uint32_t at, uint32_t imm)
{
    memcpy(e->ins.p + (size_t)at * sizeof(we_instr_t) + 4u, &imm, 4);
}

/* the level mask of a listed comparison */
static uint32_t sev_mask(uint32_t op, uint32_t lvl)
{
    uint32_t m = 0u, l;

    for (l = 0u; l < 5u; l++) {
        int hit = op == OP_EQ ? l == lvl : op == OP_NE ? l == lvl
                : op == OP_GE ? l >= lvl : op == OP_GT ? l > lvl : op == OP_LE ? l <= lvl : l < lvl;
        m |= hit ? (1u << l) : 0u;
    }
    return m;
}

static int emit_node(enc_t *e, const dir_t *d, int32_t id, uint32_t neg, uint8_t *dep);

static int emit_atom(enc_t *e, const dir_t *d, const node_t *n, uint32_t neg, uint8_t *dep)
{
    const attr_t *at = &attrs[n->attr];
    uint32_t pl = at->plane;

    *dep = (uint8_t)(*dep | (1u << pl));
    if (n->form == F_BARE) {
        uint32_t imm = at->mask;

        if (n->attr == A_TENANT_ALLOW && neg == 0u && d->action == WE_ACT_ALLOW) {
            imm |= WE_BOOL_POLARITY;
        }
        return emit(e, WE_OP_BOOL, pl, at->off, imm);
    }
    if (n->form == F_ISUNK) {
        if (emit(e, WE_OP_ISUNK, pl, 0u, 0u) != 0) {
            return -1;
        }
        return n->negated ? emit(e, WE_OP_NOT, 0u, 0u, 0u) : 0;
    }
    if (n->form == F_CMP) {
        const tok_t *lt = &d->tok[n->littok];
        int rc;

        if (at->cls == AC_LEVEL) {
            rc = emit(e, WE_OP_SEV, pl, 0u, sev_mask(n->op == OP_NE ? OP_EQ : n->op, lt->val));
        } else if (at->cls == AC_ENUM) {
            rc = emit(e, WE_OP_EQ8, pl, at->off, lt->sub == LC_UNDET ? 0u : lt->val);
        } else if (at->cls == AC_COUNTRY) {
            rc = emit(e, WE_OP_EQ16, pl, at->off, lt->sub == LC_UNDET ? 0u : lt->val);
        } else {
            rc = emit(e, WE_OP_EQ32, pl, at->off, lt->sub == LC_UNDET ? 0xffffffffu : lt->val);
        }
        if (rc != 0) {
            return -1;
        }
#ifdef WE_TEST_SENTINEL_NE
        /* the mutant: `!= undetermined` read TRUE at the sentinel, as if != were not `not ==` there */
        if (n->op == OP_NE && lt->sub == LC_UNDET) {
            return 0;
        }
#endif
        return n->op == OP_NE ? emit(e, WE_OP_NOT, 0u, 0u, 0u) : 0;
    }
    /* F_IN */
    {
        const tok_t **mem = e->c->mem;   /* not used past payload_for, which reuses it */
        uint32_t nm = members_of(e->c, d, n, mem, WE_LIM_ARG), k, mask = 0u;

        if (n->named) {
            /* every named set the program references is declared in its canonical text, whatever its
             * encoding, or the text would not re-parse */
            uint32_t q;
            int seen = 0;

            for (q = 0u; q < e->nnamed; q++) {
                seen |= e->named[q] == n->set;
            }
            if (!seen) {
                e->named[e->nnamed++] = n->set;
            }
        }
        if (at->cls == AC_LEVEL || at->cls == AC_ENUM) {
            for (k = 0u; k < nm; k++) {
                mask |= 1u << (mem[k]->sub == LC_UNDET ? 0u : mem[k]->val);
            }
            return at->cls == AC_LEVEL ? emit(e, WE_OP_SEV, pl, 0u, mask)
                                       : emit(e, WE_OP_INSET_ENUM, pl, at->off, mask);
        }
        if (at->cls == AC_ASN) {
            uint32_t numeric = 0u;

            for (k = 0u; k < nm; k++) {
                numeric += mem[k]->sub != LC_UNDET;
            }
            if (numeric == 0u) {
                /* no numeric member: `asn == undetermined`, no payload (POLICY.md §4.1) */
                return emit(e, WE_OP_EQ32, pl, at->off, 0xffffffffu);
            }
        }
        {
            int32_t pi = payload_for(e, d, n, (uint32_t)n->littok);
            payload_t *p;

            if (pi < 0) {
                return -1;
            }
            p = &e->pay[pi];
            /* the payload offset is patched to a block offset once the layout is known: record the
             * payload index in imm for now, with the ASN fields */
            if (p->kind == WE_SET_COUNTRY) {
                return emit(e, WE_OP_INSET_COUNTRY, pl, at->off, (uint32_t)pi);
            }
            return emit(e, WE_OP_INSET_ASN, pl, at->off, WE_ASN_IMM((uint32_t)pi, p->levels, p->hasu, p->count));
        }
    }
}

static int emit_node(enc_t *e, const dir_t *d, int32_t id, uint32_t neg, uint8_t *dep)
{
    const node_t *n = &d->nodes[id];

    if (n->type == N_ATOM) {
        return emit_atom(e, d, n, neg, dep);
    }
    if (n->type == N_NOT) {
        if (emit_node(e, d, n->first, neg ^ 1u, dep) != 0) {
            return -1;
        }
        return emit(e, WE_OP_NOT, 0u, 0u, 0u);
    }
    {
        uint16_t jop = n->type == N_AND ? WE_OP_JF : WE_OP_JT;
        uint16_t cop = n->type == N_AND ? WE_OP_AND : WE_OP_OR;
        uint32_t jumps[WE_LIM_OPS_RULE], nj = 0u, k;
        int32_t ch;

        if (emit_node(e, d, n->first, neg, dep) != 0) {
            return -1;
        }
        for (ch = d->nodes[n->first].next; ch >= 0; ch = d->nodes[ch].next) {
            jumps[nj++] = ins_count(e);
            if (emit(e, jop, 0u, 0u, 0u) != 0 || emit_node(e, d, ch, neg, dep) != 0 || emit(e, cop, 0u, 0u, 0u) != 0) {
                return -1;
            }
        }
        for (k = 0u; k < nj; k++) {
            patch_imm(e, jumps[k], ins_count(e));
        }
        return 0;
    }
}

/* the canonical rendering of a literal */
static void render_lit(const tok_t *t, char *out, size_t n)
{
    char a2[3];

    switch (t->sub) {
    case LC_LEVEL:   snprintf(out, n, "%s", level_name[t->val]); break;
    case LC_ENUM:    snprintf(out, n, "%s", enum_name(t->dom, t->val)); break;
    case LC_COUNTRY: snprintf(out, n, "%s", country_alpha2(t->val, a2)); break;
    case LC_ASN:     snprintf(out, n, "%" PRIu32, t->val); break;
    default:         snprintf(out, n, "undetermined"); break;
    }
}

/*
 * The canonical member order: undetermined first, then levels and enums in domain order, AS numbers
 * ascending, country codes alphabetically. One set holds one class, so the key compares within it.
 */
static int member_cmp(const void *a, const void *b)
{
    const tok_t *x = *(const tok_t *const *)a, *y = *(const tok_t *const *)b;
    int ux = x->sub == LC_UNDET, uy = y->sub == LC_UNDET;

    if (ux != uy) {
        return ux ? -1 : 1;
    }
    if (ux) {
        return 0;
    }
    if (x->sub == LC_COUNTRY && y->sub == LC_COUNTRY) {
        char ax[3], ay[3];

        return strcmp(country_alpha2(x->val, ax), country_alpha2(y->val, ay));
    }
    return x->val < y->val ? -1 : x->val > y->val ? 1 : 0;
}

/* the members, sorted canonically and without duplicates, space-separated; sorts `mem` in place */
static int render_members(buf_t *b, const tok_t **mem, uint32_t nm)
{
    uint32_t k, out = 0u;
    char lit[32];

    qsort((void *)mem, nm, sizeof *mem, member_cmp);
    for (k = 0u; k < nm; k++) {
        if (k > 0u && member_cmp(&mem[k - 1u], &mem[k]) == 0) {
            continue;
        }
        render_lit(mem[k], lit, sizeof lit);
        if ((out++ > 0u && buf_str(b, " ") != 0) || buf_str(b, lit) != 0) {
            return -1;
        }
    }
    return 0;
}

static int render_node(enc_t *e, const dir_t *d, int32_t id, buf_t *b)
{
    const node_t *n = &d->nodes[id];

    if (n->type == N_ATOM) {
        const attr_t *at = &attrs[n->attr];

        if (buf_str(b, at->name) != 0) {
            return -1;
        }
        if (n->form == F_ISUNK) {
            return buf_str(b, n->negated ? " is not unknown" : " is unknown");
        }
        if (n->form == F_CMP) {
            char lit[32];

            render_lit(&d->tok[n->littok], lit, sizeof lit);
            return buf_str(b, " ") || buf_str(b, op_name[n->op]) || buf_str(b, " ") || buf_str(b, lit) ? -1 : 0;
        }
        if (n->form == F_IN) {
            if (n->named) {
                const tok_t *rt = &d->tok[n->littok];

                return buf_str(b, " in ") || buf_put(b, d->arg + rt->off, rt->len) ? -1 : 0;
            } else {
                const tok_t **mem = e->c->mem;
                uint32_t nm = members_of(e->c, d, n, mem, WE_LIM_ARG);

                return buf_str(b, " in {") || render_members(b, mem, nm) || buf_str(b, "}") ? -1 : 0;
            }
        }
        return 0;
    }
    if (n->type == N_NOT) {
        const node_t *ch = &d->nodes[n->first];
        int paren = ch->type == N_AND || ch->type == N_OR;

        if (buf_str(b, paren ? "not (" : "not ") != 0 || render_node(e, d, n->first, b) != 0) {
            return -1;
        }
        return paren ? buf_str(b, ")") : 0;
    }
    {
        int32_t ch;
        int firstc = 1;

        for (ch = n->first; ch >= 0; ch = d->nodes[ch].next) {
            const node_t *cn = &d->nodes[ch];
            int paren = cn->type == N_AND || cn->type == N_OR;

            if (!firstc && buf_str(b, n->type == N_AND ? " and " : " or ") != 0) {
                return -1;
            }
            firstc = 0;
            if ((paren && buf_str(b, "(") != 0) || render_node(e, d, ch, b) != 0 || (paren && buf_str(b, ")") != 0)) {
                return -1;
            }
        }
        return 0;
    }
}

/* the stack depth a node needs, by the left-associative reduction */
static uint32_t node_depth(const dir_t *d, int32_t id)
{
    const node_t *n = &d->nodes[id];
    uint32_t m;
    int32_t ch;

    if (n->type == N_ATOM) {
        return 1u;
    }
    if (n->type == N_NOT) {
        return node_depth(d, n->first);
    }
    m = node_depth(d, n->first);
    for (ch = d->nodes[n->first].next; ch >= 0; ch = d->nodes[ch].next) {
        uint32_t x = 1u + node_depth(d, ch);

        m = x > m ? x : m;
    }
    return m;
}

/* ---- the hold-harmless arrays, floor blocks only (POLICY.md §3.8) ---- */

static uint32_t rank_depth_of(uint32_t m, uint32_t fanout)
{
    uint64_t p = 1u;
    uint32_t d = 0u;

    while (p < (uint64_t)m) {
        p *= fanout;
        d++;
    }
    return d;
}

static uint64_t pow_u64(uint64_t b, uint32_t e)
{
    uint64_t p = 1u;

    while (e-- > 0u) {
        p *= b;
    }
    return p;
}

static __uint128_t hh_key(const uint8_t *start, uint32_t kb, uint32_t i)
{
    if (kb == 4u) {
        uint32_t v;

        memcpy(&v, start + (size_t)i * 4u, 4);
        return v;
    } else {
        __uint128_t v;

        memcpy(&v, start + (size_t)i * 16u, 16);
        return v;
    }
}

/* the complete (B+1)-ary tree of FORMAT.md §4.2 over start[j*s], j in [1, m), in-order, max padding */
static void hh_tree(const uint8_t *start, uint32_t kb, uint32_t m, uint32_t s, uint32_t depth, uint8_t *out)
{
    uint32_t B = 64u / kb;
    uint64_t fan = (uint64_t)B + 1u, width = 1u, first = 0u;
    uint32_t l;

    for (l = 0u; l < depth; l++) {
        uint64_t below = pow_u64(fan, depth - 1u - l), t;

        for (t = 0u; t < width; t++) {
            uint8_t *node = out + (size_t)(first + t) * 64u;
            uint32_t q;

            for (q = 0u; q < B; q++) {
                uint64_t p = (t * fan + q + 1u) * below - 1u;
                __uint128_t v = p < (uint64_t)m - 1u ? hh_key(start, kb, (uint32_t)((p + 1u) * s))
                              : (kb == 4u ? (__uint128_t)0xffffffffu : ~(__uint128_t)0);

                if (kb == 4u) {
                    uint32_t v32 = (uint32_t)v;

                    memcpy(node + q * 4u, &v32, 4);
                } else {
                    memcpy(node + q * 16u, &v, 16);
                }
            }
        }
        first += width;
        width *= fan;
    }
}

static uint32_t hh_nodes(uint32_t kb, uint32_t depth)
{
    uint32_t B = 64u / kb;

    return (uint32_t)((pow_u64((uint64_t)B + 1u, depth) - 1u) / B);
}

static uint32_t al64(uint32_t v)
{
    return (v + 63u) & ~63u;
}

/* the size of the hold-harmless region */
static uint32_t hh_size(void)
{
    uint32_t n4 = WE_HH_V4_COUNT, n6 = WE_HH_V6_COUNT;
    uint32_t m4 = (n4 + 15u) / 16u, m6 = (n6 + 3u) / 4u;
    uint32_t d4 = rank_depth_of(m4, 17u), d6 = rank_depth_of(m6, 5u);

    return 64u + al64(4u * n4) * 2u + hh_nodes(4u, d4) * 64u + al64(16u * n6) * 2u + hh_nodes(16u, d6) * 64u;
}

/* write the region at `at` (block offset), into `blk` */
static void hh_write(uint8_t *blk, uint32_t at)
{
    we_hh_hdr_t h;
    uint32_t n4 = WE_HH_V4_COUNT, n6 = WE_HH_V6_COUNT, i, o = at + 64u;

    memset(&h, 0, sizeof h);
    h.v4_n = n4;
    h.v6_n = n6;
    h.v4_span = 16u;
    h.v6_span = 4u;
    h.v4_m = (n4 + 15u) / 16u;
    h.v6_m = (n6 + 3u) / 4u;
    h.v4_depth = (uint8_t)rank_depth_of(h.v4_m, 17u);
    h.v6_depth = (uint8_t)rank_depth_of(h.v6_m, 5u);
    h.v4_start_off = o;
    for (i = 0u; i < n4; i++) {
        memcpy(blk + o + i * 4u, &we_hh_v4[i][0], 4);
    }
    o += al64(4u * n4);
    h.v4_end_off = o;
    for (i = 0u; i < n4; i++) {
        memcpy(blk + o + i * 4u, &we_hh_v4[i][1], 4);
    }
    o += al64(4u * n4);
    h.v4_tree_off = hh_nodes(4u, h.v4_depth) > 0u ? o : 0u;
    hh_tree(blk + h.v4_start_off, 4u, h.v4_m, 16u, h.v4_depth, blk + o);
    o += hh_nodes(4u, h.v4_depth) * 64u;
    h.v6_start_off = o;
    for (i = 0u; i < n6; i++) {
        __uint128_t s = ((__uint128_t)we_hh_v6[i][0] << 64) | we_hh_v6[i][1];

        memcpy(blk + o + i * 16u, &s, 16);
    }
    o += al64(16u * n6);
    h.v6_end_off = o;
    for (i = 0u; i < n6; i++) {
        __uint128_t e = ((__uint128_t)we_hh_v6[i][2] << 64) | we_hh_v6[i][3];

        memcpy(blk + o + i * 16u, &e, 16);
    }
    o += al64(16u * n6);
    h.v6_tree_off = hh_nodes(16u, h.v6_depth) > 0u ? o : 0u;
    hh_tree(blk + h.v6_start_off, 16u, h.v6_m, 4u, h.v6_depth, blk + o);
    memcpy(blk + at, &h, sizeof h);
}

/*
 * Encode the rules of one program (directive indexes `rix`, in order) into a block allocated with the
 * caller's allocator, page-aligned. 0, or -2 on allocation failure.
 */
static int encode(cc_t *c, const uint32_t *rix, uint32_t nr, int floor, we_program_t **out)
{
    enc_t e;
    uint32_t r, k, nsets, hot, total, off;
    uint8_t *blk;
    we_program_t h;

    memset(&e, 0, sizeof e);
    e.c = c;
    e.ins.ar = e.rules.ar = e.text.ar = e.sdata.ar = &c->ar;
    e.floor = (uint8_t)floor;
    e.legacy = c->env->legacy;
    e.named = (int32_t *)ar_get(&c->ar, sizeof(int32_t) * (c->nsets + 1u));
    if (e.named == NULL) {
        return -2;
    }
    for (k = 0u; k < NPLANES; k++) {
        int bound = (c->env->present >> k) & 1u;

        e.inert_mask = (uint8_t)(e.inert_mask | ((!bound && !c->env->legacy) ? (1u << k) : 0u));
    }
    for (r = 0u; r < nr; r++) {
        const dir_t *d = &c->dirs[rix[r]];
        we_rule_t rule;
        uint8_t dep = 0u;
        uint32_t start = ins_count(&e), src0;

        memset(&rule, 0, sizeof rule);
        if (emit_node(&e, d, d->root, 0u, &dep) != 0 || emit(&e, WE_OP_END, 0u, 0u, 0u) != 0) {
            return -2;
        }
        rule.action = d->action;
        rule.flags = (uint8_t)((dep & e.inert_mask) != 0u ? WE_RF_INERT : 0u);
        rule.dep_mask = dep;
        rule.instr_start = (uint16_t)start;
        rule.instr_count = (uint16_t)(ins_count(&e) - start);
        rule.counter = (uint16_t)r;
        src0 = (uint32_t)e.text.len;
        if (buf_str(&e.text, d->action == WE_ACT_ALLOW ? "allow if " : d->action == WE_ACT_DENY ? "deny if " : "log if ")
                || render_node(&e, d, d->root, &e.text) != 0) {
            return -2;
        }
        rule.src_off = src0;
        rule.src_len = (uint16_t)(e.text.len - src0);
        if (buf_str(&e.text, "\n") != 0 || buf_put(&e.rules, &rule, sizeof rule) != 0) {
            return -2;
        }
        e.ops += d->ops;
    }
    /* the named sets the rules reference, declared in the text after the rules, in the order of their names */
    {
        int32_t *byname = (int32_t *)ar_get(&c->ar, sizeof(int32_t) * (e.nnamed + 1u));
        uint32_t j;

        if (byname == NULL) {
            return -2;
        }
        for (k = 0u; k < e.nnamed; k++) {
            const setdecl_t *s = &c->sets[e.named[k]];

            for (j = k; j > 0u; j--) {
                const setdecl_t *t = &c->sets[byname[j - 1u]];
                uint32_t ml = s->name_len < t->name_len ? s->name_len : t->name_len;
                int cmp = memcmp(c->dirs[t->dir].arg + t->name_off, c->dirs[s->dir].arg + s->name_off, ml);

                if (cmp < 0 || (cmp == 0 && t->name_len <= s->name_len)) {
                    break;
                }
                byname[j] = byname[j - 1u];
            }
            byname[j] = e.named[k];
        }
        e.named_text = byname;
    }
    for (k = 0u; k < e.nnamed; k++) {
        const setdecl_t *s = &c->sets[e.named_text[k]];
        const dir_t *sd = &c->dirs[s->dir];
        const tok_t **mem = c->mem;
        uint32_t nm = 0u, m;

        for (m = 1u; m < sd->ntok; m++) {
            if (sd->tok[m].type == TK_LIT) {
                mem[nm++] = &sd->tok[m];
            }
        }
        if (buf_str(&e.text, "@") != 0 || buf_put(&e.text, sd->arg + s->name_off, s->name_len) != 0
                || buf_str(&e.text, " ") != 0 || render_members(&e.text, mem, nm) != 0 || buf_str(&e.text, "\n") != 0) {
            return -2;
        }
    }
    nsets = e.npay;
    /* the layout, POLICY.md §2.1 */
    memset(&h, 0, sizeof h);
    h.magic = WE_PROG_MAGIC;
    h.version = WE_PROG_VERSION;
    h.flags = (uint16_t)((floor ? WE_PF_FLOOR : 0u) | (e.legacy ? WE_PF_LEGACY : 0u));
    h.rule_count = (uint16_t)nr;
    h.set_count = (uint16_t)nsets;
    h.instr_count = (uint16_t)ins_count(&e);
    h.op_count = (uint16_t)e.ops;
    off = 64u;
    h.rules_off = off;
    off = al64(off + 16u * nr);
    h.instrs_off = off;
    off = al64(off + 8u * h.instr_count);
    h.bindings_off = off;
    off += 256u;
    h.sets_off = off;
    off = al64(off + 16u * nsets);
    h.hh_off = off;
    off += floor ? hh_size() : 0u;
    h.setdata_off = off;
    off += (uint32_t)e.sdata.len;
    hot = off;
    h.hot_len = hot;
    h.text_off = hot;
    h.text_len = (uint32_t)e.text.len;
    total = al64(hot + h.text_len);
    h.total_len = total;
    for (r = 0u; r < nr; r++) {
        const we_rule_t *rr = (const we_rule_t *)(const void *)(e.rules.p + r * 16u);

        h.plane_mask = (uint8_t)(h.plane_mask | rr->dep_mask);
    }
    blk = (uint8_t *)a_alloc(c->alloc, (total + 4095u) & ~4095u, 4096u);
    if (blk == NULL) {
        return -2;
    }
    memset(blk, 0, (total + 4095u) & ~4095u);
    memcpy(blk, &h, sizeof h);
    if (nr > 0u) {
        memcpy(blk + h.rules_off, e.rules.p, 16u * nr);
    }
    /* the set payload offsets, now that the set data's place is known */
    for (k = 0u; k < h.instr_count; k++) {
        we_instr_t *in = (we_instr_t *)(void *)(e.ins.p + (size_t)k * 8u);

        if ((in->op & WE_OP_INSET_COUNTRY) != 0u) {
            in->imm = h.setdata_off + e.pay[in->imm].data_off;
        } else if ((in->op & WE_OP_INSET_ASN) != 0u) {
            const payload_t *p = &e.pay[WE_ASN_IMM_OFF(in->imm)];

            in->imm = WE_ASN_IMM(h.setdata_off + p->data_off, p->levels, p->hasu, p->count);
        }
    }
    if (h.instr_count > 0u) {
        memcpy(blk + h.instrs_off, e.ins.p, 8u * h.instr_count);
    }
    for (k = 0u; k < NPLANES; k++) {
        we_binding_t b;

        binding_of(k, &b);
        b.inert = (uint8_t)((e.inert_mask >> k) & 1u);
        memcpy(blk + h.bindings_off + k * 32u, &b, sizeof b);
    }
    for (k = 0u; k < nsets; k++) {
        we_setdesc_t sd;

        memset(&sd, 0, sizeof sd);
        sd.kind = e.pay[k].kind;
        sd.has_undetermined = e.pay[k].hasu;
        sd.levels = e.pay[k].levels;
        sd.count = e.pay[k].count;
        sd.data_off = h.setdata_off + e.pay[k].data_off;
        sd.data_len = e.pay[k].data_len;
        memcpy(blk + h.sets_off + k * 16u, &sd, sizeof sd);
    }
    if (floor) {
        hh_write(blk, h.hh_off);
    }
    if (e.sdata.len > 0u) {
        memcpy(blk + h.setdata_off, e.sdata.p, e.sdata.len);
    }
    if (e.text.len > 0u) {
        memcpy(blk + h.text_off, e.text.p, e.text.len);
    }
    *out = (we_program_t *)(void *)blk;
    return 0;
}

/* the hot bytes a program of these rules would take, computed before anything is allocated */
typedef struct {
    uint32_t rules, instrs, setbytes, nsets;
} hotacc_t;

static uint32_t hot_of(const hotacc_t *a, int floor)
{
    return al64(64u + 16u * a->rules) - 64u + 64u + al64(8u * a->instrs) + 256u + al64(16u * a->nsets)
         + (floor ? hh_size() : 0u) + a->setbytes;
}

/* instructions and payload bytes one rule adds; payloads of named sets already counted are not */
/*
 * The named sets a program has already paid for: one open-addressed table over the whole configuration,
 * keyed by (program, set, class), sized from the named references the source holds. A table per program
 * as long as the set table was contexts x sets of memory.
 */
typedef struct {
    uint64_t *t;
    uint32_t  mask;
} seenset_t;

/* 1 if the key was already there, else 0 and it is now */
static int seen_add(seenset_t *ss, uint64_t key)
{
    uint64_t k = key + 1u;                             /* 0 marks an empty slot */
    uint32_t i = (uint32_t)((k * 0x9E3779B97F4A7C15ull) >> 32) & ss->mask;

    while (ss->t[i] != 0u) {
        if (ss->t[i] == k) {
            return 1;
        }
        i = (i + 1u) & ss->mask;
    }
    ss->t[i] = k;
    return 0;
}

static void rule_cost(const cc_t *c, const dir_t *d, int32_t id, uint32_t *instrs, uint32_t *bytes, uint32_t *sets,
                      seenset_t *seen, uint32_t prog)
{
    const node_t *n = &d->nodes[id];

    if (n->type == N_NOT) {
        *instrs += 1u;
        rule_cost(c, d, n->first, instrs, bytes, sets, seen, prog);
        return;
    }
    if (n->type == N_AND || n->type == N_OR) {
        int32_t ch;

        rule_cost(c, d, n->first, instrs, bytes, sets, seen, prog);
        for (ch = d->nodes[n->first].next; ch >= 0; ch = d->nodes[ch].next) {
            *instrs += 2u;
            rule_cost(c, d, ch, instrs, bytes, sets, seen, prog);
        }
        return;
    }
    *instrs += 1u + ((n->form == F_ISUNK && n->negated) || (n->form == F_CMP && n->op == OP_NE) ? 1u : 0u);
    if (n->form == F_IN && (attrs[n->attr].cls == AC_COUNTRY || attrs[n->attr].cls == AC_ASN)) {
        const tok_t **mem = c->mem;
        uint32_t nm = members_of(c, d, n, mem, WE_LIM_ARG), k, numeric = 0u, u = 0u;
        uint32_t *keys = c->keys;

        if (n->named && seen_add(seen, ((uint64_t)prog << 32) | (uint32_t)(n->set * 4 + (int32_t)attrs[n->attr].cls))) {
            return;
        }
        if (attrs[n->attr].cls == AC_COUNTRY) {
            *bytes += 128u;
            *sets += 1u;
            return;
        }
        for (k = 0u; k < nm; k++) {
            if (mem[k]->sub != LC_UNDET) {
                keys[numeric++] = mem[k]->val;
            }
        }
        if (numeric == 0u) {
            return;
        }
        qsort(keys, numeric, sizeof keys[0], cmp_u32);
        for (k = 0u; k < numeric; k++) {
            if (u == 0u || keys[u - 1u] != keys[k]) {
                keys[u++] = keys[k];
            }
        }
        *bytes += splus_nodes(u) * 64u;
        *sets += 1u;
    }
}

/* ======================================================================================================
 * Layer 7: program limits; layer 8: polarity
 * ==================================================================================================== */

/*
 * Step 7: the directives in source order against their program's counters, each checked in this
 * order: over 256 rules, the operation that crosses 4,096, an allow in a floor, the instruction limit,
 * the hot bytes; and a threshold beside policy lines in its context.
 */
static int limits_layer(cc_t *c)
{
    uint32_t i;
    /* per context and kind (policy, floor): rules, operations, the hot-byte accumulator */
    struct acc { uint32_t rules, ops; hotacc_t h; } *acc;
    seenset_t seen;
    size_t named = 0u;

    acc = (struct acc *)ar_get(&c->ar, sizeof(struct acc) * c->nctx * 2u);
    if (acc == NULL) {
        return -2;
    }
    for (i = 0u; i < c->ndirs; i++) {
        uint32_t k;

        for (k = 0u; k < c->dirs[i].nnodes; k++) {
            named += c->dirs[i].nodes[k].named != 0u;
        }
    }
    seen.mask = table_size(named) - 1u;
    seen.t = (uint64_t *)ar_get(&c->ar, sizeof(uint64_t) * ((size_t)seen.mask + 1u));
    if (seen.t == NULL) {
        return -2;
    }
    for (i = 0u; i < c->ndirs; i++) {
        dir_t *d = &c->dirs[i];
        uint32_t kind = d->d->kind;

        if (kind == WE_DIR_THRESHOLD && c->ctxs[d->ctx].has_policy) {
            char fix[128], phr[64];
            uint32_t s = 0u, e;

            while (s < d->len && is_ws(d->arg[s])) {
                s++;
            }
            e = s;
            while (e < d->len && !is_ws(d->arg[e])) {
                e++;
            }
            if (d->value == 0u) {
                snprintf(phr, sizeof phr, "no rule (threshold off denies nothing)");
            } else {
                snprintf(phr, sizeof phr, "deny if listed >= %s", level_name[d->value]);
            }
            snprintf(fix, sizeof fix, "write the equivalent rule: %s", phr);
            fail_at(c, "program", phr, d, s, e - s, 1, fix, "whisper_edge_threshold in a context with policy lines");
            return -1;
        }
        if (kind == WE_DIR_POLICY || kind == WE_DIR_FLOOR) {
            struct acc *a = &acc[d->ctx * 2u + (kind == WE_DIR_FLOOR)];
            const tok_t *t0 = &d->tok[0];
            uint32_t instrs = 1u, bytes = 0u, sets = 0u;

            a->rules++;
            if (a->rules > WE_LIM_RULES) {
                fail_at(c, "program", "over 256 rules in a context", d, t0->off, t0->len, 1,
                        "a context holds at most 256 rules: use sets", "over 256 rules in a context");
                return -1;
            }
            if (a->ops + d->ops > WE_LIM_OPS_CTX) {
                const tok_t *ot = &d->tok[d->op_tok[WE_LIM_OPS_CTX - a->ops]];

                fail_at(c, "program", "over 4,096 operations in a context", d, ot->off, ot->len, 1,
                        "a context holds at most 4,096 operations: use sets, a set test is one",
                        "over 4,096 operations in a context");
                return -1;
            }
            a->ops += d->ops;
            if (kind == WE_DIR_FLOOR && d->action == WE_ACT_ALLOW) {
                fail_at(c, "program", "allow in a floor program", d, t0->off, t0->len, 1,
                        "the floor only tightens: write deny or log", "allow in a floor program");
                return -1;
            }
            if (node_depth(d, d->root) > WE_LIM_STACK) {
                /* unreachable under the nesting limit (the bound is 18 at 16); kept so the bound is checked */
                fail_at(c, "program", "nesting over 16", d, t0->off, t0->len, 1, "simplify the condition",
                        "the rule needs an evaluation stack deeper than 18");
                return -1;
            }
            rule_cost(c, d, d->root, &instrs, &bytes, &sets, &seen, d->ctx * 2u + (kind == WE_DIR_FLOOR));
            if (a->h.instrs + instrs > WE_LIM_INSTRS) {
                fail_at(c, "program", "over 8,448 instructions", d, t0->off, t0->len, 1,
                        "split the program", "over 8,448 instructions");
                return -1;
            }
            a->h.rules++;
            a->h.instrs += instrs;
            a->h.setbytes += bytes;
            a->h.nsets += sets;
            if (hot_of(&a->h, kind == WE_DIR_FLOOR) > WE_LIM_HOT_BYTES) {
                fail_at(c, "program", "over 256 KiB of program bytes", d, t0->off, t0->len, 1,
                        "use fewer or smaller sets", "over 256 KiB of program bytes: hot %u bytes (limit %u), "
                        "of which %u are set payloads over %u sets, each padded to 64 bytes",
                        hot_of(&a->h, kind == WE_DIR_FLOOR), WE_LIM_HOT_BYTES, a->h.setbytes, a->h.nsets);
                return -1;
            }
        }
    }
    return 0;
}

/* every `is unknown` with its polarity: positive at the root, flipped under not and `is not` */
static int polarity_walk(cc_t *c, dir_t *d, int32_t id, uint32_t neg, uint32_t later_deny)
{
    node_t *n = &d->nodes[id];

    if (n->type == N_NOT) {
        return polarity_walk(c, d, n->first, neg ^ 1u, later_deny);
    }
    if (n->type == N_AND || n->type == N_OR) {
        int32_t ch;

        for (ch = n->first; ch >= 0; ch = d->nodes[ch].next) {
            if (polarity_walk(c, d, ch, neg, later_deny) != 0) {
                return -1;
            }
        }
        return 0;
    }
    if (n->form == F_ISUNK) {
#ifdef WE_TEST_ISNOTUNK_POSITIVE
        uint32_t p = neg;                  /* the mutant: `is not unknown` read as positive */
#else
        uint32_t p = neg ^ n->negated;     /* 0: positive */
#endif
        uint32_t deny_rule = 0u;

        if (d->action == WE_ACT_DENY && p == 0u) {
            deny_rule = d->ordinal;
        }
#ifndef WE_TEST_POLARITY_NO_ALLOW
        if (d->action == WE_ACT_ALLOW && p == 1u && later_deny != 0u) {
            deny_rule = later_deny;
        }
#endif
        if (deny_rule != 0u) {
            const tok_t *it = &d->tok[n->optok];

            fail_at(c, "polarity", "that is a fail-closed rule", d, it->off, it->len, 1,
                    "Use it in a log rule, or in an allow rule that no later deny depends on.",
                    "rule %u: \"is unknown\" here lets rule %u deny exactly when the %s plane is missing or stale; "
                    "that is a fail-closed rule", d->ordinal, deny_rule, plane_name[attrs[n->attr].plane]);
            return -1;
        }
    }
    return 0;
}

/*
 * Step 8, last: the rules in file order across the whole configuration, every `is unknown` in a rule
 * in source order, so the first fault in the file is the one reported whichever program holds it.
 */
static int polarity_layer(cc_t *c)
{
    uint32_t j;
    /*
     * The first deny after each rule in its own program, from one pass from the back: per context and
     * kind, the ordinal of the nearest deny seen so far. Then the walks run forward, in file order.
     */
    uint32_t *next = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * ((size_t)c->nctx * 2u + 2u));
    uint32_t *later = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * ((size_t)c->ndirs + 1u));

    if (next == NULL || later == NULL) {
        return -2;
    }
    for (j = c->ndirs; j > 0u; j--) {
        const dir_t *d = &c->dirs[j - 1u];
        uint32_t *nd;

        if (d->d->kind != WE_DIR_POLICY && d->d->kind != WE_DIR_FLOOR) {
            continue;
        }
        nd = &next[d->ctx * 2u + (d->d->kind == WE_DIR_FLOOR)];
        later[j - 1u] = *nd;
        if (d->action == WE_ACT_DENY) {
            *nd = d->ordinal;
        }
    }
    for (j = 0u; j < c->ndirs; j++) {
        dir_t *d = &c->dirs[j];

        if (d->d->kind != WE_DIR_POLICY && d->d->kind != WE_DIR_FLOOR) {
            continue;
        }
        if (polarity_walk(c, d, d->root, 0u, later[j]) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ======================================================================================================
 * The value-set classifier (POLICY.md §2.5), over a block's instructions
 * ==================================================================================================== */

#define VT 1u
#define VF 2u
#define VU 4u

/* K3 on single values encoded as one of VT VF VU */
static uint8_t k3_and(uint8_t a, uint8_t b)
{
    if (a == VF || b == VF) {
        return VF;
    }
    return (a == VT && b == VT) ? VT : VU;
}

static uint8_t k3_or(uint8_t a, uint8_t b)
{
    if (a == VT || b == VT) {
        return VT;
    }
    return (a == VF && b == VF) ? VF : VU;
}

static uint8_t k3_not(uint8_t a)
{
    return a == VT ? VF : a == VF ? VT : VU;
}

static uint8_t set_bin(uint8_t x, uint8_t y, int is_and)
{
    uint8_t r = 0u, a, b;

    for (a = 1u; a <= 4u; a <<= 1) {
        for (b = 1u; b <= 4u; b <<= 1) {
            if ((x & a) && (y & b)) {
                r = (uint8_t)(r | (is_and ? k3_and(a, b) : k3_or(a, b)));
            }
        }
    }
    return r;
}

static uint8_t set_not(uint8_t x)
{
    return (uint8_t)(((x & VT) ? VF : 0u) | ((x & VF) ? VT : 0u) | (x & VU));
}

/* the value set of one rule's condition; isunk_out_f: seed `is unknown` on an out plane as {F} */
static uint8_t rule_values(const we_program_t *p, const we_rule_t *R, uint8_t out_mask, we_tenant_state_t ts,
                           int isunk_out_f)
{
    const uint8_t *base = (const uint8_t *)p;
    const we_instr_t *ins = (const we_instr_t *)(const void *)(base + p->instrs_off);
    uint8_t stack[WE_LIM_STACK + 8u];
    uint32_t sp = 0u, k;

    for (k = 0u; k < R->instr_count; k++) {
        const we_instr_t *I = &ins[R->instr_start + k];
        uint32_t op = I->op, pl = I->plane & 7u;

        if ((op & WE_OP_ATOM) != 0u) {
            uint8_t v;

            if (pl == 7u) {
                int bounded = (op & WE_OP_BOOL) != 0u && (I->imm & WE_BOOL_POLARITY) != 0u;

                if ((op & WE_OP_ISUNK) != 0u) {
                    v = (ts == WE_TENANT_GRACE || ts == WE_TENANT_LAPSED || ts == WE_TENANT_NULL) ? VT : VF;
                    if (v == VT && isunk_out_f) {
                        v = VF;
                    }
                } else if (ts == WE_TENANT_FRESH) {
                    v = VT | VF;
                } else if (ts == WE_TENANT_GRACE) {
                    v = bounded ? (uint8_t)(VT | VF) : (uint8_t)VU;
                } else if (ts == WE_TENANT_LAPSED) {
                    v = bounded ? (uint8_t)VF : (uint8_t)VU;
                } else if (ts == WE_TENANT_NULL) {
                    v = VU;
                } else {
                    v = VF;
                }
            } else if ((op & WE_OP_ISUNK) != 0u) {
#ifdef WE_TEST_CLASSIFY_ISUNK_U
                v = ((out_mask >> pl) & 1u) ? (uint8_t)VU : (uint8_t)VF;
#else
                v = ((out_mask >> pl) & 1u) ? (uint8_t)(isunk_out_f ? VF : VT) : (uint8_t)VF;
#endif
            } else {
                v = ((out_mask >> pl) & 1u) ? (uint8_t)VU : (uint8_t)(VT | VF);
            }
#ifdef WE_TEST_CLASSIFY_SINGLE_EVAL
            if (v == (VT | VF)) {
                v = VT;
            }
#endif
            if (sp < sizeof stack) {
                stack[sp++] = v;
            }
        } else if ((op & WE_OP_NOT) != 0u && sp >= 1u) {
            stack[sp - 1u] = set_not(stack[sp - 1u]);
        } else if ((op & (WE_OP_AND | WE_OP_OR)) != 0u && sp >= 2u) {
            stack[sp - 2u] = set_bin(stack[sp - 2u], stack[sp - 1u], (op & WE_OP_AND) != 0u);
            sp--;
        }
    }
    return sp >= 1u ? stack[sp - 1u] : (uint8_t)VF;
}

uint32_t we_program_dependents(const we_program_t *p, uint8_t out_mask, we_tenant_state_t tenant,
                               we_rule_class_t *out, uint32_t n)
{
    const uint8_t *base = (const uint8_t *)p;
    const we_rule_t *rules;
    uint32_t r, deps = 0u;
    uint8_t S;
    int captured = 0;

    if (p == NULL) {
        return 0u;
    }
    rules = (const we_rule_t *)(const void *)(base + p->rules_off);
    S = (uint8_t)((out_mask & 0x7fu) | (tenant != WE_TENANT_FRESH ? 0x80u : 0u));
    for (r = 0u; r < p->rule_count; r++) {
        const we_rule_t *R = &rules[r];
        we_rule_class_t rc;
        uint8_t v;

        memset(&rc, 0, sizeof rc);
        rc.rule = (uint16_t)(r + 1u);
        rc.action = R->action;
        if ((R->flags & WE_RF_INERT) != 0u) {
            rc.cls = WE_CLASS_INERT_AT_CONFIG;
        } else {
            v = rule_values(p, R, out_mask, tenant, 0);
            rc.values = v;
            if (R->action == WE_ACT_ALLOW) {
#ifdef WE_TEST_NO_CAPTURES
                rc.cls = (v & VT) ? WE_CLASS_NARROWED : WE_CLASS_INERT;
#else
                rc.cls = (v & VU) ? WE_CLASS_CAPTURES : (v & VT) ? WE_CLASS_NARROWED : WE_CLASS_INERT;
#endif
            } else {
                rc.cls = (v & VT) ? WE_CLASS_NARROWED : WE_CLASS_INERT;
            }
            rc.dependent = (uint8_t)(((R->dep_mask & S) != 0u) || (captured && R->action != WE_ACT_ALLOW));
            if (captured && R->action != WE_ACT_ALLOW) {
                rc.cls = WE_CLASS_INERT;       /* below a capturing allow: disarmed, whatever it reads */
            }
            if (rc.cls == WE_CLASS_CAPTURES) {
                captured = 1;
                rc.dependent = 1u;
            }
            if (!rc.dependent) {
                rc.cls = WE_CLASS_UNAFFECTED;
            }
        }
        deps += rc.dependent;
        if (out != NULL && r < n) {
            out[r] = rc;
        }
    }
    return deps;
}

static void fmt_ranges(const uint32_t *ns, uint32_t n, char *out, size_t cap);

/*
 * The transition line: `<what>: rule 3 allow captures; rules 4-6,9 disarmed; rule 2 narrowed`, or
 * `<what>: none`. Disarmed: a dependent rule that can no longer reach TRUE, and every deny and log below
 * a capturing allow. Narrowed: a dependent rule that still can.
 */
int we_program_dependents_line(const we_program_t *p, uint8_t out_mask, we_tenant_state_t tenant,
                               const char *what, char *buf, size_t n)
{
    we_rule_class_t rc[WE_LIM_RULES];
    uint32_t lists[3][WE_LIM_RULES], cnt[3] = { 0u, 0u, 0u }, nr, r, k, o = 0u;
    static const char *const tail[3] = { "allow captures", "disarmed", "narrowed" };
    char rg[WE_LIM_RULES * 8u];
    int parts = 0;

    if (p == NULL || buf == NULL || n == 0u) {
        return -1;
    }
    nr = p->rule_count < WE_LIM_RULES ? p->rule_count : WE_LIM_RULES;
    we_program_dependents(p, out_mask, tenant, rc, WE_LIM_RULES);
    for (r = 0u; r < nr; r++) {
        if (!rc[r].dependent) {
            continue;
        }
        k = rc[r].cls == WE_CLASS_CAPTURES ? 0u : rc[r].cls == WE_CLASS_NARROWED ? 2u : 1u;
        lists[k][cnt[k]++] = r + 1u;
    }
    o += (uint32_t)snprintf(buf, n, "%s:", what != NULL ? what : "");
    for (k = 0u; k < 3u && o < n; k++) {
        if (cnt[k] == 0u) {
            continue;
        }
        fmt_ranges(lists[k], cnt[k], rg, sizeof rg);
        o += (uint32_t)snprintf(buf + o, n - o, "%s rule%s %s %s", parts ? ";" : "", cnt[k] > 1u ? "s" : "", rg,
                                tail[k]);
        parts = 1;
    }
    if (!parts && o < n) {
        o += (uint32_t)snprintf(buf + o, n - o, " none");
    }
    return o < n ? (int)o : -1;
}
/* ======================================================================================================
 * Reports, printed once at config test (POLICY.md §1.5), never refusals
 * ==================================================================================================== */

static void report(cc_t *c, const char *context, uint8_t kind, uint32_t rule, const char *name, const char *code,
                   const char *detail, const char *fmt, ...)
{
    char msg[1024];
    we_policy_report_line_t r;
    va_list ap;

    if (c->rep == NULL || c->rep->line == NULL) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    r.context = context;
    r.kind = kind;
    r.rule = rule;
    r.name = name;
    r.code = code;
    r.detail = detail != NULL ? detail : "";
    r.msg = msg;
    c->rep->line(c->rep->ud, &r);
}

/* "3-5,7": the rule numbers as ranges; "-" when there are none */
static void fmt_ranges(const uint32_t *ns, uint32_t n, char *out, size_t cap)
{
    size_t o = 0u;
    uint32_t i = 0u;

    out[0] = '\0';
    while (i < n && o + 24u < cap) {
        uint32_t j = i;

        while (j + 1u < n && ns[j + 1u] == ns[j] + 1u) {
            j++;
        }
        if (i == j) {
            o += (size_t)snprintf(out + o, cap - o, "%s%u", o == 0u ? "" : ",", ns[i]);
        } else {
            o += (size_t)snprintf(out + o, cap - o, "%s%u-%u", o == 0u ? "" : ",", ns[i], ns[j]);
        }
        i = j + 1u;
    }
    if (o == 0u) {
        snprintf(out, cap, "-");
    }
}

/* the value of one rule on the all-fresh, all-absent record: every plane fresh, no range anywhere */
static uint8_t rule_on_absent(const we_program_t *p, const we_rule_t *R)
{
    const uint8_t *base = (const uint8_t *)p;
    const we_instr_t *ins = (const we_instr_t *)(const void *)(base + p->instrs_off);
    const we_binding_t *B = (const we_binding_t *)(const void *)(base + p->bindings_off);
    uint8_t stack[WE_LIM_STACK + 8u];
    uint32_t sp = 0u, k;

    for (k = 0u; k < R->instr_count; k++) {
        const we_instr_t *I = &ins[R->instr_start + k];
        uint32_t op = I->op;
        const uint8_t *blk = B[I->plane & 7u].tmpl + (I->off & 15u);
        uint32_t v = 0u;

        if ((op & WE_OP_ATOM) == 0u) {
            if ((op & WE_OP_NOT) != 0u && sp >= 1u) {
                stack[sp - 1u] = k3_not(stack[sp - 1u]);
            } else if ((op & (WE_OP_AND | WE_OP_OR)) != 0u && sp >= 2u) {
                stack[sp - 2u] = (op & WE_OP_AND) ? k3_and(stack[sp - 2u], stack[sp - 1u])
                                                  : k3_or(stack[sp - 2u], stack[sp - 1u]);
                sp--;
            }
            continue;
        }
        if (op & WE_OP_BOOL) {
            v = (blk[0] & I->imm & 0xffu) != 0u;
        } else if (op & WE_OP_SEV) {
            v = I->imm & 1u;
        } else if (op & WE_OP_EQ8) {
            v = blk[0] == (uint8_t)I->imm;
        } else if (op & WE_OP_EQ16) {
            v = I->imm == 0u;
        } else if (op & WE_OP_EQ32) {
            v = I->imm == 0xffffffffu;
        } else if (op & WE_OP_INSET_ENUM) {
            v = (I->imm >> blk[0]) & 1u;
        } else if (op & WE_OP_INSET_COUNTRY) {
            v = base[I->imm] & 1u;
        } else if (op & WE_OP_INSET_ASN) {
            v = WE_ASN_IMM_HASU(I->imm);
        }
        if (sp < sizeof stack) {
            stack[sp++] = v ? (uint8_t)VT : (uint8_t)VF;
        }
    }
    return sp >= 1u ? stack[sp - 1u] : (uint8_t)VF;
}

static int u64_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return x < y ? -1 : x > y ? 1 : 0;
}

/* a literal's value as the evaluator compares it, for the set arithmetic of the reports */
static uint32_t lit_value(const tok_t *t)
{
    return t->sub == LC_UNDET ? 0xffffffffu : t->val;
}

/* the distinct values of an `in` atom's set, whether it holds undetermined, and (inline) its repeats */
typedef struct {
    uint32_t n;
    uint32_t v[WE_LIM_ARG];
    int      hu;
    char     dups[WE_LIM_ARG * 12u];   /* every repeat of a full argument, rendered */
    uint64_t key[WE_LIM_ARG];          /* scratch: value << 12 | position, sorted */
    uint8_t  rep[WE_LIM_ARG];          /* scratch: the member at this position repeats an earlier one */
} vals_t;

static void literal_text(const tok_t *t, char *out, size_t n);

/*
 * The members' distinct values and their repeats in source order, in O(n log n): sorted on (value,
 * position), a member repeats when the one before it in that order has its value. A configuration
 * of 256 rules over 2,048-member sets is a few million steps here, never the n^2 of a pairwise scan.
 */
static void vals_of(const tok_t *const *mem, uint32_t nm, vals_t *vs)
{
    uint32_t k, nk = 0u;
    size_t o = 0u;

    vs->n = 0u;
    vs->hu = 0;
    vs->dups[0] = '\0';
    for (k = 0u; k < nm; k++) {
        vs->rep[k] = 0u;
        if (mem[k]->sub == LC_UNDET) {
            vs->rep[k] = (uint8_t)vs->hu;
            vs->hu = 1;
        } else {
            vs->key[nk++] = ((uint64_t)lit_value(mem[k]) << 12) | k;
        }
    }
    qsort(vs->key, nk, sizeof vs->key[0], u64_cmp);
    for (k = 0u; k < nk; k++) {
        if (k > 0u && (vs->key[k] >> 12) == (vs->key[k - 1u] >> 12)) {
            vs->rep[vs->key[k] & 0xfffu] = 1u;
        } else {
            vs->v[vs->n++] = (uint32_t)(vs->key[k] >> 12);
        }
    }
    for (k = 0u; k < nm; k++) {
        char txt[32];

        if (vs->rep[k] && o + 40u < sizeof vs->dups) {
            literal_text(mem[k], txt, sizeof txt);
            o += (size_t)snprintf(vs->dups + o, sizeof vs->dups - o, "%s%s", o == 0u ? "" : ",", txt);
        }
    }
}

static void set_vals(const cc_t *c, const dir_t *d, const node_t *a, vals_t *vs)
{
    const tok_t **mem = c->mem2;
    uint32_t nm = members_of(c, d, a, mem, WE_LIM_ARG);

    vals_of(mem, nm, vs);
}

/* the atoms of a rule in source order, with the parity of the nots above each */
static uint32_t walk_atoms(const dir_t *d, int32_t id, uint32_t neg, int32_t *out, uint8_t *pol, uint32_t n)
{
    const node_t *x = &d->nodes[id];

    if (x->type == N_ATOM) {
        out[n] = id;
        pol[n] = (uint8_t)neg;
        return n + 1u;
    }
    if (x->type == N_NOT) {
        return walk_atoms(d, x->first, neg ^ 1u, out, pol, n);
    }
    {
        int32_t ch;

        for (ch = x->first; ch >= 0; ch = d->nodes[ch].next) {
            n = walk_atoms(d, ch, neg, out, pol, n);
        }
        return n;
    }
}

/* a single atom, or an and-chain whose operands that are atoms (others NULL) */
static uint32_t flat_and(const dir_t *d, const node_t **out, int *all_atoms)
{
    const node_t *r = &d->nodes[d->root];
    uint32_t k = 0u;
    int32_t ch;

    *all_atoms = 1;
    if (r->type == N_ATOM) {
        out[0] = r;
        return 1u;
    }
    if (r->type != N_AND) {
        *all_atoms = 0;
        return 0u;
    }
    for (ch = r->first; ch >= 0; ch = d->nodes[ch].next) {
        if (d->nodes[ch].type == N_ATOM) {
            out[k++] = &d->nodes[ch];
        } else {
            out[k++] = NULL;
            *all_atoms = 0;
        }
    }
    return k;
}

static int atom_positive(const node_t *n)
{
    return n->form == F_BARE || n->form == F_IN || (n->form == F_CMP && n->op != OP_NE);
}

static int same_literal(const tok_t *a, const tok_t *b)
{
    return a->sub == b->sub && a->dom == b->dom && lit_value(a) == lit_value(b);
}

/* subsumption, per attribute (POLICY.md §2.5): positive atoms only */
/* a set's distinct values, sorted, computed once per named set and once per inline atom */
typedef struct {
    uint32_t        n;
    int             hu;
    const uint32_t *v;
} cvals_t;

static const cvals_t *atom_cvals(cc_t *c, const dir_t *d, const node_t *a)
{
    cvals_t **slot;

    if (c->vc_sets == NULL) {
        c->vc_sets = (void **)ar_get(&c->ar, sizeof(void *) * (c->nsets + 1u));
        c->vc_nodes = (void ***)ar_get(&c->ar, sizeof(void **) * (c->ndirs + 1u));
        if (c->vc_sets == NULL || c->vc_nodes == NULL) {
            c->vc_sets = NULL;
            return NULL;
        }
        memset(c->vc_sets, 0, sizeof(void *) * (c->nsets + 1u));
        memset(c->vc_nodes, 0, sizeof(void **) * (c->ndirs + 1u));
    }
    if (a->named) {
        slot = (cvals_t **)&c->vc_sets[a->set];
    } else {
        if (c->vc_nodes[d->index] == NULL) {
            c->vc_nodes[d->index] = (void **)ar_get(&c->ar, sizeof(void *) * (d->nnodes + 1u));
            if (c->vc_nodes[d->index] == NULL) {
                return NULL;
            }
            memset(c->vc_nodes[d->index], 0, sizeof(void *) * (d->nnodes + 1u));
        }
        slot = (cvals_t **)&c->vc_nodes[d->index][a - d->nodes];
    }
    if (*slot == NULL) {
        vals_t *vs = (vals_t *)c->vals + 1;
        cvals_t *cv = (cvals_t *)ar_get(&c->ar, sizeof *cv);
        uint32_t *v;

        set_vals(c, d, a, vs);
        v = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * (vs->n + 1u));
        if (cv == NULL || v == NULL) {
            return NULL;
        }
        memcpy(v, vs->v, sizeof(uint32_t) * vs->n);
        cv->n = vs->n;
        cv->hu = vs->hu;
        cv->v = v;
        *slot = cv;
    }
    return *slot;
}

static int cvals_has(const cvals_t *s, uint32_t x)
{
    uint32_t lo = 0u, hi = s->n;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;

        if (s->v[mid] < x) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < s->n && s->v[lo] == x;
}

/* S1 contains S2: a merge over the two sorted value arrays */
static int cvals_superset(const cvals_t *s1, const cvals_t *s2)
{
    uint32_t i = 0u, j;

    for (j = 0u; j < s2->n; j++) {
        while (i < s1->n && s1->v[i] < s2->v[j]) {
            i++;
        }
        if (i == s1->n || s1->v[i] != s2->v[j]) {
            return 0;
        }
    }
    return 1;
}

static int atom_subsumes(cc_t *c, const dir_t *d1, const node_t *a, uint32_t bit1, const dir_t *d2,
                         const node_t *b, uint32_t bit2)
{
    if (a->attr != b->attr) {
        return 0;
    }
    if (a->form == F_BARE && b->form == F_BARE) {
        return a->attr != A_TENANT_ALLOW || bit1 == bit2;
    }
    if (a->form == F_CMP && a->op == OP_GE && a->attr == A_LISTED) {
        return b->form == F_CMP && b->op == OP_GE && d1->tok[a->littok].val <= d2->tok[b->littok].val;
    }
    if (a->form == F_CMP && a->op == OP_EQ) {
        return b->form == F_CMP && b->op == OP_EQ && same_literal(&d1->tok[a->littok], &d2->tok[b->littok]);
    }
    if (a->form == F_IN) {
        const cvals_t *va = atom_cvals(c, d1, a), *vb;

        if (va == NULL) {
            return 0;
        }
        if (b->form == F_IN) {
            if (a->named && b->named && a->set == b->set) {
                return 1;                      /* one set: equal values, equal undetermined */
            }
            vb = atom_cvals(c, d2, b);
            return vb != NULL && cvals_superset(va, vb) && (va->hu || !vb->hu);
        }
        if (b->form == F_CMP && b->op == OP_EQ) {
            const tok_t *lt = &d2->tok[b->littok];

            return lt->sub == LC_UNDET ? va->hu : cvals_has(va, lit_value(lt));
        }
    }
    return 0;
}

/* T is reachable, and not once every `is unknown` on plane pl reads F instead of T */
static int isunk_only(const we_program_t *p, const we_rule_t *R, uint8_t out, we_tenant_state_t ts, uint32_t pl)
{
    const we_instr_t *ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
    uint32_t k;
    int has = 0;

    if ((rule_values(p, R, out, ts, 0) & VT) == 0u) {
        return 0;
    }
    for (k = 0u; k < R->instr_count; k++) {
        has |= (ins[R->instr_start + k].op & WE_OP_ISUNK) != 0u && ins[R->instr_start + k].plane == pl;
    }
    return has && (rule_values(p, R, out, ts, 1) & VT) == 0u;
}

static void literal_text(const tok_t *t, char *out, size_t n)
{
    char a2[3];

    switch (t->sub) {
    case LC_LEVEL:   snprintf(out, n, "%s", level_name[t->val]); break;
    case LC_ENUM:    snprintf(out, n, "%s", enum_name(t->dom, t->val)); break;
    case LC_COUNTRY: snprintf(out, n, "%s", country_alpha2(t->val, a2)); break;
    case LC_ASN:     snprintf(out, n, "%" PRIu32, t->val); break;
    default:         snprintf(out, n, "undetermined"); break;
    }
}

/*
 * The threshold sugar's one report (D-af): its single rule, `deny if listed >= <level>`, reads the
 * reputation plane, so outside the legacy synonym a configuration without reputation.bin makes it inert
 * at config and says so exactly as the written rule would. A lone deny of one positive atom draws no
 * other report: nothing above it to shadow it, no allow to capture, and FALSE on the absent record.
 */
static void sugar_reports(cc_t *c, const char *context, const we_program_t *p)
{
    const we_rule_t *rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    char det[256];
    size_t o = 0u;
    uint32_t r, q;

    for (r = 0u; r < p->rule_count; r++) {
        if ((rules[r].flags & WE_RF_INERT) == 0u) {
            continue;
        }
        det[0] = '\0';
        o = 0u;
        for (q = 0u; q < NPLANES; q++) {
            if (((rules[r].dep_mask >> q) & 1u) != 0u && ((c->env->present >> q) & 1u) == 0u && !c->env->legacy) {
                o += (size_t)snprintf(det + o, sizeof det - o, "%s%s", o == 0u ? "" : ",", plane_name[q]);
            }
        }
        report(c, context, WE_DIR_POLICY, r + 1u, NULL, "inert-at-config", det,
               "rule %u references plane \"%s\", which is not installed here; the rule is inert until a reload",
               r + 1u, det);
    }
}

/* every report of one program, rule by rule, in the order the differential reads them */
static void program_reports(cc_t *c, const char *context, uint8_t kind, const uint32_t *rix, uint32_t nr,
                            const we_program_t *p)
{
    const we_rule_t *rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    uint8_t absent = 0u;
    uint32_t r, q;

    for (q = 0u; q < NPLANES; q++) {
        absent = (uint8_t)(absent | (((c->env->present >> q) & 1u) || c->env->legacy
                                     ? 0u : (1u << q)));
    }
    for (r = 0u; r < nr; r++) {
        const dir_t *d = &c->dirs[rix[r]];
        const we_rule_t *R = &rules[r];
        uint32_t n = r + 1u;
        int32_t atoms[WE_LIM_OPS_RULE + 1];
        uint8_t pol[WE_LIM_OPS_RULE + 1];
        uint32_t na = walk_atoms(d, d->root, 0u, atoms, pol, 0u), k;
        char det[1024];

        /* a referenced plane not installed */
        if ((R->flags & WE_RF_INERT) != 0u) {
            size_t o = 0u;

            det[0] = '\0';
            for (q = 0u; q < NPLANES; q++) {
                if (((R->dep_mask & absent) >> q) & 1u) {
                    o += (size_t)snprintf(det + o, sizeof det - o, "%s%s", o == 0u ? "" : ",", plane_name[q]);
                }
            }
            report(c, context, kind, n, NULL, "inert-at-config", det,
                   "rule %u references plane \"%s\", which is not installed here; the rule is inert until a reload",
                   n, det);
            if (R->action == WE_ACT_ALLOW) {
                uint32_t later[WE_LIM_RULES], nl = 0u;

                for (q = r + 1u; q < nr; q++) {
                    if (rules[q].action == WE_ACT_DENY) {
                        later[nl++] = q + 1u;
                    }
                }
                fmt_ranges(later, nl, det, sizeof det);
                report(c, context, kind, n, NULL, "inert-allow-exposes", det,
                       "rule %u is an inert allow: it would have exempted addresses from the denies in rules %s", n, det);
            }
        }
        /* shadowing: the earliest non-log rule whose atoms each subsume one of this rule's positive atoms;
         * log rules are never shadowed (POLICY.md §11, D2), and an inert rule neither shadows nor is shadowed */
        if (R->action != WE_ACT_LOG && (R->flags & WE_RF_INERT) == 0u) {
            const node_t *a2[WE_LIM_OPS_RULE + 1], *a1[WE_LIM_OPS_RULE + 1];
            int all2, all1;
            uint32_t n2 = flat_and(d, a2, &all2), i, j;

            (void)all2;
            for (q = 0u; q < r && n2 > 0u; q++) {
                const dir_t *d1 = &c->dirs[rix[q]];
                uint32_t n1;
                int ok = 1;

                if (rules[q].action == WE_ACT_LOG || (rules[q].flags & WE_RF_INERT) != 0u) {
                    continue;
                }
                n1 = flat_and(d1, a1, &all1);
                if (n1 == 0u || !all1) {
                    continue;
                }
                for (i = 0u; i < n1 && ok; i++) {
                    ok = atom_positive(a1[i]);
                }
                for (i = 0u; i < n1 && ok; i++) {
                    int found = 0;

                    for (j = 0u; j < n2 && !found; j++) {
                        found = a2[j] != NULL && atom_positive(a2[j])
                             && atom_subsumes(c, d1, a1[i], a1[i]->attr == A_TENANT_ALLOW && rules[q].action == WE_ACT_ALLOW,
                                              d, a2[j], a2[j]->attr == A_TENANT_ALLOW && R->action == WE_ACT_ALLOW);
                    }
                    ok = found;
                }
                if (ok) {
                    snprintf(det, sizeof det, "%u", q + 1u);
                    report(c, context, kind, n, NULL, "shadowed-by", det, "rule %u is shadowed by rule %u and never decides",
                           n, q + 1u);
                    break;
                }
            }
        }
        /* every `in`: over a level or an enum the tautology and the coverage of the possible values; repeats */
        for (k = 0u; k < na; k++) {
            const node_t *a = &d->nodes[atoms[k]];
            vals_t *vs = (vals_t *)c->vals;
            uint32_t cnt, ndom;

            if (a->form != F_IN) {
                continue;
            }
            set_vals(c, d, a, vs);
            if (attrs[a->attr].cls == AC_ENUM || attrs[a->attr].cls == AC_LEVEL) {
                ndom = attrs[a->attr].ndom;
                cnt = vs->n + (vs->hu && attrs[a->attr].cls != AC_LEVEL ? 1u : 0u);
                if (cnt == ndom) {
                    report(c, context, kind, n, NULL, "tautology", attrs[a->attr].name,
                           "rule %u is a tautology: %s takes no value outside the set", n, attrs[a->attr].name);
                }
                snprintf(det, sizeof det, "%s %u/%u", attrs[a->attr].name, cnt, ndom);
                report(c, context, kind, n, NULL, "coverage", det, "rule %u matches %u of the %u values %s can take", n,
                       cnt, ndom, attrs[a->attr].name);
            }
            if (!a->named && vs->dups[0] != '\0') {
                report(c, context, kind, n, NULL, "duplicate-member", vs->dups,
                       "rule %u: a duplicate member inside one set, harmless (%s)", n, vs->dups);
            }
        }
        /* a negated test of a sentinel attribute in an allow, unguarded */
        if (R->action == WE_ACT_ALLOW) {
            uint8_t guards[NATTRS], warned[NATTRS];
            uint32_t nw = 0u;
            const node_t *root = &d->nodes[d->root];

            memset(guards, 0, sizeof guards);
            if (root->type == N_AND) {
                int32_t ch;

                for (ch = root->first; ch >= 0; ch = d->nodes[ch].next) {
                    const node_t *x = &d->nodes[ch];

                    if (x->type == N_ATOM && x->form == F_CMP && x->op == OP_NE && d->tok[x->littok].sub == LC_UNDET) {
                        guards[x->attr] = 1u;
                    }
                }
            }
            for (k = 0u; k < na; k++) {
                const node_t *a = &d->nodes[atoms[k]];
                uint32_t eff, i;
                int hu, seen = 0;

                if (!attrs[a->attr].sentinel || (a->form != F_CMP && a->form != F_IN)) {
                    continue;
                }
                if (a->form == F_CMP && a->op != OP_EQ && a->op != OP_NE) {
                    continue;
                }
                eff = pol[k] ^ (a->form == F_CMP && a->op == OP_NE ? 1u : 0u);
                if (eff == 0u) {
                    continue;
                }
                if (a->form == F_CMP) {
                    hu = d->tok[a->littok].sub == LC_UNDET;
                } else {
                    vals_t *vs = (vals_t *)c->vals;

                    set_vals(c, d, a, vs);
                    hu = vs->hu;
                }
                if (hu || guards[a->attr]) {
                    continue;
                }
                for (i = 0u; i < nw; i++) {
                    seen |= warned[i] == a->attr;
                }
                if (!seen) {
                    warned[nw++] = a->attr;
                }
            }
            for (k = 0u; k < nw; k++) {
                const char *an = attrs[warned[k]].name;

                report(c, context, kind, n, NULL, "sentinel-negative", an,
                       "rule %u: the negated test of %s is TRUE where %s is undetermined, which a client reaches by "
                       "announcing a fresh prefix or ASN; add `and %s != undetermined`", n, an, an, an);
            }
        }
        /* a deny or log TRUE on the all-fresh, all-absent record */
        if (R->action != WE_ACT_ALLOW && (R->flags & WE_RF_INERT) == 0u && rule_on_absent(p, R) == VT) {
            report(c, context, kind, n, NULL, "denies-all-absent", "", "rule %u %s every address no plane lists", n,
                   R->action == WE_ACT_DENY ? "denies" : "logs");
        }
        /* an allow that captures while a plane is out, or reaches TRUE only through `is unknown` */
        if (R->action == WE_ACT_ALLOW && (R->flags & WE_RF_INERT) == 0u) {
            int later_deny = 0;
            uint8_t cap = 0u, unb = 0u;

            for (q = r + 1u; q < nr; q++) {
                later_deny |= rules[q].action == WE_ACT_DENY;
            }
            for (q = 0u; q < NPLANES; q++) {
                if (((R->dep_mask >> q) & 1u) == 0u) {
                    continue;
                }
                if (q == 7u) {
                    if ((rule_values(p, R, 0u, WE_TENANT_GRACE, 0) & VU) || (rule_values(p, R, 0u, WE_TENANT_LAPSED, 0) & VU)
                            || (rule_values(p, R, 0u, WE_TENANT_NULL, 0) & VU)) {
                        cap = (uint8_t)(cap | 0x80u);
                    }
                    if ((rule_values(p, R, 0u, WE_TENANT_LAPSED, 0) & VU) || isunk_only(p, R, 0u, WE_TENANT_NULL, 7u)) {
                        unb = (uint8_t)(unb | 0x80u);
                    }
                } else {
                    if (rule_values(p, R, (uint8_t)(1u << q), WE_TENANT_FRESH, 0) & VU) {
                        cap = (uint8_t)(cap | (1u << q));
                    }
                    if (isunk_only(p, R, (uint8_t)(1u << q), WE_TENANT_FRESH, q)) {
                        unb = (uint8_t)(unb | (1u << q));
                    }
                }
            }
            if (cap != 0u && later_deny) {
                size_t o = 0u;

                for (q = 0u; q < NPLANES; q++) {
                    if ((cap >> q) & 1u) {
                        o += (size_t)snprintf(det + o, sizeof det - o, "%s%s%s", o == 0u ? "" : ",", plane_name[q],
                                              ((KEYED_MASK >> q) & 1u) ? "(keyed)" : "");
                    }
                }
                report(c, context, kind, n, NULL, "capturing-allow", det,
                       "rule %u allow captures every request while %s is stale or unarmed, disarming every deny and log "
                       "below it", n, det);
            }
            if (unb != 0u) {
                size_t o = 0u;

                for (q = 0u; q < NPLANES; q++) {
                    if ((unb >> q) & 1u) {
                        o += (size_t)snprintf(det + o, sizeof det - o, "%s%s", o == 0u ? "" : ",", plane_name[q]);
                    }
                }
                report(c, context, kind, n, NULL, "unbounded", det,
                       "rule %u allows for as long as %s stays stale or unarmed: unbounded in time", n, det);
            }
            {
                const node_t *fa[WE_LIM_OPS_RULE + 1];
                int all;
                uint32_t nf = flat_and(d, fa, &all), i;

                for (i = 0u; i < nf; i++) {
                    if (fa[i] != NULL && fa[i]->form == F_BARE && fa[i]->attr == A_TENANT_ALLOW) {
                        report(c, context, kind, n, NULL, "adds-nothing", "",
                               "rule %u adds nothing the tenant pre-stage does not already allow", n);
                        break;
                    }
                }
            }
        }
    }
}

/* a declaration's repeated members: harmless, reported */
static void declaration_reports(cc_t *c)
{
    uint32_t i;
    vals_t *vs = (vals_t *)c->vals;

    for (i = 0u; i < c->nsets; i++) {
        const setdecl_t *s = &c->sets[i];
        const dir_t *d = &c->dirs[s->dir];
        const tok_t **mem = c->mem2;
        uint32_t k, nm = 0u;
        char name[80];

        for (k = 1u; k < d->ntok; k++) {
            if (d->tok[k].type == TK_LIT) {
                mem[nm++] = &d->tok[k];
            }
        }
        vals_of(mem, nm, vs);
        if (vs->dups[0] != '\0') {
            snprintf(name, sizeof name, "%.*s", (int)s->name_len, (const char *)d->arg + s->name_off);
            report(c, c->ctxs[s->ctx].name, WE_DIR_SET, 0u, name, "duplicate-member", vs->dups,
                   "@%s: a duplicate member inside one set, harmless (%s)", name, vs->dups);
        }
    }
}

/* ======================================================================================================
 * The configuration
 * ==================================================================================================== */

struct we_policy_build {
    we_alloc_t     alloc;
    int            has_alloc;
    uint32_t       nctx;
    char         **ctx_name;
    int32_t       *ctx_parent;
    we_program_t **ctx_prog;     /* own program: lines, or threshold sugar; NULL otherwise */
    uint8_t       *ctx_mode;     /* own mode directive, 0 when none */
    uint8_t       *ctx_inferred; /* own allow_inferred directive: 0 none, 1 off, 2 on */
    we_program_t  *floor;
    we_program_t **blocks;       /* distinct, interned */
    uint32_t       nblocks;
    size_t         hot_total;
    uint32_t      *ctx_len;      /* strlen(ctx_name[i]) */
    uint32_t      *ctx_hash;     /* name_hash() of it */
    uint32_t      *ctx_ht;       /* open addressing over the names: index + 1, 0 empty */
    uint32_t       ctx_mask;
    uint8_t      (*bdig)[32];    /* while building: each block's digest */
    uint32_t      *bht;          /* ... and the blocks by digest: index + 1, 0 empty */
    uint32_t       bmask;
};

static const we_alloc_t *b_alloc(const we_policy_build_t *b)
{
    return b->has_alloc ? &b->alloc : NULL;
}

void we_program_free(const we_alloc_t *alloc, we_program_t *p)
{
    a_free(alloc, p);
}

size_t we_program_size(const we_program_t *p)
{
    return p != NULL ? p->total_len : 0u;
}

/* intern: an identical block already built is shared, confirmed by memcmp after the digest */
/* one block per distinct byte sequence: found by its digest in O(1), confirmed by memcmp */
static we_program_t *intern(we_policy_build_t *b, we_program_t *p)
{
    uint8_t dp[32];
    uint32_t i;

    we_sha256(p, p->total_len, dp);
    i = ((uint32_t)dp[0] | (uint32_t)dp[1] << 8 | (uint32_t)dp[2] << 16 | (uint32_t)dp[3] << 24) & b->bmask;
    while (b->bht[i] != 0u) {
        we_program_t *q = b->blocks[b->bht[i] - 1u];

        if (memcmp(dp, b->bdig[b->bht[i] - 1u], 32) == 0 && q->total_len == p->total_len
                && memcmp(p, q, p->total_len) == 0) {
            a_free(b_alloc(b), p);
            return q;
        }
        i = (i + 1u) & b->bmask;
    }
    memcpy(b->bdig[b->nblocks], dp, 32);
    b->blocks[b->nblocks++] = p;
    b->bht[i] = b->nblocks;
    b->hot_total += p->hot_len;
    return p;
}

void we_policy_build_free(we_policy_build_t *b)
{
    uint32_t i;
    const we_alloc_t *a;

    if (b == NULL) {
        return;
    }
    a = b_alloc(b);
    for (i = 0u; i < b->nblocks; i++) {
        a_free(a, b->blocks[i]);
    }
    for (i = 0u; i < b->nctx; i++) {
        a_free(a, b->ctx_name[i]);
    }
    a_free(a, b->ctx_name);
    a_free(a, b->ctx_parent);
    a_free(a, b->ctx_prog);
    a_free(a, b->ctx_mode);
    a_free(a, b->ctx_inferred);
    a_free(a, b->blocks);
    a_free(a, b->ctx_len);
    a_free(a, b->ctx_hash);
    a_free(a, b->ctx_ht);
    a_free(a, b->bdig);
    a_free(a, b->bht);
    a_free(a, b);
}

static int32_t build_ctx_len(const we_policy_build_t *b, const char *context, size_t len)
{
    uint32_t h = name_hash(context, len), i;

    if (b->ctx_ht == NULL) {
        return -1;
    }
    for (i = h & b->ctx_mask; b->ctx_ht[i] != 0u; i = (i + 1u) & b->ctx_mask) {
        uint32_t x = b->ctx_ht[i] - 1u;

        if (b->ctx_hash[x] == h && b->ctx_len[x] == len && memcmp(b->ctx_name[x], context, len) == 0) {
            return (int32_t)x;
        }
    }
    return -1;
}

/*
 * The context itself if the configuration named it, else its nearest named ancestor: "a/b/c" tries
 * "a/b/c", "a/b", then "a", each a prefix length of the caller's string. No copy and no buffer, so a
 * context of any length resolves the way a short one does. -1: no ancestor was named.
 */
static int32_t build_nearest(const we_policy_build_t *b, const char *context)
{
    size_t len = strlen(context);

    for (;;) {
        int32_t x = build_ctx_len(b, context, len);

        if (x >= 0) {
            return x;
        }
        while (len > 0u && context[len - 1u] != '/') {
            len--;
        }
        if (len == 0u) {
            return -1;
        }
        len--;                                 /* the '/' itself */
    }
}

int we_policy_compile(const we_policy_source_t *src, const we_policy_env_t *env, const we_alloc_t *alloc,
                      we_program_t **out, we_policy_error_t *err, we_policy_report_t *rep)
{
    we_policy_build_t *b = NULL;
    const we_program_t *p;
    we_program_t *q;
    int rc;

    if (out == NULL) {
        return WE_POLICY_NOMEM;
    }
    *out = NULL;
    rc = we_policy_build(src, env, alloc, &b, err, rep);
    if (rc != WE_POLICY_OK) {
        return rc;
    }
    p = src->floor ? we_policy_floor(b) : we_policy_program(b, src->context != NULL ? src->context : "http");
    if (p != NULL) {
        q = (we_program_t *)a_alloc(alloc, p->total_len, 64u);
        if (q == NULL) {
            we_policy_build_free(b);
            return WE_POLICY_NOMEM;
        }
        memcpy(q, p, p->total_len);
        *out = q;
    }
    we_policy_build_free(b);
    return WE_POLICY_OK;
}

const we_program_t *we_policy_program(const we_policy_build_t *b, const char *context)
{
    int32_t x;

    if (b == NULL || context == NULL) {
        return NULL;
    }
    x = build_nearest(b, context);          /* a context never named runs its nearest named ancestor's */
    while (x >= 0) {
        if (b->ctx_prog[x] != NULL) {
            return b->ctx_prog[x];
        }
        x = b->ctx_parent[x];
    }
    return NULL;
}

const we_program_t *we_policy_floor(const we_policy_build_t *b)
{
    return b != NULL ? b->floor : NULL;
}

we_ctx_conf_t we_policy_conf(const we_policy_build_t *b, const char *context)
{
    we_ctx_conf_t c;
    int32_t x;

    c.mode = WE_MODE_UNSET;
    c.allow_inferred = 0u;
    if (b == NULL || context == NULL) {
        return c;
    }
    /*
     * Each scalar from the nearest context that sets it, as the modules merge them, starting from the
     * nearest context the configuration named: a child with no lines of its own inherits, exactly as
     * we_policy_program() resolves it.
     */
    x = build_nearest(b, context);
    while (x >= 0 && c.mode == WE_MODE_UNSET) {
        c.mode = b->ctx_mode[x];
        x = b->ctx_parent[x];
    }
    x = build_nearest(b, context);
    while (x >= 0) {
        if (b->ctx_inferred[x] != 0u) {
            c.allow_inferred = (uint8_t)(b->ctx_inferred[x] - 1u);
            break;
        }
        x = b->ctx_parent[x];
    }
    return c;
}

uint32_t we_policy_block_count(const we_policy_build_t *b)
{
    return b != NULL ? b->nblocks : 0u;
}

size_t we_policy_hot_total(const we_policy_build_t *b)
{
    return b != NULL ? b->hot_total : 0u;
}

static int compile_front(cc_t *c)
{
    uint32_t i;
    tok_t *scratch;

    /* contexts, ordinals, set table */
    c->ctxcap = context_capacity(c->src);
    c->ctxs = (ctxent_t *)ar_get(&c->ar, sizeof(ctxent_t) * (c->ctxcap + 1u));
    c->cmask = table_size(c->ctxcap) - 1u;
    c->cht = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * ((size_t)c->cmask + 1u));
    c->chead = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * (c->ctxcap + 1u));
    c->dnext = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * (c->ndirs + 1u));
    c->dirs = (dir_t *)ar_get(&c->ar, sizeof(dir_t) * (c->ndirs + 1u));
    c->sets = (setdecl_t *)ar_get(&c->ar, sizeof(setdecl_t) * (c->ndirs + 1u));
    scratch = (tok_t *)ar_get(&c->ar, sizeof(tok_t) * (WE_LIM_ARG * 2u + 8u));
    c->mem = (const tok_t **)ar_get(&c->ar, sizeof(tok_t *) * WE_LIM_ARG);
    c->mem2 = (const tok_t **)ar_get(&c->ar, sizeof(tok_t *) * WE_LIM_ARG);
    c->keys = (uint32_t *)ar_get(&c->ar, sizeof(uint32_t) * WE_LIM_ARG);
    c->vals = ar_get(&c->ar, 3u * sizeof(vals_t));
    if (c->ctxs == NULL || c->cht == NULL || c->chead == NULL || c->dnext == NULL || c->dirs == NULL
            || c->sets == NULL || scratch == NULL || c->mem == NULL || c->mem2 == NULL || c->keys == NULL
            || c->vals == NULL) {
        return -2;
    }
    if (ctx_intern(c, "http") < 0) {
        return -2;
    }
    for (i = 0u; i < c->ndirs; i++) {
        dir_t *d = &c->dirs[i];
        int32_t x;

        d->d = &c->src->d[i];
        d->arg = d->d->arg != NULL ? d->d->arg : (const uint8_t *)"";
        d->len = (uint32_t)(d->d->len > 0xffffffffu ? 0xffffffffu : d->d->len);
        d->index = i;
        d->decl = -1;
        x = ctx_intern(c, d->d->context != NULL ? d->d->context : "http");
        if (x < 0) {
            return -2;
        }
        d->ctx = (uint32_t)x;
        /* the ordinal among this context's directives of this kind: a counter per context and kind */
        d->ordinal = ++c->ctxs[x].seen[d->d->kind < 8u ? d->d->kind : 0u];
        if (d->d->kind == WE_DIR_POLICY) {
            c->ctxs[x].has_policy = 1u;
        }
    }
    /* each context's directives in file order, linked once from the back (program_rules walks them) */
    for (i = c->ndirs; i > 0u; i--) {
        uint32_t x = c->dirs[i - 1u].ctx;

        c->dnext[i - 1u] = c->chead[x];
        c->chead[x] = i;
    }
    /*
     * Steps 1 to 5 per directive, in source order, the way a server hands a module its directives one
     * at a time: the argument length before anything is read, the first byte outside the alphabet,
     * lexing, parsing, typing.
     */
    for (i = 0u; i < c->ndirs; i++) {
        dir_t *d = &c->dirs[i];
        uint32_t kind = d->d->kind, k;
        int rc = 0;

        if (!c->exempt_length && d->d->len > WE_LIM_ARG) {
            fail_at(c, "length", "argument over 2,048 bytes", d, 0u, 0u, 0, "shorten it, or move members into a set",
                    "argument over 2,048 bytes (%zu bytes)", d->d->len);
            if (c->err != NULL) {
                c->err->line = 1u;
                c->err->col = 1u;
            }
            return -1;
        }
        for (k = 0u; k < d->len; k++) {
            if (!in_alphabet(d->arg[k])) {
                char phrase[32];

                snprintf(phrase, sizeof phrase, "byte 0x%02X is not allowed", d->arg[k]);
                fail_at(c, "alphabet", phrase, d, k, 1u, 1, "the language is printable ASCII", "%s", phrase);
                return -1;
            }
        }
        if (kind == WE_DIR_POLICY || kind == WE_DIR_FLOOR) {
            if (kind == WE_DIR_FLOOR && strcmp(c->ctxs[d->ctx].name, "http") != 0) {
                fail_at(c, "parsing", "a floor is http-level only", d, 0u, 0u, 0,
                        "whisper_edge_policy_floor is valid at http level only", "a floor is http-level only");
                if (c->err != NULL) {
                    c->err->line = 1u;
                    c->err->col = 1u;
                }
                return -1;
            }
            rc = lex_dir(c, d, scratch, WE_LIM_ARG * 2u + 8u);
            if (rc == 0) {
                rc = parse_policy(c, d);
            }
            if (rc == 0) {
                rc = type_rule(c, d);
            }
        } else if (kind == WE_DIR_SET) {
            rc = lex_dir(c, d, scratch, WE_LIM_ARG * 2u + 8u);
            if (rc == 0) {
                rc = parse_set(c, d);
            }
            if (rc == 0) {
                setdecl_t *s = &c->sets[c->nsets];

                s->dir = i;
                s->ctx = d->ctx;
                s->name_off = d->tok[0].off + 1u;
                s->name_len = d->tok[0].len - 1u;
                d->decl = (int32_t)c->nsets++;
            }
        } else if (kind == WE_DIR_THRESHOLD || kind == WE_DIR_MODE || kind == WE_DIR_ALLOW_INFERRED) {
            rc = lex_word_arg(c, d);
            if (rc == 0 && kind == WE_DIR_THRESHOLD) {
                c->ctxs[d->ctx].has_threshold = 1u;
                c->ctxs[d->ctx].threshold = d->value;
            } else if (rc == 0 && kind == WE_DIR_MODE) {
                c->ctxs[d->ctx].has_mode = 1u;
                c->ctxs[d->ctx].mode = (uint8_t)(WE_MODE_OFF + d->value);
            } else if (rc == 0) {
                c->ctxs[d->ctx].has_inferred = 1u;
                c->ctxs[d->ctx].inferred = d->value;
            }
        } else {
            fail_at(c, "parsing", "an unknown directive", d, 0u, 0u, 0, "", "an unknown directive");
            if (c->err != NULL) {
                c->err->line = 1u;
                c->err->col = 1u;
            }
            return -1;
        }
        if (rc != 0) {
            return rc;
        }
    }
    /* 6: sets, once every directive is seen */
    if (sets_layer(c) != 0) {
        return -1;
    }
    /* 7: program limits */
    {
        int rc = limits_layer(c);

        if (rc != 0) {
            return rc;
        }
    }
    /* 8: polarity */
    {
        int rc = polarity_layer(c);

        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

/* the directive indexes of one program, in order: a walk of the context's own list, never of the source */
static uint32_t program_rules(const cc_t *c, uint32_t ctx, uint8_t kind, uint32_t *out)
{
    uint32_t i, n = 0u;

    for (i = c->chead[ctx]; i != 0u; i = c->dnext[i - 1u]) {
        if (c->dirs[i - 1u].d->kind == kind) {
            out[n++] = i - 1u;
        }
    }
    return n;
}


/*
 * THE COMPILE IS LINEAR IN THE DIRECTIVES. Every per-directive step is O(1) or O(its own bytes): the
 * context lookup is a hash over the name (ctx_find, the build's ctx_ht), each context's directives are
 * linked once in file order (program_rules walks only its own), the later-deny ordinal for polarity is
 * one reverse pass with a per-(context, kind) slot, the named sets a program has paid for are one table
 * over (program, set), identical blocks are found by digest (intern), and the reports' context order is a
 * merge sort, O(n log n). What stays bounded rather than constant is the set table: a set reference
 * resolves against at most 1,024 declarations (the configuration's limit) per ancestor. Measured once
 * with callgrind on 2026-10-11, on the mass-hosting shape (one server context per four directives: a
 * mode, three policy lines), the build plus a never-named child's program and conf looked up per server
 * took about 287 M, 575 M and 1.15 G instructions at 10,000, 20,000 and 40,000 directives, shared block
 * or a block each alike, where before the indexes the forward polarity scan, the per-context scan of
 * every directive, the context lookup by strlen, the reports' insertion sort and a re-digest of every
 * interned block per new one were each quadratic. About a third of what remained was SHA-256 over the
 * blocks. The harness is not in the tree and no gate re-measures it; the compile path has changed since.
 */
/*
 * Context indexes by name (strcmp order), for the reports: a bottom-up merge sort, O(n log n), over the
 * caller's scratch of n entries. Names are distinct, so the order is total.
 */
static void sort_ctx_by_name(const ctxent_t *ctxs, uint32_t *v, uint32_t *tmp, uint32_t n)
{
    uint32_t w;

    for (w = 1u; w < n; w *= 2u) {
        uint32_t lo;

        for (lo = 0u; lo < n; lo += 2u * w) {
            uint32_t mid = lo + w < n ? lo + w : n, hi = lo + 2u * w < n ? lo + 2u * w : n;
            uint32_t a = lo, b = mid, o = lo;

            while (a < mid && b < hi) {
                tmp[o++] = strcmp(ctxs[v[a]].name, ctxs[v[b]].name) <= 0 ? v[a++] : v[b++];
            }
            while (a < mid) {
                tmp[o++] = v[a++];
            }
            while (b < hi) {
                tmp[o++] = v[b++];
            }
        }
        memcpy(v, tmp, sizeof(uint32_t) * n);
    }
}

static int sugar_in_env(uint8_t threshold, int legacy, uint8_t present, const we_alloc_t *alloc,
                        we_program_t **out);

int we_policy_build(const we_policy_source_t *src, const we_policy_env_t *env, const we_alloc_t *alloc,
                    we_policy_build_t **out, we_policy_error_t *err, we_policy_report_t *rep)
{
    cc_t c;
    we_policy_build_t *b = NULL;
    uint32_t i, *rix = NULL;
    int rc, vfailed = 0;
    we_policy_error_t vrf;
    static const we_policy_env_t all = WE_POLICY_ENV_ALL;

    if (out == NULL || src == NULL) {
        return WE_POLICY_NOMEM;
    }
    *out = NULL;
    memset(&c, 0, sizeof c);
    c.src = src;
    c.env = env != NULL ? env : &all;
    c.alloc = alloc;
    c.rep = rep;
    c.err = err;
    c.exempt_length = c.env->canonical != 0u;   /* POLICY.md D32: the canonical text, re-parsed, may be longer */
    c.ar.alloc = alloc;
    c.ndirs = (uint32_t)src->n;
    if (err != NULL) {
        memset(err, 0, sizeof *err);
    }
    rc = compile_front(&c);
    if (rc != 0) {
        ar_free(&c.ar);
        return rc == -1 ? WE_POLICY_REFUSED : WE_POLICY_NOMEM;
    }
    b = (we_policy_build_t *)a_alloc(alloc, sizeof *b, 16u);
    rix = (uint32_t *)ar_get(&c.ar, sizeof(uint32_t) * (c.ndirs + 1u));
    if (b == NULL || rix == NULL) {
        a_free(alloc, b);
        ar_free(&c.ar);
        return WE_POLICY_NOMEM;
    }
    memset(b, 0, sizeof *b);
    if (alloc != NULL) {
        b->alloc = *alloc;
        b->has_alloc = 1;
    }
    b->nctx = c.nctx;
    b->ctx_name = (char **)a_alloc(alloc, sizeof(char *) * (c.nctx + 1u), 16u);
    b->ctx_parent = (int32_t *)a_alloc(alloc, sizeof(int32_t) * (c.nctx + 1u), 16u);
    b->ctx_prog = (we_program_t **)a_alloc(alloc, sizeof(we_program_t *) * (c.nctx + 1u), 16u);
    b->ctx_mode = (uint8_t *)a_alloc(alloc, c.nctx + 1u, 16u);
    b->ctx_inferred = (uint8_t *)a_alloc(alloc, c.nctx + 1u, 16u);
    b->blocks = (we_program_t **)a_alloc(alloc, sizeof(we_program_t *) * (c.nctx + 2u), 16u);
    b->ctx_len = (uint32_t *)a_alloc(alloc, sizeof(uint32_t) * (c.nctx + 1u), 16u);
    b->ctx_hash = (uint32_t *)a_alloc(alloc, sizeof(uint32_t) * (c.nctx + 1u), 16u);
    b->ctx_mask = table_size(c.nctx) - 1u;
    b->ctx_ht = (uint32_t *)a_alloc(alloc, sizeof(uint32_t) * ((size_t)b->ctx_mask + 1u), 16u);
    b->bdig = (uint8_t (*)[32])a_alloc(alloc, 32u * (c.nctx + 2u), 16u);
    b->bmask = table_size(c.nctx + 2u) - 1u;
    b->bht = (uint32_t *)a_alloc(alloc, sizeof(uint32_t) * ((size_t)b->bmask + 1u), 16u);
    if (b->ctx_name == NULL || b->ctx_parent == NULL || b->ctx_prog == NULL || b->ctx_mode == NULL
            || b->ctx_inferred == NULL || b->blocks == NULL || b->ctx_len == NULL || b->ctx_hash == NULL
            || b->ctx_ht == NULL || b->bdig == NULL || b->bht == NULL) {
        b->nctx = 0u;
        we_policy_build_free(b);
        ar_free(&c.ar);
        return WE_POLICY_NOMEM;
    }
    memset(b->ctx_name, 0, sizeof(char *) * (c.nctx + 1u));
    memset(b->ctx_prog, 0, sizeof(we_program_t *) * (c.nctx + 1u));
    memset(b->ctx_ht, 0, sizeof(uint32_t) * ((size_t)b->ctx_mask + 1u));
    memset(b->bht, 0, sizeof(uint32_t) * ((size_t)b->bmask + 1u));
    for (i = 0u; i < c.nctx; i++) {
        size_t l = c.ctxs[i].len;
        uint32_t h = c.ctxs[i].hash & b->ctx_mask;

        b->ctx_name[i] = (char *)a_alloc(alloc, l + 1u, 16u);
        if (b->ctx_name[i] == NULL) {
            we_policy_build_free(b);
            ar_free(&c.ar);
            return WE_POLICY_NOMEM;
        }
        memcpy(b->ctx_name[i], c.ctxs[i].name, l + 1u);
        b->ctx_len[i] = (uint32_t)l;
        b->ctx_hash[i] = c.ctxs[i].hash;
        while (b->ctx_ht[h] != 0u) {
            h = (h + 1u) & b->ctx_mask;
        }
        b->ctx_ht[h] = i + 1u;
        b->ctx_parent[i] = c.ctxs[i].parent;
        b->ctx_mode[i] = c.ctxs[i].has_mode ? c.ctxs[i].mode : 0u;
        b->ctx_inferred[i] = c.ctxs[i].has_inferred ? (uint8_t)(c.ctxs[i].inferred + 1u) : 0u;
    }
    for (i = 0u; i < c.nctx; i++) {
        uint32_t nr;
        we_program_t *p = NULL;

        if (c.ctxs[i].has_policy) {
#ifndef WE_MOD_TEST_APPEND
            nr = program_rules(&c, i, WE_DIR_POLICY, rix);
#else
            {
                /* the control: a context's lines appended to its nearest ancestor's that has lines, not
                 * replacing them */
                int32_t a = c.ctxs[i].parent;

                while (a >= 0 && !c.ctxs[a].has_policy) {
                    a = c.ctxs[a].parent;
                }
                nr = a >= 0 ? program_rules(&c, (uint32_t)a, WE_DIR_POLICY, rix) : 0u;
                nr += program_rules(&c, i, WE_DIR_POLICY, rix + nr);
            }
#endif
            if (encode(&c, rix, nr, 0, &p) != 0) {
                goto nomem;
            }
        } else if (c.ctxs[i].has_threshold) {
            if (sugar_in_env(c.ctxs[i].threshold, c.env->legacy != 0u, c.env->present, alloc, &p) != WE_POLICY_OK) {
                goto nomem;
            }
        }
        if (p != NULL) {
            if ((vfailed = we_program_verify(p, p->total_len, &vrf)) != 0) {
                a_free(alloc, p);
                goto nomem;
            }
            b->ctx_prog[i] = intern(b, p);
        }
    }
    {
        uint32_t nr = program_rules(&c, 0u, WE_DIR_FLOOR, rix);
        we_program_t *p = NULL;

        if (encode(&c, rix, nr, 1, &p) != 0) {
            goto nomem;
        }
        if ((vfailed = we_program_verify(p, p->total_len, &vrf)) != 0) {
            a_free(alloc, p);
            goto nomem;
        }
        b->floor = intern(b, p);
    }
    /*
     * The reports, once every block is built and verified: the declarations' repeats in source order,
     * then the floor, then each context's own program in the order of its name.
     */
    declaration_reports(&c);
    {
        uint32_t nr = program_rules(&c, 0u, WE_DIR_FLOOR, rix);

        if (nr > 0u) {
            program_reports(&c, "http", WE_DIR_FLOOR, rix, nr, b->floor);
        }
    }
    {
        uint32_t *order = (uint32_t *)ar_get(&c.ar, sizeof(uint32_t) * (c.nctx + 1u)), no = 0u, k;
        uint32_t *tmp = (uint32_t *)ar_get(&c.ar, sizeof(uint32_t) * (c.nctx + 1u));

        if (order == NULL || tmp == NULL) {
            goto nomem;
        }
        /* every context that runs its own program: policy lines, or the threshold sugar (D-af) */
        for (i = 0u; i < c.nctx; i++) {
            if (c.ctxs[i].has_policy || (c.ctxs[i].has_threshold && b->ctx_prog[i] != NULL)) {
                order[no++] = i;
            }
        }
        sort_ctx_by_name(c.ctxs, order, tmp, no);
        for (k = 0u; k < no; k++) {
            if (c.ctxs[order[k]].has_policy) {
                uint32_t nr = program_rules(&c, order[k], WE_DIR_POLICY, rix);

                program_reports(&c, c.ctxs[order[k]].name, WE_DIR_POLICY, rix, nr, b->ctx_prog[order[k]]);
            } else {
                sugar_reports(&c, c.ctxs[order[k]].name, b->ctx_prog[order[k]]);
            }
        }
    }
    ar_free(&c.ar);
    *out = b;
    return WE_POLICY_OK;
nomem:
    we_policy_build_free(b);
    ar_free(&c.ar);
    if (err != NULL) {
        if (vfailed != 0) {
            /* the compiler built a block its own verifier refuses: a defect here, never the operator's */
            *err = vrf;
            return WE_POLICY_NOMEM;
        }
        memset(err, 0, sizeof *err);
        err->layer = "program";
        snprintf(err->phrase, sizeof err->phrase, "out of memory");
        snprintf(err->what, sizeof err->what, "out of memory");
    }
    return WE_POLICY_NOMEM;
}

/* compile one program from text lines (the verifier's re-parse and the sugar) */
static int compile_text(const char *text, size_t len, int floor, int legacy, uint8_t present, const we_alloc_t *alloc,
                        int exempt, we_program_t **out, we_policy_error_t *err)
{
    we_policy_directive_t *ds;
    we_policy_source_t src;
    we_policy_env_t env;
    cc_t c;
    size_t i, s, nd = 0u, cap = 1u;
    uint32_t *rix;
    int rc;

    for (i = 0u; i < len; i++) {
        cap += text[i] == '\n';
    }
    ds = (we_policy_directive_t *)calloc(cap, sizeof *ds);
    if (ds == NULL) {
        return WE_POLICY_NOMEM;
    }
    for (s = 0u, i = 0u; i <= len; i++) {
        if (i == len || text[i] == '\n') {
            if (i > s) {
                ds[nd].kind = text[s] == '@' ? WE_DIR_SET : floor ? WE_DIR_FLOOR : WE_DIR_POLICY;
                ds[nd].context = "http";
                ds[nd].arg = (const uint8_t *)text + s;
                ds[nd].len = i - s;
                nd++;
            }
            s = i + 1u;
        }
    }
    src.d = ds;
    src.n = nd;
    memset(&env, 0, sizeof env);
    env.present = present;
    env.legacy = (uint8_t)legacy;
    memset(&c, 0, sizeof c);
    c.src = &src;
    c.env = &env;
    c.alloc = alloc;
    c.err = err;
    c.ar.alloc = alloc;
    c.ndirs = (uint32_t)nd;
    c.exempt_length = exempt;
    rc = compile_front(&c);
    if (rc != 0) {
        ar_free(&c.ar);
        free(ds);
        return rc == -1 ? WE_POLICY_REFUSED : WE_POLICY_NOMEM;
    }
    rix = (uint32_t *)ar_get(&c.ar, sizeof(uint32_t) * (nd + 1u));
    if (rix == NULL) {
        ar_free(&c.ar);
        free(ds);
        return WE_POLICY_NOMEM;
    }
    {
        uint32_t nr = program_rules(&c, 0u, floor ? WE_DIR_FLOOR : WE_DIR_POLICY, rix);

        rc = encode(&c, rix, nr, floor, out) == 0 ? WE_POLICY_OK : WE_POLICY_NOMEM;
    }
    ar_free(&c.ar);
    free(ds);
    return rc;
}

/*
 * The threshold sugar in a given environment: the planes present and the legacy flag shape the block's
 * bindings, so a context's sugar is compiled for the build's environment, exactly as its policy lines
 * would be; compiled for every plane present, it would differ from its own canonical text re-parsed
 * where a plane is absent, and the module would refuse to arm it there (D4).
 */
static int sugar_in_env(uint8_t threshold, int legacy, uint8_t present, const we_alloc_t *alloc, we_program_t **out)
{
    char text[64];

    if (out == NULL || threshold > 4u) {
        return WE_POLICY_REFUSED;
    }
    if (threshold == 0u) {
        text[0] = '\0';
    } else {
        snprintf(text, sizeof text, "deny if listed >= %s\n", level_name[threshold]);
    }
    return compile_text(text, strlen(text), 0, legacy, present, alloc, 0, out, NULL);
}

int we_policy_sugar(uint8_t threshold, const we_alloc_t *alloc, we_program_t **out)
{
    return sugar_in_env(threshold, 0, 0xffu, alloc, out);
}

int we_policy_sugar_env(uint8_t threshold, const we_policy_env_t *env, const we_alloc_t *alloc, we_program_t **out)
{
    static const we_policy_env_t all = WE_POLICY_ENV_ALL;

    if (env == NULL) {
        env = &all;
    }
    return sugar_in_env(threshold, env->legacy != 0u, env->present, alloc, out);
}

/* ======================================================================================================
 * The verifier, POLICY.md §5.5: twenty-two refusals in order
 * ==================================================================================================== */

static int vfail(we_policy_error_t *err, int step, const char *fmt, ...)
{
    if (err != NULL) {
        va_list ap;

        memset(err, 0, sizeof *err);
        err->layer = "verify";
        snprintf(err->phrase, sizeof err->phrase, "a program the verifier refused");
        err->rule = (uint32_t)step;
        va_start(ap, fmt);
        vsnprintf(err->what, sizeof err->what, fmt, ap);
        va_end(ap);
        snprintf(err->fix, sizeof err->fix, "verifier step %d", step);
    }
    return -step;
}

/* record a failure when it is the lowest-numbered step seen so far (section 5.5's order) */
static void vnote(we_policy_error_t *err, int *best, int step, const char *fmt, ...)
{
    if (*best != 0 && step >= *best) {
        return;
    }
    *best = step;
    if (err != NULL) {
        va_list ap;

        memset(err, 0, sizeof *err);
        err->layer = "verify";
        snprintf(err->phrase, sizeof err->phrase, "a program the verifier refused");
        err->rule = (uint32_t)step;
        va_start(ap, fmt);
        vsnprintf(err->what, sizeof err->what, fmt, ap);
        va_end(ap);
        snprintf(err->fix, sizeof err->fix, "verifier step %d", step);
    }
}

static int pad_zero(const uint8_t *b, uint32_t from, uint32_t to)
{
    uint32_t i;

    for (i = from; i < to; i++) {
        if (b[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int we_program_verify(const we_program_t *p, size_t len, we_policy_error_t *err)
{
    const uint8_t *b = (const uint8_t *)p;
    const we_rule_t *rules;
    const we_instr_t *ins;
    const we_binding_t *bind;
    const we_setdesc_t *sd;
    uint32_t r, k, nr, ni, ns, ops_seen = 0u, ops_lo = 0u, ops_hi = 0u;
    int best = 0;                     /* the lowest-numbered step that failed, once steps 1 to 5 hold */
    uint8_t pmask = 0u;
    uint32_t hh_end;

    if (p == NULL) {
        return vfail(err, 1, "no program");
    }
    /* (1) magic, version, total length against the buffer */
    if (len < sizeof(we_program_t) || p->magic != WE_PROG_MAGIC || p->version != WE_PROG_VERSION
            || p->total_len > len || p->total_len < sizeof(we_program_t)) {
        return vfail(err, 1, "magic, version or total length");
    }
    nr = p->rule_count;
    ni = p->instr_count;
    ns = p->set_count;
    /* (2) every table inside the block, 64-byte aligned, in the layout order, no overlap */
    {
        uint32_t o[8];

        o[0] = p->rules_off;
        o[1] = p->instrs_off;
        o[2] = p->bindings_off;
        o[3] = p->sets_off;
        o[4] = p->hh_off;
        o[5] = p->setdata_off;
        o[6] = p->text_off;
        o[7] = p->total_len;
        if (o[0] != 64u) {
            return vfail(err, 2, "the rules do not follow the header");
        }
        for (k = 0u; k < 7u; k++) {
            if ((o[k] & 63u) != 0u || o[k] > o[k + 1u] || o[k] > p->total_len) {
                return vfail(err, 2, "a table offset is out of order, unaligned or outside the block");
            }
        }
        if ((uint64_t)o[0] + 16u * nr > o[1] || (uint64_t)o[1] + 8u * ni > o[2] || o[2] + 256u > o[3]
                || (uint64_t)o[3] + 16u * ns > o[4] || p->text_off != p->hot_len
                || (uint64_t)p->text_off + p->text_len > p->total_len || al64(p->text_off + p->text_len) != p->total_len) {
            return vfail(err, 2, "a table overlaps the next");
        }
    }
    rules = (const we_rule_t *)(const void *)(b + p->rules_off);
    ins = (const we_instr_t *)(const void *)(b + p->instrs_off);
    bind = (const we_binding_t *)(const void *)(b + p->bindings_off);
    sd = (const we_setdesc_t *)(const void *)(b + p->sets_off);
    /* (3) the counts against their tables and the limits */
    if (nr > WE_LIM_RULES || ni > WE_LIM_INSTRS || p->op_count > WE_LIM_OPS_CTX || ns > p->instr_count) {
        return vfail(err, 3, "a count over its limit");
    }
    /* (4) rule ranges contiguous, covering instr_count, each ending in exactly one END */
    {
        uint32_t at = 0u;

        for (r = 0u; r < nr; r++) {
            const we_rule_t *R = &rules[r];

            if (R->instr_start != at || R->instr_count == 0u || (uint32_t)R->instr_start + R->instr_count > ni) {
                return vfail(err, 4, "rule %u's instructions are not contiguous", r + 1u);
            }
            for (k = 0u; k < R->instr_count; k++) {
                int last = k + 1u == R->instr_count;

                if (((ins[at + k].op & WE_OP_END) != 0u) != last) {
                    return vfail(err, 4, "rule %u does not end in exactly one END", r + 1u);
                }
            }
            at += R->instr_count;
        }
        if (at != ni) {
            return vfail(err, 4, "the rules do not cover the instructions");
        }
    }
    /* (5) one bit of the known set */
    for (k = 0u; k < ni; k++) {
        uint32_t op = ins[k].op;

        if (op == 0u || (op & (op - 1u)) != 0u || (op & ~WE_OP_KNOWN) != 0u) {
            return vfail(err, 5, "instruction %u's opcode is not one known bit", k);
        }
    }
    /*
     * From here on, every check records its failure and carries on wherever what follows does not
     * depend on it (a failing rule skips only the rest of that rule), so the step reported is the
     * lowest-numbered one that fails, as section 5.5 orders them; steps 1 to 5 above stop at once,
     * because every later read is bounded by them.
     */
#define VSKIP(...) do { vnote(err, &best, __VA_ARGS__); goto next_rule; } while (0)
#define VNOTE(...) vnote(err, &best, __VA_ARGS__)
    for (r = 0u; r < nr; r++) {
        const we_rule_t *R = &rules[r];
        uint8_t dep = 0u;
        uint32_t h = 0u, maxh = 0u;
        uint32_t height[512];             /* a legal rule has at most 2 * 64 + 1 instructions */

        if (R->instr_count > 512u) {
            VSKIP(12, "rule %u is longer than any legal rule", r + 1u);
        }
        for (k = 0u; k < R->instr_count; k++) {
            height[k] = 0xffffffffu;
        }
        for (k = 0u; k < R->instr_count; k++) {
            const we_instr_t *I = &ins[R->instr_start + k];
            uint32_t op = I->op, pl = I->plane;

            if ((op & WE_OP_ATOM) != 0u) {
                const we_binding_t *B;
                uint32_t width;

                /* (6) the plane 0..7, a binding present */
                if (pl > 7u) {
                    VSKIP(6, "rule %u reads plane %u", r + 1u, pl + 1u);
                }
                B = &bind[pl];
                dep = (uint8_t)(dep | (1u << pl));
                /* (7) off plus the width within the block */
                width = (op & (WE_OP_BOOL | WE_OP_SEV | WE_OP_EQ8 | WE_OP_INSET_ENUM)) ? 1u
                      : (op & (WE_OP_EQ16 | WE_OP_INSET_COUNTRY)) ? 2u : (op & (WE_OP_EQ32 | WE_OP_INSET_ASN)) ? 4u : 0u;
                if ((op & WE_OP_ISUNK) != 0u) {
                    if (I->off != 0u || I->imm != 0u) {
                        VSKIP(7, "rule %u: ISUNK carries an operand", r + 1u);
                    }
                } else if ((uint32_t)I->off + width > B->width) {
                    VSKIP(7, "rule %u reads past plane %u's block", r + 1u, pl + 1u);
                }
                /* (8) SEV only on reputation, a level mask in domain */
                if ((op & WE_OP_SEV) != 0u && (pl != 0u || I->off != 0u || I->imm > 0x1fu)) {
                    VSKIP(8, "rule %u: SEV outside reputation or its domain", r + 1u);
                }
                /* (9) immediates in domain, and the tenant polarity bit exactly on its occurrence */
                if ((op & WE_OP_EQ8) != 0u) {
                    uint32_t lim = (pl == 3u && I->off == 6u) ? 4u : (pl == 2u && I->off == 5u) ? 2u
                                 : ((pl == 3u || pl == 6u) && I->off == 7u) ? 5u : (pl == 3u && I->off == 9u) ? 4u : 0xffu;

                    if (lim == 0xffu || I->imm > lim) {
                        VSKIP(9, "rule %u: EQ8 outside its attribute's domain", r + 1u);
                    }
                }
                if ((op & WE_OP_INSET_ENUM) != 0u) {
                    uint32_t lim = (pl == 3u && I->off == 6u) ? 0x1fu : (pl == 2u && I->off == 5u) ? 0x07u
                                 : ((pl == 3u || pl == 6u) && I->off == 7u) ? 0x3fu : (pl == 3u && I->off == 9u) ? 0x1fu : 0u;

                    if (lim == 0u || (I->imm & ~lim) != 0u || I->imm == 0u) {
                        VSKIP(9, "rule %u: an enum mask outside its domain", r + 1u);
                    }
                }
                if ((op & WE_OP_EQ16) != 0u && !((pl == 3u || pl == 6u) && I->off == 4u && I->imm <= WE_COUNTRY_MAX)) {
                    VSKIP(9, "rule %u: EQ16 outside the country attributes", r + 1u);
                }
                if ((op & WE_OP_EQ32) != 0u && !(pl == 3u && I->off == 0u)) {
                    VSKIP(9, "rule %u: EQ32 outside asn", r + 1u);
                }
                if ((op & WE_OP_BOOL) != 0u) {
                    uint32_t mask = I->imm & 0xffu, pol = (I->imm & WE_BOOL_POLARITY) != 0u;
                    uint32_t expect = 0u;

                    if ((I->imm & ~0x1ffu) != 0u || mask == 0u || (mask & (mask - 1u)) != 0u
                            || (pl == 0u ? mask != 0x80u : (mask & B->flag_mask) == 0u)) {
                        VSKIP(9, "rule %u: a bool mask outside its plane", r + 1u);
                    }
                    if (pl == 7u && mask == WE_MF_TENANT_ALLOW && R->action == WE_ACT_ALLOW) {
                        /*
                         * Recompute the polarity from the instructions: run the rest of the rule on an
                         * abstract stack whose entries say whether they hold this atom (bit 0) and the
                         * parity of the NOTs applied to it (bit 1). Twenty entries below it stand for
                         * whatever the stack held before; none of them holds the atom.
                         */
                        uint32_t j, flips = 0u;
                        uint32_t hs[WE_LIM_STACK + 32u];
                        uint32_t hsp = 20u;

                        memset(hs, 0, sizeof hs);
                        hs[hsp++] = 1u;          /* this atom, parity 0 */
                        for (j = k + 1u; j < R->instr_count; j++) {
                            uint32_t o2 = ins[R->instr_start + j].op;

                            if ((o2 & WE_OP_ATOM) != 0u) {
                                if (hsp < WE_LIM_STACK + 32u) {
                                    hs[hsp++] = 0u;
                                }
                            } else if ((o2 & WE_OP_NOT) != 0u && hsp >= 1u) {
                                if (hs[hsp - 1u] & 1u) {
                                    hs[hsp - 1u] ^= 2u;
                                }
                            } else if ((o2 & (WE_OP_AND | WE_OP_OR)) != 0u && hsp >= 2u) {
                                hs[hsp - 2u] = hs[hsp - 2u] | hs[hsp - 1u];
                                hsp--;
                            }
                        }
                        flips = hsp >= 1u ? (hs[hsp - 1u] >> 1) & 1u : 0u;
                        expect = flips == 0u;
                    }
                    if (pl != 7u ? pol != 0u : pol != expect) {
                        VSKIP(9, "rule %u: the tenant polarity bit disagrees with its occurrence", r + 1u);
                    }
                }
                /* (10) sets: the payload is a described set, of its kind */
                if ((op & (WE_OP_INSET_COUNTRY | WE_OP_INSET_ASN)) != 0u) {
                    uint32_t off = (op & WE_OP_INSET_ASN) ? WE_ASN_IMM_OFF(I->imm) : I->imm, q, found = 0u;

                    for (q = 0u; q < ns && !found; q++) {
                        found = sd[q].data_off == off
                             && sd[q].kind == ((op & WE_OP_INSET_ASN) ? WE_SET_ASN : WE_SET_COUNTRY);
                        if (found && (op & WE_OP_INSET_ASN) != 0u) {
                            /* (19) the packed imm: n in 1..539, the levels and the length by the formula */
                            uint32_t n = WE_ASN_IMM_N(I->imm);

                            if (n < 1u || n > WE_LIM_ASN_MEMBERS || n != sd[q].count
                                    || WE_ASN_IMM_LEVELS(I->imm) != splus_levels(n) || sd[q].levels != splus_levels(n)
                                    || WE_ASN_IMM_HASU(I->imm) != sd[q].has_undetermined
                                    || sd[q].data_len != splus_nodes(n) * 64u) {
                                VSKIP(19, "rule %u: INSET_ASN's packed fields disagree with its set", r + 1u);
                            }
                        }
                    }
                    if (!found) {
                        VSKIP(10, "rule %u: a set payload no descriptor names", r + 1u);
                    }
                    if ((op & WE_OP_INSET_COUNTRY) != 0u && !((pl == 3u || pl == 6u) && I->off == 4u)) {
                        VSKIP(9, "rule %u: INSET_COUNTRY outside the country attributes", r + 1u);
                    }
                    if ((op & WE_OP_INSET_ASN) != 0u && !(pl == 3u && I->off == 0u)) {
                        VSKIP(9, "rule %u: INSET_ASN outside asn", r + 1u);
                    }
                }
                h++;
                ops_seen++;
            } else {
                if (I->plane != 0u || I->off != 0u || ((op & (WE_OP_JF | WE_OP_JT)) == 0u && I->imm != 0u)) {
                    VSKIP(6, "rule %u: a connective carries an operand", r + 1u);
                }
                if ((op & (WE_OP_JF | WE_OP_JT)) != 0u) {
                    /* (11) forward, inside the rule */
                    if (I->imm <= R->instr_start + k || I->imm >= (uint32_t)R->instr_start + R->instr_count) {
                        VSKIP(11, "rule %u: a jump that is not forward inside the rule", r + 1u);
                    }
                }
                if ((op & WE_OP_NOT) != 0u && h < 1u) {
                    VSKIP(12, "rule %u: the stack underflows", r + 1u);
                }
                if ((op & (WE_OP_AND | WE_OP_OR)) != 0u) {
                    if (h < 2u) {
                        VSKIP(12, "rule %u: the stack underflows", r + 1u);
                    }
                    h--;
                }
                if ((op & (WE_OP_JF | WE_OP_JT)) != 0u && h < 1u) {
                    VSKIP(12, "rule %u: a jump on an empty stack", r + 1u);
                }
            }
            /* (12) the abstract stack: heights equal at every join, at most 18, exactly 1 at END */
            if ((op & (WE_OP_JF | WE_OP_JT)) != 0u) {
                uint32_t t = I->imm - R->instr_start;

                if (height[t] != 0xffffffffu && height[t] != h) {
                    VSKIP(12, "rule %u: unequal stack heights at a join", r + 1u);
                }
                height[t] = h;
            }
            if (k + 1u < R->instr_count) {
                if (height[k + 1u] != 0xffffffffu && height[k + 1u] != h) {
                    VSKIP(12, "rule %u: unequal stack heights at a join", r + 1u);
                }
                height[k + 1u] = h;
            }
            maxh = h > maxh ? h : maxh;
            if ((op & WE_OP_END) != 0u && h != 1u) {
                VSKIP(12, "rule %u ends with stack height %u", r + 1u, h);
            }
        }
        if (maxh > WE_LIM_STACK) {
            VSKIP(12, "rule %u needs a stack of %u", r + 1u, maxh);
        }
        /* (13) dep_mask exactly the planes the rule reads */
        if (R->dep_mask != dep) {
            VSKIP(13, "rule %u's dep_mask is not the planes it reads", r + 1u);
        }
        /* (14) the counter and the source line */
        if (R->counter != r || (uint64_t)R->src_off + R->src_len > p->text_len) {
            VSKIP(14, "rule %u's counter or source line is out of range", r + 1u);
        }
        /* (16) the rule's action and flags */
        if (R->action < WE_ACT_ALLOW || R->action > WE_ACT_LOG || (R->flags & ~WE_RF_KNOWN) != 0u || R->reserved != 0u) {
            VSKIP(16, "rule %u's action or flags are outside their domain", r + 1u);
        }
        {
            uint8_t inert = 0u;

            for (k = 0u; k < NPLANES; k++) {
                inert = (uint8_t)(inert | (bind[k].inert ? (1u << k) : 0u));
            }
            if (((R->flags & WE_RF_INERT) != 0u) != ((dep & inert) != 0u)) {
                VSKIP(16, "rule %u's inert flag disagrees with the bindings", r + 1u);
            }
        }
        /* (17) no allow in a floor */
        if ((p->flags & WE_PF_FLOOR) != 0u && R->action == WE_ACT_ALLOW) {
            VSKIP(17, "an allow in a floor block");
        }
    next_rule:;
    }
#undef VSKIP
    /*
     * (3) op_count against the operations the instructions hold: every atom and connective is one,
     * and a NOT is one when it is an explicit `not` but none when it is the second half of `!=` or
     * `is not unknown`, which emit the same instruction. So the instructions bound the count from
     * both sides; the exact count is step 22's, whose re-parse recounts it from the text.
     */
    for (k = 0u; k < ni; k++) {
        uint32_t op = ins[k].op;

        ops_lo += (op & (WE_OP_ATOM | WE_OP_AND | WE_OP_OR)) != 0u;
        ops_hi += (op & (WE_OP_ATOM | WE_OP_AND | WE_OP_OR | WE_OP_NOT)) != 0u;
    }
    (void)ops_seen;
    if (p->op_count < ops_lo || p->op_count > ops_hi) {
        VNOTE(3, "op_count %u is outside the %u to %u operations the instructions hold", p->op_count, ops_lo, ops_hi);
    }
#define VJUMP(label, ...) do { vnote(err, &best, __VA_ARGS__); goto label; } while (0)
    /* (13) the header's plane_mask: the union of the rules' dep_masks, each of which the loop held to its rule */
    for (r = 0u; r < nr; r++) {
        pmask = (uint8_t)(pmask | rules[r].dep_mask);
    }
    if (p->plane_mask != pmask) {
        VNOTE(13, "plane_mask is not the union of the rules' dep_masks");
    }
    /* (15) every padding byte zero */
    if (!pad_zero(b, 64u, 64u) || p->reserved1 != 0u || p->reserved0[0] != 0u || p->reserved0[1] != 0u
            || p->reserved0[2] != 0u || !pad_zero(b, p->rules_off + 16u * nr, p->instrs_off)
            || !pad_zero(b, p->instrs_off + 8u * ni, p->bindings_off) || !pad_zero(b, p->sets_off + 16u * ns, p->hh_off)
            || !pad_zero(b, p->text_off + p->text_len, p->total_len)) {
        VNOTE(15, "a padding byte is not zero");
    }
    for (k = 0u; k < ns; k++) {
        if (sd[k].reserved != 0u) {
            VNOTE(15, "a set descriptor's reserved byte is not zero");
            break;
        }
    }
    /* (16) the header flags */
    if ((p->flags & ~WE_PF_KNOWN) != 0u) {
        VNOTE(16, "a header flag outside floor and legacy");
    }
    /* (18) bindings equal, field by field, to the compiled-in table; routing's template rov exactly 4 */
    for (k = 0u; k < NPLANES; k++) {
        we_binding_t want;

        binding_of(k, &want);
        want.inert = bind[k].inert;
        if (bind[k].inert > 1u || memcmp(&want, &bind[k], sizeof want) != 0) {
            VNOTE(18, "binding %u is not FORMAT.md's", k + 1u);
            break;
        }
    }
    if (bind[3].tmpl[6] != 4u) {
        VNOTE(18, "routing's template rov is not 4");
    }
    /* (10) and (19): the set descriptors tile the set data, payloads well formed */
    {
        uint32_t at = p->setdata_off;

        for (k = 0u; k < ns; k++) {
            const we_setdesc_t *s = &sd[k];

            if (s->data_off != at || (s->data_off & 63u) != 0u || (uint64_t)s->data_off + s->data_len > p->hot_len) {
                VJUMP(sets_done, 10, "set %u's payload is misplaced", k + 1u);
            }
            if (s->kind == WE_SET_COUNTRY) {
                if (s->data_len != 128u || s->levels != 0u || s->has_undetermined > 1u
                        || ((b[s->data_off] & 1u) != 0u) != (s->has_undetermined != 0u)
                        || !pad_zero(b, s->data_off + 125u, s->data_off + 128u)) {
                    VJUMP(sets_done, 10, "set %u's country bitmap is not 125 bytes in 128", k + 1u);
                }
            } else if (s->kind == WE_SET_ASN) {
                uint32_t n = s->count, j;
                const uint8_t *pay = b + s->data_off;
                uint32_t prev = 0u;
                uint8_t *rebuilt;

                if (n < 1u || n > WE_LIM_ASN_MEMBERS || s->levels != splus_levels(n)
                        || s->data_len != splus_nodes(n) * 64u || s->has_undetermined > 1u) {
                    VJUMP(sets_done, 19, "set %u's ASN tree has the wrong shape", k + 1u);
                }
                /* the leaves: strictly increasing, padding at the maximum */
                {
                    uint32_t m0 = (n + 15u) / 16u, lv = splus_levels(n), m1 = (m0 + 16u) / 17u;
                    uint32_t leaf_off = (lv >= 2u ? 64u : 0u) + (lv >= 3u ? m1 * 64u : 0u);
                    uint32_t keys[WE_LIM_ASN_MEMBERS];

                    for (j = 0u; j < m0 * 16u; j++) {
                        uint32_t v;

                        memcpy(&v, pay + leaf_off + j * 4u, 4);
                        if (j < n) {
                            if ((j > 0u && v <= prev) || v == 0xffffffffu) {
                                VJUMP(sets_done, 10, "set %u's keys are not strictly increasing", k + 1u);
                            }
                            prev = v;
                            keys[j] = v;
                        } else if (v != 0xffffffffu) {
                            VJUMP(sets_done, 10, "set %u's padding is not the maximum key", k + 1u);
                        }
                    }
                    rebuilt = (uint8_t *)malloc(s->data_len);
                    if (rebuilt == NULL) {
                        VJUMP(sets_done, 10, "out of memory");
                    }
                    splus_build(keys, n, rebuilt);
                    j = memcmp(rebuilt, pay, s->data_len) != 0;
                    free(rebuilt);
                    if (j) {
                        VJUMP(sets_done, 10, "set %u's separators are not the S+ tree's", k + 1u);
                    }
                }
            } else {
                VJUMP(sets_done, 10, "set %u has an unknown kind", k + 1u);
            }
            at += s->data_len;
        }
        if (at != p->hot_len) {
            VJUMP(sets_done, 21, "hot_len is not the end of the set data");
        }
    }
sets_done:;
    /* (20) the hold-harmless arrays, by the loader's own family checks */
    hh_end = p->hh_off;
    if ((p->flags & WE_PF_FLOOR) != 0u) {
        we_hh_hdr_t h;
        int fam;

        if ((uint64_t)p->hh_off + 64u > p->setdata_off) {
            VJUMP(hh_done, 20, "the hold-harmless header does not fit");
        }
        memcpy(&h, b + p->hh_off, sizeof h);
        if (!pad_zero(h.reserved, 0u, sizeof h.reserved) || h.v4_span != 16u || h.v6_span != 4u) {
            VJUMP(hh_done, 20, "a hold-harmless span other than 16 and 4");
        }
        for (fam = 0; fam < 2; fam++) {
            uint32_t n = fam == 0 ? h.v4_n : h.v6_n, kb = fam == 0 ? 4u : 16u, s = fam == 0 ? 16u : 4u;
            uint32_t so = fam == 0 ? h.v4_start_off : h.v6_start_off, eo = fam == 0 ? h.v4_end_off : h.v6_end_off;
            uint32_t to = fam == 0 ? h.v4_tree_off : h.v6_tree_off, m = fam == 0 ? h.v4_m : h.v6_m;
            uint32_t dpt = fam == 0 ? h.v4_depth : h.v6_depth, nodes, j;
            __uint128_t prev_end = 0u;

            if (n == 0u) {
                continue;
            }
            if (m != (n + s - 1u) / s || dpt != rank_depth_of(m, 64u / kb + 1u)) {
                VJUMP(hh_done, 20, "a hold-harmless depth or window count is not the formula's");
            }
            nodes = hh_nodes(kb, dpt);
            if ((so & 63u) || (eo & 63u) || (to & 63u) || so < p->hh_off + 64u
                    || (uint64_t)so + (uint64_t)kb * n > eo || (uint64_t)eo + (uint64_t)kb * n > p->setdata_off
                    || (nodes > 0u && ((uint64_t)to + nodes * 64u > p->setdata_off || to < eo + (uint64_t)kb * n))
                    || (nodes == 0u && to != 0u)) {
                VJUMP(hh_done, 20, "a hold-harmless array is misplaced or unaligned");
            }
            for (j = 0u; j < n; j++) {
                __uint128_t st = hh_key(b + so, kb, j), en = hh_key(b + eo, kb, j);

                if (en < st || (j > 0u && st <= prev_end)) {
                    VJUMP(hh_done, 20, "hold-harmless ranges are not sorted and disjoint");
                }
                prev_end = en;
            }
            if (nodes > 0u) {
                uint8_t *rb = (uint8_t *)malloc((size_t)nodes * 64u);

                if (rb == NULL) {
                    VJUMP(hh_done, 20, "out of memory");
                }
                hh_tree(b + so, kb, m, s, dpt, rb);
                j = memcmp(rb, b + to, (size_t)nodes * 64u) != 0;
                free(rb);
                if (j) {
                    VJUMP(hh_done, 20, "a hold-harmless sample is not start[j * stride]");
                }
                hh_end = to + nodes * 64u;
            } else {
                hh_end = eo + al64(kb * n);
            }
        }
        if (hh_end != p->setdata_off) {
            VJUMP(hh_done, 20, "the hold-harmless region does not end at the set data");
        }
    } else if (p->hh_off != p->setdata_off) {
        VJUMP(hh_done, 20, "a hold-harmless region in a block that is not a floor");
    }
hh_done:;
    /* (21) hot_len, under the limit */
    if (p->hot_len > WE_LIM_HOT_BYTES) {
        VNOTE(21, "hot_len %u is over the limit", p->hot_len);
    }
    if (best != 0) {
        return -best;
    }
#undef VNOTE
#undef VJUMP
    /* (22) re-parse to byte identity, exempt from the argument-length check */
    {
        we_program_t *q = NULL;
        uint8_t present = 0u;
        int rc, same;

        for (k = 0u; k < NPLANES; k++) {
            present = (uint8_t)(present | (bind[k].inert ? 0u : (1u << k)));
        }
        we_policy_error_t re;

        memset(&re, 0, sizeof re);
        rc = compile_text((const char *)b + p->text_off, p->text_len, (p->flags & WE_PF_FLOOR) != 0u,
                          (p->flags & WE_PF_LEGACY) != 0u, present, NULL, 1, &q, &re);
        if (rc != WE_POLICY_OK) {
            return vfail(err, 22, "the canonical text does not compile: %s, line %u column %u near \"%s\": %s",
                         re.layer != NULL ? re.layer : "memory", re.line, re.col, re.token, re.what);
        }
        same = q->total_len == p->total_len && memcmp(q, p, p->total_len) == 0;
        free(q);
        if (!same) {
            return vfail(err, 22, "the canonical text does not re-parse to this block");
        }
    }
    return 0;
}

/* the cold text's rule part: every rule's line, LF-terminated, in order; the declarations follow it */
static uint32_t rules_text_len(const we_program_t *p)
{
    const we_rule_t *rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    const we_rule_t *last;

    if (p->rule_count == 0u) {
        return 0u;
    }
    last = &rules[p->rule_count - 1u];
    return last->src_off + last->src_len + 1u;
}

static int print_part(const we_program_t *p, uint32_t off, uint32_t len, char *buf, size_t n)
{
    if (buf == NULL || n < (size_t)len + 1u || off + len > p->text_len) {
        return -1;
    }
    memcpy(buf, (const uint8_t *)p + p->text_off + off, len);
    buf[len] = '\0';
    return (int)len;
}

int we_program_print(const we_program_t *p, char *buf, size_t n)
{
    return p == NULL ? -1 : print_part(p, 0u, rules_text_len(p), buf, n);
}

int we_program_print_sets(const we_program_t *p, char *buf, size_t n)
{
    uint32_t r;

    if (p == NULL) {
        return -1;
    }
    r = rules_text_len(p);
    return print_part(p, r, p->text_len - r, buf, n);
}

int we_program_disasm(const we_program_t *p, char *buf, size_t n)
{
    static const char *const names[15] = { "BOOL", "SEV", "EQ8", "EQ16", "EQ32", "INSET_ENUM", "INSET_COUNTRY",
                                           "INSET_ASN", "ISUNK", "NOT", "AND", "OR", "JF", "JT", "END" };
    const we_rule_t *rules;
    const we_instr_t *ins;
    size_t o = 0u;
    uint32_t r, k;

    if (p == NULL || buf == NULL || n == 0u) {
        return -1;
    }
    rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
    buf[0] = '\0';
    for (r = 0u; r < p->rule_count && o < n; r++) {
        o += (size_t)snprintf(buf + o, n - o, "rule %u %s dep 0x%02x%s: %.*s\n", r + 1u,
                              rules[r].action == WE_ACT_ALLOW ? "allow" : rules[r].action == WE_ACT_DENY ? "deny" : "log",
                              rules[r].dep_mask, (rules[r].flags & WE_RF_INERT) ? " inert" : "", (int)rules[r].src_len,
                              (const char *)p + p->text_off + rules[r].src_off);
        for (k = 0u; k < rules[r].instr_count && o < n; k++) {
            const we_instr_t *I = &ins[rules[r].instr_start + k];
            uint32_t bit = 0u;

            while (bit < 15u && (I->op >> bit) != 1u) {
                bit++;
            }
            o += (size_t)snprintf(buf + o, n - o, "  %4u %-13s plane %u off %2u imm 0x%08x\n",
                                  rules[r].instr_start + k, bit < 15u ? names[bit] : "?", I->plane + 1u, I->off, I->imm);
        }
    }
    return o < n ? (int)o : -1;
}

/* ======================================================================================================
 * The hold-harmless view
 * ==================================================================================================== */

int we_program_env_matches(const we_program_t *p, const we_policy_env_t *env)
{
    const we_binding_t *bind;
    uint32_t k, legacy;

    if (p == NULL || env == NULL) {
        return -1;
    }
    legacy = env->legacy != 0u;
    if (((p->flags & WE_PF_LEGACY) != 0u) != legacy) {
        return -1;
    }
    bind = (const we_binding_t *)(const void *)((const uint8_t *)p + p->bindings_off);
    for (k = 0u; k < NPLANES; k++) {
        uint32_t inert = !legacy && ((env->present >> k) & 1u) == 0u;

        if (bind[k].inert != inert) {
            return -1;
        }
    }
    return 0;
}

int we_program_place(const we_program_t *floor, we_hh_view_t *hh)
{
    const uint8_t *b = (const uint8_t *)floor;
    we_hh_hdr_t h;
    int fam;

    if (floor == NULL || hh == NULL || ((uintptr_t)hh & 63u) != 0u || (floor->flags & WE_PF_FLOOR) == 0u) {
        return -1;
    }
    memset(hh, 0, sizeof *hh);
    memcpy(&h, b + floor->hh_off, sizeof h);
    for (fam = 0; fam < 2; fam++) {
        we_fam_t *f = fam == 0 ? &hh->map.f4 : &hh->map.f6;
        uint32_t kb = fam == 0 ? 4u : 16u;
        uint32_t n = fam == 0 ? h.v4_n : h.v6_n;
        uint32_t so = fam == 0 ? h.v4_start_off : h.v6_start_off;
        uint32_t eo = fam == 0 ? h.v4_end_off : h.v6_end_off;
        uint32_t to = fam == 0 ? h.v4_tree_off : h.v6_tree_off;
        uint32_t span = fam == 0 ? h.v4_span : h.v6_span;

        f->kind = WE_KIND_RANK;
        f->key_bits = (uint8_t)(kb * 8u);
        f->file_kind = WE_KIND_RANK;
        if (n == 0u) {
            continue;
        }
        f->n = n;
        f->start = b + so;
        f->end = b + eo;
        f->records = NULL;
        f->sev = NULL;
        f->idx = NULL;
        f->stride = kb;
        f->first = hh_key(b + so, kb, 0u);
        f->m = fam == 0 ? h.v4_m : h.v6_m;
        f->depth = fam == 0 ? h.v4_depth : h.v6_depth;
        f->nodes = hh_nodes(kb, f->depth);
        f->stree = f->nodes > 0u ? b + to : NULL;
        f->span = span;
        f->sshift = (uint8_t)(span == 16u ? 4u : 2u);
        f->file_param = f->sshift;
    }
    hh->map.f6w.kind = WE_KIND_RANK;
    hh->map.f6w.key_bits = 64u;
    hh->map.generation = 1u;
    hh->map.format = WE_FORMAT_2;
    hh->bindings = (const we_binding_t *)(const void *)(b + floor->bindings_off);
    hh->floor = floor;
    return 0;
}

/* ======================================================================================================
 * The environment probe (POLICY.md §2.4): the header and the tail, the owner and the mode, nothing else
 * ==================================================================================================== */

int we_policy_env_probe(const char *dir, we_policy_env_t *env)
{
    uint32_t p;

    if (dir == NULL || env == NULL) {
        return -1;
    }
    memset(env, 0, sizeof *env);
    for (p = 0u; p < NPLANES; p++) {
        char path[1024];
        struct stat st;
        we_header_t h;
        int fd, ok;
        ssize_t got;
        const char *why = "cannot open";

        if (snprintf(path, sizeof path, "%s/%s.bin", dir, plane_name[p]) >= (int)sizeof path) {
            continue;
        }
        /*
         * A FIFO, a device or a directory at a plane path is never opened, so it cannot block the probe:
         * it is present, and its schema is not ok. Absent and unreadable stay absent, as before.
         */
        fd = we_open_regular(path, &why);
        if (fd < 0 && strcmp(why, "cannot open") == 0) {
            continue;                       /* absent */
        }
        ok = fd >= 0 && fstat(fd, &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
        got = ok ? read(fd, &h, sizeof h) : -1;
        if (fd >= 0) {
            close(fd);
        }
        ok = ok && got == (ssize_t)sizeof h && h.magic == WE_MAGIC && (h.format == WE_FORMAT_1 || h.format == WE_FORMAT_2);
        if (ok && (h.flags & WE_H_SCHEMA) != 0u) {
            uint32_t want = p == 0u ? WE_SCHEMA_FORMAT1 : (p == 3u || p == 6u) ? WE_SCHEMA_ROUTING : WE_SCHEMA_MEMBERSHIP;

            ok = h.schema.plane_id == p + 1u && h.schema.schema_id == want;
        } else if (ok) {
            ok = p == 0u && h.format == WE_FORMAT_1;   /* a pre-schema file is the reputation plane */
        }
        env->present = (uint8_t)(env->present | (1u << p));
        if (ok) {
            env->schema_ok = (uint8_t)(env->schema_ok | (1u << p));
        }
    }
    return 0;
}

/* ======================================================================================================
 * The attributes and the verdict, for tools: cold, and in no function the request path calls
 * ==================================================================================================== */

uint32_t we_attr_count(void)
{
    return (uint32_t)NATTRS;
}

int we_attr_info(uint32_t i, we_attr_info_t *out)
{
    static const uint8_t cls_of[6] = { 0u, WE_ATTR_BOOL, WE_ATTR_LEVEL, WE_ATTR_ENUM, WE_ATTR_ASN, WE_ATTR_COUNTRY };

    if (i >= NATTRS || out == NULL) {
        return -1;
    }
    out->name = attrs[i].name;
    out->plane = plane_name[attrs[i].plane];
    out->plane_id = (uint8_t)(attrs[i].plane + 1u);
    out->cls = cls_of[attrs[i].cls <= 5u ? attrs[i].cls : 0u];
    out->off = attrs[i].off;
    out->mask = attrs[i].mask;
    out->sentinel = attrs[i].sentinel;
    return 0;
}

int we_attr_render(uint32_t i, const uint8_t block[16], uint32_t state, char *buf, size_t n)
{
    const attr_t *t;
    const uint8_t *b;
    char a2[3];

    if (i >= NATTRS || block == NULL || buf == NULL) {
        return -1;
    }
    t = &attrs[i];
    if (state == WE_ST_NONE) {
        return snprintf(buf, n, "unread");
    }
    if (state == WE_ST_REVOKED) {
        return snprintf(buf, n, "revoked");
    }
    if (state == WE_ST_UNKNOWN || ((state == WE_ST_STALE_HIT || state == WE_ST_STALE_NR) && t->plane != 7u)) {
        return snprintf(buf, n, "unknown");
    }
    if (state == WE_ST_STALE_HIT || state == WE_ST_STALE_NR) {
        /* the tenant's stale record: within its 48-hour grace `stale:`, past it (the entry's lapsed
         * byte, block[14]) `lapsed:` (POLICY.md section 3.9) */
        b = block + t->off;
        return snprintf(buf, n, "%s:%s", block[14] != 0u ? "lapsed" : "stale", (b[0] & t->mask) != 0u ? "true" : "false");
    }
    b = block + (t->off & 15u);
    switch (t->cls) {
    case AC_BOOL:
        return snprintf(buf, n, "%s", (b[0] & t->mask) != 0u ? "true" : "false");
    case AC_LEVEL:
        return snprintf(buf, n, "%s", level_name[(b[0] & 0x0fu) <= 4u ? (b[0] & 0x0fu) : 4u]);
    case AC_ENUM:
        return snprintf(buf, n, "%s", enum_name(t->dom, b[0]));
    case AC_ASN: {
        uint32_t a;

        memcpy(&a, b, 4);
        return a == 0xffffffffu ? snprintf(buf, n, "undetermined") : snprintf(buf, n, "%" PRIu32, a);
    }
    default: {
        uint16_t c;

        memcpy(&c, b, 2);
        if (c == 0u) {
            return snprintf(buf, n, "undetermined");
        }
        country_alpha2(c, a2);
        /* a code the compiled table does not know reads `undetermined` (POLICY.md section 3.9), as the
         * fill's clamp already makes it on the request path; a tool rendering a raw block agrees */
        return a2[0] == '?' ? snprintf(buf, n, "undetermined") : snprintf(buf, n, "%s", a2);
    }
    }
}

/* the fired rules of one program's bitmap, 1-based, comma-separated; `-` for none */
static size_t fired_list(const uint8_t b[32], char *out, size_t n, int *trunc)
{
    uint32_t r;
    size_t o = 0u;

    out[0] = '\0';
    for (r = 0u; r < 256u; r++) {
        if ((b[r >> 3] >> (r & 7u)) & 1u) {
            int w = snprintf(out + o, n - o, "%s%u", o == 0u ? "" : ",", r + 1u);

            if (w < 0 || (size_t)w >= n - o) {
                *trunc = 1;
                return o;
            }
            o += (size_t)w;
        }
    }
    if (o == 0u) {
        snprintf(out, n, "-");
        o = 1u;
    }
    return o;
}

int we_verdict_format(const we_verdict_t *v, char *verdict_line, char *cost_line, size_t n)
{
    static const char *const step[6] = { "?", "1", "2", "3", "3.5", "4" };
    char why[96], lf[1100], lc[1100];
    int trunc = 0, w;

    if (v == NULL || verdict_line == NULL || cost_line == NULL || n == 0u) {
        return -1;
    }
    switch (v->reason) {
    case WE_WHY_ALLOW_BY_UNKNOWN:
        snprintf(why, sizeof why, "allow-by-unknown:%s", v->unknown_plane >= 1u && v->unknown_plane <= 8u
                 ? plane_name[v->unknown_plane - 1u] : "-");
        break;
    case WE_WHY_HOLD_HARMLESS: snprintf(why, sizeof why, "allow-by-hold-harmless"); break;
    case WE_WHY_ACME:          snprintf(why, sizeof why, "allow-by-acme"); break;
    case WE_WHY_TENANT:        snprintf(why, sizeof why, "allow-by-tenant"); break;
    case WE_WHY_NO_ADDRESS:    snprintf(why, sizeof why, "allow-by-no-address"); break;
    default:                   why[0] = '\0'; break;
    }
    if ((v->marks & WE_MARK_TENANT_REVOKED) != 0u) {
        size_t l = strlen(why);

        snprintf(why + l, sizeof why - l, "%stenant-revoked", l != 0u ? "," : "");
    }
    if (why[0] == '\0') {
        snprintf(why, sizeof why, "-");
    }
    fired_list(v->log_fired[0], lf, sizeof lf, &trunc);
    fired_list(v->log_fired[1], lc, sizeof lc, &trunc);
    w = snprintf(verdict_line, n, "verdict step=%s action=%s program=%s rule=%u reason=%s log_floor=%s log_ctx=%s",
                 step[v->step <= 5u ? v->step : 0u], v->action == WE_ACT_DENY ? "deny" : "allow",
                 v->program == WE_VPROG_FLOOR ? "floor" : v->program == WE_VPROG_CONTEXT ? "ctx" : "-",
                 (unsigned)v->rule, why, lf, lc);
    trunc |= w < 0 || (size_t)w >= n;
#ifdef WE_TRACE
    w = snprintf(cost_line, n, "cost ops=%u/%u jumps=%u/%u probes=%u/%u lookups=%u,%u,%u,%u,%u,%u,%u,%u/%u,%u,%u,%u,%u,%u,%u,%u",
                 (unsigned)v->ops_floor, (unsigned)v->ops_ctx, (unsigned)v->jumps[0], (unsigned)v->jumps[1],
                 (unsigned)v->probes[0], (unsigned)v->probes[1],
                 (unsigned)v->lookups[0][0], (unsigned)v->lookups[0][1], (unsigned)v->lookups[0][2],
                 (unsigned)v->lookups[0][3], (unsigned)v->lookups[0][4], (unsigned)v->lookups[0][5],
                 (unsigned)v->lookups[0][6], (unsigned)v->lookups[0][7], (unsigned)v->lookups[1][0],
                 (unsigned)v->lookups[1][1], (unsigned)v->lookups[1][2], (unsigned)v->lookups[1][3],
                 (unsigned)v->lookups[1][4], (unsigned)v->lookups[1][5], (unsigned)v->lookups[1][6],
                 (unsigned)v->lookups[1][7]);
#else
    /* the counts are kept in a WE_TRACE build only (the request path counts nothing) */
    w = snprintf(cost_line, n, "cost untraced");
#endif
    trunc |= w < 0 || (size_t)w >= n;
    return trunc ? -1 : 0;
}

/* ======================================================================================================
 * Per-rule counters, sharded per thread (POLICY.md §3.6)
 * ==================================================================================================== */

we_rule_counters_t *we_rule_counters_new(const we_program_t *p, uint32_t shards, uint64_t now_ms)
{
    we_rule_counters_t *c;
    uint8_t dg[32];
    size_t bytes;

    if (p == NULL || shards == 0u || shards > 65536u) {
        return NULL;
    }
    c = (we_rule_counters_t *)aligned_alloc(64, 64);
    if (c == NULL) {
        return NULL;
    }
    memset(c, 0, sizeof *c);
    c->shards = shards;
    c->rule_count = p->rule_count;
    c->stride = (p->rule_count + 7u) & ~7u;
    if (c->stride == 0u) {
        c->stride = 8u;
    }
    bytes = (size_t)shards * c->stride * sizeof(uint64_t);
    c->hits = (uint64_t *)aligned_alloc(64, bytes);
    if (c->hits == NULL) {
        free(c);
        return NULL;
    }
    memset(c->hits, 0, bytes);
    c->started_ms = now_ms;
    we_sha256(p, p->total_len, dg);
    memcpy(&c->generation, dg, 8);
    return c;
}

void we_rule_counters_free(we_rule_counters_t *c)
{
    if (c == NULL) {
        return;
    }
    free(c->hits);
    free(c);
}

uint64_t we_rule_counters_sum(const we_rule_counters_t *c, uint32_t rule)
{
    uint64_t s = 0u;
    uint32_t k;

    if (c == NULL || rule == 0u || rule > c->rule_count) {
        return 0u;
    }
    for (k = 0u; k < c->shards; k++) {
        s += __atomic_load_n(&c->hits[(size_t)k * c->stride + rule - 1u], __ATOMIC_RELAXED);
    }
    return s;
}

int we_rule_counters_write(const we_rule_counters_t *c, const we_program_t *p, const char *dir, uint64_t now_ms)
{
    char tmp[96], fin[64];
    FILE *f;
    uint32_t r;
    const we_rule_t *rules;
    int dfd, fd;
    we_procid_t id;
    struct stat st;

    if (c == NULL || p == NULL || dir == NULL || c->rule_count != p->rule_count) {
        return WE_ERR_OPEN;
    }
    /* never through a planted name (we_procid.h): an O_EXCL | O_NOFOLLOW temp, renamed into place, and as
     * root only into a directory root owns and nobody else may write */
    if (we_proc_id(&id) != 0 || (dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
        return WE_ERR_OPEN;
    }
    if (geteuid() == 0u && (fstat(dfd, &st) != 0 || st.st_uid != 0u || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0u)) {
        close(dfd);
        return WE_ERR_PERMISSIONS;
    }
    /* named by the process, pid and identity, so a reused pid never overwrites a gone writer's file */
    snprintf(fin, sizeof fin, "%llu-%s.rules.cnt", (unsigned long long)id.pid, id.id16);
    fd = we_proc_tmp_open(dfd, &id, "rules", tmp);
    f = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (f == NULL) {
        if (fd >= 0) {
            close(fd);
            unlinkat(dfd, tmp, 0);
        }
        close(dfd);
        return WE_ERR_OPEN;
    }
    rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    fprintf(f, "whisper-edge-rule-counters 1\n");
    fprintf(f, "started %" PRIu64 "\n", c->started_ms);
    fprintf(f, "written %" PRIu64 "\n", now_ms);
    fprintf(f, "program %016" PRIx64 "\n", c->generation);
    for (r = 0u; r < c->rule_count; r++) {
        uint64_t h = we_rule_counters_sum(c, r + 1u);

        if (h == 0u) {
            continue;
        }
        fprintf(f, "r %u %" PRIu64 " %.*s\n", r + 1u, h, (int)rules[r].src_len,
                (const char *)p + p->text_off + rules[r].src_off);
    }
    if (fflush(f) != 0 || ferror(f) != 0) {
        fclose(f);
        unlinkat(dfd, tmp, 0);
        close(dfd);
        return WE_ERR_OPEN;
    }
    if (fclose(f) != 0 || renameat(dfd, tmp, dfd, fin) != 0) {
        unlinkat(dfd, tmp, 0);
        close(dfd);
        return WE_ERR_OPEN;
    }
    close(dfd);
    return WE_OK;
}
