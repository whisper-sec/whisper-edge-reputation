/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * eval_programs.h - the policy programs the gate measures and the bench prints, written once.
 *
 * TEST SUPPORT for gate/cg_driver.c and bench_core.c, never linked into a module. Programs are built as
 * corpus records (testdata/policy/README.md): <kind> SP <context> SP <argument> 0x1E 0x0A, the floor
 * and sets at `http`, a context's rules at `http/server:s`. The atom table gives every atom kind a TRUE
 * and a FALSE form in the evaluator's synthetic world (gate/cg_driver.c, ev_build), so a program can be
 * arranged to take no jump; the worst-case shape is the one line of gate/evaluator-worst.tsv.
 */
#ifndef WE_EVAL_PROGRAMS_H
#define WE_EVAL_PROGRAMS_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the corpus record format (testdata/policy/README.md): <kind> SP <context> SP <argument> 0x1E 0x0A */
#define RS "\x1e\n"
#define FL "floor http "
#define PO "policy http/server:s "

typedef struct { char *p; size_t n, cap; } sb_t;

static inline void sb_add(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static inline void sb_add(sb_t *b, const char *fmt, ...)
{
    va_list ap;
    int need;

    for (;;) {
        va_start(ap, fmt);
        need = vsnprintf(b->p == NULL ? NULL : b->p + b->n, b->p == NULL ? 0 : b->cap - b->n, fmt, ap);
        va_end(ap);
        if (need < 0) { fprintf(stderr, "sb_add: format failed\n"); exit(2); }
        if (b->p != NULL && b->n + (size_t)need < b->cap) { b->n += (size_t)need; return; }
        b->cap = (b->cap + (size_t)need + 1u) * 2u;
        b->p = realloc(b->p, b->cap);
        if (b->p == NULL) { fprintf(stderr, "out of memory\n"); exit(2); }
        if (b->n == 0u) { b->p[0] = '\0'; }
    }
}

/* the atom of each kind, TRUE and FALSE in the worlds, the plane it reads, and its fill's schema */
typedef struct { const char *kind, *t, *f, *plane, *schema; int negatable; } ev_atom_t;
static const ev_atom_t ev_atoms[] = {
    { "BOOL",          "c2",                         "phishing",                   "threat",     "membership", 0 },
    { "SEV",           "listed >= low",              "listed >= critical",         "reputation", "format1",    0 },
    { "EQ8",           "rpki == valid",              "rpki == invalid",            "routing",    "routing",    1 },
    { "EQ16",          "country == NL",              "country == DE",              "routing",    "routing",    1 },
    { "EQ32",          "asn == 500",                 "asn == 501",                 "routing",    "routing",    1 },
    { "INSET_ENUM",    "rpki in { valid not-found }", "rpki in { invalid unrouted }", "routing", "routing",    0 },
    { "INSET_COUNTRY", "country in { NL BE }",       "country in { DE FR }",       "routing",    "routing",    0 },
    { "INSET_ASN",     "asn in @t",                  "asn in @f",                  "routing",    "routing",    0 },
    { "ISUNK",         "proxy is unknown",           "tor_exit is unknown",        "anonymizer", "-",          1 },
};
#define EV_NATOMS (sizeof ev_atoms / sizeof ev_atoms[0])

/* the one-op negated form of a negatable atom: `==` becomes `!=`, `is unknown` becomes `is not unknown` */
static inline void ev_negated(sb_t *b, const char *atom)
{
    const char *q = strstr(atom, "==");
    if (q != NULL) { sb_add(b, "%.*s!=%s", (int)(q - atom), atom, q + 2); return; }
    q = strstr(atom, "is unknown");
    if (q != NULL) { sb_add(b, "%.*sis not unknown", (int)(q - atom), atom); return; }
    fprintf(stderr, "ev_negated: %s has no negated form\n", atom);
    exit(2);
}

/* the two 3-level ASN sets: @t holds AS500 (the worlds' origin), @f is the same range without it */
static inline void ev_sets(sb_t *b)
{
    uint32_t a;
    sb_add(b, "set http @t");
    for (a = 0; a < 538u; a++) { sb_add(b, " %u", a); }
    sb_add(b, RS "set http @f");
    for (a = 0; a < 538u; a++) { if (a != 500u) { sb_add(b, " %u", a); } }
    sb_add(b, RS);
}

/*
 * The worst-case fixture's shape, from gate/evaluator-worst.tsv: kind, rules, atoms, unary nots, negated,
 * link, and `flip`: which operands receive the nots first. An operand's ATOM outcome is its value in
 * the chain with the parity of its nots undone, and the cost model prices a TRUE atom and a FALSE atom
 * of a kind separately, so where the nots go decides how many atoms run each way. `flip` names the
 * class of operand, by the value the chain needs from it (T or F), whose flip the maximum wants.
 */
typedef struct { const ev_atom_t *atom; uint32_t rules, atoms, nots, negated; int is_or; int flip_true; } ev_shape_t;

/* what one built program executes per request, by outcome */
typedef struct { uint32_t t, f, nots, rules, or_links; } ev_counts_t;

/* the row this build measures: the maximum is per toolchain, so the fixture is too */
#if defined(__aarch64__)
#define EV_ARCH "aarch64"
#elif defined(__x86_64__)
#define EV_ARCH "x86_64"
#else
#define EV_ARCH "other"
#endif
#if defined(__clang__)
#define EV_CC "clang"
#else
#define EV_CC "gcc"
#endif

static inline ev_shape_t ev_worst_shape(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256], arch[16], cc[16], kind[32], link[8], flip[4];
    ev_shape_t s;
    uint32_t i;
    int found = 0;

    memset(&s, 0, sizeof s);
    if (f == NULL) { perror(path); exit(2); }
    while (fgets(line, sizeof line, f) != NULL) {
        if (line[0] == '#' || line[0] == '\n') { continue; }
        if (sscanf(line, "%15s %15s %31s %u %u %u %u %7s %3s", arch, cc, kind, &s.rules, &s.atoms, &s.nots, &s.negated,
                   link, flip) != 9) {
            fprintf(stderr, "%s: a row is arch compiler kind rules atoms unary_not negated link flip\n", path);
            exit(2);
        }
        if (strcmp(arch, EV_ARCH) != 0 || strcmp(cc, EV_CC) != 0) { continue; }
        found = 1;
        for (i = 0; i < EV_NATOMS; i++) { if (!strcmp(ev_atoms[i].kind, kind)) { s.atom = &ev_atoms[i]; } }
        s.is_or = !strcmp(link, "or");
        s.flip_true = !strcmp(flip, "T");
        if (strcmp(link, "or") != 0 && strcmp(link, "and") != 0) { s.atom = NULL; }
        if (strcmp(flip, "T") != 0 && strcmp(flip, "F") != 0) { s.atom = NULL; }
        break;
    }
    fclose(f);
    if (!found) {
        fprintf(stderr, "%s has no row for %s %s: the gate prints the shape to add\n", path, EV_ARCH, EV_CC);
        exit(2);
    }
    if (s.atom == NULL || s.rules == 0u || s.atoms < s.rules || (s.negated != 0u && !s.atom->negatable)) {
        fprintf(stderr, "%s: the shape is not a program\n", path);
        exit(2);
    }
    return s;
}

/*
 * One program of the worst shape: R rules, the atoms, nots and negated forms spread as evenly as the
 * counts allow, every rule a `deny` that does not fire and takes no jump (an and-chain is TRUE until its
 * last operand, which is FALSE; an or-chain is FALSE throughout). Nots go first, one each, to the
 * operands of the class `flip` names, then in pairs (parity kept) on the first operand, at most 16 on
 * one operand; a negated form (`!=`, `is not unknown`) flips the next operand of that class not yet
 * flipped. Each operand's atom is written TRUE or FALSE so the nots land it on the value the chain
 * needs. With `first8` the first rule is instead the eight-plane rule of evaluator-worst-lines. The
 * counts it executes per request are added to *c (the eight-plane rule's are added by the caller).
 */
static inline void ev_worst_program(sb_t *b, const char *kind, ev_shape_t s, int first8, ev_counts_t *c)
{
    uint32_t r, i;
    uint32_t a_left = s.atoms, u_left = s.nots, e_left = s.negated;

    for (r = 0; r < s.rules; r++) {
        uint32_t rules_left = s.rules - r, a = a_left / rules_left + (a_left % rules_left != 0u);
        uint32_t u = u_left / rules_left + (u_left % rules_left != 0u), e = e_left / rules_left + (e_left % rules_left != 0u);
        uint32_t nn[64], ng[64];

        if (a > a_left) { a = a_left; }
        if (u > u_left) { u = u_left; }
        if (e > e_left) { e = e_left; }
        a_left -= a; u_left -= u; e_left -= e;
        if (r == 0u && first8) {
            /*
             * Eight atoms on eight planes, seven `and`s and ONE `not`: 16 operations, the and-shape's own
             * count, so the context stays at 4,096 operations. It once spent two `not`s (17 operations,
             * a context of 4,097, which the compiler refuses), because only five of the eight planes
             * hold a TRUE operand natively. The world now flags its rpki-unreachable record, so seven
             * operands are TRUE with one `not` (on tenant_deny, which must stay FALSE: a TRUE one ends
             * the request at the tenant step) and tor_exit, FALSE, is last, so no jump is taken.
             */
            sb_add(b, "%s deny if listed >= low and c2 and rpki == valid and registry_rir == ripe "
                      "and rpki_unreachable and proxy and not tenant_deny and tor_exit" RS, kind);
            continue;
        }
        if (a > 64u) { fprintf(stderr, "ev_worst_program: %u atoms in one rule\n", a); exit(2); }
        /* the value the chain needs from each operand, and where its nots and negated form go */
        memset(nn, 0, sizeof nn);
        memset(ng, 0, sizeof ng);
        for (i = 0; i < a && u > 0u; i++) {
            int need = s.is_or ? 0 : (i + 1u < a);
            if (need == s.flip_true) { nn[i] = 1; u--; }
        }
        for (i = 0; i < a && e > 0u; i++) {
            int need = s.is_or ? 0 : (i + 1u < a);
            if (need == s.flip_true && nn[i] == 0u) { ng[i] = 1; e--; }
        }
        for (i = 0; i < a && e > 0u; i++) { if (ng[i] == 0u && nn[i] == 0u) { ng[i] = 1; e--; } }
        for (i = 0; i < a && u >= 2u; i++) { while (u >= 2u && nn[i] + 2u <= 16u) { nn[i] += 2u; u -= 2u; } }
        for (i = 0; i < a && u > 0u; i++) { if (nn[i] < 16u) { nn[i]++; u--; } }
        if (u != 0u || e != 0u) { fprintf(stderr, "ev_worst_program: the nots do not fit the rule\n"); exit(2); }
        sb_add(b, "%s deny if", kind);
        for (i = 0; i < a; i++) {
            int need = s.is_or ? 0 : (i + 1u < a);
            /* the atom's own outcome: the needed value with the parity of its nots undone */
            int atom = ((nn[i] + ng[i]) & 1u) ? !need : need;
            uint32_t k;
            if (i > 0u) { sb_add(b, s.is_or ? " or" : " and"); }
            for (k = 0; k < nn[i]; k++) { sb_add(b, " not"); }
            sb_add(b, " ");
            if (ng[i] != 0u) {
                ev_negated(b, atom ? s.atom->t : s.atom->f);
            } else {
                sb_add(b, "%s", atom ? s.atom->t : s.atom->f);
            }
            if (atom) { c->t++; } else { c->f++; }
            c->nots += nn[i] + ng[i];
        }
        c->rules++;
        if (s.is_or) { c->or_links += a - 1u; }
        sb_add(b, RS);
    }
}

#ifdef WE_HAVE_EVAL
#include "we_policy.h"

/*
 * THE ADAPTER: where the gate and the bench meet the policy compiler. A whole configuration, given as
 * corpus records, is compiled once into a build (we_policy_build); its floor and each context's
 * program are read out of it (we_policy_floor, we_policy_program). Blocks are allocated 4096-byte
 * aligned, so the D1 sets a block's lines fall in do not move run to run (the cachegrind gate's rule).
 */
#define AD_MAX_DIRECTIVES 1100u

typedef struct {
    we_policy_directive_t d[AD_MAX_DIRECTIVES];
    char           ctx[AD_MAX_DIRECTIVES][64];
    size_t         n;
} ad_dirs_t;

static inline void *ad_alloc(void *ud, size_t size, size_t align)
{
    size_t a = align > 4096u ? align : 4096u;

    (void)ud;
    return aligned_alloc(a, (size + a - 1u) & ~(a - 1u));
}

static inline void ad_free(void *ud, void *p)
{
    (void)ud;
    free(p);
}

/* corpus records into the compiler's directives; the arguments point into `records`, which outlives them */
static inline void ad_parse(const char *records, ad_dirs_t *o)
{
    static const struct { const char *name; uint8_t kind; } K[] = {
        { "policy", WE_DIR_POLICY }, { "set", WE_DIR_SET }, { "floor", WE_DIR_FLOOR },
        { "threshold", WE_DIR_THRESHOLD }, { "mode", WE_DIR_MODE },
    };
    const char *p = records;

    o->n = 0;
    while (*p != '\0') {
        const char *sp1 = strchr(p, ' '), *sp2, *end = strchr(p, '\x1e');
        size_t i, kl;

        if (sp1 == NULL || end == NULL || (sp2 = strchr(sp1 + 1, ' ')) == NULL || sp2 > end || o->n == AD_MAX_DIRECTIVES) {
            fprintf(stderr, "a gate program is not a sequence of corpus records\n");
            exit(2);
        }
        kl = (size_t)(sp1 - p);
        o->d[o->n].kind = 0;
        for (i = 0; i < sizeof K / sizeof K[0]; i++) {
            if (strlen(K[i].name) == kl && strncmp(p, K[i].name, kl) == 0) { o->d[o->n].kind = K[i].kind; }
        }
        snprintf(o->ctx[o->n], sizeof o->ctx[0], "%.*s", (int)(sp2 - sp1 - 1), sp1 + 1);
        o->d[o->n].context = o->ctx[o->n];
        o->d[o->n].arg = (const uint8_t *)(sp2 + 1);
        o->d[o->n].len = (size_t)(end - sp2 - 1);
        if (o->d[o->n].kind == 0) {
            fprintf(stderr, "a gate program has a record of an unknown kind: %.*s\n", (int)kl, p);
            exit(2);
        }
        o->n++;
        p = end + 1;
        if (*p == '\n') { p++; }
    }
}

/* one configuration, compiled; every gate program must compile, so a refusal is the run's end */
static inline we_policy_build_t *ad_build(const char *records)
{
    static ad_dirs_t dirs;
    static const we_alloc_t alloc = { ad_alloc, ad_free, NULL };
    we_policy_source_t src;
    we_policy_env_t env = WE_POLICY_ENV_ALL;
    we_policy_error_t err;
    we_policy_build_t *b = NULL;

    ad_parse(records, &dirs);
    memset(&src, 0, sizeof src);
    memset(&err, 0, sizeof err);
    src.d = dirs.d;
    src.n = dirs.n;
    if (we_policy_build(&src, &env, &alloc, &b, &err, NULL) != WE_POLICY_OK || b == NULL) {
        char line[2048];

        we_policy_error_format(&err, line, sizeof line);
        fprintf(stderr, "a gate program does not compile: %s\n", line);
        exit(2);
    }
    return b;
}
#endif

#endif /* WE_EVAL_PROGRAMS_H */
