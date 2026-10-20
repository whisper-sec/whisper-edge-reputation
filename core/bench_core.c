/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * bench_core.c - the bound of every layout, computed from the file, and one sampled mean beside it;
 * the policy programs' per-rule and per-program terms; and a machine-readable record of both.
 *
 * WHAT IS PRINTED, and what is not. For each size and each layout - format 1 unindexed and radix-16,
 * format 2 radix-12, -16, -18 and rank-64 - the widest window the search can walk and the probe bound
 * that follows from it, ceil(log2(w + 1)), plus the S-tree depth for rank: numbers that are properties
 * of the file and hold for EVERY address (FORMAT.md §7). Beside them, one mean per
 * layout, labelled as information and with the machine named, because a mean is the one sampled figure
 * a batch timing can support.
 *
 * NO PERCENTILES. This program used to print p50 to p99.9 of batch means, timing 32 lookups between
 * two clock reads. A percentile of batch means is structurally blind to a tail: injecting a stall into
 * 2% of lookups put the true per-lookup p99 at 576 ns while the batches reported 57. The "186 ns tail
 * of the worst bucket" an early draft quoted from it appeared at 500 ranges in a 4.6 KB array that has
 * no worst bucket, and did not reproduce run to run. The bound is the claim; the mean is context.
 *
 * THE POLICY TABLE, after the layout table: for the default policy (POLICY.md §7), the design example (row N4) and the
 * constructed worst case, per rule and per program, the operations, the instructions they compile to,
 * the planes they read, and per program the instruction lines and the lookups a request costs in the
 * equal-key and distinct-key forms of the composed bound. Counted from the CANONICAL text the compiler
 * prints (we_program_print), never from the block's internals, so the counts are an independent reading
 * of the compiled program. It needs the policy compiler: until we_eval.h is in the tree the table is
 * reported DARK, by name, in the output and in the record.
 *
 * THE RECORD. With a second argument, bench_core writes a JSON record of everything it printed, keyed
 * by the commit, the compiler, the flags and the data it measured (the pinned seed and plane generation
 * of the synthetic layouts), so "the numbers bench_core printed on the build that shipped" has a
 * mechanism: `make bench` writes it and bench/check-record.py reads it back and holds it to its shape.
 *
 * Run it on an IDLE machine. A loaded one makes a search over cache look like a cache miss, which is
 * how a measurement talks you into the wrong design. The first version of this program is what showed
 * the bucket index beats no index by about 10x at every size, and the builder emits it as a result.
 */
#define _POSIX_C_SOURCE 200809L
#include "whisper_edge.h"
#include "we_writer.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#ifdef WE_HAVE_EVAL
#include "gate/eval_programs.h"
#endif

/* the record's key, from the build: `make bench` passes the commit and the flags it compiled with */
#ifndef WE_BENCH_COMMIT
#define WE_BENCH_COMMIT "unknown"
#endif
#ifndef WE_BENCH_FLAGS
#define WE_BENCH_FLAGS "unknown"
#endif
#if defined(__clang__)
#define WE_BENCH_CC "clang " __clang_version__
#elif defined(__GNUC__)
#define WE_BENCH_CC "gcc " __VERSION__
#else
#define WE_BENCH_CC "unknown"
#endif

static uint64_t ns(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static uint64_t rs = 0x9e3779b97f4a7c15ull;     /* the pinned xorshift seed of the measured tables */

static uint32_t rnd(void)
{
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return (uint32_t)(rs >> 32);
}

typedef struct { const char *name; uint32_t format, kind, param; } layout_t;

/* a JSON string, escaped: quotes, backslashes and every control byte */
static void jstr(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fprintf(f, "\\%c", c); }
        else if (c < 0x20u) { fprintf(f, "\\u%04x", c); }
        else { fputc(c, f); }
    }
    fputc('"', f);
}

#ifdef WE_HAVE_EVAL
/* ---- the policy table ---------------------------------------------------------------------------- */
typedef struct { uint32_t ops, instr, planes; } pc_t;

/* the plane id - 1 an attribute is read from (the vocabulary of POLICY.md section 1.3) */
static int pc_plane(const char *a)
{
    static const struct { const char *attr; int plane; } T[] = {
        { "listed", 0 }, { "inferred", 0 }, { "tor_exit", 1 }, { "rpki_unreachable", 2 }, { "rpki_reason", 2 },
        { "rpki", 3 }, { "asn", 3 }, { "country", 3 }, { "rir", 3 }, { "asn_rep", 3 }, { "anycast", 3 },
        { "moas", 3 }, { "narrowed", 3 }, { "proxy", 4 }, { "vpn", 4 }, { "c2", 5 }, { "bruteforce", 5 },
        { "spam", 5 }, { "phishing", 5 }, { "scanner", 5 }, { "state_actor", 5 }, { "registry_country", 6 },
        { "registry_rir", 6 }, { "tenant_allow", 7 }, { "tenant_deny", 7 },
    };
    size_t i;
    for (i = 0; i < sizeof T / sizeof T[0]; i++) { if (!strcmp(T[i].attr, a)) { return T[i].plane; } }
    return -1;
}

/*
 * One canonical rule, `action if expr`, counted: an atom is one operation and one instruction; a
 * connective one operation and two instructions (the operator and its jump); a unary `not` one of each;
 * the NOT that `!=` and `is not unknown` compile to an instruction only; END one instruction.
 */
static int pc_rule(const char *line, pc_t *c)
{
    char buf[8192], *tok[4096], *save = NULL, *t;
    uint32_t n = 0, i = 0;

    memset(c, 0, sizeof *c);
    snprintf(buf, sizeof buf, "%s", line);
    for (t = strtok_r(buf, " ", &save); t != NULL && n < 4096u; t = strtok_r(NULL, " ", &save)) { tok[n++] = t; }
    if (n < 3u || strcmp(tok[1], "if") != 0) { return -1; }
    for (i = 2; i < n; i++) {
        int p;
        if (!strcmp(tok[i], "and") || !strcmp(tok[i], "or")) { c->ops++; c->instr += 2u; continue; }
        if (!strcmp(tok[i], "not")) { c->ops++; c->instr++; continue; }
        if (!strcmp(tok[i], "(") || !strcmp(tok[i], ")")) { continue; }
        p = pc_plane(tok[i]);
        if (p < 0) { return -1; }
        c->planes |= 1u << p;
        c->ops++;
        c->instr++;
        if (i + 1u < n && !strcmp(tok[i + 1u], "is")) {
            if (i + 2u < n && !strcmp(tok[i + 2u], "not")) { c->instr++; i++; }
            i += 2u;                                    /* is [not] unknown */
        } else if (i + 1u < n && (!strcmp(tok[i + 1u], "==") || !strcmp(tok[i + 1u], "!=") || !strcmp(tok[i + 1u], ">=")
                                  || !strcmp(tok[i + 1u], ">") || !strcmp(tok[i + 1u], "<=") || !strcmp(tok[i + 1u], "<"))) {
            if (!strcmp(tok[i + 1u], "!=")) { c->instr++; }
            i += 2u;
        } else if (i + 1u < n && !strcmp(tok[i + 1u], "in")) {
            i += 2u;
            if (i < n && !strcmp(tok[i], "{")) { while (i < n && strcmp(tok[i], "}") != 0) { i++; } }
        }
    }
    c->instr++;                                         /* END */
    return 0;
}

static char *slurp_text(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *b;
    long l;

    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (l = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        perror(path);
        exit(2);
    }
    b = malloc((size_t)l + 1u);
    if (b == NULL || fread(b, 1, (size_t)l, f) != (size_t)l) { perror(path); exit(2); }
    b[l] = '\0';
    fclose(f);
    return b;
}

/* one program: per rule, and the totals; returns the planes it reads */
static uint32_t pc_program(FILE *rec, const char *name, const char *context, int floor, const char *records, int *first)
{
    we_policy_build_t *b = ad_build(records);
    const we_program_t *p = floor ? we_policy_floor(b) : we_policy_program(b, context);
    char *text = malloc(1u << 20), *line, *save = NULL;
    uint32_t r = 0, ops = 0, instr = 0, planes = 0;
    const we_rule_t *rules;

    if (p == NULL || text == NULL || we_program_print(p, text, 1u << 20) < 0) { fprintf(stderr, "%s: cannot print\n", name); exit(2); }
    rules = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
    for (line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        pc_t c;
        if (pc_rule(line, &c) != 0) { fprintf(stderr, "%s: cannot count `%s`\n", name, line); exit(2); }
        r++;
        /*
         * B1, against the block: the instructions counted from the canonical TEXT must be the instructions
         * the compiler laid out for that rule, and their sum the block's own count. Two derivations of
         * one number, so a counting rule here that drifted from the compiler fails the bench, never the
         * page that prints the column.
         */
        if (r > p->rule_count || rules[r - 1u].instr_count != c.instr) {
            fprintf(stderr, "B1 FAIL %s rule %u: the text counts %u instructions, the block holds %u\n", name, r, c.instr,
                    r > p->rule_count ? 0u : (unsigned)rules[r - 1u].instr_count);
            exit(1);
        }
        ops += c.ops; instr += c.instr; planes |= c.planes;
        if (r <= 8u) {
            printf("  %-12s rule %3u  ops %3u  instructions %3u  planes 0x%02x  %s\n", name, r, c.ops, c.instr, c.planes, line);
        }
        if (rec != NULL) {
            fprintf(rec, "%s{\"program\":", *first ? "" : ",");
            jstr(rec, name);
            fprintf(rec, ",\"rule\":%u,\"operations\":%u,\"instructions\":%u,\"planeMask\":%u,\"text\":", r, c.ops, c.instr, c.planes);
            jstr(rec, line);
            fprintf(rec, "}");
            *first = 0;
        }
    }
    if (r > 8u) { printf("  %-12s ... %u rules in all\n", name, r); }
    if (r != p->rule_count || instr != p->instr_count) {
        fprintf(stderr, "B1 FAIL %s: the text counts %u rules and %u instructions, the block %u and %u\n", name, r, instr,
                (unsigned)p->rule_count, (unsigned)p->instr_count);
        exit(1);
    }
    printf("  %-12s TOTAL %u rules, %u operations, %u instructions (%u lines of 64 bytes), planes 0x%02x\n",
           name, r, ops, instr, (8u * instr + 63u) / 64u, planes);
    free(text);
    we_policy_build_free(b);
    return planes;
}

static int popcount8(uint32_t m) { int n = 0; while (m != 0u) { n += (int)(m & 1u); m >>= 1; } return n; }

static void policy_table(FILE *rec)
{
    char *def = slurp_text("testdata/policy/accept/01-default-policy.policy");
    char *design = slurp_text("testdata/policy/accept/02-design-example-sets-after-rules.policy");
    ev_shape_t ws = ev_worst_shape("gate/evaluator-worst.tsv");
    sb_t worst = { 0 };
    int first = 1;
    uint32_t fl, cx;
    const uint32_t tenant = 1u << 7;

    ev_counts_t junk = { 0 };

    ev_sets(&worst);
    ev_worst_program(&worst, "floor http", ws, 0, &junk);
    ev_worst_program(&worst, "policy http/server:s", ws, 0, &junk);
    printf("\npolicy programs, counted from the compiler's canonical text\n");
    if (rec != NULL) { fprintf(rec, ",\"policy\":{\"status\":\"live\",\"rules\":["); }
    (void)pc_program(rec, "default", "http/server:a", 0, def, &first);
    (void)pc_program(rec, "design-example", "http/server:a", 0, design, &first);
    fl = pc_program(rec, "worst-floor", "http", 1, worst.p, &first);
    cx = pc_program(rec, "worst", "http/server:s", 0, worst.p, &first);
    /* the composed bound's lookup forms (POLICY.md 3.7): equal keys share one slot, distinct keys use two */
    printf("  worst        lookups per request: equal keys %d, distinct keys %d (floor and tenant, then the context)\n",
           popcount8(fl | tenant | cx), popcount8(fl | tenant) + popcount8(cx));
    if (rec != NULL) {
        fprintf(rec, "],\"worstLookups\":{\"equalKeys\":%d,\"distinctKeys\":%d}}", popcount8(fl | tenant | cx),
                popcount8(fl | tenant) + popcount8(cx));
    }
    free(def); free(design); free(worst.p);
}
#endif

int main(int argc, char **argv)
{
    static const layout_t L[] = {
        { "f1 unindexed", WE_FORMAT_1, WE_KIND_NONE,  0u },
        { "f1 radix-16",  WE_FORMAT_1, WE_KIND_RADIX, 16u },
        { "f2 radix-12",  WE_FORMAT_2, WE_KIND_RADIX, 12u },
        { "f2 radix-16",  WE_FORMAT_2, WE_KIND_RADIX, 16u },
        { "f2 radix-18",  WE_FORMAT_2, WE_KIND_RADIX, 18u },
        { "f2 rank-64",   WE_FORMAT_2, WE_KIND_RANK,  6u },
    };
    static const uint32_t sizes[] = { 500u, 4000u, 32000u, 120000u, 1500000u };
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    const char *recpath = argc > 2 ? argv[2] : NULL;
    FILE *rec = NULL;
    struct utsname u;
    size_t si, li;
    int first = 1;

    if (uname(&u) != 0) {
        strcpy(u.machine, "unknown");
    }
    if (recpath != NULL) {
        rec = fopen(recpath, "w");
        if (rec == NULL) {
            perror(recpath);
            return 1;
        }
        /* the commit this BINARY was built from, compiled in: make bench compares it with the tree's, so
         * a binary left over from another commit is refused by name rather than relabelled */
        fprintf(rec, "{\"record\":\"whisper-edge-bench\",\"version\":1,\"commit\":");
        jstr(rec, WE_BENCH_COMMIT);
        fprintf(rec, ",\"compiler\":");
        jstr(rec, WE_BENCH_CC);
        fprintf(rec, ",\"flags\":");
        jstr(rec, WE_BENCH_FLAGS);
        fprintf(rec, ",\"machine\":");
        jstr(rec, u.machine);
        fprintf(rec, ",\"data\":{\"kind\":\"synthetic\",\"seed\":\"0x9e3779b97f4a7c15\",\"planeGeneration\":1},\"layout\":[");
    }
    printf("bounds are properties of the file; the mean is information only, sampled on %s\n\n", u.machine);
    printf("%-8s %-13s %9s %13s %10s %6s %14s\n", "ranges", "layout", "file KB", "widest window",
           "max probes", "depth", "mean ns (info)");
    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        uint32_t n = sizes[si], i, cur = 1000u, step = (uint32_t)(0xf0000000u / n);
        __uint128_t *st = (__uint128_t *)malloc(sizeof(__uint128_t) * n);
        __uint128_t *en = (__uint128_t *)malloc(sizeof(__uint128_t) * n);

        if (st == NULL || en == NULL) {
            free(st);
            free(en);
            return 1;
        }
        /* spread across the IPv4 space so every index is exercised the way real data exercises it */
        for (i = 0; i < n; i++) {
            st[i] = cur;
            en[i] = cur + 255u;
            cur += 256u + (rnd() % (step > 256u ? step - 256u : 1u));
        }
        for (li = 0; li < sizeof L / sizeof L[0]; li++) {
            ww_plane_t p;
            we_map_t m;
            char path[512];
            uint32_t occ, k, a[32];
            uint64_t sum = 0;
            volatile uint32_t sink = 0;
            int rc, r, j;

            memset(&p, 0, sizeof p);
            p.format = L[li].format;
            p.schema = 1;
            p.plane = L[li].format == WE_FORMAT_1 ? WE_PLANE_REPUTATION : WE_PLANE_ROUTING;
            p.generation = 1u;
            p.v4.n = n;
            p.v4.start = st;
            p.v4.end = en;
            p.v4.kind = L[li].kind;
            p.v4.param = L[li].param;
            snprintf(path, sizeof path, "%s/bench.snap", dir);
            if (ww_write(path, &p) != 0) {
                printf("cannot write %s\n", path);
                continue;
            }
            rc = we_plane_open(path, &m, NULL);
            if (rc != WE_OK) {
                printf("open failed: %s\n", we_strerror(rc));
                continue;
            }
            occ = we_worst_bucket_occupancy4(&m);
            for (k = 0; k < 300000u; k++) {
                sink += we_find4(&m, rnd());          /* warm the cache the way traffic would */
            }
            for (r = 0; r < 30000; r++) {
                uint64_t t0, t1;

                for (j = 0; j < 32; j++) {
                    a[j] = rnd();
                }
                t0 = ns();
                for (j = 0; j < 32; j++) {
                    sink += we_find4(&m, a[j]);
                }
                t1 = ns();
                sum += t1 - t0;
            }
            printf("%-8u %-13s %9.1f %13u %10u %6u %14.1f\n", n, L[li].name, (double)m.len / 1024.0, occ,
                   we_max_probes(occ), we_rank_depth4(&m), (double)sum / (30000.0 * 32.0));
            if (rec != NULL) {
                fprintf(rec, "%s{\"ranges\":%u,\"layout\":", first ? "" : ",", n);
                jstr(rec, L[li].name);
                fprintf(rec, ",\"fileBytes\":%zu,\"widestWindow\":%u,\"maxProbes\":%u,\"depth\":%u,\"meanNsInformation\":%.1f}",
                        m.len, occ, we_max_probes(occ), we_rank_depth4(&m), (double)sum / (30000.0 * 32.0));
                first = 0;
            }
            we_map_close(&m);
            (void)sink;
        }
        free(st);
        free(en);
    }
    if (rec != NULL) { fprintf(rec, "]"); }
#ifdef WE_HAVE_EVAL
    policy_table(rec);
#else
    printf("\npolicy programs: DARK, the policy compiler (we_eval.h) is not in this tree; the table runs, with no "
           "edit here, once it is\n");
    if (rec != NULL) { fprintf(rec, ",\"policy\":{\"status\":\"dark\",\"why\":\"we_eval.h is not in this tree\"}"); }
#endif
    if (rec != NULL) {
        fprintf(rec, "}\n");
        if (fclose(rec) != 0) {
            perror(recpath);
            return 1;
        }
        printf("\nrecord: %s\n", recpath);
    }
    return 0;
}
