/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * test_policy.c - the policy language, held to its specification row by row.
 *
 * WHAT RUNS HERE. The independent corpus (testdata/policy/: 20 programs that must compile, 50 that
 * must be refused with every .expect field equal), the compiler's other refusals byte by byte, the
 * verifier's twenty-two steps one mutation each, the evaluator's three-valued logic and fixed order,
 * the memo and the fill against every record byte, the tenant plane in each of its five states, the
 * S+ tree at every size boundary against guard pages, the hold-harmless table per lookup against its
 * model, the outage classifier against an exact brute force, the sugar against we_should_deny, and an
 * exhaustive leg that evaluates every expression of up to three atoms in every value against a
 * second, value-level reference (K3 written as truth tables, never as bit pairs), filling a coverage
 * matrix that must have no zero cell. Every leg runs with the program blocks, the hold-harmless view
 * and every plane buffer under mprotect(PROT_READ), so a stray store from the evaluator faults.
 *
 * It is a WE_TRACE build: the evaluator's cost counters (instructions executed, jumps taken, lookups
 * per address and plane, set payload lines) exist only in a traced build, and the mutants of the
 * POLICY.md section 5.4 are -D builds of this file, each of which must fail its named row.
 *
 * THREE MODES.
 *   test_policy [DIR]            the rows, in DIR (default .testtmp) for the files they write
 *   test_policy --cases FILE     the C side of the differential: the case file policy_gen.py writes, and
 *                                every output line in policy_ref.py's format (program, refusal, text,
 *                                report, case, verdict, cost, invariant, classes, dependents), which
 *                                policy_diff.py compares line by line; it also fills the coverage
 *                                matrix for the legs the file holds and fails on a zero cell (K7)
 *   test_policy --cases FILE --attrs
 *                                the same, with the 25 `attr` lines after each case's cost line: the
 *                                floor address's attributes from the evaluator's memo, filled for every
 *                                plane and rendered by we_attr_render(), as whisper-edge-lookup prints
 *                                them (policy_ref.py --attrs is the reference half)
 *   test_policy --c-only DIR     the seeds only this harness can build (DIR's .c-only files): one
 *                                `c-only <name> ok` line each, and a seed it has no case for fails
 * --cases on a seed-sized file (a single testdata/policy/seeds .case file) fails K7 by design: the
 * matrix requires every cell of each leg the file holds, and a handful of programs fills almost none.
 * Those seeds are compared inside the generated file, in their own `cases` leg, which owns no cell.
 * Every mode ends with one `N checks, F failures` line (on stderr under --cases, so the compared
 * output holds nothing else) and exits non-zero on any failure. `--emit` with the first mode also
 * prints the corpus programs' canonical text and every report.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "we_eval.h"
#include "we_policy.h"
#include "we_procid.h"
#include "we_sha256.h"
#include "we_writer.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef WE_TRACE
#error "test_policy is a WE_TRACE build: the cost columns and the mutants need it"
#endif

static long long checks = 0, failures = 0;
#ifdef WE_TEST_PLANTED_STORE
volatile int we_test_planted;               /* we_eval.h's planted store, armed in H3's child alone */
#endif
static int emit = 0;
static const char *TMP = ".testtmp";

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

#define SECTION(name) printf("\n== %s ==\n", name)

/* ---- the trace hooks: every load the lookup and the evaluator make ---- */
#define TRACE_MAX 65536
static const uint8_t *trace_addr[TRACE_MAX];
static size_t trace_len[TRACE_MAX];
static int trace_n = 0;
static int trace_on = 0;
static long long k3_bad = 0;

void we_trace_read(const void *p, size_t len)
{
    if (trace_on && trace_n < TRACE_MAX) {
        trace_addr[trace_n] = (const uint8_t *)p;
        trace_len[trace_n++] = len;
    }
}

/*
 * The coverage taps. The K3 cells are counted only while a leg that owns them runs (the exhaustive
 * leg here; the case file's exhaustive leg under --cases), so a build without that leg leaves them at
 * zero and K7 fails, which is the WE_TEST_NO_EXHAUSTIVE control. The evaluator's own loads say which
 * rule and which instruction run: a 16-byte load inside a watched program's rule table is the rule,
 * an 8-byte load inside its instruction table the instruction.
 */
static int cov_k3_on;                       /* the K3 and action-final cells are being counted */
static const we_program_t *cov_prog[2];     /* the programs whose loads are watched */
static const we_rule_t *cov_rule;           /* the rule running, by its load */
static void (*cov_instr_tap)(const we_program_t *p, uint32_t idx);
static void (*cov_rule_tap)(const we_program_t *p, const we_rule_t *r);

static int cov_inside(const we_program_t *p, uint32_t off, uint32_t len, const void *q)
{
    const uint8_t *b = (const uint8_t *)p + off;

    return (const uint8_t *)q >= b && (const uint8_t *)q < b + len;
}

void we_trace_eval(const void *p, size_t len)
{
    uint32_t k;

    we_trace_read(p, len);
    for (k = 0u; k < 2u; k++) {
        const we_program_t *q = cov_prog[k];

        if (q == NULL) {
            continue;
        }
        if (len == 16u && cov_inside(q, q->rules_off, 16u * q->rule_count, p)) {
            cov_rule = (const we_rule_t *)p;
            if (cov_rule_tap != NULL) {
                cov_rule_tap(q, cov_rule);
            }
        } else if (len == 8u && cov_instr_tap != NULL && cov_inside(q, q->instrs_off, 8u * q->instr_count, p)) {
            cov_instr_tap(q, (uint32_t)(((const uint8_t *)p - ((const uint8_t *)q + q->instrs_off)) / 8u));
        }
    }
}

void we_trace_k3(uint64_t t, uint64_t f)
{
    if ((t & f) != 0u) {
        k3_bad++;                                 /* (1, 1) is unreachable: row K6 */
    }
}

static void trace_reset(void)
{
    trace_n = 0;
}

/* every traced read inside [lo, hi) */
static int trace_inside(const void *lo, const void *hi, const void *from, const void *to)
{
    int i;

    for (i = 0; i < trace_n; i++) {
        const uint8_t *a = trace_addr[i];

        if (a >= (const uint8_t *)from && a < (const uint8_t *)to) {
            if (a < (const uint8_t *)lo || a + trace_len[i] > (const uint8_t *)hi) {
                return 0;
            }
        }
    }
    return 1;
}

/* distinct 64-byte lines among the traced reads inside [from, to) */
static int trace_lines(const void *from, const void *to)
{
    uintptr_t seen[1024];
    int ns = 0, i, j;

    for (i = 0; i < trace_n; i++) {
        uintptr_t a = (uintptr_t)trace_addr[i];

        if (a >= (uintptr_t)from && a < (uintptr_t)to) {
            uintptr_t l0 = a >> 6, l1 = (a + trace_len[i] - 1u) >> 6, l;

            for (l = l0; l <= l1; l++) {
                int dup = 0;

                for (j = 0; j < ns && !dup; j++) {
                    dup = seen[j] == l;
                }
                if (!dup && ns < 1024) {
                    seen[ns++] = l;
                }
            }
        }
    }
    return ns;
}

/* ======================================================================================================
 * The corpus
 * ==================================================================================================== */

#define MAXDIR 4096
typedef struct {
    we_policy_directive_t d[MAXDIR];
    char           ctx[MAXDIR][128];
    size_t         n;
    uint8_t       *buf;
} corpus_src_t;

static uint8_t kind_of(const char *w)
{
    return strcmp(w, "policy") == 0 ? WE_DIR_POLICY : strcmp(w, "set") == 0 ? WE_DIR_SET
         : strcmp(w, "floor") == 0 ? WE_DIR_FLOOR : strcmp(w, "threshold") == 0 ? WE_DIR_THRESHOLD
         : strcmp(w, "mode") == 0 ? WE_DIR_MODE : strcmp(w, "allow_inferred") == 0 ? WE_DIR_ALLOW_INFERRED : 0u;
}

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *b;
    long n;

    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = (uint8_t *)malloc((size_t)n + 1u);
    if (b != NULL && fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        b = NULL;
    }
    fclose(f);
    if (b != NULL) {
        b[n] = 0;
        *len = (size_t)n;
    }
    return b;
}

/* `<kind> SP <context> SP <argument> 0x1E 0x0A`, repeated */
static int parse_policy_file(const char *path, corpus_src_t *s)
{
    size_t len = 0u, p = 0u;

    s->n = 0u;
    s->buf = slurp(path, &len);
    if (s->buf == NULL) {
        return -1;
    }
    while (p < len) {
        char kind[16];
        size_t k = 0u, c = 0u, a;

        while (p < len && s->buf[p] != ' ' && k + 1u < sizeof kind) {
            kind[k++] = (char)s->buf[p++];
        }
        kind[k] = '\0';
        if (p >= len || s->buf[p] != ' ' || s->n >= MAXDIR) {
            return -1;
        }
        p++;
        while (p < len && s->buf[p] != ' ' && c + 1u < sizeof s->ctx[0]) {
            s->ctx[s->n][c++] = (char)s->buf[p++];
        }
        s->ctx[s->n][c] = '\0';
        if (p >= len || s->buf[p] != ' ') {
            return -1;
        }
        p++;
        a = p;
        while (p < len && s->buf[p] != 0x1e) {
            p++;
        }
        if (p + 1u >= len + 1u || p >= len || s->buf[p] != 0x1e || p + 1u >= len || s->buf[p + 1u] != 0x0a) {
            return -1;
        }
        s->d[s->n].kind = kind_of(kind);
        s->d[s->n].context = s->ctx[s->n];
        s->d[s->n].arg = s->buf + a;
        s->d[s->n].len = p - a;
        s->n++;
        p += 2u;
    }
    return 0;
}

typedef struct {
    char layer[32], kind[16], context[128], token[300], message[300];
    unsigned rule, line, col;
} expect_t;

static int parse_expect(const char *path, expect_t *e)
{
    size_t len;
    uint8_t *b = slurp(path, &len);
    char *line, *save = NULL;

    if (b == NULL) {
        return -1;
    }
    memset(e, 0, sizeof *e);
    for (line = strtok_r((char *)b, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *tab = strchr(line, '\t');
        const char *v;

        if (tab == NULL) {
            continue;
        }
        *tab = '\0';
        v = tab + 1;
        if (strcmp(line, "layer") == 0) snprintf(e->layer, sizeof e->layer, "%s", v);
        else if (strcmp(line, "kind") == 0) snprintf(e->kind, sizeof e->kind, "%s", v);
        else if (strcmp(line, "context") == 0) snprintf(e->context, sizeof e->context, "%s", v);
        else if (strcmp(line, "token") == 0) snprintf(e->token, sizeof e->token, "%s", v);
        else if (strcmp(line, "message") == 0) snprintf(e->message, sizeof e->message, "%s", v);
        else if (strcmp(line, "rule") == 0) e->rule = (unsigned)atoi(v);
        else if (strcmp(line, "line") == 0) e->line = (unsigned)atoi(v);
        else if (strcmp(line, "col") == 0) e->col = (unsigned)atoi(v);
    }
    free(b);
    return 0;
}

static int nreports = 0;
static char last_report[WE_LIM_ARG * 12u + 1024u];
/* the reports of the last compile in the differential's form, kept for --cases to print after the text */
static char *report_buf;
static size_t report_len, report_cap;

/* `report ctx http/server:a 3 shadowed-by 1`, `report set http/@vips duplicate-member 64496` */
static void fmt_report(const we_policy_report_line_t *r, char *out, size_t n)
{
    const char *sp = r->detail != NULL && r->detail[0] != '\0' ? " " : "";
    const char *dt = r->detail != NULL ? r->detail : "";

    if (r->kind == WE_DIR_SET) {
        snprintf(out, n, "report set %s/@%s %s%s%s", r->context, r->name != NULL ? r->name : "", r->code, sp, dt);
    } else {
        snprintf(out, n, "report %s %s %u %s%s%s", r->kind == WE_DIR_FLOOR ? "floor" : "ctx", r->context, r->rule,
                 r->code, sp, dt);
    }
}

static void collect_report(void *ud, const we_policy_report_line_t *r)
{
    static char line[WE_LIM_ARG * 12u + 256u];
    size_t l;

    (void)ud;
    nreports++;
    fmt_report(r, line, sizeof line);
    snprintf(last_report, sizeof last_report, "%s: %s", line, r->msg != NULL ? r->msg : "");
    if (emit) {
        printf("%s\n", last_report);
    }
    l = strlen(line);
    if (report_len + l + 2u > report_cap) {
        size_t nc = (report_cap + l + 2u) * 2u;
        char *nb = (char *)realloc(report_buf, nc);

        if (nb == NULL) {
            return;
        }
        report_buf = nb;
        report_cap = nc;
    }
    memcpy(report_buf + report_len, line, l);
    report_buf[report_len + l] = '\n';
    report_len += l + 1u;
    report_buf[report_len] = '\0';
}
static we_policy_report_t REP = { collect_report, NULL };

static void emit_refusal(const we_policy_error_t *e)
{
    printf("refuse %u %s %u %u \"%s\" %s\n", e->rule, we_policy_kind_name(e->kind), e->line, e->col, e->token, e->phrase);
}

/* compile a source in the default environment */
static int compile_src(const we_policy_directive_t *d, size_t n, we_policy_build_t **b, we_policy_error_t *err)
{
    we_policy_source_t s;
    static const we_policy_env_t all = WE_POLICY_ENV_ALL;

    s.d = d;
    s.n = n;
    s.context = NULL;
    s.floor = 0;
    return we_policy_build(&s, &all, NULL, b, err, &REP);
}

/* compile one policy line in context "http/server:a" */
static int compile1(const char *line, we_policy_build_t **b, we_policy_error_t *err)
{
    we_policy_directive_t d;

    d.kind = WE_DIR_POLICY;
    d.context = "http/server:a";
    d.arg = (const uint8_t *)line;
    d.len = strlen(line);
    return compile_src(&d, 1u, b, err);
}

static int count_files(const char *dir, const char *suffix)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;

    if (d == NULL) {
        return 0;
    }
    while ((e = readdir(d)) != NULL) {
        size_t l = strlen(e->d_name), sl = strlen(suffix);

        n += l > sl && strcmp(e->d_name + l - sl, suffix) == 0;
    }
    closedir(d);
    return n;
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int list_files(const char *dir, const char *suffix, char **out, int cap)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int n = 0;

    if (d == NULL) {
        return 0;
    }
    while ((e = readdir(d)) != NULL && n < cap) {
        size_t l = strlen(e->d_name), sl = strlen(suffix);

        if (l > sl && strcmp(e->d_name + l - sl, suffix) == 0) {
            out[n++] = strdup(e->d_name);
        }
    }
    closedir(d);
    qsort(out, (size_t)n, sizeof out[0], name_cmp);
    return n;
}

/* the distinct blocks of a build, as a list, for the byte-identity checks */
static void build_blocks(const we_policy_build_t *b, const corpus_src_t *s, const we_program_t **out, int *n)
{
    size_t i;

    *n = 0;
    out[(*n)++] = we_policy_floor(b);
    for (i = 0u; i < s->n; i++) {
        const we_program_t *p = we_policy_program(b, s->d[i].context);
        int j, dup = 0;

        for (j = 0; j < *n && !dup; j++) {
            dup = out[j] == p;
        }
        if (p != NULL && !dup) {
            out[(*n)++] = p;
        }
    }
}

static void test_corpus(void)
{
    char *names[256];
    int na, nr, i;
    char path[512];

    SECTION("N1, P1: the independent corpus (testdata/policy)");
    /* X3: the seed floor, so deleting a file cannot pass silently */
    CHECK(count_files("testdata/policy/accept", ".policy") == 20, "accept/ holds 20 programs");
    CHECK(count_files("testdata/policy/refuse", ".policy") == 50, "refuse/ holds 50 programs");
    CHECK(count_files("testdata/policy/refuse", ".expect") == 50, "refuse/ holds 50 expectations");

    na = list_files("testdata/policy/accept", ".policy", names, 256);
    for (i = 0; i < na; i++) {
        static corpus_src_t s, s2;
        we_policy_build_t *b = NULL, *b2 = NULL;
        we_policy_error_t err;
        int rc, rc2;

        snprintf(path, sizeof path, "testdata/policy/accept/%s", names[i]);
        CHECK(parse_policy_file(path, &s) == 0, "%s parses as records", names[i]);
        nreports = 0;
        rc = compile_src(s.d, s.n, &b, &err);
        CHECK(rc == WE_POLICY_OK, "%s compiles: %s layer, rule %u line %u col %u near \"%s\": %s", names[i],
              rc == WE_POLICY_OK ? "-" : err.layer, err.rule, err.line, err.col, err.token, err.what);
        if (rc == WE_POLICY_OK) {
            const we_program_t *bl[64], *bl2[64];
            int nb, nb2, j;

            build_blocks(b, &s, bl, &nb);
            parse_policy_file(path, &s2);
            rc2 = compile_src(s2.d, s2.n, &b2, &err);
            CHECK(rc2 == WE_POLICY_OK, "%s compiles a second time", names[i]);
            if (rc2 == WE_POLICY_OK) {
                build_blocks(b2, &s2, bl2, &nb2);
                CHECK(nb == nb2, "%s: the same block count twice", names[i]);
                for (j = 0; j < nb && j < nb2; j++) {
                    CHECK(bl[j]->total_len == bl2[j]->total_len && memcmp(bl[j], bl2[j], bl[j]->total_len) == 0,
                          "%s: block %d is byte-identical across two compiles", names[i], j);
                }
            }
            for (j = 0; j < nb; j++) {
                static char listing[1 << 20];
                we_policy_error_t ve;

                CHECK(we_program_verify(bl[j], bl[j]->total_len, &ve) == 0, "%s: block %d verifies: step %u %s",
                      names[i], j, ve.rule, ve.what);
                CHECK(we_program_disasm(bl[j], listing, sizeof listing) >= 0, "%s: block %d disassembles", names[i], j);
                if (emit) {
                    static char text[1 << 20];

                    we_program_print(bl[j], text, sizeof text);
                    printf("program %s %d\n%s", names[i], j, text);
                    we_program_print_sets(bl[j], text, sizeof text);
                    fputs(text, stdout);
                }
            }
            if (strncmp(names[i], "08-", 3) == 0) {
                const we_program_t *p = we_policy_program(b, "http/server:a");

                CHECK(p != NULL, "accept/08 has a program");
                /* the n = 0 set (`@unrouted-only undetermined` against asn) compiles to EQ32, never INSET_ASN;
                 * @partners holds AS0 and numbers, so it is the one INSET_ASN the program carries */
                if (p != NULL) {
                    const we_instr_t *ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
                    const we_rule_t *ru = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
                    const we_instr_t *last = &ins[ru[4].instr_start];

                    CHECK((last->op & WE_OP_EQ32) != 0u && last->imm == 0xffffffffu,
                          "accept/08 rule 5 (asn in @unrouted-only) is EQ32 against the sentinel, op 0x%x", last->op);
                }
            }
            if (strncmp(names[i], "04-", 3) == 0) {
                CHECK(nreports > 0, "accept/04 prints its reports and refuses nothing (%d reports)", nreports);
            }
            we_policy_build_free(b2);
            we_policy_build_free(b);
        }
        free(s.buf);
        free(s2.buf);
        s2.buf = NULL;
        free(names[i]);
    }

    nr = list_files("testdata/policy/refuse", ".policy", names, 256);
    for (i = 0; i < nr; i++) {
        static corpus_src_t s;
        we_policy_build_t *b = NULL;
        we_policy_error_t err;
        expect_t x;
        int rc;
        char ep[512];

        snprintf(path, sizeof path, "testdata/policy/refuse/%s", names[i]);
        snprintf(ep, sizeof ep, "testdata/policy/refuse/%.*s.expect", (int)(strlen(names[i]) - 7u), names[i]);
        CHECK(parse_policy_file(path, &s) == 0, "%s parses as records", names[i]);
        CHECK(parse_expect(ep, &x) == 0, "%s has its .expect", names[i]);
        rc = compile_src(s.d, s.n, &b, &err);
        CHECK(rc == WE_POLICY_REFUSED, "%s is refused", names[i]);
        if (rc == WE_POLICY_REFUSED) {
            int in_text = strstr(err.what, x.message) != NULL || strstr(err.fix, x.message) != NULL;

            if (emit) {
                emit_refusal(&err);
            }
            CHECK(strcmp(err.layer, x.layer) == 0, "%s: layer %s, expected %s (%s)", names[i], err.layer, x.layer, err.what);
            CHECK(strcmp(we_policy_kind_name(err.kind), x.kind) == 0, "%s: kind %s, expected %s", names[i],
                  we_policy_kind_name(err.kind), x.kind);
            CHECK(strcmp(err.context, x.context) == 0, "%s: context %s, expected %s", names[i], err.context, x.context);
            CHECK(err.rule == x.rule, "%s: rule %u, expected %u", names[i], err.rule, x.rule);
            CHECK(err.line == x.line && err.col == x.col, "%s: line %u col %u, expected %u %u (%s)", names[i],
                  err.line, err.col, x.line, x.col, err.what);
            CHECK(strcmp(err.token, x.token) == 0, "%s: token \"%s\", expected \"%s\"", names[i], err.token, x.token);
            CHECK(in_text, "%s: \"%s\" is in what or fix (what: %s | fix: %s)", names[i], x.message, err.what, err.fix);
            CHECK(strcmp(err.phrase, x.message) == 0, "%s: the fragment \"%s\", expected \"%s\"", names[i],
                  err.phrase, x.message);
        } else {
            we_policy_build_free(b);
        }
        free(s.buf);
        free(names[i]);
    }
}

/* ======================================================================================================
 * Fixtures in read-only memory: every plane buffer, program block and hold-harmless view the evaluator
 * reads lives in its own mmap'd pages, write-protected before use (row H3), with guard pages around
 * ==================================================================================================== */

#define NOW 1800000000000ull                 /* epoch milliseconds */
#define H48 (48ull * 3600ull * 1000ull)

static size_t pgsz(void)
{
    return (size_t)sysconf(_SC_PAGESIZE);
}

/* `len` bytes, 64-byte aligned, between two PROT_NONE guard pages; flush: end at the trailing guard */
static uint8_t *region(size_t len, int flush)
{
    size_t pg = pgsz(), body = (len + pg - 1u) / pg * pg;
    uint8_t *m;

    if (body == 0u) {
        body = pg;
    }
    m = (uint8_t *)mmap(NULL, body + 2u * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        return NULL;
    }
    mprotect(m, pg, PROT_NONE);
    mprotect(m + pg + body, pg, PROT_NONE);
    return flush ? m + pg + body - ((len + 63u) & ~(size_t)63u) : m + pg;
}

static void ro(const void *p, size_t len)
{
    uintptr_t pg = (uintptr_t)pgsz(), a = (uintptr_t)p & ~(pg - 1u);
    size_t l = (size_t)(((uintptr_t)p + len + pg - 1u) & ~(pg - 1u)) - a;

    if (mprotect((void *)a, l, PROT_READ) != 0) {
        printf("  mprotect failed: %s\n", strerror(errno));
    }
}

/* a read-only copy of a program block */
static const we_program_t *ro_prog(const we_program_t *p)
{
    uint8_t *r;

    if (p == NULL) {
        return NULL;
    }
    r = region(p->total_len, 0);
    memcpy(r, p, p->total_len);
    ro(r, p->total_len);
    return (const we_program_t *)(const void *)r;
}

/* the hold-harmless view, placed from a floor on its own page and write-protected */
static const we_hh_view_t *ro_hh(const we_program_t *floor)
{
    we_hh_view_t *v = (we_hh_view_t *)(void *)region(sizeof(we_hh_view_t), 0);
    int rc = we_program_place(floor, v);

    CHECK(rc == 0 && ((uintptr_t)v & 63u) == 0u, "[M5] we_program_place builds a 64-byte aligned view");
    ro(v, sizeof *v);
    return v;
}

/* one plane's records: the test states them; the reference reads them, the loader builds the map */
#define PMAX 1700
typedef struct {
    uint32_t    plane;                 /* plane_id */
    uint32_t    n4, n6;
    uint32_t    s4[PMAX], e4[PMAX];
    uint8_t     r4[PMAX][32];          /* format 1: r4[i][0] is the sev byte; format 2: the record */
    __uint128_t s6[PMAX], e6[PMAX];    /* routing and registry: the top 64 bits, zero-extended */
    uint8_t     r6[PMAX][32];
    uint32_t    kind4, param4, kind6, param6;
    int         noblob;
} pspec_t;

static uint32_t stride_of(uint32_t plane, int fam)
{
    if (plane == WE_PLANE_REPUTATION) {
        return 1u;
    }
    if (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) {
        return fam == 4 ? 16u : 24u;
    }
    return fam == 4 ? 16u : 32u;
}

static uint32_t key6_of(uint32_t plane)
{
    return (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) ? 8u : 16u;
}

/* the pointers of a map into [ob, ob + len), moved to nb */
#define RB(p) do { if ((const uint8_t *)(p) >= ob && (const uint8_t *)(p) < ob + len) \
                       (p) = (__typeof__(p))(const void *)(nb + ((const uint8_t *)(p) - ob)); } while (0)
static void rebase_fam(we_fam_t *f, const uint8_t *ob, size_t len, const uint8_t *nb)
{
    RB(f->start);
    RB(f->end);
    RB(f->records);
    RB(f->sev);
    RB(f->idx);
    RB(f->stree);
}

static void rebase(we_map_t *m, const uint8_t *nb)
{
    const uint8_t *ob = (const uint8_t *)m->base;
    size_t len = m->len;

    rebase_fam(&m->f4, ob, len, nb);
    rebase_fam(&m->f6, ob, len, nb);
    rebase_fam(&m->f6w, ob, len, nb);
    RB(m->h);
    RB(m->v4_index);
    RB(m->v4_start);
    RB(m->v4_end);
    RB(m->v4_sev);
    RB(m->v6_index);
    RB(m->v6_start);
    RB(m->v6_end);
    RB(m->v6_sev);
    RB(m->v4_meta);
    RB(m->v6_meta);
    RB(m->blob);
    m->base = nb;
}

typedef void (*patch_fn)(uint8_t *buf, const we_map_t *m, void *ud);

/* build, load, move into read-only pages; the descriptor on a read-only page too */
static const we_map_t *mk_map(const pspec_t *ps, uint64_t gen, uint64_t vu, int flush, patch_fn patch, void *ud)
{
    ww_plane_t p;
    uint8_t *buf, *rec4 = NULL, *rec6 = NULL, *sev4 = NULL, *sev6 = NULL, *nb;
    size_t len;
    char path[512];
    we_map_t tmp, *desc;
    we_load_detail_t det;
    static int seq = 0;
    uint32_t i, st4 = stride_of(ps->plane, 4), st6 = stride_of(ps->plane, 6);

    memset(&p, 0, sizeof p);
    p.format = ps->plane == WE_PLANE_REPUTATION ? WE_FORMAT_1 : WE_FORMAT_2;
    p.schema = 1;
    p.plane = ps->plane;
    p.generation = gen;
    p.valid_until_ms = vu;
    p.country_version = (ps->plane == WE_PLANE_ROUTING || ps->plane == WE_PLANE_REGISTRY) ? 5704u : 0u;
    p.v4.n = ps->n4;
    p.v4.start = NULL;
    p.v6.n = ps->n6;
    {
        static __uint128_t s4[PMAX], e4[PMAX];

        for (i = 0u; i < ps->n4; i++) {
            s4[i] = ps->s4[i];
            e4[i] = ps->e4[i];
        }
        p.v4.start = s4;
        p.v4.end = e4;
    }
    p.v6.start = ps->s6;
    p.v6.end = ps->e6;
    p.v4.kind = ps->kind4;
    p.v4.param = ps->param4;
    p.v6.kind = ps->kind6;
    p.v6.param = ps->param6;
    if (p.format == WE_FORMAT_1) {
        sev4 = (uint8_t *)calloc(PMAX, 1);
        sev6 = (uint8_t *)calloc(PMAX, 1);
        for (i = 0u; i < ps->n4; i++) {
            sev4[i] = ps->r4[i][0];
        }
        for (i = 0u; i < ps->n6; i++) {
            sev6[i] = ps->r6[i][0];
        }
        p.v4.sev = sev4;
        p.v6.sev = sev6;
    } else {
        rec4 = (uint8_t *)calloc(PMAX, 32);
        rec6 = (uint8_t *)calloc(PMAX, 32);
        for (i = 0u; i < ps->n4; i++) {
            memcpy(rec4 + (size_t)i * st4, ps->r4[i], st4);
        }
        for (i = 0u; i < ps->n6; i++) {
            memcpy(rec6 + (size_t)i * st6, ps->r6[i], st6);
        }
        p.v4.rec = rec4;
        p.v6.rec = rec6;
        if (ps->noblob) {
            p.blob = "";
            p.blob_len = 0u;
        }
    }
    buf = ww_build(&p, &len);
    free(rec4);
    free(rec6);
    free(sev4);
    free(sev6);
    if (buf == NULL) {
        CHECK(0, "the writer built plane %u", ps->plane);
        return NULL;
    }
    snprintf(path, sizeof path, "%s/plane-%d-%u.bin", TMP, seq++, ps->plane);
    if (ww_save(path, buf, len) != 0) {
        free(buf);
        CHECK(0, "saved %s", path);
        return NULL;
    }
    free(buf);
    if (we_plane_open(path, &tmp, &det) != WE_OK) {
        CHECK(0, "loaded %s: %s", path, det.what != NULL ? det.what : "?");
        return NULL;
    }
    unlink(path);
    nb = region(tmp.len, flush);
    memcpy(nb, tmp.base, tmp.len);
    {
        const void *old = tmp.base;

        rebase(&tmp, nb);
        free((void *)old);
    }
    if (patch != NULL) {
        patch(nb, &tmp, ud);
    }
    ro(nb, tmp.len);
    desc = (we_map_t *)(void *)region(sizeof(we_map_t), 0);
    *desc = tmp;
    ro(desc, sizeof *desc);
    return desc;
}

/* ======================================================================================================
 * The world: records per plane, a state per plane, and the maps those states publish
 * ==================================================================================================== */

#define PS_FRESH   0
#define PS_STALE   1      /* the tenant plane: within the 48-hour grace */
#define PS_LAPSED  2      /* the tenant plane only: past it */
#define PS_NULL    3
#define PS_REVOKED 4      /* the tenant plane only */
#define PS_EMPTY   5      /* fresh, and listing nothing: every address is absent */

typedef struct {
    const pspec_t  *spec[8];          /* NULL: no records anywhere (an empty plane) */
    int             state[8];
    const we_map_t *map[8][4];        /* fresh, stale, lapsed, fresh-and-empty */
} world_t;

static const we_map_t *revoked_map;

static pspec_t *new_spec(uint32_t plane)
{
    pspec_t *s = (pspec_t *)calloc(1, sizeof *s);

    s->plane = plane;
    s->kind4 = WE_KIND_NONE;
    s->kind6 = WE_KIND_NONE;
    return s;
}

/* add an IPv4 range with a record; ranges must be added in order */
static void add4(pspec_t *s, uint32_t lo, uint32_t hi, const uint8_t *rec, size_t rl)
{
    s->s4[s->n4] = lo;
    s->e4[s->n4] = hi;
    memset(s->r4[s->n4], 0, 32);
    memcpy(s->r4[s->n4], rec, rl);
    s->n4++;
}

static void add6(pspec_t *s, __uint128_t lo, __uint128_t hi, const uint8_t *rec, size_t rl)
{
    s->s6[s->n6] = lo;
    s->e6[s->n6] = hi;
    memset(s->r6[s->n6], 0, 32);
    memcpy(s->r6[s->n6], rec, rl);
    s->n6++;
}

/* a membership record with these flags (and reason), IPv4 layout */
static void mrec4(uint8_t r[16], uint32_t flags, uint8_t reason)
{
    memset(r, 0, 16);
    memcpy(r + 4, &flags, 4);
    r[9] = reason;
}

static void mrec6(uint8_t r[32], uint32_t flags, uint8_t reason)
{
    memset(r, 0, 32);
    memcpy(r + 16, &flags, 4);
    r[21] = reason;
}

static void rrec4(uint8_t r[16], uint32_t asn, uint16_t country, uint8_t rov, uint8_t rir, uint8_t flags, uint8_t rep)
{
    memset(r, 0, 16);
    memcpy(r + 4, &asn, 4);
    memcpy(r + 8, &country, 2);
    r[10] = rov;
    r[11] = rir;
    r[12] = flags;
    r[13] = rep;
}

static void rrec6(uint8_t r[24], uint32_t asn, uint16_t country, uint8_t rov, uint8_t rir, uint8_t flags, uint8_t rep)
{
    memset(r, 0, 24);
    memcpy(r + 8, &asn, 4);
    memcpy(r + 12, &country, 2);
    r[14] = rov;
    r[15] = rir;
    r[16] = flags;
    r[17] = rep;
}

static void world_build(world_t *w)
{
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        static pspec_t empty;

        memset(&empty, 0, sizeof empty);
        empty.plane = p + 1u;
        empty.kind4 = empty.kind6 = WE_KIND_NONE;
        w->map[p][0] = mk_map(w->spec[p] != NULL ? w->spec[p] : &empty, 7u, 0u, 0, NULL, NULL);
        w->map[p][1] = mk_map(w->spec[p] != NULL ? w->spec[p] : &empty, 7u, NOW - 1000u, 0, NULL, NULL);
        w->map[p][2] = mk_map(w->spec[p] != NULL ? w->spec[p] : &empty, 7u, NOW - H48 - 1u, 0, NULL, NULL);
        w->map[p][3] = mk_map(&empty, 7u, 0u, 0, NULL, NULL);
    }
}

static const we_map_t *world_view(const world_t *w, uint32_t p)
{
    switch (w->state[p]) {
    case PS_FRESH:   return w->map[p][0];
    case PS_STALE:   return w->map[p][1];
    case PS_LAPSED:  return w->map[p][2];
    case PS_EMPTY:   return w->map[p][3];
    case PS_REVOKED: return revoked_map;
    default:         return NULL;
    }
}

/* the records the reference reads for a plane in its state: none when the plane lists nothing */
static const pspec_t *world_spec(const world_t *w, uint32_t p)
{
    return w->state[p] == PS_EMPTY ? NULL : w->spec[p];
}

/* ======================================================================================================
 * The reference: K3 as truth tables over values, the fixed order, the definite values of POLICY.md §1.4,
 * read from the test's own records with its own clamps. It shares the compiled instructions with the
 * evaluator (the compiler is held by the corpus and the oracle), never the memo, the fill or the pairs.
 * ==================================================================================================== */

#define RT 1
#define RF 2
#define RU 3

static int ref_not(int a) { return a == RT ? RF : a == RF ? RT : RU; }
static int ref_and(int a, int b) { return (a == RF || b == RF) ? RF : (a == RT && b == RT) ? RT : RU; }
static int ref_or(int a, int b) { return (a == RT || b == RT) ? RT : (a == RF && b == RF) ? RF : RU; }

#define WE_COUNTRY_NO_ALPHA2 1
#include "we_country_table.h"

/* the record bytes for an address on a plane, or NULL; normalised block layout per POLICY.md §2.7 */
static int ref_block(const pspec_t *s, const we_addr_t *a, uint8_t blk[16])
{
    uint32_t i;

    memset(blk, 0, 16);
    if (s == NULL) {
        return 0;
    }
    if (a->family == 4u) {
        uint32_t v = ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16) | ((uint32_t)a->b[2] << 8) | a->b[3];

        for (i = 0u; i < s->n4; i++) {
            if (v >= s->s4[i] && v <= s->e4[i]) {
                if (s->plane == WE_PLANE_REPUTATION) {
                    blk[0] = s->r4[i][0];
                } else if (s->plane == WE_PLANE_ROUTING || s->plane == WE_PLANE_REGISTRY) {
                    memcpy(blk, s->r4[i] + 4, 10);
                } else {
                    memcpy(blk, s->r4[i] + 4, 6);
                }
                return 1;
            }
        }
        return 0;
    }
    {
        __uint128_t v = 0u;
        int k;

        for (k = 0; k < 16; k++) {
            v = (v << 8) | a->b[k];
        }
        if (key6_of(s->plane) == 8u) {
            v >>= 64;
        }
        for (i = 0u; i < s->n6; i++) {
            if (v >= s->s6[i] && v <= s->e6[i]) {
                if (s->plane == WE_PLANE_REPUTATION) {
                    blk[0] = s->r6[i][0];
                } else if (s->plane == WE_PLANE_ROUTING || s->plane == WE_PLANE_REGISTRY) {
                    memcpy(blk, s->r6[i] + 8, 10);
                } else {
                    memcpy(blk, s->r6[i] + 16, 6);
                }
                return 1;
            }
        }
        return 0;
    }
}

static uint32_t plane_mask_of(uint32_t p)
{
    static const uint32_t m[8] = { 0x80u, 0x01u, 0x01u, 0x07u, 0x03u, 0x3fu, 0x07u, 0x03u };

    return m[p];
}

/* one atom's K3 value on a world, from the plane's own records, with the clamps of POLICY.md §1.4 */
static int ref_atom(const we_program_t *prog, const we_instr_t *I, const world_t *w, const we_addr_t *a, int allow_inf)
{
    uint32_t p = I->plane, op = I->op;
    int st = w->state[p];
    uint8_t blk[16];
    int hit, v = 0;
    int stale = st == PS_STALE || st == PS_LAPSED;

    if ((op & WE_OP_ISUNK) != 0u) {
        return (st == PS_NULL || stale) ? RT : RF;
    }
    if (st == PS_NULL) {
        return RU;
    }
    if (st == PS_REVOKED) {
        return RF;                          /* every bit FALSE */
    }
    if (stale && p != 7u) {
        return RU;
    }
    if (stale) {
        int bounded = (op & WE_OP_BOOL) != 0u && (I->imm & WE_BOOL_POLARITY) != 0u;

        if (!bounded) {
            return RU;
        }
        if (st == PS_LAPSED) {
            return RF;
        }
    }
    hit = ref_block(world_spec(w, p), a, blk);
    if (!hit) {
        /* the template: unrouted and undetermined; everything else zero */
        memset(blk, 0, 16);
        if (p == 3u || p == 6u) {
            memset(blk, 0xff, 4);
            blk[6] = 4u;
        }
    } else if (p == 0u) {
        uint8_t nib = (uint8_t)(blk[0] & 15u);

        blk[0] = (uint8_t)((blk[0] & 0x80u) | (nib > 4u ? 4u : nib));
    } else if (p == 3u || p == 6u) {
        uint16_t c;

        memcpy(&c, blk + 4, 2);
        if (c > 999u || ((we_country_known_table[c >> 3] >> (c & 7u)) & 1u) == 0u) {
            c = 0u;
        }
        memcpy(blk + 4, &c, 2);
        blk[6] = blk[6] > 3u ? 0u : blk[6];
        blk[7] = blk[7] > 5u ? 0u : blk[7];
        blk[8] = (uint8_t)(blk[8] & 7u);
        blk[9] = blk[9] > 4u ? 0u : blk[9];
    } else {
        uint32_t fl;

        memcpy(&fl, blk, 4);
        fl &= plane_mask_of(p);
        memcpy(blk, &fl, 4);
        blk[5] = blk[5] > 2u ? 0u : blk[5];
    }
    {
        const uint8_t *b = blk + I->off;

        if (op & WE_OP_BOOL) {
            v = (b[0] & I->imm & 0xffu) != 0u;
        } else if (op & WE_OP_SEV) {
            uint32_t L = b[0] & 15u;

            if ((b[0] & 0x80u) && !allow_inf) {
                L = 0u;
            }
            v = (I->imm >> L) & 1u;
        } else if (op & WE_OP_EQ8) {
            v = b[0] == (uint8_t)I->imm;
        } else if (op & WE_OP_EQ16) {
            uint16_t c;

            memcpy(&c, b, 2);
            v = c == I->imm;
        } else if (op & WE_OP_EQ32) {
            uint32_t x;

            memcpy(&x, b, 4);
            v = x == I->imm;
        } else if (op & WE_OP_INSET_ENUM) {
            v = (I->imm >> b[0]) & 1u;
        } else if (op & WE_OP_INSET_COUNTRY) {
            uint16_t c;

            memcpy(&c, b, 2);
            v = (((const uint8_t *)prog)[I->imm + (c >> 3)] >> (c & 7u)) & 1u;
        } else if (op & WE_OP_INSET_ASN) {
            /* membership by a linear scan of the leaves, never the tree's search */
            uint32_t x, n = WE_ASN_IMM_N(I->imm), lv = WE_ASN_IMM_LEVELS(I->imm), j;
            uint32_t m0 = (n + 15u) / 16u, m1 = (m0 + 16u) / 17u;
            uint32_t leaf = (lv >= 2u ? 64u : 0u) + (lv >= 3u ? m1 * 64u : 0u);
            const uint8_t *pay = (const uint8_t *)prog + WE_ASN_IMM_OFF(I->imm) + leaf;

            memcpy(&x, b, 4);
            if (x == 0xffffffffu) {
                v = (int)WE_ASN_IMM_HASU(I->imm);
            } else {
                for (j = 0u; j < n && !v; j++) {
                    uint32_t k;

                    memcpy(&k, pay + j * 4u, 4);
                    v = k == x;
                }
            }
        }
    }
    return v ? RT : RF;
}

static int ref_rule(const we_program_t *p, const we_rule_t *R, const world_t *w, const we_addr_t *a, int allow_inf)
{
    const we_instr_t *ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
    int st[64], sp = 0;
    uint32_t k;

    for (k = 0u; k < R->instr_count; k++) {
        const we_instr_t *I = &ins[R->instr_start + k];

        if (I->op & WE_OP_ATOM) {
            st[sp++] = ref_atom(p, I, w, a, allow_inf);
        } else if (I->op & WE_OP_NOT) {
            st[sp - 1] = ref_not(st[sp - 1]);
        } else if (I->op & WE_OP_AND) {
            st[sp - 2] = ref_and(st[sp - 2], st[sp - 1]);
            sp--;
        } else if (I->op & WE_OP_OR) {
            st[sp - 2] = ref_or(st[sp - 2], st[sp - 1]);
            sp--;
        }
    }
    return st[0];
}

typedef struct {
    const we_program_t  *floor, *ctx;
    we_ctx_conf_t        fconf, cconf;
    const we_ctx_conf_t *fc, *cc;      /* NULL to pass a NULL conf */
    const we_hh_view_t  *hh;
    we_request_t         req;
    uint64_t             now;
    world_t             *w;
} scen_t;

/* the conf's domain, as a pair: either field outside it and the whole conf is the default (log, off) */
static int conf_ok(const we_ctx_conf_t *c)
{
    return c != NULL && c->mode >= 1u && c->mode <= 3u && c->allow_inferred <= 1u;
}

static int conf_mode(const we_ctx_conf_t *c)
{
    return conf_ok(c) ? (int)c->mode : (int)WE_MODE_LOG;
}

static int conf_inf(const we_ctx_conf_t *c)
{
    return conf_ok(c) ? (int)c->allow_inferred : 0;
}

/* is the floor address in the hold-harmless set? by the generated table itself, linearly */
#include "we_hold_harmless.h"
static int ref_hh(const we_addr_t *a)
{
    uint32_t i;

    if (a->family == 4u) {
        uint32_t v = ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16) | ((uint32_t)a->b[2] << 8) | a->b[3];

        for (i = 0u; i < WE_HH_V4_COUNT; i++) {
            if (v >= we_hh_v4[i][0] && v <= we_hh_v4[i][1]) {
                return 1;
            }
        }
        return 0;
    }
    {
        __uint128_t v = 0u;
        int k;

        for (k = 0; k < 16; k++) {
            v = (v << 8) | a->b[k];
        }
        for (i = 0u; i < WE_HH_V6_COUNT; i++) {
            __uint128_t s = ((__uint128_t)we_hh_v6[i][0] << 64) | we_hh_v6[i][1];
            __uint128_t e = ((__uint128_t)we_hh_v6[i][2] << 64) | we_hh_v6[i][3];

            if (v >= s && v <= e) {
                return 1;
            }
        }
        return 0;
    }
}

static void canon(we_addr_t *a)
{
    we_addr_t o;

    we_addr_canon(a->b, a->family, &o);
    *a = o;
}

static int ref_unknown_plane(const we_rule_t *R, const world_t *w)
{
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        if (((R->dep_mask >> p) & 1u) && (w->state[p] == PS_NULL || w->state[p] == PS_STALE || w->state[p] == PS_LAPSED)) {
            return (int)p + 1;
        }
    }
    return 0;
}

static int ref_unspecified(const we_addr_t *a)
{
    static const uint8_t zero[16];

    return memcmp(a->b, zero, 16) == 0;
}

static void ref_decide(const scen_t *s, we_verdict_t *v)
{
    we_addr_t fa = s->req.floor, sa = s->req.server;
    const world_t *w = s->w;
    int pass, floor_hh, same;

    memset(v, 0, sizeof *v);
    canon(&fa);
    canon(&sa);
    /* a server slot with no address (a family other than 4 or 6, or the unspecified address) names the
     * floor's: the server has no opinion of its own about who connected (POLICY.md section 3.2) */
    if ((s->req.server.family != 4u && s->req.server.family != 6u) || ref_unspecified(&sa)) {
        sa = fa;
    }
    if (s->req.walk == WE_WALK_NO_ADDRESS) {
        v->step = WE_STEP_EXEMPT;
        v->action = WE_ACT_ALLOW;
        v->reason = WE_WHY_NO_ADDRESS;
        return;
    }
    v->marks = s->req.walk == WE_WALK_FLOOR_HEADER_MISSING ? WE_MARK_FLOOR_HEADER_MISSING : 0u;
    /* step 1's hold-harmless lookup is on the floor's address: a hit ends the floor's steps, and ends the
     * request when the server judges the same address; step 4 has no exemption of its own (section 3.2) */
    floor_hh = s->req.hold_harmless_eligible && s->hh != NULL && ref_hh(&fa);
    same = memcmp(fa.b, sa.b, 16) == 0 && fa.family == sa.family;
    if (floor_hh && same) {
        v->step = WE_STEP_EXEMPT;
        v->action = WE_ACT_ALLOW;
        v->reason = WE_WHY_HOLD_HARMLESS;
        return;
    }
    if (s->req.acme_exempt) {
        v->step = WE_STEP_EXEMPT;
        v->action = WE_ACT_ALLOW;
        v->reason = WE_WHY_ACME;
        return;
    }
    if (!floor_hh) {
        uint8_t blk[16];
        int hit = ref_block(world_spec(w, 7u), &fa, blk);
        int allow = hit && (blk[0] & 1u);

        if (w->state[7] == PS_REVOKED) {
            v->marks |= WE_MARK_TENANT_REVOKED;
        }
        if (w->state[7] == PS_FRESH && allow) {
            v->step = WE_STEP_TENANT;
            v->action = WE_ACT_ALLOW;
            v->reason = WE_WHY_TENANT;
            return;
        }
    }
    for (pass = floor_hh ? 1 : 0; pass < 2; pass++) {
        const we_program_t *p = pass == 0 ? s->floor : s->ctx;
        const we_ctx_conf_t *c = pass == 0 ? s->fc : s->cc;
        const we_addr_t *a = pass == 0 ? &fa : &sa;
        int mode = conf_mode(c), inf = conf_inf(c);
        uint32_t r;

        if (pass == 1) {
            uint8_t blk[16];
            int hit = ref_block(world_spec(w, 7u), &fa, blk);

            if (!floor_hh && w->state[7] == PS_STALE && hit && (blk[0] & 1u)) {
                v->step = WE_STEP_STALE_TENANT;
                v->action = WE_ACT_ALLOW;
                v->reason = WE_WHY_TENANT;
                return;
            }
        }
        if (p == NULL || mode == (int)WE_MODE_OFF) {
            continue;
        }
        for (r = 0u; r < p->rule_count; r++) {
            const we_rule_t *R = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off) + r;
            int val;

            if (R->flags & WE_RF_INERT) {
                continue;
            }
            val = ref_rule(p, R, w, a, inf);
            if (R->action == WE_ACT_DENY && val == RT) {
                if (mode != (int)WE_MODE_DENY) {
                    v->log_fired[pass][r >> 3] |= (uint8_t)(1u << (r & 7u));
                    continue;
                }
                v->step = pass == 0 ? WE_STEP_FLOOR : WE_STEP_CONTEXT;
                v->action = WE_ACT_DENY;
                v->program = pass == 0 ? WE_VPROG_FLOOR : WE_VPROG_CONTEXT;
                v->reason = WE_WHY_RULE;
                v->rule = (uint16_t)(r + 1u);
                v->enforce = 1u;
                return;
            }
            if (R->action == WE_ACT_LOG && val == RT) {
                v->log_fired[pass][r >> 3] |= (uint8_t)(1u << (r & 7u));
            }
            if (R->action == WE_ACT_ALLOW && (val == RT || val == RU)) {
                v->step = pass == 0 ? WE_STEP_FLOOR : WE_STEP_CONTEXT;
                v->action = WE_ACT_ALLOW;
                v->program = pass == 0 ? WE_VPROG_FLOOR : WE_VPROG_CONTEXT;
                v->rule = (uint16_t)(r + 1u);
                v->reason = val == RT ? WE_WHY_RULE : WE_WHY_ALLOW_BY_UNKNOWN;
                v->unknown_plane = val == RT ? 0u : (uint8_t)ref_unknown_plane(R, w);
                return;
            }
        }
    }
    v->step = WE_STEP_CONTEXT;
    v->action = WE_ACT_ALLOW;
}

/* ---- running the evaluator on a scenario ---- */

static we_eval_ctx_t *ectx;

static void run(const scen_t *s, we_verdict_t *v)
{
    uint32_t p;

    for (p = 0u; p < 8u; p++) {
        ectx->view[p].m = world_view(s->w, p);
    }
    we_decide(s->floor, s->fc, s->ctx, s->cc, s->hh, &s->req, ectx, s->now, v);
    for (p = 0u; p < 8u; p++) {
        ectx->view[p].m = NULL;                 /* nulled when we_decide returns (POLICY.md §2.7) */
    }
}

static const char *step_name(uint8_t st)
{
    return st == WE_STEP_EXEMPT ? "1" : st == WE_STEP_TENANT ? "2" : st == WE_STEP_FLOOR ? "3"
         : st == WE_STEP_STALE_TENANT ? "3.5" : "4";
}

static void fmt_bitmap(const uint8_t b[32], char *out, size_t n)
{
    size_t o = 0u;
    uint32_t r;

    out[0] = '\0';
    for (r = 0u; r < 256u && o + 8u < n; r++) {
        if ((b[r >> 3] >> (r & 7u)) & 1u) {
            o += (size_t)snprintf(out + o, n - o, "%s%u", o == 0u ? "" : ",", r + 1u);
        }
    }
    if (o == 0u) {
        snprintf(out, n, "-");
    }
}

static void fmt_verdict(const we_verdict_t *v, char *out, size_t n)
{
    static const char *const why[7] = { "none", "allow-by-unknown", "allow-by-hold-harmless", "allow-by-acme",
                                        "allow-by-tenant", "allow-by-no-address", "rule" };
    static const char *const pn[9] = { "", "reputation", "tor", "rpki-unreachable", "routing", "anonymizer",
                                       "threat", "registry", "tenant" };
    char a[1024], b[1024], reason[96];

    fmt_bitmap(v->log_fired[0], a, sizeof a);
    fmt_bitmap(v->log_fired[1], b, sizeof b);
    snprintf(reason, sizeof reason, "%s%s%s%s%s", why[v->reason < 7u ? v->reason : 0u],
             v->reason == WE_WHY_ALLOW_BY_UNKNOWN ? ":" : "",
             v->reason == WE_WHY_ALLOW_BY_UNKNOWN ? pn[v->unknown_plane < 9u ? v->unknown_plane : 0u] : "",
             (v->marks & WE_MARK_FLOOR_HEADER_MISSING) ? "+floor-header-missing" : "",
             (v->marks & WE_MARK_TENANT_REVOKED) ? "+tenant-revoked" : "");
    snprintf(out, n, "verdict %s %s %s %u %s %s %s", step_name(v->step), v->action == WE_ACT_DENY ? "deny" : "allow",
             v->program == WE_VPROG_FLOOR ? "floor" : v->program == WE_VPROG_CONTEXT ? "context" : "none",
             v->rule, reason, a, b);
}

static void fmt_cost(const we_verdict_t *v, char *out, size_t n)
{
    snprintf(out, n, "cost %u %u f:%u,%u,%u,%u,%u,%u,%u,%u/s:%u,%u,%u,%u,%u,%u,%u,%u %u", v->ops_executed, v->jumps_taken,
             v->lookups[0][0], v->lookups[0][1], v->lookups[0][2], v->lookups[0][3], v->lookups[0][4], v->lookups[0][5],
             v->lookups[0][6], v->lookups[0][7], v->lookups[1][0], v->lookups[1][1], v->lookups[1][2], v->lookups[1][3],
             v->lookups[1][4], v->lookups[1][5], v->lookups[1][6], v->lookups[1][7], v->set_probes);
}

static int same_verdict(const we_verdict_t *a, const we_verdict_t *b)
{
    return a->step == b->step && a->action == b->action && a->program == b->program && a->reason == b->reason
        && a->rule == b->rule && a->unknown_plane == b->unknown_plane && a->marks == b->marks
        && a->enforce == b->enforce && memcmp(a->log_fired, b->log_fired, sizeof a->log_fired) == 0;
}

/* evaluate and compare with the reference; returns 1 when they agree */
static long long cases = 0;
static int agree(const scen_t *s, const char *row, const char *what, we_verdict_t *got)
{
    we_verdict_t ref;
    char g[4096], r[4096];

    run(s, got);
    ref_decide(s, &ref);
    cases++;
    fmt_verdict(got, g, sizeof g);
    if (emit) {
        char c[256];

        fmt_cost(got, c, sizeof c);
        printf("%s\n%s\n", g, c);
    }
    if (!same_verdict(got, &ref)) {
        fmt_verdict(&ref, r, sizeof r);
        CHECK(0, "[%s] %s: the evaluator says `%s`, the reference `%s`", row, what, g, r);
        return 0;
    }
    checks++;
    return 1;
}

/* compile lines into a context program (and optional floor lines) in the default environment */
static const we_program_t *ctxprog(const char *const *lines, int n)
{
    we_policy_directive_t d[64];
    we_policy_build_t *b = NULL;
    we_policy_error_t e;
    const we_program_t *p;
    int i, rc;

    for (i = 0; i < n; i++) {
        d[i].kind = lines[i][0] == '@' ? WE_DIR_SET : WE_DIR_POLICY;
        d[i].context = "http/server:a";
        d[i].arg = (const uint8_t *)lines[i];
        d[i].len = strlen(lines[i]);
    }
    rc = compile_src(d, (size_t)n, &b, &e);
    if (rc != WE_POLICY_OK) {
        CHECK(0, "compiles: %s: %s near \"%s\" (%s)", lines[0], e.what, e.token, e.layer);
        return NULL;
    }
    p = ro_prog(we_policy_program(b, "http/server:a"));
    we_policy_build_free(b);
    return p;
}

static const we_program_t *prog1(const char *line)
{
    return ctxprog(&line, 1);
}

static const we_program_t *floorprog(const char *const *lines, int n, const we_program_t **ctx)
{
    we_policy_directive_t d[64];
    we_policy_build_t *b = NULL;
    we_policy_error_t e;
    const we_program_t *p;
    int i, rc;

    memset(d, 0, sizeof d);
    for (i = 0; i < n; i++) {
        d[i].kind = WE_DIR_FLOOR;
        d[i].context = "http";
        d[i].arg = (const uint8_t *)lines[i];
        d[i].len = strlen(lines[i]);
    }
    rc = compile_src(d, (size_t)n, &b, &e);
    if (rc != WE_POLICY_OK) {
        CHECK(0, "compiles: %s: %s", n > 0 ? lines[0] : "(empty floor)", e.what);
        return NULL;
    }
    p = ro_prog(we_policy_floor(b));
    if (ctx != NULL) {
        *ctx = NULL;
    }
    we_policy_build_free(b);
    return p;
}

static void addr4(we_addr_t *a, uint32_t v)
{
    memset(a, 0, sizeof *a);
    a->b[0] = (uint8_t)(v >> 24);
    a->b[1] = (uint8_t)(v >> 16);
    a->b[2] = (uint8_t)(v >> 8);
    a->b[3] = (uint8_t)v;
    a->family = 4u;
}

static void addr6(we_addr_t *a, __uint128_t v)
{
    int k;

    memset(a, 0, sizeof *a);
    for (k = 0; k < 16; k++) {
        a->b[k] = (uint8_t)(v >> (120 - 8 * k));
    }
    a->family = 6u;
}

static void scen_init(scen_t *s, world_t *w, const we_program_t *floor, const we_program_t *ctx, uint32_t addr)
{
    memset(s, 0, sizeof *s);
    s->w = w;
    s->floor = floor;
    s->ctx = ctx;
    s->fconf.mode = WE_MODE_DENY;
    s->cconf.mode = WE_MODE_DENY;
    s->fc = &s->fconf;
    s->cc = &s->cconf;
    addr4(&s->req.floor, addr);
    s->req.server = s->req.floor;
    s->req.hold_harmless_eligible = 1u;
    s->now = NOW;
}

/* ======================================================================================================
 * The standard world: one address per scenario value, every plane with records that make each
 * attribute take each value somewhere
 * ==================================================================================================== */

static world_t W;                  /* bools on tor, anonymizer, threat flagged at A_T, absent at A_F */
static const we_program_t *EMPTY_FLOOR;
static const we_hh_view_t *HH;

#define A_T  0x15000001u           /* 21.0.0.1: listed on every membership plane */
#define A_F  0x15000101u           /* 21.0.1.1: listed nowhere */
#define A_X  0x63000001u           /* 99.0.0.1: in no range of any plane */
#define A_TA 0x15000301u           /* 21.0.3.1: the tenant plane's allow */

static void standard_world(void)
{
    pspec_t *s;
    uint8_t r[32];
    uint32_t p;

    memset(&W, 0, sizeof W);
    for (p = 2u; p <= 8u; p++) {
        if (p == WE_PLANE_ROUTING || p == WE_PLANE_REGISTRY) {
            continue;
        }
        s = new_spec(p);
        /* the tenant plane lists A_T as a deny only, so step 2 never decides for it; A_TA is its allow */
        mrec4(r, p == WE_PLANE_TENANT ? WE_MF_TENANT_DENY : plane_mask_of(p - 1u),
              p == WE_PLANE_RPKI_UNREACHABLE ? 2u : 0u);
        add4(s, A_T, A_T, r, 16);
        mrec4(r, 0u, 0u);
        add4(s, 0x15000200u, 0x150002ffu, r, 16);  /* a range with no flags, elsewhere */
        if (p == WE_PLANE_TENANT) {
            mrec4(r, WE_MF_TENANT_ALLOW, 0u);
            add4(s, A_TA, A_TA, r, 16);
        }
        W.spec[p - 1u] = s;
    }
    s = new_spec(WE_PLANE_REPUTATION);
    r[0] = WE_SEV_HIGH;
    add4(s, A_T, A_T, r, 1);
    W.spec[0] = s;
    s = new_spec(WE_PLANE_ROUTING);
    rrec4(r, 64496u, 528u, 1u, 5u, 1u, 2u);           /* AS64496, NL, valid, RIPE, anycast, neutral */
    add4(s, A_T, A_T, r, 16);
    rrec4(r, 0xffffffffu, 0u, 0u, 0u, 0u, 0u);         /* every field at its sentinel */
    add4(s, A_F, A_F, r, 16);
    W.spec[3] = s;
    s = new_spec(WE_PLANE_REGISTRY);
    rrec4(r, 64497u, 276u, 3u, 3u, 0u, 1u);            /* DE, ARIN */
    add4(s, A_T, A_T, r, 16);
    W.spec[6] = s;
    world_build(&W);
}

/* ---- K1-K6 and the exhaustive leg ---- */

static long long cover_and[16], cover_or[16], cover_not[4], cover_jf[4], cover_jt[4];
static long long cover_act[4][4];
static long long cover_final[4][4];         /* the rule's action by its value at END */
static long long cover_slot[2];
static long long cover_clamp[8];

static int top_val(uint64_t t, uint64_t f, int i)
{
    int tt = (int)((t >> i) & 1u), ff = (int)((f >> i) & 1u);

    return tt ? RT : ff ? RF : RU;
}

void we_trace_op(uint32_t op, uint64_t t, uint64_t f)
{
    if (!cov_k3_on) {
        return;
    }
    if (op & WE_OP_END) {
        if (cov_rule != NULL && cov_rule->action >= 1u && cov_rule->action <= 3u) {
            cover_final[cov_rule->action][top_val(t, f, 0)]++;
        }
    } else if (op & WE_OP_AND) {
        cover_and[top_val(t, f, 1) * 4 + top_val(t, f, 0)]++;
    } else if (op & WE_OP_OR) {
        cover_or[top_val(t, f, 1) * 4 + top_val(t, f, 0)]++;
    } else if (op & WE_OP_NOT) {
        cover_not[top_val(t, f, 0)]++;
    } else if (op & WE_OP_JF) {
        cover_jf[top_val(t, f, 0)]++;
    } else if (op & WE_OP_JT) {
        cover_jt[top_val(t, f, 0)]++;
    }
}

static const char *const exh_templates[] = {
    "a", "not a", "a and b", "a or b", "not a and b", "a and not b", "not a or b", "not (a and b)", "not (a or b)",
    "a and b and c", "a or b or c", "(a and b) or c", "a and (b or c)", "(a or b) and c", "a or (b and c)",
    "not (a and b) or c", "not (a or b) and c", "a and not (b or c)", "(not a or b) and c", "not not a",
};
#define NTEMPL (sizeof exh_templates / sizeof exh_templates[0])

static void subst(const char *tpl, const char *const atoms[3], char *out, size_t n)
{
    size_t o = 0u;

    for (; *tpl != '\0' && o + 32u < n; tpl++) {
        if (*tpl == 'a' || *tpl == 'b' || *tpl == 'c') {
            /* a placeholder is a lone letter: the keywords contain a, n, d, o, r, t only inside words */
            int lone = (tpl[1] == '\0' || tpl[1] == ' ' || tpl[1] == ')');
            int start = (o == 0u || out[o - 1u] == ' ' || out[o - 1u] == '(');

            if (lone && start) {
                o += (size_t)snprintf(out + o, n - o, "%s", atoms[*tpl - 'a']);
                continue;
            }
        }
        out[o++] = *tpl;
    }
    out[o] = '\0';
}

static void test_exhaustive(void)
{
    static const char *const names[3] = { "tor_exit", "proxy", "c2" };
    static const int planes[3] = { 1, 4, 5 };
    static const char *const act[3] = { "allow", "deny", "log" };
    unsigned t, as, a, pos, vals;
    long long before = cases;

    SECTION("K1-K7, X5: every expression of up to three atoms, nesting 2, in every value, against the reference");
#ifdef WE_TEST_NO_EXHAUSTIVE
    printf("  the exhaustive leg is skipped in this build (WE_TEST_NO_EXHAUSTIVE)\n");
    return;
#endif
    for (t = 0u; t < NTEMPL; t++) {
        for (as = 0u; as < 27u; as++) {
            const char *atoms[3];
            char expr[256];

            atoms[0] = names[as % 3u];
            atoms[1] = names[(as / 3u) % 3u];
            atoms[2] = names[(as / 9u) % 3u];
            subst(exh_templates[t], atoms, expr, sizeof expr);
            for (a = 0u; a < 3u; a++) {
                for (pos = 0u; pos < 2u; pos++) {
                    char rule[300];
                    const char *lines[2];
                    const we_program_t *p;

                    snprintf(rule, sizeof rule, "%s if %s", act[a], expr);
                    lines[pos] = rule;
                    lines[1u - pos] = "deny if rpki_unreachable";
                    p = ctxprog(lines, 2);
                    if (p == NULL) {
                        continue;
                    }
                    cov_prog[0] = p;
                    cov_k3_on = 1;
                    for (vals = 0u; vals < 27u; vals++) {
                        scen_t s;
                        we_verdict_t v;
                        unsigned k;
                        int valk[3];

                        scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
                        s.hh = HH;
                        /* per plane: T, the address listed on a fresh plane; F, a fresh plane listing nothing;
                         * U, the view NULL */
                        for (k = 0u; k < 3u; k++) {
                            valk[k] = (int)((vals / (k == 0u ? 1u : k == 1u ? 3u : 9u)) % 3u);
                            W.state[planes[k]] = valk[k] == 0 ? PS_FRESH : valk[k] == 1 ? PS_EMPTY : PS_NULL;
                        }
                        W.state[2] = PS_FRESH;
                        agree(&s, "K2", rule, &v);
                        for (k = 0u; k < 3u; k++) {
                            W.state[planes[k]] = PS_FRESH;
                        }
                        cover_act[a + 1u][v.action]++;
                    }
                    cov_k3_on = 0;
                    cov_prog[0] = NULL;
                    cov_rule = NULL;
                }
            }
        }
    }
    printf("  %lld cases\n", cases - before);
}

/* ---- the cell counts: K7 ---- */
static void check_coverage(void)
{
    int i, zero = 0;

    SECTION("K7: the coverage matrix has no zero cell");
    /*
     * The (op, input pair) cells for AND and OR are the REACHABLE ones: the compiler puts a JF before
     * every right operand of an and-chain, so AND never sees a FALSE left operand (the chain jumped
     * past it), and likewise OR never sees a TRUE one. Those six cells must be exactly zero: a count
     * there is a short-circuit that did not happen.
     */
    for (i = 0; i < 16; i++) {
        int left = i >> 2, right = i & 3;

        if (left == 0 || right == 0) {
            continue;
        }
        if (left == RF) {
            CHECK(cover_and[i] == 0, "[K7] AND with a FALSE left operand ran %lld times: a missed short-circuit",
                  cover_and[i]);
        } else {
            zero += cover_and[i] == 0;
        }
        if (left == RT) {
            CHECK(cover_or[i] == 0, "[K7] OR with a TRUE left operand ran %lld times: a missed short-circuit",
                  cover_or[i]);
        } else {
            zero += cover_or[i] == 0;
        }
    }
    for (i = 1; i < 4; i++) {
        zero += cover_not[i] == 0;
        zero += cover_jf[i] == 0;
        zero += cover_jt[i] == 0;
    }
    for (i = 1; i <= 3; i++) {
        int v;

        for (v = RT; v <= RU; v++) {
            zero += cover_final[i][v] == 0;
        }
    }
    zero += cover_slot[0] == 0;
    zero += cover_slot[1] == 0;
    for (i = 0; i < 7; i++) {
        zero += cover_clamp[i] == 0;
    }
    printf("  AND %lld/%lld/%lld %lld/%lld/%lld %lld/%lld/%lld  OR %lld/%lld/%lld %lld/%lld/%lld %lld/%lld/%lld\n",
           cover_and[5], cover_and[6], cover_and[7], cover_and[9], cover_and[10], cover_and[11], cover_and[13],
           cover_and[14], cover_and[15], cover_or[5], cover_or[6], cover_or[7], cover_or[9], cover_or[10],
           cover_or[11], cover_or[13], cover_or[14], cover_or[15]);
    printf("  NOT %lld/%lld/%lld  JF %lld/%lld/%lld  JT %lld/%lld/%lld  slots shared %lld distinct %lld\n",
           cover_not[1], cover_not[2], cover_not[3], cover_jf[1], cover_jf[2], cover_jf[3], cover_jt[1], cover_jt[2],
           cover_jt[3], cover_slot[0], cover_slot[1]);
    printf("  final allow %lld/%lld/%lld deny %lld/%lld/%lld log %lld/%lld/%lld\n", cover_final[1][RT], cover_final[1][RF],
           cover_final[1][RU], cover_final[2][RT], cover_final[2][RF], cover_final[2][RU], cover_final[3][RT],
           cover_final[3][RF], cover_final[3][RU]);
    CHECK(zero == 0, "[K7] %d cells of the coverage matrix are zero", zero);
}


/* ======================================================================================================
 * K1-K6 by name, X1's cost columns
 * ==================================================================================================== */

/* the value of a condition, observed through `allow if <expr>` above `deny if rpki_unreachable` (TRUE) */
static int observe(const char *expr, int tor, int proxy, int c2, we_verdict_t *v)
{
    char rule[256];
    const char *lines[2];
    const we_program_t *p;
    scen_t s;

    snprintf(rule, sizeof rule, "allow if %s", expr);
    lines[0] = rule;
    lines[1] = "deny if rpki_unreachable";
    p = ctxprog(lines, 2);
    if (p == NULL) {
        return 0;
    }
    scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
    s.hh = HH;
    W.state[1] = tor;
    W.state[4] = proxy;
    W.state[5] = c2;
    W.state[2] = PS_FRESH;
    agree(&s, "K2", rule, v);
    W.state[1] = W.state[4] = W.state[5] = PS_FRESH;
    if (v->reason == WE_WHY_RULE && v->action == WE_ACT_ALLOW) {
        return RT;
    }
    if (v->reason == WE_WHY_ALLOW_BY_UNKNOWN) {
        return RU;
    }
    return RF;
}

#define T_ PS_FRESH
#define F_ PS_EMPTY
#define U_ PS_NULL

static void test_k_rows(void)
{
    we_verdict_t v;

    SECTION("K1, K2: the truth tables, named");
    CHECK(observe("not tor_exit", U_, T_, T_, &v) == RU, "[K1][K2] not U is U");
    CHECK(observe("not tor_exit", T_, T_, T_, &v) == RF, "[K1] not T is F");
    CHECK(observe("not tor_exit", F_, T_, T_, &v) == RT, "[K1] not F is T");
    CHECK(observe("tor_exit and proxy", U_, F_, T_, &v) == RF, "[K2] U and F is F");
    CHECK(observe("tor_exit and proxy", U_, T_, T_, &v) == RU, "[K2] U and T is U");
    CHECK(observe("tor_exit or proxy", U_, T_, T_, &v) == RT, "[K2] U or T is T");
    CHECK(observe("tor_exit or proxy", U_, F_, T_, &v) == RU, "[K2] U or F is U");
    CHECK(observe("not not tor_exit", U_, T_, T_, &v) == RU, "[K2] not not U is U");
    CHECK(observe("(tor_exit and proxy) or c2", U_, F_, T_, &v) == RT, "[K2] (U and F) or T is T");
    CHECK(observe("tor_exit and (proxy or c2)", U_, F_, U_, &v) == RU, "[K2] U and (F or U) is U");
    CHECK(observe("tor_exit and proxy", T_, F_, T_, &v) == RF, "[K2] T and F is F");

    SECTION("K3: a short-circuit never jumps on UNKNOWN");
    {
        const we_program_t *p = prog1("deny if tor_exit and proxy");
        const we_program_t *q = prog1("allow if tor_exit or proxy");
        scen_t s;

        scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
        s.hh = HH;
        W.state[1] = U_;
        W.state[4] = F_;
        agree(&s, "K3", "U and F", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.rule == 0u, "[K3] U and F: the deny does not fire");
        CHECK(v.jumps_taken == 0u, "[K3] U and F: no jump on U (jumps %u)", v.jumps_taken);
        CHECK(v.lookups[0][4] == 1u, "[K3] U and F: proxy is looked up because U does not jump");
        scen_init(&s, &W, EMPTY_FLOOR, q, A_T);
        s.hh = HH;
        W.state[4] = T_;
        agree(&s, "K3", "U or T", &v);
        CHECK(v.reason == WE_WHY_RULE && v.rule == 1u, "[K3] U or T is T: the allow decides");
        CHECK(v.jumps_taken == 0u, "[K3] U or T: no jump on U (jumps %u)", v.jumps_taken);
        W.state[1] = W.state[4] = T_;
    }

    SECTION("K4, K5: allow at UNKNOWN ends evaluation; deny and log act on TRUE only");
    {
        const char *l1[2] = { "allow if tor_exit", "deny if rpki_unreachable" };
        const char *l2[2] = { "deny if tor_exit", "log if proxy" };
        const we_program_t *p = ctxprog(l1, 2), *q = ctxprog(l2, 2);
        scen_t s;

        scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
        s.hh = HH;
        W.state[1] = U_;
        agree(&s, "K4", "allow at U", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.reason == WE_WHY_ALLOW_BY_UNKNOWN && v.rule == 1u && v.unknown_plane == 2u,
              "[K4] allow-by-unknown, rule 1, plane tor; the later deny does not fire");
        scen_init(&s, &W, EMPTY_FLOOR, q, A_T);
        s.hh = HH;
        W.state[4] = U_;
        agree(&s, "K5", "deny and log at U", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.rule == 0u && v.log_fired[1][0] == 0u,
              "[K5] neither the deny nor the log fires at U");
        W.state[1] = W.state[4] = T_;
    }

    SECTION("X1: the cost columns move with the memo and the short-circuit");
    {
        const we_program_t *p = prog1("deny if tor_exit and tor_exit and tor_exit");
        const we_program_t *q = prog1("deny if tor_exit and proxy");
        scen_t s;

        scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
        s.hh = HH;
        agree(&s, "X1", "memo", &v);
        CHECK(v.lookups[0][1] == 1u, "[X1] three reads of tor_exit cost one lookup (%u)", v.lookups[0][1]);
        CHECK(v.jumps_taken == 0u && v.ops_executed == 8u, "[X1] T and T and T: 8 instructions (BOOL JF BOOL AND JF BOOL AND END), no jump (%u, %u)",
              v.ops_executed, v.jumps_taken);
        scen_init(&s, &W, EMPTY_FLOOR, q, A_T);
        s.hh = HH;
        W.state[1] = F_;
        agree(&s, "X1", "short-circuit", &v);
        CHECK(v.jumps_taken == 1u, "[X1] F and ...: the JF is taken (%u)", v.jumps_taken);
        CHECK(v.lookups[0][4] == 0u, "[X1] F and proxy: proxy is never looked up (%u)", v.lookups[0][4]);
        CHECK(v.ops_executed == 3u, "[X1] F and proxy: BOOL, JF, END (%u)", v.ops_executed);
        W.state[1] = T_;
    }
}

/* ======================================================================================================
 * F1-F5: the order
 * ==================================================================================================== */

static void test_f_rows(void)
{
    we_verdict_t v;
    scen_t s;

    SECTION("F1: first match wins; log records and continues");
    {
        const char *a[2] = { "allow if tor_exit", "deny if proxy" };
        const char *b[2] = { "deny if proxy", "allow if tor_exit" };
        const char *c[2] = { "log if tor_exit", "deny if proxy" };
        const char *d[2] = { "log if tor_exit", "log if proxy" };

        scen_init(&s, &W, EMPTY_FLOOR, ctxprog(a, 2), A_T);
        s.hh = HH;
        agree(&s, "F1", "allow above deny", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.rule == 1u, "[F1] allow above deny: the allow decides");
        s.ctx = ctxprog(b, 2);
        agree(&s, "F1", "deny above allow", &v);
        CHECK(v.action == WE_ACT_DENY && v.rule == 1u && v.enforce == 1u, "[F1] deny above allow: the deny decides");
        s.ctx = ctxprog(c, 2);
        agree(&s, "F1", "log then deny", &v);
        CHECK(v.action == WE_ACT_DENY && v.rule == 2u && v.log_fired[1][0] == 0x01u,
              "[F1] log then deny: the log is recorded and the deny decides");
        s.ctx = ctxprog(d, 2);
        agree(&s, "F1", "two logs", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.rule == 0u && v.log_fired[1][0] == 0x03u,
              "[F1] two logs, then the default allow; both bits set");
    }

    SECTION("F2: mode log downgrades every deny; mode off evaluates nothing in step 4");
    {
        const char *a[2] = { "deny if tor_exit", "deny if proxy" };
        const char *fl[1] = { "log if proxy" };
        const we_program_t *ctx = ctxprog(a, 2), *floor = floorprog(fl, 1, NULL);
        const we_rule_t *ru = (const we_rule_t *)(const void *)((const uint8_t *)ctx + ctx->rules_off);

        scen_init(&s, &W, EMPTY_FLOOR, ctx, A_T);
        s.hh = HH;
        s.cconf.mode = WE_MODE_LOG;
        agree(&s, "F2", "mode log", &v);
        CHECK(v.action == WE_ACT_ALLOW && v.log_fired[1][0] == 0x03u && ru[0].action == WE_ACT_DENY,
              "[F2] mode log: both denies downgraded to logs, the action byte still deny");
        scen_init(&s, &W, floor, ctx, A_T);
        s.hh = ro_hh(floor);
        s.cconf.mode = WE_MODE_OFF;
        agree(&s, "F2", "mode off", &v);
        CHECK(v.ops_ctx == 0u && v.ops_floor > 0u && v.log_fired[0][0] == 0x01u,
              "[F2] mode off: step 4 executes nothing (%u) while the floor does (%u)", v.ops_ctx, v.ops_floor);
    }

    SECTION("F3: the fixed order");
    {
        const char *fl[1] = { "deny if listed >= none" };
        const char *ca[1] = { "allow if tor_exit" };
        const we_program_t *floor = floorprog(fl, 1, NULL), *ctx = ctxprog(ca, 1);
        const we_hh_view_t *hh = ro_hh(floor);

        scen_init(&s, &W, floor, ctx, 0xc6290004u);                 /* 198.41.0.4, a.root-servers.net */
        s.hh = hh;
        agree(&s, "F3", "hold-harmless", &v);
        CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS, "[F3] a root server: step 1 under a floor deny");
        s.req.hold_harmless_eligible = 0u;
        agree(&s, "F3", "hold-harmless, not eligible", &v);
        CHECK(v.step == WE_STEP_FLOOR && v.action == WE_ACT_DENY, "[F3] reached past a skipped hop: no exemption, denied");
        s.req.hold_harmless_eligible = 1u;
        s.req.floor.b[0] = 0u;
        s.req.floor.b[1] = 0u;
        s.req.floor.b[2] = 0u;
        s.req.floor.b[3] = 0u;
        memset(s.req.floor.b, 0, 16);
        s.req.floor.b[10] = 0xffu;
        s.req.floor.b[11] = 0xffu;
        s.req.floor.b[12] = 198u;
        s.req.floor.b[13] = 41u;
        s.req.floor.b[14] = 0u;
        s.req.floor.b[15] = 4u;
        s.req.floor.family = 6u;
        agree(&s, "F3", "::ffff: hold-harmless", &v);
        CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS, "[F3] ::ffff:198.41.0.4 is exempt too");
        scen_init(&s, &W, floor, ctx, A_T);
        s.hh = hh;
        s.req.acme_exempt = 1u;
        agree(&s, "F3", "acme", &v);
        CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_ACME, "[F3] ACME under a floor deny: step 1");
        s.req.acme_exempt = 0u;
        addr4(&s.req.floor, A_TA);                              /* the tenant plane's allow */
        s.req.server = s.req.floor;
        agree(&s, "F3", "tenant", &v);
        CHECK(v.step == WE_STEP_TENANT && v.reason == WE_WHY_TENANT, "[F3] a tenant allow under a floor deny: step 2");
        addr4(&s.req.floor, A_T);
        s.req.server = s.req.floor;
        agree(&s, "F3", "floor over context", &v);
        CHECK(v.step == WE_STEP_FLOOR && v.action == WE_ACT_DENY, "[F3] a floor deny under a context allow: step 3");
    }

    SECTION("F5: no programs at all, and no floor directive anywhere");
    {
        scen_init(&s, &W, NULL, NULL, 0xc6290004u);
        s.hh = HH;
        agree(&s, "F5", "two NULL programs", &v);
        CHECK(v.reason == WE_WHY_HOLD_HARMLESS, "[F5] two NULL programs: steps 1 to 3.5 still run, the root is exempt");
        scen_init(&s, &W, NULL, NULL, A_T);
        s.hh = HH;
        W.state[7] = PS_EMPTY;
        agree(&s, "F5", "tenant filled", &v);
        CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_ALLOW, "[F5] two NULL programs: the default allow");
        {
            /* the tenant entry is filled with both programs NULL: run by hand and look at the slot */
            uint32_t p;

            for (p = 0u; p < 8u; p++) {
                ectx->view[p].m = world_view(&W, p);
            }
            we_decide(NULL, NULL, NULL, NULL, HH, &s.req, ectx, NOW, &v);
            CHECK(ectx->slot[0].state[7] == WE_ST_FRESH_NR, "[F5] the tenant entry is filled (state %u)",
                  ectx->slot[0].state[7]);
        }
        scen_init(&s, &W, NULL, prog1("deny if tor_exit"), 0xc6290004u);
        s.hh = HH;
        agree(&s, "F5", "floor NULL with a context program", &v);
        CHECK(v.reason == WE_WHY_HOLD_HARMLESS, "[F5] floor NULL, a context deny: the root is still exempt");
        W.state[7] = PS_FRESH;
    }
}

/* ======================================================================================================
 * F4 and D1's tenant rows: the five states, per rule
 * ==================================================================================================== */

static world_t TW;    /* the tenant plane lists TA as allow and TD as deny; TX nowhere */
#define TA 0x0b000001u
#define TD 0x0b000002u
#define TX 0x0b000003u

static void tenant_world(void)
{
    pspec_t *s = new_spec(WE_PLANE_TENANT), *r = new_spec(WE_PLANE_REPUTATION);
    uint8_t rec[32];

    memset(&TW, 0, sizeof TW);
    mrec4(rec, WE_MF_TENANT_ALLOW, 0u);
    add4(s, TA, TA, rec, 16);
    mrec4(rec, WE_MF_TENANT_DENY, 0u);
    add4(s, TD, TD, rec, 16);
    TW.spec[7] = s;
    rec[0] = WE_SEV_LOW;
    add4(r, TA, TX, rec, 1);                 /* every tenant address is listed low on reputation */
    TW.spec[0] = r;
    world_build(&TW);
}

static int tenant_case(const char *const *lines, int n, int state, uint32_t addr, uint64_t now, we_verdict_t *v,
                       const char *what)
{
    const we_program_t *p = ctxprog(lines, n);
    scen_t s;

    if (p == NULL) {
        return 0;
    }
    scen_init(&s, &TW, EMPTY_FLOOR, p, addr);
    s.hh = HH;
    s.now = now;
    TW.state[7] = state;
    return agree(&s, "F4", what, v);
}

/* ======================================================================================================
 * F6: behind a proxy the server's realip trusts. Step 1's hold-harmless lookup is on the floor's address
 * and exempts the floor's steps; it ends the request only when the server judges the same address. Step 4
 * judges the server's address by the context's rules as written: no address a header carries earns an
 * exemption, and a server slot with no address names the floor's (POLICY.md section 3.2).
 * ==================================================================================================== */

static void zero_server(scen_t *s, uint8_t family)
{
    memset(&s->req.server, 0, sizeof s->req.server);
    s->req.server.family = family;
}

static void test_proxy_rows(void)
{
    static const char *ntor[1] = { "deny if not tor_exit" };
    static const char *const dflt[4] = { "deny if listed >= critical", "deny if listed >= high", "log if rpki_unreachable",
                                         "log if tor_exit" };
    static const uint32_t spoof[4] = { 0x08080808u, 0x7f000001u, 0x0a000001u, 0xc6290004u };
    static const char *const sname[4] = { "8.8.8.8", "127.0.0.1", "10.0.0.1", "198.41.0.4" };
    const we_program_t *deny_tor = prog1("deny if tor_exit"), *deny_not_tor = prog1("deny if not tor_exit");
    const we_program_t *allow_only = prog1("deny if not tenant_allow");     /* an allowlisted admin location */
    const we_program_t *floor_all = floorprog(ntor, 1, NULL), *def = ctxprog(dflt, 4);
    const uint32_t LOOP = 0x7f000001u, ROOT = 0xc6290004u;   /* 127.0.0.1; 198.41.0.4, a.root-servers.net */
    we_verdict_t v;
    scen_t s;
    int i;

    SECTION("F6: behind a proxy the server's realip trusts, step 4 judges the client by the context's rules as written");
    /* a listed client behind a loopback proxy that only the server's realip trusts: the peer is
     * hold-harmless, which exempts the floor's steps, and step 4 judges the client the server derived */
    scen_init(&s, &W, EMPTY_FLOOR, deny_tor, LOOP);
    addr4(&s.req.server, A_T);
    s.hh = HH;
    agree(&s, "F6", "a listed client behind a realip-only loopback proxy", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY && v.enforce,
          "[F6] a listed client behind a realip-only loopback proxy was not denied (step %u action %u reason %u)",
          v.step, v.action, v.reason);
    /* the same client through the module's own trust list: the floor walked to the client */
    scen_init(&s, &W, EMPTY_FLOOR, deny_tor, A_T);
    s.hh = HH;
    agree(&s, "F6", "the module's trust list walked to the listed client", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
          "[F6] a listed client the module's trust list walked to was not denied (step %u)", v.step);
    /* an untrusted peer's header is read by no one: the floor and the server judge the peer */
    scen_init(&s, &W, EMPTY_FLOOR, deny_tor, A_F);
    s.hh = HH;
    agree(&s, "F6", "an untrusted peer judged as itself", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_ALLOW,
          "[F6] an unlisted untrusted peer was not judged as itself (step %u action %u)", v.step, v.action);
    /* a hold-harmless client behind a proxy is judged by the context's rules as written: an operator's
     * `deny if not tor_exit` denies a.root-servers.net behind a public proxy and behind the loopback one */
    scen_init(&s, &W, EMPTY_FLOOR, deny_not_tor, A_F);
    addr4(&s.req.server, ROOT);
    s.hh = HH;
    agree(&s, "F6", "a root server behind a public proxy, an operator's rule", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY && v.reason == WE_WHY_RULE,
          "[F6] a hold-harmless client behind a public proxy was exempt from the context's rules (step %u action %u reason %u)",
          v.step, v.action, v.reason);
    scen_init(&s, &W, EMPTY_FLOOR, deny_not_tor, LOOP);
    addr4(&s.req.server, ROOT);
    s.hh = HH;
    agree(&s, "F6", "a root server behind a loopback proxy, an operator's rule", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY && v.reason == WE_WHY_RULE,
          "[F6] a hold-harmless client behind a loopback proxy was exempt from the context's rules (step %u action %u reason %u)",
          v.step, v.action, v.reason);
    /* under the DEFAULT policy the same root server is allowed because it is listed nowhere, not because it
     * is exempt: step 4 ran every rule and none fired (the feed never flags a hold-harmless prefix) */
    scen_init(&s, &W, EMPTY_FLOOR, def, LOOP);
    addr4(&s.req.server, ROOT);
    s.hh = HH;
    agree(&s, "F6", "a root server behind a loopback proxy, the default policy", &v);
    CHECK(def != NULL && v.step == WE_STEP_CONTEXT && v.action == WE_ACT_ALLOW && v.reason == WE_WHY_NONE,
          "[F6] a root server behind a loopback proxy under the default policy was not the default allow (step %u action %u reason %u)",
          v.step, v.action, v.reason);
    /* and the default policy denies the listed client behind the same proxy, by its high rule */
    scen_init(&s, &W, EMPTY_FLOOR, def, LOOP);
    addr4(&s.req.server, A_T);
    s.hh = HH;
    agree(&s, "F6", "a listed client behind a loopback proxy, the default policy", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY && v.rule == 2u,
          "[F6] a high-listed client behind a loopback proxy under the default policy was not denied by rule 2 (step %u action %u rule %u)",
          v.step, v.action, v.rule);
    /* the proxy itself is never denied: the floor's rules do not judge a hold-harmless peer, and with no
     * realip the proxy's own request is exempt as before */
    scen_init(&s, &W, floor_all, NULL, LOOP);
    addr4(&s.req.server, A_T);
    s.hh = HH;
    agree(&s, "F6", "the floor's rules and a hold-harmless proxy", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_ALLOW,
          "[F6] the floor judged the hold-harmless proxy (step %u action %u)", v.step, v.action);
    scen_init(&s, &W, floor_all, deny_not_tor, LOOP);
    s.hh = HH;
    agree(&s, "F6", "the proxy's own request", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS,
          "[F6] the proxy's own request was not exempt (step %u)", v.step);
    /* ACME through the proxy is still exempt */
    scen_init(&s, &W, EMPTY_FLOOR, deny_tor, LOOP);
    addr4(&s.req.server, A_T);
    s.req.acme_exempt = 1u;
    s.hh = HH;
    agree(&s, "F6", "ACME behind a loopback proxy", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_ACME, "[F6] ACME behind a loopback proxy was not exempt (step %u)",
          v.step);

    /* a client-chosen realip address earns nothing an arbitrary address does not: a vhost that trusts the
     * header from anyone, under an allowlist-shaped rule. The control first: an arbitrary spoofed address */
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, A_T);
    addr4(&s.req.server, A_F);
    s.hh = HH;
    agree(&s, "F6", "a spoofed unlisted address under `deny if not tenant_allow`", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
          "[F6] an arbitrary spoofed address under `deny if not tenant_allow` was not denied (step %u action %u reason %u)",
          v.step, v.action, v.reason);
    for (i = 0; i < 4; i++) {
        scen_init(&s, &W, EMPTY_FLOOR, allow_only, A_T);
        addr4(&s.req.server, spoof[i]);
        s.hh = HH;
        agree(&s, "F6", "a spoofed hold-harmless-shaped address under `deny if not tenant_allow`", &v);
        CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
              "[F6] a spoofed realip %s under `deny if not tenant_allow` was not denied at step 4 (step %u action %u reason %u)",
              sname[i], v.step, v.action, v.reason);
    }
    /* the floor's walk marked not eligible (an address a client could have planted), and the same spoof */
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, A_T);
    addr4(&s.req.server, LOOP);
    s.req.hold_harmless_eligible = 0u;
    s.hh = HH;
    agree(&s, "F6", "a not-eligible floor and a spoofed 127.0.0.1", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
          "[F6] a not-eligible floor and a spoofed realip 127.0.0.1 was not denied at step 4 (step %u action %u reason %u)",
          v.step, v.action, v.reason);

    /* a server slot with no address (a unix-socket listener with no realip, family 0; the unspecified
     * address; a family byte outside {4, 6}) names the floor's: a listed client is judged as itself */
    for (i = 0; i < 4; i++) {
        static const uint8_t fam[4] = { 0u, 6u, 4u, 5u };

        scen_init(&s, &W, EMPTY_FLOOR, deny_tor, A_T);
        zero_server(&s, fam[i]);
        if (i == 3) {
            memset(s.req.server.b, 0xa5, 16);                 /* any bytes: the family says no address */
        }
        s.hh = HH;
        agree(&s, "F6", "a server slot with no address", &v);
        CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
              "[F6] a server slot with no address (family %u) did not judge the floor's listed client (step %u action %u reason %u)",
              fam[i], v.step, v.action, v.reason);
    }
    /* and behind a hold-harmless floor it is one address, the floor's: exempt */
    scen_init(&s, &W, EMPTY_FLOOR, deny_not_tor, LOOP);
    zero_server(&s, 0u);
    s.hh = HH;
    agree(&s, "F6", "a hold-harmless floor and a server slot with no address", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS,
          "[F6] a hold-harmless floor and a server slot with no address was not exempt (step %u action %u)", v.step, v.action);

    /* canonical compare: every form of one address is one address, and two addresses are two */
    scen_init(&s, &W, EMPTY_FLOOR, deny_not_tor, LOOP);
    memset(s.req.server.b, 0, 16);
    s.req.server.b[10] = s.req.server.b[11] = 0xffu;
    s.req.server.b[12] = 127u;
    s.req.server.b[15] = 1u;
    s.req.server.family = 6u;
    s.hh = HH;
    agree(&s, "F6", "::ffff:127.0.0.1 behind 127.0.0.1", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS,
          "[F6] ::ffff:127.0.0.1 behind 127.0.0.1 was judged as another address (step %u action %u)", v.step, v.action);
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, LOOP);
    memset(s.req.floor.b, 0, 16);
    s.req.floor.b[10] = s.req.floor.b[11] = 0xffu;
    s.req.floor.b[12] = 127u;
    s.req.floor.b[15] = 1u;
    s.req.floor.family = 6u;
    addr4(&s.req.server, LOOP);
    s.hh = HH;
    agree(&s, "F6", "a mapped floor before an IPv4 server", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS,
          "[F6] a ::ffff:127.0.0.1 floor before a 127.0.0.1 server was judged as two addresses (step %u)", v.step);
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, LOOP);
    memset(s.req.server.b + 4, 0xa5, 12);
    memset(s.req.floor.b + 4, 0x5a, 12);
    s.hh = HH;
    agree(&s, "F6", "IPv4 with junk past byte 4 on either side", &v);
    CHECK(v.step == WE_STEP_EXEMPT && v.reason == WE_WHY_HOLD_HARMLESS,
          "[F6] two IPv4 forms of 127.0.0.1 with junk tails were judged as two addresses (step %u)", v.step);
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, LOOP);
    memset(s.req.server.b, 0, 16);
    s.req.server.b[8] = s.req.server.b[9] = 0xffu;            /* ::ffff:0:127.0.0.1, SIIT, is not 127.0.0.1 */
    s.req.server.b[12] = 127u;
    s.req.server.b[15] = 1u;
    s.req.server.family = 6u;
    s.hh = HH;
    agree(&s, "F6", "the SIIT form behind 127.0.0.1", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
          "[F6] ::ffff:0:127.0.0.1 behind 127.0.0.1 was judged as the proxy (step %u action %u)", v.step, v.action);
    scen_init(&s, &W, EMPTY_FLOOR, allow_only, LOOP);
    addr6(&s.req.server, (__uint128_t)0x7f000001u);          /* ::127.0.0.1, IPv4-compatible, is not 127.0.0.1 */
    s.hh = HH;
    agree(&s, "F6", "the IPv4-compatible form behind 127.0.0.1", &v);
    CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
          "[F6] ::127.0.0.1 behind 127.0.0.1 was judged as the proxy (step %u action %u)", v.step, v.action);

    /* the tenant entry is never read for the client behind a hold-harmless floor: the floor's entry is not
     * filled, so neither step 2 nor 3.5 allows the client, and step 4 judges it, in every tenant state */
    {
        static const int states[3] = { PS_FRESH, PS_STALE, PS_REVOKED };
        const we_program_t *p = prog1("deny if listed >= low");

        for (i = 0; i < 3; i++) {
            scen_init(&s, &TW, EMPTY_FLOOR, p, LOOP);
            addr4(&s.req.server, TA);
            s.hh = HH;
            TW.state[7] = states[i];
            agree(&s, "F6", "the tenant's allow behind a hold-harmless floor", &v);
            CHECK(v.step == WE_STEP_CONTEXT && v.action == WE_ACT_DENY,
                  "[F6] tenant state %d: a tenant-allowed client behind a hold-harmless floor was not judged at step 4 (step %u action %u reason %u)",
                  states[i], v.step, v.action, v.reason);
        }
        TW.state[7] = PS_FRESH;
    }
}

static void test_tenant(void)
{
    static const int states[5] = { PS_FRESH, PS_STALE, PS_LAPSED, PS_NULL, PS_REVOKED };
    static const char *const sn[5] = { "FRESH", "GRACE", "LAPSED", "NULL", "REVOKED" };
    we_verdict_t v;
    int i;

    SECTION("F4, D1: the tenant plane in each of its five states, per rule");
    for (i = 0; i < 5; i++) {
        const char *a1[2] = { "allow if tenant_allow", "deny if listed >= low" };
        const char *a2[1] = { "deny if not tenant_allow" };
        const char *a3[2] = { "allow if not tenant_allow", "deny if listed >= low" };
        const char *a4[1] = { "deny if tenant_deny" };
        const char *a5[2] = { "allow if not tenant_deny", "deny if listed >= low" };
        const char *a6[2] = { "allow if tenant_allow is unknown", "deny if listed >= low" };
        int st = states[i];

        /* the bounded occurrence: decides for listed addresses in FRESH and GRACE, for none in LAPSED and
         * REVOKED, captures under NULL; FRESH is decided by step 2 before step 4 */
        tenant_case(a1, 2, st, TA, NOW, &v, "allow if tenant_allow, listed");
        CHECK(st == PS_FRESH ? v.step == WE_STEP_TENANT
            : st == PS_STALE ? v.step == WE_STEP_STALE_TENANT
            : st == PS_NULL ? (v.reason == WE_WHY_ALLOW_BY_UNKNOWN && v.rule == 1u)
            : (v.action == WE_ACT_DENY && v.rule == 2u),
              "[F4] %s: allow if tenant_allow on a listed address", sn[i]);
        tenant_case(a2, 1, st, TX, NOW, &v, "deny if not tenant_allow");
        CHECK(st == PS_FRESH ? v.action == WE_ACT_DENY
            : st == PS_REVOKED ? v.action == WE_ACT_DENY : v.action == WE_ACT_ALLOW,
              "[F4] %s: deny if not tenant_allow never fires in GRACE, LAPSED or NULL", sn[i]);
        tenant_case(a3, 2, st, TA, NOW, &v, "allow if not tenant_allow");
        if (st == PS_STALE || st == PS_LAPSED || st == PS_NULL) {
            CHECK(v.reason == WE_WHY_ALLOW_BY_UNKNOWN || v.step == WE_STEP_STALE_TENANT,
                  "[F4] %s: allow if not tenant_allow captures", sn[i]);
        }
        tenant_case(a4, 1, st, TD, NOW, &v, "deny if tenant_deny");
        CHECK((v.action == WE_ACT_DENY) == (st == PS_FRESH), "[F4] %s: deny if tenant_deny fires only in FRESH", sn[i]);
        tenant_case(a5, 2, st, TX, NOW, &v, "allow if not tenant_deny");
        if (st == PS_STALE || st == PS_LAPSED) {
            CHECK(v.reason == WE_WHY_ALLOW_BY_UNKNOWN, "[F4] %s: allow if not tenant_deny captures while stale", sn[i]);
        }
        tenant_case(a6, 2, st, TX, NOW, &v, "allow if tenant_allow is unknown");
        CHECK((v.action == WE_ACT_ALLOW && v.rule == 1u) == (st == PS_STALE || st == PS_LAPSED || st == PS_NULL),
              "[F4] %s: allow if tenant_allow is unknown fires exactly in GRACE, LAPSED and NULL", sn[i]);
    }
    {
        we_policy_build_t *b = NULL;
        we_policy_error_t e;

        CHECK(compile1("deny if tenant_deny is unknown", &b, &e) == WE_POLICY_REFUSED && strcmp(e.layer, "polarity") == 0,
              "[F4] deny if tenant_deny is unknown is refused by the polarity pass");
    }
    {
        /* the 48-hour boundary: inclusive at valid_until + 48 h, lapsed one ms past */
        const char *a1[2] = { "allow if tenant_allow", "deny if listed >= low" };
        const char *a2[1] = { "deny if not tenant_allow" };
        const char *fl[1] = { "deny if listed >= low" };
        const we_program_t *floor = floorprog(fl, 1, NULL);
        scen_t s;
        uint64_t vu = NOW - 1000u;                                    /* the stale map's valid_until_ms */

        scen_init(&s, &TW, floor, NULL, TA);
        s.hh = ro_hh(floor);
        TW.state[7] = PS_STALE;
        s.now = vu + H48;
        agree(&s, "F4", "stale tenant at +48 h exactly", &v);
        CHECK(v.step == WE_STEP_FLOOR && v.action == WE_ACT_DENY,
              "[F4] the floor runs before step 3.5: a floor deny still decides for a stale-allowed address");
        scen_init(&s, &TW, EMPTY_FLOOR, ctxprog(a1, 2), TA);
        s.hh = HH;
        s.now = vu + H48;
        agree(&s, "F4", "grace edge", &v);
        CHECK(v.step == WE_STEP_STALE_TENANT, "[F4] valid_until + 48 h exactly: still inside the grace (inclusive)");
        tenant_case(a2, 1, PS_STALE, TX, vu + H48 + 1u, &v, "lapse + 1 ms");
        CHECK(v.action == WE_ACT_ALLOW, "[F4] deny if not tenant_allow at lapse + 1 ms does not deny (U)");
        /* the address added after the plane went stale: absent from the stale record */
        tenant_case(a2, 1, PS_STALE, TX, NOW, &v, "late address, deny if not");
        CHECK(v.action == WE_ACT_ALLOW, "[F4] a late-added address is not denied by deny if not tenant_allow");
        tenant_case(a1, 2, PS_STALE, TX, NOW, &v, "late address, positive allow");
        CHECK(v.action == WE_ACT_DENY && v.rule == 2u,
              "[F4] the late-added address IS denied under the positive allow above deny if listed >= low, by design");
        {
            uint32_t p;

            for (p = 0u; p < 8u; p++) {
                ectx->view[p].m = world_view(&TW, p);
            }
            we_decide(NULL, NULL, NULL, NULL, HH, &s.req, ectx, NOW, &v);
            CHECK(ectx->slot[0].state[7] == WE_ST_STALE_HIT, "[F4] a STALE tenant fill writes stale-hit, never unknown (%u)",
                  ectx->slot[0].state[7]);
        }
    }
    {
        /* valid_until_ms 0 never goes stale; UINT64_MAX - 1 is never past */
        pspec_t *s = new_spec(WE_PLANE_TENANT);
        uint8_t rec[32];
        const we_map_t *m0, *mx;
        uint32_t p;
        we_request_t req;

        mrec4(rec, WE_MF_TENANT_ALLOW, 0u);
        add4(s, TA, TA, rec, 16);
        m0 = mk_map(s, 9u, 0u, 0, NULL, NULL);
        mx = mk_map(s, 9u, UINT64_MAX - 1u, 0, NULL, NULL);
        memset(&req, 0, sizeof req);
        addr4(&req.floor, TA);
        req.server = req.floor;
        for (p = 0u; p < 8u; p++) {
            ectx->view[p].m = NULL;
        }
        ectx->view[7].m = m0;
        we_decide(NULL, NULL, NULL, NULL, HH, &req, ectx, UINT64_MAX, &v);
        CHECK(v.step == WE_STEP_TENANT, "[F4] valid_until_ms 0 is never stale, at any clock");
        ectx->view[7].m = mx;
        we_decide(NULL, NULL, NULL, NULL, HH, &req, ectx, UINT64_MAX - 1u, &v);
        CHECK(v.step == WE_STEP_TENANT, "[F4] valid_until_ms UINT64_MAX - 1 is fresh at that clock, no wrap");
        ectx->view[7].m = NULL;
        free(s);
    }
    TW.state[7] = PS_FRESH;
}

/* ======================================================================================================
 * D1 over every state vector; D2 the classifier and its soundness; D3 revocation; D4-D6
 * ==================================================================================================== */

static void test_state_vectors(void)
{
    static const char *const progs[][3] = {
        { "deny if tor_exit", "deny if listed >= low", "log if proxy" },
        { "allow if tor_exit or asn in { 64496 }", "deny if c2", "deny if listed >= high" },
        { "allow if tenant_allow", "deny if c2", NULL },
        { "log if tor_exit is unknown", "deny if not country in { NL } and c2", "allow if proxy" },
    };
    unsigned pi, vec;
    long long before = cases;

    SECTION("D1: final verdicts over every reduced state vector (two per plane, five for the tenant plane)");
    for (pi = 0u; pi < sizeof progs / sizeof progs[0]; pi++) {
        const char *lines[3];
        int n = 0;
        const we_program_t *p;

        while (n < 3 && progs[pi][n] != NULL) {
            lines[n] = progs[pi][n];
            n++;
        }
        p = ctxprog(lines, n);
        if (p == NULL) {
            continue;
        }
        /* the planes the program reads, plus the tenant plane */
        for (vec = 0u; vec < 5u * 128u; vec++) {
            uint32_t pl, bits = vec % 128u, t = vec / 128u;
            static const int ts[5] = { PS_FRESH, PS_STALE, PS_LAPSED, PS_NULL, PS_REVOKED };
            scen_t s;
            we_verdict_t v;
            uint32_t addr;

            if ((bits & ~(uint32_t)p->plane_mask) != 0u) {
                continue;
            }
            for (pl = 0u; pl < 7u; pl++) {
                W.state[pl] = ((bits >> pl) & 1u) ? PS_STALE : PS_FRESH;
            }
            W.state[7] = ts[t];
            for (addr = 0u; addr < 3u; addr++) {
                scen_init(&s, &W, EMPTY_FLOOR, p, addr == 0u ? A_T : addr == 1u ? A_F : A_X);
                s.hh = HH;
                agree(&s, "D1", progs[pi][0], &v);
            }
        }
    }
    for (vec = 0u; vec < 8u; vec++) {
        W.state[vec] = PS_FRESH;
    }
    printf("  %lld state-vector cases\n", cases - before);
}

static const char *cls_name(uint8_t c)
{
    return c == WE_CLASS_INERT ? "inert" : c == WE_CLASS_NARROWED ? "narrowed" : c == WE_CLASS_CAPTURES ? "captures"
         : c == WE_CLASS_UNAFFECTED ? "unaffected" : "inert-at-config";
}

static uint8_t class_of(const char *const *lines, int n, uint32_t rule, uint8_t out, we_tenant_state_t ts)
{
    const we_program_t *p = ctxprog(lines, n);
    we_rule_class_t rc[16];

    if (p == NULL) {
        return 0xff;
    }
    we_program_dependents(p, out, ts, rc, 16);
    return rc[rule - 1u].cls;
}

/* the exact class by brute force over ATOMS (identical instructions are one variable) */
static uint8_t exact_values(const we_program_t *p, const we_rule_t *R, uint8_t out)
{
    const we_instr_t *ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
    uint32_t atom_of[256], natoms = 0u, k, j, asg;
    const we_instr_t *atoms[16];
    uint8_t vals = 0u;

    for (k = 0u; k < R->instr_count; k++) {
        const we_instr_t *I = &ins[R->instr_start + k];

        atom_of[k] = 0xffffffffu;
        if ((I->op & WE_OP_ATOM) == 0u) {
            continue;
        }
        for (j = 0u; j < natoms; j++) {
            if (memcmp(atoms[j], I, sizeof *I) == 0) {
                break;
            }
        }
        if (j == natoms) {
            atoms[natoms++] = I;
        }
        atom_of[k] = j;
    }
    for (asg = 0u; asg < (1u << natoms); asg++) {
        int st[64], sp = 0;

        for (k = 0u; k < R->instr_count; k++) {
            const we_instr_t *I = &ins[R->instr_start + k];

            if (I->op & WE_OP_ATOM) {
                int on = (out >> I->plane) & 1u;

                if (I->op & WE_OP_ISUNK) {
                    st[sp++] = on ? RT : RF;
                } else {
                    st[sp++] = on ? RU : (((asg >> atom_of[k]) & 1u) ? RT : RF);
                }
            } else if (I->op & WE_OP_NOT) {
                st[sp - 1] = ref_not(st[sp - 1]);
            } else if (I->op & WE_OP_AND) {
                st[sp - 2] = ref_and(st[sp - 2], st[sp - 1]);
                sp--;
            } else if (I->op & WE_OP_OR) {
                st[sp - 2] = ref_or(st[sp - 2], st[sp - 1]);
                sp--;
            }
        }
        vals = (uint8_t)(vals | (st[0] == RT ? 1u : st[0] == RF ? 2u : 4u));
    }
    return vals;
}

static void test_classifier(void)
{
    SECTION("D2: inert, narrowed, captures, per (rule, out-set, tenant sub-state)");
    {
        const char *a[1] = { "log if tor_exit is unknown" };
        const char *b[1] = { "deny if tor_exit or c2" };
        const char *c[2] = { "allow if tor_exit or asn in { 64496 }", "deny if c2" };
        const char *d[1] = { "deny if (asn == 1 and not asn == 1) or tor_exit" };
        const char *e[2] = { "allow if tenant_allow", "deny if c2" };
        const char *f[1] = { "deny if not tenant_allow" };
        const char *g[2] = { "allow if not tenant_deny", "deny if c2" };

        CHECK(class_of(a, 1, 1, 0x02u, WE_TENANT_FRESH) == WE_CLASS_NARROWED,
              "[D2] log if tor_exit is unknown is narrowed under tor (is unknown reads T): %s",
              cls_name(class_of(a, 1, 1, 0x02u, WE_TENANT_FRESH)));
        CHECK(class_of(b, 1, 1, 0x02u, WE_TENANT_FRESH) == WE_CLASS_NARROWED, "[D2] deny if tor_exit or c2 under tor: narrowed");
        CHECK(class_of(b, 1, 1, 0x20u, WE_TENANT_FRESH) == WE_CLASS_NARROWED, "[D2] ... under threat: narrowed");
        CHECK(class_of(b, 1, 1, 0x22u, WE_TENANT_FRESH) == WE_CLASS_INERT, "[D2] ... under both: inert");
        CHECK(class_of(c, 2, 1, 0x02u, WE_TENANT_FRESH) == WE_CLASS_CAPTURES,
              "[D2] allow if tor_exit or asn in @partners under tor: captures, not narrowed (%s)",
              cls_name(class_of(c, 2, 1, 0x02u, WE_TENANT_FRESH)));
        CHECK(class_of(d, 1, 1, 0x02u, WE_TENANT_FRESH) == WE_CLASS_NARROWED,
              "[D2] the correlated-atom rule is narrowed per occurrence");
        CHECK(class_of(e, 2, 1, 0u, WE_TENANT_FRESH) == WE_CLASS_UNAFFECTED, "[D2] the bounded allow under FRESH: unaffected");
        CHECK(class_of(e, 2, 1, 0u, WE_TENANT_GRACE) == WE_CLASS_NARROWED, "[D2] the bounded allow under GRACE: narrowed");
        CHECK(class_of(e, 2, 1, 0u, WE_TENANT_LAPSED) == WE_CLASS_INERT, "[D2] the bounded allow under LAPSED: inert");
        CHECK(class_of(e, 2, 1, 0u, WE_TENANT_NULL) == WE_CLASS_CAPTURES, "[D2] the bounded allow under NULL: captures");
        CHECK(class_of(f, 1, 1, 0u, WE_TENANT_LAPSED) == WE_CLASS_INERT, "[D2] deny if not tenant_allow under LAPSED: inert");
        CHECK(class_of(g, 2, 1, 0u, WE_TENANT_GRACE) == WE_CLASS_CAPTURES, "[D2] allow if not tenant_deny under GRACE: captures");
        CHECK(class_of(g, 2, 1, 0x80u, WE_TENANT_FRESH) == class_of(g, 2, 1, 0u, WE_TENANT_FRESH),
              "[D2] the tenant bit of out_mask is ignored: tenant_state alone governs the plane");
    }
    {
        /* D1's "the independent deny moves under the capturing allow": named as a dependent */
        const char *c[2] = { "allow if tor_exit or asn in { 64496 }", "deny if c2" };
        const we_program_t *p = ctxprog(c, 2);
        we_rule_class_t rc[4];
        char line[256];

        we_program_dependents(p, 0x02u, WE_TENANT_FRESH, rc, 4);
        CHECK(rc[1].dependent == 1u, "[D1] the deny below a capturing allow is a dependent although it reads no tor");
        we_program_dependents_line(p, 0x02u, WE_TENANT_FRESH, "plane tor stale", line, sizeof line);
        CHECK(strcmp(line, "plane tor stale: rule 1 allow captures; rule 2 disarmed") == 0, "[D1] the line: %s", line);
    }

    SECTION("D2: soundness against an exact brute force over atoms");
    {
        static const char *const rules[] = {
            "deny if tor_exit or c2", "deny if (asn == 1 and not asn == 1) or tor_exit", "allow if tor_exit or proxy",
            "deny if not (tor_exit and proxy) or c2", "allow if not tor_exit and proxy", "deny if tor_exit and not tor_exit",
            "log if tor_exit is unknown or c2", "allow if c2 and (tor_exit or not proxy) and spam",
            "deny if (tor_exit or proxy) and (c2 or not spam)", "allow if not (tor_exit or proxy)",
        };
        unsigned i, out;

        for (i = 0u; i < sizeof rules / sizeof rules[0]; i++) {
            const we_program_t *p = prog1(rules[i]);
            const we_rule_t *R;

            if (p == NULL) {
                continue;
            }
            R = (const we_rule_t *)(const void *)((const uint8_t *)p + p->rules_off);
            for (out = 0u; out < 128u; out++) {
                we_rule_class_t rc;
                uint8_t exact;

                if ((out & ~(uint32_t)p->plane_mask) != 0u) {
                    continue;
                }
                we_program_dependents(p, (uint8_t)out, WE_TENANT_FRESH, &rc, 1);
                exact = exact_values(p, R, (uint8_t)out);
                if (R->action == WE_ACT_ALLOW) {
                    CHECK(!((exact & 4u) && !(rc.values & 4u)), "[D2] %s out 0x%02x: never omits captures", rules[i], out);
                } else {
                    CHECK(!((exact & 1u) && !(rc.values & 1u)), "[D2] %s out 0x%02x: never inert where exact is narrowed",
                          rules[i], out);
                }
            }
        }
    }
}

static int write_tenant(const char *path, uint64_t gen, uint64_t vu)
{
    pspec_t *s = new_spec(WE_PLANE_TENANT);
    ww_plane_t p;
    uint8_t rec[32];
    __uint128_t st = TA, en = TA;
    int rc;

    mrec4(rec, WE_MF_TENANT_ALLOW, 0u);
    memset(&p, 0, sizeof p);
    p.format = WE_FORMAT_2;
    p.schema = 1;
    p.plane = WE_PLANE_TENANT;
    p.generation = gen;
    p.valid_until_ms = vu;
    p.v4.n = 1u;
    p.v4.start = &st;
    p.v4.end = &en;
    p.v4.kind = WE_KIND_NONE;
    p.v4.rec = rec;
    p.v6.kind = WE_KIND_NONE;
    rc = ww_write(path, &p);
    free(s);
    return rc;
}

static void test_revocation(void)
{
    we_handle_t h;
    char path[512];
    we_map_t *rev;
    we_load_detail_t det;
    we_verdict_t v;
    we_request_t req;
    uint32_t p;

    SECTION("D3: revocation, the high-water mark, generation 0");
    memset(&h, 0, sizeof h);
    snprintf(path, sizeof path, "%s/tenant.bin", TMP);
    CHECK(write_tenant(path, 100u, 0u) == 0 && we_handle_publish_plane(&h, path, NOW, &det) == WE_OK,
          "[D3] a tenant plane of generation G arms through we_handle_publish_plane");
    CHECK(((uintptr_t)h.current & 63u) == 0u, "[M5] the published map is 64-byte aligned");
    rev = we_map_new_revoked();
    CHECK(rev != NULL && we_handle_publish_map(&h, rev, NOW) == WE_OK, "[D3] the revoked map publishes");
    CHECK(((uintptr_t)rev & 63u) == 0u, "[M5] the revoked map is 64-byte aligned");
    CHECK(h.generation == 100u, "[D3] h->generation still reads G after the revoke (%" PRIu64 ")", h.generation);
    memset(&req, 0, sizeof req);
    addr4(&req.floor, TA);
    req.server = req.floor;
    for (p = 0u; p < 8u; p++) {
        ectx->view[p].m = NULL;
    }
    {
        const char *a[3] = { "allow if tenant_allow", "deny if tenant_deny", "log if tenant_allow is unknown" };
        const we_program_t *q = ctxprog(a, 3);
        we_ctx_conf_t cf = { WE_MODE_DENY, 0u };

        ectx->view[7].m = we_current(&h);
        we_decide(EMPTY_FLOOR, &cf, q, &cf, HH, &req, ectx, NOW, &v);
        CHECK((v.marks & WE_MARK_TENANT_REVOKED) != 0u && v.action == WE_ACT_ALLOW && v.rule == 0u
              && v.log_fired[1][0] == 0u,
              "[D3] revoked: tenant_allow F, tenant_deny F, is unknown F, marked tenant-revoked");
        ectx->view[7].m = NULL;
    }
    CHECK(write_tenant(path, 99u, 0u) == 0 && we_handle_publish_plane(&h, path, NOW, &det) == WE_ERR_ROLLBACK,
          "[D3] G - 1 is refused after the revocation");
    CHECK(write_tenant(path, 100u, 0u) == 0 && we_handle_publish_plane(&h, path, NOW, &det) == WE_ERR_ROLLBACK,
          "[D3] G is refused after the revocation: the high-water mark survives it");
    CHECK(write_tenant(path, 101u, 0u) == 0 && we_handle_publish_plane(&h, path, NOW, &det) == WE_OK,
          "[D3] G + 1 arms");
    {
        /* a restart: the module seeds the mark from the high-water file outside the data directory */
        we_handle_t h2;

        memset(&h2, 0, sizeof h2);
        h2.high_water = 101u;
        CHECK(write_tenant(path, 100u, 0u) == 0 && we_handle_publish_plane(&h2, path, NOW, &det) == WE_ERR_ROLLBACK,
              "[D3] after a restart with the mark seeded, the restored pre-revocation file is refused");
        we_handle_retire(&h2, NOW + 10u * WE_DEFAULT_GRACE_MS);
    }
    CHECK(write_tenant(path, 0u, 0u) == 0 && we_plane_open(path, &(we_map_t){ 0 }, &det) == WE_ERR_FORMAT,
          "[D3] a format-2 file of generation 0 is refused by the loader");
    /* retire: the heap revoked map is freed by the retirer without a fault */
    we_handle_retire(&h, NOW + 10u * WE_DEFAULT_GRACE_MS);
    CHECK(h.retired[0].map == NULL && h.retired[1].map == NULL, "[D3] the retirer freed the old maps, the revoked one included");
    {
        we_map_t *cur = h.current;

        we_map_close(cur);
        free(cur);
    }
}

static void test_d_rest(void)
{
    we_verdict_t v;
    scen_t s;

    SECTION("D4: a plane absent at config test, then a reload with it present");
    {
        we_policy_directive_t d;
        we_policy_source_t src;
        we_policy_env_t absent = { 0xffu & ~0x08u, 0u, 0u, 0u }, all = WE_POLICY_ENV_ALL;
        we_policy_build_t *b1 = NULL, *b2 = NULL;
        we_policy_error_t e;
        const char *line = "deny if rpki == invalid";

        d.kind = WE_DIR_POLICY;
        d.context = "http/server:a";
        d.arg = (const uint8_t *)line;
        d.len = strlen(line);
        src.d = &d;
        src.n = 1u;
        nreports = 0;
        CHECK(we_policy_build(&src, &absent, NULL, &b1, &e, &REP) == WE_POLICY_OK, "[D4] compiles with routing absent");
        CHECK(nreports > 0 && strstr(last_report, "not installed") != NULL, "[D4] the report names the absent plane: %s",
              last_report);
        CHECK(we_policy_build(&src, &all, NULL, &b2, &e, &REP) == WE_POLICY_OK, "[D4] recompiles with routing present");
        if (b1 != NULL && b2 != NULL) {
            const we_program_t *p1 = we_policy_program(b1, "http/server:a"), *p2 = we_policy_program(b2, "http/server:a");
            const we_rule_t *r1 = (const we_rule_t *)(const void *)((const uint8_t *)p1 + p1->rules_off);
            const we_rule_t *r2 = (const we_rule_t *)(const void *)((const uint8_t *)p2 + p2->rules_off);

            CHECK((r1->flags & WE_RF_INERT) != 0u && (r2->flags & WE_RF_INERT) == 0u && p1 != p2,
                  "[D4] the rule is inert in the first block and armed in a NEW block");
        }
        we_policy_build_free(b1);
        we_policy_build_free(b2);
    }

    SECTION("D5: a NULL map where the module meant FRESH reads UNKNOWN");
    scen_init(&s, &W, EMPTY_FLOOR, prog1("allow if tor_exit"), A_T);
    s.hh = HH;
    W.state[1] = PS_NULL;
    agree(&s, "D5", "NULL view", &v);
    CHECK(v.reason == WE_WHY_ALLOW_BY_UNKNOWN, "[D5] a NULL view reads U");
    W.state[1] = PS_FRESH;

    SECTION("D6: the conf's domain: every undefined value reads as dry-run log, allow_inferred off");
    {
        const we_program_t *p = prog1("deny if tor_exit");
        /* zeroed, both fields out, a NULL conf, and a deny-mode pair whose other half is out of its domain */
        we_ctx_conf_t zero = { 0u, 0u }, seven = { 7u, 9u }, half = { 3u, 2u }, half0 = { 0u, 1u };
        const we_ctx_conf_t *confs[5] = { &zero, &seven, NULL, &half, &half0 };
        int i;

        for (i = 0; i < 5; i++) {
            scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
            s.hh = HH;
            s.cc = confs[i];
            agree(&s, "D6", "conf domain", &v);
            CHECK(v.action == WE_ACT_ALLOW && v.log_fired[1][0] == 0x01u, "[D6] conf %d: logged, never a deny", i);
        }
        {
            const char *fl[1] = { "deny if tor_exit" };
            const we_program_t *floor = floorprog(fl, 1, NULL);

            scen_init(&s, &W, floor, NULL, A_T);
            s.hh = ro_hh(floor);
            s.fc = NULL;
            agree(&s, "D6", "NULL floor conf", &v);
            CHECK(v.action == WE_ACT_ALLOW && v.log_fired[0][0] == 0x01u, "[D6] a NULL floor conf: logged, never a deny");
        }
    }
}

/* ======================================================================================================
 * M1-M5: the memo, the record copy, the layout
 * ==================================================================================================== */

static void test_memo(void)
{
    we_verdict_t v;
    scen_t s;

    SECTION("M1: one slot per distinct key, aliased on equal keys, canonical keys");
    {
        const char *fl[2] = { "log if listed >= low", "log if tor_exit" };
        const char *cl[2] = { "log if tor_exit", "log if asn == 64496" };
        const we_program_t *floor = floorprog(fl, 2, NULL), *ctx = ctxprog(cl, 2);
        const we_hh_view_t *hh = ro_hh(floor);

        scen_init(&s, &W, floor, ctx, A_T);
        s.hh = hh;
        agree(&s, "M1", "equal keys", &v);
        cover_slot[0]++;
        CHECK(v.lookups[0][0] == 1u && v.lookups[0][1] == 1u && v.lookups[0][3] == 1u && v.lookups[0][7] == 1u
              && v.lookups[1][1] == 0u && v.lookups[1][3] == 0u,
              "[M1] equal keys: one slot, the union of the planes (reputation, tor, routing, tenant), tor filled once");
        addr4(&s.req.server, A_F);
        agree(&s, "M1", "distinct keys", &v);
        cover_slot[1]++;
        CHECK(v.lookups[0][1] == 1u && v.lookups[1][1] == 1u && v.lookups[1][3] == 1u && v.lookups[0][3] == 0u,
              "[M1] distinct keys: the sum form, each program on its own address");
        /* re-keying resets: the floor address's record is not reused for a different server address */
        addr4(&s.req.server, A_T);
        agree(&s, "M1", "back to equal", &v);
        addr4(&s.req.server, A_X);
        agree(&s, "M1", "a re-keyed slot", &v);
        addr4(&s.req.server, A_F);
        {
            /* the same ctx kept across two requests with different server addresses: the second must not
             * read the first's memo (the module resets per request; this calls we_decide twice on one ctx) */
            uint32_t p;
            we_verdict_t v1, v2;
            we_request_t r1 = s.req, r2 = s.req;
            we_ctx_conf_t cf = { WE_MODE_DENY, 0u };
            const we_program_t *dp = prog1("deny if asn == 64496");

            addr4(&r1.server, A_T);
            addr4(&r1.floor, A_X);
            addr4(&r2.server, A_F);
            addr4(&r2.floor, A_X);
            for (p = 0u; p < 8u; p++) {
                ectx->view[p].m = world_view(&W, p);
            }
            we_decide(EMPTY_FLOOR, &cf, dp, &cf, HH, &r1, ectx, NOW, &v1);
            we_decide(EMPTY_FLOOR, &cf, dp, &cf, HH, &r2, ectx, NOW, &v2);
            CHECK(v1.action == WE_ACT_DENY && v2.action == WE_ACT_ALLOW,
                  "[M1] a re-keyed slot is reset: AS64496 at the first address, the sentinel at the second");
            /* the memo lives one request: the same address again, after a republish, reads the new map */
            {
                const we_program_t *tp = prog1("deny if tor_exit");
                we_request_t r3;

                memset(&r3, 0, sizeof r3);
                addr4(&r3.server, A_T);
                addr4(&r3.floor, A_T);
                we_decide(EMPTY_FLOOR, &cf, tp, &cf, HH, &r3, ectx, NOW, &v1);
                ectx->view[1].m = W.map[1][3];          /* tor republished, listing nothing */
                we_decide(EMPTY_FLOOR, &cf, tp, &cf, HH, &r3, ectx, NOW, &v2);
                CHECK(v1.action == WE_ACT_DENY && v2.action == WE_ACT_ALLOW && v2.lookups[0][1] == 1u,
                      "[M1] one request's memo never answers the next: the same address after a republish is looked up again");
            }
            for (p = 0u; p < 8u; p++) {
                ectx->view[p].m = NULL;
            }
        }
    }
    {
        we_addr_t a, o;
        static const uint8_t mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 21, 0, 0, 1 };
        static const uint8_t compat[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 1 };
        static const uint8_t any[16] = { 0 };
        static const uint8_t loop[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

        we_addr_canon(mapped, 6, &o);
        addr4(&a, A_T);
        CHECK(o.family == 4u && memcmp(o.b, a.b, 16) == 0, "[M1] ::ffff:21.0.0.1 and 21.0.0.1 are one key");
        we_addr_canon(compat, 6, &o);
        CHECK(o.family == 6u, "[M1] ::21.0.0.1 stays IPv6");
        we_addr_canon(any, 6, &o);
        CHECK(o.family == 6u, "[M1] :: stays IPv6");
        we_addr_canon(loop, 6, &o);
        CHECK(o.family == 6u && o.b[15] == 1u, "[M1] ::1 stays IPv6, never 0.0.0.1");
    }

    SECTION("M1: IPv6, every key width: 128-bit membership, 64-bit routing, format 1");
    {
        world_t vw;
        pspec_t *t6 = new_spec(WE_PLANE_TOR), *r6 = new_spec(WE_PLANE_ROUTING), *p6 = new_spec(WE_PLANE_REPUTATION);
        uint8_t r[32];
        __uint128_t a1 = ((__uint128_t)0x2400abcd00000000ull << 64) | 1u;
        static const char *lines[4] = { "log if tor_exit", "log if asn == 64500 and rpki == invalid and narrowed",
                                        "log if listed >= high", "log if country in { NL } and asn_rep == suspicious" };
        const we_program_t *p = ctxprog(lines, 4);
        __uint128_t probes[4];
        int k;

        memset(&vw, 0, sizeof vw);
        mrec6(r, 1u, 0u);
        add6(t6, a1, a1, r, 32);
        rrec6(r, 64500u, 528u, 2u, 5u, 4u, 3u);
        add6(r6, 0x2400abcd00000000ull, 0x2400abcd00000000ull, r, 24);
        memset(r, 0, sizeof r);
        r[0] = WE_SEV_HIGH;
        add6(p6, a1, a1, r, 1);
        vw.spec[1] = t6;
        vw.spec[3] = r6;
        vw.spec[0] = p6;
        world_build(&vw);
        probes[0] = a1;
        probes[1] = a1 + 1u;                                      /* the same /64: routing hits, the others miss */
        probes[2] = ((__uint128_t)0x2400abce00000000ull << 64) | 1u;
        probes[3] = (__uint128_t)0xffff15000001ull;                /* ::ffff:21.0.0.1, unmapped to IPv4 */
        for (k = 0; k < 4; k++) {
            scen_init(&s, &vw, EMPTY_FLOOR, p, 0u);
            s.hh = HH;
            addr6(&s.req.floor, probes[k]);
            s.req.server = s.req.floor;
            agree(&s, "M1", "IPv6", &v);
            if (k == 0) {
                CHECK(v.log_fired[1][0] == 0x0fu, "[M1] IPv6: every key width reads its record (0x%02x)", v.log_fired[1][0]);
            }
            if (k == 1) {
                CHECK(v.log_fired[1][0] == 0x0au, "[M1] IPv6: the routing /64 covers the neighbour (0x%02x)",
                      v.log_fired[1][0]);
            }
        }
        free(t6);
        free(r6);
        free(p6);
    }

    SECTION("M2: the copy outlives the mapping; a later fill re-takes the plane and records its generation");
    {
        pspec_t *ps = new_spec(WE_PLANE_ROUTING);
        uint8_t r[32];
        const we_map_t *m1, *m2;
        we_request_t req;
        we_ctx_conf_t cf = { WE_MODE_DENY, 0u };
        const we_program_t *p = prog1("log if asn == 64496");
        uint32_t q;

        rrec4(r, 64496u, 528u, 1u, 5u, 0u, 2u);
        add4(ps, A_T, A_T, r, 16);
        m1 = mk_map(ps, 11u, 0u, 0, NULL, NULL);
        m2 = mk_map(ps, 12u, 0u, 0, NULL, NULL);
        memset(&req, 0, sizeof req);
        addr4(&req.floor, A_T);
        req.server = req.floor;
        for (q = 0u; q < 8u; q++) {
            ectx->view[q].m = NULL;
        }
        ectx->view[3].m = m1;
        we_decide(EMPTY_FLOOR, &cf, p, &cf, HH, &req, ectx, NOW, &v);
        ectx->view[3].m = NULL;
        /* the mapping is retired: unmapped here, so a dangling read would fault */
        munmap((void *)(((uintptr_t)m1->base) & ~(uintptr_t)(pgsz() - 1u)), pgsz());
        {
            uint32_t asn;

            memcpy(&asn, ectx->slot[0].e[3].block, 4);
            CHECK(asn == 64496u && ectx->slot[0].e[3].generation == 11u, "[M2] the variable reads the copy, generation 11");
        }
        /* a log-phase fill of a plane the evaluator never touched: registry, through the new view */
        ectx->view[6].m = m2;
        we_eval_lazy_fill(ectx, HH, 0u, WE_PLANE_REGISTRY, NOW, &v);
        CHECK(ectx->slot[0].state[6] != WE_ST_NONE && ectx->slot[0].e[6].generation == 12u,
              "[M2] the lazy fill re-takes the plane and records generation 12");
        ectx->view[6].m = NULL;
        free(ps);
    }

    SECTION("M3: the last record of each family and stride, flush against a guard page");
    {
        static const uint32_t planes[3] = { WE_PLANE_ROUTING, WE_PLANE_TOR, WE_PLANE_TENANT };
        int k;

        for (k = 0; k < 3; k++) {
            pspec_t *ps = new_spec(planes[k]);
            uint8_t r[32];
            uint32_t i, n4 = 4u;
            const we_map_t *m;
            we_memo_slot_t *sl = &ectx->slot[0];
            const uint8_t *lo, *hi;

            for (i = 0u; i < n4; i++) {
                if (planes[k] == WE_PLANE_ROUTING) {
                    rrec4(r, 64496u + i, 528u, 1u, 5u, 1u, 2u);
                } else {
                    mrec4(r, 1u, 0u);
                }
                add4(ps, 0x0c000000u + i * 256u, 0x0c000000u + i * 256u + 255u, r, 16);
            }
            ps->noblob = 1;
            m = mk_map(ps, 5u, 0u, 1, NULL, NULL);
            lo = m->f4.records;
            hi = m->f4.records + (size_t)n4 * 16u;
            CHECK((((uintptr_t)hi) & (pgsz() - 1u)) == 0u, "[M3] plane %u: the record column ends at the guard page",
                  planes[k]);
            memset(sl, 0, sizeof *sl);
            addr4(&s.req.floor, 0x0c000000u + (n4 - 1u) * 256u + 7u);
            sl->key_valid = 1u;
            sl->family = 4u;
            memcpy(sl->addr, s.req.floor.b, 16);
            trace_reset();
            trace_on = 1;
            we_eval_fill(m, sl, planes[k] - 1u, HH->bindings + planes[k] - 1u, NOW, &v, 0u);
            trace_on = 0;
            CHECK(sl->state[planes[k] - 1u] == WE_ST_FRESH_HIT, "[M3] plane %u: the last record is a hit", planes[k]);
            CHECK(trace_inside(lo, hi, lo, hi + pgsz()), "[M3] plane %u: the copy's reads stay inside the record column",
                  planes[k]);
            CHECK(trace_lines(hi - 16, hi) == 1, "[M3] plane %u: the copy reads the record's one line", planes[k]);
            free(ps);
        }
    }

    SECTION("M4: every record byte value, clamped at fill, the template unclamped");
    {
        /* patch out-of-domain bytes into a loaded routing plane: the loader refuses them in a file it arms,
         * so this is the in-place rewrite window the clamp defends */
        static uint8_t field_off[5] = { 10, 11, 13, 12, 8 };   /* rov, rir, asn_rep, flags, country */
        pspec_t *ps = new_spec(WE_PLANE_ROUTING);
        uint8_t r[32];
        unsigned b;
        const char *lines[6] = { "log if rpki == undetermined", "log if rir == undetermined",
                                 "log if asn_rep == undetermined", "log if anycast or moas or narrowed",
                                 "log if country == undetermined", "log if rpki == unrouted" };
        const we_program_t *p = ctxprog(lines, 6);

        for (b = 0u; b < 256u; b++) {
            rrec4(r, 64496u, 528u, 1u, 1u, 0u, 1u);
            add4(ps, 0x0d000000u + b * 256u, 0x0d000000u + b * 256u + 255u, r, 16);
        }
        {
            int f;

            for (f = 0; f < 5; f++) {
                world_t mw;
                pspec_t *pp = new_spec(WE_PLANE_ROUTING);

                memset(&mw, 0, sizeof mw);
                for (b = 0u; b < 256u; b++) {
                    memcpy(pp->r4[b], ps->r4[b], 32);
                    pp->s4[b] = ps->s4[b];
                    pp->e4[b] = ps->e4[b];
                    pp->r4[b][field_off[f]] = (uint8_t)b;
                    if (field_off[f] == 8) {
                        /* country, all 65536 values over the 256 records' two bytes: low byte b, high byte b */
                        pp->r4[b][9] = (uint8_t)b;
                    }
                }
                pp->n4 = 256u;
                mw.spec[3] = pp;
                {
                    /* load an in-domain copy, then patch the out-of-domain bytes into the read-only pages */
                    pspec_t *ok = new_spec(WE_PLANE_ROUTING);

                    *ok = *ps;
                    mw.map[3][0] = mk_map(ok, 3u, 0u, 0, NULL, NULL);
                    {
                        we_map_t *m = (we_map_t *)(uintptr_t)mw.map[3][0];
                        uint8_t *rec = (uint8_t *)(uintptr_t)m->f4.records;
                        size_t len = m->len;

                        mprotect((void *)((uintptr_t)m->base & ~(uintptr_t)(pgsz() - 1u)),
                                 ((uintptr_t)m->base + len + pgsz()) - ((uintptr_t)m->base & ~(uintptr_t)(pgsz() - 1u)),
                                 PROT_READ | PROT_WRITE);
                        for (b = 0u; b < 256u; b++) {
                            memcpy(rec + (size_t)b * 16u, pp->r4[b], 16);
                            memcpy(rec + (size_t)b * 16u, &pp->e4[b], 4);
                        }
                        ro(m->base, len);
                    }
                    free(ok);
                }
                mw.state[3] = PS_FRESH;
                for (b = 0u; b < 8u; b++) {
                    if (b != 3u) {
                        mw.state[b] = PS_NULL;
                    }
                }
                for (b = 0u; b < 256u; b++) {
                    we_verdict_t vv;

                    scen_init(&s, &mw, EMPTY_FLOOR, p, 0x0d000000u + b * 256u + 1u);
                    s.hh = HH;
                    agree(&s, "M4", "a routing byte", &vv);
                }
                cover_clamp[f]++;
                free(pp);
            }
        }
        /* the template is unclamped: a no-range address reads `unrouted`, a record's rov 4 `undetermined` */
        {
            we_verdict_t vv;

            scen_init(&s, &W, EMPTY_FLOOR, prog1("log if rpki == unrouted"), A_X);
            s.hh = HH;
            agree(&s, "M4", "template", &vv);
            CHECK(vv.log_fired[1][0] == 0x01u, "[M4] no range reads rpki == unrouted: the template is not clamped");
        }
        /* sev 0x05..0x0F and 0x10/0x20, and the reason byte on rpki-unreachable */
        {
            world_t sw;
            pspec_t *rp = new_spec(WE_PLANE_REPUTATION), *ru = new_spec(WE_PLANE_RPKI_UNREACHABLE);
            const char *sl[3] = { "log if listed == critical", "log if listed == none", "log if inferred" };
            const char *rl[2] = { "log if rpki_reason == undetermined", "log if rpki_reason == length" };

            memset(&sw, 0, sizeof sw);
            for (b = 0u; b < 256u; b++) {
                uint8_t rr[32] = { 0 };

                rr[0] = (uint8_t)b;
                add4(rp, 0x0e000000u + b * 256u, 0x0e000000u + b * 256u + 255u, rr, 1);
            }
            for (b = 0u; b < 3u; b++) {
                uint8_t rr[32];

                mrec4(rr, 1u, (uint8_t)b);
                add4(ru, 0x0e000000u + b * 256u, 0x0e000000u + b * 256u + 255u, rr, 16);
            }
            sw.spec[0] = rp;
            sw.spec[2] = ru;
            world_build(&sw);
            for (b = 0u; b < 256u; b++) {
                we_verdict_t vv;

                scen_init(&s, &sw, EMPTY_FLOOR, ctxprog(sl, 3), 0x0e000000u + b * 256u + 1u);
                s.hh = HH;
                agree(&s, "M4", "a sev byte", &vv);
                s.cconf.allow_inferred = 1u;
                agree(&s, "M4", "a sev byte, allow_inferred", &vv);
            }
            cover_clamp[5]++;
            for (b = 0u; b < 3u; b++) {
                we_verdict_t vv;

                scen_init(&s, &sw, EMPTY_FLOOR, ctxprog(rl, 2), 0x0e000000u + b * 256u + 1u);
                s.hh = HH;
                agree(&s, "M4", "a reason", &vv);
            }
            cover_clamp[6]++;
            free(rp);
            free(ru);
        }
        free(ps);
    }

    SECTION("M5: the slot and the descriptor, laid out as the bounds assume");
    WE_STATIC_ASSERT(sizeof(we_fam_t) == 96, "we_fam_t is 96 bytes");
    WE_STATIC_ASSERT(offsetof(we_map_t, f4) == 0 && offsetof(we_map_t, f6) == 96 && offsetof(we_map_t, f6w) == 192,
                     "the three families at 0, 96 and 192");
    WE_STATIC_ASSERT(offsetof(we_map_t, valid_until_ms) == 296, "valid_until_ms at 296");
    WE_STATIC_ASSERT(_Alignof(we_hh_view_t) == 64, "the hold-harmless view type is 64-byte aligned");
    {
        /* a view declared on the stack, as a module or a harness would, is placed: the type aligns it */
        we_hh_view_t onstack;

        CHECK(we_program_place(EMPTY_FLOOR, &onstack) == 0 && ((uintptr_t)&onstack & 63u) == 0u,
              "[M5] a stack-declared we_hh_view_t is 64-byte aligned and placed");
    }
    WE_STATIC_ASSERT(offsetof(we_map_t, generation) == 288 && offsetof(we_map_t, country_known) == 304,
                     "generation and country_known share valid_until_ms's line");
    WE_STATIC_ASSERT(sizeof(we_memo_entry_t) == 32 && offsetof(we_memo_slot_t, e) == 64, "entries at 64 + 32 p");
    CHECK(sizeof(we_eval_ctx_t) == 704, "[M5] the context is 704 bytes (%zu)", sizeof(we_eval_ctx_t));
    CHECK(((uintptr_t)ectx & 63u) == 0u, "[M5] the context is 64-byte aligned");
}

/* ======================================================================================================
 * S1-S3: sets
 * ==================================================================================================== */

/*
 * A fault turned into a named failure: the body runs with SIGSEGV and SIGBUS caught, and a fault
 * returns here and fails the row, so a defect the guard pages catch is reported on its row and the
 * rest of the run still runs. Nothing else in the process is ever a quiet pass.
 */
static sigjmp_buf fault_jb;
static volatile sig_atomic_t fault_armed, fault_sig;

static void on_fault(int sig)
{
    if (fault_armed) {
        fault_armed = 0;
        fault_sig = sig;
        siglongjmp(fault_jb, 1);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void guarded(const char *row, const char *what, void (*body)(void))
{
    struct sigaction sa, old_segv, old_bus;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    fault_sig = 0;
    fault_armed = 1;
    if (sigsetjmp(fault_jb, 1) == 0) {
        body();
    }
    fault_armed = 0;
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    CHECK(fault_sig == 0, "[%s] %s (signal %d)", row, what, (int)fault_sig);
}

static void test_s2(void)
{
    scen_t s;
    we_verdict_t v;

    {
        static const uint32_t ns[] = { 1u, 16u, 17u, 272u, 273u, 538u, WE_LIM_ASN_MEMBERS };
        unsigned i;

        for (i = 0u; i < sizeof ns / sizeof ns[0]; i++) {
            uint32_t n = ns[i], k, hu;

            for (hu = 0u; hu < 2u; hu++) {
                static char text[1 << 14];
                const char *lines[2];
                const we_program_t *p;
                const we_instr_t *I;
                size_t o;
                pspec_t *ps;
                world_t sw;

                /* members on a stride of 3 from 100, so every leaf has non-members between them; at 538 and
                 * 539 the argument limit leaves room only for 0 .. n - 1, and none for `undetermined` too */
                if (hu != 0u && n >= 538u) {
                    continue;
                }
                o = (size_t)snprintf(text, sizeof text, "@s%s", hu ? " undetermined" : "");
                for (k = 0u; k < n; k++) {
                    o += (size_t)snprintf(text + o, sizeof text - o, " %u", n >= 538u ? k : 100u + 3u * k);
                }
                lines[0] = text;
                lines[1] = "log if asn in @s";
                p = ctxprog(lines, 2);
                if (p == NULL) {
                    continue;
                }
                I = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
                CHECK((I->op & WE_OP_INSET_ASN) != 0u && WE_ASN_IMM_N(I->imm) == n
                      && WE_ASN_IMM_LEVELS(I->imm) == (n <= 16u ? 1u : n <= 272u ? 2u : 3u),
                      "[S2] n = %u: INSET_ASN with n and the level count packed", n);
                /* one routing record per probe: below the smallest, every member, every gap, above, the sentinel */
                ps = new_spec(WE_PLANE_ROUTING);
                {
                    /* below the smallest, every member and every gap, above the largest, 0xFFFFFFFE, and the
                     * sentinel last */
                    uint32_t np = n >= 538u ? n + 1u : 3u * n + 2u, q;

                    for (q = 0u; q <= np + 1u; q++) {
                        uint8_t r[32];
                        uint32_t asn = q == np + 1u ? 0xffffffffu : q == np ? 0xfffffffeu
                                     : n >= 538u ? q : 99u + q;

                        rrec4(r, asn, 0u, 0u, 0u, 0u, 0u);
                        add4(ps, 0x0f000000u + q * 16u, 0x0f000000u + q * 16u + 15u, r, 16);
                    }
                }
                memset(&sw, 0, sizeof sw);
                sw.spec[3] = ps;
                sw.map[3][0] = mk_map(ps, 3u, 0u, 0, NULL, NULL);
                for (k = 0u; k < 8u; k++) {
                    sw.state[k] = k == 3u ? PS_FRESH : PS_NULL;
                }
                for (k = 0u; k < ps->n4; k++) {
                    const uint8_t *pay = (const uint8_t *)p + WE_ASN_IMM_OFF(I->imm);
                    uint32_t m0 = (n + 15u) / 16u, m1 = (m0 + 16u) / 17u;
                    uint32_t plen = (m0 + (n > 16u ? m1 : 0u) + (n > 272u ? 1u : 0u)) * 64u;

                    scen_init(&s, &sw, EMPTY_FLOOR, p, ps->s4[k] + 1u);
                    s.hh = HH;
                    trace_reset();
                    trace_on = 1;
                    agree(&s, "S2", "an ASN probe", &v);
                    trace_on = 0;
                    if (k < 3u || k + 1u == ps->n4 || (k % 37u) == 0u) {
                        CHECK(trace_inside(pay, pay + plen, (const uint8_t *)p + p->setdata_off, (const uint8_t *)p + p->hot_len),
                              "[S2] n = %u, probe %u: the search reads stay inside the payload (no k[-1])", n, k);
                        CHECK(v.set_probes == WE_ASN_IMM_LEVELS(I->imm),
                              "[S2] n = %u: lines = levels, fixed iteration (%u)", n, v.set_probes);
                    }
                }
                {
                    uint32_t last = ps->n4 - 1u;
                    uint8_t blk[16];
                    we_addr_t a;

                    addr4(&a, ps->s4[last] + 1u);
                    ref_block(ps, &a, blk);
                    scen_init(&s, &sw, EMPTY_FLOOR, p, ps->s4[last] + 1u);
                    s.hh = HH;
                    agree(&s, "S2", "the sentinel", &v);
                    CHECK((v.log_fired[1][0] == 0x01u) == (hu == 1u),
                          "[S2] n = %u: an unrouted address is a member iff has_undetermined (%u)", n, hu);
                }
                free(ps);
            }
        }
        /* n = 0, and AS4294967294 against the sentinel */
        {
            const char *l0[1] = { "log if asn in { undetermined }" };
            const we_program_t *p = ctxprog(l0, 1);
            const we_instr_t *I = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);

            CHECK((I->op & WE_OP_EQ32) != 0u && I->imm == 0xffffffffu && p->set_count == 0u,
                  "[S2] n = 0 compiles to EQ32 against the sentinel, with no payload");
            scen_init(&s, &W, EMPTY_FLOOR, p, A_F);
            s.hh = HH;
            agree(&s, "S2", "n = 0 unrouted", &v);
            CHECK(v.log_fired[1][0] == 0x01u, "[S2] n = 0: TRUE for the unrouted address");
            scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
            s.hh = HH;
            agree(&s, "S2", "n = 0 routed", &v);
            CHECK(v.log_fired[1][0] == 0u, "[S2] n = 0: FALSE for a routed address");
        }
        {
            int hu;

            for (hu = 0; hu < 2; hu++) {
                const char *lines[1];
                const we_program_t *p;
                pspec_t *ps = new_spec(WE_PLANE_ROUTING);
                world_t sw;
                uint8_t r[32];
                int k;

                lines[0] = hu ? "log if asn in { 4294967294 undetermined }" : "log if asn in { 4294967294 }";
                p = ctxprog(lines, 1);
                rrec4(r, 0xfffffffeu, 0u, 0u, 0u, 0u, 0u);
                add4(ps, 0x0f100000u, 0x0f1000ffu, r, 16);
                rrec4(r, 0xffffffffu, 0u, 0u, 0u, 0u, 0u);
                add4(ps, 0x0f100100u, 0x0f1001ffu, r, 16);
                memset(&sw, 0, sizeof sw);
                sw.spec[3] = ps;
                sw.map[3][0] = mk_map(ps, 3u, 0u, 0, NULL, NULL);
                for (k = 0; k < 8; k++) {
                    sw.state[k] = k == 3 ? PS_FRESH : PS_NULL;
                }
                scen_init(&s, &sw, EMPTY_FLOOR, p, 0x0f100001u);
                s.hh = HH;
                agree(&s, "S2", "AS4294967294", &v);
                CHECK(v.log_fired[1][0] == 0x01u, "[S2] AS4294967294 is a member of its set");
                scen_init(&s, &sw, EMPTY_FLOOR, p, 0x0f100101u);
                s.hh = HH;
                agree(&s, "S2", "the sentinel against AS4294967294", &v);
                CHECK((v.log_fired[1][0] == 0x01u) == (hu == 1),
                      "[S2] the sentinel answers has_undetermined (%d), never `found`", hu);
                free(ps);
            }
        }
    }

}

static void test_sets(void)
{
    we_policy_build_t *b = NULL;
    we_policy_error_t e;
    we_verdict_t v;
    scen_t s;

    SECTION("S1: value sets of each class, scope, the has_undetermined encoding");
    {
        const char *l[4] = { "@e KP SY CU", "@a undetermined KP", "deny if country in @e", "log if country in @a" };
        const we_program_t *p = ctxprog(l, 4);
        const we_setdesc_t *sd = (const we_setdesc_t *)(const void *)((const uint8_t *)p + p->sets_off);

        CHECK(p != NULL && p->set_count == 2u && sd[0].has_undetermined == 0u && sd[1].has_undetermined == 1u
              && sd[1].count == 1u, "[S1] has_undetermined per set; a duplicate-free count");
        scen_init(&s, &W, EMPTY_FLOOR, p, A_F);
        s.hh = HH;
        agree(&s, "S1", "@a matches the undetermined country", &v);
        CHECK(v.log_fired[1][0] == 0x02u, "[S1] the undetermined country is a member of @a, not of @e");
    }
    CHECK(compile1("deny if country in { NL 64496 }", &b, &e) == WE_POLICY_REFUSED && strcmp(e.layer, "typing") == 0,
          "[S1] an inline set of two classes is refused in typing");
    {
        we_policy_directive_t d[3];
        const char *a = "@x KP", *c = "deny if country in @x";

        d[0].kind = WE_DIR_SET;
        d[0].context = "http";
        d[0].arg = (const uint8_t *)a;
        d[0].len = strlen(a);
        d[1].kind = WE_DIR_POLICY;
        d[1].context = "http/server:a/location:b";
        d[1].arg = (const uint8_t *)c;
        d[1].len = strlen(c);
        CHECK(compile_src(d, 2u, &b, &e) == WE_POLICY_OK, "[S1] a set is visible from an inner context");
        we_policy_build_free(b);
    }
    nreports = 0;
    report_len = 0u;
    {
        int rc = compile1("log if country in { NL NL nl }", &b, &e);

        CHECK(rc == WE_POLICY_OK && report_buf != NULL && strstr(report_buf, " 1 duplicate-member NL,NL\n") != NULL,
              "[S1] a duplicate member is reported, never refused (%d: %s)", rc,
              rc == WE_POLICY_OK ? (report_buf != NULL ? report_buf : "") : e.what);
    }
    we_policy_build_free(b);

    SECTION("S2: ASN S+ trees at every size boundary, every member and a non-member at each leaf");
    guarded("S2", "the S+ search read past its payload into the guard page", test_s2);

    SECTION("S3: an address is not a literal");
    CHECK(compile1("deny if country in { 192.0.2.1 }", &b, &e) == WE_POLICY_REFUSED && strstr(e.fix, "tenant_allow") != NULL
          && strstr(e.fix, "op:policy") != NULL, "[S3] an address literal is refused naming tenant_allow and op:policy");
    CHECK(compile1("deny if asn in { 2001:db8::/32 }", &b, &e) == WE_POLICY_REFUSED && strstr(e.fix, "op:policy") != NULL,
          "[S3] an IPv6 prefix too");
}

/* ======================================================================================================
 * G1 the sugar, G3 interning
 * ==================================================================================================== */

static void test_sugar(void)
{
    static const char *const lv[5] = { "none", "low", "medium", "high", "critical" };
    unsigned t, mode, ai, b;
    world_t sw;
    pspec_t *rp = new_spec(WE_PLANE_REPUTATION);
    long long before = cases;

    SECTION("G1: the threshold sugar, byte-identical, and verdict-identical to we_should_deny");
    for (t = 1u; t <= 4u; t++) {
        we_program_t *sp = NULL;
        we_policy_build_t *bb = NULL;
        we_policy_error_t e;
        char line[64];

        snprintf(line, sizeof line, "deny if listed >= %s", lv[t]);
        CHECK(we_policy_sugar((uint8_t)t, NULL, &sp) == WE_POLICY_OK && compile1(line, &bb, &e) == WE_POLICY_OK,
              "[G1] threshold %s compiles both ways", lv[t]);
        if (sp != NULL && bb != NULL) {
            const we_program_t *cp = we_policy_program(bb, "http/server:a");

            CHECK(cp->total_len == sp->total_len && memcmp(cp, sp, sp->total_len) == 0,
                  "[G1] threshold %s is byte-identical to `%s`", lv[t], line);
        }
        we_program_free(NULL, sp);
        we_policy_build_free(bb);
    }
    {
        we_program_t *sp = NULL;

        CHECK(we_policy_sugar(0u, NULL, &sp) == WE_POLICY_OK && sp->rule_count == 0u, "[G1] threshold off is the empty program");
        we_program_free(NULL, sp);
    }
    memset(&sw, 0, sizeof sw);
    for (b = 0u; b < 256u; b++) {
        uint8_t rr[32] = { 0 };

        rr[0] = (uint8_t)b;
        add4(rp, 0x0e000000u + b * 256u, 0x0e000000u + b * 256u + 255u, rr, 1);
    }
    sw.spec[0] = rp;
    world_build(&sw);
    for (t = 0u; t <= 4u; t++) {
        we_program_t *sp = NULL;
        const we_program_t *p;

        we_policy_sugar((uint8_t)t, NULL, &sp);
        p = ro_prog(sp);
        we_program_free(NULL, sp);
        for (mode = WE_MODE_OFF; mode <= WE_MODE_DENY; mode++) {
            for (ai = 0u; ai < 2u; ai++) {
                for (b = 0u; b < 256u; b++) {
                    scen_t s;
                    we_verdict_t v;
                    int want = we_should_deny((uint8_t)b, (uint8_t)t, (int)ai);

                    scen_init(&s, &sw, EMPTY_FLOOR, p, 0x0e000000u + b * 256u + 1u);
                    s.hh = HH;
                    s.cconf.mode = (uint8_t)mode;
                    s.cconf.allow_inferred = (uint8_t)ai;
                    agree(&s, "G1", "sugar", &v);
                    if (mode == WE_MODE_DENY) {
                        CHECK((v.action == WE_ACT_DENY) == (want != 0), "[G1] t %u sev 0x%02x inferred %u: deny iff we_should_deny",
                              t, b, ai);
                    } else if (mode == WE_MODE_LOG) {
                        CHECK(v.action == WE_ACT_ALLOW && ((v.log_fired[1][0] & 1u) != 0u) == (want != 0),
                              "[G1] mode log t %u sev 0x%02x: logged iff we_should_deny, never a deny", t, b);
                    } else {
                        CHECK(v.action == WE_ACT_ALLOW && v.ops_ctx == 0u, "[G1] mode off: nothing evaluated");
                    }
                }
            }
        }
    }
    printf("  %lld sugar cases\n", cases - before);

    SECTION("G3: interning on the whole block; the mode is the context's, never the block's");
    {
        static const char *mk[] = { "deny", "log" };
        we_policy_directive_t d[6];
        we_policy_build_t *bb = NULL;
        we_policy_error_t e;
        const char *rule = "deny if tor_exit";

        d[0].kind = WE_DIR_POLICY;
        d[0].context = "http/server:a";
        d[0].arg = (const uint8_t *)rule;
        d[0].len = strlen(rule);
        d[1] = d[0];
        d[1].context = "http/server:b";
        d[2].kind = WE_DIR_MODE;
        d[2].context = "http/server:a";
        d[2].arg = (const uint8_t *)mk[0];
        d[2].len = 4u;
        d[3].kind = WE_DIR_MODE;
        d[3].context = "http/server:b";
        d[3].arg = (const uint8_t *)mk[1];
        d[3].len = 3u;
        d[4].kind = WE_DIR_MODE;
        d[4].context = "http/server:a/location:c";
        d[4].arg = (const uint8_t *)mk[1];
        d[4].len = 3u;
        CHECK(compile_src(d, 5u, &bb, &e) == WE_POLICY_OK, "[G3] compiles");
        if (bb != NULL) {
            const we_program_t *pa = we_policy_program(bb, "http/server:a"), *pb = we_policy_program(bb, "http/server:b");
            const we_program_t *pc = we_policy_program(bb, "http/server:a/location:c");
            we_ctx_conf_t ca = we_policy_conf(bb, "http/server:a"), cb = we_policy_conf(bb, "http/server:b");
            we_ctx_conf_t cc = we_policy_conf(bb, "http/server:a/location:c");
            scen_t s;
            we_verdict_t v1, v2, v3;

            CHECK(pa == pb, "[G3] two contexts with the same text share ONE block");
            CHECK(pc == pa && cc.mode == WE_MODE_LOG && ca.mode == WE_MODE_DENY && cb.mode == WE_MODE_LOG,
                  "[G3] the lineless child runs its parent's block under its own mode");
            scen_init(&s, &W, EMPTY_FLOOR, ro_prog(pa), A_T);
            s.hh = HH;
            s.cconf = ca;
            agree(&s, "G3", "mode deny", &v1);
            s.cconf = cb;
            agree(&s, "G3", "mode log", &v2);
            s.cconf = cc;
            agree(&s, "G3", "child log", &v3);
            CHECK(v1.action == WE_ACT_DENY && v2.action == WE_ACT_ALLOW && v3.action == WE_ACT_ALLOW,
                  "[G3] one block, different verdicts through the confs");
            we_policy_build_free(bb);
        }
        {
            we_policy_source_t src;
            we_policy_env_t legacy = { 0xffu, 0u, 1u, 0u }, all = WE_POLICY_ENV_ALL;
            we_policy_build_t *b1 = NULL, *b2 = NULL;

            src.d = d;
            src.n = 1u;
            we_policy_build(&src, &all, NULL, &b1, &e, NULL);
            we_policy_build(&src, &legacy, NULL, &b2, &e, NULL);
            if (b1 != NULL && b2 != NULL) {
                const we_program_t *p1 = we_policy_program(b1, "http/server:a"), *p2 = we_policy_program(b2, "http/server:a");

                CHECK(p1->total_len == p2->total_len && memcmp(p1, p2, p1->total_len) != 0 && (p2->flags & WE_PF_LEGACY),
                      "[G3] a text that differs only in the legacy flag is two blocks");
            }
            we_policy_build_free(b1);
            we_policy_build_free(b2);
        }
    }
    free(rp);
}

/* ======================================================================================================
 * H3: the standing control: one store into a plane buffer must fault under mprotect
 * ==================================================================================================== */

static void test_planted_store(void)
{
    pid_t pid;
    int status = 0;

    SECTION("H3: the evaluator under mprotect; a planted store faults");
    pid = fork();
    if (pid == 0) {
        scen_t s;
        we_verdict_t v;

#ifdef WE_TEST_PLANTED_STORE
        we_test_planted = 1;                    /* the control: the store is planted in this child only */
#endif
        scen_init(&s, &W, EMPTY_FLOOR, prog1("deny if tor_exit"), A_T);
        s.hh = HH;
        run(&s, &v);
        _exit(v.action == WE_ACT_DENY ? 0 : 3);
    }
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "[H3] the evaluation runs to completion with every block and plane read-only (%s %d)",
          WIFSIGNALED(status) ? "a store faulted, signal" : "exit", WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status));
}

/* ======================================================================================================
 * R1, R2: the round trip and the verifier's twenty-two refusals
 * ==================================================================================================== */

typedef void (*mut_fn)(uint8_t *b);

static int verify_mutant(const we_program_t *p, mut_fn f, size_t extra)
{
    size_t len = p->total_len + extra + 256u;
    uint8_t *b = (uint8_t *)aligned_alloc(4096, (len + 4095u) & ~(size_t)4095u);
    we_policy_error_t e;
    int rc;

    memset(b, 0, (len + 4095u) & ~(size_t)4095u);
    memcpy(b, p, p->total_len);
    f(b);
    rc = we_program_verify((const we_program_t *)(const void *)b, ((const we_program_t *)(const void *)b)->total_len, &e);
    free(b);
    return -rc;
}

#define HDR(b)   ((we_program_t *)(void *)(b))
#define RULE(b, i) ((we_rule_t *)(void *)((b) + HDR(b)->rules_off) + (i))
#define INS(b, i)  ((we_instr_t *)(void *)((b) + HDR(b)->instrs_off) + (i))
static void m1(uint8_t *b) { HDR(b)->magic ^= 1u; }
static void m2(uint8_t *b) { HDR(b)->instrs_off += 8u; }
static void m3(uint8_t *b) { HDR(b)->op_count = 5000u; }
static void m4(uint8_t *b) { RULE(b, 0)->instr_count = (uint16_t)(RULE(b, 0)->instr_count + 1u); }
static void m5(uint8_t *b) { INS(b, 0)->op = (uint16_t)(WE_OP_BOOL | WE_OP_SEV); }
static void m6(uint8_t *b) { INS(b, 0)->plane = 8u; }
static void m7(uint8_t *b) { INS(b, 0)->off = 6u; }
static void m8(uint8_t *b) { INS(b, 0)->plane = 1u; }
static void m9(uint8_t *b) { INS(b, 0)->imm ^= WE_BOOL_POLARITY; }
static void m10(uint8_t *b) { INS(b, 0)->imm += 64u; }
static void m11(uint8_t *b) { INS(b, 1)->imm = 0u; }
static void m12(uint8_t *b) { INS(b, 0)->op = WE_OP_NOT; INS(b, 0)->plane = 0u; INS(b, 0)->off = 0u; INS(b, 0)->imm = 0u; }
static void m13(uint8_t *b) { HDR(b)->plane_mask = 0u; }
static void m14(uint8_t *b) { RULE(b, 0)->counter = 5u; }
static void m15(uint8_t *b) { HDR(b)->reserved1 = 1u; }
static void m16(uint8_t *b) { HDR(b)->flags |= 0x4u; }
static void m17(uint8_t *b) { RULE(b, 0)->action = WE_ACT_ALLOW; }
static void m18(uint8_t *b) { ((we_binding_t *)(void *)(b + HDR(b)->bindings_off))[3].tmpl[6] = 3u; }
static void m19(uint8_t *b) { INS(b, 0)->imm = WE_ASN_IMM(WE_ASN_IMM_OFF(INS(b, 0)->imm), WE_ASN_IMM_LEVELS(INS(b, 0)->imm),
                                                         WE_ASN_IMM_HASU(INS(b, 0)->imm), WE_ASN_IMM_N(INS(b, 0)->imm) + 1u); }
static void m20(uint8_t *b) { ((we_hh_hdr_t *)(void *)(b + HDR(b)->hh_off))->v4_span = 32u; }
static void m21(uint8_t *b)
{
    /* sixty-four bytes of zero between the set data and the text: hot_len no longer ends the set data */
    we_program_t *h = HDR(b);

    memmove(b + h->text_off + 64u, b + h->text_off, h->text_len);
    memset(b + h->text_off, 0, 64u);
    h->hot_len += 64u;
    h->text_off += 64u;
    h->total_len = (h->text_off + h->text_len + 63u) & ~63u;
}
static void m_pad_and_reserved1(uint8_t *b)
{
    const we_setdesc_t *sd = (const we_setdesc_t *)(const void *)(b + HDR(b)->sets_off);

    b[sd[0].data_off + 125u] = 1u;            /* step 10: the country bitmap's pad */
    HDR(b)->reserved1 = 1u;                   /* step 15: a header pad */
}
static void m_counter_and_plane(uint8_t *b)
{
    RULE(b, 0)->counter = 7u;                 /* step 14, on rule 1 */
    INS(b, RULE(b, 1)->instr_start)->plane = 10u;   /* step 6, on rule 2 */
}
static void m_op_count(uint8_t *b) { HDR(b)->op_count = (uint16_t)(HDR(b)->op_count + 1u); }
static void m_op_count_dec(uint8_t *b) { HDR(b)->op_count = (uint16_t)(HDR(b)->op_count - 1u); }
static void m22(uint8_t *b)
{
    /* one byte of the canonical text: `high` becomes `none`, the same length, a different mask */
    we_program_t *h = HDR(b);
    char *t = (char *)b + h->text_off;
    char *at = strstr(t, "high");

    if (at != NULL) {
        memcpy(at, "none", 4);
    }
}

static void test_verifier(void)
{
    SECTION("R1: compile, print, re-parse, print");
    {
        const char *l[3] = { "@p 64496 64497 64498", "allow if asn in @p and not (country in {NL BE} or rpki != valid)",
                             "deny if listed>=high" };
        const we_program_t *p = ctxprog(l, 3);
        char t1[4096];

        CHECK(p != NULL && we_program_print(p, t1, sizeof t1) > 0, "[R1] prints");
        CHECK(strcmp(t1, "allow if asn in @p and not (country in {BE NL} or rpki != valid)\ndeny if listed >= high\n") == 0,
              "[R1] the canonical text, one line per rule: %s", t1);
        CHECK(we_program_print_sets(p, t1, sizeof t1) > 0 && strcmp(t1, "@p 64496 64497 64498\n") == 0,
              "[R1] the declarations the rules use: %s", t1);
        CHECK(we_program_print(p, t1, 10u) == -1 && we_program_print_sets(p, t1, 5u) == -1,
              "[R1] a buffer too small is refused, never truncated");
        CHECK(we_program_verify(p, p->total_len, NULL) == 0, "[R1] step 22's re-parse is byte-identical");
    }

    SECTION("R2: each of the verifier's twenty-two steps refuses its own mutation");
    {
        const we_program_t *pb = prog1("deny if tor_exit and proxy");
        const we_program_t *pt = prog1("allow if tenant_allow");
        const we_program_t *pc = prog1("deny if country in { NL BE }");
        const we_program_t *pa = prog1("deny if asn in { 1 2 3 }");
        const we_program_t *ps = prog1("deny if listed >= high");
        const char *fl[1] = { "deny if tor_exit" };
        const we_program_t *pf = floorprog(fl, 1, NULL);
        const char *ll[1] = { "deny if listed >= high" };
        const we_program_t *pfl = floorprog(ll, 1, NULL);
        const char *cs[2] = { "@c NL", "deny if country in @c" };
        const we_program_t *pcs = ctxprog(cs, 2);

        CHECK(verify_mutant(pb, m1, 0) == 1, "[R2] step 1: the magic");
        CHECK(verify_mutant(pb, m2, 0) == 2, "[R2] step 2: a misaligned table offset");
        CHECK(verify_mutant(pb, m3, 0) == 3, "[R2] step 3: a count over its limit");
        CHECK(verify_mutant(pb, m4, 0) == 4, "[R2] step 4: rule ranges");
        CHECK(verify_mutant(pb, m5, 0) == 5, "[R2] step 5: an opcode of two bits");
        CHECK(verify_mutant(pb, m6, 0) == 6, "[R2] step 6: plane 9");
        CHECK(verify_mutant(pb, m7, 0) == 7, "[R2] step 7: an offset past the block");
        CHECK(verify_mutant(ps, m8, 0) == 8, "[R2] step 8: SEV off reputation");
        CHECK(verify_mutant(pt, m9, 0) == 9, "[R2] step 9: the tenant polarity bit disagrees with its occurrence");
        CHECK(verify_mutant(pc, m10, 0) == 10, "[R2] step 10: a set payload no descriptor names");
        CHECK(verify_mutant(pb, m11, 0) == 11, "[R2] step 11: a jump that is not forward");
        CHECK(verify_mutant(pb, m12, 0) == 12, "[R2] step 12: the stack underflows");
        CHECK(verify_mutant(pb, m13, 0) == 13, "[R2] step 13: a plane_mask missing a used plane");
        CHECK(verify_mutant(pb, m14, 0) == 14, "[R2] step 14: the counter");
        CHECK(verify_mutant(pb, m15, 0) == 15, "[R2] step 15: a padding byte");
        CHECK(verify_mutant(pb, m16, 0) == 16, "[R2] step 16: a header flag");
        CHECK(verify_mutant(pf, m17, 0) == 17, "[R2] step 17: an allow planted in a floor block");
        CHECK(verify_mutant(pb, m18, 0) == 18, "[R2] step 18: a routing template with rov 3");
        {
            int got = verify_mutant(pa, m19, 0);

            CHECK(got == 19, "[R2] step 19: INSET_ASN's packed n disagrees with its payload (step %d)", got);
        }
        CHECK(verify_mutant(pf, m20, 0) == 20, "[R2] step 20: a hold-harmless array with a wrong span");
        CHECK(verify_mutant(pcs, m21, 64) == 21, "[R2] step 21: hot_len past the set data");
        CHECK(verify_mutant(pfl, m22, 0) == 22, "[R2] step 22: a block whose re-parse differs by one byte");
        {
            /*
             * Two faults in one block: the step reported is the lower one in section 5.5's list, whatever
             * order the verifier meets them in (the adversarial corpus's two cases), and op_count is held
             * at step 3 to the bound the instructions give.
             */
            const char *two[2] = { "deny if tor_exit", "deny if proxy" };
            const we_program_t *p2 = ctxprog(two, 2);
            int got;

            got = verify_mutant(pc, m_pad_and_reserved1, 0);
            CHECK(got == 10, "[R2] a country payload's pad byte and reserved1 together report step 10 (step %d)", got);
            got = verify_mutant(p2, m_counter_and_plane, 0);
            CHECK(got == 6, "[R2] rule 1's counter and rule 2's plane 10 together report step 6 (step %d)", got);
            got = verify_mutant(pb, m_op_count, 0);
            CHECK(got == 3, "[R2] step 3: op_count outside the operations the instructions hold (step %d)", got);
            got = verify_mutant(prog1("deny if not tor_exit"), m_op_count_dec, 0);
            CHECK(got == 22, "[R2] the control: an op_count inside the bound but not the text's is step 22's (step %d)",
                  got);
        }
    }
}

/* ======================================================================================================
 * N2-N8, P2, P3: the compiler's other refusals and literal forms
 * ==================================================================================================== */

static int refused(const char *line, const char *layer, const char *phrase, we_policy_error_t *e)
{
    we_policy_build_t *b = NULL;
    int rc = compile1(line, &b, e);

    we_policy_build_free(b);
    return rc == WE_POLICY_REFUSED && (layer == NULL || strcmp(e->layer, layer) == 0)
        && (phrase == NULL || strstr(e->phrase, phrase) != NULL || strstr(e->what, phrase) != NULL
            || strstr(e->fix, phrase) != NULL);
}

static int accepted(const char *line)
{
    we_policy_build_t *b = NULL;
    we_policy_error_t e;
    int rc = compile1(line, &b, &e);

    if (rc != WE_POLICY_OK) {
        printf("    (refused: %s: %s near \"%s\")\n", e.layer, e.what, e.token);
    }
    we_policy_build_free(b);
    return rc == WE_POLICY_OK;
}

/* a set declaration and one rule in http/server:a, compiled in an environment */
static int compile_set_rule(const char *set, const char *rule, const we_policy_env_t *env, we_policy_error_t *e)
{
    we_policy_directive_t d[2];
    we_policy_source_t s;
    we_policy_build_t *b = NULL;
    int rc;

    d[0].kind = WE_DIR_SET;
    d[0].context = "http";
    d[0].arg = (const uint8_t *)set;
    d[0].len = strlen(set);
    d[1].kind = WE_DIR_POLICY;
    d[1].context = "http/server:a";
    d[1].arg = (const uint8_t *)rule;
    d[1].len = strlen(rule);
    s.d = d;
    s.n = 2u;
    s.context = NULL;
    s.floor = 0;
    rc = we_policy_build(&s, env, NULL, &b, e, &REP);
    we_policy_build_free(b);
    return rc;
}

static void test_rulings(void)
{
    static const we_policy_env_t all = WE_POLICY_ENV_ALL;
    we_policy_error_t e;
    int rc;

    SECTION("N1 rules: undetermined only where a sentinel is, the bool's undetermined, an inline set's one class");
    /* undetermined is a member only of a set whose attribute carries the sentinel */
    CHECK(refused("deny if listed in { undetermined }", "typing", "listed takes", &e) && e.col == 21u
          && strcmp(e.token, "undetermined") == 0, "[N1] listed in {undetermined}: wrong class at the member (col %u %s)",
          e.col, e.token);
    CHECK(refused("deny if listed == undetermined", "typing", "listed takes", &e),
          "[N1] listed == undetermined: wrong class, as the set form is");
    /* POLICY.md 5.6, the D-z addendum: a declared set's class is known at step 6, so it is refused at the use */
    rc = compile_set_rule("@u undetermined", "deny if listed in @u", &all, &e);
    CHECK(rc == WE_POLICY_REFUSED && strcmp(e.layer, "sets") == 0 && e.kind == WE_DIR_POLICY && e.col == 19u
          && strcmp(e.token, "@u") == 0 && strcmp(e.phrase, "a set used against an attribute of another class") == 0,
          "[N1] @u undetermined used against listed: a set of another class, at the use (%s %s col %u %s)",
          rc == WE_POLICY_REFUSED ? e.layer : "accepted", e.token, e.col, e.phrase);
    rc = compile_set_rule("@lv low undetermined", "deny if listed in @lv", &all, &e);
    CHECK(rc == WE_POLICY_REFUSED && e.kind == WE_DIR_POLICY && strcmp(e.token, "@lv") == 0,
          "[N1] a level set holding undetermined, against listed: refused at the use (%s)", e.token);
    CHECK(compile_set_rule("@u undetermined", "deny if asn in @u", &all, &e) == WE_POLICY_OK,
          "[N1] the control: @u undetermined against asn, which carries the sentinel, compiles");
    CHECK(compile_set_rule("@lv low high", "deny if listed in @lv", &all, &e) == WE_POLICY_OK,
          "[N1] the control: a level set without undetermined compiles against listed");
    /* undetermined on a bool, after the operator */
    CHECK(refused("deny if tor_exit == undetermined", "typing", "undetermined on a bool", &e) && e.col == 21u,
          "[N1] tor_exit == undetermined: undetermined on a bool, at the literal (col %u)", e.col);
    CHECK(refused("deny if tor_exit != undetermined", "typing", "undetermined on a bool", &e),
          "[N1] tor_exit != undetermined: undetermined on a bool");
    CHECK(refused("deny if tor_exit in { undetermined undetermined }", "typing", "undetermined on a bool", &e)
          && e.col == 23u, "[N1] tor_exit in {undetermined ...}: undetermined on a bool at the first member (col %u)", e.col);
    CHECK(refused("deny if tor_exit in { undetermined NL }", "typing", "in or == on a bool", &e),
          "[N1] the control: a set that is not all undetermined is in or == on a bool");
    CHECK(refused("deny if tor_exit == NL", "typing", "in or == on a bool", &e),
          "[N1] the control: == with another operand is in or == on a bool");
    CHECK(refused("deny if tor_exit >= undetermined", "typing", "an ordered comparison on anything but listed", &e),
          "[N1] the operator is judged before the operand");
    /* an inline set's one class, before the attribute's */
    CHECK(refused("deny if asn in { 64496 NL }", "typing", "an inline set whose members are not all of one class", &e)
          && e.col == 24u && strcmp(e.token, "NL") == 0, "[N1] a mixed inline set: refused at the first member of "
          "another class (col %u %s)", e.col, e.token);
    CHECK(refused("deny if asn in { undetermined NL 64496 }", "typing", "an inline set whose members are not all", &e)
          && strcmp(e.token, "64496") == 0, "[N1] undetermined takes the others' class: the class is NL's (%s)", e.token);
    CHECK(refused("deny if country in { 64496 64497 }", "typing", "country takes", &e) && strcmp(e.token, "64496") == 0,
          "[N1] a uniform set of the wrong class: wrong class at its first member (%s)", e.token);
    CHECK(accepted("deny if country in { NL BE undetermined }"), "[N1] the control: one class and a sentinel compile");

    SECTION("S1: a context of any depth and length (the fuzzer's first find: the table was sized by guess)");
    {
        static char deep[40000];
        we_policy_directive_t d[2];
        we_policy_source_t src;
        we_policy_build_t *b = NULL;
        size_t o = 0u;
        int k;

        o += (size_t)snprintf(deep + o, sizeof deep - o, "http");
        for (k = 0; k < 3000; k++) {
            o += (size_t)snprintf(deep + o, sizeof deep - o, "/l%d", k);
        }
        d[0].kind = WE_DIR_SET;
        d[0].context = deep;
        d[0].arg = (const uint8_t *)"@e KP";
        d[0].len = 5u;
        d[1].kind = WE_DIR_POLICY;
        d[1].context = deep;
        d[1].arg = (const uint8_t *)"deny if country in @e";
        d[1].len = strlen((const char *)d[1].arg);
        src.d = d;
        src.n = 2u;
        src.context = NULL;
        src.floor = 0;
        rc = we_policy_build(&src, &all, NULL, &b, &e, NULL);
        CHECK(rc == WE_POLICY_OK && we_policy_program(b, deep) != NULL,
              "[S1] a context 3,001 levels and %zu bytes deep compiles and runs its own program (%d)", o, rc);
        we_policy_build_free(b);
    }

    SECTION("S1: a context the configuration never named resolves to its nearest named ancestor, at any length");
    {
        /*
         * The program and the conf walk the same ancestors, by prefix length over the caller's string.
         * A parent of 511 bytes and more is where a fixed 512-byte copy stopped finding the parent, and a
         * lineless child read its conf from nothing at all (mode UNSET); 40 is the short control.
         */
        static const size_t lens[4] = { 40u, 511u, 512u, 3000u };
        static char parent[3100], child[3200];
        size_t li;

        for (li = 0u; li < 4u; li++) {
            we_policy_directive_t d[2];
            we_policy_build_t *bb = NULL;
            const char *rule = "deny if tor_exit";
            size_t k;

            memcpy(parent, "http/server:", 12u);
            for (k = 12u; k < lens[li]; k++) {
                parent[k] = (char)('a' + (char)(k % 26u));
            }
            parent[lens[li]] = '\0';
            snprintf(child, sizeof child, "%s/location:x/if:y", parent);
            d[0].kind = WE_DIR_POLICY;
            d[0].context = parent;
            d[0].arg = (const uint8_t *)rule;
            d[0].len = strlen(rule);
            d[1].kind = WE_DIR_MODE;
            d[1].context = parent;
            d[1].arg = (const uint8_t *)"log";
            d[1].len = 3u;
            CHECK(compile_src(d, 2u, &bb, &e) == WE_POLICY_OK, "[S1] a %zu-byte parent compiles", lens[li]);
            if (bb != NULL) {
                const we_program_t *pp = we_policy_program(bb, parent), *pc = we_policy_program(bb, child);
                we_ctx_conf_t cp = we_policy_conf(bb, parent), cc = we_policy_conf(bb, child);
                we_ctx_conf_t cz = we_policy_conf(bb, "zz/location:x");

                CHECK(pp != NULL && pc == pp, "[S1] a %zu-byte parent: the never-named child two levels down runs "
                      "the parent's program", lens[li]);
                CHECK(cp.mode == WE_MODE_LOG && cc.mode == WE_MODE_LOG, "[S1] a %zu-byte parent: the child's conf "
                      "is the parent's mode log (%u), not UNSET", lens[li], (unsigned)cc.mode);
                CHECK(we_policy_program(bb, "zz/location:x") == NULL && cz.mode == WE_MODE_UNSET,
                      "[S1] the control: a context with no named ancestor runs nothing and has no mode");
                we_policy_build_free(bb);
            }
        }
    }

    SECTION("D23: a FIFO at a plane path is present, not schema-ok, and never blocks the probe");
    {
        char dir[600], p1[700], p2[700], p3[700];
        we_policy_env_t env;
        int fd;

        snprintf(dir, sizeof dir, "%s/probe-fifo", TMP);
        snprintf(p1, sizeof p1, "%s/tor.bin", dir);
        snprintf(p2, sizeof p2, "%s/threat.bin", dir);
        snprintf(p3, sizeof p3, "%s/anonymizer.bin", dir);
        mkdir(dir, 0755);
        unlink(p1);
        unlink(p2);
        unlink(p3);
        CHECK(mkfifo(p1, 0644) == 0 && symlink("/dev/null", p2) == 0, "[D23] a FIFO and a device link planted");
        fd = open(p3, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            close(fd);
        }
        alarm(10);
        CHECK(we_policy_env_probe(dir, &env) == 0, "[D23] the probe returns");
        alarm(0);
        CHECK((env.present & (1u << 1)) != 0u && (env.schema_ok & (1u << 1)) == 0u,
              "[D23] the FIFO tor.bin: present, schema not ok");
        CHECK((env.present & (1u << 5)) != 0u && (env.schema_ok & (1u << 5)) == 0u,
              "[D23] threat.bin linked to /dev/null: present, schema not ok");
        CHECK((env.present & (1u << 4)) != 0u && (env.schema_ok & (1u << 4)) == 0u,
              "[D23] the control: an empty regular anonymizer.bin is present and not ok, read without blocking");
        CHECK((env.present & 1u) == 0u, "[D23] an absent reputation.bin stays absent");
        unlink(p1);
        unlink(p2);
        unlink(p3);
    }

    SECTION("D4: a threshold context's sugar is compiled for the build's environment, not for every plane");
    {
        we_policy_directive_t d[2];
        we_policy_source_t src;
        we_policy_build_t *bs = NULL;
        we_policy_env_t no_routing = WE_POLICY_ENV_ALL;
        we_program_t *direct = NULL;
        we_policy_error_t es;

        no_routing.present = (uint8_t)(0xffu & ~(1u << 3));
        no_routing.schema_ok = no_routing.present;
        d[0].kind = WE_DIR_MODE;
        d[0].context = "http/server:c";
        d[0].arg = (const uint8_t *)"deny";
        d[0].len = 4u;
        d[1].kind = WE_DIR_THRESHOLD;
        d[1].context = "http/server:c";
        d[1].arg = (const uint8_t *)"high";
        d[1].len = 4u;
        src.d = d;
        src.n = 2u;
        src.context = NULL;
        src.floor = 0;
        CHECK(we_policy_build(&src, &no_routing, NULL, &bs, &es, NULL) == WE_POLICY_OK, "[D4] the threshold builds");
        if (bs != NULL) {
            const we_program_t *ps = we_policy_program(bs, "http/server:c");
            static const char line[] = "deny if listed >= high";
            we_policy_directive_t t;
            we_policy_source_t ts;

            CHECK(ps != NULL && we_program_env_matches(ps, &no_routing) == 0,
                  "[D4] the sugar's block is armed in the environment it was built in");
            t.kind = WE_DIR_POLICY;
            t.context = "http/server:c";
            t.arg = (const uint8_t *)line;
            t.len = sizeof line - 1u;
            ts.d = &t;
            ts.n = 1u;
            ts.context = "http/server:c";
            ts.floor = 0;
            CHECK(we_policy_compile(&ts, &no_routing, NULL, &direct, &es, NULL) == WE_POLICY_OK && direct != NULL
                  && ps != NULL && direct->total_len == ps->total_len && memcmp(direct, ps, ps->total_len) == 0,
                  "[D4] the sugar is byte-identical to its equivalent rule in the same environment");
            free(direct);
            direct = NULL;
            CHECK(we_policy_sugar_env(3u, &no_routing, NULL, &direct) == WE_POLICY_OK && direct != NULL && ps != NULL
                  && direct->total_len == ps->total_len && memcmp(direct, ps, ps->total_len) == 0
                  && we_program_env_matches(direct, &no_routing) == 0,
                  "[D4] we_policy_sugar_env() is the block the build arms for that context, armed in its environment");
            free(direct);
            direct = NULL;
            CHECK(we_policy_sugar(3u, NULL, &direct) == WE_POLICY_OK && direct != NULL
                  && we_program_env_matches(direct, &no_routing) == -1 && we_program_env_matches(direct, &all) == 0,
                  "[D4] we_policy_sugar() is the all-present block: refused where a plane is absent, armed where none is");
            free(direct);
            we_policy_build_free(bs);
        }
    }

    SECTION("A1: a canonical address defines every byte, so memcmp compares addresses");
    {
        we_addr_t a1, a2;
        uint8_t in4[16] = { 198, 51, 100, 7 }, in6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 7 };

        memset(&a1, 0xAA, sizeof a1);
        memset(&a2, 0x55, sizeof a2);
        we_addr_canon(in4, 4, &a1);
        we_addr_canon(in6, 6, &a2);
        CHECK(a1.pad[0] == 0u && a1.pad[6] == 0u && a2.pad[3] == 0u, "[A1] the padding is written zero");
        CHECK(memcmp(&a1, &a2, sizeof a1) == 0, "[A1] 198.51.100.7 and ::ffff:198.51.100.7 compare equal by memcmp, "
              "over buffers that held different garbage");
        in6[15] = 8u;
        we_addr_canon(in6, 6, &a2);
        CHECK(memcmp(&a1, &a2, sizeof a1) != 0, "[A1] the control: another address compares unequal");
    }

    SECTION("D21: the attribute table and the verdict lines a tool renders, exported");
    {
        we_attr_info_t ai;
        uint8_t blk[16];
        char buf[64];
        uint32_t i, n = we_attr_count(), seen_reg = 0u;
        we_verdict_t vv;
        static char vl[WE_VERDICT_LINE_MAX], cl[WE_VERDICT_LINE_MAX], small[16];

        CHECK(n == 25u, "[D21] 25 attributes (%u)", n);
        CHECK(we_attr_info(n, &ai) == -1 && we_attr_render(n, blk, WE_ST_FRESH_HIT, buf, sizeof buf) == -1,
              "[D21] an index past the table is refused");
        for (i = 0u; i < n; i++) {
            CHECK(we_attr_info(i, &ai) == 0 && ai.name != NULL && ai.plane_id >= 1u && ai.plane_id <= 8u
                  && ai.off < 16u, "[D21] attribute %u is described", i);
            if (strcmp(ai.name, "registry_country") == 0 || strcmp(ai.name, "registry_rir") == 0) {
                seen_reg += ai.plane_id == 7u && strcmp(ai.plane, "registry") == 0;
            }
        }
        CHECK(seen_reg == 2u, "[D21] registry_country and registry_rir read the registry plane, not routing");
        /* each class, from a block written as the fill writes it */
        memset(blk, 0, sizeof blk);
        for (i = 0u; i < n; i++) {
            we_attr_info(i, &ai);
            if (strcmp(ai.name, "asn") == 0) {
                uint32_t a = 0xffffffffu;

                memcpy(blk + ai.off, &a, 4);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "undetermined") == 0, "[D21] asn 0xFFFFFFFF renders undetermined, never decimal (%s)", buf);
                a = 64496u;
                memcpy(blk + ai.off, &a, 4);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "64496") == 0, "[D21] asn 64496 renders decimal (%s)", buf);
            } else if (strcmp(ai.name, "country") == 0) {
                uint16_t c = 528u;

                memcpy(blk + ai.off, &c, 2);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "NL") == 0, "[D21] country 528 renders NL (%s)", buf);
                c = 0u;
                memcpy(blk + ai.off, &c, 2);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "undetermined") == 0, "[D21] country 0 renders undetermined (%s)", buf);
                c = 999u;                       /* in range, assigned to nothing the table knows */
                memcpy(blk + ai.off, &c, 2);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "undetermined") == 0, "[D21] an unknown country code renders undetermined, never decimal (%s)", buf);
                c = 1000u;                      /* past the numeric range: a raw block only */
                memcpy(blk + ai.off, &c, 2);
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "undetermined") == 0, "[D21] a country code above 999 renders undetermined (%s)", buf);
                c = 0u;
                memcpy(blk + ai.off, &c, 2);
            } else if (strcmp(ai.name, "listed") == 0) {
                blk[ai.off] = 0x83u;            /* inferred, high */
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "high") == 0, "[D21] listed renders its level (%s)", buf);
                blk[ai.off] = 0u;
            } else if (strcmp(ai.name, "rpki") == 0) {
                blk[ai.off] = 3u;
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "not-found") == 0, "[D21] rpki 3 renders not-found (%s)", buf);
                blk[ai.off] = 0u;
            } else if (strcmp(ai.name, "tor_exit") == 0) {
                blk[ai.off] = ai.mask;
                we_attr_render(i, blk, WE_ST_FRESH_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "true") == 0, "[D21] a set bool renders true (%s)", buf);
                we_attr_render(i, blk, WE_ST_UNKNOWN, buf, sizeof buf);
                CHECK(strcmp(buf, "unknown") == 0, "[D21] the same bool on an unknown plane renders unknown");
                we_attr_render(i, blk, WE_ST_STALE_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "unknown") == 0, "[D21] a stale non-tenant plane renders unknown");
                we_attr_render(i, blk, WE_ST_NONE, buf, sizeof buf);
                CHECK(strcmp(buf, "unread") == 0, "[D21] a plane not looked up renders unread");
                blk[ai.off] = 0u;
            } else if (strcmp(ai.name, "tenant_allow") == 0) {
                blk[ai.off] = ai.mask;
                we_attr_render(i, blk, WE_ST_STALE_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "stale:true") == 0, "[D21] a stale tenant plane renders its bounded reading (%s)", buf);
                blk[14] = 1u;                   /* the entry's lapsed byte: past the 48-hour grace */
                we_attr_render(i, blk, WE_ST_STALE_HIT, buf, sizeof buf);
                CHECK(strcmp(buf, "lapsed:true") == 0, "[D21] a tenant past its grace renders lapsed: (%s)", buf);
                we_attr_render(i, blk, WE_ST_STALE_NR, buf, sizeof buf);
                CHECK(strcmp(buf, "lapsed:true") == 0, "[D21] the lapsed reading reads the block whatever the range (%s)", buf);
                blk[14] = 0u;
                we_attr_render(i, blk, WE_ST_REVOKED, buf, sizeof buf);
                CHECK(strcmp(buf, "revoked") == 0, "[D21] a revoked tenant plane renders revoked");
                blk[ai.off] = 0u;
            }
        }
        /* the verdict lines: the format the differential compares; truncation is reported, never silent */
        memset(&vv, 0, sizeof vv);
        vv.step = WE_STEP_CONTEXT;
        vv.action = WE_ACT_DENY;
        vv.program = WE_VPROG_CONTEXT;
        vv.rule = 3u;
        vv.log_fired[1][0] = 0x05u;
        CHECK(we_verdict_format(&vv, vl, cl, sizeof vl) == 0
              && strcmp(vl, "verdict step=4 action=deny program=ctx rule=3 reason=- log_floor=- log_ctx=1,3") == 0
              && strncmp(cl, "cost ops=0/0 jumps=0/0", 22) == 0, "[D21] the verdict lines (%s | %s)", vl, cl);
        CHECK(we_verdict_format(&vv, small, small, sizeof small) == -1 && strlen(small) == sizeof small - 1u,
              "[D21] a short buffer is reported and still terminated");
    }

    SECTION("D4: a block is armed only in the environment it was compiled for");
    {
        we_policy_env_t no_routing = WE_POLICY_ENV_ALL, legacy = WE_POLICY_ENV_ALL;
        we_policy_build_t *b1 = NULL;
        const we_program_t *p1;

        no_routing.present = (uint8_t)(0xffu & ~(1u << 3));
        no_routing.schema_ok = no_routing.present;
        legacy.legacy = 1u;
        rc = compile1("deny if asn == 64496 or tor_exit", &b1, &e);
        p1 = rc == WE_POLICY_OK ? we_policy_program(b1, "http/server:a") : NULL;
        CHECK(p1 != NULL && we_program_env_matches(p1, &all) == 0, "[D4] a block matches the environment it was built in");
        CHECK(p1 != NULL && we_program_env_matches(p1, &no_routing) == -1,
              "[D4] the same block, offered where routing is absent, is refused: its routing binding is not inert");
        CHECK(p1 != NULL && we_program_env_matches(p1, &legacy) == -1,
              "[D4] the same block, offered to a legacy configuration, is refused: its legacy flag differs");
        we_policy_build_free(b1);
    }

    SECTION("D2 rule: an inert rule neither shadows nor is shadowed");
    {
        we_policy_env_t no_routing = WE_POLICY_ENV_ALL;
        we_policy_directive_t d[2];
        we_policy_source_t s;
        we_policy_build_t *b = NULL;

        no_routing.present = (uint8_t)(0xffu & ~(1u << 3));
        no_routing.schema_ok = no_routing.present;
        d[0].kind = d[1].kind = WE_DIR_POLICY;
        d[0].context = d[1].context = "http/server:a";
        d[0].arg = (const uint8_t *)"deny if asn == 64496";
        d[0].len = strlen((const char *)d[0].arg);
        d[1].arg = d[0].arg;
        d[1].len = d[0].len;
        s.d = d;
        s.n = 2u;
        s.context = NULL;
        s.floor = 0;
        report_len = 0u;
        if (report_buf != NULL) {
            report_buf[0] = '\0';
        }
        CHECK(we_policy_build(&s, &no_routing, NULL, &b, &e, &REP) == WE_POLICY_OK
              && (report_buf == NULL || strstr(report_buf, "shadowed-by") == NULL),
              "[D2] routing absent: two inert copies of one rule, no shadowed-by (%s)", report_buf != NULL ? report_buf : "");
        we_policy_build_free(b);
        report_len = 0u;
        if (report_buf != NULL) {
            report_buf[0] = '\0';
        }
        CHECK(we_policy_build(&s, &all, NULL, &b, &e, &REP) == WE_POLICY_OK && report_buf != NULL
              && strstr(report_buf, "report ctx http/server:a 2 shadowed-by 1\n") != NULL,
              "[D2] the control: routing present, rule 2 is shadowed by rule 1");
        we_policy_build_free(b);
    }
}

static void test_refusals(void)
{
    we_policy_error_t e;
    unsigned c, pos;

    SECTION("N2: every byte outside the alphabet, at three positions, rendered as \\xHH");
    for (c = 0u; c < 256u; c++) {
        int ws = c == 0x09u || c == 0x0au || c == 0x0bu || c == 0x0cu || c == 0x0du || c == 0x20u;

        if ((c >= 0x20u && c <= 0x7eu) && c != 0x20u) {
            continue;
        }
        for (pos = 0u; pos < 3u; pos++) {
            char line[64];
            size_t at = pos == 0u ? 0u : pos == 1u ? 12u : 16u;
            char want[16];

            snprintf(line, sizeof line, "deny if tor_exit");
            if (pos == 2u) {
                line[16] = (char)c;
                line[17] = '\0';
            } else {
                memmove(line + at + 1u, line + at, strlen(line) - at + 1u);
                line[at] = (char)c;
            }
            {
                we_policy_directive_t d;
                we_policy_build_t *b = NULL;
                int rc;

                d.kind = WE_DIR_POLICY;
                d.context = "http/server:a";
                d.arg = (const uint8_t *)line;
                d.len = pos == 2u ? 17u : 17u;
                rc = compile_src(&d, 1u, &b, &e);
                we_policy_build_free(b);
                snprintf(want, sizeof want, "\\x%02X", c);
                if (ws) {
                    continue;      /* whitespace separates tokens: legal, or a lexing matter, never an alphabet one */
                }
                CHECK(rc == WE_POLICY_REFUSED && strcmp(e.layer, "alphabet") == 0 && e.col == at + 1u
                      && strcmp(e.token, want) == 0,
                      "[N2] byte 0x%02X at column %zu: alphabet, token %s (got %s col %u \"%s\")", c, at + 1u, want,
                      rc == WE_POLICY_REFUSED ? e.layer : "accepted", e.col, e.token);
            }
        }
    }
    CHECK(refused("deny if tor_exit\r\x1b[31m", "alphabet", "byte 0x1B", &e) && strchr(e.token, '\x1b') == NULL,
          "[N2] an ESC never reaches the log unescaped");
    CHECK(refused("deny if \"tor_exit", "lexing", "byte 0x22 is not allowed", &e) && strcmp(e.token, "\\x22") == 0,
          "[N2] a double quote renders as \\x22 (%s)", e.token);

    SECTION("N3: the limits at the boundary and one past");
    {
        /*
         * The hot-byte limit at its exact boundary, from the adversarial corpus: h1 is exactly
         * 262,144 hot bytes and compiles and verifies, h2 is 64 more and is refused by name, and h3 is a
         * floor whose rules alone fit but whose hold-harmless arrays (section 2.1 counts them) do not.
         */
        static corpus_src_t hs;
        static const struct { const char *file; int ok; } H[] = {
            { "testdata/policy/adversarial/h1-hot-exact.policy", 1 },
            { "testdata/policy/adversarial/h2-hot-plus64.policy", 0 },
            { "testdata/policy/adversarial/h3-floor-hot.policy", 0 },
        };
        size_t q;

        for (q = 0u; q < sizeof H / sizeof H[0]; q++) {
            we_policy_build_t *hb = NULL;
            int hrc;

            CHECK(parse_policy_file(H[q].file, &hs) == 0, "[N3] %s reads", H[q].file);
            hrc = compile_src(hs.d, hs.n, &hb, &e);
            if (H[q].ok) {
                const we_program_t *hp = hrc == WE_POLICY_OK ? we_policy_program(hb, "http/server:a") : NULL;

                CHECK(hp != NULL && hp->hot_len == 262144u && we_program_verify(hp, hp->total_len, NULL) == 0,
                      "[N3] %s: exactly 262,144 hot bytes, compiled and verified (%u)", H[q].file,
                      hp != NULL ? hp->hot_len : 0u);
            } else {
                CHECK(hrc == WE_POLICY_REFUSED && strcmp(e.phrase, "over 256 KiB of program bytes") == 0,
                      "[N3] %s: refused by name (%s)", H[q].file, hrc == WE_POLICY_REFUSED ? e.phrase : "compiled");
            }
            we_policy_build_free(hb);
            free(hs.buf);
            hs.buf = NULL;
        }
    }
    {
        static char big[8192];
        size_t o;
        int k;

        o = (size_t)snprintf(big, sizeof big, "@s ");
        o = (size_t)snprintf(big, sizeof big, "@%s", "a");
        for (k = 0; k < 63; k++) {
            big[o++] = 'a';
        }
        big[o] = '\0';
        {
            static char line[8400];

            snprintf(line, sizeof line, "deny if asn in %s", big);
            CHECK(refused(line, "sets", "undefined", &e), "[N3] a 64-byte identifier lexes (and is undefined here)");
            big[o++] = 'a';
            big[o] = '\0';
            snprintf(line, sizeof line, "deny if asn in %s", big);
            CHECK(refused(line, "lexing", "identifier over 64 bytes", &e), "[N3] a 65-byte identifier is refused");
        }
        /* the ASN set limit, derived: a 2,048-byte declaration of 539 distinct members, and the one past */
        o = (size_t)snprintf(big, sizeof big, "@s");
        for (k = 0; k < 539; k++) {
            o += (size_t)snprintf(big + o, sizeof big - o, " %d", k);
        }
        CHECK(o == 2048u, "[N3] the maximal ASN declaration is exactly 2,048 bytes (%zu)", o);
        {
            const char *l[2];

            l[0] = big;
            l[1] = "log if asn in @s";
            CHECK(ctxprog(l, 2) != NULL, "[N3] 539 members compile and verify (WE_LIM_ASN_MEMBERS)");
        }
        /* 8,448 instructions: 128 rules of 15 operations and 128 of 17 reach both limits exactly */
        {
            static char lines[256][256];
            const char *lp[256];
            we_policy_directive_t d[256];
            we_policy_build_t *b = NULL;
            int r;

            for (r = 0; r < 256; r++) {
                if (r % 2 == 0) {
                    snprintf(lines[r], sizeof lines[r], "deny if rpki != valid or rpki != invalid or rpki != unrouted or "
                             "rpki != not-found or asn != 1 or asn != 2 or asn != 3 or asn != 4");
                } else {
                    /* nine != atoms in an or-chain: 17 operations, 2 * 17 + 1 = 35 instructions */
                    snprintf(lines[r], sizeof lines[r], "deny if rpki != valid or rpki != invalid or rpki != unrouted or "
                             "rpki != not-found or asn != 1 or asn != 2 or asn != 3 or asn != 4 or asn != 5");
                }
                lp[r] = lines[r];
                d[r].kind = WE_DIR_POLICY;
                d[r].context = "http/server:a";
                d[r].arg = (const uint8_t *)lp[r];
                d[r].len = strlen(lp[r]);
            }
            CHECK(compile_src(d, 256u, &b, &e) == WE_POLICY_OK, "[N3] 256 rules, 4,096 operations: %s", e.what);
            if (b != NULL) {
                const we_program_t *p = we_policy_program(b, "http/server:a");

                CHECK(p->instr_count == WE_LIM_INSTRS && p->op_count == WE_LIM_OPS_CTX,
                      "[N3] exactly 8,448 instructions and 4,096 operations (%u, %u)", p->instr_count, p->op_count);
            }
            we_policy_build_free(b);
        }
        /* the hot-bytes limit: 200 rules, each with its own 400-member inline set of 1,792 payload bytes */
        {
            static char lines[200][2200];
            static we_policy_directive_t d[200];
            we_policy_build_t *b = NULL;
            int r, j;

            for (r = 0; r < 200; r++) {
                o = (size_t)snprintf(lines[r], sizeof lines[r], "log if asn in{");
                for (j = 0; j < 400; j++) {
                    o += (size_t)snprintf(lines[r] + o, sizeof lines[r] - o, "%s%d", j ? "," : "", 100 + j + r);
                }
                snprintf(lines[r] + o, sizeof lines[r] - o, "}");
                d[r].kind = WE_DIR_POLICY;
                d[r].context = "http/server:a";
                d[r].arg = (const uint8_t *)lines[r];
                d[r].len = strlen(lines[r]);
            }
            CHECK(compile_src(d, 200u, &b, &e) == WE_POLICY_REFUSED && strcmp(e.layer, "program") == 0
                  && strstr(e.what, "256 KiB") != NULL && strstr(e.what, "hot") != NULL,
                  "[N3] past the hot-bytes limit: refused with the sizes printed (%s)", e.what);
            we_policy_build_free(b);
        }
        CHECK(accepted("deny if listed>=high"), "[N3] an unspaced argument");
    }

    SECTION("N4, N5, N7, N8: polarity, the sentinel warning, the order, the all-absent warning");
    {
        const char *l1[2] = { "allow if tor_exit is unknown", "log if c2" };
        we_policy_directive_t d[2];
        we_policy_build_t *b = NULL;

        CHECK(refused("deny if tor_exit is unknown", "polarity", "that is a fail-closed rule", &e),
              "[N4] is unknown positive in a deny is refused");
        /* `is not unknown` is the negative polarity: accepted in a deny, refused in an allow above a deny */
        CHECK(accepted("deny if tor_exit is not unknown and tor_exit"),
              "[N4] is not unknown in a deny is negative, so accepted (the design example)");
        d[0].kind = d[1].kind = WE_DIR_POLICY;
        d[0].context = d[1].context = "http/server:a";
        d[0].arg = (const uint8_t *)"allow if tor_exit is not unknown";
        d[0].len = strlen((const char *)d[0].arg);
        d[1].arg = (const uint8_t *)"deny if c2";
        d[1].len = strlen((const char *)d[1].arg);
        CHECK(compile_src(d, 2u, &b, &e) == WE_POLICY_REFUSED && strcmp(e.layer, "polarity") == 0,
              "[N4] is not unknown in an allow above a deny is negative there, so refused");
        we_policy_build_free(b);
        b = NULL;
        d[0].kind = d[1].kind = WE_DIR_POLICY;
        d[0].context = d[1].context = "http/server:a";
        d[0].arg = (const uint8_t *)"allow if not tor_exit is unknown";
        d[0].len = strlen((const char *)d[0].arg);
        d[1].arg = (const uint8_t *)"deny if c2";
        d[1].len = strlen((const char *)d[1].arg);
        CHECK(compile_src(d, 2u, &b, &e) == WE_POLICY_REFUSED && strcmp(e.layer, "polarity") == 0,
              "[N4] is unknown negative in an allow with a later deny is refused");
        we_policy_build_free(b);
        b = NULL;
        CHECK(ctxprog(l1, 2) != NULL, "[N4] the same allow with no later deny compiles");
        CHECK(accepted("log if tor_exit is unknown") && accepted("log if not tor_exit is unknown"),
              "[N4] is unknown in a log rule, in either polarity");
        nreports = 0;
        CHECK(accepted("allow if country != NL") && nreports > 0 && strstr(last_report, "undetermined") != NULL,
              "[N5] != over a sentinel attribute in an allow is warned: %s", last_report);
        nreports = 0;
        CHECK(accepted("allow if not (asn_rep == suspicious or asn_rep == neutral)") && nreports > 0,
              "[N5] not (a == x or a == y) is warned");
        nreports = 0;
        CHECK(accepted("allow if country == NL") && nreports == 0, "[N5] positive == is not warned");
        nreports = 0;
        CHECK(accepted("deny if country != NL") && strstr(last_report, "undetermined") == NULL,
              "[N5] the same test in a deny is not warned");
        CHECK(accepted("allow if country != NL and country != undetermined"), "[N5] the suggested fix compiles");
        CHECK(refused("deny if rpki == XX", "typing", "rpki takes valid", &e), "[N7] rpki == XX is a typing refusal");
        CHECK(refused("deny if tor_exit garbage 010", "lexing", NULL, &e), "[N7] a lexing fault beats a later parsing fault");
        nreports = 0;
        CHECK(accepted("deny if listed >= none") && strstr(last_report, "denies every address") != NULL,
              "[N8] listed >= none is warned");
        nreports = 0;
        CHECK(accepted("deny if listed < low") && strstr(last_report, "denies every address") != NULL,
              "[N8] listed < low is warned");
        nreports = 0;
        CHECK(accepted("deny if not tor_exit") && strstr(last_report, "denies every address") != NULL,
              "[N8] deny if not tor_exit is warned");
        nreports = 0;
        CHECK(accepted("deny if not country in { NL }") && strstr(last_report, "denies every address") != NULL,
              "[N8] deny if not country in { NL } is warned (country is undetermined there)");
        nreports = 0;
        CHECK(accepted("deny if tor_exit") && nreports == 0, "[N8] deny if tor_exit is not warned");
    }

    SECTION("N6: threshold beside lines, allow in a floor, the bare action");
    CHECK(refused("deny", "parsing", "deny if not <condition>", &e) && e.col == 5u, "[N6] the bare deny");

    SECTION("P2, P3: the literal forms");
    {
        static const char *const ok[] = {
            "log if rpki == undetermined", "log if rpki_reason == undetermined", "log if asn == undetermined",
            "log if asn_rep == undetermined", "log if country == undetermined", "log if registry_country == undetermined",
            "log if rir == undetermined", "log if registry_rir == undetermined", "log if country == IN",
            "log if country in { in is no as do }", "log if country == nl", "log if country == Nl", "log if asn == as64496",
            "log if asn == AS64496", "log if asn == As64496", "log if asn == 64496", "log if asn == 0", "log if asn == as0",
            "log if rpki == not-found", "log if rpki == not_found", "log if rpki == notfound",
        };
        static const char *const bad[] = { "log if tor_exit == undetermined", "log if asn == 00", "log if asn == 010",
                                           "log if asn == as1.10", "log if asn == as 64496", "log if listed == undetermined" };
        unsigned i;

        for (i = 0u; i < sizeof ok / sizeof ok[0]; i++) {
            CHECK(accepted(ok[i]), "[P2][P3] %s", ok[i]);
        }
        for (i = 0u; i < sizeof bad / sizeof bad[0]; i++) {
            CHECK(refused(bad[i], NULL, NULL, &e), "[P2][P3] %s is refused", bad[i]);
        }
        CHECK(refused("log if asn == as1.10", "lexing", "asdot", &e) && strstr(e.fix, "asplain value 65546") != NULL,
              "[P3] asdot is refused with the asplain fix (%s)", e.fix);
        CHECK(refused("log if asn == 1.70000", "lexing", "asdot", &e) && strstr(e.fix, "70000 is not") != NULL
              && strstr(e.fix, "value 1") == NULL, "[P3] an asdot part over 65535 is named, never converted (%s)", e.fix);
        {
            /* P2: `!= undetermined` is FALSE at the sentinel and TRUE elsewhere */
            scen_t s;
            we_verdict_t v;
            const we_program_t *p = prog1("log if country != undetermined");

            scen_init(&s, &W, EMPTY_FLOOR, p, A_F);
            s.hh = HH;
            agree(&s, "P2", "!= undetermined at the sentinel", &v);
            CHECK(v.log_fired[1][0] == 0u, "[P2] country != undetermined is FALSE at the sentinel");
            scen_init(&s, &W, EMPTY_FLOOR, p, A_T);
            s.hh = HH;
            agree(&s, "P2", "!= undetermined at NL", &v);
            CHECK(v.log_fired[1][0] == 0x01u, "[P2] country != undetermined is TRUE at NL");
            p = prog1("log if country != NL");
            scen_init(&s, &W, EMPTY_FLOOR, p, A_F);
            s.hh = HH;
            agree(&s, "P2", "!= NL at the sentinel", &v);
            CHECK(v.log_fired[1][0] == 0x01u, "[P2] country != NL is TRUE at the sentinel (not ==)");
        }
    }
}

/* ======================================================================================================
 * HH1: every hold-harmless lookup over every outcome class, per lookup against the model
 * ==================================================================================================== */

static void test_hold_harmless(void)
{
    const we_map_t *m = &HH->map;
    int fam;
    long long n = 0;

    SECTION("HH1: the hold-harmless table, strides 16 and 4, every outcome class, traced lines against the model");
    CHECK(m->f4.span == 16u && m->f6.span == 4u && m->f4.depth == WE_HH_V4_DEPTH && m->f6.depth == WE_HH_V6_DEPTH,
          "[HH1] the strides are one node's capacity and the depths the generated header's");
    for (fam = 0; fam < 2; fam++) {
        const we_fam_t *f = fam == 0 ? &m->f4 : &m->f6;
        uint32_t i, maxl = 0u;
        int k;

        for (i = 0u; i < f->n; i++) {
            __uint128_t s = fam == 0 ? (__uint128_t)we_hh_v4[i][0] : ((__uint128_t)we_hh_v6[i][0] << 64) | we_hh_v6[i][1];
            __uint128_t e = fam == 0 ? (__uint128_t)we_hh_v4[i][1] : ((__uint128_t)we_hh_v6[i][2] << 64) | we_hh_v6[i][3];
            __uint128_t probes[4];

            probes[0] = s;
            probes[1] = e;
            probes[2] = s - 1u;
            probes[3] = e + 1u;
            for (k = 0; k < 4; k++) {
                __uint128_t a = probes[k];
                uint8_t ab[16];
                uint32_t got, want_lines, j, lo, hi;
                int in = 0, b;
                int lines;
                uint32_t idx;

                if ((fam == 0 && (a > 0xffffffffu)) || (k == 2 && s == 0u)) {
                    continue;
                }
                for (j = 0u; j < f->n && !in; j++) {
                    __uint128_t s2 = fam == 0 ? (__uint128_t)we_hh_v4[j][0] : ((__uint128_t)we_hh_v6[j][0] << 64) | we_hh_v6[j][1];
                    __uint128_t e2 = fam == 0 ? (__uint128_t)we_hh_v4[j][1] : ((__uint128_t)we_hh_v6[j][2] << 64) | we_hh_v6[j][3];

                    in = a >= s2 && a <= e2;
                }
                for (b = 0; b < 16; b++) {
                    ab[b] = (uint8_t)(a >> (120 - 8 * b));
                }
                trace_reset();
                trace_on = 1;
                got = fam == 0 ? we_find4(m, (uint32_t)a) : we_find6(m, ab);
                trace_on = 0;
                CHECK((got != WE_NO_RANGE) == in, "[HH1] family %d probe: the answer", fam == 0 ? 4 : 6);
                /* the model: below start[0] reads nothing; else depth nodes, the window's line when it has keys
                 * past its separator, and the end's line */
                if (a < f->first) {
                    want_lines = 0u;
                } else {
                    uint32_t win = 0u;

                    for (j = 1u; j < f->m; j++) {
                        __uint128_t sep = fam == 0 ? (__uint128_t)we_hh_v4[j * f->span][0]
                                                   : ((__uint128_t)we_hh_v6[j * f->span][0] << 64) | we_hh_v6[j * f->span][1];

                        if (sep <= a) {
                            win = j;
                        }
                    }
                    lo = win * f->span + 1u;
                    hi = (win + 1u) * f->span < f->n ? (win + 1u) * f->span : f->n;
                    want_lines = f->depth + (hi > lo ? 1u : 0u) + 1u;
                }
                lines = trace_lines((const uint8_t *)HH->floor, (const uint8_t *)HH->floor + HH->floor->total_len);
                CHECK((uint32_t)lines == want_lines, "[HH1] family %d: %d traced lines, the model says %u", fam == 0 ? 4 : 6,
                      lines, want_lines);
                maxl = (uint32_t)lines > maxl ? (uint32_t)lines : maxl;
                (void)idx;
                n++;
            }
        }
        CHECK(maxl == (fam == 0 ? WE_HH_V4_MAX_LINES : WE_HH_V6_MAX_LINES),
              "[HH1] family %d: the maximum, %u lines, is the generated header's", fam == 0 ? 4 : 6, maxl);
    }
    printf("  %lld hold-harmless lookups\n", n);
}

/* ======================================================================================================
 * Counters, sharded per thread
 * ==================================================================================================== */

static void test_counters(void)
{
    const we_program_t *p = prog1("deny if tor_exit");
    we_rule_counters_t *c;
    char path[512];
    size_t len;
    uint8_t *f;

    SECTION("the per-rule counters: one writer per shard, summed on the tick");
    c = we_rule_counters_new(p, 4u, NOW);
    CHECK(c != NULL && ((uintptr_t)c->hits & 63u) == 0u && c->stride % 8u == 0u, "the shards are 64-byte aligned and padded");
    we_rule_count(c, 0u, 1u);
    we_rule_count(c, 3u, 1u);
    we_rule_count(c, 3u, 1u);
    we_rule_count(c, 9u, 1u);              /* no such shard: ignored */
    we_rule_count(c, 0u, 2u);              /* no such rule: ignored */
    CHECK(we_rule_counters_sum(c, 1u) == 3u, "three firings over two shards");
    CHECK(we_rule_counters_write(c, p, TMP, NOW) == WE_OK, "the rules file is written");
    {
        we_procid_t id;

        CHECK(we_proc_id(&id) == 0, "the process identity is readable");
        snprintf(path, sizeof path, "%s/%llu-%s.rules.cnt", TMP, (unsigned long long)id.pid, id.id16);
    }
    f = slurp(path, &len);
    CHECK(f != NULL && strstr((const char *)f, "r 1 3 deny if tor_exit") != NULL, "the line names the rule's text");
    free(f);
    unlink(path);
    we_rule_counters_free(c);
}

/* ======================================================================================================
 * main
 * ==================================================================================================== */

/* ======================================================================================================
 * --cases FILE: the differential's C side (POLICY.md §5.1). The case file and every output line are the
 * reference interpreter's format, so policy_diff.py compares the two line by line; see policy_ref.py.
 * ==================================================================================================== */

static const char *const cs_plane[8] = { "reputation", "tor", "rpki-unreachable", "routing", "anonymizer",
                                         "threat", "registry", "tenant" };

/* the record fields a case names, per schema, in the order the case file writes them */
static int cs_field(uint32_t plane, const char *name)
{
    static const char *const f1[] = { "sev" };
    static const char *const mem[] = { "flags", "source", "reason" };
    static const char *const rt[] = { "asn", "country", "rov", "rir", "flags", "asn_rep" };
    const char *const *t = plane == 1u ? f1 : (plane == 4u || plane == 7u) ? rt : mem;
    int n = plane == 1u ? 1 : (plane == 4u || plane == 7u) ? 6 : 3, i;

    for (i = 0; i < n; i++) {
        if (strcmp(t[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

static int cs_plane_id(const char *name)
{
    int i;

    for (i = 0; i < 8; i++) {
        if (strcmp(cs_plane[i], name) == 0) {
            return i + 1;
        }
    }
    return 0;
}

typedef struct {
    int      has;          /* a rec line was given */
    int      none;         /* ... and it said none */
    uint64_t f[6];
} cs_rec_t;

#define CS_T_FRESH   0
#define CS_T_STALE   1
#define CS_T_NULL    2
#define CS_T_REVOKED 3

typedef struct {
    char      id[160];
    int       has_conf[2];
    we_ctx_conf_t conf[2];   /* [0] floor, [1] ctx */
    int       stale[8];      /* the seven non-tenant planes */
    int       tenant;
    uint64_t  now, vu;
    char      addr[2][64];
    int       has_addr[2];
    int       hh, acme;
    cs_rec_t  rec[2][9];     /* [0] floor, [1] server; by plane_id */
    int       sweep;
    int       sw_who, sw_plane, sw_field;
    uint64_t  sw_lo, sw_hi;
} cs_case_t;

typedef struct {
    char     kind[32];
    char     ctx[256];
    uint8_t *arg;
    size_t   len;
} cs_dir_t;

typedef struct {
    char        id[160];
    char        leg[24];
    cs_dir_t   *d;
    size_t      n, cap;
    char        run[256];
    uint8_t     absent;
    uint8_t     legacy;      /* the configuration names the legacy synonym (D-af) */
    int         compiled, refused, has_floor;
    we_policy_build_t *b;
    const we_program_t *floor, *ctx;
    we_hh_view_t *hh;
    uint8_t     *scratch[2];     /* the invariant's probe blocks, one per program */
} cs_prog_t;

/* ---- the plane maps a case states: built, loaded, then patched to the case's record bytes ---- */

typedef struct {
    uint64_t  hash;
    size_t    klen;
    uint8_t  *key;
    we_map_t *map;
} cs_slot_t;

#define CS_CACHE (1u << 16)
static cs_slot_t cs_cache[CS_CACHE];
static uint32_t cs_cached;
static const char *cs_feeds[256];
static char cs_feed_names[256][8];

static void cs_cache_flush(void)
{
    uint32_t i;

    for (i = 0u; i < CS_CACHE; i++) {
        if (cs_cache[i].map != NULL) {
            free((void *)cs_cache[i].map->base);
            free(cs_cache[i].map);
            free(cs_cache[i].key);
        }
    }
    memset(cs_cache, 0, sizeof cs_cache);
    cs_cached = 0u;
}

typedef struct {
    we_addr_t       a;
    const cs_rec_t *r;
} cs_ent_t;

static __uint128_t cs_key(const we_addr_t *a, uint32_t plane)
{
    __uint128_t k = 0u;
    int i;

    if (a->family == 4u) {
        return ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16) | ((uint32_t)a->b[2] << 8) | a->b[3];
    }
    for (i = 0; i < 16; i++) {
        k = (k << 8) | a->b[i];
    }
    return key6_of(plane) == 8u ? k >> 64 : k;
}

/* write the case's field values into the record at its native offsets (FORMAT.md §3), domain or not */
static void cs_patch(uint8_t *r, uint32_t plane, int fam, const uint64_t *f)
{
    if (plane == 4u || plane == 7u) {
        uint32_t asn = (uint32_t)f[0];
        uint16_t country = (uint16_t)f[1];
        size_t o = fam == 4 ? 4u : 8u;

        memcpy(r + o, &asn, 4);
        memcpy(r + o + 4u, &country, 2);
        r[o + 6u] = (uint8_t)f[2];
        r[o + 7u] = (uint8_t)f[3];
        r[o + 8u] = (uint8_t)f[4];
        r[o + 9u] = (uint8_t)f[5];
    } else {
        uint32_t flags = (uint32_t)f[0];
        size_t o = fam == 4 ? 4u : 16u;

        memcpy(r + o, &flags, 4);
        r[o + 4u] = (uint8_t)f[1];
        r[o + 5u] = (uint8_t)f[2];
    }
}

/*
 * One plane's map holding the given records at the given addresses (one exact range each; an address
 * whose key equals an earlier one's reads that one's record). The loader refuses an out-of-domain
 * record, which is the clamps' whole point, so the map is built and loaded with zeroed records and the
 * case's bytes are written into the loaded copy afterwards, as the M4 rows patch theirs.
 */
static const we_map_t *cs_map(uint32_t plane, uint64_t gen, uint64_t vu, const cs_ent_t *e, int ne)
{
    uint8_t key[512];
    size_t kl = 0u;
    uint64_t h = 1469598103934665603ull;
    uint32_t slot, i;
    int k, j, n4 = 0, n6 = 0;
    __uint128_t s4[2], s6[2];
    const cs_rec_t *r4[2], *r6[2];
    ww_plane_t p;
    uint8_t *buf, *nb, zeros[2] = { 0u, 0u };
    size_t len;
    char path[512];
    we_map_t tmp, *desc;
    we_load_detail_t det;
    static int seq = 0;

    key[kl++] = (uint8_t)plane;
    memcpy(key + kl, &gen, 8);
    kl += 8u;
    memcpy(key + kl, &vu, 8);
    kl += 8u;
    for (k = 0; k < ne; k++) {
        __uint128_t kk = cs_key(&e[k].a, plane);
        int fam = e[k].a.family;

        if (e[k].r == NULL || !e[k].r->has || e[k].r->none) {
            continue;
        }
        for (j = 0; j < (fam == 4 ? n4 : n6); j++) {
            if ((fam == 4 ? s4[j] : s6[j]) == kk) {
                break;
            }
        }
        if (j < (fam == 4 ? n4 : n6)) {
            continue;                       /* the same key: the earlier (the floor's) record */
        }
        if (fam == 4) {
            s4[n4] = kk;
            r4[n4++] = e[k].r;
        } else {
            s6[n6] = kk;
            r6[n6++] = e[k].r;
        }
        key[kl++] = (uint8_t)fam;
        memcpy(key + kl, &kk, 16);
        kl += 16u;
        memcpy(key + kl, e[k].r->f, sizeof e[k].r->f);
        kl += sizeof e[k].r->f;
    }
    /* sorted, as the format requires */
    if (n4 == 2 && s4[1] < s4[0]) {
        __uint128_t t = s4[0];
        const cs_rec_t *tr = r4[0];

        s4[0] = s4[1]; s4[1] = t; r4[0] = r4[1]; r4[1] = tr;
    }
    if (n6 == 2 && s6[1] < s6[0]) {
        __uint128_t t = s6[0];
        const cs_rec_t *tr = r6[0];

        s6[0] = s6[1]; s6[1] = t; r6[0] = r6[1]; r6[1] = tr;
    }
    for (i = 0u; i < kl; i++) {
        h = (h ^ key[i]) * 1099511628211ull;
    }
    for (slot = (uint32_t)h & (CS_CACHE - 1u); cs_cache[slot].map != NULL; slot = (slot + 1u) & (CS_CACHE - 1u)) {
        if (cs_cache[slot].hash == h && cs_cache[slot].klen == kl && memcmp(cs_cache[slot].key, key, kl) == 0) {
            return cs_cache[slot].map;
        }
    }
    memset(&p, 0, sizeof p);
    p.format = plane == WE_PLANE_REPUTATION ? WE_FORMAT_1 : WE_FORMAT_2;
    p.schema = 1;
    p.plane = plane;
    p.generation = gen;
    p.valid_until_ms = vu;
    p.country_version = (plane == WE_PLANE_ROUTING || plane == WE_PLANE_REGISTRY) ? 5704u : 0u;
    p.v4.n = (uint32_t)n4;
    p.v4.start = s4;
    p.v4.end = s4;
    p.v6.n = (uint32_t)n6;
    p.v6.start = s6;
    p.v6.end = s6;
    p.v4.kind = p.v6.kind = WE_KIND_NONE;
    if (p.format == WE_FORMAT_1) {
        p.v4.sev = zeros;
        p.v6.sev = zeros;
    } else {
        p.feeds = cs_feeds;
        p.nfeeds = 256u;
    }
    buf = ww_build(&p, &len);
    if (buf == NULL) {
        CHECK(0, "[cases] the writer built plane %u", plane);
        return NULL;
    }
    snprintf(path, sizeof path, "%s/case-%d.bin", TMP, seq++ & 7);
    if (ww_save(path, buf, len) != 0) {
        free(buf);
        CHECK(0, "[cases] saved %s", path);
        return NULL;
    }
    free(buf);
    if (we_plane_open(path, &tmp, &det) != WE_OK) {
        CHECK(0, "[cases] loaded %s: %s", path, det.what != NULL ? det.what : "?");
        return NULL;
    }
    unlink(path);
    nb = (uint8_t *)aligned_alloc(64, (tmp.len + 63u) & ~(size_t)63u);
    memcpy(nb, tmp.base, tmp.len);
    {
        const void *old = tmp.base;

        rebase(&tmp, nb);
        free((void *)old);
    }
    for (k = 0; k < n4; k++) {
        if (p.format == WE_FORMAT_1) {
            ((uint8_t *)(uintptr_t)tmp.f4.sev)[k] = (uint8_t)r4[k]->f[0];
        } else {
            cs_patch((uint8_t *)(uintptr_t)tmp.f4.records + (size_t)k * tmp.f4.stride, plane, 4, r4[k]->f);
        }
    }
    for (k = 0; k < n6; k++) {
        we_fam_t *f6 = key6_of(plane) == 8u ? &tmp.f6w : &tmp.f6;

        if (p.format == WE_FORMAT_1) {
            ((uint8_t *)(uintptr_t)f6->sev)[k] = (uint8_t)r6[k]->f[0];
        } else {
            cs_patch((uint8_t *)(uintptr_t)f6->records + (size_t)k * f6->stride, plane, 6, r6[k]->f);
        }
    }
    desc = (we_map_t *)aligned_alloc(64, (sizeof(we_map_t) + 63u) & ~(size_t)63u);
    *desc = tmp;
    cs_cache[slot].hash = h;
    cs_cache[slot].klen = kl;
    cs_cache[slot].key = (uint8_t *)malloc(kl);
    memcpy(cs_cache[slot].key, key, kl);
    cs_cache[slot].map = desc;
    cs_cached++;
    return desc;
}

/* ---- parsing ---- */

static size_t cs_unescape(const char *s, uint8_t *out)
{
    size_t o = 0u;

    while (*s != '\0') {
        if (s[0] == '\\' && s[1] == 'x' && s[2] != '\0' && s[3] != '\0') {
            char hx[3] = { s[2], s[3], 0 };

            out[o++] = (uint8_t)strtoul(hx, NULL, 16);
            s += 4;
        } else {
            out[o++] = (uint8_t)*s++;
        }
    }
    return o;
}

static uint8_t cs_kind(const char *w)
{
    if (strcmp(w, "allow_inferred") == 0) {
        return WE_DIR_ALLOW_INFERRED;
    }
    {
        uint8_t k = kind_of(w);

        return k != 0u ? k : 0xEEu;      /* a kind the module has no directive for */
    }
}

static int cs_addr(const char *s, we_addr_t *out)
{
    uint8_t raw[16];
    int fam = strchr(s, ':') != NULL ? 6 : 4;

    memset(raw, 0, sizeof raw);
    if (inet_pton(fam == 4 ? AF_INET : AF_INET6, s, raw) != 1) {
        return -1;
    }
    we_addr_canon(raw, fam, out);
    return 0;
}

/* ---- the coverage matrix under --cases (POLICY.md §5.2): the reference interpreter's cells, per leg ---- */

#define CV_MAX 4096
static struct { char leg[24]; char cell[96]; long long n; } cv[CV_MAX];
static uint32_t ncv;
static char cs_leg[24];

static void cv_add(const char *leg, const char *cell)
{
    uint32_t i;

    for (i = 0u; i < ncv; i++) {
        if (strcmp(cv[i].leg, leg) == 0 && strcmp(cv[i].cell, cell) == 0) {
            cv[i].n++;
            return;
        }
    }
    if (ncv < CV_MAX) {
        snprintf(cv[ncv].leg, sizeof cv[ncv].leg, "%s", leg);
        snprintf(cv[ncv].cell, sizeof cv[ncv].cell, "%s", cell);
        cv[ncv++].n = 1;
    }
}

static long long cv_get(const char *leg, const char *cell)
{
    uint32_t i;

    for (i = 0u; i < ncv; i++) {
        if (strcmp(cv[i].leg, leg) == 0 && strcmp(cv[i].cell, cell) == 0) {
            return cv[i].n;
        }
    }
    return 0;
}

static const char *const cs_opname[15] = { "BOOL", "SEV", "EQ8", "EQ16", "EQ32", "INSET_ENUM", "INSET_COUNTRY",
                                           "INSET_ASN", "ISUNK", "NOT", "AND", "OR", "JF", "JT", "END" };
static const char *const cs_act[4] = { "-", "allow", "deny", "log" };
static const char *cs_state[8];             /* the running case's plane states, by plane index */

/* the polarity of the `is unknown` at instruction idx: the NOTs over the subexpressions that hold it */
static int cs_isunk_negative(const we_program_t *p, const we_rule_t *r, uint32_t idx)
{
    const we_instr_t *ins = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off);
    uint8_t st[80];
    uint32_t sp = 0u, j;
    int neg = 0;

    for (j = r->instr_start; j < (uint32_t)r->instr_start + r->instr_count && j <= idx + 64u; j++) {
        uint32_t op = ins[j].op;

        if ((op & WE_OP_ATOM) != 0u) {
            if (sp < sizeof st) {
                st[sp++] = (uint8_t)(j == idx);
            }
        } else if ((op & WE_OP_NOT) != 0u && sp >= 1u) {
            neg ^= st[sp - 1u];
        } else if ((op & (WE_OP_AND | WE_OP_OR)) != 0u && sp >= 2u) {
            st[sp - 2u] = (uint8_t)(st[sp - 2u] | st[sp - 1u]);
            sp--;
        }
    }
    return neg;
}

static void cs_instr_tap(const we_program_t *p, uint32_t idx)
{
    const we_instr_t *I = (const we_instr_t *)(const void *)((const uint8_t *)p + p->instrs_off) + idx;
    uint32_t op = I->op, b, pl = I->plane & 7u;
    char cell[96];

    if ((op & WE_OP_ATOM) == 0u) {
        return;
    }
    for (b = 0u; b < 15u && ((op >> b) & 1u) == 0u; b++) {
    }
    snprintf(cell, sizeof cell, "plane-state %s %s %s", cs_opname[b], cs_plane[pl], cs_state[pl]);
    cv_add(cs_leg, cell);
    if ((op & WE_OP_ISUNK) != 0u && cov_rule != NULL) {
        snprintf(cell, sizeof cell, "polarity %s %s", cs_act[cov_rule->action & 3u],
                 cs_isunk_negative(p, cov_rule, idx) ? "negative" : "positive");
        cv_add(cs_leg, cell);
    }
}

static void cs_rule_tap(const we_program_t *p, const we_rule_t *r)
{
    (void)p;
    if ((r->flags & WE_RF_INERT) != 0u) {
        cv_add(cs_leg, "inert skipped");
    }
}

/* the fields a fill clamps on this record, as the fill reads them (POLICY.md §2.7) */
static void cs_clamps(uint32_t plane, const cs_rec_t *r)
{
    if (r == NULL || !r->has || r->none) {
        return;
    }
    if (plane == 4u || plane == 7u) {
        uint64_t c = r->f[1];

        if (r->f[2] > 3u) cv_add(cs_leg, "clamp rov");
        if (r->f[3] > 5u) cv_add(cs_leg, "clamp rir");
        if (r->f[5] > 4u) cv_add(cs_leg, "clamp asn_rep");
        if (c != 0u && !(c <= 999u && ((we_country_known_table[c >> 3] >> (c & 7u)) & 1u))) cv_add(cs_leg, "clamp country");
        if ((r->f[4] & ~(uint64_t)0x07u) != 0u) cv_add(cs_leg, "clamp routing-flags");
    } else if (plane == 1u) {
        if ((r->f[0] & 0x0fu) > 4u) cv_add(cs_leg, "clamp sev");
    } else {
        static const uint32_t mask[9] = { 0u, 0u, 0x01u, 0x01u, 0u, 0x03u, 0x3fu, 0u, 0x03u };

        if ((r->f[0] & ~(uint64_t)mask[plane]) != 0u) cv_add(cs_leg, "clamp membership-flags");
        if (plane == 3u && r->f[2] > 2u) cv_add(cs_leg, "clamp reason");
    }
}

/* the section 1.5 table phrase, or D-k phrase, a refusal's fragment stands for (the reference's table_phrase) */
static const char *const cs_phrases[] = {
    "argument over 2,048 bytes", "byte 0xHH is not allowed", "identifier over 64 bytes", "a number with a sign",
    "a leading zero other than 0", "more than 10 digits", "above 2^32 - 1", "the sentinel 4294967295", "asdot",
    "an unknown country code", "uk", "an upper-case keyword or literal", "a bare literal in expression mode",
    "a stray @", "an unknown operator", "trailing input", "and/or mixed in a chain", "unbalanced or nested braces",
    "a stray }", "nesting over 16", "over 64 operations in a rule", "an action without if", "an empty expression",
    "an unknown attribute or word", "a literal of the wrong class", "an ordered comparison on anything but listed",
    "in or == on a bool", "undetermined on a bool", "an inline set whose members are not all of one class",
    "@set undefined in this context or an enclosing one", "a duplicate definition in one scope",
    "a definition shadowing an outer set", "an empty set", "a declaration with no members",
    "a declared set whose members are not of one class", "a set used against an attribute of another class",
    "more than 1,024 sets in the configuration", "over 256 rules in a context", "over 4,096 operations in a context",
    "over 8,448 instructions", "over 256 KiB of program bytes", "allow in a floor program",
    "whisper_edge_threshold in a context with policy lines",
    "is unknown whose polarity lets a deny fire because of an outage",
    /* the phrases the reference adds to the table (D-k), pinned the same way */
    "a non-digit in a number",
    "unbalanced parentheses",
    "is not a boolean",
    "only literals inside braces",
    "only literals in a set declaration",
    "a set declaration names its set with @",
    "is takes unknown or not unknown",
    "a mode of off, log or deny",
    "a threshold of off, low, medium, high or critical",
    "allow_inferred takes on or off",
    "a floor is http-level only",
    "an unknown directive",
};
#define CS_NPHRASES (sizeof cs_phrases / sizeof cs_phrases[0])

static const char *cs_table_phrase(const char *fr)
{
    size_t i;

    for (i = 0u; i < CS_NPHRASES; i++) {
        if (strcmp(fr, cs_phrases[i]) == 0) {
            return cs_phrases[i];             /* exact first: two D-k phrases hold " takes " */
        }
    }
    if (strncmp(fr, "byte 0x", 7) == 0) return "byte 0xHH is not allowed";
    if (strstr(fr, " takes ") != NULL) return "a literal of the wrong class";
    if (strcmp(fr, "did you mean GB") == 0) return "uk";
    if (strcmp(fr, "write country in { RU } or country == RU") == 0) return "a bare literal in expression mode";
    if (strcmp(fr, "deny if not <condition>") == 0) return "an action without if";
    if (strcmp(fr, "that is a fail-closed rule") == 0) return "is unknown whose polarity lets a deny fire because of an outage";
    if (strncmp(fr, "deny if listed >= ", 18) == 0 || strncmp(fr, "no rule (threshold off", 22) == 0) {
        return "whisper_edge_threshold in a context with policy lines";
    }
    if (strcmp(fr, "undefined in this context or an enclosing one") == 0) {
        return "@set undefined in this context or an enclosing one";
    }
    for (i = 0u; i < CS_NPHRASES; i++) {
        if (strcmp(fr, cs_phrases[i]) == 0) {
            return cs_phrases[i];
        }
    }
    return NULL;
}

/*
 * Every cell the matrix requires, for the legs this case file ran: the reference's expected_cells,
 * with one named substitution. The compiler encodes every `listed` test as SEV over a level mask
 * (inferred applied in one place), so `listed in {...}` is SEV on the reputation plane, never
 * INSET_ENUM: that pair is not a cell here, and SEV's is.
 */
static int cs_check_matrix(int ran_exhaustive, int ran_other, int ran_absent)
{
    static const char *const tfu[3] = { "T", "F", "U" };
    static const struct { const char *op; int plane; } pairs[] = {
        { "BOOL", 1 }, { "BOOL", 2 }, { "BOOL", 3 }, { "BOOL", 4 }, { "BOOL", 5 }, { "BOOL", 6 }, { "BOOL", 8 },
        { "SEV", 1 }, { "EQ8", 3 }, { "INSET_ENUM", 3 }, { "EQ8", 4 }, { "INSET_ENUM", 4 }, { "EQ32", 4 },
        { "INSET_ASN", 4 }, { "EQ16", 4 }, { "INSET_COUNTRY", 4 }, { "EQ16", 7 }, { "INSET_COUNTRY", 7 },
        { "EQ8", 7 }, { "INSET_ENUM", 7 }, { "ISUNK", 1 }, { "ISUNK", 2 }, { "ISUNK", 3 }, { "ISUNK", 4 },
        { "ISUNK", 5 }, { "ISUNK", 6 }, { "ISUNK", 7 }, { "ISUNK", 8 },
    };
    static const char *const tst[5] = { "fresh", "grace", "lapsed", "null", "revoked" };
    char cell[160];
    int cells = 0, zero = 0, i, j;
    size_t k;

#define CS_CELL(leg, have) do { cells++; if (!(have)) { zero++; fprintf(stderr, "  zero cell %s: %s\n", leg, cell); } } while (0)
    if (ran_exhaustive) {
        long long *tab[2] = { cover_and, cover_or };

        for (k = 0u; k < 2u; k++) {
            for (i = 0; i < 3; i++) {
                int left = k == 0u ? (i == 0 ? RT : RU) : (i == 0 ? RF : RU);

                if (i == 2) {
                    continue;
                }
                for (j = 0; j < 3; j++) {
                    snprintf(cell, sizeof cell, "op %s %s %s", k == 0u ? "AND" : "OR", tfu[left - 1], tfu[j]);
                    CS_CELL("exhaustive", tab[k][left * 4 + j + 1] != 0);
                }
            }
        }
        for (j = 0; j < 3; j++) {
            snprintf(cell, sizeof cell, "op NOT %s", tfu[j]);
            CS_CELL("exhaustive", cover_not[j + 1] != 0);
            snprintf(cell, sizeof cell, "op JF %s", tfu[j]);
            CS_CELL("exhaustive", cover_jf[j + 1] != 0);
            snprintf(cell, sizeof cell, "op JT %s", tfu[j]);
            CS_CELL("exhaustive", cover_jt[j + 1] != 0);
        }
        for (i = 1; i <= 3; i++) {
            for (j = 0; j < 3; j++) {
                snprintf(cell, sizeof cell, "action-final %s %s", cs_act[i], tfu[j]);
                CS_CELL("exhaustive", cover_final[i][j + 1] != 0);
            }
        }
    }
    if (ran_other) {
        static const char *const pol[5][2] = { { "deny", "negative" }, { "log", "positive" }, { "log", "negative" },
                                               { "allow", "positive" }, { "allow", "negative" } };
        static const char *const clamps[8] = { "rov", "rir", "asn_rep", "reason", "country", "routing-flags",
                                               "membership-flags", "sev" };

        for (k = 0u; k < sizeof pairs / sizeof pairs[0]; k++) {
            int ns = pairs[k].plane == 8 ? 5 : 2;

            for (i = 0; i < ns; i++) {
                snprintf(cell, sizeof cell, "plane-state %s %s %s", pairs[k].op, cs_plane[pairs[k].plane - 1],
                         pairs[k].plane == 8 ? tst[i] : i == 0 ? "fresh" : "unknown");
                CS_CELL("generated", cv_get("generated", cell) != 0);
            }
        }
        for (i = 0; i < 5; i++) {
            snprintf(cell, sizeof cell, "polarity %s %s", pol[i][0], pol[i][1]);
            CS_CELL("generated", cv_get("generated", cell) != 0);
        }
        snprintf(cell, sizeof cell, "slot shared");
        CS_CELL("generated", cv_get("generated", cell) != 0);
        snprintf(cell, sizeof cell, "slot distinct");
        CS_CELL("generated", cv_get("generated", cell) != 0);
        for (i = 0; i < 8; i++) {
            snprintf(cell, sizeof cell, "clamp %s", clamps[i]);
            CS_CELL("generated", cv_get("generated", cell) != 0);
        }
        for (k = 0u; k < CS_NPHRASES; k++) {
            if (strcmp(cs_phrases[k], "over 8,448 instructions") == 0) {
                continue;                       /* unreachable from source text (D-w): the verifier's alone */
            }
            snprintf(cell, sizeof cell, "phrase %s", cs_phrases[k]);
            CS_CELL("refusals", cv_get("refusals", cell) != 0);
        }
    }
    if (ran_absent) {
        static const char *const ab[4] = { "inert skipped", "class x", "report inert-at-config",
                                           "report inert-allow-exposes" };

        for (i = 0; i < 4; i++) {
            snprintf(cell, sizeof cell, "%s", ab[i]);
            CS_CELL("absent", cv_get("absent", cell) != 0);
        }
    }
#undef CS_CELL
    fprintf(stderr, "test_policy --cases: the coverage matrix, %d cells, %d zero\n", cells, zero);
    CHECK(zero == 0, "[K7] %d of the %d coverage cells this case file owns are zero", zero, cells);
    return zero;
}

/* ---- per program ---- */

static void cs_compile(cs_prog_t *P)
{
    we_policy_directive_t *d = (we_policy_directive_t *)calloc(P->n + 1u, sizeof *d);
    we_policy_source_t src;
    we_policy_env_t env;
    we_policy_error_t e;
    size_t i;
    int rc;
    uint32_t k;

    for (i = 0u; i < P->n; i++) {
        d[i].kind = cs_kind(P->d[i].kind);
        d[i].context = P->d[i].ctx;
        d[i].arg = P->d[i].arg;
        d[i].len = P->d[i].len;
        P->has_floor |= d[i].kind == WE_DIR_FLOOR;
    }
    src.d = d;
    src.n = P->n;
    src.context = NULL;
    src.floor = 0;
    memset(&env, 0, sizeof env);
    env.present = (uint8_t)~P->absent;
    env.schema_ok = env.present;
    env.legacy = P->legacy;
    nreports = 0;
    report_len = 0u;
    if (report_buf != NULL) {
        report_buf[0] = '\0';
    }
    printf("program %s\n", P->id);
    rc = we_policy_build(&src, &env, NULL, &P->b, &e, &REP);
    P->compiled = 1;
    if (rc != WE_POLICY_OK) {
        char msg[2048];

        P->refused = 1;
        printf("refusal layer=%s kind=%s context=%s rule=%u line=%u col=%u token=\"%s\" | %s\n", e.layer,
               e.directive < P->n ? P->d[e.directive].kind : "?", e.context, e.rule, e.line, e.col, e.token, e.phrase);
        we_policy_error_format(&e, msg, sizeof msg);
        printf("msg %s\n", msg);
        if (strcmp(P->leg, "exhaustive") != 0 && cs_table_phrase(e.phrase) != NULL) {
            char cell[160];

            snprintf(cell, sizeof cell, "phrase %s", cs_table_phrase(e.phrase));
            cv_add("refusals", cell);
        }
        CHECK(rc == WE_POLICY_REFUSED, "[cases] %s: a refusal, never an allocation failure", P->id);
        free(d);
        return;
    }
    P->floor = we_policy_floor(P->b);
    P->ctx = we_policy_program(P->b, P->run);
    {
        const we_program_t *pp[2];

        pp[0] = P->has_floor ? P->floor : NULL;
        pp[1] = P->ctx;
        for (k = 0u; k < 2u; k++) {
            static char text[1u << 20];
            char *line, *nl;
            uint32_t r = 0u;

            if (pp[k] == NULL || we_program_print(pp[k], text, sizeof text) < 0) {
                continue;
            }
            {
                size_t tl = strlen(text);

                if (we_program_print_sets(pp[k], text + tl, sizeof text - tl) < 0) {
                    continue;
                }
            }
            for (line = text; *line != '\0'; line = nl + 1) {
                nl = strchr(line, '\n');
                if (nl == NULL) {
                    break;
                }
                *nl = '\0';
                if (r < pp[k]->rule_count) {
                    printf("text %s %u %s\n", k == 0u ? "floor" : "ctx", ++r, line);
                } else {
                    printf("text %s set %s\n", k == 0u ? "floor" : "ctx", line);
                }
            }
        }
    }
    if (report_buf != NULL) {
        const char *l = report_buf;

        fputs(report_buf, stdout);
        while (*l != '\0') {
            const char *nl = strchr(l, '\n');
            char w[5][128], cell[160];

            memset(w, 0, sizeof w);
            if (sscanf(l, "%127s %127s %127s %127s %127s", w[0], w[1], w[2], w[3], w[4]) >= 3) {
                snprintf(cell, sizeof cell, "report %s", strcmp(w[1], "set") == 0 ? w[2] : w[4]);
                cv_add(P->leg, cell);
            }
            if (nl == NULL) {
                break;
            }
            l = nl + 1;
        }
    }
    P->hh = (we_hh_view_t *)aligned_alloc(64, (sizeof(we_hh_view_t) + 63u) & ~(size_t)63u);
    CHECK(we_program_place(P->floor, P->hh) == 0, "[cases] %s: the hold-harmless view is placed", P->id);
    /* the invariant's probe blocks: a copy whose first rules and instructions the probe overwrites */
    for (k = 0u; k < 2u; k++) {
        const we_program_t *q = k == 0u ? (P->has_floor ? P->floor : NULL) : P->ctx;

        P->scratch[k] = NULL;
        if (q != NULL) {
            P->scratch[k] = (uint8_t *)aligned_alloc(64, (q->total_len + 63u) & ~(size_t)63u);
            memcpy(P->scratch[k], q, q->total_len);
        }
    }
    free(d);
}

static void cs_prog_free(cs_prog_t *P)
{
    size_t i;

    for (i = 0u; i < P->n; i++) {
        free(P->d[i].arg);
    }
    free(P->d);
    if (P->b != NULL) {
        we_policy_build_free(P->b);
    }
    free(P->hh);
    free(P->scratch[0]);
    free(P->scratch[1]);
    memset(P, 0, sizeof *P);
}

/* the tenant state the evaluator reads, from the case's times, valid_until 0 being no bound */
static we_tenant_state_t cs_tstate(const cs_case_t *c)
{
    if (c->tenant == CS_T_NULL) {
        return WE_TENANT_NULL;
    }
    if (c->tenant == CS_T_REVOKED) {
        return WE_TENANT_REVOKED;
    }
    if (c->vu != 0u && c->now > c->vu) {
        return c->now - c->vu <= H48 ? WE_TENANT_GRACE : WE_TENANT_LAPSED;
    }
    return WE_TENANT_FRESH;
}

static const char *const cs_tname[5] = { "fresh", "grace", "lapsed", "null", "revoked" };


/* the eight views a case states; `force` overrides one plane's state for the invariant's probe */
/*
 * A plane armed at generation 0 (D-ae): the same map, records and all, with its generation 0. Copies are
 * kept per source map, so a case file reuses them as cs_map reuses its maps.
 */
static const we_map_t *cs_gen0(const we_map_t *m)
{
    static struct { const we_map_t *src; we_map_t *copy; } g0[2 * CS_CACHE];
    uint32_t i;

    if (m == NULL) {
        return NULL;
    }
    for (i = (uint32_t)(((uintptr_t)m >> 6) & (2u * CS_CACHE - 1u)); g0[i].src != NULL; i = (i + 1u) & (2u * CS_CACHE - 1u)) {
        if (g0[i].src == m) {
            return g0[i].copy;
        }
    }
    g0[i].copy = (we_map_t *)aligned_alloc(64, (sizeof(we_map_t) + 63u) & ~(size_t)63u);
    if (g0[i].copy == NULL) {
        return NULL;
    }
    *g0[i].copy = *m;
    g0[i].copy->generation = 0u;
    g0[i].src = m;
    return g0[i].copy;
}

static void cs_views(const cs_case_t *c, const cs_ent_t ent[9][2], int force_plane, int force_state,
                     const we_map_t *view[8])
{
    uint32_t p;

    for (p = 1u; p <= 8u; p++) {
        int st;

        if (p == 8u) {
            uint64_t vu;

            st = force_plane == 8 ? force_state : -1;
            if (st < 0) {
                if (c->tenant == CS_T_NULL) {
                    view[7] = NULL;
                } else if (c->tenant == CS_T_REVOKED) {
                    view[7] = revoked_map;
                } else {
                    view[7] = cs_map(8u, 7u, c->vu, ent[8], 2);
                }
                continue;
            }
            /* the five states at this case's clock */
            if (st == WE_TENANT_NULL) {
                view[7] = NULL;
                continue;
            }
            if (st == WE_TENANT_REVOKED) {
                view[7] = revoked_map;
                continue;
            }
            vu = st == WE_TENANT_FRESH ? 0u : st == WE_TENANT_GRACE ? c->now - 1u : c->now - H48 - 1u;
            view[7] = cs_map(8u, 7u, vu, ent[8], 2);
            continue;
        }
        st = force_plane == (int)p ? force_state : c->stale[p];
        view[p - 1u] = st == 2 ? cs_gen0(cs_map(p, 7u, 0u, ent[p], 2)) : cs_map(p, 7u, st ? c->now - 1u : 0u, ent[p], 2);
    }
}

/*
 * The invariant (row X5): for every non-ISUNK atom the two programs read and every state of its plane,
 * ISUNK(plane) is TRUE exactly when the atom's uniform reading (the tenant polarity bit cleared) is
 * UNKNOWN. Both readings come from the evaluator itself: three probe rules over a copy of the block,
 * `log if A`, `log if not A` and `log if P is unknown`, run on a fresh slot.
 */
static void cs_invariant(const cs_prog_t *P, const cs_case_t *c, const cs_ent_t ent[9][2], const we_addr_t *fa,
                         uint32_t *checked, uint32_t *failed)
{
    static we_memo_slot_t slot __attribute__((aligned(64)));
    uint32_t k;

    for (k = 0u; k < 2u; k++) {
        const we_program_t *q = k == 0u ? (P->has_floor ? P->floor : NULL) : P->ctx;
        const we_instr_t *ins;
        const we_rule_t *rules;
        we_program_t *sp;
        uint32_t r, i;

        if (q == NULL) {
            continue;
        }
        sp = (we_program_t *)(void *)P->scratch[k];
        ins = (const we_instr_t *)(const void *)((const uint8_t *)q + q->instrs_off);
        rules = (const we_rule_t *)(const void *)((const uint8_t *)q + q->rules_off);
        for (r = 0u; r < q->rule_count; r++) {
            for (i = rules[r].instr_start; i < (uint32_t)rules[r].instr_start + rules[r].instr_count; i++) {
                we_instr_t a = ins[i], pr[7];
                we_rule_t pr_r[3];
                uint32_t pl = a.plane & 7u, ns, st;

                if ((a.op & WE_OP_ATOM) == 0u || (a.op & WE_OP_ISUNK) != 0u) {
                    continue;
                }
                if ((a.op & WE_OP_BOOL) != 0u) {
                    a.imm &= ~(uint32_t)WE_BOOL_POLARITY;     /* the uniform reading */
                }
                memset(pr, 0, sizeof pr);
                memset(pr_r, 0, sizeof pr_r);
                pr[0] = a;
                pr[1].op = WE_OP_END;
                pr[2] = a;
                pr[3].op = WE_OP_NOT;
                pr[4].op = WE_OP_END;
                pr[5].op = WE_OP_ISUNK;
                pr[5].plane = (uint8_t)pl;
                pr[6].op = WE_OP_END;
                pr_r[0].action = WE_ACT_LOG;
                pr_r[0].instr_start = 0u;
                pr_r[0].instr_count = 2u;
                pr_r[1].action = WE_ACT_LOG;
                pr_r[1].instr_start = 2u;
                pr_r[1].instr_count = 3u;
                pr_r[2].action = WE_ACT_LOG;
                pr_r[2].instr_start = 5u;
                pr_r[2].instr_count = 2u;
                for (st = 0u; st < 3u; st++) {
                    pr_r[st].dep_mask = (uint8_t)(1u << pl);
                }
                memcpy((uint8_t *)sp + sp->instrs_off, pr, sizeof pr);
                memcpy((uint8_t *)sp + sp->rules_off, pr_r, sizeof pr_r);
                sp->rule_count = 3u;
                ns = pl == 7u ? 5u : 2u;
                for (st = 0u; st < ns; st++) {
                    const we_map_t *view[8];
                    we_verdict_t v;
                    uint32_t p, t, f, u;

                    cs_views(c, ent, (int)pl + 1, (int)st, view);
                    for (p = 0u; p < 8u; p++) {
                        ectx->view[p].m = view[p];
                    }
                    memset(&slot, 0, sizeof slot);
                    memcpy(slot.addr, fa->b, 16);
                    slot.family = fa->family;
                    slot.key_valid = 1u;
                    we_verdict_clear(&v);
                    we_eval_run(sp, WE_MODE_DENY, 0u, 1u, ectx, &slot, 0u, we_prog_bindings(sp), c->now, &v);
                    for (p = 0u; p < 8u; p++) {
                        ectx->view[p].m = NULL;
                    }
                    t = v.log_fired[1][0] & 1u;
                    f = (v.log_fired[1][0] >> 1) & 1u;
                    u = (v.log_fired[1][0] >> 2) & 1u;
                    (*checked)++;
                    if (u != (uint32_t)(t == 0u && f == 0u)) {
                        (*failed)++;
                    }
                }
            }
        }
        memcpy(P->scratch[k], q, q->total_len);           /* restore for the next case */
    }
}

static void cs_classes(const we_program_t *p, uint8_t out_mask, we_tenant_state_t ts, char *letters, size_t n)
{
    static we_rule_class_t rc[WE_LIM_RULES];
    uint32_t r, o = 0u;

    if (p == NULL) {
        snprintf(letters, n, "-");
        return;
    }
    we_program_dependents(p, out_mask, ts, rc, WE_LIM_RULES);
    for (r = 0u; r < p->rule_count && o + 1u < n; r++) {
        char ch;

        if (rc[r].cls == WE_CLASS_INERT_AT_CONFIG) {
            ch = 'x';
        } else if (rc[r].action == WE_ACT_ALLOW) {
            ch = (rc[r].values & 4u) ? 'c' : (rc[r].values & 1u) ? 'n' : 'i';
        } else {
            ch = (rc[r].values & 1u) ? 'n' : 'i';
        }
        letters[o++] = ch;
    }
    letters[o] = '\0';
    if (o == 0u) {
        snprintf(letters, n, "-");
    }
}

/*
 * --attrs: the 25 attributes in the vocabulary's order, resolved by name in the evaluator's own table.
 * A plane absent at config prints UNKNOWN; a present tenant plane's tenant_allow carries `bounded` when
 * the plane is stale (GRACE: the stale record's value; LAPSED: false) or null (unknown).
 */
static int cs_attrs;
static const char *const cs_attr_order[25] = {
    "listed", "inferred", "tor_exit", "rpki_unreachable", "rpki_reason", "rpki", "asn", "asn_rep", "country",
    "registry_country", "rir", "registry_rir", "proxy", "vpn", "c2", "bruteforce", "spam", "phishing",
    "scanner", "state_actor", "anycast", "moas", "narrowed", "tenant_allow", "tenant_deny"
};

static void cs_print_attrs(const cs_prog_t *P, const we_memo_slot_t *s, we_tenant_state_t ts)
{
    uint32_t k, j, n = we_attr_count();

    for (k = 0u; k < 25u; k++) {
        we_attr_info_t ai;
        int found = 0;

        for (j = 0u; j < n && !found; j++) {
            found = we_attr_info(j, &ai) == 0 && strcmp(ai.name, cs_attr_order[k]) == 0;
        }
        CHECK(found, "[cases] --attrs: the evaluator's table holds %s", cs_attr_order[k]);
        if (!found) {
            continue;
        }
        {
            uint32_t pi = ai.plane_id - 1u;
            uint8_t blk[16];
            char val[64];

            memcpy(blk, &s->e[pi], sizeof blk);
            if ((P->absent >> pi) & 1u) {
                printf("attr %s UNKNOWN\n", ai.name);
                continue;
            }
            we_attr_render(j - 1u, blk, s->state[pi], val, sizeof val);
            /* `stale:<b>` within the tenant's grace, `lapsed:<b>` past it (POLICY.md section 3.9): the plane's
             * state decides, and the case line carries the bounded value the rule reads */
            if (strcmp(val, "unknown") == 0 || strncmp(val, "stale:", 6) == 0 || strncmp(val, "lapsed:", 7) == 0) {
                if (pi == 7u && strcmp(ai.name, "tenant_allow") == 0) {
                    printf("attr %s UNKNOWN bounded=%s\n", ai.name,
                           ts == WE_TENANT_NULL ? "unknown" : ts == WE_TENANT_LAPSED ? "false"
                         : strncmp(val, "stale:", 6) == 0 ? val + 6 : "unknown");
                } else {
                    printf("attr %s UNKNOWN\n", ai.name);
                }
            } else {
                printf("attr %s %s\n", ai.name, val);
            }
        }
    }
}

static void cs_run_case(cs_prog_t *P, const cs_case_t *c)
{
    we_addr_t fa, sa;
    cs_ent_t ent[9][2];
    const we_map_t *view[8];
    we_request_t req;
    we_verdict_t v;
    uint32_t p, checked = 0u, failed = 0u;
    char cf[300], cc[300], what[200], dl[4096];
    we_tenant_state_t ts = cs_tstate(c);
    uint8_t out_mask = 0u;

    if (cs_cached >= CS_CACHE / 2u) {
        cs_cache_flush();       /* between cases only: every view of a case stays valid through it */
    }
    if (cs_addr(c->has_addr[0] ? c->addr[0] : "192.0.2.1", &fa) != 0
            || cs_addr(c->has_addr[1] ? c->addr[1] : (c->has_addr[0] ? c->addr[0] : "192.0.2.1"), &sa) != 0) {
        CHECK(0, "[cases] %s: an address that does not parse", c->id);
        return;
    }
    for (p = 1u; p <= 8u; p++) {
        ent[p][0].a = fa;
        ent[p][0].r = &c->rec[0][p];
        ent[p][1].a = sa;
        ent[p][1].r = &c->rec[1][p];
    }
    cs_views(c, (const cs_ent_t (*)[2])ent, 0, -1, view);
    memset(&req, 0, sizeof req);
    req.floor = fa;
    req.server = sa;
    req.hold_harmless_eligible = (uint8_t)c->hh;
    req.acme_exempt = (uint8_t)c->acme;
    for (p = 0u; p < 8u; p++) {
        ectx->view[p].m = view[p];
        cs_state[p] = p == 7u ? cs_tname[ts] : c->stale[p + 1u] ? "unknown" : "fresh";
    }
    cov_prog[0] = P->floor;
    cov_prog[1] = P->ctx;
    cov_rule = NULL;
    cov_instr_tap = cs_instr_tap;
    cov_rule_tap = cs_rule_tap;
#ifdef WE_TEST_NO_EXHAUSTIVE
    cov_k3_on = 0;                              /* the control: the exhaustive leg fills no cell */
    if (strcmp(P->leg, "exhaustive") == 0) {
        cov_instr_tap = NULL;
        cov_rule_tap = NULL;
    }
#else
    cov_k3_on = strcmp(P->leg, "exhaustive") == 0;
#endif
    we_decide(P->floor, c->has_conf[0] ? &c->conf[0] : NULL, P->ctx, c->has_conf[1] ? &c->conf[1] : NULL, P->hh,
              &req, ectx, c->now, &v);
    cov_k3_on = 0;
    cov_prog[0] = cov_prog[1] = NULL;
    cov_instr_tap = NULL;
    cov_rule_tap = NULL;
    if (cs_attrs) {
        /* the display fills, into a scratch verdict: the decision's counters are already final */
        we_verdict_t scratch;

        memset(&scratch, 0, sizeof scratch);
        for (p = 1u; p <= 8u; p++) {
            we_eval_lazy_fill(ectx, P->hh, 0u, p, c->now, &scratch);
        }
    }
    for (p = 0u; p < 8u; p++) {
        ectx->view[p].m = NULL;
    }
    cv_add(P->leg, memcmp(&fa, &sa, sizeof fa) == 0 ? "slot shared" : "slot distinct");
    for (p = 1u; p <= 8u; p++) {
        uint32_t s2;

        for (s2 = 0u; s2 < 2u; s2++) {
            int alias = memcmp(&fa, &sa, sizeof fa) == 0;

            if (v.lookups[s2][p - 1u] != 0u) {
                cs_clamps(p, &c->rec[alias ? 0u : s2][p]);
            }
        }
    }
    /* the two compared lines come from the exported formatter, so the tool and the differential share it */
    {
        static char vl[WE_VERDICT_LINE_MAX], cl[WE_VERDICT_LINE_MAX];

        CHECK(we_verdict_format(&v, vl, cl, sizeof vl) == 0, "[cases] %s: the verdict lines fit", c->id);
        printf("case %s\n", c->id);
        printf("%s\n%s\n", vl, cl);
    }
    if (cs_attrs) {
        cs_print_attrs(P, &ectx->slot[0], ts);
    }
    cs_invariant(P, c, (const cs_ent_t (*)[2])ent, &fa, &checked, &failed);
    printf("invariant checked=%u failed=%u\n", checked, failed);
    CHECK(failed == 0u, "[cases] %s: ISUNK(x) == (K3(x) == U) on every atom and state", c->id);
    for (p = 1u; p <= 7u; p++) {
        out_mask = (uint8_t)(out_mask | (c->stale[p] ? 1u << (p - 1u) : 0u));
    }
    cs_classes(P->has_floor ? P->floor : NULL, out_mask, ts, cf, sizeof cf);
    cs_classes(P->ctx, out_mask, ts, cc, sizeof cc);
    printf("classes floor=%s ctx=%s\n", cf, cc);
    if (strchr(cf, 'x') != NULL || strchr(cc, 'x') != NULL) {
        cv_add(P->leg, "class x");
    }
    {
        size_t o = 0u;

        what[0] = '\0';
        for (p = 1u; p <= 7u; p++) {
            if (c->stale[p]) {
                o += (size_t)snprintf(what + o, sizeof what - o, "%s%s", o == 0u ? "" : ",", cs_plane[p - 1u]);
            }
        }
        snprintf(what + o, sizeof what - o, "%s tenant=%s", o == 0u ? "-" : "", cs_tname[ts]);
        memmove(what + 4, what, strlen(what) + 1u);
        memcpy(what, "out=", 4);
    }
    if (P->has_floor && we_program_dependents_line(P->floor, out_mask, ts, what, dl, sizeof dl) >= 0) {
        printf("dependents floor %s\n", dl);
    }
    if (P->ctx != NULL && we_program_dependents_line(P->ctx, out_mask, ts, what, dl, sizeof dl) >= 0) {
        printf("dependents ctx %s\n", dl);
    }
}

static int run_cases(const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0u;
    ssize_t got;
    cs_prog_t P;
    cs_case_t c;
    long long nprog = 0, ncase = 0;
    int i, ran_exh = 0, ran_other = 0, ran_absent = 0;

    if (f == NULL) {
        fprintf(stderr, "test_policy: %s: %s\n", path, strerror(errno));
        return 2;
    }
    for (i = 0; i < 256; i++) {
        if (i == 0) {
            cs_feed_names[i][0] = '\0';          /* feed 0 is unnamed */
        } else {
            snprintf(cs_feed_names[i], sizeof cs_feed_names[i], "f%d", i);
        }
        cs_feeds[i] = cs_feed_names[i];
    }
    memset(&P, 0, sizeof P);
    memset(&c, 0, sizeof c);
    while ((got = getline(&line, &cap, f)) >= 0) {
        char *rest, *sp;

        while (got > 0 && (line[got - 1] == '\n' || line[got - 1] == '\r')) {
            line[--got] = '\0';
        }
        if (got == 0 || line[0] == '#') {
            continue;
        }
        sp = strchr(line, ' ');
        rest = sp != NULL ? sp + 1 : line + got;
        if (sp != NULL) {
            *sp = '\0';
        }
        if (strcmp(line, "program") == 0) {
            if (P.id[0] != '\0' && !P.compiled) {
                cs_compile(&P);
            }
            cs_prog_free(&P);
            sp = strchr(rest, ' ');
            if (sp != NULL) {
                *sp = '\0';
                snprintf(P.leg, sizeof P.leg, "%s", sp + 1);
            }
            snprintf(P.id, sizeof P.id, "%s", rest);
            snprintf(cs_leg, sizeof cs_leg, "%s", P.leg);
            if (strcmp(P.leg, "exhaustive") == 0) {
                ran_exh = 1;
            } else if (strcmp(P.leg, "cases") != 0) {
                /* the `cases` leg (the seeds as policy_gen.py copies them into the generated file, and
                   the blocks whisper-edge-lookup --case prints) owns no coverage cell: a file of only
                   such blocks is compared, never held to the matrix; a seed file keeps its own `seeds`
                   leg and is held to it */
                ran_other = 1;
                ran_absent |= strcmp(P.leg, "absent") == 0;
            }
            snprintf(P.run, sizeof P.run, "http");
            nprog++;
        } else if (strcmp(line, "dir") == 0) {
            char *k = rest, *cx, *a;

            cx = strchr(k, ' ');
            if (cx == NULL) {
                continue;
            }
            *cx++ = '\0';
            a = strchr(cx, ' ');
            if (a != NULL) {
                *a++ = '\0';
            } else {
                a = cx + strlen(cx);
            }
            if (P.n == P.cap) {
                P.cap = P.cap != 0u ? P.cap * 2u : 16u;
                P.d = (cs_dir_t *)realloc(P.d, P.cap * sizeof *P.d);
            }
            snprintf(P.d[P.n].kind, sizeof P.d[P.n].kind, "%s", k);
            snprintf(P.d[P.n].ctx, sizeof P.d[P.n].ctx, "%s", cx);
            P.d[P.n].arg = (uint8_t *)malloc(strlen(a) + 1u);
            P.d[P.n].len = cs_unescape(a, P.d[P.n].arg);
            P.n++;
        } else if (strcmp(line, "run") == 0) {
            snprintf(P.run, sizeof P.run, "%s", rest);
        } else if (strcmp(line, "legacy") == 0) {
            P.legacy = 1u;
        } else if (strcmp(line, "absent") == 0) {
            char *t = strtok(rest, " ");

            for (; t != NULL; t = strtok(NULL, " ")) {
                int pid = cs_plane_id(t);

                P.absent = (uint8_t)(P.absent | (pid != 0 ? 1u << (pid - 1) : 0u));
            }
        } else if (strcmp(line, "case") == 0) {
            if (!P.compiled) {
                cs_compile(&P);
            }
            memset(&c, 0, sizeof c);
            snprintf(c.id, sizeof c.id, "%s", rest);
            c.tenant = CS_T_FRESH;
            c.now = 0u;
            c.vu = 1u;
        } else if (strcmp(line, "conf") == 0) {
            char w[16];
            unsigned m, a;

            if (sscanf(rest, "%15s %u %u", w, &m, &a) == 3) {
                int x = strcmp(w, "floor") == 0 ? 0 : 1;

                c.has_conf[x] = 1;
                c.conf[x].mode = (uint8_t)m;
                c.conf[x].allow_inferred = (uint8_t)a;
            }
        } else if (strcmp(line, "plane") == 0) {
            char n[32], st[16];

            if (sscanf(rest, "%31s %15s", n, st) == 2) {
                int pid = cs_plane_id(n);

                if (pid >= 1 && pid <= 7) {
                    c.stale[pid] = strcmp(st, "fresh") == 0 ? 0 : strcmp(st, "gen0") == 0 ? 2 : 1;
                }
            }
        } else if (strcmp(line, "tenant") == 0) {
            char st[16];
            unsigned long long now, vu;

            if (sscanf(rest, "%15s %llu %llu", st, &now, &vu) == 3) {
                c.tenant = strcmp(st, "fresh") == 0 ? CS_T_FRESH : strcmp(st, "stale") == 0 ? CS_T_STALE
                         : strcmp(st, "null") == 0 ? CS_T_NULL : CS_T_REVOKED;
                c.now = now;
                c.vu = vu;
            }
        } else if (strcmp(line, "addr") == 0) {
            char w[16], a[64];

            if (sscanf(rest, "%15s %63s", w, a) == 2) {
                int x = strcmp(w, "floor") == 0 ? 0 : 1;

                c.has_addr[x] = 1;
                snprintf(c.addr[x], sizeof c.addr[x], "%s", a);
            }
        } else if (strcmp(line, "flags") == 0) {
            sscanf(rest, "%d %d", &c.hh, &c.acme);
        } else if (strcmp(line, "rec") == 0) {
            char *w = strtok(rest, " "), *pl = strtok(NULL, " "), *t;
            int x, pid;
            cs_rec_t *r;

            if (w == NULL || pl == NULL) {
                continue;
            }
            x = strcmp(w, "floor") == 0 ? 0 : 1;
            pid = cs_plane_id(pl);
            r = &c.rec[x][pid];
            memset(r, 0, sizeof *r);
            r->has = 1;
            for (t = strtok(NULL, " "); t != NULL; t = strtok(NULL, " ")) {
                char *eq = strchr(t, '=');
                int fi;

                if (strcmp(t, "none") == 0) {
                    r->none = 1;
                    continue;
                }
                if (eq == NULL) {
                    continue;
                }
                *eq = '\0';
                fi = cs_field((uint32_t)pid, t);
                if (fi >= 0) {
                    r->f[fi] = strtoull(eq + 1, NULL, 10);
                }
            }
        } else if (strcmp(line, "sweep") == 0) {
            char w[16], pl[32], fl[32];
            unsigned long long lo, hi;

            if (sscanf(rest, "%15s %31s %31s %llu %llu", w, pl, fl, &lo, &hi) == 5) {
                c.sweep = 1;
                c.sw_who = strcmp(w, "floor") == 0 ? 0 : 1;
                c.sw_plane = cs_plane_id(pl);
                c.sw_field = cs_field((uint32_t)c.sw_plane, fl);
                c.sw_lo = lo;
                c.sw_hi = hi;
            }
        } else if (strcmp(line, "end") == 0) {
            if (P.refused) {
                continue;
            }
            if (!c.sweep) {
                cs_run_case(&P, &c);
                ncase++;
            } else {
                uint64_t x;
                cs_case_t c2;

                for (x = c.sw_lo; x <= c.sw_hi; x++) {
                    cs_rec_t *r;

                    c2 = c;
                    snprintf(c2.id, sizeof c2.id, "%.120s.%" PRIu64, c.id, x);
                    r = &c2.rec[c2.sw_who][c2.sw_plane];
                    if (!r->has || r->none) {
                        memset(r, 0, sizeof *r);
                        r->has = 1;
                    }
                    if (c2.sw_field >= 0) {
                        r->f[c2.sw_field] = x;
                    }
                    cs_run_case(&P, &c2);
                    ncase++;
                }
            }
        } else {
            CHECK(0, "[cases] %s: an unknown line %s", path, line);
        }
    }
    if (P.id[0] != '\0' && !P.compiled) {
        cs_compile(&P);
    }
    cs_prog_free(&P);
    free(line);
    fclose(f);
    cs_cache_flush();
    cs_check_matrix(ran_exh, ran_other, ran_absent);
    fprintf(stderr, "test_policy --cases: %lld programs, %lld cases; %lld checks, %lld failures\n", nprog, ncase,
            checks, failures);
    return failures == 0 ? 0 : 1;
}

/* ======================================================================================================
 * --c-only DIR: the seeds only this harness can build (the .c-only files of testdata/policy/seeds), one line each,
 * `c-only <name> ok`, so the Makefile can see that every such seed was accounted for
 * ==================================================================================================== */

/*
 * The last record of each family ends exactly at a page boundary, the next page a guard: the record
 * column of a loaded map is moved there (and `end`, which a format-2 family reads from the record), a
 * rule reads that plane at the last range's last address, and the request runs in a child, so a read
 * one byte past the record is a SIGSEGV the parent sees.
 */
static int co_page_boundary(void)
{
    static const struct { uint32_t plane; int fam; uint32_t n; const char *rule; } F[] = {
        { WE_PLANE_REPUTATION, 4, 64u, "deny if listed >= low" },
        { WE_PLANE_REPUTATION, 6, 64u, "deny if listed >= low" },
        { WE_PLANE_TOR, 4, 4u, "deny if tor_exit" },
        { WE_PLANE_TOR, 6, 2u, "deny if tor_exit" },
        { WE_PLANE_ROUTING, 4, 4u, "deny if asn == 64496" },
        { WE_PLANE_ROUTING, 6, 8u, "deny if asn == 64496" },
    };
    size_t k;
    int bad = 0, run;

    /* run 0: every family on the boundary; run 1, the control: the tor v4 column one byte later must fault */
    for (run = 0; run < 2; run++)
    for (k = run == 0 ? 0u : 2u; k < (run == 0 ? sizeof F / sizeof F[0] : 3u); k++) {
        pspec_t *ps = new_spec(F[k].plane);
        const we_map_t *m0;
        we_map_t *m;
        we_fam_t *f;
        uint32_t i, st;
        size_t col;
        uint8_t *nb;
        const we_program_t *p = prog1(F[k].rule);
        we_request_t req;
        pid_t pid;
        int status = 0;

        for (i = 0u; i < F[k].n; i++) {
            uint8_t r[32];

            memset(r, 0, sizeof r);
            if (F[k].plane == WE_PLANE_REPUTATION) {
                r[0] = 3u;
            } else if (F[k].plane == WE_PLANE_TOR) {
                if (F[k].fam == 4) {
                    mrec4(r, 1u, 0u);
                } else {
                    mrec6(r, 1u, 0u);
                }
            } else if (F[k].fam == 4) {
                rrec4(r, 64496u, 0u, 1u, 0u, 0u, 0u);
            } else {
                rrec6(r, 64496u, 0u, 1u, 0u, 0u, 0u);
            }
            if (F[k].fam == 4) {
                add4(ps, 0x16000000u + i * 0x100u, 0x16000000u + i * 0x100u + 0xffu, r, 32u);
            } else if (F[k].plane == WE_PLANE_ROUTING) {
                add6(ps, (__uint128_t)0x24000000u + i * 0x10u, (__uint128_t)0x24000000u + i * 0x10u + 0xfu, r, 32u);
            } else {
                __uint128_t b = ((__uint128_t)0x2400abcd00000000ull << 64) + ((__uint128_t)i << 32);

                add6(ps, b, b + 0xffffffffu, r, 32u);
            }
        }
        m0 = mk_map(ps, 7u, 0u, 0, NULL, NULL);
        free(ps);
        if (m0 == NULL || p == NULL) {
            bad++;
            continue;
        }
        m = (we_map_t *)aligned_alloc(64, (sizeof *m + 63u) & ~(size_t)63u);
        *m = *m0;
        f = F[k].fam == 4 ? &m->f4 : F[k].plane == WE_PLANE_ROUTING ? &m->f6w : &m->f6;
        st = F[k].plane == WE_PLANE_REPUTATION ? 1u : f->stride;
        col = (size_t)f->n * st;
        if (col % 64u != 0u || f->n != F[k].n) {
            printf("  page-boundary: plane %u family %d: a %zu-byte column cannot end on the boundary\n",
                   F[k].plane, F[k].fam, col);
            bad++;
            continue;
        }
        nb = region(col, 1);                     /* ends exactly where the trailing guard page begins */
        if (run == 1) {
            /*
             * The control: seven bytes later, so the record's reason byte (offset 9; 10..15 are reserved
             * and never read) is the guard page's first byte, and the fill must fault on it.
             */
            nb += 7;
            col -= 7u;
        }
        if (F[k].plane == WE_PLANE_REPUTATION) {
            memcpy(nb, f->sev, col);
            f->sev = nb;
        } else {
            memcpy(nb, f->records, col);
            f->end = nb + (f->end - f->records);
            f->records = nb;
        }
        memset(&req, 0, sizeof req);
        if (F[k].fam == 4) {
            addr4(&req.floor, 0x16000000u + (F[k].n - 1u) * 0x100u + 0xffu);
        } else if (F[k].plane == WE_PLANE_ROUTING) {
            addr6(&req.floor, (((__uint128_t)0x24000000u + (F[k].n - 1u) * 0x10u + 0xfu) << 64) | 0xffffu);
        } else {
            addr6(&req.floor, ((__uint128_t)0x2400abcd00000000ull << 64) + ((__uint128_t)(F[k].n - 1u) << 32) + 0xffffffffu);
        }
        req.server = req.floor;
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            we_ctx_conf_t cf = { WE_MODE_DENY, 0u };
            we_verdict_t v;
            uint32_t q;

            for (q = 0u; q < 8u; q++) {
                ectx->view[q].m = NULL;
            }
            ectx->view[F[k].plane - 1u].m = m;
            we_decide(EMPTY_FLOOR, &cf, p, &cf, HH, &req, ectx, NOW, &v);
            _exit(v.action == WE_ACT_DENY ? 0 : 3);
        }
        waitpid(pid, &status, 0);
        if (run == 1) {
            if (!(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)) {
                printf("  page-boundary: the control did not fault, so the boundary case proves nothing\n");
                bad++;
            }
            continue;
        }
        if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
            printf("  page-boundary: plane %u family %d: %s %d\n", F[k].plane, F[k].fam,
                   WIFSIGNALED(status) ? "signal" : "exit", WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status));
            bad++;
        }
    }
    return bad == 0;
}

/* A NULL view where the module meant FRESH: every atom on the plane reads UNKNOWN, nothing faults. */
static int co_null_marked_fresh(void)
{
    static const char *const rules[] = { "allow if tor_exit", "allow if listed >= low", "allow if asn == 64496",
                                         "allow if country in { NL }", "allow if registry_rir == ripe",
                                         "allow if tenant_allow", "allow if c2" };
    static const uint32_t plane[] = { 2u, 1u, 4u, 4u, 7u, 8u, 6u };
    size_t k;
    int ok = 1;

    for (k = 0u; k < sizeof rules / sizeof rules[0]; k++) {
        const char *lines[1] = { rules[k] };
        const we_program_t *p = ctxprog(lines, 1);
        we_ctx_conf_t cf = { WE_MODE_DENY, 0u };
        we_request_t req;
        we_verdict_t v;
        uint32_t q;

        memset(&req, 0, sizeof req);
        addr4(&req.floor, A_T);
        req.server = req.floor;
        for (q = 0u; q < 8u; q++) {
            ectx->view[q].m = NULL;            /* every plane NULL: published as refused or loading */
        }
        we_decide(EMPTY_FLOOR, &cf, p, &cf, HH, &req, ectx, NOW, &v);
        if (!(v.action == WE_ACT_ALLOW && v.reason == WE_WHY_ALLOW_BY_UNKNOWN && v.unknown_plane == plane[k])) {
            printf("  null-marked-fresh: %s reads %u reason %u plane %u, not UNKNOWN\n", rules[k], v.action, v.reason,
                   v.unknown_plane);
            ok = 0;
        }
    }
    return ok;
}

/*
 * A memo state byte of 7, outside the published states, left in the context by a previous user: the
 * evaluator starts every request unkeyed, so the byte never reaches evaluation and the verdict is the
 * clean context's.
 */
static int co_state_7(void)
{
    const we_program_t *p = prog1("deny if tor_exit");
    we_ctx_conf_t cf = { WE_MODE_DENY, 0u };
    we_request_t req;
    we_verdict_t v0, v1;
    uint32_t q, s;

    memset(&req, 0, sizeof req);
    addr4(&req.floor, A_T);
    req.server = req.floor;
    for (q = 0u; q < 8u; q++) {
        ectx->view[q].m = world_view(&W, q);
    }
    we_decide(EMPTY_FLOOR, &cf, p, &cf, HH, &req, ectx, NOW, &v0);
    for (s = 0u; s < 2u; s++) {
        memset(ectx->slot[s].state, 7, sizeof ectx->slot[s].state);   /* the same key, every state 7 */
        ectx->slot[s].key_valid = 1u;
    }
    we_decide(EMPTY_FLOOR, &cf, p, &cf, HH, &req, ectx, NOW, &v1);
    for (q = 0u; q < 8u; q++) {
        ectx->view[q].m = NULL;
    }
    return v0.action == WE_ACT_DENY && v1.action == v0.action && v1.rule == v0.rule && v1.lookups[0][1] == 1u;
}

static int run_c_only(const char *dir)
{
    static const struct { const char *name; int (*fn)(void); } T[] = {
        { "records-last-record-at-a-page-boundary", co_page_boundary },
        { "records-null-map-marked-fresh", co_null_marked_fresh },
        { "records-plane-state-7", co_state_7 },
    };
    char *names[64];
    int n = list_files(dir, ".c-only", names, 64), i, bad = 0;
    const char *none[1] = { NULL };

    EMPTY_FLOOR = floorprog(none, 0, NULL);
    HH = ro_hh(EMPTY_FLOOR);
    standard_world();
    for (i = 0; i < n; i++) {
        char base[256];
        size_t k, l;
        int done = 0;

        snprintf(base, sizeof base, "%s", names[i]);
        l = strlen(base);
        if (l > 7u && strcmp(base + l - 7u, ".c-only") == 0) {
            base[l - 7u] = '\0';
        }
        for (k = 0u; k < sizeof T / sizeof T[0]; k++) {
            if (strcmp(base, T[k].name) == 0) {
                int ok = T[k].fn();

                printf("c-only %s %s\n", base, ok ? "ok" : "FAIL");
                CHECK(ok, "[c-only] %s", base);
                bad += !ok;
                done = 1;
            }
        }
        if (!done) {
            printf("c-only %s unknown\n", base);
            CHECK(0, "[c-only] %s: a C-only seed this harness has no case for", base);
            bad++;
        }
        free(names[i]);
    }
    CHECK(n > 0, "[c-only] %s holds C-only seeds", dir);
    printf("\n%lld checks, %lld failures\n", checks, failures);
    return bad == 0 && n > 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    int i;

    const char *cases_file = NULL;
    const char *c_only_dir = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);          /* a fault never swallows the lines before it */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--emit") == 0) {
            emit = 1;
        } else if (strcmp(argv[i], "--cases") == 0 && i + 1 < argc) {
            cases_file = argv[++i];
        } else if (strcmp(argv[i], "--attrs") == 0) {
            cs_attrs = 1;
        } else if (strcmp(argv[i], "--c-only") == 0 && i + 1 < argc) {
            c_only_dir = argv[++i];
        } else {
            TMP = argv[i];
        }
    }
    mkdir(TMP, 0755);
    ectx = (we_eval_ctx_t *)aligned_alloc(64, sizeof(we_eval_ctx_t));
    memset(ectx, 0, sizeof *ectx);
    {
        we_map_t *rv = we_map_new_revoked();

        revoked_map = rv;
    }
    if (cases_file != NULL) {
        return run_cases(cases_file);
    }
    if (c_only_dir != NULL) {
        return run_c_only(c_only_dir);
    }
    test_corpus();
    {
        const char *none[1] = { NULL };

        EMPTY_FLOOR = floorprog(none, 0, NULL);
        HH = ro_hh(EMPTY_FLOOR);
    }
    standard_world();
    tenant_world();
    test_k_rows();
    test_f_rows();
    test_proxy_rows();
    test_tenant();
    test_exhaustive();
    test_state_vectors();
    test_classifier();
    test_revocation();
    test_d_rest();
    test_memo();
    test_sets();
    test_sugar();
    test_planted_store();
    test_verifier();
    test_refusals();
    test_rulings();
    test_hold_harmless();
    test_counters();
    check_coverage();
    CHECK(k3_bad == 0, "[K6] T & F == 0 after every instruction (%lld violations)", k3_bad);
    printf("\n%lld evaluated cases against the reference\n", cases);
    printf("\n%lld checks, %lld failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
