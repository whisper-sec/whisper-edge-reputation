/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * fuzz_policy - the policy compiler's fuzz harness, and its replay without a fuzzer.
 *
 * ONE INPUT is a whole configuration, so the harness reaches what a single argument cannot: several
 * directives and contexts, set scoping, duplicates, multi-rule polarity, the 256-rule and 4,096-operation
 * limits, and plane environments with planes absent or present under the wrong schema.
 *
 *   byte 0      the planes present at configuration time, bit (plane_id - 1)
 *   byte 1      of those, the planes whose header carries the wrong schema
 *   the rest    directives in the corpus's record format: <kind> SP <context> SP <argument> 0x1E, an
 *               optional 0x0A after the separator; 0x1E lies outside the language's alphabet, so no
 *               argument can contain it
 *
 * On every input, whatever it holds:
 *   - no crash, no sanitizer report, no read past the input (libFuzzer's buffer is exactly its size);
 *   - every directive set compiles, or is refused with a located error: a layer of section 1.5, a rule
 *     ordinal, a line and column of at least 1, a token of at most 64 bytes;
 *   - every accepted program passes we_program_verify(), and a second compile is byte-identical;
 *   - every accepted program's canonical text is printed (never empty when there are rules), compiled
 *     again, and gives the same text and a byte-identical block (R1, verifier step 22);
 *   - every accepted program is evaluated by we_decide() over all eight planes (fuzz_common.h), at their
 *     deciding addresses, every view write-protected, the planes the environment lacks as NULL views,
 *     and again with every view NULL; the replay requires some verdict to differ between the two (accept/01's
 *     `deny if listed >= high` at a reputation range of severity 3 denies with the views and allows without).
 *
 * Without a fuzzer (`fuzz_policy --replay DIR --planes PLANES --floor N`), the same checks run over
 * every file under DIR (the corpus, the seeds and the adversarial inputs), in the default environment (every plane present,
 * every schema right). A `refuse/` file must be refused with every key of its `.expect` present and
 * equal by the oracle's matching rule (row N1), and an `accept/` file must compile. The replay fails below the seed floor it is given, so deleting a file cannot pass.
 *
 * Built only once the compiler exists (`make fuzz` says so by name until then); fuzz_common.h holds
 * every assumption this file makes about that API beyond the names POLICY.md fixes.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_common.h"

#define FZ_MAX_CTX 64u

static unsigned long g_checks, g_failures;

#define FZ_ASSERT(cond, ...)                                                                    \
    do {                                                                                        \
        g_checks++;                                                                             \
        if (!(cond)) {                                                                          \
            g_failures++;                                                                       \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                                \
            fprintf(stderr, __VA_ARGS__);                                                       \
            fputc('\n', stderr);                                                                \
            if (getenv("FZ_ABORT") != NULL) {                                                   \
                abort();                                                                        \
            }                                                                                   \
        }                                                                                       \
    } while (0)

static const char *const FZ_LAYERS[] = { "length", "alphabet", "lexing", "parsing", "typing", "sets",
                                         "program", "polarity" };

static int fz_layer_known(const char *l)
{
    for (size_t i = 0; l != NULL && i < sizeof FZ_LAYERS / sizeof FZ_LAYERS[0]; i++) {
        if (strcmp(l, FZ_LAYERS[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Every plane, loaded once and write-protected (fuzz_common.h says which fixtures), so evaluation runs
 * the memo fill and reads real records. */
static fz_planes_t g_pl;
static int g_nplanes;
static unsigned long g_evals, g_view_differ;

/* Evaluate an accepted program over the planes' deciding addresses (32 of them, spread over the set),
 * under every mode, each request twice: with the real views (the planes the environment lacks NULL) and
 * with every view NULL. g_view_differ counts the requests whose verdicts differ, which the replay
 * requires to be above zero: if the views went back to NULL it would stay at zero. */
static void fz_evaluate(const we_program_t *floor, const we_program_t *ctx, const we_hh_view_t *hh,
                        uint8_t present)
{
    static const uint8_t MODES[][2] = { { 3, 0 }, { 2, 1 }, { 1, 0 }, { 0, 0 }, { 7, 0 } };
    we_eval_ctx_t *ec = fz_alloc(NULL, sizeof *ec, 64);
    if (ec == NULL || g_pl.naddr == 0) {
        free(ec);
        return;
    }
    size_t step = g_pl.naddr > 32 ? g_pl.naddr / 32 : 1;
    for (size_t a = 0; a < g_pl.naddr; a += step) {
        size_t b = (a + g_pl.naddr / 2) % g_pl.naddr;      /* a distinct server address beside it */
        for (size_t m = 0; m < 2 * (sizeof MODES / sizeof MODES[0]); m++) {
            we_request_t req;
            we_verdict_t real, none;
            size_t mi = m / 2, srv = (m & 1u) ? b : a;
            memset(&req, 0, sizeof req);
            we_addr_canon(g_pl.addr[a], g_pl.fam[a], &req.floor);
            we_addr_canon(g_pl.addr[srv], g_pl.fam[srv], &req.server);
            req.hold_harmless_eligible = (uint8_t)(a & 1u);
            we_ctx_conf_t conf = { MODES[mi][0], MODES[mi][1] };
            memset(ec, 0, sizeof *ec);
            fz_views(ec, &g_pl, (uint8_t)~present);
            we_decide(floor, &conf, ctx, &conf, hh, &req, ec, 1800000000000ull, &real);
            memset(ec, 0, sizeof *ec);
            fz_views(ec, &g_pl, 0xFFu);
            we_decide(floor, &conf, ctx, &conf, hh, &req, ec, 1800000000000ull, &none);
            FZ_ASSERT(real.action <= 2 && none.action <= 2, "verdict action out of domain");
            g_evals++;
            g_view_differ += (unsigned long)fz_verdicts_differ(&real, &none);
        }
    }
    free(ec);
}

/* Compile one program of the configuration (a context's, or the floor) and hold every invariant.
 * Returns the program (caller frees) or NULL when refused; *err is filled on refusal. */
static we_program_t *fz_compile_one(const fz_config_t *c, const char *context, int is_floor,
                                    const we_policy_env_t *env, we_policy_error_t *err, int *refused)
{
    we_policy_source_t src = { c->d, c->n, context, is_floor };
    we_program_t *p = NULL;
    memset(err, 0, sizeof *err);
    int rc = we_policy_compile(&src, env, &FZ_ALLOC, &p, err, NULL);
    if (rc != 0) {
        *refused = 1;
        FZ_ASSERT(fz_layer_known(err->layer), "a refusal in no layer of section 1.5 (%s)",
                  err->layer != NULL ? err->layer : "null");
        FZ_ASSERT(err->line >= 1 && err->col >= 1, "an unlocated refusal: line %u col %u", err->line, err->col);
        FZ_ASSERT(err->token_len <= 64, "a token of %zu bytes, over the 64 POLICY.md allows", err->token_len);
        FZ_ASSERT(err->what[0] != '\0', "a refusal with no what");
        return NULL;
    }
    *refused = 0;
    size_t len = we_program_size(p);
    we_policy_error_t verr;
    FZ_ASSERT(we_program_verify(p, len, &verr) == 0, "an accepted program fails verify: %s",
              verr.what);
    we_program_t *q = NULL;
    we_policy_error_t e2;
    FZ_ASSERT(we_policy_compile(&src, env, &FZ_ALLOC, &q, &e2, NULL) == 0 && q != NULL
              && we_program_size(q) == len && memcmp(p, q, len) == 0,
              "two compiles of one text are not byte-identical");
    if (q != NULL) {
        fz_free(NULL, q);
    }
    /* R1: print, re-parse with the configuration's sets in scope, print; the text AND the block must be
     * identical (row R1, verifier step 22). A program with rules must print something, so a printer
     * that returns 0 cannot pass this by skipping it. */
    static char text1[1 << 20], text2[1 << 20];
    we_program_t hdr;
    memcpy(&hdr, p, sizeof hdr);
    int n1 = we_program_print(p, text1, sizeof text1);
    FZ_ASSERT(n1 >= 0, "the disassembler failed");
    FZ_ASSERT(hdr.rule_count == 0 || n1 > 0, "a program of %u rules printed no text", (unsigned)hdr.rule_count);
    if (n1 > 0) {
        FZ_ASSERT(text1[n1 - 1] == '\n', "the canonical text does not end in LF");
        static fz_config_t rc2;
        rc2.n = 0;
        for (size_t i = 0; i < c->n; i++) {
            if (c->d[i].kind == WE_DIR_SET) {
                rc2.d[rc2.n] = c->d[i];
                rc2.n++;
            }
        }
        size_t lines = 0;
        char *line = text1;
        while (line < text1 + n1 && rc2.n < FZ_MAX_DIRS) {
            char *nl = memchr(line, '\n', (size_t)(text1 + n1 - line));
            size_t ll = nl != NULL ? (size_t)(nl - line) : (size_t)(text1 + n1 - line);
            rc2.d[rc2.n].kind = (uint8_t)(is_floor ? WE_DIR_FLOOR : WE_DIR_POLICY);
            rc2.d[rc2.n].context = context;
            rc2.d[rc2.n].arg = (const uint8_t *)line;
            rc2.d[rc2.n].len = ll;
            rc2.n++;
            lines++;
            line += ll + (nl != NULL ? 1 : 0);
        }
        FZ_ASSERT(lines == hdr.rule_count, "the text holds %zu lines for %u rules", lines, (unsigned)hdr.rule_count);
        we_policy_source_t src2 = { rc2.d, rc2.n, context, is_floor };
        we_program_t *r = NULL;
        we_policy_env_t envc = FZ_ENV(env->present, env->schema_ok, 1u);   /* the printed text: D32 */
        int ok = we_policy_compile(&src2, &envc, &FZ_ALLOC, &r, &e2, NULL) == 0 && r != NULL;
        FZ_ASSERT(ok, "the canonical text is refused on re-parse: %s", e2.what);
        if (ok) {
            int n2 = we_program_print(r, text2, sizeof text2);
            FZ_ASSERT(n2 == n1 && memcmp(text1, text2, (size_t)n1) == 0, "print, reparse, print differs");
            FZ_ASSERT(we_program_size(r) == len && memcmp(p, r, len) == 0,
                      "the re-parsed block is not byte-identical to the original");
            fz_free(NULL, r);
        }
    }
    return p;
}

/* Every context with policy lines is one program; the floor is its own. */
static int fz_one_config(const fz_config_t *c, uint8_t present, uint8_t wrong_schema, we_policy_error_t *first,
                         int *any_refused)
{
    we_policy_env_t env = FZ_ENV(present, present & (uint8_t)~wrong_schema, 0u);
    we_policy_error_t err;
    int refused = 0;
    *any_refused = 0;
    we_program_t *floor = fz_compile_one(c, "http", 1, &env, &err, &refused);
    if (refused) {
        *first = err;
        *any_refused = 1;
        return 0;
    }
    we_hh_view_t hh;
    FZ_ASSERT(we_program_place(floor, &hh) == 0, "the hold-harmless view cannot be placed");
    const char *seen[FZ_MAX_CTX];
    size_t nseen = 0;
    for (size_t i = 0; i < c->n; i++) {
        if (c->d[i].kind != WE_DIR_POLICY && c->d[i].kind != WE_DIR_THRESHOLD) {
            continue;
        }
        int dup = 0;
        for (size_t k = 0; k < nseen; k++) {
            dup |= strcmp(seen[k], c->d[i].context) == 0;
        }
        if (dup || nseen == FZ_MAX_CTX) {
            continue;
        }
        seen[nseen++] = c->d[i].context;
        we_program_t *p = fz_compile_one(c, c->d[i].context, 0, &env, &err, &refused);
        if (refused) {
            *first = err;
            *any_refused = 1;
            fz_free(NULL, floor);
            return 0;
        }
        fz_evaluate(floor, p, &hh, present);
        fz_free(NULL, p);
    }
    if (nseen == 0) {
        fz_evaluate(floor, NULL, &hh, present);
    }
    fz_free(NULL, floor);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static fz_config_t c;
    static int loaded;
    if (!loaded) {
        const char *dir = getenv("FZ_PLANES");
        g_nplanes = fz_load_planes(dir != NULL ? dir : "planes", &g_pl);
        if (g_nplanes != 8) {
            fprintf(stderr, "fuzz_policy: %d of 8 planes loaded from FZ_PLANES\n", g_nplanes);
            abort();
        }
        loaded = 1;
    }
    if (size < 2 || fz_split(data + 2, size - 2, &c) != 0) {
        return 0;
    }
    we_policy_error_t e;
    int refused;
    fz_one_config(&c, data[0], data[1], &e, &refused);
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * The replay: no fuzzer, every corpus and seed file, the .expect fields compared.
 * ------------------------------------------------------------------------------------------------ */
#ifndef FZ_LIBFUZZER

/* N1's matching rule, the oracle's: every key present and equal; the message EQUAL to what or fix for
 * the five fixed strings (the byte, GB, RU, bare-action and wrong-class messages), contained for the
 * polarity clause and every table phrase; a missing key or an empty message fails. */
static int fz_message_matches(const char *msg, const char *what, const char *fix)
{
    static const char *const FIXED[] = { "did you mean GB", "write country in { RU } or country == RU",
                                         "deny if not <condition>" };
    int exact = strncmp(msg, "byte 0x", 7) == 0 || strstr(msg, " takes ") != NULL;
    for (size_t i = 0; i < sizeof FIXED / sizeof FIXED[0]; i++) {
        exact |= strcmp(msg, FIXED[i]) == 0;
    }
    if (msg[0] == '\0') {
        return 0;
    }
    if (exact) {
        return (what != NULL && strcmp(what, msg) == 0) || (fix != NULL && strcmp(fix, msg) == 0);
    }
    return (what != NULL && strstr(what, msg) != NULL) || (fix != NULL && strstr(fix, msg) != NULL);
}

static void fz_expect(const char *expect_path, const we_policy_error_t *e, int refused, const char *name)
{
    size_t n;
    uint8_t *x = fz_read(expect_path, &n);
    FZ_ASSERT(x != NULL, "%s: no .expect", name);
    if (x == NULL) {
        return;
    }
    FZ_ASSERT(refused, "%s compiled; its .expect names a refusal", name);
    char tok[300];
    snprintf(tok, sizeof tok, "%s", e->token);   /* already rendered by the compiler (section 1.5) */
    char num[3][16];
    snprintf(num[0], sizeof num[0], "%u", e->rule);
    snprintf(num[1], sizeof num[1], "%u", e->line);
    snprintf(num[2], sizeof num[2], "%u", e->col);
    const char *got[] = { e->layer, we_policy_kind_name(e->kind), e->context, num[0], num[1], num[2], tok };
    static const char *const KEYS[] = { "layer", "kind", "context", "rule", "line", "col", "token", "message" };
    int seen[8] = { 0 };
    char *save = NULL;
    char *s = malloc(n + 1);
    if (s == NULL) {
        free(x);
        return;
    }
    memcpy(s, x, n);
    s[n] = '\0';
    for (char *line = strtok_r(s, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *tab = strchr(line, '\t');
        if (tab == NULL) {
            continue;
        }
        *tab = '\0';
        const char *v = tab + 1;
        for (size_t k = 0; k < 8; k++) {
            if (strcmp(line, KEYS[k]) != 0) {
                continue;
            }
            seen[k] = 1;
            if (!refused) {
                continue;
            }
            if (k < 7) {
                FZ_ASSERT(got[k] != NULL && strcmp(got[k], v) == 0, "%s: %s expected %s, got %s", name, KEYS[k], v,
                          got[k] != NULL ? got[k] : "null");
            } else {
                FZ_ASSERT(fz_message_matches(v, e->what, e->fix), "%s: message %s matches neither what nor fix",
                          name, v);
            }
        }
    }
    for (size_t k = 0; k < 8; k++) {
        FZ_ASSERT(seen[k], "%s: the .expect has no %s line", name, KEYS[k]);
    }
    free(s);
    free(x);
}

static unsigned long fz_replay_dir(const char *dir, const char *sub)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", dir, sub);
    DIR *d = opendir(path);
    unsigned long files = 0;
    if (d == NULL) {
        return 0;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 8 || strcmp(de->d_name + l - 7, ".policy") != 0) {
            continue;
        }
        char file[2304];
        snprintf(file, sizeof file, "%s/%s", path, de->d_name);
        size_t n;
        uint8_t *b = fz_read(file, &n);
        if (b == NULL) {
            continue;
        }
        files++;
        static fz_config_t c;
        we_policy_error_t e;
        int refused = 0;
        FZ_ASSERT(fz_split(b, n, &c) == 0, "%s: the record framing does not parse", file);
        fz_one_config(&c, 0xFF, 0x00, &e, &refused);
        if (strcmp(sub, "accept") == 0) {
            FZ_ASSERT(!refused, "%s is refused: %s", file, e.what);
        } else if (strcmp(sub, "refuse") == 0) {
            char exp[2304];
            snprintf(exp, sizeof exp, "%.*s.expect", (int)(strlen(file) - 7), file);
            fz_expect(exp, &e, refused, file);
        }
        free(b);
    }
    closedir(d);
    return files;
}

int main(int argc, char **argv)
{
    if (argc != 7 || strcmp(argv[1], "--replay") != 0 || strcmp(argv[3], "--planes") != 0
        || strcmp(argv[5], "--floor") != 0) {
        fprintf(stderr, "usage: fuzz_policy --replay TESTDATA_DIR --planes PLANE_DIR --floor N\n");
        return 2;
    }
    char base[2048];
    snprintf(base, sizeof base, "%s/policy", argv[2]);
    g_nplanes = fz_load_planes(argv[4], &g_pl);
    FZ_ASSERT(g_nplanes == 8, "%d of 8 planes loaded from %s", g_nplanes, argv[4]);
    FZ_ASSERT(g_pl.naddr > 0, "no deciding addresses read from %s", argv[4]);
    unsigned long files = fz_replay_dir(base, "accept") + fz_replay_dir(base, "refuse") + fz_replay_dir(base, "seeds")
                          + fz_replay_dir(base, "adversarial");
    unsigned long floor = strtoul(argv[6], NULL, 10);
    FZ_ASSERT(files >= floor, "%lu policy files replayed, under the seed floor of %lu", files, floor);
    FZ_ASSERT(g_view_differ > 0, "no verdict over %lu evaluations differed between the real views and NULL views: "
              "the planes decided nothing", g_evals);
    printf("fuzz_policy replay: %lu files (floor %lu), %d planes, %zu addresses, %lu of %lu evaluations decided "
           "differently with the real views than with NULL views\n", files, floor, g_nplanes, g_pl.naddr,
           g_view_differ, g_evals);
    printf("%lu checks, %lu failures\n", g_checks, g_failures);
    return g_failures != 0 ? 1 : 0;
}
#endif /* FZ_LIBFUZZER */
