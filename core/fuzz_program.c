/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * fuzz_program - the verifier's fuzz harness (rows R2 and X4).
 *
 * A compiled program is a block the module arms after we_program_verify() accepts it. This harness takes
 * blocks the compiler produced from the corpus's accept files, mutates them, and holds one property: if
 * verify accepts a block, evaluating it is memory-safe. Every accepted block is run through
 * we_program_place() (a floor) and we_decide() under ASan, with the block copied into its own pages and
 * write-protected (so a store into it faults), the evaluation context placed flush against a PROT_NONE
 * guard page (so a write past *ctx faults), and every one of the eight planes a real, write-protected
 * view (fuzz_common.h says which fixtures), so the fill runs and each instruction's `off` reads a record.
 *
 * Plain byte flips mostly die at verify's opcode check (section 5.5 step 5), so most mutations are
 * made field by field, within each field's own domain, on the layout section 2.1 fixes: the 16-byte rule
 * record (action, flags, dep_mask, reserved, instr_start, instr_count, counter, src_off, src_len), the
 * 8-byte instruction (op one-hot u16, plane u8, off u8, imm u32), the 32-byte bindings entries, the
 * 16-byte set descriptors and their payloads, and the hold-harmless arrays (see fp_mutate for which
 * verifier step each group is aimed at). Under libFuzzer the same mutations are LLVMFuzzerCustomMutator; without a fuzzer
 * (`fuzz_program --replay DIR --planes PLANES --mutations N`) every accept file is compiled and mutated a pinned number of times from
 * the pinned xorshift seed, and the run prints how many mutants verify refused and how many it accepted
 * and were evaluated.
 *
 * Built only once the compiler exists (`make fuzz` says so by name until then). fuzz_common.h lists
 * every assumption about the compiler's types, the header's table offsets among them.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fuzz_common.h"

static unsigned long g_checks, g_failures, g_refused, g_accepted, g_evaluated, g_view_differ;
static uint64_t g_rs = 0x9e3779b97f4a7c15ull;   /* the pinned xorshift seed of POLICY.md */

static uint32_t rnd(void)
{
    g_rs ^= g_rs << 13;
    g_rs ^= g_rs >> 7;
    g_rs ^= g_rs << 17;
    return (uint32_t)(g_rs >> 32);
}

#define FP_ASSERT(cond, ...)                                                                    \
    do {                                                                                        \
        g_checks++;                                                                             \
        if (!(cond)) {                                                                          \
            g_failures++;                                                                       \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                                \
            fprintf(stderr, __VA_ARGS__);                                                       \
            fputc('\n', stderr);                                                                \
        }                                                                                       \
    } while (0)

/* ------------------------------------------------------------------------------------------------
 * Field-level mutation within each field's domain
 * ------------------------------------------------------------------------------------------------ */

static const uint16_t OPS[] = { 1u << 0, 1u << 1, 1u << 2, 1u << 3, 1u << 4, 1u << 5, 1u << 6, 1u << 7,
                                1u << 8, 1u << 9, 1u << 10, 1u << 11, 1u << 12, 1u << 13, 1u << 14 };

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* One field of one table, chosen by the header's offsets, changed within (or one past) its domain. The
 * groups and the verifier steps of section 5.5 they are aimed at:
 *   instructions  opcode, plane, off, imm, jump target                     steps 5 to 9, 11, 12
 *   rules         action, flags, dep_mask, instr range, src_off, src_len   steps 4, 13, 14, 16
 *   bindings[]    schema, strides, block offsets and width, the template   step 18
 *   sets          descriptor kind, flag, count, data_off; payload bytes    steps 10, 19
 *   hold-harmless the merged starts, ends and S-tree words                 step 20
 * and a plain byte flip anywhere, the control that mostly dies at step 5. */
static int fp_in(size_t off, size_t n, size_t len)
{
    return n > 0 && off <= len && n <= len - off;
}

static size_t fp_mutate(uint8_t *b, size_t len, size_t cap)
{
    (void)cap;
    if (len < sizeof(we_program_t)) {
        return len;
    }
    we_program_t h;
    memcpy(&h, b, sizeof h);
    uint32_t k = rnd() % 16u;
    if (k == 0u) {
        b[rnd() % len] ^= (uint8_t)(1u << (rnd() % 8u));
        return len;
    }
    if (k < 5u && fp_in(h.instrs_off, (size_t)h.instr_count * 8u, len)) {
        uint8_t *in = b + h.instrs_off + (size_t)(rnd() % h.instr_count) * 8u;
        switch (rnd() % 5u) {
        case 0: put16(in, OPS[rnd() % (sizeof OPS / sizeof OPS[0])]); break;   /* another one-hot opcode */
        case 1: in[2] = (uint8_t)(rnd() % 9u); break;                          /* plane 0..8, one past */
        case 2: in[3] = (uint8_t)(rnd() % 16u); break;                         /* off within and past a block */
        case 3: put32(in + 4, rnd() % 4u == 0 ? rnd() : rnd() % 64u); break;   /* imm: small, or any */
        default: put32(in + 4, (uint32_t)(rnd() % (h.instr_count + 2u))); break; /* a jump target */
        }
        return len;
    }
    if (k < 8u && fp_in(h.rules_off, (size_t)h.rule_count * 16u, len)) {
        uint8_t *r = b + h.rules_off + (size_t)(rnd() % h.rule_count) * 16u;
        switch (rnd() % 7u) {
        case 0: r[0] = (uint8_t)(rnd() % 4u); break;                           /* action, one past */
        case 1: r[2] = (uint8_t)rnd(); break;                                  /* dep_mask */
        case 2: put16(r + 4, (uint16_t)(rnd() % (h.instr_count + 2u))); break; /* instr_start */
        case 3: put16(r + 6, (uint16_t)(rnd() % (h.instr_count + 2u))); break; /* instr_count */
        case 4: put32(r + 10, (uint32_t)(h.text_len > 0 ? rnd() % (h.text_len + 2u) : rnd())); break; /* src_off */
        case 5: put16(r + 14, (uint16_t)(rnd() % 4096u)); break;               /* src_len */
        default: r[1] = (uint8_t)rnd(); break;                                 /* flags */
        }
        return len;
    }
    if (k < 10u && fp_in(h.bindings_off, 8u * 32u, len)) {
        uint8_t *bd = b + h.bindings_off + (size_t)(rnd() % 8u) * 32u;
        switch (rnd() % 6u) {
        case 0: bd[0] = (uint8_t)(rnd() % 4u); break;                          /* schema_id, one past */
        case 1: put16(bd + 1 + 2u * (rnd() % 2u), (uint16_t)(rnd() % 40u)); break; /* a record stride */
        case 2: bd[5 + rnd() % 2u] = (uint8_t)(rnd() % 40u); break;            /* a block offset */
        case 3: bd[7] = (uint8_t)(rnd() % 20u); break;                         /* block width */
        case 4: bd[9 + rnd() % 14u] = (uint8_t)rnd(); break;                   /* the no-range template */
        default: bd[23] = (uint8_t)(rnd() % 3u); break;                        /* inert_at_config */
        }
        return len;
    }
    if (k < 13u && h.set_count > 0 && fp_in(h.sets_off, (size_t)h.set_count * 16u, len)) {
        if (rnd() % 2u == 0 && fp_in(h.setdata_off, FZ_SETDATA_LEN(h), len)) {
            uint8_t *pd = b + h.setdata_off;                                    /* payload: a key or a bitmap byte */
            size_t at = rnd() % FZ_SETDATA_LEN(h);
            if (rnd() % 2u == 0 && at + 4u <= FZ_SETDATA_LEN(h)) {
                put32(pd + at, rnd() % 3u == 0 ? 0xFFFFFFFFu : rnd());
            } else {
                pd[at] ^= (uint8_t)(1u << (rnd() % 8u));
            }
            return len;
        }
        uint8_t *sd = b + h.sets_off + (size_t)(rnd() % h.set_count) * 16u;
        switch (rnd() % 4u) {
        case 0: sd[0] = (uint8_t)(rnd() % 5u); break;                          /* kind, one past */
        case 1: sd[1] = (uint8_t)(rnd() % 3u); break;                          /* has_undetermined */
        case 2: put32(sd + 4, rnd() % 600u); break;                            /* count, past 538 */
        default: put32(sd + 8, rnd() % (uint32_t)len); break;                  /* data_off */
        }
        return len;
    }
    if (fp_in(h.hh_off, FZ_HH_LEN(h), len) && FZ_HH_LEN(h) >= 4u) {
        uint8_t *hh = b + h.hh_off;                                             /* a start, an end, a tree word */
        size_t at = (rnd() % (FZ_HH_LEN(h) / 4u)) * 4u;
        switch (rnd() % 3u) {
        case 0: put32(hh + at, rnd()); break;
        case 1: put32(hh + at, 0xFFFFFFFFu); break;
        default: { uint32_t v; memcpy(&v, hh + at, 4); put32(hh + at, v + 1u); } break;  /* break the order */
        }
        return len;
    }
    b[rnd() % len] ^= 0x01u;
    return len;
}

/* ------------------------------------------------------------------------------------------------
 * Verify, then evaluate what verify accepts with the block read-only and *ctx against a guard page
 * ------------------------------------------------------------------------------------------------ */

static fz_planes_t g_pl;

/* Verify, then evaluate what verify accepts: the block copied onto its own pages and write-protected,
 * the context flush against a PROT_NONE page, every plane a real write-protected view (fuzz_common.h),
 * so the memo fill runs and every instruction's `off` is dereferenced against a real record. Each
 * accepted block is evaluated over the planes' deciding addresses with every view present, and once
 * with every view NULL. */
static void fp_check(const uint8_t *b, size_t len)
{
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t span = (len + pg - 1) / pg * pg;
    uint8_t *blk = mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (blk == MAP_FAILED) {
        return;
    }
    memcpy(blk, b, len);
    mprotect(blk, span, PROT_READ);
    const we_program_t *p = (const we_program_t *)blk;
    we_policy_error_t err;
    if (we_program_verify(p, len, &err) != 0) {
        g_refused++;
        munmap(blk, span);
        return;
    }
    g_accepted++;
    size_t csz = (sizeof(we_eval_ctx_t) + 63u) & ~(size_t)63u;
    size_t cspan = ((csz + pg - 1) / pg + 1) * pg;
    uint8_t *cmem = mmap(NULL, cspan, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (cmem == MAP_FAILED) {
        munmap(blk, span);
        return;
    }
    mprotect(cmem + cspan - pg, pg, PROT_NONE);
    we_eval_ctx_t *ec = (we_eval_ctx_t *)(cmem + cspan - pg - csz);
    we_hh_view_t hh;
    int placed = we_program_place(p, &hh) == 0;
    size_t step = g_pl.naddr > 16 ? g_pl.naddr / 16 : 1;
    for (size_t a = 0; a < g_pl.naddr; a += step) {
        for (uint8_t pass = 0; pass < 10; pass++) {
            we_request_t req;
            we_verdict_t real, none;
            size_t s2 = (a + g_pl.naddr / 2) % g_pl.naddr, srv = (pass & 1u) ? s2 : a;
            memset(&req, 0, sizeof req);
            we_addr_canon(g_pl.addr[a], g_pl.fam[a], &req.floor);
            we_addr_canon(g_pl.addr[srv], g_pl.fam[srv], &req.server);
            we_ctx_conf_t conf = { (uint8_t)(pass / 2u), 0 };
            memset(ec, 0, sizeof *ec);
            fz_views(ec, &g_pl, 0x00u);
            we_decide(placed ? p : NULL, &conf, p, &conf, placed ? &hh : NULL, &req, ec, 1800000000000ull, &real);
            memset(ec, 0, sizeof *ec);
            fz_views(ec, &g_pl, 0xFFu);
            we_decide(placed ? p : NULL, &conf, p, &conf, placed ? &hh : NULL, &req, ec, 1800000000000ull, &none);
            g_evaluated++;
            g_view_differ += (unsigned long)fz_verdicts_differ(&real, &none);
        }
    }
    munmap(cmem, cspan);
    munmap(blk, span);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int loaded;
    if (!loaded) {
        const char *dir = getenv("FZ_PLANES");
        if (fz_load_planes(dir != NULL ? dir : "planes", &g_pl) != 8 || g_pl.naddr == 0) {
            fprintf(stderr, "fuzz_program: the eight planes did not load from FZ_PLANES\n");
            abort();
        }
        loaded = 1;
    }
    if (size >= sizeof(we_program_t)) {
        fp_check(data, size);
    }
    return 0;
}

size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed)
{
    g_rs ^= (uint64_t)seed * 0x632BE59BD9B4E019ull;
    if (g_rs == 0) {
        g_rs = 1;
    }
    if (rnd() % 8u == 0) {
        return LLVMFuzzerMutate(data, size, max_size);
    }
    return fp_mutate(data, size, max_size);
}

#ifndef FZ_LIBFUZZER
/* Replay: compile each accept file's context programs, then mutate each block a pinned number of times. */
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size)
{
    (void)max_size;
    if (size > 0) {
        data[rnd() % size] ^= (uint8_t)(1u << (rnd() % 8u));
    }
    return size;
}

/* The first program a corpus file defines: its first context with policy lines, else its floor. */
static int fz_compile_policy_file(const char *path, we_program_t **out, size_t *len)
{
    static fz_config_t c;
    size_t n;
    uint8_t *b = fz_read(path, &n);
    if (b == NULL || fz_split(b, n, &c) != 0) {
        free(b);
        return -1;
    }
    const char *ctx = "http";
    int floor = 1;
    for (size_t i = 0; i < c.n; i++) {
        if (c.d[i].kind == WE_DIR_POLICY) {
            ctx = c.d[i].context;
            floor = 0;
            break;
        }
    }
    we_policy_source_t src = { c.d, c.n, ctx, floor };
    we_policy_env_t env = FZ_ENV(0xFFu, 0xFFu, 0u);
    we_policy_error_t err;
    int rc = we_policy_compile(&src, &env, &FZ_ALLOC, out, &err, NULL);
    if (rc == 0) {
        *len = we_program_size(*out);
    }
    free(b);
    return rc;
}

/* The libFuzzer seed corpus: the block each accept file compiles to, one file per block. */
static int fp_emit_seeds(const char *out_dir, const char *accept_dir)
{
    DIR *d = opendir(accept_dir);
    struct dirent *de;
    int n = 0;
    while (d != NULL && (de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 8 || strcmp(de->d_name + l - 7, ".policy") != 0) {
            continue;
        }
        char in[2048], out[2048];
        snprintf(in, sizeof in, "%s/%s", accept_dir, de->d_name);
        snprintf(out, sizeof out, "%s/%.*s.block", out_dir, (int)(l - 7), de->d_name);
        we_program_t *p = NULL;
        size_t len = 0;
        if (fz_compile_policy_file(in, &p, &len) != 0 || p == NULL) {
            fprintf(stderr, "FAIL %s does not compile\n", in);
            closedir(d);
            return 1;
        }
        FILE *f = fopen(out, "wb");
        if (f == NULL || fwrite(p, 1, len, f) != len) {
            fprintf(stderr, "FAIL cannot write %s\n", out);
            if (f != NULL) {
                fclose(f);
            }
            fz_free(NULL, p);
            closedir(d);
            return 1;
        }
        fclose(f);
        fz_free(NULL, p);
        n++;
    }
    if (d != NULL) {
        closedir(d);
    }
    printf("fuzz_program: %d seed blocks written to %s\n", n, out_dir);
    return n > 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "--emit-seeds") == 0) {
        return fp_emit_seeds(argv[2], argv[3]);
    }
    if (argc != 7 || strcmp(argv[1], "--replay") != 0 || strcmp(argv[3], "--planes") != 0
        || strcmp(argv[5], "--mutations") != 0) {
        fprintf(stderr, "usage: fuzz_program --replay ACCEPT_DIR --planes PLANE_DIR --mutations N\n"
                        "       fuzz_program --emit-seeds OUT_DIR ACCEPT_DIR\n");
        return 2;
    }
    int np = fz_load_planes(argv[4], &g_pl);
    FP_ASSERT(np == 8 && g_pl.naddr > 0, "%d of 8 planes and %zu addresses loaded from %s", np, g_pl.naddr, argv[4]);
    unsigned long per = strtoul(argv[6], NULL, 10), seeds = 0;
    DIR *d = opendir(argv[2]);
    FP_ASSERT(d != NULL, "no accept directory %s", argv[2]);
    struct dirent *de;
    while (d != NULL && (de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 8 || strcmp(de->d_name + l - 7, ".policy") != 0) {
            continue;
        }
        char path[2048];
        snprintf(path, sizeof path, "%s/%s", argv[2], de->d_name);
        we_program_t *p = NULL;
        size_t len = 0;
        FP_ASSERT(fz_compile_policy_file(path, &p, &len) == 0 && p != NULL, "%s does not compile", path);
        if (p == NULL) {
            continue;
        }
        seeds++;
        we_policy_error_t err;
        FP_ASSERT(we_program_verify(p, len, &err) == 0, "%s: the unmutated block fails verify", path);
        fp_check((const uint8_t *)p, len);
        uint8_t *m = malloc(len);
        for (unsigned long i = 0; m != NULL && i < per; i++) {
            memcpy(m, p, len);
            fp_mutate(m, len, len);
            fp_check(m, len);
        }
        free(m);
        fz_free(NULL, p);
    }
    if (d != NULL) {
        closedir(d);
    }
    FP_ASSERT(g_refused > 0, "verify refused none of the mutants: the harness is not reaching it");
    FP_ASSERT(g_evaluated > 0, "no accepted block was evaluated");
    FP_ASSERT(g_view_differ > 0, "no verdict over %lu evaluations differed between the real views and NULL views: "
              "the planes decided nothing", g_evaluated);
    printf("fuzz_program replay: %lu seeds x %lu mutations: verify refused %lu, accepted %lu, %lu evaluations "
           "under ASan, %lu of them decided differently with the real views than with NULL views\n", seeds, per,
           g_refused, g_accepted, g_evaluated, g_view_differ);
    printf("%lu checks, %lu failures\n", g_checks, g_failures);
    return g_failures != 0 ? 1 : 0;
}
#endif /* FZ_LIBFUZZER */
