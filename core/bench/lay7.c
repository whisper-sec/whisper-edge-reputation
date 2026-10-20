/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * lay7.c - radix-k against rank-64s on the real routing table: exact counts, sampled streams, ns.
 *
 * Build:  cc -O2 -DFAM=4 lay7.c -o lay7-v4 ; cc -O2 -DFAM=6 lay7.c -o lay7-v6
 * Run:    ./lay7-vF <dir> [mode]
 *   counts   every hardware-independent column, human-readable
 *   tsv      the same columns as tab-separated rows, which run-x86.sh compares with expected-counts.tsv
 *   time     serial ns per lookup, best of 5 (information only, never a gate)
 *   cg-<kind> [u|d] [n]   n lookups of one kind, for perf stat and cachegrind
 * <dir> holds v4.start + v4.rec16 or v6.start + v6.rec24, written by build7.py.
 *
 * The layout is the routing plane's: start[] as its own array and the range END inside the record
 * (16 bytes for IPv4, 24 for IPv6 at 64-bit keys). Every lookup is written ONCE (DEF below) and
 * instantiated twice, plain and with a read trace, so the counts come from the search that is timed
 * and not from a twin of it.
 *
 * WHAT IS HARDWARE-INDEPENDENT, and why. Every array is 4096-byte aligned, so the line and page each
 * read falls on depends only on the index into the array; the address streams come from one xorshift
 * generator with a fixed seed; the percentiles are computed in integers. So the probe, line, page and
 * percentile columns must come out identical on any 64-bit host, and run-x86.sh fails if they do not.
 * The ns column moves with the machine and is printed, never compared.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if FAM == 4
typedef uint32_t K; enum { W = 32 }; static const char *FN_START = "v4.start", *FN_REC = "v4.rec16"; static unsigned RS = 16;
#else
typedef uint64_t K; enum { W = 64 }; static const char *FN_START = "v6.start", *FN_REC = "v6.rec24"; static unsigned RS = 24;
#endif
static uint32_t n; static K *st; static uint8_t *rec;
static uint32_t *ix; static unsigned kbits;          /* radix-k */
static K *samp; static uint32_t ns_, SS;             /* rank-s */
enum { BK = 64 / sizeof(K) };                        /* keys per 64-byte node */
typedef struct { K k[BK]; } __attribute__((aligned(64))) node_t;
static node_t *bt; static uint32_t (*bti)[BK]; static uint32_t nblk;  /* S-tree over samples + slot -> sample index */
static inline uint32_t blk(uint32_t k, uint32_t i) { return k * (BK + 1) + i + 1; }
static uint32_t bt_t_;
static void bt_build(uint32_t k) { if (k < nblk) { for (uint32_t i = 0; i < BK; i++) { bt_build(blk(k, i));
      if (bt_t_ < ns_) { bt[k].k[i] = samp[bt_t_]; bti[k][i] = bt_t_; bt_t_++; } else { bt[k].k[i] = (K)~(K)0; bti[k][i] = ns_; } }
    bt_build(blk(k, BK)); } }
static inline K rend(uint32_t i) { K e; memcpy(&e, rec + (size_t)i * RS, sizeof e); return e; }
/* ---- trace ---- */
enum { HOT = 0, COLD_S = 1, COLD_R = 2 };
typedef struct { uintptr_t a[96]; uint8_t c[96]; int na; int probes; } tr_t;
static inline void TRr(tr_t *t, const void *p, size_t len, int cls) { uintptr_t x = (uintptr_t)p, e = x + len - 1;
  for (uintptr_t y = x; ; y += 1) { if (t->na < 96) { t->a[t->na] = y; t->c[t->na] = (uint8_t)cls; t->na++; } if (y >= e) break; y = e - 1; } }
#define NOTR(p, l, c) ((void)0)
#define DOTR(p, l, c) TRr(tr, (p), (l), (c))
#define PR_N ((void)0)
#define PR_T (tr->probes++)
/* result: candidate index + 1 (0 = below first start); lookup then reads rec[r-1] */
#define DEF(SUF, TR, PR, ...)                                                                          \
static inline uint32_t radix##SUF(K a __VA_ARGS__) {                                                    \
  uint32_t b = (uint32_t)(a >> (W - kbits)); TR(&ix[b], 8, HOT); uint32_t lo = ix[b], hi = ix[b + 1];  \
  while (lo < hi) { uint32_t m = lo + ((hi - lo) >> 1); PR; TR(&st[m], sizeof(K), COLD_S);              \
    if (st[m] <= a) lo = m + 1; else hi = m; }                                                          \
  return lo; }
#define DEFB(SUF, TR, PR, ...)                                                                         \
static inline uint32_t stree##SUF(K a __VA_ARGS__) {                                                    \
  /* first sample > a, via the S-tree: one 64-byte node per level */                                    \
  uint32_t k = 0, rk = UINT32_MAX, ri = 0;                                                              \
  while (k < nblk) { TR(&bt[k], 64, HOT); uint32_t i = 0;                                               \
    for (uint32_t q = 0; q < BK; q++) { i += (bt[k].k[q] <= a); }                                         \
    PR;                                                                                                 \
    if (i < BK) { rk = k; ri = i; } k = blk(k, i); }                                                    \
  uint32_t lo; if (rk == UINT32_MAX) lo = ns_; else { TR(&bti[rk][ri], 4, HOT); lo = bti[rk][ri]; }     \
  if (!lo) { return 0; }                                                                                \
  uint32_t blo = (lo - 1) * SS, bhi = blo + SS; if (bhi > n) { bhi = n; }                               \
  lo = blo + 1; uint32_t hi = bhi;                                                                      \
  while (lo < hi) { uint32_t m = lo + ((hi - lo) >> 1); PR; TR(&st[m], sizeof(K), COLD_S);              \
    if (st[m] <= a) lo = m + 1; else hi = m; }                                                          \
  return lo; }
DEF(_p, NOTR, PR_N)
DEFB(_p, NOTR, PR_N)
DEFB(_t, DOTR, PR_T, , tr_t *tr)
DEF(_t, DOTR, PR_T, , tr_t *tr)
static int KIND; /* 0 radix, 2 rank-s (the S-tree) */
static inline uint32_t look_p(K a) { return KIND == 2 ? stree_p(a) : radix_p(a); }
static inline int full_p(K a) { uint32_t r = look_p(a); return r && rend(r - 1) >= a ? (int)r : 0; }
static void trace_full(K a, tr_t *tr) { tr->na = 0; tr->probes = 0; uint32_t r = KIND == 2 ? stree_t(a, tr) : radix_t(a, tr);
  if (r) TRr(tr, rec + (size_t)(r - 1) * RS, RS, COLD_R); }
typedef struct { int l64, l128, pg, cold64, cold128, coldpg, hot64, probes; } cnt_t;
static int distinct(const tr_t *t, int shift, int cls_mask) { uintptr_t u[96]; int k = 0;
  for (int i = 0; i < t->na; i++) { if (!((1 << t->c[i]) & cls_mask)) continue; uintptr_t y = t->a[i] >> shift; int f = 0;
    for (int j = 0; j < k; j++) { if (u[j] == y) { f = 1; break; } }
    if (!f) { u[k++] = y; } }
  return k; }
static cnt_t count(K a) { tr_t t; trace_full(a, &t); cnt_t c; int all = 7, cold = 6, hot = 1;
  c.l64 = distinct(&t, 6, all); c.l128 = distinct(&t, 7, all); c.pg = distinct(&t, 12, all);
  c.cold64 = distinct(&t, 6, cold); c.cold128 = distinct(&t, 7, cold); c.coldpg = distinct(&t, 12, cold);
  c.hot64 = distinct(&t, 6, hot); c.probes = t.probes; return c; }
/* ---- setup ---- */
static void *slurp(const char *d, const char *f, size_t *l) { char p[700]; snprintf(p, sizeof p, "%s/%s", d, f);
  FILE *fp = fopen(p, "rb"); if (!fp) { perror(p); exit(2); } fseek(fp, 0, SEEK_END); *l = (size_t)ftell(fp); fseek(fp, 0, SEEK_SET);
  void *b = aligned_alloc(4096, (*l + 4095) & ~4095ul); if (!b || fread(b, 1, *l, fp) != *l) exit(2); fclose(fp); return b; }
static void set_radix(unsigned k) { KIND = 0; kbits = k; free(ix); ix = aligned_alloc(4096, (((size_t)1 << k) * 4 + 4 + 4095) & ~4095ul);
  uint32_t cur = 0; for (uint64_t b = 0; b <= ((uint64_t)1 << k); b++) { while (cur < n && ((uint64_t)st[cur] >> (W - k)) < b) cur++; ix[b] = cur; } }
static void set_rank(uint32_t s) { SS = s; ns_ = (n + s - 1) / s; free(samp);
  samp = aligned_alloc(4096, ((size_t)ns_ * sizeof(K) + 4095) & ~4095ul); for (uint32_t j = 0; j < ns_; j++) samp[j] = st[(size_t)j * s]; }
static void set_stree(uint32_t s) { set_rank(s); KIND = 2; nblk = (ns_ + BK - 1) / BK; free(bt); free(bti);
  bt = aligned_alloc(4096, ((size_t)nblk * 64 + 4095) & ~4095ul); bti = aligned_alloc(4096, ((size_t)nblk * BK * 4 + 4095) & ~4095ul); bt_t_ = 0; bt_build(0); }
static size_t hot_bytes(void) { return KIND == 2 ? (size_t)nblk * 64 + (size_t)nblk * BK * 4 : (((size_t)1 << kbits) + 1) * 4; }
/* ---- exact enumeration over every outcome class: max, and the exact address-weighted distribution ---- */
#if FAM == 4
static const K DLO = 0, DHI = 0xffffffffu;               /* uniform over all of IPv4 */
#else
static const K DLO = 0x2000ull << 48, DHI = (0x4000ull << 48) - 1;  /* uniform over 2000::/3 */
#endif
/* Address weights are integers below 2^64, summed in 128 bits, and the percentile test is c * 100 >=
 * pct * total: no floating point, so x86 and aarch64 cannot round a boundary differently. */
typedef unsigned __int128 u128;
typedef struct { u128 w[40]; int mx; } hist_t;
static void hadd(hist_t *h, int v, u128 w) { if (v > 39) v = 39; h->w[v] += w; if (v > h->mx) h->mx = v; }
static int hq(const hist_t *h, unsigned pct) { u128 t = 0, c = 0; for (int i = 0; i < 40; i++) t += h->w[i];
  for (int i = 0; i < 40; i++) { c += h->w[i]; if (c * 100u >= (u128)pct * t && h->w[i] > 0) return i; } return h->mx; }
static void cls(K lo, K hi, hist_t *hc, hist_t *hl, hist_t *hp, hist_t *hpr, hist_t *hc128) {
  if (lo > hi) { return; }
  cnt_t c = count(lo); u128 w = 0;
  K a = lo > DLO ? lo : DLO, b = hi < DHI ? hi : DHI; if (a <= b) w = (u128)(b - a) + 1;
  hadd(hc, c.cold64, w); hadd(hl, c.l64, w); hadd(hp, c.pg, w); hadd(hpr, c.probes, w); hadd(hc128, c.cold128, w); }
typedef struct { int probes, cold64, cold128, all64, pages, ucold50, ucold99; } exact_t;
static exact_t exact(void) {
  hist_t hc = {0}, hl = {0}, hp = {0}, hpr = {0}, h128 = {0};
  if (KIND == 0) { int sh = W - (int)kbits;
    for (uint64_t b = 0; b < ((uint64_t)1 << kbits); b++) { uint32_t lo0 = ix[b], hi0 = ix[b + 1];
      K B0 = (K)(b << sh), B1 = (K)(((b + 1) << sh) - 1);
      for (uint32_t r = lo0; r <= hi0; r++) { K a = r > lo0 ? st[r - 1] : B0; K z = r < hi0 ? st[r] - 1 : B1;
        if (r == lo0 && hi0 > lo0 && st[lo0] == B0) { continue; }
        cls(a, z, &hc, &hl, &hp, &hpr, &h128); } }
  } else {
    if (st[0] > 0) cls(0, st[0] - 1, &hc, &hl, &hp, &hpr, &h128);
    for (uint32_t r = 1; r <= n; r++) cls(st[r - 1], r < n ? st[r] - 1 : (K)~(K)0, &hc, &hl, &hp, &hpr, &h128); }
  exact_t e = { hpr.mx, hc.mx, h128.mx, hl.mx, hp.mx, hq(&hc, 50), hq(&hc, 99) }; return e; }
/* ---- streams: one xorshift64 generator, seed 0x9e3779b97f4a7c15, pinned in expected-counts.tsv ---- */
#define SEED 0x9e3779b97f4a7c15ull
static uint64_t rs = SEED; static inline uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
#define N 4000000
static K *U, *D;
static void streams(void) { U = malloc(N * sizeof(K)); D = malloc(N * sizeof(K)); if (!U || !D) exit(2);
  for (int k = 0; k < N; k++) { U[k] = (K)(DLO + (rnd() % ((uint64_t)(DHI - DLO) + 1)));
    uint32_t i = (uint32_t)(rnd() % n); K e = rend(i); uint64_t w = (uint64_t)(e - st[i]) + 1; D[k] = st[i] + (K)(w ? rnd() % w : rnd()); } }
typedef struct { int c50, c99, cmax, l99; } samp_t;
static samp_t sampled(const K *src) { int h[40] = {0}, hl[40] = {0}, mx = 0;
  for (int k = 0; k < 1000000; k++) { cnt_t c = count(src[k]);
    h[c.cold64 > 39 ? 39 : c.cold64]++; hl[c.l64 > 39 ? 39 : c.l64]++; if (c.cold64 > mx) mx = c.cold64; }
  int c = 0, p50 = -1, p99 = -1, l99 = -1, cl = 0; for (int i = 0; i < 40; i++) { c += h[i]; cl += hl[i];
    if (p50 < 0 && c >= 500000) { p50 = i; }
    if (p99 < 0 && c >= 990000) { p99 = i; }
    if (l99 < 0 && cl >= 990000) { l99 = i; } }
  samp_t s = { p50, p99, mx, l99 }; return s; }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (double)t.tv_sec * 1e9 + (double)t.tv_nsec; }
static volatile uint32_t zero_v = 0; static volatile uint64_t sink;
static double serial(const K *a) { uint32_t z = zero_v, r = 0; uint64_t acc = 0; double t0 = now();
  for (int k = 0; k < N; k++) { int x = full_p(a[k] ^ (K)(r & z)); r = (uint32_t)x; acc += (uint64_t)x; }
  double t = (now() - t0) / N; sink = acc; return t; }
static void timed(const char *name) { double bu = 1e9, bd = 1e9;
  for (int rep = 0; rep < 5; rep++) { double u = serial(U), d = serial(D); if (u < bu) bu = u; if (d < bd) bd = d; }
  printf("IPv%d %-9s serial ns/lookup (best of 5, %s, information only): uniform %.1f  dense %.1f\n", FAM, name,
#if defined(__x86_64__)
    "x86_64",
#elif defined(__aarch64__)
    "aarch64",
#else
    "other",
#endif
    bu, bd); }
__attribute__((noinline)) uint64_t cgrun(const K *a, int cnt) { uint64_t acc = 0; uint32_t z = zero_v, r = 0;
  for (int k = 0; k < cnt; k++) { int x = full_p(a[k] ^ (K)(r & z)); r = (uint32_t)x; acc += (uint64_t)x; } return acc; }
typedef struct { const char *name; int kind; unsigned p; } kind_t;
static void setk(const kind_t *x) { if (x->kind == 2) set_stree(x->p); else set_radix(x->p); }
int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <dir> [counts|tsv|time|cg-<kind> [u|d] [n]]\n", argv[0]); return 2; }
  const char *d = argv[1], *mode = argc > 2 ? argv[2] : "counts"; size_t l;
  st = slurp(d, FN_START, &l); n = (uint32_t)(l / sizeof(K)); rec = slurp(d, FN_REC, &l); if (l / RS != n) { fprintf(stderr, "size mismatch\n"); return 2; }
  /* the three index kinds measured against each other, per family */
  kind_t ks[] = { {"radix-16", 0, 16}, {"radix-18", 0, 18}, {"rank-64s", 2, 64} };
  int nk = (int)(sizeof ks / sizeof ks[0]);
  streams();
  if (!strncmp(mode, "cg-", 3)) { const K *src = (argc > 3 && argv[3][0] == 'u') ? U : D;
    for (int i = 0; i < nk; i++) if (!strcmp(mode + 3, ks[i].name)) { setk(&ks[i]); sink = cgrun(src, argc > 4 ? atoi(argv[4]) : 1000000); return 0; }
    return 3; }
  /* agreement: every kind returns the reference binary search's answer, or nothing is reported */
  for (int i = 0; i < nk; i++) { setk(&ks[i]);
    for (int k = 0; k < N; k += 7) { K a = (k & 1) ? U[k] : D[k]; uint32_t lo = 0, hi = n; while (lo < hi) { uint32_t m = lo + ((hi - lo) >> 1); if (st[m] <= a) lo = m + 1; else hi = m; }
      if (look_p(a) != lo) { printf("DISAGREE %s at %d\n", ks[i].name, k); return 1; } } }
  if (!strcmp(mode, "time")) { for (int i = 0; i < nk; i++) { setk(&ks[i]); timed(ks[i].name); } return 0; }
  int tsv = !strcmp(mode, "tsv");
  if (!tsv && strcmp(mode, "counts")) { fprintf(stderr, "unknown mode %s\n", mode); return 2; }
  if (!tsv) printf("IPv%d routing: %u ranges, start[] %.2f MB, record %u B x n = %.2f MB\n", FAM, n, n * (double)sizeof(K) / 1e6, RS, n * (double)RS / 1e6);
  for (int i = 0; i < nk; i++) { setk(&ks[i]); exact_t e = exact(); samp_t su = sampled(U), sd = sampled(D);
    if (tsv) {
      printf("v%d\t%s\t%u\t%zu\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", FAM, ks[i].name, n, hot_bytes(),
             e.probes, e.cold64, e.cold128, e.all64, e.pages, e.ucold50, e.ucold99,
             su.c50, su.c99, su.cmax, su.l99, sd.c50, sd.c99, sd.cmax, sd.l99);
    } else {
      printf("  %-9s hot %7.1f KiB | EXACT over every outcome: probes max %2d | cold lines64 max %d (uniform p50 %d p99 %d)"
             " cold lines128 max %d | all lines64 max %d | pages4k max %d\n", ks[i].name, hot_bytes() / 1024.0, e.probes, e.cold64,
             e.ucold50, e.ucold99, e.cold128, e.all64, e.pages);
      printf("  %-9s uniform stream (1M sampled): cold lines64 p50 %d p99 %d max %d | all lines64 p99 %d\n", ks[i].name, su.c50, su.c99, su.cmax, su.l99);
      printf("  %-9s dense   stream (1M sampled): cold lines64 p50 %d p99 %d max %d | all lines64 p99 %d\n", ks[i].name, sd.c50, sd.c99, sd.cmax, sd.l99);
    } }
  return 0; }
