/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * race_core.c - the concurrency the core PROMISES, exercised.
 *
 * whisper_edge.h says one atomic pointer is what "lets the same core sit in an nginx worker, an
 * Apache prefork child and a thread without three different concurrency designs". The read side kept
 * that promise. The lifecycle side did not, and nothing here looked:
 *
 *   - the retire-slot CLAIM in we_handle_publish was a load-then-store, so two publishers could both
 *     see slot i empty and both store into it. The loser's mapping was overwritten: never unmapped,
 *     never counted in `leaked`. The design's leak is deliberate, bounded and counted; that one was
 *     unbounded and invisible.
 *   - the slot RECLAIM in we_handle_retire was a load-then-store-then-free, so two retirers could
 *     both read the same mapping, both pass the grace test, and both free it. A double free inside
 *     somebody else's web server.
 *
 * nginx cannot reach either (one thread per worker, one refresher), which is why they shipped. Apache
 * worker/event and LiteSpeed are threaded, so the shims for them could not be built on it as it stood.
 *
 * WHAT EACH TEST BELOW ACTUALLY PROVES. Stated precisely, because two of the four are decisive and
 * two are stress, and a reader who assumes all four are decisive is being misled by this file.
 *
 *   0. accounting, single-threaded  - DECISIVE AND DETERMINISTIC. Every mapping ever published is
 *      afterwards exactly one of: current, in a retire slot, or counted in `leaked`. A claim loop
 *      that loses a mapping fails this on every run, with no race needed.
 *
 *   1. the claim, concurrent        - STRESS, NOT DECISIVE, and measured to be so: with the CAS
 *      reverted to the old load-then-store this test still passed 200 rounds. The window is a few
 *      instructions at the tail of a function that spends ~100us validating a digest, so two
 *      publishers almost never arrive inside it. It is kept because it is the only thing that
 *      exercises publish from several threads at all, and the floor below makes a vacuous pass
 *      impossible; it is NOT evidence that the old code was reachable.
 *
 *   2. the reclaim, concurrent      - DECISIVE, and negative-controlled. With the reclaim CAS
 *      reverted this test aborts with glibc's "double free or corruption (!prev)". The window there
 *      is load, compare, store, close, free, which is wide enough to hit reliably.
 *
 *   3. readers against writers      - STRESS. It asserts no reader ever observes a torn severity
 *      byte while swaps and retirements run underneath, over about a billion lookups.
 *
 * WHETHER THE OLD CODE WAS REACHABLE IN WHAT WE SHIP: no, and this file should not pretend
 * otherwise. Both nginx and the Apache and LiteSpeed shims drive publish and retire from exactly ONE
 * refresher per process, so neither race could fire. The fix is here because whisper_edge.h makes an
 * UNCONDITIONAL promise that this core is safe "in a thread", and a shared core must not quietly
 * require its hosts to serialise. Either the code keeps the promise or the promise goes; the code is
 * two compare-exchanges, so the code keeps it.
 *
 * It is additionally built under -fsanitize=thread when the toolchain has it, which turns the stress
 * tests into direct data-race reports rather than consequences. The Makefile probes for that and
 * says which it ran.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>

#include "whisper_edge.h"
#include "we_sha256.h"

#define RACE_THREADS   8
#define RACE_SNAPSHOTS 64
#define RACE_ROUNDS    200

static int failures = 0;
static char dir[1024];

#define CHECK(cond, ...) do {                                                   \
        if (!(cond)) {                                                          \
            printf("  FAIL: "); printf(__VA_ARGS__); printf("\n");              \
            failures++;                                                         \
        }                                                                       \
    } while (0)

static const char *snap_path(int i)
{
    static char buf[RACE_SNAPSHOTS][1100];

    snprintf(buf[i], sizeof buf[i], "%s/race-%03d.snap", dir, i);
    return buf[i];
}

/*
 * A real snapshot, with the generation moved. Rather than re-implement the writer (which would be a
 * second definition of the format, and the one most likely to drift), this copies the fixture the
 * real builder produced, patches `generation`, and recomputes the digest exactly as the loader
 * will check it: SHA-256 over the file with the 32 digest bytes zeroed.
 */
static int make_snapshot(const char *src, const char *dst, uint64_t generation)
{
    FILE *f = fopen(src, "rb");
    long len;
    uint8_t *buf;
    we_header_t *h;
    size_t got;

    if (f == NULL) { return -1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    len = ftell(f);
    if (len < (long) sizeof(we_header_t)) { fclose(f); return -1; }
    rewind(f);
    buf = malloc((size_t) len);
    if (buf == NULL) { fclose(f); return -1; }
    got = fread(buf, 1, (size_t) len, f);
    fclose(f);
    if (got != (size_t) len) { free(buf); return -1; }

    h = (we_header_t *) buf;
    h->generation = generation;
    /* the file's validity must cover the test run; the fixture's own window may be in the past */
    h->valid_until_ms = 0xffffffffffffull;
    memset(h->digest, 0, sizeof h->digest);
    we_sha256(buf, (size_t) len, h->digest);

    f = fopen(dst, "wb");
    if (f == NULL) { free(buf); return -1; }
    got = fwrite(buf, 1, (size_t) len, f);
    fclose(f);
    free(buf);
    /*
     * 0644, EXPLICITLY. The loader refuses a group- or world-writable snapshot, which is the right
     * check (the digest is unkeyed, so whoever can write the file decides what a site blocks), and
     * the default umask on Debian and Ubuntu is 002, so fopen here produces 0664. Without this chmod
     * every publish below returns WE_ERR_PERMISSIONS, and the first version of this file PASSED on
     * that: loads_ok was 0 and the accounting identity held as 0 == 0. Hence the floor in
     * claim_race(), which is the assertion that makes a vacuous pass impossible.
     */
    if (chmod(dst, 0644) != 0) { return -1; }
    return (got == (size_t) len) ? 0 : -1;
}

/* ---------------------------------------------------------------------------------------------- */
/* 0. the accounting invariant, single-threaded and therefore decisive                              */
/* ---------------------------------------------------------------------------------------------- */

/*
 * No threads, no race, no luck. Publish more times than there are retire slots, with a grace long
 * enough that nothing is ever reclaimed, and require that every mapping is still accounted for.
 *
 * This is the test that would fail on EVERY run if the claim loop lost a mapping, which is what the
 * concurrent version below cannot promise. The exact numbers are asserted rather than a relation, so
 * a change to WE_RETIRE_SLOTS has to come here and be thought about.
 */
static void accounting_invariant(void)
{
    we_handle_t h;
    const int publishes = WE_RETIRE_SLOTS + 6;
    uint64_t occupied = 0;
    int i;

    printf("0. the accounting invariant, %d publications, nothing reclaimed\n", publishes);
    memset(&h, 0, sizeof h);
    h.grace_ms = 1000ull * 1000ull;
    for (i = 0; i < publishes; i++) {
        int rc = we_handle_publish(&h, snap_path(i), 1000ull);

        CHECK(rc == WE_OK, "publication %d of %d returned %s", i + 1, publishes, we_strerror(rc));
        if (failures > 0) { return; }
    }
    for (i = 0; i < WE_RETIRE_SLOTS; i++) {
        if (h.retired[i].map != NULL) { occupied++; }
    }
    CHECK(h.loads_ok == (uint64_t) publishes,
          "%" PRIu64 " of %d publications succeeded", h.loads_ok, publishes);
    CHECK(occupied == (uint64_t) WE_RETIRE_SLOTS,
          "%" PRIu64 " of %d retire slots are occupied; with no reclaim they must all be",
          occupied, WE_RETIRE_SLOTS);
    CHECK(h.leaked == (uint64_t) (publishes - WE_RETIRE_SLOTS - 1),
          "leaked is %" PRIu64 ", expected %d (every displaced mapping past the %d slots, with one"
          " still current)", h.leaked, publishes - WE_RETIRE_SLOTS - 1, WE_RETIRE_SLOTS);
    CHECK(we_current(&h) != NULL, "a mapping is still published");
    CHECK(occupied + h.leaked + 1u == h.loads_ok,
          "%" PRIu64 " published, %" PRIu64 " accounted for: a mapping was overwritten in a slot and"
          " can never be unmapped", h.loads_ok, occupied + h.leaked + 1u);

    we_handle_retire(&h, 1000ull + 2ull * 1000ull * 1000ull);
    {
        we_map_t *cur = (we_map_t *) we_current(&h);

        if (cur != NULL) { we_map_close(cur); free(cur); }
    }
    if (failures == 0) {
        printf("  ok: %d published, %d in slots, %" PRIu64 " leaked, 1 current, none lost\n",
               publishes, WE_RETIRE_SLOTS, h.leaked);
    }
}

/* ---------------------------------------------------------------------------------------------- */
/* 1. the claim race: two publishers must not both take one slot                                    */
/* ---------------------------------------------------------------------------------------------- */

typedef struct {
    we_handle_t *h;
    int          base;
    int          count;
} pub_arg_t;

static void *publisher(void *v)
{
    pub_arg_t *a = v;
    int i;

    for (i = 0; i < a->count; i++) {
        we_handle_publish(a->h, snap_path(a->base + i), 1000ull);
    }
    return NULL;
}

static void claim_race(void)
{
    int round;

    printf("1. the retire-slot CLAIM, %d threads publishing distinct generations\n", RACE_THREADS);
    for (round = 0; round < RACE_ROUNDS; round++) {
        we_handle_t h;
        pthread_t t[RACE_THREADS];
        pub_arg_t a[RACE_THREADS];
        uint64_t occupied = 0;
        uint64_t accounted;
        int i;

        memset(&h, 0, sizeof h);
        h.grace_ms = 1000ull * 1000ull;      /* nothing is ever reclaimed during the storm */
        for (i = 0; i < RACE_THREADS; i++) {
            a[i].h = &h;
            a[i].base = i * (RACE_SNAPSHOTS / RACE_THREADS);
            a[i].count = RACE_SNAPSHOTS / RACE_THREADS;
            pthread_create(&t[i], NULL, publisher, &a[i]);
        }
        for (i = 0; i < RACE_THREADS; i++) {
            pthread_join(t[i], NULL);
        }
        /*
         * Counted AFTER every publisher has been joined, which is what makes `map != NULL` mean "holds
         * a real mapping" here. Inside the concurrent window a slot can also hold WE_SLOT_RESERVED -
         * claimed, timestamp not yet written - and a reader that treated the sentinel as a mapping
         * would be reading address 1. Nothing in this file observes a slot mid-flight; a future edit
         * that wants to must test for the sentinel, as we_handle_retire does.
         */
        for (i = 0; i < WE_RETIRE_SLOTS; i++) {
            if (h.retired[i].map != NULL) { occupied++; }
        }
        /*
         * THE INVARIANT. Every mapping we successfully loaded is now current (exactly one), parked in
         * a retire slot, or counted in `leaked`. Nothing may simply disappear.
         */
        /*
         * THE FLOOR, first. An accounting identity is satisfied by two zeroes, so without this the
         * test passes when every publish failed - which is exactly what happened on its first run,
         * for a real reason (see the chmod above). A guard that can pass on absence is not a guard.
         */
        CHECK(h.loads_ok >= (uint64_t) WE_RETIRE_SLOTS + 1u,
              "round %d: only %" PRIu64 " publications succeeded (%" PRIu64 " failed), which cannot"
              " exercise %d retire slots. Nothing was proven.",
              round, h.loads_ok, h.loads_failed, WE_RETIRE_SLOTS);
        if (failures > 0) { return; }

        accounted = occupied + h.leaked + (we_current(&h) != NULL ? 1u : 0u);
        CHECK(accounted == h.loads_ok,
              "round %d: %" PRIu64 " mappings loaded but only %" PRIu64 " accounted for"
              " (%" PRIu64 " in slots, %" PRIu64 " leaked, %d current). The missing ones were"
              " overwritten in a slot by a second publisher and can never be unmapped.",
              round, h.loads_ok, accounted, occupied, h.leaked, we_current(&h) != NULL);

        /* drain, so the round does not hand its mappings to the next one */
        we_handle_retire(&h, 1000ull + 2ull * 1000ull * 1000ull);
        {
            we_map_t *cur = (we_map_t *) we_current(&h);

            if (cur != NULL) { we_map_close(cur); free(cur); }
        }
        if (failures > 0) { return; }
    }
    printf("  ok: %d rounds, every published mapping accounted for\n", RACE_ROUNDS);
}

/* ---------------------------------------------------------------------------------------------- */
/* 2. the reclaim race: two retirers must not both free one mapping                                 */
/* ---------------------------------------------------------------------------------------------- */

static we_handle_t *retire_target;
static uint64_t     retire_now;

static void *retirer(void *v)
{
    (void) v;
    we_handle_retire(retire_target, retire_now);
    return NULL;
}

static void reclaim_race(void)
{
    int round;

    printf("2. the slot RECLAIM, %d threads retiring the same mapping\n", RACE_THREADS);
    for (round = 0; round < RACE_ROUNDS; round++) {
        we_handle_t h;
        pthread_t t[RACE_THREADS];
        int i;

        memset(&h, 0, sizeof h);
        h.grace_ms = 10ull;
        /* two publishes, so the first mapping ends up in a retire slot */
        {
            int rc1 = we_handle_publish(&h, snap_path(0), 1000ull);
            int rc2 = we_handle_publish(&h, snap_path(1), 1000ull);

            if (rc1 != WE_OK || rc2 != WE_OK) {
                CHECK(0, "round %d: could not set up a retired mapping (%s / %s)",
                      round, we_strerror(rc1), we_strerror(rc2));
                return;
            }
        }
        retire_target = &h;
        retire_now = 1000ull + 1000ull;      /* well past the 10ms grace */

        for (i = 0; i < RACE_THREADS; i++) {
            pthread_create(&t[i], NULL, retirer, NULL);
        }
        for (i = 0; i < RACE_THREADS; i++) {
            pthread_join(t[i], NULL);
        }
        /*
         * Reaching here at all is most of the point: a double free aborts. The slot must also be
         * empty, so exactly one thread did the work rather than none.
         */
        for (i = 0; i < WE_RETIRE_SLOTS; i++) {
            CHECK(h.retired[i].map == NULL,
                  "round %d: slot %d still occupied after every retirer ran", round, i);
        }
        {
            we_map_t *cur = (we_map_t *) we_current(&h);

            if (cur != NULL) { we_map_close(cur); free(cur); }
        }
        if (failures > 0) { return; }
    }
    printf("  ok: %d rounds, exactly one reclaim per mapping and no double free\n", RACE_ROUNDS);
}

/* ---------------------------------------------------------------------------------------------- */
/* 3. the whole thing at once: readers, publishers and retirers on one handle                       */
/* ---------------------------------------------------------------------------------------------- */

/*
 * The readers' stop flag, and it is ATOMIC rather than `volatile int`.
 *
 * `volatile` orders nothing and promises nothing about concurrent access: a plain store from the
 * main thread read by eight reader threads is a data race by the letter of the standard, whatever
 * the generated code happens to do. ThreadSanitizer says so, and it is right.
 *
 * It was `volatile int` until the five edge gates were finally wired into CI, and the first enforced
 * run found this - because TSan does not work on the aarch64 box this was written on (it aborts with
 * "unexpected memory mapping" before instrumenting anything) and does work on the x86_64 runner. So
 * the sanitiser had never actually run over this file. A race in the harness whose whole job is to
 * prove the core has no races is not a thing to wave through, even when the race is in the harness.
 */
static _Atomic int    mixed_stop;
static we_handle_t    mixed_handle;
static volatile long  mixed_lookups;

static void *mixed_reader(void *v)
{
    uint32_t addr = (uint32_t) (uintptr_t) v;
    long n = 0;

    while (!atomic_load_explicit(&mixed_stop, memory_order_relaxed)) {
        const we_map_t *m = we_current(&mixed_handle);

        if (m != NULL) {
            uint8_t sev = we_lookup4(m, addr);

            /* a severity byte is a nibble plus two defined flags; anything else is a torn read */
            if ((sev & 0x30u) != 0u) {
                printf("  FAIL: lookup returned an impossible severity byte 0x%02x\n", sev);
                failures++;
                return NULL;
            }
            addr += 7919u;
            n++;
        }
    }
    __atomic_add_fetch(&mixed_lookups, n, __ATOMIC_RELAXED);
    return NULL;
}

static void *mixed_writer(void *v)
{
    int base = (int) (intptr_t) v;
    uint64_t now = 1000ull;
    int i;

    for (i = 0; i < RACE_SNAPSHOTS / 2; i++) {
        we_handle_publish(&mixed_handle, snap_path(base + (i % (RACE_SNAPSHOTS / 2))), now);
        we_handle_retire(&mixed_handle, now);
        now += 5ull;
    }
    return NULL;
}

static void mixed_race(void)
{
    pthread_t r[RACE_THREADS], w[2];
    int i;

    printf("3. readers, publishers and retirers together on one handle\n");
    memset(&mixed_handle, 0, sizeof mixed_handle);
    /*
     * A REALISTIC grace, not zero. The grace period IS the reader-safety mechanism: it exists because
     * a reader holds its pointer with no way for us to observe that it has finished. Setting it to
     * zero here would manufacture a use-after-free that the design openly does not defend against,
     * and prove nothing about the bug this file is for.
     */
    mixed_handle.grace_ms = 200ull;
    atomic_store_explicit(&mixed_stop, 0, memory_order_relaxed);

    for (i = 0; i < RACE_THREADS; i++) {
        pthread_create(&r[i], NULL, mixed_reader, (void *) (uintptr_t) (0x01020304u + i * 65537u));
    }
    for (i = 0; i < 2; i++) {
        pthread_create(&w[i], NULL, mixed_writer, (void *) (intptr_t) (i * (RACE_SNAPSHOTS / 2)));
    }
    for (i = 0; i < 2; i++) {
        pthread_join(w[i], NULL);
    }
    atomic_store_explicit(&mixed_stop, 1, memory_order_relaxed);
    for (i = 0; i < RACE_THREADS; i++) {
        pthread_join(r[i], NULL);
    }
    CHECK(mixed_lookups > 0, "the readers never saw a published mapping, so nothing was exercised");
    CHECK(mixed_handle.loads_ok > 0,
          "no publication succeeded (%" PRIu64 " failed), so no swap happened under the readers",
          mixed_handle.loads_failed);
    printf("  ok: %ld lookups against %" PRIu64 " publications with retirement running\n",
           mixed_lookups, mixed_handle.loads_ok);
}

int main(int argc, char **argv)
{
    const char *fixture = "testdata/interop.snap";
    int i;

    if (argc > 1) { snprintf(dir, sizeof dir, "%s", argv[1]); }
    else          { snprintf(dir, sizeof dir, "%s", "."); }
    if (argc > 2) { fixture = argv[2]; }

    printf("race_core: the lifecycle concurrency the header promises\n");
    for (i = 0; i < RACE_SNAPSHOTS; i++) {
        if (make_snapshot(fixture, snap_path(i), (uint64_t) (i + 1)) != 0) {
            printf("  FAIL: cannot build %s from %s\n", snap_path(i), fixture);
            return 1;
        }
    }
    accounting_invariant();
    if (failures == 0) { claim_race(); }
    if (failures == 0) { reclaim_race(); }
    if (failures == 0) { mixed_race(); }

    for (i = 0; i < RACE_SNAPSHOTS; i++) { unlink(snap_path(i)); }
    if (failures != 0) {
        printf("race_core: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("race_core: CLEAR\n");
    return 0;
}
