/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/* SHA-256 (FIPS 180-4). Validated against the NIST vectors in test_core.c. */
#include "we_sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#ifdef WE_COUNT_DIGEST
uint64_t we_sha256_blocks;
#endif

static void block(uint32_t h[8], const uint8_t *p)
{
#ifdef WE_COUNT_DIGEST
    we_sha256_blocks++;
#endif
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16)
             | ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void we_sha256_init(we_sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                                   0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    memcpy(c->h, iv, sizeof iv);
    c->buflen = 0;
    c->total = 0;
}

#ifdef WE_LOOKUP_TOOL
/*
 * whisper-edge-lookup's own count of every byte hashed in its process, through the one definition every
 * digest goes through: the loader's whole-file check, the compiler's block interning, and the tool's
 * provenance digests. The tool states it on standard error, so a gate can hold it constant in the
 * number of addresses looked up. Compiled only into that tool; the core every module links has none.
 */
uint64_t we_lookup_hashed_bytes;
#endif

/*
 * A progress mark for a long digest, called once per MiB hashed by a single update, NULL for none. The
 * module installs its thread's progress mark here at the bind (we_mod_bind), so a verification that is
 * digesting a large plane is seen to make progress by the bounded stop, which abandons only a thread with
 * none. The request path never hashes, so nothing on it reads this.
 */
void (*volatile we_sha256_progress)(void);

void we_sha256_update(we_sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    void (*mark)(void) = we_sha256_progress;
    uint32_t k = 0u;

#ifdef WE_LOOKUP_TOOL
    we_lookup_hashed_bytes += len;
#endif
    c->total += len;
    if (c->buflen > 0) {
        size_t want = 64 - c->buflen;
        size_t take = (len < want) ? len : want;

        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen < 64) {
            return;
        }
        block(c->h, c->buf);
        c->buflen = 0;
    }
    while (len >= 64) {
        block(c->h, p);
        p += 64;
        len -= 64;
        if (++k == 16384u) {                     /* 1 MiB of blocks */
            k = 0u;
            if (mark != NULL) {
                mark();
            }
        }
    }
    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void we_sha256_final(we_sha256_ctx *c, uint8_t out[32])
{
    uint8_t tail[128];
    uint64_t bits = c->total * 8ull;
    size_t n = c->buflen, t;
    int i;

    memcpy(tail, c->buf, n);
    tail[n++] = 0x80;
    t = (n <= 56) ? 64 : 128;
    memset(tail + n, 0, t - n);
    for (i = 0; i < 8; i++) {
        tail[t - 1 - (size_t)i] = (uint8_t)(bits >> (8 * i));
    }
    block(c->h, tail);
    if (t == 128) {
        block(c->h, tail + 64);
    }
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }
}

void we_sha256(const void *data, size_t len, uint8_t out[32])
{
    we_sha256_ctx c;

    we_sha256_init(&c);
    we_sha256_update(&c, data, len);
    we_sha256_final(&c, out);
}
