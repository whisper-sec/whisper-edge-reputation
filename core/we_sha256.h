/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * we_sha256.h - SHA-256, so the core has no dependencies at all.
 *
 * WHY NOT OpenSSL. This code is compiled into somebody else's nginx, which already links an SSL
 * library - but WHICH one, and which version, and with which symbol visibility, is not ours to decide.
 * A reputation feed that fails to build against BoringSSL, or that picks up a different EVP ABI at
 * runtime than it compiled against, is a feed nobody deploys. A hundred lines of well-tested hash code
 * costs less than that compatibility surface.
 *
 * WHAT THE HASH IS AND IS NOT, stated carefully because the first version of this paragraph was not
 * true and would have been published.
 *
 * This is an INTEGRITY check. It catches the failure modes that actually happen to a file on disk - a
 * truncated download, a partial write, a corrupt page, a half-copied snapshot - and it catches them
 * before the buffer is published rather than as a wrong answer later.
 *
 * It is NOT proof of origin, and nothing here makes it one. The hash is unkeyed, so anyone who can
 * rewrite the file can rewrite the hash with it. That matters concretely: on shared hosting, "another
 * tenant can write that path" is a live threat model, and whoever can write the snapshot decides whom
 * the site blocks. The install guide therefore has to require the file be root-owned and not
 * group- or world-writable, and the loader refuses a writable one.
 *
 *
 * So: what ships is an integrity digest, and that is all this file claims. Each authenticity mechanism
 * gets a sentence here on the commit that implements it, and not before.
 */
#ifndef WE_SHA256_H
#define WE_SHA256_H
#include <stdint.h>
#include <stddef.h>
/*
 * Incremental, so the loader can hash a header with the digest field zeroed followed by the mapped
 * body WITHOUT copying the file. The one-shot form was the first version; it needed a transient
 * malloc the size of the snapshot (up to 16 MB) at every load, which is a real cost at cold start for
 * no benefit. Streaming it costs twenty lines.
 */
typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    size_t   buflen;
    uint64_t total;
} we_sha256_ctx;

void we_sha256_init(we_sha256_ctx *c);
void we_sha256_update(we_sha256_ctx *c, const void *data, size_t len);
void we_sha256_final(we_sha256_ctx *c, uint8_t out[32]);

/* Called once per MiB a single update hashes, when set (the module sets its progress mark; see we_sha256.c). */
extern void (*volatile we_sha256_progress)(void);

/* One-shot convenience, for tests and small buffers. */
void we_sha256(const void *data, size_t len, uint8_t out[32]);

#ifdef WE_LOOKUP_TOOL
/* whisper-edge-lookup only: every byte through we_sha256_update in this process (we_sha256.c). */
extern uint64_t we_lookup_hashed_bytes;
#endif
#ifdef WE_COUNT_DIGEST
/* test_core's build alone: the compression blocks run since the caller zeroed it, the deterministic
 * measure of verification work (one pass over `n` bytes is ceil((n + 9) / 64) blocks) */
extern uint64_t we_sha256_blocks;
#endif
#endif
