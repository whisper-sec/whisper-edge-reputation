/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 *
 * This file is designed to be COPIED into your build. The notice above is here because it will be:
 * a vendored file with no notice is a file whose licence is unknowable at the point somebody's legal
 * review asks, which is the one place that stops an adoption. The full text is in LICENSE.
 */
/*
 * whisper_edge.h - the edge reputation lookup.
 *
 * THE VERDICT costs one acquire load of a pointer and a short binary search inside a read-only
 * buffer: no syscall, no lock, no allocation. That is the claim core/hotpath-gate.sh certifies
 * by disassembling the compiled lookup, and it is deliberately narrower than "the request path makes
 * no syscall" - which is what an earlier version of the nginx shim's header said and which is not
 * true of the log line or of the $whisper_edge_verdict variable. A log line costs what any nginx log
 * line costs; the gate does not see the handler, so the comment must not claim for it.
 *
 *  *
 * WHY THERE IS NO TRIE IN HERE. A longest-prefix-match trie is the obvious structure and we resolve
 * LPM at BUILD time instead: every prefix becomes an interval, nesting resolves by MOST-SPECIFIC-WINS
 * - true longest-prefix match, the semantic every operator already expects - and what ships is a
 * SORTED SET OF DISJOINT RANGES. A /8 at LOW containing a /24 at CRITICAL becomes three adjacent
 * ranges each already carrying the right answer. So the edge never walks a prefix hierarchy: for any
 * address there is exactly one range that can contain it, and finding it is a binary search.
 *
 * (This paragraph said "most severe verdict" for a while, which is wrong and is the one semantic the
 * safety rules depend on: most-severe makes a carve-out inexpressible, so a more specific exemption
 * inside a bad aggregate could not be honoured. It is most-specific-wins, and this is the file an
 * integrator reads first, which is the right place to be fussy about it.)
 *
 * That is a better split of work, not a cleverer structure. The builder is a service with graph access
 * and a test suite; this code runs inside somebody else's nginx and must never be the thing that
 * breaks. Complexity belongs where it is paid once.
 *
 * It is also easier to prove: "the ranges are sorted, disjoint and in bounds" is checkable over the
 * whole file in one pass, which we do at load. "Did the trie resolve this overlap correctly" has no
 * such closed form.
 *
 * FAIL OPEN IS A TYPE INVARIANT HERE, not a policy applied by callers. Severity 0 means allow, an
 * absent mapping means allow, and every error path in the loader yields a mapping that answers 0 for
 * every address. A blocking module that fails closed takes a customer's site down and ends the
 * experiment , so there is no code path in this file that can deny on missing or bad data.
 */
#ifndef WHISPER_EDGE_H
#define WHISPER_EDGE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>   /* memcpy, used by the v6 address load on the hot path */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The hot-path functions are FORCE-inlined, not merely marked inline.
 *
 * `static inline` is a request, and at -Os a compiler reasonably declines it: measured, the lookup
 * became an out-of-line tail call (`b <we_lookup4>`), which is a real call on the request path. -Os is
 * not exotic - it is the default on Alpine and OpenWrt, which is exactly the small-host population
 * this is aimed at. And the gate missed it twice over, because a tail call is neither a
 * branch-and-link nor an undefined symbol.
 *
 * The honest fix is to make the claim true rather than to narrow it: if the comment says the lookup is
 * inlined into the caller, the attribute should say so too. The gate now also sweeps -O, -O2 and -Os.
 */
#if defined(__GNUC__) || defined(__clang__)
#define WE_HOT_INLINE static inline __attribute__((always_inline))
#else
#define WE_HOT_INLINE static inline
#endif

/*
 * The rank searches' descent runs a few levels at most (the S-tree's depth, 1 to 3 for any file the
 * loader arms), so unrolling it buys nothing. clang unrolls it by four anyway under some tunings, and
 * the unrolled body needs a register more than the evaluator leaves it: measured on x86_64, 8 bytes
 * spilled in hpfloor under -mtune=znver3 and znver4 (clang 18 to 20), 8 more in hpeval, hpeval_ops,
 * hpfill4 and hpfill1 under znver3 (clang 19, 20), and 8 in hpeval and hpeval_ops under clang 20 with
 * -march=x86-64-v3 or haswell. Asked not to unroll, it holds every one of those at 0. Other compilers
 * ignore the hint.
 */
#if defined(__clang__)
#define WE_NO_UNROLL _Pragma("clang loop unroll(disable)")
#else
#define WE_NO_UNROLL
#endif

/* Byte-swap a 64-bit word. The builtin inlines to one instruction; the fallback is for a compiler
 * that has neither, and is still branch-free. */
#if defined(__GNUC__) || defined(__clang__)
#define we_bswap64(x) __builtin_bswap64(x)
#else
WE_HOT_INLINE uint64_t we_bswap64(uint64_t v)
{
    return ((v & 0x00000000000000ffull) << 56) | ((v & 0x000000000000ff00ull) << 40)
         | ((v & 0x0000000000ff0000ull) << 24) | ((v & 0x00000000ff000000ull) << 8)
         | ((v & 0x000000ff00000000ull) >> 8)  | ((v & 0x0000ff0000000000ull) >> 24)
         | ((v & 0x00ff000000000000ull) >> 40) | ((v & 0xff00000000000000ull) >> 56);
}
#endif

/* Severity, low nibble. Ordered, so a threshold is a comparison. */
#define WE_SEV_NONE      0u
#define WE_SEV_LOW       1u
#define WE_SEV_MEDIUM    2u
#define WE_SEV_HIGH      3u
#define WE_SEV_CRITICAL  4u
#define WE_SEV_MASK      0x0fu

/*
 * High nibble, flags on the verdict itself.
 *
 * WE_F_INFERRED marks a verdict with no citable listing behind it: density, a pattern, a prefix we
 * believe is bad but cannot cite. Those are never enforced by default, because the promise this feed
 * rests on is that a block can be explained in one sentence to the operator whose traffic was dropped,
 * and an inference cannot be. The flag travels WITH the entry rather than being applied at build time,
 * so the decision cannot be lost in somebody's configuration.
 */
#define WE_F_INFERRED    0x80u
#define WE_F_DROP        0x40u   /* on the Spamhaus DROP list: the strongest evidence we carry */

/*
 * File layout, LITTLE-ENDIAN throughout, including the 128-bit IPv6 bounds.
 *
 * That is a deliberate choice and not an oversight: the v6 range arrays are read with a NATIVE
 * __uint128_t load on the hot path, so the file holds the native little-endian representation rather
 * than network order. An IPv6 ADDRESS arriving from a socket is of course network order, and
 * we_lookup6() converts it with an explicit byte walk - the conversion is of the address, never of the
 * stored bounds. Getting that distinction wrong is invisible to a C-only test, because a C fixture
 * writer memcpy's a native value and agrees with the reader while the format silently depends on the
 * host; it is caught by core/interop-gate.sh, which has an independent implementation produce the file.
 *
 * A big-endian target therefore needs byte-swapping that is not written, so say so at BUILD time rather
 * than misread every snapshot at run time.
 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) \
        && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the whisper edge snapshot format is little-endian; a big-endian reader needs byte-swapping that is not implemented here"
#endif

#define WE_MAGIC         0x31504e5347444557ull  /* "WEDGSNP1" */

/*
 * TWO FORMATS, ONE CONTAINER. FORMAT.md is the byte-exact contract; where this header and
 * that file could disagree, that file wins.
 *
 * Format 1 is the shipped layout and is used by exactly one plane, `reputation`: start[], end[],
 * sev[], meta[] and, when flagged, the 65,537-entry radix-16 index. Format 2 is every other plane:
 * no end[] and no sev[], the range end is the first field of a per-range RECORD, and the index is
 * radix-k or rank-s as the schema tail says. A reader built before format 2 refuses a format-2 file
 * with WE_ERR_FORMAT, which is the clean refusal an operator who points a legacy directive at
 * routing.bin should get, and we_map_open() keeps exactly that contract (see we_plane_open()).
 *
 * WE_FORMAT keeps its name and its value because every writer before format 2 uses it.
 */
#define WE_FORMAT        1u
#define WE_FORMAT_1      1u
#define WE_FORMAT_2      2u

/* Header flags. A reader ignores bits it does not know, which is the compatibility mechanism. */
#define WE_H_V4_INDEXED  0x0001u  /* format 1: the 65,537-entry radix-16 table; format 2: radix-k */
#define WE_H_V6_INDEXED  0x0002u
#define WE_H_SCHEMA      0x0004u  /* the 56-byte tail at offset 136 describes the plane (FORMAT.md §2) */

/* plane_id, FORMAT.md §2. The id must match the installed file's base name. */
#define WE_PLANE_REPUTATION       1u
#define WE_PLANE_TOR              2u
#define WE_PLANE_RPKI_UNREACHABLE 3u
#define WE_PLANE_ROUTING          4u
#define WE_PLANE_ANONYMIZER       5u
#define WE_PLANE_THREAT           6u
#define WE_PLANE_REGISTRY         7u
#define WE_PLANE_TENANT           8u
#define WE_PLANE_MAX              8u

/* schema_id */
#define WE_SCHEMA_FORMAT1    0u   /* the format-1 layout, reputation only */
#define WE_SCHEMA_ROUTING    1u   /* routing, registry: we_route4_t / we_route6_t */
#define WE_SCHEMA_MEMBERSHIP 2u   /* tor, rpki-unreachable, anonymizer, threat, tenant */

/*
 * Index kinds. NONE is a legal value in the file (the whole array is the window); the loader folds it
 * into the radix arm with a one-bucket table, so the lookup keeps exactly two arms.
 */
#define WE_KIND_NONE   0u
#define WE_KIND_RADIX  1u
#define WE_KIND_RANK   2u

/*
 * A static assertion that also works where C11 is not on: the module is compiled with flags we do not
 * choose, and a layout check that silently vanishes under -std=gnu99 is not a check.
 */
#if defined(__cplusplus) && __cplusplus >= 201103L
#define WE_STATIC_ASSERT(c, msg) static_assert(c, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define WE_STATIC_ASSERT(c, msg) _Static_assert(c, msg)
#else
#define WE_SA_CAT_(a, b) a##b
#define WE_SA_CAT(a, b)  WE_SA_CAT_(a, b)
#define WE_STATIC_ASSERT(c, msg) typedef char WE_SA_CAT(we_static_assert_, __LINE__)[(c) ? 1 : -1]
#endif

/*
 * The schema tail: 56 bytes at offset 136, valid only when WE_H_SCHEMA is set. Every field that does
 * not apply to a plane is zero, and the loader refuses one that is not. Field by field in FORMAT.md §2.
 */
typedef struct {
    uint8_t  plane_id;               /* 136 */
    uint8_t  schema_id;              /* 137 */
    uint8_t  v4_key_bits;            /* 138: 32 */
    uint8_t  v6_key_bits;            /* 139: 64 (routing, registry) or 128 */
    uint8_t  v4_index_kind;          /* 140: WE_KIND_* */
    uint8_t  v4_index_param;         /* 141: radix k, or log2 of the rank stride */
    uint8_t  v6_index_kind;          /* 142 */
    uint8_t  v6_index_param;         /* 143 */
    uint16_t v4_record_stride;       /* 144 */
    uint16_t v6_record_stride;       /* 146 */
    uint32_t v4_record_off;          /* 148: 64-byte aligned */
    uint32_t v6_record_off;          /* 152 */
    uint32_t v4_sample_off;          /* 156: rank only, the S-tree, 64-byte aligned */
    uint32_t v6_sample_off;          /* 160 */
    uint32_t v4_sample_count;        /* 164: rank only, m = ceil(n / stride) windows */
    uint32_t v6_sample_count;        /* 168 */
    uint16_t country_table_version;  /* 172: YYYYMM mod 65536 of the ISO 3166-1 table the builder used */
    uint8_t  v4_depth;               /* 174: rank only, the S-tree depth the builder computed */
    uint8_t  v6_depth;               /* 175 */
    uint8_t  reserved[16];           /* 176: zero */
} we_schema_t;

/*
 * The on-disk header. Exactly 192 bytes: three cache lines, 16-byte aligned so the v6 arrays that
 * follow it can be __uint128_t-aligned without padding games. Every offset is a byte offset from the
 * start of the file, so the mapping is usable in place with no parse step and no allocation.
 *
 * The reserved tail is deliberate headroom. A format 2 that needs another counter or offset adds it
 * there and every existing field keeps its position, which means a snapshot and a reader can be
 * upgraded in either order. The size is asserted below rather than described in a comment, because a
 * comment claiming a layout does not stop a compiler from choosing a different one - the first draft
 * of this struct said 128 bytes and was 152.
 */
typedef struct {
    uint64_t magic;
    uint32_t format;
    uint32_t flags;
    uint64_t generation;     /* monotonic; a worker detects a swap by comparing this, no coordination */
    uint64_t built_at_ms;
    uint64_t valid_until_ms; /* the staleness bound travels IN the file, see we_is_stale() */
    uint32_t tier;
    uint32_t v4_count;
    uint32_t v6_count;
    uint32_t v4_index_off;
    uint32_t v4_start_off;
    uint32_t v4_end_off;
    uint32_t v4_sev_off;
    uint32_t v4_meta_off;
    uint32_t v6_index_off;
    uint32_t v6_start_off;
    uint32_t v6_end_off;
    uint32_t v6_sev_off;
    uint32_t v6_meta_off;
    uint32_t blob_off;       /* evidence strings: SBL id, abuse contact. NOT on the hot path. */
    uint32_t blob_len;
    uint32_t file_len;
    /*
     * The content digest: SHA-256 over this header with these 32 bytes zeroed, followed by the body.
     *
     * NAMED digest, not sig, and WE_ERR_DIGEST, not WE_ERR_SIGNATURE. It is an unkeyed hash, so it is
     * an INTEGRITY check and not proof of origin; the old names invited exactly the misreading the
     * comment in we_sha256.h is careful to avoid. Renamed now, while the format is unreleased - after
     * publication a field name is a permanent contract.
     */
    uint8_t  digest[32];
    we_schema_t schema;      /* zero in a pre-schema format-1 file; see WE_H_SCHEMA */
} we_header_t;

/*
 * The format is a contract with a file on disk, so the layout is enforced, not hoped for. If a
 * compiler or ABI ever lays this out differently the BUILD fails here, rather than the reader quietly
 * misinterpreting every offset in a snapshot a different machine wrote.
 */
WE_STATIC_ASSERT(sizeof(we_header_t) == 192, "we_header_t must be exactly 192 bytes on the wire");
WE_STATIC_ASSERT(sizeof(__uint128_t) == 16, "v6 ranges assume a 16-byte __uint128_t");
WE_STATIC_ASSERT(offsetof(we_header_t, digest) == 104, "the digest is at 104");
WE_STATIC_ASSERT(sizeof(we_schema_t) == 56, "the schema tail is 56 bytes");
WE_STATIC_ASSERT(offsetof(we_header_t, schema) == 136, "the schema tail starts at offset 136");
#define WE_TAIL_AT(f, at) \
    WE_STATIC_ASSERT(offsetof(we_header_t, schema) + offsetof(we_schema_t, f) == (at), #f " is at " #at)
WE_TAIL_AT(plane_id, 136);
WE_TAIL_AT(schema_id, 137);
WE_TAIL_AT(v4_key_bits, 138);
WE_TAIL_AT(v6_key_bits, 139);
WE_TAIL_AT(v4_index_kind, 140);
WE_TAIL_AT(v4_index_param, 141);
WE_TAIL_AT(v6_index_kind, 142);
WE_TAIL_AT(v6_index_param, 143);
WE_TAIL_AT(v4_record_stride, 144);
WE_TAIL_AT(v6_record_stride, 146);
WE_TAIL_AT(v4_record_off, 148);
WE_TAIL_AT(v6_record_off, 152);
WE_TAIL_AT(v4_sample_off, 156);
WE_TAIL_AT(v6_sample_off, 160);
WE_TAIL_AT(v4_sample_count, 164);
WE_TAIL_AT(v6_sample_count, 168);
WE_TAIL_AT(country_table_version, 172);
WE_TAIL_AT(v4_depth, 174);
WE_TAIL_AT(v6_depth, 175);
WE_TAIL_AT(reserved, 176);
#undef WE_TAIL_AT

/*
 * ---- Format-2 records, FORMAT.md §3 ----
 *
 * One record per range at record_off + i * stride, the range's inclusive END first. Every enumerated
 * field has an `undetermined` sentinel, and the loader refuses any value outside its domain and names
 * the record, because a value past the end of a name table is a read past the end on the request path.
 * Reserved bytes and bits are zero.
 *
 * NOT __attribute__((packed)), deliberately, although packing is the usual way to pin a wire layout.
 * The natural layout of each struct below has no padding, and the assertions prove it field by field;
 * the record column is 64-byte aligned and every stride is a multiple of the struct's alignment, so
 * every field is naturally aligned in the file and the hot path's `end` read is one native load.
 * Packing would pin nothing the assertions do not already pin, and it would take the alignment away
 * from the compiler, which may then split the u64 and u128 end loads.
 */
typedef struct {
    uint32_t end;          /* 0: inclusive end */
    uint32_t asn;          /* 4: origin AS; 0xFFFFFFFF undetermined (RFC 7300); 0 is AS0 (RFC 7607) */
    uint16_t country;      /* 8: ISO 3166-1 numeric; 0 undetermined; above 999 refused */
    uint8_t  rov;          /* 10: WE_ROV_* */
    uint8_t  rir;          /* 11: WE_RIR_* */
    uint8_t  flags;        /* 12: WE_RF_*; `narrowed` is IPv6 only, so bits 2..7 are zero here */
    uint8_t  asn_rep;      /* 13: WE_REP_* */
    uint16_t reserved;     /* 14: zero */
} we_route4_t;

typedef struct {
    uint64_t end;          /* 0: the top 64 bits of the inclusive end */
    uint32_t asn;          /* 8 */
    uint16_t country;      /* 12 */
    uint8_t  rov;          /* 14 */
    uint8_t  rir;          /* 15 */
    uint8_t  flags;        /* 16: bits 3..7 zero */
    uint8_t  asn_rep;      /* 17 */
    uint8_t  reserved[6];  /* 18..23: zero */
} we_route6_t;

typedef struct {
    uint32_t end;          /* 0 */
    uint32_t flags;        /* 4: the plane's attribute bits, WE_MF_*; undefined bits zero */
    uint8_t  source;       /* 8: index into the blob's feed-name table; 0 none */
    uint8_t  reason;       /* 9: rpki-unreachable only, WE_REASON_*; 0 on every other plane */
    uint8_t  reserved[6];  /* 10..15: zero */
} we_member4_t;

typedef struct {
    __uint128_t end;       /* 0 */
    uint32_t flags;        /* 16 */
    uint8_t  source;       /* 20 */
    uint8_t  reason;       /* 21 */
    uint8_t  reserved[10]; /* 22..31: zero */
} we_member6_t;

#define WE_REC_AT(t, f, at) WE_STATIC_ASSERT(offsetof(t, f) == (at), #t "." #f " is at " #at)
WE_STATIC_ASSERT(sizeof(we_route4_t) == 16, "the routing IPv4 record is 16 bytes");
WE_REC_AT(we_route4_t, end, 0);
WE_REC_AT(we_route4_t, asn, 4);
WE_REC_AT(we_route4_t, country, 8);
WE_REC_AT(we_route4_t, rov, 10);
WE_REC_AT(we_route4_t, rir, 11);
WE_REC_AT(we_route4_t, flags, 12);
WE_REC_AT(we_route4_t, asn_rep, 13);
WE_REC_AT(we_route4_t, reserved, 14);
WE_STATIC_ASSERT(sizeof(we_route6_t) == 24, "the routing IPv6 record is 24 bytes");
WE_REC_AT(we_route6_t, end, 0);
WE_REC_AT(we_route6_t, asn, 8);
WE_REC_AT(we_route6_t, country, 12);
WE_REC_AT(we_route6_t, rov, 14);
WE_REC_AT(we_route6_t, rir, 15);
WE_REC_AT(we_route6_t, flags, 16);
WE_REC_AT(we_route6_t, asn_rep, 17);
WE_REC_AT(we_route6_t, reserved, 18);
WE_STATIC_ASSERT(sizeof(we_member4_t) == 16, "the membership IPv4 record is 16 bytes");
WE_REC_AT(we_member4_t, end, 0);
WE_REC_AT(we_member4_t, flags, 4);
WE_REC_AT(we_member4_t, source, 8);
WE_REC_AT(we_member4_t, reason, 9);
WE_REC_AT(we_member4_t, reserved, 10);
WE_STATIC_ASSERT(sizeof(we_member6_t) == 32, "the membership IPv6 record is 32 bytes");
WE_REC_AT(we_member6_t, end, 0);
WE_REC_AT(we_member6_t, flags, 16);
WE_REC_AT(we_member6_t, source, 20);
WE_REC_AT(we_member6_t, reason, 21);
WE_REC_AT(we_member6_t, reserved, 22);
#undef WE_REC_AT
/* Each stride is a multiple of its struct's alignment, so a 64-byte-aligned column aligns every field. */
#if defined(__GNUC__) || defined(__clang__)
WE_STATIC_ASSERT(16 % __alignof__(we_route4_t) == 0 && 24 % __alignof__(we_route6_t) == 0
                 && 16 % __alignof__(we_member4_t) == 0 && 32 % __alignof__(we_member6_t) == 0
                 && 64 % __alignof__(we_member6_t) == 0,
                 "record strides keep every field naturally aligned");
#endif

/* Routing record domains, FORMAT.md 3.1. */
#define WE_ROV_UNDETERMINED      0u
#define WE_ROV_VALID             1u
#define WE_ROV_INVALID           2u
#define WE_ROV_NOT_FOUND         3u   /* 4, `unrouted`, never appears in a record and is refused */
#define WE_RIR_UNDETERMINED      0u
#define WE_RIR_AFRINIC           1u
#define WE_RIR_APNIC             2u
#define WE_RIR_ARIN              3u
#define WE_RIR_LACNIC            4u
#define WE_RIR_RIPE              5u
#define WE_RF_ANYCAST            0x01u
#define WE_RF_MOAS               0x02u
#define WE_RF_NARROWED           0x04u  /* IPv6 only: narrower than a /64, recorded at its /64 */
#define WE_REP_UNDETERMINED      0u
#define WE_REP_REPUTABLE         1u
#define WE_REP_NEUTRAL           2u
#define WE_REP_SUSPICIOUS        3u
#define WE_REP_HIGHLY_SUSPICIOUS 4u
#define WE_ASN_UNDETERMINED      0xffffffffu
#define WE_COUNTRY_UNDETERMINED  0u
#define WE_COUNTRY_MAX           999u

/* Membership attribute bits by plane, FORMAT.md 3.2. One plane per file, so the sets never meet. */
#define WE_MF_TOR_EXIT           0x01u
#define WE_MF_RPKI_UNREACHABLE   0x01u
#define WE_MF_PROXY              0x01u
#define WE_MF_VPN                0x02u
#define WE_MF_C2                 0x01u
#define WE_MF_BRUTEFORCE         0x02u
#define WE_MF_SPAM               0x04u
#define WE_MF_PHISHING           0x08u
#define WE_MF_SCANNER            0x10u
#define WE_MF_STATE_ACTOR        0x20u
#define WE_MF_TENANT_ALLOW       0x01u
#define WE_MF_TENANT_DENY        0x02u
#define WE_REASON_UNDETERMINED   0u
#define WE_REASON_ASN            1u
#define WE_REASON_LENGTH         2u

/*
 * One family's search, as the loader proved it. Everything the lookup needs is here, COPIED AT ARM
 * TIME: the count, the kind, the parameters and the region bounds. The lookup takes nothing about the
 * shape of the search from the mapping itself, only keys and index entries, and every position it
 * derives from those is clamped with a branchless min against the copied count. That is what keeps a
 * same-length rewrite of the bytes under an armed descriptor (the publication rule, POLICY.md §2.4) inside the mapping:
 * the answers may be wrong until the re-verify disarms it, the reads cannot leave the buffer.
 *
 * Three descriptors, not two: the IPv6 half is either 128-bit keys (format 1 and the membership
 * planes) or 64-bit keys (routing, registry), and each width has its own lookup. The loader fills the
 * one the file declares and leaves the other at n = 0, so calling the wrong width answers "no range"
 * through the same n = 0 short-circuit and costs no extra branch.
 */
typedef struct {
    __uint128_t     first;     /* start[0], zero-extended: rank's window 0 has no separator below it */
    const uint8_t  *start;     /* start[]: u32, u64 or u128 keys */
    const uint8_t  *end;       /* where the inclusive end is read: the record (format 2) or end[] */
    const uint8_t  *records;   /* format 2: the record column; NULL in format 1 */
    const uint8_t  *sev;       /* format 1: sev[]; NULL in format 2 */
    const uint32_t *idx;       /* radix: the bucket table (kind NONE: a one-bucket table, not mapped) */
    const uint8_t  *stree;     /* rank: the S-tree, 64-byte nodes in level order */
    uint32_t        n;         /* ranges; 0 short-circuits every lookup before any index-derived load */
    uint32_t        m;         /* rank: windows, ceil(n / stride) */
    uint32_t        stride;    /* bytes between successive `end` reads: the record stride, or the key size */
    uint32_t        nodes;     /* rank: S-tree nodes, ((B+1)^depth - 1) / B */
    uint32_t        span;      /* rank: window stride s (64, or 32 for 128-bit keys) */
    uint8_t         kind;      /* WE_KIND_RADIX or WE_KIND_RANK; NONE is folded into RADIX */
    uint8_t         shift;     /* radix: 32 - k for 32-bit keys, 63 - k on the top word otherwise */
    uint8_t         depth;     /* rank: S-tree levels */
    uint8_t         sshift;    /* rank: log2(span) */
    uint8_t         key_bits;  /* 32, 64 or 128 */
    uint8_t         file_kind; /* the kind byte as the file states it (NONE stays NONE here) */
    uint8_t         file_param;/* the file's index parameter: k, or log2 of the stride */
    uint8_t         _pad;
} we_fam_t;

/*
 * A published mapping. Built once per snapshot load and then immutable, so a reader needs exactly one
 * atomic load of the pointer to it and no further synchronisation.
 */
typedef struct {
    we_fam_t           f4;        /* IPv4, 32-bit keys */
    we_fam_t           f6;        /* IPv6, 128-bit keys (format 1, membership planes) */
    we_fam_t           f6w;       /* IPv6, 64-bit keys (routing, registry); n = 0 unless declared */
    /*
     * Arm-time copies: a re-verify compares against these, never against the mapping.
     *
     * generation, valid_until_ms and country_known share the 64-byte line at offset 256 with the tail
     * of f6w, because the policy evaluator reads exactly these three per fill (the generation it
     * records, the staleness bound, and the table a routing record's country is normalised through)
     * and its published per-fill descriptor line count (3, 3 and 2 by family) holds only while they
     * stay on one line. test_policy pins the offsets.
     */
    uint64_t           generation;      /* 288; 0 only on the REVOKED map, see we_handle_publish_map */
    uint64_t           valid_until_ms;  /* 296 */
    const uint8_t     *country_known;   /* 304: 125-byte bitmap of the codes this reader knows */
    uint8_t            digest[32];
    uint32_t           format;
    uint8_t            plane_id;  /* 0 for a pre-schema format-1 file */
    uint8_t            schema_id;
    uint16_t           country_table_version;
    uint32_t           country_unknown; /* records whose in-range code is not in that table */
    uint32_t           feed_count;      /* format 2: entries in the blob's feed-name table (0 in format 1) */
    uint32_t           feed_table_end;  /* format 2: blob offset just past that table */
    /*
     * The tenant plane's revocation, published as a map rather than as a state byte: a heap map with
     * both families empty, no buffer, no header, generation 0 and this flag set, built only by
     * we_handle_publish_map(). A reader checks it BEFORE we_is_stale(), which reports stale whenever
     * h is NULL. The evaluator tests generation == 0, which the loader makes equivalent: it refuses
     * generation 0 in a format-2 header and we_handle_publish_plane() refuses it in format 1.
     */
    uint8_t            revoked;
    const we_header_t *h;
    /*
     * The format-1 view, kept by name because the shims, the counters and the tools read it. In a
     * format-2 mapping end[] and sev[] do not exist and are NULL, and v6_start is NULL when the IPv6
     * keys are 64-bit: a u64 array must never be read through a u128 pointer.
     */
    const uint32_t    *v4_index;  /* the radix table when the family is radix-indexed, else NULL */
    const uint32_t    *v4_start;
    const uint32_t    *v4_end;
    const uint8_t     *v4_sev;
    const uint32_t    *v6_index;
    const __uint128_t *v6_start;
    const __uint128_t *v6_end;
    const uint8_t     *v6_sev;
    const uint32_t    *v4_meta;   /* validated at load; NULL when absent or refused */
    const uint32_t    *v6_meta;
    const char        *blob;
    uint32_t           v4_count;
    uint32_t           v6_count;
    const void        *base;      /* the owned buffer this view points into; free()d, not munmap'd */
    size_t             len;
} we_map_t;

/*
 * ---- The trace hook, FORMAT.md §7 ----
 *
 * WE_TRACE_READ(p) sits at every load the lookup makes from the mapping: the index entry, the S-tree
 * node, start[mid], the end (record or end[]) and sev. In production it is ((void)0) and its argument
 * is never evaluated, so the object code is the code without it; a test build defines WE_TRACE and
 * supplies we_trace_read(), which records every address, and the deterministic test derives probes,
 * depth, lines and pages from those addresses per lookup.
 *
 * It is an EXPRESSION, `(WE_TRACE_READ(p), value)`, and never a statement. The first draft placed it
 * as an if/return and gcc laid the blocks out differently at three optimisation levels; inside the
 * expression the object code is unchanged, which the gate checks with objdump at four levels.
 *
 * The declaration exists only under WE_TRACE, so the preprocessed production build does not contain
 * the name at all, and the hot-path gate asserts exactly that.
 */
#ifdef WE_TRACE
void we_trace_read(const void *p, size_t len);
#define WE_TRACE_READ(p) we_trace_read((const void *)(p), sizeof *(p))
#else
#define WE_TRACE_READ(p) ((void)0)
#endif

/*
 * The test suite's MUTANT: a window searched one entry longer than the structure says. It still finds
 * the right range, so a test that compares only answers, or only the maximum, passes it; the
 * per-lookup equality against the data-free model must not.
 *
 * Every window end goes through WE_WINDOW_END, which is the identity in every build but the mutant's,
 * so production code is unchanged by it. In the mutant it adds one entry, SATURATING: the earlier
 * `end + 1` wrapped the unindexed family's end (0xffffffff, clamped to n) to 0, an empty window and a
 * wrong answer, which is a different mutant from the one described. Saturating, the unindexed window,
 * already the whole array, has no further entry to search, and the mutant is a no-op there by
 * construction; the trace build asserts exactly that. Refused outside a trace build, so a stray -D
 * cannot ship a slower lookup.
 */
#if defined(WE_TEST_WINDOW_SLACK) && !defined(WE_TRACE)
#error "WE_TEST_WINDOW_SLACK is the test suite's mutant and exists only in a WE_TRACE build"
#endif
#if defined(WE_TEST_WINDOW_SLACK)
static inline uint32_t we_test_window_end(uint32_t v)
{
    return v == 0xffffffffu ? v : v + 1u;
}
#define WE_WINDOW_END(v) we_test_window_end(v)
#else
#define WE_WINDOW_END(v) (v)
#endif

/* "No range": the address is in no range of this family. Never a valid index (n is at most 2^32 - 1). */
#define WE_NO_RANGE 0xffffffffu

/* One S-tree node is one 64-byte line: B keys, B = 64 / key bytes. */
typedef struct { uint32_t    k[16]; } we_node32_t;
typedef struct { uint64_t    k[8];  } we_node64_t;
typedef struct { __uint128_t k[4];  } we_node128_t;
WE_STATIC_ASSERT(sizeof(we_node32_t) == 64 && sizeof(we_node64_t) == 64 && sizeof(we_node128_t) == 64,
                 "an S-tree node is one 64-byte line");

/* The branchless clamp. A ternary on two registers is a csel / cmov at every level that ships. */
WE_HOT_INLINE uint32_t we_min_u32(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

/*
 * THE HOT PATH: which range holds this address.
 *
 * One function per key width, each force-inlined, and inside each a TWO-ARMED `if` on the arm-time
 * kind byte. Both arms share the window search and the end read; only the step that picks the window
 * differs. No function pointer anywhere: a call through one is an indirect branch that the hot-path
 * gate cannot tell from a callback, and it would build a frame. The `else` arm is unreachable, because
 * the loader refuses every kind but radix and rank (and folds `none` into radix), and returns "no
 * range" for memory safety only.
 *
 * RADIX-k. idx[b] is the number of ranges whose start has top-k bits below b, and idx[2^k] == n, so the
 * window for a key in bucket b is [idx[b], idx[b+1]) plus the still-open entry at idx[b] - 1 that the
 * step back after the search lands on. A /8 that spans 255 empty buckets falls out of the same
 * arithmetic: no special case, no second lookup. The worst case is ceil(log2(w + 1)) probes for the
 * widest window w, and that bound is a property of the file (we_worst_bucket_occupancy4/6).
 *
 * RANK-s. The separators start[j*s], j in [1, m), are a complete (B+1)-ary search tree of 64-byte
 * nodes in level order with the keys in order (FORMAT.md §4.2). Each level reads ONE node and counts
 * the keys <= a with a branchless HALVING search over the node (log2(B) + 1 compares, each a csel on
 * a data-dependent index). It is not the obvious sum of B compares: that form auto-vectorizes on
 * aarch64 at -O2 and -O3 and loads a {1,1} mask from .rodata.cst16, which is a relocation in the hot
 * path and a cache line no count models (found by the hot-path gate). The node's keys are ascending
 * with the maximum-key padding last, so the halving search is exact. The count is the child, and the
 * counts read as digits in
 * base B+1 are the number of separators <= a, which is the window j. The window is then searched from
 * j*s + 1, because start[j*s] <= a is already known (it is the separator, or for window 0 the copied
 * start[0]), so a full window of s entries costs exactly log2(s) probes: 6 at stride 64, 5 at 32.
 *
 * BELOW start[0], EITHER KIND: one compare against the arm-time copy of start[0], before either arm,
 * answers "no range" with zero loads from the mapping (FORMAT.md §4.2, and the cost model counts it
 * the same way for radix and rank). It is what lets window 0 go without a separator below it.
 *
 * Every index-derived position is clamped against the copied n: the window bounds from the radix
 * table, and j against m - 1 (the maximum key matches the padding slots too, so j can count past
 * m - 1 for exactly that one address). The S-tree walk is bounded by construction: the depth is the
 * copied one and each child index is at most B.
 *
 * Returns the range index, or WE_NO_RANGE. The index is meaningful only for this mapping.
 */
WE_HOT_INLINE uint32_t we_find4(const we_map_t *m, uint32_t a)
{
    const we_fam_t *f;
    const uint32_t *st;
    const uint32_t *ep;
    uint32_t n, lo, hi, i;

    if (m == NULL || m->f4.n == 0u) {
        return WE_NO_RANGE;              /* fail open: no data is not a verdict */
    }
    f = &m->f4;
    n = f->n;
    st = (const uint32_t *)(const void *)f->start;
    if (a < (uint32_t)f->first) {
        return WE_NO_RANGE;              /* below start[0]: the arm-time copy, no load from the mapping */
    }
    if (f->kind == WE_KIND_RADIX) {
        const uint32_t *ix = f->idx + (uint32_t)((uint64_t)a >> f->shift);

        lo = we_min_u32((WE_TRACE_READ(ix), ix[0]), n);
        hi = we_min_u32(WE_WINDOW_END((WE_TRACE_READ(ix + 1), ix[1])), n);
    } else if (f->kind == WE_KIND_RANK) {
        const we_node32_t *nodes = (const we_node32_t *)(const void *)f->stree;
        uint32_t k = 0u, j, l, base;

        WE_NO_UNROLL
        for (l = 0u; l < f->depth; l++) {
            const we_node32_t *nd = (WE_TRACE_READ(nodes + k), nodes + k);
            uint32_t c = 0u;

            /* keys <= a, by a branchless halving search (see RANK-s above for why not a sum) */
            c += (nd->k[c + 7u] <= a) ? 8u : 0u;
            c += (nd->k[c + 3u] <= a) ? 4u : 0u;
            c += (nd->k[c + 1u] <= a) ? 2u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            k = k * 17u + c + 1u;
        }
        /*
         * The window is k less the nodes above the leaves: k runs node indices root first, so after the
         * last level it is the window's index plus nodes = ((B+1)^depth - 1) / B. One counter, not two,
         * which is one register the search no longer holds where it is inlined into the evaluator.
         */
        j = we_min_u32(k - f->nodes, f->m - 1u);
        base = j << f->sshift;
        lo = base + 1u;
        hi = we_min_u32(WE_WINDOW_END(base + f->span), n);
    } else {
        return WE_NO_RANGE;              /* unreachable: the loader refuses any other kind */
    }

    /* upper_bound: smallest i with start[i] > a. Branch-light; the compiler emits csel / cmov here. */
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if ((WE_TRACE_READ(st + mid), st[mid] <= a)) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    if (lo == 0u) {
        return WE_NO_RANGE;              /* every range starts above a */
    }
    i = lo - 1u;
    ep = (const uint32_t *)(const void *)(f->end + (size_t)i * f->stride);
    return ((WE_TRACE_READ(ep), *ep) >= a) ? i : WE_NO_RANGE;
}

/*
 * IPv6 with 64-bit keys: the routing and registry planes, whose start and end are the top 64 bits of
 * the address. The low 64 bits of the client address are the truncation and are never read; a range
 * narrower than a /64 was recorded at its /64 with WE_RF_NARROWED (FORMAT.md 3.1).
 */
WE_HOT_INLINE uint32_t we_find6_64(const we_map_t *m, const uint8_t addr[16])
{
    const we_fam_t *f;
    const uint64_t *st;
    const uint64_t *ep;
    uint64_t a;
    uint32_t n, lo, hi, i;

    if (m == NULL || m->f6w.n == 0u) {
        return WE_NO_RANGE;
    }
    f = &m->f6w;
    n = f->n;
    memcpy(&a, addr, 8);                 /* one load: the address need not be 8-byte aligned */
    a = we_bswap64(a);                   /* network order to host-comparable */
    st = (const uint64_t *)(const void *)f->start;
    if (a < (uint64_t)f->first) {
        return WE_NO_RANGE;
    }
    if (f->kind == WE_KIND_RADIX) {
        const uint32_t *ix = f->idx + (uint32_t)((a >> 1) >> f->shift);

        lo = we_min_u32((WE_TRACE_READ(ix), ix[0]), n);
        hi = we_min_u32(WE_WINDOW_END((WE_TRACE_READ(ix + 1), ix[1])), n);
    } else if (f->kind == WE_KIND_RANK) {
        const we_node64_t *nodes = (const we_node64_t *)(const void *)f->stree;
        uint32_t k = 0u, j, l, base;

        WE_NO_UNROLL
        for (l = 0u; l < f->depth; l++) {
            const we_node64_t *nd = (WE_TRACE_READ(nodes + k), nodes + k);
            uint32_t c = 0u;

            c += (nd->k[c + 3u] <= a) ? 4u : 0u;
            c += (nd->k[c + 1u] <= a) ? 2u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            k = k * 9u + c + 1u;
        }
        /*
         * The window is k less the nodes above the leaves: k runs node indices root first, so after the
         * last level it is the window's index plus nodes = ((B+1)^depth - 1) / B. One counter, not two,
         * which is one register the search no longer holds where it is inlined into the evaluator.
         */
        j = we_min_u32(k - f->nodes, f->m - 1u);
        base = j << f->sshift;
        lo = base + 1u;
        hi = we_min_u32(WE_WINDOW_END(base + f->span), n);
    } else {
        return WE_NO_RANGE;
    }
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if ((WE_TRACE_READ(st + mid), st[mid] <= a)) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    if (lo == 0u) {
        return WE_NO_RANGE;
    }
    i = lo - 1u;
    ep = (const uint64_t *)(const void *)(f->end + (size_t)i * f->stride);
    return ((WE_TRACE_READ(ep), *ep) >= a) ? i : WE_NO_RANGE;
}

/*
 * IPv6 with 128-bit keys: format 1 and the planes that list single addresses.
 *
 * Network order to host-comparable as TWO byte-swapped 64-bit loads. This was a 16-iteration loop
 * shifting one byte at a time: a serial dependency chain the compiler does not unroll, measured at 65%
 * of the whole v6 lookup; the swaps measured 2.8x on the lookup (7.24 ns mean against 2.64 over 2,000
 * ranges). memcpy of 8 bytes inlines to one load and __builtin_bswap64 to one instruction; memcpy
 * rather than a cast because the address need not be aligned. The ADDRESS is network order; the
 * stored bounds are native little-endian, and that distinction is why the interop gate exists.
 */
WE_HOT_INLINE uint32_t we_find6(const we_map_t *m, const uint8_t addr[16])
{
    const we_fam_t *f;
    const __uint128_t *st;
    const __uint128_t *ep;
    __uint128_t a;
    uint64_t top, low;
    uint32_t n, lo, hi, i;

    if (m == NULL || m->f6.n == 0u) {
        return WE_NO_RANGE;
    }
    f = &m->f6;
    n = f->n;
    memcpy(&top, addr, 8);
    memcpy(&low, addr + 8, 8);
    top = we_bswap64(top);
    low = we_bswap64(low);
    a = ((__uint128_t)top << 64) | (__uint128_t)low;
    st = (const __uint128_t *)(const void *)f->start;
    if (a < f->first) {
        return WE_NO_RANGE;
    }
    if (f->kind == WE_KIND_RADIX) {
        const uint32_t *ix = f->idx + (uint32_t)((top >> 1) >> f->shift);

        lo = we_min_u32((WE_TRACE_READ(ix), ix[0]), n);
        hi = we_min_u32(WE_WINDOW_END((WE_TRACE_READ(ix + 1), ix[1])), n);
    } else if (f->kind == WE_KIND_RANK) {
        uint32_t k = 0u, j, l, base;

        /*
         * The levels counted down from the depth, one register for both, and the tree's base re-read
         * from the descriptor per level: a 128-bit key holds two registers, and where this search is
         * inlined into the evaluator one more held here is a spill (POLICY.md D9).
         */
        WE_NO_UNROLL
        for (l = f->depth; l > 0u; l--) {
            const we_node128_t *nd = (const we_node128_t *)(const void *)f->stree + k;

            WE_TRACE_READ(nd);
            uint32_t c = 0u;

            c += (nd->k[c + 1u] <= a) ? 2u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            c += (nd->k[c] <= a) ? 1u : 0u;
            k = k * 5u + c + 1u;
        }
        /*
         * The window is k less the nodes above the leaves: k runs node indices root first, so after the
         * last level it is the window's index plus nodes = ((B+1)^depth - 1) / B. One counter, not two,
         * which is one register the search no longer holds where it is inlined into the evaluator.
         */
        j = we_min_u32(k - f->nodes, f->m - 1u);
        base = j << f->sshift;
        lo = base + 1u;
        hi = we_min_u32(WE_WINDOW_END(base + f->span), n);
    } else {
        return WE_NO_RANGE;
    }
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if ((WE_TRACE_READ(st + mid), st[mid] <= a)) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    if (lo == 0u) {
        return WE_NO_RANGE;
    }
    i = lo - 1u;
    ep = (const __uint128_t *)(const void *)(f->end + (size_t)i * f->stride);
    return ((WE_TRACE_READ(ep), *ep) >= a) ? i : WE_NO_RANGE;
}

/*
 * The format-1 verdict: a severity byte. 0 allows; non-zero carries the level in the low nibble and
 * flags in the high. A mapping with no sev[] for the family (absent, empty, or a format-2 plane, which
 * carries attributes rather than a severity) answers WE_SEV_NONE, fail-open, before any search.
 */
WE_HOT_INLINE uint8_t we_lookup4(const we_map_t *m, uint32_t addr)
{
    const uint8_t *sev;
    uint32_t i;

    if (m == NULL || m->v4_sev == NULL) {
        return WE_SEV_NONE;
    }
    sev = m->v4_sev;
    i = we_find4(m, addr);
    return (i != WE_NO_RANGE) ? (WE_TRACE_READ(sev + i), sev[i]) : (uint8_t)WE_SEV_NONE;
}

WE_HOT_INLINE uint8_t we_lookup6(const we_map_t *m, const uint8_t addr[16])
{
    const uint8_t *sev;
    uint32_t i;

    if (m == NULL || m->v6_sev == NULL) {
        return WE_SEV_NONE;
    }
    sev = m->v6_sev;
    i = we_find6(m, addr);
    return (i != WE_NO_RANGE) ? (WE_TRACE_READ(sev + i), sev[i]) : (uint8_t)WE_SEV_NONE;
}

/*
 * A format-2 range's record, for the attribute reads that follow a find. NULL for WE_NO_RANGE, for a
 * format-1 mapping (it has no records) and for an index past the copied n. The policy compiler resolves
 * every attribute to (plane, offset) at arm time, so the evaluator reads `record + offset` and this is
 * the only place that turns an index into an address.
 */
WE_HOT_INLINE const uint8_t *we_record_of(const we_fam_t *f, uint32_t i)
{
    return (f->records != NULL && i < f->n) ? f->records + (size_t)i * f->stride : (const uint8_t *)NULL;
}

/*
 * A routing record's country, through the reader's table: a code in range but not in the table this
 * reader was compiled with reads as undetermined (0), because the plane may have been built against a
 * newer ISO 3166-1 table and a new assignment must never make a module refuse a plane. Codes above 999
 * never get here: the loader refuses them.
 */
WE_HOT_INLINE uint16_t we_country(const we_map_t *m, uint16_t code)
{
    if (m == NULL || m->country_known == NULL || code > WE_COUNTRY_MAX) {
        return WE_COUNTRY_UNDETERMINED;
    }
    return ((m->country_known[code >> 3] >> (code & 7u)) & 1u) != 0u ? code
                                                                     : (uint16_t)WE_COUNTRY_UNDETERMINED;
}

/*
 * Should this verdict deny, given a configured threshold?
 *
 * Two rules live here rather than in each module, so three shims cannot disagree about them:
 *   - an INFERRED verdict never denies unless the operator asked for inference explicitly
 *   - severity must meet or exceed the threshold, and threshold 0 denies nothing
 */
WE_HOT_INLINE int we_should_deny(uint8_t verdict, uint8_t threshold, int allow_inferred)
{
    uint8_t sev = (uint8_t)(verdict & WE_SEV_MASK);

    if (threshold == 0u || sev == WE_SEV_NONE) {
        return 0;
    }
    if ((verdict & WE_F_INFERRED) != 0u && !allow_inferred) {
        return 0;
    }
    return sev >= threshold;
}

/*
 * Has the snapshot outlived its own bound? After an age with no successful refresh, a reader stops
 * enforcing rather than enforcing on old data: a blocklist nobody is maintaining any more should lapse,
 * not harden.
 *
 * The bound is carried IN the file by the builder rather than configured at the edge, so an operator
 * cannot accidentally keep enforcing a month-old snapshot by leaving a config value high. A stale
 * snapshot answers allow for everything.
 *
 * now_ms is EPOCH milliseconds, the clock valid_until_ms is written in: in nginx that is
 * `ngx_time() * 1000`, which the shim passes. Never ngx_current_msec: nginx 1.24 sets it from
 * ngx_monotonic_time, milliseconds since boot (about 10^9), and against a valid_until_ms of about
 * 1.8 * 10^12 nothing would ever read stale. The bound compared is the ARM-TIME copy, not the mapping.
 */
WE_HOT_INLINE int we_is_stale(const we_map_t *m, uint64_t now_ms)
{
    if (m == NULL || m->h == NULL) {
        return 1;
    }
    return m->valid_until_ms != 0ull && now_ms > m->valid_until_ms;
}

/*
 * ---- The published handle: how a snapshot is swapped under live traffic ----
 *
 * One atomic pointer. A reader loads it once per request and uses the mapping it names; a refresher
 * maps the new file, validates it completely, and only then stores the pointer. There is no lock on
 * the read side and no state a reader has to register, which is what lets the same core sit in an
 * nginx worker, an Apache prefork child and a thread without three different concurrency designs.
 *
 * WHEN THE OLD MAPPING IS UNMAPPED. A reader holds its pointer for the duration of one lookup -
 * nanoseconds - but it holds it with no way for us to observe that it has finished. Rather than make
 * every worker register an epoch (which is the usual answer and would put bookkeeping on the hot
 * path), we RETIRE the old mapping and unmap it only after a grace period that is many orders of
 * magnitude longer than any reader can plausibly hold it. we_handle_retire() does that work, from the
 * refresher, never from a request.
 *
 * If every retire slot is occupied - more reloads inside one grace period than we have slots - we
 * LEAK the buffer rather than free it early. A leaked read-only buffer of a few megabytes is a
 * bounded, visible cost; a buffer freed under a live reader is a segmentation fault inside a
 * customer's web server. That trade is not close.
 *
 * Atomics are the GCC/Clang __atomic builtins rather than <stdatomic.h>, because this header is
 * included by module code whose build flags we do not control and C11 atomics are not reliably
 * available there. Both nginx and Apache build with GCC or Clang.
 */
/*
 * COUNTERS ARE ATOMIC because more than one thread may publish or retire. They are RELAXED: they are
 * metrics, nothing branches on them, and a relaxed fetch-add on a counter is free on every
 * architecture we ship to. Plain `++` here was a torn read waiting for a threaded MPM.
 */
#define WE_COUNT(field) __atomic_fetch_add(&(field), 1ull, __ATOMIC_RELAXED)

/*
 * HOW MANY THREADS MAY DO WHAT. Readers: any number, with no registration and nothing on the hot
 * path. Publishers and retirers: also any number, because both slot transitions are a
 * compare-exchange, so a slot is claimed by exactly one publisher and reclaimed (and therefore freed)
 * by exactly one retirer. That is what makes ONE concurrency design serve an nginx worker, an Apache
 * prefork child and an Apache/LiteSpeed thread, which is what the paragraph above claims.
 *
 * It is stated here because it did not used to be true. Both transitions were a load followed by a
 * store, which is a benign race in nginx (one thread) and, in a threaded MPM, an unbounded invisible
 * leak on the claim side and a double free on the reclaim side.
 */
#define WE_RETIRE_SLOTS 4

/*
 * A retire slot that a publisher has CLAIMED but not yet finished writing.
 *
 * The slot holds two fields - the mapping and the time it was retired - and a reader of the pair
 * must never see one without the other. So a publisher reserves the slot with this sentinel, writes
 * the timestamp, then publishes the real pointer with a release store; a sweeper that loads the
 * pointer with an acquire load either sees the sentinel (skip, it will be complete in a few
 * instructions) or sees a real mapping and, by the release/acquire pair, the timestamp that belongs
 * to it.
 *
 * It is never dereferenced and never passed to free. 1 is used rather than, say, (void *)-1 because
 * it cannot be a valid malloc result on any target and reads unambiguously in a debugger.
 *
 * Why a sentinel at all, rather than writing the timestamp first: that writes it into a slot the
 * publisher may not get, and a failed claim then leaves the OCCUPANT's retirement time overwritten
 * with a later one, so the occupant is not reclaimed when it should be. ThreadSanitizer found that,
 * on the first run after the gates went into CI.
 */
#define WE_SLOT_RESERVED ((we_map_t *) (uintptr_t) 1)

typedef struct {
    we_map_t *map;
    uint64_t  retired_at_ms;
} we_retired_t;

typedef struct {
    we_map_t    *current;                    /* touched ONLY through the __atomic builtins */
    we_retired_t retired[WE_RETIRE_SLOTS];
    uint64_t     grace_ms;                   /* 0 selects the default, WE_DEFAULT_GRACE_MS */
    uint64_t     generation;                 /* last published generation, for metrics */
    uint64_t     loads_ok;
    uint64_t     loads_failed;
    uint64_t     leaked;                     /* retire slots exhausted; should stay 0 */
    uint64_t     rejected_rollbacks;         /* a snapshot no newer than the one in use */
    /*
     * The highest generation ever armed through we_handle_publish_plane(). A revocation does not
     * reset it and does not write `generation`, so a pre-revocation file put back by a backup
     * restore, an rsync or configuration management cannot re-arm a revoked allow list: a re-arm
     * must exceed this mark. A module seeds it at configuration load and re-reads it at every tenant
     * plane reload from the root-owned high-water file outside the plane directory,
     * /etc/whisper-edge/state/tenant.high-water (the one subdirectory the keyed refresh unit may
     * write), so a restart or a reload keeps it too. Its reload step (POLICY.md section 2.7): under a
     * shared flock it reads that file, the tombstone and tenant.bin; a well-formed value v raises this
     * field by an atomic compare-exchange max, before any publish and never lowering it; a malformed
     * file is no transition (at configuration load, nothing armed, the mark 0, NULL published);
     * REVOKED is published on a transition only; NULL is a fresh handle seeded from the file, the old
     * one freed only after the grace. Exactly one thread per handle runs the reload and every publish,
     * because the store at arm time is not a read-modify-write.
     */
    uint64_t     high_water;
    /*
     * Set at binding by a module that owns every map on this handle (we_module.h's mapped
     * planes): its maps are mappings the module unmaps after its own grace, never heap buffers the
     * core's retire ring may free. Under it every core publish refuses with WE_ERR_OWNERSHIP before it
     * loads anything, and publish_and_retire refuses before it swaps, so a stray core publish can never
     * hand a module-owned map to the ring.
     */
    uint32_t     module_owned;
} we_handle_t;

#define WE_DEFAULT_GRACE_MS 30000ull

/* The hot-path read. One acquire load, no branch on anything but the result. */
WE_HOT_INLINE const we_map_t *we_current(we_handle_t *h)
{
    if (h == NULL) {
        return NULL;                         /* and every lookup on NULL answers allow */
    }
    return __atomic_load_n(&h->current, __ATOMIC_ACQUIRE);
}

/* ---- Cold path. Loader and lifecycle; never called from a request. ---- */

#define WE_OK                 0
#define WE_ERR_OPEN          -1
#define WE_ERR_TOO_SMALL     -2
#define WE_ERR_MAGIC         -3
#define WE_ERR_FORMAT        -4
#define WE_ERR_TRUNCATED     -5
#define WE_ERR_OFFSETS       -6
#define WE_ERR_UNSORTED      -7
#define WE_ERR_OVERLAP       -8
#define WE_ERR_DIGEST        -9
#define WE_ERR_MMAP         -10
#define WE_ERR_ROLLBACK     -11
#define WE_ERR_PERMISSIONS  -12
#define WE_ERR_OWNERSHIP    -13   /* the handle is a module's: only its compare-and-swap calls publish */
/*
 * The return codes' space: -1 to -31 are the core's (WE_ERR_*); -32 to -63 are reserved for the module
 * glue (we_module.h's WE_MOD_ERR_*), so no future core code can collide with one a module returns.
 */
#define WE_ERR_CORE_LAST    -31
#define WE_ERR_MODULE_FIRST -32
#define WE_ERR_MODULE_LAST  -63

/*
 * What a refusal was about, for the one log line a failed load may emit. `rc` is the WE_ERR_* returned;
 * `family` is 4 or 6 when the refusal is about one family and 0 otherwise; `record` names the range
 * whose record failed the domain scan (FORMAT.md §3), and is -1 for every other refusal; `what` is the
 * rule, a static string.
 */
typedef struct {
    int         rc;
    int         family;
    int64_t     record;
    const char *what;
} we_load_detail_t;

/*
 * Map and fully validate a snapshot of the FORMAT-1 layout, the reputation plane every shim serves.
 * On any non-zero return *out is left untouched and nothing is mapped, so a caller that ignores the
 * error still fails open.
 *
 * A format-2 file is refused with WE_ERR_FORMAT, exactly as a reader built before format 2 refuses it:
 * this is the entry point of the legacy directive, and an operator who points it at routing.bin must
 * get the clean refusal, not a mapping that answers "allow" for every address because it carries no
 * severity. A format-1 file with WE_H_SCHEMA loads, and its tail is validated (FORMAT.md §2).
 */
int  we_map_open(const char *path, we_map_t *out);

/*
 * Map and fully validate a plane of EITHER format. Refusals in FORMAT.md §6 order, each with its
 * named error; `detail` may be NULL.
 *
 * The plane_id must match the file's base name when that name is `<plane>.bin` for one of the eight
 * planes, the names whisper_edge_data installs under. Any other name (the published keyless
 * snapshot.bin, the interop fixtures, a temp the refresh verifies before its rename) carries no claim,
 * and only the tail's own domain rules apply, plane_id in the known range among them.
 */
int  we_plane_open(const char *path, we_map_t *out, we_load_detail_t *detail);
/*
 * Open a file that must be regular, never blocking on a FIFO or a device at the path: stat, refuse a
 * non-regular target ("not a regular file"), open O_NONBLOCK, fstat and refuse again ("changed to a
 * non-regular file after its check"), clear O_NONBLOCK. The descriptor, or -1 with *why set ("cannot
 * open" for an absent or unreadable path). Every loader in the core opens through it.
 */
int  we_open_regular(const char *path, const char **why);
void we_map_close(we_map_t *m);

/*
 * Validate a plane already in memory, exactly as the loader validates a file (we_plane_open()'s rules,
 * FORMAT.md section 6 in order, the digest last), and describe it in *out, whose pointers point into
 * `base`. `name` is the base name the plane is bound under (`tor.bin`), which carries the plane-id claim
 * as a path's base name does. `base` must be 64-byte aligned (a page from mmap is); the bytes stay the
 * caller's and are never freed here, so *out must never reach we_map_close(). This is the verifier a
 * module's supervisor runs over a pread buffer and a module's thread runs over a mapping.
 */
int  we_map_from_buffer(const uint8_t *base, size_t size, const char *name, we_map_t *out, we_load_detail_t *d);
/*
 * The same rules over a buffer whose digest a budgeted verifier has already computed in chunks
 * (we_module.c's monitor): the digest is still CHECKED, against the header's own field, never
 * recomputed. `digest` is the caller's computed bytes and must follow we_validate's own recipe (the
 * 192-byte header with its digest zeroed, then the body), so a plane that verifies here is one
 * we_map_from_buffer() would also accept; a caller that computes anything else fails the check here,
 * never silently passes. NULL is refused: a verifier that did not digest the buffer may not skip it.
 */
int  we_map_from_buffer_digest(const uint8_t *base, size_t size, const char *name, we_map_t *out,
                               we_load_detail_t *d, const uint8_t digest[32]);
/*
 * Move every pointer of *m that points into its own bytes [m->base, m->base + m->len) to the same offset
 * from `new_base`, and set base to it; a pointer to the core's static tables is left alone. For a
 * supervisor that verified a pread buffer and then mapped the same bytes: it describes the mapping
 * without ever dereferencing it. The caller has required the identity unchanged across the two.
 */
void we_map_rebase(we_map_t *m, const void *new_base);
#if defined(WE_TEST_EXTRA_VERIFY_PASS) && !defined(WE_TEST_CORE_CONTROL)
#error "WE_TEST_EXTRA_VERIFY_PASS is make check's control for the load+verify row and exists only in its control build"
#endif
#if defined(WE_TEST_REBASE_DROP) && !defined(WE_TEST_CORE_CONTROL)
#error "WE_TEST_REBASE_DROP is make check's control for the rebase row and exists only in its control build"
#endif

/* Human-readable reason, for the one log line a failed load is allowed to emit. */
const char *we_strerror(int rc);

/*
 * Load, validate and publish a snapshot, retiring the one it replaces. Returns WE_OK on success; on
 * ANY failure the previously published mapping is left exactly as it was, so a refresh that cannot
 * read the new file keeps serving the old answers rather than no answers.
 *
 * now_ms is passed in rather than read, so a caller with a clock already in hand does not pay for a
 * clock_gettime, and so tests can drive the grace period. It is EPOCH milliseconds, `ngx_time() * 1000`
 * in nginx, the same clock we_is_stale() needs. This comment used to suggest ngx_current_msec, which
 * nginx 1.24 sets from the monotonic clock (milliseconds since boot): harmless for the grace period,
 * but a shim author who took the hint to the staleness check would have a plane that never goes stale.
 */
int  we_handle_publish(we_handle_t *h, const char *path, uint64_t now_ms);

/*
 * The publish path decision 7's state machine uses for EVERY plane, format 1 or 2: loads through
 * we_plane_open(), so tenant.bin and the other format-2 planes can travel it (we_handle_publish()
 * keeps the format-1 legacy contract and refuses them). The rollback check compares against the
 * CURRENT map's generation and against the handle's high-water mark, so a generation no greater than
 * anything ever armed is refused with WE_ERR_ROLLBACK even after a revocation; generation 0 is refused
 * in either format, because 0 means "nothing armed" (the revoked map's). Every map it publishes is
 * aligned_alloc(64). `detail` may be NULL.
 */
int  we_handle_publish_plane(we_handle_t *h, const char *path, uint64_t now_ms, we_load_detail_t *detail);

/*
 * Publish a map the caller built, which today is exactly one: the REVOKED tenant map (both families
 * n = 0, plane_id 8, base NULL, h NULL, generation 0, revoked set). The caller allocates it with
 * aligned_alloc(64) (we_map_new_revoked does), and the retirer frees it like any other map. It does
 * not write h->generation (the metric keeps the last armed generation) and does not lower high_water.
 * Returns WE_ERR_FORMAT for a map that is not 64-byte aligned or not a revoked map.
 */
int  we_handle_publish_map(we_handle_t *h, we_map_t *map, uint64_t now_ms);

/* The REVOKED tenant map, aligned_alloc(64)'d and filled; NULL on allocation failure. */
we_map_t *we_map_new_revoked(void);

/* Unmap anything retired longer ago than the grace period. Call from the refresher, never a request. */
void we_handle_retire(we_handle_t *h, uint64_t now_ms);

/*
 * ---- The worst-case probe bound, which is what the latency claim should rest on ----
 *
 * For this structure the worst case is EXACTLY COMPUTABLE from the file, and that is a far stronger
 * statement than any sampled p99. A lookup reads idx[b] and idx[b+1], then binary-searches the
 * entries between them, so the probe count for EVERY address in the space is bounded by
 * ceil(log2(worst bucket occupancy + 1)). One pass over the index yields that number; no timing, no
 * hardware, no distribution assumption.
 *
 * It exists because the sampled measurement turned out to be much weaker than it looked. The suite's
 * "p99" was a p99 of batch MEANS, which is structurally blind to a tail: injecting a stall into 2% of
 * lookups put the true per-lookup p99 at 576 ns, over budget, and the harness reported 57 ns and
 * passed. And the box this was measured on has a 24 MHz architected timer, so 62% of back-to-back
 * clock reads return the same value and the reported distribution was quantised to 36 distinct values
 * - the "2 ns" figure was one to two ticks of the clock, not a lookup.
 *
 * So the honest form of the claim is not "we sampled 16 ns" but "no address can require more than K
 * probes, and the builder refuses to publish a snapshot where K is exceeded". That survives a question
 * from someone who knows what a percentile is.
 *
 * THE BOUND WAS OVER BY ONE, and is corrected here, in the Java writer and in the test table together
 * (FORMAT.md §4.2). The occupancy used to count idx[b+1] - idx[b] + 1, including the still-open
 * entry at idx[b] - 1. The search never probes that entry: it is the one the step back after the loop
 * lands on, and it is read as the record, not as a key. The search window is idx[b+1] - idx[b] entries
 * and its worst case is ceil(log2(w + 1)) probes, so counting w + 1 published ceil(log2(w + 2)), one too
 * many whenever w + 1 is a power of two. The occupancy is now the window the search really walks.
 *
 * For a RANK family the window search starts after the entry already known to be <= a, so the widest
 * window walked is min(stride, n) - 1 entries and the bound is log2(stride) probes once n reaches a
 * full window; the S-tree depth is reported separately, by we_rank_depth4/6, because it is a hot-index
 * line per level, not a key probe, and the release gate bounds the two separately.
 *
 * Returns 0 for an absent or empty family, and for an UNINDEXED one (kind none) the range count, since
 * a full binary search is then the bound.
 */
uint32_t we_worst_bucket_occupancy4(const we_map_t *m);
uint32_t we_worst_bucket_occupancy6(const we_map_t *m);

/* The S-tree levels a rank family's descent reads, one node each; 0 for a radix family or none. */
uint32_t we_rank_depth4(const we_map_t *m);
uint32_t we_rank_depth6(const we_map_t *m);

/*
 * The one family descriptor that holds the IPv6 half of this mapping: f6 for 128-bit keys, f6w for
 * 64-bit keys, whichever the file declared (f6 when the family is empty). Cold path.
 */
const we_fam_t *we_family6(const we_map_t *m);

/** ceil(log2(occupancy + 1)): the maximum binary-search probes for any address in the space. */
WE_HOT_INLINE uint32_t we_max_probes(uint32_t occupancy)
{
    uint32_t p = 0;

    while (((uint32_t)1 << p) <= occupancy) {
        p++;
    }
    return p;
}

/*
 * The evidence for a denied address: an SBL id and abuse contact from the blob. Cold path, called only
 * when a module logs a decision, never to make one. Returns NULL when absent.
 *
 * BOTH FAMILIES, because only having the v4 half meant every IPv6 deny logged "evidence none carried"
 * whether the snapshot carried evidence for that range or not. The map has always had v6_meta, loaded
 * and bounds-checked beside v4_meta; nothing read it. An operator reading their log could not tell an
 * IPv6 range we hold no evidence for from one where we simply never looked, which is the difference
 * between "we cannot say" and "we did not ask".
 */
/*
 * The RANGE an address falls in, or -1 when it falls in none. The index is into the v4 (or v6) arrays
 * of this mapping and is meaningful ONLY for this mapping: a later snapshot renumbers.
 *
 * Exposed because the per-range counters need it and the evidence lookup already did the search. One
 * implementation of "which range is this" rather than two that can disagree.
 *
 * NOT for the hot path. It is an ordinary out-of-line function and it is a SECOND binary search; the
 * hot path's answer is the severity byte and that is all it needs. Call this on the deny path, which
 * is rare by construction and already pays for a log line.
 */
int we_range4(const we_map_t *m, uint32_t addr);
int we_range6(const we_map_t *m, const uint8_t addr[16]);

/*
 * ---- The weekly summary, which is the reason anybody installs this ----
 *
 * Nobody installs a blocklist because it works. They install it because someone they trust showed
 * them a number. So the module has to produce that number itself, with no console, no account and no
 * telemetry leaving the host: how many requests it denied, from how many distinct networks, and the
 * worst few with one line of evidence each.
 *
 * WHAT IS COUNTED, and why it is exact rather than sampled. One counter per RANGE in the snapshot,
 * incremented on every deny verdict, enforced or not: under mode log a would-deny counts too, and that
 * request was allowed, so the summary says "denied", never "dropped". One total, not two: telling the
 * two kinds apart would change the counter format. A range IS a network - that is what the build does, resolving every
 * prefix into a disjoint interval - so "how many distinct networks" is how many counters are non-zero
 * and "the worst offenders" is the top of the same array, sorted. No cardinality estimator, no
 * reservoir, no sampling: the numbers in the summary are the numbers.
 *
 * WHY NOT IN THE LOOKUP. {@code core/hotpath-gate.sh} fails the build on any atomic instruction
 * inside we_lookup4/6, and it says in so many words that a counter is the most likely future edit to
 * try it. It is right: an increment there would be paid by every allowed request, which is all of
 * them, to measure the rare one. So the module counts AFTER the verdict, on the path that already
 * writes a log line.
 *
 * THE WINDOW IS STATED, NOT ASSUMED. A counter set carries the wall-clock time it started counting,
 * and the summary prints that rather than the word "week". An operator who runs the tool weekly gets
 * a week; one who restarted the server yesterday gets a sentence that says yesterday. A summary that
 * claimed seven days of a six-hour process would be the most quietly dishonest artifact we ship.
 *
 * ACROSS WORKERS AND RESTARTS. Every worker process writes its own file into one directory, named by
 * pid, replaced by rename; the tool sums whatever is there. Nothing is shared between processes and
 * nothing is locked, because a counter is not worth a lock and a summing tool does not need them to
 * agree to the request. A file records PREFIXES rather than range indices, so it stays meaningful
 * after the snapshot it was counted against is replaced.
 */

/* Per-range counters for ONE process. Sized to a mapping; discarded and rebuilt when the shape moves. */
typedef struct {
    uint64_t  started_ms;      /* when this set began counting, for the window the summary prints */
    uint64_t  generation;      /* the snapshot shape these indices belong to */
    uint32_t  v4_count;
    uint32_t  v6_count;
    uint64_t  denied;          /* total requests counted, which is the headline number */
    uint64_t *v4_hits;         /* v4_count entries, or NULL */
    uint64_t *v6_hits;
} we_counters_t;

/*
 * Allocate a counter set for {@code m}. Returns NULL on allocation failure, which the caller treats
 * as "no counting": a summary is worth nothing next to an answer, so this never costs a request.
 */
we_counters_t *we_counters_new(const we_map_t *m, uint64_t now_ms);
void           we_counters_free(we_counters_t *c);

/*
 * Count one denial of {@code addr}. Cheap and branch-light, but NOT for the request path of an
 * allowed request: call it where the module has already decided to deny or to log.
 *
 * A NULL counter set, a mapping whose generation has moved on, or an address in no range are all
 * no-ops rather than errors. The counters are a convenience and must never be a failure mode.
 */
void we_counters_count4(we_counters_t *c, const we_map_t *m, uint32_t addr);
void we_counters_count6(we_counters_t *c, const we_map_t *m, const uint8_t addr[16]);

/*
 * Write this process's counters into {@code dir} as {@code <pid>-<16 hex>.cnt} (the pid and a
 * digest of the process's identity, so a reused pid never overwrites a gone writer's file), by an
 * O_EXCL temp file and a rename.
 * Returns WE_OK; WE_ERR_PERMISSIONS when this process runs as root and the directory is not root-owned
 * and closed to group and world (nothing is written there, and the next tick is refused the same way);
 * or WE_ERR_OPEN when the directory is not writable. A caller may log either once and must otherwise
 * ignore it, because a summary that cannot be written is not a reason to stop serving.
 *
 * Call it from the refresh tick, never from a request.
 */
int we_counters_write(const we_counters_t *c, const we_map_t *m, const char *dir, uint64_t now_ms);

/*
 * A format-2 membership record's `source` as the feed's name, from the blob's feed-name table. ""
 * for 0 ("none"); NULL past the table or on a format-1 mapping. Cold path: it walks the table.
 */
const char *we_feed_name(const we_map_t *m, uint32_t source);

const char *we_evidence4(const we_map_t *m, uint32_t addr);
const char *we_evidence6(const we_map_t *m, const uint8_t addr[16]);

#ifdef __cplusplus
}
#endif
#endif /* WHISPER_EDGE_H */
