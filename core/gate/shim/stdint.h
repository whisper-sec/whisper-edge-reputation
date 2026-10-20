/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026, viaGraph B.V.
 */
/*
 * The two libc headers the hot path includes, for a CROSS build with no target sysroot.
 *
 * hotpath-gate.sh compiles the wrappers for an architecture the host may not have a C library for
 * (clang --target=x86_64-linux-gnu on an aarch64 box, and the reverse). The hot path needs fixed-width
 * types and a declaration of memcpy, which the compiler inlines as a builtin; nothing else. This file
 * is used only by those cross builds, never by a native one, so a native build sees the real libc
 * headers and the shim cannot hide a difference there.
 */
#ifndef WE_GATE_SHIM_STDINT_H
#define WE_GATE_SHIM_STDINT_H
typedef __UINT8_TYPE__  uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INT8_TYPE__   int8_t;
typedef __INT16_TYPE__  int16_t;
typedef __INT32_TYPE__  int32_t;
typedef __INT64_TYPE__  int64_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTPTR_TYPE__  intptr_t;
#define UINT8_MAX  __UINT8_MAX__
#define UINT16_MAX __UINT16_MAX__
#define UINT32_MAX __UINT32_MAX__
#define UINT64_MAX __UINT64_MAX__
#define INT32_MAX  __INT32_MAX__
#define INT64_MAX  __INT64_MAX__
#endif
