// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/compat/sodium/crypto_verify_32.h
//
// AUTHORED, dependency-free stand-in for libsodium's <sodium/crypto_verify_32.h>.
//
// The vendored monero-project file `../vendor/crypto-ops.c` is used BYTE-FOR-BYTE
// unmodified (LIC-1). Its ONLY libsodium reference is a single call to
// `crypto_verify_32(a, b)` inside `ge_frombytes_vartime`'s canonical-encoding
// check (crypto-ops.c:321). c2pool deliberately carries NO libsodium: the repo
// dropped it as a transitive dep (conanfile.txt: `zeromq/*:encryption=False`,
// "keep the build lean"). Rather than re-add a whole crypto library for one
// constant-time 32-byte compare, this header supplies that one symbol with
// libsodium's exact contract, placed on the include path via `-Icompat` — the
// same mechanism the foundation uses for `../compat/warnings.h`. The vendored
// source therefore stays unmodified.
//
// Contract (matches libsodium crypto_verify_32):
//   returns 0 iff the two 32-byte buffers are equal, -1 otherwise, in constant
//   time w.r.t. the buffer CONTENTS (no data-dependent branch or early exit).
// ---------------------------------------------------------------------------
#ifndef C2POOL_XMR_COMPAT_SODIUM_CRYPTO_VERIFY_32_H
#define C2POOL_XMR_COMPAT_SODIUM_CRYPTO_VERIFY_32_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_verify_32_BYTES 32U

/* Constant-time equality of two 32-byte strings. OR-accumulate the XOR of every
 * byte pair so the running time is independent of where (or whether) they
 * differ, then fold a nonzero accumulator to -1 without branching. */
static inline int crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    unsigned int d = 0U;
    size_t i;
    for (i = 0; i < 32U; ++i) {
        d |= (unsigned int)(x[i] ^ y[i]);
    }
    /* d == 0  -> 0 ;  d != 0 -> -1. (((d-1) >> 8) & 1) is 1 iff d==0. */
    return (int)((1 & ((d - 1U) >> 8)) - 1);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C2POOL_XMR_COMPAT_SODIUM_CRYPTO_VERIFY_32_H */
