// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/compat/crypto/hash.h
//
// AUTHORED, dependency-free stand-in for monero-project's `src/crypto/hash.h`,
// supplying ONLY the one type the vendored reference oracle needs.
//
// The vendored `../vendor/difficulty.{h,cpp}` are used BYTE-FOR-BYTE unmodified
// (LIC-1). difficulty.h declares `check_hash_64(const crypto::hash&, ...)` and
// difficulty.cpp reads the 32-byte digest through `hash.data` in little-endian
// 64-bit limbs (difficulty.cpp:106-111). Monero's real crypto/hash.h drags the
// whole crypto POD family (public_key, secret_key, key_image, the blob
// serializers, epee). The oracle needs none of that — only a 32-byte POD with a
// `.data` member — so this header provides exactly that, isolated on the XMR
// lane include path (`-Icoin/compat`). The vendored files stay unmodified.
//
// NOTE: this is the CROSS-CHECK ORACLE build only. The lane's hot path never
// includes this; it uses the boost-free `../xmr_check_hash.hpp`
// (`xmr::coin::check_hash`), whose equivalence to this oracle is pinned by
// xmr_difficulty_kat.cpp.
// ---------------------------------------------------------------------------
#ifndef C2POOL_XMR_COMPAT_CRYPTO_HASH_H
#define C2POOL_XMR_COMPAT_CRYPTO_HASH_H

#include <cstddef>

namespace crypto {

// Layout-identical to monero-project crypto::hash: a bare 32-byte string.
constexpr std::size_t HASH_SIZE = 32;

#pragma pack(push, 1)
struct hash {
    char data[HASH_SIZE];
};
#pragma pack(pop)

static_assert(sizeof(hash) == HASH_SIZE, "crypto::hash must be a bare 32-byte POD");

} // namespace crypto

#endif // C2POOL_XMR_COMPAT_CRYPTO_HASH_H
