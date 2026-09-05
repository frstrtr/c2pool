// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the
// GNU Affero General Public License, version 3 or (at your option) any
// later version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_crypto_types.hpp  --  Family B (XMR lane) primitive types
//
// AUTHORED for c2pool (not ported). Slim POD aliases for the CryptoNote/ed25519
// byte-strings the lane manipulates, so the vendored monero-project crypto-ops
// (raw `const unsigned char *` API) and the extracted derivation subset can be
// driven without pulling in monerod's crypto.h / epee / boost stack.
//
// These are 32-byte (and 1-byte view-tag) opaque byte strings by construction;
// on the wire they are little-endian ed25519 encodings exactly as Monero emits.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace xmr::coin {

// 32-byte opaque ed25519/Keccak byte string. Layout-compatible with a bare
// `unsigned char[32]`, so `reinterpret_cast<const unsigned char*>(&x.bytes)`
// feeds the vendored crypto-ops (ge_*, sc_*) and keccak directly.
struct alignas(1) Bytes32 {
    std::array<unsigned char, 32> bytes{};

    unsigned char*       data()       noexcept { return bytes.data(); }
    const unsigned char* data() const noexcept { return bytes.data(); }
    static constexpr std::size_t size() noexcept { return 32; }

    bool operator==(const Bytes32& o) const noexcept {
        return std::memcmp(bytes.data(), o.bytes.data(), 32) == 0;
    }
    bool operator!=(const Bytes32& o) const noexcept { return !(*this == o); }
};
static_assert(sizeof(Bytes32) == 32, "Bytes32 must be a bare 32-byte POD");

// CryptoNote / Monero named views over the same 32-byte encoding. Distinct
// types keep spend/view/derivation from being transposed at call sites; they
// are intentionally NOT implicitly convertible into one another.
struct PublicKey     : Bytes32 {};  // e.g. spend pub B, view pub A, tx pub R = r*G
struct SecretKey     : Bytes32 {};  // e.g. tx secret r  (must pass sc_check)
struct KeyDerivation : Bytes32 {};  // D = 8*r*A, an ed25519 point encoding
struct EcScalar      : Bytes32 {};  // reduced mod l
struct Hash256       : Bytes32 {};  // Keccak-256 output / block id / tx hash

// View tag: first byte of H("view_tag" || D || varint(i)) since HF15.
struct ViewTag { unsigned char tag{}; };
static_assert(sizeof(ViewTag) == 1, "ViewTag must be one byte");

} // namespace xmr::coin
