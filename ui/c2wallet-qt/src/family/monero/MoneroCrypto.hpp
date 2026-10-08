// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/MoneroCrypto.hpp
//
// Thin, allocation-light wrapper over c2pool's ALREADY-VENDORED Monero curve
// engine (design §2.4): the ed25519 group/scalar ops in
// src/impl/xmr/coin/vendor/crypto-ops.{c,h}, Keccak/cn_fast_hash in vendor,
// and the extracted CryptoNote derivation subset in
// src/impl/xmr/coin/xmr_derivation.{hpp,cpp}. This module DOES NOT reimplement
// any curve or hash math -- it only exposes the handful of operations the
// Family B seed/address core needs, in std::array terms, so the seed/base58/
// address code stays free of raw ge_*/sc_* plumbing.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace c2wallet::monero {

using Bytes32 = std::array<std::uint8_t, 32>;

namespace mcrypto {

// H_s(data) = Keccak-256(data) reduced mod the ed25519 group order l.
Bytes32 hash_to_scalar(const std::uint8_t* data, std::size_t len);

// Keccak-256 (Monero's cn_fast_hash), full 32-byte digest. Used for the
// 4-byte address checksum.
Bytes32 keccak256(const std::uint8_t* data, std::size_t len);

// K = k * G on ed25519. Returns false if k is not a canonical reduced scalar
// (sc_check), matching what monerod would accept.
bool secret_to_public(const Bytes32& sec, Bytes32& pub);

// Reduce a 32-byte little-endian value mod l (sc_reduce32). Used to turn CSPRNG
// entropy into a valid ed25519 scalar during key generation.
Bytes32 reduce32(const Bytes32& in);

// true iff `s` is already a canonical reduced scalar (sc_check == 0).
bool is_canonical_scalar(const Bytes32& s);

// R = a + b (mod l).
Bytes32 scalar_add(const Bytes32& a, const Bytes32& b);

// R = P + Q for compressed ed25519 points. Returns false if either point does
// not decode.
bool point_add(const Bytes32& P, const Bytes32& Q, Bytes32& R);

// R = s * P, plain (non-cofactor) scalar multiplication of a point. Returns
// false if P does not decode. `s` must be a reduced scalar.
bool point_scalarmult(const Bytes32& s, const Bytes32& P, Bytes32& R);

} // namespace mcrypto
} // namespace c2wallet::monero
