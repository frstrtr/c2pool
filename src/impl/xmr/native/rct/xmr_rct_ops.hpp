// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Portions derived from monero-project/monero src/ringct/rctOps.cpp and
// src/ringct/rctTypes.h (BSD-3-Clause). See PROVENANCE.md in this directory.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/rct/xmr_rct_ops.hpp
//
// The scalar and group helpers the non-input consensus checks need, over the
// ed25519 arithmetic already vendored byte-for-byte at
// src/impl/xmr/coin/vendor/crypto-ops.c and reached through `xmr_coin`.
//
// ONE rule shapes every signature here: the input is bytes an unauthenticated
// peer chose. Upstream's helpers throw (`CHECK_AND_ASSERT_THROW_MES`) when a
// point fails to decode, and monerod catches those throws several frames up.
// Everything here returns bool instead, so a malformed point is a verdict and
// never an exception on the relay path.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace c2pool::xmr::native::rct {

// A curve point or a scalar, in its 32-byte canonical encoding. Upstream calls
// this `rct::key`; the STL array carries its own size and compares by value.
using Key  = std::array<std::uint8_t, 32>;
using KeyV = std::vector<Key>;

// --- constants ---------------------------------------------------------------
// The identity point (the encoding of the neutral element), the two generators,
// 8^-1 mod l, -1 mod l and the curve order l. All of these are DATA from
// upstream (rctOps.h / rctTypes.h / bulletproofs_plus.cc), not algorithm.
const Key& identity() noexcept;
const Key& scalar_zero() noexcept;
const Key& scalar_one() noexcept;
const Key& inv_eight() noexcept;
const Key& minus_one() noexcept;
const Key& curve_order() noexcept;

// G is the ed25519 base point; H = toPoint(cn_fast_hash(G)) is the value
// generator every amount commitment is denominated in. Both are available as
// p3 points without a decode, so no verification path pays for them.
const Key&   generator_G() noexcept;
const Key&   generator_H() noexcept;
const ge_p3& generator_G_p3() noexcept;
const ge_p3& generator_H_p3() noexcept;

// --- hashing -----------------------------------------------------------------
// Keccak-256 (monerod's cn_fast_hash) over arbitrary bytes, and the same
// reduced into a scalar. `hash_to_scalar(KeyV)` hashes the concatenation, which
// is how the Bulletproof+ transcript absorbs a vector of commitments.
Key cn_fast_hash(const void* data, std::size_t len) noexcept;
Key hash_to_scalar(const void* data, std::size_t len) noexcept;
Key hash_to_scalar(const KeyV& keys) noexcept;

// Hash-to-point: cn_fast_hash, then the Elligator-style map, then multiply by
// the cofactor so the result is in the prime-order subgroup by construction.
void hash_to_p3(ge_p3& out, const Key& k) noexcept;

// --- scalars -----------------------------------------------------------------
bool scalar_is_reduced(const Key& s) noexcept;      // sc_check == 0
bool scalar_is_zero(const Key& s) noexcept;

Key sc_mul_k(const Key& a, const Key& b) noexcept;
Key sc_add_k(const Key& a, const Key& b) noexcept;
Key sc_sub_k(const Key& a, const Key& b) noexcept;
Key sc_muladd_k(const Key& a, const Key& b, const Key& c) noexcept;   // a*b + c

// Inverse mod l by Fermat, using upstream's addition chain. Undefined for zero,
// which every caller checks first.
Key scalar_invert(const Key& x) noexcept;
// Batch inverse: one field inversion for the whole vector (Montgomery's trick).
// Returns false if any element is zero, in which case `x` is left untouched.
bool scalar_batch_invert(KeyV& x) noexcept;

// --- points ------------------------------------------------------------------
// Decode. False means the bytes are not a valid point encoding.
bool point_decode(ge_p3& out, const Key& k) noexcept;
Key  point_encode(const ge_p3& p) noexcept;

// 8*P, decoding P first. This is how every offset proof element is rescaled
// into the prime-order subgroup before it is used.
bool scalarmult8(ge_p3& out, const Key& P) noexcept;

// a*H, the value half of a Pedersen commitment.
Key scalarmult_H(const Key& a) noexcept;

// a*P for an arbitrary point. False when P is not a point. This is upstream's
// scalarmultKey, and the one caller that matters is the reconstruction of a
// range proof's commitment vector from the transaction's own output
// commitments (V_i = outPk_i * 8^-1).
bool scalarmult_key(Key& out, const Key& P, const Key& a) noexcept;

// Sum of a vector of points; false if any element fails to decode. Upstream's
// addKeys(keyV) throws in that case.
bool add_keys(const KeyV& points, Key& out) noexcept;

// Is the point in the prime-order subgroup? This is upstream's
// toPointCheckOrder, and it is exactly the key-image domain check monerod runs
// in check_tx_inputs_keyimages_domain -- a check that needs no chain state at
// all, which is why it belongs to the non-input consensus evidence.
bool in_main_subgroup(const Key& P) noexcept;

// --- amounts -----------------------------------------------------------------
// A 64-bit amount as a scalar (little-endian in the low 8 bytes). Upstream d2h.
Key amount_to_scalar(std::uint64_t amount) noexcept;

// --- randomness --------------------------------------------------------------
// A nonzero random scalar, used ONLY as the per-proof weight in the batched
// verification identity. It is not a secret and it is not consensus: any
// nonzero value makes the batch sound.
Key random_scalar_nonzero();

} // namespace c2pool::xmr::native::rct
