// Copyright (c) 2014-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. See the full BSD-3 text preserved in
// src/impl/xmr/coin/xmr_derivation.cpp (same upstream file).
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/scan/MoneroScanOps.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/crypto/crypto.cpp  (derive_subaddress_public_key,
//              hash_to_ec, generate_key_image, derive_secret_key) and
//              src/ringct/rctOps.cpp  (ecdhHash / genCommitmentMask, the v2 "short"
//              ecdhDecode amount recipe).
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the function BODIES below are the verbatim CryptoNote / RingCT recipes,
//              re-expressed over c2wallet's 32-byte Bytes32 alias and driven through the
//              SAME already-vendored ed25519/Keccak engine
//              (src/impl/xmr/coin/vendor/crypto-ops.{c,h}, hash-ops, keccak) and the
//              in-tree derivation subset xmr::coin (xmr_derivation.{hpp,cpp}). No curve
//              or hash math is reimplemented here.
//   Reuse    : key_derivation / derivation_to_scalar / derive_public_key / view_tag
//              delegate straight to xmr::coin. Only the composite ops NOT present in
//              xmr_derivation (subaddress-public-key, key image, one-time secret key,
//              RingCT amount ecdh) are added, as monero emits them.
//
// This is the Qt-free money-relevant read path for output scanning (design §4.2). It is
// the ONLY file in the Family B scanner that touches raw ge_*/sc_*; the scanner proper
// (MoneroScanner) stays in Bytes32 terms.
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "family/monero/MoneroCrypto.hpp"   // Bytes32

namespace c2wallet::monero::scanops {

// D = 8 * view_sec * R  (generate_key_derivation). false if R is not a point or
// view_sec is not a canonical scalar. Delegates to xmr::coin.
bool key_derivation(const Bytes32& R, const Bytes32& view_sec, Bytes32& D);

// s_i = H_s(D || varint(i)) reduced mod l. Delegates to xmr::coin.
Bytes32 derivation_to_scalar(const Bytes32& D, std::uint64_t output_index);

// P_i = s_i*G + base. false if base is not a point. Delegates to xmr::coin. The
// direct ownership predicate: derive_public_key(D,i,K_s) == P_i.
bool derive_public_key(const Bytes32& D, std::uint64_t output_index,
                       const Bytes32& base, Bytes32& P);

// First byte of H("view_tag" || D || varint(i)). Delegates to xmr::coin.
std::uint8_t view_tag(const Bytes32& D, std::uint64_t output_index);

// subaddress spend pubkey candidate = P_i - s_i*G  (crypto.cpp
// derive_subaddress_public_key). Looked up in the precomputed spend table to
// detect BOTH the main address (index 0,0 -> K_s) and any subaddress. false if
// P_i is not a point.
bool derive_subaddress_public_key(const Bytes32& one_time_pub, const Bytes32& D,
                                  std::uint64_t output_index, Bytes32& out);

// x_i = s_i + base_sec (mod l)  (crypto.cpp derive_secret_key). The one-time
// SECRET key; requires the spend secret -> full wallet only. For a subaddress
// output the caller adds the subaddress secret m afterwards (mcrypto::scalar_add).
Bytes32 derive_secret_key(const Bytes32& D, std::uint64_t output_index,
                          const Bytes32& base_sec);

// I = x_i * H_p(P_i)  (crypto.cpp generate_key_image; hash_to_ec = ge_fromfe of
// Keccak(P), *8). false if x_i is not canonical or P_i is not a point. The key
// image is computable ONLY with a spend secret (via x_i) -> the reason cold
// signing exists.
bool generate_key_image(const Bytes32& one_time_pub, const Bytes32& one_time_sec,
                        Bytes32& image);

// RingCT v2 "short" amount ecdh (rctOps.cpp). shared = derivation_to_scalar(D,i).
//   amount_out = masked_amount XOR Keccak("amount" || shared)[0:8]   (one Keccak)
// commitment_mask(shared) = H_s("commitment_mask" || shared)          (one Keccak)
// -> two Keccak calls + an 8-byte xor, exactly design §4.2.
std::uint64_t ecdh_decode_amount(const std::array<std::uint8_t, 8>& masked,
                                 const Bytes32& shared_secret);
Bytes32 commitment_mask(const Bytes32& shared_secret);

// The sender side of the same short ecdh, present ONLY so a construct->scan KAT
// can prove decode is the exact inverse of encode (never used by the scanner).
std::array<std::uint8_t, 8> ecdh_encode_amount(std::uint64_t amount,
                                               const Bytes32& shared_secret);

} // namespace c2wallet::monero::scanops
