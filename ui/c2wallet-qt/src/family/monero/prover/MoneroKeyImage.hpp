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
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/prover/MoneroKeyImage.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/crypto/crypto.cpp
//              (generate_key_image, generate_ring_signature,
//              check_ring_signature) and src/wallet/wallet2.cpp
//              (export_key_images: the {key_image, ring-signature} artifact).
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the offline key-image export path. The key image itself
//              (I = x*H_p(P)) delegates to the already-vendored recipe in
//              scanops::generate_key_image (byte-exact to monero-project
//              tests/crypto/tests.txt); the exportable ownership signature is
//              the CryptoNote one-out-of-n ring signature ported over the
//              vendored ed25519 engine. No curve or hash math reimplemented.
//
// This is the OFFLINE->ONLINE artifact of Monero's native cold-signing flow
// (design §4.2 / §5.4): the offline FULL wallet computes each owned output's
// key image and a public signature proving it, and hands {I_i, sig} to the
// online view-only side so it can mark outputs spent and compute balance. A
// VIEW-ONLY wallet has no spend secret k_s, so it cannot form x_i and therefore
// cannot produce a key image at all -- the reason cold signing exists. That
// split is enforced here structurally: export refuses without can_sign().
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"     // Bytes32
#include "family/monero/MoneroKey.hpp"        // MoneroKeys
#include "family/monero/scan/MoneroScanner.hpp" // ExportedOutput

namespace c2wallet::monero::prover {

// A CryptoNote ring-signature element c||r (two 32-byte scalars).
using RingSigElem = std::array<std::uint8_t, 64>;

// The public offline->online key-image artifact for one owned output.
struct ExportedKeyImage {
    Bytes32     one_time_pub{};   // P_i
    Bytes32     image{};          // I_i = x_i * H_p(P_i)
    RingSigElem signature{};      // ring sig over {P_i}, message = I_i bytes
};

struct KeyImageExportResult {
    bool                          ok{false};
    std::string                   error;
    std::vector<ExportedKeyImage> images;
};

// Export key images for a set of owned outputs. FULL WALLET ONLY: returns
// ok=false with an error if `keys` is view-only (no spend secret). For each
// output it recomputes D = 8*k_v*R, the one-time secret
// x_i = H_s(D||i) + k_s (+ subaddress secret m), the image I_i = x_i*H_p(P_i),
// and a ring signature that proves the image without revealing x_i. The secret
// x_i is wiped from the stack after use.
KeyImageExportResult export_key_images(const MoneroKeys& keys,
                                       const std::vector<ExportedOutput>& outs);

// Verify a single exported key image (the online-side check): the ring
// signature over {P_i} with message = image must hold, and the image must be
// in the prime-order subgroup (monerod's key-image domain check).
bool check_exported_key_image(const ExportedKeyImage& e);

// --- ported primitives, exposed for the KAT ---------------------------------

// CryptoNote one-out-of-n ring signature (crypto.cpp generate_ring_signature).
// `sec` is the secret for pubs[sec_index]; message is `prefix_hash`. Wipes its
// nonce. Returns false if a point fails to decode.
bool generate_ring_signature(const Bytes32& prefix_hash, const Bytes32& image,
                             const std::vector<Bytes32>& pubs,
                             const Bytes32& sec, std::size_t sec_index,
                             std::vector<RingSigElem>& sigs);

// The matching verifier (crypto.cpp check_ring_signature).
bool check_ring_signature(const Bytes32& prefix_hash, const Bytes32& image,
                          const std::vector<Bytes32>& pubs,
                          const std::vector<RingSigElem>& sigs);

} // namespace c2wallet::monero::prover
