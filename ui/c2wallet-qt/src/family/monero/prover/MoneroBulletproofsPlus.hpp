// Copyright (c) 2017-2026, The Monero Project
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
// src/impl/xmr/coin/xmr_derivation.cpp (same upstream family of files).
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/prover/MoneroBulletproofsPlus.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/ringct/bulletproofs_plus.cc
//              (bulletproof_plus_PROVE and its helpers vector_exponent,
//              compute_LR, weighted_inner_product, hadamard_fold, invert,
//              transcript_update, and the exponent/transcript init in
//              init_exponents). The scheme is Bulletproofs+ (eprint 2020/735),
//              the range proof monerod has used since HF15.
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the PROVER half only, re-expressed over the in-tree RingCT
//              scalar/point helpers (src/impl/xmr/native/rct/xmr_rct_ops.hpp)
//              and multi-scalar mult (xmr_multiexp.hpp) that already back the
//              in-tree VERIFIER. No curve or hash math is reimplemented here.
//
// This is the M4-X money-path range-proof PROVER for Family B (design §4.2
// step 4): it proves each output amount lies in [0, 2^64) WITHOUT revealing it.
// c2pool ported only the VERIFIER of Bulletproofs+ (a pool never constructs a
// range proof); this file adds the prover the offline wallet needs, and the
// KAT gate is construct -> in-tree verify, the independent oracle the design
// calls for (stronger than CLSAG's construct->ported-verify, since here the
// verifier is separate, node-consensus code).
//
// MONEY-SAFETY: every secret nonce this prover draws -- the mask commitment
// nonce alpha, the per-round blinding scalars dL/dR, and the final-round
// r/s/d/eta -- comes from the wallet-local CSPRNG (MoneroProverRng,
// getrandom(2)-backed), NEVER the node helper random_scalar_nonzero() which is
// mt19937-seeded. Bulletproofs+ publishes L/R/A1/B/r1/s1/d1, all algebraically
// bound to those nonces; a predictable RNG here would leak the output masks and
// hence the amounts. The output blinding masks (gamma) are supplied by the
// caller and are themselves required to be CSPRNG-drawn (see MoneroRingctBuilder).
// ===========================================================================
#pragma once

#include <cstdint>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"     // Bytes32
#include "xmr_bulletproofs_plus.hpp"          // c2pool::xmr::native::rct::BulletproofPlus (the in-tree verifier's type)

namespace c2wallet::monero::prover {

// The proof type is the exact struct the in-tree verifier consumes, so a proof
// this prover builds is handed straight to verify_bulletproof_plus() with no
// re-encoding -- that identity is what makes the construct->verify KAT a real
// oracle rather than a mirror.
using BulletproofPlus = c2pool::xmr::native::rct::BulletproofPlus;

// Construct a Bulletproofs+ range proof aggregating `amounts` (each < 2^64) with
// blinding masks `masks` (gamma). Faithful port of bulletproof_plus_PROVE.
//
//   * amounts.size() == masks.size(), in [1, 16] (BULLETPROOF_PLUS_MAX_OUTPUTS).
//   * each mask MUST be a canonical, CSPRNG-drawn ed25519 scalar; the caller
//     (RingCT assembly) draws them with csprng_scalar_nonzero().
//   * proof.V[i] == 8^-1 * (masks[i]*G + amounts[i]*H), i.e. 8^-1 times the
//     amount commitment commit(amounts[i], masks[i]); the verifier rescales by
//     8, which is how the proof binds to the transaction's output commitments.
//
// Returns false on a bad shape or a non-reduced mask; true with `out` filled on
// success. All internal secret nonces are wiped from the stack before return.
bool prove_range(const std::vector<std::uint64_t>& amounts,
                 const std::vector<Bytes32>& masks,
                 BulletproofPlus& out);

} // namespace c2wallet::monero::prover
