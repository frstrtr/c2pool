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
// src/impl/xmr/coin/xmr_derivation.cpp (same upstream family of files).
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/multisig/MoneroMultisigSign.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/ringct/rctSigs.cpp (CLSAG_Gen), the
//              multi-party split of the CLSAG signing nonce and response as
//              performed by src/multisig/multisig* and device_default's
//              clsag_prepare/clsag_hash/clsag_sign when driven with a shared
//              nonce and a split secret key. The CLSAG scheme is Goodell et al.
//              (eprint 2019/654).
//   License  : BSD-3-Clause (header above).
//   Subset   : the COOPERATIVE (partial) CLSAG signer -- the multi-party layer
//              on top of the single-sig M3-X MoneroClsag signer. The ring hash
//              loop mirrors MoneroClsag.cpp CLSAG_Gen exactly (same domain tags,
//              same hash ordering) so the combined signature verifies under the
//              in-tree/M3-X verifier clsag_verify() unchanged. It drives the
//              already-vendored ed25519/Keccak engine and the in-tree RingCT
//              ops (src/impl/xmr/native/rct/xmr_rct_ops); no curve/hash math is
//              reimplemented.
//
//   *** EXPERIMENTAL ***  Not wired to the UI; needs independent review.
//
// THE MULTI-PARTY ALGEBRA (why this verifies with the stock verifier):
//   Single-sig CLSAG's real-index scalar is  s[l] = a - c*(mu_P*x + mu_C*z),
//   with signing nonce a, real one-time secret x, commitment-to-zero mask z.
//   In multisig x = known_part + Sum_j pp_j  (pp_j = the subset secrets signer
//   j contributes for this quorum; known_part = H_s(derivation||out_idx), which
//   every cosigner can derive). Each signer j draws its OWN nonce a_j and keeps
//   it secret; the group uses a = Sum_j a_j. The key image likewise splits:
//   I = x*H = Sum_j (pp_j*H)  (+known_part*H by the coordinator). Each signer's
//   Round-2 response is  s_j = a_j - c*mu_P*pp_j  (the coordinator additionally
//   subtracts c*mu_P*known_part + c*mu_C*z), and s[l] = Sum_j s_j reproduces the
//   single-sig scalar exactly. The decoy scalars s[i!=l], c1, I and D are fixed
//   by the coordinator and travel to all; the final verify rejects any that
//   were altered.
//
// MONEY-SAFETY (the M3-X lesson, doubly critical here): every signer's nonce
// a_j comes from the wallet-local CSPRNG csprng_scalar_nonzero(); NEVER
// random_scalar_nonzero()/mt19937. A REUSED a_j across two signings with
// different challenges leaks pp_j (two linear equations in a_j and pp_j) and
// thus a key share, so nonces MUST be fresh per signing. Nonces and shares live
// in zeroizing storage and are wiped after Round 2.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"                // Bytes32
#include "family/monero/prover/MoneroClsag.hpp"          // CtKey, Clsag
#include "family/monero/multisig/MoneroMultisig.hpp"     // SignerShares

namespace c2wallet::monero::multisig {

using c2wallet::monero::Bytes32;
using prover::CtKey;
using prover::Clsag;

// Public, shared per-input signing context. All cosigners agree on it.
struct SigningSession {
    Bytes32            message{};     // pre-MLSAG hash (CLSAG message)
    std::vector<CtKey> ring;          // dest=P_i, mask=C_nonzero_i
    std::size_t        real_index{0}; // l -- position of the owned member
    Bytes32            Cout{};        // pseudo-output commitment (C_offset)
    Bytes32            H{};           // H_p(P[l]) -- cached basepoint for images
};

// Build the shared context (decodes P[l] and caches H). False on a bad index /
// undecodable real-member point.
bool make_signing_session(const Bytes32& message,
                          const std::vector<CtKey>& ring,
                          std::size_t real_index,
                          const Bytes32& Cout,
                          SigningSession& out);

// Given a signer's full share set and the set of participant indices actually
// signing (the quorum), return the subset secrets THIS signer contributes, with
// no double counting: a subset is contributed by its lowest-index member that
// is in the quorum. For N/N this is always the signer's single own share.
std::vector<Bytes32> assigned_shares(const SignerShares& shares,
                                     const std::vector<std::uint32_t>& quorum);

// A signer's secret per-signing nonce. Wiped on destruction / by Round 2.
struct CosignerNonce {
    Bytes32 alpha{};
    bool    live{false};
    ~CosignerNonce();
};

// A signer's Round-1 public broadcast: its nonce commitments and partial image.
struct PartialNonce {
    std::uint32_t signer_index{0};
    Bytes32       alpha_G{};    // a_j * G
    Bytes32       alpha_H{};    // a_j * H
    Bytes32       partial_ki{}; // pp_j * H  (+ known_part*H if coordinator)
};

// Round 1 for one signer. Draws a fresh CSPRNG nonce (stored in `nonce_out`),
// and publishes the commitments. `assigned` are this signer's contributed
// subset secrets (from assigned_shares). `known_part` is non-null ONLY for the
// coordinator (the quorum's lowest index), folding H_s(derivation||idx) into
// the partial key image so Sum(partial_ki) == the full key image. Returns false
// on a decode error.
bool cosigner_round1(const SigningSession& s,
                     std::uint32_t signer_index,
                     const std::vector<Bytes32>& assigned,
                     const Bytes32* known_part,
                     PartialNonce& out,
                     CosignerNonce& nonce_out);

// Coordinator's Round-1 combine: aggregates the nonce commitments and partial
// images, computes the key image I, the auxiliary image D=z*H (D/8 published),
// the aggregation scalars mu_P/mu_C, draws the decoy scalars s[i!=l] from the
// CSPRNG, walks the CLSAG ring hash to the real index, and yields the challenge
// c_at_l the responses will use. `z` (= c_a - c_out) is the coordinator's
// commitment-to-zero mask. False on any decode error.
struct Round1Combined {
    Bytes32              I{};        // sig.I  = x*H
    Bytes32              D{};        // sig.D  = (z*H)/8   (published form)
    Bytes32              mu_P{};
    Bytes32              mu_C{};
    Bytes32              c_at_l{};   // challenge feeding every response
    Bytes32              c1{};       // CLSAG anchor
    std::vector<Bytes32> s;          // decoys filled; s[real_index] left zero
};
bool coordinator_combine_round1(const SigningSession& s,
                                const std::vector<PartialNonce>& nonces,
                                const Bytes32& z,
                                Round1Combined& out);

// Round 2 for one signer: response s_j = a_j - c*mu_P*pp_j (coordinator also
// subtracts c*mu_P*known_part + c*mu_C*z). Consumes and wipes the nonce.
// `known_part` and `z` are non-null ONLY for the coordinator.
Bytes32 cosigner_round2(const Bytes32& c_at_l,
                        const Bytes32& mu_P,
                        const Bytes32& mu_C,
                        const std::vector<Bytes32>& assigned,
                        const Bytes32* known_part,
                        const Bytes32* z,
                        CosignerNonce& nonce);

// Coordinator's Round-2 combine: s[real_index] = Sum of responses; assembles
// the full CLSAG. The result verifies via prover::clsag_verify unchanged.
// Returns false if the response count is zero.
bool coordinator_combine_round2(const SigningSession& s,
                                const Round1Combined& r1,
                                const std::vector<Bytes32>& responses,
                                Clsag& out);

} // namespace c2wallet::monero::multisig
