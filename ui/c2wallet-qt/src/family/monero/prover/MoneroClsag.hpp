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
// ui/c2wallet-qt/src/family/monero/prover/MoneroClsag.hpp
//
// PROVENANCE (per c2pool porting rule LIC-1):
//   Upstream : monero-project/monero  src/ringct/rctSigs.cpp
//              (CLSAG_Gen, proveRctCLSAGSimple, verRctCLSAGSimple),
//              src/device/device_default.cpp
//              (clsag_prepare, clsag_hash, clsag_sign), and
//              src/ringct/rctOps.cpp (scalarmultKey, scalarmult8,
//              addKeys_aGbBcC, addKeys_aAbBcC, subKeys, commit). The CLSAG
//              construction follows Goodell et al. (eprint 2019/654), the
//              scheme monerod has used for every RingCT input since v12.
//   License  : BSD-3-Clause (header above; full text in xmr_derivation.cpp).
//   Subset   : the CLSAG signer + verifier, re-expressed over c2wallet's
//              32-byte Bytes32 alias and driven through the SAME already-
//              vendored ed25519/Keccak engine
//              (src/impl/xmr/coin/vendor/crypto-ops.{c,h}) and the in-tree
//              RingCT scalar/point helpers
//              (src/impl/xmr/native/rct/xmr_rct_ops.{hpp,cpp}:
//              hash_to_scalar, hash_to_p3, scalarmult_key, inv_eight, ...).
//              No curve or hash math is reimplemented here.
//
// This is the OFFLINE money-path SIGNER for Family B (design §4.2 steps 5-6):
// it proves, without revealing the real ring member, knowledge of a one-time
// secret x for P[l]=x*G and that the key image I=x*H_p(P[l]) is well formed,
// while also binding the amount commitment offset. c2pool ported only the
// VERIFY half of RingCT (non-input consensus); there is no in-tree CLSAG
// verifier (verifying CLSAG needs the chain's ring members), so this file
// ports both sign and verify and the KAT is a construct->verify round-trip,
// exactly the strong correctness harness design §4.2 calls for.
//
// Bulletproofs+ range proofs and full RingCT transaction assembly are M4-X and
// are deliberately NOT in this file.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"   // Bytes32

namespace c2wallet::monero::prover {

// One ring member as monerod carries it (rct::ctkey): the output one-time
// public key and its amount commitment.
struct CtKey {
    Bytes32 dest{};   // P_i  (output one-time public key)
    Bytes32 mask{};   // C_i  (amount commitment, "C_nonzero")
};

// A CLSAG signature over a ring (rct::clsag). `s` has one scalar per ring
// member; `c1` is the round-hash anchor; `I` is the key image; `D` is the
// scaled auxiliary image (z*H_p(P[l]) * 1/8) that binds the commitment offset.
struct Clsag {
    std::vector<Bytes32> s;
    Bytes32              c1{};
    Bytes32              I{};
    Bytes32              D{};
};

// Amount commitment C = mask*G + amount*H (rct::commit). Exposed so a caller /
// KAT can build ring commitments and pseudo-outputs without touching raw ops.
Bytes32 commit(std::uint64_t amount, const Bytes32& mask);

// CLSAG_Gen, faithfully. Keys are set as in upstream:
//   P[l]        == p*G                        (p = one-time secret of the real member)
//   C[l]        == z*G                        (z = commitment-to-zero secret)
//   C[i]        == C_nonzero[i] - C_offset     (for all i, hashing purposes)
// `p` and `z` are secret and wiped from the stack before return. Returns false
// on a size mismatch, an out-of-range index, or a point that fails to decode.
bool clsag_gen(const Bytes32& message,
               const std::vector<Bytes32>& P,
               const Bytes32& p,
               const std::vector<Bytes32>& C,
               const Bytes32& z,
               const std::vector<Bytes32>& C_nonzero,
               const Bytes32& C_offset,
               std::size_t l,
               Clsag& out);

// proveRctCLSAGSimple, faithfully: the per-input signer as a RingCT spend uses
// it. `ring` carries (dest=P_i, mask=C_a_i) for every member; `p` is the real
// member's one-time secret; `c_a` the real amount commitment mask; `c_out` the
// pseudo-output mask and `Cout` the pseudo-output commitment (C_offset). It
// forms z = c_a - c_out internally and signs. Secrets are wiped before return.
bool clsag_prove_simple(const Bytes32& message,
                        const std::vector<CtKey>& ring,
                        const Bytes32& p,
                        const Bytes32& c_a,
                        const Bytes32& c_out,
                        const Bytes32& Cout,
                        std::size_t index,
                        Clsag& out);

// verRctCLSAGSimple, faithfully: the in-tree construct->verify oracle. Returns
// true iff `sig` is a valid CLSAG over `ring` for `message` with commitment
// offset `C_offset`. Never throws (a malformed point is a false verdict).
bool clsag_verify(const Bytes32& message,
                  const Clsag& sig,
                  const std::vector<CtKey>& ring,
                  const Bytes32& C_offset);

} // namespace c2wallet::monero::prover
