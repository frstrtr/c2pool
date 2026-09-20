// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/rctSigs.cpp
// (verRctCLSAGSimple, get_pre_mlsag_hash), src/ringct/rctOps.cpp
// (addKeys_aGbBcC, addKeys_aAbBcC, precomp) and
// src/device/device_default.cpp (mlsag_prehash), BSD-3-Clause. See
// PROVENANCE.md in this directory.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/rct/xmr_clsag_verify.hpp
//
// INPUT CONSENSUS, the signature half: the CLSAG ring signature over the ring
// members. This is the check the non-input consensus (xmr_rct_verify) could not
// do, and it is the one that decides whether a REAL, owned input was spent --
// the difference between a daemonless node that mines what the network will
// accept and an SPV-mining relay that trusts the sender.
//
// It verifies; it never signs. A pool has no spend keys and proves nothing. The
// only new trust surface over the non-input half is the ring MEMBERS the
// signature is checked against, which the caller must resolve from the chain
// (contracts/outputs.hpp IRingMemberSource) -- this file takes them as given.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "xmr_bulletproofs_plus.hpp"
#include "xmr_rct_ops.hpp"

namespace c2pool::xmr::native::rct {

// A ring member as monerod's `ctkey`: the one-time output public key and its
// amount commitment, exactly the pair the signature is aggregated over.
struct CtKey {
    Key dest;   // the output one-time public key
    Key mask;   // the output amount commitment C
};

// A CLSAG signature, as it sits in the prunable part plus the key image the
// prefix already carried. `s` has one scalar per ring member; `c1` is the
// challenge seed; `D` is the (unscaled) auxiliary key image; `I` is the key
// image from the input.
struct Clsag {
    KeyV s;
    Key  c1{};
    Key  D{};
    Key  I{};
};

enum class ClsagStatus : std::uint8_t {
    Ok = 0,
    ShapeMismatch,    // ring empty, or |s| != |ring|
    BadScalar,        // a signature scalar (s[i] or c1) is not reduced mod l
    BadKeyImage,      // I is the identity point
    BadAuxKeyImage,   // 8*D is the identity point
    BadPoint,         // C_offset, I, D or a ring dest is not a curve point
    BadCommitment,    // a ring member's commitment is not a curve point
    BadHash,          // a round challenge reduced to zero
    SigMismatch,      // the ring equation did not close (c_n != c1)
};

const char* to_string(ClsagStatus s) noexcept;

// verRctCLSAGSimple, verify-only. `message` is the pre-MLSAG hash (see
// clsag_message below), `ring` the resolved members, `pseudo_out` the input's
// commitment offset (C_offset). Never throws: a malformed point an
// unauthenticated peer chose is a verdict, not an exception.
ClsagStatus verify_clsag(const Key& message, const Clsag& sig,
                         const std::vector<CtKey>& ring, const Key& pseudo_out) noexcept;

// The pre-MLSAG hash a BulletproofPlus transaction's CLSAGs are signed under:
//
//   message = cn_fast_hash( H(prefix) || H(rct base) || cn_fast_hash(bpp span) )
//
// where the bpp span is A,A1,B,r1,s1,d1 followed by L[] then R[] (V is NOT
// hashed -- it is expanded from outPk, which the rct base already covers). The
// two leading hashes are the ones the decoder already measured, so this adds
// exactly the third Keccak monerod folds in through get_pre_mlsag_hash.
Key clsag_message(const Key& prefix_hash, const Key& rct_base_hash,
                  const BulletproofPlus& bpp) noexcept;

} // namespace c2pool::xmr::native::rct
