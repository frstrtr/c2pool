// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/rctSigs.cpp
// (verRctSemanticsSimple) and src/cryptonote_core/cryptonote_core.cpp
// (key-image domain), BSD-3-Clause. See PROVENANCE.md in this directory.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/rct/xmr_rct_verify.hpp
//
// NON-INPUT CONSENSUS: everything monerod checks about a transaction that does
// NOT require knowing which outputs exist or which key images have already been
// spent.
//
// This is the exact line ruling R-VAL draws. On one side (here):
//
//   * shape -- one range proof, commitments and ecdh entries matching the
//     output count, pseudo-outputs matching the input count;
//   * commitment balance -- sum(pseudoOuts) == sum(outPk) + fee*H, which is
//     what makes an inflated or negative output amount detectable;
//   * range proofs -- Bulletproofs+, which is what makes an out-of-range
//     amount detectable;
//   * key-image domain -- every key image is in the prime-order subgroup,
//     which is a property of the image alone.
//
// On the other side (NOT here, and not implementable without the chain): the
// CLSAG signature over the ring members, and whether any key image has been
// spent before. A pool that admits a double spend loses nothing but the fee of
// one transaction in one template; a pool that admits a BAD-VALUE transaction
// mines a block the network rejects. That asymmetry is the whole argument for
// where this line sits.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "xmr_bulletproofs_plus.hpp"
#include "xmr_rct_ops.hpp"

namespace c2pool::xmr::native::rct {

// rct type tags (monero-project src/ringct/rctTypes.h). Only BulletproofPlus is
// verifiable here; see the fence in PROVENANCE.md.
inline constexpr std::uint8_t RCT_TYPE_NULL             = 0;
inline constexpr std::uint8_t RCT_TYPE_BULLETPROOF_PLUS = 6;

// Everything the checks below need, as decoded from a transaction blob.
struct RctNonInput {
    std::uint8_t  rct_type = RCT_TYPE_NULL;
    std::uint64_t fee      = 0;

    KeyV outPk;        // one commitment per output, from the rct base
    KeyV pseudoOuts;   // one per input, from the prunable part
    KeyV key_images;   // one per input, from the prefix
    // Entries in the rct base. The relay decoder derives the ecdh span FROM the
    // output count, so for it this is equal by construction; the check exists
    // for the other producers of this struct (the parity oracle builds one by
    // hand), which is where a disagreement could actually arise.
    std::size_t ecdh_count = 0;

    std::vector<BulletproofPlus> bpp;   // exactly one for a BulletproofPlus tx
};

enum class RctVerifyStatus : std::uint8_t {
    Ok = 0,
    UnsupportedType,   // not RCTTypeBulletproofPlus: fail-closed, never guessed
    ShapeMismatch,     // vector sizes disagree with the input/output counts
    BadPoint,          // a commitment or pseudo-output is not a curve point
    SumMismatch,       // sum(pseudoOuts) != sum(outPk) + fee*H
    RangeProofFail,    // Bulletproof+ verification failed
    KeyImageDomain,    // a key image is outside the prime-order subgroup
};

const char* to_string(RctVerifyStatus s) noexcept;

// Runs the checks in monerod's order, so a rejection reason is comparable with
// what monerod would have said. `in.bpp[0].V` is REBUILT here from `in.outPk`
// (never taken from the wire) -- that reconstruction is what binds the range
// proof to the commitments the balance check sums.
RctVerifyStatus verify_non_input_consensus(RctNonInput& in);

} // namespace c2pool::xmr::native::rct
