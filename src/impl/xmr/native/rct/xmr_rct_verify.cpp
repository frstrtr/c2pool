// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/rctSigs.cpp
// (verRctSemanticsSimple), BSD-3-Clause. See PROVENANCE.md in this directory.
// ---------------------------------------------------------------------------
#include "xmr_rct_verify.hpp"

namespace c2pool::xmr::native::rct {

const char* to_string(RctVerifyStatus s) noexcept {
    switch (s) {
        case RctVerifyStatus::Ok:              return "Ok";
        case RctVerifyStatus::UnsupportedType: return "UnsupportedType";
        case RctVerifyStatus::ShapeMismatch:   return "ShapeMismatch";
        case RctVerifyStatus::BadPoint:        return "BadPoint";
        case RctVerifyStatus::SumMismatch:     return "SumMismatch";
        case RctVerifyStatus::RangeProofFail:  return "RangeProofFail";
        case RctVerifyStatus::KeyImageDomain:  return "KeyImageDomain";
    }
    return "?";
}

RctVerifyStatus verify_non_input_consensus(RctNonInput& in) {
    if (in.rct_type != RCT_TYPE_BULLETPROOF_PLUS) return RctVerifyStatus::UnsupportedType;

    // --- shape ---------------------------------------------------------------
    if (in.bpp.size() != 1)                        return RctVerifyStatus::ShapeMismatch;
    if (in.outPk.empty())                          return RctVerifyStatus::ShapeMismatch;
    if (in.outPk.size() != in.ecdh_count)          return RctVerifyStatus::ShapeMismatch;
    if (in.pseudoOuts.empty())                     return RctVerifyStatus::ShapeMismatch;
    if (in.pseudoOuts.size() != in.key_images.size()) return RctVerifyStatus::ShapeMismatch;
    if (in.outPk.size() > BULLETPROOF_PLUS_MAX_OUTPUTS) return RctVerifyStatus::ShapeMismatch;
    // The proof must be able to carry this many amounts: 2**(|L|-6) >= n_out.
    if (bulletproof_plus_max_amounts(in.bpp[0]) < in.outPk.size())
        return RctVerifyStatus::ShapeMismatch;

    // --- key-image domain ----------------------------------------------------
    // A key image outside the prime-order subgroup is a forgery vector that
    // needs no chain state to detect, so it belongs here rather than with the
    // spent-set check the pool cannot do.
    for (const Key& ki : in.key_images)
        if (!in_main_subgroup(ki)) return RctVerifyStatus::KeyImageDomain;

    // --- commitment balance --------------------------------------------------
    // sum(pseudoOuts) == sum(outPk) + fee*H. The fee is plaintext, so this one
    // equality is what stops a transaction from creating money.
    Key sum_out{};
    if (!add_keys(in.outPk, sum_out)) return RctVerifyStatus::BadPoint;

    const Key fee_key = scalarmult_H(amount_to_scalar(in.fee));
    Key       sum_out_plus_fee{};
    if (!add_keys(KeyV{sum_out, fee_key}, sum_out_plus_fee)) return RctVerifyStatus::BadPoint;

    Key sum_pseudo{};
    if (!add_keys(in.pseudoOuts, sum_pseudo)) return RctVerifyStatus::BadPoint;

    if (sum_pseudo != sum_out_plus_fee) return RctVerifyStatus::SumMismatch;

    // --- range proofs --------------------------------------------------------
    // V is rebuilt from outPk, never read from the wire (see the header): a
    // proof verified against commitments it supplied itself would say nothing
    // about the amounts this transaction actually pays out.
    BulletproofPlus& proof = in.bpp[0];
    proof.V.resize(in.outPk.size());
    for (std::size_t i = 0; i < in.outPk.size(); ++i)
        if (!scalarmult_key(proof.V[i], in.outPk[i], inv_eight()))
            return RctVerifyStatus::BadPoint;

    if (!verify_bulletproof_plus(proof)) return RctVerifyStatus::RangeProofFail;

    return RctVerifyStatus::Ok;
}

} // namespace c2pool::xmr::native::rct
