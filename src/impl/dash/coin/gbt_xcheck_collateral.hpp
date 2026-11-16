#pragma once
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GBT-xcheck: LABEL a merkleRootMNList difference between the embedded
// template and dashd's getblocktemplate when it is explained, EXACTLY, by the
// masternode-collateral spends our builder excludes by design.
//
// Why a difference can be legitimate. The embedded builder never selects a
// type-0 tx that spends an MN collateral (sml_projection.hpp
// tx_spends_mn_collateral), nor its in-body descendants. dashd's miner takes
// such a tx and removes the MN in FinishListForBlock's collateral loop, so
// while the spend sits in the mempool the two templates commit different MN
// roots — both valid for their own tx set. Testnet h=1592649: deletedMN
// 8448db99…, collateral spent by type-0 74d628077f306e0d; the mined,
// ChainLocked block committed dashd's root, and the embedded root equalled the
// parent's (nothing else differed).
//
// The rule (classification only — serving is UNCHANGED: any MN-root
// difference still swaps to dashd's template in the caller). Explained iff ALL:
//   1. the quorum roots are equal (an MN-root explanation says nothing about
//      a quorum-root difference);
//   2. the builder computed an alternative root (rpc_data.hpp
//      m_xcheck_collateral_alt_mnroot): the SAME fold over the served body plus
//      the excluded collateral spends, so it differs from the committed root by
//      the removals alone;
//   3. that alternative root is byte-equal to dashd's merkleRootMNList;
//   4. every excluded tx is in dashd's set AND absent from ours (a spend in
//      BOTH sets, or one dashd did not take, explains nothing).
// Anything else is a hard mismatch, exactly as before.

#include <core/uint256.hpp>

#include <algorithm>
#include <vector>

namespace dash {
namespace coin {

enum class MnRootXcheck {
    Mismatch,             ///< unexplained: label gbt-xcheck-mnroot-mismatch
    CollateralExplained,  ///< label gbt-xcheck-modulo-collateral-explained
};

struct MnRootXcheckInput {
    uint256 embedded_mnroot;
    uint256 dashd_mnroot;
    bool    quorum_roots_equal{false};
    uint256 alt_mnroot;                                   ///< null = not computed
    const std::vector<uint256>* excluded_txids{nullptr};  ///< builder's excluded spends
    const std::vector<uint256>* embedded_txids{nullptr};  ///< our served body
    const std::vector<uint256>* dashd_txids{nullptr};     ///< dashd's GBT body
};

inline MnRootXcheck classify_mnroot_xcheck(const MnRootXcheckInput& in)
{
    if (!in.quorum_roots_equal) return MnRootXcheck::Mismatch;
    if (in.embedded_mnroot == in.dashd_mnroot) return MnRootXcheck::Mismatch;  // nothing to explain
    if (in.alt_mnroot.IsNull() || in.alt_mnroot != in.dashd_mnroot) return MnRootXcheck::Mismatch;
    if (in.excluded_txids == nullptr || in.excluded_txids->empty()
        || in.embedded_txids == nullptr || in.dashd_txids == nullptr)
        return MnRootXcheck::Mismatch;
    const auto has = [](const std::vector<uint256>& v, const uint256& id) {
        return std::find(v.begin(), v.end(), id) != v.end();
    };
    for (const auto& id : *in.excluded_txids) {
        if (!has(*in.dashd_txids, id)) return MnRootXcheck::Mismatch;    // dashd did not take it
        if (has(*in.embedded_txids, id)) return MnRootXcheck::Mismatch;  // in BOTH sets
    }
    return MnRootXcheck::CollateralExplained;
}

} // namespace coin
} // namespace dash
