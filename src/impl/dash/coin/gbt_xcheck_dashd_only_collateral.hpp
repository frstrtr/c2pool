#pragma once
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GBT-xcheck step 0b: LABEL a merkleRootMNList difference between the embedded
// template and dashd's getblocktemplate when it is explained, EXACTLY, by
// masternode-collateral spends that only dashd's template carries — txs our
// candidate set never had (not in our pool, or not priceable at build time).
//
// Why this is a separate label from gbt-xcheck-modulo-collateral-explained
// (gbt_xcheck_collateral.hpp): that one covers spends our builder EXCLUDED by
// design. This one covers spends we never had, which is a freshness / relay
// matter (the E1a "not-in-pool" bucket), not a design exclusion. Testnet
// h=1592649 was this class: the spend 74d628077f306e0d never reached the
// builder's collateral filter (no exclusion line across 4 rebuilds), dashd's
// template took it and removed MN 8448db99…, and the ChainLocked block
// committed dashd's root.
//
// The rule (classification only — serving is UNCHANGED: any MN-root
// difference still swaps to dashd's template in the caller). Explained iff ALL:
//   1. the quorum roots are equal;
//   2. the builder exported its committed fold (XcheckCollateralAid) and that
//      list's root IS the root the embedded template committed;
//   3. no tx only dashd's template carries is a provider tx (types 1-4, 10-12:
//      those change leaves, which a collateral loop cannot account for);
//   4. at least one dashd-only tx spends the collateral of an MN in our folded
//      list, and at least one such spend is NOT one our builder excluded (else
//      it is the #2244 class, not this one);
//   5. the fold's collateral loop, run for the dashd-only txs appended after
//      our body (apply_appended_collateral_spends, with the index the fold
//      itself exported), gives a root byte-equal to dashd's merkleRootMNList.
// A spend present in BOTH sets is not dashd-only and explains nothing.
// Anything else is a hard mismatch, exactly as before.

#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <core/uint256.hpp>

#include <cstddef>
#include <set>
#include <vector>

namespace dash {
namespace coin {

/// The committed fold of an embedded template, kept for the label above
/// (rpc_data.hpp DashWorkData::m_xcheck_collateral_aid). Never served.
struct XcheckCollateralAid {
    vendor::CSimplifiedMNList folded;   ///< the fold's result: its root is the CbTx root
    CollateralOwnerIndex      owners;   ///< the fold's collateral index for `folded`
};

enum class DashdOnlyCollateral {
    Mismatch,   ///< unexplained: label gbt-xcheck-mnroot-mismatch
    Explained,  ///< label gbt-xcheck-modulo-dashd-only-collateral
};

struct DashdOnlyCollateralVerdict {
    DashdOnlyCollateral verdict{DashdOnlyCollateral::Mismatch};
    uint256     alt_mnroot;      ///< null when not computed
    std::size_t dashd_only{0};   ///< txs in dashd's body, absent from ours
    std::size_t spends{0};       ///< of those, txs spending a listed MN's collateral
    unsigned    removed{0};      ///< MNs those spends remove
    const char* why{"not-run"};  ///< the condition that failed ("" when explained)
};

/// MN-list-changing provider types (the fold's special-tx loop owns them).
inline bool is_mn_list_provider_type(uint16_t type)
{
    return (type >= tx_type::PROVIDER_REGISTER && type <= tx_type::PROVIDER_UPDATE_REVOKE)
        || (type >= tx_type::PROVIDER_DISSOLVE && type <= tx_type::PROVIDER_UPDATE_SHARED_REGISTRAR);
}

/// `dashd_txs` and `dashd_txids` are dashd's GBT body, parallel (rpc.cpp
/// getwork). `excluded_txids` are the spends our builder excluded
/// (DashWorkData::m_xcheck_collateral_excluded_txids).
template <typename TxVec>
inline DashdOnlyCollateralVerdict classify_dashd_only_collateral(
    const XcheckCollateralAid* aid,
    const uint256& embedded_mnroot,
    const uint256& dashd_mnroot,
    bool quorum_roots_equal,
    const std::vector<uint256>& embedded_txids,
    const std::vector<uint256>& excluded_txids,
    const std::vector<uint256>& dashd_txids,
    const TxVec& dashd_txs)
{
    DashdOnlyCollateralVerdict v;
    if (!quorum_roots_equal) { v.why = "quorum-roots-differ"; return v; }
    if (embedded_mnroot == dashd_mnroot) { v.why = "no-difference"; return v; }
    if (aid == nullptr) { v.why = "no-aid"; return v; }
    if (aid->folded.CalcMerkleRoot() != embedded_mnroot) { v.why = "aid-not-the-committed-root"; return v; }
    if (dashd_txids.size() != dashd_txs.size()) { v.why = "dashd-body-shape"; return v; }

    const std::set<uint256> ours(embedded_txids.begin(), embedded_txids.end());
    const std::set<uint256> excluded(excluded_txids.begin(), excluded_txids.end());
    TxVec extra;                        // dashd-only txs, in dashd's order
    bool never_had_spend = false;
    for (std::size_t i = 0; i < dashd_txs.size(); ++i) {
        if (ours.count(dashd_txids[i])) continue;
        const auto& tx = dashd_txs[i];
        if (tx_is_special_version(tx.version) && is_mn_list_provider_type(tx.type)) {
            v.why = "dashd-only-provider-tx";
            return v;
        }
        ++v.dashd_only;
        bool spends = false;
        for (const auto& in : tx.vin)
            if (aid->owners.count(in.prevout)) { spends = true; break; }
        if (spends) {
            ++v.spends;
            if (!excluded.count(dashd_txids[i])) never_had_spend = true;
        }
        extra.push_back(tx);
    }
    if (v.spends == 0) { v.why = "no-dashd-only-collateral-spend"; return v; }
    if (!never_had_spend) { v.why = "all-spends-builder-excluded"; return v; }
    v.alt_mnroot = apply_appended_collateral_spends(aid->folded, aid->owners, extra, &v.removed)
                       .CalcMerkleRoot();
    if (v.alt_mnroot != dashd_mnroot) { v.why = "alt-root-not-dashd"; return v; }
    v.verdict = DashdOnlyCollateral::Explained;
    v.why = "";
    return v;
}

} // namespace coin
} // namespace dash
