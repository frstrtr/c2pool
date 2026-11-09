// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Ported from Dash Core v24.0.0, as close to verbatim as our types allow, so
// it diffs line by line against Core:
//
//   src/masternode/payments.cpp
//     FindUnmatchedMasternodePayment        :24-52
//     PlatformShare                         :54-60
//     GetMasternodePayment (EvoReward era)  :62-129 (only the MN_RR branch, :103-108)
//     CMNPaymentsProcessor::GetBlockTxOuts  :131-199
//   src/evo/providertx_util.cpp
//     LegacyPayoutAsList                    :19-22
//     ProRataFloor                          :88-95
//     SplitAmountByShares                   :97-115
//   src/evo/providertx.h
//     GetOwnerPayouts                       :93-97
//
// Adaptations (and nothing else):
//   * CAmount = int64_t; CScript = std::vector<unsigned char>; CTxOut is the
//     two-field struct below. arith_uint256 in ProRataFloor is an unsigned
//     128-bit intermediate (the product of two int64 amounts fits).
//   * GetBlockTxOuts is split where Core reads chain state: the payee
//     (mnList.GetMNPayee(pindexPrev), unchanged in v24) and the two rewards
//     (GetMasternodePayment over blockSubsidy + feeReward and over
//     blockSubsidy) are the caller's inputs; GetBlockTxOutsForPayee is the
//     rest of the function from `voutMasternodePaymentsRet.clear()` on,
//     statement for statement. Logging is dropped.
//   * The payee is read through DmnPayee, a thin adapter holding exactly the
//     CDeterministicMN / CDeterministicMNState fields GetBlockTxOuts reads
//     (nOperatorReward, scriptOperatorPayout, IsShared(), shares, and what
//     GetOwnerPayouts needs). dmn_payee_of() fills it from our state types.

#include <impl/dash/coin/vendor/providertx.hpp>   // MasternodePayoutShare(s), CCollateralShare, ProTxVersion

#include <boost/multiprecision/cpp_int.hpp>   // uint128_t: ProRataFloor without __int128 (MSVC)
#include <cstdint>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {
namespace payments {

using CAmount = int64_t;
using CScript = std::vector<unsigned char>;

struct CTxOut
{
    CAmount nValue{0};
    CScript scriptPubKey;
    CTxOut() = default;
    CTxOut(CAmount v, CScript s) : nValue(v), scriptPubKey(std::move(s)) {}
    bool operator==(const CTxOut& o) const { return nValue == o.nValue && scriptPubKey == o.scriptPubKey; }
};

// ── providertx_util.cpp:19-22 ───────────────────────────────────────────────
inline MasternodePayoutShares LegacyPayoutAsList(const OPScript& script_payout)
{
    return legacy_payout_as_list(script_payout);   // {MasternodePayoutShare{script_payout, MAX_REWARD}}
}

// ── providertx.h:93-97 ──────────────────────────────────────────────────────
template <typename T>
MasternodePayoutShares GetOwnerPayouts(const T& protx)
{
    return protx.nVersion >= ProTxVersion::EXT_ADDR ? protx.payouts : LegacyPayoutAsList(protx.scriptPayout);
}

// ── providertx_util.cpp:88-95 ───────────────────────────────────────────────
// Portable form of the same 128-bit floor, for compilers without __int128
// (MSVC). Fixed-width 128-bit unsigned arithmetic gives the bit-identical
// result; test_dash_v24_mn_state pins it equal to the native form.
inline CAmount ProRataFloorPortable(const CAmount total, const CAmount weight, const CAmount weight_total)
{
    using u128 = boost::multiprecision::uint128_t;
    u128 v{static_cast<uint64_t>(total)};
    v *= u128(static_cast<uint64_t>(weight));
    v /= u128(static_cast<uint64_t>(weight_total));
    return static_cast<CAmount>(static_cast<uint64_t>(v & u128(UINT64_MAX)));   // GetLow64()
}

inline CAmount ProRataFloor(const CAmount total, const CAmount weight, const CAmount weight_total)
{
    // 128-bit intermediate: total * weight overflows int64 for real-world values
#if defined(__SIZEOF_INT128__)
    unsigned __int128 v{static_cast<uint64_t>(total)};
    v *= static_cast<unsigned __int128>(static_cast<uint64_t>(weight));
    v /= static_cast<unsigned __int128>(static_cast<uint64_t>(weight_total));
    return static_cast<CAmount>(static_cast<uint64_t>(v));   // GetLow64()
#else
    return ProRataFloorPortable(total, weight, weight_total);
#endif
}

// ── providertx_util.cpp:97-115 ──────────────────────────────────────────────
inline std::vector<CAmount> SplitAmountByShares(const CAmount total, const CollateralShares& shares)
{
    // DIP-0026's single rounding convention, with share amounts as weights: every entry except
    // the last receives floor(total * amount / weight_total) and the last entry receives the
    // remainder, so the split always sums to total exactly.
    CAmount weight_total{0};
    for (const auto& share : shares) {
        weight_total += share.amount;
    }
    std::vector<CAmount> ret;
    ret.reserve(shares.size());
    CAmount paid{0};
    for (size_t i = 0; i < shares.size(); i++) {
        const CAmount payout{i + 1 == shares.size() ? total - paid : ProRataFloor(total, shares[i].amount, weight_total)};
        paid += payout;
        ret.push_back(payout);
    }
    return ret;
}

// ── payments.cpp:54-60 ──────────────────────────────────────────────────────
inline CAmount PlatformShare(const CAmount reward)
{
    const CAmount platformReward = reward * 375 / 1000;
    return platformReward;   // Core asserts MoneyRange
}

// ── payments.cpp:103-108, GetMasternodePayment in the EvoReward era ─────────
// ("Once MNRewardReallocated activates, block reward is 80% of block
// subsidy (+ tx fees) since treasury is 20% ... MN reward is set to 75% of
// the block reward.") The earlier eras are not ported: every height this
// builder serves is past MN_RR on mainnet and testnet.
inline CAmount GetMasternodePaymentEvoReward(const CAmount blockValue)
{
    return blockValue * 3 / 4;
}

// ── The payee as GetBlockTxOuts reads it (adapter) ─────────────────────────
struct DmnPayee
{
    uint16_t               nOperatorReward{0};   // dmnPayee->nOperatorReward
    CScript                scriptOperatorPayout; // dmnPayee->pdmnState->scriptOperatorPayout
    CollateralShares       shares;               // dmnPayee->pdmnState->shares (IsShared() = !empty)
    MasternodePayoutShares owner_payouts;        // GetOwnerPayouts(*dmnPayee->pdmnState)
    bool IsShared() const { return !shares.empty(); }
};

/// Fills DmnPayee from our state types (MNState, ReplayMNState): the v24
/// fields live in `st.v24`.
template <typename S>
DmnPayee dmn_payee_of(const S& st)
{
    struct OwnerView {
        uint16_t nVersion;
        const MasternodePayoutShares& payouts;
        const OPScript& scriptPayout;
    } view{st.nVersion, st.v24.payouts, st.scriptPayout};
    DmnPayee p;
    p.nOperatorReward = st.nOperatorReward;
    p.scriptOperatorPayout = st.scriptOperatorPayout.m_data;
    p.shares = st.v24.shares;
    p.owner_payouts = GetOwnerPayouts(view);
    return p;
}

// ── payments.cpp:131-199, GetBlockTxOuts, from the payee on ─────────────────
// `masternodeReward` is GetMasternodePayment(height, blockSubsidy + feeReward)
// and `platformReward` PlatformShare(GetMasternodePayment(height,
// blockSubsidy)) in the EvoReward era (0 before it, and then no OP_RETURN).
// `dmnPayee` is mnList.GetMNPayee(pindexPrev); nullptr = an empty list.
inline bool GetBlockTxOutsForPayee(const DmnPayee* dmnPayee, CAmount masternodeReward, CAmount platformReward,
                                   bool evo_reward_era, std::vector<CTxOut>& voutMasternodePaymentsRet)
{
    voutMasternodePaymentsRet.clear();

    if (evo_reward_era) {
        masternodeReward -= platformReward;
        voutMasternodePaymentsRet.emplace_back(platformReward, CScript{0x6a});   // CScript() << OP_RETURN
    }
    if (dmnPayee == nullptr) {
        return true;   // "no masternode registered to receive a payment"
    }

    CAmount operatorReward = 0;

    if (dmnPayee->nOperatorReward != 0 && dmnPayee->scriptOperatorPayout != CScript()) {
        // This calculation might eventually turn out to result in 0 even if an operator reward percentage is given.
        // This will however only happen in a few years when the block rewards drops very low.
        operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
        masternodeReward -= operatorReward;
    }

    if (dmnPayee->IsShared()) {
        // Shared masternodes split the owner reward by recorded collateral contribution, paying
        // each share's reward script (or its refund script when no reward script is set)
        const auto& shares = dmnPayee->shares;
        const auto amounts = SplitAmountByShares(masternodeReward, shares);
        for (size_t i = 0; i < shares.size(); ++i) {
            if (amounts[i] > 0) {
                voutMasternodePaymentsRet.emplace_back(amounts[i], shares[i].RewardScript().m_data);
            }
        }
    } else {
        const auto& owner_payouts = dmnPayee->owner_payouts;
        CAmount paid_owner_reward{0};
        for (size_t i = 0; i < owner_payouts.size(); ++i) {
            const bool last = i + 1 == owner_payouts.size();
            const CAmount payout_amount = last ? masternodeReward - paid_owner_reward
                                               : (masternodeReward * owner_payouts[i].reward) / MasternodePayoutShare::MAX_REWARD;
            paid_owner_reward += payout_amount;
            if (payout_amount > 0) {
                voutMasternodePaymentsRet.emplace_back(payout_amount, owner_payouts[i].scriptPayout.m_data);
            }
        }
    }
    if (operatorReward > 0) {
        voutMasternodePaymentsRet.emplace_back(operatorReward, dmnPayee->scriptOperatorPayout);
    }

    return true;
}

// ── payments.cpp:24-52 ──────────────────────────────────────────────────────
inline int FindUnmatchedMasternodePayment(const std::vector<CTxOut>& expected,
                                          const std::vector<CTxOut>& actual,
                                          bool strict_multiplicity)
{
    if (!strict_multiplicity) {
        for (size_t i = 0; i < expected.size(); ++i) {
            const auto& txout = expected[i];
            bool any = false;
            for (const auto& txout2 : actual) if (txout == txout2) { any = true; break; }
            if (!any) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    std::vector<bool> consumed(actual.size(), false);
    for (size_t i = 0; i < expected.size(); ++i) {
        const auto& txout = expected[i];
        bool found = false;
        for (size_t j = 0; j < actual.size(); ++j) {
            if (!consumed[j] && actual[j] == txout) {
                consumed[j] = true;
                found = true;
                break;
            }
        }
        if (!found) return static_cast<int>(i);
    }
    return -1;
}

} // namespace payments
} // namespace vendor
} // namespace coin
} // namespace dash
