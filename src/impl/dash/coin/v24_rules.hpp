// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core v24 rules for provider special transactions: the activation
/// hook, the payload version gate and the payload-only ("structural")
/// checks, with Core's reject reasons.
///
/// Ported from Dash Core v24.0.0:
///   src/evo/types.h           ProTxVersion::GetMax
///   src/evo/providertx.cpp    IsTriviallyValid of every provider payload,
///                             IsPayoutListTriviallyValid, AreShareAmountsValid,
///                             IsEarlyPenaltyValid, IsShareListTriviallyValid
///                             (CheckProviderNetworkFields: vendor/netinfo.hpp)
///   src/evo/specialtxman.cpp  GetValidatedPayload and the payload-only prefix
///                             of CheckProRegTx, CheckProUpServTx,
///                             CheckProUpRegTx, CheckProUpRevTx, CheckProDisTx,
///                             CheckProUpShareTx, CheckProUpSharedRegTx
///
/// Scope. provider_payload_refusal() returns the first reject reason Core
/// produces for a provider tx from its payload and the block's deployment
/// state alone, i.e. every check Core runs BEFORE its first check that needs
/// the masternode list, the UTXO set, the inputs hash or a signature. It
/// stops there, so for a payload that passes it Core may still reject the
/// transaction on state. Not ported: those stateful checks. BLS operator-key
/// validity is approximated by "not all zero bytes" (a real point check
/// needs the BLS backend).
///
/// Wiring. The folds trust chainlocked blocks for ProTx validity (design
/// §3.3.4); nothing here is called by a fold yet. The fold-side rule S2 does
/// enforce is fail-closed parsing (vendor::parse_protx_payload and the
/// refusals in mn_state_machine.hpp, replay_fold_engine.hpp and
/// sml_special_fold.hpp). These checks are the reference for the S3
/// transitions and the S9 regtest KATs.

#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/vendor/netinfo.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace dash {
namespace coin {

enum class DashNetwork : uint8_t { MAINNET, TESTNET, DEVNET, REGTEST };

namespace v24 {
/// First block that carried CbTx version 4 on testnet, i.e. the first block
/// with DEPLOYMENT_V24 active (measured from chain data; design §5.1).
inline constexpr uint32_t kTestnetActivationHeight = 1'578'000;
} // namespace v24

/// DeploymentActiveAfter(pindexPrev, DEPLOYMENT_V24) for the block at
/// `height`. THIS IS THE S0 SEAM: slice S0 replaces the body with the EHF
/// signal tracker + versionbits state machine. Until then: never on mainnet
/// (not locked in), the measured height on testnet, and unknown (false) on
/// devnet and regtest.
inline bool v24_active(DashNetwork net, uint32_t height)
{
    switch (net) {
    case DashNetwork::TESTNET: return height >= v24::kTestnetActivationHeight;
    case DashNetwork::MAINNET:
    case DashNetwork::DEVNET:
    case DashNetwork::REGTEST: return false;
    }
    return false;
}

/// DEPLOYMENT_V19 (basic BLS scheme) buried heights, chainparams.cpp.
inline bool v19_active(DashNetwork net, uint32_t height)
{
    switch (net) {
    case DashNetwork::MAINNET: return height >= 1'899'072;
    case DashNetwork::TESTNET: return height >= 850'100;
    case DashNetwork::DEVNET:  return height >= 2;
    case DashNetwork::REGTEST: return height >= 1;
    }
    return false;
}

/// ProTxVersion::GetMax(is_basic_scheme_active, is_extended_addr): version 3
/// only once both V19 and V24 are active.
constexpr uint16_t protx_max_version(bool v19_active_, bool v24_active_)
{
    if (v19_active_) return v24_active_ ? vendor::ProTxVersion::EXT_ADDR : vendor::ProTxVersion::BASIC_BLS;
    return vendor::ProTxVersion::LEGACY_BLS;
}

/// The deployment state a provider tx is checked under (Core SpecialTxRules
/// plus the chain parameters the netinfo rules read).
struct ProviderTxRules
{
    bool v19_active{true};
    bool v24_active{false};
    bool evo_shares_active{false};   ///< DEPLOYMENT_EVO_SHARES: not signed by v24.0.0 masternodes
    bool ipv4_optional{false};       ///< DEPLOYMENT_IPV4_OPTIONAL: never on mainnet/regtest, always on testnet/devnet
    vendor::NetInfoRules net{vendor::NetInfoRules::mainnet()};

    static ProviderTxRules for_block(DashNetwork n, uint32_t height)
    {
        ProviderTxRules r;
        r.v19_active = dash::coin::v19_active(n, height);
        r.v24_active = dash::coin::v24_active(n, height);
        r.evo_shares_active = false;
        r.ipv4_optional = n == DashNetwork::TESTNET || n == DashNetwork::DEVNET;
        switch (n) {
        case DashNetwork::MAINNET: r.net = vendor::NetInfoRules::mainnet(); break;
        case DashNetwork::TESTNET: r.net = vendor::NetInfoRules::testnet(); break;
        case DashNetwork::DEVNET:  r.net = vendor::NetInfoRules::devnet();  break;
        case DashNetwork::REGTEST: r.net = vendor::NetInfoRules::regtest(); break;
        }
        return r;
    }
};

namespace provider_rules_detail {

using Refusal = std::optional<std::string>;

inline constexpr int64_t kCoin = vendor::CCollateralShare::COIN;

/// GetMnType(nType).collat_amount.
inline int64_t collateral_amount(uint16_t mn_type)
{
    return mn_type == vendor::MnType::EVO ? 4000 * kCoin : 1000 * kCoin;
}

inline bool is_valid_mn_type(uint16_t t) { return t == vendor::MnType::REGULAR || t == vendor::MnType::EVO; }

/// CScript::IsPayToPublicKeyHash -> the key hash.
inline std::optional<uint160> p2pkh_hash(const OPScript& s)
{
    const auto& d = s.m_data;
    if (d.size() == 25 && d[0] == 0x76 && d[1] == 0xa9 && d[2] == 0x14 && d[23] == 0x88 && d[24] == 0xac) {
        uint160 h;
        std::copy(d.begin() + 3, d.begin() + 23, h.data());
        return h;
    }
    return std::nullopt;
}

/// CScript::IsPayToScriptHash.
inline bool is_p2sh(const OPScript& s)
{
    const auto& d = s.m_data;
    return d.size() == 23 && d[0] == 0xa9 && d[1] == 0x14 && d[22] == 0x87;
}

/// IsValidPayoutScript.
inline bool is_valid_payout_script(const OPScript& s) { return p2pkh_hash(s).has_value() || is_p2sh(s); }

/// ExtractDestination(script) == PKHash(key): only a P2PKH script pays a key.
inline bool pays_key(const OPScript& s, const uint160& key)
{
    const auto h = p2pkh_hash(s);
    return h && *h == key;
}

/// CBLSLazyPublicKey::Get().IsValid(), approximated (see the file comment).
inline bool opkey_plausible(const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& k)
{
    return std::any_of(k.begin(), k.end(), [](uint8_t b) { return b != 0; });
}

} // namespace provider_rules_detail

// ── providertx.cpp trivial-validity helpers ────────────────────────────────

/// IsPayoutListTriviallyValid. `owner` may be null (ProUpRegTx).
inline std::optional<std::string>
payout_list_refusal(const vendor::MasternodePayoutShares& payouts, const uint160& owner, const uint160& voting)
{
    using namespace provider_rules_detail;
    if (payouts.empty() || payouts.size() > 8) return "bad-protx-payouts-count";
    uint32_t total{0};
    std::vector<std::vector<uint8_t>> seen;
    for (const auto& p : payouts) {
        if (p.reward < vendor::MasternodePayoutShare::MIN_REWARD
            || p.reward > vendor::MasternodePayoutShare::MAX_REWARD)
            return "bad-protx-payout-reward";
        total += p.reward;
        if (!is_valid_payout_script(p.scriptPayout)) return "bad-protx-payee";
        if (std::find(seen.begin(), seen.end(), p.scriptPayout.m_data) != seen.end()) return "bad-protx-payee-dup";
        seen.push_back(p.scriptPayout.m_data);
        if ((!owner.IsNull() && pays_key(p.scriptPayout, owner)) || pays_key(p.scriptPayout, voting))
            return "bad-protx-payee-reuse";
    }
    if (total != vendor::MasternodePayoutShare::MAX_REWARD) return "bad-protx-payout-reward-sum";
    return std::nullopt;
}

/// AreShareAmountsValid.
inline std::optional<std::string> share_amounts_refusal(const std::vector<int64_t>& amounts, int64_t required)
{
    if (amounts.size() < vendor::CProRegTx::MIN_SHARES || amounts.size() > vendor::CProRegTx::MAX_SHARES)
        return "bad-protx-shares-count";
    int64_t total{0};
    for (int64_t a : amounts) {
        if (a < vendor::CCollateralShare::MIN_AMOUNT || a > required) return "bad-protx-shares-amount";
        total += a;
    }
    if (total != required) return "bad-protx-shares-amount-sum";
    return std::nullopt;
}

/// IsEarlyPenaltyValid.
inline std::optional<std::string> early_penalty_refusal(uint32_t early_period_blocks, int64_t early_penalty,
                                                        int64_t min_share_amount)
{
    if (early_penalty < 0 || early_penalty >= min_share_amount) return "bad-protx-shares-penalty";
    if (early_period_blocks == 0 && early_penalty != 0) return "bad-protx-shares-penalty";
    return std::nullopt;
}

/// IsShareListTriviallyValid.
inline std::optional<std::string>
share_list_refusal(const vendor::CollateralShares& shares, uint32_t early_period_blocks, int64_t early_penalty,
                   int64_t required_collateral, const uint160& voting)
{
    using namespace provider_rules_detail;
    std::vector<int64_t> amounts;
    for (const auto& sh : shares) amounts.push_back(sh.amount);
    if (auto why = share_amounts_refusal(amounts, required_collateral)) return why;
    if (early_period_blocks > vendor::CProRegTx::MAX_EARLY_PERIOD_BLOCKS) return "bad-protx-shares-early-period";

    std::vector<uint160> seen_owners;
    std::vector<std::vector<uint8_t>> seen_refunds;
    for (const auto& sh : shares) {
        if (sh.keyIDOwner.IsNull()) return "bad-protx-shares-key-null";
        if (std::find(seen_owners.begin(), seen_owners.end(), sh.keyIDOwner) != seen_owners.end())
            return "bad-protx-shares-dup-key";
        seen_owners.push_back(sh.keyIDOwner);
        if (std::find(seen_refunds.begin(), seen_refunds.end(), sh.scriptRefund.m_data) != seen_refunds.end())
            return "bad-protx-shares-dup-refund";
        seen_refunds.push_back(sh.scriptRefund.m_data);
        for (const OPScript* script : {&sh.scriptRefund, &sh.scriptReward}) {
            if (script == &sh.scriptReward && script->m_data.empty()) continue;   // "use the refund script"
            if (!is_valid_payout_script(*script)) return "bad-protx-shares-payee";
            if (pays_key(*script, voting)) return "bad-protx-shares-payee-reuse";
            for (const auto& other : shares)
                if (pays_key(*script, other.keyIDOwner)) return "bad-protx-shares-payee-reuse";
        }
    }
    return early_penalty_refusal(early_period_blocks, early_penalty,
                                 *std::min_element(amounts.begin(), amounts.end()));
}

// ── IsTriviallyValid, per payload ──────────────────────────────────────────

inline std::optional<std::string> trivial_refusal(const vendor::CProRegTx& p)
{
    using namespace provider_rules_detail;
    if (!vendor::ProTxVersion::is_known(p.nVersion)) return "bad-protx-version";
    if (p.nVersion < vendor::ProTxVersion::BASIC_BLS && p.nType == vendor::MnType::EVO) return "bad-protx-evo-version";
    if (!is_valid_mn_type(p.nType)) return "bad-protx-type";
    if (p.nMode != 0) return "bad-protx-mode";
    if (p.IsShared()) {
        if (!p.collateralOutpoint.hash.IsNull()) return "bad-protx-shares-external";
        if (!p.keyIDOwner.IsNull()) return "bad-protx-shares-owner-key";
        if (!p.payouts.empty()) return "bad-protx-shares-payouts";
    } else {
        if (p.nEarlyPeriodBlocks != 0 || p.nEarlyPenalty != 0) return "bad-protx-shares-empty-fields";
        if (p.keyIDOwner.IsNull()) return "bad-protx-key-null";
    }
    if (!opkey_plausible(p.pubKeyOperator) || p.keyIDVoting.IsNull()) return "bad-protx-key-null";
    if (p.IsShared()) {
        if (auto why = share_list_refusal(p.shares, p.nEarlyPeriodBlocks, p.nEarlyPenalty,
                                          collateral_amount(p.nType), p.keyIDVoting))
            return why;
    } else {
        if (auto why = payout_list_refusal(p.owner_payouts(), p.keyIDOwner, p.keyIDVoting)) return why;
    }
    const auto ni = p.net_info();
    if (ni.CanStorePlatform() != (p.nVersion >= vendor::ProTxVersion::EXT_ADDR)) return "bad-protx-netinfo-version";
    if (!ni.IsEmpty())
        if (auto why = vendor::netinfo_trivial_refusal(ni, p.nType)) return why;
    if (p.nOperatorReward > 10000) return "bad-protx-operator-reward";
    return std::nullopt;
}

inline std::optional<std::string> trivial_refusal(const vendor::CProUpServTx& p)
{
    using namespace provider_rules_detail;
    if (!vendor::ProTxVersion::is_known(p.nVersion)) return "bad-protx-version";
    if (p.nVersion < vendor::ProTxVersion::BASIC_BLS && p.nType == vendor::MnType::EVO) return "bad-protx-evo-version";
    if (!is_valid_mn_type(p.nType)) return "bad-protx-type";
    const auto ni = p.net_info();
    if (ni.CanStorePlatform() != (p.nVersion >= vendor::ProTxVersion::EXT_ADDR)) return "bad-protx-netinfo-version";
    if (ni.IsEmpty()) return "bad-protx-netinfo-empty";
    return vendor::netinfo_trivial_refusal(ni, p.nType);
}

inline std::optional<std::string> trivial_refusal(const vendor::CProUpRegTx& p)
{
    using namespace provider_rules_detail;
    if (!vendor::ProTxVersion::is_known(p.nVersion)) return "bad-protx-version";
    if (p.nMode != 0) return "bad-protx-mode";
    if (!opkey_plausible(p.pubKeyOperator) || p.keyIDVoting.IsNull()) return "bad-protx-key-null";
    return payout_list_refusal(p.owner_payouts(), uint160{}, p.keyIDVoting);
}

inline std::optional<std::string> trivial_refusal(const vendor::CProUpRevTx& p)
{
    if (!vendor::ProTxVersion::is_known(p.nVersion)) return "bad-protx-version";
    if (p.nReason > vendor::CProUpRevTx::REASON_LAST) return "bad-protx-reason";
    return std::nullopt;
}

inline std::optional<std::string> trivial_refusal(const vendor::CProDisTx& p)
{
    if (p.nVersion == 0 || p.nVersion > vendor::CProDisTx::CURRENT_VERSION) return "bad-prodis-version";
    if (p.vchSigs.empty() || p.vchSigs.size() > vendor::CProRegTx::MAX_SHARES) return "bad-prodis-sig-count";
    return std::nullopt;
}

inline std::optional<std::string> trivial_refusal(const vendor::CProUpShareTx& p)
{
    using namespace provider_rules_detail;
    if (p.nVersion == 0 || p.nVersion > vendor::CProUpShareTx::CURRENT_VERSION) return "bad-proupshare-version";
    if (p.vchSig.size() != vendor::COMPACT_SIGNATURE_SIZE) return "bad-proupshare-sig-size";
    if (!is_valid_payout_script(p.scriptReward)) return "bad-proupshare-payee";
    return std::nullopt;
}

inline std::optional<std::string> trivial_refusal(const vendor::CProUpSharedRegTx& p)
{
    using namespace provider_rules_detail;
    if (p.nVersion == 0 || p.nVersion > vendor::CProUpSharedRegTx::CURRENT_VERSION)
        return "bad-proupsharedreg-version";
    if (!opkey_plausible(p.pubKeyOperator) || p.keyIDVoting.IsNull()) return "bad-protx-key-null";
    // (pubKeyOperator.IsLegacy(): the payload is always read in the basic
    // scheme, so this check cannot fire on a decoded payload.)
    if (p.vchSigs.empty() || p.vchSigs.size() > vendor::CProRegTx::MAX_SHARES)
        return "bad-proupsharedreg-sig-count";
    return std::nullopt;
}

// ── GetValidatedPayload + the payload-only prefix of Check*Tx ──────────────

namespace provider_rules_detail {

/// GetValidatedPayload: GetTxPayload, the GetMax version gate, IsTriviallyValid.
template <typename T>
inline Refusal validated_payload(const std::vector<uint8_t>& payload, const ProviderTxRules& rules, T& out)
{
    if (!vendor::decode_special_payload(payload, out)) return "bad-protx-payload";
    if (out.nVersion > protx_max_version(rules.v19_active, rules.v24_active)) return "bad-protx-version";
    return trivial_refusal(out);
}

} // namespace provider_rules_detail

/// The first reject reason Core gives a provider special tx of `tx_type`
/// with this extra payload, from the payload and `rules` alone (see the file
/// comment for the scope), or nullopt. Types other than 1-4 and 10-12 are not
/// provider txs and return nullopt.
inline std::optional<std::string>
provider_payload_refusal(uint16_t tx_type, const std::vector<uint8_t>& payload, const ProviderTxRules& rules)
{
    using namespace provider_rules_detail;
    switch (tx_type) {
    case vendor::CProRegTx::SPECIALTX_TYPE: {
        vendor::CProRegTx p;
        if (auto why = validated_payload(payload, rules, p)) return why;
        if (rules.v24_active && p.nVersion < vendor::ProTxVersion::BASIC_BLS) return "bad-protx-version-disallowed";
        if (p.nType == vendor::MnType::EVO && !rules.evo_shares_active) {
            if (p.IsShared()) return "bad-protx-shares-evo";
            if (p.owner_payouts().size() > 1) return "bad-protx-payouts-evo";
        }
        return vendor::check_provider_network_fields(p.net_info(), p.nType, p.nVersion, &p.platformNodeID,
                                                     p.platformP2PPort, p.platformHTTPPort,
                                                     /*allow_empty=*/true, rules.ipv4_optional, rules.net);
    }
    case vendor::CProUpServTx::SPECIALTX_TYPE: {
        vendor::CProUpServTx p;
        if (auto why = validated_payload(payload, rules, p)) return why;
        return vendor::check_provider_network_fields(p.net_info(), p.nType, p.nVersion, &p.platformNodeID,
                                                     p.platformP2PPort, p.platformHTTPPort,
                                                     /*allow_empty=*/false, rules.ipv4_optional, rules.net);
    }
    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx p;
        return validated_payload(payload, rules, p);
    }
    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx p;
        return validated_payload(payload, rules, p);
    }
    case vendor::CProDisTx::SPECIALTX_TYPE: {
        vendor::CProDisTx p;
        if (auto why = validated_payload(payload, rules, p)) return why;
        if (!rules.v24_active) return "bad-prodis-too-early";
        return std::nullopt;
    }
    case vendor::CProUpShareTx::SPECIALTX_TYPE: {
        vendor::CProUpShareTx p;
        if (auto why = validated_payload(payload, rules, p)) return why;
        if (!rules.v24_active) return "bad-proupshare-too-early";
        return std::nullopt;
    }
    case vendor::CProUpSharedRegTx::SPECIALTX_TYPE: {
        vendor::CProUpSharedRegTx p;
        if (auto why = validated_payload(payload, rules, p)) return why;
        if (!rules.v24_active) return "bad-proupsharedreg-too-early";
        return std::nullopt;
    }
    default:
        return std::nullopt;
    }
}

/// CheckProUpServTx's one payload-only rule that Core runs AFTER its
/// masternode-list checks: from v24 an EvoNode service update must be
/// version 3 (its Platform ports live in netInfo).
inline std::optional<std::string> proupserv_post_state_refusal(const vendor::CProUpServTx& p,
                                                               const ProviderTxRules& rules)
{
    if (rules.v24_active && p.nType == vendor::MnType::EVO && p.nVersion < vendor::ProTxVersion::EXT_ADDR)
        return "bad-protx-version-disallowed";
    return std::nullopt;
}

} // namespace coin
} // namespace dash
