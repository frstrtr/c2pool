// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core v24 masternode-state model and state transitions, shared by the
/// payee projection (MNState, mn_state_machine.hpp) and the root-checked
/// replay fold (ReplayMNState, replay_fold_engine.hpp).
///
/// Ported from Dash Core v24.0.0:
///   src/evo/dmnstate.h        CDeterministicMNState: payouts, shares,
///                             nEarlyPeriodBlocks, nEarlyPenalty; the v3
///                             serialized form; ResetOperatorFields
///   src/evo/specialtxman.cpp  SetStateVersion (:51-103), ApplyProUpServTx
///                             (:107-137), ApplyTxToList (:346-697) for
///                             ProRegTx, ProUpServTx, ProUpRegTx, ProUpRevTx,
///                             ProUpShareTx, ProUpSharedRegTx; FinishListForBlock
///                             (:699+, shared collateral spent by a ProDisTx
///                             only); CheckProDisTxForList (:1738-1849) with the
///                             early-exit penalty rules; the shared-collateral
///                             template covenant (:1877-1911)
///   src/evo/providertx.cpp    IsShareListVotingKeySafe
///   src/evo/providertx_util.cpp ProRataFloor
///
/// Every function here is the DEPLOYMENT_V24 behaviour. The engines call them
/// only for blocks at or above the v24 activation height; below it they keep
/// their pre-v24 code paths unchanged, so a pre-activation fold is
/// byte-identical to the one before this file existed.
///
/// Our stores keep the operator key canonically in the BASIC scheme
/// (vendor::opkey_to_basic at every store site) and re-encode it per leaf from
/// nVersion (vendor::opkey_for_leaf). SetStateVersion's "re-encode the key to
/// the target scheme" step is therefore a no-op here: the in-place legacy ->
/// basic migration is just the version change.
///
/// Ban and revive bookkeeping differs between the two state types (uint32/0
/// versus int32/-1 sentinels), so the transitions report "ban" and leave it to
/// the engine; everything else is applied here.

#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/v24_rules.hpp>
#include <impl/dash/coin/vendor/netinfo.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// The state members Dash Core v24 adds to CDeterministicMNState, plus the
/// ExtNetInfo a version-3 state carries in place of the legacy service.
///
/// Persistence: every codec that stores a masternode state writes this block
/// AFTER its pre-v24 fields and only when the state's nVersion is 3 or more.
/// A v1/v2 state therefore encodes exactly as before (old rows, snapshots and
/// diff records stay valid), and the decoder knows from the nVersion it has
/// already read whether the block follows.
struct MnStateV24Ext
{
    vendor::ExtNetInfo             extNetInfo;
    vendor::MasternodePayoutShares payouts;
    vendor::CollateralShares       shares;           ///< non-empty = shared masternode
    uint32_t                       nEarlyPeriodBlocks{0};
    int64_t                        nEarlyPenalty{0};

    bool IsShared() const { return !shares.empty(); }

    bool operator==(const MnStateV24Ext& o) const
    {
        return extNetInfo == o.extNetInfo && payouts == o.payouts && shares == o.shares
            && nEarlyPeriodBlocks == o.nEarlyPeriodBlocks && nEarlyPenalty == o.nEarlyPenalty;
    }
    bool operator!=(const MnStateV24Ext& o) const { return !(*this == o); }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << extNetInfo << payouts << shares << nEarlyPeriodBlocks << nEarlyPenalty;
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> extNetInfo >> payouts >> shares >> nEarlyPeriodBlocks >> nEarlyPenalty;
    }
};

namespace v24 {

inline bool state_has_ext(uint16_t nVersion) { return nVersion >= vendor::ProTxVersion::EXT_ADDR; }

/// Result of a transition: Core's reject reason (the block is invalid; the
/// engine fails closed), and whether Core bans the masternode here.
struct Transition
{
    std::optional<std::string> error;
    bool ban{false};
};

/// The shared-masternode collateral template script: 0x04 "DSHC" OP_DROP
/// OP_TRUE (evo/sharedcollateral.h). Matching is exact.
inline const std::vector<uint8_t>& shared_collateral_script()
{
    static const std::vector<uint8_t> s{0x04, 'D', 'S', 'H', 'C', 0x75, 0x51};
    return s;
}
inline bool is_shared_collateral_script(const std::vector<uint8_t>& script)
{
    return script == shared_collateral_script();
}

/// IsShareListVotingKeySafe: no refund or effective reward script pays the
/// voting key's P2PKH destination.
inline bool share_list_voting_key_safe(const vendor::CollateralShares& shares, const uint160& voting)
{
    for (const auto& sh : shares)
        for (const OPScript* s : {&sh.scriptRefund, &sh.RewardScript()})
            if (provider_rules_detail::pays_key(*s, voting)) return false;
    return true;
}

/// ProRataFloor: floor(total * weight / weight_total) with a 128-bit intermediate.
inline int64_t pro_rata_floor(int64_t total, int64_t weight, int64_t weight_total)
{
    if (weight_total <= 0) return 0;
    const unsigned __int128 v = static_cast<unsigned __int128>(static_cast<uint64_t>(total))
                              * static_cast<uint64_t>(weight) / static_cast<uint64_t>(weight_total);
    return static_cast<int64_t>(static_cast<uint64_t>(v));
}

/// The current netInfo of a state, as a NetInfoRef. `is_ext` is the kind of
/// netInfo the state carries right now (Core: the dynamic type of its
/// netInfo pointer). At rest it equals state_has_ext(nVersion); inside a
/// transition the two can differ for a moment, exactly as in Core.
template <typename S>
vendor::NetInfoRef netinfo_of(const S& st, bool is_ext)
{
    return is_ext ? vendor::NetInfoRef{nullptr, &st.v24.extNetInfo} : vendor::NetInfoRef{&st.netInfo, nullptr};
}

/// CDeterministicMNState::ResetOperatorFields: version back to LegacyBLS,
/// operator key, netInfo (now an empty MnNetInfo), operator payout, revocation
/// reason and platformNodeID cleared. Payout list, shares and early-exit
/// terms are untouched.
template <typename S>
void reset_operator_fields(S& st)
{
    st.nVersion = vendor::ProTxVersion::LEGACY_BLS;
    st.pubKeyOperator = {};
    st.netInfo = vendor::LegacyNetService{};
    st.v24.extNetInfo = vendor::ExtNetInfo{};
    st.scriptOperatorPayout = OPScript{};
    st.nRevocationReason = vendor::CProUpRevTx::REASON_NOT_SPECIFIED;
    st.platformNodeID = uint160{};
}

/// SetStateVersion (specialtxman.cpp:51-103). `netinfo_is_ext` is the kind of
/// netInfo the state carries on entry. Returns Core's reject reason on a
/// netInfo that cannot be carried into the target format.
template <typename S>
std::optional<std::string> set_state_version(S& st, uint16_t target, uint16_t mn_type, bool netinfo_is_ext,
                                             const vendor::NetInfoRules& rules)
{
    const bool needs_ext = state_has_ext(target);
    // Before the early return: ProUpServ pre-sets nVersion, so migrate the
    // single payout script into the list here or it would be skipped.
    if (needs_ext && st.v24.payouts.empty() && !st.scriptPayout.m_data.empty()) {
        st.v24.payouts = vendor::legacy_payout_as_list(st.scriptPayout);
        st.scriptPayout = OPScript{};
    }
    // Operator key re-encoding: a no-op for the canonical-basic store (file comment).
    if (st.nVersion == target && netinfo_is_ext == needs_ext) return std::nullopt;

    if (needs_ext) {
        vendor::ExtNetInfo converted;
        if (!netinfo_is_ext) {
            auto c = vendor::ext_netinfo_from_legacy(st.netInfo, rules);
            if (!c) return std::string("bad-protx-netinfo-version");
            converted = std::move(*c);
            // The scalar Platform ports are not carried over: an EvoNode is
            // raised to ExtAddr by a ProUpServTx that spells its entries out.
            if (mn_type == vendor::MnType::EVO && !netinfo_of(st, false).IsEmpty())
                return std::string("bad-protx-netinfo-version");
        } else {
            // ExtNetInfo -> ExtNetInfo: Core re-adds every entry through
            // AddEntry; for a state Core accepted that reproduces it.
            converted = st.v24.extNetInfo;
        }
        st.platformP2PPort = 0;
        st.platformHTTPPort = 0;
        st.v24.extNetInfo = std::move(converted);
        st.netInfo = vendor::LegacyNetService{};
    } else if (netinfo_is_ext) {
        // ExtNetInfo -> MnNetInfo: at most one CORE_P2P IPv4 entry survives
        // MnNetInfo::AddEntry (MaxLimit / BadInput / ValidateService).
        const auto entries = st.v24.extNetInfo.GetEntries(vendor::NetInfoPurpose::CORE_P2P);
        vendor::LegacyNetService l;
        if (entries.size() > 1) return std::string("bad-protx-netinfo-version");
        if (entries.size() == 1) {
            const auto* svc = entries[0].service();
            if (!svc || !svc->IsIPv4()) return std::string("bad-protx-netinfo-version");
            l.ip[10] = 0xff;
            l.ip[11] = 0xff;
            std::copy(svc->addr.begin(), svc->addr.end(), l.ip.begin() + 12);
            l.port_be = svc->port;
            if (vendor::validate_mn_netinfo(l, rules) != vendor::NetInfoStatus::Success)
                return std::string("bad-protx-netinfo-version");
        }
        st.netInfo = l;
        st.v24.extNetInfo = vendor::ExtNetInfo{};
    }
    st.nVersion = target;
    return std::nullopt;
}

/// CDeterministicMNState(const CProRegTx&): the state of a new registration.
/// `opkey_basic` is the payload key in the canonical basic encoding.
template <typename S>
void state_from_proreg(S& st, const vendor::CProRegTx& p,
                       const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& opkey_basic)
{
    st.nVersion = p.nVersion;
    st.keyIDOwner = p.keyIDOwner;
    st.pubKeyOperator = opkey_basic;
    st.keyIDVoting = p.keyIDVoting;
    if (state_has_ext(p.nVersion)) {
        st.netInfo = vendor::LegacyNetService{};
        st.v24.extNetInfo = p.extNetInfo;
    } else {
        st.netInfo = p.netInfo.canonical();   // Core holds an invalid service as empty
        st.v24.extNetInfo = vendor::ExtNetInfo{};
    }
    st.scriptPayout = p.scriptPayout;
    st.v24.payouts = p.payouts;
    st.v24.shares = p.shares;
    st.v24.nEarlyPeriodBlocks = p.nEarlyPeriodBlocks;
    st.v24.nEarlyPenalty = p.nEarlyPenalty;
    st.platformNodeID = p.platformNodeID;
    st.platformP2PPort = p.platformP2PPort;
    st.platformHTTPPort = p.platformHTTPPort;
}

/// The state's netInfo is empty (a registration with an empty netInfo starts banned).
template <typename S>
bool netinfo_empty(const S& st)
{
    return netinfo_of(st, state_has_ext(st.nVersion)).IsEmpty();
}

/// ApplyProUpServTx with DEPLOYMENT_V24 active (specialtxman.cpp:107-137).
/// Revive is the engine's (revive_allowed below).
template <typename S>
Transition apply_proupserv(S& st, const vendor::CProUpServTx& p, uint16_t mn_type, const vendor::NetInfoRules& rules)
{
    const uint16_t target = std::max<uint16_t>(st.nVersion, p.nVersion);
    st.nVersion = p.nVersion;
    const bool ext = state_has_ext(p.nVersion);
    if (ext) {
        st.v24.extNetInfo = p.extNetInfo;
        st.netInfo = vendor::LegacyNetService{};
    } else {
        st.netInfo = p.netInfo.canonical();
        st.v24.extNetInfo = vendor::ExtNetInfo{};
    }
    st.scriptOperatorPayout = p.scriptOperatorPayout;
    if (p.nType == vendor::MnType::EVO) {
        st.platformNodeID = p.platformNodeID;
        if (p.nVersion < vendor::ProTxVersion::EXT_ADDR) {
            st.platformP2PPort = p.platformP2PPort;
            st.platformHTTPPort = p.platformHTTPPort;
        } else {
            st.platformP2PPort = 0;
            st.platformHTTPPort = 0;
        }
    }
    return {set_state_version(st, target, mn_type, ext, rules), false};
}

/// The ProUpServTx revive condition: a banned masternode is revived only when
/// all keys are set (a shared masternode has a null keyIDOwner; its share
/// owner keys are immutable and always set).
template <typename S>
bool revive_allowed(const S& st)
{
    const bool opkey_set = std::any_of(st.pubKeyOperator.begin(), st.pubKeyOperator.end(),
                                       [](uint8_t b) { return b != 0; });
    return opkey_set && !st.keyIDVoting.IsNull() && (st.v24.IsShared() || !st.keyIDOwner.IsNull());
}

/// ProUpRegTx with DEPLOYMENT_V24 active (specialtxman.cpp:521-584).
/// `operator_changed` is Core's pubKeyOperator != payload key (point
/// compare); `incoming_basic` the payload key in the basic encoding. The
/// any-scheme duplicate-key check is the engine's (it needs the list).
template <typename S>
Transition apply_proupreg(S& st, const vendor::CProUpRegTx& p, uint16_t mn_type, bool operator_changed,
                          const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& incoming_basic,
                          const vendor::NetInfoRules& rules)
{
    if (st.v24.IsShared()) return {std::string("bad-protx-shared-mn"), false};
    const uint16_t old_version = st.nVersion;
    const uint16_t target = std::max<uint16_t>(old_version, p.nVersion);
    bool ext = state_has_ext(old_version);
    Transition t;
    if (operator_changed) {
        reset_operator_fields(st);
        ext = false;
        t.ban = true;
        st.pubKeyOperator = incoming_basic;
    }
    st.keyIDVoting = p.keyIDVoting;
    if (auto e = set_state_version(st, target, mn_type, ext, rules)) return {e, t.ban};
    if (state_has_ext(target)) {
        st.v24.payouts = state_has_ext(p.nVersion) ? p.payouts : vendor::legacy_payout_as_list(p.scriptPayout);
        st.scriptPayout = OPScript{};
    } else {
        st.scriptPayout = p.scriptPayout;
        st.v24.payouts.clear();
    }
    return t;
}

/// ProUpRevTx with DEPLOYMENT_V24 active (specialtxman.cpp:585-613): the
/// state version is kept (max of state and payload) instead of dropping to 1.
template <typename S>
Transition apply_prouprev(S& st, const vendor::CProUpRevTx& p, uint16_t mn_type, const vendor::NetInfoRules& rules)
{
    const uint16_t target = std::max<uint16_t>(st.nVersion, p.nVersion);
    reset_operator_fields(st);
    if (target >= vendor::ProTxVersion::BASIC_BLS)
        if (auto e = set_state_version(st, target, mn_type, /*netinfo_is_ext=*/false, rules)) return {e, true};
    st.nRevocationReason = p.nReason;
    return {std::nullopt, true};
}

/// ProUpShareTx (type 11, specialtxman.cpp:614-641).
template <typename S>
Transition apply_proupshare(S& st, const vendor::CProUpShareTx& p)
{
    if (!st.v24.IsShared() || p.shareIndex >= st.v24.shares.size())
        return {std::string("bad-proupshare-index"), false};
    st.v24.shares[p.shareIndex].scriptReward = p.scriptReward;
    if (!share_list_voting_key_safe(st.v24.shares, st.keyIDVoting))
        return {std::string("bad-proupshare-payee-reuse"), false};
    return {};
}

/// ProUpSharedRegTx (type 12, specialtxman.cpp:642-697). The any-scheme
/// duplicate-key check is the engine's.
template <typename S>
Transition apply_proupsharedreg(S& st, const vendor::CProUpSharedRegTx& p, uint16_t mn_type, bool operator_changed,
                                const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& incoming_basic,
                                const vendor::NetInfoRules& rules)
{
    if (!st.v24.IsShared()) return {std::string("bad-proupsharedreg-not-shared"), false};
    const uint16_t old_version = st.nVersion;
    bool ext = state_has_ext(old_version);
    Transition t;
    if (operator_changed) {
        reset_operator_fields(st);
        ext = false;
        t.ban = true;
        st.pubKeyOperator = incoming_basic;   // always the basic scheme
    }
    st.keyIDVoting = p.keyIDVoting;
    if (auto e = set_state_version(st, old_version, mn_type, ext, rules)) return {e, t.ban};
    if (!share_list_voting_key_safe(st.v24.shares, st.keyIDVoting))
        return {std::string("bad-proupsharedreg-payee-reuse"), t.ban};
    return t;
}

/// CheckSharedCollateralTemplateOutputs: an output paying the template script
/// is valid only as the collateral output of a shared registration with
/// internal collateral, at exactly that index. Applies to every tx of a
/// block, coinbase included, once DEPLOYMENT_V24 is active.
template <typename Tx>
std::optional<std::string> shared_collateral_create_refusal(const Tx& tx)
{
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        if (!is_shared_collateral_script(tx.vout[i].scriptPubKey.m_data)) continue;
        if (!tx_is_special_version(tx.version) || tx.type != tx_type::PROVIDER_REGISTER)
            return std::string("bad-shared-collateral-create");
        vendor::CProRegTx p;
        if (!vendor::decode_special_payload(tx.extra_payload, p) || !p.IsShared()
            || !p.collateralOutpoint.hash.IsNull() || p.collateralOutpoint.index != i)
            return std::string("bad-shared-collateral-create");
    }
    return std::nullopt;
}

/// CheckSharedCollateralSpends: only a ProDisTx may spend a template output.
/// `prevout_script` returns the script of an unspent prevout (nullopt when
/// unknown or spent). Coinbase txs are exempt.
template <typename Tx, typename Lookup>
std::optional<std::string> shared_collateral_spend_refusal(const Tx& tx, bool is_coinbase, Lookup&& prevout_script)
{
    if (is_coinbase) return std::nullopt;
    for (const auto& in : tx.vin) {
        const auto script = prevout_script(in.prevout);
        if (script && is_shared_collateral_script(*script)) {
            if (!tx_is_special_version(tx.version) || tx.type != tx_type::PROVIDER_DISSOLVE)
                return std::string("bad-shared-collateral-spend");
        }
    }
    return std::nullopt;
}

/// What CheckProDisTxForList reads from the masternode a ProDisTx names.
struct ProDisTarget
{
    bool exists{false};
    bool shared{false};
    bitcoin_family::coin::TxPrevOut collateral;
    const vendor::CollateralShares* shares{nullptr};
    int64_t registered_height{0};
    uint32_t early_period_blocks{0};
    int64_t early_penalty{0};
};

/// CheckProDisTxForList (specialtxman.cpp:1738-1849) without the signature
/// check: input, actor, mode, the early-exit penalty floors and sum, the
/// actor output, the fee ceiling and the unilateral bonus ceiling.
///
/// Monotone validity: the required penalty depends on the spend height only
/// through `spend_height - registered_height < early_period_blocks`, which can
/// only turn false as the height grows, and every other rule is
/// height-independent. A ProDisTx valid at height h is valid at every later
/// height (Core's DIP "Output rules").
template <typename Tx>
std::optional<std::string> prodis_list_refusal(const Tx& tx, const vendor::CProDisTx& p, const ProDisTarget& mn,
                                               int64_t spend_height)
{
    if (!mn.exists) return std::string("bad-prodis-hash");
    if (!mn.shared || !mn.shares) return std::string("bad-prodis-not-shared");
    const auto& shares = *mn.shares;
    if (tx.vin.size() != 1 || tx.vin[0].prevout.hash != mn.collateral.hash
        || tx.vin[0].prevout.index != mn.collateral.index || !tx.vin[0].scriptSig.m_data.empty())
        return std::string("bad-prodis-input");
    if (p.actorIndex >= shares.size()) return std::string("bad-prodis-actor");
    if (p.vchSigs.size() != 1 && p.vchSigs.size() != shares.size()) return std::string("bad-prodis-sig-count");
    const bool unanimous = p.vchSigs.size() == shares.size();
    const bool early = spend_height - mn.registered_height < static_cast<int64_t>(mn.early_period_blocks);
    const int64_t required_penalty = (unanimous || !early) ? 0 : mn.early_penalty;

    const size_t non_actor_count = shares.size() - 1;
    if (tx.vout.size() != non_actor_count && tx.vout.size() != non_actor_count + 1)
        return std::string("bad-prodis-payee-count");
    int64_t non_actor_total = 0;
    for (size_t i = 0; i < shares.size(); ++i)
        if (i != p.actorIndex) non_actor_total += shares[i].amount;

    size_t out_idx = 0;
    int64_t bonus_total = 0;
    for (size_t i = 0; i < shares.size(); ++i) {
        if (i == p.actorIndex) continue;
        const auto& out = tx.vout[out_idx++];
        if (out.scriptPubKey.m_data != shares[i].scriptRefund.m_data) return std::string("bad-prodis-payee");
        const int64_t bonus = out.value - shares[i].amount;
        if (bonus < pro_rata_floor(required_penalty, shares[i].amount, non_actor_total))
            return std::string("bad-prodis-penalty-floor");
        bonus_total += bonus;
    }
    if (tx.vout.size() == non_actor_count + 1) {
        const auto& actor_out = tx.vout.back();
        if (actor_out.scriptPubKey.m_data != shares[p.actorIndex].scriptRefund.m_data)
            return std::string("bad-prodis-payee");
        if (actor_out.value == 0) return std::string("bad-prodis-actor-output-zero");
    }
    if (bonus_total < required_penalty) return std::string("bad-prodis-penalty-sum");
    int64_t out_total = 0;
    for (const auto& out : tx.vout) out_total += out.value;
    if (non_actor_total + shares[p.actorIndex].amount - out_total > vendor::CProDisTx::MAX_FEE)
        return std::string("bad-prodis-fee");
    if (!unanimous && bonus_total > mn.early_penalty) return std::string("bad-prodis-bonus");
    return std::nullopt;
}

/// The contextual tx check for a block: Core v24's type whitelist (0..12) once
/// DEPLOYMENT_V24 is active for it, the v23.1.9 list (0..9) before.
template <typename Tx>
std::optional<std::string_view> contextual_tx_check_at(const Tx& tx, bool is_coinbase, bool v24_active_)
{
    return v24_active_ ? contextual_tx_check_v24(tx, is_coinbase) : contextual_tx_check(tx, is_coinbase);
}

} // namespace v24
} // namespace coin
} // namespace dash
