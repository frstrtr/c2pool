// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Template-side masternode-list fold for the DIP-3 provider special
/// transactions (types 1-4) a served embedded block includes.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY THIS EXISTS
/// ─────────────────────────────────────────────────────────────────────────
/// dashd builds the masternode list a block commits FROM THE BLOCK'S OWN TXS:
/// `BuildNewListFromBlock(block, pindex->pprev, ...)` (evo/specialtxman.cpp),
/// then `CalcCbTxMerkleRootMNList` over that POST-diff list, then rejects
/// `bad-cbtx-mnmerkleroot` when the coinbase's committed root does not match.
/// So including a ProRegTx / ProUpServTx / ProUpRegTx / ProUpRevTx in the
/// embedded template WITHOUT recomputing merkleRootMNList over the list those
/// txs produce is a guaranteed bad-cbtx on a won block.
///
/// This header is the template-side analogue of that per-type application. It
/// runs on a COPY of the PROJECTED SML (sml_projection.hpp's confirmedHash
/// pass already applied) — it NEVER mutates any follower state — and produces
/// the post-diff list whose CalcMerkleRoot() is the root the CbTx must commit.
/// It touches ONLY the DIP-4 simplified-entry fields that feed
/// CSimplifiedMNListEntry::CalcHash (the merkle leaf): nVersion, proRegTxHash,
/// confirmedHash, service (netAddress+netPort), pubKeyOperator, keyIDVoting,
/// isValid, nType, platform fields. scriptPayout / nLastPaidHeight / penalty
/// counters are NOT hashed into the leaf, so they are deliberately absent.
///
/// ─────────────────────────────────────────────────────────────────────────
/// FAIL-CLOSED CONTRACT
/// ─────────────────────────────────────────────────────────────────────────
/// A transaction this fold cannot apply EXACTLY (payload parse failure, an
/// update naming a proRegTxHash the list does not hold, a registration whose
/// proRegTxHash or operator key already exists) is REFUSED — the caller
/// excludes that one tx from the template and logs it, exactly as dashd's own
/// getblocktemplate would never include a tx that fails BuildNewListFromBlock.
/// A refusal never mutates the list. The emit gate re-runs this same fold over
/// the served body and refuses the whole template on any residual mismatch, so
/// a folded root that is wrong for any reason is caught before it is served.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE CONTEXT FOLD (ported through Dash Core v23.1.9)
/// ─────────────────────────────────────────────────────────────────────────
/// The serving paths (embedded_gbt.hpp builder, node_coin_state.hpp emit gate)
/// call the MnFoldContext overload of fold_mn_special_txs, which adds what a
/// dashd block validator checks and the leaf-only fold below cannot see:
///   * CheckProRegTx / CheckProUpServTx / CheckProUpRegTx / CheckProUpRevTx
///     against the PRE-block list (dashd CheckSpecialTxInner reads pindexPrev):
///     payload version (ExtAddr refused — V24 not ported), IsValidMnType,
///     Evo needs BasicBLS, an update must name an MN of the pre-block list,
///     ProUpServTx nType == the registered nType (#7488), uniqueness of
///     keyIDOwner / pubKeyOperator / service / platformNodeID with keyIDOwner
///     and platformNodeID in ONE namespace (#7846), the external collateral
///     coin and amount (when the UTXO set can prove it), and the BLS operator
///     signature of ProUpServTx / ProUpRevTx (B.9, bad-protx-sig).
///   * RebuildListFromBlock's own list mutations: a ProRegTx reusing a live
///     collateral REMOVES that MN, so a later update to it is refused (#7489);
///     and, after every tx, the second loop removing each MN whose collateral
///     ANY non-refused body tx spends (specialtxman.cpp, after the special-tx
///     loop — the order dashd uses).
/// Every new condition only REFUSES (the caller drops the tx and its fee), so
/// the template stays reward-safe; the only list change it adds is dashd's own
/// removal of a replaced / collateral-spent MN.

#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>   // opkey_to_basic (canonical operator key)
#include <impl/dash/coin/mn_state_machine.hpp>    // MnFoldContext::from, TxPrevOutLess
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // dash_txid

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// Outcome of applying ONE transaction to the folded list.
enum class MnFoldOutcome {
    Ignored,   ///< not a type 1-4 tx (nothing to do)
    Applied,   ///< a type 1-4 tx whose effect was folded into the list
    Refused    ///< a type 1-4 tx that could not be applied exactly (exclude it)
};

namespace detail {

// Is a legacy 18-byte CService "empty" (no address AND no port)? dashd
// registers/keeps a masternode BANNED while its netInfo is empty; the SML
// leaf reflects that as isValid=false.
inline bool net_service_empty(const std::array<uint8_t, vendor::NETADDR_SIZE>& ip,
                              uint16_t port_be)
{
    if (port_be != 0) return false;
    for (uint8_t b : ip) if (b != 0) return false;
    return true;
}

// Find the SML entry for a proRegTxHash. Returns nullptr when absent.
inline vendor::CSimplifiedMNListEntry*
find_entry(std::vector<vendor::CSimplifiedMNListEntry>& list, const uint256& pro)
{
    for (auto& e : list)
        if (e.proRegTxHash == pro) return &e;
    return nullptr;
}

} // namespace detail

/// Apply one candidate special tx to the working entry list. `list` is the
/// mutable leaf set of a CSimplifiedMNList copy (the caller re-sorts + hashes
/// after the whole pass). Types other than 1-4 are Ignored. Returns Refused
/// (and leaves the list UNCHANGED) when the tx cannot be applied exactly.
template <typename Tx>
inline MnFoldOutcome apply_mn_special_tx_to_sml(
    std::vector<vendor::CSimplifiedMNListEntry>& list, const Tx& tx)
{
    switch (tx.type) {
    // ── type 1 ProRegTx — AddMN ──────────────────────────────────────────
    case vendor::CProRegTx::SPECIALTX_TYPE: {
        vendor::CProRegTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;

        // The new registration's proRegTxHash is the ProRegTx's own txid
        // (dashd: newState->proTxHash = tx.GetHash()).
        const uint256 pro = dash::coin::dash_txid(::dash::coin::MutableTransaction(tx));

        // dup-proRegTxHash / dup-operator-key refusal (the caller excludes the
        // tx rather than folding a list dashd's AddMN would reject).
        for (const auto& e : list) {
            if (e.proRegTxHash == pro) return MnFoldOutcome::Refused;
            if (e.pubKeyOperator == pl.pubKeyOperator) return MnFoldOutcome::Refused;
        }

        vendor::CSimplifiedMNListEntry e;
        e.nVersion       = pl.nVersion;               // 1=legacy,2=basic,3=extaddr
        e.proRegTxHash   = pro;
        e.confirmedHash  = uint256::ZERO;             // registered here, not yet confirmed
        e.netAddress     = pl.netInfo.ip;
        e.netPort        = pl.netInfo.port_be;
        // The ProReg payload's operator key is ALREADY encoded in the scheme
        // its nVersion dictates (legacy iff nVersion < BASIC_BLS), which is
        // exactly the scheme the SML leaf hashes for that nVersion — copy the
        // wire bytes straight through.
        e.pubKeyOperator = pl.pubKeyOperator;
        e.keyIDVoting    = pl.keyIDVoting;
        // Empty netInfo ⇒ registers BANNED (isValid=false), else valid.
        e.isValid        = !detail::net_service_empty(pl.netInfo.ip, pl.netInfo.port_be);
        e.nType          = pl.nType;
        e.platformHTTPPort = pl.platformHTTPPort;
        e.platformNodeID   = pl.platformNodeID;
        list.push_back(e);
        return MnFoldOutcome::Applied;
    }

    // ── type 2 ProUpServTx — UpdateService (+ revive) ────────────────────
    case vendor::CProUpServTx::SPECIALTX_TYPE: {
        vendor::CProUpServTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        e->netAddress = pl.netInfo.ip;
        e->netPort    = pl.netInfo.port_be;
        if (e->nType == vendor::CSimplifiedMNListEntry::TYPE_EVO) {
            e->platformHTTPPort = pl.platformHTTPPort;
            e->platformNodeID   = pl.platformNodeID;
        }
        // dashd revives a banned masternode on a ProUpServTx once its service
        // is set again (BuildNewListFromBlock Revive). A non-empty netInfo is
        // the revive trigger the SML leaf can see.
        if (!detail::net_service_empty(pl.netInfo.ip, pl.netInfo.port_be))
            e->isValid = true;
        return MnFoldOutcome::Applied;
    }

    // ── type 3 ProUpRegTx — UpdateRegistrar ──────────────────────────────
    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        e->keyIDVoting = pl.keyIDVoting;
        // Operator-key change ⇒ ResetOperatorFields + ban, exactly as dashd's
        // BuildNewListFromBlock: the masternode must re-announce service with a
        // ProUpServTx before it is valid again.
        if (e->pubKeyOperator != pl.pubKeyOperator) {
            e->pubKeyOperator = pl.pubKeyOperator;
            e->netAddress = {};
            e->netPort    = 0;
            e->isValid    = false;
        }
        return MnFoldOutcome::Applied;
    }

    // ── type 4 ProUpRevTx — RevokeOperator (ban) ─────────────────────────
    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        // ResetOperatorFields + ban: operator key cleared, service cleared,
        // isValid=false until a fresh ProUpRegTx(new key)+ProUpServTx pair.
        e->pubKeyOperator = {};
        e->netAddress = {};
        e->netPort    = 0;
        e->isValid    = false;
        return MnFoldOutcome::Applied;
    }

    default:
        return MnFoldOutcome::Ignored;
    }
    return MnFoldOutcome::Ignored;   // unreachable; silences -Wreturn-type
}

/// Result of folding a body's type 1-4 txs onto a projected SML copy.
struct SmlSpecialFold {
    vendor::CSimplifiedMNList sml;          ///< projected list with types 1-4 applied
    unsigned applied{0};                    ///< txs whose effect was folded
    unsigned refused{0};                    ///< txs that could not be applied
    std::vector<uint256> refused_ids;       ///< txids the caller must exclude
    /// Context fold only: dashd's reject reason per refused_ids entry.
    std::vector<std::string> refused_reasons;
    /// Context fold only: MNs a ProRegTx collateral reuse replaced (#7489).
    unsigned replaced{0};
    /// Context fold only: MNs removed because a body tx spent the collateral.
    unsigned collateral_removed{0};
    bool clean() const { return refused == 0; }
};

/// Fold every type 1-4 tx in `body_txs` onto a COPY of `base` (a projected
/// SML). Refusals are recorded but never mutate the list. The returned list is
/// re-sorted so CalcMerkleRoot() is the committed root.
template <typename TxRange, typename TxidFn>
inline SmlSpecialFold fold_mn_special_txs(const vendor::CSimplifiedMNList& base,
                                          const TxRange& body_txs,
                                          TxidFn&& txid_of)
{
    SmlSpecialFold out;
    out.sml = base;                         // COPY — never the follower's list
    for (const auto& tx : body_txs) {
        const auto r = apply_mn_special_tx_to_sml(out.sml.mnList, tx);
        if (r == MnFoldOutcome::Applied) {
            ++out.applied;
        } else if (r == MnFoldOutcome::Refused) {
            ++out.refused;
            out.refused_ids.push_back(txid_of(tx));
        }
    }
    out.sml.sort();                         // dashd memcmp(proRegTxHash) order
    return out;
}

// ═════════════════════════════════════════════════════════════════════════
// THE CONTEXT FOLD (see the header comment)
// ═════════════════════════════════════════════════════════════════════════

/// The PRE-block masternode list facts the leaf-only SML cannot carry
/// (collateral outpoints, owner keys), plus the two oracles the dashd checks
/// need. Built once per fold from the live MnStateMachine; read-only during
/// the fold (in-body changes live in the fold's own overlay).
struct MnFoldContext
{
    using Outpoint = bitcoin_family::coin::TxPrevOut;
    using Service  = std::pair<std::array<uint8_t, vendor::NETADDR_SIZE>, uint16_t>;
    using OpKey    = std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>;
    using Sig      = std::array<uint8_t, vendor::BLS_SIG_SIZE>;

    /// What the chain UTXO set can prove about an external collateral.
    enum class CollateralProof : uint8_t { Unknown, Unspent, Absent };
    /// Fills `value` (duffs) on Unspent. Unset ⇒ the coin check is skipped.
    using CollateralCoinFn =
        std::function<CollateralProof(const Outpoint&, int64_t& value)>;
    /// BLS operator-signature verify (vendor::verify_protx_operator_sig
    /// shape). Unset ⇒ ProUpServTx / ProUpRevTx are REFUSED (fail closed).
    using OperatorSigFn = std::function<bool(const OpKey& pubkey, bool key_legacy,
                                             const uint256& sign_hash,
                                             const Sig& sig, bool sig_legacy)>;

    /// The pre-block list's unique-property indexes (dashd mnUniquePropertyMap).
    struct Unique {
        /// keyIDOwner ∪ Evo platformNodeID → proTxHash. dashd hashes CKeyID
        /// and uint160 identically, so the two are ONE namespace (#7846). Null
        /// ids are never entered (AddUniqueProperty skips the null value).
        std::map<uint160, uint256> owner_or_platform_ids;
        std::map<OpKey, uint256>   operator_keys;   ///< canonical BASIC, non-null
        std::map<Service, uint256> services;        ///< non-empty netInfo
    };

    const MnStateMachine* mns{nullptr};   ///< the pre-block list (non-owning)
    CollateralCoinFn      collateral_coin;
    OperatorSigFn         verify_operator_sig;

    static MnFoldContext from(const MnStateMachine& m,
                              CollateralCoinFn coin = {},
                              OperatorSigFn sig = {})
    {
        MnFoldContext c;
        c.mns                 = &m;
        c.collateral_coin     = std::move(coin);
        c.verify_operator_sig = std::move(sig);
        return c;
    }

    /// GetMNByCollateral on the pre-block list (the machine's own index).
    std::optional<uint256> collateral_owner(const Outpoint& op) const
    {
        return mns != nullptr ? mns->find_by_collateral(op) : std::nullopt;
    }
    std::optional<Outpoint> collateral_of(const uint256& pro) const
    {
        if (mns == nullptr) return std::nullopt;
        auto it = mns->entries().find(pro);
        if (it == mns->entries().end()) return std::nullopt;
        return it->second.collateralOutpoint;
    }

    /// Built on first use: only a body that carries a ProRegTx / ProUpServTx /
    /// ProUpRegTx pays for indexing the list (the emit gate folds every
    /// served body, and most carry no provider tx at all).
    const Unique& unique() const
    {
        if (!m_unique) {
            Unique u;
            if (mns != nullptr) {
                for (const auto& [pro, st] : mns->entries()) {
                    if (!st.keyIDOwner.IsNull())
                        u.owner_or_platform_ids.emplace(st.keyIDOwner, pro);
                    if (st.nType == vendor::MnType::EVO && !st.platformNodeID.IsNull())
                        u.owner_or_platform_ids.emplace(st.platformNodeID, pro);
                    bool null_key = true;
                    for (uint8_t b : st.pubKeyOperator) if (b != 0) { null_key = false; break; }
                    if (!null_key) u.operator_keys.emplace(st.pubKeyOperator, pro);   // stored BASIC
                    if (!detail::net_service_empty(st.netInfo.ip, st.netInfo.port_be))
                        u.services.emplace(Service{st.netInfo.ip, st.netInfo.port_be}, pro);
                }
            }
            m_unique = std::move(u);
        }
        return *m_unique;
    }

private:
    mutable std::optional<Unique> m_unique;
};

/// Memoize a (pure) operator-signature verdict: the builder and the emit gate
/// re-fold the same served body many times per tip, and each ProUpServTx /
/// ProUpRevTx otherwise re-pays a BLS pairing every time. Keyed by every
/// input of the verify; bounded FIFO. Thread-safe.
inline MnFoldContext::OperatorSigFn
memoize_operator_sig_fn(MnFoldContext::OperatorSigFn inner, size_t cap = 4096)
{
    struct Memo {
        std::mutex mu;
        std::map<std::string, bool> verdicts;
        std::deque<std::string> order;
    };
    auto memo = std::make_shared<Memo>();
    return [inner = std::move(inner), memo, cap](
               const MnFoldContext::OpKey& key, bool key_legacy, const uint256& h,
               const MnFoldContext::Sig& sig, bool sig_legacy) {
        std::string k;
        k.reserve(key.size() + 32 + sig.size() + 2);
        k.append(reinterpret_cast<const char*>(key.data()), key.size());
        k.append(reinterpret_cast<const char*>(h.data()), 32);
        k.append(reinterpret_cast<const char*>(sig.data()), sig.size());
        k.push_back(key_legacy ? 1 : 0);
        k.push_back(sig_legacy ? 1 : 0);
        {
            std::lock_guard<std::mutex> lock(memo->mu);
            auto it = memo->verdicts.find(k);
            if (it != memo->verdicts.end()) return it->second;
        }
        const bool ok = inner && inner(key, key_legacy, h, sig, sig_legacy);
        std::lock_guard<std::mutex> lock(memo->mu);
        if (memo->verdicts.emplace(k, ok).second) {
            memo->order.push_back(k);
            while (memo->order.size() > cap) {
                memo->verdicts.erase(memo->order.front());
                memo->order.pop_front();
            }
        }
        return ok;
    };
}

namespace detail {

/// dashd dmn_types.h collat_amount (duffs).
inline constexpr int64_t kCollateralRegular = 1000LL * 100'000'000LL;
inline constexpr int64_t kCollateralEvo     = 4000LL * 100'000'000LL;

/// In-body changes to the pre-block list (dashd newList vs prevList).
struct MnFoldOverlay
{
    std::set<uint256> removed;   ///< replaced by a ProRegTx, or collateral spent
    std::map<MnFoldContext::Outpoint, uint256, TxPrevOutLess> added_collateral;
    std::map<uint160, uint256>                   added_ids;
    std::map<MnFoldContext::OpKey, uint256>      added_opkeys;
    std::map<MnFoldContext::Service, uint256>    added_services;

    /// GetMNByCollateral on the evolving list.
    std::optional<uint256> collateral_owner(const MnFoldContext& ctx,
                                            const MnFoldContext::Outpoint& op) const
    {
        auto a = added_collateral.find(op);
        if (a != added_collateral.end() && !removed.count(a->second)) return a->second;
        auto b = ctx.collateral_owner(op);
        if (b && !removed.count(*b)) return b;
        return std::nullopt;
    }

    template <typename Map>
    static void erase_owned(Map& m, const uint256& pro)
    {
        for (auto it = m.begin(); it != m.end();)
            it = (it->second == pro) ? m.erase(it) : std::next(it);
    }

    /// RemoveMN on the evolving list (and the folded leaf set).
    void remove_mn(std::vector<vendor::CSimplifiedMNListEntry>& list, const uint256& pro)
    {
        for (auto it = list.begin(); it != list.end(); ++it)
            if (it->proRegTxHash == pro) { list.erase(it); break; }
        removed.insert(pro);
        erase_owned(added_collateral, pro);
        erase_owned(added_ids, pro);
        erase_owned(added_opkeys, pro);
        erase_owned(added_services, pro);
    }
};

/// A value held by an MN other than `self` — in the pre-block list (dashd
/// CheckProTx reads prevList, so an MN replaced or updated earlier in this
/// body still holds its old values) or added by this body (newList).
template <typename Key, typename BaseMap, typename AddedMap>
inline bool held_by_other(const Key& k, const BaseMap& base, const AddedMap& added,
                          const uint256& self)
{
    auto b = base.find(k);
    if (b != base.end() && b->second != self) return true;
    auto a = added.find(k);
    return a != added.end() && a->second != self;
}

inline std::optional<MnFoldContext::Service>
service_of(const vendor::LegacyNetService& n)
{
    if (net_service_empty(n.ip, n.port_be)) return std::nullopt;
    return MnFoldContext::Service{n.ip, n.port_be};
}

inline bool opkey_is_null(const MnFoldContext::OpKey& k)
{
    for (uint8_t b : k) if (b != 0) return false;
    return true;
}

/// Pre-block (prevList) leaf of `pro`, or nullptr.
inline const vendor::CSimplifiedMNListEntry*
base_entry(const vendor::CSimplifiedMNList& base, const uint256& pro)
{
    for (const auto& e : base.mnList)
        if (e.proRegTxHash == pro) return &e;
    return nullptr;
}

struct FoldVerdict {
    MnFoldOutcome outcome{MnFoldOutcome::Ignored};
    std::string   reason;
};
inline FoldVerdict refuse(std::string why) { return {MnFoldOutcome::Refused, std::move(why)}; }

/// Common payload-version gate (IsTriviallyValid + the V24 boundary): ExtAddr
/// payloads (nVersion >= 3) need DEPLOYMENT_V24, which is not ported — a
/// parse that happened to succeed must never be folded.
inline std::optional<std::string> protx_version_refusal(uint16_t nVersion)
{
    if (nVersion == 0) return std::string("bad-protx-version (nVersion=0)");
    if (nVersion >= vendor::ProTxVersion::EXT_ADDR)
        return "bad-protx-version (nVersion=" + std::to_string(nVersion)
             + ", ExtAddr — DEPLOYMENT_V24 is not ported)";
    return std::nullopt;
}

/// The pre-block entry an update names, checked against both lists (dashd
/// CheckProUp*Tx on prevList, then RebuildListFromBlock on newList).
inline std::optional<std::string>
update_target_refusal(const vendor::CSimplifiedMNList& base,
                      const std::vector<vendor::CSimplifiedMNListEntry>& list,
                      const MnFoldOverlay& ov, const uint256& pro,
                      const vendor::CSimplifiedMNListEntry*& be_out)
{
    be_out = base_entry(base, pro);
    if (be_out == nullptr)
        return "bad-protx-hash (" + pro.GetHex().substr(0, 16)
             + " is not in the pre-block list)";
    if (ov.removed.count(pro))
        return "bad-protx-hash (" + pro.GetHex().substr(0, 16)
             + " was removed earlier in this block)";
    for (const auto& e : list)
        if (e.proRegTxHash == pro) return std::nullopt;
    return "bad-protx-hash (" + pro.GetHex().substr(0, 16) + " not in the folded list)";
}

/// B.9: CheckHashSig against the PRE-block operator key.
template <typename Payload>
inline std::optional<std::string>
operator_sig_refusal(const MnFoldContext& ctx, const vendor::CSimplifiedMNListEntry& be,
                     const std::vector<uint8_t>& payload, const Payload& pl)
{
    if (!ctx.verify_operator_sig)
        return std::string("bad-protx-sig (no operator-signature verifier wired)");
    const auto h = vendor::protx_operator_sign_hash(payload);
    if (!h) return std::string("bad-protx-sig (payload too short)");
    const bool key_legacy = be.nVersion < vendor::CSimplifiedMNListEntry::VER_BASIC_BLS;
    const bool sig_legacy = pl.nVersion == vendor::ProTxVersion::LEGACY_BLS;
    if (!ctx.verify_operator_sig(be.pubKeyOperator, key_legacy, *h, pl.sig, sig_legacy))
        return std::string("bad-protx-sig (not signed by the pre-block operator key)");
    return std::nullopt;
}

template <typename Tx>
inline FoldVerdict fold_one_with_ctx(vendor::CSimplifiedMNList& folded,
                                     const vendor::CSimplifiedMNList& base,
                                     const Tx& tx, const MnFoldContext& ctx,
                                     MnFoldOverlay& ov, SmlSpecialFold& out)
{
    auto& list = folded.mnList;
    if (tx.type < 1 || tx.type > 4) return {};
    if (auto why = contextual_tx_check(tx, /*is_coinbase=*/false))
        return refuse(std::string(*why));

    switch (tx.type) {
    case vendor::CProRegTx::SPECIALTX_TYPE: {
        vendor::CProRegTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return refuse("bad-protx-payload");
        if (auto why = protx_version_refusal(pl.nVersion)) return refuse(*why);
        if (pl.nType != vendor::MnType::REGULAR && pl.nType != vendor::MnType::EVO)
            return refuse("bad-protx-type (nType=" + std::to_string(pl.nType) + ")");
        if (pl.nType == vendor::MnType::EVO && pl.nVersion < vendor::ProTxVersion::BASIC_BLS)
            return refuse("bad-protx-evo-version");
        const uint256 pro = dash::coin::dash_txid(::dash::coin::MutableTransaction(tx));

        MnFoldContext::Outpoint coll = pl.collateralOutpoint;
        const bool external = !coll.hash.IsNull();
        if (!external) coll.hash = pro;
        // CheckProRegTx: an external collateral is an unspent coin of exactly
        // collat_amount(nType). Refused only on PROOF (a forward-view miss is
        // not proof — see Mempool::prove_chain_coin).
        if (external && ctx.collateral_coin) {
            int64_t value = 0;
            const auto proof = ctx.collateral_coin(coll, value);
            if (proof == MnFoldContext::CollateralProof::Absent)
                return refuse("bad-protx-collateral (not an unspent coin)");
            const int64_t want = pl.nType == vendor::MnType::EVO ? kCollateralEvo
                                                                 : kCollateralRegular;
            if (proof == MnFoldContext::CollateralProof::Unspent && value != want)
                return refuse("bad-protx-collateral (amount " + std::to_string(value)
                              + " != " + std::to_string(want) + ")");
        }
        // The leaf checks the fold always had (evolving list).
        for (const auto& e : list) {
            if (e.proRegTxHash == pro) return refuse("bad-protx-dup (proRegTxHash)");
            if (e.pubKeyOperator == pl.pubKeyOperator)
                return refuse("bad-protx-dup-key (operator key in the list)");
        }
        // "never allow duplicate keys, even if this ProTx would replace an
        // existing MN" (CheckProRegTx on prevList) + AddMN on newList.
        const uint256 none{};
        const auto& uq = ctx.unique();
        if (!pl.keyIDOwner.IsNull()
            && held_by_other(pl.keyIDOwner, uq.owner_or_platform_ids, ov.added_ids, none))
            return refuse("bad-protx-dup-key (keyIDOwner is an owner key or platformNodeID)");
        const auto op_basic = vendor::opkey_to_basic(
            pl.pubKeyOperator, pl.nVersion < vendor::ProTxVersion::BASIC_BLS);
        if (!opkey_is_null(op_basic)
            && held_by_other(op_basic, uq.operator_keys, ov.added_opkeys, none))
            return refuse("bad-protx-dup-key (pubKeyOperator)");
        const bool evo = pl.nType == vendor::MnType::EVO;
        if (evo && !pl.platformNodeID.IsNull()
            && held_by_other(pl.platformNodeID, uq.owner_or_platform_ids, ov.added_ids, none))
            return refuse("bad-protx-dup-platformnodeid (an owner key or platformNodeID)");
        const auto svc = service_of(pl.netInfo);
        if (svc) {
            // prevList: only the MN this collateral replaces may hold it.
            auto b = uq.services.find(*svc);
            if (b != uq.services.end()) {
                const auto pc = ctx.collateral_of(b->second);
                const bool same_collateral =
                    pc && pc->hash == coll.hash && pc->index == coll.index;
                if (!same_collateral)
                    return refuse("bad-protx-dup-netinfo-entry (service in use)");
            }
            if (ov.added_services.count(*svc))
                return refuse("bad-protx-dup-netinfo-entry (service registered in this block)");
        }

        // ── all checks passed: mutate ──
        // #7489: a ProRegTx reusing a live collateral REMOVES that MN first.
        if (auto replaced = ov.collateral_owner(ctx, coll)) {
            ov.remove_mn(list, *replaced);
            ++out.replaced;
        }
        if (apply_mn_special_tx_to_sml(list, tx) != MnFoldOutcome::Applied)
            return refuse("bad-protx-payload (leaf apply)");   // unreachable: checked above
        ov.added_collateral[coll] = pro;
        if (!pl.keyIDOwner.IsNull()) ov.added_ids.emplace(pl.keyIDOwner, pro);
        if (evo && !pl.platformNodeID.IsNull()) ov.added_ids.emplace(pl.platformNodeID, pro);
        if (!opkey_is_null(op_basic)) ov.added_opkeys.emplace(op_basic, pro);
        if (svc) ov.added_services.emplace(*svc, pro);
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpServTx::SPECIALTX_TYPE: {
        vendor::CProUpServTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return refuse("bad-protx-payload");
        if (auto why = protx_version_refusal(pl.nVersion)) return refuse(*why);
        // #7488: IsValidMnType in CProUpServTx::IsTriviallyValid.
        if (pl.nType != vendor::MnType::REGULAR && pl.nType != vendor::MnType::EVO)
            return refuse("bad-protx-type (nType=" + std::to_string(pl.nType) + ")");
        if (pl.nType == vendor::MnType::EVO && pl.nVersion < vendor::ProTxVersion::BASIC_BLS)
            return refuse("bad-protx-evo-version");
        const vendor::CSimplifiedMNListEntry* be = nullptr;
        if (auto why = update_target_refusal(base, list, ov, pl.proTxHash, be))
            return refuse(*why);
        // #7488: nType must equal the registered MN's nType.
        if (pl.nType != be->nType)
            return refuse("bad-protx-type-mismatch (payload nType=" + std::to_string(pl.nType)
                          + ", registered nType=" + std::to_string(be->nType) + ")");
        const auto& uq = ctx.unique();
        const auto svc = service_of(pl.netInfo);
        if (svc && held_by_other(*svc, uq.services, ov.added_services, pl.proTxHash))
            return refuse("bad-protx-dup-netinfo-entry (service held by another MN)");
        const bool evo = pl.nType == vendor::MnType::EVO;
        if (evo && !pl.platformNodeID.IsNull()
            && held_by_other(pl.platformNodeID, uq.owner_or_platform_ids, ov.added_ids,
                             pl.proTxHash))
            return refuse("bad-protx-dup-platformnodeid (another MN's owner key or platformNodeID)");
        if (auto why = operator_sig_refusal(ctx, *be, tx.extra_payload, pl))
            return refuse(*why);
        if (apply_mn_special_tx_to_sml(list, tx) != MnFoldOutcome::Applied)
            return refuse("bad-protx-hash (leaf apply)");   // unreachable: checked above
        if (svc) ov.added_services[*svc] = pl.proTxHash;
        if (evo && !pl.platformNodeID.IsNull()) ov.added_ids[pl.platformNodeID] = pl.proTxHash;
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return refuse("bad-protx-payload");
        if (auto why = protx_version_refusal(pl.nVersion)) return refuse(*why);
        const vendor::CSimplifiedMNListEntry* be = nullptr;
        if (auto why = update_target_refusal(base, list, ov, pl.proTxHash, be))
            return refuse(*why);
        const auto op_basic = vendor::opkey_to_basic(
            pl.pubKeyOperator, pl.nVersion < vendor::ProTxVersion::BASIC_BLS);
        if (!opkey_is_null(op_basic)
            && held_by_other(op_basic, ctx.unique().operator_keys, ov.added_opkeys, pl.proTxHash))
            return refuse("bad-protx-dup-key (pubKeyOperator held by another MN)");
        if (apply_mn_special_tx_to_sml(list, tx) != MnFoldOutcome::Applied)
            return refuse("bad-protx-hash (leaf apply)");   // unreachable: checked above
        if (!opkey_is_null(op_basic)) ov.added_opkeys[op_basic] = pl.proTxHash;
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return refuse("bad-protx-payload");
        if (auto why = protx_version_refusal(pl.nVersion)) return refuse(*why);
        const vendor::CSimplifiedMNListEntry* be = nullptr;
        if (auto why = update_target_refusal(base, list, ov, pl.proTxHash, be))
            return refuse(*why);
        if (auto why = operator_sig_refusal(ctx, *be, tx.extra_payload, pl))
            return refuse(*why);
        if (apply_mn_special_tx_to_sml(list, tx) != MnFoldOutcome::Applied)
            return refuse("bad-protx-hash (leaf apply)");   // unreachable: checked above
        return {MnFoldOutcome::Applied, {}};
    }

    default:
        return {};
    }
}

} // namespace detail

/// The serving-path fold: fold every type 1-4 tx in `body_txs` (block order,
/// the coinbase excluded) onto a COPY of `base` with the pre-block context
/// `ctx`, then remove every MN whose collateral a non-refused body tx spends
/// (dashd's second RebuildListFromBlock loop). Refused txs never mutate the
/// list and their inputs are not counted as spends — the caller drops them,
/// so the served body never carries them.
template <typename TxRange, typename TxidFn>
inline SmlSpecialFold fold_mn_special_txs(const vendor::CSimplifiedMNList& base,
                                          const TxRange& body_txs,
                                          TxidFn&& txid_of,
                                          const MnFoldContext& ctx)
{
    SmlSpecialFold out;
    out.sml = base;                         // COPY — never the follower's list
    detail::MnFoldOverlay ov;
    std::vector<bool> refused;
    for (const auto& tx : body_txs) {
        const auto v = detail::fold_one_with_ctx(out.sml, base, tx, ctx, ov, out);
        refused.push_back(v.outcome == MnFoldOutcome::Refused);
        if (v.outcome == MnFoldOutcome::Applied) {
            ++out.applied;
        } else if (v.outcome == MnFoldOutcome::Refused) {
            ++out.refused;
            out.refused_ids.push_back(txid_of(tx));
            out.refused_reasons.push_back(v.reason);
        }
    }
    // RebuildListFromBlock's collateral loop, after the special-tx loop.
    size_t i = 0;
    for (const auto& tx : body_txs) {
        if (!refused[i++]) {
            for (const auto& in : tx.vin) {
                if (auto mn = ov.collateral_owner(ctx, in.prevout)) {
                    ov.remove_mn(out.sml.mnList, *mn);
                    ++out.collateral_removed;
                }
            }
        }
    }
    out.sml.sort();                         // dashd memcmp(proRegTxHash) order
    return out;
}

} // namespace coin
} // namespace dash
