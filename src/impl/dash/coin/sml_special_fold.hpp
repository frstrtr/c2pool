// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Template-side masternode-list fold for the DIP-3 provider special
/// transactions (types 1-4) a served embedded block includes, and, once Dash
/// Core v24 is active for the block, for every provider type (1-4 and the
/// shared-masternode types 10-12) through the v24 transitions (THE V24 FOLD,
/// below).
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
#include <impl/dash/coin/vendor/bls_verify.hpp>   // opkey_point_eq (scheme-faithful operator-key compare)
#include <impl/dash/coin/mn_state_machine.hpp>    // MnFoldContext::from, TxPrevOutLess
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // dash_txid
#include <impl/dash/coin/v24_sml_leaf.hpp>   // Dash Core v24 state -> SML leaf (shared with the replay fold)
#include <impl/dash/coin/v24_state.hpp>      // Dash Core v24 state transitions (shared with both mined-block folds)

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
#include <tuple>
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

// Is a legacy 18-byte CService "empty"? dashd registers/keeps a masternode
// BANNED while its netInfo is empty; the SML leaf reflects that as
// isValid=false. Empty is Dash Core's rule (MnNetInfo::IsEmpty): ANY service
// whose address is not valid (::ffff:0.0.0.0, ::, ::ffff:255.255.255.255,
// TORv2- or internal-in-IPv6, 2001:db8::/32), whatever its port -- not just
// the all-zero bytes. Such a service is held and hashed as 16 zero bytes and
// port 0 (LegacyNetService::canonical()).
inline bool net_service_empty(const vendor::LegacyNetService& n)
{
    return n.IsEmpty();
}

// Find the SML entry for a proRegTxHash. Returns nullptr when absent.
inline vendor::CSimplifiedMNListEntry*
find_entry(std::vector<vendor::CSimplifiedMNListEntry>& list, const uint256& pro)
{
    for (auto& e : list)
        if (e.proRegTxHash == pro) return &e;
    return nullptr;
}

// dashd CBLSLazyWrapper::operator== (bls/bls.h @ v23.1.9) between the key a
// masternode holds and a ProUpRegTx's key, each with the scheme it was read
// under (legacy iff its nVersion < BasicBLS): two null keys are equal; under
// the same scheme the BYTES decide; across schemes the decoded POINTS decide
// (opkey_point_eq — the h=1874081 and #154 classes). Returns true when the
// operator key CHANGES.
inline bool operator_key_changed(const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& held,
                                 bool held_legacy,
                                 const std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>& wire,
                                 bool wire_legacy)
{
    bool held_null = true, wire_null = true;
    for (uint8_t b : held) if (b != 0) { held_null = false; break; }
    for (uint8_t b : wire) if (b != 0) { wire_null = false; break; }
    if (held_null || wire_null) return held_null != wire_null;
    if (held_legacy == wire_legacy) return held != wire;
    return !vendor::opkey_point_eq(held, held_legacy, wire, wire_legacy);
}

// dashd CDeterministicMNState::ResetOperatorFields (evo/dmnstate.h:112-120)
// as the SML leaf sees it, plus the ban: nVersion back to LegacyBLS, operator
// key, service and platformNodeID cleared, isValid=false. The leaf hash drops
// nType and the platform fields while nVersion < BasicBLS
// (CSimplifiedMNListEntry serialization), so the nVersion reset changes the
// committed root. platformHTTPPort is not reset by dashd and is kept.
inline void reset_operator_fields(vendor::CSimplifiedMNListEntry& e)
{
    e.nVersion       = vendor::CSimplifiedMNListEntry::VER_LEGACY_BLS;
    e.pubKeyOperator = {};
    e.netAddress     = {};
    e.netPort        = 0;
    e.isValid        = false;
    e.platformNodeID = uint160{};
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
        // A v3 (ExtAddr, Dash Core v24) leaf carries an ExtNetInfo this fold
        // does not build yet: refuse rather than emit a v2-shaped v3 leaf.
        if (pl.nVersion >= vendor::ProTxVersion::EXT_ADDR) return MnFoldOutcome::Refused;

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
        e.netAddress     = pl.netInfo.canonical().ip;
        e.netPort        = pl.netInfo.canonical().port_be;
        // The ProReg payload's operator key is ALREADY encoded in the scheme
        // its nVersion dictates (legacy iff nVersion < BASIC_BLS), which is
        // exactly the scheme the SML leaf hashes for that nVersion — copy the
        // wire bytes straight through.
        e.pubKeyOperator = pl.pubKeyOperator;
        e.keyIDVoting    = pl.keyIDVoting;
        // Empty netInfo ⇒ registers BANNED (isValid=false), else valid.
        e.isValid        = !detail::net_service_empty(pl.netInfo);
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
        if (pl.nVersion >= vendor::ProTxVersion::EXT_ADDR) return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        if (e->has_ext_netinfo()) return MnFoldOutcome::Refused;   // v24 SetStateVersion not ported
        e->netAddress = pl.netInfo.canonical().ip;
        e->netPort    = pl.netInfo.canonical().port_be;
        if (e->nType == vendor::CSimplifiedMNListEntry::TYPE_EVO) {
            e->platformHTTPPort = pl.platformHTTPPort;
            e->platformNodeID   = pl.platformNodeID;
        }
        // dashd revives a banned masternode on a ProUpServTx once its service
        // is set again (BuildNewListFromBlock Revive). A non-empty netInfo is
        // the revive trigger the SML leaf can see.
        if (!detail::net_service_empty(pl.netInfo))
            e->isValid = true;
        return MnFoldOutcome::Applied;
    }

    // ── type 3 ProUpRegTx — UpdateRegistrar ──────────────────────────────
    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;
        if (pl.nVersion >= vendor::ProTxVersion::EXT_ADDR) return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        if (e->has_ext_netinfo()) return MnFoldOutcome::Refused;   // v24 SetStateVersion not ported
        e->keyIDVoting = pl.keyIDVoting;
        // Operator-key change (dashd compares the keys as CBLSLazyPublicKey —
        // bytes under one scheme, points across schemes) ⇒ ResetOperatorFields
        // + ban, then `nVersion = nVersion > BasicBLS ? nVersion :
        // proTx.nVersion` (specialtxman.cpp RebuildListFromBlock), i.e. the
        // payload's nVersion after the reset. The payload's key bytes are
        // already in the scheme that nVersion dictates, which is now the
        // leaf's. The masternode must re-announce service with a ProUpServTx.
        if (detail::operator_key_changed(
                e->pubKeyOperator,
                e->nVersion < vendor::CSimplifiedMNListEntry::VER_BASIC_BLS,
                pl.pubKeyOperator,
                pl.nVersion < vendor::ProTxVersion::BASIC_BLS)) {
            detail::reset_operator_fields(*e);
            e->nVersion       = pl.nVersion;
            e->pubKeyOperator = pl.pubKeyOperator;
        }
        return MnFoldOutcome::Applied;
    }

    // ── type 4 ProUpRevTx — RevokeOperator (ban) ─────────────────────────
    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx pl;
        if (!vendor::parse_protx_payload(tx.extra_payload, pl))
            return MnFoldOutcome::Refused;
        if (pl.nVersion >= vendor::ProTxVersion::EXT_ADDR) return MnFoldOutcome::Refused;
        auto* e = detail::find_entry(list, pl.proTxHash);
        if (e == nullptr) return MnFoldOutcome::Refused;
        // After v24 a revocation keeps a v3 state's version; not ported.
        if (e->has_ext_netinfo()) return MnFoldOutcome::Refused;
        // ResetOperatorFields + ban (nVersion back to LegacyBLS): invalid
        // until a fresh ProUpRegTx(new key) + ProUpServTx pair.
        detail::reset_operator_fields(*e);
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
        std::map<Service, uint256> services;        ///< non-empty netInfo
    };

    const MnStateMachine* mns{nullptr};   ///< the pre-block list (non-owning)
    CollateralCoinFn      collateral_coin;
    OperatorSigFn         verify_operator_sig;

    /// Dash Core's full CheckPro*Tx for the block being built (protx_check.hpp):
    /// payload rules, network fields, collateral, inputsHash and the ECDSA
    /// signatures. Returns the reject reason, nullopt to pass.
    using CoreCheckFn = std::function<std::optional<std::string>(const MutableTransaction&)>;
    CoreCheckFn core_check;
    /// The serving folds (template builder and emit gate) set this: every
    /// provider tx must then pass core_check, and a missing core_check refuses
    /// it (fail closed). The service-update ordering rule of Dash Core's miner
    /// applies as well. Unset (the plain context fold) => unchanged.
    bool require_core_check{false};

    /// Dash Core v24: DEPLOYMENT_V24 is active for the block being built. The
    /// fold then applies every provider type (1-4 and 10-12) through the v24
    /// transitions (v24_state.hpp, the code the payee projection and the
    /// root-checked replay fold run for mined blocks) on full masternode
    /// states, and re-derives each changed leaf from the state
    /// (v24_sml_leaf.hpp). False (the default): the pre-v24 fold, unchanged.
    bool v24_rules{false};
    /// The height of the block being built: a registration's
    /// nRegisteredHeight and a ban's height. Read only when v24_rules is set.
    uint32_t height{0};
    /// SetStateVersion's netInfo chain parameters (v24 fold only).
    vendor::NetInfoRules netinfo_rules{vendor::NetInfoRules::mainnet()};

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
                    if (!detail::net_service_empty(st.netInfo))
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
    /// Operator keys added by this body, as the payload's wire bytes.
    std::map<MnFoldContext::OpKey, uint256>      added_opkeys;
    /// The pre-block list's operator keys, keyed by the LEAF bytes — the key
    /// under its holder's own scheme (legacy iff the leaf nVersion <
    /// BasicBLS). That is what dashd's unique-property map hashes
    /// (CBLSLazyWrapper::Serialize under the scheme the key was read with,
    /// deterministicmns.h GetUniquePropertyHash): a legacy L(P) and a basic
    /// B(P) of ONE point are two properties, and equal bytes of two different
    /// points are one. Built on first use.
    std::optional<std::map<MnFoldContext::OpKey, uint256>> base_opkeys_idx;

    const std::map<MnFoldContext::OpKey, uint256>&
    base_opkeys(const vendor::CSimplifiedMNList& base)
    {
        if (!base_opkeys_idx) {
            std::map<MnFoldContext::OpKey, uint256> m;
            for (const auto& e : base.mnList) {
                bool null_key = true;
                for (uint8_t b : e.pubKeyOperator) if (b != 0) { null_key = false; break; }
                if (!null_key) m.emplace(e.pubKeyOperator, e.proRegTxHash);
            }
            base_opkeys_idx = std::move(m);
        }
        return *base_opkeys_idx;
    }
    std::map<MnFoldContext::Service, uint256>    added_services;
    /// Masternodes whose operator key a body tx changed or revoked (a
    /// ProUpRegTx with a new key, a ProUpRevTx): Dash Core's miner never puts a
    /// ProUpServTx for one of them after that tx (node/miner.cpp, the
    /// keyChangedMNs rule).
    std::set<uint256> key_changed;

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
    if (net_service_empty(n)) return std::nullopt;
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
    for (const auto& e : list) {
        if (e.proRegTxHash != pro) continue;
        // Dash Core v24: an update of a version-3 (ExtAddr) state goes
        // through SetStateVersion (target max(state, tx), netInfo
        // conversion), which this fold does not implement: refuse by name.
        if (be_out->has_ext_netinfo() || e.has_ext_netinfo())
            return "bad-protx-version (target entry " + pro.GetHex().substr(0, 16)
                 + " is nVersion=3, ExtAddr — DEPLOYMENT_V24 transitions are not ported)";
        return std::nullopt;
    }
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
    if (ctx.require_core_check) {
        if (!ctx.core_check)
            return refuse("provider tx not checkable (no Dash Core check wired) - excluded");
        if (auto why = ctx.core_check(::dash::coin::MutableTransaction(tx)))
            return refuse(*why);
    }

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
        // Operator key: the payload's wire bytes against each holder's bytes
        // under the holder's scheme (MnFoldOverlay::base_opkeys).
        const auto& op_wire = pl.pubKeyOperator;
        if (!opkey_is_null(op_wire)
            && held_by_other(op_wire, ov.base_opkeys(base), ov.added_opkeys, none))
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
        if (!opkey_is_null(op_wire)) ov.added_opkeys.emplace(op_wire, pro);
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
        // CProUpServTx::IsTriviallyValid (providertx.cpp:177 v23.1.7, :471
        // v24.0.0): an empty netInfo -- any invalid service, whatever its
        // port -- makes the tx, and a block carrying it, invalid.
        if (pl.netInfo.IsEmpty()) return refuse("bad-protx-netinfo-empty");
        const vendor::CSimplifiedMNListEntry* be = nullptr;
        if (auto why = update_target_refusal(base, list, ov, pl.proTxHash, be))
            return refuse(*why);
        if (ctx.require_core_check && ov.key_changed.count(pl.proTxHash))
            return refuse("service update follows a key change of masternode "
                          + pl.proTxHash.GetHex().substr(0, 16)
                          + " in this block (Dash Core miner rule) - excluded");
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
        // CheckProUpRegTx / UpdateMN: the new key's wire bytes must not be a
        // key another masternode holds (bytes under the holder's scheme).
        const auto& op_wire = pl.pubKeyOperator;
        if (!opkey_is_null(op_wire)
            && held_by_other(op_wire, ov.base_opkeys(base), ov.added_opkeys, pl.proTxHash))
            return refuse("bad-protx-dup-key (pubKeyOperator held by another MN)");
        // Only a key that CHANGES enters the unique-property map (UpdateMN);
        // decide it on the evolving leaf, as the leaf apply below does.
        bool key_changes = false;
        for (const auto& e : list)
            if (e.proRegTxHash == pl.proTxHash)
                key_changes = detail::operator_key_changed(
                    e.pubKeyOperator,
                    e.nVersion < vendor::CSimplifiedMNListEntry::VER_BASIC_BLS,
                    pl.pubKeyOperator,
                    pl.nVersion < vendor::ProTxVersion::BASIC_BLS);
        if (apply_mn_special_tx_to_sml(list, tx) != MnFoldOutcome::Applied)
            return refuse("bad-protx-hash (leaf apply)");   // unreachable: checked above
        if (key_changes && !opkey_is_null(op_wire)) ov.added_opkeys[op_wire] = pl.proTxHash;
        if (key_changes) ov.key_changed.insert(pl.proTxHash);
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
        ov.key_changed.insert(pl.proTxHash);   // a revocation resets the operator key
        return {MnFoldOutcome::Applied, {}};
    }

    default:
        return {};
    }
}

// ═════════════════════════════════════════════════════════════════════════
// THE V24 FOLD (DEPLOYMENT_V24 active for the block being built)
// ═════════════════════════════════════════════════════════════════════════
//
// Dash Core v24 ApplyTxToList (specialtxman.cpp:346-697) and
// FinishListForBlock (:732-806), as the miner's CMNListBuilder runs them on
// the block it builds (node/miner.cpp:741-768), for every provider type:
// 1-4 and the shared-masternode types 10 (ProDisTx), 11 (ProUpShareTx) and
// 12 (ProUpSharedRegTx). The transitions are v24_state.hpp's, the code the
// payee projection and the root-checked replay fold run for mined blocks;
// nothing here re-states a rule. Each masternode a body tx touches is held as
// a FULL state, copied from the payee projection's pre-block state the first
// time, and its leaf is re-derived from that state (v24_sml_leaf.hpp, the
// replay fold's to_sml_entry). confirmedHash and isValid come from the
// projected leaf (the confirmation pass and the PoSe pass ran before).
//
// FAIL CLOSED: a tx this fold cannot apply exactly is refused, never folded
// approximately:
//   * the projection's pre-block state of the masternode must reproduce its
//     SML leaf byte for byte (CalcHash); a state that drifted from the list
//     dashd committed refuses every tx touching that masternode;
//   * no projection state, no leaf, an unknown or removed masternode;
//   * any transition error Core reports (Core rejects the block on it);
//   * the uniqueness rules of CheckPro*Tx (pre-block list) and of
//     ApplyTxToList (the list as built so far), both enforced;
//   * a tx spending a shared masternode's collateral that is not a ProDisTx
//     (bad-shared-collateral-spend).
// A refused tx never mutates the list and its inputs are not counted as
// spends.

/// In-body changes to the pre-block list under the v24 rules.
struct MnFoldOverlayV24
{
    /// A netInfo entry as a unique property: (network id, address bytes,
    /// port) for a service (Core hashes the CService, ADDRv2 for the
    /// networks ADDRv1 cannot carry), (kDomain, name bytes, port) for a
    /// domain entry.
    using Service = std::tuple<uint8_t, std::vector<uint8_t>, uint16_t>;
    static constexpr uint8_t kDomain = 0xff;

    /// The evolving state of every masternode a body tx registered or
    /// changed (newList for those entries).
    std::map<uint256, MNState> touched;
    /// Removed by a ProRegTx collateral reuse, or by a collateral spend.
    std::set<uint256> removed;
    /// Dash Core's miner keyChangedMNs: an operator key changed or revoked.
    std::set<uint256> key_changed;

    /// prevList unique-property indexes (dashd mnUniquePropertyMap), built on
    /// first use: operator keys (the store is canonical basic, so a point is
    /// one byte string and this is HasOperatorKeyUnderAnyScheme), keyIDOwner
    /// ∪ Evo platformNodeID ∪ share owner keys (one namespace), and every
    /// netInfo entry (the legacy CService, or each ExtNetInfo service and
    /// domain entry of every purpose).
    struct PreIndex {
        std::multimap<MnFoldContext::OpKey, uint256> opkeys;
        std::multimap<uint160, uint256>              ids;
        std::multimap<Service, uint256>              services;
    };
    std::optional<PreIndex> pre;

    /// The unique-property entries of a netInfo: ExtNetInfo when `ext`,
    /// else the legacy service (none when empty).
    static std::vector<Service> entries_of(bool ext, const vendor::LegacyNetService& legacy,
                                           const vendor::ExtNetInfo& extinfo)
    {
        std::vector<Service> out;
        if (ext) {
            for (const auto& e : extinfo.GetAllEntries()) {
                if (const auto* s = e.service(); s && s->IsValid())
                    out.emplace_back(static_cast<uint8_t>(s->net), s->addr, s->port);
                else if (const auto* d = e.domain())
                    out.emplace_back(kDomain, std::vector<uint8_t>(d->addr.begin(), d->addr.end()), d->port);
            }
        } else if (!net_service_empty(legacy)) {
            const auto s = vendor::NetService::from_legacy(legacy);
            out.emplace_back(static_cast<uint8_t>(s.net), s.addr, s.port);
        }
        return out;
    }
    static std::vector<Service> services_of(const MNState& st)
    {
        return entries_of(v24::state_has_ext(st.nVersion), st.netInfo, st.v24.extNetInfo);
    }
    static std::vector<uint160> ids_of(const MNState& st)
    {
        std::vector<uint160> out;
        if (!st.keyIDOwner.IsNull()) out.push_back(st.keyIDOwner);
        if (st.nType == vendor::MnType::EVO && !st.platformNodeID.IsNull()) out.push_back(st.platformNodeID);
        for (const auto& sh : st.v24.shares)
            if (!sh.keyIDOwner.IsNull()) out.push_back(sh.keyIDOwner);
        return out;
    }

    const PreIndex& pre_index(const MnFoldContext& ctx)
    {
        if (!pre) {
            PreIndex ix;
            if (ctx.mns != nullptr) {
                for (const auto& [pro, st] : ctx.mns->entries()) {
                    if (!opkey_is_null(st.pubKeyOperator)) ix.opkeys.emplace(st.pubKeyOperator, pro);
                    for (const auto& id : ids_of(st)) ix.ids.emplace(id, pro);
                    for (auto& s : services_of(st)) ix.services.emplace(std::move(s), pro);
                }
            }
            pre = std::move(ix);
        }
        return *pre;
    }

    /// Held by a masternode other than `self` (and other than `also_not`) in
    /// the pre-block list (CheckPro*Tx reads pindexPrev's list, so an entry
    /// a body tx changed or removed still counts there) or in the list as
    /// built so far (ApplyTxToList; a touched state's current value).
    template <typename Key, typename PreMap, typename Of>
    bool held_by_other(const Key& k, const PreMap& pm, Of&& values_of, const uint256& self,
                       const uint256& also_not = uint256{}) const
    {
        for (auto [it, end] = pm.equal_range(k); it != end; ++it)
            if (it->second != self && it->second != also_not) return true;
        for (const auto& [pro, st] : touched) {
            if (pro == self || pro == also_not || removed.count(pro)) continue;
            for (const auto& v : values_of(st))
                if (v == k) return true;
        }
        return false;
    }
    bool opkey_held_by_other(const MnFoldContext& ctx, const MnFoldContext::OpKey& basic, const uint256& self,
                             const uint256& also_not = uint256{})
    {
        if (opkey_is_null(basic)) return false;
        return held_by_other(basic, pre_index(ctx).opkeys,
                             [](const MNState& st) { return std::vector<MnFoldContext::OpKey>{st.pubKeyOperator}; },
                             self, also_not);
    }
    bool id_held_by_other(const MnFoldContext& ctx, const uint160& id, const uint256& self,
                          const uint256& also_not = uint256{})
    {
        if (id.IsNull()) return false;
        return held_by_other(id, pre_index(ctx).ids, &ids_of, self, also_not);
    }
    bool service_held_by_other(const MnFoldContext& ctx, const Service& s, const uint256& self,
                               const uint256& also_not = uint256{})
    {
        return held_by_other(s, pre_index(ctx).services, &services_of, self, also_not);
    }

    /// GetMN on the list as built so far.
    const MNState* state_of(const MnFoldContext& ctx, const uint256& pro) const
    {
        if (removed.count(pro)) return nullptr;
        if (auto t = touched.find(pro); t != touched.end()) return &t->second;
        if (ctx.mns == nullptr) return nullptr;
        auto it = ctx.mns->entries().find(pro);
        return it == ctx.mns->entries().end() ? nullptr : &it->second;
    }

    /// GetMNByCollateral on the list as built so far.
    std::optional<uint256> collateral_owner(const MnFoldContext& ctx, const MnFoldContext::Outpoint& op) const
    {
        for (const auto& [pro, st] : touched)
            if (!removed.count(pro) && st.collateralOutpoint.hash == op.hash
                && st.collateralOutpoint.index == op.index)
                return pro;
        auto b = ctx.collateral_owner(op);
        if (b && !removed.count(*b)) return b;
        return std::nullopt;
    }

    /// RemoveMN on the evolving list and its leaves.
    void remove_mn(std::vector<vendor::CSimplifiedMNListEntry>& list, const uint256& pro)
    {
        for (auto it = list.begin(); it != list.end(); ++it)
            if (it->proRegTxHash == pro) { list.erase(it); break; }
        removed.insert(pro);
        touched.erase(pro);
    }
};

/// The masternode's state to transition, held in the overlay: on first touch
/// the projection's pre-block state, with isValid taken from the projected
/// leaf, and only if that state reproduces the leaf exactly. nullptr with
/// `why` set refuses.
inline MNState* touch_v24(vendor::CSimplifiedMNList& folded, const MnFoldContext& ctx, MnFoldOverlayV24& ov,
                          const uint256& pro, const char* code, std::string& why)
{
    const std::string short_pro = pro.GetHex().substr(0, 16);
    if (ov.removed.count(pro)) {
        why = std::string(code) + " (" + short_pro + " was removed earlier in this block)";
        return nullptr;
    }
    if (auto t = ov.touched.find(pro); t != ov.touched.end()) return &t->second;
    const MNState* pre = ov.state_of(ctx, pro);
    vendor::CSimplifiedMNListEntry* leaf = find_entry(folded.mnList, pro);
    if (pre == nullptr || leaf == nullptr) {
        why = std::string(code) + " (" + short_pro
            + (pre == nullptr ? " is not in the payee projection's pre-block list)"
                              : " is not in the projected SML)");
        return nullptr;
    }
    MNState st = *pre;
    st.isValid = leaf->isValid;
    if (!st.isValid && st.nPoSeBanHeight == 0) st.nPoSeBanHeight = ctx.height;
    if (st.isValid) st.nPoSeBanHeight = 0;
    vendor::CSimplifiedMNListEntry derived = *leaf;
    v24::write_sml_leaf_fields(st, derived);
    if (derived.CalcHash() != leaf->CalcHash()) {
        why = "masternode " + short_pro
            + ": the payee projection's state does not reproduce its SML leaf (state drift) - excluded";
        return nullptr;
    }
    return &ov.touched.emplace(pro, std::move(st)).first->second;
}

/// Re-derive the leaf of `pro` from its state (a new registration's leaf is
/// added unconfirmed).
inline void write_leaf_v24(vendor::CSimplifiedMNList& folded, const uint256& pro, const MNState& st)
{
    vendor::CSimplifiedMNListEntry* e = find_entry(folded.mnList, pro);
    if (e == nullptr) {
        vendor::CSimplifiedMNListEntry fresh;
        fresh.proRegTxHash = pro;
        fresh.confirmedHash = uint256::ZERO;
        folded.mnList.push_back(fresh);
        e = &folded.mnList.back();
    }
    v24::write_sml_leaf_fields(st, *e);
    e->isValid = st.isValid;
}

inline void ban_v24(MNState& st, uint32_t height)
{
    if (st.nPoSeBanHeight == 0) st.nPoSeBanHeight = height;
    st.isValid = false;
}

template <typename Tx>
inline FoldVerdict fold_one_v24(vendor::CSimplifiedMNList& folded, const vendor::CSimplifiedMNList& base,
                                const Tx& tx, const MnFoldContext& ctx, MnFoldOverlayV24& ov,
                                SmlSpecialFold& out)
{
    auto& list = folded.mnList;
    // FinishListForBlock: a shared masternode's collateral may be spent only
    // by a ProDisTx; any other spender makes the block invalid.
    if (!(tx_is_special_version(tx.version) && tx.type == tx_type::PROVIDER_DISSOLVE)) {
        for (const auto& in : tx.vin)
            if (auto mn = ov.collateral_owner(ctx, in.prevout))
                if (const MNState* st = ov.state_of(ctx, *mn); st != nullptr && st->v24.IsShared())
                    return refuse("bad-shared-collateral-spend (masternode " + mn->GetHex().substr(0, 16) + ")");
    }
    const bool provider = (tx.type >= 1 && tx.type <= 4) || tx_type_is_v24_provider(tx.type);
    if (!provider) return {};
    if (auto why = contextual_tx_check_v24(tx, /*is_coinbase=*/false)) return refuse(std::string(*why));
    if (ctx.require_core_check) {
        if (!ctx.core_check)
            return refuse("provider tx not checkable (no Dash Core check wired) - excluded");
        if (auto why = ctx.core_check(::dash::coin::MutableTransaction(tx))) return refuse(*why);
    }
    const auto& rules = ctx.netinfo_rules;
    std::string why;

    switch (tx.type) {
    case vendor::CProRegTx::SPECIALTX_TYPE: {
        vendor::CProRegTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        if (p.nVersion >= vendor::ProTxVersion::EXT_ADDR || p.IsShared())
            return refuse("bad-protx-version (ExtAddr ProRegTx: its Dash Core checks are not ported) - excluded");
        const uint256 pro = dash::coin::dash_txid(::dash::coin::MutableTransaction(tx));
        MnFoldContext::Outpoint coll = p.collateralOutpoint;
        const bool external = !coll.hash.IsNull();
        if (!external) coll.hash = pro;
        if (external && ctx.collateral_coin) {
            int64_t value = 0;
            const auto proof = ctx.collateral_coin(coll, value);
            if (proof == MnFoldContext::CollateralProof::Absent)
                return refuse("bad-protx-collateral (not an unspent coin)");
            const int64_t want = p.nType == vendor::MnType::EVO ? kCollateralEvo : kCollateralRegular;
            if (proof == MnFoldContext::CollateralProof::Unspent && value != want)
                return refuse("bad-protx-collateral (amount " + std::to_string(value) + " != "
                              + std::to_string(want) + ")");
        }
        if (ov.state_of(ctx, pro) != nullptr || find_entry(list, pro) != nullptr)
            return refuse("bad-protx-dup (proRegTxHash)");
        const auto replaced = ov.collateral_owner(ctx, coll);
        const uint256 none{};
        const uint256 replaced_pro = replaced ? *replaced : uint256{};
        // CheckProRegTx (prevList, the MN being replaced included) and
        // ApplyTxToList (the list as built so far, after the replacement).
        if (ov.id_held_by_other(ctx, p.keyIDOwner, none))
            return refuse("bad-protx-dup-key (keyIDOwner is an owner key or platformNodeID)");
        const auto op_basic = vendor::opkey_to_basic(p.pubKeyOperator, p.nVersion < vendor::ProTxVersion::BASIC_BLS);
        if (ov.opkey_held_by_other(ctx, op_basic, none))
            return refuse("bad-protx-dup-key (pubKeyOperator under either scheme)");
        if (p.nType == vendor::MnType::EVO && ov.id_held_by_other(ctx, p.platformNodeID, none))
            return refuse("bad-protx-dup-platformnodeid");
        {
            const auto svc_list = MnFoldOverlayV24::entries_of(false, p.netInfo.canonical(), vendor::ExtNetInfo{});
            for (const auto& svc : svc_list) {
                // prevList: only the masternode this collateral replaces may hold it.
                const auto& pm = ov.pre_index(ctx).services;
                for (auto [it, end] = pm.equal_range(svc); it != end; ++it) {
                    const auto pc = ctx.collateral_of(it->second);
                    if (!(pc && pc->hash == coll.hash && pc->index == coll.index))
                        return refuse("bad-protx-dup-netinfo-entry (service in use)");
                }
                if (ov.held_by_other(svc, std::multimap<MnFoldOverlayV24::Service, uint256>{},
                                     &MnFoldOverlayV24::services_of, none, replaced_pro))
                    return refuse("bad-protx-dup-netinfo-entry (service registered in this block)");
            }
        }
        // ── mutate (Core ApplyTxToList, the projection's case 1) ──
        if (replaced) {
            ov.remove_mn(list, *replaced);
            ++out.replaced;
        }
        MNState st;
        st.nType = static_cast<uint8_t>(p.nType);
        st.nRegisteredHeight = ctx.height;
        st.collateralOutpoint = coll;
        v24::state_from_proreg(st, p, op_basic);
        st.nOperatorReward = p.nOperatorReward;
        st.payoutSplitProvenance = MNState::SPLIT_KNOWN;
        st.isValid = true;
        if (v24::netinfo_empty(st)) ban_v24(st, ctx.height);
        write_leaf_v24(folded, pro, st);
        ov.touched[pro] = std::move(st);
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpServTx::SPECIALTX_TYPE: {
        vendor::CProUpServTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        const vendor::CSimplifiedMNListEntry* be = base_entry(base, p.proTxHash);
        if (be == nullptr) return refuse("bad-protx-hash (not in the pre-block list)");
        MNState* cur = touch_v24(folded, ctx, ov, p.proTxHash, "bad-protx-hash", why);
        if (cur == nullptr) return refuse(why);
        if (ctx.require_core_check && ov.key_changed.count(p.proTxHash))
            return refuse("service update follows a key change of masternode "
                          + p.proTxHash.GetHex().substr(0, 16) + " in this block (Dash Core miner rule) - excluded");
        if (p.nType != cur->nType) return refuse("bad-protx-type-mismatch");
        for (const auto& svc : MnFoldOverlayV24::entries_of(v24::state_has_ext(p.nVersion), p.netInfo.canonical(),
                                                            p.extNetInfo))
            if (ov.service_held_by_other(ctx, svc, p.proTxHash))
                return refuse("bad-protx-dup-netinfo-entry (an entry held by another MN)");
        if (p.nType == vendor::MnType::EVO && ov.id_held_by_other(ctx, p.platformNodeID, p.proTxHash))
            return refuse("bad-protx-dup-platformnodeid");
        if (auto w = operator_sig_refusal(ctx, *be, tx.extra_payload, p)) return refuse(*w);
        MNState next = *cur;
        const uint16_t old_version = next.nVersion;
        const uint16_t target = std::max<uint16_t>(old_version, p.nVersion);
        const auto t = v24::apply_proupserv(next, p, next.nType, rules);
        if (t.error) return refuse(*t.error);
        if (!next.isValid && v24::revive_allowed(next)) {
            next.nPoSeBanHeight = 0;
            next.nPoSeRevivedHeight = ctx.height;
            next.isValid = true;
        }
        if (v24::is_scheme_migration(old_version, target)
            && ov.opkey_held_by_other(ctx, next.pubKeyOperator, p.proTxHash))
            return refuse("bad-protx-dup-key (the legacy-to-basic migration re-keys onto a held key)");
        *cur = std::move(next);
        write_leaf_v24(folded, p.proTxHash, *cur);
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpRegTx::SPECIALTX_TYPE: {
        vendor::CProUpRegTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        if (base_entry(base, p.proTxHash) == nullptr) return refuse("bad-protx-hash (not in the pre-block list)");
        MNState* cur = touch_v24(folded, ctx, ov, p.proTxHash, "bad-protx-hash", why);
        if (cur == nullptr) return refuse(why);
        const auto incoming = vendor::opkey_to_basic(p.pubKeyOperator, p.nVersion < vendor::ProTxVersion::BASIC_BLS);
        const bool operator_changed = cur->pubKeyOperator != incoming;
        const uint16_t target = std::max<uint16_t>(cur->nVersion, p.nVersion);
        if ((operator_changed || v24::is_scheme_migration(cur->nVersion, target))
            && ov.opkey_held_by_other(ctx, incoming, p.proTxHash))
            return refuse("bad-protx-dup-key (pubKeyOperator held by another MN under either scheme)");
        MNState next = *cur;
        const auto t = v24::apply_proupreg(next, p, next.nType, operator_changed, incoming, rules);
        if (t.error) return refuse(*t.error);
        if (t.ban) ban_v24(next, ctx.height);
        *cur = std::move(next);
        if (operator_changed) ov.key_changed.insert(p.proTxHash);
        write_leaf_v24(folded, p.proTxHash, *cur);
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpRevTx::SPECIALTX_TYPE: {
        vendor::CProUpRevTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        const vendor::CSimplifiedMNListEntry* be = base_entry(base, p.proTxHash);
        if (be == nullptr) return refuse("bad-protx-hash (not in the pre-block list)");
        MNState* cur = touch_v24(folded, ctx, ov, p.proTxHash, "bad-protx-hash", why);
        if (cur == nullptr) return refuse(why);
        if (auto w = operator_sig_refusal(ctx, *be, tx.extra_payload, p)) return refuse(*w);
        MNState next = *cur;
        const auto t = v24::apply_prouprev(next, p, next.nType, rules);
        if (t.error) return refuse(*t.error);
        ban_v24(next, ctx.height);
        *cur = std::move(next);
        ov.key_changed.insert(p.proTxHash);   // a revocation resets the operator key
        write_leaf_v24(folded, p.proTxHash, *cur);
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProDisTx::SPECIALTX_TYPE: {
        // No list action in ApplyTxToList: the masternode leaves in the
        // collateral-spend pass (FinishListForBlock), like any spent
        // collateral. The Core check proved it exists before the block and
        // that this tx spends its collateral.
        vendor::CProDisTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        const MNState* st = ov.state_of(ctx, p.proTxHash);
        if (st == nullptr) return refuse("bad-prodis-hash (not in the list as built so far)");
        if (!st->v24.IsShared()) return refuse("bad-prodis-not-shared");
        if (tx.vin.size() != 1 || tx.vin[0].prevout.hash != st->collateralOutpoint.hash
            || tx.vin[0].prevout.index != st->collateralOutpoint.index)
            return refuse("bad-prodis-input");
        if (find_entry(list, p.proTxHash) == nullptr)
            return refuse("bad-prodis-hash (" + p.proTxHash.GetHex().substr(0, 16) + " is not in the projected SML)");
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpShareTx::SPECIALTX_TYPE: {
        vendor::CProUpShareTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        MNState* cur = touch_v24(folded, ctx, ov, p.proTxHash, "bad-protx-hash", why);
        if (cur == nullptr) return refuse(why);
        MNState next = *cur;
        const auto t = v24::apply_proupshare(next, p);
        if (t.error) return refuse(*t.error);
        *cur = std::move(next);
        write_leaf_v24(folded, p.proTxHash, *cur);   // the share table is not hashed: the leaf is unchanged
        return {MnFoldOutcome::Applied, {}};
    }

    case vendor::CProUpSharedRegTx::SPECIALTX_TYPE: {
        vendor::CProUpSharedRegTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p)) return refuse("bad-protx-payload");
        MNState* cur = touch_v24(folded, ctx, ov, p.proTxHash, "bad-protx-hash", why);
        if (cur == nullptr) return refuse(why);
        const auto incoming = vendor::opkey_to_basic(p.pubKeyOperator, /*legacy=*/false);
        const bool operator_changed = cur->pubKeyOperator != incoming;
        MNState next = *cur;
        const auto t = v24::apply_proupsharedreg(next, p, next.nType, operator_changed, incoming, rules);
        if (t.error) return refuse(*t.error);
        if (operator_changed && ov.opkey_held_by_other(ctx, incoming, p.proTxHash))
            return refuse("bad-protx-dup-key (pubKeyOperator held by another MN under either scheme)");
        if (t.ban) ban_v24(next, ctx.height);
        *cur = std::move(next);
        if (operator_changed) ov.key_changed.insert(p.proTxHash);
        write_leaf_v24(folded, p.proTxHash, *cur);
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
/// so the served body never carries them. With `ctx.v24_rules` the v24 fold
/// above runs instead, for types 1-4 and 10-12.
template <typename TxRange, typename TxidFn>
inline SmlSpecialFold fold_mn_special_txs(const vendor::CSimplifiedMNList& base,
                                          const TxRange& body_txs,
                                          TxidFn&& txid_of,
                                          const MnFoldContext& ctx)
{
    SmlSpecialFold out;
    out.sml = base;                         // COPY — never the follower's list
    if (ctx.v24_rules) {
        detail::MnFoldOverlayV24 ov;
        std::vector<bool> refused;
        for (const auto& tx : body_txs) {
            const auto v = detail::fold_one_v24(out.sml, base, tx, ctx, ov, out);
            refused.push_back(v.outcome == MnFoldOutcome::Refused);
            if (v.outcome == MnFoldOutcome::Applied) {
                ++out.applied;
            } else if (v.outcome == MnFoldOutcome::Refused) {
                ++out.refused;
                out.refused_ids.push_back(txid_of(tx));
                out.refused_reasons.push_back(v.reason);
            }
        }
        // FinishListForBlock's collateral loop, after every tx was applied.
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
        out.sml.sort();                     // dashd memcmp(proRegTxHash) order
        return out;
    }
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
