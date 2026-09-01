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

#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // dash_txid

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
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

} // namespace coin
} // namespace dash
