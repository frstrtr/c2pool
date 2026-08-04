// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// confirmedHash rollover projection — the height-driven MN confirmation pass.
///
/// dashcore's verifier rebuilds the deterministic MN list for EVERY block it
/// connects, and the FIRST thing that rebuild does is a purely height-driven
/// confirmation pass (dashcore v23.1.7, src/evo/specialtxman.cpp:206-215,
/// CSpecialTxProcessor::RebuildListFromBlock):
///
///     prevList.ForEachMN(false, [&](const auto& dmn) {
///         if (!dmn.pdmnState->confirmedHash.IsNull()) return;  // already confirmed
///         int nConfirmations = pindexPrev->nHeight - dmn.pdmnState->nRegisteredHeight;
///         if (nConfirmations >= nMasternodeMinimumConfirmations) {
///             newState->UpdateConfirmedHash(dmn.proTxHash, pindexPrev->GetBlockHash());
///             newList.UpdateMN(dmn.proTxHash, newState);
///         }
///     });
///
/// `confirmedHash` IS a hashed field of the DIP-0004 Simplified MN List entry
/// (CSimplifiedMNListEntry::CalcHash — see vendor/simplifiedmns.hpp), so the
/// merkleRootMNList the verifier expects block N to commit differs from the
/// TIP list's root at exactly the height where a registered MN crosses
/// nMasternodeMinimumConfirmations — with NO transaction in the block causing
/// it. A template that commits the tip SML root verbatim at that height is a
/// consensus-invalid block (bad-cbtx-mnmerkleroot): a winning share there is a
/// silently lost block, and no tip-relative freshness gate can catch it
/// because the tip SML *is* current — it is the projection for the block
/// BEING TEMPLATED that is missing.
///
/// This header is that projection. Given the tip SML (current at prev_hash),
/// the DMN view (which carries nRegisteredHeight: live ProRegTx applies stamp
/// it exactly, and the `protx list registered true` seed carries dashd's own
/// registeredHeight — see mn_seed.hpp), and the tip (prev_height, prev_hash),
/// it replicates the verifier's confirmation pass:
///
///   for every SML entry with a null confirmedHash:
///     nConfirmations = prev_height - nRegisteredHeight
///     if nConfirmations >= nMasternodeMinimumConfirmations:
///         entry.confirmedHash = prev_hash        // UpdateConfirmedHash
///
/// (UpdateConfirmedHash additionally derives confirmedHashWithProRegTxHash,
/// but that field is quorum-scoring state, not an SML entry field — the SML
/// leaf hashes confirmedHash itself, so setting it is sufficient here.)
///
/// FAIL-CLOSED CONTRACT: if any null-confirmedHash entry's registration
/// height is UNKNOWN to the DMN view (proTxHash absent, or the height is the
/// 0 / UINT32_MAX "never" sentinel), the projection reports ok=false and the
/// caller must refuse to serve (NodeCoinState names this
/// "mn-confirm-rollover-pending"). Serving on a guess would be the exact
/// silent-wrongness class this file exists to close. The refusal window is
/// bounded: it can only persist while an unconfirmed (recently registered)
/// MN with unknown registration height sits in the SML — at most
/// ~nMasternodeMinimumConfirmations blocks per such registration.
///
/// Frequency (INFERRED, not measured): mainnet MN registrations are on the
/// order of a few per day, and each poisons exactly one height (the crossing
/// height) — after that block connects, the network's own mnlistdiff carries
/// the confirmedHash and the tip SML is correct again.

#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <limits>
#include <optional>

namespace dash {
namespace coin {

/// Consensus::Params.nMasternodeMinimumConfirmations, verified against
/// dashcore v23.1.7 src/chainparams.cpp: mainnet = 15 (line 177); testnet,
/// devnet and regtest = 1 (lines 376/549/780). NOT 16 — the crossing height
/// for a mainnet MN registered at height R is R + 16 (the pass runs on
/// pindexPrev, so confirmation lands one block after 15 confirmations exist,
/// with confirmedHash = the hash of block R + 15).
inline constexpr int DASH_MN_MIN_CONFIRMATIONS_MAINNET = 15;
inline constexpr int DASH_MN_MIN_CONFIRMATIONS_TESTNET = 1;

/// True when the DMN view knows a usable registration height for `protx`.
/// 0 and UINT32_MAX are the "never / unknown" sentinels (see mn_seed.hpp
/// sane_height_json and mn_state_machine.hpp payee_score).
inline bool mn_registration_height_known(const MnStateMachine& mnstates,
                                         const uint256& protx,
                                         uint32_t* out_height = nullptr)
{
    auto it = mnstates.entries().find(protx);
    if (it == mnstates.entries().end()) return false;
    const uint32_t h = it->second.nRegisteredHeight;
    if (h == 0 || h == std::numeric_limits<uint32_t>::max()) return false;
    if (out_height) *out_height = h;
    return true;
}

/// Cheap viability probe (no SML copy): the first null-confirmedHash SML
/// entry whose registration height the DMN view cannot supply — i.e. the
/// entry that makes the confirmation pass unprojectable. nullopt => the pass
/// is fully projectable for the next block.
inline std::optional<uint256> find_unprojectable_confirmation(
    const vendor::CSimplifiedMNList& tip_sml,
    const MnStateMachine& mnstates)
{
    for (const auto& e : tip_sml.mnList) {
        if (!e.confirmedHash.IsNull()) continue;   // already confirmed
        if (!mn_registration_height_known(mnstates, e.proRegTxHash))
            return e.proRegTxHash;
    }
    return std::nullopt;
}

struct SmlConfirmationProjection {
    vendor::CSimplifiedMNList sml;   ///< tip SML with the confirmation pass applied
    size_t  confirmed{0};            ///< entries confirmed by the pass (usually 0)
    bool    ok{true};                ///< false => a null-confirmedHash entry has no known reg height
    uint256 unprojectable_protx;     ///< first offender when !ok (observability)
};

/// Apply the verifier's confirmation pass (specialtxman.cpp:206-215) to a
/// COPY of the tip SML, producing the list whose merkle root block
/// (prev_height + 1) must commit. Entries are keyed/sorted by proRegTxHash,
/// which the pass never changes, so no re-sort is needed and the projected
/// root is CalcMerkleRoot() over the returned list.
///
/// When !ok the pass was applied to every projectable entry and skipped the
/// offender(s); the root is then NOT trustworthy and callers must fail
/// closed (the NodeCoinState viability + pre-emit gates do).
inline SmlConfirmationProjection project_sml_confirmations(
    const vendor::CSimplifiedMNList& tip_sml,
    uint32_t prev_height,
    const uint256& prev_hash,
    const MnStateMachine& mnstates,
    int mn_min_confirmations = DASH_MN_MIN_CONFIRMATIONS_MAINNET)
{
    SmlConfirmationProjection out;
    out.sml = tip_sml;
    for (auto& e : out.sml.mnList) {
        if (!e.confirmedHash.IsNull()) continue;   // already confirmed
        uint32_t reg_height = 0;
        if (!mn_registration_height_known(mnstates, e.proRegTxHash,
                                          &reg_height)) {
            if (out.ok) out.unprojectable_protx = e.proRegTxHash;
            out.ok = false;
            continue;
        }
        // dashd: nConfirmations = pindexPrev->nHeight - nRegisteredHeight;
        // signed arithmetic so a same-block registration (reg == prev+1 via
        // a not-yet-folded diff) can never wrap into a huge positive count.
        const int64_t confirmations =
            static_cast<int64_t>(prev_height) - static_cast<int64_t>(reg_height);
        if (confirmations >= static_cast<int64_t>(mn_min_confirmations)) {
            e.confirmedHash = prev_hash;           // UpdateConfirmedHash
            ++out.confirmed;
        }
    }
    return out;
}

/// FINDING-2 predicate — collateral spends by NORMAL transactions.
///
/// dashcore's verifier (specialtxman.cpp:457-464) runs a second pass over ALL
/// block txs — with NO special-tx guard — and REMOVES from the MN list any
/// masternode whose collateral outpoint is spent by any input:
///
///     for (int i = 1; i < (int)block.vtx.size(); i++)
///         for (const auto& in : block.vtx[i]->vin)
///             if (auto dmn = newList.GetMNByCollateral(in.prevout); ...)
///                 newList.RemoveMN(dmn->proTxHash);
///
/// So a plain type-0 tx spending a 1000-DASH MN collateral forces the
/// verifier's list for THAT block to drop the MN — and the committed
/// merkleRootMNList must reflect the removal. The embedded template's
/// special-tx filter (mempool.hpp exclude_special) does not catch it: the tx
/// is type 0. Rather than fold the removal into the committed root (dashd's
/// miner does, but it is a second root computation with its own wrongness
/// budget), the embedded builder EXCLUDES such txs from selection — no tx is
/// ever mandatory in a block, so exclusion is consensus-clean and forfeits
/// only that tx's fee while the spend sits in the mempool.
///
/// Coverage / posture: the lookup is MnStateMachine::find_by_collateral —
/// the UNFILTERED collateral index (banned MNs included, matching dashd's
/// GetMNByCollateral in this pass). The index is populated for every entry
/// the DMN view holds (live ProRegTx applies resolve the outpoint exactly,
/// incl. the null-hash "own output" form; the `protx list registered true`
/// seed carries collateralHash/collateralIndex — see mn_seed.hpp). An
/// outpoint the index does not hold is treated as NOT a collateral —
/// dropping every type-0 tx with any unknown input would gut template fill.
/// The residual exposure is an MN present in the SML but absent from the DMN
/// view; the serve path already fails closed on that skew via the #996
/// payee-resolution and freshness gates. Frequency (INFERRED, not measured):
/// collateral spends of active MNs are rare — but while such a tx sits in
/// the mempool it poisons EVERY template that includes it, which is why the
/// pre-emit gate re-checks this predicate as defence in depth.
template <typename Tx>
inline bool tx_spends_mn_collateral(const MnStateMachine& mnstates,
                                    const Tx& tx,
                                    uint256* out_protx = nullptr)
{
    for (const auto& in : tx.vin) {
        if (auto protx = mnstates.find_by_collateral(in.prevout)) {
            if (out_protx) *out_protx = *protx;
            return true;
        }
    }
    return false;
}

} // namespace coin
} // namespace dash
