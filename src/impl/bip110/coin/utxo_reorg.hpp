// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::utxo_reorg — fail-closed UTXO-view reorg handling (GAP4).
//
// main_bip110 wires full_block -> connect_block but had NO disconnect path, so
// after a fork-chain reorg the post-anchor UTXO view kept coins the new branch
// never created (and treated rolled-back spends as still-spent) — pricing and
// INCLUDING coins that do not exist on the active chain = INVALID block.
//
// reorg_disconnect_to_fork() walks the view's best_block back along the OLD
// branch (header-index prev pointers) to the common ancestor of new_tip,
// calling UTXOViewCache::disconnect_from_undo() at each rolled-back height. That
// removes every output the rolled-back block ADDED (added_outpoints) — a
// rolled-back coin must never price/include — and puts back every coin the
// block SPENT (TxUndo stores each spent coin with its outpoint, #2059): such a
// coin is unspent again on the new chain, so GAP2's inclusion rule rightly
// admits its spender after the re-price. The new branch's bodies re-connect via
// the normal inv->getdata flow.
//
// Fail closed on ANY doubt: missing undo data, a legacy (pre-#2059) undo record
// that cannot put its spent coins back (its outputs are still removed), a walk
// that runs off the index, or a rollback deeper than the kept-undo horizon ⇒ a
// non-OK result; the caller leaves the view flagged inconsistent (serves
// coinbase-only) until it can be rebuilt. NEVER a wrong ledger. ZERO DASH code.
// ---------------------------------------------------------------------------

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/uint256.hpp>

#include <cstdint>

namespace bip110 {
namespace coin {

enum class ReorgResult { OK, UNDO_MISSING, TOO_DEEP, WALK_BROKEN, UNDO_LEGACY };

inline const char* reorg_result_name(ReorgResult r) {
    switch (r) {
        case ReorgResult::OK:          return "ok";
        case ReorgResult::UNDO_MISSING:return "undo-missing";
        case ReorgResult::TOO_DEEP:    return "too-deep";
        case ReorgResult::WALK_BROKEN: return "walk-broken";
        case ReorgResult::UNDO_LEGACY: return "undo-legacy";
    }
    return "?";
}

// Disconnect the view from its current (old-branch) best_block down to the
// common ancestor of new_tip. HeaderChainT must expose:
//   std::optional<Entry> get_header(const uint256&)          // .header.m_previous_block
//   std::optional<Entry> get_header_by_height(uint32_t)      // .block_hash  (active chain)
// keep_depth bounds how far we will roll back (must match the undo-prune horizon).
template <typename HeaderChainT>
inline ReorgResult reorg_disconnect_to_fork(core::coin::UTXOViewCache& cache,
                                            core::coin::UTXOViewDB& db,
                                            const HeaderChainT& chain,
                                            const uint256& /*new_tip*/,
                                            uint32_t keep_depth)
{
    uint256  cur    = cache.get_best_block();
    uint32_t h      = cache.get_best_height();
    const uint32_t start_h = h;

    while (h > 0) {
        // The active (new) chain's block at this height. If it equals the old
        // hash we are walking, the branches agree here — fork point reached.
        auto active = chain.get_header_by_height(h);
        if (active && active->block_hash == cur) break;

        // Roll back the old-branch block at height h. A legacy record removes
        // the block's outputs but cannot put its spent coins back.
        core::coin::BlockUndo undo;
        if (!db.get_block_undo(h, undo)) return ReorgResult::UNDO_MISSING;
        if (!cache.disconnect_from_undo(undo)) return ReorgResult::UNDO_LEGACY;

        // Step to the old-branch parent via the header index.
        auto oldent = chain.get_header(cur);
        if (!oldent) return ReorgResult::WALK_BROKEN;
        cur = oldent->header.m_previous_block;
        --h;
        if (start_h - h > keep_depth) return ReorgResult::TOO_DEEP;
    }

    // Persist the rolled-back view with the common ancestor as the new best.
    cache.flush(cur, h);
    return ReorgResult::OK;
}

} // namespace coin
} // namespace bip110
