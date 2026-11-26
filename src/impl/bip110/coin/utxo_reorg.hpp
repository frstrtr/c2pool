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
// that cannot put its spent coins back (its outputs are still removed), a
// record bound to another block than the one being rolled back (untouched), a
// walk that runs off the index, or a rollback deeper than the kept-undo
// horizon ⇒ a non-OK result; the caller leaves the view flagged inconsistent (serves
// coinbase-only) until it can be rebuilt. NEVER a wrong ledger. ZERO DASH code.
// ---------------------------------------------------------------------------

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <exception>

namespace bip110 {
namespace coin {

enum class ReorgResult { OK, UNDO_MISSING, TOO_DEEP, WALK_BROKEN, UNDO_LEGACY, UNDO_MISMATCH };

inline const char* reorg_result_name(ReorgResult r) {
    switch (r) {
        case ReorgResult::OK:          return "ok";
        case ReorgResult::UNDO_MISSING:return "undo-missing";
        case ReorgResult::TOO_DEEP:    return "too-deep";
        case ReorgResult::WALK_BROKEN: return "walk-broken";
        case ReorgResult::UNDO_LEGACY: return "undo-legacy";
        case ReorgResult::UNDO_MISMATCH: return "undo-of-another-block";
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
        if (!undo.block_hash.IsNull() && undo.block_hash != cur) return ReorgResult::UNDO_MISMATCH;
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

// reorg_disconnect_to_fork, and on any failure the disconnects it already
// made are dropped (UTXOViewCache::discard_pending: they were only in the
// cache, a rollback flushes once at the end): the view is the backing DB's
// again, unchanged at its old best, never partly rolled back. Without the
// drop, the next connect's flush would write the half-undone blocks (their
// spent coins back, their new coins gone) under a best that still names the
// old tip.
template <typename HeaderChainT>
inline ReorgResult reorg_disconnect_or_discard(core::coin::UTXOViewCache& cache,
                                               core::coin::UTXOViewDB& db,
                                               const HeaderChainT& chain,
                                               const uint256& new_tip,
                                               uint32_t keep_depth)
{
    const ReorgResult r = reorg_disconnect_to_fork(cache, db, chain, new_tip, keep_depth);
    if (r != ReorgResult::OK)
        cache.discard_pending();
    return r;
}

// Connect `block` at `height` to the view and persist it: its undo record,
// then the flush, then the undo prune below keep_depth. If the flush (or the
// connect) fails, the block's changes are dropped (discard_pending): the view
// stays the DB's, at its old best, and false is returned, so the block is
// connected again later from scratch -- not on top of its own unflushed
// changes, which would apply it twice and write an undo record without the
// coins it spent (a later rollback could not restore them). Cache / Db:
// core::coin::UTXOViewCache / UTXOViewDB (templates: the KAT injects a
// failing flush).
template <typename Cache, typename Db, typename Block, typename TxidFn>
inline bool utxo_connect_and_flush(Cache& cache, Db& db, const Block& block, uint32_t height,
                                   TxidFn txid_fn, const uint256& block_hash, uint32_t keep_depth)
{
    try {
        auto undo = cache.connect_block(block, height, txid_fn, block_hash);
        db.put_block_undo(height, undo);
        if (!cache.flush(block_hash, height)) {
            cache.discard_pending();
            LOG_ERROR << "[EMB-BIP110] UTXO flush failed h=" << height << " hash="
                      << block_hash.GetHex().substr(0, 16)
                      << ": the connect is dropped, the view stays at its best";
            return false;
        }
        cache.prune_undo(height, keep_depth);
    } catch (const std::exception& e) {
        cache.discard_pending();
        LOG_WARNING << "[EMB-BIP110] UTXO connect_block failed h=" << height << ": " << e.what();
        return false;
    }
    return true;
}

} // namespace coin
} // namespace bip110
