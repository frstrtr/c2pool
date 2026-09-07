// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>

/// Pure decision for the embedded UTXO fee-proof lane's full_block accrual
/// (main_dgb.cpp full_block handler) — extracted so the RESTART-LIVENESS
/// contract is KAT-testable (dgb_mempool_ingest_test) rather than buried in a
/// lambda.
///
/// == THE LIVENESS BUG THIS ENCODES THE FIX FOR ==============================
/// The accrual view is a rolling partial UTXO set (#145): it connects a block
/// only when that block is the confirmed header-chain tip AND extends the view
/// by exactly one (height == best_height + 1). best_height is PERSISTED in the
/// view's LevelDB, so it survives a restart. After a restart the header tip has
/// moved far ahead of the persisted best_height, so the FIRST full_block seen
/// is at a height MANY blocks past best_height + 1. The pre-fix handler simply
/// returned on that mismatch — and since the view could then never again
/// observe best_height + 1, it returned on EVERY subsequent block too: the
/// fee-proof lane was silently DEAD for the rest of the process, every tx
/// stuck fee_known=false, templates coinbase-only forever.
///
/// The fix: distinguish a FORWARD gap (tip ran ahead — the restart case) from a
/// BACKWARD/equal height (reorg or duplicate). On a forward gap, RE-ANCHOR:
/// wipe the stale view and resume accrual with this block as a fresh anchor
/// (UTXOViewCache::reanchor()). On a backward/equal height, keep the
/// fail-closed DROP — an accrual-only view cannot safely fold a reorg, and
/// dropping never overstates a fee. A fresh view (best_height == 0) always
/// connects as the first anchor.
///
/// == THE PREV-HASH CONTINUITY GAP THIS ALSO CLOSES =========================
/// Height equality alone is NOT proof of continuity. A SAME-HEIGHT reorg can
/// replace the tip the view flushed: our view sits at best_height (best_block
/// id B), the chain reorgs best_height to a DIFFERENT block, then advances to
/// best_height+1 whose parent is that NEW block, not B. The incoming height is
/// exactly best_height+1 so the height-only classifier said Connect — but
/// connect_block would then fold a block whose parent ≠ the view's flushed
/// best_block, spending against a UTXO set that never saw the replacement. That
/// over-proves an output already spent out from under us on the winning fork.
/// So the exact-next-height case additionally requires `parent_matches` (the
/// incoming block's m_previous_block == the view's persisted best_block). When
/// it does not match, DROP (fail-closed hold) exactly as for a reorg: the view
/// stops accruing until it observes a block that truly extends its own tip, and
/// no tx is ever fee-proved against a stale view. The forward-gap and
/// first-anchor cases do not consult it — reanchor() wipes the view (nothing to
/// be continuous with) and the first anchor has no predecessor to match.
///
/// This mirrors the DASH Window-2 re-anchor posture (main_dash.cpp): a view
/// that has fallen behind the tip re-syncs rather than latching dead.

namespace dgb {
namespace coin {

/// What the full_block handler should do with a confirmed-tip block, given the
/// view's persisted best_height and the block's absolute height.
enum class FullBlockAccrualAction {
    Connect,             ///< extend the view by one (or first-ever anchor)
    ReAnchorThenConnect, ///< forward gap (e.g. restart): wipe + accrue afresh
    Drop,                ///< reorg / lower-or-equal height: fail-closed, hold view
};

/// Pure classifier. `best_height` is UTXOViewCache::get_best_height() (0 when
/// the view has never connected a block); `incoming_height` is the absolute
/// height of the confirmed-tip block being connected; `parent_matches` is
/// whether the incoming block's m_previous_block == the view's persisted
/// best_block id (UTXOViewCache::get_best_block()). It is consulted ONLY in the
/// exact-next-height case — where it distinguishes a genuine one-block extend
/// of OUR tip from a same-height reorg that replaced the tip we flushed. The
/// first-anchor and forward-gap cases ignore it (no predecessor / the view is
/// about to be wiped by reanchor()).
inline FullBlockAccrualAction classify_full_block_accrual(uint32_t best_height,
                                                          uint32_t incoming_height,
                                                          bool parent_matches)
{
    if (best_height == 0)
        return FullBlockAccrualAction::Connect;              // first anchor (no parent to match)
    if (incoming_height == best_height + 1)
        return parent_matches
                   ? FullBlockAccrualAction::Connect         // normal extend of OUR tip
                   : FullBlockAccrualAction::Drop;           // same-height reorg replaced our tip
    if (incoming_height > best_height + 1)
        return FullBlockAccrualAction::ReAnchorThenConnect;  // forward gap (restart) — reanchor wipes
    return FullBlockAccrualAction::Drop;                     // reorg / <= best
}

} // namespace coin
} // namespace dgb
