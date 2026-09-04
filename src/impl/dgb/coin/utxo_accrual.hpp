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
/// height of the confirmed-tip block being connected.
inline FullBlockAccrualAction classify_full_block_accrual(uint32_t best_height,
                                                          uint32_t incoming_height)
{
    if (best_height == 0)
        return FullBlockAccrualAction::Connect;              // first anchor
    if (incoming_height == best_height + 1)
        return FullBlockAccrualAction::Connect;              // normal extend
    if (incoming_height > best_height + 1)
        return FullBlockAccrualAction::ReAnchorThenConnect;  // forward gap (restart)
    return FullBlockAccrualAction::Drop;                     // reorg / <= best
}

} // namespace coin
} // namespace dgb
