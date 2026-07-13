// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dash reception wire (leg 3 of 4) -- interfaces::Node::block_connected ->
// maintainer.
//
// #672..#685 landed the node-held embedded coin-state bundle + its async
// CoinStateMaintainer; leg 1 (wire_mempool_ingest) subscribed the mempool-relay
// event and leg 2 (wire_tip_ingest) the header/think TIP-ADVANCE event. This
// leg subscribes the BLOCK-CONNECT event: every connected block is routed to
// CoinStateMaintainer::on_block_connected(), which folds the block's DIP3
// special txs into the DMN set incrementally (MnStateMachine::apply_block),
// keeping the masternode set the embedded coinbase pays current BETWEEN full
// mnlistdiff snapshots. A block that empties the set (all collateral spent)
// clears MN-readiness and demotes the bundle to the retained dashd getblock-
// template fallback rather than backing a template with a phantom payee.
//
// PAYLOAD: a bare full_block carries the block body but NOT its height, and
// apply_block needs the connected height (DIP3 special-tx chain position). So
// this leg subscribes block_connected, which pairs (block, height) -- the
// interface-shape addition this leg makes, mirroring leg 2's TipAdvance, kept to
// the dash interface only (single-coin, purely additive). on_mn_list_update
// remains the authoritative bulk resync (leg 4, mnlistdiff source event).
//
// LIFETIME: the handler captures maint by reference, so maint (and the
// NodeCoinState it drives) MUST outlive node. The returned EventDisposable lets
// a caller tear the subscription down explicitly; it does NOT auto-dispose on
// drop -- identical contract to wire_mempool_ingest / wire_tip_ingest.
//
// SCC: pulls node_interface.hpp (transaction/block codec via BlockConnected),
// so include this header ONLY from a TU that already links the full dash codec
// (main_dash + this leg KAT), never a guard-weight TU.
// ===========================================================================
#include <memory>

#include <core/events.hpp>

#include "node_interface.hpp"        // dash::interfaces::Node (block_connected feed) + BlockConnected
#include "coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer::on_block_connected

namespace c2pool::dash
{

// Subscribe maint to node.block_connected: every connected block folds its DIP3
// special txs into the DMN set via on_block_connected(block, height). The
// maintainer refreshes MN-readiness from the post-apply set size -- a block that
// empties the set demotes the node-held bundle to the dashd fallback; otherwise
// it republishes with the freshened MN set. Returns the subscription handle so
// the caller controls teardown.
inline std::shared_ptr<EventDisposable>
wire_block_connect_ingest(::dash::interfaces::Node& node,
                          ::dash::coin::CoinStateMaintainer& maint)
{
    return node.block_connected.subscribe(
        [&maint](const ::dash::interfaces::BlockConnected& bc)
        {
            maint.on_block_connected(bc.block, bc.height);
        });
}

} // namespace c2pool::dash
