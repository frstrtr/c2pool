// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dash reception wire (leg 1 of 4) -- interfaces::Node::new_tx -> maintainer.
//
// #672..#685 landed the node-held embedded coin-state bundle plus its async
// CoinStateMaintainer, and proved that DRIVING the maintainer's on_*() methods
// flips select_work() to the embedded arm. But nothing in a LIVE NodeImpl ever
// subscribed the coin interface's reception events to that maintainer, so in a
// running node the arm could never flip on its own -- the maintainer sat idle.
// This is the first of the four reception legs
// (on_mempool_tx / on_block_connected / on_new_tip / on_mn_list_update): the
// mempool-relay leg, wired exactly as the dgb sibling (wire_mempool_ingest)
// but routed through the maintainer's on_mempool_tx() so the readiness /
// republish bookkeeping stays in one place.
//
// PAYLOAD-COMPLETE TODAY: interfaces::Node::new_tx carries a whole
// coin::Transaction, and on_mempool_tx() never gates publication (an empty
// mempool still yields a valid coinbase-only template), so this leg needs no
// chain context. The other three legs are NOT wired here: on_block_connected
// needs the connected block's HEIGHT (full_block carries none -- see bch's
// block_connector deriving it from the chain tip), on_new_tip needs
// bits/mtp/address-version params a bare best_block_hash does not carry, and
// on_mn_list_update has no source event on interfaces::Node at all. Those are
// their own slices; opening them touches the interface shape and is a design
// decision surfaced to the integrator, not guessed here.
//
// LIFETIME: the handler captures `maint` by reference, so `maint` (and the
// NodeCoinState it drives) MUST outlive `node`. The returned EventDisposable
// lets a caller tear the subscription down explicitly; EventDisposable does
// NOT auto-dispose on destruction, so if the handle is dropped the
// subscription persists for the node's life.
//
// SCC (#143 / #22 / #39): pulls transaction.hpp (the tx serialization codec),
// so include this header ONLY from a TU that already links the full dash codec
// (main_dash + this leg's KAT), never a guard-weight TU -- identical to the
// dgb mempool_ingest / embedded_tx_select btclibs-SCC trap.
// ===========================================================================
#include <memory>

#include <core/events.hpp>

#include "node_interface.hpp"        // dash::interfaces::Node (new_tx feed)
#include "coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer::on_mempool_tx
#include "transaction.hpp"           // dash::coin::Transaction -> MutableTransaction

namespace c2pool::dash
{

// Subscribe `maint` to `node.new_tx`: every relayed tx is folded into the
// maintainer's mempool via on_mempool_tx (fee_known=false until a UTXO view
// feeds it, matching the embedded shaper's conservative default -- a P2P-fed
// mempool cannot desync coinbasevalue versus a daemon's GBT). The mempool leg
// never gates publication, so a rejected tx (bad utxo ref / already-in) is a
// no-op here, not a demotion. Returns the subscription handle so the caller
// controls teardown.
inline std::shared_ptr<EventDisposable>
wire_mempool_ingest(::dash::interfaces::Node& node,
                    ::dash::coin::CoinStateMaintainer& maint)
{
    return node.new_tx.subscribe(
        [&maint](const ::dash::coin::Transaction& tx)
        {
            maint.on_mempool_tx(::dash::coin::MutableTransaction(tx));
        });
}

} // namespace c2pool::dash
