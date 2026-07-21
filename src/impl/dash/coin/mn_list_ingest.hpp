// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dash reception wire (leg 4 of 4) -- interfaces::Node::mn_list_update ->
// maintainer.
//
// Legs 1-3 wired the mempool-relay (new_tx), tip-advance (new_tip) and block-
// connect (block_connected) events into CoinStateMaintainer. This CLOSES the
// wire with the mnlistdiff RESYNC leg: every full masternode-set snapshot
// dashd delivers is routed to CoinStateMaintainer::on_mn_list_update(), which
// REPLACES the DMN set the embedded coinbase pays wholesale (the authoritative
// bulk feed), as opposed to leg 3s on_block_connected() which folds per-block
// special-tx deltas INCREMENTALLY between snapshots. Together the two keep the
// masternode set both correct at each snapshot and current between them.
//
// PAYLOAD: on_mn_list_update() takes the full projected set as a
// vector<pair<uint256, MNState>>; leg 1s scope note called out that this leg
// "has no source event on interfaces::Node at all". That source event
// (mn_list_update, carrying MnListUpdate) is the interface-shape addition this
// leg makes -- purely additive, dash interface only (single-coin), mirroring
// leg 2s TipAdvance and leg 3s BlockConnected. An EMPTY snapshot is forwarded
// verbatim: on_mn_list_update() treats it as a set-gap and demotes the bundle
// to the retained dashd fallback rather than backing a template with no payee.
//
// LIFETIME: the handler captures maint by reference, so maint (and the
// NodeCoinState it drives) MUST outlive node. The returned EventDisposable lets
// a caller tear the subscription down explicitly; it does NOT auto-dispose on
// drop -- identical contract to wire_mempool_ingest / wire_tip_ingest /
// wire_block_connect_ingest.
//
// SCC: pulls node_interface.hpp (which now carries MnListUpdate -> MNState via
// mn_state_machine.hpp) and coin_state_maintainer.hpp, so include this header
// ONLY from a TU that already links the full dash codec (main_dash + this leg
// KAT), never a guard-weight TU.
// ===========================================================================
#include <memory>
#include <utility>

#include <core/events.hpp>

#include "node_interface.hpp"        // dash::interfaces::Node (mn_list_update feed) + MnListUpdate
#include "coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer::on_mn_list_update

namespace c2pool::dash
{

// Subscribe maint to node.mn_list_update: every mnlistdiff snapshot RESYNCS the
// DMN set via on_mn_list_update(mnstates), which republishes when the set is
// non-empty (MN-readiness met) or demotes the node-held bundle to the dashd
// fallback when the snapshot is empty (set-gap). Returns the subscription
// handle so the caller controls teardown.
inline std::shared_ptr<EventDisposable>
wire_mn_list_ingest(::dash::interfaces::Node& node,
                    ::dash::coin::CoinStateMaintainer& maint)
{
    return node.mn_list_update.subscribe(
        [&maint](const ::dash::interfaces::MnListUpdate& u)
        {
            // as_of_height rides along (E2c): the maintainer uses it to fence
            // off re-application of blocks the snapshot already reflects.
            maint.on_mn_list_update(u.mnstates, u.as_of_height);
        });
}

// Subscribe maint to node.new_mnlistdiff: the SML axis (DAEMONLESS CCbTx). Each
// parsed mnlistdiff off the live coin-P2P feed advances the SML
// (merkleRootMNList) + QuorumManager (merkleRootQuorums) + seeds bestCL*/
// creditPool via CoinStateMaintainer::on_mnlistdiff. Distinct from
// wire_mn_list_ingest above (the PAYEE axis). Returns the subscription handle.
inline std::shared_ptr<EventDisposable>
wire_mnlistdiff_ingest(::dash::interfaces::Node& node,
                       ::dash::coin::CoinStateMaintainer& maint)
{
    return node.new_mnlistdiff.subscribe(
        [&maint](const ::dash::coin::vendor::CSimplifiedMNListDiff& diff)
        {
            maint.on_mnlistdiff(diff);
        });
}

} // namespace c2pool::dash
