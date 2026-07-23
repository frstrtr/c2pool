// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dash reception wire (E-SUPERBLOCK) -- interfaces::Node governance feed ->
// maintainer -> GovernanceStore (daemonless superblock payee sourcing).
//
// Two legs, mirroring the SML axis (wire_mnlistdiff_ingest):
//   * new_govobject -> CoinStateMaintainer::on_govobject: a governance object.
//     A TRIGGER (type 2) whose vchData parses as a valid superblock schedule is
//     added to the store; everything else is dropped.
//   * new_govvote   -> CoinStateMaintainer::on_govvote: a governance vote. A
//     FUNDING-signal vote on a known trigger is counted ONLY if the maintainer's
//     vote verifier confirms its ECDSA signature (default UNSET => fail closed).
//
// LIFETIME: the handlers capture maint by reference, so maint (and the
// NodeCoinState it drives) MUST outlive node. Same EventDisposable teardown
// contract as wire_mn_list_ingest / wire_mnlistdiff_ingest.
// ===========================================================================
#include <memory>

#include <core/events.hpp>

#include "node_interface.hpp"        // dash::interfaces::Node governance feed
#include "coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer::on_gov*

namespace c2pool::dash
{

// Subscribe maint to node.new_govobject: every governance object off the
// coin-P2P govsync feed is routed to on_govobject(), which parses a trigger's
// payment schedule into the GovernanceStore. Returns the subscription handle.
inline std::shared_ptr<EventDisposable>
wire_govobject_ingest(::dash::interfaces::Node& node,
                      ::dash::coin::CoinStateMaintainer& maint)
{
    return node.new_govobject.subscribe(
        [&maint](const ::dash::interfaces::Node::GovObjectRecord& r)
        {
            maint.on_govobject(r.object_hash, r.object_type, r.vch_data);
        });
}

// Subscribe maint to node.new_govvote: every governance vote off the coin-P2P
// govsync feed is routed to on_govvote(), which tallies a verified funding vote
// into the GovernanceStore. Returns the subscription handle.
inline std::shared_ptr<EventDisposable>
wire_govvote_ingest(::dash::interfaces::Node& node,
                    ::dash::coin::CoinStateMaintainer& maint)
{
    return node.new_govvote.subscribe(
        [&maint](const ::dash::interfaces::Node::GovVoteRecord& r)
        {
            ::dash::coin::CoinStateMaintainer::GovVoteContext ctx;
            ctx.parent_hash       = r.parent_hash;
            ctx.mn_outpoint_hash  = r.mn_outpoint_hash;
            ctx.mn_outpoint_index = r.mn_outpoint_index;
            ctx.outcome           = r.outcome;
            ctx.signal            = r.signal;
            ctx.time              = r.time;
            ctx.vch_sig           = r.vch_sig;
            ctx.vote_hash         = r.vote_hash;
            maint.on_govvote(ctx, r.mn_outpoint_key);
        });
}

} // namespace c2pool::dash
