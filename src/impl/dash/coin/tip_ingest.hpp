// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dash reception wire (leg 2 of 4) -- interfaces::Node::new_tip -> maintainer.
//
// #672..#685 landed the node-held embedded coin-state bundle + its async
// CoinStateMaintainer; wire_mempool_ingest (leg 1) subscribed the mempool-relay
// event. This leg subscribes the header/think TIP-ADVANCE event: every tip
// advance is routed to CoinStateMaintainer::on_new_tip(), which stashes the tip
// params and marks tip-readiness -- one of the two prerequisites (the MN list
// is the other) that must BOTH be present before the node-held bundle publishes
// and select_work() flips off the retained dashd getblocktemplate fallback.
//
// PAYLOAD: unlike a bare best_block_hash, interfaces::Node::new_tip carries a
// TipAdvance -- the height/hash to build ON, next-block bits, tip MTP, and the
// coin address versions -- exactly build_embedded_workdata() inputs. That
// struct is the interface-shape addition this leg makes; the leg 1 note flagged
// that on_new_tip needs params best_block_hash does not carry, and this is that
// payload, kept to the dash interface only (single-coin, purely additive).
//
// STILL UNWIRED (own slices): on_mn_list_update has no source event on
// interfaces::Node yet; on_block_connected needs the connected block height,
// which full_block does not carry.
//
// LIFETIME: the handler captures maint by reference, so maint (and the
// NodeCoinState it drives) MUST outlive node. The returned EventDisposable
// lets a caller tear the subscription down explicitly; it does NOT auto-dispose
// on drop -- identical contract to wire_mempool_ingest.
//
// SCC: pulls node_interface.hpp (transaction/block codec via TipAdvance
// siblings), so include this header ONLY from a TU that already links the full
// dash codec (main_dash + this leg KAT), never a guard-weight TU.
// ===========================================================================
#include <memory>

#include <core/events.hpp>

#include "node_interface.hpp"        // dash::interfaces::Node (new_tip feed) + TipAdvance
#include "coin_state_maintainer.hpp" // dash::coin::CoinStateMaintainer::on_new_tip

namespace c2pool::dash
{

// Subscribe maint to node.new_tip: every tip advance stashes the embedded
// template params and marks tip-readiness via on_new_tip(); the maintainer
// republishes the node-held bundle only once the MN list is ALSO seeded, so a
// tip arriving before the first mnlistdiff leaves the bundle on the dashd
// fallback. Returns the subscription handle so the caller controls teardown.
inline std::shared_ptr<EventDisposable>
wire_tip_ingest(::dash::interfaces::Node& node,
                ::dash::coin::CoinStateMaintainer& maint)
{
    return node.new_tip.subscribe(
        [&maint](const ::dash::interfaces::TipAdvance& t)
        {
            maint.on_new_tip(t.prev_height, t.prev_hash, t.bits_for_next,
                             t.mtp_at_tip, t.address_version, t.address_p2sh_version,
                             t.curtime, t.version);
        });
}

} // namespace c2pool::dash
