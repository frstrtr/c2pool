// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Phase S8 — WonBlockRelay <-> DashBroadcaster binding (LEAF).
//
// The last PURE rung before the operator-gated broadcaster_full keystone. The
// planner (block_relay_plan.hpp) builds a won-block fan-out plan against a
// caller-supplied list of live slot keys; the broadcaster (broadcaster.hpp)
// owns the actual pool of live "host:port" slots. Neither references the other.
// This leaf is the thin adapter that joins them:
//
//     [DashBroadcaster pool] --live_slot_keys()--> [binding] --> [planner] --> plan
//
//   * plan_announce(hash, block)
//       reads the broadcaster's CURRENT live slot keys and asks the planner to
//       record the won block and build its inv fan-out plan against THOSE keys
//       (not a synthetic span). The block is recorded even at zero live slots.
//   * plan_getdata_reply(slot, getdata_msg)
//       pass-through to the planner: route ONE inbound getdata back to the slot
//       that asked.
//
// SCOPE / NON-CONSENSUS: identical invariant to the framer/dispatcher/planner.
// Slot keys are OPAQUE strings owned by the broadcaster pool; this binding opens
// no socket, touches no io_context, recomputes no hash, and serves a block only
// if it was announced. The plan is INERT data — the DECISION to walk it and
// write the frames onto the live slots' sockets (and the dashd submitblock
// fallback arm) stays in the operator-gated broadcaster_full keystone. The
// binding only DECIDES recipients from the live pool; it does not transmit.
// Header-only, single dash tree, socket-free — unit-testable with zero sockets
// and zero live dashd, like its sibling leaves.

#include "block_relay_plan.hpp"
#include "broadcaster.hpp"

#include <core/message.hpp>
#include <core/uint256.hpp>

#include <string>

namespace dash
{

// Joins a DashBroadcaster's live slot pool to a WonBlockRelayPlanner. Holds both
// by reference (the broadcaster owns the pool; the planner owns the relay book;
// the binding is stateless). Pure: opens no socket, recomputes no hash.
class WonBlockRelayBinding
{
public:
    WonBlockRelayBinding(DashBroadcaster& pool, WonBlockRelayPlanner& planner)
        : m_pool(pool), m_planner(planner) {}

    // Record the won block and build its fan-out plan against the broadcaster's
    // CURRENT live slots. Equivalent to pulling broadcaster.live_slot_keys() and
    // handing it to the planner — so the inv is addressed to exactly the peers
    // that are live at announce time. Pruned/dead slots are excluded (they fail
    // the liveness predicate), and the block is still recorded when the pool is
    // empty: recording is decoupled from fan-out, so the submitblock arm and a
    // later-connecting peer still carry/serve it.
    AnnouncePlan plan_announce(const uint256& hash, WonBlockRelay::BlockType block)
    {
        const std::vector<std::string> live = m_pool.live_slot_keys();
        return m_planner.plan_announce(live, hash, std::move(block));
    }

    // Route an inbound getdata from `slot` back to that same slot. Pass-through
    // to the planner; the slot key is whichever pool key the connection belongs
    // to (the keystone supplies it from the receiving socket).
    ReplyPlan plan_getdata_reply(const std::string& slot,
                                 const RawMessage& getdata_msg) const
    {
        return m_planner.plan_getdata_reply(slot, getdata_msg);
    }

    // Convenience observer: how many live peers a won block would fan out to
    // right now, without recording anything. Mirrors the broadcaster predicate.
    size_t live_fanout() const { return m_pool.live_slot_keys().size(); }

private:
    DashBroadcaster&      m_pool;
    WonBlockRelayPlanner& m_planner;
};

} // namespace dash