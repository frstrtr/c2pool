#pragma once

// Phase S8 — WonBlockRelay live-slots reply path (LEAF).
//
// Binds the relay HANDSHAKE (block_relay.hpp framer + the inbound getdata
// decode, inlined below) to the broadcaster's LIVE SLOTS, producing a per-slot SEND
// PLAN. It is the last pure rung before the operator-gated keystone:
//
//     announce/dispatch frames ──▶ [block_relay_plan] ──▶ broadcaster_full
//        (what to send)              (to WHICH slot)         (actual sockets)
//
// The framer/dispatcher answer "what frame" for ONE hash or ONE inbound getdata;
// the DashBroadcaster (broadcaster.hpp) holds the pool of live "host:port" slot
// keys. Neither knows the other. This leaf is the planner that joins them:
//
//   * plan_announce(live_slots, hash, block)
//       records the won block (delegates to WonBlockRelay::announce) and returns
//       the SINGLE `inv` frame plus the de-duped list of live slot keys it must
//       fan out to. One frame, many slots — an inv broadcast, modelled honestly
//       as one frame + a recipient list rather than N identical copies.
//   * plan_getdata_reply(slot, getdata_msg)
//       routes ONE inbound getdata (decoded inline against the relay) back to the
//       SAME slot that asked: the ordered `block` replies + optional `notfound`,
//       all tagged with the requesting slot key.
//
// SCOPE / NON-CONSENSUS: identical invariant to the framer/dispatcher. Slot keys
// are OPAQUE strings (the broadcaster's pool keys) — no socket is opened, no
// io_context touched, no block hash recomputed, and a block is served only if it
// was announced. The plan is INERT data; the DECISION to walk it and write the
// frames onto the live slots' sockets stays in the operator-gated
// broadcaster_full keystone. A won block is recorded even when there are zero
// live slots (the dashd submitblock arm still carries it, and a peer that
// connects later can still getdata it) — recording is decoupled from fan-out.
// Header-only, single dash tree, socket-free — unit-testable with zero sockets
// and zero live dashd, like its sibling leaves.

#include "block_relay.hpp"
#include "coin/p2p_messages.hpp"

#include <core/message.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace dash
{

// The fan-out plan for a won block: ONE inv frame + the live slot keys to send
// it to. The inv is identical for every recipient (a broadcast), so it is held
// once rather than copied per slot.
struct AnnouncePlan
{
    std::vector<std::string>    slots;   // de-duped live slot keys to fan out to
    std::unique_ptr<RawMessage> inv;     // the single `inv(MSG_BLOCK, hash)` frame

    size_t fanout() const { return slots.size(); }
};

// The reply plan for ONE inbound getdata: the decoded block replies + optional
// notfound, tagged with the slot that asked so broadcaster_full writes them back
// to the right socket.
struct ReplyPlan
{
    std::string                              slot;      // the slot that requested
    std::vector<std::unique_ptr<RawMessage>> blocks;    // ordered `block` replies
    std::unique_ptr<RawMessage>              notfound;  // misses, or nullptr

    size_t served()     const { return blocks.size(); }
    bool   has_misses() const { return notfound != nullptr; }
};

// Joins a WonBlockRelay to the broadcaster's live slot keys. Holds the relay by
// reference (the relay owns the pending-block book; the planner is stateless).
// Pure: opens no socket, recomputes no hash.
class WonBlockRelayPlanner
{
public:
    explicit WonBlockRelayPlanner(WonBlockRelay& relay) : m_relay(relay) {}

    // Record the won block and build its fan-out plan: the single inv frame plus
    // the live slot keys to send it to. Slot keys are de-duped and empties are
    // skipped, so a slot is never announced to twice. The block is recorded even
    // when `live_slots` is empty — fan-out is decoupled from recording.
    AnnouncePlan plan_announce(std::span<const std::string> live_slots,
                               const uint256& hash,
                               WonBlockRelay::BlockType block)
    {
        AnnouncePlan plan;
        plan.inv = m_relay.announce(hash, std::move(block));

        std::set<std::string> seen;
        for (const auto& key : live_slots)
        {
            if (key.empty() || !seen.insert(key).second)
                continue;
            plan.slots.push_back(key);
        }
        return plan;
    }

    // Route an inbound getdata from `slot` back to that same slot: decode the
    // request against the relay's pending-block book, then tag the result with
    // the requesting slot. `slot` is preserved even when nothing is served, so
    // the caller always knows which connection the (possibly empty) reply
    // belongs to.
    ReplyPlan plan_getdata_reply(const std::string& slot,
                                 const RawMessage& getdata_msg) const
    {
        using inventory_type = dash::coin::p2p::inventory_type;

        ReplyPlan plan;
        plan.slot = slot;

        // Decode the inbound getdata against the relay's pending-block book and
        // route each MSG_BLOCK request through it. (This pure routing previously
        // lived in the block_relay_dispatch.hpp leaf; that getdata-decoder was
        // folded on landing, so the same socket-free logic is inlined here.)
        // make() consumes the stream, so parse a COPY - keeps getdata_msg const.
        std::vector<inventory_type> misses;
        PackStream stream = getdata_msg.m_data;
        auto parsed = dash::coin::p2p::message_getdata::make(stream);
        for (const auto& req : parsed->m_requests)
        {
            // Dash has no segwit, but a peer may tag MSG_WITNESS_BLOCK; match on
            // the base type and serve the same canonical block either way.
            if (req.base_type() != inventory_type::block)
                continue;  // won-block relay serves blocks only

            if (auto blk = m_relay.on_getdata_block(req.m_hash))
                plan.blocks.push_back(std::move(blk));
            else
                misses.emplace_back(inventory_type::block, req.m_hash);
        }

        if (!misses.empty())
            plan.notfound = dash::coin::p2p::message_notfound::make_raw(misses);

        return plan;
    }

private:
    WonBlockRelay& m_relay;
};

} // namespace dash
