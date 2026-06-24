#pragma once

// Phase S8 — WonBlockRelay getdata dispatch (LEAF).
//
// The INBOUND half of the embedded-P2P won-block relay handshake. The framer
// (block_relay.hpp) builds the OUTBOUND frames: announce() -> `inv`, and
// on_getdata_block(hash) -> the full `block` for ONE hash. But a peer answers
// our inv with a single `getdata` message carrying a VECTOR of inventory
// requests, and the node read-loop hands us that whole RawMessage off the wire.
// This leaf is the pure dispatcher that decodes one inbound `getdata` and routes
// every MSG_BLOCK request through the relay's pending-block book:
//
//     [peer] getdata(MSG_BLOCK h1, MSG_TX t, MSG_BLOCK h2_unknown, ...)
//        -> dispatch_getdata:
//             base_type == block && relay knows hash -> queue `block` reply
//             base_type == block && unknown          -> collect into `notfound`
//             base_type != block                     -> ignore (won blocks only)
//
// Result: the ordered list of `block` RawMessages to transmit (one per known
// block request, in the peer's request order), plus an optional `notfound`
// RawMessage for the block hashes we could not serve — the standard Dash/Bitcoin
// relay courtesy so the peer stops waiting on us. Non-block inv types (tx,
// filtered_block, cmpct_block) are silently ignored: this is the won-block
// relay, not a general inventory server.
//
// SCOPE / NON-CONSENSUS: same invariant as the framer. We never recompute a
// block hash and never serve a block we did not announce — on_getdata_block()
// (which gates on the pending-block book) returns nullptr for anything else, so
// this carries no consensus value and cannot diverge a hash. Wiring the decoded
// replies onto the live slots' sockets stays in the operator-gated
// broadcaster_full keystone. Header-only, single dash tree, socket-free —
// unit-testable with zero sockets and zero live dashd, like its sibling leaves.

#include "block_relay.hpp"
#include "coin/p2p_messages.hpp"

#include <core/message.hpp>
#include <core/uint256.hpp>

#include <memory>
#include <vector>

namespace dash
{

// The decoded result of an inbound getdata evaluated against a WonBlockRelay.
struct GetDataDispatch
{
    // `block` RawMessages to send, one per KNOWN MSG_BLOCK request, preserving
    // the peer's request order.
    std::vector<std::unique_ptr<RawMessage>> blocks;
    // A single `notfound` RawMessage listing the block hashes the peer asked
    // for that we never announced, or nullptr if every block request was served.
    std::unique_ptr<RawMessage> notfound;

    size_t served()     const { return blocks.size(); }
    bool   has_misses() const { return notfound != nullptr; }
};

// Decode an inbound `getdata` RawMessage and route each MSG_BLOCK request
// through the relay's pending-block book. Pure: reads `relay` const, opens no
// socket, recomputes no hash. Non-block requests are ignored.
inline GetDataDispatch dispatch_getdata(const RawMessage& getdata_msg,
                                        const WonBlockRelay& relay)
{
    using inventory_type = dash::coin::p2p::inventory_type;

    GetDataDispatch out;
    std::vector<inventory_type> misses;

    // make() consumes the stream, so parse a COPY — decoding an inbound message
    // must not mutate the caller's RawMessage (keeps `getdata_msg` const).
    PackStream stream = getdata_msg.m_data;
    auto parsed = dash::coin::p2p::message_getdata::make(stream);
    for (const auto& req : parsed->m_requests)
    {
        // Dash has no segwit, but a peer may still tag MSG_WITNESS_BLOCK; match
        // on the base type and serve the same canonical block either way.
        if (req.base_type() != inventory_type::block)
            continue;  // not our concern — the won-block relay serves blocks only

        if (auto blk = relay.on_getdata_block(req.m_hash))
            out.blocks.push_back(std::move(blk));
        else
            misses.emplace_back(inventory_type::block, req.m_hash);
    }

    if (!misses.empty())
        out.notfound = dash::coin::p2p::message_notfound::make_raw(misses);

    return out;
}

} // namespace dash
