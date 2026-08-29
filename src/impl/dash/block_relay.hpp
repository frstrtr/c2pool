// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Phase S8 — WonBlockRelay: embedded-P2P won-block relay framer (LEAF).
//
// This is the framing half of the embedded-P2P broadcast leg of the dual-path
// block-viability gate. The OTHER arm (won block -> dashd submitblock RPC) is
// already proven (the launcher producer, regtest crossing). When DASH wins a
// block, the embedded path must also fan it out to the parent-chain (dashd)
// peers the DashBroadcaster pool holds. Dash/Bitcoin block relay is a two-step
// handshake, not a raw push:
//
//     [we win a block]
//        -> announce  : send `inv(MSG_BLOCK, hash)` to every live peer
//     [peer]  -> getdata(MSG_BLOCK, hash)
//        -> on_getdata_block : answer with the full `block` message
//
// This LEAF is the PURE, socket-free framer + pending-block book for exactly
// that handshake:
//
//   * announce(hash, block)      -> the `inv` RawMessage to fan out, and
//                                   records the block under `hash` so a later
//                                   getdata can be answered.
//   * on_getdata_block(hash)     -> the full `block` RawMessage if known, else
//                                   nullptr (we never serve a block we did not
//                                   announce).
//   * knows / pending / forget / clear — the pending-block bookkeeping.
//
// SCOPE / NON-CONSENSUS: the block hash is SUPPLIED by the consensus/producer
// layer (the X11 header hash already computed on the won-block path) — it is
// NOT recomputed here, so this leaf carries no consensus value and cannot
// silently diverge a hash. The DECISION to actually transmit a REAL won block
// onto the live network — wiring on_block_found -> announce -> the live slots'
// sockets — stays in the operator-gated broadcaster_full keystone. This leaf
// only builds the wire frames and answers getdata deterministically, so it is
// unit-testable with zero sockets and zero live dashd, like its sibling leaves
// (broadcaster.hpp, p2p_messages.hpp). Header-only, single dash tree.

#include "coin/p2p_messages.hpp"
#include "coin/block.hpp"

#include <core/message.hpp>
#include <core/uint256.hpp>

#include <map>
#include <memory>
#include <vector>

namespace dash
{

// Won-block relay framer + pending-block book. Non-consensus, socket-free.
class WonBlockRelay
{
public:
    using inventory_type = dash::coin::p2p::inventory_type;
    using BlockType      = dash::coin::BlockType;

    // Record a won block under its (consensus-computed) block hash and return
    // the `inv(MSG_BLOCK, hash)` RawMessage to fan out to the live peers.
    // Idempotent: re-announcing a known hash refreshes the stored block.
    std::unique_ptr<RawMessage> announce(const uint256& hash, BlockType block)
    {
        m_pending[hash] = std::move(block);
        std::vector<inventory_type> invs{
            inventory_type(inventory_type::block, hash)};
        return dash::coin::p2p::message_inv::make_raw(invs);
    }

    // Answer a peer's getdata(MSG_BLOCK, hash): the full `block` RawMessage if
    // the hash was previously announced, else nullptr. We never serve a block
    // we did not announce.
    std::unique_ptr<RawMessage> on_getdata_block(const uint256& hash) const
    {
        auto it = m_pending.find(hash);
        if (it == m_pending.end())
            return nullptr;
        return dash::coin::p2p::message_block::make_raw(it->second);
    }

    bool   knows(const uint256& hash) const { return m_pending.count(hash) != 0; }
    size_t pending() const { return m_pending.size(); }
    void   forget(const uint256& hash) { m_pending.erase(hash); }
    void   clear() { m_pending.clear(); }

private:
    std::map<uint256, BlockType> m_pending;
};

} // namespace dash