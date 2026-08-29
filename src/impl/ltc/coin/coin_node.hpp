// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// ltc::coin::CoinNode -- concrete core::coin::ICoinNode for LTC (family-1 P2
// WorkView seam). This is the REFERENCE impl the btc::coin::CoinNode mirrors
// (piece-5(c)); the control flow / sequencing here are the load-bearing part.
//
//   m_embedded : CoinNodeInterface*       -- EmbeddedCoinNode in-process source
//   m_rpc      : NodeRPC*                  -- external coin-RPC client
//   work       : Variable<rpc::WorkData>  -- full per-coin WorkData kept coin-side
//
// web_server (shared core) historically held raw pointers to CONCRETE ltc types
// (ltc::coin::NodeRPC, ltc::interfaces::Node) and called getwork()/submit on
// them directly -- that names ltc:: symbols in web_server.cpp.o and breaks the
// BTC link. This type collapses the embedded-vs-rpc decision plus the full
// WorkData retention coin-side, and exposes only the coin-agnostic
// core::coin::ICoinNode contract across the seam (WorkView, 2-arg submit).
//
// MWEB arity: ltc::coin::NodeRPC::submit_block_hex is the 3-arg
// (block_hex, mweb, ignore_failure) LTC form. The ICoinNode override is the
// coin-agnostic 2-arg form; it forwards to the 3-arg rpc with mweb="" coin-side.
// The sole pre-seam caller (web_server.cpp:2730) already passed mweb="", so
// dropping the mweb slot across the seam is behaviour-preserving for MWEB
// submit. (See coin_node.cpp for the forward + the standing flag.)
// ---------------------------------------------------------------------------

#include <string>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/events.hpp>

#include "rpc.hpp"
#include "rpc_data.hpp"
#include "template_builder.hpp"

namespace ltc
{

namespace coin
{

class CoinNode : public core::coin::ICoinNode
{
    // Embedded in-process template source (EmbeddedCoinNode, via the
    // CoinNodeInterface base). May be null when the node runs RPC-only.
    // is_embedded() reports its presence.
    CoinNodeInterface* m_embedded = nullptr;

    // External coin-RPC client. May be null in embedded-only mode; it is the
    // sole sink for submit_block_hex(). has_rpc() reports its presence.
    NodeRPC* m_rpc = nullptr;

    // Full per-coin WorkData (incl. vector<Transaction> m_txs) retained
    // coin-side via work.set(wd); only the agnostic WorkView slice crosses the
    // seam into core/web_server. Replaces the old ltc::interfaces::Node::work
    // slot that web_server used to reach through m_coin_node.
    Variable<rpc::WorkData> work;

public:
    CoinNode(CoinNodeInterface* embedded, NodeRPC* rpc)
        : m_embedded(embedded), m_rpc(rpc) {}

    core::coin::WorkView get_work_view() override;
    bool submit_block_hex(const std::string& block_hex, bool ignore_failure) override;

    bool is_embedded() const override { return m_embedded != nullptr; }
    bool has_rpc()     const override { return m_rpc != nullptr; }
};

} // namespace coin

} // namespace ltc