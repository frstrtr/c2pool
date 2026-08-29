// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// bch::coin::CoinNode -- concrete core::coin::ICoinNode for BCH (family-1 P2
// WorkView seam). 1:1 mirror of the btc::coin::CoinNode reference, member-mapped
// onto BCH's node types (M3 slices 1-4):
//   m_embedded : CoinNodeInterface*       -- embedded in-process work source
//   m_rpc      : NodeRPC*                  -- external coin-RPC client
//   work       : Variable<rpc::WorkData>  -- full per-coin WorkData kept coin-side
//
// Build-INERT: defines the type but is NOT yet wired into web_server (a separate
// member-wiring cluster). impl_bch stays unregistered in CMake (bch = skip-green)
// so CI is untouched; the seam gate flips only after wiring + a clean nm census.
//
// BCH carries NO MWEB: get_work_view() hands core only the agnostic slice and
// submit_block_hex() forwards the 2-arg/no-mweb form (mweb is LTC-specific).
// ---------------------------------------------------------------------------

#include <string>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/events.hpp>

#include "rpc.hpp"
#include "rpc_data.hpp"
#include "template_builder.hpp"

namespace bch
{

namespace coin
{

class CoinNode : public core::coin::ICoinNode
{
    // Embedded in-process template source. May be null when the node runs
    // RPC-only. is_embedded() reports its presence.
    CoinNodeInterface* m_embedded = nullptr;

    // External coin-RPC client. May be null in embedded-preferred mode; it is
    // the sole sink for submit_block_hex(). has_rpc() reports its presence.
    NodeRPC* m_rpc = nullptr;

    // Full per-coin WorkData (incl. m_txs) retained coin-side via work.set(wd);
    // only the agnostic WorkView slice crosses the seam into core/web_server.
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

} // namespace bch