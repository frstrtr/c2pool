#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::CoinNode -- concrete core::coin::ICoinNode for DGB (family-1 P2
// WorkView seam, Path A minimal-stub). 1:1 mirror of btc::coin::CoinNode
// (src/impl/btc/coin/coin_node.{hpp,cpp}), which is itself member-mapped from
// the ltc::coin::CoinNode reference -- the control flow / sequencing are the
// load-bearing part and are preserved verbatim:
//   m_embedded : CoinNodeInterface*       -- embedded in-process source
//   m_rpc      : NodeRPC*                 -- external coin-RPC client (STUB)
//   work       : Variable<rpc::WorkData>  -- full per-coin WorkData kept
//                                            coin-side; only the agnostic
//                                            WorkView slice crosses the seam
//
// DGB Path A status: both work sources behind this adapter are stubs --
// NodeRPC throws on getwork() (rpc.hpp) and no EmbeddedCoinNode exists until
// the M3 daemon slice -- so a wired DGB node reports "no template" loudly
// through the ICoinNode contract rather than fabricating work. The adapter
// itself is COMPLETE: when either source becomes real, no seam-side change
// is needed.
//
// Build-INERT: defines the type; NOT yet wired into web_server or a
// main_dgb.cpp (no such binary split exists yet). Registration follows the
// ci-steward OBJECT-lib convention; see src/impl/dgb/CMakeLists.txt.
// ---------------------------------------------------------------------------

#include <string>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/events.hpp>

#include "rpc.hpp"
#include "rpc_data.hpp"
#include "template_builder.hpp"

namespace dgb
{

namespace coin
{

class CoinNode : public core::coin::ICoinNode
{
    // Embedded in-process template source (EmbeddedCoinNode, M3). May be null
    // when the node runs RPC-only. is_embedded() reports its presence.
    CoinNodeInterface* m_embedded = nullptr;

    // External coin-RPC client. May be null in embedded-preferred mode; it is
    // the sole sink for submit_block_hex(). has_rpc() reports its presence.
    NodeRPC* m_rpc = nullptr;

    // Full per-coin WorkData retained coin-side via work.set(wd); only the
    // agnostic WorkView slice crosses the seam into core/web_server.
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

} // namespace dgb
