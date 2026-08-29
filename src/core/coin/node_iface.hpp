// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin::ICoinNode -- generic per-coin node interface for src/core/web_server
// (family-1 link fix, P2 WorkView seam).
//
// web_server is SHARED core but historically forward-declared and held raw
// pointers to CONCRETE impl/ltc types (ltc::coin::NodeRPC,
// ltc::interfaces::Node, ltc::coin::CoinNodeInterface). That breaks the BTC link
// (ltc symbols absent; btc's per-coin types differ).
//
// SUPERSEDES the earlier template<class WorkData> INodeRPC/ICoinNode draft. The
// nm census proved web_server consumes a WorkData via only its agnostic slice
// (m_data/m_hashes/m_latency), never m_txs -- so getwork() does NOT need to
// return the per-coin WorkData across the seam. Instead the concrete coin node
// keeps the FULL WorkData coin-side (work.set(wd)) and hands core a WorkView.
// A single NON-TEMPLATE virtual now suffices, and the original "keep getwork
// parametric" gate is preserved where it matters: full WorkData (incl. m_txs)
// never leaves the coin.
//
// Each coin's concrete node (ltc::coin::CoinNode, btc::coin::CoinNode) inherits
// this base directly (direct-inherit, no adapter -- ltc-doge OK) and web_server
// holds one core::coin::ICoinNode* m_coin_node.
// ---------------------------------------------------------------------------

#include <string>

#include <core/coin/work_view.hpp>

namespace core::coin {

struct ICoinNode {
    virtual ~ICoinNode() = default;

    // Build (or fetch) a block template and return its coin-agnostic slice.
    // The concrete impl makes the embedded-vs-rpc decision internally, calls
    // work.set(wd) to retain the FULL per-coin WorkData coin-side, then moves
    // m_data/m_hashes/m_latency into the returned view. Throws std::runtime_error
    // if no template is available. (Folds web_server.cpp:2167-2172.)
    virtual WorkView get_work_view() = 0;

    // Submit a pre-serialised block as hex. Coin-agnostic 2-arg form: the
    // LTC-MWEB extension block is NOT carried on this shared virtual -- mweb is
    // LTC-specific and the concrete ltc node forwards to its 3-arg rpc overload
    // with mweb="" coin-side. Sole caller (web_server.cpp:2730) passed mweb="",
    // so dropping the slot cannot break MWEB submit. Returns true iff accepted.
    virtual bool submit_block_hex(const std::string& block_hex,
                                  bool ignore_failure) = 0;

    // True iff this node has the embedded in-process template source.
    // is_embedded() and has_rpc() are ORTHOGONAL -- a node may have BOTH (embedded
    // preferred for get_work_view(), external RPC as fallback). Preserves the
    // source labels (web_server.cpp:4423-4451) and the status JSON key "embedded"
    // (web_server.cpp:4696).
    virtual bool is_embedded() const = 0;

    // True iff this node has an external coin-RPC client. ORTHOGONAL to
    // is_embedded() -- may co-exist with embedded as the getwork fallback and is
    // the sole path for submit_block_hex(). Backs the status JSON key "has_rpc"
    // (web_server.cpp:4697).
    virtual bool has_rpc() const = 0;
};

} // namespace core::coin