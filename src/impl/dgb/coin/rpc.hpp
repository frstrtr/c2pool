#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::NodeRPC -- external coin-RPC client STUB (Path A minimal-stub,
// "rpc stubs" scope item).
//
// btc/ltc NodeRPC is a boost::beast + jsonrpccxx HTTP JSON-RPC client whose
// header drags in block.hpp / transaction.hpp -- types dgb does not port
// until M3. This stub keeps the call surface coin_node.cpp and coin/node.hpp
// consume, with no transport behind it:
//
//   getwork()          -> throws std::runtime_error. This is the ICoinNode
//                         contract for "no template available" -- web_server
//                         already handles the throw, so a wired-but-stub DGB
//                         node degrades loudly, not silently.
//   submit_block_hex() -> false ("no RPC sink"; the same result the null-
//                         m_rpc guard in CoinNode::submit_block_hex yields).
//   check()            -> false (never connected).
//
// connect()/reconnect()/the RPC method set (getblocktemplate etc.) arrive
// with the real transport in M3 as a body-only swap mirroring
// src/impl/btc/coin/rpc.{hpp,cpp}; DGB's getblocktemplate call passes
// rules=["scrypt"] per the Scrypt GBT filter point (template_builder.hpp,
// impl plan section 3) so only Scrypt-eligible templates are returned.
// ---------------------------------------------------------------------------

#include <stdexcept>
#include <string>

#include "node_interface.hpp"
#include "rpc_data.hpp"

namespace dgb
{

namespace coin
{

class NodeRPC
{
    // Shared-state surface the real client fills (work variable); the stub
    // holds the pointer so the M3 swap does not change construction sites.
    dgb::interfaces::Node* m_coin = nullptr;

public:
    explicit NodeRPC(dgb::interfaces::Node* coin = nullptr) : m_coin(coin) {}

    // Never connected: no transport in the stub.
    bool check() const { return false; }

    rpc::WorkData getwork()
    {
        throw std::runtime_error(
            "dgb: NodeRPC is a Path A stub -- no external RPC transport until M3");
    }

    bool submit_block_hex(const std::string& /*block_hex*/, bool /*ignore_failure*/)
    {
        return false;
    }
};

} // namespace coin

} // namespace dgb
