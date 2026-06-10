#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::Node -- per-coin node owner (Path A minimal-stub). TRIMMED mirror
// of src/impl/btc/coin/node.hpp: owns the NodeRPC client and inherits the
// dgb::interfaces::Node shared-state surface (work variable + new_block
// event) that NodeRPC and the seam-side CoinNode bind against.
//
// Deliberately ABSENT until M3 (each needs a port dgb does not have yet):
//   - NodeP2P / p2p_connection (coin P2P block relay; btc's p2p_node.hpp)
//   - init_rpc() transport connect (NodeRPC is a stub with no transport)
//   - submit_block_p2p / send_getheaders / handshake surface
// The ctor keeps btc's (context, config) shape via auto params (no boost
// include needed in the stub) so M3 restores the body without re-typing
// construction sites.
// ---------------------------------------------------------------------------

#include <memory>

#include "node_interface.hpp"
#include "rpc.hpp"

namespace dgb
{

namespace coin
{

template <typename ConfigType>
class Node : public dgb::interfaces::Node
{
    using config_t = ConfigType;

    config_t* m_config = nullptr;

    std::unique_ptr<NodeRPC> m_rpc;

public:
    Node(auto* /*context*/, auto* config) : m_config(config)
    {
    }

    void run()
    {
        // Stub NodeRPC: constructed so has-rpc presence wiring can be
        // exercised, but no transport connect until M3.
        m_rpc = std::make_unique<NodeRPC>(this);
    }

    NodeRPC* rpc() { return m_rpc.get(); }
};

} // namespace coin

} // namespace dgb
