// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::NodeP2PPoolPeer -- one CoinPeerPool connection over the BTC
// coin P2P driver (p2p::NodeP2P). Each connection has its own event sink, so
// the pool knows which peer sent a headers message, an announcement or a
// block body.

#include "coin_peer_pool.hpp"
#include "node_interface.hpp"
#include "p2p_node.hpp"

#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace btc::coin {

template <typename ConfigT>
class NodeP2PPoolPeer final : public PoolPeer {
    // The driver and its event sink in one allocation: the driver holds a
    // raw pointer to the sink, and the dial-lifetime guard (an aliasing
    // shared_ptr to the driver) keeps both alive while a resolve/connect
    // completion is pending after this connection was dropped.
    struct Link {
        btc::interfaces::Node   sink;
        p2p::NodeP2P<ConfigT>   node;

        Link(boost::asio::io_context* ioc, ConfigT* config, const std::string& label)
            : node(ioc, &sink, config, label)
        {
        }
    };

    std::shared_ptr<Link> m_link;

public:
    NodeP2PPoolPeer(boost::asio::io_context* ioc, ConfigT* config, const NetService& addr,
                    PoolPeerHooks hooks, const std::string& label = "CoinP2P")
        : m_link(std::make_shared<Link>(ioc, config, label))
    {
        std::shared_ptr<core::INetwork> life(m_link, &m_link->node);
        m_link->node.set_lifetime(life);
        assert(m_link->node.lifetime_armed() && "pooled coin-P2P dial lifetime failed to arm");

        auto& sink = m_link->sink;
        if (hooks.headers)
            sink.new_headers.subscribe(
                [f = hooks.headers](const std::vector<BlockHeaderType>& h) { f(h); });
        if (hooks.block_announced)
            sink.new_block.subscribe([f = hooks.block_announced](const uint256& h) { f(h); });
        if (hooks.tx)
            sink.new_tx.subscribe([f = hooks.tx](const Transaction& tx) { f(tx); });
        if (hooks.full_block)
            sink.full_block.subscribe([f = hooks.full_block](const BlockType& b) { f(b); });
        if (hooks.headers_message)
            m_link->node.set_on_headers_message(std::move(hooks.headers_message));
        if (hooks.fetch)
            m_link->node.set_fetch_filter(std::move(hooks.fetch));
        m_link->node.connect(addr);
    }

    bool handshaked() const override { return m_link->node.is_handshake_complete(); }
    std::string subver() const override { return m_link->node.peer_subver(); }
    uint32_t start_height() const override { return m_link->node.peer_start_height(); }

    void send_getheaders(const std::vector<uint256>& locator, const uint256& stop) override
    {
        // 70016: the protocol version this driver's version message advertises.
        m_link->node.send_getheaders(70016, locator, stop);
    }

    bool relay_block(const std::vector<unsigned char>& block_bytes) override
    {
        return m_link->node.submit_block_raw(block_bytes);
    }

    void request_block(const uint256& hash) override { m_link->node.request_full_block(hash); }
};

} // namespace btc::coin
