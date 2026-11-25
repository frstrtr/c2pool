// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::NodeP2PPoolPeer -- one CoinPeerPool connection over the BTC
// coin P2P driver (p2p::NodeP2P). Each connection has its own event sink, so
// the pool knows which peer sent a headers message, an announcement or a
// block body.
//
// Lifetime: the driver is owned by a shared_ptr constructed from the raw
// pointer, so its enable_shared_from_this (core::INetwork) is set. The
// sockets it creates (core::make_socket) then hold a weak reference to it and
// every read / write completion locks that reference first: a connection
// dropped while a write is in flight aborts the socket instead of calling
// into a freed driver. The same shared_ptr is the dial-lifetime handle
// (set_lifetime). The event sink lives in the deleter, so it outlives the
// driver that points at it.

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
public:
    using Driver = p2p::NodeP2P<ConfigT>;

    /// label: the driver's log label ("" = "CoinP2P <addr>").
    NodeP2PPoolPeer(boost::asio::io_context* ioc, ConfigT* config, const NetService& addr,
                    PoolPeerHooks hooks, const std::string& label = std::string())
    {
        auto sink = std::make_shared<btc::interfaces::Node>();
        const std::string lbl = label.empty() ? "CoinP2P " + addr.to_string() : label;
        m_node = std::shared_ptr<Driver>(new Driver(ioc, sink.get(), config, lbl),
                                         [sink](Driver* p) { delete p; });
        m_node->set_lifetime(m_node);
        assert(m_node->lifetime_armed() && "pooled coin-P2P dial lifetime failed to arm");
        assert(lifetime_managed() && "pooled coin-P2P driver is not shared_ptr-managed");

        if (hooks.headers)
            sink->new_headers.subscribe(
                [f = hooks.headers](const std::vector<BlockHeaderType>& h) { f(h); });
        if (hooks.block_announced)
            sink->new_block.subscribe([f = hooks.block_announced](const uint256& h) { f(h); });
        if (hooks.tx)
            sink->new_tx.subscribe([f = hooks.tx](const Transaction& tx) { f(tx); });
        if (hooks.full_block)
            sink->full_block.subscribe([f = hooks.full_block](const BlockType& b) { f(b); });
        if (hooks.headers_message)
            m_node->set_on_headers_message(std::move(hooks.headers_message));
        if (hooks.fetch)
            m_node->set_fetch_filter(std::move(hooks.fetch));
        m_node->connect(addr);
    }

    /// The driver's enable_shared_from_this is set: the sockets it makes
    /// track its lifetime (core::make_socket was_managed).
    bool lifetime_managed() const
    {
        const core::INetwork* net = m_node.get();
        return net && net->weak_from_this().lock() != nullptr;
    }

    const std::string& label() const { return m_node->chain_label(); }

    bool handshaked() const override { return m_node->is_handshake_complete(); }
    std::string subver() const override { return m_node->peer_subver(); }
    uint32_t start_height() const override { return m_node->peer_start_height(); }

    void send_getheaders(const std::vector<uint256>& locator, const uint256& stop) override
    {
        // 70016: the protocol version this driver's version message advertises.
        m_node->send_getheaders(70016, locator, stop);
    }

    bool relay_block(const std::vector<unsigned char>& block_bytes) override
    {
        return m_node->submit_block_raw(block_bytes);
    }

    void request_block(const uint256& hash) override { m_node->request_full_block(hash); }
    void request_tx(const uint256& txid) override { m_node->request_tx(txid); }

private:
    std::shared_ptr<Driver> m_node;
};

} // namespace btc::coin
