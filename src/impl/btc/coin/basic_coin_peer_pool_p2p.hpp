// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// btc::coin::BasicNodeP2PPoolPeer -- one BasicCoinPeerPool connection over a
// coin P2P driver (DriverT<ConfigT>: the coin's p2p::NodeP2P) with its own
// event sink (Sink: the coin's interfaces::Node), so the pool knows which peer
// sent a headers message, an announcement or a block body. coin_peer_pool_p2p.hpp
// instantiates it for c2pool-btc, impl/bip110/coin/coin_peer_pool_p2p.hpp for
// c2pool-bip110.
//
// Lifetime: the driver is owned by a shared_ptr constructed from the raw
// pointer, so its enable_shared_from_this (core::INetwork) is set. The
// sockets it creates (core::make_socket) then hold a weak reference to it and
// every read / write completion locks that reference first: a connection
// dropped while a write is in flight aborts the socket instead of calling
// into a freed driver. The same shared_ptr is the dial-lifetime handle
// (set_lifetime). The event sink lives in the deleter, so it outlives the
// driver that points at it.
//
// The driver API it uses: set_lifetime / lifetime_armed, set_on_headers_message,
// set_fetch_filter, connect, chain_label, is_handshake_complete, peer_subver,
// peer_start_height, send_getheaders, submit_block_raw, request_full_block and
// request_tx(txid) (and request_tx(std::vector<uint256>) if it has one: one
// getdata for request_txs); the sink's new_headers / new_block / new_tx /
// full_block events.

#include "basic_coin_peer_pool.hpp"

#include <core/inetwork.hpp>
#include <core/netaddress.hpp>

#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace btc::coin {

template <typename Coin, typename ConfigT, template <typename> class DriverT, typename Sink>
class BasicNodeP2PPoolPeer final : public PoolPeer {
public:
    using Driver          = DriverT<ConfigT>;
    using BlockHeaderType = typename Coin::Header;
    using BlockType       = typename Coin::Block;
    using Transaction     = typename Coin::Tx;
    /// Applied to the driver after the pool's hooks and before it dials
    /// (optional).
    using Configure       = std::function<void(Driver&)>;

    /// label: the driver's log label ("" = "CoinP2P <addr>").
    BasicNodeP2PPoolPeer(boost::asio::io_context* ioc, ConfigT* config, const NetService& addr,
                         BasicPoolPeerHooks<Coin> hooks, const std::string& label = std::string(),
                         const Configure& configure = Configure())
    {
        auto sink = std::make_shared<Sink>();
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
        if (configure)
            configure(*m_node);
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

    /// The driver (tests, diagnostics).
    const Driver& driver() const { return *m_node; }

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

    /// One getdata for all of them where the driver takes a list
    /// (request_tx(std::vector<uint256>)); else one request_tx each.
    void request_txs(const std::vector<uint256>& txids) override
    {
        if constexpr (requires(Driver& d, const std::vector<uint256>& v) { d.request_tx(v); })
            m_node->request_tx(txids);
        else
            PoolPeer::request_txs(txids);
    }

private:
    std::shared_ptr<Driver> m_node;
};

} // namespace btc::coin
