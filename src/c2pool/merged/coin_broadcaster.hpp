#pragma once

/// Lightweight P2P broadcaster for any Bitcoin-derived coin daemon.
/// Connects to a single daemon, performs version handshake, and can
/// relay blocks via the P2P "block" message for fast propagation.
/// Used for both parent chain and merged chain block relay.

#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/coin/node_interface.hpp>

namespace c2pool {
namespace merged {

/// Minimal config adapter that satisfies NodeP2P<Config>'s coin()->m_p2p
/// requirements without pulling in the full ltc::Config template.
class BroadcasterConfig
{
public:
    struct CoinPart {
        ltc::config::P2PData m_p2p;
        ltc::config::RPCData m_rpc;  // unused, but keeps interface uniform
    };

    BroadcasterConfig(const std::vector<std::byte>& prefix, const NetService& addr)
    {
        m_coin.m_p2p.prefix = prefix;
        m_coin.m_p2p.address = addr;
    }

    CoinPart* coin() { return &m_coin; }
    const CoinPart* coin() const { return &m_coin; }

private:
    CoinPart m_coin;
};

/// Wraps a NodeP2P<BroadcasterConfig> for a single chain's P2P block relay.
class CoinBroadcaster
{
public:
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    const NetService& addr)
        : m_symbol(symbol)
        , m_config(prefix, addr)
        , m_node_p2p(&ioc, &m_coin_node, &m_config)
    {
    }

    /// Initiate async TCP connection + version handshake.
    void start()
    {
        auto addr = m_config.coin()->m_p2p.address;
        LOG_INFO << "[" << m_symbol << "] P2P broadcaster connecting to " << addr.to_string();
        m_node_p2p.connect(addr);
    }

    /// Send a block over P2P for fast relay.
    void submit_block(ltc::coin::BlockType& block)
    {
        m_node_p2p.submit_block(block);
    }

    const std::string& symbol() const { return m_symbol; }

private:
    std::string m_symbol;
    BroadcasterConfig m_config;
    ltc::interfaces::Node m_coin_node;  // event sink (unused signals are fine)
    ltc::coin::p2p::NodeP2P<BroadcasterConfig> m_node_p2p;
};

} // namespace merged
} // namespace c2pool
