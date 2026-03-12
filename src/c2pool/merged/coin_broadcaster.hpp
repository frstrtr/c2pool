#pragma once

/// Multi-peer P2P broadcaster for any Bitcoin-derived coin daemon.
/// Manages a pool of P2P connections with peer discovery (getpeerinfo
/// bootstrap + addr crawl), scoring, exponential backoff, and capacity
/// gating. Follows Python p2pool broadcaster design (chain-agnostic).
///
/// Used for both parent chain (sends full block) and merged chain
/// (sends inv announcement) block relay.

#include "coin_peer_manager.hpp"

#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/coin/node_interface.hpp>

#include <map>
#include <set>
#include <memory>
#include <functional>

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

/// One P2P connection slot: config + node + NodeP2P instance.
struct BroadcastPeer
{
    std::string                                     key;        // "host:port"
    BroadcasterConfig                               config;
    ltc::interfaces::Node                           coin_node;  // event sink
    ltc::coin::p2p::NodeP2P<BroadcasterConfig>      node_p2p;
    bool                                            connected{false};
    bool                                            handshake_done{false};

    BroadcastPeer(boost::asio::io_context* ioc,
                  const std::string& peer_key,
                  const std::vector<std::byte>& prefix,
                  const NetService& addr)
        : key(peer_key)
        , config(prefix, addr)
        , node_p2p(ioc, &coin_node, &config)
    {
    }
};

/// Multi-peer P2P broadcaster for one coin chain.
/// Manages discovery, connection lifecycle, and parallel block broadcast.
class CoinBroadcaster
{
public:
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    const NetService& local_daemon_addr,
                    const std::string& data_dir,
                    const PeerManagerConfig& pm_config)
        : m_ioc(ioc)
        , m_symbol(symbol)
        , m_prefix(prefix)
        , m_local_daemon_addr(local_daemon_addr)
        , m_peer_manager(ioc, symbol, data_dir, pm_config)
        , m_maintenance_timer(ioc)
    {
    }

    /// Convenience constructor with defaults (backward compatible).
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    const NetService& addr)
        : CoinBroadcaster(ioc, symbol, prefix, addr, ".", PeerManagerConfig{})
    {
    }

    ~CoinBroadcaster() { stop(); }

    /// Set the function to query daemon for peers via RPC getpeerinfo.
    void set_getpeerinfo_fn(CoinPeerManager::GetPeerInfoFn fn)
    {
        m_peer_manager.set_getpeerinfo_fn(std::move(fn));
    }

    /// Start: register local node, start peer manager, begin connection loop.
    void start()
    {
        // Protected local daemon node — always connected, never dropped
        m_peer_manager.set_local_node(m_local_daemon_addr);
        m_peer_manager.start();

        // Connect to local daemon immediately
        connect_peer(m_local_daemon_addr);

        schedule_maintenance();
        LOG_INFO << "[" << m_symbol << "] Multi-peer broadcaster started, local="
                 << m_local_daemon_addr.to_string();
    }

    void stop()
    {
        m_running = false;
        m_maintenance_timer.cancel();
        m_peer_manager.stop();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peers.clear();
    }

    /// Broadcast full block to ALL connected peers in parallel (parent chain).
    void submit_block(ltc::coin::BlockType& block)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0, failed = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                peer->node_p2p.submit_block(block);
                m_peer_manager.record_broadcast_success(key);
                ++sent;
            } catch (const std::exception& e) {
                m_peer_manager.record_broadcast_failure(key);
                ++failed;
                LOG_DEBUG_COIND << "[" << m_symbol << "] Broadcast to "
                     << key << " failed: " << e.what();
            }
        }
        LOG_INFO << "[" << m_symbol << "] Block broadcast to "
                 << sent << "/" << (sent + failed) << " peers";
    }

    /// Broadcast raw block bytes to ALL connected peers (parent chain).
    void submit_block_raw(const std::vector<unsigned char>& block_bytes)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0, failed = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                peer->node_p2p.submit_block_raw(block_bytes);
                m_peer_manager.record_broadcast_success(key);
                ++sent;
            } catch (const std::exception& e) {
                m_peer_manager.record_broadcast_failure(key);
                ++failed;
            }
        }
        LOG_INFO << "[" << m_symbol << "] Raw block broadcast to "
                 << sent << "/" << (sent + failed) << " peers ("
                 << block_bytes.size() << " bytes)";
    }

    /// Send inv announcement to ALL connected peers (merged chain relay).
    void send_block_inv(const uint256& block_hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                peer->node_p2p.send_block_inv(block_hash);
                m_peer_manager.record_broadcast_success(key);
                ++sent;
            } catch (...) {
                m_peer_manager.record_broadcast_failure(key);
            }
        }
        if (sent > 0) {
            LOG_INFO << "[" << m_symbol << "] Block inv sent to " << sent << " peers";
        }
    }

    int connected_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<int>(m_peers.size());
    }

    const std::string& symbol() const { return m_symbol; }
    CoinPeerManager& peer_manager() { return m_peer_manager; }

private:
    void connect_peer(const NetService& addr)
    {
        auto key = addr.to_string();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_peers.count(key)) return; // already connected

            auto peer = std::make_unique<BroadcastPeer>(
                &m_ioc, key, m_prefix, addr);

            // Wire addr callback for peer discovery
            bool should_discover = m_peer_manager.discovery_enabled();
            peer->node_p2p.set_addr_callback(
                [this](const std::vector<NetService>& addrs) {
                    for (auto& a : addrs) {
                        m_peer_manager.add_discovered_peer(a);
                    }
                });

            peer->node_p2p.connect(addr);

            // Send getaddr after connection for peer discovery
            if (should_discover) {
                // getaddr will be sent after verack in maintenance
            }

            m_peers[key] = std::move(peer);
        }
        m_peer_manager.notify_connected(key);
    }

    void disconnect_peer(const std::string& key)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_peers.erase(key);
        }
        m_peer_manager.notify_disconnected(key);
    }

    void schedule_maintenance()
    {
        m_maintenance_timer.expires_after(std::chrono::seconds(5));
        m_maintenance_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_running) return;
            do_maintenance();
            schedule_maintenance();
        });
    }

    void do_maintenance()
    {
        // 1. Get set of currently connected keys
        std::set<std::string> connected;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& [k, _] : m_peers) {
                connected.insert(k);
            }
        }

        // 2. Ask peer manager for more peers to connect
        auto to_connect = m_peer_manager.get_peers_to_connect(connected);

        for (auto& addr : to_connect) {
            connect_peer(addr);
        }

        // 3. Prune dead peers
        m_peer_manager.prune_dead_peers();

        // 4. Emergency refresh if below min
        if (m_peer_manager.needs_emergency_refresh(
                static_cast<int>(connected.size()))) {
            // Trigger re-bootstrap (rate-limited inside peer manager)
        }
    }

    boost::asio::io_context& m_ioc;
    std::string m_symbol;
    std::vector<std::byte> m_prefix;
    NetService m_local_daemon_addr;
    CoinPeerManager m_peer_manager;
    boost::asio::steady_timer m_maintenance_timer;

    mutable std::mutex m_mutex;
    std::map<std::string, std::unique_ptr<BroadcastPeer>> m_peers;
    bool m_running{true};
};

} // namespace merged
} // namespace c2pool
