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
                  const NetService& addr,
                  const std::string& chain_label = "CoinP2P")
        : key(peer_key)
        , config(prefix, addr)
        , node_p2p(ioc, &coin_node, &config, chain_label)
    {
    }
};

/// Multi-peer P2P broadcaster for one coin chain.
/// Manages discovery, connection lifecycle, and parallel block broadcast.
class CoinBroadcaster
{
public:
    /// Primary constructor. Takes an optional validated PeerEndpoint for the
    /// local daemon. If nullopt, runs in seed-only mode (peer discovery only).
    /// The type system enforces that an invalid/empty address can never be
    /// stored — std::optional<PeerEndpoint> is either valid or absent.
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    std::optional<PeerEndpoint> local_daemon,
                    const std::string& data_dir,
                    const PeerManagerConfig& pm_config)
        : m_ioc(ioc)
        , m_symbol(symbol)
        , m_prefix(prefix)
        , m_local_daemon(std::move(local_daemon))
        , m_peer_manager(ioc, symbol, data_dir, pm_config)
        , m_maintenance_timer(ioc)
    {
    }

    /// Convenience constructor: validates a raw NetService via PeerEndpoint::from().
    /// If validation fails, silently falls back to seed-only mode.
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    const NetService& local_daemon_addr,
                    const std::string& data_dir,
                    const PeerManagerConfig& pm_config)
        : CoinBroadcaster(ioc, symbol, prefix,
                          PeerEndpoint::from(local_daemon_addr),
                          data_dir, pm_config)
    {
        // Log if validation rejected the address
        if (!m_local_daemon && local_daemon_addr.port() > 0) {
            LOG_WARNING << "[" << symbol << "] Local daemon address rejected by validation: "
                       << local_daemon_addr.to_string()
                       << " — running in seed-only mode";
        }
    }

    /// Seed-only constructor (no local daemon).
    CoinBroadcaster(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::vector<std::byte>& prefix,
                    const std::string& data_dir,
                    const PeerManagerConfig& pm_config)
        : CoinBroadcaster(ioc, symbol, prefix,
                          std::optional<PeerEndpoint>{std::nullopt},
                          data_dir, pm_config)
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

    // Event callbacks — wired to every peer's coin_node events.
    // Initially just logging; later phases feed into HeaderChain / Mempool.
    using BlockCallback   = std::function<void(const std::string& peer, const uint256&)>;
    using TxCallback      = std::function<void(const std::string& peer, const ltc::coin::Transaction&)>;
    using HeadersCallback = std::function<void(const std::string& peer, const std::vector<ltc::coin::BlockHeaderType>&)>;

    using FullBlockCallback = std::function<void(const std::string& peer, const ltc::coin::BlockType&)>;

    void set_on_new_block(BlockCallback cb)     { m_on_new_block = std::move(cb); }
    void set_on_new_tx(TxCallback cb)           { m_on_new_tx = std::move(cb); }
    void set_on_new_headers(HeadersCallback cb)  { m_on_new_headers = std::move(cb); }
    void set_on_full_block(FullBlockCallback cb) { m_on_full_block = std::move(cb); }

    using PeerHeightCallback = std::function<void(uint32_t)>;
    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }

    // Set custom raw headers parser for AuxPoW chains (DOGE).
    // Applied to every new peer connection.
    using RawHeadersParser = std::function<std::vector<ltc::coin::BlockHeaderType>(const uint8_t*, size_t)>;
    void set_raw_headers_parser(RawHeadersParser p) { m_raw_headers_parser = std::move(p); }

    // Set custom raw block parser for AuxPoW chains (DOGE).
    // Applied to every new peer connection.
    using RawBlockParser = std::function<ltc::coin::BlockType(const uint8_t*, size_t)>;
    void set_raw_block_parser(RawBlockParser p) { m_raw_block_parser = std::move(p); }

    /// Enable BIP 35 mempool request for all current and future peer connections.
    /// Call after UTXO is initialized so incoming txs can have fees computed.
    void enable_mempool_request() {
        m_request_mempool = true;
        // Enable on all existing connected peers — but ONLY send mempool
        // to peers that advertise NODE_BLOOM. Peers without NODE_BLOOM
        // DISCONNECT us on mempool request (litecoind net_processing.cpp:3918).
        for (auto& [key, peer] : m_peers) {
            if (peer && peer->node_p2p.is_handshake_complete()) {
                peer->node_p2p.enable_mempool_request();
                if (peer->node_p2p.peer_has_bloom()) {
                    peer->node_p2p.send_mempool();
                    LOG_INFO << "[" << m_symbol << "] Sent BIP 35 mempool request to " << key;
                } else {
                    LOG_INFO << "[" << m_symbol << "] Skipped BIP 35 for " << key
                             << " — no NODE_BLOOM (svc=0x" << std::hex
                             << peer->node_p2p.peer_services() << std::dec << ")";
                }
            }
        }
    }

    /// Start: register local node (if any), start peer manager, begin connection loop.
    void start()
    {
        if (m_local_daemon) {
            LOG_INFO << "[" << m_symbol << "] CoinBroadcaster::start() — prefix="
                     << m_prefix.size() << " bytes, local_daemon=" << m_local_daemon->to_string()
                     << " (class=" << static_cast<int>(m_local_daemon->addr_class()) << ")"
                     << " discovery=" << m_peer_manager.discovery_enabled();
            // Protected local daemon node — always connected, never dropped.
            // set_local_node validates via PeerEndpoint internally.
            m_peer_manager.set_local_node(m_local_daemon->to_net_service());
        } else {
            LOG_INFO << "[" << m_symbol << "] CoinBroadcaster::start() — prefix="
                     << m_prefix.size() << " bytes, seed-only mode (no local daemon)"
                     << " discovery=" << m_peer_manager.discovery_enabled();
        }

        m_peer_manager.start();

        // Connect to local daemon immediately (if validated)
        if (m_local_daemon)
            connect_peer(*m_local_daemon);

        schedule_maintenance();
        if (m_local_daemon) {
            LOG_INFO << "[" << m_symbol << "] Multi-peer broadcaster started, local="
                     << m_local_daemon->to_string();
        } else {
            LOG_INFO << "[" << m_symbol << "] Multi-peer broadcaster started (seed-only, "
                     << m_peer_manager.peer_count() << " seed peers)";
        }
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
                LOG_WARNING << "[" << m_symbol << "] Raw block relay to " << key
                            << " FAILED: " << e.what();
            }
        }
        if (sent + failed == 0) {
            LOG_WARNING << "[" << m_symbol << "] Raw block broadcast: NO PEERS connected!"
                        << " Block (" << block_bytes.size() << " bytes) NOT relayed.";
        } else {
            LOG_INFO << "[" << m_symbol << "] Raw block broadcast to "
                     << sent << "/" << (sent + failed) << " peers ("
                     << block_bytes.size() << " bytes)";
        }
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

    /// Return per-peer info JSON array (daemon-style getpeerinfo).
    nlohmann::json get_peer_info() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& [key, peer] : m_peers) {
            arr.push_back({
                {"addr", key},
                {"version", peer->node_p2p.peer_version()},
                {"subver", peer->node_p2p.peer_subver()},
                {"services", peer->node_p2p.peer_services()},
                {"startingheight", peer->node_p2p.peer_start_height()},
                {"conntime", peer->node_p2p.peer_uptime_sec()},
                {"inbound", false},  // broadcaster only makes outbound connections
                {"connected", peer->node_p2p.peer_version() > 0}
            });
        }
        return arr;
    }

    const std::string& symbol() const { return m_symbol; }

    /// Request a full block (MSG_MWEB_BLOCK) from all peers via getdata.
    /// Used after a chain reorg to re-fetch MWEB state for the new tip.
    void request_full_block(const uint256& block_hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                peer->node_p2p.request_full_block(block_hash);
                ++sent;
            } catch (...) {}
        }
        if (sent > 0) {
            LOG_INFO << "[" << m_symbol << "] Full block requested from "
                     << sent << " peer(s): " << block_hash.GetHex().substr(0, 16) << "...";
        }
    }

    /// Request a full block from ONE specific peer (for bootstrap pipeline).
    /// Uses round-robin index: peer_idx % peer_count selects the target.
    /// Returns true if the request was sent, false if no peers available.
    bool request_full_block_targeted(const uint256& block_hash, size_t peer_idx)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_peers.empty()) return false;
        auto it = m_peers.begin();
        std::advance(it, peer_idx % m_peers.size());
        try {
            it->second->node_p2p.request_full_block(block_hash);
            return true;
        } catch (...) {
            return false;
        }
    }

    /// Number of connected peers (for bootstrap round-robin).
    size_t peer_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers.size();
    }

    /// Request a block via plain MSG_BLOCK (0x02) from all peers.
    /// Works for any block in the chain regardless of MWEB/witness support.
    void request_block_plain(const uint256& block_hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                peer->node_p2p.request_block(block_hash);
                ++sent;
            } catch (...) {}
        }
        if (sent > 0) {
            LOG_INFO << "[" << m_symbol << "] Block (MSG_BLOCK) requested from "
                     << sent << " peer(s): " << block_hash.GetHex().substr(0, 16) << "...";
        }
    }

    /// Send getheaders to all connected peers using the supplied block locator.
    /// Used by the embedded node to request initial header sync after seeding genesis.
    void request_headers(const std::vector<uint256>& locator, const uint256& stop_hash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int sent = 0;
        for (auto& [key, peer] : m_peers) {
            try {
                // DOGE uses protocol 70015, LTC uses 70017
                uint32_t proto = (m_symbol == "DOGE" || m_symbol == "doge") ? 70015 : 70017;
                peer->node_p2p.send_getheaders(proto, locator, stop_hash);
                ++sent;
            } catch (const std::exception& e) {
                LOG_WARNING << "[" << m_symbol << "] getheaders to "
                            << key << " failed: " << e.what();
            }
        }
        LOG_INFO << "[" << m_symbol << "] getheaders sent to " << sent << " peer(s)"
                 << " locator_size=" << locator.size()
                 << (locator.empty() ? "" : " tip=" + locator.front().GetHex().substr(0, 16) + "...");
    }

    CoinPeerManager& peer_manager() { return m_peer_manager; }

private:
    /// Connect to a validated peer endpoint. The PeerEndpoint type guarantees
    /// the address is non-empty, parseable, and has a valid port — no runtime
    /// checks needed. Wire protocol still uses NetService internally.
    void connect_peer(const PeerEndpoint& endpoint)
    {
        auto key = endpoint.to_string();
        auto addr = endpoint.to_net_service();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_peers.count(key)) {
                LOG_DEBUG_COIND << "[" << m_symbol << "] connect_peer: already connected to " << key;
                return;
            }

            LOG_INFO << "[" << m_symbol << "] Connecting to P2P peer: " << key;
            auto peer = std::make_unique<BroadcastPeer>(
                &m_ioc, key, m_prefix, addr, m_symbol);

            // Wire addr callback for peer discovery (disabled on isolated networks)
            bool should_discover = m_peer_manager.discovery_enabled();
            if (should_discover) {
                peer->node_p2p.set_addr_callback(
                    [this](const std::vector<NetService>& addrs) {
                        if (!m_peer_manager.discovery_enabled()) return;
                        for (auto& a : addrs) {
                            m_peer_manager.add_discovered_peer(a);
                        }
                    });
            }

            // Wire coin_node events so received P2P data feeds upward
            auto peer_key = key;
            peer->coin_node.new_block.subscribe(
                [this, peer_key](const uint256& hash) {
                    LOG_DEBUG_COIND << "[" << m_symbol << "] Peer " << peer_key
                                   << " announced block " << hash.GetHex();
                    if (m_on_new_block)
                        m_on_new_block(peer_key, hash);
                });
            peer->coin_node.new_tx.subscribe(
                [this, peer_key](const ltc::coin::Transaction& tx) {
                    if (m_on_new_tx)
                        m_on_new_tx(peer_key, tx);
                });
            peer->coin_node.new_headers.subscribe(
                [this, peer_key](const std::vector<ltc::coin::BlockHeaderType>& hdrs) {
                    LOG_DEBUG_COIND << "[" << m_symbol << "] Peer " << peer_key
                                   << " sent " << hdrs.size() << " headers";
                    if (m_on_new_headers)
                        m_on_new_headers(peer_key, hdrs);
                });
            peer->coin_node.full_block.subscribe(
                [this, peer_key](const ltc::coin::BlockType& block) {
                    if (m_on_full_block)
                        m_on_full_block(peer_key, block);
                });

            // Wire peer height callback (for fast-sync scrypt skip)
            if (m_on_peer_height) {
                peer->node_p2p.set_on_peer_height(
                    [this](uint32_t h) { m_on_peer_height(h); });
            }

            // Wire AuxPoW raw headers parser (DOGE)
            if (m_raw_headers_parser) {
                peer->node_p2p.set_raw_headers_parser(m_raw_headers_parser);
            }
            // Wire AuxPoW raw block parser (DOGE)
            if (m_raw_block_parser) {
                peer->node_p2p.set_raw_block_parser(m_raw_block_parser);
            }

            // BIP 35: enable mempool request if UTXO is ready
            if (m_request_mempool) {
                peer->node_p2p.enable_mempool_request();
            }

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
        LOG_INFO << "[" << m_symbol << "] Disconnecting P2P peer: " << key;
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
            schedule_maintenance();
            try {
                do_maintenance();
            } catch (const std::exception& e) {
                LOG_WARNING << "[" << m_symbol << "] Broadcaster maintenance error: " << e.what();
            }
        });
    }

    void do_maintenance()
    {
        // Isolated networks: skip all discovery/connection logic
        if (m_peer_manager.config().disable_discovery) return;

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
            LOG_WARNING << "[" << m_symbol << "] Emergency peer refresh triggered, connected=" << connected.size();
        }

        // Periodic status log (every 12 maintenance cycles = 60s)
        static int s_maint_count = 0;
        if (++s_maint_count % 12 == 0) {
            LOG_INFO << "[" << m_symbol << "] Broadcaster status: connected=" << connected.size()
                     << " to_connect=" << to_connect.size();
        }
    }

    boost::asio::io_context& m_ioc;
    std::string m_symbol;
    std::vector<std::byte> m_prefix;
    std::optional<PeerEndpoint> m_local_daemon;  // nullopt = seed-only mode
    CoinPeerManager m_peer_manager;
    boost::asio::steady_timer m_maintenance_timer;

    mutable std::mutex m_mutex;
    std::map<std::string, std::unique_ptr<BroadcastPeer>> m_peers;
    bool m_running{true};

    BlockCallback        m_on_new_block;
    TxCallback           m_on_new_tx;
    HeadersCallback      m_on_new_headers;
    FullBlockCallback    m_on_full_block;
    PeerHeightCallback   m_on_peer_height;
    RawHeadersParser     m_raw_headers_parser;
    RawBlockParser       m_raw_block_parser;
    bool                 m_request_mempool{false};  // BIP 35 mempool sync
};

} // namespace merged
} // namespace c2pool
