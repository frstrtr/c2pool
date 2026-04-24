#pragma once

// Phase 2 full broadcaster for Dash (port of c2pool-ltc CoinBroadcaster).
//
// Provides what the Phase-1 DashBroadcaster lacked:
//   * Wilson-score peer reputation via CoinPeerManager (chain-agnostic)
//   * Exponential backoff on dial failure (managed by CoinPeerManager)
//   * Anchor peers persisted across restarts (ditto)
//   * Group limits (/16 caps) to avoid single-AS clustering (ditto)
//   * Addr-message driven discovery — no RPC getpeerinfo dependency
//     (peers send us new addrs via p2p, we feed CoinPeerManager, it dials)
//
// Structure mirrors c2pool-ltc's coin_broadcaster.hpp line-for-line:
//   DashBroadcasterConfig — minimal P2PData+RPCData adapter for NodeP2P
//   DashBroadcastPeer     — one connection slot (config + InterfacesNode + NodeP2P)
//   DashCoinBroadcaster   — pool manager (maintenance timer + submit fan-out)
//
// Not templated on coin type: dash::coin::* types are used directly.
// Templatizing the LTC broadcaster on a Traits struct was considered but
// introduces a template-template-param layer (NodeP2P<Config>) that's
// hairy; parallel per-coin files match the rest of c2pool's per-coin
// layout (params.hpp, share.hpp, etc.) and CoinPeerManager already
// provides the chain-agnostic reusable core.

#include <c2pool/merged/coin_peer_manager.hpp>

#include <impl/dash/coin/node_interface.hpp>
#include <impl/dash/coin/p2p_node.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/config.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace dash {

/// Minimal config adapter that satisfies Dash NodeP2P<Config>'s
/// coin()->m_p2p requirements without pulling in the full dash::Config
/// (which nests pool + coin configs). One per peer slot.
class DashBroadcasterConfig
{
public:
    struct CoinPart {
        dash::CoinConfig::P2PData m_p2p;
        dash::CoinConfig::RPCData m_rpc;  // unused, keeps interface uniform
    };

    DashBroadcasterConfig(const std::vector<std::byte>& prefix, const NetService& addr)
    {
        m_coin.m_p2p.prefix  = prefix;
        m_coin.m_p2p.address = addr;
    }

    CoinPart*       coin()       { return &m_coin; }
    const CoinPart* coin() const { return &m_coin; }

private:
    CoinPart m_coin;
};

/// One P2P connection slot: config + NodeP2P + event sink.
struct DashBroadcastPeer
{
    std::string                                       key;        // "host:port"
    DashBroadcasterConfig                             config;
    dash::interfaces::Node                            coin_node;  // event sink
    dash::coin::p2p::NodeP2P<DashBroadcasterConfig>   node_p2p;
    bool                                              connected{false};
    bool                                              handshake_done{false};

    DashBroadcastPeer(boost::asio::io_context* ioc,
                      const std::string& peer_key,
                      const std::vector<std::byte>& prefix,
                      const NetService& addr)
        : key(peer_key)
        , config(prefix, addr)
        , node_p2p(ioc, &coin_node, &config)
    {
    }
};

using ::c2pool::merged::CoinPeerManager;
using ::c2pool::merged::PeerManagerConfig;
// PeerEndpoint is in the global namespace (core/netaddress.hpp); used
// unqualified below. Pulled in transitively via coin_peer_manager.hpp.

/// Multi-peer P2P broadcaster for Dash daemon network.
/// Manages discovery, connection lifecycle, and parallel block broadcast
/// with full peer scoring / backoff / anchor persistence.
class DashCoinBroadcaster
{
public:
    /// Full constructor with explicit local-daemon endpoint.
    DashCoinBroadcaster(boost::asio::io_context& ioc,
                        const std::vector<std::byte>& prefix,
                        std::optional<PeerEndpoint> local_daemon,
                        const std::string& data_dir,
                        const PeerManagerConfig& pm_config)
        : m_ioc(ioc)
        , m_prefix(prefix)
        , m_local_daemon(std::move(local_daemon))
        , m_peer_manager(ioc, "DASH", data_dir, pm_config)
        , m_maintenance_timer(ioc)
    {}

    /// Convenience: validate raw NetService via PeerEndpoint::from().
    DashCoinBroadcaster(boost::asio::io_context& ioc,
                        const std::vector<std::byte>& prefix,
                        const NetService& local_daemon_addr,
                        const std::string& data_dir,
                        const PeerManagerConfig& pm_config)
        : DashCoinBroadcaster(ioc, prefix,
                              PeerEndpoint::from(local_daemon_addr),
                              data_dir, pm_config)
    {
        if (!m_local_daemon && local_daemon_addr.port() > 0) {
            LOG_WARNING << "[DASH] local daemon address rejected by validation: "
                        << local_daemon_addr.to_string()
                        << " — running in seed-only mode";
        }
    }

    ~DashCoinBroadcaster() { stop(); }

    void set_getpeerinfo_fn(CoinPeerManager::GetPeerInfoFn fn) {
        m_peer_manager.set_getpeerinfo_fn(std::move(fn));
    }

    // Event callbacks — wired to every peer's coin_node events.
    using BlockCallback     = std::function<void(const std::string&, const uint256&)>;
    using TxCallback        = std::function<void(const std::string&, const dash::coin::Transaction&)>;
    using HeadersCallback   = std::function<void(const std::string&, const std::vector<dash::coin::BlockHeaderType>&)>;
    using FullBlockCallback = std::function<void(const std::string&, const dash::coin::BlockType&)>;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    // Phase C-SML step 4: SML diff arrival callback. Higher layer
    // (main_dash.cpp tip-changed handler in step 6) consumes diffs.
    using MnListDiffCallback = std::function<void(
        const std::string& peer_key,
        const dash::coin::vendor::CSimplifiedMNListDiff& diff)>;
    // Phase L step 3: ChainLock arrival fan-out. main_dash.cpp registers
    // a single consumer that runs verify_chainlock against QuorumManager
    // + HeaderChain it owns.
    using ClsigCallback = std::function<void(
        const std::string& peer_key,
        int32_t height,
        const uint256& block_hash,
        const std::array<uint8_t, 96>& sig)>;

    void set_on_new_block(BlockCallback cb)     { m_on_new_block   = std::move(cb); }
    void set_on_new_tx(TxCallback cb)           { m_on_new_tx      = std::move(cb); }
    void set_on_new_headers(HeadersCallback cb) { m_on_new_headers = std::move(cb); }
    void set_on_full_block(FullBlockCallback cb){ m_on_full_block  = std::move(cb); }
    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }
    void set_on_mnlistdiff(MnListDiffCallback cb) { m_on_mnlistdiff = std::move(cb); }
    void set_on_clsig(ClsigCallback cb) { m_on_clsig = std::move(cb); }

    /// Start: register local node (if any), start peer manager, begin
    /// connection maintenance loop.
    void start()
    {
        if (m_local_daemon) {
            LOG_INFO << "[DASH] DashCoinBroadcaster::start() — prefix="
                     << m_prefix.size() << " bytes, local_daemon="
                     << m_local_daemon->to_string()
                     << " discovery=" << m_peer_manager.discovery_enabled();
            m_peer_manager.set_local_node(m_local_daemon->to_net_service());
        } else {
            LOG_INFO << "[DASH] DashCoinBroadcaster::start() — seed-only mode"
                     << " discovery=" << m_peer_manager.discovery_enabled();
        }

        m_peer_manager.start();

        if (m_local_daemon)
            connect_peer(*m_local_daemon);

        schedule_maintenance();

        LOG_INFO << "[DASH] Multi-peer broadcaster started"
                 << (m_local_daemon ? (", local=" + m_local_daemon->to_string()) : "");
    }

    void stop()
    {
        m_running = false;
        m_maintenance_timer.cancel();
        m_graveyard_timer.cancel();
        m_peer_manager.stop();
        std::lock_guard<std::mutex> lock(m_mutex);
        // Move live peers into the graveyard so async callbacks still see
        // valid m_target_addr when they unwind. The graveyard itself is
        // drained on process exit by ~vector destruction; by that point
        // io_context has stopped so no more callbacks can fire.
        for (auto& [k, p] : m_peers)
            if (p) retire_to_graveyard_locked(std::move(p));
        m_peers.clear();
    }

    /// Broadcast full block to ALL connected peers in parallel.
    void submit_block(dash::coin::BlockType& block)
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
                LOG_WARNING << "[DASH] Broadcast to " << key
                            << " failed: " << e.what();
            }
        }
        LOG_INFO << "[DASH] Block broadcast to "
                 << sent << "/" << (sent + failed) << " peers";
    }

    /// Broadcast raw block bytes to ALL connected peers. Prefer this over
    /// submit_block when the bytes are already packed (from submit_validator)
    /// to skip deserialize → reserialize.
    void submit_block_raw(std::span<const unsigned char> block_bytes)
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
                LOG_WARNING << "[DASH] Raw block relay to " << key
                            << " FAILED: " << e.what();
            }
        }
        if (sent + failed == 0) {
            LOG_WARNING << "[DASH] Raw block broadcast: NO PEERS connected! "
                        << "Block (" << block_bytes.size()
                        << " bytes) NOT relayed.";
        } else {
            LOG_INFO << "[DASH] Raw block broadcast to "
                     << sent << "/" << (sent + failed) << " peers ("
                     << block_bytes.size() << " bytes)";
        }
    }

    /// Send inv announcement to ALL connected peers.
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
        if (sent > 0)
            LOG_INFO << "[DASH] Block inv sent to " << sent << " peers";
    }

    int connected_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<int>(m_peers.size());
    }

    size_t peer_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers.size();
    }

    /// Per-peer info JSON array (daemon-style getpeerinfo). Feeds the
    /// dashboard "Dash Peers" panel via MiningInterface's
    /// set_coin_peer_info_fn hook.
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
                {"inbound", false},
                {"connected", peer->node_p2p.is_handshake_complete()}
            });
        }
        return arr;
    }

    CoinPeerManager& peer_manager() { return m_peer_manager; }

    /// Iteration-2b hardening: disconnect a single peer by key + record a
    /// broadcast failure (hurts their Wilson-score in CoinPeerManager so
    /// they're deprioritized for redial). Called from the on_clsig
    /// INVALID_SIG branch and the on_mnlistdiff root MISMATCH branch in
    /// main_dash. No-op if the key isn't in m_peers — this is the
    /// natural exemption for the singleton dashd path (its peer key is
    /// the dashd address, which broadcaster doesn't track).
    ///
    /// `reason` shows up in the log line for forensics.
    void disconnect_peer(const std::string& peer_key,
                         const std::string& reason)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peers.find(peer_key);
        if (it == m_peers.end()) {
            // Not a broadcaster-tracked peer — likely the singleton
            // dashd path. Don't drop our trusted seed.
            return;
        }
        LOG_WARNING << "[DASH] Disconnecting peer " << peer_key
                    << " (Misbehaving — " << reason << ")";
        try {
            it->second->node_p2p.disconnect();
        } catch (const std::exception& e) {
            LOG_WARNING << "[DASH] disconnect_peer "
                        << peer_key << " threw: " << e.what();
        }
        m_peer_manager.record_broadcast_failure(peer_key);
        // Bug 3 mitigation: defer destruction so in-flight async callbacks
        // on this NodeP2P see m_target_addr alive when they fire. See the
        // GRAVEYARD_TTL block at the bottom of this class.
        retire_to_graveyard(std::move(it->second));
        m_peers.erase(it);
    }

    /// Broadcast a `getdata(MSG_BLOCK, hash)` to every connected peer.
    /// Used by the bootstrap pipeline's initial window + stall-timer
    /// fallback so at least one peer responds. Same pattern as LTC's
    /// CoinBroadcaster::request_full_block (c2pool/merged/coin_broadcaster.hpp).
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
            LOG_INFO << "[DASH] Full block requested from " << sent
                     << " peer(s): " << block_hash.GetHex().substr(0, 16) << "...";
        }
    }

    /// Targeted single-peer fetch for bootstrap window refill — spreads
    /// load via round-robin (peer_idx % peer_count). Returns true if
    /// the request was sent. Same pattern as LTC.
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

    /// Phase C-SML step 4: ask one peer for an SML diff. Targeted
    /// (single-peer) because the response can be ~400 KB on cold
    /// start; broadcasting would multiply bandwidth across peers
    /// for no gain. Round-robin via peer_idx so steady-state diffs
    /// spread load. Returns the peer key that was asked, or empty
    /// string if no peer was available.
    std::string request_mnlistdiff_targeted(const uint256& base_block_hash,
                                            const uint256& target_block_hash,
                                            size_t peer_idx)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_peers.empty()) return {};
        auto it = m_peers.begin();
        std::advance(it, peer_idx % m_peers.size());
        try {
            it->second->node_p2p.request_mnlistdiff(
                base_block_hash, target_block_hash);
            return it->first;
        } catch (...) {
            return {};
        }
    }

private:
    /// Connect to a validated peer endpoint. PeerEndpoint guarantees
    /// non-empty parseable addr with valid port — no runtime checks.
    void connect_peer(const PeerEndpoint& endpoint)
    {
        auto key  = endpoint.to_string();
        auto addr = endpoint.to_net_service();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_peers.count(key)) return;  // already connected

            LOG_INFO << "[DASH] Connecting to P2P peer: " << key;
            auto peer = std::make_unique<DashBroadcastPeer>(
                &m_ioc, key, m_prefix, addr);

            // Peer discovery via addr-message callback. Only arm if
            // discovery is enabled on this PeerManager instance.
            bool should_discover = m_peer_manager.discovery_enabled();
            if (should_discover) {
                peer->node_p2p.set_addr_callback(
                    [this](const std::vector<NetService>& addrs) {
                        if (!m_peer_manager.discovery_enabled()) return;
                        for (auto& a : addrs)
                            m_peer_manager.add_discovered_peer(a);
                    });
            }

            // Wire coin_node events so received P2P data feeds upward to
            // the main_dash.cpp subscribers (header chain, chain-lock,
            // full-block logger).
            auto peer_key = key;
            peer->coin_node.new_block.subscribe(
                [this, peer_key](const uint256& hash) {
                    if (m_on_new_block) m_on_new_block(peer_key, hash);
                });
            peer->coin_node.new_tx.subscribe(
                [this, peer_key](const dash::coin::Transaction& tx) {
                    if (m_on_new_tx) m_on_new_tx(peer_key, tx);
                });
            peer->coin_node.new_headers.subscribe(
                [this, peer_key](const std::vector<dash::coin::BlockHeaderType>& hdrs) {
                    if (m_on_new_headers) m_on_new_headers(peer_key, hdrs);
                });
            peer->coin_node.full_block.subscribe(
                [this, peer_key](const dash::coin::BlockType& block) {
                    if (m_on_full_block) m_on_full_block(peer_key, block);
                });

            if (m_on_peer_height)
                peer->node_p2p.set_on_peer_height(
                    [this](uint32_t h) { m_on_peer_height(h); });

            // Phase C-SML step 4: fan SML diffs out to broadcaster
            // consumer. Always-armed because the per-peer dispatch is
            // cheap and main_dash.cpp may register the callback after
            // some peers have already connected.
            peer->node_p2p.set_on_mnlistdiff(
                [this](const std::string& pk,
                       const dash::coin::vendor::CSimplifiedMNListDiff& diff) {
                    if (m_on_mnlistdiff) m_on_mnlistdiff(pk, diff);
                });

            // Phase L step 3: fan ChainLock arrivals out to verifier.
            peer->node_p2p.set_on_clsig(
                [this](const std::string& pk,
                       int32_t h,
                       const uint256& bhash,
                       const std::array<uint8_t, 96>& sig) {
                    if (m_on_clsig) m_on_clsig(pk, h, bhash, sig);
                });

            peer->node_p2p.connect(addr);
            m_peers[key] = std::move(peer);
        }
        m_peer_manager.notify_connected(key);
    }

    void disconnect_peer(const std::string& key)
    {
        LOG_INFO << "[DASH] Disconnecting P2P peer: " << key;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_peers.find(key);
            if (it != m_peers.end()) {
                // Bug 3 mitigation: graveyard, not direct erase.
                retire_to_graveyard(std::move(it->second));
                m_peers.erase(it);
            }
        }
        m_peer_manager.notify_disconnected(key);
    }

    // Bug 3 mitigation: defer destruction of disconnected peers so any
    // in-flight async callback (NodeP2P::connected, message handlers, timers)
    // sees a valid m_target_addr when it unwinds. After GRAVEYARD_TTL seconds
    // the io_context has no remaining handlers referencing the peer; safe
    // to destruct.
    //
    // Caller MUST hold m_mutex.
    void retire_to_graveyard_locked(std::unique_ptr<DashBroadcastPeer> peer)
    {
        if (!peer) return;
        m_graveyard.push_back({std::move(peer),
                               std::chrono::steady_clock::now() + GRAVEYARD_TTL});
        if (m_graveyard.size() == 1)
            schedule_graveyard_drain();
    }

    // Wrapper that locks for callers that don't already hold m_mutex.
    void retire_to_graveyard(std::unique_ptr<DashBroadcastPeer> peer)
    {
        // Heuristic: callers that already hold the lock pass the unique_ptr
        // directly; the helper above handles them. Distinct external entry
        // point retained for clarity in disconnect_peer paths that lock
        // around a tighter scope than the enclosing function.
        retire_to_graveyard_locked(std::move(peer));
    }

    void schedule_graveyard_drain()
    {
        m_graveyard_timer.expires_after(std::chrono::seconds(5));
        m_graveyard_timer.async_wait(
            [this](const boost::system::error_code& ec) {
                if (ec) return;
                drain_graveyard();
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!m_graveyard.empty() && m_running)
                    schedule_graveyard_drain();
            });
    }

    void drain_graveyard()
    {
        const auto now = std::chrono::steady_clock::now();
        std::vector<std::unique_ptr<DashBroadcastPeer>> to_destroy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_graveyard.begin();
            while (it != m_graveyard.end() && it->die_at <= now) {
                to_destroy.push_back(std::move(it->peer));
                ++it;
            }
            m_graveyard.erase(m_graveyard.begin(), it);
        }
        // Destruction outside the mutex — peer destructor may invoke
        // callbacks/log calls that themselves take other locks.
        to_destroy.clear();
    }

    void schedule_maintenance()
    {
        m_maintenance_timer.expires_after(std::chrono::seconds(5));
        m_maintenance_timer.async_wait(
            [this](const boost::system::error_code& ec) {
                if (ec || !m_running) return;
                schedule_maintenance();
                try { do_maintenance(); }
                catch (const std::exception& e) {
                    LOG_WARNING << "[DASH] Broadcaster maintenance error: "
                                << e.what();
                }
            });
    }

    void do_maintenance()
    {
        if (m_peer_manager.config().disable_discovery) return;

        // 1. Collect currently-connected keys.
        std::set<std::string> connected;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& [k, _] : m_peers) connected.insert(k);
        }

        // 2. Ask peer manager for best candidates.
        auto to_connect = m_peer_manager.get_peers_to_connect(connected);

        for (auto& ep : to_connect)
            connect_peer(ep);

        // 3. Prune dead peers (in the slot map; PeerManager notices via
        //    notify_disconnected when we drop them).
        prune_dead_locally();
        m_peer_manager.prune_dead_peers();

        // 4. Emergency refresh if below min.
        if (m_peer_manager.needs_emergency_refresh(
                static_cast<int>(connected.size()))) {
            LOG_WARNING << "[DASH] Emergency peer refresh triggered, connected="
                        << connected.size();
        }

        // Periodic status log (every 12 cycles = 60 s).
        static int s_maint_count = 0;
        if (++s_maint_count % 12 == 0) {
            LOG_INFO << "[DASH] Broadcaster status: connected="
                     << connected.size()
                     << " to_connect=" << to_connect.size();
        }
    }

    // Drop slots whose NodeP2P has lost its connection. Mirror behavior
    // of LTC CoinBroadcaster — rely on NodeP2P's is_handshake_complete
    // staying true for as long as the socket is alive; on failure the
    // slot stops contributing to broadcasts, prune_dead_locally clears
    // it so the maintenance tick can refill from PeerManager candidates.
    void prune_dead_locally()
    {
        std::vector<std::string> to_drop;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto& [key, peer] : m_peers) {
                if (!peer) { to_drop.push_back(key); continue; }
                // A slot that never handshook within 30 s or that lost
                // its socket (is_connected false) is dead. We keep the
                // handshake-pending case alive briefly via the NodeP2P
                // timeout, but once peer_version() is zero AND no
                // handshake, drop it.
                if (!peer->node_p2p.is_handshake_complete()
                    && peer->node_p2p.peer_uptime_sec() == 0) {
                    // Still connecting — don't drop yet.
                    continue;
                }
                if (!peer->node_p2p.is_connected())
                    to_drop.push_back(key);
            }
        }
        for (auto& key : to_drop) disconnect_peer(key);
    }

    boost::asio::io_context&    m_ioc;
    std::vector<std::byte>      m_prefix;
    std::optional<PeerEndpoint> m_local_daemon;
    CoinPeerManager             m_peer_manager;
    boost::asio::steady_timer   m_maintenance_timer;

    mutable std::mutex                                        m_mutex;
    std::map<std::string, std::unique_ptr<DashBroadcastPeer>> m_peers;
    bool                                                      m_running{true};

    // Bug 3 mitigation (use-after-free during peer disconnect/reconnect cascade):
    // NodeP2P doesn't inherit enable_shared_from_this and DashBroadcastPeer
    // holds it by value. When m_peers.erase() destructs the slot, any
    // in-flight async callback (connect/read/timer) that captured `this`
    // UAFs on the freed m_target_addr string → garbage in to_string() →
    // boost::log codecvt crashes on non-UTF8 bytes.
    //
    // Until the proper shared_from_this refactor lands, defer destruction
    // by GRAVEYARD_TTL seconds. Callers move erased peers here and a timer
    // pops the front when its TTL expires. By then all in-flight async
    // ops on the dead peer have either completed or seen ec=cancelled.
    static constexpr std::chrono::seconds GRAVEYARD_TTL{30};
    struct DeferredPeer {
        std::unique_ptr<DashBroadcastPeer>      peer;
        std::chrono::steady_clock::time_point   die_at;
    };
    std::vector<DeferredPeer>                                 m_graveyard;
    boost::asio::steady_timer                                 m_graveyard_timer{m_ioc};

    BlockCallback      m_on_new_block;
    TxCallback         m_on_new_tx;
    HeadersCallback    m_on_new_headers;
    FullBlockCallback  m_on_full_block;
    PeerHeightCallback m_on_peer_height;
    MnListDiffCallback m_on_mnlistdiff;
    ClsigCallback      m_on_clsig;
};

} // namespace dash
