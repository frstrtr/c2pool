#pragma once

/// Multi-peer manager for coin daemon P2P connections.
/// Handles peer discovery (getpeerinfo bootstrap + addr crawl),
/// scoring, exponential backoff, capacity gating, and protected local node.
/// Follows Python p2pool broadcaster design (chain-agnostic).

#include <string>
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <chrono>
#include <functional>
#include <fstream>
#include <cmath>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <core/log.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>
#include <core/dns_seeder.hpp>

namespace c2pool {
namespace merged {

// ─── Peer info tracked per endpoint ──────────────────────────────────────────
struct PeerInfo
{
    enum class Source { coind, addr_crawl, manual, dns_seed, fixed_seed };

    NetService          address;
    int                 score{0};
    Source              source{Source::coind};
    bool                is_protected{false};    // local daemon node — never drop

    // Timing
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point last_attempt;

    // Backoff state
    int                 backoff_sec{30};
    int                 attempt_count{0};
    int                 max_attempts{10};

    // Stats
    int                 broadcast_successes{0};
    int                 broadcast_failures{0};
    int                 connection_successes{0};
    int                 blocks_relayed{0};

    std::string key() const { return address.to_string(); }

    void record_success()
    {
        ++broadcast_successes;
        ++blocks_relayed;
        score += 10;
    }

    void record_failure()
    {
        ++broadcast_failures;
        score -= 5;
    }

    void record_connected()
    {
        ++connection_successes;
        backoff_sec = 30; // reset backoff
        attempt_count = 0;
        score += 10;
        last_seen = std::chrono::steady_clock::now();
    }

    void record_disconnected()
    {
        ++attempt_count;
        backoff_sec = std::min(backoff_sec * 2, is_protected ? 600 : 3600);
    }

    bool can_retry() const
    {
        if (is_protected) return true;
        if (attempt_count >= max_attempts) return false;
        auto elapsed = std::chrono::steady_clock::now() - last_attempt;
        return elapsed >= std::chrono::seconds(backoff_sec);
    }

    int compute_score() const
    {
        if (is_protected) return 999999;

        int s = score;

        // Source bonus
        if (source == Source::addr_crawl) s += 50;
        else if (source == Source::coind) s -= 20;

        // Broadcast success rate
        int total = broadcast_successes + broadcast_failures;
        if (total > 0) {
            s += static_cast<int>(100.0 * broadcast_successes / total);
        }

        // Age modifiers
        auto age = std::chrono::steady_clock::now() - first_seen;
        auto hours = std::chrono::duration_cast<std::chrono::hours>(age).count();
        if (hours < 1) s += 50;
        else if (hours > 24) s -= 50;
        else if (hours > 6) s -= 20;

        // Block relay activity
        if (blocks_relayed > 10) s += 30;
        else if (blocks_relayed > 5) s += 20;
        else if (blocks_relayed > 0) s += 10;

        // Connection stability
        if (connection_successes > 0) {
            auto uptime = std::chrono::steady_clock::now() - last_seen;
            if (std::chrono::duration_cast<std::chrono::hours>(uptime).count() < 1)
                s += 20;
        }

        return s;
    }
};

// ─── Peer manager configuration ──────────────────────────────────────────────
struct PeerManagerConfig
{
    int         max_peers{20};
    int         min_peers{5};
    int         max_concurrent_connections{3};
    int         max_connections_per_cycle{5};
    int         base_backoff_sec{30};
    int         max_backoff_sec{3600};
    int         max_connection_attempts{10};
    int         refresh_interval_sec{1800};     // 30 min for parent, 300 for merged
    int         peer_db_save_interval_sec{300};
    int         maintenance_interval_sec{5};
    bool        is_merged{false};               // merged chain uses inv instead of full block
    std::set<uint16_t> valid_ports;             // only connect to peers on known ports
};

// ─── CoinPeerManager ─────────────────────────────────────────────────────────
class CoinPeerManager
{
public:
    using GetPeerInfoFn = std::function<std::vector<NetService>()>;

    CoinPeerManager(boost::asio::io_context& ioc,
                    const std::string& symbol,
                    const std::string& data_dir,
                    const PeerManagerConfig& config)
        : m_ioc(ioc)
        , m_symbol(symbol)
        , m_data_dir(data_dir)
        , m_config(config)
        , m_refresh_timer(ioc)
        , m_save_timer(ioc)
        , m_maintenance_timer(ioc)
        , m_fixed_seed_timer(ioc)
    {
    }

    ~CoinPeerManager() { stop(); }

    /// Set callback to get peers from daemon via RPC getpeerinfo.
    void set_getpeerinfo_fn(GetPeerInfoFn fn) { m_getpeerinfo_fn = std::move(fn); }

    /// Register the protected local daemon node. Score=999999, never dropped.
    void set_local_node(const NetService& addr)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto key = addr.to_string();
        auto& peer = m_peers[key];
        peer.address = addr;
        peer.score = 999999;
        peer.is_protected = true;
        peer.source = PeerInfo::Source::manual;
        peer.first_seen = std::chrono::steady_clock::now();
        peer.last_seen = std::chrono::steady_clock::now();
        peer.max_attempts = 999999; // never give up
        m_local_node_key = key;
        LOG_INFO << "[" << m_symbol << "] Protected local node: " << key;
    }

    /// Set DNS seeds for this chain. Call before start().
    void set_dns_seeds(std::vector<c2pool::dns::DnsSeed> seeds)
    {
        m_dns_seeds = std::move(seeds);
    }

    /// Set hardcoded fixed seeds (fallback if DNS fails). Call before start().
    void set_fixed_seeds(std::vector<NetService> seeds)
    {
        m_fixed_seeds = std::move(seeds);
    }

    /// Start peer management (bootstrap + periodic refresh + maintenance).
    void start()
    {
        load_peers();
        bootstrap_from_getpeerinfo();
        bootstrap_from_dns_seeds();
        schedule_refresh();
        schedule_save();
        schedule_maintenance();
        schedule_fixed_seed_fallback();
        m_running = true;
        LOG_INFO << "[" << m_symbol << "] PeerManager started, "
                 << m_peers.size() << " known peers"
                 << " dns_seeds=" << m_dns_seeds.size()
                 << " fixed_seeds=" << m_fixed_seeds.size();
    }

    void stop()
    {
        m_running = false;
        m_refresh_timer.cancel();
        m_save_timer.cancel();
        m_maintenance_timer.cancel();
        m_fixed_seed_timer.cancel();
        save_peers();
    }

    /// Add a peer discovered via P2P addr message.
    void add_discovered_peer(const NetService& addr)
    {
        if (!is_valid_port(addr.port())) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        if (static_cast<int>(m_peers.size()) >= m_config.max_peers) return; // capacity gating
        auto key = addr.to_string();
        if (m_peers.count(key)) return; // already known
        if (m_coind_peers.count(key)) return; // daemon already has it

        auto& peer = m_peers[key];
        peer.address = addr;
        peer.source = PeerInfo::Source::addr_crawl;
        peer.first_seen = std::chrono::steady_clock::now();
        peer.last_seen = std::chrono::steady_clock::now();
        peer.max_attempts = m_config.max_connection_attempts;
    }

    /// Get list of peers that should be connected right now.
    /// Returns up to max_connections_per_cycle peers sorted by score,
    /// excluding already-connected and backed-off peers.
    std::vector<NetService> get_peers_to_connect(
        const std::set<std::string>& connected_keys) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int pending = static_cast<int>(connected_keys.size());
        if (pending >= m_config.max_peers) return {};

        // Count how many more we can connect
        int budget = std::min(
            m_config.max_connections_per_cycle,
            std::min(m_config.max_concurrent_connections,
                     m_config.max_peers - pending));
        if (budget <= 0) return {};

        // Score-sorted candidates
        struct Candidate { int score; NetService addr; };
        std::vector<Candidate> candidates;
        for (auto& [key, peer] : m_peers) {
            if (connected_keys.count(key)) continue;
            if (!peer.can_retry()) continue;
            candidates.push_back({peer.compute_score(), peer.address});
        }

        std::sort(candidates.begin(), candidates.end(),
                  [](const auto& a, const auto& b) { return a.score > b.score; });

        std::vector<NetService> result;
        for (int i = 0; i < budget && i < static_cast<int>(candidates.size()); ++i) {
            result.push_back(candidates[i].addr);
        }
        return result;
    }

    /// Notify that connection to a peer succeeded.
    void notify_connected(const std::string& key)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peers.find(key);
        if (it != m_peers.end()) {
            it->second.record_connected();
        }
        if (!m_bootstrapped) m_bootstrapped = true;
    }

    /// Notify that connection to a peer was lost.
    void notify_disconnected(const std::string& key)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peers.find(key);
        if (it != m_peers.end()) {
            it->second.record_disconnected();
        }
    }

    /// Record broadcast success for a peer.
    void record_broadcast_success(const std::string& key)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peers.find(key);
        if (it != m_peers.end()) {
            it->second.record_success();
        }
    }

    /// Record broadcast failure for a peer.
    void record_broadcast_failure(const std::string& key)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peers.find(key);
        if (it != m_peers.end()) {
            it->second.record_failure();
        }
    }

    /// Check if we're below min_peers — triggers emergency refresh.
    bool needs_emergency_refresh(int connected_count) const
    {
        return connected_count < m_config.min_peers;
    }

    /// Whether discovery (getaddr) should be enabled.
    bool discovery_enabled() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<int>(m_peers.size()) < m_config.max_peers;
    }

    /// Remove peers that are exhausted (max attempts reached, not protected).
    void prune_dead_peers()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_peers.begin(); it != m_peers.end(); ) {
            if (!it->second.is_protected &&
                it->second.attempt_count >= it->second.max_attempts)
            {
                LOG_DEBUG_COIND << "[" << m_symbol << "] Pruning dead peer: " << it->first;
                it = m_peers.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t peer_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers.size();
    }

    const std::string& symbol() const { return m_symbol; }

private:
    bool is_valid_port(uint16_t port) const
    {
        if (m_config.valid_ports.empty()) return true;
        return m_config.valid_ports.count(port) > 0;
    }

    void bootstrap_from_getpeerinfo()
    {
        if (!m_getpeerinfo_fn) return;
        try {
            auto peers = m_getpeerinfo_fn();
            std::lock_guard<std::mutex> lock(m_mutex);
            m_coind_peers.clear();
            for (auto& addr : peers) {
                if (!is_valid_port(addr.port())) continue;
                auto key = addr.to_string();
                m_coind_peers.insert(key);
                if (!m_peers.count(key)) {
                    auto& peer = m_peers[key];
                    peer.address = addr;
                    peer.source = PeerInfo::Source::coind;
                    peer.first_seen = std::chrono::steady_clock::now();
                    peer.last_seen = std::chrono::steady_clock::now();
                    peer.max_attempts = m_config.max_connection_attempts;
                }
            }
            LOG_INFO << "[" << m_symbol << "] Bootstrap: " << peers.size()
                     << " peers from getpeerinfo, " << m_peers.size() << " total";
        } catch (const std::exception& e) {
            LOG_WARNING << "[" << m_symbol << "] getpeerinfo failed: " << e.what();
        }
    }

    void schedule_refresh()
    {
        m_refresh_timer.expires_after(
            std::chrono::seconds(m_config.refresh_interval_sec));
        m_refresh_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_running) return;
            bootstrap_from_getpeerinfo();
            prune_dead_peers();
            schedule_refresh();
        });
    }

    void schedule_save()
    {
        m_save_timer.expires_after(
            std::chrono::seconds(m_config.peer_db_save_interval_sec));
        m_save_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_running) return;
            save_peers();
            schedule_save();
        });
    }

    void schedule_maintenance()
    {
        m_maintenance_timer.expires_after(
            std::chrono::seconds(m_config.maintenance_interval_sec));
        m_maintenance_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_running) return;
            schedule_maintenance();
        });
    }

    // ─── JSON persistence ────────────────────────────────────────────────

    std::string db_path() const
    {
        std::filesystem::path dir;
        if (m_data_dir.empty() || m_data_dir == ".")
            dir = ::core::filesystem::config_path() / "broadcaster";
        else
            dir = m_data_dir;
        std::filesystem::create_directories(dir);
        return (dir / ("peers_" + m_symbol + ".json")).string();
    }

    void save_peers()
    {
        try {
            std::lock_guard<std::mutex> lock(m_mutex);
            nlohmann::json j;
            j["bootstrapped"] = m_bootstrapped;
            j["saved_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            nlohmann::json peers_j = nlohmann::json::object();
            for (auto& [key, peer] : m_peers) {
                nlohmann::json pj;
                pj["score"] = peer.score;
                pj["source"] = static_cast<int>(peer.source);
                pj["protected"] = peer.is_protected;
                pj["attempt_count"] = peer.attempt_count;
                pj["backoff_sec"] = peer.backoff_sec;
                pj["broadcast_successes"] = peer.broadcast_successes;
                pj["broadcast_failures"] = peer.broadcast_failures;
                pj["blocks_relayed"] = peer.blocks_relayed;
                peers_j[key] = pj;
            }
            j["peers"] = peers_j;

            // Atomic write: .tmp → rename
            std::string tmp_path = db_path() + ".tmp";
            {
                std::ofstream ofs(tmp_path);
                ofs << j.dump(2);
            }
            std::rename(tmp_path.c_str(), db_path().c_str());
            LOG_DEBUG_COIND << "[" << m_symbol << "] Saved " << m_peers.size() << " peers";
        } catch (const std::exception& e) {
            LOG_WARNING << "[" << m_symbol << "] Failed to save peers: " << e.what();
        }
    }

    void load_peers()
    {
        try {
            std::ifstream ifs(db_path());
            if (!ifs.is_open()) return;

            auto j = nlohmann::json::parse(ifs);
            m_bootstrapped = j.value("bootstrapped", false);

            if (j.contains("peers") && j["peers"].is_object()) {
                std::lock_guard<std::mutex> lock(m_mutex);
                for (auto& [key, pj] : j["peers"].items()) {
                    // Parse "host:port" back into NetService
                    auto colon = key.rfind(':');
                    if (colon == std::string::npos) continue;
                    std::string host = key.substr(0, colon);
                    uint16_t port = static_cast<uint16_t>(
                        std::stoul(key.substr(colon + 1)));

                    auto& peer = m_peers[key];
                    peer.address = NetService(host, port);
                    peer.score = pj.value("score", 0);
                    peer.source = static_cast<PeerInfo::Source>(
                        pj.value("source", 0));
                    peer.is_protected = pj.value("protected", false);
                    peer.attempt_count = pj.value("attempt_count", 0);
                    peer.backoff_sec = pj.value("backoff_sec", 30);
                    peer.broadcast_successes = pj.value("broadcast_successes", 0);
                    peer.broadcast_failures = pj.value("broadcast_failures", 0);
                    peer.blocks_relayed = pj.value("blocks_relayed", 0);
                    peer.first_seen = std::chrono::steady_clock::now();
                    peer.last_seen = std::chrono::steady_clock::now();
                    peer.max_attempts = peer.is_protected ? 999999
                        : m_config.max_connection_attempts;
                }
                LOG_INFO << "[" << m_symbol << "] Loaded " << m_peers.size()
                         << " peers from " << db_path();
            }
        } catch (const std::exception& e) {
            LOG_DEBUG_COIND << "[" << m_symbol << "] No saved peers: " << e.what();
        }
    }

    // ─── DNS seed bootstrap ─────────────────────────────────────────────

    void bootstrap_from_dns_seeds()
    {
        if (m_dns_seeds.empty()) return;

        LOG_INFO << "[" << m_symbol << "] Resolving " << m_dns_seeds.size() << " DNS seeds...";
        c2pool::dns::DnsSeeder seeder(m_ioc, m_dns_seeds);
        auto peers = seeder.resolve_all_sync();

        if (peers.empty()) {
            LOG_WARNING << "[" << m_symbol << "] DNS seeds returned 0 peers";
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        int added = 0;
        for (auto& addr : peers) {
            if (!is_valid_port(addr.port())) continue;
            if (static_cast<int>(m_peers.size()) >= m_config.max_peers) break;
            auto key = addr.to_string();
            if (m_peers.count(key)) continue;

            auto& peer = m_peers[key];
            peer.address = addr;
            peer.source = PeerInfo::Source::dns_seed;
            peer.first_seen = std::chrono::steady_clock::now();
            peer.last_seen = std::chrono::steady_clock::now();
            peer.max_attempts = m_config.max_connection_attempts;
            ++added;
        }
        LOG_INFO << "[" << m_symbol << "] DNS seeds: " << peers.size()
                 << " resolved, " << added << " new peers added, "
                 << m_peers.size() << " total";
    }

    void load_fixed_seeds()
    {
        if (m_fixed_seeds.empty()) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        // Only load fixed seeds if we still have very few peers
        int non_protected = 0;
        for (auto& [k, p] : m_peers) {
            if (!p.is_protected) ++non_protected;
        }
        if (non_protected >= m_config.min_peers) {
            LOG_DEBUG_COIND << "[" << m_symbol << "] Skipping fixed seeds: "
                            << non_protected << " peers already known";
            return;
        }

        int added = 0;
        for (auto& addr : m_fixed_seeds) {
            if (static_cast<int>(m_peers.size()) >= m_config.max_peers) break;
            auto key = addr.to_string();
            if (m_peers.count(key)) continue;

            auto& peer = m_peers[key];
            peer.address = addr;
            peer.source = PeerInfo::Source::fixed_seed;
            peer.first_seen = std::chrono::steady_clock::now();
            peer.last_seen = std::chrono::steady_clock::now();
            peer.max_attempts = m_config.max_connection_attempts;
            ++added;
        }
        if (added > 0) {
            LOG_INFO << "[" << m_symbol << "] Loaded " << added
                     << " fixed seed peers (fallback), " << m_peers.size() << " total";
        }
    }

    void schedule_fixed_seed_fallback()
    {
        if (m_fixed_seeds.empty()) return;

        // Load fixed seeds after 60s if we still have few peers
        m_fixed_seed_timer.expires_after(std::chrono::seconds(60));
        m_fixed_seed_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !m_running) return;
            load_fixed_seeds();
        });
    }

    // ─── Members ─────────────────────────────────────────────────────────

    boost::asio::io_context& m_ioc;
    std::string m_symbol;
    std::string m_data_dir;
    PeerManagerConfig m_config;

    boost::asio::steady_timer m_refresh_timer;
    boost::asio::steady_timer m_save_timer;
    boost::asio::steady_timer m_maintenance_timer;
    boost::asio::steady_timer m_fixed_seed_timer;

    GetPeerInfoFn m_getpeerinfo_fn;

    // DNS + fixed seeds
    std::vector<c2pool::dns::DnsSeed> m_dns_seeds;
    std::vector<NetService> m_fixed_seeds;

    mutable std::mutex m_mutex;
    std::map<std::string, PeerInfo> m_peers;        // key = "host:port"
    std::set<std::string> m_coind_peers;            // daemon's own peers (overlap filter)
    std::string m_local_node_key;
    bool m_bootstrapped{false};
    bool m_running{false};
};

} // namespace merged
} // namespace c2pool
