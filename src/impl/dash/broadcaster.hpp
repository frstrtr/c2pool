#pragma once

// DashBroadcaster — pool of dashd P2P connections for redundant block
// broadcast + peer discovery via dashd's getpeerinfo RPC.
//
// Purpose matches p2pool-dash/p2pool/dash/broadcaster.py DashNetworkBroadcaster
// (max_peers=20) and c2pool-ltc's CoinBroadcaster: maintain many parent-
// chain P2P connections so a found block can be fanned out in parallel,
// cutting propagation latency below what a single-dashd submit can reach.
//
// Scope (Phase 1):
//   * pool of N `dash::coin::Node<Config>` instances
//   * each holds one `NodeP2P<Config>` doing full handshake + mempool snap
//   * periodic discovery tick:
//       1. call getpeerinfo on the primary RPC connection
//       2. enumerate peers reported by dashd
//       3. dial any not-yet-connected ones up to max_peers
//       4. prune disconnected slots
//   * submit_block_raw_all() fans out to every live slot
//   * peer_info_json_all() aggregates for the dashboard panel
//
// Out of scope here (future phase):
//   * peer scoring / Wilson-score reputation (c2pool-ltc CoinPeerManager)
//   * exponential backoff on failed dials
//   * group limits (/16 caps)
//   * anchor peers persisted across restarts

#include "coin/node.hpp"
#include "coin/rpc.hpp"
#include "config.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace dash {

class DashBroadcaster
{
public:
    // Exclude the primary (header-sync) connection from this pool —
    // main_dash.cpp keeps that separate so it can subscribe to
    // new_headers / full_block / new_chainlock without duplication.
    DashBroadcaster(boost::asio::io_context& ioc,
                    dash::Config* config,
                    dash::coin::NodeRPC* rpc,
                    const NetService& primary_addr,
                    size_t max_peers)
        : m_ioc(ioc)
        , m_config(config)
        , m_rpc(rpc)
        , m_primary_addr(primary_addr)
        , m_max_peers(max_peers)
    {}

    // Kick off the discovery timer. Initial discovery fires after
    // `initial_delay` so the primary dashd connection has time to settle.
    void start(int initial_delay_sec = 15, int interval_sec = 30)
    {
        m_interval_sec = interval_sec;
        m_timer = std::make_shared<boost::asio::steady_timer>(m_ioc);
        schedule_tick(initial_delay_sec);
    }

    // Fan-out block broadcast. Called from main_dash.cpp submit handler
    // *after* the primary P2P broadcast, so the primary path remains the
    // source-of-truth for acceptance latency and this pool just widens
    // propagation.
    void submit_block_raw_all(std::span<const unsigned char> block_bytes)
    {
        size_t sent = 0;
        for (auto& [key, slot] : m_slots) {
            if (slot && slot->has_p2p()) {
                try {
                    slot->submit_block_raw(block_bytes);
                    ++sent;
                } catch (const std::exception& e) {
                    LOG_WARNING << "[DashBroadcast] submit to " << key
                                << " failed: " << e.what();
                }
            }
        }
        LOG_INFO << "[DashBroadcast] block fanned out to " << sent << " peer(s)";
    }

    // Dashboard panel feed — combines the primary peer + pool peers into
    // one array. Called by the MiningInterface coin-peer-info callback.
    nlohmann::json peer_info_json_all(const nlohmann::json& primary) const
    {
        nlohmann::json arr = nlohmann::json::array();
        if (primary.is_array())
            for (const auto& p : primary) arr.push_back(p);
        for (const auto& [key, slot] : m_slots) {
            if (!slot) continue;
            auto entry = slot->peer_info_json();
            if (!entry.is_array()) continue;
            for (auto& p : entry) arr.push_back(std::move(p));
        }
        return arr;
    }

    size_t live_count() const
    {
        size_t n = 0;
        for (const auto& [key, slot] : m_slots)
            if (slot && slot->has_p2p()) ++n;
        return n;
    }

private:
    void schedule_tick(int delay_sec)
    {
        m_timer->expires_after(std::chrono::seconds(delay_sec));
        // Capture broadcast + timer by pointer so the lambda survives
        // re-scheduling without recursive std::function references.
        auto self = this;
        auto timer = m_timer;
        m_timer->async_wait([self, timer](const boost::system::error_code& ec) {
            if (ec) return;
            try { self->discover_once(); }
            catch (const std::exception& e) {
                LOG_WARNING << "[DashBroadcast] discover_once threw: " << e.what();
            }
            self->schedule_tick(self->m_interval_sec);
        });
    }

    // Call getpeerinfo on primary RPC; dial candidates up to max_peers.
    void discover_once()
    {
        if (!m_rpc || !m_rpc->is_connected()) {
            LOG_INFO << "[DashBroadcast] discovery skipped — RPC not connected";
            return;
        }

        nlohmann::json peers;
        try { peers = m_rpc->getpeerinfo(); }
        catch (const std::exception& e) {
            LOG_WARNING << "[DashBroadcast] getpeerinfo failed: " << e.what();
            return;
        }

        // Prune dead slots first: anything that no longer reports has_p2p
        // (handshake gave up) gets removed so the next discovery can
        // replace it from the fresh getpeerinfo list.
        prune_dead();

        if (!peers.is_array()) return;

        size_t dialed = 0, live = live_count();
        const size_t port = m_config ? m_config->coin()->m_p2p.address.port() : 9999;

        for (const auto& p : peers) {
            if (live + dialed >= m_max_peers) break;
            if (!p.is_object()) continue;
            if (!p.contains("addr")) continue;
            std::string addr_raw = p.value("addr", "");
            // dashd's getpeerinfo uses IPv6-bracketed form for v4-mapped
            // or v6 ("[::ffff:1.2.3.4]:9999"). Strip brackets.
            auto ep = parse_host_port(addr_raw);
            if (!ep.valid) continue;
            // Only dial the canonical mainnet/testnet port. dashd's peer
            // may report an ephemeral client port on inbound entries.
            if (ep.port != port) continue;
            // Don't dial the primary (already connected via main_dash).
            if (ep.host == primary_host()) continue;

            std::string key = ep.host + ":" + std::to_string(ep.port);
            if (m_slots.count(key)) continue;  // already have a slot

            // Respect backoff — if we tried recently and it failed, skip.
            auto bo = m_backoff.find(key);
            if (bo != m_backoff.end()
                && std::chrono::steady_clock::now() < bo->second)
                continue;

            try_dial(key, NetService(ep.host, static_cast<uint16_t>(ep.port)));
            ++dialed;
        }

        if (dialed > 0 || live > 0) {
            LOG_INFO << "[DashBroadcast] discovery: dialed=" << dialed
                     << " live=" << live_count()
                     << "/" << m_max_peers
                     << " (primary + pool)";
        }
    }

    struct ParsedEndpoint { std::string host; int port{0}; bool valid{false}; };
    static ParsedEndpoint parse_host_port(const std::string& s) {
        ParsedEndpoint out;
        // Accept "host:port" or "[host]:port".
        if (s.empty()) return out;
        std::string host;
        std::string port_str;
        if (s.front() == '[') {
            auto close = s.find(']');
            if (close == std::string::npos) return out;
            host = s.substr(1, close - 1);
            if (close + 1 >= s.size() || s[close + 1] != ':') return out;
            port_str = s.substr(close + 2);
        } else {
            auto colon = s.rfind(':');
            if (colon == std::string::npos) return out;
            host = s.substr(0, colon);
            port_str = s.substr(colon + 1);
        }
        // Strip IPv4-mapped prefix on plain IPv6 string.
        const std::string v4map = "::ffff:";
        if (host.rfind(v4map, 0) == 0) host = host.substr(v4map.size());
        try { out.port = std::stoi(port_str); }
        catch (...) { return out; }
        if (out.port <= 0 || out.port > 65535) return out;
        out.host = std::move(host);
        out.valid = true;
        return out;
    }

    std::string primary_host() const
    {
        // m_primary_addr is a NetService; to_string gives "ip:port".
        auto full = m_primary_addr.to_string();
        auto colon = full.rfind(':');
        return (colon == std::string::npos) ? full : full.substr(0, colon);
    }

    void try_dial(const std::string& key, const NetService& addr)
    {
        auto node = std::make_unique<dash::coin::Node<dash::Config>>(
            &m_ioc, m_config);
        LOG_INFO << "[DashBroadcast] dialing " << key
                 << " (pool=" << m_slots.size() << "/" << m_max_peers << ")";
        try {
            node->start_p2p(addr);
        } catch (const std::exception& e) {
            LOG_WARNING << "[DashBroadcast] dial " << key
                        << " threw: " << e.what();
            // Short backoff so we retry this endpoint quickly instead of
            // having the discovery tick ignore it forever.
            m_backoff[key] = std::chrono::steady_clock::now()
                             + std::chrono::minutes(1);
            return;
        }
        m_slots[key] = std::move(node);
    }

    // Remove slots whose has_p2p() is false (connection collapsed /
    // never handshook). Preserve the backoff entry so we don't thrash
    // dialing the same dead address repeatedly.
    void prune_dead()
    {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_slots.begin(); it != m_slots.end(); ) {
            if (!it->second || !it->second->has_p2p()) {
                LOG_INFO << "[DashBroadcast] pruning dead slot " << it->first;
                m_backoff[it->first] = now + std::chrono::minutes(5);
                it = m_slots.erase(it);
            } else {
                ++it;
            }
        }
    }

    boost::asio::io_context&         m_ioc;
    dash::Config*                    m_config;
    dash::coin::NodeRPC*             m_rpc;
    NetService                       m_primary_addr;
    size_t                           m_max_peers;
    int                              m_interval_sec{30};

    std::shared_ptr<boost::asio::steady_timer> m_timer;
    std::map<std::string, std::unique_ptr<dash::coin::Node<dash::Config>>> m_slots;
    std::map<std::string, std::chrono::steady_clock::time_point>           m_backoff;
};

} // namespace dash
