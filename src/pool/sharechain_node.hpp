// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// pool::SharechainNode
// ────────────────────
// Intermediate layer between pool::BaseNode and each coin's NodeImpl that owns
// the coin-agnostic, non-consensus P2P *policy* machinery shared verbatim by
// every coin. This first slice hoists the peer ban-list + whitelist subsystem,
// which was byte-identical across ltc/btc/bch/dgb node.cpp (only the coin
// namespace differed). The bodies are relocated unchanged — behaviour is
// identical, this is pure de-duplication.
//
// Only the self-contained ban/whitelist surface lives here: every method below
// touches ONLY members declared in this class, so no dependent-base (BaseNode)
// qualification is needed and no consensus/sharechain state is involved. The
// peer/outbound-connection admin endpoints (admin_list_peers/drop/dial,
// admin_whitelist_add) stay in NodeImpl for now because they reach into
// BaseNode's connection maps and the outbound-dial members; they can be hoisted
// in a follow-up once those members move here too.

#include <pool/node.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>

namespace pool
{

template <typename ConfigType, typename ShareChainType, typename PeerData>
class SharechainNode : public BaseNode<ConfigType, ShareChainType, PeerData>
{
public:
    using base_t = BaseNode<ConfigType, ShareChainType, PeerData>;

    SharechainNode() : base_t() {}
    SharechainNode(boost::asio::io_context* context, typename base_t::config_t* config)
        : base_t(context, config) {}

    // ── Ban policy ────────────────────────────────────────────────────────
    /// Set P2P ban duration (seconds).
    void set_ban_duration(int seconds) { m_ban_duration = std::chrono::seconds(seconds); }

    /// Check whether a peer address is currently banned.
    bool is_banned(const NetService& addr) const
    {
        // Whitelist bypass: permanent dial targets are immune to bans.
        if (is_whitelisted(addr)) return false;

        auto now = std::chrono::steady_clock::now();
        auto it = m_ban_list.find(addr);
        if (it != m_ban_list.end() && it->second > now) return true;

        auto ip_it = m_ip_ban_list.find(addr.address());
        if (ip_it != m_ip_ban_list.end() && ip_it->second > now) return true;

        return false;
    }

    // ── Whitelist ─────────────────────────────────────────────────────────
    /// True if addr's IP matches a whitelist entry (IP or host:port).
    bool is_whitelisted(const NetService& addr) const
    {
        const std::string ip = addr.address();
        if (m_whitelist_ips.contains(ip)) return true;
        if (m_whitelist_hosts.contains(addr)) return true;
        return false;
    }

    /// Path to persisted whitelist file (~/.c2pool/pool_whitelist.json).
    /// Set by c2pool_refactored.cpp before start(); empty = no persistence.
    void set_whitelist_path(const std::string& path)
    {
        m_whitelist_path = path;
        if (!path.empty()) load_whitelist_from_disk();
    }

    // ── Runtime admin API (ban/whitelist subset) ───────────────────────────
    /// All methods assumed to run on the io_context thread — callers
    /// (web_server HTTP handlers) dispatch via thread_safe_wrap().
    ///
    /// Returned JSON uses the shape:
    ///   {"ok": true|false, "error"?: "...", "bans": [...], "whitelist": [...]}
    nlohmann::json admin_list_bans() const
    {
        return {{"ok", true}, {"bans", build_bans_json(m_ban_list, m_ip_ban_list)}};
    }

    nlohmann::json admin_ban_ip(const std::string& ip, int duration_sec)
    {
        if (ip.empty())
            return {{"ok", false}, {"error", "ip required"}};
        int dur = duration_sec > 0 ? duration_sec : static_cast<int>(m_ban_duration.count());
        auto expiry = std::chrono::steady_clock::now() + std::chrono::seconds(dur);
        m_ip_ban_list[ip] = expiry;
        LOG_INFO << "[Pool] Admin ban: " << ip << " for " << dur << "s";
        return {{"ok", true}, {"action", "ban"}, {"target", ip},
                {"duration_sec", dur},
                {"bans", build_bans_json(m_ban_list, m_ip_ban_list)}};
    }

    nlohmann::json admin_unban_ip(const std::string& ip)
    {
        if (ip.empty())
            return {{"ok", false}, {"error", "ip required"}};
        size_t removed = m_ip_ban_list.erase(ip);
        for (auto it = m_ban_list.begin(); it != m_ban_list.end(); ) {
            if (it->first.address() == ip) { it = m_ban_list.erase(it); ++removed; }
            else ++it;
        }
        LOG_INFO << "[Pool] Admin unban: " << ip << " (" << removed << " entries removed)";
        return {{"ok", true}, {"action", "unban"}, {"target", ip},
                {"removed", removed},
                {"bans", build_bans_json(m_ban_list, m_ip_ban_list)}};
    }

    nlohmann::json admin_list_whitelist() const
    {
        return {{"ok", true}, {"whitelist", build_whitelist_json(m_whitelist_hosts)}};
    }

    nlohmann::json admin_whitelist_remove(const std::string& host, uint16_t port)
    {
        if (host.empty() || port == 0)
            return {{"ok", false}, {"error", "host and port required"}};
        NetService addr(host, port);
        size_t removed_h = m_whitelist_hosts.erase(addr);
        // Only remove the IP from whitelist if no other host:port remains for it.
        bool other_on_same_ip = std::any_of(
            m_whitelist_hosts.begin(), m_whitelist_hosts.end(),
            [&](const NetService& n) { return n.address() == host; });
        if (!other_on_same_ip) m_whitelist_ips.erase(host);
        if (removed_h) save_whitelist_to_disk();
        LOG_INFO << "[Pool] De-whitelisted " << addr.to_string();
        return {{"ok", true}, {"action", "whitelist_remove"},
                {"target", addr.to_string()}, {"removed", removed_h},
                {"whitelist", build_whitelist_json(m_whitelist_hosts)}};
    }

protected:
    void load_whitelist_from_disk()
    {
        if (m_whitelist_path.empty()) return;
        std::ifstream f(m_whitelist_path);
        if (!f) return;
        try {
            nlohmann::json j;
            f >> j;
            if (!j.contains("entries") || !j["entries"].is_array()) return;
            for (const auto& e : j["entries"]) {
                if (!e.contains("host") || !e.contains("port")) continue;
                std::string host = e["host"].get<std::string>();
                uint16_t port = e["port"].get<uint16_t>();
                m_whitelist_ips.insert(host);
                m_whitelist_hosts.insert(NetService(host, port));
            }
            LOG_INFO << "[Pool] Loaded " << m_whitelist_hosts.size()
                     << " whitelist entries from " << m_whitelist_path;
        } catch (const std::exception& e) {
            LOG_WARNING << "[Pool] Failed to parse whitelist " << m_whitelist_path
                        << ": " << e.what();
        }
    }

    void save_whitelist_to_disk() const
    {
        if (m_whitelist_path.empty()) return;
        try {
            nlohmann::json j;
            j["version"] = 1;
            auto arr = nlohmann::json::array();
            auto now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            for (const auto& host : m_whitelist_hosts) {
                arr.push_back({
                    {"host", host.address()},
                    {"port", host.port()},
                    {"added_unix", now_unix}
                });
            }
            j["entries"] = arr;
            std::string tmp = m_whitelist_path + ".new";
            {
                std::ofstream f(tmp);
                f << j.dump(2);
            }
            std::filesystem::rename(tmp, m_whitelist_path);
        } catch (const std::exception& e) {
            LOG_WARNING << "[Pool] Failed to persist whitelist: " << e.what();
        }
    }

    static nlohmann::json build_bans_json(
        const std::map<NetService, std::chrono::steady_clock::time_point>& peer_bans,
        const std::map<std::string, std::chrono::steady_clock::time_point>& ip_bans)
    {
        auto now = std::chrono::steady_clock::now();
        auto arr = nlohmann::json::array();
        for (const auto& [addr, expiry] : peer_bans) {
            if (expiry <= now) continue;
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(expiry - now).count();
            arr.push_back({{"host", addr.address()}, {"port", addr.port()},
                           {"expires_in_sec", secs}, {"source", "auto"}});
        }
        for (const auto& [ip, expiry] : ip_bans) {
            if (expiry <= now) continue;
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(expiry - now).count();
            arr.push_back({{"host", ip}, {"port", 0},
                           {"expires_in_sec", secs}, {"source", "admin"}});
        }
        return arr;
    }

    static nlohmann::json build_whitelist_json(const std::set<NetService>& hosts)
    {
        auto arr = nlohmann::json::array();
        for (const auto& h : hosts)
            arr.push_back({{"host", h.address()}, {"port", h.port()}});
        return arr;
    }

    // Peer banning: maps address → ban expiry time
    std::map<NetService, std::chrono::steady_clock::time_point> m_ban_list;
    std::chrono::seconds m_ban_duration{300}; // 5 minutes (configurable)

    // IP-only manual bans (admin endpoint). Keyed by IP string so the
    // operator can ban/unban without knowing the peer's source port.
    std::map<std::string, std::chrono::steady_clock::time_point> m_ip_ban_list;

    // Whitelist: IPs that bypass is_banned() and host:port entries kept as
    // permanent dial targets. Persists across restart via m_whitelist_path.
    std::set<std::string> m_whitelist_ips;
    std::set<NetService> m_whitelist_hosts;
    std::string m_whitelist_path;
};

} // namespace pool
