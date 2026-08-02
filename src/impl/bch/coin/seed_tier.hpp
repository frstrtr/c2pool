// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// bch::coin::SeedTier -- embedded-P2P peer DISCOVERY LADDER for the home-grown
// single-peer BCH node (there is NO CoinPeerManager in this lane; dash/ltc
// have one, BCH connects a single EmbeddedDaemon peer). This is the ADDITIVE
// Option-A discovery source: it is consulted ONLY when no explicit
// coin()->m_p2p.address peer is configured. The external BCHN-RPC arm and the
// explicit single-peer default are untouched.
//
// It holds the three converged seed tiers (matching the dash/ltc setter
// interface -- set_dns_seeds / set_fixed_seeds / set_http_peer_seeds) and
// resolves them into an ORDERED candidate list the single-peer NodeP2P dials
// first and walks on reconnect:
//
//   DNS seeds (DnsSeeder async resolve)               -- PRIMARY tier
//     └─ if DNS resolved nothing → fixed seeds        -- SUBSTITUTE tier
//        └─ if both empty → http-peer seeds           -- FINAL fallback
//           (ported verbatim-ish from dash's self-contained
//            http_fetch_coin_peers: raw boost::asio TCP GET /api/coin_peers +
//            nlohmann::json parse, NO peer-manager / core-manager dependency).
//
// Resolved seeds flow as ordinary NetService objects, so the getaddrs
// is_wire_advertisable() guard (#911) in protocol_actual/legacy.cpp already
// covers them -- routable resolved IPs are advertisable, unresolved hostname-
// stored entries are not. This header does NOT duplicate that guard.
//
// PER-COIN ISOLATION: src/impl/bch only. Depends solely on shared CORE
// primitives (NetService / DnsSeeder) and boost::asio + nlohmann::json.
// p2pool-merged-v36 surface: NONE (transport discovery only -- no PoW / share /
// coinbase / PPLNS / WorkData-shape change). Header-only, matching the sibling
// bch coin leaves (coin/*.hpp).
// ---------------------------------------------------------------------------

#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <memory>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>
#include <core/dns_seeder.hpp>

namespace bch {
namespace coin {

class SeedTier
{
public:
    using ResultCallback = std::function<void(std::vector<NetService>)>;

    // ── Converged setter interface (mirrors dash/ltc CoinPeerManager) ────────

    /// DNS seed hostnames + default port (async-resolved, primary tier).
    void set_dns_seeds(std::vector<c2pool::dns::DnsSeed> seeds)
    { m_dns_seeds = std::move(seeds); }

    /// Hardcoded fallback peers, used when DNS resolves nothing.
    void set_fixed_seeds(std::vector<NetService> seeds)
    { m_fixed_seeds = std::move(seeds); }

    /// c2pool seed-node HTTP endpoints ({host, port}); queried via
    /// GET /api/coin_peers as the FINAL fallback when DNS + fixed are empty.
    void set_http_peer_seeds(std::vector<std::pair<std::string, uint16_t>> seeds)
    { m_http_peer_seeds = std::move(seeds); }

    /// True when at least one tier is populated.
    bool has_seeds() const
    {
        return !m_dns_seeds.empty() || !m_fixed_seeds.empty()
            || !m_http_peer_seeds.empty();
    }

    const std::vector<c2pool::dns::DnsSeed>& dns_seeds() const { return m_dns_seeds; }
    const std::vector<NetService>& fixed_seeds() const { return m_fixed_seeds; }
    const std::vector<std::pair<std::string, uint16_t>>& http_peer_seeds() const
    { return m_http_peer_seeds; }

    // ── Ladder gate (SSOT, pure/testable) ────────────────────────────────────

    /// The embedded seed-tier ladder is consulted ONLY when NO explicit peer is
    /// configured (explicit_peer_port == 0) AND at least one tier is populated.
    /// An explicit peer (port != 0) ALWAYS bypasses the ladder -- the existing
    /// single-peer path dials that configured address directly, unchanged.
    static bool should_run_ladder(uint16_t explicit_peer_port, bool has_seeds)
    {
        return explicit_peer_port == 0 && has_seeds;
    }

    // ── Ordered candidate assembly (pure/testable) ────────────────────────────

    /// Build the ordered, deduped candidate list from resolved tier outputs.
    /// DNS is the primary tier; when it resolved nothing the fixed-seed tier
    /// substitutes for it (DNS→fixed fallback). The HTTP-peer tier is appended
    /// as the FINAL fallback after the primary tier. Dedup preserves first
    /// occurrence, so the returned order is: [DNS or fixed] then [http].
    static std::vector<NetService> build_ladder(
        const std::vector<NetService>& dns_resolved,
        const std::vector<NetService>& fixed,
        const std::vector<NetService>& http_resolved)
    {
        const std::vector<NetService>& primary =
            dns_resolved.empty() ? fixed : dns_resolved;

        std::vector<NetService> out;
        auto push_unique = [&](const NetService& s) {
            for (const auto& e : out)
                if (e == s) return;
            out.push_back(s);
        };
        for (const auto& s : primary)       push_unique(s);
        for (const auto& s : http_resolved) push_unique(s);
        return out;
    }

    // ── Async ladder walk ─────────────────────────────────────────────────────

    /// Resolve the tiers into an ordered candidate list and deliver it via cb
    /// (posted on ioc). DNS is resolved asynchronously via DnsSeeder; if the
    /// DNS tier (or, when empty, the fixed tier) yields any candidate, cb fires
    /// with it immediately -- the blocking HTTP-peer GET is only consulted as
    /// the FINAL fallback (single-peer-friendly: keep startup off the network
    /// GET unless nothing else resolved). The callback delivers the ORDERED
    /// list; NodeP2P dials the first and walks the remainder on reconnect.
    /// `ioc` must outlive the resolution (owned by the binary entrypoint).
    void resolve_candidates(boost::asio::io_context& ioc, ResultCallback cb)
    {
        auto fixed = m_fixed_seeds;
        auto http  = m_http_peer_seeds;
        auto seeder = std::make_shared<c2pool::dns::DnsSeeder>(ioc, m_dns_seeds);

        seeder->resolve_all(
            [&ioc, cb = std::move(cb), fixed, http, seeder]
            (std::vector<NetService> dns_resolved) mutable
            {
                // Primary tier: DNS-resolved; fixed substitutes when DNS empty.
                auto primary = SeedTier::build_ladder(dns_resolved, fixed, {});
                if (!primary.empty()) {
                    LOG_INFO << "[SeedTier] ladder primary tier -> "
                             << primary.size() << " candidate(s)";
                    cb(std::move(primary));
                    return;
                }

                // FINAL fallback: blocking HTTP GET on a detached thread; the
                // parsed peers are posted back onto ioc as the candidate list.
                if (http.empty()) {
                    LOG_WARNING << "[SeedTier] DNS + fixed tiers empty and no "
                                   "http-peer seeds -- 0 candidates";
                    cb({});
                    return;
                }
                std::thread([&ioc, cb = std::move(cb), http]() mutable {
                    std::vector<NetService> fetched;
                    for (auto& [host, port] : http) {
                        try {
                            fetched = http_fetch_coin_peers(host, port, "bch");
                            if (!fetched.empty()) {
                                LOG_INFO << "[SeedTier] http-peer seed " << host
                                         << ":" << port << " -> " << fetched.size()
                                         << " peers";
                                break;
                            }
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[SeedTier] http-peer seed " << host
                                        << ":" << port << " failed: " << e.what();
                        }
                    }
                    auto candidates = SeedTier::build_ladder({}, {}, fetched);
                    boost::asio::post(ioc,
                        [cb = std::move(cb), candidates]() mutable {
                            cb(std::move(candidates));
                        });
                }).detach();
            });
    }

    /// Lightweight blocking HTTP GET -- fetches /api/coin_peers from a c2pool
    /// seed node. Raw TCP sockets (no boost::beast dependency). Ported from
    /// dash::coin::DashCoinPeerManager::http_fetch_coin_peers; the JSON chain
    /// key is the per-lane feed name ("bch").
    static std::vector<NetService> http_fetch_coin_peers(
        const std::string& host, uint16_t port, const std::string& chain_key)
    {
        std::vector<NetService> result;
        try {
            boost::asio::io_context tmp_ioc;
            boost::asio::ip::tcp::resolver resolver(tmp_ioc);
            auto endpoints = resolver.resolve(host, std::to_string(port));

            boost::asio::ip::tcp::socket sock(tmp_ioc);
            boost::asio::connect(sock, endpoints);

            std::string request =
                "GET /api/coin_peers HTTP/1.0\r\n"
                "Host: " + host + "\r\n"
                "User-Agent: c2pool/0.1\r\n"
                "Connection: close\r\n\r\n";
            boost::asio::write(sock, boost::asio::buffer(request));

            std::string response;
            boost::system::error_code ec;
            char buf[4096];
            while (true) {
                size_t n = sock.read_some(boost::asio::buffer(buf), ec);
                if (n > 0) response.append(buf, n);
                if (ec) break;
            }

            auto body_pos = response.find("\r\n\r\n");
            if (body_pos == std::string::npos) return result;
            std::string body = response.substr(body_pos + 4);

            auto j = nlohmann::json::parse(body);
            if (!j.contains(chain_key) || !j[chain_key].is_array())
                return result;

            for (auto& peer_str : j[chain_key]) {
                std::string s = peer_str.get<std::string>();
                auto colon = s.rfind(':');
                if (colon == std::string::npos) continue;
                std::string ip = s.substr(0, colon);
                uint16_t p = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
                if (!ip.empty() && p > 0)
                    result.emplace_back(ip, p);
            }
        } catch (...) {
            // Connection / DNS / parse failure -- return empty (final fallback).
        }
        return result;
    }

private:
    std::vector<c2pool::dns::DnsSeed>                m_dns_seeds;
    std::vector<NetService>                          m_fixed_seeds;
    std::vector<std::pair<std::string, uint16_t>>    m_http_peer_seeds;
};

} // namespace coin
} // namespace bch
