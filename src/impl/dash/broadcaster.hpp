// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Phase S8 — DashBroadcaster: dashd P2P peer-pool + discovery scaffold (LEAF).
//
// One rung above the socket-node, this is the pool that holds many parent-chain
// (dashd) P2P connections so a found block can be fanned out in parallel,
// cutting propagation latency below what a single-dashd submit can reach:
//
//     p2p_connection -> p2p_node -> [broadcaster] -> broadcaster_full
//
// Mirrors the INTENT of p2pool-dash/p2pool/dash/broadcaster.py
// (DashNetworkBroadcaster, max_peers=20) and c2pool-ltc's CoinBroadcaster, but
// this LEAF is strictly the PURE peer-pool + discovery + fan-out SCAFFOLD:
//
//   * a slot pool keyed "host:port", slot = unique_ptr<dash::coin::p2p::NodeP2P>
//     (the concrete current node type). Slot creation (the DIAL) is injected via
//     a std::function factory so the selection/discovery logic is unit-testable
//     WITHOUT opening a socket. The default factory just constructs a NodeP2P.
//   * the deterministic discovery pipeline driven from a getpeerinfo-shaped
//     nlohmann::json array: parse "addr" -> port-filter to the canonical p2p
//     port -> exclude the primary host -> dedupe vs existing slots -> respect a
//     per-key backoff map -> cap at max_peers.
//   * prune-dead: drop slots whose liveness predicate is false and arm a
//     backoff so we don't thrash-dial a dead address.
//   * live_count + peer_info aggregation (primary array + per-slot arrays).
//
// EXPLICITLY OUT OF SCOPE for this LEAF (lands in the SEPARATE keystone
// broadcaster_full.hpp, which routes the won block through the operator):
//   * real block submission / submit_block_raw / the won-block path. Here the
//     fan-out only iterates the LIVE slots invoking an injectable per-slot hook
//     (a no-op by default) — NO consensus, NO submitblock, NO RPC.
//   * the dashd handshake (version/verack), GBT fetch, quorum/mnlistdiff sync,
//     reconnect/ping cadence, peer scoring / Wilson-score reputation,
//     exponential backoff growth, /16 group caps, persisted anchor peers, and
//     the actual getpeerinfo RPC call (discover() takes the json directly so the
//     selection logic is driven deterministically; wiring the live RPC tick is
//     a broadcaster_full concern).
//
// Header-only to match the sibling leaves (config.hpp, p2p_node.hpp,
// p2p_connection.hpp, p2p_messages.hpp). No consensus value, single dash tree.

#include "coin/p2p_node.hpp"
#include "config.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace dash
{

// Pool of dashd P2P node slots + discovery/fan-out scaffold. Non-consensus.
class DashBroadcaster
{
public:
    using Slot = std::unique_ptr<dash::coin::p2p::NodeP2P>;

    // Injectable DIAL/slot factory. Default constructs a bare NodeP2P bound to
    // the io_context (no socket attached yet — attach()/handshake is a
    // broadcaster_full concern). Tests inject a stub factory so the selection
    // pipeline runs with no socket opened.
    using SlotFactory = std::function<Slot(const NetService& /*addr*/)>;

    // Injectable per-slot liveness predicate. Defaults to NodeP2P::is_attached.
    // Decoupled so tests can drive prune/live_count deterministically without a
    // live peer; production uses the real attached() predicate.
    using LivePredicate = std::function<bool(const dash::coin::p2p::NodeP2P&)>;

    // Injectable per-slot fan-out hook. THIS LEAF leaves it a no-op; the real
    // block-submit fan-out lands in broadcaster_full.hpp. submit_block_raw_all
    // only iterates the LIVE slots invoking this hook.
    using FanOutHook = std::function<void(dash::coin::p2p::NodeP2P& /*slot*/,
                                          std::span<const unsigned char> /*block_bytes*/)>;

    DashBroadcaster(boost::asio::io_context* ioc,
                    dash::Config* config,
                    const NetService& primary_addr,
                    size_t max_peers)
        : m_ioc(ioc)
        , m_config(config)
        , m_primary_addr(primary_addr)
        , m_max_peers(max_peers)
        , m_factory(default_factory(ioc))
        , m_is_live([](const dash::coin::p2p::NodeP2P& n) { return n.is_attached(); })
        , m_fan_out([](dash::coin::p2p::NodeP2P&, std::span<const unsigned char>) {})
    {}

    // ── injection seams (tests / broadcaster_full) ───────────────────────

    void set_slot_factory(SlotFactory f) { m_factory = std::move(f); }
    void set_live_predicate(LivePredicate p) { m_is_live = std::move(p); }
    void set_fan_out_hook(FanOutHook h) { m_fan_out = std::move(h); }

    // ── pure deterministic endpoint parse ────────────────────────────────

    struct ParsedEndpoint { std::string host; int port{0}; bool valid{false}; };

    // Parse a getpeerinfo "addr" entry: "host:port" or bracketed "[host]:port".
    // Strips an "::ffff:" IPv4-mapped prefix off the host. Rejects empties,
    // missing/bad ports, and out-of-range ports.
    static ParsedEndpoint parse_host_port(const std::string& s)
    {
        ParsedEndpoint out;
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
        const std::string v4map = "::ffff:";
        if (host.rfind(v4map, 0) == 0) host = host.substr(v4map.size());
        if (host.empty()) return out;
        try { out.port = std::stoi(port_str); }
        catch (...) { return out; }
        if (out.port <= 0 || out.port > 65535) return out;
        out.host = std::move(host);
        out.valid = true;
        return out;
    }

    // ── pure deterministic candidate selection ───────────────────────────

    // From a getpeerinfo-shaped json array, select the endpoints we should dial:
    //   * parse the "addr" field; skip malformed
    //   * port-filter to the canonical p2p port
    //   * exclude the primary host (already connected via main_dash)
    //   * dedupe vs existing slots AND within this batch
    //   * respect the per-key backoff map (skip if still backed off)
    //   * cap so live_count + selected does not exceed max_peers
    // Returns the chosen NetService dial targets in input order. PURE w.r.t. the
    // pool: it reads the slot keys / backoff but does NOT create slots.
    std::vector<NetService> select_candidates(const nlohmann::json& peers) const
    {
        std::vector<NetService> chosen;
        if (!peers.is_array()) return chosen;

        const int port = canonical_port();
        const std::string primary = primary_host();
        const auto now = std::chrono::steady_clock::now();
        const size_t live = live_count();

        std::map<std::string, bool> seen_this_batch;

        for (const auto& p : peers) {
            if (live + chosen.size() >= m_max_peers) break;
            if (!p.is_object()) continue;
            if (!p.contains("addr")) continue;

            auto ep = parse_host_port(p.value("addr", std::string{}));
            if (!ep.valid) continue;
            if (ep.port != port) continue;          // canonical-port only
            if (ep.host == primary) continue;        // exclude primary

            std::string key = ep.host + ":" + std::to_string(ep.port);
            if (m_slots.count(key)) continue;        // dedupe vs existing slots
            if (seen_this_batch.count(key)) continue; // dedupe within batch

            auto bo = m_backoff.find(key);
            if (bo != m_backoff.end() && now < bo->second) continue; // backoff

            seen_this_batch[key] = true;
            chosen.emplace_back(ep.host, static_cast<uint16_t>(ep.port));
        }
        return chosen;
    }

    // ── pool mutation ────────────────────────────────────────────────────

    // Run one discovery pass over a getpeerinfo-shaped json array: select
    // candidates, then create a slot for each via the injected factory. Returns
    // the number of new slots created. prune_dead() is run first so freed
    // capacity is reused. No socket is opened by this method itself — that is
    // entirely the factory's business (default factory only constructs).
    size_t discover(const nlohmann::json& peers)
    {
        prune_dead();
        auto cands = select_candidates(peers);
        size_t dialed = 0;
        for (const auto& addr : cands) {
            std::string key = slot_key(addr);
            if (m_slots.count(key)) continue;
            auto slot = m_factory ? m_factory(addr) : Slot{};
            if (!slot) {
                // Factory declined (dial failed) — short backoff, try again soon.
                m_backoff[key] = std::chrono::steady_clock::now()
                                 + std::chrono::minutes(1);
                continue;
            }
            m_slots[key] = std::move(slot);
            ++dialed;
        }
        if (dialed > 0)
            LOG_INFO << "[DashBroadcast] discovery: dialed=" << dialed
                     << " live=" << live_count() << "/" << m_max_peers;
        return dialed;
    }

    // Remove slots whose liveness predicate is false (connection collapsed /
    // never handshook) and arm a backoff so the same dead address is not
    // thrash-dialed by the next discovery pass. Returns count pruned.
    size_t prune_dead()
    {
        const auto now = std::chrono::steady_clock::now();
        size_t pruned = 0;
        for (auto it = m_slots.begin(); it != m_slots.end(); ) {
            const bool live = it->second && m_is_live && m_is_live(*it->second);
            if (!live) {
                LOG_INFO << "[DashBroadcast] pruning dead slot " << it->first;
                m_backoff[it->first] = now + std::chrono::minutes(5);
                it = m_slots.erase(it);
                ++pruned;
            } else {
                ++it;
            }
        }
        return pruned;
    }

    // ── fan-out (SCAFFOLD — NO real block submit in this leaf) ────────────

    // Iterate the LIVE slots invoking the injected fan-out hook. In this leaf
    // the hook is a no-op by default; the REAL block-submit fan-out lands in
    // broadcaster_full.hpp (which routes the won block through the operator).
    // Returns the number of live slots the hook was invoked on.
    size_t submit_block_raw_all(std::span<const unsigned char> block_bytes)
    {
        size_t sent = 0;
        for (auto& [key, slot] : m_slots) {
            if (slot && m_is_live && m_is_live(*slot)) {
                m_fan_out(*slot, block_bytes);
                ++sent;
            }
        }
        return sent;
    }

    // ── observers ────────────────────────────────────────────────────────

    size_t live_count() const
    {
        size_t n = 0;
        for (const auto& [key, slot] : m_slots)
            if (slot && m_is_live && m_is_live(*slot)) ++n;
        return n;
    }

    // Opaque "host:port" keys of the LIVE slots, in deterministic (std::map,
    // sorted) order. The won-block planner fans an inv out to exactly these
    // keys; this is the read seam that lets the relay binding pull the live
    // pool WITHOUT touching a socket. Pure: same liveness predicate as
    // live_count(), no dial, no I/O. broadcaster_full still owns writing the
    // frames onto the live slot sockets.
    std::vector<std::string> live_slot_keys() const
    {
        std::vector<std::string> keys;
        for (const auto& [key, slot] : m_slots)
            if (slot && m_is_live && m_is_live(*slot)) keys.push_back(key);
        return keys;
    }

    size_t slot_count() const { return m_slots.size(); }

    bool has_slot(const std::string& key) const { return m_slots.count(key) != 0; }

    bool is_backed_off(const std::string& key) const
    {
        auto bo = m_backoff.find(key);
        return bo != m_backoff.end()
               && std::chrono::steady_clock::now() < bo->second;
    }

    // Dashboard panel feed: combine the primary peer array with each slot's
    // own peer_info array into a single flat array. Slots contribute via the
    // injected per-slot json provider; absent one, only the primary passes
    // through (a per-slot json source is a broadcaster_full concern).
    nlohmann::json peer_info_json_all(
        const nlohmann::json& primary,
        const std::function<nlohmann::json(const dash::coin::p2p::NodeP2P&)>& slot_json
            = {}) const
    {
        nlohmann::json arr = nlohmann::json::array();
        if (primary.is_array())
            for (const auto& p : primary) arr.push_back(p);
        if (slot_json) {
            for (const auto& [key, slot] : m_slots) {
                if (!slot) continue;
                auto entry = slot_json(*slot);
                if (entry.is_array())
                    for (auto& p : entry) arr.push_back(std::move(p));
                else if (!entry.is_null())
                    arr.push_back(std::move(entry));
            }
        }
        return arr;
    }

private:
    static SlotFactory default_factory(boost::asio::io_context* ioc)
    {
        return [ioc](const NetService&) -> Slot {
            // Bare node bound to the io_context. The actual socket dial /
            // attach / handshake is deferred to broadcaster_full.hpp.
            return std::make_unique<dash::coin::p2p::NodeP2P>(ioc);
        };
    }

    int canonical_port() const
    {
        return m_config ? static_cast<int>(m_config->coin()->m_p2p.address.port())
                        : 0;
    }

    std::string primary_host() const { return m_primary_addr.address(); }

    static std::string slot_key(const NetService& addr)
    {
        return addr.address() + ":" + std::to_string(addr.port());
    }

    boost::asio::io_context* m_ioc{};
    dash::Config*            m_config{};
    NetService               m_primary_addr;
    size_t                   m_max_peers{};

    SlotFactory   m_factory;
    LivePredicate m_is_live;
    FanOutHook    m_fan_out;

    std::map<std::string, Slot>                                    m_slots;
    std::map<std::string, std::chrono::steady_clock::time_point>   m_backoff;
};

} // namespace dash