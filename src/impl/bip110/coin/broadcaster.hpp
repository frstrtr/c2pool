// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// bip110 M3 PR-C2 — Bip110Broadcaster: NODE_BLAKE2B coin-P2P peer-pool + fan-out
// (LEAF). One rung above the single-peer coin NodeP2P, this is the pool that
// holds MANY fork-network (NODE_BLAKE2B) P2P connections so a FOUND block can be
// fanned out in parallel to the whole reachable mesh, instead of reaching the
// one peer coin_node.m_p2p happens to hold:
//
//     p2p_connection -> p2p_node -> [broadcaster] -> broadcaster_full
//
// This mirrors the DASH #152 precedent (src/impl/dash/broadcaster.hpp
// DashBroadcaster) and the python p2pool NetworkBroadcaster
// (p2pool/bitcoin/broadcaster.py broadcast_block, a true parallel per-peer
// DeferredList). The DASH leaf is a pure SCAFFOLD whose slot factory never opens
// a socket and whose NodeP2P had no submit_block_raw on master. bip110 is
// strictly better positioned: bip110::coin::p2p::NodeP2P::submit_block_raw is
// REAL and proven, so THIS leaf's default factory dials a LIVE fork peer and the
// default fan-out hook pushes the real block bytes to every live slot.
//
// The fan-out TARGET SET is addrman-backed: main feeds discover() from the
// BtcCoinPeerManager tried set (core::CoinAddrMan, NODE_BLAKE2B-filtered) +
// explicit fork peers, so the pool grows across the whole known NODE_BLAKE2B
// address space. The primary coin_node.m_p2p is the PROTECTED/always-preferred
// path (python's local-node PROTECT): it is reached by broadcaster_full's ARM B
// (coin_node.submit_block_with_fallback), never dropped, and optionally excluded
// from the pool via set_primary_addr so a slot is not spent re-dialing it.
//
// EXPLICITLY OUT OF SCOPE for this LEAF (kept for PR-D persistence + soak, per
// the PR-C2 remaining map): per-peer broadcast scoring persistence, addr-gossip
// growth beyond the tried set, an inv->getdata WonBlockRelay handshake (raw
// submit_block_raw already caches the served block so a follow-up
// getdata(MSG_BLOCK) is answerable), and the live multi-node soak.
//
// ISOLATION FENCE: header-only leaf under src/impl/bip110/coin/*, template on
// the same duck-typed config the coin NodeP2P uses. No src/core / no src/pool
// edit; the coin-P2P push primitive, the addrman and the cross-coin policy all
// already exist and are only WIRED here.

#include "p2p_node.hpp"
#include "node_interface.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace bip110
{
namespace coin
{

// Pool of NODE_BLAKE2B coin-P2P node slots + discovery/fan-out. Non-consensus.
template <typename ConfigType>
class Bip110Broadcaster
{
public:
    using config_t = ConfigType;
    using Node = bip110::coin::p2p::NodeP2P<config_t>;
    using Slot = std::unique_ptr<Node>;

    // Injectable DIAL/slot factory. Default constructs a NodeP2P bound to the
    // io_context + coin interface + config and CONNECTs it to the fork peer.
    // Tests inject a stub factory so the selection pipeline runs without a live
    // dial.
    using SlotFactory = std::function<Slot(const NetService& /*addr*/)>;

    // Injectable per-slot liveness predicate. Defaults to is_handshake_complete
    // (a NODE_BLAKE2B peer that passed version/verack). Decoupled so tests drive
    // prune/live_count deterministically without a live peer.
    using LivePredicate = std::function<bool(const Node&)>;

    // Injectable per-slot fan-out hook. Returns TRUE iff the block was placed on
    // the slot's wire. Default pushes the raw block via submit_block_raw (BIP152
    // compact with full-block fallback; caches the block so a getdata(MSG_BLOCK)
    // is answerable). submit_block_raw_all counts the TRUE returns.
    using FanOutHook =
        std::function<bool(Node& /*slot*/, const std::vector<unsigned char>& /*block_bytes*/)>;

    Bip110Broadcaster(boost::asio::io_context* ioc,
                      bip110::interfaces::Node* coin,
                      config_t* config,
                      size_t max_peers)
        : m_ioc(ioc)
        , m_coin(coin)
        , m_config(config)
        , m_max_peers(max_peers)
        , m_factory(default_factory(ioc, coin, config))
        , m_is_live([](const Node& n) { return n.is_handshake_complete(); })
        , m_fan_out([](Node& n, const std::vector<unsigned char>& b) {
              return n.submit_block_raw(b);
          })
    {}

    // ── injection seams (tests / broadcaster_full) ───────────────────────────
    void set_slot_factory(SlotFactory f) { m_factory = std::move(f); }
    void set_live_predicate(LivePredicate p) { m_is_live = std::move(p); }
    void set_fan_out_hook(FanOutHook h) { m_fan_out = std::move(h); }

    // Exclude the primary coin-P2P peer (already reached by broadcaster_full's
    // ARM B) so a pool slot is not spent re-dialing it. Optional: a duplicate
    // connection to the primary is a harmless non-event, so leaving this unset
    // is safe, only slightly wasteful.
    void set_primary_addr(const NetService& addr) { m_primary_key = slot_key(addr); }

    // ── pure deterministic candidate selection ───────────────────────────────
    // From an addrman-backed candidate list (NetService, already NODE_BLAKE2B-
    // filtered upstream by BtcCoinPeerManager's valid_ports + version gate),
    // choose the endpoints to dial: exclude the primary, dedupe vs existing slots
    // AND within the batch, respect the per-key backoff, and cap so live + new
    // does not exceed max_peers. PURE: reads slot keys / backoff, creates nothing.
    std::vector<NetService> select_targets(const std::vector<NetService>& cands) const
    {
        std::vector<NetService> chosen;
        const auto now = std::chrono::steady_clock::now();
        const size_t live = live_count();
        std::map<std::string, bool> seen_this_batch;

        for (const auto& addr : cands) {
            if (live + chosen.size() >= m_max_peers) break;
            std::string key = slot_key(addr);
            if (key.empty()) continue;
            if (!m_primary_key.empty() && key == m_primary_key) continue; // primary
            if (m_slots.count(key)) continue;          // dedupe vs existing slots
            if (seen_this_batch.count(key)) continue;   // dedupe within batch
            auto bo = m_backoff.find(key);
            if (bo != m_backoff.end() && now < bo->second) continue; // backoff
            seen_this_batch[key] = true;
            chosen.push_back(addr);
        }
        return chosen;
    }

    // ── pool mutation ────────────────────────────────────────────────────────
    // One discovery pass over an addrman-backed candidate list: prune dead slots
    // first (reuse freed capacity), select, then dial each via the factory.
    // Returns the number of new slots created.
    size_t discover(const std::vector<NetService>& cands)
    {
        prune_dead();
        auto targets = select_targets(cands);
        size_t dialed = 0;
        for (const auto& addr : targets) {
            std::string key = slot_key(addr);
            if (key.empty() || m_slots.count(key)) continue;
            Slot slot = m_factory ? m_factory(addr) : Slot{};
            if (!slot) {
                m_backoff[key] = std::chrono::steady_clock::now()
                                 + std::chrono::minutes(1);
                continue;
            }
            m_slots[key] = std::move(slot);
            ++dialed;
        }
        if (dialed > 0)
            LOG_INFO << "[BIP110-Broadcast] discovery: dialed=" << dialed
                     << " slots=" << m_slots.size() << " live=" << live_count()
                     << "/" << m_max_peers;
        return dialed;
    }

    // Remove slots whose liveness predicate is false (never handshook / dropped)
    // and arm a backoff so the same dead address is not thrash-dialed by the next
    // pass. Returns count pruned.
    size_t prune_dead()
    {
        const auto now = std::chrono::steady_clock::now();
        size_t pruned = 0;
        for (auto it = m_slots.begin(); it != m_slots.end(); ) {
            const bool live = it->second && m_is_live && m_is_live(*it->second);
            if (!live) {
                m_backoff[it->first] = now + std::chrono::minutes(5);
                it = m_slots.erase(it);
                ++pruned;
            } else {
                ++it;
            }
        }
        return pruned;
    }

    // ── fan-out (the REAL block push) ─────────────────────────────────────────
    // Push the packed block to EVERY live slot via the fan-out hook. Robust: one
    // slot throwing/failing never aborts the others. Returns the number of live
    // slots that ACCEPTED the block (hook returned true).
    size_t submit_block_raw_all(const std::vector<unsigned char>& block_bytes)
    {
        size_t reached = 0;
        for (auto& [key, slot] : m_slots) {
            if (!(slot && m_is_live && m_is_live(*slot)))
                continue;
            try {
                if (m_fan_out && m_fan_out(*slot, block_bytes))
                    ++reached;
            } catch (const std::exception& e) {
                LOG_WARNING << "[BIP110-Broadcast] fan-out to " << key
                            << " threw (" << e.what() << ") — other peers continue";
            } catch (...) {
                LOG_WARNING << "[BIP110-Broadcast] fan-out to " << key
                            << " threw (non-std) — other peers continue";
            }
        }
        return reached;
    }

    // ── observers ─────────────────────────────────────────────────────────────
    size_t live_count() const
    {
        size_t n = 0;
        for (const auto& [key, slot] : m_slots)
            if (slot && m_is_live && m_is_live(*slot)) ++n;
        return n;
    }

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

private:
    static SlotFactory default_factory(boost::asio::io_context* ioc,
                                       bip110::interfaces::Node* coin,
                                       config_t* config)
    {
        return [ioc, coin, config](const NetService& addr) -> Slot {
            auto node = std::make_unique<Node>(ioc, coin, config, "BIP110-Fanout");
            // Single-peer coins run their own stall recovery; a fan-out slot must
            // NOT idle-evict itself between blocks (matches the primary's policy).
            node->set_idle_eviction_enabled(false);
            node->connect(addr);
            return node;
        };
    }

    static std::string slot_key(const NetService& addr)
    {
        return addr.address() + ":" + std::to_string(addr.port());
    }

    boost::asio::io_context*   m_ioc{};
    bip110::interfaces::Node*  m_coin{};
    config_t*                  m_config{};
    size_t                     m_max_peers{};
    std::string                m_primary_key;

    SlotFactory   m_factory;
    LivePredicate m_is_live;
    FanOutHook    m_fan_out;

    std::map<std::string, Slot>                                  m_slots;
    std::map<std::string, std::chrono::steady_clock::time_point> m_backoff;
};

} // namespace coin
} // namespace bip110
