// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_dial_plan.hpp
//
// Wave 1, component C1c: WHO TO DIAL, WHO TO DROP, AND WHO SPEAKS FOR THE
// CHAIN. Three pure decisions over the peer store and the live connection set,
// with no sockets, no clock of its own and no I/O -- which is the whole reason
// they are here instead of inline in the pool.
//
// 1. REFILL. Keep `target_outbound` handshaked peers. Dial in tier order --
//    anchors first, then white, then gray -- because that order is the eclipse
//    defence: an attacker who floods our gray list on restart still loses every
//    anchor slot, and the anchors were chosen before the flood began.
//
// 2. THE /16 NETGROUP CAP. At most `max_per_netgroup` connections may share a
//    /16. This is the only structural defence a client has against an attacker
//    who owns one netblock: without it, ten "different" peers can be ten
//    addresses on one machine and the node is eclipsed while its peer count
//    looks perfect. The cap is enforced in BOTH directions -- a dial into a
//    full group is not planned, and a group found over cap (which happens when
//    the operator pins peers, or when two dials race) contributes its NEWEST
//    member to the drop list. Newest, not worst: the older connection is the
//    one that has been feeding us blocks.
//
//    ECLIPSE FLOOR. `min_netgroups` is the separate, weaker assertion that the
//    connections we hold span at least N distinct /16s. It gates nothing here;
//    it is reported so the C4 arm resolver can refuse to demote the daemon
//    while the P2P side is structurally thin (plan §4.5's eclipse guard).
//
// 3. ROTATION. A peer set that never changes is a peer set an attacker only has
//    to win once. Every `rotation_interval_ms`, if we are AT target and have a
//    dialable alternative, the worst non-protected, non-primary peer older than
//    `min_peer_age_ms` is dropped so refill can try someone else. The age floor
//    matters: rotating a peer that just handshaked would churn the pool without
//    ever letting a connection prove itself.
//
// 4. PRIMARY ELECTION. Exactly one handshaked peer is the PRIMARY carrier -- the
//    peer whose chain we follow first and whose sync data drives the cohort
//    height. This mirrors the DASH pool's primary/witness split, and the
//    property that matters is HYSTERESIS: the primary changes only when a
//    challenger is better by a margin (`primary_switch_margin`), never on a
//    tie and never on a one-block flutter. Without the margin, two peers a
//    block apart hand the role back and forth on every TIMED_SYNC, and the sync
//    driver restarts its spans each time.
//
//    Order of preference: protected (the operator's own daemon) > strictly
//    greater cumulative difficulty > store score. Cumulative difficulty, not
//    height: height is what a lying peer inflates for free, and the C2 index
//    recomputes cumulative difficulty from verified blocks anyway, so an
//    inflated claim only ever costs the liar its own slot.
//
// SEEDS ARE A LAST RESORT. `use_seeds` is set only when the store has NOTHING
// dialable left. monerod treats its seed nodes the same way, and the reason is
// load: five hardcoded addresses serve the whole network, and a client that
// dials them on every refill is a client the seed operators eventually block.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
//
// Header-only, STL only. Every decision here is a pure function of its inputs.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/p2p/xmr_peer_store.hpp"

namespace c2pool::xmr::native::p2p {

struct DialPlanConfig {
    std::size_t target_outbound = 8;    // steady-state handshaked peers
    std::size_t max_outbound    = 16;   // hard ceiling incl. in-flight dials
    std::size_t max_concurrent_dials = 4;

    // Eclipse geometry.
    std::size_t max_per_netgroup = 2;   // /16 cap on CONNECTIONS
    std::size_t min_netgroups    = 3;   // reported floor, see header

    // Anchors get their own reserved share of the target.
    std::size_t anchor_slots = 2;

    // Rotation.
    Millis rotation_interval_ms = 15 * 60 * 1000;
    Millis min_peer_age_ms      = 10 * 60 * 1000;

    // Primary hysteresis: a challenger must beat the incumbent's cumulative
    // difficulty by more than this to take the role. In practice one stagenet
    // block of difficulty; expressed as a raw 128-bit delta so it needs no
    // chain state to evaluate.
    U128 primary_switch_margin{/*lo=*/0, /*hi=*/0};
};

// One live connection, as the plan sees it. The pool fills this in; nothing
// here reaches into a socket.
struct LivePeer {
    std::string   key;
    std::uint32_t netgroup = 0;
    std::uint64_t peer_id  = 0;
    bool          handshaked = false;
    bool          is_protected = false;
    Millis        connected_at_ms = 0;
    Millis        handshaked_at_ms = 0;
    PeerSyncData  sync{};        // last advertised CORE_SYNC_DATA
    Millis        last_sync_ms = 0;
    bool          dialing = false;   // TCP connect in flight, not yet handshaked
};

enum class DropReason : std::uint8_t {
    NetgroupOverCap = 0,
    Rotation,
    OverTarget,
};

inline const char* to_string(DropReason r) noexcept {
    switch (r) {
        case DropReason::NetgroupOverCap: return "netgroup-over-cap";
        case DropReason::Rotation:        return "rotation";
        case DropReason::OverTarget:      return "over-target";
    }
    return "?";
}

struct DialDecision {
    std::vector<std::string> dial;                      // addresses to connect, in order
    std::vector<std::pair<std::string, DropReason>> drop;
    bool        use_seeds = false;                      // nothing dialable left
    std::size_t handshaked = 0;
    std::size_t in_flight  = 0;
    std::size_t netgroups  = 0;                         // distinct /16s held
    bool        eclipse_floor_met = false;              // netgroups >= min_netgroups
};

// ---------------------------------------------------------------------------
// The plan. Stateless except for the rotation clock, which is one timestamp.
// ---------------------------------------------------------------------------
class DialPlan {
public:
    explicit DialPlan(DialPlanConfig cfg = {}) : cfg_(cfg) {}

    const DialPlanConfig& config() const noexcept { return cfg_; }
    void set_config(DialPlanConfig cfg) noexcept { cfg_ = cfg; }

    // Marks the moment the rotation clock last fired. The pool calls this after
    // acting on a Rotation drop so a plan that is never executed does not
    // consume the interval.
    void note_rotation(Millis now) noexcept { last_rotation_ms_ = now; }
    Millis last_rotation_ms() const noexcept { return last_rotation_ms_; }

    DialDecision plan(const PeerStore& store,
                      const std::vector<LivePeer>& live,
                      Millis now) const {
        DialDecision d;

        // --- census -----------------------------------------------------------
        std::map<std::uint32_t, std::vector<const LivePeer*>> by_group;
        std::size_t handshaked = 0, in_flight = 0;
        for (const LivePeer& p : live) {
            if (p.handshaked) ++handshaked; else ++in_flight;
            by_group[p.netgroup].push_back(&p);
        }
        d.handshaked = handshaked;
        d.in_flight  = in_flight;
        d.netgroups  = by_group.size();
        d.eclipse_floor_met = by_group.size() >= cfg_.min_netgroups;

        // --- 1. netgroup cap, enforced on what we already hold -----------------
        // Newest first out: the older connection is the one already earning.
        std::vector<std::string> dropped;
        for (auto& [group, members] : by_group) {
            if (members.size() <= cfg_.max_per_netgroup) continue;
            std::vector<const LivePeer*> sorted = members;
            std::sort(sorted.begin(), sorted.end(), [](const LivePeer* a, const LivePeer* b) {
                if (a->is_protected != b->is_protected) return !a->is_protected;  // pins last
                if (a->connected_at_ms != b->connected_at_ms)
                    return a->connected_at_ms > b->connected_at_ms;               // newest first
                return a->key > b->key;
            });
            std::size_t over = members.size() - cfg_.max_per_netgroup;
            for (const LivePeer* p : sorted) {
                if (over == 0) break;
                if (p->is_protected) continue;   // an operator pin is never dropped
                d.drop.emplace_back(p->key, DropReason::NetgroupOverCap);
                dropped.push_back(p->key);
                --over;
            }
        }

        // --- 2. over target ----------------------------------------------------
        std::size_t effective = handshaked;
        for (const std::string& k : dropped) {
            (void)k;
            if (effective > 0) --effective;
        }
        if (effective > cfg_.target_outbound) {
            std::vector<const LivePeer*> worst = rank_droppable(store, live, dropped, now);
            std::size_t over = effective - cfg_.target_outbound;
            for (const LivePeer* p : worst) {
                if (over == 0) break;
                d.drop.emplace_back(p->key, DropReason::OverTarget);
                dropped.push_back(p->key);
                --over;
                --effective;
            }
        }

        // --- 3. rotation -------------------------------------------------------
        // Only at target, only on the interval, only one peer, and only when
        // there is somebody else to try.
        if (effective >= cfg_.target_outbound && cfg_.rotation_interval_ms > 0
            && now >= last_rotation_ms_ + cfg_.rotation_interval_ms) {
            std::vector<const LivePeer*> worst = rank_droppable(store, live, dropped, now);
            const LivePeer* victim = nullptr;
            for (const LivePeer* p : worst) {
                if (p->handshaked_at_ms == 0) continue;
                if (now < p->handshaked_at_ms + cfg_.min_peer_age_ms) continue;
                victim = p;
                break;
            }
            if (victim && has_fresh_alternative(store, live, dropped, victim->key, now)) {
                d.drop.emplace_back(victim->key, DropReason::Rotation);
                dropped.push_back(victim->key);
                --effective;
            }
        }

        // --- 4. refill ---------------------------------------------------------
        std::size_t want = 0;
        const std::size_t occupied = effective + in_flight;
        if (occupied < cfg_.target_outbound) want = cfg_.target_outbound - occupied;
        want = std::min(want, cfg_.max_concurrent_dials > in_flight
                                  ? cfg_.max_concurrent_dials - in_flight : 0u);
        if (occupied + want > cfg_.max_outbound)
            want = cfg_.max_outbound > occupied ? cfg_.max_outbound - occupied : 0;

        if (want > 0) {
            // Live group occupancy AFTER the drops we just planned.
            std::map<std::uint32_t, std::size_t> occ;
            std::vector<std::string> held;
            for (const LivePeer& p : live) {
                if (std::find(dropped.begin(), dropped.end(), p.key) != dropped.end()) continue;
                ++occ[p.netgroup];
                held.push_back(p.key);
            }

            // Anchors first, then white, then gray. Reserving anchor_slots means
            // a node with plenty of white peers still spends part of its budget
            // re-reaching the set it trusted before the last restart.
            const std::size_t anchors_held = count_tier_held(store, held, PeerTier::Anchor);
            const std::size_t anchor_want =
                anchors_held < cfg_.anchor_slots ? cfg_.anchor_slots - anchors_held : 0;

            take(store, PeerTier::Anchor, true, std::min(want, anchor_want), occ, held, d, now);
            if (d.dial.size() < want)
                take(store, PeerTier::White, true, want - d.dial.size(), occ, held, d, now);
            if (d.dial.size() < want)
                take(store, PeerTier::Gray, true, want - d.dial.size(), occ, held, d, now);

            // Nothing dialable in any tier and we are below target: fall back to
            // the compiled-in seeds. This is the ONLY path that sets use_seeds.
            if (d.dial.empty()) d.use_seeds = true;
        }
        return d;
    }

    // -----------------------------------------------------------------------
    // Primary election. `incumbent` is the current primary's key ("" = none).
    // Returns the key that should hold the role.
    // -----------------------------------------------------------------------
    std::string elect_primary(const std::vector<LivePeer>& live,
                              const PeerStore&             store,
                              const std::string&           incumbent,
                              Millis                       now) const {
        const LivePeer* best = nullptr;
        const LivePeer* inc  = nullptr;
        for (const LivePeer& p : live) {
            if (!p.handshaked) continue;
            if (p.key == incumbent) inc = &p;
            if (!best || better_primary(p, *best, store, now)) best = &p;
        }
        if (!best) return {};
        if (!inc) return best->key;                 // incumbent is gone
        if (best->key == inc->key) return inc->key;

        // Hysteresis. A protected peer takes the role immediately (the operator
        // pinned it for exactly this); anyone else must clear the margin.
        if (best->is_protected && !inc->is_protected) return best->key;
        if (inc->is_protected) return inc->key;

        const U128 threshold = u128_add(inc->sync.cumulative_difficulty,
                                        cfg_.primary_switch_margin);
        if (u128_greater(best->sync.cumulative_difficulty, threshold)) return best->key;
        return inc->key;
    }

private:
    static bool better_primary(const LivePeer& a, const LivePeer& b,
                               const PeerStore& store, Millis now) {
        if (a.is_protected != b.is_protected) return a.is_protected;
        if (!(a.sync.cumulative_difficulty == b.sync.cumulative_difficulty))
            return u128_greater(a.sync.cumulative_difficulty, b.sync.cumulative_difficulty);
        const PeerRecord* ra = store.find(a.key);
        const PeerRecord* rb = store.find(b.key);
        const std::int64_t sa = ra ? ra->score(now) : 0;
        const std::int64_t sb = rb ? rb->score(now) : 0;
        if (sa != sb) return sa > sb;
        return a.key < b.key;                       // total order, so the KAT can pin it
    }

    static std::size_t count_tier_held(const PeerStore& store,
                                       const std::vector<std::string>& held,
                                       PeerTier tier) {
        std::size_t n = 0;
        for (const std::string& k : held) {
            const PeerRecord* r = store.find(k);
            if (r && r->tier == tier) ++n;
        }
        return n;
    }

    // Live peers ordered worst-first, skipping protected peers and anything
    // already on the drop list.
    static std::vector<const LivePeer*> rank_droppable(const PeerStore& store,
                                                       const std::vector<LivePeer>& live,
                                                       const std::vector<std::string>& dropped,
                                                       Millis now) {
        std::vector<const LivePeer*> out;
        for (const LivePeer& p : live) {
            if (!p.handshaked || p.is_protected) continue;
            if (std::find(dropped.begin(), dropped.end(), p.key) != dropped.end()) continue;
            out.push_back(&p);
        }
        std::sort(out.begin(), out.end(), [&store, now](const LivePeer* a, const LivePeer* b) {
            const PeerRecord* ra = store.find(a->key);
            const PeerRecord* rb = store.find(b->key);
            const std::int64_t sa = ra ? ra->score(now) : 0;
            const std::int64_t sb = rb ? rb->score(now) : 0;
            if (sa != sb) return sa < sb;                       // worst first
            if (a->handshaked_at_ms != b->handshaked_at_ms)
                return a->handshaked_at_ms > b->handshaked_at_ms;  // newest first
            return a->key < b->key;
        });
        return out;
    }

    static bool has_fresh_alternative(const PeerStore& store,
                                      const std::vector<LivePeer>& live,
                                      const std::vector<std::string>& dropped,
                                      const std::string& victim,
                                      Millis now) {
        for (const PeerRecord* r : store.candidates(now)) {
            if (r->key == victim) continue;
            if (std::find(dropped.begin(), dropped.end(), r->key) != dropped.end()) continue;
            bool connected = false;
            for (const LivePeer& p : live) if (p.key == r->key) { connected = true; break; }
            if (!connected) return true;
        }
        return false;
    }

    // Append up to `n` dial targets from one tier, respecting the /16 cap and
    // never dialing an address we already hold or already planned.
    void take(const PeerStore& store, PeerTier tier, bool exact, std::size_t n,
              std::map<std::uint32_t, std::size_t>& occ,
              const std::vector<std::string>& held,
              DialDecision& d, Millis now) const {
        if (n == 0) return;
        for (const PeerRecord* r : store.candidates(now, tier, exact)) {
            if (n == 0) break;
            if (std::find(held.begin(), held.end(), r->key) != held.end()) continue;
            if (std::find(d.dial.begin(), d.dial.end(), r->key) != d.dial.end()) continue;
            // A protected peer is exempt from the netgroup cap: the operator
            // asked for it by name, and a pin that silently never dials is
            // worse than a slightly lopsided peer set.
            if (!r->is_protected) {
                auto it = occ.find(r->netgroup);
                const std::size_t have = it == occ.end() ? 0 : it->second;
                if (have >= cfg_.max_per_netgroup) continue;
            }
            ++occ[r->netgroup];
            d.dial.push_back(r->key);
            --n;
        }
    }

    DialPlanConfig cfg_;
    mutable Millis last_rotation_ms_ = 0;
};

} // namespace c2pool::xmr::native::p2p
