// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_peer_store.hpp
//
// Wave 1, component C1c: the scored peer store -- white / gray / anchor, the
// /16 netgroup index, backoff, the fail score and the ban list.
//
// WHERE ADDRESSES COME FROM, and why the store is small. Monero has no addr
// gossip and no getaddr: a peerlist arrives ONLY inside a HANDSHAKE or
// TIMED_SYNC response, at most P2P_MAX_PEERS_IN_HANDSHAKE (250) entries, and
// each entry is {adr, id, last_seen, pruning_seed, rpc_port,
// rpc_credits_per_hash}. So the store's whole input is: the compiled-in seeds
// (chain_seeds.hpp), whatever the operator pinned, and those bounded lists.
//
// THE THREE TIERS are monerod's own, and each one means something different:
//
//   * GRAY   -- an address someone told us about. Never dialed successfully by
//               us. Its `last_seen` is the PEER'S claim, not our observation.
//   * WHITE  -- an address WE have completed a handshake with. Promotion is by
//               our own observation only; a peer cannot talk itself white.
//   * ANCHOR -- a white peer we were connected to when the process last shut
//               down (or, here, when the pool last had a healthy connection to
//               it). monerod keeps a handful and dials them FIRST on restart,
//               and the reason is the eclipse attack: an attacker who fills a
//               restarting node's gray list wins the whole peer set unless some
//               of the dials go to peers chosen before the attack began.
//
// Tier is a RATCHET UPWARD within a session (gray -> white -> anchor) and falls
// only through eviction or a ban. That asymmetry is deliberate: a peer that
// once proved itself and is now merely unreachable should keep its priority
// over an unproven address a stranger just handed us.
//
// SCORING. Ordering candidates is not a beauty contest, it is an eclipse
// budget: the score exists so that the dial plan spends its scarce outbound
// slots on peers with a demonstrated history rather than on a flood of
// freshly-injected gray addresses. Protected (operator-pinned) peers outrank
// everything by construction, and are never evicted, never banned and never
// rotated out -- the "pinned local monerod" of the C6 parity phase.
//
// BAN vs BACKOFF, which are NOT the same thing:
//   * backoff  -- "this address did not answer; try later". Exponential per
//                 address, capped, forgotten after P2P_FAILED_ADDR_FORGET
//                 (3600 s) of quiet. A cost, not a judgement.
//   * fail score / ban -- "this address MISBEHAVED". Points accrue
//                 (P2P_IP_FAILS_BEFORE_BLOCK = 10 is the ban threshold) and a
//                 ban lasts P2P_IP_BLOCKTIME (86400 s). A confirmed bad PoW is
//                 the whole threshold on its own. Bans are keyed by the /16
//                 netgroup as well as by the address, because a single hostile
//                 operator with a /24 would otherwise cost us ten bans and ten
//                 dial budgets to shake off.
//
// TIME. Everything takes an injected monotonic millisecond clock. There is no
// steady_clock::now() anywhere in this file, which is what makes the ban decay,
// the backoff ladder and the forget window testable in microseconds.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record.
//
// Header-only, STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/p2p/levin_invoke_queue.hpp"   // Millis

namespace c2pool::xmr::native::p2p {

using levin::Millis;

// ---------------------------------------------------------------------------
// monerod's own limits (p2p/net_node.h, cryptonote_config.h). Named rather than
// inlined so a divergence from upstream is a one-line diff.
// ---------------------------------------------------------------------------
inline constexpr std::size_t P2P_WHITE_LIST_LIMIT   = 1000;  // P2P_LOCAL_WHITE_PEERLIST_LIMIT
inline constexpr std::size_t P2P_GRAY_LIST_LIMIT    = 5000;  // P2P_LOCAL_GRAY_PEERLIST_LIMIT
inline constexpr std::size_t P2P_ANCHOR_LIST_LIMIT  = 8;
inline constexpr std::uint32_t P2P_FAILS_BEFORE_BAN = 10;    // P2P_IP_FAILS_BEFORE_BLOCK
inline constexpr Millis P2P_IP_BLOCKTIME_MS         = 86'400'000;  // P2P_IP_BLOCKTIME (24 h)
inline constexpr Millis P2P_FAILED_ADDR_FORGET_MS   = 3'600'000;   // P2P_FAILED_ADDR_FORGET_SECONDS

inline constexpr Millis BACKOFF_BASE_MS      = 30'000;
inline constexpr Millis BACKOFF_CAP_MS       = 3'600'000;
inline constexpr Millis BACKOFF_CAP_PINNED_MS= 600'000;   // an operator-pinned peer retries harder

enum class PeerTier : std::uint8_t { Gray = 0, White = 1, Anchor = 2 };

inline const char* to_string(PeerTier t) noexcept {
    switch (t) {
        case PeerTier::Gray:   return "gray";
        case PeerTier::White:  return "white";
        case PeerTier::Anchor: return "anchor";
    }
    return "?";
}

// How we learned about the address. Feeds the score, and separates "the
// operator told me" from "a stranger told me".
enum class PeerSource : std::uint8_t {
    Manual = 0,   // --xmr-p2p-connect; protected
    Anchor,       // restored from the anchor file
    IpSeed,       // compiled-in fallback
    DnsSeed,      // resolved from a DNS seed host
    Peerlist,     // learned inside a HANDSHAKE / TIMED_SYNC response
};

inline const char* to_string(PeerSource s) noexcept {
    switch (s) {
        case PeerSource::Manual:   return "manual";
        case PeerSource::Anchor:   return "anchor";
        case PeerSource::IpSeed:   return "ip-seed";
        case PeerSource::DnsSeed:  return "dns-seed";
        case PeerSource::Peerlist: return "peerlist";
    }
    return "?";
}

struct PeerRecord {
    std::string   key;          // "ip:port", the identity everywhere in C1c
    std::string   ip;
    std::uint16_t port      = 0;
    std::uint32_t netgroup  = 0;      // /16
    std::uint64_t peer_id   = 0;      // levin id, learned at handshake
    std::uint32_t pruning_seed = 0;   // from the peerlist entry; 0 = unpruned

    PeerTier   tier   = PeerTier::Gray;
    PeerSource source = PeerSource::Peerlist;
    bool       is_protected = false;  // operator-pinned: never evicted, never banned

    // Observations. `last_seen_claimed_s` is the PEER's number and is used only
    // as a weak freshness tiebreak; everything else is ours.
    std::int64_t last_seen_claimed_s = 0;
    Millis first_known_ms  = 0;
    Millis last_attempt_ms = 0;
    Millis last_success_ms = 0;
    Millis last_failure_ms = 0;

    std::uint32_t attempts  = 0;
    std::uint32_t successes = 0;
    std::uint32_t failures  = 0;      // consecutive dial failures
    Millis        backoff_ms = 0;

    std::uint32_t fail_score    = 0;  // misbehaviour points
    Millis        banned_until_ms = 0;

    bool banned(Millis now) const noexcept {
        return !is_protected && banned_until_ms > now;
    }

    // Ready to dial: not banned, and past its backoff window.
    //
    // A protected peer is exempt from BANS, not from backoff. Exempting it from
    // backoff too would make a pinned daemon that is down (or that refuses us)
    // a redial on every maintenance tick, forever. What being pinned buys is
    // the lower ladder cap in on_dial_failed(): it retries harder, not
    // continuously.
    bool dialable(Millis now) const noexcept {
        if (banned(now)) return false;
        if (last_attempt_ms == 0) return true;
        return now >= last_attempt_ms + backoff_ms;
    }

    // Ordering key for the dial plan. Higher is dialed first.
    //
    // The weights encode the eclipse budget described in the file header:
    // an operator pin outranks the tier ladder, the tier ladder outranks source
    // provenance, and provenance outranks raw success history -- so a hostile
    // flood of gray peerlist entries can never outbid a single proven white
    // peer no matter how many of them arrive.
    std::int64_t score(Millis now) const noexcept {
        if (is_protected) return 1'000'000;
        std::int64_t s = 0;
        switch (tier) {
            case PeerTier::Anchor: s += 4000; break;
            case PeerTier::White:  s += 2000; break;
            case PeerTier::Gray:   break;
        }
        switch (source) {
            case PeerSource::Manual:   s += 800; break;
            case PeerSource::Anchor:   s += 600; break;
            case PeerSource::IpSeed:   s += 200; break;
            case PeerSource::DnsSeed:  s += 200; break;
            case PeerSource::Peerlist: s += 100; break;
        }
        s += std::min<std::int64_t>(successes, 20) * 25;
        s -= std::min<std::int64_t>(failures, 20) * 40;
        s -= static_cast<std::int64_t>(fail_score) * 30;
        // Recency of OUR last success, decayed over an hour.
        if (last_success_ms != 0 && now >= last_success_ms) {
            const Millis age = now - last_success_ms;
            if (age < 3'600'000) s += static_cast<std::int64_t>(300 - (age * 300) / 3'600'000);
        }
        return s;
    }
};

// ---------------------------------------------------------------------------
// The store. Not thread-safe by design: it lives on the io thread beside the
// peer pool, exactly like monerod's peerlist under its own lock discipline.
// ---------------------------------------------------------------------------
class PeerStore {
public:
    struct Limits {
        std::size_t white  = P2P_WHITE_LIST_LIMIT;
        std::size_t gray   = P2P_GRAY_LIST_LIMIT;
        std::size_t anchor = P2P_ANCHOR_LIST_LIMIT;
        std::uint32_t fails_before_ban = P2P_FAILS_BEFORE_BAN;
        Millis ban_ms          = P2P_IP_BLOCKTIME_MS;
        Millis fail_forget_ms  = P2P_FAILED_ADDR_FORGET_MS;
        Millis backoff_base_ms = BACKOFF_BASE_MS;
        Millis backoff_cap_ms  = BACKOFF_CAP_MS;
    };

    // Two constructors rather than one with `Limits lim = {}`: `Limits` is a
    // NESTED class, so its member initializers are not yet parsed at the point
    // a default argument in the same class would need them.
    PeerStore() = default;
    explicit PeerStore(Limits lim) : lim_(lim) {}

    // --- population ---------------------------------------------------------
    // Adds or refreshes an address. Returns a pointer to the stored record, or
    // nullptr when the address was refused (unparseable key, or a full gray
    // list with nothing worse to evict).
    //
    // A record that already exists is never DOWNGRADED by a second sighting:
    // a peerlist entry naming a peer we have handshaked leaves it white.
    PeerRecord* add(const std::string& key, PeerSource src, Millis now,
                    std::int64_t last_seen_claimed_s = 0,
                    std::uint64_t peer_id = 0,
                    std::uint32_t pruning_seed = 0) {
        std::string ip;
        std::uint16_t port = 0;
        if (!split_peer_key(key, ip, port)) return nullptr;

        auto it = peers_.find(key);
        if (it != peers_.end()) {
            PeerRecord& r = it->second;
            if (last_seen_claimed_s > r.last_seen_claimed_s) r.last_seen_claimed_s = last_seen_claimed_s;
            if (peer_id != 0) r.peer_id = peer_id;
            if (pruning_seed != 0) r.pruning_seed = pruning_seed;
            // Provenance ratchets toward the more trusted source only.
            if (static_cast<int>(src) < static_cast<int>(r.source)) r.source = src;
            if (src == PeerSource::Manual) r.is_protected = true;
            return &r;
        }

        if (count_tier(PeerTier::Gray) >= lim_.gray && src != PeerSource::Manual) {
            if (!evict_worst(PeerTier::Gray, now)) return nullptr;
        }

        PeerRecord r;
        r.key      = key;
        r.ip       = ip;
        r.port     = port;
        r.netgroup = netgroup16(ip);
        r.peer_id  = peer_id;
        r.pruning_seed = pruning_seed;
        r.source   = src;
        r.tier     = (src == PeerSource::Anchor) ? PeerTier::Anchor : PeerTier::Gray;
        r.is_protected = (src == PeerSource::Manual);
        r.last_seen_claimed_s = last_seen_claimed_s;
        r.first_known_ms = now;
        auto ins = peers_.emplace(key, std::move(r));
        return &ins.first->second;
    }

    // Bulk-add a peerlist that arrived inside a 1001/1002 response. Returns how
    // many were newly learned. The caller has already enforced the 250-entry
    // wire cap (levin_messages.hpp); this is the policy half.
    std::size_t add_peerlist(const std::vector<std::pair<std::string, std::int64_t>>& entries,
                             Millis now) {
        std::size_t learned = 0;
        for (const auto& [key, seen] : entries) {
            const bool was_known = peers_.count(key) != 0;
            if (add(key, PeerSource::Peerlist, now, seen) && !was_known) ++learned;
        }
        return learned;
    }

    // --- observations -------------------------------------------------------
    void on_dial_started(const std::string& key, Millis now) {
        if (PeerRecord* r = find(key)) {
            r->last_attempt_ms = now;
            ++r->attempts;
        }
    }

    // A completed handshake. THE ONLY promotion path to white.
    void on_handshaked(const std::string& key, std::uint64_t peer_id, Millis now) {
        PeerRecord* r = find(key);
        if (!r) r = add(key, PeerSource::Peerlist, now);
        if (!r) return;
        r->peer_id = peer_id;
        r->last_success_ms = now;
        ++r->successes;
        r->failures   = 0;
        r->backoff_ms = 0;
        if (r->tier == PeerTier::Gray) {
            if (count_tier(PeerTier::White) >= lim_.white) evict_worst(PeerTier::White, now);
            r->tier = PeerTier::White;
        }
    }

    // A dial that never reached a handshake. Backoff doubles; the address is
    // NOT scored down -- unreachable is not misbehaviour.
    void on_dial_failed(const std::string& key, Millis now) {
        PeerRecord* r = find(key);
        if (!r) return;
        ++r->failures;
        r->last_failure_ms = now;
        r->last_attempt_ms = now;
        const Millis cap = r->is_protected ? BACKOFF_CAP_PINNED_MS : lim_.backoff_cap_ms;
        r->backoff_ms = r->backoff_ms == 0 ? lim_.backoff_base_ms
                                           : std::min<Millis>(r->backoff_ms * 2, cap);
    }

    // A handshaked connection ended cleanly (rotation, shutdown, peer closed).
    // The peer keeps its tier and gets a short backoff so refill does not
    // immediately redial the peer it just rotated away from.
    void on_disconnected(const std::string& key, Millis now, bool was_healthy) {
        PeerRecord* r = find(key);
        if (!r) return;
        r->last_attempt_ms = now;
        r->backoff_ms = was_healthy ? lim_.backoff_base_ms
                                    : std::min<Millis>(std::max<Millis>(r->backoff_ms * 2,
                                                                        lim_.backoff_base_ms),
                                                       lim_.backoff_cap_ms);
        if (was_healthy) promote_anchor(*r, now);
    }

    // --- misbehaviour -------------------------------------------------------
    // Adds points. Returns true when the peer crossed into a ban. Protected
    // peers accrue points (so the operator can see the damage in telemetry) but
    // are never banned.
    bool penalize(const std::string& key, std::uint32_t points, Millis now) {
        PeerRecord* r = find(key);
        if (!r) return false;
        forget_stale_score(*r, now);
        r->fail_score += points;
        r->last_failure_ms = now;
        if (r->is_protected) return false;
        if (r->fail_score >= lim_.fails_before_ban) {
            ban(key, lim_.ban_ms, now);
            return true;
        }
        return false;
    }

    void ban(const std::string& key, Millis duration_ms, Millis now) {
        PeerRecord* r = find(key);
        if (!r || r->is_protected) return;
        r->banned_until_ms = std::max<Millis>(r->banned_until_ms, now + duration_ms);
        // The /16 goes with it: one operator behind a /24 must not cost us 256
        // separate bans and 256 separate dial budgets.
        banned_groups_[r->netgroup] = std::max<Millis>(banned_groups_[r->netgroup],
                                                       r->banned_until_ms);
    }

    bool is_banned(const std::string& key, Millis now) const {
        auto it = peers_.find(key);
        if (it != peers_.end()) {
            if (it->second.is_protected) return false;
            if (it->second.banned(now)) return true;
            return group_banned(it->second.netgroup, now);
        }
        return group_banned(netgroup16_of_key(key), now);
    }

    bool group_banned(std::uint32_t netgroup, Millis now) const {
        auto it = banned_groups_.find(netgroup);
        return it != banned_groups_.end() && it->second > now;
    }

    // --- reads --------------------------------------------------------------
    PeerRecord* find(const std::string& key) {
        auto it = peers_.find(key);
        return it == peers_.end() ? nullptr : &it->second;
    }
    const PeerRecord* find(const std::string& key) const {
        auto it = peers_.find(key);
        return it == peers_.end() ? nullptr : &it->second;
    }

    std::size_t size() const noexcept { return peers_.size(); }

    std::size_t count_tier(PeerTier t) const {
        std::size_t n = 0;
        for (const auto& [k, r] : peers_) if (r.tier == t) ++n;
        return n;
    }

    // Dialable candidates, best first. `tier_floor` restricts the pass (the
    // dial plan runs anchor-first, then white, then gray).
    std::vector<const PeerRecord*> candidates(Millis now, PeerTier tier_floor = PeerTier::Gray,
                                              bool exact_tier = false) const {
        std::vector<const PeerRecord*> out;
        out.reserve(peers_.size());
        for (const auto& [k, r] : peers_) {
            if (exact_tier ? (r.tier != tier_floor)
                           : (static_cast<int>(r.tier) < static_cast<int>(tier_floor))) continue;
            if (!r.dialable(now)) continue;
            if (group_banned(r.netgroup, now) && !r.is_protected) continue;
            out.push_back(&r);
        }
        // Deterministic: score, then the key, so two runs of the same state
        // produce the same dial order and a KAT can pin it.
        std::sort(out.begin(), out.end(), [now](const PeerRecord* a, const PeerRecord* b) {
            const std::int64_t sa = a->score(now), sb = b->score(now);
            if (sa != sb) return sa > sb;
            return a->key < b->key;
        });
        return out;
    }

    // The anchor set to persist at shutdown, best first.
    std::vector<std::string> anchor_keys() const {
        std::vector<const PeerRecord*> a;
        for (const auto& [k, r] : peers_) if (r.tier == PeerTier::Anchor) a.push_back(&r);
        std::sort(a.begin(), a.end(), [](const PeerRecord* x, const PeerRecord* y) {
            if (x->last_success_ms != y->last_success_ms) return x->last_success_ms > y->last_success_ms;
            return x->key < y->key;
        });
        std::vector<std::string> out;
        for (const PeerRecord* r : a) out.push_back(r->key);
        return out;
    }

    // Seed the store from the compiled-in tables. Called only when the store
    // has nothing dialable left -- see DialPlan::plan().
    std::size_t seed_from_tables(XmrNet net, Millis now) {
        std::size_t added = 0;
        for (const IpSeed& s : ip_seeds(net))
            if (add(make_peer_key(s.ip, s.port), PeerSource::IpSeed, now)) ++added;
        return added;
    }

    const std::unordered_map<std::string, PeerRecord>& all() const noexcept { return peers_; }

private:
    void promote_anchor(PeerRecord& r, Millis now) {
        if (r.tier == PeerTier::Anchor) return;
        if (r.tier != PeerTier::White) return;
        if (count_tier(PeerTier::Anchor) >= lim_.anchor) {
            // Displace the STALEST anchor, never the freshest: the point of the
            // set is that it predates any ongoing flood.
            PeerRecord* worst = nullptr;
            for (auto& [k, o] : peers_) {
                if (o.tier != PeerTier::Anchor || o.is_protected) continue;
                if (!worst || o.last_success_ms < worst->last_success_ms) worst = &o;
            }
            if (!worst || worst->last_success_ms >= r.last_success_ms) return;
            worst->tier = PeerTier::White;
        }
        r.tier = PeerTier::Anchor;
        (void)now;
    }

    // Points decay: an address quiet for the forget window starts clean, which
    // is what stops a long-lived honest peer from accumulating a ban over days
    // of unrelated one-off faults.
    // `fail_score == 0` is the only guard needed: a zero last_failure_ms is a
    // legitimate timestamp (millisecond zero of the pool's epoch), not a
    // sentinel, and treating it as one would freeze that address's score.
    void forget_stale_score(PeerRecord& r, Millis now) {
        if (r.fail_score == 0) return;
        if (now >= r.last_failure_ms + lim_.fail_forget_ms) r.fail_score = 0;
    }

    bool evict_worst(PeerTier tier, Millis now) {
        PeerRecord* worst = nullptr;
        std::int64_t worst_score = 0;
        for (auto& [k, r] : peers_) {
            if (r.tier != tier || r.is_protected) continue;
            const std::int64_t s = r.score(now);
            if (!worst || s < worst_score) { worst = &r; worst_score = s; }
        }
        if (!worst) return false;
        peers_.erase(worst->key);
        return true;
    }

    Limits lim_{};
    std::unordered_map<std::string, PeerRecord> peers_;
    std::map<std::uint32_t, Millis>             banned_groups_;
};

} // namespace c2pool::xmr::native::p2p
