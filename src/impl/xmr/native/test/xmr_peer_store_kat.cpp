// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_peer_store_kat.cpp
//
// Wave 1, C1c: the peer store (white / gray / anchor, backoff, ban) and the
// dial plan (refill, /16 netgroup cap, rotation, primary election).
//
// Every check here is a pure function of an injected millisecond clock; there
// is no socket, no thread and no wall clock in this file, which is what makes a
// 24-hour ban and a 15-minute rotation testable in microseconds.
//
// The four properties worth naming, because each one is a real attack:
//
//   * TIER RATCHET. Only OUR OWN completed handshake promotes gray -> white. A
//     peer cannot talk itself white by claiming a good last_seen, and a later
//     peerlist sighting cannot demote a peer we have proven.
//   * NETGROUP CAP. At most max_per_netgroup CONNECTIONS share a /16, enforced
//     both when planning a dial and when a group is found over cap. Without it
//     ten "peers" can be ten addresses on one machine and the node is eclipsed
//     while its peer count looks perfect.
//   * BAN CARRIES THE /16. One hostile operator behind a /24 must not cost ten
//     separate bans and ten separate dial budgets.
//   * PRIMARY HYSTERESIS. The carrier changes only on a margin, never on a tie
//     and never on a one-block flutter, or two peers a block apart hand the
//     role back and forth on every TIMED_SYNC.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/xmr_dial_plan.hpp"
#include "impl/xmr/native/p2p/xmr_peer_store.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace p2p    = c2pool::xmr::native::p2p;
namespace kat    = c2pool::xmr::native::kat;
using p2p::Millis;
using p2p::PeerSource;
using p2p::PeerStore;
using p2p::PeerTier;

namespace {

constexpr Millis SEC = 1000;
constexpr Millis MIN = 60 * SEC;

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

std::vector<std::string> keys_of(const std::vector<const p2p::PeerRecord*>& v) {
    std::vector<std::string> out;
    for (const p2p::PeerRecord* r : v) out.push_back(r->key);
    return out;
}

p2p::LivePeer live(const std::string& key, Millis handshaked_at, std::uint64_t cumdiff_lo) {
    p2p::LivePeer p;
    p.key              = key;
    p.netgroup         = p2p::netgroup16_of_key(key);
    p.handshaked       = true;
    p.connected_at_ms  = handshaked_at;
    p.handshaked_at_ms = handshaked_at;
    p.sync.cumulative_difficulty = native::U128{cumdiff_lo, 0};
    p.sync.current_height        = 1'000'000 + cumdiff_lo;
    return p;
}

// -----------------------------------------------------------------------
void test_tiers_and_ratchet() {
    PeerStore s;
    const Millis t0 = 10 * MIN;

    kat::check(s.add("10.1.0.1:38080", PeerSource::Peerlist, t0) != nullptr, "gray add");
    kat::check(s.find("10.1.0.1:38080")->tier == PeerTier::Gray, "a learned address starts gray");
    kat::check(s.add("nonsense", PeerSource::Peerlist, t0) == nullptr,
               "an unparseable key is refused");

    // A second sighting with a better claimed last_seen does NOT promote.
    s.add("10.1.0.1:38080", PeerSource::Peerlist, t0, /*last_seen=*/1'790'000'000);
    kat::check(s.find("10.1.0.1:38080")->tier == PeerTier::Gray,
               "a peer cannot talk itself white with a claimed last_seen");

    s.on_handshaked("10.1.0.1:38080", 0xabcd, t0 + SEC);
    kat::check(s.find("10.1.0.1:38080")->tier == PeerTier::White,
               "our own completed handshake is the only promotion path");
    kat::check(s.find("10.1.0.1:38080")->peer_id == 0xabcd, "the levin peer id is recorded");

    // A later peerlist sighting must not demote a proven peer.
    s.add("10.1.0.1:38080", PeerSource::Peerlist, t0 + 2 * SEC);
    kat::check(s.find("10.1.0.1:38080")->tier == PeerTier::White, "the tier ratchet holds");

    // A healthy disconnect promotes to anchor: this is the set that predates
    // any future gray-list flood.
    s.on_disconnected("10.1.0.1:38080", t0 + 3 * SEC, /*was_healthy=*/true);
    kat::check(s.find("10.1.0.1:38080")->tier == PeerTier::Anchor,
               "a healthy disconnect promotes to anchor");
    kat::check(s.anchor_keys().size() == 1, "the anchor set is reportable for persistence");

    // A protected (operator-pinned) peer.
    s.add("127.0.0.1:38080", PeerSource::Manual, t0);
    kat::check(s.find("127.0.0.1:38080")->is_protected, "a manual peer is protected");
    kat::check(s.find("127.0.0.1:38080")->score(t0) > s.find("10.1.0.1:38080")->score(t0),
               "a pin outranks every tier");
}

// -----------------------------------------------------------------------
void test_backoff_is_not_a_ban() {
    PeerStore s;
    const Millis t0 = MIN;
    s.add("10.2.0.1:38080", PeerSource::Peerlist, t0);
    kat::check(s.find("10.2.0.1:38080")->dialable(t0), "a fresh address is dialable");

    s.on_dial_failed("10.2.0.1:38080", t0);
    const auto* r = s.find("10.2.0.1:38080");
    kat::check(!r->dialable(t0 + SEC), "an address in backoff is not dialable");
    kat::check(r->dialable(t0 + 31 * SEC), "... and is dialable again after the base backoff");
    kat::check(r->fail_score == 0, "an unreachable address is NOT scored down");
    kat::check(!s.is_banned("10.2.0.1:38080", t0 + SEC), "... and is not banned");

    // The ladder doubles and caps.
    Millis t = t0;
    for (int i = 0; i < 12; ++i) { t += 10 * MIN; s.on_dial_failed("10.2.0.1:38080", t); }
    kat::checkf(s.find("10.2.0.1:38080")->backoff_ms == p2p::BACKOFF_CAP_MS,
                "the backoff ladder caps at an hour (%llu)",
                static_cast<unsigned long long>(s.find("10.2.0.1:38080")->backoff_ms));

    // A success resets it.
    s.on_handshaked("10.2.0.1:38080", 1, t + MIN);
    kat::check(s.find("10.2.0.1:38080")->backoff_ms == 0, "a handshake clears the backoff");
    kat::check(s.find("10.2.0.1:38080")->failures == 0, "... and the consecutive-failure count");
}

// -----------------------------------------------------------------------
void test_ban_and_netgroup() {
    PeerStore s;
    const Millis t0 = MIN;
    s.add("203.0.113.7:38080",  PeerSource::Peerlist, t0);
    s.add("203.0.113.8:38080",  PeerSource::Peerlist, t0);
    s.add("198.51.100.9:38080", PeerSource::Peerlist, t0);

    // Nine points is not a ban; the tenth is.
    for (int i = 0; i < 9; ++i)
        kat::check(!s.penalize("203.0.113.7:38080", 1, t0), "sub-threshold points do not ban");
    kat::check(s.penalize("203.0.113.7:38080", 1, t0), "the tenth point bans");
    kat::check(s.is_banned("203.0.113.7:38080", t0), "the banned address is banned");

    // The /16 goes with it -- and 203.0.113.8 shares that /16.
    kat::check(s.is_banned("203.0.113.8:38080", t0),
               "the ban carries the /16, so a sibling address is also blocked");
    kat::check(!s.is_banned("198.51.100.9:38080", t0), "a different /16 is untouched");

    // ... and it expires.
    kat::check(!s.is_banned("203.0.113.8:38080", t0 + p2p::P2P_IP_BLOCKTIME_MS + SEC),
               "the ban expires after P2P_IP_BLOCKTIME");

    // One fault of full weight bans in a single step: a completed RandomX hash
    // below target is incontrovertible.
    PeerStore s2;
    s2.add("192.0.2.5:38080", PeerSource::Peerlist, t0);
    kat::check(s2.penalize("192.0.2.5:38080", 10, t0), "a full-weight fault bans in one step");

    // A protected peer accrues points but is never banned.
    PeerStore s3;
    s3.add("127.0.0.1:38080", PeerSource::Manual, t0);
    for (int i = 0; i < 20; ++i) s3.penalize("127.0.0.1:38080", 1, t0);
    kat::check(!s3.is_banned("127.0.0.1:38080", t0), "an operator pin is never banned");
    kat::check(s3.find("127.0.0.1:38080")->fail_score >= 20,
               "... but the damage is still visible in telemetry");

    // Points decay after the forget window: an honest long-lived peer must not
    // accumulate a ban out of unrelated one-off faults spread over days.
    PeerStore s4;
    s4.add("192.0.2.9:38080", PeerSource::Peerlist, t0);
    for (int i = 0; i < 9; ++i) s4.penalize("192.0.2.9:38080", 1, t0);
    const Millis later = t0 + p2p::P2P_FAILED_ADDR_FORGET_MS + SEC;
    kat::check(!s4.penalize("192.0.2.9:38080", 1, later),
               "a point after the forget window starts a fresh score");
    kat::check(s4.find("192.0.2.9:38080")->fail_score == 1, "... of exactly one point");
}

// -----------------------------------------------------------------------
void test_candidate_order() {
    PeerStore s;
    const Millis t0 = 10 * MIN;
    s.add("10.9.0.1:38080", PeerSource::Peerlist, t0);              // gray
    s.add("10.8.0.1:38080", PeerSource::Peerlist, t0);
    s.on_handshaked("10.8.0.1:38080", 1, t0);                        // white
    s.add("10.7.0.1:38080", PeerSource::Anchor,   t0);               // anchor
    s.add("127.0.0.1:38080", PeerSource::Manual,  t0);               // pinned

    const auto all = keys_of(s.candidates(t0));
    kat::check(all.size() == 4, "every dialable address is a candidate");
    kat::check(all[0] == "127.0.0.1:38080", "the pin is dialed first");
    kat::check(all[1] == "10.7.0.1:38080",  "then the anchor");
    kat::check(all[2] == "10.8.0.1:38080",  "then white");
    kat::check(all[3] == "10.9.0.1:38080",  "then gray");

    // Tier-restricted passes are how the dial plan reserves anchor slots.
    kat::check(keys_of(s.candidates(t0, PeerTier::Anchor, true)).size() == 1,
               "an exact-tier pass sees only that tier");

    // A banned address never appears.
    s.ban("10.9.0.1:38080", p2p::P2P_IP_BLOCKTIME_MS, t0);
    kat::check(!contains(keys_of(s.candidates(t0)), "10.9.0.1:38080"),
               "a banned address is not a candidate");
}

// -----------------------------------------------------------------------
void test_gray_eviction() {
    PeerStore::Limits lim;
    lim.gray = 4;
    PeerStore s(lim);
    const Millis t0 = MIN;
    for (int i = 1; i <= 4; ++i)
        s.add("10.0.0." + std::to_string(i) + ":38080", PeerSource::Peerlist, t0);
    kat::check(s.size() == 4, "the gray list fills to its limit");
    // A worse-scoring entry to evict: give one of them failures.
    s.on_dial_failed("10.0.0.2:38080", t0);
    s.on_dial_failed("10.0.0.2:38080", t0);
    kat::check(s.add("10.0.0.5:38080", PeerSource::Peerlist, t0) != nullptr,
               "a full gray list evicts to make room");
    kat::check(s.size() == 4, "... and stays at its limit");
    kat::check(s.find("10.0.0.2:38080") == nullptr, "the worst-scoring entry is the one evicted");
}

// -----------------------------------------------------------------------
void test_refill_and_netgroup_cap() {
    PeerStore s;
    const Millis t0 = 10 * MIN;
    // Four addresses in ONE /16 and two in others: exactly the eclipse shape.
    for (int i = 1; i <= 4; ++i)
        s.add("203.0." + std::to_string(113) + "." + std::to_string(i) + ":38080",
              PeerSource::Peerlist, t0);
    s.add("198.51.100.1:38080", PeerSource::Peerlist, t0);
    s.add("192.0.2.1:38080",    PeerSource::Peerlist, t0);

    p2p::DialPlanConfig cfg;
    cfg.target_outbound      = 6;
    cfg.max_concurrent_dials = 8;
    cfg.max_per_netgroup     = 2;
    cfg.anchor_slots         = 0;
    p2p::DialPlan plan(cfg);

    const p2p::DialDecision d = plan.plan(s, {}, t0);
    kat::checkf(d.dial.size() == 4, "the cap limits a six-address store to four dials (%zu)",
                d.dial.size());
    std::size_t from_203 = 0;
    for (const std::string& k : d.dial)
        if (k.rfind("203.0.113.", 0) == 0) ++from_203;
    kat::checkf(from_203 == 2, "at most two dials share a /16 (%zu)", from_203);
    kat::check(!d.use_seeds, "seeds are not needed while the store has candidates");

    // A store with nothing dialable falls back to the seeds -- and ONLY then.
    PeerStore empty;
    const p2p::DialDecision cold = plan.plan(empty, {}, t0);
    kat::check(cold.dial.empty() && cold.use_seeds,
               "an empty store asks for the seed tables");
    kat::check(empty.seed_from_tables(p2p::XmrNet::Stagenet, t0) == 5,
               "the stagenet seed table lands five addresses");
    kat::check(!plan.plan(empty, {}, t0).use_seeds,
               "and once seeded, the seed path is not taken again");
}

// -----------------------------------------------------------------------
void test_netgroup_over_cap_drop() {
    PeerStore s;
    const Millis t0 = 60 * MIN;
    std::vector<p2p::LivePeer> lp;
    // Three live connections in one /16 with a cap of two: the NEWEST goes.
    lp.push_back(live("203.0.113.1:38080", t0 - 30 * MIN, 100));
    lp.push_back(live("203.0.113.2:38080", t0 - 20 * MIN, 100));
    lp.push_back(live("203.0.113.3:38080", t0 -  1 * MIN, 100));
    for (const auto& p : lp) { s.add(p.key, PeerSource::Peerlist, t0 - MIN);
                               s.on_handshaked(p.key, 1, t0 - MIN); }

    p2p::DialPlanConfig cfg;
    cfg.target_outbound  = 8;
    cfg.max_per_netgroup = 2;
    cfg.rotation_interval_ms = 0;   // rotation off, so the drop is unambiguous
    p2p::DialPlan plan(cfg);

    const p2p::DialDecision d = plan.plan(s, lp, t0);
    std::size_t over_cap_drops = 0;
    std::string dropped;
    for (const auto& [key, why] : d.drop)
        if (why == p2p::DropReason::NetgroupOverCap) { ++over_cap_drops; dropped = key; }
    kat::checkf(over_cap_drops == 1, "one connection is dropped to reach the cap (%zu)",
                over_cap_drops);
    kat::check(dropped == "203.0.113.3:38080",
               "the NEWEST connection in the over-cap group is the one dropped");
    kat::check(!d.eclipse_floor_met,
               "one netgroup does not meet the eclipse floor");

    // A pinned peer is exempt: the operator asked for it by name.
    std::vector<p2p::LivePeer> pinned = lp;
    pinned[2].is_protected = true;
    const p2p::DialDecision d2 = plan.plan(s, pinned, t0);
    for (const auto& [key, why] : d2.drop)
        kat::check(key != "203.0.113.3:38080", "an operator pin is never dropped for the cap");
}

// -----------------------------------------------------------------------
void test_rotation() {
    PeerStore s;
    const Millis t0 = 60 * MIN;
    p2p::DialPlanConfig cfg;
    cfg.target_outbound      = 3;
    cfg.max_per_netgroup     = 8;
    cfg.rotation_interval_ms = 15 * MIN;
    cfg.min_peer_age_ms      = 10 * MIN;
    cfg.anchor_slots         = 0;
    p2p::DialPlan plan(cfg);

    std::vector<p2p::LivePeer> lp{
        live("10.1.0.1:38080", t0 - 40 * MIN, 100),
        live("10.2.0.1:38080", t0 - 40 * MIN, 100),
        live("10.3.0.1:38080", t0 -  2 * MIN, 100),   // too young to rotate
    };
    for (const auto& p : lp) { s.add(p.key, PeerSource::Peerlist, t0 - 41 * MIN);
                               s.on_handshaked(p.key, 1, t0 - 40 * MIN); }
    // Make 10.2 the worst so the choice is deterministic.
    s.penalize("10.2.0.1:38080", 3, t0 - 30 * MIN);

    // No alternative in the store: rotation must NOT fire, or the pool would
    // drop a working peer and reconnect to the same one.
    kat::check(plan.plan(s, lp, t0).drop.empty(),
               "rotation does not fire without a fresh alternative");

    s.add("10.9.0.9:38080", PeerSource::Peerlist, t0);
    const p2p::DialDecision d = plan.plan(s, lp, t0);
    std::string rotated;
    for (const auto& [key, why] : d.drop)
        if (why == p2p::DropReason::Rotation) rotated = key;
    kat::check(rotated == "10.2.0.1:38080", "rotation drops the worst old peer");
    kat::check(rotated != "10.3.0.1:38080", "... and never one younger than the age floor");

    // The interval is honoured: having just rotated, the next plan does not.
    plan.note_rotation(t0);
    bool rotated_again = false;
    for (const auto& [key, why] : plan.plan(s, lp, t0 + MIN).drop)
        if (why == p2p::DropReason::Rotation) rotated_again = true;
    kat::check(!rotated_again, "rotation waits out its interval");

    // A pinned peer is never the victim.
    std::vector<p2p::LivePeer> pinned = lp;
    pinned[1].is_protected = true;
    p2p::DialPlan plan2(cfg);
    for (const auto& [key, why] : plan2.plan(s, pinned, t0).drop)
        if (why == p2p::DropReason::Rotation)
            kat::check(key != "10.2.0.1:38080", "an operator pin is never rotated out");
}

// -----------------------------------------------------------------------
void test_primary_election() {
    PeerStore s;
    const Millis t0 = 60 * MIN;
    p2p::DialPlanConfig cfg;
    cfg.primary_switch_margin = native::U128{50, 0};
    p2p::DialPlan plan(cfg);

    std::vector<p2p::LivePeer> lp{
        live("10.1.0.1:38080", t0 - MIN, 1000),
        live("10.2.0.1:38080", t0 - MIN, 1020),
    };
    for (const auto& p : lp) { s.add(p.key, PeerSource::Peerlist, t0 - MIN);
                               s.on_handshaked(p.key, 1, t0 - MIN); }

    kat::check(plan.elect_primary(lp, s, "", t0) == "10.2.0.1:38080",
               "with no incumbent the highest cumulative difficulty wins");

    // HYSTERESIS: 20 ahead is inside the 50 margin, so the incumbent keeps it.
    kat::check(plan.elect_primary(lp, s, "10.1.0.1:38080", t0) == "10.1.0.1:38080",
               "a challenger inside the margin does not take the role");

    lp[1].sync.cumulative_difficulty = native::U128{1100, 0};      // 100 ahead
    kat::check(plan.elect_primary(lp, s, "10.1.0.1:38080", t0) == "10.2.0.1:38080",
               "a challenger past the margin does take it");

    // A tie never switches.
    lp[1].sync.cumulative_difficulty = lp[0].sync.cumulative_difficulty;
    kat::check(plan.elect_primary(lp, s, "10.1.0.1:38080", t0) == "10.1.0.1:38080",
               "an exact tie leaves the incumbent in place");

    // An operator pin takes the role immediately and keeps it against any
    // difficulty claim: it is the C6 parity phase's reference daemon.
    std::vector<p2p::LivePeer> withpin = lp;
    withpin.push_back(live("127.0.0.1:38080", t0 - MIN, 1));
    withpin.back().is_protected = true;
    s.add("127.0.0.1:38080", PeerSource::Manual, t0 - MIN);
    kat::check(plan.elect_primary(withpin, s, "10.1.0.1:38080", t0) == "127.0.0.1:38080",
               "a pinned peer takes the primary role at once");
    withpin[1].sync.cumulative_difficulty = native::U128{9'000'000, 0};
    kat::check(plan.elect_primary(withpin, s, "127.0.0.1:38080", t0) == "127.0.0.1:38080",
               "... and keeps it against any advertised difficulty");

    // The incumbent vanishing hands the role to the best survivor, not to
    // nobody.
    kat::check(plan.elect_primary(lp, s, "gone:38080", t0) == "10.1.0.1:38080",
               "a departed incumbent is replaced");
    kat::check(plan.elect_primary({}, s, "10.1.0.1:38080", t0).empty(),
               "with no handshaked peers there is no primary");

    // Only handshaked peers are eligible.
    std::vector<p2p::LivePeer> dialing = lp;
    dialing[1].handshaked = false;
    kat::check(plan.elect_primary(dialing, s, "", t0) == "10.1.0.1:38080",
               "a peer still dialing cannot be primary");
}

// -----------------------------------------------------------------------
void test_anchor_reserve() {
    PeerStore s;
    const Millis t0 = 60 * MIN;
    s.add("10.7.0.1:38080", PeerSource::Anchor, t0);
    s.add("10.7.0.2:38080", PeerSource::Anchor, t0);
    for (int i = 1; i <= 10; ++i)
        s.add("10.20." + std::to_string(i) + ".1:38080", PeerSource::Peerlist, t0);

    p2p::DialPlanConfig cfg;
    cfg.target_outbound      = 4;
    cfg.max_concurrent_dials = 8;
    cfg.max_per_netgroup     = 8;
    cfg.anchor_slots         = 2;
    p2p::DialPlan plan(cfg);

    const p2p::DialDecision d = plan.plan(s, {}, t0);
    kat::check(d.dial.size() == 4, "refill fills to target");
    kat::check(contains(d.dial, "10.7.0.1:38080") && contains(d.dial, "10.7.0.2:38080"),
               "both anchor slots are spent on anchors even with ten gray alternatives");
}

// -----------------------------------------------------------------------
void test_dial_budget_bounds() {
    PeerStore s;
    const Millis t0 = 60 * MIN;
    for (int i = 1; i <= 40; ++i)
        s.add("10." + std::to_string(i) + ".0.1:38080", PeerSource::Peerlist, t0);

    p2p::DialPlanConfig cfg;
    cfg.target_outbound      = 8;
    cfg.max_outbound         = 10;
    cfg.max_concurrent_dials = 3;
    cfg.max_per_netgroup     = 2;
    cfg.anchor_slots         = 0;
    p2p::DialPlan plan(cfg);

    kat::checkf(plan.plan(s, {}, t0).dial.size() == 3,
                "no more than max_concurrent_dials are started at once (%zu)",
                plan.plan(s, {}, t0).dial.size());

    // In-flight dials count against the budget: otherwise a slow connect storm
    // would open max_concurrent_dials NEW sockets on every maintenance tick.
    std::vector<p2p::LivePeer> dialing;
    for (int i = 1; i <= 3; ++i) {
        p2p::LivePeer p = live("10." + std::to_string(i) + ".0.1:38080", t0, 1);
        p.handshaked = false;
        p.dialing    = true;
        dialing.push_back(p);
    }
    kat::check(plan.plan(s, dialing, t0).dial.empty(),
               "three dials already in flight consume the whole concurrency budget");
}

} // namespace

int main() {
    test_tiers_and_ratchet();
    test_backoff_is_not_a_ban();
    test_ban_and_netgroup();
    test_candidate_order();
    test_gray_eviction();
    test_refill_and_netgroup_cap();
    test_netgroup_over_cap_drop();
    test_rotation();
    test_primary_election();
    test_anchor_reserve();
    test_dial_budget_bounds();
    return kat::report("xmr_native_peer_store_kat");
}
