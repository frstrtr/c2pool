// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// PR-3 proactive peer-rotation policy — pure, dependency-free decision helpers
// shared by the coin P2P client (p2p_client.hpp maybe_proactive_rotate) and the
// KAT (dash_proactive_rotation_kat.cpp). Kept free of any coin / boost / socket
// / session dependency so BOTH the real call site AND the KAT link against the
// EXACT same logic — no duplicated shadow implementation that could go green
// while the shipped path regresses (the bulk_peer_policy.hpp precedent).
//
// WHAT this adds (dashd-cut coin-P2P, task #154 line, stacks on PR-0 arrival
// instrumentation). The always-on stall rotation (#147/#148,
// maybe_rotate_outbound) only cycles peers WHILE BEHIND — a demonstrated
// deep-body non-server occupies a slot, or a fold getmnlistd is stalled. A
// HEALTHY pool therefore latches on its frozen first-come set forever, even if
// a member is the slowest deliverer in it. This policy is the LOW-RATE
// proactive half: when armed, a healthy pool periodically probes one fresh
// candidate and sheds its SLOWEST measured non-primary server, so the working
// set trends toward the fastest deliverers.
//
// SAFETY (same class as #1329). This decides only WHICH / HOW-MANY peers we
// fetch from and WHEN we probe — never WHAT is fetched or derived. Every reply
// still flows through the identical merkle / payee / DIP-4 / BLS self-checks;
// the worst case is one extra probe connection plus one reconnect on an
// already-verified small object. m_primary and any protected-local peer (#147)
// are the latency REFERENCE and are NEVER retirement-eligible; selection and
// retirement operate ONLY among CanServeBlocks peers (#148).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dash {
namespace coin {
namespace proactivepolicy {

// A per-peer view for proactive-rotation retirement selection. Pure data: the
// caller (CoinClient) fills it from its live PeerSession set, the KAT fills it
// by hand, and BOTH run the identical selector below.
struct PeerLatencyView {
    std::string key;
    bool     is_primary{false};          // #147: latency reference, NEVER retired
    bool     is_protected_local{false};  // #147: loopback/LAN, NEVER retired
    bool     can_serve_blocks{false};    // #148: only servers are in play
    bool     has_latency{false};         // a TipBody delivery-latency sample exists
    int64_t  ewma_ms{-1};                // smoothed TipBody delivery latency (PR-0)
};

// Cadence gate. Proactive rotation may fire at most once per interval; `armed`
// false (flag default-OFF) => NEVER (byte-identical to master). A never-fired
// clock (last_fire==0) becomes due once `now` has advanced one interval, the
// same now-last>=interval convention the stall rotation uses. A non-positive
// interval never fires (defensive).
inline bool proactive_due(bool armed, std::int64_t now, std::int64_t last_fire,
                          std::int64_t interval_sec) {
    if (!armed) return false;
    if (interval_sec <= 0) return false;
    return now - last_fire >= interval_sec;
}

// Retirement victim: the SLOWEST (highest EWMA) eligible peer.
//   eligible = can_serve_blocks (#148)
//              AND NOT is_primary AND NOT is_protected_local (#147 exempt)
//              AND has_latency AND ewma_ms >= 0
// Returns the index into `peers`, or -1 when nothing is eligible. Ties resolve
// to the FIRST such peer (stable / deterministic — the KAT locks it). The
// caller's surplus guard decides whether it is SAFE to retire the returned
// peer; this function only names the slowest.
inline int slowest_retirement_victim(const std::vector<PeerLatencyView>& peers) {
    int victim = -1;
    std::int64_t worst = -1;
    for (std::size_t i = 0; i < peers.size(); ++i) {
        const PeerLatencyView& p = peers[i];
        if (p.is_primary || p.is_protected_local) continue;  // #147 exempt
        if (!p.can_serve_blocks) continue;                    // #148 servers only
        if (!p.has_latency || p.ewma_ms < 0) continue;        // no measurement
        if (victim < 0 || p.ewma_ms > worst) {
            victim = static_cast<int>(i);
            worst = p.ewma_ms;
        }
    }
    return victim;
}

} // namespace proactivepolicy
} // namespace coin
} // namespace dash
