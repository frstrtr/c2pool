// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// #154 bulk-lane peer policy — pure, dependency-free decision helpers shared by
// the coin P2P client (WHICH peer is bulk-eligible, p2p_client.hpp
// eligible_bulk_peer_keys) and the replay bulk scheduler (HOW MUCH inflight
// budget each peer gets, replay_bulk_fetch.hpp BulkBlockScheduler::pump). Kept
// free of any coin / boost / leveldb dependency so BOTH real call sites AND the
// KAT link against the exact same logic — no duplicated shadow implementation
// that could go green while the shipped path regresses.
//
// ROOT CAUSE these two levers fix (benchmark-proven, wf task #154): a daemonless
// cold-start / replay ran fetch-pipeline-bound (~16 blk/s) instead of dashd-
// parity fast because
//   (1) eligible_bulk_peer_keys() unconditionally erased the PRIMARY from the
//       bulk set whenever any other handshaked peer existed. With
//       --coin-p2p-discover arming ~15 internet peers, the pinned gigabit-LAN
//       archival dashd (the "Protected local dashd node") was thrown out of the
//       bulk lane — 0 of 16961 bodies served by it, a distant internet peer
//       carried 53%; and
//   (2) flat round-robin (per_peer_inflight=32 for every peer) let a slow peer
//       hold a contiguous low-height range and stall the in-order delivery
//       cursor (buffer rides the window ceiling, timeout climbs to 10k+).
//
// SAFETY: these change only WHICH peer serves block bodies and HOW MUCH each is
// asked for. They do NOT touch fold / consensus / block validation — every body
// is still verified identically by the fold.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace dash {
namespace coin {
namespace bulkpolicy {

// LEVER 1 (Priority Invariant #1, made REMOTE-primary-only). `universe` is the
// handshaked+serving bulk-peer key set. Exclude the PRIMARY from the bulk lane
// ONLY when it is a REMOTE primary — it carries every live-tip request/response
// leg, so loading it with bulk bodies would block the tip lane — AND at least
// one other peer exists to serve bulk. A pinned PROTECTED-LOCAL primary
// (loopback / private-LAN "Protected local dashd node") is KEPT bulk-eligible:
// during a historical replay there is no tip-lane pressure and the local node
// is the fastest deliverer, so excluding it was pure throughput loss (#154).
inline std::vector<std::string> select_bulk_eligible_keys(
    std::vector<std::string> universe,
    const std::string& primary_key,
    bool primary_is_protected_local)
{
    if (universe.size() > 1 && !primary_key.empty() &&
        !primary_is_protected_local)
    {
        universe.erase(
            std::remove(universe.begin(), universe.end(), primary_key),
            universe.end());
    }
    return universe;
}

// LEVER 2 (throughput-weighted inflight window, anti head-of-line-blocking).
// Scale a peer's per-peer inflight budget by its DELIVERED block throughput
// relative to the fastest peer in the set, linearly across [floor, base]. A
// slow / timing-out peer thus claims a SMALLER contiguous low-height range and
// can no longer stall the in-order delivery cursor; the fast local / archival
// deliverer earns the big window and fills the shared work-ahead budget.
//
// DEGENERATE cold start — nobody has delivered a body yet (max_delivered == 0),
// or this is the sole/lead peer (peer_delivered >= max_delivered) — returns the
// flat `base`, BYTE-IDENTICAL to the pre-#154 round-robin. This is what keeps
// the discover-only path (uniform delivery converges every peer back to `base`)
// and the KAT / any embedding without per-peer throughput data unregressed.
inline std::uint32_t weighted_peer_inflight(
    std::uint32_t base,           // Config::per_peer_inflight
    std::uint32_t floor,          // Config::min_peer_inflight (clamped to base)
    std::uint64_t peer_delivered, // this peer's PeerTally::blocks
    std::uint64_t max_delivered)  // max PeerTally::blocks across the peer set
{
    if (floor > base) floor = base;
    if (max_delivered == 0) return base;               // cold start -> flat
    if (peer_delivered >= max_delivered) return base;  // the fastest peer
    const std::uint32_t span = base - floor;
    const std::uint32_t bonus = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(span) * peer_delivered) / max_delivered);
    std::uint32_t eff = floor + bonus;
    if (eff < floor) eff = floor;
    if (eff > base)  eff = base;
    return eff;
}

} // namespace bulkpolicy
} // namespace coin
} // namespace dash
