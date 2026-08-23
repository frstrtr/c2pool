// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT: #154 daemonless bulk-fetch dashd-parity — use a fast PROTECTED-LOCAL /
// pinned archival peer for bulk block-body fetch, and weight the inflight
// window toward the peers that actually deliver.
//
// PROVEN DIAGNOSIS (benchmark, wf task #154): a daemonless cold-start / replay
// ran fetch-pipeline-bound (~16 blk/s, 1% CPU, 0.35 MB/s) instead of dashd-
// parity fast because:
//
//   LEVER 1  eligible_bulk_peer_keys() unconditionally erased the PRIMARY from
//            the bulk set whenever any other handshaked peer existed. With
//            --coin-p2p-discover arming ~15 internet peers the pinned gigabit-
//            LAN archival dashd (the "Protected local dashd node", AddrClass
//            private_net / loopback) was thrown out of the bulk lane — 0 of
//            16961 bodies served by it; a distant internet peer carried 53%.
//            The invariant only ever meant to protect a REMOTE primary's live-
//            tip legs, so it is now gated on "remote primary only".
//
//   LEVER 2  flat round-robin (per_peer_inflight=32 for every peer) let a slow
//            peer hold a contiguous low-height range and stall the in-order
//            delivery cursor. The per-peer inflight window is now weighted by
//            each peer's DELIVERED throughput across [min_peer_inflight,
//            per_peer_inflight].
//
// Both levers change only WHICH peer is asked and HOW MUCH — never the fold /
// consensus / validation. This KAT exercises the SHIPPED decision helpers
// (bulkpolicy::select_bulk_eligible_keys — the exact call eligible_bulk_peer_keys
// makes; bulkpolicy::weighted_peer_inflight AND the real
// BulkBlockScheduler::effective_per_peer_inflight — the exact path pump() uses),
// so there is no shadow implementation that could go green while ship regresses.
//
//   A. LOCAL PRIMARY KEPT   — protected-local primary + N remote peers ⇒ the
//                             local primary is INCLUDED in the bulk set (#154).
//   B. REMOTE PRIMARY CUT   — remote primary + N remote peers ⇒ the primary is
//                             EXCLUDED, exactly as before (invariant 1 held).
//   C. DISCOVER-ONLY SAME   — with no protected-local peer, the result is
//                             byte-identical to the legacy erase.
//   D. SOLE SURVIVOR KEPT   — a lone primary (local or remote) is never erased.
//   E. WEIGHTED INFLIGHT    — a fast deliverer earns the full window; a slow one
//                             a narrower one (floored), on the REAL scheduler.
//   F. COLD-START FLAT      — before any delivery every peer gets the flat
//                             per_peer_inflight (pre-#154 round-robin preserved).
//
// FOLDED (was standalone src/c2pool/dash_bulk_local_primary_kat.cpp with a
// main()) into the already-allowlisted test_dash_p2p_node target — a standalone
// executable was NOT in the build.yml "Build tests" --target list, so CTest saw
// it registered-but-not-built ("Not Run") and red'd the suite (the #769 /
// unregistered-KAT NOT_BUILT class). Separate TU, own anonymous namespace +
// distinct DashBulkLocalPrimaryKat suite, gtest_main-provided main() → no clash.

#include <gtest/gtest.h>

#include <impl/dash/coin/bulk_peer_policy.hpp>
#include <impl/dash/coin/replay_bulk_fetch.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

namespace bp = dash::coin::bulkpolicy;
namespace rp = dash::coin::replay;

bool has(const std::vector<std::string>& v, const std::string& k)
{
    return std::find(v.begin(), v.end(), k) != v.end();
}

// ── LEVER 1: select_bulk_eligible_keys (the exact logic of the shipped
//    CoinClient::eligible_bulk_peer_keys tail). ──────────────────────────────
TEST(DashBulkLocalPrimaryKat, Lever1BulkEligibleSelection)
{
    const std::string local  = "192.168.86.165:9999"; // protected-local primary
    const std::string remA   = "203.0.113.7:9999";    // remote archival
    const std::string remB   = "198.51.100.9:9999";   // remote archival

    // A. protected-local primary + N remote ⇒ INCLUDES the local primary.
    {
        std::vector<std::string> universe = {local, remA, remB};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/local, /*primary_is_protected_local=*/true);
        EXPECT_TRUE(has(keys, local)) << "A: protected-local primary KEPT in bulk set";
        EXPECT_TRUE(has(keys, remA) && has(keys, remB)) << "A: remote peers still present";
        EXPECT_EQ(keys.size(), 3u) << "A: nothing erased (was: local erased -> 2)";
    }

    // B. remote primary + N remote ⇒ EXCLUDES the primary (invariant 1 held).
    {
        std::vector<std::string> universe = {remA, remB, local};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/remA, /*primary_is_protected_local=*/false);
        EXPECT_TRUE(!has(keys, remA)) << "B: remote primary EXCLUDED from bulk set";
        EXPECT_TRUE(has(keys, remB) && has(keys, local)) << "B: other peers present";
        EXPECT_EQ(keys.size(), 2u) << "B: exactly the primary removed";
    }

    // C. discover-only (no protected-local peer): identical to legacy erase.
    {
        std::vector<std::string> universe = {remA, remB};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/remA, /*primary_is_protected_local=*/false);
        std::vector<std::string> legacy = {remA, remB};
        legacy.erase(std::remove(legacy.begin(), legacy.end(), remA), legacy.end());
        EXPECT_EQ(keys, legacy) << "C: discover-only path byte-identical to legacy";
    }

    // D. sole survivor is never erased (size>1 guard), local or remote.
    {
        auto r = bp::select_bulk_eligible_keys({remA}, remA, false);
        EXPECT_TRUE(r.size() == 1 && r[0] == remA) << "D: lone remote primary kept";
        auto l = bp::select_bulk_eligible_keys({local}, local, true);
        EXPECT_TRUE(l.size() == 1 && l[0] == local) << "D: lone local primary kept";
    }

    // Empty primary key ⇒ no erase (defensive).
    {
        std::vector<std::string> universe = {remA, remB};
        auto keys = bp::select_bulk_eligible_keys(universe, "", false);
        EXPECT_EQ(keys.size(), 2u) << "empty primary key erases nothing";
    }
}

// ── LEVER 2 (pure): weighted_peer_inflight across [floor, base]. ────────────
TEST(DashBulkLocalPrimaryKat, Lever2WeightedInflightPure)
{
    const std::uint32_t base = 32, floor = 8;

    EXPECT_EQ(bp::weighted_peer_inflight(base, floor, 0, 0), base)
        << "cold start (max=0) -> flat base";
    EXPECT_EQ(bp::weighted_peer_inflight(base, floor, 0, 100), floor)
        << "zero-delivery peer -> floor";
    EXPECT_EQ(bp::weighted_peer_inflight(base, floor, 100, 100), base)
        << "fastest peer -> full base";
    EXPECT_EQ(bp::weighted_peer_inflight(base, floor, 50, 100), 20u)
        << "half-rate peer -> floor + span/2 (8 + 12 = 20)";
    // A slow peer is always strictly between floor and base, never below floor.
    auto slow = bp::weighted_peer_inflight(base, floor, 1, 16);
    EXPECT_TRUE(slow >= floor && slow < base) << "slow-but-delivering peer within (floor,base)";
    // floor > base is clamped (never underflows / exceeds base).
    EXPECT_EQ(bp::weighted_peer_inflight(base, 40, 50, 100), base)
        << "floor>base clamped to base";
}

// ── LEVER 2 (integration): the REAL BulkBlockScheduler reflects delivered
//    throughput, and is flat before any delivery. ─────────────────────────────
TEST(DashBulkLocalPrimaryKat, Lever2WeightedInflightScheduler)
{
    rp::BulkBlockScheduler sched;
    rp::BulkBlockScheduler::Config cfg;
    cfg.window            = 2000;
    cfg.per_peer_inflight = 32;
    cfg.min_peer_inflight = 8;
    cfg.batch             = 16;
    sched.configure(cfg);
    sched.reset(1);
    sched.set_target_end(100000);

    const std::vector<std::string> peers = {"fast", "slow"};
    auto hash_at = [](std::uint32_t h) -> std::optional<uint256> {
        return std::optional<uint256>(uint256(static_cast<std::uint64_t>(h)));
    };

    // F. Cold start: no peer has delivered ⇒ every peer flat at per_peer_inflight.
    EXPECT_EQ(sched.effective_per_peer_inflight("fast"), 32u) << "F: cold-start flat (fast)";
    EXPECT_EQ(sched.effective_per_peer_inflight("slow"), 32u) << "F: cold-start flat (slow)";

    // Assign a batch to each peer, then deliver ALL of fast's bodies and only
    // ONE of slow's — fast becomes the high-throughput deliverer.
    auto assign = sched.pump(/*now=*/1, peers, hash_at, /*buffered=*/0);
    std::map<std::string, std::vector<uint256>> got;
    for (const auto& a : assign)
        for (const auto& [h, hash] : a.blocks)
            got[a.peer].push_back(hash);
    EXPECT_TRUE(!got["fast"].empty() && !got["slow"].empty())
        << "E-pre: both peers were assigned a fresh range";

    for (const auto& hash : got["fast"]) sched.on_body(hash, 1024);
    if (!got["slow"].empty()) sched.on_body(got["slow"].front(), 1024);

    const std::uint32_t eff_fast = sched.effective_per_peer_inflight("fast");
    const std::uint32_t eff_slow = sched.effective_per_peer_inflight("slow");
    EXPECT_EQ(eff_fast, 32u) << "E: fast (top deliverer) earns the full window";
    EXPECT_TRUE(eff_slow >= 8 && eff_slow < 32) << "E: slow peer window narrowed but floored";
    EXPECT_TRUE(eff_slow < eff_fast) << "E: slow window strictly below fast window";
}

} // namespace
