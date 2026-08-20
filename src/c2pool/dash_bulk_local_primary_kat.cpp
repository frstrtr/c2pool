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

#include <impl/dash/coin/bulk_peer_policy.hpp>
#include <impl/dash/coin/replay_bulk_fetch.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace bp = dash::coin::bulkpolicy;
namespace rp = dash::coin::replay;

static int g_failures = 0;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::cout << "  FAIL: " << (msg) << "\n";                           \
            ++g_failures;                                                       \
        } else {                                                                \
            std::cout << "  ok:   " << (msg) << "\n";                           \
        }                                                                       \
    } while (0)

static bool has(const std::vector<std::string>& v, const std::string& k)
{
    return std::find(v.begin(), v.end(), k) != v.end();
}

// ── LEVER 1: select_bulk_eligible_keys (the exact logic of the shipped
//    CoinClient::eligible_bulk_peer_keys tail). ──────────────────────────────
static void test_lever1()
{
    std::cout << "[LEVER 1] bulk-eligible peer selection\n";

    const std::string local  = "192.168.86.165:9999"; // protected-local primary
    const std::string remA   = "203.0.113.7:9999";    // remote archival
    const std::string remB   = "198.51.100.9:9999";   // remote archival

    // A. protected-local primary + N remote ⇒ INCLUDES the local primary.
    {
        std::vector<std::string> universe = {local, remA, remB};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/local, /*primary_is_protected_local=*/true);
        CHECK(has(keys, local), "A: protected-local primary KEPT in bulk set");
        CHECK(has(keys, remA) && has(keys, remB), "A: remote peers still present");
        CHECK(keys.size() == 3, "A: nothing erased (was: local erased -> 2)");
    }

    // B. remote primary + N remote ⇒ EXCLUDES the primary (invariant 1 held).
    {
        std::vector<std::string> universe = {remA, remB, local};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/remA, /*primary_is_protected_local=*/false);
        CHECK(!has(keys, remA), "B: remote primary EXCLUDED from bulk set");
        CHECK(has(keys, remB) && has(keys, local), "B: other peers present");
        CHECK(keys.size() == 2, "B: exactly the primary removed");
    }

    // C. discover-only (no protected-local peer): identical to legacy erase.
    {
        std::vector<std::string> universe = {remA, remB};
        auto keys = bp::select_bulk_eligible_keys(
            universe, /*primary=*/remA, /*primary_is_protected_local=*/false);
        std::vector<std::string> legacy = {remA, remB};
        legacy.erase(std::remove(legacy.begin(), legacy.end(), remA), legacy.end());
        CHECK(keys == legacy, "C: discover-only path byte-identical to legacy");
    }

    // D. sole survivor is never erased (size>1 guard), local or remote.
    {
        auto r = bp::select_bulk_eligible_keys({remA}, remA, false);
        CHECK(r.size() == 1 && r[0] == remA, "D: lone remote primary kept");
        auto l = bp::select_bulk_eligible_keys({local}, local, true);
        CHECK(l.size() == 1 && l[0] == local, "D: lone local primary kept");
    }

    // Empty primary key ⇒ no erase (defensive).
    {
        std::vector<std::string> universe = {remA, remB};
        auto keys = bp::select_bulk_eligible_keys(universe, "", false);
        CHECK(keys.size() == 2, "empty primary key erases nothing");
    }
}

// ── LEVER 2 (pure): weighted_peer_inflight across [floor, base]. ────────────
static void test_lever2_pure()
{
    std::cout << "[LEVER 2] weighted_peer_inflight (pure)\n";
    const std::uint32_t base = 32, floor = 8;

    CHECK(bp::weighted_peer_inflight(base, floor, 0, 0) == base,
          "cold start (max=0) -> flat base");
    CHECK(bp::weighted_peer_inflight(base, floor, 0, 100) == floor,
          "zero-delivery peer -> floor");
    CHECK(bp::weighted_peer_inflight(base, floor, 100, 100) == base,
          "fastest peer -> full base");
    CHECK(bp::weighted_peer_inflight(base, floor, 50, 100) == 20,
          "half-rate peer -> floor + span/2 (8 + 12 = 20)");
    // A slow peer is always strictly between floor and base, never below floor.
    auto slow = bp::weighted_peer_inflight(base, floor, 1, 16);
    CHECK(slow >= floor && slow < base, "slow-but-delivering peer within (floor,base)");
    // floor > base is clamped (never underflows / exceeds base).
    CHECK(bp::weighted_peer_inflight(base, 40, 50, 100) == base,
          "floor>base clamped to base");
}

// ── LEVER 2 (integration): the REAL BulkBlockScheduler reflects delivered
//    throughput, and is flat before any delivery. ─────────────────────────────
static void test_lever2_scheduler()
{
    std::cout << "[LEVER 2] BulkBlockScheduler::effective_per_peer_inflight (real)\n";

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
    CHECK(sched.effective_per_peer_inflight("fast") == 32, "F: cold-start flat (fast)");
    CHECK(sched.effective_per_peer_inflight("slow") == 32, "F: cold-start flat (slow)");

    // Assign a batch to each peer, then deliver ALL of fast's bodies and only
    // ONE of slow's — fast becomes the high-throughput deliverer.
    auto assign = sched.pump(/*now=*/1, peers, hash_at, /*buffered=*/0);
    std::map<std::string, std::vector<uint256>> got;
    for (const auto& a : assign)
        for (const auto& [h, hash] : a.blocks)
            got[a.peer].push_back(hash);
    CHECK(!got["fast"].empty() && !got["slow"].empty(),
          "E-pre: both peers were assigned a fresh range");

    for (const auto& hash : got["fast"]) sched.on_body(hash, 1024);
    if (!got["slow"].empty()) sched.on_body(got["slow"].front(), 1024);

    const std::uint32_t eff_fast = sched.effective_per_peer_inflight("fast");
    const std::uint32_t eff_slow = sched.effective_per_peer_inflight("slow");
    CHECK(eff_fast == 32, "E: fast (top deliverer) earns the full window");
    CHECK(eff_slow >= 8 && eff_slow < 32, "E: slow peer window narrowed but floored");
    CHECK(eff_slow < eff_fast, "E: slow window strictly below fast window");
}

int main()
{
    std::cout << "=== #154 bulk local-primary + weighted-inflight KAT ===\n";
    test_lever1();
    test_lever2_pure();
    test_lever2_scheduler();

    if (g_failures == 0)
        std::cout << "ALL PASS\n";
    else
        std::cout << g_failures << " CHECK(S) FAILED\n";
    return g_failures == 0 ? 0 : 1;
}
