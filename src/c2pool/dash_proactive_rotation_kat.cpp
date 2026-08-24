// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: PR-3 PROACTIVE PEER ROTATION policy (dashd-cut coin-P2P, task #154 line).
//
// Locks the three invariants the shipped proactive rotation
// (p2p_client.hpp maybe_proactive_rotate) relies on, over the pure decision
// header proactive_rotation_policy.hpp — the EXACT code the client calls, so a
// green KAT cannot diverge from the shipped path:
//
//   (1) PRIMARY IS NEVER RETIRED. m_primary and any protected-local peer (#147)
//       are the latency reference; slowest_retirement_victim() must skip them
//       even when they are the slowest measured peer in the set.
//   (2) RETIREMENT PICKS THE SLOWEST. Among eligible CanServeBlocks (#148)
//       peers with a measured TipBody delivery-latency EWMA, the victim is the
//       one with the HIGHEST EWMA; ties resolve to the first (deterministic).
//       Non-servers and peers with no measurement are never chosen.
//   (3) CADENCE IS BOUNDED. proactive_due() is false while armed but inside the
//       interval, true once a full interval has elapsed, and NEVER fires when
//       the flag is OFF (byte-identical to master).
//
// Pure red/green over ONE header-only unit, NO node and NO daemon (mirrors the
// PR-0 arrival KAT). Built under -DC2POOL_DASH_BLS=ON like the rest of the dash
// suite; it carries no BLS symbols.

#include <impl/dash/coin/proactive_rotation_policy.hpp>

#include <cstdio>
#include <string>
#include <vector>

using dash::coin::proactivepolicy::PeerLatencyView;
using dash::coin::proactivepolicy::proactive_due;
using dash::coin::proactivepolicy::slowest_retirement_victim;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A plain measured CanServeBlocks server (the common eligible case).
static PeerLatencyView server(const std::string& key, int64_t ewma_ms) {
    PeerLatencyView v;
    v.key = key;
    v.can_serve_blocks = true;
    v.has_latency = ewma_ms >= 0;
    v.ewma_ms = ewma_ms;
    return v;
}

int main()
{
    // ── (1) PRIMARY / PROTECTED-LOCAL ARE NEVER RETIRED ──────────────────────
    {
        // The primary is the SLOWEST peer, yet it must never be the victim.
        std::vector<PeerLatencyView> peers;
        PeerLatencyView prim = server("primary", 9000);
        prim.is_primary = true;
        peers.push_back(prim);
        peers.push_back(server("fast",  50));
        peers.push_back(server("mid",  200));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 2);                       // "mid" (200) — the slowest NON-primary
        CHECK(peers[v].key == "mid");
    }
    {
        // A protected-local (loopback/LAN) peer, even slowest, is exempt (#147).
        std::vector<PeerLatencyView> peers;
        PeerLatencyView loc = server("local", 12000);
        loc.is_protected_local = true;
        peers.push_back(loc);
        peers.push_back(server("remoteA", 300));
        peers.push_back(server("remoteB", 700));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 2);                       // "remoteB" (700), not the local ref
        CHECK(peers[v].key == "remoteB");
    }
    {
        // Only the primary has a measurement — nothing else is eligible, so no
        // victim (the primary is exempt and it is the only measured peer).
        std::vector<PeerLatencyView> peers;
        PeerLatencyView prim = server("primary", 5000);
        prim.is_primary = true;
        peers.push_back(prim);
        peers.push_back(server("unmeasured", -1));   // no sample yet
        CHECK(slowest_retirement_victim(peers) == -1);
    }

    // ── (2) RETIREMENT PICKS THE SLOWEST ─────────────────────────────────────
    {
        // Highest EWMA wins regardless of position.
        std::vector<PeerLatencyView> peers;
        peers.push_back(server("a", 120));
        peers.push_back(server("b", 880));   // slowest
        peers.push_back(server("c", 300));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 1);
        CHECK(peers[v].key == "b");
    }
    {
        // Ties resolve to the FIRST peer (deterministic).
        std::vector<PeerLatencyView> peers;
        peers.push_back(server("first",  500));
        peers.push_back(server("second", 500));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 0);
        CHECK(peers[v].key == "first");
    }
    {
        // A NON-SERVER (#148) is never chosen even when it is slowest — proactive
        // rotation operates ONLY among CanServeBlocks peers.
        std::vector<PeerLatencyView> peers;
        PeerLatencyView nonserver = server("nonserver", 9999);
        nonserver.can_serve_blocks = false;
        peers.push_back(nonserver);
        peers.push_back(server("server", 400));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 1);
        CHECK(peers[v].key == "server");
    }
    {
        // A peer with no measurement is never chosen, even if it is the only
        // non-primary server; a slower MEASURED server outranks it.
        std::vector<PeerLatencyView> peers;
        peers.push_back(server("measured",   250));
        peers.push_back(server("unmeasured", -1));
        const int v = slowest_retirement_victim(peers);
        CHECK(v == 0);
        CHECK(peers[v].key == "measured");
    }
    {
        // Empty set / no eligible peer => -1 (the caller then does nothing).
        std::vector<PeerLatencyView> empty;
        CHECK(slowest_retirement_victim(empty) == -1);

        std::vector<PeerLatencyView> all_unmeasured;
        all_unmeasured.push_back(server("x", -1));
        all_unmeasured.push_back(server("y", -1));
        CHECK(slowest_retirement_victim(all_unmeasured) == -1);
    }

    // ── (3) CADENCE IS BOUNDED ───────────────────────────────────────────────
    {
        const int64_t interval = 300;
        // Flag OFF => NEVER due, however much time has passed (byte-identical to
        // master).
        CHECK(!proactive_due(/*armed=*/false, /*now=*/1'000'000, /*last=*/0, interval));

        // Armed, first fire (last==0): not due until a full interval elapses.
        CHECK(!proactive_due(true, /*now=*/0,   /*last=*/0, interval));
        CHECK(!proactive_due(true, /*now=*/299, /*last=*/0, interval));
        CHECK( proactive_due(true, /*now=*/300, /*last=*/0, interval));
        CHECK( proactive_due(true, /*now=*/900, /*last=*/0, interval));

        // Armed, after a fire at t=1000: bounded to one per interval.
        CHECK(!proactive_due(true, /*now=*/1000, /*last=*/1000, interval));
        CHECK(!proactive_due(true, /*now=*/1299, /*last=*/1000, interval));
        CHECK( proactive_due(true, /*now=*/1300, /*last=*/1000, interval));

        // Non-positive interval never fires (defensive).
        CHECK(!proactive_due(true, /*now=*/10'000, /*last=*/0, 0));
        CHECK(!proactive_due(true, /*now=*/10'000, /*last=*/0, -5));
    }

    if (g_fail == 0) {
        std::printf("dash_proactive_rotation_kat: ALL PASS\n");
        return 0;
    }
    std::printf("dash_proactive_rotation_kat: %d CHECK(s) FAILED\n", g_fail);
    return 1;
}
