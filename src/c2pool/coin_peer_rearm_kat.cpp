// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: emergency fallback re-arm — backoff policy, re-entry guard, recovery reset.
// Locks the three MANDATORY properties of docs/coin-peer-manager-rearm.md.
// FAILS on master: emergency_backoff_delay/arm_emergency_fallbacks/
// clear_emergency_state/emergency_attempts do not exist there (compile red).
#include <boost/asio.hpp>
#include <c2pool/merged/coin_peer_manager.hpp>
#include <cstdio>
#include <cstdlib>

using c2pool::merged::CoinPeerManager;
using c2pool::merged::PeerManagerConfig;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main()
{
    // (1) BACKOFF: base, 2*base, 4*base, ... clamped at cap; overflow-safe.
    CHECK(CoinPeerManager::emergency_backoff_delay(0, 60, 3600) == 60);
    CHECK(CoinPeerManager::emergency_backoff_delay(1, 60, 3600) == 120);
    CHECK(CoinPeerManager::emergency_backoff_delay(2, 60, 3600) == 240);
    CHECK(CoinPeerManager::emergency_backoff_delay(5, 60, 3600) == 1920);
    CHECK(CoinPeerManager::emergency_backoff_delay(6, 60, 3600) == 3600); // 3840 clamped
    CHECK(CoinPeerManager::emergency_backoff_delay(100, 60, 3600) == 3600); // no overflow
    CHECK(CoinPeerManager::emergency_backoff_delay(1000000, 30, 3600) == 3600);
    // monotonic non-decreasing, always within [base, cap]
    int prev = 0;
    for (int n = 0; n < 40; ++n) {
        int d = CoinPeerManager::emergency_backoff_delay(n, 60, 3600);
        CHECK(d >= prev);
        CHECK(d <= 3600);
        prev = d;
    }

    // (2) RE-ENTRY GUARD + (3) RECOVERY RESET
    boost::asio::io_context ioc;
    PeerManagerConfig cfg;
    cfg.disable_discovery = false;
    cfg.min_peers = 5;
    cfg.base_backoff_sec = 30;
    cfg.max_backoff_sec = 3600;
    CoinPeerManager pm(ioc, "LTC", "/tmp", cfg);
    pm.test_set_running(true);

    CHECK(pm.emergency_attempts() == 0);
    pm.arm_emergency_fallbacks();
    CHECK(pm.emergency_attempts() == 1);          // first arm schedules once
    // Simulate many maintenance ticks while starvation persists (timer not fired):
    for (int i = 0; i < 5; ++i) pm.arm_emergency_fallbacks();
    CHECK(pm.emergency_attempts() == 1);          // GUARD: no storm, still exactly 1

    pm.clear_emergency_state();
    CHECK(pm.emergency_attempts() == 0);          // RECOVERY RESET to base

    pm.test_set_running(false);                   // do NOT run ioc (no network)

    if (g_fail == 0) { std::printf("coin_peer_rearm_kat PASS\n"); return 0; }
    std::printf("coin_peer_rearm_kat FAIL (%d)\n", g_fail);
    return 1;
}
