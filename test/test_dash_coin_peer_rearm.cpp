// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH-isolated CoinPeerManager — emergency seed RE-ARM KATs (never-re-arm fix)
///
/// Pins the three MANDATORY properties of the coin-peer emergency fallback
/// re-arm (docs/coin-peer-manager-rearm.md sections 2.1-2.4), applied to the
/// DASH per-coin copy src/impl/dash/coin/coin_peer_manager.hpp:
///
///   1. BACKOFF — saturating binary exponential: base, 2*base, 4*base, ...
///      clamped at max_backoff_sec, base floored at 60s, overflow-safe for
///      large n (never a bare `base << n`).
///   2. RE-ENTRY GUARD — N starved maintenance ticks between two timer firings
///      schedule EXACTLY ONE re-arm (attempt counter advances by 1, not N).
///   3. RECOVERY RESET — a tick with connected >= min_peers zeroes the attempt
///      counter; the subsequent starvation re-arms from base, not the ceiling.
///
/// On master these entry points do not exist (the DASH copy never wired the
/// emergency path — the maintenance tick only rescheduled itself), so this TU
/// fails to COMPILE against master: the required red.
///
/// Compiled as a fourth TU into the EXISTING allowlisted test_dash_p2p_node
/// target (no new test target, no workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/coin_peer_manager.hpp>

#include <boost/asio.hpp>

#include <filesystem>
#include <string>
#include <unistd.h>

using dash::coin::DashCoinPeerManager;
using dash::coin::DashPeerManagerConfig;

namespace {

DashPeerManagerConfig rearm_cfg()
{
    DashPeerManagerConfig cfg;
    cfg.valid_ports = {9999};
    cfg.min_peers = 5;
    cfg.base_backoff_sec = 30;     // floored to 60 by the emergency path
    cfg.max_backoff_sec = 3600;
    return cfg;
}

std::string rearm_tmp_dir()
{
    static int seq = 0;
    auto dir = std::filesystem::temp_directory_path()
        / ("c2pool_dash_rearm_" + std::to_string(::getpid()) + "_"
           + std::to_string(seq++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir.string();
}

// ── 1. BACKOFF schedule + floor + saturation ─────────────────────────────────

TEST(DashCoinPeerRearm, backoff_schedule_floors_at_60_and_saturates)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", rearm_tmp_dir(), rearm_cfg());

    // base floored to 60: 60, 120, 240, 480, 960, 1920, then clamp at 3600.
    EXPECT_EQ(pm.emergency_delay_sec(0), 60);
    EXPECT_EQ(pm.emergency_delay_sec(1), 120);
    EXPECT_EQ(pm.emergency_delay_sec(2), 240);
    EXPECT_EQ(pm.emergency_delay_sec(3), 480);
    EXPECT_EQ(pm.emergency_delay_sec(4), 960);
    EXPECT_EQ(pm.emergency_delay_sec(5), 1920);
    EXPECT_EQ(pm.emergency_delay_sec(6), 3600);   // 3840 -> clamp
    EXPECT_EQ(pm.emergency_delay_sec(7), 3600);   // saturated

    // never re-arms faster than the original 60s tier, and never exceeds ceiling.
    for (int n = 0; n < 64; ++n) {
        EXPECT_GE(pm.emergency_delay_sec(n), 60);
        EXPECT_LE(pm.emergency_delay_sec(n), 3600);
    }
}

TEST(DashCoinPeerRearm, saturating_helper_is_overflow_safe)
{
    // direct helper: `base << n` early-saturates, never overflows.
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(60, 0, 3600), 60);
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(60, 1, 3600), 120);
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(60, 6, 3600), 3600);
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(1, 100000, 3600), 3600);
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(1, (1 << 30), 3600), 3600);
    EXPECT_EQ(DashCoinPeerManager::saturating_backoff_delay(100, 0, 50), 50); // cap<base
}

// ── 2. RE-ENTRY GUARD: N arms between firings -> exactly ONE re-arm ───────────

TEST(DashCoinPeerRearm, reentry_guard_collapses_many_ticks_to_one_rearm)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", rearm_tmp_dir(), rearm_cfg());
    pm.start();   // sets m_running; no seeds -> nothing fires; ioc not run

    ASSERT_EQ(pm.emergency_attempt_count(), 0);
    ASSERT_FALSE(pm.emergency_active());

    // Simulate MANY starved maintenance ticks before the pending timer fires.
    for (int i = 0; i < 20; ++i)
        pm.arm_emergency_fallbacks();

    // Latch collapsed all 20 arms into ONE scheduled re-arm.
    EXPECT_TRUE(pm.emergency_active());
    EXPECT_EQ(pm.emergency_attempt_count(), 1);

    // Timer fires: latch releases, cycle acts (no seeds -> refresh is a no-op).
    pm.handle_emergency_timer({});
    EXPECT_FALSE(pm.emergency_active());
    EXPECT_EQ(pm.emergency_attempt_count(), 1);

    // Still starved: the next tick arms the SECOND (longer) re-arm -> counter 2.
    for (int i = 0; i < 20; ++i)
        pm.arm_emergency_fallbacks();
    EXPECT_TRUE(pm.emergency_active());
    EXPECT_EQ(pm.emergency_attempt_count(), 2);

    pm.stop();
}

// ── 3. RECOVERY RESET: connected>=min_peers zeroes counter, re-arm from base ──

TEST(DashCoinPeerRearm, recovery_resets_counter_and_rearms_from_base)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", rearm_tmp_dir(), rearm_cfg());
    pm.start();

    // Escalate a few cycles: arm, fire, arm, fire ... -> counter climbs.
    for (int cycle = 0; cycle < 4; ++cycle) {
        pm.arm_emergency_fallbacks();
        pm.handle_emergency_timer({});
    }
    EXPECT_EQ(pm.emergency_attempt_count(), 4);

    // Recovery tick: connected >= min_peers.
    pm.clear_emergency_state();
    EXPECT_EQ(pm.emergency_attempt_count(), 0);
    EXPECT_FALSE(pm.emergency_active());

    // The next drop re-arms from BASE (attempt index 0 -> delay 60), not ceiling.
    pm.arm_emergency_fallbacks();
    EXPECT_EQ(pm.emergency_attempt_count(), 1);
    EXPECT_EQ(pm.emergency_delay_sec(0), 60);   // fresh cycle starts at base

    pm.stop();
}

// ── 4. FLOOR does NOT stop; SHUTDOWN cancels + handler early-returns ──────────

TEST(DashCoinPeerRearm, never_permanently_gives_up_but_stop_terminates)
{
    boost::asio::io_context ioc;
    DashCoinPeerManager pm(ioc, "DASH", rearm_tmp_dir(), rearm_cfg());
    pm.start();

    // Drive well past the ceiling: still starved -> keeps re-arming, saturated
    // at max_backoff_sec (bounded ~1h heartbeat, not silence, not a storm).
    for (int cycle = 0; cycle < 12; ++cycle) {
        pm.arm_emergency_fallbacks();
        pm.handle_emergency_timer({});
    }
    EXPECT_EQ(pm.emergency_attempt_count(), 12);
    EXPECT_EQ(pm.emergency_delay_sec(pm.emergency_attempt_count()), 3600);

    // SHUTDOWN: stop() cancels the emergency timer; a firing after shutdown
    // releases the latch and early-returns (no refresh).
    pm.arm_emergency_fallbacks();
    EXPECT_TRUE(pm.emergency_active());
    pm.stop();
    pm.handle_emergency_timer(boost::asio::error::operation_aborted);
    EXPECT_FALSE(pm.emergency_active());
}

} // namespace
