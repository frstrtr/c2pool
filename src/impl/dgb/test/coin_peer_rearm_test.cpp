// dgb_coin_peer_rearm_test — KAT for the emergency seed-fallback RE-ARM fix.
//
// Pins the three MANDATORY properties of docs/coin-peer-manager-rearm.md as
// applied to the DGB per-coin copy (src/impl/dgb/coin/coin_peer_manager.hpp):
//
//   1. BACKOFF     — delay(n) = min(base<<n, cap), base floored 60s, saturating
//                    at cap; the shift is overflow-safe for arbitrarily large n.
//   2. RE-ENTRY    — N consecutive starved ticks between two timer firings arm
//                    EXACTLY ONE re-arm (attempt counter advances by 1, not N).
//   3. RECOVERY    — a connected>=min_peers tick zeroes the attempt counter; the
//                    next starvation re-arms from base, not from the ceiling.
//
// On master these entry points do not exist (arm_emergency_fallbacks /
// clear_emergency_state / emergency_backoff_delay_sec / emergency_attempt), so
// this TU fails to COMPILE — the required red.
//
// Deterministic + hermetic: no io_context is ever run and the manager carries
// no DNS/fixed/HTTP seeds, so on_emergency_timer_fired's three tiers are all
// no-ops. The state machine is driven synchronously through the public API and
// a simulated timer fire.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include <impl/dgb/coin/coin_peer_manager.hpp>

using dgb::coin::DgbCoinPeerManager;
using dgb::coin::DgbPeerManagerConfig;

namespace {

// A started manager with NO seeds: every fallback tier is a no-op, so the
// re-arm handler touches no network / no disk and we can drive the machine by
// hand. start() sets m_running (arm_* early-returns otherwise).
std::unique_ptr<DgbCoinPeerManager> make_started(boost::asio::io_context& ioc,
                                                 const DgbPeerManagerConfig& cfg)
{
    auto mgr = std::make_unique<DgbCoinPeerManager>(
        ioc, "DGBTEST", ::testing::TempDir(), cfg);
    mgr->start();   // no seeds set -> bootstrap/fixed/http tiers all no-op
    return mgr;
}

} // namespace

// ── Property 1: saturating binary-exponential backoff schedule + overflow ─────
TEST(DgbCoinPeerRearm, BackoffScheduleFlooredAndSaturating)
{
    // base_backoff_sec default 30 is floored to 60 (never faster than the
    // original 60s/90s one-shot tiers): 60,120,240,480,960,1920, then clamped.
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 0),   60);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 1),  120);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 2),  240);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 3),  480);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 4),  960);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 5), 1920);
    // 60<<6 = 3840 > 3600 -> clamped to the ~1h ceiling (bounded heartbeat).
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 6), 3600);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 7), 3600);

    // A base ABOVE the 60s floor shifts from that base.
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(100, 3600, 0), 100);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(100, 3600, 1), 200);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(100, 3600, 5), 3200);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(100, 3600, 6), 3600);

    // cap below the 60s floor: min(base<<n, cap) == cap immediately.
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 50, 0), 50);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 50, 3), 50);

    // OVERFLOW GUARD: huge n never overflows / never spins — saturates at cap.
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 1000000), 3600);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, 2147483647), 3600);

    // Monotonic non-decreasing across the whole sweep.
    long long prev = 0;
    for (int n = 0; n < 64; ++n) {
        long long d = DgbCoinPeerManager::emergency_backoff_delay_sec(30, 3600, n);
        EXPECT_GE(d, prev);
        EXPECT_LE(d, 3600);
        prev = d;
    }
}

// ── Property 2: re-entry guard — N starved ticks arm EXACTLY ONE re-arm ───────
TEST(DgbCoinPeerRearm, ReEntryGuardOneArmPerFiring)
{
    boost::asio::io_context ioc;
    DgbPeerManagerConfig cfg;              // min_peers 5, base 30, max 3600
    auto mgr = make_started(ioc, cfg);

    ASSERT_FALSE(mgr->emergency_active());
    ASSERT_EQ(mgr->emergency_attempt(), 0);

    // First starved maintenance tick arms once.
    mgr->arm_emergency_fallbacks();
    EXPECT_TRUE(mgr->emergency_active());
    EXPECT_EQ(mgr->emergency_attempt(), 1);

    // Many further starved ticks BEFORE the timer fires must all no-op.
    for (int i = 0; i < 25; ++i)
        mgr->arm_emergency_fallbacks();
    EXPECT_TRUE(mgr->emergency_active());
    EXPECT_EQ(mgr->emergency_attempt(), 1);   // exactly ONE arm, not 26

    // Simulate the scheduled re-arm firing: latch released at the top so the
    // next starved tick can escalate.
    mgr->on_emergency_timer_fired(boost::system::error_code{});
    EXPECT_FALSE(mgr->emergency_active());
    EXPECT_EQ(mgr->emergency_attempt(), 1);   // firing does not advance n

    // Still starved -> next tick arms again, escalating the attempt counter.
    mgr->arm_emergency_fallbacks();
    EXPECT_TRUE(mgr->emergency_active());
    EXPECT_EQ(mgr->emergency_attempt(), 2);
    for (int i = 0; i < 10; ++i)
        mgr->arm_emergency_fallbacks();
    EXPECT_EQ(mgr->emergency_attempt(), 2);   // still exactly one arm this window
}

// ── Property 3: recovery zeroes the counter; next starvation restarts at base ─
TEST(DgbCoinPeerRearm, RecoveryResetsBackoffToBase)
{
    boost::asio::io_context ioc;
    DgbPeerManagerConfig cfg;
    auto mgr = make_started(ioc, cfg);

    // Escalate a few rounds: arm, fire, arm, fire, ...
    for (int round = 0; round < 4; ++round) {
        mgr->arm_emergency_fallbacks();
        mgr->on_emergency_timer_fired(boost::system::error_code{});
    }
    mgr->arm_emergency_fallbacks();           // leave one pending
    EXPECT_EQ(mgr->emergency_attempt(), 5);
    EXPECT_TRUE(mgr->emergency_active());

    // Recovery tick (connected >= min_peers) resets EVERYTHING.
    mgr->clear_emergency_state();
    EXPECT_FALSE(mgr->emergency_active());
    EXPECT_EQ(mgr->emergency_attempt(), 0);

    // The next starvation re-arms from base (attempt index 0), NOT the ceiling.
    mgr->arm_emergency_fallbacks();
    EXPECT_EQ(mgr->emergency_attempt(), 1);
    EXPECT_EQ(DgbCoinPeerManager::emergency_backoff_delay_sec(
                  cfg.base_backoff_sec, cfg.max_backoff_sec, 0),
              60);
}

// ── needs_emergency_refresh gate: below min triggers, at/above does not ───────
TEST(DgbCoinPeerRearm, NeedsEmergencyRefreshGate)
{
    boost::asio::io_context ioc;
    DgbPeerManagerConfig cfg;                 // min_peers 5
    auto mgr = make_started(ioc, cfg);

    EXPECT_TRUE(mgr->needs_emergency_refresh(0));
    EXPECT_TRUE(mgr->needs_emergency_refresh(cfg.min_peers - 1));
    EXPECT_FALSE(mgr->needs_emergency_refresh(cfg.min_peers));
    EXPECT_FALSE(mgr->needs_emergency_refresh(cfg.min_peers + 10));

    // disable_discovery hard-off: no re-arm even when starved.
    DgbPeerManagerConfig off = cfg;
    off.disable_discovery = true;
    auto mgr_off = make_started(ioc, off);
    EXPECT_FALSE(mgr_off->needs_emergency_refresh(0));
}
