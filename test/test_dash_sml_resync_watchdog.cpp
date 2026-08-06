// D-DASH.SML-RESYNC — the tip mnlistdiff request had no retry, and one lost
// reply cost a full block interval of embedded serving.
//
// MEASURED (hotel node 109.161.52.148, 2026-08-06, 5h33m window). The embedded
// arm spent 943 s on the dashd fallback. 586 s of that — 62% of the total and
// 99% of all `dmn-stale` time — sat in FIVE episodes of 275/156/103/51/1 s, and
// every one was closed by `[EMB-DASH] tip advanced`, i.e. by the chain moving
// on, never by the SML catching up at the tip it was already on. The SML
// advances on exactly one trigger (a tip change fires getmnlistd) and there is
// no retry anywhere, so a request that is never sent or never answered strands
// the embedded arm until the next block fires the trigger again.
//
// The two competing explanations were ELIMINATED, not assumed:
//   * not the base-continuity guard — zero `[SML] REJECT` lines in the window;
//   * not the historical demux stealing the tip reply — QuorumMemberSource::
//     on_mnlistdiff matches STRICTLY on (baseBlockHash.IsNull() AND blockHash
//     in the await set), so a tip incremental can never be claimed by it.
//
// These tests pin the POLICY, which is where the risk is. A retry that is too
// eager hammers a peer that is already struggling; one that is too lazy is the
// bug. So the bounds are the contract: never on the ordinary sub-second per-tip
// window, never unbounded, always reset by real progress.
#include <gtest/gtest.h>

#include <array>
#include <cstring>

#include <impl/dash/coin/sml_resync_watchdog.hpp>

using dash::coin::SmlResyncWatchdog;

namespace {

uint256 blk(uint8_t seed)
{
    uint256 h;
    // Mainnet-SHAPED: top bytes zero (difficulty padding), entropy low down.
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 25; ++i) p[i] = static_cast<uint8_t>(seed + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

SmlResyncWatchdog::Config fast()
{
    SmlResyncWatchdog::Config c;
    c.min_quiet_sec = 20;
    c.backoff_mult  = 2;
    c.max_attempts  = 3;
    return c;
}

}  // namespace

// ── THE DEFECT: a stuck SML must eventually be re-asked ─────────────────────
// Without a retry this is the 156 s hole at h=2517141: the SML sits behind the
// tip and nothing asks again until the next block.
TEST(DashSmlResyncWatchdog, StuckSmlIsReRequestedAfterTheQuietPeriod)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11), sml = blk(0x22);

    EXPECT_FALSE(w.observe(tip, sml, 1000).has_value())
        << "the FIRST sighting of a lag must never retry — that is the ordinary "
           "tip-change round trip, measured at ~54 ms";
    EXPECT_FALSE(w.observe(tip, sml, 1019).has_value())
        << "still inside the quiet period";

    auto r = w.observe(tip, sml, 1020);
    ASSERT_TRUE(r.has_value())
        << "after min_quiet with NO SML progress the request must be re-sent; "
           "without this the arm waits for the next block (~156 s measured)";
    EXPECT_EQ(r->base, sml)   << "re-ask from where the SML actually is";
    EXPECT_EQ(r->target, tip) << "...up to the tip we are trying to build on";
    EXPECT_EQ(r->attempt, 1u);
}

// ── The ordinary per-tip window must NEVER trigger it ───────────────────────
// 104 of the 109 measured dmn-stale episodes were sub-second. A retry there is
// pure duplicate traffic against a peer that is answering perfectly well.
TEST(DashSmlResyncWatchdog, OrdinaryPerTipWindowNeverRetries)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11);
    EXPECT_FALSE(w.observe(tip, blk(0x22), 1000).has_value());
    // The real diff lands ~54 ms later; the watchdog is polled either side.
    EXPECT_FALSE(w.observe(tip, tip, 1001).has_value());
    EXPECT_EQ(w.attempts(), 0u)
        << "a healthy tip-change round trip must cost ZERO retries";
}

// ── Progress resets the policy ──────────────────────────────────────────────
TEST(DashSmlResyncWatchdog, SmlProgressResetsAttempts)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11);
    w.observe(tip, blk(0x22), 1000);
    ASSERT_TRUE(w.observe(tip, blk(0x22), 1020).has_value());
    EXPECT_EQ(w.attempts(), 1u);

    // The SML moved (to an intermediate block, still not the tip): that is
    // progress, so the budget starts over rather than expiring mid-recovery.
    EXPECT_FALSE(w.observe(tip, blk(0x33), 1021).has_value());
    EXPECT_EQ(w.attempts(), 0u);
}

TEST(DashSmlResyncWatchdog, ReachingTheTipClearsEverything)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11);
    w.observe(tip, blk(0x22), 1000);
    ASSERT_TRUE(w.observe(tip, blk(0x22), 1020).has_value());
    EXPECT_FALSE(w.observe(tip, tip, 1030).has_value());
    EXPECT_EQ(w.attempts(), 0u);
}

// ── Bounded: backoff, then silence ──────────────────────────────────────────
// The failure mode of a retry is hammering a peer that is already struggling,
// so the cap is the safety property, not a nicety.
TEST(DashSmlResyncWatchdog, BacksOffGeometricallyThenStopsAtTheCap)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11), sml = blk(0x22);
    w.observe(tip, sml, 1000);

    ASSERT_TRUE(w.observe(tip, sml, 1020).has_value());          // +20
    EXPECT_FALSE(w.observe(tip, sml, 1059).has_value());         // needs +40
    ASSERT_TRUE(w.observe(tip, sml, 1060).has_value());          // attempt 2
    EXPECT_FALSE(w.observe(tip, sml, 1139).has_value());         // needs +80
    auto third = w.observe(tip, sml, 1140);
    ASSERT_TRUE(third.has_value());
    EXPECT_EQ(third->attempt, 3u);

    // Cap reached: from here we are silent and the next block does what it
    // does today. A stuck peer therefore sees today's traffic plus at most
    // max_attempts extra requests, ever.
    EXPECT_FALSE(w.observe(tip, sml, 5000).has_value());
    EXPECT_FALSE(w.observe(tip, sml, 99999).has_value());
    EXPECT_EQ(w.attempts(), 3u);
}

// A new tip is a new situation: the previous budget described a lag that no
// longer exists, so it must not carry over and silence the new one.
TEST(DashSmlResyncWatchdog, NewTipRestartsTheBudget)
{
    SmlResyncWatchdog w(fast());
    const uint256 sml = blk(0x22);
    w.observe(blk(0x11), sml, 1000);
    w.observe(blk(0x11), sml, 1020);
    w.observe(blk(0x11), sml, 1060);
    ASSERT_TRUE(w.observe(blk(0x11), sml, 1140).has_value());
    EXPECT_FALSE(w.observe(blk(0x11), sml, 9000).has_value());   // capped

    EXPECT_FALSE(w.observe(blk(0x44), sml, 9001).has_value());   // new tip: first sighting
    EXPECT_EQ(w.attempts(), 0u);
    EXPECT_TRUE(w.observe(blk(0x44), sml, 9021).has_value())
        << "a fresh tip must get its own retry budget — otherwise one exhausted "
           "episode silences the watchdog for every block after it";
}

// ── A cold / reorg-wiped SML is NOT this watchdog's business ────────────────
// ZERO base means a FULL-snapshot re-seed, a different and much heavier
// request with its own drivers (handshake, on_sml_reorg -> m_on_full_resync).
// Re-asking for one here would duplicate a ~32 kB snapshot fetch.
TEST(DashSmlResyncWatchdog, ColdOrWipedSmlIsNeverReRequestedHere)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11);
    EXPECT_FALSE(w.observe(tip, uint256::ZERO, 1000).has_value());
    EXPECT_FALSE(w.observe(tip, uint256::ZERO, 5000).has_value());
    EXPECT_EQ(w.attempts(), 0u);
}

// ── The watchdog cannot widen what is served ────────────────────────────────
// It emits a REQUEST and nothing else: no gate, no threshold, no predicate. The
// only thing it can do is make the state the gate reads arrive sooner. This
// test pins that the request is exactly the one the tip-change path would have
// sent, so a retry can never ask for something the normal path would not.
TEST(DashSmlResyncWatchdog, RequestIsIdenticalToTheOneTheTipChangeWouldSend)
{
    SmlResyncWatchdog w(fast());
    const uint256 tip = blk(0x11), sml = blk(0x22);
    w.observe(tip, sml, 1000);
    auto r = w.observe(tip, sml, 1020);
    ASSERT_TRUE(r.has_value());
    // main_dash's tip-change path sends send_getmnlistd(*sml_base, new_tip).
    EXPECT_EQ(r->base, sml);
    EXPECT_EQ(r->target, tip);
}
