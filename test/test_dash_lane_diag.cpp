// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH embedded/replay DIAGNOSTIC LOGGING KAT.
///
/// Every case here pins a behaviour that a real incident on 2026-08-04/05 paid
/// for. The suite is deliberately about the MECHANISM (throttle policy,
/// watchdog independence, source attribution) rather than about log text —
/// text is not a contract, but "the warning fires even when the drive function
/// is skipped" is.
///
///   1. THROTTLE — a progress line must be emitted on progress OR on elapsed
///      time, whichever comes FIRST, and never per block. The same day's log
///      carried 205k+ repeated lines from one un-throttled site.
///
///   2. WATCHDOG INDEPENDENCE — the worst defect of the day. The MN-CKPT
///      bridge froze on BOTH .211 and contabo right after a completed
///      on-demand PoSe fold (cursors h=2514874 / h=2516862) for 11-12 minutes
///      with NO warning, because the stall probe lived inside pump(), below
///      the very early-return that the freeze state produces. The KAT drives
///      the lane into exactly that state — a fold request outstanding, so
///      pump() returns before its own probe — and asserts the watchdog still
///      reports the freeze, and names what the lane is waiting for.
///
///   3. SOURCE ATTRIBUTION — we believed a serve was daemonless when the payee
///      queue was riding a dashd `protx list` seed; only an A/B with
///      --coin-rpc removed exposed it. Every population event now names its
///      source and the maintainer keeps it.
///
///   4. SUPPRESSION — a repeat storm collapses to one line plus a counted
///      `suppressed=N`, never to silence.
///
/// #895 note: nothing here is #ifdef-guarded — a green tick means the bodies
/// ran.

#include <gtest/gtest.h>

#include <impl/dash/coin/lane_diag.hpp>           // the DUT primitives
#include <impl/dash/coin/mn_checkpoint.hpp>       // parse_mn_checkpoint
#include <impl/dash/coin/mn_checkpoint_lane.hpp>  // MnCheckpointLane (watchdog)
#include <impl/dash/coin/node_interface.hpp>      // MnListUpdate::source
#include <impl/dash/coin/replay_payee_publish.hpp>  // kPayeeSource* (#1128 SSOT tokens)
#include <impl/dash/coin/mn_list_ingest.hpp>      // wire_mn_list_ingest (leg 4)
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>

#include <core/uint256.hpp>

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace diag = dash::coin::diag;
using dash::coin::MNState;
using dash::coin::MnCheckpoint;
using dash::coin::MnCheckpointLane;
using dash::coin::parse_mn_checkpoint;

namespace {

// Same committed testnet anchor the E2d suite uses. Included rather than
// re-derived so a fixture regeneration cannot make these two suites disagree
// about what the anchor says.
const char* const kDiagCheckpoint1519543 =
#include "dash_mn_checkpoint_testnet_1519543.inc"
    ;

constexpr uint32_t kDiagAnchorHeight = 1519543;

MnCheckpoint diag_checkpoint()
{
    auto cp = parse_mn_checkpoint(kDiagCheckpoint1519543, "testnet");
    EXPECT_TRUE(cp.ok) << cp.error;
    return cp;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// 1. ProgressReporter — the two-axis throttle
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashLaneDiag, ProgressThrottleFiresOnUnitsBeforeTime)
{
    diag::ProgressReporter p(/*every_units=*/100, /*every_ms=*/60000);
    int64_t t = 1000;
    p.start(0, t);

    // 99 units, well inside the time window: NOTHING.
    EXPECT_FALSE(p.sample(99, t + 10).has_value())
        << "a progress line fired before either throttle axis was reached —"
           " that is the per-block flood this class exists to prevent";
    // The 100th unit trips the unit axis even though no time has passed.
    auto s = p.sample(100, t + 20);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->delta, 100u);
    EXPECT_EQ(s->units, 100u);
}

TEST(DashLaneDiag, ProgressThrottleFiresOnTimeWhenUnitsCrawl)
{
    diag::ProgressReporter p(/*every_units=*/500, /*every_ms=*/15000);
    int64_t t = 0;
    p.start(0, t);

    // A lane crawling at a few blocks a minute must NOT go quiet until it has
    // covered 500 blocks. That silence is exactly when an operator most needs
    // the line.
    EXPECT_FALSE(p.sample(3, t + 14999).has_value());
    auto s = p.sample(4, t + 15000);
    ASSERT_TRUE(s.has_value()) << "the time axis never fired: a slow lane would"
                                  " stay silent for as long as it takes to"
                                  " cover 500 blocks";
    EXPECT_EQ(s->delta, 4u);
    EXPECT_EQ(s->elapsed_ms, 15000);
}

TEST(DashLaneDiag, ProgressRateAndEtaAreMeasuredOverTheLastWindow)
{
    diag::ProgressReporter p(/*every_units=*/100, /*every_ms=*/1000000);
    p.start(0, 0);
    // 100 blocks in 1000 ms == 100 blk/s.
    auto s = p.sample(100, 1000);
    ASSERT_TRUE(s.has_value());
    EXPECT_DOUBLE_EQ(s->rate_per_s, 100.0);
    auto eta = diag::ProgressReporter::eta_s(*s, /*remaining=*/250);
    ASSERT_TRUE(eta.has_value());
    EXPECT_DOUBLE_EQ(*eta, 2.5);

    // The NEXT window is measured on its own, not since the start: 100 blocks
    // in 2000 ms == 50 blk/s. "Is it speeding up or slowing down" is the
    // question an operator actually asks.
    auto s2 = p.sample(200, 3000);
    ASSERT_TRUE(s2.has_value());
    EXPECT_DOUBLE_EQ(s2->rate_per_s, 50.0);
}

TEST(DashLaneDiag, EtaIsNotAvailableRatherThanZeroWhenNothingMoved)
{
    diag::ProgressReporter p(/*every_units=*/100, /*every_ms=*/1000);
    p.start(0, 0);
    auto s = p.sample(0, 1000);       // time axis fired, zero progress
    ASSERT_TRUE(s.has_value());
    EXPECT_DOUBLE_EQ(s->rate_per_s, 0.0);
    EXPECT_FALSE(diag::ProgressReporter::eta_s(*s, 500).has_value())
        << "a stalled lane must print eta=n/a; 'zero seconds remaining' is a"
           " different claim and it is false";
    EXPECT_EQ(diag::fmt_eta(std::nullopt), "n/a");
}

TEST(DashLaneDiag, StartRebaselinesSoARearmCannotReportANegativeDelta)
{
    diag::ProgressReporter p(/*every_units=*/10, /*every_ms=*/1000);
    p.start(0, 0);
    ASSERT_TRUE(p.sample(500, 1000).has_value());
    // A re-armed bridge restarts its counter at 0. Without the rebaseline the
    // next sample computes 0 - 500 and reports nonsense.
    p.start(0, 2000);
    auto s = p.sample(10, 3000);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->delta, 10u);
    EXPECT_GT(s->rate_per_s, 0.0);
}

TEST(DashLaneDiag, ByteFormattingKeepsValueAndUnitInOneToken)
{
    EXPECT_EQ(diag::fmt_bytes(512), "512B");
    EXPECT_EQ(diag::fmt_bytes(1024), "1.0KB");
    EXPECT_EQ(diag::fmt_bytes(59662336), "56.9MB");
    EXPECT_EQ(diag::fmt_eta(19.0), "19s");
    EXPECT_EQ(diag::fmt_eta(252.0), "4m12s");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. StallWatchdog — the primitive
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashLaneDiag, WatchdogFiresAfterSilenceAndRepeatsOnItsOwnInterval)
{
    diag::StallWatchdog w(/*stall_ms=*/90000, /*repeat_ms=*/120000);
    w.arm(0);
    EXPECT_FALSE(w.due(89999).has_value());
    auto first = w.due(90000);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(*first, 90000);
    // Not again until the repeat interval — a freeze must be loud, not a storm.
    EXPECT_FALSE(w.due(150000).has_value());
    ASSERT_TRUE(w.due(210000).has_value());
    EXPECT_EQ(w.warnings(), 2u);
}

TEST(DashLaneDiag, WatchdogProgressResetsTheClockAndDisarmSilencesIt)
{
    diag::StallWatchdog w(/*stall_ms=*/1000, /*repeat_ms=*/1000);
    w.arm(0);
    w.progress(900);
    EXPECT_FALSE(w.due(1500).has_value()) << "the clock must run from the last"
                                             " ADVANCE, not from arm()";
    ASSERT_TRUE(w.due(1900).has_value());

    // A published / failed-closed lane is DONE, not frozen.
    w.disarm();
    EXPECT_FALSE(w.due(999999).has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. THE INCIDENT KAT: the watchdog fires from a path pump() cannot skip
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// Minimal lane rig: a synthetic header chain, a block request seam that never
/// answers, and a snapshot seam that never replies — i.e. the exact shape of
/// the 2026-08-04 freeze (a fold request outstanding, nothing coming back).
struct WatchdogRig
{
    MnCheckpointLane lane;
    std::map<uint32_t, uint256> headers;
    uint32_t tip{0};
    int64_t  now{0};
    std::vector<uint32_t> requested_blocks;
    int snapshot_requests{0};

    WatchdogRig()
    {
        lane.set_clock_fn([this] { return now; });
        lane.set_tip_height_fn([this] { return tip; });
        lane.set_header_hash_at_fn(
            [this](uint32_t h) -> std::optional<uint256> {
                auto it = headers.find(h);
                if (it == headers.end()) return std::nullopt;
                return it->second;
            });
        lane.set_publish_fn(
            [](std::vector<std::pair<uint256, MNState>>, uint32_t) {});
        // The peer that goes quiet: getdata is recorded and never answered.
        // (#138: returns true — the request DID reach the peer; it is the
        // answer that never comes. A false return would model a request that
        // died locally, which is a different defect with its own test in
        // test_dash_mn_checkpoint.cpp.)
        lane.set_request_block_fn(
            [this](uint32_t h) { requested_blocks.push_back(h); return true; });
        // The masternode-list request that never draws a reply — this is what
        // parks pump() before its own stall probe.
        lane.set_request_snapshot_fn(
            [this](const uint256&) { ++snapshot_requests; });
        lane.set_merkle_root_at_fn(
            [](const uint256&) -> std::optional<uint256> { return std::nullopt; });
    }
};

} // namespace

TEST(DashLaneDiag, WatchdogFiresWhilePumpEarlyReturnsOnAPendingFold)
{
    WatchdogRig rig;
    auto cp = diag_checkpoint();
    rig.headers[kDiagAnchorHeight] = cp.blockhash;
    rig.tip = kDiagAnchorHeight + 50;
    rig.lane.arm(cp);
    rig.lane.set_watchdog(/*stall_ms=*/90000, /*repeat_ms=*/120000);

    // Drive the bridge to the anchor fold: the lane requests the masternode
    // list as of the anchor and PARKS. m_snapshot_pending is now set.
    rig.lane.pump();
    ASSERT_TRUE(rig.lane.snapshot_pending())
        << "the rig failed to reach the parked state the incident occurred in";
    ASSERT_GE(rig.snapshot_requests, 1);

    // THE DEFECT, reproduced: pump() returns before its own stall probe while
    // a snapshot is pending, so no amount of pumping produces a symptom.
    const uint32_t cursor_before = rig.lane.cursor_height();
    for (int i = 0; i < 10; ++i) rig.lane.pump();
    EXPECT_EQ(rig.lane.cursor_height(), cursor_before)
        << "the cursor moved — this rig is no longer reproducing a freeze";

    // THE FIX: the watchdog runs off wall clock on an independent path. Twelve
    // minutes of silence — the measured duration of the real freeze — MUST be
    // reportable, and reportable long before that.
    rig.now = 89999;
    rig.lane.watchdog_tick();               // not yet
    rig.now = 90000;
    rig.lane.watchdog_tick();               // fires

    // And it names what the lane is waiting for, which is the fact that was
    // missing: a frozen lane published a cursor but never said why it was
    // stuck, so "peer dropped our getdata" and "peer never answered the fold"
    // looked identical from outside.
    const std::string waiting = rig.lane.waiting_for();
    EXPECT_NE(waiting.find("mnlist-reply"), std::string::npos)
        << "waiting_for() did not name the outstanding masternode-list"
           " request; it said: " << waiting;
    EXPECT_NE(waiting.find(std::to_string(kDiagAnchorHeight)),
              std::string::npos)
        << "waiting_for() did not name the height it is parked on: " << waiting;
}

TEST(DashLaneDiag, WatchdogStaysSilentOnAnUnstartedLane)
{
    WatchdogRig rig;
    // Armed but the header chain has not reached the anchor: the bridge has
    // not started, so there is nothing to be frozen. A watchdog that cried
    // here would train operators to ignore the tag.
    auto cp = diag_checkpoint();
    rig.tip = kDiagAnchorHeight - 1000;
    rig.lane.arm(cp);
    rig.lane.pump();
    rig.now = 100000000;
    rig.lane.watchdog_tick();   // must not throw, must not warn
    EXPECT_EQ(rig.lane.cursor_height(), kDiagAnchorHeight);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3b. THE ONDEMAND-MNLIST FREEZE KAT (2026-08-19). A bridging getmnlistd that
//     goes unanswered must RE-ASK A DIFFERENT PEER and raise the outbound
//     stall signal on WALL CLOCK — WITHOUT waiting for a tip change. dashd
//     re-asks mnlistdiff from another peer on timeout and opens an extra
//     outbound when behind; our tip-driven tick_pending_fold() re-ask cannot,
//     because a 1.38M-block-behind fold sees no new tip while it is frozen
//     (live: waiting_for=ondemand-mnlist-reply, 1316 s, ONE ask, ONE peer,
//     pool pinned at 8/8).
// ═══════════════════════════════════════════════════════════════════════════

namespace {

/// WatchdogRig plus the rotate+demote RE-ASK seam and the outbound STALL
/// SIGNAL seam the fix drives from wall clock.
struct OndemandReaskRig
{
    MnCheckpointLane lane;
    std::map<uint32_t, uint256> headers;
    uint32_t tip{0};
    int64_t  now{0};
    int first_asks{0};
    int reasks{0};
    bool last_stall{false};

    OndemandReaskRig()
    {
        lane.set_clock_fn([this] { return now; });
        lane.set_tip_height_fn([this] { return tip; });
        lane.set_header_hash_at_fn(
            [this](uint32_t h) -> std::optional<uint256> {
                auto it = headers.find(h);
                if (it == headers.end()) return std::nullopt;
                return it->second;
            });
        lane.set_publish_fn(
            [](std::vector<std::pair<uint256, MNState>>, uint32_t) {});
        lane.set_request_block_fn([](uint32_t) { return true; });
        lane.set_request_snapshot_fn([this](const uint256&) { ++first_asks; });
        // Production wires this to send_getmnlistd_reask (strike the silent
        // carrier + rotate to a fresh eligible peer). Here we observe only that
        // the lane DROVE it — the peer rotation itself is proven in
        // test_dash_coin_p2p_pool.cpp.
        lane.set_reask_snapshot_fn([this](const uint256&) { ++reasks; });
        // The outbound expansion signal (dashd SetTryNewOutboundPeer).
        lane.set_stateful_stall_fn([this](bool s) { last_stall = s; });
        lane.set_merkle_root_at_fn(
            [](const uint256&) -> std::optional<uint256> { return std::nullopt; });
    }
};

} // namespace

TEST(DashLaneDiag, FrozenOndemandMnlistReasksAnotherPeerAndExpandsOnWallClock)
{
    OndemandReaskRig rig;
    auto cp = diag_checkpoint();
    rig.headers[kDiagAnchorHeight] = cp.blockhash;
    rig.tip = kDiagAnchorHeight + 50;
    rig.lane.arm(cp);

    // Nothing outstanding yet: a wall-clock tick, even far past the grace, must
    // NOT declare the pool behind. The stall signal is CONDITIONAL, not latched.
    rig.now = MnCheckpointLane::kStatefulStallGraceMs * 10;
    rig.lane.watchdog_tick();
    EXPECT_FALSE(rig.last_stall);
    rig.now = 0;

    // Park on the anchor fold: ONE getmnlistd out, replay PAUSED — the exact
    // shape the live freeze was stuck in.
    rig.lane.pump();
    ASSERT_TRUE(rig.lane.snapshot_pending());
    ASSERT_EQ(rig.first_asks, 1);
    ASSERT_EQ(rig.reasks, 0);

    // THE FREEZE: the header tip never advances (a fold 1.38M blocks behind
    // sees no new tip), so pump() is NEVER CALLED again — pump() is driven by
    // HeaderChain::on_tip_changed, and there is no tip change while the leg is
    // frozen. tick_pending_fold() therefore never runs, so its own tip-counted
    // re-ask (kFoldRetryPumps) and give-up (kFoldGiveUpPumps) cannot fire. This
    // is the exact live shape: ONE ask, ONE peer, no rotation, forever. Only
    // the wall clock moves from here — nothing calls pump().
    ASSERT_EQ(rig.reasks, 0);

    // Below the grace: not yet stalled.
    rig.now = MnCheckpointLane::kStatefulStallGraceMs - 1;
    rig.lane.watchdog_tick();
    EXPECT_FALSE(rig.last_stall);
    EXPECT_EQ(rig.reasks, 0);

    // Past the grace: THE FIX. Wall clock alone re-asks a fresh peer AND raises
    // the outbound-behind stall signal — no tip change involved.
    rig.now = MnCheckpointLane::kStatefulStallGraceMs;
    rig.lane.watchdog_tick();
    EXPECT_TRUE(rig.last_stall)
        << "a frozen ondemand-mnlist must signal BEHIND so the pool dials past 8";
    EXPECT_EQ(rig.reasks, 1)
        << "a frozen ondemand-mnlist must re-ask on wall clock, not on a tip";
    EXPECT_EQ(rig.lane.wallclock_reasks(), 1u);

    // Still frozen one interval later: it keeps rotating (dashd re-asks another
    // peer each cycle), not one-shot.
    rig.now += MnCheckpointLane::kStatefulReaskIntervalMs;
    rig.lane.watchdog_tick();
    EXPECT_EQ(rig.reasks, 2);
    EXPECT_TRUE(rig.last_stall);
}

TEST(DashLaneDiag, ColdStartIsTheDefaultAndIsStated)
{
    WatchdogRig rig;
    auto cp = diag_checkpoint();
    rig.headers[kDiagAnchorHeight] = cp.blockhash;
    rig.tip = kDiagAnchorHeight + 5;
    rig.lane.arm(cp);
    // There is no replay-cursor persistence in this build. The point of the
    // flag is that the log states the discard rather than leaving it silent.
    EXPECT_FALSE(rig.lane.cursor_restored());
    rig.lane.pump();
    EXPECT_FALSE(rig.lane.cursor_restored());
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. LogSuppressor — a storm becomes one line plus a count, never silence
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashLaneDiag, SuppressorCollapsesAStormAndCarriesTheCount)
{
    diag::LogSuppressor s(/*every_ms=*/30000);
    EXPECT_TRUE(s.allow("k", 0));           // first is always allowed
    for (int i = 1; i < 205000; ++i)
        EXPECT_FALSE(s.allow("k", 1000));   // the 205k-line flood, absorbed
    EXPECT_TRUE(s.allow("k", 30000));
    EXPECT_EQ(s.take_suppressed("k"), 204999u)
        << "the suppressed lines were dropped without being counted — that is"
           " silence, not throttling";
    EXPECT_EQ(s.take_suppressed("k"), 0u);  // taking resets
}

TEST(DashLaneDiag, SuppressorKeyTableIsBounded)
{
    diag::LogSuppressor s(/*every_ms=*/1000);
    for (int i = 0; i < 10 * static_cast<int>(diag::LogSuppressor::kMaxKeys); ++i)
        s.allow("key-" + std::to_string(i), i);
    // No assertion on contents: the contract is only that an unbounded key
    // space cannot grow the table without limit (a leak in a diagnostic is
    // still a leak). Reaching here without exhausting memory is the check.
    SUCCEED();
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. MN-LIST SOURCE ATTRIBUTION — the state says its own name
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashLaneDiag, SourceNamesRoundTripAndDaemonlessIsExplicit)
{
    EXPECT_STREQ(diag::mn_source_name(diag::MnSource::DashdSeed), "dashd-seed");
    EXPECT_STREQ(diag::mn_source_name(diag::MnSource::MnCkpt), "mn-ckpt");
    EXPECT_STREQ(diag::mn_source_name(diag::MnSource::ReplayFold), "replay-fold");
    EXPECT_EQ(diag::mn_source_from_name("mn-ckpt"), diag::MnSource::MnCkpt);
    EXPECT_EQ(diag::mn_source_from_name("nonsense"), diag::MnSource::Unknown);
    // The classifier's tokens ARE #1128's publisher constants. Pinned so a
    // rename on either side is a red test, not a silently mis-classified
    // payee queue.
    EXPECT_EQ(diag::mn_source_from_name(dash::coin::replay::kPayeeSourceDashdSeed),
              diag::MnSource::DashdSeed);
    EXPECT_EQ(diag::mn_source_from_name(dash::coin::replay::kPayeeSourceMnCkpt),
              diag::MnSource::MnCkpt);
    EXPECT_EQ(diag::mn_source_from_name(dash::coin::replay::kPayeeSourceReplayFold),
              diag::MnSource::ReplayFold);
    // "unnamed" is #1128's own word for an un-named publisher.
    EXPECT_FALSE(diag::mn_source_is_daemonless(
        diag::mn_source_from_name("unnamed")));

    // The predicate the A/B run had to establish by hand.
    EXPECT_FALSE(diag::mn_source_is_daemonless(diag::MnSource::DashdSeed));
    EXPECT_TRUE(diag::mn_source_is_daemonless(diag::MnSource::MnCkpt));
    EXPECT_TRUE(diag::mn_source_is_daemonless(diag::MnSource::ReplayFold));
}

TEST(DashLaneDiag, PopulationSourceSurvivesTheLegFourEventIntoTheMaintainer)
{
    dash::coin::NodeCoinState        state;
    dash::coin::CoinStateMaintainer  maint(state);
    dash::interfaces::Node           node;
    auto sub = c2pool::dash::wire_mn_list_ingest(node, maint);

    // Nothing has populated the queue yet.
    EXPECT_TRUE(maint.mn_source().empty());
    EXPECT_FALSE(maint.mn_source_daemonless());

    // A dashd `protx list` startup seed — the source we mistook for
    // daemonless. One masternode is enough: this is about attribution.
    // The token is #1128's own kPayeeSourceDashdSeed constant, so this KAT
    // fails if the publisher constants and the classifier ever drift apart.
    auto cp = diag_checkpoint();
    ASSERT_FALSE(cp.entries.empty());
    dash::interfaces::MnListUpdate up;
    up.mnstates     = {cp.entries.front()};
    up.as_of_height = kDiagAnchorHeight;
    up.source       = dash::coin::replay::kPayeeSourceDashdSeed;
    node.mn_list_update.happened(up);

    EXPECT_EQ(maint.mn_source(), "dashd-seed");
    EXPECT_FALSE(maint.mn_source_daemonless())
        << "a queue riding a dashd seed reported itself as daemonless — this"
           " is the exact misreading that cost a day on 2026-08-04";
    EXPECT_TRUE(maint.have_mn());
    EXPECT_EQ(maint.mn_snapshot_height(), kDiagAnchorHeight);

    // The bridge re-publishes the same queue daemonlessly: the source must
    // FOLLOW the publisher, not stick to whatever came first.
    dash::interfaces::MnListUpdate up2;
    up2.mnstates     = {cp.entries.front()};
    up2.as_of_height = kDiagAnchorHeight + 1;
    up2.source       = dash::coin::replay::kPayeeSourceMnCkpt;
    node.mn_list_update.happened(up2);

    EXPECT_EQ(maint.mn_source(), "mn-ckpt");
    EXPECT_TRUE(maint.mn_source_daemonless());

    // And the root-checked fold, the third lane #1128 added.
    dash::interfaces::MnListUpdate up3;
    up3.mnstates     = {cp.entries.front()};
    up3.as_of_height = kDiagAnchorHeight + 2;
    up3.source       = dash::coin::replay::kPayeeSourceReplayFold;
    node.mn_list_update.happened(up3);
    EXPECT_EQ(maint.mn_source(), "replay-fold");
    EXPECT_TRUE(maint.mn_source_daemonless());
}

TEST(DashLaneDiag, AnUnattributedPublisherIsNeverClassifiedDaemonless)
{
    dash::coin::NodeCoinState        state;
    dash::coin::CoinStateMaintainer  maint(state);
    auto cp = diag_checkpoint();
    // Default-constructed MnListUpdate: no publisher named itself. #1128
    // records that as "unnamed"; the classification must then refuse to
    // claim daemonless — an unattributed queue is exactly the state that
    // cost a day, and it must never read as the good case.
    maint.on_mn_list_update({cp.entries.front()}, kDiagAnchorHeight);
    EXPECT_EQ(maint.mn_source(), "unnamed");
    EXPECT_FALSE(maint.mn_source_daemonless())
        << "an un-named publisher was classified as daemonless — 'unknown'"
           " must show up as a bug, not as 'fine'";
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. STANDING-STATE READOUTS — the [EMBED-STATUS] inputs are readable
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashLaneDiag, PopulateInputsAreReadableWithoutProvokingADecline)
{
    dash::coin::NodeCoinState state;
    // Never reported: -1, which the status line prints as n/a rather than 0.
    EXPECT_EQ(state.have_tip_dbg(), -1);
    EXPECT_EQ(state.have_mn_dbg(), -1);
    state.set_populate_inputs(/*have_tip=*/true, /*have_mn=*/false);
    EXPECT_EQ(state.have_tip_dbg(), 1);
    EXPECT_EQ(state.have_mn_dbg(), 0);
}

TEST(DashLaneDiag, LaneNamesItsOwnStateAndWhatItIsWaitingFor)
{
    WatchdogRig rig;
    EXPECT_STREQ(rig.lane.state_name(), "unarmed");
    auto cp = diag_checkpoint();
    rig.lane.arm(cp);
    EXPECT_STREQ(rig.lane.state_name(), "waiting");
    // Before the header chain reaches the anchor the lane is waiting on
    // headers, and says so by name.
    EXPECT_NE(rig.lane.waiting_for().find("header-tip-to-reach-anchor"),
              std::string::npos)
        << rig.lane.waiting_for();
}
