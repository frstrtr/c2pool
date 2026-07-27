// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for core/p2p_message_stats.hpp — the p2p wire observability layer.
//
// Folded into the EXISTING allowlisted core_test target (never a new
// add_executable: a standalone target is not in build.yml's --target list, so
// CI never builds it and CTest reports the cases "Not Run" — the #769 trap that
// has now bitten this repo three times).
//
// Covers the two pieces with real logic in them:
//   1. command-string -> message-type mapping, including the NUL-padded wire
//      form that reaches the inbound counter BEFORE MessageHandler::parse()
//      strips the padding, plus the unknown-command bucket;
//   2. compute_timestamp_saturation() — the embedded-timestamp clip detector
//      behind the DASH deploy criterion, and compute_tip_lag_seconds().
//
// One KAT covers every coin: both instrumentation points (pool::NodeBridge::
// handle for inbound, pool::Peer::write for outbound) are shared code that all
// coin lanes route through.

#include <gtest/gtest.h>

#include <core/p2p_message_stats.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace core::obs;

// ── 1. command -> message type ──────────────────────────────────────────────

TEST(P2PMessageStats, MapsEveryCanonicalCommand)
{
    // The full operator-facing list. Each name must map to its own slot.
    const std::vector<std::pair<std::string, P2PMessage>> expected = {
        {"version",     P2PMessage::version},
        {"verack",      P2PMessage::verack},
        {"ping",        P2PMessage::ping},
        {"pong",        P2PMessage::pong},
        {"addrme",      P2PMessage::addrme},
        {"addrs",       P2PMessage::addrs},
        {"getaddrs",    P2PMessage::getaddrs},
        {"shares",      P2PMessage::shares},
        {"sharereq",    P2PMessage::sharereq},
        {"sharereply",  P2PMessage::sharereply},
        {"have_tx",     P2PMessage::have_tx},
        {"losing_tx",   P2PMessage::losing_tx},
        {"remember_tx", P2PMessage::remember_tx},
        {"forget_tx",   P2PMessage::forget_tx},
        {"bestblock",   P2PMessage::bestblock},
    };
    ASSERT_EQ(expected.size(), P2P_MESSAGE_COUNT - 1)  // -1 for the unknown bucket
        << "message list drifted from the enum";

    for (const auto& [cmd, type] : expected) {
        EXPECT_EQ(p2p_message_from_command(cmd), type) << "command: " << cmd;
        EXPECT_EQ(p2p_message_name(type), cmd);
    }
}

TEST(P2PMessageStats, TrimsNulPaddedWireCommands)
{
    // Wire command fields are fixed-width and NUL-padded. The inbound counter
    // runs BEFORE MessageHandler::parse() strips the padding, so the untrimmed
    // form must map to the same slot — otherwise every inbound message would
    // land in the unknown bucket and the counters would be useless.
    const std::string padded("ping\0\0\0\0\0\0\0\0", 12);
    EXPECT_EQ(p2p_message_from_command(padded), P2PMessage::ping);
    EXPECT_EQ(trim_command(padded), "ping");

    const std::string padded_share("remember_tx\0", 12);
    EXPECT_EQ(p2p_message_from_command(padded_share), P2PMessage::remember_tx);
}

TEST(P2PMessageStats, UnknownCommandsLandInTheUnknownBucket)
{
    EXPECT_EQ(p2p_message_from_command(""), P2PMessage::unknown);
    EXPECT_EQ(p2p_message_from_command("not_a_message"), P2PMessage::unknown);
    EXPECT_EQ(p2p_message_from_command("ver"), P2PMessage::unknown);      // prefix, not a match
    EXPECT_EQ(p2p_message_from_command("versionx"), P2PMessage::unknown); // superstring
    EXPECT_EQ(p2p_message_from_command("PING"), P2PMessage::unknown);     // case sensitive
}

// ── 2. counters ─────────────────────────────────────────────────────────────

TEST(P2PMessageStats, CountsInAndOutIndependently)
{
    P2PMessageStats stats;   // local instance; the process-global stays untouched

    stats.count_in("shares");
    stats.count_in("shares");
    stats.count_in(std::string("have_tx\0\0", 9));   // NUL-padded wire form
    stats.count_out("sharereq");
    stats.count_out("bestblock");
    stats.count_in("garbage");

    EXPECT_EQ(stats.get_in(P2PMessage::shares), 2u);
    EXPECT_EQ(stats.get_in(P2PMessage::have_tx), 1u);
    EXPECT_EQ(stats.get_out(P2PMessage::shares), 0u)
        << "inbound must not leak into the outbound counter";
    EXPECT_EQ(stats.get_out(P2PMessage::sharereq), 1u);
    EXPECT_EQ(stats.get_out(P2PMessage::bestblock), 1u);
    EXPECT_EQ(stats.get_in(P2PMessage::unknown), 1u);

    EXPECT_EQ(stats.total_in(), 4u);
    EXPECT_EQ(stats.total_out(), 2u);

    stats.reset();
    EXPECT_EQ(stats.total_in(), 0u);
    EXPECT_EQ(stats.total_out(), 0u);
    EXPECT_EQ(stats.known_txs_order_size.load(), -1)
        << "reset must restore the 'lane has no order deque' sentinel, not 0";
}

TEST(P2PMessageStats, DefaultsAreZeroAndTraceIsOff)
{
    P2PMessageStats stats;
    EXPECT_EQ(stats.total_in(), 0u);
    EXPECT_EQ(stats.total_out(), 0u);
    EXPECT_EQ(stats.known_txs_size.load(), 0u);
    EXPECT_EQ(stats.known_txs_order_size.load(), -1);
    EXPECT_FALSE(stats.trace_enabled.load())
        << "per-message tracing must be OFF by default (hot path)";
}

// ── 3. embedded-timestamp saturation ────────────────────────────────────────
//
// DASH: SHARE_PERIOD = 20 s, so the p2pool clip upper bound is 2*20-1 = 39 s.
static constexpr std::uint32_t DASH_CLIP = 39;

TEST(TimestampSaturation, FullySaturatedChainReportsOne)
{
    // Every consecutive embedded delta pinned to the clip bound: the failure
    // mode measured live (embedded clock 6.81 h behind wall-clock).
    std::vector<std::uint32_t> ts;           // newest first
    std::uint32_t t = 1'700'000'000;
    for (int i = 0; i < 101; ++i) { ts.push_back(t); t -= DASH_CLIP; }

    const auto sat = compute_timestamp_saturation(ts, DASH_CLIP);
    EXPECT_EQ(sat.samples, 100u);
    EXPECT_EQ(sat.saturated, 100u);
    EXPECT_DOUBLE_EQ(sat.fraction, 1.0);
}

TEST(TimestampSaturation, HealthyCadenceReportsZero)
{
    // Deltas comfortably under the bound — retarget still sees real cadence.
    std::vector<std::uint32_t> ts;
    std::uint32_t t = 1'700'000'000;
    for (int i = 0; i < 101; ++i) { ts.push_back(t); t -= 20; }

    const auto sat = compute_timestamp_saturation(ts, DASH_CLIP);
    EXPECT_EQ(sat.samples, 100u);
    EXPECT_EQ(sat.saturated, 0u);
    EXPECT_DOUBLE_EQ(sat.fraction, 0.0);
}

TEST(TimestampSaturation, MixedChainReportsTheFraction)
{
    // 4 saturated deltas out of 10.
    const std::vector<std::uint32_t> deltas =
        {DASH_CLIP, 20, DASH_CLIP, 5, DASH_CLIP, 12, 20, DASH_CLIP, 7, 1};
    std::vector<std::uint32_t> ts;
    std::uint32_t t = 1'700'000'000;
    ts.push_back(t);
    for (auto d : deltas) { t -= d; ts.push_back(t); }

    const auto sat = compute_timestamp_saturation(ts, DASH_CLIP);
    EXPECT_EQ(sat.samples, 10u);
    EXPECT_EQ(sat.saturated, 4u);
    EXPECT_DOUBLE_EQ(sat.fraction, 0.4);
}

TEST(TimestampSaturation, OffByOneDeltasAreNotSaturated)
{
    // 38 and 40 are NOT the bound. The detector must be exact — a fuzzy match
    // would fire on a healthy chain and this field is a deploy criterion.
    const std::vector<std::uint32_t> ts = {1'000'078, 1'000'040, 1'000'000};
    const auto sat = compute_timestamp_saturation(ts, DASH_CLIP);
    EXPECT_EQ(sat.samples, 2u);
    EXPECT_EQ(sat.saturated, 0u);
}

TEST(TimestampSaturation, DegenerateInputsAreSafe)
{
    EXPECT_EQ(compute_timestamp_saturation({}, DASH_CLIP).samples, 0u);
    EXPECT_EQ(compute_timestamp_saturation({12345}, DASH_CLIP).samples, 0u);
    EXPECT_DOUBLE_EQ(compute_timestamp_saturation({}, DASH_CLIP).fraction, 0.0);
    // clip 0 is not a real coin configuration; must not divide or fire.
    EXPECT_EQ(compute_timestamp_saturation({100, 100, 100}, 0).samples, 0u);
}

TEST(TimestampSaturation, OutOfOrderPairsCountAsSampleButNeverSaturated)
{
    // Child older than parent is only reachable on a malformed/forked walk.
    // It must not manufacture a false all-clear OR a false alarm — including
    // when the reversed magnitude happens to equal the clip bound exactly.
    const std::vector<std::uint32_t> ts = {1'000'000, 1'000'039, 1'000'078};
    const auto sat = compute_timestamp_saturation(ts, DASH_CLIP);
    EXPECT_EQ(sat.samples, 2u);
    EXPECT_EQ(sat.saturated, 0u);

    // A well-ordered saturated pair adjacent to a reversed one still counts
    // exactly once: {t, t-39, t-39+39=t} -> pair0 saturated, pair1 reversed.
    const std::vector<std::uint32_t> mixed = {1'000'039, 1'000'000, 1'000'039};
    const auto sat_mixed = compute_timestamp_saturation(mixed, DASH_CLIP);
    EXPECT_EQ(sat_mixed.samples, 2u);
    EXPECT_EQ(sat_mixed.saturated, 1u);
}

// ── 4. tip lag ──────────────────────────────────────────────────────────────

TEST(TipLag, MeasuresWallClockMinusEmbeddedTimestamp)
{
    // The live DASH observation: embedded tip 6.81 hours behind wall-clock.
    const std::int64_t now = 1'700'024'516;
    const std::uint32_t tip = 1'700'000'000;
    EXPECT_EQ(compute_tip_lag_seconds(now, tip), 24'516);

    // No tip timestamp known yet -> 0, never a bogus "now" sized lag.
    EXPECT_EQ(compute_tip_lag_seconds(now, 0), 0);

    // A tip stamped slightly ahead of local wall-clock is legal (clock skew);
    // report it honestly as negative rather than clamping.
    EXPECT_EQ(compute_tip_lag_seconds(1'700'000'000, 1'700'000'005), -5);
}
