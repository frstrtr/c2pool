// SPDX-License-Identifier: AGPL-3.0-or-later
/// [QC-EPISODE] terminal-event classifier KATs (qc_episode_classifier.hpp).
/// Compiled into the CI-allowlisted test_dash_embedded_gbt executable.
///
/// Every `qc-plan-underivable` episode ends exactly one of three ways —
/// `real-arrived` (the qfcommit flood delivered the commitment),
/// `real-mined` (another miner mined it, has_mined flipped), or
/// `window-closed-null` (the DKG window closed with NO real commitment ever
/// seen — the ONLY case dashd's null-commitment arm would have recovered).
/// The class-3 wall-clock total is the standing measurement the null-arm
/// design (docs/DASH_NULL_COMMITMENT_ARM_DESIGN.md §8) defers its build
/// decision to, so the classifier must be exact: each synthetic episode
/// below ends one way and must be named that way, once, with the measured
/// duration — and a resolution none of the three facts explains must say
/// `unclassified`, never borrow a real class.

#include <gtest/gtest.h>

#include <impl/dash/coin/qc_episode_classifier.hpp>

#include <core/uint256.hpp>

#include <cstring>

using dash::coin::QcEpisodeClassifier;
using Terminal = QcEpisodeClassifier::Terminal;

namespace {

uint256 qh256(uint8_t fill)
{
    uint256 u;
    std::memset(u.data(), fill, 32);
    return u;
}

// The incident-shaped window: testnet interval-24 window [1518418,1518426]
// (cycle 1518408, dkgMiningWindowEnd offset 18).
constexpr uint32_t kFirstH = 1'518'418u;
constexpr uint32_t kLastH  = 1'518'426u;

} // namespace

TEST(DashQcEpisodeClassifier, FloodDeliveryClassifiesRealArrived)
{
    QcEpisodeClassifier ep;
    EXPECT_FALSE(ep.active());
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x50), kLastH, /*now=*/100);
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x50), kLastH, /*now=*/160);
    ASSERT_TRUE(ep.active());

    // The cache gained the commitment (the flood delivered it): RESUME.
    auto ended = ep.observe_derivable(kFirstH, /*cache_has=*/true,
                                      /*mined=*/false, /*now=*/245);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->terminal, Terminal::RealArrived);
    EXPECT_STREQ(QcEpisodeClassifier::terminal_name(ended->terminal),
                 "real-arrived");
    EXPECT_EQ(ended->duration_sec, 145)
        << "duration must span the WHOLE episode (first refusal to resume), "
           "not the last observation";
    EXPECT_EQ(ended->llmq_type, 1);
    EXPECT_EQ(ended->quorum_hash, qh256(0x50));
    EXPECT_EQ(ended->first_height, kFirstH);
    EXPECT_EQ(ended->resumed_height, kFirstH);
    EXPECT_FALSE(ep.active());
}

TEST(DashQcEpisodeClassifier, AnotherMinerMiningClassifiesRealMined)
{
    QcEpisodeClassifier ep;
    ep.observe_underivable(kFirstH, 4, 0, qh256(0x51), kLastH, 1000);
    // has_mined flipped (mnlistdiff-fed QuorumManager gained the quorum);
    // the slot left the mandatory set two heights later.
    auto ended = ep.observe_derivable(kFirstH + 2, /*cache_has=*/false,
                                      /*mined=*/true, 1300);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->terminal, Terminal::RealMined);
    EXPECT_STREQ(QcEpisodeClassifier::terminal_name(ended->terminal),
                 "real-mined");
    EXPECT_EQ(ended->duration_sec, 300);
    EXPECT_EQ(ended->resumed_height, kFirstH + 2);
}

TEST(DashQcEpisodeClassifier, WindowCloseWithNothingSeenClassifiesNull)
{
    // The one class that argues FOR the null arm: the whole window passed
    // with the commitment neither delivered nor mined — the network mined
    // null to the end, and only a null arm could have served those heights.
    QcEpisodeClassifier ep;
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x52), kLastH, 0);
    auto ended = ep.observe_derivable(kLastH + 1, /*cache_has=*/false,
                                      /*mined=*/false, 1380);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->terminal, Terminal::WindowClosedNull);
    EXPECT_STREQ(QcEpisodeClassifier::terminal_name(ended->terminal),
                 "window-closed-null");
    EXPECT_EQ(ended->duration_sec, 1380)
        << "~23 min — the whole-window outage shape the design doc predicts "
           "for a genuine failed DKG";
}

TEST(DashQcEpisodeClassifier, InexplicableResolutionSaysUnclassified)
{
    // Window still open, commitment neither cached nor mined, yet the plan
    // derived (e.g. a reorg re-keyed the slot's base hash). The honest name
    // is `unclassified` — mapping it onto a real class would corrupt the
    // very measurement the classifier exists to take.
    QcEpisodeClassifier ep;
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x53), kLastH, 0);
    auto ended = ep.observe_derivable(kFirstH + 1, /*cache_has=*/false,
                                      /*mined=*/false, 60);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->terminal, Terminal::Unclassified);
    EXPECT_STREQ(QcEpisodeClassifier::terminal_name(ended->terminal),
                 "unclassified");
}

TEST(DashQcEpisodeClassifier, EpisodeReSlotsToTheLastBlocker)
{
    // An episode can progress across slots: slot A (type 1) resolves while
    // slot B (type 4) still blocks. The terminal event is classified against
    // the LAST blocker — the slot whose fact-flip actually ended the episode
    // — while the duration still spans from the FIRST refusal.
    QcEpisodeClassifier ep;
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x54), kLastH, 100);
    ep.observe_underivable(kFirstH + 1, 4, 0, qh256(0x55), kLastH, 400);
    ASSERT_TRUE(ep.pending().has_value());
    EXPECT_EQ(ep.pending()->llmq_type, 4);
    EXPECT_EQ(ep.pending()->quorum_hash, qh256(0x55));

    auto ended = ep.observe_derivable(kFirstH + 1, /*cache_has=*/true,
                                      /*mined=*/false, 500);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->llmq_type, 4);
    EXPECT_EQ(ended->quorum_hash, qh256(0x55));
    EXPECT_EQ(ended->duration_sec, 400)
        << "re-slotting must not restart the episode clock";
    EXPECT_EQ(ended->first_height, kFirstH);
}

TEST(DashQcEpisodeClassifier, OneLinePerEpisodeAndNoLineWithoutOne)
{
    QcEpisodeClassifier ep;
    // Derivable observations with NO active episode (the steady-state
    // serving path, hit on every template re-source) must return nothing.
    EXPECT_FALSE(ep.observe_derivable(kFirstH, true, true, 10).has_value());
    EXPECT_FALSE(ep.pending().has_value());

    ep.observe_underivable(kFirstH, 1, 0, qh256(0x56), kLastH, 20);
    EXPECT_TRUE(ep.observe_derivable(kFirstH, true, false, 30).has_value());
    // The episode is spent: exactly one terminal line, never two.
    EXPECT_FALSE(ep.observe_derivable(kFirstH, true, false, 40).has_value());
    EXPECT_FALSE(ep.active());
}

TEST(DashQcEpisodeClassifier, ArrivalOutranksMinedInTheTieBreak)
{
    // Both facts true at resume (the flood delivered it AND the network
    // mined it before we won a block): classified real-arrived — the
    // arrival-lane evidence is the diagnostic split; only
    // window-closed-null feeds the null-arm decision, and it is unaffected.
    QcEpisodeClassifier ep;
    ep.observe_underivable(kFirstH, 1, 0, qh256(0x57), kLastH, 0);
    auto ended = ep.observe_derivable(kFirstH + 1, /*cache_has=*/true,
                                      /*mined=*/true, 90);
    ASSERT_TRUE(ended.has_value());
    EXPECT_EQ(ended->terminal, Terminal::RealArrived);
}
