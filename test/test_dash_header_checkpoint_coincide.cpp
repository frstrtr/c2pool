// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH daemonless COLD-CUT first-embedded-template latency KAT.
///
/// THE INCIDENT (2026-08-16, hotel-reserve). The first --coin-rpc-removed
/// binary header-synced for >14 min without ever acquiring a tip: the status
/// line held "[DASH] Waiting for block template (header sync in progress)",
/// the embedded arm reported have_tip=0 / populated=0 / arm=would-decline, and
/// every stratum rig timed out (25 -> 0) before the first serve.
///
/// ROOT CAUSE. It was NOT "state thrown away under dashd". The header
/// fast-start checkpoint and the MN-set bridge anchor
/// (dash_mn_checkpoint_mainnet.inc) were pinned at DIFFERENT heights and left
/// to drift 113k blocks apart (2400000 vs 2513000). The MN-set fold
/// (mn_checkpoint_lane) cannot begin until the header tip REACHES its anchor
/// height -- until then it reports
///     waiting_for() == "header-tip-to-reach-anchor@h=2513000"
/// so a fresh (cold) data-dir spent ~113000 / ~60 hdr/s ~= 31 min crawling
/// headers forward BEFORE the first fold could even start. have_tip=0 and
/// populated=0 are downstream of that single gate.
///
/// THE FIX (this PR). Coincide the header fast-start checkpoint with the MN
/// anchor, reusing the SAME release-pinned trust anchor the MN checkpoint
/// already commits to and cross-checks against (no new consensus data). Then
/// hdr_tip >= anchor at t~=0, the fold precondition is satisfied immediately,
/// and only the residual anchor->tip folds.
///
/// This suite is RED on master (checkpoints 113k apart -> lane parked ->
/// est. crawl >> work-timeout) and GREEN with the fix (coincident -> the fold
/// is eligible at t~=0 -> < work-timeout). Both facts are read from the REAL
/// product constant (make_dash_chain_params_mainnet) and the REAL pinned MN
/// anchor, not from synthetic fixtures.
///
/// #143 note: FOLDED into the allowlisted test_dash_node_reception_wire target
/// (a standalone add_executable would silently report "Not Run"). #895 note:
/// no #ifdef guards, so a green tick means these bodies ran.

#include <gtest/gtest.h>

#include <impl/dash/coin/header_chain.hpp>        // HeaderChain, make_dash_chain_params_mainnet
#include <impl/dash/coin/mn_checkpoint.hpp>       // MnCheckpoint, parse_mn_checkpoint, MNState
#include <impl/dash/coin/mn_checkpoint_lane.hpp>  // MnCheckpointLane

#include <core/uint256.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

using dash::coin::HeaderChain;
using dash::coin::MnCheckpoint;
using dash::coin::MnCheckpointLane;
using dash::coin::MNState;
using dash::coin::make_dash_chain_params_mainnet;
using dash::coin::parse_mn_checkpoint;

namespace {

// The release-pinned mainnet MN-set checkpoint, compiled in exactly as
// main_dash.cpp compiles it. Its `height`/`blockhash` are the authoritative
// bridge anchor; the header fast-start checkpoint must equal them.
const char* const kMainnetMnCheckpoint =
#include <impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc>
    ;

// The stratum work-timeout the cold cut must beat. Rigs dropped their work
// (25 -> 0) once the first embedded template did not arrive within this window.
constexpr double kWorkTimeoutS = 120.0;

// MEASURED forward-sync rate on the 2026-08-16 cut repro: 18000 headers
// ACCEPTED in 264 s == ~68 hdr/s (received/accepted ran ~4.4x redundant). 60
// is the conservative floor used here, so the estimated crawl time is if
// anything an UNDER-count of the incident's ~31 min.
constexpr double kMeasuredFwdHdrPerSec = 60.0;

MnCheckpoint mainnet_anchor()
{
    auto cp = parse_mn_checkpoint(kMainnetMnCheckpoint, "mainnet");
    EXPECT_TRUE(cp.ok) << cp.error;
    return cp;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 1. ANTI-DRIFT INVARIANT. The header fast-start checkpoint MUST equal the
//    MN-set bridge anchor, height AND hash. This is the guard that keeps the
//    2026-08-16 incident from recurring: regenerate the .inc to a newer anchor
//    and forget to bump the header checkpoint, and this test goes RED in CI
//    before the drift can ship. RED on master (2400000 != 2513000).
// ─────────────────────────────────────────────────────────────────────────
TEST(DashHeaderCheckpointCoincide, HeaderFastStartEqualsMnAnchor)
{
    auto params = make_dash_chain_params_mainnet();
    ASSERT_TRUE(params.fast_start_checkpoint.has_value())
        << "no header fast-start checkpoint pinned at all";
    auto cp = mainnet_anchor();

    EXPECT_EQ(params.fast_start_checkpoint->height, cp.height)
        << "header fast-start checkpoint (h=" << params.fast_start_checkpoint->height
        << ") is not pinned at the MN-set bridge anchor (h=" << cp.height
        << "); a cold start would gate the MN fold behind a forward header crawl of "
        << (cp.height > params.fast_start_checkpoint->height
                ? cp.height - params.fast_start_checkpoint->height : 0)
        << " headers";
    EXPECT_EQ(params.fast_start_checkpoint->hash, cp.blockhash)
        << "header fast-start checkpoint hash does not match the MN anchor hash "
           "at the same height — the anchor is for a different block";
}

// ─────────────────────────────────────────────────────────────────────────
// 2. BEHAVIORAL. On a COLD data-dir the MN-set fold precondition must be
//    satisfied at t~=0, not behind a multi-minute forward header crawl. This
//    drives the REAL HeaderChain (seeded from the product constant) into the
//    REAL MnCheckpointLane armed at the REAL pinned anchor.
//
//    RED on master: the header tip seeds at 2400000 < anchor 2513000, so the
//    lane parks on "header-tip-to-reach-anchor@h=2513000", position is NOT
//    verified, and the estimated cold crawl (113000 / 60 ~= 1883 s) dwarfs the
//    work-timeout. GREEN with the fix: tip seeds AT 2513000, the fold is
//    eligible immediately, residual crawl 0 s.
// ─────────────────────────────────────────────────────────────────────────
TEST(DashHeaderCheckpointCoincide, ColdCutFoldEligibleBeforeWorkTimeout)
{
    HeaderChain hc(make_dash_chain_params_mainnet()); // db_path="" -> in-memory
    ASSERT_TRUE(hc.init());                           // seeds the fast-start checkpoint

    auto cp = mainnet_anchor();

    MnCheckpointLane lane;
    int64_t clock = 0;
    lane.set_clock_fn([&clock] { return clock; });
    lane.set_tip_height_fn([&hc] { return hc.height(); });
    lane.set_header_hash_at_fn(
        [&hc](uint32_t h) -> std::optional<uint256> {
            auto e = hc.get_header_by_height(h);
            if (!e) return std::nullopt;
            return e->hash;
        });
    lane.set_publish_fn(
        [](std::vector<std::pair<uint256, MNState>>, uint32_t) {});
    lane.set_request_block_fn([](uint32_t) { return true; });
    lane.set_request_snapshot_fn([](const uint256&) {});
    lane.set_merkle_root_at_fn(
        [](const uint256&) -> std::optional<uint256> { return std::nullopt; });

    lane.arm(cp);
    lane.pump();

    const uint32_t tip   = hc.height();
    const uint32_t crawl = tip >= cp.height ? 0u : cp.height - tip;
    const double   crawl_s = crawl / kMeasuredFwdHdrPerSec;

    EXPECT_TRUE(lane.position_verified())
        << "MN fold gated on the header chain: tip h=" << tip
        << " has not reached anchor h=" << cp.height
        << " (waiting_for=" << lane.waiting_for()
        << "); estimated cold forward-crawl " << crawl_s << " s at "
        << kMeasuredFwdHdrPerSec << " hdr/s";

    EXPECT_EQ(lane.waiting_for().find("header-tip-to-reach-anchor"),
              std::string::npos)
        << "the lane is still parked waiting for the header tip to climb to the "
           "anchor: " << lane.waiting_for();

    EXPECT_LT(crawl_s, kWorkTimeoutS)
        << "cold-cut header backfill to the MN anchor (" << crawl
        << " headers, ~" << crawl_s << " s at " << kMeasuredFwdHdrPerSec
        << " hdr/s) exceeds the stratum work-timeout (" << kWorkTimeoutS
        << " s): every rig times out before the first embedded template";
}
