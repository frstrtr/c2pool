// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for the GBT-xcheck quorumroot-dashd-stale classifier
// (src/impl/dash/coin/gbt_quorum_staleness.hpp), wired into the #127 null-arm
// reward-safety backstop in stratum/work_source.cpp.
//
// GAP (measured, mainnet 2026-08): at each LLMQ DKG commitment boundary
// (24-block cadence: 2525987, 2526011, 2526035, ...) dashd's getblocktemplate
// momentarily serves the PREVIOUS cycle's merkleRootQuorums while our embedded
// arm has already advanced to the freshly-committed one. Chain truth: the mined
// block's CbTx carries the EMBEDDED root, so the pre-fix code -- which HARD-
// swaps to dashd on ANY quorum-root difference -- was serving a would-be-
// rejected bad-cbtx-quorummerkleroot template in that ~1s window (the reward-
// safety direction was INVERTED).
//
// RED  (pre-fix / always-swap): the classifier does not fire, embedded is never
//      kept, and StaleBoundaryKeepsEmbedded FAILS.
// GREEN (with the predicate): the DKG-boundary stale case is isolated and KEEPS
//      embedded, while every inverse / no-history / mixed-divergence case still
//      returns false so the ordinary swap runs.

#include <impl/dash/coin/gbt_quorum_staleness.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

namespace {

using dash::coin::quorumroot_dashd_is_stale;

// Chain-proven vectors (prefixes are the real mainnet roots from the 2525987 /
// 2526011 episodes; padded to 64 hex for unambiguous distinctness).
const uint256 kFresh = uint256S(  // embedded root the chain committed at h
    "8b5f6344000000000000000000000000000000000000000000000000000000ee");
const uint256 kStale = uint256S(  // dashd's momentarily-stale root == prior cycle
    "164eeaf7000000000000000000000000000000000000000000000000000000aa");
const uint256 kOlder = uint256S(  // two cycles back (a longer dashd lag)
    "275ded6e000000000000000000000000000000000000000000000000000000bb");

// The proven case: dashd regressed to the last-agreed (prior-cycle) root while
// embedded advanced past it, and the MN-list root axis agrees. KEEP embedded.
TEST(GbtQuorumStaleness, StaleBoundaryKeepsEmbedded)
{
    EXPECT_TRUE(quorumroot_dashd_is_stale(kFresh, kStale,
                                          /*mnlist_matches=*/true, &kStale));
}

// Inverse skew: embedded is the stale one, dashd is fresh. dref != last_agreed,
// so the predicate must return false and the caller SWAPS to dashd (reward-safe).
TEST(GbtQuorumStaleness, InverseSkewSwapsToDashd)
{
    EXPECT_FALSE(quorumroot_dashd_is_stale(kStale, kFresh,
                                           /*mnlist_matches=*/true, &kStale));
}

// No prior agreement (cold start): cannot assert embedded is right -> swap.
TEST(GbtQuorumStaleness, NoHistorySwaps)
{
    EXPECT_FALSE(quorumroot_dashd_is_stale(kFresh, kStale,
                                           /*mnlist_matches=*/true, nullptr));
}

// A null last-agreed sentinel is treated as "no history" -> swap.
TEST(GbtQuorumStaleness, NullSentinelSwaps)
{
    const uint256 null_root;  // default-constructed == all-zero
    EXPECT_FALSE(quorumroot_dashd_is_stale(kFresh, kStale,
                                           /*mnlist_matches=*/true, &null_root));
}

// Simultaneous MN-list divergence means this is body-divergence, not a pure DKG
// boundary; take the ordinary swap even though dref == last_agreed.
TEST(GbtQuorumStaleness, MixedMnlistDivergenceSwaps)
{
    EXPECT_FALSE(quorumroot_dashd_is_stale(kFresh, kStale,
                                           /*mnlist_matches=*/false, &kStale));
}

// Equal quorum roots: nothing to classify (the branch would not even be
// entered) -> false.
TEST(GbtQuorumStaleness, EqualRootsIsNotStale)
{
    EXPECT_FALSE(quorumroot_dashd_is_stale(kFresh, kFresh,
                                           /*mnlist_matches=*/true, &kStale));
}

// A two-cycle dashd lag (dref equals a root OLDER than last_agreed) is outside
// the chain-proven single-boundary case -> swap, do not assert embedded.
TEST(GbtQuorumStaleness, TwoCycleLagSwaps)
{
    EXPECT_FALSE(quorumroot_dashd_is_stale(kFresh, kOlder,
                                           /*mnlist_matches=*/true, &kStale));
}

// The reference IS the last-agreed and embedded advanced: symmetry check that a
// DIFFERENT fresh embedded value still keeps embedded as long as dref regressed.
TEST(GbtQuorumStaleness, AnyAdvancedEmbeddedOverRegressedDashdKeeps)
{
    EXPECT_TRUE(quorumroot_dashd_is_stale(kOlder /*advanced, != last_agreed*/,
                                          kStale, /*mnlist_matches=*/true,
                                          &kStale));
}

} // namespace
