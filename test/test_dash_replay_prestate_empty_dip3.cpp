// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT: the SCOPED empty-prestate relaxation in replay_prestate.hpp.
//
// A TRUE from-DIP3 self-derive seeds the W1 fold from an EMPTY masternode set
// at the DIP3 activation height (h = MAINNET_DIP3_HEIGHT = 1028160): DASH's
// deterministic MN list is empty until the first ProRegTx at/after DIP3
// enforcement, so empty-at-DIP3 is CHAIN-TRUE and lets the whole set be
// derived from chain (dashd BuildNewListFromBlock parity) instead of captured
// from dashd RPC.
//
// The loader (parse_prestate_text) historically rejected EVERY empty entries
// set ("a half-parsed masternode set would seed a replay that diverges
// silently"). This suite pins the reward-safe relaxation:
//
//   * empty prestate AT the DIP3 activation height  -> ACCEPTED
//   * empty prestate at ANY other height            -> HARD REJECT
//   * an empty DIP3 seed reproduces the empty-list merkleRootMNList
//     (uint256::ZERO) through the SAME seed_engine_from_prestate root
//     self-check a live replay trusts.
//
// The relaxation is fail-closed: the empty seed is never minted on faith —
// the fold's per-block merkleRootMNList self-check (replay_fold_engine.hpp
// poison()) hard-stops at the first post-DIP3 ProRegTx block if the seed is
// wrong. This suite proves the LOADER gate; the fold self-check is covered by
// test_dash_replay_fold.cpp (RootMismatchIsAHardStopWithNamedHeight).
//
// Folded into the test_dash_mn_state executable (the allowlisted target that
// already builds the W1/W5 replay TUs) so it is actually built + run in CI —
// a standalone add_executable would be a #143 NOT_BUILT sentinel.

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_prestate.hpp>

#include <string>

namespace {

namespace rp = dash::coin::replay;

// The well-known empty-list merkleRootMNList: dashd returns the null hash for a
// CSimplifiedMNList with no entries (CalcMerkleRoot: `if (mnList.empty())
// return uint256();`), which is exactly what DmlFoldEngine::compute_sml_root()
// returns for an empty engine. 64 zero hex nibbles.
const std::string kEmptyListRoot =
    "0000000000000000000000000000000000000000000000000000000000000000";

// A distinctive 64-hex placeholder for the anchor block hash. parse_prestate_text
// validates only that blockhash is 64 hex chars; its CHAIN identity is the
// fold's job (each folded block carries its own hashPrevBlock + committed root),
// not the loader's — so this unit test of the loader uses a fixture value.
const std::string kAnchorHashPlaceholder =
    "00000000000000000abcdef0123456789abcdef0123456789abcdef012345678";

std::string make_empty_prestate(uint32_t height, const std::string& mnroot)
{
    std::string t;
    t += rp::kPrestateMagic;              t += "\n";
    t += "network mainnet\n";
    t += "height " + std::to_string(height) + "\n";
    t += "blockhash " + kAnchorHashPlaceholder + "\n";
    t += "mnroot " + mnroot + "\n";
    t += "count 0\n";
    return t;
}

} // namespace

// ── The relaxation: empty AT DIP3 activation is ACCEPTED ─────────────────────
TEST(DashReplayPrestateEmptyDip3, EmptyPrestateAtDip3ActivationAccepted)
{
    const auto ps = rp::parse_prestate_text(
        make_empty_prestate(rp::MAINNET_DIP3_HEIGHT, kEmptyListRoot));
    ASSERT_TRUE(ps.ok) << "empty prestate at the DIP3 activation height must be "
                          "accepted (chain-true empty set), got: " << ps.error;
    EXPECT_TRUE(ps.entries.empty());
    EXPECT_EQ(ps.height, rp::MAINNET_DIP3_HEIGHT);
}

// ── The scope: empty ABOVE DIP3 stays a HARD REJECT ──────────────────────────
TEST(DashReplayPrestateEmptyDip3, EmptyPrestateAboveDip3Rejected)
{
    const auto ps = rp::parse_prestate_text(
        make_empty_prestate(2513000, kEmptyListRoot));
    EXPECT_FALSE(ps.ok) << "an empty set above DIP3 must stay a hard reject";
    EXPECT_NE(ps.error.find("DIP3 activation height"), std::string::npos)
        << "the rejection must name why empty is only legal at DIP3: "
        << ps.error;
}

// ── The scope: empty BELOW DIP3 stays a HARD REJECT ──────────────────────────
TEST(DashReplayPrestateEmptyDip3, EmptyPrestateBelowDip3Rejected)
{
    const auto ps = rp::parse_prestate_text(
        make_empty_prestate(rp::MAINNET_DIP3_HEIGHT - 1, kEmptyListRoot));
    EXPECT_FALSE(ps.ok) << "an empty set below DIP3 must stay a hard reject";
}

// ── The scope: the relaxation is SPOT-EXACT, not a window ────────────────────
TEST(DashReplayPrestateEmptyDip3, EmptyPrestateOneAboveDip3Rejected)
{
    const auto ps = rp::parse_prestate_text(
        make_empty_prestate(rp::MAINNET_DIP3_HEIGHT + 1, kEmptyListRoot));
    EXPECT_FALSE(ps.ok)
        << "the relaxation is scoped to the EXACT DIP3 height, not h>=DIP3";
}

// ── Other guards remain intact under the relaxation ──────────────────────────
// A count/records mismatch must still fail even at the DIP3 height: the empty
// relaxation only reaches the `entries.empty()` gate AFTER the count-parity
// gate, so a header that declares count=1 with zero mn records is still caught.
TEST(DashReplayPrestateEmptyDip3, CountMismatchStillFailsAtDip3)
{
    std::string t;
    t += rp::kPrestateMagic;              t += "\n";
    t += "network mainnet\n";
    t += "height " + std::to_string(rp::MAINNET_DIP3_HEIGHT) + "\n";
    t += "blockhash " + kAnchorHashPlaceholder + "\n";
    t += "mnroot " + kEmptyListRoot + "\n";
    t += "count 1\n";   // declares 1, carries 0
    const auto ps = rp::parse_prestate_text(t);
    EXPECT_FALSE(ps.ok);
    EXPECT_NE(ps.error.find("count"), std::string::npos) << ps.error;
}

// ── End to end: the empty DIP3 seed reproduces the committed empty-list root ──
// This is the check a live replay actually trusts: seed the engine from the
// empty DIP3 prestate and RE-VERIFY that the seeded (empty) state computes the
// prestate's committed merkleRootMNList. compute_sml_root() over an empty
// engine is uint256::ZERO — the well-known empty-list root — so the anchor is
// self-consistent, and any wrong post-DIP3 fold poisons at its own height.
TEST(DashReplayPrestateEmptyDip3, EmptyDip3SeedReproducesEmptyListRoot)
{
    const auto ps = rp::parse_prestate_text(
        make_empty_prestate(rp::MAINNET_DIP3_HEIGHT, kEmptyListRoot));
    ASSERT_TRUE(ps.ok) << ps.error;

    rp::FoldConfig fcfg;
    fcfg.enabled = true;
    rp::DmlFoldEngine eng(fcfg);

    const std::string serr = rp::seed_engine_from_prestate(eng, ps);
    EXPECT_TRUE(serr.empty())
        << "seeding an empty engine at DIP3 must reproduce the empty-list "
           "merkleRootMNList (uint256::ZERO): " << serr;
    EXPECT_EQ(eng.size(), 0u);
    EXPECT_EQ(eng.compute_sml_root().GetHex(), kEmptyListRoot);
}
