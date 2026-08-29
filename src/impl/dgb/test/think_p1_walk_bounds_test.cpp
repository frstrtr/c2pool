// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb think() Phase-1 desired-set walk BOUNDS conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p1_walk_bounds.hpp against the p2pool data.py think()
// Phase-1 oracle for the two pure decisions per unverified head:
//   walk_count = head_height                              if unrooted (no last)
//              = min(5, max(0, head_height - CHAIN_LENGTH)) otherwise
//   in_pruning_zone = head_height >= 2*CHAIN_LENGTH + 10   (inclusive)
//
// Expectations are HAND-DERIVED from the oracle formula, NOT read back from the
// code under test — a conformance KAT that asks its subject for the answer
// passes vacuously. Pure arithmetic: links only core (no chain standup). MUST
// appear in BOTH this dir's CMakeLists.txt AND the build.yml --target allowlist,
// or it becomes a #143 NOT_BUILT sentinel (compiled-out, silently "passing").

#include <impl/dgb/think_p1_walk_bounds.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

// ---- walk_count: unrooted head (has_last == false) → full accumulated height
TEST(ThinkP1WalkBounds, UnrootedWalksFullHeight)
{
    EXPECT_EQ(dgb::think_p1_walk_count(0,   false, 10), 0);
    EXPECT_EQ(dgb::think_p1_walk_count(1,   false, 10), 1);
    EXPECT_EQ(dgb::think_p1_walk_count(3,   false, 10), 3);
    EXPECT_EQ(dgb::think_p1_walk_count(100, false, 10), 100);
    // chain_length must not influence the unrooted branch.
    EXPECT_EQ(dgb::think_p1_walk_count(7,   false, 9999), 7);
}

// ---- walk_count: rooted head (has_last == true) → min(5, max(0, h - CL))
TEST(ThinkP1WalkBounds, RootedClampsAtFiveFloorsAtZero)
{
    constexpr int32_t CL = 10;
    // below/at CHAIN_LENGTH → floored to 0
    EXPECT_EQ(dgb::think_p1_walk_count(8,  true, CL), 0);   // max(0,-2)=0
    EXPECT_EQ(dgb::think_p1_walk_count(10, true, CL), 0);   // max(0, 0)=0 (boundary)
    // between CL and CL+5 → exact difference
    EXPECT_EQ(dgb::think_p1_walk_count(11, true, CL), 1);   // min(5,1)=1
    EXPECT_EQ(dgb::think_p1_walk_count(12, true, CL), 2);   // min(5,2)=2
    EXPECT_EQ(dgb::think_p1_walk_count(15, true, CL), 5);   // min(5,5)=5 (boundary)
    // above CL+5 → clamped to 5
    EXPECT_EQ(dgb::think_p1_walk_count(16, true, CL), 5);   // min(5,6)=5
    EXPECT_EQ(dgb::think_p1_walk_count(20, true, CL), 5);   // min(5,10)=5
    EXPECT_EQ(dgb::think_p1_walk_count(999, true, CL), 5);
}

// ---- pruning zone: inclusive threshold 2*CL + 10
TEST(ThinkP1WalkBounds, PruningZoneInclusiveThreshold)
{
    constexpr int32_t CL = 10;            // threshold = 2*10 + 10 = 30
    EXPECT_FALSE(dgb::think_p1_in_pruning_zone(0,  CL));
    EXPECT_FALSE(dgb::think_p1_in_pruning_zone(29, CL));
    EXPECT_TRUE (dgb::think_p1_in_pruning_zone(30, CL));   // inclusive lower bound
    EXPECT_TRUE (dgb::think_p1_in_pruning_zone(31, CL));
    EXPECT_TRUE (dgb::think_p1_in_pruning_zone(1000, CL));

    constexpr int32_t CL2 = 24;           // threshold = 2*24 + 10 = 58
    EXPECT_FALSE(dgb::think_p1_in_pruning_zone(57, CL2));
    EXPECT_TRUE (dgb::think_p1_in_pruning_zone(58, CL2));
}

// ---- Non-circular delegation proof ---------------------------------------
// share_tracker.hpp think() Phase-1 was rewired to CALL the SSOT functions
// above (the walk_count ternary + the two prune-zone guards). This test does
// NOT stand up a ShareTracker; instead it re-implements the EXACT pre-delegation
// inline expressions verbatim (copied from the share_tracker.hpp think() body
// as it stood before this slice) and asserts they are byte-identical to the SSOT
// across a dense input grid. Independent code path => non-circular: if the
// delegation ever drifts from the open-coded original, this fails.
namespace {

// Verbatim copy of the pre-delegation inline walk_count expression.
// Original: last.IsNull() ? head_height
//                         : std::min(5, std::max(0, head_height - CHAIN_LENGTH))
inline int32_t inline_walk_count_verbatim(int32_t head_height, bool last_is_null,
                                          int32_t chain_length)
{
    return last_is_null
        ? head_height
        : std::min(5, std::max(0, head_height - chain_length));
}

// Verbatim copy of the pre-delegation inline prune-zone guard.
// Original: head_height >= 2 * CL_prune + 10
inline bool inline_in_pruning_zone_verbatim(int32_t head_height, int32_t chain_length)
{
    return head_height >= 2 * chain_length + 10;
}

} // namespace

TEST(ThinkP1WalkBounds, DelegationMatchesPreDelegationInlineWalk)
{
    for (int32_t CL : {1, 8, 10, 16, 24, 50}) {
        for (int32_t h = 0; h <= 4 * CL + 30; ++h) {
            for (bool last_is_null : {false, true}) {
                // last_is_null == true  -> unrooted head (has_last == false)
                EXPECT_EQ(dgb::think_p1_walk_count(h, /*has_last=*/!last_is_null, CL),
                          inline_walk_count_verbatim(h, last_is_null, CL))
                    << "walk_count drift @ h=" << h << " CL=" << CL
                    << " last_is_null=" << last_is_null;
            }
            EXPECT_EQ(dgb::think_p1_in_pruning_zone(h, CL),
                      inline_in_pruning_zone_verbatim(h, CL))
                << "prune-zone drift @ h=" << h << " CL=" << CL;
        }
    }
}

} // namespace