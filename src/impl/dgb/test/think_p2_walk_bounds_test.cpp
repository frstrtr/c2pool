// dgb think() Phase-2 verification-extension walk BOUNDS conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p2_walk_bounds.hpp against the p2pool data.py think()
// Phase-2 oracle (data.py:2098-2103) for the three pure decisions per verified
// head:
//   want = max(CHAIN_LENGTH - head_height, 0)
//   can  = last_height                              if unrooted (no last_last)
//        = max(last_height - 1 - CHAIN_LENGTH, 0)   otherwise
//   get  = min(want, can)
//
// Expectations are HAND-DERIVED from the oracle formula, NOT read back from the
// code under test — a conformance KAT that asks its subject for the answer
// passes vacuously. Pure arithmetic: links only core (no chain standup). MUST
// appear in BOTH this dir's CMakeLists.txt AND the build.yml --target allowlist,
// or it becomes a #143 NOT_BUILT sentinel (compiled-out, silently "passing").

#include <impl/dgb/think_p2_walk_bounds.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

// ---- want = max(CHAIN_LENGTH - head_height, 0): floors at 0 above CL
TEST(ThinkP2WalkBounds, WantFloorsAtZeroAboveChainLength)
{
    constexpr int32_t CL = 10;
    // head below CL → positive remaining-to-verify count
    EXPECT_EQ(dgb::think_p2_walk_bounds(0,  0, false, CL).want, 10); // max(10,0)
    EXPECT_EQ(dgb::think_p2_walk_bounds(3,  0, false, CL).want, 7);  // max(7,0)
    EXPECT_EQ(dgb::think_p2_walk_bounds(9,  0, false, CL).want, 1);  // max(1,0)
    // head at/above CL → floored to 0
    EXPECT_EQ(dgb::think_p2_walk_bounds(10, 0, false, CL).want, 0);  // boundary
    EXPECT_EQ(dgb::think_p2_walk_bounds(15, 0, false, CL).want, 0);  // max(-5,0)
}

// ---- can, UNROOTED head (has_last == false) → full last_height
TEST(ThinkP2WalkBounds, CanUnrootedIsFullLastHeight)
{
    constexpr int32_t CL = 10;
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 0,   false, CL).can, 0);
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 1,   false, CL).can, 1);
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 50,  false, CL).can, 50);
    // chain_length must not influence the unrooted `can`.
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 7,   false, 9999).can, 7);
}

// ---- can, ROOTED head (has_last == true) → max(last_height - 1 - CL, 0)
TEST(ThinkP2WalkBounds, CanRootedAppliesOffsetAndFloor)
{
    constexpr int32_t CL = 10;
    // last_height - 1 - CL below 0 → floored to 0
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 10, true, CL).can, 0);  // max(-1,0)
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 11, true, CL).can, 0);  // max(0,0) boundary
    // above the offset → exact difference
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 12, true, CL).can, 1);  // max(1,0)
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 20, true, CL).can, 9);  // max(9,0)
    EXPECT_EQ(dgb::think_p2_walk_bounds(0, 100, true, CL).can, 89);
}

// ---- get = min(want, can): each side can dominate
TEST(ThinkP2WalkBounds, GetIsMinOfWantAndCan)
{
    constexpr int32_t CL = 10;
    // want dominates: head=2 → want=8; unrooted last_height=50 → can=50; get=8
    {
        auto b = dgb::think_p2_walk_bounds(2, 50, false, CL);
        EXPECT_EQ(b.want, 8);
        EXPECT_EQ(b.can, 50);
        EXPECT_EQ(b.get, 8);
    }
    // can dominates: head=0 → want=10; rooted last_height=14 → can=max(3,0)=3; get=3
    {
        auto b = dgb::think_p2_walk_bounds(0, 14, true, CL);
        EXPECT_EQ(b.want, 10);
        EXPECT_EQ(b.can, 3);
        EXPECT_EQ(b.get, 3);
    }
    // both zero → get=0 (head past CL, rooted tail under offset)
    {
        auto b = dgb::think_p2_walk_bounds(12, 11, true, CL);
        EXPECT_EQ(b.want, 0);
        EXPECT_EQ(b.can, 0);
        EXPECT_EQ(b.get, 0);
    }
    // equal want==can → get equals both
    {
        auto b = dgb::think_p2_walk_bounds(5, 5, false, CL); // want=5, can=5
        EXPECT_EQ(b.get, 5);
    }
}

} // namespace
