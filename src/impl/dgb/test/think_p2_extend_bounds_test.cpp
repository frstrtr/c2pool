// dgb think() Phase-2 verification-extension BOUNDS conformance KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/think_p2_extend_bounds.hpp against the p2pool data.py think()
// Phase-2 oracle for the per-verified-head pull bound:
//   want = max(CHAIN_LENGTH - head_height, 0)
//   can  = max(last_height - 1 - CHAIN_LENGTH, 0)  if tail rooted (has parent)
//        = last_height                             if tail is itself the root
//   get  = min(want, can)
//
// Expectations are HAND-DERIVED from the oracle formula, NOT read back from the
// code under test — a conformance KAT that asks its subject for the answer
// passes vacuously. Pure arithmetic: links only core (no chain standup). MUST
// appear in BOTH this dir's CMakeLists.txt AND the build.yml --target allowlist,
// or it becomes a #143 NOT_BUILT sentinel (compiled-out, silently "passing").

#include <impl/dgb/think_p2_extend_bounds.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace {

// ---- want floored at 0: a head already at/over CHAIN_LENGTH pulls nothing,
//      whatever the tail could supply.
TEST(ThinkP2ExtendBounds, WantFlooredAtZeroAtAndAboveChainLength)
{
    constexpr int32_t CL = 10;
    // head_height == CL → want = max(0,0) = 0 → get = 0 even with a huge rooted tail.
    EXPECT_EQ(dgb::think_p2_extend_get(/*head*/10, /*last*/100, /*rooted*/true,  CL), 0);
    // head_height > CL → want = max(-5,0) = 0 → get = 0 with a full unrooted tail.
    EXPECT_EQ(dgb::think_p2_extend_get(/*head*/15, /*last*/5,   /*rooted*/false, CL), 0);
}

// ---- unrooted tail (last_has_parent == false): can = last_height in full.
TEST(ThinkP2ExtendBounds, UnrootedTailSuppliesFullHeight)
{
    constexpr int32_t CL = 10;
    // want=10, can=3  → 3
    EXPECT_EQ(dgb::think_p2_extend_get(0, 3,  false, CL), 3);
    // want=10, can=50 → 10  (want is the binding limit)
    EXPECT_EQ(dgb::think_p2_extend_get(0, 50, false, CL), 10);
    // want=5,  can=2  → 2
    EXPECT_EQ(dgb::think_p2_extend_get(5, 2,  false, CL), 2);
}

// ---- rooted tail (last_has_parent == true): can = max(last_height-1-CL, 0),
//      i.e. stop one share above CHAIN_LENGTH from the tail.
TEST(ThinkP2ExtendBounds, RootedTailStopsAboveChainLength)
{
    constexpr int32_t CL = 10;
    // last=100 → can = max(89,0) = 89; want=10 → 10
    EXPECT_EQ(dgb::think_p2_extend_get(0, 100, true, CL), 10);
    // last=12  → can = max(1,0)  = 1;  want=10 → 1
    EXPECT_EQ(dgb::think_p2_extend_get(0, 12,  true, CL), 1);
    // last=11  → can = max(0,0)  = 0  (boundary) → 0
    EXPECT_EQ(dgb::think_p2_extend_get(0, 11,  true, CL), 0);
    // last=10  → can = max(-1,0) = 0 → 0
    EXPECT_EQ(dgb::think_p2_extend_get(0, 10,  true, CL), 0);
}

// ---- get = min(want, can), both directions and the tie.
TEST(ThinkP2ExtendBounds, GetIsMinOfWantAndCan)
{
    constexpr int32_t CL = 10;
    // want=7 < can=9  → 7   (head=3 → want=7; last=20 rooted → can=9)
    EXPECT_EQ(dgb::think_p2_extend_get(3, 20, true, CL), 7);
    // want=7 > can=3  → 3   (head=3 → want=7; last=14 rooted → can=3)
    EXPECT_EQ(dgb::think_p2_extend_get(3, 14, true, CL), 3);
    // want=10 == can=10 → 10 (head=0 → want=10; last=21 rooted → can=10)
    EXPECT_EQ(dgb::think_p2_extend_get(0, 21, true, CL), 10);
}

} // namespace
