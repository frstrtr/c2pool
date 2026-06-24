// dgb NAUGHTY-PROPAGATION ancestor-punishment KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/coin/naughty_propagation.hpp against the p2pool-dgb-scrypt
// data.py:543-549 propagation rule:
//     if prev_share_hash and tracker.items[prev_share_hash].naughty:
//         self.naughty = 1 + tracker.items[prev_share_hash].naughty
//         if self.naughty > 6: self.naughty = 0
//
// Every expectation is hand-derived from the oracle Python (the +1-per-generation
// step and the 6-generation reset clamp), NOT read from the code under test, so
// the KAT is non-circular. The inline body at share_tracker.hpp:561-577 is NOT
// yet rewired (delegation is the byte-identity follow-on). Pure unsigned
// arithmetic -> links only GTest.
// MUST appear in BOTH this dir CMakeLists.txt AND the build.yml --target
// allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/naughty_propagation.hpp>

#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

using dgb::naughty_child_generation;
using dgb::propagate_naughty_from_parent;

// --- bare child generation = 1 + parent, clamp >6 -> 0 (data.py:547-549) ----
// Hand-derived table over every reachable parent generation. Parent naughty in
// the live chain is always in [1,6] (it was itself produced by this same rule),
// but we pin 7 too as a defensive over-the-clamp input.
TEST(DgbNaughtyPropagation, ChildGenerationTable)
{
    // parent gen 1 (the bad-reward share itself) -> child gen 2
    EXPECT_EQ(naughty_child_generation(1u), 2u);
    EXPECT_EQ(naughty_child_generation(2u), 3u);
    EXPECT_EQ(naughty_child_generation(3u), 4u);
    EXPECT_EQ(naughty_child_generation(4u), 5u);
    // gen 5 -> 6 is the LAST kept generation (6 is not > 6)
    EXPECT_EQ(naughty_child_generation(5u), 6u);
    // gen 6 -> would-be 7, clamps to 0: the 6th-generation descendant is forgiven
    EXPECT_EQ(naughty_child_generation(6u), 0u);
    // defensive: an out-of-range parent (7) also wraps to 0 (8 > 6)
    EXPECT_EQ(naughty_child_generation(7u), 0u);
}

// --- the guarded propagation: nullopt when parent not naughty (data.py:543) --
TEST(DgbNaughtyPropagation, NonNaughtyParentLeavesChildUntouched)
{
    // parent.naughty == 0 is falsy in Python -> no assignment happens.
    EXPECT_FALSE(propagate_naughty_from_parent(0u).has_value());
}

// --- guarded propagation matches the bare table for naughty parents ---------
TEST(DgbNaughtyPropagation, NaughtyParentPropagates)
{
    EXPECT_EQ(propagate_naughty_from_parent(1u), std::optional<std::uint32_t>(2u));
    EXPECT_EQ(propagate_naughty_from_parent(2u), std::optional<std::uint32_t>(3u));
    EXPECT_EQ(propagate_naughty_from_parent(3u), std::optional<std::uint32_t>(4u));
    EXPECT_EQ(propagate_naughty_from_parent(4u), std::optional<std::uint32_t>(5u));
    EXPECT_EQ(propagate_naughty_from_parent(5u), std::optional<std::uint32_t>(6u));
    // 6th-generation descendant forgiven (assigned 0, NOT left untouched)
    EXPECT_EQ(propagate_naughty_from_parent(6u), std::optional<std::uint32_t>(0u));
}

// --- non-circular: a full 8-generation chain walk reproduces the oracle ------
// Seed share is itself naughty (gen 1, excessive reward). Walk forward applying
// the rule and compare against the hand-derived sequence the oracle produces:
//   1 (seed, bad reward), then each child = clamp(1+parent):
//   1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 0(forgiven) -> 0(parent 0 = clean, untouched)
TEST(DgbNaughtyPropagation, EightGenerationChainMatchesOracleSequence)
{
    const std::uint32_t expected[8] = {1u, 2u, 3u, 4u, 5u, 6u, 0u, 0u};

    std::uint32_t gen = 1u;  // seed: excessive-reward share, naughty=1
    EXPECT_EQ(gen, expected[0]);
    for (int i = 1; i < 8; ++i) {
        auto next = propagate_naughty_from_parent(gen);
        if (next.has_value()) {
            gen = *next;             // parent was naughty -> inherit/clamp
        } else {
            gen = 0u;                // parent clean -> child stays at its default 0
        }
        EXPECT_EQ(gen, expected[i]) << "generation " << i;
    }
}
