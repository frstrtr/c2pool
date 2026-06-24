// dgb lookbehind chain-walk WINDOW clamp -- KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/coin/chain_walk_window.hpp against the p2pool-dgb-scrypt oracle
// idiom that governs every backward sharechain accessor:
//     actual = min(lookbehind, height);  if (actual <= 0) -> empty result
// open-coded today in share_tracker.hpp get_average_stale_prop /
// get_stale_counts / get_desired_version_counts / get_desired_version_weights,
// mirroring p2pool util/forest.py Tracker.get_chain (walk at most n parents,
// stop at chain end) under the main.py call-site min(lookbehind, height) clamp.
//
// Every expectation is hand-derived from the oracle min()/<=0 formula, NOT read
// from the code under test. The final case is non-circular: it re-implements the
// verbatim inline clamp+guard the four share_tracker accessors use today and
// asserts the SSOT is value-identical across a dense matrix -- so the
// byte-identity delegation follow-on is proven safe before it is written.
// share_tracker.hpp is NOT rewired here. MUST appear in BOTH this dir
// CMakeLists.txt AND the build.yml --target allowlist (#143 NOT_BUILT trap).

#include <impl/dgb/coin/chain_walk_window.hpp>

#include <algorithm>
#include <gtest/gtest.h>

using namespace dgb;

// --- realized window = min(lookbehind, height) ------------------------------
TEST(DgbChainWalkWindow, ClampsToHeight) {
    // lookbehind below height -> identity (the ask is satisfiable).
    EXPECT_EQ(chain_walk_window_count(/*height=*/2880, /*lookbehind=*/720), 720);
    EXPECT_EQ(chain_walk_window_count(100, 50), 50);
    // lookbehind above height -> clamped to what the chain can yield.
    EXPECT_EQ(chain_walk_window_count(/*height=*/30, /*lookbehind=*/720), 30);
    EXPECT_EQ(chain_walk_window_count(0, 720), 0);
    // exact boundary: equal -> that value.
    EXPECT_EQ(chain_walk_window_count(720, 720), 720);
    // one-deep chain.
    EXPECT_EQ(chain_walk_window_count(1, 720), 1);
}

// --- degenerate / defensive inputs ------------------------------------------
TEST(DgbChainWalkWindow, NonPositiveInputs) {
    // genesis head (height 0) -> zero window regardless of lookbehind.
    EXPECT_EQ(chain_walk_window_count(0, 1), 0);
    // zero lookbehind -> zero window (caller asked for nothing).
    EXPECT_EQ(chain_walk_window_count(2880, 0), 0);
    // negative height (should never occur, but min() must still pick it).
    EXPECT_EQ(chain_walk_window_count(-5, 720), -5);
}

// --- activation guard: actual > 0 -------------------------------------------
TEST(DgbChainWalkWindow, ActivationGuard) {
    // share_tracker accessors early-return the empty result when actual <= 0.
    EXPECT_FALSE(chain_walk_window_active(0));
    EXPECT_FALSE(chain_walk_window_active(-3));
    EXPECT_TRUE(chain_walk_window_active(1));
    EXPECT_TRUE(chain_walk_window_active(2880));
}

// --- composite: the realized window is walked iff it is positive -------------
TEST(DgbChainWalkWindow, ClampThenActivateComposite) {
    // genesis: clamp to 0, guard fails -> no walk.
    EXPECT_FALSE(chain_walk_window_active(chain_walk_window_count(0, 720)));
    // one-deep: clamp to 1, guard passes -> walk one ancestor.
    EXPECT_TRUE(chain_walk_window_active(chain_walk_window_count(1, 720)));
    // deep chain, real lookbehind: clamp to 720, walk 720.
    EXPECT_TRUE(chain_walk_window_active(chain_walk_window_count(5000, 720)));
}

// --- NON-CIRCULAR: SSOT == verbatim inline clamp+guard over a dense matrix ---
// Re-implements the exact three-line pattern from the four share_tracker.hpp
// accessors WITHOUT calling the header, then proves the SSOT matches. This is
// the safety proof for the byte-identity delegation follow-on.
TEST(DgbChainWalkWindow, DelegationMatchesPreDelegationInline) {
    for (int32_t height = -2; height <= 64; ++height) {
        for (int32_t lookbehind = 0; lookbehind <= 64; ++lookbehind) {
            // verbatim pre-delegation inline (see share_tracker.hpp:2149-2153):
            int32_t inline_actual = std::min(lookbehind, height);
            bool inline_runs = !(inline_actual <= 0);

            EXPECT_EQ(chain_walk_window_count(height, lookbehind), inline_actual)
                << "height=" << height << " lookbehind=" << lookbehind;
            EXPECT_EQ(chain_walk_window_active(inline_actual), inline_runs)
                << "actual=" << inline_actual;
        }
    }
}
