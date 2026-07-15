// SPDX-License-Identifier: AGPL-3.0-or-later
// LTC lookbehind chain-walk WINDOW clamp + activation guard -- KAT, exercised
// through LTC's REAL ShareTracker API.
//
// FENCED, additive (no production code touched this slice). Pins the pure
// integer window idiom that governs every backward sharechain accessor:
//     actual = min(lookbehind, height);  if (actual <= 0) -> empty result
//
// Unlike dgb -- which lifts the clamp into a header (chain_walk_window.hpp) and
// KATs the free functions -- LTC is the V36 reference impl and does NOT
// modularize this guard: the identical three-line pattern is open-coded inline
// in FOUR share_tracker.hpp accessors:
//     auto height = chain.get_height(share_hash);            // depth of the head
//     auto actual = std::min(lookbehind, height);            // clamp
//     if (actual <= 0) return <empty>;                       // guard
//     auto view = chain.get_chain(share_hash, actual);       // walk
//   get_average_stale_prop      (share_tracker.hpp:2091)
//   get_stale_counts            (share_tracker.hpp:2114)
//   get_desired_version_counts  (share_tracker.hpp:2156)
//   get_desired_version_weights (share_tracker.hpp:2185)
//
// APPROACH (mirrors the LTC desired_version_tally precedent, commit 0c8a83a3):
// LTC has no header to lift, and this KAT must NOT touch production code, so it
// drives the clamp+guard through the real chain-walk API rather than a lifted
// oracle. It builds a resolved ltc::ShareTracker of ltc::MergedMiningShare (V36)
// of a KNOWN depth H, then observes the REALIZED window -- the number of shares
// get_desired_version_counts actually walks -- across a dense (H, lookbehind)
// matrix. All shares carry one desired_version, so the single tally bucket's
// count IS the realized walk length. The realized window is asserted equal to an
// INDEPENDENT inline oracle min(lookbehind, H) computed from the construction
// depth H and the loop variable -- NOT read from the code under test -- and the
// empty/non-empty result is asserted to track the (actual > 0) guard.
//
// Why H == the share count: get_height returns get_delta_to_last().height, which
// accumulates 1 per contained ancestor from the head to the null-parent chain
// end, so a chain of H shares (share 0 has a null parent) reports height H. The
// high-lookbehind matrix cells (lookbehind >> H) self-validate this: they observe
// exactly H walked, proving height == H and available == H before the sub-H cells
// exercise the clamp. This is the non-circular basis for the min() oracle.
//
// The clamp feeds two consensus-bearing consumers via get_desired_version_weights
// -- the check()-phase 60% work-weighted v36 switch gate (share_check step 2) and
// the #288 AutoRatchet VOTING tail guard -- so a drifted window would re-scope the
// accept gate. share_tracker.hpp is NOT rewired here. This target joins the
// existing `share_test` executable (already on the build.yml --target allowlist),
// so it cannot become a #143 NOT_BUILT sentinel.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

// A short hex tail -> uint256 (zero-padded to 64 nibbles), matching the LTC
// desired_version_tally / dgb share_test hx() convention.
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// Build a resolved ltc::ShareTracker with `count` uniform V36 shares (share i's
// parent is i-1; share 0 has a null parent = resolved chain genesis) and return
// the tip hash. Every share carries the same desired_version so the single tally
// bucket's count equals the realized walk length. Distinct `salt` gives disjoint
// hash spaces across the matrix so no two trackers collide (each tracker is
// independent, but keeping hashes disjoint is defensive).
uint256 build_uniform_chain(ltc::ShareTracker& tracker, int32_t count,
                            uint64_t dv, uint32_t bits, size_t salt) {
    uint256 prev;
    prev.SetNull();
    uint256 tip;
    tip.SetNull();
    for (int32_t i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%zx",
                      static_cast<size_t>((salt << 16) + 0x1c70 + i));
        uint256 h = hx(buf);
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        if (i == 0) sh->m_prev_hash.SetNull(); else sh->m_prev_hash = prev;
        sh->m_desired_version = dv;
        sh->m_bits = bits;
        sh->m_max_bits = bits;
        ltc::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

// Realized window = number of shares the backward walk actually tallied. All
// shares share one desired_version, so the map has at most one bucket whose
// count IS the walk length; sum defensively.
int32_t realized_window(ltc::ShareTracker& tracker, const uint256& tip,
                        int32_t lookbehind) {
    int32_t total = 0;
    for (const auto& [dv, n] : tracker.get_desired_version_counts(tip, lookbehind))
        total += n;
    return total;
}

// The walk runs (non-empty result) iff the realized window is positive.
bool walk_ran(ltc::ShareTracker& tracker, const uint256& tip,
              int32_t lookbehind) {
    return !tracker.get_desired_version_counts(tip, lookbehind).empty();
}

constexpr uint64_t kDv = 36;
constexpr uint32_t kBits = 0x1e0fffff;

}  // namespace

// --- realized window = min(lookbehind, height) ------------------------------
TEST(LtcChainWalkWindow, ClampsToHeight) {
    // A head 6 shares deep.
    ltc::ShareTracker t6;
    const uint256 tip6 = build_uniform_chain(t6, 6, kDv, kBits, 1);
    // lookbehind below height -> identity (the ask is satisfiable).
    EXPECT_EQ(realized_window(t6, tip6, 3), 3);
    // lookbehind above height -> clamped to what the chain can yield.
    EXPECT_EQ(realized_window(t6, tip6, 720), 6);
    // exact boundary: equal -> that value.
    EXPECT_EQ(realized_window(t6, tip6, 6), 6);

    // One-deep chain: at most one ancestor to walk.
    ltc::ShareTracker t1;
    const uint256 tip1 = build_uniform_chain(t1, 1, kDv, kBits, 2);
    EXPECT_EQ(realized_window(t1, tip1, 720), 1);
    EXPECT_EQ(realized_window(t1, tip1, 1), 1);
}

// --- degenerate / defensive inputs ------------------------------------------
TEST(LtcChainWalkWindow, NonPositiveInputs) {
    // Genesis head (no such share present) -> zero window: chain.contains()==false
    // is the height-0 analog (a present head is always >=1 deep), empty map.
    ltc::ShareTracker t;
    EXPECT_EQ(realized_window(t, hx("deadbeef"), 720), 0);
    EXPECT_FALSE(walk_ran(t, hx("deadbeef"), 720));

    ltc::ShareTracker t3;
    const uint256 tip3 = build_uniform_chain(t3, 3, kDv, kBits, 3);
    // zero lookbehind -> min(0,height)=0 -> actual<=0 -> zero window.
    EXPECT_EQ(realized_window(t3, tip3, 0), 0);
    EXPECT_FALSE(walk_ran(t3, tip3, 0));
    // negative lookbehind -> min(-5,height)=-5 -> actual<=0 -> zero window.
    EXPECT_EQ(realized_window(t3, tip3, -5), 0);
    EXPECT_FALSE(walk_ran(t3, tip3, -5));
}

// --- activation guard: actual > 0 -------------------------------------------
TEST(LtcChainWalkWindow, ActivationGuard) {
    ltc::ShareTracker t;
    const uint256 tip = build_uniform_chain(t, 4, kDv, kBits, 4);
    // The accessors early-return the empty result when actual <= 0.
    EXPECT_FALSE(walk_ran(t, tip, 0));
    EXPECT_FALSE(walk_ran(t, tip, -3));
    // Absent tip is also empty (contains() guard, the height-0 analog).
    EXPECT_FALSE(walk_ran(t, hx("cafe"), 720));
    // A positive realized window runs.
    EXPECT_TRUE(walk_ran(t, tip, 1));
    EXPECT_TRUE(walk_ran(t, tip, 720));
}

// --- composite: the realized window is walked iff it is positive -------------
TEST(LtcChainWalkWindow, ClampThenActivateComposite) {
    // Present head, lookbehind 0: clamp to 0, guard fails -> no walk.
    ltc::ShareTracker t8;
    const uint256 tip8 = build_uniform_chain(t8, 8, kDv, kBits, 5);
    EXPECT_FALSE(walk_ran(t8, tip8, 0));

    // One-deep: clamp to 1, guard passes -> walk one ancestor.
    ltc::ShareTracker t1;
    const uint256 tip1 = build_uniform_chain(t1, 1, kDv, kBits, 6);
    EXPECT_TRUE(walk_ran(t1, tip1, 720));
    EXPECT_EQ(realized_window(t1, tip1, 720), 1);

    // Deep chain, real lookbehind: clamp to 8, walk 8.
    EXPECT_TRUE(walk_ran(t8, tip8, 720));
    EXPECT_EQ(realized_window(t8, tip8, 720), 8);
}

// --- NON-CIRCULAR: realized window == inline min()+guard over a dense matrix --
// Re-implements the exact clamp+guard pattern from the four share_tracker.hpp
// accessors WITHOUT reading their `actual`, then proves the OBSERVABLE realized
// window matches it across a dense (height, lookbehind) grid. The high-lookbehind
// cells (lookbehind >> height) self-validate height == the construction depth,
// giving the min() oracle a non-circular basis.
TEST(LtcChainWalkWindow, RealizedWindowMatchesInlineClampMatrix) {
    for (int32_t height = 1; height <= 8; ++height) {
        ltc::ShareTracker t;
        const uint256 tip =
            build_uniform_chain(t, height, kDv, kBits, 100 + height);
        for (int32_t lookbehind = -2; lookbehind <= 12; ++lookbehind) {
            // verbatim pre-lift inline (see share_tracker.hpp:2155-2160):
            const int32_t inline_actual = std::min(lookbehind, height);
            const bool inline_runs = !(inline_actual <= 0);

            EXPECT_EQ(realized_window(t, tip, lookbehind),
                      inline_runs ? inline_actual : 0)
                << "height=" << height << " lookbehind=" << lookbehind;
            EXPECT_EQ(walk_ran(t, tip, lookbehind), inline_runs)
                << "height=" << height << " lookbehind=" << lookbehind;
        }
    }
}
