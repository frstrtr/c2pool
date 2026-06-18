// ---------------------------------------------------------------------------
// bch::abla AblaTracker budget-GROWTH soak test (M5 dynamic-sizing proof).
//
// The floor-invariant test (abla_floor_invariant_test.cpp) pins the SAFETY
// claim: the embedded build budget can never undercut the 32 MB floor. But
// that test only ever observes the budget AT the floor -- it never exercises
// the feature ABLA actually exists for: raising the limit above 32 MB when the
// network sustains full blocks. Live near-tip BCH stays well sub-floor, so the
// dynamic-RISE path is structurally unprovable against VM300 data. This fixture
// closes that gap with a synthetic over-floor stream and pins the GROWTH claim
// directly against AblaTracker -- the same node->feed->tracker path the daemon
// folds live full-block sizes through.
//
// Drive: sustained MAXIMALLY-FULL blocks. Each height feeds a block exactly the
// size of the previous tip's limit (budget_for_tip), the worst-case load ABLA
// is designed to absorb. Under the BCHN v29 control function (zeta=192/128=1.5x
// amplification, gamma/theta reciprocal 37938) this is a monotonic ramp off the
// floor of ~2 KB/block.
//
// Invariants asserted:
//   1. cold start                       -> budget == 32 MB floor exactly
//   2. sustained full blocks            -> budget is monotonic NON-DECREASING
//                                          every step (never dips under load)
//   3. the rise is STRICT and sustained -> a strong majority of steps strictly
//                                          increase (not a one-off blip / mere
//                                          change)
//   4. end state                        -> budget strictly ABOVE the 32 MB
//                                          floor (the dynamic feature fires)
//   5. testnet (fixedSize ABLA)         -> budget stays pinned at floor even
//                                          under identical full-block load
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green; don't race ci-steward). Verified with -fsyntax-only; runs under
// the embedded ABLA test target. Header-only against coin/abla*.hpp -- no node,
// RPC, or boost graph. p2pool-merged-v36 surface: NONE (pure local build-time
// block-size budget; no PoW/share/coinbase math; p2poolBCH carries no ABLA, so
// this path is purely additive with zero shared-surface divergence).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/abla.hpp"
#include "../coin/abla_tracker.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

} // namespace

int main() {
    using bch::coin::AblaTracker;

    const uint32_t H0 = 800000;   // arbitrary anchor height
    const int WINDOW = 5000;      // ~5000 sustained full blocks (~3.5 days @10min)

    // ---- mainnet: sustained full blocks must ramp the budget off the floor --
    {
        const uint64_t floor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/false);
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/false, H0);

        // 1) Cold start sits exactly on the 32 MB floor.
        CHECK(t.budget_for_tip(H0) == floor);
        CHECK(t.is_current(H0));

        uint64_t prev = floor;
        uint64_t strict_increases = 0;
        for (int i = 1; i <= WINDOW; ++i) {
            const uint32_t h = H0 + static_cast<uint32_t>(i);
            // Maximally-full block: exactly the previous tip's limit.
            t.record_block_size(h, prev);
            CHECK(t.is_current(h));                 // contiguous feed never goes stale
            const uint64_t b = t.budget_for_tip(h);
            CHECK(b >= prev);                       // 2) monotonic under sustained load
            if (b > prev) ++strict_increases;
            prev = b;
        }

        // 3) The rise is strict and sustained, not a single blip.
        CHECK(strict_increases >= static_cast<uint64_t>(WINDOW) * 9 / 10);
        // 4) The budget genuinely rose ABOVE the 32 MB floor (feature fired).
        CHECK(prev > floor);

        std::cout << "abla_growth_soak_test[mainnet]: floor=" << floor
                  << " final=" << prev
                  << " delta=" << (prev - floor)
                  << " strict_steps=" << strict_increases << "/" << WINDOW << "\n";
    }

    // ---- testnet: fixedSize ABLA must NOT grow under the same full-block load -
    {
        const uint64_t tfloor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/true);
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/true, H0);
        CHECK(t.budget_for_tip(H0) == tfloor);
        for (int i = 1; i <= WINDOW; ++i) {
            const uint32_t h = H0 + static_cast<uint32_t>(i);
            t.record_block_size(h, tfloor);
            CHECK(t.budget_for_tip(h) == tfloor);   // 5) fixed at floor, no ramp
        }
        std::cout << "abla_growth_soak_test[testnet]: pinned=" << tfloor << " (no ramp)\n";
    }

    if (failures == 0) {
        std::cout << "abla_growth_soak_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "abla_growth_soak_test: " << failures << " FAILURE(S)\n";
    return 1;
}
