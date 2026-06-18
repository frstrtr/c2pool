// ---------------------------------------------------------------------------
// bch::abla AblaTracker floor-invariant test (M5 cold-start safety).
//
// EmbeddedDaemon cold-starts the ABLA loop at the activation/floor State and
// folds live full-block sizes forward (node -> feed -> tracker). Its safety
// claim -- the one the whole embedded budget rests on -- is: the dynamic build
// budget can only EVER equal-or-exceed the 32 MB floor; folding live sizes can
// only RAISE it, and any feed fault (gap / stale / cold) falls back to the
// floor outright, never undercutting it. This test pins that claim directly
// against AblaTracker so a regression in the budget path cannot silently emit
// a sub-floor template.
//
// Invariants asserted:
//   1. cold-start floor_anchored        -> budget_for_tip == floor exactly
//   2. contiguous record advances cursor & budget stays >= floor (grows)
//   3. GAP (height > cursor+1)          -> stale: state_for_tip==nullptr,
//                                          budget falls back to floor, and
//                                          further records are IGNORED
//   4. reanchor() restores a current State and re-enables folding
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green; don`t race ci-steward). Verified with -fsyntax-only; runs under
// the embedded test target once impl_bch is registered. Header-only against
// coin/abla*.hpp -- no node, RPC, or boost graph. p2pool-merged-v36 surface:
// NONE (pure local build-time block-size budget; no PoW/share/coinbase math).
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

    const uint32_t H0 = 800000;                       // arbitrary anchor height

    // ---- mainnet (growing) ------------------------------------------------
    {
        const uint64_t floor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/false);
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/false, H0);

        // 1) Cold start: budget is exactly the floor, state is current.
        CHECK(t.budget_for_tip(H0) == floor);
        CHECK(t.is_current(H0));
        CHECK(t.state_for_tip(H0) != nullptr);

        // 2) Fold a contiguous full-ish block in -> cursor advances, never < floor.
        t.record_block_size(H0 + 1, /*serialized_size=*/30u * 1000000u);
        CHECK(t.is_current(H0 + 1));
        CHECK(t.budget_for_tip(H0 + 1) >= floor);      // ABLA only raises

        // 3) GAP: skip a height -> stale; sub-floor never returned, records ignored.
        t.record_block_size(H0 + 5, /*serialized_size=*/1u * 1000000u);
        CHECK(!t.is_current(H0 + 5));                  // gap invalidated the cursor
        CHECK(t.state_for_tip(H0 + 5) == nullptr);     // builder takes floor fallback
        CHECK(t.budget_for_tip(H0 + 5) == floor);      // hard floor, never undercut
        // a further record while stale must NOT silently resume folding
        t.record_block_size(H0 + 6, 31u * 1000000u);
        CHECK(t.budget_for_tip(H0 + 6) == floor);

        // 4) reanchor with a known-good floor State -> current again, folding on.
        AblaTracker fresh = AblaTracker::floor_anchored(/*is_testnet=*/false, H0 + 6);
        const bch::coin::abla::State* good = fresh.state_for_tip(H0 + 6);
        CHECK(good != nullptr);
        t.reanchor(H0 + 6, *good);
        CHECK(t.is_current(H0 + 6));
        CHECK(t.budget_for_tip(H0 + 6) == floor);
        t.record_block_size(H0 + 7, 30u * 1000000u);
        CHECK(t.is_current(H0 + 7));
        CHECK(t.budget_for_tip(H0 + 7) >= floor);
    }

    // ---- testnet (fixed 32 MB) -------------------------------------------
    {
        const uint64_t floor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/true);
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/true, H0);
        CHECK(t.budget_for_tip(H0) == floor);
        // testnet ABLA is a no-op (fixedSize) -> budget stays pinned at floor.
        t.record_block_size(H0 + 1, 32u * 1000000u);
        CHECK(t.budget_for_tip(H0 + 1) == floor);
    }

    if (failures == 0) {
        std::cout << "abla_floor_invariant_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "abla_floor_invariant_test: " << failures << " FAILURE(S)\n";
    return 1;
}
