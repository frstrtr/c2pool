// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::BchnAnchorRecord cold-start anchor test (M5, embedded-daemon body).
//
// EmbeddedDaemon::dry_run_bchn_anchor() / apply_bchn_anchor() (wired @48a45344)
// pin the ABLA runtime from a STATIC, read-only VM300 capture (BchnAnchorRecord,
// height 955700; divergence-set section 4, frstrtr/the @0d55c4d2). The live VM
// is never touched. This test pins the two claims that wiring rests on:
//   A. PROVENANCE+FLOOR: the recorded capture is still at the 32 MB floor, so
//      pinning it changes nothing vs the cold-start floor anchor -- which is
//      exactly why the M4 safe-floor budget (slice 3, 6336679a) is correct
//      against live mainnet. is_floor() must agree with the rebuilt State.
//   B. NON-FLOOR PIN HONOURED + NEVER UNDERCUTS: when a future capture is ABOVE
//      floor, reanchor()ing the tracker from it must RAISE the build budget to
//      that live limit (the pin sharpens the cold-start), and the budget can
//      never drop below the floor regardless of the pinned State.
//
// This complements abla_floor_invariant_test.cpp (which pins the *folding* path
// off floor_anchored); here we pin the *anchor-record* path the operator-gated
// reanchor uses. Both feed the same budget_for_tip invariant.
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green; don`t race ci-steward). Verified with -fsyntax-only; runs under
// the embedded test target once impl_bch is registered. Header-only against
// coin/abla*.hpp + bchn_anchor_record.hpp -- no HeaderChain, Node, RPC, or boost
// graph (the anchor record is static; reanchor is a tracker passthrough).
// p2pool-merged-v36 surface: NONE (embedded-internal ABLA cold-start only; BCH
// is a SHA256d standalone parent, ABLA is not on the share/sharechain surface).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/abla.hpp"
#include "../coin/abla_tracker.hpp"
#include "../coin/bchn_anchor_record.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

} // namespace

int main() {
    using bch::coin::AblaTracker;
    using bch::coin::BchnAnchorRecord;
    namespace abla = bch::coin::abla;

    using Rec = BchnAnchorRecord;

    // ---- A. provenance + the recorded capture is at floor ------------------
    {
        // Provenance constants are pinned verbatim from the VM300 capture.
        CHECK(Rec::height == 955700u);
        CHECK(Rec::hash.size() == 64);          // 32-byte block hash, hex
        CHECK(Rec::merkleroot.size() == 64);
        CHECK(Rec::abla_blocksizelimit == 32000000u);

        // is_floor() must agree with the rebuilt ABLA State on BOTH networks:
        // control+elastic == 32 MB <=> GetBlockSizeLimit() == the floor.
        CHECK(Rec::is_floor());                  // the 955700 capture is at floor

        for (bool testnet : {false, true}) {
            const uint64_t floor = abla::floor_block_size_limit(testnet);
            const abla::State rec = Rec::state(testnet);
            // Recorded State limit == the floor: pinning is a no-op vs cold-start.
            CHECK(rec.GetBlockSizeLimit() == floor);
            // ...and the recorded limit field matches the rebuilt State on mainnet
            // (testnet ABLA is fixedSize, so the recorded mainnet field is the ref).
            if (!testnet)
                CHECK(rec.GetBlockSizeLimit() == Rec::abla_blocksizelimit);
        }
    }

    // ---- B1. reanchor FROM the (floor) record is a no-op vs cold start -----
    {
        const uint64_t floor = abla::floor_block_size_limit(/*is_testnet=*/false);
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/false, 800000u);
        const uint64_t cold = t.budget_for_tip(800000u);
        CHECK(cold == floor);

        // apply_bchn_anchor() passthrough: reanchor at the recorded height+State.
        t.reanchor(Rec::height, Rec::state(/*is_testnet=*/false));
        CHECK(t.is_current(Rec::height));
        // Floor record pinned -> budget identical to the cold-start floor.
        CHECK(t.budget_for_tip(Rec::height) == floor);
        CHECK(t.budget_for_tip(Rec::height) >= floor);   // hard floor, never under
    }

    // ---- B2. a future ABOVE-floor capture RAISES the budget, never under ---
    {
        const uint64_t floor = abla::floor_block_size_limit(/*is_testnet=*/false);
        const abla::Config cfg = abla::mainnet_config();

        // Synthesise a plausible non-floor capture: replay the floor anchor over
        // a run of maximally-full (32 MB) blocks. ABLA raises the control limit
        // when blocks press the limit, so the resulting State sits ABOVE floor.
        const size_t N = 64;
        uint64_t sizes[N];
        for (size_t i = 0; i < N; ++i) sizes[i] = 32u * 1000000u;
        const abla::State above = abla::replay(abla::State(cfg, 0), cfg, sizes, N);
        CHECK(above.GetBlockSizeLimit() > floor);        // pin would sharpen

        // Pinning THAT State must raise the live budget to its limit.
        AblaTracker t = AblaTracker::floor_anchored(/*is_testnet=*/false, 800000u);
        CHECK(t.budget_for_tip(800000u) == floor);
        t.reanchor(900000u, above);
        CHECK(t.is_current(900000u));
        CHECK(t.budget_for_tip(900000u) == above.GetBlockSizeLimit());
        CHECK(t.budget_for_tip(900000u) > floor);        // raised, as captured
        CHECK(t.budget_for_tip(900000u) >= floor);       // and never undercuts
    }

    if (failures == 0) {
        std::cout << "bchn_anchor_record_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "bchn_anchor_record_test: " << failures << " FAILURE(S)\n";
    return 1;
}