// ---------------------------------------------------------------------------
// bch::coin::header_sync SYNC-TO-PEER-TIP sequence soak (M5 full-block body).
//
// header_sync_test.cpp pins classify_headers_batch() one batch at a time. But
// the property the embedded daemon actually relies on is COMPOSITIONAL: that
// the per-batch policy, driven in a loop, makes cold-start IBD CONVERGE -- walk
// the whole header chain from the anchor and HALT exactly at the peer tip,
// without (a) stalling mid-chain after one batch, or (b) spinning forever on
// ContinueSync. A single-batch unit test cannot observe either failure mode.
// This fixture drives the real sync loop NodeP2P runs (getheaders -> ingest ->
// classify -> re-issue) as a pure simulation over batch sizes and pins the
// convergence + steady-state-follow claims directly.
//
// Invariants asserted:
//   1. cold-start IBD over a large gap CONVERGES: synced == peer_tip exactly
//      (no overshoot, no header left behind) for both a non-multiple gap and
//      an exact-multiple-of-cap gap.
//   2. the loop TERMINATES: round count is bounded at floor(gap/cap)+1 for
//      every gap -- the exact-multiple case takes one trailing empty/partial
//      round and then halts (never an infinite ContinueSync).
//   3. mid-IBD rounds are all ContinueSync until the final round; the final
//      round is the ONLY non-ContinueSync (the convergence point).
//   4. steady-state follow: once caught up, a BIP130 single-block tip announce
//      drives RequestBlocks (fetch the new block) -- NOT a spurious re-entry
//      into ContinueSync IBD.
//   5. degenerate gaps (0 and 1) behave: empty chain -> immediate Idle in one
//      round; one-header gap -> RequestBlocks (announce) in one round.
//
// Build-INERT / source-only: header-only over coin/header_sync.hpp -- no node,
// socket, RPC, or coin lib (impl_bch stays unregistered; bch = skip-green,
// don't race ci-steward). p2pool-merged-v36 surface: NONE -- pure SPV/IBD wire-
// sync plumbing (no PoW hash, share format, coinbase commitment, AuxPoW, or
// PPLNS math). per-coin isolation: src/impl/bch/coin/ only.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <iostream>

#include "../coin/header_sync.hpp"

using bch::coin::header_sync::Followup;
using bch::coin::header_sync::classify_headers_batch;
using bch::coin::header_sync::MAX_HEADERS_RESULTS;
using bch::coin::header_sync::DEFAULT_ANNOUNCE_THRESHOLD;

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Result of driving the headers-first IBD loop against a peer that holds
// `gap` headers beyond our anchor, serving at most `cap` per `headers` message.
struct SyncRun {
    std::uint64_t synced       = 0;  // headers ingested when the loop halted
    std::size_t   rounds       = 0;  // getheaders round-trips taken
    std::size_t   continue_n   = 0;  // rounds that classified ContinueSync
    Followup      final_action = Followup::Idle; // why the loop halted
};

// Mirror of NodeP2P's `headers` follow-up loop: request up to `cap`, ingest the
// batch, classify; ContinueSync re-issues, anything else halts the IBD walk.
// MAX_ROUNDS is a TEST-SIDE runaway guard -- if the policy ever fails to
// converge, we trip it and the bound assertion (inv. 2) catches the bug instead
// of the test hanging.
SyncRun drive_ibd(std::uint64_t gap, std::size_t cap = MAX_HEADERS_RESULTS,
                  std::size_t announce = DEFAULT_ANNOUNCE_THRESHOLD)
{
    SyncRun r;
    const std::size_t MAX_ROUNDS = 1'000'000;
    while (r.rounds < MAX_ROUNDS) {
        ++r.rounds;
        std::uint64_t remaining = gap - r.synced;
        std::size_t batch = (remaining >= cap) ? cap
                                               : static_cast<std::size_t>(remaining);
        r.synced += batch;
        Followup f = classify_headers_batch(batch, announce, cap);
        if (f == Followup::ContinueSync) { ++r.continue_n; continue; }
        r.final_action = f;
        break;
    }
    return r;
}

} // namespace

int main()
{
    const std::size_t CAP = MAX_HEADERS_RESULTS; // 2000

    // ---- inv. 1 + 2 + 3: non-multiple gap (realistic cold-start anchor) -----
    // 955700 headers ~ a fresh sync to a near-tip BCH peer from the anchor.
    {
        const std::uint64_t gap = 955700;
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // converged exactly (inv.1)
        const std::size_t expect_rounds = gap / CAP + 1; // 477 full + 1 partial
        CHECK(r.rounds == expect_rounds);             // bounded + terminates (inv.2)
        CHECK(r.continue_n == r.rounds - 1);          // all but last = ContinueSync (inv.3)
        // 955700 % 2000 == 1700, above the announce threshold -> caught-up Idle.
        CHECK(r.final_action == Followup::Idle);
    }

    // ---- inv. 1 + 2: exact-multiple gap takes a trailing round, still halts --
    {
        const std::uint64_t gap = 954000;            // == 477 * 2000, exact multiple
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // converged exactly
        // 477 maximal ContinueSync rounds, then one remaining==0 (empty) Idle round.
        CHECK(r.rounds == gap / CAP + 1);             // 478, NOT infinite
        CHECK(r.continue_n == gap / CAP);             // exactly the 477 full batches
        CHECK(r.final_action == Followup::Idle);      // empty trailing batch -> Idle
    }

    // ---- inv. 2 (bound holds across many gap shapes) ------------------------
    for (std::uint64_t gap = 0; gap <= 8005; ++gap) {
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // always converges
        CHECK(r.rounds == gap / CAP + 1);             // always bounded
        CHECK(r.rounds <= 5);                         // <= floor(8005/2000)+1 = 5
    }

    // ---- inv. 4: steady-state follow after caught up ------------------------
    // A single new block announced via BIP130 -> RequestBlocks (fetch it), and
    // crucially NOT ContinueSync (no spurious IBD re-entry on a 1-block tip).
    CHECK(classify_headers_batch(1) == Followup::RequestBlocks);
    {
        SyncRun tip_advance = drive_ibd(/*gap=*/1);
        CHECK(tip_advance.rounds == 1);               // one round, no IBD walk
        CHECK(tip_advance.continue_n == 0);           // never entered ContinueSync
        CHECK(tip_advance.final_action == Followup::RequestBlocks);
    }

    // ---- inv. 5: degenerate gaps --------------------------------------------
    {
        SyncRun empty = drive_ibd(/*gap=*/0);
        CHECK(empty.synced == 0);
        CHECK(empty.rounds == 1);                     // single empty batch
        CHECK(empty.continue_n == 0);
        CHECK(empty.final_action == Followup::Idle);  // nothing arrived -> Idle
    }

    if (failures == 0)
        std::cout << "bch header_sync sync-to-peer-tip soak: ALL PASS\n";
    else
        std::cout << "bch header_sync sync-to-peer-tip soak: " << failures << " FAIL\n";
    return failures == 0 ? 0 : 1;
}
