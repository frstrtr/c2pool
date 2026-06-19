// ---------------------------------------------------------------------------
// bch::coin::header_sync::classify_headers_batch -- M5 full-block body.
// Pins the headers-first IBD continuation policy that NodeP2P's `headers`
// handler dispatches on. Pure function over a batch size, so this test needs
// NO peer, socket, or coin lib -- header-only over coin/header_sync.hpp.
//
// The behavior under test (the gap this slice closed): a MAXIMAL headers batch
// (== MAX_HEADERS_RESULTS) must drive ContinueSync so cold-start IBD walks the
// whole header chain instead of stalling after the first batch; a small BIP130
// tip-announce batch (<= threshold) drives RequestBlocks; everything else
// (empty, or a non-maximal "caught up" batch) is Idle.
//
// p2pool-merged-v36 surface: NONE. per-coin isolation: src/impl/bch/ only.
// ---------------------------------------------------------------------------

#include <cassert>
#include <iostream>

#include "../coin/header_sync.hpp"

using bch::coin::header_sync::Followup;
using bch::coin::header_sync::classify_headers_batch;
using bch::coin::header_sync::MAX_HEADERS_RESULTS;
using bch::coin::header_sync::DEFAULT_ANNOUNCE_THRESHOLD;

int main()
{
    // Empty batch: nothing arrived.
    assert(classify_headers_batch(0) == Followup::Idle);

    // BIP130 tip-announce sizes (1..threshold) -> request the announced blocks.
    assert(classify_headers_batch(1) == Followup::RequestBlocks);
    assert(classify_headers_batch(DEFAULT_ANNOUNCE_THRESHOLD) == Followup::RequestBlocks);

    // Just above the announce threshold but well below the cap: a partial IBD
    // batch means we've reached the peer's tip -> Idle (no further getheaders).
    assert(classify_headers_batch(DEFAULT_ANNOUNCE_THRESHOLD + 1) == Followup::Idle);
    assert(classify_headers_batch(MAX_HEADERS_RESULTS - 1) == Followup::Idle);

    // Maximal batch (== cap): the peer capped its response because it has more
    // -> ContinueSync (re-issue getheaders for the next batch). THE FIX.
    assert(classify_headers_batch(MAX_HEADERS_RESULTS) == Followup::ContinueSync);
    // Defensive: a batch somehow larger than the cap is still ContinueSync.
    assert(classify_headers_batch(MAX_HEADERS_RESULTS + 1) == Followup::ContinueSync);

    // ContinueSync dominates RequestBlocks at the cap even with a wide announce
    // threshold (ordering of the policy checks is correct).
    assert(classify_headers_batch(MAX_HEADERS_RESULTS, MAX_HEADERS_RESULTS) == Followup::ContinueSync);

    // Custom thresholds: announce_threshold widens the RequestBlocks band.
    assert(classify_headers_batch(5, /*announce=*/5) == Followup::RequestBlocks);
    assert(classify_headers_batch(6, /*announce=*/5) == Followup::Idle);
    // Custom small cap: at-cap batch is ContinueSync.
    assert(classify_headers_batch(10, /*announce=*/3, /*cap=*/10) == Followup::ContinueSync);

    std::cout << "bch header_sync classify: ALL PASS\n";
    return 0;
}
