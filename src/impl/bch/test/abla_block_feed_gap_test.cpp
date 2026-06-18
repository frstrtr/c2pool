// ---------------------------------------------------------------------------
// bch::coin AblaBlockFeed GAP/never-undercut test (M5 -- full-block -> ABLA).
//
// abla_block_feed_test pins the feed's height-resolution, off-chain-skip, and
// duplicate-ignore paths -- but it only ever feeds CONTIGUOUS blocks, so the
// single most load-bearing safety claim of the whole size feed is left
// unexercised END-TO-END through the feed:
//
//   "a reorg or a skipped block can only ever DROP the budget to the safe
//    floor, never raise it on bad data" (abla_block_feed.hpp).
//
// The tracker's gap logic (height > cursor+1 -> m_valid=false -> stale -> floor)
// is unit-tested directly in abla_floor_invariant_test, but that bypasses the
// feed's height-resolution -- the exact seam where a real missed/replaced block
// turns into a non-contiguous height. This test drives that path through the
// REAL AblaBlockFeed::on_full_block: it resolves a height from the header index
// that is non-contiguous with the tracker cursor and asserts the never-undercut
// invariant holds, latches, and is recoverable only via reanchor().
//
// Setup: a block indexed at height H, but the tracker anchored at H-5, so the
// feed resolves H and hands the tracker a GAP (H != cursor+1). Asserts:
//   1. GAP -> tracker goes stale; cursor is NOT advanced on a non-contiguous
//      block; budget_for_tip falls back to EXACTLY the 32 MB floor (never sub-,
//      never raised on data we cannot fold) for every queried height.
//   2. STALE LATCHES: re-feeding the same block while stale does not silently
//      "recover" -- still stale, still floor, cursor still pinned.
//   3. RECOVERY is reanchor()-only: a fresh known-good {height,State} clears the
//      stale flag and restores a current, >= floor budget.
//
// Build-INERT / source-only (matches abla_block_feed_test): impl_bch stays
// unregistered in CMake (bch = skip-green; don't race ci-steward). Verified
// -fsyntax-only EXIT=0 AND compile+link+run ALL PASS EXIT=0, linking the REAL
// core objects (same recipe as abla_block_feed_test): core.dir/{uint256,log,
// leveldb_store}.cpp.o + libbtclibs.a + -lboost_log[_setup] -lleveldb -lssl
// -lcrypto -lpthread, built -DBOOST_LOG_DYN_LINK to match the project's boost
// ABI. (Pull only those 3 core objects -- the full core.dir/*.o set drags in
// YAML/hashrate/web_server transitively.) No daemon-graph stubbing.
// p2pool-merged-v36 surface: NONE
// (pure local build-time block-size budget; no PoW/share/coinbase/PPLNS math).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/abla.hpp"
#include "../coin/abla_block_feed.hpp"
#include "../coin/abla_tracker.hpp"
#include "../coin/block.hpp"
#include "../coin/header_chain.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Same minimal-block crafting as abla_block_feed_test: non-null prev (not the
// genesis-special case) + distinct nonce so each block has a distinct hash.
bch::coin::BlockType make_block(uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block.SetHex(
        "00000000000000000001a2b3c4d5e6f700000000000000000000000000000000");
    b.m_merkle_root.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    b.m_timestamp = 1700000000;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

} // namespace

int main() {
    using bch::coin::AblaTracker;
    using bch::coin::AblaBlockFeed;
    using bch::coin::BCHChainParams;
    using bch::coin::HeaderChain;

    const uint32_t H   = 800001;   // the height our indexed block resolves to
    const uint32_t GAP = 5;        // anchor this far below H -> non-contiguous

    // Index exactly one block at height H via the fast-start checkpoint, mirror
    // of abla_block_feed_test's seeding.
    bch::coin::BlockType on_chain = make_block(/*nonce=*/1);
    const uint256 on_hash =
        bch::coin::block_hash(static_cast<const bch::coin::BlockHeaderType&>(on_chain));

    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, on_hash};
    HeaderChain chain(params);
    CHECK(chain.init());
    {
        auto e = chain.get_header(on_hash);
        CHECK(e.has_value());
        CHECK(e && e->height == H);
    }

    const uint64_t floor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/false);

    // Anchor the tracker GAP blocks BELOW H so the resolved height H is
    // non-contiguous (H != (H-GAP)+1). This is the shape a missed/replaced
    // block download produces: header index ahead of where ABLA folded to.
    AblaTracker tracker = AblaTracker::floor_anchored(/*is_testnet=*/false, H - GAP);
    AblaBlockFeed feed(tracker, chain);

    CHECK(!tracker.is_stale());
    CHECK(tracker.is_current(H - GAP));
    CHECK(tracker.cursor_height() == H - GAP);

    // 1) GAP: feed resolves H from the index, hands the tracker a non-contiguous
    //    height -> stale; cursor NOT advanced; budget falls to EXACTLY the floor
    //    for every tip we could ask about (never sub-floor, never raised on data
    //    we cannot fold). This is the never-undercut invariant through the feed.
    feed.on_full_block(on_chain);
    CHECK(tracker.is_stale());                       // gap detected
    CHECK(!tracker.is_current(H));                   // did NOT fold at the gap height
    CHECK(tracker.cursor_height() == H - GAP);       // cursor pinned, not advanced on a gap
    CHECK(tracker.budget_for_tip(H)        == floor);
    CHECK(tracker.budget_for_tip(H - GAP)  == floor);
    CHECK(tracker.budget_for_tip(H + 1)    == floor);

    // 2) STALE LATCHES: re-feeding the same block must not silently recover --
    //    record_block_size() short-circuits while invalid, so the feed cannot
    //    climb back off the floor on its own; only reanchor() may.
    feed.on_full_block(on_chain);
    CHECK(tracker.is_stale());
    CHECK(tracker.cursor_height() == H - GAP);
    CHECK(tracker.budget_for_tip(H) == floor);

    // 3) RECOVERY is reanchor()-only: a fresh known-good {height, State} (here
    //    the floor State at H, the BCHN-pin / explicit-reanchor path) clears the
    //    stale flag and restores a current, >= floor budget.
    tracker.reanchor(H, bch::coin::abla::State(bch::coin::abla::mainnet_config(), 0));
    CHECK(!tracker.is_stale());
    CHECK(tracker.is_current(H));
    CHECK(tracker.cursor_height() == H);
    CHECK(tracker.budget_for_tip(H) >= floor);

    if (failures == 0) {
        std::cout << "abla_block_feed_gap_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "abla_block_feed_gap_test: " << failures << " FAILURE(S)\n";
    return 1;
}
