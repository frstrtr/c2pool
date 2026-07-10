// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin AblaBlockFeed test (M5 -- the full-block -> ABLA wiring layer).
//
// AblaBlockFeed is the piece that closes the gap M5 slice C left open:
// AblaTracker::record_block_size() existed, but nothing fed it from the real
// block-connect path. The feed subscribes to interfaces::Node::full_block,
// resolves each received block's height from the best-chain HeaderChain index,
// and folds the block's ACTUAL serialized size into the tracker. Its safety
// claims are NOT exercised by abla_floor_invariant_test, which drives the
// tracker directly and bypasses the feed's two load-bearing decisions:
//
//   (a) HEIGHT RESOLUTION via the header index -- the feed never *guesses* a
//       height; it reads it from HeaderChain::get_header(block_hash).
//   (b) OFF-CHAIN SKIP -- a block whose hash is not on the indexed best chain
//       (unsolicited / side branch / header not yet synced) is dropped with NO
//       record_block_size() call, so the tracker's cursor is never advanced on
//       a block we cannot trust a height for.
//
// This test pins (a) and (b) directly against a real (in-memory) HeaderChain
// seeded so that one crafted block resolves to a known height, asserting:
//   1. on_full_block(on-chain block) -> folds at the resolved height; cursor
//      advances, budget stays >= 32 MB floor (ABLA only raises).
//   2. on_full_block(off-chain block) -> NO state change: budget and currency
//      identical before/after; the cursor is NOT moved on an unindexed block.
//   3. on_full_block(duplicate of the on-chain block) -> tracker's height<=cursor
//      idempotent-ignore holds end-to-end through the feed (no spurious gap).
//
// Build-INERT / source-only posture (matches abla_floor_invariant_test): impl_bch
// stays unregistered in CMake (bch = skip-green; don't race ci-steward). Verified
// with -fsyntax-only and standalone compile+run. p2pool-merged-v36 surface: NONE
// (pure local build-time block-size budget; no PoW/share/coinbase/PPLNS math).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/abla_block_feed.hpp"
#include "../coin/abla_tracker.hpp"
#include "../coin/block.hpp"
#include "../coin/header_chain.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Craft a minimal full block with a non-null prev (so it is NOT treated as the
// genesis-special case) and a distinct nonce. Empty tx vector is fine -- the
// feed records pack(block).size(), and ABLA only ever RAISES vs the floor, so a
// small block keeps the budget pinned at the floor (still >= floor: the invariant).
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

    const uint32_t H = 800001;   // the height our on-chain block resolves to

    // The on-chain block, and its SHA256d identity hash.
    bch::coin::BlockType on_chain = make_block(/*nonce=*/1);
    const uint256 on_hash =
        bch::coin::block_hash(static_cast<const bch::coin::BlockHeaderType&>(on_chain));

    // Seed an in-memory HeaderChain whose fast-start checkpoint IS our block's
    // hash at height H. get_header(on_hash) now returns {height = H}; any other
    // hash is unindexed -> the feed's off-chain branch.
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

    // Anchor the tracker at H-1 so the on-chain block at H is a CONTIGUOUS fold.
    AblaTracker tracker = AblaTracker::floor_anchored(/*is_testnet=*/false, H - 1);
    AblaBlockFeed feed(tracker, chain);

    // 1) On-chain block -> feed resolves height H from the index and folds.
    CHECK(tracker.cursor_height() == H - 1);
    feed.on_full_block(on_chain);
    CHECK(tracker.is_current(H));                 // resolved + folded at H
    CHECK(tracker.cursor_height() == H);          // cursor advanced exactly one
    CHECK(tracker.budget_for_tip(H) >= floor);    // ABLA only raises, never sub-floor

    // 2) Off-chain block -> hash not indexed -> NO state change at all.
    const uint64_t budget_before = tracker.budget_for_tip(H);
    bch::coin::BlockType off_chain = make_block(/*nonce=*/99);  // different hash
    const uint256 off_hash =
        bch::coin::block_hash(static_cast<const bch::coin::BlockHeaderType&>(off_chain));
    CHECK(!chain.get_header(off_hash).has_value());            // truly unindexed
    feed.on_full_block(off_chain);
    CHECK(tracker.is_current(H));                 // cursor untouched...
    CHECK(tracker.cursor_height() == H);          // ...not advanced on a guess
    CHECK(tracker.budget_for_tip(H) == budget_before);        // zero state change

    // 3) Duplicate of the on-chain block -> height H <= cursor -> idempotent
    //    ignore propagates cleanly through the feed (no spurious gap -> floor).
    feed.on_full_block(on_chain);
    CHECK(tracker.is_current(H));
    CHECK(tracker.cursor_height() == H);
    CHECK(tracker.budget_for_tip(H) == budget_before);

    if (failures == 0) {
        std::cout << "abla_block_feed_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "abla_block_feed_test: " << failures << " FAILURE(S)\n";
    return 1;
}