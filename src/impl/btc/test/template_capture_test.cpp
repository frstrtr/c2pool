// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc_template_capture_test -- pins coin/template_capture.hpp, the per-job
// template-retention seam: the PRODUCTION captured_template_txs_fn the won-block
// reconstructor's template_other_txs_fn is built from (via the slice-5
// make_template_other_txs_fn bridge, not yet landed), replacing any interim
// mempool RE-SELECTION path (merkle-consistent only on a static mempool).
//
// BTC reconstructor slice 3/7. This is a LEAF slice: TemplateCapture is opaque
// to transactions[] content (it stores/replays nlohmann::json verbatim), so the
// KAT pins the store contract WITHOUT the slice-5 bridge -- keeping the slice
// dependency-free. The composed bridge round-trip lands with slice 5.
//
// Oracle vectors are coin-agnostic GBT transactions[] shape ({data,txid,hash,
// fee}) hand-built as json literals -- the capture store treats them as opaque
// json, so no coin codec / mempool dependency is needed to observe its bytes.
//
// What it pins:
//   * capture(share_hash, transactions[]) -> provide(share_hash) replays the
//     SAME GBT transactions[] json-faithfully (json-equal), keyed by share.
//   * a capture MISS replays an empty array -> coinbase-only valid block (NOT
//     fail-closed), so a missing template never forfeits the won subsidy.
//   * overwrite-same-hash keeps one entry (latest wins); FIFO eviction bounds
//     the store and drops the OLDEST template once over capacity.
//
// Rides the allowlisted btc_share_test add_executable (test/CMakeLists.txt);
// a new *_test.cpp MUST be in that source list or it silently NOT_BUILT (#143).
// Per-coin isolation: src/impl/btc/ only.
// ---------------------------------------------------------------------------
#include <cstddef>
#include <string>

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include <impl/btc/coin/template_capture.hpp>
#include <core/uint256.hpp>

using btc::coin::TemplateCapture;

namespace {

uint256 hash_for(const char* hex)
{
    uint256 h; h.SetHex(hex);
    return h;
}

// A production-shaped GBT transactions[]: array of {data,txid,hash,fee}. Content
// is opaque to TemplateCapture -- these literals stand in for a populated GBT.
nlohmann::json sample_template_txs()
{
    return nlohmann::json::array({
        {{"data", "0100000001aa"}, {"txid", "aa01"}, {"hash", "aa01"}, {"fee", 700}},
        {{"data", "0100000001bb"}, {"txid", "bb02"}, {"hash", "bb02"}, {"fee", 300}},
    });
}

const char* H_A = "00000000000000000000000000000000000000000000000000000000000000a1";
const char* H_B = "00000000000000000000000000000000000000000000000000000000000000b2";
const char* H_C = "00000000000000000000000000000000000000000000000000000000000000c3";
const char* H_MISS = "00000000000000000000000000000000000000000000000000000000deadbeef";

} // namespace

// --- Test 1: capture -> provide round-trips the template json-faithfully -------
TEST(BtcTemplateCapture, CaptureProvideRoundTrip)
{
    TemplateCapture cap;
    const auto txs = sample_template_txs();
    ASSERT_EQ(txs.size(), 2u);

    cap.capture(hash_for(H_A), txs);
    EXPECT_EQ(cap.size(), 1u);
    // json-equal: the exact transactions[] handed in comes back out.
    EXPECT_EQ(cap.provide(hash_for(H_A)), txs);
}

// --- Test 2: a MISS replays an empty array (coinbase-only, not fail-closed) ---
TEST(BtcTemplateCapture, MissReplaysEmptyArray)
{
    TemplateCapture cap;
    cap.capture(hash_for(H_A), sample_template_txs());

    const auto miss = cap.provide(hash_for(H_MISS));
    ASSERT_TRUE(miss.is_array());
    EXPECT_TRUE(miss.empty());
}

// --- Test 3: the provider() closure replays HIT and MISS identically ----------
// Pins that provider() is a transparent view over provide(): a HIT yields the
// captured template json-equal, a MISS yields an empty array. (The slice-5
// make_template_other_txs_fn bridge decodes this same output; that composed
// round-trip lands with slice 5.)
TEST(BtcTemplateCapture, ProviderClosureMirrorsProvide)
{
    TemplateCapture cap;
    const auto txs = sample_template_txs();
    cap.capture(hash_for(H_A), txs);

    auto provider = cap.provider();
    EXPECT_EQ(provider(hash_for(H_A)), txs);          // HIT: json-equal
    EXPECT_TRUE(provider(hash_for(H_MISS)).empty());  // MISS: empty array
}

// --- Test 4: overwrite the same share_hash keeps one entry (latest wins) ------
TEST(BtcTemplateCapture, OverwriteSameHashLatestWins)
{
    TemplateCapture cap;
    cap.capture(hash_for(H_A), nlohmann::json::array());      // empty first
    cap.capture(hash_for(H_A), sample_template_txs());        // then 2-tx template
    EXPECT_EQ(cap.size(), 1u);                                // not duplicated
    EXPECT_EQ(cap.provide(hash_for(H_A)).size(), 2u);         // latest content
}

// --- Test 5: FIFO eviction bounds the store, drops the OLDEST template --------
TEST(BtcTemplateCapture, BoundedFifoEvictsOldest)
{
    TemplateCapture cap(/*capacity=*/2);
    cap.capture(hash_for(H_A), sample_template_txs());
    cap.capture(hash_for(H_B), sample_template_txs());
    cap.capture(hash_for(H_C), sample_template_txs());        // evicts H_A

    EXPECT_EQ(cap.size(), 2u);
    EXPECT_TRUE(cap.provide(hash_for(H_A)).empty());          // oldest evicted -> miss
    EXPECT_EQ(cap.provide(hash_for(H_B)).size(), 2u);         // newest retained
    EXPECT_EQ(cap.provide(hash_for(H_C)).size(), 2u);
}
