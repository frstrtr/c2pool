// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_template_capture_test -- pins coin/template_capture.hpp, the per-job
// template-retention seam (#271): the PRODUCTION captured_template_txs_fn the
// won-block reconstructor's template_other_txs_fn is built from (via the #299
// make_template_other_txs_fn bridge), replacing main_dgb's interim mempool
// RE-SELECTION lambda (merkle-consistent only on a static mempool).
//
// What it pins:
//   * capture(share_hash, transactions[]) -> provide(share_hash) replays the
//     SAME GBT transactions[] byte-faithfully (json-equal), keyed by share.
//   * a capture MISS replays an empty array -> coinbase-only valid block (NOT
//     fail-closed), so a missing template never forfeits the won subsidy.
//   * make_template_other_txs_fn(capture.provider()) decodes a HIT to the exact
//     MutableTransaction vector deserialize_template_other_txs yields directly
//     from the same template -- i.e. the capture path is transparent to the
//     #299 bridge -- and a MISS to an empty other_txs vector.
//   * overwrite-same-hash keeps one entry (latest wins); FIFO eviction bounds
//     the store and drops the OLDEST template once over capacity.
//
// Links the full dgb_coin codec + reconstruct closure (it composes the #299
// bridge over the production make_mempool_tx_source template). MUST be in BOTH
// build.yml --target allowlists (#143 NOT_BUILT trap). Per-coin isolation:
// src/impl/dgb/ only.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/template_capture.hpp>
#include <impl/dgb/coin/template_other_txs.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/transaction.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::TX_WITH_WITNESS;
using dgb::coin::compute_txid;
using dgb::coin::make_mempool_tx_source;
using dgb::coin::deserialize_template_other_txs;
using dgb::coin::make_template_other_txs_fn;
using dgb::coin::TemplateCapture;

namespace {

MutableTransaction tagged_tx(int64_t value, uint32_t index)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

std::string withwit_hex(const MutableTransaction& tx)
{
    return HexStr(pack(TX_WITH_WITNESS(tx)).get_span());
}

uint256 hash_for(const char* hex)
{
    uint256 h; h.SetHex(hex);
    return h;
}

// A production-shaped GBT transactions[] from a populated mempool.
nlohmann::json sample_template_txs()
{
    Mempool pool;
    MutableTransaction a = tagged_tx(11, 0);
    MutableTransaction b = tagged_tx(22, 1);
    pool.add_tx(a);
    pool.add_tx(b);
    pool.set_tx_fee(compute_txid(a), 700);
    pool.set_tx_fee(compute_txid(b), 300);
    return make_mempool_tx_source(pool, /*max_weight=*/4'000'000)().transactions;
}

const char* H_A = "00000000000000000000000000000000000000000000000000000000000000a1";
const char* H_B = "00000000000000000000000000000000000000000000000000000000000000b2";
const char* H_C = "00000000000000000000000000000000000000000000000000000000000000c3";
const char* H_MISS = "00000000000000000000000000000000000000000000000000000000deadbeef";

} // namespace

// --- Test 1: capture -> provide round-trips the template byte-faithfully ------
TEST(DgbTemplateCapture, CaptureProvideRoundTrip)
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
TEST(DgbTemplateCapture, MissReplaysEmptyArray)
{
    TemplateCapture cap;
    cap.capture(hash_for(H_A), sample_template_txs());

    const auto miss = cap.provide(hash_for(H_MISS));
    ASSERT_TRUE(miss.is_array());
    EXPECT_TRUE(miss.empty());
}

// --- Test 3: composed through the #299 bridge, a HIT decodes to the exact tx --
// vector deserialize_template_other_txs yields directly from the same template;
// a MISS decodes to an empty other_txs vector. Proves the capture path is
// transparent to the reconstructor's template_other_txs_fn.
TEST(DgbTemplateCapture, ComposedWithBridgeHitAndMiss)
{
    TemplateCapture cap;
    const auto txs = sample_template_txs();
    cap.capture(hash_for(H_A), txs);

    auto other_txs_fn = make_template_other_txs_fn(cap.provider());

    // HIT: identical to decoding the template directly, in template order.
    const auto via_capture = other_txs_fn(hash_for(H_A));
    const auto direct = deserialize_template_other_txs(txs);
    ASSERT_EQ(via_capture.size(), direct.size());
    ASSERT_EQ(via_capture.size(), 2u);
    for (size_t i = 0; i < via_capture.size(); ++i)
        EXPECT_EQ(withwit_hex(via_capture[i]), withwit_hex(direct[i]));

    // MISS: empty other_txs -> the reconstructor frames a coinbase-only block.
    EXPECT_TRUE(other_txs_fn(hash_for(H_MISS)).empty());
}

// --- Test 4: overwrite the same share_hash keeps one entry (latest wins) ------
TEST(DgbTemplateCapture, OverwriteSameHashLatestWins)
{
    TemplateCapture cap;
    cap.capture(hash_for(H_A), nlohmann::json::array());      // empty first
    cap.capture(hash_for(H_A), sample_template_txs());        // then 2-tx template
    EXPECT_EQ(cap.size(), 1u);                                // not duplicated
    EXPECT_EQ(cap.provide(hash_for(H_A)).size(), 2u);         // latest content
}

// --- Test 5: FIFO eviction bounds the store, drops the OLDEST template --------
TEST(DgbTemplateCapture, BoundedFifoEvictsOldest)
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