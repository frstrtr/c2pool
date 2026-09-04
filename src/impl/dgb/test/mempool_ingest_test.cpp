// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_mempool_ingest_test -- pins c2pool::dgb::wire_mempool_ingest, the
// connector that routes the embedded P2P `tx` relay (dgb::interfaces::Node::
// new_tx) into the in-process Mempool so the embedded work template selects
// from a live pool instead of an always-empty one.
//
// This is the tx analog of dgb_header_ingest_test (new_headers -> HeaderChain).
// Disposition (txid compute, duplicate rejection, weight + byte cap) is
// delegated to Mempool::add_tx, the insertion SSOT; the connector adds no
// policy of its own, so the assertions here pin the WIRING (the feed reaches
// the pool, an unwired node feeds nothing, the handle drives it) rather than
// re-testing the mempool's internals.
//
// Links the full dgb_coin codec like dgb_embedded_tx_select_test (it compiles
// the tx serialization). MUST be in BOTH build.yml --target allowlists (#143
// NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <cstdint>

#include <gtest/gtest.h>

#include <impl/dgb/coin/mempool_ingest.hpp>
#include <impl/dgb/coin/node_interface.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/transaction.hpp>
#include <impl/dgb/coin/embedded_tx_select.hpp>     // make_mempool_tx_source (fee-proof selection)
#include <impl/dgb/coin/good_citizen_defaults.hpp>  // resolve_tx_serve_posture (S1 truth table)
#include <core/coin/utxo.hpp>                        // core::coin::Coin/Outpoint/DGB_LIMITS
#include <core/coin/utxo_view_cache.hpp>            // core::coin::UTXOViewCache (fee view)

using c2pool::dgb::wire_mempool_ingest;
using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::Transaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::compute_txid;

namespace {

// A minimal, distinct tx tagged by its prevout index so each has a distinct
// txid (mirrors the builder in dgb_embedded_tx_select_test).
MutableTransaction tagged_tx(uint32_t index)
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
    out.value = 50'000;
    tx.vout.push_back(out);
    return tx;
}

} // namespace

// 1. A fresh, wired-but-quiet node leaves the pool empty.
TEST(MempoolIngest, EmptyPoolBeforeRelay)
{
    Mempool pool;
    dgb::interfaces::Node node;
    auto sub = wire_mempool_ingest(node, pool);

    EXPECT_EQ(pool.size(), 0u);
}

// 2. A tx announced on new_tx is ingested through add_tx: the pool grows and
//    the tx is queryable by its txid.
TEST(MempoolIngest, AnnouncedTxIsIngested)
{
    Mempool pool;
    dgb::interfaces::Node node;
    auto sub = wire_mempool_ingest(node, pool);

    auto mt = tagged_tx(0);
    node.new_tx.happened(Transaction(mt));

    EXPECT_EQ(pool.size(), 1u);
    EXPECT_TRUE(pool.contains(compute_txid(mt)));
}

// 3. Multiple distinct relays accumulate in the pool.
TEST(MempoolIngest, DistinctRelaysAccumulate)
{
    Mempool pool;
    dgb::interfaces::Node node;
    auto sub = wire_mempool_ingest(node, pool);

    auto a = tagged_tx(0);
    auto b = tagged_tx(1);
    node.new_tx.happened(Transaction(a));
    node.new_tx.happened(Transaction(b));

    EXPECT_EQ(pool.size(), 2u);
    EXPECT_TRUE(pool.contains(compute_txid(a)));
    EXPECT_TRUE(pool.contains(compute_txid(b)));
}

// 4. Disposition is delegated to add_tx, not the connector: a duplicate relay
//    of the same tx is rejected by the pool's SSOT, leaving size unchanged.
TEST(MempoolIngest, DuplicateRelayIsRejected)
{
    Mempool pool;
    dgb::interfaces::Node node;
    auto sub = wire_mempool_ingest(node, pool);

    auto mt = tagged_tx(0);
    node.new_tx.happened(Transaction(mt));
    node.new_tx.happened(Transaction(mt));  // same txid

    EXPECT_EQ(pool.size(), 1u);
}

// 5. The connector is the driver: a node with NO ingest subscription drops the
//    relay -- the pool stays empty.
TEST(MempoolIngest, UnwiredNodeIngestsNothing)
{
    Mempool pool;
    dgb::interfaces::Node node;  // deliberately NOT wired

    node.new_tx.happened(Transaction(tagged_tx(0)));

    EXPECT_EQ(pool.size(), 0u);
}

// ===========================================================================
// S1 fee-proof lane KATs (--embedded-serve-mempool-txs). These pin the ACTUAL
// ingest port the good-citizen gap needs: a relayed tx priced against an
// embedded UTXO view so make_mempool_tx_source builds a FEE-BEARING template.
// ===========================================================================

using dgb::coin::make_mempool_tx_source;

namespace {

// A tx that SPENDS a seeded outpoint (null-hash, `index`) for `out_value`; the
// coin seeded below carries `out_value + fee`, so the fee is exactly `fee`.
MutableTransaction spending_tx(uint32_t index, int64_t out_value)
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
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

// Seed the outpoint (null-hash, `index`) with a non-coinbase coin worth `value`.
void seed_coin(core::coin::UTXOViewCache& utxo, uint32_t index, int64_t value)
{
    uint256 null_hash;
    null_hash.SetNull();
    core::coin::Outpoint op(null_hash, index);
    utxo.add_coin(op, core::coin::Coin(value, OPScript{},
                                       /*height=*/1, /*coinbase=*/false));
}

} // namespace

// 6. REGRESSION WITNESS (coinbase-only "before"): a tx fed through the SAME
//    connector with NO UTXO view stays fee_known=false, so the fee-sorted
//    selection is EMPTY and the served template carries zero txs — today's
//    exact behaviour, and the baseline the S1 lane lifts.
TEST(MempoolIngest, NoUtxoViewLeavesSelectionEmpty)
{
    Mempool pool(core::coin::DGB_LIMITS);
    dgb::interfaces::Node node;
    auto sub = c2pool::dgb::wire_mempool_ingest(node, pool, /*utxo=*/nullptr);

    node.new_tx.happened(Transaction(spending_tx(/*index=*/0, /*out_value=*/50'000)));
    ASSERT_EQ(pool.size(), 1u);  // the tx IS in the pool (feed works)...

    auto sel = make_mempool_tx_source(pool, /*max_weight=*/4'000'000)();
    EXPECT_EQ(sel.total_fees, 0u);           // ...but its fee is UNKNOWN,
    EXPECT_TRUE(sel.transactions.empty());   // so it is EXCLUDED (coinbase-only).
}

// 7. FEE-PROVED "after": the SAME tx fed through the connector WITH a UTXO view
//    holding its input becomes fee_known, so the fee-sorted selection carries
//    it and total_fees is exact — the fee-bearing template the good-citizen
//    default serves.
TEST(MempoolIngest, UtxoViewFeeProvesTxIntoSelection)
{
    Mempool pool(core::coin::DGB_LIMITS);
    core::coin::UTXOViewCache utxo(nullptr);   // in-memory view (no LevelDB base)
    seed_coin(utxo, /*index=*/0, /*value=*/60'000);  // input worth 60k
    pool.set_utxo(&utxo);                       // selection-time view

    dgb::interfaces::Node node;
    auto sub = c2pool::dgb::wire_mempool_ingest(node, pool, &utxo);  // ingest-time view

    node.new_tx.happened(Transaction(spending_tx(/*index=*/0, /*out_value=*/50'000)));
    ASSERT_EQ(pool.size(), 1u);

    auto sel = make_mempool_tx_source(pool, /*max_weight=*/4'000'000)();
    EXPECT_EQ(sel.total_fees, 10'000u);        // 60k in - 50k out = 10k fee
    ASSERT_TRUE(sel.transactions.is_array());
    ASSERT_EQ(sel.transactions.size(), 1u);    // the tx is SELECTED (fee-bearing)
    EXPECT_EQ(sel.transactions[0]["fee"].get<int64_t>(), 10'000);
    EXPECT_EQ(sel.transactions[0]["txid"], compute_txid(spending_tx(0, 50'000)).GetHex());
}

// 8. Multiple fee-proved txs accumulate and their fees sum into total_fees —
//    the fee total that folds into coinbasevalue.
TEST(MempoolIngest, MultipleFeeProvedTxsSumFees)
{
    Mempool pool(core::coin::DGB_LIMITS);
    core::coin::UTXOViewCache utxo(nullptr);
    seed_coin(utxo, 0, 60'000);   // -> 10k fee
    seed_coin(utxo, 1, 55'000);   // -> 5k  fee
    pool.set_utxo(&utxo);

    dgb::interfaces::Node node;
    auto sub = c2pool::dgb::wire_mempool_ingest(node, pool, &utxo);

    node.new_tx.happened(Transaction(spending_tx(0, 50'000)));
    node.new_tx.happened(Transaction(spending_tx(1, 50'000)));
    ASSERT_EQ(pool.size(), 2u);

    auto sel = make_mempool_tx_source(pool, /*max_weight=*/4'000'000)();
    EXPECT_EQ(sel.total_fees, 15'000u);
    EXPECT_EQ(sel.transactions.size(), 2u);
}

// ===========================================================================
// good_citizen_defaults resolver truth table (pure function).
// ===========================================================================

using dgb::coin::TxServeLever;
using dgb::coin::TxServeLevers;
using dgb::coin::resolve_tx_serve_posture;

// 9a. Operator silent + default OFF (this PR's dormant posture): nothing armed.
TEST(GoodCitizenDefaults, SilentDefaultOffArmsNothing)
{
    auto p = resolve_tx_serve_posture(TxServeLevers{}, /*default_on=*/false);
    EXPECT_FALSE(p.arm_embedded_utxo);
    EXPECT_FALSE(p.arm_serve_mempool_txs);
}

// 9b. Explicit opt-in arms the fee-proof lane even when the default is OFF.
TEST(GoodCitizenDefaults, ExplicitOnArmsUtxoLane)
{
    TxServeLevers lv;
    lv.embedded_utxo.on = true;
    auto p = resolve_tx_serve_posture(lv, /*default_on=*/false);
    EXPECT_TRUE(p.arm_embedded_utxo);
}

// 9c. Operator silent + good-citizen default ON (the S2 posture) arms the lane.
TEST(GoodCitizenDefaults, SilentDefaultOnArmsUtxoLane)
{
    auto p = resolve_tx_serve_posture(TxServeLevers{}, /*default_on=*/true);
    EXPECT_TRUE(p.arm_embedded_utxo);
}

// 9d. Explicit opt-out wins over a good-citizen default ON.
TEST(GoodCitizenDefaults, ExplicitOffWinsOverDefaultOn)
{
    TxServeLevers lv;
    lv.embedded_utxo.explicit_off = true;
    auto p = resolve_tx_serve_posture(lv, /*default_on=*/true);
    EXPECT_FALSE(p.arm_embedded_utxo);
}

// 9e. serve_mempool_txs (S2) is CLAMPED off whenever the fee-proof lane is off:
//     a fee-bearing commit cannot be armed without fee-proved txs behind it.
TEST(GoodCitizenDefaults, ServeClampedWithoutUtxoLane)
{
    TxServeLevers lv;
    lv.serve_mempool_txs.on = true;      // ask to serve...
    lv.embedded_utxo.explicit_off = true; // ...but the fee lane is off.
    auto p = resolve_tx_serve_posture(lv, /*default_on=*/false);
    EXPECT_FALSE(p.arm_embedded_utxo);
    EXPECT_FALSE(p.arm_serve_mempool_txs);  // clamped
}