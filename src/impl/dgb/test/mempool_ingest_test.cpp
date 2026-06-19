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
