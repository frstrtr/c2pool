// ---------------------------------------------------------------------------
// dgb_embedded_tx_select_test -- pins make_mempool_tx_source (embedded_tx_select.cpp),
// the production shaper that turns the embedded Mempool's fee-sorted selection
// into the GBT transactions[] form build_work_template passes through.
//
// CONFORMANCE (frstrtr/p2pool-dgb-scrypt): the per-tx entry shape
// {data,txid,hash,fee} and the total_fees fold are exactly what p2pool's GBT
// consumer reads -- `data` is the with-witness submit bytes, `txid` the legacy
// sha256d, `hash` the wtxid for the witness merkle tree, `fee` the per-tx fee
// (null when unknown). The coinbasevalue fold (subsidy(h)+total_fees) is
// asserted in dgb_embedded_coin_node_test against the #207 SSOT; here we pin
// the byte-level shaping the .cpp does over a real Mempool.
//
// Links the full dgb_coin codec like dgb_embedded_coin_node_test (it compiles
// the tx serialization). MUST be in BOTH build.yml --target allowlists (#143
// NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/embedded_tx_select.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/transaction.hpp>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <btclibs/util/strencodings.h>

using dgb::coin::Mempool;
using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::TX_WITH_WITNESS;
using dgb::coin::compute_txid;
using dgb::coin::make_mempool_tx_source;

namespace {

// A minimal, distinct tx tagged by its output value (mirrors the builder used
// across the dgb won-block tests). `index` keeps the prevout distinct so each
// tx has a distinct txid.
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

// Expected GBT entry shape for a tx, computed independently of the shaper.
nlohmann::json expect_entry(const MutableTransaction& tx, int64_t fee)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    nlohmann::json e;
    e["data"] = HexStr(packed.get_span());
    e["txid"] = compute_txid(tx).GetHex();
    e["hash"] = Hash(packed.get_span()).GetHex();
    e["fee"]  = fee;
    return e;
}

} // namespace

// Two fee-known txs: total_fees == sum, entries shaped {data,txid,hash,fee}.
TEST(DgbEmbeddedTxSelect, ShapesKnownFeeTxsAndSumsFees)
{
    Mempool pool;
    MutableTransaction a = tagged_tx(10, 0);
    MutableTransaction b = tagged_tx(20, 1);
    ASSERT_TRUE(pool.add_tx(a));
    ASSERT_TRUE(pool.add_tx(b));
    pool.set_tx_fee(compute_txid(a), 700);
    pool.set_tx_fee(compute_txid(b), 300);

    auto source = make_mempool_tx_source(pool, /*max_weight=*/4'000'000);
    const auto sel = source();

    EXPECT_EQ(sel.total_fees, 1000u);                 // 700 + 300
    ASSERT_TRUE(sel.transactions.is_array());
    EXPECT_EQ(sel.transactions.size(), 2u);

    // Each selected tx must carry the exact independently-computed entry. The
    // selection is feerate-sorted, so match by txid rather than position.
    for (const auto& want : {expect_entry(a, 700), expect_entry(b, 300)})
    {
        bool found = false;
        for (const auto& got : sel.transactions)
            if (got["txid"] == want["txid"]) { EXPECT_EQ(got, want); found = true; }
        EXPECT_TRUE(found) << "missing txid " << want["txid"];
    }
}

// Empty mempool -> empty transactions[] + zero fees (truthful absence).
TEST(DgbEmbeddedTxSelect, EmptyPoolEmptySelection)
{
    Mempool pool;
    auto source = make_mempool_tx_source(pool, /*max_weight=*/4'000'000);
    const auto sel = source();
    EXPECT_EQ(sel.total_fees, 0u);
    ASSERT_TRUE(sel.transactions.is_array());
    EXPECT_TRUE(sel.transactions.empty());
}

// Unknown-fee txs are excluded from the template (get_sorted_txs_with_fees
// only emits fee-known txs -- including fee=0 would desync coinbasevalue vs the
// p2pool/daemon GBT figure). So a pool with only unknown-fee txs selects none.
TEST(DgbEmbeddedTxSelect, UnknownFeeTxExcluded)
{
    Mempool pool;
    ASSERT_TRUE(pool.add_tx(tagged_tx(10, 0)));   // no set_tx_fee -> fee_known=false
    auto source = make_mempool_tx_source(pool, /*max_weight=*/4'000'000);
    const auto sel = source();
    EXPECT_EQ(sel.total_fees, 0u);
    EXPECT_TRUE(sel.transactions.empty());
}

// ---------------------------------------------------------------------------
// CONFORMANCE: selection ORDER + weight-cap skip semantics.
//
// p2pool consumes the daemon GBT transactions[] in the order Core emits it --
// ancestor-feerate descending (CreateNewBlock). The embedded shaper must emit
// the same ordering so the share's tx set and any p2pool-side fee accounting
// line up. get_sorted_txs_with_fees walks m_feerate_index, a
// std::multimap<double,uint256,std::greater<double>> -> highest feerate first.
// These pin that ordering and the weight-cap skip (a `continue`, NOT a `break`:
// a high-feerate tx that overflows the cap is skipped while a lighter,
// lower-feerate tx further down can still be packed).
// ---------------------------------------------------------------------------

namespace {

// A tx with `n` outputs (each tagged distinct via index), to vary weight.
MutableTransaction wide_tx(uint32_t index, int n_outputs)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    for (int i = 0; i < n_outputs; ++i) {
        TxOut out;
        out.value = 1000 + i;
        tx.vout.push_back(out);
    }
    return tx;
}

uint32_t tx_weight(const MutableTransaction& tx)
{
    uint32_t base = 0, wit = 0, weight = 0;
    dgb::coin::compute_tx_weight(tx, base, wit, weight);
    return weight;
}

} // namespace

// transactions[] are emitted highest-feerate-first (equal weight -> by fee).
TEST(DgbEmbeddedTxSelect, EmitsFeerateDescendingOrder)
{
    Mempool pool;
    MutableTransaction lo  = tagged_tx(10, 0);   // fee 300 -> lowest feerate
    MutableTransaction mid = tagged_tx(20, 1);   // fee 600
    MutableTransaction hi  = tagged_tx(30, 2);   // fee 900 -> highest feerate
    // Insert out of feerate order to prove the index, not arrival, drives order.
    ASSERT_TRUE(pool.add_tx(mid));
    ASSERT_TRUE(pool.add_tx(lo));
    ASSERT_TRUE(pool.add_tx(hi));
    pool.set_tx_fee(compute_txid(lo),  300);
    pool.set_tx_fee(compute_txid(mid), 600);
    pool.set_tx_fee(compute_txid(hi),  900);

    auto source = make_mempool_tx_source(pool, /*max_weight=*/4'000'000);
    const auto sel = source();

    ASSERT_EQ(sel.transactions.size(), 3u);
    EXPECT_EQ(sel.transactions[0]["txid"], compute_txid(hi).GetHex());
    EXPECT_EQ(sel.transactions[1]["txid"], compute_txid(mid).GetHex());
    EXPECT_EQ(sel.transactions[2]["txid"], compute_txid(lo).GetHex());
    EXPECT_EQ(sel.total_fees, 1800u);
}

// Weight cap skips an over-cap high-feerate tx but still packs a lighter one
// below it (skip-not-break). total_fees reflects only the packed tx.
TEST(DgbEmbeddedTxSelect, WeightCapSkipsHeavyButPacksLighter)
{
    Mempool pool;
    MutableTransaction heavy = wide_tx(0, /*n_outputs=*/40);  // large weight
    MutableTransaction light = tagged_tx(50, 1);              // single output
    ASSERT_TRUE(pool.add_tx(heavy));
    ASSERT_TRUE(pool.add_tx(light));
    pool.set_tx_fee(compute_txid(heavy), 10'000'000);  // huge fee -> top feerate
    pool.set_tx_fee(compute_txid(light), 100);         // low feerate, low weight

    const uint32_t w_heavy = tx_weight(heavy);
    const uint32_t w_light = tx_weight(light);
    ASSERT_GT(w_heavy, w_light) << "test needs heavy strictly heavier than light";

    // Cap exactly fits `light` but not `heavy`: heavy is first (top feerate),
    // overflows -> skipped; light follows and fits.
    auto source = make_mempool_tx_source(pool, /*max_weight=*/w_light);
    const auto sel = source();

    ASSERT_EQ(sel.transactions.size(), 1u);
    EXPECT_EQ(sel.transactions[0]["txid"], compute_txid(light).GetHex());
    EXPECT_EQ(sel.total_fees, 100u);
}
