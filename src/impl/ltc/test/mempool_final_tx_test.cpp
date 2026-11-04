// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded LTC mempool and template take only txs final in the next block
// (litecoind IsFinalTx, consensus/tx_verify.cpp; #2137 S1; rides share_test):
//   - ltc::coin::is_final_tx: nLockTime 0, a height lock at the next height
//     (not final) and one below it (final), a time lock at / below the
//     median time past, the LOCKTIME_THRESHOLD boundary, every input's
//     nSequence final;
//   - admission (CheckFinalTx at the tip's height + 1 and MTP) refuses a
//     non-final tx under non_final, counted; unset (DOGE), nothing changes;
//   - the template's selection takes only txs final at its own height and
//     its parent's MTP (a REAL HeaderChain and TemplateBuilder), and a child
//     of a non-final tx stays out with it;
//   - coinbase maturity: the selection at the template's own height, the
//     admission at the next block's (header tip + 1), never at a lagging
//     pool height (#2136);
//   - priced_changes() moves exactly when admission prices a tx (itself, or
//     a child waiting for it): the transaction-triggered template refresh
//     main_ltc wires on it; admitted_unpriced / still_unknown count the txs
//     a partial view cannot price (/local_stats).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/test/mempool_test_view.hpp>

namespace {

using namespace ltc::coin;

constexpr uint32_t kFinal = 0xffffffff;
constexpr uint32_t kNotFinal = 0xfffffffe;   // e.g. a wallet's anti-fee-sniping tx
constexpr int64_t  kMtp = 1'600'000'000;

uint256 fund(uint32_t n)
{
    uint256 v;
    v.SetHex(std::to_string(0xf000 + n));
    return v;
}

MutableTransaction tx_with(uint32_t locktime, uint32_t sequence, const uint256& prev = fund(0),
                           uint32_t prev_index = 0, int64_t out_value = 99'000)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = locktime;
    TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = prev_index;
    in.sequence = sequence;
    tx.vin.push_back(in);
    TxOut out;
    out.value = out_value;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

BlockHeaderType testnet_genesis()
{
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 293345;
    return g;
}

// Genesis then three headers 150 s apart: tip at height 3, next block 4.
BlockHeaderType grow(HeaderChain& chain)
{
    EXPECT_TRUE(chain.init());
    EXPECT_TRUE(chain.add_header(testnet_genesis()));
    chain.set_peer_tip_height(10'000'000);
    uint256 prev = Hash(pack(testnet_genesis()).get_span());
    BlockHeaderType h;
    for (uint32_t i = 0; i < 3; ++i) {
        h = BlockHeaderType{};
        h.m_version = 0x20000000;
        h.m_previous_block = prev;
        h.m_merkle_root.SetHex(std::to_string(900 + i));
        h.m_timestamp = 1486949366 + 150 * (i + 1);
        h.m_bits = 0x1e0ffff0;
        h.m_nonce = i;
        EXPECT_TRUE(chain.add_header(h));
        prev = Hash(pack(h).get_span());
    }
    EXPECT_EQ(chain.height(), 3u);
    return h;
}

void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

void add_coin(core::coin::UTXOViewCache& view, const uint256& txid, uint32_t index, int64_t value)
{
    core::coin::Coin coin;
    coin.value = value;
    coin.scriptPubKey.m_data = {0x51};
    coin.height = 1;
    view.add_coin(core::coin::Outpoint(txid, index), coin);
}

} // namespace

TEST(LtcMempoolFinalTx, IsFinalTxMatchesLitecoind)
{
    // nLockTime 0: always final.
    EXPECT_TRUE(is_final_tx(tx_with(0, kNotFinal), 1001, kMtp));
    // A height lock: final once the block's height is above it.
    EXPECT_FALSE(is_final_tx(tx_with(1001, kNotFinal), 1001, kMtp)) << "locktime = next height";
    EXPECT_TRUE(is_final_tx(tx_with(1000, kNotFinal), 1001, kMtp)) << "locktime = next height - 1";
    // Every input's nSequence final disables the lock.
    EXPECT_TRUE(is_final_tx(tx_with(5000, kFinal), 1001, kMtp));
    MutableTransaction two = tx_with(5000, kFinal);
    two.vin.push_back(two.vin.front());
    two.vin.back().sequence = kNotFinal;
    EXPECT_FALSE(is_final_tx(two, 1001, kMtp)) << "one input not final keeps the lock";
    // A time lock (>= LOCKTIME_THRESHOLD) is judged against the cutoff time.
    EXPECT_FALSE(is_final_tx(tx_with(static_cast<uint32_t>(kMtp), kNotFinal), 1001, kMtp));
    EXPECT_TRUE(is_final_tx(tx_with(static_cast<uint32_t>(kMtp - 1), kNotFinal), 1001, kMtp));
    // The threshold boundary: 499,999,999 is a height, 500,000,000 a time.
    EXPECT_FALSE(is_final_tx(tx_with(499'999'999, kNotFinal), 1001, kMtp));
    EXPECT_TRUE(is_final_tx(tx_with(500'000'000, kNotFinal), 1001, kMtp));
}

TEST(LtcMempoolFinalTx, AdmissionRefusesNonFinal)
{
    // Unset (DOGE, or before the first tip): no finality check.
    {
        Mempool pool;
        EXPECT_FALSE(pool.admit(tx_with(1001, kNotFinal), nullptr));
        EXPECT_EQ(pool.size(), 1u);
    }
    Mempool pool;
    pool.set_lock_time_cutoff(1001, kMtp);
    EXPECT_EQ(pool.lock_time_cutoff().height, 1001u);

    auto r = pool.admit(tx_with(1001, kNotFinal, fund(1)), nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_final);
    r = pool.admit(tx_with(static_cast<uint32_t>(kMtp), kNotFinal, fund(2)), nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_final);
    EXPECT_EQ(pool.size(), 0u);

    EXPECT_FALSE(pool.admit(tx_with(1000, kNotFinal, fund(3)), nullptr));
    EXPECT_FALSE(pool.admit(tx_with(static_cast<uint32_t>(kMtp - 1), kNotFinal, fund(4)), nullptr));
    EXPECT_FALSE(pool.admit(tx_with(5000, kFinal, fund(5)), nullptr));
    EXPECT_EQ(pool.size(), 3u);

    const auto j = pool.reject_stats_json();
    EXPECT_EQ(j["rejected"]["non_final"], 2);
    EXPECT_EQ(std::string(Mempool::reject_code_name(Mempool::Reject::non_final)), "non_final");

    // The next tip makes the height lock final.
    pool.set_lock_time_cutoff(1002, kMtp);
    EXPECT_FALSE(pool.admit(tx_with(1001, kNotFinal, fund(1)), nullptr));
}

// The template's own block: next height 4, cutoff = the tip's MTP. A tx
// locked to height 4 stays out (and its child with it); one locked to 3
// ships. The pool took them past admission (a reorg lowered the next height).
TEST(LtcMempoolFinalTx, TemplateSelectsOnlyTxsFinalInItsBlock)
{
    HeaderChain chain(make_ltc_chain_params_testnet());
    const BlockHeaderType tip = grow(chain);
    Mempool pool;
    const MutableTransaction locked = tx_with(4, kNotFinal, fund(1));
    const MutableTransaction child = tx_with(0, kFinal, compute_txid(locked), 0, 98'000);
    const MutableTransaction ok = tx_with(3, kNotFinal, fund(2));
    ASSERT_TRUE(pool.add_tx_unchecked(locked));
    ASSERT_TRUE(pool.add_tx_unchecked(child));
    ASSERT_TRUE(pool.add_tx_unchecked(ok));
    pool.set_tx_fee(compute_txid(locked), 1'000);
    pool.set_tx_fee(compute_txid(child), 5'000);
    pool.set_tx_fee(compute_txid(ok), 2'000);
    ltc_test::CoveringView view;
    view.cover(pool);
    clean_for(pool, tip);

    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/true);
    ASSERT_TRUE(wd);
    const auto& txs = wd->m_data["transactions"];
    ASSERT_EQ(txs.size(), 1u);
    EXPECT_EQ(txs[0]["txid"].get<std::string>(), compute_txid(ok).GetHex());
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(4)) + 2'000);

    // Without a cutoff the selection is unchanged (other callers).
    auto [sel, fees] = pool.get_sorted_txs_with_fees(TemplateBuilder::MAX_BLOCK_WEIGHT);
    EXPECT_EQ(sel.size(), 3u);
    EXPECT_EQ(fees, 8'000u);
}

// priced_changes() moves when admission prices a tx, or a child waiting for
// it, and not for a tx the partial view cannot price; those are counted.
TEST(LtcMempoolFinalTx, PricedChangesDriveTheTxRefresh)
{
    Mempool pool;
    core::coin::UTXOViewCache view(nullptr);  // in memory: a partial view
    add_coin(view, fund(1), 0, 100'000);
    add_coin(view, fund(2), 0, 100'000);
    pool.set_utxo(&view);

    uint64_t seq = pool.priced_changes();
    ASSERT_FALSE(pool.admit(tx_with(0, kFinal, fund(1)), &view));
    EXPECT_EQ(pool.priced_changes(), seq + 1) << "admitted priced";

    // A child admitted before its parent: unpriced, no refresh.
    const MutableTransaction parent = tx_with(0, kFinal, fund(2), 0, 90'000);
    const MutableTransaction child = tx_with(0, kFinal, compute_txid(parent), 0, 80'000);
    seq = pool.priced_changes();
    ASSERT_FALSE(pool.admit(child, &view));
    EXPECT_EQ(pool.priced_changes(), seq);
    auto j = pool.reject_stats_json();
    EXPECT_EQ(j["admitted_unpriced"], 1);
    EXPECT_EQ(j["still_unknown"], 1);

    // The parent: priced, and it prices the child.
    ASSERT_FALSE(pool.admit(parent, &view));
    EXPECT_EQ(pool.priced_changes(), seq + 2);
    j = pool.reject_stats_json();
    EXPECT_EQ(j["still_unknown"], 0);
    EXPECT_EQ(j["admitted_unpriced"], 1);

    // A refused tx moves nothing.
    seq = pool.priced_changes();
    EXPECT_TRUE(pool.admit(tx_with(0, kFinal, fund(1)), &view)) << "duplicate";
    EXPECT_EQ(pool.priced_changes(), seq);
}

namespace {

core::coin::Coin coinbase_at(uint32_t height)
{
    core::coin::Coin cb;
    cb.value = 50'000'000;
    cb.scriptPubKey.m_data = {0x51};
    cb.height = height;
    cb.coinbase = true;
    return cb;
}

} // namespace

// The selection judges coinbase maturity at the template's own height (Core
// GetSpendHeight), not at the pool's height + 1: the pool's height follows
// the UTXO view and stays above the template's after a reorg onto a lower
// branch. The verifier's VerifyS0.SelectionMaturityIgnoresTheTemplateHeight,
// inverted: pool height 106, a block at 105 spending a coinbase from height
// 6 (mature from 106) is bad-txns-premature-spend-of-coinbase.
TEST(LtcMempoolFinalTx, SelectionJudgesCoinbaseMaturityAtTheTemplateHeight)
{
    Mempool pool;
    core::coin::UTXOViewCache view(nullptr);
    view.add_coin(core::coin::Outpoint(fund(9), 0), coinbase_at(6));
    pool.set_utxo(&view);
    pool.set_tip_height(106);
    const MutableTransaction t = tx_with(0, kFinal, fund(9), 0, 49'000'000);
    ASSERT_FALSE(pool.admit(t, &view));
    const auto at105 = pool.get_sorted_txs_with_fees(TemplateBuilder::MAX_BLOCK_WEIGHT, LockTimeCutoff{105, 0});
    EXPECT_EQ(at105.first.size(), 0u) << "immature in a block at height 105";
    const auto at106 = pool.get_sorted_txs_with_fees(TemplateBuilder::MAX_BLOCK_WEIGHT, LockTimeCutoff{106, 0});
    EXPECT_EQ(at106.first.size(), 1u) << "mature in a block at height 106";
}

// Admission judges maturity at the next block's height (the header tip + 1,
// set_lock_time_cutoff), not at the UTXO view's height + 1: during a fill the
// view lags the tip, and a spend that matures in between was refused
// inputs_invalid and erased for good. Unset (DOGE), the pool's height + 1.
TEST(LtcMempoolFinalTx, AdmissionJudgesMaturityAtTheNextBlock)
{
    core::coin::UTXOViewCache view(nullptr);
    view.add_coin(core::coin::Outpoint(fund(9), 0), coinbase_at(6));
    const MutableTransaction t = tx_with(0, kFinal, fund(9), 0, 49'000'000);
    {
        Mempool pool;
        pool.set_utxo(&view);
        pool.set_tip_height(100);            // the view, mid-fill
        pool.set_lock_time_cutoff(106, kMtp);  // the header tip is 105
        EXPECT_FALSE(pool.admit(t, &view)) << "spendable in the next block";
        EXPECT_EQ(pool.size(), 1u);
    }
    {
        Mempool pool;
        pool.set_utxo(&view);
        pool.set_tip_height(100);
        pool.set_lock_time_cutoff(105, kMtp);
        auto r = pool.admit(t, &view);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Mempool::Reject::inputs_invalid) << "premature in the next block";
    }
    {
        Mempool pool;  // no cutoff: the pool's height + 1
        pool.set_utxo(&view);
        pool.set_tip_height(105);
        EXPECT_FALSE(pool.admit(t, &view));
    }
}
