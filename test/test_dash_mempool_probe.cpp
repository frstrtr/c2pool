// SPDX-License-Identifier: AGPL-3.0-or-later
// GET /mempool_entry: Mempool::probe + mempool_probe_json.
//
// The fee-parity shadow comparator asks the node about every tx dashd mined
// and we did not. These tests pin each answer the probe can give, against the
// same pool states compute_fee_locked sees: a priced candidate, an input no
// coin source holds (the "coin older than our UTXO view" class), an input that
// became resolvable but waits for recompute_unknown_fees, a CPFP parent in the
// pool (and a vout index past its outputs), and a tx we never had. The probe
// must change nothing: a read of an unpriced entry leaves it unpriced.

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/mempool_probe_json.hpp>

#include <core/coin/utxo_view_cache.hpp>
#include <core/uint256.hpp>

using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using dash::coin::mempool_probe_json;
using dash::coin::mempool_probe_reason;
using ::core::coin::Coin;
using ::core::coin::Outpoint;
using ::core::coin::UTXOViewCache;

namespace {

uint256 seed_hash(uint32_t seed)
{
    MutableTransaction t;
    t.version  = 1;
    t.type     = 0;
    t.locktime = 0x52000000u ^ seed;
    auto ps = ::pack(t);
    return ::Hash(ps.get_span());
}

MutableTransaction spend(const uint256& prev, uint32_t index, int64_t out_value, uint32_t salt,
                         uint32_t n_outputs = 1)
{
    MutableTransaction tx;
    tx.version  = 1;
    tx.type     = 0;
    tx.locktime = salt;
    ::bitcoin_family::coin::TxIn in;
    in.prevout.hash  = prev;
    in.prevout.index = index;
    in.sequence      = 0xffffffffu;
    tx.vin.push_back(in);
    for (uint32_t i = 0; i < n_outputs; ++i) {
        ::bitcoin_family::coin::TxOut out;
        out.value = out_value;
        tx.vout.push_back(out);
    }
    return tx;
}

} // namespace

TEST(DashMempoolProbe, NotInPool)
{
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    const auto p = mp.probe(seed_hash(1));
    EXPECT_FALSE(p.in_pool);
    EXPECT_TRUE(p.utxo_view);
    EXPECT_FALSE(p.fold_live);
    EXPECT_FALSE(p.fee_coin_lookup);
    EXPECT_STREQ(mempool_probe_reason(p), "not-in-pool");
    const auto j = mempool_probe_json(seed_hash(1), p);
    EXPECT_FALSE(j.at("in_pool").get<bool>());
    EXPECT_FALSE(j.contains("fee"));
}

TEST(DashMempoolProbe, PricedFromTheUtxoViewIsACandidate)
{
    UTXOViewCache utxo(nullptr);
    const uint256 prev = seed_hash(2);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));
    Mempool mp;
    mp.set_utxo(&utxo);
    const auto tx = spend(prev, 0, 90'000, 1);
    ASSERT_TRUE(mp.add_tx(tx));
    const auto p = mp.probe(dash_txid(tx));
    EXPECT_TRUE(p.in_pool);
    EXPECT_TRUE(p.fee_known);
    EXPECT_TRUE(p.fee_fold_proven);
    EXPECT_TRUE(p.in_feerate_index);
    EXPECT_EQ(p.fee, 10'000u);
    EXPECT_EQ(p.n_vin, 1u);
    EXPECT_EQ(p.n_vin_unresolved, 0u);
    EXPECT_GT(p.time_added, 0);
    EXPECT_STREQ(mempool_probe_reason(p), "candidate");
}

// The E2 class: a coin older than the node's UTXO view, in no other source.
TEST(DashMempoolProbe, InputInNoCoinSourceNamesTheOutpoint)
{
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    const uint256 old_coin_tx = seed_hash(3);
    const auto tx = spend(old_coin_tx, 7, 50'000, 2);
    ASSERT_TRUE(mp.add_tx(tx));
    const auto p = mp.probe(dash_txid(tx));
    EXPECT_TRUE(p.in_pool);
    EXPECT_FALSE(p.fee_known);
    EXPECT_FALSE(p.fee_fold_proven);
    EXPECT_FALSE(p.in_feerate_index);
    EXPECT_EQ(p.n_vin_unresolved, 1u);
    EXPECT_EQ(p.first_unresolved_vin, 0u);
    EXPECT_EQ(p.first_unresolved_hash, old_coin_tx);
    EXPECT_EQ(p.first_unresolved_index, 7u);
    EXPECT_FALSE(p.first_unresolved_parent_in_pool);
    EXPECT_STREQ(mempool_probe_reason(p), "input-not-in-any-coin-source");
    const auto j = mempool_probe_json(dash_txid(tx), p);
    EXPECT_EQ(j.at("reason").get<std::string>(), "input-not-in-any-coin-source");
    EXPECT_EQ(j.at("first_unresolved").at("prevout_hash").get<std::string>(), old_coin_tx.GetHex());
    EXPECT_EQ(j.at("first_unresolved").at("prevout_index").get<uint32_t>(), 7u);
}

// The coin arrives later; the entry stays unpriced until
// recompute_unknown_fees runs (today: on block connect only). The probe sees
// that gap and does not close it itself.
TEST(DashMempoolProbe, ResolvableInputWaitsForRecomputeAndProbeChangesNothing)
{
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    const uint256 prev = seed_hash(4);
    const auto tx = spend(prev, 0, 80'000, 3);
    ASSERT_TRUE(mp.add_tx(tx));
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    const auto p = mp.probe(dash_txid(tx));
    EXPECT_FALSE(p.fee_known);
    EXPECT_EQ(p.n_vin_unresolved, 0u);
    EXPECT_STREQ(mempool_probe_reason(p), "fee-unknown-inputs-resolvable");
    EXPECT_FALSE(mp.get_entry(dash_txid(tx))->fee_known) << "the probe must not price the entry";

    ASSERT_EQ(mp.recompute_unknown_fees(&utxo), 1);
    EXPECT_STREQ(mempool_probe_reason(mp.probe(dash_txid(tx))), "candidate");
}

TEST(DashMempoolProbe, CpfpParentInPoolPricesTheChildButNotAMissingVout)
{
    UTXOViewCache utxo(nullptr);
    const uint256 funding = seed_hash(5);
    utxo.add_coin(Outpoint(funding, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    mp.set_utxo(&utxo);
    const auto parent = spend(funding, 0, 45'000, 4, /*n_outputs=*/2);
    ASSERT_TRUE(mp.add_tx(parent));
    const uint256 parent_id = dash_txid(parent);

    const auto child = spend(parent_id, 1, 40'000, 5);
    ASSERT_TRUE(mp.add_tx(child));
    EXPECT_STREQ(mempool_probe_reason(mp.probe(dash_txid(child))), "candidate");

    const auto bad_child = spend(parent_id, 5, 40'000, 6);   // parent has 2 outputs
    ASSERT_TRUE(mp.add_tx(bad_child));
    const auto p = mp.probe(dash_txid(bad_child));
    EXPECT_EQ(p.n_vin_unresolved, 1u);
    EXPECT_TRUE(p.first_unresolved_parent_in_pool);
    EXPECT_STREQ(mempool_probe_reason(p), "parent-in-pool-output-missing");
}
