// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// /local_stats "ltc_utxo" (ltc::coin::utxo_view_json, #2137; rides
// share_test): the depth of the UTXO view the embedded LTC template prices
// against and the mempool counters of what it cannot price, over a REAL
// UTXOViewCache/UTXOViewDB and Mempool:
//   - no set: nothing known, complete false;
//   - an accrual set (no sync state): the anchor this process observed
//     (a cold start into an empty set), else unknown -- never a guess;
//   - a set with a sync state: its anchor, depth best - anchor + 1, complete
//     only when its best block is the chain's tip;
//   - missing_inputs / inputs_invalid / admitted_unpriced / still_unknown
//     follow admission.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>

#include <core/uint256.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/utxo_view_stats.hpp>

namespace {

using namespace ltc::coin;

uint256 hx(uint32_t n)
{
    uint256 v;
    v.SetHex(std::to_string(0xa000 + n));
    return v;
}

struct View {
    std::filesystem::path dir;
    std::unique_ptr<core::coin::UTXOViewDB> db;
    std::unique_ptr<core::coin::UTXOViewCache> cache;
    View()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_utxo_view_stats_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::coin::UTXOViewDB>(dir.string());
        EXPECT_TRUE(db->open());
        cache = std::make_unique<core::coin::UTXOViewCache>(db.get());
    }
    ~View()
    {
        cache.reset();
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    void coin(const uint256& txid, uint32_t index, int64_t value)
    {
        core::coin::Coin c;
        c.value = value;
        c.scriptPubKey.m_data = {0x51};
        c.height = 1;
        cache->add_coin(core::coin::Outpoint(txid, index), c);
    }
};

MutableTransaction spend(const uint256& prev, int64_t out_value)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = out_value;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

} // namespace

TEST(LtcUtxoViewStats, NoSetKnowsNothing)
{
    Mempool pool;
    const auto j = utxo_view_json(nullptr, 0, 100, hx(100), &pool);
    EXPECT_TRUE(j["anchor_height"].is_null());
    EXPECT_EQ(j["anchor_source"], "unknown");
    EXPECT_TRUE(j["depth"].is_null());
    EXPECT_EQ(j["complete"], false);
    EXPECT_EQ(j["best_height"], 0);
    EXPECT_EQ(j["missing_inputs"], 0);
    EXPECT_EQ(j["inputs_invalid"], 0);
    EXPECT_EQ(j["still_unknown"], 0);
}

// An accrual set records no anchor: the one this process observed, else null.
TEST(LtcUtxoViewStats, AccrualSetAnchorIsObservedOrUnknown)
{
    View v;
    ASSERT_TRUE(v.cache->flush(hx(150), 150));
    auto j = utxo_view_json(v.cache.get(), 0, 150, hx(150), nullptr);
    EXPECT_TRUE(j["anchor_height"].is_null()) << "loaded from disk: unknown, not guessed";
    EXPECT_EQ(j["anchor_source"], "unknown");
    EXPECT_EQ(j["best_height"], 150);
    EXPECT_EQ(j["best_block"], hx(150).GetHex());
    EXPECT_EQ(j["complete"], false) << "an accrual set is never complete";
    EXPECT_FALSE(j.contains("still_unknown")) << "no pool, no pool counters";

    j = utxo_view_json(v.cache.get(), 100, 150, hx(150), nullptr);
    EXPECT_EQ(j["anchor_height"], 100);
    EXPECT_EQ(j["anchor_source"], "observed");
    EXPECT_EQ(j["depth"], 51);

    // An observation above the set's best (it was wiped since) is not used.
    j = utxo_view_json(v.cache.get(), 200, 150, hx(150), nullptr);
    EXPECT_TRUE(j["anchor_height"].is_null());
}

// A set with a sync state: its own anchor; built from genesis it is complete
// only at the chain's tip.
TEST(LtcUtxoViewStats, SyncStateAnchorAndComplete)
{
    View v;
    ASSERT_TRUE(v.cache->flush(hx(150), 150));
    core::coin::SyncState ss;
    ss.anchor_height = 0;
    ASSERT_TRUE(v.cache->set_sync_state(ss));
    auto j = utxo_view_json(v.cache.get(), 100, 150, hx(150), nullptr);
    EXPECT_EQ(j["anchor_height"], 0);
    EXPECT_EQ(j["anchor_source"], "sync_state");
    EXPECT_EQ(j["depth"], 151);
    EXPECT_EQ(j["complete"], true);
    j = utxo_view_json(v.cache.get(), 0, 151, hx(151), nullptr);
    EXPECT_EQ(j["complete"], false) << "the tip moved on";
    j = utxo_view_json(v.cache.get(), 0, 150, hx(999), nullptr);
    EXPECT_EQ(j["complete"], false) << "a sibling of the tip is not the tip's set";
}

// The admission counters: a full set refuses a missing input (an orphan) and
// an invalid one; a partial set admits a missing input fee-unknown.
TEST(LtcUtxoViewStats, AdmissionCounters)
{
    {
        View full;
        full.coin(hx(1), 0, 1'000);
        ASSERT_TRUE(full.cache->flush(hx(150), 150));
        core::coin::SyncState ss;
        ss.anchor_height = 0;
        ASSERT_TRUE(full.cache->set_sync_state(ss));
        Mempool pool;
        pool.set_utxo(full.cache.get());
        auto r = pool.admit(spend(hx(2), 500), full.cache.get());
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Mempool::Reject::missing_inputs);
        r = pool.admit(spend(hx(1), 2'000), full.cache.get());
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Mempool::Reject::inputs_invalid) << "outputs above inputs";
        const auto j = utxo_view_json(full.cache.get(), 0, 150, hx(150), &pool);
        EXPECT_EQ(j["missing_inputs"], 1);
        EXPECT_EQ(j["inputs_invalid"], 1);
        EXPECT_EQ(j["admitted_unpriced"], 0);
        EXPECT_EQ(j["still_unknown"], 0);
    }
    {
        View partial;
        partial.coin(hx(1), 0, 1'000);
        ASSERT_TRUE(partial.cache->flush(hx(150), 150));
        Mempool pool;
        pool.set_utxo(partial.cache.get());
        EXPECT_FALSE(pool.admit(spend(hx(2), 500), partial.cache.get())) << "admitted fee-unknown";
        EXPECT_FALSE(pool.admit(spend(hx(1), 900), partial.cache.get())) << "priced";
        const auto j = utxo_view_json(partial.cache.get(), 0, 150, hx(150), &pool);
        EXPECT_EQ(j["missing_inputs"], 0) << "a partial view cannot tell missing from old";
        EXPECT_EQ(j["admitted_unpriced"], 1);
        EXPECT_EQ(j["still_unknown"], 1);
    }
}
