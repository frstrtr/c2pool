// KATs for core::coin set hashes (src/core/coin/utxo_set_hash.{hpp,cpp}):
// TxOutSer bytes, muhash and hash_serialized_2 over a coin stream and over a
// real UTXOViewDB, against an independent reference (utxo_kat_fixture.hpp).

#include "utxo_kat_fixture.hpp"

#include <core/coin/coin_compressor.hpp>
#include <core/coin/utxo_set_hash.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/leveldb_store.hpp>

#include <btclibs/crypto/common.h>

#include <gtest/gtest.h>

#include <random>

using namespace core::coin;
using namespace utxo_kat;

namespace {

/// Write `coins` into a fresh UTXOViewDB through its own write_batch.
void build_view_db(const std::string& dir, const std::vector<KatCoin>& coins, const uint256& best, uint32_t height)
{
    UTXOViewDB db(dir);
    ASSERT_TRUE(db.open());
    UTXOViewDB::ChangeMap changes;
    for (const auto& k : coins) changes[k.op] = k.coin;
    ASSERT_TRUE(db.write_batch(changes, best, height));
    db.close();
}

std::optional<UtxoSetHashes> feed(const std::vector<KatCoin>& coins, const uint256& best, std::string* refusal = nullptr)
{
    UtxoSetHasher h(best);
    for (const auto& k : coins) {
        if (!h.add(k.op, k.coin)) {
            if (refusal) *refusal = h.refusal();
            return std::nullopt;
        }
    }
    return h.finalize();
}

} // namespace

TEST(UtxoSetHash, TxOutSerLayout)
{
    // kernel/coinstats.cpp TxOutSer: outpoint, u32 LE height*2+coinbase, CTxOut.
    Coin c(100001000, OPScript(), 2542518, false);
    c.scriptPubKey.m_data = hex("76a9143a3b7b6c89a099c64fbc24b2c1d9ceddcbffec5488ac");
    Outpoint op;
    std::memcpy(op.txid.data(), hex("000008879aa1eb4c85423c7e1939d8726721c147485858b891813803f647de27").data(), 32);
    op.index = 1;
    std::vector<unsigned char> b;
    TxOutSer(b, op, c);
    EXPECT_EQ(to_hex(b),
              "000008879aa1eb4c85423c7e1939d8726721c147485858b891813803f647de27"
              "01000000" "6c974d00" "e8e4f50500000000"
              "19" "76a9143a3b7b6c89a099c64fbc24b2c1d9ceddcbffec5488ac");
}

TEST(UtxoSetHash, StreamMatchesIndependentReference)
{
    const auto coins = synthetic_set();
    ASSERT_EQ(coins.size(), 307u);
    const auto best = syn_best();
    ASSERT_EQ(best.GetHex(), kSynBestHex);
    auto r = feed(coins, best);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->muhash.GetHex(), kSynMuhash);
    EXPECT_EQ(r->hash_serialized_2.GetHex(), kSynHashSer2);
    EXPECT_EQ(r->coins, 307u);
    EXPECT_EQ(r->tx_groups, 5u);
    EXPECT_EQ(r->zero_value_coins, 1u);
    EXPECT_EQ(r->empty_script_coins, 1u);

    // Inside a group any order: shuffle every group's outputs.
    auto shuffled = coins;
    std::mt19937 rng(7);
    for (size_t i = 0; i < shuffled.size();) {
        size_t j = i;
        while (j < shuffled.size() && shuffled[j].op.txid == shuffled[i].op.txid) ++j;
        std::shuffle(shuffled.begin() + i, shuffled.begin() + j, rng);
        i = j;
    }
    auto r2 = feed(shuffled, best);
    ASSERT_TRUE(r2);
    EXPECT_EQ(r2->muhash, r->muhash);
    EXPECT_EQ(r2->hash_serialized_2, r->hash_serialized_2);

    // Only one of the two hashes when asked.
    UtxoSetHasher only_mu(best, UtxoSetHasher::Options{true, false});
    for (const auto& k : coins) ASSERT_TRUE(only_mu.add(k.op, k.coin));
    auto r3 = only_mu.finalize();
    ASSERT_TRUE(r3);
    EXPECT_TRUE(r3->have_muhash);
    EXPECT_FALSE(r3->have_hash_serialized_2);
    EXPECT_EQ(r3->muhash.GetHex(), kSynMuhash);
}

TEST(UtxoSetHash, RefusesUnorderedGroupsAndDuplicates)
{
    const auto coins = synthetic_set();
    const auto best = syn_best();
    // A group that comes back after a later txid.
    auto unordered = coins;
    std::swap(unordered.front(), unordered.back());
    std::string why;
    EXPECT_FALSE(feed(unordered, best, &why));
    EXPECT_NE(why.find("utxo-set-unordered"), std::string::npos) << why;
    // A repeated outpoint.
    auto dup = coins;
    dup.insert(dup.begin() + 1, dup.front());
    why.clear();
    EXPECT_FALSE(feed(dup, best, &why));
    EXPECT_NE(why.find("utxo-set-duplicate-outpoint"), std::string::npos) << why;
}

TEST(UtxoSetHash, GroupCodeIsTernaryQuirkLiteralOne)
{
    // dashd v23.1.x ApplyHash: VARINT(nHeight * 2 + fCoinBase ? 1u : 0u) folds
    // the literal 1, so moving every height leaves hash_serialized_2 alone;
    // muhash carries the height and moves.
    const auto best = syn_best();
    auto r = feed(synthetic_set(1), best);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->hash_serialized_2.GetHex(), kSynHashSer2);
    EXPECT_EQ(r->muhash.GetHex(), kSynMuhashHeightsPlus1);
}

TEST(UtxoSetHash, EmptySetIsHashOfBestBlockOnly)
{
    auto r = feed({}, syn_best());
    ASSERT_TRUE(r);
    EXPECT_EQ(r->coins, 0u);
    EXPECT_EQ(r->hash_serialized_2.GetHex(), kEmptyHashSer2);
    EXPECT_EQ(r->muhash.GetHex(), kEmptyMuhash);
}

TEST(UtxoSetHash, HashSerialized2OverViewDbEqualsW3Stream)
{
    // The W3 fold (impl/dash/coin/replay_utxo_fold.hpp hash_serialized_2)
    // scans the same 'C' + txid + vout LE layout, groups per txid into an
    // ascending-vout map and folds apply_hash_group seeded with the best
    // block. The free function over a real UTXOViewDB must give the
    // reference value for that stream, including a 300-output txid whose LE
    // vout keys do not sort numerically.
    utxo_kat::TempDir tmp("sethash");
    const auto coins = synthetic_set();
    const auto best = syn_best();
    build_view_db(tmp.path(), coins, best, 4242);

    core::LevelDBStore store(tmp.path(), core::LevelDBOptions{});
    ASSERT_TRUE(store.open());
    std::string refusal;
    auto r = hash_utxo_view_db(store, UtxoSetHasher::Options{}, refusal);
    ASSERT_TRUE(r) << refusal;
    EXPECT_EQ(r->best_height, 4242u);
    EXPECT_EQ(r->hashes.best_block, best);
    EXPECT_EQ(r->hashes.coins, 307u);
    EXPECT_EQ(r->hashes.tx_groups, 5u);
    EXPECT_EQ(r->hashes.hash_serialized_2.GetHex(), kSynHashSer2);
    EXPECT_EQ(r->hashes.muhash.GetHex(), kSynMuhash);

    // A malformed 'C' value is refused, never skipped.
    {
        auto b = store.create_batch();
        b.put(view_db_coin_key(coins[5].op), std::vector<uint8_t>{0x80});
        ASSERT_TRUE(b.commit());
    }
    refusal.clear();
    EXPECT_FALSE(hash_utxo_view_db(store, UtxoSetHasher::Options{}, refusal));
    EXPECT_NE(refusal.find("utxo-view-db-bad-coin"), std::string::npos) << refusal;
    store.close();
}

TEST(UtxoSetHash, ViewDbWithoutBestBlockIsRefused)
{
    utxo_kat::TempDir tmp("nobest");
    core::LevelDBStore store(tmp.path(), core::LevelDBOptions{});
    ASSERT_TRUE(store.open());
    std::string refusal;
    EXPECT_FALSE(hash_utxo_view_db(store, UtxoSetHasher::Options{}, refusal));
    EXPECT_EQ(refusal, "utxo-view-db-no-best-block");
}

TEST(UtxoSetHash, RealCoinsMatchIndependentReference)
{
    std::vector<KatCoin> coins;
    for (const char* c : kRealCoinBytes) {
        const auto b = hex(c);
        KatCoin k;
        std::memcpy(k.op.txid.data(), b.data(), 32);
        k.op.index = ReadLE32(b.data() + 32);
        SpanStream s{b.data() + 36, b.size() - 36};
        ASSERT_EQ(UnserializeCoreCoin(s, k.coin), CodecStatus::ok);
        coins.push_back(std::move(k));
    }
    auto r = feed(coins, display_hash(kRealBaseHex));
    ASSERT_TRUE(r);
    EXPECT_EQ(r->muhash.GetHex(), kReal3Muhash);
    EXPECT_EQ(r->hash_serialized_2.GetHex(), kReal3HashSer2);
}
