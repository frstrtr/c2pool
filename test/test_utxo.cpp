#include <gtest/gtest.h>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>

using namespace core::coin;

static OPScript make_script(std::initializer_list<unsigned char> bytes) {
    OPScript s;
    s.m_data.assign(bytes);
    return s;
}

// ─── Coin serialization roundtrip ───────────────────────────────────────────

TEST(UTXOTest, CoinSerializeRoundtrip) {
    Coin c(123456789LL, make_script({0x76, 0xa9, 0x14, 0x01, 0x02, 0x03}), 500000, true, false);
    auto data = serialize_coin(c);
    Coin c2;
    ASSERT_TRUE(deserialize_coin(data, c2));
    EXPECT_EQ(c2.value, 123456789LL);
    EXPECT_EQ(c2.height, 500000u);
    EXPECT_TRUE(c2.coinbase);
    EXPECT_FALSE(c2.pegout);
    EXPECT_EQ(c2.scriptPubKey.m_data.size(), 6u);
}

TEST(UTXOTest, CoinSerializePegout) {
    Coin c(999LL, make_script({0x00, 0x14, 0xab}), 12345, false, true);
    auto data = serialize_coin(c);
    Coin c2;
    ASSERT_TRUE(deserialize_coin(data, c2));
    EXPECT_EQ(c2.value, 999LL);
    EXPECT_EQ(c2.height, 12345u);
    EXPECT_FALSE(c2.coinbase);
    EXPECT_TRUE(c2.pegout);
}

// ─── Outpoint key roundtrip ─────────────────────────────────────────────────

TEST(UTXOTest, OutpointKeyRoundtrip) {
    uint256 h;
    h.SetHex("deadbeef01020304050607080900aabbccddeeff112233445566778899001122");
    Outpoint op(h, 42);
    auto key = outpoint_to_key(op);
    ASSERT_EQ(key.size(), 36u);
    auto op2 = key_to_outpoint(key);
    EXPECT_EQ(op2.txid, op.txid);
    EXPECT_EQ(op2.index, 42u);
}

// ─── MoneyRange ─────────────────────────────────────────────────────────────

TEST(UTXOTest, MoneyRangeLTC) {
    EXPECT_TRUE(money_range(0, LTC_LIMITS));
    EXPECT_TRUE(money_range(8'400'000'000'000'000LL, LTC_LIMITS));
    EXPECT_FALSE(money_range(8'400'000'000'000'001LL, LTC_LIMITS));
    EXPECT_FALSE(money_range(-1, LTC_LIMITS));
}

TEST(UTXOTest, MoneyRangeDOGE) {
    EXPECT_TRUE(money_range(0, DOGE_LIMITS));
    EXPECT_TRUE(money_range(1'000'000'000'000'000'000LL, DOGE_LIMITS));
    EXPECT_FALSE(money_range(1'000'000'000'000'000'001LL, DOGE_LIMITS));
    EXPECT_FALSE(money_range(-1, DOGE_LIMITS));
}

// ─── Maturity ───────────────────────────────────────────────────────────────

TEST(UTXOTest, CoinbaseMaturityLTC) {
    Coin c(100, OPScript(), 1000, true, false);
    EXPECT_FALSE(c.is_mature(1050, LTC_LIMITS));  // 50 < 100
    EXPECT_FALSE(c.is_mature(1099, LTC_LIMITS));  // 99 < 100
    EXPECT_TRUE(c.is_mature(1100, LTC_LIMITS));   // 100 == 100
    EXPECT_TRUE(c.is_mature(1200, LTC_LIMITS));   // 200 > 100
}

TEST(UTXOTest, PegoutMaturityLTC) {
    Coin c(100, OPScript(), 1000, false, true);  // pegout
    EXPECT_FALSE(c.is_mature(1003, LTC_LIMITS));  // 3 < 6
    EXPECT_FALSE(c.is_mature(1005, LTC_LIMITS));  // 5 < 6
    EXPECT_TRUE(c.is_mature(1006, LTC_LIMITS));   // 6 == 6
}

TEST(UTXOTest, CoinbaseMaturityDOGE) {
    Coin c(100, OPScript(), 1000, true, false);
    EXPECT_FALSE(c.is_mature(1100, DOGE_LIMITS));  // 100 < 240
    EXPECT_FALSE(c.is_mature(1239, DOGE_LIMITS));  // 239 < 240
    EXPECT_TRUE(c.is_mature(1240, DOGE_LIMITS));   // 240 == 240
}

TEST(UTXOTest, PegoutIgnoredDOGE) {
    // DOGE has pegout_maturity=0, so pegout flag is irrelevant
    Coin c(100, OPScript(), 1000, false, true);
    EXPECT_TRUE(c.is_mature(1001, DOGE_LIMITS));
}

// ─── is_unspendable ─────────────────────────────────────────────────────────

TEST(UTXOTest, IsUnspendable) {
    EXPECT_FALSE(is_unspendable(OPScript()));
    EXPECT_TRUE(is_unspendable(make_script({0x6a})));
    EXPECT_TRUE(is_unspendable(make_script({0x6a, 0x04, 0x01, 0x02, 0x03, 0x04})));
    EXPECT_FALSE(is_unspendable(make_script({0x76, 0xa9})));

    OPScript big;
    big.m_data.resize(10001, 0x00);
    EXPECT_TRUE(is_unspendable(big));

    OPScript ok;
    ok.m_data.resize(10000, 0x00);
    EXPECT_FALSE(is_unspendable(ok));
}

// ─── BlockUndo serialization ────────────────────────────────────────────────

TEST(UTXOTest, BlockUndoRoundtrip) {
    BlockUndo undo;

    TxUndo tu;
    tu.spent_coins.push_back(Coin(50000, make_script({0x76, 0xa9}), 100, true, false));
    tu.spent_coins.push_back(Coin(30000, make_script({0x00, 0x14, 0xab}), 200, false, true));
    undo.tx_undos.push_back(tu);

    uint256 h;
    h.SetHex("aabb");
    undo.added_outpoints.push_back(Outpoint(h, 0));
    undo.added_outpoints.push_back(Outpoint(h, 1));

    auto data = serialize_block_undo(undo);
    BlockUndo undo2;
    ASSERT_TRUE(deserialize_block_undo(data, undo2));

    ASSERT_EQ(undo2.tx_undos.size(), 1u);
    ASSERT_EQ(undo2.tx_undos[0].spent_coins.size(), 2u);
    EXPECT_EQ(undo2.tx_undos[0].spent_coins[0].value, 50000);
    EXPECT_TRUE(undo2.tx_undos[0].spent_coins[0].coinbase);
    EXPECT_EQ(undo2.tx_undos[0].spent_coins[1].value, 30000);
    EXPECT_TRUE(undo2.tx_undos[0].spent_coins[1].pegout);

    ASSERT_EQ(undo2.added_outpoints.size(), 2u);
    EXPECT_EQ(undo2.added_outpoints[0].index, 0u);
    EXPECT_EQ(undo2.added_outpoints[1].index, 1u);
}

// ─── UTXOViewCache basic operations ─────────────────────────────────────────

TEST(UTXOTest, CacheAddGetSpend) {
    UTXOViewCache cache(nullptr);

    uint256 h;
    h.SetHex("1234");
    Outpoint op(h, 0);
    Coin c(5000, make_script({0x76}), 100, false);

    Coin out;
    EXPECT_FALSE(cache.get_coin(op, out));
    EXPECT_FALSE(cache.have_coin(op));

    cache.add_coin(op, c);
    EXPECT_TRUE(cache.have_coin(op));
    EXPECT_TRUE(cache.get_coin(op, out));
    EXPECT_EQ(out.value, 5000);

    auto spent = cache.spend_coin(op);
    ASSERT_TRUE(spent.has_value());
    EXPECT_EQ(spent->value, 5000);

    EXPECT_FALSE(cache.have_coin(op));
}

TEST(UTXOTest, CacheOutputValue) {
    UTXOViewCache cache(nullptr);
    uint256 h;
    h.SetHex("abcd");
    Outpoint op(h, 3);

    EXPECT_EQ(cache.get_output_value(op), -1);

    cache.add_coin(op, Coin(42000, OPScript(), 1, false));
    EXPECT_EQ(cache.get_output_value(op), 42000);
}

// ─── disconnect_from_undo ───────────────────────────────────────────────────

TEST(UTXOTest, DisconnectFromUndo) {
    UTXOViewCache cache(nullptr);

    uint256 h1;
    h1.SetHex("1111");

    Outpoint added1(h1, 0);
    Outpoint added2(h1, 1);
    cache.add_coin(added1, Coin(1000, OPScript(), 100, true));
    cache.add_coin(added2, Coin(2000, OPScript(), 100, false));

    EXPECT_TRUE(cache.have_coin(added1));
    EXPECT_TRUE(cache.have_coin(added2));

    BlockUndo undo;
    undo.added_outpoints = {added1, added2};

    EXPECT_TRUE(cache.disconnect_from_undo(undo));

    EXPECT_FALSE(cache.have_coin(added1));
    EXPECT_FALSE(cache.have_coin(added2));
}
