// KATs for core::coin::utxo_stats (src/core/coin/utxo_stats.{hpp,cpp}):
// gettxoutsetinfo of a UTXOViewDB as Dogecoin Core 1.14.9 GetUTXOStats
// (src/rpc/blockchain.cpp:874-912) computes it.
//
// The synthetic sets' expected values come from an independent Python
// transcription of GetUTXOStats and CCoins::Serialize (its own VARINT,
// CompressAmount, secp256k1 curve check and mask code), not from this code;
// that transcription reproduces a live Dogecoin Core 1.14.9 node's
// gettxoutsetinfo, the last KAT's set. The functional-test figures are the
// ones Dogecoin Core 1.14.9 and Bitcoin Core 0.14.2 assert for their regtest
// chains (qa/rpc-tests/blockchain.py).

#include "utxo_kat_fixture.hpp"

#include <core/coin/utxo_snapshot.hpp>
#include <core/coin/utxo_stats.hpp>
#include <core/coin/utxo_view_db.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

using namespace core::coin;

namespace {

#include "utxo_stats_doge1149_regtest.inc"

struct StatCoin {
    std::vector<unsigned char> txid;  // 32 raw bytes (the key's order)
    uint32_t index;
    int64_t value;
    std::vector<unsigned char> script;
    uint32_t height;
    bool coinbase;
};

std::vector<unsigned char> bytes(std::initializer_list<int> head, int fill, size_t fill_n,
                                 std::initializer_list<int> tail = {})
{
    std::vector<unsigned char> v;
    for (int b : head) v.push_back(static_cast<unsigned char>(b));
    v.insert(v.end(), fill_n, static_cast<unsigned char>(fill));
    for (int b : tail) v.push_back(static_cast<unsigned char>(b));
    return v;
}

uint256 raw_hash(const std::vector<unsigned char>& raw)
{
    uint256 h;
    std::memcpy(h.data(), raw.data(), 32);
    return h;
}

/// Write `coins` into a fresh UTXOViewDB at `dir` through its own write_batch.
void build_db(const std::string& dir, const std::vector<StatCoin>& coins, const uint256& best, uint32_t height)
{
    UTXOViewDB db(dir);
    ASSERT_TRUE(db.open());
    UTXOViewDB::ChangeMap changes;
    for (const auto& c : coins) {
        Outpoint op;
        std::memcpy(op.txid.data(), c.txid.data(), 32);
        op.index = c.index;
        OPScript s;
        s.m_data = c.script;
        changes[op] = Coin(c.value, s, c.height, c.coinbase);
    }
    ASSERT_TRUE(db.write_batch(changes, best, height));
    db.close();
}

UtxoStats stats_of(const std::vector<StatCoin>& coins, const uint256& best, uint32_t height, const char* tag)
{
    utxo_kat::TempDir tmp(tag);
    build_db(tmp.path(), coins, best, height);
    UTXOViewDB db(tmp.path());
    EXPECT_TRUE(db.open());
    auto st = utxo_stats(db);
    db.close();
    return st;
}

// Set 1 (utxo_stats_ref.py COINS): the txids' first bytes order them D, A,
// B, C; their last bytes (GetHex's first) would order them B, D, A.
const auto TXID_A = bytes({0x01}, 0xaa, 30, {0xff});
const auto TXID_B = bytes({0x02}, 0xbb, 30, {0x00});
const auto TXID_C = bytes({0x03}, 0xcc, 31);
const auto TXID_D = bytes({0x00}, 0xdd, 31);

const char* GX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char* GY = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

std::vector<StatCoin> set1()
{
    auto p2pk_g = bytes({65, 0x04}, 0, 0);
    for (auto b : utxo_kat::hex(GX)) p2pk_g.push_back(b);
    for (auto b : utxo_kat::hex(GY)) p2pk_g.push_back(b);
    p2pk_g.push_back(0xac);
    // x = 1, y = 1: not on the curve (not compressible).
    auto p2pk_bad = bytes({65, 0x04}, 0, 31, {0x01});
    for (int i = 0; i < 31; ++i) p2pk_bad.push_back(0);
    p2pk_bad.push_back(0x01);
    p2pk_bad.push_back(0xac);
    return {
        {TXID_A, 0, 100000000, bytes({0x76, 0xa9, 20}, 0x11, 20, {0x88, 0xac}), 100, false},
        {TXID_A, 2, 0, {}, 100, false},
        {TXID_A, 256, 123456789, bytes({}, 0x51, 300), 100, false},
        {TXID_B, 1, 5000000000, bytes({0xa9, 20}, 0x22, 20, {0x87}), 200, true},
        {TXID_C, 0, 7, bytes({0x6a, 4, 0xde, 0xad, 0xbe, 0xef}, 0, 0), 300, false},
        {TXID_D, 0, 1000, bytes({33, 0x02}, 0x33, 32, {0xac}), 50, false},
        {TXID_D, 1, 2000, p2pk_g, 50, false},
        {TXID_D, 3, 3000, p2pk_bad, 50, false},
    };
}

std::vector<unsigned char> best1()
{
    std::vector<unsigned char> b;
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<unsigned char>(i));
    return b;
}

} // namespace

TEST(UtxoStats, Set1MatchesIndependentReference)
{
    // Groups by txid in raw byte order, outputs by numeric index (A's keys
    // come back 0, 256, 2: LE index bytes), a value-0 empty-script output
    // counted, the OP_RETURN record skipped (C: no entry), the uncompressed
    // P2PK compressed only when the point is valid (bytes_serialized).
    const auto st = stats_of(set1(), raw_hash(best1()), 777, "stats1");
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.best_height, 777u);
    EXPECT_EQ(st.best_block, raw_hash(best1()));
    EXPECT_EQ(st.hash_serialized.GetHex(), "0a15a4521e5bd6e501a52271ff3ca0623e07b8d3b2d67198e38b5d9b539199ca");
    EXPECT_EQ(st.transactions, 3u);
    EXPECT_EQ(st.txouts, 7u);
    EXPECT_EQ(u128_to_string(st.total_amount), "5223462789");
    EXPECT_EQ(format_coin_amount(st.total_amount), "52.23462789");
    EXPECT_EQ(st.bytes_serialized, 629u);
    EXPECT_EQ(st.unspendable_skipped, 1u);
}

TEST(UtxoStats, EmptySetHashesOnlyTheBestBlock)
{
    const auto st = stats_of({}, raw_hash(best1()), 0, "stats0");
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.hash_serialized.GetHex(), "4e83196fc86ffaeb6a4aaa812cc5e8998064b4d11b9edacaf610493d4d7b282f");
    EXPECT_EQ(st.transactions, 0u);
    EXPECT_EQ(st.txouts, 0u);
    EXPECT_EQ(format_coin_amount(st.total_amount), "0.00000000");
    EXPECT_EQ(st.bytes_serialized, 0u);
}

TEST(UtxoStats, Set2IndexOrderSparseMaskAndTotalPastInt64)
{
    // E's index keys sort 0, 65536, 256, 1, 255 (LE bytes); its spentness
    // mask is 8192 bytes with two non-zero; F has neither output 0 nor 1
    // (header code 8*(mask-1)); a 253-byte script (CompactSize fd fd 00);
    // the total passes INT64_MAX (Core: arith_uint256).
    const auto E = bytes({}, 0xee, 32);
    const auto F = bytes({0x10}, 0x00, 31);
    const auto p2pkh = bytes({0x76, 0xa9, 20}, 0x44, 20, {0x88, 0xac});
    const std::vector<StatCoin> coins = {
        {E, 0, 4000000000000000000, p2pkh, 1234567, false},
        {E, 1, 4000000000000000000, p2pkh, 1234567, false},
        {E, 255, 4000000000000000000, bytes({}, 0x52, 253), 1234567, false},
        {E, 256, 1, bytes({0x53}, 0, 0), 1234567, false},
        {E, 65536, 100000000000000000, p2pkh, 1234567, false},
        {F, 5, 1000000000000, bytes({0xa9, 20}, 0x55, 20, {0x87}), 1000000, true},
    };
    const auto st = stats_of(coins, raw_hash(bytes({}, 0xfe, 31, {0x01})), 1234567, "stats2");
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.hash_serialized.GetHex(), "292bac9662275adcda37989e401fcab8b3b76b795caaacc050bc2823cc9ee619");
    EXPECT_EQ(st.transactions, 2u);
    EXPECT_EQ(st.txouts, 6u);
    EXPECT_EQ(u128_to_string(st.total_amount), "12100001000000000001");
    EXPECT_EQ(format_coin_amount(st.total_amount), "121000010000.00000001");
    EXPECT_EQ(st.bytes_serialized, 8634u);
    EXPECT_EQ(st.unspendable_skipped, 0u);
}

TEST(UtxoStats, DogecoinCore1149FunctionalTestFigures)
{
    // Dogecoin Core 1.14.9 qa/rpc-tests/blockchain.py _test_gettxoutsetinfo
    // on its 120-block regtest chain: 120 coinbases of 500,000 DOGE to a
    // compressed P2PK, heights 1..120 -> transactions 120, txouts 120,
    // bytes_serialized 8520, total_amount 60000000.00000000.
    std::vector<StatCoin> coins;
    for (uint32_t h = 1; h <= 120; ++h) {
        auto txid = bytes({}, 0, 28);
        for (int i = 0; i < 4; ++i) txid.push_back(static_cast<unsigned char>(h >> (8 * i)));
        coins.push_back({txid, 0, 50000000000000, bytes({33, 0x03}, 0x5a, 32, {0xac}), h, true});
    }
    const auto st = stats_of(coins, raw_hash(best1()), 120, "statsdoge");
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.transactions, 120u);
    EXPECT_EQ(st.txouts, 120u);
    EXPECT_EQ(st.bytes_serialized, 8520u);
    EXPECT_EQ(format_coin_amount(st.total_amount), "60000000.00000000");
}

TEST(UtxoStats, BitcoinCore0142FunctionalTestFigures)
{
    // Bitcoin Core 0.14.2 qa/rpc-tests/blockchain.py on its 200-block regtest
    // chain (halving at 150): 149 x 50 + 51 x 25 BTC to a compressed P2PK ->
    // bytes_serialized 13924 (the height VARINT goes to two bytes at 128, the
    // 25 BTC amount compresses to two bytes), total_amount 8725.00000000.
    std::vector<StatCoin> coins;
    for (uint32_t h = 1; h <= 200; ++h) {
        auto txid = bytes({}, 0x77, 28);
        for (int i = 0; i < 4; ++i) txid.push_back(static_cast<unsigned char>(h >> (8 * i)));
        coins.push_back({txid, 0, h < 150 ? 5000000000 : 2500000000, bytes({33, 0x02}, 0x6b, 32, {0xac}), h, true});
    }
    const auto st = stats_of(coins, raw_hash(best1()), 200, "statsbtc");
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.transactions, 200u);
    EXPECT_EQ(st.txouts, 200u);
    EXPECT_EQ(st.bytes_serialized, 13924u);
    EXPECT_EQ(format_coin_amount(st.total_amount), "8725.00000000");
}

TEST(UtxoStats, FormatCoinAmount)
{
    auto amt = [](uint64_t hi, uint64_t lo) { Amount128 a; a.hi = hi; a.lo = lo; return a; };
    EXPECT_EQ(format_coin_amount(amt(0, 0)), "0.00000000");
    EXPECT_EQ(format_coin_amount(amt(0, 1)), "0.00000001");
    EXPECT_EQ(format_coin_amount(amt(0, 100000000)), "1.00000000");
    EXPECT_EQ(format_coin_amount(amt(0, UINT64_MAX)), "184467440737.09551615");
    // 2^64 + 12345 koinu, and the carry of add().
    EXPECT_EQ(u128_to_string(amt(1, 12345)), "18446744073709563961");
    EXPECT_EQ(format_coin_amount(amt(1, 12345)), "184467440737.09563961");
    Amount128 sum = amt(0, UINT64_MAX - 1);
    sum.add(3);
    EXPECT_EQ(sum, amt(1, 1));
    // 2^128 - 1.
    EXPECT_EQ(u128_to_string(amt(UINT64_MAX, UINT64_MAX)), "340282366920938463463374607431768211455");
}

TEST(UtxoStats, DogecoinCore1149RegtestNodeGettxoutsetinfo)
{
    // A live Dogecoin Core 1.14.9 regtest node's UTXO set (161 coins, 3
    // non-coinbase txs, P2PKH and P2SH) through the snapshot reader into a
    // UTXOViewDB: every gettxoutsetinfo field equals the node's own.
    utxo_kat::TempDir tmp("statsregtest");
    const std::string snap = tmp.sub("regtest.snap");
    {
        const auto raw = utxo_kat::hex(kDoge1149RegtestH158SnapshotHex);
        ASSERT_EQ(raw.size(), 9968u);
        std::ofstream f(snap, std::ios::binary);
        f.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    }
    SnapshotReader reader({snap});
    ASSERT_TRUE(reader.open()) << reader.refusal();
    UTXOViewDB::ChangeMap changes;
    Outpoint op;
    Coin coin;
    while (reader.next(op, coin))
        changes[op] = coin;
    ASSERT_FALSE(reader.refused()) << reader.refusal() << " " << reader.detail();
    ASSERT_TRUE(reader.finish()) << reader.refusal();
    ASSERT_EQ(changes.size(), 161u);
    const std::string dir = tmp.sub("db");
    {
        UTXOViewDB db(dir);
        ASSERT_TRUE(db.open());
        ASSERT_TRUE(db.write_batch(changes, reader.metadata().base_blockhash, 158));
        db.close();
    }
    UTXOViewDB db(dir);
    ASSERT_TRUE(db.open());
    const auto st = utxo_stats(db);
    ASSERT_TRUE(st.ok);
    EXPECT_EQ(st.best_height, 158u);
    EXPECT_EQ(st.best_block.GetHex(), "9fd35ef05bc1c023c6a7b5336abc1340fcf17650e615401e67ee23ac7c66e3e8");
    EXPECT_EQ(st.transactions, 158u);
    EXPECT_EQ(st.txouts, 161u);
    EXPECT_EQ(st.bytes_serialized, 9437u);
    EXPECT_EQ(st.hash_serialized.GetHex(), "06e50c727eae6123e80f715f7ffb820ca23d6725d1f947cbabc938c1e7b52d80");
    EXPECT_EQ(format_coin_amount(st.total_amount), "76750000.00000000");
}
