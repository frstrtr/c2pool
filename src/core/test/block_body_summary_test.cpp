// SPDX-License-Identifier: AGPL-3.0-or-later
//
// #946 slice 2b KAT: core::summarize_block_body (coinbase txid + tx count read
// from a submitted block) and MiningInterface::set_found_block_body (fill the
// explorer fields on an already-recorded row, never overwrite).

#include <gtest/gtest.h>

#include <core/block_body_summary.hpp>
#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <string>
#include <vector>

using core::summarize_block_body;

namespace {

// Bitcoin mainnet genesis block. Its only tx is the coinbase, so the coinbase
// txid equals the header merkle root, a value every explorer agrees on.
const char* kGenesisHex =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000"
    "00000000000000000000000000000000000000000000ffffffff4d04ffff001d"
    "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c"
    "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066"
    "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554827"
    "1967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4"
    "f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
const char* kGenesisCoinbaseTxid =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

std::vector<unsigned char> header80() { return std::vector<unsigned char>(80, 0x11); }

// version | vin(1 coinbase input) | vout(1) -- no locktime
std::vector<unsigned char> coinbase_io()
{
    return ParseHex(
        "01"                                                                // vin count
        "0000000000000000000000000000000000000000000000000000000000000000"  // prev hash
        "ffffffff"                                                          // prev index
        "0403a1b2c3"                                                        // scriptSig
        "ffffffff"                                                          // sequence
        "01"                                                                // vout count
        "00f2052a01000000"                                                  // value
        "160014" "00112233445566778899aabbccddeeff00112233");               // p2wpkh
}

std::vector<unsigned char> cat(std::initializer_list<std::vector<unsigned char>> parts)
{
    std::vector<unsigned char> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

} // namespace

TEST(BlockBodySummary, GenesisCoinbaseTxidAndCount)
{
    auto s = summarize_block_body(ParseHex(kGenesisHex));
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->coinbase_txid, kGenesisCoinbaseTxid);
    EXPECT_EQ(s->tx_count, 1u);
}

TEST(BlockBodySummary, SegwitCoinbaseTxidIgnoresWitness)
{
    const auto version  = ParseHex("02000000");
    const auto locktime = ParseHex("00000000");
    const auto io       = coinbase_io();
    // witness: 1 item of 32 zero bytes (the BIP141 coinbase witness nonce)
    const auto witness  = cat({ParseHex("0120"), std::vector<unsigned char>(32, 0)});

    // 0xfd 2c01 = 300 txs; only the coinbase is present, which is all the
    // parser walks.
    const auto legacy = cat({header80(), ParseHex("fd2c01"), version, io, locktime});
    const auto segwit = cat({header80(), ParseHex("fd2c01"), version, ParseHex("0001"),
                             io, witness, locktime});

    const uint256 expected = Hash(cat({version, io, locktime}));

    auto a = summarize_block_body(legacy);
    auto b = summarize_block_body(segwit);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(a->coinbase_txid, expected.GetHex());
    EXPECT_EQ(b->coinbase_txid, expected.GetHex()) << "txid must exclude marker/flag/witness";
    EXPECT_EQ(a->tx_count, 300u);
    EXPECT_EQ(b->tx_count, 300u);
}

TEST(BlockBodySummary, MalformedOrUnknownFlagIsNullopt)
{
    auto genesis = ParseHex(kGenesisHex);
    EXPECT_FALSE(summarize_block_body(header80()).has_value()) << "header only";
    for (size_t cut : {81u, 90u, 150u, 200u, static_cast<unsigned>(genesis.size() - 1)}) {
        std::vector<unsigned char> t(genesis.begin(), genesis.begin() + cut);
        EXPECT_FALSE(summarize_block_body(t).has_value()) << "truncated at " << cut;
    }
    // zero tx count
    EXPECT_FALSE(summarize_block_body(cat({header80(), ParseHex("00")})).has_value());
    // marker 0x00 with an unknown flag (0x08, MWEB-style) is refused, not guessed
    const auto mweb = cat({header80(), ParseHex("01"), ParseHex("02000000"),
                           ParseHex("0008"), coinbase_io(), ParseHex("00000000")});
    EXPECT_FALSE(summarize_block_body(mweb).has_value());
}

TEST(BlockBodySummary, SetFoundBlockBodyFillsOnceAndNeverOverwrites)
{
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    const std::string h =
        "946946946946946946946946946946946946946946946946946946946946c2b0";
    mi.record_found_block(3000100, uint256S(h), 1790000000, "LTC",
                          "ltc1qminer", h, 0.0, 0.0, 0.0, 0);

    auto row = mi.rest_found_block(h);
    ASSERT_TRUE(row.is_object());
    EXPECT_TRUE(row["coinbase_txid"].is_null());
    EXPECT_TRUE(row["tx_count"].is_null());

    mi.set_found_block_body(h, kGenesisCoinbaseTxid, 7u);
    row = mi.rest_found_block(h);
    EXPECT_EQ(row["coinbase_txid"].get<std::string>(), kGenesisCoinbaseTxid);
    EXPECT_EQ(row["tx_count"].get<uint32_t>(), 7u);

    // A later call never rewrites a known value (fill-only, like enrichment).
    mi.set_found_block_body(h, std::string(64, 'f'), 9u);
    row = mi.rest_found_block(h);
    EXPECT_EQ(row["coinbase_txid"].get<std::string>(), kGenesisCoinbaseTxid);
    EXPECT_EQ(row["tx_count"].get<uint32_t>(), 7u);

    // Unknown hash is a no-op, not a new row.
    mi.set_found_block_body(std::string(64, 'e'), kGenesisCoinbaseTxid, 1u);
    EXPECT_TRUE(mi.rest_found_block(std::string(64, 'e')).is_null());
}
