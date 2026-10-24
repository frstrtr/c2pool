// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// core::coin::check_template_txs -- the structural check of a template's
// transactions, on real Litecoin mainnet bytes (ltc_mweb_tx_fixtures.hpp):
// litecoind's own getblocktemplate at 3200605 passes, block 3200572's
// transactions (a peg-in and the HogEx spending its output) pass, and each
// rule refuses the template that breaks it (core_test, folded into the
// existing target): a stub with no inputs, the HogEx
// not last, a tx carrying an mw::Transaction, unknown serialization flags,
// undecodable hex, a wrong txid, a pegin output without its HogEx input or
// with the wrong one, a HogEx input no pegin output matches, fees above
// coinbasevalue. A fee above 1 coin is reported, not refused.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/template_txs_check.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/test/ltc_mweb_tx_fixtures.hpp>

namespace {

namespace fx = ltc_mweb_tx_fixture;
using core::coin::check_template_txs;
using core::coin::walk_tx_hex;

nlohmann::json gbt()
{
    return nlohmann::json::parse(fx::kGbt3200605Json);
}

std::string txid_of_hex(const std::string& hex)
{
    auto b = ParseHex(hex);
    PackStream ps(b);
    ltc::coin::MutableTransaction tx;
    ps >> ltc::coin::TX_WITH_WITNESS(tx);
    return ltc::coin::compute_txid(tx).GetHex();
}

nlohmann::json entry(const std::string& data, int64_t fee)
{
    return {{"data", data}, {"txid", txid_of_hex(data)}, {"hash", txid_of_hex(data)}, {"fee", fee}};
}

// Insert `e` before the HogEx (the last entry).
void insert_before_hogex(nlohmann::json& t, const nlohmann::json& e)
{
    auto& txs = t["transactions"];
    txs.insert(txs.end() - 1, e);
}

// A template over block 3200572's transactions (coinbase excluded), as
// litecoind's getblocktemplate would list them.
nlohmann::json template_from_block_3200572()
{
    auto bytes = ParseHex(fx::kBlock3200572Hex);
    PackStream ps(bytes);
    ltc::coin::BlockType b;
    ps >> b;
    nlohmann::json txs = nlohmann::json::array();
    for (size_t i = 1; i < b.m_txs.size(); ++i) {
        auto packed = pack(ltc::coin::TX_WITH_WITNESS(b.m_txs[i]));
        txs.push_back({{"data", HexStr(packed.get_span())},
                       {"txid", ltc::coin::compute_txid(b.m_txs[i]).GetHex()}});
    }
    return {
        {"height", fx::kBlock3200572Height},
        {"coinbasevalue", 625000000},
        {"rules", nlohmann::json::array({"csv", "!segwit", "taproot", "mweb"})},
        {"mweb", HexStr(std::span<const unsigned char>(b.m_mweb_raw.data(), b.m_mweb_raw.size()))},
        {"transactions", txs},
    };
}

// Re-serialize a tx after `edit`, keeping the template entry consistent.
template <typename Edit>
nlohmann::json edited_entry(const std::string& data, Edit edit)
{
    auto b = ParseHex(data);
    PackStream ps(b);
    ltc::coin::MutableTransaction tx;
    ps >> ltc::coin::TX_WITH_WITNESS(tx);
    edit(tx);
    auto packed = pack(ltc::coin::TX_WITH_WITNESS(tx));
    return {{"data", HexStr(packed.get_span())}, {"txid", ltc::coin::compute_txid(tx).GetHex()}};
}

} // namespace

TEST(TemplateTxsCheck, WalkerReadsRealTransactions)
{
    auto pegin = walk_tx_hex(fx::kPeginTxHex);
    ASSERT_TRUE(pegin);
    EXPECT_TRUE(pegin->consumed_all);
    EXPECT_EQ(pegin->flags, 0x09);
    ASSERT_TRUE(pegin->mweb_presence);
    EXPECT_EQ(*pegin->mweb_presence, 0x01);
    EXPECT_EQ(pegin->n_vin, 1u);
    EXPECT_EQ(pegin->n_vout, 1u);
    EXPECT_EQ(pegin->txid.GetHex(), fx::kPeginTxid);

    auto pegout = walk_tx_hex(fx::kPegoutTxHex);
    ASSERT_TRUE(pegout);
    EXPECT_TRUE(pegout->consumed_all);
    EXPECT_EQ(pegout->n_vin, 0u);
    EXPECT_EQ(pegout->n_vout, 0u);

    auto hogex = walk_tx_hex(fx::kBlock3200604HogexHex);
    ASSERT_TRUE(hogex);
    EXPECT_EQ(hogex->flags, 0x08);
    EXPECT_EQ(hogex->mweb_presence.value_or(9), 0x00);
    EXPECT_EQ(hogex->txid.GetHex(), fx::kBlock3200604HogexTxid);

    // Truncated, odd-length, non-hex, trailing byte.
    const std::string h = fx::kPeginTxHex;
    EXPECT_FALSE(walk_tx_hex(h.substr(0, h.size() - 2)));
    EXPECT_FALSE(walk_tx_hex(h.substr(0, h.size() - 1)));
    EXPECT_FALSE(walk_tx_hex("zz" + h.substr(2)));
    auto longer = walk_tx_hex(h + "00");
    ASSERT_TRUE(longer);
    EXPECT_FALSE(longer->consumed_all);
}

TEST(TemplateTxsCheck, EachRuleRefuses)
{
    // litecoind's own template at 3200605 passes.
    {
        size_t outliers = 99;
        EXPECT_FALSE(check_template_txs(gbt(), &outliers));
        EXPECT_EQ(outliers, 0u);
    }
    // 2: the 10-byte stub (no inputs, no outputs).
    {
        auto t = gbt();
        insert_before_hogex(t, entry(fx::kPegoutStubHex, 0));
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "tx-vin-empty");
        EXPECT_EQ(r->index, 13u);
    }
    // 4: the HogEx moved off the end.
    {
        auto t = gbt();
        auto& txs = t["transactions"];
        std::swap(txs[12], txs[13]);
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "mweb-flag-not-last");
        EXPECT_EQ(r->index, 12u);
    }
    // 4: MWEB active, no HogEx at all.
    {
        auto t = gbt();
        t["transactions"].erase(t["transactions"].end() - 1);
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "hogex-missing");
    }
    // 3: a tx carrying its mw::Transaction (the relayed peg-in).
    {
        auto t = gbt();
        insert_before_hogex(t, entry(fx::kPeginTxHex, 4064));
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "tx-carries-mweb-data");
        EXPECT_EQ(r->txid, fx::kPeginTxid);
    }
    // 5: unknown serialization flags (0x03 on a segwit tx).
    {
        auto t = gbt();
        std::string d = t["transactions"][0]["data"].get<std::string>();
        ASSERT_EQ(d.substr(8, 4), "0001");
        d[11] = '3';
        t["transactions"][0]["data"] = d;
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "tx-unknown-flags");
        EXPECT_EQ(r->index, 0u);
    }
    // 1: undecodable / bytes after the locktime.
    {
        auto t = gbt();
        t["transactions"][3]["data"] = t["transactions"][3]["data"].get<std::string>() + "00";
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "tx-undecodable");
        EXPECT_EQ(r->index, 3u);
        t["transactions"][3]["data"] = "0200";
        r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "tx-undecodable");
    }
    // 6: a txid that is not the tx's.
    {
        auto t = gbt();
        t["transactions"][5]["txid"] = std::string(64, '0');
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "txid-mismatch");
        EXPECT_EQ(r->index, 5u);
    }
    // 8: fees above coinbasevalue; one large fee is only an outlier.
    {
        auto t = gbt();
        t["coinbasevalue"] = 32145;
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "fee-exceeds-coinbasevalue");

        auto u = gbt();
        u["transactions"][0]["fee"] = 100000001;
        size_t outliers = 0;
        EXPECT_FALSE(check_template_txs(u, &outliers));
        EXPECT_EQ(outliers, 1u);

        auto n = gbt();
        n["transactions"][2]["fee"] = -1;
        r = check_template_txs(n);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "fee-negative");
        EXPECT_EQ(r->index, 2u);
    }
}

// Rule 7 exactly as litecoind's ContextualCheckBlock walks pegin outputs.
TEST(TemplateTxsCheck, PeginOutputsMatchHogexInputs)
{
    // Block 3200572's transactions pass: a peg-in and the HogEx spending its
    // output.
    EXPECT_FALSE(check_template_txs(template_from_block_3200572()));

    // The peg-in without a HogEx input: block 3200572's peg-in in litecoind's
    // 3200605 template, whose HogEx has only the previous-HogEx input.
    {
        const auto b = template_from_block_3200572();
        auto t = gbt();
        insert_before_hogex(t, b["transactions"][fx::kBlock3200572PeginTxIndex - 1]);
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "pegins-missing");
        EXPECT_EQ(r->txid, fx::kBlock3200572PeginTxid);
    }
    // The HogEx's input without its peg-in.
    {
        auto t = template_from_block_3200572();
        auto& txs = t["transactions"];
        txs.erase(txs.begin() + (fx::kBlock3200572PeginTxIndex - 1));
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "extra-hogex-input");
        EXPECT_EQ(r->txid, fx::kBlock3200572HogexTxid);
    }
    // The HogEx's input naming another output of the peg-in.
    {
        auto t = template_from_block_3200572();
        auto& txs = t["transactions"];
        txs.back() = edited_entry(txs.back()["data"].get<std::string>(),
                                  [](ltc::coin::MutableTransaction& tx) { tx.vin[1].prevout.index = 1; });
        auto r = check_template_txs(t);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, "pegin-mismatch");
        EXPECT_EQ(r->txid, fx::kBlock3200572PeginTxid);
    }
}
