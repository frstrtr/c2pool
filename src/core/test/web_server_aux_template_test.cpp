// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// getblocktemplate with params [{"chain": "DOGE"}] answers with the merged
// DOGE block template the node is mining (MergedMiningManager::
// aux_template_json), not the LTC one: prev, height, bits, curtime, coinbase
// value, the tx list (txid, raw, fee), tx bytes, the degraded mark. It feeds
// a local cross-check of the DOGE bodies c2pool builds; over JSON-RPC it is
// answered to a direct local client only. Without "chain" (or with the
// node's own) the call is unchanged.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using core::MiningInterface;

struct MockCoinNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    core::coin::WorkView get_work_view() override
    {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return true; }
    bool has_rpc() const override { return false; }
};

const std::string kLtcPrev  = std::string(62, '0') + "ab";
const std::string kDogePrev = std::string(62, '0') + "cd";
const std::string kDogeTx   = "01000000" "01" + std::string(64, '1') + "00000000" "00" "ffffffff"
                              "01" "00e1f50500000000" "00" "00000000";

struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    DogeBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.coinbase_value = 1000000500000ULL;
        w.block_hash.SetHex(std::string(63, '0') + "9");
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = kDogePrev;
        w.block_template = {
            {"previousblockhash", kDogePrev}, {"height", 5'000'001}, {"bits", "1a01d2c3"},
            {"curtime", 1793210000}, {"mintime", 1793209000}, {"version", 0x620004},
            {"coinbasevalue", 1000000500000LL},
            {"transactions", nlohmann::json::array({{{"data", kDogeTx}, {"txid", std::string(64, 'e')},
                                                     {"fee", 500000}}})},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return kDogePrev; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

nlohmann::json rpc(MiningInterface& mi, const std::string& params)
{
    return nlohmann::json::parse(mi.HandleRequest(
        R"({"jsonrpc":"2.0","id":1,"method":"getblocktemplate","params":)" + params + "}"));
}

} // namespace

TEST(WebServerAuxTemplate, GetblocktemplateChainDogeReturnsTheDogeTemplate)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    {
        auto b = std::make_unique<DogeBackend>();
        const auto cfg = b->cfg;
        mm.add_chain(cfg, std::move(b));
    }
    mm.refresh_aux_work();

    MockCoinNode node;
    MiningInterface mi{/*testnet=*/true};
    mi.set_coin_node(&node);
    node.work_data = {
        {"previousblockhash", kLtcPrev}, {"version", 0x20000000}, {"height", 100},
        {"bits", "207fffff"}, {"curtime", 1600000000}, {"coinbasevalue", 5000000000LL},
        {"transactions", nlohmann::json::array()}, {"rules", nlohmann::json::array({"segwit"})},
    };
    mi.refresh_work();
    mi.set_merged_mining_manager(&mm);

    // No chain: the node's own (LTC) template, as before.
    EXPECT_EQ(mi.getblocktemplate(nlohmann::json::array())["previousblockhash"], kLtcPrev);
    EXPECT_EQ(mi.getblocktemplate(nlohmann::json::array({{{"chain", "tLTC"}}}))["previousblockhash"], kLtcPrev);

    // chain DOGE: the DOGE template.
    const auto d = mi.getblocktemplate(nlohmann::json::array({{{"chain", "DOGE"}}}));
    EXPECT_EQ(d["chain"], "DOGE");
    EXPECT_EQ(d["previousblockhash"], kDogePrev) << "not the LTC template";
    EXPECT_EQ(d["height"], 5'000'001);
    EXPECT_EQ(d["bits"], "1a01d2c3");
    EXPECT_EQ(d["curtime"], 1793210000);
    EXPECT_EQ(d["coinbasevalue"], 1000000500000ULL);
    ASSERT_EQ(d["tx_count"], 1u);
    EXPECT_EQ(d["tx_bytes"], kDogeTx.size() / 2);
    EXPECT_EQ(d["transactions"][0]["data"], kDogeTx);
    EXPECT_EQ(d["transactions"][0]["txid"], std::string(64, 'e'));
    EXPECT_EQ(d["transactions"][0]["fee"], 500000);
    EXPECT_TRUE(d["degraded"].is_null());

    // Over JSON-RPC: a direct local client gets it, any other is refused.
    MiningInterface::t_direct_local_request = true;
    auto r = rpc(mi, R"([{"chain":"doge"}])");
    EXPECT_EQ(r["result"]["previousblockhash"], kDogePrev);
    r = rpc(mi, R"([{"chain":"NMC"}])");
    EXPECT_TRUE(r.contains("error")) << "no such merged chain";
    MiningInterface::t_direct_local_request = false;
    r = rpc(mi, R"([{"chain":"DOGE"}])");
    EXPECT_TRUE(r.contains("error")) << "local-only";
    EXPECT_FALSE(r.contains("result"));
    r = rpc(mi, "[]");
    EXPECT_EQ(r["result"]["previousblockhash"], kLtcPrev) << "the LTC call is unchanged";
}
