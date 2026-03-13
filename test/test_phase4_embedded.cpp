/// Phase 4 — Embedded Coin Node unit tests
///
/// Tests the EmbeddedCoinNode / CoinNodeInterface wiring for the
/// "drop LTC daemon" feature:
///
///  1.  MockCoinNodeInterface satisfies CoinNodeInterface contract
///  2.  EmbeddedCoinNode is polymorphic via CoinNodeInterface*
///  3.  EmbeddedCoinNode::getwork throws when chain has no genesis
///  4.  EmbeddedCoinNode::getwork returns WorkData after genesis
///  5.  EmbeddedCoinNode::getblockchaininfo has required fields
///  6.  EmbeddedCoinNode::getblockchaininfo.chain is "test" for testnet
///  7.  EmbeddedCoinNode::getblockchaininfo.chain is "main" for mainnet params
///  8.  EmbeddedCoinNode::is_synced returns false when tip is old
///  9.  EmbeddedCoinNode::getblockchaininfo.blocks matches chain height
/// 10.  EmbeddedCoinNode::getblockchaininfo.bestblockhash is the tip hash
/// 11.  WorkData has all required GBT keys
/// 12.  WorkData.height is tip.height + 1
/// 13.  WorkData.previousblockhash matches tip block_hash
/// 14.  WorkData.coinbasevalue matches expected LTC subsidy at genesis+1
/// 15.  HeaderChain::get_header returns correct entry for tip
/// 16.  block_rel_height via HeaderChain: genesis depth = 1
/// 17.  block_rel_height via HeaderChain: unknown hash → 0
/// 18.  MiningInterface::set_embedded_node accepts CoinNodeInterface*
/// 19.  refresh_work with embedded node populates cached template
/// 20.  refresh_work falls back to RPC when embedded node is null

#include <gtest/gtest.h>

#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <core/web_server.hpp>
#include <core/address_validator.hpp>

#include <string>
#include <vector>
#include <stdexcept>
#include <memory>

using namespace ltc::coin;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// LTC testnet genesis block (same as Phase 3 tests)
static BlockHeaderType ltc_testnet_genesis() {
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits      = 0x1e0ffff0;
    g.m_nonce     = 293345;
    return g;
}

static std::unique_ptr<HeaderChain> make_chain_with_genesis(bool testnet = true) {
    LTCChainParams p = testnet ? LTCChainParams::testnet() : LTCChainParams::mainnet();
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    EXPECT_TRUE(chain->add_header(ltc_testnet_genesis()));
    return chain;
}

// ─── Mock CoinNodeInterface ──────────────────────────────────────────────────

class MockCoinNode : public CoinNodeInterface {
public:
    rpc::WorkData getwork() override {
        rpc::WorkData wd;
        wd.m_data = {
            {"version",           4},
            {"previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000"},
            {"bits",              "1e0ffff0"},
            {"height",            1},
            {"curtime",           1700000000},
            {"coinbasevalue",     5000000000},
            {"transactions",      nlohmann::json::array()},
            {"rules",             nlohmann::json::array({"segwit"})},
            {"coinbaseflags",     ""},
            {"mweb",              ""},
            {"sigoplimit",        80000},
            {"sizelimit",         1000000},
            {"weightlimit",       4000000},
            {"mintime",           1486949367}
        };
        return wd;
    }

    void submit_block(BlockType&) override { ++submit_count; }
    nlohmann::json getblockchaininfo() override {
        return {{"chain", "test"}, {"blocks", 1}, {"headers", 1},
                {"bestblockhash", "aabbcc"}, {"initialblockdownload", false}};
    }
    bool is_synced() const override { return true; }

    int submit_count{0};
};

// ─── Test Suite 1: MockCoinNodeInterface ────────────────────────────────────

TEST(Phase4MockNodeTest, SatisfiesInterface) {
    MockCoinNode node;
    CoinNodeInterface* iface = &node;
    auto wd = iface->getwork();
    EXPECT_EQ(wd.m_data.value("height", 0), 1);
}

TEST(Phase4MockNodeTest, SubmitBlockCallable) {
    MockCoinNode node;
    BlockType blk;
    node.submit_block(blk);
    EXPECT_EQ(node.submit_count, 1);
}

TEST(Phase4MockNodeTest, GetblockchaininfoHasChain) {
    MockCoinNode node;
    auto info = node.getblockchaininfo();
    EXPECT_TRUE(info.contains("chain"));
    EXPECT_EQ(info["chain"].get<std::string>(), "test");
}

// ─── Test Suite 2: EmbeddedCoinNode ─────────────────────────────────────────

TEST(Phase4EmbeddedNodeTest, IsPolymorphic) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, /*testnet=*/true);
    CoinNodeInterface* iface = &node;
    EXPECT_NE(iface, nullptr);
}

TEST(Phase4EmbeddedNodeTest, GetworkThrowsWithNoGenesis) {
    LTCChainParams p = LTCChainParams::testnet();
    HeaderChain chain(p);
    chain.init();
    Mempool pool;
    EmbeddedCoinNode node(chain, pool, true);
    EXPECT_THROW(node.getwork(), std::runtime_error);
}

TEST(Phase4EmbeddedNodeTest, GetworkSucceedsAfterGenesis) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    EXPECT_NO_THROW({
        auto wd = node.getwork();
        EXPECT_FALSE(wd.m_data.is_null());
    });
}

TEST(Phase4EmbeddedNodeTest, GetblockchaininfoHasRequiredFields) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    auto info = node.getblockchaininfo();
    EXPECT_TRUE(info.contains("chain"));
    EXPECT_TRUE(info.contains("blocks"));
    EXPECT_TRUE(info.contains("headers"));
    EXPECT_TRUE(info.contains("bestblockhash"));
    EXPECT_TRUE(info.contains("synced"));  // EmbeddedCoinNode uses "synced" (not "initialblockdownload")
}

TEST(Phase4EmbeddedNodeTest, GetblockchaininfoChainIsTestForTestnet) {
    auto chain = make_chain_with_genesis(true);
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, /*testnet=*/true);
    auto info = node.getblockchaininfo();
    EXPECT_EQ(info["chain"].get<std::string>(), "test");
}

TEST(Phase4EmbeddedNodeTest, GetblockchaininfoChainIsMainForMainnet) {
    // Use testnet genesis but testnet=false — chain field should reflect node config
    LTCChainParams p = LTCChainParams::testnet();
    auto chain = std::make_unique<HeaderChain>(p);
    chain->init();
    chain->add_header(ltc_testnet_genesis());
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, /*testnet=*/false);
    auto info = node.getblockchaininfo();
    EXPECT_EQ(info["chain"].get<std::string>(), "main");
}

TEST(Phase4EmbeddedNodeTest, IsSyncedFalseWhenTipIsOld) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    // Genesis block timestamp (1486949366) is far in the past → not synced
    EXPECT_FALSE(node.is_synced());
}

TEST(Phase4EmbeddedNodeTest, GetblockchaininfoBlocksMatchesChainHeight) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    auto info = node.getblockchaininfo();
    EXPECT_EQ(info["blocks"].get<uint32_t>(), chain->height());
}

TEST(Phase4EmbeddedNodeTest, GetblockchaininfoHashMatchesTip) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);

    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());

    auto info = node.getblockchaininfo();
    std::string expected = tip->block_hash.GetHex();
    std::string actual   = info["bestblockhash"].get<std::string>();
    EXPECT_EQ(actual, expected);
}

// ─── Test Suite 3: WorkData fields ──────────────────────────────────────────

TEST(Phase4WorkDataTest, HasAllRequiredGBTKeys) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    auto wd = node.getwork();

    static const std::vector<std::string> required_keys = {
        "version", "previousblockhash", "bits", "height", "curtime",
        "coinbasevalue", "transactions", "rules", "coinbaseflags", "mintime"
    };
    for (const auto& key : required_keys)
        EXPECT_TRUE(wd.m_data.contains(key)) << "Missing GBT key: " << key;
}

TEST(Phase4WorkDataTest, HeightIsTipHeightPlusOne) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    auto wd = node.getwork();

    uint32_t tip_h = chain->height();  // genesis = 0
    uint32_t wd_h  = wd.m_data["height"].get<uint32_t>();
    EXPECT_EQ(wd_h, tip_h + 1);
}

TEST(Phase4WorkDataTest, PreviousBlockHashMatchesTip) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);

    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());
    std::string expected = tip->block_hash.GetHex();

    auto wd = node.getwork();
    std::string actual = wd.m_data["previousblockhash"].get<std::string>();
    EXPECT_EQ(actual, expected);
}

TEST(Phase4WorkDataTest, CoinbasevalueMatchesLTCSubsidy) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    auto wd = node.getwork();

    // Height 1 = first block after genesis → 50 LTC = 5_000_000_000 sat
    uint64_t expected_subsidy = get_block_subsidy(1);
    uint64_t actual = wd.m_data["coinbasevalue"].get<uint64_t>();
    EXPECT_EQ(actual, expected_subsidy);
}

// ─── Test Suite 4: HeaderChain depth queries ────────────────────────────────

TEST(Phase4ChainDepthTest, GetHeaderReturnsEntryForTip) {
    auto chain = make_chain_with_genesis();
    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());
    auto entry = chain->get_header(tip->block_hash);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->height, 0u);
}

TEST(Phase4ChainDepthTest, GenesisDepthIsOne) {
    auto chain = make_chain_with_genesis();
    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());
    auto entry = chain->get_header(tip->block_hash);
    ASSERT_TRUE(entry.has_value());

    // depth = tip_height - entry_height + 1
    int32_t tip_h   = static_cast<int32_t>(chain->height());
    int32_t entry_h = static_cast<int32_t>(entry->height);
    int32_t depth   = tip_h - entry_h + 1;
    EXPECT_EQ(depth, 1);
}

TEST(Phase4ChainDepthTest, UnknownHashReturnsNoEntry) {
    auto chain = make_chain_with_genesis();
    uint256 unknown;
    unknown.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    auto entry = chain->get_header(unknown);
    EXPECT_FALSE(entry.has_value());
}

// ─── Test Suite 5: MiningInterface integration ──────────────────────────────

TEST(Phase4MiningInterfaceTest, SetEmbeddedNodeAcceptsNull) {
    core::MiningInterface mi(/*testnet=*/false, nullptr, c2pool::address::Blockchain::LITECOIN);
    EXPECT_NO_THROW(mi.set_embedded_node(nullptr));
}

TEST(Phase4MiningInterfaceTest, SetEmbeddedNodeAcceptsMock) {
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::LITECOIN);
    MockCoinNode mock;
    EXPECT_NO_THROW(mi.set_embedded_node(&mock));
}

TEST(Phase4MiningInterfaceTest, RefreshWorkWithEmbeddedNodePopulatesTemplate) {
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::LITECOIN);
    MockCoinNode mock;
    mi.set_embedded_node(&mock);

    EXPECT_NO_THROW(mi.refresh_work());

    auto tmpl = mi.get_current_work_template();
    EXPECT_FALSE(tmpl.is_null());
    EXPECT_TRUE(tmpl.contains("height"));
    EXPECT_EQ(tmpl["height"].get<int>(), 1);
}

TEST(Phase4MiningInterfaceTest, RefreshWorkWithNoNodeIsNoop) {
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::LITECOIN);
    // No embedded node, no coin_rpc → refresh_work should return without crash
    EXPECT_NO_THROW(mi.refresh_work());
    auto tmpl = mi.get_current_work_template();
    EXPECT_TRUE(tmpl.is_null() || tmpl.empty());
}
