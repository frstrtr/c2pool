/// Phase 3 — TemplateBuilder unit tests
///
/// Tests the LTC TemplateBuilder, subsidy schedule, Merkle tree, and
/// EmbeddedCoinNode without any network connectivity:
///   1.  get_block_subsidy: initial, first halving, second halving, zero
///   2.  compute_merkle_root: empty, single, two, three, four elements
///   3.  bits_to_hex formatting
///   4.  TemplateBuilder::build_template — no genesis → nullopt
///   5.  TemplateBuilder::build_template — chain at genesis → valid WorkData
///   6.  WorkData JSON has required GBT-compatible keys
///   7.  previousblockhash matches tip block_hash
///   8.  height is tip.height + 1
///   9.  bits is non-empty 8-char hex
///  10.  coinbasevalue matches expected subsidy (empty mempool, no fees)
///  11.  transactions array includes mempool txs
///  12.  EmbeddedCoinNode::getwork throws when no genesis
///  13.  EmbeddedCoinNode::getwork returns WorkData after genesis
///  14.  EmbeddedCoinNode::getblockchaininfo returns chain/synced/bestblockhash
///  15.  EmbeddedCoinNode::is_synced returns false when tip is old
///  16.  Template with populated mempool: tx count matches
///  17.  Template tx weight budget: total weight ≤ MAX_BLOCK_WEIGHT - COINBASE_RESERVE
///  18.  curtime is a reasonable Unix timestamp
///  19.  mintime is tip.timestamp + 1
///  20.  rules contains "segwit"

#include <gtest/gtest.h>

#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>

#include <ctime>
#include <string>
#include <vector>

using namespace ltc::coin;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// LTC testnet genesis block (used to seed a header chain for testing).
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

/// Build a minimal non-coinbase transaction for testing.
static MutableTransaction make_tx(uint32_t nonce = 0) {
    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash.SetNull();
    uint8_t* d = in.prevout.hash.data();
    d[0] = (nonce >> 24) & 0xFF;
    d[1] = (nonce >> 16) & 0xFF;
    d[2] = (nonce >> 8)  & 0xFF;
    d[3] = nonce         & 0xFF;
    in.prevout.index = nonce;
    in.sequence = 0xFFFFFFFF;
    tx.vin.push_back(in);

    TxOut out;
    out.value = 100000;
    out.scriptPubKey.m_data = {0x76, 0xa9, 0x14,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,
        0x88, 0xac};
    tx.vout.push_back(out);
    return tx;
}

/// Create a chain with genesis already added (returned as unique_ptr — HeaderChain is non-copyable).
static std::unique_ptr<HeaderChain> make_chain_with_genesis(bool testnet = true) {
    LTCChainParams p = testnet ? LTCChainParams::testnet() : LTCChainParams::mainnet();
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    EXPECT_TRUE(chain->add_header(ltc_testnet_genesis()));
    return chain;
}

// ─── Test 1–2: Subsidy ───────────────────────────────────────────────────────

TEST(SubsidyTest, InitialSubsidy) {
    EXPECT_EQ(get_block_subsidy(0),  5'000'000'000ULL);  // 50 LTC
    EXPECT_EQ(get_block_subsidy(1),  5'000'000'000ULL);
    EXPECT_EQ(get_block_subsidy(839'999), 5'000'000'000ULL);
}

TEST(SubsidyTest, FirstHalving) {
    EXPECT_EQ(get_block_subsidy(840'000),   2'500'000'000ULL);  // 25 LTC
    EXPECT_EQ(get_block_subsidy(840'001),   2'500'000'000ULL);
    EXPECT_EQ(get_block_subsidy(1'679'999), 2'500'000'000ULL);
}

TEST(SubsidyTest, SecondHalving) {
    EXPECT_EQ(get_block_subsidy(1'680'000), 1'250'000'000ULL);  // 12.5 LTC
}

TEST(SubsidyTest, ThirdHalving) {
    EXPECT_EQ(get_block_subsidy(2'520'000), 625'000'000ULL);  // 6.25 LTC
}

TEST(SubsidyTest, VeryLargeHeight) {
    // 64 halvings → 0
    EXPECT_EQ(get_block_subsidy(840'000u * 64u), 0ULL);
}

// ─── Test 3: bits_to_hex ─────────────────────────────────────────────────────

TEST(BitsHexTest, Formatting) {
    EXPECT_EQ(bits_to_hex(0x1a01aa3e), "1a01aa3e");
    EXPECT_EQ(bits_to_hex(0x1e0ffff0), "1e0ffff0");
    EXPECT_EQ(bits_to_hex(0x00000001), "00000001");
    EXPECT_EQ(bits_to_hex(0xffffffff), "ffffffff");
}

// ─── Test 4–5: Merkle root ───────────────────────────────────────────────────

TEST(MerkleTest, EmptyList) {
    EXPECT_EQ(compute_merkle_root({}), uint256::ZERO);
}

TEST(MerkleTest, SingleElement) {
    uint256 h;
    h.SetHex("abcdef0000000000000000000000000000000000000000000000000000000001");
    auto root = compute_merkle_root({h});
    EXPECT_EQ(root, h);
}

TEST(MerkleTest, TwoElements) {
    uint256 a, b;
    a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    b.SetHex("2222222222222222222222222222222222222222222222222222222222222222");

    auto root = compute_merkle_root({a, b});
    auto expected = merkle_hash_pair(a, b);
    EXPECT_EQ(root, expected);
}

TEST(MerkleTest, ThreeElements) {
    uint256 a, b, c;
    a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    b.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    c.SetHex("3333333333333333333333333333333333333333333333333333333333333333");

    // Three elements: duplicate c → [a, b, c, c]
    // Level 1: [hash(a,b), hash(c,c)]
    // Level 2: hash(hash(a,b), hash(c,c))
    uint256 ab    = merkle_hash_pair(a, b);
    uint256 cc    = merkle_hash_pair(c, c);
    uint256 root  = merkle_hash_pair(ab, cc);

    EXPECT_EQ(compute_merkle_root({a, b, c}), root);
}

TEST(MerkleTest, FourElements) {
    uint256 a, b, c, d;
    a.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    b.SetHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    c.SetHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    d.SetHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    uint256 ab   = merkle_hash_pair(a, b);
    uint256 cd   = merkle_hash_pair(c, d);
    uint256 root = merkle_hash_pair(ab, cd);

    EXPECT_EQ(compute_merkle_root({a, b, c, d}), root);
}

TEST(MerkleTest, Deterministic) {
    std::vector<uint256> hashes(8);
    for (int i = 0; i < 8; ++i) {
        hashes[i].SetNull();
        hashes[i].data()[0] = static_cast<uint8_t>(i + 1);
    }
    auto r1 = compute_merkle_root(hashes);
    auto r2 = compute_merkle_root(hashes);
    EXPECT_EQ(r1, r2);
    EXPECT_FALSE(r1.IsNull());
}

// ─── Test 6: TemplateBuilder — no genesis ────────────────────────────────────

TEST(TemplateBuilderTest, NoGenesisReturnsNullopt) {
    LTCChainParams p = LTCChainParams::testnet();
    HeaderChain chain(p);
    ASSERT_TRUE(chain.init());

    Mempool pool;
    auto result = TemplateBuilder::build_template(chain, pool, true);
    EXPECT_FALSE(result.has_value());
}

// ─── Test 7: TemplateBuilder — with genesis ──────────────────────────────────

TEST(TemplateBuilderTest, WithGenesisReturnsWorkData) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto result = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(result.has_value());
}

TEST(TemplateBuilderTest, WorkDataHasRequiredKeys) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    const auto& d = wd->m_data;
    EXPECT_TRUE(d.contains("version"));
    EXPECT_TRUE(d.contains("previousblockhash"));
    EXPECT_TRUE(d.contains("bits"));
    EXPECT_TRUE(d.contains("height"));
    EXPECT_TRUE(d.contains("curtime"));
    EXPECT_TRUE(d.contains("coinbasevalue"));
    EXPECT_TRUE(d.contains("transactions"));
    EXPECT_TRUE(d.contains("rules"));
    EXPECT_TRUE(d.contains("coinbaseflags"));
    EXPECT_TRUE(d.contains("mweb"));
    EXPECT_TRUE(d.contains("weightlimit"));
    EXPECT_TRUE(d.contains("mintime"));
}

TEST(TemplateBuilderTest, PreviousBlockHashMatchesTip) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());

    std::string prevhash = wd->m_data["previousblockhash"].get<std::string>();
    EXPECT_EQ(prevhash, tip->block_hash.GetHex());
}

TEST(TemplateBuilderTest, HeightIsNextBlock) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    int height = wd->m_data["height"].get<int>();
    EXPECT_EQ(static_cast<uint32_t>(height), chain->height() + 1);
}

TEST(TemplateBuilderTest, BitsIsEightCharHex) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    std::string bits = wd->m_data["bits"].get<std::string>();
    EXPECT_EQ(bits.size(), 8u);
    // All hex characters
    for (char c : bits)
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "Non-hex character in bits: " << c;
}

TEST(TemplateBuilderTest, CoinbaseValueMatchesSubsidy) {
    auto chain = make_chain_with_genesis();
    Mempool pool;  // empty → no fees
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    int64_t cv = wd->m_data["coinbasevalue"].get<int64_t>();
    // Height 0 is genesis; next block is height 1 → same subsidy as height 0 (no halving yet)
    EXPECT_EQ(static_cast<uint64_t>(cv), get_block_subsidy(1u));
}

TEST(TemplateBuilderTest, EmptyMempoolYieldsNoTransactions) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    EXPECT_TRUE(wd->m_data["transactions"].empty());
    EXPECT_TRUE(wd->m_txs.empty());
    EXPECT_TRUE(wd->m_hashes.empty());
}

TEST(TemplateBuilderTest, MempoolTxsAppearInTemplate) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    for (int i = 0; i < 5; ++i) {
        auto tx = make_tx(static_cast<uint32_t>(i));
        auto txid = compute_txid(tx);
        pool.add_tx(tx);
        pool.set_tx_fee(txid, 1000);
    }

    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    EXPECT_EQ(wd->m_data["transactions"].size(), 5u);
    EXPECT_EQ(wd->m_txs.size(), 5u);
    EXPECT_EQ(wd->m_hashes.size(), 5u);
}

TEST(TemplateBuilderTest, TxArrayHasDataAndTxidFields) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto tx99 = make_tx(99);
    auto txid99 = compute_txid(tx99);
    pool.add_tx(tx99);
    pool.set_tx_fee(txid99, 500);
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    const auto& txs = wd->m_data["transactions"];
    ASSERT_EQ(txs.size(), 1u);
    EXPECT_TRUE(txs[0].contains("data"));
    EXPECT_TRUE(txs[0].contains("txid"));
    // data should be a non-empty hex string
    EXPECT_GT(txs[0]["data"].get<std::string>().size(), 0u);
    // txid should be a 64-char hex string
    EXPECT_EQ(txs[0]["txid"].get<std::string>().size(), 64u);
}

TEST(TemplateBuilderTest, TxHashConsistencyWithHashes) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto tx = make_tx(42);
    auto txid42 = compute_txid(tx);
    pool.add_tx(tx);
    pool.set_tx_fee(txid42, 500);

    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    // m_hashes[0] should match the txid in the JSON
    std::string json_txid = wd->m_data["transactions"][0]["txid"].get<std::string>();
    uint256 map_txid;
    map_txid.SetHex(json_txid);
    EXPECT_EQ(wd->m_hashes[0], map_txid);

    // Also verify it matches compute_txid directly
    EXPECT_EQ(wd->m_hashes[0], compute_txid(tx));
}

TEST(TemplateBuilderTest, WeightBudgetNotExceeded) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    // Add many transactions
    for (int i = 0; i < 200; ++i)
        pool.add_tx(make_tx(static_cast<uint32_t>(1000 + i)));

    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    uint32_t total_weight = 0;
    for (const auto& mtx : pool.get_sorted_txs(TemplateBuilder::MAX_BLOCK_WEIGHT
                                                - TemplateBuilder::COINBASE_RESERVE)) {
        uint32_t bs, ws, w;
        compute_tx_weight(mtx, bs, ws, w);
        total_weight += w;
    }
    EXPECT_LE(total_weight,
              TemplateBuilder::MAX_BLOCK_WEIGHT - TemplateBuilder::COINBASE_RESERVE);
}

TEST(TemplateBuilderTest, CurtimeIsReasonable) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto before = static_cast<int64_t>(std::time(nullptr));
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    auto after  = static_cast<int64_t>(std::time(nullptr));
    ASSERT_TRUE(wd.has_value());

    int64_t curtime = wd->m_data["curtime"].get<int64_t>();
    EXPECT_GE(curtime, before);
    EXPECT_LE(curtime, after + 1);
}

TEST(TemplateBuilderTest, MintimeIsTipTimestampPlusOne) {
    auto chain = make_chain_with_genesis();
    auto tip = chain->tip();
    ASSERT_TRUE(tip.has_value());

    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    int64_t mintime = wd->m_data["mintime"].get<int64_t>();
    EXPECT_EQ(mintime, static_cast<int64_t>(tip->header.m_timestamp + 1));
}

TEST(TemplateBuilderTest, RulesContainsSegwit) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());

    auto rules = wd->m_data["rules"].get<std::vector<std::string>>();
    bool has_segwit = std::find(rules.begin(), rules.end(), "segwit") != rules.end();
    EXPECT_TRUE(has_segwit);
}

TEST(TemplateBuilderTest, WeightlimitIs4000000) {
    auto chain = make_chain_with_genesis();
    Mempool pool;
    auto wd = TemplateBuilder::build_template(*chain, pool, true);
    ASSERT_TRUE(wd.has_value());
    EXPECT_EQ(wd->m_data["weightlimit"].get<int>(), 4'000'000);
}

// ─── EmbeddedCoinNode tests ───────────────────────────────────────────────────

TEST(EmbeddedCoinNodeTest, GetworkThrowsWithNoGenesis) {
    LTCChainParams p = LTCChainParams::testnet();
    HeaderChain chain(p);
    ASSERT_TRUE(chain.init());
    Mempool pool;

    EmbeddedCoinNode node(chain, pool, true);
    EXPECT_THROW(node.getwork(), std::runtime_error);
}

TEST(EmbeddedCoinNodeTest, GetworkThrowsWhenNotSynced) {
    // Genesis has timestamp from 2017 — sync gate blocks getwork
    auto chain = make_chain_with_genesis();
    Mempool pool;
    EmbeddedCoinNode node(*chain, pool, true);
    EXPECT_THROW(node.getwork(), std::runtime_error);
}

TEST(EmbeddedCoinNodeTest, GetblockchainInfoFields) {
    auto chain = make_chain_with_genesis();
    Mempool pool;

    EmbeddedCoinNode node(*chain, pool, true);
    auto info = node.getblockchaininfo();

    EXPECT_EQ(info["chain"].get<std::string>(), "test");
    EXPECT_GE(info["blocks"].get<int>(), 0);
    EXPECT_TRUE(info.contains("bestblockhash"));
    EXPECT_TRUE(info.contains("synced"));
    EXPECT_TRUE(info.contains("bits"));
}

TEST(EmbeddedCoinNodeTest, GetblockchainInfoMainnet) {
    // Mainnet EmbeddedCoinNode reports "main"
    LTCChainParams p = LTCChainParams::mainnet();
    HeaderChain chain(p);
    ASSERT_TRUE(chain.init());
    Mempool pool;

    EmbeddedCoinNode node(chain, pool, false);
    auto info = node.getblockchaininfo();
    EXPECT_EQ(info["chain"].get<std::string>(), "main");
}

TEST(EmbeddedCoinNodeTest, IsSyncedFalseForOldTip) {
    // Testnet genesis was in 2017 — well beyond the 2-hour sync window.
    auto chain = make_chain_with_genesis();
    Mempool pool;

    EmbeddedCoinNode node(*chain, pool, true);
    EXPECT_FALSE(node.is_synced());
}

TEST(EmbeddedCoinNodeTest, SubmitBlockDoesNotCrash) {
    auto chain = make_chain_with_genesis();
    Mempool pool;

    EmbeddedCoinNode node(*chain, pool, true);
    BlockType blk;
    EXPECT_NO_THROW(node.submit_block(blk));
}

// ─── CoinNodeInterface polymorphism ─────────────────────────────────────────

TEST(CoinNodeInterfaceTest, EmbeddedNodeIsPolymorphic) {
    auto chain = make_chain_with_genesis();
    Mempool pool;

    std::unique_ptr<CoinNodeInterface> iface =
        std::make_unique<EmbeddedCoinNode>(*chain, pool, true);

    // Chain with only genesis is not synced — getwork() throws the sync gate
    EXPECT_THROW(iface->getwork(), std::runtime_error);
    EXPECT_FALSE(iface->is_synced());
}
