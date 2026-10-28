// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded DOGE template never carries the txs its tip confirmed (rides
// share_test).
//
// The txs a DOGE tip confirmed leave the mempool only when the tip's body
// runs through Mempool::remove_for_block. The merged-mining poll fetches the
// DOGE template once per tip change, usually before that body, and kept it
// for the whole interval: on the canary 12.2 % of DOGE intervals (100 of 818)
// carried txs already in the tip, and a DOGE block found on such a template
// is invalid (bad-txns-inputs-missingorspent).
//   - doge::coin::TemplateBuilder: a pool not cleaned for the tip (and not
//     empty) yields a coinbase-only template on the new tip, marked
//     "degraded": "mempool-not-cleaned-for-tip"; cleaned for the tip, the
//     template is full; a sibling's body does not count for the tip.
//   - MergedMiningManager::refresh_aux_work: a degraded template does not
//     latch the tip, the next poll fetches again until a clean one comes back.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <deque>
#include <memory>
#include <utility>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/utxo.hpp>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using ltc::coin::BlockHeaderType;
using ltc::coin::BlockType;
using ltc::coin::MutableTransaction;

/// A DOGE header chain in memory: a checkpoint root, then the tip T (and
/// a sibling T' the chain also knows).
struct DogeChain {
    doge::coin::DOGEChainParams params = doge::coin::DOGEChainParams::mainnet();
    doge::coin::HeaderChain chain{params};
    BlockHeaderType tip;
    BlockHeaderType sibling;

    DogeChain()
    {
        uint256 root;
        root.SetHex("00000000000000000000000000000000000000000000000000000000000d0e02");
        chain.set_dynamic_checkpoint(5'000'000, root);
        const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        tip = header(root, now - 30, 1);
        sibling = header(root, now - 20, 2);
        // Equal work: this header chain moves to the later one (S3).
        EXPECT_TRUE(chain.add_header(sibling));
        EXPECT_TRUE(chain.add_header(tip));
        EXPECT_EQ(chain.tip()->block_hash, hash_of(tip));
    }
    static BlockHeaderType header(const uint256& prev, uint32_t ts, uint32_t nonce)
    {
        BlockHeaderType h;
        h.m_version = 0x00620104;
        h.m_previous_block = prev;
        h.m_merkle_root.SetHex(std::to_string(77 + nonce));
        h.m_timestamp = ts;
        h.m_bits = 0x1a01d2c3;
        h.m_nonce = nonce;
        return h;
    }
    static uint256 hash_of(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }
    static BlockType body(const BlockHeaderType& h)
    {
        BlockType b;
        static_cast<BlockHeaderType&>(b) = h;
        return b;
    }
};

/// A priced tx (what a body of the tip may have confirmed).
MutableTransaction priced_tx(ltc::coin::Mempool& pool, uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    for (int i = 0; i < 32; ++i)
        in.prevout.hash.data()[i] = static_cast<uint8_t>(tag + i);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    ltc::coin::TxOut out;
    out.value = 500000000;
    out.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
    out.scriptPubKey.m_data.insert(out.scriptPubKey.m_data.end(), 20, tag);
    out.scriptPubKey.m_data.push_back(0x88);
    out.scriptPubKey.m_data.push_back(0xac);
    tx.vout.push_back(out);
    EXPECT_TRUE(pool.add_tx_unchecked(tx));
    pool.set_tx_fee(ltc::coin::compute_txid(tx), 1000000);
    return tx;
}

nlohmann::json build(const DogeChain& c, const ltc::coin::Mempool& pool)
{
    auto wd = doge::coin::TemplateBuilder::build_template(c.chain, pool, c.params);
    EXPECT_TRUE(wd.has_value());
    return wd ? wd->m_data : nlohmann::json();
}

int64_t subsidy_of(const DogeChain& c)
{
    return static_cast<int64_t>(doge::coin::get_doge_block_subsidy(
        c.chain.height() + 1, c.params, c.chain.tip()->block_hash));
}

} // namespace

TEST(DogeTemplateGate, MempoolNotCleanedForTipBuildsCoinbaseOnly)
{
    DogeChain c;
    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    priced_tx(pool, 0x11);
    const auto t = build(c, pool);
    EXPECT_TRUE(t["transactions"].empty()) << "the tip's body has not cleaned the pool";
    EXPECT_EQ(t["coinbasevalue"].get<int64_t>(), subsidy_of(c)) << "subsidy only";
    ASSERT_TRUE(t.contains("degraded"));
    EXPECT_EQ(t["degraded"], "mempool-not-cleaned-for-tip");
    EXPECT_EQ(t["previousblockhash"], DogeChain::hash_of(c.tip).GetHex()) << "on the new tip";
}

TEST(DogeTemplateGate, CleanedForTipFillsTemplate)
{
    DogeChain c;
    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    const auto tx = priced_tx(pool, 0x22);
    pool.remove_for_block(DogeChain::body(c.tip));   // the tip's body: did not confirm tx
    const auto t = build(c, pool);
    ASSERT_EQ(t["transactions"].size(), 1u);
    EXPECT_EQ(t["transactions"][0]["txid"], ltc::coin::compute_txid(tx).GetHex());
    EXPECT_FALSE(t.contains("degraded"));
}

TEST(DogeTemplateGate, EmptyPoolNeedsNoCleanup)
{
    DogeChain c;
    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    const auto t = build(c, pool);
    EXPECT_TRUE(t["transactions"].empty());
    EXPECT_FALSE(t.contains("degraded"));
}

TEST(DogeTemplateGate, LateSiblingBodyDoesNotCountAsTheTip)
{
    DogeChain c;
    ltc::coin::Mempool pool(core::coin::DOGE_LIMITS);
    priced_tx(pool, 0x33);
    pool.remove_for_block(DogeChain::body(c.sibling));   // not the tip's body
    const auto t = build(c, pool);
    EXPECT_TRUE(t["transactions"].empty());
    ASSERT_TRUE(t.contains("degraded"));
}

namespace {

/// An aux backend whose templates come back degraded or clean, in order.
struct StubBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(63, '0') + "a";
    std::deque<bool> degraded;   // consumed by get_work_template
    int template_fetches = 0;

    StubBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork work(bool is_degraded) const
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        w.block_template = {{"height", w.height}, {"previousblockhash", tip},
                            {"transactions", nlohmann::json::array()}};
        if (is_degraded)
            w.block_template["degraded"] = "mempool-not-cleaned-for-tip";
        return w;
    }
    bool connect() override { return true; }
    c2pool::merged::AuxWork get_work_template() override
    {
        ++template_fetches;
        bool d = false;
        if (!degraded.empty()) {
            d = degraded.front();
            degraded.pop_front();
        }
        return work(d);
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return work(false); }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

} // namespace

TEST(MergedMining, DegradedDogeTemplateIsRefetchedUntilCleaned)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    auto backend = std::make_unique<StubBackend>();
    auto* stub = backend.get();
    stub->degraded = {true, false};
    mm.add_chain(stub->cfg, std::move(backend));

    mm.refresh_aux_work();   // new tip: degraded template
    EXPECT_EQ(stub->template_fetches, 1);
    EXPECT_TRUE(mm.get_current_work().at(98).block_template.contains("degraded"));

    mm.refresh_aux_work();   // same tip: fetched again, clean now
    EXPECT_EQ(stub->template_fetches, 2) << "a degraded template does not latch the tip";
    EXPECT_FALSE(mm.get_current_work().at(98).block_template.contains("degraded"));

    mm.refresh_aux_work();   // same tip, clean: nothing to fetch
    EXPECT_EQ(stub->template_fetches, 2);

    const auto j = mm.get_template_gate_json();
    EXPECT_EQ(j["DOGE"]["degraded"], 1u);
    EXPECT_EQ(j["DOGE"]["refetched_clean"], 1u);
    EXPECT_EQ(j["DOGE"]["degraded_now"], false);
}

// Control: a clean template latches the tip at once (one fetch per tip).
TEST(MergedMining, CleanDogeTemplateLatchesTheTip)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    auto backend = std::make_unique<StubBackend>();
    auto* stub = backend.get();
    mm.add_chain(stub->cfg, std::move(backend));
    mm.refresh_aux_work();
    mm.refresh_aux_work();
    EXPECT_EQ(stub->template_fetches, 1);
    stub->tip = std::string(63, '0') + "b";   // a new tip: fetched
    mm.refresh_aux_work();
    EXPECT_EQ(stub->template_fetches, 2);
}

// A re-fetch that is still degraded on the same tip keeps the block already
// being mined: no rebuild, no new work pushed to the miners. Before, every
// such poll (1 s) rebuilt the DOGE block and pushed a new LTC job to every
// miner, for as long as the tip's body was missing.
TEST(MergedMining, StillDegradedRefetchKeepsTheBlock)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    int work_changed = 0;
    mm.set_on_work_changed([&work_changed]() { ++work_changed; });
    auto backend = std::make_unique<StubBackend>();
    auto* stub = backend.get();
    stub->degraded = {true, true, true, false};
    mm.add_chain(stub->cfg, std::move(backend));

    mm.refresh_aux_work();   // new tip, degraded: the new work goes out
    ioc.restart();
    ioc.poll();
    EXPECT_EQ(work_changed, 1);
    mm.refresh_aux_work();   // same tip, still degraded: kept
    mm.refresh_aux_work();
    ioc.restart();
    ioc.poll();
    EXPECT_EQ(stub->template_fetches, 3) << "it keeps asking";
    EXPECT_EQ(work_changed, 1) << "but pushes nothing new while still degraded";
    EXPECT_TRUE(mm.get_current_work().at(98).block_template.contains("degraded"));
    mm.refresh_aux_work();   // clean: the full template goes out
    ioc.restart();
    ioc.poll();
    EXPECT_EQ(work_changed, 2);
    EXPECT_FALSE(mm.get_current_work().at(98).block_template.contains("degraded"));
    const auto j = mm.get_template_gate_json();
    EXPECT_EQ(j["DOGE"]["degraded"], 1u);
    EXPECT_EQ(j["DOGE"]["still_degraded"], 2u);
    EXPECT_EQ(j["DOGE"]["refetched_clean"], 1u);
}

// frozen_history holds the snapshots a share's committed DOGE block is
// rebuilt from at submit. Past its cap (100) it must drop the OLDEST: it is
// keyed by block hash, and trimming in key order dropped arbitrary ones, the
// one just frozen included, so a DOGE find on the current job was skipped
// ("No matching snapshot") and lost.
TEST(MergedMining, FrozenHistoryKeepsTheNewestSnapshots)
{
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm(ioc);
    auto backend = std::make_unique<StubBackend>();
    auto* stub = backend.get();
    mm.add_chain(stub->cfg, std::move(backend));
    uint64_t round = 0;
    mm.set_payout_provider([&round](uint32_t, uint64_t value) {
        std::vector<unsigned char> s{0x76, 0xa9, 0x14};
        s.insert(s.end(), 20, 0x5a);
        s.push_back(0x88);
        s.push_back(0xac);
        return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{{s, value - round}};
    });
    mm.refresh_aux_work();
    std::vector<uint256> hashes;
    for (round = 1; round <= 150; ++round) {   // a new PPLNS split each round
        mm.mark_pplns_dirty();
        mm.rebuild_cached_blocks();
        hashes.push_back(mm.get_current_work().at(98).block_hash);
    }
    for (size_t i = 0; i < hashes.size(); ++i) {
        if (i + 100 >= hashes.size())
            EXPECT_TRUE(mm.has_frozen_snapshot(98, hashes[i])) << "snapshot " << i << " of the last 100";
        else
            EXPECT_FALSE(mm.has_frozen_snapshot(98, hashes[i])) << "snapshot " << i << " is older";
    }
}
