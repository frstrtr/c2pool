// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc_template_hogex (rides share_test) -- LTC MWEB template KAT.
//
// Pins the embedded TemplateBuilder's MWEB shape (choke 3):
//   - a mempool selection cut by the max_weight budget still ends with the
//     HogEx and carries the mweb data and the "mweb" rule; coinbasevalue
//     counts only the fees of the transactions that ship;
//   - once MWEB is active (an MWEB block was seen, or the next height reaches
//     ChainParams::mweb_activation_height) a builder without MWEB state
//     returns nullopt -- never a HogEx-less "segwit"-only template; the
//     refused template it hands out still names "mweb", so core ingress and
//     block assembly both reject it as an LTC block;
//   - before activation the plain segwit template is unchanged;
//   - the activation heights are the ones litecoind's chain shows.
// max_weight is the seam the #1708 block-budget work rebases onto: its budget
// break sits inside the selection, the HogEx is appended after it.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/coin/mweb_shape.hpp>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/rpc_data.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/template_builder.hpp>

namespace {

using namespace ltc::coin;

uint256 h(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

MutableTransaction pay(const uint256& prev_hash, uint32_t prev_index, int64_t out_value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash  = prev_hash;
    in.prevout.index = prev_index;
    in.sequence      = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

BlockHeaderType mainnet_genesis()
{
    BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1317972665;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 2084524493;
    return g;
}

std::unique_ptr<HeaderChain> mainnet_chain_at_genesis()
{
    auto chain = std::make_unique<HeaderChain>(make_ltc_chain_params_mainnet());
    EXPECT_TRUE(chain->init());
    EXPECT_TRUE(chain->add_header(mainnet_genesis()));
    EXPECT_EQ(chain->height(), 0u);
    return chain;
}

// A chain whose tip is a fast-start checkpoint at `height` (no real headers)
// with block hash `tip_hash`.
std::unique_ptr<HeaderChain> mainnet_chain_at(
    uint32_t height,
    const uint256& tip_hash = h("00000000000000000000000000000000000000000000000000000000c0ffee01"))
{
    auto p = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = height;
    cp.hash = tip_hash;
    p.fast_start_checkpoint = cp;
    auto chain = std::make_unique<HeaderChain>(p);
    EXPECT_TRUE(chain->init());
    EXPECT_EQ(chain->height(), height);
    return chain;
}

// A distinct synthetic block header per tag, and its SHA256d block hash.
BlockHeaderType synthetic_header(uint32_t tag)
{
    BlockHeaderType hdr;
    hdr.m_version = 0x20000000;
    hdr.m_previous_block = h("00000000000000000000000000000000000000000000000000000000000000ee");
    hdr.m_merkle_root.SetNull();
    hdr.m_timestamp = 1600000000 + tag;
    hdr.m_bits = 0x1e0ffff0;
    hdr.m_nonce = tag;
    return hdr;
}

uint256 block_hash_of(const BlockHeaderType& hdr)
{
    auto packed = pack(hdr);
    return Hash(packed.get_span());
}

// Height of the synthetic MWEB chain tip used by the template KATs.
constexpr uint32_t kTipHeight = 1000;

// A synthetic MWEB block with header `hdr` at `height`: coinbase + HogEx whose
// first output is the HogAddr (OP_8 PUSH32 <hash>), plus the raw empty
// mw::Block.
void feed_tracker(MWEBTracker& tracker, uint32_t height, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    MutableTransaction cb;
    cb.version = 1;
    cb.locktime = 0;
    TxIn cin;
    cin.prevout.hash.SetNull();
    cin.prevout.index = 0xffffffff;
    cin.sequence = 0xffffffff;
    cb.vin.push_back(cin);
    TxOut cb_out;
    cb_out.value = 5000000000LL;
    cb.vout.push_back(cb_out);

    MutableTransaction hog;
    hog.version = 2;
    hog.locktime = 0;
    hog.m_hogEx = true;
    TxIn hin;
    hin.prevout.hash = h("4444444444444444444444444444444444444444444444444444444444444444");
    hin.prevout.index = 0;
    hin.sequence = 0xffffffff;
    hog.vin.push_back(hin);
    TxOut hout;
    hout.value = 123456789;
    hout.scriptPubKey.m_data.assign(34, 0x77);
    hout.scriptPubKey.m_data[0] = 0x58;  // OP_8
    hout.scriptPubKey.m_data[1] = 0x20;  // PUSH 32
    hog.vout.push_back(hout);

    b.m_txs = {cb, hog};

    PackStream ps;
    ps << MWEBBlock{};
    auto sp = ps.get_span();
    std::vector<unsigned char> raw(reinterpret_cast<const unsigned char*>(sp.data()),
                                   reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    ASSERT_TRUE(tracker.update(b, height, raw));
}

bool rules_have(const nlohmann::json& d, const std::string& rule)
{
    for (const auto& r : d["rules"])
        if (r == rule) return true;
    return false;
}

const uint256 FUND_A = h("00000000000000000000000000000000000000000000000000000000000000a1");
const uint256 FUND_B = h("00000000000000000000000000000000000000000000000000000000000000b2");
const uint256 FUND_C = h("00000000000000000000000000000000000000000000000000000000000000c3");

} // namespace

TEST(LtcTemplateHogex, MwebActivationHeightsPinned)
{
    // First block whose last tx is a HogEx, checked against both chains.
    EXPECT_EQ(make_ltc_chain_params_mainnet().mweb_activation_height, 2265984u);
    EXPECT_EQ(make_ltc_chain_params_testnet().mweb_activation_height, 2215584u);
}

// Case 1: the selection is cut by max_weight; the HogEx survives as the last
// tx and the fees of the cut txs are not in coinbasevalue.
TEST(LtcTemplateHogex, HogexSurvivesTruncation)
{
    const auto tip_hdr = synthetic_header(1);
    auto chain = mainnet_chain_at(kTipHeight, block_hash_of(tip_hdr));
    Mempool pool;
    MutableTransaction a = pay(FUND_A, 0, 100000);
    MutableTransaction b = pay(FUND_B, 0, 100000);
    MutableTransaction c = pay(FUND_C, 0, 100000);
    ASSERT_TRUE(pool.add_tx(a));
    ASSERT_TRUE(pool.add_tx(b));
    ASSERT_TRUE(pool.add_tx(c));
    pool.set_tx_fee(compute_txid(a), 1000);
    pool.set_tx_fee(compute_txid(b), 2000);
    pool.set_tx_fee(compute_txid(c), 3000);
    auto entry = pool.get_entry(compute_txid(c));
    ASSERT_TRUE(entry);
    const uint32_t one_tx_weight = entry->weight;

    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, tip_hdr);
    EXPECT_EQ(tracker.mweb_seen_height(), kTipHeight);

    // Uncut: all three mempool txs + HogEx.
    auto full = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(full);
    EXPECT_EQ(full->m_data["transactions"].size(), 4u);
    EXPECT_EQ(full->m_data["coinbasevalue"].get<int64_t>(), 5000000000LL + 6000);

    auto cut = TemplateBuilder::build_template(*chain, pool, false, &tracker, one_tx_weight + 10);
    ASSERT_TRUE(cut) << "a truncated selection is still a valid MWEB template";
    const auto& d = cut->m_data;
    ASSERT_EQ(d["transactions"].size(), 2u) << "highest-feerate tx + HogEx";
    const std::string last = d["transactions"].back()["data"].get<std::string>();
    EXPECT_TRUE(core::coin::tx_hex_is_hogex(last)) << "HogEx must stay the last tx";
    ASSERT_EQ(cut->m_txs.size(), 2u);
    EXPECT_TRUE(cut->m_txs.back().m_hogEx);
    EXPECT_FALSE(d["mweb"].get<std::string>().empty());
    EXPECT_TRUE(rules_have(d, "mweb"));
    EXPECT_EQ(d["coinbasevalue"].get<int64_t>(), 5000000000LL + 3000)
        << "coinbasevalue counts only the fees of the txs that ship";
    EXPECT_FALSE(core::coin::check_template_shape(d));
}

// Case 2: MWEB state invalidated (tip change / reorg). The chain is known to
// be MWEB-active, so the builder HOLDs (nullopt) instead of emitting a
// HogEx-less "segwit"-only template.
TEST(LtcTemplateHogex, InvalidatedStateNeverYieldsSegwitOnlyTemplate)
{
    const auto tip_hdr = synthetic_header(1);
    auto chain = mainnet_chain_at(kTipHeight, block_hash_of(tip_hdr));
    Mempool pool;
    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, tip_hdr);
    ASSERT_TRUE(TemplateBuilder::build_template(*chain, pool, false, &tracker));

    tracker.invalidate();
    EXPECT_FALSE(tracker.has_state());
    EXPECT_EQ(tracker.mweb_seen_height(), kTipHeight) << "invalidate() keeps the seen height";

    std::optional<ltc::coin::rpc::WorkData> refused;
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker,
                                              TemplateBuilder::MAX_BLOCK_WEIGHT
                                                  - TemplateBuilder::COINBASE_RESERVE,
                                              &refused);
    EXPECT_FALSE(wd) << "MWEB active without state: no valid template";

    // The refused template (what getwork hands to the ingress guard for HOLD
    // or a degraded start) still names MWEB and has no mweb data, so block
    // assembly refuses any LTC block built from it.
    ASSERT_TRUE(refused);
    EXPECT_TRUE(rules_have(refused->m_data, "mweb"));
    EXPECT_TRUE(refused->m_data["mweb"].get<std::string>().empty());
    EXPECT_TRUE(core::coin::check_template_shape(refused->m_data));
}

// Before activation, with no MWEB block seen, the plain segwit template is
// unchanged.
TEST(LtcTemplateHogex, PreActivationTemplateUnchanged)
{
    auto chain = mainnet_chain_at_genesis();
    Mempool pool;
    MWEBTracker tracker;  // never fed
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(wd);
    EXPECT_EQ(wd->m_data["rules"], nlohmann::json::array({"segwit"}));
    EXPECT_TRUE(wd->m_data["mweb"].get<std::string>().empty());
    EXPECT_FALSE(core::coin::check_template_shape(wd->m_data));
}

// The activation height alone makes MWEB active, even before the tracker has
// seen an MWEB block (e.g. a cold start right at the tip).
TEST(LtcTemplateHogex, ActivationHeightBoundary)
{
    Mempool pool;
    MWEBTracker tracker;  // never fed

    auto before = mainnet_chain_at(2265982);  // next block 2265983
    auto wd = TemplateBuilder::build_template(*before, pool, false, &tracker);
    ASSERT_TRUE(wd);
    EXPECT_FALSE(rules_have(wd->m_data, "mweb"));

    auto at = mainnet_chain_at(2265983);      // next block 2265984
    EXPECT_FALSE(TemplateBuilder::build_template(*at, pool, false, &tracker))
        << "next block must carry a HogEx; without MWEB state there is no template";
    EXPECT_FALSE(TemplateBuilder::build_template(*at, pool, false, nullptr));
}

// MWEB state must belong to the block the template builds on. Here the sync
// gate asked for tip N, the tip moved to N+1, and N's body landed afterwards:
// a HogEx built from N's state would spend N's HogEx output, which N+1 already
// spent, and would still pass the shape check. The builder treats such state
// as no state (refused -> HOLD at ingress) until N+1's own body arrives.
TEST(LtcTemplateHogex, StaleMwebStateIsNotUsed)
{
    Mempool pool;
    const auto hdr_n = synthetic_header(1);
    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, hdr_n);

    // Control: tip is N itself -> the state is used.
    {
        auto at_n = mainnet_chain_at(kTipHeight, block_hash_of(hdr_n));
        auto wd = TemplateBuilder::build_template(*at_n, pool, false, &tracker);
        ASSERT_TRUE(wd);
        EXPECT_TRUE(core::coin::tx_hex_is_hogex(
            wd->m_data["transactions"].back()["data"].get<std::string>()));
    }
    // Tip moved to N+1 -> refused.
    {
        auto at_n1 = mainnet_chain_at(kTipHeight + 1, block_hash_of(synthetic_header(2)));
        std::optional<ltc::coin::rpc::WorkData> refused;
        auto wd = TemplateBuilder::build_template(*at_n1, pool, false, &tracker,
                                                  TemplateBuilder::MAX_BLOCK_WEIGHT
                                                      - TemplateBuilder::COINBASE_RESERVE,
                                                  &refused);
        EXPECT_FALSE(wd) << "state from N must not build a HogEx on top of N+1";
        ASSERT_TRUE(refused);
        EXPECT_TRUE(refused->m_data["mweb"].get<std::string>().empty());
        EXPECT_TRUE(core::coin::check_template_shape(refused->m_data));
    }
    // Same height, different block (a competing N) -> refused.
    {
        auto other_n = mainnet_chain_at(kTipHeight, block_hash_of(synthetic_header(3)));
        EXPECT_FALSE(TemplateBuilder::build_template(*other_n, pool, false, &tracker));
    }
}
