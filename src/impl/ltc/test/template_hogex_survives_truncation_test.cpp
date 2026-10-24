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
//
// The template's transactions (PR-L3):
//   - txs with an MWEB part (the real peg-in and peg-out mempool txs) never
//     reach it: the HogEx is its only flag-0x08 entry, every entry has inputs
//     and outputs and no pegin output, coinbasevalue = subsidy + listed fees;
//     a tx no block can carry that got into the pool anyway is dropped and
//     counted (template_tx_dropped);
//   - a non-empty mempool not yet cleaned for the tip (remove_for_block has
//     not seen the tip's body) refuses the template:
//     mempool-not-cleaned-for-tip, marked for the ingress HOLD.
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

#include <btclibs/util/strencodings.h>

#include "ltc_mweb_tx_fixtures.hpp"

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

// Run `hdr`'s (empty) block body through the pool's cleanup, as the
// full-block handler does before the tip's template is built.
void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

MutableTransaction parse_tx(const char* hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
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
    clean_for(pool, tip_hdr);

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

// The real peg-in and peg-out mempool txs never reach a template: only the
// three ordinary txs and the HogEx ship, and the template is one litecoind
// can accept structurally.
TEST(LtcTemplateHogex, MwebCarryingTxsNeverReachTheTemplate)
{
    namespace fx = ltc_mweb_tx_fixture;
    const auto tip_hdr = synthetic_header(1);
    auto chain = mainnet_chain_at(kTipHeight, block_hash_of(tip_hdr));
    Mempool pool;
    const MutableTransaction a = pay(FUND_A, 0, 100000);
    const MutableTransaction b = pay(FUND_B, 0, 100000);
    const MutableTransaction c = pay(FUND_C, 0, 100000);
    for (const auto* t : {&a, &b, &c})
        ASSERT_TRUE(pool.add_tx(*t));
    pool.set_tx_fee(compute_txid(a), 1000);
    pool.set_tx_fee(compute_txid(b), 2000);
    pool.set_tx_fee(compute_txid(c), 3000);

    const MutableTransaction pegin = parse_tx(fx::kPeginTxHex);
    const MutableTransaction pegout = parse_tx(fx::kPegoutTxHex);
    ASSERT_TRUE(pegin.HasMWEBTx());
    ASSERT_TRUE(pegout.IsMWEBOnly());
    EXPECT_FALSE(pool.add_tx(pegin));
    EXPECT_FALSE(pool.add_tx(pegout));
    pool.set_tx_fee(compute_txid(pegin), 4064);   // no-ops: not in the pool
    pool.set_tx_fee(compute_txid(pegout), 2262);
    EXPECT_EQ(pool.size(), 3u);

    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, tip_hdr);
    clean_for(pool, tip_hdr);
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(wd);
    const auto& txs = wd->m_data["transactions"];
    ASSERT_EQ(txs.size(), 4u) << "three ordinary txs + HogEx";
    int64_t fees = 0;
    for (size_t i = 0; i < txs.size(); ++i) {
        const MutableTransaction t = parse_tx(txs[i]["data"].get<std::string>().c_str());
        EXPECT_FALSE(t.vin.empty()) << i;
        EXPECT_FALSE(t.vout.empty()) << i;
        EXPECT_FALSE(t.HasMWEBTx()) << i;
        EXPECT_EQ(t.m_hogEx, i + 1 == txs.size()) << "the HogEx is the only flag-0x08 entry and last";
        for (const auto& out : t.vout)
            EXPECT_FALSE(mweb_wire::pegin_kernel_of(out.scriptPubKey)) << i;
        EXPECT_NE(txs[i]["txid"].get<std::string>(), compute_txid(pegin).GetHex());
        EXPECT_NE(txs[i]["txid"].get<std::string>(), compute_txid(pegout).GetHex());
        if (txs[i].contains("fee") && txs[i]["fee"].is_number_integer())
            fees += txs[i]["fee"].get<int64_t>();
    }
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>(), 5000000000LL + fees);
    EXPECT_EQ(fees, 6000);
    EXPECT_EQ(pool.reject_stats().template_tx_dropped.load(), 0u);
}

// A tx no block can carry that got into the pool anyway (here: past the
// admission rules) is dropped from the template and counted.
TEST(LtcTemplateHogex, TxNoBlockCanCarryIsDroppedAndCounted)
{
    namespace fx = ltc_mweb_tx_fixture;
    const auto tip_hdr = synthetic_header(1);
    auto chain = mainnet_chain_at(kTipHeight, block_hash_of(tip_hdr));
    Mempool pool;
    const MutableTransaction a = pay(FUND_A, 0, 100000);
    ASSERT_TRUE(pool.add_tx(a));
    pool.set_tx_fee(compute_txid(a), 1000);
    const MutableTransaction pegout = parse_tx(fx::kPegoutTxHex);
    ASSERT_TRUE(pool.add_tx_unchecked(pegout));
    pool.set_tx_fee(compute_txid(pegout), 2262);  // selectable as far as fees go

    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, tip_hdr);
    clean_for(pool, tip_hdr);
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(wd);
    const auto& txs = wd->m_data["transactions"];
    ASSERT_EQ(txs.size(), 2u) << "the ordinary tx + HogEx";
    EXPECT_EQ(txs[0]["txid"].get<std::string>(), compute_txid(a).GetHex());
    EXPECT_EQ(wd->m_data["coinbasevalue"].get<int64_t>(), 5000000000LL + 1000);
    EXPECT_EQ(pool.reject_stats().template_tx_dropped.load(), 1u);
}

// The first template on a new tip waits for the mempool cleanup of the tip's
// body: a non-empty pool not cleaned for the tip refuses the template (HOLD
// at ingress); once remove_for_block saw the tip it builds. A late copy of an
// older block cleaned afterwards does not undo it.
TEST(LtcTemplateHogex, MempoolNotCleanedForTipRefuses)
{
    const auto hdr_n = synthetic_header(1);
    const auto hdr_n1 = synthetic_header(2);
    auto chain = mainnet_chain_at(kTipHeight, block_hash_of(hdr_n));
    Mempool pool;
    const MutableTransaction a = pay(FUND_A, 0, 100000);
    ASSERT_TRUE(pool.add_tx(a));
    pool.set_tx_fee(compute_txid(a), 1000);
    MWEBTracker tracker;
    feed_tracker(tracker, kTipHeight, hdr_n);

    // Never cleaned.
    std::optional<ltc::coin::rpc::WorkData> refused;
    auto wd = TemplateBuilder::build_template(*chain, pool, false, &tracker,
                                              TemplateBuilder::MAX_BLOCK_WEIGHT
                                                  - TemplateBuilder::COINBASE_RESERVE,
                                              &refused);
    EXPECT_FALSE(wd) << "the pool may still hold txs the tip confirmed";
    ASSERT_TRUE(refused);
    EXPECT_EQ(core::coin::template_refusal_code(refused->m_data),
              std::optional<std::string>("mempool-not-cleaned-for-tip"));
    EXPECT_TRUE(core::coin::check_template_shape(refused->m_data)) << "ingress HOLDs it";

    // Cleaned for another block only.
    clean_for(pool, hdr_n1);
    EXPECT_EQ(pool.last_block_hash(), block_hash_of(hdr_n1));
    EXPECT_FALSE(TemplateBuilder::build_template(*chain, pool, false, &tracker));

    // Cleaned for the tip.
    clean_for(pool, hdr_n);
    EXPECT_TRUE(pool.cleaned_for(block_hash_of(hdr_n)));
    wd = TemplateBuilder::build_template(*chain, pool, false, &tracker);
    ASSERT_TRUE(wd);
    EXPECT_FALSE(core::coin::template_refusal_code(wd->m_data));
    EXPECT_EQ(wd->m_data["transactions"].size(), 2u);

    // A late copy of another block cleaned after the tip's.
    clean_for(pool, synthetic_header(3));
    EXPECT_TRUE(TemplateBuilder::build_template(*chain, pool, false, &tracker));

    // An empty pool needs no cleanup.
    Mempool empty;
    EXPECT_TRUE(TemplateBuilder::build_template(*chain, empty, false, &tracker));
}
