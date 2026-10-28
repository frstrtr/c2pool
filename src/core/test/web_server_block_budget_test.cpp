// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// KATs for the LTC block weight on the shared-core submit path
// (core::MiningInterface): litecoind refuses a block above 4,000,000 weight
// (bad-blk-weight, validation.cpp:3756; GetBlockWeight consensus/validation.h
// :165-168). A template filled to 4,000,000 - 2,000 with a PPLNS coinbase of
// up to max_coinbase_outputs = 4,000 outputs (about 136 kB, 544 kWU) is
// above it: a block found on it is lost.
//
//   LtcTemplateBudget.FullTemplateWithLargeCoinbaseStaysUnder4MWU: a 4,000
//     output coinbase, then a REAL ltc::coin::TemplateBuilder template over a
//     mempool holding more than 4 MWU, selected within the budget the
//     embedded node uses (EmbeddedCoinNode::tx_weight_budget over
//     MiningInterface::coinbase_weight_reserve); the block found on it is
//     submitted and weighs at most 4,000,000 (weighed here independently, by
//     parsing the submitted bytes).
//   LtcBlockWeight.OversizeBlockIsRefusedAtAssembly: a job whose block would
//     weigh more than 4,000,000 never reaches the daemon; it is counted under
//     "oversize". One just under the limit is submitted.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <btclibs/util/strencodings.h>
#include <crypto/scrypt.h>

namespace {

using core::MiningInterface;

struct MockCoinNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    std::vector<uint256> hashes;
    int submit_calls = 0;
    std::string last_submitted_hex;

    core::coin::WorkView get_work_view() override {
        core::coin::WorkView v;
        v.m_data = work_data;
        v.m_hashes = hashes;
        return v;
    }
    bool submit_block_hex(const std::string& block_hex, bool) override {
        ++submit_calls;
        last_submitted_hex = block_hex;
        return true;
    }
    bool is_embedded() const override { return true; }
    bool has_rpc() const override { return true; }
};

const std::string kEn1   = "aabbccdd";
const std::string kEn2   = "00000001";
const std::string kNtime = "5f5e1000";
const std::string kBits  = "207fffff";
constexpr uint32_t kVersion = 0x20000000u;

std::string to_hex(const std::vector<unsigned char>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

uint256 scrypt_of(const std::vector<unsigned char>& header)
{
    char out[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), out);
    uint256 r;
    std::memcpy(r.begin(), out, 32);
    return r;
}

std::string find_nonce(const std::string& prev_hex, const uint256& merkle_root)
{
    const uint256 target = chain::bits_to_target(0x207fffffu);
    for (uint32_t n = 0; n < 10000; ++n) {
        char buf[9];
        std::snprintf(buf, sizeof(buf), "%08x", n);
        auto h = MiningInterface::build_header_bytes(kVersion, prev_hex, merkle_root, kNtime, kBits, buf);
        if (h.size() == 80 && scrypt_of(h) <= target)
            return buf;
    }
    ADD_FAILURE() << "no nonce met the block target";
    return "00000000";
}

/// A legacy tx: one input (`tag`, `index` make it distinct) and `outputs`
/// P2PKH outputs, about 34 bytes each.
ltc::coin::MutableTransaction big_tx(uint8_t tag, uint32_t index, size_t outputs)
{
    ltc::coin::MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    ltc::coin::TxIn in;
    for (int i = 0; i < 32; ++i)
        in.prevout.hash.data()[i] = static_cast<uint8_t>(tag + i);
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    for (size_t k = 0; k < outputs; ++k) {
        ltc::coin::TxOut out;
        out.value = 1000 + static_cast<int64_t>(k);
        out.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i)
            out.scriptPubKey.m_data.push_back(static_cast<unsigned char>(k + i));
        out.scriptPubKey.m_data.push_back(0x88);
        out.scriptPubKey.m_data.push_back(0xac);
        tx.vout.push_back(out);
    }
    return tx;
}

std::string tx_hex(const ltc::coin::MutableTransaction& tx)
{
    auto packed = pack(ltc::coin::TX_NO_WITNESS(tx));
    return HexStr(packed.get_span());
}

/// GetBlockWeight of a submitted block, weighed independently of production
/// code: every tx re-serialized without witness (x3) plus the block bytes
/// (no MWEB data here: x1).
uint64_t weigh_block(const std::string& block_hex)
{
    auto bytes = ParseHex(block_hex);
    PackStream ps(bytes);
    ltc::coin::BlockType b;
    ps >> b;
    uint64_t stripped = 80;
    const size_t n = b.m_txs.size();
    stripped += n < 0xfd ? 1 : 3;
    for (const auto& tx : b.m_txs)
        stripped += pack(ltc::coin::TX_NO_WITNESS(tx)).get_span().size();
    return stripped * 3 + bytes.size();
}

/// PPLNS of `n` distinct P2PKH payees, the subsidy split evenly.
MiningInterface::pplns_fn_t pplns_of(size_t n)
{
    return [n](const uint256&, const uint256&, uint64_t subsidy,
               const std::vector<unsigned char>&) {
        std::map<std::vector<unsigned char>, double> out;
        for (size_t i = 0; i < n; ++i) {
            std::vector<unsigned char> s{0x76, 0xa9, 0x14};
            for (int k = 0; k < 20; ++k)
                s.push_back(static_cast<unsigned char>((i >> (8 * (k % 4))) + k));
            s.push_back(0x88);
            s.push_back(0xac);
            out[s] = static_cast<double>(subsidy / n);
        }
        return out;
    };
}

void stub_ref_hash(MiningInterface& mi)
{
    mi.set_ref_hash_fn([](const uint256&, const std::vector<unsigned char>&,
                          const std::vector<unsigned char>&, uint64_t, uint32_t, uint32_t,
                          bool, const std::string&, const uint256&,
                          const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                          const std::vector<uint256>&) {
        MiningInterface::RefHashResult r;
        r.ref_hash.SetHex(std::string(64, '5'));
        r.bits = 0x207fffff;
        return r;
    });
}

struct Frozen {
    MiningInterface::JobSnapshot snap;
    std::string nonce;
};

Frozen freeze(MiningInterface& mi, const uint256& best, const std::string& prev)
{
    const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
    auto cbr = mi.build_connection_coinbase(best, kEn1, payout, {});
    EXPECT_FALSE(cbr.coinb1.empty());
    Frozen j;
    j.snap.coinb1 = cbr.coinb1;
    j.snap.coinb2 = cbr.coinb2;
    j.snap.gbt_prevhash = prev;
    j.snap.nbits = kBits;
    j.snap.block_nbits = kBits;
    j.snap.version = kVersion;
    j.snap.merkle_branches = cbr.snapshot.merkle_branches;
    j.snap.tx_data = cbr.snapshot.tx_data;
    j.snap.mweb = cbr.snapshot.mweb;
    j.snap.mweb_active = cbr.snapshot.mweb_active;
    j.snap.degraded = cbr.snapshot.degraded;
    j.snap.segwit_active = cbr.snapshot.segwit_active;
    const uint256 root = MiningInterface::reconstruct_merkle_root(
        j.snap.coinb1 + kEn1 + kEn2 + j.snap.coinb2, j.snap.merkle_branches);
    j.nonce = find_nonce(prev, root);
    return j;
}

ltc::coin::BlockHeaderType ltc_testnet_genesis()
{
    ltc::coin::BlockHeaderType g;
    g.m_version = 1;
    g.m_previous_block.SetNull();
    g.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    g.m_timestamp = 1486949366;
    g.m_bits = 0x1e0ffff0;
    g.m_nonce = 293345;
    return g;
}

uint64_t refusals(const MiningInterface& mi, const std::string& code)
{
    const auto j = mi.get_mweb_refusals_by_code_json();
    return j.contains(code) ? j[code].get<uint64_t>() : 0;
}

} // namespace

TEST(LtcTemplateBudget, FullTemplateWithLargeCoinbaseStaysUnder4MWU)
{
    MiningInterface mi{/*testnet=*/true};
    MockCoinNode node;
    mi.set_coin_node(&node);
    stub_ref_hash(mi);
    uint256 best;
    best.SetHex(std::string(63, '0') + "7");
    mi.set_best_share_hash_fn([best]() { return best; });
    mi.set_pplns_fn(pplns_of(4000));

    // The chain: LTC testnet genesis (the template builds height 1 on it).
    ltc::coin::HeaderChain chain(ltc::coin::make_ltc_chain_params_testnet());
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(ltc_testnet_genesis()));
    const auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    const std::string prev = tip->block_hash.GetHex();

    // A first template (no txs): its coinbase carries the 4,000 payees.
    node.work_data = {
        {"previousblockhash", prev}, {"version", kVersion}, {"height", 1},
        {"bits", kBits}, {"curtime", 1600000000}, {"coinbasevalue", 5000000000LL},
        {"transactions", nlohmann::json::array()}, {"rules", nlohmann::json::array({"segwit"})},
    };
    mi.refresh_work();
    const uint32_t reserve = mi.coinbase_weight_reserve();
    EXPECT_GT(reserve, 4000u * 34 * 4) << "the 4,000-output coinbase is reserved";

    // A mempool holding more than 4 MWU, every tx priced.
    ltc::coin::Mempool pool;
    for (uint32_t i = 0; i < 420; ++i) {
        auto tx = big_tx(static_cast<uint8_t>(i), i, 290);   // ~9.9 kB, ~39.5 kWU
        ASSERT_TRUE(pool.add_tx_unchecked(tx));
        pool.set_tx_fee(ltc::coin::compute_txid(tx), 10000 + i);
    }
    {
        ltc::coin::BlockType g;
        static_cast<ltc::coin::BlockHeaderType&>(g) = ltc_testnet_genesis();
        pool.remove_for_block(g);   // cleaned for the tip
    }

    // The embedded node's budget over the web server's reserve, then the
    // template it builds.
    ltc::coin::EmbeddedCoinNode embedded(chain, pool, /*testnet=*/true);
    embedded.set_coinbase_reserve_fn([&mi]() { return mi.coinbase_weight_reserve(); });
    std::optional<ltc::coin::rpc::WorkData> refused;
    auto wd = ltc::coin::TemplateBuilder::build_template(
        chain, pool, /*is_testnet=*/true, nullptr, embedded.tx_weight_budget(), &refused);
    ASSERT_TRUE(wd.has_value()) << (refused ? refused->m_data.dump().substr(0, 200) : "no template");
    ASSERT_GT(wd->m_data["transactions"].size(), 50u);

    // The web server takes it, builds the coinbase, a miner finds a block.
    node.work_data = wd->m_data;
    node.hashes = wd->m_hashes;
    mi.refresh_work();
    auto j = freeze(mi, best, prev);
    mi.mining_submit("budget-kat-miner", "j1", kEn1, kEn2, kNtime, j.nonce, "1", {}, &j.snap);

    ASSERT_EQ(node.submit_calls, 1) << "the block reached the daemon (oversize refusals: "
                                    << refusals(mi, "oversize") << ")";
    const uint64_t weight = weigh_block(node.last_submitted_hex);
    EXPECT_LE(weight, 4000000u) << "bad-blk-weight";
    EXPECT_GT(weight, 3800000u) << "the template is still full";
}

TEST(LtcBlockWeight, OversizeBlockIsRefusedAtAssembly)
{
    auto run = [](size_t n_tx, int& submits, uint64_t& oversize) {
        MiningInterface mi{/*testnet=*/true};
        MockCoinNode node;
        mi.set_coin_node(&node);
        std::vector<std::string> txs, txids;
        for (size_t i = 0; i < n_tx; ++i) {
            auto tx = big_tx(static_cast<uint8_t>(i), static_cast<uint32_t>(i), 290);
            txs.push_back(tx_hex(tx));
            txids.push_back(ltc::coin::compute_txid(tx).GetHex());
        }
        MiningInterface::JobSnapshot snap;
        snap.coinb1 = "01000000" "01" + std::string(64, '0') + "ffffffff" "08";
        snap.coinb2 = "ffffffff" "01" "00f2052a01000000" "00" "00000000";
        const std::string prev = std::string(62, '0') + "ab";
        snap.gbt_prevhash = prev;
        snap.nbits = kBits;
        snap.block_nbits = kBits;
        snap.version = kVersion;
        snap.merkle_branches = MiningInterface::compute_merkle_branches(txids);
        snap.tx_data = std::make_shared<std::vector<std::string>>(txs);
        snap.segwit_active = true;
        const uint256 root = MiningInterface::reconstruct_merkle_root(
            snap.coinb1 + kEn1 + kEn2 + snap.coinb2, snap.merkle_branches);
        const std::string nonce = find_nonce(prev, root);
        mi.mining_submit("weight-kat-miner", "j1", kEn1, kEn2, kNtime, nonce, "1", {}, &snap);
        submits = node.submit_calls;
        oversize = refusals(mi, "oversize");
    };
    // 102 txs of ~9.9 kB: ~4.04 MWU. 100: ~3.96 MWU.
    int submits = 0;
    uint64_t oversize = 0;
    run(102, submits, oversize);
    EXPECT_EQ(submits, 0) << "a block above 4,000,000 weight never reaches the daemon";
    EXPECT_EQ(oversize, 1u);
    run(100, submits, oversize);
    EXPECT_EQ(submits, 1) << "under the limit: submitted";
    EXPECT_EQ(oversize, 0u);
}
