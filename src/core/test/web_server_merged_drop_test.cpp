// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The share side follows the merged commitment (rides core_test).
//
// When the merged-mining manager has no buildable DOGE block (no payouts for
// the new parent) it drops the chain from the commitment. The stratum job
// built meanwhile must then carry neither the commitment (mm_data in the LTC
// coinbase) nor the merged header info the share puts in its V36
// merged_coinbase_info. build_connection_coinbase used to fall back to the
// commitment refresh_work cached (resurrecting the dropped one) and kept the
// previous header infos when the fresh read was empty: after the next
// refresh_work the share claimed the previous DOGE block while its coinbase
// had no mm_data, which a V36 peer rejects ("merged_coinbase_info present but
// no mm_data marker", share_check.hpp verify_merged_coinbase_commitment,
// p2pool data.py). Checked through the real MiningInterface and
// MergedMiningManager: at every step, infos present <=> mm_data present, and
// the committed root is the hash of the info's header.
// Folded into the allowlisted core_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using core::MiningInterface;
using c2pool::merged::MergedMiningManager;
using Payouts = std::vector<std::pair<std::vector<unsigned char>, uint64_t>>;

struct LtcNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    core::coin::WorkView get_work_view() override
    {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

/// The embedded DOGE backend's shape: the work's block hash is its tip.
struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
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
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", 5'000'001}, {"bits", "1a01d2c3"},
            {"curtime", 1793210000}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    DogeBackend* doge{nullptr};
    LtcNode ltc;
    MiningInterface mi{/*testnet=*/true};
    bool payouts{true};
    // What ref_hash_fn saw (it copies these into the share's merged_coinbase_info).
    std::vector<MiningInterface::CachedMergedHeaderInfo> share_infos;

    Rig()
    {
        auto backend = std::make_unique<DogeBackend>();
        doge = backend.get();
        mm.add_chain(doge->cfg, std::move(backend));
        mm.set_payout_provider([this](uint32_t, uint64_t value) -> Payouts {
            if (!payouts) {
                MergedMiningManager::note_payout_miss("tracker_busy");
                return {};
            }
            std::vector<unsigned char> s{0x76, 0xa9, 0x14};
            s.insert(s.end(), 20, 0x5c);
            s.push_back(0x88);
            s.push_back(0xac);
            return {{s, value}};
        });
        ltc.work_data = {
            {"previousblockhash", std::string(62, '0') + "ab"}, {"version", 0x20000000},
            {"height", 100}, {"bits", "207fffff"}, {"curtime", 1600000000},
            {"coinbasevalue", 5000000000LL}, {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array({"csv", "!segwit", "taproot"})},
        };
        mi.set_coin_node(&ltc);
        mi.set_merged_mining_manager(&mm);
        mi.set_ref_hash_fn([this](const uint256&, const std::vector<unsigned char>&,
                                  const std::vector<unsigned char>&, uint64_t, uint32_t, uint32_t,
                                  bool, const std::string&, const uint256&,
                                  const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                                  const std::vector<uint256>&) {
            share_infos = mi.get_last_merged_header_infos();
            MiningInterface::RefHashResult r;
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = 0x207fffff;
            return r;
        });
    }

    /// A stratum job: the coinbase hex, with share_infos set as the share gets them.
    std::string job()
    {
        const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
        share_infos.clear();
        auto cbr = mi.build_connection_coinbase(uint256(), "aabbccdd", payout, {});
        EXPECT_FALSE(cbr.coinb1.empty());
        return cbr.coinb1 + cbr.coinb2;
    }
};

/// The merged root the coinbase commits to; null when it has no mm_data.
uint256 mm_root(const std::string& coinbase_hex)
{
    uint256 r;
    const auto pos = coinbase_hex.find("fabe6d6d");
    if (pos == std::string::npos || pos + 8 + 64 > coinbase_hex.size())
        return r;
    r.SetHex(coinbase_hex.substr(pos + 8, 64));   // stored big-endian
    return r;
}

/// The V36 rule a peer applies to the share: merged_coinbase_info only with
/// mm_data, and the (single-chain) root is the hash of the info's header.
void expect_share_matches_coinbase(const std::string& coinbase_hex,
                                   const std::vector<MiningInterface::CachedMergedHeaderInfo>& infos,
                                   const char* when)
{
    const uint256 root = mm_root(coinbase_hex);
    if (infos.empty()) {
        EXPECT_TRUE(root.IsNull()) << when << ": mm_data without merged_coinbase_info";
        return;
    }
    ASSERT_FALSE(root.IsNull()) << when << ": merged_coinbase_info present but no mm_data";
    ASSERT_EQ(infos.size(), 1u) << when;
    ASSERT_EQ(infos[0].block_header.size(), 80u) << when;
    EXPECT_EQ(Hash(infos[0].block_header), root)
        << when << ": merged block hash != committed root";
}

} // namespace

TEST(MergedShareSide, DroppedCommitmentLeavesNeitherMmDataNorMergedInfo)
{
    Rig r;
    r.mm.refresh_aux_work();
    const uint256 a = r.mm.get_current_work().at(98).block_hash;
    ASSERT_FALSE(a.IsNull());
    r.mi.refresh_work();
    std::string cb = r.job();
    EXPECT_EQ(mm_root(cb), a) << "a built block is committed";
    ASSERT_EQ(r.share_infos.size(), 1u);
    expect_share_matches_coinbase(cb, r.share_infos, "built");

    // A new DOGE tip with no payouts: the manager drops the chain.
    r.payouts = false;
    r.doge->tip = std::string(62, '0') + "c2";
    r.mm.refresh_aux_work();
    ASSERT_TRUE(r.mm.get_auxpow_commitment().empty());

    // A job before the work refresh: no mm_data (not the commitment
    // refresh_work cached for the old parent) and no merged info.
    cb = r.job();
    EXPECT_TRUE(mm_root(cb).IsNull()) << "the dropped commitment came back in the coinbase";
    EXPECT_TRUE(r.share_infos.empty()) << "the share claims the previous DOGE block";
    expect_share_matches_coinbase(cb, r.share_infos, "dropped, before refresh_work");

    // After the (debounced) work refresh: still neither.
    r.mi.refresh_work();
    cb = r.job();
    EXPECT_TRUE(mm_root(cb).IsNull());
    EXPECT_TRUE(r.share_infos.empty()) << "merged_coinbase_info without mm_data";
    expect_share_matches_coinbase(cb, r.share_infos, "dropped, after refresh_work");

    // Payouts back: the new block is committed and claimed, together.
    r.payouts = true;
    r.mm.refresh_aux_work();
    const uint256 b = r.mm.get_current_work().at(98).block_hash;
    ASSERT_FALSE(b.IsNull());
    ASSERT_NE(b, a);
    cb = r.job();
    EXPECT_EQ(mm_root(cb), b);
    expect_share_matches_coinbase(cb, r.share_infos, "built again");
}
