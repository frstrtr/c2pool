// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ONE FIND -> THE SAME LTC ROW ON EVERY NODE (ltc/dashboard_found_block.hpp).
//
// LTC block 3211872 (84024db9...), found 2026-11-12 by a v0.2.12.4 node.
//   finder /recent_blocks: height 3211872, miner "", share 9497f877... (the
//          winner's PARENT share), found_by "unknown"
//   peers  /recent_blocks: height 27707625 (the share ABSHEIGHT), miner
//          "085cdff070d752d9e137e82396e387ec1641fd75" (raw, byte-reversed
//          pubkey hash), share 84024db9...
// Both rows now come from the share's own fields: row_from_share on the
// peers, row_from_submit (fed by the stratum submit that minted the share)
// on the finder. The share below is the real one, as /web/share serves it.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <btclibs/util/strencodings.h>
#include <nlohmann/json.hpp>

#include <core/found_block_submit.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <impl/ltc/dashboard_found_block.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>

using core::MiningInterface;

namespace {

const std::string kBlock  = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
const std::string kParent = "9497f877ae2d49aba9bf469a54777d97a813d29f78a715dacef97d3cf4fda1ad";
const std::string kDoge   = "da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb";
const std::string kMiner  = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";
const std::string kScriptSigHex =
    "036002312cfabe6d6dda2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb"
    "0100000000000000082f6332706f6f6c2f8950f2d18d7c1a7df35444ae7383d4e2f11cb808f0f974"
    "0506ef5d9a91f0f4e6";
constexpr uint32_t kTimestamp = 1794498365;
constexpr uint64_t kHeight    = 3211872;
constexpr uint32_t kAbsheight = 27707625;
constexpr uint64_t kSubsidy   = 625549157;     // gentx value 6.25549157 LTC
constexpr uint32_t kShareBits = 461335236;     // share_data.target

// The winning share (v36), field values.
ltc::MergedMiningShare field_share()
{
    ltc::MergedMiningShare s(uint256S(kBlock), uint256S(kParent));
    s.m_min_header.m_timestamp = kTimestamp;
    s.m_coinbase = BaseScript(ParseHex(kScriptSigHex));
    // The peers' raw miner value IS this field's GetHex().
    s.m_pubkey_hash.SetHex("085cdff070d752d9e137e82396e387ec1641fd75");
    s.m_pubkey_type = 0;   // P2PKH
    s.m_absheight = kAbsheight;
    s.m_subsidy = kSubsidy;
    s.m_bits = kShareBits;
    return s;
}

// What the stratum submit that minted the share hands over
// (MiningInterface::mining_submit -> make_found_block_submit_context).
core::FoundBlockSubmitContext finder_context(const ltc::MergedMiningShare& s)
{
    return core::make_found_block_submit_context(
        ltc::get_share_script(&s), /*is_litecoin=*/true, /*testnet=*/false,
        "login-address", uint256S(kBlock), s.m_coinbase.m_data, s.m_subsidy, s.m_bits);
}

nlohmann::json only_row(const nlohmann::json& arr)
{
    EXPECT_EQ(arr.size(), 1u) << arr.dump(1);
    return arr.empty() ? nlohmann::json(nullptr) : arr[0];
}

} // namespace

// The peer path: block height, rendered miner, the share's own hash.
TEST(LtcDashboardRow, PeerRowCarriesBlockFactsNotShareFacts)
{
    const auto s = field_share();
    const auto row = ltc::dashboard::row_from_share(uint256S(kBlock), s, /*testnet=*/false);
    EXPECT_EQ(row.height, kHeight) << "the BIP34 height, not the share absheight " << kAbsheight;
    EXPECT_EQ(row.miner, kMiner) << "the payout address, not raw pubkey-hash hex";
    EXPECT_EQ(row.share_hash, kBlock) << "p2pool: the share hash IS the block hash";
    EXPECT_EQ(row.block_hash.GetHex(), kBlock);
    EXPECT_EQ(row.timestamp, kTimestamp);
    EXPECT_EQ(row.chain, "LTC");
    EXPECT_EQ(row.subsidy, kSubsidy);
    EXPECT_GT(row.share_difficulty, 0.0);

    EXPECT_EQ(ltc::dashboard::row_from_share(uint256S(kBlock), s, /*testnet=*/true).chain, "tLTC");
}

// A v34/v35 share carries its address as a string.
TEST(LtcDashboardRow, V35ShareMinerIsTheAddressString)
{
    ltc::PaddingBugfixShare s(uint256S(kBlock), uint256S(kParent));
    s.m_min_header.m_timestamp = kTimestamp;
    s.m_coinbase = BaseScript(ParseHex(kScriptSigHex));
    s.m_address = BaseScript(std::string(kMiner));
    const auto row = ltc::dashboard::row_from_share(uint256S(kBlock), s, false);
    EXPECT_EQ(row.miner, kMiner);
    EXPECT_EQ(row.height, kHeight);
}

// The finder path builds the identical row from the stratum submit.
TEST(LtcDashboardRow, FinderRowEqualsPeerRow)
{
    const auto s = field_share();
    const auto peer = ltc::dashboard::row_from_share(uint256S(kBlock), s, false);
    const auto ctx = finder_context(s);
    for (uint64_t chain_height : {kHeight, uint64_t{0}}) {   // header chain known / not yet
        const auto finder = ltc::dashboard::row_from_submit(
            uint256S(kBlock), kTimestamp, chain_height, &ctx, false);
        EXPECT_EQ(finder.height, peer.height);
        EXPECT_EQ(finder.block_hash, peer.block_hash);
        EXPECT_EQ(finder.timestamp, peer.timestamp);
        EXPECT_EQ(finder.chain, peer.chain);
        EXPECT_EQ(finder.miner, peer.miner);
        EXPECT_EQ(finder.share_hash, peer.share_hash);
        EXPECT_DOUBLE_EQ(finder.share_difficulty, peer.share_difficulty);
        EXPECT_EQ(finder.subsidy, peer.subsidy);
    }
    // No stratum context (JSON-RPC submitblock): no share, no miner named.
    const auto rpc = ltc::dashboard::row_from_submit(uint256S(kBlock), kTimestamp, kHeight,
                                                     nullptr, false);
    EXPECT_TRUE(rpc.share_hash.empty());
    EXPECT_TRUE(rpc.miner.empty());
    EXPECT_EQ(rpc.height, kHeight);
}

// End to end through the dashboard: the finder (its submit + the DOGE solve
// it rode + the sharechain hook when the share verifies there, either order)
// and a peer (the hook only) serve the same LTC row; only the authorship
// differs, and the DOGE block is on the finder's merged list, not its
// Recent Blocks.
TEST(LtcDashboardRow, EveryNodeServesTheSameLtcRow)
{
    const auto s = field_share();
    const auto peer_row = ltc::dashboard::row_from_share(uint256S(kBlock), s, false);
    const auto ctx = finder_context(s);
    const auto finder_row = ltc::dashboard::row_from_submit(uint256S(kBlock), kTimestamp,
                                                            kHeight, &ctx, false);
    auto record = [](MiningInterface& mi, const ltc::dashboard::FoundBlockRow& r,
                     MiningInterface::BlockAuthorship who) {
        mi.record_found_block(r.height, r.block_hash, r.timestamp, r.chain, r.miner,
                              r.share_hash, 94729203.0, r.share_difficulty, 0.0,
                              r.subsidy, who);
    };
    auto record_doge = [](MiningInterface& mi) {
        MiningInterface::MergedSubmitContext m;
        m.parent_hash = kBlock;
        m.miner = kMiner;
        m.share_hash = kBlock;
        MiningInterface::MergedSubmitScope scope(std::move(m));
        mi.record_merged_found_block("DOGE", 6454700, kDoge, true, 1000117205332ULL);
    };

    MiningInterface peer(false, nullptr, c2pool::address::Blockchain::LITECOIN);
    record(peer, peer_row, MiningInterface::BlockAuthorship::sharechain_peer);
    const auto p = only_row(peer.rest_recent_blocks());
    ASSERT_TRUE(p.is_object());
    EXPECT_EQ(p["found_by"].get<std::string>(), "sharechain_peer");

    for (bool hook_first : {false, true}) {
        MiningInterface finder(false, nullptr, c2pool::address::Blockchain::LITECOIN);
        if (hook_first)
            record(finder, peer_row, MiningInterface::BlockAuthorship::sharechain_peer);
        record(finder, finder_row, MiningInterface::BlockAuthorship::this_node);
        record_doge(finder);
        if (!hook_first)
            record(finder, peer_row, MiningInterface::BlockAuthorship::sharechain_peer);

        const auto f = only_row(finder.rest_recent_blocks());
        ASSERT_TRUE(f.is_object());
        EXPECT_EQ(f["found_by"].get<std::string>(), "this_node");
        for (const char* k : {"chain", "hash", "height", "number", "miner", "share",
                              "ts", "subsidy", "share_difficulty", "explorer_url"})
            EXPECT_EQ(f[k], p[k]) << k << (hook_first ? " (hook first)" : " (submit first)");
        EXPECT_EQ(f["height"].get<uint64_t>(), kHeight);
        EXPECT_EQ(f["miner"].get<std::string>(), kMiner);
        EXPECT_EQ(f["share"].get<std::string>(), kBlock);

        bool doge_listed = false;
        for (const auto& m : finder.rest_recent_merged_blocks())
            if (m.value("pow_hash", std::string()) == kDoge) {
                doge_listed = true;
                EXPECT_EQ(m["parent_hash"].get<std::string>(), kBlock);
                EXPECT_EQ(m["miner"].get<std::string>(), kMiner);
                EXPECT_EQ(m["height"].get<int>(), 6454700);
            }
        EXPECT_TRUE(doge_listed);
    }
}
