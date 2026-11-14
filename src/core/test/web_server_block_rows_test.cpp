// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ONE FIND, ONE STORY ON EVERY NODE: /recent_blocks vs /recent_merged_blocks.
//
// Field data (outside operator, v0.2.12.4, 2026-11-12): one find, LTC block
// 3211872 (84024db9...) carrying DOGE block 6454700 (da2714c8...), miner
// LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F.
//
//   FINDER /recent_blocks: TWO rows -- the DOGE block as a "Recent Blocks" row
//          (explorer_url pointing at blockchair/litecoin, which cannot resolve
//          a DOGE id) and the LTC row naming the PARENT share (9497f877...).
//   FINDER /recent_merged_blocks: [] after a restart.
//   PEERS  /recent_blocks: one LTC row; /recent_merged_blocks: the DOGE block.
//
// The merged (aux) find rides the found-block ledger on the finder (it is
// verified and persisted there), so every reader of that ledger must tell a
// parent-chain row from an aux row. These KATs use only the public API that
// predates the fix, so each one also runs -- and fails -- against the old
// web_server.cpp (red on master).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cctype>
#include <cmath>
#include <ctime>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <core/web_server.hpp>

using core::MiningInterface;

namespace {

// The 2026-11-12 find.
const std::string kLtcBlock  = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
const std::string kParentShr = "9497f877ae2d49aba9bf469a54777d97a813d29f78a715dacef97d3cf4fda1ad";
const std::string kDogeBlock = "da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb";
const std::string kMiner     = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";
constexpr uint64_t kLtcHeight  = 3211872;
constexpr uint64_t kDogeHeight = 6454700;
constexpr uint64_t kAbsheight  = 27707625;

nlohmann::json find_row(const nlohmann::json& arr, const std::string& key,
                        const std::string& value)
{
    for (const auto& b : arr)
        if (b.contains(key) && b[key].is_string() && b[key].get<std::string>() == value)
            return b;
    return nlohmann::json(nullptr);
}

// The finder's records of the find: the LTC block from the block-submitted
// callback, the DOGE block from the merged-found callback inside the stratum
// submit (the MergedSubmitScope names the parent block and the share).
void record_the_find(MiningInterface& mi)
{
    mi.record_found_block(kLtcHeight, uint256S(kLtcBlock), 1794498365, "LTC",
                          kMiner, kLtcBlock, 94729203.0, 514.33, 0.0, 625549157,
                          MiningInterface::BlockAuthorship::this_node);
    MiningInterface::MergedSubmitContext ctx;
    ctx.parent_hash = kLtcBlock;
    ctx.miner = kMiner;
    ctx.share_hash = kLtcBlock;
    MiningInterface::MergedSubmitScope scope(std::move(ctx));
    mi.record_merged_found_block("DOGE", static_cast<int>(kDogeHeight), kDogeBlock,
                                 /*accepted=*/true, 1000117205332ULL);
}

} // namespace

// Requirement 1: a merged block is never a "Recent Blocks" row.
TEST(FoundBlockRows, MergedFindIsNotARecentBlocksRow)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    record_the_find(mi);

    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 1u)
        << "the finder listed the DOGE block as a second Recent Blocks row:\n"
        << recent.dump(1);
    EXPECT_EQ(recent[0]["chain"].get<std::string>(), "LTC");
    EXPECT_EQ(recent[0]["hash"].get<std::string>(), kLtcBlock);
    EXPECT_TRUE(find_row(recent, "hash", kDogeBlock).is_null());

    // /found_block/<hash> still answers for the aux block -- with its own
    // chain's explorer, never the parent's.
    const auto doge = mi.rest_found_block(kDogeBlock);
    ASSERT_TRUE(doge.is_object());
    ASSERT_TRUE(doge["explorer_url"].is_string());
    EXPECT_EQ(doge["explorer_url"].get<std::string>(),
              "https://blockchair.com/dogecoin/block/" + kDogeBlock);
}

// Requirement 1: the finder's own merged find is on /recent_merged_blocks,
// with the facts its peers show (they read them off the share).
TEST(FoundBlockRows, FinderListsItsOwnMergedFind)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    record_the_find(mi);

    const auto merged = mi.rest_recent_merged_blocks();
    const auto row = find_row(merged, "pow_hash", kDogeBlock);
    ASSERT_TRUE(row.is_object())
        << "the finder's merged list did not hold the DOGE block it found:\n"
        << merged.dump(1);
    EXPECT_EQ(row["symbol"].get<std::string>(), "DOGE");
    EXPECT_EQ(row["network"].get<std::string>(), "DOGE");
    EXPECT_EQ(row["height"].get<uint64_t>(), kDogeHeight);
    EXPECT_EQ(row["parent_hash"].get<std::string>(), kLtcBlock);
    EXPECT_EQ(row["miner"].get<std::string>(), kMiner);
    EXPECT_EQ(row["explorer_url"].get<std::string>(),
              "https://blockchair.com/dogecoin/block/" + kDogeBlock);
    EXPECT_FALSE(find_row(merged, "pow_hash", kLtcBlock).is_object())
        << "a parent block is not a merged block";
}

// The "Recent Blocks" count, the first-row pool-luck aggregate and the luck
// series count parent blocks only.
TEST(FoundBlockRows, LuckAndCountsIgnoreMergedRows)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([]() { return 2.0e11; });
    const std::string l1 = "1111111111111111111111111111111111111111111111111111111111110001";
    const std::string l2 = "1111111111111111111111111111111111111111111111111111111111110002";
    const std::string d1 = "2222222222222222222222222222222222222222222222222222222222220001";
    const std::string d2 = "2222222222222222222222222222222222222222222222222222222222220002";
    mi.record_found_block(3211000, uint256S(l1), 1794400000, "LTC", kMiner, l1,
                          94729203.0, 0.0, 2.0e11, 625000000,
                          MiningInterface::BlockAuthorship::this_node);
    mi.record_found_block(3211872, uint256S(l2), 1794498365, "LTC", kMiner, l2,
                          94729203.0, 0.0, 2.0e11, 625000000,
                          MiningInterface::BlockAuthorship::this_node);
    // Two aux finds a minute apart: as rows they carried a luck computed from
    // the PARENT's difficulty over the AUX inter-find gap.
    mi.record_merged_found_block("DOGE", 6454000, d1, true, 1000000000000ULL);
    mi.record_merged_found_block("DOGE", 6454700, d2, true, 1000000000000ULL);

    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 2u) << recent.dump(1);
    EXPECT_EQ(recent[0]["blocks_for_luck"].get<uint64_t>(), 1u)
        << "only the second LTC block has an interval, so only it has a luck";

    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck["blocks"].is_array());
    EXPECT_EQ(luck["blocks"].size(), 2u) << luck.dump(1);
    EXPECT_TRUE(find_row(luck["blocks"], "hash", d1).is_null());
    EXPECT_TRUE(find_row(luck["blocks"], "hash", d2).is_null());
}

// The open round's "Round: N%" is timed from the newest PARENT block. It was
// timed from m_found_blocks.front() -- the highest-HEIGHT row, which on an
// LTC node with any DOGE row is a DOGE row (6.4M > 3.2M): every local DOGE
// find restarted the round.
TEST(FoundBlockRows, RoundLuckIsTimedFromTheNewestParentBlock)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const double hashrate = 2.0e11, netdiff = 1.0e6;
    mi.set_pool_hashrate_fn([hashrate]() { return hashrate; });
    mi.update_network_difficulty(netdiff, "test");
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    const std::string l = "3333333333333333333333333333333333333333333333333333333333330001";
    const std::string d = "3333333333333333333333333333333333333333333333333333333333330002";
    mi.record_found_block(kLtcHeight, uint256S(l), now - 10000, "LTC", kMiner, l,
                          netdiff, 0.0, hashrate, 625000000,
                          MiningInterface::BlockAuthorship::this_node);
    mi.record_found_block(kDogeHeight, uint256S(d), now - 100, "DOGE", kMiner, "",
                          netdiff, 0.0, hashrate, 1000000000000ULL,
                          MiningInterface::BlockAuthorship::this_node);

    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck["luck_available"].get<bool>());
    ASSERT_TRUE(luck["current_luck_trend"].is_number()) << luck.dump(1);
    const double expected = netdiff * 4294967296.0 / hashrate;
    const double want = expected / 10000.0 * 100.0;
    const double got = luck["current_luck_trend"].get<double>();
    EXPECT_NEAR(got, want, want * 0.01)
        << "round must run from the LTC block (10000 s ago), not the DOGE one "
           "(100 s ago, which reads " << expected / 100.0 * 100.0 << "%)";
}

// Only aux finds so far: there is no parent block, so no pool luck and no
// open-round figure.
TEST(FoundBlockRows, OnlyMergedFindsMeansNoParentLuckYet)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([]() { return 2.0e11; });
    mi.update_network_difficulty(1.0e6, "test");
    mi.record_merged_found_block("DOGE", 6454700, kDogeBlock, true, 1000000000000ULL);
    EXPECT_TRUE(mi.rest_recent_blocks().empty());
    const auto luck = mi.rest_luck_stats();
    EXPECT_FALSE(luck["luck_available"].get<bool>()) << luck.dump(1);
    EXPECT_TRUE(luck["current_luck_trend"].is_null());
}

// A merged find ends no round: /best_share.round keeps its record.
TEST(FoundBlockRows, MergedFindDoesNotResetTheRound)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    mi.record_share_difficulty(1234.0, kMiner);
    mi.record_merged_found_block("DOGE", 6454700, kDogeBlock, true, 1000000000000ULL);
    EXPECT_DOUBLE_EQ(mi.rest_best_share()["round"]["difficulty"].get<double>(), 1234.0)
        << "a DOGE find reset the LTC round's best share on the finder only";

    // A parent block does.
    mi.record_found_block(kLtcHeight, uint256S(kLtcBlock), 1794498365, "LTC", kMiner,
                          kLtcBlock, 0.0, 0.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::this_node);
    EXPECT_DOUBLE_EQ(mi.rest_best_share()["round"]["difficulty"].get<double>(), 0.0);
}

// The per-miner payout page (/miner_payouts/<addr>) counts the miner's parent
// blocks and parent rewards only: the DOGE row added a block and its 10001
// DOGE reward to the LTC totals, linked through the litecoin explorer.
TEST(FoundBlockRows, MinerPayoutsCountParentBlocksOnly)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    record_the_find(mi);
    const auto st = mi.rest_miner_payouts(kMiner);
    ASSERT_TRUE(st.contains("blocks_found")) << st.dump(1);
    EXPECT_EQ(st["blocks_found"].get<int>(), 1) << st["blocks"].dump(1);
    ASSERT_EQ(st["blocks"].size(), 1u);
    EXPECT_EQ(st["blocks"][0]["block_hash"].get<std::string>(), kLtcBlock);
    EXPECT_NEAR(st["total_estimated_rewards"].get<double>(), 6.25549157, 1e-9);
}

// /miner_payouts matches the PAYEE, not the spelling of its address: an LTC
// P2SH is 3... or M..., a bech32 may be written in upper case.
TEST(FoundBlockRows, MinerPayoutsMatchThePayeeNotTheSpelling)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    std::vector<unsigned char> h(20);
    for (size_t i = 0; i < h.size(); ++i) h[i] = static_cast<unsigned char>(0x40 + i);
    std::vector<unsigned char> p2sh{0xa9, 0x14};
    p2sh.insert(p2sh.end(), h.begin(), h.end());
    p2sh.push_back(0x87);
    std::vector<unsigned char> p2wpkh{0x00, 0x14};
    p2wpkh.insert(p2wpkh.end(), h.begin(), h.end());
    const std::string m_addr = core::script_to_address(p2sh, "", 0x30, 0x32);   // M...
    const std::string three  = core::script_to_address(p2sh, "", 0x00, 0x05);   // 3...
    const std::string bech   = core::script_to_address(p2wpkh, "ltc", 0x30, 0x32);
    ASSERT_EQ(m_addr[0], 'M');
    ASSERT_EQ(three[0], '3');
    std::string bech_uc = bech;
    for (auto& c : bech_uc) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    const std::string b1 = "7777777777777777777777777777777777777777777777777777777777770001";
    const std::string b2 = "7777777777777777777777777777777777777777777777777777777777770002";
    mi.record_found_block(3211000, uint256S(b1), 1794400000, "LTC", m_addr, b1,
                          0.0, 0.0, 0.0, 625000000, MiningInterface::BlockAuthorship::this_node);
    mi.record_found_block(3211001, uint256S(b2), 1794400100, "LTC", bech, b2,
                          0.0, 0.0, 0.0, 625000000, MiningInterface::BlockAuthorship::this_node);
    EXPECT_EQ(mi.rest_miner_payouts(three)["blocks_found"].get<int>(), 1)
        << three << " and " << m_addr << " pay the same script";
    EXPECT_EQ(mi.rest_miner_payouts(bech_uc)["blocks_found"].get<int>(), 1) << bech_uc;
    EXPECT_EQ(mi.rest_miner_payouts(kMiner)["blocks_found"].get<int>(), 0);
}

// Requirement 3: rows persisted by the old binaries restore without harm and
// render the facts they can, null where they cannot.
TEST(FoundBlockRows, PreFixRowsRenderHonestly)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);

    // Finder, pre-fix: miner "", the PARENT share, authorship unknown.
    MiningInterface::FoundBlock finder{};
    finder.height = kLtcHeight; finder.hash = kLtcBlock; finder.ts = 1794498365;
    finder.chain = "LTC"; finder.miner = ""; finder.share_hash = kParentShr;
    finder.status = MiningInterface::BlockStatus::confirmed;

    // Peer, pre-fix, v36 share: absheight, the byte-reversed pubkey hash.
    const std::string peer_hash = "4444444444444444444444444444444444444444444444444444444444440001";
    MiningInterface::FoundBlock peer{};
    peer.height = kAbsheight; peer.hash = peer_hash; peer.ts = 1794400000;
    peer.chain = "LTC"; peer.miner = "085cdff070d752d9e137e82396e387ec1641fd75";
    peer.share_hash = peer_hash;
    peer.authorship = MiningInterface::BlockAuthorship::sharechain_peer;

    // Peer, pre-fix, v35 share: HexStr of the address STRING.
    const std::string v35_hash = "4444444444444444444444444444444444444444444444444444444444440002";
    std::string v35_hex;
    static const char* hexd = "0123456789abcdef";
    for (unsigned char c : kMiner) { v35_hex += hexd[c >> 4]; v35_hex += hexd[c & 0xf]; }
    MiningInterface::FoundBlock v35{};
    v35.height = 3100000; v35.hash = v35_hash; v35.ts = 1790000000;
    v35.chain = "LTC"; v35.miner = v35_hex; v35.share_hash = v35_hash;
    v35.authorship = MiningInterface::BlockAuthorship::sharechain_peer;

    // The finder's DOGE row, pre-#946 (no parent_hash): the chain label alone
    // must keep it off /recent_blocks.
    MiningInterface::FoundBlock doge{};
    doge.height = kDogeHeight; doge.hash = kDogeBlock; doge.ts = 1794498370;
    doge.chain = "DOGE"; doge.miner = kMiner; doge.share_hash = kLtcBlock;
    doge.status = MiningInterface::BlockStatus::confirmed;

    std::vector<MiningInterface::FoundBlock> restored = {doge, finder, peer, v35};
    mi.set_found_block_persistence(
        [](const MiningInterface::FoundBlock&) { return true; },
        [&restored]() { return restored; });
    mi.load_persisted_found_blocks();

    const auto recent = mi.rest_recent_blocks();
    EXPECT_EQ(recent.size(), 3u) << recent.dump(1);
    EXPECT_TRUE(find_row(recent, "hash", kDogeBlock).is_null());

    const auto f = find_row(recent, "hash", kLtcBlock);
    ASSERT_TRUE(f.is_object());
    EXPECT_TRUE(f["share"].is_null())
        << "the parent share is not the share that found the block";

    const auto p = find_row(recent, "hash", peer_hash);
    ASSERT_TRUE(p.is_object());
    EXPECT_EQ(p["miner"].get<std::string>(), "")
        << "a bare pubkey hash is not an address and cannot be rendered without its type";
    EXPECT_EQ(p["share"].get<std::string>(), peer_hash);

    const auto o = find_row(recent, "hash", v35_hash);
    ASSERT_TRUE(o.is_object());
    EXPECT_EQ(o["miner"].get<std::string>(), kMiner);

    // ... and the finder's DOGE row is on the merged list.
    EXPECT_TRUE(find_row(mi.rest_recent_merged_blocks(), "pow_hash", kDogeBlock).is_object());
}
