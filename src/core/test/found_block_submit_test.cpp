// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The pieces the found-block rows are built from (core/found_block_submit.hpp
// and the MiningInterface found-block helpers): BIP34 height, the stratum
// submit's context, the parent-vs-merged predicate, the display repair of
// pre-fix rows, and the header-chain height correction.
// Field values: LTC block 3211872 (share 84024db9...), 2026-11-12.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <btclibs/util/strencodings.h>
#include <nlohmann/json.hpp>

#include <core/found_block_submit.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

using core::MiningInterface;

namespace {

const std::string kLtcBlock = "84024db9063696eabf560504fa15737d6ab15a560441e5bab7fd51bd03571223";
const std::string kMiner    = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";
// The share's coinbase scriptSig, as /web/share/84024db9... serves it.
const std::string kScriptSigHex =
    "036002312cfabe6d6dda2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb"
    "0100000000000000082f6332706f6f6c2f8950f2d18d7c1a7df35444ae7383d4e2f11cb808f0f974"
    "0506ef5d9a91f0f4e6";
// The finder's payout: P2PKH over the hash160 the merged address commits to
// (script 76a91475fd4116ec87e39623e837e1d952d770f0df5c0888ac).
const std::string kPayoutScriptHex = "76a91475fd4116ec87e39623e837e1d952d770f0df5c0888ac";

nlohmann::json find_row(const nlohmann::json& arr, const std::string& hash)
{
    for (const auto& b : arr)
        if (b.value("hash", std::string()) == hash) return b;
    return nlohmann::json(nullptr);
}

} // namespace

TEST(FoundBlockSubmit, Bip34HeightIsTheCoinbaseHeightPush)
{
    const auto sig = ParseHex(kScriptSigHex);
    EXPECT_EQ(core::bip34_height_from_script_sig(sig), 3211872u);

    const std::vector<unsigned char> op5 = {0x55, 0x00};          // OP_5
    EXPECT_EQ(core::bip34_height_from_script_sig(op5), 5u);
    const std::vector<unsigned char> two = {0x02, 0x80, 0x00};    // 128, sign byte
    EXPECT_EQ(core::bip34_height_from_script_sig(two), 128u);
    const std::vector<unsigned char> neg = {0x01, 0x81};          // -1
    EXPECT_EQ(core::bip34_height_from_script_sig(neg), 0u);
    const std::vector<unsigned char> cut = {0x03, 0x60, 0x02};    // truncated push
    EXPECT_EQ(core::bip34_height_from_script_sig(cut), 0u);
    const std::vector<unsigned char> tag = {0x2f, 0x63, 0x32};    // no height push
    EXPECT_EQ(core::bip34_height_from_script_sig(tag), 0u);
    EXPECT_EQ(core::bip34_height_from_script_sig(std::vector<unsigned char>{}), 0u);
}

TEST(FoundBlockSubmit, ContextNamesTheShareItsPayoutAndHeight)
{
    const auto script = ParseHex(kPayoutScriptHex);
    const auto ctx = core::make_found_block_submit_context(
        script, /*is_litecoin=*/true, /*testnet=*/false, "login-address",
        uint256S(kLtcBlock), ParseHex(kScriptSigHex), 625549157, /*share_bits=*/0);
    EXPECT_EQ(ctx.miner, kMiner) << "the share's payout script, rendered for LTC";
    EXPECT_EQ(ctx.share_hash, kLtcBlock);
    EXPECT_EQ(ctx.height, 3211872u);
    EXPECT_EQ(ctx.subsidy, 625549157u);
    EXPECT_EQ(ctx.share_difficulty, 0.0);

    // No script: the login. No share minted: none named.
    const auto bare = core::make_found_block_submit_context(
        {}, true, false, "login-address", uint256(), {}, 0, 0);
    EXPECT_EQ(bare.miner, "login-address");
    EXPECT_TRUE(bare.share_hash.empty());
    EXPECT_EQ(bare.height, 0u);
}

TEST(FoundBlockSubmit, ScopeIsVisibleOnlyInsideAndNests)
{
    EXPECT_EQ(MiningInterface::found_block_submit_context(), nullptr);
    {
        core::FoundBlockSubmitContext a; a.miner = "A";
        MiningInterface::FoundBlockSubmitScope sa(a);
        ASSERT_NE(MiningInterface::found_block_submit_context(), nullptr);
        EXPECT_EQ(MiningInterface::found_block_submit_context()->miner, "A");
        {
            core::FoundBlockSubmitContext b; b.miner = "B";
            MiningInterface::FoundBlockSubmitScope sb(b);
            EXPECT_EQ(MiningInterface::found_block_submit_context()->miner, "B");
        }
        EXPECT_EQ(MiningInterface::found_block_submit_context()->miner, "A");
    }
    EXPECT_EQ(MiningInterface::found_block_submit_context(), nullptr);
}

TEST(FoundBlockSubmit, PrimaryChainPredicate)
{
    using MI = MiningInterface;
    EXPECT_TRUE(MI::found_block_chain_is_primary("LTC", "", "LTC"));
    EXPECT_TRUE(MI::found_block_chain_is_primary("tLTC", "", "LTC"));
    EXPECT_FALSE(MI::found_block_chain_is_primary("DOGE", "", "LTC"));
    EXPECT_FALSE(MI::found_block_chain_is_primary("tDOGE", "", "LTC"));
    // #946: a parent block named -> a merged row, whatever its label.
    EXPECT_FALSE(MI::found_block_chain_is_primary("LTC", kLtcBlock, "LTC"));
    // Unlabelled rows and an unconfigured node keep every unparented row.
    EXPECT_TRUE(MI::found_block_chain_is_primary("", "", "LTC"));
    EXPECT_TRUE(MI::found_block_chain_is_primary("DOGE", "", ""));
    // The other lanes' own labels.
    EXPECT_TRUE(MI::found_block_chain_is_primary("DASH", "", "DASH"));
    EXPECT_TRUE(MI::found_block_chain_is_primary("BTC", "", "BTC"));
    EXPECT_TRUE(MI::found_block_chain_is_primary("DGB", "", "DGB"));
    EXPECT_TRUE(MI::found_block_chain_is_primary("BIP110", "", "BIP110"));

    // The node's own symbol, testnet included.
    MiningInterface tn(/*testnet=*/true, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    MiningInterface::FoundBlock b{};
    b.chain = "tLTC";
    EXPECT_TRUE(tn.is_primary_found_block(b));
    b.chain = "tDOGE";
    EXPECT_FALSE(tn.is_primary_found_block(b));
}

TEST(FoundBlockSubmit, MinerDisplayRepairsPreFixHex)
{
    using MI = MiningInterface;
    EXPECT_EQ(MI::found_block_miner_display(kMiner), kMiner);
    EXPECT_EQ(MI::found_block_miner_display(""), "");
    EXPECT_EQ(MI::found_block_miner_display("ltc1qminer"), "ltc1qminer");
    EXPECT_EQ(MI::found_block_miner_display("XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4"),
              "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4");
    // v36 m_pubkey_hash.GetHex(): no script type, not renderable.
    EXPECT_EQ(MI::found_block_miner_display("085cdff070d752d9e137e82396e387ec1641fd75"), "");
    // v34/v35 HexStr(m_address): the address string itself.
    std::string hex;
    static const char* d = "0123456789abcdef";
    for (unsigned char c : kMiner) { hex += d[c >> 4]; hex += d[c & 0xf]; }
    EXPECT_EQ(MI::found_block_miner_display(hex), kMiner);
}

TEST(FoundBlockSubmit, MergedExplorerPrefix)
{
    using MI = MiningInterface;
    EXPECT_EQ(MI::merged_block_explorer_prefix("DOGE"), "https://blockchair.com/dogecoin/block/");
    EXPECT_EQ(MI::merged_block_explorer_prefix("tDOGE"), "");
    EXPECT_EQ(MI::merged_block_explorer_prefix("PEP"), "");
}

// Requirement 3: pre-fix peer rows hold the share absheight; the header chain
// knows the block's height and corrects them (merged rows untouched).
TEST(FoundBlockSubmit, HeaderChainCorrectsAContradictedHeight)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    MiningInterface::FoundBlock peer{};
    peer.height = 27707625; peer.hash = kLtcBlock; peer.ts = 1794498365;
    peer.chain = "LTC"; peer.miner = kMiner; peer.share_hash = kLtcBlock;
    const std::string doge = "da2714c8e3c4d17214ea4c9daa7d079df8682acbcfea0d9c6068da56e649a6fb";
    MiningInterface::FoundBlock aux{};
    aux.height = 6454700; aux.hash = doge; aux.ts = 1794498370;
    aux.chain = "DOGE"; aux.miner = kMiner; aux.share_hash = kLtcBlock;
    std::vector<MiningInterface::FoundBlock> restored = {peer, aux};
    std::vector<MiningInterface::FoundBlock> persisted;
    mi.set_found_block_persistence(
        [&persisted](const MiningInterface::FoundBlock& b) { persisted.push_back(b); return true; },
        [&restored]() { return restored; });
    mi.load_persisted_found_blocks();

    std::vector<std::string> asked;
    mi.correct_found_block_heights([&asked](const std::string& h) -> uint64_t {
        asked.push_back(h);
        return h == kLtcBlock ? 3211872u : 0u;
    });
    ASSERT_EQ(asked.size(), 1u) << "a merged row is never looked up in the parent chain";
    EXPECT_EQ(asked[0], kLtcBlock);
    ASSERT_EQ(persisted.size(), 1u);
    EXPECT_EQ(persisted[0].height, 3211872u);
    EXPECT_EQ(find_row(mi.rest_recent_blocks(), kLtcBlock)["height"].get<uint64_t>(), 3211872u);
    EXPECT_EQ(mi.rest_found_block(doge)["height"].get<uint64_t>(), 6454700u);

    // Agreement or no answer leaves the row alone.
    persisted.clear();
    mi.correct_found_block_heights([](const std::string&) -> uint64_t { return 3211872u; });
    mi.correct_found_block_heights([](const std::string&) -> uint64_t { return 0u; });
    EXPECT_TRUE(persisted.empty());
}

// Two record paths meet on one block: the finder's submit and the sharechain
// hook. What one lacks the other fills; nothing known is overwritten.
TEST(FoundBlockSubmit, SecondRecordFillsOnlyWhatTheFirstLacked)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    // A JSON-RPC submit: miner known, no share, no subsidy.
    mi.record_found_block(3211872, uint256S(kLtcBlock), 1794498365, "LTC",
                          kMiner, "", 0.0, 0.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::this_node);
    // The winning share verifies here.
    mi.record_found_block(3211872, uint256S(kLtcBlock), 1794498365, "LTC",
                          "LSomeoneElse", kLtcBlock, 0.0, 514.33, 0.0, 625549157,
                          MiningInterface::BlockAuthorship::sharechain_peer);
    const auto row = find_row(mi.rest_recent_blocks(), kLtcBlock);
    ASSERT_TRUE(row.is_object());
    EXPECT_EQ(row["miner"].get<std::string>(), kMiner) << "a known miner is never overwritten";
    EXPECT_EQ(row["share"].get<std::string>(), kLtcBlock);
    EXPECT_EQ(row["subsidy"].get<uint64_t>(), 625549157u);
    EXPECT_DOUBLE_EQ(row["share_difficulty"].get<double>(), 514.33);
    EXPECT_EQ(row["found_by"].get<std::string>(), "this_node");
}
