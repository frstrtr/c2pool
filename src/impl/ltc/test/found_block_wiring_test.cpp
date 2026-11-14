// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC found-block WIRING -- source-structural guard over main_ltc.cpp.
//
// The two record sites of an LTC block live inside main_ltc.cpp's run
// function (a stratum submit callback and the tracker's m_on_block_found),
// which no unit test can drive; dashboard_found_block_test.cpp pins the row
// builders they must use. This pins that they do use them, over
// comment-stripped source (the fix's own comments quote the old code):
//
//   tracker hook   : ltc::dashboard::row_from_share -- never the share
//                    absheight as the block height, never raw pubkey-hash /
//                    address-string hex as the miner;
//   submit callback: ltc::dashboard::row_from_submit over the stratum
//                    submit's context, labelled this_node -- never the
//                    sharechain best share as the block's share.
//
// The 2026-11-12 find (LTC 3211872) showed every one of these on master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

std::string read_text(const std::string& path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Comments -> spaces (offsets kept); string and char literals left intact.
std::string strip_comments(const std::string& s)
{
    std::string out = s;
    enum { kCode, kLine, kBlock, kStr, kChr } st = kCode;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        const char n = (i + 1 < out.size()) ? out[i + 1] : '\0';
        switch (st) {
        case kCode:
            if (c == '/' && n == '/') { st = kLine; out[i] = ' '; }
            else if (c == '/' && n == '*') { st = kBlock; out[i] = ' '; }
            else if (c == '"') st = kStr;
            else if (c == '\'') st = kChr;
            break;
        case kLine:
            if (c == '\n') st = kCode; else out[i] = ' ';
            break;
        case kBlock:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
            else if (c != '\n') out[i] = ' ';
            break;
        case kStr:
            if (c == '\\') ++i;
            else if (c == '"') st = kCode;
            break;
        case kChr:
            if (c == '\\') ++i;
            else if (c == '\'') st = kCode;
            break;
        }
    }
    return out;
}

// The text from `from` up to the first `to` after it ("" when absent).
std::string section(const std::string& src, const std::string& from, const std::string& to)
{
    const auto a = src.find(from);
    if (a == std::string::npos) return {};
    const auto b = src.find(to, a + from.size());
    return src.substr(a, (b == std::string::npos ? src.size() : b) - a);
}

std::string main_ltc()
{
    return strip_comments(read_text(std::string(C2POOL_IMPL_DIR) + "/../c2pool/main_ltc.cpp"));
}

} // namespace

TEST(LtcFoundBlockWiring, SharechainHookRecordsTheBlockFactsOfTheShare)
{
    const auto src = main_ltc();
    const auto hook = section(src, "tracker().m_on_block_found =", "m_on_share_difficulty");
    ASSERT_FALSE(hook.empty()) << "the tracker found-block hook is not bound in main_ltc.cpp";
    EXPECT_NE(hook.find("ltc::dashboard::row_from_share("), std::string::npos)
        << "the hook must build its row with ltc::dashboard::row_from_share";
    EXPECT_EQ(hook.find("height = s->m_absheight"), std::string::npos)
        << "the share absheight is not a block height";
    EXPECT_EQ(hook.find("m_pubkey_hash.GetHex()"), std::string::npos)
        << "a raw pubkey hash is not a miner address";
    EXPECT_EQ(hook.find("HexStr(s->m_address"), std::string::npos)
        << "hex of the address string is not the address";
}

TEST(LtcFoundBlockWiring, SubmitCallbackRecordsTheMintedShareAsThisNode)
{
    const auto src = main_ltc();
    const auto cb = section(src, "set_on_block_submitted(", "set_on_block_relay(");
    ASSERT_FALSE(cb.empty()) << "the block-submitted callback is not bound in main_ltc.cpp";
    EXPECT_NE(cb.find("ltc::dashboard::row_from_submit("), std::string::npos)
        << "the finder must build its row with ltc::dashboard::row_from_submit";
    EXPECT_NE(cb.find("found_block_submit_context()"), std::string::npos)
        << "the row's share, miner and height come from the stratum submit";
    EXPECT_EQ(cb.find("get_best_share_hash_fn"), std::string::npos)
        << "the sharechain best share is the winner's PARENT, not the block's share";
    EXPECT_NE(cb.find("BlockAuthorship::this_node"), std::string::npos)
        << "the node that submitted the block found it";
}
