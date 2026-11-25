// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// createauxblock "target" (and the legacy "_target") is the raw little-endian
// bytes of the aux target, as Dogecoin Core / Namecoin print it with
// HexStr(BEGIN(target), END(target)). GBT "target" is the big-endian display
// form. p2pool unpacks the createauxblock field as a little-endian integer.
//
// Known answer: one real pair captured from dogecoind 1.14.9 regtest at the
// same tip (height 165, prev b3d5148c...905b, bits 207fffff):
//   createauxblock target = 00..00ffff7f   (little-endian)
//   getblocktemplate target = 7fffff00..00 (big-endian)
// Both must give SetCompact(0x207fffff). Before the fix, create_aux_block
// passed the little-endian string straight to SetHex, which gives
// 0x7fffff00 (a target near zero), so a DOGE share never met it.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using c2pool::merged::aux_target_from_le_hex;
using c2pool::merged::aux_work_from_createauxblock;

// Captured from dogecoind 1.14.9 -regtest (createauxblock <addr>), height 165.
const char* kCreateAuxBlockReply = R"({
  "hash": "f43548cdbe5ba9a3021eca9e9cd5fc1480b296b7200b4beecfea12989fcdfdd6",
  "chainid": 98,
  "previousblockhash": "b3d5148c51c0135903fd6718659a36f28d4b97256c11cbfeedce1ac930ad905b",
  "coinbasevalue": 25000003364000,
  "bits": "207fffff",
  "height": 165,
  "target": "0000000000000000000000000000000000000000000000000000000000ffff7f"
})";

// getblocktemplate at the same tip: "target" field, big-endian.
const char* kGbtTargetBE =
    "7fffff0000000000000000000000000000000000000000000000000000000000";

uint256 compact(uint32_t bits)
{
    uint256 t;
    t.SetCompact(bits);
    return t;
}

// Little-endian hex of a uint256, the way the daemon prints it.
std::string le_hex_of(const uint256& v)
{
    const std::string be = v.GetHex();
    std::string le;
    for (int i = 62; i >= 0; i -= 2)
        le.append(be, static_cast<size_t>(i), 2);
    return le;
}

TEST(MergedAuxTargetLE, CapturedRegtestPairAgrees)
{
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);

    uint256 from_aux;
    ASSERT_TRUE(aux_target_from_le_hex(reply["target"].get<std::string>(), from_aux));

    uint256 from_gbt;
    from_gbt.SetHex(kGbtTargetBE);

    EXPECT_EQ(from_aux, compact(0x207fffff));
    EXPECT_EQ(from_gbt, compact(0x207fffff));
    EXPECT_EQ(from_aux, from_gbt);
}

TEST(MergedAuxTargetLE, PlainSetHexIsTheOldBug)
{
    // Documents the defect this fixes: SetHex on the little-endian string
    // gives a far smaller target than the daemon's.
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);
    uint256 wrong;
    wrong.SetHex(reply["target"].get<std::string>());
    EXPECT_NE(wrong, compact(0x207fffff));
    EXPECT_LT(wrong, compact(0x207fffff));
}

TEST(MergedAuxTargetLE, ParserUsesTargetField)
{
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);
    auto work = aux_work_from_createauxblock(reply, 0, "DOGE");
    EXPECT_EQ(work.target, compact(0x207fffff));
    EXPECT_EQ(work.chain_id, 98u);
    EXPECT_EQ(work.height, 165);
    EXPECT_EQ(work.coinbase_value, 25000003364000ULL);
    EXPECT_EQ(work.block_hash.GetHex(),
              "f43548cdbe5ba9a3021eca9e9cd5fc1480b296b7200b4beecfea12989fcdfdd6");
}

TEST(MergedAuxTargetLE, ParserUsesLegacyUnderscoreTarget)
{
    // Namecoin-style getauxblock reply: "_target" only, also little-endian.
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);
    reply["_target"] = reply["target"];
    reply.erase("target");
    reply.erase("bits");
    auto work = aux_work_from_createauxblock(reply, 98, "DOGE");
    EXPECT_EQ(work.target, compact(0x207fffff));
}

TEST(MergedAuxTargetLE, TargetBeatsUnderscoreTargetBeatsBits)
{
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);
    reply["_target"] = le_hex_of(compact(0x1d00ffff));
    reply["bits"] = "1c00ffff";
    EXPECT_EQ(aux_work_from_createauxblock(reply, 98, "DOGE").target, compact(0x207fffff));

    reply.erase("target");
    EXPECT_EQ(aux_work_from_createauxblock(reply, 98, "DOGE").target, compact(0x1d00ffff));

    reply.erase("_target");
    EXPECT_EQ(aux_work_from_createauxblock(reply, 98, "DOGE").target, compact(0x1c00ffff));
}

TEST(MergedAuxTargetLE, MalformedTargetFallsBackToBits)
{
    auto reply = nlohmann::json::parse(kCreateAuxBlockReply);
    for (const std::string bad : {std::string(""),
                                  std::string(63, 'f'),
                                  std::string(66, 'f'),
                                  std::string(62, '0') + "zz",
                                  std::string(64, '0')}) {  // null target
        reply["target"] = bad;
        reply["bits"] = "1e0fffff";
        EXPECT_EQ(aux_work_from_createauxblock(reply, 98, "DOGE").target, compact(0x1e0fffff))
            << "target=\"" << bad << "\"";
    }
}

TEST(MergedAuxTargetLE, RejectsLeaveOutputUntouched)
{
    uint256 out = compact(0x1d00ffff);
    const uint256 before = out;
    EXPECT_FALSE(aux_target_from_le_hex("", out));
    EXPECT_FALSE(aux_target_from_le_hex(std::string(63, 'a'), out));
    EXPECT_FALSE(aux_target_from_le_hex(std::string(65, 'a'), out));
    EXPECT_FALSE(aux_target_from_le_hex(std::string(63, 'a') + "g", out));
    EXPECT_EQ(out, before);
}

TEST(MergedAuxTargetLE, RoundTripsRealisticTargets)
{
    // Regtest, DOGE-mainnet-scale, and BTC diff-1 compact values: the
    // little-endian rendering of each parses back to the same target.
    for (uint32_t bits : {0x207fffffu, 0x1e0fffffu, 0x1b0404cbu, 0x1a01cd2du, 0x1d00ffffu}) {
        uint256 t = compact(bits);
        uint256 parsed;
        ASSERT_TRUE(aux_target_from_le_hex(le_hex_of(t), parsed));
        EXPECT_EQ(parsed, t) << std::hex << bits;
    }
}

}  // namespace
