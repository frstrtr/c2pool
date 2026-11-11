// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The redistribution recipient of an address share keeps its script type
// (rides share_test).
//
// A share without pubkey fields (an address share) entered the
// redistribution candidates as P2PKH over the first 20 bytes of its script:
// a P2SH payout became P2PKH(a9 14 ...), a P2WPKH one P2PKH(<program>), a
// P2WSH one P2PKH(00 20 ...) — outputs nobody can spend, or another address.
// script_pubkey_of gives the (hash, type) a share carries, and nothing for a
// script no share can carry (those are not candidates).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <vector>

#include <impl/ltc/redistribute.hpp>

namespace {

std::vector<unsigned char> with(std::vector<unsigned char> head, unsigned char b, size_t n,
                                std::vector<unsigned char> tail = {})
{
    head.insert(head.end(), n, b);
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

} // namespace

TEST(RedistributeScriptType, EachShareScriptGivesTheHashAndTypeItCarries)
{
    uint160 h;
    uint8_t t = 9;
    ASSERT_TRUE(ltc::script_pubkey_of(with({0x76, 0xa9, 0x14}, 0x11, 20, {0x88, 0xac}), h, t));
    EXPECT_EQ(t, 0);
    EXPECT_EQ(h.data()[0], 0x11);
    ASSERT_TRUE(ltc::script_pubkey_of(with({0x00, 0x14}, 0x22, 20), h, t));
    EXPECT_EQ(t, 1);
    EXPECT_EQ(h.data()[19], 0x22);
    ASSERT_TRUE(ltc::script_pubkey_of(with({0xa9, 0x14}, 0x33, 20, {0x87}), h, t));
    EXPECT_EQ(t, 2);
    EXPECT_EQ(h.data()[0], 0x33);
}

TEST(RedistributeScriptType, ScriptsNoShareCarriesAreNotRecipients)
{
    uint160 h;
    uint8_t t = 0;
    EXPECT_FALSE(ltc::script_pubkey_of(with({0x00, 0x20}, 0x44, 32), h, t)) << "P2WSH";
    EXPECT_FALSE(ltc::script_pubkey_of(with({0x51, 0x20}, 0x55, 32), h, t)) << "P2TR";
    EXPECT_FALSE(ltc::script_pubkey_of(with({0x21}, 0x02, 33, {0xac}), h, t)) << "bare pubkey";
    EXPECT_FALSE(ltc::script_pubkey_of(with({0x76, 0xa9, 0x14}, 0x11, 20, {0x88}), h, t)) << "truncated";
}
