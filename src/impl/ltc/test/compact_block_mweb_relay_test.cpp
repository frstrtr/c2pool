// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Compact-block relay of MWEB blocks KAT (rides share_test).
//
// Our CompactBlock is the BIP 152 v2 encoding: header, nonce, short ids,
// prefilled txs. It has no field for the MWEB extension block, so a v2
// cmpctblock of a HogEx block drops the "01" + mweb tail -- and after MWEB
// activation litecoind ignores v1/v2 cmpctblocks outright. A block we found
// that ends with a HogEx must therefore be relayed as a full block.
//
// Also pins the sendcmpct fold: litecoind sends v3, v2, v1 in that order;
// the peer's version is the highest one announced, not the last one.
//
// Folded into the allowlisted share_test target (NOT a standalone executable)
// to avoid the #769 "Not Run" CI trap.

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <impl/ltc/coin/compact_blocks.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <btclibs/util/strencodings.h>

using ltc::coin::BlockType;
using ltc::coin::BuildCompactBlock;
using ltc::coin::MutableTransaction;
using ltc::coin::RelayMode;
using ltc::coin::TxIn;
using ltc::coin::TxOut;
using ltc::coin::block_has_hogex;
using ltc::coin::fold_cmpct_version;
using ltc::coin::relay_mode_for;

namespace {

MutableTransaction make_tx(int64_t value, uint32_t index)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_hogex()
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    tx.m_hogEx = true;
    TxIn in;
    in.prevout.hash.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 1000;
    out.scriptPubKey.m_data.assign(34, 0x33);
    out.scriptPubKey.m_data[0] = 0x58;
    out.scriptPubKey.m_data[1] = 0x20;
    tx.vout.push_back(out);
    return tx;
}

const std::vector<unsigned char> kMweb(64, 0xab);

BlockType make_block(bool with_hogex)
{
    BlockType b;
    b.m_version = 0x20000000;
    b.m_timestamp = 1600000000;
    b.m_bits = 0x207fffff;
    b.m_txs = {make_tx(5000000000LL, 0xffffffff), make_tx(100000, 1)};
    if (with_hogex) {
        b.m_txs.push_back(make_hogex());
        b.m_mweb_raw = kMweb;
    }
    return b;
}

std::string hex_of(PackStream& ps)
{
    return HexStr(ps.get_span());
}

bool ends_with(const std::string& s, const std::string& tail)
{
    return s.size() >= tail.size() && s.compare(s.size() - tail.size(), tail.size(), tail) == 0;
}

} // namespace

TEST(LtcCompactMwebRelay, HogexBlockAlwaysRelayedFull)
{
    const BlockType hog = make_block(true);
    const BlockType plain = make_block(false);
    ASSERT_TRUE(block_has_hogex(hog));
    ASSERT_FALSE(block_has_hogex(plain));

    EXPECT_EQ(relay_mode_for(2, hog), RelayMode::Full) << "v2 compact cannot carry mweb";
    EXPECT_EQ(relay_mode_for(3, hog), RelayMode::Full) << "v3 is not encoded here";
    EXPECT_EQ(relay_mode_for(1, hog), RelayMode::Full);
    EXPECT_EQ(relay_mode_for(0, hog), RelayMode::Full);

    EXPECT_EQ(relay_mode_for(2, plain), RelayMode::Compact);
    EXPECT_EQ(relay_mode_for(3, plain), RelayMode::Full);
    EXPECT_EQ(relay_mode_for(1, plain), RelayMode::Full);
    EXPECT_EQ(relay_mode_for(0, plain), RelayMode::Full);
}

TEST(LtcCompactMwebRelay, SendcmpctFoldKeepsHighestVersion)
{
    // litecoind: sendcmpct v3, then v2, then v1.
    uint64_t v = 0;
    for (uint64_t announced : {3u, 2u, 1u})
        v = fold_cmpct_version(v, announced);
    EXPECT_EQ(v, 3u) << "keeping the last one (1) would hide the peer's MWEB support";

    v = 0;
    for (uint64_t announced : {1u, 2u})
        v = fold_cmpct_version(v, announced);
    EXPECT_EQ(v, 2u);
}

TEST(LtcCompactMwebRelay, CompactEncodingDropsMwebFullBlockKeepsIt)
{
    const BlockType hog = make_block(true);
    const std::string mweb_hex = HexStr(std::span<const unsigned char>(kMweb.data(), kMweb.size()));

    PackStream full;
    full << hog;
    const std::string full_hex = hex_of(full);
    EXPECT_TRUE(ends_with(full_hex, "01" + mweb_hex)) << "full block carries 01 + mweb";

    auto cb = BuildCompactBlock(static_cast<const ltc::coin::BlockHeaderType&>(hog), hog.m_txs);
    PackStream compact;
    compact << cb;
    const std::string compact_hex = hex_of(compact);
    EXPECT_FALSE(ends_with(compact_hex, mweb_hex)) << "v2 compact has no mweb field";
    EXPECT_EQ(compact_hex.find(mweb_hex), std::string::npos);

    // The full bytes round-trip with the HogEx last and the mweb intact.
    auto bytes = ParseHex(full_hex);
    PackStream ps(bytes);
    BlockType parsed;
    ps >> parsed;
    EXPECT_TRUE(block_has_hogex(parsed));
    EXPECT_EQ(parsed.m_mweb_raw, kMweb);
}
