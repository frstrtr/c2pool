// SPDX-License-Identifier: AGPL-3.0-or-later
    // PackStream stream_share;
    // stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <sharechain/sharechain.hpp>
#include <impl/ltc/share.hpp>

// struct FakeBlock
// {

// };

TEST(LTC_share_test, Init)
{
    PackStream stream_share;
    // stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
    stream_share.from_hex("23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc08500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b44785235374766374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a41fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b3210073990593df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c039a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8db8b277110a50a9a268b6");

    chain::RawShare rshare;
    stream_share >> rshare;

    std::cout << rshare.type << std::endl;

    auto share = ltc::load_share(rshare, NetService{"0.0.0.0", 0});
}
// ---------------------------------------------------------------------------
// Three-tier v35-phase wire-compat KATs (KAT-form of soak gates ST-2/ST-3,
// "Standing CI reduction", v35-threetier-wirecompat-design.md §5.2).
//
// FENCED, NON-CIRCULAR: expected bytes are hand-transcribed from the jtoomim /
// frstrtr/p2pool-merged-v36 oracle wire semantics (VarIntType == Bitcoin
// CompactSize, VarStrType == CompactSize-prefixed bytes, FixedStrType(N) == N
// raw bytes no prefix) -- NOT a second read of the c2pool SUT serializer. A
// field-order or encoding drift in ltc/share_types.hpp that silently diverges
// from what a T-A (jtoomim) node round-trips fails HERE.
//   ST-2: the v36 vote rides desired_version = VarInt(36) == single byte 0x24
//         (design §1.1); pin the CompactSize codec that carries it + the
//         share_type outer type tag (v35 mint class 35 -> "23", v36 -> "24").
//   ST-3: zero v36-byte leakage into the v35 codec -- the v35 HashLinkType has
//         NO extra_data slot (FixedStr(0), zero bytes), whereas the v36
//         V36HashLinkType inserts a VarStr(extra_data) the v35 wire never carries.
// ---------------------------------------------------------------------------
#include <span>
#include <cstdint>
#include <impl/ltc/share_types.hpp>

namespace {

// FixedStrType(32) operand: raw bytes 0x00..0x1f (oracle transcription).
const std::string ST_STATE_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

std::string st_state_raw()
{
    std::string s;
    for (int i = 0; i < 32; ++i) s.push_back(static_cast<char>(i));
    return s;
}

std::string st_to_hex(std::span<std::byte> sp)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(sp.size() * 2);
    for (std::byte b : sp) {
        auto v = static_cast<unsigned>(b);
        s.push_back(d[(v >> 4) & 0xf]);
        s.push_back(d[v & 0xf]);
    }
    return s;
}

} // namespace

// ST-3: v35 hash_link carries NO extra_data; v36 codec adds a VarStr slot the
// v35 wire never has -> any v36-byte leak into a v35 share is structural, not policy.
TEST(LTC_threetier_wirecompat, ST3_no_v36_hash_link_leak)
{
    // v35 lineage (PaddingBugfixShare): state(32) || VarInt(len); FixedStr(0)
    // extra_data contributes ZERO bytes. length = 300 -> CompactSize "fd2c01".
    {
        ltc::HashLinkType hl;
        hl.m_state  = FixedStrType<32>(st_state_raw());
        hl.m_length = 300;
        PackStream ss;
        ss << hl;
        EXPECT_EQ(st_to_hex(ss.get_span()), ST_STATE_HEX + "fd2c01");
        EXPECT_EQ(ss.get_span().size(), 35u); // 32 + 3, nothing between state and len
    }
    // v36 struct with EMPTY extra_data still emits the VarStr length prefix "00"
    // -> exactly one byte more than the v35 wire; the leak is detectable.
    {
        ltc::V36HashLinkType hl;
        hl.m_state      = FixedStrType<32>(st_state_raw());
        hl.m_extra_data = BaseScript(std::vector<unsigned char>{});
        hl.m_length     = 300;
        PackStream ss;
        ss << hl;
        EXPECT_EQ(st_to_hex(ss.get_span()), ST_STATE_HEX + "00" + "fd2c01");
        EXPECT_EQ(ss.get_span().size(), 36u);
    }
    // v36 struct with non-empty extra_data: state || VarStr(aabbcc) || VarInt(len).
    {
        ltc::V36HashLinkType hl;
        hl.m_state      = FixedStrType<32>(st_state_raw());
        hl.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
        hl.m_length     = 300;
        PackStream ss;
        ss << hl;
        EXPECT_EQ(st_to_hex(ss.get_span()), ST_STATE_HEX + "03aabbcc" + "fd2c01");
    }
}

// ST-2: the v36 vote value (36) is the single byte 0x24 under the CompactSize
// codec that carries desired_version; the share_type outer type tag agrees.
TEST(LTC_threetier_wirecompat, ST2_desired_version_vote_byte)
{
    // VarInt == Bitcoin CompactSize: pin the vote value 36 -> "24" plus the
    // boundary vectors, via the same VarInt codec desired_version uses.
    struct { uint64_t v; const char* hex; } vec[] = {
        {35, "23"}, {36, "24"}, {252, "fc"},
        {253, "fdfd00"}, {300, "fd2c01"}, {65536, "fe00000100"},
    };
    for (auto& t : vec) {
        ltc::HashLinkType hl;
        hl.m_state  = FixedStrType<32>(st_state_raw());
        hl.m_length = t.v;
        PackStream ss;
        ss << hl;
        EXPECT_EQ(st_to_hex(ss.get_span()), ST_STATE_HEX + t.hex)
            << "VarInt(" << t.v << ") != oracle CompactSize";
    }
    // share_type outer wrapper: VarInt(type) || VarStr(contents).
    // v35 mint class 35 -> "23"; v36 class -> "24" (same single-byte CompactSize
    // as the vote value 36) -- the tier discriminator on the wire.
    {
        chain::RawShare rs(35, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
        PackStream ss;
        ss << rs;
        EXPECT_EQ(st_to_hex(ss.get_span()), std::string("23") + "04deadbeef");
    }
    {
        chain::RawShare rs(36, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
        PackStream ss;
        ss << rs;
        EXPECT_EQ(st_to_hex(ss.get_span()), std::string("24") + "04deadbeef");
    }
}
