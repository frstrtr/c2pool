// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Three-tier v35/v36 wire-compat RUNTIME harness (soak gates ST-2 / ST-3).
//
// This is the c2pool-side runtime counterpart of
//   frstrtr/p2pool-merged-v36 : p2pool/test/test_getwork_differential.py
// It asserts byte-identical serialization across paths ("old path == new
// path") by ACTUALLY round-tripping real corpus shares through the production
// LTC share codec (src/impl/ltc/share.hpp SHARE_FORMATTER) at RUNTIME -- not
// against a hand-transcribed oracle like the static KAT
// (LTC_threetier_wirecompat.ST2_desired_version_vote_byte / ST3_*).
//
// A field-order or encoding drift in ltc/share.hpp or ltc/share_types.hpp that
// silently diverges from what a T-A (jtoomim) node round-trips fails HERE:
//   ROUNDTRIP     : load_share(hex) -> re-Serialize -> bytes IDENTICAL to input.
//   ST2_runtime   : desired_version survives a full re-encode/re-parse round
//                   trip and its VarInt (== Bitcoin CompactSize) vote slice is
//                   visible & correct on the wire for the boundary vote values.
//   ST3_runtime   : a v35-lineage share carries ZERO v36 bytes -- the v35
//                   HashLinkType has NO extra_data VarStr slot the v36
//                   V36HashLinkType inserts; the v35 wire is exactly one
//                   VarStr-length-prefix byte shorter. Driven off the loaded
//                   share's real hash_link so it exercises the runtime path.
//
// Ratchet-state dimension: every corpus assertion runs once tagged state="v35"
// and once state="v36" so the SAME test body is what the soak invokes at each
// crossing stage. CI (no live node) runs BOTH tags against the embedded corpus
// and both must be green. The env var C2POOL_RATCHET_STATE, when set to a
// single tag, narrows the harness to that tag for the in-soak gate.
//
// SOAK INVOCATION (integrator, exit code gates the stage):
//   before the ratchet cross:
//     C2POOL_RATCHET_STATE=v35 ctest -R LTC_threetier_wirecompat_runtime
//   after the ratchet cross:
//     C2POOL_RATCHET_STATE=v36 ctest -R LTC_threetier_wirecompat_runtime
//   unset (CI default) runs both tags.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <sharechain/sharechain.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_types.hpp>

namespace {

// Two REAL type-tagged corpus shares captured on the LTC testnet sharechain,
// reused verbatim from share_test.cpp's LTC_share_test.Init: a 0x21/type-33
// (NewShare, v33) and a 0x23/type-35 (PaddingBugfixShare, v35) share. Both are
// v35-lineage (< 36): HashLinkType, NO extra_data slot on the wire.
const char* CORPUS_TYPE33 =
    "21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203";

const char* CORPUS_TYPE35 =
    "23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc08500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b44785235374766374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a41fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b3210073990593df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c039a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8db8b277110a50a9a268b6";

const char* HEXDIG = "0123456789abcdef";

std::string to_hex(std::span<const std::byte> sp)
{
    std::string s;
    s.reserve(sp.size() * 2);
    for (std::byte b : sp) {
        auto v = static_cast<unsigned>(b);
        s.push_back(HEXDIG[(v >> 4) & 0xf]);
        s.push_back(HEXDIG[v & 0xf]);
    }
    return s;
}

std::string to_hex(const std::vector<unsigned char>& v)
{
    std::string s;
    s.reserve(v.size() * 2);
    for (unsigned char c : v) {
        s.push_back(HEXDIG[(c >> 4) & 0xf]);
        s.push_back(HEXDIG[c & 0xf]);
    }
    return s;
}

// The ratchet-state tags this harness runs. Env var C2POOL_RATCHET_STATE, when
// set to exactly "v35" or "v36", narrows to that single soak stage; otherwise
// (CI default) both tags run and both must be green.
std::vector<std::string> ratchet_states()
{
    const char* e = std::getenv("C2POOL_RATCHET_STATE");
    if (e) {
        std::string s(e);
        if (s == "v35") return {"v35"};
        if (s == "v36") return {"v36"};
    }
    return {"v35", "v36"};
}

struct Loaded
{
    chain::RawShare rshare;      // outer: VarInt(type) || VarStr(contents)
    ltc::ShareType  share;       // heap-allocated variant; caller destroys
    std::string     body_hex;    // original contents (body) bytes, hex
};

// from_hex -> >> RawShare -> load_share. Body (contents) bytes retained.
Loaded load_corpus(const char* hex)
{
    Loaded out;
    PackStream stream_share;
    stream_share.from_hex(hex);
    stream_share >> out.rshare;
    out.body_hex = to_hex(out.rshare.contents.m_data);
    out.share = ltc::load_share(out.rshare, NetService{"0.0.0.0", 0});
    return out;
}

// VarInt(v) == the exact CompactSize slice desired_version rides on the wire.
std::string varint_hex(uint64_t v)
{
    PackStream ss;
    ss << VarInt(v);
    return to_hex(ss.get_span());
}

} // namespace

// ---------------------------------------------------------------------------
// ROUNDTRIP: the c2pool analog of "old path == new path" from the differential.
// Re-emit each loaded corpus share through the production codec and assert the
// bytes are byte-IDENTICAL to the input hex, both the body and the full
// type-tagged wire form. Runs under each ratchet-state tag.
// ---------------------------------------------------------------------------
TEST(LTC_threetier_wirecompat_runtime, ROUNDTRIP)
{
    for (const auto& state : ratchet_states()) {
        SCOPED_TRACE("ratchet_state=" + state);
        for (const char* hex : {CORPUS_TYPE33, CORPUS_TYPE35}) {
            Loaded L = load_corpus(hex);

            // body: production codec re-emit == original contents bytes.
            PackStream body_out;
            L.share.Serialize(body_out);
            EXPECT_EQ(to_hex(body_out.get_span()), L.body_hex)
                << "codec body re-emit diverged (state=" << state << ")";

            // full type-tagged wire form: VarInt(type) || VarStr(body) == input.
            chain::RawShare rewrapped(L.rshare.type, BaseScript(body_out));
            PackStream full_out;
            full_out << rewrapped;
            EXPECT_EQ(to_hex(full_out.get_span()), std::string(hex))
                << "full wire re-emit diverged (state=" << state << ")";

            L.share.destroy();
        }
    }
}

// ---------------------------------------------------------------------------
// ST2_runtime: the desired_version vote is visible & correct through the LIVE
// codec. For each boundary vote value: drive it into a loaded share, re-encode
// the whole share through the production serializer, re-parse, and assert the
// vote survives byte-identically; assert its VarInt == the expected CompactSize
// and that slice is present on the re-emitted wire. Also pins the same VarInt
// codec via the live HashLinkType.m_length path (as the KAT does).
// ---------------------------------------------------------------------------
TEST(LTC_threetier_wirecompat_runtime, ST2_runtime)
{
    struct { uint64_t v; const char* hex; } vec[] = {
        {35, "23"}, {36, "24"}, {252, "fc"},
        {253, "fdfd00"}, {300, "fd2c01"}, {65536, "fe00000100"},
    };

    // 32-byte state operand for the live HashLinkType.m_length codec path.
    std::vector<unsigned char> state32(32);
    for (int i = 0; i < 32; ++i) state32[i] = static_cast<unsigned char>(i);
    const std::string state32_hex = to_hex(state32);

    for (const auto& state : ratchet_states()) {
        SCOPED_TRACE("ratchet_state=" + state);
        for (const auto& t : vec) {
            // (a) live standalone VarInt codec == oracle CompactSize.
            EXPECT_EQ(varint_hex(t.v), std::string(t.hex))
                << "VarInt(" << t.v << ") != CompactSize";

            // (b) same codec via live HashLinkType.m_length (KAT parity).
            {
                ltc::HashLinkType hl;
                hl.m_state.m_data = state32;
                hl.m_length = t.v;
                PackStream ss;
                ss << hl;
                EXPECT_EQ(to_hex(ss.get_span()), state32_hex + t.hex)
                    << "HashLinkType.m_length(" << t.v << ") drift";
            }

            // (c) drive the vote through the FULL production share codec: set
            //     desired_version, re-Serialize, re-parse, assert it survives.
            Loaded L = load_corpus(CORPUS_TYPE35);
            L.share.ACTION({ obj->m_desired_version = t.v; });

            PackStream body2;
            L.share.Serialize(body2);
            const std::string body2_hex = to_hex(body2.get_span());

            chain::RawShare rs2(L.rshare.type, BaseScript(body2));
            ltc::ShareType share2 = ltc::load_share(rs2, NetService{"0.0.0.0", 0});
            uint64_t dv2 = 0;
            share2.ACTION({ dv2 = obj->m_desired_version; });
            EXPECT_EQ(dv2, t.v)
                << "desired_version did not survive codec round-trip";

            // the CompactSize vote slice is actually on the re-emitted wire.
            EXPECT_NE(body2_hex.find(t.hex), std::string::npos)
                << "vote slice " << t.hex << " absent from wire";

            L.share.destroy();
            share2.destroy();
        }
    }
}

// ---------------------------------------------------------------------------
// ST3_runtime: a v35-lineage share carries ZERO v36 bytes. Driven off the
// loaded corpus share's REAL hash_link (state + length): the v35 HashLinkType
// wire is exactly one VarStr-length-prefix byte shorter than the v36
// V36HashLinkType with an EMPTY extra_data, and no extra_data/merged/message
// bytes leak. Any v36-byte leak into the v35 codec is structural, not policy.
// ---------------------------------------------------------------------------
TEST(LTC_threetier_wirecompat_runtime, ST3_runtime)
{
    for (const auto& state : ratchet_states()) {
        SCOPED_TRACE("ratchet_state=" + state);

        // pull the real hash_link fields off the loaded v35 share.
        Loaded L = load_corpus(CORPUS_TYPE35);
        std::vector<unsigned char> hl_state;
        uint64_t hl_len = 0;
        L.share.ACTION({
            hl_state = obj->m_hash_link.m_state.m_data;
            hl_len   = obj->m_hash_link.m_length;
        });
        ASSERT_EQ(hl_state.size(), 32u) << "v35 hash_link state must be 32 bytes";

        // v35 lineage: state(32) || VarInt(len). NO extra_data bytes.
        ltc::HashLinkType v35;
        v35.m_state.m_data = hl_state;
        v35.m_length = hl_len;
        PackStream ss35;
        ss35 << v35;
        const std::string v35_hex = to_hex(ss35.get_span());

        // v36 with EMPTY extra_data: state(32) || VarStr("") == "00" || VarInt(len).
        ltc::V36HashLinkType v36;
        v36.m_state.m_data = hl_state;
        v36.m_extra_data = BaseScript(std::vector<unsigned char>{});
        v36.m_length = hl_len;
        PackStream ss36;
        ss36 << v36;
        const std::string v36_hex = to_hex(ss36.get_span());

        // exactly one VarStr-length-prefix byte longer; that byte is 0x00 at
        // offset 32; removing it yields the v35 wire byte-for-byte.
        ASSERT_EQ(ss36.get_span().size(), ss35.get_span().size() + 1)
            << "v36 hash_link must be exactly 1 byte longer (empty extra VarStr)";
        EXPECT_EQ(v36_hex.substr(64, 2), std::string("00"))
            << "v36 empty extra_data must be a single 00 length prefix";
        EXPECT_EQ(v36_hex.substr(0, 64) + v36_hex.substr(66), v35_hex)
            << "v35 wire must equal v36 wire minus the extra_data prefix byte";

        // non-empty extra_data leaks detectably: state || VarStr(aabbcc) || len.
        ltc::V36HashLinkType v36e;
        v36e.m_state.m_data = hl_state;
        v36e.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
        v36e.m_length = hl_len;
        PackStream ss36e;
        ss36e << v36e;
        const std::string v36e_hex = to_hex(ss36e.get_span());
        EXPECT_EQ(v36e_hex.substr(64, 8), std::string("03aabbcc"))
            << "v36 extra_data must ride as a VarStr the v35 wire never carries";
        EXPECT_EQ(v36e_hex.substr(0, 64), v35_hex.substr(0, 64))
            << "state prefix must be shared";
        // the v35 codec output contains none of the v36 extra_data bytes.
        EXPECT_EQ(v35_hex.find("aabbcc"), std::string::npos)
            << "v36 extra_data bytes leaked into the v35 wire";

        L.share.destroy();
    }
}
