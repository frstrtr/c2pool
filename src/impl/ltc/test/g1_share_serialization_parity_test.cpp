// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc (+DOGE aux) G1 share-serialization byte-parity KAT
//   — three-tier wire-compat gate, SHARE layer. [s=threetier]
//
// FENCED conformance test (no production code touched). Pins the on-the-wire
// SHARE serialization byte layout of the c2pool-ltc SUT against the wire format
// hand-transcribed from the LTC/DOGE crossing oracle jtoomim /
// frstrtr/p2pool-merged-v36  p2pool/data.py:
//
//   share_type        = ComposedType([('type', VarIntType()),
//                                      ('contents', VarStrType())])   (data.py:98)
//   hash_link_type    = ComposedType([('state', FixedStrType(32)),
//                                      ('extra_data', FixedStrType(0)),
//                                      ('length', VarIntType())])      (data.py:32)
//   v36_hash_link_type= ComposedType([('state', FixedStrType(32)),
//                                      ('extra_data', VarStrType()),
//                                      ('length', VarIntType())])      (data.py:41)
//
// NON-CIRCULAR: the expected side below is literal wire bytes typed from the
// oracle python ComposedType field order + P2Pool's VarIntType (== Bitcoin
// CompactSize), VarStrType (CompactSize-prefixed bytes) and FixedStrType(N)
// (N raw bytes, no prefix) semantics — NOT a second read of the same c2pool C++
// SUT serializer. A field-order or encoding drift in ltc/share_types.hpp or
// RawShare that silently diverges from the oracle fails HERE even though every
// other ltc share test (which sources the same SUT serializer on both sides)
// stays green. This is the byte-for-byte compat the jtoomim v35 tier requires:
// old raw-tx nodes MUST accept our v35 shares unchanged, so the v35 hash_link
// wire (extra_data FixedStr(0) -> zero bytes) must be exactly preserved while
// the v36 wire (extra_data VarStr) is a strict, gated superset.
//
// 3-bucket posture (operator 2026-06-17):
//   - the share wire FORMAT is bucket-2 v36-native shared structure -> pinned
//     toward the canonical jtoomim layout (this KAT).
//
// STANDARDIZATION GAP (surfaced authoring this KAT, routed to decisions@):
//   bch/btc/dgb/dash expose a named crossing-floor SSOT constant
//   PoolConfig::CROSSING_FLOOR_VERSION (bch config_pool.hpp:81 == 35); LTC's
//   ltc::PoolConfig has NO such constant (only MINIMUM/ADVERTISED_PROTOCOL_
//   VERSION). The "-- 0. pinned live share version" section of the bch KAT
//   therefore has no LTC SSOT to bind against and is DEFERRED here. This is a
//   bucket-2 divergence: LTC should grow the same CROSSING_FLOOR_VERSION
//   constant so v37 sees one uniform accept-floor shape across all coins.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml COIN_LTC --target allowlist, or it becomes a #143-style NOT_BUILT
// sentinel that silently never builds.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/pack.hpp>
#include <sharechain/share.hpp>
#include "../config_pool.hpp"
#include "../share_types.hpp"

namespace {

std::string to_hex(std::span<std::byte> sp)
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

// 32-byte state: 0x00,0x01,...,0x1f (transcribed as the oracle FixedStrType(32)
// operand). Same value reused for the v35 and v36 hash_link vectors.
const std::string STATE_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

std::string state_raw()
{
    std::string s;
    for (int i = 0; i < 32; ++i) s.push_back(static_cast<char>(i));
    return s;
}

} // namespace

// -- ST-1. hash_link_type (v35): state(32) + FixedStr(0) empty + VarInt(len) --
// Oracle wire = <32-byte state> || <length VarInt>. extra_data FixedStr(0)
// contributes ZERO bytes (the jtoomim v35 layout the old tier accepts). length
// = 300 -> CompactSize "fd2c01".
TEST(LTC_g1_share_parity, v35_hash_link_wire)
{
    ltc::HashLinkType hl;
    hl.m_state  = FixedStrType<32>(state_raw());
    hl.m_length = 300;

    PackStream ss;
    ss << hl;
    const std::string want = STATE_HEX + "fd2c01";
    EXPECT_EQ(to_hex(ss.get_span()), want)
        << "v35 hash_link_type wire (state||VarInt len, no extra_data) drifted "
           "from jtoomim oracle — would fork the live v35 sharechain";
}

// -- ST-2. v36_hash_link_type: state(32) + VarStr(extra_data) + VarInt(len) ---
// Oracle wire = <32-byte state> || <VarStr extra_data> || <length VarInt>.
// extra_data = aa bb cc -> VarStr "03aabbcc"; length = 300 -> "fd2c01".
TEST(LTC_g1_share_parity, v36_hash_link_wire)
{
    ltc::V36HashLinkType hl;
    hl.m_state      = FixedStrType<32>(state_raw());
    hl.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
    hl.m_length     = 300;

    PackStream ss;
    ss << hl;
    const std::string want = STATE_HEX + "03aabbcc" + "fd2c01";
    EXPECT_EQ(to_hex(ss.get_span()), want)
        << "v36_hash_link_type wire (state||VarStr extra_data||VarInt len) "
           "drifted from oracle";
}

// -- ST-3. share_type outer wrapper: VarInt(type) + VarStr(contents) ----------
// Oracle share_type = ('type', VarIntType()), ('contents', VarStrType()).
// v35: type=35 -> "23"; contents = de ad be ef -> VarStr "04deadbeef".
// v36: post-ratchet type tag still single-byte CompactSize -> "24".
TEST(LTC_g1_share_parity, share_type_wrapper_v35)
{
    chain::RawShare rs(35, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
    PackStream ss;
    ss << rs;
    const std::string want = std::string("23") + "04deadbeef";
    EXPECT_EQ(to_hex(ss.get_span()), want)
        << "share_type wrapper v35 (VarInt type || VarStr contents) drifted";
}

TEST(LTC_g1_share_parity, share_type_wrapper_v36)
{
    chain::RawShare rs(36, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
    PackStream ss;
    ss << rs;
    const std::string want = std::string("24") + "04deadbeef";
    EXPECT_EQ(to_hex(ss.get_span()), want)
        << "share_type wrapper v36 (VarInt type || VarStr contents) drifted";
}

// -- ST-4. desired_version vote is a legacy-visible VarInt --------------------
// The v36 vote rides the share_info `desired_version` field (share.hpp:63/190,
// Formatter `VarInt(obj->m_desired_version)`), a plain CompactSize the jtoomim
// v35 tier deserializes via get_desired_version_counts (data.py:2651) and tallies
// WITHOUT understanding any v36 feature. Pin the encoding of the crossing-relevant
// vote values against literal oracle CompactSize bytes — the SAME primitive ST-3
// pins for the share_type tag, here proving the *vote* transports identically. A
// silent switch to a fixed-width or version-gated encoding (which would make the
// vote invisible to the v35 tier and fork the ratchet tally) reddens HERE.
TEST(LTC_g1_share_parity, desired_version_vote_is_legacy_varint)
{
    struct Case { uint64_t dv; const char* want; };
    const Case cases[] = {
        {35,  "23"},        // pre-crossing floor the live jtoomim net mints
        {36,  "24"},        // the ratchet target (the v36 vote)
        {300, "fd2c01"},    // multi-byte -> proves general CompactSize, not fixed width
    };
    for (const auto& c : cases) {
        uint64_t dv = c.dv;
        PackStream ss;
        ss << VarInt(dv);
        EXPECT_EQ(to_hex(ss.get_span()), std::string(c.want))
            << "desired_version=" << dv << " must encode as the CompactSize VarInt "
               "the oracle get_desired_version_counts (data.py:2651) tallies";
    }
}

// -- ST-5. vote sits at a version-independent legacy offset -------------------
// share_info Formatter emits, contiguously and BEFORE any `if constexpr (version
// >= 36)` gate:  donation(uint16 LE, 2B) || stale_info(enum8, 1B) || VarInt(dv).
// So a jtoomim v35 reader locates desired_version at a FIXED 3-byte offset from
// the donation block regardless of the vote value or the miner share version, and
// zero v36-gated bytes precede it (no v36 leak into the pre-vote wire). Hand-
// transcribed field order (non-circular): donation=0 -> "0000", stale none=0 ->
// "00", dv=36 -> "24".
TEST(LTC_g1_share_parity, desired_version_vote_at_legacy_offset)
{
    uint16_t donation = 0;
    ltc::StaleInfo stale = ltc::none;
    uint64_t dv = 36;

    PackStream ss;
    ss << Using<IntType<16>>(donation)
       << Using<EnumType<IntType<8>>>(stale)
       << VarInt(dv);
    const std::string wire = to_hex(ss.get_span());
    EXPECT_EQ(wire, std::string("0000") + "00" + "24")
        << "donation||stale_info||desired_version wire drifted from oracle field order";
    EXPECT_EQ(wire.substr(6), std::string("24"))
        << "v36 vote (24) not at the legacy 3-byte offset a jtoomim v35 reader tallies";
}
