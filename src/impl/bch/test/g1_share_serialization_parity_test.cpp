// ---------------------------------------------------------------------------
// bch G1 share-serialization byte-parity KAT (greenlight gate G1, share layer).
//
// FENCED conformance test (no production code touched). Complements
// g1_oracle_byte_parity_test (which pins net/consensus constants): this KAT
// pins the on-the-wire SHARE serialization byte layout of the c2pool-bch SUT
// against the wire format hand-transcribed from the BCH crossing oracle
// jtoomim / frstrtr/p2pool-merged-v36  p2pool/data.py:
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
// (N raw bytes, no prefix) semantics -- NOT a second read of the same C++ SUT
// serializer. A field-order or encoding drift in share_types.hpp / RawShare
// that silently diverges from the oracle fails HERE even though every other bch
// share test (which sources the same SUT serializer on both sides) stays green.
//
// PINNED LIVE SHARE VERSION / accept-both crossing floor:
//   CROSSING_FLOOR_VERSION == 35 is the version the live jtoomim BCH net mints
//   today; it is the SSOT feeding author/ref_hash/donation and the accept-both
//   floor until the 60%-by-work auto-ratchet (#326/#577) flips to v36. Pinned
//   here so a silent bump of the crossing floor (which would fork the live
//   sharechain) reddens this gate.
//
// 3-bucket posture (operator 2026-06-17):
//   - the share wire FORMAT is bucket-2 v36-native shared structure -> pinned
//     toward the canonical jtoomim layout (this KAT).
//   - CROSSING_FLOOR_VERSION is a bucket-3 transition value (accept-both floor),
//     dropped after the ratchet crossing-soak; pinned here for the crossing only.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml COIN_BCH --target allowlist, or it becomes a #143-style NOT_BUILT
// sentinel that silently never builds.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <sharechain/share.hpp>
#include "../config_pool.hpp"
#include "../share_types.hpp"

static int failures = 0;
#define CHECK_EQ(label, got, want) do {                                        \
    if ((got) != (want)) {                                                      \
        std::cerr << "FAIL: " << (label) << "\n  want: " << (want)              \
                  << "\n  got : " << (got) << "\n";                             \
        ++failures;                                                             \
    }                                                                          \
} while (0)

static std::string to_hex(std::span<std::byte> sp)
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

// 32-byte state: 0x00,0x01,...,0x1f  (transcribed as the oracle FixedStrType(32)
// operand). Same value reused for the v35 and v36 hash_link vectors.
static const std::string STATE_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

static std::string state_raw()
{
    std::string s;
    for (int i = 0; i < 32; ++i) s.push_back(static_cast<char>(i));
    return s;
}

int main()
{
    using PC = bch::PoolConfig;

    // -- 0. pinned live share version (accept-both crossing floor) ------------
    // Oracle: live jtoomim BCH net mints v35 today; ratchet-current SSOT.
    CHECK_EQ("CROSSING_FLOOR_VERSION == 35 (live jtoomim mint / accept floor)",
             (int)PC::CROSSING_FLOOR_VERSION, 35);

    // -- 1. hash_link_type (v35): state(32) + FixedStr(0) empty + VarInt(len) --
    // Oracle wire = <32-byte state> || <length VarInt>. extra_data FixedStr(0)
    // contributes ZERO bytes. length = 300 -> CompactSize "fd2c01".
    {
        bch::HashLinkType hl;
        hl.m_state  = FixedStrType<32>(state_raw());
        hl.m_length = 300;

        PackStream ss;
        ss << hl;
        const std::string want = STATE_HEX + "fd2c01";
        CHECK_EQ("v35 hash_link_type wire (state||VarInt len, no extra_data)",
                 to_hex(ss.get_span()), want);
    }

    // -- 2. v36_hash_link_type: state(32) + VarStr(extra_data) + VarInt(len) ---
    // Oracle wire = <32-byte state> || <VarStr extra_data> || <length VarInt>.
    // extra_data = aa bb cc -> VarStr "03aabbcc"; length = 300 -> "fd2c01".
    {
        bch::V36HashLinkType hl;
        hl.m_state      = FixedStrType<32>(state_raw());
        hl.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
        hl.m_length     = 300;

        PackStream ss;
        ss << hl;
        const std::string want = STATE_HEX + "03aabbcc" + "fd2c01";
        CHECK_EQ("v36_hash_link_type wire (state||VarStr extra_data||VarInt len)",
                 to_hex(ss.get_span()), want);
    }

    // -- 3. share_type outer wrapper: VarInt(type) + VarStr(contents) ----------
    // Oracle share_type = ('type', VarIntType()), ('contents', VarStrType()).
    // type=35 -> "23"; contents = de ad be ef -> VarStr "04deadbeef".
    {
        chain::RawShare rs(35, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
        PackStream ss;
        ss << rs;
        const std::string want = std::string("23") + "04deadbeef";
        CHECK_EQ("share_type wrapper wire v35 (VarInt type || VarStr contents)",
                 to_hex(ss.get_span()), want);
    }
    {
        // post-ratchet v36 type tag still single-byte CompactSize -> "24".
        chain::RawShare rs(36, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
        PackStream ss;
        ss << rs;
        const std::string want = std::string("24") + "04deadbeef";
        CHECK_EQ("share_type wrapper wire v36 (VarInt type || VarStr contents)",
                 to_hex(ss.get_span()), want);
    }

    if (failures) {
        std::cerr << "\nbch G1 share-serialization byte-parity KAT: "
                  << failures << " MISMATCH(es) vs jtoomim oracle wire format\n";
        return 1;
    }
    std::cout << "bch G1 share-serialization byte-parity KAT: PASS "
                 "(share_type + hash_link v35/v36 + crossing-floor v35 pinned)\n";
    return 0;
}
