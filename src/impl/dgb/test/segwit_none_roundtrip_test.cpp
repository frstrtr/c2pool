// G1 follow-on — v36 segwit_data PossiblyNoneType None-sentinel round-trip KAT.
//
// FENCED greenlight-gate artifact (test-only; rides the batched G0-G3 operator
// tap with G0 @a7dddbe13 and G1 surface#4 @a2428133f). Closes the None-segwit
// sentinel gap that g1_share_header_byte_pin_test explicitly left out of scope.
//
// ORACLE: frstrtr/p2pool-merged-v36 @9903aab7. data.py:1680 (v36 share_info_type)
// and :702 (pre-v36) both set the segwit_data PossiblyNoneType none_value to
//   dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=2**256-1).
// The witness-commitment path (data.py:1015/1019) recomputes segwit_data fresh
// and non-None, so the all-0xff wtxid root is a WIRE sentinel only and never
// reaches the coinbase commitment calc. Integrator independently re-verified the
// oracle at @9903aab7 before greenlighting (UID2672).
//
// WHAT THIS PINS (non-circular against the oracle pack spec, NOT a second read
// of the SUT serializer):
//   1. The literal None-record WIRE bytes: VarStr-list len 0 (empty txid merkle
//      branch, MERKLE_LINK_SMALL => no index) + 32x 0xff wtxid_merkle_root.
//   2. Symmetric round-trip: nullopt -> serialize -> deserialize -> nullopt
//      (has_value()==false) via the dgb-local SegwitDataPossiblyNone formatter.
//      Serialize-only (the pre-fix state) would deserialize the sentinel as a
//      PRESENT value carrying the 0xff root -- the bogus-witness-commitment bug.
//   3. A genuinely PRESENT value round-trips unchanged and stays present.
//   4. A present value sharing the 0xff wtxid root but a NON-empty branch is NOT
//      collapsed to None -- proves None detection is the FULL record, not a bare
//      wtxid compare.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist (#143), or it becomes a NOT_BUILT sentinel.

#include <impl/dgb/share_types.hpp>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

namespace {

using dgb::SegwitData;
using dgb::SegwitDataDefault;
using dgb::SegwitDataPossiblyNone;
using dgb::MerkleLink;

std::vector<unsigned char> to_bytes(PackStream& s)
{
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(s.data()),
        reinterpret_cast<const unsigned char*>(s.data()) + s.size());
}

uint256 all_ff()
{
    uint256 v;
    v.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return v;
}

// (1) None-record WIRE bytes == oracle none_value layout.
TEST(SegwitNoneRoundtrip, NoneRecordBytesMatchOracle)
{
    std::optional<SegwitData> none = std::nullopt;

    PackStream stream;
    stream << Using<SegwitDataPossiblyNone>(none);

    // Oracle none_value: empty txid_merkle_link branch list (CompactSize 0x00,
    // index suppressed by MERKLE_LINK_SMALL) + wtxid_merkle_root = 2**256-1.
    std::vector<unsigned char> expected;
    expected.push_back(0x00);            // branch list length = 0
    for (int i = 0; i < 32; ++i)         // wtxid_merkle_root = all 0xff
        expected.push_back(0xff);

    ASSERT_EQ(to_bytes(stream), expected);
    ASSERT_EQ(stream.size(), 33u);
}

// (2) nullopt round-trips back to nullopt (symmetric read-side mapping).
TEST(SegwitNoneRoundtrip, NoneRoundTripsToNullopt)
{
    std::optional<SegwitData> none = std::nullopt;

    PackStream stream;
    stream << Using<SegwitDataPossiblyNone>(none);

    std::optional<SegwitData> got;
    got = SegwitData{};                  // poison: must be cleared on read
    stream >> Using<SegwitDataPossiblyNone>(got);

    ASSERT_FALSE(got.has_value());
}

// (3) a genuinely present value round-trips unchanged and stays present.
TEST(SegwitNoneRoundtrip, PresentRoundTripsUnchanged)
{
    SegwitData present;
    present.m_txid_merkle_link.m_branch.push_back(uint256S(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
    present.m_wtxid_merkle_root.SetHex(
        "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f");

    std::optional<SegwitData> opt = present;

    PackStream stream;
    stream << Using<SegwitDataPossiblyNone>(opt);

    std::optional<SegwitData> got;
    stream >> Using<SegwitDataPossiblyNone>(got);

    ASSERT_TRUE(got.has_value());
    ASSERT_EQ(got.value(), present);
}

// (4) present value with the 0xff wtxid root but a NON-empty branch must NOT
//     collapse to None -- None detection is the full record, not a bare wtxid.
TEST(SegwitNoneRoundtrip, FullRecordCompareNotBareWtxid)
{
    SegwitData near_sentinel;
    near_sentinel.m_txid_merkle_link.m_branch.push_back(uint256S(
        "0000000000000000000000000000000000000000000000000000000000000001"));
    near_sentinel.m_wtxid_merkle_root = all_ff();   // same 0xff root as sentinel

    std::optional<SegwitData> opt = near_sentinel;

    PackStream stream;
    stream << Using<SegwitDataPossiblyNone>(opt);

    std::optional<SegwitData> got;
    stream >> Using<SegwitDataPossiblyNone>(got);

    ASSERT_TRUE(got.has_value());
    ASSERT_EQ(got.value(), near_sentinel);
}

// Guard: SegwitDataDefault::get() IS the oracle sentinel (all-0xff wtxid).
TEST(SegwitNoneRoundtrip, DefaultIsOracleSentinel)
{
    SegwitData def = SegwitDataDefault::get();
    EXPECT_TRUE(def.m_txid_merkle_link.m_branch.empty());
    EXPECT_EQ(def.m_wtxid_merkle_root, all_ff());
}

} // namespace
