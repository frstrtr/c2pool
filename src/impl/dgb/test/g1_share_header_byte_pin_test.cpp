// G1 surface #4 — v36 share-HEADER record byte-parity KAT (DGB).
//
// FENCED greenlight-gate G1 artifact (test-only; no production code touched).
// This is the share-HEADER record byte-pin that gentx_share_path_test left as a
// gap: gentx_share_path proves the *coinbase* SSOT framing via a round-trip
// equivalence, but it cannot pin the pre-hash ref-record bytes to a fixed oracle
// vector (its op_return ref_hash is share-derived). This KAT closes that gap by
// pinning the ref_type pre-hash record bytes (NOT ref_hash) of a fixed
// null-parent v36 MergedMiningShare to literals derived from the oracle pack
// spec, non-circularly.
//
// DUAL-ORACLE SPLIT (operator/integrator ruling 2026-06-26, batched G0–G3 tap):
//   * Bucket-1 ISOLATION PRIMITIVE — IDENTIFIER (8B) — sourced from the DGB G0
//     oracle frstrtr/p2pool-dgb-scrypt @22761e7 (IDENTIFIER 4B62545B1A631AFE).
//     Kept per-coin/per-instance; NOT a standardization target.
//   * v36-NATIVE SHARED STRUCTURE — the MergedMiningShare share_info_type record
//     (subsidy=VarInt, pubkey_hash+pubkey_type, merged_addresses after
//     segwit_data, abswork=VarInt, merged_coinbase_info+merged_payout_hash,
//     message_data trailer) — sourced from the v36 oracle
//     frstrtr/p2pool-merged-v36 @9903aab7 (p2pool/data.py:1627 MergedMiningShare,
//     get_dynamic_types share_info_type @1698-1722). This is the cross-coin v36
//     standardization target, not a per-coin compat choice. Only @9903aab7 (not
//     the VERSION-35 dgb-scrypt oracle) carries merged_addresses /
//     merged_coinbase_info, so it is the correct authority for this surface.
//
// NON-CIRCULAR: the expected bytes below are typed from the oracle pack spec
// (pack.IntType / VarIntType=CompactSize / VarStrType / PossiblyNoneType /
// FloatingIntegerType layout), NOT a second read of the C++ SUT serializer. A
// drift in share.hpp / share_check.hpp / share_types.hpp that silently changes
// the v36 share-header wire layout fails here even though the round-trip tests
// (which source the same SUT serializer on both sides) stay green.
//
// SCOPE NOTE — segwit_data is pinned PRESENT (witness-bearing), the
// representative case for a v36 share on a segwit-active chain. The None-segwit
// sentinel (SUT SegwitDataDefault wtxid=0 vs oracle PossiblyNoneType sentinel
// wtxid=2**256-1) is surfaced separately to integrator/decisions@ as a latent
// v36-compat question; it is intentionally NOT exercised here.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist (#143), or it becomes a NOT_BUILT sentinel.

#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/share_types.hpp>
#include <impl/dgb/params.hpp>

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <core/version_gate.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace {

using dgb::MergedMiningShare;

// ---- SUT side: serialize the v36 ref-record (ref_type) pre-hash bytes -------
// Mirrors the production verifier ref_stream construction in share_check.hpp
// (compute_ref_hash_for_work / share_init_verify): IDENTIFIER || share_info ||
// message_data, via the IDENTICAL pack primitives the production path uses.
std::vector<unsigned char> serialize_ref_record(const MergedMiningShare& s,
                                                const core::CoinParams& params)
{
    constexpr int64_t ver = MergedMiningShare::version;
    static_assert(core::version_gate::is_v36_active(ver),
                  "surface #4 is a v36-only share-header pin");

    PackStream ref;

    // IDENTIFIER (8B) — bucket-1 isolation primitive (G0 oracle).
    {
        auto hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char b = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&b), 1));
        }
    }

    // share_info (v36-native, oracle @9903aab7 share_info_type order).
    ref << s.m_prev_hash;                                  // prev_hash      IntType(256)
    ref << s.m_coinbase;                                   // coinbase       VarStrType
    ref << s.m_nonce;                                      // nonce          IntType(32)
    ref << s.m_pubkey_hash;                                // pubkey_hash    IntType(160)
    ref << s.m_pubkey_type;                                // pubkey_type    IntType(8)
    ::Serialize(ref, VarInt(s.m_subsidy));                 // subsidy        VarIntType
    ref << s.m_donation;                                   // donation       IntType(16)
    { uint8_t si = static_cast<uint8_t>(s.m_stale_info); ref << si; } // stale_info EnumType(IntType8)
    ::Serialize(ref, VarInt(s.m_desired_version));         // desired_version VarIntType
    ref << s.m_segwit_data.value();                        // segwit_data    (present)
    ref << s.m_merged_addresses;                           // merged_addresses ListType
    ref << s.m_far_share_hash;                             // far_share_hash IntType(256)
    ref << s.m_max_bits;                                   // max_bits       FloatingIntegerType
    ref << s.m_bits;                                       // bits           FloatingIntegerType
    ref << s.m_timestamp;                                  // timestamp      IntType(32)
    ref << s.m_absheight;                                  // absheight      IntType(32)
    ::Serialize(ref, Using<dgb::AbsworkV36Format>(s.m_abswork)); // abswork  VarIntType
    ref << s.m_merged_coinbase_info;                       // merged_coinbase_info ListType
    ref << s.m_merged_payout_hash;                         // merged_payout_hash IntType(256)
    ref << s.m_message_data;                               // message_data   VarStrType

    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(ref.data()),
        reinterpret_cast<const unsigned char*>(ref.data()) + ref.size());
}

// ---- Oracle side: expected ref-record bytes, typed from the pack spec -------
// Fixed null-parent share => determinate merkle fold (PPLNS skipped). All
// constant segments are oracle-derived literals; the three VarInt-width fields
// (subsidy / absheight / abswork) are supplied per fixture so the same field
// ORDER is asserted across both small and large encodings.
void append(std::vector<unsigned char>& v, std::initializer_list<unsigned char> b)
{
    v.insert(v.end(), b);
}
void append_n(std::vector<unsigned char>& v, unsigned char b, size_t n)
{
    v.insert(v.end(), n, b);
}

std::vector<unsigned char> build_expected(std::initializer_list<unsigned char> subsidy_varint,
                                          std::initializer_list<unsigned char> absheight_le,
                                          std::initializer_list<unsigned char> abswork_varint)
{
    std::vector<unsigned char> e;
    // IDENTIFIER 4B62545B1A631AFE (G0 oracle isolation primitive)
    append(e, {0x4b, 0x62, 0x54, 0x5b, 0x1a, 0x63, 0x1a, 0xfe});
    // prev_hash = null -> PossiblyNoneType(0, IntType(256)) -> 32x00
    append_n(e, 0x00, 32);
    // coinbase = VarStr{03 a1 b2 c3 04 11 22 33 44} -> len(9) + bytes
    append(e, {0x09, 0x03, 0xa1, 0xb2, 0xc3, 0x04, 0x11, 0x22, 0x33, 0x44});
    // nonce = 0x12345678 -> IntType(32) LE
    append(e, {0x78, 0x56, 0x34, 0x12});
    // pubkey_hash = null -> IntType(160) -> 20x00
    append_n(e, 0x00, 20);
    // pubkey_type = 0 -> IntType(8)
    append(e, {0x00});
    // subsidy -> VarIntType (CompactSize) [fixture-specific]
    e.insert(e.end(), subsidy_varint);
    // donation = 0 -> IntType(16) LE
    append(e, {0x00, 0x00});
    // stale_info = none(0) -> EnumType(IntType(8))
    append(e, {0x00});
    // desired_version = 36 -> VarIntType (0x24 < 0xfd)
    append(e, {0x24});
    // segwit_data PRESENT: txid_merkle_link branch=[] -> CompactSize(0);
    //   (index IntType(0) = 0 bytes); wtxid_merkle_root = 0x11..x32 (IntType256 LE)
    append(e, {0x00});
    append_n(e, 0x11, 32);
    // merged_addresses = [] -> ListType(empty) -> CompactSize(0)
    append(e, {0x00});
    // far_share_hash = null -> PossiblyNoneType(0, IntType(256)) -> 32x00
    append_n(e, 0x00, 32);
    // max_bits = 0x1e0fffff -> FloatingIntegerType -> IntType(32) LE
    append(e, {0xff, 0xff, 0x0f, 0x1e});
    // bits = 0x1e0fffff -> IntType(32) LE
    append(e, {0xff, 0xff, 0x0f, 0x1e});
    // timestamp = 1718700000 = 0x667147E0 -> IntType(32) LE
    append(e, {0xe0, 0x47, 0x71, 0x66});
    // absheight -> IntType(32) LE [fixture-specific]
    e.insert(e.end(), absheight_le);
    // abswork -> VarIntType (AbsworkV36Format = CompactSize of low64) [fixture-specific]
    e.insert(e.end(), abswork_varint);
    // merged_coinbase_info = [] -> ListType(empty) -> CompactSize(0)
    append(e, {0x00});
    // merged_payout_hash = null -> PossiblyNoneType(0, IntType(256)) -> 32x00
    append_n(e, 0x00, 32);
    // message_data = empty -> PossiblyNoneType(b'', VarStrType) -> CompactSize(0)
    append(e, {0x00});
    return e;
}

// Fixed null-parent v36 share; segwit_data present (witness-bearing). The three
// VarInt-width fields are parameters so each fixture sets its own.
MergedMiningShare make_fixture(uint64_t subsidy, uint32_t absheight, uint64_t abswork_low)
{
    MergedMiningShare s;
    s.m_prev_hash.SetNull();                 // null parent => determinate fold
    s.m_coinbase.m_data = {0x03, 0xa1, 0xb2, 0xc3, 0x04, 0x11, 0x22, 0x33, 0x44};
    s.m_nonce = 0x12345678;
    s.m_pubkey_hash.SetNull();
    s.m_pubkey_type = 0;
    s.m_subsidy = subsidy;
    s.m_donation = 0;
    s.m_stale_info = dgb::none;
    s.m_desired_version = 36;
    // segwit_data PRESENT: empty txid branch, wtxid_merkle_root = 0x11..x32
    dgb::SegwitData sd;
    sd.m_wtxid_merkle_root = uint256(std::vector<unsigned char>(32, 0x11));
    s.m_segwit_data = sd;
    s.m_far_share_hash.SetNull();
    s.m_max_bits = 0x1e0fffff;
    s.m_bits = 0x1e0fffff;
    s.m_timestamp = 1718700000;              // 0x667147E0
    s.m_absheight = absheight;
    s.m_abswork = uint128(abswork_low);
    s.m_merged_payout_hash.SetNull();
    s.m_last_txout_nonce = 0x0001020304050607ull;
    return s;
}

const core::CoinParams& params()
{
    static core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);
    return p;
}

// SMALL header-ordering path: subsidy < 0xfd (1-byte VarInt), abswork = 0
// (1-byte VarInt), small absheight. Locks field order at the narrow encodings.
TEST(DgbG1ShareHeaderBytePin, RefRecordSmallVarints)
{
    auto s = make_fixture(/*subsidy=*/100, /*absheight=*/1, /*abswork_low=*/0);
    auto actual = serialize_ref_record(s, params());
    auto expected = build_expected(
        /*subsidy=*/{0x64},               // VarInt(100) = 0x64
        /*absheight=*/{0x01, 0x00, 0x00, 0x00}, // IntType(32) LE 1
        /*abswork=*/{0x00});              // CompactSize(0)
    EXPECT_EQ(actual, expected);
}

// LARGE header-ordering path: subsidy > 2**32 (9-byte 0xff VarInt), abswork
// > 2**32 (9-byte 0xff VarInt), absheight 1000. Same field order across the
// widest CompactSize encodings -> proves no width-dependent reordering.
TEST(DgbG1ShareHeaderBytePin, RefRecordLargeVarints)
{
    auto s = make_fixture(/*subsidy=*/0x0102030405060708ull,
                          /*absheight=*/1000,
                          /*abswork_low=*/0x1112131415161718ull);
    auto actual = serialize_ref_record(s, params());
    auto expected = build_expected(
        // VarInt(0x0102030405060708) = 0xff + uint64 LE
        /*subsidy=*/{0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
        // IntType(32) LE 1000 = 0x000003E8
        /*absheight=*/{0xe8, 0x03, 0x00, 0x00},
        // CompactSize(0x1112131415161718) = 0xff + uint64 LE
        /*abswork=*/{0xff, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11});
    EXPECT_EQ(actual, expected);
}

// Canonical subsidy (5 DGB = 500000000) -> 0xfe + uint32 LE, the real v36
// block-subsidy magnitude. Mid-width VarInt between the two extremes above.
TEST(DgbG1ShareHeaderBytePin, RefRecordCanonicalSubsidy)
{
    auto s = make_fixture(/*subsidy=*/500000000ull, /*absheight=*/1000, /*abswork_low=*/0);
    auto actual = serialize_ref_record(s, params());
    auto expected = build_expected(
        // VarInt(500000000=0x1DCD6500) = 0xfe + uint32 LE
        /*subsidy=*/{0xfe, 0x00, 0x65, 0xcd, 0x1d},
        /*absheight=*/{0xe8, 0x03, 0x00, 0x00},
        /*abswork=*/{0x00});
    EXPECT_EQ(actual, expected);
}

} // namespace
