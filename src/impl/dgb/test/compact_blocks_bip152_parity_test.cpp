// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_compact_blocks_bip152_parity_test -- FENCED, additive KAT pinning the
// BIP 152 compact-block RELAY wire primitives in coin/compact_blocks.hpp:
//   * ShortTxID 6-byte little-endian byte layout + to_uint64() inverse, and
//   * the differential transaction-index encoding/decoding on
//     BlockTransactionsRequest (the "getblocktxn" message).
//
// Both are RELAY-ONLY (the embedded P2P compact-block path reconstructs a full
// block which is then validated normally): NO consensus surface, no PoW, no
// share format, no payout/subsidy/version-gate value. A 1-byte divergence in
// either primitive only changes bandwidth/reconstruction, never block validity,
// but a silent drift there desyncs us from any BIP 152 peer (DigiByte Core /
// the btc-family relay this header 1:1 mirrors).
//
// The anchors are NON-CIRCULAR. BIP 152 fixes both encodings by spec:
//   * short IDs are 6 bytes, least-significant byte first (the spec's
//     "6-byte integer" little-endian wire form) -- pinned here with hand-written
//     byte goldens, not by re-deriving them from the code under test.
//   * differential indexes: "The first index ... is the absolute index. Each
//     subsequent index is the difference minus one from the previous" -- so the
//     absolute list {0,2,6,10,11} MUST serialise its index diffs as
//     {0,1,3,3,0} (2-0-1, 6-2-1, 10-6-1, 11-10-1). The expected diff bytes are
//     computed by hand from the spec and asserted against the on-the-wire bytes
//     the BlockTransactionsRequest serialiser emits.
//
// DIAGNOSTICS / WIRE-RELAY ONLY. No call site rewired; pins existing behaviour.
// MUST also appear in BOTH build.yml --target allowlists (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/compact_blocks.hpp"

using dgb::coin::ShortTxID;
using dgb::coin::BlockTransactionsRequest;

namespace {

// Pull the bytes a PackStream currently holds into a plain vector<uint8_t> so
// the wire encoding can be asserted byte for byte.
std::vector<uint8_t> drain(PackStream& ps)
{
    std::vector<uint8_t> out;
    out.reserve(ps.size());
    const std::byte* p = ps.data();
    for (size_t i = 0; i < ps.size(); ++i)
        out.push_back(static_cast<uint8_t>(p[i]));
    return out;
}

} // namespace

// A short ID is the low 48 bits of a uint64, stored least-significant byte
// first. The byte goldens are written by hand from the BIP 152 6-byte LE form.
TEST(DgbCompactBlocksBip152Parity, ShortTxIDLittleEndianByteLayout)
{
    ShortTxID s(0x123456789abcULL);
    const uint8_t expect[6] = {0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12};
    for (int i = 0; i < 6; ++i)
        EXPECT_EQ(s.data[i], expect[i]) << "byte " << i;
    EXPECT_EQ(s.to_uint64(), 0x123456789abcULL);
}

// Boundary values round-trip through the 6-byte form: zero, one, and the
// 48-bit maximum (everything above 2^48 is masked off by construction).
TEST(DgbCompactBlocksBip152Parity, ShortTxIDRoundTripBoundaries)
{
    for (uint64_t v : {uint64_t(0), uint64_t(1), uint64_t(0xffffffffffffULL)})
        EXPECT_EQ(ShortTxID(v).to_uint64(), v);

    // The top byte of a 6-byte ID survives (pins that it is byte index 5).
    ShortTxID hi(0xff0000000000ULL);
    EXPECT_EQ(hi.data[5], 0xff);
    EXPECT_EQ(hi.data[0], 0x00);
}

// getblocktxn differential index encoding: absolute {0,2,6,10,11} must emit
// the spec diff sequence {0,1,3,3,0}. Blockhash left null so the 32 leading
// wire bytes are zero and the index region is unambiguous.
TEST(DgbCompactBlocksBip152Parity, GetBlockTxnDifferentialIndexWireBytes)
{
    BlockTransactionsRequest req;
    req.blockhash = uint256::ZERO;
    req.indexes = {0u, 2u, 6u, 10u, 11u};

    PackStream ps;
    req.Serialize(ps);
    const std::vector<uint8_t> wire = drain(ps);

    // 32 (blockhash) + 1 (count) + 5 (single-byte diffs) = 38 bytes.
    ASSERT_EQ(wire.size(), 38u);
    for (int i = 0; i < 32; ++i)
        EXPECT_EQ(wire[i], 0x00) << "blockhash byte " << i;
    EXPECT_EQ(wire[32], 0x05);  // CompactSize(5)
    const uint8_t expect_diffs[5] = {0x00, 0x01, 0x03, 0x03, 0x00};
    for (int i = 0; i < 5; ++i)
        EXPECT_EQ(wire[33 + i], expect_diffs[i]) << "diff " << i;
}

// Decoding the differential stream reconstructs the ABSOLUTE index list and the
// blockhash unchanged -- the inverse of the encoding above.
TEST(DgbCompactBlocksBip152Parity, GetBlockTxnDifferentialIndexRoundTrip)
{
    BlockTransactionsRequest req;
    req.blockhash = uint256S(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    req.indexes = {0u, 2u, 6u, 10u, 11u};

    PackStream ps;
    req.Serialize(ps);
    std::vector<unsigned char> bytes;
    {
        const std::byte* p = ps.data();
        bytes.assign(reinterpret_cast<const unsigned char*>(p),
                     reinterpret_cast<const unsigned char*>(p) + ps.size());
    }

    BlockTransactionsRequest got;
    PackStream rs(bytes);
    got.Unserialize(rs);

    EXPECT_EQ(got.blockhash, req.blockhash);
    EXPECT_EQ(got.indexes, req.indexes);
}

// Edge cases: the first index is absolute (not delta-encoded), and an empty
// index list serialises to a bare CompactSize(0).
TEST(DgbCompactBlocksBip152Parity, GetBlockTxnFirstAbsoluteAndEmpty)
{
    {
        BlockTransactionsRequest req;
        req.blockhash = uint256::ZERO;
        req.indexes = {7u};
        PackStream ps;
        req.Serialize(ps);
        const std::vector<uint8_t> wire = drain(ps);
        ASSERT_EQ(wire.size(), 34u);   // 32 + count(1) + diff(1)
        EXPECT_EQ(wire[32], 0x01);     // CompactSize(1)
        EXPECT_EQ(wire[33], 0x07);     // first index is absolute -> 7, not 6
    }
    {
        BlockTransactionsRequest req;
        req.blockhash = uint256::ZERO;
        PackStream ps;
        req.Serialize(ps);
        const std::vector<uint8_t> wire = drain(ps);
        ASSERT_EQ(wire.size(), 33u);   // 32 + count(0)
        EXPECT_EQ(wire[32], 0x00);

        BlockTransactionsRequest got;
        std::vector<unsigned char> bytes(
            reinterpret_cast<const unsigned char*>(ps.data()),
            reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
        PackStream rs(bytes);
        got.Unserialize(rs);
        EXPECT_TRUE(got.indexes.empty());
    }
}