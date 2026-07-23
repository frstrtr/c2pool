// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// c2pool::dgb::make_header_sample / compact_to_target test (embedded-ingest
// HeaderSample builder).
//
// Pins the boundary where a parsed BlockHeaderType becomes the HeaderSample
// HeaderChain::validate_and_append consumes -- in particular the two pieces
// that were stubbed out as "filled at the embedded-daemon port":
//   * block_hash = sha256d(80-byte header), stored so u256_be_display_hex()
//     renders the canonical big-endian explorer hash. Lights up tip_hash() ->
//     previousblockhash in the work template.
//   * target = compact_to_target(nBits), arith_uint256::SetCompact expansion.
//
// External KAT: the Bitcoin genesis header (identical 80-byte layout to DGB's
// BlockHeaderType) hashes to the universally-known genesis block id, and its
// 0x1d00ffff nBits expands to the canonical difficulty-1 target -- so a byte-
// order or SetCompact regression fails loudly against values anyone can verify.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <core/uint256.hpp>
#include <span>

#include <core/pack.hpp>
#include <core/pow.hpp>

#include "../coin/block.hpp"
#include "../coin/dgb_block_algo.hpp"
#include "../coin/hash_format.hpp"
#include "../coin/header_sample_build.hpp"

namespace {

using ::dgb::coin::BlockHeaderType;
using ::dgb::coin::u256_be_display_hex;
using c2pool::dgb::compact_to_target;
using c2pool::dgb::make_header_sample;
using c2pool::dgb::HeaderSample;

// Canonical Bitcoin genesis header -- same 80-byte serialization DGB uses.
BlockHeaderType genesis_header()
{
    BlockHeaderType h;
    h.m_version = 1;
    h.m_previous_block.SetNull();
    h.m_merkle_root.SetHex(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    h.m_timestamp = 1231006505u;
    h.m_bits      = 0x1d00ffffu;
    h.m_nonce     = 2083236893u;
    return h;
}

// nBits 0x1d00ffff expands to the canonical difficulty-1 target.
TEST(CompactToTarget, Difficulty1)
{
    EXPECT_EQ(u256_be_display_hex(compact_to_target(0x1d00ffffu)),
        "00000000ffff0000000000000000000000000000000000000000000000000000");
}

// A small in-range mantissa with a low exponent (no truncation): 0x05009234
// -> 0x9234 * 256^(5-3) = 0x9234 * 65536 = 0x92340000.
TEST(CompactToTarget, LowExponent)
{
    EXPECT_EQ(u256_be_display_hex(compact_to_target(0x05009234u)),
        "0000000000000000000000000000000000000000000000000000000092340000");
}

// exponent <= 3 right-shifts the mantissa: 0x03001234 -> 0x1234 * 256^0.
TEST(CompactToTarget, ExponentThreeIsMantissa)
{
    EXPECT_EQ(u256_be_display_hex(compact_to_target(0x03001234u)),
        "0000000000000000000000000000000000000000000000000000000000001234");
}

// block_hash = sha256d(header) rendered big-endian == the well-known genesis id.
TEST(MakeHeaderSample, GenesisBlockHash)
{
    HeaderSample s = make_header_sample(genesis_header());
    EXPECT_EQ(u256_be_display_hex(s.block_hash),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
}

// Scalar fields pass through verbatim; target decodes the header's nBits.
TEST(MakeHeaderSample, ScalarFieldsAndTarget)
{
    HeaderSample s = make_header_sample(genesis_header());
    EXPECT_EQ(s.n_version, 1);
    EXPECT_EQ(s.n_time, 1231006505);
    EXPECT_EQ(u256_be_display_hex(s.target),
        "00000000ffff0000000000000000000000000000000000000000000000000000");
}

// A Scrypt-disposition header (algo bits == 0; the Bitcoin-genesis v1 used here
// qualifies under DGB's GetAlgo mask) gets pow_hash = scrypt(80-byte header),
// stored little-endian like target. Self-consistency KAT: the field must equal
// an INDEPENDENT scrypt over the same canonical serialization routed through the
// SAME from_le_bytes convention -- proving make_header_sample wires header bytes
// -> core::pow::scrypt -> pow_hash with no byte-order drift, and that the
// previously-stubbed (== 0) field is now live for the satisfaction gate.
TEST(MakeHeaderSample, ScryptHeaderPowHashFilled)
{
    BlockHeaderType h = genesis_header();
    ASSERT_TRUE(::dgb::coin::is_scrypt_header(static_cast<int32_t>(h.m_version)));

    HeaderSample s = make_header_sample(h);

    auto packed = pack(h);
    auto tspan = packed.get_span();
    uint256 ph = core::pow::scrypt(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(tspan.data()), tspan.size()));
    dgb::coin::u256 expected = dgb::coin::u256::from_le_bytes(
        reinterpret_cast<const unsigned char*>(ph.begin()));

    EXPECT_EQ(u256_be_display_hex(s.pow_hash), u256_be_display_hex(expected));
    EXPECT_FALSE(s.pow_hash.is_zero());
}

// A non-Scrypt header (SHA256D algo bits) is accept-by-continuity in V36; its
// PoW gate never runs, so make_header_sample leaves pow_hash == 0 rather than
// computing a scrypt digest nothing reads.
TEST(MakeHeaderSample, NonScryptHeaderPowHashZero)
{
    BlockHeaderType h = genesis_header();
    h.m_version = ::dgb::coin::DGB_BLOCK_VERSION_SHA256D;  // 0x0200 algo bits
    ASSERT_FALSE(::dgb::coin::is_scrypt_header(static_cast<int32_t>(h.m_version)));

    HeaderSample s = make_header_sample(h);
    EXPECT_TRUE(s.pow_hash.is_zero());
}

} // namespace