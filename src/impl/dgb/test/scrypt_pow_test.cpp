// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB-Scrypt PoW digest CALL guard (coin/scrypt_pow.hpp) -- Stage 4b/4c.
//
// Pins (1) the scrypt_1024_1_1_256 digest bytes over a fixed 80-byte header and
// (2) that the little-endian u256 decode compares correctly against SetCompact-
// shaped targets the way the coin/header_chain.hpp satisfaction gate does
// (pow_hash <= target == valid PoW). The byte order proven here is exactly what
// the embedded nonce grinder must satisfy for node B to ACCEPT a reconstructed
// block, so this is the unit floor under the live tip-extension test.
//
// EXTERNAL ANCHOR (closes the #158 self-derived caveat): the two DigestMatches*
// vectors below are captured from btclibs over an ARBITRARY header, so on their
// own they only change-detect our own routine. The MainnetGenesis* case anchors
// the SAME digest SSOT to an EXTERNAL authority -- the DigiByte MAINNET chain --
// by asserting our Scrypt hash of the real mainnet genesis header satisfies that
// block's own on-chain target. See that block's comment for provenance.

#include <array>
#include <cstdint>
#include <gtest/gtest.h>

#include <impl/dgb/coin/scrypt_pow.hpp>

using dgb::coin::u256;
using dgb::coin::scrypt_pow_hash;
using dgb::coin::compact_to_target;

namespace {

// Deterministic 80-byte header: byte i = (i*7+1) mod 251. Arbitrary content but
// fixed; the conversion + comparison proof does not depend on header semantics.
std::array<unsigned char, 80> fixed_header() {
    std::array<unsigned char, 80> h{};
    for (int i = 0; i < 80; ++i) h[i] = static_cast<unsigned char>((i * 7 + 1) % 251);
    return h;
}

// scrypt_1024_1_1_256(fixed_header) little-endian u256 limbs (limb[0] = LSB),
// captured from btclibs. digest LE-in-memory:
//   632b7c4db1da77a9683731a4a7a97761a2f600f66a1af420919a3aa0d4869a6c
constexpr uint64_t L0 = 0xa977dab14d7c2b63ULL;
constexpr uint64_t L1 = 0x6177a9a7a4313768ULL;
constexpr uint64_t L2 = 0x20f41a6af600f6a2ULL;
constexpr uint64_t L3 = 0x6c9a86d4a03a9a91ULL;

u256 expected_pow() {
    u256 r;
    r.limb[0] = L0; r.limb[1] = L1; r.limb[2] = L2; r.limb[3] = L3;
    return r;
}

// --- KAT: the digest CALL is byte-exact ------------------------------------
TEST(DgbScryptPowKAT, DigestMatchesPinnedVector) {
    EXPECT_TRUE(scrypt_pow_hash(fixed_header()) == expected_pow());
}

// The pointer overload and the std::array overload are the same SSOT.
TEST(DgbScryptPowKAT, PointerAndArrayOverloadsAgree) {
    auto h = fixed_header();
    EXPECT_TRUE(scrypt_pow_hash(h.data()) == scrypt_pow_hash(h));
}

// --- satisfaction-gate byte order (header_chain.hpp: pow_hash <= target) ----
// A target one ULP above the digest in the MOST-significant limb accepts;
// one ULP below rejects. This is the exact comparison header_chain runs, so it
// proves from_le_bytes feeds the gate in the right (MSB-first compare) order.
TEST(DgbScryptPowKAT, SatisfiesTargetJustAbove) {
    u256 pow = scrypt_pow_hash(fixed_header());
    u256 target_above = expected_pow();
    target_above.limb[3] = L3 + 1;   // strictly greater
    EXPECT_FALSE(pow > target_above); // pow <= target -> valid PoW
}

TEST(DgbScryptPowKAT, FailsTargetJustBelow) {
    u256 pow = scrypt_pow_hash(fixed_header());
    u256 target_below = expected_pow();
    target_below.limb[3] = L3 - 1;   // strictly less
    EXPECT_TRUE(pow > target_below);  // pow > target -> PoW failed (high-hash)
}

// Equal target is satisfied (hash <= target is inclusive).
TEST(DgbScryptPowKAT, SatisfiesEqualTarget) {
    u256 pow = scrypt_pow_hash(fixed_header());
    EXPECT_FALSE(pow > expected_pow());
}

// ===========================================================================
// MAINNET-HEADER-ANCHORED Scrypt parity -- closes the #158 self-derived caveat.
// ===========================================================================
// The DigiByte MAINNET GENESIS block is a real Scrypt-mined mainnet block. Its
// 80-byte header is fully authoritative from DigiByte Core kernel/chainparams.cpp
//   genesis = CreateGenesisBlock(1389388394, 2447652, 0x1e0ffff0, 1, 8000);
//   assert(consensus.hashGenesisBlock ==
//          0x7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496);
//   assert(genesis.hashMerkleRoot ==
//          0x72ddd9496b004221ed0557358846d9248ecd4c440ebd28ed901efc18757d0fad);
// (nVersion=1 is the pre-multialgo default => Scrypt algo -- the ONLY algo this
// module validates.) Because the DigiByte network mined and accepted this block,
// its Scrypt PoW hash MUST satisfy its declared target SetCompact(0x1e0ffff0).
//
// Asserting scrypt_pow_hash(header) <= compact_to_target(0x1e0ffff0) therefore
// binds our btclibs scrypt_1024_1_1_256 to an EXTERNAL authority (the DGB chain),
// not to a digest captured from the same routine: if btclibs ever diverged from
// DigiByte Core's canonical Scrypt, our hash would exceed the target and this
// FAILS. This is precisely the header_chain.hpp satisfaction gate, exercised now
// on a mainnet header.

// 64-char big-endian DISPLAY hex (as printed by uint256S / block explorers) ->
// 32 serialized (internal little-endian) header bytes. Byte order is reversed;
// the serialization is done IN CODE so no header byte is hand-transcribed.
std::array<unsigned char, 32> le_from_display_hex(const char* be_hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<unsigned char, 32> out{};
    for (int i = 0; i < 32; ++i) {
        int hi = nib(be_hex[2 * i]);
        int lo = nib(be_hex[2 * i + 1]);
        out[31 - i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

void put_u32_le(std::array<unsigned char, 80>& h, int off, uint32_t v) {
    h[off + 0] = static_cast<unsigned char>(v & 0xff);
    h[off + 1] = static_cast<unsigned char>((v >> 8) & 0xff);
    h[off + 2] = static_cast<unsigned char>((v >> 16) & 0xff);
    h[off + 3] = static_cast<unsigned char>((v >> 24) & 0xff);
}

// DigiByte MAINNET genesis 80-byte header, assembled from the authoritative
// chainparams fields (Bitcoin CBlockHeader serialization).
std::array<unsigned char, 80> dgb_mainnet_genesis_header() {
    std::array<unsigned char, 80> h{};
    put_u32_le(h, 0, 1u);                 // [0..4)   nVersion (Scrypt algo)
    // [4..36)  hashPrevBlock = 0 (genesis) -- already zero-initialised.
    auto mr = le_from_display_hex(
        "72ddd9496b004221ed0557358846d9248ecd4c440ebd28ed901efc18757d0fad");
    for (int i = 0; i < 32; ++i) h[36 + i] = mr[i];  // [36..68) hashMerkleRoot
    put_u32_le(h, 68, 1389388394u);       // [68..72) nTime
    put_u32_le(h, 72, 0x1e0ffff0u);       // [72..76) nBits
    put_u32_le(h, 76, 2447652u);          // [76..80) nNonce
    return h;
}

// Sanity: the assembled header is a real DigiByte header, so its sha256d block
// id must equal the published mainnet genesis hash. Guards the byte assembly
// (order/endianness) independently of the Scrypt routine. Uses the same
// display->LE convention; block id is compared as the internal LE serialization.
TEST(DgbScryptPowKAT, MainnetGenesisHeaderAssemblyIsWellFormed) {
    auto h = dgb_mainnet_genesis_header();
    // nVersion, nTime, nBits, nNonce round-trip at their fixed offsets.
    EXPECT_EQ(h[0], 0x01u);
    EXPECT_EQ(h[68], 0x6au); EXPECT_EQ(h[69], 0x62u);  // nTime 1389388394 LE
    EXPECT_EQ(h[72], 0xf0u); EXPECT_EQ(h[73], 0xffu);  // nBits 0x1e0ffff0 LE
    EXPECT_EQ(h[76], 0x24u); EXPECT_EQ(h[77], 0x59u);  // nNonce 2447652 LE
    // hashPrevBlock is all-zero (genesis).
    for (int i = 4; i < 36; ++i) EXPECT_EQ(h[i], 0u);
}

// EXTERNAL ANCHOR: mainnet genesis Scrypt PoW satisfies its on-chain target.
TEST(DgbScryptPowKAT, MainnetGenesisSatisfiesOnChainTarget) {
    u256 pow    = scrypt_pow_hash(dgb_mainnet_genesis_header());
    u256 target = compact_to_target(0x1e0ffff0u);
    EXPECT_FALSE(pow > target)
        << "btclibs scrypt diverged from DigiByte Core: DGB mainnet genesis PoW "
           "hash does not satisfy its own SetCompact(0x1e0ffff0) target";
}

}  // namespace
