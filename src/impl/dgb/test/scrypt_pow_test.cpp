// DGB-Scrypt PoW digest CALL guard (coin/scrypt_pow.hpp) -- Stage 4b/4c.
//
// Pins (1) the scrypt_1024_1_1_256 digest bytes over a fixed 80-byte header and
// (2) that the little-endian u256 decode compares correctly against SetCompact-
// shaped targets the way the coin/header_chain.hpp satisfaction gate does
// (pow_hash <= target == valid PoW). The byte order proven here is exactly what
// the embedded nonce grinder must satisfy for node B to ACCEPT a reconstructed
// block, so this is the unit floor under the live tip-extension test.
//
// The digest vector is pinned from btclibs scrypt_1024_1_1_256 itself (the DGB-
// Scrypt algo SSOT, same routine as DigiByte Core); end-to-end agreement with
// DigiByte Core is proven by the live node-B ACCEPT integration test, not here.

#include <array>
#include <gtest/gtest.h>

#include <impl/dgb/coin/scrypt_pow.hpp>

using dgb::coin::u256;
using dgb::coin::scrypt_pow_hash;

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

}  // namespace
