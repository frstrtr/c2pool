// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB nonce grinder guard (coin/nonce_grinder.hpp) -- #82 Stage 4b/4c.
//
// Proves the embedded real work-gen primitive: grind_won_nonce increments the
// header nonce until the DGB-Scrypt PoW digest satisfies the target, computing
// the hash ONLY through scrypt_pow_hash (the #286 digest CALL SSOT) and using
// the EXACT satisfaction comparison coin/header_chain.hpp runs (pow_hash <=
// target). The nonce it returns is therefore the nonce node B's own Scrypt
// validation accepts -- this is the unit floor under the live tip-extension
// (ProcessNewBlock ACCEPT) integration test.
//
// Real scrypt (the _dgb_scrypt_tus set), header-only u256 -- the same no-core /
// no-OBJECT-lib standalone-guard discipline as scrypt_pow_test / dgb_arith256.

#include <array>
#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

#include <impl/dgb/coin/nonce_grinder.hpp>
#include <impl/dgb/coin/scrypt_pow.hpp>

using dgb::coin::u256;
using dgb::coin::grind_won_nonce;
using dgb::coin::scrypt_pow_hash;
using dgb::coin::kHeaderNonceOffset;

namespace {

// Arbitrary fixed 76-byte header prefix; the grinder owns bytes [76..79].
std::array<unsigned char, 80> base_header() {
    std::array<unsigned char, 80> h{};
    for (int i = 0; i < 80; ++i) h[i] = static_cast<unsigned char>((i * 13 + 5) % 251);
    return h;
}

uint32_t read_nonce_le(const std::array<unsigned char, 80>& h) {
    return  (uint32_t)h[kHeaderNonceOffset + 0]
         | ((uint32_t)h[kHeaderNonceOffset + 1] << 8)
         | ((uint32_t)h[kHeaderNonceOffset + 2] << 16)
         | ((uint32_t)h[kHeaderNonceOffset + 3] << 24);
}

// Target accepting ~1/4 of uniform digests: top two bits of the MS limb zero
// (pow.limb[3] <= 0x3fff... with all lower limbs maxed). Expected ~4 iters, so
// termination "well inside the test budget" is overwhelming; max_iters is the
// hard ceiling, not the expected cost.
u256 easy_quarter_target() {
    u256 t;
    t.limb[0] = 0xffffffffffffffffULL;
    t.limb[1] = 0xffffffffffffffffULL;
    t.limb[2] = 0xffffffffffffffffULL;
    t.limb[3] = 0x3fffffffffffffffULL;
    return t;
}

constexpr uint64_t kTestBudget = uint64_t{1} << 20;  // 1,048,576 vs ~4 expected

// --- grinder finds a satisfying nonce, well inside budget -------------------
TEST(DgbNonceGrinderKAT, FindsSatisfyingNonceWithinBudget) {
    auto h = base_header();
    auto out = grind_won_nonce(h, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    EXPECT_GE(out->iters, uint64_t{1});
    // P(iters > 200) = (3/4)^200 ~ 1e-25 -- terminates inside budget by construction.
    EXPECT_LE(out->iters, uint64_t{200});
}

// --- the winning header actually satisfies the gate (pow <= target) ---------
TEST(DgbNonceGrinderKAT, WinningHeaderSatisfiesTarget) {
    auto h = base_header();
    u256 target = easy_quarter_target();
    auto out = grind_won_nonce(h, target, 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    // Recompute through the SAME #286 SSOT over the mutated header.
    u256 pow = scrypt_pow_hash(h);
    EXPECT_FALSE(pow > target);          // pow <= target -> valid PoW
    EXPECT_TRUE(pow == out->pow_hash);   // reported digest == SSOT digest (no bypass)
}

// --- the winning nonce is left written into header[76..79], little-endian ----
TEST(DgbNonceGrinderKAT, WritesWinningNonceLittleEndian) {
    auto h = base_header();
    auto out = grind_won_nonce(h, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(read_nonce_le(h), out->nonce);
}

// --- determinism + start_nonce honored: re-grinding from the winner hits it
//     on the first try (the found nonce truly satisfies AND start is respected).
TEST(DgbNonceGrinderKAT, ReGrindFromWinnerSucceedsImmediately) {
    auto h = base_header();
    auto first = grind_won_nonce(h, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(first.has_value());
    auto h2 = base_header();
    auto again = grind_won_nonce(h2, easy_quarter_target(), first->nonce, kTestBudget);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->nonce, first->nonce);
    EXPECT_EQ(again->iters, uint64_t{1});  // satisfied on the first nonce tried
}

// --- fail-closed: an unsatisfiable target inside a small budget -> nullopt ----
// target == 1 (limb[0]=1, rest 0): essentially no scrypt digest is <= 1, so the
// grinder MUST exhaust the budget and return nullopt rather than loop forever.
TEST(DgbNonceGrinderKAT, ReturnsNulloptWhenNoNonceInBudget) {
    auto h = base_header();
    u256 impossible;            // all-zero ...
    impossible.limb[0] = 1;     // ... except 1 -> target = 1
    auto out = grind_won_nonce(h, impossible, 0, /*max_iters=*/256);
    EXPECT_FALSE(out.has_value());
}

}  // namespace