// ---------------------------------------------------------------------------
// dgb_regrind_block_test -- the grind -> reconstruct -> submit INTEGRATION
// seam guard (coin/regrind_block.hpp), #82 Stage 4b/4c.
//
// Pins regrind_block_nonce: given an already-framed reconstructed-block blob
// (header(80) | varint(txcount) | txs), it grinds the header nonce through the
// #286 scrypt_pow_hash SSOT until the DGB-Scrypt PoW digest satisfies the
// parent target, writing the winning nonce back into header [76..79] IN PLACE.
// This is the missing wiring between reconstruct (merkle root fixed) and a
// node-B ProcessNewBlock ACCEPT: the live A/B soak is the corroborating
// evidence; THIS KAT is the binding proof that the re-ground block satisfies
// the EXACT satisfaction gate header_chain.hpp runs (pow <= target) while the
// merkle root and tx tail are byte-preserved.
//
// Real scrypt (the _dgb_scrypt_tus set), header-only u256 -- the same no-core /
// no-OBJECT-lib standalone-guard discipline as nonce_grinder_test / scrypt_pow.
// Per-coin isolation: src/impl/dgb/ only. MUST appear in BOTH test/CMakeLists
// AND the build.yml --target allowlist (#143 NOT_BUILT sentinel trap).
// ---------------------------------------------------------------------------

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/regrind_block.hpp>
#include <impl/dgb/coin/scrypt_pow.hpp>

using dgb::coin::u256;
using dgb::coin::regrind_block_nonce;
using dgb::coin::scrypt_pow_hash;
using dgb::coin::kHeaderNonceOffset;

namespace {

// A synthetic "framed block" blob: 80-byte header (arbitrary, with a non-zero
// merkle region [36..67]) followed by a short tx tail. The seam owns ONLY the
// header nonce [76..79]; everything else must survive byte-for-byte.
std::vector<unsigned char> make_framed_block() {
    std::vector<unsigned char> b;
    b.reserve(80 + 5);
    for (int i = 0; i < 80; ++i) b.push_back(static_cast<unsigned char>((i * 13 + 5) % 251));
    // tx tail: varint count(1) + 4 sentinel bytes (stand in for a tx blob).
    b.push_back(0x01);
    b.push_back(0xde); b.push_back(0xad); b.push_back(0xbe); b.push_back(0xef);
    return b;
}

uint32_t read_nonce_le(const std::vector<unsigned char>& b) {
    return  (uint32_t)b[kHeaderNonceOffset + 0]
         | ((uint32_t)b[kHeaderNonceOffset + 1] << 8)
         | ((uint32_t)b[kHeaderNonceOffset + 2] << 16)
         | ((uint32_t)b[kHeaderNonceOffset + 3] << 24);
}

// Top two bits of the MS limb zero -> accepts ~1/4 of uniform digests, ~4 iters
// expected (mirrors nonce_grinder_test::easy_quarter_target). max_iters is the
// hard termination ceiling, not the expected cost.
u256 easy_quarter_target() {
    u256 t;
    t.limb[0] = 0xffffffffffffffffULL;
    t.limb[1] = 0xffffffffffffffffULL;
    t.limb[2] = 0xffffffffffffffffULL;
    t.limb[3] = 0x3fffffffffffffffULL;
    return t;
}

constexpr uint64_t kTestBudget = uint64_t{1} << 20;  // 1,048,576 vs ~4 expected

// --- the re-ground block's header satisfies the EXACT satisfaction gate ------
TEST(DgbRegrindBlockKAT, RegroundHeaderSatisfiesTarget) {
    auto block = make_framed_block();
    u256 target = easy_quarter_target();

    auto out = regrind_block_nonce(block, target, 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    EXPECT_LE(out->iters, uint64_t{200});  // (3/4)^200 ~ 1e-25 inside budget

    // Recompute through the SAME #286 SSOT over the mutated header [0..79].
    std::array<unsigned char, 80> hdr{};
    for (int i = 0; i < 80; ++i) hdr[i] = block[i];
    u256 pow = scrypt_pow_hash(hdr);
    EXPECT_FALSE(pow > target);            // pow <= target (inclusive gate)
    // The winning nonce the seam reports is the one it wrote back into [76..79].
    EXPECT_EQ(read_nonce_le(block), out->nonce);
}

// --- ONLY header [76..79] changes: merkle root + tx tail byte-preserved ------
TEST(DgbRegrindBlockKAT, OnlyNonceBytesMutated) {
    auto before = make_framed_block();
    auto after  = before;

    auto out = regrind_block_nonce(after, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(before.size(), after.size());

    for (std::size_t i = 0; i < after.size(); ++i) {
        if (i >= kHeaderNonceOffset && i < 80) continue;  // the 4 nonce bytes may differ
        EXPECT_EQ(before[i], after[i]) << "byte " << i << " (outside nonce) changed";
    }
    // In particular the merkle region [36..67] and the tx tail are untouched.
    for (std::size_t i = 36; i < 68; ++i) EXPECT_EQ(before[i], after[i]);
    for (std::size_t i = 80; i < after.size(); ++i) EXPECT_EQ(before[i], after[i]);
}

// --- fail-closed on a runt blob (< 80 bytes): nullopt, bytes UNCHANGED -------
TEST(DgbRegrindBlockKAT, RuntBlobFailsClosed) {
    std::vector<unsigned char> runt(79, 0x00);  // one byte short of a header
    auto copy = runt;
    auto out = regrind_block_nonce(runt, easy_quarter_target(), 0, kTestBudget);
    EXPECT_FALSE(out.has_value());
    EXPECT_EQ(runt, copy);  // unchanged
}

// --- fail-closed on exhausted budget: nullopt, bytes UNCHANGED ---------------
TEST(DgbRegrindBlockKAT, ExhaustedBudgetFailsClosed) {
    auto block = make_framed_block();
    auto copy  = block;
    u256 impossible;  // all-zero target -- no digest can be <= 0 in practice
    auto out = regrind_block_nonce(block, impossible, 0, /*max_iters=*/256);
    EXPECT_FALSE(out.has_value());
    EXPECT_EQ(block, copy);  // bytes left exactly as reconstructed
}

// --- deterministic: same blob + target -> same winning nonce -----------------
TEST(DgbRegrindBlockKAT, Deterministic) {
    auto a = make_framed_block();
    auto b = make_framed_block();
    auto oa = regrind_block_nonce(a, easy_quarter_target(), 0, kTestBudget);
    auto ob = regrind_block_nonce(b, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(oa.has_value());
    ASSERT_TRUE(ob.has_value());
    EXPECT_EQ(oa->nonce, ob->nonce);
    EXPECT_EQ(a, b);  // identical re-ground blobs
}

}  // namespace
