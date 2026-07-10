// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB won-block finalize joint (coin/won_block_finalize.hpp) -- #82 gate.
//
// Pins finalize_won_block_pow: the grind->reconstruct->submit composition that
// turns a faithfully RECONSTRUCTED parent block (header[0..79] with merkle_root
// already set; merkle FIRST, integrator-pinned ordering) into one whose header
// nonce satisfies the parent target -- the missing link between leg-2's
// reconstruction and a node-B ProcessNewBlock ACCEPT. The PoW is computed ONLY
// through grind_won_nonce -> scrypt_pow_hash (the #286 digest CALL SSOT), so a
// finalized block is, by construction, one node B's own Scrypt validation
// accepts. This is the unit floor directly under the live tip-extension gate.
//
// Real scrypt (the _dgb_scrypt_tus set), header-only u256 -- the same no-core /
// no-OBJECT-lib standalone-guard discipline as nonce_grinder_test / scrypt_pow_test.

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/won_block_finalize.hpp>
#include <impl/dgb/coin/nonce_grinder.hpp>
#include <impl/dgb/coin/scrypt_pow.hpp>

using dgb::coin::u256;
using dgb::coin::scrypt_pow_hash;
using dgb::coin::kHeaderNonceOffset;
using dgb::coin::finalize_won_block_pow;
using dgb::coin::finalize_block_to_hex;

namespace {

// A synthetic reconstructed block: a deterministic 80-byte header (merkle_root
// already baked in -- finalize never touches it) followed by a short tx tail
// standing in for tx_count|[gentx]++other_txs. finalize owns header[76..79] only.
std::vector<unsigned char> synthetic_block(std::size_t tail_len = 37) {
    std::vector<unsigned char> b;
    b.reserve(80 + tail_len);
    for (int i = 0; i < 80; ++i)
        b.push_back(static_cast<unsigned char>((i * 13 + 5) % 251));
    for (std::size_t i = 0; i < tail_len; ++i)
        b.push_back(static_cast<unsigned char>((i * 7 + 3) % 256));
    return b;
}

// Target accepting ~1/4 of uniform digests (same shape as nonce_grinder_test):
// terminates in ~4 iters, so the budget below is never a factor.
u256 easy_quarter_target() {
    u256 t;
    t.limb[0] = 0xffffffffffffffffULL;
    t.limb[1] = 0xffffffffffffffffULL;
    t.limb[2] = 0xffffffffffffffffULL;
    t.limb[3] = 0x3fffffffffffffffULL;
    return t;
}

// The 80-byte header sitting at the front of a (finalized) block.
std::array<unsigned char, 80> header_of(const std::vector<unsigned char>& block) {
    std::array<unsigned char, 80> h{};
    std::copy(block.begin(), block.begin() + 80, h.begin());
    return h;
}

uint32_t read_nonce_le(const std::vector<unsigned char>& block) {
    return  (uint32_t)block[kHeaderNonceOffset + 0]
         | ((uint32_t)block[kHeaderNonceOffset + 1] << 8)
         | ((uint32_t)block[kHeaderNonceOffset + 2] << 16)
         | ((uint32_t)block[kHeaderNonceOffset + 3] << 24);
}

constexpr uint64_t kTestBudget = uint64_t{1} << 20;  // vs ~4 expected

// --- finalize yields a block whose header satisfies the parent target -------
TEST(DgbWonBlockFinalizeKAT, FinalizesToSatisfyingPoW) {
    u256 target = easy_quarter_target();
    auto out = finalize_won_block_pow(synthetic_block(), target, 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    // Re-hash the finalized header through the SAME #286 SSOT.
    u256 pow = scrypt_pow_hash(header_of(out->bytes));
    EXPECT_FALSE(pow > target);                  // pow <= target -> valid PoW
    EXPECT_TRUE(pow == out->grind.pow_hash);     // reported digest == SSOT (no bypass)
    EXPECT_GE(out->grind.iters, uint64_t{1});
}

// --- the winning nonce is spliced into block bytes[76..79] little-endian ----
TEST(DgbWonBlockFinalizeKAT, SplicesWinningNonceLittleEndian) {
    auto out = finalize_won_block_pow(synthetic_block(), easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(read_nonce_le(out->bytes), out->grind.nonce);
}

// --- RPC-fallback hex stays in lockstep with the P2P-arm bytes --------------
TEST(DgbWonBlockFinalizeKAT, HexMatchesFinalizedBytes) {
    auto out = finalize_won_block_pow(synthetic_block(), easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->hex.size(), out->bytes.size() * 2);
    EXPECT_EQ(out->hex, finalize_block_to_hex(out->bytes));
}

// --- ONLY the 4 nonce bytes change: merkle_root + every tx byte untouched ---
TEST(DgbWonBlockFinalizeKAT, OnlyNonceBytesMutated) {
    auto in = synthetic_block();
    auto out = finalize_won_block_pow(in, easy_quarter_target(), 0, kTestBudget);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(out->bytes.size(), in.size());
    // header[0..75] (version|prev|merkle|time|bits) identical.
    for (std::size_t i = 0; i < kHeaderNonceOffset; ++i)
        EXPECT_EQ(out->bytes[i], in[i]) << "prefix byte " << i << " changed";
    // tx tail [80..] identical.
    for (std::size_t i = 80; i < in.size(); ++i)
        EXPECT_EQ(out->bytes[i], in[i]) << "tail byte " << i << " changed";
}

// --- fail-closed: too short to frame an 80-byte header -> nullopt -----------
TEST(DgbWonBlockFinalizeKAT, FailsClosedOnShortInput) {
    std::vector<unsigned char> shortb(79, 0x11);
    auto out = finalize_won_block_pow(shortb, easy_quarter_target(), 0, kTestBudget);
    EXPECT_FALSE(out.has_value());
}

}  // namespace