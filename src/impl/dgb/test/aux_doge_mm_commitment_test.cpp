// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) — KAT for the DGB-side AuxPoW coinbase
// merged-mining commitment builder.  Fenced / test-only.
//
// Pins the EXACT byte layout emitted by dgb::coin::build_aux_mm_commitment for
// fixed (aux_merkle_root, merkle_size, merkle_nonce) inputs:
//
//     fa be 6d 6d || aux_root(32, big-endian) || size(4 LE) || nonce(4 LE)
//
// NON-CIRCULAR.  The expected commitment bytes are hand-constructed in each
// case from the raw inputs (magic literal + reversed root bytes + manually
// little-endian-split size/nonce), NOT by re-invoking the builder.  The test is
// therefore a true layout anchor: a re-shaped builder cannot self-confirm.
//
// SSOT DELEGATION GUARD.  Each case ALSO asserts the DGB entry point is
// byte-identical to the canonical cross-coin producer
// c2pool::merged::build_auxpow_commitment.  Per the integrator adjudication
// (core builder = MM SSOT), DGB owns no build body of its own; this pins
// DGBs chain slot + goldens to the one canonical builder (delegation), not a
// fenced copy.  Mirrors the NMC SSOT drift-guard auxpow_merkle_test.cpp.
//
// Mirrors the established DGB aux-test style (unhex/tohex helpers) of the
// sibling src/impl/dgb/test/aux_doge_db_commitment_bind_test.cpp.  MUST appear
// in BOTH test/CMakeLists.txt AND the build.yml --target allowlist or it
// becomes a NOT_BUILT sentinel that reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/aux_doge_mm_commitment.hpp>  // the fenced builder under test
#include <c2pool/merged/merged_mining.hpp>     // SSOT drift-guard: build_auxpow_commitment
#include <core/uint256.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}
std::string tohex(const std::vector<unsigned char>& v) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char b : v) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xf]); }
    return s;
}

// Build a uint256 whose internal little-endian byte image == root_le[0..31].
// (base_uint(vector) reads the vector little-endian, so on a little-endian host
// reinterpret_cast<uint8_t*>(pn)[i] == root_le[i].)  Requires exactly 32 bytes.
uint256 root_from_le_bytes(const std::vector<unsigned char>& root_le) {
    EXPECT_EQ(root_le.size(), 32u);
    return uint256(root_le);
}

// NON-CIRCULAR expected blob: magic || reverse(root_le) || size_LE || nonce_LE.
// Hand-assembled from the raw inputs — does NOT call the builder.
std::vector<unsigned char> expected_commitment(
    const std::vector<unsigned char>& root_le,
    uint32_t size,
    uint32_t nonce)
{
    std::vector<unsigned char> e;
    // magic
    e.push_back(0xfa); e.push_back(0xbe); e.push_back(0x6d); e.push_back(0x6d);
    // root, big-endian (reverse of the internal little-endian image)
    for (int i = 31; i >= 0; --i) e.push_back(root_le[i]);
    // size, little-endian
    e.push_back(static_cast<unsigned char>(size & 0xFF));
    e.push_back(static_cast<unsigned char>((size >> 8) & 0xFF));
    e.push_back(static_cast<unsigned char>((size >> 16) & 0xFF));
    e.push_back(static_cast<unsigned char>((size >> 24) & 0xFF));
    // nonce, little-endian
    e.push_back(static_cast<unsigned char>(nonce & 0xFF));
    e.push_back(static_cast<unsigned char>((nonce >> 8) & 0xFF));
    e.push_back(static_cast<unsigned char>((nonce >> 16) & 0xFF));
    e.push_back(static_cast<unsigned char>((nonce >> 24) & 0xFF));
    return e;
}

} // namespace

// 0) Structural: blob is exactly 44 bytes and starts with the fabe6d6d magic.
TEST(DGB_AuxDogeMMCommitment, SizeAndMagic) {
    auto root_le = unhex(std::string(64, '0'));
    auto blob = dgb::coin::build_aux_mm_commitment(root_from_le_bytes(root_le), 0, 0);
    ASSERT_EQ(blob.size(), 44u);
    EXPECT_EQ(blob.size(), dgb::coin::AUX_MM_COMMITMENT_SIZE);
    EXPECT_EQ(tohex({blob.begin(), blob.begin() + 4}), "fabe6d6d");
    // SSOT delegation: structural blob is the core builders output verbatim.
    EXPECT_EQ(tohex(blob),
        tohex(c2pool::merged::build_auxpow_commitment(
            root_from_le_bytes(root_le), 0, 0)));
}

// 1) All-zero root, size=1, nonce=0 — canonical degenerate (single-aux) case.
TEST(DGB_AuxDogeMMCommitment, KAT_ZeroRoot_Size1_Nonce0) {
    auto root_le = unhex(std::string(64, '0'));
    const uint32_t size = 1, nonce = 0;
    auto got = dgb::coin::build_aux_mm_commitment(root_from_le_bytes(root_le), size, nonce);
    auto want = expected_commitment(root_le, size, nonce);
    // SSOT delegation: DGB entry point forwards verbatim to the core builder.
    auto ssot = c2pool::merged::build_auxpow_commitment(
        root_from_le_bytes(root_le), size, nonce);
    EXPECT_EQ(tohex(got), tohex(ssot));
    EXPECT_EQ(tohex(got), tohex(want));
    // Fully pinned literal: magic || 32 zero bytes || 01000000 || 00000000
    EXPECT_EQ(tohex(got),
        "fabe6d6d"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "01000000"
        "00000000");
}

// 2) Distinct-byte root, multi-byte LE size + nonce — exercises root reversal
//    and full little-endian width of both 32-bit fields.
TEST(DGB_AuxDogeMMCommitment, KAT_PatternedRoot_SizeNonceLE) {
    // Internal little-endian image: byte i == i (00 01 02 ... 1f).
    std::vector<unsigned char> root_le;
    for (int i = 0; i < 32; ++i) root_le.push_back(static_cast<unsigned char>(i));
    const uint32_t size = 0x04030201u, nonce = 0xdeadbeefu;
    auto got = dgb::coin::build_aux_mm_commitment(root_from_le_bytes(root_le), size, nonce);
    auto want = expected_commitment(root_le, size, nonce);
    // SSOT delegation: DGB entry point forwards verbatim to the core builder.
    auto ssot = c2pool::merged::build_auxpow_commitment(
        root_from_le_bytes(root_le), size, nonce);
    EXPECT_EQ(tohex(got), tohex(ssot));
    EXPECT_EQ(tohex(got), tohex(want));
    // Fully pinned literal: root big-endian is 1f..00; size LE=01020304; nonce LE=efbeadde.
    EXPECT_EQ(tohex(got),
        "fabe6d6d"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "01020304"
        "efbeadde");
}

// 3) Real-shaped DOGE-style root, max size, mid nonce.
TEST(DGB_AuxDogeMMCommitment, KAT_RealishRoot_MaxSize) {
    // Internal little-endian image of a non-symmetric 32-byte root.
    auto root_le = unhex(
        "112233445566778899aabbccddeeff00"
        "fedcba98765432100123456789abcdef");
    const uint32_t size = 0xffffffffu, nonce = 0x00c0ffeeu;
    auto got = dgb::coin::build_aux_mm_commitment(root_from_le_bytes(root_le), size, nonce);
    auto want = expected_commitment(root_le, size, nonce);
    // SSOT delegation: DGB entry point forwards verbatim to the core builder.
    auto ssot = c2pool::merged::build_auxpow_commitment(
        root_from_le_bytes(root_le), size, nonce);
    EXPECT_EQ(tohex(got), tohex(ssot));
    EXPECT_EQ(tohex(got), tohex(want));
    // Fully pinned literal.
    EXPECT_EQ(tohex(got),
        "fabe6d6d"
        "efcdab89674523011032547698badcfe00ffeeddccbbaa998877665544332211"
        "ffffffff"
        "eeffc000");
}
