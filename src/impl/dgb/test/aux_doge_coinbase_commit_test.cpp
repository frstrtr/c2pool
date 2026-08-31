// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining — DGB-as-parent BUILT-COINBASE commitment KAT.
//
// The sibling aux_doge_mm_commitment_test.cpp pins the 44-byte blob the SSOT
// builder emits in isolation. THIS test proves the blob is spliced, findable,
// and byte-correct THROUGH the real DGB coinbase assembler
// dgb::coin::build_connection_coinbase_from_pplns — the exact production path
// DGBWorkSource::build_connection_coinbase drives once a --merged DOGE spec has
// armed the embedded aux backend (work_source.cpp populates
// ConnCoinbasePplnsInputs::aux_mm_commitment from the manager's cached
// commitment). It is the DGB analog of the live-proven BTC->NMC parent-lane KAT
// src/impl/btc/test/merged_commitment_test.cpp.
//
// RED / GREEN:
//   * RED  (merged-off): aux_mm_commitment == nullopt -> the assembled coinbase
//     carries ZERO fabe6d6d markers, byte-identical to a standalone DGB parent.
//   * GREEN (merged-on): aux_mm_commitment == [0x2c][44-byte SSOT blob] -> the
//     assembled coinbase carries EXACTLY ONE fabe6d6d marker whose 44 following
//     bytes are byte-identical to c2pool::merged::build_auxpow_commitment, with
//     the magic immediately preceding the aux merkle root (the invariant a
//     Dogecoin node's CAuxPow::check enforces via std::search) and preceded by
//     the 0x2c push opcode (the parent-lane framing).
//
// The commitment layout is NOT reconstructed here — the expected 44 bytes come
// straight from the cross-coin SSOT, so a re-shaped builder cannot self-confirm.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a NOT_BUILT sentinel that reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/connection_coinbase.hpp>      // build_connection_coinbase_from_pplns
#include <impl/dgb/coin/aux_doge_mm_commitment.hpp>   // build_aux_mm_commitment, AUX_MM_COMMITMENT_SIZE
#include <c2pool/merged/merged_mining.hpp>            // SSOT: build_auxpow_commitment
#include <core/uint256.hpp>                           // uint256, uint288

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

// The DOGE merged-mining magic marker (\xfa\xbe"mm").
const unsigned char MM_MAGIC[4] = {0xfa, 0xbe, 0x6d, 0x6d};

// Count non-overlapping occurrences of the 4-byte magic in a byte buffer.
size_t count_magic(const std::vector<unsigned char>& buf) {
    size_t n = 0;
    auto it = buf.begin();
    while ((it = std::search(it, buf.end(), std::begin(MM_MAGIC), std::end(MM_MAGIC)))
           != buf.end()) {
        ++n;
        it += 4;
    }
    return n;
}

// A 32-byte little-endian aux merkle root with a non-symmetric byte pattern so
// the big-endian reversal in the commitment is observable.
uint256 sample_root() {
    std::vector<unsigned char> le;
    for (int i = 0; i < 32; ++i) le.push_back(static_cast<unsigned char>(0x10 + i));
    return uint256(le);
}

// Build the production-shaped aux_mm_commitment: [push 0x2c][44-byte SSOT blob].
// This is exactly what DGBWorkSource::build_connection_coinbase assembles from
// the manager's cached commitment before handing it to the assembler.
std::vector<unsigned char> tagged_commitment(const uint256& root,
                                             uint32_t size, uint32_t nonce) {
    auto blob = c2pool::merged::build_auxpow_commitment(root, size, nonce);
    std::vector<unsigned char> tagged;
    tagged.push_back(static_cast<unsigned char>(blob.size()));  // 0x2c push opcode
    tagged.insert(tagged.end(), blob.begin(), blob.end());
    return tagged;
}

// Minimal but well-formed PPLNS inputs for one payout identity. The coinbase
// scriptSig carries a BIP34-style height push + a pool tag, mirroring the live
// producer (the aux commitment is APPENDED after these by the assembler).
dgb::coin::ConnCoinbasePplnsInputs make_inputs() {
    dgb::coin::ConnCoinbasePplnsInputs in;
    // [BIP34 height push 0x03 || 0x0f4240 (=1000000)] then "/c2pool-dgb/" tag.
    in.coinbase_script = {0x03, 0x40, 0x42, 0x0f};
    static const std::string TAG = "/c2pool-dgb/";
    in.coinbase_script.push_back(static_cast<unsigned char>(TAG.size()));
    in.coinbase_script.insert(in.coinbase_script.end(), TAG.begin(), TAG.end());

    // One payout identity (a P2PKH-shaped 25-byte script) with all the weight.
    std::vector<unsigned char> payout = {
        0x76, 0xa9, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x88, 0xac};
    in.weights[payout] = uint288(1000);
    in.total_weight    = uint288(1000);
    in.subsidy         = 500000000ULL;  // arbitrary DGB coinbase value
    in.use_v36_pplns   = true;
    in.donation_script = {0x6a};         // trivial non-empty donation target
    in.ref_hash        = sample_root();  // any 32-byte value
    in.last_txout_nonce = 0x0123456789abcdefULL;
    return in;
}

}  // namespace

// RED: merged-off (nullopt) -> no marker in the assembled coinbase.
TEST(DGB_AuxDogeCoinbaseCommit, MergedOff_NoMarker) {
    auto in = make_inputs();
    ASSERT_FALSE(in.aux_mm_commitment.has_value());
    auto parts = dgb::coin::build_connection_coinbase_from_pplns(in);
    EXPECT_EQ(count_magic(parts.gentx.bytes), 0u)
        << "standalone DGB coinbase must carry no fabe6d6d marker";
}

// GREEN: merged-on -> exactly one marker, 44 bytes byte-identical to the SSOT,
// magic immediately before the aux root, 0x2c push opcode immediately before it.
TEST(DGB_AuxDogeCoinbaseCommit, MergedOn_FindableAndByteExact) {
    const uint256 root = sample_root();
    const uint32_t size = 1, nonce = 0xdeadbeefu;

    auto in = make_inputs();
    in.aux_mm_commitment = tagged_commitment(root, size, nonce);
    auto parts = dgb::coin::build_connection_coinbase_from_pplns(in);
    const auto& cb = parts.gentx.bytes;

    // Exactly one marker (DOGE CAuxPow::check rejects multiple headers).
    ASSERT_EQ(count_magic(cb), 1u) << "expected exactly one fabe6d6d marker";

    auto pos = std::search(cb.begin(), cb.end(),
                           std::begin(MM_MAGIC), std::end(MM_MAGIC));
    ASSERT_NE(pos, cb.end());
    size_t off = static_cast<size_t>(std::distance(cb.begin(), pos));

    // 44 contiguous bytes at the marker == the cross-coin SSOT commitment.
    ASSERT_LE(off + dgb::coin::AUX_MM_COMMITMENT_SIZE, cb.size());
    std::vector<unsigned char> found(cb.begin() + off,
                                     cb.begin() + off + dgb::coin::AUX_MM_COMMITMENT_SIZE);
    auto ssot = c2pool::merged::build_auxpow_commitment(root, size, nonce);
    EXPECT_EQ(found, ssot) << "spliced 44-byte blob must match the SSOT layout";

    // DOGE invariant: magic (4B) immediately precedes the 32-byte aux root, i.e.
    // the reversed (big-endian) internal image of `root` starts at off+4.
    auto root_chars = root.GetChars();  // 32 LE internal bytes
    for (int i = 0; i < 32; ++i)
        EXPECT_EQ(cb[off + 4 + i], root_chars[31 - i])
            << "aux root (big-endian) must follow the magic at byte " << i;

    // Parent-lane framing: the 0x2c (=44) push opcode sits immediately before
    // the magic (byte off-1). off is >= 1 because the scriptSig precedes it.
    ASSERT_GE(off, 1u);
    EXPECT_EQ(cb[off - 1], static_cast<unsigned char>(dgb::coin::AUX_MM_COMMITMENT_SIZE));
}
