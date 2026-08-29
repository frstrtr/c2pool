// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// KATs for the BTC merged-mining (NMC AuxPoW) coinbase-commitment slice.
//
// These pin the byte-exact contract that the PRODUCER
// (BTCWorkSource::build_connection_coinbase, which splices
// c2pool::merged::build_auxpow_commitment into the coinbase scriptSig and
// freezes a vector<btc::MergedCoinbaseEntry> blob per share) and the VERIFIER
// (btc::verify_merged_coinbase_commitment, share_check.hpp:1602) BOTH depend
// on. If either side drifts, one of these fails at compile-of-behaviour time
// rather than as a silently-orphaned NMC block on the live canary.
//
//   A. 44-byte commitment layout + the verifier's magic-search / reverse-root
//      / LE-size parse recover exactly what the producer wrote.
//   B. Single-chain identity (aux_size==1): committed mm_root == Hash(header)
//      — the verifier's share_check.hpp:1739-1745 equality.
//   C. SSOT freeze blob round-trips (split-brain guard): the exact bytes the
//      producer serializes deserialize back to the same entries the mint +
//      verifier consume; empty in => empty out (merged-off / pre-sync).
//   D. Producer scriptSig layout [height][0x2c mm][tag] parses under the
//      verifier's marker search; a merged-off scriptSig has NO marker.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <c2pool/merged/merged_mining.hpp>   // build_auxpow_commitment
#include <impl/btc/share_types.hpp>          // btc::MergedCoinbaseEntry
#include <core/pack.hpp>                      // PackStream
#include <core/uint256.hpp>
#include <core/hash.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace {

static const uint8_t MM_MAGIC[] = {0xfa, 0xbe, 0x6d, 0x6d};

// Mirror of the verifier's parse (share_check.hpp:1646-1670): find the magic,
// read the 32-byte big-endian mm root (reversed into an internal uint256), and
// the 4-byte little-endian aux tree size.
bool parse_commitment(const std::vector<uint8_t>& script,
                      uint256& root_out, uint32_t& aux_size_out)
{
    auto pos = std::search(script.begin(), script.end(),
                           std::begin(MM_MAGIC), std::end(MM_MAGIC));
    if (pos == script.end()) return false;
    size_t off = std::distance(script.begin(), pos) + 4;
    if (script.size() - off < 40) return false;
    const uint8_t* p = script.data() + off;
    uint8_t* dst = reinterpret_cast<uint8_t*>(root_out.begin());
    for (int i = 31; i >= 0; --i) dst[i] = *p++;
    const uint8_t* q = script.data() + off + 32;
    aux_size_out = q[0] | (q[1] << 8) | (q[2] << 16) | (q[3] << 24);
    return true;
}

// Deterministic non-trivial 32-byte root. Derived via Hash() rather than
// written byte-by-byte through uint256::begin() so the test never depends on
// the internal storage layout.
uint256 root_from_pattern(uint8_t seed)
{
    std::vector<uint8_t> seed_bytes(16, seed);
    return Hash(std::span<const uint8_t>(seed_bytes.data(), seed_bytes.size()));
}

std::vector<uint8_t> make_header(uint8_t seed)
{
    std::vector<uint8_t> h(80);
    for (int i = 0; i < 80; ++i) h[i] = static_cast<uint8_t>(seed ^ i);
    return h;
}

TEST(BtcMergedCommitment, LayoutIs44BytesMagicSizeNonce)
{
    uint256 root = root_from_pattern(0x11);
    auto c = c2pool::merged::build_auxpow_commitment(root, /*tree_size*/1, /*nonce*/0);
    ASSERT_EQ(c.size(), 44u);
    // magic fabe6d6d
    EXPECT_EQ(c[0], 0xfa); EXPECT_EQ(c[1], 0xbe);
    EXPECT_EQ(c[2], 0x6d); EXPECT_EQ(c[3], 0x6d);
    // [4..35] = 32-byte mm root; [36..39] = tree size LE == 1; [40..43] = nonce LE == 0.
    EXPECT_EQ(c[36], 0x01); EXPECT_EQ(c[37], 0x00);
    EXPECT_EQ(c[38], 0x00); EXPECT_EQ(c[39], 0x00);
    for (int i = 40; i < 44; ++i) EXPECT_EQ(c[i], 0x00);
    // The root bytes' orientation is defined by the round trip the VERIFIER
    // performs (parse_commitment mirrors share_check.hpp:1657-1670), not by the
    // producer's internal uint256 byte layout: build -> parse recovers the root.
    uint256 got; uint32_t size = 0;
    ASSERT_TRUE(parse_commitment(c, got, size));
    EXPECT_EQ(size, 1u);
    EXPECT_EQ(got, root);
}

TEST(BtcMergedCommitment, VerifierParseRecoversProducerRootAndSize)
{
    uint256 root = root_from_pattern(0x42);
    auto c = c2pool::merged::build_auxpow_commitment(root, 1, 0);
    uint256 got; uint32_t size = 0;
    ASSERT_TRUE(parse_commitment(c, got, size));
    EXPECT_EQ(size, 1u);
    EXPECT_EQ(got, root);
    // Drift guard: mutating one root byte changes what the verifier parses.
    c[4] ^= 0xff;
    uint256 got2; uint32_t size2 = 0;
    ASSERT_TRUE(parse_commitment(c, got2, size2));
    EXPECT_NE(got2, root);
}

TEST(BtcMergedCommitment, SingleChainRootEqualsHeaderHash)
{
    // Producer sets current_work.block_hash = Hash(header) and builds the
    // commitment root from exactly that (merged_mining.cpp:1251/:1291). For
    // aux_size==1 the verifier requires parsed_root == Hash(header).
    auto header = make_header(0x7e);
    uint256 block_hash = Hash(std::span<const uint8_t>(header.data(), 80));
    auto c = c2pool::merged::build_auxpow_commitment(block_hash, 1, 0);
    uint256 parsed; uint32_t size = 0;
    ASSERT_TRUE(parse_commitment(c, parsed, size));
    EXPECT_EQ(size, 1u);
    EXPECT_EQ(parsed, block_hash);  // the aux_size==1 verify equality
}

TEST(BtcMergedCommitment, FrozenBlobRoundTripsToSameEntries)
{
    // SSOT freeze blob: producer serializes vector<MergedCoinbaseEntry>; the
    // mint (create_local_share, share_check.hpp:2790) + the verifier read the
    // SAME bytes back. count/fields MUST survive the round trip.
    std::vector<btc::MergedCoinbaseEntry> in;
    btc::MergedCoinbaseEntry e;
    e.m_chain_id = 1;
    e.m_coinbase_value = 500000000ull;
    e.m_block_height = 654321;
    e.m_block_header.m_data = make_header(0x33);
    e.m_coinbase_merkle_link.m_index = 0;
    e.m_coinbase_script.m_data = {0x03, 0xaa, 0xbb, 0xcc};
    in.push_back(e);

    PackStream ps;
    ps << in;
    std::vector<unsigned char> blob(
        reinterpret_cast<const unsigned char*>(ps.data()),
        reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
    ASSERT_FALSE(blob.empty());

    std::vector<btc::MergedCoinbaseEntry> out;
    PackStream rs;
    rs.write(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    rs >> out;

    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].m_chain_id, 1u);
    EXPECT_EQ(out[0].m_coinbase_value, 500000000ull);
    EXPECT_EQ(out[0].m_block_height, 654321u);
    EXPECT_EQ(out[0].m_block_header.m_data, e.m_block_header.m_data);
    EXPECT_EQ(out[0].m_coinbase_script.m_data, e.m_coinbase_script.m_data);
}

TEST(BtcMergedCommitment, EmptyFrozenBlobIsEmpty_MergedOffNoOp)
{
    // emit_mm=false path: an empty entry vector must serialize to a blob that
    // deserializes back to empty (no split-brain: no commitment, no info).
    std::vector<btc::MergedCoinbaseEntry> none;
    PackStream ps;
    ps << none;
    std::vector<unsigned char> blob(
        reinterpret_cast<const unsigned char*>(ps.data()),
        reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
    std::vector<btc::MergedCoinbaseEntry> out;
    PackStream rs;
    rs.write(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    rs >> out;
    EXPECT_TRUE(out.empty());
}

TEST(BtcMergedCommitment, ProducerScriptSigLayoutParsesMergedOnAndOff)
{
    // Reproduce the producer's [height][0x2c mm][tag] scriptSig assembly and
    // confirm the verifier's marker search + trailing-length gate accept it.
    uint256 root = root_from_pattern(0x5a);
    auto commit = c2pool::merged::build_auxpow_commitment(root, 1, 0);
    ASSERT_EQ(commit.size(), 44u);

    std::vector<uint8_t> ss;
    // BIP34-ish height push: 03 <3 bytes>
    ss.insert(ss.end(), {0x03, 0x01, 0x02, 0x03});
    // mm push: opcode == length (0x2c) then 44 bytes.
    ss.push_back(static_cast<uint8_t>(commit.size()));
    ss.insert(ss.end(), commit.begin(), commit.end());
    // pool tag push.
    static const char TAG[] = "/c2pool-btc/";
    ss.push_back(static_cast<uint8_t>(sizeof(TAG) - 1));
    ss.insert(ss.end(), TAG, TAG + sizeof(TAG) - 1);

    uint256 got; uint32_t size = 0;
    ASSERT_TRUE(parse_commitment(ss, got, size));
    EXPECT_EQ(size, 1u);
    EXPECT_EQ(got, root);

    // Merged-off scriptSig (height + tag only): NO marker — verify returns the
    // "no mm_data marker" branch, and a share carrying empty info skips.
    std::vector<uint8_t> ss_off;
    ss_off.insert(ss_off.end(), {0x03, 0x01, 0x02, 0x03});
    ss_off.push_back(static_cast<uint8_t>(sizeof(TAG) - 1));
    ss_off.insert(ss_off.end(), TAG, TAG + sizeof(TAG) - 1);
    uint256 none; uint32_t nsize = 0;
    EXPECT_FALSE(parse_commitment(ss_off, none, nsize));
}

} // namespace
