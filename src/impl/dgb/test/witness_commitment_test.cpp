// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb::coin::add_witness_commitment / assemble_won_block witness-commitment KAT
// (#82 broadcaster-gate, POPULATED-block witness slice, 2026-06-25).
//
// Locks the BIP141 coinbase witness-commitment injection that lets a forced-won
// reconstruct over a WITNESS-BEARING mempool ship a block node B ACCEPTs (the
// coinbase-only G3b proof drained witness; the populated set was rejected
// `unexpected-witness` until this seam landed). Mirrors Bitcoin Core
// GenerateCoinbaseCommitment:
//   * witness merkle root over [coinbase wtxid==0] ++ other-tx wtxids;
//   * commitment = SHA256d(witness_root || 32-byte reserved value);
//   * coinbase gains an OP_RETURN 0x24 0xaa21a9ed <commitment> output AND a
//     single 32-byte reserved-value input witness.
// Trigger discipline: inject IFF the body carries witness data -- a coinbase-
// only / all-legacy body is left byte-identical (zero regression).
//
// Goldens are hand-derived through the same Hash()/pack primitives via an
// INDEPENDENT recomputation path (not by calling add_witness_commitment), so
// the assertions are non-circular against the production injector.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/block_assembly.hpp"
#include "../coin/witness_commitment.hpp"

namespace {

using dgb::coin::BlockType;
using dgb::coin::MutableTransaction;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::assemble_won_block;
using dgb::coin::add_witness_commitment;
using dgb::coin::body_has_witness;
using dgb::coin::compute_wtxid;
using dgb::coin::compute_witness_merkle_root;
using dgb::coin::witness_commitment_script;

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

// A plain (legacy) non-coinbase tx.
MutableTransaction make_legacy_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

// A witness-bearing (segwit) non-coinbase tx: a non-empty input witness stack.
MutableTransaction make_segwit_tx(int64_t value, unsigned char tag)
{
    auto tx = make_legacy_tx(value);
    tx.vin[0].scriptWitness.stack = { std::vector<unsigned char>{tag, 0xbe, 0xef} };
    return tx;
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

uint256 fixed_gentx_hash()
{
    uint256 h;
    h.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    return h;
}

// Independent recomputation of the BIP141 commitment hash for a body, NOT via
// add_witness_commitment: witness_root = duplicate-last merkle over
// [0] ++ wtxids; commitment = SHA256d(witness_root || 32 zero bytes).
uint256 expected_commitment(const std::vector<MutableTransaction>& body)
{
    std::vector<uint256> wids;
    wids.push_back(uint256());                       // coinbase wtxid := 0
    for (const auto& tx : body) {
        auto packed = pack(dgb::coin::TX_WITH_WITNESS(tx));
        wids.push_back(Hash(packed.get_span()));     // wtxid
    }
    // duplicate-last merkle
    while (wids.size() > 1) {
        if (wids.size() % 2 == 1) wids.push_back(wids.back());
        std::vector<uint256> next;
        for (size_t i = 0; i + 1 < wids.size(); i += 2)
            next.push_back(Hash(wids[i], wids[i + 1]));
        wids = std::move(next);
    }
    return Hash(wids[0], uint256());                  // || reserved value (zero)
}

// --- Test 1: body_has_witness predicate ---------------------------------------
TEST(DgbWitnessCommitment, BodyHasWitnessPredicate)
{
    EXPECT_FALSE(body_has_witness({}));
    EXPECT_FALSE(body_has_witness({ make_legacy_tx(1), make_legacy_tx(2) }));
    EXPECT_TRUE(body_has_witness({ make_legacy_tx(1), make_segwit_tx(2, 0x01) }));
}

// --- Test 2: commitment script is OP_RETURN 0x24 0xaa21a9ed <32-byte hash> -----
TEST(DgbWitnessCommitment, CommitmentScriptShape)
{
    uint256 c; c.SetHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    auto s = witness_commitment_script(c);
    ASSERT_EQ(s.size(), 38u);
    EXPECT_EQ(s[0], 0x6a);  // OP_RETURN
    EXPECT_EQ(s[1], 0x24);  // push 36
    EXPECT_EQ(s[2], 0xaa); EXPECT_EQ(s[3], 0x21);
    EXPECT_EQ(s[4], 0xa9); EXPECT_EQ(s[5], 0xed);
    // tail 32 bytes == commitment little-endian byte layout (uint256::data()).
    std::vector<unsigned char> tail(s.begin() + 6, s.end());
    std::vector<unsigned char> want(c.data(), c.data() + 32);
    EXPECT_EQ(tail, want);
}

// --- Test 3: add_witness_commitment matches the independent golden -------------
TEST(DgbWitnessCommitment, InjectorMatchesIndependentGolden)
{
    std::vector<MutableTransaction> body = { make_legacy_tx(10), make_segwit_tx(20, 0x07) };
    const uint256 want_commit = expected_commitment(body);

    auto coinbase = make_gentx();
    ASSERT_FALSE(coinbase.HasWitness());
    const size_t vout_before = coinbase.vout.size();
    add_witness_commitment(coinbase, body);

    // (a) coinbase gained exactly one output, the commitment OP_RETURN.
    ASSERT_EQ(coinbase.vout.size(), vout_before + 1);
    const auto& spk = coinbase.vout.back().scriptPubKey.m_data;
    EXPECT_EQ(coinbase.vout.back().value, 0);
    ASSERT_EQ(spk.size(), 38u);
    std::vector<unsigned char> got_commit_bytes(spk.begin() + 6, spk.end());
    std::vector<unsigned char> want_commit_bytes(want_commit.data(), want_commit.data() + 32);
    EXPECT_EQ(got_commit_bytes, want_commit_bytes);

    // (b) coinbase input[0] now carries a single 32-byte zero reserved value.
    ASSERT_EQ(coinbase.vin.size(), 1u);
    ASSERT_EQ(coinbase.vin[0].scriptWitness.stack.size(), 1u);
    EXPECT_EQ(coinbase.vin[0].scriptWitness.stack[0],
              std::vector<unsigned char>(32, 0x00));
    EXPECT_TRUE(coinbase.HasWitness());
}

// --- Test 4: witness merkle root, coinbase wtxid is zero (single other tx) -----
TEST(DgbWitnessCommitment, WitnessMerkleRootCoinbaseZero)
{
    auto seg = make_segwit_tx(5, 0x03);
    std::vector<MutableTransaction> body = { seg };
    // [0, wtxid] => root == Hash(0, wtxid).
    EXPECT_EQ(compute_witness_merkle_root(body),
              Hash(uint256(), compute_wtxid(seg)));
}

// --- Test 5: assemble injects ONLY for a witness body (trigger discipline) -----
TEST(DgbWitnessCommitment, AssembleInjectsForWitnessBodyOnly)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;

    // Legacy body: NO injection -> coinbase still 1 output, legacy block.
    {
        std::vector<MutableTransaction> body = { make_legacy_tx(10), make_legacy_tx(20) };
        auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, body);
        PackStream ps(bytes); BlockType blk; ps >> blk;
        ASSERT_EQ(blk.m_txs.size(), 3u);
        EXPECT_EQ(blk.m_txs[0].vout.size(), 1u);       // no commitment output
        EXPECT_FALSE(blk.m_txs[0].HasWitness());       // legacy coinbase
        // merkle root over legacy body txids (post-injection == pre here).
        EXPECT_EQ(blk.m_merkle_root, dgb::coin::build_block_merkle_root(
            { gtx_hash, dgb::coin::compute_txid(body[0]), dgb::coin::compute_txid(body[1]) }));
    }

    // Witness body: injection -> coinbase 2 outputs (commitment last), segwit.
    {
        std::vector<MutableTransaction> body = { make_legacy_tx(10), make_segwit_tx(20, 0x09) };
        auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, body);
        PackStream ps(bytes); BlockType blk; ps >> blk;
        ASSERT_EQ(blk.m_txs.size(), 3u);

        // (a) coinbase carries the commitment output + reserved-value witness.
        ASSERT_EQ(blk.m_txs[0].vout.size(), 2u);
        EXPECT_TRUE(blk.m_txs[0].HasWitness());
        ASSERT_EQ(blk.m_txs[0].vin[0].scriptWitness.stack.size(), 1u);
        EXPECT_EQ(blk.m_txs[0].vin[0].scriptWitness.stack[0],
                  std::vector<unsigned char>(32, 0x00));
        const auto& spk = blk.m_txs[0].vout.back().scriptPubKey.m_data;
        ASSERT_EQ(spk.size(), 38u);
        EXPECT_EQ(spk[0], 0x6a); EXPECT_EQ(spk[1], 0x24);
        EXPECT_EQ(spk[2], 0xaa); EXPECT_EQ(spk[3], 0x21);
        EXPECT_EQ(spk[4], 0xa9); EXPECT_EQ(spk[5], 0xed);
        std::vector<unsigned char> got(spk.begin() + 6, spk.end());
        auto wc = expected_commitment(body);
        std::vector<unsigned char> want(wc.data(), wc.data() + 32);
        EXPECT_EQ(got, want);

        // (b) header merkle_root is over the POST-injection coinbase txid (the
        //     coinbase changed when the commitment output was appended), so the
        //     header agrees with the body the daemon validates.
        const uint256 post_txid = dgb::coin::compute_txid(blk.m_txs[0]);
        EXPECT_EQ(blk.m_merkle_root, dgb::coin::build_block_merkle_root(
            { post_txid, dgb::coin::compute_txid(body[0]), dgb::coin::compute_txid(body[1]) }));
        EXPECT_NE(post_txid, gtx_hash);   // injection mutated the coinbase txid
    }
}

} // namespace