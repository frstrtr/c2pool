// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb::coin::assemble_won_block / reconstruct_block_header test (#82
// broadcaster-gate, faithful as_block FRAMING half).
//
// Locks the share->block reassembly contract that the won-block reconstructor
// feeds to broadcast_won_block, mirroring p2pool data.py Share.as_block:
//   * the full header's merkle_root is RECONSTRUCTED from the gentx hash walked
//     up the share's merkle_link (SmallBlockHeader stores no merkle_root) --
//     empty branch => root == gentx_hash; index bit selects branch side;
//   * block txs are [gentx] ++ other_txs with the coinbase at index 0;
//   * the assembled block round-trips through BlockType (the live submitblock
//     wire path) and block_hex == HexStr(block_bytes).
//
// The gentx bytes + known_txs lookup are injected (the gentx-byte build that
// hits coinbase-byte adjudication is the next reconstructor slice); this pins
// the framing + merkle_root math NOW. KATs are self-derived via the same Hash()
// the merkle walk uses, so they are independent of any fixture file.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <util/strencodings.h>

#include "../coin/block_assembly.hpp"

namespace {

using dgb::coin::BlockType;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::MutableTransaction;
using dgb::coin::assemble_won_block;
using dgb::coin::reconstruct_block_header;

// A minimal coinbase-shaped gentx: one input spending the null outpoint, one
// output. Exact bytes are irrelevant to the framing math -- it just needs to
// serialize and round-trip.
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

MutableTransaction make_tx(int64_t value)
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

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;   // a non-trivial version (algo bits live here)
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

// Replicate one merkle-branch combine step the way dgb::check_merkle_link does:
// if index bit is set, branch is on the LEFT, else cur is on the LEFT; then
// double-SHA256 the 64-byte concat.
uint256 combine(const uint256& cur, const uint256& branch, bool branch_left)
{
    PackStream ps;
    if (branch_left) { ps << branch; ps << cur; }
    else             { ps << cur; ps << branch; }
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
    return Hash(sp);
}

uint256 fixed_gentx_hash()
{
    uint256 h;
    h.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    return h;
}

// --- Test 1: empty merkle branch => merkle_root == gentx_hash, header copied --
TEST(DgbBlockAssembly, EmptyBranchRootIsGentxHash)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;  // empty branch, index 0

    auto header = reconstruct_block_header(sh, gtx_hash, link);

    EXPECT_EQ(header.m_merkle_root, gtx_hash);
    EXPECT_EQ(header.m_version, sh.m_version);
    EXPECT_EQ(header.m_previous_block, sh.m_previous_block);
    EXPECT_EQ(header.m_timestamp, sh.m_timestamp);
    EXPECT_EQ(header.m_bits, sh.m_bits);
    EXPECT_EQ(header.m_nonce, sh.m_nonce);
}

// --- Test 2: one-branch link, index bit 0 => cur on left (KAT) ----------------
TEST(DgbBlockAssembly, SingleBranchIndexZero)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    uint256 b0; b0.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    link.m_branch.push_back(b0);
    link.m_index = 0;

    auto header = reconstruct_block_header(sh, gtx_hash, link);
    EXPECT_EQ(header.m_merkle_root, combine(gtx_hash, b0, /*branch_left=*/false));
}

// --- Test 3: index bit set => branch on left (order matters) -------------------
TEST(DgbBlockAssembly, SingleBranchIndexOne)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    uint256 b0; b0.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    link.m_branch.push_back(b0);
    link.m_index = 1;

    auto header = reconstruct_block_header(sh, gtx_hash, link);
    EXPECT_EQ(header.m_merkle_root, combine(gtx_hash, b0, /*branch_left=*/true));
    // index discriminates side: the two orderings must differ.
    EXPECT_NE(combine(gtx_hash, b0, true), combine(gtx_hash, b0, false));
}

// --- Test 4: full assemble round-trips, coinbase first, hex==HexStr(bytes) -----
TEST(DgbBlockAssembly, AssembleRoundTripsCoinbaseFirst)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;  // empty branch => root == gtx_hash
    std::vector<MutableTransaction> other = { make_tx(10), make_tx(20) };

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, other);

    ASSERT_FALSE(bytes.empty());
    // hex is the lowercase serialization of the same bytes.
    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
    EXPECT_EQ(hex, HexStr(sp));

    // Round-trip through the live BlockType wire codec.
    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;

    EXPECT_EQ(blk.m_version, sh.m_version);
    EXPECT_EQ(blk.m_previous_block, sh.m_previous_block);
    EXPECT_EQ(blk.m_timestamp, sh.m_timestamp);
    EXPECT_EQ(blk.m_bits, sh.m_bits);
    EXPECT_EQ(blk.m_nonce, sh.m_nonce);
    // header merkle_root is recomputed over the ACTUAL block tx vector
    // ([gentx_hash] ++ other-tx txids), NOT the (empty here) share merkle_link:
    // with two other_txs it must differ from the coinbase-only root and equal
    // build_block_merkle_root over the real leaves (#82 bad-txnmrklroot fix).
    {
        std::vector<uint256> leaves = { gtx_hash,
            dgb::coin::compute_txid(other[0]), dgb::coin::compute_txid(other[1]) };
        EXPECT_EQ(blk.m_merkle_root, dgb::coin::build_block_merkle_root(leaves));
        EXPECT_NE(blk.m_merkle_root, gtx_hash);
    }

    // txs = [gentx] ++ other_txs : coinbase at index 0, total = 1 + 2.
    ASSERT_EQ(blk.m_txs.size(), 3u);
    // tx 0 must be the coinbase (gentx): structural identity (spends the null
    // outpoint at the 0xffffffff index) -- proves coinbase-first ordering.
    EXPECT_EQ(blk.m_txs[0].version, gentx.version);
    ASSERT_EQ(blk.m_txs[0].vin.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_TRUE(blk.m_txs[0].vin[0].prevout.hash.IsNull());
    ASSERT_EQ(blk.m_txs[0].vout.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vout[0].value, gentx.vout[0].value);
    // the other_txs follow, in transaction_hashes order.
    ASSERT_EQ(blk.m_txs[1].vout.size(), 1u);
    ASSERT_EQ(blk.m_txs[2].vout.size(), 1u);
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 10);
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 20);
}

// --- Test 5: no other_txs => single-tx block (coinbase only) -------------------
TEST(DgbBlockAssembly, CoinbaseOnlyBlock)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<MutableTransaction> none;

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, none);

    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_merkle_root, gtx_hash);
}


// === Witness predicate KATs (#82 DGB<->BCH coinbase adjudication) =============
// The block wire codec is BlockType::Serialize -> TX_WITH_WITNESS(m_txs), the
// standard Bitcoin-Core CONDITIONAL serializer: it emits the per-tx witness
// marker/flag (and the witness stacks) iff some tx HasWitness(), and a legacy
// blob otherwise. So the won-block's witness shape is governed by whether the
// gentx carries a witness -- i.e. by is_segwit_activated(share_version) at
// gentx-build time -- NOT by an unconditional witness branch in the framer.
//   DGB: SEGWIT_ACTIVATION_VERSION=35 => v36 gentx carries the BIP141 coinbase
//        witness reserved value => won block is TX_WITH_WITNESS (asserted here).
//   BCH: SEGWIT_ACTIVATION_VERSION=0 sentinel => is_segwit_activated() false for
//        every version => gentx has no witness => the identical codec emits a
//        LEGACY block (the companion bch test asserts the absence).
// These pin the predicate so emission == verification == oracle, per the paired
// adjudication; we do not assume it.

// The BIP141 coinbase witness reserved value: a single 32-byte zero stack item.
MutableTransaction make_segwit_gentx()
{
    auto tx = make_gentx();
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    return tx;
}

// --- Test 6: DGB segwit-active gentx => TX_WITH_WITNESS block (predicate true) -
TEST(DgbBlockAssembly, SegwitGentxEmitsWitnessBlock)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<MutableTransaction> none;

    auto seg = make_segwit_gentx();
    ASSERT_TRUE(seg.HasWitness());        // gentx carries the coinbase witness
    auto [wbytes, whex] = assemble_won_block(sh, seg, gtx_hash, link, none);

    // The conditional codec must have emitted the witness: the witnessful block
    // is strictly larger than the legacy block over the same logical txs, and
    // the round-tripped coinbase preserves the reserved value.
    auto [lbytes, lhex] = assemble_won_block(sh, make_gentx(), gtx_hash, link, none);
    EXPECT_GT(wbytes.size(), lbytes.size());

    PackStream ps(wbytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_TRUE(blk.m_txs[0].HasWitness());
    ASSERT_EQ(blk.m_txs[0].vin.size(), 1u);
    ASSERT_EQ(blk.m_txs[0].vin[0].scriptWitness.stack.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].scriptWitness.stack[0],
              std::vector<unsigned char>(32, 0x00));
    EXPECT_EQ(whex, HexStr(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(wbytes.data()), wbytes.size())));
}

// --- Test 7: no-witness gentx => LEGACY block (predicate false, BCH-shape) -----
TEST(DgbBlockAssembly, LegacyGentxEmitsLegacyBlock)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<MutableTransaction> none;

    auto plain = make_gentx();
    ASSERT_FALSE(plain.HasWitness());
    auto [bytes, hex] = assemble_won_block(sh, plain, gtx_hash, link, none);

    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_FALSE(blk.m_txs[0].HasWitness());   // legacy: no marker/flag emitted

    // Legacy block re-serializes byte-identically (no witness round-trip drift).
    auto [bytes2, hex2] = assemble_won_block(sh, blk.m_txs[0], gtx_hash, link, none);
    EXPECT_EQ(hex, hex2);
}

// --- Test 8: tx-bearing block header root == body root, != coinbase-only ------
// Regression lock for the #82 funded multi-tx gate: a reconstructed block that
// carries 1+ non-coinbase txs MUST publish a header merkle_root computed over
// [gentx]++other_txs, so a peer/daemon validating the body accepts it.  The
// pre-fix path walked the share merkle_link (empty == coinbase-only => gentx_hash)
// and the daemon rejected bad-txnmrklroot.
TEST(DgbBlockAssembly, TxBearingRootMatchesBodyNotMerkleLink)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    ::dgb::MerkleLink link;            // empty link == the coinbase-only branch
    std::vector<MutableTransaction> other = { make_tx(42) };

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, other);
    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;

    ASSERT_EQ(blk.m_txs.size(), 2u);
    const uint256 body_root = dgb::coin::build_block_merkle_root(
        { gtx_hash, dgb::coin::compute_txid(other[0]) });
    EXPECT_EQ(blk.m_merkle_root, body_root);
    // the empty merkle_link would have yielded gentx_hash -- prove we did NOT.
    EXPECT_NE(blk.m_merkle_root, gtx_hash);
    EXPECT_NE(body_root, gtx_hash);
}

} // namespace