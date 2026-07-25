// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::assemble_won_block / reconstruct_block_header / body_merkle_root
// test (#744 broadcaster arc, faithful as_block FRAMING half -- slice 4/7).
//
// Locks the share->block reassembly contract the BTC won-block reconstructor
// feeds to the dual-path broadcaster, mirroring p2pool data.py Share.as_block:
//   * the full header's merkle_root is RECONSTRUCTED from the gentx txid walked
//     up the share's (segwit-resolved) merkle link -- SmallBlockHeader stores no
//     merkle_root -- empty branch => root == gentx_hash; index bit selects side;
//   * block txs are [gentx] ++ other_txs, coinbase at index 0, template order;
//   * the assembled body's merkle root (sealed compute_merkle_root over the
//     non-witness txids) MUST match the share-committed header root, else
//     assemble_won_block FAILS CLOSED (throws) rather than emit a
//     bad-txnmrklroot block;
//   * the block round-trips through BlockType (the live submitblock wire path),
//     block_hex == HexStr(block_bytes), and the CONDITIONAL witness codec emits
//     a witness block iff the (already-committed) gentx carries a witness.
//
// The gentx enters as an already witness-committed MutableTransaction + its
// non-witness txid (BTC commits at gentx-build time -- share_check.hpp:2166/
// :2296 -- so this framer does NOT re-inject a witness commitment). KATs are
// self-derived via the same Hash() the merkle walk uses, independent of any
// fixture file, and build every non-empty merkle link from the SSOT
// other_tx_txid so the body/header guard is exercised on genuinely consistent
// inputs.
//
// MUST appear in src/impl/btc/test/CMakeLists.txt's btc_share_test target (it
// does) or it becomes a NOT_BUILT sentinel; btc_share_test is already on the
// build.yml --target allowlist, so no workflow change is needed.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/btc/coin/block_assembly.hpp>

namespace {

using btc::coin::BlockType;
using btc::coin::SmallBlockHeaderType;
using btc::coin::MutableTransaction;
using btc::coin::TxIn;
using btc::coin::TxOut;
using btc::coin::assemble_won_block;
using btc::coin::reconstruct_block_header;
using btc::coin::body_merkle_root;
using btc::coin::other_tx_txid;

// A minimal coinbase-shaped gentx: one input spending the null outpoint, one
// output. Exact bytes are irrelevant to the framing math -- it just needs to
// serialize and round-trip.
MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
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

// Replicate one merkle-branch combine step the way btc::check_merkle_link does:
// if the index bit is set, branch is on the LEFT, else cur is on the LEFT; then
// double-SHA256 the 64-byte concat. combine(a,b,false) also equals a single
// compute_merkle_root pair fold of [a,b].
uint256 combine(const uint256& cur, const uint256& branch, bool branch_left)
{
    PackStream ps;
    if (branch_left) { ps << branch; ps << cur; }
    else             { ps << cur; ps << branch; }
    auto sp = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
    return Hash(sp);
}
uint256 pair_hash(const uint256& a, const uint256& b) { return combine(a, b, /*branch_left=*/false); }

uint256 fixed_gentx_hash()
{
    uint256 h;
    h.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    return h;
}

// --- Test 1: empty merkle branch => merkle_root == gentx_hash, header copied --
TEST(BtcBlockAssembly, EmptyBranchRootIsGentxHash)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;  // empty branch, index 0

    auto header = reconstruct_block_header(sh, gtx_hash, link);

    EXPECT_EQ(header.m_merkle_root, gtx_hash);
    EXPECT_EQ(header.m_version, sh.m_version);
    EXPECT_EQ(header.m_previous_block, sh.m_previous_block);
    EXPECT_EQ(header.m_timestamp, sh.m_timestamp);
    EXPECT_EQ(header.m_bits, sh.m_bits);
    EXPECT_EQ(header.m_nonce, sh.m_nonce);
}

// --- Test 2: one-branch link, index bit 0 => cur on left (KAT) ----------------
TEST(BtcBlockAssembly, SingleBranchIndexZero)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;
    uint256 b0; b0.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    link.m_branch.push_back(b0);
    link.m_index = 0;

    auto header = reconstruct_block_header(sh, gtx_hash, link);
    EXPECT_EQ(header.m_merkle_root, combine(gtx_hash, b0, /*branch_left=*/false));
}

// --- Test 3: index bit set => branch on left (order matters) -------------------
TEST(BtcBlockAssembly, SingleBranchIndexOne)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;
    uint256 b0; b0.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    link.m_branch.push_back(b0);
    link.m_index = 1;

    auto header = reconstruct_block_header(sh, gtx_hash, link);
    EXPECT_EQ(header.m_merkle_root, combine(gtx_hash, b0, /*branch_left=*/true));
    // index discriminates side: the two orderings must differ.
    EXPECT_NE(combine(gtx_hash, b0, true), combine(gtx_hash, b0, false));
}

// --- Test 4: body_merkle_root is the sealed compute_merkle_root SSOT ----------
TEST(BtcBlockAssembly, BodyMerkleRootMatchesSSOT)
{
    auto gtx_hash = fixed_gentx_hash();
    // no other txs => root == gentx_hash (single leaf).
    EXPECT_EQ(body_merkle_root(gtx_hash, {}), gtx_hash);

    // one other tx => pair fold of [gentx_hash, txid(t1)].
    auto t1 = make_tx(10);
    auto t1id = other_tx_txid(t1);
    EXPECT_EQ(body_merkle_root(gtx_hash, {t1}), pair_hash(gtx_hash, t1id));
    // cross-check against the sealed compute_merkle_root directly.
    EXPECT_EQ(body_merkle_root(gtx_hash, {t1}),
              btc::coin::compute_merkle_root({gtx_hash, t1id}));
}

// --- Test 5: full assemble round-trips, coinbase first, hex==HexStr(bytes) -----
// Two-leaf tree: leaves [gentx, t1]; coinbase (leaf 0) branch = [txid(t1)].
TEST(BtcBlockAssembly, AssembleRoundTripsCoinbaseFirst)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    auto tx1 = make_tx(10);
    auto t1id = other_tx_txid(tx1);

    ::btc::MerkleLink link;            // consistent leaf-0 branch for [gentx, t1]
    link.m_branch.push_back(t1id);
    link.m_index = 0;
    std::vector<MutableTransaction> other = { tx1 };

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, other);

    ASSERT_FALSE(bytes.empty());
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
    EXPECT_EQ(blk.m_merkle_root, pair_hash(gtx_hash, t1id));

    // txs = [gentx] ++ other_txs : coinbase at index 0, total = 1 + 1.
    ASSERT_EQ(blk.m_txs.size(), 2u);
    // tx 0 is the coinbase (gentx): spends the null outpoint at 0xffffffff.
    EXPECT_EQ(blk.m_txs[0].version, gentx.version);
    ASSERT_EQ(blk.m_txs[0].vin.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_TRUE(blk.m_txs[0].vin[0].prevout.hash.IsNull());
    ASSERT_EQ(blk.m_txs[0].vout.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vout[0].value, gentx.vout[0].value);
    // the other_tx follows.
    ASSERT_EQ(blk.m_txs[1].vout.size(), 1u);
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 10);
}

// --- Test 6: multi-tx ordering preserved (3-leaf consistent tree) --------------
// leaves [gentx, t1, t2]; compute_merkle_root duplicates the odd last leaf, so
// the coinbase branch is [txid(t1), pair(txid(t2), txid(t2))].
TEST(BtcBlockAssembly, MultiTxOrderPreserved)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    auto tx1 = make_tx(11);
    auto tx2 = make_tx(22);
    auto t1id = other_tx_txid(tx1);
    auto t2id = other_tx_txid(tx2);

    ::btc::MerkleLink link;
    link.m_branch.push_back(t1id);
    link.m_branch.push_back(pair_hash(t2id, t2id));   // odd-leaf duplication
    link.m_index = 0;
    std::vector<MutableTransaction> other = { tx1, tx2 };

    // sanity: the branch we built reconstructs the same root the body hashes to.
    ASSERT_EQ(reconstruct_block_header(sh, gtx_hash, link).m_merkle_root,
              body_merkle_root(gtx_hash, other));

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, other);
    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 3u);
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 11);   // t1 before t2
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 22);
}

// --- Test 7: no other_txs => single-tx block (coinbase only) -------------------
TEST(BtcBlockAssembly, CoinbaseOnlyBlock)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;   // empty branch => root == gtx_hash, body matches
    std::vector<MutableTransaction> none;

    auto [bytes, hex] = assemble_won_block(sh, gentx, gtx_hash, link, none);

    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_merkle_root, gtx_hash);
}

// --- Test 8: body/header mismatch FAILS CLOSED (never emit bad-txnmrklroot) ----
TEST(BtcBlockAssembly, MismatchedBodyThrows)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gtx_hash = fixed_gentx_hash();
    // Header commits to a coinbase-only root (empty branch) but the body carries
    // a fee tx: the assembled body root (pair fold) != the header root -- exactly
    // the template-capture non-empty-link miss case. Must throw, not emit.
    ::btc::MerkleLink empty_link;
    std::vector<MutableTransaction> other = { make_tx(99) };
    EXPECT_THROW(assemble_won_block(sh, gentx, gtx_hash, empty_link, other),
                 std::runtime_error);

    // Conversely, a wrong (non-matching) branch with a matching-count body also
    // fails: branch sibling that is not txid(t1).
    auto tx1 = make_tx(99);
    ::btc::MerkleLink bad_link;
    uint256 wrong; wrong.SetHex("dead00000000000000000000000000000000000000000000000000000000beef");
    bad_link.m_branch.push_back(wrong);
    bad_link.m_index = 0;
    EXPECT_THROW(assemble_won_block(sh, gentx, gtx_hash, bad_link, { tx1 }),
                 std::runtime_error);
}

// === Witness predicate KATs (BTC gentx-time commitment) =======================
// The block wire codec is BlockType::Serialize -> TX_WITH_WITNESS(m_txs), the
// standard Bitcoin-Core CONDITIONAL serializer: it emits the per-tx witness
// marker/flag (and stacks) iff some tx HasWitness(), a legacy blob otherwise. So
// the won-block's witness shape is governed by whether the ALREADY-COMMITTED
// gentx carries a witness -- NOT by an unconditional witness branch in the
// framer, and NOT by any re-injection here. These pin emission == verification.

// The BIP141 coinbase witness reserved value: a single 32-byte zero stack item.
MutableTransaction make_segwit_gentx()
{
    auto tx = make_gentx();
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    return tx;
}

// --- Test 9: segwit gentx => TX_WITH_WITNESS block (predicate true) ------------
// Coinbase-only (empty branch) so the body/header guard passes on the reserved
// gentx_hash; the point under test is the conditional witness emission.
TEST(BtcBlockAssembly, SegwitGentxEmitsWitnessBlock)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;
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

// --- Test 10: no-witness gentx => LEGACY block (predicate false) ---------------
TEST(BtcBlockAssembly, LegacyGentxEmitsLegacyBlock)
{
    auto sh = make_small_header();
    auto gtx_hash = fixed_gentx_hash();
    ::btc::MerkleLink link;
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

} // namespace
