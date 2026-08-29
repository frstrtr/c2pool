// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DGB compact-block reconstruction Merkle backstop (issue #976) KAT.
// 1:1 mirror of src/impl/ltc/test/compact_block_merkle_test.cpp (Defect 1),
// ported to the dgb:: coin namespace. LTC/BTC/BCH already carry this guard;
// DGB's ReconstructBlock() was MISSING it.
//
// Defect: ReconstructBlock() used to declare a block complete the instant every
// short-ID slot was filled, never checking the reconstructed tx vector against the
// header Merkle root. A 48-bit SipHash short-ID collision could substitute the wrong
// transaction and nothing would catch it before it reached the UTXO cache. The fix
// computes the Merkle root over the reconstructed txids and DISCARDS on mismatch
// (signalling a full getdata fallback) instead of delivering.
//
// A non-segwit tx has wtxid == txid, so this KAT also pins that such a tx
// reconstructs identically under both id conventions -- the invariant the handler
// fix relies on.
//
// Folded into the allowlisted dgb_compact_blocks_bip152_parity_test target (NOT a
// standalone executable) to avoid the #143 NOT_BUILT / #769 "Not Run" CI trap.

#include <cstdint>
#include <map>
#include <vector>

#include <gtest/gtest.h>

#include "../coin/compact_blocks.hpp"
#include "../coin/transaction.hpp"
#include "../coin/block.hpp"
#include "../coin/mempool.hpp"
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

using dgb::coin::MutableTransaction;
using dgb::coin::TxIn;
using dgb::coin::TxOut;
using dgb::coin::CompactBlock;
using dgb::coin::BlockHeaderType;
using dgb::coin::BuildCompactBlock;
using dgb::coin::ReconstructBlock;
using dgb::coin::ComputeTxMerkleRoot;
using dgb::coin::compute_txid;
using dgb::coin::TX_WITH_WITNESS;

namespace {

// A minimal non-segwit transaction (no witness -> wtxid == txid).
MutableTransaction make_tx(int64_t value, uint32_t index)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

uint256 wtxid_of(const MutableTransaction& tx)
{
    MutableTransaction mtx(tx);
    auto packed = pack(TX_WITH_WITNESS(mtx));
    return Hash(packed.get_span());
}

// The non-coinbase txs (index >= 1) keyed by wtxid, as the cmpctblock handler does.
// The coinbase (index 0) is carried prefilled by BuildCompactBlock.
std::map<uint256, MutableTransaction> known_by_wtxid(const std::vector<MutableTransaction>& txs)
{
    std::map<uint256, MutableTransaction> known;
    for (size_t i = 1; i < txs.size(); ++i)
        known[wtxid_of(txs[i])] = txs[i];
    return known;
}

std::vector<MutableTransaction> sample_block_txs()
{
    std::vector<MutableTransaction> txs;
    for (int i = 0; i < 4; ++i)
        txs.push_back(make_tx(5000 + i, static_cast<uint32_t>(i)));
    return txs;
}

} // namespace

// Correct header Merkle root -> reconstruction completes and delivers.
TEST(DgbCompactBlockMerkle, ReconstructsWhenMerkleMatches)
{
    auto txs = sample_block_txs();
    BlockHeaderType header;
    header.SetNull();
    header.m_merkle_root = ComputeTxMerkleRoot(txs);

    auto cb = BuildCompactBlock(header, txs);
    auto result = ReconstructBlock(cb, known_by_wtxid(txs));

    ASSERT_TRUE(result.complete);
    EXPECT_FALSE(result.merkle_mismatch);
    ASSERT_EQ(result.block.m_txs.size(), txs.size());
    EXPECT_EQ(ComputeTxMerkleRoot(result.block.m_txs), header.m_merkle_root);
}

// A header Merkle root that does NOT match the reconstructed txs must DISCARD, not
// deliver. Simulates a short-ID collision substituting a wrong tx: every slot still
// fills from known_txs, so only the Merkle check can catch it.
//
// RED on master DGB (no Merkle check): result.complete == true -> block ACCEPTED.
// GREEN with the fix: result.complete == false, merkle_mismatch == true -> DISCARDED.
TEST(DgbCompactBlockMerkle, DiscardsOnMerkleMismatch)
{
    auto txs = sample_block_txs();
    BlockHeaderType header;
    header.SetNull();
    header.m_merkle_root = ComputeTxMerkleRoot(txs);
    header.m_merkle_root.data()[0] ^= 0x01;  // flip one bit -> deliberately wrong root

    auto cb = BuildCompactBlock(header, txs);
    auto result = ReconstructBlock(cb, known_by_wtxid(txs));

    EXPECT_FALSE(result.complete) << "must NOT deliver a block whose txs fail the header Merkle check";
    EXPECT_TRUE(result.merkle_mismatch) << "must signal discard + full-block getdata fallback";
    EXPECT_TRUE(result.block.m_txs.empty());
}

// A non-segwit tx has wtxid == txid, so the wtxid-keyed cmpctblock pass and a
// txid-keyed pass compute the SAME short ID: reconstruction from a txid-keyed map
// must still succeed for such a tx.
TEST(DgbCompactBlockMerkle, NonSegwitTxIdPathsAgree)
{
    auto txs = sample_block_txs();
    for (const auto& tx : txs)
        EXPECT_EQ(compute_txid(tx), wtxid_of(tx)) << "non-segwit tx must have wtxid == txid";

    BlockHeaderType header;
    header.SetNull();
    header.m_merkle_root = ComputeTxMerkleRoot(txs);
    auto cb = BuildCompactBlock(header, txs);

    std::map<uint256, MutableTransaction> known_by_txid;
    for (size_t i = 1; i < txs.size(); ++i)
        known_by_txid[compute_txid(txs[i])] = txs[i];

    auto result = ReconstructBlock(cb, known_by_txid);
    ASSERT_TRUE(result.complete);
    EXPECT_FALSE(result.merkle_mismatch);
}
