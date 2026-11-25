// btc::coin::block_body_matches_header (impl/btc/coin/block_body_check.hpp):
// a pooled block body is passed on only when it belongs to its header (txid
// merkle root, no duplicated txid, the BIP 141 witness commitment).
#include <gtest/gtest.h>

#include <impl/btc/coin/block_body_check.hpp>

#include <cstdint>
#include <vector>

using namespace btc::coin;

namespace {

MutableTransaction coinbase(uint32_t tag)
{
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash = uint256::ZERO;
    in.prevout.index = 0xffffffffu;
    in.scriptSig.m_data = {0x03, static_cast<unsigned char>(tag), 0x01, 0x02};
    in.sequence = 0xffffffffu;
    cb.vin.push_back(in);
    TxOut out;
    out.value = 312500000;
    out.scriptPubKey.m_data = {0x51};
    cb.vout.push_back(out);
    return cb;
}

MutableTransaction spend(uint32_t tag, bool witness)
{
    MutableTransaction tx;
    TxIn in;
    in.prevout.hash = uint256::ONE;
    in.prevout.index = tag;
    in.sequence = 0xfffffffeu;
    if (witness)
        in.scriptWitness.stack.push_back(std::vector<unsigned char>(72, 0x30));
    tx.vin.push_back(in);
    TxOut out;
    out.value = 1000 + tag;
    out.scriptPubKey.m_data = {0x00, 0x14, 0x11, 0x22};
    tx.vout.push_back(out);
    return tx;
}

/// The header's merkle root from the body (as a miner builds it).
void seal(BlockType& b)
{
    std::vector<uint256> txids;
    for (const auto& tx : b.m_txs)
        txids.push_back(compute_txid(tx));
    b.m_merkle_root = compute_merkle_root(txids);
}

/// A coinbase witness commitment over the block's other transactions.
void commit_witness(BlockType& b)
{
    auto& cb = b.m_txs.front();
    const std::vector<unsigned char> reserved(32, 0x00);
    cb.vin.front().scriptWitness.stack = {reserved};
    std::vector<uint256> others;
    for (size_t i = 1; i < b.m_txs.size(); ++i)
        others.push_back(compute_wtxid(b.m_txs[i]));
    const uint256 root = witness_merkle_root(others);
    const uint256 c = Hash(std::span<const uint8_t>(root.data(), 32),
                           std::span<const uint8_t>(reserved.data(), 32));
    TxOut out;
    out.value = 0;
    out.scriptPubKey.m_data = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    out.scriptPubKey.m_data.insert(out.scriptPubKey.m_data.end(), c.data(), c.data() + 32);
    cb.vout.push_back(out);
}

} // namespace

TEST(BtcBlockBodyCheck, MerkleRootAndDuplicates)
{
    BlockType b;
    EXPECT_FALSE(block_body_matches_header(b));   // no transactions

    b.m_txs = {coinbase(1)};
    seal(b);
    EXPECT_TRUE(block_body_matches_header(b));
    b.m_merkle_root = uint256::ONE;
    EXPECT_FALSE(block_body_matches_header(b));

    // [cb, t1, t2] and [cb, t1, t2, t2] have the same merkle root; the second
    // repeats a txid and is not the block.
    BlockType odd;
    odd.m_txs = {coinbase(2), spend(1, false), spend(2, false)};
    seal(odd);
    EXPECT_TRUE(block_body_matches_header(odd));
    BlockType dup = odd;
    dup.m_txs.push_back(dup.m_txs.back());
    EXPECT_EQ(dup.m_merkle_root, odd.m_merkle_root);
    seal(dup);
    EXPECT_EQ(dup.m_merkle_root, odd.m_merkle_root);
    EXPECT_FALSE(block_body_matches_header(dup));
}

TEST(BtcBlockBodyCheck, WitnessCommitment)
{
    // Witness data with a matching commitment.
    BlockType w;
    w.m_txs = {coinbase(3), spend(3, true), spend(4, false)};
    commit_witness(w);
    seal(w);
    EXPECT_GE(witness_commitment_index(w.m_txs.front()), 0);
    EXPECT_TRUE(block_body_matches_header(w));

    // Witness data and no commitment.
    BlockType none;
    none.m_txs = {coinbase(4), spend(5, true)};
    seal(none);
    EXPECT_EQ(witness_commitment_index(none.m_txs.front()), -1);
    EXPECT_FALSE(block_body_matches_header(none));

    // A different witness than the one committed to (the txid merkle root
    // still matches: witnesses are not in txids).
    BlockType swapped = w;
    swapped.m_txs[1].vin.front().scriptWitness.stack.front()[0] = 0x31;
    EXPECT_EQ(swapped.m_merkle_root, w.m_merkle_root);
    seal(swapped);
    EXPECT_EQ(swapped.m_merkle_root, w.m_merkle_root);
    EXPECT_FALSE(block_body_matches_header(swapped));

    // The commitment without the coinbase's 32-byte reserved value.
    BlockType nonce = w;
    nonce.m_txs.front().vin.front().scriptWitness.stack.clear();
    seal(nonce);
    EXPECT_FALSE(block_body_matches_header(nonce));

    // A commitment and no witness data anywhere else: valid.
    BlockType plain;
    plain.m_txs = {coinbase(5), spend(6, false)};
    commit_witness(plain);
    seal(plain);
    EXPECT_TRUE(block_body_matches_header(plain));
}
