// btc::coin::block_body_matches_header (impl/btc/coin/block_body_check.hpp):
// a pooled block body is passed on only when it belongs to its header (one
// coinbase, first; no repeated txid; txid merkle root; the BIP 141 witness
// commitment). A 64-byte transaction is valid by consensus and accepted. Positive vectors: blocks bitcoind produced
// (the regtest segwit block of btc_regtest_cmpct_fixtures.hpp) and mainnet
// block 170 (pre-segwit, two transactions), checked against its known hash.
#include <gtest/gtest.h>

#include <impl/btc/coin/block_body_check.hpp>

#include <btclibs/util/strencodings.h>

#include "btc_regtest_cmpct_fixtures.hpp"

#include <cstdint>
#include <string>
#include <utility>
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
    out.scriptPubKey.m_data = {0x00, 0x14};   // P2WPKH: 22 bytes
    out.scriptPubKey.m_data.resize(22, static_cast<unsigned char>(tag));
    tx.vout.push_back(out);
    return tx;
}

BlockType parse_block(const std::string& hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
}

// Mainnet block 170 (the first block with a spend), serialized from its known
// header and its two transactions; the KAT checks the hash and the txids.
const char* kBlock170Hex =
    "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000"
    "ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49"
    "ffff001d283e9e70"
    "02"
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2"
    "aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd7257"
    "06957c092db53805b821a85b23a7ac61725bac00000000"
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
    "000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548"
    "ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d"
    "1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f715"
    "9b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded"
    "5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb6"
    "8a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03"
    "f999b8643f656b412a3ac00000000";
const char* kBlock170Hash = "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee";
const char* kBlock170Txid0 = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082";
const char* kBlock170Txid1 = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

uint256 header_hash(const BlockType& b)
{
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    return Hash(packed.get_span());
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

TEST(BtcBlockBodyCheck, CoinbaseFirstAndOnly64ByteTransactionsAccepted)
{
    // The first transaction is not a coinbase.
    BlockType nocb;
    nocb.m_txs = {spend(1, false), spend(2, false)};
    seal(nocb);
    EXPECT_FALSE(block_body_matches_header(nocb));

    // A second coinbase.
    BlockType two;
    two.m_txs = {coinbase(1), coinbase(2)};
    seal(two);
    EXPECT_FALSE(block_body_matches_header(two));

    // A transaction of exactly 64 bytes without witness: valid by consensus,
    // accepted after a coinbase.
    MutableTransaction t64 = spend(3, false);
    t64.vout.front().scriptPubKey.m_data = {0x51, 0x52, 0x53, 0x54};
    ASSERT_EQ(pack(TX_NO_WITNESS(t64)).size(), 64u);
    BlockType b64;
    b64.m_txs = {coinbase(3), t64};
    seal(b64);
    EXPECT_TRUE(block_body_matches_header(b64));
    // A 64-byte coinbase: accepted too.
    MutableTransaction cb64 = coinbase(4);
    cb64.vin.front().scriptSig.m_data = {0x03, 0x04, 0x01};
    ASSERT_EQ(pack(TX_NO_WITNESS(cb64)).size(), 64u);
    BlockType bcb64;
    bcb64.m_txs = {cb64, spend(4, false)};
    seal(bcb64);
    EXPECT_TRUE(block_body_matches_header(bcb64));
    // A 64-byte first transaction that is not a coinbase (Core's mutation
    // case): rejected by the coinbase-first rule.
    BlockType first64;
    first64.m_txs = {t64, spend(5, false)};
    seal(first64);
    EXPECT_FALSE(block_body_matches_header(first64));
}

TEST(BtcBlockBodyCheck, RealBlocksMatch)
{
    // bitcoind's regtest segwit block: six witness spends and a commitment.
    namespace rx = btc_regtest_cmpct_fixture;
    BlockType rt = parse_block(rx::kBlockHex);
    ASSERT_EQ(rt.m_txs.size(), rx::kTxCount);
    EXPECT_EQ(header_hash(rt).GetHex(), rx::kBlockHash);
    EXPECT_GE(witness_commitment_index(rt.m_txs.front()), 0);
    EXPECT_TRUE(block_body_matches_header(rt));
    // One witness byte changed: the txids (and the merkle root) hold, the
    // commitment does not.
    BlockType rt_bad = rt;
    rt_bad.m_txs[1].vin.front().scriptWitness.stack.front().back() ^= 0x01;
    EXPECT_FALSE(block_body_matches_header(rt_bad));
    // Two transactions swapped: the merkle root does not hold.
    BlockType rt_swap = rt;
    std::swap(rt_swap.m_txs[1], rt_swap.m_txs[2]);
    EXPECT_FALSE(block_body_matches_header(rt_swap));

    // Mainnet block 170: pre-segwit, no commitment, no witness data.
    BlockType b170 = parse_block(kBlock170Hex);
    ASSERT_EQ(b170.m_txs.size(), 2u);
    EXPECT_EQ(header_hash(b170).GetHex(), kBlock170Hash);
    EXPECT_EQ(compute_txid(b170.m_txs[0]).GetHex(), kBlock170Txid0);
    EXPECT_EQ(compute_txid(b170.m_txs[1]).GetHex(), kBlock170Txid1);
    EXPECT_EQ(witness_commitment_index(b170.m_txs.front()), -1);
    EXPECT_TRUE(block_body_matches_header(b170));
    BlockType b170_bad = b170;
    b170_bad.m_txs[1].vout.front().value += 1;
    EXPECT_FALSE(block_body_matches_header(b170_bad));
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
