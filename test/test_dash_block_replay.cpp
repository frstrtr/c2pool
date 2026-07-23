// SPDX-License-Identifier: AGPL-3.0-or-later
// Block-replay (BIP 152 compact-block) reassembly tests for DASH (S5 slice).
//
// Exercises the vendored compact-block encoding ported in
// src/impl/dash/coin/vendor/blockencodings.{hpp,cpp} (foundation bdecc5c2):
//   - CBlockHeaderAndShortTxIDs construction + short-ID derivation
//   - PartiallyDownloadedBlock::InitData / IsTxAvailable / FillBlock
//   - the getblocktxn wire types (BlockTransactionsRequest / BlockTransactions)
//     and the differential index encoding (DifferenceListFormat).
//
// These are behavioural round-trip tests, not byte-for-byte KATs against a
// captured dashcore corpus: the foundation comment promises wire-format
// parity, but the value the reassembler must guarantee is that a block fed
// through compact-encode -> serialize -> deserialize -> reassemble comes back
// byte-identical. We assert that, plus the documented INVALID/short-circuit
// rejection paths. A regression in the SipHash short-ID, the prefilled-index
// walk, or the missing-tx fill order turns these red.
//
// Transactions are identified here by serialized hash (the same
// ::Hash(pack(tx)) the encoder uses to build short IDs), so distinct
// locktimes are enough to make them distinguishable fixtures.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/blockencodings.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <utility>
#include <vector>

using namespace dash::coin;
namespace v = dash::coin::vendor;

namespace {

// A minimal-but-distinct transaction. Empty inputs/outputs keep the fixture
// small; the locktime is the only varying field, which is sufficient to give
// each tx a unique serialized hash (and therefore a unique short ID).
MutableTransaction make_tx(uint32_t locktime) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = locktime;
    return tx;
}

// Serialized hash — mirrors the encoder's GetShortID input
// (CBlockHeaderAndShortTxIDs ctor: ::Hash(pack(tx).get_span())).
uint256 tx_hash(const MutableTransaction& tx) {
    auto ps = pack(tx);
    return ::Hash(ps.get_span());
}

// A block with a non-null header (m_bits != 0) and `n_txs` distinct txs.
// m_txs[0] is the coinbase, prefilled by the compact encoder.
BlockType make_block(size_t n_txs) {
    BlockType b;
    b.m_version = 1;
    b.m_bits = 0x1d00ffff;       // non-zero => header.IsNull() == false
    b.m_timestamp = 1700000000;
    b.m_nonce = 42;
    for (size_t i = 0; i < n_txs; ++i)
        b.m_txs.push_back(make_tx(static_cast<uint32_t>(1000 + i)));
    return b;
}

// No mempool snapshot (pre-Phase-M): every non-prefilled tx must arrive via
// getblocktxn. The constructor accepts a null std::function.
v::MempoolShortIdProvider no_mempool() { return nullptr; }

constexpr size_t kMaxBlockTxCount = 100000;  // generous bound; not under test here

// Assert two blocks have identical transaction sets (by serialized hash) and
// matching header identity fields.
void expect_block_eq(const BlockType& got, const BlockType& want) {
    ASSERT_EQ(got.m_txs.size(), want.m_txs.size());
    for (size_t i = 0; i < want.m_txs.size(); ++i)
        EXPECT_EQ(tx_hash(got.m_txs[i]), tx_hash(want.m_txs[i])) << "tx mismatch at index " << i;
    EXPECT_EQ(got.m_bits, want.m_bits);
    EXPECT_EQ(got.m_timestamp, want.m_timestamp);
    EXPECT_EQ(got.m_nonce, want.m_nonce);
    EXPECT_EQ(got.m_previous_block, want.m_previous_block);
    EXPECT_EQ(got.m_merkle_root, want.m_merkle_root);
}

} // namespace

// Full round trip with no mempool help: coinbase is prefilled, every other tx
// is supplied as a "missing" getblocktxn response, and the reassembled block
// must match the original.
TEST(DashBlockReplay, RoundTripAllMissing) {
    const BlockType block = make_block(4);

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    EXPECT_EQ(cmpct.BlockTxCount(), 4u);

    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    ASSERT_EQ(pdb.InitData(cmpct, {}), v::READ_STATUS_OK);

    // Only the coinbase (index 0) is available before getblocktxn.
    EXPECT_TRUE(pdb.IsTxAvailable(0));
    for (size_t i = 1; i < 4; ++i)
        EXPECT_FALSE(pdb.IsTxAvailable(i)) << "index " << i << " should be missing";

    std::vector<v::CTransactionRef> missing;
    for (size_t i = 1; i < block.m_txs.size(); ++i)
        missing.push_back(v::MakeTransactionRef(block.m_txs[i]));

    BlockType recon;
    ASSERT_EQ(pdb.FillBlock(recon, missing), v::READ_STATUS_OK);
    expect_block_eq(recon, block);
}

// The compact block survives a serialize/deserialize hop (the wire path) and
// still reassembles. This is the property the foundation's "byte-for-byte"
// claim has to satisfy end to end.
TEST(DashBlockReplay, CompactBlockSerializationRoundTrip) {
    const BlockType block = make_block(5);

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    auto stream = pack(cmpct);
    EXPECT_GT(stream.size(), 0u);

    v::CBlockHeaderAndShortTxIDs decoded;
    stream >> decoded;
    EXPECT_EQ(decoded.BlockTxCount(), cmpct.BlockTxCount());

    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    ASSERT_EQ(pdb.InitData(decoded, {}), v::READ_STATUS_OK);

    std::vector<v::CTransactionRef> missing;
    for (size_t i = 1; i < block.m_txs.size(); ++i)
        missing.push_back(v::MakeTransactionRef(block.m_txs[i]));

    BlockType recon;
    ASSERT_EQ(pdb.FillBlock(recon, missing), v::READ_STATUS_OK);
    expect_block_eq(recon, block);
}

// A mempool snapshot supplies one of the block's txs by short ID, so it no
// longer has to be requested via getblocktxn.
TEST(DashBlockReplay, MempoolProviderSatisfiesShortId) {
    const BlockType block = make_block(4);

    // Provide tx at index 1 from the "mempool".
    const MutableTransaction& mem_tx = block.m_txs[1];
    auto provider = [mem_tx]() -> std::vector<std::pair<uint256, v::CTransactionRef>> {
        return {{tx_hash(mem_tx), v::MakeTransactionRef(mem_tx)}};
    };

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    v::PartiallyDownloadedBlock pdb(provider, kMaxBlockTxCount);
    ASSERT_EQ(pdb.InitData(cmpct, {}), v::READ_STATUS_OK);

    EXPECT_TRUE(pdb.IsTxAvailable(0));  // coinbase, prefilled
    EXPECT_TRUE(pdb.IsTxAvailable(1));  // satisfied from mempool
    EXPECT_FALSE(pdb.IsTxAvailable(2));
    EXPECT_FALSE(pdb.IsTxAvailable(3));

    // getblocktxn now only needs indexes 2 and 3, in order.
    std::vector<v::CTransactionRef> missing{
        v::MakeTransactionRef(block.m_txs[2]),
        v::MakeTransactionRef(block.m_txs[3]),
    };

    BlockType recon;
    ASSERT_EQ(pdb.FillBlock(recon, missing), v::READ_STATUS_OK);
    expect_block_eq(recon, block);
}

// extra_txn (the orphan/recent-relay pool) is consulted the same way the
// mempool snapshot is.
TEST(DashBlockReplay, ExtraTxnSatisfiesShortId) {
    const BlockType block = make_block(3);

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);

    std::vector<std::pair<uint256, v::CTransactionRef>> extra{
        {tx_hash(block.m_txs[2]), v::MakeTransactionRef(block.m_txs[2])},
    };
    ASSERT_EQ(pdb.InitData(cmpct, extra), v::READ_STATUS_OK);

    EXPECT_TRUE(pdb.IsTxAvailable(0));
    EXPECT_FALSE(pdb.IsTxAvailable(1));
    EXPECT_TRUE(pdb.IsTxAvailable(2));  // from extra_txn

    std::vector<v::CTransactionRef> missing{v::MakeTransactionRef(block.m_txs[1])};
    BlockType recon;
    ASSERT_EQ(pdb.FillBlock(recon, missing), v::READ_STATUS_OK);
    expect_block_eq(recon, block);
}

// A null/empty header is rejected outright.
TEST(DashBlockReplay, InitDataRejectsNullHeader) {
    v::CBlockHeaderAndShortTxIDs empty;  // default header is null (m_bits == 0)
    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    EXPECT_EQ(pdb.InitData(empty, {}), v::READ_STATUS_INVALID);
}

// A non-null header with no shorttxids and no prefilled txn is rejected: there
// is nothing to reassemble.
TEST(DashBlockReplay, InitDataRejectsEmptyBody) {
    v::CBlockHeaderAndShortTxIDs cmpct;  // leaves shorttxids/prefilledtxn empty
    cmpct.header.m_bits = 0x1d00ffff;    // make the header non-null
    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    EXPECT_EQ(pdb.InitData(cmpct, {}), v::READ_STATUS_INVALID);
}

// FillBlock must reject a getblocktxn response that supplies too few
// transactions to fill the missing slots.
TEST(DashBlockReplay, FillBlockRejectsTooFewMissing) {
    const BlockType block = make_block(4);  // needs 3 missing (indexes 1..3)

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    ASSERT_EQ(pdb.InitData(cmpct, {}), v::READ_STATUS_OK);

    std::vector<v::CTransactionRef> too_few{
        v::MakeTransactionRef(block.m_txs[1]),
        v::MakeTransactionRef(block.m_txs[2]),
    };
    BlockType recon;
    EXPECT_EQ(pdb.FillBlock(recon, too_few), v::READ_STATUS_INVALID);
}

// FillBlock must also reject a response with too many transactions (leftover
// after the missing slots are filled).
TEST(DashBlockReplay, FillBlockRejectsTooManyMissing) {
    const BlockType block = make_block(3);  // needs 2 missing (indexes 1..2)

    v::CBlockHeaderAndShortTxIDs cmpct(block);
    v::PartiallyDownloadedBlock pdb(no_mempool(), kMaxBlockTxCount);
    ASSERT_EQ(pdb.InitData(cmpct, {}), v::READ_STATUS_OK);

    std::vector<v::CTransactionRef> too_many{
        v::MakeTransactionRef(block.m_txs[1]),
        v::MakeTransactionRef(block.m_txs[2]),
        v::MakeTransactionRef(make_tx(9999)),  // unwanted extra
    };
    BlockType recon;
    EXPECT_EQ(pdb.FillBlock(recon, too_many), v::READ_STATUS_INVALID);
}

// getblocktxn request wire type: blockhash + a strictly-increasing index set
// encoded with the differential compact-size formatter. Round trip must
// preserve both fields exactly.
TEST(DashBlockReplay, BlockTransactionsRequestRoundTrip) {
    v::BlockTransactionsRequest req;
    req.blockhash = tx_hash(make_tx(7));            // any concrete uint256
    req.indexes = {0, 1, 5, 100, 4242, 65535};       // strictly increasing

    auto stream = pack(req);
    v::BlockTransactionsRequest decoded;
    stream >> decoded;

    EXPECT_EQ(decoded.blockhash, req.blockhash);
    EXPECT_EQ(decoded.indexes, req.indexes);
}

// getblocktxn response wire type: blockhash + a vector of full transactions.
TEST(DashBlockReplay, BlockTransactionsRoundTrip) {
    v::BlockTransactions resp;
    resp.blockhash = tx_hash(make_tx(11));
    resp.txn = {
        v::MakeTransactionRef(make_tx(1)),
        v::MakeTransactionRef(make_tx(2)),
        v::MakeTransactionRef(make_tx(3)),
    };

    auto stream = pack(resp);
    v::BlockTransactions decoded;
    stream >> decoded;

    EXPECT_EQ(decoded.blockhash, resp.blockhash);
    ASSERT_EQ(decoded.txn.size(), resp.txn.size());
    for (size_t i = 0; i < resp.txn.size(); ++i) {
        ASSERT_TRUE(decoded.txn[i]);
        EXPECT_EQ(tx_hash(*decoded.txn[i]), tx_hash(*resp.txn[i])) << "txn mismatch at " << i;
    }
}