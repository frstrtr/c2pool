// SPDX-License-Identifier: AGPL-3.0-or-later
// #968a KAT: BIP 152 compact-block RECEIVE state machine
// (src/impl/dash/coin/compact_block_receive.hpp).
//
// Drives every verdict branch: complete-from-mempool, getblocktxn round trip,
// partial mempool, unrequested / mismatched blocktxn, short blocktxn,
// disconnect, and the merkle bind. The bind cases (PoisonedMempool...,
// SubstitutedBlocktxn..., HeaderMerkleMismatch...) are the revert-red arm:
// drop block_body_binds_to_header from CompactBlockReceiver::fill and they
// come back Complete instead of FallbackFull.

#include <gtest/gtest.h>

#include <impl/dash/coin/compact_block_receive.hpp>
#include <impl/dash/coin/block_producer.hpp>
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
using Kind = CompactReceiveVerdict::Kind;

namespace {

constexpr size_t kMaxTx = 100000;
const std::string kPeer = "1.2.3.4:9999";

MutableTransaction mk_tx(uint32_t locktime) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = locktime;
    return tx;
}

uint256 txid(const MutableTransaction& tx) {
    auto ps = pack(tx);
    return ::Hash(ps.get_span());
}

// A block whose header commits to its own tx set, so a correct reassembly
// passes the merkle bind.
BlockType mk_block(size_t n) {
    BlockType b;
    b.m_version = 1;
    b.m_bits = 0x1d00ffff;
    b.m_timestamp = 1700000000;
    b.m_nonce = 7;
    std::vector<uint256> ids;
    for (size_t i = 0; i < n; ++i) {
        b.m_txs.push_back(mk_tx(static_cast<uint32_t>(5000 + i)));
        ids.push_back(txid(b.m_txs.back()));
    }
    b.m_merkle_root = compute_merkle_root(ids);
    return b;
}

// Any non-null value works: the receiver takes the caller's X11 hash on
// trust and only uses it to pair blocktxn with the parked block.
uint256 bhash(uint8_t tag) {
    uint256 h;
    h.data()[0] = tag;
    return h;
}

v::MempoolShortIdProvider pool_of(const BlockType& b, std::vector<size_t> idx) {
    std::vector<std::pair<uint256, v::CTransactionRef>> snap;
    for (size_t i : idx)
        snap.emplace_back(txid(b.m_txs[i]), v::MakeTransactionRef(b.m_txs[i]));
    return [snap] { return snap; };
}

v::BlockTransactions answer(const v::BlockTransactionsRequest& req, const BlockType& b) {
    v::BlockTransactions resp(req);
    for (size_t k = 0; k < req.indexes.size(); ++k)
        resp.txn[k] = v::MakeTransactionRef(b.m_txs[req.indexes[k]]);
    return resp;
}

void expect_same(const BlockType& got, const BlockType& want) {
    ASSERT_EQ(got.m_txs.size(), want.m_txs.size());
    for (size_t i = 0; i < want.m_txs.size(); ++i)
        EXPECT_EQ(txid(got.m_txs[i]), txid(want.m_txs[i])) << "index " << i;
    EXPECT_EQ(got.m_merkle_root, want.m_merkle_root);
    EXPECT_EQ(got.m_nonce, want.m_nonce);
}

} // namespace

TEST(DashCompactReceive, FullMempoolCompletesWithoutRoundTrip) {
    const BlockType b = mk_block(5);
    CompactBlockReceiver rx(pool_of(b, {1, 2, 3, 4}), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(1));
    ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
    expect_same(vd.block, b);
    EXPECT_EQ(rx.parked_count(), 0u);
}

TEST(DashCompactReceive, NoMempoolRequestsEveryNonPrefilledThenCompletes) {
    const BlockType b = mk_block(4);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(2));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.blockhash, bhash(2));
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{1, 2, 3}));
    EXPECT_TRUE(rx.has_parked(kPeer));

    auto done = rx.on_blocktxn(kPeer, answer(vd.request, b));
    ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
    expect_same(done.block, b);
    EXPECT_FALSE(rx.has_parked(kPeer));
}

TEST(DashCompactReceive, PartialMempoolRequestsOnlyTheGaps) {
    const BlockType b = mk_block(6);
    CompactBlockReceiver rx(pool_of(b, {2, 4}), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(3));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{1, 3, 5}));
    auto done = rx.on_blocktxn(kPeer, answer(vd.request, b));
    ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
    expect_same(done.block, b);
}

// A mempool entry keyed by the real txid but holding a different tx (the
// short-id collision case dashcore catches in CheckBlock) must not be
// accepted: the merkle bind fails and we fall back to the full block.
TEST(DashCompactReceive, PoisonedMempoolFallsBackToFullBlock) {
    const BlockType b = mk_block(3);
    std::vector<std::pair<uint256, v::CTransactionRef>> snap{
        {txid(b.m_txs[1]), v::MakeTransactionRef(mk_tx(999999))},
        {txid(b.m_txs[2]), v::MakeTransactionRef(b.m_txs[2])},
    };
    CompactBlockReceiver rx([snap] { return snap; }, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(4));
    EXPECT_EQ(vd.kind, Kind::FallbackFull) << vd.reason;
    EXPECT_EQ(vd.blockhash, bhash(4));
}

TEST(DashCompactReceive, SubstitutedBlocktxnFallsBackToFullBlock) {
    const BlockType b = mk_block(4);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(5));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    auto resp = answer(vd.request, b);
    resp.txn[1] = v::MakeTransactionRef(mk_tx(123456));
    auto done = rx.on_blocktxn(kPeer, resp);
    EXPECT_EQ(done.kind, Kind::FallbackFull) << done.reason;
    EXPECT_FALSE(rx.has_parked(kPeer));
}

TEST(DashCompactReceive, HeaderMerkleMismatchFallsBackToFullBlock) {
    BlockType b = mk_block(3);
    b.m_merkle_root = uint256::ZERO;
    CompactBlockReceiver rx(pool_of(b, {1, 2}), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(6));
    EXPECT_EQ(vd.kind, Kind::FallbackFull) << vd.reason;
}

TEST(DashCompactReceive, UnrequestedBlocktxnIsIgnored) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    v::BlockTransactions stray;
    stray.blockhash = bhash(7);
    stray.txn.push_back(v::MakeTransactionRef(b.m_txs[1]));
    EXPECT_EQ(rx.on_blocktxn(kPeer, stray).kind, Kind::Ignore);
}

TEST(DashCompactReceive, BlocktxnForOtherHashLeavesParkedBlock) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(8));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    auto wrong = answer(vd.request, b);
    wrong.blockhash = bhash(9);
    EXPECT_EQ(rx.on_blocktxn(kPeer, wrong).kind, Kind::Ignore);
    EXPECT_TRUE(rx.has_parked(kPeer));
    // and a different peer cannot answer for this one
    EXPECT_EQ(rx.on_blocktxn("5.6.7.8:9999", answer(vd.request, b)).kind, Kind::Ignore);
    EXPECT_EQ(rx.on_blocktxn(kPeer, answer(vd.request, b)).kind, Kind::Complete);
}

TEST(DashCompactReceive, ShortBlocktxnIsRejected) {
    const BlockType b = mk_block(4);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(10));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    auto resp = answer(vd.request, b);
    resp.txn.pop_back();
    EXPECT_EQ(rx.on_blocktxn(kPeer, resp).kind, Kind::Reject);
    EXPECT_FALSE(rx.has_parked(kPeer));
}

TEST(DashCompactReceive, DisconnectDropsParkedBlock) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(11));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    rx.on_disconnect(kPeer);
    EXPECT_EQ(rx.parked_count(), 0u);
    EXPECT_EQ(rx.on_blocktxn(kPeer, answer(vd.request, b)).kind, Kind::Ignore);
}

// Wire hop: the cmpctblock the receiver sees came off the socket, so it must
// survive pack/unpack (FillShortTxIDSelector is primed on read).
TEST(DashCompactReceive, DeserializedCmpctblockReassembles) {
    const BlockType b = mk_block(4);
    v::CBlockHeaderAndShortTxIDs sent(b);
    auto ps = pack(sent);
    v::CBlockHeaderAndShortTxIDs got;
    ps >> got;
    CompactBlockReceiver rx(pool_of(b, {1, 3}), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, got, bhash(12));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{2}));
    auto done = rx.on_blocktxn(kPeer, answer(vd.request, b));
    ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
    expect_same(done.block, b);
}
