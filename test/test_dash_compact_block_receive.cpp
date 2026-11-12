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
//
// DashCompactMempool (slice 3) drives the same receiver over a real Mempool
// through make_mempool_short_id_provider; its revert-red arms are listed at
// that section. DashCompactBinding (slice 3b) tears a bound client and its
// Mempool owner down in run_node's declared order.

#include <gtest/gtest.h>

#include <impl/dash/coin/compact_block_receive.hpp>
#include <impl/dash/coin/compact_negotiation.hpp>
#include <impl/dash/coin/compact_mempool_provider.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/vendor/blockencodings.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/dash/crypto/hash_x11.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace dash::coin;
namespace v = dash::coin::vendor;
using Kind = CompactReceiveVerdict::Kind;

namespace {

// The production bound: Dash Core MaxBlockSize() in bytes; InitData divides
// it by MIN_TRANSACTION_SIZE itself.
constexpr size_t kMaxTx = DASH_MAX_BLOCK_SIZE;
const std::string kPeer = "1.2.3.4:9999";

MutableTransaction mk_tx(uint32_t locktime) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = locktime;
    return tx;
}

// A coinbase-shaped tx: one input, one output. Dash Core InitData rejects a
// prefilled tx with neither (CTransaction::IsNull).
MutableTransaction mk_coinbase(uint32_t tag) {
    MutableTransaction tx = mk_tx(tag);
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 500000000 + tag;
    tx.vout.push_back(out);
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
        b.m_txs.push_back(i == 0 ? mk_coinbase(5000) : mk_tx(static_cast<uint32_t>(5000 + i)));
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

// A provider over a fixed (key, tx) list, walked the way the Mempool walks.
v::MempoolShortIdProvider walk_of(std::vector<std::pair<uint256, MutableTransaction>> entries) {
    return [entries](const v::MempoolTxVisitor& visit) {
        for (const auto& [k, tx] : entries)
            if (!visit(k, tx)) return;
    };
}

v::MempoolShortIdProvider pool_of(const BlockType& b, std::vector<size_t> idx) {
    std::vector<std::pair<uint256, MutableTransaction>> snap;
    for (size_t i : idx)
        snap.emplace_back(txid(b.m_txs[i]), b.m_txs[i]);
    return walk_of(std::move(snap));
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
    CompactBlockReceiver rx(walk_of({
        {txid(b.m_txs[1]), mk_tx(999999)},
        {txid(b.m_txs[2]), b.m_txs[2]},
    }), kMaxTx);
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

// L1: a blocktxn whose tx count is not the count we asked for is not an
// answer to our getblocktxn: ignored, never punished, and the park is kept
// (the lost-body watchdog falls back if the right answer never comes).
TEST(DashCompactReceive, ShortBlocktxnIsIgnoredAndKeepsThePark) {
    const BlockType b = mk_block(4);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(10));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    auto resp = answer(vd.request, b);
    resp.txn.pop_back();
    EXPECT_EQ(rx.on_blocktxn(kPeer, resp).kind, Kind::Ignore);
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(10)));
    EXPECT_EQ(rx.on_blocktxn(kPeer, answer(vd.request, b)).kind, Kind::Complete);
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

// ── #968a slice 2: sendcmpct negotiation ───────────────────────────────────
//
// Revert-red arms: drop the version != 1 guard in on_sendcmpct
// (Version2IsIgnored and Version2DoesNotOverwriteVersion1 go red).

TEST(DashCompactNegotiation, UnknownPeerHasNoCompactState) {
    dash::coin::CompactPeerNegotiation n;
    EXPECT_FALSE(n.supports_compact("a"));
    EXPECT_FALSE(n.prefers_compact_announce("a"));
    EXPECT_EQ(n.peer_count(), 0u);
}

TEST(DashCompactNegotiation, Version1LowBandwidthIsRecorded) {
    dash::coin::CompactPeerNegotiation n;
    EXPECT_TRUE(n.on_sendcmpct("a", false, 1));
    EXPECT_TRUE(n.supports_compact("a"));
    EXPECT_TRUE(n.state("a").provides_header_and_ids);
    EXPECT_FALSE(n.prefers_compact_announce("a"));
}

TEST(DashCompactNegotiation, AnnounceFlagFollowsLatestMessage) {
    dash::coin::CompactPeerNegotiation n;
    ASSERT_TRUE(n.on_sendcmpct("a", true, 1));
    EXPECT_TRUE(n.prefers_compact_announce("a"));
    ASSERT_TRUE(n.on_sendcmpct("a", false, 1));
    EXPECT_FALSE(n.prefers_compact_announce("a"));
    EXPECT_TRUE(n.supports_compact("a"));   // latched, not cleared by announce=false
}

TEST(DashCompactNegotiation, Version2IsIgnored) {
    dash::coin::CompactPeerNegotiation n;
    EXPECT_FALSE(n.on_sendcmpct("a", true, 2));
    EXPECT_FALSE(n.supports_compact("a"));
    EXPECT_FALSE(n.prefers_compact_announce("a"));
    EXPECT_EQ(n.peer_count(), 0u);
}

TEST(DashCompactNegotiation, Version2DoesNotOverwriteVersion1) {
    dash::coin::CompactPeerNegotiation n;
    ASSERT_TRUE(n.on_sendcmpct("a", false, 1));
    EXPECT_FALSE(n.on_sendcmpct("a", true, 2));
    EXPECT_TRUE(n.supports_compact("a"));
    EXPECT_FALSE(n.prefers_compact_announce("a"));
}

TEST(DashCompactNegotiation, PeersAreIndependentAndDisconnectClears) {
    dash::coin::CompactPeerNegotiation n;
    ASSERT_TRUE(n.on_sendcmpct("a", true, 1));
    ASSERT_TRUE(n.on_sendcmpct("b", false, 1));
    EXPECT_TRUE(n.prefers_compact_announce("a"));
    EXPECT_FALSE(n.prefers_compact_announce("b"));
    n.on_disconnect("a");
    EXPECT_FALSE(n.supports_compact("a"));
    EXPECT_TRUE(n.supports_compact("b"));
    EXPECT_EQ(n.peer_count(), 1u);
}

// ── #968a slice 3: mempool short-id lookup ──────────────────────────────────
// make_mempool_short_id_provider (compact_mempool_provider.hpp) over a real
// dash::coin::Mempool. Revert-red arms (fresh binary per arm):
//   A provider returns an empty snapshot          -> 6 of 7 red (all but NullMempool...)
//   B snapshot taken when the provider is built   -> TxAdmittedAfter..., Evicted... red
//   C snapshot key is not dash_txid (1 bit flip)  -> 6 of 7 red (all but NullMempool...)
//   D set_mempool_provider does not store         -> SetterArmsAndClears... red

namespace {

uint256 dtxid(const MutableTransaction& tx) { return dash_txid(tx); }

void add_block_txs(Mempool& mp, const BlockType& b, std::vector<size_t> idx) {
    for (size_t i : idx)
        ASSERT_TRUE(mp.add_tx(b.m_txs[i])) << "index " << i;
}

} // namespace

TEST(DashCompactMempool, NullMempoolGivesNullProvider) {
    EXPECT_FALSE(static_cast<bool>(make_mempool_short_id_provider(nullptr)));

    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(make_mempool_short_id_provider(nullptr), kMaxTx);
    EXPECT_FALSE(rx.has_mempool_provider());
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(40));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{1, 2}));
}

TEST(DashCompactMempool, LiveMempoolCompletesWithoutRoundTrip) {
    const BlockType b = mk_block(5);
    Mempool mp;
    add_block_txs(mp, b, {1, 2, 3, 4});
    ASSERT_TRUE(mp.add_tx(mk_tx(9999)));   // in the pool, not in the block

    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(41));
    ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
    expect_same(vd.block, b);
    EXPECT_EQ(rx.parked_count(), 0u);
    EXPECT_EQ(mp.size(), 5u);   // lookup does not consume the pool
}

TEST(DashCompactMempool, PartialMempoolRequestsOnlyTheMissing) {
    const BlockType b = mk_block(5);
    Mempool mp;
    add_block_txs(mp, b, {1, 3});

    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(42));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{2, 4}));

    auto done = rx.on_blocktxn(kPeer, answer(vd.request, b));
    ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
    expect_same(done.block, b);
}

TEST(DashCompactMempool, TxAdmittedAfterProviderIsBuiltIsFound) {
    const BlockType b = mk_block(4);
    Mempool mp;
    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    add_block_txs(mp, b, {1, 2, 3});

    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(43));
    ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
    expect_same(vd.block, b);
}

TEST(DashCompactMempool, EvictedTxIsRequested) {
    const BlockType b = mk_block(4);
    Mempool mp;
    add_block_txs(mp, b, {1, 2, 3});
    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    mp.remove_tx(dtxid(b.m_txs[2]));

    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(44));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{2}));
}

TEST(DashCompactMempool, WalkKeysAreInstanceHashes) {
    Mempool mp;
    std::vector<MutableTransaction> txs{mk_tx(7001), mk_tx(7002), mk_tx(7003)};
    for (const auto& tx : txs) ASSERT_TRUE(mp.add_tx(tx));

    auto provider = make_mempool_short_id_provider(&mp);
    ASSERT_TRUE(static_cast<bool>(provider));
    // The walk holds the pool lock: the visitor must not call back into the
    // Mempool, so membership is checked after it returns.
    std::vector<uint256> keys;
    provider([&](const uint256& key, const MutableTransaction& tx) {
        // The hash Dash Core v24 keys vTxHashes by and the vendored
        // GetShortID is fed: the instance hash, here equal to the txid.
        EXPECT_EQ(key, dash_instance_hash(tx));
        EXPECT_EQ(key, dtxid(tx));
        keys.push_back(key);
        return true;
    });
    EXPECT_EQ(keys.size(), txs.size());
    for (const auto& k : keys) EXPECT_TRUE(mp.contains(k));
}

// The walk stops when the visitor says so (Dash Core's early exit once every
// short id is filled) and copies nothing on its own.
TEST(DashCompactMempool, WalkStopsWhenTheVisitorSaysSo) {
    Mempool mp;
    for (uint32_t i = 0; i < 5; ++i) ASSERT_TRUE(mp.add_tx(mk_tx(7100 + i)));
    auto provider = make_mempool_short_id_provider(&mp);
    size_t seen = 0;
    provider([&](const uint256&, const MutableTransaction&) { return ++seen < 2; });
    EXPECT_EQ(seen, 2u);
}

TEST(DashCompactMempool, SetterArmsAndClearsTheReceiver) {
    const BlockType b = mk_block(4);
    Mempool mp;
    add_block_txs(mp, b, {1, 2, 3});

    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto first = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(45));
    ASSERT_EQ(first.kind, Kind::NeedTxn);
    EXPECT_EQ(first.request.indexes, (std::vector<uint16_t>{1, 2, 3}));

    rx.set_mempool_provider(make_mempool_short_id_provider(&mp));
    EXPECT_TRUE(rx.has_mempool_provider());
    auto second = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(45));
    ASSERT_EQ(second.kind, Kind::Complete) << second.reason;
    expect_same(second.block, b);
    EXPECT_FALSE(rx.has_parked(kPeer));   // the re-announce replaced the park

    rx.set_mempool_provider(nullptr);
    EXPECT_FALSE(rx.has_mempool_provider());
    auto third = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(45));
    ASSERT_EQ(third.kind, Kind::NeedTxn);
    EXPECT_EQ(third.request.indexes, (std::vector<uint16_t>{1, 2, 3}));
}

// ── DashCompactBinding (slice 3b): CompactMempoolBinding teardown ──────────
// run_node (main_dash.cpp) declares coin_p2p, then node_coin_state (which owns
// the Mempool), then cmpct_mempool_binding. Scope exit destroys them in reverse:
// the binding, then node_coin_state, then the scope's coin_p2p ref. coin_p2p
// can outlive the scope: set_lifetime pins it with a strong ref per in-flight
// async op. `pin` below plays that ref. The client is a stand-in with the
// CoinClient surface the binding calls, plus the receiver a cmpctblock reaches.
// Revert-red arms (fresh binary per arm):
//   E ~CompactMempoolBinding does not unbind   -> DeclaredOrderTeardown... red
//     (fails the has_compact_mempool_provider check, then the late cmpctblock
//     reads the freed Mempool: ASan heap-use-after-free, SIGSEGV in a plain
//     build)
//   F unbind does not clear the client         -> DeclaredOrderTeardown...
//     (same use-after-free), UnbindClearsTheClient, RebindMovesTheProvider red
//   G bind does not unbind the previous client -> RebindMovesTheProvider red

namespace {

struct BindingTestClient {
    CompactBlockReceiver rx{nullptr, kMaxTx};
    void set_compact_mempool_provider(v::MempoolShortIdProvider p)
    { rx.set_mempool_provider(std::move(p)); }
    bool has_compact_mempool_provider() const { return rx.has_mempool_provider(); }
};

using Binding = CompactMempoolBinding<BindingTestClient>;

} // namespace

TEST(DashCompactBinding, DeclaredOrderTeardownDetachesBeforeMempoolDies) {
    const BlockType b = mk_block(4);
    std::shared_ptr<BindingTestClient> pin;
    {
        auto coin_p2p = std::make_shared<BindingTestClient>();
        auto node_coin_state = std::make_unique<NodeCoinState>();
        add_block_txs(node_coin_state->mempool(), b, {1, 2, 3});
        Binding cmpct_mempool_binding;
        cmpct_mempool_binding.bind(coin_p2p, node_coin_state->mempool());
        ASSERT_TRUE(cmpct_mempool_binding.bound());
        ASSERT_TRUE(coin_p2p->has_compact_mempool_provider());

        auto live = coin_p2p->rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(46));
        ASSERT_EQ(live.kind, Kind::Complete) << live.reason;
        expect_same(live.block, b);
        pin = coin_p2p;
    }
    // The binding, node_coin_state and the scope's ref are gone, in that
    // order. The pinned client must not reach the freed Mempool.
    ASSERT_EQ(pin.use_count(), 1);
    EXPECT_FALSE(pin->has_compact_mempool_provider());
    auto late = pin->rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(47));
    ASSERT_EQ(late.kind, Kind::NeedTxn);
    EXPECT_EQ(late.request.indexes, (std::vector<uint16_t>{1, 2, 3}));
}

TEST(DashCompactBinding, UnbindClearsTheClient) {
    const BlockType b = mk_block(3);
    Mempool mp;
    add_block_txs(mp, b, {1, 2});
    auto client = std::make_shared<BindingTestClient>();
    Binding binding;
    binding.bind(client, mp);
    ASSERT_TRUE(client->has_compact_mempool_provider());

    binding.unbind();
    EXPECT_FALSE(binding.bound());
    EXPECT_FALSE(client->has_compact_mempool_provider());
    auto vd = client->rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(48));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{1, 2}));
}

TEST(DashCompactBinding, RebindMovesTheProvider) {
    const BlockType b = mk_block(3);
    Mempool mp;
    add_block_txs(mp, b, {1, 2});
    auto first = std::make_shared<BindingTestClient>();
    auto second = std::make_shared<BindingTestClient>();
    Binding binding;
    binding.bind(first, mp);
    binding.bind(second, mp);
    EXPECT_FALSE(first->has_compact_mempool_provider());
    EXPECT_TRUE(second->has_compact_mempool_provider());
    auto vd = second->rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(49));
    ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
}

TEST(DashCompactBinding, NullClientStaysUnbound) {
    Mempool mp;
    Binding binding;
    binding.bind(nullptr, mp);
    EXPECT_FALSE(binding.bound());
}

TEST(DashCompactBinding, ClientGoneFirstIsSafe) {
    Mempool mp;
    Binding binding;
    {
        auto client = std::make_shared<BindingTestClient>();
        binding.bind(client, mp);
        ASSERT_TRUE(binding.bound());
    }
    EXPECT_FALSE(binding.bound());
    binding.unbind();   // nothing to take out; must not touch the freed client
    EXPECT_FALSE(binding.bound());
}

// ── #968a hostile / bound cases at the receiver ─────────────────────────────
//
// Raw cmpctblock bytes, built the way a peer would put them on the wire, so
// the cases the in-memory constructor cannot express (bad prefilled index,
// duplicate short ids, a null prefilled tx) reach InitData exactly as they
// would off the socket. Revert-red arms:
//   bound back to a tx count (m_cmpct_rx{nullptr, 200000})  -> ProductionBound... red
//   drop the prefilled IsNull check in InitData              -> NullPrefilledTx... red
//   drop the short-id collision check                        -> DuplicateShortIds... red

namespace {

v::CBlockHeaderAndShortTxIDs raw_cmpct(const BlockHeaderType& h, uint64_t nonce,
                                       const std::vector<uint64_t>& ids,
                                       const std::vector<std::pair<uint64_t, MutableTransaction>>& prefilled)
{
    PackStream ps;
    ps << h;
    ps << nonce;
    WriteCompactSize(ps, ids.size());
    for (uint64_t id : ids) {
        uint8_t b6[6];
        for (int i = 0; i < 6; ++i) b6[i] = static_cast<uint8_t>((id >> (8 * i)) & 0xff);
        ps.write(std::as_bytes(std::span{b6}));
    }
    WriteCompactSize(ps, prefilled.size());
    for (const auto& [idx, tx] : prefilled) {
        WriteCompactSize(ps, idx);
        ps << tx;
    }
    v::CBlockHeaderAndShortTxIDs out;
    ps >> out;
    return out;
}

BlockHeaderType hdr_of(const BlockType& b) { return static_cast<const BlockHeaderType&>(b); }

} // namespace

// Dash Core passes MaxBlockSize() (2 MB) and divides by MIN_TRANSACTION_SIZE
// (10) inside InitData: 200'000 tx. A block with 20'001 txs is legal on Dash
// (2 MB of ~60-byte txs is ~33k) and must not be refused; the old bound
// (200'000 / 10 = 20'000) refused it as INVALID, i.e. Misbehaving(100) on an
// honest peer.
TEST(DashCompactReceive, ProductionBoundAcceptsMoreThanTwentyThousandTxs) {
    BlockType b;
    b.m_version = 1;
    b.m_bits = 0x1d00ffff;
    b.m_txs.push_back(mk_coinbase(1));
    for (uint32_t i = 0; i < 20001; ++i) b.m_txs.push_back(mk_tx(100000 + i));
    v::CBlockHeaderAndShortTxIDs cmpct(b);
    ASSERT_EQ(cmpct.BlockTxCount(), 20002u);
    CompactBlockReceiver rx(nullptr, DASH_MAX_BLOCK_SIZE);
    auto vd = rx.on_cmpctblock(kPeer, cmpct, bhash(60));
    ASSERT_EQ(vd.kind, Kind::NeedTxn) << vd.reason;
    EXPECT_EQ(vd.request.indexes.size(), 20001u);
}

// The bound is still enforced, in bytes / MIN_TRANSACTION_SIZE.
TEST(DashCompactReceive, TooManyEntriesForTheSizeLimitIsInvalid) {
    const BlockType b = mk_block(11);
    CompactBlockReceiver rx(nullptr, /*max_block_size=*/100);   // 100 / 10 = 10 tx
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(61));
    EXPECT_EQ(vd.kind, Kind::Reject) << vd.reason;
    CompactBlockReceiver ok(nullptr, /*max_block_size=*/110);   // 11 tx fit
    EXPECT_EQ(ok.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(61)).kind, Kind::NeedTxn);
}

TEST(DashCompactReceive, PrefilledIndexPastTheBlockIsInvalid) {
    const BlockType b = mk_block(3);
    // two short ids + one prefilled at differential index 3 -> absolute 3,
    // past shorttxids.size() + 0 = 2: a tx with neither prefill nor short id.
    auto cmpct = raw_cmpct(hdr_of(b), 42, {1, 2}, {{3, b.m_txs[0]}});
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, cmpct, bhash(62));
    EXPECT_EQ(vd.kind, Kind::Reject) << vd.reason;
    EXPECT_FALSE(rx.has_parked(kPeer));
}

TEST(DashCompactReceive, NullPrefilledTxIsInvalid) {
    const BlockType b = mk_block(3);
    auto cmpct = raw_cmpct(hdr_of(b), 42, {1, 2}, {{0, mk_tx(77)}});   // no vin, no vout
    CompactBlockReceiver rx(nullptr, kMaxTx);
    EXPECT_EQ(rx.on_cmpctblock(kPeer, cmpct, bhash(63)).kind, Kind::Reject);
}

TEST(DashCompactReceive, NullHeaderIsInvalid) {
    BlockType b = mk_block(3);
    b.m_bits = 0;   // BlockHeaderType::IsNull
    CompactBlockReceiver rx(nullptr, kMaxTx);
    EXPECT_EQ(rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(64)).kind, Kind::Reject);
}

TEST(DashCompactReceive, EmptyCmpctblockIsInvalid) {
    const BlockType b = mk_block(1);
    auto cmpct = raw_cmpct(hdr_of(b), 42, {}, {});
    CompactBlockReceiver rx(nullptr, kMaxTx);
    EXPECT_EQ(rx.on_cmpctblock(kPeer, cmpct, bhash(65)).kind, Kind::Reject);
}

// Dash Core READ_STATUS_FAILED: duplicate short ids are a collision, not
// misbehaviour; the answer is the full block.
TEST(DashCompactReceive, DuplicateShortIdsFallBackToFullBlock) {
    const BlockType b = mk_block(3);
    auto cmpct = raw_cmpct(hdr_of(b), 42, {0xabcdef, 0xabcdef}, {{0, b.m_txs[0]}});
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, cmpct, bhash(66));
    EXPECT_EQ(vd.kind, Kind::FallbackFull) << vd.reason;
    EXPECT_FALSE(rx.has_parked(kPeer));
}

TEST(DashCompactReceive, OverLongBlocktxnIsIgnoredAndKeepsThePark) {
    const BlockType b = mk_block(4);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(67));
    ASSERT_EQ(vd.kind, Kind::NeedTxn);
    auto resp = answer(vd.request, b);
    resp.txn.push_back(v::MakeTransactionRef(mk_tx(4242)));
    EXPECT_EQ(rx.on_blocktxn(kPeer, resp).kind, Kind::Ignore);
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(67)));
}

// L2: parks are keyed by (peer, block). One peer can have two blocks parked;
// a third evicts that peer's oldest; the overall cap evicts the oldest park.
TEST(DashCompactReceive, ParksAreKeyedByPeerAndBlock) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    auto r1 = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(80));
    auto r2 = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(81));
    ASSERT_EQ(r1.kind, Kind::NeedTxn);
    ASSERT_EQ(r2.kind, Kind::NeedTxn);
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(80)));
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(81)));
    EXPECT_EQ(rx.parked_count(), 2u);
    // Each completes against its own park.
    v::BlockTransactions t2 = answer(r2.request, b);
    EXPECT_EQ(rx.on_blocktxn(kPeer, t2).kind, Kind::Complete);
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(80)));
    EXPECT_EQ(rx.on_blocktxn(kPeer, answer(r1.request, b)).kind, Kind::Complete);
    EXPECT_EQ(rx.parked_count(), 0u);
}

TEST(DashCompactReceive, ParkCapsEvictTheOldest) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    // Per peer: a third block evicts that peer's oldest.
    for (uint8_t i = 0; i < 3; ++i)
        ASSERT_EQ(rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(90 + i)).kind,
                  Kind::NeedTxn);
    EXPECT_EQ(rx.parked_count(), CompactBlockReceiver::MAX_PARKED_PER_PEER);
    EXPECT_FALSE(rx.has_parked(kPeer, bhash(90)));
    EXPECT_TRUE(rx.has_parked(kPeer, bhash(92)));
    // Overall: never more than MAX_PARKED_TOTAL.
    for (int p = 0; p < 10; ++p)
        rx.on_cmpctblock("peer" + std::to_string(p), v::CBlockHeaderAndShortTxIDs(b), bhash(100));
    EXPECT_EQ(rx.parked_count(), CompactBlockReceiver::MAX_PARKED_TOTAL);
    EXPECT_EQ(rx.parked_count_for(bhash(100)), CompactBlockReceiver::MAX_PARKED_TOTAL);
    rx.on_disconnect("peer9");
    EXPECT_EQ(rx.parked_count(), CompactBlockReceiver::MAX_PARKED_TOTAL - 1);
}

TEST(DashCompactReceive, DropBlockClearsEveryPeersPark) {
    const BlockType b = mk_block(3);
    CompactBlockReceiver rx(nullptr, kMaxTx);
    ASSERT_EQ(rx.on_cmpctblock("a", v::CBlockHeaderAndShortTxIDs(b), bhash(68)).kind, Kind::NeedTxn);
    ASSERT_EQ(rx.on_cmpctblock("b", v::CBlockHeaderAndShortTxIDs(b), bhash(68)).kind, Kind::NeedTxn);
    ASSERT_EQ(rx.parked_count_for(bhash(68)), 2u);
    EXPECT_EQ(rx.drop_block(bhash(68)), 2u);
    EXPECT_EQ(rx.parked_count(), 0u);
}

// ── #968a v24: version-2 asset unlocks are matched by INSTANCE hash ─────────
// A re-signed instance of one withdrawal shares the stable txid with the
// pooled one, so a txid-keyed lookup would splice the WRONG instance into the
// block (and fail the CbTx v4 unlock commitment). Keyed by instance hash, the
// block's instance has a short id no pooled tx produces: it is requested.
// Revert-red arm: key the walk by the pool key (dash_txid, the stable txid)
// for every tx -> SameV2AssetUnlockInstanceIsFilledFromThePool goes red (the
// pooled instance no longer matches its own short id and is re-fetched).

namespace {

MutableTransaction mk_unlock_v2(uint8_t sig_tag) {
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 9;   // tx_type::ASSET_UNLOCK
    tx.extra_payload.assign(kAssetUnlockPayloadSize, 0x11);
    tx.extra_payload[0] = 2;   // payload version 2: stable txid
    std::fill(tx.extra_payload.end() - 96, tx.extra_payload.end(), sig_tag);
    TxOut o;
    o.value = 123456;
    tx.vout.push_back(o);
    return tx;
}

BlockType block_with(std::vector<MutableTransaction> txs) {
    BlockType b;
    b.m_version = 1;
    b.m_bits = 0x1d00ffff;
    b.m_timestamp = 1700000000;
    b.m_txs.push_back(mk_coinbase(9));
    for (auto& t : txs) b.m_txs.push_back(std::move(t));
    std::vector<uint256> ids;
    for (const auto& t : b.m_txs) ids.push_back(dash_txid(t));
    b.m_merkle_root = compute_merkle_root(ids);
    return b;
}

} // namespace

TEST(DashCompactMempool, ReSignedV2AssetUnlockIsRequested) {
    const MutableTransaction pooled = mk_unlock_v2(0xaa);
    const MutableTransaction mined = mk_unlock_v2(0xbb);   // re-signed instance
    ASSERT_TRUE(is_asset_unlock_with_stable_txid(pooled));
    ASSERT_EQ(dash_txid(pooled), dash_txid(mined));
    ASSERT_NE(dash_instance_hash(pooled), dash_instance_hash(mined));

    Mempool mp;
    ASSERT_TRUE(mp.add_tx(pooled) || mp.add_tx_skipping_contextual_check_for_test(pooled));
    const MutableTransaction plain = mk_tx(8801);
    ASSERT_TRUE(mp.add_tx(plain));

    const BlockType b = block_with({plain, mined});
    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(70));
    ASSERT_EQ(vd.kind, Kind::NeedTxn) << vd.reason;
    EXPECT_EQ(vd.request.indexes, (std::vector<uint16_t>{2}))
        << "the plain tx comes from the pool, the re-signed unlock is requested";
    auto done = rx.on_blocktxn(kPeer, answer(vd.request, b));
    ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
    EXPECT_EQ(dash_instance_hash(done.block.m_txs[2]), dash_instance_hash(mined));
}

TEST(DashCompactMempool, SameV2AssetUnlockInstanceIsFilledFromThePool) {
    const MutableTransaction pooled = mk_unlock_v2(0xaa);
    Mempool mp;
    ASSERT_TRUE(mp.add_tx(pooled) || mp.add_tx_skipping_contextual_check_for_test(pooled));
    const BlockType b = block_with({pooled});
    CompactBlockReceiver rx(make_mempool_short_id_provider(&mp), kMaxTx);
    auto vd = rx.on_cmpctblock(kPeer, v::CBlockHeaderAndShortTxIDs(b), bhash(71));
    ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
    EXPECT_EQ(dash_instance_hash(vd.block.m_txs[1]), dash_instance_hash(pooled));
}

// ── #968a: the cmpctblock gate (solicited only) ─────────────────────────────

TEST(DashCompactGate, DecisionTable) {
    using G = CompactGate;
    CompactGateFacts ok;
    ok.requested = ok.header_known = ok.more_work = ok.near_tip = true;

    auto with = [&](auto f) { CompactGateFacts x = ok; f(x); return compact_gate(x); };

    EXPECT_EQ(compact_gate(ok), G::Reconstruct);
    // Not our request: ignored whatever else is true. Nothing is fed anywhere.
    EXPECT_EQ(with([](auto& x) { x.requested = false; }), G::Ignore);
    EXPECT_EQ(compact_gate(CompactGateFacts{}), G::Ignore);
    // Our request, but the header did not come through getheaders yet.
    EXPECT_EQ(with([](auto& x) { x.header_known = false; }), G::FetchFull);
    EXPECT_EQ(with([](auto& x) { x.have_body = true; }), G::Drop);
    EXPECT_EQ(with([](auto& x) { x.more_work = false; }), G::FetchFull);
    EXPECT_EQ(with([](auto& x) { x.near_tip = false; }), G::FetchFull);
}

// ── #968a GOLDEN VECTOR: a real Dash testnet cmpctblock ─────────────────────
// fixtures/dash_testnet_cmpctblock_1590326.txt: captured from a Dash Core
// v24.0.0 testnet node over P2P (we sent sendcmpct(1,1), it pushed this
// cmpctblock for block 1590326; we then asked for the same block with
// getdata(MSG_CMPCT_BLOCK) and for every non-prefilled tx with getblocktxn).
// Checks our codec, our X11 block identity, our SipHash keys and short ids
// (over dash_instance_hash) and both reassembly paths against dashd's bytes.

namespace {

std::map<std::string, std::string> load_fixture(const std::string& name) {
    std::map<std::string, std::string> kv;
    std::ifstream f(std::string(DASH_FIXTURE_DIR) + "/" + name);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq != std::string::npos) kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return kv;
}

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

template <typename T>
T unpack_bytes(const std::vector<unsigned char>& bytes) {
    PackStream ps(bytes);
    T out;
    ps >> out;
    return out;
}

std::vector<unsigned char> bytes_of(PackStream ps) {
    auto sp = ps.get_span();
    const auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

// The 6-byte short ids straight off the wire (offset 88: header + nonce).
std::vector<uint64_t> wire_short_ids(const std::vector<unsigned char>& raw) {
    PackStream ps(std::vector<unsigned char>(raw.begin() + 88, raw.end()));
    const uint64_t n = ReadCompactSize(ps);
    std::vector<uint64_t> ids;
    for (uint64_t i = 0; i < n; ++i) {
        uint8_t b6[6];
        ps.read(std::as_writable_bytes(std::span{b6}));
        uint64_t v = 0;
        for (int k = 0; k < 6; ++k) v |= static_cast<uint64_t>(b6[k]) << (8 * k);
        ids.push_back(v);
    }
    return ids;
}

} // namespace

TEST(DashCompactGolden, TestnetBlock1590326FromDashCoreV24) {
    auto fx = load_fixture("dash_testnet_cmpctblock_1590326.txt");
    ASSERT_FALSE(fx["block"].empty()) << "fixture missing";
    const auto raw_block = unhex(fx["block"]);
    const auto raw_pushed = unhex(fx["pushed_cmpctblock"]);
    const auto raw_asked = unhex(fx["getdata_cmpctblock"]);
    const auto raw_txn = unhex(fx["blocktxn"]);
    const size_t ntx = std::stoul(fx["ntx"]);

    const BlockType block = unpack_bytes<BlockType>(raw_block);
    ASSERT_EQ(block.m_txs.size(), ntx);
    auto hp = pack(static_cast<const BlockHeaderType&>(block));
    const uint256 hash = dash::crypto::hash_x11(hp.get_span());
    EXPECT_EQ(hash.GetHex(), fx["hash"]) << "X11 block identity";
    EXPECT_TRUE(block_body_binds_to_header(block));
    // The full block round-trips byte-exact through our codec.
    EXPECT_EQ(bytes_of(pack(block)), raw_block);

    for (const auto* raw : {&raw_pushed, &raw_asked}) {
        const auto cmpct = unpack_bytes<v::CBlockHeaderAndShortTxIDs>(*raw);
        // Codec: byte-exact round trip, header identical to the block's.
        EXPECT_EQ(bytes_of(pack(cmpct)), *raw);
        EXPECT_EQ(bytes_of(pack(cmpct.header)), bytes_of(hp));
        ASSERT_EQ(cmpct.BlockTxCount(), ntx);

        // SipHash keys (SHA256(header || nonce)) and short ids over the
        // instance hash: ours must equal dashd's for every non-prefilled tx
        // (dashd prefills only the coinbase).
        const auto ids = wire_short_ids(*raw);
        ASSERT_EQ(ids.size(), ntx - 1);
        for (size_t i = 1; i < ntx; ++i)
            EXPECT_EQ(cmpct.GetShortID(dash_instance_hash(block.m_txs[i])), ids[i - 1])
                << "short id of tx " << i;
    }
    // The pushed one also matches the Python recomputation in the fixture.
    {
        const auto ids = wire_short_ids(raw_pushed);
        std::string joined;
        for (uint64_t id : ids) {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%012llx", static_cast<unsigned long long>(id));
            if (!joined.empty()) joined += ",";
            joined += buf;
        }
        EXPECT_EQ(joined, fx["wire_shortids"]);
    }

    // Reassembly from a full mempool: no round trip, byte-identical block.
    std::vector<std::pair<uint256, MutableTransaction>> pool;
    for (size_t i = 1; i < ntx; ++i) pool.emplace_back(dash_instance_hash(block.m_txs[i]), block.m_txs[i]);
    {
        CompactBlockReceiver rx(walk_of(pool), DASH_MAX_BLOCK_SIZE);
        auto vd = rx.on_cmpctblock(kPeer, unpack_bytes<v::CBlockHeaderAndShortTxIDs>(raw_pushed), hash);
        ASSERT_EQ(vd.kind, Kind::Complete) << vd.reason;
        EXPECT_EQ(bytes_of(pack(vd.block)), raw_block);
    }
    // Reassembly from an empty mempool + dashd's own blocktxn answer.
    {
        CompactBlockReceiver rx(nullptr, DASH_MAX_BLOCK_SIZE);
        auto vd = rx.on_cmpctblock(kPeer, unpack_bytes<v::CBlockHeaderAndShortTxIDs>(raw_asked), hash);
        ASSERT_EQ(vd.kind, Kind::NeedTxn) << vd.reason;
        ASSERT_EQ(vd.request.indexes.size(), ntx - 1);
        const auto txn = unpack_bytes<v::BlockTransactions>(raw_txn);
        EXPECT_EQ(txn.blockhash, hash);
        EXPECT_EQ(bytes_of(pack(txn)), raw_txn);
        auto done = rx.on_blocktxn(kPeer, txn);
        ASSERT_EQ(done.kind, Kind::Complete) << done.reason;
        EXPECT_EQ(bytes_of(pack(done.block)), raw_block);
    }
    // Our own getblocktxn for the same indexes encodes the way dashd decoded
    // it (differential indexes): it answered with exactly these txs.
    {
        v::BlockTransactionsRequest req;
        req.blockhash = hash;
        for (size_t i = 1; i < ntx; ++i) req.indexes.push_back(static_cast<uint16_t>(i));
        const auto back = unpack_bytes<v::BlockTransactionsRequest>(bytes_of(pack(req)));
        EXPECT_EQ(back.indexes, req.indexes);
    }
}
