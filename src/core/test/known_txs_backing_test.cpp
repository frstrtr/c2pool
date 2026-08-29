// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the coin-generic share-broadcast completeness gate and the
// mark-after-send de-dup rule (core/known_txs_backing.hpp).
//
// Both are reward-path: a share we broadcast without the bytes of a referenced
// new tx gets us dropped by canonical p2pool ("referenced unknown transaction",
// p2p.py:404) -> sharechain isolation -> orphaned shares; and a share marked
// "already broadcast" that was never actually written is never re-pushed, which
// is the same loss with no log line to find it by.
//
// Folded into the EXISTING allowlisted core_test target rather than a new
// add_executable: a standalone target is absent from build.yml's --target list,
// so CI would never build it and CTest would report the cases "Not Run" (the
// #769 trap). One KAT covers every coin because all node lanes consume this one
// shared helper.

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <vector>

#include <core/known_txs_backing.hpp>

namespace {

using KnownTxs = std::map<uint256, int>;  // hash -> stand-in "tx bytes"

uint256 H(uint64_t n) { return uint256(n); }

// Minimal stand-in for a share on the broadcast path: an identity plus the list
// of new txs it references.
struct FakeShare {
    uint256 hash;
    std::vector<uint256> new_txs;
};

const std::vector<uint256>* tx_hashes_of(FakeShare& s) { return &s.new_txs; }

// The exact shape of NodeImpl::send_shares' contract: gate the batch, then
// report the hashes that reached the wire. `peer_writable` models the early
// returns (tracker-lock miss, zero peers) that abandon the whole batch.
std::vector<uint256> send_shares_model(std::vector<FakeShare> batch,
                                       const KnownTxs& held,
                                       bool peer_writable,
                                       std::size_t* skipped_out = nullptr)
{
    if (!peer_writable)
        return {};  // abandoned before any write
    if (batch.empty())
        return {};

    const std::size_t skipped =
        core::retain_backable_shares(batch, tx_hashes_of, held);
    if (skipped_out)
        *skipped_out = skipped;
    if (batch.empty())
        return {};

    std::vector<uint256> sent;
    for (const auto& s : batch)
        sent.push_back(s.hash);
    return sent;
}

// ---------------------------------------------------------------- F3 gate ---

TEST(KnownTxsBacking, EmptyTxListIsTriviallyBackable)
{
    KnownTxs held;
    EXPECT_TRUE(core::all_txs_backable({}, held));
}

TEST(KnownTxsBacking, AllHeldIsBackable)
{
    KnownTxs held{{H(1), 1}, {H(2), 2}, {H(3), 3}};
    EXPECT_TRUE(core::all_txs_backable({H(1), H(3)}, held));
}

TEST(KnownTxsBacking, OneMissingTxMakesTheWholeShareUnbackable)
{
    KnownTxs held{{H(1), 1}, {H(2), 2}};
    // H(9) is not held: canonical would drop the connection over it, so the
    // whole share is unbackable even though the other two txs are fine.
    EXPECT_FALSE(core::all_txs_backable({H(1), H(9), H(2)}, held));
}

TEST(KnownTxsBacking, UnbackableShareIsNotBroadcast)
{
    // THE regression: before the gate existed, an unheld referenced tx was
    // silently omitted from remember_tx and the share was sent anyway.
    KnownTxs held{{H(1), 1}};
    std::vector<FakeShare> batch{{H(100), {H(1), H(2)}}};  // H(2) not held

    std::size_t skipped = 0;
    auto sent = send_shares_model(batch, held, /*peer_writable=*/true, &skipped);

    EXPECT_EQ(skipped, 1u);
    EXPECT_TRUE(sent.empty()) << "a share referencing an unheld tx must not be "
                                 "put on the wire";
}

TEST(KnownTxsBacking, GateFiltersPerShareAndKeepsTheBackableTip)
{
    // One unbackable ancestor must not suppress the backable tip — the tip is
    // the share our PPLNS credit depends on.
    KnownTxs held{{H(1), 1}};
    std::vector<FakeShare> batch{
        {H(100), {H(1)}},        // backable
        {H(101), {H(7)}},        // NOT backable
        {H(102), {}},            // no new txs -> trivially backable
    };

    std::size_t skipped = 0;
    auto sent = send_shares_model(batch, held, /*peer_writable=*/true, &skipped);

    EXPECT_EQ(skipped, 1u);
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[0], H(100));
    EXPECT_EQ(sent[1], H(102));  // order preserved
}

TEST(KnownTxsBacking, GateReleasesTheShareOnceItsTxsArrive)
{
    KnownTxs held;
    std::vector<FakeShare> batch{{H(100), {H(2)}}};

    EXPECT_TRUE(send_shares_model(batch, held, true).empty());

    held.emplace(H(2), 2);  // peer remember_tx delivers the bytes
    auto sent = send_shares_model(batch, held, true);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0], H(100));
}

// --------------------------------------------------- F2 mark-after-send ---

TEST(KnownTxsBacking, AbandonedBatchIsNotMarkedBroadcast)
{
    // THE regression: the de-dup set used to be advanced during the chain walk,
    // BEFORE send_shares ran. Every early return in send_shares then left a
    // share marked "already broadcast" that had never been written to a socket,
    // and the next walk breaks on that mark — permanently orphaned, no retry.
    KnownTxs held{{H(1), 1}};
    std::vector<FakeShare> batch{{H(100), {H(1)}}};
    std::set<uint256> shared_share_hashes;

    // Batch abandoned (tracker-lock miss / no peers): nothing written.
    auto sent = send_shares_model(batch, held, /*peer_writable=*/false);
    core::commit_broadcast_marks(shared_share_hashes, sent);

    EXPECT_TRUE(sent.empty());
    EXPECT_EQ(shared_share_hashes.count(H(100)), 0u)
        << "an abandoned batch must stay unmarked so the next cycle retries it";

    // Next cycle succeeds -> now, and only now, it is marked.
    sent = send_shares_model(batch, held, /*peer_writable=*/true);
    core::commit_broadcast_marks(shared_share_hashes, sent);
    EXPECT_EQ(shared_share_hashes.count(H(100)), 1u);
}

TEST(KnownTxsBacking, ZeroPeersMarksNothing)
{
    // broadcast_share with an empty peer map: the loop body never runs, so no
    // hash is reported sent and nothing may be marked.
    std::set<uint256> shared_share_hashes;
    std::vector<uint256> actually_sent;  // union over zero peers
    core::commit_broadcast_marks(shared_share_hashes, actually_sent);
    EXPECT_TRUE(shared_share_hashes.empty());
}

TEST(KnownTxsBacking, OnlyTheGatedSubsetIsMarked)
{
    KnownTxs held{{H(1), 1}};
    std::vector<FakeShare> batch{
        {H(100), {H(1)}},   // sent
        {H(101), {H(7)}},   // gated out
    };
    std::set<uint256> shared_share_hashes;

    auto sent = send_shares_model(batch, held, true);
    core::commit_broadcast_marks(shared_share_hashes, sent);

    EXPECT_EQ(shared_share_hashes.count(H(100)), 1u);
    EXPECT_EQ(shared_share_hashes.count(H(101)), 0u)
        << "a share the gate withheld must be retried, not retired";
}

TEST(KnownTxsBacking, MarksAreTheUnionAcrossPeers)
{
    // broadcast_share unions the per-peer reports: reaching >= 1 peer is enough
    // to consider a share broadcast.
    std::set<uint256> shared_share_hashes;
    core::commit_broadcast_marks(shared_share_hashes, {});          // peer A: nothing
    core::commit_broadcast_marks(shared_share_hashes, {H(100)});    // peer B: sent
    EXPECT_EQ(shared_share_hashes.count(H(100)), 1u);
    EXPECT_EQ(shared_share_hashes.size(), 1u);
}

} // namespace
