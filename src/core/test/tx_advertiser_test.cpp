// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <set>
#include <vector>

#include <core/tx_advertiser.hpp>
#include <core/uint256.hpp>

// KATs for core::run_tx_advert / plan_tx_advert — the SEND side of the p2pool
// `have_tx` / `losing_tx` tx-pool advertisement that c2pool never implemented
// (receive-only in every coin, so canonical p2pool dashboards rendered every
// c2pool node with txpool = 0).
//
// The helper is coin-agnostic on purpose: DASH wires it first, LTC/DGB/BCH/BTC
// follow, and all five consume this one implementation — so one KAT covers the
// delta semantics for every coin. Advert-only; nothing here is consensus state.
//
// Canonical semantics under test (p2pool python, p2pool/p2p.py):
//   p2p.py:276      full have_tx immediately after the version handshake
//   p2p.py:243-248  known_txs added   -> have_tx(added)
//   p2p.py:250-259  known_txs removed -> losing_tx(removed)
//   p2p.py:261-274  transitioned      -> have_tx(added) THEN losing_tx(removed)
//   p2p.py:494-495  receiver truncates its view at 10000 hashes (our chunk cap)

using core::chunk_tx_hashes;
using core::plan_tx_advert;
using core::run_tx_advert;
using core::TxAdvertPlan;
using core::TxAdvertState;

namespace {

uint256 H(uint64_t i) { return uint256(i); }

std::set<uint256> hashes(uint64_t first, uint64_t last)
{
    std::set<uint256> s;
    for (uint64_t i = first; i <= last; ++i)
        s.insert(H(i));
    return s;
}

// Records exactly what would go on the wire, in order.
struct Wire
{
    enum class Kind { have, losing };
    struct Msg { Kind kind; std::vector<uint256> hashes; };
    std::vector<Msg> msgs;

    auto have_fn() { return [this](const std::vector<uint256>& h) { msgs.push_back({Kind::have, h}); }; }
    auto losing_fn() { return [this](const std::vector<uint256>& h) { msgs.push_back({Kind::losing, h}); }; }

    size_t count(Kind k) const
    {
        size_t n = 0;
        for (const auto& m : msgs) if (m.kind == k) ++n;
        return n;
    }
    std::vector<uint256> all(Kind k) const
    {
        std::vector<uint256> out;
        for (const auto& m : msgs)
            if (m.kind == k) out.insert(out.end(), m.hashes.begin(), m.hashes.end());
        return out;
    }
};

TxAdvertPlan sweep(TxAdvertState& st, const std::set<uint256>& current, Wire& w,
                   size_t cap = core::TX_ADVERT_MAX_HASHES_PER_MESSAGE)
{
    return run_tx_advert(st, current, w.have_fn(), w.losing_fn(), cap);
}

} // namespace

// p2p.py:276 — the handshake advert carries the FULL current known-tx set.
TEST(TxAdvertiser, FirstAdvertSendsEverything)
{
    TxAdvertState st;
    Wire w;
    const auto current = hashes(1, 5);

    auto plan = sweep(st, current, w);

    EXPECT_EQ(plan.m_have.size(), 5u);
    EXPECT_TRUE(plan.m_losing.empty());
    EXPECT_EQ(w.count(Wire::Kind::have), 1u);
    EXPECT_EQ(w.count(Wire::Kind::losing), 0u);
    EXPECT_EQ(w.all(Wire::Kind::have).size(), 5u);
    EXPECT_EQ(st.m_advertised, current);
    EXPECT_TRUE(st.m_initial_sent);
}

// p2p.py:276 is UNCONDITIONAL — a node with an empty tx pool still announces
// once, so the peer's view is explicitly established rather than assumed.
TEST(TxAdvertiser, FirstAdvertOnEmptyPoolStillSendsExactlyOneMessage)
{
    TxAdvertState st;
    Wire w;

    auto plan = sweep(st, std::set<uint256>{}, w);

    EXPECT_TRUE(plan.empty());
    ASSERT_EQ(w.msgs.size(), 1u);
    EXPECT_EQ(w.msgs[0].kind, Wire::Kind::have);
    EXPECT_TRUE(w.msgs[0].hashes.empty());
    EXPECT_TRUE(st.m_initial_sent);

    // ...and the very next sweep, still empty, sends NOTHING.
    Wire w2;
    sweep(st, std::set<uint256>{}, w2);
    EXPECT_TRUE(w2.msgs.empty());
}

// The whole point of the per-peer advertised set: a re-sweep over an unchanged
// pool puts nothing on the wire. Without this the 10s timer would re-broadcast
// the entire pool six times a minute to every peer.
TEST(TxAdvertiser, UnchangedPoolSendsNothing)
{
    TxAdvertState st;
    Wire w;
    const auto current = hashes(1, 100);

    sweep(st, current, w);
    ASSERT_EQ(w.msgs.size(), 1u);

    for (int i = 0; i < 5; ++i) {
        Wire again;
        auto plan = sweep(st, current, again);
        EXPECT_TRUE(plan.empty());
        EXPECT_TRUE(again.msgs.empty());
    }
}

// p2p.py:243-248 — the second advert carries ONLY what is new.
TEST(TxAdvertiser, SecondAdvertSendsOnlyTheDelta)
{
    TxAdvertState st;
    Wire w0;
    sweep(st, hashes(1, 5), w0);

    Wire w;
    auto plan = sweep(st, hashes(1, 8), w);

    ASSERT_EQ(plan.m_have.size(), 3u);
    EXPECT_TRUE(plan.m_losing.empty());
    const auto sent = w.all(Wire::Kind::have);
    ASSERT_EQ(sent.size(), 3u);
    const std::set<uint256> sent_set(sent.begin(), sent.end());
    EXPECT_EQ(sent_set, hashes(6, 8));
}

// Eviction retraction: hashes that left the known-tx pool (bounded oldest-first
// eviction on LTC/DGB/BCH/BTC, template-window retention on DASH) are retracted
// with losing_tx and are NOT re-sent as have_tx.
TEST(TxAdvertiser, EvictionEmitsLosingTx)
{
    TxAdvertState st;
    Wire w0;
    sweep(st, hashes(1, 10), w0);

    Wire w;
    auto plan = sweep(st, hashes(6, 10), w); // 1..5 evicted

    EXPECT_TRUE(plan.m_have.empty());
    ASSERT_EQ(plan.m_losing.size(), 5u);
    EXPECT_EQ(w.count(Wire::Kind::have), 0u);
    ASSERT_EQ(w.count(Wire::Kind::losing), 1u);
    const auto lost = w.all(Wire::Kind::losing);
    EXPECT_EQ(std::set<uint256>(lost.begin(), lost.end()), hashes(1, 5));
    EXPECT_EQ(st.m_advertised, hashes(6, 10));
}

// p2p.py:261-274 (transitioned): additions go out BEFORE retractions, so a peer
// that re-learns a hash in the same sweep never ends up with it retracted.
TEST(TxAdvertiser, MixedDeltaSendsHaveBeforeLosing)
{
    TxAdvertState st;
    Wire w0;
    sweep(st, hashes(1, 5), w0);

    Wire w;
    auto plan = sweep(st, hashes(4, 9), w); // drop 1..3, add 6..9

    ASSERT_EQ(w.msgs.size(), 2u);
    EXPECT_EQ(w.msgs[0].kind, Wire::Kind::have);
    EXPECT_EQ(w.msgs[1].kind, Wire::Kind::losing);
    EXPECT_EQ(std::set<uint256>(w.msgs[0].hashes.begin(), w.msgs[0].hashes.end()), hashes(6, 9));
    EXPECT_EQ(std::set<uint256>(w.msgs[1].hashes.begin(), w.msgs[1].hashes.end()), hashes(1, 3));
}

// No hash is ever advertised twice across a long run of sweeps, and a hash that
// is retracted and later re-learned IS advertised again (exactly once more).
TEST(TxAdvertiser, NothingAdvertisedTwiceAndReLearnReAdvertises)
{
    TxAdvertState st;
    std::vector<uint256> ever_advertised;

    auto record = [&](Wire& w) {
        for (const auto& h : w.all(Wire::Kind::have))
            ever_advertised.push_back(h);
    };

    Wire a; sweep(st, hashes(1, 4), a); record(a);
    Wire b; sweep(st, hashes(1, 4), b); record(b);   // no change
    Wire c; sweep(st, hashes(3, 6), c); record(c);   // drop 1,2 add 5,6
    Wire d; sweep(st, hashes(3, 6), d); record(d);   // no change

    // 1,2,3,4 then 5,6 — six adverts, no duplicates.
    EXPECT_EQ(ever_advertised.size(), 6u);
    EXPECT_EQ(std::set<uint256>(ever_advertised.begin(), ever_advertised.end()).size(), 6u);

    // Re-learn hash 1 (evicted at sweep c): it must be advertised again.
    Wire e; sweep(st, hashes(1, 6), e); record(e);
    const auto again = e.all(Wire::Kind::have);
    ASSERT_EQ(again.size(), 2u);
    EXPECT_EQ(std::set<uint256>(again.begin(), again.end()), hashes(1, 2));
    EXPECT_EQ(ever_advertised.size(), 8u);
}

// Wire bound: a pool at exactly the cap is one message; cap+1 is two, and the
// split is complete and non-overlapping (canonical fragments instead, p2p.py:230).
TEST(TxAdvertiser, ChunkBoundaryExactAndOverflow)
{
    constexpr size_t cap = 4;

    {
        TxAdvertState st;
        Wire w;
        sweep(st, hashes(1, cap), w, cap);
        ASSERT_EQ(w.msgs.size(), 1u);
        EXPECT_EQ(w.msgs[0].hashes.size(), cap);
    }
    {
        TxAdvertState st;
        Wire w;
        sweep(st, hashes(1, cap + 1), w, cap);
        ASSERT_EQ(w.msgs.size(), 2u);
        EXPECT_EQ(w.msgs[0].hashes.size(), cap);
        EXPECT_EQ(w.msgs[1].hashes.size(), 1u);
        const auto all = w.all(Wire::Kind::have);
        EXPECT_EQ(std::set<uint256>(all.begin(), all.end()), hashes(1, cap + 1));
    }
    {
        // Retractions chunk on the same bound.
        TxAdvertState st;
        Wire w0;
        sweep(st, hashes(1, 9), w0, cap);
        Wire w;
        sweep(st, std::set<uint256>{}, w, cap);
        EXPECT_EQ(w.count(Wire::Kind::have), 0u);
        EXPECT_EQ(w.count(Wire::Kind::losing), 3u); // 4 + 4 + 1
        EXPECT_EQ(w.all(Wire::Kind::losing).size(), 9u);
    }
}

// The default cap is the canonical receive-side truncation bound (p2p.py:494),
// so we never emit a message a canonical peer could not fully retain, and the
// payload stays ~320 KB — far under canonical's 3 MiB max_payload (p2p.py:41).
TEST(TxAdvertiser, DefaultChunkCapMatchesCanonicalReceiverBound)
{
    EXPECT_EQ(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE, 10000u);
    EXPECT_LE(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE * 32u, 3145728u);
    EXPECT_EQ(core::TX_ADVERT_INTERVAL_SECONDS, 10);
}

// chunk_tx_hashes never yields an empty chunk — an empty delta must produce no
// message at all (canonical `if added:` / `if removed:` guards).
TEST(TxAdvertiser, ChunkingNeverEmitsEmptyChunks)
{
    EXPECT_TRUE(chunk_tx_hashes({}, 10).empty());
    const std::vector<uint256> one{H(1)};
    const auto c = chunk_tx_hashes(one, 10);
    ASSERT_EQ(c.size(), 1u);
    EXPECT_EQ(c[0].size(), 1u);
}

// plan_tx_advert is pure: it must not mutate the state it inspects.
TEST(TxAdvertiser, PlanIsPure)
{
    TxAdvertState st;
    st.m_advertised = hashes(1, 3);
    st.m_initial_sent = true;

    const auto plan = plan_tx_advert(st, hashes(2, 5));

    EXPECT_EQ(st.m_advertised, hashes(1, 3));
    EXPECT_TRUE(st.m_initial_sent);
    EXPECT_EQ(std::set<uint256>(plan.m_have.begin(), plan.m_have.end()), hashes(4, 5));
    ASSERT_EQ(plan.m_losing.size(), 1u);
    EXPECT_EQ(plan.m_losing[0], H(1));
}
