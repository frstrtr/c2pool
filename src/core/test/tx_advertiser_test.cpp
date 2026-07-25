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

// p2p.py:261-274 (transitioned): additions go out BEFORE retractions. With the
// one-message-per-sweep bound this becomes "adds this sweep, retractions the
// next" — the ordering canonical guarantees is preserved across sweeps.
TEST(TxAdvertiser, MixedDeltaSendsHaveBeforeLosing)
{
    TxAdvertState st;
    Wire w0;
    sweep(st, hashes(1, 5), w0);

    Wire a;
    sweep(st, hashes(4, 9), a); // drop 1..3, add 6..9
    ASSERT_EQ(a.msgs.size(), 1u);
    EXPECT_EQ(a.msgs[0].kind, Wire::Kind::have);
    EXPECT_EQ(std::set<uint256>(a.msgs[0].hashes.begin(), a.msgs[0].hashes.end()), hashes(6, 9));

    Wire b;
    sweep(st, hashes(4, 9), b);
    ASSERT_EQ(b.msgs.size(), 1u);
    EXPECT_EQ(b.msgs[0].kind, Wire::Kind::losing);
    EXPECT_EQ(std::set<uint256>(b.msgs[0].hashes.begin(), b.msgs[0].hashes.end()), hashes(1, 3));

    Wire c;
    sweep(st, hashes(4, 9), c);
    EXPECT_TRUE(c.msgs.empty());
}

// No hash is ever advertised twice across a long run of sweeps, and a hash that
// is retracted and later re-learned IS advertised again (exactly once more).
// Each state is swept to quiescence so the one-message-per-sweep budget does not
// hide an outstanding delta.
TEST(TxAdvertiser, NothingAdvertisedTwiceAndReLearnReAdvertises)
{
    TxAdvertState st;
    std::vector<uint256> ever_advertised;

    // Sweep `pool` until nothing more is emitted, recording every have_tx hash.
    auto drain = [&](const std::set<uint256>& pool) {
        for (int i = 0; i < 20; ++i) {
            Wire w;
            sweep(st, pool, w);
            if (w.msgs.empty())
                return;
            ASSERT_EQ(w.msgs.size(), 1u);
            for (const auto& h : w.all(Wire::Kind::have))
                ever_advertised.push_back(h);
        }
        FAIL() << "advert never reached quiescence";
    };

    drain(hashes(1, 4));   // advertise 1,2,3,4
    drain(hashes(1, 4));   // no change -> nothing
    drain(hashes(3, 6));   // drop 1,2 (losing_tx); add 5,6
    drain(hashes(3, 6));   // no change -> nothing

    EXPECT_EQ(ever_advertised.size(), 6u);
    EXPECT_EQ(std::set<uint256>(ever_advertised.begin(), ever_advertised.end()).size(), 6u);
    EXPECT_EQ(st.m_advertised, hashes(3, 6));

    // Re-learn 1,2 (retracted above): they must be advertised again.
    drain(hashes(1, 6));
    EXPECT_EQ(ever_advertised.size(), 8u);
    EXPECT_EQ(st.m_advertised, hashes(1, 6));
}

// Write-safety bound: a sweep emits AT MOST ONE message. core::Socket::write has
// no outbound queue (socket.cpp:110-137), so a chunk burst would overlap composed
// async_writes and interleave bytes mid-message -> bad checksum -> the canonical
// peer drops us. Over-budget hashes are NOT committed; they resurface next sweep.
TEST(TxAdvertiser, OneMessagePerSweepAndCommitsOnlyWhatWasEmitted)
{
    constexpr size_t budget = 4;
    TxAdvertState st;
    Wire w;

    sweep(st, hashes(1, 10), w, budget);

    // Exactly one message, exactly `budget` hashes.
    ASSERT_EQ(w.msgs.size(), 1u);
    EXPECT_EQ(w.msgs[0].kind, Wire::Kind::have);
    EXPECT_EQ(w.msgs[0].hashes.size(), budget);
    // ...and ONLY those are recorded as advertised — committing the un-sent
    // remainder would be a permanent per-peer desync.
    EXPECT_EQ(st.m_advertised.size(), budget);
    for (const auto& h : w.msgs[0].hashes)
        EXPECT_TRUE(st.m_advertised.count(h));
}

// The remainder is carried by the FOLLOWING sweeps until the pool converges,
// with no hash sent twice and none dropped.
TEST(TxAdvertiser, RemainderIsAdvertisedOnSubsequentSweeps)
{
    constexpr size_t budget = 4;
    TxAdvertState st;
    const auto pool = hashes(1, 10);

    std::vector<uint256> ever;
    size_t sweeps = 0;
    for (; sweeps < 20; ++sweeps) {
        Wire w;
        sweep(st, pool, w, budget);
        if (w.msgs.empty())
            break;
        ASSERT_EQ(w.msgs.size(), 1u); // never more than one message per sweep
        EXPECT_LE(w.msgs[0].hashes.size(), budget);
        for (const auto& h : w.msgs[0].hashes)
            ever.push_back(h);
    }

    // ceil(10/4) = 3 sweeps of adverts, then a 4th that emits nothing.
    EXPECT_EQ(sweeps, 3u);
    EXPECT_EQ(ever.size(), 10u);
    EXPECT_EQ(std::set<uint256>(ever.begin(), ever.end()), pool); // complete, no dupes
    EXPECT_EQ(st.m_advertised, pool);
}

// Retractions are budgeted the same way, and additions always drain FIRST
// (canonical have-before-losing, p2p.py:264-267) — so a sweep never emits a
// have_tx and a losing_tx back to back.
TEST(TxAdvertiser, LosingTxIsBudgetedAndDrainsAfterHaveTx)
{
    constexpr size_t budget = 4;
    TxAdvertState st;

    // Seed 9 advertised hashes over 3 sweeps.
    for (int i = 0; i < 3; ++i) { Wire w; sweep(st, hashes(1, 9), w, budget); }
    ASSERT_EQ(st.m_advertised, hashes(1, 9));

    // Now the pool drops to {1..2} AND gains {20..21}: adds go first.
    std::set<uint256> next = hashes(1, 2);
    next.insert(H(20));
    next.insert(H(21));

    Wire a;
    sweep(st, next, a, budget);
    ASSERT_EQ(a.msgs.size(), 1u);
    EXPECT_EQ(a.msgs[0].kind, Wire::Kind::have);
    EXPECT_EQ(std::set<uint256>(a.msgs[0].hashes.begin(), a.msgs[0].hashes.end()),
              (std::set<uint256>{H(20), H(21)}));

    // Only once additions are exhausted do retractions start, one message each.
    Wire b;
    sweep(st, next, b, budget);
    ASSERT_EQ(b.msgs.size(), 1u);
    EXPECT_EQ(b.msgs[0].kind, Wire::Kind::losing);
    EXPECT_EQ(b.msgs[0].hashes.size(), budget);

    Wire c;
    sweep(st, next, c, budget);
    ASSERT_EQ(c.msgs.size(), 1u);
    EXPECT_EQ(c.msgs[0].kind, Wire::Kind::losing);
    EXPECT_EQ(c.msgs[0].hashes.size(), 3u); // 7 retractions total: 4 + 3

    Wire d;
    sweep(st, next, d, budget);
    EXPECT_TRUE(d.msgs.empty());
    EXPECT_EQ(st.m_advertised, next);
}

// Fail closed on a zero budget: nothing can be emitted, so nothing may be
// committed. Committing under a zero budget would mark hashes advertised that
// never reached the wire -> they would never resurface in a later diff.
TEST(TxAdvertiser, ZeroBudgetEmitsNothingAndCommitsNothing)
{
    TxAdvertState st;
    Wire w;

    auto plan = sweep(st, hashes(1, 5), w, /*cap=*/0);

    EXPECT_TRUE(plan.empty());
    EXPECT_TRUE(w.msgs.empty());
    EXPECT_TRUE(st.m_advertised.empty());
    EXPECT_FALSE(st.m_initial_sent);   // the handshake advert is still owed

    // A later sweep with a real budget still delivers the full set.
    Wire w2;
    sweep(st, hashes(1, 5), w2, 10);
    ASSERT_EQ(w2.msgs.size(), 1u);
    EXPECT_EQ(w2.msgs[0].hashes.size(), 5u);
    EXPECT_EQ(st.m_advertised, hashes(1, 5));
}

// The default per-message bound must stay inside a single write_some on a fresh
// socket (the no-outbound-queue constraint) and inside canonical's own receiver
// truncation (p2p.py:494) and max_payload (p2p.py:41).
TEST(TxAdvertiser, DefaultBoundsAreWireSafe)
{
    EXPECT_LE(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE, 2000u);
    // 32 bytes/hash + framing must stay well under a conservative 64 KB sndbuf.
    EXPECT_LE(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE * 32u + 64u, 64u * 1024u);
    // ...and inside what a canonical peer would even retain / accept.
    EXPECT_LE(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE, 10000u);
    EXPECT_LE(core::TX_ADVERT_MAX_HASHES_PER_MESSAGE * 32u, 3145728u);
    EXPECT_EQ(core::TX_ADVERT_INTERVAL_SECONDS, 10);
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
