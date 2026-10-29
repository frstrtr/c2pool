// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// doge::coin::HashSchedule (rides share_test, DESIGN doge-underfill §3.1,
// KAT 8): the best chain's block hash at every height below the DOGE header
// chain's checkpoint, served only once the hash chain links from genesis
// into the checkpoint hash.
//   - LinksIntoCheckpointOrIsRejected: 300 headers, checkpoint at 300: the
//     schedule is accepted and serves 1..299; a variant broken at 150 (its
//     parent hash is not 149's) and one that reaches 300 with another hash
//     are rejected and serve nothing.
//   - ResumesAfterRestart: the frontier survives a reopen; the sync goes on
//     from there.
//   - A batch is taken only when it extends the frontier: a lagging peer's
//     answer from genesis (the live livelock at h=2000) and a batch from a
//     stale locator entry are ignored, never a rewind; a frontier no peer
//     continues is dropped only by discard().
//   - CompletionProvesTheStoredPrefix: a stored prefix that does not link
//     (a corrupted record) is never persisted as complete.
//   - HashScheduleSync: a batch continuing the frontier extends it from a
//     peer with an outstanding ask (a replaced peer's late answer too), never
//     from one never asked or one whose run was cut; a stall is no frontier
//     progress (asking the same peer again does not reset it) and asks two
//     peers; silence and the header chain's traffic never count; a liar's
//     batches are cut back to the frontier before it, not to genesis, after
//     a restart too.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/ltc/coin/block.hpp>

namespace {

using doge::coin::HashSchedule;
using Feed = HashSchedule::Feed;
using ltc::coin::BlockHeaderType;

struct TempStore {
    std::filesystem::path dir;
    std::unique_ptr<core::LevelDBStore> db;
    TempStore()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("doge_hash_schedule_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        open();
    }
    void open()
    {
        db = std::make_unique<core::LevelDBStore>(dir.string(), core::LevelDBOptions{});
        EXPECT_TRUE(db->open());
    }
    ~TempStore()
    {
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

uint256 hash_of(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

/// A header chain of `n` headers on `genesis` (heights 1..n); `hashes[h]` is
/// height h's hash (hashes[0] = genesis).
struct Headers {
    std::vector<BlockHeaderType> headers;  // headers[h - 1] is height h
    std::vector<uint256> hashes;
    Headers(const uint256& genesis, uint32_t n, uint32_t salt = 0)
    {
        hashes.push_back(genesis);
        for (uint32_t h = 1; h <= n; ++h) {
            BlockHeaderType b;
            b.m_version = 0x00620104;
            b.m_previous_block = hashes.back();
            b.m_merkle_root.SetHex(std::to_string(1000 + h));
            b.m_timestamp = 1400000000 + h * 60;
            b.m_bits = 0x1e0ffff0;
            b.m_nonce = h + salt;
            headers.push_back(b);
            hashes.push_back(hash_of(b));
        }
    }
    std::vector<BlockHeaderType> slice(uint32_t from, uint32_t to) const  // heights from..to
    {
        return {headers.begin() + (from - 1), headers.begin() + to};
    }
};

uint256 genesis_hash()
{
    uint256 g;
    g.SetHex("1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691");
    return g;
}

} // namespace

TEST(DogeHashSchedule, LinksIntoCheckpointOrIsRejected)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    {
        TempStore s;
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        EXPECT_FALSE(sched.complete());
        EXPECT_TRUE(sched.hash_at(1).IsNull()) << "served before the proof";
        EXPECT_EQ(sched.feed(chain.slice(1, 120)), Feed::Extended);
        EXPECT_EQ(sched.frontier_height(), 120u);
        EXPECT_TRUE(sched.hash_at(100).IsNull()) << "served before the proof";
        EXPECT_EQ(sched.feed(chain.slice(121, CP)), Feed::Complete);
        ASSERT_TRUE(sched.complete());
        for (uint32_t h = 0; h <= CP; ++h)
            ASSERT_EQ(sched.hash_at(h), chain.hashes[h]) << "h=" << h;
        EXPECT_TRUE(sched.hash_at(CP + 1).IsNull()) << "above the checkpoint: the header chain's";
        EXPECT_EQ(sched.feed(chain.slice(1, 10)), Feed::Done);
    }
    {
        // Broken at 150: its parent hash is not 149's.
        TempStore s;
        Headers broken(genesis_hash(), CP);
        broken.headers[149].m_previous_block = chain.hashes[10];
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        EXPECT_EQ(sched.feed(broken.slice(1, CP)), Feed::Broken);
        EXPECT_FALSE(sched.complete());
        EXPECT_EQ(sched.frontier_height(), 0u) << "nothing of the broken batch stored";
        for (uint32_t h = 1; h < CP; ++h)
            ASSERT_TRUE(sched.hash_at(h).IsNull());
    }
    {
        // A chain that links but reaches 300 with another hash (another
        // branch, or a peer's own chain).
        TempStore s;
        const Headers other(genesis_hash(), CP, /*salt=*/7);
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        EXPECT_EQ(sched.feed(other.slice(1, 200)), Feed::Extended);
        EXPECT_EQ(sched.feed(other.slice(201, CP)), Feed::Rejected);
        EXPECT_FALSE(sched.complete());
        EXPECT_EQ(sched.frontier_height(), 200u) << "the rejected batch dropped, the prefix kept";
        EXPECT_TRUE(sched.hash_at(150).IsNull());
        // HashScheduleSync cuts back what the sending peer stored (here: all
        // of it); the honest chain afterwards, from genesis.
        sched.truncate(0);
        EXPECT_EQ(sched.frontier_height(), 0u);
        EXPECT_EQ(sched.feed(chain.slice(1, CP)), Feed::Complete);
        EXPECT_EQ(sched.hash_at(150), chain.hashes[150]);
    }
}

TEST(DogeHashSchedule, ResumesAfterRestart)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    {
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        ASSERT_EQ(sched.feed(chain.slice(1, 180)), Feed::Extended);
    }
    s.open();
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    EXPECT_EQ(sched.frontier_height(), 180u);
    EXPECT_EQ(sched.frontier_hash(), chain.hashes[180]);
    EXPECT_EQ(sched.feed(chain.slice(1, 10)), Feed::NotNext) << "not a continuation (no locator asked yet)";
    EXPECT_EQ(sched.locator().front(), chain.hashes[180]);
    EXPECT_EQ(sched.feed(chain.slice(181, CP)), Feed::Complete);
    EXPECT_EQ(sched.hash_at(42), chain.hashes[42]);

    // A schedule stored for another checkpoint is not used.
    s.open();
    HashSchedule moved(*s.db, CP - 1, chain.hashes[CP - 1], genesis_hash());
    moved.load();
    EXPECT_FALSE(moved.complete());
    EXPECT_EQ(moved.frontier_height(), 0u);
}

// A frontier no honest peer has (a lying peer's chain): their answers from
// genesis are not taken; only discard() (HashScheduleSync, after peers in a
// row fail to continue it) starts over.
TEST(DogeHashSchedule, PeerWithoutTheFrontierAnswersFromGenesis)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    const Headers stale(genesis_hash(), 60, /*salt=*/3);   // a frontier no peer has
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.feed(stale.slice(1, 60)), Feed::Extended);
    const auto loc = sched.locator();
    EXPECT_EQ(loc.front(), stale.hashes[60]);
    EXPECT_EQ(loc.back(), genesis_hash());
    EXPECT_LE(loc.size(), 20u);
    EXPECT_EQ(sched.feed(chain.slice(1, CP)), Feed::NotNext) << "an answer from genesis rewound the frontier";
    EXPECT_EQ(sched.frontier_height(), 60u);
    EXPECT_EQ(sched.frontier_hash(), stale.hashes[60]);
    sched.discard();
    EXPECT_EQ(sched.feed(chain.slice(1, CP)), Feed::Complete);
    EXPECT_EQ(sched.hash_at(60), chain.hashes[60]);
}

// The live livelock (VERIFY M1): the header chain's tip-only getheaders go to
// every peer; a peer that has not seen that tip answers from genesis. That
// batch (from the peer the schedule asked, or any) must not rewind the
// frontier: before, it rewound to 0 and rewrote 1..2000 on every such answer.
TEST(DogeHashSchedule, LaggingPeerAnswerFromGenesisDoesNotRewind)
{
    constexpr uint32_t CP = 3000;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.feed(chain.slice(1, 2000)), Feed::Extended);
    (void)sched.locator();   // the sync asks with it before every batch
    EXPECT_EQ(sched.feed(chain.slice(1, 1000)), Feed::NotNext);
    EXPECT_EQ(sched.frontier_height(), 2000u) << "rewound by an answer from genesis";
    EXPECT_EQ(sched.feed(chain.slice(2001, CP)), Feed::Complete);
}

// A batch linking from a stored height below the frontier (a stale locator
// entry) is not taken: the prefix grows only at its end, so the stored hashes
// stay one hash chain.
TEST(DogeHashSchedule, StaleLocatorEntryCannotBreakContiguity)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.feed(chain.slice(1, 200)), Feed::Extended);
    (void)sched.locator();
    // A header off height 176, an entry of that locator (200..190, 188, 184,
    // 176, 160, ...).
    BlockHeaderType f = chain.headers[176];
    f.m_previous_block = chain.hashes[176];
    f.m_nonce += 77;
    std::vector<BlockHeaderType> branch{f};
    EXPECT_EQ(sched.feed(branch), Feed::NotNext) << "a batch off a stored height below the frontier";
    EXPECT_EQ(sched.frontier_height(), 200u);
    EXPECT_EQ(sched.feed(chain.slice(201, CP)), Feed::Complete);
    for (uint32_t h = 1; h < CP; ++h)
        ASSERT_EQ(sched.hash_at(h), chain.hashes[h]) << "h=" << h;
}

// The stored prefix is read back before the schedule is marked complete: a
// record that does not link (here written over, as a disk fault would) means
// the schedule is discarded, never served.
TEST(DogeHashSchedule, CompletionProvesTheStoredPrefix)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.feed(chain.slice(1, 200)), Feed::Extended);
    std::string key(5, '\0');
    key[0] = 'H';
    key[4] = static_cast<char>(100);
    std::vector<uint8_t> bogus(64, 0x5a);   // height 100: another hash, another parent
    ASSERT_TRUE(s.db->put(key, bogus));
    EXPECT_EQ(sched.feed(chain.slice(201, CP)), Feed::Rejected);
    EXPECT_FALSE(sched.complete());
    EXPECT_TRUE(sched.hash_at(100).IsNull());
    EXPECT_EQ(sched.frontier_height(), 0u) << "discarded";
}

namespace {

using Sync = doge::coin::HashScheduleSync;
using Clock = Sync::Clock;

Clock::time_point t0() { return Clock::time_point{} + std::chrono::hours(1); }

} // namespace

// A batch from a peer with an outstanding getheaders that continues the
// frontier extends it (the turn's peer, or the hedge asked with it); the next
// batch is asked from that peer. One answer per ask; a peer never asked, or a
// batch that does not continue the frontier, is the header chain's.
TEST(DogeHashScheduleSync, AnAskedPeerContinuingTheFrontierExtends)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    const auto a = sync.due(t0());
    ASSERT_TRUE(a.has_value());
    EXPECT_TRUE(a->peer.empty()) << "a new peer, round robin";
    sync.asked("peer-a", t0());
    sync.asked("peer-b", t0(), /*hedge=*/true);
    std::optional<Sync::Ask> next;
    EXPECT_EQ(sync.on_headers("peer-c", chain.slice(1, 100), t0(), next), Feed::NotNext)
        << "a peer never asked";
    EXPECT_EQ(sync.on_headers("peer-b", chain.slice(1, 100), t0(), next), Feed::Extended);
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->peer, "peer-b") << "the next batch from the peer that delivered";
    EXPECT_EQ(next->locator.front(), chain.hashes[100]);
    EXPECT_EQ(sync.peer(), "peer-b") << "the turn is the deliverer's";
    EXPECT_EQ(sync.on_headers("peer-b", chain.slice(101, 150), t0(), next), Feed::NotNext)
        << "one answer per ask";
    sync.asked("peer-b", t0());
    EXPECT_EQ(sync.on_headers("peer-b", chain.slice(50, 150), t0(), next), Feed::NotNext);
    EXPECT_EQ(sched.frontier_height(), 100u);
}

// After a stall two new peers are asked (a hedge), never one whose run was
// cut; the pick is round robin over the connected peers.
TEST(DogeHashScheduleSync, AStallAsksTwoPeersNeverACutOne)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    const auto first = sync.due(t);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->peers, 1u) << "the first ask: one peer";
    sync.asked("a", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("a", chain.slice(1, 100), t, next), Feed::Extended);
    sync.asked("a", t);
    auto broken = chain.slice(101, 150);
    broken[3].m_previous_block = chain.hashes[9];
    ASSERT_EQ(sync.on_headers("a", broken, t, next), Feed::Broken);
    EXPECT_EQ(sync.cut_peers(), 1u);
    t += Sync::STALL + std::chrono::seconds(1);
    sync.asked("b", t);
    t += Sync::STALL + std::chrono::seconds(1);
    const auto stalled = sync.due(t);
    ASSERT_TRUE(stalled.has_value());
    EXPECT_EQ(stalled->peers, Sync::HEDGE);
    const std::vector<std::string> ready{"a", "b", "c", "d"};
    for (size_t idx = 0; idx < 8; ++idx) {
        Sync::Ask ask = *stalled;
        ask.peer_idx = idx;
        const auto picked = sync.pick(ready, ask);
        ASSERT_EQ(picked.size(), 2u);
        EXPECT_NE(picked[0], picked[1]);
        EXPECT_NE(picked[0], "a") << "a cut peer asked again";
        EXPECT_NE(picked[1], "a");
    }
    EXPECT_TRUE(sync.pick({"a"}, *stalled).empty()) << "only a cut peer connected: nobody";
}

// The live stall (VERIFY2 M3): peer A's answer for 2001.. arrives after its
// 30 s and after A was replaced (the header chain's getheaders traffic queued
// it). It continues the frontier: taken. Before, it was dropped as "not the
// asked peer" and A counted as fruitless.
TEST(DogeHashScheduleSync, LateValidContinuationFromAReplacedPeerIsTaken)
{
    constexpr uint32_t CP = 5000;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("peer-a", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("peer-a", chain.slice(1, 2000), t, next), Feed::Extended);
    sync.asked("peer-a", t);   // asked for 2001.. (the ask stays outstanding: ASK_TTL)
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value()) << "A replaced";
    sync.asked("peer-b", t);
    EXPECT_EQ(sync.on_headers("peer-a", chain.slice(2001, 4000), t, next), Feed::Extended)
        << "a late answer that continues the frontier was dropped";
    EXPECT_EQ(sched.frontier_height(), 4000u);
}

// Silence is not evidence of a fake frontier: peers that never answer, for
// any number of stalls and any time, never cut the frontier back. Before, 20
// silent peers in a row discarded it to genesis.
TEST(DogeHashScheduleSync, SilentPeersNeverDropTheFrontier)
{
    constexpr uint32_t CP = 3000;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("peer-a", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("peer-a", chain.slice(1, 2000), t, next), Feed::Extended);
    for (int i = 0; i < 60; ++i) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("silent-" + std::to_string(i), t);
    }
    EXPECT_EQ(sync.stalls(), 60u);
    EXPECT_EQ(sched.frontier_height(), 2000u) << "silence cut the frontier back";
    EXPECT_EQ(sync.truncations(), 0u);
}

// A liar extends an honest 200-prefix with 60 headers of its own; no honest
// peer continues that (they answer, from deeper). After FRUITLESS_AFTER such
// answers and TRUNCATE_AFTER without progress the frontier is cut back to
// where it stood when the liar was asked (200), not to genesis.
TEST(DogeHashScheduleSync, LiarIsCutBackToTheFrontierBeforeIt)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("honest", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("honest", chain.slice(1, 200), t, next), Feed::Extended);
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("liar", t);
    // The liar's 60 headers on the real 200.
    std::vector<BlockHeaderType> fake;
    uint256 prev = chain.hashes[200];
    for (uint32_t h = 201; h <= 260; ++h) {
        BlockHeaderType b = chain.headers[h - 1];
        b.m_previous_block = prev;
        b.m_nonce += 1000;
        fake.push_back(b);
        prev = Hash(pack(b).get_span());
    }
    ASSERT_EQ(sync.on_headers("liar", fake, t, next), Feed::Extended);
    ASSERT_EQ(sched.frontier_height(), 260u);
    // Honest peers answer (not from the fake frontier, which they lack).
    uint32_t i = 0;
    while (sched.frontier_height() == 260u && i < 200) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "honest-" + std::to_string(i++);
        sync.asked(p, t);
        EXPECT_EQ(sync.on_headers(p, chain.slice(1, 100), t, next), Feed::NotNext);
    }
    EXPECT_EQ(sched.frontier_height(), 200u) << "cut back to before the liar, not to genesis";
    EXPECT_GE(i, Sync::FRUITLESS_AFTER);
    EXPECT_GE(t - t0(), Sync::TRUNCATE_AFTER);
    EXPECT_EQ(sync.truncations(), 1u);
    t += Sync::STALL + std::chrono::seconds(1);
    sync.due(t);
    sync.asked("honest-x", t);
    EXPECT_EQ(sync.on_headers("honest-x", chain.slice(201, CP), t, next), Feed::Complete);
}

// A batch that breaks a link: the batch is dropped and what its sender
// stored on top is cut back; the prefix before that peer stays, the sender
// is not fed again. A broken batch from a peer whose run others continued
// drops only the batch.
TEST(DogeHashScheduleSync, BrokenBatchCutsBackOnlyItsSender)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("a", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("a", chain.slice(1, 100), t, next), Feed::Extended);
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("b", t);
    ASSERT_EQ(sync.on_headers("b", chain.slice(101, 150), t, next), Feed::Extended);
    sync.asked("b", t);  // the follow-up
    auto broken = chain.slice(151, 200);
    broken[10].m_previous_block = chain.hashes[3];
    EXPECT_EQ(sync.on_headers("b", broken, t, next), Feed::Broken);
    EXPECT_EQ(sched.frontier_height(), 100u) << "b's batches go, a's stay";
    ASSERT_TRUE(next.has_value());
    EXPECT_TRUE(next->peer.empty()) << "another peer, now";
    sync.asked("b", t);
    EXPECT_EQ(sync.on_headers("b", chain.slice(101, 150), t, next), Feed::NotNext) << "b is not fed again";
    sync.asked("c", t);
    ASSERT_EQ(sync.on_headers("c", chain.slice(101, 150), t, next), Feed::Extended);
    sync.asked("a", t, /*hedge=*/true);
    auto broken_a = chain.slice(151, 200);
    broken_a[5].m_previous_block = chain.hashes[7];
    EXPECT_EQ(sync.on_headers("a", broken_a, t, next), Feed::Broken);
    EXPECT_EQ(sched.frontier_height(), 150u) << "c continued a's run: only a's batch goes";
    EXPECT_EQ(sync.truncations(), 1u);
}

TEST(DogeHashScheduleSync, StallIsMeasuredByFrontierProgress)
{
    constexpr uint32_t CP = 3000;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    ASSERT_TRUE(sync.due(t0()).has_value());
    sync.asked("peer-a", t0());
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("peer-a", chain.slice(1, 2000), t0() + std::chrono::seconds(1), next),
              Feed::Extended);
    // peer-a answers from genesis from now on (it does not move the
    // frontier); asking it again every 5 s does not count as progress.
    for (int i = 1; i <= 6; ++i) {
        const auto t = t0() + std::chrono::seconds(1 + 5 * i);
        EXPECT_EQ(sync.on_headers("peer-a", chain.slice(1, 2000), t, next), Feed::NotNext);
        sync.asked("peer-a", t);
        if (i < 6)
            EXPECT_FALSE(sync.due(t).has_value()) << "within STALL of the last progress";
    }
    const auto later = t0() + std::chrono::seconds(32);
    const auto a = sync.due(later);
    ASSERT_TRUE(a.has_value()) << "no progress for 30 s: another peer";
    EXPECT_TRUE(a->peer.empty());
    EXPECT_EQ(sync.stalls(), 1u);
    EXPECT_EQ(sched.frontier_height(), 2000u) << "nothing lost";
    sync.asked("peer-b", later);
    EXPECT_EQ(sync.on_headers("peer-b", chain.slice(2001, CP), later, next), Feed::Complete);
}

// ---------------------------------------------------------------------------
// VERIFY3 (d8ee36367): an unasked peer fed the schedule (V3-M1), the header
// chain's traffic counted as an answer (V3-S1), the run stack did not survive
// a restart (V3-S2). The verifier's probes, kept as KATs.
// ---------------------------------------------------------------------------

namespace {
uint256 other_base()
{
    uint256 g;
    g.SetHex("00000000000000000000000000000000000000000000000000000000000000ab");
    return g;
}
} // namespace

// V3-M1: only a peer with an outstanding getheaders feeds the schedule. A
// peer never asked sends one header whose parent is the frontier (no PoW is
// checked below the checkpoint): not taken, the honest continuation links.
TEST(DogeHashScheduleSync, UnaskedPeerCannotSteerTheSchedule)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("honest", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("honest", chain.slice(1, 200), t, next), Feed::Extended);
    sync.asked("honest", t);
    BlockHeaderType fake = chain.headers[200];  // height 201's header, parent = the frontier
    fake.m_nonce += 7;                           // another hash
    EXPECT_EQ(sync.on_headers("poison", {fake}, t, next), Feed::NotNext)
        << "a peer we never asked fed the schedule";
    EXPECT_EQ(sched.frontier_height(), 200u);
    EXPECT_EQ(sync.on_headers("honest", chain.slice(201, CP), t, next), Feed::Complete)
        << "the honest continuation no longer links";
}

// V3-M1: the livelock. An unasked peer's one-header poison, resent after
// every cut, must not hold the sync at the height it chose.
TEST(DogeHashScheduleSync, OneUnaskedPeerDoesNotLivelockTheSync)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("honest", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("honest", chain.slice(1, 200), t, next), Feed::Extended);
    BlockHeaderType fake = chain.headers[200];
    fake.m_nonce += 7;
    const uint256 fake_hash = Hash(pack(fake).get_span());
    uint32_t cycles = 0;
    const auto start = t;
    for (; cycles < 3; ++cycles) {
        if (sync.on_headers("poison", {fake}, t, next) != Feed::Extended)
            break;
        EXPECT_EQ(sched.frontier_hash(), fake_hash);
        EXPECT_EQ(sync.on_headers("honest", chain.slice(201, CP), t, next), Feed::NotNext);
        int i = 0;
        while (sched.frontier_hash() == fake_hash && i < 400) {
            t += Sync::STALL + std::chrono::seconds(1);
            ASSERT_TRUE(sync.due(t).has_value());
            const std::string p = "honest-" + std::to_string(i++);
            sync.asked(p, t);
            sync.on_headers(p, chain.slice(1, 100), t, next);  // from the locator's real entry
        }
        ASSERT_EQ(sched.frontier_height(), 200u) << "the cut went elsewhere";
    }
    EXPECT_LE(sync.truncations(), 1u)
        << "livelock: " << cycles << " poison cycles, " << sync.truncations() << " truncations, "
        << std::chrono::duration_cast<std::chrono::minutes>(t - start).count()
        << " simulated minutes, the frontier never passed 200";
}

// V3-M1: a peer whose run was cut is never fed again in this process: asked
// again by a rotation, its fake is not taken (a liar that was asked costs one
// 30-min cycle, not one per rotation).
TEST(DogeHashScheduleSync, ACutPeerIsNeverFedAgain)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("honest", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("honest", chain.slice(1, 200), t, next), Feed::Extended);
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("liar", t);
    std::vector<BlockHeaderType> fake;
    uint256 prev = chain.hashes[200];
    for (uint32_t h = 201; h <= 260; ++h) {
        BlockHeaderType b = chain.headers[h - 1];
        b.m_previous_block = prev;
        b.m_nonce += 1000;
        fake.push_back(b);
        prev = Hash(pack(b).get_span());
    }
    ASSERT_EQ(sync.on_headers("liar", fake, t, next), Feed::Extended);
    int i = 0;
    while (sched.frontier_height() == 260u && i < 200) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "honest-" + std::to_string(i++);
        sync.asked(p, t);
        sync.on_headers(p, chain.slice(1, 100), t, next);
    }
    ASSERT_EQ(sched.frontier_height(), 200u);
    t += Sync::STALL + std::chrono::seconds(1);
    sync.due(t);
    sync.asked("liar", t);
    EXPECT_EQ(sync.on_headers("liar", fake, t, next), Feed::NotNext) << "a cut peer fed the schedule again";
    EXPECT_EQ(sched.frontier_height(), 200u);
}

// V3-S1: a batch from the asked peer whose first parent is not in the
// schedule's locator (the header chain's answer, a block it announced: above
// the checkpoint) is not an answer to the schedule's getheaders, so slow
// honest peers never make the honest frontier "fruitless".
TEST(DogeHashScheduleSync, HeaderChainTrafficFromTheAskedPeerIsNotAFruitlessAnswer)
{
    constexpr uint32_t CP = 5000;
    const Headers chain(genesis_hash(), CP);
    const Headers tip(other_base(), 3);  // headers above the checkpoint, as the schedule sees them
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("b", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("b", chain.slice(1, 1000), t, next), Feed::Extended);
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("c", t);
    ASSERT_EQ(sync.on_headers("c", chain.slice(1001, 3000), t, next), Feed::Extended);
    for (int i = 0; i < 70; ++i) {  // 36 min of honest peers too slow for STALL
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "slow-" + std::to_string(i);
        sync.asked(p, t);
        EXPECT_EQ(sync.on_headers(p, tip.slice(1, 3), t, next), Feed::NotNext);
    }
    EXPECT_EQ(sched.frontier_height(), 3000u)
        << "honest slow peers that never answered the schedule's locator cut its frontier back";
    EXPECT_EQ(sync.truncations(), 0u);
}

// V3-S2 (the verifier's): after a restart, slow honest peers do not send the
// frontier to genesis.
TEST(DogeHashScheduleSync, AfterARestartACutDoesNotGoToGenesis)
{
    constexpr uint32_t CP = 5000;
    const Headers chain(genesis_hash(), CP);
    const Headers tip(other_base(), 3);
    TempStore s;
    {
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        Sync sync(sched);
        auto t = t0();
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("b", t);
        std::optional<Sync::Ask> next;
        ASSERT_EQ(sync.on_headers("b", chain.slice(1, 1000), t, next), Feed::Extended);
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("c", t);
        ASSERT_EQ(sync.on_headers("c", chain.slice(1001, 3000), t, next), Feed::Extended);
    }
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.frontier_height(), 3000u);
    Sync sync(sched);
    auto t = t0() + std::chrono::hours(2);
    std::optional<Sync::Ask> next;
    for (int i = 0; i < 70; ++i) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "slow-" + std::to_string(i);
        sync.asked(p, t);
        sync.on_headers(p, tip.slice(1, 3), t, next);
    }
    EXPECT_GE(sched.frontier_height(), 1000u)
        << "after a restart the cut went to genesis (" << sync.truncations() << " truncations)";
}

// V3-S2: the run bases survive a restart. A liar extended an honest 3000
// before the restart; after it, the first cut returns to 3000 (the liar's
// base), not to genesis, and the honest chain completes from there.
TEST(DogeHashScheduleSync, RestartThenCutReturnsToTheLastRunBase)
{
    constexpr uint32_t CP = 5000;
    const Headers chain(genesis_hash(), CP);
    std::vector<BlockHeaderType> fake;
    uint256 prev = chain.hashes[3000];
    for (uint32_t h = 3001; h <= 3060; ++h) {
        BlockHeaderType b = chain.headers[h - 1];
        b.m_previous_block = prev;
        b.m_nonce += 1000;
        fake.push_back(b);
        prev = Hash(pack(b).get_span());
    }
    TempStore s;
    {
        HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
        sched.load();
        Sync sync(sched);
        auto t = t0();
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("b", t);
        std::optional<Sync::Ask> next;
        ASSERT_EQ(sync.on_headers("b", chain.slice(1, 1000), t, next), Feed::Extended);
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("c", t);
        ASSERT_EQ(sync.on_headers("c", chain.slice(1001, 3000), t, next), Feed::Extended);
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("liar", t);
        ASSERT_EQ(sync.on_headers("liar", fake, t, next), Feed::Extended);
    }
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    ASSERT_EQ(sched.frontier_height(), 3060u);
    Sync sync(sched);
    auto t = t0() + std::chrono::hours(2);
    std::optional<Sync::Ask> next;
    int i = 0;
    while (sched.frontier_height() == 3060u && i < 200) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "honest-" + std::to_string(i++);
        sync.asked(p, t);
        sync.on_headers(p, chain.slice(1, 100), t, next);  // from the locator's genesis entry
    }
    EXPECT_EQ(sched.frontier_height(), 3000u)
        << "after a restart the cut went to h=" << sched.frontier_height() << ", not the last run's base";
    EXPECT_EQ(sync.truncations(), 1u);
    t += Sync::STALL + std::chrono::seconds(1);
    sync.due(t);
    sync.asked("honest-x", t);
    EXPECT_EQ(sync.on_headers("honest-x", chain.slice(3001, CP), t, next), Feed::Complete);
}

// The time guard: 20 fruitless answers within 30 min do not cut (pins the
// AND: FRUITLESS_AFTER alone would let a slow honest network cut itself).
TEST(DogeHashScheduleSync, TwentyFruitlessPeersWithinThirtyMinutesDoNotCut)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("honest", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("honest", chain.slice(1, 200), t, next), Feed::Extended);
    for (uint32_t i = 0; i < Sync::FRUITLESS_AFTER + 5; ++i) {
        t += Sync::STALL + std::chrono::seconds(1);  // 25 stalls: ~13 min
        ASSERT_TRUE(sync.due(t).has_value());
        const std::string p = "h-" + std::to_string(i);
        sync.asked(p, t);
        EXPECT_EQ(sync.on_headers(p, chain.slice(1, 100), t, next), Feed::NotNext);
    }
    EXPECT_EQ(sched.frontier_height(), 200u);
    EXPECT_EQ(sync.truncations(), 0u);
}
