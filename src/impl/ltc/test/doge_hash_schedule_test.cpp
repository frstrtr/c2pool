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
//   - HashScheduleSync: only the peer asked feeds the schedule; a stall is
//     no frontier progress (asking the same peer again does not reset it);
//     peers in a row that do not continue the frontier discard it.
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
        EXPECT_EQ(sched.frontier_height(), 0u) << "discarded back to genesis";
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
        EXPECT_EQ(sched.frontier_height(), 0u);
        EXPECT_TRUE(sched.hash_at(150).IsNull());
        // The honest chain afterwards, from genesis.
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

// Only the peer the schedule asked feeds it; another peer's continuing batch
// is the header chain's (NotNext), so a peer we did not ask cannot steer the
// schedule.
TEST(DogeHashScheduleSync, OnlyTheAskedPeerFeedsTheSchedule)
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
    std::optional<Sync::Ask> next;
    EXPECT_EQ(sync.on_headers("peer-b", chain.slice(1, 100), t0(), next), Feed::NotNext);
    EXPECT_FALSE(next.has_value());
    EXPECT_EQ(sched.frontier_height(), 0u);
    EXPECT_EQ(sync.on_headers("peer-a", chain.slice(1, 100), t0(), next), Feed::Extended);
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->peer, "peer-a") << "the next batch from the same peer";
    EXPECT_EQ(next->locator.front(), chain.hashes[100]);
}

// A stall is no frontier progress for STALL; asking the same peer again
// does not restart the clock; a stalled peer is replaced by another.
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

// A frontier that DISCARD_AFTER peers in a row do not continue (a chain a
// peer made up): discarded, the sync starts again from genesis.
TEST(DogeHashScheduleSync, FruitlessPeersDiscardTheFrontier)
{
    constexpr uint32_t CP = 300;
    const Headers chain(genesis_hash(), CP);
    const Headers stale(genesis_hash(), 60, /*salt=*/9);
    TempStore s;
    HashSchedule sched(*s.db, CP, chain.hashes[CP], genesis_hash());
    sched.load();
    Sync sync(sched);
    auto t = t0();
    ASSERT_TRUE(sync.due(t).has_value());
    sync.asked("liar", t);
    std::optional<Sync::Ask> next;
    ASSERT_EQ(sync.on_headers("liar", stale.slice(1, 60), t, next), Feed::Extended);
    for (uint32_t i = 0; i < Sync::DISCARD_AFTER; ++i) {
        t += Sync::STALL + std::chrono::seconds(1);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("honest-" + std::to_string(i), t);
    }
    EXPECT_EQ(sched.frontier_height(), 60u) << "not before DISCARD_AFTER fruitless peers";
    t += Sync::STALL + std::chrono::seconds(1);
    ASSERT_TRUE(sync.due(t).has_value());
    EXPECT_EQ(sched.frontier_height(), 0u) << "discarded";
    sync.asked("honest-x", t);
    EXPECT_EQ(sync.on_headers("honest-x", chain.slice(1, CP), t, next), Feed::Complete);
}
