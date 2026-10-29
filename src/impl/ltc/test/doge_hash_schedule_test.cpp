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
//   - PeerWithoutTheFrontierAnswersFromGenesis: the locator ends at genesis;
//     an answer from there is taken (rewinding the frontier).
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
    // A peer that has none of the locator's hashes but genesis answers from 1.
    EXPECT_EQ(sched.feed(chain.slice(1, CP)), Feed::Complete);
    EXPECT_EQ(sched.hash_at(60), chain.hashes[60]);
}
