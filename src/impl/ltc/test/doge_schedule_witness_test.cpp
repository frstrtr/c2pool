// SPDX-License-Identifier: AGPL-3.0-or-later
// DOGE hash schedule on the live failure: REAL mainnet 'headers' batches
// whose AuxPoW parent coinbase carries the BIP144 witness
// (doge_headers_witness_fixtures.hpp). Read witness-stripped, the batch came
// out short or with garbage after h=4715979, 5080796, 5641398 and 6101857,
// and the schedule took the garbage for another chain ("broken") and cut its
// frontier back (19 cuts in the live log). Read as Dogecoin Core reads it,
// each batch extends the frontier by all of its headers, and a sync fed it
// from an asked peer cuts nothing.

#include <gtest/gtest.h>

#include "doge_headers_witness_fixtures.hpp"

#include <impl/doge/coin/auxpow_header.hpp>
#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/ltc/coin/block.hpp>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

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
        dir = std::filesystem::temp_directory_path() / ("doge_schedule_witness_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
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

struct Batch {
    const char*          name;
    const unsigned char* data;
    size_t               size;
    const char*          frontier;  // the parent of the batch's first header
    const char*          last;      // the batch's last header
};

const std::array<Batch, 4> BATCHES{{
    {"h5641397..h5641399", doge::test::DOGE_HEADERS_WIT_5641398, sizeof(doge::test::DOGE_HEADERS_WIT_5641398),
     "f4f0aa5d1732b3245913ef347ee3f610bb4017a11a14eb15bb5bb96a5f021349",
     "248f7d07447f1929b6ad9cd09bb95645b6344a5503ce6943cc0fe0920772eded"},
    {"h5080795..h5080797", doge::test::DOGE_HEADERS_WIT_5080796, sizeof(doge::test::DOGE_HEADERS_WIT_5080796),
     "97b370a3eb18a8fd86749dbf1cf2146d24a42f29c8f681008836b55f80d8221d",
     "8a3394d6212785bf5b7eb29b5fc2249db3d96441fb68a61bb4b172ac0f29f601"},
    {"h4715978..h4715980", doge::test::DOGE_HEADERS_WIT_4715979, sizeof(doge::test::DOGE_HEADERS_WIT_4715979),
     "6332830c6eeb5e4298bfaf0a8d4707e72bf552572f47727de4ba7892f9559f55",
     "ebb501d6ed9c67b83511bec1225fb3eb55eda9af2104333fc56e3e281d280de1"},
    {"h6101856..h6101858", doge::test::DOGE_HEADERS_WIT_6101857, sizeof(doge::test::DOGE_HEADERS_WIT_6101857),
     "f37ba6645234b618aac3325a0e97c096344edaa0bebb995e292a113eb6ee5866",
     "b3f10ec8763aaca7fcc5ae54ba239f6952730c722fed17f393a4064bd15dbda1"},
}};

uint256 u256(const char* hex)
{
    uint256 x;
    x.SetHex(hex);
    return x;
}

// A schedule whose frontier is the batch's parent (the schedule's "genesis"
// stands in for it) and whose checkpoint lies far above the batch.
constexpr uint32_t CP = 1000;
uint256 checkpoint_hash() { return u256("00000000000000000000000000000000000000000000000000000000000c0ffe"); }

} // namespace

// K8: fed the parse of each captured batch at its frontier, the schedule
// extends by the whole batch (not Broken, not NotNext).
TEST(DogeScheduleWitness, Feed_WitnessBatch_ExtendsByTheWholeBatch)
{
    for (const auto& b : BATCHES) {
        SCOPED_TRACE(b.name);
        TempStore s;
        HashSchedule sched(*s.db, CP, checkpoint_hash(), u256(b.frontier));
        sched.load();
        const auto hs = doge::coin::parse_doge_headers_message(b.data, b.size);
        EXPECT_EQ(sched.feed(hs), Feed::Extended);
        EXPECT_EQ(sched.frontier_height(), 3u);
        EXPECT_EQ(sched.frontier_hash().GetHex(), b.last);
    }
}

// K8, through the sync the live node runs: an asked peer's answer extends
// the frontier, nothing is cut, the peer keeps its turn.
TEST(DogeScheduleWitness, Sync_WitnessBatch_FromAnAskedPeer_NoCut)
{
    using Sync = doge::coin::HashScheduleSync;
    const auto t = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    for (const auto& b : BATCHES) {
        SCOPED_TRACE(b.name);
        TempStore s;
        HashSchedule sched(*s.db, CP, checkpoint_hash(), u256(b.frontier));
        sched.load();
        Sync sync(sched);
        ASSERT_TRUE(sync.due(t).has_value());
        sync.asked("peer", t);
        std::optional<Sync::Ask> next;
        const auto hs = doge::coin::parse_doge_headers_message(b.data, b.size);
        EXPECT_EQ(sync.on_headers("peer", hs, t, next), Feed::Extended);
        EXPECT_EQ(sched.frontier_height(), 3u);
        EXPECT_EQ(sync.truncations(), 0u);
        EXPECT_EQ(sync.cut_peers(), 0u);
        ASSERT_TRUE(next.has_value());
        EXPECT_EQ(next->peer, "peer");
    }
}
