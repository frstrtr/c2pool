// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The sharechain store's height index keeps every stored share of an absheight,
// in a layout every earlier binary still reads, and is rebuilt whenever an
// earlier binary may have written it since.
//
// The store is shared by every coin (core::SharechainLevelDBStore). Its
// `height:<h>` key held ONE hash, and removing any share of a height deleted
// the key whatever it held: every pruned fork share took the main-chain share
// of its height out of the index, and a graceful restart reloaded the chain in
// fragments (LTC 2026-11-13; on a copy of a DASH store, 42 main-chain shares
// unreachable, the first 7 deep). Now:
//   * `height:<h>` still holds exactly one 32-byte hash (the primary); every
//     other share of h has a `hsib:<h><hash>` key. Removing a share removes only
//     it; a removed primary is replaced by a sibling.
//   * close() writes dirty=2; earlier binaries write 0 (and 1 while open). Any
//     value but 2 at open() means an earlier binary or a crash wrote the index
//     last: it is rebuilt, the best-chain share of each height as its primary.
//
// RED on master: all of them (master closes with dirty=0, keeps one hash per
// height and deletes `height:<h>` whatever it held).
//
// Folded into the existing core_test target.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

namespace {

std::filesystem::path fresh_dir(const char* tag)
{
    static std::atomic<uint64_t> ctr{0};
    auto dir = std::filesystem::temp_directory_path() /
               ("c2pool_kat_height_index_" + std::string(tag) + "_" + std::to_string(::getpid()) + "_" +
                std::to_string(ctr.fetch_add(1)));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

uint256 H(uint64_t n) { return uint256(n); }

core::ShareMetadata meta_at(const uint256& prev, uint64_t height)
{
    core::ShareMetadata m;
    m.prev_hash = prev;
    m.height = height;
    return m;
}

const std::vector<uint8_t> kBlob(16, 0x5a);

std::string height_key(uint64_t h)
{
    std::string digits = std::to_string(h);
    return "height:" + std::string(16 - digits.size(), '0') + digits;
}

// What an earlier binary (and the DASH chain auditor) reads: the `height:`
// value of every height, as a hash, or nullopt when it is not exactly 32 bytes.
struct OldReaderView
{
    std::map<uint64_t, std::optional<uint256>> heights;
    size_t sibling_keys = 0;
    uint8_t dirty = 0xff;
};

OldReaderView old_reader_view(const std::string& db_path)
{
    OldReaderView v;
    core::LevelDBStore raw(db_path, core::LevelDBOptions{});
    EXPECT_TRUE(raw.open());
    raw.for_each_prefix("height:", [&](const std::string& key, const std::vector<uint8_t>& value) {
        std::optional<uint256> h;
        if (value.size() == 32)
            h = uint256(std::vector<unsigned char>(value.begin(), value.end()));
        v.heights[std::stoull(key.substr(7))] = h;
        return true;
    });
    raw.for_each_prefix("hsib:", [&](const std::string&, const std::vector<uint8_t>&) {
        ++v.sibling_keys;
        return true;
    });
    std::vector<uint8_t> d;
    if (raw.get("dirty", d) && !d.empty())
        v.dirty = d[0];
    raw.close();
    return v;
}

// A main chain 1..n (hashes 0x1000+h) stored in one batch.
std::vector<uint256> store_main(core::SharechainLevelDBStore& st, uint64_t n)
{
    std::vector<core::SharechainLevelDBStore::BatchShareEntry> batch;
    std::vector<uint256> main;
    uint256 prev;
    for (uint64_t h = 1; h <= n; ++h) {
        const uint256 m = H(0x1000 + h);
        batch.push_back({m, kBlob, meta_at(prev, h)});
        main.push_back(m);
        prev = m;
    }
    EXPECT_TRUE(st.store_shares_batch(batch));
    return main;
}

} // namespace

// The DASH ask: two shares at one height, the orphan neighbour pruned (as the
// node's clean-up does, in a batch). The surviving main-chain share is still
// what `height:<h>` holds — for this binary and for every earlier reader — and
// a reload returns it. Both orders: the orphan stored before (it was the
// primary) and after the main share.
TEST(SharechainHeightIndex, PruningTheOrphanNeighbourKeepsTheMainShareReachable)
{
    for (const bool orphan_first : {true, false}) {
        SCOPED_TRACE(orphan_first ? "orphan stored first" : "orphan stored second");
        const auto dir = fresh_dir("orphan");
        std::string db_path;
        std::vector<uint256> main;
        const uint256 orphan = H(0x2005);
        {
            core::SharechainLevelDBStore st(dir.string(), "kat");
            ASSERT_TRUE(st.open());
            db_path = st.db_path();
            if (orphan_first)
                ASSERT_TRUE(st.store_share(orphan, kBlob, meta_at(H(0x1004), 5)));
            main = store_main(st, 8);
            if (!orphan_first)
                ASSERT_TRUE(st.store_share(orphan, kBlob, meta_at(H(0x1004), 5)));
            ASSERT_TRUE(st.remove_shares_batch({orphan}));
            st.close();
        }
        const auto view = old_reader_view(db_path);
        ASSERT_TRUE(view.heights.count(5));
        EXPECT_EQ(view.heights.at(5), std::optional<uint256>(main[4]))
            << "height:5 holds the main-chain share, as one 32-byte hash";
        EXPECT_EQ(view.sibling_keys, 0u);

        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX), main) << "the reload gets the whole main chain";
        EXPECT_EQ(st.get_chain_hashes(main[3], 3, /*forward=*/true),
                  (std::vector<uint256>{main[3], main[4], main[5]}));
        st.close();
        std::filesystem::remove_all(dir);
    }
}

// Every `height:` value stays exactly one 32-byte hash however many shares the
// height has: an earlier binary reading the store sees one share per height,
// as it always did; the other shares are under `hsib:` keys it does not read.
TEST(SharechainHeightIndex, EveryHeightValueIsOneHashForEarlierReaders)
{
    const auto dir = fresh_dir("one_hash");
    std::string db_path;
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        db_path = st.db_path();
        store_main(st, 6);
        for (uint64_t f = 0; f < 3; ++f)   // three forks at height 4
            ASSERT_TRUE(st.store_share(H(0x3000 + f), kBlob, meta_at(H(0x1003), 4)));
        EXPECT_EQ(st.get_shares_by_height_range(4, 4).size(), 4u);
        st.close();
    }
    const auto view = old_reader_view(db_path);
    EXPECT_EQ(view.heights.size(), 6u);
    for (const auto& [h, hash] : view.heights)
        EXPECT_TRUE(hash.has_value()) << "height:" << h << " is not one 32-byte hash";
    EXPECT_EQ(view.heights.at(4), std::optional<uint256>(H(0x1004))) << "the first stored stays the primary";
    EXPECT_EQ(view.sibling_keys, 3u);
    EXPECT_EQ(view.dirty, core::SharechainLevelDBStore::kCleanClose);
    std::filesystem::remove_all(dir);
}

// The rollback hazard: an earlier binary runs on the store in between (it
// prunes the orphan at height 5 with its unguarded delete, which also takes
// the main share's `height:5`, knows nothing of `hsib:` keys, and closes
// cleanly with dirty=0). The next open by this binary sees dirty != 2 and
// rebuilds: height 5 is whole again and the stale sibling key is gone.
TEST(SharechainHeightIndex, AnEarlierBinaryRunningInBetweenIsRepairedOnOpen)
{
    for (const uint8_t left_by_old_binary : {uint8_t{0}, uint8_t{1}}) {
        SCOPED_TRACE(left_by_old_binary ? "old binary crashed (dirty=1)" : "old binary stopped cleanly (dirty=0)");
        const auto dir = fresh_dir("rollback");
        std::string db_path;
        std::vector<uint256> main;
        const uint256 orphan = H(0x2005);
        {
            core::SharechainLevelDBStore st(dir.string(), "kat");
            ASSERT_TRUE(st.open());
            db_path = st.db_path();
            main = store_main(st, 8);
            ASSERT_TRUE(st.store_share(orphan, kBlob, meta_at(H(0x1004), 5)));
            st.close();
        }
        {
            // The earlier binary: remove_share(orphan) = delete its share and
            // index records and height:5, whatever height:5 held.
            core::LevelDBStore raw(db_path, core::LevelDBOptions{});
            ASSERT_TRUE(raw.open());
            raw.remove("share:" + orphan.ToString());
            raw.remove("index:" + orphan.ToString());
            raw.remove(height_key(5));
            raw.put("dirty", std::vector<uint8_t>{left_by_old_binary});
            raw.close();
        }
        {
            core::SharechainLevelDBStore st(dir.string(), "kat");
            ASSERT_TRUE(st.open());
            EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX), main) << "rebuilt: no hole at 5";
            st.close();
        }
        const auto view = old_reader_view(db_path);
        EXPECT_EQ(view.heights.at(5), std::optional<uint256>(main[4]));
        EXPECT_EQ(view.sibling_keys, 0u) << "the sibling key of the removed orphan is gone";
        std::filesystem::remove_all(dir);
    }
}

// The rebuild makes the best-chain share the primary of its height, even when
// a fork share of that height sorts first: what an earlier reader (or the
// DASH chain auditor) sees after a rebuild is the chain.
TEST(SharechainHeightIndex, TheRebuildPicksTheBestChainShareAsPrimary)
{
    const auto dir = fresh_dir("best_chain");
    std::string db_path;
    std::vector<uint256> main;
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        db_path = st.db_path();
        // A fork share at height 7 stored first, with a hash that sorts before
        // main[6] (0x1007): before the rebuild it is height 7's primary.
        ASSERT_TRUE(st.store_share(H(0x0007), kBlob, meta_at(H(0x1006), 7)));
        main = store_main(st, 10);
        st.close();
    }
    EXPECT_EQ(old_reader_view(db_path).heights.at(7), std::optional<uint256>(H(0x0007)));
    {
        core::LevelDBStore raw(db_path, core::LevelDBOptions{});
        ASSERT_TRUE(raw.open());
        raw.put("dirty", std::vector<uint8_t>{1});   // a crash: the next open rebuilds
        raw.close();
    }
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        EXPECT_EQ(st.get_shares_by_height_range(7, 7).size(), 2u) << "both shares of height 7 kept";
        st.close();
    }
    const auto view = old_reader_view(db_path);
    for (uint64_t h = 1; h <= 10; ++h)
        EXPECT_EQ(view.heights.at(h), std::optional<uint256>(main[h - 1])) << "height " << h;
    EXPECT_EQ(view.sibling_keys, 1u);
    std::filesystem::remove_all(dir);
}

// A store this binary closed cleanly is trusted: no rebuild on every start.
// (Seen through a height key removed behind its back: it stays removed.)
TEST(SharechainHeightIndex, AStoreClosedByThisBinaryIsTrusted)
{
    const auto dir = fresh_dir("trusted");
    std::string db_path;
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        db_path = st.db_path();
        store_main(st, 4);
        st.close();
    }
    {
        core::LevelDBStore raw(db_path, core::LevelDBOptions{});
        ASSERT_TRUE(raw.open());
        std::vector<uint8_t> d;
        ASSERT_TRUE(raw.get("dirty", d));
        ASSERT_EQ(d, std::vector<uint8_t>{core::SharechainLevelDBStore::kCleanClose});
        raw.remove(height_key(2));
        raw.close();
    }
    core::SharechainLevelDBStore st(dir.string(), "kat");
    ASSERT_TRUE(st.open());
    EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX).size(), 3u);
    st.close();
    std::filesystem::remove_all(dir);
}
