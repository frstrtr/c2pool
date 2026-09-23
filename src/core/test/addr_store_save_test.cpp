// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression test for issue #1719: core::AddrStore persistence (addrs.json).
// Lives in the core_test executable (already built + run in CI) -- never a new
// add_executable (the #769 "Not Run" trap). AddrStore is the one shared peer
// book behind every coin lane, so one KAT covers all of them.
//
// Drives the REAL core::AddrStore against a real file under an isolated
// set_data_dir() root. No mocks.
//
// Defects pinned (every TEST below except the two no-op ones fails on the
// pre-fix save()/remove()/from_json()):
//   1. save() opened std::fstream(m_path) = in|out with NO truncate. A shorter
//      document left the previous tail behind, the file stopped parsing, and
//      the next boot's from_json() logged a warning and dropped the whole book.
//   2. A legacy [[[k,v],...]] file (old brace-init to_json) is rewritten two
//      bytes shorter on its first save, so (1) corrupts it deterministically.
//   3. in|out never creates a missing file, so a save after addrs.json was
//      deleted underneath the store silently wrote nothing.
//   4. remove() had its guard inverted: it returned early when the entry
//      EXISTED and erased nothing.
//   5. from_json()'s legacy unwrap ("size 1 and element 0 is an array") also
//      matched a CURRENT one-entry book [[k,v]], unwrapped it to [k,v], and
//      failed the parse: a store holding exactly one peer never reloaded.

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include <unistd.h>

#include <core/addr_store.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

namespace {

constexpr const char* kCoin = "addr_store_1719";
// A realistic 10-digit unix timestamp; replacing it with 0 shrinks the JSON.
constexpr uint64_t kTs = 1785747656;

std::string read_file(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool parses(const fs::path& p)
{
    try {
        (void)nlohmann::json::parse(read_file(p));
        return true;
    } catch (const nlohmann::json::exception&) {
        return false;
    }
}

NetService peer(int n) { return NetService("10.0.0." + std::to_string(n), uint16_t{9999}); }

class AddrStoreSaveTest : public ::testing::Test {
protected:
    fs::path root;
    fs::path path;

    void SetUp() override
    {
        root = fs::temp_directory_path() / ("c2pool_addr_store_1719_" + std::to_string(::getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        core::filesystem::set_data_dir(root);
        path = root / kCoin / "addrs.json";
    }

    void TearDown() override
    {
        core::filesystem::set_data_dir("");
        std::error_code ec;
        fs::remove_all(root, ec);
    }
};

} // namespace

// (1) A rewrite that shrinks the document must leave a parseable file that
// round-trips on the next boot.
TEST_F(AddrStoreSaveTest, ShorterRewriteLeavesNoStaleTail)
{
    {
        core::AddrStore s(kCoin);
        for (int i = 1; i <= 3; ++i)
            s.add(peer(i), {1, kTs, kTs});
        ASSERT_TRUE(parses(path)) << read_file(path);
        const auto long_size = fs::file_size(path);

        for (int i = 1; i <= 3; ++i)
            s.update(peer(i), {0, 0, 0});
        EXPECT_LT(fs::file_size(path), long_size) << "file kept its old length: " << read_file(path);
        EXPECT_TRUE(parses(path)) << "stale tail after shorter rewrite: " << read_file(path);
    }

    core::AddrStore reloaded(kCoin);
    EXPECT_EQ(reloaded.len(), 3u) << "peer book lost on reload";
    EXPECT_EQ(reloaded.get(peer(2)).m_last_seen, 0u);

    // Nothing but addrs.json may be left in the store directory.
    int entries = 0;
    for (const auto& e : fs::directory_iterator(root / kCoin)) { (void)e; ++entries; }
    EXPECT_EQ(entries, 1);
}

// (2) A legacy [[[k,v],...]] file loads via the unwrap in from_json(); its first
// save is two bytes shorter and must not leave the old "]]" behind.
TEST_F(AddrStoreSaveTest, LegacyWrappedFileSurvivesFirstSave)
{
    std::map<NetService, core::AddrValue> book{{peer(1), {1, kTs, kTs}}};
    const nlohmann::json legacy = nlohmann::json::array({nlohmann::json(book)});
    const std::string legacy_str = legacy.dump();
    ASSERT_EQ(legacy_str.rfind("[[[", 0), 0u) << "fixture is not the legacy wrapped form: " << legacy_str;

    fs::create_directories(path.parent_path());
    { std::ofstream f(path); f << legacy_str; }

    {
        core::AddrStore s(kCoin);
        ASSERT_EQ(s.len(), 1u) << "legacy unwrap on load regressed";
        s.update(peer(1), {1, kTs, kTs});
        EXPECT_TRUE(parses(path)) << "legacy file corrupted by first save: " << read_file(path);
    }

    core::AddrStore reloaded(kCoin);
    EXPECT_EQ(reloaded.len(), 1u) << "peer book lost on reload";
}

// (3) If addrs.json is deleted underneath a live store, the next save must
// recreate it rather than silently write nothing.
TEST_F(AddrStoreSaveTest, SaveRecreatesMissingFile)
{
    core::AddrStore s(kCoin);
    ASSERT_TRUE(fs::exists(path));
    fs::remove(path);

    s.add(peer(1), {1, kTs, kTs});
    ASSERT_TRUE(fs::exists(path)) << "save() did not create the missing file";
    EXPECT_TRUE(parses(path)) << read_file(path);

    core::AddrStore reloaded(kCoin);
    EXPECT_EQ(reloaded.len(), 1u);
}

// (4) remove() must erase a present entry, in memory and on disk.
TEST_F(AddrStoreSaveTest, RemoveErasesPresentEntry)
{
    {
        core::AddrStore s(kCoin);
        s.add(peer(1), {1, kTs, kTs});
        s.add(peer(2), {1, kTs, kTs});

        s.remove(peer(1));
        EXPECT_FALSE(s.check(peer(1))) << "remove() left a present entry in place";
        EXPECT_TRUE(s.check(peer(2)));
        EXPECT_TRUE(parses(path)) << read_file(path);
    }

    core::AddrStore reloaded(kCoin);
    EXPECT_FALSE(reloaded.check(peer(1))) << "removed entry came back on reload";
    EXPECT_EQ(reloaded.len(), 1u);
}

// remove() of an absent entry is a no-op (passes before and after the fix).
TEST_F(AddrStoreSaveTest, RemoveAbsentIsNoOp)
{
    core::AddrStore s(kCoin);
    s.add(peer(1), {1, kTs, kTs});
    s.remove(peer(7));
    EXPECT_EQ(s.len(), 1u);
    EXPECT_TRUE(parses(path)) << read_file(path);
}

// (5) A current-format one-entry book [[k,v]] must reload. Isolated from (1)-(3):
// the file only ever grows here, so no stale tail and no missing file.
TEST_F(AddrStoreSaveTest, SingleEntryBookRoundTrips)
{
    {
        core::AddrStore s(kCoin);
        s.add(peer(1), {1, kTs, kTs});
        ASSERT_TRUE(parses(path)) << read_file(path);
    }

    core::AddrStore reloaded(kCoin);
    EXPECT_EQ(reloaded.len(), 1u) << "one-entry book taken for the legacy wrapped form: " << read_file(path);
    EXPECT_TRUE(reloaded.check(peer(1)));
}

// The legacy wrapped form of an EMPTY book, [[]], still loads as empty
// (passes before and after the fix).
TEST_F(AddrStoreSaveTest, LegacyWrappedEmptyBookLoadsEmpty)
{
    fs::create_directories(path.parent_path());
    { std::ofstream f(path); f << "[[]]"; }
    core::AddrStore s(kCoin);
    EXPECT_EQ(s.len(), 0u);
}
