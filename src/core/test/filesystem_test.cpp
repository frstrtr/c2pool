// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression test for the --data-dir isolation chokepoint (issue #722).
// Lives in the core_test executable (already built + run in CI) so it is
// exercised without a dedicated build.yml --target entry.
//
// core::filesystem::config_path() is the single root every per-instance state
// path derives from (sharechain LevelDB, addr store, whitelist, ratchet,
// found-blocks db, logs). This test pins its resolution order so co-located
// instances can each own an isolated namespace:
//
//   1. --data-dir PATH  -> set_data_dir()   (operator-supplied CLI flag)
//   2. historical platform default          (byte-for-byte unchanged)
//
// The default-parity case is the ship-critical invariant: with no --data-dir
// set, config_path() MUST return the exact prior expression so single-instance
// deployments are unaffected.

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <string>

#include <core/filesystem.hpp>

namespace fs = std::filesystem;

namespace {

// Recompute the historical default independently of config_path() so the
// parity assertion is a genuine cross-check, not a tautology.
fs::path historical_default()
{
#ifdef _WIN32
    const char* base = std::getenv("APPDATA");
    return fs::path(base ? base : ".") / "c2pool";
#else
    const char* base = std::getenv("HOME");
    return fs::path(base ? base : ".") / ".c2pool";
#endif
}

// Fixture that clears the override before and after each test so tests do not
// leak process-wide state into one another (config_path() reads it).
class DataDirTest : public ::testing::Test {
protected:
    void SetUp() override    { core::filesystem::set_data_dir(""); }
    void TearDown() override { core::filesystem::set_data_dir(""); }
};

// Tier 2: no --data-dir -> exact historical default (ship-critical parity).
TEST_F(DataDirTest, DefaultUnchangedWhenUnset)
{
    EXPECT_EQ(core::filesystem::config_path(), historical_default());
}

// Tier 1: --data-dir (set_data_dir) overrides the platform default.
TEST_F(DataDirTest, CliOverrideTakesEffect)
{
    core::filesystem::set_data_dir("/tmp/c2pool_cli_instY");
    EXPECT_EQ(core::filesystem::config_path(), fs::path("/tmp/c2pool_cli_instY"));
}

// Clearing the override falls back to the default again (no sticky state).
TEST_F(DataDirTest, ClearOverrideFallsBack)
{
    core::filesystem::set_data_dir("/tmp/c2pool_cli_instY");
    ASSERT_EQ(core::filesystem::config_path(), fs::path("/tmp/c2pool_cli_instY"));
    core::filesystem::set_data_dir("");
    EXPECT_EQ(core::filesystem::config_path(), historical_default());
}

// The isolation guarantee itself: two distinct --data-dir values yield two
// distinct, non-overlapping state roots (each gets its own LevelDB namespace,
// so neither contends the other's LOCK).
TEST_F(DataDirTest, TwoInstancesGetDistinctRoots)
{
    core::filesystem::set_data_dir("/tmp/c2pool_instA");
    const fs::path a = core::filesystem::config_path();
    core::filesystem::set_data_dir("/tmp/c2pool_instB");
    const fs::path b = core::filesystem::config_path();

    EXPECT_NE(a, b);
    // The paths derived downstream (e.g. the sharechain LevelDB) stay disjoint.
    EXPECT_NE(a / "sharechain_leveldb", b / "sharechain_leveldb");
}

} // namespace
