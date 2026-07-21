// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression test for the --data-dir isolation chokepoint (issue #722).
// Lives in the core_test executable (already built + run in CI) so it is
// exercised without a dedicated build.yml --target entry.
//
// core::filesystem::config_path() is the single root every per-instance state
// path derives from (sharechain LevelDB, addr store, whitelist, ratchet,
// found-blocks db, logs, crash/block hex dumps). This test pins its three-tier
// resolution order so co-located instances can each own an isolated namespace:
//
//   1. --data-dir PATH  -> set_data_dir()      (highest priority)
//   2. C2POOL_DATA_DIR  -> environment         (config-less isolation)
//   3. historical platform default             (byte-for-byte unchanged)
//
// The default-parity case is the ship-critical invariant: with neither the
// flag nor the env var set, config_path() MUST return the exact prior
// expression so single-instance deployments are unaffected.

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

const char* kEnvVar = "C2POOL_DATA_DIR";

// Fixture that snapshots and restores the override + env var so tests do not
// leak process-wide state into one another (config_path() reads both).
class DataDirTest : public ::testing::Test {
protected:
    void SetUp() override {
        core::filesystem::set_data_dir("");   // clear CLI override
        if (const char* prev = std::getenv(kEnvVar))
            m_saved_env = std::string(prev);
        unsetenv(kEnvVar);
    }
    void TearDown() override {
        core::filesystem::set_data_dir("");
        if (m_saved_env.has_value())
            setenv(kEnvVar, m_saved_env->c_str(), 1);
        else
            unsetenv(kEnvVar);
    }
    std::optional<std::string> m_saved_env;
};

// Tier 3: neither flag nor env -> exact historical default (ship-critical).
TEST_F(DataDirTest, DefaultUnchangedWhenUnset)
{
    EXPECT_EQ(core::filesystem::config_path(), historical_default());
}

// Tier 2: env var wins over the platform default.
TEST_F(DataDirTest, EnvOverrideTakesEffect)
{
    setenv(kEnvVar, "/tmp/c2pool_env_instX", 1);
    EXPECT_EQ(core::filesystem::config_path(), fs::path("/tmp/c2pool_env_instX"));
}

// Tier 1: --data-dir (set_data_dir) wins over BOTH env and default.
TEST_F(DataDirTest, CliOverrideBeatsEnv)
{
    setenv(kEnvVar, "/tmp/c2pool_env_instX", 1);
    core::filesystem::set_data_dir("/tmp/c2pool_cli_instY");
    EXPECT_EQ(core::filesystem::config_path(), fs::path("/tmp/c2pool_cli_instY"));
}

// Clearing the override falls back through the chain again (no sticky state).
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
