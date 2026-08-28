// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <cstddef>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

// ---------------------------------------------------------------------------
// KATs for the daemonless graph-store feed fix (dash.voidbind.com ~6 days of
// all-zero /web/graph_data series on the fully-daemonless canary).
//
// Two coin-generic contracts in core::MiningInterface are pinned here:
//
//   (1) network_difficulty is FED, not fabricated. On a zero-rig relay no
//       stratum template exists, so the atomic stayed 0 and the netdiff graph
//       was a flat zero line. The daemonless think-tick now pushes the embedded
//       header follower's difficulty via update_network_difficulty(); once fed,
//       the sample carries the live value. Before any feed it is honest-absent
//       (0), never a fabricated number.
//
//   (2) unique_miner_count falls back to the pool-wide sharechain payout-address
//       count (shares_by_miner.size(), the same value /global_stats reports as
//       unique_miners) when the LOCAL stratum registry is empty — the daemonless
//       relay case. With no sharechain seam and no local workers it stays 0
//       (honest-absent, never fabricated).
//
// Observed through the persisted flat stat-log ("nd" / "mc" fields), the same
// public surface the frozen-pool-rate KATs use.
// ---------------------------------------------------------------------------

namespace {

nlohmann::json read_stat_log(const std::string& path)
{
    std::ifstream f(path);
    EXPECT_TRUE(static_cast<bool>(f)) << "stat-log file must exist: " << path;
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto arr = nlohmann::json::parse(content);
    EXPECT_TRUE(arr.is_array());
    return arr;
}

struct TempStatDir {
    std::filesystem::path dir;
    explicit TempStatDir(const char* name)
    {
        dir = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
    }
    ~TempStatDir() { std::filesystem::remove_all(dir); }
    std::string path(const char* leaf) const { return (dir / leaf).string(); }
};

}  // namespace

// (1a) A daemonless relay with no work source yet recorded honest-absent 0 for
// network_difficulty — never a fabricated value.
TEST(DaemonlessGraphFeed, NetworkDifficultyHonestAbsentBeforeFeed) {
    TempStatDir tmp("core_dl_graph_nd_absent");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), 1u);
    EXPECT_EQ(arr[0]["nd"].get<double>(), 0.0)
        << "no feed -> honest-absent 0, not a fabricated difficulty";
}

// (1b) Once the daemonless header-follower feed reaches the atomic (simulating
// the think-tick's update_network_difficulty from the maintainer's published
// bits), the sample carries the live value instead of a zero.
TEST(DaemonlessGraphFeed, NetworkDifficultyRecordedOnceFed) {
    TempStatDir tmp("core_dl_graph_nd_fed");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    constexpr double kNetDiff = 1234567.5;
    mi.update_network_difficulty(kNetDiff, "header-tip");
    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), 1u);
    EXPECT_DOUBLE_EQ(arr[0]["nd"].get<double>(), kNetDiff)
        << "a fed difficulty must reach the graph store verbatim";
}

// (2a) With no local stratum workers but a live sharechain, unique_miner_count
// falls back to the pool-wide distinct payout-address count (shares_by_miner
// size) — the '4' the daemonless canary's /global_stats reports.
TEST(DaemonlessGraphFeed, UniqueMinerCountFallsBackToSharechainWhenLocalEmpty) {
    TempStatDir tmp("core_dl_graph_umc_fallback");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    // No stratum server wired -> the local worker registry is genuinely empty.
    mi.set_sharechain_stats_fn([]() {
        nlohmann::json sc = nlohmann::json::object();
        nlohmann::json by_miner = nlohmann::json::object();
        by_miner["Xaddr1"] = 10;
        by_miner["Xaddr2"] = 7;
        by_miner["Xaddr3"] = 3;
        by_miner["Xaddr4"] = 1;
        sc["shares_by_miner"] = by_miner;
        return sc;
    });

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), 1u);
    EXPECT_EQ(arr[0]["mc"].get<int>(), 4)
        << "empty local registry -> pool-wide sharechain payout-address count";
}

// (2b) With neither local workers NOR a sharechain seam, unique_miner_count
// stays 0 (honest-absent) — the fallback never fabricates a count.
TEST(DaemonlessGraphFeed, UniqueMinerCountZeroWhenNoSourceAtAll) {
    TempStatDir tmp("core_dl_graph_umc_zero");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), 1u);
    EXPECT_EQ(arr[0]["mc"].get<int>(), 0)
        << "no local workers and no sharechain seam -> honest-absent 0";
}
