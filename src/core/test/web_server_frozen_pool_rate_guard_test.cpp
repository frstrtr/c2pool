// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

// ---------------------------------------------------------------------------
// KATs for the frozen-estimator graph-store guard (dash.voidbind.com 48.96 TH/s
// rectangle). A live pool-rate estimator recomputed every stat-log tick over a
// sliding share window essentially never returns the same bit-identical
// nonzero double for many consecutive ticks (empirical ceiling on live data:
// 4). When an upstream latch freezes, the stuck value used to be recorded
// verbatim for hours and PERSISTED into graph_db, so the plateau kept
// rendering after the estimator itself was fixed and even across restarts.
//
// Two independent layers under test, both coin-generic in core::MiningInterface:
//   1. INGEST guard (update_stat_log): after kMaxIdenticalPoolRateRun (10)
//      consecutive bit-identical nonzero samples, record honest-absent 0.0
//      so the graph breaks instead of extending a fabricated rectangle.
//   2. LOAD sanitizer (load_stat_log): zero any persisted run LONGER than the
//      ingest guard could ever write (pre-guard pollution), including the
//      desired_versions series derived from the frozen value, and force the
//      binned views to re-seed from the sanitized flat log.
//
// All of these FAIL WITHOUT THE FIX: pre-guard, every frozen sample is
// recorded and reloaded verbatim.
// ---------------------------------------------------------------------------

namespace {

// The literal frozen constant observed live (48.96 TH/s, whale-era estimate
// latched by a stuck verified-best election on a zero-local-mint relay).
constexpr double kFrozen = 48959943024877.0;

// Matches MiningInterface::kMaxIdenticalPoolRateRun (private); the KATs pin
// the behavioral contract — if the threshold changes, these numbers must too.
constexpr int kMaxRun = 10;

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
    TempStatDir(const char* name)
    {
        dir = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
    }
    ~TempStatDir() { std::filesystem::remove_all(dir); }
    std::string path(const char* leaf) const { return (dir / leaf).string(); }
};

}  // namespace

// INGEST: a bit-identical nonzero estimator is recorded for at most kMaxRun
// consecutive samples; every subsequent sample of the freeze is honest-absent
// 0.0 (the graph BREAKS instead of extending the rectangle).
TEST(FrozenPoolRateGuard, IngestZeroesAfterIdenticalRunThreshold) {
    TempStatDir tmp("core_frozen_phr_ingest_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));
    mi.set_pool_hashrate_fn([]() { return kFrozen; });

    const int kTicks = kMaxRun + 5;
    for (int i = 0; i < kTicks; ++i) mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(kTicks));
    for (int i = 0; i < kMaxRun; ++i)
        EXPECT_EQ(arr[i]["phr"].get<double>(), kFrozen)
            << "sample " << i << " is within the plausible identical run";
    for (int i = kMaxRun; i < kTicks; ++i)
        EXPECT_EQ(arr[i]["phr"].get<double>(), 0.0)
            << "sample " << i << " must be honest-absent once the run is "
               "implausibly long";
}

// INGEST: a live (varying) estimator is never touched — every sample recorded
// verbatim, including immediately after a freeze ends.
TEST(FrozenPoolRateGuard, IngestVaryingEstimatorRecordedVerbatim) {
    TempStatDir tmp("core_frozen_phr_varying_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    // Phase 1: freeze long enough to trip the guard.
    mi.set_pool_hashrate_fn([]() { return kFrozen; });
    for (int i = 0; i < kMaxRun + 3; ++i) mi.update_stat_log();
    // Phase 2: the estimator recovers and moves again.
    double live = 8.5e12;
    mi.set_pool_hashrate_fn([&live]() { return live += 1.0e9; });
    const int kLiveTicks = 6;
    for (int i = 0; i < kLiveTicks; ++i) mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(kMaxRun + 3 + kLiveTicks));
    // Recovery: every post-freeze sample is nonzero and strictly increasing.
    double prev = 0.0;
    for (std::size_t i = kMaxRun + 3; i < arr.size(); ++i) {
        const double v = arr[i]["phr"].get<double>();
        EXPECT_GT(v, prev) << "recovered live samples must be recorded verbatim";
        prev = v;
    }
}

// LOAD: a persisted run longer than the ingest guard could ever write is
// pre-guard pollution — zero it (and the desired_versions derived from it) on
// load, while short legitimate runs and varying samples survive untouched.
TEST(FrozenPoolRateGuard, LoadSanitizesLongFrozenRunAndDerivedVersions) {
    TempStatDir tmp("core_frozen_phr_load_kat");
    const std::string polluted = tmp.path("graph_db");
    const std::string reload = tmp.path("graph_db.reload");

    // Craft a polluted store: [4 varying] [12 frozen w/ dv] [4-run identical]
    // [3 varying]. Only the 12-run is beyond what the ingest guard can write.
    const double now = static_cast<double>(std::time(nullptr));
    nlohmann::json arr = nlohmann::json::array();
    double t = now - 3600.0;
    auto push = [&](double phr, nlohmann::json dv) {
        arr.push_back({{"t", t}, {"phr", phr}, {"dv", std::move(dv)}});
        t += 60.0;
    };
    for (int i = 0; i < 4; ++i) push(7.0e12 + i * 1.0e10, {});
    for (int i = 0; i < 12; ++i) push(kFrozen, {{"16", kFrozen}});
    const double kShortRunVal = 6.5e12;
    for (int i = 0; i < 4; ++i) push(kShortRunVal, {});
    for (int i = 0; i < 3; ++i) push(8.0e12 + i * 1.0e10, {});
    { std::ofstream f(polluted); f << arr.dump(); }

    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(polluted);
    mi.load_stat_log();
    // Re-flush to a second path to observe what was loaded (pattern of the
    // B-STATS.944 shutdown KAT — no core-size getter is added for tests).
    mi.set_stat_log_path(reload);
    mi.save_stat_log();

    auto out = read_stat_log(reload);
    ASSERT_EQ(out.size(), arr.size());
    for (int i = 0; i < 4; ++i)
        EXPECT_NE(out[i]["phr"].get<double>(), 0.0) << "varying head survives";
    for (int i = 4; i < 16; ++i) {
        EXPECT_EQ(out[i]["phr"].get<double>(), 0.0)
            << "frozen sample " << i << " must be purged on load";
        EXPECT_EQ(out[i]["dv"]["16"].get<double>(), 0.0)
            << "desired_versions derived from the frozen value must be purged";
    }
    for (int i = 16; i < 20; ++i)
        EXPECT_EQ(out[i]["phr"].get<double>(), kShortRunVal)
            << "a short identical run (<= threshold) is legitimate and kept";
    for (int i = 20; i < 23; ++i)
        EXPECT_NE(out[i]["phr"].get<double>(), 0.0) << "varying tail survives";
}
