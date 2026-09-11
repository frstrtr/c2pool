// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/stratum_types.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface local_share_hash_rates (share-derived series).
//
// This series was an ALIAS: rest_web_graph_data("local_share_hash_rates") and
// feed_history_entry both re-emitted entry.local_hash_rates -- the MEASURED
// RateMonitor hashrate -- so the "share hash rate" graph was a duplicate of the
// local-hashrate graph and never reflected actual accepted-share work. The fix
// gives it its own StatLogEntry field, computed in update_stat_log() from the
// SAME per-worker accepted+vardiff the getstats path reports:
//     rate[addr] = (accepted_delta) * vardiff_difficulty * 2^32 / dt
// aggregated by payout address, persisted under key "lshr".
//
// Honesty rules these lock, both directions:
//   * FIRST TICK (no previous accepted baseline): honest-absent -- an EMPTY
//     object, NOT the measured-hashrate alias. A share-work rate cannot be
//     known from a single sample, so it must not fabricate one.
//   * STEADY STATE: the value is the real accepted-share-work rate for the
//     interval, DISTINCT from the measured RateMonitor hashrate.
//
// Both FAIL WITHOUT THE FIX: pre-fix there is no "lshr" field (serialize omits
// it, the key is absent) and the series aliased local_hash_rates, so the
// empty-first-tick and the derived-value assertions both fail.
// ---------------------------------------------------------------------------

namespace {

constexpr double kTwo32 = 4294967296.0;  // 2^32

struct TempStatDir {
    std::filesystem::path dir;
    explicit TempStatDir(const char* name) {
        dir = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
    }
    ~TempStatDir() { std::filesystem::remove_all(dir); }
    std::string path(const char* leaf) const { return (dir / leaf).string(); }
};

nlohmann::json read_stat_log(const std::string& path) {
    std::ifstream f(path);
    EXPECT_TRUE(static_cast<bool>(f)) << "stat-log file must exist: " << path;
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto arr = nlohmann::json::parse(content);
    EXPECT_TRUE(arr.is_array());
    return arr;
}

core::stratum::WorkerInfo make_worker(const std::string& user, uint64_t accepted,
                                      double difficulty, double measured_hr) {
    core::stratum::WorkerInfo w;
    w.username = user;
    w.accepted = accepted;
    w.difficulty = difficulty;
    w.hashrate = measured_hr;  // the MEASURED rate the old alias echoed
    return w;
}

}  // namespace

// FIRST TICK: honest-absent empty object, NOT the measured-hashrate alias, and
// the field is serialized under its own "lshr" key (round-trips independently
// of the measured "lhr" series).
TEST(LocalShareHashRates, FirstTickHonestAbsentNotMeasuredAlias) {
    TempStatDir tmp("core_lshr_first_tick_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    const double kMeasured = 5.0e6;  // ~5 MH/s measured on the RateMonitor seam
    mi.set_stratum_workers_fn([&]() {
        std::map<std::string, core::stratum::WorkerInfo> m;
        m["s1"] = make_worker("addrA", /*accepted=*/100, /*difficulty=*/1000.0, kMeasured);
        return m;
    });

    mi.update_stat_log();
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(1));

    ASSERT_TRUE(arr[0].contains("lshr"))
        << "share-hash-rate series must serialize under its own key, not alias lhr";
    EXPECT_TRUE(arr[0]["lshr"].is_object());
    EXPECT_TRUE(arr[0]["lshr"].empty())
        << "first tick has no accepted-share baseline: honest-absent, not a "
           "fabricated rate and not the measured-hashrate alias";

    // Sanity: the measured series IS populated, so the empty share series above
    // is a real distinction (fix dropped the alias), not just no workers.
    ASSERT_TRUE(arr[0]["lhr"].contains("addrA"));
    EXPECT_DOUBLE_EQ(arr[0]["lhr"]["addrA"].get<double>(), kMeasured);
}

// STEADY STATE: with an accepted-share delta over a real interval, the series
// is the derived share-work rate (accepted_delta * vardiff * 2^32 / dt),
// distinct from the measured hashrate; and it deserializes on a fresh instance.
TEST(LocalShareHashRates, DerivedFromAcceptedDeltaAcrossTicks) {
    TempStatDir tmp("core_lshr_derived_kat");
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));

    const double kDiff = 1000.0;
    const double kMeasured = 5.0e6;
    uint64_t accepted = 100;
    mi.set_stratum_workers_fn([&]() {
        std::map<std::string, core::stratum::WorkerInfo> m;
        m["s1"] = make_worker("addrA", accepted, kDiff, kMeasured);
        return m;
    });

    mi.update_stat_log();                 // baseline tick, accepted=100
    const uint64_t kDelta = 50;
    accepted += kDelta;                    // 50 accepted shares since baseline
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));  // guarantee dt >= 1s
    mi.update_stat_log();                 // derives from the delta
    mi.save_stat_log();

    auto arr = read_stat_log(tmp.path("graph_db"));
    ASSERT_EQ(arr.size(), static_cast<std::size_t>(2));

    EXPECT_TRUE(arr[0]["lshr"].empty()) << "first tick still honest-absent";

    const double dt = arr[1]["t"].get<double>() - arr[0]["t"].get<double>();
    ASSERT_GT(dt, 0.0);
    const double expected = static_cast<double>(kDelta) * kDiff * kTwo32 / dt;

    ASSERT_TRUE(arr[1]["lshr"].contains("addrA"));
    const double got = arr[1]["lshr"]["addrA"].get<double>();
    EXPECT_NEAR(got, expected, expected * 1e-9)
        << "steady-state share rate must equal accepted_delta*vardiff*2^32/dt";
    EXPECT_GT(got, kMeasured)
        << "derived share-work rate must be its own series, not the measured alias";

    // Deserialize on a fresh instance: the persisted share series reloads and the
    // graph dispatch serves the derived field (not the measured alias).
    core::MiningInterface mi2(/*testnet=*/false, /*node=*/nullptr,
                              c2pool::address::Blockchain::LITECOIN);
    mi2.set_stat_log_path(tmp.path("graph_db"));
    mi2.load_stat_log();
    auto series = mi2.rest_web_graph_data("local_share_hash_rates", "last_hour");
    ASSERT_TRUE(series.is_array());
    ASSERT_EQ(series.size(), static_cast<std::size_t>(2));
    // series entry = [t, {addr: rate}, width, 0]; last entry carries the delta.
    ASSERT_TRUE(series[1][1].is_object());
    ASSERT_TRUE(series[1][1].contains("addrA"));
    EXPECT_NEAR(series[1][1]["addrA"].get<double>(), expected, expected * 1e-9)
        << "deserialized+dispatched series must match the derived rate";
}
