// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <chrono>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

// ---------------------------------------------------------------------------
// KATs for #959 worker liveness (SILENT class + active/total).
//
// A tenant rig held an authorized Stratum session for 24h while submitting
// zero shares, and the miner count never moved. These lock the rule that an
// authorized session with no accepted share past the threshold is SILENT and
// is not counted as active.
//
// FAIL WITHOUT THE FIX: classify/observe do not exist, and /local_stats emits
// no stratum_sessions and /stratum_stats no silent fields.
// ---------------------------------------------------------------------------

using core::MiningInterface;
using Clock = std::chrono::steady_clock;
using std::chrono::seconds;

namespace {
MiningInterface::WorkerInfo worker(Clock::time_point connected_at,
                                   double hashrate = 0.0, double difficulty = 1.0,
                                   uint64_t accepted = 0)
{
    MiningInterface::WorkerInfo w;
    w.username = "XaddrD9";
    w.worker_name = "D2";
    w.connected_at = connected_at;
    w.hashrate = hashrate;
    w.difficulty = difficulty;
    w.accepted = accepted;
    return w;
}
}  // namespace

// Authorized, never shared, past the 15-minute floor -> SILENT.
TEST(WorkerLiveness, NeverSharedPastFloorIsSilent) {
    const auto now = Clock::now();
    auto w = worker(now - seconds(MiningInterface::kSilentFloorSeconds + 1));
    auto lv = MiningInterface::classify_worker_liveness(w, std::nullopt, now);
    EXPECT_TRUE(lv.silent);
    EXPECT_FALSE(lv.has_shared);
    EXPECT_EQ(lv.threshold_seconds, MiningInterface::kSilentFloorSeconds);
}

// Fresh session inside the floor is not slandered.
TEST(WorkerLiveness, FreshSessionIsNotSilent) {
    const auto now = Clock::now();
    auto w = worker(now - seconds(60));
    EXPECT_FALSE(MiningInterface::classify_worker_liveness(w, std::nullopt, now).silent);
}

// A slow rig (expected share every 10 min) gets 6 intervals, not 15 minutes.
TEST(WorkerLiveness, ThresholdScalesWithVardiff) {
    const auto now = Clock::now();
    const double diff = 600.0;                 // 600 * 2^32 / 2^32 H/s = 600 s/share
    auto w = worker(now - seconds(7200), 4294967296.0, diff, 3);
    auto last = now - seconds(1800);           // 30 min since last share
    auto lv = MiningInterface::classify_worker_liveness(w, last, now);
    EXPECT_EQ(lv.threshold_seconds, 3600);
    EXPECT_FALSE(lv.silent) << "3 missed intervals is normal variance for a slow rig";
    EXPECT_EQ(lv.silent_seconds, 1800);
}

// No share and no connect time: nothing to measure from, never silent.
TEST(WorkerLiveness, UnknownConnectTimeIsNotSilent) {
    auto w = worker(Clock::time_point{});
    EXPECT_FALSE(MiningInterface::classify_worker_liveness(w, std::nullopt, Clock::now()).silent);
}

// Observer: silence counts from the last time accepted moved, and a share
// re-arms the worker.
TEST(WorkerLiveness, ObserverTracksAcceptedMovement) {
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const auto t0 = Clock::now();
    std::map<std::string, MiningInterface::WorkerInfo> ws{
        {"s1", worker(t0 - seconds(60), 1e9, 1.0, 5)}};

    auto lv = mi.observe_worker_liveness(ws, t0);
    EXPECT_TRUE(lv.at("s1").has_shared);
    EXPECT_FALSE(lv.at("s1").silent);

    // 20 minutes later, accepted unchanged -> silent for 1200 s.
    lv = mi.observe_worker_liveness(ws, t0 + seconds(1200));
    EXPECT_TRUE(lv.at("s1").silent);
    EXPECT_EQ(lv.at("s1").silent_seconds, 1200);

    // One more accepted share -> active again.
    ws["s1"].accepted = 6;
    lv = mi.observe_worker_liveness(ws, t0 + seconds(1260));
    EXPECT_FALSE(lv.at("s1").silent);
    EXPECT_EQ(lv.at("s1").silent_seconds, 0);
}

// /local_stats splits active from silent; /stratum_stats flags the worker.
TEST(WorkerLiveness, LocalAndStratumStatsReportSilent) {
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const auto now = Clock::now();
    mi.register_stratum_worker("dead", worker(now - seconds(3600)));
    auto live = worker(now - seconds(3600));
    live.worker_name = "D4";
    mi.register_stratum_worker("live", live);
    mi.update_stratum_worker("live", 1e9, 0.0, 1.0, 10, 0, 0);

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.contains("stratum_sessions"));
    EXPECT_EQ(r["stratum_sessions"]["total"], 2);
    EXPECT_EQ(r["stratum_sessions"]["active"], 1);
    EXPECT_EQ(r["stratum_sessions"]["silent"], 1);

    auto s = mi.rest_stratum_stats();
    EXPECT_EQ(s["pool"]["connections_silent"], 1);
    EXPECT_EQ(s["pool"]["connections_active"], 1);
    EXPECT_TRUE(s["workers"]["XaddrD9.D2"]["silent"].get<bool>());
    EXPECT_FALSE(s["workers"]["XaddrD9.D4"]["silent"].get<bool>());
}

// Slice B: /local_stats names the silent worker, not just counts it.
TEST(WorkerLiveness, LocalStatsListsSilentWorkers) {
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const auto now = Clock::now();
    mi.register_stratum_worker("dead", worker(now - seconds(3600)));
    auto live = worker(now - seconds(3600));
    live.worker_name = "D4";
    mi.register_stratum_worker("live", live);
    mi.update_stratum_worker("live", 1e9, 0.0, 1.0, 10, 0, 0);

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.contains("workers_silent"));
    ASSERT_EQ(r["workers_silent"].size(), 1u);
    EXPECT_EQ(r["workers_silent"][0]["worker"], "XaddrD9.D2");
    EXPECT_FALSE(r["workers_silent"][0]["has_shared"].get<bool>());
    EXPECT_GE(r["workers_silent"][0]["silent_seconds"].get<int64_t>(), 3600);
}

// A worker is listed only if every connection is silent; longest silence first.
TEST(WorkerLiveness, SilentListGroupsByWorkerAndSorts) {
    const auto now = Clock::now();
    std::map<std::string, MiningInterface::WorkerInfo> ws;
    std::map<std::string, MiningInterface::WorkerLiveness> lv;
    auto add = [&](const std::string& sid, const std::string& name,
                   bool silent, int64_t secs) {
        auto w = worker(now);
        w.worker_name = name;
        ws[sid] = w;
        MiningInterface::WorkerLiveness l;
        l.silent = silent;
        l.silent_seconds = secs;
        l.threshold_seconds = MiningInterface::kSilentFloorSeconds;
        lv[sid] = l;
    };
    add("a1", "D2", true, 2000);
    add("a2", "D2", true, 1000);   // freshest of D2's two silent connections
    add("b1", "D9", true, 5000);
    add("c1", "D4", true, 9000);
    add("c2", "D4", false, 10);    // D4 still has a live connection

    auto out = MiningInterface::silent_workers_list(ws, lv);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0]["worker"], "XaddrD9.D9");
    EXPECT_EQ(out[0]["silent_seconds"], 5000);
    EXPECT_EQ(out[1]["worker"], "XaddrD9.D2");
    EXPECT_EQ(out[1]["silent_seconds"], 1000);
    EXPECT_EQ(out[1]["connections"], 2);
}
