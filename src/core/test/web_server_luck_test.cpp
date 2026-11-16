// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// POOL LUCK AS EFFORT, end to end through the dashboard endpoints.
//
// The audit of 2026-11-16 (master 810c39832): every headline luck figure was
// the arithmetic mean of per-block luck, expected / actual, whose expectation
// is infinite. DASH read 1281 % where blocks found over blocks expected is
// 101 %; an LTC node holding three rows recorded at its own 4 MH/s read
// 4,416,464 %. Per block, the expected time came from ONE hashrate sample at
// find time, the round was timed from the previous row in HEIGHT order
// (orphans included), a block learned from a peer had no luck at all, and a
// merged DOGE block was measured against LTC's difficulty.
//
// These KATs drive the node the way it runs: the pool rate history arrives
// through the persisted stat log (load_stat_log) or the minute tick
// (update_stat_log), blocks through record_found_block and the persistence
// load hook, verdicts through the block verifier; they read /recent_blocks,
// /luck_stats, /recent_merged_blocks, /global_stats and /web/graph_data.
// Nothing but API that predates the change is used, so each KAT also builds
// against the old web_server.cpp -- and fails there (red on master).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <core/web_server.hpp>

using core::MiningInterface;
using c2pool::address::Blockchain;

namespace {

constexpr double kT32 = 4294967296.0;
const std::string kMiner = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";

// A block hash that is unique per tag.
std::string hash_of(unsigned tag)
{
    std::ostringstream os;
    os << std::hex << tag;
    std::string tail = os.str();
    return std::string(64 - tail.size(), 'a') + tail;
}

nlohmann::json find_row(const nlohmann::json& arr, const std::string& key,
                        const std::string& value)
{
    for (const auto& b : arr)
        if (b.contains(key) && b[key].is_string() && b[key].get<std::string>() == value)
            return b;
    return nlohmann::json(nullptr);
}

double num(const nlohmann::json& row, const char* key)
{
    if (!row.is_object() || !row.contains(key) || !row[key].is_number())
        return std::nan("");
    return row[key].get<double>();
}

std::string str(const nlohmann::json& row, const char* key)
{
    if (!row.is_object() || !row.contains(key) || !row[key].is_string())
        return "<absent>";
    return row[key].get<std::string>();
}

struct TempDir {
    std::filesystem::path dir;
    explicit TempDir(const char* name)
    {
        dir = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
    }
    ~TempDir() { std::filesystem::remove_all(dir); }
    std::string path(const char* leaf) const { return (dir / leaf).string(); }
};

// One persisted stat-log sample: the estimator's NON-STALE pool rate, the
// stale proportion and the network difficulty read at `t`.
struct Sample { double t, rate, stale, diff; };

// The node's persisted stat log (graph_db), as save_stat_log writes it.
void write_stat_log(const std::string& path, const std::vector<Sample>& samples)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : samples)
        arr.push_back({{"t", s.t}, {"phr", s.rate}, {"psp", s.stale}, {"nd", s.diff}});
    std::ofstream f(path, std::ios::trunc);
    f << arr.dump();
}

void record(MiningInterface& mi, const std::string& chain, uint64_t height, unsigned tag,
            double ts, double netdiff, double pool_rate, bool attributed = true)
{
    const std::string h = hash_of(tag);
    mi.record_found_block(height, uint256S(h), static_cast<uint64_t>(ts), chain,
                          attributed ? kMiner : "", attributed ? h : "",
                          netdiff, 0.0, pool_rate, 625000000,
                          MiningInterface::BlockAuthorship::sharechain_peer);
}

double now_s() { return static_cast<double>(std::time(nullptr)); }

// A source file with its // comments removed (what the compiler sees of them).
std::string read_code(const std::string& rel)
{
    std::ifstream f(std::string(C2POOL_SRC_ROOT) + "/" + rel);
    EXPECT_TRUE(static_cast<bool>(f)) << rel;
    std::string code, line;
    while (std::getline(f, line)) {
        const auto c = line.find("//");
        code += (c == std::string::npos ? line : line.substr(0, c)) + "\n";
    }
    return code;
}

// The code of the first record_found_block( ... ); call in a source file.
std::string record_call(const std::string& rel)
{
    const std::string src = read_code(rel);
    const auto a = src.find("record_found_block(");
    if (a == std::string::npos) return "";
    const auto b = src.find(");", a);
    return b == std::string::npos ? "" : src.substr(a, b - a);
}

} // namespace

// C1. Effort is the integral of gross pool rate over network difficulty over
// the round. The round [T, T + 4000], from the rate history:
//
//   [T,        T + 1000]  H = 0.25 * 2^32   D = 1000   ->  0.250
//   [T + 1000, T + 2500]  H = 0.50 * 2^32   D = 1000   ->  0.750
//   [T + 2500, T + 4000]  H = 0.50 * 2^32   D = 2000   ->  0.375
//                                               effort =   1.375   luck 72.73 %
//
// The one sample at find time (H = 0.5 * 2^32, D = 2000) says the expected
// time is 4000 s: luck 100 %.
TEST(PoolLuckEndpoints, EffortIsIntegratedOverTheRateHistory)
{
    TempDir tmp("core_luck_integrated_kat");
    const double T = now_s() - 20000.0;
    write_stat_log(tmp.path("graph_db"), {
        {T,          0.25 * kT32, 0.0, 1000.0},
        {T + 1000.0, 0.25 * kT32, 0.0, 1000.0},
        {T + 2500.0, 0.50 * kT32, 0.0, 1000.0},
        {T + 4000.0, 0.50 * kT32, 0.0, 2000.0},
    });
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::LITECOIN);
    mi.set_stat_log_path(tmp.path("graph_db"));
    mi.load_stat_log();
    record(mi, "LTC", 3211000, 1, T, 1000.0, 0.25 * kT32);
    record(mi, "LTC", 3211001, 2, T + 4000.0, 2000.0, 0.50 * kT32);

    const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
    ASSERT_TRUE(row.is_object());
    EXPECT_NEAR(num(row, "effort"), 1.375, 1e-9) << row.dump(1);
    EXPECT_EQ(str(row, "effort_method"), "integrated");
    EXPECT_NEAR(num(row, "history_coverage"), 1.0, 1e-9);
    EXPECT_NEAR(num(row, "time_to_find"), 4000.0, 1e-9);
    EXPECT_NEAR(num(row, "expected_time"), 4000.0 / 1.375, 1e-6);
    EXPECT_NEAR(num(row, "luck"), 100.0 / 1.375, 1e-6)
        << "single sample at find reads 100 %";
    EXPECT_EQ(str(row, "prev_block_hash"), hash_of(1));
    // The mean rate and difficulty the effort ran on, and how many history
    // segments they are the mean of.
    EXPECT_NEAR(num(row, "avg_hashrate_used"), 0.4375 * kT32, 1.0);
    EXPECT_NEAR(num(row, "avg_difficulty_used"), 1375.0, 1e-6);
    EXPECT_EQ(row.value("hashrate_samples_used", 0), 3);
    EXPECT_EQ(row.value("luck_approximate", true), false)
        << "a fully covered, integrated round is not an approximation";
}

// C1 fallback. No rate history over the round: the one sample taken at find
// time, and the row says so.
TEST(PoolLuckEndpoints, RoundWithoutHistoryFallsBackToTheSampleAtFind)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double T = now_s() - 20000.0;
    record(mi, "LTC", 3211000, 1, T, 1000.0, kT32);
    record(mi, "LTC", 3211001, 2, T + 4000.0, 1000.0, kT32);   // 4000 s at 1e-3 / s

    const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
    ASSERT_TRUE(row.is_object());
    EXPECT_NEAR(num(row, "effort"), 4.0, 1e-9) << row.dump(1);
    EXPECT_EQ(str(row, "effort_method"), "single_sample");
    EXPECT_NEAR(num(row, "history_coverage"), 0.0, 1e-12);
    EXPECT_NEAR(num(row, "luck"), 25.0, 1e-9);
    EXPECT_EQ(row.value("luck_approximate", false), true);
}

// C2. DASH, 2026-10-25: 2561418 was timed from the orphaned 2561316
// (15,515 s, effort 1.29). Its round ran from the last main-chain block,
// 2561265: 23,835 s. The verdict arrives AFTER the rows exist, as it does
// live, so the round must move when the orphan is called.
TEST(PoolLuckEndpoints, OrphanIsNeverAPredecessor)
{
    MiningInterface mi(false, nullptr, Blockchain::DASH);
    const double t0 = now_s() - 200000.0;
    const double D = 93611841.0, H = 4.6e13;
    record(mi, "DASH", 2561265, 0x265, t0, D, H);
    record(mi, "DASH", 2561316, 0x316, t0 + 8320.0, D, H);
    record(mi, "DASH", 2561418, 0x418, t0 + 23835.0, D, H);

    mi.set_block_verify_fn([](const std::string& hash) {
        return hash == hash_of(0x316) ? -1 : 12;
    });
    for (unsigned tag : {0x265u, 0x316u, 0x418u})
        mi.run_block_verification_now(hash_of(tag));

    const auto recent = mi.rest_recent_blocks();
    const auto b418 = find_row(recent, "hash", hash_of(0x418));
    const auto b316 = find_row(recent, "hash", hash_of(0x316));
    ASSERT_TRUE(b418.is_object() && b316.is_object());
    ASSERT_EQ(str(b316, "status"), "orphaned");
    EXPECT_NEAR(num(b418, "time_to_find"), 23835.0, 1e-9)
        << "timed from the orphan it reads 15515";
    EXPECT_EQ(str(b418, "prev_block_hash"), hash_of(0x265));
    EXPECT_NEAR(num(b418, "effort"), 23835.0 * H / (D * kT32), 1e-9);
    // The orphan is a find too, timed from the main-chain block before it --
    // but it ends no round and is not a block found.
    EXPECT_NEAR(num(b316, "time_to_find"), 8320.0, 1e-9);
    EXPECT_EQ(str(b316, "prev_block_hash"), hash_of(0x265));

    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck.contains("periods")) << luck.dump(1);
    EXPECT_EQ(luck["periods"]["all"]["k"].get<uint64_t>(), 2u) << "the orphan is not a block found";
    EXPECT_EQ(str(luck["current_round"], "since_block_hash"), hash_of(0x418));
}

// C2 heal. The rows of the LTC canary (ltc.voidbind), restored from disk:
// recorded by an earlier build at the node's OWN stratum rate (~4 MH/s on a
// ~180 GH/s pool), one of them at the share ABSHEIGHT 27,588,573 -- a find
// that never reached the chain (no explorer knows its hash), left "pending"
// for good because the verdict lane waits for the chain to reach that
// height. Nothing derived is stored, so the load recomputes every row from
// its inputs and the rate history; the stored rate itself is put right
// (against the minute samples taken at each block's own time) and written
// back. The phantom ends no round and is not a block found -- once the
// confirm lane has the evidence: the header chain holds the pool's blocks
// from before and after it, and not this one.
TEST(PoolLuckEndpoints, CorruptRowsHealOnLoad)
{
    TempDir tmp("core_luck_heal_kat");
    const double now = std::floor(now_s());
    const double day = 86400.0;
    // An hourly rate history over the last 26 days: ~180 GH/s, D = 9.5e7.
    std::vector<Sample> samples;
    for (int i = 26 * 24; i >= 0; --i)
        samples.push_back({now - i * 3600.0, 1.8e11 + 1.0e6 * (i % 7), 0.0, 9.5e7});
    write_stat_log(tmp.path("graph_db"), samples);

    using FB = MiningInterface::FoundBlock;
    auto stored_row = [](uint64_t height, unsigned tag, double ts, double netdiff,
                         double rate, MiningInterface::BlockStatus status, bool attributed) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(ts);
        b.status = status;
        b.chain = "LTC";
        if (attributed) b.share_hash = b.hash;
        b.network_difficulty = netdiff;
        b.pool_hashrate = rate;
        b.authorship = MiningInterface::BlockAuthorship::sharechain_peer;
        return b;
    };
    const double t0 = now - 25 * day, t1 = now - 22 * day, t2 = now - 14 * day, t3 = now - 2 * day;
    const std::vector<FB> on_disk = {
        stored_row(3160570, 0xa0, t0, 90789408.8, 0.0, MiningInterface::BlockStatus::confirmed, false),
        stored_row(27588573, 0xa1, t1, 91737839.6, 4030409.5, MiningInterface::BlockStatus::pending, true),
        stored_row(3204796, 0xa2, t2, 95864124.3, 4123391.6, MiningInterface::BlockStatus::confirmed, true),
        stored_row(3211872, 0xa3, t3, 94729203.3, 3939911.9, MiningInterface::BlockStatus::confirmed, true),
    };
    std::vector<FB> written;

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([]() { return 1.8e11; });
    mi.update_network_difficulty(9.5e7, "test");
    mi.set_stat_log_path(tmp.path("graph_db"));
    mi.load_stat_log();
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    // The confirm lane re-checks the row left pending. The chain cannot
    // reach its stored height (no verdict), but the header chain holds every
    // real block of the ledger and does not know this hash.
    auto in_header_chain = [](const std::string& hash) {
        return hash == hash_of(0xa0) || hash == hash_of(0xa2) || hash == hash_of(0xa3);
    };
    mi.set_block_field_lookups(
        [&](const std::string& hash) { return in_header_chain(hash) ? 9.5e7 : 0.0; },
        [](const std::string&) { return uint32_t(0); });
    mi.set_block_verify_fn([](const std::string&) { return 0; });
    EXPECT_EQ(mi.run_block_verification_now(hash_of(0xa1)), 0);

    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 4u) << recent.dump(1);
    const auto newest = find_row(recent, "hash", hash_of(0xa3));
    ASSERT_TRUE(newest.is_object());
    // 12 days at ~1.8e11 H/s against D = 9.5e7: effort ~0.457, luck ~219 %.
    const double effort = 12 * day * 1.8e11 / (9.5e7 * kT32);
    EXPECT_NEAR(num(newest, "effort"), effort, effort * 1e-3) << newest.dump(1);
    EXPECT_NEAR(num(newest, "luck"), 100.0 / effort, 100.0 / effort * 1e-3)
        << "from the stored 3.9 MH/s it reads 9,725,567 %";
    EXPECT_EQ(str(newest, "effort_method"), "integrated");
    EXPECT_NEAR(num(newest, "history_coverage"), 1.0, 1e-6);
    // The stored input is repaired, in the row and on disk.
    EXPECT_NEAR(num(newest, "pool_hashrate_at_find"), 1.8e11, 1.8e11 * 1e-3);
    bool rewritten = false;
    for (const auto& b : written)
        if (b.hash == hash_of(0xa3))
            rewritten = std::fabs(b.pool_hashrate - 1.8e11) < 1.8e11 * 1e-3;
    EXPECT_TRUE(rewritten) << "the repaired rate must be persisted";

    // The row at the bogus height is still pending, and the header chain --
    // which holds the pool's blocks from 3 days before it and 8 days after
    // it -- does not hold it: it is no block of the chain for luck. The
    // block after it is timed from the last block that is; the row itself
    // keeps a round (from that same block) for display.
    const auto bogus = find_row(recent, "hash", hash_of(0xa1));
    ASSERT_TRUE(bogus.is_object());
    EXPECT_EQ(str(bogus, "status"), "pending");
    EXPECT_EQ(bogus.value("main_chain", true), false) << bogus.dump(1);
    EXPECT_EQ(str(bogus, "prev_block_hash"), hash_of(0xa0));
    EXPECT_NEAR(num(bogus, "time_to_find"), t1 - t0, 1e-6);
    const auto mid = find_row(recent, "hash", hash_of(0xa2));
    EXPECT_EQ(mid.value("main_chain", false), true);
    EXPECT_EQ(str(mid, "prev_block_hash"), hash_of(0xa0));
    EXPECT_NEAR(num(mid, "time_to_find"), t2 - t0, 1e-6);

    // The headline figure: blocks found over blocks expected. Three blocks
    // (the first as 1 / 1) over 25 days at ~0.038 blocks a day.
    const double per_day = day * 1.8e11 / (9.5e7 * kT32);
    const double want = 100.0 * 3.0 / (1.0 + 25.0 * per_day);
    EXPECT_EQ(recent[0].value("blocks_for_luck", uint64_t(0)), 3u);
    EXPECT_NEAR(num(recent[0], "pool_avg_luck"), want, want * 2e-3)
        << "the mean of per-block luck read 4,416,464 %: " << recent[0].dump(1);
}

// C4. A block learned from a peer with no local record ("relayed") has a
// round, an effort and a luck like any other; luck_method keeps naming its
// provenance.
TEST(PoolLuckEndpoints, RelayedRowGetsALuck)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double T = now_s() - 20000.0;
    record(mi, "LTC", 3211000, 1, T, 1000.0, kT32);
    record(mi, "LTC", 3211001, 2, T + 2000.0, 1000.0, kT32, /*attributed=*/false);

    const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
    ASSERT_TRUE(row.is_object());
    EXPECT_EQ(str(row, "luck_method"), "relayed");
    EXPECT_FALSE(row.value("found_locally", true));
    ASSERT_TRUE(row["luck"].is_number()) << "a relayed row had no luck: " << row.dump(1);
    EXPECT_NEAR(num(row, "time_to_find"), 2000.0, 1e-9);
    EXPECT_NEAR(num(row, "effort"), 2.0, 1e-9);
    EXPECT_NEAR(num(row, "luck"), 50.0, 1e-9);
    EXPECT_NEAR(num(row, "expected_time"), 1000.0, 1e-9);
}

// A luck is null only when an input cannot be had, and the row names which.
// Here the block's difficulty is known but no pool rate was ever sampled for
// its round (no estimator at record time, no history): that is not a missing
// network difficulty.
TEST(PoolLuckEndpoints, RowWithoutAnyPoolRateSaysSo)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double T = now_s() - 20000.0;
    record(mi, "LTC", 3211000, 1, T, 1000.0, 0.0);
    record(mi, "LTC", 3211001, 2, T + 2000.0, 1000.0, 0.0);
    record(mi, "LTC", 3211002, 3, T + 3000.0, 1000.0, 0.0, /*attributed=*/false);

    const auto recent = mi.rest_recent_blocks();
    for (unsigned tag : {2u, 3u}) {
        const auto row = find_row(recent, "hash", hash_of(tag));
        ASSERT_TRUE(row.is_object());
        EXPECT_TRUE(row["luck"].is_null()) << row.dump(1);
        EXPECT_EQ(str(row, "luck_method"), "hashrate_unavailable") << "tag " << tag;
        EXPECT_NEAR(num(row, "network_difficulty"), 1000.0, 1e-9);
        // The round itself is known.
        EXPECT_NEAR(num(row, "time_to_find"), tag == 2 ? 2000.0 : 1000.0, 1e-9);
    }
    // Left out of the pool's luck on both sides, and counted as such.
    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck.contains("periods")) << luck.dump(1);
    EXPECT_EQ(luck["periods"]["all"]["k"].get<uint64_t>(), 1u);
    EXPECT_EQ(luck["periods"]["all"]["k_unmeasured"].get<uint64_t>(), 2u);
}

// C5. Operator ruling: the first block is effort 1.0 / luck 100 %, and it
// counts in the pool's luck as one block found for one expected.
TEST(PoolLuckEndpoints, FirstBlockIsEffortOne)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    // A rate so low the open round after the block adds nothing measurable.
    mi.set_pool_hashrate_fn([]() { return 1.0; });
    mi.update_network_difficulty(1.0e9, "test");
    record(mi, "LTC", 3211000, 1, now_s(), 1.0e9, 1.0);

    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 1u);
    const auto& row = recent[0];
    EXPECT_EQ(str(row, "luck_method"), "first_block");
    EXPECT_EQ(str(row, "effort_method"), "first_block");
    EXPECT_NEAR(num(row, "effort"), 1.0, 1e-12) << row.dump(1);
    EXPECT_NEAR(num(row, "luck"), 100.0, 1e-9);
    EXPECT_TRUE(row["time_to_find"].is_null()) << "a first block has no round";
    EXPECT_EQ(row.value("blocks_for_luck", uint64_t(0)), 1u);
    EXPECT_NEAR(num(row, "pool_avg_luck"), 100.0, 1e-3);

    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck.contains("periods")) << luck.dump(1);
    const auto& all = luck["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 1u);
    EXPECT_NEAR(num(all, "blocks_expected"), 1.0, 1e-6);
    EXPECT_NEAR(num(all, "luck"), 100.0, 1e-3);
    EXPECT_NEAR(num(luck["blocks"][0], "luck"), 100.0, 1e-9);
}

// C7 / C8. Period luck is blocks found over blocks expected with the exact
// Poisson interval. lambda = 1e-3 blocks per second (H = 2^32, D = 1000):
//
//   now - 8000  first block                      1 found / 1 expected
//   now - 7000  round 1000 s  effort 1.0
//   now - 4000  round 3000 s  effort 3.0
//   now - 3500  round  500 s  effort 0.5
//   now - 3400  orphaned
//   now - 1500  round 2000 s  effort 2.0
//   now         open round 1500 s    effort 1.5
//
//   k = 5, blocks expected = 9: luck 55.56 %, CI95 [18.04 %, 129.65 %]
//   (scipy: chi2.ppf(.025, 10) / 2 = 1.6234863901, chi2.ppf(.975, 12) / 2 =
//   11.6683320793). The per-block luck values (100, 100, 33, 200, 50) are
//   never averaged: their mean, 97 %, is not the pool's luck.
TEST(PoolLuckEndpoints, PeriodLuckIsBlocksFoundOverBlocksExpected)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double H = kT32, D = 1000.0;
    mi.set_pool_hashrate_fn([H]() { return H; });
    mi.update_network_difficulty(D, "test");
    const double now = now_s();
    record(mi, "LTC", 100, 1, now - 8000.0, D, H);
    record(mi, "LTC", 101, 2, now - 7000.0, D, H);
    record(mi, "LTC", 102, 3, now - 4000.0, D, H);
    record(mi, "LTC", 103, 4, now - 3500.0, D, H);
    record(mi, "LTC", 104, 5, now - 3400.0, D, H);
    record(mi, "LTC", 105, 6, now - 1500.0, D, H);
    mi.set_block_verify_fn([](const std::string& hash) { return hash == hash_of(5) ? -1 : 6; });
    mi.run_block_verification_now(hash_of(5));

    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck.contains("periods")) << luck.dump(1);
    // The clock moved a second or two since `now`: 0.002 blocks expected.
    const double tol = 0.01;
    for (const char* name : {"1d", "7d", "30d", "90d", "all"}) {
        const auto& p = luck["periods"][name];
        EXPECT_EQ(p["k"].get<uint64_t>(), 5u) << name;
        EXPECT_NEAR(num(p, "blocks_expected"), 9.0, tol) << name;
        EXPECT_NEAR(num(p, "luck"), 100.0 * 5.0 / 9.0, 0.1) << name;
        EXPECT_NEAR(num(p, "ci95_low"), 100.0 * 1.6234863901184207 / 9.0, 0.05) << name;
        EXPECT_NEAR(num(p, "ci95_high"), 100.0 * 11.66833207932267 / 9.0, 0.2) << name;
        EXPECT_NEAR(num(p, "span_s"), 8000.0, 5.0) << name;
    }
    const auto& round = luck["current_round"];
    EXPECT_NEAR(num(round, "elapsed"), 1500.0, 5.0);
    EXPECT_NEAR(num(round, "expected_time"), 1000.0, 1e-6);
    EXPECT_NEAR(num(round, "effort"), 1.5, tol);
    EXPECT_EQ(str(round, "since_block_hash"), hash_of(6));
    // The deprecated field old pages read is the same round, as luck.
    EXPECT_NEAR(num(luck, "current_luck_trend"), 100.0 / 1.5, 0.5);

    // The compat figure on the first /recent_blocks row is the SAME number.
    const auto recent = mi.rest_recent_blocks();
    EXPECT_NEAR(num(recent[0], "pool_avg_luck"), 100.0 * 5.0 / 9.0, 0.1)
        << "pool_avg_luck is blocks found over blocks expected, not a mean";
    EXPECT_EQ(recent[0].value("blocks_for_luck", uint64_t(0)), 5u);
    EXPECT_NEAR(num(recent[0], "blocks_expected"), 9.0, tol);
}

// C6. A block recorded with no rate takes the POOL estimator -- never the
// node's own stratum rate -- and takes it GROSS: the estimator counts the
// shares that made the chain, so the pool's rate is that over (1 - stale
// proportion). 8e10 non-stale at 20 % stale is 1e11.
TEST(PoolLuckEndpoints, RecordedPoolRateIsTheGrossPoolEstimator)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([]() { return 8.0e10; });
    mi.set_sharechain_stats_fn([]() {
        return nlohmann::json{{"pool_stale_prop", 0.2}, {"total_shares", 100}};
    });
    mi.set_local_hashrate(4.0e6);          // this node's own miners
    mi.update_network_difficulty(1000.0, "test");
    mi.update_stat_log();                  // the minute tick samples the stale proportion
    record(mi, "LTC", 3211000, 1, now_s(), 1000.0, /*pool_rate=*/0.0);

    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 1u);
    EXPECT_NEAR(num(recent[0], "pool_hashrate_at_find"), 1.0e11, 1.0) << recent[0].dump(1);
}

// C6. The BTC-family record sites handed record_found_block the node's OWN
// stratum rate (get_local_hashrate) as the pool rate. They must pass 0 and
// let the core read the sharechain pool estimator. The main_*.cpp sites are
// not linked into any test, so the call text itself is pinned.
TEST(PoolLuckEndpoints, BtcFamilyRecordSitesPassThePoolEstimator)
{
    for (const char* rel : {"c2pool/main_btc.cpp", "c2pool/main_dgb.cpp",
                            "c2pool/main_bip110.cpp", "impl/bch/pool_entrypoint.hpp"}) {
        const std::string call = record_call(rel);
        ASSERT_FALSE(call.empty()) << rel << ": no record_found_block call";
        EXPECT_EQ(call.find("get_local_hashrate"), std::string::npos)
            << rel << " records a found block at this node's own stratum rate:\n" << call;
    }
    // BCH reads the rate into a local first.
    EXPECT_EQ(read_code("impl/bch/pool_entrypoint.hpp").find("pool_hr = mi->get_local_hashrate()"),
              std::string::npos);
}

// C6. A merged (aux) block is measured against the AUX chain's own
// difficulty, over the aux chain's own rounds, at the pool's parent-chain
// rate -- and /recent_merged_blocks serves it. DOGE's difficulty is about a
// third of LTC's: against the parent's, a DOGE block's effort read 3x low.
TEST(PoolLuckEndpoints, MergedBlockLuckUsesTheAuxChainsOwnDifficulty)
{
    TempDir tmp("core_luck_merged_kat");
    const double now = std::floor(now_s());
    const double ltc_diff = 9.5e7, doge_diff = 3.3e7, H = 1.9e11;
    std::vector<Sample> samples;
    for (int i = 10 * 24; i >= 0; --i)
        samples.push_back({now - i * 3600.0, H + 1.0e6 * (i % 7), 0.0, ltc_diff});
    write_stat_log(tmp.path("graph_db"), samples);

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([H]() { return H; });
    mi.update_network_difficulty(ltc_diff, "test");
    mi.set_stat_log_path(tmp.path("graph_db"));
    mi.load_stat_log();
    const double day = 86400.0;
    record(mi, "LTC", 3211872, 0x10, now - 5 * day, ltc_diff, 0.0);
    record(mi, "DOGE", 6454000, 0xd1, now - 9 * day, doge_diff, 0.0);
    record(mi, "DOGE", 6454700, 0xd2, now - 5 * day, doge_diff, 0.0);

    const auto merged = mi.rest_recent_merged_blocks();
    const auto row = find_row(merged, "pow_hash", hash_of(0xd2));
    ASSERT_TRUE(row.is_object()) << merged.dump(1);
    EXPECT_NEAR(num(row, "network_difficulty"), doge_diff, 1.0) << row.dump(1);
    EXPECT_NEAR(num(row, "time_to_find"), 4 * day, 1e-6);
    EXPECT_EQ(str(row, "prev_block_hash"), hash_of(0xd1))
        << "the previous DOGE block, never the LTC one";
    const double effort = 4 * day * H / (doge_diff * kT32);
    EXPECT_NEAR(num(row, "effort"), effort, effort * 1e-3);
    EXPECT_NEAR(num(row, "luck"), 100.0 / effort, 100.0 / effort * 1e-3)
        << "against LTC's difficulty it reads "
        << 100.0 / (4 * day * H / (ltc_diff * kT32)) << " %";
    EXPECT_NEAR(num(row, "expected_time"), 4 * day / effort, 4 * day / effort * 1e-3);
    EXPECT_EQ(str(row, "effort_method"), "integrated");
    const auto first = find_row(merged, "pow_hash", hash_of(0xd1));
    EXPECT_EQ(str(first, "effort_method"), "first_block");
    EXPECT_NEAR(num(first, "effort"), 1.0, 1e-12);
    // Every merged row says whether it is a block of the aux chain for luck
    // (it ends a round), and what a period would count of it.
    for (const auto& r : {row, first}) {
        ASSERT_TRUE(r.contains("main_chain")) << r.dump(1);
        EXPECT_TRUE(r["main_chain"].get<bool>());
        EXPECT_TRUE(r.value("measured", false));
    }
    EXPECT_NEAR(num(row, "effort_covered"), effort, effort * 1e-3);
    EXPECT_NEAR(num(first, "effort_covered"), 1.0, 1e-12);

    // The parent's luck is untouched by the aux rows.
    const auto recent = mi.rest_recent_blocks();
    ASSERT_EQ(recent.size(), 1u);
    EXPECT_EQ(str(recent[0], "effort_method"), "first_block");
}

// C3. A block's network difficulty is its header's nBits. A block recorded
// after the fact (a sharechain replay, a win learned from a peer) was stored
// with the live template's difficulty at RECORD time.
TEST(PoolLuckEndpoints, DifficultyComesFromTheBlocksOwnHeader)
{
    MiningInterface mi(false, nullptr, Blockchain::BITCOIN);
    mi.set_block_field_lookups(
        [](const std::string& hash) { return hash == hash_of(2) ? 2000.0 : 0.0; },
        [](const std::string&) { return uint32_t(0); });
    const double T = now_s() - 20000.0;
    record(mi, "BTC", 900000, 1, T, 1000.0, kT32);
    // The header chain holds this block: its bits say 2000, the live
    // template at record time says 5000.
    record(mi, "BTC", 900001, 2, T + 4000.0, /*live reading=*/5000.0, kT32);

    const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
    ASSERT_TRUE(row.is_object());
    EXPECT_NEAR(num(row, "network_difficulty"), 2000.0, 1e-9) << row.dump(1);
    EXPECT_NEAR(num(row, "effort"), 4000.0 / 2000.0, 1e-9);
}

// The network hashrate is difficulty * 2^32 over THIS coin's block interval.
// It was a fixed 150 s (LTC's): 4x too high on BTC / BCH.
TEST(PoolLuckEndpoints, NetworkHashrateUsesTheCoinsBlockPeriod)
{
    struct Case { Blockchain chain; const char* label; double period; };
    const Case cases[] = {
        {Blockchain::LITECOIN, "", 150.0},
        {Blockchain::DASH, "", 150.0},
        {Blockchain::BITCOIN, "", 600.0},
        {Blockchain::BITCOIN, "BCH", 600.0},
        {Blockchain::BITCOIN, "BIP110", 600.0},
        {Blockchain::DOGECOIN, "", 60.0},
        // Five algorithms, each retargeted to one block in 75 s.
        {Blockchain::DIGIBYTE, "", 75.0},
    };
    const double D = 1.0e6;
    for (const auto& c : cases) {
        MiningInterface mi(false, nullptr, c.chain);
        if (*c.label) mi.set_coin_label(c.label);
        mi.update_network_difficulty(D, "test");
        const double want = D * kT32 / c.period;
        EXPECT_NEAR(mi.rest_global_stats()["network_hashrate"].get<double>(), want, want * 1e-12)
            << "chain " << static_cast<int>(c.chain) << " label '" << c.label << "'";
        EXPECT_NEAR(mi.rest_global_rate().get<double>(), want, want * 1e-12);
    }
}

// The "good" series of the pool-rate graph is the estimator's reading (the
// work of the shares that made the chain), and "orphan" the stale work on
// top of it. "good" was the estimator's reading times (1 - stale): the
// non-stale rate discounted for stales a second time.
TEST(PoolLuckEndpoints, GraphGoodSeriesIsNotDiscountedForStalesTwice)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_pool_hashrate_fn([]() { return 9.0e10; });
    mi.set_sharechain_stats_fn([]() {
        return nlohmann::json{{"pool_stale_prop", 0.1}, {"total_shares", 100}};
    });
    mi.update_stat_log();
    const auto data = mi.rest_web_graph_data("pool_rates", "last_hour");
    ASSERT_TRUE(data.is_array());
    ASSERT_FALSE(data.empty());
    const auto& val = data.back()[1];
    EXPECT_NEAR(val["good"].get<double>(), 9.0e10, 1.0) << data.back().dump();
    EXPECT_NEAR(val["orphan"].get<double>(), 1.0e10, 1.0)
        << "gross 1e11 less the 9e10 that made the chain";
}

// C1, beyond the flat stat log. The minute samples are kept for 31 days; the
// year-scale graph bins (the .views sidecar, one bin = 29.22 h holding the
// MEAN of its samples) reach back a year. A round older than the flat log is
// integrated over those bins; a bin its samples cover only in part weighs in
// by that part.
TEST(PoolLuckEndpoints, RoundOlderThanTheFlatLogIsIntegratedOverTheYearBins)
{
    TempDir tmp("core_luck_year_bins_kat");
    const std::string path = tmp.path("graph_db");
    {
        // A node that ran: it leaves a flat log and a .views sidecar behind.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        mi.set_pool_hashrate_fn([]() { static double v = 1.0e11; return v += 1.0; });
        mi.update_network_difficulty(1000.0, "test");
        mi.set_stat_log_path(path);
        mi.load_stat_log();
        for (int waited = 0; waited < 5000 && !mi.graph_views_ready(); waited += 20)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ASSERT_TRUE(mi.graph_views_ready());
        for (int i = 0; i < 3; ++i) mi.update_stat_log();
        mi.save_stat_log();
    }

    // Give the sidecar a past: two year bins well before the flat log, as a
    // node that had been up for two months would hold them.
    nlohmann::json views;
    {
        std::ifstream f(path + ".views");
        ASSERT_TRUE(f.good());
        views = nlohmann::json::parse(f);
    }
    auto& data = views["data"];
    const double bw = data["pool_hash_rate"]["last_year"]["bin_width"].get<double>();
    const double lbe = data["pool_hash_rate"]["last_year"]["last_bin_end"].get<double>();
    const double full = bw / 60.0;   // samples in a fully covered bin
    // Bin 40: fully sampled, 0.5 * 2^32 H/s against D = 1000.
    // Bin 41: sampled a quarter of the time, 0.25 * 2^32 H/s against D = 1000.
    auto set_bin = [&](int k, double rate, double count) {
        data["pool_hash_rate"]["last_year"]["bins"][k] = {{"null", {rate * count, count}}};
        data["pool_stale_prop"]["last_year"]["bins"][k] = {{"null", {0.0, count}}};
        data["network_difficulty"]["last_year"]["bins"][k] = {{"null", {1000.0 * count, count}}};
    };
    set_bin(40, 0.50 * kT32, full);
    set_bin(41, 0.25 * kT32, full / 4.0);
    { std::ofstream f(path + ".views", std::ios::trunc); f << views.dump(); }

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_stat_log_path(path);
    mi.load_stat_log();
    ASSERT_TRUE(mi.graph_views_ready());

    // A round over exactly those two bins: [lbe - 42 bw, lbe - 40 bw].
    const double a = lbe - 42.0 * bw, b = lbe - 40.0 * bw;
    record(mi, "LTC", 3100000, 1, a, 1000.0, kT32);
    record(mi, "LTC", 3100500, 2, b, 1000.0, kT32);
    const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
    ASSERT_TRUE(row.is_object());
    EXPECT_EQ(str(row, "effort_method"), "integrated") << row.dump(1);
    // Covered: all of bin 40 and a quarter of bin 41 -> 1.25 bw of 2 bw.
    //   effort over the covered time = bw * 0.5 / 1000 + 0.25 bw * 0.25 / 1000
    //   scaled to the round          = that * 2 bw / 1.25 bw
    // The block times are whole seconds, the bin edges are not: 1e-4.
    const double covered_effort = bw * 0.5 / 1000.0 + 0.25 * bw * 0.25 / 1000.0;
    const double effort = covered_effort * 2.0 / 1.25;
    EXPECT_NEAR(num(row, "history_coverage"), 1.25 / 2.0, 1e-4);
    EXPECT_NEAR(num(row, "effort"), effort, effort * 1e-4);
    EXPECT_NEAR(num(row, "luck"), 100.0 / effort, 100.0 / effort * 1e-4)
        << "the single sample at find (2^32 H/s) reads " << 100.0 * 1000.0 / (2.0 * bw) << " %";
}

// F3. A rate recorded "at find" is used only if it is plausibly a POOL rate.
// The rows an earlier build recorded at the node's own ~4 MH/s, on a node
// with NO rate history over them (a wiped graph_db, a fresh data directory):
// nothing integrates those rounds, and as single samples each is an effort of
// ~1e-5 -- a block found for nothing expected, k / expected of 300 % and up.
// The winning shares of those very rows (difficulty 500-700) put the pool
// above 100 MH/s, so the stored rate is refused: the round has no pool rate
// (hashrate_unavailable) and is left out of the pool's luck on both sides.
TEST(PoolLuckEndpoints, RowAtTheNodesOwnRateIsNotAPoolSample)
{
    using FB = MiningInterface::FoundBlock;
    const double now = std::floor(now_s());
    const double day = 86400.0;
    auto stored_row = [](uint64_t height, unsigned tag, double ts, double share_difficulty,
                         double rate) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(ts);
        b.status = MiningInterface::BlockStatus::confirmed;
        b.chain = "LTC";
        b.share_hash = b.hash;
        b.network_difficulty = 9.5e7;
        b.share_difficulty = share_difficulty;
        b.pool_hashrate = rate;
        return b;
    };
    const std::vector<FB> on_disk = {
        stored_row(3160570, 0xb0, now - 40 * day, 700.0, 1.9e11),
        stored_row(3190000, 0xb1, now - 30 * day, 693.5440248241151, 4030409.5),
        stored_row(3204796, 0xb2, now - 20 * day, 709.9291624908818, 4123391.6),
        stored_row(3211872, 0xb3, now - 15 * day, 785.1381125177094, 1.9e11),
    };
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);   // no stat log, no estimator
    mi.set_found_block_persistence([](const FB&) { return true; },
                                   [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    const auto recent = mi.rest_recent_blocks();
    for (unsigned tag : {0xb1u, 0xb2u}) {
        const auto row = find_row(recent, "hash", hash_of(tag));
        ASSERT_TRUE(row.is_object());
        EXPECT_TRUE(row["luck"].is_null()) << row.dump(1);
        EXPECT_TRUE(row["effort"].is_null());
        EXPECT_EQ(str(row, "luck_method"), "hashrate_unavailable");
        EXPECT_TRUE(row["pool_hashrate_at_find"].is_null())
            << "4 MH/s is this node's own miners, not a pool rate";
        EXPECT_EQ(row.value("measured", true), false);
    }
    // A plausible single sample stands: 5 days at 1.9e11 against D = 9.5e7.
    const auto good = find_row(recent, "hash", hash_of(0xb3));
    const double effort = 5 * day * 1.9e11 / (9.5e7 * kT32);
    EXPECT_EQ(str(good, "effort_method"), "single_sample");
    EXPECT_NEAR(num(good, "effort"), effort, effort * 1e-9);
    EXPECT_EQ(str(good, "pool_hashrate_source"), "recorded");

    // The pool's luck: the first block and the one measured round. The two
    // refused rounds are in k_unmeasured, not in k.
    const auto luck = mi.rest_luck_stats();
    ASSERT_TRUE(luck.contains("periods")) << luck.dump(1);
    const auto& all = luck["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 2u);
    EXPECT_EQ(all["k_unmeasured"].get<uint64_t>(), 2u);
    EXPECT_NEAR(num(all, "blocks_expected"), 1.0 + effort, 1e-9);
    EXPECT_NEAR(num(recent[0], "pool_avg_luck"), 100.0 * 2.0 / (1.0 + effort), 1e-6)
        << "with the 4 MH/s rows as samples it reads " << 100.0 * 4.0 / (1.0 + effort) << " %";
}

// F2. The rate a row stored at find is rewritten -- and written back to disk
// -- only against a MINUTE sample taken at the block's own time. The history
// older than the minute samples is binned (~29 h bins of the year-scale graph
// store): a bin is a mean, and a legitimate instantaneous rate sits well away
// from it (DASH at find: 4.4e13 .. 6.06e13 within days). Judged against the
// 25 % tolerance, such a row was overwritten with the bin's mean, for good.
TEST(PoolLuckEndpoints, BinnedHistoryNeverRewritesAStoredRate)
{
    TempDir tmp("core_luck_binned_repair_kat");
    const std::string path = tmp.path("graph_db");
    {
        MiningInterface seed(false, nullptr, Blockchain::DASH);
        seed.set_pool_hashrate_fn([]() { static double v = 5.0e13; return v += 1.0; });
        seed.update_network_difficulty(1.0e8, "test");
        seed.set_stat_log_path(path);
        seed.load_stat_log();
        for (int waited = 0; waited < 5000 && !seed.graph_views_ready(); waited += 20)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ASSERT_TRUE(seed.graph_views_ready());
        for (int i = 0; i < 3; ++i) seed.update_stat_log();
        seed.save_stat_log();
    }
    // Two fully sampled year bins ~48 days back: the pool at a mean 5.0e13.
    nlohmann::json views;
    { std::ifstream f(path + ".views"); ASSERT_TRUE(f.good()); views = nlohmann::json::parse(f); }
    auto& data = views["data"];
    const double bw = data["pool_hash_rate"]["last_year"]["bin_width"].get<double>();
    const double lbe = data["pool_hash_rate"]["last_year"]["last_bin_end"].get<double>();
    const double full = bw / 60.0;
    for (int k : {40, 41}) {
        data["pool_hash_rate"]["last_year"]["bins"][k] = {{"null", {5.0e13 * full, full}}};
        data["pool_stale_prop"]["last_year"]["bins"][k] = {{"null", {0.0, full}}};
        data["network_difficulty"]["last_year"]["bins"][k] = {{"null", {1.0e8 * full, full}}};
    }
    { std::ofstream f(path + ".views", std::ios::trunc); f << views.dump(); }

    using FB = MiningInterface::FoundBlock;
    auto stored_row = [&](uint64_t height, unsigned tag, double bins_back, double rate) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(lbe - bins_back * bw);
        b.status = MiningInterface::BlockStatus::confirmed;
        b.chain = "DASH";
        b.share_hash = b.hash;
        b.miner = "Xminer";
        b.network_difficulty = 1.0e8;
        b.pool_hashrate = rate;
        return b;
    };
    const std::vector<FB> on_disk = {
        stored_row(2550000, 0xc0, 41.8, 5.0e13),
        stored_row(2550100, 0xc1, 41.2, 6.5e13),   // a real reading, 30 % above the bin's mean
        stored_row(2550200, 0xc2, 40.8, 3.7e13),   // a real reading, 26 % below it
        stored_row(2550300, 0xc3, 40.5, 4.0e6),    // some node's own stratum rate
        stored_row(2550400, 0xc4, 40.2, 0.0),      // never recorded
    };
    std::vector<FB> written;

    MiningInterface mi(false, nullptr, Blockchain::DASH);
    mi.set_stat_log_path(path);
    mi.load_stat_log();
    ASSERT_TRUE(mi.graph_views_ready());
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    EXPECT_TRUE(written.empty())
        << "a row was rewritten on disk against binned history: " << written.size();
    const auto recent = mi.rest_recent_blocks();
    // The legitimate readings are served as recorded.
    const auto high = find_row(recent, "hash", hash_of(0xc1));
    EXPECT_NEAR(num(high, "pool_hashrate_at_find"), 6.5e13, 1.0) << high.dump(1);
    EXPECT_EQ(str(high, "pool_hashrate_source"), "recorded");
    const auto low = find_row(recent, "hash", hash_of(0xc2));
    EXPECT_NEAR(num(low, "pool_hashrate_at_find"), 3.7e13, 1.0);
    EXPECT_EQ(str(low, "pool_hashrate_source"), "recorded");
    // An implausible or missing one is stood in for by the bin's mean -- in
    // memory, and marked as such.
    for (unsigned tag : {0xc3u, 0xc4u}) {
        const auto row = find_row(recent, "hash", hash_of(tag));
        EXPECT_NEAR(num(row, "pool_hashrate_at_find"), 5.0e13, 5.0e13 * 1e-9) << row.dump(1);
        EXPECT_EQ(str(row, "pool_hashrate_source"), "history");
    }
    // The rounds themselves are integrated over the bins, whatever was stored.
    EXPECT_EQ(str(high, "effort_method"), "integrated");
    EXPECT_TRUE(written.empty()) << "a read must not write a row back either";
}

// Deviation 13. DigiByte makes a block every 15 s over FIVE algorithms, each
// retargeted to one block in 75 s. currency_info.block_period is the chain's
// (15); the network rate behind this node's difficulty is
// difficulty * 2^32 / 75. algo_block_period serves that interval, equal to
// block_period on every other coin.
TEST(PoolLuckEndpoints, CurrencyInfoServesTheAlgorithmsBlockPeriod)
{
    struct Case { Blockchain chain; const char* label; int block_period, algo_block_period; };
    const Case cases[] = {
        {Blockchain::DIGIBYTE, "", 15, 75},
        {Blockchain::LITECOIN, "", 150, 150},
        {Blockchain::DASH, "", 150, 150},
        {Blockchain::BITCOIN, "", 600, 600},
        {Blockchain::BITCOIN, "BCH", 600, 600},
        {Blockchain::DOGECOIN, "", 60, 60},
    };
    for (const auto& c : cases) {
        MiningInterface mi(false, nullptr, c.chain);
        if (*c.label) mi.set_coin_label(c.label);
        mi.update_network_difficulty(1.0e6, "test");
        const auto info = mi.rest_web_currency_info();
        ASSERT_TRUE(info.contains("block_period")) << info.dump(1);
        EXPECT_EQ(info["block_period"].get<int>(), c.block_period);
        ASSERT_TRUE(info.contains("algo_block_period"))
            << "chain " << static_cast<int>(c.chain) << " label '" << c.label << "'";
        EXPECT_EQ(info["algo_block_period"].get<int>(), c.algo_block_period);
        // The interval /global_stats turns the difficulty into a rate with.
        EXPECT_NEAR(mi.rest_global_stats()["network_hashrate"].get<double>(),
                    1.0e6 * kT32 / c.algo_block_period, 1.0);
    }
}
