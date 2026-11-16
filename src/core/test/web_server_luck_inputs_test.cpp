// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The INPUTS of pool luck that arrive through hooks added with the effort
// rework (web_server_luck_test.cpp covers everything reachable through the
// API that predates it):
//
//   * the aux chain's own difficulty for a merged block -- from the merged
//     manager's record of the block (read off the aux block's bits), or from
//     the aux header chain by hash (add_chain_block_difficulty_lookup) for a
//     row stored before the difficulty was recorded;
//   * the rate history fed sample by sample (add_luck_rate_sample), and the
//     endpoints as of a given instant (rest_luck_stats_at / _blocks_at), so
//     the open round and the period windows are exact.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cmath>
#include <sstream>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <c2pool/merged/merged_mining.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

using core::MiningInterface;
using c2pool::address::Blockchain;
using c2pool::merged::DiscoveredMergedBlock;
using c2pool::merged::MergedMiningManager;

namespace {

constexpr double kT32 = 4294967296.0;
const std::string kMiner = "LVypi56LPcT9jR3e5Y5AdoVc5EGdrVk26F";

std::string hash_of(unsigned tag)
{
    std::ostringstream os;
    os << std::hex << tag;
    std::string tail = os.str();
    return std::string(64 - tail.size(), 'b') + tail;
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

// A flat hour-by-hour rate history over [from, to]: H against the PARENT's
// difficulty.
void feed_history(MiningInterface& mi, double from, double to, double rate, double parent_diff)
{
    for (double t = from; t <= to; t += 3600.0)
        mi.add_luck_rate_sample(t, rate, 0.0, parent_diff);
}

} // namespace

// A merged row restored from a ledger written before the aux difficulty was
// stored holds the PARENT's difficulty (#1738). That is not the block's: the
// row has no difficulty and no luck until the aux header chain names it by
// hash -- then it is measured against the aux chain's own, and written back.
TEST(PoolLuckInputs, LegacyMergedRowTakesItsDifficultyFromTheAuxHeaderChain)
{
    using FB = MiningInterface::FoundBlock;
    const double ltc_diff = 9.5e7, doge_diff = 3.3e7, H = 1.9e11;
    const double t1 = 1.0e9, t2 = t1 + 4 * 86400.0;
    auto legacy = [&](uint64_t height, unsigned tag, double ts) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(ts);
        b.status = MiningInterface::BlockStatus::confirmed;
        b.chain = "DOGE";
        b.miner = kMiner;
        b.parent_hash = hash_of(0x100 + tag);
        b.network_difficulty = ltc_diff;   // what the old record path stored
        b.pool_hashrate = H;
        return b;                          // aux_difficulty_known stays false
    };
    const std::vector<FB> on_disk = {legacy(6454000, 0xd1, t1), legacy(6454700, 0xd2, t2)};
    std::vector<FB> written;

    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    feed_history(mi, t1 - 3600.0, t2 + 3600.0, H, ltc_diff);
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    auto row = find_row(mi.rest_recent_merged_blocks(), "pow_hash", hash_of(0xd2));
    ASSERT_TRUE(row.is_object());
    EXPECT_TRUE(row["network_difficulty"].is_null())
        << "the stored value is the parent's difficulty, not this block's: " << row.dump(1);
    EXPECT_TRUE(row["luck"].is_null());
    EXPECT_TRUE(row["effort"].is_null());
    EXPECT_EQ(row["luck_method"].get<std::string>(), "netdiff_unavailable");
    EXPECT_NEAR(num(row, "time_to_find"), t2 - t1, 1e-6) << "the round is known all the same";
    // /found_block/<hash> does not show the parent's difficulty either.
    EXPECT_TRUE(mi.rest_found_block(hash_of(0xd2))["network_difficulty"].is_null());

    // The embedded DOGE header chain comes up.
    mi.add_chain_block_difficulty_lookup("DOGE", [&](const std::string& hash) {
        return (hash == hash_of(0xd1) || hash == hash_of(0xd2)) ? doge_diff : 0.0;
    });

    row = find_row(mi.rest_recent_merged_blocks(), "pow_hash", hash_of(0xd2));
    EXPECT_NEAR(num(row, "network_difficulty"), doge_diff, 1e-6) << row.dump(1);
    const double effort = (t2 - t1) * H / (doge_diff * kT32);
    EXPECT_NEAR(num(row, "effort"), effort, effort * 1e-9);
    EXPECT_NEAR(num(row, "luck"), 100.0 / effort, 100.0 / effort * 1e-9);
    EXPECT_EQ(row["effort_method"].get<std::string>(), "integrated");
    EXPECT_EQ(row["prev_block_hash"].get<std::string>(), hash_of(0xd1));

    // Both rows went back to disk carrying the aux difficulty and the flag.
    int persisted = 0;
    for (const auto& b : written)
        if (b.aux_difficulty_known && std::fabs(b.network_difficulty - doge_diff) < 1e-6)
            ++persisted;
    EXPECT_EQ(persisted, 2);
}

// A merged block learned from a peer's share lives in the merged manager,
// with the difficulty read off the aux header the share carries.
TEST(PoolLuckInputs, PeerLearnedMergedBlockIsMeasuredAgainstItsOwnBits)
{
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    mi.set_merged_mining_manager(&mm);

    const double ltc_diff = 9.5e7, doge_diff = 3.3e7, H = 1.9e11;
    const double t1 = 1.0e9, t2 = t1 + 2 * 86400.0, t3 = t2 + 86400.0;
    feed_history(mi, t1 - 3600.0, t3 + 3600.0, H, ltc_diff);
    auto peer_block = [&](int height, unsigned tag, double ts, double difficulty, bool accepted) {
        DiscoveredMergedBlock blk;
        blk.chain_id = 98;
        blk.symbol = "DOGE";
        blk.height = height;
        blk.block_hash = hash_of(tag);
        blk.parent_hash = hash_of(0x100 + tag);
        blk.timestamp = static_cast<int64_t>(ts);
        blk.accepted = accepted;
        if (!accepted) blk.verdict = "rejected: bad-auxpow";
        blk.miner = kMiner;
        blk.difficulty = difficulty;
        mm.add_discovered_block(blk);
    };
    peer_block(6454000, 0xd1, t1, doge_diff, true);
    peer_block(6454400, 0xd2, t2, doge_diff, /*accepted=*/false);   // refused by the aux daemon
    peer_block(6454700, 0xd3, t3, doge_diff, true);

    const auto merged = mi.rest_recent_merged_blocks();
    const auto row = find_row(merged, "pow_hash", hash_of(0xd3));
    ASSERT_TRUE(row.is_object()) << merged.dump(1);
    EXPECT_NEAR(num(row, "network_difficulty"), doge_diff, 1e-6);
    // Timed from the last block the aux chain HELD: the refused one ends no round.
    EXPECT_EQ(row["prev_block_hash"].get<std::string>(), hash_of(0xd1));
    EXPECT_NEAR(num(row, "time_to_find"), t3 - t1, 1e-6);
    const double effort = (t3 - t1) * H / (doge_diff * kT32);
    EXPECT_NEAR(num(row, "effort"), effort, effort * 1e-9);
    EXPECT_NEAR(num(row, "luck"), 100.0 / effort, 100.0 / effort * 1e-9);
    EXPECT_NEAR(num(row, "history_coverage"), 1.0, 1e-9);
}

// The open round and the period windows as of an exact instant, over a
// sampled history. lambda = 1e-3 blocks per second until t = 20000, then the
// pool rate doubles (2e-3):
//
//   t = 10000  first block
//   t = 14000  round 4000 s at 1e-3                       effort 4.0
//   now = 26000  open round: 6000 s at 1e-3 + 6000 s at 2e-3   effort 18.0
//
//   all:              k = 2, expected = 1 + 4 + 18 = 23
//   window 8000 s (from 18000): k = 0, expected = 2000 * 1e-3 + 6000 * 2e-3 = 14
TEST(PoolLuckInputs, OpenRoundAndWindowsAreIntegratedAsOfNow)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double D = 1000.0;
    for (double t = 10000.0; t <= 20000.0; t += 1000.0)
        mi.add_luck_rate_sample(t, 1.0 * kT32, 0.0, D);
    for (double t = 21000.0; t <= 26000.0; t += 1000.0)
        mi.add_luck_rate_sample(t, 2.0 * kT32, 0.0, D);
    auto rec = [&](uint64_t height, unsigned tag, double ts) {
        const std::string h = hash_of(tag);
        mi.record_found_block(height, uint256S(h), static_cast<uint64_t>(ts), "LTC",
                              kMiner, h, D, 0.0, kT32, 625000000,
                              MiningInterface::BlockAuthorship::this_node);
    };
    rec(100, 1, 10000.0);
    rec(101, 2, 14000.0);

    const double now = 26000.0;
    const auto luck = mi.rest_luck_stats_at(now);
    const auto& round = luck["current_round"];
    EXPECT_NEAR(num(round, "elapsed"), 12000.0, 1e-9) << luck.dump(1);
    EXPECT_NEAR(num(round, "effort"), 18.0, 1e-9);
    EXPECT_EQ(round["effort_method"].get<std::string>(), "integrated");
    EXPECT_NEAR(num(round, "history_coverage"), 1.0, 1e-9);
    EXPECT_EQ(round["since_block_hash"].get<std::string>(), hash_of(2));
    EXPECT_NEAR(num(luck, "current_luck_trend"), 100.0 / 18.0, 1e-9);

    const auto& all = luck["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 2u);
    EXPECT_NEAR(num(all, "blocks_expected"), 23.0, 1e-9);
    EXPECT_NEAR(num(all, "luck"), 100.0 * 2.0 / 23.0, 1e-9);
    EXPECT_NEAR(num(all, "span_s"), 16000.0, 1e-9);

    // The first /recent_blocks row carries the same figures.
    const auto recent = mi.rest_recent_blocks_at(now);
    EXPECT_NEAR(num(recent[0], "pool_avg_luck"), 100.0 * 2.0 / 23.0, 1e-9);
    EXPECT_NEAR(num(recent[0], "blocks_expected"), 23.0, 1e-9);

    // 1d covers everything here; a window is the integral over exactly its
    // own stretch of time. As of now = 18000 + 86400 the 1d window starts at
    // t = 18000, inside the open round: 2000 s at 1e-3 and 6000 s at 2e-3
    // are behind the samples, the rest is past the end of the history.
    const double later = 18000.0 + 86400.0;
    const auto shifted = mi.rest_luck_stats_at(later);
    const auto& d1 = shifted["periods"]["1d"];
    EXPECT_EQ(d1["k"].get<uint64_t>(), 0u) << shifted.dump(1);
    // A period counts the time the history watched and extrapolates nothing:
    // 8000 s of the window are covered, 14.0 blocks expected. (The ROUND's
    // own effort, for display, is the scaled estimate: 18.0 over the covered
    // 12000 s, times 90400 / 12000.)
    EXPECT_NEAR(num(d1, "blocks_expected"), 14.0, 1e-9);
    EXPECT_NEAR(num(shifted["current_round"], "effort"), 18.0 / 12000.0 * 90400.0, 1e-6);
    EXPECT_NEAR(num(shifted["current_round"], "history_coverage"), 12000.0 / 90400.0, 1e-9);
    EXPECT_NEAR(num(d1, "luck"), 0.0, 1e-12);
    EXPECT_NEAR(num(d1, "ci95_low"), 0.0, 1e-12);
    EXPECT_GT(num(d1, "ci95_high"), 0.0);
    EXPECT_NEAR(num(d1, "span_s"), 86400.0, 1e-9);
}

// A row recorded at height 0 (a lane whose work source does not know the
// height of the block it found: DGB records its header chain's base) takes
// its height from the header chain when the confirm lane finds the block
// there -- during the run, not only at the startup backfill of the next one.
TEST(PoolLuckInputs, RowAtHeightZeroLearnsItsHeightWhenItsBlockConfirms)
{
    using FB = MiningInterface::FoundBlock;
    MiningInterface mi(false, nullptr, Blockchain::DIGIBYTE);
    std::vector<FB> written;
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        []() { return std::vector<FB>{}; });
    const std::string h1 = hash_of(1), h2 = hash_of(2);
    mi.record_found_block(21000000, uint256S(h1), 1000000000, "DGB", kMiner, h1,
                          1000.0, 0.0, kT32, 0, MiningInterface::BlockAuthorship::this_node);
    mi.record_found_block(/*height=*/0, uint256S(h2), 1000004000, "DGB", kMiner, h2,
                          1000.0, 0.0, kT32, 0, MiningInterface::BlockAuthorship::this_node);
    ASSERT_EQ(mi.rest_found_block(h2)["height"].get<uint64_t>(), 0u);

    mi.set_block_height_lookup([&](const std::string& hash) -> uint64_t {
        return hash == h2 ? 21000250u : 0u;
    });
    mi.set_block_verify_fn([](const std::string&) { return 6; });
    // A height the chain does not name leaves a row alone.
    EXPECT_GT(mi.run_block_verification_now(h1), 0);
    EXPECT_EQ(mi.rest_found_block(h1)["height"].get<uint64_t>(), 21000000u);
    EXPECT_GT(mi.run_block_verification_now(h2), 0);

    const auto row = mi.rest_found_block(h2);
    EXPECT_EQ(row["height"].get<uint64_t>(), 21000250u) << row.dump(1);
    EXPECT_EQ(row["status"].get<std::string>(), "confirmed");
    // Its round was right all along: rounds follow time, not height.
    EXPECT_NEAR(num(row, "time_to_find"), 4000.0, 1e-9);
    EXPECT_NEAR(num(row, "effort"), 4.0, 1e-9);
    ASSERT_FALSE(written.empty());
    EXPECT_EQ(written.back().hash, h2);
    EXPECT_EQ(written.back().height, 21000250u);
    EXPECT_EQ(written.back().status, MiningInterface::BlockStatus::confirmed);
}
