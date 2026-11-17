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
//     the open round and the period windows are exact: what a period counts
//     of a row (effort_covered / measured), when a stored rate is rewritten,
//     the hourly fold of samples older than a month;
//   * the confirm lane: the evidence that a pending block is not on the
//     chain (set_block_height_lookup, set_block_chain_span_fn), and its
//     header lookups running with the ledger unlocked.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <ctime>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
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

std::string str(const nlohmann::json& row, const char* key)
{
    if (!row.is_object() || !row.contains(key) || !row[key].is_string())
        return "<absent>";
    return row[key].get<std::string>();
}

double now_s() { return static_cast<double>(std::time(nullptr)); }

// A block of the pool, recorded as a sharechain peer's (no share difficulty).
void record(MiningInterface& mi, const std::string& chain, uint64_t height, unsigned tag,
            double ts, double netdiff, double pool_rate)
{
    const std::string h = hash_of(tag);
    mi.record_found_block(height, uint256S(h), static_cast<uint64_t>(ts), chain, kMiner, h,
                          netdiff, 0.0, pool_rate, 625000000,
                          MiningInterface::BlockAuthorship::sharechain_peer);
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
    peer_block(6453900, 0xd0, t1 - 3600.0, doge_diff, /*accepted=*/false);   // refused, before any block
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

    // F1. Every merged row SAYS whether it is a block of the aux chain. The
    // refused submit is served with its own effort and luck (timed from the
    // block before it), exactly like a real block: without main_chain a
    // consumer builds a round out of it -- here a "block" one day before the
    // next one, a fake fast pair.
    for (const auto& r : merged) {
        ASSERT_TRUE(r.contains("main_chain")) << r.dump(1);
        ASSERT_TRUE(r["main_chain"].is_boolean());
    }
    const auto refused = find_row(merged, "pow_hash", hash_of(0xd2));
    ASSERT_TRUE(refused.is_object());
    EXPECT_FALSE(refused["main_chain"].get<bool>()) << refused.dump(1);
    EXPECT_FALSE(refused.value("measured", true));
    EXPECT_TRUE(refused["verified"].is_null());
    EXPECT_TRUE(refused["luck"].is_number()) << "it still carries a luck of its own";
    EXPECT_TRUE(row["main_chain"].get<bool>());
    EXPECT_TRUE(row.value("measured", false));
    EXPECT_TRUE(find_row(merged, "pow_hash", hash_of(0xd1))["main_chain"].get<bool>());

    // A refused submit with no block of the aux chain before it has no round
    // at all: no luck, and the label a parent row has in that case -- not
    // "first_block", and not a missing difficulty (it has one).
    const auto early = find_row(merged, "pow_hash", hash_of(0xd0));
    ASSERT_TRUE(early.is_object());
    EXPECT_FALSE(early["main_chain"].get<bool>());
    EXPECT_TRUE(early["luck"].is_null()) << early.dump(1);
    EXPECT_TRUE(early["effort"].is_null());
    EXPECT_TRUE(early["effort_method"].is_null());
    EXPECT_TRUE(early["time_to_find"].is_null());
    EXPECT_NEAR(num(early, "network_difficulty"), doge_diff, 1e-6);
    EXPECT_EQ(early["luck_method"].get<std::string>(), "interval_unavailable");
    EXPECT_EQ(find_row(merged, "pow_hash", hash_of(0xd1))["luck_method"].get<std::string>(),
              "first_block");
}

// F1, the ledger side: this node's own merged find that its aux chain
// orphaned is not a block of the aux chain either.
TEST(PoolLuckInputs, OrphanedMergedLedgerRowIsNotMainChain)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double t1 = 1.0e9, day = 86400.0;
    feed_history(mi, t1 - 3600.0, t1 + 3 * day, 1.9e11, 9.5e7);
    auto doge = [&](uint64_t height, unsigned tag, double ts) {
        const std::string h = hash_of(tag);
        mi.record_found_block(height, uint256S(h), static_cast<uint64_t>(ts), "DOGE", kMiner, "",
                              3.3e7, 0.0, 0.0, 1000000000000ULL,
                              MiningInterface::BlockAuthorship::this_node);
    };
    doge(6454000, 0xe1, t1);
    doge(6454400, 0xe2, t1 + day);
    doge(6454700, 0xe3, t1 + 2 * day);
    mi.add_chain_verify_fn("DOGE", [](const std::string& hash) {
        return hash == hash_of(0xe2) ? -1 : 12;
    });
    for (unsigned tag : {0xe1u, 0xe2u, 0xe3u})
        mi.run_block_verification_now(hash_of(tag));

    const auto merged = mi.rest_recent_merged_blocks();
    const auto orphan = find_row(merged, "pow_hash", hash_of(0xe2));
    ASSERT_TRUE(orphan.is_object()) << merged.dump(1);
    EXPECT_FALSE(orphan["main_chain"].get<bool>());
    EXPECT_FALSE(orphan["verified"].get<bool>());
    const auto last = find_row(merged, "pow_hash", hash_of(0xe3));
    EXPECT_TRUE(last["main_chain"].get<bool>());
    EXPECT_EQ(last["prev_block_hash"].get<std::string>(), hash_of(0xe1));
    EXPECT_NEAR(num(last, "time_to_find"), 2 * day, 1e-6);
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

// A pending block is left out only on POSITIVE evidence that it is not on
// the chain. "Nobody can judge it" keeps it: no lookup wired, a header chain
// that does not reach back to it, an RPC or header outage however long. (The
// rule used to be "still pending after its checks ran out while a later
// block confirmed", which dropped a real block after any long outage.)
TEST(PoolLuckInputs, PendingBlockIsKeptUnlessTheChainProvesItAbsent)
{
    const double now = now_s();
    const double day = 86400.0;
    const double D = 1000.0, H = kT32;
    // Four blocks, days apart; the second never gets a verdict.
    auto ledger = [&](MiningInterface& mi) {
        record(mi, "LTC", 100, 1, now - 40 * day, D, H);
        record(mi, "LTC", 101, 2, now - 30 * day, D, H);
        record(mi, "LTC", 102, 3, now - 20 * day, D, H);
        record(mi, "LTC", 103, 4, now - 10 * day, D, H);
        mi.set_block_verify_fn([](const std::string& hash) { return hash == hash_of(2) ? 0 : 6; });
    };
    auto verify_all = [](MiningInterface& mi) {
        for (unsigned tag : {1u, 3u, 4u, 2u})
            mi.run_block_verification_now(hash_of(tag));
    };
    auto pending_row = [](MiningInterface& mi) {
        const auto recent = mi.rest_recent_blocks();
        auto row = find_row(recent, "hash", hash_of(2));
        row["__next_prev"] = str(find_row(recent, "hash", hash_of(3)), "prev_block_hash");
        row["__k"] = recent[0].value("blocks_for_luck", uint64_t(0));
        return row;
    };

    {   // No by-hash lookup at all (a lane that cannot ask): kept.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        verify_all(mi);
        const auto row = pending_row(mi);
        ASSERT_EQ(str(row, "status"), "pending");
        EXPECT_EQ(row.value("main_chain", false), true) << row.dump(1);
        EXPECT_EQ(str(row, "__next_prev"), hash_of(2));
        EXPECT_EQ(row["__k"].get<uint64_t>(), 4u);
    }
    {   // The lookup is down -- it answers for nothing, the pool's confirmed
        // blocks included (an RPC outage): that is no evidence. Kept.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        mi.set_block_height_lookup([](const std::string&) -> uint64_t { return 0; });
        verify_all(mi);
        const auto row = pending_row(mi);
        EXPECT_EQ(row.value("main_chain", false), true) << row.dump(1);
        EXPECT_EQ(row["__k"].get<uint64_t>(), 4u);
    }
    {   // The header chain is rooted AFTER the block (a later checkpoint): it
        // holds the later blocks only. It cannot speak for the block. Kept.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
            return (hash == hash_of(3) || hash == hash_of(4)) ? 3200000u : 0u;
        });
        mi.set_block_chain_span_fn([&]() {
            return std::pair<uint64_t, uint64_t>(static_cast<uint64_t>(now - 25 * day),
                                                 static_cast<uint64_t>(now));
        });
        verify_all(mi);
        const auto row = pending_row(mi);
        EXPECT_EQ(row.value("main_chain", false), true) << row.dump(1);
        EXPECT_EQ(str(row, "__next_prev"), hash_of(2));
    }
    {   // One failed call is not evidence: the lookup answers "nothing" for
        // the block once (an RPC that timed out), then is seen working for
        // the blocks around it -- and, asked again, holds the block. Kept.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        int asked = 0;
        mi.set_block_height_lookup([&asked](const std::string& hash) -> uint64_t {
            if (hash == hash_of(2) && ++asked == 1) return 0u;
            return 3200000u;
        });
        verify_all(mi);
        const auto row = pending_row(mi);
        EXPECT_EQ(asked, 2);
        EXPECT_EQ(row.value("main_chain", false), true) << row.dump(1);
        EXPECT_EQ(row["__k"].get<uint64_t>(), 4u);
    }
    {   // A lookup that throws is nobody to ask. Kept.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
            if (hash == hash_of(2)) throw std::runtime_error("rpc timeout");
            return 3200000u;
        });
        verify_all(mi);
        EXPECT_EQ(pending_row(mi).value("main_chain", false), true);
    }
    {   // Evidence: the lookup holds the pool's confirmed blocks from before
        // and after it, and not this one.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        ledger(mi);
        mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
            return hash == hash_of(2) ? 0u : 3200000u;
        });
        verify_all(mi);
        const auto row = pending_row(mi);
        ASSERT_EQ(str(row, "status"), "pending");
        EXPECT_EQ(row.value("main_chain", true), false) << row.dump(1);
        EXPECT_EQ(str(row, "__next_prev"), hash_of(1)) << "the round runs across it";
        EXPECT_EQ(row["__k"].get<uint64_t>(), 3u);
    }
    {   // Evidence: the header chain's own span covers the block's time (no
        // earlier pool block needed), and it does not hold the hash.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        record(mi, "LTC", 101, 2, now - 30 * day, D, H);   // the ledger starts with it
        record(mi, "LTC", 102, 3, now - 20 * day, D, H);
        mi.set_block_verify_fn([](const std::string& hash) { return hash == hash_of(2) ? 0 : 6; });
        mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
            return hash == hash_of(3) ? 3200000u : 0u;
        });
        mi.set_block_chain_span_fn([&]() {
            return std::pair<uint64_t, uint64_t>(static_cast<uint64_t>(now - 60 * day),
                                                 static_cast<uint64_t>(now));
        });
        mi.run_block_verification_now(hash_of(3));
        mi.run_block_verification_now(hash_of(2));
        const auto recent = mi.rest_recent_blocks();
        const auto row = find_row(recent, "hash", hash_of(2));
        EXPECT_EQ(row.value("main_chain", true), false) << row.dump(1);
        EXPECT_EQ(str(find_row(recent, "hash", hash_of(3)), "effort_method"), "first_block");

        // The header turns up after all (a late sync): the evidence is gone.
        mi.set_block_height_lookup([](const std::string&) -> uint64_t { return 3200000u; });
        mi.run_block_verification_now(hash_of(2));
        EXPECT_EQ(find_row(mi.rest_recent_blocks(), "hash", hash_of(2)).value("main_chain", false),
                  true);
    }
    {   // A block found minutes ago is nobody's phantom: the chain has not
        // moved a clear margin past its time yet.
        MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
        record(mi, "LTC", 100, 1, now - 40 * day, D, H);
        record(mi, "LTC", 101, 2, now - 600.0, D, H);
        mi.set_block_verify_fn([](const std::string& hash) { return hash == hash_of(2) ? 0 : 6; });
        mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
            return hash == hash_of(1) ? 3200000u : 0u;
        });
        mi.set_block_chain_span_fn([&]() {
            return std::pair<uint64_t, uint64_t>(static_cast<uint64_t>(now - 60 * day),
                                                 static_cast<uint64_t>(now));
        });
        mi.run_block_verification_now(hash_of(1));
        mi.run_block_verification_now(hash_of(2));
        EXPECT_EQ(find_row(mi.rest_recent_blocks(), "hash", hash_of(2)).value("main_chain", false),
                  true);
    }
}

// F4. The by-hash header lookups can be RPCs (DGB: digibyted
// getblockheader). They ran under the ledger's lock in the confirm lane, so
// a slow daemon stalled every /recent_blocks, /luck_stats and found-block
// record. Each lookup here asks another thread to read the ledger and waits
// for it: if that thread cannot get in, the lookup was called with the lock
// held. (The wait is long so that a loaded machine cannot fail the test; it
// is only ever waited out when the lookup IS under the lock.)
TEST(PoolLuckInputs, HeaderLookupsRunWithTheLedgerUnlocked)
{
    MiningInterface mi(false, nullptr, Blockchain::DIGIBYTE);
    std::atomic<int> calls{0}, under_lock{0};
    std::vector<std::thread> probes;
    std::mutex probes_mutex;
    auto probe = [&]() {
        ++calls;
        auto done = std::make_shared<std::promise<void>>();
        auto fut = done->get_future();
        {
            std::lock_guard<std::mutex> l(probes_mutex);
            probes.emplace_back([&mi, done]() { (void)mi.get_found_blocks(); done->set_value(); });
        }
        if (fut.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
            ++under_lock;
    };
    mi.set_block_field_lookups(
        [&](const std::string&) { probe(); return 2000.0; },
        [&](const std::string&) { probe(); return uint32_t(0); });
    mi.set_block_height_lookup([&](const std::string&) -> uint64_t { probe(); return 21000250u; });

    const std::string h1 = hash_of(1), h2 = hash_of(2), h3 = hash_of(3);
    auto rec = [&](uint64_t height, const std::string& h, uint64_t ts, double netdiff) {
        mi.record_found_block(height, uint256S(h), ts, "DGB", kMiner, h, netdiff, 0.0, kT32, 0,
                              MiningInterface::BlockAuthorship::this_node);
    };
    rec(21000000, h1, 1000000000, 1000.0);
    rec(0, h2, 1000100000, 0.0);        // height and difficulty to be learned
    rec(21000900, h3, 1000200000, 1000.0);
    rec(0, h2, 1000100000, 0.0);        // the same block recorded again: the existing-row path
    const int at_record = calls.load();
    EXPECT_GT(at_record, 0) << "the record path asks the header for the difficulty";

    // The confirm lane: a confirmation (difficulty + height from the header),
    // then a block with no verdict (is it absent from the chain?).
    mi.set_block_verify_fn([&](const std::string& hash) { return hash == h3 ? 0 : 6; });
    EXPECT_GT(mi.run_block_verification_now(h1), 0);
    EXPECT_GT(mi.run_block_verification_now(h2), 0);
    EXPECT_EQ(mi.run_block_verification_now(h3), 0);
    EXPECT_GT(calls.load(), at_record) << "the confirm lane asks the header too";

    // The startup backfill asks the same two lookups about every row.
    const int at_backfill = calls.load();
    mi.backfill_block_fields(
        [&](const std::string&) { probe(); return 3000.0; },
        [&](const std::string&) { probe(); return uint32_t(0); });
    EXPECT_EQ(calls.load() - at_backfill, 6) << "difficulty and time of each of the 3 rows";
    EXPECT_NEAR(num(mi.rest_found_block(h1), "network_difficulty"), 3000.0, 1e-9)
        << "and the backfill's answers landed";

    for (auto& t : probes) t.join();
    EXPECT_EQ(under_lock.load(), 0)
        << under_lock.load() << " of " << calls.load()
        << " header lookups were made with the ledger locked";
    // And the confirm lane's answers landed (the height; the difficulty is
    // the backfill's by now).
    const auto row = mi.rest_found_block(h2);
    EXPECT_EQ(row["height"].get<uint64_t>(), 21000250u);
    EXPECT_NEAR(num(row, "network_difficulty"), 3000.0, 1e-9);
}

// A check of a pending row reads the chain with the ledger unlocked, so two
// checks of one row can overlap and finish out of order. The older one must
// not apply what it found over the newer one's: here the first check asks
// while the header chain does not hold the block yet and is held up in its
// last lookup; the second runs start to finish against a chain that does hold
// it; then the first comes back with "the chain does not hold it".
TEST(PoolLuckInputs, OlderCheckDoesNotOverrideANewerOne)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double now = now_s(), day = 86400.0;
    record(mi, "LTC", 100, 1, now - 40 * day, 1000.0, kT32);
    record(mi, "LTC", 101, 2, now - 30 * day, 1000.0, kT32);
    record(mi, "LTC", 102, 3, now - 20 * day, 1000.0, kT32);
    mi.set_block_verify_fn([](const std::string& hash) { return hash == hash_of(2) ? 0 : 6; });

    std::mutex m;
    std::condition_variable cv;
    int asked = 0;            // lookups of the pending block so far
    bool held = false;        // the first check is inside its last lookup
    bool release = false;     // ... and may come back
    mi.set_block_height_lookup([&](const std::string& hash) -> uint64_t {
        if (hash != hash_of(2)) return 3200000u;   // the pool's blocks around it
        std::unique_lock<std::mutex> l(m);
        const int n = ++asked;
        if (n == 1) return 0u;                     // first check, first ask: not held
        if (n == 2) {                              // first check, asked again: held up
            held = true;
            cv.notify_all();
            cv.wait(l, [&] { return release; });
            return 0u;                             // still its old answer
        }
        return 3200000u;                           // from now on the chain holds it
    });
    mi.run_block_verification_now(hash_of(1));
    mi.run_block_verification_now(hash_of(3));

    std::thread older([&] { mi.run_block_verification_now(hash_of(2)); });
    bool reached = false;
    {
        std::unique_lock<std::mutex> l(m);
        reached = cv.wait_for(l, std::chrono::seconds(30), [&] { return held; });
    }
    EXPECT_TRUE(reached) << "the first check never asked for the block a second time";
    if (reached) {
        // The newer check, start to finish: the chain holds the block.
        EXPECT_EQ(mi.run_block_verification_now(hash_of(2)), 0);
        const auto row = find_row(mi.rest_recent_blocks(), "hash", hash_of(2));
        EXPECT_EQ(row.value("main_chain", false), true) << row.dump(1);
    }
    {
        std::lock_guard<std::mutex> l(m);
        release = true;
    }
    cv.notify_all();
    older.join();
    EXPECT_EQ(asked, 3);

    const auto recent = mi.rest_recent_blocks();
    const auto row = find_row(recent, "hash", hash_of(2));
    EXPECT_EQ(str(row, "status"), "pending");
    EXPECT_EQ(row.value("main_chain", false), true)
        << "the older check's 'absent' was applied over the newer 'present': " << row.dump(1);
    EXPECT_EQ(str(find_row(recent, "hash", hash_of(3)), "prev_block_hash"), hash_of(2));

    // Alone again, a check applies what it finds: the chain loses the block.
    mi.set_block_height_lookup([](const std::string& hash) -> uint64_t {
        return hash == hash_of(2) ? 0u : 3200000u;
    });
    mi.run_block_verification_now(hash_of(2));
    EXPECT_EQ(find_row(mi.rest_recent_blocks(), "hash", hash_of(2)).value("main_chain", true),
              false);
}

// L2-1. A row's `effort` is the best estimate for its own round: where the
// history has a gap it is scaled up to the whole round. A period counts only
// the time the history watched. A consumer summing rows needs the SAME rule
// as the server's periods, so every row serves what a period counts of it:
// effort_covered and measured. lambda = 1e-3 blocks per second:
//
//   t = 100000  first block                                 1.0     counted
//   t = 106000  history covers [100400, 106000] of its      5.6     counted
//               round: effort 6.0 (scaled), 5.6 covered
//   t = 120000  no history over its round: single sample   14.0     counted
//   t = 140000  history covers [126400, 131000]; the block   4.6     NOT counted
//               was found in the dark: effort 20.0 (scaled)          (k_unmeasured)
//   now = 141000  open round, no history: live rate          1.0
//
//   periods.all: k = 3, blocks_expected = 26.2
TEST(PoolLuckInputs, RowsServeWhatAPeriodCountsOfThem)
{
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    const double D = 1000.0;
    mi.set_pool_hashrate_fn([]() { return kT32; });
    mi.update_network_difficulty(D, "test");
    for (double t : {104000.0, 105000.0, 106000.0, 130000.0, 131000.0})
        mi.add_luck_rate_sample(t, kT32, 0.0, D);
    auto rec = [&](uint64_t height, unsigned tag, double ts) {
        const std::string h = hash_of(tag);
        mi.record_found_block(height, uint256S(h), static_cast<uint64_t>(ts), "LTC", kMiner, h,
                              D, 0.0, kT32, 625000000,
                              MiningInterface::BlockAuthorship::this_node);
    };
    rec(100, 1, 100000.0);
    rec(101, 2, 106000.0);
    rec(102, 3, 120000.0);
    rec(103, 4, 140000.0);

    const double now = 141000.0;
    const auto recent = mi.rest_recent_blocks_at(now);
    struct Want { unsigned tag; double effort, covered; bool measured; const char* method; };
    const Want wants[] = {
        {1, 1.0, 1.0, true, "first_block"},
        {2, 6.0, 5.6, true, "integrated"},
        {3, 14.0, 14.0, true, "single_sample"},
        {4, 20.0, 4.6, false, "integrated"},
    };
    double sum_covered = 0.0;
    uint64_t sum_measured = 0;
    for (const auto& w : wants) {
        const auto row = find_row(recent, "hash", hash_of(w.tag));
        ASSERT_TRUE(row.is_object());
        EXPECT_EQ(row["effort_method"].get<std::string>(), w.method) << row.dump(1);
        EXPECT_NEAR(num(row, "effort"), w.effort, 1e-9) << "tag " << w.tag;
        EXPECT_NEAR(num(row, "effort_covered"), w.covered, 1e-9) << "tag " << w.tag;
        EXPECT_EQ(row["measured"].get<bool>(), w.measured) << "tag " << w.tag;
        EXPECT_TRUE(row["main_chain"].get<bool>());
        sum_covered += num(row, "effort_covered");
        if (row["measured"].get<bool>()) ++sum_measured;
    }

    const auto luck = mi.rest_luck_stats_at(now);
    const auto& round = luck["current_round"];
    EXPECT_NEAR(num(round, "effort"), 1.0, 1e-9);
    EXPECT_NEAR(num(round, "effort_covered"), 1.0, 1e-9);
    const auto& all = luck["periods"]["all"];
    EXPECT_EQ(all["k"].get<uint64_t>(), 3u);
    EXPECT_EQ(all["k_unmeasured"].get<uint64_t>(), 1u);
    EXPECT_NEAR(num(all, "blocks_expected"), 26.2, 1e-9);
    // The rows and the open round ADD UP to the period: what the dashboard's
    // trend is built from is what the badges show.
    EXPECT_EQ(sum_measured, all["k"].get<uint64_t>());
    EXPECT_NEAR(sum_covered + num(round, "effort_covered"), num(all, "blocks_expected"), 1e-9);
    // /luck_stats blocks[] carries the same pair.
    for (const auto& b : luck["blocks"]) {
        const auto row = find_row(recent, "hash", b["hash"].get<std::string>());
        EXPECT_NEAR(num(b, "effort_covered"), num(row, "effort_covered"), 1e-12);
        EXPECT_EQ(b["measured"].get<bool>(), row["measured"].get<bool>());
    }
}


// F2, the samples' side. A stored rate is rewritten on disk -- for good --
// only against a sample of the block's OWN MINUTE: a sample (not a bin) that
// speaks for at most 300 s, was taken no more than 60 s after the block's
// time, and is borne out by the samples next to it. Against that a stored
// value is wrong when it is missing, not plausibly a pool rate, or more than
// 25 % away. Everything else leaves the disk alone, and at most stands in in
// memory:
//
//   steady minutes at R ................ [T - 2 h, T + 2 h]
//   a 240 s outage; the first sample after it reads 0.7 R (the estimator's
//     window is still filling): T1 = T + 2 h + 240 s
//   steady minutes at R ................ (T1, T1 + 1 h], but for ONE minute
//     that reads 150 R (ends at T1 + 30 min)
//   a 6 h outage; the first sample after it, an hour long, reads 150 R: T2
//   steady minutes at R ................ (T2, T2 + 10 min]
TEST(PoolLuckInputs, StoredRateIsRewrittenOnlyAgainstASampleOfItsOwnMinute)
{
    using FB = MiningInterface::FoundBlock;
    const double R = 2.0e11, D = 9.5e7;
    const double T = 1.0e9;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    for (double t = T - 7200.0; t <= T + 7200.0; t += 60.0)
        mi.add_luck_rate_sample(t, R, 0.0, D);
    const double T1 = T + 7200.0 + 240.0;
    mi.add_luck_rate_sample(T1, 0.7 * R, 0.0, D);
    const double stray = T1 + 1800.0;                     // the minute (stray - 60, stray]
    for (double t = T1 + 60.0; t <= T1 + 3600.0; t += 60.0)
        mi.add_luck_rate_sample(t, t == stray ? 150.0 * R : R, 0.0, D);
    const double T2 = T1 + 3600.0 + 6 * 3600.0;
    mi.add_luck_rate_sample(T2, 150.0 * R, 0.0, D);
    for (double t = T2 + 60.0; t <= T2 + 600.0; t += 60.0)
        mi.add_luck_rate_sample(t, R, 0.0, D);

    auto stored_row = [&](uint64_t height, unsigned tag, double ts, double rate) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(ts);
        b.status = MiningInterface::BlockStatus::confirmed;
        b.chain = "LTC";
        b.share_hash = b.hash;
        b.miner = kMiner;
        b.network_difficulty = D;
        b.pool_hashrate = rate;
        return b;
    };
    const std::vector<FB> on_disk = {
        // In the steady minutes: the block's own minute speaks.
        stored_row(3200000, 0x10, T - 3000.0 + 30.0, 1.2 * R),   // agrees: kept
        stored_row(3200010, 0x11, T - 1000.0 + 30.0, 1.3 * R),   // contradicted: rewritten
        stored_row(3200020, 0x12, T + 1000.0 + 30.0, 0.0),       // never recorded: filled in
        stored_row(3200030, 0x13, T + 2000.0 + 30.0, 4.0e6),     // not a pool rate: rewritten
        // (a) Under the 240 s restart sample at 0.7 R. It is short enough to
        // pass for a sample, and 30 % off the R these rows recorded.
        stored_row(3200040, 0x14, T + 7200.0 + 30.0, R),         // found 210 s before it was taken
        stored_row(3200050, 0x15, T1 - 20.0, R),                 // found 20 s before it was taken
        stored_row(3200060, 0x16, T1 - 100.0, 0.0),              // never recorded
        // The one-off minute at 150 R: R is "under 1 %" of it.
        stored_row(3200070, 0x17, stray - 30.0, R),
        // (b) Under the hour-long restart sample at 150 R.
        stored_row(3200080, 0x18, T2 - 1000.0, R),
        stored_row(3200090, 0x19, T2 - 2000.0, 4.0e6),           // not a pool rate
        // In the outage: no history at its time.
        stored_row(3200100, 0x1a, T1 + 3600.0 + 3600.0, 1.3 * R),
    };
    std::vector<FB> written;
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    auto written_rate = [&](unsigned tag) {
        double rate = -1.0;   // -1 = the row was not written back
        for (const auto& b : written)
            if (b.hash == hash_of(tag)) rate = b.pool_hashrate;
        return rate;
    };
    EXPECT_DOUBLE_EQ(written_rate(0x10), -1.0);
    EXPECT_NEAR(written_rate(0x11), R, R * 1e-9);
    EXPECT_NEAR(written_rate(0x12), R, R * 1e-9);
    EXPECT_NEAR(written_rate(0x13), R, R * 1e-9);
    EXPECT_DOUBLE_EQ(written_rate(0x14), -1.0)
        << "(a) rewritten against a sample taken 210 s after the block, after a restart";
    EXPECT_DOUBLE_EQ(written_rate(0x15), -1.0)
        << "(a) rewritten against the restart sample: the samples around it read R";
    EXPECT_DOUBLE_EQ(written_rate(0x16), -1.0) << "(a) filled in from the restart sample";
    EXPECT_DOUBLE_EQ(written_rate(0x17), -1.0) << "rewritten against a one-off reading";
    EXPECT_DOUBLE_EQ(written_rate(0x18), -1.0)
        << "(b) rewritten against a 150x reading that spans an hour";
    EXPECT_DOUBLE_EQ(written_rate(0x19), -1.0) << "(b) rewritten against an hour-long reading";
    EXPECT_DOUBLE_EQ(written_rate(0x1a), -1.0);
    EXPECT_EQ(written.size(), 3u);

    // What is served. A recorded rate that is plausibly the pool's stands,
    // next to a stray reading too; a missing or implausible one is stood in
    // for by the history's reading at the block's time, in memory.
    const auto recent = mi.rest_recent_blocks_at(T2 + 600.0);
    struct Want { unsigned tag; double rate; const char* source; };
    const Want wants[] = {
        {0x10, 1.2 * R, "recorded"}, {0x11, R, "recorded"}, {0x12, R, "recorded"},
        {0x13, R, "recorded"},
        {0x14, R, "recorded"}, {0x15, R, "recorded"}, {0x16, 0.7 * R, "history"},
        {0x17, R, "recorded"},
        {0x18, R, "recorded"}, {0x19, 150.0 * R, "history"},
        {0x1a, 1.3 * R, "recorded"},
    };
    for (const auto& w : wants) {
        const auto row = find_row(recent, "hash", hash_of(w.tag));
        ASSERT_TRUE(row.is_object()) << "tag " << w.tag;
        EXPECT_NEAR(num(row, "pool_hashrate_at_find"), w.rate, R * 1e-9) << "tag " << w.tag;
        EXPECT_EQ(str(row, "pool_hashrate_source"), w.source) << "tag " << w.tag;
    }
}

// F6. The node feeds the history a sample a minute and kept every one for
// 400 days: 576,000 segments, and a trim that shifted them all every minute.
// Samples older than 31 days are now folded into hourly bins, a day's worth
// at a time. A round over whole hours has the same effort as before; a row
// the bins cover is never "repaired" against them.
TEST(PoolLuckInputs, SamplesOlderThanAMonthAreFoldedIntoHourlyBins)
{
    using FB = MiningInterface::FoundBlock;
    const double D = 1000.0;
    const double T0 = 277778.0 * 3600.0;   // an hour boundary, ~1.0e9
    const double hour = 3600.0, day = 86400.0;
    MiningInterface mi(false, nullptr, Blockchain::LITECOIN);
    // 34 days, a sample a minute. Within every hour the rate climbs from
    // 1.0 to 2.0 x 2^32 H/s over the first half and comes back down over the
    // second (1/30 a minute): the hour's mean is 1.5 x 2^32.
    const int minutes = 34 * 24 * 60;
    for (int i = 1; i <= minutes; ++i) {
        const int m = (i - 1) % 60;
        const double x = 1.0 + (m < 30 ? m : 60 - m) / 30.0;
        mi.add_luck_rate_sample(T0 + 60.0 * i, x * kT32, 0.0, D);
    }
    const double mean = 1.5;

    // 31 to 32 days of minute samples, the rest in hourly bins (unfolded:
    // 48,960 segments here, 576,000 after 400 days).
    const size_t held = mi.luck_rate_history_size();
    EXPECT_LE(held, static_cast<size_t>(32 * 1440 + 3 * 24 + 2));
    EXPECT_GE(held, static_cast<size_t>(31 * 1440));

    // Stored rows: each found in the first minute of an hour (the sample of
    // that minute reads 1.0 x 2^32) and stored at the hour's mean, 50 % up.
    auto stored_row = [&](uint64_t height, unsigned tag, double ts) {
        FB b;
        b.height = height;
        b.hash = hash_of(tag);
        b.ts = static_cast<uint64_t>(ts);
        b.status = MiningInterface::BlockStatus::confirmed;
        b.chain = "LTC";
        b.share_hash = b.hash;
        b.miner = kMiner;
        b.network_difficulty = D;
        b.pool_hashrate = mean * kT32;
        return b;
    };
    const std::vector<FB> on_disk = {
        stored_row(100, 0x20, T0 + 6 * hour + 30.0),               // 34 days old: binned
        stored_row(101, 0x21, T0 + 30 * hour + 30.0),              // 33 days old: binned
        stored_row(102, 0x22, T0 + 20 * day + 6 * hour + 30.0),    // 14 days old: minute samples
    };
    std::vector<FB> written;
    mi.set_found_block_persistence(
        [&written](const FB& b) { written.push_back(b); return true; },
        [&on_disk]() { return on_disk; });
    mi.load_persisted_found_blocks();

    // Only the row its own minute contradicts is rewritten.
    ASSERT_EQ(written.size(), 1u);
    EXPECT_EQ(written[0].hash, hash_of(0x22));
    EXPECT_NEAR(written[0].pool_hashrate, kT32, kT32 * 1e-9);

    const auto recent = mi.rest_recent_blocks_at(T0 + 34 * day);
    // The round over 24 whole hours of bins: 24 h at the hourly mean.
    const auto old_round = find_row(recent, "hash", hash_of(0x21));
    const double effort = 24 * hour * mean / D;
    EXPECT_EQ(str(old_round, "effort_method"), "integrated") << old_round.dump(1);
    EXPECT_NEAR(num(old_round, "effort"), effort, effort * 1e-9);
    EXPECT_NEAR(num(old_round, "history_coverage"), 1.0, 1e-9);
    EXPECT_NEAR(num(old_round, "pool_hashrate_at_find"), mean * kT32, kT32 * 1e-9);
    EXPECT_EQ(str(old_round, "pool_hashrate_source"), "recorded");
    // The 19-day round that runs from the bins into the minute samples: the
    // same mean throughout, but for its last 30 s -- the first half of a
    // minute sampled at 1.0, where a bin would have said the hour's mean.
    const auto fine_round = find_row(recent, "hash", hash_of(0x22));
    const double long_seconds = 20 * day + 6 * hour - 30 * hour;
    const double long_effort = ((long_seconds - 30.0) * mean + 30.0 * 1.0) / D;
    EXPECT_NEAR(num(fine_round, "effort"), long_effort, long_effort * 1e-9);
    EXPECT_NEAR(num(fine_round, "pool_hashrate_at_find"), kT32, kT32 * 1e-9);
}
