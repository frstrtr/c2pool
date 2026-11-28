// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// /best_share pct_of_block is measured against the network difficulty in
// effect when the record's hash was found, not the live one:
//   * parent legs: the difficulty of the job's block bits (the target the
//     stratum block check used), else the node's network difficulty at
//     record time;
//   * merged legs: the difficulty of the first aux chain's current work at
//     record time (the target try_submit_merged_blocks compares against).
// Each leg serves network_difficulty_at_share (0 = unknown) and pct_basis
// ("at_share" / "current"); network_difficulty stays the live value. The
// all-time legs persist it (sidecar v3); an older sidecar loads with it
// unknown and the leg is measured against the live difficulty
// (pct_basis "current").
//
// KAT values: a 58.56 M share checked against DOGE work of difficulty
// 62.63 M is 93.5% of a DOGE block; read against a later live 39.77 M it
// would be 147.2%.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cmath>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <c2pool/merged/merged_mining.hpp>

namespace {

using core::MiningInterface;
using c2pool::address::Blockchain;

// Aux targets for DOGE difficulties 62.63 M, 39.77 M and 95.0 M
// (2^224 / difficulty).
const char* const kAuxTarget6263 =
    "000000000000004493ab9585fad0000000000000000000000000000000000000";
const char* const kAuxTarget3977 =
    "000000000000006bfec272a5bd64000000000000000000000000000000000000";
const char* const kAuxTarget9500 =
    "000000000000002d35ce7ddf780e000000000000000000000000000000000000";

// The aux difficulty the merged manager serves for a target.
double aux_difficulty(const char* target_hex)
{
    uint256 t;
    t.SetHex(target_hex);
    return std::ldexp(1.0, 224) / t.getdouble();
}

// A DOGE backend whose current work the test moves: a new target comes with
// a new tip, so refresh_aux_work takes it as new work.
struct AuxBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string target_hex = kAuxTarget6263;
    int height = 5'000'001;
    AuxBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
    }
    std::string tip() const
    {
        char buf[16];
        std::snprintf(buf, sizeof buf, "%08x", static_cast<unsigned>(height));
        return std::string(56, '0') + buf;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = height;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(std::string(56, 'a') + tip().substr(56));
        w.target.SetHex(target_hex);
        w.prev_block_hash = tip();
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip(); }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

// An LTC MiningInterface over a merged manager with one DOGE chain.
struct MergedNode {
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm{ioc};
    AuxBackend* aux = nullptr;
    MiningInterface mi{/*testnet=*/false, /*node=*/nullptr, Blockchain::LITECOIN};

    MergedNode()
    {
        auto b = std::make_unique<AuxBackend>();
        aux = b.get();
        const auto cfg = b->cfg;
        mm.add_chain(cfg, std::move(b));
        mm.refresh_aux_work();
        mi.set_merged_mining_manager(&mm);
        EXPECT_NEAR(aux_now(), aux_difficulty(kAuxTarget6263), 1e-6);
    }
    double aux_now() const
    {
        const auto infos = mm.get_chain_infos();
        return infos.empty() ? 0.0 : infos.front().difficulty;
    }
    ~MergedNode() { mi.set_merged_mining_manager(nullptr); }

    // The aux chain moves to a new block with this target.
    void move_aux(const char* target_hex)
    {
        aux->target_hex = target_hex;
        ++aux->height;
        mm.refresh_aux_work();
        EXPECT_NEAR(aux_now(), aux_difficulty(target_hex), 1e-6) << "the aux work did not move";
    }
};

// An accepted LTC pseudoshare without header fields: the parent leg falls
// back to the node's network difficulty at record time.
void pseudoshare(MiningInterface& mi, double diff, const std::string& who)
{
    mi.record_best_pseudoshare(diff, who, "", "", "", "", "", "", 0, "", "", {});
}

double num(const nlohmann::json& j, const char* key)
{
    return j.at(key).get<double>();
}

std::string basis(const nlohmann::json& leg)
{
    return leg.at("pct_basis").get<std::string>();
}

void remove_sidecar(const std::string& log_path)
{
    std::remove(log_path.c_str());
    std::remove((log_path + ".best.json").c_str());
}

}  // namespace

// The incident: a 58.56 M round best found while the DOGE work needed
// 62.63 M; DOGE difficulty then falls to 39.77 M. The card must keep 93.5%,
// not show 147%.
TEST(BestShareAtTime, MergedPctStaysAgainstTheAuxWorkTheShareWasCheckedAgainst)
{
    MergedNode n;
    const double d1 = aux_difficulty(kAuxTarget6263);
    const double d2 = aux_difficulty(kAuxTarget3977);
    ASSERT_NEAR(d1, 62.63e6, 1.0);
    ASSERT_NEAR(d2, 39.77e6, 1.0);
    n.mi.update_network_difficulty(9.5e7, "test");

    pseudoshare(n.mi, 58.56e6, "w1");
    auto bs = n.mi.rest_best_share();
    ASSERT_TRUE(bs.contains("merged")) << bs.dump(1);
    EXPECT_NEAR(num(bs["merged"], "network_difficulty"), d1, 1e-6);
    EXPECT_NEAR(num(bs["merged"]["round"], "network_difficulty_at_share"), d1, 1e-6);

    n.move_aux(kAuxTarget3977);
    bs = n.mi.rest_best_share();
    EXPECT_EQ(bs["merged"]["symbol"].get<std::string>(), "DOGE");
    EXPECT_NEAR(num(bs["merged"], "network_difficulty"), d2, 1e-6)
        << "network_difficulty stays the live aux difficulty";
    for (const char* leg : {"round", "all_time"}) {
        const auto& e = bs["merged"][leg];
        EXPECT_DOUBLE_EQ(num(e, "difficulty"), 58.56e6) << leg;
        EXPECT_NEAR(num(e, "network_difficulty_at_share"), d1, 1e-6) << leg;
        EXPECT_NEAR(num(e, "pct_of_block"), 58.56e6 / d1 * 100.0, 1e-9) << leg;
        EXPECT_NEAR(num(e, "pct_of_block"), 93.5015, 1e-3) << leg;
        EXPECT_EQ(basis(e), "at_share") << leg;
    }
    // median_merged_pct is a property of the current window: live.
    n.mi.set_sharechain_stats_fn([] { return nlohmann::json{{"median_difficulty", 1.0e6}}; });
    EXPECT_NEAR(n.mi.rest_best_share()["median_merged_pct"].get<double>(), 1.0e6 / d2 * 100.0, 1e-9);
}

// The parent legs keep the network difficulty in effect at record time when
// the caller has no job bits (DASH / bip110 record_share_difficulty).
TEST(BestShareAtTime, ParentPctStaysAgainstTheDifficultyAtRecordTime)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::DASH);
    const double d1 = 2.0e8, d2 = 1.25e8;
    mi.update_network_difficulty(d1, "test");
    mi.record_share_difficulty(5.0e7, "w1", "aa");
    mi.update_network_difficulty(d2, "test");

    const auto bs = mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs, "network_difficulty"), d2) << "the live value is kept";
    for (const char* leg : {"round", "session", "all_time"}) {
        EXPECT_DOUBLE_EQ(num(bs[leg], "network_difficulty_at_share"), d1) << leg;
        EXPECT_DOUBLE_EQ(num(bs[leg], "pct_of_block"), 25.0) << leg;
        EXPECT_EQ(basis(bs[leg]), "at_share") << leg;
    }
    EXPECT_FALSE(bs.contains("merged"));

    // /local_stats best_share follows the same rule.
    const auto ls = mi.rest_local_stats()["best_share"];
    EXPECT_DOUBLE_EQ(num(ls, "network_difficulty"), d2);
    for (const char* leg : {"round", "session", "all_time"}) {
        EXPECT_DOUBLE_EQ(num(ls[leg], "network_difficulty_at_share"), d1) << leg;
        EXPECT_DOUBLE_EQ(num(ls[leg], "pct_of_block"), 25.0) << leg;
        EXPECT_EQ(basis(ls[leg]), "at_share") << leg;
    }
}

// The LTC stratum path measures the parent legs against the job's block
// bits, the target the block check used, not the node's difficulty.
TEST(BestShareAtTime, ParentAtShareIsTheJobsBlockBits)
{
    const std::string coinb1 = "01000000", coinb2 = "00000000";
    const std::string en1 = "00000000", en2 = "00000000";
    const std::string ntime = "6ae2a090", nonce = "00000000";
    const std::string prev(64, '1'), nbits = "1a0fffff";
    const uint32_t version = 0x20000000;
    const double d = MiningInterface::calculate_share_difficulty(
        coinb1, coinb2, en1, en2, ntime, nonce, version, prev, nbits, {});
    ASSERT_GT(d, 0.0);
    const double job_diff = chain::target_to_difficulty(chain::bits_to_target(0x1a0fffffu));
    ASSERT_GT(job_diff, 0.0);

    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::LITECOIN);
    mi.update_network_difficulty(job_diff * 3.0, "test");   // the node's, not the job's
    mi.record_best_pseudoshare(d, "w1", coinb1, coinb2, en1, en2, ntime, nonce,
                               version, prev, nbits, {});
    const auto bs = mi.rest_best_share();
    for (const char* leg : {"round", "session", "all_time"}) {
        EXPECT_DOUBLE_EQ(num(bs[leg], "network_difficulty_at_share"), job_diff) << leg;
        EXPECT_NEAR(num(bs[leg], "pct_of_block"), d / job_diff * 100.0, 1e-12) << leg;
        EXPECT_EQ(basis(bs[leg]), "at_share") << leg;
    }
    EXPECT_DOUBLE_EQ(num(bs, "network_difficulty"), job_diff * 3.0);
}

TEST(BestShareAtTime, BitsHexToDifficulty)
{
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1d00ffff"), 1.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1D00FFFF"), 1.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1a0fffff"),
                     chain::target_to_difficulty(chain::bits_to_target(0x1a0fffffu)));
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty(""), 0.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1d00fff"), 0.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1d00ffffff"), 0.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1d00ffzz"), 0.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("00000000"), 0.0);
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("1d800000"), 0.0) << "negative";
    EXPECT_DOUBLE_EQ(MiningInterface::bits_hex_to_difficulty("2100ffff"), 0.0) << "oversized";
}

// A higher best replaces the at-share difficulty with the difficulty; a
// lower one changes neither.
TEST(BestShareAtTime, HigherBestReplacesTheAtShareDifficulty)
{
    MergedNode n;
    const double m1 = aux_difficulty(kAuxTarget6263);
    const double m2 = aux_difficulty(kAuxTarget9500);
    n.mi.update_network_difficulty(1.0e8, "test");
    pseudoshare(n.mi, 3.0e7, "w1");

    n.move_aux(kAuxTarget9500);
    n.mi.update_network_difficulty(2.0e8, "test");
    pseudoshare(n.mi, 2.0e7, "w2");   // lower: no leg moves
    auto bs = n.mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 1.0e8);
    EXPECT_EQ(bs["round"]["miner"].get<std::string>(), "w1");
    EXPECT_NEAR(num(bs["merged"]["round"], "network_difficulty_at_share"), m1, 1e-6);

    pseudoshare(n.mi, 6.0e7, "w3");   // higher: every leg moves, with its difficulty
    bs = n.mi.rest_best_share();
    for (const char* leg : {"round", "session", "all_time"}) {
        EXPECT_DOUBLE_EQ(num(bs[leg], "difficulty"), 6.0e7) << leg;
        EXPECT_DOUBLE_EQ(num(bs[leg], "network_difficulty_at_share"), 2.0e8) << leg;
        EXPECT_NEAR(num(bs[leg], "pct_of_block"), 30.0, 1e-9) << leg;
    }
    for (const char* leg : {"round", "all_time"}) {
        EXPECT_DOUBLE_EQ(num(bs["merged"][leg], "difficulty"), 6.0e7) << leg;
        EXPECT_NEAR(num(bs["merged"][leg], "network_difficulty_at_share"), m2, 1e-6) << leg;
        EXPECT_NEAR(num(bs["merged"][leg], "pct_of_block"), 6.0e7 / m2 * 100.0, 1e-9) << leg;
    }
}

// A round reset clears the round legs' at-share difficulty with them; the
// all-time legs keep theirs.
TEST(BestShareAtTime, RoundResetClearsTheAtShareDifficulty)
{
    MergedNode n;
    const double m1 = aux_difficulty(kAuxTarget6263);
    const double m2 = aux_difficulty(kAuxTarget3977);
    n.mi.update_network_difficulty(1.0e8, "test");
    pseudoshare(n.mi, 3.0e7, "w1");

    n.mi.reset_best_difficulty_round(1793000000);
    n.mi.update_network_difficulty(4.0e8, "test");
    auto bs = n.mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "difficulty"), 0.0);
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 0.0);
    EXPECT_EQ(basis(bs["round"]), "current");
    EXPECT_DOUBLE_EQ(num(bs["merged"]["round"], "difficulty"), 0.0);
    EXPECT_DOUBLE_EQ(num(bs["merged"]["round"], "network_difficulty_at_share"), 0.0);
    EXPECT_EQ(basis(bs["merged"]["round"]), "current");
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "network_difficulty_at_share"), 1.0e8);
    EXPECT_DOUBLE_EQ(num(bs["session"], "network_difficulty_at_share"), 1.0e8);
    EXPECT_NEAR(num(bs["merged"]["all_time"], "network_difficulty_at_share"), m1, 1e-6);

    // The new round's first share brings the difficulty in effect now.
    n.move_aux(kAuxTarget3977);
    pseudoshare(n.mi, 1.0e7, "w2");
    bs = n.mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 4.0e8);
    EXPECT_NEAR(num(bs["merged"]["round"], "network_difficulty_at_share"), m2, 1e-6);
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "network_difficulty_at_share"), 1.0e8);
}

// Sidecar v3 keeps the at-share difficulty of both all-time legs.
TEST(BestShareAtTime, SidecarV3RoundTripKeepsTheAtShareDifficulty)
{
    const std::string log_path = "/tmp/c2pool_test_bestshare_attime_v3.json";
    remove_sidecar(log_path);
    const double m1 = aux_difficulty(kAuxTarget6263);
    {
        MergedNode n;
        n.mi.set_stat_log_path(log_path);
        n.mi.update_network_difficulty(1.0e8, "test");
        pseudoshare(n.mi, 5.856e7, "w1");
        n.mi.save_stat_log();
    }
    {
        std::ifstream f(log_path + ".best.json");
        const auto j = nlohmann::json::parse(f);
        EXPECT_EQ(j.value("v", 0), 3);
        EXPECT_DOUBLE_EQ(j.value("network_difficulty_at_share", 0.0), 1.0e8);
        ASSERT_TRUE(j.contains("merged"));
        EXPECT_NEAR(j["merged"].value("network_difficulty_at_share", 0.0), m1, 1e-6);
    }
    // Restart with other live difficulties and no merged manager yet.
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::LITECOIN);
    mi.set_stat_log_path(log_path);
    mi.update_network_difficulty(4.0e8, "test");
    mi.load_stat_log();
    const auto bs = mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "difficulty"), 5.856e7);
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "network_difficulty_at_share"), 1.0e8);
    EXPECT_NEAR(num(bs["all_time"], "pct_of_block"), 58.56, 1e-9);
    EXPECT_EQ(basis(bs["all_time"]), "at_share");
    ASSERT_TRUE(bs.contains("merged"));
    EXPECT_NEAR(num(bs["merged"]["all_time"], "network_difficulty_at_share"), m1, 1e-6);
    EXPECT_NEAR(num(bs["merged"]["all_time"], "pct_of_block"), 5.856e7 / m1 * 100.0, 1e-9);
    EXPECT_EQ(basis(bs["merged"]["all_time"]), "at_share");
    // Session and round are per-process.
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 0.0);
    EXPECT_DOUBLE_EQ(num(bs["session"], "network_difficulty_at_share"), 0.0);
    remove_sidecar(log_path);
}

// A v2 sidecar has no at-share difficulty: the all-time legs load with it
// unknown (0) and are measured against the live difficulty, pct_basis
// "current". Saving again does not invent one.
TEST(BestShareAtTime, SidecarV2LoadsWithTheAtShareUnknown)
{
    const std::string log_path = "/tmp/c2pool_test_bestshare_attime_v2.json";
    const std::string side = log_path + ".best.json";
    remove_sidecar(log_path);
    {
        std::ofstream f(side, std::ios::trunc);
        f << R"({"v":2,"difficulty":5.0e7,"miner":"w1","hash":"ab","ts":1793000000,)"
             R"("merged":{"difficulty":5.856e7,"miner":"w1","ts":1793000000}})";
    }
    MergedNode n;   // live DOGE work: 62.63 M
    const double m_live = aux_difficulty(kAuxTarget6263);
    n.mi.set_stat_log_path(log_path);
    n.mi.update_network_difficulty(2.0e8, "test");
    n.mi.load_stat_log();
    auto bs = n.mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "difficulty"), 5.0e7) << "a v2 file still loads on LTC";
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "network_difficulty_at_share"), 0.0);
    EXPECT_DOUBLE_EQ(num(bs["all_time"], "pct_of_block"), 25.0);
    EXPECT_EQ(basis(bs["all_time"]), "current");
    EXPECT_DOUBLE_EQ(num(bs["merged"]["all_time"], "difficulty"), 5.856e7);
    EXPECT_DOUBLE_EQ(num(bs["merged"]["all_time"], "network_difficulty_at_share"), 0.0);
    EXPECT_NEAR(num(bs["merged"]["all_time"], "pct_of_block"), 5.856e7 / m_live * 100.0, 1e-9);
    EXPECT_EQ(basis(bs["merged"]["all_time"]), "current");

    n.mi.save_stat_log();
    {
        std::ifstream f(side);
        const auto j = nlohmann::json::parse(f);
        EXPECT_EQ(j.value("v", 0), 3);
        EXPECT_DOUBLE_EQ(j.value("network_difficulty_at_share", -1.0), 0.0);
        EXPECT_DOUBLE_EQ(j["merged"].value("network_difficulty_at_share", -1.0), 0.0);
    }
    remove_sidecar(log_path);
}

// A v3 sidecar whose at-share value is not a positive number loads the leg
// with it unknown, the rest of the leg intact.
TEST(BestShareAtTime, SidecarV3MalformedAtShareIsUnknown)
{
    const std::string log_path = "/tmp/c2pool_test_bestshare_attime_bad.json";
    const std::string side = log_path + ".best.json";
    for (const char* bad : {"null", "-5.0", "\"1e8\"", "0"}) {
        remove_sidecar(log_path);
        {
            std::ofstream f(side, std::ios::trunc);
            f << R"({"v":3,"difficulty":5.0e7,"miner":"w1","hash":"ab","ts":1793000000,)"
              << R"("network_difficulty_at_share":)" << bad << "}";
        }
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::LITECOIN);
        mi.set_stat_log_path(log_path);
        mi.update_network_difficulty(1.0e8, "test");
        mi.load_stat_log();
        const auto bs = mi.rest_best_share();
        EXPECT_DOUBLE_EQ(num(bs["all_time"], "difficulty"), 5.0e7) << bad;
        EXPECT_EQ(bs["all_time"]["miner"].get<std::string>(), "w1") << bad;
        EXPECT_DOUBLE_EQ(num(bs["all_time"], "network_difficulty_at_share"), 0.0) << bad;
        EXPECT_EQ(basis(bs["all_time"]), "current") << bad;
        EXPECT_DOUBLE_EQ(num(bs["all_time"], "pct_of_block"), 50.0) << bad;
    }
    remove_sidecar(log_path);
}

// The BTC / BCH sinks pass the job's block bits; a sink without them (or
// with malformed ones) falls back to the node's difficulty at record time.
TEST(BestShareAtTime, UpdateBestDifficultyTakesTheCallersDifficulty)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::BITCOIN);
    mi.update_network_difficulty(1.0e14, "test");
    mi.update_best_difficulty(2.0e12, "w1", "", /*update_merged=*/false,
                              MiningInterface::bits_hex_to_difficulty("1d00ffff"));
    auto bs = mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 1.0);
    EXPECT_EQ(basis(bs["round"]), "at_share");

    mi.update_best_difficulty(3.0e12, "w2", "", /*update_merged=*/false,
                              MiningInterface::bits_hex_to_difficulty("bad"));
    bs = mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 1.0e14);
    EXPECT_NEAR(num(bs["round"], "pct_of_block"), 3.0, 1e-9);
}

// No network difficulty known at record time: the leg is measured against
// the live one once that is known, and says so.
TEST(BestShareAtTime, NoDifficultyAtRecordTimeFallsBackToTheLiveOne)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, Blockchain::DASH);
    mi.record_share_difficulty(5.0e7, "w1", "aa");
    mi.update_network_difficulty(1.0e8, "test");
    const auto bs = mi.rest_best_share();
    EXPECT_DOUBLE_EQ(num(bs["round"], "network_difficulty_at_share"), 0.0);
    EXPECT_DOUBLE_EQ(num(bs["round"], "pct_of_block"), 50.0);
    EXPECT_EQ(basis(bs["round"]), "current");
}

