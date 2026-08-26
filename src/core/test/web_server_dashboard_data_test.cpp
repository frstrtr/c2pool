// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Dashboard DATA honesty KATs — every case pins a defect measured on the two
// hotel DASH dashboards on 2026-08-05 (primary :8080 / reserve :8081, both on
// the same build):
//
//   * rows for OUR OWN accepted blocks h=2516911/2516914 rendered as junk on
//     the primary (miner="" subsidy=0 network_difficulty=0.0 luck=null) —
//     legacy-persisted rows blocked the attributed re-record forever;
//   * the reserve's rows carried luck=0.0/expected_time=0.0 because network
//     difficulty was read from a cache that only a dashboard poll refreshes,
//     and the luck-trend chart DREW those zeros;
//   * /local_stats said the miner share of a block was 53% when the ACCEPTED
//     coinbase of h=2516911 paid miners 25% — the DIP-0027 platform burn was
//     counted as miner money;
//   * best_share.all_time reset on restart (all_time == session after 36 min
//     of uptime);
//   * /global_stats last_block was a hardcoded 0 with 107 ledger rows on disk.
//
// All display-path; no consensus surface is reachable from anything here.

#include <gtest/gtest.h>

#include <core/web_server.hpp>
#include <core/uint256.hpp>

#include <cstdio>
#include <string>
#include <chrono>
#include <fstream>
#include <thread>

using core::MiningInterface;

namespace {

nlohmann::json find_block(const nlohmann::json& arr, const std::string& hash)
{
    for (const auto& b : arr)
        if (b.contains("hash") && b["hash"].get<std::string>() == hash)
            return b;
    return nlohmann::json(nullptr);
}

// Wire a live coin template the way main_dash does: netdiff 1.0 and a pool
// hashrate of exactly 2^32 H/s make expected_time == 1 s, so the luck
// arithmetic is checkable by eye. (MiningInterface is neither movable nor
// copyable — mutexes/atomics — so this configures in place.)
void wire_dash_template(MiningInterface& mi)
{
    mi.set_coin_work_fn([]() {
        MiningInterface::CoinWorkInfo cw;
        cw.valid               = true;
        cw.network_difficulty  = 1.0;
        cw.coinbase_value_sat  = 177109977;   // the real h=2516911 total
        cw.payment_amount_sat  = 83044903;    // MN payee alone (legacy field)
        cw.payments_total_sat  = 132832482;   // MN payee + platform burn
        cw.burn_sat            = 49787579;    // the OP_RETURN burn
        cw.height              = 2516911;
        cw.template_age_sec    = 7;
        return cw;
    });
    mi.set_pool_hashrate_fn([]() { return 4294967296.0; });   // 2^32 H/s
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// 1. Luck / expected-time math, with the netdiff-at-find fallback
// ═══════════════════════════════════════════════════════════════════════════

// THE INCIDENT: both record paths passed a cached network difficulty that is
// only refreshed when somebody polls /local_stats, so blocks found before the
// first dashboard hit recorded netdiff=0 -> expected_time=0 -> luck=0, and
// the chart drew the zeros. The live template knows the real difficulty; the
// record path must ask it before accepting a zero.
TEST(DashboardData, LuckIsComputedFromTheLiveTemplateWhenTheCacheIsCold)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    wire_dash_template(mi);

    const std::string h1 =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const std::string h2 =
        "4444444444444444444444444444444444444444444444444444444444444444";

    // NO dashboard poll has happened: the netdiff cache is cold (0), and the
    // caller passes 0 for both netdiff and pool hashrate — the exact call
    // shape of the DASH record sites after this fix.
    mi.record_found_block(2516911, uint256S(h1), /*ts=*/1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h1,
                          /*network_difficulty=*/0.0,
                          /*share_difficulty=*/240228.0,
                          /*pool_hashrate=*/0.0, /*subsidy=*/0);
    // Second block 2 s later: expected_time = 1.0 * 2^32 / 2^32 = 1 s,
    // time_to_find = 2 s, luck = 50%.
    mi.record_found_block(2516914, uint256S(h2), /*ts=*/1785955174, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h2,
                          0.0, 240228.0, 0.0, 0);

    auto blk = find_block(mi.rest_recent_blocks(), h2);
    ASSERT_TRUE(blk.is_object());

    ASSERT_TRUE(blk["network_difficulty"].is_number())
        << "netdiff must be recovered from the live template, not stored as 0";
    EXPECT_DOUBLE_EQ(blk["network_difficulty"].get<double>(), 1.0);
    ASSERT_TRUE(blk["expected_time"].is_number())
        << "expected_time = netdiff * 2^32 / pool_hashrate must be computable";
    EXPECT_DOUBLE_EQ(blk["expected_time"].get<double>(), 1.0);
    ASSERT_TRUE(blk["time_to_find"].is_number());
    EXPECT_DOUBLE_EQ(blk["time_to_find"].get<double>(), 2.0);
    ASSERT_TRUE(blk["luck"].is_number());
    EXPECT_DOUBLE_EQ(blk["luck"].get<double>(), 50.0);
    EXPECT_EQ(blk["luck_method"].get<std::string>(), "simple_avg");

    // Subsidy fallback: the caller passed 0 on the node's own chain, so the
    // template's coinbasevalue must have been recorded instead (row 2516914
    // showed subsidy=0 on the hotel because the WebServer-held template is
    // empty on the embedded arm).
    EXPECT_EQ(blk["subsidy"].get<uint64_t>(), 177109977u);

    // Pool hashrate: 0 from the caller routes to the pool estimator.
    ASSERT_TRUE(blk["pool_hashrate_at_find"].is_number());
    EXPECT_DOUBLE_EQ(blk["pool_hashrate_at_find"].get<double>(), 4294967296.0);
}

// The FIRST block of a ledger has no predecessor, hence no time_to_find and
// no luck MEASUREMENT. That must surface as null ("not computed"), never as
// a numeric 0 the chart will draw — 0% luck is a catastrophe claim, and the
// hotel chart made exactly that claim out of unmeasured rows.
TEST(DashboardData, UncomputedLuckIsNullNeverZero)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    wire_dash_template(mi);
    const std::string h =
        "5555555555555555555555555555555555555555555555555555555555555555";
    mi.record_found_block(2516911, uint256S(h), 1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h,
                          0.0, 240228.0, 0.0, 0);

    auto blk = find_block(mi.rest_recent_blocks(), h);
    ASSERT_TRUE(blk.is_object());
    EXPECT_TRUE(blk["luck"].is_null())
        << "a first block has no luck measurement; 0 is a fabricated one";
    EXPECT_TRUE(blk["time_to_find"].is_null());
    EXPECT_EQ(blk["luck_method"].get<std::string>(), "first_block");

    // /luck_stats feeds the trend chart: same rule there.
    auto luck = mi.rest_luck_stats();
    ASSERT_FALSE(luck["blocks"].empty());
    EXPECT_TRUE(luck["blocks"][0]["luck"].is_null())
        << "the trend chart must SKIP unmeasured rows, not draw them at 0";
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Junk-row honesty + ENRICHMENT
// ═══════════════════════════════════════════════════════════════════════════

// THE INCIDENT: the primary's rows for our own blocks were persisted by an
// older binary as miner="" share="" subsidy=0, restored at startup, and the
// dedup's plain early-return then blocked the attributed re-record (the
// sharechain hook) forever. An attributed record must UPGRADE an
// unattributed row; nothing may downgrade.
TEST(DashboardData, AttributedRecordEnrichesAJunkRowInsteadOfBeingDropped)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    const std::string h =
        "6666666666666666666666666666666666666666666666666666666666666666";

    // The legacy junk row (what load_persisted restored on the primary).
    mi.record_found_block(2516911, uint256S(h), 1785955172, "DASH",
                          /*miner=*/"", /*share_hash=*/"",
                          0.0, 0.0, 0.0, 0);
    {
        auto blk = find_block(mi.rest_recent_blocks(), h);
        ASSERT_TRUE(blk.is_object());
        EXPECT_FALSE(blk["found_locally"].get<bool>());
        // Junk numerics are honest-absent, not zero-valued data.
        EXPECT_TRUE(blk["network_difficulty"].is_null());
        EXPECT_TRUE(blk["subsidy"].is_null());
        EXPECT_TRUE(blk["share_difficulty"].is_null());
        EXPECT_TRUE(blk["pool_hashrate_at_find"].is_null());
    }

    // The attributed record arrives (sharechain hook after restart).
    mi.record_found_block(2516911, uint256S(h), 1785955172, "DASH",
                          "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4", h,
                          47674323.0, 240228.0, 48896352084867.0, 177109977);

    auto arr = mi.rest_recent_blocks();
    int copies = 0;
    for (const auto& b : arr)
        if (b["hash"].get<std::string>() == h) ++copies;
    EXPECT_EQ(copies, 1) << "enrichment must upgrade in place, never duplicate";

    auto blk = find_block(arr, h);
    EXPECT_TRUE(blk["found_locally"].get<bool>())
        << "the junk row must have been upgraded by the attributed record";
    EXPECT_EQ(blk["miner"].get<std::string>(),
              "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4");
    EXPECT_DOUBLE_EQ(blk["network_difficulty"].get<double>(), 47674323.0);
    EXPECT_EQ(blk["subsidy"].get<uint64_t>(), 177109977u);
}

TEST(DashboardData, AnAttributedRowIsNeverDowngraded)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    const std::string h =
        "7777777777777777777777777777777777777777777777777777777777777777";
    mi.record_found_block(2516911, uint256S(h), 1785955172, "DASH",
                          "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4", h,
                          47674323.0, 240228.0, 1.0, 177109977);
    // A later unattributed record for the same block (relay echo).
    mi.record_found_block(2516911, uint256S(h), 1785955999, "DASH",
                          "", "", 0.0, 0.0, 0.0, 0);

    auto blk = find_block(mi.rest_recent_blocks(), h);
    EXPECT_EQ(blk["miner"].get<std::string>(),
              "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4")
        << "an unattributed echo must not clobber real attribution";
    EXPECT_EQ(blk["ts"].get<uint64_t>(), 1785955172u);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Block-value split — the ACCEPTED-coinbase truth
// ═══════════════════════════════════════════════════════════════════════════

// THE INCIDENT, in the exact numbers of our accepted h=2516911: coinbase
// total 1.77109977, MN payee 0.83044903, platform burn 0.49787579 => miners
// received 0.44277495 (25%). The card computed miner share as coinbasevalue
// minus the MN payee ALONE — 0.94065074 (53%) — silently counting the burn
// as miner money.
TEST(DashboardData, MinerShareSubtractsEveryProtocolOutputNotJustTheMnPayee)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    wire_dash_template(mi);
    auto stats = mi.rest_local_stats();

    EXPECT_NEAR(stats["block_value"].get<double>(), 1.77109977, 1e-9);
    // payments = MN payee + burn (payments_total_sat), NOT the MN payee alone.
    EXPECT_NEAR(stats["block_value_payments"].get<double>(), 1.32832482, 1e-9);
    EXPECT_NEAR(stats["block_value_burn"].get<double>(), 0.49787579, 1e-9);
    // gross miner share = the 25% the chain actually paid, not 53%.
    EXPECT_NEAR(stats["block_value_miner_gross"].get<double>(), 0.44277495, 1e-9);
    // The reconciliation identity #948 documented still holds.
    EXPECT_NEAR(stats["block_value_miner_gross"].get<double>()
                    + stats["block_value_payments"].get<double>(),
                stats["block_value"].get<double>(), 1e-9);
    // WHICH template, and how old: staleness is now visible instead of a
    // stale number rendering as current.
    EXPECT_EQ(stats["block_value_height"].get<uint64_t>(), 2516911u);
    EXPECT_EQ(stats["block_value_age_sec"].get<int64_t>(), 7);
}

// A producer that does NOT fill payments_total_sat (the LTC path) must keep
// byte-identical legacy behaviour: payments falls back to payment_amount_sat.
TEST(DashboardData, LegacyProducerWithoutPaymentsTotalIsUnchanged)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    mi.set_coin_work_fn([]() {
        MiningInterface::CoinWorkInfo cw;
        cw.valid              = true;
        cw.coinbase_value_sat = 100000000;
        cw.payment_amount_sat = 25000000;
        // payments_total_sat / burn_sat left 0 — legacy producer.
        return cw;
    });
    auto stats = mi.rest_local_stats();
    EXPECT_NEAR(stats["block_value_payments"].get<double>(), 0.25, 1e-12);
    EXPECT_NEAR(stats["block_value_miner_gross"].get<double>(), 0.75, 1e-12);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Fee units say their own name
// ═══════════════════════════════════════════════════════════════════════════

// THE INCIDENT: /fee returned the bare string "1.0" and /local_stats carried
// fee=1.0 alongside donation_proportion=0.01 — two spellings of the same 1%
// in two different units, with nothing naming either unit.
TEST(DashboardData, FeeFieldsDeclareTheirUnits)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    mi.set_pool_fee_percent(1.0);
    auto stats = mi.rest_local_stats();
    EXPECT_DOUBLE_EQ(stats["fee"].get<double>(), 1.0);            // legacy: percent
    EXPECT_DOUBLE_EQ(stats["fee_percent"].get<double>(), 1.0);    // named unit
    EXPECT_DOUBLE_EQ(stats["donation_percent"].get<double>(), 1.0);
    EXPECT_DOUBLE_EQ(stats["donation_proportion"].get<double>(), 0.01);
    EXPECT_EQ(stats["fee_units"].get<std::string>(), "percent");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. last_block comes from the ledger, not a hardcoded 0
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashboardData, GlobalStatsLastBlockReadsTheFoundBlockLedger)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    // Empty ledger: 0 is then the truth (no block ever found), ts is null.
    {
        auto gs = mi.rest_global_stats();
        EXPECT_EQ(gs["last_block"].get<uint64_t>(), 0u);
        EXPECT_TRUE(gs["last_block_ts"].is_null());
    }
    const std::string h =
        "8888888888888888888888888888888888888888888888888888888888888888";
    mi.record_found_block(2516911, uint256S(h), 1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h,
                          1.0, 1.0, 1.0, 1);
    auto gs = mi.rest_global_stats();
    EXPECT_EQ(gs["last_block"].get<uint64_t>(), 2516911u)
        << "both hotel nodes showed last_block=0 with 100+ rows on disk";
    EXPECT_EQ(gs["last_block_ts"].get<uint64_t>(), 1785955172u);
    // And the miners-count scope is stated, so 5-vs-33-rigs cannot again be
    // read as a bug: 5 counts pool-wide payout addresses, rigs are local
    // stratum workers, published separately.
    EXPECT_EQ(gs["unique_miners_scope"].get<std::string>(),
              "sharechain-payout-addresses-pool-wide");
    EXPECT_TRUE(gs.contains("local_workers"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. All-time best share survives a restart
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashboardData, AllTimeBestShareSurvivesARestart)
{
    const std::string log_path = "/tmp/c2pool_test_bestshare_statlog.json";
    std::remove(log_path.c_str());
    std::remove((log_path + ".best.json").c_str());

    {
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                           c2pool::address::Blockchain::DASH);
        mi.set_stat_log_path(log_path);
        mi.record_share_difficulty(268585.98,
                                   "XudUrCvNXLRwyJqnpdEvZC8Hd6DRAW81TV",
                                   "aa11");
        mi.save_stat_log();   // the 100 s tick / clean shutdown path
    }

    // "Restart": a fresh interface loading the same stat-log path.
    MiningInterface mi2(/*testnet=*/false, /*node=*/nullptr,
                        c2pool::address::Blockchain::DASH);
    mi2.set_stat_log_path(log_path);
    mi2.load_stat_log();

    auto stats = mi2.rest_local_stats();
    const auto& best = stats["best_share"];
    EXPECT_NEAR(best["all_time"]["difficulty"].get<double>(), 268585.98, 1e-6)
        << "the hotel primary showed all_time == session after 36 min of"
           " uptime: 'all time' reset on every restart";
    EXPECT_EQ(best["all_time"]["miner"].get<std::string>(),
              "XudUrCvNXLRwyJqnpdEvZC8Hd6DRAW81TV");
    EXPECT_EQ(best["all_time"]["hash"].get<std::string>(), "aa11");
    // Session is honestly per-process: the restarted node has seen nothing.
    EXPECT_DOUBLE_EQ(best["session"]["difficulty"].get<double>(), 0.0);

    std::remove(log_path.c_str());
    std::remove((log_path + ".best.json").c_str());
}

// A persisted record must only ever RAISE the in-memory one.
TEST(DashboardData, PersistedBestShareNeverLowersALiveRecord)
{
    const std::string log_path = "/tmp/c2pool_test_bestshare_statlog2.json";
    std::remove(log_path.c_str());
    std::remove((log_path + ".best.json").c_str());
    {
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                           c2pool::address::Blockchain::DASH);
        mi.set_stat_log_path(log_path);
        mi.record_share_difficulty(100.0, "Xlow", "bb22");
        mi.save_stat_log();
    }
    MiningInterface mi2(/*testnet=*/false, /*node=*/nullptr,
                        c2pool::address::Blockchain::DASH);
    mi2.set_stat_log_path(log_path);
    mi2.record_share_difficulty(500.0, "Xhigh", "cc33");   // before the load
    mi2.load_stat_log();
    auto stats = mi2.rest_local_stats();
    EXPECT_DOUBLE_EQ(stats["best_share"]["all_time"]["difficulty"].get<double>(),
                     500.0)
        << "loading a 100-difficulty record over a live 500 would erase the"
           " better share";
    std::remove(log_path.c_str());
    std::remove((log_path + ".best.json").c_str());
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. The node-fee amount is readable WITHOUT knowing which coin this is
// ═══════════════════════════════════════════════════════════════════════════

// THE INCIDENT (live, 2026-08-06, DASH node 109.161.52.148:8081): the Node Fee
// card showed "- DASH" — no amount. /local_stats on that node carried
//     node_fee_dash = 0.004240003478694174
//     node_fee_ltc  = ABSENT
// and dashboard.html:3228 read `local_stats.node_fee_ltc` unconditionally.
// d3.format('.4f')(undefined) renders nothing, so the card sat at "-" on a node
// that had computed the number correctly.
//
// There is exactly ONE shared web-static/dashboard.html for every coin, so the
// key it reads cannot be per-coin. This pins the coin-neutral `node_fee` on
// EVERY blockchain — a fix that only added `node_fee_bch`, say, would leave the
// next coin broken the same way.
//
// The coin-suffixed keys are pinned as UNCHANGED in the same test: they are the
// p2pool-compat surface, and the dashboard falls back to them so a newer page
// dropped on an older binary still renders.
namespace {

// Fee amount = miner_subsidy x fee% x (local hashrate / pool hashrate).
// 4.0 coins of miner subsidy (no protocol-payment lane), 1% fee, and
// 1000/4000 = a quarter of the pool -> 4.0 x 0.01 x 0.25 = 0.01 exactly, so
// the number is checkable by eye rather than merely "greater than zero".
constexpr double kExpectedNodeFee = 0.01;

void wire_fee_node(MiningInterface& mi)
{
    mi.set_coin_work_fn([]() {
        MiningInterface::CoinWorkInfo cw;
        cw.valid              = true;
        cw.coinbase_value_sat = 400000000;   // 4.0
        cw.height             = 1000000;
        return cw;
    });
    mi.set_pool_fee_percent(1.0);
    mi.set_stratum_hashrate_fn([]() { return 1000.0; });
    mi.set_pool_hashrate_fn([]()    { return 4000.0; });
}

} // namespace

TEST(DashboardData, NodeFeeAmountIsExposedUnderACoinNeutralKey)
{
    struct Case { c2pool::address::Blockchain chain; const char* legacy; };
    const Case cases[] = {
        {c2pool::address::Blockchain::DASH,     "node_fee_dash"},
        {c2pool::address::Blockchain::LITECOIN, "node_fee_ltc"},
        {c2pool::address::Blockchain::DOGECOIN, "node_fee_doge"},
        {c2pool::address::Blockchain::BITCOIN,  "node_fee_ltc"},
        {c2pool::address::Blockchain::DIGIBYTE, "node_fee_ltc"},
    };

    for (const auto& c : cases) {
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr, c.chain);
        wire_fee_node(mi);
        auto stats = mi.rest_local_stats();

        // THE FIX: present on every coin, so the shared page needs no per-coin
        // knowledge to render the card.
        ASSERT_TRUE(stats.contains("node_fee"))
            << "no coin-neutral node_fee — the shared dashboard cannot read"
               " this coin's amount";
        EXPECT_DOUBLE_EQ(stats["node_fee"].get<double>(), kExpectedNodeFee);

        // The legacy key still carries the identical value (compat surface).
        ASSERT_TRUE(stats.contains(c.legacy));
        EXPECT_DOUBLE_EQ(stats[c.legacy].get<double>(),
                         stats["node_fee"].get<double>());
    }
}

// THE NEGATIVE CONTROL: this reproduces the shipped defect exactly. On DASH the
// key the dashboard actually read is absent, and reading it yields the
// undefined that formatted to nothing.
TEST(DashboardData, TheKeyTheDashboardUsedToReadIsAbsentOnDash)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    wire_fee_node(mi);
    auto stats = mi.rest_local_stats();

    EXPECT_FALSE(stats.contains("node_fee_ltc"))
        << "if DASH ever emits node_fee_ltc this test is stale — but the "
           "dashboard must still not depend on it";
    EXPECT_TRUE(stats.contains("node_fee_dash"));
    EXPECT_TRUE(stats.contains("node_fee"));

    // The dashboard's resolution order (node_fee -> node_fee_<symbol> ->
    // node_fee_ltc) transcribed: step 1 alone already answers.
    EXPECT_DOUBLE_EQ(stats["node_fee"].get<double>(),
                     stats["node_fee_dash"].get<double>());
}

// A node with no local miners owes no fee — and must say 0, not omit the key,
// so the card renders "0.0000" rather than falling back through the chain to
// some other coin's number.
TEST(DashboardData, NodeFeeIsZeroNotAbsentWhenNothingIsMiningLocally)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::DASH);
    mi.set_pool_fee_percent(1.0);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });
    mi.set_pool_hashrate_fn([]()    { return 4000.0; });
    auto stats = mi.rest_local_stats();
    ASSERT_TRUE(stats.contains("node_fee"));
    EXPECT_DOUBLE_EQ(stats["node_fee"].get<double>(), 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. block_value_payments only means "protocol outputs" where such a lane exists
// ═══════════════════════════════════════════════════════════════════════════

// The API sets block_value_payments == block_value on every non-DASH coin
// (there is no masternode/superblock lane to deduct), so the dashboard must
// gate the "− protocol" line on payments < block_value. Pinning the shape here
// keeps that front-end gate honest: if a coin ever starts reporting a real
// payments lane, the line appears on its own.
TEST(DashboardData, PaymentsEqualBlockValueWhereThereIsNoProtocolLane)
{
    {
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                           c2pool::address::Blockchain::DASH);
        wire_dash_template(mi);
        auto stats = mi.rest_local_stats();
        // A genuine deduction: 1.77109977 total, 1.32832482 protocol outputs.
        EXPECT_LT(stats["block_value_payments"].get<double>(),
                  stats["block_value"].get<double>());
        EXPECT_GT(stats["block_value_burn"].get<double>(), 0.0);
    }
    {
        MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                           c2pool::address::Blockchain::LITECOIN);
        mi.set_coin_work_fn([]() {
            MiningInterface::CoinWorkInfo cw;
            cw.valid              = true;
            cw.coinbase_value_sat = 671473381;
            cw.height             = 3000000;
            return cw;
        });
        auto stats = mi.rest_local_stats();
        EXPECT_DOUBLE_EQ(stats["block_value_payments"].get<double>(),
                         stats["block_value"].get<double>())
            << "the dashboard's protocol-lane gate keys on this equality";
        EXPECT_FALSE(stats.contains("block_value_burn"));
    }
}

// ── AUTHORSHIP: three states, and "unknown" is one of them ───────────────
//
// Block 2517979 (2026-08-07) read as ours by every check the log offered --
// our address in the coinbase, BLOCK CONFIRMED printed, confirmations=1 --
// and was found by another node on the sharechain. The coinbase cannot
// answer authorship on a p2pool sharechain: it pays every participant.
//
// The first cut of the fix used a bool defaulting to false. That is a
// two-valued answer to a three-valued question, and its default reads as a
// CLAIM -- every LTC/DGB/BTC/BCH block, whose call sites do not label, would
// have announced a sharechain peer as its finder. These tests pin the third
// state and the direction of the merge.
TEST(FoundBlockAuthorship, UnlabelledCallSiteStaysUnknownAndClaimsNothing)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const std::string h =
        "5555555555555555555555555555555555555555555555555555555555555555";
    // The LTC/DGB/BTC/BCH call shape: no authorship argument at all.
    mi.record_found_block(2500000, uint256S(h), /*ts=*/1785955172, "LTC",
                          "LhY4example", h, 1000.0, 1.0, 0.0, 0);
    auto blk = find_block(mi.rest_recent_blocks(), h);
    ASSERT_TRUE(blk.is_object());
    EXPECT_EQ(blk["found_by"].get<std::string>(), "unknown")
        << "a lane that does not label must say unknown, never name a finder";
}

TEST(FoundBlockAuthorship, LabelledSitesReportTheFinderTheyKnow)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const std::string hp =
        "6666666666666666666666666666666666666666666666666666666666666666";
    const std::string hl =
        "7777777777777777777777777777777777777777777777777777777777777777";
    mi.record_found_block(2517979, uint256S(hp), 1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", hp,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::sharechain_peer);
    mi.record_found_block(2517980, uint256S(hl), 1785955174, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", hl,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::this_node);
    auto blocks = mi.rest_recent_blocks();
    EXPECT_EQ(find_block(blocks, hp)["found_by"].get<std::string>(),
              "sharechain_peer");
    EXPECT_EQ(find_block(blocks, hl)["found_by"].get<std::string>(),
              "this_node");
}

TEST(FoundBlockAuthorship, EnrichmentRaisesAuthorshipAndNeverLowersIt)
{
    MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                       c2pool::address::Blockchain::LITECOIN);
    const std::string h =
        "8888888888888888888888888888888888888888888888888888888888888888";
    // The real ordering on DASH: the peer path sees the block on the
    // sharechain first, and our own dispatch enriches the SAME row after.
    // That second call is the one that knows we built it.
    mi.record_found_block(2517981, uint256S(h), 1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::sharechain_peer);
    mi.record_found_block(2517981, uint256S(h), 1785955172, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::this_node);
    EXPECT_EQ(find_block(mi.rest_recent_blocks(), h)["found_by"].get<std::string>(),
              "this_node");

    // And the reverse order must NOT demote it. An assignment-style merge
    // would; taking the max is why it cannot.
    const std::string h2 =
        "9999999999999999999999999999999999999999999999999999999999999999";
    mi.record_found_block(2517982, uint256S(h2), 1785955174, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h2,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::this_node);
    mi.record_found_block(2517982, uint256S(h2), 1785955174, "DASH",
                          "XoZcEFbqwnty5secW7HYjdQEZYfubMkURu", h2,
                          1000.0, 1.0, 0.0, 0,
                          MiningInterface::BlockAuthorship::sharechain_peer);
    EXPECT_EQ(find_block(mi.rest_recent_blocks(), h2)["found_by"].get<std::string>(),
              "this_node")
        << "a later, less informed call must not downgrade a known finder";
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. G4: year-scale binned graph history (#159)
// ═══════════════════════════════════════════════════════════════════════════
//
// These extend the persistence round-trip (case 6) to the new <path>.views
// sidecar: a clean save/reload serves the long horizons from the bins, the
// pool_rates served dict keeps its exact {good,orphan,dead} shape with no
// leaked 'null' counter, and a missing / corrupt / truncated sidecar degrades
// to the flat fallback without ever crashing load or startup.

namespace {

// Poll until the binned views finish loading/seeding (background thread), with
// a generous bound so slow CI never flakes. Returns true if ready in time.
bool wait_views_ready(const MiningInterface& mi, int timeout_ms = 5000)
{
    for (int waited = 0; waited < timeout_ms; waited += 20) {
        if (mi.graph_views_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return mi.graph_views_ready();
}

// The week view's bin width == 604800/300 == 2016 s; the flat path hardcodes
// 300.0 for d[2]. Reading the width tells us WHICH path served the request.
constexpr double kWeekBinWidth = 604800.0 / 300.0;  // 2016.0

}  // namespace

TEST(DashboardData, GraphViewsSidecarRoundTrip)
{
    const std::string path = "/tmp/c2pool_test_g4_views.json";
    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());

    {
        MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
        mi.set_pool_hashrate_fn([]() { return 1234.0; });
        mi.set_stat_log_path(path);
        mi.load_stat_log();               // empty flat -> schema built + seeded
        ASSERT_TRUE(wait_views_ready(mi));
        for (int i = 0; i < 5; ++i) mi.update_stat_log();  // fan into the bins
        mi.save_stat_log();               // writes flat FIRST, then .views
    }

    // The sidecar exists on disk.
    { std::ifstream f(path + ".views"); ASSERT_TRUE(f.good()); }

    // Reload: a clean load must adopt the bins (no reseed) and serve week from
    // them — provable by the bin width in d[2].
    MiningInterface mi2(false, nullptr, c2pool::address::Blockchain::DASH);
    mi2.set_stat_log_path(path);
    mi2.load_stat_log();
    ASSERT_TRUE(wait_views_ready(mi2));

    auto week = mi2.rest_web_graph_data("pool_hash_rate", "last_week");
    ASSERT_TRUE(week.is_array());
    ASSERT_FALSE(week.empty());
    // The bin path's newest bin is partial, so its width is < the full 2016 s
    // bin width but is NEVER the flat path's hardcoded 300.0 — that difference
    // is the proof the request was answered from the bins.
    const double wk_w = week.back()[2].get<double>();
    EXPECT_NE(wk_w, 300.0) << "week must be served from the bins, not the flat 300s path";
    EXPECT_GT(wk_w, 0.0);
    EXPECT_LE(wk_w, kWeekBinWidth + 1e-6);

    // last_hour stays on the flat path (unchanged), width == 300.
    auto hour = mi2.rest_web_graph_data("pool_hash_rate", "last_hour");
    ASSERT_TRUE(hour.is_array());
    if (!hour.empty())
        EXPECT_NEAR(hour.back()[2].get<double>(), 300.0, 1e-6)
            << "last_hour must keep the flat path unchanged";

    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());
}

// The served pool_rates dict keeps EXACTLY {good,orphan,dead}; the internal
// 'null' sample-counter key must never leak (dashboard.html sums d[1]['null']
// into DOA — review-mandated served-dict hygiene).
TEST(DashboardData, GraphViewsPoolRatesServedShapeHasNoNullKey)
{
    const std::string path = "/tmp/c2pool_test_g4_poolrates.json";
    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());

    MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    mi.set_pool_hashrate_fn([]() { return 5000.0; });
    mi.set_stat_log_path(path);
    mi.load_stat_log();
    ASSERT_TRUE(wait_views_ready(mi));
    for (int i = 0; i < 4; ++i) mi.update_stat_log();

    auto week = mi.rest_web_graph_data("pool_rates", "last_week");
    ASSERT_TRUE(week.is_array());
    ASSERT_FALSE(week.empty());
    const double wk_w = week.back()[2].get<double>();
    EXPECT_NE(wk_w, 300.0);            // from bins, not the flat 300s path
    EXPECT_LE(wk_w, kWeekBinWidth + 1e-6);
    const auto& val = week.back()[1];
    ASSERT_TRUE(val.is_object());
    EXPECT_TRUE(val.contains("good"));
    EXPECT_TRUE(val.contains("orphan"));
    EXPECT_TRUE(val.contains("dead"));
    EXPECT_FALSE(val.contains("null")) << "the sample-counter key must not leak";

    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());
}

// A corrupt sidecar must NOT crash load_stat_log and must NOT block the flat
// file from loading; the node degrades to reseed-from-flat and keeps serving.
TEST(DashboardData, GraphViewsCorruptSidecarDegradesToFlatSeed)
{
    const std::string path = "/tmp/c2pool_test_g4_corrupt.json";
    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());

    // First, produce a valid flat log with a few entries.
    {
        MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
        mi.set_pool_hashrate_fn([]() { return 42.0; });
        mi.set_stat_log_path(path);
        mi.load_stat_log();
        ASSERT_TRUE(wait_views_ready(mi));
        for (int i = 0; i < 3; ++i) mi.update_stat_log();
        mi.save_stat_log();
    }
    // Now corrupt the sidecar (valid flat file still present).
    { std::ofstream f(path + ".views", std::ios::trunc); f << "{ this is not json"; }

    MiningInterface mi2(false, nullptr, c2pool::address::Blockchain::DASH);
    mi2.set_stat_log_path(path);
    ASSERT_NO_THROW(mi2.load_stat_log());   // must not crash on the corrupt file
    ASSERT_TRUE(wait_views_ready(mi2));     // seeded from the flat log instead
    // Still serves week (from the reseeded bins).
    auto week = mi2.rest_web_graph_data("pool_hash_rate", "last_week");
    EXPECT_TRUE(week.is_array());

    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());
}

// A truncated sidecar (partial JSON) is tolerated the same way; and a totally
// absent sidecar on an existing flat log is the ordinary upgrade path.
TEST(DashboardData, GraphViewsTruncatedAndMissingSidecarTolerated)
{
    const std::string path = "/tmp/c2pool_test_g4_trunc.json";
    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());

    {
        MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
        mi.set_pool_hashrate_fn([]() { return 7.0; });
        mi.set_stat_log_path(path);
        mi.load_stat_log();
        ASSERT_TRUE(wait_views_ready(mi));
        for (int i = 0; i < 3; ++i) mi.update_stat_log();
        mi.save_stat_log();
    }
    // Truncate the sidecar to a partial object.
    {
        std::ifstream in(path + ".views");
        std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::ofstream out(path + ".views", std::ios::trunc);
        out << s.substr(0, s.size() / 2);   // half a JSON document
    }
    MiningInterface mi2(false, nullptr, c2pool::address::Blockchain::DASH);
    mi2.set_stat_log_path(path);
    ASSERT_NO_THROW(mi2.load_stat_log());
    EXPECT_TRUE(wait_views_ready(mi2));

    // Absent sidecar: the classic first-boot-after-upgrade path. The flat 31d
    // history seeds the week/month/year views.
    std::remove((path + ".views").c_str());
    MiningInterface mi3(false, nullptr, c2pool::address::Blockchain::DASH);
    mi3.set_stat_log_path(path);
    ASSERT_NO_THROW(mi3.load_stat_log());
    EXPECT_TRUE(wait_views_ready(mi3));
    auto year = mi3.rest_web_graph_data("pool_hash_rate", "last_year");
    EXPECT_TRUE(year.is_array());   // seeded from the flat log, serves

    std::remove(path.c_str());
    std::remove((path + ".views").c_str());
    std::remove((path + ".best.json").c_str());
}
