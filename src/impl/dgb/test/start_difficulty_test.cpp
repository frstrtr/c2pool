// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB stratum start difficulty (rides dgb_work_source_test). VARDIFF item 2.
//
// kr1z1s p2pool-dgb-scrypt work.py get_work: rate/10 per second node-wide,
// else 3000x the dust target, power-of-two rounding at >= 4, SANE clip. The
// expected values were computed by the oracle's formulas re-stated with exact
// integers (bitcoin/data.py average_attempts_to_target, target_to_difficulty,
// difficulty_to_target; networks SANE_TARGET_RANGE, SPREAD 24, DUST 0.001
// DGB), not by the code under test. Before, a DGB session always started at
// the 0.0005 floor: a ~9.5 GH/s rig sent thousands of pseudoshares a second
// (each a scrypt hash here) until vardiff caught up.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/stratum_start_difficulty.hpp>

#include <gtest/gtest.h>

#include <cmath>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC (path of src/c2pool/main_dgb.cpp) is not defined"
#endif

namespace {

bool near(double a, double b) { return std::fabs(a - b) <= 1e-9 * std::fabs(b); }

constexpr uint64_t kSubsidy = 27700000000ULL;

} // namespace

TEST(DgbStartDifficulty, MatchesThePythonNetwork)
{
    struct V { double rate; uint32_t bits; double want; };
    const V vs[] = {
        {9.5e9, 0x1a00ffff, 0.22118573639318131},      // node rate / 10 per second
        {0.0, 0x1a00ffff, 0.4845405342960288},         // no rate: 3000x the dust target
        {0.0, 0x1b0404cb, 0.00047097244587794606},
        {1e15, 0x1a00ffff, 23.282709094019083},        // 2^14 rounding, then the SANE clip
        {1e20, 0x1a00ffff, 23.282709094019083},
        {100.0, 0x1a00ffff, 2.3282709094019083e-07},   // the SANE floor
    };
    for (const auto& v : vs) {
        SCOPED_TRACE(v.rate);
        const double got = dgb::dgb_start_difficulty(v.rate, v.bits, kSubsidy, dgb::PoolConfig::SPREAD, 100000);
        EXPECT_TRUE(near(got, v.want)) << got << " want " << v.want;
    }
    EXPECT_EQ(dgb::dgb_start_difficulty(0.0, 0, kSubsidy, 24, 100000), 0.0) << "no template: no seed";
}

TEST(DgbStartDifficulty, WorkSourceUsesTheNodeRateElseTheTemplate)
{
    c2pool::dgb::HeaderChain hc;
    dgb::coin::Mempool mempool;
    hc.set_base_height(20000000);
    dgb::stratum::DGBWorkSource ws(hc, mempool, false, [](const std::vector<unsigned char>&, uint32_t) { return false; },
                                   [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); });
    core::stratum::PayoutKey key{};
    EXPECT_EQ(ws.start_difficulty(key), 0.0) << "no rate and no template: no seed";
    ws.set_gbt_tip_fn([]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
        return dgb::stratum::DGBWorkSource::GbtTip{std::string(64, '1'), "1a00ffff", 20000000};
    });
    const double from_template = ws.start_difficulty(key);
    EXPECT_TRUE(near(from_template, dgb::dgb_start_difficulty(0.0, 0x1a00ffff, dgb::CoinParams::subsidy(20000000),
                                                              dgb::PoolConfig::SPREAD, 100000)));
    ws.set_node_rate_fn([] { return 9.5e9; });
    EXPECT_TRUE(near(ws.start_difficulty(key), 0.22118573639318131));
}

TEST(DgbStartDifficulty, MainDgbBindsTheNodeRate)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    const auto bind = s.find("work_source->set_node_rate_fn(");
    ASSERT_NE(bind, std::string::npos);
    EXPECT_NE(s.find("srv->get_total_hashrate()", bind), std::string::npos);
    const auto unbind = s.find("if (work_source) work_source->set_node_rate_fn(nullptr);");
    ASSERT_NE(unbind, std::string::npos);
    EXPECT_LT(unbind, s.find("    stratum_server.reset();", unbind));
}
