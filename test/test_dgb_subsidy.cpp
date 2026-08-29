// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression test: DGB block subsidy vs the coin's OWN canonical oracle,
// p2pool-dgb-scrypt (bitcoin/networks/digibyte.py :: get_subsidy).
//
// Operator decision, card #156 (2026-06-17): V36 = parity with DGB's own
// reference, so the oracle behaviour IS the spec -- including COIN=1e6 and the
// weeks/months + 1 decay count. These are NOT quirks to "fix". 3-bucket: COMPAT
// (pre-v36 per-coin baseline, temporary for the crossing-soak).
//
// Vectors generated deterministically by executing the oracle get_subsidy() at
// the boundary and interior of every reward phase (all four phases + floor).

#include <gtest/gtest.h>
#include <cstdint>

#include <impl/dgb/config_coin.hpp>

namespace {

struct SubsidyVec { uint32_t height; uint64_t expected; };

// Oracle p2pool-dgb-scrypt get_subsidy() reference vectors (satoshis, COIN=1e6).
constexpr SubsidyVec kOracleVectors[] = {
    {0,        72000000000ULL},  // phase 1: 72000 DGB
    {1,        72000000000ULL},
    {1439,     72000000000ULL},
    {1440,     16000000000ULL},  // phase 1 step -> 16000
    {5759,     16000000000ULL},
    {5760,      8000000000ULL},  // phase 1 step -> 8000
    {67199,     8000000000ULL},
    {67200,     7960000000ULL},  // phase 2 in: weeks+1 = 1 -> -0.5%
    {77280,     7920200000ULL},
    {87359,     7920200000ULL},
    {87360,     7880599000ULL},
    {399999,    6746441103ULL},
    {400000,    2434410000ULL},  // phase 3 in: base 2459, weeks+1 = 1 -> -1%
    {480159,    2434410000ULL},
    {480160,    2410065900ULL},
    {1429999,   2157824200ULL},
    {1430000,   1078500000ULL},  // phase 4 in: base 2157/2
    {4057999,    921689224ULL},
    {4058000,    911403172ULL},
    {20000000,   331934836ULL},
};

}  // namespace

TEST(DgbSubsidy, MatchesOracleVectors) {
    for (const auto& v : kOracleVectors) {
        EXPECT_EQ(dgb::CoinParams::subsidy(v.height), v.expected)
            << "subsidy(" << v.height << ") diverged from the p2pool-dgb-scrypt oracle";
    }
}

TEST(DgbSubsidy, NeverBelowCoinFloor) {
    // Oracle clamps: if nSubsidy < COIN -> COIN. COIN = 1e6 sat.
    // Sweep deep into the monthly-decay region where the reward is floored.
    for (uint32_t h = 0; h < 80u; ++h) {
        const uint32_t height = 130000000u + h * 1000000u;
        EXPECT_GE(dgb::CoinParams::subsidy(height), 1000000ULL)
            << "subsidy floor breached at height " << height;
    }
}