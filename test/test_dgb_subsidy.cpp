// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression test: DGB block subsidy vs DigiByte Core consensus.
//
// GROUND TRUTH = DigiByte Core GetBlockSubsidy(nHeight, consensusParams)
// (src/validation.cpp), the supply curve every DGB mainnet node validates
// against. COIN = 1e8 (src/consensus/amount.h). dgb::CoinParams::subsidy is an
// exact port of that function and feeds the live daemonless coinbase-build path
// (embedded_coinbase_value.hpp), so it MUST match Core to the satoshi -- an
// under- or over-scaled value silently destroys reward or gets the block
// rejected (bad-cb-amount) once real hashrate mines.
//
// This supersedes the earlier card #156 "the p2pool-dgb-scrypt oracle IS the
// spec" ruling: that oracle's COIN=1e6 get_subsidy() was display-only (it never
// built a coinbase in python p2pool), and binding it verbatim to a real coinbase
// underpaid ~100x. For a real coinbase the spec is DigiByte Core.
//
// Vectors are the DigiByte Core GetBlockSubsidy() output (satoshis, COIN=1e8) at
// the boundary and interior of every reward period, plus the live Scrypt tip
// whose value is byte-identical to the on-chain coinbase at height 24,125,022
// (coinbase vout total 25,355,810,338 sat = 253.55810338 DGB).

#include <gtest/gtest.h>
#include <cstdint>

#include <impl/dgb/config_coin.hpp>

namespace {

struct SubsidyVec { uint32_t height; uint64_t expected; };

// DigiByte Core GetBlockSubsidy() reference vectors (satoshis, COIN=1e8).
constexpr SubsidyVec kCoreVectors[] = {
    {0,           7200000000000ULL},  // Period I:   72000 DGB
    {1,           7200000000000ULL},
    {1439,        7200000000000ULL},
    {1440,        1600000000000ULL},  // Period II:  16000 DGB
    {5759,        1600000000000ULL},
    {5760,         800000000000ULL},  // Period III:  8000 DGB
    {67199,        800000000000ULL},
    {67200,        796000000000ULL},  // Period IV in: weeks=1 -> -0.5%
    {77280,        792020000000ULL},
    {87359,        792020000000ULL},
    {87360,        788059900000ULL},
    {399999,       674644108854ULL},
    {400000,       243441000000ULL},  // Period V in: base 2459, weeks=1 -> -1%
    {480159,       243441000000ULL},
    {480160,       241006590000ULL},
    {1429999,      215782419560ULL},
    {1430000,      107850000000ULL},  // Period VI in: base 2157/2, DigiSpeed HF
    {4057999,       92168922949ULL},
    {4058000,       91140317768ULL},
    {20000000,      33193486585ULL},
    {24125001,      25355810338ULL},  // LIVE Scrypt tip (months=129 band)
    {24125022,      25355810338ULL},  // == on-chain coinbase at 47515a15f270cbb4
};

// Independent DigiByte Core GetBlockSubsidy() reference implementation, kept
// separate from the ported CoinParams::subsidy so the full-domain sweep below
// cannot pass by sharing a bug with the code under test.
uint64_t core_reference_subsidy(uint32_t nHeight) {
    constexpr uint64_t COIN = 100000000ULL;
    constexpr uint32_t nDiffChangeTarget = 67200;
    constexpr uint32_t alwaysUpdateDiffChangeTarget = 400000;
    constexpr uint32_t workComputationChangeTarget = 1430000;
    constexpr uint32_t patchBlockRewardDuration = 10080;
    constexpr uint32_t patchBlockRewardDuration2 = 80160;
    uint64_t nSubsidy = COIN;
    if (nHeight < nDiffChangeTarget) {
        if (nHeight < 1440) nSubsidy = 72000 * COIN;
        else if (nHeight < 5760) nSubsidy = 16000 * COIN;
        else nSubsidy = 8000 * COIN;
    } else if (nHeight < alwaysUpdateDiffChangeTarget) {
        nSubsidy = 8000 * COIN;
        uint32_t weeks = ((nHeight - nDiffChangeTarget) / patchBlockRewardDuration) + 1;
        for (uint32_t i = 0; i < weeks; ++i) nSubsidy -= nSubsidy / 200;
    } else if (nHeight < workComputationChangeTarget) {
        nSubsidy = 2459 * COIN;
        uint32_t weeks = ((nHeight - alwaysUpdateDiffChangeTarget) / patchBlockRewardDuration2) + 1;
        for (uint32_t i = 0; i < weeks; ++i) nSubsidy -= nSubsidy / 100;
    } else {
        nSubsidy = 2157 * COIN / 2;
        uint64_t months = (static_cast<uint64_t>(nHeight) - workComputationChangeTarget)
                          * 15ULL / (60ULL * 60 * 24 * 365 / 12);
        for (uint64_t i = 0; i < months; ++i) { nSubsidy *= 98884; nSubsidy /= 100000; }
    }
    if (nSubsidy < COIN) nSubsidy = 0;
    return nSubsidy;
}

}  // namespace

TEST(DgbSubsidy, MatchesDigiByteCoreVectors) {
    for (const auto& v : kCoreVectors) {
        EXPECT_EQ(dgb::CoinParams::subsidy(v.height), v.expected)
            << "subsidy(" << v.height << ") diverged from DigiByte Core";
    }
}

// The tip value is the money-critical one: it is exactly what a solved block's
// coinbase would pay, and must equal the real on-chain coinbase to the satoshi.
TEST(DgbSubsidy, LiveTipMatchesOnChainCoinbase) {
    // Both heights fall in the months=129 monthly-decay band and pay the same
    // value; 24125001 is the money-critical build height, 24125022 is a block
    // whose on-chain coinbase vout total is byte-identical to this value.
    EXPECT_EQ(dgb::CoinParams::subsidy(24125001u), 25355810338ULL)
        << "built DGB coinbase subsidy != DigiByte Core at the live Scrypt tip "
           "-- real hashrate would underpay or the block would be rejected";
    EXPECT_EQ(dgb::CoinParams::subsidy(24125022u), 25355810338ULL)
        << "built DGB coinbase subsidy != on-chain coinbase at the live Scrypt tip";
}

// Full-domain byte parity against an independent Core reference: boundaries,
// every-block near each hard fork, and a coarse sweep across all six periods
// including the far-future floor-to-zero region.
TEST(DgbSubsidy, ByteParityWithCoreAcrossDomain) {
    auto check = [](uint32_t h) {
        ASSERT_EQ(dgb::CoinParams::subsidy(h), core_reference_subsidy(h))
            << "byte divergence from DigiByte Core at height " << h;
    };
    for (uint32_t h : {0u, 1439u, 1440u, 5759u, 5760u, 67199u, 67200u, 67201u,
                       399999u, 400000u, 400001u, 1429999u, 1430000u, 1430001u})
        check(h);
    for (uint32_t h = 0; h <= 60000000u; h += 97777u) check(h);   // all periods + zero floor
}

// DigiByte Core master floors a sub-1-DGB reward to 0 (ConnectBlock accepts
// underpay; overpay is what gets rejected). Deep in the monthly-decay era the
// reward reaches 0 and stays there.
TEST(DgbSubsidy, FloorsToZeroFarInTheFuture) {
    // Below the 1-DGB (1e8 sat) floor the port returns exactly 0, matching Core.
    for (uint32_t h = 120000000u; h < 200000000u; h += 5000000u) {
        EXPECT_EQ(dgb::CoinParams::subsidy(h), core_reference_subsidy(h))
            << "floor-region divergence from Core at height " << h;
    }
    EXPECT_EQ(dgb::CoinParams::subsidy(130000000u), 0ULL);
}
