// SPDX-License-Identifier: AGPL-3.0-or-later
// Known-answer tests for DASH consensus: DarkGravityWave v3 per-block retarget
// (PR-0 foundation, S3 slice) and the SPV HeaderChain primitives.
//
// Reference: dashcore src/pow.cpp DarkGravityWave() — 24-block lookback,
// average-of-targets retarget, actual-timespan clamped to [tgt/3, tgt*3].
//
// The expected next-bits for every DGW vector below were derived BY HAND from
// the documented algorithm (and cross-checked with an independent re-implementation
// of the dashcore arithmetic — NOT by capturing this code's own output), so a
// regression in dark_gravity_wave() will turn these red. With a constant-difficulty
// window of target T and 24-block target timespan (24 * spacing = 3600s):
//
//   bn_new = T * clamp(actual_timespan, 1200, 10800) / 3600
//
//   (b) actual = 3600  -> bn_new = T            (bits unchanged)
//   (c) actual <= 1200  -> bn_new = T/3         (difficulty UP,   target smaller)
//   (d) actual >= 10800 -> bn_new = 3*T         (difficulty DOWN, target larger)
//
// For the base difficulty 0x1b104c8b (mantissa 0x104c8b, exp 27):
//   T/3 -> 0x104c8b/3 = 0x056ed9 -> 0x1b056ed9
//   3*T -> 0x104c8b*3 = 0x30e5a1 -> 0x1b30e5a1

#include <gtest/gtest.h>

#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

using namespace dash::coin;

namespace {

// Build a 24+-entry window where height h maps to bits/time. The DGW walks
// ancestors from the tip backward via get_ancestor(height). We back the window
// with a flat vector indexed by height.
struct Window {
    std::vector<IndexEntry> entries;  // entries[h] is the block at height h

    std::function<std::optional<IndexEntry>(uint32_t)> ancestor_fn() const {
        return [this](uint32_t h) -> std::optional<IndexEntry> {
            if (h >= entries.size()) return std::nullopt;
            return entries[h];
        };
    }
};

// Construct a window of `count` blocks ending at tip_height with constant bits
// and a fixed spacing between consecutive blocks (seconds).
// The DGW timespan is (time[tip] - time[tip-23]); we control it via `spacing`,
// then optionally override the oldest/tip timestamps for exact-timespan cases.
Window make_constant_window(uint32_t tip_height, uint32_t bits,
                            int64_t base_time, int64_t spacing) {
    Window w;
    w.entries.resize(tip_height + 1);
    for (uint32_t h = 0; h <= tip_height; ++h) {
        IndexEntry e;
        e.height = h;
        e.header.m_bits = bits;
        // older blocks have smaller timestamps; consecutive blocks `spacing` apart
        e.header.m_timestamp = static_cast<uint32_t>(base_time + static_cast<int64_t>(h) * spacing);
        w.entries[h] = e;
    }
    return w;
}

constexpr uint32_t kBaseBits = 0x1b104c8b;   // realistic Dash mainnet difficulty
constexpr int64_t  kBaseTime = 1700000000;

} // namespace

// ─── (a) Early-height passthrough below the DGW window ──────────────────────

TEST(DashDGWv3Kat, EarlyHeightReturnsPowLimit) {
    auto params = make_dash_chain_params_mainnet();
    uint32_t pow_limit_bits = params.pow_limit.GetCompact();
    EXPECT_EQ(pow_limit_bits, 0x1e0fffffu)
        << "Dash pow_limit 00000fff... must compact to 0x1e0fffff";

    // tip_height < DGW_PAST_BLOCKS (24) => unconditional pow-limit passthrough.
    auto none = [](uint32_t) -> std::optional<IndexEntry> { return std::nullopt; };
    for (uint32_t h = 0; h < static_cast<uint32_t>(DGW_PAST_BLOCKS); ++h) {
        EXPECT_EQ(dark_gravity_wave(none, h, params), pow_limit_bits)
            << "height " << h << " is below the 24-block window";
    }
}

// ─── (b) Steady state: constant spacing -> unchanged bits ───────────────────

TEST(DashDGWv3Kat, SteadyStateExactTimespanUnchanged) {
    auto params = make_dash_chain_params_mainnet();
    ASSERT_EQ(params.target_spacing, 150);

    const uint32_t tip = 100;
    auto w = make_constant_window(tip, kBaseBits, kBaseTime, /*spacing=*/150);

    // Pin the exact DGW timespan: time[tip] - time[tip-23] == 24*150 == 3600.
    w.entries[tip].header.m_timestamp        = static_cast<uint32_t>(kBaseTime + 3600);
    w.entries[tip - 23].header.m_timestamp   = static_cast<uint32_t>(kBaseTime);

    uint32_t bits = dark_gravity_wave(w.ancestor_fn(), tip, params);
    EXPECT_EQ(bits, kBaseBits)
        << "actual==target timespan over a constant window must leave bits unchanged";
}

// ─── (c) Fast blocks: timespan clamps low -> difficulty increases ───────────

TEST(DashDGWv3Kat, FastBlocksIncreaseDifficulty) {
    auto params = make_dash_chain_params_mainnet();

    const uint32_t tip = 100;
    auto w = make_constant_window(tip, kBaseBits, kBaseTime, /*spacing=*/30);

    // time[tip]-time[tip-23] = 23*30 = 690s; DGW clamps to target/3 = 1200s.
    // bn_new = T * 1200/3600 = T/3 -> 0x1b056ed9.
    uint32_t bits = dark_gravity_wave(w.ancestor_fn(), tip, params);
    EXPECT_EQ(bits, 0x1b056ed9u)
        << "fast blocks (clamped timespan 1200) must yield T/3 (harder target)";

    // Direction sanity: smaller target than the base.
    uint256 t_new; t_new.SetCompact(bits);
    uint256 t_base; t_base.SetCompact(kBaseBits);
    EXPECT_LT(t_new, t_base) << "fast blocks must lower the target (raise difficulty)";
}

// ─── (d) Slow blocks: timespan clamps high -> difficulty decreases ──────────

TEST(DashDGWv3Kat, SlowBlocksDecreaseDifficulty) {
    auto params = make_dash_chain_params_mainnet();

    const uint32_t tip = 100;
    auto w = make_constant_window(tip, kBaseBits, kBaseTime, /*spacing=*/600);

    // time[tip]-time[tip-23] = 23*600 = 13800s; DGW clamps to target*3 = 10800s.
    // bn_new = T * 10800/3600 = 3*T -> 0x1b30e5a1.
    uint32_t bits = dark_gravity_wave(w.ancestor_fn(), tip, params);
    EXPECT_EQ(bits, 0x1b30e5a1u)
        << "slow blocks (clamped timespan 10800) must yield 3*T (easier target)";

    uint256 t_new; t_new.SetCompact(bits);
    uint256 t_base; t_base.SetCompact(kBaseBits);
    EXPECT_GT(t_new, t_base) << "slow blocks must raise the target (lower difficulty)";
}

// ─── PoW / target helper round-trips ────────────────────────────────────────

TEST(DashDGWv3Kat, TargetFromBitsRoundTrip) {
    EXPECT_EQ(target_from_bits(0x1b104c8b).GetCompact(), 0x1b104c8bu);
    EXPECT_EQ(target_from_bits(0x1e0ffff0).GetCompact(), 0x1e0ffff0u);
}

TEST(DashDGWv3Kat, GetBlockProofMonotonic) {
    // A harder target (smaller) must carry MORE work than an easier one.
    uint256 work_hard = get_block_proof(0x1b056ed9); // T/3
    uint256 work_easy = get_block_proof(0x1b30e5a1); // 3*T
    EXPECT_FALSE(work_hard.IsNull());
    EXPECT_FALSE(work_easy.IsNull());
    EXPECT_GT(work_hard, work_easy)
        << "lower target => higher accumulated work";
}

TEST(DashDGWv3Kat, CheckPowAcceptsBelowTargetRejectsAbove) {
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    uint256 low_hash;  // clearly below target
    low_hash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_TRUE(check_pow(low_hash, 0x1e0ffff0, pow_limit));

    uint256 high_hash; // clearly above any target
    high_hash.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_FALSE(check_pow(high_hash, 0x1e0ffff0, pow_limit));
}

// ── Real-node KAT: DASH testnet3 DGW-v3 retarget at height 1497944 ──────────
// Live counterpart to the hand-derived synthetic vectors above. The 24 real
// ancestors 1497920..1497943 (genuine bits + timestamps captured from a synced
// testnet3 dashd; verified to contain no min-difficulty / pow-limit resets, so
// the pure DarkGravityWave path applies) must reproduce the bits the node
// itself assigned to block 1497944, namely 0x1e00f256. A divergence here is a
// real consensus drift vs live Dash, not a synthetic-arithmetic quibble.
TEST(DashDGWv3Kat, RealTestnet3Window1497944ReproducesNextBits) {
    struct Row { uint32_t height; uint32_t bits; uint32_t time; };
    static const Row rows[] = {
        {1497920u, 0x1e01279eu, 1781733608u}, {1497921u, 0x1e010524u, 1781733780u},
        {1497922u, 0x1e00fa0eu, 1781734122u}, {1497923u, 0x1e010475u, 1781734381u},
        {1497924u, 0x1e0101a5u, 1781734502u}, {1497925u, 0x1e01061bu, 1781734507u},
        {1497926u, 0x1e00fcd3u, 1781734513u}, {1497927u, 0x1e00f77bu, 1781734560u},
        {1497928u, 0x1e00e365u, 1781735022u}, {1497929u, 0x1e010157u, 1781735130u},
        {1497930u, 0x1e00fa44u, 1781735136u}, {1497931u, 0x1e00eb8au, 1781735361u},
        {1497932u, 0x1e00eda8u, 1781735637u}, {1497933u, 0x1e00fb31u, 1781735760u},
        {1497934u, 0x1e00f824u, 1781736070u}, {1497935u, 0x1e00fa74u, 1781736216u},
        {1497936u, 0x1e00faccu, 1781736245u}, {1497937u, 0x1e00f8deu, 1781736267u},
        {1497938u, 0x1e00f49bu, 1781736600u}, {1497939u, 0x1e01013au, 1781736614u},
        {1497940u, 0x1e00fa45u, 1781736710u}, {1497941u, 0x1e00fb8au, 1781736758u},
        {1497942u, 0x1e00f3b6u, 1781737051u}, {1497943u, 0x1e00f4c3u, 1781737080u},
    };
    auto ancestor = [&](uint32_t h) -> std::optional<IndexEntry> {
        for (const auto& r : rows) {
            if (r.height == h) {
                IndexEntry e;
                e.height = r.height;
                e.header.m_bits = r.bits;
                e.header.m_timestamp = r.time;
                return e;
            }
        }
        return std::nullopt;
    };

    // testnet3 params: target_spacing 150 and pow_limit identical to mainnet, so
    // the DGW arithmetic is the same; allow_min_difficulty is not consulted by
    // the pure dark_gravity_wave() (it gates the validation layer, not the avg).
    auto params = make_dash_chain_params_testnet();
    uint32_t bits = dark_gravity_wave(ancestor, /*tip_height=*/1497943u, params);
    EXPECT_EQ(bits, 0x1e00f256u)
        << "DGW-v3 over the real 1497920..1497943 window must reproduce the "
           "node-assigned bits of block 1497944";
}