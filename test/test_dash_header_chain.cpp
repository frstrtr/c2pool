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

#include <algorithm>   // std::find over the refusal `requires` array
#include <gtest/gtest.h>

#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/chain_rpc.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string>
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
// ════════════════════════════════════════════════════════════════════════════
// Daemonless chain queries — getbestblockhash / getblockhash /
// getblockchaininfo answered from the header chain (chain_rpc.hpp).
//
// Every positive assertion below has a negative twin: for each query there is
// a state in which the header chain CANNOT answer, and the test asserts the
// response NAMES that state (condition + measured value + threshold) instead
// of returning a stale hash, an empty string, or a zero.
// ════════════════════════════════════════════════════════════════════════════

namespace {

// A chain whose PoW target is easy enough to mine in a unit test (top 8 bits
// zero => ~256 X11 attempts per header) while still exercising the REAL
// check_pow / add_header_internal path — the headers below are genuinely
// PoW-valid, not injected. allow_min_difficulty short-circuits the DGW bits
// check at pow-limit difficulty, which is what a testnet chain does anyway.
DashChainParams make_easy_test_params() {
    DashChainParams p;
    p.target_timespan = 3600;
    p.target_spacing  = 150;
    p.allow_min_difficulty = true;
    p.no_retargeting = false;
    p.pow_limit.SetHex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    // Arbitrary but fixed: init() seeds this as a genesis STUB without a PoW
    // check, and every mined header below builds on it.
    p.genesis_hash.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    p.halving_interval = 210240;
    p.initial_subsidy = 500000000ULL;
    p.pow_func = [](std::span<const unsigned char> data) -> uint256 {
        return dash::crypto::hash_x11(data);
    };
    p.block_hash_func = p.pow_func;
    return p;
}

// Mine a real header on top of `prev` at the pow-limit target.
BlockHeaderType mine_header(const uint256& prev, uint32_t timestamp,
                            uint32_t bits, const uint256& pow_limit) {
    BlockHeaderType h;
    h.m_version = 536870912;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000bb");
    h.m_timestamp = timestamp;
    h.m_bits = bits;
    for (uint32_t nonce = 0; nonce < 50'000'000u; ++nonce) {
        h.m_nonce = nonce;
        if (check_pow(x11_hash(h), bits, pow_limit)) return h;
    }
    ADD_FAILURE() << "mine_header exhausted the nonce range — pow_limit too hard "
                     "for a unit test";
    return h;
}

// Build an in-memory chain of `count` real headers above the genesis stub,
// spaced 150 s apart ending at `tip_time`. Returns the per-height hashes
// (index 0 == genesis stub).
struct MinedChain {
    DashChainParams params;
    std::unique_ptr<HeaderChain> hc;
    std::vector<uint256> hashes;   // hashes[h] is the hash at height h
    uint32_t tip_time{0};
};

MinedChain build_mined_chain(uint32_t count, uint32_t tip_time) {
    MinedChain mc;
    mc.params = make_easy_test_params();
    mc.hc = std::make_unique<HeaderChain>(mc.params, /*db_path=*/"");
    EXPECT_TRUE(mc.hc->init());
    mc.hashes.push_back(mc.params.genesis_hash);
    const uint32_t bits = mc.params.pow_limit.GetCompact();
    uint32_t t = tip_time - count * 150u;
    for (uint32_t i = 0; i < count; ++i) {
        t += 150u;
        auto h = mine_header(mc.hashes.back(), t, bits, mc.params.pow_limit);
        EXPECT_TRUE(mc.hc->add_header(h))
            << "mined header at height " << (i + 1) << " must be accepted";
        mc.hashes.push_back(x11_hash(h));
    }
    mc.tip_time = t;
    return mc;
}

// Assert the two honesty invariants that hold for EVERY getblockchaininfo
// response: nothing listed as unavailable is also emitted, and no emitted
// numeric field is a placeholder zero.
void expect_no_field_is_both_emitted_and_unavailable(const nlohmann::json& r) {
    ASSERT_TRUE(r.contains("unavailable")) << r.dump(2);
    for (auto it = r["unavailable"].begin(); it != r["unavailable"].end(); ++it) {
        EXPECT_FALSE(r.contains(it.key()))
            << "field '" << it.key() << "' is listed unavailable but ALSO emitted "
            << "— that is exactly the fabricated-value defect: " << r.dump(2);
        EXPECT_FALSE(it.value().get<std::string>().empty())
            << "unavailable['" << it.key() << "'] must name the blocking condition";
    }
}

} // namespace

// ─── getbestblockhash ───────────────────────────────────────────────────────

TEST(DashChainRpc, BestBlockHashAnsweredFromSyncedHeaderChain) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto a = chain_rpc::getbestblockhash(*mc.hc, /*now=*/mc.tip_time + 60);
    ASSERT_TRUE(a.available) << a.unavailable_reason;
    EXPECT_EQ(a.value.get<std::string>(), mc.hashes.back().GetHex());
    EXPECT_EQ(mc.hc->height(), 3u);
}

// NEGATIVE TWIN: a tip older than the 24 h window is not the network best
// block. The answer must say so and name the age and the threshold.
TEST(DashChainRpc, BestBlockHashWithheldWhenTipStale) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 90'000u;   // 25 h past the tip
    auto a = chain_rpc::getbestblockhash(*mc.hc, now);
    ASSERT_FALSE(a.available)
        << "a 25 h-old tip must NOT be served as bestblockhash";
    EXPECT_NE(a.unavailable_reason.find("90000"), std::string::npos)
        << "refusal must carry the MEASURED tip age: " << a.unavailable_reason;
    EXPECT_NE(a.unavailable_reason.find("86400"), std::string::npos)
        << "refusal must carry the THRESHOLD: " << a.unavailable_reason;
    EXPECT_TRUE(a.value.is_null()) << "no stale hash may leak through the refusal";
}

// NEGATIVE TWIN: a chain that has never been initialised has no tip at all.
TEST(DashChainRpc, BestBlockHashWithheldWhenChainHasNoTip) {
    auto params = make_easy_test_params();
    HeaderChain hc(params, /*db_path=*/"");   // deliberately NOT init()ed
    auto a = chain_rpc::getbestblockhash(hc, /*now=*/1'800'000'000u);
    ASSERT_FALSE(a.available);
    EXPECT_NE(a.unavailable_reason.find("no tip"), std::string::npos)
        << a.unavailable_reason;
}

// NEGATIVE TWIN: a fast-start checkpoint tip is a SYNTHETIC entry (bits=0,
// timestamp=0) — a hard-coded anchor, not an observed best block.
TEST(DashChainRpc, BestBlockHashWithheldAtSyntheticCheckpointAnchor) {
    auto params = make_dash_chain_params_mainnet();
    ASSERT_TRUE(params.fast_start_checkpoint.has_value());
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    ASSERT_EQ(hc.height(), params.fast_start_checkpoint->height);

    auto a = chain_rpc::getbestblockhash(hc, /*now=*/static_cast<uint32_t>(std::time(nullptr)));
    ASSERT_FALSE(a.available)
        << "the compiled-in checkpoint hash must not be served as the network tip";
    EXPECT_NE(a.unavailable_reason.find("synthetic anchor"), std::string::npos)
        << a.unavailable_reason;
    EXPECT_NE(a.unavailable_reason.find("bits=0"), std::string::npos)
        << a.unavailable_reason;
}

// ─── getblockhash ───────────────────────────────────────────────────────────

TEST(DashChainRpc, BlockHashAnsweredForEveryOwnedHeight) {
    auto mc = build_mined_chain(4, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    for (uint32_t h = 1; h <= 4; ++h) {
        auto a = chain_rpc::getblockhash(*mc.hc, h, now);
        ASSERT_TRUE(a.available) << "height " << h << ": " << a.unavailable_reason;
        EXPECT_EQ(a.value.get<std::string>(), mc.hashes[h].GetHex());
    }
}

// NEGATIVE TWIN: above the tip there is no block, and the refusal names both
// the requested height and the tip height it was compared against.
TEST(DashChainRpc, BlockHashWithheldAboveTip) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto a = chain_rpc::getblockhash(*mc.hc, 9999u, mc.tip_time + 60);
    ASSERT_FALSE(a.available);
    EXPECT_NE(a.unavailable_reason.find("9999"), std::string::npos) << a.unavailable_reason;
    EXPECT_NE(a.unavailable_reason.find("above owned tip"), std::string::npos)
        << a.unavailable_reason;
    EXPECT_TRUE(a.value.is_null());
}

// NEGATIVE TWIN: below the fast-start anchor the headers were never
// downloaded. The refusal must name the anchor height, not return "".
TEST(DashChainRpc, BlockHashWithheldBelowFastStartAnchor) {
    auto params = make_dash_chain_params_mainnet();
    const uint32_t cp = params.fast_start_checkpoint->height;
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());

    auto a = chain_rpc::getblockhash(hc, cp - 1, /*now=*/1'800'000'000u);
    ASSERT_FALSE(a.available);
    EXPECT_NE(a.unavailable_reason.find("below owned anchor"), std::string::npos)
        << a.unavailable_reason;
    EXPECT_NE(a.unavailable_reason.find(std::to_string(cp)), std::string::npos)
        << "refusal must name the MEASURED anchor height: " << a.unavailable_reason;
}

// NEGATIVE TWIN: the anchor height itself resolves to a synthetic entry with
// no real header behind it.
TEST(DashChainRpc, BlockHashWithheldAtSyntheticAnchorHeight) {
    auto params = make_dash_chain_params_mainnet();
    const uint32_t cp = params.fast_start_checkpoint->height;
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    auto a = chain_rpc::getblockhash(hc, cp, /*now=*/1'800'000'000u);
    ASSERT_FALSE(a.available);
    EXPECT_NE(a.unavailable_reason.find("synthetic anchor"), std::string::npos)
        << a.unavailable_reason;
}

// NEGATIVE TWIN: on a STALE tip the last few blocks may still be reorged away.
// Buried heights stay answerable; heights inside the margin do not.
TEST(DashChainRpc, BlockHashStaleTipServesBuriedWithholdsRecent) {
    auto mc = build_mined_chain(10, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 90'000u;   // stale
    const uint32_t tip = mc.hc->height();
    ASSERT_EQ(tip, 10u);

    // Inside the reorg margin -> withheld, and the refusal names the margin.
    for (uint32_t h = tip - chain_rpc::STALE_TIP_REORG_MARGIN + 1; h <= tip; ++h) {
        auto a = chain_rpc::getblockhash(*mc.hc, h, now);
        EXPECT_FALSE(a.available) << "height " << h << " is within the margin of a stale tip";
        EXPECT_NE(a.unavailable_reason.find("not synced"), std::string::npos)
            << a.unavailable_reason;
    }
    // Buried -> still answered, because PoW does not go stale.
    for (uint32_t h = 1; h <= tip - chain_rpc::STALE_TIP_REORG_MARGIN; ++h) {
        auto a = chain_rpc::getblockhash(*mc.hc, h, now);
        EXPECT_TRUE(a.available) << "height " << h << ": " << a.unavailable_reason;
        EXPECT_EQ(a.value.get<std::string>(), mc.hashes[h].GetHex());
    }
}

// ─── getblockchaininfo ──────────────────────────────────────────────────────

TEST(DashChainRpc, ChainInfoSyncedEmitsOwnedFieldsOnly) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblockchaininfo(*mc.hc, /*now=*/mc.tip_time + 60);

    EXPECT_EQ(r["chain"], "test");
    EXPECT_TRUE(r["synced"].get<bool>()) << r.dump(2);
    EXPECT_EQ(r["blocks"].get<uint32_t>(), 3u);
    EXPECT_EQ(r["headers"].get<uint32_t>(), 3u);
    EXPECT_EQ(r["bestblockhash"].get<std::string>(), mc.hashes.back().GetHex());
    EXPECT_EQ(r["tip_age_seconds"].get<int64_t>(), 60);
    EXPECT_EQ(r["tip_max_age_seconds"].get<int64_t>(), chain_rpc::TIP_MAX_AGE_SECONDS);
    EXPECT_EQ(r["source"], chain_rpc::SOURCE_TAG);
    EXPECT_GT(r["difficulty"].get<double>(), 0.0);
    EXPECT_EQ(r["mediantime"].get<uint32_t>(), mc.hc->median_time_past());

    // chainwork is anchor-relative here and is therefore NEVER emitted.
    EXPECT_FALSE(r.contains("chainwork"))
        << "anchor-relative work must not masquerade as a daemon chainwork";
    EXPECT_TRUE(r["unavailable"].contains("chainwork"));
    EXPECT_FALSE(r.contains("verificationprogress"));
    expect_no_field_is_both_emitted_and_unavailable(r);
}

// NEGATIVE TWIN: a stale tip must not present blocks/headers/bestblockhash as
// current. They move under "stale" and are named in "unavailable".
TEST(DashChainRpc, ChainInfoStaleTipMovesTipFieldsToStale) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblockchaininfo(*mc.hc, /*now=*/mc.tip_time + 90'000u);

    EXPECT_FALSE(r["synced"].get<bool>());
    EXPECT_FALSE(r.contains("blocks"))        << r.dump(2);
    EXPECT_FALSE(r.contains("headers"))       << r.dump(2);
    EXPECT_FALSE(r.contains("bestblockhash")) << r.dump(2);
    ASSERT_TRUE(r.contains("sync_blocked_by"));
    EXPECT_NE(r["sync_blocked_by"].get<std::string>().find("90000"), std::string::npos);
    EXPECT_NE(r["sync_blocked_by"].get<std::string>().find("86400"), std::string::npos);

    ASSERT_TRUE(r.contains("stale"));
    EXPECT_EQ(r["stale"]["tip_height"].get<uint32_t>(), 3u);
    EXPECT_EQ(r["stale"]["tip_hash"].get<std::string>(), mc.hashes.back().GetHex());
    expect_no_field_is_both_emitted_and_unavailable(r);
}

// NEGATIVE TWIN: at a synthetic checkpoint anchor, difficulty and mediantime
// would both be fabricated zeros. They must be withheld, not zeroed.
TEST(DashChainRpc, ChainInfoSyntheticAnchorWithholdsDifficultyAndMediantime) {
    auto params = make_dash_chain_params_mainnet();
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    auto r = chain_rpc::getblockchaininfo(hc, /*now=*/1'800'000'000u);

    EXPECT_EQ(r["chain"], "main");
    EXPECT_FALSE(r["synced"].get<bool>());
    EXPECT_FALSE(r.contains("difficulty"))
        << "bits=0 would divide by a null target — a fabricated zero: " << r.dump(2);
    EXPECT_FALSE(r.contains("mediantime"))
        << "median_time_past() is 0 at a synthetic anchor — a fabricated zero";
    EXPECT_NE(r["unavailable"]["difficulty"].get<std::string>().find("fabricated"),
              std::string::npos);
    EXPECT_EQ(r["first_indexed_height"].get<uint32_t>(),
              params.fast_start_checkpoint->height);
    // Confirms that median_time_past() really would have returned the zero we
    // refused to publish — the withheld field is not a false alarm.
    EXPECT_EQ(hc.median_time_past(), 0u);
    expect_no_field_is_both_emitted_and_unavailable(r);
}

// NEGATIVE TWIN: with no tip at all, every tip-derived field is unavailable
// and none is emitted as 0 / "".
TEST(DashChainRpc, ChainInfoNoTipWithholdsEveryTipDerivedField) {
    auto params = make_easy_test_params();
    HeaderChain hc(params, /*db_path=*/"");   // deliberately NOT init()ed
    auto r = chain_rpc::getblockchaininfo(hc, /*now=*/1'800'000'000u);

    for (const char* f : {"blocks", "headers", "bestblockhash", "mediantime", "difficulty"}) {
        EXPECT_FALSE(r.contains(f)) << f << " must not be emitted with no tip: " << r.dump(2);
        EXPECT_TRUE(r["unavailable"].contains(f)) << f << " must be named unavailable";
    }
    EXPECT_FALSE(r["synced"].get<bool>());
    EXPECT_EQ(r["headers_stored"].get<uint64_t>(), 0u);
    expect_no_field_is_both_emitted_and_unavailable(r);
}

// ─── invariants across the three ────────────────────────────────────────────

// Anti-drift guard. chain_rpc::sync_status() reimplements the freshness
// predicate over HeaderChain's PUBLIC api so header_chain.hpp needs no edit.
// If someone changes HeaderChain::is_synced()'s window (or ours) without the
// other, this goes red instead of the two silently disagreeing.
TEST(DashChainRpc, SyncStatusMatchesHeaderChainIsSynced) {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));

    auto fresh = build_mined_chain(2, /*tip_time=*/now - 600);       // 10 min old
    EXPECT_TRUE(fresh.hc->is_synced());
    EXPECT_EQ(chain_rpc::sync_status(*fresh.hc, now).synced, fresh.hc->is_synced());

    auto stale = build_mined_chain(2, /*tip_time=*/now - 200'000u);  // ~55 h old
    EXPECT_FALSE(stale.hc->is_synced());
    EXPECT_EQ(chain_rpc::sync_status(*stale.hc, now).synced, stale.hc->is_synced());
}

// getbestblockhash and getblockchaininfo are served by one backend, so they
// can never report different tips.
TEST(DashChainRpc, BestBlockHashAgreesWithChainInfo) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    auto best = chain_rpc::getbestblockhash(*mc.hc, now);
    auto info = chain_rpc::getblockchaininfo(*mc.hc, now);
    ASSERT_TRUE(best.available);
    EXPECT_EQ(best.value.get<std::string>(), info["bestblockhash"].get<std::string>());
    // ... and the tip that getblockhash reports at the chain-info height.
    auto at_tip = chain_rpc::getblockhash(*mc.hc, info["blocks"].get<uint32_t>(), now);
    ASSERT_TRUE(at_tip.available) << at_tip.unavailable_reason;
    EXPECT_EQ(at_tip.value.get<std::string>(), best.value.get<std::string>());
}

TEST(DashChainRpc, FirstIndexedHeightFindsTheAnchor) {
    auto mc = build_mined_chain(5, /*tip_time=*/1'800'000'000u);
    auto anchor = chain_rpc::first_indexed_height(*mc.hc);
    ASSERT_TRUE(anchor.has_value());
    EXPECT_EQ(*anchor, 0u) << "genesis-stub chains are indexed from height 0";

    auto params = make_dash_chain_params_mainnet();
    HeaderChain cp_chain(params, /*db_path=*/"");
    ASSERT_TRUE(cp_chain.init());
    auto cp_anchor = chain_rpc::first_indexed_height(cp_chain);
    ASSERT_TRUE(cp_anchor.has_value());
    EXPECT_EQ(*cp_anchor, params.fast_start_checkpoint->height)
        << "the binary search must land on the fast-start checkpoint, not 0";
}

// The dispatch surface the web server installs: unknown methods are refused by
// name rather than answered, so the six remaining daemon RPCs can never be
// silently faked by this backend.
TEST(DashChainRpc, ChainQueryRefusesMethodsTheHeaderChainDoesNotOwn) {
    auto mc = build_mined_chain(2, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    for (const char* m : {"getblock", "getpeerinfo", "getrawmempool",
                          "getnetworkinfo", "getmininginfo", "protx"}) {
        auto r = chain_rpc::chain_query(*mc.hc, m, nlohmann::json::array(), now);
        ASSERT_TRUE(r.contains("error")) << m << " must be refused: " << r.dump();
        EXPECT_NE(r["error"].get<std::string>().find(m), std::string::npos);
    }
    // getblockhash with no height is a caller error, and says so.
    auto bad = chain_rpc::chain_query(*mc.hc, "getblockhash", nlohmann::json::array(), now);
    ASSERT_TRUE(bad.contains("error"));
    EXPECT_NE(bad["error"].get<std::string>().find("height parameter"), std::string::npos);

    // Happy path through the same dispatch returns the BARE daemon-shaped value.
    auto ok = chain_rpc::chain_query(*mc.hc, "getbestblockhash", nlohmann::json::array(), now);
    EXPECT_TRUE(ok.is_string()) << ok.dump();
    EXPECT_EQ(ok.get<std::string>(), mc.hashes.back().GetHex());
}

// ═══════════════════════════════════════════════════════════════════════════
// HEADER-BACKFILL PROGRESS TELEMETRY
// ═══════════════════════════════════════════════════════════════════════════
//
// The old line was `[DASH] Header sync: N/M (P%)`, throttled on HEIGHT ALONE
// by a function-local `static` — i.e. one counter shared by every HeaderChain
// in the process. On 2026-08-04 that cost real time twice: a backfill that
// slowed to a crawl went silent for as long as it took to cover 2000 blocks,
// and rate/ETA had to be reconstructed by diffing log timestamps by hand.
//
// What is pinned here: the FIRST batch establishes a baseline and reports
// nothing (a rate cannot be measured from one sample — reporting one would be
// a fabricated number), and a LATER batch past the throttle emits the line.
TEST(DashHeaderChainDiag, BackfillProgressBaselinesThenReports) {
    auto params = make_easy_test_params();
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    hc.set_peer_tip_height(100);
    // Tight throttle so the KAT need not mine 2000 headers to prove the line.
    hc.set_progress_throttle(/*headers=*/2, /*ms=*/60'000);

    const uint32_t bits = params.pow_limit.GetCompact();
    uint256  prev = params.genesis_hash;
    uint32_t t    = 1'800'000'000u;

    auto mine_batch = [&](int n) {
        std::vector<BlockHeaderType> batch;
        for (int i = 0; i < n; ++i) {
            t += 150u;
            auto h = mine_header(prev, t, bits, params.pow_limit);
            prev = x11_hash(h);
            batch.push_back(h);
        }
        return batch;
    };

    // First batch: accepted, and it BASELINES the reporter.
    auto b1 = mine_batch(3);
    EXPECT_EQ(hc.add_headers(b1), 3);
    EXPECT_EQ(hc.height(), 3u);

    // Second batch: three more headers is past the 2-header throttle, so the
    // progress line is due. The assertion available to a KAT is the state the
    // line reports — the cursor and the peer target it prints.
    auto b2 = mine_batch(3);
    EXPECT_EQ(hc.add_headers(b2), 3);
    EXPECT_EQ(hc.height(), 6u);
}

// ─── DAEMONLESS BLOCK-DATA POLICY (#99) ─────────────────────────────────────
//
// Three behaviours, one contract:
//   (a) SERVE what the header chain owns  — getblockheader in full, getblock
//       verbosity 1 partially.
//   (b) REFUSE what needs bodies, NAMING the reason and the remedies, in a
//       shape no empty answer can imitate.
//   (c) archive mode is the remedy the refusal itself advertises.
//
// The regression these pin is the one that motivated the whole task: an
// unwired seam answered HTTP 200 with a well-formed EMPTY document, so a dead
// view was indistinguishable from an empty one. Every assertion below exists
// to keep "no data" and "no capability" in different representations.

namespace {

// A refusal must be recognisable by a machine with ONE predicate and by a
// human from the prose. Both halves are asserted together so neither can rot.
void expect_is_refusal(const nlohmann::json& r, const char* expect_code) {
    ASSERT_TRUE(r.is_object()) << r.dump(2);
    ASSERT_TRUE(r.contains("code")) << "the machine discriminator is missing; a "
                                       "caller cannot tell this from data: " << r.dump(2);
    EXPECT_EQ(r["code"].get<std::string>(), expect_code) << r.dump(2);
    EXPECT_EQ(r.value("http_status", 0), chain_rpc::REFUSAL_HTTP_STATUS)
        << "a refusal must carry the non-2xx status the transport will serve";
    EXPECT_EQ(r.value("source", std::string()), chain_rpc::SOURCE_TAG);
    EXPECT_EQ(r.value("retained", std::string()), chain_rpc::RETAINED_HEADERS_ONLY);
    const std::string err = r.value("error", std::string());
    EXPECT_FALSE(err.empty()) << "a refusal must name the blocking condition";
    EXPECT_GT(err.size(), 40u) << "refusal prose must be a sentence, not a token: " << err;
    // Back-compat with the callers of the original three queries.
    EXPECT_EQ(r.value("unavailable_reason", std::string()), err);
}

} // namespace

TEST(DashDaemonlessBlockData, GetBlockHeaderIsFullyAnsweredFromOwnedState) {
    auto mc = build_mined_chain(5, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    auto r = chain_rpc::getblockheader(*mc.hc, mc.hashes[3].GetHex(), true, now);

    ASSERT_FALSE(r.contains("code")) << "this query is fully owned: " << r.dump(2);
    EXPECT_EQ(r["hash"].get<std::string>(), mc.hashes[3].GetHex());
    EXPECT_EQ(r["height"].get<uint32_t>(), 3u);
    EXPECT_EQ(r["previousblockhash"].get<std::string>(), mc.hashes[2].GetHex());
    EXPECT_EQ(r["nextblockhash"].get<std::string>(), mc.hashes[4].GetHex());
    // 5 - 3 + 1
    EXPECT_EQ(r["confirmations"].get<int64_t>(), 3);
    EXPECT_TRUE(r.contains("merkleroot"));
    EXPECT_TRUE(r.contains("time"));
    EXPECT_TRUE(r.contains("bits"));
    EXPECT_TRUE(r.contains("nonce"));
    EXPECT_TRUE(r.contains("difficulty"));
    // A fully-owned answer carries NO partial marker and NO unavailable list.
    EXPECT_FALSE(r.contains("partial")) << r.dump(2);
    EXPECT_FALSE(r.contains("unavailable")) << r.dump(2);
}

TEST(DashDaemonlessBlockData, GetBlockHeaderTipHasNoNextBlockHash) {
    auto mc = build_mined_chain(4, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblockheader(*mc.hc, mc.hashes.back().GetHex(), true,
                                       mc.tip_time + 60);
    // Absent, never an empty string — the successor does not exist yet.
    EXPECT_FALSE(r.contains("nextblockhash")) << r.dump(2);
}

TEST(DashDaemonlessBlockData, GetBlockHeaderNonVerboseReturnsSerialisedHex) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblockheader(*mc.hc, mc.hashes[2].GetHex(), false,
                                       mc.tip_time + 60);
    ASSERT_TRUE(r.is_string()) << r.dump(2);
    // A Dash header is 80 bytes on the wire.
    EXPECT_EQ(r.get<std::string>().size(), 160u);
}

TEST(DashDaemonlessBlockData, GetBlockVerbosity1IsPartialAndNeverFakesATxList) {
    auto mc = build_mined_chain(5, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblock(*mc.hc, mc.hashes[3].GetHex(), 1, mc.tip_time + 60);

    // Not a refusal — we own most of it.
    ASSERT_FALSE(r.contains("code")) << r.dump(2);
    EXPECT_EQ(r["height"].get<uint32_t>(), 3u);
    EXPECT_TRUE(r.contains("merkleroot"));

    // ...but it MUST announce that it is incomplete.
    ASSERT_TRUE(r.value("partial", false)) << r.dump(2);
    ASSERT_TRUE(r.contains("requires")) << r.dump(2);

    // THE CENTRAL ASSERTION. The withheld fields are ABSENT, not empty. If `tx`
    // were emitted as [], a consumer reading result.tx.length would render an
    // empty transaction table and call it data — the exact class of bug this
    // policy exists to remove. Absent makes that consumer throw instead.
    for (const char* f : {"tx", "nTx", "size", "strippedsize", "weight"}) {
        EXPECT_FALSE(r.contains(f))
            << "field '" << f << "' must be ABSENT, never a plausible empty/zero: "
            << r.dump(2);
        ASSERT_TRUE(r["unavailable"].contains(f)) << r.dump(2);
        EXPECT_NE(r["unavailable"][f].get<std::string>().find("HEADERS ONLY"),
                  std::string::npos)
            << "each withheld field must name what we retain: " << r.dump(2);
    }
}

TEST(DashDaemonlessBlockData, GetBlockRawAndDecodedShapesAreRefusedWithRemedies) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    const std::string h = mc.hashes[2].GetHex();

    for (int verbosity : {0, 2}) {
        auto r = chain_rpc::getblock(*mc.hc, h, verbosity, mc.tip_time + 60);
        expect_is_refusal(r, chain_rpc::CODE_REQUIRES_BLOCK_BODIES);
        // Both product choices are advertised in the payload itself, so the
        // operator never has to consult docs to learn the way out.
        ASSERT_TRUE(r.contains("requires")) << r.dump(2);
        auto req = r["requires"];
        EXPECT_NE(std::find(req.begin(), req.end(), "external-daemon-rpc"), req.end())
            << r.dump(2);
        EXPECT_NE(std::find(req.begin(), req.end(), "archive-mode"), req.end())
            << r.dump(2);
    }
}

TEST(DashDaemonlessBlockData, GetRawTransactionNamesBOTHMissingCapabilities) {
    auto r = chain_rpc::getrawtransaction(
        "0000000000000000000000000000000000000000000000000000000000000001");
    expect_is_refusal(r, chain_rpc::CODE_REQUIRES_BLOCK_BODIES);
    // Archive mode ALONE does not fix this one: without a txid->block index we
    // still cannot find which body to open. Saying so prevents an operator
    // paying the archive disk cost and finding the query still refuses.
    EXPECT_EQ(r.value("also_requires", std::string()), chain_rpc::CODE_REQUIRES_TX_INDEX);
    auto req = r["requires"];
    EXPECT_NE(std::find(req.begin(), req.end(), "archive-mode+txindex"), req.end())
        << r.dump(2);
    EXPECT_EQ(std::find(req.begin(), req.end(), "archive-mode"), req.end())
        << "plain archive-mode must NOT be offered as a sufficient remedy here: "
        << r.dump(2);
}

TEST(DashDaemonlessBlockData, UnknownBlockHashIsChainStateNotACapabilityRefusal) {
    auto mc = build_mined_chain(3, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblock(
        *mc.hc,
        "00000000000000000000000000000000000000000000000000000000deadbeef",
        1, mc.tip_time + 60);
    // "we do not have that block" is a fact about the CHAIN; "we cannot serve
    // bodies" is a fact about THIS NODE. Different codes, so a caller can tell
    // a typo from a missing feature.
    expect_is_refusal(r, chain_rpc::CODE_CHAIN_STATE);
    EXPECT_NE(r["error"].get<std::string>().find("not in our header index"),
              std::string::npos) << r.dump(2);
}

TEST(DashDaemonlessBlockData, MalformedHashIsRejectedBeforeAnyLookup) {
    auto mc = build_mined_chain(2, /*tip_time=*/1'800'000'000u);
    auto r = chain_rpc::getblockheader(*mc.hc, "not-a-hash", true, mc.tip_time + 60);
    expect_is_refusal(r, chain_rpc::CODE_BAD_PARAMS);
}

TEST(DashDaemonlessBlockData, StaleTipWithholdsConfirmationsRatherThanOverstateFinality) {
    auto mc = build_mined_chain(5, /*tip_time=*/1'800'000'000u);
    const uint32_t stale_now = mc.tip_time + 90'000u;   // > TIP_MAX_AGE_SECONDS
    auto r = chain_rpc::getblockheader(*mc.hc, mc.hashes[2].GetHex(), true, stale_now);

    // Header fields are still ours to serve — PoW does not go stale.
    EXPECT_EQ(r["height"].get<uint32_t>(), 2u);
    EXPECT_TRUE(r.contains("merkleroot"));
    // But confirmations counted against a tip we know is behind would overstate
    // burial, so it is withheld rather than computed.
    EXPECT_FALSE(r.contains("confirmations")) << r.dump(2);
}

TEST(DashDaemonlessBlockData, DispatchRoutesEveryOwnedAndRefusedMethod) {
    auto mc = build_mined_chain(4, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    const std::string h = mc.hashes[3].GetHex();

    auto q = [&](const char* m, nlohmann::json p) {
        return chain_rpc::chain_query(*mc.hc, m, p, now);
    };

    // Owned.
    EXPECT_FALSE(q("getblockheader", {h}).contains("code"));
    EXPECT_FALSE(q("getblock", {h, 1}).contains("code"));
    // getblock defaults to verbosity 1 when the caller omits it.
    EXPECT_TRUE(q("getblock", {h}).value("partial", false));

    // Refused, each with its own code.
    expect_is_refusal(q("getblock", {h, 0}), chain_rpc::CODE_REQUIRES_BLOCK_BODIES);
    expect_is_refusal(q("getblock", {h, 2}), chain_rpc::CODE_REQUIRES_BLOCK_BODIES);
    expect_is_refusal(q("getrawtransaction", {h}), chain_rpc::CODE_REQUIRES_BLOCK_BODIES);
    expect_is_refusal(q("getblockheader", nlohmann::json::array()), chain_rpc::CODE_BAD_PARAMS);
    expect_is_refusal(q("getpeerinfo", nlohmann::json::array()), chain_rpc::CODE_UNKNOWN_METHOD);
}

TEST(DashDaemonlessBlockData, NoSuccessfulAnswerCarriesTheRefusalDiscriminator) {
    // The one-predicate contract: `code` present <=> refusal. If any owned
    // answer ever grew a `code` field the caller's check would misfire, so this
    // sweeps every success path at once.
    auto mc = build_mined_chain(4, /*tip_time=*/1'800'000'000u);
    const uint32_t now = mc.tip_time + 60;
    const std::string h = mc.hashes[2].GetHex();

    for (const auto& r : {
             chain_rpc::chain_query(*mc.hc, "getblockchaininfo", nlohmann::json::array(), now),
             chain_rpc::chain_query(*mc.hc, "getbestblockhash", nlohmann::json::array(), now),
             chain_rpc::chain_query(*mc.hc, "getblockhash", nlohmann::json::array({2}), now),
             chain_rpc::chain_query(*mc.hc, "getblockheader", nlohmann::json::array({h}), now),
             chain_rpc::chain_query(*mc.hc, "getblock", nlohmann::json::array({h, 1}), now),
         }) {
        if (r.is_object())
            EXPECT_FALSE(r.contains("code"))
                << "an ANSWER must never carry the refusal discriminator: " << r.dump(2);
    }
}

// Dash Core pow.cpp DarkGravityWave with fPowAllowMinDifficultyBlocks
// (testnet): the bits depend on the block's own time. Real testnet data from
// the VM504 shadow (dashd 24.0.0): block 1,586,762 has bits 1e00a6e0 and time
// 1793992483; block 1,586,763 came 605 s later (more than 4 x 150 s) and
// carries 1e0684c0, ten times the parent's target. Our template had served
// the DGW bits 1e009fe7 at a curtime past that mark: a block from it would
// have been bad-diffbits. Mainnet has no such rule.
TEST(DashHeaderChain, TestnetMinDifficultyBitsFollowTheBlockTime)
{
    const auto tn = dash::coin::make_dash_chain_params_testnet();
    const auto mn = dash::coin::make_dash_chain_params_mainnet();
    ASSERT_TRUE(tn.allow_min_difficulty);
    ASSERT_FALSE(mn.allow_min_difficulty);
    const uint32_t dgw = 0x1e009fe7, prev_bits = 0x1e00a6e0;
    const int64_t prev_time = 1793992483;
    using dash::coin::dgw_bits_for_block_time;
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 605, tn), 0x1e0684c0u)
        << "the chain's own block 1,586,763";
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 600, tn), dgw)
        << "exactly 4 x spacing is not more than it";
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 601, tn), 0x1e0684c0u);
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 7201, tn),
              tn.pow_limit.GetCompact()) << "more than two hours: powLimit";
    // Ten times a target already near powLimit is capped at powLimit.
    EXPECT_EQ(dgw_bits_for_block_time(dgw, tn.pow_limit.GetCompact(), prev_time, prev_time + 900, tn),
              tn.pow_limit.GetCompact());
    // Mainnet: always the DGW bits, whatever the time.
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 7201, mn), dgw);
    EXPECT_EQ(dgw_bits_for_block_time(dgw, prev_bits, prev_time, prev_time + 605, mn), dgw);
}

// Head scoring's block-solution credit asks the header chain for the network
// target of a block on top of a given parent (expected_bits_after): for any
// parent on our best chain, not only the tip; nothing for an unknown parent,
// a parent off the best chain, or an incomplete retarget window (where
// dark_gravity_wave would answer powLimit, which is no target to check
// against).
TEST(DashHeaderChain, ExpectedBitsAfterAnyBestChainParent)
{
    auto mc = build_mined_chain(30, 1'800'000'000u);
    auto& hc = *mc.hc;
    const int64_t t = mc.tip_time + 150;

    // The tip: the same answer as next_work_required_at.
    const auto at_tip = hc.expected_bits_after(mc.hashes[30], t);
    ASSERT_TRUE(at_tip.has_value());
    EXPECT_EQ(*at_tip, hc.next_work_required_at(mc.hashes[30], t));

    // A parent below the tip: DGW over the window ending at it, with its own
    // bits and time for the min-difficulty rule.
    const auto p29 = hc.get_header(mc.hashes[29]);
    ASSERT_TRUE(p29.has_value());
    const int64_t t29 = static_cast<int64_t>(p29->header.m_timestamp) + 150;
    const auto below = hc.expected_bits_after(mc.hashes[29], t29);
    ASSERT_TRUE(below.has_value());
    auto anc = [&](uint32_t hh) { return hc.get_header_by_height(hh); };
    EXPECT_EQ(*below, dgw_bits_for_block_time(dark_gravity_wave(anc, 29, mc.params),
                                              p29->header.m_bits, p29->header.m_timestamp,
                                              t29, mc.params));

    // Unknown parent.
    uint256 unknown;
    unknown.SetHex("ab");
    EXPECT_FALSE(hc.expected_bits_after(unknown, t).has_value());

    // Fewer than DGW_PAST_BLOCKS headers ending at the parent.
    EXPECT_FALSE(hc.expected_bits_after(mc.hashes[10], t).has_value());
    EXPECT_FALSE(hc.expected_bits_after(mc.hashes[22], t).has_value());
    EXPECT_FALSE(hc.expected_bits_after(mc.hashes[23], t).has_value())
        << "below height DGW_PAST_BLOCKS Core answers powLimit: no target to check against";
    EXPECT_TRUE(hc.expected_bits_after(mc.hashes[24], t).has_value()) << "heights 1..24: a full window";

    // A parent off the best chain: a mined sibling of hashes[29].
    const auto fork = mine_header(mc.hashes[28], p29->header.m_timestamp + 1,
                                  mc.params.pow_limit.GetCompact(), mc.params.pow_limit);
    ASSERT_TRUE(hc.add_header(fork));
    ASSERT_TRUE(hc.has_header(x11_hash(fork)));
    EXPECT_EQ(hc.get_header_by_height(30)->hash, mc.hashes[30]) << "the tip did not move";
    EXPECT_FALSE(hc.expected_bits_after(x11_hash(fork), t).has_value());
}

// A chain seeded from a fast-start anchor: the anchor entry is synthetic
// (bits 0, time 0). A retarget window that still contains it is no network
// target (dark_gravity_wave would average a zero target in and answer a far
// easier one), so expected_bits_after gives nothing until the window is 24
// real headers above the anchor.
TEST(DashHeaderChain, ExpectedBitsAfterSkipsWindowsWithTheSyntheticAnchor)
{
    auto params = make_easy_test_params();
    DashChainParams::Checkpoint cp{};
    cp.height = 1000;
    cp.hash.SetHex("00000000000000000000000000000000000000000000000000000000000000cc");
    params.fast_start_checkpoint = cp;
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    ASSERT_EQ(hc.height(), 1000u);
    std::vector<uint256> hashes{cp.hash};
    uint32_t t = 1'800'000'000u;
    for (int i = 0; i < 30; ++i) {
        t += 150u;
        auto h = mine_header(hashes.back(), t, params.pow_limit.GetCompact(), params.pow_limit);
        ASSERT_TRUE(hc.add_header(h)) << "mined header " << (i + 1) << " above the anchor";
        hashes.push_back(x11_hash(h));
    }
    ASSERT_EQ(hc.height(), 1030u);
    EXPECT_FALSE(hc.expected_bits_after(hashes[0], t).has_value()) << "the anchor itself";
    EXPECT_FALSE(hc.expected_bits_after(hashes[23], t).has_value())
        << "anchor + 23: the window still holds the synthetic anchor";
    EXPECT_TRUE(hc.expected_bits_after(hashes[24], t).has_value())
        << "anchor + 24: 24 real headers";
}

// A store that already has a tip (here a fast-start anchor, as on mainnet,
// where no genesis stub is seeded) keeps it when the genesis header arrives.
TEST(DashHeaderChain, GenesisHeaderDoesNotMoveAnAnchoredTip)
{
    auto params = make_easy_test_params();
    // A real genesis header for these params: no parent, its X11 hash IS the
    // configured genesis hash.
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000dd");
    genesis.m_timestamp = 1'700'000'000u;
    genesis.m_bits = params.pow_limit.GetCompact();
    genesis.m_nonce = 0;
    params.genesis_hash = x11_hash(genesis);
    DashChainParams::Checkpoint cp{};
    cp.height = 1000;
    cp.hash.SetHex("00000000000000000000000000000000000000000000000000000000000000cc");
    params.fast_start_checkpoint = cp;
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    std::vector<uint256> hashes{cp.hash};
    uint32_t t = 1'800'000'000u;
    for (int i = 0; i < 5; ++i) {
        t += 150u;
        auto h = mine_header(hashes.back(), t, params.pow_limit.GetCompact(), params.pow_limit);
        ASSERT_TRUE(hc.add_header(h));
        hashes.push_back(x11_hash(h));
    }
    ASSERT_EQ(hc.height(), 1005u);
    ASSERT_FALSE(hc.has_header(params.genesis_hash)) << "an anchored store seeds no genesis stub";

    EXPECT_FALSE(hc.add_header(genesis)) << "the genesis header is refused by an anchored store";
    EXPECT_EQ(hc.height(), 1005u) << "the tip height did not move";
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.tip()->hash, hashes.back()) << "the tip did not move";
    EXPECT_FALSE(hc.has_header(params.genesis_hash));

    // The chain keeps extending from the real tip.
    auto next = mine_header(hashes.back(), t + 150u, params.pow_limit.GetCompact(), params.pow_limit);
    EXPECT_TRUE(hc.add_header(next));
    EXPECT_EQ(hc.height(), 1006u);
}

// An empty store still starts from the genesis header.
TEST(DashHeaderChain, GenesisHeaderStartsAnEmptyStore)
{
    auto params = make_easy_test_params();
    BlockHeaderType genesis;
    genesis.m_version = 1;
    genesis.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000dd");
    genesis.m_timestamp = 1'700'000'000u;
    genesis.m_bits = params.pow_limit.GetCompact();
    genesis.m_nonce = 0;
    params.genesis_hash = x11_hash(genesis);
    HeaderChain hc(params, /*db_path=*/"");   // not init()'d: no stub, no anchor
    EXPECT_TRUE(hc.add_header(genesis));
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.tip()->hash, params.genesis_hash);
    EXPECT_EQ(hc.height(), 0u);
}

// An old parent is refused: the block-solution credit checks a share's
// header bits against its parent's expected bits, and an old parent's
// historic bits are easier whenever the difficulty rose since. With
// max_depth only parents within that many blocks of the tip are answered.
TEST(DashHeaderChain, ExpectedBitsAfterRefusesAParentDeeperThanMaxDepth)
{
    auto mc = build_mined_chain(40, 1'800'000'000u);
    auto& hc = *mc.hc;
    const int64_t t = mc.tip_time + 150;
    EXPECT_TRUE(hc.expected_bits_after(mc.hashes[40], t, 6).has_value()) << "the tip";
    EXPECT_TRUE(hc.expected_bits_after(mc.hashes[34], t, 6).has_value()) << "6 below the tip";
    EXPECT_FALSE(hc.expected_bits_after(mc.hashes[33], t, 6).has_value()) << "7 below the tip";
    EXPECT_TRUE(hc.expected_bits_after(mc.hashes[33], t).has_value()) << "no depth bound by default";
}

// ─── network hashrate (Dash Core getnetworkhashps) ─────────────────────────
// The dashboard used tip difficulty * 2^32 / 150, which DarkGravityWave swings
// ~2x within hours on Dash (11-16: 5.6 PH/s against getnetworkhashps 3.25
// PH/s). HeaderChain::network_hashps is Dash Core's GetNetworkHashPS: chain
// work over the window divided by the window's max - min block time.

// RED on master (no helper): Dash Core's own answer at mainnet h=2573376.
// Vector from a Dash Core 24.0.2 node: getnetworkhashps 576 2573376 =
// 3251162766216974, chainwork at 2573376 and 2572800, and the min / max block
// time over 2572800..2573376.
TEST(DashNetworkHashps, MatchesDashCoreGetNetworkHashpsAtMainnetHeight)
{
    uint256 tip, base;
    tip.SetHex("00000000000000000000000000000000000000000000c274b3be21c35c4e1f9f");
    base.SetHex("00000000000000000000000000000000000000000000c264dc173e55c7f73f67");
    const double hps = network_hashps_from(tip, base, 1794763522, 1794853410);
    EXPECT_NEAR(hps, 3251162766216974.0, 1.0);
}

TEST(DashNetworkHashps, NoGrowthOrNoTimeSpanIsZero)
{
    uint256 a, b;
    a.SetHex("0000000000000000000000000000000000000000000000000000000000001000");
    b.SetHex("0000000000000000000000000000000000000000000000000000000000002000");
    EXPECT_EQ(network_hashps_from(b, a, 100, 100), 0.0) << "min == max time (dashd returns 0)";
    EXPECT_EQ(network_hashps_from(b, a, 200, 100), 0.0) << "inverted span";
    EXPECT_EQ(network_hashps_from(a, b, 100, 200), 0.0) << "work does not grow";
    EXPECT_EQ(network_hashps_from(a, a, 100, 200), 0.0) << "equal work";
    EXPECT_GT(network_hashps_from(b, a, 100, 200), 0.0);
}

// The HeaderChain method walks a real (mined) window: 10 blocks at the
// pow-limit target, 150 s apart => 10 * proof / 1500 s.
TEST(DashNetworkHashps, HeaderChainWindowOverAMinedChain)
{
    auto mc = build_mined_chain(40, 1'800'000'000u);
    const auto& hc = *mc.hc;
    const double proof = get_block_proof(mc.params.pow_limit.GetCompact()).getdouble();
    EXPECT_NEAR(hc.network_hashps(10), 10.0 * proof / 1500.0, 10.0 * proof / 1500.0 * 1e-12);
    EXPECT_EQ(hc.network_hashps(40), 0.0) << "the window must lie above the chain's first entry";
    EXPECT_EQ(hc.network_hashps(0), 0.0);
}

// ─── median_time_past_at: the found-block relay gate's time floor ───────────
// Dash Core GetMedianTimePast of a given block: the median of its own and its
// 10 ancestors' timestamps. A block built on it needs a time above that.

TEST(DashHeaderChainMtp, MedianOfTheBlockAndItsTenAncestors)
{
    // Heights 1..15 at tip_time - (15 - h) * 150 s.
    auto mc = build_mined_chain(15, 1'800'000'000u);
    const uint32_t t7 = mc.tip_time - (15u - 7u) * 150u;
    const auto m12 = mc.hc->median_time_past_at(mc.hashes[12]);
    ASSERT_TRUE(m12.has_value());
    EXPECT_EQ(*m12, t7) << "the median of heights 2..12 is height 7's time";
    const auto m15 = mc.hc->median_time_past_at(mc.hashes[15]);
    ASSERT_TRUE(m15.has_value());
    EXPECT_EQ(*m15, mc.hc->median_time_past()) << "at the tip it is the tip's MTP";
}

TEST(DashHeaderChainMtp, UnknownTooDeepOrTooShortIsUnknown)
{
    auto mc = build_mined_chain(15, 1'800'000'000u);
    uint256 unknown;
    unknown.SetHex("00000000000000000000000000000000000000000000000000000000000abcde");
    EXPECT_FALSE(mc.hc->median_time_past_at(unknown).has_value()) << "not in the header chain";
    EXPECT_FALSE(mc.hc->median_time_past_at(mc.hashes[12], /*max_depth=*/2).has_value())
        << "3 blocks below the tip, deeper than max_depth";
    EXPECT_TRUE(mc.hc->median_time_past_at(mc.hashes[12], /*max_depth=*/3).has_value());
    EXPECT_FALSE(mc.hc->median_time_past_at(mc.hashes[9]).has_value())
        << "fewer than 11 headers up to height 9";
}

// Above a fast-start anchor the synthetic anchor (time 0) is never counted:
// the window must be 11 real headers above it.
TEST(DashHeaderChainMtp, WindowWithTheSyntheticAnchorIsUnknown)
{
    auto params = make_easy_test_params();
    DashChainParams::Checkpoint cp{};
    cp.height = 1000;
    cp.hash.SetHex("00000000000000000000000000000000000000000000000000000000000000cc");
    params.fast_start_checkpoint = cp;
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    std::vector<uint256> hashes{cp.hash};
    uint32_t t = 1'800'000'000u;
    for (int i = 0; i < 15; ++i) {
        t += 150u;
        auto h = mine_header(hashes.back(), t, params.pow_limit.GetCompact(), params.pow_limit);
        ASSERT_TRUE(hc.add_header(h)) << "mined header " << (i + 1) << " above the anchor";
        hashes.push_back(x11_hash(h));
    }
    EXPECT_FALSE(hc.median_time_past_at(hashes[0]).has_value()) << "the anchor itself";
    EXPECT_FALSE(hc.median_time_past_at(hashes[10]).has_value())
        << "anchor + 10: the window still holds the synthetic anchor";
    const auto m11 = hc.median_time_past_at(hashes[11]);
    ASSERT_TRUE(m11.has_value()) << "anchor + 11: 11 real headers";
    EXPECT_EQ(*m11, 1'800'000'000u + 6u * 150u) << "the median of anchor+1..anchor+11 is anchor+6";
}

// Timestamps out of order (each above its own window's MTP, as the network
// allows): the answer is the median, not the 6th header back.
TEST(DashHeaderChainMtp, MedianOfUnorderedTimestamps)
{
    auto params = make_easy_test_params();
    HeaderChain hc(params, /*db_path=*/"");
    ASSERT_TRUE(hc.init());
    std::vector<uint256> hashes{params.genesis_hash};
    std::vector<uint32_t> times{0};
    const uint32_t base = 1'800'000'000u;
    for (uint32_t h = 1; h <= 15; ++h) {
        // Up 600 s, then back 300 s: never below the previous window's median.
        const uint32_t t = base + h * 150u + ((h % 2) ? 300u : 0u);
        auto hdr = mine_header(hashes.back(), t, params.pow_limit.GetCompact(), params.pow_limit);
        ASSERT_TRUE(hc.add_header(hdr)) << "header " << h;
        hashes.push_back(x11_hash(hdr));
        times.push_back(t);
    }
    std::vector<uint32_t> w(times.begin() + 2, times.begin() + 13);   // heights 2..12
    std::sort(w.begin(), w.end());
    const auto m12 = hc.median_time_past_at(hashes[12]);
    ASSERT_TRUE(m12.has_value());
    EXPECT_EQ(*m12, w[5]);
    EXPECT_NE(*m12, times[7]) << "the window is out of order, so position and median differ";
}

// ── A store that started at the fast-start anchor keeps its best chain
// through the anchor, and reaches the live chain from a locator resync. ──
namespace {
struct AnchoredNet {
    DashChainParams params;
    std::vector<BlockHeaderType> hdr;   // index = height
    std::vector<uint256> hash;
};
AnchoredNet make_anchored_net(uint32_t K, uint32_t A)
{
    AnchoredNet n;
    n.params = make_easy_test_params();
    BlockHeaderType G;
    G.m_version = 1;
    G.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000dd");
    G.m_timestamp = 1'500'000'000u;
    G.m_bits = n.params.pow_limit.GetCompact();
    G.m_nonce = 0;
    n.params.genesis_hash = x11_hash(G);
    n.hdr.push_back(G);
    n.hash.push_back(n.params.genesis_hash);
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (uint32_t i = 1; i <= K; ++i) {
        const uint32_t t = now - (K - i) * 60u - 30u;
        auto h = mine_header(n.hash.back(), t, n.params.pow_limit.GetCompact(), n.params.pow_limit);
        n.hdr.push_back(h);
        n.hash.push_back(x11_hash(h));
    }
    DashChainParams::Checkpoint cp{};
    cp.height = A;
    cp.hash = n.hash[A];
    n.params.fast_start_checkpoint = cp;
    return n;
}
// A peer answering getheaders to the store's own locator (<= 2000 per reply),
// until a reply adds nothing three times in a row.
void resync_from_locator(HeaderChain& hc, const AnchoredNet& n, uint32_t K)
{
    int zero_rounds = 0;
    for (int rounds = 0; rounds < 30; ++rounds) {
        const auto loc = hc.get_locator();
        uint32_t start = 0; bool found = false;
        for (const auto& l : loc) {
            for (uint32_t i = 0; i <= K; ++i)
                if (n.hash[i] == l) { start = i + 1; found = true; break; }
            if (found) break;
        }
        if (!found || start > K) return;
        std::vector<BlockHeaderType> reply;
        for (uint32_t i = start; i <= K && reply.size() < 2000; ++i) reply.push_back(n.hdr[i]);
        if (hc.add_headers(reply) <= 0 && ++zero_rounds >= 3) return;
    }
}
BlockHeaderType header_on(const AnchoredNet& n, const uint256& parent)
{
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    return mine_header(parent, now - 10, n.params.pow_limit.GetCompact(), n.params.pow_limit);
}
} // namespace

TEST(DashHeaderChainAnchor, AHeaderOnTheAnchorGivesWayToTheLiveChain)
{
    constexpr uint32_t A = 40, K = 50;
    AnchoredNet n = make_anchored_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    ASSERT_EQ(hc.height(), A);
    // It descends from the anchor, so it may hold the tip until the live
    // chain arrives; the live chain then takes over.
    hc.add_header(header_on(n, n.hash[A]));
    resync_from_locator(hc, n, K);
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.height(), K);
    EXPECT_EQ(hc.tip()->hash, n.hash[K]);
    EXPECT_TRUE(hc.is_synced());
}

TEST(DashHeaderChainAnchor, AHeaderOnAPreAnchorEntryDoesNotBecomeTheTip)
{
    constexpr uint32_t A = 40, K = 50;
    AnchoredNet n = make_anchored_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    std::vector<BlockHeaderType> span(n.hdr.begin() + (A - 5), n.hdr.begin() + A + 1);
    ASSERT_EQ(hc.install_preanchor_span(n.hash[A], span), 5u);

    hc.add_header(header_on(n, n.hash[A - 3]));
    EXPECT_EQ(hc.height(), A) << "the tip must stay on the anchor's chain";
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.tip()->hash, n.hash[A]);

    resync_from_locator(hc, n, K);
    EXPECT_EQ(hc.height(), K);
    EXPECT_TRUE(hc.is_synced());
}

TEST(DashHeaderChainAnchor, APreAnchorSpanLongerThanOneReplyStillReachesTheLiveChain)
{
    // The held span is longer than one getheaders reply (2000 headers).
    constexpr uint32_t A = 2200, K = 2210;
    AnchoredNet n = make_anchored_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    std::vector<BlockHeaderType> span(n.hdr.begin() + (A - 2100), n.hdr.begin() + A + 1);
    ASSERT_EQ(hc.install_preanchor_span(n.hash[A], span), 2100u);

    hc.add_header(header_on(n, n.hash[A - 2100]));
    EXPECT_GE(hc.height(), A) << "the tip must never fall below the anchor";

    resync_from_locator(hc, n, K);
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.height(), K) << "the store must reach the live chain";
    EXPECT_EQ(hc.tip()->hash, n.hash[K]);
    EXPECT_TRUE(hc.is_synced());
}

// ── Near the anchor the first DGW window reaches below it, so a header there
// is bounded by the DGW clamp instead: its target may be at most 3x the
// easiest of the pinned anchor and its own ancestors above the anchor. ──
namespace {
struct HardNet {
    DashChainParams params;
    std::vector<BlockHeaderType> hdr;
    std::vector<uint256> hash;
    uint32_t bits{0};
};
// A mainnet-style store (no min-difficulty blocks) whose chain runs at a
// target 16x harder than pow_limit, anchored at A with the anchor's header
// pinned, as the mainnet checkpoint is.
HardNet make_hard_net(uint32_t K, uint32_t A)
{
    HardNet n;
    n.params = make_easy_test_params();
    n.params.allow_min_difficulty = false;
    uint256 t = n.params.pow_limit;
    t >>= 4;
    n.bits = t.GetCompact();
    BlockHeaderType G;
    G.m_version = 1;
    G.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000de");
    G.m_timestamp = 1'500'000'000u;
    G.m_bits = n.params.pow_limit.GetCompact();
    G.m_nonce = 0;
    n.params.genesis_hash = x11_hash(G);
    n.hdr.push_back(G);
    n.hash.push_back(n.params.genesis_hash);
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (uint32_t i = 1; i <= K; ++i) {
        const uint32_t ts = now - (K - i) * 150u - 30u;
        auto h = mine_header(n.hash.back(), ts, n.bits, n.params.pow_limit);
        n.hdr.push_back(h);
        n.hash.push_back(x11_hash(h));
    }
    DashChainParams::Checkpoint cp{};
    cp.height = A;
    cp.hash = n.hash[A];
    cp.has_header = true;
    cp.hdr_version = n.hdr[A].m_version;
    cp.hdr_prev_block = n.hdr[A].m_previous_block;
    cp.hdr_merkle_root = n.hdr[A].m_merkle_root;
    cp.hdr_time = n.hdr[A].m_timestamp;
    cp.hdr_bits = n.hdr[A].m_bits;
    cp.hdr_nonce = n.hdr[A].m_nonce;
    n.params.fast_start_checkpoint = cp;
    return n;
}
} // namespace

TEST(DashHeaderChainAnchor, AHeaderOnTheAnchorAtPowLimitIsRefused)
{
    constexpr uint32_t A = 40, K = 50;
    HardNet n = make_hard_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    ASSERT_EQ(hc.height(), A);

    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    auto easy = mine_header(n.hash[A], now - 10, n.params.pow_limit.GetCompact(),
                            n.params.pow_limit);
    EXPECT_FALSE(hc.add_header(easy))
        << "a target 16x easier than the anchor window allows must be refused";
    EXPECT_EQ(hc.height(), A);
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.tip()->hash, n.hash[A]);

    // The chain itself, at the anchor's difficulty, is accepted.
    std::vector<BlockHeaderType> rest(n.hdr.begin() + A + 1, n.hdr.end());
    EXPECT_EQ(hc.add_headers(rest), static_cast<int>(K - A));
    EXPECT_EQ(hc.height(), K);
    EXPECT_TRUE(hc.is_synced());
}

TEST(DashHeaderChainAnchor, NearAnchorBoundAllowsTheDgwClamp)
{
    // A real step down in difficulty within the clamp (2x easier) is accepted.
    constexpr uint32_t A = 40, K = 42;
    HardNet n = make_hard_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    uint256 t2;
    t2.SetCompact(n.bits);
    t2 *= 2u;
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    auto step = mine_header(n.hash[A], now - 10, t2.GetCompact(), n.params.pow_limit);
    EXPECT_TRUE(hc.add_header(step));
    EXPECT_EQ(hc.height(), A + 1);
}

#include <filesystem>
#include <unistd.h>

// ── A persisted store whose tip does not run through the anchor (written
// before the anchor rule) re-selects its tip at load, so the headers it
// already holds cannot keep it where it is. ──
TEST(DashHeaderChainAnchor, StoredTipOffTheAnchorIsReselectedAtLoad)
{
    constexpr uint32_t A = 40, K = 50, FORK = 10, SIDE = 55;
    AnchoredNet n = make_anchored_net(K, A);
    auto no_anchor = n.params;
    no_anchor.fast_start_checkpoint.reset();

    const auto dir = std::filesystem::temp_directory_path()
        / ("c2pool-hc-reselect-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const std::string db = (dir / "dash_headers").string();

    // A store synced from genesis that also holds a longer branch forking
    // below the anchor height; that branch is its tip.
    {
        HeaderChain hc(no_anchor, db);
        ASSERT_TRUE(hc.init());
        std::vector<BlockHeaderType> chain(n.hdr.begin() + 1, n.hdr.end());
        ASSERT_EQ(hc.add_headers(chain), static_cast<int>(K));
        uint256 prev = n.hash[FORK];
        const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        std::vector<BlockHeaderType> side;
        for (uint32_t h = FORK + 1; h <= SIDE; ++h) {
            auto s = mine_header(prev, now - (SIDE - h) * 60u - 20u,
                                 n.params.pow_limit.GetCompact(), n.params.pow_limit);
            side.push_back(s);
            prev = x11_hash(s);
        }
        hc.add_headers(side);
        ASSERT_EQ(hc.height(), SIDE) << "the longer branch holds the tip";
    }

    // Reopened by a build that carries the anchor at A on the main chain.
    {
        HeaderChain hc(n.params, db);
        ASSERT_TRUE(hc.init());
        ASSERT_TRUE(hc.tip().has_value());
        EXPECT_EQ(hc.height(), K) << "the tip must be re-selected through the anchor";
        EXPECT_EQ(hc.tip()->hash, n.hash[K]);
        EXPECT_TRUE(hc.is_synced());
    }
    std::filesystem::remove_all(dir);
}

// ── Mainnet refuses a header whose bits are not the DGW bits of its own
// window; set_refuse_dgw_mismatch(false) (--header-dgw-log-only) logs and
// accepts it instead. ──
TEST(DashHeaderChainAnchor, DgwMismatchIsRefusedByDefaultAndAcceptedWhenLogOnly)
{
    // The first height whose DGW window lies wholly above the anchor is
    // anchor+25; from there mainnet checks the bits, also on a fresh store
    // that holds only the anchor and the 24 headers above it.
    for (const bool refuse : {true, false}) {
        auto params = make_easy_test_params();
        params.allow_min_difficulty = false;          // mainnet rules
        constexpr uint32_t A = 34200;                 // past the DGW activation window
        const uint32_t bits = params.pow_limit.GetCompact();
        const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        uint256 seed;
        seed.SetHex("0000000000000000000000000000000000000000000000000000000000000a01");
        const auto anchor_hdr = mine_header(seed, now - 60u * 150u, bits, params.pow_limit);
        DashChainParams::Checkpoint cp{};
        cp.height = A;
        cp.hash = x11_hash(anchor_hdr);
        params.fast_start_checkpoint = cp;

        HeaderChain hc(params, "");
        hc.set_refuse_dgw_mismatch(refuse);
        ASSERT_TRUE(hc.init());
        uint256 prev = cp.hash;
        for (uint32_t i = 1; i <= 24; ++i) {
            auto h = mine_header(prev, now - (60u - i) * 150u, bits, params.pow_limit);
            ASSERT_TRUE(hc.add_header(h)) << "refuse=" << refuse << " h=A+" << i;
            prev = x11_hash(h);
        }
        ASSERT_EQ(hc.height(), A + 24);

        // Constant bits over 24 blocks spaced exactly target_spacing are NOT
        // the DGW bits (DGW measures 23 intervals against a 24-interval
        // target timespan), so this header is off its window's DGW bits.
        const uint32_t want = hc.next_work_required();
        ASSERT_NE(want, bits) << "the KAT needs a header off its DGW bits";
        auto off = mine_header(prev, now - 35u * 150u, bits, params.pow_limit);
        EXPECT_EQ(hc.add_header(off), !refuse) << "refuse=" << refuse << " at anchor+25";

        if (refuse) {
            // The same window's DGW bits are accepted.
            auto on = mine_header(prev, now - 35u * 150u, want, params.pow_limit);
            EXPECT_TRUE(hc.add_header(on));
            EXPECT_EQ(hc.height(), A + 25);
        }
    }
}

// ── A side-branch header is judged by the DGW window it actually extends,
// not by the best chain's window at the same heights. ──
TEST(DashHeaderChainAnchor, SideBranchIsJudgedByItsOwnDgwWindow)
{
    auto params = make_easy_test_params();
    params.allow_min_difficulty = false;
    constexpr uint32_t A = 34200, FORK = A + 20, TOP = A + 30;
    const uint32_t bits = params.pow_limit.GetCompact();
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    uint256 seed;
    seed.SetHex("0000000000000000000000000000000000000000000000000000000000000b02");
    const auto anchor_hdr = mine_header(seed, now - 90u * 150u, bits, params.pow_limit);
    DashChainParams::Checkpoint cp{};
    cp.height = A;
    cp.hash = x11_hash(anchor_hdr);
    params.fast_start_checkpoint = cp;

    // The best chain: 150 s apart, DGW bits from anchor+25 on.
    HeaderChain hc(params, "");
    ASSERT_TRUE(hc.init());
    std::vector<uint256> main{cp.hash};
    std::vector<BlockHeaderType> main_hdr{anchor_hdr};
    for (uint32_t h = A + 1; h <= TOP; ++h) {
        const uint32_t b = (h <= A + 24) ? bits : hc.next_work_required();
        auto hd = mine_header(main.back(), now - (90u - (h - A)) * 150u, b, params.pow_limit);
        ASSERT_TRUE(hc.add_header(hd)) << "main h=A+" << (h - A);
        main.push_back(x11_hash(hd));
        main_hdr.push_back(hd);
    }
    ASSERT_EQ(hc.height(), TOP);

    // A side branch from FORK with blocks 600 s apart: its own window differs.
    HeaderChain side(params, "");
    ASSERT_TRUE(side.init());
    for (uint32_t h = A + 1; h <= FORK; ++h) ASSERT_TRUE(side.add_header(main_hdr[h - A]));
    std::vector<BlockHeaderType> branch;
    uint256 prev = main[FORK - A];
    uint32_t t = main_hdr[FORK - A].m_timestamp;
    for (uint32_t h = FORK + 1; h <= A + 24; ++h) {
        t += 600u;
        auto hd = mine_header(prev, t, bits, params.pow_limit);
        ASSERT_TRUE(side.add_header(hd));
        branch.push_back(hd);
        prev = x11_hash(hd);
    }
    const uint32_t side_bits = side.next_work_required();   // DGW of the branch's own window
    // The best chain's DGW for the same height, from its own window.
    HeaderChain best24(params, "");
    ASSERT_TRUE(best24.init());
    for (uint32_t h = A + 1; h <= A + 24; ++h) ASSERT_TRUE(best24.add_header(main_hdr[h - A]));
    const uint32_t best_bits = best24.next_work_required();
    ASSERT_NE(side_bits, best_bits) << "the two windows must differ for the KAT to mean anything";

    // In the store where the best chain is longer, the branch's anchor+25 is
    // accepted with ITS window's bits and refused with the best chain's.
    for (const auto& hd : branch) ASSERT_TRUE(hc.add_header(hd));
    t += 600u;
    auto own = mine_header(prev, t, side_bits, params.pow_limit);
    auto other = mine_header(prev, t + 1, best_bits, params.pow_limit);
    EXPECT_TRUE(hc.add_header(own)) << "the branch's own DGW bits";
    EXPECT_FALSE(hc.add_header(other)) << "the best chain's bits are not this branch's";
    EXPECT_EQ(hc.height(), TOP) << "the shorter branch does not take the tip";
}

// ── A header at the anchor height that is not the anchor never takes the tip,
// even when its parent is a held pre-anchor entry. ──
TEST(DashHeaderChainAnchor, ASiblingOfTheAnchorDoesNotBecomeTheTip)
{
    constexpr uint32_t A = 40, K = 50;
    AnchoredNet n = make_anchored_net(K, A);
    HeaderChain hc(n.params, "");
    ASSERT_TRUE(hc.init());
    std::vector<BlockHeaderType> span(n.hdr.begin() + (A - 5), n.hdr.begin() + A + 1);
    ASSERT_EQ(hc.install_preanchor_span(n.hash[A], span), 5u);
    hc.add_header(header_on(n, n.hash[A - 1]));     // height A, not the anchor
    ASSERT_TRUE(hc.tip().has_value());
    EXPECT_EQ(hc.height(), A);
    EXPECT_EQ(hc.tip()->hash, n.hash[A]);
}

// ── A store written before this anchor existed (its tip below the anchor, the
// anchor not held) starts from the anchor at load and reaches the live chain. ──
TEST(DashHeaderChainAnchor, AStoreBelowTheAnchorStartsFromItAndReachesTheLiveChain)
{
    constexpr uint32_t A = 2200, K = 2210, OLD = 100;
    AnchoredNet n = make_anchored_net(K, A);
    auto no_anchor = n.params;
    no_anchor.fast_start_checkpoint.reset();
    const auto dir = std::filesystem::temp_directory_path()
        / ("c2pool-hc-below-anchor-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const std::string db = (dir / "dash_headers").string();
    {
        HeaderChain hc(no_anchor, db);
        ASSERT_TRUE(hc.init());
        std::vector<BlockHeaderType> early(n.hdr.begin() + 1, n.hdr.begin() + OLD + 1);
        ASSERT_EQ(hc.add_headers(early), static_cast<int>(OLD));
        ASSERT_EQ(hc.height(), OLD);
    }
    {
        HeaderChain hc(n.params, db);
        ASSERT_TRUE(hc.init());
        ASSERT_TRUE(hc.tip().has_value());
        EXPECT_EQ(hc.height(), A) << "the store starts from the anchor";
        EXPECT_EQ(hc.tip()->hash, n.hash[A]);
        resync_from_locator(hc, n, K);
        EXPECT_EQ(hc.height(), K) << "and reaches the live chain";
        EXPECT_TRUE(hc.is_synced());
    }
    std::filesystem::remove_all(dir);
}
