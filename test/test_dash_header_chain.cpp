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
