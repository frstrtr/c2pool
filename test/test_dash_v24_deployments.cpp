// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Dash Core v24 deployment tracking (slice S0): parameter table, MNHF payload,
// versionbits port with EHF start heights, EHF signal tracker, deployment
// status (exact / bound / buried / override) and the block version.
//
// The testnet replay pins the switch height against chain data: with the
// measured testnet headers and any admissible EHF signal height, the machine
// gives LOCKED_IN for 1,577,900..1,577,999 and ACTIVE from 1,578,000 -- the
// first CbTx version-4 block. A signal one period later moves activation to
// 1,578,100, which the chain contradicts.

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/deployment_status.hpp>
#include <impl/dash/coin/ehf_tracker.hpp>
#include <impl/dash/coin/versionbits.hpp>
#include <impl/dash/coin/vendor/mnhftx.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/service_update_order.hpp>
#include <impl/dash/coin/v24_activation_wire.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "dash_v24_testnet_versionbits.inc"

using namespace dash::coin;

namespace {

uint256 height_hash(uint32_t h, uint32_t salt = 0)
{
    uint256 x;
    for (int i = 0; i < 4; ++i) x.data()[i] = static_cast<uint8_t>(h >> (8 * i));
    for (int i = 0; i < 4; ++i) x.data()[4 + i] = static_cast<uint8_t>(salt >> (8 * i));
    x.data()[31] = 0x5a;
    return x;
}

/// A synthetic chain: one block every 150 s from t0, versions set per height.
struct SynthChain
{
    uint32_t t0{1'800'000'000};
    std::map<uint32_t, int32_t> version;      // default 0x20000000
    std::map<uint32_t, uint32_t> salt;        // fork marker per height
    uint32_t tip{0};

    std::optional<VbBlockInfo> at(uint32_t h) const
    {
        if (h > tip) return std::nullopt;
        VbBlockInfo b;
        auto it = version.find(h);
        b.nVersion = it == version.end() ? kVersionBitsTopBits : it->second;
        b.nTime = t0 + 150 * h;
        auto s = salt.find(h);
        b.hash = height_hash(h, s == salt.end() ? 0 : s->second);
        return b;
    }
    VbChainFn fn() const { return [this](uint32_t h) { return at(h); }; }
    void signal_range(uint32_t from, uint32_t to, int bit = 13)
    {
        for (uint32_t h = from; h <= to; ++h) version[h] = kVersionBitsTopBits | (1 << bit);
    }
    /// MTP of block h (synthetic times are monotone: the middle of 11).
    int64_t mtp(uint32_t h) const { return t0 + 150 * (static_cast<int64_t>(h) - 5); }
};

/// Small fast parameters: window 10, threshold 8 falling to 6.
DashDeploymentParams fast_params(int64_t start)
{
    DashDeploymentParams p = dash_deployment_params(DashNetwork::REGTEST);
    for (auto& d : p.deployments) {
        d.nStartTime = start;
        d.nTimeout = Bip9Deployment::NO_TIMEOUT;
        d.nWindowSize = 10;
        d.nThresholdStart = 8;
        d.nThresholdMin = 6;
        d.nFalloffCoeff = 5;
    }
    p.min_bip9_warning_height = 0;
    p.v20_height = 0;
    p.ehf_anchor_height = 0;
    p.v24_buried_height.reset();
    return p;
}

MutableTransaction mnhf_tx(uint8_t bit)
{
    vendor::MNHFTxPayload pl;
    pl.signal.versionBit = bit;
    pl.signal.quorumHash = height_hash(777);
    for (size_t i = 0; i < pl.signal.sig.size(); ++i) pl.signal.sig[i] = static_cast<uint8_t>(i);
    auto ps = ::pack(pl);
    auto sp = ps.get_span();
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 7;
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

/// Commit the header's merkle root to the body's tx set (a bound body).
void bind_body(BlockType& b)
{
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) {
        auto ps = ::pack(tx);
        ids.push_back(::Hash(ps.get_span()));
    }
    b.m_merkle_root = compute_merkle_root(ids);
}

/// A bound body on the synthetic chain (the header's merkle root commits to
/// its txs; the synthetic chain hash is not an X11 hash, see X11Chain).
BlockType block_at(const SynthChain& c, uint32_t h, std::vector<MutableTransaction> extra = {})
{
    BlockType b;
    if (h > 0) b.m_previous_block = c.at(h - 1)->hash;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    b.m_txs.push_back(cb);
    for (auto& t : extra) b.m_txs.push_back(std::move(t));
    bind_body(b);
    return b;
}

/// Lane check for the synthetic chain: the merkle binding only (its hashes
/// are labels, not X11 hashes of the bodies' headers).
bool merkle_bound_only(const uint256&, const BlockType& b) { return block_body_binds_to_header(b); }

uint256 x11_header_hash(const BlockType& b)
{
    auto packed = ::pack(static_cast<const BlockHeaderType&>(b));
    return dash::crypto::hash_x11(packed.get_span());
}

/// A chain of real bodies whose hashes ARE the X11 hashes of their headers,
/// for the production binding check (ehf_rescan_body_binds).
struct X11Chain
{
    std::vector<BlockType> blocks;
    std::vector<uint256>   hashes;
    void build(uint32_t tip, const std::map<uint32_t, std::vector<MutableTransaction>>& extra)
    {
        for (uint32_t h = 0; h <= tip; ++h) {
            BlockType b;
            b.m_version = static_cast<uint32_t>(kVersionBitsTopBits);
            b.m_previous_block = h ? hashes[h - 1] : uint256();
            b.m_timestamp = 1'800'000'000 + 150 * h;
            b.m_bits = 0x207fffff;
            b.m_nonce = h;
            MutableTransaction cb;
            cb.version = 3;
            cb.type = 5;
            cb.locktime = h;   // distinct coinbases
            b.m_txs.push_back(cb);
            auto it = extra.find(h);
            if (it != extra.end()) for (const auto& t : it->second) b.m_txs.push_back(t);
            bind_body(b);
            hashes.push_back(x11_header_hash(b));
            blocks.push_back(b);
        }
    }
    VbChainFn fn() const
    {
        return [this](uint32_t h) -> std::optional<VbBlockInfo> {
            if (h >= blocks.size()) return std::nullopt;
            VbBlockInfo i;
            i.nVersion = static_cast<int32_t>(blocks[h].m_version);
            i.nTime = blocks[h].m_timestamp;
            i.hash = hashes[h];
            return i;
        };
    }
};

} // namespace

// ── Parameter table and thresholds (design §1.1, §1.2) ──────────────────────

TEST(DashV24Deployments, ParameterTableMatchesCore)
{
    const auto& m = dash_deployment_params(DashNetwork::MAINNET);
    const auto& v24 = m.dep(DashDeployment::V24);
    EXPECT_EQ(v24.bit, 13);
    EXPECT_EQ(v24.nStartTime, 1794182400);
    EXPECT_EQ(v24.nTimeout, 1857340800);
    EXPECT_EQ(v24.nWindowSize, 4032);
    EXPECT_EQ(v24.nThresholdStart, 3226);
    EXPECT_EQ(v24.nThresholdMin, 2420);
    EXPECT_EQ(v24.nFalloffCoeff, 5);
    EXPECT_TRUE(v24.useEHF);
    EXPECT_EQ(m.dep(DashDeployment::EVO_SHARES).bit, 14);
    EXPECT_EQ(m.llmq_type_mnhf, 3);   // LLMQ_400_85
    EXPECT_FALSE(m.v24_buried_height.has_value());

    const auto& t = dash_deployment_params(DashNetwork::TESTNET);
    EXPECT_EQ(t.dep(DashDeployment::V24).nStartTime, 1790208000);
    EXPECT_EQ(t.dep(DashDeployment::V24).nTimeout, Bip9Deployment::NO_TIMEOUT);
    EXPECT_EQ(t.dep(DashDeployment::V24).nWindowSize, 100);
    EXPECT_EQ(t.llmq_type_mnhf, 1);   // LLMQ_50_60
    ASSERT_TRUE(t.v24_buried_height.has_value());
    EXPECT_EQ(*t.v24_buried_height, 1'578'000u);

    const auto& r = dash_deployment_params(DashNetwork::REGTEST);
    EXPECT_EQ(r.dep(DashDeployment::V24).nWindowSize, 250);
    EXPECT_EQ(r.dep(DashDeployment::V24).nThresholdStart, 200);
    EXPECT_EQ(r.dep(DashDeployment::V24).nThresholdMin, 150);
    EXPECT_EQ(r.dep(DashDeployment::V24).nStartTime, 0);
}

TEST(DashV24Deployments, ThresholdTablesFallTo60PercentOver10Windows)
{
    const auto& m = dash_deployment_params(DashNetwork::MAINNET);
    const int64_t main_exp[] = {3226, 3218, 3194, 3154, 3097, 3025, 2936, 2831, 2710, 2573, 2420};
    for (int a = 0; a <= 10; ++a)
        EXPECT_EQ(vb_threshold(m, m.dep(DashDeployment::V24), a), main_exp[a]) << "a=" << a;
    EXPECT_EQ(vb_threshold(m, m.dep(DashDeployment::V24), 11), 2420) << "floor holds after 10";
    EXPECT_EQ(vb_threshold(m, m.dep(DashDeployment::V24), 1000), 2420);

    const auto& t = dash_deployment_params(DashNetwork::TESTNET);
    const int64_t test_exp[] = {80, 80, 80, 79, 77, 75, 73, 71, 68, 64, 60};
    for (int a = 0; a <= 10; ++a)
        EXPECT_EQ(vb_threshold(t, t.dep(DashDeployment::V24), a), test_exp[a]) << "a=" << a;
}

TEST(DashV24Deployments, SignallingConditionNeedsTopBits)
{
    const auto& d = dash_deployment_params(DashNetwork::MAINNET).dep(DashDeployment::V24);
    EXPECT_TRUE(vb_signals(0x20002000, d));
    EXPECT_TRUE(vb_signals(0x20006000, d));
    EXPECT_FALSE(vb_signals(0x20000000, d));
    EXPECT_FALSE(vb_signals(0x20004000, d));   // bit 14 only
    EXPECT_FALSE(vb_signals(0x60002000, d));   // wrong top bits
    EXPECT_FALSE(vb_signals(0x00002000, d));
}

// ── MNHF payload ────────────────────────────────────────────────────────────

TEST(DashV24Deployments, MnhfPayloadRoundTripAndExtract)
{
    auto tx = mnhf_tx(13);
    EXPECT_EQ(tx.extra_payload.size(), 1u + 1u + 32u + 96u);
    vendor::MNHFTxPayload p;
    ASSERT_TRUE(vendor::parse_mnhf_payload(tx.extra_payload, p));
    EXPECT_EQ(p.nVersion, 1);
    EXPECT_EQ(p.signal.versionBit, 13);
    EXPECT_EQ(p.signal.quorumHash, height_hash(777));
    EXPECT_TRUE(p.is_trivially_valid());
    EXPECT_EQ(extract_ehf_signal(tx), std::optional<uint8_t>(13));

    // Not special version / another type / truncated / trailing byte.
    auto v2 = tx; v2.version = 2;
    EXPECT_EQ(extract_ehf_signal(v2), std::nullopt);
    auto t8 = tx; t8.type = 8;
    EXPECT_EQ(extract_ehf_signal(t8), std::nullopt);
    auto tr = tx; tr.extra_payload.pop_back();
    EXPECT_EQ(extract_ehf_signal(tr), std::nullopt);
    auto tg = tx; tg.extra_payload.push_back(0);
    EXPECT_EQ(extract_ehf_signal(tg), std::nullopt);
    // IsTriviallyValid: version and bit range.
    p.nVersion = 2;
    EXPECT_FALSE(p.is_trivially_valid());
    p.nVersion = 1;
    p.signal.versionBit = 29;
    EXPECT_FALSE(p.is_trivially_valid());
}

// ── Versionbits state machine on synthetic chains ───────────────────────────

TEST(DashV24Deployments, DefinedUntilSignalThenStartedLockedInActive)
{
    SynthChain c;
    c.tip = 200;
    const auto p = fast_params(0);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    // Signal mined at 23 (inside the period 20..29): STARTED from 30.
    c.signal_range(30, 37);   // 8 of 10 in period 30..39 -> LOCKED_IN at 40
    EXPECT_EQ(vb.state_for(29, kNoSignalHeight), ThresholdState::DEFINED);
    EXPECT_EQ(vb.state_for(18, 23), ThresholdState::DEFINED);
    EXPECT_EQ(vb.state_for(28, 23), ThresholdState::DEFINED) << "prev 19 < signal 23";
    EXPECT_EQ(vb.state_for(29, 23), ThresholdState::STARTED) << "first block of period 30..39";
    EXPECT_EQ(vb.state_for(39, 23), ThresholdState::LOCKED_IN);
    EXPECT_EQ(vb.state_for(48, 23), ThresholdState::LOCKED_IN);
    EXPECT_EQ(vb.state_for(49, 23), ThresholdState::ACTIVE);
    EXPECT_EQ(vb.state_for(200, 23), ThresholdState::ACTIVE);
    EXPECT_EQ(vb.state_since_height(49, 23), std::optional<int64_t>(50));
    EXPECT_EQ(vb.state_since_height(39, 23), std::optional<int64_t>(40));
    EXPECT_EQ(vb.state_since_height(29, 23), std::optional<int64_t>(30));
    EXPECT_EQ(vb.state_since_height(10, 23), std::optional<int64_t>(0));
}

TEST(DashV24Deployments, SignalOnLastBlockOfPeriodStartsAtThatBoundary)
{
    SynthChain c;
    c.tip = 100;
    const auto p = fast_params(0);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    // Signal mined on 29, the last block of 20..29: prev 29 >= 29 -> STARTED at 30.
    EXPECT_EQ(vb.state_for(29, 29), ThresholdState::STARTED);
    EXPECT_EQ(vb.state_for(28, 29), ThresholdState::DEFINED);
    // Signal on 30 (first block of the next period): STARTED only at 40.
    EXPECT_EQ(vb.state_for(29, 30), ThresholdState::DEFINED);
    EXPECT_EQ(vb.state_for(39, 30), ThresholdState::STARTED);
}

TEST(DashV24Deployments, ThresholdJustReachesAndJustMisses)
{
    const auto p = fast_params(0);
    {   // 8 of 10 at attempt 0: reaches.
        SynthChain c; c.tip = 100;
        c.signal_range(31, 38);
        VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
        EXPECT_EQ(vb.state_for(39, 0), ThresholdState::LOCKED_IN);
    }
    {   // 7 of 10 at attempt 0: misses.
        SynthChain c; c.tip = 100;
        c.signal_range(31, 37);
        VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
        EXPECT_EQ(vb.state_for(39, 0), ThresholdState::STARTED);
    }
}

TEST(DashV24Deployments, FalloffReachesMinimumAfterTenAttempts)
{
    const auto p = fast_params(0);
    // Window 10, 8 falling to 6 in integer steps: 8 for a=0..7, 7 for a=8..9,
    // 6 from a=10 (8 - a*a*10/100/5).
    EXPECT_EQ(vb_threshold(p, p.dep(DashDeployment::V24), 7), 8);
    EXPECT_EQ(vb_threshold(p, p.dep(DashDeployment::V24), 8), 7);
    EXPECT_EQ(vb_threshold(p, p.dep(DashDeployment::V24), 9), 7);
    EXPECT_EQ(vb_threshold(p, p.dep(DashDeployment::V24), 10), 6);
    // STARTED at 10 (signal at 0, prev 9). 6 signalling blocks lock in only
    // at attempt 10: the period 110..119.
    SynthChain c; c.tip = 300;
    for (uint32_t s = 10; s <= 110; s += 10) c.signal_range(s, s + 5);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    EXPECT_EQ(vb.state_for(9, 0), ThresholdState::STARTED);
    EXPECT_EQ(vb.state_for(109, 0), ThresholdState::STARTED) << "a=9 needs 7";
    EXPECT_EQ(vb.state_for(119, 0), ThresholdState::LOCKED_IN) << "a=10 needs 6";
    EXPECT_EQ(vb.state_for(129, 0), ThresholdState::ACTIVE);
}

TEST(DashV24Deployments, StartTimeAndTimeout)
{
    SynthChain c; c.tip = 300;
    // Start time reached by the MTP of block ~105.
    auto p = fast_params(c.mtp(105));
    for (auto& d : p.deployments) d.nTimeout = c.mtp(150);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    EXPECT_EQ(vb.state_for(99, 0), ThresholdState::DEFINED) << "MTP(99) < start";
    EXPECT_EQ(vb.state_for(109, 0), ThresholdState::STARTED);
    // No signalling: FAILED at the first period end with MTP >= timeout.
    EXPECT_EQ(vb.state_for(149, 0), ThresholdState::STARTED);
    EXPECT_EQ(vb.state_for(159, 0), ThresholdState::FAILED);
    EXPECT_EQ(vb.state_for(300, 0), ThresholdState::FAILED);
}

TEST(DashV24Deployments, MissingHeaderIsUnknownNotAGuess)
{
    SynthChain c; c.tip = 50;
    const auto p = fast_params(0);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    EXPECT_EQ(vb.state_for(79, 0), std::nullopt);
}

TEST(DashV24Deployments, CacheFollowsReorgAndSignalHeight)
{
    SynthChain c; c.tip = 100;
    const auto p = fast_params(0);
    c.signal_range(31, 38);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    EXPECT_EQ(vb.state_for(39, 0), ThresholdState::LOCKED_IN);
    // Reorg: blocks 30..39 replaced by a branch that does not signal.
    for (uint32_t h = 30; h <= 100; ++h) { c.salt[h] = 1; c.version.erase(h); }
    EXPECT_EQ(vb.state_for(39, 0), ThresholdState::STARTED);
    // A different signal height is a different question (not a cache hit).
    EXPECT_EQ(vb.state_for(29, 35), ThresholdState::DEFINED);
    EXPECT_EQ(vb.state_for(39, 35), ThresholdState::STARTED);
    EXPECT_EQ(vb.state_for(39, 0), ThresholdState::STARTED);
}

TEST(DashV24Deployments, StatisticsLikeGetDeploymentInfo)
{
    SynthChain c; c.tip = 100;
    const auto p = fast_params(0);
    c.signal_range(31, 33);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    auto st = vb.statistics(34, 0);
    ASSERT_TRUE(st);
    EXPECT_EQ(st->period, 10);
    EXPECT_EQ(st->threshold, 8);
    EXPECT_EQ(st->elapsed, 5);
    EXPECT_EQ(st->count, 3);
    EXPECT_TRUE(st->possible);
}

// ── Testnet replay: the switch height from chain data ───────────────────────

namespace {

struct TestnetChain
{
    std::map<uint32_t, VbBlockInfo> blocks;

    TestnetChain()
    {
        using namespace dash_v24_tn_fixture;
        // Versions everywhere (default 0x20000000, the measured bit-13 ranges).
        for (uint32_t h = kFirstHeight; h <= kLastHeight; ++h) {
            VbBlockInfo b;
            b.nVersion = kVersionBitsTopBits;
            b.hash = height_hash(h, 0x7e57);
            blocks[h] = b;
        }
        for (const auto& r : kBit13Ranges)
            for (uint32_t h = r.from; h <= r.to; ++h) blocks[h].nVersion = 0x20002000;
        // Timestamps: the 11-block window of every period end.
        for (const auto& pe : kPeriodEnds)
            for (int i = 0; i < 11; ++i) blocks[pe.height - 10 + i].nTime = pe.times[i];
    }
    VbChainFn fn() const
    {
        return [this](uint32_t h) -> std::optional<VbBlockInfo> {
            auto it = blocks.find(h);
            if (it == blocks.end()) return std::nullopt;
            return it->second;
        };
    }
};

} // namespace

TEST(DashV24Deployments, TestnetMedianTimePastMatchesInsight)
{
    TestnetChain tc;
    auto fn = tc.fn();
    size_t n = 0;
    for (const auto& pe : dash_v24_tn_fixture::kPeriodEnds) {
        auto mtp = vb_median_time_past(fn, pe.height);
        ASSERT_TRUE(mtp) << pe.height;
        EXPECT_EQ(*mtp, pe.insight_mtp) << "h=" << pe.height;
        ++n;
    }
    EXPECT_EQ(n, 272u);
    // The first period end whose MTP reaches the testnet start time.
    const int64_t start = dash_deployment_params(DashNetwork::TESTNET).dep(DashDeployment::V24).nStartTime;
    EXPECT_LT(*vb_median_time_past(fn, 1'559'499), start);
    EXPECT_GE(*vb_median_time_past(fn, 1'559'599), start);
}

TEST(DashV24Deployments, TestnetReplayActivatesAt1578000)
{
    TestnetChain tc;
    DashDeploymentParams p = dash_deployment_params(DashNetwork::TESTNET);
    p.v24_buried_height.reset();
    // The MNHF signal block is not located yet (design §5.1: somewhere in
    // [1,559,509, 1,577,199]). Every admissible signal height must give the
    // measured switch: earliest (first block with MTP >= start), the middle,
    // and the last one that still starts by 1,577,200.
    // The real signal (VM504 getdeploymentinfo ehf_height) is 1,565,132.
    for (int64_t signal : {int64_t{1'559'509}, int64_t{1'565'132}, int64_t{1'567'000},
                           int64_t{1'577'150}, int64_t{1'577'199}}) {
        VersionBitsChecker vb(p, DashDeployment::V24, tc.fn());
        SCOPED_TRACE("signal=" + std::to_string(signal));
        EXPECT_EQ(vb.state_for(1'577'798, signal), ThresholdState::STARTED);
        EXPECT_EQ(vb.state_for(1'577'898, signal), ThresholdState::STARTED);
        EXPECT_EQ(vb.state_for(1'577'899, signal), ThresholdState::LOCKED_IN) << "block 1,577,900";
        EXPECT_EQ(vb.state_for(1'577'998, signal), ThresholdState::LOCKED_IN) << "block 1,577,999 (last CbTx v3)";
        EXPECT_EQ(vb.state_for(1'577'999, signal), ThresholdState::ACTIVE) << "block 1,578,000 (first CbTx v4)";
        EXPECT_EQ(vb.state_for(1'586'244, signal), ThresholdState::ACTIVE) << "tip";
        EXPECT_EQ(vb.state_since_height(1'577'999, signal), std::optional<int64_t>(1'578'000));
        EXPECT_EQ(vb.state_since_height(1'577'899, signal), std::optional<int64_t>(1'577'900));
        // The 1,567,1xx pre-release signalling (17, 53, 39 per window) never
        // reaches a threshold.
        EXPECT_NE(vb.state_for(1'567'399, signal), ThresholdState::LOCKED_IN);
    }
    // The real signal height, as Core reports it (VM504 getdeploymentinfo):
    // STARTED since 1,565,200, LOCKED_IN since 1,577,900, ACTIVE since
    // 1,578,000; the signal's own period stays DEFINED.
    {
        const int64_t S = 1'565'132;
        auto sig = [S](int64_t prev) { return prev >= S ? S : kNoSignalHeight; };
        VersionBitsChecker vb(p, DashDeployment::V24, tc.fn());
        EXPECT_EQ(vb.state_for(1'565'131, sig(1'565'131)), ThresholdState::DEFINED);
        EXPECT_EQ(vb.state_for(1'565'198, sig(1'565'198)), ThresholdState::DEFINED);
        EXPECT_EQ(vb.state_for(1'565'199, sig(1'565'199)), ThresholdState::STARTED);
        EXPECT_EQ(vb.state_since_height(1'565'199, S), std::optional<int64_t>(1'565'200));
        EXPECT_EQ(vb.state_since_height(1'577'898, S), std::optional<int64_t>(1'565'200));
        EXPECT_EQ(vb.state_since_height(1'577'899, S), std::optional<int64_t>(1'577'900));
        EXPECT_EQ(vb.state_since_height(1'577'999, S), std::optional<int64_t>(1'578'000));
        // getdeploymentinfo statistics at 1,577,898 / 1,577,899.
        auto st = vb.statistics(1'577'898, S);
        ASSERT_TRUE(st);
        EXPECT_EQ(st->elapsed, 99); EXPECT_EQ(st->count, 72); EXPECT_EQ(st->threshold, 60);
        EXPECT_TRUE(st->possible);
        st = vb.statistics(1'577'899, S);
        ASSERT_TRUE(st);
        EXPECT_EQ(st->elapsed, 100); EXPECT_EQ(st->count, 73); EXPECT_EQ(st->threshold, 80);
        EXPECT_FALSE(st->possible);
    }
    // 73 of 100 in 1,577,800..1,577,899 is exactly Threshold(6): STARTED must
    // be at or before 1,577,200. A signal one period later (STARTED at
    // 1,577,300, attempt 5 needs 75) misses, and activation would be
    // 1,578,100 -- contradicted by the first CbTx v4 at 1,578,000.
    {
        VersionBitsChecker vb(p, DashDeployment::V24, tc.fn());
        EXPECT_EQ(vb.state_for(1'577'899, 1'577'250), ThresholdState::STARTED);
        EXPECT_EQ(vb.state_for(1'577'999, 1'577'250), ThresholdState::LOCKED_IN);
        EXPECT_EQ(vb.state_for(1'578'099, 1'577'250), ThresholdState::ACTIVE);
    }
    // No signal at all: DEFINED forever, the bits notwithstanding.
    {
        VersionBitsChecker vb(p, DashDeployment::V24, tc.fn());
        EXPECT_EQ(vb.state_for(1'586'244, kNoSignalHeight), ThresholdState::DEFINED);
    }
    // evo_shares: no bit-14 signalling, so at best STARTED.
    {
        VersionBitsChecker vb(p, DashDeployment::EVO_SHARES, tc.fn());
        EXPECT_EQ(vb.state_for(1'586'199, 1'559'509), ThresholdState::STARTED);
    }
}

TEST(DashV24Deployments, TestnetBoundWithoutBodiesAndBlockVersion)
{
    // Headers only, no EHF scan: the bound (signal at 0) cannot rule out
    // activation at 1,578,000, so that height is UNKNOWN; 1,577,999 is
    // proven inactive.
    TestnetChain tc;
    DashDeploymentParams p = dash_deployment_params(DashNetwork::TESTNET);
    p.v24_buried_height.reset();
    DashDeploymentStatus st(p, tc.fn(), [] { return std::optional<uint32_t>(1'586'245); }, nullptr);
    EXPECT_EQ(st.v24_state(1'577'999), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(1'578'000), V24State::UNKNOWN);
    EXPECT_EQ(st.v24_state(1'560'000), V24State::INACTIVE);
    // No exact state, so no signalling bit is claimed.
    EXPECT_EQ(st.block_version(1'577'950), 0x20000000u);
    // The emergency pin decides where the computation cannot.
    st.set_v24_activation_override(1'578'000);
    EXPECT_EQ(st.v24_state(1'578'000), V24State::ACTIVE);
    EXPECT_EQ(st.v24_state(1'577'999), V24State::INACTIVE);
    // A pin that contradicts a decided height fails closed.
    st.set_v24_activation_override(1'577'900);
    EXPECT_EQ(st.v24_state(1'577'950), V24State::UNKNOWN) << "computed inactive, pin says active";
}

// VERIFY-H0-S0-S1 N5: the mainnet versionbits walk-back reads headers down to
// 2,564,341 (the period end 2,564,351, whose MTP is still before the v24 start
// time, minus the 10 extra headers of its median time past), and the EHF
// tracker scans bodies from its anchor. A header fast-start checkpoint above
// either would leave no headers to walk back over: every mainnet height would
// read UNKNOWN, before activation as well as after.
TEST(DashV24Deployments, FastStartCheckpointLeavesTheV24WalkBack)
{
    const auto cp = dash::coin::make_dash_chain_params_mainnet();
    ASSERT_TRUE(cp.fast_start_checkpoint.has_value());
    EXPECT_LE(cp.fast_start_checkpoint->height, 2'564'341u);
    EXPECT_LE(cp.fast_start_checkpoint->height,
              dash_deployment_params(DashNetwork::MAINNET).ehf_anchor_height);
}

TEST(DashV24Deployments, TestnetBuriedHeightIsTheS2Hook)
{
    // No status installed for testnet in this binary: the buried height.
    EXPECT_FALSE(v24_active(DashNetwork::TESTNET, 1'577'999));
    EXPECT_TRUE(v24_active(DashNetwork::TESTNET, 1'578'000));
    EXPECT_EQ(v24_state(DashNetwork::TESTNET, 1'577'999), V24State::INACTIVE);
    // Mainnet without a status: inactive below the earliest possible
    // activation, unknown from it.
    EXPECT_EQ(v24_state(DashNetwork::MAINNET, 2'580'479), V24State::INACTIVE);
    EXPECT_EQ(v24_state(DashNetwork::MAINNET, 2'580'480), V24State::UNKNOWN);
    EXPECT_FALSE(v24_active(DashNetwork::MAINNET, 2'580'480));
    EXPECT_FALSE(v24_active(DashNetwork::MAINNET, 4'000'000));
    EXPECT_FALSE(v24_active(DashNetwork::REGTEST, 1'000'000));
}

// ── EHF tracker ─────────────────────────────────────────────────────────────

TEST(DashV24Deployments, EhfTrackerRecordsSignalCoverageAndExpiry)
{
    SynthChain c; c.tip = 120;
    auto p = fast_params(c.mtp(20));   // start time = MTP of block 20
    EhfSignalTracker t(p, c.fn());
    EXPECT_FALSE(t.covers(0)) << "anchor 0 not scanned yet";
    for (uint32_t h = 0; h <= 60; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 10) extra.push_back(mnhf_tx(13));   // MTP(10) < start: expired
        if (h == 25) extra.push_back(mnhf_tx(14));   // valid, bit 14
        if (h == 33) extra.push_back(mnhf_tx(13));   // valid, bit 13
        ASSERT_TRUE(t.connect_block(block_at(c, h, extra), h, c.at(h)->hash)) << h;
    }
    EXPECT_EQ(t.scanned_to(), std::optional<uint32_t>(60));
    EXPECT_TRUE(t.covers(60));
    EXPECT_FALSE(t.covers(61));
    EXPECT_EQ(t.signal_height(13, 32), kNoSignalHeight) << "expired at 10, next at 33";
    EXPECT_EQ(t.signal_height(13, 33), 33);
    EXPECT_EQ(t.signal_height(13, 60), 33);
    EXPECT_EQ(t.signal_height(14, 60), 25);
    EXPECT_EQ(t.signals().size(), 3u);

    // Re-delivery and fork bodies change nothing; a gap does not extend.
    EXPECT_FALSE(t.connect_block(block_at(c, 50), 50, c.at(50)->hash));
    EXPECT_FALSE(t.connect_block(block_at(c, 61), 61, height_hash(61, 9)));
    EXPECT_FALSE(t.connect_block(block_at(c, 63), 63, c.at(63)->hash));
    EXPECT_EQ(t.scanned_to(), std::optional<uint32_t>(60));

    // Reorg below the bit-13 signal: the branch from 30 has no signal.
    for (uint32_t h = 30; h <= 120; ++h) c.salt[h] = 2;
    EXPECT_EQ(t.reconcile_with_chain(), std::optional<uint32_t>(29));
    EXPECT_EQ(t.signal_height(13, 60), kNoSignalHeight);
    EXPECT_EQ(t.signal_height(14, 60), 25) << "the signal below the fork stays";
    for (uint32_t h = 30; h <= 40; ++h)
        ASSERT_TRUE(t.connect_block(block_at(c, h), h, c.at(h)->hash)) << h;
    EXPECT_EQ(t.scanned_to(), std::optional<uint32_t>(40));
}

TEST(DashV24Deployments, EhfTrackerPersistenceRoundTrip)
{
    SynthChain c; c.tip = 80;
    auto p = fast_params(0);
    p.ehf_anchor_height = 5;
    EhfSignalTracker t(p, c.fn());
    for (uint32_t h = 0; h <= 70; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 42) extra.push_back(mnhf_tx(13));
        t.connect_block(block_at(c, h, extra), h, c.at(h)->hash);
    }
    EXPECT_EQ(t.scanned_to(), std::optional<uint32_t>(70)) << "bodies below the anchor are ignored";
    const std::string text = t.serialize();
    EhfSignalTracker u(p, c.fn());
    ASSERT_TRUE(u.deserialize(text)) << text;
    EXPECT_EQ(u.scanned_to(), std::optional<uint32_t>(70));
    EXPECT_EQ(u.signal_height(13, 70), 42);
    EXPECT_EQ(u.signals(), t.signals());
    // Another anchor or network is refused.
    auto q = p; q.ehf_anchor_height = 6;
    EhfSignalTracker w(q, c.fn());
    EXPECT_FALSE(w.deserialize(text));
    // A stale tip hash (the chain moved while we were down) cuts coverage
    // back to the deepest record still on the chain: the signal block.
    for (uint32_t h = 60; h <= 80; ++h) c.salt[h] = 3;
    EhfSignalTracker v(p, c.fn());
    ASSERT_TRUE(v.deserialize(text));
    EXPECT_EQ(v.scanned_to(), std::optional<uint32_t>(42));
    EXPECT_EQ(v.signal_height(13, 70), 42);
    // File round trip (on the original chain).
    c.salt.clear();
    const std::string path = ::testing::TempDir() + "ehf_signals_test.v1";
    ASSERT_TRUE(t.save(path));
    EhfSignalTracker f(p, c.fn());
    ASSERT_TRUE(f.load(path));
    EXPECT_EQ(f.scanned_to(), std::optional<uint32_t>(70));
    std::remove(path.c_str());
}

// ── Deployment status on a synthetic chain: exact, bound, beyond tip ────────

TEST(DashV24Deployments, StatusExactBoundAndBlockVersion)
{
    SynthChain c; c.tip = 200;
    auto p = fast_params(0);
    p.ehf_anchor_height = 0;
    c.signal_range(31, 38);   // locks in at 40 once STARTED at 30
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    uint32_t tip = 200;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);

    // Nothing scanned: bound only. With the signal at 0, STARTED at 10;
    // 31..38 lock in at 40, ACTIVE at 50 at the earliest.
    EXPECT_EQ(st.v24_state(49), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(50), V24State::UNKNOWN);
    EXPECT_EQ(st.block_version(35), 0x20000000u) << "no exact state, no bit";

    // Scan up to 60 with the signal mined at 23.
    for (uint32_t h = 0; h <= 60; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 23) extra.push_back(mnhf_tx(13));
        ASSERT_TRUE(t->connect_block(block_at(c, h, extra), h, c.at(h)->hash));
    }
    EXPECT_EQ(st.resolve(29, DashDeployment::V24).basis, std::string("exact"));
    EXPECT_EQ(st.resolve(29, DashDeployment::V24).state, ThresholdState::DEFINED);
    EXPECT_EQ(st.resolve(35, DashDeployment::V24).state, ThresholdState::STARTED);
    EXPECT_EQ(st.resolve(45, DashDeployment::V24).state, ThresholdState::LOCKED_IN);
    EXPECT_EQ(st.v24_state(49), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(50), V24State::ACTIVE);
    EXPECT_TRUE(st.v24_active(61)) << "parent 60 is covered";
    // Parent 61 is not scanned, but the signal at 23 is final (a later one
    // cannot be lower), so SignalHeight is decided for every later parent:
    // the state after the tip does not wait for the tip's own body (M3).
    EXPECT_EQ(st.v24_state(62), V24State::ACTIVE);
    EXPECT_EQ(st.resolve(62, DashDeployment::V24).basis, std::string("exact"));
    EXPECT_EQ(st.v24_state(150), V24State::ACTIVE);

    // Block version: bit 13 while STARTED or LOCKED_IN (Core GBT, gbt_force).
    EXPECT_EQ(st.block_version(25), 0x20000000u) << "DEFINED";
    EXPECT_EQ(st.block_version(35), 0x20002000u) << "STARTED";
    EXPECT_EQ(st.block_version(45), 0x20002000u) << "LOCKED_IN";
    EXPECT_EQ(st.block_version(55), 0x20000000u) << "ACTIVE";

    // Activation height known from the chain.
    tip = 60;
    EXPECT_EQ(st.activation_height(DashDeployment::V24), std::optional<uint32_t>(50));
}

TEST(DashV24Deployments, StatusBeyondTipFromPeriodBounds)
{
    SynthChain c; c.tip = 300;
    auto p = fast_params(0);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    uint32_t tip = 34;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    for (uint32_t h = 0; h <= 34; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 23) extra.push_back(mnhf_tx(13));
        t->connect_block(block_at(c, h, extra), h, c.at(h)->hash);
    }
    // Next block 35 is in a STARTED period (30..39): 40.. can lock in, 50..
    // can be active.
    EXPECT_EQ(st.resolve(35, DashDeployment::V24).state, ThresholdState::STARTED);
    EXPECT_EQ(st.v24_state(49), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(50), V24State::UNKNOWN);
    // Activation pinned by the operator for heights the chain cannot decide.
    st.set_v24_activation_override(50);
    EXPECT_EQ(st.v24_state(50), V24State::ACTIVE);
    st.set_v24_activation_override(40);
    EXPECT_EQ(st.v24_state(45), V24State::UNKNOWN) << "pin contradicts the STARTED bound";
}

TEST(DashV24Deployments, ActivationPinValidation)
{
    EXPECT_TRUE(validate_v24_activation_pin(DashNetwork::MAINNET, 2'580'480).empty());
    EXPECT_FALSE(validate_v24_activation_pin(DashNetwork::MAINNET, 2'580'481).empty());
    EXPECT_FALSE(validate_v24_activation_pin(DashNetwork::MAINNET, 0).empty());
    EXPECT_TRUE(validate_v24_activation_pin(DashNetwork::TESTNET, 1'578'000).empty());
    EXPECT_FALSE(validate_v24_activation_pin(DashNetwork::TESTNET, 1'578'050).empty());
}

// ── Cold-start rescan lane ──────────────────────────────────────────────────

TEST(DashV24Deployments, RescanLaneFillsFromAnchorBelowTheLiveFloor)
{
    SynthChain c; c.tip = 200;
    auto p = fast_params(0);
    p.ehf_anchor_height = 20;
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    std::optional<uint32_t> floor;   // live path not ready yet
    std::vector<std::vector<uint256>> sent;
    EhfRescanLane lane(t, c.fn(), [&] { return floor; },
                       [&](const std::vector<uint256>& hs) { sent.push_back(hs); return true; },
                       merkle_bound_only);
    EXPECT_EQ(lane.tick(0), 0u) << "idle without a live floor";

    floor = 120;   // the payee cursor sits at 119
    const size_t n = lane.tick(1000);
    EXPECT_EQ(n, EhfRescanLane::kWindow);
    ASSERT_FALSE(sent.empty());
    EXPECT_EQ(sent.front().front(), c.at(20)->hash) << "anchor first";
    EXPECT_EQ(sent.front().size(), EhfRescanLane::kBatch);
    EXPECT_EQ(lane.in_flight(), EhfRescanLane::kWindow);

    // A body nobody asked for is not claimed; out-of-order arrivals buffer.
    EXPECT_FALSE(lane.on_body(c.at(150)->hash, block_at(c, 150)));
    EXPECT_TRUE(lane.on_body(c.at(22)->hash, block_at(c, 22)));
    EXPECT_FALSE(t->scanned_to().has_value());
    EXPECT_TRUE(lane.on_body(c.at(20)->hash, block_at(c, 20)));
    EXPECT_TRUE(lane.on_body(c.at(21)->hash, block_at(c, 21, {mnhf_tx(13)})));
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(22));
    EXPECT_EQ(t->signal_height(13, 22), 21);

    // Unanswered asks are re-sent after kReaskMs; answered ones are not.
    sent.clear();
    EXPECT_EQ(lane.tick(1000 + EhfRescanLane::kReaskMs - 1), 3u) << "only the three newly opened slots";
    sent.clear();
    EXPECT_GT(lane.tick(1000 + EhfRescanLane::kReaskMs), 0u);

    // Deliver everything below the floor: the lane goes idle at floor - 1.
    for (int round = 0; round < 10; ++round) {
        lane.tick(100'000 + round * 30'000);
        for (uint32_t h = 23; h < 120; ++h) lane.on_body(c.at(h)->hash, block_at(c, h));
    }
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(119));
    sent.clear();
    EXPECT_EQ(lane.tick(1'000'000), 0u);
    EXPECT_TRUE(sent.empty());
    // From here the live feed extends coverage contiguously.
    EXPECT_TRUE(t->connect_block(block_at(c, 120), 120, c.at(120)->hash));
}

// ── Rescan bodies are bound to their headers (VERIFY-H0-S0-S1 M1) ────────────

TEST(DashV24Deployments, RescanLaneBindsEveryBodyToItsHeader)
{
    auto p = fast_params(0);
    X11Chain xc;
    xc.build(40, {{25, {mnhf_tx(13)}}});
    auto t = std::make_shared<EhfSignalTracker>(p, xc.fn());
    std::vector<uint256> asked;
    EhfRescanLane lane(t, xc.fn(), [] { return std::optional<uint32_t>(30); },
                       [&](const std::vector<uint256>& hs) {
                           asked.insert(asked.end(), hs.begin(), hs.end());
                           return true;
                       });   // production check: ehf_rescan_body_binds
    lane.tick(0);
    ASSERT_EQ(asked.size(), 30u);

    // The real body binds (merkle root and header hash).
    EXPECT_TRUE(ehf_rescan_body_binds(xc.hashes[0], xc.blocks[0]));
    EXPECT_TRUE(lane.on_body(xc.hashes[0], xc.blocks[0]));
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(0));

    // Body 1 with a planted MNHF tx under the real header: merkle mismatch.
    BlockType planted = xc.blocks[1];
    planted.m_txs.push_back(mnhf_tx(13));
    EXPECT_FALSE(ehf_rescan_body_binds(xc.hashes[1], planted));
    EXPECT_TRUE(lane.on_body(xc.hashes[1], planted)) << "claimed (we asked for it), not kept";
    EXPECT_EQ(lane.rejected(), 1u);
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(0));
    EXPECT_TRUE(t->signals().empty());

    // A self-consistent forged block (its own header commits its txs) under
    // the requested hash: the header is not ours.
    BlockType forged = xc.blocks[1];
    forged.m_txs.push_back(mnhf_tx(13));
    bind_body(forged);
    EXPECT_FALSE(ehf_rescan_body_binds(xc.hashes[1], forged));
    EXPECT_TRUE(lane.on_body(xc.hashes[1], forged));
    EXPECT_EQ(lane.rejected(), 2u);
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(0));

    // Body 25 WITHOUT its signal tx under the real header: refused, so the
    // tracker can never be told "no signal here".
    BlockType omitted = xc.blocks[25];
    omitted.m_txs.pop_back();
    EXPECT_FALSE(ehf_rescan_body_binds(xc.hashes[25], omitted));

    // A refused height is re-asked at the very next tick (not after 20 s).
    asked.clear();
    lane.tick(1);
    EXPECT_EQ(asked.size(), 1u);
    EXPECT_EQ(asked.front(), xc.hashes[1]);

    // The real bodies fill the range and the real signal is found.
    for (uint32_t h = 1; h < 30; ++h) EXPECT_TRUE(lane.on_body(xc.hashes[h], xc.blocks[h]));
    EXPECT_EQ(t->scanned_to(), std::optional<uint32_t>(29));
    EXPECT_EQ(t->signal_height(13, 29), 25);
    EXPECT_EQ(lane.rejected(), 2u);
}

// ── Coverage is checked against the chain view ──────────────────────────────

TEST(DashV24Deployments, VerifiedCoverageFollowsAHeaderReorgBeforeAnyBody)
{
    SynthChain c; c.tip = 60;
    auto p = fast_params(0);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 40; ++h) {
        std::vector<MutableTransaction> extra;
        if (h == 33) extra.push_back(mnhf_tx(13));
        ASSERT_TRUE(t->connect_block(block_at(c, h, extra), h, c.at(h)->hash));
    }
    EXPECT_EQ(t->verified_coverage(), 40);
    // The header chain switches at 30 (no body of the new branch yet): the
    // recorded bodies above 29 are not on the chain any more, and neither is
    // the signal at 33.
    for (uint32_t h = 30; h <= 60; ++h) c.salt[h] = 9;
    EXPECT_EQ(t->verified_coverage(), 29);
    uint32_t tip = 60;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_NE(st.resolve(50, DashDeployment::V24).basis, std::string("exact"))
        << "the old branch's signal must not decide the new branch";
    // Nothing scanned at all: anchor - 1.
    auto t2 = std::make_shared<EhfSignalTracker>(p, c.fn());
    EXPECT_EQ(t2->verified_coverage(), -1);
}

// ── The real testnet MNHF transaction (block 1,565,132) ─────────────────────

TEST(DashV24Deployments, RealTestnetMnhfSignalTx)
{
    // VM504 getrawtransaction 46a47fe6..., mined in testnet block 1,565,132.
    const std::string hex =
        "0300070000000000000082010dfab03beecae3ec79691a966f8a37a836dab21a409f1ee39bfe98a26f"
        "03000000a3520c90ae1a3aa2b750be245cb9eaa1c4be78f0ee43f46b56a0d319cae9e76a87c5ce23d9"
        "3e24b7484b93288bdbc7e70610d04c7d9ba4f30dc3b71b58baf6436752ffbace4c79da3e4d6de8764"
        "6610a8cff9001b51d768c4b6d8a4ddda6f01c";
    std::vector<unsigned char> raw;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        raw.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    MutableTransaction tx;
    ::PackStream ps(raw);
    ps >> tx;
    EXPECT_TRUE(ps.empty());
    EXPECT_EQ(tx.type, 7);
    EXPECT_EQ(extract_ehf_signal(tx), std::optional<uint8_t>(13));
    auto packed = ::pack(tx);
    EXPECT_EQ(::Hash(packed.get_span()).GetHex().substr(0, 16), "46a47fe65c9fd29e");
}

// ── Live cross-check latch (VERIFY-H0-S0-S1 M2) ─────────────────────────────

namespace {
// Chain with bit-13 signalling 30..39 and the MNHF signal at 25: Core is
// STARTED 30, LOCKED_IN 40, ACTIVE 50.
struct LatchFixture
{
    SynthChain c;
    DashDeploymentParams p = fast_params(0);
    std::shared_ptr<EhfSignalTracker> t;
    uint32_t tip{120};
    std::unique_ptr<DashDeploymentStatus> st;
    explicit LatchFixture(bool with_signal)
    {
        c.tip = 120;
        c.signal_range(30, 39);
        t = std::make_shared<EhfSignalTracker>(p, c.fn());
        for (uint32_t h = 0; h <= 120; ++h) {
            std::vector<MutableTransaction> x;
            if (with_signal && h == 25) x.push_back(mnhf_tx(13));
            t->connect_block(block_at(c, h, x), h, c.at(h)->hash);
        }
        st = std::make_unique<DashDeploymentStatus>(
            p, c.fn(), [this] { return std::optional<uint32_t>(tip); }, t);
    }
};
} // namespace

TEST(DashV24Deployments, CrossCheckAgreesWithTheChain)
{
    LatchFixture f(true);
    EXPECT_EQ(f.st->cross_check_cbtx_version(45, f.c.at(45)->hash, 3), V24CrossCheck::AGREE);
    EXPECT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::AGREE);
    EXPECT_EQ(f.st->latch(), V24Latch::NONE);
    // A block that is not our chain's block at that height is not compared.
    EXPECT_EQ(f.st->cross_check_cbtx_version(55, height_hash(55, 7), 3), V24CrossCheck::UNDECIDED);
    EXPECT_EQ(f.st->latch(), V24Latch::NONE);
    EXPECT_EQ(f.st->contradictions(), 0u);
}

TEST(DashV24Deployments, CrossCheckContradictionLatchesFailClosed)
{
    // The tracker missed the signal (as a forged rescan body could make it):
    // decided INACTIVE where the chain says v4 (ACTIVE).
    LatchFixture f(false);
    ASSERT_EQ(f.st->v24_state(55), V24State::INACTIVE);
    EXPECT_EQ(f.st->resolve(55, DashDeployment::V24).basis, std::string("exact"));
    EXPECT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::CONTRADICTS);
    EXPECT_EQ(f.st->latch(), V24Latch::EXACT);
    // Fail closed: no tracker-derived answer any more. The header-only bound
    // (signal at 0: STARTED 10, LOCKED_IN 40, ACTIVE 50) still proves 45 and
    // below inactive; 50 on is UNKNOWN.
    EXPECT_EQ(f.st->v24_state(55), V24State::UNKNOWN);
    EXPECT_EQ(f.st->resolve(55, DashDeployment::V24).basis, std::string("cross-check-latch"));
    EXPECT_EQ(f.st->v24_state(100), V24State::UNKNOWN);
    EXPECT_EQ(f.st->v24_state(45), V24State::INACTIVE);
    EXPECT_EQ(f.st->resolve(45, DashDeployment::V24).basis, std::string("bound"));
    EXPECT_EQ(f.st->block_version(45), 0x20000000u) << "no signalling from a refuted state";
    EXPECT_EQ(f.st->activation_height(DashDeployment::V24), std::nullopt);
    // Further v4 blocks: still latched (the recomputed state still disagrees).
    EXPECT_EQ(f.st->cross_check_cbtx_version(56, f.c.at(56)->hash, 4), V24CrossCheck::UNDECIDED);
    EXPECT_EQ(f.st->latch(), V24Latch::EXACT);
    // The operator pin decides under the latch.
    f.st->set_v24_activation_override(50);
    EXPECT_EQ(f.st->v24_state(55), V24State::ACTIVE);
    EXPECT_EQ(f.st->resolve(55, DashDeployment::V24).basis, std::string("override"));
    EXPECT_EQ(f.st->cross_check_cbtx_version(57, f.c.at(57)->hash, 4), V24CrossCheck::AGREE);
}

TEST(DashV24Deployments, CrossCheckRefutingTheBoundLatchesEverything)
{
    // No tracker at all (bound only): the bound says 45 is INACTIVE. A v4
    // block at 45 refutes the bound itself.
    SynthChain c; c.tip = 120;
    c.signal_range(30, 39);
    auto p = fast_params(0);
    uint32_t tip = 120;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, nullptr);
    ASSERT_EQ(st.v24_state(45), V24State::INACTIVE);
    EXPECT_EQ(st.cross_check_cbtx_version(45, c.at(45)->hash, 4), V24CrossCheck::CONTRADICTS);
    EXPECT_EQ(st.latch(), V24Latch::BOUND);
    EXPECT_EQ(st.v24_state(45), V24State::UNKNOWN);
    EXPECT_EQ(st.v24_state(20), V24State::UNKNOWN);
}

TEST(DashV24Deployments, CrossCheckEscalatesWhenTheFallbackIsRefutedToo)
{
    // Tracker without the signal says INACTIVE at 45 (exact); the bound says
    // INACTIVE at 45 too. A v4 block at 45 refutes both in one check.
    LatchFixture f(false);
    EXPECT_EQ(f.st->cross_check_cbtx_version(45, f.c.at(45)->hash, 4), V24CrossCheck::CONTRADICTS);
    EXPECT_EQ(f.st->latch(), V24Latch::BOUND);
    EXPECT_EQ(f.st->v24_state(45), V24State::UNKNOWN);
}

TEST(DashV24Deployments, CrossCheckRefutedPinIsIgnored)
{
    SynthChain c; c.tip = 120;
    auto p = fast_params(0);
    uint32_t tip = 120;
    // Bound only, with signalling the bound cannot rule out (ACTIVE possible
    // from 50), so the pin decides 60.
    c.signal_range(30, 39);
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, nullptr);
    ASSERT_EQ(st.v24_state(60), V24State::UNKNOWN);
    st.set_v24_activation_override(60);
    ASSERT_EQ(st.v24_state(60), V24State::ACTIVE);
    // The chain says v3 at 60: the pin is wrong.
    EXPECT_EQ(st.cross_check_cbtx_version(60, c.at(60)->hash, 3), V24CrossCheck::CONTRADICTS);
    EXPECT_TRUE(st.pin_refuted());
    EXPECT_EQ(st.v24_state(60), V24State::UNKNOWN);
    // Setting a pin again (operator action) re-arms it.
    st.set_v24_activation_override(70);
    EXPECT_FALSE(st.pin_refuted());
    EXPECT_EQ(st.v24_state(60), V24State::INACTIVE);
}

TEST(DashV24Deployments, CrossCheckLatchClearsWhenTheRecomputedStateAgrees)
{
    // The tracker held a stale branch without the signal; the chain says v4.
    LatchFixture f(false);
    EXPECT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::CONTRADICTS);
    ASSERT_EQ(f.st->latch(), V24Latch::EXACT);
    // The tracker is corrected: block 25 with its signal on a new branch
    // (the chain view switches at 25 and the bodies are re-fed).
    for (uint32_t h = 25; h <= 120; ++h) f.c.salt[h] = 3;
    for (uint32_t h = 25; h <= 120; ++h) {
        std::vector<MutableTransaction> x;
        if (h == 25) x.push_back(mnhf_tx(13));
        f.t->connect_block(block_at(f.c, h, x), h, f.c.at(h)->hash);
    }
    ASSERT_EQ(f.t->signal_height(13, 120), 25);
    // The next block agrees, and the latched height recomputes to what the
    // chain said there: the latch clears.
    EXPECT_EQ(f.st->cross_check_cbtx_version(56, f.c.at(56)->hash, 4), V24CrossCheck::AGREE);
    EXPECT_EQ(f.st->latch(), V24Latch::NONE);
    EXPECT_EQ(f.st->v24_state(55), V24State::ACTIVE);
}

TEST(DashV24Deployments, ShutdownStopsReadingTheChain)
{
    LatchFixture f(true);
    ASSERT_EQ(f.st->v24_state(55), V24State::ACTIVE);
    f.st->shutdown();
    EXPECT_EQ(f.st->v24_state(55), V24State::UNKNOWN);
    EXPECT_EQ(f.st->block_version(35), 0x20000000u);
    EXPECT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::UNDECIDED);
}

// ── Decidability before the tip body (VERIFY-H0-S0-S1 M3) ───────────────────

TEST(DashV24Deployments, StateBeforeTheSignalIsFoundDecidedOffPeriodEnds)
{
    // No signal yet anywhere; tracker covers 0..34, header tip 35. Block 36
    // (parent 35) has no period end in (34, 35]: the signal height is "none"
    // for it and the state is exact. Block 41 (parent 40) has the period end
    // 39 in (34, 40]: a signal in 35..39 would matter -> not exact.
    SynthChain c; c.tip = 60;
    auto p = fast_params(0);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 34; ++h) ASSERT_TRUE(t->connect_block(block_at(c, h), h, c.at(h)->hash));
    uint32_t tip = 60;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_EQ(st.resolve(36, DashDeployment::V24).basis, std::string("exact"));
    EXPECT_EQ(st.resolve(36, DashDeployment::V24).state, ThresholdState::DEFINED);
    EXPECT_NE(st.resolve(41, DashDeployment::V24).basis, std::string("exact"));
    EXPECT_EQ(st.v24_state(41), V24State::INACTIVE) << "bound";
}

// ═════ The verifier's adversarial KATs (VERIFY-H0-S0-S1 §6): the seven that
// failed on the S1 head, now passing. Expectations are Dash Core v24.0.0's
// answers (versionbits.cpp, mnhftx.cpp) or an independent pure reference.

namespace {

uint256 hh(uint32_t h, uint32_t salt = 0)
{
    uint256 x;
    for (int i = 0; i < 4; ++i) x.data()[i] = static_cast<uint8_t>(h >> (8 * i));
    for (int i = 0; i < 4; ++i) x.data()[4 + i] = static_cast<uint8_t>(salt >> (8 * i));
    x.data()[31] = 0xa5;
    return x;
}

// Synthetic chain (one block every 150 s, or explicit times).
struct Synth
{
    uint32_t t0{1'800'000'000};
    std::map<uint32_t, int32_t> ver;
    std::map<uint32_t, uint32_t> salt;
    std::map<uint32_t, uint32_t> tm;
    uint32_t tip{0};
    std::optional<VbBlockInfo> at(uint32_t h) const
    {
        if (h > tip) return std::nullopt;
        VbBlockInfo i;
        auto v = ver.find(h);
        i.nVersion = v == ver.end() ? kVersionBitsTopBits : v->second;
        auto t = tm.find(h);
        i.nTime = t == tm.end() ? t0 + 150 * h : t->second;
        auto s = salt.find(h);
        i.hash = hh(h, s == salt.end() ? 0 : s->second);
        return i;
    }
    VbChainFn fn() const { return [this](uint32_t h) { return at(h); }; }
    void sig(uint32_t a, uint32_t z) { for (uint32_t h = a; h <= z; ++h) ver[h] = 0x20002000; }
};

DashDeploymentParams fast(int64_t start, int64_t P = 10, int64_t thr = 8, int64_t thrmin = 6)
{
    DashDeploymentParams p = dash_deployment_params(DashNetwork::REGTEST);
    for (auto& d : p.deployments) {
        d.nStartTime = start;
        d.nTimeout = Bip9Deployment::NO_TIMEOUT;
        d.nWindowSize = P;
        d.nThresholdStart = thr;
        d.nThresholdMin = thrmin;
        d.nFalloffCoeff = 5;
    }
    p.min_bip9_warning_height = 0;
    p.v20_height = 0;
    p.ehf_anchor_height = 0;
    p.v24_buried_height.reset();
    return p;
}

MutableTransaction mnhf(uint8_t bit) { return mnhf_tx(bit); }

// An UNBOUND body (header merkle root zero), as a lying peer would serve it.
BlockType body(const Synth& c, uint32_t h, std::vector<MutableTransaction> extra = {})
{
    BlockType b;
    if (h > 0) b.m_previous_block = c.at(h - 1)->hash;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    b.m_txs.push_back(cb);
    for (auto& t : extra) b.m_txs.push_back(std::move(t));
    return b;
}

// Independent reference: Core GetStateFor as a pure forward function. No
// cache. SignalHeight from the stage at the query's pindexPrev; a period end
// E leaves DEFINED when MTP(E) >= start && E >= S; nAttempt = (E - nStart)/P.
struct RefVb
{
    const DashDeploymentParams& p;
    const Bip9Deployment& d;
    VbChainFn chain;
    std::optional<int64_t> mtp(int64_t h) const { return vb_median_time_past(chain, h); }
    std::optional<ThresholdState> state(int64_t prev, int64_t S) const
    {
        const int64_t P = vb_period(p, d);
        if (prev < 0) return ThresholdState::DEFINED;
        const int64_t top = prev - ((prev + 1) % P);
        ThresholdState s = ThresholdState::DEFINED;
        int64_t nStart = -1;
        for (int64_t E = P - 1; E <= top; E += P) {
            if (E < p.min_bip9_warning_height) { s = ThresholdState::DEFINED; continue; }
            auto m = mtp(E);
            if (!m) return std::nullopt;
            switch (s) {
            case ThresholdState::DEFINED:
                if (*m >= d.nStartTime && E >= S) { s = ThresholdState::STARTED; nStart = E + 1; }
                break;
            case ThresholdState::STARTED: {
                int64_t cnt = 0;
                for (int64_t h = E - P + 1; h <= E; ++h) {
                    auto bi = chain(static_cast<uint32_t>(h));
                    if (!bi) return std::nullopt;
                    if (vb_signals(bi->nVersion, d)) ++cnt;
                }
                const int64_t thr = vb_threshold(p, d, (E - nStart) / P);
                if (cnt >= thr) s = ThresholdState::LOCKED_IN;
                else if (*m >= d.nTimeout) s = ThresholdState::FAILED;
                break;
            }
            case ThresholdState::LOCKED_IN:
                if (E + 1 >= d.min_activation_height) s = ThresholdState::ACTIVE;
                break;
            default: break;
            }
        }
        return s;
    }
};

} // namespace

// M4: signal at 25 (mid-period 20..29). Core: STARTED 30, LOCKED_IN 40,
// ACTIVE 50. A query for block 23 (prev 22 < S: the tracker answers "no
// signal") after a query that cached the STARTED run must not change any
// later answer.
TEST(DashV24VerifyFold, CacheMustNotBePoisonedByAQueryBelowTheSignal)
{
    Synth c; c.tip = 120;
    auto p = fast(0);
    c.sig(30, 39);
    VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
    const int64_t S = 25;
    EXPECT_EQ(vb.state_for(35, S), ThresholdState::STARTED);
    EXPECT_EQ(vb.state_for(22, kNoSignalHeight), ThresholdState::DEFINED);   // block 23
    EXPECT_EQ(vb.state_for(45, S), ThresholdState::LOCKED_IN) << "poisoned cache => nullopt";
    EXPECT_EQ(vb.state_for(55, S), ThresholdState::ACTIVE) << "poisoned cache => nullopt";
}

// M4 through DashDeploymentStatus + tracker.
TEST(DashV24VerifyFold, StatusStaysDecidableAfterAHistoricalQuery)
{
    Synth c; c.tip = 120;
    auto p = fast(0);
    c.sig(30, 39);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 120; ++h) {
        std::vector<MutableTransaction> x;
        if (h == 25) x.push_back(mnhf(13));
        ASSERT_TRUE(t->connect_block(body(c, h, x), h, c.at(h)->hash));
    }
    uint32_t tip = 120;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_EQ(st.v24_state(36), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(23), V24State::INACTIVE);
    EXPECT_EQ(st.v24_state(50), V24State::ACTIVE);
    EXPECT_EQ(st.v24_state(100), V24State::ACTIVE);
}

// M3: with the tracker covering T-1 (body T not yet in), v24 is still
// exactly ACTIVE for T+1.
TEST(DashV24VerifyFold, ActiveIsDecidableBeforeTheTipBodyArrives)
{
    Synth c; c.tip = 100;
    auto p = fast(0);
    c.sig(30, 39);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 99; ++h) {   // body 100 not yet connected
        std::vector<MutableTransaction> x;
        if (h == 25) x.push_back(mnhf(13));
        ASSERT_TRUE(t->connect_block(body(c, h, x), h, c.at(h)->hash));
    }
    uint32_t tip = 100;   // header 100 is in
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_EQ(st.v24_state(100), V24State::ACTIVE) << "parent 99 covered";
    EXPECT_EQ(st.v24_state(101), V24State::ACTIVE)
        << "post-activation every new header tip must not read UNKNOWN until its body is scanned";
}

// SF1: block_version at the header tip, before the tip body reaches the
// tracker: STARTED must still set bit 13.
TEST(DashV24VerifyFold, BlockVersionSignalsAtHeaderTipBeforeBody)
{
    Synth c; c.tip = 35;
    auto p = fast(0);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 34; ++h) {   // header 35 in, body not yet
        std::vector<MutableTransaction> x;
        if (h == 25) x.push_back(mnhf(13));
        ASSERT_TRUE(t->connect_block(body(c, h, x), h, c.at(h)->hash));
    }
    uint32_t tip = 35;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_EQ(st.block_version(35), 0x20002000u) << "covered parent";
    EXPECT_EQ(st.block_version(36), 0x20002000u)
        << "main_dash tip-advance: ta->version = block_version(tip+1) before body(tip) is scanned";
}

// M1: a forged rescan body with a fake signal is refused.
TEST(DashV24VerifyFold, RescanLaneRefusesAForgedBodyWithAFakeSignal)
{
    Synth c; c.tip = 200;
    auto p = fast(0);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    std::vector<uint256> asked;
    EhfRescanLane lane(t, c.fn(), [] { return std::optional<uint32_t>(150); },
                       [&](const std::vector<uint256>& hs) { asked.insert(asked.end(), hs.begin(), hs.end()); return true; });
    lane.tick(0);
    ASSERT_FALSE(asked.empty());
    BlockType forged = body(c, 0, {mnhf(13)});
    ASSERT_FALSE(block_body_binds_to_header(forged));
    lane.on_body(c.at(0)->hash, forged);
    EXPECT_TRUE(t->signals().empty()) << "a forged body planted an EHF signal at h=0";
    EXPECT_FALSE(t->scanned_to().has_value()) << "a forged body extended coverage";
}

// M1: bodies that omit the real signal cannot decide INACTIVE.
TEST(DashV24VerifyFold, RescanLaneRefusesABodyThatOmitsTheRealSignal)
{
    Synth c; c.tip = 200;
    auto p = fast(0);
    c.sig(30, 39);
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    std::vector<uint256> asked;
    EhfRescanLane lane(t, c.fn(), [] { return std::optional<uint32_t>(120); },
                       [&](const std::vector<uint256>& hs) { asked.insert(asked.end(), hs.begin(), hs.end()); return true; });
    for (int round = 0; round < 4; ++round) {
        lane.tick(round * 100'000);
        const uint32_t from = t->next_needed_height();
        for (uint32_t h = from; h < from + EhfRescanLane::kWindow && h < 120; ++h)
            lane.on_body(c.at(h)->hash, body(c, h));   // never carries the signal; unbound
    }
    uint32_t tip = 119;
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_NE(st.v24_state(60), V24State::INACTIVE)
        << "unbound rescan bodies -> decided INACTIVE after Core activation (v3 CbTx on a v24 chain)";
}

// M4: randomized differential against the pure reference, non-monotone
// queries; no wrong decided state and no unknown on a fully known chain.
TEST(DashV24VerifyFold, DifferentialFuzzAgainstPureReference)
{
    std::mt19937_64 rng(0xD45A24);
    int checked = 0, mismatches = 0, unknown = 0;
    for (int iter = 0; iter < 300; ++iter) {
        Synth c; c.tip = 400;
        uint32_t t = 1'800'000'000;
        for (uint32_t h = 0; h <= c.tip; ++h) { t += 30 + rng() % 400; c.tm[h] = t; }
        const int64_t P = 10 + rng() % 3 * 5;   // 10, 15, 20
        const int64_t thr = P * 8 / 10, thrmin = P * 6 / 10;
        const int64_t start = c.tm[20 + rng() % 60];
        auto p = fast(start, P, thr, thrmin);
        if (rng() % 4 == 0) for (auto& d : p.deployments) d.nTimeout = c.tm[200 + rng() % 150];
        const double dens = (rng() % 100) / 100.0;
        for (uint32_t h = 0; h <= c.tip; ++h) if ((rng() % 1000) / 1000.0 < dens) c.ver[h] = 0x20002000;
        const int64_t S = rng() % 3 == 0 ? kNoSignalHeight : static_cast<int64_t>(rng() % 300);
        auto sigq = [S](int64_t prev) { return prev >= S ? S : kNoSignalHeight; };
        VersionBitsChecker vb(p, DashDeployment::V24, c.fn());
        RefVb ref{p, p.dep(DashDeployment::V24), c.fn()};
        for (int q = 0; q < 60; ++q) {
            const int64_t prev = rng() % (c.tip + 1);
            auto a = vb.state_for(prev, sigq(prev));
            auto b = ref.state(prev, sigq(prev));
            ++checked;
            if (!a) { ++unknown; continue; }
            if (*a != *b) ++mismatches;
        }
    }
    EXPECT_EQ(mismatches, 0) << "wrong decided states vs Core reference";
    EXPECT_EQ(unknown, 0) << "nullopt from a fully known chain (cache poisoning) out of " << checked;
}

// The status (tracker + exact/bound + decided-before-body rule) against the
// pure reference with the tracker lagging the header tip by 0..25 blocks and
// random query order: a decided answer is never wrong.
TEST(DashV24VerifyFold, StatusDecidedAnswersMatchTheReferenceUnderTrackerLag)
{
    std::mt19937_64 rng(0x24E4F);
    int decided = 0, wrong = 0;
    for (int iter = 0; iter < 150; ++iter) {
        Synth c; c.tip = 300;
        const int64_t P = 10;
        auto p = fast(c.t0 + 150 * (5 + rng() % 40), P, 8, 6);
        const double dens = (rng() % 100) / 100.0;
        for (uint32_t h = 0; h <= c.tip; ++h) if ((rng() % 1000) / 1000.0 < dens) c.ver[h] = 0x20002000;
        const bool mined = rng() % 4 != 0;
        const uint32_t S = static_cast<uint32_t>(rng() % 250);
        // GetSignalsStage drops a signal whose block MTP is before the start.
        const bool has_signal = mined && *vb_median_time_past(c.fn(), S) >= p.dep(DashDeployment::V24).nStartTime;
        auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
        const uint32_t covered = static_cast<uint32_t>(rng() % 300);
        for (uint32_t h = 0; h <= covered; ++h) {
            std::vector<MutableTransaction> x;
            if (mined && h == S) x.push_back(mnhf(13));
            ASSERT_TRUE(t->connect_block(body(c, h, x), h, c.at(h)->hash));
        }
        uint32_t tip = std::min<uint32_t>(c.tip, covered + static_cast<uint32_t>(rng() % 26));
        DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
        RefVb ref{p, p.dep(DashDeployment::V24), c.fn()};
        for (int q = 0; q < 40; ++q) {
            const uint32_t h = 1 + static_cast<uint32_t>(rng() % (tip + 1));
            const int64_t prev = static_cast<int64_t>(h) - 1;
            const int64_t sq = (has_signal && prev >= S) ? S : kNoSignalHeight;
            const auto truth = ref.state(prev, sq);
            ASSERT_TRUE(truth);
            const V24State want = *truth == ThresholdState::ACTIVE ? V24State::ACTIVE : V24State::INACTIVE;
            const auto r = st.resolve(h, DashDeployment::V24);
            if (r.active == V24State::UNKNOWN) continue;
            ++decided;
            if (r.active != want) ++wrong;
            if (r.state) EXPECT_EQ(*r.state, *truth) << "h=" << h << " basis " << r.basis;
        }
    }
    EXPECT_EQ(wrong, 0);
    EXPECT_GT(decided, 1000);
}

// VERIFY-H0-S0-S1 N6: the cross-check latch survives a restart.
TEST(DashV24Deployments, CrossCheckLatchSurvivesARestart)
{
    LatchFixture f(false);
    const uint64_t v0 = f.st->latch_version();
    ASSERT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::CONTRADICTS);
    EXPECT_GT(f.st->latch_version(), v0);
    const std::string rec = f.st->serialize_latch();
    // A fresh status (a restarted node) loads it and stays fail closed.
    DashDeploymentStatus again(f.p, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
    ASSERT_TRUE(again.deserialize_latch(rec));
    EXPECT_EQ(again.latch(), f.st->latch());
    EXPECT_EQ(again.v24_state(55), V24State::UNKNOWN);
    EXPECT_EQ(again.contradictions(), f.st->contradictions());
    // Another network's record, or garbage, is refused.
    DashDeploymentStatus testnet(DashNetwork::TESTNET, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
    EXPECT_FALSE(testnet.deserialize_latch(rec));
    EXPECT_FALSE(again.deserialize_latch("v24_latch v1 x"));
    // A refuted pin stays refuted only for the same pin.
    SynthChain c; c.tip = 120; c.signal_range(30, 39);
    auto p = fast_params(0);
    uint32_t tip = 120;
    DashDeploymentStatus s1(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, nullptr);
    s1.set_v24_activation_override(60);
    ASSERT_EQ(s1.cross_check_cbtx_version(60, c.at(60)->hash, 3), V24CrossCheck::CONTRADICTS);
    ASSERT_TRUE(s1.pin_refuted());
    const std::string prec = s1.serialize_latch();
    DashDeploymentStatus same(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, nullptr);
    same.set_v24_activation_override(60);
    ASSERT_TRUE(same.deserialize_latch(prec));
    EXPECT_TRUE(same.pin_refuted());
    DashDeploymentStatus other(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, nullptr);
    other.set_v24_activation_override(70);
    ASSERT_TRUE(other.deserialize_latch(prec));
    EXPECT_FALSE(other.pin_refuted()) << "a different pin is a new operator decision";
}

// The latch is bound to the block that set it: it clears once that block is
// no longer on our best chain (reorged out, orphaned), never while it is.
TEST(DashV24Deployments, CrossCheckLatchClearsWhenItsBlockIsOrphaned)
{
    LatchFixture f(false);   // no signal: v24 never active on this chain
    ASSERT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::CONTRADICTS);
    ASSERT_NE(f.st->latch(), V24Latch::NONE);
    // The disagreeing block stays on the best chain: later agreeing blocks
    // do not clear it, nor does a revalidation.
    for (uint32_t h = 56; h <= 60; ++h) f.st->cross_check_cbtx_version(h, f.c.at(h)->hash, 3);
    f.st->revalidate_latch();
    EXPECT_NE(f.st->latch(), V24Latch::NONE) << "the disagreeing block is still on our chain";
    EXPECT_EQ(f.st->v24_state(61), V24State::UNKNOWN);
    // It is reorged out: the next cross-check (or a revalidation) clears it.
    f.c.salt[55] = 0x55;
    const uint64_t v = f.st->latch_version();
    EXPECT_EQ(f.st->cross_check_cbtx_version(61, f.c.at(61)->hash, 3), V24CrossCheck::AGREE);
    EXPECT_EQ(f.st->latch(), V24Latch::NONE);
    EXPECT_GT(f.st->latch_version(), v) << "the node persists the change";
    EXPECT_EQ(f.st->v24_state(61), V24State::INACTIVE);
}

TEST(DashV24Deployments, CrossCheckLatchRecordKnowsItsBlockAcrossARestart)
{
    LatchFixture f(false);
    ASSERT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 4), V24CrossCheck::CONTRADICTS);
    const std::string rec = f.st->serialize_latch();
    EXPECT_EQ(rec.rfind("v24_latch v2 ", 0), 0u);
    EXPECT_NE(rec.find(f.c.at(55)->hash.GetHex()), std::string::npos);
    // Restart with the block still on our chain: the latch stays.
    {
        DashDeploymentStatus again(f.p, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
        ASSERT_TRUE(again.deserialize_latch(rec));
        again.revalidate_latch();
        EXPECT_NE(again.latch(), V24Latch::NONE);
    }
    // Restart after the block was orphaned while we were down: a latch from
    // a valid block (our answer refuted) stays until a cross-check at or above
    // its height agrees with the recomputed answer.
    f.c.salt[55] = 0x66;
    {
        DashDeploymentStatus again(f.p, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
        ASSERT_TRUE(again.deserialize_latch(rec));
        ASSERT_NE(again.latch(), V24Latch::NONE);
        again.revalidate_latch();
        EXPECT_NE(again.latch(), V24Latch::NONE);
        EXPECT_EQ(again.cross_check_cbtx_version(56, f.c.at(56)->hash, 3), V24CrossCheck::AGREE);
        EXPECT_EQ(again.latch(), V24Latch::NONE);
    }
    // A record from before v2 (no block hash) still loads and stays latched
    // until the recomputed answer agrees (the old rule).
    {
        DashDeploymentStatus again(f.p, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
        ASSERT_TRUE(again.deserialize_latch("v24_latch v1 " + std::to_string(static_cast<int>(f.p.network))
                                            + " 1 55 1 0 0 1\n"));
        again.revalidate_latch();
        EXPECT_NE(again.latch(), V24Latch::NONE);
    }
    // A malformed v2 hash is refused.
    DashDeploymentStatus bad(f.p, f.c.fn(), [&f] { return std::optional<uint32_t>(f.tip); }, f.t);
    EXPECT_FALSE(bad.deserialize_latch("v24_latch v2 " + std::to_string(static_cast<int>(f.p.network))
                                       + " 1 55 1 0 0 1 xyz 0\n"));
}

// N4: a latch set by a VALID block that refuted our answer (the tracker was
// wrong) is not cleared by that block's reorg alone: the refuted answer must
// not be served until a cross-check at or above the latched height agrees.
TEST(DashV24Deployments, LatchFromAValidBlockWaitsForAnAgreeingCrossCheck)
{
    LatchFixture f(true);   // signal at 25: our tracker says v24 is active from 50
    ASSERT_EQ(f.st->v24_state(56), V24State::ACTIVE);
    // A valid block at 55 states inactive: our answer is refuted.
    ASSERT_EQ(f.st->cross_check_cbtx_version(55, f.c.at(55)->hash, 3), V24CrossCheck::CONTRADICTS);
    ASSERT_NE(f.st->latch(), V24Latch::NONE);
    EXPECT_NE(f.st->v24_state(56), V24State::ACTIVE);
    // That block is reorged out: the latch stays, the refuted answer is not served.
    f.c.salt[55] = 0x44;
    f.st->revalidate_latch();
    EXPECT_NE(f.st->latch(), V24Latch::NONE);
    EXPECT_NE(f.st->v24_state(56), V24State::ACTIVE);
    // The next block on the new branch also states inactive: our recomputed
    // answer is still refuted there, so the latch stays (and the latched
    // state answers nothing).
    EXPECT_EQ(f.st->cross_check_cbtx_version(56, f.c.at(56)->hash, 3), V24CrossCheck::UNDECIDED);
    EXPECT_NE(f.st->latch(), V24Latch::NONE);
    // A branch whose blocks agree with the recomputed answer clears it at the
    // first agreeing cross-check at or above the latched height.
    f.c.salt[56] = 0x45;
    EXPECT_EQ(f.st->cross_check_cbtx_version(54, f.c.at(54)->hash, 4), V24CrossCheck::UNDECIDED)
        << "below the latched height: no clearing";
    EXPECT_NE(f.st->latch(), V24Latch::NONE);
    EXPECT_EQ(f.st->cross_check_cbtx_version(57, f.c.at(57)->hash, 4), V24CrossCheck::AGREE);
    EXPECT_EQ(f.st->latch(), V24Latch::NONE);
    EXPECT_EQ(f.st->v24_state(58), V24State::ACTIVE);
}

// A CbTx version Dash Core rejects at that height (CheckCbTx) disagrees with
// every answer: it latches at the bound level, and only that block leaving
// our chain clears it.
TEST(DashV24Deployments, CrossCheckLatchesOnACbTxVersionCoreRejects)
{
    SynthChain c;
    c.tip = 120;
    c.signal_range(30, 39);
    auto p = fast_params(0);
    p.v20_height = 10;
    uint32_t tip = 120;
    auto t = std::make_shared<EhfSignalTracker>(p, c.fn());
    for (uint32_t h = 0; h <= 120; ++h) t->connect_block(block_at(c, h, {}), h, c.at(h)->hash);
    DashDeploymentStatus st(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
    EXPECT_EQ(st.cross_check_cbtx_version(50, c.at(50)->hash, 3), V24CrossCheck::AGREE);
    for (const auto& [h, v] : std::vector<std::pair<uint32_t, uint16_t>>{{51, 5}, {52, 2}, {5, 3}, {53, 0}}) {
        DashDeploymentStatus s2(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
        EXPECT_EQ(s2.cross_check_cbtx_version(h, c.at(h)->hash, v), V24CrossCheck::CONTRADICTS) << h << " v" << v;
        EXPECT_EQ(s2.latch(), V24Latch::BOUND) << h << " v" << v;
        EXPECT_EQ(s2.v24_state(60), V24State::UNKNOWN);
        // Agreeing blocks after it never clear it ...
        s2.cross_check_cbtx_version(60, c.at(60)->hash, 3);
        EXPECT_EQ(s2.latch(), V24Latch::BOUND);
        // ... its orphaning does, and the record round-trips the flag.
        DashDeploymentStatus s3(p, c.fn(), [&tip] { return std::optional<uint32_t>(tip); }, t);
        ASSERT_TRUE(s3.deserialize_latch(s2.serialize_latch()));
        c.salt[h] = 0x99;
        s2.revalidate_latch();
        EXPECT_EQ(s2.latch(), V24Latch::NONE);
        s3.revalidate_latch();
        EXPECT_EQ(s3.latch(), V24Latch::NONE);
        c.salt.erase(h);
    }
}


// ── The activation height into the folds (v24_activation.hpp) ──────────────
// A synthetic chain on MAINNET parameters: the EHF signal for bit 13 is mined
// at 2,569,000 (after the November 9 start time), the window 2,572,416..
// 2,576,447 signals, so v24 is LOCKED_IN at 2,576,448 and ACTIVE at
// 2,580,480 -- the earliest mainnet activation.
namespace {

constexpr uint32_t kMainSignal = 2'569'000;
constexpr uint32_t kMainLockIn = 2'576'448;
constexpr uint32_t kMainActive = 2'580'480;

struct MainnetActivationWorld
{
    SynthChain c;
    DashDeploymentParams p = dash_deployment_params(DashNetwork::MAINNET);
    std::shared_ptr<EhfSignalTracker> t;
    uint32_t tip{0};
    std::unique_ptr<DashDeploymentStatus> st;

    MainnetActivationWorld()
    {
        c.t0 = 1'794'182'400u - 150u * 2'568'500u;   // MTP reaches the start time near 2,568,505
        c.tip = kMainActive + 300;
        c.signal_range(kMainLockIn - 4032, kMainLockIn - 1);
        t = std::make_shared<EhfSignalTracker>(p, c.fn());
        st = std::make_unique<DashDeploymentStatus>(p, c.fn(), [this] { return std::optional<uint32_t>(tip); }, t);
    }
    /// Scan bodies up to `h` and move the tip there.
    void advance(uint32_t h)
    {
        for (uint32_t x = t->next_needed_height(); x <= h; ++x) {
            std::vector<MutableTransaction> extra;
            if (x == kMainSignal) extra.push_back(mnhf_tx(13));
            ASSERT_TRUE(t->connect_block(block_at(c, x, extra), x, c.at(x)->hash)) << x;
        }
        tip = h;
    }
    /// What main_dash wires: the tracking's answers and the header tip.
    V24TrackingView view()
    {
        V24TrackingView v;
        v.activation_height = [this] { return st->activation_height(DashDeployment::V24); };
        v.state = [this](uint32_t h) { return st->v24_state(h); };
        v.refuted = [this] { return st->latch() != V24Latch::NONE; };
        v.tip = [this] { return std::optional<uint32_t>(tip); };
        return v;
    }
};

/// A mined block on top of `prev` whose coinbase states CbTx `version`.
BlockType cbtx_block(uint32_t height, const uint256& prev, uint16_t version)
{
    vendor::CCbTx cb;
    cb.nVersion = version;
    cb.nHeight = static_cast<int32_t>(height);
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 5;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    auto ps = ::pack(cb);
    auto sp = ps.get_span();
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_timestamp = 1'800'000'000 + height;
    b.m_bits = 0x1e0fffff;
    b.m_nonce = height;
    b.m_txs.push_back(tx);
    return b;
}

replay::FoldConfig mainnet_fold_cfg()
{
    replay::FoldConfig cfg;
    cfg.enabled = true;   // mainnet gates; v24 height unknown until pushed
    cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();   // no payee axis here
    return cfg;
}

std::string temp_path(const char* tag)
{
    return (std::filesystem::temp_directory_path()
            / ("c2pool-v24-activation-" + std::string(tag) + "-" + std::to_string(std::random_device{}()) + ".v1"))
        .string();
}

} // namespace

namespace {
/// A tracking view with fixed answers (a tracker that does not know yet, or
/// one that has decided).
V24TrackingView fixed_view(std::optional<uint32_t> height, V24State state_everywhere = V24State::UNKNOWN,
                           std::optional<uint32_t> tip = std::nullopt, bool refuted = false)
{
    V24TrackingView v;
    v.activation_height = [height] { return height; };
    v.state = [state_everywhere](uint32_t) { return state_everywhere; };
    v.refuted = [refuted] { return refuted; };
    v.tip = [tip] { return tip; };
    return v;
}
bool file_exists(const std::string& path) { return std::filesystem::exists(path); }
}  // namespace

TEST(DashV24Activation, HeightIsPushedOnceTheLockInIsSettled)
{
    MainnetActivationWorld w;
    const std::string path = temp_path("window");
    std::remove(path.c_str());
    V24ActivationWire wire(DashNetwork::MAINNET, w.view(), path);
    MnStateMachine sm;
    replay::DmlFoldEngine eng(mainnet_fold_cfg());
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    wire.add_sink([&](uint32_t h) { eng.set_v24_height(h); });

    // Still STARTED for the block after the tip: nothing to push.
    w.advance(kMainLockIn - 2);
    EXPECT_EQ(wire.refresh(), std::nullopt);
    // LOCKED_IN for the next block, decided by the window's last block: known,
    // but not pushed until that block is kV24ActivationConfirmations deep.
    w.advance(kMainLockIn - 1);
    ASSERT_EQ(w.st->activation_height(DashDeployment::V24), std::optional<uint32_t>(kMainActive));
    EXPECT_EQ(wire.refresh(), std::nullopt);
    w.advance(kMainLockIn - 1 + kV24ActivationConfirmations - 1);
    EXPECT_EQ(wire.refresh(), std::nullopt);
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    w.advance(kMainLockIn - 1 + kV24ActivationConfirmations);
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive));
    EXPECT_EQ(sm.v24_height(), kMainActive);
    EXPECT_EQ(eng.v24_height(), static_cast<int32_t>(kMainActive));
    EXPECT_LT(kMainLockIn - 1 + kV24ActivationConfirmations, kMainActive - 3000) << "most of a window early";
    {
        std::ifstream in(path);
        std::stringstream ss;
        ss << in.rdbuf();
        EXPECT_EQ(V24ActivationWire::parse(DashNetwork::MAINNET, ss.str()), std::optional<uint32_t>(kMainActive));
    }
    // ACTIVE at the tip: the same height, re-checked against the exact state.
    w.advance(kMainActive + 50);
    EXPECT_EQ(w.st->v24_state(kMainActive - 1), V24State::INACTIVE);
    EXPECT_EQ(w.st->v24_state(kMainActive), V24State::ACTIVE);
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive));

    // Both engines fold the boundary as each block states; the pushed height
    // agrees, so nothing is counted.
    sm.load({}, kMainActive - 2);
    EXPECT_TRUE(sm.apply_block(cbtx_block(kMainActive - 1, uint256{}, 3), kMainActive - 1).refused.empty());
    EXPECT_TRUE(sm.apply_block(cbtx_block(kMainActive, uint256{}, 4), kMainActive).refused.empty());
    EXPECT_EQ(sm.v24_contradictions(), 0u);
    eng.seed({}, 0, kMainActive - 1, height_hash(1, 0xa1));
    const auto f = eng.fold_block(cbtx_block(kMainActive, eng.block_hash(), 4), kMainActive);
    EXPECT_TRUE(f.ok) << f.error;
    EXPECT_EQ(eng.v24_contradictions(), 0u);
    std::remove(path.c_str());
}

TEST(DashV24Activation, AWrongHeightNeverStallsAFold)
{
    // A height that disagrees with the chain (a bad persisted file, a tracker
    // fault): every block still folds as its CbTx version states, and the
    // disagreement is counted. Nothing is refused, nothing stalls.
    MnStateMachine sm;
    sm.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    sm.set_v24_height(kMainActive);
    sm.load({}, kMainActive - 1);
    auto r = sm.apply_block(cbtx_block(kMainActive, uint256{}, 3), kMainActive);
    EXPECT_TRUE(r.refused.empty()) << r.refused;
    r = sm.apply_block(cbtx_block(kMainActive + 1, uint256{}, 3), kMainActive + 1);
    EXPECT_TRUE(r.refused.empty()) << r.refused;
    EXPECT_EQ(sm.v24_contradictions(), 2u);
    replay::DmlFoldEngine eng(mainnet_fold_cfg());
    eng.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    eng.set_v24_height(kMainActive + 4032);
    eng.seed({}, 0, kMainActive + 9, height_hash(2, 0xa1));
    const auto f = eng.fold_block(cbtx_block(kMainActive + 10, eng.block_hash(), 4), kMainActive + 10);
    EXPECT_TRUE(f.ok) << f.error;
    EXPECT_EQ(eng.v24_contradictions(), 1u);
}

TEST(DashV24Activation, ABlockNeverSetsTheSwitchOfAnotherBlock)
{
    // No height pushed. A v24 statement below the earliest possible mainnet
    // activation is a block dashd rejects (bad-cbtx-version): refused before
    // any mutation, and nothing about it survives.
    const uint32_t H = 2'569'300;
    MnStateMachine sm;
    sm.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    sm.load({}, H - 1);
    auto r = sm.apply_block(cbtx_block(H, uint256{}, 4), H);
    EXPECT_NE(r.refused.find("bad-cbtx-version"), std::string::npos) << r.refused;
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    EXPECT_TRUE(sm.apply_block(cbtx_block(H, uint256{}, 3), H).refused.empty()) << "the honest block";
    EXPECT_TRUE(sm.apply_block(cbtx_block(H + 1, uint256{}, 3), H + 1).refused.empty()) << "and the next";
    // Without the network bound, the block folds as it states, and still
    // sets nothing: after a reorg the honest block and every later one fold.
    MnStateMachine loose;
    loose.load({}, H - 1);
    EXPECT_TRUE(loose.apply_block(cbtx_block(H, uint256{}, 4), H).refused.empty());
    EXPECT_EQ(loose.v24_height(), kV24HeightUnknown);
    loose.load({}, H - 1);
    EXPECT_TRUE(loose.apply_block(cbtx_block(H, uint256{}, 3), H).refused.empty());
    EXPECT_TRUE(loose.apply_block(cbtx_block(H + 1, uint256{}, 3), H + 1).refused.empty());
    // A refused block (bad-txns-type for a type outside v24's list) changes
    // nothing either, in both engines.
    MutableTransaction bad;
    bad.version = 3;
    bad.type = 13;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = uint256::ONE;
    in.prevout.index = 0;
    bad.vin.push_back(in);
    bad.extra_payload = {0x01};
    auto with_bad = cbtx_block(kMainActive + 5, uint256{}, 4);
    with_bad.m_txs.push_back(bad);
    MnStateMachine sm2;
    sm2.load({}, kMainActive + 4);
    EXPECT_FALSE(sm2.apply_block(with_bad, kMainActive + 5).refused.empty());
    EXPECT_EQ(sm2.v24_height(), kV24HeightUnknown);
    replay::DmlFoldEngine eng(mainnet_fold_cfg());
    eng.seed({}, 0, kMainActive + 4, height_hash(4, 0xa1));
    with_bad.m_previous_block = eng.block_hash();
    const auto f = eng.fold_block(with_bad, kMainActive + 5);
    EXPECT_FALSE(f.ok);
    EXPECT_TRUE(f.refused_unchanged);
    EXPECT_EQ(eng.v24_height(), std::numeric_limits<int32_t>::max());
    // The replay fold refuses a v24 statement below the earliest activation.
    replay::DmlFoldEngine e2(mainnet_fold_cfg());
    e2.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    e2.seed({}, 0, H - 1, height_hash(5, 0xa1));
    const auto f2 = e2.fold_block(cbtx_block(H, e2.block_hash(), 4), H);
    EXPECT_FALSE(f2.ok);
    EXPECT_TRUE(f2.refused_unchanged);
    EXPECT_NE(f2.error.find("bad-cbtx-version"), std::string::npos) << f2.error;
}

TEST(DashV24Activation, BlockSwitchMatrix)
{
    const uint32_t E = kMainActive;
    // Pre-V20 CbTx (version 2) or none: the pushed height decides.
    EXPECT_FALSE(v24_block_switch(100, kV24HeightUnknown, std::nullopt).active);
    EXPECT_FALSE(v24_block_switch(100, kV24HeightUnknown, uint16_t{2}).active);
    EXPECT_TRUE(v24_block_switch(kMainActive, kMainActive, uint16_t{2}).active);
    // Version 3 / 4: the block decides; the height only cross-checks.
    EXPECT_TRUE(v24_block_switch(100, kV24HeightUnknown, uint16_t{4}).active);
    EXPECT_TRUE(v24_block_switch(100, kV24HeightUnknown, uint16_t{4}, E).invalid.has_value());
    EXPECT_FALSE(v24_block_switch(kMainActive, kV24HeightUnknown, uint16_t{4}, E).invalid.has_value());
    EXPECT_FALSE(v24_block_switch(kMainActive - 1, kMainActive, uint16_t{3}).contradiction.has_value());
    const auto early = v24_block_switch(kMainActive - 1, kMainActive, uint16_t{4});
    EXPECT_TRUE(early.contradiction.has_value());
    EXPECT_TRUE(early.active);
    const auto late = v24_block_switch(kMainActive, kMainActive, uint16_t{3});
    EXPECT_TRUE(late.contradiction.has_value());
    EXPECT_FALSE(late.active);
    EXPECT_FALSE(v24_block_switch(kMainActive, kMainActive, uint16_t{4}).contradiction.has_value());
    // CheckCbTx: version 0 or 5+ is invalid at every height; with the V20
    // height known, below 3 after it and 3+ before it are invalid too.
    const uint32_t V20 = dash_deployment_params(DashNetwork::MAINNET).v20_height;
    EXPECT_TRUE(v24_block_switch(kMainActive, kV24HeightUnknown, uint16_t{5}, E, V20).invalid.has_value());
    EXPECT_TRUE(v24_block_switch(kMainActive, kV24HeightUnknown, uint16_t{5}).invalid.has_value());
    EXPECT_FALSE(v24_block_switch(kMainActive, kV24HeightUnknown, uint16_t{5}).active);
    EXPECT_TRUE(v24_block_switch(kMainActive, kV24HeightUnknown, uint16_t{0}).invalid.has_value());
    EXPECT_TRUE(v24_block_switch(V20, kV24HeightUnknown, uint16_t{2}, E, V20).invalid.has_value());
    EXPECT_TRUE(v24_block_switch(V20, kV24HeightUnknown, std::nullopt, E, V20).invalid.has_value())
        << "no CbTx after V20";
    EXPECT_FALSE(v24_block_switch(V20, kV24HeightUnknown, uint16_t{3}, E, V20).invalid.has_value());
    EXPECT_TRUE(v24_block_switch(V20 - 1, kV24HeightUnknown, uint16_t{3}, E, V20).invalid.has_value());
    EXPECT_FALSE(v24_block_switch(V20 - 1, kV24HeightUnknown, uint16_t{2}, E, V20).invalid.has_value());
}

TEST(DashV24Activation, CbTxVersionsCoreRejectsAreRefusedBeforeAnyMutation)
{
    const uint32_t V20 = dash_deployment_params(DashNetwork::MAINNET).v20_height;
    for (uint16_t bad : {uint16_t{5}, uint16_t{2}}) {
        MnStateMachine sm;
        sm.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
        sm.set_v20_height(V20);
        sm.load({}, kMainActive + 9);
        const auto r = sm.apply_block(cbtx_block(kMainActive + 10, uint256{}, bad), kMainActive + 10);
        EXPECT_NE(r.refused.find("bad-cbtx-version"), std::string::npos) << bad << ": " << r.refused;
        EXPECT_TRUE(sm.apply_block(cbtx_block(kMainActive + 10, uint256{}, 4), kMainActive + 10).refused.empty())
            << "the valid block at the same height";
        replay::DmlFoldEngine eng(mainnet_fold_cfg());
        eng.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
        eng.set_v20_height(V20);
        eng.seed({}, 0, kMainActive + 9, height_hash(6, 0xa1));
        const auto f = eng.fold_block(cbtx_block(kMainActive + 10, eng.block_hash(), bad), kMainActive + 10);
        EXPECT_FALSE(f.ok);
        EXPECT_TRUE(f.refused_unchanged);
        EXPECT_NE(f.error.find("bad-cbtx-version"), std::string::npos) << f.error;
        const auto ok = eng.fold_block(cbtx_block(kMainActive + 10, eng.block_hash(), 4), kMainActive + 10);
        EXPECT_TRUE(ok.ok) << ok.error;
    }
}

TEST(DashV24Activation, PersistedFileIsStrictAndPlausible)
{
    using W = V24ActivationWire;
    const auto M = DashNetwork::MAINNET;
    EXPECT_EQ(W::parse(M, W::serialize(M, kMainActive)), std::optional<uint32_t>(kMainActive));
    EXPECT_EQ(W::parse(M, W::serialize(M, kMainActive + 4032)), std::optional<uint32_t>(kMainActive + 4032));
    // Not a period boundary, below the earliest activation, height 1.
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 1\n"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 2569220\n"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 2580481\n"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 2576448\n"), std::nullopt);
    // Not strict: trailing junk, signs, padding, another network.
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 2580480 trailing junk"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 +2580480"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1 0 02580480"), std::nullopt);
    EXPECT_EQ(W::parse(M, "c2pool-dash-v24-activation/1  0 2580480"), std::nullopt);
    EXPECT_EQ(W::parse(M, W::serialize(DashNetwork::TESTNET, kMainActive)), std::nullopt);
    // Testnet: only its buried height.
    EXPECT_EQ(W::parse(DashNetwork::TESTNET, W::serialize(DashNetwork::TESTNET, 1'578'000)),
              std::optional<uint32_t>(1'578'000));
    EXPECT_EQ(W::parse(DashNetwork::TESTNET, W::serialize(DashNetwork::TESTNET, 1'582'032)), std::nullopt);

    // An implausible file is deleted and applied nowhere.
    const std::string path = temp_path("implausible");
    {
        std::ofstream o(path);
        o << "c2pool-dash-v24-activation/1 0 2569220\n";
    }
    V24ActivationWire wire(M, fixed_view(std::nullopt), path);
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    EXPECT_FALSE(wire.load());
    EXPECT_FALSE(file_exists(path));
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    EXPECT_EQ(wire.refresh(), std::nullopt);
}

TEST(DashV24Activation, PersistedHeightIsReCheckedAndWithdrawn)
{
    const std::string path = temp_path("restart");
    {
        std::ofstream out(path, std::ios::trunc);
        out << V24ActivationWire::serialize(DashNetwork::MAINNET, kMainActive);
    }
    // After a restart the tracker has not rescanned yet: it knows nothing.
    V24ActivationWire wire(DashNetwork::MAINNET, fixed_view(std::nullopt), path);
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    EXPECT_TRUE(wire.load());
    EXPECT_EQ(sm.v24_height(), kMainActive);
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive)) << "an undecided tracking keeps it";
    // A sink added later gets it at once (the replay folds are built late).
    replay::DmlFoldEngine eng(mainnet_fold_cfg());
    wire.add_sink([&](uint32_t h) { eng.set_v24_height(h); });
    EXPECT_EQ(eng.v24_height(), static_cast<int32_t>(kMainActive));
    // The tracking decides v24 is NOT active there: withdrawn from every
    // engine, the file deleted, and the engines go on folding.
    wire.set_view(fixed_view(std::nullopt, V24State::INACTIVE, kMainActive + 10));
    EXPECT_EQ(wire.refresh(), std::nullopt);
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    EXPECT_EQ(eng.v24_height(), std::numeric_limits<int32_t>::max());
    EXPECT_FALSE(file_exists(path));
    sm.load({}, kMainActive - 1);
    EXPECT_TRUE(sm.apply_block(cbtx_block(kMainActive, uint256{}, 3), kMainActive).refused.empty());
    // A settled, different height from the tracking replaces it.
    wire.set_view(fixed_view(kMainActive + 4032, V24State::UNKNOWN, kMainActive + 4032 + 10));
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive + 4032));
    EXPECT_EQ(sm.v24_height(), kMainActive + 4032);
    // The tracking already knows: a persisted file does not override it.
    {
        std::ofstream out(path, std::ios::trunc);
        out << V24ActivationWire::serialize(DashNetwork::MAINNET, kMainActive);
    }
    EXPECT_FALSE(wire.load());
    EXPECT_EQ(wire.applied(), std::optional<uint32_t>(kMainActive + 4032));
    // Another network's file is ignored (and removed).
    V24ActivationWire tn(DashNetwork::TESTNET, {}, path);
    EXPECT_FALSE(tn.load());
    EXPECT_EQ(tn.applied(), std::nullopt);
    std::remove(path.c_str());
}

TEST(DashV24Activation, TheCrossCheckLatchWithdrawsTheHeightAndDeletesTheFile)
{
    const std::string path = temp_path("latch");
    V24ActivationWire wire(DashNetwork::MAINNET, fixed_view(kMainActive, V24State::UNKNOWN, kMainActive + 1), path);
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    ASSERT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive));
    ASSERT_TRUE(file_exists(path));
    wire.set_view(fixed_view(kMainActive, V24State::UNKNOWN, kMainActive + 1, /*refuted=*/true));
    EXPECT_EQ(wire.refresh(), std::nullopt);
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    EXPECT_FALSE(file_exists(path));
}

TEST(DashV24Activation, AnUnsettledLockInNeverReachesTheEngines)
{
    // LOCKED_IN known with the deciding block (kMainLockIn - 1) only 50 deep,
    // then reorged back to STARTED: nothing was ever pushed or persisted.
    const std::string path = temp_path("unsettled");
    V24ActivationWire wire(DashNetwork::MAINNET, fixed_view(kMainActive, V24State::UNKNOWN, kMainLockIn - 1 + 50),
                           path);
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    EXPECT_EQ(wire.refresh(), std::nullopt);
    wire.set_view(fixed_view(std::nullopt, V24State::UNKNOWN, kMainLockIn - 1 + 60));
    EXPECT_EQ(wire.refresh(), std::nullopt);
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    EXPECT_FALSE(file_exists(path));
    // An implausible answer from the tracking is never pushed either.
    wire.set_view(fixed_view(kMainActive + 1, V24State::UNKNOWN, kMainActive + 500));
    EXPECT_EQ(wire.refresh(), std::nullopt);
}

TEST(DashV24Activation, ReorgAcrossTheActivationBoundaryKeepsTheHeight)
{
    MainnetActivationWorld w;
    V24ActivationWire wire(DashNetwork::MAINNET, w.view());
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    w.advance(kMainActive + 100);
    ASSERT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive));
    // Replace 2,580,470..2,580,600 with another branch: the activation height
    // is fixed by the signalling window, so the tracking still answers it.
    for (uint32_t h = kMainActive - 10; h <= kMainActive + 120; ++h) w.c.salt[h] = 0xb2;
    w.c.tip = kMainActive + 120;
    const auto kept = w.t->reconcile_with_chain();
    ASSERT_TRUE(kept.has_value());
    EXPECT_LT(*kept, kMainActive - 9) << "coverage cut back below the fork";
    w.advance(kMainActive + 120);
    EXPECT_EQ(w.st->activation_height(DashDeployment::V24), std::optional<uint32_t>(kMainActive));
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(kMainActive));
    EXPECT_EQ(sm.v24_height(), kMainActive);
    // The new branch's activation block folds under v24.
    sm.load({}, kMainActive - 1);
    EXPECT_TRUE(sm.apply_block(cbtx_block(kMainActive, uint256{}, 4), kMainActive).refused.empty());
    EXPECT_EQ(sm.v24_contradictions(), 0u);
}

TEST(DashV24Activation, ColdRestartAfterActivationFoldsByTheBlocks)
{
    // A cold restart after activation without the persisted file, before the
    // tracker has rescanned: each block's statement decides, nothing is
    // adopted.
    MnStateMachine sm;
    sm.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    sm.load({}, kMainActive + 9);
    auto r = sm.apply_block(cbtx_block(kMainActive + 10, uint256{}, 4), kMainActive + 10);
    EXPECT_TRUE(r.refused.empty()) << r.refused;
    EXPECT_EQ(sm.v24_height(), kV24HeightUnknown);
    replay::DmlFoldEngine eng(mainnet_fold_cfg());
    eng.seed({}, 0, kMainActive + 9, height_hash(3, 0xa1));
    const auto f = eng.fold_block(cbtx_block(kMainActive + 10, eng.block_hash(), 4), kMainActive + 10);
    EXPECT_TRUE(f.ok) << f.error;
    EXPECT_EQ(eng.v24_height(), std::numeric_limits<int32_t>::max());
}

TEST(DashV24Activation, TestnetHeightComesFromTheSameTrackingAndMatches)
{
    // Testnet's activation is history: the same tracking answers the buried
    // height, which equals the replay fold's testnet gate and the height the
    // versionbits machine derives from the real testnet headers.
    DashDeploymentStatus st(DashNetwork::TESTNET, [](uint32_t) { return std::optional<VbBlockInfo>{}; },
                            [] { return std::optional<uint32_t>(1'586'000); }, nullptr);
    V24TrackingView v;
    v.activation_height = [&st] { return st.activation_height(DashDeployment::V24); };
    v.state = [&st](uint32_t h) { return st.v24_state(h); };
    v.refuted = [&st] { return st.latch() != V24Latch::NONE; };
    v.tip = [] { return std::optional<uint32_t>(1'586'000); };
    V24ActivationWire wire(DashNetwork::TESTNET, v);
    MnStateMachine sm;
    wire.add_sink([&](uint32_t h) { sm.set_v24_height(h); });
    EXPECT_EQ(wire.refresh(), std::optional<uint32_t>(1'578'000));
    EXPECT_EQ(sm.v24_height(), 1'578'000u);
    EXPECT_EQ(static_cast<uint32_t>(replay::FoldGates::testnet().v24_height), 1'578'000u);
    EXPECT_EQ(replay::FoldGates::testnet().v24_earliest, 1'578'000u);
    TestnetChain tc;
    DashDeploymentParams p = dash_deployment_params(DashNetwork::TESTNET);
    p.v24_buried_height.reset();
    VersionBitsChecker vb(p, DashDeployment::V24, tc.fn());
    EXPECT_EQ(vb.state_since_height(1'577'999, 1'565'132), std::optional<int64_t>(1'578'000));
}

// ── order_service_updates (service_update_order.hpp): invariants over
// random parent-before-child bodies (independent verifier's property test).
// ── order_service_updates: property fuzz over random DAG bodies ────────────
namespace {
struct FuzzBody {
    std::vector<ServiceOrderTx> txs;
};
FuzzBody random_body(std::mt19937_64& rng, size_t n, int nmn)
{
    FuzzBody b;
    auto id = [](size_t i) {
        uint256 h;
        h.data()[0] = static_cast<uint8_t>(i & 0xff);
        h.data()[1] = static_cast<uint8_t>((i >> 8) & 0xff);
        h.data()[31] = 0x5a;
        return h;
    };
    auto mn = [](int m) {
        uint256 h;
        h.data()[0] = static_cast<uint8_t>(0xc0 + m);
        h.data()[30] = 0x77;
        return h;
    };
    for (size_t i = 0; i < n; ++i) {
        ServiceOrderTx t;
        t.txid = id(i);
        // parents among earlier txs (topological input order)
        const int np = static_cast<int>(rng() % 3);
        for (int k = 0; k < np && i > 0; ++k) t.spends.push_back(id(rng() % i));
        t.spends.push_back(uint256::ONE);   // a confirmed coin
        const int kind = static_cast<int>(rng() % 10);
        if (kind < 3) t.service_update_of = mn(static_cast<int>(rng() % nmn));
        else if (kind < 5) t.key_change_of = mn(static_cast<int>(rng() % nmn));
        else if (kind == 5) t.unorderable_kind = true;
        b.txs.push_back(std::move(t));
    }
    return b;
}
} // namespace

TEST(DashServiceOrder, FuzzInvariants)
{
    std::mt19937_64 rng(0xC0FFEE);
    size_t moved_total = 0, dropped_total = 0;
    for (int iter = 0; iter < 20000; ++iter) {
        const size_t n = 1 + rng() % 14;
        const auto b = random_body(rng, n, 1 + static_cast<int>(rng() % 3));
        const auto r = order_service_updates(b.txs);
        moved_total += r.moved;
        dropped_total += r.dropped.size();
        std::set<size_t> dropped;
        for (const auto& d : r.dropped) dropped.insert(d.first);
        // 1. every tx is either placed exactly once or dropped
        std::set<size_t> placed;
        for (size_t i : r.order) ASSERT_TRUE(placed.insert(i).second) << "placed twice iter=" << iter;
        for (size_t i = 0; i < n; ++i)
            ASSERT_TRUE(placed.count(i) + dropped.count(i) == 1) << "tx " << i << " lost/duplicated iter=" << iter;
        // 2. parents before children; no kept child of a dropped parent
        std::map<uint256, size_t> pos;
        for (size_t k = 0; k < r.order.size(); ++k) pos[b.txs[r.order[k]].txid] = k;
        std::map<uint256, size_t> idx;
        for (size_t i = 0; i < n; ++i) idx[b.txs[i].txid] = i;
        for (size_t k = 0; k < r.order.size(); ++k) {
            const auto& t = b.txs[r.order[k]];
            for (const auto& s : t.spends) {
                auto it = idx.find(s);
                if (it == idx.end()) continue;
                ASSERT_FALSE(dropped.count(it->second)) << "kept child of dropped parent iter=" << iter;
                ASSERT_LT(pos.at(s), k) << "child before parent iter=" << iter;
            }
        }
        // 3. no service update of X after a key change of X
        std::set<uint256> changed;
        for (size_t k = 0; k < r.order.size(); ++k) {
            const auto& t = b.txs[r.order[k]];
            if (t.service_update_of) ASSERT_FALSE(changed.count(*t.service_update_of)) << "iter=" << iter;
            if (t.key_change_of) changed.insert(*t.key_change_of);
        }
        // 4. only service updates and their descendants are left out:
        //    a dropped tx is a service update or a descendant of a dropped tx
        for (size_t d : dropped) {
            bool ok = b.txs[d].service_update_of.has_value();
            for (const auto& s : b.txs[d].spends) {
                auto it = idx.find(s);
                if (it != idx.end() && dropped.count(it->second)) ok = true;
            }
            ASSERT_TRUE(ok) << "dropped a non-service, non-descendant tx iter=" << iter;
        }
        // 5. key changes and unorderable kinds keep their relative order
        std::vector<size_t> fixed_in, fixed_out;
        for (size_t i = 0; i < n; ++i)
            if (b.txs[i].key_change_of || b.txs[i].unorderable_kind) fixed_in.push_back(i);
        for (size_t i : r.order)
            if (b.txs[i].key_change_of || b.txs[i].unorderable_kind) fixed_out.push_back(i);
        std::vector<size_t> fixed_in_kept;
        for (size_t i : fixed_in) if (!dropped.count(i)) fixed_in_kept.push_back(i);
        ASSERT_EQ(fixed_in_kept, fixed_out) << "iter=" << iter;
    }
    EXPECT_GT(moved_total, 0u);
    EXPECT_GT(dropped_total, 0u);
}

// ── The independent verifier's delta KATs on the activation wire (fbfea8f58) ──
namespace {
constexpr uint32_t kDeltaAct = 2'580'480;

BlockType delta_block(uint32_t height, const uint256& prev, uint16_t cbver, std::vector<MutableTransaction> extra = {})
{
    vendor::CCbTx cb;
    cb.nVersion = cbver;
    cb.nHeight = static_cast<int32_t>(height);
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 5;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    auto ps = ::pack(cb);
    auto sp = ps.get_span();
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_timestamp = 1'800'000'000 + height;
    b.m_bits = 0x1e0fffff;
    b.m_nonce = height;
    b.m_txs.push_back(tx);
    for (auto& t : extra) b.m_txs.push_back(std::move(t));
    return b;
}
std::string delta_tmp(const char* tag)
{
    return (std::filesystem::temp_directory_path()
            / ("verify-delta-" + std::string(tag) + "-" + std::to_string(std::random_device{}()) + ".v1"))
        .string();
}
V24TrackingView delta_view(std::optional<uint32_t> h, V24State st, std::optional<uint32_t> tip, bool refuted = false)
{
    V24TrackingView v;
    v.activation_height = [h] { return h; };
    v.state = [st](uint32_t) { return st; };
    v.refuted = [refuted] { return refuted; };
    v.tip = [tip] { return tip; };
    return v;
}
} // namespace

// Strict parse: a fuzz of near-miss spellings never yields a height, and only
// period starts >= 2,580,480 are ever accepted on mainnet.
TEST(DashV24ActivationDelta, PersistedFileParseIsStrict)
{
    const std::string M = "c2pool-dash-v24-activation/1";
    const std::vector<std::string> bad = {
        M + " 0 2580480 x", M + "  0 2580480", M + " 0  2580480", M + "\t0 2580480",
        M + " 0 02580480", M + " 0 +2580480", M + " 0 2580481", M + " 0 2576448", M + " 0 1",
        M + " 1 2580480", M + " 00 2580480", M + " 0 4294967295", M + " 0 99999999999", M + " 0 -2580480",
        "c2pool-dash-v24-activation/2 0 2580480", M + " 0 2580480 ", " " + M + " 0 2580480", M + " 0",
        M + " 0 2580480\r\nextra"};
    for (const auto& s : bad)
        EXPECT_EQ(V24ActivationWire::parse(DashNetwork::MAINNET, s), std::nullopt) << "accepted: [" << s << "]";
    EXPECT_EQ(V24ActivationWire::parse(DashNetwork::MAINNET, M + " 0 2580480\r\n"), std::optional<uint32_t>(kDeltaAct));
    EXPECT_EQ(V24ActivationWire::parse(DashNetwork::MAINNET, M + " 0 2584512"), std::optional<uint32_t>(kDeltaAct + 4032));
    // random fuzz: anything accepted must be plausible
    std::mt19937_64 rng(7);
    const std::string alphabet = "0123456789 \n\r\t+-x";
    for (int i = 0; i < 200000; ++i) {
        std::string s = M + " 0 ";
        const int n = 1 + static_cast<int>(rng() % 9);
        for (int k = 0; k < n; ++k) s.push_back(alphabet[rng() % alphabet.size()]);
        if (const auto h = V24ActivationWire::parse(DashNetwork::MAINNET, s)) {
            ASSERT_EQ(*h % 4032, 0u) << s;
            ASSERT_GE(*h, kDeltaAct) << s;
        }
    }
    // testnet: only the buried height
    EXPECT_EQ(V24ActivationWire::parse(DashNetwork::TESTNET, M + " 1 1578000"), std::optional<uint32_t>(1'578'000));
    EXPECT_EQ(V24ActivationWire::parse(DashNetwork::TESTNET, M + " 1 1578100"), std::nullopt);
}

// Settlement boundary: deciding block = h - 4032 - 1; pushed only at tip >= deciding + 100.
TEST(DashV24ActivationDelta, PushedOnlyWhenTheDecidingBlockIs100Deep)
{
    const uint32_t deciding = kDeltaAct - 4032 - 1;
    for (uint32_t tip : {deciding, deciding + 99, deciding + 100, deciding + 101}) {
        V24ActivationWire wire(DashNetwork::MAINNET, delta_view(kDeltaAct, V24State::UNKNOWN, tip));
        std::optional<uint32_t> got;
        wire.add_sink([&](uint32_t h) { got = h; });
        wire.refresh();
        if (tip >= deciding + 100)
            EXPECT_EQ(got, std::optional<uint32_t>(kDeltaAct)) << tip;
        else
            EXPECT_EQ(got, std::nullopt) << tip;
    }
    // An implausible tracking answer is never pushed, however deep.
    V24ActivationWire wire(DashNetwork::MAINNET, delta_view(kDeltaAct + 1, V24State::UNKNOWN, kDeltaAct + 100000));
    std::optional<uint32_t> got;
    wire.add_sink([&](uint32_t h) { got = h; });
    wire.refresh();
    EXPECT_EQ(got, std::nullopt);
}

// A stale but plausible persisted height that the tracking later contradicts
// is withdrawn and the file deleted; the latch withdraws too.
TEST(DashV24ActivationDelta, StaleFileIsWithdrawnByTheTrackingOrTheLatch)
{
    const std::string path = delta_tmp("stale");
    {
        std::ofstream o(path);
        o << V24ActivationWire::serialize(DashNetwork::MAINNET, kDeltaAct);
    }
    {
        V24ActivationWire wire(DashNetwork::MAINNET, delta_view(std::nullopt, V24State::UNKNOWN, std::nullopt), path);
        std::vector<uint32_t> pushed;
        wire.add_sink([&](uint32_t h) { pushed.push_back(h); });
        EXPECT_TRUE(wire.load());
        wire.refresh();   // tracking undecided: kept
        EXPECT_EQ(wire.applied(), std::optional<uint32_t>(kDeltaAct));
        wire.set_view(delta_view(std::nullopt, V24State::INACTIVE, kDeltaAct + 10));
        wire.refresh();
        EXPECT_EQ(wire.applied(), std::nullopt);
        ASSERT_EQ(pushed.size(), 2u);
        EXPECT_EQ(pushed[1], kV24HeightUnknown);
        EXPECT_FALSE(std::filesystem::exists(path));
    }
    {
        std::ofstream o(path);
        o << V24ActivationWire::serialize(DashNetwork::MAINNET, kDeltaAct);
    }
    {
        V24ActivationWire wire(DashNetwork::MAINNET, delta_view(std::nullopt, V24State::UNKNOWN, std::nullopt, true), path);
        EXPECT_TRUE(wire.load());
        wire.refresh();
        EXPECT_EQ(wire.applied(), std::nullopt);
        EXPECT_FALSE(std::filesystem::exists(path));
    }
    std::remove(path.c_str());
}

// A Core-invalid block (CbTx v4 at/after the earliest height but before the
// real activation) is folded by the engines as it states and counted; the
// templates are gated by the deployment status, whose cross-check latches on
// exactly this block (DashV24Deployments.CrossCheck*).
TEST(DashV24ActivationDelta, InvalidV4AboveEarliestFoldsButTheStatusLatches)
{
    const uint32_t real = kDeltaAct + 4032;   // the chain activates one period later
    MnStateMachine sm;
    sm.set_v24_earliest(v24_earliest_unmeasured_activation(DashNetwork::MAINNET));
    sm.set_v24_height(real);
    sm.load({}, kDeltaAct + 9);
    const auto r = sm.apply_block(delta_block(kDeltaAct + 10, uint256{}, 4), kDeltaAct + 10);
    EXPECT_TRUE(r.refused.empty()) << "folded as it states (was: refused) " << r.refused;
    EXPECT_EQ(sm.v24_contradictions(), 1u);
    // CbTx v5 (bad-cbtx-version in Core: >= UNKNOWN) is invalid, never "v24".
    EXPECT_FALSE(v24_block_switch(kDeltaAct + 11, real, uint16_t{5}, kDeltaAct).active);
    EXPECT_TRUE(v24_block_switch(kDeltaAct + 11, real, uint16_t{5}, kDeltaAct).invalid.has_value());
}
