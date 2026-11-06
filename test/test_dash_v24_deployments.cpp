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

#include <core/pack.hpp>

#include <gtest/gtest.h>

#include <cstdio>
#include <map>
#include <memory>
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

BlockType block_at(const SynthChain& c, uint32_t h, std::vector<MutableTransaction> extra = {})
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
    for (int64_t signal : {int64_t{1'559'509}, int64_t{1'567'000}, int64_t{1'577'150}, int64_t{1'577'199}}) {
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
    EXPECT_EQ(st.v24_state(62), V24State::UNKNOWN) << "parent 61 not scanned; bound says ACTIVE possible";

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
                       [&](const std::vector<uint256>& hs) { sent.push_back(hs); return true; });
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
