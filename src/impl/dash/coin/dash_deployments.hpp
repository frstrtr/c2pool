// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Dash Core v24 versionbits deployments: the per-network parameter table.
///
/// Ported from Dash Core v24.0.0:
///   src/chainparams.cpp     vDeployments[DEPLOYMENT_V24 / DEPLOYMENT_EVO_SHARES],
///                           llmqTypeMnhf, V20Height, MinBIP9WarningHeight
///   src/consensus/params.h  BIP9Deployment (NO_TIMEOUT, ALWAYS/NEVER_ACTIVE)
///   src/versionbits.h       VERSIONBITS_TOP_BITS / TOP_MASK / NUM_BITS
///   src/deploymentinfo.cpp  gbt_force (true for both deployments)
///
/// Both deployments are "EHF" (useEHF): a deployment can leave DEFINED only
/// once a masternode hard-fork signal (special tx type 7, MNHF) for its bit has
/// been mined; see ehf_tracker.hpp and versionbits.hpp.
///
/// The table also carries two values that are ours, not Core's:
///   ehf_anchor_height  the fixed height the EHF tracker rescans block bodies
///                      from on a cold start (operator decision O7). It sits
///                      before the first block whose median time past reaches
///                      the deployment start, so no unexpired signal can be
///                      mined below it.
///   v24_buried_height  an activation height that is history and has been
///                      proven by replaying the state machine (testnet:
///                      1,578,000, test_dash_v24_deployments.cpp). Like
///                      Core's buried deployments it short-cuts the tracker.

#include <cstdint>
#include <limits>
#include <optional>

namespace dash {
namespace coin {

/// The four Dash networks. The same enum (name, values) as the S2 codec slice
/// (v24_rules.hpp) declares, so the two merge by deleting one copy.
enum class DashNetwork : uint8_t { MAINNET, TESTNET, DEVNET, REGTEST };

/// The versionbits deployments this node tracks (Core DeploymentPos without
/// DEPLOYMENT_TESTDUMMY, which is NEVER_ACTIVE on every network).
enum class DashDeployment : uint8_t { V24 = 0, EVO_SHARES = 1 };
inline constexpr int kDashDeploymentCount = 2;

/// Core ThresholdState.
enum class ThresholdState : uint8_t { DEFINED, STARTED, LOCKED_IN, ACTIVE, FAILED };

inline const char* threshold_state_name(ThresholdState s)
{
    switch (s) {
    case ThresholdState::DEFINED:   return "defined";
    case ThresholdState::STARTED:   return "started";
    case ThresholdState::LOCKED_IN: return "locked_in";
    case ThresholdState::ACTIVE:    return "active";
    case ThresholdState::FAILED:    return "failed";
    }
    return "?";
}

inline constexpr int32_t kVersionBitsTopBits = 0x20000000;
inline constexpr uint32_t kVersionBitsTopMask = 0xE0000000u;
inline constexpr int kVersionBitsNumBits = 29;

/// Core Consensus::BIP9Deployment.
struct Bip9Deployment
{
    static constexpr int64_t NO_TIMEOUT    = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
    static constexpr int64_t NEVER_ACTIVE  = -2;

    const char* name{""};
    int     bit{28};
    int64_t nStartTime{NEVER_ACTIVE};
    int64_t nTimeout{NEVER_ACTIVE};
    int     min_activation_height{0};
    int64_t nWindowSize{0};
    int64_t nThresholdStart{0};
    int64_t nThresholdMin{0};
    int64_t nFalloffCoeff{0};
    bool    useEHF{false};

    uint32_t mask() const { return uint32_t{1} << bit; }
};

/// The deployment parameters of one network.
struct DashDeploymentParams
{
    DashNetwork    network{DashNetwork::MAINNET};
    Bip9Deployment deployments[kDashDeploymentCount];
    /// Fallbacks Core uses when a deployment leaves nWindowSize or
    /// nThresholdStart at 0 (not the case for V24 / EVO_SHARES).
    int64_t  nMinerConfirmationWindow{2016};
    int64_t  nRuleChangeActivationThreshold{1815};
    /// GetStateFor treats every period end below this height as DEFINED.
    int64_t  min_bip9_warning_height{0};
    /// GetSignalsStage is empty before DEPLOYMENT_V20.
    uint32_t v20_height{0};
    /// Consensus::llmqTypeMnhf (LLMQ_400_85 = 3, LLMQ_50_60 = 1,
    /// LLMQ_DEVNET = 101, LLMQ_TEST = 100). Recorded for the signal checks
    /// and the dashboard; the tracker does not verify signal signatures
    /// (mined signals ride blocks Core already validated, design §3.1).
    uint8_t  llmq_type_mnhf{0};
    /// Ours: fixed rescan anchor of the EHF tracker (operator decision O7).
    uint32_t ehf_anchor_height{0};
    /// Ours: replay-proven historical V24 activation height, if any.
    std::optional<uint32_t> v24_buried_height;

    const Bip9Deployment& dep(DashDeployment d) const { return deployments[static_cast<int>(d)]; }
};

namespace deployment_detail {

inline Bip9Deployment make(const char* name, int bit, int64_t start, int64_t timeout,
                           int64_t window, int64_t thr_start, int64_t thr_min)
{
    Bip9Deployment d;
    d.name = name;
    d.bit = bit;
    d.nStartTime = start;
    d.nTimeout = timeout;
    d.min_activation_height = 0;
    d.nWindowSize = window;
    d.nThresholdStart = thr_start;
    d.nThresholdMin = thr_min;
    d.nFalloffCoeff = 5;   // "this corresponds to 10 periods"
    d.useEHF = true;
    return d;
}

inline DashDeploymentParams mainnet()
{
    DashDeploymentParams p;
    p.network = DashNetwork::MAINNET;
    // 1794182400 = Monday, November 9, 2026 0:00:00 UTC; timeout two years on.
    p.deployments[0] = make("v24",        13, 1794182400, 1857340800, 4032, 3226, 2420);
    p.deployments[1] = make("evo_shares", 14, 1794182400, 1857340800, 4032, 3226, 2420);
    p.nMinerConfirmationWindow = 2016;
    p.nRuleChangeActivationThreshold = 1815;
    p.min_bip9_warning_height = 2201472 + 2016;
    p.v20_height = 1987776;
    p.llmq_type_mnhf = 3;   // LLMQ_400_85
    // Mined on 2026-11-07, about two days before the start time: no signal
    // for bit 13 or 14 can be unexpired below it.
    p.ehf_anchor_height = 2'568'000;
    return p;
}

inline DashDeploymentParams testnet()
{
    DashDeploymentParams p;
    p.network = DashNetwork::TESTNET;
    // 1790208000 = Thursday, September 24, 2026 0:00:00 UTC.
    p.deployments[0] = make("v24",        13, 1790208000, Bip9Deployment::NO_TIMEOUT, 100, 80, 60);
    p.deployments[1] = make("evo_shares", 14, 1790208000, Bip9Deployment::NO_TIMEOUT, 100, 80, 60);
    p.nMinerConfirmationWindow = 2016;
    p.nRuleChangeActivationThreshold = 1512;
    p.min_bip9_warning_height = 1148500 + 2016;
    p.v20_height = 905100;
    p.llmq_type_mnhf = 1;   // LLMQ_50_60
    // MTP(1,559,000) = 1790137270 < start; the first block with MTP >= start
    // is 1,559,509 (measured, design §5.1).
    p.ehf_anchor_height = 1'559'000;
    // First block with CbTx version 4 (measured); reproduced by the replay
    // KAT DashV24Deployments.TestnetReplayActivatesAt1578000.
    p.v24_buried_height = 1'578'000;
    return p;
}

inline DashDeploymentParams devnet()
{
    DashDeploymentParams p;
    p.network = DashNetwork::DEVNET;
    p.deployments[0] = make("v24",        13, 1751328000, Bip9Deployment::NO_TIMEOUT, 120, 96, 72);
    p.deployments[1] = make("evo_shares", 14, 1751328000, Bip9Deployment::NO_TIMEOUT, 120, 96, 72);
    p.nMinerConfirmationWindow = 2016;
    p.nRuleChangeActivationThreshold = 1512;
    p.min_bip9_warning_height = 2 + 2016;
    p.v20_height = 2;
    p.llmq_type_mnhf = 101; // LLMQ_DEVNET
    p.ehf_anchor_height = 0;
    return p;
}

inline DashDeploymentParams regtest()
{
    DashDeploymentParams p;
    p.network = DashNetwork::REGTEST;
    p.deployments[0] = make("v24",        13, 0, Bip9Deployment::NO_TIMEOUT, 250, 250 / 5 * 4, 250 / 5 * 3);
    p.deployments[1] = make("evo_shares", 14, 0, Bip9Deployment::NO_TIMEOUT, 250, 250 / 5 * 4, 250 / 5 * 3);
    p.nMinerConfirmationWindow = 144;
    p.nRuleChangeActivationThreshold = 108;
    p.min_bip9_warning_height = 0;
    p.v20_height = 0;       // regtest V20 = DIP0003Height (-testactivationheight)
    p.llmq_type_mnhf = 100; // LLMQ_TEST
    p.ehf_anchor_height = 0;
    return p;
}

} // namespace deployment_detail

/// The deployment table of a network (static storage, never null).
inline const DashDeploymentParams& dash_deployment_params(DashNetwork net)
{
    static const DashDeploymentParams k_main = deployment_detail::mainnet();
    static const DashDeploymentParams k_test = deployment_detail::testnet();
    static const DashDeploymentParams k_dev  = deployment_detail::devnet();
    static const DashDeploymentParams k_reg  = deployment_detail::regtest();
    switch (net) {
    case DashNetwork::MAINNET: return k_main;
    case DashNetwork::TESTNET: return k_test;
    case DashNetwork::DEVNET:  return k_dev;
    case DashNetwork::REGTEST: return k_reg;
    }
    return k_main;
}

/// VersionBitsConditionChecker::Period.
inline int64_t vb_period(const DashDeploymentParams& p, const Bip9Deployment& d)
{
    return d.nWindowSize ? d.nWindowSize : p.nMinerConfirmationWindow;
}

/// VersionBitsConditionChecker::Threshold: the number of signalling blocks
/// the period of attempt `nAttempt` (0-based, counted from nStartHeight)
/// needs, falling quadratically from nThresholdStart to nThresholdMin. Integer
/// arithmetic in Core's left-to-right order.
inline int64_t vb_threshold(const DashDeploymentParams& p, const Bip9Deployment& d, int64_t nAttempt)
{
    if (d.nThresholdStart == 0) return p.nRuleChangeActivationThreshold;
    if (d.nThresholdMin == 0 || d.nFalloffCoeff == 0) return d.nThresholdStart;
    const int64_t calc = d.nThresholdStart - nAttempt * nAttempt * vb_period(p, d) / 100 / d.nFalloffCoeff;
    return calc > d.nThresholdMin ? calc : d.nThresholdMin;
}

/// VersionBitsConditionChecker::Condition: does a block with this header
/// version signal for the deployment?
inline bool vb_signals(int32_t nVersion, const Bip9Deployment& d)
{
    const uint32_t v = static_cast<uint32_t>(nVersion);
    return (v & kVersionBitsTopMask) == static_cast<uint32_t>(kVersionBitsTopBits) && (v & d.mask()) != 0;
}

/// Earliest height at which V24 can be ACTIVE when nothing has been measured:
/// the first period that can be STARTED, plus two periods. Mainnet: the
/// period end 2,568,383 precedes the start time by about two days, so
/// STARTED is at the earliest 2,572,416, LOCKED_IN 2,576,448, ACTIVE
/// 2,580,480 (design §0).
inline uint32_t v24_earliest_unmeasured_activation(DashNetwork net)
{
    switch (net) {
    case DashNetwork::MAINNET: return 2'580'480;
    case DashNetwork::TESTNET: return 1'578'000;   // buried
    case DashNetwork::DEVNET:
    case DashNetwork::REGTEST: return 0;
    }
    return 0;
}

} // namespace coin
} // namespace dash
